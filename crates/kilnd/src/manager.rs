//! The sandbox manager: validates requests, drives the runtime adapter and
//! records every transition in the store. The gRPC layer is a thin
//! translation on top of this.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use crate::admission::{Admission, AdmissionSnapshot};
use crate::model::{
    Captured, CommandStatus, Execution, ExecutionState, Network, RuntimeDiagnostic,
    RuntimeErrorKind, RuntimeStage, Sandbox, SandboxSpec, SandboxState, new_id, now_ms, valid_id,
};
use crate::runtime::{BackendStatus, ExecFinish, ExecOutcome, ExecSpec, Runtime, RuntimeError};
use crate::store::{ExecutionResult, Store};
use crate::validation::{
    MAX_ALLOWLIST_ENTRIES, MAX_WRITABLE_PATHS, validate_allowlist_entry, validate_argv,
    validate_image_name, validate_writable_path,
};

/// Limits and defaults; see `Config` in main.rs for the flags that set them.
#[derive(Clone, Debug)]
pub struct Limits {
    pub default_image: String,
    pub default_memory_bytes: u64,
    pub default_cpu_millis: u32,
    pub default_pids: u32,
    pub default_disk_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_cpu_millis: u32,
    pub max_pids: u32,
    pub max_disk_bytes: u64,
    pub max_sandboxes: u32,
    pub default_timeout: Duration,
    pub max_timeout: Duration,
    pub max_output_bytes: usize,
    pub max_stdin_bytes: usize,
    pub max_argv_bytes: usize,
    pub max_connections: usize,
    pub max_concurrent_rpcs: usize,
    pub max_concurrent_health: usize,
    pub max_concurrent_execs: usize,
    pub max_queued_execs_per_sandbox: usize,
    pub max_queued_exec_stdin_bytes: usize,
    pub max_streams_per_connection: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_list_page_size: u32,
    pub max_list_response_bytes: usize,
    pub health_probe_timeout: Duration,
    pub health_success_cache: Duration,
    pub health_failure_cache: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            default_image: "alpine".into(),
            default_memory_bytes: 512 << 20,
            default_cpu_millis: 1000,
            default_pids: 128,
            default_disk_bytes: 1 << 30,
            max_memory_bytes: 8 << 30,
            max_cpu_millis: 8000,
            max_pids: 4096,
            max_disk_bytes: 32 << 30,
            max_sandboxes: 32,
            default_timeout: Duration::from_secs(60),
            max_timeout: Duration::from_secs(3600),
            max_output_bytes: 1 << 20,
            max_stdin_bytes: 1 << 20,
            max_argv_bytes: 256 << 10,
            max_connections: 64,
            max_concurrent_rpcs: 64,
            max_concurrent_health: 4,
            max_concurrent_execs: 32,
            max_queued_execs_per_sandbox: 8,
            max_queued_exec_stdin_bytes: 16 << 20,
            max_streams_per_connection: 8,
            max_request_bytes: 2 << 20,
            max_response_bytes: 4 << 20,
            max_list_page_size: 200,
            max_list_response_bytes: 1 << 20,
            health_probe_timeout: Duration::from_secs(2),
            health_success_cache: Duration::from_secs(5),
            health_failure_cache: Duration::from_secs(1),
        }
    }
}

/// What a caller sent for CreateSandbox, before defaults. Zero means default.
#[derive(Clone, Debug, Default)]
pub struct CreateRequest {
    pub image: String,
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub pids: u32,
    pub disk_bytes: u64,
    pub network: Network,
    pub read_only_root: bool,
    pub writable_paths: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

pub struct ExecRequest {
    pub sandbox_id: String,
    pub argv: Vec<String>,
    pub stdin: Vec<u8>,
    /// Zero means the default.
    pub timeout_ms: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    FailedPrecondition(String),
    #[error("{0}")]
    ResourceExhausted(String),
    #[error("{0}")]
    DeadlineExceeded(String),
    #[error("kilnd is shutting down")]
    ShuttingDown,
    #[error("{0}")]
    Backend(String),
    #[error("internal error: {0:#}")]
    Internal(#[from] anyhow::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Per-sandbox coordination: executions in one sandbox run one at a time
/// (kiln's PID 1 serves them serially anyway), and delete can cancel the one
/// running.
struct Slot {
    exec_lock: tokio::sync::Mutex<()>,
    running: Mutex<Option<Arc<ExecCancellation>>>,
    outstanding_execs: Arc<Semaphore>,
}

impl Slot {
    fn new(capacity: usize) -> Self {
        Self {
            exec_lock: tokio::sync::Mutex::new(()),
            running: Mutex::new(None),
            outstanding_execs: Arc::new(Semaphore::new(capacity)),
        }
    }
}

struct ExecTicket {
    _global: OwnedSemaphorePermit,
    _sandbox: OwnedSemaphorePermit,
    _stdin: Option<OwnedSemaphorePermit>,
}

#[derive(Default)]
struct HealthProbeState {
    cached: Option<(Instant, std::result::Result<String, String>)>,
    in_flight: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecCancelReason {
    ClientGone,
    SandboxDeleted,
    Shutdown,
}

impl ExecCancelReason {
    fn message(self) -> &'static str {
        match self {
            Self::ClientGone => "client disconnected",
            Self::SandboxDeleted => "sandbox deleted",
            Self::Shutdown => "kilnd shut down",
        }
    }
}

/// One authoritative cancellation source for a running execution. Recording
/// the reason before firing the token makes the first observed request win
/// across RPC disconnect, delete and daemon shutdown races.
struct ExecCancellation {
    token: CancellationToken,
    reason: OnceLock<ExecCancelReason>,
}

impl ExecCancellation {
    fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            reason: OnceLock::new(),
        }
    }

    fn request(&self, reason: ExecCancelReason) {
        if self.reason.set(reason).is_ok() {
            self.token.cancel();
        }
    }

    fn reason(&self) -> Option<ExecCancelReason> {
        self.reason.get().copied()
    }
}

pub struct Manager<R> {
    runtime: R,
    store: Store,
    limits: Limits,
    admission: Arc<Admission>,
    health_probe: Mutex<HealthProbeState>,
    health_changed: Notify,
    slots: Mutex<HashMap<String, Weak<Slot>>>,
    /// Refuses new work once canceled.
    shutting_down: CancellationToken,
    /// Daemon-owned operations that must outlive the RPC waiting for them.
    operations: TaskTracker,
    /// Terminal execution writes currently retrying after a store failure.
    finalization_failures: AtomicU32,
    started_at_ms: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Health {
    pub serving: bool,
    pub shutting_down: bool,
    pub backend: &'static str,
    pub backend_version: String,
    pub detail: String,
    pub started_at_ms: i64,
    pub active_sandboxes: u32,
    pub running_executions: u32,
    pub admission: AdmissionSnapshot,
}

/// What startup reconciliation changed, for logs and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub gc_removed: Vec<String>,
    pub recovered: Vec<String>,
    pub lost: Vec<String>,
    pub failed: Vec<String>,
    pub deleted: Vec<String>,
    pub still_deleting: Vec<String>,
    pub interrupted_executions: usize,
    pub unmanaged: Vec<String>,
}

const MAX_LABELS: usize = 32;

impl<R: Runtime> Manager<R> {
    pub fn new(runtime: R, store: Store, limits: Limits) -> Self {
        Self {
            runtime,
            store,
            admission: Arc::new(Admission::new(&limits)),
            health_probe: Mutex::new(HealthProbeState::default()),
            health_changed: Notify::new(),
            limits,
            slots: Mutex::new(HashMap::new()),
            shutting_down: CancellationToken::new(),
            operations: TaskTracker::new(),
            finalization_failures: AtomicU32::new(0),
            started_at_ms: now_ms(),
        }
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) fn admission(&self) -> &Arc<Admission> {
        &self.admission
    }

    fn slot(&self, id: &str) -> Arc<Slot> {
        let mut slots = self.slots.lock().unwrap();
        slots.retain(|_, slot| slot.strong_count() != 0);
        if let Some(slot) = slots.get(id).and_then(Weak::upgrade) {
            return slot;
        }
        let slot = Arc::new(Slot::new(
            self.limits
                .max_queued_execs_per_sandbox
                .checked_add(1)
                .expect("queue capacity fits usize"),
        ));
        slots.insert(id.to_string(), Arc::downgrade(&slot));
        slot
    }

    fn check_serving(&self) -> Result<()> {
        if self.shutting_down.is_cancelled() {
            Err(Error::ShuttingDown)
        } else {
            Ok(())
        }
    }

    /// Brings the store in line with the backend. Run once at startup,
    /// before serving. Safe to repeat: a second run changes nothing. It never
    /// removes a sandbox kilnd didn't create, and never marks anything lost
    /// unless the backend's list succeeded.
    pub async fn reconcile(&self) -> Result<Reconciled> {
        let cancel = CancellationToken::new();
        self.runtime
            .version(Instant::now() + self.limits.health_probe_timeout, &cancel)
            .await
            .map_err(backend)?;
        let sandboxes = self.store.sandboxes(true)?;
        let known: HashSet<String> = sandboxes
            .iter()
            .filter(|sandbox| sandbox.backend == self.runtime.name())
            .filter_map(|sandbox| sandbox.backend_id.clone())
            .collect();
        let before_gc: HashMap<String, BackendStatus> = self
            .runtime
            .list()
            .await
            .map_err(backend)?
            .into_iter()
            .map(|s| (s.id, s.status))
            .collect();
        // Prove the initial listing complete before even scoped backend
        // cleanup. A hidden reachable managed sandbox makes all evidence
        // suspect, while an explicit stale record is itself cleanup evidence.
        self.validate_reconciliation_evidence(&sandboxes, &before_gc, &cancel)
            .await?;
        let mut stale_owned: Vec<String> = before_gc
            .iter()
            .filter(|(id, status)| **status == BackendStatus::Stale && known.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        stale_owned.sort();
        let gc_removed = if stale_owned.is_empty() {
            Vec::new()
        } else {
            let removed = self.runtime.gc(&stale_owned).await.map_err(backend)?;
            let requested: HashSet<_> = stale_owned.iter().cloned().collect();
            let mut reported = HashSet::new();
            for id in &removed {
                if !requested.contains(id) || !reported.insert(id.clone()) {
                    return Err(Error::Backend(format!(
                        "backend garbage collection reported sandbox {id} outside its unique requested scope"
                    )));
                }
            }
            removed
        };
        let live: HashMap<String, BackendStatus> = self
            .runtime
            .list()
            .await
            .map_err(backend)?
            .into_iter()
            .map(|s| (s.id, s.status))
            .collect();
        self.validate_reconciliation_evidence(&sandboxes, &live, &cancel)
            .await?;
        if let Some(id) = stale_owned
            .iter()
            .find(|id| live.get(*id) == Some(&BackendStatus::Stale))
        {
            return Err(Error::Backend(format!(
                "backend garbage collection left managed sandbox {id} stale"
            )));
        }
        let mut out = Reconciled {
            gc_removed,
            ..Default::default()
        };
        for s in sandboxes {
            if s.backend != self.runtime.name() {
                continue;
            }
            let alive =
                s.backend_id.as_ref().and_then(|b| live.get(b)) == Some(&BackendStatus::Running);
            match (s.state, &s.backend_id) {
                (SandboxState::Creating, None) => {
                    self.store.set_sandbox_state(
                        &s.id,
                        SandboxState::Failed,
                        None,
                        Some("kilnd stopped while the sandbox was being created"),
                    )?;
                    out.failed.push(s.id);
                }
                (SandboxState::Creating | SandboxState::Ready, Some(b)) => {
                    if alive {
                        if s.state == SandboxState::Creating {
                            self.store
                                .set_sandbox_state(&s.id, SandboxState::Ready, None, None)?;
                        }
                    } else {
                        let reason = format!(
                            "backend sandbox {b} was gone at kilnd startup (host reboot or crashed shim)"
                        );
                        self.store.set_sandbox_state(
                            &s.id,
                            SandboxState::Lost,
                            None,
                            Some(&reason),
                        )?;
                        out.lost.push(s.id);
                    }
                }
                (SandboxState::Deleting, Some(b)) if live.contains_key(b) => match self
                    .runtime
                    .remove(b)
                    .await
                {
                    Ok(()) | Err(RuntimeError::NotFound(_)) => {
                        self.store
                            .set_sandbox_state(&s.id, SandboxState::Deleted, None, None)?;
                        out.deleted.push(s.id);
                    }
                    Err(e) => {
                        let reason = format!("delete retry at startup failed: {e}");
                        self.store.set_sandbox_state(
                            &s.id,
                            SandboxState::Deleting,
                            None,
                            Some(&reason),
                        )?;
                        out.still_deleting.push(s.id);
                    }
                },
                (SandboxState::Deleting, _) => {
                    self.store
                        .set_sandbox_state(&s.id, SandboxState::Deleted, None, None)?;
                    out.deleted.push(s.id);
                }
                (SandboxState::Ready, None) => {
                    self.store.set_sandbox_state(
                        &s.id,
                        SandboxState::Lost,
                        None,
                        Some("ready sandbox had no backend ID"),
                    )?;
                    out.lost.push(s.id);
                }
                (SandboxState::Lost, Some(_)) if alive => {
                    self.store
                        .set_sandbox_state(&s.id, SandboxState::Ready, None, None)?;
                    out.recovered.push(s.id);
                }
                (SandboxState::Deleted | SandboxState::Failed | SandboxState::Lost, _) => {}
            }
        }
        out.interrupted_executions = self.store.interrupt_running_executions_for_backend(
            self.runtime.name(),
            "kilnd stopped while the execution was running",
        )?;
        out.unmanaged = live.into_keys().filter(|b| !known.contains(b)).collect();
        out.unmanaged.sort();
        for b in &out.unmanaged {
            warn!(backend_id = %b, "backend sandbox not created by kilnd; leaving it alone");
        }
        Ok(out)
    }

    async fn validate_reconciliation_evidence(
        &self,
        sandboxes: &[Sandbox],
        live: &HashMap<String, BackendStatus>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        // Check all candidates before any durable reconciliation mutation.
        // A complete list is necessary but not sufficient absence evidence:
        // independently probe any managed backend whose list record is
        // missing. A reachable backend proves the list was incomplete, so
        // startup must fail without changing the store or cleaning anything.
        for sandbox in sandboxes {
            if sandbox.backend != self.runtime.name() {
                continue;
            }
            let Some(id) = &sandbox.backend_id else {
                continue;
            };
            match (sandbox.state, live.get(id)) {
                (
                    SandboxState::Creating | SandboxState::Ready | SandboxState::Lost,
                    Some(BackendStatus::Running),
                ) => {
                    self.runtime
                        .validate_sandbox(
                            id,
                            Instant::now() + self.limits.health_probe_timeout,
                            cancel,
                        )
                        .await
                        .map_err(backend)?;
                }
                (SandboxState::Creating | SandboxState::Ready | SandboxState::Deleting, None) => {
                    match self
                        .runtime
                        .validate_sandbox(
                            id,
                            Instant::now() + self.limits.health_probe_timeout,
                            cancel,
                        )
                        .await
                    {
                        Ok(()) => {
                            return Err(Error::Backend(format!(
                                "backend listing did not report reachable managed sandbox {id} for {} as present",
                                sandbox.id
                            )));
                        }
                        Err(RuntimeError::NotFound(_)) => {}
                        Err(error) => return Err(backend(error)),
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub async fn health(self: &Arc<Self>) -> Result<Health> {
        let probe = loop {
            // Register before examining state so completion cannot be missed.
            let changed = self.health_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.health_probe.lock().unwrap();
                if self.shutting_down.is_cancelled() {
                    break state
                        .cached
                        .as_ref()
                        .map(|(_, result)| result.clone())
                        .unwrap_or_else(|| Err("probe unavailable during shutdown".into()));
                }
                if let Some((completed, result)) = &state.cached {
                    let ttl = if result.is_ok() {
                        self.limits.health_success_cache
                    } else {
                        self.limits.health_failure_cache
                    };
                    if completed.elapsed() < ttl {
                        break result.clone();
                    }
                }
                if !state.in_flight {
                    state.in_flight = true;
                    let manager = self.clone();
                    self.operations.spawn(async move {
                        let deadline = Instant::now()
                            .checked_add(manager.limits.health_probe_timeout)
                            .expect("validated Health deadline fits the monotonic clock");
                        let cancel = CancellationToken::new();
                        let runtime_manager = manager.clone();
                        let probe_cancel = cancel.clone();
                        let mut task = tokio::spawn(async move {
                            runtime_manager
                                .runtime
                                .version(deadline, &probe_cancel)
                                .await
                        });
                        let result = tokio::select! {
                            biased;
                            joined = &mut task => match joined {
                                Ok(result) => result.map_err(|error| error.to_string()),
                                Err(error) => Err(format!("version probe task failed: {error}")),
                            },
                            () = tokio::time::sleep_until(deadline) => {
                                cancel.cancel();
                                let _ = task.await;
                                Err("version probe timed out".into())
                            },
                            () = manager.shutting_down.cancelled() => {
                                cancel.cancel();
                                let _ = task.await;
                                Err("version probe canceled during shutdown".into())
                            },
                        };
                        {
                            let mut state = manager.health_probe.lock().unwrap();
                            state.cached = Some((Instant::now(), result));
                            state.in_flight = false;
                        }
                        manager.health_changed.notify_waiters();
                    });
                }
            }
            tokio::select! {
                () = &mut changed => {},
                () = self.shutting_down.cancelled() => {},
            }
        };
        let (mut serving, backend_version, mut detail) = match probe {
            Ok(v) => (true, v, String::new()),
            Err(e) => (false, String::new(), format!("backend: {e}")),
        };
        let finalization_failures = self.finalization_failures.load(Ordering::Relaxed);
        if finalization_failures != 0 {
            serving = false;
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&format!(
                "{finalization_failures} execution finalization write(s) retrying"
            ));
        }
        Ok(Health {
            serving: serving && !self.shutting_down.is_cancelled(),
            shutting_down: self.shutting_down.is_cancelled(),
            backend: self.runtime.name(),
            backend_version,
            detail,
            started_at_ms: self.started_at_ms,
            active_sandboxes: self.store.count_active_sandboxes()?,
            running_executions: self.store.count_running_executions()?,
            admission: self.admission.snapshot(),
        })
    }

    /// Starts a daemon-owned create and waits for its result. Dropping this
    /// waiter does not cancel the operation: once admitted, the supervisor
    /// always publishes the backend ID or compensates by removing it.
    pub async fn create(self: &Arc<Self>, req: CreateRequest) -> Result<Sandbox> {
        // No await separates this check from task registration, so shutdown
        // cannot close and drain the tracker before an accepted task exists.
        self.check_serving()?;
        let (result_tx, result_rx) = oneshot::channel();
        let manager = Arc::clone(self);
        self.operations.spawn(async move {
            let result = manager.create_owned(req).await;
            if let Err(result) = result_tx.send(result) {
                match result {
                    Ok(sandbox) => info!(sandbox = %sandbox.id, "create RPC stopped waiting; supervised operation completed"),
                    Err(error) => warn!(error = %error, "create RPC stopped waiting; supervised operation failed"),
                }
            }
        });
        result_rx.await.map_err(|_| {
            Error::Internal(anyhow::anyhow!(
                "create supervisor stopped without a result"
            ))
        })?
    }

    async fn create_owned(self: Arc<Self>, req: CreateRequest) -> Result<Sandbox> {
        self.check_serving()?;
        let spec = self.resolve_spec(req)?;
        if self.store.count_active_sandboxes()? >= self.limits.max_sandboxes {
            return Err(Error::ResourceExhausted(format!(
                "at most {} sandboxes may be active",
                self.limits.max_sandboxes
            )));
        }
        let now = now_ms();
        let mut sandbox = Sandbox {
            id: new_id("sb"),
            state: SandboxState::Creating,
            spec,
            backend: self.runtime.name().to_string(),
            backend_id: None,
            created_at_ms: now,
            updated_at_ms: now,
            deleted_at_ms: None,
            failure_reason: None,
        };
        // Recorded before the backend runs, so a crash mid-create leaves a
        // trace for reconciliation.
        self.store.insert_sandbox(&sandbox)?;
        info!(sandbox = %sandbox.id, image = %sandbox.spec.image, "creating sandbox");
        // Isolate a backend panic from the supervisor so the database still
        // reaches a terminal state. A backend that panics after making an
        // external resource but before returning its ID remains ambiguous by
        // the Runtime contract and is left for startup reconciliation to
        // report as unmanaged if it can still observe it.
        let backend_create = {
            let manager = Arc::clone(&self);
            let spec = sandbox.spec.clone();
            tokio::spawn(async move { manager.runtime.create(&spec).await })
        };
        let created = match backend_create.await {
            Ok(result) => result,
            Err(join) => {
                let reason = if join.is_panic() {
                    "backend create task panicked"
                } else {
                    "backend create task was canceled"
                };
                warn!(sandbox = %sandbox.id, error = reason, "sandbox creation failed");
                self.store.set_sandbox_state(
                    &sandbox.id,
                    SandboxState::Failed,
                    None,
                    Some(reason),
                )?;
                return Err(Error::Backend(format!(
                    "create sandbox {}: {reason}",
                    sandbox.id
                )));
            }
        };
        match created {
            Ok(backend_id) => {
                if let Err(e) = self.store.set_sandbox_state(
                    &sandbox.id,
                    SandboxState::Ready,
                    Some(&backend_id),
                    None,
                ) {
                    return Err(self
                        .compensate_failed_publication(&sandbox.id, &backend_id, e)
                        .await);
                }
                info!(sandbox = %sandbox.id, backend_id = %backend_id, "sandbox ready");
                sandbox.backend_id = Some(backend_id);
                sandbox.state = SandboxState::Ready;
                Ok(self.store.sandbox(&sandbox.id)?.unwrap_or(sandbox))
            }
            Err(e) => {
                let reason = e.to_string();
                warn!(sandbox = %sandbox.id, error = %reason, "sandbox creation failed");
                self.store.set_sandbox_state(
                    &sandbox.id,
                    SandboxState::Failed,
                    None,
                    Some(&reason),
                )?;
                Err(Error::Backend(format!(
                    "create sandbox {}: {reason}",
                    sandbox.id
                )))
            }
        }
    }

    /// A backend exists but READY could not be persisted. Publish cleanup
    /// intent before awaiting removal, then preserve any failed compensation
    /// as DELETING so it remains counted and retryable.
    async fn compensate_failed_publication(
        &self,
        sandbox_id: &str,
        backend_id: &str,
        publication: anyhow::Error,
    ) -> Error {
        let slot = self.slot(sandbox_id);
        let _guard = slot.exec_lock.lock().await;
        let publication_reason = format!("record ready state failed: {publication:#}");
        if let Err(e) = self.store.set_sandbox_state(
            sandbox_id,
            SandboxState::Deleting,
            Some(backend_id),
            Some(&publication_reason),
        ) {
            warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "could not record create compensation intent");
        }

        match self.runtime.remove(backend_id).await {
            Ok(()) | Err(RuntimeError::NotFound(_)) => {
                let reason = format!("{publication_reason}; backend removed");
                if let Err(e) = self.store.set_sandbox_state(
                    sandbox_id,
                    SandboxState::Failed,
                    Some(backend_id),
                    Some(&reason),
                ) {
                    warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "backend removed but create failure could not be finalized");
                }
                warn!(sandbox = %sandbox_id, backend_id = %backend_id, "ready publication failed; removed backend sandbox");
                Error::Internal(publication)
            }
            Err(cleanup) => {
                let reason = format!("{publication_reason}; cleanup failed: {cleanup}");
                if let Err(e) = self.store.set_sandbox_state(
                    sandbox_id,
                    SandboxState::Deleting,
                    Some(backend_id),
                    Some(&reason),
                ) {
                    warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "create compensation failure could not be recorded");
                }
                warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %cleanup, "ready publication and compensation failed");
                Error::Internal(anyhow::anyhow!(
                    "{publication_reason}; cleanup failed: {cleanup}"
                ))
            }
        }
    }

    pub fn get(&self, id: &str, execution_limit: u32) -> Result<(Sandbox, Vec<Execution>)> {
        let sandbox = self.load(id)?;
        let limit = match execution_limit {
            0 => 10,
            n => n.min(100),
        };
        let executions = self.store.recent_executions(id, limit)?;
        Ok((sandbox, executions))
    }

    pub fn list(&self, include_deleted: bool) -> Result<Vec<Sandbox>> {
        Ok(self.store.sandboxes(include_deleted)?)
    }

    pub(crate) fn list_page(
        &self,
        include_deleted: bool,
        upper: Option<i64>,
        before: Option<i64>,
        limit: u32,
    ) -> Result<crate::store::SandboxPage> {
        Ok(self
            .store
            .sandbox_page(include_deleted, upper, before, limit)?)
    }

    pub fn execution(&self, id: &str) -> Result<Execution> {
        if !valid_id("ex", id) {
            return Err(Error::InvalidArgument(format!(
                "invalid execution ID {id:?}"
            )));
        }
        self.store
            .execution(id)?
            .ok_or_else(|| Error::NotFound(format!("execution {id}")))
    }

    fn load(&self, id: &str) -> Result<Sandbox> {
        if !valid_id("sb", id) {
            return Err(Error::InvalidArgument(format!("invalid sandbox ID {id:?}")));
        }
        self.store
            .sandbox(id)?
            .ok_or_else(|| Error::NotFound(format!("sandbox {id}")))
    }

    /// Publishes delete intent without allowing a stale caller to overwrite a
    /// newer state. The loop only repeats when another writer won the state
    /// comparison between our read and update.
    fn prepare_delete(&self, id: &str, mut sandbox: Sandbox) -> Result<Sandbox> {
        loop {
            match sandbox.state {
                SandboxState::Deleted | SandboxState::Deleting => return Ok(sandbox),
                // Its backend ID isn't known yet. If kilnd crashed mid-create,
                // startup reconciliation has already moved it to FAILED.
                SandboxState::Creating => {
                    return Err(Error::FailedPrecondition(format!(
                        "sandbox {id} is still being created; retry"
                    )));
                }
                expected @ (SandboxState::Ready | SandboxState::Failed | SandboxState::Lost) => {
                    if self.store.compare_and_set_sandbox_state(
                        id,
                        expected,
                        SandboxState::Deleting,
                        None,
                        sandbox.failure_reason.as_deref(),
                    )? {
                        return self.load(id);
                    }
                    sandbox = self.load(id)?;
                }
            }
        }
    }

    pub async fn delete(&self, id: &str) -> Result<Sandbox> {
        let sandbox = self.load(id)?;
        if sandbox.state == SandboxState::Deleted {
            return Ok(sandbox);
        }
        // Hold a strong reference before publishing DELETING so every caller
        // that observes the transition reuses this exact coordination slot.
        let slot = self.slot(id);
        let sandbox = self.prepare_delete(id, sandbox)?;
        if sandbox.state == SandboxState::Deleted {
            return Ok(sandbox);
        }
        info!(sandbox = %id, "deleting sandbox");
        if let Some(cancel) = &*slot.running.lock().unwrap() {
            cancel.request(ExecCancelReason::SandboxDeleted);
        }
        // Wait for a running execution to finish canceling; new ones see
        // DELETING and refuse.
        let _guard = slot.exec_lock.lock().await;

        // Another delete may have completed while this caller waited. Reload
        // under the lock so backend removal and all result transitions use
        // current state rather than the caller's stale pre-lock snapshot.
        let sandbox = self.prepare_delete(id, self.load(id)?)?;
        if sandbox.state == SandboxState::Deleted {
            return Ok(sandbox);
        }

        let result = match &sandbox.backend_id {
            Some(b) => match self.runtime.remove(b).await {
                Ok(()) | Err(RuntimeError::NotFound(_)) => Ok(()),
                Err(e) => Err(e),
            },
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                if !self.store.compare_and_set_sandbox_state(
                    id,
                    SandboxState::Deleting,
                    SandboxState::Deleted,
                    None,
                    None,
                )? {
                    let current = self.load(id)?;
                    if current.state == SandboxState::Deleted {
                        return Ok(current);
                    }
                    return Err(Error::Internal(anyhow::anyhow!(
                        "sandbox {id} changed from deleting to {} while backend removal completed",
                        current.state.as_str()
                    )));
                }
                // Queued requests still own this slot. Keep it stable until
                // manager teardown rather than replacing its admission gate.
                info!(sandbox = %id, "sandbox deleted");
                Ok(self.load(id)?)
            }
            Err(e) => {
                let reason = format!("delete failed: {e}");
                warn!(sandbox = %id, error = %reason, "sandbox delete failed");
                if !self.store.compare_and_set_sandbox_state(
                    id,
                    SandboxState::Deleting,
                    SandboxState::Deleting,
                    None,
                    Some(&reason),
                )? {
                    let current = self.load(id)?;
                    if current.state == SandboxState::Deleted {
                        return Ok(current);
                    }
                    return Err(Error::Internal(anyhow::anyhow!(
                        "sandbox {id} changed from deleting to {} while backend removal failed: {e}",
                        current.state.as_str()
                    )));
                }
                Err(Error::Backend(format!("delete sandbox {id}: {e}")))
            }
        }
    }

    /// Starts a daemon-owned execution and waits for its result. Once the
    /// execution row exists, dropping this waiter requests cancellation but
    /// cannot drop backend cleanup, output capture or row finalization.
    pub async fn exec(self: &Arc<Self>, req: ExecRequest) -> Result<Execution> {
        self.exec_received(req, Instant::now()).await
    }

    pub(crate) async fn exec_received(
        self: &Arc<Self>,
        req: ExecRequest,
        received_at: Instant,
    ) -> Result<Execution> {
        self.check_serving()?;
        let timeout = self.check_exec(&req)?;
        let deadline = received_at
            .checked_add(timeout)
            .ok_or_else(|| Error::InvalidArgument("timeout deadline overflow".into()))?;
        let sandbox = self.load(&req.sandbox_id)?;
        ready(&sandbox)?;
        let slot = self.slot(&sandbox.id);
        let global = self.admission.try_exec().map_err(|_| {
            Error::ResourceExhausted(format!(
                "global Exec admission limit ({}) reached",
                self.limits.max_concurrent_execs
            ))
        })?;
        let outstanding = slot
            .outstanding_execs
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                self.admission.reject_sandbox_exec();
                Error::ResourceExhausted(format!(
                    "sandbox Exec capacity reached (one running plus {} queued)",
                    self.limits.max_queued_execs_per_sandbox
                ))
            })?;
        let stdin = self.admission.try_stdin(req.stdin.len()).map_err(|_| {
            Error::ResourceExhausted(format!(
                "aggregate retained Exec stdin limit ({} bytes) reached",
                self.limits.max_queued_exec_stdin_bytes
            ))
        })?;
        let ticket = ExecTicket {
            _global: global,
            _sandbox: outstanding,
            _stdin: stdin,
        };
        // No await separates the admission check from tracker registration.
        // On the daemon's current-thread runtime, shutdown cannot close and
        // finish draining the tracker between these two operations.
        let (result_tx, result_rx) = oneshot::channel();
        let manager = Arc::clone(self);
        self.operations.spawn(async move {
            manager
                .supervise_exec(req, result_tx, slot, timeout, deadline, ticket)
                .await;
        });
        result_rx.await.map_err(|_| {
            Error::Internal(anyhow::anyhow!("exec supervisor stopped without a result"))
        })?
    }

    async fn supervise_exec(
        self: Arc<Self>,
        req: ExecRequest,
        mut reply: oneshot::Sender<Result<Execution>>,
        slot: Arc<Slot>,
        timeout: Duration,
        deadline: Instant,
        _ticket: ExecTicket,
    ) {
        let Some(result) = self
            .exec_owned(req, &mut reply, slot, timeout, deadline)
            .await
        else {
            return;
        };
        if let Err(result) = reply.send(result) {
            match result {
                Ok(execution) => {
                    info!(execution = %execution.id, state = execution.state.as_str(), "exec RPC stopped waiting; supervised operation completed")
                }
                Err(error) => {
                    warn!(error = %error, "exec RPC stopped waiting; supervised operation failed")
                }
            }
        }
    }

    /// Returns `None` only when the waiter vanished before an execution row
    /// was inserted. After insertion the supervisor retains ownership until
    /// it has published a terminal result; an unavailable store keeps it
    /// pending and retrying.
    async fn exec_owned(
        self: &Arc<Self>,
        req: ExecRequest,
        reply: &mut oneshot::Sender<Result<Execution>>,
        slot: Arc<Slot>,
        timeout: Duration,
        deadline: Instant,
    ) -> Option<Result<Execution>> {
        let sandbox = match self.load(&req.sandbox_id).and_then(|sandbox| {
            ready(&sandbox)?;
            Ok(sandbox)
        }) {
            Ok(sandbox) => sandbox,
            Err(error) => return Some(Err(error)),
        };
        // A queued RPC that disappears must not run later. Bias cancellation
        // when the lock and closure become ready in the same scheduler turn.
        let _guard = tokio::select! {
            biased;
            () = reply.closed() => {
                info!(sandbox = %sandbox.id, "queued exec RPC stopped waiting; discarding request");
                return None;
            }
            () = self.shutting_down.cancelled() => return Some(Err(Error::ShuttingDown)),
            () = tokio::time::sleep_until(deadline) => return Some(Err(Error::DeadlineExceeded("Exec deadline expired while queued".into()))),
            guard = slot.exec_lock.lock() => guard,
        };
        if reply.is_closed() {
            info!(sandbox = %sandbox.id, "queued exec RPC stopped waiting; discarding request");
            return None;
        }
        if Instant::now() >= deadline {
            return Some(Err(Error::DeadlineExceeded(
                "Exec deadline expired before execution started".into(),
            )));
        }
        // The sandbox may have changed while this request waited its turn.
        let sandbox = match self.load(&req.sandbox_id).and_then(|sandbox| {
            ready(&sandbox)?;
            self.check_serving()?;
            Ok(sandbox)
        }) {
            Ok(sandbox) => sandbox,
            Err(error) => return Some(Err(error)),
        };
        let backend_id = match sandbox.backend_id.clone() {
            Some(id) => id,
            None => {
                return Some(Err(Error::FailedPrecondition(
                    "sandbox has no backend ID".into(),
                )));
            }
        };

        let mut execution = Execution {
            id: new_id("ex"),
            sandbox_id: sandbox.id.clone(),
            argv: req.argv,
            state: ExecutionState::Running,
            exit_code: None,
            command_status: None,
            runtime_error: None,
            failure_reason: None,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            timeout_ms: u32::try_from(timeout.as_millis()).expect("validated timeout fits u32"),
            stdin_bytes: req.stdin.len() as u64,
            stdout: Captured::default(),
            stderr: Captured::default(),
        };
        if Instant::now() >= deadline {
            return Some(Err(Error::DeadlineExceeded(
                "Exec deadline expired before row insertion".into(),
            )));
        }
        if let Err(error) = self.store.insert_execution(&execution) {
            return Some(Err(error.into()));
        }
        let cancel = Arc::new(ExecCancellation::new());
        *slot.running.lock().unwrap() = Some(cancel.clone());
        info!(sandbox = %sandbox.id, execution = %execution.id, argc = execution.argv.len(), "exec started");

        // The backend future lives in its own task so both construction-time
        // and polling-time panics become a result the supervisor can record.
        // All borrowed ExecSpec data is owned by that task.
        let backend_manager = Arc::clone(self);
        let backend_id_for_task = backend_id.clone();
        let argv = execution.argv.clone();
        let stdin = req.stdin;
        let max_output = self.limits.max_output_bytes;
        let backend_cancel = cancel.clone();
        let mut backend = tokio::spawn(async move {
            if backend_cancel.token.is_cancelled() {
                return ExecOutcome {
                    finish: Ok(ExecFinish::Canceled),
                    command_status: None,
                    stdout: Captured::known_empty(),
                    stderr: Captured::known_empty(),
                };
            }
            let spec = ExecSpec {
                argv: &argv,
                stdin: &stdin,
                deadline,
                max_output,
            };
            backend_manager
                .runtime
                .exec(&backend_id_for_task, &spec, &backend_cancel.token)
                .await
        });
        // Poll backend completion first so a late receiver drop cannot turn
        // an already-completed command into a cancellation. Once closure is
        // observed, disable that branch by leaving the select and await the
        // exact same backend task through cleanup.
        let joined = tokio::select! {
            biased;
            joined = &mut backend => joined,
            () = reply.closed() => {
                cancel.request(ExecCancelReason::ClientGone);
                backend.await
            }
        };
        slot.running.lock().unwrap().take();

        let mut outcome = match joined {
            Ok(outcome) => outcome,
            Err(join) => {
                let reason = if join.is_panic() {
                    "backend exec task panicked"
                } else {
                    "backend exec task was canceled"
                };
                warn!(sandbox = %sandbox.id, execution = %execution.id, error = reason, "exec backend task failed");
                ExecOutcome {
                    finish: Err(RuntimeDiagnostic::new(
                        RuntimeErrorKind::Internal,
                        RuntimeStage::Report,
                        reason,
                    )),
                    command_status: None,
                    stdout: Captured::default(),
                    stderr: Captured::default(),
                }
            }
        };
        if outcome.finish == Ok(ExecFinish::Completed) && outcome.command_status.is_none() {
            outcome.finish = Err(RuntimeDiagnostic::new(
                RuntimeErrorKind::Internal,
                RuntimeStage::Report,
                "backend reported completion without command status",
            ));
        }
        let (state, exit_code, reason) = match &outcome.finish {
            Ok(ExecFinish::Completed) => (
                ExecutionState::Exited,
                outcome
                    .command_status
                    .as_ref()
                    .map(CommandStatus::legacy_projection),
                None,
            ),
            Ok(ExecFinish::TimedOut) => (
                ExecutionState::TimedOut,
                None,
                Some(format!("timed out after {} ms", timeout.as_millis())),
            ),
            Ok(ExecFinish::Canceled) => {
                let why = cancel
                    .reason()
                    .map_or("backend canceled execution", ExecCancelReason::message);
                (ExecutionState::Canceled, None, Some(why.to_string()))
            }
            Err(e) => (ExecutionState::Failed, None, Some(e.message.clone())),
        };
        let (stdout, stderr) = (&outcome.stdout, &outcome.stderr);
        let mut retry_delay = Duration::from_millis(10);
        let mut finalization_degraded = false;
        loop {
            match self.store.finish_execution(
                &execution.id,
                &ExecutionResult {
                    state,
                    exit_code,
                    command_status: outcome.command_status.as_ref(),
                    runtime_error: outcome.finish.as_ref().err(),
                    failure_reason: reason.as_deref(),
                    stdout,
                    stderr,
                },
            ) {
                Ok(()) => break,
                Err(error) => {
                    if !finalization_degraded {
                        self.finalization_failures.fetch_add(1, Ordering::Relaxed);
                        finalization_degraded = true;
                    }
                    warn!(execution = %execution.id, state = state.as_str(), error = %format!("{error:#}"), retry_ms = retry_delay.as_millis(), "exec cleanup completed but terminal state could not be recorded; retaining ownership and retrying");
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(5));
                }
            }
        }
        if finalization_degraded {
            self.finalization_failures.fetch_sub(1, Ordering::Relaxed);
        }
        if matches!(&outcome.finish, Err(d) if d.kind == RuntimeErrorKind::NotFound) {
            let why = format!("backend sandbox {backend_id} disappeared during an execution");
            warn!(sandbox = %sandbox.id, "{why}");
            if let Err(error) = self.store.mark_sandbox_lost_if_ready(&sandbox.id, &why) {
                return Some(Err(error.into()));
            }
        }
        info!(
            sandbox = %sandbox.id,
            execution = %execution.id,
            state = state.as_str(),
            exit_code = exit_code.unwrap_or(-1),
            stdout_bytes = stdout.total_bytes,
            stderr_bytes = stderr.total_bytes,
            "exec finished"
        );
        execution = match self.store.execution(&execution.id) {
            Ok(Some(execution)) => execution,
            Ok(None) => return Some(Err(Error::Internal(anyhow::anyhow!("execution vanished")))),
            Err(error) => return Some(Err(error.into())),
        };
        Some(Ok(execution))
    }

    /// Starts shutdown: new sandboxes and executions are refused. Running
    /// executions continue until `cancel_executions`.
    pub fn begin_shutdown(&self) {
        self.shutting_down.cancel();
        self.operations.close();
    }

    /// Waits until every accepted daemon-owned operation has finished. Call
    /// after `begin_shutdown`, which closes the tracker to new idle periods.
    pub async fn drain_operations(&self) {
        self.operations.wait().await;
    }

    /// Cancels every running execution; they finish as CANCELED.
    pub fn cancel_executions(&self) {
        let slots: Vec<_> = self
            .slots
            .lock()
            .unwrap()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for slot in slots {
            if let Some(cancel) = &*slot.running.lock().unwrap() {
                cancel.request(ExecCancelReason::Shutdown);
            }
        }
    }

    fn check_exec(&self, req: &ExecRequest) -> Result<Duration> {
        validate_argv(&req.argv, self.limits.max_argv_bytes)
            .map_err(Error::InvalidArgument)?;
        if req.stdin.len() > self.limits.max_stdin_bytes {
            return Err(Error::InvalidArgument(format!(
                "stdin is {} bytes; the limit is {}",
                req.stdin.len(),
                self.limits.max_stdin_bytes
            )));
        }
        let timeout = match req.timeout_ms {
            0 => self.limits.default_timeout,
            ms => Duration::from_millis(ms.into()),
        };
        if timeout > self.limits.max_timeout {
            return Err(Error::InvalidArgument(format!(
                "timeout {} ms is above the limit of {} ms",
                timeout.as_millis(),
                self.limits.max_timeout.as_millis()
            )));
        }
        Ok(timeout)
    }

    fn resolve_spec(&self, req: CreateRequest) -> Result<SandboxSpec> {
        let l = &self.limits;
        let invalid = |msg: String| Err(Error::InvalidArgument(msg));
        let image = if req.image.is_empty() {
            l.default_image.clone()
        } else {
            req.image
        };
        validate_image_name(&image).map_err(Error::InvalidArgument)?;
        let pick = |v: u64, default: u64| if v == 0 { default } else { v };
        let spec = SandboxSpec {
            image,
            memory_bytes: pick(req.memory_bytes, l.default_memory_bytes),
            cpu_millis: pick(req.cpu_millis.into(), l.default_cpu_millis.into()) as u32,
            pids: pick(req.pids.into(), l.default_pids.into()) as u32,
            disk_bytes: pick(req.disk_bytes, l.default_disk_bytes),
            network: req.network,
            read_only_root: req.read_only_root,
            writable_paths: req.writable_paths,
            labels: req.labels,
        };
        if spec.memory_bytes > l.max_memory_bytes {
            return invalid(format!(
                "memory {} is above the limit of {}",
                spec.memory_bytes, l.max_memory_bytes
            ));
        }
        if spec.cpu_millis > l.max_cpu_millis {
            return invalid(format!(
                "cpu {} millis is above the limit of {}",
                spec.cpu_millis, l.max_cpu_millis
            ));
        }
        if spec.pids > l.max_pids {
            return invalid(format!(
                "pids {} is above the limit of {}",
                spec.pids, l.max_pids
            ));
        }
        if spec.disk_bytes > l.max_disk_bytes {
            return invalid(format!(
                "disk {} is above the limit of {}",
                spec.disk_bytes, l.max_disk_bytes
            ));
        }
        if let Network::Allow(allow) = &spec.network {
            if allow.is_empty() || allow.len() > MAX_ALLOWLIST_ENTRIES {
                return invalid(format!(
                    "an allowlist needs 1 to {MAX_ALLOWLIST_ENTRIES} entries"
                ));
            }
            for a in allow {
                validate_allowlist_entry(a).map_err(Error::InvalidArgument)?;
            }
        }
        if !spec.writable_paths.is_empty() && !spec.read_only_root {
            return invalid("writable_paths needs read_only_root".into());
        }
        if spec.writable_paths.len() > MAX_WRITABLE_PATHS {
            return invalid(format!("at most {MAX_WRITABLE_PATHS} writable paths"));
        }
        for p in &spec.writable_paths {
            validate_writable_path(p).map_err(Error::InvalidArgument)?;
        }
        if spec.labels.len() > MAX_LABELS {
            return invalid(format!("at most {MAX_LABELS} labels"));
        }
        for (k, v) in &spec.labels {
            if k.is_empty()
                || k.len() > 63
                || !k
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
                || v.len() > 256
                || v.chars().any(|c| c.is_control())
            {
                return invalid(format!("invalid label {k:?}"));
            }
        }
        Ok(spec)
    }
}

fn ready(s: &Sandbox) -> Result<()> {
    if s.state == SandboxState::Ready {
        Ok(())
    } else {
        Err(Error::FailedPrecondition(format!(
            "sandbox {} is {}, not ready",
            s.id,
            s.state.as_str()
        )))
    }
}

fn backend(e: RuntimeError) -> Error {
    Error::Backend(e.to_string())
}

#[cfg(test)]
mod tests;
