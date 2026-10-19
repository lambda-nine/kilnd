//! The sandbox manager: validates requests, drives the runtime adapter and
//! records every transition in the store. The gRPC layer is a thin
//! translation on top of this.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio_util::task::TaskTracker;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::model::{
    Captured, Execution, ExecutionState, Network, Sandbox, SandboxSpec, SandboxState, new_id, now_ms, valid_id,
};
use crate::runtime::{BackendStatus, ExecFinish, ExecSpec, Runtime, RuntimeError};
use crate::store::{ExecutionResult, Store};

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
#[derive(Default)]
struct Slot {
    exec_lock: tokio::sync::Mutex<()>,
    running: Mutex<Option<CancellationToken>>,
}

pub struct Manager<R> {
    runtime: R,
    store: Store,
    limits: Limits,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    /// Refuses new work once canceled.
    shutting_down: CancellationToken,
    /// Cancels running executions once canceled.
    abort_executions: CancellationToken,
    /// Daemon-owned operations that must outlive the RPC waiting for them.
    operations: TaskTracker,
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
}

/// What startup reconciliation changed, for logs and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub gc_removed: Vec<String>,
    pub lost: Vec<String>,
    pub failed: Vec<String>,
    pub deleted: Vec<String>,
    pub still_deleting: Vec<String>,
    pub interrupted_executions: usize,
    pub unmanaged: Vec<String>,
}

const MAX_LABELS: usize = 32;
const MAX_ALLOW: usize = 64;
const MAX_WRITABLE: usize = 16;

impl<R: Runtime> Manager<R> {
    pub fn new(runtime: R, store: Store, limits: Limits) -> Self {
        Self {
            runtime,
            store,
            limits,
            slots: Mutex::new(HashMap::new()),
            shutting_down: CancellationToken::new(),
            abort_executions: CancellationToken::new(),
            operations: TaskTracker::new(),
            started_at_ms: now_ms(),
        }
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn slot(&self, id: &str) -> Arc<Slot> {
        self.slots.lock().unwrap().entry(id.to_string()).or_default().clone()
    }

    fn check_serving(&self) -> Result<()> {
        if self.shutting_down.is_cancelled() { Err(Error::ShuttingDown) } else { Ok(()) }
    }

    /// Brings the store in line with the backend. Run once at startup,
    /// before serving. Safe to repeat: a second run changes nothing. It never
    /// removes a sandbox kilnd didn't create, and never marks anything lost
    /// unless the backend's list succeeded.
    pub async fn reconcile(&self) -> Result<Reconciled> {
        let mut out = Reconciled { gc_removed: self.runtime.gc().await.map_err(backend)?, ..Default::default() };
        let live: HashMap<String, BackendStatus> =
            self.runtime.list().await.map_err(backend)?.into_iter().map(|s| (s.id, s.status)).collect();
        let mut known = std::collections::HashSet::new();

        for s in self.store.sandboxes(true)? {
            if s.backend != self.runtime.name() {
                continue;
            }
            if let Some(b) = &s.backend_id {
                known.insert(b.clone());
            }
            let alive = s.backend_id.as_ref().and_then(|b| live.get(b)) == Some(&BackendStatus::Running);
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
                            self.store.set_sandbox_state(&s.id, SandboxState::Ready, None, None)?;
                        }
                    } else {
                        let reason = format!("backend sandbox {b} was gone at kilnd startup (host reboot or crashed shim)");
                        self.store.set_sandbox_state(&s.id, SandboxState::Lost, None, Some(&reason))?;
                        out.lost.push(s.id);
                    }
                }
                (SandboxState::Deleting, Some(b)) if live.contains_key(b) => match self.runtime.remove(b).await {
                    Ok(()) | Err(RuntimeError::NotFound(_)) => {
                        self.store.set_sandbox_state(&s.id, SandboxState::Deleted, None, None)?;
                        out.deleted.push(s.id);
                    }
                    Err(e) => {
                        let reason = format!("delete retry at startup failed: {e}");
                        self.store.set_sandbox_state(&s.id, SandboxState::Deleting, None, Some(&reason))?;
                        out.still_deleting.push(s.id);
                    }
                },
                (SandboxState::Deleting, _) => {
                    self.store.set_sandbox_state(&s.id, SandboxState::Deleted, None, None)?;
                    out.deleted.push(s.id);
                }
                (SandboxState::Ready, None) => {
                    self.store.set_sandbox_state(&s.id, SandboxState::Lost, None, Some("ready sandbox had no backend ID"))?;
                    out.lost.push(s.id);
                }
                (SandboxState::Deleted | SandboxState::Failed | SandboxState::Lost, _) => {}
            }
        }
        out.interrupted_executions =
            self.store.interrupt_running_executions("kilnd stopped while the execution was running")?;
        out.unmanaged = live.into_keys().filter(|b| !known.contains(b)).collect();
        out.unmanaged.sort();
        for b in &out.unmanaged {
            warn!(backend_id = %b, "backend sandbox not created by kilnd; leaving it alone");
        }
        Ok(out)
    }

    pub async fn health(&self) -> Result<Health> {
        let (serving, backend_version, detail) = match self.runtime.version().await {
            Ok(v) => (true, v, String::new()),
            Err(e) => (false, String::new(), format!("backend: {e}")),
        };
        Ok(Health {
            serving,
            shutting_down: self.shutting_down.is_cancelled(),
            backend: self.runtime.name(),
            backend_version,
            detail,
            started_at_ms: self.started_at_ms,
            active_sandboxes: self.store.count_active_sandboxes()?,
            running_executions: self.store.count_running_executions()?,
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
        result_rx.await.map_err(|_| Error::Internal(anyhow::anyhow!("create supervisor stopped without a result")))?
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
                let reason = if join.is_panic() { "backend create task panicked" } else { "backend create task was canceled" };
                warn!(sandbox = %sandbox.id, error = reason, "sandbox creation failed");
                self.store.set_sandbox_state(&sandbox.id, SandboxState::Failed, None, Some(reason))?;
                return Err(Error::Backend(format!("create sandbox {}: {reason}", sandbox.id)));
            }
        };
        match created {
            Ok(backend_id) => {
                if let Err(e) = self.store.set_sandbox_state(&sandbox.id, SandboxState::Ready, Some(&backend_id), None) {
                    return Err(self.compensate_failed_publication(&sandbox.id, &backend_id, e).await);
                }
                info!(sandbox = %sandbox.id, backend_id = %backend_id, "sandbox ready");
                sandbox.backend_id = Some(backend_id);
                sandbox.state = SandboxState::Ready;
                Ok(self.store.sandbox(&sandbox.id)?.unwrap_or(sandbox))
            }
            Err(e) => {
                let reason = e.to_string();
                warn!(sandbox = %sandbox.id, error = %reason, "sandbox creation failed");
                self.store.set_sandbox_state(&sandbox.id, SandboxState::Failed, None, Some(&reason))?;
                Err(Error::Backend(format!("create sandbox {}: {reason}", sandbox.id)))
            }
        }
    }

    /// A backend exists but READY could not be persisted. Publish cleanup
    /// intent before awaiting removal, then preserve any failed compensation
    /// as DELETING so it remains counted and retryable.
    async fn compensate_failed_publication(&self, sandbox_id: &str, backend_id: &str, publication: anyhow::Error) -> Error {
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
                if let Err(e) = self.store.set_sandbox_state(sandbox_id, SandboxState::Failed, Some(backend_id), Some(&reason)) {
                    warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "backend removed but create failure could not be finalized");
                }
                self.slots.lock().unwrap().remove(sandbox_id);
                warn!(sandbox = %sandbox_id, backend_id = %backend_id, "ready publication failed; removed backend sandbox");
                Error::Internal(publication)
            }
            Err(cleanup) => {
                let reason = format!("{publication_reason}; cleanup failed: {cleanup}");
                if let Err(e) =
                    self.store.set_sandbox_state(sandbox_id, SandboxState::Deleting, Some(backend_id), Some(&reason))
                {
                    warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "create compensation failure could not be recorded");
                }
                warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %cleanup, "ready publication and compensation failed");
                Error::Internal(anyhow::anyhow!("{publication_reason}; cleanup failed: {cleanup}"))
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

    pub fn execution(&self, id: &str) -> Result<Execution> {
        if !valid_id("ex", id) {
            return Err(Error::InvalidArgument(format!("invalid execution ID {id:?}")));
        }
        self.store.execution(id)?.ok_or_else(|| Error::NotFound(format!("execution {id}")))
    }

    fn load(&self, id: &str) -> Result<Sandbox> {
        if !valid_id("sb", id) {
            return Err(Error::InvalidArgument(format!("invalid sandbox ID {id:?}")));
        }
        self.store.sandbox(id)?.ok_or_else(|| Error::NotFound(format!("sandbox {id}")))
    }

    pub async fn delete(&self, id: &str) -> Result<Sandbox> {
        let sandbox = self.load(id)?;
        match sandbox.state {
            SandboxState::Deleted => return Ok(sandbox),
            // Its backend ID isn't known yet. If kilnd crashed mid-create,
            // startup reconciliation has already moved it to FAILED.
            SandboxState::Creating => {
                return Err(Error::FailedPrecondition(format!("sandbox {id} is still being created; retry")));
            }
            _ => {}
        }
        self.store.set_sandbox_state(id, SandboxState::Deleting, None, sandbox.failure_reason.as_deref())?;
        info!(sandbox = %id, "deleting sandbox");
        let slot = self.slot(id);
        if let Some(cancel) = &*slot.running.lock().unwrap() {
            cancel.cancel();
        }
        // Wait for a running execution to finish canceling; new ones see
        // DELETING and refuse.
        let _guard = slot.exec_lock.lock().await;

        let result = match &sandbox.backend_id {
            Some(b) => match self.runtime.remove(b).await {
                Ok(()) | Err(RuntimeError::NotFound(_)) => Ok(()),
                Err(e) => Err(e),
            },
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                self.store.set_sandbox_state(id, SandboxState::Deleted, None, None)?;
                self.slots.lock().unwrap().remove(id);
                info!(sandbox = %id, "sandbox deleted");
                Ok(self.load(id)?)
            }
            Err(e) => {
                let reason = format!("delete failed: {e}");
                warn!(sandbox = %id, error = %reason, "sandbox delete failed");
                self.store.set_sandbox_state(id, SandboxState::Deleting, None, Some(&reason))?;
                Err(Error::Backend(format!("delete sandbox {id}: {e}")))
            }
        }
    }

    pub async fn exec(&self, req: ExecRequest) -> Result<Execution> {
        self.check_serving()?;
        let timeout = self.check_exec(&req)?;
        let sandbox = self.load(&req.sandbox_id)?;
        ready(&sandbox)?;
        let slot = self.slot(&sandbox.id);
        let _guard = slot.exec_lock.lock().await;
        // The sandbox may have changed while this request waited its turn.
        let sandbox = self.load(&req.sandbox_id)?;
        ready(&sandbox)?;
        self.check_serving()?;
        let backend_id = sandbox.backend_id.clone().ok_or_else(|| Error::FailedPrecondition("sandbox has no backend ID".into()))?;

        let mut execution = Execution {
            id: new_id("ex"),
            sandbox_id: sandbox.id.clone(),
            argv: req.argv,
            state: ExecutionState::Running,
            exit_code: None,
            failure_reason: None,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            timeout_ms: timeout.as_millis() as u32,
            stdin_bytes: req.stdin.len() as u64,
            stdout: Captured::default(),
            stderr: Captured::default(),
        };
        self.store.insert_execution(&execution)?;
        let cancel = self.abort_executions.child_token();
        *slot.running.lock().unwrap() = Some(cancel.clone());
        info!(sandbox = %sandbox.id, execution = %execution.id, argc = execution.argv.len(), "exec started");

        let spec = ExecSpec { argv: &execution.argv, stdin: &req.stdin, timeout, max_output: self.limits.max_output_bytes };
        let outcome = self.runtime.exec(&backend_id, &spec, &cancel).await;
        slot.running.lock().unwrap().take();

        let (state, exit_code, reason) = match &outcome {
            Ok(o) => match o.finish {
                ExecFinish::Exited(code) => (ExecutionState::Exited, Some(code), None),
                ExecFinish::TimedOut => {
                    (ExecutionState::TimedOut, None, Some(format!("timed out after {} ms", timeout.as_millis())))
                }
                ExecFinish::Canceled => {
                    let why = if self.abort_executions.is_cancelled() { "kilnd shut down" } else { "sandbox deleted" };
                    (ExecutionState::Canceled, None, Some(why.to_string()))
                }
            },
            Err(e) => (ExecutionState::Failed, None, Some(e.to_string())),
        };
        let empty = Captured::default();
        let (stdout, stderr) = match &outcome {
            Ok(o) => (&o.stdout, &o.stderr),
            Err(_) => (&empty, &empty),
        };
        self.store.finish_execution(
            &execution.id,
            &ExecutionResult { state, exit_code, failure_reason: reason.as_deref(), stdout, stderr },
        )?;
        if let Err(RuntimeError::NotFound(_)) = &outcome {
            let why = format!("backend sandbox {backend_id} disappeared during an execution");
            warn!(sandbox = %sandbox.id, "{why}");
            self.store.set_sandbox_state(&sandbox.id, SandboxState::Lost, None, Some(&why))?;
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
        execution = self.store.execution(&execution.id)?.ok_or_else(|| anyhow::anyhow!("execution vanished"))?;
        Ok(execution)
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
        self.abort_executions.cancel();
    }

    fn check_exec(&self, req: &ExecRequest) -> Result<Duration> {
        if req.argv.is_empty() || req.argv[0].is_empty() {
            return Err(Error::InvalidArgument("argv must name a program".into()));
        }
        if req.argv.iter().any(|a| a.contains('\0')) {
            return Err(Error::InvalidArgument("argv must not contain NUL bytes".into()));
        }
        let size: usize = req.argv.iter().map(|a| a.len() + 1).sum();
        if size > self.limits.max_argv_bytes {
            return Err(Error::InvalidArgument(format!("argv is {size} bytes; the limit is {}", self.limits.max_argv_bytes)));
        }
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
        let image = if req.image.is_empty() { l.default_image.clone() } else { req.image };
        if image.len() > 128
            || image.starts_with(['.', '-'])
            || !image.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return invalid(format!("invalid image name {image:?}"));
        }
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
            return invalid(format!("memory {} is above the limit of {}", spec.memory_bytes, l.max_memory_bytes));
        }
        if spec.cpu_millis > l.max_cpu_millis {
            return invalid(format!("cpu {} millis is above the limit of {}", spec.cpu_millis, l.max_cpu_millis));
        }
        if spec.pids > l.max_pids {
            return invalid(format!("pids {} is above the limit of {}", spec.pids, l.max_pids));
        }
        if spec.disk_bytes > l.max_disk_bytes {
            return invalid(format!("disk {} is above the limit of {}", spec.disk_bytes, l.max_disk_bytes));
        }
        if let Network::Allow(allow) = &spec.network {
            if allow.is_empty() || allow.len() > MAX_ALLOW {
                return invalid(format!("an allowlist needs 1 to {MAX_ALLOW} entries"));
            }
            for a in allow {
                if a.is_empty()
                    || a.len() > 260
                    || a.starts_with('-')
                    || !a.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:/".contains(c))
                {
                    return invalid(format!("invalid allowlist entry {a:?}"));
                }
            }
        }
        if !spec.writable_paths.is_empty() && !spec.read_only_root {
            return invalid("writable_paths needs read_only_root".into());
        }
        if spec.writable_paths.len() > MAX_WRITABLE {
            return invalid(format!("at most {MAX_WRITABLE} writable paths"));
        }
        for p in &spec.writable_paths {
            if !p.starts_with('/')
                || p.len() > 1024
                || p.split('/').any(|part| part == "..")
                || p.chars().any(|c| c.is_control())
            {
                return invalid(format!("invalid writable path {p:?}"));
            }
        }
        if spec.labels.len() > MAX_LABELS {
            return invalid(format!("at most {MAX_LABELS} labels"));
        }
        for (k, v) in &spec.labels {
            if k.is_empty()
                || k.len() > 63
                || !k.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
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
        Err(Error::FailedPrecondition(format!("sandbox {} is {}, not ready", s.id, s.state.as_str())))
    }
}

fn backend(e: RuntimeError) -> Error {
    Error::Backend(e.to_string())
}

#[cfg(test)]
mod tests;
