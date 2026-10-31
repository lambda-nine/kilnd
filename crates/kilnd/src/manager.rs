//! The sandbox manager: validates requests, drives the runtime adapter and
//! records every transition in the store. The gRPC layer is a thin
//! translation on top of this.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use crate::admission::{Admission, AdmissionSnapshot};
use crate::model::{
    AccountingRegime, AllocationBinding, Captured, CleanupEvidence, CommandStatus, CreateCertainty,
    Digest, Execution, ExecutionState, Id128, Network, ReservationRelease, RuntimeDiagnostic,
    RuntimeErrorKind, RuntimeStage, Sandbox, SandboxAccounting, SandboxDisposition, SandboxSpec,
    SandboxState, new_id, now_ms, spec_digests, valid_id,
};
use crate::runtime::{
    AbsenceReceipt, AccountingAuthority, AllocationObservation, BackendRecord, BackendStatus,
    CreateContext, CreateFailure, CreatedSandbox, EvidenceRegime, ExecFinish, ExecOutcome,
    ExecSpec, ExecutionContext, FencedAbsence, MAX_BACKEND_PLAN_BYTES, PreparedCreate, Runtime,
    RuntimeCapabilities, RuntimeError, RuntimeReceipt,
};
use crate::store::{ExecutionResult, ReserveSandbox, SandboxBudgets, SandboxResources, Store};
use crate::validation::{
    MAX_ALLOWLIST_ENTRIES, MAX_WRITABLE_PATHS, validate_allowlist_entry, validate_argv,
    validate_image_name, validate_writable_path,
};

/// Limits and defaults; see `Config` in main.rs for the flags that set them.
#[derive(Clone, Debug)]
pub struct Limits {
    pub retention: crate::retention::Retention,
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
    pub max_node_memory_bytes: u64,
    pub max_node_pids: u64,
    pub max_node_disk_bytes: u64,
    /// Local policy for the host commitments only an allocation-token backend
    /// reserves. Legacy kiln rows reserve zero, so these never limit them.
    pub max_node_host_cpu_millis: u64,
    pub max_node_virtual_cpu_slots: u64,
    pub max_node_host_pids: u64,
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
            retention: crate::retention::Retention::default(),
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
            max_node_memory_bytes: 3 << 30,
            max_node_pids: 2048,
            max_node_disk_bytes: 16 << 30,
            max_node_host_cpu_millis: 3000,
            max_node_virtual_cpu_slots: 3,
            max_node_host_pids: 96,
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
    /// Create requests rejected by the durable sandbox reservation budgets.
    node_resource_rejections: AtomicU64,
    /// Reconciliation found backend resources it cannot attribute, so no new
    /// allocation may join them until a clean reconciliation.
    admission_blocked: AtomicBool,
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
    pub node_resources: NodeResourceSnapshot,
    pub capabilities: RuntimeCapabilities,
}

/// Where a Health report's node totals came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeAccountingStatus {
    /// This daemon's durable sum is the promise; CPU, vCPU and host PIDs are
    /// not reserved.
    LocalLegacy,
    /// A node authority owns totals and it cannot be read. `reserved` is then
    /// this daemon's local sum only and must not be presented as node totals.
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeResourceSnapshot {
    pub limits: SandboxBudgets,
    pub reserved: SandboxResources,
    pub rejected_creates: u64,
    pub accounting: NodeAccountingStatus,
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
    /// Rows whose release this pass committed with matching absence evidence.
    pub released: Vec<String>,
    pub quarantined: Vec<String>,
    pub admission_blocked: bool,
}

/// What reconciliation learned about one charged absence-fenced row, gathered
/// before any row or backend changes.
struct FencedEvidence {
    observation: AllocationObservation,
    healthy: bool,
    binding_error: Option<String>,
}

const MAX_LABELS: usize = 32;
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const CREATE_TIMEOUT: Duration = Duration::from_secs(120);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(120);
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const INSPECT_TIMEOUT: Duration = Duration::from_secs(5);
const FENCE_TIMEOUT: Duration = Duration::from_secs(30);

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
            node_resource_rejections: AtomicU64::new(0),
            admission_blocked: AtomicBool::new(false),
            started_at_ms: now_ms(),
        }
    }

    pub fn prune(&self) -> Result<crate::retention::Pruned> {
        Ok(self.store.prune(&self.limits.retention, now_ms())?)
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn store_resources_for_test(&self) -> SandboxResources {
        self.store.sandbox_resources().unwrap()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) fn admission(&self) -> &Arc<Admission> {
        &self.admission
    }

    fn sandbox_budgets(&self) -> SandboxBudgets {
        SandboxBudgets {
            sandboxes: u64::from(self.limits.max_sandboxes),
            memory_bytes: self.limits.max_node_memory_bytes,
            pids: self.limits.max_node_pids,
            disk_bytes: self.limits.max_node_disk_bytes,
            host_cpu_millis: self.limits.max_node_host_cpu_millis,
            virtual_cpu_slots: self.limits.max_node_virtual_cpu_slots,
            host_pids: self.limits.max_node_host_pids,
        }
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
        // Reconciliation may clean or explain only IDs whose lifecycle can
        // still own a backend. A compensated FAILED row retained for history
        // proved its former backend absent; if that ID reappears, it is
        // unmanaged rather than permission to hide or garbage-collect it.
        let mut known: HashSet<String> = self
            .store
            .owned_backend_ids(self.runtime.name())?
            .into_iter()
            .collect();
        // A charged allocation owns its token's backend ID before any publication.
        let fenced_ids: HashSet<String> = sandboxes
            .iter()
            .filter(|s| s.backend == self.runtime.name() && s.is_fenced() && s.is_charged())
            .filter_map(|s| {
                s.accounting
                    .allocation
                    .as_ref()
                    .map(AllocationBinding::backend_id)
            })
            .collect();
        let before_gc = self.validated_inventory(&sandboxes, &cancel).await?;
        // Prove the initial listing complete before even scoped backend
        // cleanup. A hidden reachable managed sandbox makes all evidence
        // suspect, while an explicit stale record is itself cleanup evidence.
        self.validate_reconciliation_evidence(&sandboxes, &before_gc, &cancel)
            .await?;
        let mut fenced_evidence = self.observe_fenced(&sandboxes, &before_gc, &cancel).await?;
        let mut stale_owned: Vec<String> = before_gc
            .iter()
            .filter(|(id, record)| {
                record.status == BackendStatus::Stale
                    && known.contains(*id)
                    && !fenced_ids.contains(*id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        stale_owned.sort();
        let gc_removed = if stale_owned.is_empty() {
            Vec::new()
        } else {
            let receipts = self
                .runtime
                .gc(&stale_owned, Instant::now() + LIST_TIMEOUT, &cancel)
                .await
                .map_err(backend)?;
            let requested: HashSet<_> = stale_owned.iter().cloned().collect();
            let mut reported = HashSet::new();
            let mut removed = Vec::new();
            for receipt in receipts {
                let AbsenceReceipt::Legacy(absence) = receipt else {
                    return Err(Error::Backend(
                        "backend garbage collection returned an allocation receipt for a legacy scope".into(),
                    ));
                };
                let id = absence.backend_id;
                if !requested.contains(&id) || !reported.insert(id.clone()) {
                    return Err(Error::Backend(format!(
                        "backend garbage collection reported sandbox {id} outside its unique requested scope"
                    )));
                }
                removed.push(id);
            }
            removed
        };
        let live = self.validated_inventory(&sandboxes, &cancel).await?;
        self.validate_reconciliation_evidence(&sandboxes, &live, &cancel)
            .await?;
        if let Some(id) = stale_owned
            .iter()
            .find(|id| live.get(*id).map(|r| r.status) == Some(BackendStatus::Stale))
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
            if s.is_fenced() {
                if let Some(evidence) = fenced_evidence.remove(&s.id) {
                    self.reconcile_fenced(s, evidence, &mut out).await?;
                }
                continue;
            }
            let alive = s
                .backend_id
                .as_ref()
                .and_then(|b| live.get(b))
                .map(|r| r.status)
                == Some(BackendStatus::Running);
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
                    .remove_legacy(b)
                    .await
                {
                    Ok(()) => {
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
                // An older interrupted Delete may have published intent for
                // an ambiguous no-ID create. Listing absence cannot clear it.
                (SandboxState::Deleting, None) => out.still_deleting.push(s.id),
                (SandboxState::Deleting, Some(_)) => {
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
                (
                    SandboxState::Deleted
                    | SandboxState::Failed
                    | SandboxState::Lost
                    | SandboxState::Quarantined,
                    _,
                ) => {}
            }
        }
        out.interrupted_executions += self.store.interrupt_running_executions_for_backend(
            self.runtime.name(),
            "kilnd stopped while the execution was running",
        )?;
        known.extend(fenced_ids);
        // An allocation record or Unknown entry no row explains may be live work
        // this daemon lost track of. Keep it, and stop admitting beside it.
        out.admission_blocked = live.iter().any(|(id, record)| {
            !known.contains(id)
                && (record.allocation_id.is_some() || record.status == BackendStatus::Unknown)
        });
        self.admission_blocked
            .store(out.admission_blocked, Ordering::Relaxed);
        out.unmanaged = live.into_keys().filter(|b| !known.contains(b)).collect();
        out.unmanaged.sort();
        for b in &out.unmanaged {
            warn!(backend_id = %b, "backend sandbox not created by kilnd; leaving it alone");
        }
        Ok(out)
    }

    /// A partial, duplicated or corrupt inventory proves nothing, so this fails
    /// before reconciliation can read any omission as absence or act on a record.
    async fn validated_inventory(
        &self,
        sandboxes: &[Sandbox],
        cancel: &CancellationToken,
    ) -> Result<HashMap<String, BackendRecord>> {
        let inventory = self
            .runtime
            .list(Instant::now() + LIST_TIMEOUT, cancel)
            .await
            .map_err(backend)?;
        if !inventory.complete {
            return Err(Error::Backend(format!(
                "backend inventory generation {} is incomplete",
                inventory.generation
            )));
        }
        let legacy_ids: HashSet<&str> = sandboxes
            .iter()
            .filter(|s| s.backend == self.runtime.name() && !s.is_fenced())
            .filter_map(|s| s.backend_id.as_deref())
            .collect();
        let mut records = HashMap::with_capacity(inventory.records.len());
        let mut allocations = HashSet::new();
        for record in inventory.records {
            let duplicate_allocation = record
                .allocation_id
                .is_some_and(|allocation| !allocations.insert(allocation));
            let mislabeled = record
                .allocation_id
                .is_some_and(|allocation| record.id != format!("fc-{allocation}"));
            if duplicate_allocation || mislabeled {
                return Err(Error::Backend(format!(
                    "backend inventory has a corrupt allocation record {}",
                    record.id
                )));
            }
            if legacy_ids.contains(record.id.as_str())
                && !matches!(record.status, BackendStatus::Running | BackendStatus::Stale)
            {
                return Err(Error::Backend(format!(
                    "backend inventory reports managed legacy sandbox {} as {:?}",
                    record.id, record.status
                )));
            }
            let id = record.id.clone();
            if records.insert(id.clone(), record).is_some() {
                return Err(Error::Backend(format!(
                    "backend inventory lists {id} more than once"
                )));
            }
        }
        Ok(records)
    }

    /// Gathers allocation-token evidence for every charged absence-fenced row, and
    /// fails with no mutation if any of it contradicts the inventory or the row.
    async fn observe_fenced(
        &self,
        sandboxes: &[Sandbox],
        inventory: &HashMap<String, BackendRecord>,
        cancel: &CancellationToken,
    ) -> Result<HashMap<String, FencedEvidence>> {
        let mut gathered = HashMap::new();
        for sandbox in sandboxes {
            if sandbox.backend != self.runtime.name()
                || !sandbox.is_fenced()
                || !sandbox.is_charged()
            {
                continue;
            }
            let binding = fenced_binding(sandbox)?;
            let binding_error = self.verify_fenced_binding(sandbox, binding).err();
            let observation = self
                .runtime
                .inspect_allocation(
                    &fenced_context(sandbox, binding),
                    &binding.plan_digest,
                    Instant::now() + INSPECT_TIMEOUT,
                    cancel,
                )
                .await
                .map_err(backend)?;
            let backend_id = binding.backend_id();
            let record = inventory.get(&backend_id);
            // Helper generations only move forward: an older answer than this row
            // already published contradicts the helper's own ledger.
            let recorded = sandbox.accounting.last_helper_generation.unwrap_or(0);
            let contradiction = match (&observation, record) {
                (AllocationObservation::Present { receipt, .. }, _)
                    if !receipt.matches(binding) =>
                {
                    Some("a ready receipt for another identity or plan")
                }
                (AllocationObservation::Present { receipt, .. }, _)
                    if receipt.validate().is_err() || receipt.helper_generation < recorded =>
                {
                    Some("a ready receipt with an invalid or older generation")
                }
                (AllocationObservation::StoppedWithResources { helper_generation }, _)
                    if *helper_generation < recorded =>
                {
                    Some("a stop observation older than this row's generation")
                }
                (AllocationObservation::AbsentFenced(receipt), _) if !receipt.matches(binding) => {
                    Some("an absence receipt for another identity or plan")
                }
                (AllocationObservation::AbsentFenced(receipt), _)
                    if receipt.helper_generation() <= recorded =>
                {
                    Some("an absence receipt not newer than this row's generation")
                }
                (
                    AllocationObservation::Present { .. }
                    | AllocationObservation::StoppedWithResources { .. },
                    None,
                ) => Some("a present allocation the inventory omitted"),
                (AllocationObservation::AbsentFenced(_), Some(_)) => {
                    Some("an absence receipt for an allocation the inventory lists")
                }
                (_, Some(r))
                    if r.allocation_id != Some(binding.allocation_id)
                        || r.plan_digest != Some(binding.plan_digest) =>
                {
                    Some("an inventory record for another identity or plan")
                }
                _ => None,
            };
            if let Some(contradiction) = contradiction {
                return Err(Error::Backend(format!(
                    "reconciliation evidence for {} shows {contradiction}",
                    sandbox.id
                )));
            }
            // A record that is not plainly ready, like Unknown, never reads as healthy.
            let healthy = match &observation {
                AllocationObservation::Present {
                    healthy_idle: true,
                    uncertain_execution: false,
                    ..
                } if record.is_some_and(|r| r.status == BackendStatus::Ready) => self
                    .runtime
                    .validate_sandbox(&backend_id, Instant::now() + INSPECT_TIMEOUT, cancel)
                    .await
                    .is_ok(),
                _ => false,
            };
            gathered.insert(
                sandbox.id.clone(),
                FencedEvidence {
                    observation,
                    healthy,
                    binding_error,
                },
            );
        }
        Ok(gathered)
    }

    /// Recomputes every stored commitment before trusting a row's plan: both spec
    /// digests, the plan digest and its bound, and this database's instance.
    fn verify_fenced_binding(
        &self,
        sandbox: &Sandbox,
        binding: &AllocationBinding,
    ) -> std::result::Result<(), String> {
        let accounting = &sandbox.accounting;
        if spec_digests(&sandbox.spec)
            != (
                accounting.host_spec_sha256,
                accounting.guest_exec_spec_sha256,
            )
        {
            return Err("stored spec does not match its digests".into());
        }
        if binding.plan.is_empty()
            || binding.plan.len() > MAX_BACKEND_PLAN_BYTES
            || Digest::of(&binding.plan) != binding.plan_digest
        {
            return Err("stored plan does not match its digest".into());
        }
        let identity = self.store.identity().map_err(|e| format!("{e:#}"))?;
        if binding.instance_id != identity.instance_id {
            return Err(format!(
                "row belongs to instance {}, not {}",
                binding.instance_id, identity.instance_id
            ));
        }
        Ok(())
    }

    /// One absence-fenced row's recovery, from evidence already validated. A RUNNING
    /// execution settles first and never reruns; nothing here resurrects a stopped
    /// boot, and the only release path is a matching receipt.
    async fn reconcile_fenced(
        &self,
        sandbox: Sandbox,
        evidence: FencedEvidence,
        out: &mut Reconciled,
    ) -> Result<()> {
        let id = sandbox.id.clone();
        let FencedEvidence {
            observation,
            healthy,
            binding_error,
        } = evidence;
        if self.store.has_running_execution(&id)? {
            let stopped = matches!(
                observation,
                AllocationObservation::StoppedWithResources { .. }
                    | AllocationObservation::AbsentFenced(_)
            );
            let reason = if stopped {
                "kilnd stopped while the execution was running; the host stopped this session"
            } else {
                "kilnd stopped while the execution was running; no stop barrier could be established"
            };
            out.interrupted_executions += self
                .store
                .conclude_running_executions(&id, stopped, reason)?;
        }
        let sandbox = self.load(&id).unwrap_or(sandbox);
        if let Some(why) = &binding_error {
            warn!(sandbox = %id, error = %why, "allocation binding failed verification");
            if !matches!(sandbox.state, SandboxState::Deleting | SandboxState::Failed) {
                self.store.set_sandbox_state(
                    &id,
                    SandboxState::Quarantined,
                    None,
                    Some(&format!("allocation binding failed verification: {why}")),
                )?;
                out.quarantined.push(id);
            }
            return Ok(());
        }
        if let AllocationObservation::AbsentFenced(receipt) = &observation {
            let terminal = if sandbox.state == SandboxState::Deleting {
                SandboxState::Deleted
            } else {
                SandboxState::Failed
            };
            self.store.release_fenced(
                &id,
                terminal,
                receipt,
                Some("the backend proved this allocation absent"),
            )?;
            if terminal == SandboxState::Deleted {
                out.deleted.push(id.clone());
            }
            out.released.push(id);
            return Ok(());
        }
        match sandbox.state {
            SandboxState::Creating => {
                // Adopt only the identical healthy boot. Anything partial or unknown
                // is compensated or fenced by exact token, never booted again.
                if let (true, AllocationObservation::Present { receipt, .. }) =
                    (healthy, &observation)
                {
                    let created = CreatedSandbox {
                        backend_id: fenced_binding(&sandbox)?.backend_id(),
                        receipt: RuntimeReceipt::Ready(receipt.clone()),
                    };
                    self.store.publish_fenced_ready(&id, &created)?;
                    out.recovered.push(id);
                    return Ok(());
                }
                self.store.compare_and_set_sandbox_state(
                    &id,
                    SandboxState::Creating,
                    SandboxState::Failed,
                    None,
                    Some("kilnd stopped while the sandbox was being created"),
                )?;
                out.failed.push(id.clone());
                let row = self.load(&id)?;
                self.settle_or_report(&row, SandboxState::Failed, out).await;
            }
            SandboxState::Ready => match &observation {
                AllocationObservation::Present { receipt, .. }
                    if healthy && sandbox.accounting.boot_id.as_ref() == Some(&receipt.boot_id) => {
                }
                AllocationObservation::StoppedWithResources { .. } => {
                    self.store.retire_sandbox(
                        &id,
                        SandboxDisposition::Stopped,
                        "no process remains for this session; its resources await Delete",
                    )?;
                    out.lost.push(id);
                }
                _ => {
                    self.store.retire_sandbox(
                        &id,
                        SandboxDisposition::Quarantined,
                        "this session's boot could not be established after restart",
                    )?;
                    out.quarantined.push(id);
                }
            },
            SandboxState::Deleting => {
                match self
                    .settle_fenced(&sandbox, SandboxState::Deleted, None)
                    .await
                {
                    Ok(()) => {
                        out.deleted.push(id.clone());
                        out.released.push(id);
                    }
                    Err(error) => {
                        self.store.compare_and_set_sandbox_state(
                            &id,
                            SandboxState::Deleting,
                            SandboxState::Deleting,
                            None,
                            Some(&format!("delete retry at startup failed: {error}")),
                        )?;
                        out.still_deleting.push(id);
                    }
                }
            }
            SandboxState::Failed => {
                self.settle_or_report(&sandbox, SandboxState::Failed, out)
                    .await;
            }
            // LOST and QUARANTINED wait for Delete; a charged row never self-heals.
            SandboxState::Lost | SandboxState::Quarantined | SandboxState::Deleted => {}
        }
        Ok(())
    }

    async fn settle_or_report(
        &self,
        sandbox: &Sandbox,
        terminal: SandboxState,
        out: &mut Reconciled,
    ) {
        match self.settle_fenced(sandbox, terminal, None).await {
            Ok(()) => out.released.push(sandbox.id.clone()),
            Err(error) => {
                warn!(sandbox = %sandbox.id, error = %error, "allocation stays charged; no matching absence proof");
            }
        }
    }

    /// Establishes absence for one exact token and commits it with the terminal
    /// row in one transaction. A present or stopped allocation goes through
    /// removal; one with no record through the fence. NotFound, an empty listing or
    /// a legacy proof can never produce the receipt this requires.
    async fn settle_fenced(
        &self,
        sandbox: &Sandbox,
        terminal: SandboxState,
        reason: Option<&str>,
    ) -> Result<()> {
        let binding = fenced_binding(sandbox)?;
        let context = fenced_context(sandbox, binding);
        let cancel = CancellationToken::new();
        let observation = self
            .runtime
            .inspect_allocation(
                &context,
                &binding.plan_digest,
                Instant::now() + INSPECT_TIMEOUT,
                &cancel,
            )
            .await
            .map_err(backend)?;
        let receipt = match observation {
            AllocationObservation::AbsentFenced(receipt) => AbsenceReceipt::Fenced(receipt),
            AllocationObservation::Present { .. }
            | AllocationObservation::StoppedWithResources { .. } => self
                .runtime
                .remove(
                    &binding.backend_id(),
                    Instant::now() + REMOVE_TIMEOUT,
                    &cancel,
                )
                .await
                .map_err(backend)?,
            AllocationObservation::Unknown { .. } => self
                .runtime
                .fence_absent(
                    &context,
                    &binding.plan_digest,
                    Instant::now() + FENCE_TIMEOUT,
                    &cancel,
                )
                .await
                .map_err(backend)?,
            AllocationObservation::Unsupported => {
                return Err(Error::Backend(format!(
                    "the {} backend cannot prove allocation {} absent",
                    self.runtime.name(),
                    binding.allocation_id
                )));
            }
        };
        let AbsenceReceipt::Fenced(receipt) = receipt else {
            return Err(Error::Backend(format!(
                "legacy removal proof cannot release allocation {}",
                binding.allocation_id
            )));
        };
        self.commit_absence(sandbox, binding, terminal, &receipt, reason)
    }

    fn commit_absence(
        &self,
        sandbox: &Sandbox,
        binding: &AllocationBinding,
        terminal: SandboxState,
        receipt: &FencedAbsence,
        reason: Option<&str>,
    ) -> Result<()> {
        if !receipt.matches(binding) {
            return Err(Error::Backend(format!(
                "absence receipt {} does not match allocation {}",
                receipt.receipt_id(),
                binding.allocation_id
            )));
        }
        self.store
            .release_fenced(&sandbox.id, terminal, receipt, reason)?;
        info!(sandbox = %sandbox.id, receipt = %receipt.receipt_id(), generation = receipt.helper_generation(), "allocation absence recorded");
        Ok(())
    }

    /// Legacy kiln's existing release standard: its strict removal, or its NotFound
    /// from the same probe. It releases only through the row's explicit legacy tag.
    async fn remove_legacy(&self, backend_id: &str) -> std::result::Result<(), RuntimeError> {
        match self
            .runtime
            .remove(
                backend_id,
                Instant::now() + REMOVE_TIMEOUT,
                &CancellationToken::new(),
            )
            .await
        {
            Ok(AbsenceReceipt::Legacy(absence)) if absence.backend_id == backend_id => Ok(()),
            Ok(_) => Err(RuntimeError::Backend(format!(
                "backend removal of {backend_id} returned a receipt for another identity"
            ))),
            Err(RuntimeError::NotFound(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn validate_reconciliation_evidence(
        &self,
        sandboxes: &[Sandbox],
        live: &HashMap<String, BackendRecord>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        // Check all candidates before any durable reconciliation mutation.
        // A complete list is necessary but not sufficient absence evidence:
        // independently probe any managed backend whose list record is
        // missing. A reachable backend proves the list was incomplete, so
        // startup must fail without changing the store or cleaning anything.
        for sandbox in sandboxes {
            if sandbox.backend != self.runtime.name() || sandbox.is_fenced() {
                continue;
            }
            let Some(id) = &sandbox.backend_id else {
                continue;
            };
            match (sandbox.state, live.get(id).map(|r| r.status)) {
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

    // Wake API waiters at the probe deadline, while the tracked operation keeps
    // owning cleanup. in_flight remains true, so no replacement probe can start.
    fn publish_health_failure_while_draining(&self, message: &str) {
        self.health_probe.lock().unwrap().cached = Some((Instant::now(), Err(message.into())));
        self.health_changed.notify_waiters();
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
                    if completed.elapsed() < ttl || (state.in_flight && result.is_err()) {
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
                                manager.publish_health_failure_while_draining("version probe timed out");
                                let _ = task.await;
                                Err("version probe timed out".into())
                            },
                            () = manager.shutting_down.cancelled() => {
                                cancel.cancel();
                                manager.publish_health_failure_while_draining("version probe canceled during shutdown");
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
        let (reserved, accounting_degraded) = self.store.accounting_snapshot()?;
        if accounting_degraded {
            serving = false;
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str("degraded accounting: invalid release evidence is quarantined and charged; admission disabled");
        }
        let limits = self.sandbox_budgets();
        let over_budget = [
            ("sandboxes", reserved.sandboxes, limits.sandboxes),
            ("memory bytes", reserved.memory_bytes, limits.memory_bytes),
            ("PIDs", reserved.pids, limits.pids),
            ("disk bytes", reserved.disk_bytes, limits.disk_bytes),
            (
                "host CPU millis",
                reserved.host_cpu_millis,
                limits.host_cpu_millis,
            ),
            (
                "vCPU slots",
                reserved.virtual_cpu_slots,
                limits.virtual_cpu_slots,
            ),
            ("host PIDs", reserved.host_pids, limits.host_pids),
        ]
        .into_iter()
        .filter(|(_, current, limit)| current > limit)
        .map(|(resource, current, limit)| format!("{resource} {current}/{limit}"))
        .collect::<Vec<_>>();
        if !over_budget.is_empty() {
            serving = false;
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&format!(
                "node sandbox reservations exceed configured budgets: {} (CreateSandbox is disabled until DeleteSandbox releases capacity)",
                over_budget.join(", ")
            ));
        }
        let capabilities = self.runtime.capabilities();
        let accounting = match capabilities.accounting {
            AccountingAuthority::LocalLegacy => NodeAccountingStatus::LocalLegacy,
            AccountingAuthority::Node => {
                serving = false;
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                detail.push_str("node accounting authority is unavailable");
                NodeAccountingStatus::Unavailable
            }
        };
        if self.admission_blocked.load(Ordering::Relaxed) {
            serving = false;
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail
                .push_str("backend resources no row explains block CreateSandbox until reconciled");
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
            node_resources: NodeResourceSnapshot {
                limits,
                reserved,
                rejected_creates: self.node_resource_rejections.load(Ordering::Relaxed),
                accounting,
            },
            capabilities,
        })
    }

    /// A trusted in-process create, owned by root. The RPC service uses
    /// [`Self::create_owned`] with the caller's kernel-reported uid instead.
    pub async fn create(self: &Arc<Self>, req: CreateRequest) -> Result<Sandbox> {
        self.create_owned(req, 0).await
    }

    /// Starts a daemon-owned create for `owner_uid` and waits for its result.
    /// Dropping this waiter does not cancel the operation: once admitted, the
    /// supervisor always publishes the backend ID or compensates by removing it.
    pub async fn create_owned(
        self: &Arc<Self>,
        req: CreateRequest,
        owner_uid: u32,
    ) -> Result<Sandbox> {
        // No await separates this check from task registration, so shutdown
        // cannot close and drain the tracker before an accepted task exists.
        self.check_serving()?;
        let (result_tx, result_rx) = oneshot::channel();
        let manager = Arc::clone(self);
        self.operations.spawn(async move {
            let result = manager.create_supervised(req, owner_uid).await;
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

    async fn create_supervised(
        self: Arc<Self>,
        req: CreateRequest,
        owner_uid: u32,
    ) -> Result<Sandbox> {
        self.check_serving()?;
        if self.admission_blocked.load(Ordering::Relaxed) {
            return Err(Error::FailedPrecondition(
                "backend resources no row explains block new sandboxes until reconciled".into(),
            ));
        }
        let spec = self.resolve_spec(req)?;
        let context = CreateContext {
            instance_id: self.store.identity()?.instance_id,
            allocation_id: Id128::random(),
            sandbox_id: new_id("sb"),
        };
        // C0: read-only preflight. A rejection here leaves no row and no charge.
        let prepared = self.prepare_create(&context, &spec).await;
        // Serving may have ended during that await. An operation tracked since
        // create_owned still refuses here, before any reservation or allocation.
        self.check_serving()?;
        let prepared = prepared?;
        let binding = prepared.binding(&context);
        let now = now_ms();
        let sandbox = Sandbox {
            id: context.sandbox_id.clone(),
            state: SandboxState::Creating,
            spec: prepared.spec().clone(),
            backend: self.runtime.name().to_string(),
            backend_id: None,
            created_at_ms: now,
            updated_at_ms: now,
            deleted_at_ms: None,
            failure_reason: None,
            create_certainty: CreateCertainty::AllocationAmbiguous,
            owner_uid,
            accounting: SandboxAccounting {
                regime: match prepared.regime() {
                    EvidenceRegime::LegacyLocal => AccountingRegime::Legacy,
                    EvidenceRegime::AbsenceFenced { .. } => AccountingRegime::AbsenceFenced,
                },
                reservation: prepared.reservation(),
                host_spec_sha256: prepared.host_spec_sha256(),
                guest_exec_spec_sha256: prepared.guest_exec_spec_sha256(),
                runtime_profile: prepared.runtime_profile().into(),
                runtime_artifact_digest: prepared.runtime_artifact_digest().into(),
                allocation: binding,
                boot_id: None,
                disposition: SandboxDisposition::Reusable,
                release: ReservationRelease::Charged,
                last_helper_generation: match prepared.regime() {
                    EvidenceRegime::LegacyLocal => None,
                    EvidenceRegime::AbsenceFenced { .. } => Some(0),
                },
            },
        };
        // C1: recorded before the backend runs, so a crash mid-create leaves a
        // trace for reconciliation. Count and every resource sum are checked with
        // this insert in one SQLite transaction.
        match self
            .store
            .reserve_sandbox(&sandbox, self.sandbox_budgets())?
        {
            ReserveSandbox::Inserted => {}
            ReserveSandbox::Exhausted(exhausted) => {
                self.node_resource_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(Error::ResourceExhausted(format!(
                    "node {} budget exhausted: {} reserved + {} requested exceeds limit {}",
                    exhausted.resource, exhausted.reserved, exhausted.requested, exhausted.limit
                )));
            }
        }
        info!(sandbox = %sandbox.id, image = %sandbox.spec.image, owner_uid, "creating sandbox");
        // Isolate a backend panic from the supervisor so the database still
        // reaches a terminal state. A backend that panics after making an
        // external resource but before returning its ID remains ambiguous by
        // the Runtime contract and is left for startup reconciliation to
        // report as unmanaged if it can still observe it.
        let backend_create = {
            let manager = Arc::clone(&self);
            let context = context.clone();
            let deadline = Instant::now() + CREATE_TIMEOUT;
            tokio::spawn(async move {
                manager
                    .runtime
                    .create(&context, &prepared, deadline, &CancellationToken::new())
                    .await
            })
        };
        let joined = backend_create.await;
        if sandbox.is_fenced() {
            return self.finish_fenced_create(sandbox, joined).await;
        }
        let created = match joined {
            Ok(result) => result,
            Err(join) => {
                let reason = join_reason(&join);
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
            Ok(created) => {
                let backend_id = created.backend_id;
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
                let id = sandbox.id.clone();
                let fallback = Sandbox {
                    backend_id: Some(backend_id),
                    state: SandboxState::Ready,
                    ..sandbox
                };
                Ok(self.store.sandbox(&id)?.unwrap_or(fallback))
            }
            Err(failure) => {
                let reason = failure.error().to_string();
                warn!(sandbox = %sandbox.id, error = %reason, certainty = failure.certainty().as_str(), "sandbox creation failed");
                // Capacity is released only by the durable certainty update.
                // If it fails, this returns with the row still CREATING and
                // charged, and restart turns it into an ambiguous FAILED.
                match failure.certainty() {
                    CreateCertainty::DefinitelyNotCreated => {
                        self.store.fail_create_definitely(&sandbox.id, &reason)?
                    }
                    CreateCertainty::AllocationAmbiguous => self.store.set_sandbox_state(
                        &sandbox.id,
                        SandboxState::Failed,
                        None,
                        Some(&reason),
                    )?,
                }
                Err(Error::Backend(format!(
                    "create sandbox {}: {reason}",
                    sandbox.id
                )))
            }
        }
    }

    /// C0. Runs in its own task so a panic stays a create error with no row, and
    /// the result must commit to the exact spec this daemon resolved.
    async fn prepare_create(
        self: &Arc<Self>,
        context: &CreateContext,
        spec: &SandboxSpec,
    ) -> Result<PreparedCreate> {
        let task = {
            let manager = Arc::clone(self);
            let (context, spec) = (context.clone(), spec.clone());
            let cancel = self.shutting_down.child_token();
            let deadline = Instant::now() + PREPARE_TIMEOUT;
            tokio::spawn(async move {
                manager
                    .runtime
                    .prepare(&context, &spec, deadline, &cancel)
                    .await
            })
        };
        let prepared = match task.await {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error @ (RuntimeError::Incompatible(_) | RuntimeError::Unsupported(_)))) => {
                return Err(Error::FailedPrecondition(error.to_string()));
            }
            Ok(Err(error)) => return Err(backend(error)),
            Err(join) => {
                let reason = if join.is_panic() {
                    "backend prepare task panicked"
                } else {
                    "backend prepare task was canceled"
                };
                return Err(Error::Backend(format!("prepare sandbox: {reason}")));
            }
        };
        if prepared.spec() != spec {
            return Err(Error::Backend(
                "backend prepared a plan for a different spec".into(),
            ));
        }
        Ok(prepared)
    }

    /// C6 through C8 for an allocation token. Only a matching ready receipt may
    /// publish READY, and only a matching absence receipt may release. A backend
    /// panic or error, or a definite claim without that receipt, stays charged.
    async fn finish_fenced_create(
        &self,
        sandbox: Sandbox,
        joined: std::result::Result<
            std::result::Result<CreatedSandbox, CreateFailure>,
            tokio::task::JoinError,
        >,
    ) -> Result<Sandbox> {
        let id = sandbox.id.clone();
        let binding = fenced_binding(&sandbox)?.clone();
        let reason = match joined {
            Ok(Ok(created)) => match ready_receipt_mismatch(&binding, &created) {
                None => {
                    if let Err(e) =
                        self.store
                            .publish_fenced_ready(&id, &created)
                            .and_then(|published| {
                                if published {
                                    Ok(())
                                } else {
                                    Err(anyhow::anyhow!("sandbox {id} left CREATING before READY"))
                                }
                            })
                    {
                        return Err(self.compensate_fenced_publication(&id, e).await);
                    }
                    info!(sandbox = %id, backend_id = %created.backend_id, "sandbox ready");
                    return self.load(&id);
                }
                Some(why) => format!("backend create returned {why}"),
            },
            Ok(Err(failure)) => {
                let reason = failure.error().to_string();
                if let Some(receipt) = failure.absence() {
                    match self.commit_absence(
                        &sandbox,
                        &binding,
                        SandboxState::Failed,
                        receipt,
                        Some(&reason),
                    ) {
                        Ok(()) => {
                            warn!(sandbox = %id, error = %reason, "create rejected with durable absence proof");
                            return Err(Error::Backend(format!("create sandbox {id}: {reason}")));
                        }
                        // An unusable receipt is no proof: charged like any failure.
                        Err(error) => {
                            warn!(sandbox = %id, error = %error, "create rejection carried unusable absence evidence");
                        }
                    }
                }
                reason
            }
            Err(join) => join_reason(&join).to_string(),
        };
        warn!(sandbox = %id, error = %reason, "sandbox creation failed; allocation stays charged");
        // Published first: the row is visibly FAILED and charged however long the
        // fence below takes, and if this write fails it stays CREATING and charged.
        self.store.compare_and_set_sandbox_state(
            &id,
            SandboxState::Creating,
            SandboxState::Failed,
            None,
            Some(&reason),
        )?;
        let row = self.load(&id)?;
        if let Err(error) = self.settle_fenced(&row, SandboxState::Failed, None).await {
            warn!(sandbox = %id, error = %error, "allocation stays charged; retry through Delete or reconciliation");
        }
        Err(Error::Backend(format!("create sandbox {id}: {reason}")))
    }

    /// C8: READY could not be persisted. Publish cleanup intent if possible, then
    /// remove by exact token; the row stays charged until the receipt commits.
    async fn compensate_fenced_publication(
        &self,
        sandbox_id: &str,
        publication: anyhow::Error,
    ) -> Error {
        let slot = self.slot(sandbox_id);
        let _guard = slot.exec_lock.lock().await;
        let reason = format!("record ready state failed: {publication:#}");
        if let Err(e) = self.store.compare_and_set_sandbox_state(
            sandbox_id,
            SandboxState::Creating,
            SandboxState::Deleting,
            None,
            Some(&reason),
        ) {
            warn!(sandbox = %sandbox_id, error = %format!("{e:#}"), "could not record create compensation intent");
        }
        let row = match self.load(sandbox_id) {
            Ok(row) => row,
            Err(error) => return error,
        };
        let finished = format!("{reason}; backend removed");
        match self
            .settle_fenced(&row, SandboxState::Failed, Some(&finished))
            .await
        {
            Ok(()) => {
                warn!(sandbox = %sandbox_id, "ready publication failed; allocation proved absent");
                Error::Internal(publication)
            }
            Err(cleanup) => {
                let reason = format!("{reason}; cleanup failed: {cleanup}");
                if let Err(e) = self.store.compare_and_set_sandbox_state(
                    sandbox_id,
                    SandboxState::Deleting,
                    SandboxState::Deleting,
                    None,
                    Some(&reason),
                ) {
                    warn!(sandbox = %sandbox_id, error = %format!("{e:#}"), "create compensation failure could not be recorded");
                }
                warn!(sandbox = %sandbox_id, error = %cleanup, "ready publication and compensation failed");
                Error::Internal(anyhow::anyhow!("{reason}"))
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

        match self.remove_legacy(backend_id).await {
            Ok(()) => {
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

    /// `owner` is `None` for root, which sees every sandbox, or one exact uid.
    pub(crate) fn list_page_owned(
        &self,
        include_deleted: bool,
        upper: Option<i64>,
        before: Option<i64>,
        limit: u32,
        owner: Option<u32>,
    ) -> Result<crate::store::SandboxPage> {
        Ok(self
            .store
            .sandbox_page_owned(include_deleted, upper, before, limit, owner)?)
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

    /// The sandbox, if `uid` may use it. A foreign sandbox fails exactly like a
    /// missing one, so callers cannot probe for other users' IDs. Owners never
    /// change, so this answer still holds for an operation that queues after it.
    pub(crate) fn authorize(&self, id: &str, uid: u32) -> Result<Sandbox> {
        let sandbox = self.load(id)?;
        if !may_use(&sandbox, uid) {
            return Err(Error::NotFound(format!("sandbox {id}")));
        }
        Ok(sandbox)
    }

    /// Decides access from the parent sandbox without reading stored output. A
    /// foreign execution fails exactly like a missing one and never names its
    /// parent.
    pub(crate) fn authorize_execution(&self, id: &str, uid: u32) -> Result<()> {
        if !valid_id("ex", id) {
            return Err(Error::InvalidArgument(format!(
                "invalid execution ID {id:?}"
            )));
        }
        let not_found = || Error::NotFound(format!("execution {id}"));
        let sandbox_id = self.store.execution_sandbox_id(id)?.ok_or_else(not_found)?;
        let sandbox = self.store.sandbox(&sandbox_id)?.ok_or_else(not_found)?;
        if !may_use(&sandbox, uid) {
            return Err(not_found());
        }
        Ok(())
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
            if sandbox.is_fenced() {
                // Every charged allocation can move to DELETING: without an ID it
                // can still be fenced by exact token. A released FAILED row needs
                // no backend work and keeps its evidence.
                let expected = match sandbox.state {
                    SandboxState::Deleted | SandboxState::Deleting => return Ok(sandbox),
                    SandboxState::Creating => {
                        return Err(Error::FailedPrecondition(format!(
                            "sandbox {id} is still being created; retry"
                        )));
                    }
                    expected => expected,
                };
                let next = if sandbox.is_charged() {
                    SandboxState::Deleting
                } else {
                    SandboxState::Deleted
                };
                if self.store.compare_and_set_sandbox_state(
                    id,
                    expected,
                    next,
                    None,
                    sandbox.failure_reason.as_deref(),
                )? {
                    return self.load(id);
                }
                sandbox = self.load(id)?;
                continue;
            }
            if sandbox.backend_id.is_none()
                && sandbox.create_certainty == CreateCertainty::AllocationAmbiguous
                && !matches!(
                    sandbox.state,
                    SandboxState::Deleted | SandboxState::Creating
                )
            {
                return Err(self.ambiguous_reservation_error(&sandbox));
            }
            match sandbox.state {
                SandboxState::Deleted | SandboxState::Deleting => return Ok(sandbox),
                // Its backend ID isn't known yet. If kilnd crashed mid-create,
                // startup reconciliation has already moved it to FAILED.
                SandboxState::Creating => {
                    return Err(Error::FailedPrecondition(format!(
                        "sandbox {id} is still being created; retry"
                    )));
                }
                SandboxState::Failed => {
                    // The ambiguous no-ID case was refused above. What is
                    // left never touches the backend: with an ID this is
                    // compensated history, including when compensation ended
                    // while Delete waited for the coordination lock, so never
                    // reassert ownership of the historical backend ID. Without
                    // one, the typed create result proved nothing was allocated.
                    if self.store.compare_and_set_sandbox_state(
                        id,
                        SandboxState::Failed,
                        SandboxState::Deleted,
                        None,
                        None,
                    )? {
                        return self.load(id);
                    }
                    sandbox = self.load(id)?;
                }
                expected @ (SandboxState::Ready
                | SandboxState::Lost
                | SandboxState::Quarantined) => {
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

        if sandbox.is_fenced() {
            return match self
                .settle_fenced(&sandbox, SandboxState::Deleted, None)
                .await
            {
                Ok(()) => {
                    info!(sandbox = %id, "sandbox deleted");
                    self.load(id)
                }
                Err(e) => {
                    let reason = format!("delete failed: {e}");
                    warn!(sandbox = %id, error = %reason, "sandbox delete failed; allocation stays charged");
                    self.store.compare_and_set_sandbox_state(
                        id,
                        SandboxState::Deleting,
                        SandboxState::Deleting,
                        None,
                        Some(&reason),
                    )?;
                    Err(Error::Backend(format!("delete sandbox {id}: {e}")))
                }
            };
        }

        let result = match &sandbox.backend_id {
            Some(b) => self.remove_legacy(b).await,
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

    /// The ordinary listing is not an inventory of hidden/unpublished
    /// resources. Only a typed create result can prove absence without an ID,
    /// so an ambiguous reservation must stay charged, even on an empty list.
    fn ambiguous_reservation_error(&self, sandbox: &Sandbox) -> Error {
        Error::FailedPrecondition(format!(
            "cannot release the ambiguous reservation for failed sandbox {}: no backend ID was reported; the {} backend listing cannot account for hidden or unpublished resources; authoritative resource reconciliation is required and is not currently supported",
            sandbox.id,
            self.runtime.name()
        ))
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
            sandbox_reusable: None,
            cleanup_evidence: CleanupEvidence::Unknown,
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
        let execution_context = ExecutionContext {
            execution_id: execution.id.clone(),
            execution_token: Id128::random(),
        };
        let mut backend = tokio::spawn(async move {
            if backend_cancel.token.is_cancelled() {
                return ExecOutcome {
                    finish: Ok(ExecFinish::Canceled),
                    command_status: None,
                    stdout: Captured::known_empty(),
                    stderr: Captured::known_empty(),
                    disposition: SandboxDisposition::Reusable,
                    cleanup: CleanupEvidence::NoChildStarted,
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
                .exec(
                    &backend_id_for_task,
                    &execution_context,
                    &spec,
                    &backend_cancel.token,
                )
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
                    // Legacy kiln keeps its existing behavior after an adapter
                    // panic, but records that nothing established cleanup. Any
                    // other regime retires the session below.
                    disposition: SandboxDisposition::Reusable,
                    cleanup: CleanupEvidence::Unknown,
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
        // Normalized first, so the terminal state can never read as a clean timeout,
        // cancellation or exit when the evidence for it did not hold.
        let (disposition, cleanup_evidence, sandbox_reusable) =
            normalize_exec_outcome(&sandbox, &mut outcome);
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
        let disposition_reason = match disposition {
            SandboxDisposition::Reusable => None,
            SandboxDisposition::Stopped if matches!(&outcome.finish, Err(d) if d.kind == RuntimeErrorKind::NotFound) => {
                Some(format!(
                    "backend sandbox {backend_id} disappeared during an execution"
                ))
            }
            SandboxDisposition::Stopped => Some(format!(
                "execution {} retired this session: its host stop barrier passed",
                execution.id
            )),
            SandboxDisposition::Quarantined => Some(format!(
                "execution {} could not establish cleanup; delete this sandbox",
                execution.id
            )),
        };
        if let Some(why) = &disposition_reason {
            warn!(sandbox = %sandbox.id, disposition = disposition.as_str(), "{why}");
        }
        let mut retry_delay = Duration::from_millis(10);
        let mut finalization_degraded = false;
        loop {
            match self.store.finish_execution_with_storage(
                &execution.id,
                &ExecutionResult {
                    state,
                    exit_code,
                    command_status: outcome.command_status.as_ref(),
                    runtime_error: outcome.finish.as_ref().err(),
                    failure_reason: reason.as_deref(),
                    stdout,
                    stderr,
                    sandbox_reusable,
                    cleanup_evidence,
                    disposition: Some(disposition),
                    disposition_reason: disposition_reason.as_deref(),
                },
                self.limits.retention.output_storage,
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
        // Retention is a storage policy. The waiting caller still receives the
        // captured bytes, even when history keeps metadata or no output.
        execution.stdout = outcome.stdout;
        execution.stderr = outcome.stderr;
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
        validate_argv(&req.argv, self.limits.max_argv_bytes).map_err(Error::InvalidArgument)?;
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

fn join_reason(join: &tokio::task::JoinError) -> &'static str {
    if join.is_panic() {
        "backend create task panicked"
    } else {
        "backend create task was canceled"
    }
}

fn fenced_binding(sandbox: &Sandbox) -> Result<&AllocationBinding> {
    sandbox.accounting.allocation.as_ref().ok_or_else(|| {
        Error::Internal(anyhow::anyhow!(
            "absence-fenced sandbox {} has no allocation identity",
            sandbox.id
        ))
    })
}

fn fenced_context(sandbox: &Sandbox, binding: &AllocationBinding) -> CreateContext {
    CreateContext {
        instance_id: binding.instance_id,
        allocation_id: binding.allocation_id,
        sandbox_id: sandbox.id.clone(),
    }
}

/// Why a create result cannot publish this allocation, if any.
fn ready_receipt_mismatch(
    binding: &AllocationBinding,
    created: &CreatedSandbox,
) -> Option<&'static str> {
    let RuntimeReceipt::Ready(receipt) = &created.receipt else {
        return Some("legacy evidence for an allocation token");
    };
    if !receipt.matches(binding) {
        return Some("a ready receipt for another identity or plan");
    }
    if created.backend_id != binding.backend_id() {
        return Some("a backend ID other than its allocation's");
    }
    if receipt.validate().is_err() {
        return Some("an invalid generation or boot identity");
    }
    None
}

/// Holds a runtime's claim to its evidence before it reaches the row. A legacy
/// claim passes through; its existing contract is what the disposition names, and
/// only `Unknown` cleanup, like an adapter panic, leaves reusability unknown. An
/// absence-fenced session is reusable only after a completed result, or with proof
/// that no child started. Anything weaker is quarantined.
fn settled_exec_evidence(
    sandbox: &Sandbox,
    outcome: &ExecOutcome,
) -> (SandboxDisposition, CleanupEvidence, Option<bool>) {
    use CleanupEvidence as Cleanup;
    use SandboxDisposition as Disposition;
    let (disposition, cleanup) = (outcome.disposition, outcome.cleanup);
    if !sandbox.is_fenced() {
        let reusable = match (disposition, cleanup) {
            (Disposition::Reusable, Cleanup::Unknown) => None,
            (Disposition::Reusable, _) => Some(true),
            _ => Some(false),
        };
        return (disposition, cleanup, reusable);
    }
    let completed = outcome.finish == Ok(ExecFinish::Completed);
    match (disposition, cleanup) {
        (Disposition::Reusable, Cleanup::RuntimeDrained) if completed => {
            (disposition, cleanup, Some(true))
        }
        (Disposition::Reusable, Cleanup::NoChildStarted) if !completed => {
            (disposition, cleanup, Some(true))
        }
        (Disposition::Stopped, Cleanup::SandboxStopped) => (disposition, cleanup, Some(false)),
        _ => (Disposition::Quarantined, Cleanup::Unknown, Some(false)),
    }
}

/// Settles an outcome's evidence and makes its result agree. A session quarantined
/// because its claim did not hold has no host stop barrier, so an otherwise clean
/// finish becomes CleanupFailed; status, captures and any existing failure stay.
fn normalize_exec_outcome(
    sandbox: &Sandbox,
    outcome: &mut ExecOutcome,
) -> (SandboxDisposition, CleanupEvidence, Option<bool>) {
    let settled = settled_exec_evidence(sandbox, outcome);
    if sandbox.is_fenced() && settled.0 == SandboxDisposition::Quarantined && outcome.finish.is_ok()
    {
        outcome.finish = Err(RuntimeDiagnostic::new(
            RuntimeErrorKind::CleanupFailed,
            RuntimeStage::Cleanup,
            "the backend reported this result without evidence that its cleanup held",
        ));
    }
    settled
}

/// The owner and root may use a sandbox; nobody else may.
fn may_use(sandbox: &Sandbox, uid: u32) -> bool {
    uid == 0 || sandbox.owner_uid == uid
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fenced_tests;
