//! The sandbox manager: validates requests, drives the runtime adapter and
//! records every transition in the store. The gRPC layer is a thin
//! translation on top of this.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use crate::admission::{Admission, AdmissionSnapshot};
use crate::expiry::{Clock, Due, ExpiryLimits, ExpiryQueue, RequestedExpiry, SystemClock};
use crate::model::{
    AccountingRegime, AllocationBinding, CancelReason, Captured, CleanupEvidence, CommandStatus,
    CreateCertainty, DeletionReason, Digest, Execution, ExecutionState, Id128, Network,
    ReservationRelease, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage, Sandbox,
    SandboxAccounting, SandboxDisposition, SandboxLifecycle, SandboxSpec, SandboxState, new_id,
    now_ms, spec_digests, valid_id,
};
use crate::runtime::{
    AbsenceReceipt, AccountingAuthority, AllocationObservation, BackendRecord, BackendStatus,
    CreateContext, CreateFailure, CreatedSandbox, EvidenceRegime, ExecFinish, ExecOutcome,
    PrepareContext, RemoveTarget,
    ExecSpec, ExecutionContext, FencedAbsence, MAX_BACKEND_PLAN_BYTES, NodeTotals, PreparedCreate,
    Runtime, RuntimeCapabilities, RuntimeError, RuntimeReceipt,
};
use crate::store::{
    ExecutionResult, ReleaseRequestId, RequestAdmission, ReserveSandbox, SandboxBudgets,
    SandboxResources, Store,
};
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
    /// Connection slots, of `max_connections`, held back for Health and cleanup RPCs
    /// (B7, B6-BI-03); each UID may hold one.
    pub reserved_connections: usize,
    /// General connection slots one UID may hold: by default half of the general pool,
    /// so no one UID holds most of it.
    pub max_connections_per_uid: usize,
    /// How long an accepted connection may take to send the HTTP/2 client preface.
    pub connection_preface_timeout: Duration,
    pub max_concurrent_rpcs: usize,
    /// Ordinary RPC permits one UID may hold: by default half of them.
    pub max_concurrent_rpcs_per_uid: usize,
    /// The cleanup lane (GetSandbox and DeleteSandbox once the ordinary lane refuses
    /// them); each UID may hold one.
    pub max_concurrent_cleanup: usize,
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
    /// Sandbox expiry flags (API additions design, section 7).
    pub expiry: ExpiryLimits,
    /// Create request record caps (design 3.3); retention is in `retention`.
    pub create_requests: CreateRequestLimits,
    /// `--max-exec-cwd-bytes` (design 7), at most the 4,096-byte ceiling.
    pub max_exec_cwd_bytes: usize,
    /// `--max-exec-env-*`, for a request's env, a sandbox's default env and their merge.
    pub exec_env: crate::exec_env::EnvLimits,
    /// ExecStream (design 5.1 and 7): `--default-stream-timeout-secs` and
    /// `--max-stream-timeout-secs`, both within the helper's four-hour live ceiling.
    pub default_stream_timeout: Duration,
    pub max_stream_timeout: Duration,
    /// `--max-exec-streams` (below the global Exec tickets) and
    /// `--max-exec-streams-per-uid` (below that).
    pub max_exec_streams: usize,
    pub max_exec_streams_per_uid: usize,
    /// `--exec-stream-buffer-bytes` and `--exec-stream-chunk-bytes`.
    pub exec_stream: crate::exec_stream::StreamBuffer,
}

/// `--max-create-requests-per-uid` and `--max-create-requests`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateRequestLimits {
    pub max_per_uid: u64,
    pub max_node: u64,
}

impl Default for CreateRequestLimits {
    fn default() -> Self {
        Self {
            max_per_uid: 4096,
            max_node: 32_768,
        }
    }
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
            reserved_connections: 4,
            max_connections_per_uid: 32,
            connection_preface_timeout: Duration::from_secs(5),
            max_concurrent_rpcs: 64,
            max_concurrent_rpcs_per_uid: 32,
            max_concurrent_cleanup: 4,
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
            expiry: ExpiryLimits::default(),
            create_requests: CreateRequestLimits::default(),
            max_exec_cwd_bytes: crate::exec_env::MAX_CWD_BYTES,
            exec_env: crate::exec_env::EnvLimits::CEILINGS,
            default_stream_timeout: Duration::from_secs(1800),
            max_stream_timeout: Duration::from_secs(7200),
            max_exec_streams: 16,
            max_exec_streams_per_uid: 8,
            exec_stream: crate::exec_stream::StreamBuffer::default(),
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
    /// `CreateSandboxRequest.expiry` if sent; `None` never expires (decision 2).
    pub expiry: Option<RequestedExpiry>,
    /// `CreateSandboxRequest.default_env` as sent; values are redacted from `Debug`.
    pub default_env: Vec<crate::exec_env::EnvVar>,
}

/// A keyed create's identity within its owner's scope (design 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateKey {
    /// Already checked by `idempotency::validate_request_id`.
    pub request_id: String,
    /// `idempotency::request_digest` of the request as sent.
    pub sha256: Digest,
}

pub struct ExecRequest {
    pub sandbox_id: String,
    pub argv: Vec<String>,
    pub stdin: Vec<u8>,
    /// Zero means the default.
    pub timeout_ms: u32,
    /// Empty: `/`, kiln's operation 4 as before (design 4).
    pub cwd: String,
    /// Overrides over the sandbox's default env; values never leave this request.
    pub env: Vec<crate::exec_env::EnvVar>,
}

/// One admitted execution's options (design 4): what kiln gets, and what history
/// keeps instead of the values.
struct ResolvedOptions {
    options: crate::exec_env::ExecOptions,
    env_names: Vec<String>,
    env_sha256: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    FailedPrecondition(Refusal),
    #[error("{0}")]
    ResourceExhausted(String),
    #[error("{0}")]
    DeadlineExceeded(String),
    #[error("kilnd is shutting down")]
    ShuttingDown,
    #[error("{0}")]
    Backend(String),
    /// A typed refusal with a code other than FAILED_PRECONDITION (design section 1).
    #[error("{1}")]
    Refused(RefusalCode, Refusal),
    /// Two keyed attempts reached the admitting transaction together and this one lost
    /// on the primary key; it answers again from the in-flight lookup. Never leaves
    /// the manager.
    #[error("another create recorded this request ID first")]
    RequestIdTaken,
    #[error("internal error: {0:#}")]
    Internal(#[from] anyhow::Error),
}

/// The gRPC code of an [`Error::Refused`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCode {
    AlreadyExists,
    ResourceExhausted,
    DeadlineExceeded,
    Unavailable,
    /// `backend_unsupported:<feature>` (design section 1).
    Unimplemented,
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// A refusal's message and, for the typed ones (API additions design, section 1),
/// its stable `kilnd-reason` token. It derefs to the message alone; it displays as
/// `<token>: <message>`, which is also the status message the API sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    reason: Option<&'static str>,
    message: String,
}

impl Refusal {
    pub fn typed(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason: Some(reason),
            message: message.into(),
        }
    }

    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<String> for Refusal {
    fn from(message: String) -> Self {
        Self {
            reason: None,
            message,
        }
    }
}

impl From<&str> for Refusal {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

impl std::ops::Deref for Refusal {
    type Target = str;

    fn deref(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            Some(reason) => write!(f, "{reason}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// The typed reason a non-READY sandbox refuses Exec and Renew (design section 1):
/// a DELETING or retained DELETED row's deletion reason, else its state.
pub fn not_ready_reason(s: &Sandbox) -> &'static str {
    match s.state {
        SandboxState::Deleting | SandboxState::Deleted => match s.lifecycle.deletion_reason {
            Some(DeletionReason::ExpiredIdle) => "expired_idle",
            Some(DeletionReason::ExpiredLifetime) => "expired_lifetime",
            Some(DeletionReason::Requested) | None => "sandbox_deleted",
        },
        SandboxState::Failed => "sandbox_failed",
        SandboxState::Lost => "sandbox_lost",
        SandboxState::Quarantined => "sandbox_quarantined",
        SandboxState::Creating | SandboxState::Ready => "sandbox_not_ready",
    }
}

/// Features this daemon's code and flags provide, fixed for the process.
pub const STATIC_FEATURES: [Feature; 4] = [
    Feature::SandboxExpiry,
    Feature::IdempotentCreate,
    Feature::TypedReasons,
    Feature::RequestIdRelease,
];

/// An optional API part, in `kilnd.v1.Feature` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    SandboxExpiry,
    IdempotentCreate,
    ExecCwd,
    ExecEnv,
    SandboxDefaultEnv,
    ExecStream,
    TypedReasons,
    RequestIdRelease,
}

/// Facts the backend proved in its latest successful probe (design section 1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProvenFeatures(pub Vec<Feature>);

/// Per-sandbox coordination: executions in one sandbox run one at a time
/// (kiln's PID 1 serves them serially anyway), and delete can cancel the one
/// running.
struct Slot {
    exec_lock: tokio::sync::Mutex<()>,
    running: Mutex<Option<Arc<ExecCancellation>>>,
    outstanding_execs: Arc<Semaphore>,
    capacity: usize,
    /// The admission gate (Daybreak recheck MEDIUM 1): Exec rechecks READY and takes
    /// its outstanding permit while holding it, and idle expiry holds it with the
    /// exec lock from its all-permits-free check through its delete-intent CAS, so a
    /// newly admitted request and an idle expiry cannot both win. Nothing awaits
    /// while it is held.
    admission: Mutex<()>,
}

impl Slot {
    fn new(capacity: usize) -> Self {
        Self {
            exec_lock: tokio::sync::Mutex::new(()),
            running: Mutex::new(None),
            outstanding_execs: Arc::new(Semaphore::new(capacity)),
            capacity,
            admission: Mutex::new(()),
        }
    }

    /// An execution is running or an admitted request is queued.
    fn busy(&self) -> bool {
        self.outstanding_execs.available_permits() != self.capacity
    }
}

/// How an admission is waited for, before the supervisor exists.
enum Waiting {
    Unary(oneshot::Sender<Result<Execution>>),
    Stream {
        start: oneshot::Sender<Result<StreamStart>>,
        uid: u32,
        rpc: Option<crate::admission::RpcPermit>,
    },
}

/// Who waits for one admitted execution: a unary Exec's reply, or an ExecStream's start
/// signal and then its live queue (design 5).
enum ExecWaiter {
    Unary(oneshot::Sender<Result<Execution>>),
    Stream(StreamWaiter),
}

struct StreamWaiter {
    /// Taken when the row exists; until then a refusal goes back through it.
    start: Option<oneshot::Sender<Result<StreamStart>>>,
    queue: Arc<crate::exec_stream::LiveQueue>,
    /// The RPC permit and the stream permit, released with the ticket at handoff.
    _permits: (
        Option<crate::admission::RpcPermit>,
        crate::admission::SharedPermit,
    ),
}

/// An ExecStream whose execution row exists: what `ExecStarted` carries, and the handle
/// the RPC drains. Dropping the handle is the client's disconnect.
pub struct StreamStart {
    pub execution_id: String,
    pub sandbox_id: String,
    pub started_at_ms: i64,
    pub timeout_ms: u32,
    pub handle: crate::exec_stream::StreamHandle,
}

impl ExecWaiter {
    fn mode(&self) -> crate::model::ExecutionMode {
        match self {
            Self::Unary(_) => crate::model::ExecutionMode::Unary,
            Self::Stream(_) => crate::model::ExecutionMode::Stream,
        }
    }

    /// Resolves when the caller is gone: a unary waiter's receiver, a stream's start
    /// receiver before its row, its handle after.
    async fn closed(&mut self) {
        match self {
            Self::Unary(reply) => reply.closed().await,
            Self::Stream(StreamWaiter {
                start: Some(start), ..
            }) => start.closed().await,
            Self::Stream(StreamWaiter { queue, .. }) => queue.disconnected().await,
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Self::Unary(reply) => reply.is_closed(),
            Self::Stream(StreamWaiter {
                start: Some(start), ..
            }) => start.is_closed(),
            Self::Stream(StreamWaiter { queue, .. }) => queue.is_disconnected(),
        }
    }

    fn live(&self) -> Option<Arc<dyn crate::exec_stream::LiveTap>> {
        match self {
            Self::Unary(_) => None,
            Self::Stream(stream) => {
                Some(Arc::clone(&stream.queue) as Arc<dyn crate::exec_stream::LiveTap>)
            }
        }
    }

    /// The row exists: a stream's `ExecStarted`. If the RPC is already gone the start
    /// (and its handle) is dropped here, which is the disconnect.
    fn started(&mut self, execution: &Execution) {
        if let Self::Stream(stream) = self
            && let Some(start) = stream.start.take()
        {
            let _ = start.send(Ok(StreamStart {
                execution_id: execution.id.clone(),
                sandbox_id: execution.sandbox_id.clone(),
                started_at_ms: execution.started_at_ms,
                timeout_ms: execution.timeout_ms,
                handle: stream.queue.handle(),
            }));
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
    cached: Option<(Instant, std::result::Result<Probed, String>)>,
    in_flight: bool,
}

/// One shared Health probe: the backend version and, for a backend with a node
/// authority, that authority's totals or why they could not be read.
#[derive(Clone, Debug)]
struct Probed {
    version: String,
    node: Option<std::result::Result<(NodeTotals, i64), String>>,
    /// The dynamic features this probe proved.
    dynamic: ProvenFeatures,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecCancelReason {
    ClientGone,
    SandboxDeleted,
    Shutdown,
    ExpiredLifetime,
}

impl ExecCancelReason {
    fn message(self) -> &'static str {
        match self {
            Self::ClientGone => "client disconnected",
            Self::SandboxDeleted => "sandbox deleted",
            Self::Shutdown => "kilnd shut down",
            Self::ExpiredLifetime => "sandbox reached its max_lifetime",
        }
    }

    fn typed(self) -> CancelReason {
        match self {
            Self::ClientGone => CancelReason::ClientDisconnected,
            Self::SandboxDeleted => CancelReason::SandboxDeleted,
            Self::Shutdown => CancelReason::DaemonShutdown,
            Self::ExpiredLifetime => CancelReason::SandboxExpiredLifetime,
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
    /// The clocks expiry reads; the store stamps anchors with the same one.
    clock: Arc<dyn Clock>,
    expiry: Mutex<ExpiryState>,
    expiry_changed: Notify,
    /// Expiry removals running at once (`--max-concurrent-expiry-deletes`).
    expiry_deletes: Arc<Semaphore>,
    expired_idle: AtomicU64,
    expired_lifetime: AtomicU64,
    failed_expiry_deletes: AtomicU64,
    /// The dynamic feature set: empty at startup, set by a successful probe and
    /// cleared by any other result (design section 1, fail closed).
    dynamic_features: Mutex<ProvenFeatures>,
    /// Keyed creates in flight and their pending quota slots (design 3.1).
    keyed: Arc<Mutex<KeyedCreates>>,
    create_retries_answered: AtomicU64,
    request_ids_released: AtomicU64,
    rejected_create_requests: AtomicU64,
    #[cfg(test)]
    idle_commit_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

/// The in-flight map keyed by `(owner_uid, request_id)`, and the keyed creates that
/// hold a pending quota slot. One mutex, never held across an await.
#[derive(Default)]
struct KeyedCreates {
    in_flight: HashMap<(u32, String), InFlight>,
    pending_node: u64,
    pending_by_uid: HashMap<u32, u64>,
}

/// One registered keyed create: its digest and a watch that closes when the create
/// operation has fully finished (READY published, or FAILED published and its fence or
/// compensation done).
struct InFlight {
    sha256: Digest,
    /// Retries subscribe; removing the entry drops it and closes every subscription.
    done: watch::Sender<()>,
}

/// Held by the create operation: dropping it removes the in-flight entry, which
/// closes the watch, so a woken waiter's next lookup sees the settled record.
struct InFlightGuard {
    keyed: Arc<Mutex<KeyedCreates>>,
    key: (u32, String),
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let entry = self
            .keyed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_flight
            .remove(&self.key);
        drop(entry);
    }
}

/// A pending keyed-create quota slot (design 3.1 step 4). It bounds concurrent keyed
/// creates and reserves no ID; it is returned on every exit, cancellation included,
/// once the admitting transaction has recounted the durable records.
struct PendingSlot {
    keyed: Arc<Mutex<KeyedCreates>>,
    uid: u32,
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        let mut keyed = self.keyed.lock().unwrap_or_else(|e| e.into_inner());
        keyed.pending_node = keyed.pending_node.saturating_sub(1);
        if let Some(count) = keyed.pending_by_uid.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                keyed.pending_by_uid.remove(&self.uid);
            }
        }
    }
}

/// What a keyed create carries into its supervised operation.
struct KeyedOperation {
    request_id: String,
    sha256: Digest,
    pending: Option<PendingSlot>,
}

/// What steps 3 to 5 decided for a keyed create.
enum KeyedAdmit {
    /// A stored record with an equal digest: its settled row.
    Answered(Box<Sandbox>),
    /// A fresh attempt, registered and holding a pending slot.
    Registered {
        guard: InFlightGuard,
        pending: PendingSlot,
        req: Box<CreateRequest>,
    },
}

fn request_id_conflict(request_id: &str) -> Error {
    Error::Refused(
        RefusalCode::AlreadyExists,
        Refusal::typed(
            "request_id_conflict",
            format!("request_id {request_id:?} was used for a different create request"),
        ),
    )
}

/// `AdmissionStats` fields 21-25.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateRequestStats {
    pub max_node: u64,
    pub node: u64,
    pub max_per_uid: u64,
    pub caller: u64,
    pub rejected: u64,
}

/// The sweeper's state: the queue, delete retries and the restart grace.
#[derive(Default)]
struct ExpiryState {
    queue: ExpiryQueue,
    /// Expiry deletes published and not yet DELETED, by sandbox key.
    pending: HashMap<u64, PendingDelete>,
    /// Idle deadlines never fall before this boottime (`--expiry-restart-grace-secs`).
    grace_until: i64,
    /// The queue's bound (Daybreak recheck LOW 1): one entry per durable reservation,
    /// which admission holds at `--max-sandboxes` except that reservations made under
    /// a higher earlier cap remain until they drain. So the bound is
    /// `max(--max-sandboxes, reservations at startup)`.
    bound: usize,
}

struct PendingDelete {
    /// The boottime of the persisted expiry intent (MEDIUM 1): a restart keeps it.
    since: i64,
    failures: u32,
    retry_at: i64,
    /// An attempt holds an expiry removal permit: a worker's or a joined Delete's.
    running: bool,
    /// Due, but every permit was taken. It has no queue entry and no task; a
    /// returned permit starts it (break-it HIGH 1).
    waiting: bool,
}

/// Who runs `delete_inner`: a client Delete (which joins an expiry-owned removal
/// under the expiry permit) or an expiry worker already holding that permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeleteRole {
    Client,
    ExpiryWorker,
}

fn expiry_owned(s: &Sandbox) -> bool {
    s.state == SandboxState::Deleting
        && matches!(
            s.lifecycle.deletion_reason,
            Some(DeletionReason::ExpiredIdle | DeletionReason::ExpiredLifetime)
        )
}

/// A client Delete following an expiry removal: it holds one expiry permit for its
/// attempt and, if no expiry attempt was running, that slot's attempt too. Dropping
/// it, on completion or cancellation, settles the attempt, returns the permit and
/// starts a waiting removal.
struct ExpiryJoin<R: Runtime + 'static> {
    manager: Arc<Manager<R>>,
    id: String,
    key: u64,
    permit: Option<OwnedSemaphorePermit>,
    claimed: bool,
    /// The attempt's result, or `None` if the caller was canceled first.
    outcome: Option<bool>,
}

impl<R: Runtime + 'static> Drop for ExpiryJoin<R> {
    fn drop(&mut self) {
        if self.claimed {
            self.manager
                .settle_expiry_attempt(&self.id, self.key, self.outcome);
        }
        drop(self.permit.take());
        self.manager.start_waiting_expiry_removals();
    }
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
    /// Static features plus the dynamic ones currently proven, in enum order.
    pub features: Vec<Feature>,
    pub lifecycle: LifecycleSnapshot,
}

/// Expiry counters since startup, for `HealthResponse.lifecycle`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LifecycleSnapshot {
    pub expired_idle: u64,
    pub expired_lifetime: u64,
    pub pending_expiry_deletes: u32,
    pub failed_expiry_deletes: u64,
    pub create_retries_answered: u64,
    pub request_ids_released: u64,
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
    /// `limits` and `reserved` are the node authority's own totals, at its snapshot
    /// generation, read during the shared Health probe at `observed_at_ms`.
    Authoritative {
        generation: u64,
        observed_at_ms: i64,
    },
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
        let clock: Arc<dyn Clock> = match SystemClock::new() {
            Ok(clock) => Arc::new(clock),
            Err(error) => panic!("read the kernel boot ID: {error}"),
        };
        Self::with_clock(runtime, store, limits, clock)
    }

    /// As [`Self::new`], with the clocks expiry reads.
    pub fn with_clock(runtime: R, store: Store, limits: Limits, clock: Arc<dyn Clock>) -> Self {
        store.set_clock(clock.clone());
        Self {
            expiry: Mutex::new(ExpiryState {
                bound: limits.max_sandboxes as usize,
                ..ExpiryState::default()
            }),
            expiry_changed: Notify::new(),
            expiry_deletes: Arc::new(Semaphore::new(limits.expiry.max_concurrent_deletes)),
            expired_idle: AtomicU64::new(0),
            expired_lifetime: AtomicU64::new(0),
            failed_expiry_deletes: AtomicU64::new(0),
            dynamic_features: Mutex::new(ProvenFeatures::default()),
            keyed: Arc::new(Mutex::new(KeyedCreates::default())),
            create_retries_answered: AtomicU64::new(0),
            request_ids_released: AtomicU64::new(0),
            rejected_create_requests: AtomicU64::new(0),
            #[cfg(test)]
            idle_commit_hook: Mutex::new(None),
            clock,
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
    pub(crate) fn store_set_state_for_test(&self, id: &str, state: SandboxState) {
        self.store.set_sandbox_state(id, state, None, None).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn store_retire_for_test(&self, id: &str, disposition: SandboxDisposition) {
        self.store
            .retire_sandbox(id, disposition, "retired by a test")
            .unwrap();
    }

    #[cfg(test)]
    pub(crate) fn store_for_test(&self) -> &Store {
        &self.store
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
            // Only legacy rows reach Gc (fenced rows recover by exact token), and each
            // target is the Store's own: never List inventory or a cache.
            let targets: Vec<RemoveTarget<'_>> = stale_owned
                .iter()
                .map(|backend_id| RemoveTarget::Legacy { backend_id })
                .collect();
            let receipts = self
                .runtime
                .gc(&targets, Instant::now() + LIST_TIMEOUT, &cancel)
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
                        exec_features: None,
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
                    RemoveTarget::Fenced { binding },
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
                RemoveTarget::Legacy { backend_id },
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
        *self.dynamic_features.lock().unwrap() = ProvenFeatures::default();
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
                            let runtime = &runtime_manager.runtime;
                            let version = runtime.version(deadline, &probe_cancel).await?;
                            let dynamic = runtime.proven_features(deadline, &probe_cancel).await?;
                            // A node authority's totals are read in the same bounded probe,
                            // so Health never presents this daemon's local sum as the node's.
                            let node = match runtime.capabilities().accounting {
                                AccountingAuthority::LocalLegacy => None,
                                AccountingAuthority::Node => Some(
                                    match runtime.node_totals(deadline, &probe_cancel).await {
                                        Ok(Some(totals)) => Ok((totals, now_ms())),
                                        Ok(None) => {
                                            Err("the backend reports no node totals".to_string())
                                        }
                                        Err(error) => Err(error.to_string()),
                                    },
                                ),
                            };
                            Ok::<_, RuntimeError>(Probed {
                                version,
                                node,
                                dynamic,
                            })
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
                            // Fail closed: only a fresh success republishes dynamic features.
                            *manager.dynamic_features.lock().unwrap() = match &result {
                                Ok(probed) => probed.dynamic.clone(),
                                Err(_) => ProvenFeatures::default(),
                            };
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
        let (mut serving, backend_version, node, mut detail) = match probe {
            Ok(probed) => (true, probed.version, probed.node, String::new()),
            Err(e) => (false, String::new(), None, format!("backend: {e}")),
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
        let (mut limits, mut reserved) = (limits, reserved);
        let accounting = match (capabilities.accounting, node) {
            (AccountingAuthority::LocalLegacy, _) => NodeAccountingStatus::LocalLegacy,
            (AccountingAuthority::Node, Some(Ok((totals, observed_at_ms)))) => {
                if totals.over_committed {
                    serving = false;
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    detail.push_str(
                        "node commitments exceed its ceilings (lowered?); the node admits nothing new",
                    );
                }
                if let Some(kind) = &totals.node_fault {
                    serving = false;
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    detail.push_str(&format!(
                        "node fault ({kind}): every forward effect is latched node-wide until root's offline inventory and clear-node-faults"
                    ));
                }
                if let Some(reason) = &totals.degraded {
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    detail.push_str(&format!("node ledger degraded: {reason}"));
                }
                limits = totals.limits;
                reserved = totals.reserved;
                NodeAccountingStatus::Authoritative {
                    generation: totals.generation,
                    observed_at_ms,
                }
            }
            (AccountingAuthority::Node, unavailable) => {
                serving = false;
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                match unavailable {
                    Some(Err(why)) => {
                        detail.push_str(&format!("node accounting authority is unavailable: {why}"))
                    }
                    _ => detail.push_str("node accounting authority is unavailable"),
                }
                NodeAccountingStatus::Unavailable
            }
        };
        // B7 (design 16.6): under a node-authority backend, rows of another backend
        // never drain; Health says how many are still charged.
        if capabilities.accounting == AccountingAuthority::Node {
            let foreign = self
                .store
                .sandboxes(true)?
                .iter()
                .filter(|s| s.backend != self.runtime.name() && s.is_charged())
                .count();
            if foreign != 0 {
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                detail.push_str(&format!(
                    "{foreign} charged row(s) of another backend cannot drain under {}: delete them with that backend selected",
                    self.runtime.name()
                ));
            }
        }
        if self.admission_blocked.load(Ordering::Relaxed) {
            serving = false;
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail
                .push_str("backend resources no row explains block CreateSandbox until reconciled");
        }
        let lifecycle = self.lifecycle_snapshot();
        let stale = self.stale_expiry_deletes();
        if stale != 0 {
            serving = false;
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&format!(
                "{stale} expiry delete(s) pending longer than {} s; their sandboxes stay charged",
                self.limits.expiry.degraded_after.as_secs()
            ));
        }
        Ok(Health {
            features: self.features(),
            lifecycle,
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
            let result = Arc::clone(&manager)
                .create_supervised(req, owner_uid, None, &OnceLock::new())
                .await;
            if let Ok(sandbox) = &result {
                manager.expiry_refresh(&sandbox.id);
            }
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

    /// A keyed create (design 3.1). `req` is the converted request, or why it is
    /// invalid: validation runs only after the lookups, so a retry finds an accepted
    /// request even if a node limit changed since. `deadline` is the RPC's own, from
    /// `grpc-timeout`. Once the create's row commits, the original call and every retry
    /// return `OK` with the settled row, whatever its state.
    pub async fn create_keyed(
        self: &Arc<Self>,
        req: std::result::Result<CreateRequest, String>,
        owner_uid: u32,
        key: CreateKey,
        deadline: Option<Instant>,
    ) -> Result<Sandbox> {
        let map_key = (owner_uid, key.request_id.clone());
        loop {
            let (guard, pending, admitted) = loop {
                // Steps 2 to 5 run under one lock with no await, so a lookup that
                // finds nothing is followed by this attempt's registration before any
                // other attempt can look.
                let mut done = {
                    let mut keyed = self.keyed.lock().unwrap();
                    match keyed.in_flight.get(&map_key) {
                        Some(entry) if entry.sha256 != key.sha256 => {
                            return Err(request_id_conflict(&key.request_id));
                        }
                        Some(entry) => entry.done.subscribe(),
                        None => match self.admit_keyed(&mut keyed, &req, owner_uid, &key)? {
                            KeyedAdmit::Answered(sandbox) => return Ok(*sandbox),
                            KeyedAdmit::Registered {
                                guard,
                                pending,
                                req,
                            } => break (guard, pending, *req),
                        },
                    }
                };
                // Step 2: wait for the original within this retry's own deadline, then
                // look again. The watch closes when the operation has fully finished;
                // dropping this future (a canceled RPC) leaves nothing behind.
                let finished = done.changed();
                match deadline {
                    Some(deadline) => {
                        if tokio::time::timeout_at(deadline, finished).await.is_err() {
                            return Err(Error::Refused(
                                RefusalCode::DeadlineExceeded,
                                Refusal::typed(
                                    "create_in_flight",
                                    format!(
                                        "the create with request_id {:?} is still running; retry to get its result",
                                        key.request_id
                                    ),
                                ),
                            ));
                        }
                    }
                    None => {
                        let _ = finished.await;
                    }
                }
            };
            let (result_tx, result_rx) = oneshot::channel();
            let manager = Arc::clone(self);
            let keyed = KeyedOperation {
                request_id: key.request_id.clone(),
                sha256: key.sha256,
                pending: Some(pending),
            };
            self.operations.spawn(async move {
                let committed = OnceLock::new();
                let result = Arc::clone(&manager)
                    .create_supervised(admitted, owner_uid, Some(keyed), &committed)
                    .await;
                // The same answer for the original and every retry: once the row
                // committed, the settled row, never the error the backend gave.
                let result = match committed.get() {
                    Some(id) => manager.load(id).and_then(|row| manager.settled_keyed(row)),
                    None => result,
                };
                if let Ok(sandbox) = &result {
                    manager.expiry_refresh(&sandbox.id);
                }
                // The operation has fully finished: send waiters to the store.
                drop(guard);
                if let Err(result) = result_tx.send(result) {
                    match result {
                        Ok(sandbox) => info!(sandbox = %sandbox.id, "create RPC stopped waiting; keyed operation completed"),
                        Err(error) => warn!(error = %error, "create RPC stopped waiting; keyed operation failed"),
                    }
                }
            });
            match result_rx.await.map_err(|_| {
                Error::Internal(anyhow::anyhow!("create supervisor stopped without a result"))
            })? {
                // Design 3.1: the loser of a primary-key race allocated nothing and
                // answers from step 2, which now finds the winner's record.
                Err(Error::RequestIdTaken) => continue,
                other => return other,
            }
        }
    }

    /// Design 3.1 steps 3 to 5, under the keyed lock: the stored record, then the
    /// feature gates, validation, serving check and pending quota, then registration.
    fn admit_keyed(
        &self,
        keyed: &mut KeyedCreates,
        req: &std::result::Result<CreateRequest, String>,
        owner_uid: u32,
        key: &CreateKey,
    ) -> Result<KeyedAdmit> {
        // Step 3. Answered during shutdown too.
        if let Some((sha256, row)) = self.store.create_request(owner_uid, &key.request_id)? {
            if sha256 != key.sha256 {
                return Err(request_id_conflict(&key.request_id));
            }
            self.create_retries_answered
                .fetch_add(1, Ordering::Relaxed);
            return self
                .settled_keyed(row)
                .map(|row| KeyedAdmit::Answered(Box::new(row)));
        }
        // Step 4: a fresh attempt.
        let req = req.clone().map_err(Error::InvalidArgument)?;
        crate::expiry::resolve_expiry(req.expiry, &self.limits.expiry)
            .map_err(Error::InvalidArgument)?;
        self.check_default_env(&req.default_env)?;
        self.resolve_spec(req.clone())?;
        self.check_serving()?;
        let durable = self.store.create_request_counts(owner_uid)?;
        let limits = self.limits.create_requests;
        let pending_uid = keyed.pending_by_uid.get(&owner_uid).copied().unwrap_or(0);
        let refused = if durable.uid.saturating_add(pending_uid) >= limits.max_per_uid {
            Some(("uid", durable.uid.saturating_add(pending_uid), limits.max_per_uid))
        } else if durable.node.saturating_add(keyed.pending_node) >= limits.max_node {
            Some((
                "node",
                durable.node.saturating_add(keyed.pending_node),
                limits.max_node,
            ))
        } else {
            None
        };
        if let Some((scope, count, limit)) = refused {
            return Err(self.request_quota_error(scope, count, limit));
        }
        keyed.pending_node += 1;
        *keyed.pending_by_uid.entry(owner_uid).or_insert(0) += 1;
        let pending = PendingSlot {
            keyed: Arc::clone(&self.keyed),
            uid: owner_uid,
        };
        // Step 5.
        let map_key = (owner_uid, key.request_id.clone());
        keyed.in_flight.insert(
            map_key.clone(),
            InFlight {
                sha256: key.sha256,
                done: watch::Sender::new(()),
            },
        );
        let guard = InFlightGuard {
            keyed: Arc::clone(&self.keyed),
            key: map_key,
        };
        Ok(KeyedAdmit::Registered {
            guard,
            pending,
            req: Box::new(req),
        })
    }

    /// A keyed row as the original and its retries return it. A CREATING row with no
    /// live operation (only if a store write failed mid-create; reconciliation settles
    /// it at the next start) is never answered as a fresh create.
    fn settled_keyed(&self, row: Sandbox) -> Result<Sandbox> {
        if row.state == SandboxState::Creating {
            warn!(sandbox = %row.id, "keyed create row is CREATING with no live create operation");
            return Err(Error::Refused(
                RefusalCode::Unavailable,
                Refusal::typed(
                    "create_unsettled",
                    format!(
                        "sandbox {} is still CREATING with no live create; it settles at the next kilnd start",
                        row.id
                    ),
                ),
            ));
        }
        Ok(row)
    }

    fn request_quota_error(&self, scope: &str, count: u64, limit: u64) -> Error {
        self.rejected_create_requests
            .fetch_add(1, Ordering::Relaxed);
        Error::Refused(
            RefusalCode::ResourceExhausted,
            Refusal::typed(
                "request_id_quota",
                format!(
                    "create request records at the {scope} cap: {count} retained or pending of {limit}; release or wait for retention"
                ),
            ),
        )
    }

    async fn create_supervised(
        self: Arc<Self>,
        mut req: CreateRequest,
        owner_uid: u32,
        mut keyed: Option<KeyedOperation>,
        committed: &OnceLock<String>,
    ) -> Result<Sandbox> {
        self.check_serving()?;
        if self.admission_blocked.load(Ordering::Relaxed) {
            return Err(Error::FailedPrecondition(
                "backend resources no row explains block new sandboxes until reconciled".into(),
            ));
        }
        // Resolved once, before preparation: an invalid policy allocates nothing.
        let expiry = crate::expiry::resolve_expiry(req.expiry, &self.limits.expiry)
            .map_err(Error::InvalidArgument)?;
        // Design 6: an unproven default env is refused here, before prepare (which on
        // Firecracker issues a token) and before any row.
        let default_env = std::mem::take(&mut req.default_env);
        let (default_env_names, default_env_sha256) = self.check_default_env(&default_env)?;
        let spec = self.resolve_spec(req)?;
        // Design 9.1 (B7): preparation names no allocation. A fenced backend's
        // authority issues the token inside its preflight (RTC-2).
        let prepare_context = PrepareContext {
            instance_id: self.store.identity()?.instance_id,
            sandbox_id: new_id("sb"),
        };
        // C0: read-only preflight. A rejection here leaves no row and no charge.
        let prepared = self.prepare_create(&prepare_context, &spec).await;
        // Serving may have ended during that await. An operation tracked since
        // create_owned still refuses here, before any reservation or allocation.
        self.check_serving()?;
        let prepared = prepared?;
        // Built after preparation and before C1: the helper's token for a fenced plan,
        // or for kiln a legacy random ID that records no allocation. The manager never
        // invents a fenced token, and a plan whose token contradicts its regime stops here.
        let allocation_id = match (prepared.regime(), prepared.allocation_id()) {
            (EvidenceRegime::AbsenceFenced { .. }, Some(token)) => token,
            (EvidenceRegime::LegacyLocal, None) => Id128::random(),
            _ => {
                return Err(Error::Backend(
                    "the backend's plan and its allocation token disagree".into(),
                ));
            }
        };
        let context = CreateContext {
            instance_id: prepare_context.instance_id,
            allocation_id,
            sandbox_id: prepare_context.sandbox_id,
        };
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
            lifecycle: SandboxLifecycle {
                expiry,
                request_id: keyed.as_ref().map(|k| k.request_id.clone()),
                default_env_names,
                default_env_sha256,
                ..SandboxLifecycle::default()
            },
        };
        let admission = keyed.as_ref().map(|k| RequestAdmission {
            sha256: k.sha256,
            max_per_uid: self.limits.create_requests.max_per_uid,
            max_node: self.limits.create_requests.max_node,
        });
        // C1: recorded before the backend runs, so a crash mid-create leaves a
        // trace for reconciliation. Count and every resource sum are checked with
        // this insert in one SQLite transaction; for a keyed create, so are the
        // durable request records, and the record commits with the row.
        let reserved = self.store.reserve_sandbox_with_env(
            &sandbox,
            self.sandbox_budgets(),
            admission.as_ref(),
            &default_env,
        );
        drop(default_env);
        // The durable count now holds whatever this transaction did.
        if let Some(keyed) = keyed.as_mut() {
            drop(keyed.pending.take());
        }
        match reserved? {
            ReserveSandbox::Inserted => {
                let _ = committed.set(sandbox.id.clone());
            }
            ReserveSandbox::RequestQuota(quota) => {
                return Err(self.request_quota_error(quota.scope, quota.count, quota.limit));
            }
            ReserveSandbox::RequestIdTaken => return Err(Error::RequestIdTaken),
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
                // Design 4.1: a sandbox whose defaults only reach kiln through exec
                // options is published only with its runtime's proof of them. A failed
                // or older probe removes the backend and settles the create FAILED.
                if let Some(why) = unproven_default_env(&sandbox, created.exec_features) {
                    return Err(self
                        .compensate_unproven_features(&sandbox.id, &backend_id, &why)
                        .await);
                }
                // Design 4.1: the runtime's exec feature bits, recorded with READY.
                if let Err(e) = self.store.publish_legacy_ready(
                    &sandbox.id,
                    &backend_id,
                    created.exec_features,
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
        context: &PrepareContext,
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
                return Err(Error::FailedPrecondition(error.to_string().into()));
            }
            // Refused before any backend effect (B7: the Firecracker digest cache's cap).
            Ok(Err(RuntimeError::Exhausted(reason))) => {
                return Err(Error::ResourceExhausted(format!("prepare sandbox: {reason}")));
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
        // Design 9.2: a node that refused for capacity is RESOURCE_EXHAUSTED, once the
        // row has done what any post-C1 refusal must.
        let exhausted = matches!(&joined, Ok(Err(failure)) if failure.is_exhausted());
        let refused = |reason: String| {
            if exhausted {
                self.node_resource_rejections
                    .fetch_add(1, Ordering::Relaxed);
                Error::ResourceExhausted(format!("create sandbox {id}: {reason}"))
            } else {
                Error::Backend(format!("create sandbox {id}: {reason}"))
            }
        };
        let mut probe_failed = false;
        let reason = match joined {
            Ok(Ok(created)) => match (
                ready_receipt_mismatch(&binding, &created),
                unproven_default_env(&sandbox, created.exec_features),
            ) {
                // Design 4.1, as for a legacy create: no READY without the proof its
                // defaults need. The allocation settles below like any failed create.
                (None, Some(why)) => {
                    probe_failed = true;
                    format!("{SANDBOX_FEATURE_PROBE_FAILED}: {why}")
                }
                (None, None) => {
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
                (Some(why), _) => format!("backend create returned {why}"),
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
                            return Err(refused(reason));
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
        if probe_failed {
            return Err(feature_probe_refusal(&id));
        }
        Err(refused(reason))
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
        let publication_reason = format!("record ready state failed: {publication:#}");
        match self
            .compensate_legacy_create(sandbox_id, backend_id, &publication_reason)
            .await
        {
            Ok(()) => {
                warn!(sandbox = %sandbox_id, backend_id = %backend_id, "ready publication failed; removed backend sandbox");
                Error::Internal(publication)
            }
            Err(reason) => {
                warn!(sandbox = %sandbox_id, backend_id = %backend_id, "ready publication and compensation failed");
                Error::Internal(anyhow::anyhow!("{reason}"))
            }
        }
    }

    /// Design 4.1: the new sandbox did not prove the exec options its default env
    /// needs, so it is never READY. Its backend is removed as for a failed publication,
    /// and the create answers with a typed, retryable refusal; a keyed create's
    /// original and retries answer with the FAILED row instead.
    async fn compensate_unproven_features(
        &self,
        sandbox_id: &str,
        backend_id: &str,
        why: &str,
    ) -> Error {
        let reason = format!("{SANDBOX_FEATURE_PROBE_FAILED}: {why}");
        warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %reason, "sandbox creation failed");
        if let Err(cleanup) = self
            .compensate_legacy_create(sandbox_id, backend_id, &reason)
            .await
        {
            // Left DELETING and charged, which Delete or reconciliation retries.
            warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %cleanup, "unproven sandbox could not be removed");
        }
        feature_probe_refusal(sandbox_id)
    }

    /// A legacy create's compensation once its backend exists: cleanup intent as
    /// DELETING with `reason`, removal, then FAILED (which releases the reservation and
    /// clears the default env). A failed removal stays DELETING and charged, and its
    /// recorded reason is the error.
    async fn compensate_legacy_create(
        &self,
        sandbox_id: &str,
        backend_id: &str,
        reason: &str,
    ) -> std::result::Result<(), String> {
        let slot = self.slot(sandbox_id);
        let _guard = slot.exec_lock.lock().await;
        if let Err(e) = self.store.set_sandbox_state(
            sandbox_id,
            SandboxState::Deleting,
            Some(backend_id),
            Some(reason),
        ) {
            warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "could not record create compensation intent");
        }

        match self.remove_legacy(backend_id).await {
            Ok(()) => {
                let reason = format!("{reason}; backend removed");
                if let Err(e) = self.store.set_sandbox_state(
                    sandbox_id,
                    SandboxState::Failed,
                    Some(backend_id),
                    Some(&reason),
                ) {
                    warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "backend removed but create failure could not be finalized");
                }
                Ok(())
            }
            Err(cleanup) => {
                let reason = format!("{reason}; cleanup failed: {cleanup}");
                if let Err(e) = self.store.set_sandbox_state(
                    sandbox_id,
                    SandboxState::Deleting,
                    Some(backend_id),
                    Some(&reason),
                ) {
                    warn!(sandbox = %sandbox_id, backend_id = %backend_id, error = %format!("{e:#}"), "create compensation failure could not be recorded");
                }
                Err(reason)
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
                        return Err(Error::FailedPrecondition(
                            format!("sandbox {id} is still being created; retry").into(),
                        ));
                    }
                    expected => expected,
                };
                let next = if sandbox.is_charged() {
                    SandboxState::Deleting
                } else {
                    SandboxState::Deleted
                };
                if self.store.publish_delete_intent(
                    id,
                    expected,
                    next,
                    sandbox.failure_reason.as_deref(),
                    DeletionReason::Requested,
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
                    return Err(Error::FailedPrecondition(
                        format!("sandbox {id} is still being created; retry").into(),
                    ));
                }
                SandboxState::Failed => {
                    // The ambiguous no-ID case was refused above. What is
                    // left never touches the backend: with an ID this is
                    // compensated history, including when compensation ended
                    // while Delete waited for the coordination lock, so never
                    // reassert ownership of the historical backend ID. Without
                    // one, the typed create result proved nothing was allocated.
                    if self.store.publish_delete_intent(
                        id,
                        SandboxState::Failed,
                        SandboxState::Deleted,
                        None,
                        DeletionReason::Requested,
                    )? {
                        return self.load(id);
                    }
                    sandbox = self.load(id)?;
                }
                expected @ (SandboxState::Ready
                | SandboxState::Lost
                | SandboxState::Quarantined) => {
                    if self.store.publish_delete_intent(
                        id,
                        expected,
                        SandboxState::Deleting,
                        sandbox.failure_reason.as_deref(),
                        DeletionReason::Requested,
                    )? {
                        return self.load(id);
                    }
                    sandbox = self.load(id)?;
                }
            }
        }
    }

    /// DeleteSandbox with `release_request_id` (design 3.4). Delete runs exactly as
    /// without it. Only if the row it leaves is DELETED does one transaction that sees
    /// it DELETED drop the create request record; a DELETING row (a failed removal or
    /// a follower that returned early) releases nothing and remembers nothing.
    pub async fn delete_releasing(self: &Arc<Self>, id: &str, release: bool) -> Result<Sandbox> {
        let sandbox = self.delete(id).await?;
        if !release || sandbox.state != SandboxState::Deleted {
            return Ok(sandbox);
        }
        match self.store.release_request_id(id)? {
            ReleaseRequestId::Released => {
                self.request_ids_released.fetch_add(1, Ordering::Relaxed);
                info!(sandbox = %id, request_id = ?sandbox.lifecycle.request_id, "request ID released");
                self.load(id)
            }
            ReleaseRequestId::NoRecord | ReleaseRequestId::NotDeleted => Ok(sandbox),
            // A prune won the race: absence, like any pruned ID.
            ReleaseRequestId::NoSandbox => Err(Error::NotFound(format!("sandbox {id}"))),
        }
    }

    pub async fn delete(self: &Arc<Self>, id: &str) -> Result<Sandbox> {
        let result = self.delete_inner(id, DeleteRole::Client).await;
        // A finished delete leaves no timer; a failed one keeps its retry if expiry owns it.
        self.expiry_refresh(id);
        result
    }

    async fn delete_inner(self: &Arc<Self>, id: &str, role: DeleteRole) -> Result<Sandbox> {
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
        // Break-it HIGH 1: once the first-wins reason is an expiry's, this caller is
        // a follower of that expiry removal and every backend removal it runs counts
        // against `--max-concurrent-expiry-deletes`. It takes the same permit (and,
        // when no expiry attempt is running, the slot's attempt) before the exec lock.
        let join = match role {
            DeleteRole::Client if expiry_owned(&sandbox) => {
                Some(self.join_expiry_removal(id).await?)
            }
            DeleteRole::Client | DeleteRole::ExpiryWorker => None,
        };
        let result = self.remove_deleting(id, &slot).await;
        if let Some(mut join) = join {
            join.outcome = Some(matches!(&result, Ok(s) if s.state == SandboxState::Deleted));
        }
        result
    }

    /// The backend removal of a row this caller has moved to, or found, DELETING.
    async fn remove_deleting(&self, id: &str, slot: &Slot) -> Result<Sandbox> {
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
        ).into())
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
        let (result_tx, result_rx) = oneshot::channel();
        self.admit_exec(req, received_at, Waiting::Unary(result_tx))?;
        result_rx.await.map_err(|_| {
            Error::Internal(anyhow::anyhow!("exec supervisor stopped without a result"))
        })?
    }

    /// ExecStream without an RPC permit, as `exec` is Exec without one (direct callers
    /// and tests): everything else as [`Self::exec_stream_received`].
    pub async fn exec_stream(self: &Arc<Self>, req: ExecRequest, uid: u32) -> Result<StreamStart> {
        self.exec_stream_inner(req, Instant::now(), uid, None).await
    }

    /// ExecStream (design 5): the same validation, gates, sandbox checks and admission
    /// as Exec, in the same order, plus a stream permit for `uid`. It returns once the
    /// execution row exists; every refusal before that is an error and nothing was
    /// allocated. The RPC permit is held, with the stream permit and the Exec ticket,
    /// until the final message is handed to the transport.
    pub(crate) async fn exec_stream_received(
        self: &Arc<Self>,
        req: ExecRequest,
        received_at: Instant,
        uid: u32,
        rpc: crate::admission::RpcPermit,
    ) -> Result<StreamStart> {
        self.exec_stream_inner(req, received_at, uid, Some(rpc))
            .await
    }

    async fn exec_stream_inner(
        self: &Arc<Self>,
        req: ExecRequest,
        received_at: Instant,
        uid: u32,
        rpc: Option<crate::admission::RpcPermit>,
    ) -> Result<StreamStart> {
        let (start_tx, start_rx) = oneshot::channel();
        self.admit_exec(
            req,
            received_at,
            Waiting::Stream {
                start: start_tx,
                uid,
                rpc,
            },
        )?;
        start_rx.await.map_err(|_| {
            Error::Internal(anyhow::anyhow!(
                "exec stream supervisor stopped without starting"
            ))
        })?
    }

    /// Validation, feature gates, sandbox checks and admission, then the supervisor.
    /// Nothing here awaits, so a refusal allocates nothing and shutdown cannot drain
    /// the tracker between admission and registration.
    fn admit_exec(
        self: &Arc<Self>,
        req: ExecRequest,
        received_at: Instant,
        waiting: Waiting,
    ) -> Result<()> {
        self.check_serving()?;
        let stream = matches!(waiting, Waiting::Stream { .. });
        let timeout = self.check_exec(&req, stream)?;
        let deadline = received_at
            .checked_add(timeout)
            .ok_or_else(|| Error::InvalidArgument("timeout deadline overflow".into()))?;
        let sandbox = self.load(&req.sandbox_id)?;
        ready(&sandbox)?;
        // Design 4.1 and 6: every exec-options refusal precedes admission, so nothing
        // is allocated: no ticket, no row and no backend call.
        let resolved = self.resolve_exec_options(&req, &sandbox)?;
        let slot = self.slot(&sandbox.id);
        // A stream's own permit first, so a stream refused for the stream caps counts
        // only there and holds nothing else (design 5.1).
        let stream_permit = match &waiting {
            Waiting::Stream { uid, .. } => {
                Some(self.admission.try_stream(Some(*uid)).map_err(|_| {
                    Error::Refused(
                        RefusalCode::ResourceExhausted,
                        Refusal::typed(
                            "exec_stream_limit",
                            format!(
                                "ExecStream limit reached ({} on the node, {} per uid)",
                                self.limits.max_exec_streams, self.limits.max_exec_streams_per_uid
                            ),
                        ),
                    )
                })?)
            }
            Waiting::Unary(_) => None,
        };
        let global = self.admission.try_exec().map_err(|_| {
            Error::ResourceExhausted(format!(
                "global Exec admission limit ({}) reached",
                self.limits.max_concurrent_execs
            ))
        })?;
        let outstanding = {
            // MEDIUM 1: READY is rechecked and the permit taken under the gate idle
            // expiry holds from its all-permits-free check through its CAS. Either this
            // admission wins and expiry re-arms, or expiry wins and this request sees its
            // typed reason without ever being admitted.
            let _gate = slot.admission.lock().unwrap_or_else(|e| e.into_inner());
            ready(&self.load(&req.sandbox_id)?)?;
            slot.outstanding_execs
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    self.admission.reject_sandbox_exec();
                    Error::ResourceExhausted(format!(
                        "sandbox Exec capacity reached (one running plus {} queued)",
                        self.limits.max_queued_execs_per_sandbox
                    ))
                })?
        };
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
        let waiter = match waiting {
            Waiting::Unary(reply) => ExecWaiter::Unary(reply),
            Waiting::Stream { start, rpc, .. } => ExecWaiter::Stream(StreamWaiter {
                start: Some(start),
                queue: crate::exec_stream::LiveQueue::new(self.limits.exec_stream),
                _permits: (rpc, stream_permit.expect("a stream took its permit")),
            }),
        };
        // No await separates the admission check from tracker registration.
        // On the daemon's current-thread runtime, shutdown cannot close and
        // finish draining the tracker between these two operations.
        let manager = Arc::clone(self);
        let sandbox_id = sandbox.id.clone();
        self.operations.spawn(async move {
            Arc::clone(&manager)
                .supervise_exec(req, resolved, waiter, slot, timeout, deadline, ticket)
                .await;
            // The ticket is released: finishing the last admitted request resumes the
            // idle timer from its finish activity (design 2.1).
            manager.expiry_refresh(&sandbox_id);
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn supervise_exec(
        self: Arc<Self>,
        req: ExecRequest,
        resolved: ResolvedOptions,
        mut waiter: ExecWaiter,
        slot: Arc<Slot>,
        timeout: Duration,
        deadline: Instant,
        _ticket: ExecTicket,
    ) {
        let Some(result) = self
            .exec_owned(req, resolved, &mut waiter, slot, timeout, deadline)
            .await
        else {
            return;
        };
        let stream = match waiter {
            ExecWaiter::Unary(reply) => {
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
                return;
            }
            ExecWaiter::Stream(stream) => stream,
        };
        let StreamWaiter {
            mut start,
            queue,
            _permits: permits,
        } = stream;
        if let Some(start) = start.take() {
            // Refused before its row: an RPC error, and no message was sent.
            let error = match result {
                Err(error) => error,
                Ok(_) => Error::Internal(anyhow::anyhow!("stream finished without starting")),
            };
            let _ = start.send(Err(error));
            return;
        }
        let total = |c: &Captured| crate::exec_stream::CaptureTotal {
            total_bytes: c.total_bytes,
            known: c.total_bytes_known,
        };
        let last = match result {
            // Parity (design 5): the stored row, read after terminal publication by the
            // function GetExecution uses, with the authoritative capture totals.
            Ok(execution) => crate::exec_stream::StreamFinal {
                stdout: total(&execution.stdout),
                stderr: total(&execution.stderr),
                execution: self.execution(&execution.id),
            },
            Err(error) => crate::exec_stream::StreamFinal {
                execution: Err(error),
                stdout: Default::default(),
                stderr: Default::default(),
            },
        };
        // The handoff: the final message goes to the transport's slot, and the stream
        // permit, the RPC permit (in `_permits`) and the Exec ticket are released as
        // this returns, whether or not the peer ever reads it (design 5.1).
        queue.finish(last);
        drop(permits);
    }

    /// Returns `None` only when the waiter vanished before an execution row
    /// was inserted. After insertion the supervisor retains ownership until
    /// it has published a terminal result; an unavailable store keeps it
    /// pending and retrying.
    async fn exec_owned(
        self: &Arc<Self>,
        req: ExecRequest,
        resolved: ResolvedOptions,
        waiter: &mut ExecWaiter,
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
            () = waiter.closed() => {
                info!(sandbox = %sandbox.id, "queued exec RPC stopped waiting; discarding request");
                return None;
            }
            () = self.shutting_down.cancelled() => return Some(Err(Error::ShuttingDown)),
            () = tokio::time::sleep_until(deadline) => return Some(Err(Error::DeadlineExceeded("Exec deadline expired while queued".into()))),
            guard = slot.exec_lock.lock() => guard,
        };
        if waiter.is_closed() {
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
            cancel_reason: None,
            cwd: resolved.options.cwd.clone(),
            env_names: resolved.env_names,
            env_sha256: resolved.env_sha256,
            mode: Some(waiter.mode()),
        };
        let with_options = !resolved.options.is_empty();
        if Instant::now() >= deadline {
            return Some(Err(Error::DeadlineExceeded(
                "Exec deadline expired before row insertion".into(),
            )));
        }
        // Published before the row, so a lifetime expiry or Delete whose intent commits
        // after the insert always finds this execution to cancel; one that commits
        // before it makes the conditional insert refuse.
        let cancel = Arc::new(ExecCancellation::new());
        *slot.running.lock().unwrap() = Some(cancel.clone());
        match self.store.start_execution(&execution) {
            Ok(true) => {}
            Ok(false) => {
                slot.running.lock().unwrap().take();
                return Some(Err(
                    match self.load(&req.sandbox_id).and_then(|s| ready(&s)) {
                        Err(error) => error,
                        // The insert saw a non-READY row; only a startup recovery makes one
                        // READY again, so this is a retryable race, never a run. Its own
                        // token: the sandbox is READY now, so sandbox_not_ready would
                        // misdescribe it.
                        Ok(()) => Error::FailedPrecondition(Refusal::typed(
                            "execution_start_raced",
                            format!(
                                "sandbox {} changed while the execution was starting; retry",
                                req.sandbox_id
                            ),
                        )),
                    },
                ));
            }
            Err(error) => {
                slot.running.lock().unwrap().take();
                return Some(Err(error.into()));
            }
        }
        info!(sandbox = %sandbox.id, execution = %execution.id, argc = execution.argv.len(), env_overrides = execution.env_names.len(), cwd_set = execution.cwd.is_some(), mode = waiter.mode().as_str(), "exec started");
        // ExecStream's first message carries the ID; from here the waiter is the
        // stream's handle, and dropping it is the disconnect.
        waiter.started(&execution);

        // The backend future lives in its own task so both construction-time
        // and polling-time panics become a result the supervisor can record.
        // All borrowed ExecSpec data is owned by that task.
        let backend_manager = Arc::clone(self);
        let backend_id_for_task = backend_id.clone();
        let argv = execution.argv.clone();
        let stdin = req.stdin;
        let max_output = self.limits.max_output_bytes;
        let backend_cancel = cancel.clone();
        let options = resolved.options;
        let live = waiter.live();
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
                options: &options,
                live,
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
            () = waiter.closed() => {
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
            Err(e) => (
                ExecutionState::Failed,
                None,
                Some(exec_failure_reason(e, with_options)),
            ),
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
                    cancel_reason: cancel.reason().map(ExecCancelReason::typed),
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

    /// RenewSandbox (design 2): activity on a READY sandbox, committed before the
    /// reply. It never waits for the exec lock. Any other state is refused with its
    /// typed reason; a Renew that lost to an idle expiry answers `expired_idle`.
    pub fn renew(&self, id: &str) -> Result<Sandbox> {
        if !valid_id("sb", id) {
            return Err(Error::InvalidArgument(format!("invalid sandbox ID {id:?}")));
        }
        let (sandbox, renewed) = self
            .store
            .renew(id)?
            .ok_or_else(|| Error::NotFound(format!("sandbox {id}")))?;
        if !renewed {
            ready(&sandbox)?;
        }
        self.expiry_refresh(id);
        Ok(sandbox)
    }

    /// Every feature Health advertises now: static plus currently proven dynamic.
    pub fn features(&self) -> Vec<Feature> {
        let mut features: Vec<Feature> = STATIC_FEATURES.to_vec();
        features.extend(self.dynamic_features.lock().unwrap().0.iter().copied());
        features.sort();
        features.dedup();
        features
    }

    /// The gate every create-time and Exec-time option check reads: the same set
    /// Health publishes, so Health never advertises an option this daemon refuses.
    pub fn has_feature(&self, feature: Feature) -> bool {
        STATIC_FEATURES.contains(&feature)
            || self.dynamic_features.lock().unwrap().0.contains(&feature)
    }

    pub fn lifecycle_snapshot(&self) -> LifecycleSnapshot {
        let pending = self.expiry.lock().unwrap().pending.len();
        LifecycleSnapshot {
            expired_idle: self.expired_idle.load(Ordering::Relaxed),
            expired_lifetime: self.expired_lifetime.load(Ordering::Relaxed),
            pending_expiry_deletes: u32::try_from(pending).unwrap_or(u32::MAX),
            failed_expiry_deletes: self.failed_expiry_deletes.load(Ordering::Relaxed),
            create_retries_answered: self.create_retries_answered.load(Ordering::Relaxed),
            request_ids_released: self.request_ids_released.load(Ordering::Relaxed),
        }
    }

    /// Expiry deletes pending longer than `--expiry-degraded-after-secs`.
    fn stale_expiry_deletes(&self) -> usize {
        let now = self.clock.boottime_ms();
        let after =
            i64::try_from(self.limits.expiry.degraded_after.as_millis()).unwrap_or(i64::MAX);
        self.expiry
            .lock()
            .unwrap()
            .pending
            .values()
            .filter(|p| now.saturating_sub(p.since) >= after)
            .count()
    }

    /// What `Sandbox.expiry` reports: the effective policy, the deadlines projected
    /// onto the wall clock at read time, the last activity and whether idle is paused.
    pub fn expiry_view(&self, s: &Sandbox) -> ExpiryView {
        let policy = s.lifecycle.expiry;
        let busy = self.existing_slot(&s.id).is_some_and(|slot| slot.busy());
        let grace = self.expiry.lock().unwrap().grace_until;
        let (now_wall, now_boot) = (self.clock.wall_ms(), self.clock.boottime_ms());
        let project = |deadline: i64| now_wall.saturating_add(deadline.saturating_sub(now_boot));
        let live = crate::expiry::deadlines_run(s.state);
        let idle_paused = live && busy && policy.idle_timeout_ms.is_some();
        ExpiryView {
            policy,
            lifetime_expires_at_ms: live
                .then(|| crate::expiry::lifetime_deadline(s).map(project))
                .flatten(),
            idle_expires_at_ms: (live && !busy)
                .then(|| crate::expiry::idle_deadline(s, grace).map(project))
                .flatten(),
            last_activity_at_ms: s.lifecycle.activity_at_ms,
            idle_paused,
        }
    }

    fn existing_slot(&self, id: &str) -> Option<Arc<Slot>> {
        self.slots.lock().unwrap().get(id).and_then(Weak::upgrade)
    }

    /// The cross-boot rebase (design 2.3). Run once after reconciliation and before
    /// the sweeper, admission or any prune.
    pub fn rebase_expiry_clocks(&self) -> Result<usize> {
        Ok(self.store.rebase_clocks()?)
    }

    /// The request-record rebase (design 3.3 R2). Run once after reconciliation and
    /// before admission, any prune or any keyed lookup.
    pub fn rebase_create_requests(&self) -> Result<usize> {
        Ok(self.store.rebase_create_requests()?)
    }

    /// `AdmissionStats` fields 21-25 for `caller` (Health is open to every caller; a
    /// caller sees only its own count besides the node's).
    pub fn create_request_stats(&self, caller: Option<u32>) -> Result<CreateRequestStats> {
        let counts = self.store.create_request_counts(caller.unwrap_or(0))?;
        Ok(CreateRequestStats {
            max_node: self.limits.create_requests.max_node,
            node: counts.node,
            max_per_uid: self.limits.create_requests.max_per_uid,
            caller: caller.map_or(0, |_| counts.uid),
            rejected: self.rejected_create_requests.load(Ordering::Relaxed),
        })
    }

    /// Keyed creates registered now, and pending quota slots (tests).
    #[cfg(test)]
    pub(crate) fn keyed_in_flight(&self) -> (usize, u64, usize) {
        let keyed = self.keyed.lock().unwrap();
        let receivers = keyed.in_flight.values().map(|e| e.done.receiver_count()).sum();
        (keyed.in_flight.len(), keyed.pending_node, receivers)
    }

    /// Rebuilds the timer queue from the store, one entry per qualifying row, and
    /// starts the restart grace. Run after reconciliation and the rebase.
    pub fn rebuild_expiry(&self) -> Result<()> {
        let rows = self.store.expiry_rows()?;
        let ages = self.store.expiry_intent_ages()?;
        let reserved =
            usize::try_from(self.store.sandbox_resources()?.sandboxes).unwrap_or(usize::MAX);
        let now = self.clock.boottime_ms();
        let grace = i64::try_from(self.limits.expiry.restart_grace.as_millis()).unwrap_or(i64::MAX);
        let mut st = self.expiry.lock().unwrap();
        st.queue.clear();
        st.pending.clear();
        st.grace_until = now.saturating_add(grace);
        st.bound = (self.limits.max_sandboxes as usize).max(reserved);
        for row in rows {
            let Some(key) = crate::expiry::key(&row.id) else {
                continue;
            };
            if expiry_owned(&row) && row.is_charged() {
                // MEDIUM 1: the age is the persisted intent's, rebased across a
                // reboot, so a restart never grants a stale delete a fresh window.
                // A row without one is treated as already stale.
                let since = ages.get(&row.id).copied().flatten().unwrap_or(i64::MIN);
                st.pending.insert(
                    key,
                    PendingDelete {
                        since,
                        failures: 0,
                        retry_at: now,
                        running: false,
                        waiting: false,
                    },
                );
            }
            let next = next_action(Some(&row), false, &mut st, key);
            st.queue.set(key, next);
        }
        drop(st);
        self.expiry_changed.notify_one();
        Ok(())
    }

    /// Starts the sweeper: one tracked task owning the queue's single timer.
    pub fn start_expiry(self: &Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        self.rebuild_expiry()?;
        let manager = Arc::clone(self);
        Ok(tokio::spawn(async move { manager.sweep().await }))
    }

    async fn sweep(self: Arc<Self>) {
        loop {
            if self.shutting_down.is_cancelled() {
                break;
            }
            self.expire_due();
            let now = self.clock.boottime_ms();
            let head = self.expiry.lock().unwrap().queue.head();
            // Timers are derived from the remaining boottime budget, and the rescan
            // bounds how late a resume from suspend can be noticed.
            let rescan = self.limits.expiry.rescan;
            let wait = head.map_or(rescan, |head| {
                Duration::from_millis(u64::try_from(head.saturating_sub(now)).unwrap_or(0))
                    .min(rescan)
            });
            tokio::select! {
                biased;
                () = self.shutting_down.cancelled() => break,
                () = self.expiry_changed.notified() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// One sweep: every entry due now, earliest first. Never awaits; removals run as
    /// tracked operations under `--max-concurrent-expiry-deletes`.
    pub fn expire_due(self: &Arc<Self>) {
        self.start_waiting_expiry_removals();
        let now = self.clock.boottime_ms();
        let due = self.expiry.lock().unwrap().queue.pop_due(now);
        for key in due {
            if self.shutting_down.is_cancelled() {
                break;
            }
            self.process_due(key, now);
        }
    }

    fn process_due(self: &Arc<Self>, key: u64, now: i64) {
        let id = crate::expiry::id(key);
        let row = match self.store.sandbox(&id) {
            Ok(Some(row)) => row,
            Ok(None) => {
                self.expiry_refresh(&id);
                return;
            }
            Err(error) => {
                warn!(sandbox = %id, error = %format!("{error:#}"), "expiry could not read the sandbox; retrying");
                self.requeue(key, now);
                return;
            }
        };
        if row.state == SandboxState::Deleting {
            let due = {
                let st = self.expiry.lock().unwrap();
                matches!(st.pending.get(&key), Some(p) if !p.running && p.retry_at <= now)
            };
            if due {
                // Started now, or left waiting for a permit with no task and no entry.
                self.try_start_expiry_removal(key);
            } else {
                self.refresh_after_miss(&id, key, now);
            }
            return;
        }
        if !crate::expiry::is_target(&row) {
            self.expiry_refresh(&id);
            return;
        }
        if crate::expiry::lifetime_deadline(&row).is_some_and(|deadline| deadline <= now) {
            self.expire_lifetime(&id, key, now);
            return;
        }
        let grace = self.expiry.lock().unwrap().grace_until;
        if crate::expiry::idle_deadline(&row, grace).is_some_and(|deadline| deadline <= now) {
            self.expire_idle(&id, key, now);
            return;
        }
        self.refresh_after_miss(&id, key, now);
    }

    /// Lifetime (design 2.4): no lock. Publish the intent first-wins, cancel the
    /// running execution with its reason, then join the ordinary serialized delete.
    fn expire_lifetime(self: &Arc<Self>, id: &str, key: u64, now: i64) {
        // Held before the intent, as Delete does, so every observer shares this slot.
        let slot = self.slot(id);
        match self
            .store
            .publish_expiry_intent(id, DeletionReason::ExpiredLifetime, None)
        {
            Ok(true) => {
                self.expired_lifetime.fetch_add(1, Ordering::Relaxed);
                info!(sandbox = %id, "sandbox reached its max_lifetime; deleting");
                if let Some(cancel) = &*slot.running.lock().unwrap() {
                    cancel.request(ExecCancelReason::ExpiredLifetime);
                }
                self.begin_expiry_removal(key, now);
            }
            Ok(false) => self.refresh_after_miss(id, key, now),
            Err(error) => {
                warn!(sandbox = %id, error = %format!("{error:#}"), "lifetime expiry could not publish its intent; retrying");
                self.requeue(key, now);
            }
        }
    }

    /// Idle (design 2.4 with MEDIUM 1's gate): `try_lock` the exec lock, and holding
    /// it and the admission gate, require every outstanding permit free and commit the
    /// CAS on `activity_seq`; drop both before the ordinary delete retakes the lock.
    fn expire_idle(self: &Arc<Self>, id: &str, key: u64, now: i64) {
        let slot = self.slot(id);
        let Ok(guard) = slot.exec_lock.try_lock() else {
            // Not idle: the execution's finish activity re-arms it.
            self.refresh_after_miss(id, key, now);
            return;
        };
        let committed = {
            let _gate = slot.admission.lock().unwrap_or_else(|e| e.into_inner());
            if slot.busy() {
                Ok(false)
            } else {
                let grace = self.expiry.lock().unwrap().grace_until;
                match self.store.sandbox(id) {
                    Ok(Some(row))
                        if crate::expiry::is_target(&row)
                            && crate::expiry::idle_deadline(&row, grace)
                                .is_some_and(|deadline| deadline <= now) =>
                    {
                        #[cfg(test)]
                        if let Some(hook) = &*self.idle_commit_hook.lock().unwrap() {
                            hook();
                        }
                        self.store.publish_expiry_intent(
                            id,
                            DeletionReason::ExpiredIdle,
                            Some(row.lifecycle.activity_seq),
                        )
                    }
                    Ok(_) => Ok(false),
                    Err(error) => Err(error),
                }
            }
        };
        drop(guard);
        match committed {
            Ok(true) => {
                self.expired_idle.fetch_add(1, Ordering::Relaxed);
                info!(sandbox = %id, "sandbox reached its idle timeout; deleting");
                self.begin_expiry_removal(key, now);
            }
            Ok(false) => self.refresh_after_miss(id, key, now),
            Err(error) => {
                warn!(sandbox = %id, error = %format!("{error:#}"), "idle expiry could not publish its intent; retrying");
                self.requeue(key, now);
            }
        }
    }

    fn begin_expiry_removal(self: &Arc<Self>, key: u64, now: i64) {
        self.expiry.lock().unwrap().pending.insert(
            key,
            PendingDelete {
                since: now,
                failures: 0,
                retry_at: now,
                running: false,
                waiting: false,
            },
        );
        self.try_start_expiry_removal(key);
    }

    /// Break-it HIGH 1: a removal task exists only while it holds a permit. Without
    /// a free permit the pending delete waits, bounded by reservations like the
    /// queue, and the next returned permit starts it.
    fn try_start_expiry_removal(self: &Arc<Self>, key: u64) -> bool {
        let permit = {
            let mut st = self.expiry.lock().unwrap();
            let Some(p) = st.pending.get_mut(&key) else {
                return false;
            };
            if p.running {
                return false;
            }
            match self.expiry_deletes.clone().try_acquire_owned() {
                Ok(permit) => {
                    p.running = true;
                    p.waiting = false;
                    permit
                }
                Err(_) => {
                    p.waiting = true;
                    st.queue.set(key, None);
                    return false;
                }
            }
        };
        self.spawn_expiry_removal(key, permit);
        true
    }

    /// Starts waiting removals, earliest retry first, while permits are free. Every
    /// returned permit calls this; each sweep does too, so none is ever stranded.
    fn start_waiting_expiry_removals(self: &Arc<Self>) {
        loop {
            if self.shutting_down.is_cancelled() {
                return;
            }
            let started = {
                let mut st = self.expiry.lock().unwrap();
                let Some(key) = st
                    .pending
                    .iter()
                    .filter(|(_, p)| p.waiting && !p.running)
                    .min_by_key(|(key, p)| (p.retry_at, **key))
                    .map(|(key, _)| *key)
                else {
                    return;
                };
                let Ok(permit) = self.expiry_deletes.clone().try_acquire_owned() else {
                    return;
                };
                let p = st.pending.get_mut(&key).expect("selected above");
                p.waiting = false;
                p.running = true;
                (key, permit)
            };
            self.spawn_expiry_removal(started.0, started.1);
        }
    }

    /// A client Delete of an expiry-owned row: wait for an expiry permit (refused at
    /// shutdown), then take the slot's attempt unless an expiry attempt is running,
    /// in which case the exec lock orders this caller behind it.
    async fn join_expiry_removal(self: &Arc<Self>, id: &str) -> Result<ExpiryJoin<R>> {
        let key = crate::expiry::key(id)
            .ok_or_else(|| Error::InvalidArgument(format!("invalid sandbox ID {id:?}")))?;
        let permit = tokio::select! {
            biased;
            () = self.shutting_down.cancelled() => return Err(Error::ShuttingDown),
            permit = self.expiry_deletes.clone().acquire_owned() => permit
                .map_err(|_| Error::ShuttingDown)?,
        };
        let claimed = {
            let mut st = self.expiry.lock().unwrap();
            match st.pending.get_mut(&key) {
                Some(p) if !p.running => {
                    p.running = true;
                    p.waiting = false;
                    st.queue.set(key, None);
                    true
                }
                _ => false,
            }
        };
        Ok(ExpiryJoin {
            manager: Arc::clone(self),
            id: id.to_string(),
            key,
            permit: Some(permit),
            claimed,
            outcome: None,
        })
    }

    /// Ends one expiry attempt: a failure backs off and counts; a cancellation
    /// retries at its old time. Then the row's entry is recomputed.
    fn settle_expiry_attempt(&self, id: &str, key: u64, outcome: Option<bool>) {
        if outcome == Some(false) {
            self.failed_expiry_deletes.fetch_add(1, Ordering::Relaxed);
        }
        {
            let now = self.clock.boottime_ms();
            let mut st = self.expiry.lock().unwrap();
            if let Some(p) = st.pending.get_mut(&key) {
                p.running = false;
                if outcome == Some(false) {
                    p.failures = p.failures.saturating_add(1);
                    let delay = crate::expiry::retry_delay(p.failures);
                    p.retry_at =
                        now.saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX));
                }
            }
        }
        self.expiry_refresh(id);
    }

    /// One expiry removal: the ordinary delete path, under the expiry delete permit
    /// it was started with and no client RPC permit. A failure leaves the row
    /// DELETING and charged, retried with backoff; startup completes any left.
    fn spawn_expiry_removal(self: &Arc<Self>, key: u64, permit: OwnedSemaphorePermit) {
        let manager = Arc::clone(self);
        let id = crate::expiry::id(key);
        self.operations.spawn(async move {
            let result = manager.delete_inner(&id, DeleteRole::ExpiryWorker).await;
            let deleted = matches!(&result, Ok(s) if s.state == SandboxState::Deleted);
            if !deleted {
                let why = match &result {
                    Ok(s) => format!("still {}", s.state.as_str()),
                    Err(error) => error.to_string(),
                };
                warn!(sandbox = %id, error = %why, "expiry delete failed; the sandbox stays charged and is retried");
            }
            manager.settle_expiry_attempt(&id, key, Some(deleted));
            drop(permit);
            manager.start_waiting_expiry_removals();
        });
    }

    /// Recomputes one sandbox's single queue entry from its row and slot, replacing
    /// whatever entry it had. Every activity, pause, resume and retry comes here.
    pub(crate) fn expiry_refresh(&self, id: &str) {
        let Some(key) = crate::expiry::key(id) else {
            return;
        };
        let row = match self.store.sandbox(id) {
            Ok(row) => row,
            Err(error) => {
                warn!(sandbox = %id, error = %format!("{error:#}"), "expiry could not read the sandbox; retrying");
                self.requeue(key, self.clock.boottime_ms());
                return;
            }
        };
        let busy = self.existing_slot(id).is_some_and(|slot| slot.busy());
        let mut st = self.expiry.lock().unwrap();
        let next = next_action(row.as_ref(), busy, &mut st, key);
        debug_assert!(next.is_none() || st.queue.len() < st.bound || st.queue.get(key).is_some());
        if st.queue.set(key, next) {
            drop(st);
            self.expiry_changed.notify_one();
        }
    }

    /// After an attempt that changed nothing, never re-arm at a time already past:
    /// that would spin. A second later is soon enough for a state that just changed.
    fn refresh_after_miss(&self, id: &str, key: u64, now: i64) {
        self.expiry_refresh(id);
        let mut st = self.expiry.lock().unwrap();
        if let Some((time, _)) = st.queue.get(key)
            && time <= now
        {
            st.queue
                .set(key, Some((now.saturating_add(1_000), Due::Retry)));
        }
    }

    fn requeue(&self, key: u64, now: i64) {
        let mut st = self.expiry.lock().unwrap();
        st.queue
            .set(key, Some((now.saturating_add(5_000), Due::Retry)));
        drop(st);
        self.expiry_changed.notify_one();
    }

    /// The timer queue's length and its bound, for tests and the LOW 1 contract.
    pub fn expiry_queue_len(&self) -> (usize, usize) {
        let st = self.expiry.lock().unwrap();
        (st.queue.len(), st.bound)
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

    fn check_exec(&self, req: &ExecRequest, stream: bool) -> Result<Duration> {
        // Design 6: an option this backend has not proven is refused first, the first
        // in Feature order (cwd, env, then streaming), before its value is even looked at.
        if !req.cwd.is_empty() {
            self.require_feature(Feature::ExecCwd)?;
        }
        if !req.env.is_empty() {
            self.require_feature(Feature::ExecEnv)?;
        }
        if stream {
            self.require_feature(Feature::ExecStream)?;
        }
        validate_argv(&req.argv, self.limits.max_argv_bytes).map_err(Error::InvalidArgument)?;
        if !req.cwd.is_empty() {
            crate::exec_env::validate_cwd(&req.cwd, self.limits.max_exec_cwd_bytes)
                .map_err(Error::InvalidArgument)?;
        }
        crate::exec_env::validate_env(&req.env, &self.limits.exec_env, "env")
            .map_err(Error::InvalidArgument)?;
        if req.stdin.len() > self.limits.max_stdin_bytes {
            return Err(Error::InvalidArgument(format!(
                "stdin is {} bytes; the limit is {}",
                req.stdin.len(),
                self.limits.max_stdin_bytes
            )));
        }
        // A stream's own limits (decision 4): 30 minutes by default, two hours at most.
        let (default, max) = if stream {
            (
                self.limits.default_stream_timeout,
                self.limits.max_stream_timeout,
            )
        } else {
            (self.limits.default_timeout, self.limits.max_timeout)
        };
        let timeout = match req.timeout_ms {
            0 => default,
            ms => Duration::from_millis(ms.into()),
        };
        if timeout > max {
            return Err(Error::InvalidArgument(format!(
                "timeout {} ms is above the limit of {} ms",
                timeout.as_millis(),
                max.as_millis()
            )));
        }
        Ok(timeout)
    }

    /// `backend_unsupported:<feature>` (design section 1) unless the backend lists it now.
    fn require_feature(&self, feature: Feature) -> Result<()> {
        if self.has_feature(feature) {
            return Ok(());
        }
        let (reason, field) = match feature {
            Feature::ExecCwd => ("backend_unsupported:exec_cwd", "cwd"),
            Feature::ExecEnv => ("backend_unsupported:exec_env", "env"),
            Feature::SandboxDefaultEnv => {
                ("backend_unsupported:sandbox_default_env", "default_env")
            }
            Feature::ExecStream => ("backend_unsupported:exec_stream", "ExecStream"),
            _ => ("backend_unsupported", "this field"),
        };
        Err(Error::Refused(
            RefusalCode::Unimplemented,
            Refusal::typed(
                reason,
                format!(
                    "the {} backend has not proven {field} support; read Health's features before setting it",
                    self.runtime.name()
                ),
            ),
        ))
    }

    /// A create's default env (design 4): the feature gate, then the same bounds as an
    /// Exec's env. Returns its names and digest for the row.
    fn check_default_env(
        &self,
        default_env: &[crate::exec_env::EnvVar],
    ) -> Result<(Vec<String>, Option<String>)> {
        if default_env.is_empty() {
            return Ok((Vec::new(), None));
        }
        self.require_feature(Feature::SandboxDefaultEnv)?;
        crate::exec_env::validate_env(default_env, &self.limits.exec_env, "default_env")
            .map_err(Error::InvalidArgument)?;
        Ok((
            crate::exec_env::env_names(default_env),
            crate::exec_env::env_sha256(default_env),
        ))
    }

    /// One Exec's effective options (design 4): the sandbox's default env overlaid by
    /// the request's, within the same bounds, refused before admission unless the
    /// backend proves them now and the sandbox's runtime recorded bit 0x20 at READY.
    fn resolve_exec_options(&self, req: &ExecRequest, sandbox: &Sandbox) -> Result<ResolvedOptions> {
        let defaults = if sandbox.lifecycle.default_env_names.is_empty() {
            Vec::new()
        } else {
            // The defaults reach kiln only through exec options: an operator downgrade
            // after create refuses here rather than running without them.
            self.require_feature(Feature::ExecEnv)?;
            let values = self.store.sandbox_default_env(&sandbox.id)?;
            if crate::exec_env::env_names(&values) != sandbox.lifecycle.default_env_names {
                // Cleared by a FAILED or DELETED transition since the row was read.
                ready(&self.load(&sandbox.id)?)?;
                return Err(Error::Internal(anyhow::anyhow!(
                    "sandbox {}: stored default env does not match its names",
                    sandbox.id
                )));
            }
            values
        };
        let env = crate::exec_env::merge_env(&defaults, &req.env);
        crate::exec_env::validate_env(&env, &self.limits.exec_env, "the merged env (default_env overlaid by env)")
            .map_err(Error::InvalidArgument)?;
        let options = crate::exec_env::ExecOptions {
            cwd: (!req.cwd.is_empty()).then(|| req.cwd.clone()),
            env,
        };
        if !options.is_empty()
            && sandbox
                .lifecycle
                .exec_features
                .is_none_or(|bits| bits & crate::exec_env::FEATURE_EXEC_OPTIONS == 0)
        {
            let reason = if options.cwd.is_some() {
                "sandbox_unsupported:exec_cwd"
            } else {
                "sandbox_unsupported:exec_env"
            };
            return Err(Error::FailedPrecondition(Refusal::typed(
                reason,
                format!(
                    "sandbox {}'s runtime predates exec options (it did not advertise feature {:#x} when it became ready); create a new sandbox",
                    sandbox.id,
                    crate::exec_env::FEATURE_EXEC_OPTIONS
                ),
            )));
        }
        Ok(ResolvedOptions {
            env_names: crate::exec_env::env_names(&options.env),
            env_sha256: crate::exec_env::env_sha256(&options.env),
            options,
        })
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

/// Today's "is X, not ready" refusal, with its typed reason (design section 1):
/// only the message's token prefix is new, and the code is unchanged.
fn ready(s: &Sandbox) -> Result<()> {
    if s.state == SandboxState::Ready {
        Ok(())
    } else {
        Err(Error::FailedPrecondition(Refusal::typed(
            not_ready_reason(s),
            format!("sandbox {} is {}, not ready", s.id, s.state.as_str()),
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
/// The typed reason a create whose new sandbox did not prove exec options for its
/// default env fails with (design 4.1). Retryable: the next create probes again.
const SANDBOX_FEATURE_PROBE_FAILED: &str = "sandbox_feature_probe_failed";

/// Why a new sandbox with a default env may not become READY, if it may not: its
/// runtime's post-create probe failed (`None`) or did not advertise exec options.
fn unproven_default_env(sandbox: &Sandbox, exec_features: Option<u32>) -> Option<String> {
    let bit = crate::exec_env::FEATURE_EXEC_OPTIONS;
    if sandbox.lifecycle.default_env_names.is_empty() {
        return None;
    }
    match exec_features {
        Some(bits) if bits & bit != 0 => None,
        Some(bits) => Some(format!(
            "the new sandbox's runtime advertised features {bits:#x} without {bit:#x}, which its default_env needs"
        )),
        None => Some(format!(
            "the new sandbox's runtime did not answer its feature probe, so feature {bit:#x}, which its default_env needs, is unproven"
        )),
    }
}

fn feature_probe_refusal(sandbox_id: &str) -> Error {
    Error::Refused(
        RefusalCode::Unavailable,
        Refusal::typed(
            SANDBOX_FEATURE_PROBE_FAILED,
            format!(
                "sandbox {sandbox_id} did not prove the exec options its default_env needs and was not made ready; retry the create"
            ),
        ),
    )
}

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
/// A FAILED execution's `failure_reason`: the runtime's message, with a typed token
/// first for the exec-options outcomes the API names (design 4.1; `kilnd.proto`'s
/// `Execution.failure_reason`). None of these started a child but `cwd_not_found`,
/// whose child failed before its command ran.
fn exec_failure_reason(d: &RuntimeDiagnostic, with_options: bool) -> String {
    let token = match (d.kind, d.stage) {
        (RuntimeErrorKind::LaunchFailed, RuntimeStage::Cwd) => Some("cwd_not_found"),
        _ if !with_options => None,
        (RuntimeErrorKind::Unavailable, RuntimeStage::Handshake) => {
            Some("exec_options_unconfirmed")
        }
        (RuntimeErrorKind::Incompatible, RuntimeStage::Handshake) => {
            Some("exec_options_unsupported")
        }
        (RuntimeErrorKind::Unavailable, RuntimeStage::Prepare) => {
            Some("exec_options_unavailable")
        }
        _ => None,
    };
    match token {
        Some(token) => format!("{token}: {}", d.message),
        None => d.message.clone(),
    }
}

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

/// One sandbox's next expiry action, or none (design 2.4): the earliest of the
/// lifetime deadline, the idle deadline (absent while paused) and a pending retry.
fn next_action(
    row: Option<&Sandbox>,
    busy: bool,
    st: &mut ExpiryState,
    key: u64,
) -> Option<(i64, Due)> {
    let Some(s) = row else {
        st.pending.remove(&key);
        return None;
    };
    match s.state {
        SandboxState::Deleting => match st.pending.get(&key) {
            Some(p) if !p.running && !p.waiting => Some((p.retry_at, Due::Retry)),
            _ => None,
        },
        SandboxState::Ready | SandboxState::Lost | SandboxState::Quarantined => {
            st.pending.remove(&key);
            if !crate::expiry::is_target(s) {
                return None;
            }
            let lifetime = crate::expiry::lifetime_deadline(s).map(|t| (t, Due::Lifetime));
            let idle = (!busy)
                .then(|| crate::expiry::idle_deadline(s, st.grace_until))
                .flatten()
                .map(|t| (t, Due::Idle));
            match (lifetime, idle) {
                (Some(l), Some(i)) => Some(l.min(i)),
                (l, i) => l.or(i),
            }
        }
        SandboxState::Creating | SandboxState::Deleted | SandboxState::Failed => {
            st.pending.remove(&key);
            None
        }
    }
}

/// `Sandbox.expiry` as the API reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExpiryView {
    pub policy: crate::model::ExpiryPolicy,
    pub lifetime_expires_at_ms: Option<i64>,
    pub idle_expires_at_ms: Option<i64>,
    pub last_activity_at_ms: Option<i64>,
    pub idle_paused: bool,
}

/// The owner and root may use a sandbox; nobody else may.
fn may_use(sandbox: &Sandbox, uid: u32) -> bool {
    uid == 0 || sandbox.owner_uid == uid
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fenced_tests;

#[cfg(test)]
mod expiry_tests;

#[cfg(test)]
mod m2_tests;

#[cfg(test)]
mod m3_tests;

#[cfg(test)]
mod m4_tests;
