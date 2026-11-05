//! B3's approved plans, root node ledger and concrete worker model, with B4's real
//! host lifecycle: allocation, the jailer/VMM launch, supervision, stop and removal.
//! This module is H's side of the group: bounded framing has already happened, and
//! everything here is in-memory checks and dispatch to worker processes. It performs
//! no filesystem, SQLite, hashing or `/proc` work on the socket runtime. No reply can
//! say READY: that needs B5's broker, and production profiles stay refused until B7.
pub mod broker;
pub mod cgroup;
pub mod compaction;
pub mod config;
pub mod console;
pub mod exec;
pub mod executable;
pub mod identity;
pub mod inventory;
pub mod journal;
mod lifecycle;
pub mod manifest;
pub mod monitor;
pub mod offline;
pub mod peer;
pub mod proven;
pub mod storage;
pub mod supervisor;
pub mod token;
pub mod workers;

use self::config::{MAX_ENROLLED_HARD, NodePolicy, ProfileCatalog};
use self::executable::{ExecutableIdentity, ExecutableTable, Role, WalkPolicy};
use self::identity::AllocationKey;
use self::inventory::{NamespaceObservation, NodeObservation, ObservationBackend, WorkerFreshness};
use self::journal::{
    AdmitOutcome, AdmitRequest, AttachOutcome, EnrollOutcome, FenceOutcome, FenceRequest,
    LedgerConfig, StopAuthority, TokenLookup, WorkerIntentSpec,
};
use self::manifest::ManifestGate;
use self::monitor::StopTarget;
use self::peer::{Enrollment, PeerAttestor, PeerCredentials, PeerPin};
use self::workers::{
    AdmissionAuthority, CallError, Channel, Endpoint, Heartbeat, Lane, LedgerReply, LedgerRequest,
    MonitorCommand, MonitorEvent, MonitorReply, MonitorSockets, NodeConfig, PrepReply, PrepRequest,
    ProcessId, ProfileRuntime, RecoveryReply, RecoveryRequest, RevalidatedPlan, RevocationTable,
    SupervisorCommand, SupervisorContext, SupervisorEvent, Timings, try_reap,
};
use super::protocol::{
    self, AccountingReply, AmbiguousClass, CapabilitiesReply, CreateReply,
    FIRECRACKER_GROUP_VERSION, FenceReply, FirecrackerOperation, FirecrackerRequest,
    FirecrackerResponse, GroupError, GroupErrorKind, InspectReply, ListReply, WireBytes,
    WorkerHealth, WorkersHealth,
};
use crate::lock::ExclusiveFileLock;
use crate::model::{Digest, Id128, SandboxSpec};
use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream as StdUnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Attach attempts that may wait for one enrolled account's turn with L. Only that account
/// can join them, and it cannot use them to hold anything: a refused proof gives the turn
/// straight back. L's attach lane has a place for every account's one proof.
const MAX_ATTACH_WAITERS: usize = 8;
/// Rejected-token memory for the node, divided equally among possible instances. The
/// ledger stays authoritative for every token it owns, so this bounds memory, not answers.
const MAX_TOKEN_GATES: usize = 4096;
/// Queued requests for one token, beyond which a duplicate is refused immediately.
const MAX_TOKEN_WAITERS: usize = 16;
/// Accepted work that may outlive its waiter, divided the same way.
const MAX_DETACHED: usize = 128;
/// Creates waiting for a preparation slot. Preflight never waits: it refuses at once.
const MAX_PREP_WAITERS: usize = 16;
/// Later stop, settlement and observation records waiting for L.
const MAX_PENDING_RECORDS: usize = 4096;
/// A read-only fence lookup may answer this long after an expired wire deadline. It
/// authorizes nothing: it returns an existing fence unchanged or refuses.
const LOOKUP_GRACE: Duration = Duration::from_millis(250);
const CONTROL_QUEUE: usize = 8;
/// How long startup waits for a previous helper's ledger process to leave.
const LOCK_WAIT: Duration = Duration::from_secs(5);
const SUPERVISOR_CGROUP_LEAF: &str = "control";
/// A private replacement L gets this long for each exact reply before it is discarded.
const REPLACEMENT_LEDGER_REPLY: Duration = Duration::from_secs(5);
/// Failed replacements fork no faster than this.
const REPLACEMENT_LEDGER_RETRY: Duration = Duration::from_millis(250);

/// The resource names a supervisor may touch. Journaled before its gate opens.
const ALLOWED_RESOURCES: [&str; 5] = ["work.xfs", "identity.bin", "jail-root", "cgroup", "vm"];

/// A wire deadline in both clocks: same absolute instant, never a fresh budget.
#[derive(Clone, Copy, Debug)]
pub struct WireDeadline {
    pub instant: Instant,
    pub ns: u64,
}

impl WireDeadline {
    /// An earlier instant on the same clocks: the monotonic nanosecond value moves back
    /// by exactly as much. Never later than the original deadline.
    fn from_instant(instant: Instant) -> Self {
        let now = Instant::now();
        let ns = workers::monotonic_ns()
            .saturating_add(instant.saturating_duration_since(now).as_nanos() as u64);
        Self { instant, ns }
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.instant
    }

    fn with_grace(&self) -> u64 {
        self.ns.saturating_add(LOOKUP_GRACE.as_nanos() as u64)
    }
}

/// A queued journal record taken for writing. Dropped while still holding it (the
/// flush was cancelled mid-call), it goes back to the front of the queue.
struct Requeue<'a> {
    pending: &'a Mutex<VecDeque<LedgerRequest>>,
    record: Option<LedgerRequest>,
}

impl Drop for Requeue<'_> {
    fn drop(&mut self) {
        if let Some(record) = self.record.take() {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_front(record);
        }
    }
}

/// 128 random bits from the kernel without a filesystem open on H's runtime.
fn fresh_id() -> io::Result<Id128> {
    let mut bytes = [0u8; 16];
    // SAFETY: bytes is writable and within getentropy's 256-byte limit.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Id128::from_bytes(bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Config(String),
}

#[derive(Debug)]
struct Attachment {
    epoch: Id128,
    peer_pid: i32,
    peer_uid: u32,
    /// L's reading, kept for diagnosis. The pin below is what authorizes.
    #[cfg_attr(not(test), allow(dead_code))]
    peer_start: u64,
    /// The attested process itself. Once it is gone this attachment authorizes nothing,
    /// whoever later gets its number or inherited its socket.
    pin: PeerPin,
    /// False when another database already owns this namespace.
    admission_open: bool,
    /// Its slot and generation in the table L reads at C2. A namespace with closed
    /// admission never publishes this, so nothing it asked for can commit.
    authority: AdmissionAuthority,
}

/// Why a gate closed and how replaceable that memory is.
#[derive(Clone, Copy)]
struct ClosedGate {
    class: AmbiguousClass,
    /// Rejected on the plan's own bytes or token binding: a daemon verifies both before
    /// C1, so no charge can depend on this. Any other rejection might be post-C1.
    evictable: bool,
    order: u64,
}

static GATE_ORDER: AtomicU64 = AtomicU64::new(0);

/// Per-token serialization and the in-memory dispatch gate. The first rejection after
/// the durable lookup closes the gate at once; nothing reopens it, even when the cause
/// later clears. Requests in flight use an open gate; only a closed one is retained.
#[derive(Default)]
struct TokenGate {
    serial: Arc<tokio::sync::Mutex<()>>,
    closed: Mutex<Option<ClosedGate>>,
    waiters: AtomicUsize,
    /// In-flight flows using this entry, counted under the table's lock.
    users: AtomicUsize,
    /// The ledger owns this token and answers for it from now on: no need to retain it.
    durable: std::sync::atomic::AtomicBool,
}

impl TokenGate {
    /// A possibly post-C1 rejection or a fence. Also protects an earlier evictable close.
    fn close(&self, class: AmbiguousClass) {
        let mut closed = self.closed.lock().unwrap();
        match closed.as_mut() {
            Some(existing) => existing.evictable = false,
            None => {
                *closed = Some(ClosedGate {
                    class,
                    evictable: false,
                    order: GATE_ORDER.fetch_add(1, Ordering::Relaxed),
                });
            }
        }
    }

    fn close_evictable(&self, class: AmbiguousClass) {
        self.closed.lock().unwrap().get_or_insert(ClosedGate {
            class,
            evictable: true,
            order: GATE_ORDER.fetch_add(1, Ordering::Relaxed),
        });
    }

    fn closed(&self) -> Option<AmbiguousClass> {
        self.closed.lock().unwrap().map(|closed| closed.class)
    }

    fn mark_durable(&self) {
        self.durable.store(true, Ordering::Relaxed);
    }

    fn idle(&self) -> bool {
        self.users.load(Ordering::Relaxed) == 0
    }
}

/// One instance's non-durable token memory. Its size is `quota` retained gates plus
/// that instance's in-flight flows, and no other instance can add to it or evict from it.
struct GateTable {
    quota: usize,
    gates: HashMap<Id128, Arc<TokenGate>>,
}

impl GateTable {
    fn new(quota: usize) -> Self {
        Self {
            quota,
            gates: HashMap::new(),
        }
    }

    fn enter(&mut self, allocation: Id128) -> Arc<TokenGate> {
        let gate = self.gates.entry(allocation).or_default().clone();
        gate.users.fetch_add(1, Ordering::Relaxed);
        gate
    }

    fn leave(&mut self, allocation: Id128, gate: &TokenGate) {
        gate.users.fetch_sub(1, Ordering::Relaxed);
        if gate.idle() && (gate.closed().is_none() || gate.durable.load(Ordering::Relaxed)) {
            self.gates.remove(&allocation);
        }
        self.enforce_quota();
    }

    fn retained(&self) -> usize {
        self.gates
            .values()
            .filter(|gate| gate.idle() && gate.closed().is_some())
            .count()
    }

    /// The oldest idle closed gate that matches `evictable_only`.
    fn oldest(&self, evictable_only: bool) -> Option<Id128> {
        self.gates
            .iter()
            .filter(|(_, gate)| gate.idle())
            .filter_map(|(id, gate)| {
                let closed = (*gate.closed.lock().unwrap())?;
                (closed.evictable || !evictable_only).then_some((closed.order, *id))
            })
            .min()
            .map(|(_, id)| id)
    }

    /// Room for one more rejection, making it from a malformed token if needed. No room
    /// means every retained gate may guard a charged token, so a new one gets no work.
    fn make_room(&mut self) -> bool {
        if self.retained() < self.quota {
            return true;
        }
        match self.oldest(true) {
            Some(id) => {
                self.gates.remove(&id);
                true
            }
            None => false,
        }
    }

    /// Fence attempts on unknown tokens can close gates past `make_room`, and memory
    /// stays bounded regardless. The cost of dropping one lands on this instance alone,
    /// and is safe: a later request still starts from the durable lookup, and only a
    /// matching ABSENT ever releases anything.
    fn enforce_quota(&mut self) {
        while self.retained() > self.quota {
            let Some(id) = self.oldest(true).or_else(|| self.oldest(false)) else {
                return;
            };
            self.gates.remove(&id);
        }
    }
}

/// One enrolled instance's fixed share of the node. These exist only for instances root
/// enrolled, so no request can create one, and none of them is drawn from a common pool.
/// Every enrolled instance's share, and which account each one belongs to. One account
/// serves one instance, so a peer's kernel-reported UID names its instance by itself.
#[derive(Default)]
struct Shares {
    by_instance: HashMap<Id128, Arc<InstanceShare>>,
    by_uid: HashMap<u32, Id128>,
}

struct InstanceShare {
    /// FIFO: one proof at a time for this instance's account, and its one attachment slot.
    attach_turn: Arc<Semaphore>,
    attach_waiters: AtomicUsize,
    detached: Arc<Semaphore>,
    gates: Mutex<GateTable>,
}

impl InstanceShare {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            attach_turn: Arc::new(Semaphore::new(1)),
            attach_waiters: AtomicUsize::new(0),
            detached: Arc::new(Semaphore::new((MAX_DETACHED / capacity).max(2))),
            gates: Mutex::new(GateTable::new(MAX_TOKEN_GATES / capacity)),
        }
    }
}

/// A flow's use of its token's gate, released however the flow ends.
struct GateUse {
    share: Arc<InstanceShare>,
    allocation: Id128,
    gate: Arc<TokenGate>,
}

impl GateUse {
    fn enter(share: Arc<InstanceShare>, allocation: Id128) -> Self {
        let gate = share.gates.lock().unwrap().enter(allocation);
        Self {
            share,
            allocation,
            gate,
        }
    }
}

impl Drop for GateUse {
    fn drop(&mut self) {
        self.share
            .gates
            .lock()
            .unwrap()
            .leave(self.allocation, &self.gate);
    }
}

/// A cleanup-only S's reported result, filled by its event and read after its exit.
type CleanupOutcome = Arc<Mutex<Option<Result<(), String>>>>;

struct SupervisorEntry {
    pid: i32,
    channel: Arc<Channel>,
    worker_id: i64,
    /// Everything M and K need to stop this boot: the `vm` subtree from the moment it
    /// exists, and the validated VMM once published.
    vm: Option<StopTarget>,
    /// The plan's executable vector, for J's and V's journal rows.
    expected: Vec<ExecutableIdentity>,
    /// J's and V's worker rows, settled once each is provably gone.
    children: Vec<(i64, ProcessId)>,
    /// V was validated, hardened and journaled BOOTING.
    booted: bool,
    /// A cleanup-only S's result, when this entry's S is one.
    cleanup: Option<CleanupOutcome>,
    /// One of the two node-wide preparation slots, leased to this S's session hashing,
    /// fallocate and mkfs in its `control` leaf until it reports them done or exits.
    prep: Option<PrepLease>,
    vm_worker: Option<i64>,
    vm_gone: bool,
    /// Revoked by a fence: S's exit after this is expected, not a loss.
    revoked: bool,
    exit: Option<String>,
    exited: Arc<CancellationToken>,
    settle_queued: bool,
    stop_fenced: bool,
    stalled: bool,
    contained: Option<bool>,
    /// One K dispatch at a time for this entry, retried until the subtree is gone.
    kill_inflight: bool,
    /// The revoke actually reached S's bounded write queue.
    revoke_sent: bool,
    /// B5: H's end of S's descriptor socket, for an execution's stdio.
    descriptors: Option<Arc<std::os::unix::net::UnixDatagram>>,
    /// B5: the broker's journaled boot and inner sandbox once READY.
    ready: Option<(String, String)>,
    /// B5: the execution token between EXEC_INTENT and its settlement.
    busy: Option<Id128>,
    /// B5: waiters for relay reports, by job.
    jobs: HashMap<u64, mpsc::UnboundedSender<broker::RelayReport>>,
    /// B5-05: the allocation's one control operation at a time. A Probe holds it until
    /// R's job ends; Exec admission takes it briefly, so the two are ordered.
    control: Arc<tokio::sync::Semaphore>,
}

impl SupervisorEntry {
    fn new(pid: i32, channel: Arc<Channel>, worker_id: i64) -> Self {
        Self {
            pid,
            channel,
            worker_id,
            vm: None,
            expected: Vec::new(),
            children: Vec::new(),
            booted: false,
            cleanup: None,
            prep: None,
            vm_worker: None,
            vm_gone: false,
            revoked: false,
            exit: None,
            exited: Arc::new(CancellationToken::new()),
            settle_queued: false,
            stop_fenced: false,
            stalled: false,
            contained: None,
            kill_inflight: false,
            revoke_sent: false,
            descriptors: None,
            ready: None,
            busy: None,
            jobs: HashMap::new(),
            control: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}

struct WorkerSlot {
    pid: i32,
    channel: Arc<Channel>,
    /// Set when this slot's process has exited and been reaped.
    reaped: bool,
    busy: Arc<std::sync::atomic::AtomicBool>,
    /// This process's journal row, once it has one. It settles only after the reap.
    worker_id: Option<i64>,
    exit: Option<String>,
    /// A single replacement is underway; it never runs beside its predecessor.
    replacing: bool,
    /// B7 RTC-3: the ledger slot's K, sent by this very L over this channel and
    /// published with it in one swap. Every other slot has none.
    key: Option<token::TokenKey>,
}

impl WorkerSlot {
    fn new(pid: i32, channel: Arc<Channel>) -> Self {
        Self {
            pid,
            channel,
            reaped: false,
            busy: Arc::default(),
            worker_id: None,
            exit: None,
            replacing: false,
            key: None,
        }
    }
}

/// B7 RTC-14's in-memory latch in H. Once set it stays set for this process's life.
#[derive(Default)]
struct NodeLatch {
    /// The fault kind, the only thing other instances are told.
    kind: Option<String>,
    /// The instance whose verified token detected a rollback.
    detector: Option<Id128>,
    /// A fault L reported but has not confirmed durable: every replacement L commits it
    /// before it serves anything.
    pending: Option<(Id128, Id128, u64)>,
}

/// The fixed infrastructure slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotKind {
    Ledger,
    Prep(usize),
    Monitor,
    Recovery(usize),
}

const SLOTS: [SlotKind; 6] = [
    SlotKind::Ledger,
    SlotKind::Prep(0),
    SlotKind::Prep(1),
    SlotKind::Monitor,
    SlotKind::Recovery(0),
    SlotKind::Recovery(1),
];

impl SlotKind {
    fn mode(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Prep(_) => "prep",
            Self::Monitor => "monitor",
            Self::Recovery(_) => "recovery",
        }
    }
}

enum Spawned {
    Plain(WorkerSlot),
    Monitor(MonitorSlot, mpsc::Receiver<serde_json::Value>),
}

impl Spawned {
    fn worker(&self) -> &WorkerSlot {
        match self {
            Self::Plain(slot) => slot,
            Self::Monitor(slot, _) => &slot.worker,
        }
    }

    fn worker_mut(&mut self) -> &mut WorkerSlot {
        match self {
            Self::Plain(slot) => slot,
            Self::Monitor(slot, _) => &mut slot.worker,
        }
    }
}

struct MonitorSlot {
    worker: WorkerSlot,
    descriptors: Arc<tokio::net::UnixStream>,
    last_status: std::time::Instant,
}

/// Each worker's heartbeat pair and each K slot's M-facing pair. H holds both ends
/// without using them, so a re-forked worker inherits a live channel.
struct SharedSockets {
    heartbeats: Vec<(String, UnixDatagram, UnixDatagram)>,
    recovery: Vec<(UnixDatagram, UnixDatagram)>,
}

impl SharedSockets {
    fn worker_end(&self, name: &str) -> io::Result<UnixDatagram> {
        self.heartbeats
            .iter()
            .find(|(worker, _, _)| worker == name)
            .ok_or_else(|| io::Error::other("unknown worker name"))?
            .1
            .try_clone()
    }
}

pub struct Node {
    config: Arc<NodeConfig>,
    _lock: Option<ExclusiveFileLock>,
    sockets: SharedSockets,
    ledger: Mutex<WorkerSlot>,
    prep: [Mutex<WorkerSlot>; workers::PREP_SLOTS],
    monitor: Mutex<MonitorSlot>,
    recovery: [Mutex<WorkerSlot>; workers::RECOVERY_SLOTS],
    attachments: Mutex<HashMap<Id128, Attachment>>,
    /// Filled from the ledger before serving. Enrollment needs the node lock, which this
    /// helper holds, so the set cannot change while it runs.
    shares: Mutex<Option<Shares>>,
    supervisors: Mutex<HashMap<AllocationKey, SupervisorEntry>>,
    /// Remove's per-allocation serialization; a concurrent Remove is told to retry.
    removing: Mutex<std::collections::HashSet<AllocationKey>>,
    pending: Mutex<VecDeque<LedgerRequest>>,
    flushing: tokio::sync::Mutex<()>,
    prep_waiters: AtomicUsize,
    ledger_fault: Mutex<Option<String>>,
    /// B5-01: L refused an answer too large for one frame.
    ledger_reply_fault: Mutex<Option<String>>,
    /// The last replacement L that had to be discarded, until one succeeds.
    ledger_replacement_fault: Mutex<Option<String>>,
    ledger_retry_at: Mutex<Option<std::time::Instant>>,
    lease_fault: Mutex<Option<String>>,
    stale_workers: Mutex<Vec<String>>,
    monitor_lost: Mutex<bool>,
    orphans: Mutex<Vec<Orphan>>,
    /// Forked replacements that never got their journal record, awaiting their reap.
    discarded: Mutex<Vec<i32>>,
    revocations: Arc<RevocationTable>,
    next_authority: AtomicU64,
    generation_hint: AtomicU64,
    stop: CancellationToken,
    /// B7 RTC-14: checked before any gate, L write or host action of forward work.
    latched: std::sync::atomic::AtomicBool,
    latch: Mutex<NodeLatch>,
    /// B7 recheck R1: answers to fault-bearing requests whose waiters gave up while L
    /// may still answer. Each holds every forward effect fail-closed, exactly as the
    /// latch does, until its answer is consumed (`LostAnswers`).
    lost_answers: AtomicUsize,
    /// The node, for each fault-bearing call's [`LostAnswers`] owner.
    lost_node: std::sync::Weak<Node>,
    /// B7 integrated recheck HIGH-2: the holds of fault-bearing answers L died before
    /// giving, until a replacement's Handover has imported its durable latch state.
    transferred: Mutex<TransferredHolds>,
    /// How many times the ledger slot has been published: the generation of the L that
    /// a call made now reaches. Read and changed only under the ledger slot's lock.
    ledger_generation: AtomicU64,
    /// B7: the last compaction stuck token, for Health.
    compaction_fault: Mutex<Option<String>>,
    /// Test instrumentation: L calls made and tokens refused by the tag check.
    ledger_calls: AtomicU64,
    tag_refusals: AtomicU64,
}

fn call_class(error: CallError) -> AmbiguousClass {
    match error {
        CallError::Full => AmbiguousClass::WorkerExhausted,
        CallError::Closed | CallError::Protocol => AmbiguousClass::WorkerPanic,
    }
}

fn ambiguous_create(class: AmbiguousClass, message: impl Into<String>) -> CreateReply {
    CreateReply::Ambiguous {
        class,
        message: message.into(),
    }
}

fn ambiguous_fence(class: AmbiguousClass, message: impl Into<String>) -> FenceReply {
    FenceReply::Ambiguous {
        class,
        message: message.into(),
    }
}

fn group_error(kind: GroupErrorKind, message: impl Into<String>) -> FirecrackerResponse {
    FirecrackerResponse::Error(GroupError::new(kind, message))
}

fn spawn_ledger_slot(
    config: &Arc<NodeConfig>,
    sockets: &SharedSockets,
    revocations: &Arc<RevocationTable>,
    lock_fd: Option<RawFd>,
) -> io::Result<WorkerSlot> {
    let (host, child) = StdUnixStream::pair()?;
    let heartbeat = sockets.worker_end("ledger")?;
    let every = config.timings.heartbeat;
    let ledger = config.ledger.clone();
    let mut keep = vec![child.as_raw_fd(), heartbeat.as_raw_fd()];
    keep.extend(lock_fd);
    let inherited = revocations.clone();
    #[cfg(not(test))]
    let attestor = PeerAttestor::new();
    #[cfg(test)]
    let attestor = PeerAttestor::with_test_peers(config.test.peers.clone());
    let pid = workers::spawn_process(&keep, move || {
        workers::ledger_main(
            Endpoint::new(child),
            ledger,
            attestor,
            Heartbeat::new(heartbeat, every),
            inherited,
            workers::ledger_request_expires,
        );
    })?;
    let (channel, _events) = Channel::spawn_with_attach(
        host,
        workers::LEDGER_QUEUE_NORMAL,
        workers::LEDGER_QUEUE_RESERVED,
        workers::LEDGER_QUEUE_ATTACH,
        workers::LEDGER_QUEUE_COMPACTION,
    )?;
    Ok(WorkerSlot::new(pid, channel))
}

fn spawn_prep_slot(
    config: &Arc<NodeConfig>,
    sockets: &SharedSockets,
    index: usize,
) -> io::Result<WorkerSlot> {
    let (host, child) = StdUnixStream::pair()?;
    let heartbeat = sockets.worker_end(&format!("prep-{index}"))?;
    let every = config.timings.heartbeat;
    let mut keep = vec![child.as_raw_fd(), heartbeat.as_raw_fd()];
    keep.extend(config.table_fds());
    let inherited = config.clone();
    let pid = workers::spawn_process(&keep, move || {
        workers::prep_main(
            Endpoint::new(child),
            inherited,
            Heartbeat::new(heartbeat, every),
        );
    })?;
    let (channel, _events) = Channel::spawn(host, CONTROL_QUEUE, 0)?;
    Ok(WorkerSlot::new(pid, channel))
}

fn spawn_recovery_slot(
    config: &Arc<NodeConfig>,
    sockets: &SharedSockets,
    index: usize,
) -> io::Result<WorkerSlot> {
    let (host, child) = StdUnixStream::pair()?;
    let heartbeat = sockets.worker_end(&format!("recovery-{index}"))?;
    let monitor = sockets.recovery[index].1.try_clone()?;
    let every = config.timings.heartbeat;
    let keep = [
        child.as_raw_fd(),
        heartbeat.as_raw_fd(),
        monitor.as_raw_fd(),
    ];
    let pid = workers::spawn_process(&keep, move || {
        workers::recovery_main(
            Endpoint::new(child),
            monitor,
            Heartbeat::new(heartbeat, every),
        );
    })?;
    let (channel, _events) = Channel::spawn(host, CONTROL_QUEUE, 0)?;
    Ok(WorkerSlot::new(pid, channel))
}

fn spawn_monitor_slot(
    config: &Arc<NodeConfig>,
    sockets: &SharedSockets,
) -> io::Result<(MonitorSlot, mpsc::Receiver<serde_json::Value>)> {
    let (host, child) = StdUnixStream::pair()?;
    let (descriptors_host, descriptors_child) = StdUnixStream::pair()?;
    let heartbeat = sockets.worker_end("monitor")?;
    let every = config.timings;
    let mut heartbeats = Vec::new();
    for (name, _, monitor_end) in &sockets.heartbeats {
        if name != "monitor" {
            heartbeats.push((name.clone(), monitor_end.try_clone()?));
        }
    }
    let mut recovery = Vec::new();
    for (monitor_end, _) in &sockets.recovery {
        recovery.push(monitor_end.try_clone()?);
    }
    let mut keep = vec![
        child.as_raw_fd(),
        descriptors_child.as_raw_fd(),
        heartbeat.as_raw_fd(),
    ];
    keep.extend(heartbeats.iter().map(|(_, s)| s.as_raw_fd()));
    keep.extend(recovery.iter().map(AsRawFd::as_raw_fd));
    let pid = workers::spawn_process(&keep, move || {
        workers::monitor_main(
            MonitorSockets {
                control: Endpoint::new(child),
                descriptors: descriptors_child.into(),
                heartbeats,
                recovery,
            },
            every,
            Heartbeat::new(heartbeat, every.heartbeat),
        );
    })?;
    descriptors_host.set_nonblocking(true)?;
    let (channel, events) = Channel::spawn(host, CONTROL_QUEUE, 0)?;
    Ok((
        MonitorSlot {
            worker: WorkerSlot::new(pid, channel),
            descriptors: Arc::new(tokio::net::UnixStream::from_std(descriptors_host)?),
            last_status: std::time::Instant::now(),
        },
        events,
    ))
}

impl Node {
    /// Starts L, P, M and K before any traffic is accepted, replays every unreleased
    /// claim, and only then returns. The caller's listener serves nothing until then.
    pub async fn start(config: NodeConfig) -> Result<Arc<Self>, NodeError> {
        let directory = executable::walk_directory(&config.ledger.policy, &config.ledger.directory)
            .map_err(|e| NodeError::Config(e.to_string()))?;
        // A previous helper's L holds this until it has seen its EOF and finished.
        let lock_wait = Instant::now() + LOCK_WAIT;
        let lock = loop {
            match ExclusiveFileLock::acquire_at(
                directory.file(),
                OsStr::new(journal::LEDGER_LOCK),
                &journal::ledger_lock_path(&config.ledger.directory),
                "Firecracker node ledger",
            ) {
                Ok(lock) => break lock,
                Err(error) if Instant::now() >= lock_wait => {
                    return Err(NodeError::Config(format!("{error:#}")));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        };
        let lock_fd = lock.raw_fd();
        let config = Arc::new(config);
        let mut heartbeats = Vec::new();
        let names = [
            "ledger",
            "prep-0",
            "prep-1",
            "recovery-0",
            "recovery-1",
            "monitor",
        ];
        for name in names {
            let (worker_end, monitor_end) = workers::datagram_pair()?;
            heartbeats.push((name.to_string(), worker_end, monitor_end));
        }
        let mut recovery = Vec::new();
        for _ in 0..workers::RECOVERY_SLOTS {
            recovery.push(workers::datagram_pair()?);
        }
        let sockets = SharedSockets {
            heartbeats,
            recovery,
        };
        // Mapped before any fork, so every L, including a replacement, shares it.
        let revocations = Arc::new(RevocationTable::new(MAX_ENROLLED_HARD as usize)?);
        let ledger = spawn_ledger_slot(&config, &sockets, &revocations, Some(lock_fd))?;
        let prep = [
            spawn_prep_slot(&config, &sockets, 0)?,
            spawn_prep_slot(&config, &sockets, 1)?,
        ];
        let kill = [
            spawn_recovery_slot(&config, &sockets, 0)?,
            spawn_recovery_slot(&config, &sockets, 1)?,
        ];
        let (monitor, monitor_events) = spawn_monitor_slot(&config, &sockets)?;
        let [prep0, prep1] = prep;
        let [kill0, kill1] = kill;
        let node = Arc::new_cyclic(|me| Self {
            config,
            _lock: Some(lock),
            sockets,
            ledger: Mutex::new(ledger),
            prep: [Mutex::new(prep0), Mutex::new(prep1)],
            monitor: Mutex::new(monitor),
            recovery: [Mutex::new(kill0), Mutex::new(kill1)],
            attachments: Mutex::default(),
            shares: Mutex::new(None),
            supervisors: Mutex::default(),
            removing: Mutex::default(),
            pending: Mutex::default(),
            flushing: tokio::sync::Mutex::new(()),
            prep_waiters: AtomicUsize::new(0),
            ledger_fault: Mutex::new(None),
            ledger_reply_fault: Mutex::new(None),
            ledger_replacement_fault: Mutex::new(None),
            ledger_retry_at: Mutex::new(None),
            lease_fault: Mutex::new(None),
            stale_workers: Mutex::default(),
            monitor_lost: Mutex::new(false),
            orphans: Mutex::default(),
            discarded: Mutex::default(),
            revocations,
            next_authority: AtomicU64::new(1),
            generation_hint: AtomicU64::new(0),
            stop: CancellationToken::new(),
            latched: std::sync::atomic::AtomicBool::new(false),
            latch: Mutex::default(),
            lost_answers: AtomicUsize::new(0),
            lost_node: me.clone(),
            transferred: Mutex::default(),
            ledger_generation: AtomicU64::new(0),
            compaction_fault: Mutex::new(None),
            ledger_calls: AtomicU64::new(0),
            tag_refusals: AtomicU64::new(0),
        });
        tokio::spawn(Self::monitor_events(Arc::downgrade(&node), monitor_events));
        tokio::spawn(Self::supervise(Arc::downgrade(&node)));
        tokio::spawn(Self::compactor(Arc::downgrade(&node)));
        drop(directory);
        if let Err(reason) = node.replay_at_startup().await {
            node.abandon_startup().await;
            return Err(NodeError::Config(reason));
        }
        Ok(node)
    }

    /// A node that can't journal its own workers serves nothing. Its sockets close, its
    /// workers leave on that EOF, and this helper reaps them and goes on serving kiln.
    async fn abandon_startup(&self) {
        self.stop.cancel();
        for kind in SLOTS {
            self.with_slot(kind, |slot| slot.channel.close());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut waiting = 0;
            for kind in SLOTS {
                self.with_slot(kind, |slot| {
                    if !slot.reaped {
                        if let Some(evidence) = try_reap(slot.pid) {
                            slot.reaped = true;
                            slot.exit = Some(evidence);
                        } else {
                            waiting += 1;
                        }
                    }
                });
            }
            if waiting == 0 || Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Replays claims before serving. A ledger that cannot answer leaves the node
    /// degraded: read paths say Unavailable, and capacity is never presumed free. A
    /// ledger that answers but cannot journal the workers about to serve is an error.
    async fn replay_at_startup(self: &Arc<Self>) -> Result<(), String> {
        let deadline = workers::monotonic_ns().saturating_add(30_000_000_000);
        let channel = self.ledger_channel();
        match channel
            .call::<LedgerReply>(Lane::Reserved, &LedgerRequest::Replay, deadline)
            .await
        {
            Ok(LedgerReply::Replay(snapshot)) => {
                self.generation_hint
                    .store(snapshot.generation, Ordering::Relaxed);
                // A durable fault or the fail-stop marker latches H before it serves.
                if let Some(kind) = snapshot.node_faults.first() {
                    self.set_latch(kind, None, None);
                }
                // K comes over this private channel before any tag can be checked.
                match self.fetch_key(&channel).await {
                    Ok(key) => self.ledger.lock().unwrap().key = Some(key),
                    Err(reason) => {
                        *self.ledger_fault.lock().unwrap() = Some(reason);
                        return Ok(());
                    }
                }
                if let Err(reason) = self.load_shares(&snapshot.enrolled) {
                    // Refused whole. Nothing can attach, and kiln goes on being served.
                    *self.ledger_fault.lock().unwrap() = Some(reason);
                    return Ok(());
                }
                self.register_infrastructure().await?;
                if !snapshot.executable_leases.is_empty()
                    && let Some(slot) = self.try_prep_slot()
                {
                    let reply: Result<PrepReply, _> = slot
                        .channel
                        .call(
                            Lane::Normal,
                            &PrepRequest::VerifyLeases {
                                expected: snapshot.executable_leases.clone(),
                            },
                            deadline,
                        )
                        .await;
                    match reply {
                        Ok(PrepReply::LeasesVerified) => {}
                        Ok(PrepReply::LeasesRefused { reason }) => {
                            *self.lease_fault.lock().unwrap() = Some(reason);
                        }
                        _ => {
                            *self.lease_fault.lock().unwrap() =
                                Some("generation leases could not be reverified".into());
                        }
                    }
                }
                self.recover_workers(&snapshot.unsettled_workers).await;
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                *self.ledger_fault.lock().unwrap() = Some(reason);
            }
            _ => {
                *self.ledger_fault.lock().unwrap() =
                    Some("the ledger did not answer its replay".into());
            }
        }
        Ok(())
    }

    /// One fixed share per enrolled instance, sized for the most this policy allows, so
    /// an instance's share doesn't depend on how many others are enrolled today. Every
    /// separation between instances rests on their accounts, so a ledger that binds one
    /// to anything but its own serves no instance at all.
    fn load_shares(&self, enrolled: &[journal::EnrolledAccount]) -> Result<(), String> {
        let capacity = (self.config.max_enrolled as usize).max(enrolled.len());
        let mut shares = Shares::default();
        for account in enrolled {
            peer::validate_account(
                account.uid,
                account.gid,
                self.config.helper_uid,
                &self.config.ranges,
            )
            .map_err(|reason| format!("instance {}: {reason}", account.instance_id))?;
            if shares
                .by_uid
                .insert(account.uid, account.instance_id)
                .is_some()
            {
                return Err("two enrolled instances share a Unix account".into());
            }
            shares
                .by_instance
                .insert(account.instance_id, Arc::new(InstanceShare::new(capacity)));
        }
        *self.shares.lock().unwrap() = Some(shares);
        Ok(())
    }

    fn share(&self, instance: Id128) -> Option<Arc<InstanceShare>> {
        let shares = self.shares.lock().unwrap();
        shares.as_ref()?.by_instance.get(&instance).cloned()
    }

    /// Whether this account is enrolled. The listener asks this before reading anything
    /// from a connection, so it takes one in-memory lock and nothing else.
    pub fn admits_uid(&self, uid: u32) -> bool {
        let shares = self.shares.lock().unwrap();
        shares.as_ref().is_some_and(|s| s.by_uid.contains_key(&uid))
    }

    /// The kernel's UID for this peer. A test fixture has only one real account, so its
    /// peers stand in for theirs the way they do for a cgroup. L reads the same evidence.
    #[cfg(test)]
    fn observed_uid(&self, peer: PeerCredentials, instance: Id128) -> u32 {
        let test = &self.config.test.peers;
        if test.any_account {
            let shares = self.shares.lock().unwrap();
            let mine = shares.as_ref().and_then(|shares| {
                shares
                    .by_uid
                    .iter()
                    .find(|(_, owner)| **owner == instance)
                    .map(|(uid, _)| *uid)
            });
            return mine.unwrap_or(peer.uid);
        }
        test.directory
            .as_deref()
            .zip(peer.pid)
            .and_then(|(directory, pid)| peer::marked_account(directory, pid))
            .map_or(peer.uid, |(uid, _)| uid)
    }

    #[cfg(not(test))]
    fn observed_uid(&self, peer: PeerCredentials, _instance: Id128) -> u32 {
        peer.uid
    }

    /// Journals each startup worker's inherited image identity, when a profile pins it.
    /// Only an exact reply counts. A slot without its row keeps being retried within the
    /// budget, and past that startup fails: the caller's listener never serves.
    async fn register_infrastructure(self: &Arc<Self>) -> Result<(), String> {
        let Some(image) = self.config.helper_image else {
            return Ok(());
        };
        let give_up = Instant::now() + self.config.timings.startup_journal;
        for kind in SLOTS {
            loop {
                // A replaced L records itself, so this also ends when that happened.
                let (pid, recorded) = self.with_slot(kind, |slot| (slot.pid, slot.worker_id));
                if recorded.is_some() {
                    break;
                }
                let remaining = give_up.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!(
                        "the {} worker has no journal row, so nothing can be served",
                        kind.mode()
                    ));
                }
                let request = LedgerRequest::RecordInfrastructure {
                    spec: Box::new(infrastructure_spec(kind, image)),
                    pid,
                };
                // Through `ledger_call`, so a `SyncFailed` or a lost answer latches H.
                let call = self.ledger_call(Lane::Reserved, &request, u64::MAX);
                if let Ok(Ok(LedgerReply::Worker { worker_id })) =
                    tokio::time::timeout(remaining, call).await
                {
                    self.with_slot(kind, |slot| {
                        if slot.pid == pid {
                            slot.worker_id = Some(worker_id);
                        }
                    });
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        Ok(())
    }

    fn with_slot<T>(&self, kind: SlotKind, use_slot: impl FnOnce(&mut WorkerSlot) -> T) -> T {
        match kind {
            SlotKind::Ledger => use_slot(&mut self.ledger.lock().unwrap()),
            SlotKind::Prep(index) => use_slot(&mut self.prep[index].lock().unwrap()),
            SlotKind::Recovery(index) => use_slot(&mut self.recovery[index].lock().unwrap()),
            SlotKind::Monitor => use_slot(&mut self.monitor.lock().unwrap().worker),
        }
    }

    /// PID evidence from an earlier helper is only a candidate. A process that is
    /// provably gone settles; a live one stays charged and is revisited by the tick.
    async fn recover_workers(self: &Arc<Self>, unsettled: &[journal::WorkerRecord]) {
        for worker in unsettled {
            // An older row's missing or malformed boot ID is None: such a process can
            // only be proven gone, never signaled, and stays charged until it is.
            let live_identity = match (worker.pid, worker.start_time) {
                (Some(pid), Some(start_time)) => Some(ProcessId {
                    pid,
                    start_time,
                    boot_id: worker
                        .host_boot_id
                        .as_deref()
                        .and_then(proven::BootId::parse),
                }),
                _ => None,
            };
            match live_identity {
                // Infrastructure from this very startup is not an orphan.
                Some(target)
                    if worker.allocation_id.is_none()
                        && self.is_current_infrastructure(target.pid) => {}
                Some(target) => {
                    let gone = self
                        .probe_process(StopTarget::process(target))
                        .await
                        .unwrap_or(false);
                    if gone {
                        self.queue_record(LedgerRequest::Settle {
                            worker_id: worker.worker_id,
                            settlement: "gone-after-helper-restart".into(),
                        });
                    } else if worker.mode == "vm" {
                        // An owned subtree that outlived its helper: stop it under
                        // the conditional authority, then prove it gone.
                        let gone = self
                            .dispatch_kill(StopTarget::process(target))
                            .await
                            .unwrap_or(false);
                        if gone {
                            self.queue_record(LedgerRequest::Settle {
                                worker_id: worker.worker_id,
                                settlement: "stopped-after-helper-restart".into(),
                            });
                        } else {
                            self.orphans.lock().unwrap().push(Orphan {
                                worker_id: worker.worker_id,
                                target,
                            });
                        }
                    } else {
                        self.orphans.lock().unwrap().push(Orphan {
                            worker_id: worker.worker_id,
                            target,
                        });
                    }
                }
                None => {
                    // Never identified, so it never held an open gate.
                    self.queue_record(LedgerRequest::Settle {
                        worker_id: worker.worker_id,
                        settlement: "never-started".into(),
                    });
                }
            }
        }
        self.flush_pending().await;
    }

    fn is_current_infrastructure(&self, pid: i32) -> bool {
        self.ledger.lock().unwrap().pid == pid
            || self.monitor.lock().unwrap().worker.pid == pid
            || self.prep.iter().any(|p| p.lock().unwrap().pid == pid)
            || self.recovery.iter().any(|r| r.lock().unwrap().pid == pid)
    }

    fn ledger_channel(&self) -> Arc<Channel> {
        self.ledger_channel_at().0
    }

    /// The published L's channel and its generation, read together.
    fn ledger_channel_at(&self) -> (Arc<Channel>, u64) {
        let slot = self.ledger.lock().unwrap();
        (slot.channel.clone(), self.ledger_generation.load(Ordering::SeqCst))
    }

    fn try_prep_slot(&self) -> Option<PrepLease> {
        for slot in &self.prep {
            let slot = slot.lock().unwrap();
            if !slot.reaped
                && !slot.channel.is_closed()
                && slot
                    .busy
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return Some(PrepLease {
                    channel: slot.channel.clone(),
                    busy: slot.busy.clone(),
                });
            }
        }
        None
    }

    /// Runs one job on one P slot. The job is detached from its waiter: if the waiter
    /// leaves, the slot stays busy until that same process answers or exits.
    async fn prep_call(
        &self,
        request: PrepRequest,
        deadline: WireDeadline,
    ) -> Result<PrepReply, CallError> {
        let lease = self.try_prep_slot().ok_or(CallError::Full)?;
        self.prep_with(lease, request, deadline).await
    }

    async fn prep_with(
        &self,
        lease: PrepLease,
        request: PrepRequest,
        deadline: WireDeadline,
    ) -> Result<PrepReply, CallError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tokio::spawn(async move {
            let reply = lease
                .channel
                .call::<PrepReply>(Lane::Normal, &request, deadline.ns)
                .await;
            drop(lease);
            let _ = reply_tx.send(reply);
        });
        reply_rx.await.map_err(|_| CallError::Closed)?
    }

    /// A preparation slot for S's own session work: the same bounded waiters and wire
    /// deadline as revalidation. The P process stays idle while S holds its lease.
    async fn queued_prep_lease(&self, deadline: WireDeadline) -> Option<PrepLease> {
        if self.prep_waiters.fetch_add(1, Ordering::AcqRel) >= MAX_PREP_WAITERS {
            self.prep_waiters.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        let mut lease = self.try_prep_slot();
        while lease.is_none() && !deadline.expired() {
            tokio::time::sleep(Duration::from_millis(2)).await;
            lease = self.try_prep_slot();
        }
        self.prep_waiters.fetch_sub(1, Ordering::AcqRel);
        lease
    }

    /// Create's revalidation may wait for a slot: at most a fixed number of waiters,
    /// and never past its wire deadline. Nothing here adds a process or borrows K.
    async fn queued_prep_call(
        &self,
        request: PrepRequest,
        deadline: WireDeadline,
    ) -> Result<PrepReply, CallError> {
        if self.prep_waiters.fetch_add(1, Ordering::AcqRel) >= MAX_PREP_WAITERS {
            self.prep_waiters.fetch_sub(1, Ordering::AcqRel);
            return Err(CallError::Full);
        }
        let mut lease = self.try_prep_slot();
        while lease.is_none() && !deadline.expired() {
            tokio::time::sleep(Duration::from_millis(2)).await;
            lease = self.try_prep_slot();
        }
        self.prep_waiters.fetch_sub(1, Ordering::AcqRel);
        self.prep_with(lease.ok_or(CallError::Full)?, request, deadline)
            .await
    }

    /// B7 RTC-14: from here every forward effect is refused node-wide, for the rest of
    /// this process's life. `pending` is a fault not yet known durable.
    fn set_latch(&self, kind: &str, detector: Option<Id128>, pending: Option<(Id128, Id128, u64)>) {
        let mut latch = self.latch.lock().unwrap();
        latch.kind.get_or_insert_with(|| kind.to_string());
        if detector.is_some() {
            latch.detector = detector;
        }
        if pending.is_some() {
            latch.pending = pending;
        }
        self.latched.store(true, Ordering::SeqCst);
    }

    /// Forward effects are refused: by the latch, or while a lost answer that may
    /// carry a fault is outstanding (B7 recheck R1).
    fn is_latched(&self) -> bool {
        self.is_latched_durably() || self.lost_answers.load(Ordering::SeqCst) > 0
    }

    /// The RTC-14 latch itself, which only root's offline clear ends.
    fn is_latched_durably(&self) -> bool {
        self.latched.load(Ordering::SeqCst)
    }

    /// B7 recheck R1 at a forward boundary that can wait: whether forward effects are
    /// latched once every outstanding lost answer has been consumed. L answers in order,
    /// so a hold normally lasts as long as L's queue; still held at `until`, the answer
    /// is treated as a fault (fail-closed). A client's own lapsed deadline therefore
    /// delays other work for that long at most and never refuses it on its own. The count
    /// includes holds transferred from a dead L (integrated recheck HIGH-2), which last
    /// until a replacement's Handover has imported the durable latch.
    async fn latched_once_answered(&self, until: Instant) -> bool {
        loop {
            if self.is_latched_durably() {
                return true;
            }
            if self.lost_answers.load(Ordering::SeqCst) == 0 {
                return false;
            }
            if Instant::now() >= until {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// B7 recheck R1: imports an answer nobody waits for any longer. It is consumed
    /// whenever it arrives, so a fault it carries latches H even though the request
    /// that asked has gone; an answer that cannot be read while L lives fails stop.
    fn import_lost_answer(&self, reply: Result<serde_json::Value, CallError>) {
        let Ok(value) = reply else {
            // L is gone: its replacement's handover imports whatever it made durable.
            // The hold is not released here but transferred (`transfer_hold`).
            return;
        };
        match serde_json::from_value::<LedgerReply>(value) {
            Ok(LedgerReply::SyncFailed { .. }) => self.set_latch("fail_stop", None, None),
            Ok(LedgerReply::Latched { kind }) => self.set_latch(&kind, None, None),
            // L wrote the fail-stop marker at detection; the commit waits for the next
            // handover, which H's latch now forces.
            Ok(LedgerReply::FaultPending { .. }) => self.set_latch("rollback", None, None),
            Ok(_) => {}
            Err(_) => self.set_latch("fail_stop", None, None),
        }
        if self.is_latched_durably() {
            tracing::error!("a lost ledger answer carried a fault: forward effects are latched");
        }
    }

    /// The refusal every forward effect gets under the latch: no gate, no L write and
    /// no host action (section 8.3's ledger-loss rule).
    fn latch_refusal(&self) -> FirecrackerResponse {
        if !self.is_latched_durably() {
            return group_error(
                GroupErrorKind::Unavailable,
                "forward effects are held: a ledger answer that may carry a fault is \
                 still outstanding",
            );
        }
        let kind = self.latch.lock().unwrap().kind.clone();
        group_error(
            GroupErrorKind::Unavailable,
            format!(
                "forward effects are latched node-wide ({}): root must run the offline \
                 inventory and clear-node-faults",
                kind.unwrap_or_else(|| "fault".into())
            ),
        )
    }

    /// K, from this L over its own private channel (RTC-3), only ever together with L's
    /// latch state (RTC-14). The latch is imported here, before K is returned, so a
    /// caller that has K has already latched H if L was latched in any way: by a fault
    /// row, by the fail-stop marker or in memory.
    async fn fetch_key(&self, channel: &Channel) -> Result<token::TokenKey, String> {
        let reply = tokio::time::timeout(
            REPLACEMENT_LEDGER_REPLY,
            channel.call::<LedgerReply>(Lane::Reserved, &LedgerRequest::Handover, u64::MAX),
        )
        .await;
        match reply {
            Ok(Ok(LedgerReply::Handover { key, latch })) => {
                let key = key
                    .into_key()
                    .filter(|key| key.node_id() == self.config.node_id)
                    .ok_or_else(|| "the ledger sent no valid token key".to_string())?;
                if let Some(kind) = latch.kind() {
                    self.set_latch(&kind, None, None);
                }
                #[cfg(test)]
                workers::faults::hold("H.ledger.latch_imported").await;
                Ok(key)
            }
            Ok(Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason })) => {
                Err(reason)
            }
            _ => Err("the ledger did not hand over its token key and latch".into()),
        }
    }

    /// A replacement L's handover before H publishes it (design 16.6, "H and L
    /// replacement"): any pending RTC-14 fault is committed first, then K and L's latch
    /// state come over the new channel and H imports the latch. Only then is the channel
    /// published. A fail-stop marker written by an L that died before H saw its
    /// `SyncFailed` therefore latches H here, before any forward effect can reach the new L.
    async fn handover_ledger(&self, channel: &Channel) -> Result<token::TokenKey, String> {
        let pending = self.latch.lock().unwrap().pending;
        if let Some((instance, token, issue_next)) = pending {
            let committed = tokio::time::timeout(
                REPLACEMENT_LEDGER_REPLY,
                channel.call::<LedgerReply>(
                    Lane::Reserved,
                    &LedgerRequest::CommitFault {
                        instance,
                        token,
                        issue_next,
                    },
                    u64::MAX,
                ),
            )
            .await;
            match committed {
                Ok(Ok(LedgerReply::FaultCommitted { .. })) => {
                    self.latch.lock().unwrap().pending = None;
                }
                _ => return Err("it could not commit the pending rollback fault".into()),
            }
        }
        let key = self.fetch_key(channel).await?;
        // Integrated recheck HIGH-2: the latch is imported (`fetch_key`), so the holds
        // transferred from every L this one replaces can lift now, and not before.
        self.release_transferred_holds();
        Ok(key)
    }

    /// Integrated recheck HIGH-2: a fault-bearing call to the L of `generation` ended
    /// without its answer because that L is gone. Whatever it made durable (a fail-stop
    /// marker, a fault row) only a replacement's Handover imports, so the call holds
    /// forward effects until then: `counted` says whether it already holds one (a
    /// parked lost answer), else it takes one now. If a replacement of that L has
    /// already handed over, its import happened after this L's death and there is
    /// nothing left to wait for.
    fn transfer_hold(&self, generation: u64, counted: bool) {
        let mut holds = self.transferred.lock().unwrap();
        if generation < holds.handed_over_below {
            if counted {
                self.lost_answers.fetch_sub(1, Ordering::SeqCst);
            }
            return;
        }
        if !counted {
            self.lost_answers.fetch_add(1, Ordering::SeqCst);
        }
        *holds.held.entry(generation).or_default() += 1;
    }

    /// After a successful Handover has imported the replacement's latch state, before
    /// the replacement is published: every L up to the one in the slot is dead and
    /// imported, so their transferred holds lift. A failed Handover never gets here.
    fn release_transferred_holds(&self) {
        let mut holds = self.transferred.lock().unwrap();
        let replaced = self.ledger_generation.load(Ordering::SeqCst);
        holds.handed_over_below = holds.handed_over_below.max(replaced + 1);
        let below = holds.handed_over_below;
        let kept = holds.held.split_off(&below);
        let lifted: usize = std::mem::replace(&mut holds.held, kept).values().sum();
        if lifted > 0 {
            self.lost_answers.fetch_sub(lifted, Ordering::SeqCst);
            tracing::warn!(
                "{lifted} hold(s) transferred from a dead ledger lifted after the \
                 replacement's handover imported its latch state"
            );
        }
    }

    /// RTC-3's H check, before any gate, quota or L call: a constant-time tag check in
    /// the caller's authenticated instance. No key yet means the ledger is unavailable,
    /// which is not a verdict on the token.
    fn check_token(&self, instance: Id128, token: Id128) -> Result<u64, Box<FirecrackerResponse>> {
        let slot = self.ledger.lock().unwrap();
        let Some(key) = slot.key.as_ref() else {
            return Err(Box::new(group_error(
                GroupErrorKind::Unavailable,
                "the node ledger's token key is not available",
            )));
        };
        key.verify(instance, token).ok_or_else(|| {
            self.tag_refusals.fetch_add(1, Ordering::Relaxed);
            Box::new(group_error(
                GroupErrorKind::Incompatible,
                "this allocation token was not issued to this instance",
            ))
        })
    }

    /// B7 RTC-18: one compaction pass at a time on the compaction lane, each instance in
    /// round-robin order, the next batch only after the previous reply. L decides from its
    /// boot clock whether a checkpoint or an advance is due; H only keeps passes coming.
    async fn compactor(node: std::sync::Weak<Self>) {
        let tick = match node.upgrade() {
            Some(node) => node.config.timings.compaction_tick,
            None => return,
        };
        loop {
            tokio::time::sleep(tick).await;
            let Some(node) = node.upgrade() else { return };
            if node.stop.is_cancelled() {
                return;
            }
            let instances: Vec<Id128> = {
                let shares = node.shares.lock().unwrap();
                match shares.as_ref() {
                    Some(shares) => {
                        let mut ids: Vec<_> = shares.by_instance.keys().copied().collect();
                        ids.sort();
                        ids
                    }
                    None => continue,
                }
            };
            for instance in instances {
                // A due instance keeps its turn while its batches come back full.
                for _ in 0..64 {
                    if node.stop.is_cancelled() {
                        return;
                    }
                    let reply = node
                        .ledger_call(
                            Lane::Compaction,
                            &LedgerRequest::Compact {
                                instance,
                                max_tokens: journal::COMPACTION_BATCH,
                            },
                            u64::MAX,
                        )
                        .await;
                    match reply {
                        Ok(LedgerReply::Compacted(reply)) => {
                            *node.compaction_fault.lock().unwrap() =
                                reply.batch.stuck.first().map(|token| {
                                    format!("fenced token {token} cannot be compacted")
                                });
                            if !reply.more {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
    }

    async fn ledger_call(
        &self,
        lane: Lane,
        request: &LedgerRequest,
        deadline_ns: u64,
    ) -> Result<LedgerReply, CallError> {
        // The compactor's own passes are not request work; the counter is for proving
        // that a refused request made no L call at all.
        if lane != Lane::Compaction {
            self.ledger_calls.fetch_add(1, Ordering::Relaxed);
        }
        let (channel, generation) = self.ledger_channel_at();
        // B7 recheck R1: if this future is dropped once the request is on its way (a
        // deadline, a cancellation), the channel hands the answer to `LostAnswers`
        // instead of discarding it, and forward effects are held until it arrives.
        let owner = request.fault_bearing().then(|| {
            Arc::new(LostAnswers {
                node: self.lost_node.clone(),
                generation,
            }) as Arc<dyn workers::Orphan>
        });
        let raw = channel
            .call_owned::<serde_json::Value>(lane, request, deadline_ns, owner)
            .await;
        // Integrated recheck HIGH-2: L died with this fault-bearing request unanswered
        // (or before it could be sent): forward effects wait for its replacement's
        // Handover, exactly as for a lost answer.
        if matches!(raw, Err(CallError::Closed)) && request.fault_bearing() {
            self.transfer_hold(generation, false);
        }
        let reply = raw.and_then(|value| {
            serde_json::from_value::<LedgerReply>(value).map_err(|_| {
                // L answered and lives, but H cannot read the answer: fail stop.
                if request.fault_bearing() {
                    self.set_latch("fail_stop", None, None);
                }
                CallError::Protocol
            })
        });
        // RTC-R2-01: a failed commit latched L and wrote the fail-stop marker. H latches
        // too, and the caller sees an ordinary failure that proves nothing.
        let reply = match reply {
            Ok(LedgerReply::SyncFailed { reason }) => {
                self.set_latch("fail_stop", None, None);
                Ok(LedgerReply::Failed { reason })
            }
            // L refused a forward effect under its own latch, which H had not seen: H
            // latches now, and the caller sees a refusal that wrote nothing.
            Ok(LedgerReply::Latched { kind }) => {
                self.set_latch(&kind, None, None);
                Ok(LedgerReply::Failed {
                    reason: format!("forward effects are latched node-wide ({kind})"),
                })
            }
            other => other,
        };
        if let Ok(LedgerReply::Oversized { bytes }) = &reply {
            // L stayed up and refused the answer; whatever asked treats it as Unknown
            // and stays charged (B5-01). Health says so until the helper restarts.
            *self.ledger_reply_fault.lock().unwrap() = Some(format!(
                "a ledger answer of {bytes} bytes exceeded the worker frame bound"
            ));
        }
        reply
    }
}

/// B7 recheck R1: the owner of every ledger answer whose waiter gave up. The channel
/// parks it on the pending call when the waiter is dropped and hands it the answer
/// (or L's death) when it comes: the fault is imported whatever happened to the request,
/// and the hold on forward effects lasts exactly until then.
struct LostAnswers {
    node: std::sync::Weak<Node>,
    /// The generation of the L the request was sent to.
    generation: u64,
}

/// Integrated recheck HIGH-2: holds transferred from dead L generations, keyed by the
/// generation each request was sent to, and the generations a successful Handover has
/// since imported (all below `handed_over_below`).
#[derive(Default)]
struct TransferredHolds {
    held: std::collections::BTreeMap<u64, usize>,
    handed_over_below: u64,
}

impl workers::Orphan for LostAnswers {
    fn parked(&self) {
        if let Some(node) = self.node.upgrade() {
            node.lost_answers.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn answer(&self, reply: Result<serde_json::Value, CallError>, parked: bool) {
        if let Some(node) = self.node.upgrade() {
            if matches!(reply, Err(CallError::Closed)) {
                // Integrated recheck HIGH-2: L died first. Its durable state comes only
                // with a replacement's Handover, so the hold moves to that barrier
                // instead of lifting.
                node.transfer_hold(self.generation, parked);
                return;
            }
            // Imported first, so a fault latches before the hold lifts.
            node.import_lost_answer(reply);
            if parked {
                node.lost_answers.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

impl Node {
    /// One reserved K slot, then the other. A stuck slot stays occupied by its original
    /// process; this only moves on to the other fixed slot and never spawns a third.
    async fn dispatch_kill(&self, target: StopTarget) -> Option<bool> {
        for slot in &self.recovery {
            let channel = {
                let slot = slot.lock().unwrap();
                if slot.reaped {
                    continue;
                }
                slot.channel.clone()
            };
            let request = RecoveryRequest::Kill {
                target: target.clone(),
            };
            let call = channel.call::<RecoveryReply>(Lane::Normal, &request, u64::MAX);
            if let Ok(Ok(RecoveryReply::Killed { gone })) =
                tokio::time::timeout(Duration::from_millis(2_750), call).await
            {
                return Some(gone);
            }
        }
        None
    }

    async fn probe_process(&self, target: StopTarget) -> Option<bool> {
        for slot in &self.recovery {
            let channel = {
                let slot = slot.lock().unwrap();
                if slot.reaped {
                    continue;
                }
                slot.channel.clone()
            };
            let request = RecoveryRequest::Probe {
                target: target.clone(),
            };
            let call = channel.call::<RecoveryReply>(Lane::Normal, &request, u64::MAX);
            if let Ok(Ok(RecoveryReply::Probed { gone })) =
                tokio::time::timeout(Duration::from_millis(500), call).await
            {
                return Some(gone);
            }
        }
        None
    }

    fn queue_record(&self, record: LedgerRequest) {
        let mut pending = self.pending.lock().unwrap();
        if pending.len() < MAX_PENDING_RECORDS {
            pending.push_back(record);
        }
    }

    /// Later records wait here. Dropping one could only leave a worker unsettled, which
    /// keeps its charge: a full queue fails toward more cost, never toward release.
    /// Writes queued records in order. True once the queue is empty; false when L gave
    /// no usable answer, with that record still first. Cancel-safe (B5-R1): a record in
    /// flight when this future is dropped goes back to the front, so a caller may bound
    /// the flush without losing a record. L may then see it twice, exactly as after
    /// any unanswered call, which this queue has always retried.
    async fn flush_pending(&self) -> bool {
        let _flushing = self.flushing.lock().await;
        loop {
            let Some(record) = self.pending.lock().unwrap().pop_front() else {
                return true;
            };
            let mut requeue = Requeue {
                pending: &self.pending,
                record: Some(record),
            };
            let reply = self
                .ledger_call(Lane::Reserved, requeue.record.as_ref().unwrap(), u64::MAX)
                .await;
            let record = requeue.record.take().unwrap();
            match reply {
                Ok(LedgerReply::Done | LedgerReply::Generation(_)) => {
                    if let (
                        LedgerRequest::RecordChild {
                            instance,
                            allocation,
                            ..
                        },
                        Ok(LedgerReply::Generation(id)),
                    ) = (&record, &reply)
                        && let Some(entry) =
                            self.supervisors.lock().unwrap().get_mut(&AllocationKey {
                                instance: *instance,
                                allocation: *allocation,
                            })
                    {
                        entry.vm_worker = Some(*id as i64);
                    }
                }
                Ok(LedgerReply::Failed { .. } | LedgerReply::Expired) => {
                    // A stale record (the row already moved on) is safe to drop only
                    // because the ledger refused it without changing anything.
                }
                _ => {
                    self.pending.lock().unwrap().push_front(record);
                    return false;
                }
            }
        }
    }

    /// One reserved-lane ledger call that the caller stops waiting for at `until`
    /// (B5-R1). The request carries its own deadline, but L checks that only once it
    /// reads the frame; a stalled L never answers. Missing the bound reads as no answer,
    /// which every caller turns into a charged, ambiguous reply.
    async fn ledger_until(
        &self,
        request: &LedgerRequest,
        deadline_ns: u64,
        until: Instant,
    ) -> Result<LedgerReply, CallError> {
        tokio::time::timeout_at(
            until,
            self.ledger_call(Lane::Reserved, request, deadline_ns),
        )
        .await
        .unwrap_or(Err(CallError::Full))
    }

    /// Irrevocable for this boot: the gate closes, S's permit is revoked and nothing can
    /// reopen either. Later records follow; none of this needs L.
    fn set_stop_fence(&self, key: AllocationKey, reason: &str) {
        let mut supervisors = self.supervisors.lock().unwrap();
        let Some(entry) = supervisors.get_mut(&key) else {
            return;
        };
        if entry.stop_fenced {
            return;
        }
        entry.stop_fenced = true;
        entry.revoked = true;
        entry.revoke_sent = entry.channel.notify(&SupervisorCommand::Revoke);
        drop(supervisors);
        if let Some(gate) = self.gate(key.instance, key.allocation) {
            gate.close(AmbiguousClass::GateClosed);
        }
        self.queue_record(LedgerRequest::RecordStop {
            instance: key.instance,
            allocation: key.allocation,
            reason: reason.into(),
        });
    }

    /// Section 4.4's stop path: revoke reuse in memory first, then dispatch K without
    /// any new fsync. Never a receipt or release: journal evidence follows when it can.
    fn contain_allocation(self: &Arc<Self>, key: AllocationKey, reason: &str) {
        self.set_stop_fence(key, reason);
        self.dispatch_containment(key);
    }

    /// One K dispatch per subtree at a time, until it is gone. The tick retries, so no
    /// subtree is forgotten while both fixed slots are occupied.
    fn dispatch_containment(self: &Arc<Self>, allocation: AllocationKey) {
        let target = {
            let mut supervisors = self.supervisors.lock().unwrap();
            let Some(entry) = supervisors.get_mut(&allocation) else {
                return;
            };
            match &entry.vm {
                Some(target) if !entry.vm_gone && !entry.kill_inflight => {
                    entry.kill_inflight = true;
                    target.clone()
                }
                _ => return,
            }
        };
        let node = self.clone();
        tokio::spawn(async move {
            let gone = node.dispatch_kill(target).await;
            let mut supervisors = node.supervisors.lock().unwrap();
            if let Some(entry) = supervisors.get_mut(&allocation) {
                entry.kill_inflight = false;
                entry.contained = Some(gone.unwrap_or(false));
                entry.vm_gone = entry.vm_gone || gone.unwrap_or(false);
            }
        });
    }

    fn retry_containment(self: &Arc<Self>) {
        let unfinished: Vec<AllocationKey> = self
            .supervisors
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, entry)| entry.stop_fenced && entry.vm.is_some() && !entry.vm_gone)
            .map(|(allocation, _)| *allocation)
            .collect();
        for allocation in unfinished {
            self.dispatch_containment(allocation);
        }
    }

    /// Every live boot, fenced and contained. A monitor that left took its watches and
    /// targets with it, so these boots never get forward effects again, whatever comes.
    fn contain_all(self: &Arc<Self>, reason: &str) {
        let affected: Vec<AllocationKey> =
            self.supervisors.lock().unwrap().keys().copied().collect();
        for allocation in affected {
            self.contain_allocation(allocation, reason);
        }
    }

    async fn monitor_events(
        node: std::sync::Weak<Self>,
        mut events: mpsc::Receiver<serde_json::Value>,
    ) {
        while let Some(event) = events.recv().await {
            let Some(node) = node.upgrade() else { return };
            let Ok(event) = serde_json::from_value::<MonitorEvent>(event) else {
                continue;
            };
            match event {
                MonitorEvent::Status {
                    stale_workers,
                    stale_supervisors,
                } => {
                    node.monitor.lock().unwrap().last_status = std::time::Instant::now();
                    *node.stale_workers.lock().unwrap() = stale_workers;
                    {
                        let mut supervisors = node.supervisors.lock().unwrap();
                        for (allocation, entry) in supervisors.iter_mut() {
                            entry.stalled = stale_supervisors.contains(allocation);
                        }
                    }
                    // A silent S is an irrevocable stop. The same process keeps its slot
                    // and its permit stays charged until it really exits.
                    for allocation in stale_supervisors {
                        node.contain_allocation(allocation, "supervisor heartbeat expired");
                    }
                }
                MonitorEvent::SupervisorLost { allocation } => {
                    node.contain_allocation(allocation, "supervisor lost");
                }
                MonitorEvent::Contained { allocation, gone } => {
                    let mut supervisors = node.supervisors.lock().unwrap();
                    if let Some(entry) = supervisors.get_mut(&allocation) {
                        entry.contained = Some(gone);
                        entry.vm_gone = gone;
                    }
                }
                MonitorEvent::NoRecovery { allocation } => {
                    let mut supervisors = node.supervisors.lock().unwrap();
                    if let Some(entry) = supervisors.get_mut(&allocation) {
                        entry.contained = Some(false);
                    }
                }
            }
        }
    }

    async fn supervise(node: std::sync::Weak<Self>) {
        let (tick, heartbeat) = match node.upgrade() {
            Some(node) => (node.config.timings.tick, node.config.timings.heartbeat),
            None => return,
        };
        let mut last_heartbeat = std::time::Instant::now();
        loop {
            tokio::time::sleep(tick).await;
            let Some(node) = node.upgrade() else { return };
            if node.stop.is_cancelled() {
                return;
            }
            node.reap_supervisors();
            // Before any reap below could make a replacement look healthy.
            node.check_monitor();
            node.reap_infrastructure();
            node.retry_containment();
            if last_heartbeat.elapsed() >= heartbeat {
                last_heartbeat = std::time::Instant::now();
                node.send_heartbeats();
            }
            // A flush already underway covers this tick.
            if node.flushing.try_lock().is_ok() {
                let flusher = node.clone();
                tokio::spawn(async move { flusher.flush_pending().await });
            }
            node.retry_orphans();
        }
    }

    fn retry_orphans(self: &Arc<Self>) {
        let orphans: Vec<_> = self.orphans.lock().unwrap().drain(..).collect();
        if orphans.is_empty() {
            return;
        }
        let node = self.clone();
        tokio::spawn(async move {
            for orphan in orphans {
                let gone = node
                    .probe_process(StopTarget::process(orphan.target))
                    .await
                    .unwrap_or(false);
                if gone {
                    node.queue_record(LedgerRequest::Settle {
                        worker_id: orphan.worker_id,
                        settlement: "gone-after-helper-restart".into(),
                    });
                } else {
                    node.orphans.lock().unwrap().push(orphan);
                }
            }
        });
    }

    fn send_heartbeats(&self) {
        self.monitor
            .lock()
            .unwrap()
            .worker
            .channel
            .notify(&MonitorCommand::Tick);
        for entry in self.supervisors.lock().unwrap().values_mut() {
            if entry.exit.is_some() {
                continue;
            }
            // A revoke that met a full queue is retried until it fits.
            if entry.revoked {
                if !entry.revoke_sent {
                    entry.revoke_sent = entry.channel.notify(&SupervisorCommand::Revoke);
                }
            } else {
                entry.channel.notify(&SupervisorCommand::Tick);
            }
        }
    }

    /// A monitor that exited or went silent denies admission and stops every affected
    /// allocation through K. A repaired monitor never silently resumes those boots.
    fn check_monitor(self: &Arc<Self>) {
        let timeout = self.config.timings.heartbeat_timeout;
        let silent = {
            let monitor = self.monitor.lock().unwrap();
            monitor.worker.channel.is_closed() || monitor.last_status.elapsed() >= timeout
        };
        let mut lost = self.monitor_lost.lock().unwrap();
        if silent && !*lost {
            *lost = true;
            drop(lost);
            self.contain_all("monitor lost");
        } else if !silent {
            *lost = false;
        }
    }

    fn monitor_healthy(&self) -> bool {
        let timeout = self.config.timings.heartbeat_timeout;
        let monitor = self.monitor.lock().unwrap();
        !monitor.worker.channel.is_closed()
            && !monitor.worker.reaped
            && monitor.last_status.elapsed() < timeout
    }

    fn reap_supervisors(self: &Arc<Self>) {
        let mut lost = Vec::new();
        {
            let mut supervisors = self.supervisors.lock().unwrap();
            for (allocation, entry) in supervisors.iter_mut() {
                if entry.exit.is_none()
                    && let Some(evidence) = try_reap(entry.pid)
                {
                    entry.exit = Some(evidence.clone());
                    entry.prep = None;
                    entry.exited.cancel();
                    entry.channel.close();
                    if !entry.revoked {
                        lost.push(*allocation);
                    }
                    if !entry.settle_queued {
                        entry.settle_queued = true;
                        self.queue_record(LedgerRequest::Settle {
                            worker_id: entry.worker_id,
                            settlement: evidence,
                        });
                    }
                }
            }
        }
        for allocation in lost {
            self.contain_allocation(allocation, "supervisor exited");
        }
    }

    /// Reassigns a fixed slot only after its original process exited and was reaped.
    /// A stalled process keeps its slot, however long it takes.
    fn reap_infrastructure(self: &Arc<Self>) {
        self.discarded
            .lock()
            .unwrap()
            .retain(|pid| try_reap(*pid).is_none());
        for kind in SLOTS {
            let due = self.with_slot(kind, |slot| {
                if !slot.reaped
                    && slot.channel.is_closed()
                    && let Some(evidence) = try_reap(slot.pid)
                {
                    slot.reaped = true;
                    slot.exit = Some(evidence);
                }
                let due = slot.reaped && !slot.replacing;
                if due {
                    slot.replacing = true;
                }
                due
            });
            if !due {
                continue;
            }
            // Before a replacement can exist: its watches would start empty, so every
            // existing boot is fenced now and is contained without M.
            if kind == SlotKind::Monitor {
                self.contain_all("monitor exited");
            }
            let node = self.clone();
            tokio::spawn(async move {
                if node.replace_worker(kind).await.is_err() {
                    node.with_slot(kind, |slot| slot.replacing = false);
                }
            });
        }
    }

    fn spawn_slot(&self, kind: SlotKind) -> io::Result<Spawned> {
        Ok(match kind {
            SlotKind::Ledger => Spawned::Plain(spawn_ledger_slot(
                &self.config,
                &self.sockets,
                &self.revocations,
                self._lock.as_ref().map(|lock| lock.raw_fd()),
            )?),
            SlotKind::Prep(index) => {
                Spawned::Plain(spawn_prep_slot(&self.config, &self.sockets, index)?)
            }
            SlotKind::Recovery(index) => {
                Spawned::Plain(spawn_recovery_slot(&self.config, &self.sockets, index)?)
            }
            SlotKind::Monitor => {
                let (slot, events) = spawn_monitor_slot(&self.config, &self.sockets)?;
                Spawned::Monitor(slot, events)
            }
        })
    }

    fn publish_slot(self: &Arc<Self>, kind: SlotKind, spawned: Spawned) {
        match (kind, spawned) {
            (SlotKind::Ledger, Spawned::Plain(slot)) => {
                let mut published = self.ledger.lock().unwrap();
                *published = slot;
                self.ledger_generation.fetch_add(1, Ordering::SeqCst);
            }
            (SlotKind::Prep(index), Spawned::Plain(slot)) => {
                *self.prep[index].lock().unwrap() = slot;
            }
            (SlotKind::Recovery(index), Spawned::Plain(slot)) => {
                *self.recovery[index].lock().unwrap() = slot;
            }
            (SlotKind::Monitor, Spawned::Monitor(slot, events)) => {
                *self.monitor.lock().unwrap() = slot;
                tokio::spawn(Self::monitor_events(Arc::downgrade(self), events));
            }
            _ => unreachable!("spawn_slot makes the kind it was asked for"),
        }
    }

    /// Settles the reaped predecessor, journals the successor's expected image and
    /// identity, and only then hands it any work: no other caller can reach a worker
    /// that is not yet in its slot. With no ledger reply this does not replace at all.
    /// The ledger itself must exist before it can write, so its own row comes first thing.
    async fn replace_worker(self: &Arc<Self>, kind: SlotKind) -> Result<(), ()> {
        let (prior, evidence) = self.with_slot(kind, |slot| (slot.worker_id, slot.exit.clone()));
        let evidence = evidence.unwrap_or_else(|| "exited".into());
        let Some(image) = self.config.helper_image else {
            let mut spawned = self.spawn_slot(kind).map_err(|_| ())?;
            if kind == SlotKind::Ledger {
                let channel = spawned.worker().channel.clone();
                match self.handover_ledger(&channel).await {
                    Ok(key) => spawned.worker_mut().key = Some(key),
                    Err(reason) => {
                        channel.close();
                        self.discarded.lock().unwrap().push(spawned.worker().pid);
                        *self.ledger_replacement_fault.lock().unwrap() =
                            Some(format!("the ledger was not replaced: {reason}"));
                        return Err(());
                    }
                }
            }
            self.publish_slot(kind, spawned);
            return Ok(());
        };
        let spec = Box::new(infrastructure_spec(kind, image));
        if kind == SlotKind::Ledger {
            return self.replace_ledger(prior, evidence, spec).await;
        }
        if let Some(worker_id) = prior {
            let settled = self
                .ledger_call(
                    Lane::Reserved,
                    &LedgerRequest::Settle {
                        worker_id,
                        settlement: evidence,
                    },
                    u64::MAX,
                )
                .await;
            if !matches!(settled, Ok(LedgerReply::Done)) {
                return Err(());
            }
            self.with_slot(kind, |slot| slot.worker_id = None);
        }
        let intent = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::InfrastructureIntent { spec },
                u64::MAX,
            )
            .await;
        let Ok(LedgerReply::Worker { worker_id }) = intent else {
            return Err(());
        };
        let mut spawned = self.spawn_slot(kind).map_err(|_| ())?;
        let pid = spawned.worker().pid;
        let identity = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::RecordWorker { worker_id, pid },
                u64::MAX,
            )
            .await;
        if !matches!(identity, Ok(LedgerReply::Identity { .. })) {
            // Its socket closes, it exits having been given nothing, and it is reaped.
            spawned.worker().channel.close();
            self.discarded.lock().unwrap().push(pid);
            self.queue_record(LedgerRequest::Settle {
                worker_id,
                settlement: "never-served".into(),
            });
            return Err(());
        }
        spawned.worker_mut().worker_id = Some(worker_id);
        self.publish_slot(kind, spawned);
        Ok(())
    }

    /// L alone is forked before its own row can exist. It stays private until it has
    /// settled its predecessor and journaled itself, each with the exact reply: anything
    /// else closes its socket, so it exits having served nothing, and it gets reaped.
    /// The dead slot keeps refusing ledger traffic and the fault is visible in Capabilities.
    async fn replace_ledger(
        self: &Arc<Self>,
        prior: Option<i64>,
        evidence: String,
        spec: Box<WorkerIntentSpec>,
    ) -> Result<(), ()> {
        {
            let mut retry_at = self.ledger_retry_at.lock().unwrap();
            if retry_at.is_some_and(|at| std::time::Instant::now() < at) {
                return Err(());
            }
            *retry_at = Some(std::time::Instant::now() + REPLACEMENT_LEDGER_RETRY);
        }
        let mut spawned = self.spawn_slot(SlotKind::Ledger).map_err(|error| {
            *self.ledger_replacement_fault.lock().unwrap() =
                Some(format!("no replacement ledger process: {error}"));
        })?;
        let channel = spawned.worker().channel.clone();
        let pid = spawned.worker().pid;
        let journaled = match self
            .journal_replacement_ledger(&channel, pid, prior, evidence, spec)
            .await
        {
            Ok(worker_id) => {
                #[cfg(test)]
                workers::faults::hold("H.ledger.before_publish").await;
                self.handover_ledger(&channel)
                    .await
                    .map(|key| (worker_id, key))
            }
            Err(reason) => Err(reason),
        };
        match journaled {
            Ok((worker_id, key)) => {
                spawned.worker_mut().worker_id = Some(worker_id);
                spawned.worker_mut().key = Some(key);
                self.publish_slot(SlotKind::Ledger, spawned);
                *self.ledger_replacement_fault.lock().unwrap() = None;
                *self.ledger_retry_at.lock().unwrap() = None;
                Ok(())
            }
            Err(reason) => {
                channel.close();
                self.discarded.lock().unwrap().push(pid);
                *self.ledger_replacement_fault.lock().unwrap() =
                    Some(format!("the ledger was not replaced: {reason}"));
                Err(())
            }
        }
    }

    async fn journal_replacement_ledger(
        &self,
        channel: &Channel,
        pid: i32,
        prior: Option<i64>,
        evidence: String,
        spec: Box<WorkerIntentSpec>,
    ) -> Result<i64, String> {
        if let Some(worker_id) = prior {
            let settled = tokio::time::timeout(
                REPLACEMENT_LEDGER_REPLY,
                channel.call::<LedgerReply>(
                    Lane::Reserved,
                    &LedgerRequest::Settle {
                        worker_id,
                        settlement: evidence,
                    },
                    u64::MAX,
                ),
            )
            .await;
            if !matches!(settled, Ok(Ok(LedgerReply::Done))) {
                return Err("its predecessor did not settle".into());
            }
            // Durable now, so a later attempt must not settle it again.
            self.with_slot(SlotKind::Ledger, |slot| slot.worker_id = None);
        }
        let recorded = tokio::time::timeout(
            REPLACEMENT_LEDGER_REPLY,
            channel.call::<LedgerReply>(
                Lane::Reserved,
                &LedgerRequest::RecordInfrastructure { spec, pid },
                u64::MAX,
            ),
        )
        .await;
        match recorded {
            Ok(Ok(LedgerReply::Worker { worker_id })) => Ok(worker_id),
            _ => Err("it could not journal its own identity".into()),
        }
    }

    fn gate(&self, instance: Id128, allocation: Id128) -> Option<Arc<TokenGate>> {
        let share = self.share(instance)?;
        let gates = share.gates.lock().unwrap();
        gates.gates.get(&allocation).cloned()
    }

    /// The live holder of this instance is the process making this request. It is the
    /// only one any instance-scoped request can speak for: a request from anyone else
    /// gets no lookup, no answer about a token, and no in-memory state of any kind.
    fn is_holder(&self, instance: Id128, peer: PeerCredentials) -> bool {
        let attachments = self.attachments.lock().unwrap();
        attachments.get(&instance).is_some_and(|attachment| {
            peer.pid == Some(attachment.peer_pid)
                && peer.uid == attachment.peer_uid
                && attachment.pin.alive()
        })
    }

    fn epoch_valid(&self, instance: Id128, epoch: Option<Id128>, peer: PeerCredentials) -> bool {
        let attachments = self.attachments.lock().unwrap();
        attachments.get(&instance).is_some_and(|attachment| {
            Some(attachment.epoch) == epoch
                && peer.pid == Some(attachment.peer_pid)
                && peer.uid == attachment.peer_uid
                && attachment.pin.alive()
        })
    }

    /// The attachment's C2 authority, if this request's epoch is its current one.
    fn admission_authority(&self, instance: Id128) -> Option<AdmissionAuthority> {
        self.attachments
            .lock()
            .unwrap()
            .get(&instance)
            .map(|attachment| attachment.authority)
    }

    fn admission_open(&self, instance: Id128) -> bool {
        self.attachments
            .lock()
            .unwrap()
            .get(&instance)
            .is_some_and(|attachment| attachment.admission_open)
    }

    /// The live holder went away; its epoch is invalid at once. Accepted work stays
    /// ledger-owned, and a later attachment cannot clear any claim.
    pub fn detach(&self, instance: Id128, epoch: Id128) {
        let mut attachments = self.attachments.lock().unwrap();
        if let Some(attachment) = attachments.get(&instance).filter(|a| a.epoch == epoch) {
            // One atomic store, with no wait on L: from here nothing queued under this
            // attachment can commit, and whatever just did gets no effects.
            self.revocations.revoke(attachment.authority.slot);
            attachments.remove(&instance);
        }
    }

    /// One Firecracker request. Epoch-checked read operations run under the waiter;
    /// Create and FenceAbsent become detached work whose ownership outlives it.
    pub async fn handle(
        self: &Arc<Self>,
        request: FirecrackerRequest,
        peer: PeerCredentials,
        pin: Option<PeerPin>,
        deadline: WireDeadline,
        cancel: &CancellationToken,
    ) -> FirecrackerResponse {
        self.handle_with_stdio(request, peer, pin, deadline, cancel, None)
            .await
    }

    /// As [`Self::handle`], with an Exec's helper-side stdio ends (B5).
    pub async fn handle_with_stdio(
        self: &Arc<Self>,
        request: FirecrackerRequest,
        peer: PeerCredentials,
        pin: Option<PeerPin>,
        deadline: WireDeadline,
        cancel: &CancellationToken,
        stdio: Option<[std::os::fd::OwnedFd; 3]>,
    ) -> FirecrackerResponse {
        let instance = request.instance_id;
        let epoch = request.connection_epoch;
        if let FirecrackerOperation::AttachInstance {
            database_uuid,
            highest_token,
        } = request.operation
        {
            return self
                .attach(instance, database_uuid, highest_token, peer, pin, deadline)
                .await;
        }
        let peer = PeerCredentials {
            uid: self.observed_uid(peer, instance),
            ..peer
        };
        // B7 RTC-3: every token a request names is tag-checked in the caller's instance
        // before any gate, quota or L call (a Gc's whole vector, all or nothing). Only
        // the instance's live holder gets even this answer.
        let tokens: Vec<Id128> = match &request.operation {
            FirecrackerOperation::Create { allocation_id, .. }
            | FirecrackerOperation::FenceAbsent { allocation_id, .. }
            | FirecrackerOperation::Stop { allocation_id, .. }
            | FirecrackerOperation::Remove { allocation_id, .. }
            | FirecrackerOperation::Inspect { allocation_id, .. }
            | FirecrackerOperation::Validate { allocation_id, .. }
            | FirecrackerOperation::Exec { allocation_id, .. } => vec![*allocation_id],
            FirecrackerOperation::Gc { targets } => {
                targets.iter().map(|t| t.allocation_id).collect()
            }
            _ => Vec::new(),
        };
        if !tokens.is_empty() && self.is_holder(instance, peer) {
            for token in &tokens {
                if let Err(refusal) = self.check_token(instance, *token) {
                    return *refusal;
                }
            }
        }
        // B7 RTC-14: under the latch, work that starts anything is refused before any
        // gate, L write or host action. Cleanup and reads stay.
        if matches!(
            request.operation,
            FirecrackerOperation::Preflight { .. }
                | FirecrackerOperation::Create { .. }
                | FirecrackerOperation::Validate { .. }
                | FirecrackerOperation::Exec { .. }
        ) && self.latched_once_answered(deadline.instant).await
        {
            return self.latch_refusal();
        }
        match request.operation {
            FirecrackerOperation::AttachInstance { .. } => unreachable!("handled above"),
            FirecrackerOperation::Create {
                allocation_id,
                sandbox_id,
                plan,
                plan_digest,
            } => {
                let (Some(share), true) = (self.share(instance), self.is_holder(instance, peer))
                else {
                    return FirecrackerResponse::Create(ambiguous_create(
                        AmbiguousClass::OldEpoch,
                        "this process does not hold the instance",
                    ));
                };
                let node = self.clone();
                let token = CreateToken {
                    instance,
                    epoch,
                    peer,
                    allocation: allocation_id,
                    sandbox_id,
                    plan: plan.0,
                    plan_digest,
                    deadline,
                };
                let reply = self
                    .run_detached(
                        &share,
                        deadline,
                        cancel,
                        allocation_id,
                        ambiguous_create(AmbiguousClass::Pending, "create outcome not yet known"),
                        move || node.create_flow(token),
                    )
                    .await;
                FirecrackerResponse::Create(reply)
            }
            FirecrackerOperation::FenceAbsent {
                allocation_id,
                sandbox_id,
                plan_digest,
            } => {
                let (Some(share), true) = (self.share(instance), self.is_holder(instance, peer))
                else {
                    return FirecrackerResponse::Fence(ambiguous_fence(
                        AmbiguousClass::OldEpoch,
                        "this process does not hold the instance",
                    ));
                };
                let node = self.clone();
                let token = FenceToken {
                    instance,
                    epoch,
                    peer,
                    allocation: allocation_id,
                    sandbox_id,
                    plan_digest,
                    deadline,
                };
                let reply = self
                    .run_detached(
                        &share,
                        deadline,
                        cancel,
                        allocation_id,
                        ambiguous_fence(AmbiguousClass::Pending, "fence outcome not yet known"),
                        move || node.fence_flow(token),
                    )
                    .await;
                FirecrackerResponse::Fence(reply)
            }
            FirecrackerOperation::Stop {
                allocation_id,
                expected_generation,
                reason,
            } => {
                let (Some(share), true) = (self.share(instance), self.is_holder(instance, peer))
                else {
                    return FirecrackerResponse::Stop(protocol::StopReply::Unknown {
                        reason: "this process does not hold the instance".into(),
                    });
                };
                if !self.epoch_valid(instance, epoch, peer) {
                    return group_error(
                        GroupErrorKind::StaleEpoch,
                        "connection epoch is not current for this instance",
                    );
                }
                let node = self.clone();
                let key = AllocationKey {
                    instance,
                    allocation: allocation_id,
                };
                let reply = self
                    .run_detached(
                        &share,
                        deadline,
                        cancel,
                        allocation_id,
                        protocol::StopReply::Unknown {
                            reason: "stop outcome not yet known".into(),
                        },
                        move || async move {
                            node.stop_flow(key, expected_generation, reason, deadline)
                                .await
                        },
                    )
                    .await;
                FirecrackerResponse::Stop(reply)
            }
            FirecrackerOperation::Remove {
                allocation_id,
                plan_digest,
            } => {
                let (Some(share), true) = (self.share(instance), self.is_holder(instance, peer))
                else {
                    return FirecrackerResponse::Remove(ambiguous_fence(
                        AmbiguousClass::OldEpoch,
                        "this process does not hold the instance",
                    ));
                };
                let node = self.clone();
                let token = lifecycle::RemoveToken {
                    instance,
                    epoch,
                    peer,
                    allocation: allocation_id,
                    plan_digest,
                    deadline,
                };
                let reply = self
                    .run_detached(
                        &share,
                        deadline,
                        cancel,
                        allocation_id,
                        ambiguous_fence(AmbiguousClass::Pending, "removal outcome not yet known"),
                        move || node.remove_flow(token),
                    )
                    .await;
                FirecrackerResponse::Remove(reply)
            }
            FirecrackerOperation::Gc { targets } => {
                let (Some(share), true) = (self.share(instance), self.is_holder(instance, peer))
                else {
                    return group_error(
                        GroupErrorKind::Unauthorized,
                        "this process does not hold the instance",
                    );
                };
                if !self.epoch_valid(instance, epoch, peer) {
                    return group_error(
                        GroupErrorKind::StaleEpoch,
                        "connection epoch is not current for this instance",
                    );
                }
                let node = self.clone();
                let anchor = targets
                    .first()
                    .map(|t| t.allocation_id)
                    .unwrap_or_else(Id128::random);
                let reply = self
                    .run_detached(&share, deadline, cancel, anchor, Vec::new(), move || {
                        node.gc_flow(instance, epoch, peer, targets, deadline)
                    })
                    .await;
                FirecrackerResponse::Gc(reply)
            }
            FirecrackerOperation::Validate {
                allocation_id,
                expected_boot_id,
                expected_inner_id,
            } => {
                if !self.is_holder(instance, peer) || !self.epoch_valid(instance, epoch, peer) {
                    return group_error(
                        GroupErrorKind::Unauthorized,
                        "this process does not hold the instance",
                    );
                }
                let key = AllocationKey {
                    instance,
                    allocation: allocation_id,
                };
                let node = self.clone();
                let work = tokio::spawn(async move {
                    node.validate_op(key, expected_boot_id, expected_inner_id, deadline)
                        .await
                });
                match work.await {
                    Ok(reply) => FirecrackerResponse::Validate(reply),
                    Err(_) => group_error(GroupErrorKind::Unavailable, "validation panicked"),
                }
            }
            FirecrackerOperation::Exec {
                allocation_id,
                expected_boot_id,
                execution_token,
                execution_id,
                argv,
                stdin_bytes,
                max_output,
            } => {
                if !self.is_holder(instance, peer) || !self.epoch_valid(instance, epoch, peer) {
                    return group_error(
                        GroupErrorKind::Unauthorized,
                        "this process does not hold the instance",
                    );
                }
                let Some(stdio) = stdio else {
                    return group_error(GroupErrorKind::Unavailable, "no execution stdio");
                };
                let key = AllocationKey {
                    instance,
                    allocation: allocation_id,
                };
                // Its own task: the caller's disconnect is an interruption the work
                // itself carries through the stop barrier, never a dropped future.
                let node = self.clone();
                let waiter = cancel.clone();
                let work = tokio::spawn(async move {
                    node.exec_op(
                        key,
                        expected_boot_id,
                        execution_token,
                        execution_id,
                        argv,
                        stdin_bytes,
                        max_output,
                        stdio,
                        deadline,
                        waiter,
                    )
                    .await
                });
                match work.await {
                    Ok(reply) => FirecrackerResponse::Exec(Box::new(reply)),
                    Err(_) => group_error(GroupErrorKind::Unavailable, "execution panicked"),
                }
            }
            #[cfg(test)]
            FirecrackerOperation::TestDispatchProbe { allocation_id } => {
                FirecrackerResponse::TestDispatch {
                    admitted: self.reusable_dispatch(AllocationKey {
                        instance,
                        allocation: allocation_id,
                    }),
                }
            }
            operation => {
                if !self.epoch_valid(instance, epoch, peer) {
                    return group_error(
                        GroupErrorKind::StaleEpoch,
                        "connection epoch is not current for this instance",
                    );
                }
                let response = async {
                    match operation {
                        FirecrackerOperation::Capabilities => self.capabilities(instance),
                        FirecrackerOperation::Accounting => {
                            self.accounting(instance, deadline).await
                        }
                        FirecrackerOperation::Preflight {
                            sandbox_id,
                            profile,
                            spec,
                        } => {
                            self.preflight(instance, sandbox_id, profile, spec, deadline)
                                .await
                        }
                        FirecrackerOperation::Inspect {
                            allocation_id,
                            plan_digest,
                        } => {
                            // Holds a settlement's first look for the deterministic
                            // capacity crash scenario (B7, B6-RC-03).
                            #[cfg(test)]
                            workers::faults::hold("H.inspect").await;
                            self.inspect(instance, allocation_id, plan_digest, deadline)
                                .await
                        }
                        FirecrackerOperation::List => {
                            // Holds a whole normal operation open for the budget tests.
                            #[cfg(test)]
                            workers::faults::hold("H.list").await;
                            self.list(instance, deadline).await
                        }
                        _ => unreachable!("handled above"),
                    }
                };
                tokio::pin!(response);
                tokio::select! {
                    response = &mut response => response,
                    _ = cancel.cancelled() => group_error(
                        GroupErrorKind::Unavailable, "request canceled"),
                    _ = tokio::time::sleep_until(deadline.instant) => group_error(
                        GroupErrorKind::Unavailable, "request deadline expired"),
                }
            }
        }
    }

    /// Accepted work runs on its own task. A waiter that times out or disconnects gets
    /// an honest "not yet known", and permits and ownership stay exactly where they are.
    /// No free slot in this instance's share leaves no new state either: the lookup has
    /// not run yet, and only an existing gate can close on this.
    async fn run_detached<T, F, Fut>(
        self: &Arc<Self>,
        share: &InstanceShare,
        deadline: WireDeadline,
        cancel: &CancellationToken,
        allocation: Id128,
        unknown: T,
        work: F,
    ) -> T
    where
        T: Send + 'static,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        let Ok(permit) = share.detached.clone().try_acquire_owned() else {
            if let Some(gate) = share.gates.lock().unwrap().gates.get(&allocation) {
                gate.close(AmbiguousClass::WorkerExhausted);
            }
            return unknown;
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let future = work();
        tokio::spawn(async move {
            let reply = future.await;
            drop(permit);
            let _ = reply_tx.send(reply);
        });
        tokio::pin!(reply_rx);
        tokio::select! {
            reply = &mut reply_rx => reply.unwrap_or(unknown),
            _ = cancel.cancelled() => unknown,
            _ = tokio::time::sleep_until(deadline.instant + LOOKUP_GRACE) => unknown,
        }
    }

    /// Root's enrollment is the only authority here. An unenrolled instance is refused
    /// with no L call and no state. For an enrolled one, L proves the connecting process
    /// is the enrolled service, and the database UUID only names reconciliation state.
    async fn attach(
        self: &Arc<Self>,
        instance: Id128,
        database_uuid: Id128,
        highest_token: Option<Id128>,
        peer: PeerCredentials,
        pin: Option<PeerPin>,
        deadline: WireDeadline,
    ) -> FirecrackerResponse {
        let (Some(peer_pid), Some(pin)) = (peer.pid, pin) else {
            return group_error(
                GroupErrorKind::Unauthorized,
                "the connecting process cannot be identified",
            );
        };
        if self.shares.lock().unwrap().is_none() {
            let reason = self.ledger_fault.lock().unwrap().clone();
            return group_error(
                GroupErrorKind::Unavailable,
                reason.unwrap_or_else(|| "the node ledger has not been read".into()),
            );
        }
        #[cfg(test)]
        if self.config.test.auto_enroll && self.share(instance).is_none() {
            self.test_enroll(instance, peer_pid).await;
        }
        // The queue is chosen by what the kernel says about this peer, never by the
        // instance it names, so nothing unproven can reach another instance's queue.
        let peer_uid = self.observed_uid(peer, instance);
        let serves_it = {
            let shares = self.shares.lock().unwrap();
            shares.as_ref().and_then(|s| s.by_uid.get(&peer_uid)) == Some(&instance)
        };
        let share = self.share(instance).filter(|_| serves_it);
        let Some(share) = share else {
            return group_error(
                GroupErrorKind::Unauthorized,
                "this instance is not enrolled under this account",
            );
        };
        if self.holder_alive(instance) {
            return group_error(
                GroupErrorKind::AlreadyAttached,
                "another live holder has this instance",
            );
        }
        // This account's own queue, so nothing another account does can fill it.
        if share.attach_waiters.fetch_add(1, Ordering::AcqRel) >= MAX_ATTACH_WAITERS {
            share.attach_waiters.fetch_sub(1, Ordering::AcqRel);
            return group_error(
                GroupErrorKind::ResourceExhausted,
                "too many attach attempts from this account",
            );
        }
        let turn =
            tokio::time::timeout_at(deadline.instant, share.attach_turn.clone().acquire_owned())
                .await;
        share.attach_waiters.fetch_sub(1, Ordering::AcqRel);
        let Ok(Ok(_turn)) = turn else {
            return group_error(GroupErrorKind::Unavailable, "attach deadline expired");
        };
        if self.holder_alive(instance) {
            return group_error(
                GroupErrorKind::AlreadyAttached,
                "another live holder has this instance",
            );
        }
        // B7 RTC-14: the report is checked exactly as RTC-3 checks any token, in this
        // account's own instance. A malformed, foreign or bit-flipped report fails this
        // attachment alone, with no L call, latch or write.
        if let Some(token) = highest_token
            && let Err(refusal) = self.check_token(instance, token)
        {
            return *refusal;
        }
        let reply = tokio::time::timeout_at(
            deadline.instant,
            self.ledger_call(
                Lane::Attach,
                &LedgerRequest::Attach {
                    instance,
                    database_uuid,
                    peer_pid,
                    highest_token,
                },
                deadline.ns,
            ),
        )
        .await;
        let (outcome, peer_start) = match reply {
            Ok(Ok(LedgerReply::FaultPending { token, issue_next })) => {
                return self.rollback_detected(instance, token, issue_next).await;
            }
            Ok(Ok(LedgerReply::Attached {
                outcome,
                peer_start,
            })) => (outcome, peer_start),
            Ok(Ok(LedgerReply::AttachRefused { reason })) => {
                tracing::warn!(%instance, peer_pid, %reason, "attachment refused");
                return group_error(
                    GroupErrorKind::Unauthorized,
                    "this process is not the enrolled service for that instance",
                );
            }
            Ok(Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason })) => {
                return group_error(GroupErrorKind::Unavailable, reason);
            }
            _ => return group_error(GroupErrorKind::Unavailable, "ledger did not answer attach"),
        };
        // Still alive means the connector kept this number through L's reads, so the
        // process L proved is the one on this connection, not a later user of its PID.
        if !pin.alive() {
            return group_error(
                GroupErrorKind::Unauthorized,
                "the connecting process is gone",
            );
        }
        let Ok(epoch) = fresh_id() else {
            return group_error(GroupErrorKind::Unavailable, "no entropy for an epoch");
        };
        let (node_id, admission_open) = match outcome {
            AttachOutcome::Bound { node_id, .. } => (node_id, true),
            AttachOutcome::DatabaseMismatch { node_id, .. } => (node_id, false),
            AttachOutcome::NotEnrolled => {
                return group_error(
                    GroupErrorKind::Unauthorized,
                    "this instance is not enrolled",
                );
            }
            AttachOutcome::Malformed => {
                return group_error(
                    GroupErrorKind::Incompatible,
                    "the reported highest token was not issued to this instance",
                );
            }
            AttachOutcome::Latched => return self.latch_refusal(),
            AttachOutcome::RollbackDetected { token, issue_next } => {
                return self.rollback_detected(instance, token, issue_next).await;
            }
        };
        {
            let mut attachments = self.attachments.lock().unwrap();
            // A holder whose process died but whose socket lingers in another process
            // holds nothing. Its epoch ends here, and its own EOF later finds a new one.
            if let Some(stale) = attachments.remove(&instance) {
                self.revocations.revoke(stale.authority.slot);
            }
            let Some(slot) = (0..MAX_ENROLLED_HARD)
                .find(|slot| !attachments.values().any(|a| a.authority.slot == *slot))
            else {
                return group_error(GroupErrorKind::ResourceExhausted, "too many attachments");
            };
            let authority = AdmissionAuthority {
                slot,
                generation: self.next_authority.fetch_add(1, Ordering::Relaxed),
            };
            if admission_open {
                self.revocations.publish(slot, authority.generation);
            } else {
                self.revocations.revoke(slot);
            }
            attachments.insert(
                instance,
                Attachment {
                    epoch,
                    peer_pid,
                    peer_uid,
                    peer_start,
                    pin,
                    admission_open,
                    authority,
                },
            );
        }
        FirecrackerResponse::Attached {
            node_id,
            connection_epoch: epoch,
            admission_open,
        }
    }

    /// B7 RTC-14 and RTC-R2-03: L has latched and written nothing. H latches here, in
    /// memory and atomically, and only then asks L to commit the fault. If the commit
    /// fails or its outcome is unknown, the fault stays pending: every replacement L
    /// commits it before serving, and the latch stays for this process's life.
    async fn rollback_detected(
        self: &Arc<Self>,
        instance: Id128,
        token: Id128,
        issue_next: u64,
    ) -> FirecrackerResponse {
        tracing::error!(%instance, %token, issue_next, "rollback detected: the node ledger is behind a verified token");
        self.set_latch("rollback", Some(instance), Some((instance, token, issue_next)));
        #[cfg(test)]
        workers::faults::hold("H.fault.latched_before_commit").await;
        let committed = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::CommitFault {
                    instance,
                    token,
                    issue_next,
                },
                u64::MAX,
            )
            .await;
        if matches!(committed, Ok(LedgerReply::FaultCommitted { .. })) {
            self.latch.lock().unwrap().pending = None;
        }
        group_error(
            GroupErrorKind::Incompatible,
            "the reported token is ahead of the node ledger: a rollback is latched node-wide",
        )
    }

    fn holder_alive(&self, instance: Id128) -> bool {
        self.attachments
            .lock()
            .unwrap()
            .get(&instance)
            .is_some_and(|attachment| attachment.pin.alive())
    }

    /// The fixture's stand-in for root's enrollment command, for tests of other things.
    #[cfg(test)]
    async fn test_enroll(&self, instance: Id128, peer_pid: i32) {
        let enrolled = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::TestEnroll { instance, peer_pid },
                u64::MAX,
            )
            .await;
        if matches!(enrolled, Ok(LedgerReply::Done)) {
            let capacity = self.config.max_enrolled as usize;
            if let Some(shares) = self.shares.lock().unwrap().as_mut() {
                let (uid, _) = peer::fixture_account(instance);
                shares.by_uid.insert(uid, instance);
                shares
                    .by_instance
                    .entry(instance)
                    .or_insert_with(|| Arc::new(InstanceShare::new(capacity)));
            }
        }
    }

    fn worker_health(&self, slot: &WorkerSlot, name: &str, stale: &[String]) -> WorkerHealth {
        if slot.channel.is_closed() || slot.reaped {
            WorkerHealth::Dead
        } else if stale.iter().any(|worker| worker == name) {
            WorkerHealth::Stalled
        } else if slot.busy.load(Ordering::Acquire) {
            WorkerHealth::Busy
        } else {
            WorkerHealth::Healthy
        }
    }

    /// Cached: no worker is asked. It answers while every worker is stuck.
    fn capabilities(&self, instance: Id128) -> FirecrackerResponse {
        let stale = self.stale_workers.lock().unwrap().clone();
        let monitor = if self.monitor_healthy() {
            WorkerHealth::Healthy
        } else {
            WorkerHealth::Stalled
        };
        let mut ledger_fault = self.ledger_fault.lock().unwrap().clone();
        if ledger_fault.is_none() {
            ledger_fault = self.ledger_replacement_fault.lock().unwrap().clone();
        }
        if ledger_fault.is_none() {
            ledger_fault = self.lease_fault.lock().unwrap().clone();
        }
        if ledger_fault.is_none() {
            ledger_fault = self.ledger_reply_fault.lock().unwrap().clone();
        }
        let health = WorkersHealth {
            ledger: self.worker_health(&self.ledger.lock().unwrap(), "ledger", &stale),
            preparation: [
                self.worker_health(&self.prep[0].lock().unwrap(), "prep-0", &stale),
                self.worker_health(&self.prep[1].lock().unwrap(), "prep-1", &stale),
            ],
            monitor,
            recovery: [
                self.worker_health(&self.recovery[0].lock().unwrap(), "recovery-0", &stale),
                self.worker_health(&self.recovery[1].lock().unwrap(), "recovery-1", &stale),
            ],
            supervisors: self
                .supervisors
                .lock()
                .unwrap()
                .values()
                .filter(|entry| entry.exit.is_none())
                .count() as u64,
            ledger_fault,
            node_fault: {
                let latch = self.latch.lock().unwrap();
                latch.kind.as_ref().map(|kind| {
                    if latch.detector == Some(instance) {
                        format!("{kind}: detected by this instance's verified token")
                    } else {
                        kind.clone()
                    }
                })
            },
            compaction_fault: self.compaction_fault.lock().unwrap().clone(),
        };
        FirecrackerResponse::Capabilities(CapabilitiesReply {
            group_version: FIRECRACKER_GROUP_VERSION,
            broker_protocol: 1,
            helper_version: env!("CARGO_PKG_VERSION").into(),
            enabled: true,
            launch_enabled: !self.config.profiles.is_empty() && self.real_plan(b"{}").is_some(),
            profiles: self
                .config
                .profiles
                .iter()
                .map(|p| p.catalog.profile.clone())
                .collect(),
            health: Some(health),
        })
    }

    async fn accounting(&self, instance: Id128, deadline: WireDeadline) -> FirecrackerResponse {
        let reply = tokio::time::timeout_at(
            deadline.instant,
            self.ledger_call(
                Lane::Reserved,
                &LedgerRequest::Accounting {
                    instance: Some(instance),
                },
                deadline.ns,
            ),
        )
        .await;
        FirecrackerResponse::Accounting(match reply {
            Ok(Ok(LedgerReply::Accounting(snapshot))) => AccountingReply::Fresh(snapshot),
            Ok(Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason })) => {
                AccountingReply::Unknown { reason }
            }
            _ => AccountingReply::Unknown {
                reason: "the node ledger did not answer inside the deadline".into(),
            },
        })
    }

    /// B7 RTC-2 and RTC-4: the helper issues the token. L commits the exact pointer and
    /// the identity snapshot in one transaction; P then binds the token into the plan.
    /// Once committed the seq may be abandoned (a refusal from P, a lost reply), never
    /// reused.
    async fn preflight(
        self: &Arc<Self>,
        instance: Id128,
        sandbox_id: String,
        profile: String,
        spec: SandboxSpec,
        deadline: WireDeadline,
    ) -> FirecrackerResponse {
        if !self.admission_open(instance) {
            return group_error(
                GroupErrorKind::OwnershipConflict,
                "this namespace belongs to another database; admission is blocked",
            );
        }
        if let Some(fault) = self.lease_fault.lock().unwrap().clone() {
            return group_error(GroupErrorKind::Incompatible, fault);
        }
        if deadline.expired() {
            return group_error(GroupErrorKind::Unavailable, "preflight deadline expired");
        }
        // Take the preparation slot before issuing, so a busy node refuses without
        // consuming a seq. Preflight never waits for one.
        let Some(lease) = self.try_prep_slot() else {
            return group_error(
                GroupErrorKind::ResourceExhausted,
                "every preparation slot is in use",
            );
        };
        #[cfg(test)]
        workers::faults::hold("H.preflight.before_issue").await;
        if self.latched_once_answered(deadline.instant).await {
            return self.latch_refusal();
        }
        let issued = self
            .ledger_call(
                Lane::Normal,
                &LedgerRequest::IssueAndSnapshot { instance },
                deadline.ns,
            )
            .await;
        let (allocation, claimed) = match issued {
            Ok(LedgerReply::Issued(journal::IssueOutcome::Issued { token, claimed })) => {
                (token, claimed)
            }
            Ok(LedgerReply::Issued(journal::IssueOutcome::Refused { refusal })) => {
                use journal::IssueRefusal;
                return match refusal {
                    IssueRefusal::Latched => self.latch_refusal(),
                    IssueRefusal::Headroom => group_error(
                        GroupErrorKind::ResourceExhausted,
                        "no admitted headroom is left for this instance",
                    ),
                    IssueRefusal::NeverAdmittedFloor => group_error(
                        GroupErrorKind::ResourceExhausted,
                        "this instance's never-admitted fences fill its window quota",
                    ),
                    IssueRefusal::Exhausted => group_error(
                        GroupErrorKind::ResourceExhausted,
                        "this instance's issue sequence is exhausted",
                    ),
                    IssueRefusal::LedgerSpace => group_error(
                        GroupErrorKind::ResourceExhausted,
                        "the node ledger is past its share of the reservation",
                    ),
                    IssueRefusal::NotEnrolled => group_error(
                        GroupErrorKind::Unauthorized,
                        "this instance is not enrolled",
                    ),
                };
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                return group_error(GroupErrorKind::Unavailable, reason);
            }
            Err(CallError::Full) => {
                return group_error(GroupErrorKind::ResourceExhausted, "ledger queue is full");
            }
            _ => return group_error(GroupErrorKind::Unavailable, "ledger did not answer"),
        };
        #[cfg(test)]
        workers::faults::hold("H.preflight.after_l_reply_before_public").await;
        match self
            .prep_with(
                lease,
                PrepRequest::Preflight {
                    instance,
                    allocation,
                    sandbox_id,
                    profile,
                    spec,
                    claimed,
                },
                deadline,
            )
            .await
        {
            Ok(PrepReply::Prepared(prepared)) if prepared.allocation_id == allocation => {
                if workers::fault_enabled("H.preflight.drop_public_reply") {
                    return group_error(GroupErrorKind::Unavailable, "injected lost reply");
                }
                FirecrackerResponse::Prepared(prepared)
            }
            Ok(PrepReply::Prepared(_)) => group_error(
                GroupErrorKind::Unavailable,
                "preparation bound another token",
            ),
            Ok(PrepReply::Refused { reason }) => group_error(GroupErrorKind::Incompatible, reason),
            Err(CallError::Full) => group_error(
                GroupErrorKind::ResourceExhausted,
                "every preparation slot is in use",
            ),
            _ => group_error(GroupErrorKind::Unavailable, "preparation worker failed"),
        }
    }

    /// The detached body of Create. The ordering is the design's: durable token lookup
    /// first, then gate, epoch, deadline and revalidation, then the one C2 transaction.
    async fn create_flow(self: Arc<Self>, token: CreateToken) -> CreateReply {
        // Holds a real manager's Create after its C1 and before anything here.
        #[cfg(test)]
        workers::faults::hold(&format!("H.create.enter.{}", token.instance)).await;
        let Some(share) = self.share(token.instance) else {
            return ambiguous_create(AmbiguousClass::OldEpoch, "this instance is not enrolled");
        };
        // An open entry for serialization only: it leaves with this flow unless the
        // durable lookup says Unknown and a later step rejects the token.
        let entry = GateUse::enter(share.clone(), token.allocation);
        let gate = entry.gate.clone();
        if gate.waiters.fetch_add(1, Ordering::AcqRel) >= MAX_TOKEN_WAITERS {
            gate.waiters.fetch_sub(1, Ordering::AcqRel);
            return ambiguous_create(AmbiguousClass::Pending, "too many queued duplicates");
        }
        let serial = gate.serial.clone().lock_owned().await;
        gate.waiters.fetch_sub(1, Ordering::AcqRel);
        let _serial = serial;
        // An existing record is authoritative whatever else has changed since.
        let reply = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::Lookup {
                    instance: token.instance,
                    allocation: token.allocation,
                    plan_digest: token.plan_digest,
                },
                token.deadline.with_grace(),
            )
            .await;
        match reply {
            Ok(LedgerReply::Lookup(TokenLookup::Fenced { receipt })) => {
                gate.mark_durable();
                return CreateReply::Absent {
                    receipt: WireBytes(receipt),
                };
            }
            Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                gate.mark_durable();
                return ambiguous_create(AmbiguousClass::Conflict, reason);
            }
            Ok(LedgerReply::Lookup(TokenLookup::Active {
                generation, phase, ..
            })) => {
                gate.mark_durable();
                // The expired read-only grace can return a fence and nothing else.
                if token.deadline.expired() {
                    return ambiguous_create(AmbiguousClass::Expired, "create deadline expired");
                }
                return CreateReply::Accepted {
                    generation,
                    phase,
                    replay: true,
                };
            }
            // B7 RTC-8: absent forever. No gate is closed or retained (RTC-15).
            Ok(LedgerReply::Lookup(TokenLookup::Compacted { receipt })) => {
                gate.mark_durable();
                return CreateReply::Absent {
                    receipt: WireBytes(receipt),
                };
            }
            Ok(LedgerReply::Lookup(TokenLookup::NotIssued)) => {
                gate.mark_durable();
                return ambiguous_create(
                    AmbiguousClass::NotIssued,
                    "this token was never issued by this node ledger",
                );
            }
            Ok(LedgerReply::Lookup(TokenLookup::Malformed)) => {
                gate.mark_durable();
                return ambiguous_create(
                    AmbiguousClass::Conflict,
                    "this token does not verify in this instance",
                );
            }
            Ok(LedgerReply::Lookup(TokenLookup::Unknown)) => {}
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                return ambiguous_create(AmbiguousClass::LedgerUnavailable, reason);
            }
            Ok(_) | Err(_) => {
                return ambiguous_create(
                    AmbiguousClass::LedgerUnavailable,
                    "token lookup had no answer",
                );
            }
        }
        if let Some(class) = gate.closed() {
            return ambiguous_create(
                AmbiguousClass::GateClosed,
                format!("this token was rejected earlier ({class:?}); it needs its fence"),
            );
        }
        // A rejection below must be able to close this gate, or it can't start at all. Only
        // this instance's own rejected tokens can fill its table, and only for its new work.
        if !share.gates.lock().unwrap().make_room() {
            return ambiguous_create(
                AmbiguousClass::WorkerExhausted,
                "this instance has too many rejected tokens awaiting their fences",
            );
        }
        // Every rejection below closes the gate before answering.
        let reject = |class: AmbiguousClass, message: String| {
            gate.close(class);
            ambiguous_create(class, message)
        };
        if !self.epoch_valid(token.instance, token.epoch, token.peer) {
            return reject(
                AmbiguousClass::OldEpoch,
                "connection epoch is not current".into(),
            );
        }
        if !self.admission_open(token.instance) {
            return reject(
                AmbiguousClass::AdmissionBlocked,
                "this namespace belongs to another database".into(),
            );
        }
        // This attachment's authority is what the rest of this Create runs under.
        let Some(authority) = self.admission_authority(token.instance) else {
            return reject(
                AmbiguousClass::OldEpoch,
                "connection epoch is not current".into(),
            );
        };
        if let Some(fault) = self.lease_fault.lock().unwrap().clone() {
            return reject(AmbiguousClass::CatalogMismatch, fault);
        }
        if token.deadline.expired() {
            return reject(AmbiguousClass::Expired, "create deadline expired".into());
        }
        if !self.monitor_healthy() {
            return reject(
                AmbiguousClass::MonitorUnavailable,
                "the process monitor is not healthy".into(),
            );
        }
        let revalidated = match self
            .queued_prep_call(
                PrepRequest::Revalidate {
                    instance: token.instance,
                    allocation: token.allocation,
                    sandbox_id: token.sandbox_id.clone(),
                    plan: token.plan.clone(),
                    plan_digest: token.plan_digest,
                },
                token.deadline,
            )
            .await
        {
            Ok(PrepReply::Revalidated(plan)) => plan,
            Ok(PrepReply::Rejected {
                class,
                reason,
                malformed,
            }) => {
                if malformed {
                    gate.close_evictable(class);
                    return ambiguous_create(class, reason);
                }
                return reject(class, reason);
            }
            Ok(_) => {
                return reject(
                    AmbiguousClass::WorkerPanic,
                    "unexpected worker reply".into(),
                );
            }
            Err(error) => {
                return reject(
                    call_class(error),
                    "preparation worker gave no answer".into(),
                );
            }
        };
        // Revalidation can take a while: its answer authorizes only a request that
        // still has both its attachment and its original deadline.
        if !self.revocations.is_current(&authority) {
            return reject(
                AmbiguousClass::OldEpoch,
                "the attachment was replaced during revalidation".into(),
            );
        }
        if token.deadline.expired() {
            return reject(AmbiguousClass::Expired, "create deadline expired".into());
        }
        let Some(image) = self.config.helper_image else {
            return reject(
                AmbiguousClass::CatalogMismatch,
                "no verified helper image is pinned".into(),
            );
        };
        let host_name = identity::host_name(token.instance, token.allocation);
        let cgroup = format!(
            "kilnd-firecracker/{}/{host_name}/{SUPERVISOR_CGROUP_LEAF}",
            token.instance
        );
        let allowed_names: Vec<String> = ALLOWED_RESOURCES
            .iter()
            .map(|name| name.to_string())
            .collect();
        #[cfg(test)]
        workers::faults::hold("H.create.before_admit").await;
        let plan_generation_request =
            admit_request(&token, *revalidated, &cgroup, &allowed_names, image);
        let expected = plan_generation_request.executables.clone();
        let profile = plan_generation_request.profile.clone();
        let admission = self
            .ledger_call(
                Lane::Normal,
                &LedgerRequest::Admit {
                    request: Box::new(plan_generation_request),
                    authority,
                },
                token.deadline.ns,
            )
            .await;
        match admission {
            Ok(LedgerReply::Admit(AdmitOutcome::Accepted {
                generation,
                worker_id,
                operation_generation,
                phase,
                replay,
            })) => {
                gate.mark_durable();
                if replay {
                    return CreateReply::Accepted {
                        generation,
                        phase,
                        replay,
                    };
                }
                // The commit may have raced a revocation, or its reply a deadline. Either
                // way the claim is durable, and held for an exact fence: nothing starts.
                #[cfg(test)]
                workers::faults::hold("H.create.before_effects").await;
                let refused = if !self.revocations.is_current(&authority) {
                    Some((
                        AmbiguousClass::OldEpoch,
                        "the attachment was replaced as this committed",
                    ))
                } else if self.latched_once_answered(token.deadline.instant).await {
                    // RTC-R2-03: the latch linearized before any host effect began.
                    Some((
                        AmbiguousClass::Latched,
                        "forward effects are latched node-wide; nothing starts",
                    ))
                } else if token.deadline.expired() {
                    Some((
                        AmbiguousClass::Expired,
                        "create deadline expired before any effect started",
                    ))
                } else {
                    None
                };
                if let Some((class, reason)) = refused {
                    self.abandon_start(token.key(), reason);
                    return reject(class, reason.into());
                }
                match self
                    .start_supervisor(
                        &token,
                        &gate,
                        authority,
                        worker_id,
                        operation_generation,
                        generation,
                        &profile,
                        allowed_names,
                        expected,
                    )
                    .await
                {
                    Ok(generation) => CreateReply::Accepted {
                        generation,
                        phase: "preparing".into(),
                        replay: false,
                    },
                    // The claim is durable and held: this reports only the unfinished
                    // start. A gated S that was never released does nothing.
                    Err((class, reason)) => {
                        gate.close(class);
                        ambiguous_create(class, reason)
                    }
                }
            }
            Ok(LedgerReply::Admit(AdmitOutcome::Revoked)) => reject(
                AmbiguousClass::OldEpoch,
                "the attachment was replaced before this could commit".into(),
            ),
            Ok(LedgerReply::Admit(AdmitOutcome::Fenced { receipt })) => {
                gate.mark_durable();
                CreateReply::Absent {
                    receipt: WireBytes(receipt),
                }
            }
            Ok(LedgerReply::Admit(AdmitOutcome::Conflict { reason })) => {
                reject(AmbiguousClass::Conflict, reason)
            }
            Ok(LedgerReply::Admit(AdmitOutcome::Capacity { dimension })) => reject(
                AmbiguousClass::Capacity,
                format!("node capacity exhausted: {dimension:?}"),
            ),
            Ok(LedgerReply::Admit(AdmitOutcome::Collision { kind })) => reject(
                AmbiguousClass::Collision,
                format!("planned {} identity is already claimed", kind.as_str()),
            ),
            Ok(LedgerReply::Admit(AdmitOutcome::InstanceMismatch)) => reject(
                AmbiguousClass::AdmissionBlocked,
                "this namespace was never attached".into(),
            ),
            Ok(LedgerReply::Expired) => {
                reject(AmbiguousClass::Expired, "create deadline expired".into())
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                reject(AmbiguousClass::LedgerUnavailable, reason)
            }
            Ok(_) => reject(
                AmbiguousClass::WorkerPanic,
                "unexpected ledger reply".into(),
            ),
            // L may or may not have committed before it died. Either way the token
            // needs an exact answer, and a retry finds any claim that exists.
            Err(error) => reject(
                call_class(error),
                "the ledger gave no admission reply".into(),
            ),
        }
    }

    /// C2 committed but no S will start. The stop is recorded, and the permit that never
    /// had a process settles as never started. The claim itself stays until ABSENT.
    fn abandon_start(&self, key: AllocationKey, reason: &str) {
        self.queue_record(LedgerRequest::RecordStop {
            instance: key.instance,
            allocation: key.allocation,
            reason: reason.into(),
        });
        self.queue_record(LedgerRequest::SettleUnstarted {
            instance: key.instance,
            allocation: key.allocation,
        });
    }

    /// C3: fork S gated, require M's acknowledged watch, record its identity, journal
    /// PREPARING with its permits, and only then open the gate. Every step is forward
    /// authority and carries the original deadline; detached work keeps the claim and
    /// its cleanup, never unlimited time to begin effects. Any failure drops the control
    /// socket instead, and an ungated S exits on that EOF without side effects.
    #[allow(clippy::too_many_arguments)]
    async fn start_supervisor(
        self: &Arc<Self>,
        token: &CreateToken,
        gate: &TokenGate,
        authority: AdmissionAuthority,
        worker_id: i64,
        operation_generation: u64,
        generation: u64,
        profile: &str,
        allowed_names: Vec<String>,
        expected: Vec<ExecutableIdentity>,
    ) -> Result<u64, (AmbiguousClass, String)> {
        let unavailable = |e: io::Error| (AmbiguousClass::MonitorUnavailable, e.to_string());
        let (host, child) = StdUnixStream::pair().map_err(unavailable)?;
        let (watch_monitor, watch_child) = StdUnixStream::pair().map_err(unavailable)?;
        watch_child.set_nonblocking(true).map_err(unavailable)?;
        // B5: an execution's stdio crosses to S on its own socket, never the frames.
        let (descriptors_host, descriptors_child) =
            std::os::unix::net::UnixDatagram::pair().map_err(unavailable)?;
        descriptors_host
            .set_nonblocking(true)
            .map_err(unavailable)?;
        let mut keep = vec![
            child.as_raw_fd(),
            watch_child.as_raw_fd(),
            descriptors_child.as_raw_fd(),
        ];
        keep.extend(self.config.table_fds());
        let inherited = self.config.clone();
        let instance = token.instance;
        let allocation = token.allocation;
        let key = token.key();
        let profile_name = profile.to_string();
        let pid = workers::spawn_process(&keep, move || {
            workers::supervisor_main(SupervisorContext {
                config: inherited,
                instance,
                allocation,
                profile: profile_name,
                control: Endpoint::new(child),
                watch: watch_child,
                descriptors: Some(descriptors_child),
            });
        })
        .map_err(unavailable)?;
        let (channel, events) = Channel::spawn(host, CONTROL_QUEUE, 0).map_err(unavailable)?;
        let mut entry = SupervisorEntry::new(pid, channel.clone(), worker_id);
        entry.expected = expected.clone();
        entry.descriptors = Some(Arc::new(descriptors_host));
        self.supervisors.lock().unwrap().insert(key, entry);
        tokio::spawn(Self::supervisor_events(self.clone(), key, events));
        // A failure before the gate means S exits on EOF with nothing done. It is not
        // a lost boot: mark it expected, record the stop, and let the exit settle S.
        let abort = |class: AmbiguousClass, reason: String| {
            let mut supervisors = self.supervisors.lock().unwrap();
            if let Some(entry) = supervisors.get_mut(&key) {
                entry.revoked = true;
                entry.channel.close();
            }
            drop(supervisors);
            self.queue_record(LedgerRequest::RecordStop {
                instance,
                allocation,
                reason: reason.clone(),
            });
            (class, reason)
        };
        // Which of the two ran out decides how an unfinished step is reported.
        let step_failed = |reason: &str| {
            let class = if token.deadline.expired() {
                AmbiguousClass::Expired
            } else {
                AmbiguousClass::MonitorUnavailable
            };
            abort(class, reason.to_string())
        };
        let (monitor_channel, descriptors) = {
            let monitor = self.monitor.lock().unwrap();
            (monitor.worker.channel.clone(), monitor.descriptors.clone())
        };
        let handoff = tokio::time::timeout_at(
            token.deadline.instant,
            crate::helper::fds::send(&descriptors, &[watch_monitor.as_raw_fd()]),
        )
        .await;
        if !matches!(handoff, Ok(Ok(()))) {
            return Err(step_failed("monitor watch handoff failed"));
        }
        let acknowledged = tokio::time::timeout_at(
            token.deadline.instant,
            monitor_channel.call::<MonitorReply>(
                Lane::Normal,
                &MonitorCommand::RegisterWatch { allocation: key },
                token.deadline.ns,
            ),
        )
        .await;
        // Held until M installed its copy: Darwin can report EOF on a Unix endpoint
        // whose last installed descriptor closes while another is still in flight.
        drop(watch_monitor);
        if !matches!(acknowledged, Ok(Ok(MonitorReply::Registered))) {
            return Err(step_failed("monitor did not acknowledge the watch"));
        }
        let identity = tokio::time::timeout_at(
            token.deadline.instant,
            self.ledger_call(
                Lane::Normal,
                &LedgerRequest::RecordWorker { worker_id, pid },
                token.deadline.ns,
            ),
        )
        .await;
        if !matches!(identity, Ok(Ok(LedgerReply::Identity { .. }))) {
            return Err(step_failed("the ledger did not record the supervisor"));
        }
        let advanced = tokio::time::timeout_at(
            token.deadline.instant,
            self.ledger_call(
                Lane::Normal,
                &LedgerRequest::AdvancePhase {
                    instance,
                    allocation,
                    expected_generation: generation,
                    phase: "preparing".into(),
                },
                token.deadline.ns,
            ),
        )
        .await;
        let admitted_generation = generation;
        let Ok(Ok(LedgerReply::Generation(generation))) = advanced else {
            return Err(step_failed("the ledger did not record PREPARING"));
        };
        // A real launch carries the verified plan; the fake fixtures carry none.
        let real_plan = self.real_plan(&token.plan);
        // Session preparation counts against the node's two P slots (section 6.4).
        if real_plan.is_some() {
            let Some(lease) = self.queued_prep_lease(token.deadline).await else {
                return Err(abort(
                    AmbiguousClass::WorkerExhausted,
                    "no preparation slot became free before the deadline".into(),
                ));
            };
            if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&key) {
                entry.prep = Some(lease);
            }
        }
        // The last check before S may act. Each of these can have changed during C3.
        if !self.revocations.is_current(&authority) {
            return Err(abort(
                AmbiguousClass::OldEpoch,
                "the attachment was replaced during setup".into(),
            ));
        }
        if token.deadline.expired() {
            return Err(abort(
                AmbiguousClass::Expired,
                "create deadline expired before the gate".into(),
            ));
        }
        if gate.closed().is_some() || !self.monitor_healthy() {
            return Err(abort(
                AmbiguousClass::MonitorUnavailable,
                "supervision was lost during setup".into(),
            ));
        }
        // B7 RTC-14: the node latch, last of all, immediately before S is released. A
        // latch that linearized anywhere during C3 (supervisor setup, the preparation
        // slot, the checks above) starts nothing.
        #[cfg(test)]
        workers::faults::hold("H.create.before_open_gate").await;
        if self.latched_once_answered(token.deadline.instant).await {
            return Err(abort(
                AmbiguousClass::Latched,
                "forward effects were latched node-wide during setup; nothing starts".into(),
            ));
        }
        let opened = {
            let mut supervisors = self.supervisors.lock().unwrap();
            supervisors.get_mut(&key).is_some_and(|entry| {
                !entry.stop_fenced
                    && entry.channel.notify(&SupervisorCommand::Tick)
                    && entry.channel.notify(&SupervisorCommand::OpenGate {
                        operation_generation,
                        allowed_names,
                        expected,
                        deadline_ns: token.deadline.ns,
                        plan: real_plan.clone(),
                        plan_generation: admitted_generation,
                    })
            })
        };
        if !opened {
            return Err(abort(
                AmbiguousClass::MonitorUnavailable,
                "the supervisor could not be released".into(),
            ));
        }
        Ok(generation)
    }

    /// The canonical plan S launches from. Production always launches for real; the
    /// B3 fixtures keep their fake effects unless a test asks for the real chain.
    fn real_plan(&self, plan: &[u8]) -> Option<String> {
        #[cfg(test)]
        if !self.config.test.real {
            return None;
        }
        String::from_utf8(plan.to_vec()).ok()
    }

    async fn supervisor_events(
        self: Arc<Self>,
        key: AllocationKey,
        mut events: mpsc::Receiver<serde_json::Value>,
    ) {
        while let Some(event) = events.recv().await {
            let Ok(event) = serde_json::from_value::<SupervisorEvent>(event) else {
                continue;
            };
            match event {
                SupervisorEvent::ExecObserved(observation) => {
                    self.queue_record(LedgerRequest::RecordObserved {
                        instance: key.instance,
                        allocation: key.allocation,
                        actual: observation.actual,
                    });
                }
                SupervisorEvent::ExecRefused { role, reason } => {
                    self.contain_allocation(
                        key,
                        &format!("{} identity mismatch: {reason}", role.as_str()),
                    );
                }
                SupervisorEvent::VmStarted(target) => {
                    self.on_vm_started(key, target).await;
                }
                SupervisorEvent::EffectsDone => {}
                SupervisorEvent::SetupExpired => {
                    self.contain_allocation(key, "setup deadline expired");
                }
                SupervisorEvent::Record { seq, record } => {
                    let ok = self.on_record(key, record).await;
                    let channel = self
                        .supervisors
                        .lock()
                        .unwrap()
                        .get(&key)
                        .map(|entry| entry.channel.clone());
                    if let Some(channel) = channel {
                        channel.notify(&SupervisorCommand::Recorded { seq, ok });
                    }
                }
                SupervisorEvent::PreparationDone => {
                    if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&key) {
                        entry.prep = None;
                    }
                }
                SupervisorEvent::Booting => {
                    if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&key) {
                        entry.booted = true;
                    }
                }
                SupervisorEvent::LaunchRefused { reason } => {
                    self.contain_allocation(key, &format!("launch refused: {reason}"));
                }
                SupervisorEvent::VmExited => {
                    if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&key) {
                        entry.vm_gone = false;
                    }
                    self.contain_allocation(key, "the VMM exited");
                }
                SupervisorEvent::Ready { boot_id, inner_id } => {
                    if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&key) {
                        entry.ready = Some((boot_id, inner_id));
                    }
                }
                SupervisorEvent::Broker { report } => {
                    let job = report.job();
                    let mut supervisors = self.supervisors.lock().unwrap();
                    if let Some(entry) = supervisors.get_mut(&key) {
                        let finished = report.is_final();
                        if let Some(waiter) = entry.jobs.get(&job) {
                            let _ = waiter.send(report);
                        }
                        if finished {
                            entry.jobs.remove(&job);
                        }
                    }
                }
                SupervisorEvent::Retire { reason } => {
                    self.contain_allocation(key, &format!("retired: {reason}"));
                }
                SupervisorEvent::CleanedUp | SupervisorEvent::CleanupFailed { .. } => {
                    let result = match event {
                        SupervisorEvent::CleanupFailed { reason } => Err(reason),
                        _ => Ok(()),
                    };
                    if let Some(slot) = self
                        .supervisors
                        .lock()
                        .unwrap()
                        .get(&key)
                        .and_then(|entry| entry.cleanup.clone())
                    {
                        *slot.lock().unwrap() = Some(result);
                    }
                }
            }
        }
    }

    /// The precommitted authority's concrete target reaches M before anything else,
    /// and it needs no ledger write: an emergency works with L already blocked.
    async fn on_vm_started(self: &Arc<Self>, key: AllocationKey, target: ProcessId) {
        let registered = self.register_target(key, StopTarget::process(target)).await;
        let real = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|entry| entry.vm.as_ref().is_some_and(|vm| vm.cgroup.is_some()));
        // Without M's copy, this subtree has lost independent supervision. A fence that
        // landed first also needs the target it could not have known about.
        let fenced = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|entry| entry.stop_fenced);
        if fenced || !registered {
            self.contain_allocation(key, "subtree target has no monitor");
        }
        // A real VMM's row came from S's own record, against the plan's VMM image.
        if real {
            return;
        }
        if let Some(image) = self.config.helper_image {
            self.queue_record(LedgerRequest::RecordChild {
                instance: key.instance,
                allocation: key.allocation,
                spec: Box::new(WorkerIntentSpec {
                    mode: "vm".into(),
                    allowed_names: vec!["vm".into()],
                    cgroup: format!(
                        "{}/vm/vmm",
                        identity::host_name(key.instance, key.allocation)
                    ),
                    image,
                }),
                target,
            });
        }
    }

    /// The detached body of FenceAbsent. An existing fence replays unchanged. A new one
    /// closes the gate, revokes and waits for every permit, requires positive absence
    /// and then commits once. A response of Absent always follows that durable commit.
    async fn fence_flow(self: Arc<Self>, token: FenceToken) -> FenceReply {
        let Some(share) = self.share(token.instance) else {
            return ambiguous_fence(AmbiguousClass::OldEpoch, "this instance is not enrolled");
        };
        let entry = GateUse::enter(share.clone(), token.allocation);
        let gate = entry.gate.clone();
        if gate.waiters.fetch_add(1, Ordering::AcqRel) >= MAX_TOKEN_WAITERS {
            gate.waiters.fetch_sub(1, Ordering::AcqRel);
            return ambiguous_fence(AmbiguousClass::Pending, "too many queued duplicates");
        }
        let serial = gate.serial.clone().lock_owned().await;
        gate.waiters.fetch_sub(1, Ordering::AcqRel);
        let _serial = serial;
        // Every ledger wait below ends at the request's own deadline (B5-R1), so a
        // stalled L leaves this attempt charged and ambiguous and gives back the detached
        // slot and any removing claim, and a later attempt can make progress.
        let reply = self
            .ledger_until(
                &LedgerRequest::Lookup {
                    instance: token.instance,
                    allocation: token.allocation,
                    plan_digest: token.plan_digest,
                },
                token.deadline.with_grace(),
                token.deadline.instant + LOOKUP_GRACE,
            )
            .await;
        let mut never_admitted = false;
        match reply {
            Ok(LedgerReply::Lookup(TokenLookup::Fenced { receipt })) => {
                self.forget_token(&gate, token.key());
                return FenceReply::Absent {
                    receipt: WireBytes(receipt),
                };
            }
            Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                gate.mark_durable();
                return ambiguous_fence(AmbiguousClass::Conflict, reason);
            }
            Ok(LedgerReply::Lookup(TokenLookup::Active { .. })) => gate.mark_durable(),
            Ok(LedgerReply::Lookup(TokenLookup::Unknown)) => never_admitted = true,
            // B7 RTC-8: a synthesized receipt for this request's digest; nothing acts.
            Ok(LedgerReply::Lookup(TokenLookup::Compacted { receipt })) => {
                gate.mark_durable();
                return FenceReply::Absent {
                    receipt: WireBytes(receipt),
                };
            }
            Ok(LedgerReply::Lookup(TokenLookup::NotIssued)) => {
                gate.mark_durable();
                return ambiguous_fence(
                    AmbiguousClass::NotIssued,
                    "this token was never issued by this node ledger",
                );
            }
            Ok(LedgerReply::Lookup(TokenLookup::Malformed)) => {
                gate.mark_durable();
                return ambiguous_fence(
                    AmbiguousClass::Conflict,
                    "this token does not verify in this instance",
                );
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                return ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason);
            }
            _ => {
                return ambiguous_fence(
                    AmbiguousClass::LedgerUnavailable,
                    "token lookup had no answer",
                );
            }
        }
        if !self.epoch_valid(token.instance, token.epoch, token.peer) {
            return ambiguous_fence(AmbiguousClass::OldEpoch, "connection epoch is not current");
        }
        if !self.admission_open(token.instance) {
            return ambiguous_fence(
                AmbiguousClass::AdmissionBlocked,
                "this namespace belongs to another database",
            );
        }
        if token.deadline.expired() {
            return ambiguous_fence(AmbiguousClass::Expired, "fence deadline expired");
        }
        // From here no new permit can be issued, whatever this attempt concludes.
        gate.close(AmbiguousClass::GateClosed);
        // Refuse at the quota here, before this instance can occupy a shared P slot. The
        // commit below checks again in its own transaction, and that is the authority.
        if never_admitted {
            let allowed = self
                .ledger_until(
                    &LedgerRequest::NeverAdmittedFenceAllowed {
                        instance: token.instance,
                    },
                    token.deadline.ns,
                    token.deadline.instant,
                )
                .await;
            match allowed {
                Ok(LedgerReply::NeverAdmittedFenceAllowed(true)) => {}
                Ok(LedgerReply::NeverAdmittedFenceAllowed(false)) => {
                    return ambiguous_fence(
                        AmbiguousClass::ResourceExhausted,
                        "this instance has used its quota of never-admitted fences",
                    );
                }
                Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                    return ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason);
                }
                _ => {
                    return ambiguous_fence(
                        AmbiguousClass::LedgerUnavailable,
                        "the ledger did not answer the fence quota",
                    );
                }
            }
        }
        if let Err(reply) = self.settle_permits(&token).await {
            return reply;
        }
        // A journaled allocation's loop slots are observed on the slots themselves: a
        // replacement there need not be backed inside the work directory (section 7.1).
        let mut recorded = supervisor::RecordedResources::default();
        if !never_admitted {
            match self.allocation_state(token.key(), token.deadline).await {
                Ok(Some(state)) => {
                    for record in &state.resources {
                        recorded.absorb(record);
                    }
                }
                Ok(None) => {
                    return ambiguous_fence(
                        AmbiguousClass::LedgerUnavailable,
                        "an active token has no journal record",
                    );
                }
                Err(reason) => return ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason),
            }
        }
        let observation = self
            .prep_call(
                PrepRequest::ObserveAllocation {
                    instance: token.instance,
                    allocation: token.allocation,
                    loops: recorded.loops,
                },
                token.deadline,
            )
            .await;
        match observation {
            Ok(PrepReply::Allocation(NamespaceObservation::Absent)) => {}
            Ok(PrepReply::Allocation(NamespaceObservation::Present { names })) => {
                return ambiguous_fence(
                    AmbiguousClass::ResourcesPresent,
                    format!("owned resources remain: {}", names.join(", ")),
                );
            }
            Ok(PrepReply::Allocation(NamespaceObservation::Unknown { reason })) => {
                return ambiguous_fence(AmbiguousClass::ObservationUnavailable, reason);
            }
            Ok(_) | Err(_) => {
                return ambiguous_fence(
                    AmbiguousClass::ObservationUnavailable,
                    "no fresh namespace observation",
                );
            }
        }
        // Later records (S's exit and the like) must be durable before the commit.
        match tokio::time::timeout_at(token.deadline.instant, self.flush_pending()).await {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                return ambiguous_fence(
                    AmbiguousClass::LedgerUnavailable,
                    "earlier journal records are not durable yet",
                );
            }
        }
        #[cfg(test)]
        workers::faults::hold("H.fence.before_commit").await;
        let outcome = self
            .ledger_until(
                &LedgerRequest::Fence(Box::new(FenceRequest {
                    instance_id: token.instance,
                    allocation_id: token.allocation,
                    sandbox_id: token.sandbox_id.clone(),
                    plan_digest: token.plan_digest,
                    observations: "permits=settled;namespace=absent".into(),
                })),
                token.deadline.ns,
                token.deadline.instant,
            )
            .await;
        match outcome {
            Ok(LedgerReply::Fence(FenceOutcome::Absent { receipt, .. })) => {
                // Durable now, with this token's serialization still held.
                #[cfg(test)]
                workers::faults::hold(&format!("H.fence.after_commit.{}", token.allocation)).await;
                self.forget_token(&gate, token.key());
                FenceReply::Absent {
                    receipt: WireBytes(receipt),
                }
            }
            Ok(LedgerReply::Fence(FenceOutcome::Conflict { reason })) => {
                ambiguous_fence(AmbiguousClass::Conflict, reason)
            }
            Ok(LedgerReply::Fence(FenceOutcome::Unsettled { workers })) => ambiguous_fence(
                AmbiguousClass::PermitsUnsettled,
                format!("{workers} worker records remain unsettled"),
            ),
            Ok(LedgerReply::Fence(FenceOutcome::QuotaExhausted { quota })) => ambiguous_fence(
                AmbiguousClass::ResourceExhausted,
                format!("this instance has used its {quota} never-admitted fences"),
            ),
            Ok(LedgerReply::Expired) => {
                ambiguous_fence(AmbiguousClass::Expired, "fence deadline expired")
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason)
            }
            _ => ambiguous_fence(
                AmbiguousClass::LedgerUnavailable,
                "the ledger gave no fence reply",
            ),
        }
    }

    /// Revokes S and waits for its real exit. Its VM child must also be proven gone. An
    /// unfinished wait reports that, and leaves the gate closed and the claim held.
    async fn settle_permits(&self, token: &FenceToken) -> Result<(), FenceReply> {
        let key = token.key();
        let target = {
            let mut supervisors = self.supervisors.lock().unwrap();
            supervisors.get_mut(&key).map(|entry| {
                entry.revoked = true;
                entry.channel.notify(&SupervisorCommand::Revoke);
                (entry.exited.clone(), entry.exit.is_some())
            })
        };
        if let Some((exited, done)) = target
            && !done
        {
            let waited = tokio::time::timeout_at(token.deadline.instant, exited.cancelled()).await;
            if waited.is_err() {
                return Err(ambiguous_fence(
                    AmbiguousClass::PermitsUnsettled,
                    "the supervisor has not exited; its permit stays charged",
                ));
            }
        }
        let vm = {
            let supervisors = self.supervisors.lock().unwrap();
            supervisors.get(&key).and_then(|entry| {
                entry
                    .vm
                    .clone()
                    .map(|vm| (vm, entry.vm_gone, entry.vm_worker))
            })
        };
        if let Some((target, known_gone, worker)) = vm {
            let gone = known_gone || self.probe_process(target).await.unwrap_or(false);
            if !gone {
                return Err(ambiguous_fence(
                    AmbiguousClass::PermitsUnsettled,
                    "an owned process subtree is still present",
                ));
            }
            if let Some(worker_id) = worker {
                self.queue_record(LedgerRequest::Settle {
                    worker_id,
                    settlement: "subtree-gone".into(),
                });
            }
        }
        // Rows with no identity never had an open gate: S was never released.
        let settled = self
            .ledger_until(
                &LedgerRequest::SettleUnstarted {
                    instance: token.instance,
                    allocation: token.allocation,
                },
                token.deadline.ns,
                token.deadline.instant,
            )
            .await;
        match settled {
            Ok(LedgerReply::Done) => Ok(()),
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                Err(ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason))
            }
            _ => Err(ambiguous_fence(
                AmbiguousClass::LedgerUnavailable,
                "the ledger did not settle unstarted permits",
            )),
        }
    }

    /// The durable fence now answers for this token; its memory can go.
    fn forget_token(&self, gate: &TokenGate, key: AllocationKey) {
        gate.mark_durable();
        let removed = self.supervisors.lock().unwrap().remove(&key);
        if removed.is_some() {
            self.monitor
                .lock()
                .unwrap()
                .worker
                .channel
                .notify(&MonitorCommand::Forget { allocation: key });
        }
    }

    fn freshness(&self, key: AllocationKey) -> WorkerFreshness {
        let supervisors = self.supervisors.lock().unwrap();
        match supervisors.get(&key) {
            Some(entry) => WorkerFreshness {
                stop_fenced: entry.stop_fenced,
                supervisor_stalled: entry.stalled,
                supervisor_missing: false,
            },
            // After a restart, an active allocation has no supervisor yet.
            None => WorkerFreshness {
                supervisor_missing: true,
                ..WorkerFreshness::default()
            },
        }
    }

    async fn inspect(
        &self,
        instance: Id128,
        allocation: Id128,
        plan_digest: Digest,
        deadline: WireDeadline,
    ) -> FirecrackerResponse {
        let reply = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::Inspect {
                    instance,
                    allocation,
                    plan_digest,
                },
                deadline.ns,
            )
            .await;
        // B7 recheck R3: holds an answer read before a concurrent terminal Remove.
        #[cfg(test)]
        workers::faults::hold("H.inspect.after_lookup").await;
        FirecrackerResponse::Inspect(match reply {
            Ok(LedgerReply::Lookup(
                TokenLookup::Fenced { receipt } | TokenLookup::Compacted { receipt },
            )) => InspectReply::AbsentFenced {
                receipt: WireBytes(receipt),
            },
            Ok(LedgerReply::Lookup(TokenLookup::NotIssued)) => InspectReply::Incompatible {
                message: "this token was never issued by this node ledger".into(),
            },
            Ok(LedgerReply::Lookup(TokenLookup::Malformed)) => InspectReply::Incompatible {
                message: "this token does not verify in this instance".into(),
            },
            Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                InspectReply::Incompatible { message: reason }
            }
            Ok(LedgerReply::Lookup(TokenLookup::Unknown)) => InspectReply::Unknown {
                reason: "no journal record; this is not evidence of absence".into(),
            },
            Ok(LedgerReply::Lookup(TokenLookup::Active {
                generation, phase, ..
            })) => {
                let fresh = self.freshness(AllocationKey {
                    instance,
                    allocation,
                });
                if phase == "stopped" || phase == "cleaning" {
                    InspectReply::StoppedWithResources { generation }
                } else if fresh.stop_fenced {
                    InspectReply::Unknown {
                        reason: "a stop is in progress; proof is not established".into(),
                    }
                } else if fresh.supervisor_stalled || fresh.supervisor_missing {
                    InspectReply::Unknown {
                        reason: "no fresh supervisor observation".into(),
                    }
                } else if !self.monitor_healthy() {
                    InspectReply::Unknown {
                        reason: "the process monitor is not healthy".into(),
                    }
                } else {
                    let ready = self
                        .supervisors
                        .lock()
                        .unwrap()
                        .get(&AllocationKey {
                            instance,
                            allocation,
                        })
                        .filter(|entry| entry.busy.is_none())
                        .and_then(|entry| entry.ready.clone());
                    match ready {
                        Some((boot_id, inner_id)) if phase == "ready" => {
                            InspectReply::PresentReady {
                                generation,
                                boot_id,
                                inner_id,
                            }
                        }
                        _ => InspectReply::PresentBusy {
                            generation,
                            phase,
                            plan_digest: None,
                        },
                    }
                }
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                InspectReply::Unknown { reason }
            }
            _ => InspectReply::Unknown {
                reason: "the node ledger gave no fresh answer".into(),
            },
        })
    }

    async fn list(&self, instance: Id128, deadline: WireDeadline) -> FirecrackerResponse {
        let journal = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::Inventory { instance },
                deadline.ns,
            )
            .await;
        let journal = match journal {
            Ok(LedgerReply::Inventory(snapshot)) => snapshot,
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                return group_error(GroupErrorKind::Unavailable, reason);
            }
            _ => {
                return group_error(
                    GroupErrorKind::Unavailable,
                    "the node ledger gave no inventory",
                );
            }
        };
        let namespace = match self
            .prep_call(
                PrepRequest::ObserveNode {
                    instance,
                    known: journal.records.iter().map(|r| r.allocation_id).collect(),
                },
                deadline,
            )
            .await
        {
            Ok(PrepReply::Node(observation)) => observation,
            _ => NodeObservation::Unknown {
                reason: "no worker could observe the namespace".into(),
            },
        };
        let assembled = inventory::assemble(
            &journal,
            &namespace,
            self.monitor_healthy(),
            &|allocation| {
                self.freshness(AllocationKey {
                    instance,
                    allocation,
                })
            },
        );
        FirecrackerResponse::List(ListReply {
            generation: assembled.generation,
            complete: assembled.complete,
            incomplete_reason: assembled.incomplete_reason,
            records: assembled.records,
        })
    }

    /// Stops background work; children notice their closed sockets and exit.
    pub fn shutdown(&self) {
        self.stop.cancel();
    }

    /// A process census for tests: exact processes, with no shared counters.
    #[cfg(test)]
    pub fn census(&self) -> serde_json::Value {
        let supervisors = self.supervisors.lock().unwrap();
        serde_json::json!({
            "ledger": self.ledger.lock().unwrap().pid,
            "prep": [self.prep[0].lock().unwrap().pid, self.prep[1].lock().unwrap().pid],
            "monitor": self.monitor.lock().unwrap().worker.pid,
            "recovery": [self.recovery[0].lock().unwrap().pid, self.recovery[1].lock().unwrap().pid],
            "supervisors": supervisors.iter().map(|(key, entry)| {
                (key.allocation.to_string(), serde_json::json!({
                    "pid": entry.pid,
                    "exit": entry.exit,
                    "stop_fenced": entry.stop_fenced,
                    "stalled": entry.stalled,
                    "contained": entry.contained,
                    "vm": entry.vm.as_ref().and_then(|vm| vm.process).map(|vm| vm.pid),
                }))
            }).collect::<serde_json::Map<_, _>>(),
            "closed_gates": self.shares.lock().unwrap().iter().flat_map(|shares| shares.by_instance.values()).map(|share| {
                share.gates.lock().unwrap().gates.values().filter(|g| g.closed().is_some()).count()
            }).sum::<usize>(),
            "open_gates": self.shares.lock().unwrap().iter().flat_map(|shares| shares.by_instance.values()).map(|share| {
                share.gates.lock().unwrap().gates.values().filter(|g| g.closed().is_none()).count()
            }).sum::<usize>(),
            "discarded": self.discarded.lock().unwrap().clone(),
            "attached": self.attachments.lock().unwrap().len(),
            // Free detached-operation slots across instances, and removals in flight:
            // a stalled ledger must not keep either (B5-R1).
            "detached_available": self.shares.lock().unwrap().iter().flat_map(|shares| shares.by_instance.values()).map(|share| share.detached.available_permits()).sum::<usize>(),
            "removing": self.removing.lock().unwrap().len(),
            "peer_starts": self.attachments.lock().unwrap().values().map(|a| a.peer_start).collect::<Vec<_>>(),
            // B7 instrumentation: every call to L, tokens H refused by their tag, and
            // the RTC-14 latch.
            "ledger_calls": self.ledger_calls.load(Ordering::Relaxed),
            "tag_refusals": self.tag_refusals.load(Ordering::Relaxed),
            "latched": self.is_latched_durably(),
            "pending_fault": self.latch.lock().unwrap().pending.is_some(),
            "latch_kind": self.latch.lock().unwrap().kind.clone(),
            "lost_answers": self.lost_answers.load(Ordering::SeqCst),
            "transferred_holds": self.transferred.lock().unwrap().held.values().sum::<usize>(),
            "ledger_replacement_fault": self.ledger_replacement_fault.lock().unwrap().clone(),
        })
    }
}

/// A worker from an earlier helper that was still alive at recovery. It stays charged
/// and is revisited until it is gone; only then does its row settle.
#[derive(Clone)]
struct Orphan {
    worker_id: i64,
    target: ProcessId,
}

struct PrepLease {
    channel: Arc<Channel>,
    busy: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for PrepLease {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}

struct CreateToken {
    instance: Id128,
    epoch: Option<Id128>,
    peer: PeerCredentials,
    allocation: Id128,
    sandbox_id: String,
    plan: Vec<u8>,
    plan_digest: Digest,
    deadline: WireDeadline,
}

struct FenceToken {
    instance: Id128,
    epoch: Option<Id128>,
    peer: PeerCredentials,
    allocation: Id128,
    sandbox_id: String,
    plan_digest: Digest,
    deadline: WireDeadline,
}

impl CreateToken {
    fn key(&self) -> AllocationKey {
        AllocationKey {
            instance: self.instance,
            allocation: self.allocation,
        }
    }
}

impl FenceToken {
    fn key(&self) -> AllocationKey {
        AllocationKey {
            instance: self.instance,
            allocation: self.allocation,
        }
    }
}

fn infrastructure_spec(kind: SlotKind, image: ExecutableIdentity) -> WorkerIntentSpec {
    WorkerIntentSpec {
        mode: kind.mode().into(),
        allowed_names: vec![],
        cgroup: "kilnd-helper-shared".into(),
        image,
    }
}

fn admit_request(
    token: &CreateToken,
    plan: RevalidatedPlan,
    cgroup: &str,
    allowed_names: &[String],
    image: ExecutableIdentity,
) -> AdmitRequest {
    AdmitRequest {
        instance_id: token.instance,
        allocation_id: token.allocation,
        sandbox_id: token.sandbox_id.clone(),
        plan_version: config::PLAN_VERSION,
        plan_digest: token.plan_digest,
        plan: token.plan.clone(),
        profile: plan.profile,
        manifest_sha256: plan.manifest_sha256,
        host_spec_sha256: plan.host_spec_sha256,
        guest_exec_spec_sha256: plan.guest_exec_spec_sha256,
        reservation: plan.reservation,
        leases: plan.leases,
        work_uuid: plan.work_uuid,
        executables: plan.executables,
        stop_authority: StopAuthority::standard(format!(
            "kilnd-firecracker/{}/{}",
            token.instance,
            identity::host_name(token.instance, token.allocation)
        )),
        supervisor: WorkerIntentSpec {
            mode: "supervisor".into(),
            allowed_names: allowed_names.to_vec(),
            cgroup: cgroup.to_string(),
            image,
        },
    }
}

/// Verifies one catalog entry under its gate and retains its executable table. Runs
/// before any traffic. The production gate refuses every manifest today, so the node
/// serves no profile: every Preflight is a C0 refusal with zero session effects.
pub fn load_profile(
    walk: &WalkPolicy,
    gate: ManifestGate,
    catalog: &ProfileCatalog,
) -> Result<ProfileRuntime, String> {
    let bundle =
        executable::walk_directory(walk, &catalog.bundle_directory).map_err(|e| e.to_string())?;
    let raw = manifest::read_manifest(&bundle, walk.owner_uid)?;
    let verified = manifest::verify_manifest(&raw, &catalog.approved_manifest_sha256, gate)?;
    manifest::verify_artifacts(&bundle, walk.owner_uid, &verified)?;
    let pins = manifest::executable_pins(&verified, &catalog.installation_generations)?;
    let table = ExecutableTable::open(walk.clone(), &catalog.exec_store, &pins)
        .map_err(|e| e.to_string())?;
    Ok(ProfileRuntime {
        catalog: catalog.clone(),
        table,
        pins: verified.pins,
        manifest_sha256: verified.sha256,
        artifacts: verified.artifacts,
    })
}

/// The production configuration from a verified root policy. Nothing here accepts a
/// fixture, and until B7 the production gate leaves the served profile list empty.
pub fn production_config(policy: NodePolicy, helper_uid: u32) -> NodeConfig {
    let walk = WalkPolicy::production();
    let mut profiles = Vec::new();
    for catalog in &policy.profiles {
        match load_profile(&walk, ManifestGate::ProductionDisabled, catalog) {
            Ok(profile) => profiles.push(profile),
            Err(error) => {
                tracing::warn!(profile = %catalog.profile, %error, "Firecracker profile refused");
            }
        }
    }
    // H checks its own image before workers exist, whenever a profile pins one.
    let helper_image =
        profiles.iter().find_map(
            |profile| match executable::verify_self_image(&profile.table) {
                Ok(image) => Some(image),
                Err(error) => {
                    tracing::warn!(%error, "helper image self-check refused");
                    None
                }
            },
        );
    if helper_image.is_none() {
        profiles.clear();
    }
    NodeConfig {
        node_id: policy.node_id,
        ledger: LedgerConfig {
            directory: policy.ledger_dir,
            policy: walk.clone(),
            node_id: policy.node_id,
            ceilings: policy.ceilings,
            shared: policy.shared,
            max_enrolled: policy.max_enrolled_instances,
            compaction: policy.compaction,
        },
        ranges: policy.identity_ranges,
        profiles,
        walk,
        gate: ManifestGate::ProductionDisabled,
        observation: ObservationBackend::Real,
        timings: Timings {
            compaction_tick: Duration::from_millis((policy.compaction.pass_ms / 4).max(250)),
            ..Timings::default()
        },
        helper_image,
        helper_uid,
        max_enrolled: policy.max_enrolled_instances,
        #[cfg(test)]
        test: workers::TestInjection::default(),
    }
}

/// Reads and parses the root-owned policy through a protected walk: its directory and
/// file must be root-owned, single-link and not writable by anyone else.
pub fn read_policy(path: &Path, service_uid: u32) -> Result<NodePolicy, String> {
    let walk = WalkPolicy::production();
    let parent = path.parent().ok_or("policy path has no parent")?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("policy path has no file name")?;
    let directory = executable::walk_directory(&walk, parent).map_err(|e| e.to_string())?;
    let raw = manifest::read_bounded(&directory, name, walk.owner_uid, 1 << 20)?;
    config::parse_policy(&raw, service_uid)
}

/// The explicit one-time ledger creation. Install scripts do not run this.
pub fn provision_ledger(policy: &NodePolicy) -> Result<(), String> {
    journal::Ledger::provision(&root_ledger_config(policy)).map_err(|e| e.to_string())
}

/// The ledger as root's commands reach it, with no helper running.
fn root_ledger_config(policy: &NodePolicy) -> LedgerConfig {
    LedgerConfig {
        directory: policy.ledger_dir.clone(),
        policy: WalkPolicy::production(),
        node_id: policy.node_id,
        ceilings: policy.ceilings,
        shared: policy.shared,
        max_enrolled: policy.max_enrolled_instances,
        compaction: policy.compaction,
    }
}

/// B7: root's mandatory offline inventory (design 16.6, 16.7), over the real owned
/// namespaces. It reports and destroys nothing.
pub fn offline_inventory(
    policy: &NodePolicy,
    daemon_databases: &std::collections::BTreeMap<Id128, std::path::PathBuf>,
    report: &Path,
) -> Result<String, String> {
    let report = offline::offline_inventory(
        &root_ledger_config(policy),
        &ObservationBackend::Real,
        daemon_databases,
        report,
    )?;
    Ok(format!(
        "verdict {}: {} unexplained, {} faults, ledger generation {}",
        report.verdict,
        report.unexplained.len(),
        report.faults.len(),
        report.ledger_generation
    ))
}

/// B7: root's offline RTC-14 fault clear, from an explained, current inventory report.
pub fn clear_node_faults(policy: &NodePolicy, report: &Path) -> Result<String, String> {
    offline::clear_node_faults(&root_ledger_config(policy), report)
}

/// B7: read-only per-instance token statistics.
pub fn ledger_stats(policy: &NodePolicy) -> Result<String, String> {
    offline::ledger_stats(&root_ledger_config(policy))
}

/// Runs one root command on the ledger under the node lock, which only a stopped helper
/// leaves free.
fn with_node_lock<T>(
    config: &LedgerConfig,
    command: impl FnOnce(&mut journal::Ledger) -> Result<T, String>,
) -> Result<T, String> {
    let directory =
        executable::walk_directory(&config.policy, &config.directory).map_err(|e| e.to_string())?;
    let _lock = ExclusiveFileLock::acquire_at(
        directory.file(),
        OsStr::new(journal::LEDGER_LOCK),
        &journal::ledger_lock_path(&config.directory),
        "Firecracker node ledger",
    )
    .map_err(|error| format!("stop kilnd-helper first: {error:#}"))?;
    let mut ledger = journal::Ledger::open(config.clone()).map_err(|e| e.to_string())?;
    command(&mut ledger)
}

/// Root's `kilnd-helper enrollments`: every enrollment, as upgrades read them.
pub fn list_enrollments(policy: &NodePolicy) -> Result<Vec<Enrollment>, String> {
    list_enrollments_with(&root_ledger_config(policy))
}

fn list_enrollments_with(config: &LedgerConfig) -> Result<Vec<Enrollment>, String> {
    with_node_lock(config, |ledger| {
        ledger.enrollments().map_err(|e| e.to_string())
    })
}

/// Root's `kilnd-helper refresh-enrollments`: binds every enrolled instance to the image
/// at `kilnd`, in one transaction, leaving each instance's identity, account and unit
/// alone. With `check` it proves the same command would work, and writes nothing.
pub fn refresh_enrollments(
    policy: &NodePolicy,
    kilnd: &Path,
    check: bool,
) -> Result<String, String> {
    refresh_enrollments_with(&root_ledger_config(policy), kilnd, check)
}

fn refresh_enrollments_with(
    config: &LedgerConfig,
    kilnd: &Path,
    check: bool,
) -> Result<String, String> {
    with_node_lock(config, |ledger| {
        let image = peer::read_installed_kilnd(&config.policy, kilnd).map_err(|e| e.to_string())?;
        let mut rows = ledger.enrollments().map_err(|e| e.to_string())?;
        if check {
            return Ok(format!("can refresh {} enrollments", rows.len()));
        }
        for row in &mut rows {
            row.executable = image;
        }
        written_images(ledger, &rows)
    })
}

/// Root's `kilnd-helper restore-enrollments`: puts back the images `enrollments` printed
/// earlier, for an upgrade that failed. It can change only images, and only if the
/// snapshot names exactly the instances enrolled now, each with its stored binding.
pub fn restore_enrollments(policy: &NodePolicy, snapshot: &[Enrollment]) -> Result<String, String> {
    restore_enrollments_with(&root_ledger_config(policy), snapshot)
}

fn restore_enrollments_with(
    config: &LedgerConfig,
    snapshot: &[Enrollment],
) -> Result<String, String> {
    with_node_lock(config, |ledger| written_images(ledger, snapshot))
}

fn written_images(ledger: &mut journal::Ledger, rows: &[Enrollment]) -> Result<String, String> {
    match ledger
        .set_enrolled_images(rows)
        .map_err(|e| e.to_string())?
    {
        journal::EnrolledImagesOutcome::Updated {
            generation,
            instances,
        } => Ok(format!(
            "set the image of {instances} enrollments at generation {generation}"
        )),
        journal::EnrolledImagesOutcome::IdentityChanged => {
            Err("the enrolled instances are not the ones named; nothing was changed".into())
        }
    }
}

/// Root's `kilnd-helper enroll`. It takes the node lock, so it runs with the helper
/// stopped and reaches the ledger by no socket, and the next helper loads the result.
#[allow(clippy::too_many_arguments)]
pub fn enroll_instance(
    policy: &NodePolicy,
    instance: Id128,
    unit: &str,
    cgroup: Option<&str>,
    (uid, gid): (u32, u32),
    helper_uid: u32,
    kilnd: &Path,
) -> Result<String, String> {
    peer::validate_account(uid, gid, helper_uid, &policy.identity_ranges)?;
    enroll_with(
        &root_ledger_config(policy),
        policy.max_enrolled_instances,
        instance,
        unit,
        cgroup,
        (uid, gid),
        kilnd,
    )
}

fn enroll_with(
    config: &LedgerConfig,
    limit: u32,
    instance: Id128,
    unit: &str,
    cgroup: Option<&str>,
    (uid, gid): (u32, u32),
    kilnd: &Path,
) -> Result<String, String> {
    let cgroup = peer::unit_cgroup(unit, cgroup)?;
    with_node_lock(config, |ledger| {
        let executable =
            peer::read_installed_kilnd(&config.policy, kilnd).map_err(|e| e.to_string())?;
        let enrollment = Enrollment {
            instance_id: instance,
            unit: unit.to_string(),
            cgroup,
            uid,
            gid,
            executable,
        };
        match ledger
            .enroll_instance(&enrollment, limit)
            .map_err(|e| e.to_string())?
        {
            EnrollOutcome::Enrolled { generation } => {
                Ok(format!("enrolled {instance} at generation {generation}"))
            }
            EnrollOutcome::Updated { generation } => Ok(format!(
                "updated {instance}'s enrollment at generation {generation}"
            )),
            EnrollOutcome::LimitReached { limit } => Err(format!(
                "the node policy allows {limit} enrolled instances, and all are in use"
            )),
            EnrollOutcome::UnitTaken => Err("another instance is enrolled with this unit".into()),
            EnrollOutcome::AccountTaken => {
                Err("another instance is enrolled under this UID or GID".into())
            }
            EnrollOutcome::NoSpace => {
                Err("the ledger has no room left beyond what its fences need".into())
            }
        }
    })
}

/// The role J, V and the formatter would be dispatched from, in plan order.
pub const DISPATCHED_ROLES: [Role; 3] = [Role::Jailer, Role::Firecracker, Role::MkfsXfs];

#[cfg(test)]
mod tests;
