//! B3: approved plans, the root node ledger and the concrete worker model, with fake
//! resources only. This module is H's side of the group: bounded framing has already
//! happened, and everything here is in-memory checks and dispatch to worker processes.
//! It performs no filesystem, SQLite, hashing or `/proc` work on the socket runtime.
//! No code path launches a VM, a jailer or Firecracker, and no reply can say READY.
pub mod config;
pub mod executable;
pub mod identity;
pub mod inventory;
pub mod journal;
pub mod manifest;
pub mod workers;

use self::config::{NodePolicy, ProfileCatalog};
use self::executable::{ExecutableIdentity, ExecutableTable, Role, WalkPolicy};
use self::inventory::{NamespaceObservation, NodeObservation, ObservationBackend, WorkerFreshness};
use self::journal::{
    AdmitOutcome, AdmitRequest, AttachOutcome, FenceOutcome, FenceRequest, LedgerConfig,
    StopAuthority, TokenLookup, WorkerIntentSpec,
};
use self::manifest::ManifestGate;
use self::workers::{
    AdmissionAuthority, CallError, Channel, Endpoint, Heartbeat, Lane, LedgerReply, LedgerRequest,
    MonitorCommand, MonitorEvent, MonitorReply, MonitorSockets, NodeConfig, PrepReply, PrepRequest,
    ProcessId, ProfileRuntime, RecoveryReply, RecoveryRequest, RevalidatedPlan, RevocationTable,
    SupervisorCommand, SupervisorContext, SupervisorEvent, Timings, try_reap,
};
use super::protocol::{
    AccountingReply, AmbiguousClass, CapabilitiesReply, CreateReply, FIRECRACKER_GROUP_VERSION,
    FenceReply, FirecrackerOperation, FirecrackerRequest, FirecrackerResponse, GroupError,
    GroupErrorKind, InspectReply, ListReply, WireBytes, WorkerHealth, WorkersHealth,
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

/// The most live instance attachments on one node.
const MAX_ATTACHMENTS: usize = 16;
/// Bounded in-memory token state. Closed gates survive until their fence is durable.
const MAX_TOKEN_GATES: usize = 4096;
/// Queued requests for one token, beyond which a duplicate is refused immediately.
const MAX_TOKEN_WAITERS: usize = 16;
/// Accepted work that may outlive its waiter.
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

/// The resource names a supervisor may touch. Journaled before its gate opens.
const ALLOWED_RESOURCES: [&str; 5] = ["work.xfs", "identity.bin", "jail-root", "cgroup", "vm"];

/// A wire deadline in both clocks: same absolute instant, never a fresh budget.
#[derive(Clone, Copy, Debug)]
pub struct WireDeadline {
    pub instant: Instant,
    pub ns: u64,
}

impl WireDeadline {
    fn expired(&self) -> bool {
        Instant::now() >= self.instant
    }

    fn with_grace(&self) -> u64 {
        self.ns.saturating_add(LOOKUP_GRACE.as_nanos() as u64)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attachment {
    epoch: Id128,
    peer_pid: i32,
    peer_start: Option<u64>,
    /// False when another database already owns this namespace.
    admission_open: bool,
    /// Its slot and generation in the table L reads at C2. A namespace with closed
    /// admission never publishes this, so nothing it asked for can commit.
    authority: AdmissionAuthority,
}

/// Per-token serialization and the in-memory dispatch gate. The first rejection after
/// C1 closes the gate at once; nothing reopens it, even when the cause later clears.
#[derive(Default)]
struct TokenGate {
    serial: Arc<tokio::sync::Mutex<()>>,
    closed: Mutex<Option<AmbiguousClass>>,
    waiters: AtomicUsize,
}

impl TokenGate {
    fn close(&self, class: AmbiguousClass) {
        self.closed.lock().unwrap().get_or_insert(class);
    }

    fn closed(&self) -> Option<AmbiguousClass> {
        *self.closed.lock().unwrap()
    }
}

struct SupervisorEntry {
    pid: i32,
    channel: Arc<Channel>,
    worker_id: i64,
    vm: Option<ProcessId>,
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
        }
    }
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
    attaching: Mutex<std::collections::HashSet<Id128>>,
    gates: Mutex<HashMap<Id128, Arc<TokenGate>>>,
    supervisors: Mutex<HashMap<Id128, SupervisorEntry>>,
    pending: Mutex<VecDeque<LedgerRequest>>,
    flushing: tokio::sync::Mutex<()>,
    detached: Arc<Semaphore>,
    prep_waiters: AtomicUsize,
    ledger_fault: Mutex<Option<String>>,
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
    let pid = workers::spawn_process(&keep, move || {
        workers::ledger_main(
            Endpoint::new(child),
            ledger,
            Heartbeat::new(heartbeat, every),
            inherited,
            workers::ledger_request_expires,
        );
    })?;
    let (channel, _events) = Channel::spawn(
        host,
        workers::LEDGER_QUEUE_NORMAL,
        workers::LEDGER_QUEUE_RESERVED,
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
        let directory = executable::walk_directory(&config.walk, &config.ledger.directory)
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
        let revocations = Arc::new(RevocationTable::new(MAX_ATTACHMENTS)?);
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
        let node = Arc::new(Self {
            config,
            _lock: Some(lock),
            sockets,
            ledger: Mutex::new(ledger),
            prep: [Mutex::new(prep0), Mutex::new(prep1)],
            monitor: Mutex::new(monitor),
            recovery: [Mutex::new(kill0), Mutex::new(kill1)],
            attachments: Mutex::default(),
            attaching: Mutex::default(),
            gates: Mutex::default(),
            supervisors: Mutex::default(),
            pending: Mutex::default(),
            flushing: tokio::sync::Mutex::new(()),
            detached: Arc::new(Semaphore::new(MAX_DETACHED)),
            prep_waiters: AtomicUsize::new(0),
            ledger_fault: Mutex::new(None),
            lease_fault: Mutex::new(None),
            stale_workers: Mutex::default(),
            monitor_lost: Mutex::new(false),
            orphans: Mutex::default(),
            discarded: Mutex::default(),
            revocations,
            next_authority: AtomicU64::new(1),
            generation_hint: AtomicU64::new(0),
            stop: CancellationToken::new(),
        });
        tokio::spawn(Self::monitor_events(Arc::downgrade(&node), monitor_events));
        tokio::spawn(Self::supervise(Arc::downgrade(&node)));
        drop(directory);
        node.replay_at_startup().await;
        Ok(node)
    }

    /// Replays claims before serving. A ledger that cannot answer leaves the node
    /// degraded: read paths say Unavailable, and capacity is never presumed free.
    async fn replay_at_startup(self: &Arc<Self>) {
        let deadline = workers::monotonic_ns().saturating_add(30_000_000_000);
        let channel = self.ledger_channel();
        match channel
            .call::<LedgerReply>(Lane::Reserved, &LedgerRequest::Replay, deadline)
            .await
        {
            Ok(LedgerReply::Replay(snapshot)) => {
                self.generation_hint
                    .store(snapshot.generation, Ordering::Relaxed);
                self.register_infrastructure().await;
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
    }

    /// Journals each startup worker's inherited image identity, when a profile pins it.
    async fn register_infrastructure(self: &Arc<Self>) {
        let Some(image) = self.config.helper_image else {
            return;
        };
        let deadline = workers::monotonic_ns().saturating_add(5_000_000_000);
        let channel = self.ledger_channel();
        for kind in SLOTS {
            let pid = self.with_slot(kind, |slot| slot.pid);
            let reply = channel
                .call::<LedgerReply>(
                    Lane::Reserved,
                    &LedgerRequest::RecordInfrastructure {
                        spec: Box::new(infrastructure_spec(kind, image)),
                        pid,
                    },
                    deadline,
                )
                .await;
            if let Ok(LedgerReply::Worker { worker_id }) = reply {
                self.with_slot(kind, |slot| slot.worker_id = Some(worker_id));
            }
        }
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
            let live_identity = match (worker.pid, worker.start_time) {
                (Some(pid), Some(start_time)) => Some(ProcessId { pid, start_time }),
                _ => None,
            };
            match live_identity {
                // Infrastructure from this very startup is not an orphan.
                Some(target)
                    if worker.allocation_id.is_none()
                        && self.is_current_infrastructure(target.pid) => {}
                Some(target) => {
                    let gone = self
                        .probe_process(target, worker.host_boot_id.clone())
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
                        let gone = self.dispatch_kill(target).await.unwrap_or(false);
                        if gone {
                            self.queue_record(LedgerRequest::Settle {
                                worker_id: worker.worker_id,
                                settlement: "stopped-after-helper-restart".into(),
                            });
                        } else {
                            self.orphans.lock().unwrap().push(Orphan {
                                worker_id: worker.worker_id,
                                target,
                                boot_id: worker.host_boot_id.clone(),
                            });
                        }
                    } else {
                        self.orphans.lock().unwrap().push(Orphan {
                            worker_id: worker.worker_id,
                            target,
                            boot_id: worker.host_boot_id.clone(),
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
        self.ledger.lock().unwrap().channel.clone()
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

    async fn ledger_call(
        &self,
        lane: Lane,
        request: &LedgerRequest,
        deadline_ns: u64,
    ) -> Result<LedgerReply, CallError> {
        let channel = self.ledger_channel();
        channel.call(lane, request, deadline_ns).await
    }

    /// One reserved K slot, then the other. A stuck slot stays occupied by its original
    /// process; this only moves on to the other fixed slot and never spawns a third.
    async fn dispatch_kill(&self, target: ProcessId) -> Option<bool> {
        for slot in &self.recovery {
            let channel = {
                let slot = slot.lock().unwrap();
                if slot.reaped {
                    continue;
                }
                slot.channel.clone()
            };
            let request = RecoveryRequest::Kill { target };
            let call = channel.call::<RecoveryReply>(Lane::Normal, &request, u64::MAX);
            if let Ok(Ok(RecoveryReply::Killed { gone })) =
                tokio::time::timeout(Duration::from_millis(750), call).await
            {
                return Some(gone);
            }
        }
        None
    }

    async fn probe_process(&self, target: ProcessId, boot_id: Option<String>) -> Option<bool> {
        for slot in &self.recovery {
            let channel = {
                let slot = slot.lock().unwrap();
                if slot.reaped {
                    continue;
                }
                slot.channel.clone()
            };
            let request = RecoveryRequest::Probe {
                target,
                boot_id: boot_id.clone(),
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
    async fn flush_pending(&self) {
        let _flushing = self.flushing.lock().await;
        loop {
            let record = self.pending.lock().unwrap().pop_front();
            let Some(record) = record else { return };
            let reply = self.ledger_call(Lane::Reserved, &record, u64::MAX).await;
            match reply {
                Ok(LedgerReply::Done | LedgerReply::Generation(_)) => {
                    if let (
                        LedgerRequest::RecordChild { allocation, .. },
                        Ok(LedgerReply::Generation(id)),
                    ) = (&record, &reply)
                        && let Some(entry) = self.supervisors.lock().unwrap().get_mut(allocation)
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
                    return;
                }
            }
        }
    }

    /// Irrevocable for this boot: the gate closes, S's permit is revoked and nothing can
    /// reopen either. Later records follow; none of this needs L.
    fn set_stop_fence(&self, allocation: Id128, reason: &str) {
        let mut supervisors = self.supervisors.lock().unwrap();
        let Some(entry) = supervisors.get_mut(&allocation) else {
            return;
        };
        if entry.stop_fenced {
            return;
        }
        entry.stop_fenced = true;
        entry.revoked = true;
        entry.revoke_sent = entry.channel.notify(&SupervisorCommand::Revoke);
        drop(supervisors);
        if let Some(gate) = self.gate(allocation) {
            gate.close(AmbiguousClass::GateClosed);
        }
        self.queue_record(LedgerRequest::RecordStop {
            allocation,
            reason: reason.into(),
        });
    }

    /// Section 4.4's stop path: revoke reuse in memory first, then dispatch K without
    /// any new fsync. Never a receipt or release: journal evidence follows when it can.
    fn contain_allocation(self: &Arc<Self>, allocation: Id128, reason: &str) {
        self.set_stop_fence(allocation, reason);
        self.dispatch_containment(allocation);
    }

    /// One K dispatch per subtree at a time, until it is gone. The tick retries, so no
    /// subtree is forgotten while both fixed slots are occupied.
    fn dispatch_containment(self: &Arc<Self>, allocation: Id128) {
        let target = {
            let mut supervisors = self.supervisors.lock().unwrap();
            let Some(entry) = supervisors.get_mut(&allocation) else {
                return;
            };
            match entry.vm {
                Some(target) if !entry.vm_gone && !entry.kill_inflight => {
                    entry.kill_inflight = true;
                    target
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
        let unfinished: Vec<Id128> = self
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
        let affected: Vec<Id128> = self.supervisors.lock().unwrap().keys().copied().collect();
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
                    .probe_process(orphan.target, orphan.boot_id.clone())
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
            (SlotKind::Ledger, Spawned::Plain(slot)) => *self.ledger.lock().unwrap() = slot,
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
            let spawned = self.spawn_slot(kind).map_err(|_| ())?;
            self.publish_slot(kind, spawned);
            return Ok(());
        };
        let spec = Box::new(infrastructure_spec(kind, image));
        if kind == SlotKind::Ledger {
            let mut spawned = self.spawn_slot(kind).map_err(|_| ())?;
            let channel = spawned.worker().channel.clone();
            let pid = spawned.worker().pid;
            // A row still unsettled travels with the slot, for the next attempt.
            spawned.worker_mut().worker_id = prior;
            if let Some(worker_id) = prior {
                let settled = channel
                    .call::<LedgerReply>(
                        Lane::Reserved,
                        &LedgerRequest::Settle {
                            worker_id,
                            settlement: evidence,
                        },
                        u64::MAX,
                    )
                    .await;
                if matches!(settled, Ok(LedgerReply::Done)) {
                    spawned.worker_mut().worker_id = None;
                }
            }
            let recorded = channel
                .call::<LedgerReply>(
                    Lane::Reserved,
                    &LedgerRequest::RecordInfrastructure { spec, pid },
                    u64::MAX,
                )
                .await;
            if let Ok(LedgerReply::Worker { worker_id }) = recorded {
                spawned.worker_mut().worker_id = Some(worker_id);
            }
            self.publish_slot(kind, spawned);
            return Ok(());
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

    fn gate(&self, allocation: Id128) -> Option<Arc<TokenGate>> {
        self.gates.lock().unwrap().get(&allocation).cloned()
    }

    /// Finds or creates a token's gate. When the map is full, only idle open gates
    /// are evicted: a closed gate stays until its durable fence replaces it.
    fn gate_for(&self, allocation: Id128) -> Option<Arc<TokenGate>> {
        let mut gates = self.gates.lock().unwrap();
        if let Some(gate) = gates.get(&allocation) {
            return Some(gate.clone());
        }
        if gates.len() >= MAX_TOKEN_GATES {
            let idle = gates
                .iter()
                .find(|(_, gate)| Arc::strong_count(gate) == 1 && gate.closed().is_none())
                .map(|(id, _)| *id);
            gates.remove(&idle?);
        }
        let gate = Arc::new(TokenGate::default());
        gates.insert(allocation, gate.clone());
        Some(gate)
    }

    fn epoch_valid(&self, instance: Id128, epoch: Option<Id128>, peer_pid: Option<i32>) -> bool {
        let attachments = self.attachments.lock().unwrap();
        attachments.get(&instance).is_some_and(|attachment| {
            Some(attachment.epoch) == epoch && peer_pid == Some(attachment.peer_pid)
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
        peer_pid: Option<i32>,
        deadline: WireDeadline,
        cancel: &CancellationToken,
    ) -> FirecrackerResponse {
        let instance = request.instance_id;
        let epoch = request.connection_epoch;
        match request.operation {
            FirecrackerOperation::AttachInstance { database_uuid } => {
                self.attach(instance, database_uuid, peer_pid, deadline)
                    .await
            }
            FirecrackerOperation::Create {
                allocation_id,
                sandbox_id,
                plan,
                plan_digest,
            } => {
                let node = self.clone();
                let token = CreateToken {
                    instance,
                    epoch,
                    peer_pid,
                    allocation: allocation_id,
                    sandbox_id,
                    plan: plan.0,
                    plan_digest,
                    deadline,
                };
                let reply = self
                    .run_detached(
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
                let node = self.clone();
                let token = FenceToken {
                    instance,
                    epoch,
                    peer_pid,
                    allocation: allocation_id,
                    sandbox_id,
                    plan_digest,
                    deadline,
                };
                let reply = self
                    .run_detached(
                        deadline,
                        cancel,
                        allocation_id,
                        ambiguous_fence(AmbiguousClass::Pending, "fence outcome not yet known"),
                        move || node.fence_flow(token),
                    )
                    .await;
                FirecrackerResponse::Fence(reply)
            }
            operation => {
                if !self.epoch_valid(instance, epoch, peer_pid) {
                    return group_error(
                        GroupErrorKind::StaleEpoch,
                        "connection epoch is not current for this instance",
                    );
                }
                let response = async {
                    match operation {
                        FirecrackerOperation::Capabilities => self.capabilities(),
                        FirecrackerOperation::Accounting => self.accounting(deadline).await,
                        FirecrackerOperation::Preflight {
                            allocation_id,
                            sandbox_id,
                            profile,
                            spec,
                        } => {
                            self.preflight(
                                instance,
                                allocation_id,
                                sandbox_id,
                                profile,
                                spec,
                                deadline,
                            )
                            .await
                        }
                        FirecrackerOperation::Inspect { allocation_id } => {
                            self.inspect(instance, allocation_id, deadline).await
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
    async fn run_detached<T, F, Fut>(
        self: &Arc<Self>,
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
        let Ok(permit) = self.detached.clone().try_acquire_owned() else {
            if let Some(gate) = self.gate_for(allocation) {
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

    async fn attach(
        self: &Arc<Self>,
        instance: Id128,
        database_uuid: Id128,
        peer_pid: Option<i32>,
        deadline: WireDeadline,
    ) -> FirecrackerResponse {
        let Some(peer_pid) = peer_pid else {
            return group_error(GroupErrorKind::Invalid, "peer PID is unavailable");
        };
        {
            let attachments = self.attachments.lock().unwrap();
            let mut attaching = self.attaching.lock().unwrap();
            if attachments.contains_key(&instance) || attaching.contains(&instance) {
                return group_error(
                    GroupErrorKind::AlreadyAttached,
                    "another live holder has this instance",
                );
            }
            if attachments.len() + attaching.len() >= MAX_ATTACHMENTS {
                return group_error(GroupErrorKind::ResourceExhausted, "too many attachments");
            }
            attaching.insert(instance);
        }
        let reply = tokio::time::timeout_at(
            deadline.instant,
            self.ledger_call(
                Lane::Normal,
                &LedgerRequest::Attach {
                    instance,
                    database_uuid,
                    peer_pid,
                },
                deadline.ns,
            ),
        )
        .await;
        self.attaching.lock().unwrap().remove(&instance);
        let (outcome, peer_start) = match reply {
            Ok(Ok(LedgerReply::Attached {
                outcome,
                peer_start,
            })) => (outcome, peer_start),
            Ok(Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason })) => {
                return group_error(GroupErrorKind::Unavailable, reason);
            }
            _ => return group_error(GroupErrorKind::Unavailable, "ledger did not answer attach"),
        };
        let Ok(epoch) = fresh_id() else {
            return group_error(GroupErrorKind::Unavailable, "no entropy for an epoch");
        };
        let (node_id, admission_open) = match outcome {
            AttachOutcome::Bound { node_id, .. } => (node_id, true),
            AttachOutcome::DatabaseMismatch { node_id, .. } => (node_id, false),
        };
        {
            let mut attachments = self.attachments.lock().unwrap();
            let Some(slot) = (0..MAX_ATTACHMENTS as u32)
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
                    peer_start,
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
    fn capabilities(&self) -> FirecrackerResponse {
        let stale = self.stale_workers.lock().unwrap().clone();
        let monitor = if self.monitor_healthy() {
            WorkerHealth::Healthy
        } else {
            WorkerHealth::Stalled
        };
        let mut ledger_fault = self.ledger_fault.lock().unwrap().clone();
        if ledger_fault.is_none() {
            ledger_fault = self.lease_fault.lock().unwrap().clone();
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
        };
        FirecrackerResponse::Capabilities(CapabilitiesReply {
            group_version: FIRECRACKER_GROUP_VERSION,
            broker_protocol: 1,
            helper_version: env!("CARGO_PKG_VERSION").into(),
            enabled: true,
            launch_enabled: false,
            profiles: self
                .config
                .profiles
                .iter()
                .map(|p| p.catalog.profile.clone())
                .collect(),
            health: Some(health),
        })
    }

    async fn accounting(&self, deadline: WireDeadline) -> FirecrackerResponse {
        let reply = tokio::time::timeout_at(
            deadline.instant,
            self.ledger_call(Lane::Reserved, &LedgerRequest::Accounting, deadline.ns),
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

    async fn preflight(
        self: &Arc<Self>,
        instance: Id128,
        allocation: Id128,
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
        let snapshot = self
            .ledger_call(
                Lane::Normal,
                &LedgerRequest::PreflightSnapshot {
                    instance,
                    allocation,
                },
                deadline.ns,
            )
            .await;
        let claimed = match snapshot {
            Ok(LedgerReply::PreflightSnapshot {
                claimed,
                retired_or_active,
                headroom,
            }) => {
                if retired_or_active {
                    return group_error(
                        GroupErrorKind::OwnershipConflict,
                        "this allocation token was already used",
                    );
                }
                if !headroom {
                    return group_error(
                        GroupErrorKind::ResourceExhausted,
                        "no fence headroom is left for another token",
                    );
                }
                claimed
            }
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => {
                return group_error(GroupErrorKind::Unavailable, reason);
            }
            Err(CallError::Full) => {
                return group_error(GroupErrorKind::ResourceExhausted, "ledger queue is full");
            }
            _ => return group_error(GroupErrorKind::Unavailable, "ledger did not answer"),
        };
        match self
            .prep_call(
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
            Ok(PrepReply::Prepared(prepared)) => FirecrackerResponse::Prepared(prepared),
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
        let Some(gate) = self.gate_for(token.allocation) else {
            return ambiguous_create(AmbiguousClass::WorkerExhausted, "token table is full");
        };
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
                return CreateReply::Absent {
                    receipt: WireBytes(receipt),
                };
            }
            Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                return ambiguous_create(AmbiguousClass::Conflict, reason);
            }
            Ok(LedgerReply::Lookup(TokenLookup::Active {
                generation, phase, ..
            })) => {
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
        // Every rejection below closes the gate before answering.
        let reject = |class: AmbiguousClass, message: String| {
            gate.close(class);
            ambiguous_create(class, message)
        };
        if !self.epoch_valid(token.instance, token.epoch, token.peer_pid) {
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
            Ok(PrepReply::Rejected { class, reason }) => return reject(class, reason),
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
        let backend_id = identity::backend_id(token.allocation);
        let cgroup = format!(
            "kilnd-firecracker/{}/{backend_id}/{SUPERVISOR_CGROUP_LEAF}",
            token.instance
        );
        let allowed_names: Vec<String> = ALLOWED_RESOURCES
            .iter()
            .map(|name| name.to_string())
            .collect();
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
                if replay {
                    return CreateReply::Accepted {
                        generation,
                        phase,
                        replay,
                    };
                }
                // The commit may have raced a revocation, or its reply a deadline. Either
                // way the claim is durable, and held for an exact fence: nothing starts.
                let refused = if !self.revocations.is_current(&authority) {
                    Some((
                        AmbiguousClass::OldEpoch,
                        "the attachment was replaced as this committed",
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
                    self.abandon_start(token.allocation, reason);
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
            Ok(LedgerReply::Admit(AdmitOutcome::Fenced { receipt })) => CreateReply::Absent {
                receipt: WireBytes(receipt),
            },
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
    fn abandon_start(&self, allocation: Id128, reason: &str) {
        self.queue_record(LedgerRequest::RecordStop {
            allocation,
            reason: reason.into(),
        });
        self.queue_record(LedgerRequest::SettleUnstarted { allocation });
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
        let mut keep = vec![child.as_raw_fd(), watch_child.as_raw_fd()];
        keep.extend(self.config.table_fds());
        let inherited = self.config.clone();
        let instance = token.instance;
        let allocation = token.allocation;
        let profile_name = profile.to_string();
        let pid = workers::spawn_process(&keep, move || {
            workers::supervisor_main(SupervisorContext {
                config: inherited,
                instance,
                allocation,
                profile: profile_name,
                control: Endpoint::new(child),
                watch: watch_child,
            });
        })
        .map_err(unavailable)?;
        let (channel, events) = Channel::spawn(host, CONTROL_QUEUE, 0).map_err(unavailable)?;
        self.supervisors.lock().unwrap().insert(
            allocation,
            SupervisorEntry {
                pid,
                channel: channel.clone(),
                worker_id,
                vm: None,
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
            },
        );
        tokio::spawn(Self::supervisor_events(self.clone(), allocation, events));
        // A failure before the gate means S exits on EOF with nothing done. It is not
        // a lost boot: mark it expected, record the stop, and let the exit settle S.
        let abort = |class: AmbiguousClass, reason: String| {
            let mut supervisors = self.supervisors.lock().unwrap();
            if let Some(entry) = supervisors.get_mut(&allocation) {
                entry.revoked = true;
                entry.channel.close();
            }
            drop(supervisors);
            self.queue_record(LedgerRequest::RecordStop {
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
                &MonitorCommand::RegisterWatch { allocation },
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
                    allocation,
                    expected_generation: generation,
                    phase: "preparing".into(),
                },
                token.deadline.ns,
            ),
        )
        .await;
        let Ok(Ok(LedgerReply::Generation(generation))) = advanced else {
            return Err(step_failed("the ledger did not record PREPARING"));
        };
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
        let opened = {
            let mut supervisors = self.supervisors.lock().unwrap();
            supervisors.get_mut(&allocation).is_some_and(|entry| {
                !entry.stop_fenced
                    && entry.channel.notify(&SupervisorCommand::Tick)
                    && entry.channel.notify(&SupervisorCommand::OpenGate {
                        operation_generation,
                        allowed_names,
                        expected,
                        deadline_ns: token.deadline.ns,
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

    async fn supervisor_events(
        self: Arc<Self>,
        allocation: Id128,
        mut events: mpsc::Receiver<serde_json::Value>,
    ) {
        while let Some(event) = events.recv().await {
            let Ok(event) = serde_json::from_value::<SupervisorEvent>(event) else {
                continue;
            };
            match event {
                SupervisorEvent::ExecObserved(observation) => {
                    self.queue_record(LedgerRequest::RecordObserved {
                        allocation,
                        actual: observation.actual,
                    });
                }
                SupervisorEvent::ExecRefused { role, reason } => {
                    self.contain_allocation(
                        allocation,
                        &format!("{} identity mismatch: {reason}", role.as_str()),
                    );
                }
                SupervisorEvent::VmStarted(target) => {
                    self.on_vm_started(allocation, target).await;
                }
                SupervisorEvent::EffectsDone => {}
                SupervisorEvent::SetupExpired => {
                    self.contain_allocation(allocation, "setup deadline expired");
                }
            }
        }
    }

    /// The precommitted authority's concrete target reaches M before anything else,
    /// and it needs no ledger write: an emergency works with L already blocked.
    async fn on_vm_started(self: &Arc<Self>, allocation: Id128, target: ProcessId) {
        if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&allocation) {
            entry.vm = Some(target);
        }
        let channel = self.monitor.lock().unwrap().worker.channel.clone();
        let registered = tokio::time::timeout(
            Duration::from_secs(1),
            channel.call::<MonitorReply>(
                Lane::Normal,
                &MonitorCommand::RegisterTarget { allocation, target },
                u64::MAX,
            ),
        )
        .await;
        // Without M's copy, this subtree has lost independent supervision. A fence that
        // landed first also needs the target it could not have known about.
        let fenced = self
            .supervisors
            .lock()
            .unwrap()
            .get(&allocation)
            .is_some_and(|entry| entry.stop_fenced);
        if fenced || !matches!(registered, Ok(Ok(MonitorReply::Registered))) {
            self.contain_allocation(allocation, "subtree target has no monitor");
        }
        if let Some(image) = self.config.helper_image {
            self.queue_record(LedgerRequest::RecordChild {
                allocation,
                spec: Box::new(WorkerIntentSpec {
                    mode: "vm".into(),
                    allowed_names: vec!["vm".into()],
                    cgroup: format!("fc-{allocation}/vm/vmm"),
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
        let Some(gate) = self.gate_for(token.allocation) else {
            return ambiguous_fence(AmbiguousClass::WorkerExhausted, "token table is full");
        };
        if gate.waiters.fetch_add(1, Ordering::AcqRel) >= MAX_TOKEN_WAITERS {
            gate.waiters.fetch_sub(1, Ordering::AcqRel);
            return ambiguous_fence(AmbiguousClass::Pending, "too many queued duplicates");
        }
        let serial = gate.serial.clone().lock_owned().await;
        gate.waiters.fetch_sub(1, Ordering::AcqRel);
        let _serial = serial;
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
                self.forget_token(token.allocation);
                return FenceReply::Absent {
                    receipt: WireBytes(receipt),
                };
            }
            Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                return ambiguous_fence(AmbiguousClass::Conflict, reason);
            }
            Ok(LedgerReply::Lookup(TokenLookup::Active { .. } | TokenLookup::Unknown)) => {}
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
        if !self.epoch_valid(token.instance, token.epoch, token.peer_pid) {
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
        if let Err(reply) = self.settle_permits(&token).await {
            return reply;
        }
        let observation = self
            .prep_call(
                PrepRequest::ObserveAllocation {
                    instance: token.instance,
                    allocation: token.allocation,
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
        self.flush_pending().await;
        let outcome = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::Fence(Box::new(FenceRequest {
                    instance_id: token.instance,
                    allocation_id: token.allocation,
                    sandbox_id: token.sandbox_id.clone(),
                    plan_digest: token.plan_digest,
                    observations: "permits=settled;namespace=absent".into(),
                })),
                token.deadline.ns,
            )
            .await;
        match outcome {
            Ok(LedgerReply::Fence(FenceOutcome::Absent { receipt, .. })) => {
                // Durable now, with this token's serialization still held.
                #[cfg(test)]
                workers::faults::hold(&format!("H.fence.after_commit.{}", token.allocation)).await;
                self.forget_token(token.allocation);
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
        let target = {
            let mut supervisors = self.supervisors.lock().unwrap();
            supervisors.get_mut(&token.allocation).map(|entry| {
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
            supervisors
                .get(&token.allocation)
                .and_then(|entry| entry.vm.map(|vm| (vm, entry.vm_gone, entry.vm_worker)))
        };
        if let Some((target, known_gone, worker)) = vm {
            let gone = known_gone || self.probe_process(target, None).await.unwrap_or(false);
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
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::SettleUnstarted {
                    allocation: token.allocation,
                },
                token.deadline.ns,
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
    fn forget_token(&self, allocation: Id128) {
        self.gates.lock().unwrap().remove(&allocation);
        let removed = self.supervisors.lock().unwrap().remove(&allocation);
        if removed.is_some() {
            self.monitor
                .lock()
                .unwrap()
                .worker
                .channel
                .notify(&MonitorCommand::Forget { allocation });
        }
    }

    fn freshness(&self, allocation: Id128) -> WorkerFreshness {
        let supervisors = self.supervisors.lock().unwrap();
        match supervisors.get(&allocation) {
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
        deadline: WireDeadline,
    ) -> FirecrackerResponse {
        let reply = self
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::Inspect {
                    instance,
                    allocation,
                },
                deadline.ns,
            )
            .await;
        FirecrackerResponse::Inspect(match reply {
            Ok(LedgerReply::Lookup(TokenLookup::Fenced { receipt })) => {
                InspectReply::AbsentFenced {
                    receipt: WireBytes(receipt),
                }
            }
            Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                InspectReply::Incompatible { message: reason }
            }
            Ok(LedgerReply::Lookup(TokenLookup::Unknown)) => InspectReply::Unknown {
                reason: "no journal record; this is not evidence of absence".into(),
            },
            Ok(LedgerReply::Lookup(TokenLookup::Active {
                generation, phase, ..
            })) => {
                let fresh = self.freshness(allocation);
                if phase == "stopped" {
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
                    InspectReply::PresentBusy {
                        generation,
                        phase,
                        plan_digest: None,
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
            .prep_call(PrepRequest::ObserveNode { instance }, deadline)
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
            &|allocation| self.freshness(allocation),
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
            "supervisors": supervisors.iter().map(|(allocation, entry)| {
                (allocation.to_string(), serde_json::json!({
                    "pid": entry.pid,
                    "exit": entry.exit,
                    "stop_fenced": entry.stop_fenced,
                    "stalled": entry.stalled,
                    "contained": entry.contained,
                    "vm": entry.vm.map(|vm| vm.pid),
                }))
            }).collect::<serde_json::Map<_, _>>(),
            "closed_gates": self.gates.lock().unwrap().values().filter(|g| g.closed().is_some()).count(),
            "peer_starts": self.attachments.lock().unwrap().values().map(|a| a.peer_start).collect::<Vec<_>>(),
        })
    }
}

/// A worker from an earlier helper that was still alive at recovery. It stays charged
/// and is revisited until it is gone; only then does its row settle.
#[derive(Clone)]
struct Orphan {
    worker_id: i64,
    target: ProcessId,
    boot_id: Option<String>,
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
    peer_pid: Option<i32>,
    allocation: Id128,
    sandbox_id: String,
    plan: Vec<u8>,
    plan_digest: Digest,
    deadline: WireDeadline,
}

struct FenceToken {
    instance: Id128,
    epoch: Option<Id128>,
    peer_pid: Option<i32>,
    allocation: Id128,
    sandbox_id: String,
    plan_digest: Digest,
    deadline: WireDeadline,
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
            identity::backend_id(token.allocation)
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
    })
}

/// The production configuration from a verified root policy. Nothing here accepts a
/// fixture, and until B7 the production gate leaves the served profile list empty.
pub fn production_config(policy: NodePolicy) -> NodeConfig {
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
            shared: config::SharedReserve::default(),
        },
        ranges: policy.identity_ranges,
        profiles,
        walk,
        gate: ManifestGate::ProductionDisabled,
        observation: ObservationBackend::Disabled,
        timings: Timings::default(),
        helper_image,
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
    journal::Ledger::provision(&LedgerConfig {
        directory: policy.ledger_dir.clone(),
        policy: WalkPolicy::production(),
        node_id: policy.node_id,
        ceilings: policy.ceilings,
        shared: config::SharedReserve::default(),
    })
    .map_err(|e| e.to_string())
}

/// The role J, V and the formatter would be dispatched from, in plan order.
pub const DISPATCHED_ROLES: [Role; 3] = [Role::Jailer, Role::Firecracker, Role::MkfsXfs];

#[cfg(test)]
mod tests;
