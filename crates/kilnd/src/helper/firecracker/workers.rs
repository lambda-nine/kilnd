//! Section 6.4's fixed process model, with fake effects and real processes. H stays
//! on its current-thread runtime and only frames, authorizes, dispatches and waits.
//! L owns SQLite; P runs hashing and namespace reads; S is one per accepted allocation;
//! M watches heartbeats and dispatches stops; K holds two reserved recovery slots.
//! These are limits, not replacement-on-timeout pools: a slot is reassigned only after
//! its original process exited and was reaped. Every mode here is fork-only and
//! inherits the verified helper image; nothing here execs or launches a VM.
use super::config::{self, ExactPlan, PlanInputs, ProfileCatalog};
use super::executable::{
    self, ExecObservation, ExecutableIdentity, ExecutableTable, Role, WalkPolicy,
};
use super::identity::{self, ClaimedIdentities, IdentityLeases, IdentityRanges};
use super::inventory::{NamespaceObservation, NodeObservation, ObservationBackend};
use super::journal::{
    AccountingSnapshot, AdmitOutcome, AdmitRequest, AttachOutcome, FenceOutcome, FenceRequest,
    InventorySnapshot, Ledger, LedgerConfig, LedgerError, ReplaySnapshot, TokenLookup,
    WorkerIntentSpec,
};
use super::manifest::{self, ManifestGate};
use super::peer::PeerAttestor;
use crate::helper::protocol::{AmbiguousClass, PreparedReply, WireBytes};
use crate::model::{Digest, Id128, ResourceReservation, SandboxSpec};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Plan bytes as hex plus their envelope always fit, and nothing else needs more.
pub const MAX_IPC_FRAME: usize = 1 << 20;
/// L's bounded queue. The reserved lane is never consumed by new admissions.
pub const LEDGER_QUEUE_NORMAL: usize = 28;
pub const LEDGER_QUEUE_RESERVED: usize = 4;
/// One attachment proof per enrolled instance, separate from the lanes above: no volume
/// of other traffic takes this lane, and attach traffic never takes theirs.
pub const LEDGER_QUEUE_ATTACH: usize = super::config::MAX_ENROLLED_HARD as usize;
pub const PREP_SLOTS: usize = 2;
pub const RECOVERY_SLOTS: usize = 2;

/// Test-only deterministic faults, by marker file. Compiled out of production: there
/// is no public fixture mode, CLI switch or environment hook.
#[cfg(test)]
pub mod faults {
    use std::path::PathBuf;
    use std::sync::OnceLock;
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

    pub fn install(directory: PathBuf) {
        let _ = DIRECTORY.set(directory);
    }

    pub fn present(name: &str) -> bool {
        DIRECTORY
            .get()
            .is_some_and(|directory| directory.join(name).exists())
    }

    /// `<name>.panic` panics this process. `<name>.stall` blocks it, with no
    /// heartbeats, until the file is removed: a real stuck worker, not a counter.
    pub fn point(name: &str) {
        if present(&format!("{name}.panic")) {
            panic!("injected fault at {name}");
        }
        let stall = format!("{name}.stall");
        if present(&stall) {
            if let Some(directory) = DIRECTORY.get() {
                let _ = std::fs::write(directory.join(format!("{name}.reached")), b"");
            }
            while present(&stall) {
                // A fixture's helper was killed: nothing will ever clear this stall.
                // SAFETY: getppid has no preconditions.
                if unsafe { libc::getppid() } == 1 {
                    // SAFETY: leave without running inherited destructors.
                    unsafe { libc::_exit(0) };
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }

    /// H's own test hold. It waits asynchronously, so H stays responsive while one
    /// token's serialized work is held open at an exact point.
    pub async fn hold(name: &str) {
        let hold = format!("{name}.hold");
        if present(&hold) {
            if let Some(directory) = DIRECTORY.get() {
                let _ = std::fs::write(directory.join(format!("{name}.reached")), b"");
            }
            while present(&hold) {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        }
    }
}

#[inline]
pub fn fault_point(_name: &str) {
    #[cfg(test)]
    faults::point(_name);
}

#[inline]
pub fn fault_enabled(_name: &str) -> bool {
    #[cfg(test)]
    {
        faults::present(_name)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// The current time on the same clock as the wire's absolute deadlines.
pub fn monotonic_ns() -> u64 {
    crate::helper::monotonic_ns().unwrap_or(u64::MAX)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    /// Zero marks an unsolicited event; a request's reply echoes its nonzero ID.
    id: u64,
    deadline_ns: u64,
    body: T,
}

fn encode_frame<T: Serialize>(envelope: &Envelope<T>) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(envelope).map_err(io::Error::other)?;
    if body.is_empty() || body.len() > MAX_IPC_FRAME {
        return Err(io::Error::other("worker frame size exceeded"));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Blocking only inside bounded `poll`; every read and write is `MSG_DONTWAIT`.
pub struct Endpoint {
    fd: OwnedFd,
    buffer: Vec<u8>,
    /// The unsent tail of a frame a slow peer did not take in time. It goes first next
    /// time, so giving a write up can drop a whole frame but never tear the stream.
    unsent: Vec<u8>,
}

pub enum Received<T> {
    Message { id: u64, deadline_ns: u64, body: T },
    Idle,
    Closed,
}

impl Endpoint {
    /// These private pairs share no open file description with anyone, so the flag is
    /// safe. Darwin can otherwise block a partial `send` despite `MSG_DONTWAIT`.
    pub fn new(stream: std::os::unix::net::UnixStream) -> Self {
        let _ = stream.set_nonblocking(true);
        Self {
            fd: stream.into(),
            buffer: Vec::new(),
            unsent: Vec::new(),
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// True when a whole frame is already buffered, so polling must not sleep.
    fn frame_buffered(&self) -> bool {
        self.buffer.len() >= 4
            && self.buffer.len()
                >= 4 + u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize
    }

    /// Reads whatever is available without waiting. `Ok(false)` means EOF.
    fn fill(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 64 * 1024];
        loop {
            // SAFETY: chunk is writable and the descriptor is owned.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n == 0 {
                return Ok(false);
            }
            if n < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock => Ok(true),
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => Ok(false),
                    _ => Err(error),
                };
            }
            self.buffer.extend_from_slice(&chunk[..n as usize]);
            if self.buffer.len() > 2 * MAX_IPC_FRAME {
                return Err(io::Error::other("worker frame backlog exceeded"));
            }
        }
    }

    fn take_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let size = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
        if size == 0 || size > MAX_IPC_FRAME {
            return Err(io::Error::other("worker frame size exceeded"));
        }
        if self.buffer.len() < 4 + size {
            return Ok(None);
        }
        let frame = self.buffer[4..4 + size].to_vec();
        self.buffer.drain(..4 + size);
        Ok(Some(frame))
    }

    /// One bounded wait for one message.
    pub fn receive<T: DeserializeOwned>(&mut self, wait: Duration) -> io::Result<Received<T>> {
        if !self.frame_buffered() && !poll_one(self.fd.as_raw_fd(), libc::POLLIN, wait)? {
            return Ok(Received::Idle);
        }
        let open = self.fill()?;
        match self.take_frame()? {
            Some(frame) => {
                let envelope: Envelope<T> =
                    serde_json::from_slice(&frame).map_err(io::Error::other)?;
                Ok(Received::Message {
                    id: envelope.id,
                    deadline_ns: envelope.deadline_ns,
                    body: envelope.body,
                })
            }
            None if open => Ok(Received::Idle),
            None => Ok(Received::Closed),
        }
    }

    /// Sends one frame under an absolute bound; a peer that never reads cannot pin
    /// this process, because the worker gives the frame up instead.
    pub fn send<T: Serialize>(&mut self, id: u64, body: &T, within: Duration) -> io::Result<()> {
        let end = std::time::Instant::now() + within;
        if !self.unsent.is_empty() {
            let tail = std::mem::take(&mut self.unsent);
            self.write_until(tail, end)?;
        }
        let frame = encode_frame(&Envelope {
            id,
            deadline_ns: 0,
            body,
        })?;
        self.write_until(frame, end)
    }

    fn write_until(&mut self, frame: Vec<u8>, end: std::time::Instant) -> io::Result<()> {
        let mut sent = 0;
        while sent < frame.len() {
            // SAFETY: the unsent suffix is readable and the descriptor is owned.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    frame[sent..].as_ptr().cast(),
                    frame.len() - sent,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if n >= 0 {
                sent += n as usize;
                continue;
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let left = end.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        // Nothing of an untouched frame is kept: it is simply dropped.
                        if sent > 0 {
                            self.unsent = frame[sent..].to_vec();
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "worker frame write deadline",
                        ));
                    }
                    poll_one(self.fd.as_raw_fd(), libc::POLLOUT, left)?;
                }
                _ => return Err(error),
            }
        }
        Ok(())
    }
}

fn poll_one(fd: RawFd, events: libc::c_short, wait: Duration) -> io::Result<bool> {
    let mut entry = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    poll_many(std::slice::from_mut(&mut entry), wait)?;
    Ok(entry.revents != 0)
}

fn poll_many(entries: &mut [libc::pollfd], wait: Duration) -> io::Result<()> {
    let millis = wait.as_millis().min(60_000) as libc::c_int;
    // SAFETY: entries is a live writable array of the stated length.
    let rc = unsafe { libc::poll(entries.as_mut_ptr(), entries.len() as _, millis) };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

/// One attachment's admission authority: a slot in the shared table and the generation
/// it must still hold. Internal to H and L; no request or peer ever names one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAuthority {
    pub slot: u32,
    pub generation: u64,
}

/// The value of a slot with no admission-capable attachment.
const REVOKED: u64 = 0;

/// Per-instance admission generations in a shared anonymous page, mapped before any
/// fork, so every L inherits it. H revokes with one atomic store, whatever L is doing;
/// L reads it at the commit point. The mapping stays for the life of the process tree.
pub struct RevocationTable {
    slots: *const AtomicU64,
    len: usize,
}

// SAFETY: the pointer stays valid forever and only atomics are accessed through it.
unsafe impl Send for RevocationTable {}
// SAFETY: as above; AtomicU64 is safe to share.
unsafe impl Sync for RevocationTable {}

impl std::fmt::Debug for RevocationTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationTable")
            .field("len", &self.len)
            .finish()
    }
}

impl RevocationTable {
    pub fn new(len: usize) -> io::Result<Self> {
        let bytes = len
            .checked_mul(std::mem::size_of::<AtomicU64>())
            .filter(|bytes| *bytes > 0)
            .ok_or_else(|| io::Error::other("invalid revocation table size"))?;
        // SAFETY: a fresh anonymous shared mapping, zeroed by the kernel: all REVOKED.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            slots: mapping.cast(),
            len,
        })
    }

    fn slot(&self, slot: u32) -> Option<&AtomicU64> {
        // SAFETY: the index is in bounds of the live mapping, and zeroed memory is a
        // valid AtomicU64.
        ((slot as usize) < self.len).then(|| unsafe { &*self.slots.add(slot as usize) })
    }

    /// Publishes a slot's current generation.
    pub fn publish(&self, slot: u32, generation: u64) {
        if let Some(cell) = self.slot(slot) {
            cell.store(generation, Ordering::SeqCst);
        }
    }

    /// Whether this exact authority is still current. An out-of-range slot never is.
    pub fn is_current(&self, authority: &AdmissionAuthority) -> bool {
        authority.generation != REVOKED
            && self
                .slot(authority.slot)
                .is_some_and(|cell| cell.load(Ordering::SeqCst) == authority.generation)
    }

    pub fn revoke(&self, slot: u32) {
        self.publish(slot, REVOKED);
    }
}

/// Why a worker call has no answer. None of these is evidence about the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The bounded queue is full; nothing was sent.
    Full,
    /// The worker process is gone, with or without having acted on the request.
    Closed,
    /// The reply did not decode: a protocol fault, treated as no answer.
    Protocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Normal,
    Reserved,
    Attach,
}

struct PendingCall {
    reply: oneshot::Sender<Result<Value, CallError>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// H's end of a worker socket. Reader and writer are separate tasks, so abandoning a
/// waiter can never split a frame. A permit stays held until the worker actually
/// answers, which keeps the queue bound honest while the worker is stalled.
pub struct Channel {
    writer: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<HashMap<u64, PendingCall>>>,
    next_id: AtomicU64,
    normal: Arc<Semaphore>,
    reserved: Arc<Semaphore>,
    attach: Arc<Semaphore>,
    closed: CancellationToken,
}

impl Channel {
    /// Spawns the I/O tasks. Unsolicited events arrive on the returned receiver.
    pub fn spawn(
        stream: std::os::unix::net::UnixStream,
        normal: usize,
        reserved: usize,
    ) -> io::Result<(Arc<Self>, mpsc::Receiver<Value>)> {
        Self::spawn_with_attach(stream, normal, reserved, 0)
    }

    /// L's channel, which alone has an attachment lane.
    pub fn spawn_with_attach(
        stream: std::os::unix::net::UnixStream,
        normal: usize,
        reserved: usize,
        attach: usize,
    ) -> io::Result<(Arc<Self>, mpsc::Receiver<Value>)> {
        stream.set_nonblocking(true)?;
        let stream = crate::helper::socket::Socket(UnixStream::from_std(stream)?);
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (writer, mut outgoing) =
            mpsc::channel::<Vec<u8>>((normal + reserved + attach).max(4) + 8);
        let (event_tx, events) = mpsc::channel(64);
        let pending: Arc<Mutex<HashMap<u64, PendingCall>>> = Arc::default();
        let closed = CancellationToken::new();
        let channel = Arc::new(Self {
            writer,
            pending: pending.clone(),
            next_id: AtomicU64::new(1),
            normal: Arc::new(Semaphore::new(normal)),
            reserved: Arc::new(Semaphore::new(reserved)),
            attach: Arc::new(Semaphore::new(attach)),
            closed: closed.clone(),
        });
        {
            let closed = closed.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = closed.cancelled() => break,
                        frame = outgoing.recv() => {
                            let Some(frame) = frame else { break };
                            if write_half.write_all(&frame).await.is_err() {
                                closed.cancel();
                                break;
                            }
                        }
                    }
                }
            });
        }
        tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = closed.cancelled() => break,
                    frame = read_frame(&mut read_half) => frame,
                };
                let Ok(frame) = frame else { break };
                let Ok(envelope) = serde_json::from_slice::<Envelope<Value>>(&frame) else {
                    break;
                };
                if envelope.id == 0 {
                    // A full event queue drops only that event; evidence always
                    // comes again from the process table or a later report.
                    let _ = event_tx.try_send(envelope.body);
                } else if let Some(call) = pending.lock().unwrap().remove(&envelope.id) {
                    let _ = call.reply.send(Ok(envelope.body));
                }
            }
            closed.cancel();
            // Every unanswered call learns the process is gone.
            let drained: Vec<_> = pending.lock().unwrap().drain().collect();
            for (_, call) in drained {
                let _ = call.reply.send(Err(CallError::Closed));
            }
        });
        Ok((channel, events))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub async fn closed(&self) {
        self.closed.cancelled().await
    }

    pub fn close(&self) {
        self.closed.cancel();
    }

    /// Sends a request and waits for the worker. The future itself has no deadline:
    /// a waiter that gives up leaves the call owned, and its permit, until it settles.
    pub async fn call<Rep: DeserializeOwned>(
        &self,
        lane: Lane,
        body: &impl Serialize,
        deadline_ns: u64,
    ) -> Result<Rep, CallError> {
        let permit = match lane {
            Lane::Normal => self.normal.clone().try_acquire_owned(),
            Lane::Reserved => self
                .reserved
                .clone()
                .try_acquire_owned()
                .or_else(|_| self.normal.clone().try_acquire_owned()),
            Lane::Attach => self.attach.clone().try_acquire_owned(),
        }
        .map_err(|_| CallError::Full)?;
        if self.is_closed() {
            return Err(CallError::Closed);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = encode_frame(&Envelope {
            id,
            deadline_ns,
            body,
        })
        .map_err(|_| CallError::Protocol)?;
        let (reply, answer) = oneshot::channel();
        self.pending.lock().unwrap().insert(
            id,
            PendingCall {
                reply,
                _permit: permit,
            },
        );
        if self.writer.try_send(frame).is_err() {
            self.pending.lock().unwrap().remove(&id);
            return Err(CallError::Full);
        }
        if self.is_closed() {
            self.pending.lock().unwrap().remove(&id);
            return Err(CallError::Closed);
        }
        let value = answer.await.map_err(|_| CallError::Closed)??;
        serde_json::from_value(value).map_err(|_| CallError::Protocol)
    }

    /// One unacknowledged message, dropped rather than queued if the worker is behind.
    pub fn notify(&self, body: &impl Serialize) -> bool {
        match encode_frame(&Envelope {
            id: 0,
            deadline_ns: 0,
            body,
        }) {
            Ok(frame) => self.writer.try_send(frame).is_ok(),
            Err(_) => false,
        }
    }
}

async fn read_frame(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let size = reader.read_u32().await? as usize;
    if size == 0 || size > MAX_IPC_FRAME {
        return Err(io::Error::other("worker frame size exceeded"));
    }
    let mut frame = vec![0; size];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

// Process identity, used only inside workers, never on H.

/// A process and when it began. A PID alone is never used to signal anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessId {
    pub pid: i32,
    pub start_time: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Gone,
    Zombie,
    Running { start_time: u64 },
}

#[cfg(target_os = "linux")]
pub fn process_state(pid: i32) -> ProcessState {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return ProcessState::Gone;
    };
    // The command name can hold spaces and parentheses: parse after the last ')'.
    let Some(tail) = stat.rfind(')').map(|at| &stat[at + 1..]) else {
        return ProcessState::Gone;
    };
    let fields: Vec<&str> = tail.split_whitespace().collect();
    match (fields.first(), fields.get(19).and_then(|f| f.parse().ok())) {
        (Some(&"Z"), _) | (Some(&"X"), _) => ProcessState::Zombie,
        (_, Some(start_time)) => ProcessState::Running { start_time },
        _ => ProcessState::Gone,
    }
}

#[cfg(target_os = "macos")]
pub fn process_state(pid: i32) -> ProcessState {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: info is writable and exactly the size given.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if n != size {
        // A zombie has no BSD info on macOS, but still answers kill(pid, 0).
        // SAFETY: signal 0 only checks for existence.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return ProcessState::Zombie;
        }
        return ProcessState::Gone;
    }
    if info.pbi_status == libc::SZOMB {
        return ProcessState::Zombie;
    }
    ProcessState::Running {
        start_time: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
    }
}

/// The path a fixture peer runs from, for the test-only enrollment above.
#[cfg(all(test, target_os = "linux"))]
fn test_process_image(pid: i32) -> std::path::PathBuf {
    std::fs::read_link(format!("/proc/{pid}/exe")).expect("the fixture peer's image")
}

#[cfg(all(test, target_os = "macos"))]
fn test_process_image(pid: i32) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: path is writable and exactly the size given.
    let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    assert!(len > 0, "the fixture peer's image");
    path.truncate(len as usize);
    std::ffi::OsStr::from_bytes(&path).into()
}

/// Host boot identity: a changed value invalidates every recorded PID.
#[cfg(target_os = "linux")]
pub fn host_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|id| id.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(target_os = "macos")]
pub fn host_boot_id() -> String {
    let mut boot: libc::timeval = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::timeval>();
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    // SAFETY: mib and output pointers are live and exactly sized.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut boot as *mut libc::timeval).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 {
        format!("boot-{}", boot.tv_sec)
    } else {
        "unknown".into()
    }
}

/// Starts one fork-only worker: it keeps only `keep`, never returns to the caller's
/// stack and cannot unwind into it. It inherits the verified helper image.
pub fn spawn_process(keep: &[RawFd], body: impl FnOnce()) -> io::Result<i32> {
    // SAFETY: H and the fixture processes fork from a single-threaded runtime; the
    // child immediately closes inherited descriptors and resets signal dispositions.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        return Ok(pid);
    }
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGCHLD, libc::SIGHUP] {
            // SAFETY: restoring a default disposition in the new process.
            unsafe { libc::signal(signal, libc::SIG_DFL) };
        }
        // SAFETY: SIGPIPE would otherwise end a worker on a dead peer's write.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        executable::close_all_except(keep);
        body();
    }));
    // SAFETY: skip the parent's destructors and runtime; this process only exits.
    unsafe { libc::_exit(if code.is_ok() { 0 } else { 101 }) }
}

/// Reaps one exact child if it has exited. Never blocks and never waits on others.
pub fn try_reap(pid: i32) -> Option<String> {
    let mut status = 0;
    // SAFETY: status is writable; WNOHANG returns at once.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if rc == pid {
        Some(if libc::WIFEXITED(status) {
            format!("exit:{}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("signal:{}", libc::WTERMSIG(status))
        } else {
            "stopped".into()
        })
    } else if rc < 0 {
        Some("not-a-child".into())
    } else {
        None
    }
}

/// A nonblocking datagram ping. A stalled worker sends none, which M notices.
pub struct Heartbeat {
    socket: UnixDatagram,
    last: std::time::Instant,
    every: Duration,
}

impl Heartbeat {
    pub fn new(socket: UnixDatagram, every: Duration) -> Self {
        let _ = socket.set_nonblocking(true);
        Self {
            socket,
            last: std::time::Instant::now() - every,
            every,
        }
    }

    pub fn beat(&mut self) {
        if self.last.elapsed() >= self.every {
            // SAFETY: the byte is readable and the descriptor is owned.
            unsafe {
                libc::send(
                    self.socket.as_raw_fd(),
                    b"h".as_ptr().cast(),
                    1,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            self.last = std::time::Instant::now();
        }
    }
}

/// Timer settings. Production uses the design's values; tests may only widen them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timings {
    pub tick: Duration,
    pub heartbeat: Duration,
    pub heartbeat_timeout: Duration,
    /// How long startup retries its infrastructure rows before giving up on serving.
    pub startup_journal: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            tick: Duration::from_millis(100),
            heartbeat: Duration::from_millis(250),
            heartbeat_timeout: Duration::from_secs(1),
            startup_journal: Duration::from_secs(30),
        }
    }
}

/// One profile with its retained executable table, verified before serving.
#[derive(Debug)]
pub struct ProfileRuntime {
    pub catalog: ProfileCatalog,
    pub table: ExecutableTable,
    pub pins: Value,
    pub manifest_sha256: Digest,
}

/// What a test may inject. This whole struct is absent from production builds.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct TestInjection {
    pub effects: Vec<FakeEffect>,
    pub fake_root: Option<std::path::PathBuf>,
    /// Root's enrollment, done on first attach, for tests about something else.
    pub auto_enroll: bool,
    pub peers: super::peer::TestPeers,
}

/// Fake side effects, performed for real by S under its permit: an owned file or a
/// real child process standing in for the VM subtree. No VM, jail or cgroup.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeEffect {
    Marker(String),
    Vm,
}

/// Everything a forked worker needs, inherited as memory. Never serialized, so no
/// request or peer can supply any of it.
#[derive(Debug)]
pub struct NodeConfig {
    pub node_id: Id128,
    pub ledger: LedgerConfig,
    pub ranges: IdentityRanges,
    pub profiles: Vec<ProfileRuntime>,
    pub walk: WalkPolicy,
    pub gate: ManifestGate,
    pub observation: ObservationBackend,
    pub timings: Timings,
    /// The verified image every fork-only worker inherits, when a profile pins it.
    pub helper_image: Option<ExecutableIdentity>,
    /// The kilnd account an attached peer must run as.
    pub service_uid: u32,
    /// Root policy's total of enrolled instances, which sizes each instance's share.
    pub max_enrolled: u32,
    #[cfg(test)]
    pub test: TestInjection,
}

impl NodeConfig {
    /// Every descriptor a worker needs to use the retained tables.
    pub fn table_fds(&self) -> Vec<RawFd> {
        self.profiles
            .iter()
            .flat_map(|profile| profile.table.raw_fds())
            .collect()
    }

    pub fn profile(&self, name: &str) -> Option<&ProfileRuntime> {
        self.profiles.iter().find(|p| p.catalog.profile == name)
    }
}

// L: the ledger process.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LedgerRequest {
    Attach {
        instance: Id128,
        database_uuid: Id128,
        peer_pid: i32,
    },
    /// Root's enrollment, for fixtures testing something other than enrollment. It
    /// enrolls the peer's real image. Production enrolls only from the root command.
    #[cfg(test)]
    TestEnroll {
        instance: Id128,
        peer_pid: i32,
    },
    Lookup {
        instance: Id128,
        allocation: Id128,
        plan_digest: Digest,
    },
    NeverAdmittedFenceAllowed {
        instance: Id128,
    },
    Inspect {
        instance: Id128,
        allocation: Id128,
    },
    PreflightSnapshot {
        instance: Id128,
        allocation: Id128,
    },
    Admit {
        request: Box<AdmitRequest>,
        authority: AdmissionAuthority,
    },
    RecordWorker {
        worker_id: i64,
        pid: i32,
    },
    RecordInfrastructure {
        spec: Box<WorkerIntentSpec>,
        pid: i32,
    },
    /// A replacement's intent, journaled before it is forked.
    InfrastructureIntent {
        spec: Box<WorkerIntentSpec>,
    },
    RecordChild {
        allocation: Id128,
        spec: Box<WorkerIntentSpec>,
        target: ProcessId,
    },
    AdvancePhase {
        allocation: Id128,
        expected_generation: u64,
        phase: String,
    },
    RecordStop {
        allocation: Id128,
        reason: String,
    },
    RecordObserved {
        allocation: Id128,
        actual: ExecutableIdentity,
    },
    Settle {
        worker_id: i64,
        settlement: String,
    },
    SettleUnstarted {
        allocation: Id128,
    },
    Fence(Box<FenceRequest>),
    Accounting,
    Inventory {
        instance: Id128,
    },
    Replay,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LedgerReply {
    /// No authority exists: missing, corrupt or unsafe. Never an empty answer.
    Unavailable {
        reason: String,
    },
    /// The request's original deadline passed before L began it. Nothing changed.
    Expired,
    Attached {
        outcome: AttachOutcome,
        peer_start: u64,
    },
    /// The peer is not the enrolled service, or the instance isn't enrolled.
    AttachRefused {
        reason: String,
    },
    Lookup(TokenLookup),
    NeverAdmittedFenceAllowed(bool),
    PreflightSnapshot {
        claimed: ClaimedIdentities,
        retired_or_active: bool,
        headroom: bool,
    },
    Admit(AdmitOutcome),
    Identity {
        start_time: u64,
        host_boot_id: String,
    },
    Worker {
        worker_id: i64,
    },
    Generation(u64),
    Done,
    Fence(FenceOutcome),
    Accounting(Box<AccountingSnapshot>),
    Inventory(InventorySnapshot),
    Replay(Box<ReplaySnapshot>),
    Failed {
        reason: String,
    },
}

fn handle_ledger(
    ledger: &mut Ledger,
    attestor: &mut PeerAttestor,
    revocations: &RevocationTable,
    request: LedgerRequest,
) -> Result<LedgerReply, LedgerError> {
    Ok(match request {
        LedgerRequest::Attach {
            instance,
            database_uuid,
            peer_pid,
        } => {
            let Some(enrollment) = ledger.enrollment(instance)? else {
                return Ok(LedgerReply::AttachRefused {
                    reason: "this instance is not enrolled".into(),
                });
            };
            // The proof comes first. A refused peer never reaches any write.
            let peer_start = match attestor.attest(peer_pid, &enrollment) {
                Ok(start) => start,
                Err(refusal) => {
                    return Ok(LedgerReply::AttachRefused {
                        reason: refusal.to_string(),
                    });
                }
            };
            LedgerReply::Attached {
                outcome: ledger.attach_instance(instance, database_uuid)?,
                peer_start,
            }
        }
        #[cfg(test)]
        LedgerRequest::TestEnroll { instance, peer_pid } => {
            let path = test_process_image(peer_pid);
            let meta = std::fs::metadata(&path).expect("the fixture peer's image");
            use std::os::unix::fs::MetadataExt;
            let unit = format!("fixture-{instance}.service");
            let enrollment = super::peer::Enrollment {
                instance_id: instance,
                cgroup: format!("/fixture.slice/{unit}"),
                unit,
                executable: super::peer::EnrolledExecutable {
                    st_dev: meta.dev(),
                    st_ino: meta.ino(),
                    bytes: meta.len(),
                    sha256: super::peer::fixture_digest(),
                },
            };
            ledger.enroll_instance(&enrollment, super::config::MAX_ENROLLED_HARD)?;
            LedgerReply::Done
        }
        LedgerRequest::Lookup {
            instance,
            allocation,
            plan_digest,
        } => LedgerReply::Lookup(ledger.lookup_token(instance, allocation, &plan_digest)?),
        LedgerRequest::NeverAdmittedFenceAllowed { instance } => {
            LedgerReply::NeverAdmittedFenceAllowed(ledger.never_admitted_fence_allowed(instance)?)
        }
        LedgerRequest::Inspect {
            instance,
            allocation,
        } => LedgerReply::Lookup(ledger.inspect(instance, allocation)?),
        LedgerRequest::PreflightSnapshot {
            instance,
            allocation,
        } => LedgerReply::PreflightSnapshot {
            claimed: ledger.claimed_identities()?,
            retired_or_active: !matches!(
                ledger.inspect(instance, allocation)?,
                TokenLookup::Unknown
            ),
            headroom: ledger.fence_headroom()? && ledger.pre_intent_headroom(instance)?,
        },
        LedgerRequest::Admit { request, authority } => {
            fault_point("L.admit");
            let authorized = || revocations.is_current(&authority);
            LedgerReply::Admit(ledger.admit_intent_authorized(&request, &authorized)?)
        }
        LedgerRequest::RecordWorker { worker_id, pid } => {
            let ProcessState::Running { start_time } = process_state(pid) else {
                return Ok(LedgerReply::Failed {
                    reason: "worker exited before its identity was recorded".into(),
                });
            };
            let host_boot_id = host_boot_id();
            ledger.record_worker_identity(worker_id, pid, start_time, &host_boot_id)?;
            LedgerReply::Identity {
                start_time,
                host_boot_id,
            }
        }
        LedgerRequest::RecordInfrastructure { spec, pid } => {
            if fault_enabled("L.record_infrastructure.fail") {
                return Ok(LedgerReply::Failed {
                    reason: "injected infrastructure journal failure".into(),
                });
            }
            let ProcessState::Running { start_time } = process_state(pid) else {
                return Ok(LedgerReply::Failed {
                    reason: "worker exited before its identity was recorded".into(),
                });
            };
            let worker_id =
                ledger.record_infrastructure_worker(&spec, pid, start_time, &host_boot_id())?;
            LedgerReply::Worker { worker_id }
        }
        LedgerRequest::InfrastructureIntent { spec } => LedgerReply::Worker {
            worker_id: ledger.record_infrastructure_intent(&spec)?,
        },
        LedgerRequest::RecordChild {
            allocation,
            spec,
            target,
        } => {
            let id = ledger.record_child_worker(
                allocation,
                &spec,
                target.pid,
                target.start_time,
                &host_boot_id(),
            )?;
            LedgerReply::Generation(id as u64)
        }
        LedgerRequest::AdvancePhase {
            allocation,
            expected_generation,
            phase,
        } => LedgerReply::Generation(ledger.advance_phase(
            allocation,
            expected_generation,
            &phase,
        )?),
        LedgerRequest::RecordStop { allocation, reason } => {
            LedgerReply::Generation(ledger.record_stop(allocation, &reason)?)
        }
        LedgerRequest::RecordObserved { allocation, actual } => {
            ledger.record_observed_executable(allocation, &actual)?;
            LedgerReply::Done
        }
        LedgerRequest::Settle {
            worker_id,
            settlement,
        } => {
            if fault_enabled("L.settle.fail") {
                return Ok(LedgerReply::Failed {
                    reason: "injected settlement failure".into(),
                });
            }
            ledger.settle_worker(worker_id, &settlement)?;
            LedgerReply::Done
        }
        LedgerRequest::SettleUnstarted { allocation } => {
            ledger.settle_unstarted(allocation)?;
            LedgerReply::Done
        }
        LedgerRequest::Fence(request) => {
            fault_point("L.fence");
            LedgerReply::Fence(ledger.commit_fence(&request)?)
        }
        LedgerRequest::Accounting => LedgerReply::Accounting(Box::new(ledger.accounting()?)),
        LedgerRequest::Inventory { instance } => {
            LedgerReply::Inventory(ledger.inventory(instance)?)
        }
        LedgerRequest::Replay => LedgerReply::Replay(Box::new(ledger.replay()?)),
    })
}

/// A failure in the ledger itself: refusing the request keeps claims held.
fn ledger_failure(error: LedgerError) -> LedgerReply {
    LedgerReply::Failed {
        reason: error.to_string(),
    }
}

/// L: one fixed process and the sole SQLite owner. Requests run strictly in order,
/// so a stalled fsync delays durable answers for every allocation and nothing else.
pub fn ledger_main(
    mut endpoint: Endpoint,
    config: LedgerConfig,
    mut attestor: PeerAttestor,
    mut heartbeat: Heartbeat,
    revocations: Arc<RevocationTable>,
    expiring: fn(&LedgerRequest) -> bool,
) {
    let mut ledger = Ledger::open(config);
    loop {
        heartbeat.beat();
        fault_point("L.loop");
        let message = endpoint.receive::<LedgerRequest>(Duration::from_millis(50));
        let (id, deadline_ns, request) = match message {
            Ok(Received::Message {
                id,
                deadline_ns,
                body,
            }) => (id, deadline_ns, body),
            Ok(Received::Idle) => continue,
            Ok(Received::Closed) | Err(_) => return,
        };
        let reply = match &mut ledger {
            Err(error) => LedgerReply::Unavailable {
                reason: error.to_string(),
            },
            Ok(_) if expiring(&request) && monotonic_ns() >= deadline_ns => LedgerReply::Expired,
            Ok(ledger) => handle_ledger(ledger, &mut attestor, &revocations, request)
                .unwrap_or_else(ledger_failure),
        };
        fault_point("L.reply");
        if endpoint.send(id, &reply, Duration::from_secs(5)).is_err() {
            return;
        }
    }
}

/// Requests that may begin only inside their original wire deadline. C3's identity and
/// PREPARING records are forward authority too: cleanup records have their own lanes.
pub fn ledger_request_expires(request: &LedgerRequest) -> bool {
    matches!(
        request,
        LedgerRequest::Admit { .. }
            | LedgerRequest::Fence(_)
            | LedgerRequest::Attach { .. }
            | LedgerRequest::RecordWorker { .. }
            | LedgerRequest::AdvancePhase { .. }
    )
}

// P: preparation.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PrepRequest {
    Preflight {
        instance: Id128,
        allocation: Id128,
        sandbox_id: String,
        profile: String,
        spec: SandboxSpec,
        claimed: ClaimedIdentities,
    },
    Revalidate {
        instance: Id128,
        allocation: Id128,
        sandbox_id: String,
        plan: Vec<u8>,
        plan_digest: Digest,
    },
    ObserveAllocation {
        instance: Id128,
        allocation: Id128,
    },
    ObserveNode {
        instance: Id128,
    },
    VerifyLeases {
        expected: Vec<ExecutableIdentity>,
    },
}

/// Facts recomputed from verified plan bytes, for the C2 transaction.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidatedPlan {
    pub profile: String,
    pub manifest_sha256: Digest,
    pub host_spec_sha256: Digest,
    pub guest_exec_spec_sha256: Digest,
    pub reservation: ResourceReservation,
    pub leases: IdentityLeases,
    pub work_uuid: String,
    pub executables: Vec<ExecutableIdentity>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PrepReply {
    Prepared(Box<PreparedReply>),
    /// A C0 refusal: nothing was created and no row should exist.
    Refused {
        reason: String,
    },
    Revalidated(Box<RevalidatedPlan>),
    Rejected {
        class: AmbiguousClass,
        reason: String,
        /// The plan failed its own bytes or its binding to this token. A daemon verifies
        /// both before C1, so this token cannot be one it holds a charge for.
        malformed: bool,
    },
    Allocation(NamespaceObservation),
    Node(NodeObservation),
    LeasesVerified,
    LeasesRefused {
        reason: String,
    },
}

fn expected_plan_shape(config: &NodeConfig, plan: &ExactPlan) -> Result<&'static str, String> {
    let profile = config
        .profile(&plan.inputs.profile)
        .ok_or("plan names a profile this helper does not serve")?;
    if plan.inputs.manifest_sha256 != profile.manifest_sha256 {
        return Err("plan names a different approved manifest".into());
    }
    if plan.inputs.catalog_generation != profile.catalog.catalog_generation {
        return Err("plan names a stale catalog generation".into());
    }
    if !config.ranges.contains(&plan.inputs.leases) {
        return Err("plan identities are outside the configured ranges".into());
    }
    Ok("ok")
}

/// Reads and verifies the manifest and every artifact through a fresh protected walk.
fn verify_bundle(
    config: &NodeConfig,
    profile: &ProfileRuntime,
) -> Result<manifest::VerifiedManifest, String> {
    let bundle = executable::walk_directory(&config.walk, &profile.catalog.bundle_directory)
        .map_err(|e| e.to_string())?;
    let raw = manifest::read_manifest(&bundle, config.walk.owner_uid)?;
    let verified =
        manifest::verify_manifest(&raw, &profile.catalog.approved_manifest_sha256, config.gate)?;
    manifest::verify_artifacts(&bundle, config.walk.owner_uid, &verified)?;
    Ok(verified)
}

fn preflight_job(
    config: &NodeConfig,
    instance: Id128,
    allocation: Id128,
    sandbox_id: String,
    profile_name: String,
    spec: SandboxSpec,
    claimed: &ClaimedIdentities,
) -> Result<PreparedReply, String> {
    let profile = config
        .profile(&profile_name)
        .ok_or_else(|| format!("profile {profile_name} is not approved on this node"))?;
    fault_point("P.preflight");
    let verified = verify_bundle(config, profile)?;
    if verified.sha256 != profile.manifest_sha256 {
        return Err("catalog changed since startup; revalidation is required".into());
    }
    let vector = profile.table.vector();
    profile
        .table
        .revalidate(&vector)
        .map_err(|e| e.to_string())?;
    let mut entropy_failed = false;
    let mut entropy = || {
        identity::random_u32().unwrap_or_else(|_| {
            entropy_failed = true;
            0
        })
    };
    let leases = identity::select_candidates(&config.ranges, claimed, &mut entropy)?;
    if entropy_failed {
        return Err("no entropy available".into());
    }
    let plan = config::build_plan(PlanInputs {
        node_id: config.node_id,
        instance_id: instance,
        allocation_id: allocation,
        sandbox_id,
        profile: profile_name.clone(),
        manifest_sha256: profile.manifest_sha256,
        catalog_generation: profile.catalog.catalog_generation,
        spec,
        leases,
        boot_nonce: identity::new_boot_nonce().map_err(|e| e.to_string())?,
        work_uuid: identity::new_work_uuid().map_err(|e| e.to_string())?,
        executables: vector,
        pins: profile.pins.clone(),
    })?;
    Ok(PreparedReply {
        node_id: config.node_id,
        profile: profile_name,
        manifest_sha256: profile.manifest_sha256,
        plan_version: config::PLAN_VERSION,
        plan_digest: plan.digest,
        host_spec_sha256: plan.host_spec_sha256,
        guest_exec_spec_sha256: plan.guest_exec_spec_sha256,
        reservation: plan.reservation,
        plan: WireBytes(plan.bytes),
    })
}

struct RevalidateRefusal {
    reason: String,
    malformed: bool,
}

fn revalidate_job(
    config: &NodeConfig,
    instance: Id128,
    allocation: Id128,
    sandbox_id: &str,
    plan: &[u8],
    plan_digest: &Digest,
) -> Result<RevalidatedPlan, RevalidateRefusal> {
    fault_point("P.revalidate");
    let plan = config::verify_plan_bytes(
        plan,
        plan_digest,
        config.node_id,
        instance,
        allocation,
        sandbox_id,
    )
    .map_err(|reason| RevalidateRefusal {
        reason,
        malformed: true,
    })?;
    let current = |reason| RevalidateRefusal {
        reason,
        malformed: false,
    };
    expected_plan_shape(config, &plan).map_err(current)?;
    let profile = config.profile(&plan.inputs.profile).expect("just checked");
    verify_bundle(config, profile).map_err(current)?;
    profile
        .table
        .revalidate(&plan.inputs.executables)
        .map_err(|e| current(e.to_string()))?;
    Ok(RevalidatedPlan {
        profile: plan.inputs.profile.clone(),
        manifest_sha256: plan.inputs.manifest_sha256,
        host_spec_sha256: plan.host_spec_sha256,
        guest_exec_spec_sha256: plan.guest_exec_spec_sha256,
        reservation: plan.reservation,
        leases: plan.inputs.leases,
        work_uuid: plan.inputs.work_uuid.clone(),
        executables: plan.inputs.executables.clone(),
    })
}

/// A restart reopens exactly the journal's tuples by protected traversal. Same bytes
/// at a new inode, and any other change, refuses: there is no pathname fallback.
fn verify_leases(config: &NodeConfig, expected: &[ExecutableIdentity]) -> Result<(), String> {
    let mut by_role: BTreeMap<Role, Vec<ExecutableIdentity>> = BTreeMap::new();
    for identity in expected {
        by_role.entry(identity.role).or_default().push(*identity);
    }
    for identities in by_role.values() {
        for identity in identities {
            let matched = config.profiles.iter().any(|profile| {
                executable::ExecutableTable::reopen_exact(
                    config.walk.clone(),
                    &profile.catalog.exec_store,
                    &[*identity],
                )
                .is_ok()
            });
            if !matched {
                return Err(format!(
                    "journaled {} tuple can no longer be reopened exactly",
                    identity.role.as_str()
                ));
            }
        }
    }
    Ok(())
}

/// P: one of two fixed job slots. Read-only: it can hash and read owned namespaces
/// but has no ledger, no write path and no session side effect.
pub fn prep_main(mut endpoint: Endpoint, config: Arc<NodeConfig>, mut heartbeat: Heartbeat) {
    loop {
        heartbeat.beat();
        fault_point("P.loop");
        let (id, deadline_ns, request) =
            match endpoint.receive::<PrepRequest>(Duration::from_millis(50)) {
                Ok(Received::Message {
                    id,
                    deadline_ns,
                    body,
                }) => (id, deadline_ns, body),
                Ok(Received::Idle) => continue,
                Ok(Received::Closed) | Err(_) => return,
            };
        let expired = monotonic_ns() >= deadline_ns;
        let reply = match request {
            PrepRequest::Preflight { .. } if expired => PrepReply::Refused {
                reason: "preflight deadline expired".into(),
            },
            PrepRequest::Revalidate { .. } if expired => PrepReply::Rejected {
                class: AmbiguousClass::Expired,
                reason: "create deadline expired before revalidation".into(),
                malformed: false,
            },
            PrepRequest::Preflight {
                instance,
                allocation,
                sandbox_id,
                profile,
                spec,
                claimed,
            } => match preflight_job(
                &config, instance, allocation, sandbox_id, profile, spec, &claimed,
            ) {
                Ok(prepared) => PrepReply::Prepared(Box::new(prepared)),
                Err(reason) => PrepReply::Refused { reason },
            },
            PrepRequest::Revalidate {
                instance,
                allocation,
                sandbox_id,
                plan,
                plan_digest,
            } => match revalidate_job(
                &config,
                instance,
                allocation,
                &sandbox_id,
                &plan,
                &plan_digest,
            ) {
                Ok(plan) => PrepReply::Revalidated(Box::new(plan)),
                Err(refusal) => PrepReply::Rejected {
                    class: AmbiguousClass::CatalogMismatch,
                    reason: refusal.reason,
                    malformed: refusal.malformed,
                },
            },
            PrepRequest::ObserveAllocation {
                instance,
                allocation,
            } => {
                fault_point("P.observe");
                PrepReply::Allocation(config.observation.observe_allocation(instance, allocation))
            }
            PrepRequest::ObserveNode { instance } => {
                fault_point("P.observe");
                PrepReply::Node(config.observation.observe_node(instance))
            }
            PrepRequest::VerifyLeases { expected } => match verify_leases(&config, &expected) {
                Ok(()) => PrepReply::LeasesVerified,
                Err(reason) => PrepReply::LeasesRefused { reason },
            },
        };
        if endpoint.send(id, &reply, Duration::from_secs(5)).is_err() {
            return;
        }
    }
}

// S: one lifecycle supervisor per accepted allocation.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorCommand {
    /// The journaled permit. S does nothing before this; EOF instead means no effect.
    OpenGate {
        operation_generation: u64,
        allowed_names: Vec<String>,
        expected: Vec<ExecutableIdentity>,
        /// The original Create deadline: start authority for every forward effect ends
        /// here, whatever the waiter or this process is doing.
        deadline_ns: u64,
    },
    /// A fence revoked every future permit: stop and exit.
    Revoke,
    Tick,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorEvent {
    ExecObserved(ExecObservation),
    ExecRefused {
        role: Role,
        reason: String,
    },
    VmStarted(ProcessId),
    EffectsDone,
    /// Forward setup ran out of its original deadline. S stops here with nothing further.
    SetupExpired,
}

/// What a supervisor owns besides itself. It reaches other processes only through
/// its pair of sockets and retained tables.
pub struct SupervisorContext {
    pub config: Arc<NodeConfig>,
    pub instance: Id128,
    pub allocation: Id128,
    pub profile: String,
    pub control: Endpoint,
    /// Heartbeats to M. Its EOF is how M learns S is gone.
    pub watch: std::os::unix::net::UnixStream,
}

fn send_watch_byte(watch: &std::os::unix::net::UnixStream, byte: u8) {
    // SAFETY: the byte is readable and the socket is owned.
    unsafe {
        libc::send(
            watch.as_raw_fd(),
            [byte].as_ptr().cast(),
            1,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
}

/// The last step before dispatch: what would run is the retained descriptor, compared
/// with the plan's tuple. Reports both tuples; a difference runs nothing.
fn model_dispatch(
    config: &NodeConfig,
    profile: &str,
    expected: &[ExecutableIdentity],
) -> Vec<SupervisorEvent> {
    let Some(profile) = config.profile(profile) else {
        return vec![];
    };
    #[cfg(test)]
    {
        for role in Role::ALL {
            if fault_enabled(&format!("S.reuse_fd.{}", role.as_str()))
                && let Some(fd) = profile.table.raw_fd(role)
            {
                // Models a close-and-reuse: the number now names another open file.
                let devnull = c"/dev/null";
                // SAFETY: test-only; dup2 atomically replaces this process's copy.
                unsafe {
                    let other = libc::open(devnull.as_ptr(), libc::O_RDONLY);
                    libc::dup2(other, fd);
                    libc::close(other);
                }
            }
        }
    }
    expected
        .iter()
        .map(|identity| match profile.table.model_execute(identity) {
            Ok(observation) => SupervisorEvent::ExecObserved(observation),
            Err(error) => SupervisorEvent::ExecRefused {
                role: identity.role,
                reason: error.to_string(),
            },
        })
        .collect()
}

/// S: gated, serialized, and the owner of this allocation's fake namespace. H's
/// heartbeat is fail-closed: if H stalls or dies, S stops its subtree and exits.
pub fn supervisor_main(mut context: SupervisorContext) {
    let timings = context.config.timings;
    let mut last_helper = std::time::Instant::now();
    let mut last_beat = std::time::Instant::now();
    #[allow(unused_mut, unused_variables)]
    let mut vm: Option<ProcessId> = None;
    let mut gated = true;
    #[cfg(test)]
    let mut setup_deadline_ns = u64::MAX;
    #[cfg(test)]
    let mut pending_effects: std::collections::VecDeque<FakeEffect> =
        std::collections::VecDeque::new();
    #[cfg(test)]
    let mut allowed: Vec<String> = Vec::new();
    loop {
        if last_beat.elapsed() >= timings.heartbeat {
            send_watch_byte(&context.watch, b'h');
            last_beat = std::time::Instant::now();
        }
        fault_point("S.loop");
        // Every queued command is read before the next effect: a Revoke behind Ticks
        // still stops it. The first read waits briefly and the rest do not.
        let mut wait = Duration::from_millis(10);
        loop {
            match context.control.receive::<SupervisorCommand>(wait) {
                Ok(Received::Message { body, .. }) => match body {
                    SupervisorCommand::Tick => last_helper = std::time::Instant::now(),
                    SupervisorCommand::Revoke => {
                        // The permit ends now: no later effect runs, and exiting is what
                        // settles it. Existing resources stay for positive observation.
                        send_watch_byte(&context.watch, b'E');
                        return;
                    }
                    SupervisorCommand::OpenGate {
                        allowed_names,
                        expected,
                        deadline_ns,
                        ..
                    } => {
                        last_helper = std::time::Instant::now();
                        if gated {
                            gated = false;
                            let _ = &allowed_names;
                            #[cfg(test)]
                            {
                                allowed = allowed_names;
                                setup_deadline_ns = deadline_ns;
                            }
                            fault_point("S.gate");
                            if monotonic_ns() >= deadline_ns {
                                report_setup_expired(&mut context);
                                return;
                            }
                            for event in
                                model_dispatch(&context.config, &context.profile, &expected)
                            {
                                let refused = matches!(event, SupervisorEvent::ExecRefused { .. });
                                let _ = context.control.send(0, &event, Duration::from_secs(1));
                                if refused {
                                    // Nothing further runs: this boot is contained and stays
                                    // charged. Exiting marks S lost, which fences it.
                                    return;
                                }
                            }
                            #[cfg(test)]
                            {
                                pending_effects =
                                    context.config.test.effects.iter().cloned().collect();
                            }
                        }
                    }
                },
                Ok(Received::Idle) => break,
                // H is gone. Contain and exit; the ledger still holds everything.
                Ok(Received::Closed) | Err(_) => {
                    stop_vm(&vm);
                    send_watch_byte(&context.watch, b'E');
                    return;
                }
            }
            wait = Duration::ZERO;
        }
        if !gated && last_helper.elapsed() >= timings.heartbeat_timeout {
            stop_vm(&vm);
            send_watch_byte(&context.watch, b'E');
            return;
        }
        #[cfg(test)]
        if let Some(effect) = pending_effects.pop_front() {
            // Each forward effect needs start authority at the moment it begins.
            if monotonic_ns() >= setup_deadline_ns {
                report_setup_expired(&mut context);
                return;
            }
            run_effect(&mut context, effect, &allowed, &mut vm);
            if pending_effects.is_empty() {
                let _ =
                    context
                        .control
                        .send(0, &SupervisorEvent::EffectsDone, Duration::from_secs(1));
            }
        }
    }
}

/// S leaves without another effect. Anything it already owns stays for H to fence,
/// contain and observe: this is not a clean completion and settles nothing else.
fn report_setup_expired(context: &mut SupervisorContext) {
    let _ = context
        .control
        .send(0, &SupervisorEvent::SetupExpired, Duration::from_secs(1));
    send_watch_byte(&context.watch, b'E');
}

fn stop_vm(vm: &Option<ProcessId>) {
    if let Some(target) = vm {
        kill_target(*target);
    }
}

/// Signals a process group only if the recorded start time still matches, and never
/// a bare PID on mismatch. Returns whether the target is now provably gone.
pub fn kill_target(target: ProcessId) -> bool {
    match process_state(target.pid) {
        ProcessState::Gone | ProcessState::Zombie => return true,
        ProcessState::Running { start_time } if start_time != target.start_time => return true,
        ProcessState::Running { .. } => {}
    }
    // SAFETY: the identity was just verified; the fake VM leads its own group.
    unsafe { libc::kill(-target.pid, libc::SIGKILL) };
    let end = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < end {
        match process_state(target.pid) {
            ProcessState::Gone | ProcessState::Zombie => return true,
            ProcessState::Running { start_time } if start_time != target.start_time => return true,
            ProcessState::Running { .. } => std::thread::sleep(Duration::from_millis(2)),
        }
    }
    false
}

#[cfg(test)]
fn run_effect(
    context: &mut SupervisorContext,
    effect: FakeEffect,
    allowed: &[String],
    vm: &mut Option<ProcessId>,
) {
    let Some(root) = context.config.test.fake_root.clone() else {
        return;
    };
    let directory =
        super::inventory::fake::allocation_dir(&root, context.instance, context.allocation);
    match effect {
        FakeEffect::Marker(name) => {
            fault_point(&format!("S.effect.{name}"));
            assert!(allowed.contains(&name), "effect {name} has no permit");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(&name), b"fake").unwrap();
        }
        FakeEffect::Vm => {
            fault_point("S.effect.vm");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("vm"), b"fake").unwrap();
            let pid = spawn_process(&[], || {
                // SAFETY: making this child its group's leader, like the VM cgroup.
                unsafe { libc::setpgid(0, 0) };
                // A real process that outlives S, until K kills it or the fixture is gone.
                while root.exists() {
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
            .unwrap();
            // SAFETY: also from the parent, closing the race before K could signal.
            unsafe { libc::setpgid(pid, pid) };
            if let ProcessState::Running { start_time } = process_state(pid) {
                let target = ProcessId { pid, start_time };
                *vm = Some(target);
                let _ = context.control.send(
                    0,
                    &SupervisorEvent::VmStarted(target),
                    Duration::from_secs(1),
                );
            }
        }
    }
}

// M: the monitor.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MonitorCommand {
    /// The watch endpoint for this supervisor arrives on the descriptor socket first.
    RegisterWatch {
        allocation: Id128,
    },
    /// The conditional stop authority's concrete target, before it could be needed.
    RegisterTarget {
        allocation: Id128,
        target: ProcessId,
    },
    Forget {
        allocation: Id128,
    },
    Tick,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MonitorReply {
    Registered,
    Refused,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MonitorEvent {
    Status {
        stale_workers: Vec<String>,
        stale_supervisors: Vec<Id128>,
    },
    SupervisorLost {
        allocation: Id128,
    },
    Contained {
        allocation: Id128,
        gone: bool,
    },
    /// Both fixed recovery slots are occupied. The target stays pending in M.
    NoRecovery {
        allocation: Id128,
    },
}

/// The most stop targets M holds: far above any node's slots, and a refusal past it
/// makes H contain that allocation itself rather than lose the authority silently.
const MAX_MONITOR_TARGETS: usize = 1024;
/// How long a K keeps serving M with H gone and no dispatch arriving.
const RECOVERY_IDLE_AFTER_HELPER_LOSS: Duration = Duration::from_secs(3);

/// M's bounded stop work over the two fixed K slots. A target is never dropped because
/// both are busy; it waits here, and only an original slot's reply frees that slot. No
/// third K exists, and a stuck slot simply never frees.
#[derive(Default)]
struct StopQueue {
    targets: HashMap<Id128, ProcessId>,
    /// Waiting for a free slot, in arrival order.
    pending: std::collections::VecDeque<Id128>,
    /// Which allocation each K slot is working on.
    busy: Vec<Option<Id128>>,
    /// Proven gone: nothing further to dispatch.
    finished: std::collections::HashSet<Id128>,
    reported_blocked: std::collections::HashSet<Id128>,
    /// Stop requested before H registered any concrete target.
    awaiting_target: std::collections::HashSet<Id128>,
}

impl StopQueue {
    fn new(slots: usize) -> Self {
        Self {
            busy: vec![None; slots],
            ..Self::default()
        }
    }

    /// Requests a stop, once. A target that arrives later inherits an open request.
    fn request(&mut self, allocation: Id128) {
        if !self.finished.contains(&allocation)
            && !self.pending.contains(&allocation)
            && !self.busy.contains(&Some(allocation))
        {
            self.pending.push_back(allocation);
        }
    }

    fn request_all(&mut self) {
        let all: Vec<Id128> = self.targets.keys().copied().collect();
        for allocation in all {
            self.request(allocation);
        }
    }

    /// A K slot's answer frees that slot; an unproven stop waits its turn again.
    fn settle(&mut self, index: usize, allocation: Id128, gone: bool) {
        if self.busy[index] == Some(allocation) {
            self.busy[index] = None;
        }
        if gone {
            self.finished.insert(allocation);
            self.reported_blocked.remove(&allocation);
        } else {
            self.request(allocation);
        }
    }

    /// Hands pending stops to free slots. Returns the ones with no slot to take them.
    fn dispatch(&mut self, recovery: &[UnixDatagram]) -> Vec<Id128> {
        let mut index = 0;
        while index < self.busy.len() && !self.pending.is_empty() {
            if self.busy[index].is_some() {
                index += 1;
                continue;
            }
            let allocation = self.pending.pop_front().expect("checked nonempty");
            // No concrete target yet: the request stays open for when H registers one.
            let Some(target) = self.targets.get(&allocation).copied() else {
                self.awaiting_target.insert(allocation);
                continue;
            };
            let sent = serde_json::to_vec(&RecoveryDatagram { allocation, target })
                .ok()
                .is_some_and(|bytes| recovery[index].send(&bytes).is_ok());
            if sent {
                self.busy[index] = Some(allocation);
            } else {
                self.pending.push_front(allocation);
                index += 1;
            }
        }
        let mut blocked = Vec::new();
        for allocation in &self.pending {
            if self.reported_blocked.insert(*allocation) {
                blocked.push(*allocation);
            }
        }
        blocked
    }

    fn idle(&self) -> bool {
        self.pending.is_empty() && self.busy.iter().all(Option::is_none)
    }
}

/// One datagram each way between M and a K slot: small, fixed and atomic, so a new M
/// inherits a usable channel after the old one exits.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecoveryDatagram {
    pub allocation: Id128,
    pub target: ProcessId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecoveryDatagramReply {
    pub allocation: Id128,
    pub gone: bool,
}

struct Watch {
    allocation: Id128,
    stream: std::os::unix::net::UnixStream,
    last_seen: std::time::Instant,
    clean_exit: bool,
    open: bool,
}

/// Receives one descriptor sent by H with the shared SCM_RIGHTS envelope, in bounds.
fn receive_descriptor(socket: RawFd, wait: Duration) -> io::Result<OwnedFd> {
    if !poll_one(socket, libc::POLLIN, wait)? {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "watch descriptor did not arrive",
        ));
    }
    let mut marker = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut marker as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    // SAFETY: zero is a valid initial msghdr; all pointers below are live.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of::<[usize; 16]>() as _;
    // SAFETY: message describes live buffers.
    let rc = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_DONTWAIT) };
    if rc != 1 {
        return Err(io::Error::other("malformed watch descriptor message"));
    }
    // SAFETY: the kernel filled the control buffer described by message.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::other("watch descriptor missing"));
        }
        let fd = *libc::CMSG_DATA(header).cast::<RawFd>();
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// The sockets M is forked with; H keeps its own copies of the recovery ones.
pub struct MonitorSockets {
    pub control: Endpoint,
    pub descriptors: OwnedFd,
    pub heartbeats: Vec<(String, UnixDatagram)>,
    pub recovery: Vec<UnixDatagram>,
}

/// M: nonblocking polling and stop dispatch only, with no journal, filesystem or
/// cgroup writes in its loop. A live-but-stalled H is not equivalent to supervision:
/// H's silence requests every registered stop, and M owns that work through H's death.
/// A stale S watch requests its stop as well. S keeps its slot and permit charged.
pub fn monitor_main(mut sockets: MonitorSockets, timings: Timings, mut heartbeat: Heartbeat) {
    let mut watches: Vec<Watch> = Vec::new();
    let mut stops = StopQueue::new(sockets.recovery.len());
    let mut stale_requested: std::collections::HashSet<Id128> = Default::default();
    let mut infra_seen: Vec<std::time::Instant> =
        vec![std::time::Instant::now(); sockets.heartbeats.len()];
    let mut last_helper = std::time::Instant::now();
    let mut last_status = std::time::Instant::now();
    let mut last_recovery_heartbeat = std::time::Instant::now();
    let mut helper_gone: Option<std::time::Instant> = None;
    let mut helper_stale_requested = false;
    for socket in sockets
        .recovery
        .iter()
        .chain(sockets.heartbeats.iter().map(|(_, s)| s))
    {
        let _ = socket.set_nonblocking(true);
    }
    loop {
        heartbeat.beat();
        fault_point("M.loop");
        let mut entries: Vec<libc::pollfd> = Vec::with_capacity(
            1 + watches.len() + sockets.heartbeats.len() + sockets.recovery.len(),
        );
        let event = |fd: RawFd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // A closed control socket stays readable forever: stop polling it.
        if helper_gone.is_none() {
            entries.push(event(sockets.control.raw_fd()));
        }
        for watch in &watches {
            entries.push(event(watch.stream.as_raw_fd()));
        }
        for (_, socket) in &sockets.heartbeats {
            entries.push(event(socket.as_raw_fd()));
        }
        for socket in &sockets.recovery {
            entries.push(event(socket.as_raw_fd()));
        }
        if poll_many(&mut entries, Duration::from_millis(20)).is_err() {
            return;
        }
        // Infrastructure heartbeats.
        let mut chunk = [0u8; 16];
        for (index, (_, socket)) in sockets.heartbeats.iter().enumerate() {
            while socket.recv(&mut chunk).is_ok() {
                infra_seen[index] = std::time::Instant::now();
            }
        }
        // Recovery replies free exactly the slot that answered.
        for (index, socket) in sockets.recovery.iter().enumerate() {
            let mut bytes = [0u8; 1024];
            while let Ok(n) = socket.recv(&mut bytes) {
                if let Ok(reply) = serde_json::from_slice::<RecoveryDatagramReply>(&bytes[..n]) {
                    stops.settle(index, reply.allocation, reply.gone);
                    if helper_gone.is_none() {
                        let _ = sockets.control.send(
                            0,
                            &MonitorEvent::Contained {
                                allocation: reply.allocation,
                                gone: reply.gone,
                            },
                            Duration::from_millis(100),
                        );
                    }
                }
            }
        }
        // Supervisor watches.
        let mut lost = Vec::new();
        for watch in watches.iter_mut() {
            loop {
                let mut bytes = [0u8; 256];
                // SAFETY: bytes is writable and the socket is owned.
                let n = unsafe {
                    libc::recv(
                        watch.stream.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n > 0 {
                    watch.last_seen = std::time::Instant::now();
                    if bytes[..n as usize].contains(&b'E') {
                        watch.clean_exit = true;
                    }
                    continue;
                }
                let error = io::Error::last_os_error();
                if n == 0
                    || !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    )
                {
                    watch.open = false;
                    if !watch.clean_exit {
                        lost.push(watch.allocation);
                    }
                }
                break;
            }
        }
        watches.retain(|watch| watch.open);
        // Commands from H.
        while helper_gone.is_none() {
            match sockets.control.receive::<MonitorCommand>(Duration::ZERO) {
                Ok(Received::Message {
                    id,
                    deadline_ns,
                    body,
                }) => {
                    last_helper = std::time::Instant::now();
                    match body {
                        MonitorCommand::Tick => {}
                        MonitorCommand::RegisterWatch { allocation } => {
                            let received = receive_descriptor(
                                sockets.descriptors.as_raw_fd(),
                                Duration::from_millis(500),
                            );
                            // An expired start has no authority to gain a watch.
                            let reply = match received {
                                Ok(fd) if monotonic_ns() < deadline_ns => {
                                    let stream: std::os::unix::net::UnixStream = fd.into();
                                    let _ = stream.set_nonblocking(true);
                                    watches.push(Watch {
                                        allocation,
                                        stream,
                                        last_seen: std::time::Instant::now(),
                                        clean_exit: false,
                                        open: true,
                                    });
                                    MonitorReply::Registered
                                }
                                _ => MonitorReply::Refused,
                            };
                            let _ = sockets.control.send(id, &reply, Duration::from_millis(200));
                        }
                        MonitorCommand::RegisterTarget { allocation, target } => {
                            let reply = if stops.targets.len() < MAX_MONITOR_TARGETS
                                || stops.targets.contains_key(&allocation)
                            {
                                stops.targets.insert(allocation, target);
                                // An already-stale or lost S may have just started this
                                // subtree, and its stop request still stands.
                                if stale_requested.contains(&allocation)
                                    || stops.awaiting_target.remove(&allocation)
                                {
                                    stops.request(allocation);
                                }
                                MonitorReply::Registered
                            } else {
                                MonitorReply::Refused
                            };
                            let _ = sockets.control.send(id, &reply, Duration::from_millis(200));
                        }
                        MonitorCommand::Forget { allocation } => {
                            stops.targets.remove(&allocation);
                            stops.finished.remove(&allocation);
                            stops.pending.retain(|pending| *pending != allocation);
                            stops.awaiting_target.remove(&allocation);
                            stale_requested.remove(&allocation);
                        }
                    }
                }
                Ok(Received::Idle) => break,
                Ok(Received::Closed) | Err(_) => {
                    helper_gone = Some(std::time::Instant::now());
                    break;
                }
            }
        }
        // A lost supervisor: tell H and contain under the precommitted authority.
        for allocation in lost {
            if helper_gone.is_none() {
                let _ = sockets.control.send(
                    0,
                    &MonitorEvent::SupervisorLost { allocation },
                    Duration::from_millis(50),
                );
            }
            stops.request(allocation);
        }
        // A silent S is an irrevocable stop too, without asking H. Its own slot, permit
        // and charge stay exactly where they are.
        for watch in &watches {
            if watch.last_seen.elapsed() >= timings.heartbeat_timeout
                && stale_requested.insert(watch.allocation)
            {
                stops.request(watch.allocation);
            }
        }
        let stale_helper =
            helper_gone.is_some() || last_helper.elapsed() >= timings.heartbeat_timeout;
        if stale_helper && !helper_stale_requested {
            helper_stale_requested = true;
            stops.request_all();
        }
        if !stale_helper {
            helper_stale_requested = false;
        }
        let blocked = stops.dispatch(&sockets.recovery);
        // Keep idle K slots available while another original K is stuck. An empty
        // private datagram is a heartbeat, never side-effect authority or a reply.
        if last_recovery_heartbeat.elapsed() >= timings.heartbeat {
            last_recovery_heartbeat = std::time::Instant::now();
            for socket in &sockets.recovery {
                let _ = socket.send(&[]);
            }
        }
        if helper_gone.is_some() {
            // Ownership cannot time out. A stuck K retains M and every pending target
            // until they settle; ledger replay is a fallback, not an assumed restart.
            if stops.idle() {
                return;
            }
            continue;
        }
        for allocation in blocked {
            let _ = sockets.control.send(
                0,
                &MonitorEvent::NoRecovery { allocation },
                Duration::from_millis(50),
            );
        }
        if last_status.elapsed() >= timings.heartbeat {
            last_status = std::time::Instant::now();
            let stale_workers = sockets
                .heartbeats
                .iter()
                .zip(&infra_seen)
                .filter(|(_, seen)| seen.elapsed() >= timings.heartbeat_timeout)
                .map(|((name, _), _)| name.clone())
                .collect();
            let stale_supervisors = watches
                .iter()
                .filter(|watch| watch.last_seen.elapsed() >= timings.heartbeat_timeout)
                .map(|watch| watch.allocation)
                .collect();
            let _ = sockets.control.send(
                0,
                &MonitorEvent::Status {
                    stale_workers,
                    stale_supervisors,
                },
                Duration::from_millis(50),
            );
        }
    }
}

// K: the reserved recovery workers.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryRequest {
    Kill {
        target: ProcessId,
    },
    Probe {
        target: ProcessId,
        boot_id: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryReply {
    Killed { gone: bool },
    Probed { gone: bool },
}

/// K: independent of L and S. It uses already-authorized identity only and never
/// hashes, formats, inventories or waits on the ledger. Its result is evidence for
/// containment, never a durable receipt.
pub fn recovery_main(mut endpoint: Endpoint, monitor: UnixDatagram, mut heartbeat: Heartbeat) {
    let _ = monitor.set_nonblocking(true);
    let mut helper_gone = false;
    let mut last_dispatch = std::time::Instant::now();
    loop {
        heartbeat.beat();
        fault_point("K.loop");
        let mut entries = vec![libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // A closed H socket stays readable forever: stop polling it.
        if !helper_gone {
            entries.push(libc::pollfd {
                fd: endpoint.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if poll_many(&mut entries, Duration::from_millis(50)).is_err() {
            return;
        }
        let mut bytes = [0u8; 1024];
        while let Ok(n) = monitor.recv(&mut bytes) {
            if n == 0 {
                last_dispatch = std::time::Instant::now();
                continue;
            }
            if let Ok(request) = serde_json::from_slice::<RecoveryDatagram>(&bytes[..n]) {
                last_dispatch = std::time::Instant::now();
                fault_point("K.kill");
                let gone = kill_target(request.target);
                if let Ok(reply) = serde_json::to_vec(&RecoveryDatagramReply {
                    allocation: request.allocation,
                    gone,
                }) {
                    let _ = monitor.send(&reply);
                }
            }
        }
        if helper_gone {
            // M owns the remaining stops and paces them; it holds no socket K could see
            // close, so K leaves once M has plainly stopped sending.
            if last_dispatch.elapsed() >= RECOVERY_IDLE_AFTER_HELPER_LOSS {
                return;
            }
            continue;
        }
        match endpoint.receive::<RecoveryRequest>(Duration::ZERO) {
            Ok(Received::Message { id, body, .. }) => {
                let reply = match body {
                    RecoveryRequest::Kill { target } => {
                        fault_point("K.kill");
                        RecoveryReply::Killed {
                            gone: kill_target(target),
                        }
                    }
                    RecoveryRequest::Probe { target, boot_id } => {
                        let rebooted = boot_id.is_some_and(|boot| boot != host_boot_id());
                        RecoveryReply::Probed {
                            gone: rebooted
                                || match process_state(target.pid) {
                                    ProcessState::Gone | ProcessState::Zombie => true,
                                    ProcessState::Running { start_time } => {
                                        start_time != target.start_time
                                    }
                                },
                        }
                    }
                };
                if endpoint.send(id, &reply, Duration::from_secs(2)).is_err() {
                    helper_gone = true;
                    last_dispatch = std::time::Instant::now();
                }
            }
            Ok(Received::Idle) => {}
            Ok(Received::Closed) | Err(_) => {
                helper_gone = true;
                last_dispatch = std::time::Instant::now();
            }
        }
    }
}

/// A socket pair for a datagram channel, close-on-exec on both ends.
pub fn datagram_pair() -> io::Result<(UnixDatagram, UnixDatagram)> {
    UnixDatagram::pair()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn endpoint_frames_are_bounded_and_survive_partial_delivery() {
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut receiver = Endpoint::new(left);
        let frame = encode_frame(&Envelope {
            id: 7,
            deadline_ns: 9,
            body: "hello".to_string(),
        })
        .unwrap();
        let mut sender = right.try_clone().unwrap();
        use std::io::Write;
        sender.write_all(&frame[..3]).unwrap();
        assert!(matches!(
            receiver
                .receive::<String>(Duration::from_millis(5))
                .unwrap(),
            Received::Idle
        ));
        sender.write_all(&frame[3..]).unwrap();
        match receiver
            .receive::<String>(Duration::from_millis(50))
            .unwrap()
        {
            Received::Message {
                id,
                deadline_ns,
                body,
            } => assert_eq!((id, deadline_ns, body.as_str()), (7, 9, "hello")),
            _ => panic!("no message"),
        }
        // An oversize header is a protocol failure before any body is read.
        sender
            .write_all(&((MAX_IPC_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        sender.write_all(&[0u8; 8]).unwrap();
        assert!(
            receiver
                .receive::<String>(Duration::from_millis(50))
                .is_err()
        );
    }

    #[test]
    fn endpoint_write_cannot_outlive_its_bound_when_the_peer_never_reads() {
        let (left, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sender = Endpoint::new(left);
        let body = vec![0u8; MAX_IPC_FRAME / 4];
        let began = std::time::Instant::now();
        let mut outcome = Ok(());
        for _ in 0..64 {
            outcome = sender.send(1, &body, Duration::from_millis(50));
            if outcome.is_err() {
                break;
            }
        }
        assert_eq!(
            outcome.unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "the kernel buffer should have filled"
        );
        assert!(began.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_given_up_write_never_tears_the_frame_stream() {
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sender = Endpoint::new(left);
        let mut receiver = Endpoint::new(right);
        let body = vec![7u8; MAX_IPC_FRAME / 8];
        let mut delivered = 0;
        for _ in 0..64 {
            if sender.send(1, &body, Duration::from_millis(10)).is_ok() {
                delivered += 1;
            } else {
                break;
            }
        }
        assert!(delivered < 64, "the kernel buffer should have filled");
        // Whatever arrives is whole frames: the kept tail goes out before anything new.
        let reader = std::thread::spawn(move || {
            let mut frames = 0;
            let mut last = 0;
            while last != 2 {
                match receiver
                    .receive::<Vec<u8>>(Duration::from_millis(200))
                    .unwrap()
                {
                    Received::Message { id, body, .. } => {
                        assert_eq!(body.len(), MAX_IPC_FRAME / 8);
                        last = id;
                        frames += 1;
                    }
                    Received::Idle => {}
                    Received::Closed => break,
                }
            }
            (frames, last)
        });
        std::thread::sleep(Duration::from_millis(50));
        sender.send(2, &body, Duration::from_secs(5)).unwrap();
        let (frames, last) = reader.join().unwrap();
        assert!(frames > delivered, "{frames} {delivered}");
        assert_eq!(last, 2);
    }

    #[test]
    fn stop_queue_never_drops_a_target_when_both_slots_are_busy() {
        let (a, a_peer) = UnixDatagram::pair().unwrap();
        let (b, b_peer) = UnixDatagram::pair().unwrap();
        for socket in [&a, &b, &a_peer, &b_peer] {
            socket.set_nonblocking(true).unwrap();
        }
        let recovery = vec![a, b];
        let mut queue = StopQueue::new(2);
        let ids: Vec<Id128> = (1..=3).map(|n| Id128::from_bytes([n; 16])).collect();
        for (index, id) in ids.iter().enumerate() {
            queue.targets.insert(
                *id,
                ProcessId {
                    pid: 1000 + index as i32,
                    start_time: 1,
                },
            );
        }
        queue.request_all();
        queue.request_all();
        assert_eq!(
            queue.dispatch(&recovery).len(),
            1,
            "one stop has no free slot"
        );
        // The third is retained, reported once and not duplicated.
        assert_eq!(queue.pending.len(), 1);
        assert!(queue.dispatch(&recovery).is_empty());
        let mut bytes = [0u8; 1024];
        let n = a_peer.recv(&mut bytes).unwrap();
        let first: RecoveryDatagram = serde_json::from_slice(&bytes[..n]).unwrap();
        // A stuck slot never frees; only slot 0's real answer moves the third.
        queue.settle(0, first.allocation, true);
        assert!(queue.dispatch(&recovery).is_empty());
        assert!(queue.pending.is_empty());
        let n = a_peer.recv(&mut bytes).unwrap();
        let third: RecoveryDatagram = serde_json::from_slice(&bytes[..n]).unwrap();
        assert_ne!(third.allocation, first.allocation);
        // An unproven stop is retried instead of being counted finished.
        queue.settle(0, third.allocation, false);
        assert_eq!(queue.pending.len(), 1);
        assert!(!queue.finished.contains(&third.allocation));
        assert!(!queue.idle());
        queue.dispatch(&recovery);
        queue.settle(0, third.allocation, true);
        let n = b_peer.recv(&mut bytes).unwrap();
        let second: RecoveryDatagram = serde_json::from_slice(&bytes[..n]).unwrap();
        assert!(!queue.idle(), "slot 1 has not answered");
        queue.settle(1, second.allocation, true);
        assert!(queue.idle());
        // A finished stop never restarts.
        queue.request_all();
        assert!(queue.idle());
    }

    #[test]
    fn revocation_table_is_shared_across_fork_and_checks_exact_generations() {
        let table = RevocationTable::new(4).unwrap();
        let authority = AdmissionAuthority {
            slot: 1,
            generation: 7,
        };
        assert!(!table.is_current(&authority), "slots start revoked");
        table.publish(1, 7);
        assert!(table.is_current(&authority));
        assert!(!table.is_current(&AdmissionAuthority {
            slot: 1,
            generation: 8
        }));
        assert!(!table.is_current(&AdmissionAuthority {
            slot: 2,
            generation: 7
        }));
        assert!(!table.is_current(&AdmissionAuthority {
            slot: 400,
            generation: 7
        }));
        assert!(!table.is_current(&AdmissionAuthority {
            slot: 0,
            generation: REVOKED
        }));
        // A store in the parent is visible in a child forked before it, and back.
        let mut to_child = [0; 2];
        // SAFETY: to_child is writable.
        assert_eq!(unsafe { libc::pipe(to_child.as_mut_ptr()) }, 0);
        // SAFETY: the child uses atomics and a pipe, then exits without destructors.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut byte = 0u8;
            // SAFETY: byte is writable and the pipe is live.
            unsafe { libc::read(to_child[0], (&mut byte as *mut u8).cast(), 1) };
            let revoked = !table.is_current(&authority);
            table.publish(3, 99);
            // SAFETY: leaving the child.
            unsafe { libc::_exit(if revoked { 0 } else { 1 }) };
        }
        table.revoke(1);
        // SAFETY: the byte is readable and the pipe is live.
        unsafe { libc::write(to_child[1], b"x".as_ptr().cast(), 1) };
        let mut status = 0;
        // SAFETY: status is writable and pid is this process's child.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert!(table.is_current(&AdmissionAuthority {
            slot: 3,
            generation: 99
        }));
        // SAFETY: closing this test's own pipe ends.
        unsafe {
            libc::close(to_child[0]);
            libc::close(to_child[1]);
        }
    }

    #[test]
    fn process_identity_tells_running_from_gone_and_a_reused_pid_is_never_signaled() {
        let me = unsafe { libc::getpid() };
        let ProcessState::Running { start_time } = process_state(me) else {
            panic!("this process is running");
        };
        assert!(start_time > 0);
        assert_eq!(process_state(i32::MAX - 7), ProcessState::Gone);
        // A wrong start time counts as gone, and must not signal this process.
        assert!(kill_target(ProcessId {
            pid: me,
            start_time: start_time + 1
        }));
        assert_eq!(process_state(me), ProcessState::Running { start_time });
        assert_ne!(host_boot_id(), "unknown");
    }
}
