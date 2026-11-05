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
use super::identity::{self, AllocationKey, ClaimedIdentities, IdentityLeases, IdentityRanges};
use super::inventory::{NamespaceObservation, NodeObservation, ObservationBackend};
use super::compaction::{self, CompactReply, Compactor};
use super::journal::{
    AccountingSnapshot, AdmitOutcome, AdmitRequest, AttachOutcome, FenceOutcome, FenceRequest,
    InventorySnapshot, IssueOutcome, Ledger, LedgerConfig, LedgerError, ReplaySnapshot,
    TokenLookup, WorkerIntentSpec,
};
use super::token::KeyTransfer;
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
/// B7 RTC-18: one permit for compaction on its own lane, never a reserved one.
pub const LEDGER_QUEUE_COMPACTION: usize = 1;
pub const PREP_SLOTS: usize = 2;
pub const RECOVERY_SLOTS: usize = 2;

/// Test-only deterministic faults, by marker file. Compiled out of production: there
/// is no public fixture mode, CLI switch or environment hook.
#[cfg(test)]
// Approved (design 7.1): test-only fault markers, compiled only under cfg(test).
#[allow(clippy::disallowed_methods)]
pub mod faults {
    use std::path::PathBuf;
    use std::sync::OnceLock;
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

    pub fn install(directory: PathBuf) {
        let _ = DIRECTORY.set(directory);
    }

    /// Writes a test artifact next to the fault markers, if a fixture installed them.
    pub fn write(name: &str, bytes: &[u8]) {
        if let Some(directory) = DIRECTORY.get() {
            let _ = std::fs::write(directory.join(name), bytes);
        }
    }

    /// A fixture-written value, such as the injected boot clock offset.
    pub fn read(name: &str) -> Option<String> {
        let directory = DIRECTORY.get()?;
        std::fs::read_to_string(directory.join(name)).ok()
    }

    /// Appends one line to a test artifact (L's frame order for RTC-18).
    pub fn append(name: &str, line: &str) {
        use std::io::Write;
        if let Some(directory) = DIRECTORY.get()
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(directory.join(name))
        {
            let _ = writeln!(file, "{line}");
        }
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
pub(super) struct Envelope<T> {
    /// Zero marks an unsolicited event; a request's reply echoes its nonzero ID.
    pub(super) id: u64,
    pub(super) deadline_ns: u64,
    pub(super) body: T,
}

pub(super) fn encode_frame<T: Serialize>(envelope: &Envelope<T>) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(envelope).map_err(io::Error::other)?;
    if body.is_empty() || body.len() > MAX_IPC_FRAME {
        return Err(oversized(body.len()));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// A frame too large for the worker protocol, refused before any byte is written.
fn oversized(bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("worker frame size exceeded: {bytes} bytes"),
    )
}

/// True when `error` is `encode_frame`'s size refusal: nothing was written.
pub fn oversized_frame(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::InvalidData
        && !partial_send(error)
        && error.to_string().starts_with("worker frame size exceeded")
}

/// Blocking only inside bounded `poll`; every read and write is `MSG_DONTWAIT`.
///
/// A frame is all or nothing (B5-03). A write given up before its first byte reached
/// the kernel drops that frame whole and the stream stays usable. A write that fails
/// or times out after any byte was handed over **poisons** the endpoint: the socket is
/// shut down both ways, so the peer reads a torn frame and then EOF and never a late
/// delivery, and every later `send` returns the stored error. The unsent tail is never
/// flushed and the connection is never resumed.
pub struct Endpoint {
    fd: OwnedFd,
    buffer: Vec<u8>,
    poisoned: Option<(io::ErrorKind, String)>,
}

/// The marker inside an error from a frame that was partly handed to the kernel: the
/// peer may have any prefix of it, so the send is uncertain, not undelivered.
#[derive(Debug)]
pub struct PartialFrame(pub String);

impl std::fmt::Display for PartialFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} after a partial frame; the connection is poisoned",
            self.0
        )
    }
}

impl std::error::Error for PartialFrame {}

/// True when `error` came from a send that had already handed bytes of its frame to
/// the kernel, or from an endpoint poisoned by one: delivery is uncertain.
pub fn partial_send(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.downcast_ref::<PartialFrame>().is_some())
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
            poisoned: None,
        }
    }

    /// True once a partial write poisoned this endpoint.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    fn poisoned_error(&self) -> Option<io::Error> {
        self.poisoned
            .as_ref()
            .map(|(kind, why)| io::Error::new(*kind, PartialFrame(why.clone())))
    }

    /// Records the failure and shuts the socket both ways; the peer sees EOF after
    /// whatever prefix arrived, which never decodes as a frame.
    fn poison(&mut self, error: io::Error) -> io::Error {
        if self.poisoned.is_none() {
            self.poisoned = Some((error.kind(), error.to_string()));
            // SAFETY: the descriptor is owned; shutdown never blocks.
            unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR) };
        }
        self.poisoned_error()
            .unwrap_or_else(|| io::Error::other("poisoned"))
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
    /// A frame that cannot be encoded (too large) is refused before any byte is
    /// written and leaves the endpoint usable.
    pub fn send<T: Serialize>(&mut self, id: u64, body: &T, within: Duration) -> io::Result<()> {
        if let Some(error) = self.poisoned_error() {
            return Err(error);
        }
        let end = std::time::Instant::now() + within;
        let frame = encode_frame(&Envelope {
            id,
            deadline_ns: 0,
            body,
        })?;
        self.write_until(frame, end)
    }

    fn write_until(&mut self, frame: Vec<u8>, end: std::time::Instant) -> io::Result<()> {
        let mut sent = 0;
        let result = self.write_frame(&frame, &mut sent, end);
        match result {
            Err(error) if sent > 0 => Err(self.poison(error)),
            other => other,
        }
    }

    fn write_frame(
        &mut self,
        frame: &[u8],
        sent: &mut usize,
        end: std::time::Instant,
    ) -> io::Result<()> {
        while *sent < frame.len() {
            // SAFETY: the unsent suffix is readable and the descriptor is owned.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    frame[*sent..].as_ptr().cast(),
                    frame.len() - *sent,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if n >= 0 {
                *sent += n as usize;
                continue;
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let left = end.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        // An untouched frame is simply dropped; a started one poisons.
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
    /// B7 RTC-18: the compactor's one permit.
    Compaction,
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
    compaction: Arc<Semaphore>,
    closed: CancellationToken,
}

impl Channel {
    /// Spawns the I/O tasks. Unsolicited events arrive on the returned receiver.
    pub fn spawn(
        stream: std::os::unix::net::UnixStream,
        normal: usize,
        reserved: usize,
    ) -> io::Result<(Arc<Self>, mpsc::Receiver<Value>)> {
        Self::spawn_with_attach(stream, normal, reserved, 0, 0)
    }

    /// L's channel, which alone has attachment and compaction lanes.
    pub fn spawn_with_attach(
        stream: std::os::unix::net::UnixStream,
        normal: usize,
        reserved: usize,
        attach: usize,
        compaction: usize,
    ) -> io::Result<(Arc<Self>, mpsc::Receiver<Value>)> {
        stream.set_nonblocking(true)?;
        let stream = crate::helper::socket::Socket(UnixStream::from_std(stream)?);
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (writer, mut outgoing) =
            mpsc::channel::<Vec<u8>>((normal + reserved + attach + compaction).max(4) + 8);
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
            compaction: Arc::new(Semaphore::new(compaction)),
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
            Lane::Compaction => self.compaction.clone().try_acquire_owned(),
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

/// A process, when it began and the boot it ran in. A PID alone is never used to
/// signal anything, and PID plus start time only within the journaled boot: every
/// identity written since B4 recheck 3 carries the boot ID. A record without one (an
/// older row) deserializes with `None`, which proves nothing (`proven::prove_process`):
/// it is never signaled and stays charged until it is provably gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessId {
    pub pid: i32,
    pub start_time: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<super::proven::BootId>,
}

impl ProcessId {
    /// A live process of this boot, identified now.
    pub fn of_this_boot(pid: i32, start_time: u64) -> io::Result<Self> {
        Ok(Self {
            pid,
            start_time,
            boot_id: Some(super::proven::BootId::current()?),
        })
    }
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
    // Beneath the helper's private procfs instance, never a /proc pathname a mount in
    // its namespace could shadow (B4 recheck 5).
    let Ok(stat) = crate::sys::procfs::read_to_string(&format!("{pid}/stat")) else {
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
        if crate::sys::process_exists(pid) {
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

/// Host boot identity: a changed value invalidates every recorded PID. Unreadable is
/// an error, never a placeholder.
pub fn host_boot_id() -> io::Result<super::proven::BootId> {
    super::proven::BootId::current()
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
    /// B7 RTC-18: how often H offers each instance a compaction pass. L's boot clock,
    /// not this, decides when a checkpoint or advance is due; production uses a quarter
    /// of the pass so no pass is missed by timer jitter.
    pub compaction_tick: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            tick: Duration::from_millis(100),
            heartbeat: Duration::from_millis(250),
            heartbeat_timeout: Duration::from_secs(1),
            startup_journal: Duration::from_secs(30),
            compaction_tick: Duration::from_millis(super::journal::DEFAULT_COMPACTION_PASS_MS / 4),
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
    /// Every declared artifact's pin. S re-verifies the kernel and root on each create.
    pub artifacts: BTreeMap<String, super::manifest::ArtifactPin>,
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
    /// B4's root tests: S runs the real chain instead of fake effects.
    pub real: bool,
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
    /// The helper's own account, which no instance may be enrolled under.
    pub helper_uid: u32,
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
        /// B7 RTC-14: the daemon's highest recorded complete token, already H-checked.
        highest_token: Option<Id128>,
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
        plan_digest: Digest,
    },
    /// B7 RTC-4: Preflight's issuance and identity snapshot, in one transaction.
    IssueAndSnapshot {
        instance: Id128,
    },
    /// B7 RTC-3 and RTC-14: K, over this private channel only, before H checks any tag,
    /// always together with L's latch state. H imports the latch before it publishes the
    /// channel, so no channel is ever served whose handover omitted it.
    Handover,
    /// B7 RTC-14: H has latched; commit the pending fault (idempotent).
    CommitFault {
        instance: Id128,
        token: Id128,
        issue_next: u64,
    },
    /// B7 RTC-18: one compaction pass, on the compaction lane.
    Compact {
        instance: Id128,
        max_tokens: u64,
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
        instance: Id128,
        allocation: Id128,
        spec: Box<WorkerIntentSpec>,
        target: ProcessId,
    },
    AdvancePhase {
        instance: Id128,
        allocation: Id128,
        expected_generation: u64,
        phase: String,
    },
    RecordStop {
        instance: Id128,
        allocation: Id128,
        reason: String,
    },
    RecordObserved {
        instance: Id128,
        allocation: Id128,
        actual: ExecutableIdentity,
    },
    /// A retained descriptor's tuple, inferred from its confirmed exec, never observed.
    RecordInferred {
        instance: Id128,
        allocation: Id128,
        inferred: ExecutableIdentity,
    },
    RecordResource {
        instance: Id128,
        allocation: Id128,
        record: super::supervisor::ResourceRecord,
    },
    SetPhase {
        instance: Id128,
        allocation: Id128,
        from: Vec<String>,
        to: String,
    },
    AllocationState {
        instance: Id128,
        allocation: Id128,
    },
    /// A cleanup S's intent, journaled before it is forked.
    AllocationWorkerIntent {
        instance: Id128,
        allocation: Id128,
        spec: Box<WorkerIntentSpec>,
    },
    Settle {
        worker_id: i64,
        settlement: String,
    },
    SettleUnstarted {
        instance: Id128,
        allocation: Id128,
    },
    Fence(Box<FenceRequest>),
    Accounting {
        instance: Option<Id128>,
    },
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
    /// B7 RTC-14: rollback evidence. L has latched and written nothing; H latches, then
    /// asks for the commit.
    FaultPending {
        token: Id128,
        issue_next: u64,
    },
    FaultCommitted {
        generation: u64,
    },
    Issued(IssueOutcome),
    /// K and L's latch state, inseparable: the only way H receives K.
    Handover {
        key: KeyTransfer,
        latch: LatchState,
    },
    /// B7 RTC-14: L refused a forward effect under its own latch or fail-stop marker,
    /// whatever H believed. Nothing was written. H latches on this answer too.
    Latched {
        kind: String,
    },
    Compacted(Box<CompactReply>),
    /// A ledger commit failed: L wrote the fail-stop marker and latched (RTC-R2-01).
    SyncFailed {
        reason: String,
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
    State(Option<Box<super::journal::AllocationState>>),
    WorkerIntent {
        worker_id: i64,
        operation_generation: u64,
    },
    Fence(FenceOutcome),
    Accounting(Box<AccountingSnapshot>),
    Inventory(InventorySnapshot),
    Replay(Box<ReplaySnapshot>),
    Failed {
        reason: String,
    },
    /// The answer would exceed the worker frame bound (B5-01). L stays up; nothing
    /// was changed by encoding it, and the caller treats the state as Unknown.
    Oversized {
        bytes: u64,
    },
}

/// L's RTC-14 latch as handed to H at every handover: the durable fault rows, the
/// fail-stop marker and L's in-memory latch. Any one of them latches H.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatchState {
    /// The kinds of the `node_faults` rows, oldest first.
    pub node_faults: Vec<String>,
    /// The fail-stop marker beside the ledger (RTC-R2-01).
    pub failstop: bool,
    /// L's in-memory latch, set before any fault commit is attempted.
    pub latched: bool,
}

impl LatchState {
    /// The latch kind H records, or `None` when nothing is latched.
    pub fn kind(&self) -> Option<String> {
        if let Some(kind) = self.node_faults.first() {
            return Some(kind.clone());
        }
        if self.failstop {
            return Some("fail_stop".into());
        }
        self.latched.then(|| "rollback".into())
    }
}

/// B7 RTC-14 at L: the ledger writes that start or continue a forward effect. Under L's
/// own latch each is refused before anything is written, whoever sends it. Preflight's
/// issuance and a first attach are refused inside their own transactions
/// (`issue_and_snapshot`, `attach_instance`), which read the same latch and the fault
/// rows. Validate journals nothing; H refuses it under its latch. Cleanup and evidence
/// (Inspect, List, Stop, Remove, Gc, FenceAbsent, settlement, observed records, `booting`
/// and `ready` after the fact) are never refused here.
pub(super) fn forward_effect(request: &LedgerRequest) -> bool {
    match request {
        // C2, replays included: an exact replay reports Accepted and lets H go on.
        LedgerRequest::Admit { .. } => true,
        // C3's PREPARING, the only phase advance there is.
        LedgerRequest::AdvancePhase { .. } => true,
        // S's spawn intent and Exec's EXEC_INTENT, each before its effect.
        LedgerRequest::SetPhase { to, .. } => FORWARD_PHASES.contains(&to.as_str()),
        LedgerRequest::RecordResource {
            record: super::supervisor::ResourceRecord::Exec { state, .. },
            ..
        } => state == "intent",
        _ => false,
    }
}

/// Phases whose record authorizes the effect that follows it.
pub(super) const FORWARD_PHASES: [&str; 2] = ["spawn_intent", "exec_intent"];

/// L's in-memory state beside the ledger: the RTC-14 latch and the compactor's
/// checkpoints. Neither survives L; the durable fault rows and the fail-stop marker do,
/// and a new L starts latched from either.
pub(super) struct LedgerState {
    /// Set before any fault commit is attempted, by any failed commit, and at open by any
    /// durable fault row. Never cleared while this L lives.
    pub(super) latched: bool,
    pub(super) failstop: bool,
    pub(super) compactor: Compactor,
    /// The ledger directory, for the fail-stop marker.
    pub(super) config: LedgerConfig,
}

impl LedgerState {
    /// L's latch as H must import it at handover.
    pub(super) fn latch_state(&self, ledger: &Ledger) -> Result<LatchState, LedgerError> {
        Ok(LatchState {
            node_faults: ledger
                .faults()?
                .into_iter()
                .map(|(_, kind, _, _)| kind)
                .collect(),
            failstop: self.failstop,
            latched: self.latched,
        })
    }

    /// The refusal of a forward effect under L's own latch (RTC-14, RTC-R2-01).
    fn forward_refusal(&self, request: &LedgerRequest) -> Option<LedgerReply> {
        if !(self.latched || self.failstop) || !forward_effect(request) {
            return None;
        }
        let kind = if self.failstop { "fail_stop" } else { "rollback" };
        Some(LedgerReply::Latched { kind: kind.into() })
    }
}

pub(super) fn handle_ledger(
    ledger: &mut Ledger,
    state: &mut LedgerState,
    attestor: &mut PeerAttestor,
    revocations: &RevocationTable,
    request: LedgerRequest,
) -> Result<LedgerReply, LedgerError> {
    if let Some(refusal) = state.forward_refusal(&request) {
        fault_point("L.latched_refusal");
        return Ok(refusal);
    }
    Ok(match request {
        LedgerRequest::Attach {
            instance,
            database_uuid,
            peer_pid,
            highest_token,
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
            let latched = state.latched || state.failstop;
            match ledger.attach_instance(instance, database_uuid, highest_token, latched)? {
                // L latches here, before anything is committed; H latches on this
                // answer and only then asks for the commit (RTC-R2-03).
                AttachOutcome::RollbackDetected { token, issue_next } => {
                    state.latched = true;
                    // RTC-R2-01 fail-stop: durable from detection, before any commit is
                    // attempted, so no restart of H or L can serve forward effects
                    // until root's offline clear, whatever happens to the fault row.
                    if let Err(error) = compaction::write_failstop(&state.config, true) {
                        return Err(LedgerError::SyncFailed(format!(
                            "the fail-stop marker could not be written: {error}"
                        )));
                    }
                    state.failstop = true;
                    fault_point("L.fault.detected");
                    LedgerReply::FaultPending { token, issue_next }
                }
                outcome => LedgerReply::Attached {
                    outcome,
                    peer_start,
                },
            }
        }
        LedgerRequest::Handover => LedgerReply::Handover {
            latch: state.latch_state(ledger)?,
            key: KeyTransfer::of(ledger.token_key()),
        },
        LedgerRequest::CommitFault {
            instance,
            token,
            issue_next,
        } => {
            state.latched = true;
            // A replacement L handed a pending fault makes it fail-stop first, too.
            if !state.failstop {
                compaction::write_failstop(&state.config, true).map_err(|error| {
                    LedgerError::SyncFailed(format!("the fail-stop marker: {error}"))
                })?;
                state.failstop = true;
            }
            let generation = ledger.commit_fault(instance, token, issue_next)?;
            fault_point("L.fault.after_commit_before_reply");
            LedgerReply::FaultCommitted { generation }
        }
        LedgerRequest::IssueAndSnapshot { instance } => {
            let latched = state.latched || state.failstop;
            let outcome = ledger.issue_and_snapshot(instance, latched)?;
            fault_point("L.issue.after_commit_before_reply");
            LedgerReply::Issued(outcome)
        }
        LedgerRequest::Compact {
            instance,
            max_tokens,
        } => {
            let reply = state.compactor.pass(
                ledger,
                instance,
                max_tokens.min(super::journal::COMPACTION_BATCH),
                compaction::boot_ms(),
            )?;
            fault_point("L.compact.after_commit_before_reply");
            LedgerReply::Compacted(Box::new(reply))
        }
        #[cfg(test)]
        LedgerRequest::TestEnroll { instance, peer_pid } => {
            let path = test_process_image(peer_pid);
            let meta = std::fs::metadata(&path).expect("the fixture peer's image");
            use std::os::unix::fs::MetadataExt;
            let unit = format!("fixture-{instance}.service");
            let (uid, gid) = super::peer::fixture_account(instance);
            let enrollment = super::peer::Enrollment {
                instance_id: instance,
                cgroup: format!("/fixture.slice/{unit}"),
                unit,
                uid,
                gid,
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
            plan_digest,
        } => LedgerReply::Lookup(ledger.inspect(instance, allocation, &plan_digest)?),
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
            let host_boot_id = match host_boot_id() {
                Ok(id) => id.to_string(),
                Err(error) => {
                    return Ok(LedgerReply::Failed {
                        reason: format!("the host boot ID is unreadable: {error}"),
                    });
                }
            };
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
            let host_boot_id = match host_boot_id() {
                Ok(id) => id.to_string(),
                Err(error) => {
                    return Ok(LedgerReply::Failed {
                        reason: format!("the host boot ID is unreadable: {error}"),
                    });
                }
            };
            let worker_id =
                ledger.record_infrastructure_worker(&spec, pid, start_time, &host_boot_id)?;
            LedgerReply::Worker { worker_id }
        }
        LedgerRequest::InfrastructureIntent { spec } => LedgerReply::Worker {
            worker_id: ledger.record_infrastructure_intent(&spec)?,
        },
        LedgerRequest::RecordChild {
            instance,
            allocation,
            spec,
            target,
        } => {
            // S identified the child in this boot; an identity without one is refused.
            let Some(boot_id) = target.boot_id else {
                return Ok(LedgerReply::Failed {
                    reason: "a child identity carries no boot ID".into(),
                });
            };
            let id = ledger.record_child_worker(
                instance,
                allocation,
                &spec,
                target.pid,
                target.start_time,
                &boot_id.to_string(),
            )?;
            LedgerReply::Generation(id as u64)
        }
        LedgerRequest::AdvancePhase {
            instance,
            allocation,
            expected_generation,
            phase,
        } => LedgerReply::Generation(ledger.advance_phase(
            instance,
            allocation,
            expected_generation,
            &phase,
        )?),
        LedgerRequest::RecordStop {
            instance,
            allocation,
            reason,
        } => LedgerReply::Generation(ledger.record_stop(instance, allocation, &reason)?),
        LedgerRequest::RecordObserved {
            instance,
            allocation,
            actual,
        } => {
            ledger.record_observed_executable(instance, allocation, &actual)?;
            LedgerReply::Done
        }
        LedgerRequest::RecordInferred {
            instance,
            allocation,
            inferred,
        } => {
            ledger.record_inferred_executable(instance, allocation, &inferred)?;
            LedgerReply::Done
        }
        LedgerRequest::RecordResource {
            instance,
            allocation,
            record,
        } => {
            fault_point("L.record_resource");
            LedgerReply::Generation(ledger.record_resource(instance, allocation, &record)?)
        }
        LedgerRequest::SetPhase {
            instance,
            allocation,
            from,
            to,
        } => LedgerReply::Generation(ledger.set_phase(instance, allocation, &from, &to)?),
        LedgerRequest::AllocationState {
            instance,
            allocation,
        } => LedgerReply::State(ledger.allocation_state(instance, allocation)?.map(Box::new)),
        LedgerRequest::AllocationWorkerIntent {
            instance,
            allocation,
            spec,
        } => {
            let (worker_id, operation_generation) =
                ledger.record_allocation_worker_intent(instance, allocation, &spec)?;
            LedgerReply::WorkerIntent {
                worker_id,
                operation_generation,
            }
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
        LedgerRequest::SettleUnstarted {
            instance,
            allocation,
        } => {
            ledger.settle_unstarted(instance, allocation)?;
            LedgerReply::Done
        }
        LedgerRequest::Fence(request) => {
            fault_point("L.fence");
            LedgerReply::Fence(ledger.commit_fence(&request)?)
        }
        LedgerRequest::Accounting { instance } => {
            let mut snapshot = ledger.accounting(instance)?;
            let now = compaction::boot_ms();
            let lease = state.compactor.lease_ms();
            if let (Some(instance), Some(tokens)) = (instance, snapshot.tokens.as_mut()) {
                tokens.checkpoints = state.compactor.checkpoints(instance);
                tokens.compaction_lag_ms = state.compactor.lag_ms(instance, now);
                if tokens.compaction_lag_ms > lease.saturating_mul(2) {
                    snapshot.degraded = Some(format!(
                        "compaction lags {} ms, past two leases",
                        tokens.compaction_lag_ms
                    ));
                }
            }
            if let Some((instance, tokens)) = state.compactor.stuck().next() {
                snapshot.degraded = Some(format!(
                    "{} fenced tokens of instance {instance} cannot be compacted, first {}",
                    tokens.len(),
                    tokens[0]
                ));
            }
            if snapshot.node_fault.is_none() && state.latched {
                snapshot.node_fault = Some("rollback".into());
            }
            if snapshot.node_fault.is_none() && state.failstop {
                snapshot.node_fault = Some("fail_stop".into());
            }
            LedgerReply::Accounting(Box::new(snapshot))
        }
        LedgerRequest::Inventory { instance } => {
            LedgerReply::Inventory(ledger.inventory(instance)?)
        }
        LedgerRequest::Replay => {
            let mut snapshot = ledger.replay()?;
            if state.failstop {
                snapshot.node_faults.push("fail_stop".into());
            }
            if state.latched && snapshot.node_faults.is_empty() {
                snapshot.node_faults.push("rollback".into());
            }
            LedgerReply::Replay(Box::new(snapshot))
        }
    })
}

/// A failed or uncertain durable commit: never evidence, and RTC-R2-01's fail-stop.
fn sync_failure(error: &LedgerError) -> bool {
    matches!(error, LedgerError::CommitFailed | LedgerError::SyncFailed(_))
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
    // L reads an attaching peer's `/proc/<pid>/exe`, which needs L's capabilities to
    // cover the peer's. A production peer holds none. The B4 root tests' peer is the root
    // test process itself, holding the unit's whole set, so only that fixture keeps them.
    #[cfg(all(target_os = "linux", test))]
    if !faults::present("L.keep_launch_capabilities") {
        crate::process::require_firecracker_launch_capabilities_dropped();
    }
    #[cfg(all(target_os = "linux", not(test)))]
    crate::process::require_firecracker_launch_capabilities_dropped();
    let directory_config = config.clone();
    let policy = config.compaction;
    let mut ledger = Ledger::open(config);
    // RTC-R2-01: a marker left by any earlier failed commit latches this L at open, and
    // so does any durable fault row (RTC-14). An unreadable answer latches too.
    let failstop = compaction::failstop_latched(&directory_config).unwrap_or(true);
    let faulted = ledger
        .as_ref()
        .is_ok_and(|ledger| ledger.durable_faults().map_or(true, |faults| faults != 0));
    let mut state = LedgerState {
        latched: faulted,
        failstop,
        compactor: Compactor::start(policy, ledger.as_ref().ok(), compaction::boot_ms()),
        config: directory_config.clone(),
    };
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
        #[cfg(test)]
        if faults::present("L.frame_log") {
            let kind = serde_json::to_value(&request)
                .ok()
                .and_then(|v| match v {
                    Value::String(name) => Some(name),
                    Value::Object(map) => map.keys().next().cloned(),
                    _ => None,
                })
                .unwrap_or_default();
            faults::append("L.frames", &kind);
        }
        let fault_commit = matches!(request, LedgerRequest::CommitFault { .. });
        let mut exit_after = false;
        let reply = match &mut ledger {
            Err(error) => LedgerReply::Unavailable {
                reason: error.to_string(),
            },
            Ok(_) if expiring(&request) && monotonic_ns() >= deadline_ns => LedgerReply::Expired,
            Ok(ledger) => {
                match handle_ledger(ledger, &mut state, &mut attestor, &revocations, request) {
                    Ok(reply) => reply,
                    Err(error) if sync_failure(&error) => {
                        // Latch first in memory, then durably beside the ledger, so no
                        // later L serves forward effects either (RTC-R2-01). A fault
                        // commit that failed or is uncertain also ends this L (RTC-14).
                        state.latched = true;
                        state.failstop = true;
                        let _ = compaction::write_failstop(&directory_config, true);
                        exit_after = fault_commit;
                        LedgerReply::SyncFailed {
                            reason: error.to_string(),
                        }
                    }
                    Err(error) => ledger_failure(error),
                }
            }
        };
        fault_point("L.reply");
        if send_ledger_reply(&mut endpoint, id, &reply).is_err() || exit_after {
            return;
        }
    }
}

/// L's answer, or in its place a typed refusal when it is too large for one frame
/// (B5-01): a reply's size must never take the shared ledger down. Only a transport
/// failure is an error, and it ends L.
pub(super) fn send_ledger_reply(
    endpoint: &mut Endpoint,
    id: u64,
    reply: &LedgerReply,
) -> io::Result<()> {
    match endpoint.send(id, reply, Duration::from_secs(5)) {
        Err(error) if oversized_frame(&error) => {
            let bytes = serde_json::to_vec(reply).map_or(u64::MAX, |b| b.len() as u64);
            endpoint.send(
                id,
                &LedgerReply::Oversized { bytes },
                Duration::from_secs(5),
            )
        }
        other => other,
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
            | LedgerRequest::IssueAndSnapshot { .. }
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
        /// The journal's loop slots for this allocation: each is observed on the slot
        /// itself, since a replacement need not be backed inside the work directory.
        loops: Vec<super::supervisor::RecordedLoop>,
    },
    ObserveNode {
        instance: Id128,
        /// The journal's allocations, to map digest host names back.
        known: Vec<Id128>,
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
        allocation_id: allocation,
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
    #[cfg(target_os = "linux")]
    crate::process::require_firecracker_launch_capabilities_dropped();
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
                loops,
            } => {
                fault_point("P.observe");
                PrepReply::Allocation(
                    config
                        .observation
                        .observe_allocation(instance, allocation, &loops),
                )
            }
            PrepRequest::ObserveNode { instance, known } => {
                fault_point("P.observe");
                PrepReply::Node(config.observation.observe_node(instance, &known))
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
        /// The verified plan's canonical bytes. Present for a real launch; absent only
        /// for the fake-effect fixtures, which compile only under `cfg(test)`.
        plan: Option<String>,
        /// The C2 generation, bound into J's bootstrap record.
        plan_generation: u64,
    },
    /// H's durable answer to one `Record`, in order. `ok == false` ends forward work.
    Recorded {
        seq: u64,
        ok: bool,
    },
    /// A cleanup-only S: stop what remains and remove exactly the owned resources.
    Cleanup {
        deadline_ns: u64,
        plan: String,
        resources: Box<super::supervisor::RecordedResources>,
    },
    /// A fence revoked every future permit: stop and exit.
    Revoke,
    Tick,
    /// B5: one broker job for a READY S (Probe, Exec or Cancel).
    Broker(super::broker::BrokerCommand),
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
    /// Something S must make durable before it proceeds; H answers with `Recorded`.
    Record {
        seq: u64,
        record: super::supervisor::SupervisorRecord,
    },
    /// Hashing, fallocate, mkfs and the private files are done: the P lease returns.
    PreparationDone,
    /// V was validated, hardened and journaled BOOTING. Never READY in B4.
    Booting,
    /// The launch stopped before BOOTING; what exists stays charged for Remove.
    LaunchRefused {
        reason: String,
    },
    /// V exited on its own while S lived.
    VmExited,
    CleanedUp,
    CleanupFailed {
        reason: String,
    },
    /// B5: the broker handshake and Initialize succeeded; READY is journaled.
    Ready {
        boot_id: String,
        inner_id: String,
    },
    /// B5: one relay report for a job H gave.
    Broker {
        report: super::broker::RelayReport,
    },
    /// B5: a console, relay or transport breach; S contained the VM subtree.
    Retire {
        reason: String,
    },
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
    /// B5: H's descriptor socket, which carries an execution's stdio. Absent for a
    /// cleanup-only S.
    pub descriptors: Option<UnixDatagram>,
}

pub(super) fn send_watch_byte(watch: &std::os::unix::net::UnixStream, byte: u8) {
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
                        plan: Some(plan),
                        plan_generation,
                        ..
                    } => {
                        let _ = allowed_names;
                        if gated {
                            fault_point("S.gate");
                            real_supervisor(
                                &mut context,
                                &plan,
                                &expected,
                                deadline_ns,
                                plan_generation,
                            );
                            return;
                        }
                    }
                    SupervisorCommand::Cleanup {
                        deadline_ns,
                        plan,
                        resources,
                    } => {
                        if gated {
                            real_cleanup(&mut context, &plan, &resources, deadline_ns);
                            return;
                        }
                    }
                    // Broker jobs reach only a READY S's steady loop.
                    SupervisorCommand::Recorded { .. } | SupervisorCommand::Broker(_) => {}
                    SupervisorCommand::OpenGate {
                        allowed_names,
                        expected,
                        deadline_ns,
                        plan: None,
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

/// The real launch: run the pipeline, then the steady loop. Every way out contains the
/// VM subtree first; resources stay for Remove, which needs ABSENT to release them.
#[cfg(target_os = "linux")]
fn real_supervisor(
    context: &mut SupervisorContext,
    plan: &str,
    expected: &[ExecutableIdentity],
    deadline_ns: u64,
    plan_generation: u64,
) {
    use super::supervisor::{Abort, LaunchPlan, Link};
    let parsed = match LaunchPlan::parse(plan.as_bytes()) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = context.control.send(
                0,
                &SupervisorEvent::LaunchRefused {
                    reason: error.to_string(),
                },
                Duration::from_secs(1),
            );
            send_watch_byte(&context.watch, b'E');
            return;
        }
    };
    let mut created = None;
    let descriptors = context.descriptors.take();
    let mut link = Link::new(context, deadline_ns);
    let result =
        super::supervisor::launch(&mut link, &parsed, expected, plan_generation, &mut created);
    let end = match result {
        Ok(mut booted) => {
            link.event(&SupervisorEvent::Booting);
            booted_supervisor(
                &mut link,
                &parsed,
                &mut booted,
                descriptors,
                created.as_ref(),
            )
        }
        Err(abort) => Some(abort),
    };
    let _ = super::supervisor::contain(&parsed, created.as_ref());
    match end {
        Some(Abort::Expired) => link.event(&SupervisorEvent::SetupExpired),
        Some(Abort::Refused(reason)) => {
            let reason = format!("at {}: {reason}", link.current_step());
            link.event(&SupervisorEvent::LaunchRefused { reason })
        }
        Some(Abort::Revoked | Abort::HelperGone) | None => {}
    }
    drop(link);
    send_watch_byte(&context.watch, b'E');
}

/// B5: after BOOTING, D and R, readiness through the broker, then the steady loop.
/// Every way out stops both workers and contains the VM subtree; a VM exit or a breach
/// stays owned until H revokes, since cleanup is Remove's, by its own S.
#[cfg(target_os = "linux")]
fn booted_supervisor(
    link: &mut super::supervisor::Link<'_>,
    parsed: &super::supervisor::LaunchPlan,
    booted: &mut super::supervisor::Booted,
    descriptors: Option<UnixDatagram>,
    created: Option<&super::cgroup::CgroupIdentity>,
) -> Option<super::supervisor::Abort> {
    use super::broker::supervise::{self, SteadyEnd};
    use super::supervisor::Abort;
    let mut workers = match supervise::start(link, parsed, booted) {
        Ok(workers) => workers,
        Err(abort) => return Some(abort),
    };
    if let Err(abort) = supervise::ready(link, parsed, booted, &mut workers) {
        workers.stop();
        return Some(abort);
    }
    let Some(descriptors) = descriptors else {
        workers.stop();
        return Some(Abort::Refused("no descriptor socket".into()));
    };
    let end = supervise::steady(link, booted, &mut workers, &descriptors);
    let reported = match end {
        SteadyEnd::VmExited => Some(SupervisorEvent::VmExited),
        SteadyEnd::Retire(reason) => Some(SupervisorEvent::Retire { reason }),
        SteadyEnd::Revoked | SteadyEnd::HelperGone => None,
    };
    // Contain first: a breach retires the VM before anything is reported.
    let _ = super::supervisor::contain(parsed, created);
    workers.stop();
    // A subreaper accumulates no zombies; R and D were reaped by their handles above.
    super::supervisor::reap_strays(&[]);
    if let Some(event) = reported {
        link.event(&event);
        loop {
            link.beat();
            if link.poll(Duration::from_millis(20)).is_err() {
                break;
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn real_supervisor(
    context: &mut SupervisorContext,
    _: &str,
    _: &[ExecutableIdentity],
    _: u64,
    _: u64,
) {
    let _ = context.control.send(
        0,
        &SupervisorEvent::LaunchRefused {
            reason: "real launches need Linux".into(),
        },
        Duration::from_secs(1),
    );
    send_watch_byte(&context.watch, b'E');
}

/// A cleanup-only S: contain, unmount, detach and remove, then report and exit.
#[cfg(target_os = "linux")]
fn real_cleanup(
    context: &mut SupervisorContext,
    plan: &str,
    resources: &super::supervisor::RecordedResources,
    deadline_ns: u64,
) {
    use super::supervisor::{Abort, LaunchPlan, Link};
    let event = match LaunchPlan::parse(plan.as_bytes()) {
        Err(error) => SupervisorEvent::CleanupFailed {
            reason: error.to_string(),
        },
        Ok(parsed) => {
            let mut link = Link::new(context, deadline_ns);
            // A tree that still exists charges this work to its allocation.
            if let Some(identity) = &resources.cgroup
                && super::cgroup::exists(&parsed.cgroup).unwrap_or(false)
            {
                let _ = super::cgroup::join(
                    &format!("{}/control", parsed.cgroup),
                    identity.control_ino,
                );
            }
            let result = super::supervisor::cleanup(&mut link, &parsed, resources);
            drop(link);
            match result {
                Ok(()) => SupervisorEvent::CleanedUp,
                Err(Abort::Refused(reason)) => SupervisorEvent::CleanupFailed { reason },
                Err(other) => SupervisorEvent::CleanupFailed {
                    reason: format!("{other:?}"),
                },
            }
        }
    };
    let _ = context.control.send(0, &event, Duration::from_secs(1));
    send_watch_byte(&context.watch, b'E');
}

#[cfg(not(target_os = "linux"))]
fn real_cleanup(
    context: &mut SupervisorContext,
    _: &str,
    _: &super::supervisor::RecordedResources,
    _: u64,
) {
    let _ = context.control.send(
        0,
        &SupervisorEvent::CleanupFailed {
            reason: "cleanup needs Linux".into(),
        },
        Duration::from_secs(1),
    );
    send_watch_byte(&context.watch, b'E');
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
        super::proven::stop_process(target);
    }
}

#[cfg(test)]
// Approved (design 7.1): the fake runtime's marker files, compiled only under cfg(test).
#[allow(clippy::disallowed_methods)]
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
            if let ProcessState::Running { start_time } = process_state(pid)
                && let Ok(target) = ProcessId::of_this_boot(pid, start_time)
            {
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
        allocation: AllocationKey,
    },
    /// The conditional stop authority's concrete target, before it could be needed.
    RegisterTarget {
        allocation: AllocationKey,
        target: super::monitor::StopTarget,
    },
    Forget {
        allocation: AllocationKey,
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
        stale_supervisors: Vec<AllocationKey>,
    },
    SupervisorLost {
        allocation: AllocationKey,
    },
    Contained {
        allocation: AllocationKey,
        gone: bool,
    },
    /// Both fixed recovery slots are occupied. The target stays pending in M.
    NoRecovery {
        allocation: AllocationKey,
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
    targets: HashMap<AllocationKey, super::monitor::StopTarget>,
    /// Waiting for a free slot, in arrival order.
    pending: std::collections::VecDeque<AllocationKey>,
    /// Which allocation each K slot is working on.
    busy: Vec<Option<AllocationKey>>,
    /// Proven gone: nothing further to dispatch.
    finished: std::collections::HashSet<AllocationKey>,
    reported_blocked: std::collections::HashSet<AllocationKey>,
    /// Stop requested before H registered any concrete target.
    awaiting_target: std::collections::HashSet<AllocationKey>,
}

impl StopQueue {
    fn new(slots: usize) -> Self {
        Self {
            busy: vec![None; slots],
            ..Self::default()
        }
    }

    /// Requests a stop, once. A target that arrives later inherits an open request.
    fn request(&mut self, allocation: AllocationKey) {
        if !self.finished.contains(&allocation)
            && !self.pending.contains(&allocation)
            && !self.busy.contains(&Some(allocation))
        {
            self.pending.push_back(allocation);
        }
    }

    fn request_all(&mut self) {
        let all: Vec<AllocationKey> = self.targets.keys().copied().collect();
        for allocation in all {
            self.request(allocation);
        }
    }

    /// A K slot's answer frees that slot; an unproven stop waits its turn again.
    fn settle(&mut self, index: usize, allocation: AllocationKey, gone: bool) {
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
    fn dispatch(&mut self, recovery: &[UnixDatagram]) -> Vec<AllocationKey> {
        let mut index = 0;
        while index < self.busy.len() && !self.pending.is_empty() {
            if self.busy[index].is_some() {
                index += 1;
                continue;
            }
            let allocation = self.pending.pop_front().expect("checked nonempty");
            // No concrete target yet: the request stays open for when H registers one.
            let Some(target) = self.targets.get(&allocation).cloned() else {
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
    pub allocation: AllocationKey,
    pub target: super::monitor::StopTarget,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecoveryDatagramReply {
    pub allocation: AllocationKey,
    pub gone: bool,
}

struct Watch {
    allocation: AllocationKey,
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
    #[cfg(target_os = "linux")]
    crate::process::require_firecracker_launch_capabilities_dropped();
    let mut watches: Vec<Watch> = Vec::new();
    let mut stops = StopQueue::new(sockets.recovery.len());
    let mut stale_requested: std::collections::HashSet<AllocationKey> = Default::default();
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
                                stops
                                    .targets
                                    .entry(allocation)
                                    .and_modify(|known| known.merge(&target))
                                    .or_insert(target);
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
        target: super::monitor::StopTarget,
    },
    /// Whether a target is provably gone. Its process carries its own boot ID.
    Probe {
        target: super::monitor::StopTarget,
    },
    /// Removes an allocation's empty cgroup tree after S exited (section 6.4).
    RemoveCgroup {
        relative: String,
        identity: Option<super::cgroup::CgroupIdentity>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryReply {
    Killed {
        gone: bool,
    },
    Probed {
        gone: bool,
    },
    Removed {
        state: Option<super::cgroup::NodeState>,
    },
}

#[cfg(target_os = "linux")]
fn cgroup_empty(target: Option<&super::cgroup::CgroupStopTarget>) -> bool {
    let Some(target) = target else { return true };
    super::cgroup::vm_empty(&target.relative, target.identity.as_ref())
}

#[cfg(not(target_os = "linux"))]
fn cgroup_empty(target: Option<&super::cgroup::CgroupStopTarget>) -> bool {
    target.is_none()
}

fn remove_cgroup(
    relative: &str,
    identity: Option<&super::cgroup::CgroupIdentity>,
) -> Option<super::cgroup::NodeState> {
    super::cgroup::remove_tree(relative, identity).ok()
}

/// K: independent of L and S. It uses already-authorized identity only and never
/// hashes, formats, inventories or waits on the ledger. Its result is evidence for
/// containment, never a durable receipt.
pub fn recovery_main(mut endpoint: Endpoint, monitor: UnixDatagram, mut heartbeat: Heartbeat) {
    #[cfg(target_os = "linux")]
    crate::process::require_firecracker_launch_capabilities_dropped();
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
        // A stop target carries the whole journaled tree identity and the VMM's boot ID:
        // a truncated datagram would fail to parse and stop nothing.
        let mut bytes = [0u8; 8192];
        while let Ok(n) = monitor.recv(&mut bytes) {
            if n == 0 {
                last_dispatch = std::time::Instant::now();
                continue;
            }
            if let Ok(request) = serde_json::from_slice::<RecoveryDatagram>(&bytes[..n]) {
                last_dispatch = std::time::Instant::now();
                fault_point("K.kill");
                let gone = super::monitor::execute(&request.target);
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
                            gone: super::monitor::execute(&target),
                        }
                    }
                    RecoveryRequest::Probe { target } => {
                        // Gone only when proven: a missing boot ID with a matching PID
                        // and start time is Unknown, not gone.
                        let process_gone = target
                            .process
                            .is_none_or(|process| super::proven::process_gone(&process));
                        RecoveryReply::Probed {
                            gone: process_gone && cgroup_empty(target.cgroup.as_ref()),
                        }
                    }
                    RecoveryRequest::RemoveCgroup { relative, identity } => {
                        fault_point("K.remove_cgroup");
                        RecoveryReply::Removed {
                            state: remove_cgroup(&relative, identity.as_ref()),
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
        let error = loop {
            match sender.send(1, &body, Duration::from_millis(10)) {
                Ok(()) => delivered += 1,
                Err(error) => break error,
            }
            assert!(delivered < 64, "the kernel buffer should have filled");
        };
        // Whatever arrives is whole frames, then EOF if a frame was torn: never a
        // frame stitched from a given-up tail and a later send.
        let poisoned = sender.is_poisoned();
        assert_eq!(poisoned, partial_send(&error), "{error}");
        let later = sender.send(2, &body, Duration::from_secs(1));
        if poisoned {
            let later = later.expect_err("a poisoned endpoint refuses every later send");
            assert!(partial_send(&later));
        }
        drop(sender);
        let mut frames = 0;
        loop {
            match receiver.receive::<Vec<u8>>(Duration::from_millis(200)) {
                Ok(Received::Message { id, body, .. }) => {
                    assert_eq!(body.len(), MAX_IPC_FRAME / 8);
                    assert!(!poisoned || id == 1, "nothing after the torn frame");
                    frames += 1;
                }
                Ok(Received::Idle) => {}
                Ok(Received::Closed) | Err(_) => break,
            }
        }
        assert!(frames >= delivered, "{frames} {delivered}");
    }

    fn small_send_buffer(stream: &std::os::unix::net::UnixStream) {
        let bytes: libc::c_int = 4096;
        // SAFETY: the option pointer and size describe a live c_int.
        let rc = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&bytes as *const libc::c_int).cast(),
                std::mem::size_of_val(&bytes) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    }

    /// B5-03 (Daybreak's `endpoint_resume`): a frame that timed out after a partial
    /// write is never completed by the next send. The endpoint is poisoned, the second
    /// send fails with the stored error, and the receiver sees no frame 101.
    #[test]
    fn b5_03_a_timed_out_partial_frame_is_never_delivered_later() {
        #[derive(Debug, Deserialize, Serialize)]
        struct Job {
            generation: u64,
            payload: String,
        }
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        small_send_buffer(&sender);
        let mut sender = Endpoint::new(sender);
        let first = Job {
            generation: 1,
            payload: "A".repeat(900_000),
        };
        let error = sender
            .send(101, &first, Duration::from_millis(5))
            .expect_err("a peer that never reads must time out after a partial write");
        assert!(partial_send(&error), "{error}");
        assert!(sender.is_poisoned());
        let reader = std::thread::spawn(move || {
            let mut receiver = Endpoint::new(receiver);
            let end = std::time::Instant::now() + Duration::from_secs(5);
            let mut seen = Vec::new();
            while std::time::Instant::now() < end {
                match receiver.receive::<Job>(Duration::from_millis(50)) {
                    Ok(Received::Message { id, body, .. }) => {
                        seen.push((id, body.generation, body.payload.len()))
                    }
                    Ok(Received::Idle) => {}
                    Ok(Received::Closed) | Err(_) => break,
                }
            }
            seen
        });
        let second = Job {
            generation: 2,
            payload: "B".repeat(32),
        };
        let later = sender
            .send(102, &second, Duration::from_secs(5))
            .expect_err("the poisoned endpoint refuses the next frame");
        assert!(partial_send(&later), "{later}");
        drop(sender);
        assert_eq!(reader.join().unwrap(), Vec::<(u64, u64, usize)>::new());
    }

    /// B5-01 defense in depth: an `AllocationState` larger than one frame (Daybreak's
    /// 5,890 Exec rows) is answered with a typed refusal, and L's endpoint stays up.
    #[test]
    fn b5_01_an_oversized_ledger_answer_is_refused_and_l_stays_up() {
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut l = Endpoint::new(left);
        let mut h = Endpoint::new(right);
        let record = super::super::supervisor::ResourceRecord::Exec {
            token: "00112233445566778899aabbccddeeff".into(),
            execution_id: "ex-00112233445566778899aabbccddeeff".into(),
            boot_id: "00112233-4455-6677-8899-aabbccddeeff".into(),
            state: "interrupted".into(),
        };
        let state = LedgerReply::State(Some(Box::new(super::super::journal::AllocationState {
            sandbox_id: "sb-00112233445566778899aabbccddeeff".into(),
            plan_digest: crate::model::Digest::of(b"plan"),
            phase: "stop_intent".into(),
            created_generation: 1,
            plan: b"{}".to_vec(),
            resources: vec![record; 5_890],
        })));
        let reader = std::thread::spawn(move || {
            let mut answers = Vec::new();
            while answers.len() < 2 {
                match h.receive::<LedgerReply>(Duration::from_secs(2)).unwrap() {
                    Received::Message { id, body, .. } => answers.push((id, body)),
                    Received::Idle => {}
                    Received::Closed => break,
                }
            }
            answers
        });
        send_ledger_reply(&mut l, 7, &state).unwrap();
        send_ledger_reply(&mut l, 8, &LedgerReply::Done).unwrap();
        let answers = reader.join().unwrap();
        assert!(
            matches!(&answers[0], (7, LedgerReply::Oversized { bytes }) if *bytes > MAX_IPC_FRAME as u64),
            "{answers:?}"
        );
        assert!(matches!(answers[1], (8, LedgerReply::Done)));
        assert!(!l.is_poisoned());
    }

    /// A frame that cannot be encoded is refused before any byte: the endpoint stays
    /// usable (L answers such a reply with a typed refusal, B5-01).
    #[test]
    fn an_oversized_frame_is_refused_without_poisoning() {
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sender = Endpoint::new(left);
        let mut receiver = Endpoint::new(right);
        let huge = vec![0u8; MAX_IPC_FRAME];
        let error = sender
            .send(1, &huge, Duration::from_millis(50))
            .unwrap_err();
        assert!(!partial_send(&error));
        assert!(!sender.is_poisoned());
        sender
            .send(2, &"small".to_string(), Duration::from_secs(1))
            .unwrap();
        match receiver
            .receive::<String>(Duration::from_millis(500))
            .unwrap()
        {
            Received::Message { id, body, .. } => assert_eq!((id, body.as_str()), (2, "small")),
            _ => panic!("no message"),
        }
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
        // The same allocation ID in another instance is a separate stop.
        let shared = Id128::from_bytes([9; 16]);
        let ids: Vec<AllocationKey> = (1..=3)
            .map(|n| AllocationKey {
                instance: Id128::from_bytes([n; 16]),
                allocation: shared,
            })
            .collect();
        for (index, id) in ids.iter().enumerate() {
            queue.targets.insert(
                *id,
                super::super::monitor::StopTarget::process(ProcessId {
                    pid: 1000 + index as i32,
                    start_time: 1,
                    boot_id: None,
                }),
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
        assert!(super::super::proven::stop_process(&ProcessId {
            pid: me,
            start_time: start_time + 1,
            boot_id: Some(host_boot_id().unwrap()),
        }));
        assert_eq!(process_state(me), ProcessState::Running { start_time });
        assert!(host_boot_id().is_ok());
    }
}
