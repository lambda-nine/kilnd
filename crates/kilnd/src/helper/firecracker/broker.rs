//! The host half of broker protocol version 1 (design 5.2, 5.3, 5.6) and the broker
//! relay R (section 6.4).
//!
//! R is one fork-only worker per allocation, forked by S after BOOTING into the
//! allocation's `relay` leaf and dropped to the allocation's own relay UID/GID with no
//! groups, no capabilities and no new privileges. It holds only its private control
//! stream and descriptor socket to S, and per job the descriptors S hands it: a vsock
//! connection S made as root (and checked against the journaled VMM), and for an
//! execution the three helper-side stdio sockets. R does every byte of guest-facing
//! parsing: `CONNECT 5252`, the bounded `OK <port>` reply, Hello, the request, the
//! cumulative budgets and deadlines of the protocol crate, and stdin and output
//! transfer. It never touches the root filesystem, the ledger or the public helper
//! socket; its reports are bounded typed events that S checks and forwards to H.

use std::io;
use std::time::Duration;

use kilnd_broker_protocol::budget::{Budget, ExchangeBudget, ExecBudget, SharedBudget};
use kilnd_broker_protocol::exchange::{HostConnection, HostEvent};
use kilnd_broker_protocol::message::{
    BrokerState, Cancel, CancelAck, Channel, ErrorReply, Exec, ExecResult, Hello, HelloReply,
    Initialize, Message, Probe, ProbeReply, Ready, SessionBinding, StdinEnd,
};
use kilnd_broker_protocol::stream::{Due, FrameReader, FrameWriter};
use kilnd_broker_protocol::{
    BROKER_PORT, BootId, Direction, Hex32, Id128, InnerId, MAX_DATA_PAYLOAD, MAX_REMAINING_MS,
    MAX_STDIN_BYTES, PROTOCOL_VERSION, STAGE_TIMEOUT, WorkUuid,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::{Instant, timeout_at};

/// Firecracker's host-initiated vsock handshake (design 5.2): the request, and the
/// longest acceptable `OK <decimal host port>\n` reply.
pub const CONNECT_REQUEST: &[u8] = b"CONNECT 5252\n";
pub const MAX_CONNECT_REPLY: usize = 32;

/// What the host requires of the guest it reaches: the binding it journaled, the work
/// UUID it formatted, and, once READY, the boot and inner sandbox it recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub binding: SessionBinding,
    pub work_uuid: WorkUuid,
    pub boot_id: Option<BootId>,
    pub inner_id: Option<InnerId>,
}

/// One job S gives R: one fresh connection, one operation. Deadlines are absolute
/// host `CLOCK_MONOTONIC` nanoseconds, the wire's own clock.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayJob {
    Initialize {
        job: u64,
        expected: Expected,
        init: Initialize,
        deadline_ns: u64,
    },
    Probe {
        job: u64,
        expected: Expected,
        probe: Probe,
        deadline_ns: u64,
    },
    Cancel {
        job: u64,
        expected: Expected,
        cancel: Cancel,
        deadline_ns: u64,
    },
    /// Descriptors: the vsock connection, then stdin, stdout and stderr.
    Exec {
        job: u64,
        expected: Expected,
        exec: Exec,
        deadline_ns: u64,
    },
}

impl RelayJob {
    pub fn job(&self) -> u64 {
        match self {
            Self::Initialize { job, .. }
            | Self::Probe { job, .. }
            | Self::Cancel { job, .. }
            | Self::Exec { job, .. } => *job,
        }
    }

    pub fn descriptors(&self) -> usize {
        match self {
            Self::Exec { .. } => 4,
            _ => 1,
        }
    }
}

/// What R reports. `dispatched` is false only with proof that no Exec byte was sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayReport {
    Ready {
        job: u64,
        hello: Box<HelloReply>,
        ready: Box<Ready>,
    },
    Probed {
        job: u64,
        reply: ProbeReply,
    },
    CancelAcked {
        job: u64,
        ack: CancelAck,
    },
    Accepted {
        job: u64,
        token: Id128,
    },
    Executed {
        job: u64,
        result: Box<ExecResult>,
        /// Every retained byte reached kilnd's stdout and stderr sockets.
        delivered: bool,
    },
    Refused {
        job: u64,
        error: ErrorReply,
        dispatched: bool,
    },
    Failed {
        job: u64,
        reason: String,
        dispatched: bool,
    },
}

impl RelayReport {
    pub fn job(&self) -> u64 {
        match self {
            Self::Ready { job, .. }
            | Self::Probed { job, .. }
            | Self::CancelAcked { job, .. }
            | Self::Accepted { job, .. }
            | Self::Executed { job, .. }
            | Self::Refused { job, .. }
            | Self::Failed { job, .. } => *job,
        }
    }

    /// The last report of its job.
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Accepted { .. })
    }
}

/// Why a relay job ended without its reply.
#[derive(Debug)]
enum Fail {
    Refused(ErrorReply),
    Broken(String),
}

impl From<kilnd_broker_protocol::ProtocolError> for Fail {
    fn from(error: kilnd_broker_protocol::ProtocolError) -> Self {
        Fail::Broken(error.to_string())
    }
}

fn stage() -> Instant {
    Instant::now() + STAGE_TIMEOUT
}

/// A host monotonic deadline as a tokio instant.
pub fn instant_of(deadline_ns: u64) -> Instant {
    let now = super::workers::monotonic_ns();
    Instant::now() + Duration::from_nanos(deadline_ns.saturating_sub(now))
}

/// Writes `CONNECT 5252` and reads `OK <port>\n` a byte at a time, so nothing of the
/// broker's first frame is consumed, all within `by`.
pub async fn connect_port<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    by: Instant,
) -> Result<u32, String> {
    let exchange = async {
        stream.write_all(CONNECT_REQUEST).await?;
        stream.flush().await?;
        let mut line = Vec::with_capacity(MAX_CONNECT_REPLY);
        loop {
            let mut byte = [0u8; 1];
            if stream.read(&mut byte).await? == 0 {
                return Err(io::Error::other("the VMM closed before OK"));
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(line);
            }
            if line.len() >= MAX_CONNECT_REPLY {
                return Err(io::Error::other("the VMM's reply exceeds 32 bytes"));
            }
        }
    };
    let line = timeout_at(by, exchange)
        .await
        .map_err(|_| "no OK from the VMM within its stage deadline".to_string())?
        .map_err(|e| e.to_string())?;
    let port = line
        .strip_prefix(b"OK ")
        .and_then(|rest| rest.strip_suffix(b"\n"))
        .filter(|digits| !digits.is_empty() && digits.len() <= 10)
        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
        .and_then(|digits| std::str::from_utf8(digits).ok()?.parse::<u32>().ok())
        .ok_or_else(|| "malformed OK reply from the VMM".to_string())?;
    let _ = BROKER_PORT;
    Ok(port)
}

/// Everything the host requires of a `HelloReply` beyond the exchange layer's
/// challenge echo. The guest's identity is compared with the host's own journal, not
/// trusted on its own.
pub fn check_hello(reply: &HelloReply, expected: &Expected) -> Result<(), String> {
    if reply.protocol != PROTOCOL_VERSION || reply.kiln.protocol != 1 {
        return Err("protocol or kiln protocol is not 1".into());
    }
    if reply.identity.binding() != expected.binding {
        return Err("the guest's identity is not this allocation's".into());
    }
    if reply.identity.work_uuid != expected.work_uuid || reply.work.uuid != expected.work_uuid {
        return Err("the guest's work disk is not this allocation's".into());
    }
    let work = &reply.work;
    if !(work.nosuid && work.nodev && work.noexec && work.prjquota) {
        return Err("the work disk lacks nosuid, nodev, noexec or project quota".into());
    }
    if !reply.hardening.all() {
        return Err(format!(
            "the guest's runtime hardening is incomplete: {:?}",
            reply.hardening
        ));
    }
    if let Some(boot) = &expected.boot_id
        && *boot != reply.boot_id
    {
        return Err("the guest booted again: its boot ID changed".into());
    }
    if let Some(inner) = &expected.inner_id
        && Some(inner) != reply.inner_id.as_ref()
    {
        return Err("the guest's inner sandbox is not the recorded one".into());
    }
    if reply.state == BrokerState::Faulted {
        return Err("the guest broker has faulted".into());
    }
    Ok(())
}

struct Link<S> {
    reader: FrameReader<ReadHalf<S>>,
    writer: FrameWriter<WriteHalf<S>>,
    conn: HostConnection,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Link<S> {
    async fn next<B: Budget>(&mut self, due: Due, budget: &mut B) -> Result<HostEvent, Fail> {
        let frame = self
            .reader
            .read_frame(due, budget)
            .await?
            .ok_or(kilnd_broker_protocol::ProtocolError::EofBeforeTerminal)?;
        Ok(self.conn.received(frame)?)
    }

    async fn request(&mut self, id: Id128, message: &Message, by: Instant) -> Result<(), Fail> {
        self.conn.sending(id, message)?;
        self.writer.send(id, message, by).await?;
        Ok(())
    }
}

/// Connects the port, then Hello: a fresh challenge and request ID per connection.
async fn open<S: AsyncRead + AsyncWrite + Unpin, B: Budget>(
    mut stream: S,
    expected: &Expected,
    channel: Channel,
    budget: &mut B,
) -> Result<(Link<S>, HelloReply), Fail> {
    let first = stage();
    connect_port(&mut stream, first)
        .await
        .map_err(Fail::Broken)?;
    let (read, write) = tokio::io::split(stream);
    let challenge = Hex32::random().map_err(|e| Fail::Broken(e.to_string()))?;
    let hello_id = Id128::random().map_err(|e| Fail::Broken(e.to_string()))?;
    let hello = Hello {
        protocol: PROTOCOL_VERSION,
        channel,
        challenge,
        expected: expected.binding.clone(),
    };
    let mut link = Link {
        reader: FrameReader::new(read, Direction::GuestToHost),
        writer: FrameWriter::new(write, Direction::HostToGuest),
        conn: HostConnection::new(hello_id, &hello),
    };
    link.writer
        .send(hello_id, &Message::Hello(hello), stage())
        .await?;
    match link.next(Due::By(stage()), budget).await? {
        HostEvent::HelloReply(reply) => {
            check_hello(&reply, expected).map_err(Fail::Broken)?;
            Ok((link, *reply))
        }
        HostEvent::Error(error) => Err(Fail::Refused(error)),
        other => Err(Fail::Broken(format!("unexpected {other:?}"))),
    }
}

fn failed(job: u64, fail: Fail, dispatched: bool) -> RelayReport {
    match fail {
        Fail::Refused(error) => RelayReport::Refused {
            job,
            error,
            dispatched,
        },
        Fail::Broken(reason) => RelayReport::Failed {
            job,
            reason,
            dispatched,
        },
    }
}

/// `Initialize` within `deadline`: the guest's persistent create and smoke exec.
pub async fn initialize<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    job: u64,
    expected: &Expected,
    init: Initialize,
    deadline: Instant,
) -> RelayReport {
    let run = async {
        let mut budget = ExchangeBudget::default();
        let (mut link, hello) = open(stream, expected, Channel::Control, &mut budget).await?;
        let id = Id128::random().map_err(|e| Fail::Broken(e.to_string()))?;
        link.request(id, &Message::Initialize(init), stage())
            .await?;
        let reply = link.next(Due::By(deadline), &mut budget).await?;
        link.reader.read_eof(stage()).await?;
        match reply {
            HostEvent::Reply(Message::Ready(ready)) => {
                if ready.binding != expected.binding
                    || ready.boot_id != hello.boot_id
                    || !ready.idle
                    || !ready.work_quota_verified
                    || ready.kiln.protocol != 1
                {
                    return Err(Fail::Broken(
                        "Ready does not bind this session, its boot or an idle quota-checked sandbox"
                            .into(),
                    ));
                }
                Ok(RelayReport::Ready {
                    job,
                    hello: Box::new(hello),
                    ready,
                })
            }
            HostEvent::Error(error) => Err(Fail::Refused(error)),
            other => Err(Fail::Broken(format!("unexpected {other:?}"))),
        }
    };
    run.await.unwrap_or_else(|fail| failed(job, fail, false))
}

/// `Probe`: the boot and inner sandbox, idle or busy. No create, restart or mutation.
pub async fn probe<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    job: u64,
    expected: &Expected,
    probe: Probe,
    deadline: Instant,
) -> RelayReport {
    let run = async {
        let mut budget = ExchangeBudget::default();
        let (mut link, _) = open(stream, expected, Channel::Control, &mut budget).await?;
        let id = Id128::random().map_err(|e| Fail::Broken(e.to_string()))?;
        let by = stage().min(deadline);
        link.request(id, &Message::Probe(probe), by).await?;
        let reply = link.next(Due::By(by), &mut budget).await?;
        link.reader.read_eof(by).await?;
        match reply {
            HostEvent::Reply(Message::ProbeReply(reply)) => Ok(RelayReport::Probed { job, reply }),
            HostEvent::Error(error) => Err(Fail::Refused(error)),
            other => Err(Fail::Broken(format!("unexpected {other:?}"))),
        }
    };
    run.await.unwrap_or_else(|fail| failed(job, fail, false))
}

/// `Cancel` on its own control connection, which never waits on the exec writer. With
/// the execution's shared budget, its frames count against that execution (design 5.6:
/// both channels count; Cancel is budgeted once per token).
pub async fn cancel<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    job: u64,
    expected: &Expected,
    cancel: Cancel,
    deadline: Instant,
    shared: Option<SharedBudget<ExecBudget>>,
) -> RelayReport {
    match shared {
        Some(budget) => cancel_with(stream, job, expected, cancel, deadline, budget).await,
        None => {
            cancel_with(stream, job, expected, cancel, deadline, ExchangeBudget::default()).await
        }
    }
}

async fn cancel_with<S: AsyncRead + AsyncWrite + Unpin, B: Budget>(
    stream: S,
    job: u64,
    expected: &Expected,
    cancel: Cancel,
    deadline: Instant,
    mut budget: B,
) -> RelayReport {
    let run = async {
        let (mut link, _) = open(stream, expected, Channel::Control, &mut budget).await?;
        let id = Id128::random().map_err(|e| Fail::Broken(e.to_string()))?;
        let by = stage().min(deadline);
        link.request(id, &Message::Cancel(cancel), by).await?;
        let reply = link.next(Due::By(by), &mut budget).await?;
        match reply {
            HostEvent::Reply(Message::CancelAck(ack)) => Ok(RelayReport::CancelAcked { job, ack }),
            HostEvent::Error(error) => Err(Fail::Refused(error)),
            other => Err(Fail::Broken(format!("unexpected {other:?}"))),
        }
    };
    run.await.unwrap_or_else(|fail| failed(job, fail, true))
}

/// The guest-relative budget at send time: rounded down, 1..=3,600,000 ms; zero
/// prevents dispatch (design 5.4).
pub fn remaining_ms(deadline: Instant) -> Option<u64> {
    let ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(MAX_REMAINING_MS)) as u64;
    (ms > 0).then_some(ms)
}

/// One execution. Stdin is read from kilnd first, so a short or late stdin fails before
/// any Exec byte is sent; from the Exec frame on, every failure is `dispatched`.
/// Retained output is held (at most the negotiated prefixes) until the `Result` is
/// validated, then written to kilnd's sockets within two seconds.
#[allow(clippy::too_many_arguments)]
pub async fn exec<S, I, O, E>(
    stream: S,
    job: u64,
    expected: &Expected,
    mut exec: Exec,
    deadline: Instant,
    mut stdin: I,
    mut stdout: O,
    mut stderr: E,
    mut budget: SharedBudget<ExecBudget>,
    accepted: impl FnOnce(Id128),
) -> RelayReport
where
    S: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let token = exec.token;
    // Before dispatch: stdin within two seconds or the remaining budget.
    let mut input = Vec::new();
    let read = timeout_at(
        stage().min(deadline),
        (&mut stdin)
            .take(MAX_STDIN_BYTES + 1)
            .read_to_end(&mut input),
    )
    .await;
    if !matches!(read, Ok(Ok(_))) || input.len() as u64 != exec.stdin_bytes {
        return RelayReport::Failed {
            job,
            reason: format!(
                "stdin: expected {} bytes, observed {} ({})",
                exec.stdin_bytes,
                input.len(),
                if read.is_err() {
                    "late"
                } else {
                    "short or failed"
                }
            ),
            dispatched: false,
        };
    }
    let (mut link, _) = match open(stream, expected, Channel::Exec, &mut budget).await {
        Ok(opened) => opened,
        Err(fail) => return failed(job, fail, false),
    };
    let Some(remaining) = remaining_ms(deadline) else {
        return RelayReport::Failed {
            job,
            reason: "no execution budget remained at dispatch".into(),
            dispatched: false,
        };
    };
    exec.remaining_ms = remaining;
    // From the first Exec byte on, the command may have started.
    let dispatched = async {
        link.request(token, &Message::Exec(exec), stage().min(deadline))
            .await?;
        match link
            .next(Due::By(stage().min(deadline)), &mut budget)
            .await?
        {
            HostEvent::Accepted => accepted(token),
            HostEvent::Error(error) => return Err(Fail::Refused(error)),
            other => return Err(Fail::Broken(format!("unexpected {other:?}"))),
        }
        let by = stage().min(deadline);
        for chunk in input.chunks(MAX_DATA_PAYLOAD) {
            let message = Message::Stdin(chunk.to_vec());
            link.conn.sending_stdin(token, &message)?;
            link.writer.send(token, &message, by).await?;
        }
        let end = Message::StdinEnd(StdinEnd {
            token,
            total: input.len() as u64,
        });
        link.conn.sending_stdin(token, &end)?;
        link.writer.send(token, &end, by).await?;
        drop(input);
        // The command's own time is the original deadline; once output starts, all of
        // it and the EOF settle within two seconds.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut due = Due::FirstByte {
            first: deadline,
            then: STAGE_TIMEOUT,
        };
        let result = loop {
            let event = link.next(due, &mut budget).await?;
            if let Some(first) = link.reader.first_byte_at() {
                due = Due::By(first + STAGE_TIMEOUT);
            }
            match event {
                HostEvent::Stdout(bytes) => out.extend_from_slice(&bytes),
                HostEvent::Stderr(bytes) => err.extend_from_slice(&bytes),
                HostEvent::Result(result) => break result,
                HostEvent::Error(error) => return Err(Fail::Refused(error)),
                other => return Err(Fail::Broken(format!("unexpected {other:?}"))),
            }
        };
        let Due::By(settle) = due else {
            return Err(Fail::Broken("no transfer deadline".into()));
        };
        link.reader.read_eof(settle).await?;
        Ok((result, out, err))
    }
    .await;
    let (result, out, err) = match dispatched {
        Ok(done) => done,
        Err(fail) => return failed(job, fail, true),
    };
    let delivered = timeout_at(stage(), async {
        stdout.write_all(&out).await?;
        stdout.shutdown().await?;
        stderr.write_all(&err).await?;
        stderr.shutdown().await?;
        Ok::<_, io::Error>(())
    })
    .await
    .is_ok_and(|written| written.is_ok());
    RelayReport::Executed {
        job,
        result,
        delivered,
    }
}

#[cfg(unix)]
pub mod relay {
    //! R's process: its control stream and descriptor socket to S, jobs on a
    //! current-thread runtime, at most one exec and one control job at a time.
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream as StdUnixStream};

    /// Most descriptors one job carries.
    const MAX_JOB_FDS: usize = 4;

    /// Sends `fds` tagged with a job number over a datagram socket.
    pub fn send_fds(socket: &UnixDatagram, tag: u64, fds: &[RawFd]) -> io::Result<()> {
        let payload = tag.to_be_bytes();
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let size = std::mem::size_of_val(fds);
        // SAFETY: CMSG_SPACE is a pure size computation.
        let space = unsafe { libc::CMSG_SPACE(size as u32) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: zero is a valid initial msghdr; every pointer below is live.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !fds.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = space as _;
            // SAFETY: the control buffer has room for one header and `size` bytes.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(size as u32) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    size,
                );
            }
        }
        // SAFETY: message describes live buffers.
        let rc = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if rc != payload.len() as isize {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receives one tagged descriptor message, if one is waiting. Truncated control
    /// data or a foreign shape is an error; every received descriptor is owned (and so
    /// closed) whatever happens next.
    pub fn recv_fds(socket: RawFd) -> io::Result<Option<(u64, Vec<OwnedFd>)>> {
        let mut payload = [0u8; 8];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: CMSG_SPACE is a pure size computation.
        let space = unsafe { libc::CMSG_SPACE((MAX_JOB_FDS * std::mem::size_of::<RawFd>()) as u32) }
            as usize;
        let mut control = vec![0u8; space];
        // SAFETY: zero is a valid initial msghdr; every pointer below is live.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        // SAFETY: message describes live buffers.
        let rc = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_DONTWAIT) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let mut fds = Vec::new();
        // SAFETY: the kernel filled the control buffer described by message.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let data = libc::CMSG_DATA(header).cast::<RawFd>();
                    for i in 0..bytes / std::mem::size_of::<RawFd>() {
                        let fd = std::ptr::read_unaligned(data.add(i));
                        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        fds.push(OwnedFd::from_raw_fd(fd));
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if rc != 8 || message.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() > MAX_JOB_FDS {
            return Err(io::Error::other("malformed descriptor message"));
        }
        Ok(Some((u64::from_be_bytes(payload), fds)))
    }

    fn stream_of(fd: OwnedFd) -> io::Result<tokio::net::UnixStream> {
        let stream = StdUnixStream::from(fd);
        stream.set_nonblocking(true)?;
        tokio::net::UnixStream::from_std(stream)
    }

    async fn read_job(
        control: &mut tokio::net::unix::OwnedReadHalf,
    ) -> io::Result<Option<RelayJob>> {
        let mut len = [0u8; 4];
        match control.read_exact(&mut len).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > super::super::workers::MAX_IPC_FRAME {
            return Err(io::Error::other("relay job frame size"));
        }
        let mut body = vec![0u8; len];
        control.read_exact(&mut body).await?;
        let envelope: super::super::workers::Envelope<RelayJob> =
            serde_json::from_slice(&body).map_err(io::Error::other)?;
        Ok(Some(envelope.body))
    }

    /// Waits up to two seconds for this job's descriptors. Any other tag is a breach.
    async fn job_fds(
        socket: &tokio::io::unix::AsyncFd<UnixDatagram>,
        job: u64,
        count: usize,
    ) -> io::Result<Vec<OwnedFd>> {
        let receive = async {
            loop {
                let mut guard = socket.readable().await?;
                match recv_fds(socket.get_ref().as_raw_fd()) {
                    Ok(Some(found)) => return Ok(found),
                    Ok(None) => guard.clear_ready(),
                    Err(error) => return Err(error),
                }
            }
        };
        let (tag, fds) = tokio::time::timeout(STAGE_TIMEOUT, receive)
            .await
            .map_err(|_| io::Error::other("job descriptors did not arrive"))??;
        if tag != job || fds.len() != count {
            return Err(io::Error::other("descriptors for another job"));
        }
        Ok(fds)
    }

    /// R's whole life: jobs until S closes the control stream.
    pub fn relay_main(control: StdUnixStream, descriptors: UnixDatagram) {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let _ = control.set_nonblocking(true);
            let _ = descriptors.set_nonblocking(true);
            let Ok(control) = tokio::net::UnixStream::from_std(control) else {
                return;
            };
            // SAFETY: an owned socket stays open and names the same description for
            // the AsyncFd's whole life.
            let Ok(descriptors) = (unsafe { tokio::io::unix::AsyncFd::register(descriptors) })
            else {
                return;
            };
            let (mut reader, mut writer) = control.into_split();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RelayReport>();
            tokio::task::spawn_local(async move {
                while let Some(report) = rx.recv().await {
                    let Ok(frame) =
                        super::super::workers::encode_frame(&super::super::workers::Envelope {
                            id: 0,
                            deadline_ns: 0,
                            body: &report,
                        })
                    else {
                        return;
                    };
                    if timeout_at(stage(), writer.write_all(&frame)).await.is_err() {
                        return;
                    }
                }
            });
            let busy = std::rc::Rc::new(std::cell::Cell::new((false, false)));
            let budgets: Budgets = Default::default();
            while let Ok(Some(job)) = read_job(&mut reader).await {
                let id = job.job();
                let fds = match job_fds(&descriptors, id, job.descriptors()).await {
                    Ok(fds) => fds,
                    Err(error) => {
                        let _ = tx.send(RelayReport::Failed {
                            job: id,
                            reason: error.to_string(),
                            dispatched: false,
                        });
                        // A lost or mismatched descriptor desynchronizes S and R.
                        return;
                    }
                };
                let exec = matches!(job, RelayJob::Exec { .. });
                let (exec_busy, control_busy) = busy.get();
                if (exec && exec_busy) || (!exec && control_busy) {
                    let _ = tx.send(RelayReport::Failed {
                        job: id,
                        reason: "that channel already has a job".into(),
                        dispatched: false,
                    });
                    continue;
                }
                busy.set(if exec {
                    (true, control_busy)
                } else {
                    (exec_busy, true)
                });
                let tx = tx.clone();
                let busy = busy.clone();
                let budgets = budgets.clone();
                tokio::task::spawn_local(async move {
                    let report = run_job(job, fds, &tx, &budgets).await;
                    let _ = tx.send(report);
                    let (e, c) = busy.get();
                    busy.set(if exec { (false, c) } else { (e, false) });
                });
            }
        });
    }

    /// Each in-flight execution's guest-to-host budget, by token, which its Cancel
    /// exchange also charges.
    type Budgets = std::rc::Rc<
        std::cell::RefCell<std::collections::HashMap<Id128, SharedBudget<ExecBudget>>>,
    >;

    async fn run_job(
        job: RelayJob,
        fds: Vec<OwnedFd>,
        tx: &tokio::sync::mpsc::UnboundedSender<RelayReport>,
        budgets: &Budgets,
    ) -> RelayReport {
        let id = job.job();
        let mut fds = fds.into_iter();
        let Some(Ok(vsock)) = fds.next().map(stream_of) else {
            return RelayReport::Failed {
                job: id,
                reason: "no usable vsock connection".into(),
                dispatched: false,
            };
        };
        match job {
            RelayJob::Initialize {
                expected,
                init,
                deadline_ns,
                ..
            } => initialize(vsock, id, &expected, init, instant_of(deadline_ns)).await,
            RelayJob::Probe {
                expected,
                probe: request,
                deadline_ns,
                ..
            } => probe(vsock, id, &expected, request, instant_of(deadline_ns)).await,
            RelayJob::Cancel {
                expected,
                cancel: request,
                deadline_ns,
                ..
            } => {
                let shared = budgets.borrow().get(&request.token).cloned();
                cancel(vsock, id, &expected, request, instant_of(deadline_ns), shared).await
            }
            RelayJob::Exec {
                expected,
                exec: request,
                deadline_ns,
                ..
            } => {
                let stdio: Vec<_> = fds.map(stream_of).collect();
                let [Ok(stdin), Ok(stdout), Ok(stderr)] =
                    <[_; 3]>::try_from(stdio).unwrap_or_else(|_| {
                        [
                            Err(io::Error::other("stdio")),
                            Err(io::Error::other("stdio")),
                            Err(io::Error::other("stdio")),
                        ]
                    })
                else {
                    return RelayReport::Failed {
                        job: id,
                        reason: "missing stdio descriptors".into(),
                        dispatched: false,
                    };
                };
                let token = request.token;
                let budget = SharedBudget::new(ExecBudget::new(
                    request.max_output,
                    request.max_output,
                ));
                budgets.borrow_mut().insert(token, budget.clone());
                let report = exec(
                    vsock,
                    id,
                    &expected,
                    request,
                    instant_of(deadline_ns),
                    stdin,
                    stdout,
                    stderr,
                    budget,
                    |token| {
                        let _ = tx.send(RelayReport::Accepted { job: id, token });
                    },
                )
                .await;
                budgets.borrow_mut().remove(&token);
                report
            }
        }
    }
}

/// H's broker commands to S, one job each.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerCommand {
    Probe {
        job: u64,
        deadline_ns: u64,
    },
    /// The three stdio descriptors arrive first, on S's descriptor socket, tagged
    /// with `job`.
    Exec {
        job: u64,
        exec: Exec,
        deadline_ns: u64,
    },
    Cancel {
        job: u64,
        cancel: Cancel,
        deadline_ns: u64,
    },
}

#[cfg(target_os = "linux")]
pub mod supervise {
    //! S's half: forking D and R after BOOTING, the root vsock connect checked against
    //! the journaled VMM, readiness through R, and the steady loop's broker duties.
    use super::relay::{recv_fds, send_fds};
    use super::*;
    use crate::helper::firecracker::proven::{self, Forked, UnreapedChild};
    use crate::helper::firecracker::supervisor::{
        Abort, Booted, ChildRole, LaunchPlan, Link, ResourceRecord, SupervisorRecord,
    };
    use crate::helper::firecracker::workers::{
        Endpoint, ProcessId, Received, SupervisorCommand, SupervisorEvent, monotonic_ns,
    };
    use kilnd_broker_protocol::message::GuestExecSpec;
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream as StdUnixStream};

    fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    /// Drops this single-threaded child to `uid`:`gid` with no groups, no
    /// capabilities and no new privileges, and proves it.
    fn drop_to(uid: u32, gid: u32) -> io::Result<()> {
        // SAFETY: plain credential calls in a single-threaded child.
        unsafe {
            cvt(libc::setgroups(0, std::ptr::null()))?;
            cvt(libc::setresgid(gid, gid, gid))?;
            cvt(libc::setresuid(uid, uid, uid))?;
        }
        if crate::sys::prctl::set_no_new_privs() != 0 {
            return Err(io::Error::last_os_error());
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        // SAFETY: three writable IDs.
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
        let mut header = crate::sys::CapHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut data = [crate::sys::CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        crate::sys::capget(&mut header, &mut data)?;
        let any = data
            .iter()
            .any(|d| d.effective | d.permitted | d.inheritable != 0);
        if (r, e, s) != (uid, uid, uid) || any {
            return Err(io::Error::other("credentials did not drop"));
        }
        Ok(())
    }

    /// A fork-only worker: dies with S, joins its leaf, drops credentials, keeps only
    /// `keep`, runs `body`. Never returns in the child.
    fn fork_worker(
        leaf: &str,
        leaf_ino: u64,
        uid: u32,
        gid: u32,
        keep: &[RawFd],
        body: impl FnOnce(),
    ) -> io::Result<UnreapedChild> {
        // SAFETY: the parent getpid has no preconditions.
        let parent = unsafe { libc::getpid() };
        // SAFETY: S is single-threaded; the child runs only this worker and exits.
        match unsafe { proven::fork_child() }? {
            Forked::Parent(child) => Ok(child),
            Forked::Child => {
                let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    // SAFETY: restoring default dispositions and ignoring SIGPIPE.
                    unsafe {
                        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGCHLD, libc::SIGHUP] {
                            libc::signal(signal, libc::SIG_DFL);
                        }
                        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                    }
                    super::super::executable::close_all_except(keep);
                    // SAFETY: getppid has no preconditions.
                    if crate::sys::prctl::set_parent_death_kill() != 0
                        || unsafe { libc::getppid() } != parent
                    {
                        return 120;
                    }
                    if crate::helper::firecracker::cgroup::join(leaf, leaf_ino).is_err() {
                        return 121;
                    }
                    if drop_to(uid, gid).is_err() {
                        return 122;
                    }
                    body();
                    0
                }));
                // SAFETY: leave without unwinding into S.
                unsafe { libc::_exit(code.unwrap_or(101)) }
            }
        }
    }

    fn identify(pid: i32) -> io::Result<ProcessId> {
        match super::super::workers::process_state(pid) {
            super::super::workers::ProcessState::Running { start_time } => {
                ProcessId::of_this_boot(pid, start_time)
            }
            _ => Err(io::Error::other("worker is gone")),
        }
    }

    pub struct Relay {
        child: UnreapedChild,
        control: Endpoint,
        descriptors: UnixDatagram,
    }

    pub struct Drainer {
        child: UnreapedChild,
        report: File,
    }

    /// The broker workers of one booted allocation.
    pub struct Workers {
        pub relay: Relay,
        pub drainer: Drainer,
        pub expected: Expected,
        next_job: u64,
    }

    impl Workers {
        fn job(&mut self) -> u64 {
            self.next_job += 1;
            // S's own jobs count down from the top; H's come from H.
            u64::MAX - self.next_job
        }

        /// Ends both workers: R's control EOF, then a bounded wait, then SIGKILL of
        /// whichever own child is still unreaped. D normally dies with the VM.
        pub fn stop(self) {
            let Workers {
                relay, mut drainer, ..
            } = self;
            let Relay {
                mut child,
                control,
                descriptors,
            } = relay;
            drop(control);
            drop(descriptors);
            for victim in [&mut child, &mut drainer.child] {
                let end = std::time::Instant::now() + Duration::from_secs(1);
                while matches!(victim.try_reap(), Ok(None)) {
                    if std::time::Instant::now() >= end {
                        victim.kill_unreaped();
                        let _ = victim.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    fn open_dir_at(dir: &File, name: &str) -> io::Result<File> {
        let name = CString::new(name).map_err(io::Error::other)?;
        // SAFETY: a relative name under a held directory descriptor.
        let fd = cvt(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: a new descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn socket_identity(run: &File, uid: u32) -> io::Result<(u64, u64)> {
        // SAFETY: zero is a valid stat buffer.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a fixed relative name under a held directory, not followed.
        cvt(unsafe {
            libc::fstatat(
                run.as_raw_fd(),
                c"vsock.sock".as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_uid != uid {
            return Err(io::Error::other(
                "the jail's vsock.sock is not the VMM's socket",
            ));
        }
        Ok((stat.st_dev, stat.st_ino))
    }

    /// The root connect to exactly this VM's vsock socket (design 5.2): the name is
    /// resolved beneath the held jail descriptor, never through a path from the plan;
    /// it must be a socket owned by the VMM's UID before and after; and the connected
    /// peer, by `SO_PEERCRED`, must be the journaled VMM process (S's own unreaped
    /// child, so its PID cannot be reused) with that UID. A substituted name, a
    /// symlink to another host socket or another process's listener is refused.
    pub fn connect_vsock(jail: &File, plan: &LaunchPlan, vmm: &ProcessId) -> io::Result<OwnedFd> {
        let run = open_dir_at(&open_dir_at(jail, "root")?, "run")?;
        let before = socket_identity(&run, plan.uid)?;
        // SAFETY: plain socket creation.
        let fd =
            cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
        // SAFETY: a new descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zero is a valid sockaddr_un; the name is short and NUL-terminated.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(b"vsock.sock\0") {
            *slot = *byte as libc::c_char;
        }
        let run_fd = run.as_raw_fd();
        let raw = socket.as_raw_fd();
        // The relative name resolves against a private working directory on a thread
        // of its own, so S's own working directory never changes.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // SAFETY: this thread's private filesystem context.
                    unsafe {
                        cvt(libc::unshare(libc::CLONE_FS))?;
                        cvt(libc::fchdir(run_fd))?;
                        cvt(libc::connect(
                            raw,
                            (&address as *const libc::sockaddr_un).cast(),
                            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                        ))?;
                    }
                    Ok::<_, io::Error>(())
                })
                .join()
                .map_err(|_| io::Error::other("connect thread panicked"))?
        })?;
        // SAFETY: zero is a valid ucred; the length is its size.
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: credentials and len describe a live buffer.
        cvt(unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut len,
            )
        })?;
        if credentials.pid != vmm.pid || credentials.uid != plan.uid {
            return Err(io::Error::other("the vsock peer is not the journaled VMM"));
        }
        if socket_identity(&run, plan.uid)? != before {
            return Err(io::Error::other("the vsock socket was replaced"));
        }
        Ok(socket)
    }

    fn relay_credentials(plan: &LaunchPlan) -> io::Result<(u32, u32)> {
        let recipe = &plan.launch["resource_recipe"]["relay_credentials"];
        let uid = recipe["uid"]
            .as_u64()
            .ok_or_else(|| io::Error::other("relay uid"))? as u32;
        let gid = recipe["gid"]
            .as_u64()
            .ok_or_else(|| io::Error::other("relay gid"))? as u32;
        if uid == 0 || gid == 0 || uid == plan.uid || gid == plan.gid {
            return Err(io::Error::other("relay credentials overlap"));
        }
        Ok((uid, gid))
    }

    /// The session binding and work UUID, from the very identity block S wrote.
    pub fn expected_of(plan: &LaunchPlan) -> io::Result<Expected> {
        let block = super::super::storage::identity_block(&plan.plan)?;
        let identity =
            kilnd_broker_protocol::identity::parse_block(&block).map_err(io::Error::other)?;
        Ok(Expected {
            binding: identity.binding(),
            work_uuid: identity.work_uuid,
            boot_id: None,
            inner_id: None,
        })
    }

    /// Forks D into `vm/console` as the VMM's U:G with the console pipe, and R into
    /// `relay` as the relay U:G with its private sockets, journaling each before use.
    pub fn start(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        booted: &mut Booted,
    ) -> Result<Workers, Abort> {
        link.step("broker_workers")?;
        let console = booted
            .console
            .take()
            .ok_or_else(|| Abort::Refused("no console pipe".into()))?;
        let console = console.into_fd();
        let mut pipe = [0 as RawFd; 2];
        // SAFETY: pipe2 fills two descriptors.
        cvt(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })?;
        // SAFETY: new descriptors this process owns.
        let (report_read, report_write) =
            unsafe { (File::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let console_leaf = format!("{}/vm/console", plan.cgroup);
        let console_raw = console.as_raw_fd();
        let report_raw = report_write.as_raw_fd();
        let drainer_child = fork_worker(
            &console_leaf,
            booted.cgroup.console_ino,
            plan.uid,
            plan.gid,
            &[console_raw, report_raw],
            || {
                // SAFETY: the kept descriptors are this process's own.
                let (console, report) = unsafe {
                    (
                        OwnedFd::from_raw_fd(console_raw),
                        OwnedFd::from_raw_fd(report_raw),
                    )
                };
                super::super::console::drainer_main(console, report);
            },
        )?;
        drop(console);
        drop(report_write);
        link.record(SupervisorRecord::Child {
            role: ChildRole::Console,
            process: identify(drainer_child.pid())?,
        })?;
        let (relay_uid, relay_gid) = relay_credentials(plan)?;
        let (control_s, control_r) = StdUnixStream::pair()?;
        let (fds_s, fds_r) = UnixDatagram::pair()?;
        let (control_raw, fds_raw) = (control_r.as_raw_fd(), fds_r.as_raw_fd());
        let relay_child = fork_worker(
            &format!("{}/relay", plan.cgroup),
            booted.cgroup.relay_ino,
            relay_uid,
            relay_gid,
            &[control_raw, fds_raw],
            || {
                // SAFETY: the kept descriptors are this process's own.
                let (control, fds) = unsafe {
                    (
                        StdUnixStream::from_raw_fd(control_raw),
                        UnixDatagram::from_raw_fd(fds_raw),
                    )
                };
                super::relay::relay_main(control, fds);
            },
        )?;
        drop(control_r);
        drop(fds_r);
        fds_s.set_nonblocking(true)?;
        link.record(SupervisorRecord::Child {
            role: ChildRole::Relay,
            process: identify(relay_child.pid())?,
        })?;
        Ok(Workers {
            relay: Relay {
                child: relay_child,
                control: Endpoint::new(control_s),
                descriptors: fds_s,
            },
            drainer: Drainer {
                child: drainer_child,
                report: report_read,
            },
            expected: expected_of(plan)?,
            next_job: 0,
        })
    }

    /// Something that ends the steady loop and retires the VM.
    fn breach(workers: &mut Workers) -> Option<String> {
        use std::io::Read;
        let mut byte = [0u8; 1];
        match workers.drainer.report.read(&mut byte) {
            Ok(1) if byte[0] == super::super::console::REPORT_RATE => {
                return Some("the console exceeded 1 MiB/s".into());
            }
            Ok(1) => return Some("the console drainer reported a counter overflow".into()),
            _ => {}
        }
        if !matches!(workers.drainer.child.try_reap(), Ok(None)) {
            return Some("the console drainer died".into());
        }
        if !matches!(workers.relay.child.try_reap(), Ok(None)) {
            return Some("the broker relay died".into());
        }
        None
    }

    fn submit(
        link: &Link<'_>,
        plan: &LaunchPlan,
        booted: &Booted,
        workers: &mut Workers,
        job: RelayJob,
        stdio: Vec<OwnedFd>,
    ) -> io::Result<()> {
        let _ = link;
        let vsock = connect_vsock(&booted.jail, plan, &booted.vmm)?;
        let mut fds = vec![vsock.as_raw_fd()];
        fds.extend(stdio.iter().map(AsRawFd::as_raw_fd));
        send_fds(&workers.relay.descriptors, job.job(), &fds)?;
        workers.relay.control.send(0, &job, Duration::from_secs(1))
    }

    fn next_report(workers: &mut Workers) -> Result<Option<RelayReport>, String> {
        match workers.relay.control.receive::<RelayReport>(Duration::ZERO) {
            Ok(Received::Message { body, .. }) => Ok(Some(body)),
            Ok(Received::Idle) => Ok(None),
            Ok(Received::Closed) => Err("the broker relay closed".into()),
            Err(error) => Err(format!("the broker relay sent a malformed report: {error}")),
        }
    }

    /// Readiness (design 5.3): Hello against the journaled identity, then Initialize
    /// with the plan's exact label-free spec, within the original Create deadline.
    /// Journals the broker's boot and inner identity, then READY.
    pub fn ready(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        booted: &Booted,
        workers: &mut Workers,
    ) -> Result<(BootId, InnerId), Abort> {
        link.step("broker_ready")?;
        let spec: GuestExecSpec =
            serde_json::from_value(plan.plan["substitutions"]["inner_spec"].clone())
                .map_err(|e| Abort::Refused(format!("plan inner spec: {e}")))?;
        let digest = spec.sha256();
        if digest != workers.expected.binding.guest_exec_spec_sha256 {
            return Err(Abort::Refused(
                "the inner spec does not match its identity".into(),
            ));
        }
        let job = workers.job();
        let request = RelayJob::Initialize {
            job,
            expected: workers.expected.clone(),
            init: Initialize {
                spec,
                guest_exec_spec_sha256: digest,
            },
            deadline_ns: link.deadline_ns(),
        };
        submit(link, plan, booted, workers, request, Vec::new())?;
        let report = loop {
            link.beat();
            if let Some(command) = link.poll(Duration::from_millis(5))? {
                return Err(Abort::Refused(format!("unexpected command {command:?}")));
            }
            if let Some(reason) = breach(workers) {
                return Err(Abort::Refused(reason));
            }
            match next_report(workers).map_err(Abort::Refused)? {
                Some(report) if report.job() == job => break report,
                Some(_) => return Err(Abort::Refused("a report for another job".into())),
                None => {}
            }
            if monotonic_ns() >= link.deadline_ns() {
                return Err(Abort::Expired);
            }
        };
        let (boot_id, inner_id) = match report {
            RelayReport::Ready { hello, ready, .. } => (hello.boot_id, ready.inner_id),
            RelayReport::Refused { error, .. } => {
                return Err(Abort::Refused(format!(
                    "the broker refused readiness: {:?} {}",
                    error.code, error.message
                )));
            }
            RelayReport::Failed { reason, .. } => {
                return Err(Abort::Refused(format!("readiness failed: {reason}")));
            }
            other => return Err(Abort::Refused(format!("unexpected {other:?}"))),
        };
        link.record(SupervisorRecord::Resource(ResourceRecord::Broker {
            boot_id: boot_id.to_string(),
            inner_id: inner_id.to_string(),
        }))?;
        link.record(SupervisorRecord::Phase {
            from: vec!["booting".into()],
            to: "ready".into(),
        })?;
        workers.expected.boot_id = Some(boot_id.clone());
        workers.expected.inner_id = Some(inner_id.clone());
        link.event(&SupervisorEvent::Ready {
            boot_id: boot_id.to_string(),
            inner_id: inner_id.to_string(),
        });
        Ok((boot_id, inner_id))
    }

    pub enum SteadyEnd {
        VmExited,
        Revoked,
        HelperGone,
        Retire(String),
    }

    /// H's broker command: connect, hand R the job and its descriptors. A failure
    /// before R has the job is reported as never dispatched.
    fn command(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        booted: &Booted,
        workers: &mut Workers,
        descriptors: &UnixDatagram,
        command: BrokerCommand,
    ) {
        let expected = workers.expected.clone();
        let (job, stdio, request) = match command {
            BrokerCommand::Probe { job, deadline_ns } => {
                let probe = Probe {
                    boot_id: expected.boot_id.clone().expect("ready"),
                    inner_id: expected.inner_id.clone().expect("ready"),
                };
                (
                    job,
                    Ok(Vec::new()),
                    RelayJob::Probe {
                        job,
                        expected,
                        probe,
                        deadline_ns,
                    },
                )
            }
            BrokerCommand::Cancel {
                job,
                cancel,
                deadline_ns,
            } => (
                job,
                Ok(Vec::new()),
                RelayJob::Cancel {
                    job,
                    expected,
                    cancel,
                    deadline_ns,
                },
            ),
            BrokerCommand::Exec {
                job,
                exec,
                deadline_ns,
            } => {
                let stdio = stdio_for(descriptors, job);
                (
                    job,
                    stdio,
                    RelayJob::Exec {
                        job,
                        expected,
                        exec,
                        deadline_ns,
                    },
                )
            }
        };
        let submitted = stdio.and_then(|stdio| submit(link, plan, booted, workers, request, stdio));
        if let Err(error) = submitted {
            link.event(&SupervisorEvent::Broker {
                report: RelayReport::Failed {
                    job,
                    reason: error.to_string(),
                    dispatched: false,
                },
            });
        }
    }

    /// H sends an execution's stdio before its command.
    fn stdio_for(descriptors: &UnixDatagram, job: u64) -> io::Result<Vec<OwnedFd>> {
        let end = std::time::Instant::now() + STAGE_TIMEOUT;
        loop {
            if let Some((tag, fds)) = recv_fds(descriptors.as_raw_fd())? {
                if tag != job || fds.len() != 3 {
                    return Err(io::Error::other("stdio for another execution"));
                }
                return Ok(fds);
            }
            if std::time::Instant::now() >= end {
                return Err(io::Error::other("the execution's stdio did not arrive"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The steady loop of a READY S: heartbeats, V's pidfd, D's and R's health, H's
    /// broker commands and R's reports, which S forwards. Any breach retires the VM.
    pub fn steady(
        link: &mut Link<'_>,
        booted: &mut Booted,
        workers: &mut Workers,
        descriptors: &UnixDatagram,
    ) -> SteadyEnd {
        let plan = booted.plan.clone();
        loop {
            link.beat();
            if super::super::supervisor::pidfd_exited(&booted.vmm_pidfd) {
                return SteadyEnd::VmExited;
            }
            if let Some(reason) = breach(workers) {
                return SteadyEnd::Retire(reason);
            }
            loop {
                match next_report(workers) {
                    Ok(Some(report)) => link.event(&SupervisorEvent::Broker { report }),
                    Ok(None) => break,
                    Err(reason) => return SteadyEnd::Retire(reason),
                }
            }
            match link.poll(Duration::from_millis(10)) {
                Ok(Some(SupervisorCommand::Broker(request))) => {
                    command(link, &plan, booted, workers, descriptors, request);
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(Abort::Revoked) => return SteadyEnd::Revoked,
                Err(_) => return SteadyEnd::HelperGone,
            }
        }
    }
}

#[cfg(test)]
mod tests;
