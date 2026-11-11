use super::firecracker::peer::{PeerCredentials, PeerPin};
use super::firecracker::{Node, WireDeadline};
use super::protocol::*;
use super::{fds, socket::Socket, write_frame};
use crate::model::CreateCertainty;
use crate::runtime::{ExecFinish, ExecSpec, Runtime, kiln_direct::DirectKilnRuntime};
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Connections being framed and classified, each for at most two seconds. A peer that
/// keeps more than this many silent connections open can still delay framing itself;
/// nothing can make every raw connection fair. The guarantees are below: an enrolled
/// account always has its own few, and once framed, a recovery request has dispatch
/// capacity that normal operations can never occupy.
const FRAMING_SLOTS: usize = 128;
/// Framing slots only this enrolled account can use, so another account holding every
/// shared one can't keep it from reaching its attach queue. Enrollment bounds the total.
const RESERVED_FRAMING_SLOTS: usize = 4;
/// Section 6.1's 64 operations: 60 for anything, 4 reserved for inspection and recovery.
const NORMAL_OPERATION_SLOTS: usize = 60;
const RESERVED_RECOVERY_SLOTS: usize = 4;

/// The separate capacities of one listener.
struct Budgets {
    framing: Arc<Semaphore>,
    reserved_framing: std::sync::Mutex<HashMap<u32, Arc<Semaphore>>>,
    normal: Arc<Semaphore>,
    recovery: Arc<Semaphore>,
}

impl Budgets {
    fn new() -> Self {
        Self {
            framing: Arc::new(Semaphore::new(FRAMING_SLOTS)),
            reserved_framing: Default::default(),
            normal: Arc::new(Semaphore::new(NORMAL_OPERATION_SLOTS)),
            recovery: Arc::new(Semaphore::new(RESERVED_RECOVERY_SLOTS)),
        }
    }

    /// A framing slot for this connection: an enrolled account's own first, so its other
    /// connections leave the shared ones free, and the shared ones after that.
    fn admit_framing(&self, uid: u32, enrolled: bool) -> Option<OwnedSemaphorePermit> {
        if enrolled {
            let reserved = self
                .reserved_framing
                .lock()
                .unwrap()
                .entry(uid)
                .or_insert_with(|| Arc::new(Semaphore::new(RESERVED_FRAMING_SLOTS)))
                .clone();
            if let Ok(permit) = reserved.try_acquire_owned() {
                return Some(permit);
            }
        }
        self.framing.clone().try_acquire_owned().ok()
    }

    /// A slot for a classified request. Recovery prefers its reserve and may use a free
    /// normal slot; a normal operation can never take a reserved one.
    fn admit(&self, recovery: bool) -> Option<OwnedSemaphorePermit> {
        if recovery {
            self.recovery
                .clone()
                .try_acquire_owned()
                .or_else(|_| self.normal.clone().try_acquire_owned())
                .ok()
        } else {
            self.normal.clone().try_acquire_owned().ok()
        }
    }
}

/// Listener ownership is supplied by systemd's root-owned socket unit. The
/// numeric service UID comes only from the root-controlled account database.
pub async fn serve(
    listener: UnixListener,
    uid: u32,
    bin: PathBuf,
    shutdown: CancellationToken,
) -> io::Result<()> {
    serve_with_firecracker(listener, uid, bin, None, shutdown).await
}

/// `firecracker` is present only under an explicit root policy. Its absence leaves
/// the group answering Disabled and every kiln behavior byte-identical.
pub async fn serve_with_firecracker(
    listener: UnixListener,
    uid: u32,
    bin: PathBuf,
    firecracker: Option<Arc<Node>>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let runtime = Arc::new(DirectKilnRuntime::new(bin));
    let budgets = Arc::new(Budgets::new());
    let tasks = TaskTracker::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => result?,
        };
        let stream = accepted.0;
        // Reject before reading any attacker-controlled frame (including root). Darwin
        // refuses this query once a peer has gone, which must not end the listener.
        let Ok(peer_uid) = stream.peer_cred().map(|peer| peer.uid()) else {
            continue;
        };
        // The kiln account, or an account root enrolled for a Firecracker instance.
        let enrolled = firecracker.as_ref().is_some_and(|n| n.admits_uid(peer_uid));
        if peer_uid != uid && !enrolled {
            continue;
        }
        let Some(framing) = budgets.admit_framing(peer_uid, enrolled) else {
            continue;
        };
        let runtime = runtime.clone();
        let stop = shutdown.child_token();
        let firecracker = firecracker.clone();
        let budgets = budgets.clone();
        tasks.spawn(async move {
            let legacy = peer_uid == uid;
            if let Err(error) =
                handle(stream, runtime, firecracker, legacy, framing, budgets, stop).await
            {
                tracing::warn!(%error, "helper request failed");
                #[cfg(test)]
                eprintln!("helper request error: {error}");
            }
        });
    }
    tasks.close();
    tasks.wait().await;
    Ok(())
}

async fn handle(
    stream: UnixStream,
    runtime: Arc<DirectKilnRuntime>,
    firecracker: Option<Arc<Node>>,
    legacy: bool,
    framing: OwnedSemaphorePermit,
    budgets: Arc<Budgets>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let mut stream = Socket(stream);
    let request = timeout(Duration::from_secs(2), async {
        let descriptors = fds::receive(&stream.0).await?;
        let request: Request = read_request(&mut stream).await?;
        request
            .validate(descriptors.len())
            .map_err(io::Error::other)?;
        Ok::<_, io::Error>(request)
    })
    .await
    .map_err(io::Error::other)??;
    // Framed and classified: this connection now competes for dispatch, not framing.
    drop(framing);
    let remaining = request.deadline_ns.saturating_sub(super::monotonic_ns()?);
    if remaining > (u64::from(request.timeout_ms) + 1) * 1_000_000 {
        return Err(io::Error::other("invalid monotonic deadline"));
    }
    let deadline = Instant::now() + Duration::from_nanos(remaining);
    let wire_deadline_ns = request.deadline_ns;
    let request = match request.operation {
        Operation::Firecracker(group) => {
            return firecracker_request(
                stream,
                group,
                firecracker,
                budgets,
                WireDeadline {
                    instant: deadline,
                    ns: wire_deadline_ns,
                },
                cancel,
            )
            .await;
        }
        // kiln's registry has no instances: it is the service account's alone, and an
        // enrolled account gets no answer about it at all.
        Operation::Kiln(_) if !legacy => return Ok(()),
        Operation::Kiln(op) => op,
    };
    // As before, an operation with no slot closes without a reply.
    let Some(_permit) = budgets.admit(request.is_recovery()) else {
        return Ok(());
    };
    // Only the opposite endpoints cross SCM_RIGHTS. Never share an open file
    // description for any endpoint on which the helper performs I/O.
    let mut stdio = None;
    let mut live = None;
    timeout(Duration::from_secs(2), async {
        if let KilnRequest::Exec {
            live: wants_live, ..
        } = &request
        {
            let (sockets, sender) = handoff_stdio_with(&mut stream, *wants_live)
                .await
                .map_err(|e| super::io_stage("stdio handoff", e))?;
            stdio = Some(sockets);
            live = sender;
        } else {
            fds::send(&stream.0, &[]).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(io::Error::other)??;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let operation = dispatch(request, stdio, live, &runtime, deadline, &cancel);
    tokio::pin!(operation);
    let response = tokio::select! {
        result = &mut operation => result?,
        // One cancellation byte, extra data, or EOF all request cancellation.
        _ = reader.read_u8() => { cancel.cancel(); operation.await? },
    };
    timeout(Duration::from_secs(2), write_frame(&mut writer, &response))
        .await
        .map_err(io::Error::other)??;
    writer
        .shutdown()
        .await
        .map_err(|e| super::io_stage("response shutdown", e))
}

/// SCM_RIGHTS keeps descriptors in flight, but Darwin can disconnect a Unix
/// endpoint if its last installed descriptor closes before recvmsg installs
/// the receiver's copy. Retain the sent endpoints until an explicit receipt.
/// No I/O is performed on these shared open file descriptions.
pub(super) async fn handoff_stdio(stream: &mut Socket) -> io::Result<[Socket; 3]> {
    Ok(handoff_stdio_with(stream, false).await?.0)
}

/// With `live` (ExecStream, design 5.1), a fourth descriptor: kilnd's end of a fresh
/// `SOCK_SEQPACKET` pair, after the three stdio sockets. The helper keeps the sending
/// end and, like the others, performs no I/O on it until the receipt.
async fn handoff_stdio_with(
    stream: &mut Socket,
    live: bool,
) -> io::Result<([Socket; 3], Option<OwnedFd>)> {
    let (input, input_peer) = UnixStream::pair()?;
    let (output, output_peer) = UnixStream::pair()?;
    let (error, error_peer) = UnixStream::pair()?;
    let live = live.then(super::live::pair).transpose()?;
    let mut sent = vec![
        input_peer.as_raw_fd(),
        output_peer.as_raw_fd(),
        error_peer.as_raw_fd(),
    ];
    sent.extend(live.as_ref().map(|(_, peer)| peer.as_raw_fd()));
    fds::send(&stream.0, &sent).await?;
    if stream.read_u8().await? != STDIO_RECEIVED {
        return Err(io::Error::other("missing stdio receipt"));
    }
    Ok((
        [Socket(input), Socket(output), Socket(error)],
        live.map(|(sender, _peer)| sender),
    ))
}

async fn read_request(stream: &mut Socket) -> io::Result<Request> {
    parse_request(&super::read_frame_bytes(stream).await?)
}

/// Parses a frame. A Firecracker frame must also be strict JSON as a whole, so a
/// duplicate key inside labels cannot pass; a kiln frame parses exactly as before.
/// The error the serve loop logs names only the failure's category and position:
/// serde's own text quotes the frame's values, an env value among them (break-it M3b
/// LOW 2). Tests also print the detail.
fn parse_request(bytes: &[u8]) -> io::Result<Request> {
    let request: Request = serde_json::from_slice(bytes).map_err(|error| {
        #[cfg(test)]
        eprintln!("helper request frame detail: {error}");
        let category = match error.classify() {
            serde_json::error::Category::Io => "unreadable",
            serde_json::error::Category::Syntax => "not JSON",
            serde_json::error::Category::Data => "not a valid request",
            serde_json::error::Category::Eof => "truncated",
        };
        io::Error::other(format!(
            "malformed helper request frame: {category} at line {} column {}",
            error.line(),
            error.column()
        ))
    })?;
    if matches!(request.operation, Operation::Firecracker(_)) {
        crate::firecracker::strict_json(bytes).map_err(|_error| {
            #[cfg(test)]
            eprintln!("helper request frame detail: {_error}");
            io::Error::other("malformed helper request frame: not strict JSON")
        })?;
    }
    Ok(request)
}

#[cfg(test)]
pub(super) fn parse_request_for_test(bytes: &[u8]) -> io::Result<Request> {
    parse_request(bytes)
}

/// One Firecracker request: no descriptors cross in either direction except B5 Exec's
/// three stdio sockets, and the reply is the separate `Response::Firecracker` branch. AttachInstance alone keeps its
/// connection: that connection's EOF is the detach.
async fn firecracker_request(
    stream: Socket,
    request: FirecrackerRequest,
    firecracker: Option<Arc<Node>>,
    budgets: Arc<Budgets>,
    deadline: WireDeadline,
    cancel: CancellationToken,
) -> io::Result<()> {
    let mut stream = stream;
    // Only B5's Exec hands out descriptors: the three opposite stdio endpoints, kept
    // until the caller's receipt, exactly as for kiln's Exec.
    let stdio = if matches!(request.operation, FirecrackerOperation::Exec { .. }) {
        let [input, output, error] = timeout(Duration::from_secs(2), handoff_stdio(&mut stream))
            .await
            .map_err(io::Error::other)??;
        let owned = |socket: Socket| -> io::Result<std::os::fd::OwnedFd> {
            Ok(socket.0.into_std()?.into())
        };
        Some([owned(input)?, owned(output)?, owned(error)?])
    } else {
        timeout(Duration::from_secs(2), fds::send(&stream.0, &[]))
            .await
            .map_err(io::Error::other)??;
        None
    };
    // The connector's own pidfd, taken before any reply. A kernel that can't supply one
    // gets no authority at all. A live connector holds its number, so the PID below is
    // really this connection's, and a socket left behind by a process whose PID was
    // later reused speaks for no one.
    let pin = PeerPin::of_connection(stream.0.as_raw_fd()).ok();
    let credentials = stream.0.peer_cred()?;
    let peer = PeerCredentials {
        pid: credentials
            .pid()
            .filter(|_| pin.as_ref().is_some_and(PeerPin::alive)),
        uid: credentials.uid(),
    };
    let instance = request.instance_id;
    let attach = matches!(
        request.operation,
        FirecrackerOperation::AttachInstance { .. }
    );
    let recovery = request.operation.is_recovery();
    // No common pool of attachments exists: each enrolled instance has its own one, and
    // anything else is refused at once by the node. A full operation budget answers at
    // once too: the last four operation slots serve only recovery.
    let operation_slot = (!attach).then(|| budgets.admit(recovery));
    let refused = matches!(operation_slot, Some(None));
    let (mut reader, mut writer) = tokio::io::split(stream);
    let waiter = cancel.child_token();
    let response = match &firecracker {
        None => FirecrackerResponse::disabled(&request.operation),
        Some(_) if refused => FirecrackerResponse::Error(GroupError::new(
            GroupErrorKind::ResourceExhausted,
            "only reserved recovery slots remain",
        )),
        Some(node) => {
            let operation = node.handle_with_stdio(request, peer, pin, deadline, &waiter, stdio);
            tokio::pin!(operation);
            tokio::select! {
                response = &mut operation => response,
                // One cancellation byte, extra data or EOF ends this waiter only.
                // Accepted work remains owned by the helper.
                _ = reader.read_u8() => { waiter.cancel(); operation.await }
            }
        }
    };
    let epoch = match &response {
        FirecrackerResponse::Attached {
            connection_epoch, ..
        } if attach => Some(*connection_epoch),
        _ => None,
    };
    let written = timeout(
        Duration::from_secs(2),
        write_frame(&mut writer, &Response::Firecracker(response)),
    )
    .await
    .map_err(io::Error::other)
    .and_then(|result| result);
    let (Some(epoch), Some(node)) = (epoch, firecracker) else {
        written?;
        return writer
            .shutdown()
            .await
            .map_err(|e| super::io_stage("response shutdown", e));
    };
    drop(operation_slot);
    if written.is_ok() {
        tokio::select! {
            _ = cancel.cancelled() => {}
            _ = hold_until_eof(&mut reader) => {}
        }
    }
    node.detach(instance, epoch);
    written
}

/// Discards bytes until EOF or an error; nothing on this connection is a request.
async fn hold_until_eof(reader: &mut (impl AsyncReadExt + Unpin)) {
    let mut bytes = [0u8; 64];
    while matches!(reader.read(&mut bytes).await, Ok(n) if n > 0) {}
}

async fn dispatch(
    op: KilnRequest,
    stdio: Option<[Socket; 3]>,
    live: Option<OwnedFd>,
    runtime: &DirectKilnRuntime,
    deadline: Instant,
    cancel: &CancellationToken,
) -> io::Result<Response> {
    let error = |e| Response::Error {
        error: e,
        definitely_not_created: false,
    };
    Ok(match op {
        KilnRequest::Capabilities { id: None } => runtime
            .version(deadline, cancel)
            .await
            .map(Response::Version)
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Features { id } => runtime
            .exec_features(id.as_deref(), deadline, cancel)
            .await
            .map(|(features, exec_options)| Response::Features {
                features,
                exec_options,
                exec_stream: super::live::supported(),
            })
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Capabilities { id: Some(id) } => runtime
            .validate_sandbox(&id, deadline, cancel)
            .await
            .map(|_| Response::Validated)
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Create { spec: _ } if Instant::now() >= deadline || cancel.is_cancelled() => {
            Response::Error {
                error: WireError::Backend("create expired before invocation".into()),
                definitely_not_created: true,
            }
        }
        KilnRequest::Create { spec } => runtime
            .create_until(&spec, deadline, cancel)
            .await
            .map(Response::Created)
            .unwrap_or_else(|e| Response::Error {
                definitely_not_created: e.certainty() == CreateCertainty::DefinitelyNotCreated,
                error: match e.error() {
                    crate::runtime::RuntimeError::Incompatible(s) => {
                        WireError::Incompatible(s.chars().take(2048).collect())
                    }
                    _ => WireError::Backend(e.to_string().chars().take(2048).collect()),
                },
            }),
        KilnRequest::Rm { id } => runtime
            .remove_until(&id, deadline, cancel)
            .await
            .map(|_| Response::Removed)
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Ls => runtime
            .list_until(deadline, cancel)
            .await
            .map(|rows| Response::Listed(rows.into_iter().map(Into::into).collect()))
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Gc { ids } => runtime
            .gc_until(&ids, deadline, cancel)
            .await
            .map(Response::Collected)
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Exec {
            id,
            argv,
            stdin_bytes,
            max_output,
            cwd,
            env,
            live: wants_live,
        } => {
            let [mut input, mut stdout, mut stderr] =
                stdio.ok_or_else(|| io::Error::other("missing helper stdio"))?;
            let live = match (wants_live, live) {
                (true, Some(fd)) => Some(super::live::LiveSender::new(fd)),
                (false, None) => None,
                _ => {
                    return Err(io::Error::other(
                        "live descriptor does not match the request",
                    ));
                }
            };
            let mut stdin = Vec::new();
            let mut bounded_input = (&mut input).take((MAX_STDIN + 1) as u64);
            tokio::select! {
                result = timeout_at(
                    deadline.min(Instant::now() + Duration::from_secs(2)),
                    bounded_input.read_to_end(&mut stdin),
                ) => { result.map_err(io::Error::other)??; },
                _ = cancel.cancelled() => return Err(io::Error::other("stdin canceled")),
            }
            if stdin.len() != stdin_bytes {
                return Err(io::Error::other(format!(
                    "stdin size mismatch: expected {stdin_bytes}, observed {}",
                    stdin.len()
                )));
            }
            let options = kilnd_exec_core::exec_options::ExecOptions { cwd, env };
            let spec = ExecSpec {
                argv: &argv,
                stdin: &stdin,
                deadline,
                max_output,
                options: &options,
                live: live
                    .clone()
                    .map(|live| live as std::sync::Arc<dyn crate::exec_stream::LiveTap>),
            };
            let outcome = runtime.exec_direct(&id, &spec, cancel).await;
            // Every capture reader has settled: end the live channel before the reply,
            // so kilnd has read every live message by the time it reads the result.
            if let Some(live) = &live {
                live.close();
                let (sent, dropped) = live.counts();
                tracing::debug!(sent, dropped, "live output channel closed");
            }
            // No stdio bytes appear in the control protocol, only evidence.
            let response = Response::Executed {
                finish: match outcome.finish {
                    Ok(ExecFinish::Completed) => WireFinish::Completed,
                    Ok(ExecFinish::TimedOut) => WireFinish::TimedOut,
                    Ok(ExecFinish::Canceled) => WireFinish::Canceled,
                    Err(e) => WireFinish::Failed(e),
                },
                status: outcome.command_status,
                stdout: CaptureInfo::of(&outcome.stdout),
                stderr: CaptureInfo::of(&outcome.stderr),
            };
            timeout(Duration::from_secs(2), async {
                tokio::try_join!(
                    async {
                        stdout
                            .write_all(&outcome.stdout.data)
                            .await
                            .map_err(|e| super::io_stage("stdout write", e))
                    },
                    async {
                        stderr
                            .write_all(&outcome.stderr.data)
                            .await
                            .map_err(|e| super::io_stage("stderr write", e))
                    }
                )?;
                tokio::try_join!(
                    async {
                        stdout
                            .shutdown()
                            .await
                            .map_err(|e| super::io_stage("stdout shutdown", e))
                    },
                    async {
                        stderr
                            .shutdown()
                            .await
                            .map_err(|e| super::io_stage("stderr shutdown", e))
                    }
                )?;
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(io::Error::other)??;
            response
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit1_normal_operations_cannot_take_reserved_recovery_slots() {
        let budgets = Budgets::new();
        let mut held: Vec<_> = (0..NORMAL_OPERATION_SLOTS)
            .map(|_| budgets.admit(false).expect("a normal slot"))
            .collect();
        // Sixty normal operations, including legacy ones: the sixty-first has no slot,
        // and all four reserved ones remain for recovery alone.
        assert!(budgets.admit(false).is_none());
        let recovery: Vec<_> = (0..RESERVED_RECOVERY_SLOTS)
            .map(|_| budgets.admit(true).expect("a reserved slot"))
            .collect();
        assert!(budgets.admit(true).is_none(), "the total is sixty-four");
        assert!(budgets.admit(false).is_none());
        // Recovery can also use a free normal slot, so it never starves when idle.
        held.pop();
        assert!(budgets.admit(true).is_some());
        drop(recovery);
        assert_eq!(budgets.framing.available_permits(), FRAMING_SLOTS);
        // Health and cleanup are the legacy requests that keep the reserve.
        for (request, reserved) in [
            (KilnRequest::Capabilities { id: None }, true),
            (KilnRequest::Features { id: None }, true),
            (KilnRequest::Rm { id: "ab".into() }, true),
            (KilnRequest::Gc { ids: vec![] }, true),
            (KilnRequest::Ls, false),
        ] {
            assert_eq!(request.is_recovery(), reserved, "{request:?}");
        }
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn b3r_03_an_account_holding_every_shared_framing_slot_leaves_others_theirs() {
        let budgets = Budgets::new();
        let (attacker, victim) = (1000, 1001);
        let mut held = Vec::new();
        while let Some(permit) = budgets.admit_framing(attacker, true) {
            held.push(permit);
        }
        assert_eq!(held.len(), FRAMING_SLOTS + RESERVED_FRAMING_SLOTS);
        // Nothing left for the kiln account's own unenrolled traffic, as before.
        assert!(budgets.admit_framing(2000, false).is_none());
        // The victim's own are untouched, and bounded too.
        for _ in 0..RESERVED_FRAMING_SLOTS {
            held.push(budgets.admit_framing(victim, true).unwrap());
        }
        assert!(budgets.admit_framing(victim, true).is_none());
        drop(held);
        assert!(budgets.admit_framing(2000, false).is_some());
    }
}
