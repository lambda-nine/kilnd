use super::firecracker::peer::PeerPin;
use super::firecracker::{Node, WireDeadline};
use super::protocol::*;
use super::{fds, socket::Socket, write_frame};
use crate::model::CreateCertainty;
use crate::runtime::{ExecFinish, ExecSpec, Runtime, kiln_direct::DirectKilnRuntime};
use std::io;
use std::os::fd::AsRawFd;
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
/// nothing can make every raw connection fair. The guarantee is below: once framed, a
/// recovery request has dispatch capacity that normal operations can never occupy.
const FRAMING_SLOTS: usize = 128;
/// Section 6.1's 64 operations: 60 for anything, 4 reserved for inspection and recovery.
const NORMAL_OPERATION_SLOTS: usize = 60;
const RESERVED_RECOVERY_SLOTS: usize = 4;

/// The separate capacities of one listener.
struct Budgets {
    framing: Arc<Semaphore>,
    normal: Arc<Semaphore>,
    recovery: Arc<Semaphore>,
}

impl Budgets {
    fn new() -> Self {
        Self {
            framing: Arc::new(Semaphore::new(FRAMING_SLOTS)),
            normal: Arc::new(Semaphore::new(NORMAL_OPERATION_SLOTS)),
            recovery: Arc::new(Semaphore::new(RESERVED_RECOVERY_SLOTS)),
        }
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
        if !stream.peer_cred().is_ok_and(|peer| peer.uid() == uid) {
            continue;
        }
        let Ok(framing) = budgets.framing.clone().try_acquire_owned() else {
            continue;
        };
        let runtime = runtime.clone();
        let stop = shutdown.child_token();
        let firecracker = firecracker.clone();
        let budgets = budgets.clone();
        tasks.spawn(async move {
            if let Err(error) = handle(stream, runtime, firecracker, framing, budgets, stop).await {
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
        Operation::Kiln(op) => op,
    };
    // As before, an operation with no slot closes without a reply.
    let Some(_permit) = budgets.admit(request.is_recovery()) else {
        return Ok(());
    };
    // Only the opposite endpoints cross SCM_RIGHTS. Never share an open file
    // description for any endpoint on which the helper performs I/O.
    let mut stdio = None;
    timeout(Duration::from_secs(2), async {
        if matches!(request, KilnRequest::Exec { .. }) {
            stdio = Some(
                handoff_stdio(&mut stream)
                    .await
                    .map_err(|e| super::io_stage("stdio handoff", e))?,
            );
        } else {
            fds::send(&stream.0, &[]).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(io::Error::other)??;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let operation = dispatch(request, stdio, &runtime, deadline, &cancel);
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
    let (input, input_peer) = UnixStream::pair()?;
    let (output, output_peer) = UnixStream::pair()?;
    let (error, error_peer) = UnixStream::pair()?;
    fds::send(
        &stream.0,
        &[
            input_peer.as_raw_fd(),
            output_peer.as_raw_fd(),
            error_peer.as_raw_fd(),
        ],
    )
    .await?;
    if stream.read_u8().await? != STDIO_RECEIVED {
        return Err(io::Error::other("missing stdio receipt"));
    }
    Ok([Socket(input), Socket(output), Socket(error)])
}

/// Parses a frame. A Firecracker frame must also be strict JSON as a whole, so a
/// duplicate key inside labels cannot pass; a kiln frame parses exactly as before.
async fn read_request(stream: &mut Socket) -> io::Result<Request> {
    let bytes = super::read_frame_bytes(stream).await?;
    let request: Request = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if matches!(request.operation, Operation::Firecracker(_)) {
        crate::firecracker::strict_json(&bytes).map_err(io::Error::other)?;
    }
    Ok(request)
}

/// One Firecracker request: no descriptors cross, in either direction, and the reply
/// is the separate `Response::Firecracker` branch. AttachInstance alone keeps its
/// connection: that connection's EOF is the detach.
async fn firecracker_request(
    stream: Socket,
    request: FirecrackerRequest,
    firecracker: Option<Arc<Node>>,
    budgets: Arc<Budgets>,
    deadline: WireDeadline,
    cancel: CancellationToken,
) -> io::Result<()> {
    timeout(Duration::from_secs(2), fds::send(&stream.0, &[]))
        .await
        .map_err(io::Error::other)??;
    // The connector's own pidfd, taken before any reply. A kernel that can't supply one
    // gets no authority at all. A live connector holds its number, so the PID below is
    // really this connection's, and a socket left behind by a process whose PID was
    // later reused speaks for no one.
    let pin = PeerPin::of_connection(stream.0.as_raw_fd()).ok();
    let peer_pid = stream
        .0
        .peer_cred()?
        .pid()
        .filter(|_| pin.as_ref().is_some_and(PeerPin::alive));
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
            let operation = node.handle(request, peer_pid, pin, deadline, &waiter);
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
        } => {
            let [mut input, mut stdout, mut stderr] =
                stdio.ok_or_else(|| io::Error::other("missing helper stdio"))?;
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
            let spec = ExecSpec {
                argv: &argv,
                stdin: &stdin,
                deadline,
                max_output,
            };
            let outcome = runtime.exec_direct(&id, &spec, cancel).await;
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
            (KilnRequest::Rm { id: "ab".into() }, true),
            (KilnRequest::Gc { ids: vec![] }, true),
            (KilnRequest::Ls, false),
        ] {
            assert_eq!(request.is_recovery(), reserved, "{request:?}");
        }
    }
}
