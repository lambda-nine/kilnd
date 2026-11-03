use super::protocol::*;
use super::{fds, read_frame, write_frame};
use crate::model::{
    Captured, CleanupEvidence, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage,
    SandboxDisposition,
};
use crate::runtime::{ExecFinish, ExecOutcome, ExecSpec, legacy_exec_evidence};
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

pub(crate) struct Client {
    pub path: PathBuf,
    pub expected_uid: u32,
}

/// A live AttachInstance connection. Dropping it is the detach.
pub(crate) struct AttachedConnection {
    _stream: UnixStream,
}

fn request_for(operation: Operation, deadline: Instant) -> io::Result<Request> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .max(1);
    let deadline_ns = super::monotonic_ns()?
        .checked_add(
            u64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_nanos(),
            )
            .map_err(io::Error::other)?,
        )
        .ok_or_else(|| io::Error::other("helper deadline overflow"))?;
    let request = Request {
        version: VERSION,
        deadline_ns,
        timeout_ms: u32::try_from(remaining).map_err(io::Error::other)?,
        operation,
    };
    request.validate(0).map_err(io::Error::other)?;
    Ok(request)
}

fn group_deadline(operation: &FirecrackerOperation) -> Instant {
    Instant::now() + Duration::from_millis(u64::from(operation.timeout_ms()))
}

impl Client {
    pub async fn call(
        &self,
        operation: KilnRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> io::Result<Response> {
        self.exchange(Operation::Kiln(operation), deadline, cancel, None)
            .await
    }

    /// One typed Firecracker exchange. Budgets are the wire's, with the same transport
    /// allowances as kiln's controls. No descriptor travels either way.
    pub async fn firecracker(
        &self,
        request: FirecrackerRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> io::Result<FirecrackerResponse> {
        // A longer caller budget narrows to this operation's own; it never fails.
        let deadline = deadline.min(group_deadline(&request.operation));
        match self
            .exchange(Operation::Firecracker(request), deadline, cancel, None)
            .await?
        {
            Response::Firecracker(response) => Ok(response),
            _ => Err(io::Error::other("unexpected helper reply")),
        }
    }

    /// AttachInstance keeps its connection open: one reply, then no EOF until a side
    /// detaches. It fails only by not attaching, so there is nothing to clean up.
    pub async fn attach(
        &self,
        request: FirecrackerRequest,
        deadline: Instant,
    ) -> io::Result<(FirecrackerResponse, AttachedConnection)> {
        let deadline = deadline.min(group_deadline(&request.operation));
        let request = request_for(Operation::Firecracker(request), deadline)?;
        let mut stream = timeout_at(deadline, UnixStream::connect(&self.path))
            .await
            .map_err(io::Error::other)??;
        if stream.peer_cred()?.uid() != self.expected_uid {
            return Err(io::Error::other("helper is not root"));
        }
        let response_deadline = deadline + Duration::from_secs(2);
        let response = timeout_at(response_deadline, async {
            fds::send(&stream, &[]).await?;
            write_frame(&mut stream, &request).await?;
            if !fds::receive(&stream).await?.is_empty() {
                return Err(io::Error::other("wrong helper descriptor count"));
            }
            read_frame::<Response>(&mut stream).await
        })
        .await
        .map_err(io::Error::other)??;
        match response {
            Response::Firecracker(response) => {
                Ok((response, AttachedConnection { _stream: stream }))
            }
            _ => Err(io::Error::other("unexpected helper reply")),
        }
    }

    async fn exchange(
        &self,
        operation: Operation,
        deadline: Instant,
        cancel: &CancellationToken,
        stdio: Option<tokio::sync::oneshot::Sender<Vec<OwnedFd>>>,
    ) -> io::Result<Response> {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "helper deadline/cancellation before request",
            ));
        }
        let allowance = match &operation {
            Operation::Kiln(KilnRequest::Exec { .. }) => Duration::from_secs(70),
            Operation::Kiln(KilnRequest::Create { .. }) => Duration::from_secs(5),
            Operation::Kiln(KilnRequest::Capabilities { .. }) => Duration::from_secs(1),
            Operation::Firecracker(request) => match request.operation {
                FirecrackerOperation::Create { .. } => Duration::from_secs(5),
                FirecrackerOperation::Capabilities => Duration::from_secs(1),
                // After its deadline the helper still sends Cancel, waits up to two
                // seconds for the guest, then proves the VM subtree empty: the same
                // allowance as kiln's cleanup.
                FirecrackerOperation::Exec { .. } => Duration::from_secs(70),
                _ => Duration::from_secs(2),
            },
            _ => Duration::from_secs(2),
        };
        let response_deadline = deadline + allowance;
        // The group answers at its deadline and closes, so a cancel byte can race that
        // close. Its reply decides the result, not a failed courtesy write.
        let group = matches!(operation, Operation::Firecracker(_));
        let request = request_for(operation, deadline)?;
        let mut stream = timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(2)),
            UnixStream::connect(&self.path),
        )
        .await
        .map_err(io::Error::other)??;
        if stream.peer_cred()?.uid() != self.expected_uid {
            return Err(io::Error::other("helper is not root"));
        }
        timeout_at(deadline, async {
            fds::send(&stream, &[]).await?;

            write_frame(&mut stream, &request).await
        })
        .await
        .map_err(io::Error::other)??;
        let (mut reader, mut writer) = stream.into_split();
        let result = {
            let response = async {
                timeout_at(response_deadline, async {
                    let descriptors = fds::receive(reader.as_ref())
                        .await
                        .map_err(|e| super::io_stage("stdio envelope", e))?;
                    if descriptors.len() != if stdio.is_some() { 3 } else { 0 } {
                        return Err(io::Error::other("wrong helper descriptor count"));
                    }
                    if let Some(tx) = stdio {
                        // The helper retains its copies until recvmsg has installed
                        // ours. Closing an in-flight Unix socket on Darwin can
                        // otherwise deliver premature EOF on the received endpoint.
                        loop {
                            reader.as_ref().writable().await?;
                            match reader.as_ref().try_write(&[STDIO_RECEIVED]) {
                                Ok(1) => break,
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(e) => return Err(e),
                                _ => return Err(io::Error::other("short stdio acknowledgment")),
                            }
                        }
                        tx.send(descriptors)
                            .map_err(|_| io::Error::other("stdio receiver closed"))?;
                    }
                    read_frame(&mut reader)
                        .await
                        .map_err(|e| super::io_stage("response frame", e))
                })
                .await
                .map_err(io::Error::other)?
            };
            tokio::pin!(response);
            tokio::select! {
                result = &mut response => result,
                _ = cancel.cancelled() => {
                    let written = writer.write_u8(1).await;
                    if !group { written?; }
                    response.await
                },
                _ = tokio::time::sleep_until(deadline) => {
                    // Firecracker enforces the original wire deadline itself. A
                    // redundant byte can race its response shutdown on Linux and
                    // reset the stream before the required EOF is observed.
                    if !group { writer.write_u8(1).await?; }
                    response.await
                },
            }?
        };
        // Exactly one response and EOF, so a prefix cannot be accepted as proof.
        let eof = timeout_at(response_deadline, reader.read_u8())
            .await
            .map_err(io::Error::other)?;
        match eof {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(result),
            _ => Err(io::Error::other("helper response lacks EOF")),
        }
    }

    pub async fn exec(
        &self,
        id: &str,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        if let Some(outcome) = undispatched(spec, cancel) {
            return outcome;
        }
        let request = KilnRequest::Exec {
            id: id.into(),
            argv: spec.argv.to_vec(),
            stdin_bytes: spec.stdin.len(),
            max_output: spec.max_output,
        };
        let observed = Observed::default();
        let operation = async {
            let (response, out, err) = self
                .stdio_exchange(Operation::Kiln(request), spec, cancel, &observed)
                .await?;
            match response {
                Response::Executed {
                    finish,
                    status,
                    stdout,
                    stderr,
                } => {
                    let finish = match finish {
                        WireFinish::Completed => Ok(ExecFinish::Completed),
                        WireFinish::TimedOut => Ok(ExecFinish::TimedOut),
                        WireFinish::Canceled
                            if Instant::now() >= spec.deadline && !cancel.is_cancelled() =>
                        {
                            Ok(ExecFinish::TimedOut)
                        }
                        WireFinish::Canceled => Ok(ExecFinish::Canceled),
                        WireFinish::Failed(d) => Err(d),
                    };
                    let (disposition, cleanup) = legacy_exec_evidence(&finish);
                    Ok(ExecOutcome {
                        finish,
                        command_status: status,
                        stdout: stdout.capture(out, spec.max_output)?,
                        stderr: stderr.capture(err, spec.max_output)?,
                        disposition,
                        cleanup,
                    })
                }
                Response::Error { error, .. } => Err(io::Error::other(
                    crate::runtime::RuntimeError::from(error).to_string(),
                )),
                _ => Err(io::Error::other("unexpected helper exec reply")),
            }
        }
        .await;
        operation.unwrap_or_else(|error| observed.unconfirmed(error))
    }

    /// B6: one Firecracker execution, the same stdio exchange as kiln's. The helper owns
    /// cancellation through its stop barrier, so the reply's own reuse and cleanup
    /// evidence decide the disposition; an exchange that fails before a reply proves
    /// nothing about the guest and is quarantined.
    pub async fn firecracker_exec(
        &self,
        request: FirecrackerRequest,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        if let Some(outcome) = undispatched(spec, cancel) {
            return outcome;
        }
        let observed = Observed::default();
        let operation = async {
            let (response, out, err) = self
                .stdio_exchange(Operation::Firecracker(request), spec, cancel, &observed)
                .await?;
            match response {
                Response::Firecracker(FirecrackerResponse::Exec(reply)) => {
                    firecracker_outcome(*reply, out, err, spec, cancel)
                }
                Response::Firecracker(FirecrackerResponse::Error(error)) => {
                    Err(io::Error::other(format!(
                        "Firecracker helper refused the execution: {}",
                        error.message
                    )))
                }
                _ => Err(io::Error::other("unexpected helper exec reply")),
            }
        }
        .await;
        operation.unwrap_or_else(|error| observed.unconfirmed(error))
    }

    /// Sends one execution request, takes the three stdio endpoints, writes stdin and
    /// drains both outputs beside the reply. Shared by kiln and Firecracker.
    async fn stdio_exchange(
        &self,
        operation: Operation,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
        observed: &Observed,
    ) -> io::Result<(Response, Vec<u8>, Vec<u8>)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let exchange = self.exchange(operation, spec.deadline, cancel, Some(tx));
        let io_work = async {
            let descriptors = rx.await.map_err(io::Error::other)?;
            let mut streams = descriptors.into_iter();
            let mut next = || {
                fds::socket(
                    streams
                        .next()
                        .ok_or_else(|| io::Error::other("missing helper stdio"))?,
                    self.expected_uid,
                )
            };
            let mut input = next()?;
            let mut output = next()?;
            let mut error = next()?;
            input
                .write_all(spec.stdin)
                .await
                .map_err(|e| super::io_stage("stdin write", e))?;
            input
                .shutdown()
                .await
                .map_err(|e| super::io_stage("stdin shutdown", e))?;
            tokio::try_join!(
                async {
                    read_output(&mut output, spec.max_output, &observed.out)
                        .await
                        .map_err(|e| super::io_stage("stdout drain", e))
                },
                async {
                    read_output(&mut error, spec.max_output, &observed.err)
                        .await
                        .map_err(|e| super::io_stage("stderr drain", e))
                }
            )?;
            Ok::<_, io::Error>(())
        };
        let (response, ()) = tokio::try_join!(exchange, io_work)?;
        let out = observed.out.lock().unwrap().data.clone();
        let err = observed.err.lock().unwrap().data.clone();
        Ok((response, out, err))
    }
}

/// A pre-canceled or expired execution sends nothing: no command can have started.
fn undispatched(spec: &ExecSpec<'_>, cancel: &CancellationToken) -> Option<ExecOutcome> {
    if !(cancel.is_cancelled() || Instant::now() >= spec.deadline) {
        return None;
    }
    Some(ExecOutcome {
        finish: Ok(if cancel.is_cancelled() {
            ExecFinish::Canceled
        } else {
            ExecFinish::TimedOut
        }),
        command_status: None,
        stdout: Captured::known_empty(),
        stderr: Captured::known_empty(),
        disposition: SandboxDisposition::Reusable,
        cleanup: CleanupEvidence::NoChildStarted,
    })
}

/// Output the caller actually read, kept even when the exchange then fails.
#[derive(Default)]
struct Observed {
    out: Arc<Mutex<Captured>>,
    err: Arc<Mutex<Captured>>,
}

impl Observed {
    fn unconfirmed(&self, error: io::Error) -> ExecOutcome {
        ExecOutcome {
            finish: Err(RuntimeDiagnostic::new(
                RuntimeErrorKind::CleanupFailed,
                RuntimeStage::Cleanup,
                format!("helper execution/cleanup could not be confirmed: {error}"),
            )),
            command_status: None,
            stdout: self.out.lock().unwrap().clone(),
            stderr: self.err.lock().unwrap().clone(),
            disposition: SandboxDisposition::Quarantined,
            cleanup: CleanupEvidence::Unknown,
        }
    }
}

/// Maps a validated Firecracker reply. Reuse needs the reply's own word and trusted
/// guest cleanup evidence; a retired VM needs the host's stop barrier. Anything else
/// is quarantined: the guest's state is unknown.
pub(crate) fn firecracker_outcome(
    reply: ExecReply,
    out: Vec<u8>,
    err: Vec<u8>,
    spec: &ExecSpec<'_>,
    cancel: &CancellationToken,
) -> io::Result<ExecOutcome> {
    let finish = match reply.finish {
        WireFinishFc::Completed => Ok(ExecFinish::Completed),
        WireFinishFc::TimedOut => Ok(ExecFinish::TimedOut),
        // The helper cancels at the deadline too; the caller's own token says which.
        WireFinishFc::Canceled if Instant::now() >= spec.deadline && !cancel.is_cancelled() => {
            Ok(ExecFinish::TimedOut)
        }
        WireFinishFc::Canceled => Ok(ExecFinish::Canceled),
        WireFinishFc::Failed(diagnostic) => Err(diagnostic),
    };
    let cleanup = match reply.cleanup {
        ExecCleanup::NoChildStarted => CleanupEvidence::NoChildStarted,
        ExecCleanup::GuestCgroupDrained => CleanupEvidence::RuntimeDrained,
        ExecCleanup::VmStopped => CleanupEvidence::SandboxStopped,
        ExecCleanup::Unknown => CleanupEvidence::Unknown,
    };
    let disposition = match (reply.reusable, cleanup) {
        (true, CleanupEvidence::NoChildStarted | CleanupEvidence::RuntimeDrained) => {
            SandboxDisposition::Reusable
        }
        (false, CleanupEvidence::SandboxStopped) => SandboxDisposition::Stopped,
        _ => SandboxDisposition::Quarantined,
    };
    Ok(ExecOutcome {
        finish,
        command_status: reply.status,
        stdout: reply.stdout.capture(out, spec.max_output)?,
        stderr: reply.stderr.capture(err, spec.max_output)?,
        disposition,
        cleanup,
    })
}

async fn read_output(
    stream: &mut UnixStream,
    max: usize,
    observed: &Mutex<Captured>,
) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        let mut capture = observed.lock().unwrap();
        capture.total_bytes = capture.total_bytes.saturating_add(n as u64);
        let kept = n.min(max.saturating_sub(capture.data.len()));
        capture.data.extend_from_slice(&buffer[..kept]);
        if capture.total_bytes > max as u64 {
            capture.truncated = true;
            return Err(io::Error::other("helper output exceeded retained bound"));
        }
    }
}
