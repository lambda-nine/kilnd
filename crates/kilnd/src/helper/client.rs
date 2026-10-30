use super::protocol::*;
use super::{fds, read_frame, write_frame};
use crate::model::{Captured, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage};
use crate::runtime::{ExecFinish, ExecOutcome, ExecSpec};
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
impl Client {
    pub async fn call(
        &self,
        operation: KilnRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> io::Result<Response> {
        self.exchange(operation, deadline, cancel, None).await
    }
    async fn exchange(
        &self,
        operation: KilnRequest,
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
        let allowance = match &operation {
            KilnRequest::Exec { .. } => Duration::from_secs(70),
            KilnRequest::Create { .. } => Duration::from_secs(5),
            KilnRequest::Capabilities { .. } => Duration::from_secs(1),
            _ => Duration::from_secs(2),
        };
        let response_deadline = deadline + allowance;
        let request = Request {
            version: VERSION,
            deadline_ns,
            timeout_ms: u32::try_from(remaining).map_err(io::Error::other)?,
            operation: Operation::Kiln(operation),
        };
        request.validate(0).map_err(io::Error::other)?;
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
                _ = cancel.cancelled() => { writer.write_u8(1).await?; response.await },
                _ = tokio::time::sleep_until(deadline) => { writer.write_u8(1).await?; response.await },
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
        if cancel.is_cancelled() || Instant::now() >= spec.deadline {
            return ExecOutcome {
                finish: Ok(if cancel.is_cancelled() {
                    ExecFinish::Canceled
                } else {
                    ExecFinish::TimedOut
                }),
                command_status: None,
                stdout: Captured::known_empty(),
                stderr: Captured::known_empty(),
            };
        }
        let observed_out = Arc::new(Mutex::new(Captured::default()));
        let observed_err = Arc::new(Mutex::new(Captured::default()));
        let failed = |error: io::Error| ExecOutcome {
            finish: Err(RuntimeDiagnostic::new(
                RuntimeErrorKind::CleanupFailed,
                RuntimeStage::Cleanup,
                format!("helper execution/cleanup could not be confirmed: {error}"),
            )),
            command_status: None,
            stdout: observed_out.lock().unwrap().clone(),
            stderr: observed_err.lock().unwrap().clone(),
        };
        let operation = async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let request = KilnRequest::Exec {
                id: id.into(),
                argv: spec.argv.to_vec(),
                stdin_bytes: spec.stdin.len(),
                max_output: spec.max_output,
            };
            let exchange = self.exchange(request, spec.deadline, cancel, Some(tx));
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
                        read_output(&mut output, spec.max_output, &observed_out)
                            .await
                            .map_err(|e| super::io_stage("stdout drain", e))
                    },
                    async {
                        read_output(&mut error, spec.max_output, &observed_err)
                            .await
                            .map_err(|e| super::io_stage("stderr drain", e))
                    }
                )?;
                Ok::<_, io::Error>(())
            };
            let (response, ()) = tokio::try_join!(exchange, io_work)?;
            let out = observed_out.lock().unwrap().data.clone();
            let err = observed_err.lock().unwrap().data.clone();
            match response {
                Response::Executed {
                    finish,
                    status,
                    stdout,
                    stderr,
                } => Ok(ExecOutcome {
                    finish: match finish {
                        WireFinish::Completed => Ok(ExecFinish::Completed),
                        WireFinish::TimedOut => Ok(ExecFinish::TimedOut),
                        WireFinish::Canceled
                            if Instant::now() >= spec.deadline && !cancel.is_cancelled() =>
                        {
                            Ok(ExecFinish::TimedOut)
                        }
                        WireFinish::Canceled => Ok(ExecFinish::Canceled),
                        WireFinish::Failed(d) => Err(d),
                    },
                    command_status: status,
                    stdout: stdout.capture(out, spec.max_output)?,
                    stderr: stderr.capture(err, spec.max_output)?,
                }),
                Response::Error { error, .. } => Err(io::Error::other(
                    crate::runtime::RuntimeError::from(error).to_string(),
                )),
                _ => Err(io::Error::other("unexpected helper exec reply")),
            }
        }
        .await;
        operation.unwrap_or_else(failed)
    }
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
