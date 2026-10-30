use super::protocol::*;
use super::{fds, read_frame, write_frame};
use crate::model::CreateCertainty;
use crate::runtime::{ExecFinish, ExecSpec, Runtime, kiln_direct::DirectKilnRuntime};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Listener ownership is supplied by systemd's root-owned socket unit. The
/// numeric service UID comes only from the root-controlled account database.
pub async fn serve(
    listener: UnixListener,
    uid: u32,
    bin: PathBuf,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let runtime = Arc::new(DirectKilnRuntime::new(bin));
    let slots = Arc::new(Semaphore::new(64));
    let tasks = TaskTracker::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => result?,
        };
        let stream = accepted.0;
        // Reject before reading any attacker-controlled frame (including root).
        if stream.peer_cred()?.uid() != uid {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let runtime = runtime.clone();
        let stop = shutdown.child_token();
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle(stream, uid, runtime, stop).await {
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
    mut stream: UnixStream,
    uid: u32,
    runtime: Arc<DirectKilnRuntime>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let (request, descriptors) = timeout(Duration::from_secs(2), async {
        let descriptors = fds::receive(&stream).await?;
        let request: Request = read_frame(&mut stream).await?;
        request
            .validate(descriptors.len())
            .map_err(io::Error::other)?;
        Ok::<_, io::Error>((request, descriptors))
    })
    .await
    .map_err(io::Error::other)??;
    let remaining = request.deadline_ns.saturating_sub(super::monotonic_ns()?);
    if remaining > (u64::from(request.timeout_ms) + 1) * 1_000_000 {
        return Err(io::Error::other("invalid monotonic deadline"));
    }
    let deadline = Instant::now() + Duration::from_nanos(remaining);
    let (mut reader, mut writer) = stream.into_split();
    let operation = dispatch(
        request.operation,
        descriptors,
        uid,
        &runtime,
        deadline,
        &cancel,
    );
    tokio::pin!(operation);
    let response = tokio::select! {
        result = &mut operation => result?,
        // One cancellation byte, extra data, or EOF all request cancellation.
        _ = reader.read_u8() => { cancel.cancel(); operation.await? },
    };
    timeout(Duration::from_secs(2), write_frame(&mut writer, &response))
        .await
        .map_err(io::Error::other)??;
    writer.shutdown().await
}

async fn dispatch(
    operation: Operation,
    descriptors: Vec<std::os::fd::OwnedFd>,
    uid: u32,
    runtime: &DirectKilnRuntime,
    deadline: Instant,
    cancel: &CancellationToken,
) -> io::Result<Response> {
    let Operation::Kiln(op) = operation;
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
            .create(&spec)
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
            .remove(&id)
            .await
            .map(|_| Response::Removed)
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Ls => runtime
            .list()
            .await
            .map(|rows| Response::Listed(rows.into_iter().map(Into::into).collect()))
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Gc { ids } => runtime
            .gc(&ids)
            .await
            .map(Response::Collected)
            .unwrap_or_else(|e| error(e.into())),
        KilnRequest::Exec {
            id,
            argv,
            stdin_bytes,
            max_output,
        } => {
            let mut streams = descriptors.into_iter();
            let mut input = fds::socket(
                streams
                    .next()
                    .ok_or_else(|| io::Error::other("missing stdin"))?,
                uid,
            )?;
            let mut stdout = fds::socket(
                streams
                    .next()
                    .ok_or_else(|| io::Error::other("missing stdout"))?,
                uid,
            )?;
            let mut stderr = fds::socket(
                streams
                    .next()
                    .ok_or_else(|| io::Error::other("missing stderr"))?,
                uid,
            )?;
            let mut stdin = Vec::new();
            timeout(
                Duration::from_secs(2),
                (&mut input)
                    .take((MAX_STDIN + 1) as u64)
                    .read_to_end(&mut stdin),
            )
            .await
            .map_err(io::Error::other)??;
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
            let outcome = runtime.exec(&id, &spec, cancel).await;
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
                    stdout.write_all(&outcome.stdout.data),
                    stderr.write_all(&outcome.stderr.data)
                )?;
                tokio::try_join!(stdout.shutdown(), stderr.shutdown())?;
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(io::Error::other)??;
            response
        }
    })
}
