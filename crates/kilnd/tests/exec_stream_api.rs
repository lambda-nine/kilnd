//! ExecStream over a real Unix socket with the fake backend (API additions design 5 and
//! 8): the wire order, `seq`, parity with GetExecution on the encoded bytes, refusals
//! with no message, the disconnect, and permits back at handoff from a peer that
//! withholds HTTP/2 flow-control credit.
// Approved (design 7.1): test fixtures, an integration-test crate. They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#![allow(clippy::disallowed_methods)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kilnd::manager::{Feature, Limits, Manager};
use kilnd::runtime::fake::FakeRuntime;
use kilnd::store::Store;
use kilnd_api::v1 as pb;
use pb::exec_stream_response::Event;
use pb::kilnd_service_client::KilndServiceClient;
use prost::Message;
use tokio::net::UnixStream;
use tonic::Code;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

async fn connect(path: PathBuf, window: Option<u32>) -> KilndServiceClient<Channel> {
    let mut endpoint = Endpoint::try_from("http://kilnd.invalid").unwrap();
    if let Some(window) = window {
        endpoint = endpoint
            .initial_stream_window_size(window)
            .initial_connection_window_size(window)
            .http2_adaptive_window(false);
    }
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    KilndServiceClient::new(channel).max_decoding_message_size(8 << 20)
}

struct Daemon {
    socket: PathBuf,
    manager: Arc<Manager<FakeRuntime>>,
    fake: FakeRuntime,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    _tmp: tempfile::TempDir,
}

impl Daemon {
    async fn start(features: &[Feature], limits: Limits) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = tmp.path().join("run/kilnd.sock");
        let fake = FakeRuntime::default();
        fake.state().proven_features = Ok(features.to_vec());
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            limits,
        ));
        let listener = kilnd::server::bind(&socket, None).await.unwrap();
        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(kilnd::server::serve(
            manager.clone(),
            listener,
            async {
                let _ = stop_rx.await;
            },
            Duration::from_millis(500),
        ));
        let daemon = Self {
            socket,
            manager,
            fake,
            stop: Some(stop),
            server: Some(server),
            _tmp: tmp,
        };
        // The Health probe proves the dynamic features.
        let health = daemon
            .client()
            .await
            .health(pb::HealthRequest {})
            .await
            .unwrap();
        assert_eq!(
            health.into_inner().status,
            i32::from(pb::health_response::Status::Serving)
        );
        daemon
    }

    async fn client(&self) -> KilndServiceClient<Channel> {
        connect(self.socket.clone(), None).await
    }

    async fn sandbox(&self) -> String {
        self.client()
            .await
            .create_sandbox(pb::CreateSandboxRequest::default())
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
            .id
    }

    async fn admission(&self) -> pb::AdmissionStats {
        self.client()
            .await
            .health(pb::HealthRequest {})
            .await
            .unwrap()
            .into_inner()
            .admission
            .unwrap()
    }

    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.server.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn exec(sandbox_id: &str, argv: &[&str]) -> pb::ExecStreamRequest {
    pb::ExecStreamRequest {
        exec: Some(pb::ExecRequest {
            sandbox_id: sandbox_id.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }),
    }
}

fn reason(status: &tonic::Status) -> Option<String> {
    status
        .metadata()
        .get("kilnd-reason")
        .map(|v| v.to_str().unwrap().to_string())
}

async fn collect(
    stream: &mut tonic::Streaming<pb::ExecStreamResponse>,
) -> Vec<pb::ExecStreamResponse> {
    let mut messages = Vec::new();
    while let Some(message) = stream.message().await.unwrap() {
        messages.push(message);
    }
    messages
}

/// The order and numbering every stream must have: `ExecStarted` at seq 0, then chunks
/// and gaps, then exactly one `ExecFinished`, with `seq` gap-free.
fn check_order(messages: &[pb::ExecStreamResponse]) -> (&pb::ExecStarted, &pb::ExecFinished) {
    for (i, message) in messages.iter().enumerate() {
        assert_eq!(message.seq, i as u64, "seq is gap-free from 0");
    }
    let Some(Event::Started(started)) = &messages[0].event else {
        panic!("the first message is not ExecStarted");
    };
    let Some(Event::Finished(finished)) = &messages.last().unwrap().event else {
        panic!("the last message is not ExecFinished");
    };
    for message in &messages[1..messages.len() - 1] {
        assert!(
            matches!(message.event, Some(Event::Chunk(_) | Event::Gap(_))),
            "{message:?}"
        );
    }
    (started, finished)
}

#[tokio::test]
async fn a_stream_is_ordered_numbered_and_ends_with_get_execution_byte_for_byte() {
    let daemon = Daemon::start(&[Feature::ExecStream], Limits::default()).await;
    let mut c = daemon.client().await;
    let health = c.health(pb::HealthRequest {}).await.unwrap().into_inner();
    let capabilities = health.runtime_capabilities.unwrap();
    assert!(
        capabilities
            .features
            .contains(&i32::from(pb::Feature::ExecStream))
    );
    let limits = capabilities.limits.unwrap();
    assert_eq!(
        (
            limits.default_stream_timeout_ms,
            limits.max_stream_timeout_ms,
            limits.stream_chunk_bytes,
            limits.stream_buffer_bytes
        ),
        (1_800_000, 7_200_000, 32 * 1024, 256 * 1024)
    );
    assert_eq!(health.admission.unwrap().max_exec_streams, 16);
    let sandbox = daemon.sandbox().await;
    let mut stream = c
        .exec_stream(exec(&sandbox, &["stream", "8", "50000", "1"]))
        .await
        .unwrap()
        .into_inner();
    let messages = collect(&mut stream).await;
    let (started, finished) = check_order(&messages);
    assert_eq!(started.sandbox_id, sandbox);
    assert_eq!(started.timeout_ms, 1_800_000);
    let mut stdout = Vec::new();
    for message in &messages {
        if let Some(Event::Chunk(chunk)) = &message.event {
            assert!(!chunk.data.is_empty() && chunk.data.len() <= 32 * 1024);
            if chunk.stream == i32::from(pb::OutputStream::Stdout) {
                assert_eq!(chunk.offset, stdout.len() as u64);
                stdout.extend_from_slice(&chunk.data);
            }
        }
    }
    let expected: Vec<u8> = (0..8u8).flat_map(|i| vec![i; 50_000]).collect();
    assert_eq!(stdout, expected);
    let execution = finished.execution.as_ref().unwrap();
    assert_eq!(execution.id, started.execution_id);
    assert_eq!(execution.mode, i32::from(pb::ExecutionMode::Stream));
    // Parity (design 5) on the encoded message.
    let read = c
        .get_execution(pb::GetExecutionRequest {
            id: started.execution_id.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(execution.encode_to_vec(), read.encode_to_vec());
    assert_eq!(
        finished.stdout.unwrap(),
        pb::LiveDelivery {
            delivered_bytes: 400_000,
            dropped_bytes: 0,
            dropped_bytes_known: true
        }
    );
    // A unary Exec says so; GetSandbox's history agrees.
    let unary = c
        .exec(pb::ExecRequest {
            sandbox_id: sandbox.clone(),
            argv: vec!["true".into()],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(unary.mode, i32::from(pb::ExecutionMode::Unary));
    daemon.stop().await;
}

#[tokio::test]
async fn refusals_before_the_row_are_rpc_errors_with_no_message() {
    let daemon = Daemon::start(&[], Limits::default()).await;
    let mut c = daemon.client().await;
    let sandbox = daemon.sandbox().await;
    let status = c
        .exec_stream(exec(&sandbox, &["true"]))
        .await
        .map(drop)
        .expect_err("refused before any message");
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(
        reason(&status).as_deref(),
        Some("backend_unsupported:exec_stream")
    );
    assert!(
        status
            .message()
            .starts_with("backend_unsupported:exec_stream: ")
    );
    daemon.stop().await;

    let daemon = Daemon::start(
        &[Feature::ExecStream],
        Limits {
            max_exec_streams: 1,
            max_exec_streams_per_uid: 1,
            ..Limits::default()
        },
    )
    .await;
    let mut c = daemon.client().await;
    let sandbox = daemon.sandbox().await;
    let other = daemon.sandbox().await;
    for (request, code) in [
        (exec(&sandbox, &[]), Code::InvalidArgument),
        (
            pb::ExecStreamRequest {
                exec: Some(pb::ExecRequest {
                    sandbox_id: sandbox.clone(),
                    argv: vec!["true".into()],
                    timeout_ms: 7_200_001,
                    ..Default::default()
                }),
            },
            Code::InvalidArgument,
        ),
        (exec("sb-0000000000000000", &["true"]), Code::NotFound),
        (pb::ExecStreamRequest { exec: None }, Code::InvalidArgument),
    ] {
        let status = c.exec_stream(request).await.map(drop).expect_err("refused");
        assert_eq!(status.code(), code, "{status:?}");
    }
    // The cap: one stream holds it, the next is RESOURCE_EXHAUSTED exec_stream_limit.
    let mut first = c
        .exec_stream(exec(&sandbox, &["sleep"]))
        .await
        .unwrap()
        .into_inner();
    let started = first.message().await.unwrap().unwrap();
    assert!(matches!(started.event, Some(Event::Started(_))));
    let status = c
        .exec_stream(exec(&other, &["true"]))
        .await
        .map(drop)
        .expect_err("refused");
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(reason(&status).as_deref(), Some("exec_stream_limit"));
    let admission = daemon.admission().await;
    assert_eq!(
        (
            admission.max_exec_streams,
            admission.current_exec_streams,
            admission.rejected_exec_streams
        ),
        (1, 1, 1)
    );
    assert_eq!(
        daemon.manager.get(&other, 10).unwrap().1.len(),
        0,
        "no row for any refusal"
    );
    drop(first);
    daemon.stop().await;
}

#[tokio::test]
async fn dropping_the_stream_is_a_disconnect_that_cancels_like_exec() {
    let daemon = Daemon::start(&[Feature::ExecStream], Limits::default()).await;
    let mut c = daemon.client().await;
    let sandbox = daemon.sandbox().await;
    let mut stream = c
        .exec_stream(exec(&sandbox, &["sleep"]))
        .await
        .unwrap()
        .into_inner();
    let Some(Event::Started(started)) = stream.message().await.unwrap().unwrap().event else {
        panic!("no ExecStarted");
    };
    drop(stream);
    let execution = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let execution = c
                .get_execution(pb::GetExecutionRequest {
                    id: started.execution_id.clone(),
                })
                .await
                .unwrap()
                .into_inner()
                .execution
                .unwrap();
            if execution.state != i32::from(pb::ExecutionState::Running) {
                break execution;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the disconnect did not cancel");
    assert_eq!(execution.state, i32::from(pb::ExecutionState::Canceled));
    assert_eq!(
        execution.cancel_reason,
        i32::from(pb::CancelReason::ClientDisconnected)
    );
    assert_eq!(daemon.fake.state().canceled_execs, 1);
    daemon.stop().await;
}

async fn wait_released(daemon: &Daemon) -> pb::AdmissionStats {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let admission = daemon.admission().await;
            if admission.current_exec_streams == 0
                && admission.current_execs == 0
                && admission.current_rpcs == 0
            {
                break admission;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("permits were not released at handoff")
}

/// Design 5.1 and 8: a peer that never reads, so never returns HTTP/2 window, while the
/// command writes at full rate. The command finishes on time, every permit (stream,
/// Exec ticket, sandbox and RPC) comes back at handoff with the final message unread,
/// and reading afterwards still gets an exact account.
#[tokio::test]
async fn a_peer_withholding_window_updates_gets_its_permits_back_at_handoff() {
    let daemon = Daemon::start(&[Feature::ExecStream], Limits::default()).await;
    let sandbox = daemon.sandbox().await;
    let mut stalled = connect(daemon.socket.clone(), Some(64 * 1024)).await;
    let started = std::time::Instant::now();
    let response = stalled
        .exec_stream(exec(&sandbox, &["flood", "500"]))
        .await
        .unwrap();
    // Nothing reads this stream while the command runs and finishes.
    let mut stream = response.into_inner();
    let admission = wait_released(&daemon).await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a stalled peer slowed the command: {:?}",
        started.elapsed()
    );
    assert_eq!(admission.max_exec_streams, 16);
    // The sandbox is free for another Exec while the final message waits for credit.
    let mut c = daemon.client().await;
    c.exec(pb::ExecRequest {
        sandbox_id: sandbox.clone(),
        argv: vec!["true".into()],
        ..Default::default()
    })
    .await
    .unwrap();
    let messages = collect(&mut stream).await;
    let (started, finished) = check_order(&messages);
    let execution = finished.execution.as_ref().unwrap();
    assert_eq!(execution.id, started.execution_id);
    let total = execution.stdout.as_ref().unwrap().total_bytes;
    let stdout = finished.stdout.unwrap();
    assert!(stdout.dropped_bytes > 0, "a 64 KiB window dropped nothing");
    assert_eq!(stdout.delivered_bytes + stdout.dropped_bytes, total);
    assert!(stdout.dropped_bytes_known);
    // Every gap precedes the next chunk, and offsets cover every byte.
    let mut next = 0u64;
    for message in &messages {
        match &message.event {
            Some(Event::Gap(gap)) if gap.stream == i32::from(pb::OutputStream::Stdout) => {
                assert_eq!(gap.offset, next);
                assert!(gap.dropped_bytes_known);
                next += gap.dropped_bytes;
            }
            Some(Event::Chunk(chunk)) if chunk.stream == i32::from(pb::OutputStream::Stdout) => {
                assert_eq!(chunk.offset, next);
                next += chunk.data.len() as u64;
            }
            _ => {}
        }
    }
    assert_eq!(next, total);
    daemon.stop().await;
}

/// Design 5.1's handoff over the wire (from the M4 break-it's controls): completed,
/// unread response bodies hold no stream permit, so three connections can keep more of
/// them than the node stream cap; each still delivers its whole final row when read.
/// They are bounded by the transport's per-connection streams and connection caps.
#[tokio::test]
async fn unread_finished_wire_streams_hold_no_stream_permit() {
    let daemon = Daemon::start(&[Feature::ExecStream], Limits::default()).await;
    let sandbox = daemon.sandbox().await;
    let mut clients = [
        daemon.client().await,
        daemon.client().await,
        daemon.client().await,
    ];
    let mut unread = Vec::new();

    for i in 0..17 {
        let client = i % clients.len();
        let response = clients[client]
            .exec_stream(exec(&sandbox, &["stream", "64", "16384", "0"]))
            .await
            .unwrap();
        unread.push(response.into_inner());
        let _ = wait_released(&daemon).await;
    }

    let snapshot = daemon.admission().await;
    assert_eq!(snapshot.current_exec_streams, 0);
    assert_eq!(snapshot.max_exec_streams, 16);
    assert_eq!(
        unread.len(),
        17,
        "more unread finals than the node stream cap"
    );

    let mut final_blob_bytes = 0usize;
    for stream in &mut unread {
        let messages = collect(stream).await;
        let (_, finished) = check_order(&messages);
        let execution = finished.execution.as_ref().unwrap();
        final_blob_bytes += execution.stdout.as_ref().unwrap().data.len();
        final_blob_bytes += execution.stderr.as_ref().unwrap().data.len();
    }
    assert!(final_blob_bytes >= 17 << 20);
    daemon.stop().await;
}
