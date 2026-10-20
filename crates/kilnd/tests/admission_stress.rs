//! Opt-in Linux resource regression for Chapter 9. The parent test drives a
//! dedicated child harness so `/proc` measurements describe only the daemon.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kilnd::manager::{Limits, Manager};
use kilnd::model::SandboxSpec;
use kilnd::runtime::fake::FakeRuntime;
use kilnd::runtime::{BackendSandbox, ExecOutcome, ExecSpec, Runtime, RuntimeError};
use kilnd::store::Store;
use kilnd_api::v1 as pb;
use pb::kilnd_service_client::KilndServiceClient;
use prost::Message;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;
use tonic::codegen::{Bytes, http};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const CHILD_ENV: &str = "KILND_ADMISSION_STRESS_CHILD";

#[derive(Clone, Default)]
struct StressRuntime {
    inner: FakeRuntime,
    version_calls: Arc<AtomicU32>,
}

impl Runtime for StressRuntime {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn version(
        &self,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<String, RuntimeError> {
        self.version_calls.fetch_add(1, Ordering::SeqCst);
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(RuntimeError::Backend("stress version canceled".into())),
            () = tokio::time::sleep_until(deadline) => Err(RuntimeError::Backend("stress version timed out".into())),
            () = tokio::time::sleep(Duration::from_millis(100)) => Ok("stress 1.0".into()),
        }
    }

    async fn create(&self, spec: &SandboxSpec) -> Result<String, RuntimeError> {
        self.inner.create(spec).await
    }

    async fn exec(
        &self,
        id: &str,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> Result<ExecOutcome, RuntimeError> {
        self.inner.exec(id, spec, cancel).await
    }

    async fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        self.inner.remove(id).await
    }

    async fn list(&self) -> Result<Vec<BackendSandbox>, RuntimeError> {
        self.inner.list().await
    }

    async fn gc(&self) -> Result<Vec<String>, RuntimeError> {
        self.inner.gc().await
    }
}

async fn connect_client(path: PathBuf) -> KilndServiceClient<Channel> {
    let channel = Endpoint::try_from("http://kilnd.invalid")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    KilndServiceClient::new(channel).max_encoding_message_size(2 << 20)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "Linux child harness; run the parent admission resource test"]
async fn admission_stress_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let root = PathBuf::from(std::env::var_os("KILND_ADMISSION_STRESS_ROOT").unwrap());
    let socket_path = root.join("run/kilnd.sock");
    let stop_path = root.join("stop");
    let result_path = root.join("version-calls");
    let runtime = StressRuntime::default();
    let version_calls = runtime.version_calls.clone();
    let manager = Arc::new(Manager::new(
        runtime,
        Store::open(&root.join("state")).unwrap(),
        Limits {
            max_sandboxes: 2,
            default_timeout: Duration::from_millis(300),
            max_timeout: Duration::from_secs(2),
            max_connections: 8,
            max_concurrent_rpcs: 16,
            max_concurrent_health: 4,
            max_concurrent_execs: 4,
            max_queued_execs_per_sandbox: 2,
            max_queued_exec_stdin_bytes: 4 << 20,
            max_streams_per_connection: 4,
            ..Limits::default()
        },
    ));
    let socket = kilnd::server::bind(&socket_path, None).await.unwrap();
    std::fs::write(root.join("ready"), b"").unwrap();
    let shutdown = async {
        while !stop_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    kilnd::server::serve(manager, socket, shutdown, Duration::from_secs(1))
        .await
        .unwrap();
    std::fs::write(
        result_path,
        version_calls.load(Ordering::SeqCst).to_string(),
    )
    .unwrap();
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn pid(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    async fn wait_success(mut self) {
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("admission child did not stop");
        self.0.take();
        assert!(status.success(), "admission child failed: {status}");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .count()
}

fn rss_bytes(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let kb: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .unwrap()
        .parse()
        .unwrap();
    kb * 1024
}

async fn wait_for(path: &Path, what: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn grpc_request(path: &'static str) -> http::Request<()> {
    http::Request::builder()
        .method("POST")
        .uri(format!("http://kilnd.invalid{path}"))
        .version(http::Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap()
}

fn grpc_body(message: &impl Message) -> Bytes {
    let mut body = Vec::with_capacity(message.encoded_len() + 5);
    body.push(0);
    body.extend_from_slice(&u32::try_from(message.encoded_len()).unwrap().to_be_bytes());
    message.encode(&mut body).unwrap();
    Bytes::from(body)
}

async fn wait_for_fd_recovery(pid: u32, baseline_fds: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while fd_count(pid) > baseline_fds + 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("connection FDs did not return to their warmed baseline");
}

async fn slow_connection_round(socket: &Path, pid: u32, baseline_fds: usize) {
    let mut streams = Vec::new();
    for _ in 0..12 {
        streams.push(UnixStream::connect(socket).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        fd_count(pid) <= baseline_fds + 12,
        "connection admission exceeded the FD envelope"
    );
    let mut closed = 0;
    for stream in &mut streams {
        let mut byte = [0; 1];
        if matches!(
            tokio::time::timeout(Duration::from_millis(20), stream.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        ) {
            closed += 1;
        }
    }
    assert!(closed >= 4, "excess slow connections were not closed");
    drop(streams);
    wait_for_fd_recovery(pid, baseline_fds).await;
}

async fn partial_request_round(socket: &Path, pid: u32, baseline_fds: usize) {
    let before = rss_bytes(pid);
    let stream = UnixStream::connect(socket).await.unwrap();
    let (mut sender, connection) = h2::client::handshake(stream).await.unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut responses = Vec::new();
    let mut bodies = Vec::new();
    for _ in 0..4 {
        sender = sender.ready().await.unwrap();
        let (response, mut body) = sender
            .send_request(grpc_request("/kilnd.v1.KilndService/Exec"), false)
            .unwrap();
        // Declare a maximum-sized message, send one payload byte, and never
        // end the stream. This forces bounded partial decoding on every
        // allowed stream without reaching a handler.
        body.send_data(Bytes::from_static(&[0, 0, 32, 0, 0, 0]), false)
            .unwrap();
        responses.push(response);
        bodies.push(body);
    }
    let mut peak = before;
    for _ in 0..20 {
        peak = peak.max(rss_bytes(pid));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        peak <= before + (64 << 20),
        "partial request decoding exceeded its RSS envelope: before={before} peak={peak}"
    );
    assert!(fd_count(pid) <= baseline_fds + 5);
    drop((bodies, responses, sender));
    connection.abort();
    let _ = connection.await;
    wait_for_fd_recovery(pid, baseline_fds).await;
}

async fn stalled_response_round(
    socket: &Path,
    observer: &KilndServiceClient<Channel>,
    execution_id: &str,
    pid: u32,
    baseline_fds: usize,
) {
    let before = rss_bytes(pid);
    let stream = UnixStream::connect(socket).await.unwrap();
    let (mut sender, connection) = h2::client::handshake(stream).await.unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let body = grpc_body(&pb::GetExecutionRequest {
        id: execution_id.to_string(),
    });
    let mut responses = Vec::new();
    for _ in 0..4 {
        sender = sender.ready().await.unwrap();
        let (response, mut request_body) = sender
            .send_request(grpc_request("/kilnd.v1.KilndService/GetExecution"), false)
            .unwrap();
        request_body.send_data(body.clone(), true).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("large response headers were not produced")
            .unwrap();
        responses.push(response);
    }
    // Do not poll or release capacity on any response body. The server may
    // fill only the configured HTTP/2 windows; other connections stay usable.
    let mut peak = before;
    for _ in 0..20 {
        peak = peak.max(rss_bytes(pid));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        peak <= before + (64 << 20),
        "stalled responses exceeded their RSS envelope: before={before} peak={peak}"
    );
    assert_eq!(
        observer
            .clone()
            .health(pb::HealthRequest {})
            .await
            .unwrap()
            .into_inner()
            .status,
        pb::health_response::Status::Serving as i32
    );
    drop((responses, sender));
    connection.abort();
    let _ = connection.await;
    wait_for_fd_recovery(pid, baseline_fds + 1).await;
}

async fn exec_cycle(
    client: &KilndServiceClient<Channel>,
    observer: &KilndServiceClient<Channel>,
    sandbox_id: &str,
    pid: u32,
) -> u64 {
    let before = observer
        .clone()
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner()
        .admission
        .unwrap();
    let mut calls = Vec::new();
    for _ in 0..4 {
        let mut client = client.clone();
        let sandbox_id = sandbox_id.to_string();
        calls.push(tokio::spawn(async move {
            client
                .exec(pb::ExecRequest {
                    sandbox_id,
                    argv: vec!["sleep".into()],
                    stdin: vec![b'x'; 1 << 20],
                    timeout_ms: 2_000,
                })
                .await
        }));
    }
    let mut peak = rss_bytes(pid);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let stats = observer
                .clone()
                .health(pb::HealthRequest {})
                .await
                .unwrap()
                .into_inner()
                .admission
                .unwrap();
            peak = peak.max(rss_bytes(pid));
            if stats.current_execs == 3
                && stats.current_stdin_bytes == 3 << 20
                && stats.rejected_sandbox_execs == before.rejected_sandbox_execs + 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Exec saturation was not fully admitted before sampling");
    for call in calls {
        call.abort();
        let _ = call.await;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let stats = observer
                .clone()
                .health(pb::HealthRequest {})
                .await
                .unwrap()
                .into_inner()
                .admission
                .unwrap();
            if stats.current_execs == 0 && stats.current_stdin_bytes == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Exec admission did not recover after client cancellation");
    peak
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "Linux /proc stress; run scripts/integration-test.sh in the VM"]
async fn admission_resource_bounds_plateau_and_recover() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let socket = root.join("run/kilnd.sock");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "admission_stress_child",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env("KILND_ADMISSION_STRESS_ROOT", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let child = ChildGuard(Some(child));
    wait_for(&root.join("ready"), "admission child").await;
    let pid = child.pid();
    let baseline_fds = fd_count(pid);
    let baseline_rss = rss_bytes(pid);

    for _ in 0..5 {
        slow_connection_round(&socket, pid, baseline_fds).await;
    }

    let client = connect_client(socket.clone()).await;
    let mut health_calls = Vec::new();
    for _ in 0..4 {
        let mut client = client.clone();
        health_calls.push(tokio::spawn(async move {
            client.health(pb::HealthRequest {}).await
        }));
    }
    for call in health_calls {
        assert_eq!(
            call.await.unwrap().unwrap().into_inner().status,
            pb::health_response::Status::Serving as i32
        );
    }

    // Use a separate HTTP/2 connection for observations. Four Exec streams
    // intentionally consume the primary connection's configured stream cap.
    let observer = connect_client(socket.clone()).await;

    let mut create_client = client.clone();
    let sandbox_id = create_client
        .create_sandbox(pb::CreateSandboxRequest { spec: None })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
        .id;
    partial_request_round(&socket, pid, baseline_fds + 2).await;
    for _ in 0..5 {
        let _ = exec_cycle(&client, &observer, &sandbox_id, pid).await;
    }
    let warmed_rss = rss_bytes(pid);
    let mut peak_rss = warmed_rss;
    for _ in 0..20 {
        let peak = exec_cycle(&client, &observer, &sandbox_id, pid).await;
        peak_rss = peak_rss.max(peak);
    }

    let execution_id = client
        .clone()
        .exec(pb::ExecRequest {
            sandbox_id: sandbox_id.clone(),
            argv: vec!["spew-both".into(), (1 << 20).to_string()],
            stdin: Vec::new(),
            timeout_ms: 1_000,
        })
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap()
        .id;
    stalled_response_round(&socket, &observer, &execution_id, pid, baseline_fds + 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let final_rss = rss_bytes(pid);
    assert!(
        peak_rss <= baseline_rss + (256 << 20),
        "RSS exceeded regression envelope: baseline={baseline_rss} peak={peak_rss}"
    );
    assert!(
        final_rss <= warmed_rss + (32 << 20),
        "RSS did not plateau: warmed={warmed_rss} final={final_rss}"
    );
    assert!(
        fd_count(pid) <= baseline_fds + 6,
        "FDs did not recover after stress"
    );

    let stats = observer
        .clone()
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner()
        .admission
        .unwrap();
    assert_eq!(stats.max_connections, 8);
    assert!(stats.rejected_connections >= 20);
    assert_eq!(stats.max_queued_execs_per_sandbox, 2);
    assert!(stats.rejected_sandbox_execs >= 25);
    client
        .clone()
        .delete_sandbox(pb::DeleteSandboxRequest { id: sandbox_id })
        .await
        .unwrap();
    drop(client);
    drop(observer);

    std::fs::write(root.join("stop"), b"").unwrap();
    child.wait_success().await;
    let version_calls = std::fs::read_to_string(root.join("version-calls"))
        .unwrap()
        .parse::<u32>()
        .unwrap();
    assert!(
        (1..=2).contains(&version_calls),
        "concurrent Health calls did not share one probe per cache miss: {version_calls} calls"
    );
}
