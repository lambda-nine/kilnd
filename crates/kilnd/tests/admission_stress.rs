//! Opt-in Linux resource regressions for Chapters 9 and 12. Parent tests drive
//! dedicated child harnesses so `/proc` measurements stay isolated.
// Approved (design 7.1): test fixtures, an integration-test crate. They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#![allow(clippy::disallowed_methods)]
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kilnd::manager::{Limits, Manager};
use kilnd::model::{
    Captured, CleanupEvidence, CommandStatus, Digest, Execution, ExecutionState, Network, Sandbox,
    SandboxAccounting, SandboxSpec, SandboxState,
};
use kilnd::runtime::fake::FakeRuntime;
use kilnd::runtime::{
    AbsenceReceipt, AllocationObservation, BackendInventory, CreateContext, CreateFailure,
    CreatedSandbox, ExecOutcome, ExecSpec, ExecutionContext, PrepareContext, PreparedCreate,
    RemoveTarget, Runtime,
    RuntimeCapabilities, RuntimeError,
};
use kilnd::store::{ExecutionResult, Store};
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
const HISTORY_CHILD_ENV: &str = "KILND_HISTORY_RSS_CHILD";
const HISTORY_ROOT_ENV: &str = "KILND_HISTORY_RSS_ROOT";
const HISTORY_ROWS: usize = 100;
const HISTORY_STREAM_BYTES: usize = 1 << 20;

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

    fn capabilities(&self) -> RuntimeCapabilities {
        self.inner.capabilities()
    }

    async fn prepare(
        &self,
        context: &PrepareContext,
        spec: &SandboxSpec,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<PreparedCreate, RuntimeError> {
        self.inner.prepare(context, spec, deadline, cancel).await
    }

    async fn create(
        &self,
        context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<CreatedSandbox, CreateFailure> {
        self.inner.create(context, prepared, deadline, cancel).await
    }

    async fn inspect_allocation(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<AllocationObservation, RuntimeError> {
        self.inner
            .inspect_allocation(context, prepared_digest, deadline, cancel)
            .await
    }

    async fn fence_absent(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        self.inner
            .fence_absent(context, prepared_digest, deadline, cancel)
            .await
    }

    async fn validate_sandbox(
        &self,
        id: &str,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        self.inner.validate_sandbox(id, deadline, cancel).await
    }

    async fn exec(
        &self,
        id: &str,
        execution: &ExecutionContext,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        self.inner.exec(id, execution, spec, cancel).await
    }

    async fn remove(
        &self,
        target: RemoveTarget<'_>,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        self.inner.remove(target, deadline, cancel).await
    }

    async fn list(
        &self,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<BackendInventory, RuntimeError> {
        self.inner.list(deadline, cancel).await
    }

    async fn gc(
        &self,
        targets: &[RemoveTarget<'_>],
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<AbsenceReceipt>, RuntimeError> {
        self.inner.gc(targets, deadline, cancel).await
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

#[test]
#[ignore = "Linux child harness; run the parent metadata-history resource test"]
fn metadata_history_rss_child() {
    if std::env::var_os(HISTORY_CHILD_ENV).is_none() {
        return;
    }
    let root = PathBuf::from(std::env::var_os(HISTORY_ROOT_ENV).unwrap());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spec = SandboxSpec {
        image: "alpine:latest".into(),
        memory_bytes: 512 << 20,
        cpu_millis: 1_000,
        pids: 256,
        disk_bytes: 2 << 30,
        network: Network::None,
        read_only_root: true,
        writable_paths: Vec::new(),
        labels: Default::default(),
    };
    let sandbox = Sandbox {
        id: "sb-0000000000000001".into(),
        state: SandboxState::Ready,
        spec: spec.clone(),
        backend: "fake".into(),
        backend_id: Some("kiln-history".into()),
        created_at_ms: 1,
        updated_at_ms: 1,
        deleted_at_ms: None,
        failure_reason: None,
        create_certainty: Default::default(),
        owner_uid: 0,
        accounting: SandboxAccounting::legacy(&spec, ""),
    };
    let capture = Captured {
        data: vec![b'x'; HISTORY_STREAM_BYTES],
        total_bytes: HISTORY_STREAM_BYTES as u64,
        truncated: false,
        total_bytes_known: true,
    };
    let status = CommandStatus::Exited(0);
    let store = Store::open(&root).unwrap();
    store.insert_sandbox(&sandbox).unwrap();
    for sequence in 0..HISTORY_ROWS {
        let execution = Execution {
            id: format!("ex-{sequence:016x}"),
            sandbox_id: sandbox.id.clone(),
            argv: vec!["true".into()],
            state: ExecutionState::Running,
            exit_code: None,
            command_status: None,
            runtime_error: None,
            failure_reason: None,
            started_at_ms: sequence as i64,
            finished_at_ms: None,
            timeout_ms: 1_000,
            stdin_bytes: 0,
            stdout: Captured::default(),
            stderr: Captured::default(),
            sandbox_reusable: None,
            cleanup_evidence: CleanupEvidence::Unknown,
        };
        store.insert_execution(&execution).unwrap();
        store
            .finish_execution(
                &execution.id,
                &ExecutionResult {
                    state: ExecutionState::Exited,
                    exit_code: Some(0),
                    command_status: Some(&status),
                    runtime_error: None,
                    failure_reason: None,
                    stdout: &capture,
                    stderr: &capture,
                    sandbox_reusable: None,
                    cleanup_evidence: CleanupEvidence::Unknown,
                    disposition: None,
                    disposition_reason: None,
                },
            )
            .unwrap();
    }
    drop(store);
    drop(capture);

    let manager = Manager::new(
        FakeRuntime::default(),
        Store::open(&root).unwrap(),
        Limits::default(),
    );
    let before = rss_bytes(std::process::id());
    let (_, history) = manager.get(&sandbox.id, HISTORY_ROWS as u32).unwrap();
    let after = rss_bytes(std::process::id());
    let delta = after.saturating_sub(before);
    assert_eq!(history.len(), HISTORY_ROWS);
    assert!(history.iter().all(|execution| {
        execution.stdout.data.is_empty()
            && execution.stderr.data.is_empty()
            && !execution.stdout.truncated()
            && !execution.stderr.truncated()
            && execution.stdout.total_bytes_known
            && execution.stderr.total_bytes_known
    }));
    println!(
        "GetSandbox metadata RSS: before={before} after={after} delta={delta}; omitted={} retained-output bytes",
        HISTORY_ROWS * 2 * HISTORY_STREAM_BYTES
    );
    assert!(
        delta < 32 << 20,
        "metadata projection loaded output BLOBs: before={before} after={after} delta={delta}"
    );
    std::hint::black_box(history);
}

#[test]
#[ignore = "Linux /proc stress; run scripts/integration-test.sh in the VM"]
fn getsandbox_metadata_worst_case_does_not_load_output_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "metadata_history_rss_child",
            "--nocapture",
        ])
        .env(HISTORY_CHILD_ENV, "1")
        .env(HISTORY_ROOT_ENV, tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "metadata RSS child failed");
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
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
