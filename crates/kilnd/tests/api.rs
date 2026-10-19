//! The whole gRPC API over a real Unix socket, with the fake backend.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kilnd::manager::{Limits, Manager};
use kilnd::runtime::fake::{FakeGate, FakeRuntime};
use kilnd::store::Store;
use kilnd_api::v1 as pb;
use pb::kilnd_service_client::KilndServiceClient;
use tokio::net::UnixStream;
use tonic::Code;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

async fn client(path: PathBuf) -> KilndServiceClient<Channel> {
    let channel = Endpoint::try_from("http://kilnd.invalid")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    KilndServiceClient::new(channel)
}

#[tokio::test]
async fn every_rpc_over_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(fake.clone(), Store::open(&tmp.path().join("state")).unwrap(), Limits::default()));
    let listener = kilnd::server::bind(&socket, None).unwrap();
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(socket.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager,
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_millis(200),
    ));
    let mut c = client(socket.clone()).await;

    let h = c.health(pb::HealthRequest {}).await.unwrap().into_inner();
    assert_eq!(h.status, pb::health_response::Status::Serving as i32);
    assert_eq!(h.backend, "fake");

    let spec = pb::SandboxSpec {
        limits: Some(pb::ResourceLimits { memory_bytes: 64 << 20, ..Default::default() }),
        network: Some(pb::NetworkPolicy { mode: pb::NetworkMode::Allowlist as i32, allow: vec!["example.com:443".into()] }),
        labels: [("purpose".to_string(), "test".to_string())].into(),
        ..Default::default()
    };
    let sandbox = c
        .create_sandbox(pb::CreateSandboxRequest { spec: Some(spec) })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(sandbox.state, pb::SandboxState::Ready as i32);
    let effective = sandbox.spec.clone().unwrap();
    assert_eq!(effective.image, "alpine");
    assert_eq!(effective.limits.unwrap().memory_bytes, 64 << 20);
    assert_eq!(effective.labels["purpose"], "test");
    assert!(!sandbox.backend_id.is_empty());

    let e = c
        .exec(pb::ExecRequest {
            sandbox_id: sandbox.id.clone(),
            argv: vec!["echo".into(), "hi".into()],
            stdin: vec![],
            timeout_ms: 5000,
        })
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(e.state, pb::ExecutionState::Exited as i32);
    assert_eq!(e.exit_code, Some(0));
    assert_eq!(e.stdout.as_ref().unwrap().data, b"hi\n");

    let fetched = c.get_execution(pb::GetExecutionRequest { id: e.id.clone() }).await.unwrap().into_inner();
    assert_eq!(fetched.execution.unwrap(), e);

    let got = c
        .get_sandbox(pb::GetSandboxRequest { id: sandbox.id.clone(), execution_limit: 0 })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.sandbox.unwrap().id, sandbox.id);
    assert_eq!(got.recent_executions.len(), 1);
    assert!(got.recent_executions[0].stdout.as_ref().unwrap().data.is_empty());

    let listed = c.list_sandboxes(pb::ListSandboxesRequest { include_deleted: false }).await.unwrap().into_inner();
    assert_eq!(listed.sandboxes.len(), 1);

    let deleted = c
        .delete_sandbox(pb::DeleteSandboxRequest { id: sandbox.id.clone() })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(deleted.state, pb::SandboxState::Deleted as i32);
    assert!(deleted.deleted_at_unix_ms > 0);
    assert!(fake.state().sandboxes.is_empty());
    let listed = c.list_sandboxes(pb::ListSandboxesRequest { include_deleted: false }).await.unwrap().into_inner();
    assert!(listed.sandboxes.is_empty());
    let listed = c.list_sandboxes(pb::ListSandboxesRequest { include_deleted: true }).await.unwrap().into_inner();
    assert_eq!(listed.sandboxes.len(), 1);

    // Error codes.
    let missing = pb::GetSandboxRequest { id: "sb-0000000000000000".into(), execution_limit: 0 };
    assert_eq!(c.get_sandbox(missing).await.unwrap_err().code(), Code::NotFound);
    let bad = pb::GetSandboxRequest { id: "../x".into(), execution_limit: 0 };
    assert_eq!(c.get_sandbox(bad).await.unwrap_err().code(), Code::InvalidArgument);
    let exec_deleted = pb::ExecRequest { sandbox_id: sandbox.id.clone(), argv: vec!["echo".into()], ..Default::default() };
    assert_eq!(c.exec(exec_deleted).await.unwrap_err().code(), Code::FailedPrecondition);
    let mixed = pb::SandboxSpec {
        network: Some(pb::NetworkPolicy { mode: pb::NetworkMode::Full as i32, allow: vec!["example.com".into()] }),
        ..Default::default()
    };
    let err = c.create_sandbox(pb::CreateSandboxRequest { spec: Some(mixed) }).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    fake.state().fail_create = Some("no image".into());
    let err = c.create_sandbox(pb::CreateSandboxRequest { spec: None }).await.unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("no image"));

    drop(c);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn graceful_shutdown_cancels_running_executions_after_the_grace_period() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("kilnd.sock");
    let manager = Arc::new(Manager::new(FakeRuntime::default(), Store::open_in_memory().unwrap(), Limits::default()));
    let sandbox = manager.create(Default::default()).await.unwrap();
    let listener = kilnd::server::bind(&socket, None).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_millis(300),
    ));
    let mut c = client(socket.clone()).await;
    let exec = tokio::spawn(async move {
        c.exec(pb::ExecRequest { sandbox_id: sandbox.id, argv: vec!["sleep".into()], ..Default::default() }).await
    });
    while manager.health().await.unwrap().running_executions == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop_tx.send(()).unwrap();
    let e = tokio::time::timeout(Duration::from_secs(5), exec).await.unwrap().unwrap().unwrap().into_inner();
    let e = e.execution.unwrap();
    assert_eq!(e.state, pb::ExecutionState::Canceled as i32);
    assert_eq!(e.failure_reason, "kilnd shut down");
    tokio::time::timeout(Duration::from_secs(15), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn canceling_a_tonic_exec_request_finalizes_and_releases_the_backend() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(fake.clone(), Store::open_in_memory().unwrap(), Limits::default()));
    let sandbox = manager.create(Default::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let listener = kilnd::server::bind(&socket, None).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));
    let mut c = client(socket).await;
    let request = tokio::spawn({
        let sandbox_id = sandbox.id.clone();
        async move {
            c.exec(pb::ExecRequest {
                sandbox_id,
                argv: vec!["sleep".into()],
                ..Default::default()
            })
            .await
        }
    });

    gate.entered().await;
    let execution_id = manager.get(&sandbox.id, 1).unwrap().1[0].id.clone();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    gate.release();
    let execution = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let execution = manager.execution(&execution_id).unwrap();
            if execution.state != kilnd::model::ExecutionState::Running {
                break execution;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("canceled tonic exec did not finalize");
    assert_eq!(execution.state, kilnd::model::ExecutionState::Canceled);
    assert_eq!(execution.failure_reason.as_deref(), Some("client disconnected"));
    assert_eq!(fake.state().active_execs, 0);
    assert_eq!(fake.state().canceled_execs, 1);

    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn graceful_shutdown_drains_a_create_after_its_rpc_disconnects() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("kilnd.sock");
    let fake = FakeRuntime::default();
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let manager = Arc::new(Manager::new(fake.clone(), Store::open_in_memory().unwrap(), Limits::default()));
    let listener = kilnd::server::bind(&socket, None).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::ZERO,
    ));
    let mut c = client(socket).await;
    let request = tokio::spawn(async move { c.create_sandbox(pb::CreateSandboxRequest { spec: None }).await });

    gate.entered().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    stop_tx.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut server).await.is_err(),
        "server exited without draining its accepted create"
    );
    assert_eq!(manager.list(true).unwrap()[0].state, kilnd::model::SandboxState::Creating);

    gate.release();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
    let row = manager.list(true).unwrap().remove(0);
    assert_eq!(row.state, kilnd::model::SandboxState::Ready);
    assert_eq!(row.backend_id.as_ref(), fake.state().sandboxes.keys().next());
}

#[test]
fn bind_refuses_to_replace_a_regular_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("kilnd.sock");
    std::fs::write(&path, b"not a socket").unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _guard = rt.enter();
    assert!(kilnd::server::bind(&path, None).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

#[test]
fn bind_replaces_a_stale_socket_and_tightens_the_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.join("kilnd.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _guard = rt.enter();
    let _listener = kilnd::server::bind(&path, None).unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
}
