//! The whole gRPC API over a real Unix socket, with the fake backend.

use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
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
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
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
    let socket = tmp.path().join("run/kilnd.sock");
    let manager = Arc::new(Manager::new(FakeRuntime::default(), Store::open_in_memory().unwrap(), Limits::default()));
    let sandbox = manager.create(Default::default()).await.unwrap();
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
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
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(fake.clone(), Store::open_in_memory().unwrap(), Limits::default()));
    let sandbox = manager.create(Default::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));
    let mut c = client(socket.clone()).await;
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
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let manager = Arc::new(Manager::new(fake.clone(), Store::open_in_memory().unwrap(), Limits::default()));
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::ZERO,
    ));
    let mut c = client(socket.clone()).await;
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
    let alternate = socket.parent().unwrap().join("alternate.sock");
    let error = kilnd::server::bind(&alternate, None)
        .await
        .err()
        .expect("socket-directory ownership was released before operation drain");
    assert!(error.to_string().contains("socket directory already owned"), "{error:#}");

    gate.release();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
    assert!(!socket.exists(), "graceful shutdown left its owned socket behind");
    let replacement = kilnd::server::bind(&alternate, None).await.unwrap();
    drop(replacement);
    let row = manager.list(true).unwrap().remove(0);
    assert_eq!(row.state, kilnd::model::SandboxState::Ready);
    assert_eq!(row.backend_id.as_ref(), fake.state().sandboxes.keys().next());
}

#[test]
fn bind_refuses_to_replace_a_regular_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    std::fs::write(&path, b"not a socket").unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    assert!(rt.block_on(kilnd::server::bind(&path, None)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

#[cfg(target_os = "linux")]
#[test]
fn bind_replaces_a_stale_socket_and_tightens_the_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.join("kilnd.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _listener = rt.block_on(kilnd::server::bind(&path, None)).unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn bind_preserves_a_stale_socket_when_refusal_is_ambiguous() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let inode = std::fs::symlink_metadata(&path).unwrap().ino();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

    let error = rt.block_on(kilnd::server::bind(&path, None)).err().expect("ambiguous refusal was treated as stale");
    assert!(error.to_string().contains("inconclusive"), "{error:#}");
    assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
}

#[test]
fn bind_refuses_to_replace_a_live_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    let incumbent = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let incumbent_inode = std::fs::symlink_metadata(&path).unwrap().ino();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    assert!(rt.block_on(kilnd::server::bind(&path, None)).is_err());
    assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), incumbent_inode);
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
    drop(incumbent);
}

#[tokio::test]
async fn bind_preserves_a_live_listener_with_a_full_backlog() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    let incumbent = std::os::unix::net::UnixListener::bind(&path).unwrap();
    // SAFETY: the descriptor is a live listening Unix socket. Repeating
    // listen changes only its backlog, making saturation deterministic.
    assert_eq!(unsafe { libc::listen(incumbent.as_raw_fd(), 1) }, 0);
    incumbent.set_nonblocking(true).unwrap();
    let incumbent_inode = std::fs::symlink_metadata(&path).unwrap().ino();
    let mut queued = Vec::new();
    let mut saturated = false;
    for _ in 0..32 {
        match tokio::time::timeout(Duration::from_millis(20), UnixStream::connect(&path)).await {
            Ok(Ok(stream)) => queued.push(stream),
            Ok(Err(_)) | Err(_) => {
                saturated = true;
                break;
            }
        }
    }
    assert!(saturated, "could not saturate the incumbent listener backlog");

    let error = kilnd::server::bind(&path, None)
        .await
        .err()
        .expect("a saturated live listener was replaced");
    assert!(
        error.to_string().contains("refusing") || error.to_string().contains("timed out"),
        "{error:#}"
    );
    assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), incumbent_inode);

    let incumbent = tokio::net::UnixListener::from_std(incumbent).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(1), incumbent.accept()).await.unwrap().unwrap().0;
    let fresh = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(&path)).await.unwrap().unwrap();
    drop((fresh, accepted, queued));
}

#[test]
fn socket_directory_has_one_owner_even_for_different_socket_names() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let first_path = dir.join("first.sock");
    let second_path = dir.join("second.sock");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let first = rt.block_on(kilnd::server::bind(&first_path, None)).unwrap();

    let error = rt
        .block_on(kilnd::server::bind(&second_path, None))
        .err()
        .expect("two sockets acquired the same directory");
    assert!(error.to_string().contains("socket directory already owned"), "{error:#}");
    assert!(!second_path.exists());

    drop(first);
    assert!(!first_path.exists());
    let second = rt.block_on(kilnd::server::bind(&second_path, None)).unwrap();
    assert!(second_path.exists());
    drop(second);
    assert!(!second_path.exists());
}

#[test]
fn simultaneous_socket_directory_starts_have_one_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    let paths = [dir.join("first.sock"), dir.join("second.sock")];
    let start = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(3));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut threads = Vec::new();
    for path in paths {
        let start = start.clone();
        let release = release.clone();
        let tx = tx.clone();
        threads.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            start.wait();
            let owned = runtime.block_on(kilnd::server::bind(&path, None));
            let outcome = owned.as_ref().map(|_| ()).map_err(|error| format!("{error:#}"));
            tx.send(outcome).unwrap();
            release.wait();
            drop(owned);
        }));
    }
    drop(tx);

    let outcomes: Vec<_> = (0..2).map(|_| rx.recv().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let loser = outcomes.iter().find_map(|outcome| outcome.as_ref().err()).unwrap();
    assert!(loser.contains("socket directory already owned"), "{loser}");
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
fn socket_cleanup_leaves_a_replacement_inode_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    let old_path = dir.join("original.sock");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let owned = rt.block_on(kilnd::server::bind(&path, None)).unwrap();

    std::fs::rename(&path, &old_path).unwrap();
    let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let replacement_inode = std::fs::symlink_metadata(&path).unwrap().ino();
    drop(owned);

    assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), replacement_inode);
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
    drop(replacement);
}
