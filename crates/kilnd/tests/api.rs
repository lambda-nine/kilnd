//! The whole gRPC API over a real Unix socket, with the fake backend.
// Approved (design 7.1): test fixtures, an integration-test crate. They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#![allow(clippy::disallowed_methods)]

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
use prost::Message;
use tokio::net::UnixStream;
use tonic::Code;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

#[test]
fn signal_number_is_uint32_in_generated_types_schema_and_wire() {
    let _: u32 = pb::SignalStatus::default().number;
    assert!(include_str!("../../../proto/kilnd/v1/kilnd.proto").contains("uint32 number = 1;"));
    let status = pb::SignalStatus {
        number: u32::MAX,
        core_dumped: true,
    };
    assert_eq!(
        pb::SignalStatus::decode(status.encode_to_vec().as_slice()).unwrap(),
        status
    );
    let execution = kilnd::model::Execution {
        id: "ex-signal".into(),
        sandbox_id: "sb-signal".into(),
        argv: vec![],
        state: kilnd::model::ExecutionState::Exited,
        exit_code: Some(192),
        command_status: Some(kilnd::model::CommandStatus::Signaled {
            signal: 64,
            core_dumped: true,
        }),
        runtime_error: None,
        failure_reason: None,
        started_at_ms: 1,
        finished_at_ms: Some(2),
        timeout_ms: 1,
        stdin_bytes: 0,
        stdout: Default::default(),
        stderr: Default::default(),
        sandbox_reusable: None,
        cleanup_evidence: Default::default(),
        cancel_reason: None,
    };
    let converted = kilnd::service::execution_pb(execution);
    let decoded = pb::Execution::decode(converted.encode_to_vec().as_slice()).unwrap();
    assert_eq!(
        decoded.command_status.unwrap().termination,
        Some(pb::command_status::Termination::Signal(pb::SignalStatus {
            number: 64u32,
            core_dumped: true
        }))
    );
}

/// The uid the kernel reports for this test's own socket connections.
fn test_uid() -> u32 {
    unsafe { libc::geteuid() }
}

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
async fn many_socket_clients_share_one_serialized_delete() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&tmp.path().join("state")).unwrap(),
        // One UID's 33 clients: this is about the serialized Delete, so the per-UID
        // shares (B7, B6-BI-03) are opened to the whole budget.
        Limits {
            max_connections_per_uid: 60,
            max_concurrent_rpcs_per_uid: 64,
            ..Limits::default()
        },
    ));
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager,
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_millis(200),
    ));

    let mut creator = client(socket.clone()).await;
    let sandbox_id = creator
        .create_sandbox(pb::CreateSandboxRequest::default())
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
        .id;
    let gate = FakeGate::default();
    fake.state().remove_before_delete = Some(gate.clone());

    let mut first_client = client(socket.clone()).await;
    let first_id = sandbox_id.clone();
    let first = tokio::spawn(async move {
        first_client
            .delete_sandbox(pb::DeleteSandboxRequest { release_request_id: false, id: first_id })
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
    });
    gate.entered().await;

    let mut queued = Vec::new();
    for _ in 0..31 {
        let mut delete_client = client(socket.clone()).await;
        let id = sandbox_id.clone();
        queued.push(tokio::spawn(async move {
            delete_client
                .delete_sandbox(pb::DeleteSandboxRequest { release_request_id: false, id })
                .await
                .unwrap()
                .into_inner()
                .sandbox
                .unwrap()
        }));
    }
    tokio::task::yield_now().await;
    gate.release();

    let deleted = first.await.unwrap();
    assert_eq!(deleted.state, pb::SandboxState::Deleted as i32);
    for response in queued {
        let response = response.await.unwrap();
        assert_eq!(response.state, pb::SandboxState::Deleted as i32);
        assert_eq!(response.deleted_at_unix_ms, deleted.deleted_at_unix_ms);
        assert_eq!(response.updated_at_unix_ms, deleted.updated_at_unix_ms);
    }
    assert_eq!(fake.state().remove_attempts.len(), 1);
    assert_eq!(fake.state().removed.len(), 1);

    drop(creator);
    let _ = stop_tx.send(());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn typed_outcomes_and_failed_binary_evidence_survive_api_store_and_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let state = tmp.path().join("state");
    let fake = FakeRuntime::default();
    let mut saved = Vec::new();
    let mut sandbox_id = String::new();
    for phase in 0..2 {
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open(&state).unwrap(),
            Limits::default(),
        ));
        let listener = kilnd::server::bind(&socket, None).await.unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(kilnd::server::serve(
            manager.clone(),
            listener,
            async {
                let _ = stopped.await;
            },
            Duration::from_millis(100),
        ));
        let mut c = client(socket.clone()).await;
        if phase == 0 {
            sandbox_id = c
                .create_sandbox(pb::CreateSandboxRequest::default())
                .await
                .unwrap()
                .into_inner()
                .sandbox
                .unwrap()
                .id;
            for argv in [
                vec!["exit", "125"],
                vec!["exit", "143"],
                vec!["signal", "15", "core"],
                vec!["runtime-failure"],
            ] {
                let e = c
                    .exec(pb::ExecRequest {
                        sandbox_id: sandbox_id.clone(),
                        argv: argv.into_iter().map(str::to_owned).collect(),
                        timeout_ms: 5000,
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .into_inner()
                    .execution
                    .unwrap();
                saved.push(e);
            }
            assert_eq!(saved[0].exit_code, Some(125));
            assert_eq!(
                saved[0].command_status.as_ref().unwrap().termination,
                Some(pb::command_status::Termination::ExitCode(125))
            );
            assert_eq!(
                saved[1].command_status.as_ref().unwrap().termination,
                Some(pb::command_status::Termination::ExitCode(143))
            );
            assert_eq!(
                saved[2].command_status.as_ref().unwrap().termination,
                Some(pb::command_status::Termination::Signal(pb::SignalStatus {
                    number: 15,
                    core_dumped: true
                }))
            );
            let failure = &saved[3];
            assert_eq!(failure.state, pb::ExecutionState::Failed as i32);
            assert_eq!(failure.exit_code, None);
            assert_eq!(
                failure.runtime_error.as_ref().unwrap().kind,
                pb::RuntimeErrorKind::Io as i32
            );
            assert_eq!(failure.stdout.as_ref().unwrap().data, b"\0\xffout");
            assert_eq!(failure.stdout.as_ref().unwrap().total_bytes, 99);
            assert!(failure.stdout.as_ref().unwrap().truncated);
            assert!(!failure.stdout.as_ref().unwrap().total_bytes_known);
            assert_eq!(failure.stderr.as_ref().unwrap().data, b"\0\xfeerr");
            assert_eq!(failure.stderr.as_ref().unwrap().total_bytes, 101);
            assert!(failure.stderr.as_ref().unwrap().truncated);
            assert!(!failure.stderr.as_ref().unwrap().total_bytes_known);
        }
        for expected in &saved {
            let got = c
                .get_execution(pb::GetExecutionRequest {
                    id: expected.id.clone(),
                })
                .await
                .unwrap()
                .into_inner()
                .execution
                .unwrap();
            assert_eq!(&got, expected);
        }
        let recent = c
            .get_sandbox(pb::GetSandboxRequest {
                id: sandbox_id.clone(),
                execution_limit: 10,
            })
            .await
            .unwrap()
            .into_inner()
            .recent_executions;
        assert_eq!(recent.len(), 4);
        assert!(recent[0].stdout.as_ref().unwrap().data.is_empty());
        for metadata in recent {
            let full = saved.iter().find(|e| e.id == metadata.id).unwrap();
            assert_eq!(metadata.command_status, full.command_status);
            assert_eq!(metadata.runtime_error, full.runtime_error);
            assert_eq!(
                metadata.stdout.as_ref().unwrap().truncated,
                full.stdout.as_ref().unwrap().truncated,
                "GetSandbox metadata changed stdout truncation"
            );
            assert_eq!(
                metadata.stderr.as_ref().unwrap().truncated,
                full.stderr.as_ref().unwrap().truncated,
                "GetSandbox metadata changed stderr truncation"
            );
            assert_eq!(
                metadata.stdout.as_ref().unwrap().total_bytes_known,
                full.stdout.as_ref().unwrap().total_bytes_known,
                "GetSandbox metadata changed stdout total certainty"
            );
            assert_eq!(
                metadata.stderr.as_ref().unwrap().total_bytes_known,
                full.stderr.as_ref().unwrap().total_bytes_known,
                "GetSandbox metadata changed stderr total certainty"
            );
        }
        drop(c);
        let _ = stop.send(());
        server.await.unwrap().unwrap();
        drop(manager);
    }
}

#[tokio::test]
async fn every_rpc_over_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&tmp.path().join("state")).unwrap(),
        Limits::default(),
    ));
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

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
    let admission = h.admission.unwrap();
    assert_eq!(admission.max_connections, 64);
    assert_eq!(admission.current_connections, 1);
    assert_eq!(admission.current_health, 1);
    let resources = h.node_resources.unwrap();
    assert_eq!(resources.max_memory_bytes, 3 << 30);
    assert_eq!(resources.max_pids, 2048);
    assert_eq!(resources.max_disk_bytes, 16 << 30);
    assert_eq!(resources.reserved_sandboxes, 0);

    let spec = pb::SandboxSpec {
        limits: Some(pb::ResourceLimits {
            memory_bytes: 64 << 20,
            ..Default::default()
        }),
        network: Some(pb::NetworkPolicy {
            mode: pb::NetworkMode::Allowlist as i32,
            allow: vec!["example.com:443".into()],
        }),
        labels: [("purpose".to_string(), "test".to_string())].into(),
        ..Default::default()
    };
    let sandbox = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: Some(spec),
            expiry: None,
        })
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

    let fetched = c
        .get_execution(pb::GetExecutionRequest { id: e.id.clone() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fetched.execution.unwrap(), e);

    let got = c
        .get_sandbox(pb::GetSandboxRequest {
            id: sandbox.id.clone(),
            execution_limit: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.sandbox.unwrap().id, sandbox.id);
    assert_eq!(got.recent_executions.len(), 1);
    assert!(
        got.recent_executions[0]
            .stdout
            .as_ref()
            .unwrap()
            .data
            .is_empty()
    );

    let listed = c
        .list_sandboxes(pb::ListSandboxesRequest {
            include_deleted: false,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.sandboxes.len(), 1);

    let deleted = c
        .delete_sandbox(pb::DeleteSandboxRequest { release_request_id: false,
            id: sandbox.id.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(deleted.state, pb::SandboxState::Deleted as i32);
    assert!(deleted.deleted_at_unix_ms > 0);
    assert!(fake.state().sandboxes.is_empty());
    let listed = c
        .list_sandboxes(pb::ListSandboxesRequest {
            include_deleted: false,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(listed.sandboxes.is_empty());
    let listed = c
        .list_sandboxes(pb::ListSandboxesRequest {
            include_deleted: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.sandboxes.len(), 1);

    // Error codes.
    let missing = pb::GetSandboxRequest {
        id: "sb-0000000000000000".into(),
        execution_limit: 0,
    };
    assert_eq!(
        c.get_sandbox(missing).await.unwrap_err().code(),
        Code::NotFound
    );
    let bad = pb::GetSandboxRequest {
        id: "../x".into(),
        execution_limit: 0,
    };
    assert_eq!(
        c.get_sandbox(bad).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let exec_deleted = pb::ExecRequest {
        sandbox_id: sandbox.id.clone(),
        argv: vec!["echo".into()],
        ..Default::default()
    };
    let refused = c.exec(exec_deleted).await.unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    // The typed reason crosses the real transport as an ASCII trailer.
    assert_eq!(
        refused
            .metadata()
            .get("kilnd-reason")
            .map(|v| v.to_str().unwrap()),
        Some("sandbox_deleted")
    );
    assert!(
        refused.message().starts_with("sandbox_deleted: "),
        "{}",
        refused.message()
    );
    let renew = c
        .renew_sandbox(pb::RenewSandboxRequest {
            id: sandbox.id.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(renew.code(), Code::FailedPrecondition);
    assert_eq!(
        renew.metadata().get("kilnd-reason").map(|v| v.to_str().unwrap()),
        Some("sandbox_deleted")
    );
    let mixed = pb::SandboxSpec {
        network: Some(pb::NetworkPolicy {
            mode: pb::NetworkMode::Full as i32,
            allow: vec!["example.com".into()],
        }),
        ..Default::default()
    };
    let err = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: Some(mixed),
            expiry: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    fake.state().fail_create = Some("no image".into());
    let err = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: None,
            expiry: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("no image"));

    // The wire contract is unchanged for a definite failure; only Health's
    // reservations and DeleteSandbox's result show its release.
    let charged = c
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner()
        .node_resources
        .unwrap()
        .reserved_sandboxes;
    {
        let mut backend = fake.state();
        backend.fail_create = None;
        backend.fail_create_definitely = Some("image missing".into());
    }
    let err = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: None,
            expiry: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("image missing"));
    assert_eq!(
        c.health(pb::HealthRequest {})
            .await
            .unwrap()
            .into_inner()
            .node_resources
            .unwrap()
            .reserved_sandboxes,
        charged
    );
    let id = c
        .list_sandboxes(pb::ListSandboxesRequest::default())
        .await
        .unwrap()
        .into_inner()
        .sandboxes
        .into_iter()
        .find(|sandbox| sandbox.failure_reason.contains("image missing"))
        .unwrap()
        .id;
    let deleted = c
        .delete_sandbox(pb::DeleteSandboxRequest { release_request_id: false, id })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(deleted.state, pb::SandboxState::Deleted as i32);

    drop(c);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn wire_message_caps_reject_oversize_decode_and_encode_without_losing_owned_work() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_request_bytes: 128,
            max_response_bytes: 128,
            ..Limits::default()
        },
    ));
    let listener = kilnd::server::bind(&path, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));
    let mut c = client(path).await;
    let oversize = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: Some(pb::SandboxSpec {
                labels: [("test".into(), "x".repeat(256))].into(),
                ..Default::default()
            }),
            expiry: None,
        })
        .await
        .unwrap_err();
    assert_eq!(oversize.code(), Code::OutOfRange);
    assert!(fake.state().created.is_empty());
    assert!(manager.list(true).unwrap().is_empty());
    // The response cap can fail only after a successful owned operation.
    // Its durable result is still inspectable and is not compensated away.
    let response = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: Some(pb::SandboxSpec {
                labels: [("test".into(), "x".repeat(70))].into(),
                ..Default::default()
            }),
            expiry: None,
        })
        .await
        .unwrap_err();
    assert_eq!(response.code(), Code::OutOfRange);
    assert_eq!(fake.state().created.len(), 1);
    assert_eq!(
        manager.list(true).unwrap()[0].state,
        kilnd::model::SandboxState::Ready
    );
    assert_eq!(fake.state().sandboxes.len(), 1);
    drop(c);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ownership_comes_from_the_kernel_credentials_of_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager.clone(),
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_millis(200),
    ));
    let mut c = client(socket.clone()).await;

    let mine = c
        .create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: None,
            expiry: None,
        })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(mine.owner_uid, test_uid());
    assert_eq!(
        pb::Sandbox::decode(mine.encode_to_vec().as_slice())
            .unwrap()
            .owner_uid,
        test_uid()
    );
    let execution = c
        .exec(pb::ExecRequest {
            sandbox_id: mine.id.clone(),
            argv: vec!["echo".into(), "mine".into()],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(
        c.get_execution(pb::GetExecutionRequest { id: execution.id })
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap()
            .stdout
            .unwrap()
            .data,
        b"mine\n"
    );

    // Whichever uid runs this test, another uid's rows behave accordingly.
    let foreign_uid = test_uid().wrapping_add(1);
    let foreign = manager
        .create_owned(Default::default(), foreign_uid)
        .await
        .unwrap();
    let foreign_execution = manager
        .exec(kilnd::manager::ExecRequest {
            sandbox_id: foreign.id.clone(),
            argv: vec!["echo".into(), "theirs".into()],
            stdin: vec![],
            timeout_ms: 0,
        })
        .await
        .unwrap();
    let listed: Vec<String> = c
        .list_sandboxes(pb::ListSandboxesRequest {
            page_size: Some(10),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .sandboxes
        .into_iter()
        .map(|s| s.id)
        .collect();
    let get = c
        .get_sandbox(pb::GetSandboxRequest {
            id: foreign.id.clone(),
            execution_limit: 0,
        })
        .await;
    let read = c
        .get_execution(pb::GetExecutionRequest {
            id: foreign_execution.id,
        })
        .await;
    if test_uid() == 0 {
        assert_eq!(listed, [foreign.id.clone(), mine.id.clone()]);
        get.unwrap();
        read.unwrap();
    } else {
        assert_eq!(listed, std::slice::from_ref(&mine.id));
        assert_eq!(get.unwrap_err().code(), Code::NotFound);
        assert_eq!(read.unwrap_err().code(), Code::NotFound);
        assert_eq!(
            c.exec(pb::ExecRequest {
                sandbox_id: foreign.id.clone(),
                argv: vec!["echo".into()],
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
            Code::NotFound
        );
        assert_eq!(
            c.delete_sandbox(pb::DeleteSandboxRequest { release_request_id: false,
                id: foreign.id.clone()
            })
            .await
            .unwrap_err()
            .code(),
            Code::NotFound
        );
        assert_eq!(fake.state().exec_calls.len(), 2);
        assert!(fake.state().remove_attempts.is_empty());
    }

    stop_tx.send(()).unwrap();
    drop(c);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn graceful_shutdown_cancels_running_executions_after_the_grace_period() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let manager = Arc::new(Manager::new(
        FakeRuntime::default(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let sandbox = manager
        .create_owned(Default::default(), test_uid())
        .await
        .unwrap();
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
        c.exec(pb::ExecRequest {
            sandbox_id: sandbox.id,
            argv: vec!["sleep".into()],
            ..Default::default()
        })
        .await
    });
    while manager.health().await.unwrap().running_executions == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop_tx.send(()).unwrap();
    let e = tokio::time::timeout(Duration::from_secs(5), exec)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_inner();
    let e = e.execution.unwrap();
    assert_eq!(e.state, pb::ExecutionState::Canceled as i32);
    assert_eq!(e.failure_reason, "kilnd shut down");
    tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn canceling_a_tonic_exec_request_finalizes_and_releases_the_backend() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let sandbox = manager
        .create_owned(Default::default(), test_uid())
        .await
        .unwrap();
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
    assert_eq!(
        execution.failure_reason.as_deref(),
        Some("client disconnected")
    );
    assert_eq!(fake.state().active_execs, 0);
    assert_eq!(fake.state().canceled_execs, 1);

    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn graceful_shutdown_drains_a_create_after_its_rpc_disconnects() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
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
    let request = tokio::spawn(async move {
        c.create_sandbox(pb::CreateSandboxRequest { request_id: String::new(),
            spec: None,
            expiry: None,
        })
        .await
    });

    gate.entered().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    stop_tx.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut server)
            .await
            .is_err(),
        "server exited without draining its accepted create"
    );
    assert_eq!(
        manager.list(true).unwrap()[0].state,
        kilnd::model::SandboxState::Creating
    );
    let alternate = socket.parent().unwrap().join("alternate.sock");
    let error = kilnd::server::bind(&alternate, None)
        .await
        .err()
        .expect("socket-directory ownership was released before operation drain");
    assert!(
        error.to_string().contains("socket directory already owned"),
        "{error:#}"
    );

    gate.release();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        !socket.exists(),
        "graceful shutdown left its owned socket behind"
    );
    let replacement = kilnd::server::bind(&alternate, None).await.unwrap();
    drop(replacement);
    let row = manager.list(true).unwrap().remove(0);
    assert_eq!(row.state, kilnd::model::SandboxState::Ready);
    assert_eq!(
        row.backend_id.as_ref(),
        fake.state().sandboxes.keys().next()
    );
}

#[test]
fn bind_refuses_to_replace_a_regular_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    std::fs::write(&path, b"not a socket").unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(rt.block_on(kilnd::server::bind(&path, None)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

#[cfg(target_os = "linux")]
#[test]
fn bind_replaces_a_stale_socket_and_tightens_the_directory() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = tmp.path().join("run");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.join("kilnd.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _listener = rt.block_on(kilnd::server::bind(&path, None)).unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let error = rt
        .block_on(kilnd::server::bind(&path, None))
        .err()
        .expect("ambiguous refusal was treated as stale");
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(rt.block_on(kilnd::server::bind(&path, None)).is_err());
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().ino(),
        incumbent_inode
    );
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
    drop(incumbent);
}

#[tokio::test]
async fn bind_preserves_a_live_listener_with_a_full_backlog() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
    assert!(
        saturated,
        "could not saturate the incumbent listener backlog"
    );

    let error = kilnd::server::bind(&path, None)
        .await
        .err()
        .expect("a saturated live listener was replaced");
    assert!(
        error.to_string().contains("refusing") || error.to_string().contains("timed out"),
        "{error:#}"
    );
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().ino(),
        incumbent_inode
    );

    let incumbent = tokio::net::UnixListener::from_std(incumbent).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(1), incumbent.accept())
        .await
        .unwrap()
        .unwrap()
        .0;
    let fresh = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(&path))
        .await
        .unwrap()
        .unwrap();
    drop((fresh, accepted, queued));
}

#[test]
fn socket_directory_has_one_owner_even_for_different_socket_names() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let first_path = dir.join("first.sock");
    let second_path = dir.join("second.sock");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let first = rt.block_on(kilnd::server::bind(&first_path, None)).unwrap();

    let error = rt
        .block_on(kilnd::server::bind(&second_path, None))
        .err()
        .expect("two sockets acquired the same directory");
    assert!(
        error.to_string().contains("socket directory already owned"),
        "{error:#}"
    );
    assert!(!second_path.exists());

    drop(first);
    assert!(!first_path.exists());
    let second = rt
        .block_on(kilnd::server::bind(&second_path, None))
        .unwrap();
    assert!(second_path.exists());
    drop(second);
    assert!(!second_path.exists());
}

#[test]
fn simultaneous_socket_directory_starts_have_one_owner() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            start.wait();
            let owned = runtime.block_on(kilnd::server::bind(&path, None));
            let outcome = owned
                .as_ref()
                .map(|_| ())
                .map_err(|error| format!("{error:#}"));
            tx.send(outcome).unwrap();
            release.wait();
            drop(owned);
        }));
    }
    drop(tx);

    let outcomes: Vec<_> = (0..2).map(|_| rx.recv().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let loser = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().err())
        .unwrap();
    assert!(loser.contains("socket directory already owned"), "{loser}");
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
fn socket_cleanup_leaves_a_replacement_inode_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = tmp.path().join("run");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("kilnd.sock");
    let old_path = dir.join("original.sock");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let owned = rt.block_on(kilnd::server::bind(&path, None)).unwrap();

    std::fs::rename(&path, &old_path).unwrap();
    let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let replacement_inode = std::fs::symlink_metadata(&path).unwrap().ino();
    drop(owned);

    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().ino(),
        replacement_inode
    );
    assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
    drop(replacement);
}

fn reason(status: &tonic::Status) -> Option<String> {
    status
        .metadata()
        .get("kilnd-reason")
        .map(|v| v.to_str().unwrap().to_string())
}

/// API additions M2 over a real socket: the client's own gRPC deadline reaches the
/// handler, so a retry of a create still in flight is told `create_in_flight` before
/// its transport gives up; a retry without one waits and gets the original's answer;
/// release frees the key.
#[tokio::test]
async fn idempotent_create_over_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&tmp.path().join("state")).unwrap(),
        Limits::default(),
    ));
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager,
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_millis(200),
    ));
    let request = |labels: &[(&str, &str)]| pb::CreateSandboxRequest {
        request_id: "run-1/task-2".into(),
        spec: Some(pb::SandboxSpec {
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let gate = FakeGate::default();
    fake.state().create_after_allocation = Some(gate.clone());
    let mut original_client = client(socket.clone()).await;
    let original_request = request(&[("a", "1"), ("b", "2")]);
    let original = tokio::spawn(async move {
        original_client
            .create_sandbox(original_request)
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
    });
    gate.entered().await;

    let mut c = client(socket.clone()).await;
    let mut timed = tonic::Request::new(request(&[("b", "2"), ("a", "1")]));
    timed.set_timeout(Duration::from_millis(400));
    let late = c.create_sandbox(timed).await.unwrap_err();
    assert_eq!(late.code(), Code::DeadlineExceeded, "{late:?}");
    assert_eq!(reason(&late).as_deref(), Some("create_in_flight"));
    assert!(late.message().starts_with("create_in_flight: "));

    let conflict = c
        .create_sandbox(request(&[("a", "other")]))
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), Code::AlreadyExists);
    assert_eq!(reason(&conflict).as_deref(), Some("request_id_conflict"));

    let mut waiting_client = client(socket.clone()).await;
    let waiting = tokio::spawn(async move {
        waiting_client
            .create_sandbox(request(&[("a", "1"), ("b", "2")]))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.release();
    let original = original.await.unwrap();
    let waited = waiting.await.unwrap();
    assert_eq!(original.request_id, "run-1/task-2");
    assert_eq!(waited.id, original.id);
    assert_eq!(fake.state().created.len(), 1);

    let invalid = c
        .create_sandbox(pb::CreateSandboxRequest {
            request_id: "has space".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), Code::InvalidArgument);

    let health = c
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    let admission = health.admission.unwrap();
    assert_eq!(
        (
            admission.max_create_requests,
            admission.current_create_requests,
            admission.max_create_requests_per_uid,
            admission.caller_create_requests,
            admission.rejected_create_requests
        ),
        (32_768, 1, 4096, 1, 0)
    );
    let lifecycle = health.lifecycle.unwrap();
    assert_eq!(lifecycle.create_retries_answered, 1);
    let capabilities = health.runtime_capabilities.unwrap();
    assert!(
        capabilities
            .features
            .contains(&(pb::Feature::IdempotentCreate as i32))
    );
    assert!(
        capabilities
            .features
            .contains(&(pb::Feature::RequestIdRelease as i32))
    );
    assert_eq!(
        capabilities.limits.unwrap().create_request_retention_ms,
        86_400_000
    );

    let released = c
        .delete_sandbox(pb::DeleteSandboxRequest {
            id: original.id.clone(),
            release_request_id: true,
        })
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(released.state, pb::SandboxState::Deleted as i32);
    assert!(released.request_id_released);
    assert_eq!(released.request_id, "run-1/task-2");
    let fresh = c
        .create_sandbox(request(&[("a", "1"), ("b", "2")]))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_ne!(fresh.id, original.id);
    assert!(!fresh.request_id_released);
    let health = c.health(pb::HealthRequest {}).await.unwrap().into_inner();
    assert_eq!(health.lifecycle.unwrap().request_ids_released, 1);

    drop(c);
    let _ = stop_tx.send(());
    server.await.unwrap().unwrap();
}
