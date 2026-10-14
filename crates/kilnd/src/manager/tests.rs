use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::runtime::fake::FakeRuntime;

fn manager() -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    manager_with(Limits::default())
}

fn manager_with(limits: Limits) -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    let fake = FakeRuntime::default();
    let m = Manager::new(fake.clone(), Store::open_in_memory().unwrap(), limits);
    (Arc::new(m), fake)
}

fn exec_req(id: &str, argv: &[&str]) -> ExecRequest {
    ExecRequest { sandbox_id: id.into(), argv: argv.iter().map(|s| s.to_string()).collect(), stdin: vec![], timeout_ms: 0 }
}

#[tokio::test]
async fn create_fills_defaults_and_becomes_ready() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(s.state, SandboxState::Ready);
    assert_eq!(s.backend, "fake");
    assert!(valid_id("sb", &s.id));
    let b = s.backend_id.clone().unwrap();
    assert_eq!(fake.state().sandboxes.get(&b), Some(&BackendStatus::Running));
    let spec = &fake.state().created[0];
    assert_eq!((spec.image.as_str(), spec.memory_bytes, spec.cpu_millis), ("alpine", 512 << 20, 1000));
    assert_eq!(m.get(&s.id, 0).unwrap().0, s);
}

#[tokio::test]
async fn create_failure_is_recorded_and_returned() {
    let (m, fake) = manager();
    fake.state().fail_create = Some("image \"nope\" is missing".into());
    let err = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(err, Error::Backend(ref msg) if msg.contains("is missing")), "{err}");
    let all = m.list(true).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, SandboxState::Failed);
    assert!(all[0].failure_reason.as_deref().unwrap().contains("is missing"));
    // A failed sandbox can be cleared.
    let gone = m.delete(&all[0].id).await.unwrap();
    assert_eq!(gone.state, SandboxState::Deleted);
}

#[tokio::test]
async fn create_validates_the_spec() {
    let (m, fake) = manager();
    let bad = [
        CreateRequest { image: "../etc".into(), ..Default::default() },
        CreateRequest { image: "-x".into(), ..Default::default() },
        CreateRequest { memory_bytes: 1 << 40, ..Default::default() },
        CreateRequest { cpu_millis: 100_000, ..Default::default() },
        CreateRequest { pids: 1 << 20, ..Default::default() },
        CreateRequest { disk_bytes: 1 << 50, ..Default::default() },
        CreateRequest { network: Network::Allow(vec![]), ..Default::default() },
        CreateRequest { network: Network::Allow(vec!["--net=full".into()]), ..Default::default() },
        CreateRequest { network: Network::Allow(vec!["a b".into()]), ..Default::default() },
        CreateRequest { writable_paths: vec!["/data".into()], ..Default::default() },
        CreateRequest { read_only_root: true, writable_paths: vec!["data".into()], ..Default::default() },
        CreateRequest { read_only_root: true, writable_paths: vec!["/a/../etc".into()], ..Default::default() },
        CreateRequest { labels: [("".to_string(), "x".to_string())].into(), ..Default::default() },
        CreateRequest { labels: [("k".to_string(), "a\nb".to_string())].into(), ..Default::default() },
    ];
    for req in bad {
        let shown = format!("{req:?}");
        assert!(matches!(m.create(req).await, Err(Error::InvalidArgument(_))), "{shown}");
    }
    assert!(fake.state().created.is_empty());
    assert!(m.list(true).unwrap().is_empty(), "invalid requests leave no record");

    let ok = CreateRequest {
        network: Network::Allow(vec!["example.com:443".into(), "10.0.0.0/8".into()]),
        read_only_root: true,
        writable_paths: vec!["/data".into()],
        labels: [("app.lambda-nine/owner".to_string(), "tests".to_string())].into(),
        ..Default::default()
    };
    assert_eq!(m.create(ok).await.unwrap().state, SandboxState::Ready);
}

#[tokio::test]
async fn caps_active_sandboxes() {
    let (m, _) = manager_with(Limits { max_sandboxes: 2, ..Limits::default() });
    let a = m.create(CreateRequest::default()).await.unwrap();
    m.create(CreateRequest::default()).await.unwrap();
    assert!(matches!(m.create(CreateRequest::default()).await, Err(Error::ResourceExhausted(_))));
    m.delete(&a.id).await.unwrap();
    m.create(CreateRequest::default()).await.unwrap();
}

#[tokio::test]
async fn exec_records_the_result() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let e = m.exec(exec_req(&s.id, &["echo", "hello", "world"])).await.unwrap();
    assert_eq!(e.state, ExecutionState::Exited);
    assert_eq!(e.exit_code, Some(0));
    assert_eq!(e.stdout.data, b"hello world\n");
    assert!(e.finished_at_ms.is_some());
    assert_eq!(e.timeout_ms, 60_000);
    assert_eq!(m.execution(&e.id).unwrap(), e);

    let e = m.exec(exec_req(&s.id, &["exit", "37"])).await.unwrap();
    assert_eq!((e.state, e.exit_code), (ExecutionState::Exited, Some(37)));

    let mut req = exec_req(&s.id, &["cat"]);
    req.stdin = b"from stdin".to_vec();
    let e = m.exec(req).await.unwrap();
    assert_eq!((e.stdout.data.as_slice(), e.stdin_bytes), (&b"from stdin"[..], 10));

    let (_, recent) = m.get(&s.id, 2).unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].argv, ["cat"], "newest first");
}

#[tokio::test]
async fn exec_output_is_bounded() {
    let (m, _) = manager_with(Limits { max_output_bytes: 100, ..Limits::default() });
    let s = m.create(CreateRequest::default()).await.unwrap();
    let e = m.exec(exec_req(&s.id, &["spew", "5000"])).await.unwrap();
    assert_eq!(e.stdout.data.len(), 100);
    assert_eq!(e.stdout.total_bytes, 5000);
    assert!(m.execution(&e.id).unwrap().stdout.truncated());
}

#[tokio::test]
async fn exec_times_out() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let mut req = exec_req(&s.id, &["sleep"]);
    req.timeout_ms = 50;
    let e = m.exec(req).await.unwrap();
    assert_eq!(e.state, ExecutionState::TimedOut);
    assert_eq!(e.exit_code, None);
    assert_eq!(e.timeout_ms, 50);
    // The sandbox stays usable.
    assert_eq!(m.exec(exec_req(&s.id, &["echo"])).await.unwrap().state, ExecutionState::Exited);
}

#[tokio::test]
async fn exec_validates_requests() {
    let (m, _) = manager_with(Limits { max_stdin_bytes: 4, max_argv_bytes: 16, ..Limits::default() });
    let s = m.create(CreateRequest::default()).await.unwrap();
    let mut too_much_stdin = exec_req(&s.id, &["cat"]);
    too_much_stdin.stdin = b"12345".to_vec();
    let mut too_long = exec_req(&s.id, &["sleep"]);
    too_long.timeout_ms = 3_600_001;
    for req in [
        exec_req(&s.id, &[]),
        exec_req(&s.id, &[""]),
        exec_req(&s.id, &["echo", "a\0b"]),
        exec_req(&s.id, &["echo", "0123456789abcdef"]),
        exec_req("not-an-id", &["echo"]),
        too_much_stdin,
        too_long,
    ] {
        assert!(matches!(m.exec(req).await, Err(Error::InvalidArgument(_))));
    }
    assert!(matches!(m.exec(exec_req("sb-0000000000000000", &["echo"])).await, Err(Error::NotFound(_))));
    assert!(m.get(&s.id, 10).unwrap().1.is_empty(), "nothing was recorded");
}

#[tokio::test]
async fn exec_into_a_vanished_sandbox_marks_it_lost() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let e = m.exec(exec_req(&s.id, &["vanish"])).await.unwrap();
    assert_eq!(e.state, ExecutionState::Failed);
    assert!(e.failure_reason.unwrap().contains("not found"));
    let lost = m.get(&s.id, 0).unwrap().0;
    assert_eq!(lost.state, SandboxState::Lost);
    assert!(matches!(m.exec(exec_req(&s.id, &["echo"])).await, Err(Error::FailedPrecondition(_))));
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
}

#[tokio::test]
async fn delete_cancels_a_running_exec() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let running = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["sleep"])).await }
    });
    // Let the exec start.
    while m.health().await.unwrap().running_executions == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let deleted = m.delete(&s.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    let e = running.await.unwrap().unwrap();
    assert_eq!(e.state, ExecutionState::Canceled);
    assert_eq!(e.failure_reason.as_deref(), Some("sandbox deleted"));
    assert!(fake.state().sandboxes.is_empty());
    assert!(matches!(m.exec(exec_req(&s.id, &["echo"])).await, Err(Error::FailedPrecondition(_))));
}

#[tokio::test]
async fn execs_in_one_sandbox_run_one_at_a_time() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let mut first = exec_req(&s.id, &["sleep"]);
    first.timeout_ms = 100;
    let a = tokio::spawn({
        let m = m.clone();
        async move { m.exec(first).await }
    });
    while m.health().await.unwrap().running_executions == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let b = m.exec(exec_req(&s.id, &["echo"])).await.unwrap();
    let a = a.await.unwrap().unwrap();
    assert_eq!(a.state, ExecutionState::TimedOut);
    assert!(b.started_at_ms >= a.finished_at_ms.unwrap(), "the second waited for the first");
}

#[tokio::test]
async fn delete_is_idempotent_and_handles_a_gone_backend() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state().sandboxes.clear();
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
    let again = m.delete(&s.id).await.unwrap();
    assert_eq!(again.state, SandboxState::Deleted);
    assert!(matches!(m.delete("sb-0000000000000000").await, Err(Error::NotFound(_))));
    assert!(matches!(m.delete("x").await, Err(Error::InvalidArgument(_))));
}

#[tokio::test]
async fn failed_delete_stays_deleting_and_can_be_retried() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state().fail_remove = true;
    assert!(matches!(m.delete(&s.id).await, Err(Error::Backend(_))));
    let stuck = m.get(&s.id, 0).unwrap().0;
    assert_eq!(stuck.state, SandboxState::Deleting);
    assert!(stuck.failure_reason.unwrap().contains("delete failed"));
    assert!(matches!(m.exec(exec_req(&s.id, &["echo"])).await, Err(Error::FailedPrecondition(_))));
    fake.state().fail_remove = false;
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
}

#[tokio::test]
async fn shutdown_refuses_new_work_and_cancels_executions() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let running = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["sleep"])).await }
    });
    while m.health().await.unwrap().running_executions == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    m.begin_shutdown();
    assert!(m.health().await.unwrap().shutting_down);
    assert!(matches!(m.create(CreateRequest::default()).await, Err(Error::ShuttingDown)));
    assert!(matches!(m.exec(exec_req(&s.id, &["echo"])).await, Err(Error::ShuttingDown)));
    m.cancel_executions();
    let e = running.await.unwrap().unwrap();
    assert_eq!((e.state, e.failure_reason.as_deref()), (ExecutionState::Canceled, Some("kilnd shut down")));
    // The sandbox itself survives a daemon shutdown.
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Ready);
}

#[tokio::test]
async fn health_reports_backend_trouble() {
    let (m, fake) = manager();
    let h = m.health().await.unwrap();
    assert!(h.serving);
    assert_eq!((h.backend, h.backend_version.as_str()), ("fake", "fake 1.0"));
    fake.state().unavailable = true;
    let h = m.health().await.unwrap();
    assert!(!h.serving);
    assert!(h.detail.contains("unavailable"));
}

/// Builds the state a crash or reboot leaves behind, then reconciles twice.
#[tokio::test]
async fn reconcile_repairs_state_and_is_repeatable() {
    let fake = FakeRuntime::default();
    let store = Store::open_in_memory().unwrap();
    let m = Manager::new(fake.clone(), store, Limits::default());

    let alive = m.create(CreateRequest::default()).await.unwrap();
    let rebooted = m.create(CreateRequest::default()).await.unwrap();
    let stale = m.create(CreateRequest::default()).await.unwrap();
    let half_deleted = m.create(CreateRequest::default()).await.unwrap();
    let half_deleted_gone = m.create(CreateRequest::default()).await.unwrap();
    let deleted = m.create(CreateRequest::default()).await.unwrap();
    m.delete(&deleted.id).await.unwrap();
    let running_exec = m.exec(exec_req(&alive.id, &["echo"])).await.unwrap();

    let now = now_ms();
    let crashed_create = Sandbox {
        id: new_id("sb"),
        state: SandboxState::Creating,
        spec: alive.spec.clone(),
        backend: "fake".into(),
        backend_id: None,
        created_at_ms: now,
        updated_at_ms: now,
        deleted_at_ms: None,
        failure_reason: None,
    };
    m.store.insert_sandbox(&crashed_create).unwrap();
    let other_backend = Sandbox { id: new_id("sb"), backend: "firecracker".into(), ..crashed_create.clone() };
    m.store.insert_sandbox(&other_backend).unwrap();
    m.store.set_sandbox_state(&half_deleted.id, SandboxState::Deleting, None, None).unwrap();
    m.store.set_sandbox_state(&half_deleted_gone.id, SandboxState::Deleting, None, None).unwrap();
    let interrupted = Execution { id: new_id("ex"), state: ExecutionState::Running, ..running_exec };
    m.store.insert_execution(&interrupted).unwrap();
    {
        let mut s = fake.state();
        s.sandboxes.remove(rebooted.backend_id.as_ref().unwrap());
        s.sandboxes.insert(stale.backend_id.clone().unwrap(), BackendStatus::Stale);
        s.sandboxes.remove(half_deleted_gone.backend_id.as_ref().unwrap());
    }
    let unmanaged = fake.insert(BackendStatus::Running);
    let unmanaged_stale = fake.insert(BackendStatus::Stale);

    let first = m.reconcile().await.unwrap();
    let mut gc_removed = vec![stale.backend_id.clone().unwrap(), unmanaged_stale];
    gc_removed.sort();
    let mut lost = vec![rebooted.id.clone(), stale.id.clone()];
    lost.sort();
    let mut deleted_now = vec![half_deleted.id.clone(), half_deleted_gone.id.clone()];
    deleted_now.sort();
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    assert_eq!(sorted(first.gc_removed.clone()), gc_removed);
    assert_eq!(sorted(first.lost.clone()), lost);
    assert_eq!(first.failed, vec![crashed_create.id.clone()]);
    assert_eq!(sorted(first.deleted.clone()), deleted_now);
    assert_eq!(first.interrupted_executions, 1);
    assert_eq!(first.unmanaged, vec![unmanaged.clone()]);

    let state = |id: &str| m.get(id, 0).unwrap().0.state;
    assert_eq!(state(&alive.id), SandboxState::Ready);
    assert_eq!(state(&rebooted.id), SandboxState::Lost);
    assert_eq!(state(&stale.id), SandboxState::Lost);
    assert_eq!(state(&half_deleted.id), SandboxState::Deleted);
    assert_eq!(state(&deleted.id), SandboxState::Deleted);
    assert_eq!(state(&crashed_create.id), SandboxState::Failed);
    assert_eq!(state(&other_backend.id), SandboxState::Creating, "other backends' sandboxes are not touched");
    assert_eq!(m.execution(&interrupted.id).unwrap().state, ExecutionState::Interrupted);
    assert!(fake.state().sandboxes.contains_key(&unmanaged), "unmanaged sandboxes are left alone");
    assert!(!fake.state().sandboxes.contains_key(half_deleted.backend_id.as_ref().unwrap()));

    let second = m.reconcile().await.unwrap();
    assert_eq!(second, Reconciled { unmanaged: vec![unmanaged], ..Default::default() });
    assert_eq!(m.exec(exec_req(&alive.id, &["echo", "still"])).await.unwrap().stdout.data, b"still\n");
}

#[tokio::test]
async fn reconcile_changes_nothing_when_the_backend_is_unavailable() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state().unavailable = true;
    assert!(matches!(m.reconcile().await, Err(Error::Backend(_))));
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Ready);
}
