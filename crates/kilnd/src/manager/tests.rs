use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::runtime::fake::{FakeGate, FakeRuntime};

fn manager() -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    manager_with(Limits::default())
}

fn manager_with(limits: Limits) -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    let fake = FakeRuntime::default();
    let m = Manager::new(fake.clone(), Store::open_in_memory().unwrap(), limits);
    (Arc::new(m), fake)
}

fn exec_req(id: &str, argv: &[&str]) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms: 0,
    }
}

async fn drain(m: &Arc<Manager<FakeRuntime>>) {
    m.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(5), m.drain_operations())
        .await
        .expect("supervised operations did not drain");
}

async fn until(mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        condition(),
        "condition did not become true after bounded scheduler turns"
    );
}

fn spawn_exec(
    m: &Arc<Manager<FakeRuntime>>,
    req: ExecRequest,
) -> tokio::task::JoinHandle<Result<Execution>> {
    let m = m.clone();
    tokio::spawn(async move { m.exec(req).await })
}

#[tokio::test]
async fn zero_queue_rejects_second_exec_before_row_or_backend() {
    let (m, fake) = manager_with(Limits {
        max_queued_execs_per_sandbox: 0,
        ..Limits::default()
    });
    let sandbox = m.create(Default::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let running = spawn_exec(&m, exec_req(&sandbox.id, &["echo", "first"]));
    gate.entered().await;
    assert!(
        matches!(m.exec(exec_req(&sandbox.id, &["echo", "second"])).await, Err(Error::ResourceExhausted(message)) if message.contains("one running plus 0 queued"))
    );
    assert_eq!(fake.state().exec_calls.len(), 1);
    assert_eq!(m.get(&sandbox.id, 100).unwrap().1.len(), 1);
    assert_eq!(m.admission.snapshot().execs.current, 1);
    gate.release();
    running.await.unwrap().unwrap();
    assert_eq!(m.admission.snapshot().execs.current, 0);
}

#[tokio::test]
async fn slot_registry_prunes_deleted_sandbox_churn_without_replacing_live_slots() {
    let (m, _) = manager();
    for _ in 0..100 {
        let sandbox = m.create(Default::default()).await.unwrap();
        let first = m.slot(&sandbox.id);
        let second = m.slot(&sandbox.id);
        assert!(Arc::ptr_eq(&first, &second));
        drop((first, second));
        m.delete(&sandbox.id).await.unwrap();
        assert!(
            m.slots.lock().unwrap().len() <= 1,
            "dead coordination entries accumulated"
        );
    }
}

#[tokio::test]
async fn two_queue_slots_cancel_without_rows_and_recover_stdin() {
    let (m, fake) = manager_with(Limits {
        max_queued_execs_per_sandbox: 2,
        max_queued_exec_stdin_bytes: 6,
        ..Limits::default()
    });
    let sandbox = m.create(Default::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let running = spawn_exec(&m, exec_req(&sandbox.id, &["echo", "first"]));
    gate.entered().await;
    let mut queued = Vec::new();
    for _ in 0..2 {
        let mut req = exec_req(&sandbox.id, &["cat"]);
        req.stdin = vec![1; 3];
        queued.push(spawn_exec(&m, req));
    }
    until(|| m.admission.snapshot().execs.current == 3).await;
    assert_eq!(m.admission.snapshot().stdin.current, 6);
    assert!(matches!(
        m.exec(exec_req(&sandbox.id, &["echo", "fourth"])).await,
        Err(Error::ResourceExhausted(_))
    ));
    for task in queued {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    until(|| m.admission.snapshot().execs.current == 1).await;
    assert_eq!(m.admission.snapshot().stdin.current, 0);
    assert_eq!(m.slot(&sandbox.id).outstanding_execs.available_permits(), 2);
    assert_eq!(fake.state().exec_calls.len(), 1);
    assert_eq!(m.get(&sandbox.id, 100).unwrap().1.len(), 1);
    gate.release();
    running.await.unwrap().unwrap();
    let mut req = exec_req(&sandbox.id, &["cat"]);
    req.stdin = vec![1; 6];
    m.exec(req).await.unwrap();
    assert_eq!(m.admission.snapshot().stdin.current, 0);
}

#[tokio::test(start_paused = true)]
async fn exec_deadline_includes_queue_and_runtime_uses_the_same_instant() {
    let (m, fake) = manager();
    let sandbox = m.create(Default::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let running = spawn_exec(&m, exec_req(&sandbox.id, &["echo", "first"]));
    gate.entered().await;
    let mut req = exec_req(&sandbox.id, &["echo", "expired"]);
    req.timeout_ms = 100;
    let queued = spawn_exec(&m, req);
    until(|| m.admission.snapshot().execs.current == 2).await;
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(matches!(
        queued.await.unwrap(),
        Err(Error::DeadlineExceeded(_))
    ));
    assert_eq!(fake.state().exec_calls.len(), 1);
    assert_eq!(m.get(&sandbox.id, 100).unwrap().1.len(), 1);

    let received = Instant::now();
    let expected_deadline = received + Duration::from_millis(1000);
    let mut req = exec_req(&sandbox.id, &["sleep"]);
    req.timeout_ms = 1000;
    let queued = tokio::spawn({
        let m = m.clone();
        async move { m.exec_received(req, received).await }
    });
    until(|| m.admission.snapshot().execs.current == 2).await;
    tokio::time::advance(Duration::from_millis(800)).await;
    gate.release();
    until(|| fake.state().exec_calls.len() == 2).await;
    assert_eq!(fake.state().exec_deadlines[1], expected_deadline);
    running.await.unwrap().unwrap();
    tokio::time::advance(Duration::from_millis(199)).await;
    assert!(!queued.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    let execution = queued.await.unwrap().unwrap();
    assert_eq!(execution.state, ExecutionState::TimedOut);
    assert_eq!(
        execution.timeout_ms, 1000,
        "persist requested timeout, not remaining time"
    );
    assert_eq!(m.admission.snapshot().execs.current, 0);
}

#[tokio::test]
async fn global_exec_and_stdin_limits_span_sandboxes_and_survive_cancel_and_panic() {
    for stdin_bound in [false, true] {
        let (m, fake) = manager_with(Limits {
            max_concurrent_execs: if stdin_bound { 3 } else { 2 },
            max_queued_exec_stdin_bytes: if stdin_bound { 4 } else { 6 },
            ..Limits::default()
        });
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(m.create(Default::default()).await.unwrap().id);
        }
        let first_gate = FakeGate::default();
        fake.state().exec_before_run = Some(first_gate.clone());
        let mut req = exec_req(&ids[0], &["sleep"]);
        req.stdin = vec![1; 2];
        let first = spawn_exec(&m, req);
        first_gate.entered().await;
        let second_gate = FakeGate::default();
        fake.state().exec_before_run = Some(second_gate.clone());
        fake.state().panic_exec = true;
        let mut req = exec_req(&ids[1], &["sleep"]);
        req.stdin = vec![1; 2];
        let second = spawn_exec(&m, req);
        second_gate.entered().await;
        let mut req = exec_req(&ids[2], &["cat"]);
        req.stdin = vec![1];
        let error = m.exec(req).await.unwrap_err();
        assert!(
            matches!(error, Error::ResourceExhausted(ref message) if message.contains(if stdin_bound { "stdin" } else { "global Exec" }))
        );
        assert_eq!(m.admission.snapshot().execs.current, 2);
        assert_eq!(m.admission.snapshot().stdin.current, 4);
        assert_eq!(fake.state().exec_calls.len(), 2);
        assert!(m.get(&ids[2], 100).unwrap().1.is_empty());
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(
            m.admission.snapshot().execs.current,
            2,
            "cleanup still owns canceled request"
        );
        first_gate.release();
        second_gate.release();
        assert_eq!(second.await.unwrap().unwrap().state, ExecutionState::Failed);
        until(|| m.admission.snapshot().execs.current == 0).await;
        assert_eq!(m.admission.snapshot().stdin.current, 0);
        assert_eq!(fake.state().active_execs, 0);
        fake.state().panic_exec = false;
        m.exec(exec_req(&ids[2], &["echo", "recovered"]))
            .await
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn health_is_single_flight_cached_and_caller_independent() {
    let (m, fake) = manager();
    let gate = FakeGate::default();
    fake.state().version_gate = Some(gate.clone());
    let mut callers = Vec::new();
    for _ in 0..20 {
        let m = m.clone();
        callers.push(tokio::spawn(async move { m.health().await.unwrap() }));
    }
    gate.entered().await;
    assert_eq!(fake.state().version_calls, 1);
    assert_eq!(fake.state().active_version_calls, 1);
    for caller in callers.drain(..5) {
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
    }
    assert_eq!(fake.state().active_version_calls, 1);
    gate.release();
    let expected = m.health().await.unwrap();
    for caller in callers {
        assert_eq!(caller.await.unwrap(), expected);
    }
    assert!(expected.serving);
    assert_eq!(fake.state().version_calls, 1);
    fake.state().unavailable = true;
    assert!(m.health().await.unwrap().serving);
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(!m.health().await.unwrap().serving);
    assert_eq!(fake.state().version_calls, 2);
    fake.state().unavailable = false;
    assert!(!m.health().await.unwrap().serving);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(m.health().await.unwrap().serving);
    assert_eq!(fake.state().version_calls, 3);
    m.begin_shutdown();
    tokio::time::advance(Duration::from_secs(5)).await;
    let shutdown = m.health().await.unwrap();
    assert!(shutdown.shutting_down);
    assert!(!shutdown.serving);
    assert_eq!(shutdown.backend_version, "fake 1.0");
    assert_eq!(fake.state().version_calls, 3);
    m.drain_operations().await;
}

#[tokio::test(start_paused = true)]
async fn health_timeout_and_panic_release_shared_probe_and_allow_retry() {
    let (m, fake) = manager();
    let gate = FakeGate::default();
    fake.state().version_gate = Some(gate.clone());
    let waiter = tokio::spawn({
        let m = m.clone();
        async move { m.health().await.unwrap() }
    });
    gate.entered().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let h = waiter.await.unwrap();
    assert!(!h.serving);
    assert!(h.detail.contains("timed out"));
    assert_eq!(fake.state().active_version_calls, 0);
    fake.state().panic_version = true;
    tokio::time::advance(Duration::from_secs(1)).await;
    let h = m.health().await.unwrap();
    assert!(!h.serving);
    assert!(h.detail.contains("task failed"));
    assert_eq!(fake.state().active_version_calls, 0);
    assert_eq!(fake.state().version_calls, 2);
    fake.state().panic_version = false;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(m.health().await.unwrap().serving);
    assert_eq!(fake.state().version_calls, 3);
}

#[tokio::test]
async fn create_fills_defaults_and_becomes_ready() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(s.state, SandboxState::Ready);
    assert_eq!(s.backend, "fake");
    assert!(valid_id("sb", &s.id));
    let b = s.backend_id.clone().unwrap();
    assert_eq!(
        fake.state().sandboxes.get(&b),
        Some(&BackendStatus::Running)
    );
    let spec = &fake.state().created[0];
    assert_eq!(
        (spec.image.as_str(), spec.memory_bytes, spec.cpu_millis),
        ("alpine", 512 << 20, 1000)
    );
    assert_eq!(m.get(&s.id, 0).unwrap().0, s);
}

#[tokio::test]
async fn create_failure_is_recorded_and_returned() {
    let (m, fake) = manager();
    fake.state().fail_create = Some("image \"nope\" is missing".into());
    let err = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(
        matches!(err, Error::Backend(ref msg) if msg.contains("is missing")),
        "{err}"
    );
    let all = m.list(true).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, SandboxState::Failed);
    assert!(
        all[0]
            .failure_reason
            .as_deref()
            .unwrap()
            .contains("is missing")
    );
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1,
        "an ambiguous backend create error released its reservation"
    );
    // Even an empty listing cannot prove that an ambiguous allocation is gone.
    assert!(matches!(
        m.delete(&all[0].id).await,
        Err(Error::FailedPrecondition(_))
    ));
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1
    );
}

#[tokio::test]
async fn ambiguous_create_with_unlisted_live_backend_keeps_reservation() {
    let (m, fake) = manager();
    fake.state().fail_create = Some("ambiguous backend failure".into());
    m.create(CreateRequest::default()).await.unwrap_err();
    let row = m.list(true).unwrap().remove(0);
    let unreported = fake.insert(BackendStatus::Running);
    fake.state().hidden_from_list.push(unreported.clone());
    assert!(fake.list().await.unwrap().is_empty());
    assert!(matches!(
        m.delete(&row.id).await,
        Err(Error::FailedPrecondition(_))
    ));
    assert!(fake.state().sandboxes.contains_key(&unreported));
    assert_eq!(m.get(&row.id, 0).unwrap().0.state, SandboxState::Failed);
    // Also recover an interrupted Delete written by the old list-only path.
    m.store.set_sandbox_state(&row.id, SandboxState::Deleting, None, None).unwrap();
    assert!(matches!(m.delete(&row.id).await, Err(Error::FailedPrecondition(_))));
    assert!(m.reconcile().await.unwrap().still_deleting.contains(&row.id));
    assert_eq!(m.get(&row.id, 0).unwrap().0.state, SandboxState::Deleting);
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1
    );
}

#[tokio::test]
async fn ambiguous_failed_reservation_survives_even_a_clean_backend_listing() {
    let (m, fake) = manager();
    fake.state().fail_create = Some("ambiguous create error".into());
    m.create(CreateRequest::default()).await.unwrap_err();
    fake.state().fail_create = None;
    let row = m.list(true).unwrap().remove(0);
    let unexplained = fake.insert(BackendStatus::Running);
    let mut compensated = row.clone();
    compensated.id = new_id("sb");
    compensated.backend_id = Some(unexplained.clone());
    compensated.failure_reason = Some("prior compensation proved this ID absent".into());
    m.store.insert_sandbox(&compensated).unwrap();

    let error = m.delete(&row.id).await.unwrap_err();
    assert!(
        matches!(error, Error::FailedPrecondition(ref message) if message.contains("fake backend") && message.contains("authoritative resource reconciliation")),
        "{error}"
    );
    assert_eq!(m.get(&row.id, 0).unwrap().0.state, SandboxState::Failed);
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1
    );

    fake.state().sandboxes.remove(&unexplained);
    assert!(matches!(
        m.delete(&row.id).await,
        Err(Error::FailedPrecondition(_))
    ));
    assert_eq!(
        m.delete(&compensated.id).await.unwrap().state,
        SandboxState::Deleted
    );
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1
    );
}

#[tokio::test]
async fn reappeared_compensated_id_is_unmanaged_not_gc_owned_or_release_proof() {
    let (m, fake) = manager();
    fake.state().fail_create = Some("ambiguous create error".into());
    m.create(CreateRequest::default()).await.unwrap_err();
    fake.state().fail_create = None;
    let ambiguous = m.list(true).unwrap().remove(0);

    let reappeared = fake.insert(BackendStatus::Stale);
    let mut compensated = ambiguous.clone();
    compensated.id = new_id("sb");
    compensated.backend_id = Some(reappeared.clone());
    compensated.failure_reason = Some("prior compensation proved this ID absent".into());
    m.store.insert_sandbox(&compensated).unwrap();

    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.unmanaged, vec![reappeared.clone()]);
    assert!(reconciled.gc_removed.is_empty());
    assert!(fake.state().gc_requests.is_empty());
    assert!(fake.state().sandboxes.contains_key(&reappeared));
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1,
        "compensated history was charged as ownership"
    );

    assert_eq!(
        m.delete(&compensated.id).await.unwrap().state,
        SandboxState::Deleted
    );
    {
        let state = fake.state();
        assert!(
            state.sandboxes.contains_key(&reappeared),
            "deleting compensated history removed a reappeared unmanaged backend"
        );
        assert!(state.remove_attempts.is_empty());
        assert!(state.gc_requests.is_empty());
    }

    let error = m.delete(&ambiguous.id).await.unwrap_err();
    assert!(
        matches!(error, Error::FailedPrecondition(ref message) if message.contains("authoritative resource reconciliation")),
        "{error}"
    );
    fake.state().sandboxes.remove(&reappeared);
    assert!(matches!(
        m.delete(&ambiguous.id).await,
        Err(Error::FailedPrecondition(_))
    ));
}

#[tokio::test]
async fn node_budget_reservation_is_atomic_while_create_is_in_flight() {
    let (m, fake) = manager_with(Limits {
        max_node_memory_bytes: 512 << 20,
        max_node_pids: 128,
        max_node_disk_bytes: 1 << 30,
        ..Limits::default()
    });
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let first = tokio::spawn({
        let m = m.clone();
        async move { m.create(CreateRequest::default()).await }
    });
    gate.entered().await;

    let rejected = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(
        matches!(rejected, Error::ResourceExhausted(ref message) if message.contains("memory bytes")),
        "{rejected}"
    );
    assert_eq!(m.list(true).unwrap().len(), 1);
    let health = m.health().await.unwrap();
    assert_eq!(health.node_resources.reserved.memory_bytes, 512 << 20);
    assert_eq!(health.node_resources.rejected_creates, 1);

    gate.release();
    let first = first.await.unwrap().unwrap();
    m.delete(&first.id).await.unwrap();
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved,
        SandboxResources::default()
    );
    assert!(m.create(CreateRequest::default()).await.is_ok());
}

#[tokio::test]
async fn an_unpolled_create_does_nothing() {
    let (m, fake) = manager();
    let create = m.create(CreateRequest::default());
    drop(create);
    tokio::task::yield_now().await;
    assert!(m.list(true).unwrap().is_empty());
    assert!(fake.state().sandboxes.is_empty());
}

#[tokio::test]
async fn dropping_the_waiter_before_backend_allocation_does_not_cancel_create() {
    let (m, fake) = manager();
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let waiter = tokio::spawn({
        let m = m.clone();
        async move { m.create(CreateRequest::default()).await }
    });
    gate.entered().await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    gate.release();
    drain(&m).await;

    let rows = m.list(true).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, SandboxState::Ready);
    assert_eq!(fake.state().sandboxes.len(), 1);
    assert_eq!(
        rows[0].backend_id.as_ref(),
        fake.state().sandboxes.keys().next()
    );
}

#[tokio::test]
async fn dropping_the_waiter_after_backend_allocation_publishes_its_id() {
    let (m, fake) = manager();
    let gate = FakeGate::default();
    fake.state().create_after_allocation = Some(gate.clone());
    let waiter = tokio::spawn({
        let m = m.clone();
        async move { m.create(CreateRequest::default()).await }
    });
    gate.entered().await;
    let backend_id = fake.state().sandboxes.keys().next().unwrap().clone();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    gate.release();
    drain(&m).await;

    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Ready);
    assert_eq!(row.backend_id.as_deref(), Some(backend_id.as_str()));
    assert_eq!(fake.state().sandboxes.len(), 1);
}

#[tokio::test]
async fn dropped_waiter_still_records_backend_failure() {
    let (m, fake) = manager();
    let gate = FakeGate::default();
    {
        let mut state = fake.state();
        state.create_before_allocation = Some(gate.clone());
        state.fail_create = Some("injected create failure".into());
    }
    let waiter = tokio::spawn({
        let m = m.clone();
        async move { m.create(CreateRequest::default()).await }
    });
    gate.entered().await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    gate.release();
    drain(&m).await;

    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Failed);
    assert!(
        row.failure_reason
            .as_deref()
            .unwrap()
            .contains("injected create failure")
    );
    assert!(fake.state().sandboxes.is_empty());
}

#[tokio::test]
async fn dropped_waiter_does_not_interrupt_publication_compensation() {
    let (m, fake) = manager();
    m.store.reject_ready_updates().unwrap();
    let remove_gate = FakeGate::default();
    fake.state().remove_before_delete = Some(remove_gate.clone());
    let waiter = tokio::spawn({
        let m = m.clone();
        async move { m.create(CreateRequest::default()).await }
    });
    remove_gate.entered().await;
    let during = m.list(true).unwrap().remove(0);
    assert_eq!(during.state, SandboxState::Deleting);
    assert!(during.backend_id.is_some());
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    remove_gate.release();
    drain(&m).await;

    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.backend_id.is_some());
    assert!(
        row.failure_reason
            .as_deref()
            .unwrap()
            .contains("backend removed")
    );
    {
        let state = fake.state();
        assert!(state.sandboxes.is_empty());
        assert_eq!(state.remove_attempts.len(), 1);
    }
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved,
        SandboxResources::default(),
        "proven successful compensation retained its reservation"
    );
}

#[tokio::test]
async fn failed_publication_and_compensation_remain_retryable_and_counted() {
    let (m, fake) = manager();
    m.store.reject_ready_updates().unwrap();
    fake.state().fail_remove = true;
    let err = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(err, Error::Internal(_)));

    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Deleting);
    assert!(row.backend_id.is_some());
    assert!(
        row.failure_reason
            .as_deref()
            .unwrap()
            .contains("cleanup failed")
    );
    assert_eq!(m.health().await.unwrap().active_sandboxes, 1);
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1,
        "failed compensation released a live backend reservation"
    );
    assert_eq!(fake.state().sandboxes.len(), 1);

    fake.state().fail_remove = false;
    assert_eq!(
        m.delete(&row.id).await.unwrap().state,
        SandboxState::Deleted
    );
    assert!(fake.state().sandboxes.is_empty());
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved,
        SandboxResources::default()
    );
}

#[tokio::test]
async fn backend_create_panic_is_recorded_as_failed() {
    let (m, fake) = manager();
    fake.state().panic_create = true;
    let err = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(err, Error::Backend(ref message) if message.contains("panicked")));
    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.failure_reason.as_deref().unwrap().contains("panicked"));
    assert!(fake.state().sandboxes.is_empty());
    assert_eq!(
        m.health().await.unwrap().node_resources.reserved.sandboxes,
        1,
        "an ambiguous backend panic released its reservation"
    );
}

#[tokio::test]
async fn create_validates_the_spec() {
    let (m, fake) = manager();
    let bad = [
        CreateRequest {
            image: "../etc".into(),
            ..Default::default()
        },
        CreateRequest {
            image: "-x".into(),
            ..Default::default()
        },
        CreateRequest {
            memory_bytes: 1 << 40,
            ..Default::default()
        },
        CreateRequest {
            cpu_millis: 100_000,
            ..Default::default()
        },
        CreateRequest {
            pids: 1 << 20,
            ..Default::default()
        },
        CreateRequest {
            disk_bytes: 1 << 50,
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec![]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["--net=full".into()]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["a b".into()]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["/".into()]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["example.com:0".into()]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["10.0.0.1/33".into()]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["bad..example".into()]),
            ..Default::default()
        },
        CreateRequest {
            network: Network::Allow(vec!["example.com".into(); 65]),
            ..Default::default()
        },
        CreateRequest {
            writable_paths: vec!["/data".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["data".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["/a/../etc".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["/".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["/a/./b".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["/a//b".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["/data/".into()],
            ..Default::default()
        },
        CreateRequest {
            read_only_root: true,
            writable_paths: vec!["/data".into(); 17],
            ..Default::default()
        },
        CreateRequest {
            labels: [("".to_string(), "x".to_string())].into(),
            ..Default::default()
        },
        CreateRequest {
            labels: [("k".to_string(), "a\nb".to_string())].into(),
            ..Default::default()
        },
        CreateRequest {
            labels: (0..33).map(|n| (format!("key-{n}"), "value".into())).collect(),
            ..Default::default()
        },
        CreateRequest {
            labels: [("k".repeat(64), "value".into())].into(),
            ..Default::default()
        },
        CreateRequest {
            labels: [("key".into(), "v".repeat(257))].into(),
            ..Default::default()
        },
    ];
    for req in bad {
        let shown = format!("{req:?}");
        assert!(
            matches!(m.create(req).await, Err(Error::InvalidArgument(_))),
            "{shown}"
        );
    }
    assert!(fake.state().created.is_empty());
    assert!(
        m.list(true).unwrap().is_empty(),
        "invalid requests leave no record"
    );

    let ok = CreateRequest {
        network: Network::Allow(vec!["example.com:443".into(), "10.0.0.0/8".into()]),
        read_only_root: true,
        writable_paths: vec!["/data".into(), "/workspace/雪".into()],
        labels: [("app.lambda-nine/owner".to_string(), "tests".to_string())].into(),
        ..Default::default()
    };
    assert_eq!(m.create(ok).await.unwrap().state, SandboxState::Ready);
    let boundary = CreateRequest {
        image: "i".repeat(128),
        network: Network::Allow(vec!["example.com:65535".into(); 64]),
        read_only_root: true,
        writable_paths: (0..16).map(|n| format!("/data/{n}")).collect(),
        labels: {
            let mut labels: BTreeMap<String, String> =
                (0..31).map(|n| (format!("key-{n}"), "value".into())).collect();
            labels.insert("k".repeat(63), "v".repeat(256));
            labels
        },
        ..Default::default()
    };
    assert_eq!(m.create(boundary).await.unwrap().state, SandboxState::Ready);
}

#[tokio::test]
async fn caps_retained_sandbox_reservations() {
    let (m, _) = manager_with(Limits {
        max_sandboxes: 2,
        ..Limits::default()
    });
    let a = m.create(CreateRequest::default()).await.unwrap();
    m.create(CreateRequest::default()).await.unwrap();
    assert!(matches!(
        m.create(CreateRequest::default()).await,
        Err(Error::ResourceExhausted(_))
    ));
    m.delete(&a.id).await.unwrap();
    m.create(CreateRequest::default()).await.unwrap();
}

#[tokio::test]
async fn exec_records_the_result() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let e = m
        .exec(exec_req(&s.id, &["echo", "hello", "world"]))
        .await
        .unwrap();
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
    assert_eq!(
        (e.stdout.data.as_slice(), e.stdin_bytes),
        (&b"from stdin"[..], 10)
    );

    let (_, recent) = m.get(&s.id, 2).unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].argv, ["cat"], "newest first");
}

#[tokio::test]
async fn typed_status_and_failed_binary_evidence_survive_publication_retry() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let exit = m.exec(exec_req(&s.id, &["exit", "125"])).await.unwrap();
    assert_eq!(exit.command_status, Some(CommandStatus::Exited(125)));
    assert_eq!(exit.exit_code, Some(125));
    assert!(exit.runtime_error.is_none());
    let signal = m
        .exec(exec_req(&s.id, &["signal", "15", "core"]))
        .await
        .unwrap();
    assert_eq!(
        signal.command_status,
        Some(CommandStatus::Signaled {
            signal: 15,
            core_dumped: true
        })
    );
    assert_eq!(signal.exit_code, Some(143));
    m.store.reject_execution_finishes().unwrap();
    let task = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["runtime-failure"])).await }
    });
    while fake.state().exec_calls.len() < 3 {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let health = m.health().await.unwrap();
            if !health.serving && health.detail.contains("finalization write") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal UPDATE was never rejected/degraded");
    assert!(
        !task.is_finished(),
        "publication escaped while writes were rejected"
    );
    assert_eq!(m.admission.snapshot().execs.current, 1);
    m.store.allow_execution_finishes().unwrap();
    let failed = task.await.unwrap().unwrap();
    assert_eq!(failed.state, ExecutionState::Failed);
    assert_eq!(failed.exit_code, None);
    assert_eq!(failed.command_status, Some(CommandStatus::Exited(125)));
    assert_eq!(
        failed.runtime_error.as_ref().unwrap().kind,
        RuntimeErrorKind::Io
    );
    assert_eq!(
        failed.stdout,
        Captured {
            data: b"\0\xffout".to_vec(),
            total_bytes: 99,
            truncated: true,
            total_bytes_known: false,
        }
    );
    assert_eq!(
        failed.stderr,
        Captured {
            data: b"\0\xfeerr".to_vec(),
            total_bytes: 101,
            truncated: true,
            total_bytes_known: false,
        }
    );
    assert_eq!(m.execution(&failed.id).unwrap(), failed);
    let metadata = &m.get(&s.id, 1).unwrap().1[0];
    assert_eq!(metadata.command_status, failed.command_status);
    assert_eq!(metadata.runtime_error, failed.runtime_error);
}

#[tokio::test]
async fn completed_without_status_fails_without_losing_output() {
    let (m, _) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let out = m
        .exec(exec_req(&s.id, &["invalid-completed"]))
        .await
        .unwrap();
    assert_eq!(out.state, ExecutionState::Failed);
    assert_eq!(out.exit_code, None);
    assert_eq!(out.stdout.data, b"saved");
    let d = out.runtime_error.unwrap();
    assert_eq!(
        (d.kind, d.stage),
        (RuntimeErrorKind::Internal, RuntimeStage::Report)
    );
}

#[tokio::test]
async fn reconciliation_checks_all_live_capabilities_before_state_changes() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state()
        .incompatible_sandboxes
        .push(s.backend_id.clone().unwrap());
    let mut interrupted = m.exec(exec_req(&s.id, &["true"])).await.unwrap();
    interrupted.id = new_id("ex");
    interrupted.state = ExecutionState::Running;
    m.store.insert_execution(&interrupted).unwrap();
    let before = m.store.sandboxes(true).unwrap();
    assert!(m.reconcile().await.is_err());
    assert_eq!(m.store.sandboxes(true).unwrap(), before);
    assert_eq!(
        m.execution(&interrupted.id).unwrap().state,
        ExecutionState::Running
    );
    assert!(fake.state().removed.is_empty());
    fake.state().unavailable = true;
    let gc_runs = fake.state().gc_runs;
    assert!(m.reconcile().await.is_err());
    assert_eq!(
        fake.state().gc_runs,
        gc_runs,
        "global validation must precede gc"
    );
}

#[tokio::test]
async fn an_unpolled_exec_does_nothing() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let exec = m.exec(exec_req(&s.id, &["echo", "never"]));
    drop(exec);
    tokio::task::yield_now().await;
    assert!(m.get(&s.id, 10).unwrap().1.is_empty());
    assert!(fake.state().exec_calls.is_empty());
}

#[tokio::test]
async fn closed_queued_exec_never_reaches_the_backend_or_store() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());

    let mut first_req = exec_req(&s.id, &["sleep"]);
    first_req.timeout_ms = 1;
    let first = tokio::spawn({
        let m = m.clone();
        async move { m.exec(first_req).await }
    });
    gate.entered().await;

    let queued = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["echo", "must-not-run"])).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !queued.is_finished(),
        "second exec should be queued behind the sandbox lock"
    );
    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());

    gate.release();
    assert_eq!(
        first.await.unwrap().unwrap().state,
        ExecutionState::TimedOut
    );
    drain(&m).await;
    assert_eq!(fake.state().exec_calls.len(), 1);
    assert_eq!(m.get(&s.id, 10).unwrap().1.len(), 1);
}

#[tokio::test]
async fn backend_exec_panic_is_finalized_and_releases_the_sandbox_lock() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state().panic_exec = true;

    let failed = m.exec(exec_req(&s.id, &["echo", "panic"])).await.unwrap();
    assert_eq!(failed.state, ExecutionState::Failed);
    assert!(
        failed
            .failure_reason
            .as_deref()
            .unwrap()
            .contains("panicked")
    );
    assert!(failed.finished_at_ms.is_some());
    assert_eq!(fake.state().active_execs, 0);

    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let after_await = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["echo", "panic-after-await"])).await }
    });
    gate.entered().await;
    gate.release();
    let failed = after_await.await.unwrap().unwrap();
    assert_eq!(failed.state, ExecutionState::Failed);
    assert!(
        failed
            .failure_reason
            .as_deref()
            .unwrap()
            .contains("panicked")
    );
    assert_eq!(fake.state().active_execs, 0);

    fake.state().panic_exec = false;
    let next = m.exec(exec_req(&s.id, &["echo", "usable"])).await.unwrap();
    assert_eq!(next.state, ExecutionState::Exited);
    assert_eq!(next.stdout.data, b"usable\n");
}

#[tokio::test]
async fn finalization_failure_stays_owned_until_storage_recovers() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    m.store.reject_execution_finishes().unwrap();
    let waiter = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move {
            let mut req = exec_req(&id, &["echo", "completed"]);
            req.stdin = vec![1; 3];
            m.exec(req).await
        }
    });

    while fake.state().active_execs != 0 || fake.state().exec_calls.is_empty() {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;
    let execution_id = m.get(&s.id, 10).unwrap().1[0].id.clone();
    assert!(
        !waiter.is_finished(),
        "terminal publication failure escaped the supervisor"
    );
    let health = m.health().await.unwrap();
    assert!(!health.serving);
    assert_eq!(health.running_executions, 1);
    assert!(health.detail.contains("finalization write"));
    assert_eq!(
        health.admission.execs.current, 1,
        "ticket released during terminal write retry"
    );
    assert_eq!(health.admission.stdin.current, 3);

    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    m.begin_shutdown();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), m.drain_operations())
            .await
            .is_err(),
        "shutdown reported a successful drain while terminal publication was failing"
    );

    m.store.allow_execution_finishes().unwrap();
    tokio::time::timeout(Duration::from_secs(5), m.drain_operations())
        .await
        .expect("supervisor did not retry finalization after storage recovered");
    let execution = m.execution(&execution_id).unwrap();
    assert_eq!(execution.state, ExecutionState::Exited);
    assert_eq!(execution.stdout.data, b"completed\n");
    assert!(m.health().await.unwrap().detail.is_empty());
    assert_eq!(m.admission.snapshot().execs.current, 0);
    assert_eq!(m.admission.snapshot().stdin.current, 0);
}

#[tokio::test]
async fn exec_output_is_bounded() {
    let (m, _) = manager_with(Limits {
        max_output_bytes: 100,
        ..Limits::default()
    });
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
    assert_eq!(
        m.exec(exec_req(&s.id, &["echo"])).await.unwrap().state,
        ExecutionState::Exited
    );
}

#[tokio::test]
async fn exec_validates_requests() {
    let (m, _) = manager_with(Limits {
        max_stdin_bytes: 4,
        max_argv_bytes: 16,
        ..Limits::default()
    });
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
    assert!(matches!(
        m.exec(exec_req("sb-0000000000000000", &["echo"])).await,
        Err(Error::NotFound(_))
    ));
    assert!(
        m.get(&s.id, 10).unwrap().1.is_empty(),
        "nothing was recorded"
    );
    let mut req = exec_req(&s.id, &["echo"]);
    req.argv.extend(std::iter::repeat_n(String::new(), 4096));
    assert!(
        matches!(m.exec(req).await, Err(Error::InvalidArgument(message)) if message.contains("4096 arguments"))
    );
}

#[tokio::test]
async fn exec_accepts_exact_boundaries_and_preserves_literal_argv() {
    let (m, fake) = manager_with(Limits {
        max_argv_bytes: 8192,
        ..Limits::default()
    });
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let literal = vec!["echo".into(), "雪\n--timeout=1".into(), String::new()];
    let execution = m
        .exec(ExecRequest {
            sandbox_id: sandbox.id.clone(),
            argv: literal.clone(),
            stdin: Vec::new(),
            timeout_ms: 0,
        })
        .await
        .unwrap();
    assert_eq!(execution.argv, literal);
    assert_eq!(fake.state().exec_calls, [execution.argv]);

    let exact = vec!["echo".into(), "x".repeat(8186)];
    assert_eq!(exact.iter().map(|arg: &String| arg.len() + 1).sum::<usize>(), 8192);
    m.exec(ExecRequest {
        sandbox_id: sandbox.id.clone(),
        argv: exact,
        stdin: Vec::new(),
        timeout_ms: 0,
    })
    .await
    .unwrap();

    let mut max_count = vec!["echo".into()];
    max_count.extend(std::iter::repeat_n(String::new(), 4095));
    m.exec(ExecRequest {
        sandbox_id: sandbox.id,
        argv: max_count,
        stdin: Vec::new(),
        timeout_ms: 0,
    })
    .await
    .unwrap();
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
    assert!(matches!(
        m.exec(exec_req(&s.id, &["echo"])).await,
        Err(Error::FailedPrecondition(_))
    ));
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
    assert!(matches!(
        m.exec(exec_req(&s.id, &["echo"])).await,
        Err(Error::FailedPrecondition(_))
    ));
}

#[tokio::test]
async fn first_recorded_delete_reason_wins_over_shutdown() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let running = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["sleep"])).await }
    });
    gate.entered().await;
    let deleting = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.delete(&id).await }
    });
    while m.get(&s.id, 0).unwrap().0.state != SandboxState::Deleting {
        tokio::task::yield_now().await;
    }
    m.begin_shutdown();
    m.cancel_executions();
    gate.release();

    let execution = running.await.unwrap().unwrap();
    assert_eq!(execution.failure_reason.as_deref(), Some("sandbox deleted"));
    assert_eq!(
        deleting.await.unwrap().unwrap().state,
        SandboxState::Deleted
    );
}

#[tokio::test]
async fn first_recorded_shutdown_reason_wins_over_delete() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let running = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["sleep"])).await }
    });
    gate.entered().await;
    m.begin_shutdown();
    m.cancel_executions();
    let deleting = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.delete(&id).await }
    });
    gate.release();

    let execution = running.await.unwrap().unwrap();
    assert_eq!(execution.failure_reason.as_deref(), Some("kilnd shut down"));
    assert_eq!(
        deleting.await.unwrap().unwrap().state,
        SandboxState::Deleted
    );
}

#[tokio::test]
async fn waiter_drop_preserves_a_backend_completed_outcome() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let waiter = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["echo", "completed"])).await }
    });
    gate.entered().await;
    let execution_id = m.get(&s.id, 1).unwrap().1[0].id.clone();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    tokio::task::yield_now().await;
    gate.release();

    let execution = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let execution = m.execution(&execution_id).unwrap();
            if execution.state != ExecutionState::Running {
                break execution;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(execution.state, ExecutionState::Exited);
    assert_eq!(execution.stdout.data, b"completed\n");
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
    assert!(
        b.started_at_ms >= a.finished_at_ms.unwrap(),
        "the second waited for the first"
    );
}

#[tokio::test]
async fn delete_is_idempotent_and_handles_a_gone_backend() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state().sandboxes.clear();
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
    let again = m.delete(&s.id).await.unwrap();
    assert_eq!(again.state, SandboxState::Deleted);
    assert!(matches!(
        m.delete("sb-0000000000000000").await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        m.delete("x").await,
        Err(Error::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn concurrent_deletes_remove_the_backend_once_and_preserve_deletion_time() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().remove_before_delete = Some(gate.clone());

    let first = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move { m.delete(&id).await }
    });
    gate.entered().await;
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Deleting);

    let mut queued = Vec::new();
    for _ in 0..63 {
        queued.push(tokio::spawn({
            let m = m.clone();
            let id = s.id.clone();
            async move { m.delete(&id).await }
        }));
    }
    until(|| {
        m.slots
            .lock()
            .unwrap()
            .get(&s.id)
            .is_some_and(|slot| slot.strong_count() == 64)
    })
    .await;
    gate.release();

    assert_eq!(first.await.unwrap().unwrap().state, SandboxState::Deleted);
    for delete in queued {
        assert_eq!(delete.await.unwrap().unwrap().state, SandboxState::Deleted);
    }

    let deleted = m.get(&s.id, 0).unwrap().0;
    let deleted_at = deleted.deleted_at_ms.unwrap();
    let updated_at = deleted.updated_at_ms;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let again = m.delete(&s.id).await.unwrap();
    assert_eq!(again.deleted_at_ms, Some(deleted_at));
    assert_eq!(again.updated_at_ms, updated_at);

    let state = fake.state();
    assert_eq!(state.remove_attempts.len(), 1);
    assert_eq!(state.removed.len(), 1);
}

#[tokio::test]
async fn delete_recovers_when_interrupted_on_either_side_of_backend_removal() {
    let (m, fake) = manager();

    let before = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().remove_before_delete = Some(gate.clone());
    let interrupted = tokio::spawn({
        let m = m.clone();
        let id = before.id.clone();
        async move { m.delete(&id).await }
    });
    gate.entered().await;
    interrupted.abort();
    assert!(interrupted.await.unwrap_err().is_cancelled());
    assert_eq!(
        m.get(&before.id, 0).unwrap().0.state,
        SandboxState::Deleting
    );
    assert_eq!(
        m.delete(&before.id).await.unwrap().state,
        SandboxState::Deleted
    );

    let after = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().remove_after_delete = Some(gate.clone());
    let interrupted = tokio::spawn({
        let m = m.clone();
        let id = after.id.clone();
        async move { m.delete(&id).await }
    });
    gate.entered().await;
    interrupted.abort();
    assert!(interrupted.await.unwrap_err().is_cancelled());
    assert_eq!(m.get(&after.id, 0).unwrap().0.state, SandboxState::Deleting);
    assert_eq!(
        m.delete(&after.id).await.unwrap().state,
        SandboxState::Deleted
    );

    let attempts = fake.state().remove_attempts.clone();
    assert_eq!(attempts.iter().filter(|id| *id == "f00d-1").count(), 2);
    assert_eq!(attempts.iter().filter(|id| *id == "f00d-2").count(), 2);
    assert_eq!(fake.state().removed, ["f00d-1", "f00d-2"]);
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
    assert!(matches!(
        m.exec(exec_req(&s.id, &["echo"])).await,
        Err(Error::FailedPrecondition(_))
    ));
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
    assert!(matches!(
        m.create(CreateRequest::default()).await,
        Err(Error::ShuttingDown)
    ));
    assert!(matches!(
        m.exec(exec_req(&s.id, &["echo"])).await,
        Err(Error::ShuttingDown)
    ));
    m.cancel_executions();
    let e = running.await.unwrap().unwrap();
    assert_eq!(
        (e.state, e.failure_reason.as_deref()),
        (ExecutionState::Canceled, Some("kilnd shut down"))
    );
    // The sandbox itself survives a daemon shutdown.
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Ready);
}

#[tokio::test(start_paused = true)]
async fn health_reports_backend_trouble() {
    let (m, fake) = manager();
    let h = m.health().await.unwrap();
    assert!(h.serving);
    assert_eq!(
        (h.backend, h.backend_version.as_str()),
        ("fake", "fake 1.0")
    );
    fake.state().unavailable = true;
    assert!(
        m.health().await.unwrap().serving,
        "success remains cached for its TTL"
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    let h = m.health().await.unwrap();
    assert!(!h.serving);
    assert!(h.detail.contains("unavailable"));
}

/// Builds the state a crash or reboot leaves behind, then reconciles twice.
#[tokio::test]
async fn reconcile_repairs_state_and_is_repeatable() {
    let fake = FakeRuntime::default();
    let store = Store::open_in_memory().unwrap();
    let m = Arc::new(Manager::new(fake.clone(), store, Limits::default()));

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
    let other_backend = Sandbox {
        id: new_id("sb"),
        backend: "firecracker".into(),
        ..crashed_create.clone()
    };
    m.store.insert_sandbox(&other_backend).unwrap();
    m.store
        .set_sandbox_state(&half_deleted.id, SandboxState::Deleting, None, None)
        .unwrap();
    m.store
        .set_sandbox_state(&half_deleted_gone.id, SandboxState::Deleting, None, None)
        .unwrap();
    let interrupted = Execution {
        id: new_id("ex"),
        state: ExecutionState::Running,
        ..running_exec.clone()
    };
    let foreign_running = Execution {
        id: new_id("ex"),
        sandbox_id: other_backend.id.clone(),
        state: ExecutionState::Running,
        ..running_exec
    };
    m.store.insert_execution(&interrupted).unwrap();
    m.store.insert_execution(&foreign_running).unwrap();
    {
        let mut s = fake.state();
        s.sandboxes.remove(rebooted.backend_id.as_ref().unwrap());
        s.sandboxes
            .insert(stale.backend_id.clone().unwrap(), BackendStatus::Stale);
        s.sandboxes
            .remove(half_deleted_gone.backend_id.as_ref().unwrap());
    }
    let unmanaged = fake.insert(BackendStatus::Running);
    let unmanaged_stale = fake.insert(BackendStatus::Stale);

    let first = m.reconcile().await.unwrap();
    let gc_removed = vec![stale.backend_id.clone().unwrap()];
    let mut lost = vec![rebooted.id.clone(), stale.id.clone()];
    lost.sort();
    let mut deleted_now = vec![half_deleted.id.clone(), half_deleted_gone.id.clone()];
    deleted_now.sort();
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    assert_eq!(first.gc_removed, gc_removed);
    assert_eq!(sorted(first.lost.clone()), lost);
    assert_eq!(first.failed, vec![crashed_create.id.clone()]);
    assert_eq!(sorted(first.deleted.clone()), deleted_now);
    assert_eq!(first.interrupted_executions, 1);
    assert_eq!(
        first.unmanaged,
        sorted(vec![unmanaged.clone(), unmanaged_stale.clone()])
    );

    let state = |id: &str| m.get(id, 0).unwrap().0.state;
    assert_eq!(state(&alive.id), SandboxState::Ready);
    assert_eq!(state(&rebooted.id), SandboxState::Lost);
    assert_eq!(state(&stale.id), SandboxState::Lost);
    assert_eq!(state(&half_deleted.id), SandboxState::Deleted);
    assert_eq!(state(&deleted.id), SandboxState::Deleted);
    assert_eq!(state(&crashed_create.id), SandboxState::Failed);
    assert_eq!(
        state(&other_backend.id),
        SandboxState::Creating,
        "other backends' sandboxes are not touched"
    );
    assert_eq!(
        m.execution(&interrupted.id).unwrap().state,
        ExecutionState::Interrupted
    );
    assert_eq!(
        m.execution(&foreign_running.id).unwrap().state,
        ExecutionState::Running,
        "another backend's execution is outside this manager's restart scope"
    );
    assert!(
        fake.state().sandboxes.contains_key(&unmanaged),
        "unmanaged sandboxes are left alone"
    );
    assert!(
        fake.state().sandboxes.contains_key(&unmanaged_stale),
        "unmanaged stale sandboxes are outside kilnd's garbage-collection scope"
    );
    assert!(
        !fake
            .state()
            .sandboxes
            .contains_key(half_deleted.backend_id.as_ref().unwrap())
    );
    assert_eq!(
        fake.state().gc_requests,
        [vec![stale.backend_id.clone().unwrap()]],
        "garbage collection receives only stale IDs owned by this backend"
    );

    let second = m.reconcile().await.unwrap();
    assert_eq!(
        second,
        Reconciled {
            unmanaged: sorted(vec![unmanaged.clone(), unmanaged_stale.clone()]),
            ..Default::default()
        }
    );
    assert_eq!(
        m.exec(exec_req(&alive.id, &["echo", "still"]))
            .await
            .unwrap()
            .stdout
            .data,
        b"still\n"
    );
    m.begin_shutdown();
    m.drain_operations().await;
    let backend = fake.state();
    assert!(backend.sandboxes.contains_key(&unmanaged));
    assert!(backend.sandboxes.contains_key(&unmanaged_stale));
    assert_eq!(
        backend.gc_requests.len(),
        1,
        "shutdown must not run backend GC"
    );
}

#[tokio::test]
async fn lowered_node_budgets_degrade_but_keep_cleanup_available() {
    let fake = FakeRuntime::default();
    let backend_id = fake.insert(BackendStatus::Running);
    let store = Store::open_in_memory().unwrap();
    let now = now_ms();
    let sandbox = Sandbox {
        id: new_id("sb"),
        state: SandboxState::Ready,
        spec: SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 1 << 30,
            cpu_millis: 1000,
            pids: 256,
            disk_bytes: 2 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: Vec::new(),
            labels: BTreeMap::new(),
        },
        backend: "fake".into(),
        backend_id: Some(backend_id),
        created_at_ms: now,
        updated_at_ms: now,
        deleted_at_ms: None,
        failure_reason: None,
    };
    store.insert_sandbox(&sandbox).unwrap();
    let manager = Arc::new(Manager::new(
        fake.clone(),
        store,
        Limits {
            max_node_memory_bytes: 512 << 20,
            max_node_pids: 128,
            max_node_disk_bytes: 1 << 30,
            ..Limits::default()
        },
    ));

    manager.reconcile().await.unwrap();
    let health = manager.health().await.unwrap();
    assert!(!health.serving);
    assert!(health.detail.contains("exceed configured budgets"));
    assert_eq!(manager.get(&sandbox.id, 0).unwrap().0.state, SandboxState::Ready);
    assert_eq!(manager.list(false).unwrap().len(), 1);
    assert!(matches!(
        manager.create(CreateRequest::default()).await,
        Err(Error::ResourceExhausted(_))
    ));

    assert_eq!(
        manager.delete(&sandbox.id).await.unwrap().state,
        SandboxState::Deleted
    );
    let health = manager.health().await.unwrap();
    assert!(health.serving, "{}", health.detail);
    assert_eq!(health.node_resources.reserved, SandboxResources::default());
}

#[tokio::test]
async fn restart_turns_creating_without_an_id_into_reserved_ambiguous_failed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let fake = FakeRuntime::default();
    let now = now_ms();
    let crashed_create = Sandbox {
        id: new_id("sb"),
        state: SandboxState::Creating,
        spec: SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 512 << 20,
            cpu_millis: 1000,
            pids: 128,
            disk_bytes: 1 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: Vec::new(),
            labels: BTreeMap::new(),
        },
        backend: "fake".into(),
        backend_id: None,
        created_at_ms: now,
        updated_at_ms: now,
        deleted_at_ms: None,
        failure_reason: None,
    };
    {
        let store = Store::open(&state_dir).unwrap();
        store.insert_sandbox(&crashed_create).unwrap();
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);
    }

    let manager = Arc::new(Manager::new(
        fake,
        Store::open(&state_dir).unwrap(),
        Limits::default(),
    ));
    let reconciled = manager.reconcile().await.unwrap();
    assert_eq!(reconciled.failed, vec![crashed_create.id.clone()]);
    let failed = manager.get(&crashed_create.id, 0).unwrap().0;
    assert_eq!(failed.state, SandboxState::Failed);
    assert!(failed.backend_id.is_none());
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        1,
        "restart reconciliation released an ambiguous create"
    );

    assert!(matches!(manager.delete(&crashed_create.id).await, Err(Error::FailedPrecondition(_))));
    assert_eq!(manager.health().await.unwrap().node_resources.reserved.sandboxes, 1);
}

#[tokio::test]
async fn reconcile_changes_nothing_when_the_backend_is_unavailable() {
    let (m, fake) = manager();
    let s = m.create(CreateRequest::default()).await.unwrap();
    fake.state().unavailable = true;
    assert!(matches!(m.reconcile().await, Err(Error::Backend(_))));
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Ready);
}

#[tokio::test]
async fn reconcile_rejects_a_listing_that_hides_a_reachable_managed_sandbox() {
    let (m, fake) = manager();
    let visible = m.create(CreateRequest::default()).await.unwrap();
    let hidden = m.create(CreateRequest::default()).await.unwrap();
    let stale = m.create(CreateRequest::default()).await.unwrap();
    let mut interrupted = m.exec(exec_req(&visible.id, &["true"])).await.unwrap();
    interrupted.id = new_id("ex");
    interrupted.state = ExecutionState::Running;
    m.store.insert_execution(&interrupted).unwrap();
    fake.state()
        .hidden_from_list
        .push(hidden.backend_id.clone().unwrap());
    fake.state()
        .sandboxes
        .insert(stale.backend_id.clone().unwrap(), BackendStatus::Stale);

    let before = m.store.sandboxes(true).unwrap();
    let error = m.reconcile().await.unwrap_err();
    assert!(matches!(error, Error::Backend(_)));
    assert!(
        error
            .to_string()
            .contains("listing did not report reachable")
    );
    assert_eq!(m.store.sandboxes(true).unwrap(), before);
    assert_eq!(
        m.execution(&interrupted.id).unwrap().state,
        ExecutionState::Running,
        "incomplete evidence must not partially reconcile executions"
    );
    assert_eq!(m.get(&hidden.id, 0).unwrap().0.state, SandboxState::Ready);
    assert!(
        fake.state()
            .sandboxes
            .contains_key(stale.backend_id.as_ref().unwrap()),
        "scoped GC must wait until the whole listing is trusted"
    );
    assert!(fake.state().gc_requests.is_empty());
}

#[tokio::test]
async fn a_provably_reappeared_backend_recovers_after_restart_once() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let fake = FakeRuntime::default();
    let sandbox = {
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open(&state_dir).unwrap(),
            Limits::default(),
        ));
        let sandbox = manager.create(CreateRequest::default()).await.unwrap();
        manager
            .store
            .set_sandbox_state(
                &sandbox.id,
                SandboxState::Lost,
                None,
                Some("injected crash-era false absence"),
            )
            .unwrap();
        assert_eq!(
            manager.store.sandbox_resources().unwrap().sandboxes,
            1,
            "LOST released capacity before possible recovery"
        );
        sandbox
    };

    let manager = Arc::new(Manager::new(
        fake,
        Store::open(&state_dir).unwrap(),
        Limits::default(),
    ));
    let first = manager.reconcile().await.unwrap();
    assert_eq!(first.recovered, vec![sandbox.id.clone()]);
    let recovered = manager.get(&sandbox.id, 0).unwrap().0;
    assert_eq!(recovered.state, SandboxState::Ready);
    assert_eq!(recovered.failure_reason, None);
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        1
    );

    let second = manager.reconcile().await.unwrap();
    assert_eq!(second, Reconciled::default());
    assert_eq!(
        manager.get(&sandbox.id, 0).unwrap().0.state,
        SandboxState::Ready
    );
}
