//! API additions M1 (design sections 2 and 8): expiry, Renew, the sweeper's races,
//! its clocks and its bounds, driven by a manual clock.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::expiry::{ManualClock, RequestedExpiry};
use crate::runtime::fake::{FakeGate, FakeRuntime};

const SEC: i64 = 1000;

fn test_limits() -> Limits {
    Limits {
        max_node_memory_bytes: 1 << 40,
        max_node_pids: 1 << 20,
        max_node_disk_bytes: 1 << 50,
        expiry: ExpiryLimits {
            restart_grace: Duration::ZERO,
            ..ExpiryLimits::default()
        },
        ..Limits::default()
    }
}

fn clocked(limits: Limits) -> (Arc<Manager<FakeRuntime>>, FakeRuntime, ManualClock) {
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let m = Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        limits,
        Arc::new(clock.clone()),
    );
    (Arc::new(m), fake, clock)
}

fn on_disk(
    dir: &std::path::Path,
    fake: &FakeRuntime,
    clock: &ManualClock,
    limits: &Limits,
) -> Arc<Manager<FakeRuntime>> {
    Arc::new(Manager::with_clock(
        fake.clone(),
        Store::reopen_after_restart(dir),
        limits.clone(),
        Arc::new(clock.clone()),
    ))
}

fn state_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = tmp.path().join("state");
    (tmp, state)
}

fn policy(lifetime_s: u64, idle_s: u64) -> CreateRequest {
    CreateRequest {
        expiry: Some(RequestedExpiry {
            max_lifetime_ms: lifetime_s * 1000,
            idle_timeout_ms: idle_s * 1000,
        }),
        ..CreateRequest::default()
    }
}

fn exec_req(id: &str, argv: &[&str]) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms: 0,
    }
}

fn row(m: &Manager<FakeRuntime>, id: &str) -> Sandbox {
    m.store.sandbox(id).unwrap().unwrap()
}

fn reason_of(error: &Error) -> Option<&'static str> {
    match error {
        Error::FailedPrecondition(refusal) => refusal.reason(),
        _ => None,
    }
}

/// Lets spawned removals, executions and their refreshes run to quiescence.
async fn settle(m: &Arc<Manager<FakeRuntime>>) {
    for _ in 0..2000 {
        let running = m.expiry.lock().unwrap().pending.values().any(|p| p.running);
        if !running {
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            if !m.expiry.lock().unwrap().pending.values().any(|p| p.running) {
                return;
            }
        }
        tokio::task::yield_now().await;
    }
    panic!("expiry removals did not settle");
}

async fn until(mut condition: impl FnMut() -> bool) {
    for _ in 0..5000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(condition(), "condition did not become true");
}

async fn sweep(m: &Arc<Manager<FakeRuntime>>) {
    m.expire_due();
    settle(m).await;
}

#[tokio::test]
async fn absent_expiry_never_expires_even_with_node_defaults_but_present_zeros_take_them() {
    let (m, fake, clock) = clocked(Limits {
        expiry: ExpiryLimits {
            default_lifetime_ms: 0,
            default_idle_ms: 20_000,
            restart_grace: Duration::ZERO,
            ..ExpiryLimits::default()
        },
        ..test_limits()
    });
    let legacy = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(
        legacy.lifecycle.expiry,
        crate::model::ExpiryPolicy::default()
    );
    let defaulted = m.create(policy(0, 0)).await.unwrap();
    assert_eq!(defaulted.lifecycle.expiry.idle_timeout_ms, Some(20_000));
    assert_eq!(defaulted.lifecycle.expiry.max_lifetime_ms, None);
    m.rebuild_expiry().unwrap();
    assert_eq!(
        m.expiry_queue_len().0,
        1,
        "only the row with a policy is queued"
    );
    clock.advance(10 * 86_400 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &legacy.id).state, SandboxState::Ready);
    assert_eq!(row(&m, &defaulted.id).state, SandboxState::Deleted);
    assert_eq!(
        row(&m, &defaulted.id).lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredIdle)
    );
    assert_eq!(fake.state().removed.len(), 1);
    assert_eq!(m.expiry_queue_len().0, 0);
}

#[tokio::test]
async fn invalid_policies_refuse_before_any_allocation() {
    let (m, fake, _) = clocked(test_limits());
    for (lifetime, idle) in [(9, 0), (0, 9), (7 * 86_400 + 1, 0), (0, 86_400 + 1)] {
        let error = m.create(policy(lifetime, idle)).await.unwrap_err();
        assert!(matches!(error, Error::InvalidArgument(_)), "{error}");
    }
    assert!(fake.state().created.is_empty());
    assert!(m.store.sandboxes(true).unwrap().is_empty());
}

#[tokio::test]
async fn idle_expiry_removes_the_backend_and_keeps_a_typed_reason() {
    let (m, fake, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let ready = row(&m, &sandbox.id);
    assert_eq!(ready.lifecycle.ready_boottime_ms, Some(clock.boottime_ms()));
    clock.advance(10 * SEC - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    clock.advance(1);
    sweep(&m).await;
    let expired = row(&m, &sandbox.id);
    assert_eq!(expired.state, SandboxState::Deleted);
    assert_eq!(
        expired.lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredIdle)
    );
    assert!(fake.state().sandboxes.is_empty(), "backend is gone");
    assert_eq!(m.lifecycle_snapshot().expired_idle, 1);
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 0);
    assert!(!expired.is_charged());
    for error in [
        m.exec(exec_req(&sandbox.id, &["echo", "late"]))
            .await
            .unwrap_err(),
        m.renew(&sandbox.id).unwrap_err(),
    ] {
        assert_eq!(reason_of(&error), Some("expired_idle"), "{error}");
        assert!(error.to_string().starts_with("expired_idle: "), "{error}");
    }
    assert!(
        m.store
            .recent_executions(&sandbox.id, 10)
            .unwrap()
            .is_empty()
    );
    // Delete of an expired row succeeds and shows the expiry.
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_eq!(
        deleted.lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredIdle)
    );
}

#[tokio::test]
async fn observers_never_count_as_activity() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let seq = row(&m, &sandbox.id).lifecycle.activity_seq;
    clock.advance(5 * SEC);
    m.get(&sandbox.id, 10).unwrap();
    m.list(true).unwrap();
    m.health().await.unwrap();
    m.expiry_view(&row(&m, &sandbox.id));
    assert_eq!(row(&m, &sandbox.id).lifecycle.activity_seq, seq);
    clock.advance(5 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
}

#[tokio::test]
async fn exec_start_and_finish_and_renew_move_only_the_idle_deadline() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(60, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    clock.advance(8 * SEC);
    m.exec(exec_req(&sandbox.id, &["echo", "hi"]))
        .await
        .unwrap();
    until(|| !m.existing_slot(&sandbox.id).is_some_and(|s| s.busy())).await;
    let after_exec = row(&m, &sandbox.id);
    assert_eq!(after_exec.lifecycle.activity_seq, 2, "start and finish");
    clock.advance(9 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    let renewed = m.renew(&sandbox.id).unwrap();
    assert_eq!(renewed.lifecycle.activity_seq, 3);
    // Coalesced: within a second of the last durable activity, nothing is written.
    clock.advance(SEC - 1);
    assert_eq!(m.renew(&sandbox.id).unwrap().lifecycle.activity_seq, 3);
    clock.advance(10 * SEC - (SEC - 1) - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    clock.advance(1);
    sweep(&m).await;
    assert_eq!(
        row(&m, &sandbox.id).lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredIdle)
    );
    // Lifetime was never extended by any of it.
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(20, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    for _ in 0..19 {
        clock.advance(SEC);
        m.renew(&sandbox.id).unwrap();
        m.exec(exec_req(&sandbox.id, &["echo"])).await.unwrap();
    }
    clock.advance(SEC);
    sweep(&m).await;
    assert_eq!(
        row(&m, &sandbox.id).lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );
}

#[tokio::test]
async fn running_and_queued_executions_pause_idle() {
    let (m, fake, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let running = {
        let m = m.clone();
        let id = sandbox.id.clone();
        tokio::spawn(async move { m.exec(exec_req(&id, &["echo", "long"])).await })
    };
    gate.entered().await;
    clock.advance(3600 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    let view = m.expiry_view(&row(&m, &sandbox.id));
    assert!(view.idle_paused);
    assert_eq!(view.idle_expires_at_ms, None);
    let key = crate::expiry::key(&sandbox.id).unwrap();
    assert_eq!(
        m.expiry.lock().unwrap().queue.get(key),
        None,
        "paused idle has no entry"
    );
    gate.release();
    running.await.unwrap().unwrap();
    until(|| m.expiry.lock().unwrap().queue.get(key).is_some()).await;
    let finished = row(&m, &sandbox.id).lifecycle.activity_boottime_ms.unwrap();
    assert_eq!(
        m.expiry.lock().unwrap().queue.get(key),
        Some((finished + 10 * SEC, Due::Idle)),
        "the finish restarts idle"
    );

    // An admitted request that is only queued (its permit held, the lock free).
    clock.advance(10 * SEC);
    let slot = m.slot(&sandbox.id);
    let permit = slot.outstanding_execs.clone().try_acquire_owned().unwrap();
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    assert!(m.expiry_view(&row(&m, &sandbox.id)).idle_paused);
    drop(permit);
    m.expiry_refresh(&sandbox.id);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
}

/// Daybreak recheck MEDIUM 1: expiry paused after its all-permits-free check while
/// an Exec arrives. The gate keeps the Exec from being admitted; when expiry's CAS
/// commits, the Exec sees the typed expiry and never held a permit.
#[tokio::test]
async fn idle_expiry_and_exec_admission_are_serialized_by_the_gate() {
    let (m, fake, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    clock.advance(10 * SEC);
    let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx);
    *m.idle_commit_hook.lock().unwrap() = Some(Box::new(move || {
        paused_tx.send(()).unwrap();
        resume_rx.lock().unwrap().recv().unwrap();
    }));
    // The sweeper runs on its own thread (removals it spawns still land on this
    // test's runtime) and pauses after its all-permits-free check, holding the exec
    // lock and the gate.
    let handle = tokio::runtime::Handle::current();
    let expiring = {
        let m = m.clone();
        std::thread::spawn(move || {
            let _runtime = handle.enter();
            m.expire_due();
        })
    };
    paused_rx.recv().unwrap();
    // While this thread's Exec blocks on the gate, a checker looks at its permits,
    // then lets the sweeper's CAS commit.
    let slot = m.slot(&sandbox.id);
    let checker = {
        let slot = slot.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let free = slot.outstanding_execs.available_permits();
            resume_tx.send(()).unwrap();
            free
        })
    };
    let error = m
        .exec(exec_req(&sandbox.id, &["echo", "racing"]))
        .await
        .unwrap_err();
    assert_eq!(
        checker.join().unwrap(),
        slot.capacity,
        "the Exec was admitted past a paused idle expiry"
    );
    expiring.join().unwrap();
    assert_eq!(reason_of(&error), Some("expired_idle"), "{error}");
    assert!(fake.state().exec_calls.is_empty());
    assert!(
        m.store
            .recent_executions(&sandbox.id, 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(slot.outstanding_execs.available_permits(), slot.capacity);
    assert_eq!(m.admission.snapshot().execs.current, 0);
    *m.idle_commit_hook.lock().unwrap() = None;
    settle(&m).await;
    until(|| row(&m, &sandbox.id).state == SandboxState::Deleted).await;

    // The other order: the Exec's permit is taken first, so expiry re-arms.
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    clock.advance(10 * SEC);
    // An admitted request holds its slot as well as its permit.
    let slot = m.slot(&sandbox.id);
    let admitted = {
        let _gate = slot.admission.lock().unwrap();
        slot.outstanding_execs.clone().try_acquire_owned().unwrap()
    };
    m.expire_due();
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    drop(admitted);
}

/// A Renew that commits between the sweeper's read and its CAS changes
/// `activity_seq`, so the CAS matches nothing and the sandbox lives.
#[tokio::test]
async fn renew_and_idle_expiry_race_in_both_orders() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    clock.advance(10 * SEC);
    let store_renews = {
        let m = Arc::downgrade(&m);
        let id = sandbox.id.clone();
        move || {
            let m = m.upgrade().unwrap();
            m.store.renew(&id).unwrap();
        }
    };
    *m.idle_commit_hook.lock().unwrap() = Some(Box::new(store_renews));
    sweep(&m).await;
    *m.idle_commit_hook.lock().unwrap() = None;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    let key = crate::expiry::key(&sandbox.id).unwrap();
    assert!(
        m.expiry.lock().unwrap().queue.get(key).is_some(),
        "re-armed"
    );
    // Expiry first: the Renew that comes after loses with the typed reason.
    clock.advance(10 * SEC);
    sweep(&m).await;
    let error = m.renew(&sandbox.id).unwrap_err();
    assert_eq!(reason_of(&error), Some("expired_idle"));
}

#[tokio::test]
async fn lifetime_cancels_the_running_exec_without_its_lock_and_refuses_the_queue() {
    let (m, fake, clock) = clocked(test_limits());
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let running = {
        let m = m.clone();
        let mut req = exec_req(&sandbox.id, &["sleep"]);
        req.timeout_ms = 600_000;
        tokio::spawn(async move { m.exec(req).await })
    };
    until(|| fake.state().active_execs == 1).await;
    let queued = {
        let m = m.clone();
        let id = sandbox.id.clone();
        tokio::spawn(async move { m.exec(exec_req(&id, &["echo", "queued"])).await })
    };
    until(|| m.admission.snapshot().execs.current == 2).await;
    clock.advance(10 * SEC);
    // The intent publishes at once: the sweeper never waits for the exec lock.
    m.expire_due();
    let intent = row(&m, &sandbox.id);
    assert_eq!(intent.state, SandboxState::Deleting);
    assert_eq!(
        intent.lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );
    let canceled = running.await.unwrap().unwrap();
    assert_eq!(canceled.state, ExecutionState::Canceled);
    assert_eq!(
        canceled.cancel_reason,
        Some(CancelReason::SandboxExpiredLifetime)
    );
    let error = queued.await.unwrap().unwrap_err();
    assert_eq!(reason_of(&error), Some("expired_lifetime"), "{error}");
    settle(&m).await;
    until(|| row(&m, &sandbox.id).state == SandboxState::Deleted).await;
    assert_eq!(m.lifecycle_snapshot().expired_lifetime, 1);
    assert_eq!(fake.state().exec_calls.len(), 1);
    let stored = m.store.execution(&canceled.id).unwrap().unwrap();
    assert_eq!(
        stored.cancel_reason,
        Some(CancelReason::SandboxExpiredLifetime)
    );
}

#[tokio::test]
async fn a_completed_outcome_wins_over_a_later_lifetime_expiry() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let done = m
        .exec(exec_req(&sandbox.id, &["echo", "done"]))
        .await
        .unwrap();
    clock.advance(10 * SEC);
    sweep(&m).await;
    let stored = m.store.execution(&done.id).unwrap().unwrap();
    assert_eq!(stored.state, ExecutionState::Exited);
    assert_eq!(stored.cancel_reason, None);
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
}

#[tokio::test]
async fn delete_and_expiry_keep_the_first_reason() {
    // Delete first: the reason is REQUESTED and expiry finds nothing to do.
    let (m, fake, clock) = clocked(test_limits());
    let sandbox = m.create(policy(10, 10)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_eq!(
        deleted.lifecycle.deletion_reason,
        Some(DeletionReason::Requested)
    );
    clock.advance(20 * SEC);
    sweep(&m).await;
    assert_eq!(
        row(&m, &sandbox.id).lifecycle.deletion_reason,
        Some(DeletionReason::Requested)
    );
    assert_eq!(
        m.lifecycle_snapshot().expired_idle + m.lifecycle_snapshot().expired_lifetime,
        0
    );

    // Expiry first, its removal held: a concurrent Delete is a follower and shows it.
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    let hold = Arc::new(tokio::sync::Notify::new());
    fake.state().remove_hold = Some(hold.clone());
    clock.advance(10 * SEC);
    m.expire_due();
    until(|| fake.state().active_removes == 1).await;
    let follower = {
        let m = m.clone();
        let id = sandbox.id.clone();
        tokio::spawn(async move { m.delete(&id).await })
    };
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    fake.state().remove_hold = None;
    hold.notify_waiters();
    let shown = follower.await.unwrap().unwrap();
    assert_eq!(shown.state, SandboxState::Deleted);
    assert_eq!(
        shown.lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );
    settle(&m).await;
}

#[tokio::test]
async fn no_clock_runs_before_ready() {
    let (m, fake, clock) = clocked(test_limits());
    m.rebuild_expiry().unwrap();
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let creating = {
        let m = m.clone();
        tokio::spawn(async move { m.create(policy(10, 10)).await })
    };
    gate.entered().await;
    clock.advance(3600 * SEC);
    sweep(&m).await;
    let mid = m.store.sandboxes(true).unwrap().pop().unwrap();
    assert_eq!(mid.state, SandboxState::Creating);
    assert_eq!(mid.lifecycle.ready_boottime_ms, None);
    gate.release();
    let sandbox = creating.await.unwrap().unwrap();
    let ready_at = row(&m, &sandbox.id).lifecycle.ready_boottime_ms.unwrap();
    assert_eq!(ready_at, clock.boottime_ms(), "lifetime counts from READY");
    clock.advance(10 * SEC - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    clock.advance(1);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
}

#[tokio::test]
async fn restart_grace_holds_idle_but_not_lifetime() {
    let (m, _, clock) = clocked(Limits {
        expiry: ExpiryLimits {
            restart_grace: Duration::from_secs(60),
            ..ExpiryLimits::default()
        },
        ..test_limits()
    });
    let idle = m.create(policy(0, 10)).await.unwrap();
    let lifetime = m.create(policy(30, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    clock.advance(35 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &lifetime.id).state, SandboxState::Deleted);
    assert_eq!(row(&m, &idle.id).state, SandboxState::Ready);
    let view = m.expiry_view(&row(&m, &idle.id));
    assert_eq!(
        view.idle_expires_at_ms,
        Some(clock.wall_ms() + 25 * SEC),
        "the display shows the grace"
    );
    clock.advance(25 * SEC - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &idle.id).state, SandboxState::Ready);
    clock.advance(1);
    sweep(&m).await;
    assert_eq!(row(&m, &idle.id).state, SandboxState::Deleted);
}

#[tokio::test]
async fn wall_clock_steps_change_no_deadline_only_its_projection() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(100, 50)).await.unwrap();
    m.rebuild_expiry().unwrap();
    let before = m.expiry_view(&row(&m, &sandbox.id));
    for step in [8 * 86_400 * SEC, -16 * 86_400 * SEC] {
        clock.step_wall(step);
        sweep(&m).await;
        assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    }
    clock.step_wall(8 * 86_400 * SEC);
    assert_eq!(m.expiry_view(&row(&m, &sandbox.id)), before);
    assert_eq!(
        m.rebase_expiry_clocks().unwrap(),
        0,
        "a wall step is not a reboot"
    );
    clock.advance(50 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
}

/// A suspend stalls tokio's timers (CLOCK_MONOTONIC) while boottime runs on: the
/// sweeper's rescan notices within one interval.
#[tokio::test(start_paused = true)]
async fn the_rescan_catches_a_resume_from_suspend() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(0, 3600)).await.unwrap();
    let sweeper = m.start_expiry().unwrap();
    tokio::task::yield_now().await;
    clock.advance(7200 * SEC);
    tokio::time::advance(Duration::from_secs(29)).await;
    settle(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    tokio::time::advance(Duration::from_secs(1)).await;
    until(|| row(&m, &sandbox.id).state == SandboxState::Deleted).await;
    m.begin_shutdown();
    sweeper.await.unwrap();
}

#[tokio::test]
async fn deadlines_survive_a_daemon_restart_exactly() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let sandbox = m.create(policy(100, 30)).await.unwrap();
    let anchors = row(&m, &sandbox.id).lifecycle;
    clock.advance(20 * SEC);
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 0);
    assert_eq!(row(&m, &sandbox.id).lifecycle, anchors);
    m.rebuild_expiry().unwrap();
    clock.advance(10 * SEC - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    clock.advance(1);
    sweep(&m).await;
    assert_eq!(
        row(&m, &sandbox.id).lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredIdle)
    );
}

/// A reboot: every anchor is another boot's. One rebase moves both anchors into this
/// boot by the wall time already spent, capped by each limit; later wall steps change
/// nothing, and a second rebase finds nothing.
#[tokio::test]
async fn a_reboot_rebases_both_anchors_once() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let long = m.create(policy(200, 100)).await.unwrap();
    let short = m.create(policy(0, 20)).await.unwrap();
    clock.advance(20 * SEC);
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    // Nothing survives a reboot in the fake backend either.
    fake.state().sandboxes.clear();
    clock.reboot("boot-b", 5_000, 30 * SEC);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.lost.len(), 2);
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 2);
    let rebased = row(&m, &long.id).lifecycle;
    assert_eq!(rebased.clock_boot_id.as_deref(), Some("boot-b"));
    assert_eq!(rebased.ready_boottime_ms, Some(5_000 - 50 * SEC));
    assert_eq!(rebased.activity_boottime_ms, Some(5_000 - 50 * SEC));
    // The elapsed part never exceeds the limit.
    let capped = row(&m, &short.id).lifecycle;
    assert_eq!(capped.activity_boottime_ms, Some(5_000 - 20 * SEC));
    clock.step_wall(8 * 86_400 * SEC);
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 0);
    assert_eq!(row(&m, &long.id).lifecycle, rebased);
    m.rebuild_expiry().unwrap();
    sweep(&m).await;
    // LOST rows keep their deadlines: the short one is due now, the long one at
    // 100 s of idle less the 50 s spent.
    assert_eq!(row(&m, &short.id).state, SandboxState::Deleted);
    assert_eq!(row(&m, &long.id).state, SandboxState::Lost);
    clock.advance(50 * SEC - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &long.id).state, SandboxState::Lost);
    clock.advance(1);
    sweep(&m).await;
    assert_eq!(row(&m, &long.id).state, SandboxState::Deleted);
    assert!(
        !row(&m, &long.id).is_charged(),
        "the vanished client's charge came back"
    );
}

#[tokio::test]
async fn mass_expiry_runs_at_most_the_concurrent_delete_limit() {
    let (m, fake, clock) = clocked(test_limits());
    let mut ids = Vec::new();
    for _ in 0..32 {
        ids.push(m.create(policy(10, 0)).await.unwrap().id);
    }
    m.rebuild_expiry().unwrap();
    let hold = Arc::new(tokio::sync::Notify::new());
    fake.state().remove_hold = Some(hold.clone());
    clock.advance(10 * SEC);
    m.expire_due();
    for id in &ids {
        assert_eq!(
            row(&m, id).state,
            SandboxState::Deleting,
            "every intent publishes at once"
        );
    }
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 32);
    until(|| fake.state().active_removes == 4).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(fake.state().active_removes, 4);
    while ids
        .iter()
        .any(|id| row(&m, id).state != SandboxState::Deleted)
    {
        hold.notify_waiters();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(fake.state().max_active_removes, 4);
    settle(&m).await;
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 0);
    assert_eq!(m.lifecycle_snapshot().expired_lifetime, 32);
}

#[tokio::test]
async fn a_failed_expiry_delete_stays_charged_retries_with_backoff_and_degrades() {
    let (m, fake, clock) = clocked(test_limits());
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    fake.state().fail_remove = true;
    clock.advance(10 * SEC);
    sweep(&m).await;
    let failed = row(&m, &sandbox.id);
    assert_eq!(failed.state, SandboxState::Deleting);
    assert!(failed.is_charged());
    assert_eq!(m.lifecycle_snapshot().failed_expiry_deletes, 1);
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 1);
    let key = crate::expiry::key(&sandbox.id).unwrap();
    let now = clock.boottime_ms();
    assert_eq!(
        m.expiry.lock().unwrap().queue.get(key),
        Some((now + 5 * SEC, Due::Retry))
    );
    clock.advance(5 * SEC);
    sweep(&m).await;
    assert_eq!(m.lifecycle_snapshot().failed_expiry_deletes, 2);
    assert_eq!(
        m.expiry.lock().unwrap().queue.get(key),
        Some((clock.boottime_ms() + 10 * SEC, Due::Retry))
    );
    assert!(m.health().await.unwrap().serving);
    clock.advance(600 * SEC);
    let health = m.health().await.unwrap();
    assert!(!health.serving);
    assert!(
        health.detail.contains("expiry delete(s) pending"),
        "{}",
        health.detail
    );
    fake.state().fail_remove = false;
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 0);
    assert!(m.health().await.unwrap().serving);
}

/// Design section 8's churn bound through the manager: renews and short executions
/// over 32 sandboxes with no idle cap never hold more entries than reservations.
#[tokio::test]
async fn churn_never_grows_the_queue_past_reservations() {
    let (m, _, clock) = clocked(Limits {
        expiry: ExpiryLimits {
            max_idle_ms: 0,
            restart_grace: Duration::ZERO,
            ..ExpiryLimits::default()
        },
        ..test_limits()
    });
    let mut ids = Vec::new();
    for _ in 0..32 {
        let req = CreateRequest {
            expiry: Some(RequestedExpiry {
                max_lifetime_ms: 0,
                idle_timeout_ms: u64::MAX / 8,
            }),
            ..CreateRequest::default()
        };
        ids.push(m.create(req).await.unwrap().id);
    }
    m.rebuild_expiry().unwrap();
    let reserved = m.store.sandbox_resources().unwrap().sandboxes as usize;
    let capacity = m.expiry.lock().unwrap().queue.capacity();
    for event in 0..4000usize {
        let id = &ids[event % ids.len()];
        clock.advance(SEC);
        if event % 2 == 0 {
            m.renew(id).unwrap();
        } else {
            m.exec(exec_req(id, &["echo"])).await.unwrap();
        }
        let (len, bound) = m.expiry_queue_len();
        assert!(
            len <= reserved && len <= bound,
            "{len} entries for {reserved} reservations"
        );
    }
    assert_eq!(m.expiry.lock().unwrap().queue.capacity(), capacity);
}

/// Daybreak recheck LOW 1: restarting with a lower `--max-sandboxes` keeps one entry
/// per durable reservation; the bound is `max(cap, reservations at startup)`.
#[tokio::test]
async fn a_lowered_cap_restart_keeps_one_entry_per_reservation() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let mut ids = Vec::new();
    for _ in 0..8 {
        ids.push(m.create(policy(0, 60)).await.unwrap().id);
    }
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let lowered = Limits {
        max_sandboxes: 4,
        ..limits
    };
    let m = on_disk(&dir, &fake, &clock, &lowered);
    m.reconcile().await.unwrap();
    m.rebase_expiry_clocks().unwrap();
    m.rebuild_expiry().unwrap();
    assert_eq!(m.expiry_queue_len(), (8, 8));
    assert!(matches!(
        m.create(policy(0, 60)).await,
        Err(Error::ResourceExhausted(_))
    ));
    for id in &ids {
        clock.advance(SEC);
        m.renew(id).unwrap();
        assert_eq!(m.expiry_queue_len(), (8, 8));
    }
    for id in &ids[..5] {
        m.delete(id).await.unwrap();
    }
    assert_eq!(m.expiry_queue_len(), (3, 8));
}

#[tokio::test]
async fn startup_completes_an_expiry_intent_that_a_crash_interrupted() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    // The intent commits; the daemon dies before removal.
    assert!(
        m.store
            .publish_expiry_intent(&sandbox.id, DeletionReason::ExpiredLifetime, None)
            .unwrap()
    );
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.deleted, vec![sandbox.id.clone()]);
    let done = row(&m, &sandbox.id);
    assert_eq!(done.state, SandboxState::Deleted);
    assert_eq!(
        done.lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );

    // A removal that also fails at startup is retried by the sweeper.
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    assert!(
        m.store
            .publish_expiry_intent(&sandbox.id, DeletionReason::ExpiredLifetime, None)
            .unwrap()
    );
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    fake.state().fail_remove = true;
    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.still_deleting, vec![sandbox.id.clone()]);
    m.rebuild_expiry().unwrap();
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 1);
    fake.state().fail_remove = false;
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 0);
}

#[tokio::test]
async fn an_ambiguous_legacy_row_is_never_an_expiry_target() {
    let (m, _, clock) = clocked(test_limits());
    let sandbox = m.create(policy(10, 10)).await.unwrap();
    // A LOST row without a backend ID: Delete refuses it, so expiry must not take it.
    m.store
        .set_sandbox_state(&sandbox.id, SandboxState::Lost, None, Some("lost"))
        .unwrap();
    m.store
        .execute_for_test(
            "UPDATE sandboxes SET backend_id = NULL WHERE id = ?1",
            &sandbox.id,
        )
        .unwrap();
    m.rebuild_expiry().unwrap();
    assert_eq!(m.expiry_queue_len().0, 0);
    clock.advance(3600 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Lost);
    assert!(
        !m.store
            .publish_expiry_intent(&sandbox.id, DeletionReason::ExpiredIdle, None)
            .unwrap()
    );
}

#[tokio::test]
async fn dynamic_features_fail_closed_and_return_only_after_a_fresh_probe() {
    let (m, fake, _) = clocked(Limits {
        health_success_cache: Duration::from_millis(1),
        health_failure_cache: Duration::from_millis(1),
        ..test_limits()
    });
    assert_eq!(m.features(), STATIC_FEATURES.to_vec());
    assert!(!m.has_feature(Feature::ExecCwd));
    fake.state().proven_features = Ok(vec![Feature::ExecCwd]);
    let health = m.health().await.unwrap();
    assert_eq!(
        health.features,
        vec![
            Feature::SandboxExpiry,
            Feature::ExecCwd,
            Feature::TypedReasons
        ]
    );
    assert!(m.has_feature(Feature::ExecCwd));
    fake.state().proven_features = Err("older helper".into());
    tokio::time::sleep(Duration::from_millis(5)).await;
    let health = m.health().await.unwrap();
    assert!(!health.serving);
    assert_eq!(health.features, STATIC_FEATURES.to_vec());
    assert!(
        !m.has_feature(Feature::ExecCwd),
        "the gate reads the same set"
    );
    fake.state().proven_features = Ok(vec![Feature::ExecCwd]);
    fake.state().unavailable = true;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(m.health().await.unwrap().features, STATIC_FEATURES.to_vec());
    fake.state().unavailable = false;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(
        m.health()
            .await
            .unwrap()
            .features
            .contains(&Feature::ExecCwd)
    );
}

#[tokio::test]
async fn exec_refuses_a_sandbox_that_left_ready_before_its_row() {
    let (m, fake, _) = clocked(test_limits());
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    let execution = Execution {
        id: new_id("ex"),
        sandbox_id: sandbox.id.clone(),
        argv: vec!["echo".into()],
        state: ExecutionState::Running,
        exit_code: None,
        command_status: None,
        runtime_error: None,
        failure_reason: None,
        started_at_ms: now_ms(),
        finished_at_ms: None,
        timeout_ms: 1000,
        stdin_bytes: 0,
        stdout: Captured::default(),
        stderr: Captured::default(),
        sandbox_reusable: None,
        cleanup_evidence: CleanupEvidence::Unknown,
        cancel_reason: None,
    };
    assert!(
        m.store
            .publish_expiry_intent(&sandbox.id, DeletionReason::ExpiredLifetime, None)
            .unwrap()
    );
    assert!(!m.store.start_execution(&execution).unwrap());
    assert!(m.store.execution(&execution.id).unwrap().is_none());
    assert_eq!(row(&m, &sandbox.id).lifecycle.activity_seq, 0);
    assert!(fake.state().exec_calls.is_empty());
}

// ---- Break-it fixes (API additions M1 review) ----

/// HIGH 1 regression (the review's PoC): an expiry removal task exists only with a
/// permit, and a client Delete of an expiry-owned row joins under the same permit.
/// So tracked expiry operations and active backend removals both stay at the
/// configured limit, and no waiter outlives its row.
#[tokio::test]
async fn client_delete_joins_expiry_removals_under_the_removal_bound() {
    // Joined Deletes hold their reservations until they finish, so make room.
    let (m, fake, clock) = clocked(Limits {
        max_sandboxes: 128,
        ..test_limits()
    });
    m.rebuild_expiry().unwrap();
    let limit = m.limits.expiry.max_concurrent_deletes;
    assert_eq!(limit, 4);

    let hold = Arc::new(tokio::sync::Notify::new());
    fake.state().remove_hold = Some(hold.clone());
    let mut held = Vec::new();
    for _ in 0..limit {
        held.push(m.create(policy(10, 0)).await.unwrap().id);
    }
    clock.advance(10 * SEC);
    m.expire_due();
    until(|| fake.state().active_removes == limit as u32).await;

    // The review's interleaving: later removals are not held, the four are.
    fake.state().remove_hold = None;
    const CHURN: usize = 64;
    let mut clients = Vec::new();
    for _ in 0..CHURN {
        let sandbox = m.create(policy(10, 0)).await.unwrap();
        clock.advance(10 * SEC);
        m.expire_due();
        assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleting);
        let key = crate::expiry::key(&sandbox.id).unwrap();
        {
            let st = m.expiry.lock().unwrap();
            let p = st.pending.get(&key).unwrap();
            assert!(p.waiting && !p.running, "no permit: it waits, with no task");
            assert_eq!(st.queue.get(key), None);
        }
        let (manager, id) = (m.clone(), sandbox.id.clone());
        clients.push(tokio::spawn(async move { manager.delete(&id).await }));
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(m.operations.len(), limit, "only permit holders are tracked");
        assert!(fake.state().max_active_removes <= limit as u32);
        assert!(m.lifecycle_snapshot().pending_expiry_deletes as usize <= limit + CHURN);
    }
    assert!(
        clients.iter().all(|c| !c.is_finished()),
        "a joined Delete waits for an expiry permit"
    );
    assert_eq!(fake.state().max_active_removes, limit as u32);

    // Releasing the four lets every joined Delete and waiting removal finish.
    hold.notify_waiters();
    for client in clients {
        assert_eq!(client.await.unwrap().unwrap().state, SandboxState::Deleted);
    }
    until(|| m.operations.is_empty()).await;
    for id in &held {
        assert_eq!(row(&m, id).state, SandboxState::Deleted);
    }
    assert_eq!(fake.state().max_active_removes, limit as u32);
    assert_eq!(m.lifecycle_snapshot().pending_expiry_deletes, 0);
    assert_eq!(m.expiry_queue_len().0, 0);
    assert_eq!(m.expiry_deletes.available_permits(), limit);
    assert_eq!(m.lifecycle_snapshot().failed_expiry_deletes, 0);
}

/// HIGH 1: a joined Delete that is canceled while it waits, or while it holds the
/// slot's attempt, returns its permit and hands the attempt back to expiry.
#[tokio::test]
async fn a_canceled_joined_delete_hands_the_attempt_back() {
    let (m, fake, clock) = clocked(Limits {
        expiry: ExpiryLimits {
            max_concurrent_deletes: 1,
            ..test_limits().expiry
        },
        ..test_limits()
    });
    m.rebuild_expiry().unwrap();
    let hold = Arc::new(tokio::sync::Notify::new());
    fake.state().remove_hold = Some(hold.clone());
    let first = m.create(policy(10, 0)).await.unwrap();
    let second = m.create(policy(10, 0)).await.unwrap();
    clock.advance(10 * SEC);
    m.expire_due();
    until(|| fake.state().active_removes == 1).await;
    // Whichever started, the other waits for the single permit.
    let waiting = if row(&m, &first.id).state == SandboxState::Deleting
        && m.expiry.lock().unwrap().pending[&crate::expiry::key(&first.id).unwrap()].waiting
    {
        first.id.clone()
    } else {
        second.id.clone()
    };
    let (manager, id) = (m.clone(), waiting.clone());
    let client = tokio::spawn(async move { manager.delete(&id).await });
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    let key = crate::expiry::key(&waiting).unwrap();
    assert!(m.expiry.lock().unwrap().pending[&key].waiting);

    // Now a joined Delete that claims the attempt and is canceled mid-removal.
    fake.state().remove_hold = None;
    hold.notify_waiters();
    until(|| m.expiry.lock().unwrap().pending.is_empty()).await;
    assert_eq!(row(&m, &waiting).state, SandboxState::Deleted);

    let third = m.create(policy(10, 0)).await.unwrap();
    let hold = Arc::new(tokio::sync::Notify::new());
    fake.state().fail_remove = true;
    clock.advance(10 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &third.id).state, SandboxState::Deleting);
    fake.state().fail_remove = false;
    fake.state().remove_hold = Some(hold.clone());
    let (manager, id) = (m.clone(), third.id.clone());
    let client = tokio::spawn(async move { manager.delete(&id).await });
    until(|| fake.state().active_removes == 1).await;
    let key = crate::expiry::key(&third.id).unwrap();
    assert!(m.expiry.lock().unwrap().pending[&key].running, "the Delete claimed it");
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    {
        let st = m.expiry.lock().unwrap();
        let p = &st.pending[&key];
        assert!(!p.running && !p.waiting);
        assert!(st.queue.get(key).is_some(), "expiry owns the retry again");
    }
    assert_eq!(m.expiry_deletes.available_permits(), 1);
    fake.state().remove_hold = None;
    hold.notify_waiters();
    clock.advance(600 * SEC);
    sweep(&m).await;
    assert_eq!(row(&m, &third.id).state, SandboxState::Deleted);
    until(|| m.operations.is_empty()).await;
}

/// MEDIUM 1 regression (the review's PoC): the stale-delete age is the persisted
/// intent's, so a same-boot restart keeps Health degraded.
#[tokio::test]
async fn restart_keeps_the_health_age_of_a_stale_expiry_delete() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    fake.state().fail_remove = true;
    clock.advance(10 * SEC);
    sweep(&m).await;
    clock.advance(300 * SEC);
    assert!(m.health().await.unwrap().serving);
    clock.advance(300 * SEC);
    assert!(!m.health().await.unwrap().serving);

    for _ in 0..2 {
        m.begin_shutdown();
        m.drain_operations().await;
    }
    drop(m);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.still_deleting, vec![sandbox.id.clone()]);
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 0);
    m.rebuild_expiry().unwrap();
    let health = m.health().await.unwrap();
    assert!(!health.serving, "a restart must not reset the age");
    assert!(health.detail.contains("expiry delete(s) pending"), "{}", health.detail);
    fake.state().fail_remove = false;
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
    assert!(m.health().await.unwrap().serving);
}

/// MEDIUM 1: across a reboot the intent's age is rebased with the other anchors:
/// it keeps the wall time already spent and keeps growing.
#[tokio::test]
async fn a_reboot_rebases_the_expiry_delete_age() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let sandbox = m.create(policy(10, 0)).await.unwrap();
    m.rebuild_expiry().unwrap();
    fake.state().fail_remove = true;
    clock.advance(10 * SEC);
    sweep(&m).await;
    clock.advance(400 * SEC);
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    // 100 s of wall time pass while the node is down; the backend keeps failing.
    clock.reboot("boot-b", 5_000, 100 * SEC);
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 1);
    m.rebuild_expiry().unwrap();
    assert!(m.health().await.unwrap().serving, "500 s so far");
    clock.advance(100 * SEC - 1);
    assert!(m.health().await.unwrap().serving);
    clock.advance(1);
    assert!(!m.health().await.unwrap().serving, "600 s since the intent");
    fake.state().fail_remove = false;
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Deleted);
}

/// MEDIUM 2 regression (the review's PoC): startup's terminal publication of an
/// interrupted execution is finish activity, so idle restarts from it.
#[tokio::test]
async fn startup_execution_interruption_restarts_the_idle_timeout() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = Limits {
        expiry: ExpiryLimits {
            restart_grace: Duration::from_secs(60),
            ..ExpiryLimits::default()
        },
        ..test_limits()
    };
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let sandbox = m.create(policy(0, 300)).await.unwrap();
    let execution = running_execution(&sandbox.id);
    assert!(m.store.start_execution(&execution).unwrap());
    let start = row(&m, &sandbox.id).lifecycle;
    clock.advance(900 * SEC);
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);

    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.interrupted_executions, 1);
    let after = row(&m, &sandbox.id).lifecycle;
    assert_eq!(after.activity_seq, start.activity_seq + 1);
    assert_eq!(after.activity_boottime_ms, Some(clock.boottime_ms()));
    m.rebase_expiry_clocks().unwrap();
    m.rebuild_expiry().unwrap();
    clock.advance(300 * SEC - 1);
    sweep(&m).await;
    assert_eq!(row(&m, &sandbox.id).state, SandboxState::Ready);
    clock.advance(1);
    sweep(&m).await;
    assert_eq!(
        row(&m, &sandbox.id).lifecycle.deletion_reason,
        Some(DeletionReason::ExpiredIdle),
        "idle runs 300 s from the reconciliation finish publication"
    );
}

/// MEDIUM 2 across a reboot: the publication runs before the rebase, so only the
/// wall anchor moves; the rebase then places this boot's activity anchor at now.
#[tokio::test]
async fn startup_interruption_after_a_reboot_restarts_idle_from_the_rebase() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = test_limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let sandbox = m.create(policy(0, 300)).await.unwrap();
    let execution = running_execution(&sandbox.id);
    assert!(m.store.start_execution(&execution).unwrap());
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    clock.reboot("boot-b", 5_000, 900 * SEC);
    // The legacy fake backend still lists the sandbox: it stays READY.
    let m = on_disk(&dir, &fake, &clock, &limits);
    assert_eq!(m.reconcile().await.unwrap().interrupted_executions, 1);
    let published = row(&m, &sandbox.id).lifecycle;
    assert_eq!(published.clock_boot_id.as_deref(), Some("boot-a"), "not yet rebased");
    assert_eq!(published.activity_at_ms, Some(clock.wall_ms()));
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 1);
    let rebased = row(&m, &sandbox.id).lifecycle;
    assert_eq!(rebased.clock_boot_id.as_deref(), Some("boot-b"));
    assert_eq!(rebased.activity_boottime_ms, Some(5_000));
    assert_eq!(rebased.ready_boottime_ms, Some(5_000 - 900 * SEC));
}

fn running_execution(sandbox_id: &str) -> Execution {
    Execution {
        id: new_id("ex"),
        sandbox_id: sandbox_id.into(),
        argv: vec!["sleep".into()],
        state: ExecutionState::Running,
        exit_code: None,
        command_status: None,
        runtime_error: None,
        failure_reason: None,
        started_at_ms: now_ms(),
        finished_at_ms: None,
        timeout_ms: 0,
        stdin_bytes: 0,
        stdout: Captured::default(),
        stderr: Captured::default(),
        sandbox_reusable: None,
        cleanup_evidence: CleanupEvidence::Unknown,
        cancel_reason: None,
    }
}

/// LOW 1 regression (the review's PoC): with no node maximum, a duration the
/// schema cannot store is refused as INVALID_ARGUMENT before preparation.
#[tokio::test]
async fn uncapped_unrepresentable_expiry_is_refused_before_preparation() {
    let (m, fake, _) = clocked(Limits {
        expiry: ExpiryLimits {
            max_lifetime_ms: 0,
            max_idle_ms: 0,
            ..ExpiryLimits::default()
        },
        ..test_limits()
    });
    {
        let mut state = fake.state();
        state.mode = crate::runtime::fake::FakeEvidenceMode::Fenced;
        state.fenced.node_id = Some(Id128::random());
    }
    for expiry in [
        RequestedExpiry {
            max_lifetime_ms: i64::MAX as u64 + 1,
            idle_timeout_ms: 0,
        },
        RequestedExpiry {
            max_lifetime_ms: 0,
            idle_timeout_ms: u64::MAX,
        },
    ] {
        let request = CreateRequest {
            expiry: Some(expiry),
            ..CreateRequest::default()
        };
        let error = m.create(request).await.unwrap_err();
        assert!(matches!(error, Error::InvalidArgument(_)), "{error}");
    }
    assert_eq!(fake.state().fenced.prepare_calls, 0);
    assert_eq!(fake.state().fenced.issued, 0);
    assert!(m.store.sandboxes(true).unwrap().is_empty());
}
