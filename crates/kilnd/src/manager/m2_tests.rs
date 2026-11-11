//! API additions M2 (design sections 3 and 8): idempotent create, its in-flight map,
//! quotas, boot-clock retention and opt-in release, driven by the fake runtime and a
//! manual clock.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::expiry::ManualClock;
use crate::runtime::fake::{FakeGate, FakePhase, FakeRuntime};

const SEC: i64 = 1000;
const DAY: i64 = 86_400 * SEC;
/// R + ceil(R / 1000) for the default one-day retention.
const PRUNE_AGE: i64 = DAY + DAY / 1000;

fn limits() -> Limits {
    Limits {
        max_node_memory_bytes: 1 << 40,
        max_node_pids: 1 << 20,
        max_node_disk_bytes: 1 << 50,
        ..Limits::default()
    }
}

fn clocked_with(
    fake: FakeRuntime,
    limits: Limits,
) -> (Arc<Manager<FakeRuntime>>, FakeRuntime, ManualClock) {
    let clock = ManualClock::default();
    let m = Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        limits,
        Arc::new(clock.clone()),
    );
    (Arc::new(m), fake, clock)
}

fn clocked(limits: Limits) -> (Arc<Manager<FakeRuntime>>, FakeRuntime, ManualClock) {
    clocked_with(FakeRuntime::default(), limits)
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

fn key(request_id: &str, request: &str) -> CreateKey {
    CreateKey {
        request_id: request_id.into(),
        sha256: Digest::of(request.as_bytes()),
    }
}

async fn keyed(
    m: &Arc<Manager<FakeRuntime>>,
    uid: u32,
    request_id: &str,
    request: &str,
) -> Result<Sandbox> {
    m.create_keyed(Ok(CreateRequest::default()), uid, key(request_id, request), None)
        .await
}

fn refusal_of(error: &Error) -> Option<(RefusalCode, &'static str)> {
    match error {
        Error::Refused(code, refusal) => refusal.reason().map(|r| (*code, r)),
        _ => None,
    }
}

fn row(m: &Manager<FakeRuntime>, id: &str) -> Option<Sandbox> {
    m.store.sandbox(id).unwrap()
}

fn records(m: &Manager<FakeRuntime>, uid: u32) -> (u64, u64) {
    let counts = m.store.create_request_counts(uid).unwrap();
    (counts.node, counts.uid)
}

async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("condition never held");
}

#[tokio::test]
async fn retries_return_the_same_row_in_every_state() {
    let (m, fake, _) = clocked(limits());
    let first = keyed(&m, 1000, "k", "spec-a").await.unwrap();
    assert_eq!(first.state, SandboxState::Ready);
    assert_eq!(first.lifecycle.request_id.as_deref(), Some("k"));
    let again = keyed(&m, 1000, "k", "spec-a").await.unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(fake.state().created.len(), 1);
    assert_eq!(m.lifecycle_snapshot().create_retries_answered, 1);
    // A different request under the same key is an error, never a no-op.
    let conflict = keyed(&m, 1000, "k", "spec-b").await.unwrap_err();
    assert_eq!(
        refusal_of(&conflict),
        Some((RefusalCode::AlreadyExists, "request_id_conflict"))
    );
    // DELETED is a settled state like any other.
    m.delete(&first.id).await.unwrap();
    let deleted = keyed(&m, 1000, "k", "spec-a").await.unwrap();
    assert_eq!(deleted.id, first.id);
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(fake.state().created.len(), 1);
    assert_eq!(records(&m, 1000), (1, 1));
}

#[tokio::test]
async fn a_post_commit_failure_is_ok_for_the_original_and_every_retry() {
    let (m, fake, _) = clocked(limits());
    fake.state().fail_create = Some("ambiguous boom".into());
    let failed = keyed(&m, 1000, "ambiguous", "a").await.unwrap();
    assert_eq!(failed.state, SandboxState::Failed);
    assert!(failed.is_charged(), "an ambiguous failure stays charged");
    assert_eq!(
        keyed(&m, 1000, "ambiguous", "a").await.unwrap(),
        m.load(&failed.id).unwrap()
    );
    fake.state().fail_create_definitely = Some("definitely not".into());
    let definite = keyed(&m, 1000, "definite", "a").await.unwrap();
    assert_eq!(definite.state, SandboxState::Failed);
    assert!(!definite.is_charged());
    assert_eq!(keyed(&m, 1000, "definite", "a").await.unwrap().id, definite.id);
    // An unkeyed create still reports the backend's error, exactly as before.
    fake.state().fail_create = Some("unkeyed boom".into());
    assert!(matches!(
        m.create_owned(CreateRequest::default(), 1000).await,
        Err(Error::Backend(_))
    ));
}

#[tokio::test]
async fn a_refusal_before_the_commit_leaves_the_id_free() {
    let (m, fake, _) = clocked(Limits {
        max_sandboxes: 1,
        ..limits()
    });
    let filler = m.create(CreateRequest::default()).await.unwrap();
    assert!(matches!(
        keyed(&m, 1000, "k", "a").await,
        Err(Error::ResourceExhausted(_))
    ));
    assert_eq!(records(&m, 1000), (0, 0));
    // Invalid requests are refused only after the lookups, and record nothing.
    let invalid = m
        .create_keyed(Err("bad spec".into()), 1000, key("k", "a"), None)
        .await
        .unwrap_err();
    assert!(matches!(invalid, Error::InvalidArgument(ref m) if m == "bad spec"));
    m.delete(&filler.id).await.unwrap();
    let created = keyed(&m, 1000, "k", "a").await.unwrap();
    assert_eq!(created.state, SandboxState::Ready);
    // Lookup precedes validation: an accepted key is answered even when the request
    // would now fail validation, for example after a node limit changed.
    let answered = m
        .create_keyed(Err("now invalid".into()), 1000, key("k", "a"), None)
        .await
        .unwrap();
    assert_eq!(answered.id, created.id);
    assert_eq!(fake.state().created.len(), 2);
    assert_eq!(m.keyed_in_flight(), (0, 0, 0));
}

#[tokio::test]
async fn a_retry_waits_for_the_original_and_gets_its_answer() {
    let (m, fake, _) = clocked(limits());
    let gate = FakeGate::default();
    fake.state().create_after_allocation = Some(gate.clone());
    let original = tokio::spawn({
        let m = m.clone();
        async move { keyed(&m, 1000, "k", "a").await }
    });
    gate.entered().await;
    // The row and its record have committed; the operation is still running.
    assert_eq!(records(&m, 1000), (1, 1));
    assert_eq!(m.keyed_in_flight().0, 1);
    let retry = tokio::spawn({
        let m = m.clone();
        async move { keyed(&m, 1000, "k", "a").await }
    });
    until(|| m.keyed_in_flight().2 == 1).await;
    // An unequal digest is refused at once, without waiting.
    let conflict = keyed(&m, 1000, "k", "b").await.unwrap_err();
    assert_eq!(
        refusal_of(&conflict),
        Some((RefusalCode::AlreadyExists, "request_id_conflict"))
    );
    // A retry whose own deadline passes first is told the create is in flight.
    let late = m
        .create_keyed(
            Ok(CreateRequest::default()),
            1000,
            key("k", "a"),
            Some(Instant::now() + Duration::from_millis(30)),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_of(&late),
        Some((RefusalCode::DeadlineExceeded, "create_in_flight"))
    );
    assert_eq!(m.keyed_in_flight().2, 1, "the timed-out waiter left nothing");
    gate.release();
    let original = original.await.unwrap().unwrap();
    let retry = retry.await.unwrap().unwrap();
    assert_eq!(original.state, SandboxState::Ready);
    assert_eq!(retry, original);
    assert_eq!(fake.state().created.len(), 1);
    assert_eq!(m.keyed_in_flight(), (0, 0, 0));
}

/// Waiter leaks on cancellation: canceled retries and a canceled original leave no
/// subscription, no entry and no pending slot once the operation ends.
#[tokio::test]
async fn canceled_waiters_and_originals_leave_nothing_behind() {
    let (m, fake, _) = clocked(limits());
    let gate = FakeGate::default();
    fake.state().create_after_allocation = Some(gate.clone());
    let original = tokio::spawn({
        let m = m.clone();
        async move { keyed(&m, 1000, "k", "a").await }
    });
    gate.entered().await;
    let waiters: Vec<_> = (0..10)
        .map(|_| {
            let m = m.clone();
            tokio::spawn(async move { keyed(&m, 1000, "k", "a").await })
        })
        .collect();
    until(|| m.keyed_in_flight().2 == 10).await;
    for waiter in &waiters {
        waiter.abort();
    }
    for waiter in waiters {
        assert!(waiter.await.unwrap_err().is_cancelled());
    }
    assert_eq!(m.keyed_in_flight(), (1, 0, 0));
    // The original's own RPC goes away too; the operation still finishes.
    original.abort();
    assert!(original.await.unwrap_err().is_cancelled());
    gate.release();
    until(|| m.keyed_in_flight() == (0, 0, 0)).await;
    let settled = keyed(&m, 1000, "k", "a").await.unwrap();
    assert_eq!(settled.state, SandboxState::Ready);
    assert_eq!(fake.state().created.len(), 1);
}

#[tokio::test]
async fn two_simultaneous_first_attempts_create_once() {
    let (m, fake, _) = clocked(limits());
    let (a, b) = tokio::join!(keyed(&m, 1000, "k", "a"), keyed(&m, 1000, "k", "a"));
    assert_eq!(a.unwrap().id, b.unwrap().id);
    assert_eq!(fake.state().created.len(), 1);
    // The primary key is the last line: a second insert for the key is refused in
    // the admitting transaction and inserts nothing.
    let mut twin = m.list(true).unwrap().remove(0);
    twin.id = "sb-00000000000000aa".into();
    twin.state = SandboxState::Creating;
    twin.backend_id = None;
    let admission = RequestAdmission {
        sha256: Digest::of(b"a"),
        max_per_uid: 10,
        max_node: 10,
    };
    assert_eq!(
        m.store
            .reserve_keyed_sandbox(&twin, m.sandbox_budgets(), Some(&admission))
            .unwrap(),
        ReserveSandbox::RequestIdTaken
    );
    assert!(row(&m, &twin.id).is_none());
}

#[tokio::test]
async fn request_ids_are_scoped_per_uid() {
    let (m, fake, _) = clocked(limits());
    let mine = keyed(&m, 1000, "k", "a").await.unwrap();
    let theirs = keyed(&m, 1001, "k", "b").await.unwrap();
    let roots = keyed(&m, 0, "k", "c").await.unwrap();
    assert_ne!(mine.id, theirs.id);
    assert_ne!(mine.id, roots.id);
    assert_eq!(theirs.owner_uid, 1001);
    assert_eq!(fake.state().created.len(), 3);
    assert_eq!(records(&m, 1000), (3, 1));
}

#[tokio::test]
async fn caps_refuse_with_request_id_quota_and_release_frees_a_slot() {
    let (m, _, _) = clocked(Limits {
        create_requests: CreateRequestLimits {
            max_per_uid: 2,
            max_node: 3,
        },
        ..limits()
    });
    let one = keyed(&m, 1, "k1", "a").await.unwrap();
    keyed(&m, 1, "k2", "a").await.unwrap();
    let refused = keyed(&m, 1, "k3", "a").await.unwrap_err();
    assert_eq!(
        refusal_of(&refused),
        Some((RefusalCode::ResourceExhausted, "request_id_quota"))
    );
    keyed(&m, 2, "k1", "a").await.unwrap();
    let node = keyed(&m, 3, "k1", "a").await.unwrap_err();
    assert_eq!(
        refusal_of(&node),
        Some((RefusalCode::ResourceExhausted, "request_id_quota"))
    );
    // A retry of a recorded key is never refused for quota.
    assert_eq!(keyed(&m, 1, "k1", "a").await.unwrap().id, one.id);
    let stats = m.create_request_stats(Some(1)).unwrap();
    assert_eq!(
        stats,
        CreateRequestStats {
            max_node: 3,
            node: 3,
            max_per_uid: 2,
            caller: 2,
            rejected: 2,
        }
    );
    // The counts drop the moment a release commits.
    let released = m.delete_releasing(&one.id, true).await.unwrap();
    assert!(released.lifecycle.request_id_released_at_ms.is_some());
    assert_eq!(records(&m, 1), (2, 1));
    keyed(&m, 1, "k3", "a").await.unwrap();
}

/// Two distinct keys racing for the last slot: the pending slot taken before prepare
/// counts, so exactly one is admitted.
#[tokio::test]
async fn two_keys_racing_for_the_last_slot_admit_one() {
    let (m, fake, _) = clocked_with(
        FakeRuntime::fenced(),
        Limits {
            create_requests: CreateRequestLimits {
                max_per_uid: 1,
                max_node: 8,
            },
            ..limits()
        },
    );
    let gate = FakeGate::default();
    fake.state().fenced.prepare_gate = Some(gate.clone());
    let first = tokio::spawn({
        let m = m.clone();
        async move { keyed(&m, 1, "a", "x").await }
    });
    gate.entered().await;
    assert_eq!(m.keyed_in_flight(), (1, 1, 0));
    assert_eq!(records(&m, 1), (0, 0), "nothing durable yet");
    let second = keyed(&m, 1, "b", "x").await.unwrap_err();
    assert_eq!(
        refusal_of(&second),
        Some((RefusalCode::ResourceExhausted, "request_id_quota"))
    );
    gate.release();
    assert_eq!(first.await.unwrap().unwrap().state, SandboxState::Ready);
    assert_eq!(m.keyed_in_flight(), (0, 0, 0));
    assert_eq!(fake.state().fenced.prepare_calls, 1);
}

/// The durable recount inside the admitting transaction, which no in-memory state can
/// bypass: at a cap the transaction inserts nothing.
#[tokio::test]
async fn the_admitting_transaction_recounts_durable_records() {
    let (m, _, _) = clocked(limits());
    let template = keyed(&m, 1, "k1", "a").await.unwrap();
    let mut next = template.clone();
    next.id = "sb-00000000000000bb".into();
    next.state = SandboxState::Creating;
    next.backend_id = None;
    next.lifecycle = SandboxLifecycle {
        request_id: Some("k2".into()),
        ..SandboxLifecycle::default()
    };
    for (per_uid, node, scope) in [(1, 10, "uid"), (10, 1, "node")] {
        let admission = RequestAdmission {
            sha256: Digest::of(b"a"),
            max_per_uid: per_uid,
            max_node: node,
        };
        match m
            .store
            .reserve_keyed_sandbox(&next, m.sandbox_budgets(), Some(&admission))
            .unwrap()
        {
            ReserveSandbox::RequestQuota(quota) => assert_eq!(quota.scope, scope),
            other => panic!("{other:?}"),
        }
        assert!(row(&m, &next.id).is_none());
    }
}

#[tokio::test]
async fn release_happens_only_in_the_transaction_that_sees_deleted() {
    let (m, fake, _) = clocked(limits());
    let first = keyed(&m, 1000, "k", "a").await.unwrap();
    // Removal fails: the row stays DELETING and nothing is released or remembered.
    fake.state().fail_remove = true;
    assert!(m.delete_releasing(&first.id, true).await.is_err());
    let deleting = row(&m, &first.id).unwrap();
    assert_eq!(deleting.state, SandboxState::Deleting);
    assert!(deleting.lifecycle.request_id_released_at_ms.is_none());
    assert_eq!(records(&m, 1000), (1, 1));
    // A retry reading the record now returns the DELETING row.
    assert_eq!(keyed(&m, 1000, "k", "a").await.unwrap().state, SandboxState::Deleting);
    fake.state().fail_remove = false;
    // A retry that reads the record before the release returns the DELETED row.
    m.delete(&first.id).await.unwrap();
    assert_eq!(keyed(&m, 1000, "k", "a").await.unwrap().state, SandboxState::Deleted);
    let released = m.delete_releasing(&first.id, true).await.unwrap();
    assert_eq!(released.state, SandboxState::Deleted);
    assert_eq!(released.lifecycle.request_id.as_deref(), Some("k"));
    assert!(released.lifecycle.request_id_released_at_ms.is_some());
    assert_eq!(m.lifecycle_snapshot().request_ids_released, 1);
    // Idempotent: a repeat finds no record and changes nothing.
    assert_eq!(m.delete_releasing(&first.id, true).await.unwrap(), released);
    assert_eq!(m.lifecycle_snapshot().request_ids_released, 1);
    // One that reads after the release creates afresh: the risk the client took.
    let second = keyed(&m, 1000, "k", "a").await.unwrap();
    assert_ne!(second.id, first.id);
    assert_eq!(fake.state().created.len(), 2);
    // Without the flag, and on an unkeyed row, nothing is released.
    m.delete(&second.id).await.unwrap();
    assert_eq!(records(&m, 1000), (1, 1));
    let unkeyed = m.create(CreateRequest::default()).await.unwrap();
    let deleted = m.delete_releasing(&unkeyed.id, true).await.unwrap();
    assert!(deleted.lifecycle.request_id_released_at_ms.is_none());
    assert_eq!(m.lifecycle_snapshot().request_ids_released, 1);
}

#[tokio::test]
async fn a_prune_that_got_there_first_leaves_release_a_no_op_or_not_found() {
    let (m, _, clock) = clocked(limits());
    let first = keyed(&m, 1000, "k", "a").await.unwrap();
    m.delete(&first.id).await.unwrap();
    clock.advance(PRUNE_AGE);
    let pruned = m.prune().unwrap();
    assert_eq!(pruned.create_requests, 1);
    // The row is unpinned but within ordinary retention: release finds no record.
    let row_now = m.delete_releasing(&first.id, true).await.unwrap();
    assert!(row_now.lifecycle.request_id_released_at_ms.is_none());
    assert_eq!(row_now.lifecycle.request_id.as_deref(), Some("k"));
    // Once ordinary retention removes it too, the ID is NOT_FOUND: absence.
    let none_kept = crate::retention::Retention {
        sandbox_max_count: 0,
        ..crate::retention::Retention::default()
    };
    assert_eq!(m.store.prune(&none_kept, now_ms()).unwrap().sandboxes, 1);
    assert!(matches!(
        m.delete_releasing(&first.id, true).await,
        Err(Error::NotFound(_))
    ));
}

/// H1: records age only on the boot clock. Wall steps of eight days either way
/// change nothing; inside R a retry always returns the original row; the pinned row
/// outlives ordinary retention; after R plus the margin the record goes.
#[tokio::test]
async fn retention_ignores_wall_steps_and_holds_for_r_plus_the_margin() {
    // A zero count cap: every unpinned terminal row goes at the next prune.
    let mut limits = limits();
    limits.retention.sandbox_max_count = 0;
    let (m, fake, clock) = clocked(limits);
    let first = keyed(&m, 1000, "k", "a").await.unwrap();
    m.delete(&first.id).await.unwrap();
    for step in [8 * DAY, -16 * DAY, 8 * DAY] {
        clock.step_wall(step);
        let pruned = m.prune().unwrap();
        assert_eq!((pruned.create_requests, pruned.sandboxes), (0, 0), "{step}");
        assert_eq!(keyed(&m, 1000, "k", "a").await.unwrap().id, first.id);
    }
    clock.advance(PRUNE_AGE - 1);
    // Pinned: the zero count cap still keeps the row.
    assert_eq!(m.prune().unwrap(), crate::retention::Pruned::default());
    assert_eq!(keyed(&m, 1000, "k", "a").await.unwrap().id, first.id);
    clock.advance(1);
    let pruned = m.prune().unwrap();
    assert_eq!(pruned.create_requests, 1);
    // The record ended in this transaction, then ordinary retention took the row.
    assert_eq!(pruned.sandboxes, 1);
    assert!(row(&m, &first.id).is_none());
    let fresh = keyed(&m, 1000, "k", "a").await.unwrap();
    assert_ne!(fresh.id, first.id);
    assert_eq!(fake.state().created.len(), 2);
}

/// Pruning interplay: a live, LOST or charged FAILED row keeps its record however
/// old; an uncharged FAILED row's record ages out like a DELETED one's.
#[tokio::test]
async fn charged_and_live_rows_keep_their_records() {
    let mut limits = limits();
    limits.retention.sandbox_max_count = 0;
    let (m, fake, clock) = clocked(limits);
    let ready = keyed(&m, 1000, "ready", "a").await.unwrap();
    fake.state().fail_create = Some("ambiguous".into());
    let ambiguous = keyed(&m, 1000, "ambiguous", "a").await.unwrap();
    fake.state().fail_create = None;
    fake.state().fail_create_definitely = Some("definitely not".into());
    let definite = keyed(&m, 1000, "definite", "a").await.unwrap();
    assert!(ambiguous.is_charged() && !definite.is_charged());
    clock.advance(30 * DAY);
    clock.step_wall(30 * DAY);
    let pruned = m.prune().unwrap();
    assert_eq!(pruned.create_requests, 1);
    assert_eq!(pruned.sandboxes, 1, "the released FAILED row, after its record");
    assert!(row(&m, &definite.id).is_none());
    for kept in [&ready, &ambiguous] {
        assert!(row(&m, &kept.id).is_some());
        assert_eq!(
            keyed(&m, 1000, kept.lifecycle.request_id.as_deref().unwrap(), "a")
                .await
                .unwrap()
                .id,
            kept.id
        );
    }
    // Direct SQL cannot drop a record whose sandbox is still charged or live, nor a
    // sandbox row its record pins.
    for id in [&ready.id, &ambiguous.id] {
        assert!(
            m.store
                .execute_for_test("DELETE FROM create_requests WHERE sandbox_id = ?1", id)
                .is_err()
        );
        assert!(
            m.store
                .execute_for_test("DELETE FROM sandboxes WHERE id = ?1", id)
                .is_err()
        );
    }
}

/// A reboot gives every record a fresh, full window in the new boot (R2), never a
/// wall-clock estimate; until the rebase runs, a record from another boot is never
/// pruned however far either clock moves.
#[tokio::test]
async fn a_reboot_gives_records_a_fresh_window_and_foreign_records_are_never_pruned() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let first = keyed(&m, 1000, "k", "a").await.unwrap();
    m.delete(&first.id).await.unwrap();
    clock.advance(DAY - SEC);
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    clock.reboot("boot-b", 5_000, 3 * DAY);
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    // A crash before the rebase commits leaves the record foreign: never prunable.
    clock.advance(10 * DAY);
    assert_eq!(m.prune().unwrap().create_requests, 0);
    assert_eq!(m.rebase_create_requests().unwrap(), 1);
    assert_eq!(m.rebase_create_requests().unwrap(), 0, "one rebase");
    clock.step_wall(-30 * DAY);
    clock.advance(PRUNE_AGE - 1);
    assert_eq!(m.prune().unwrap().create_requests, 0);
    assert_eq!(keyed(&m, 1000, "k", "a").await.unwrap().id, first.id);
    clock.advance(1);
    assert_eq!(m.prune().unwrap().create_requests, 1);
    assert_ne!(keyed(&m, 1000, "k", "a").await.unwrap().id, first.id);
}

/// A crash between the reservation commit and the backend create: the record and
/// its CREATING row exist with no live operation. Before reconciliation a retry is
/// never a fresh create (`create_unsettled`); after it, the legacy row is an
/// ambiguous FAILED, still charged, which every retry returns and Delete refuses.
#[tokio::test]
async fn a_crash_between_reservation_and_create_is_answered_never_recreated() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let limits = limits();
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    let template = m.create(CreateRequest::default()).await.unwrap();
    m.delete(&template.id).await.unwrap();
    let mut crashed = template.clone();
    crashed.id = "sb-00000000000000cc".into();
    crashed.state = SandboxState::Creating;
    crashed.backend_id = None;
    crashed.deleted_at_ms = None;
    crashed.lifecycle = SandboxLifecycle {
        request_id: Some("k".into()),
        ..SandboxLifecycle::default()
    };
    let admission = RequestAdmission {
        sha256: Digest::of(b"a"),
        max_per_uid: 10,
        max_node: 10,
    };
    assert_eq!(
        m.store
            .reserve_keyed_sandbox(&crashed, m.sandbox_budgets(), Some(&admission))
            .unwrap(),
        ReserveSandbox::Inserted
    );
    let root_retry = keyed(&m, crashed.owner_uid, "k", "a").await.unwrap_err();
    assert_eq!(
        refusal_of(&root_retry),
        Some((RefusalCode::Unavailable, "create_unsettled"))
    );
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    m.rebase_create_requests().unwrap();
    let failed = keyed(&m, crashed.owner_uid, "k", "a").await.unwrap();
    assert_eq!(failed.id, crashed.id);
    assert_eq!(failed.state, SandboxState::Failed);
    assert!(failed.is_charged());
    assert_eq!(fake.state().created.len(), 1, "only the template was created");
    assert!(matches!(
        m.delete(&failed.id).await,
        Err(Error::FailedPrecondition(_))
    ));
}

/// Firecracker: a retry never reaches prepare, so it takes no helper token; one
/// that arrives while the failed create's fence is still settling waits for it and
/// gets the original's OK row.
#[tokio::test]
async fn firecracker_retries_take_no_token_and_wait_through_compensation() {
    let (m, fake, _) = clocked_with(FakeRuntime::fenced(), limits());
    let ready = keyed(&m, 1000, "ready", "a").await.unwrap();
    let issued = fake.state().fenced.issued;
    for _ in 0..3 {
        assert_eq!(keyed(&m, 1000, "ready", "a").await.unwrap().id, ready.id);
    }
    assert_eq!(fake.state().fenced.issued, issued);
    assert_eq!(fake.state().fenced.prepare_calls, 1);

    let gate = FakeGate::default();
    {
        let mut state = fake.state();
        state.fenced.stop_at = Some(FakePhase::Intent);
        // Whichever way the fake settles it, removal or fence, waits here.
        state.remove_before_delete = Some(gate.clone());
        state.fenced.fence_gate = Some(gate.clone());
    }
    let original = tokio::spawn({
        let m = m.clone();
        async move { keyed(&m, 1000, "failing", "a").await }
    });
    gate.entered().await;
    // FAILED is published before the fence, and the operation is still settling.
    let published = m.list(true).unwrap().remove(0);
    assert_eq!(published.state, SandboxState::Failed);
    assert!(published.is_charged());
    let retry = tokio::spawn({
        let m = m.clone();
        async move { keyed(&m, 1000, "failing", "a").await }
    });
    until(|| m.keyed_in_flight().2 == 1).await;
    fake.state().fenced.stop_at = None;
    gate.release();
    gate.release();
    let original = original.await.unwrap().unwrap();
    let retry = retry.await.unwrap().unwrap();
    assert_eq!(retry, original);
    assert_eq!(original.state, SandboxState::Failed);
    assert!(!original.is_charged(), "the fence proved absence");
    assert_eq!(fake.state().fenced.prepare_calls, 2);
}

/// Compatibility: a create that sets nothing new behaves exactly as before: never
/// idempotent, no record, no request ID, errors as RPC errors.
#[tokio::test]
async fn unkeyed_creates_are_unchanged() {
    let (m, fake, _) = clocked(limits());
    let a = m.create_owned(CreateRequest::default(), 1000).await.unwrap();
    let b = m.create_owned(CreateRequest::default(), 1000).await.unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(fake.state().created.len(), 2);
    assert!(a.lifecycle.request_id.is_none());
    assert_eq!(records(&m, 1000), (0, 0));
    assert_eq!(m.keyed_in_flight(), (0, 0, 0));
    assert_eq!(m.lifecycle_snapshot().create_retries_answered, 0);
    let deleted = m.delete_releasing(&a.id, false).await.unwrap();
    assert_eq!(deleted, m.load(&a.id).unwrap());
}
