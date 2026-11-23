//! M3-2 findings F1 and F2 at the daemon: a charged absence-fenced row whose settlement
//! failed is retried behind its caller, with a bounded backoff, until its receipt
//! releases it, and never otherwise. The fake's fence models the helper's absence
//! observation being unavailable.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::runtime::fake::{FakeRejection, FakeRuntime};

fn manager() -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    let fake = FakeRuntime::fenced();
    let m = Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    );
    (Arc::new(m), fake)
}

fn state_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = tmp.path().join("state");
    (tmp, dir)
}

fn charged(m: &Manager<FakeRuntime>) -> u64 {
    m.store.sandbox_resources().unwrap().sandboxes
}

const UNAVAILABLE: &str =
    "allocation stays charged (ObservationUnavailable): no fresh namespace observation";

/// The READY session's VMM is gone, but its fence can't get a fresh observation.
fn vmm_gone_and_observation_unavailable(fake: &FakeRuntime, row: &Sandbox) {
    let allocation = row.accounting.allocation.as_ref().unwrap().allocation_id;
    let mut state = fake.state();
    state.fenced.allocations.remove(&allocation);
    state.sandboxes.remove(row.backend_id.as_deref().unwrap());
    state.fenced.fence_unavailable = Some(UNAVAILABLE.into());
}

fn fence_calls(fake: &FakeRuntime) -> u32 {
    fake.state().fenced.fence_calls
}

fn released_by_fence(fake: &FakeRuntime, row: &Sandbox) -> bool {
    let allocation = row.accounting.allocation.as_ref().unwrap();
    fake.state()
        .fenced
        .fences
        .get(&allocation.allocation_id)
        .is_some_and(|fence| {
            row.accounting.release == ReservationRelease::Fenced(fence.receipt_id())
        })
}

/// F1: the Delete returns its error, and the retry behind it records the absence and
/// releases the claim within the first backoff once the observation is available.
#[tokio::test(start_paused = true)]
async fn a_failed_delete_is_retried_until_its_receipt_releases_it() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(sandbox.state, SandboxState::Ready);
    let retries = m.start_settle_retries().unwrap();
    vmm_gone_and_observation_unavailable(&fake, &sandbox);
    let error = m.delete(&sandbox.id).await.unwrap_err();
    assert!(
        error.to_string().contains("ObservationUnavailable"),
        "{error}"
    );
    let row = m.load(&sandbox.id).unwrap();
    assert_eq!(row.state, SandboxState::Deleting);
    assert!(row.is_charged());
    assert_eq!(charged(&m), 1);
    assert_eq!(m.settle_retries(), [(sandbox.id.clone(), 0)]);
    // Create pressure ends; nobody sends another Delete.
    fake.state().fenced.fence_unavailable = None;
    tokio::time::sleep(settle_retry::SETTLE_RETRY_FIRST + Duration::from_millis(100)).await;
    let row = m.load(&sandbox.id).unwrap();
    assert_eq!(row.state, SandboxState::Deleted);
    assert!(!row.is_charged());
    assert!(released_by_fence(&fake, &row));
    assert_eq!(charged(&m), 0);
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    retries.await.unwrap();
}

/// An observation that keeps failing is retried on the backoff (1, 2, 4, 8, 16, then
/// every 30 seconds), never faster, and the retries stop once absence is recorded.
#[tokio::test(start_paused = true)]
async fn a_settlement_that_keeps_failing_backs_off_and_stops_once_released() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let retries = m.start_settle_retries().unwrap();
    vmm_gone_and_observation_unavailable(&fake, &sandbox);
    assert!(m.delete(&sandbox.id).await.is_err());
    let after_delete = fence_calls(&fake);
    let started = Instant::now();
    // Attempts come at 1, 3, 7, 15, 31, 61, 91 and 121 s after the failure.
    tokio::time::sleep(Duration::from_millis(121_500)).await;
    let attempts = fence_calls(&fake) - after_delete;
    assert_eq!(attempts, 8, "one attempt per backoff step, no spinning");
    assert_eq!(m.settle_retries(), [(sandbox.id.clone(), 8)]);
    assert_eq!(charged(&m), 1, "never released without its receipt");
    assert_eq!(m.load(&sandbox.id).unwrap().state, SandboxState::Deleting);
    // The observation comes back: the next attempt, at most 30 s away, releases it.
    fake.state().fenced.fence_unavailable = None;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let row = m.load(&sandbox.id).unwrap();
    assert_eq!(row.state, SandboxState::Deleted);
    assert!(released_by_fence(&fake, &row));
    assert!(started.elapsed() <= Duration::from_secs(152));
    // And then nothing more is attempted.
    let settled = fence_calls(&fake);
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(fence_calls(&fake), settled);
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    retries.await.unwrap();
}

/// F2: a Create refused for capacity whose own fence failed stays visibly FAILED and
/// charged, and the retry, not a Delete, records its absence.
#[tokio::test(start_paused = true)]
async fn a_charged_refused_create_is_settled_failed_without_a_delete() {
    let (m, fake) = manager();
    let retries = m.start_settle_retries().unwrap();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::CapacityExhausted);
        state.fenced.fence_unavailable = Some(UNAVAILABLE.into());
    }
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(error, Error::ResourceExhausted(_)), "{error}");
    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.is_charged());
    assert_eq!(m.settle_retries(), [(row.id.clone(), 0)]);
    fake.state().fenced.fence_unavailable = None;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let row = m.load(&row.id).unwrap();
    assert_eq!(row.state, SandboxState::Failed, "no Delete ran");
    assert!(!row.is_charged());
    assert!(released_by_fence(&fake, &row));
    assert!(fake.state().remove_targets.is_empty());
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    retries.await.unwrap();
}

/// Startup queues what reconciliation left charged, and a legacy row is never queued.
#[tokio::test(start_paused = true)]
async fn startup_queues_every_charged_fenced_row_left_failed_or_deleting() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::fenced();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&dir).unwrap(),
        Limits::default(),
    ));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    vmm_gone_and_observation_unavailable(&fake, &sandbox);
    assert!(m.delete(&sandbox.id).await.is_err());
    drop(m);
    // A daemon restart: a fresh manager over the same rows.
    let restarted = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&dir).unwrap(),
        Limits::default(),
    ));
    assert!(restarted.settle_retries().is_empty());
    let retries = restarted.start_settle_retries().unwrap();
    assert_eq!(restarted.settle_retries(), [(sandbox.id.clone(), 0)]);
    fake.state().fenced.fence_unavailable = None;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        restarted.load(&sandbox.id).unwrap().state,
        SandboxState::Deleted
    );
    restarted.begin_shutdown();
    retries.await.unwrap();

    // The default path: a legacy row's failed Delete is not this retry's to run.
    let legacy = FakeRuntime::default();
    let m = Arc::new(Manager::new(
        legacy.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    legacy.state().fail_remove = true;
    assert!(m.delete(&sandbox.id).await.is_err());
    let retries = m.start_settle_retries().unwrap();
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    retries.await.unwrap();
}

/// A Create refused for capacity whose own fence failed leaves a charged FAILED row. A
/// daemon restart queues it, and the retry releases it with its exact receipt, with no
/// client Delete; the row stays FAILED.
#[tokio::test(start_paused = true)]
async fn startup_recovers_a_charged_failed_create_with_its_receipt() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::fenced();
    let open = || {
        Arc::new(Manager::new(
            fake.clone(),
            Store::open(&dir).unwrap(),
            Limits::default(),
        ))
    };
    let m = open();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::CapacityExhausted);
        state.fenced.fence_unavailable = Some(UNAVAILABLE.into());
    }
    assert!(matches!(
        m.create(CreateRequest::default()).await,
        Err(Error::ResourceExhausted(_))
    ));
    let row = m.list(true).unwrap().remove(0);
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.is_charged());
    drop(m);
    fake.state().fenced.fence_unavailable = None;
    let restarted = open();
    let retries = restarted.start_settle_retries().unwrap();
    assert_eq!(restarted.settle_retries(), [(row.id.clone(), 0)]);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let row = restarted.load(&row.id).unwrap();
    assert_eq!(row.state, SandboxState::Failed, "no Delete ran");
    assert!(!row.is_charged());
    assert!(released_by_fence(&fake, &row));
    assert!(fake.state().remove_targets.is_empty());
    assert!(restarted.settle_retries().is_empty());
    restarted.begin_shutdown();
    retries.await.unwrap();
}

/// Builds a database whose charged DELETING row was written by the fake backend, then
/// reopens it with the real kiln adapter. Returns the reopened manager and the row as
/// the fake left it.
async fn foreign_row(
    dir: &std::path::Path,
) -> (Arc<Manager<crate::runtime::kiln::KilnRuntime>>, Sandbox) {
    let fake = FakeRuntime::fenced();
    let original = Arc::new(Manager::new(
        fake.clone(),
        Store::open(dir).unwrap(),
        Limits::default(),
    ));
    let row = original.create(CreateRequest::default()).await.unwrap();
    vmm_gone_and_observation_unavailable(&fake, &row);
    assert!(original.delete(&row.id).await.is_err());
    let before = original.load(&row.id).unwrap();
    assert_eq!(before.state, SandboxState::Deleting);
    assert!(before.is_charged());
    drop(original);
    // The kiln adapter answers allocation inspection Unsupported, locally.
    let runtime = crate::runtime::kiln::KilnRuntime::new(dir.join("unused.sock"));
    let m = Arc::new(Manager::new(
        runtime,
        Store::open(dir).unwrap(),
        Limits::default(),
    ));
    (m, before)
}

fn assert_untouched(after: &Sandbox, before: &Sandbox) {
    assert_eq!(after.state, before.state);
    assert_eq!(after.is_charged(), before.is_charged());
    assert_eq!(after.failure_reason, before.failure_reason);
    assert_eq!(after.lifecycle, before.lifecycle);
    assert_eq!(after.accounting, before.accounting);
}

/// A restart with another backend never queues a charged row the previous backend
/// wrote, so its visible failure (reason and timestamps) stays exactly as it was.
#[tokio::test(start_paused = true)]
async fn startup_with_another_backend_never_queues_its_rows() {
    let (_tmp, dir) = state_dir();
    let (m, before) = foreign_row(&dir).await;
    let retries = m.start_settle_retries().unwrap();
    assert!(m.settle_retries().is_empty(), "not queued at admission");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_untouched(&m.load(&before.id).unwrap(), &before);
    // Nor does a failed client request on it queue the row.
    m.schedule_settle_retry(&before.id);
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    retries.await.unwrap();
}

/// The recheck before each attempt: a foreign row that is in the queue anyway is
/// dropped from it untouched, never retried.
#[tokio::test(start_paused = true)]
async fn an_attempt_on_another_backends_row_leaves_it_untouched() {
    let (_tmp, dir) = state_dir();
    let (m, before) = foreign_row(&dir).await;
    m.settle_retries.lock().unwrap().insert(
        before.id.clone(),
        settle_retry::SettleRetry {
            failures: 0,
            at: Instant::now(),
            requests: 1,
        },
    );
    let retries = m.start_settle_retries().unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_untouched(&m.load(&before.id).unwrap(), &before);
    assert!(m.settle_retries().is_empty(), "dropped, not retried");
    m.begin_shutdown();
    retries.await.unwrap();
}

/// The handoff: a retry of a charged FAILED row loads it, then a client's Delete takes
/// it to DELETING and departs before running (its RPC canceled). The retry finds a
/// charged DELETING row under the exec lock: that is not settled, so the row stays
/// queued and the next attempt runs its Delete, which releases it by receipt.
#[tokio::test(start_paused = true)]
async fn a_charged_row_a_departed_delete_took_to_deleting_stays_queued() {
    let (m, fake) = manager();
    let retries = m.start_settle_retries().unwrap();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::CapacityExhausted);
        state.fenced.fence_unavailable = Some(UNAVAILABLE.into());
    }
    assert!(m.create(CreateRequest::default()).await.is_err());
    let id = m.list(true).unwrap().remove(0).id;
    assert_eq!(m.settle_retries(), [(id.clone(), 0)]);
    fake.state().fenced.rejection = None;
    // The retry's attempt waits for the exec lock this test holds.
    let slot = m.slot(&id);
    let held = slot.exec_lock.lock().await;
    let fences = fence_calls(&fake);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // A client's Delete publishes DELETING, queues behind the retry for the lock, and
    // departs.
    let client = {
        let (m, id) = (m.clone(), id.clone());
        tokio::spawn(async move { m.delete(&id).await })
    };
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(m.load(&id).unwrap().state, SandboxState::Deleting);
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    drop(held);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(fence_calls(&fake), fences, "the FAILED settlement did not run");
    let row = m.load(&id).unwrap();
    assert_eq!(row.state, SandboxState::Deleting);
    assert!(row.is_charged());
    assert_eq!(
        m.settle_retries(),
        [(id.clone(), 1)],
        "still charged, so still queued"
    );
    // The observation comes back; the next attempt follows the row to its Delete.
    fake.state().fenced.fence_unavailable = None;
    tokio::time::sleep(settle_retry::settle_retry_delay(1) + Duration::from_millis(100)).await;
    let row = m.load(&id).unwrap();
    assert_eq!(row.state, SandboxState::Deleted);
    assert!(released_by_fence(&fake, &row));
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    retries.await.unwrap();
}

/// Only a released charge or a gone row settles an attempt, whatever state a charged
/// row is in; and a request that arrives during an attempt is never lost when that
/// attempt settles.
#[tokio::test(start_paused = true)]
async fn only_a_released_or_gone_row_leaves_the_queue_and_late_requests_survive() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    vmm_gone_and_observation_unavailable(&fake, &sandbox);
    assert!(m.delete(&sandbox.id).await.is_err());
    let id = sandbox.id.clone();
    let requests = |m: &Manager<FakeRuntime>| {
        m.settle_retries.lock().unwrap().get(&id).map(|r| r.requests)
    };
    assert_eq!(requests(&m), Some(1));
    // A charged row, whatever its state, is not settled: it is looked at again later.
    for state in [
        SandboxState::Deleting,
        SandboxState::Failed,
        SandboxState::Lost,
        SandboxState::Quarantined,
    ] {
        m.store
            .execute_for_test(
                &format!("UPDATE sandboxes SET state = '{}' WHERE id = ?1", state.as_str()),
                &id,
            )
            .unwrap();
        assert!(m.load(&id).unwrap().is_charged());
        let attempt = m.settle_attempt(&id).await;
        assert!(
            matches!(attempt, settle_retry::Attempt::Failed(_)),
            "{state:?}: {attempt:?}"
        );
    }
    // A request coalesced during an attempt that settles keeps the entry for one more look.
    let began = requests(&m);
    m.schedule_settle_retry(&id);
    assert_eq!(requests(&m), began.map(|n| n + 1));
    m.finish_settle_retry(&id, began, settle_retry::Attempt::Settled);
    assert_eq!(m.settle_retries(), [(id.clone(), 0)], "the late request survives");
    // Without one, a settled attempt ends the entry.
    m.finish_settle_retry(&id, requests(&m), settle_retry::Attempt::Settled);
    assert!(m.settle_retries().is_empty());
}

/// A charged refused Create left FAILED, whose retry is waiting for its receipt: a
/// client's Delete publishes its intent (DELETING) after the retry's locked reread and
/// departs. The receipt then commits DELETED, not the FAILED the retry chose before it
/// waited, with the charge released by that receipt and the queue empty.
#[tokio::test(start_paused = true)]
async fn a_receipt_that_commits_after_a_delete_intent_ends_deleted() {
    use crate::runtime::fake::FakeGate;

    let (m, fake) = manager();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::CapacityExhausted);
        state.fenced.fence_unavailable = Some(UNAVAILABLE.into());
    }
    assert!(m.create(CreateRequest::default()).await.is_err());
    let row = m.list(true).unwrap().pop().unwrap();
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.is_charged());

    let receipt_ready = FakeGate::default();
    {
        let mut state = fake.state();
        state.fenced.fence_unavailable = None;
        state.fenced.fence_gate = Some(receipt_ready.clone());
    }
    let worker = m.start_settle_retries().unwrap();
    tokio::time::timeout(Duration::from_secs(3), receipt_ready.entered())
        .await
        .expect("the scheduled retry reached its receipt");
    // The retry holds the exec lock and chose FAILED; the client's intent lands now.
    let intent = m.prepare_delete(&row.id, m.load(&row.id).unwrap()).unwrap();
    assert_eq!(intent.state, SandboxState::Deleting);
    assert!(intent.is_charged());
    receipt_ready.release();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let settled = m.load(&row.id).unwrap();
    assert_eq!(settled.state, SandboxState::Deleted);
    assert!(settled.deleted_at_ms.is_some());
    assert!(!settled.is_charged());
    assert!(released_by_fence(&fake, &settled));
    assert_eq!(charged(&m), 0);
    assert!(fake.state().remove_targets.is_empty());
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    worker.await.unwrap();
}

/// The same race on the refused Create's own settlement: the Create chose FAILED and is
/// waiting for its fence when a client's Delete publishes its intent. The receipt commits
/// DELETED; nothing is queued.
#[tokio::test(start_paused = true)]
async fn a_refused_creates_own_receipt_honours_a_delete_intent_published_meanwhile() {
    use crate::runtime::fake::FakeGate;

    let (m, fake) = manager();
    let fence_ready = FakeGate::default();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::CapacityExhausted);
        state.fenced.fence_gate = Some(fence_ready.clone());
    }
    let creating = {
        let m = m.clone();
        tokio::spawn(async move { m.create(CreateRequest::default()).await })
    };
    tokio::time::timeout(Duration::from_secs(3), fence_ready.entered())
        .await
        .expect("the refused Create reached its fence");
    let row = m.list(true).unwrap().pop().unwrap();
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.is_charged());
    let intent = m.prepare_delete(&row.id, row.clone()).unwrap();
    assert_eq!(intent.state, SandboxState::Deleting);
    fence_ready.release();
    let error = creating.await.unwrap().unwrap_err();
    assert!(matches!(error, Error::ResourceExhausted(_)), "{error}");
    let settled = m.load(&row.id).unwrap();
    assert_eq!(settled.state, SandboxState::Deleted);
    assert!(!settled.is_charged());
    assert!(released_by_fence(&fake, &settled));
    assert!(m.settle_retries().is_empty());
}

/// The reverse order: the retry's receipt commits first (FAILED, released), and a later
/// Delete takes the released row to DELETED with no backend work and nothing queued.
#[tokio::test(start_paused = true)]
async fn a_delete_after_the_receipt_committed_needs_no_backend_work() {
    let (m, fake) = manager();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::CapacityExhausted);
        state.fenced.fence_unavailable = Some(UNAVAILABLE.into());
    }
    assert!(m.create(CreateRequest::default()).await.is_err());
    let id = m.list(true).unwrap().pop().unwrap().id;
    fake.state().fenced.fence_unavailable = None;
    let worker = m.start_settle_retries().unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let released = m.load(&id).unwrap();
    assert_eq!(released.state, SandboxState::Failed, "no Delete intent: FAILED");
    assert!(!released.is_charged());
    assert!(m.settle_retries().is_empty());
    let fences = fence_calls(&fake);
    let deleted = m.delete(&id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(deleted.accounting.release, released.accounting.release);
    assert_eq!(fence_calls(&fake), fences, "no backend work");
    assert!(fake.state().remove_targets.is_empty());
    assert!(m.settle_retries().is_empty());
    m.begin_shutdown();
    worker.await.unwrap();
}

/// A charged CREATING row is its Create's, or after a restart startup reconciliation's
/// (which settles CREATING), never this retry's: a row a storage failure left CREATING
/// (READY publication and its cleanup intent both failed) would otherwise be retried
/// forever with nothing to do. The attempt drops it from the queue untouched, once, with
/// no backend work and no further attempts. READY is dropped the same way; LOST and
/// QUARANTINED stay queued for their Delete (`only_a_released_or_gone_row_...`).
#[tokio::test(start_paused = true)]
async fn a_row_left_creating_leaves_the_queue_untouched_and_never_spins() {
    use crate::runtime::fake::FakeGate;

    for state in [SandboxState::Creating, SandboxState::Ready] {
        let (m, fake) = manager();
        let held = FakeGate::default();
        let creating = if state == SandboxState::Creating {
            fake.state().fenced.queued_create_gates.push_back(held.clone());
            let m = m.clone();
            let create = tokio::spawn(async move { m.create(CreateRequest::default()).await });
            tokio::time::timeout(Duration::from_secs(3), held.entered())
                .await
                .expect("the Create reached its backend");
            Some(create)
        } else {
            m.create(CreateRequest::default()).await.unwrap();
            None
        };
        let before = m.list(true).unwrap().pop().unwrap();
        assert_eq!(before.state, state);
        assert!(before.is_charged());
        m.schedule_settle_retry(&before.id);
        assert_eq!(m.settle_retries(), [(before.id.clone(), 0)], "{state:?}");
        let fences = fence_calls(&fake);
        let worker = m.start_settle_retries().unwrap();
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(m.settle_retries().is_empty(), "{state:?}: dropped at its first attempt");
        assert_eq!(fence_calls(&fake), fences, "{state:?}: no backend work");
        assert!(fake.state().remove_targets.is_empty(), "{state:?}");
        assert_untouched(&m.load(&before.id).unwrap(), &before);
        if let Some(create) = creating {
            // Its Create, untouched by the retry, still finishes.
            held.release();
            assert_eq!(create.await.unwrap().unwrap().state, SandboxState::Ready);
        }
        // And nothing more is attempted.
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert!(m.settle_retries().is_empty(), "{state:?}");
        assert_eq!(fence_calls(&fake), fences, "{state:?}");
        assert!(fake.state().remove_targets.is_empty(), "{state:?}");
        assert_eq!(m.load(&before.id).unwrap().state, SandboxState::Ready);
        m.begin_shutdown();
        worker.await.unwrap();
    }
}
