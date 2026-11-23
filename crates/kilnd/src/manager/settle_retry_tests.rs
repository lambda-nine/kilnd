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
