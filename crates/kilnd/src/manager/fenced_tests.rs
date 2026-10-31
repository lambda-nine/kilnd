//! The absence-fenced lifecycle against the fake's fault points: charges, fences
//! and dispositions. Real helper workers and the node ledger belong to B3 and B4.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::model::Network;
use crate::retention::Retention;
use crate::runtime::fake::{
    FakeEvidenceMode, FakeForgery, FakeGate, FakePhase, FakeRejection, FakeRuntime,
};
use crate::runtime::{CreateFailure, ReadyReceipt};

fn manager_with(limits: Limits) -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    let fake = FakeRuntime::fenced();
    let m = Manager::new(fake.clone(), Store::open_in_memory().unwrap(), limits);
    (Arc::new(m), fake)
}

fn manager() -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    manager_with(Limits::default())
}

fn state_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = tmp.path().join("state");
    (tmp, dir)
}

fn exec_req(id: &str, argv: &[&str], timeout_ms: u32) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn charged(m: &Manager<FakeRuntime>) -> u64 {
    m.store.sandbox_resources().unwrap().sandboxes
}

fn row(m: &Manager<FakeRuntime>) -> Sandbox {
    m.list(true).unwrap().remove(0)
}

fn context_of(row: &Sandbox) -> CreateContext {
    fenced_context(row, row.accounting.allocation.as_ref().unwrap())
}

async fn prepared_of(fake: &FakeRuntime, row: &Sandbox) -> PreparedCreate {
    let prepared = fake
        .prepare(
            &context_of(row),
            &row.spec,
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        prepared.plan_digest(),
        row.accounting.allocation.as_ref().unwrap().plan_digest,
        "replays must carry the exact stored plan"
    );
    prepared
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("condition became true");
}

/// A healthy backend's receipt is exactly what the row references.
fn assert_released_by_its_fence(fake: &FakeRuntime, row: &Sandbox) {
    let allocation = row.accounting.allocation.as_ref().unwrap();
    let state = fake.state();
    let fence = state
        .fenced
        .fences
        .get(&allocation.allocation_id)
        .expect("a released row has a durable fence");
    assert!(fence.matches(allocation));
    assert_eq!(
        row.accounting.release,
        ReservationRelease::Fenced(fence.receipt_id()),
        "{}",
        row.id
    );
    assert!(matches!(
        row.state,
        SandboxState::Failed | SandboxState::Deleted
    ));
    assert!(
        !state
            .fenced
            .allocations
            .contains_key(&allocation.allocation_id)
    );
}

/// After a fence, a delayed Create with the same token finds it and nothing else.
async fn assert_late_create_is_fenced(fake: &FakeRuntime, row: &Sandbox) {
    let claims = fake.state().fenced.claims_made;
    let prepared = prepared_of(fake, row).await;
    let failure = fake
        .create(
            &context_of(row),
            &prepared,
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    let allocation = row.accounting.allocation.as_ref().unwrap();
    assert_eq!(
        failure.absence(),
        fake.state().fenced.fences.get(&allocation.allocation_id)
    );
    assert_eq!(fake.state().fenced.claims_made, claims);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    C0Preflight,
    C1Reserved,
    Phase(FakePhase),
    /// READY committed in the helper; the crash precedes SQLite's READY.
    C7Publish,
    /// READY could not be published; the crash precedes compensating removal.
    C8BeforeRemoval,
    /// ABSENT committed in the helper; the crash precedes SQLite's terminal row.
    C8AfterAbsent,
}

#[derive(Debug, PartialEq, Eq)]
enum Recovery {
    NoRow,
    Adopt,
    Release,
}

/// Each boundary kills the daemon with its runtime, so no destructor or later line
/// runs: exactly what a process crash leaves behind, in the store and the fake.
#[test]
fn every_c0_through_c8_crash_boundary_stays_charged_until_its_matching_fence() {
    for (boundary, recovery) in [
        (Boundary::C0Preflight, Recovery::NoRow),
        (Boundary::C1Reserved, Recovery::Release),
        (Boundary::Phase(FakePhase::Intent), Recovery::Release),
        (Boundary::Phase(FakePhase::Preparing), Recovery::Release),
        (Boundary::Phase(FakePhase::SpawnIntent), Recovery::Release),
        (Boundary::Phase(FakePhase::Booting), Recovery::Release),
        (Boundary::Phase(FakePhase::Ready), Recovery::Adopt),
        (Boundary::C7Publish, Recovery::Adopt),
        (Boundary::C8BeforeRemoval, Recovery::Release),
        (Boundary::C8AfterAbsent, Recovery::Release),
    ] {
        let label = format!("{boundary:?}");
        let (_tmp, dir) = state_dir();
        let fake = FakeRuntime::fenced();
        let gate = FakeGate::default();
        let store = Store::open(&dir).unwrap();
        {
            let mut state = fake.state();
            match boundary {
                Boundary::C0Preflight => state.fenced.prepare_gate = Some(gate.clone()),
                Boundary::C1Reserved => state.fenced.queued_create_gates.push_back(gate.clone()),
                Boundary::Phase(phase) => {
                    state.fenced.phase_gates.insert(phase, gate.clone());
                }
                Boundary::C7Publish => {
                    state
                        .fenced
                        .phase_gates
                        .insert(FakePhase::Ready, gate.clone());
                }
                Boundary::C8BeforeRemoval => {
                    store.reject_ready_updates().unwrap();
                    state.remove_before_delete = Some(gate.clone());
                }
                Boundary::C8AfterAbsent => {
                    store.reject_ready_updates().unwrap();
                    state.remove_after_delete = Some(gate.clone());
                }
            }
        }
        let daemon = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let first = Arc::new(Manager::new(fake.clone(), store, Limits::default()));
        let waiter = {
            let first = first.clone();
            daemon.spawn(async move { first.create(CreateRequest::default()).await })
        };
        daemon.block_on(gate.entered());
        // The crash: every task and the store go away, nothing else runs.
        drop(waiter);
        drop(first);
        drop(daemon);

        let restarted = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let m = Arc::new(Manager::new(
            fake.clone(),
            Store::reopen_after_restart(&dir),
            Limits::default(),
        ));
        restarted.block_on(async {
            if recovery == Recovery::NoRow {
                assert_eq!(charged(&m), 0, "{label}: C0 charges nothing");
                assert!(
                    m.list(true).unwrap().is_empty(),
                    "{label}: C0 leaves no row"
                );
                m.reconcile().await.unwrap();
                assert_eq!(fake.state().fenced.claims_made, 0, "{label}");
                assert_eq!(fake.state().fenced.fence_calls, 0, "{label}");
                return;
            }
            assert_eq!(charged(&m), 1, "{label}: charged across the crash");
            assert!(row(&m).is_charged(), "{label}");

            // With proof unavailable, every repeat stays charged.
            {
                let mut state = fake.state();
                state.fail_remove = true;
                state.fenced.fence_unavailable = Some("injected fence sync failure".into());
            }
            if boundary != Boundary::C8AfterAbsent {
                for _ in 0..2 {
                    m.reconcile().await.unwrap();
                    assert_eq!(charged(&m), 1, "{label}: released without proof");
                    assert!(row(&m).is_charged(), "{label}");
                }
            }
            {
                let mut state = fake.state();
                state.fail_remove = false;
                state.fenced.fence_unavailable = None;
            }

            if recovery == Recovery::Adopt {
                // C6/C7: adopt only that exact boot, without a second claim.
                let adopted = row(&m);
                assert_eq!(adopted.state, SandboxState::Ready, "{label}");
                assert_eq!(fake.state().fenced.claims_made, 1, "{label}");
                let ok = m
                    .exec(exec_req(&adopted.id, &["echo", "hi"], 5000))
                    .await
                    .unwrap();
                assert_eq!(ok.state, ExecutionState::Exited, "{label}");
                assert_eq!(charged(&m), 1, "{label}");
                m.delete(&adopted.id).await.unwrap();
            } else {
                m.reconcile().await.unwrap();
            }
            let released = row(&m);
            assert_eq!(charged(&m), 0, "{label}");
            assert_released_by_its_fence(&fake, &released);
            assert!(fake.state().fenced.claims_made <= 1, "{label}");

            // Repeating recovery changes nothing, timestamps included.
            m.reconcile().await.unwrap();
            assert_eq!(row(&m), released, "{label}");
            assert_late_create_is_fenced(&fake, &released).await;
        });
    }
}

#[tokio::test]
async fn pre_intent_rejection_queued_replays_return_the_same_fence() {
    for rejection in [
        FakeRejection::Collision,
        FakeRejection::CatalogMismatch,
        FakeRejection::DeadlineExpired,
        FakeRejection::CapacityExhausted,
        FakeRejection::Panic,
    ] {
        let (m, fake) = manager();
        let fence_sync = FakeGate::default();
        let (first_queued, second_queued) = (FakeGate::default(), FakeGate::default());
        {
            let mut state = fake.state();
            state.fenced.rejection = Some(rejection);
            state.fenced.fence_gate = Some(fence_sync.clone());
        }
        // The first create is rejected before INTENT, then pauses at the fence's sync.
        let creating = tokio::spawn({
            let m = m.clone();
            async move { m.create(CreateRequest::default()).await }
        });
        fence_sync.entered().await;
        let failed = row(&m);
        assert_eq!(failed.state, SandboxState::Failed, "{rejection:?}");
        assert!(
            failed.is_charged(),
            "{rejection:?}: rejection alone released"
        );
        assert_eq!(charged(&m), 1, "{rejection:?}");
        assert!(fake.state().fenced.fences.is_empty(), "{rejection:?}");

        // Two identical requests queue, and the original cause disappears.
        {
            let mut state = fake.state();
            state
                .fenced
                .queued_create_gates
                .push_back(first_queued.clone());
            state
                .fenced
                .queued_create_gates
                .push_back(second_queued.clone());
        }
        let prepared = prepared_of(&fake, &failed).await;
        let duplicate = |prepared: PreparedCreate| {
            let (fake, context) = (fake.clone(), context_of(&failed));
            tokio::spawn(async move {
                fake.create(&context, &prepared, deadline(), &CancellationToken::new())
                    .await
            })
        };
        let duplicates = [duplicate(prepared.clone()), duplicate(prepared.clone())];
        first_queued.entered().await;
        second_queued.entered().await;
        fake.state().fenced.rejection = None;

        // The fence commits, publishes and only then can the duplicates proceed.
        fence_sync.release();
        assert!(creating.await.unwrap().is_err(), "{rejection:?}");
        assert_eq!(charged(&m), 0, "{rejection:?}");
        let released = row(&m);
        assert_released_by_its_fence(&fake, &released);

        first_queued.release();
        second_queued.release();
        let mut receipts = Vec::new();
        for duplicate in duplicates {
            let failure: CreateFailure = duplicate.await.unwrap().unwrap_err();
            receipts.push(
                failure
                    .absence()
                    .cloned()
                    .expect("a fenced token returns its fence"),
            );
        }
        assert_eq!(
            receipts[0], receipts[1],
            "{rejection:?}: one permanent fence"
        );
        assert_eq!(
            released.accounting.release,
            ReservationRelease::Fenced(receipts[0].receipt_id())
        );
        let state = fake.state();
        assert_eq!(
            state.fenced.claims_made, 0,
            "{rejection:?}: no new allocation"
        );
        assert!(state.fenced.allocations.is_empty(), "{rejection:?}");
        assert!(state.created.is_empty(), "{rejection:?}");
    }
}

#[tokio::test]
async fn unfenced_duplicate_during_rejection_stays_ambiguous_and_claims_nothing() {
    let (m, fake) = manager();
    let fence_sync = FakeGate::default();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::Collision);
        state.fenced.fence_gate = Some(fence_sync.clone());
    }
    let creating = tokio::spawn({
        let m = m.clone();
        async move { m.create(CreateRequest::default()).await }
    });
    fence_sync.entered().await;
    let failed = row(&m);
    let prepared = prepared_of(&fake, &failed).await;
    let failure = fake
        .create(
            &context_of(&failed),
            &prepared,
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(failure.certainty(), CreateCertainty::AllocationAmbiguous);
    assert!(failure.absence().is_none());
    assert_eq!(charged(&m), 1);
    fence_sync.release();
    creating.await.unwrap().unwrap_err();
    assert_eq!(charged(&m), 0);
}

#[tokio::test]
async fn delayed_duplicate_create_cannot_allocate_after_a_delete_fence() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let prepared = prepared_of(&fake, &sandbox).await;
    let queued = FakeGate::default();
    fake.state()
        .fenced
        .queued_create_gates
        .push_back(queued.clone());
    let delayed = tokio::spawn({
        let (fake, context, prepared) = (fake.clone(), context_of(&sandbox), prepared.clone());
        async move {
            fake.create(&context, &prepared, deadline(), &CancellationToken::new())
                .await
        }
    });
    queued.entered().await;
    m.delete(&sandbox.id).await.unwrap();
    assert_eq!(charged(&m), 0);
    queued.release();
    let failure = delayed.await.unwrap().unwrap_err();
    assert!(failure.absence().is_some());
    let state = fake.state();
    assert_eq!(state.fenced.claims_made, 1);
    assert!(state.fenced.allocations.is_empty());
    assert!(state.sandboxes.is_empty());
}

#[tokio::test]
async fn a_retried_token_is_a_query_and_never_a_second_claim() {
    let (m, fake) = manager();
    {
        let mut state = fake.state();
        // The capacity transaction commits and its reply is lost; removal is stuck.
        state.fenced.stop_at = Some(FakePhase::Intent);
        state.fail_remove = true;
    }
    m.create(CreateRequest::default()).await.unwrap_err();
    let failed = row(&m);
    assert_eq!(failed.state, SandboxState::Failed);
    assert_eq!(charged(&m), 1);
    assert_eq!(fake.state().fenced.claims_made, 1);
    let prepared = prepared_of(&fake, &failed).await;
    for _ in 0..2 {
        fake.create(
            &context_of(&failed),
            &prepared,
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    }
    assert_eq!(
        fake.state().fenced.claims_made,
        1,
        "retry allocated another claim"
    );
    // A conflicting plan for the token is never accepted.
    let mut changed = failed.spec.clone();
    changed.labels.insert("k".into(), "v".into());
    let other = fake
        .prepare(
            &context_of(&failed),
            &changed,
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_ne!(other.plan_digest(), prepared.plan_digest());
    assert!(
        fake.create(
            &context_of(&failed),
            &other,
            deadline(),
            &CancellationToken::new()
        )
        .await
        .is_err()
    );
    assert_eq!(fake.state().fenced.claims_made, 1);
    fake.state().fail_remove = false;
    m.reconcile().await.unwrap();
    assert_eq!(charged(&m), 0);
    assert_released_by_its_fence(&fake, &row(&m));
}

#[tokio::test]
async fn lost_replies_stay_charged_until_the_exact_receipt_replays() {
    // READY committed, reply lost: the live supervisor compensates rather than adopts.
    let (m, fake) = manager();
    {
        let mut state = fake.state();
        state.fenced.lose_ready_reply = true;
        state.fenced.lose_remove_reply = true;
    }
    m.create(CreateRequest::default()).await.unwrap_err();
    // Removal committed ABSENT but lost its reply too: still charged.
    assert_eq!(charged(&m), 1);
    assert_eq!(row(&m).state, SandboxState::Failed);
    let fence = fake.state().fenced.fences.values().next().cloned().unwrap();
    m.reconcile().await.unwrap();
    assert_eq!(charged(&m), 0);
    assert_eq!(
        row(&m).accounting.release,
        ReservationRelease::Fenced(fence.receipt_id())
    );

    // A fence's commit with a lost reply is the same.
    let (m, fake) = manager();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::Collision);
        state.fenced.lose_fence_reply = true;
    }
    m.create(CreateRequest::default()).await.unwrap_err();
    assert_eq!(charged(&m), 1);
    assert_eq!(fake.state().fenced.fences.len(), 1);
    fake.state().fenced.rejection = None;
    m.reconcile().await.unwrap();
    assert_eq!(charged(&m), 0);
    assert_released_by_its_fence(&fake, &row(&m));
    assert_eq!(fake.state().fenced.fences.len(), 1);
}

#[tokio::test]
async fn absence_receipt_survives_a_lost_terminal_commit() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let reject = m.store.evidence_commit_rejection_flag();
    reject.store(true, Ordering::SeqCst);
    let error = m.delete(&sandbox.id).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected evidence commit failure"),
        "{error}"
    );
    // The helper fence exists; the daemon's terminal row does not. Double-counted,
    // never undercounted.
    let fence = fake.state().fenced.fences.values().next().cloned().unwrap();
    assert_eq!(row(&m).state, SandboxState::Deleting);
    assert_eq!(charged(&m), 1);
    assert!(m.delete(&sandbox.id).await.is_err());
    assert_eq!(charged(&m), 1);
    reject.store(false, Ordering::SeqCst);
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(
        deleted.accounting.release,
        ReservationRelease::Fenced(fence.receipt_id()),
        "the same receipt replayed"
    );
    assert_eq!(charged(&m), 0);
}

#[tokio::test]
async fn forged_receipts_never_publish_or_release() {
    for forgery in [
        FakeForgery::Node,
        FakeForgery::Instance,
        FakeForgery::Allocation,
        FakeForgery::Plan,
    ] {
        // A create reply for another identity is not READY.
        let (m, fake) = manager();
        {
            let mut state = fake.state();
            state.fenced.forge = Some(forgery);
        }
        m.create(CreateRequest::default()).await.unwrap_err();
        let failed = row(&m);
        assert_eq!(failed.state, SandboxState::Failed, "{forgery:?}");
        assert_eq!(failed.backend_id, None, "{forgery:?}");
        assert_eq!(charged(&m), 1, "{forgery:?}");

        // A removal or fence receipt for another identity releases nothing, however
        // often it arrives, and reconciliation refuses it before changing any row.
        assert!(m.delete(&failed.id).await.is_err(), "{forgery:?}");
        assert_eq!(row(&m).state, SandboxState::Deleting, "{forgery:?}");
        assert_eq!(charged(&m), 1, "{forgery:?}");
        assert!(m.reconcile().await.is_err(), "{forgery:?}");
        assert_eq!(charged(&m), 1, "{forgery:?}");

        // The helper's real fence still works once the forged path is gone.
        fake.state().fenced.forge = None;
        let deleted = m.delete(&failed.id).await.unwrap();
        assert_eq!(deleted.state, SandboxState::Deleted, "{forgery:?}");
        assert_released_by_its_fence(&fake, &deleted);
        assert_eq!(charged(&m), 0);
    }
}

#[tokio::test]
async fn not_found_listing_absence_and_legacy_proof_never_release_a_fenced_row() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let backend_id = sandbox.backend_id.clone().unwrap();
    let allocation = sandbox.accounting.allocation.as_ref().unwrap();
    // The helper record vanished with no fence, and fencing cannot complete.
    {
        let mut state = fake.state();
        state.fenced.allocations.remove(&allocation.allocation_id);
        state.sandboxes.remove(&backend_id);
        state.fenced.fence_unavailable = Some("ledger cannot sync".into());
    }
    assert!(matches!(
        fake.remove(&backend_id, deadline(), &CancellationToken::new())
            .await,
        Err(RuntimeError::NotFound(_))
    ));
    assert!(
        fake.list(deadline(), &CancellationToken::new())
            .await
            .unwrap()
            .records
            .is_empty()
    );
    // Delete sees NotFound-equivalent evidence and an empty listing: still charged.
    assert!(m.delete(&sandbox.id).await.is_err());
    assert_eq!(row(&m).state, SandboxState::Deleting);
    assert_eq!(charged(&m), 1);

    // A race where inspection saw it present and removal then finds nothing.
    fake.state().fenced.observation_override = Some(AllocationObservation::StoppedWithResources {
        helper_generation: 9,
    });
    assert!(m.delete(&sandbox.id).await.is_err());
    assert_eq!(charged(&m), 1);

    // Only the fence, once it can commit, releases.
    {
        let mut state = fake.state();
        state.fenced.observation_override = None;
        state.fenced.fence_unavailable = None;
    }
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_released_by_its_fence(&fake, &deleted);
    assert_eq!(charged(&m), 0);

    // A backend that answers with legacy proof cannot release either.
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().mode = FakeEvidenceMode::Legacy;
    fake.state()
        .sandboxes
        .insert(sandbox.backend_id.clone().unwrap(), BackendStatus::Running);
    assert!(m.delete(&sandbox.id).await.is_err());
    assert_eq!(charged(&m), 1);
    assert_eq!(row(&m).state, SandboxState::Deleting);
}

#[tokio::test]
async fn failed_ready_publication_compensates_by_exact_allocation_and_stays_charged() {
    let (m, fake) = manager();
    m.store.reject_ready_updates().unwrap();
    fake.state().fail_remove = true;
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(error.to_string().contains("cleanup failed"), "{error}");
    let stuck = row(&m);
    assert_eq!(stuck.state, SandboxState::Deleting);
    assert_eq!(stuck.backend_id, None, "READY never published this ID");
    assert_eq!(charged(&m), 1);
    let binding = stuck.accounting.allocation.clone().unwrap();
    assert_eq!(
        fake.state().remove_attempts,
        vec![binding.backend_id()],
        "compensation targets the exact allocation"
    );
    assert_eq!(
        fake.state().fenced.allocations[&binding.allocation_id].phase,
        FakePhase::Stopped
    );

    // Stopped is not absent; the retry owns the disk until ABSENT commits.
    fake.state().fail_remove = false;
    let deleted = m.delete(&stuck.id).await.unwrap();
    assert_released_by_its_fence(&fake, &deleted);
    assert_eq!(charged(&m), 0);

    // On the first attempt's success the row ends FAILED, uncharged, with history.
    let (m, fake) = manager();
    m.store.reject_ready_updates().unwrap();
    m.create(CreateRequest::default()).await.unwrap_err();
    let compensated = row(&m);
    assert_eq!(compensated.state, SandboxState::Failed);
    assert_released_by_its_fence(&fake, &compensated);
    assert!(
        compensated
            .failure_reason
            .unwrap()
            .contains("backend removed")
    );
    assert_eq!(charged(&m), 0);
}

#[tokio::test]
async fn timed_out_stopped_session_refuses_its_queued_successor() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let running = tokio::spawn({
        let (m, id) = (m.clone(), sandbox.id.clone());
        async move { m.exec(exec_req(&id, &["sleep"], 50)).await }
    });
    let f = fake.clone();
    wait_until(move || !f.state().exec_calls.is_empty()).await;
    let queued = tokio::spawn({
        let (m, id) = (m.clone(), sandbox.id.clone());
        async move { m.exec(exec_req(&id, &["echo", "successor"], 5000)).await }
    });
    let timed_out = running.await.unwrap().unwrap();
    assert_eq!(timed_out.state, ExecutionState::TimedOut);
    assert_eq!(timed_out.sandbox_reusable, Some(false));
    assert_eq!(timed_out.cleanup_evidence, CleanupEvidence::SandboxStopped);
    let refused = queued.await.unwrap().unwrap_err();
    assert!(matches!(refused, Error::FailedPrecondition(_)), "{refused}");
    assert_eq!(
        fake.state().exec_calls.len(),
        1,
        "the successor reached the backend of a retired session"
    );
    let lost = m.get(&sandbox.id, 10).unwrap();
    assert_eq!(lost.0.state, SandboxState::Lost);
    assert_eq!(lost.0.accounting.disposition, SandboxDisposition::Stopped);
    assert!(lost.0.is_charged(), "stopped is not absent");
    assert_eq!(charged(&m), 1);
    assert_eq!(lost.1.len(), 1, "the refused successor made no row");
    // A retired session cannot be dispatched to again, and Delete still works.
    assert!(matches!(
        m.exec(exec_req(&sandbox.id, &["echo"], 5000)).await,
        Err(Error::FailedPrecondition(_))
    ));
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_released_by_its_fence(&fake, &deleted);
    assert_eq!(charged(&m), 0);
}

#[tokio::test]
async fn normal_completion_preserves_the_session_and_records_reuse() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    for _ in 0..2 {
        let done = m
            .exec(exec_req(&sandbox.id, &["exit", "125"], 5000))
            .await
            .unwrap();
        assert_eq!(done.state, ExecutionState::Exited);
        assert_eq!(done.exit_code, Some(125), "real status is preserved");
        assert_eq!(done.sandbox_reusable, Some(true));
        assert_eq!(done.cleanup_evidence, CleanupEvidence::RuntimeDrained);
    }
    assert_eq!(row(&m).state, SandboxState::Ready);
    assert_eq!(fake.state().exec_calls.len(), 2);
}

#[tokio::test]
async fn cleanup_failure_quarantines_and_refuses_queued_successor_on_every_regime() {
    for fenced in [false, true] {
        let fake = if fenced {
            FakeRuntime::fenced()
        } else {
            FakeRuntime::default()
        };
        let m = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let sandbox = m.create(CreateRequest::default()).await.unwrap();
        let gate = FakeGate::default();
        fake.state().exec_before_run = Some(gate.clone());
        let running = tokio::spawn({
            let (m, id) = (m.clone(), sandbox.id.clone());
            async move { m.exec(exec_req(&id, &["cleanup-fail"], 5000)).await }
        });
        gate.entered().await;
        let queued = tokio::spawn({
            let (m, id) = (m.clone(), sandbox.id.clone());
            async move { m.exec(exec_req(&id, &["echo"], 5000)).await }
        });
        tokio::task::yield_now().await;
        gate.release();
        let failed = running.await.unwrap().unwrap();
        assert_eq!(failed.state, ExecutionState::Failed);
        assert_eq!(failed.sandbox_reusable, Some(false));
        assert_eq!(failed.cleanup_evidence, CleanupEvidence::Unknown);
        assert_eq!(
            failed.runtime_error.as_ref().map(|d| d.kind),
            Some(RuntimeErrorKind::CleanupFailed)
        );
        let refused = queued.await.unwrap().unwrap_err();
        assert!(matches!(refused, Error::FailedPrecondition(_)), "{refused}");
        assert_eq!(fake.state().exec_calls.len(), 1);
        let quarantined = row(&m);
        assert_eq!(quarantined.state, SandboxState::Quarantined);
        assert!(quarantined.is_charged());
        assert_eq!(charged(&m), 1);
        assert_eq!(m.health().await.unwrap().active_sandboxes, 1);
        // Reconciliation never resumes it, and only Delete's proof releases it.
        m.reconcile().await.unwrap();
        assert_eq!(row(&m).state, SandboxState::Quarantined);
        assert_eq!(
            m.delete(&sandbox.id).await.unwrap().state,
            SandboxState::Deleted
        );
        assert_eq!(charged(&m), 0);
    }
}

#[tokio::test]
async fn panic_retires_a_fenced_session_and_records_unknown_on_legacy() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().panic_exec = true;
    let failed = m
        .exec(exec_req(&sandbox.id, &["echo"], 5000))
        .await
        .unwrap();
    assert_eq!(failed.state, ExecutionState::Failed);
    assert_eq!(failed.sandbox_reusable, Some(false));
    assert_eq!(row(&m).state, SandboxState::Quarantined);
    assert_eq!(charged(&m), 1);
    fake.state().panic_exec = false;
    assert!(
        m.exec(exec_req(&sandbox.id, &["echo"], 5000))
            .await
            .is_err()
    );

    // Legacy kiln's behavior is unchanged, but nothing claims it was proven reusable.
    let fake = FakeRuntime::default();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().panic_exec = true;
    let failed = m
        .exec(exec_req(&sandbox.id, &["echo"], 5000))
        .await
        .unwrap();
    assert_eq!(failed.sandbox_reusable, None);
    assert_eq!(failed.cleanup_evidence, CleanupEvidence::Unknown);
    assert_eq!(row(&m).state, SandboxState::Ready);
}

#[test]
fn runtime_claims_cannot_outrun_their_evidence_on_a_fenced_row() {
    use CleanupEvidence as C;
    use SandboxDisposition as D;
    let fake_row = |fenced: bool| Sandbox {
        id: new_id("sb"),
        state: SandboxState::Ready,
        spec: SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 1,
            cpu_millis: 1,
            pids: 1,
            disk_bytes: 1,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: Default::default(),
        },
        backend: "fake".into(),
        backend_id: None,
        created_at_ms: 0,
        updated_at_ms: 0,
        deleted_at_ms: None,
        failure_reason: None,
        create_certainty: CreateCertainty::AllocationAmbiguous,
        owner_uid: 0,
        accounting: SandboxAccounting {
            regime: if fenced {
                AccountingRegime::AbsenceFenced
            } else {
                AccountingRegime::Legacy
            },
            ..SandboxAccounting::legacy(
                &SandboxSpec {
                    image: "alpine".into(),
                    memory_bytes: 1,
                    cpu_millis: 1,
                    pids: 1,
                    disk_bytes: 1,
                    network: Network::None,
                    read_only_root: false,
                    writable_paths: vec![],
                    labels: Default::default(),
                },
                "",
            )
        },
    };
    let outcome = |finish, disposition, cleanup| ExecOutcome {
        finish,
        command_status: None,
        stdout: Captured::default(),
        stderr: Captured::default(),
        disposition,
        cleanup,
    };
    let done = || Ok(ExecFinish::Completed);
    let timeout = || Ok(ExecFinish::TimedOut);
    let failed = || {
        Err(RuntimeDiagnostic::new(
            RuntimeErrorKind::Protocol,
            RuntimeStage::Report,
            "x",
        ))
    };
    let quarantine = (D::Quarantined, C::Unknown, Some(false));
    for (finish, disposition, cleanup, expected) in [
        (
            done(),
            D::Reusable,
            C::RuntimeDrained,
            (D::Reusable, C::RuntimeDrained, Some(true)),
        ),
        (
            timeout(),
            D::Reusable,
            C::NoChildStarted,
            (D::Reusable, C::NoChildStarted, Some(true)),
        ),
        (
            timeout(),
            D::Stopped,
            C::SandboxStopped,
            (D::Stopped, C::SandboxStopped, Some(false)),
        ),
        // A guest's Drained after interruption or failure cannot preserve the VM.
        (timeout(), D::Reusable, C::RuntimeDrained, quarantine),
        (failed(), D::Reusable, C::RuntimeDrained, quarantine),
        (done(), D::Reusable, C::Unknown, quarantine),
        (done(), D::Reusable, C::NoChildStarted, quarantine),
        // Stopped must carry stop evidence.
        (failed(), D::Stopped, C::Unknown, quarantine),
        (timeout(), D::Stopped, C::RuntimeDrained, quarantine),
        (failed(), D::Quarantined, C::SandboxStopped, quarantine),
    ] {
        let case = format!("{finish:?} {disposition:?} {cleanup:?}");
        assert_eq!(
            settled_exec_evidence(&fake_row(true), &outcome(finish, disposition, cleanup)),
            expected,
            "{case}"
        );
    }
    // A legacy claim is its existing contract.
    assert_eq!(
        settled_exec_evidence(
            &fake_row(false),
            &outcome(timeout(), D::Reusable, C::RuntimeDrained)
        ),
        (D::Reusable, C::RuntimeDrained, Some(true))
    );
    assert_eq!(
        settled_exec_evidence(&fake_row(false), &outcome(done(), D::Reusable, C::Unknown)),
        (D::Reusable, C::Unknown, None)
    );
}

#[tokio::test]
async fn preflight_paused_through_shutdown_allocates_nothing() {
    for ignores_cancel in [false, true] {
        let (m, fake) = manager();
        let gate = FakeGate::default();
        {
            let mut state = fake.state();
            state.fenced.prepare_gate = Some(gate.clone());
            state.fenced.prepare_ignores_cancel = ignores_cancel;
        }
        let creating = tokio::spawn({
            let m = m.clone();
            async move { m.create(CreateRequest::default()).await }
        });
        gate.entered().await;
        assert!(m.list(true).unwrap().is_empty(), "preflight inserted a row");
        // The serving check that admitted this call has now gone stale.
        m.begin_shutdown();
        gate.release();
        let error = creating.await.unwrap().unwrap_err();
        assert!(matches!(error, Error::ShuttingDown), "{error}");
        assert!(m.list(true).unwrap().is_empty(), "shutdown still reserved");
        assert_eq!(charged(&m), 0);
        {
            let state = fake.state();
            assert_eq!(state.fenced.claims_made, 0, "shutdown still allocated");
            assert!(state.created.is_empty());
            assert!(state.fenced.allocations.is_empty());
        }
        tokio::time::timeout(Duration::from_secs(5), m.drain_operations())
            .await
            .expect("the tracked preflight drained");
    }
}

#[tokio::test]
async fn c0_rejection_leaves_no_row_no_charge_and_no_fence() {
    let (m, fake) = manager();
    fake.state().fenced.fail_prepare = Some("profile not approved".into());
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error}");
    fake.state().fenced.fail_prepare = None;
    fake.state().fenced.prepare_panics = true;
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(error.to_string().contains("panicked"), "{error}");
    assert!(m.list(true).unwrap().is_empty());
    assert_eq!(charged(&m), 0);
    {
        let state = fake.state();
        assert_eq!(state.fenced.claims_made, 0);
        assert_eq!(state.fenced.fence_calls, 0);
    }
    // A spec outside the offline profile is refused the same way, with no row.
    fake.state().fenced.prepare_panics = false;
    let error = m
        .create(CreateRequest {
            network: Network::Full,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error}");
    assert!(m.list(true).unwrap().is_empty());
}

#[tokio::test]
async fn reservation_budget_charges_stored_vectors_for_every_session() {
    let (m, fake) = manager_with(Limits {
        // 3072 MiB less the once-per-node shared reserve.
        max_node_memory_bytes: 2944 << 20,
        ..Limits::default()
    });
    let mut ids = Vec::new();
    for _ in 0..3 {
        let sandbox = m.create(CreateRequest::default()).await.unwrap();
        assert_eq!(sandbox.accounting.reservation.memory_bytes, 896 << 20);
        assert_eq!(sandbox.accounting.reservation.disk_bytes, 1408 << 20);
        assert_eq!(sandbox.accounting.reservation.pids, 192);
        assert_eq!(sandbox.accounting.runtime_profile, "offline-768-v1");
        assert_eq!(
            sandbox.spec.memory_bytes,
            512 << 20,
            "tool limits stay as asked"
        );
        ids.push(sandbox.id);
    }
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(error, Error::ResourceExhausted(_)), "{error}");
    assert_eq!(
        m.list(true).unwrap().len(),
        3,
        "a rejected reservation has no row"
    );
    assert_eq!(fake.state().fenced.claims_made, 3);
    let snapshot = m.health().await.unwrap().node_resources;
    assert_eq!(snapshot.reserved.memory_bytes, 3 * (896 << 20));
    assert_eq!(snapshot.reserved.host_cpu_millis, 3000);
    assert_eq!(snapshot.reserved.virtual_cpu_slots, 3);
    assert_eq!(snapshot.reserved.host_pids, 96);
    assert_eq!(snapshot.rejected_creates, 1);
    // A freed slot admits exactly one more, only after the fence commits.
    m.delete(&ids[0]).await.unwrap();
    m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(fake.state().fenced.claims_made, 4);
}

#[tokio::test]
async fn concurrent_deletes_share_one_removal_and_one_final_row() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let gate = FakeGate::default();
    fake.state().remove_before_delete = Some(gate.clone());
    let delete =
        |m: Arc<Manager<FakeRuntime>>, id: String| tokio::spawn(async move { m.delete(&id).await });
    let first = delete(m.clone(), sandbox.id.clone());
    gate.entered().await;
    let followers = [
        delete(m.clone(), sandbox.id.clone()),
        delete(m.clone(), sandbox.id.clone()),
    ];
    tokio::task::yield_now().await;
    assert_eq!(row(&m).state, SandboxState::Deleting);
    assert_eq!(charged(&m), 1);
    gate.release();
    let final_row = first.await.unwrap().unwrap();
    for follower in followers {
        assert_eq!(follower.await.unwrap().unwrap(), final_row);
    }
    assert_eq!(fake.state().removed.len(), 1);
    assert_released_by_its_fence(&fake, &final_row);
    // Deleting a deleted sandbox is an idempotent no-op.
    assert_eq!(m.delete(&sandbox.id).await.unwrap(), final_row);
}

#[tokio::test]
async fn delete_cancels_a_running_exec_only_after_durable_intent() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let running = tokio::spawn({
        let (m, id) = (m.clone(), sandbox.id.clone());
        async move { m.exec(exec_req(&id, &["sleep"], 60_000)).await }
    });
    let f = fake.clone();
    wait_until(move || f.state().active_execs == 1).await;
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    let canceled = running.await.unwrap().unwrap();
    assert_eq!(canceled.state, ExecutionState::Canceled);
    assert_eq!(canceled.failure_reason.as_deref(), Some("sandbox deleted"));
    assert_eq!(canceled.sandbox_reusable, Some(false));
    assert_released_by_its_fence(&fake, &deleted);
}

#[tokio::test]
async fn no_id_allocation_can_be_fenced_where_legacy_stays_ambiguous() {
    let (m, fake) = manager();
    {
        let mut state = fake.state();
        state.fenced.rejection = Some(FakeRejection::Collision);
        state.fenced.fence_unavailable = Some("ledger blocked".into());
    }
    m.create(CreateRequest::default()).await.unwrap_err();
    let failed = row(&m);
    assert_eq!(
        (failed.state, failed.backend_id.clone()),
        (SandboxState::Failed, None)
    );
    assert_eq!(charged(&m), 1);
    assert!(m.delete(&failed.id).await.is_err());
    assert_eq!(row(&m).state, SandboxState::Deleting);
    assert_eq!(charged(&m), 1);
    fake.state().fenced.fence_unavailable = None;
    let deleted = m.delete(&failed.id).await.unwrap();
    assert_released_by_its_fence(&fake, &deleted);
    assert_eq!(charged(&m), 0);

    // The same shape on the legacy regime has no token, so it stays charged.
    let fake = FakeRuntime::default();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    fake.state().fail_create = Some("ambiguous".into());
    m.create(CreateRequest::default()).await.unwrap_err();
    let failed = row(&m);
    assert!(matches!(
        m.delete(&failed.id).await,
        Err(Error::FailedPrecondition(_))
    ));
    assert_eq!(charged(&m), 1);
}

#[tokio::test]
async fn reconcile_validates_inventory_and_evidence_before_any_mutation() {
    type Fault = fn(&mut crate::runtime::fake::FakeState, Id128);
    let faults: [(&str, Fault); 7] = [
        ("incomplete", |s, _| s.fenced.inventory_incomplete = true),
        ("duplicate", |s, _| s.fenced.inventory_duplicates = true),
        ("corrupt label", |s, allocation| {
            s.fenced.inventory_extra.push(BackendRecord {
                id: "fc-mislabeled".into(),
                status: BackendStatus::Stale,
                allocation_id: Some(allocation),
                plan_digest: None,
                generation: 1,
            })
        }),
        ("wrong plan", |s, allocation| {
            let entry = s.fenced.allocations.get_mut(&allocation).unwrap();
            entry.plan_digest = Digest::of(b"another plan");
            s.fenced.observation_override = Some(AllocationObservation::Unknown {
                reason: "plan".into(),
            });
        }),
        ("inspection unavailable", |s, _| {
            s.fenced.inspect_unavailable = true
        }),
        ("backend unavailable", |s, _| s.unavailable = true),
        ("hidden allocation", |s, allocation| {
            // Inspection reports it present while the inventory omits it.
            let existing = s.fenced.allocations.remove(&allocation).unwrap();
            s.fenced.observation_override = Some(AllocationObservation::Present {
                receipt: ReadyReceipt {
                    node_id: s.fenced.node_id.unwrap(),
                    instance_id: existing.instance_id,
                    allocation_id: allocation,
                    plan_digest: existing.plan_digest,
                    helper_generation: existing.generation,
                    boot_id: existing.boot_id,
                },
                healthy_idle: true,
                uncertain_execution: false,
            });
        }),
    ];
    for (name, fault) in faults {
        let (m, fake) = manager();
        let ready = m.create(CreateRequest::default()).await.unwrap();
        // A second row that recovery would otherwise fence or remove.
        fake.state().fenced.stop_at = Some(FakePhase::Preparing);
        fake.state().fail_remove = true;
        m.create(CreateRequest::default()).await.unwrap_err();
        {
            let mut state = fake.state();
            state.fenced.stop_at = None;
            state.fail_remove = false;
        }
        let allocation = ready.accounting.allocation.as_ref().unwrap().allocation_id;
        let rows_before = m.list(true).unwrap();
        let (removes, fences) = {
            let mut state = fake.state();
            let observed = (state.remove_attempts.len(), state.fenced.fence_calls);
            fault(&mut state, allocation);
            observed
        };
        let error = m.reconcile().await.unwrap_err();
        assert!(!error.to_string().is_empty(), "{name}");
        assert_eq!(m.list(true).unwrap(), rows_before, "{name} changed a row");
        let state = fake.state();
        assert_eq!(state.remove_attempts.len(), removes, "{name} removed");
        assert_eq!(state.fenced.fence_calls, fences, "{name} fenced");
        assert!(state.gc_requests.is_empty(), "{name} collected");
    }
}

#[tokio::test]
async fn ready_recovery_keeps_only_the_identical_healthy_boot() {
    // The same healthy boot survives, repeatedly.
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::fenced();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&dir).unwrap(),
        Limits::default(),
    ));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let boot = sandbox.accounting.boot_id.clone().unwrap();
    assert!(boot.starts_with("boot-"));
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::reopen_after_restart(&dir),
        Limits::default(),
    ));
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled, Reconciled::default());
    assert_eq!(row(&m).state, SandboxState::Ready);
    assert_eq!(
        m.exec(exec_req(&sandbox.id, &["echo"], 5000))
            .await
            .unwrap()
            .state,
        ExecutionState::Exited
    );

    // A different boot, a busy session, an unknown session each quarantine; a
    // stopped one is LOST. All stay charged and none is rebooted.
    type Change = fn(&mut crate::runtime::fake::FakeAllocation);
    let cases: [(&str, Change, SandboxState); 4] = [
        (
            "replaced boot",
            |a| a.boot_id = "boot-other".into(),
            SandboxState::Quarantined,
        ),
        (
            "uncertain execution",
            |a| a.uncertain_execution = true,
            SandboxState::Quarantined,
        ),
        (
            "not ready",
            |a| a.phase = FakePhase::Booting,
            SandboxState::Quarantined,
        ),
        (
            "stopped",
            |a| a.phase = FakePhase::Stopped,
            SandboxState::Lost,
        ),
    ];
    for (name, change, expected) in cases {
        let (m, fake) = manager();
        let sandbox = m.create(CreateRequest::default()).await.unwrap();
        let allocation = sandbox
            .accounting
            .allocation
            .as_ref()
            .unwrap()
            .allocation_id;
        change(
            fake.state()
                .fenced
                .allocations
                .get_mut(&allocation)
                .unwrap(),
        );
        m.reconcile().await.unwrap();
        let after = row(&m);
        assert_eq!(after.state, expected, "{name}");
        assert!(after.is_charged(), "{name}");
        assert!(
            matches!(
                m.exec(exec_req(&sandbox.id, &["echo"], 5000)).await,
                Err(Error::FailedPrecondition(_))
            ),
            "{name}"
        );
        // Even a fresh healthy report cannot revive it.
        change(
            fake.state()
                .fenced
                .allocations
                .get_mut(&allocation)
                .unwrap(),
        );
        {
            let mut state = fake.state();
            let entry = state.fenced.allocations.get_mut(&allocation).unwrap();
            entry.phase = FakePhase::Ready;
            entry.uncertain_execution = false;
            entry.boot_id = sandbox.accounting.boot_id.clone().unwrap();
        }
        m.reconcile().await.unwrap();
        assert_eq!(row(&m).state, expected, "{name} resurrected");
        assert_eq!(fake.state().fenced.claims_made, 1, "{name}");
        let deleted = m.delete(&sandbox.id).await.unwrap();
        assert_released_by_its_fence(&fake, &deleted);
    }

    // Unknown evidence is not absence either.
    let (m, fake) = manager();
    m.create(CreateRequest::default()).await.unwrap();
    fake.state().fenced.observation_override = Some(AllocationObservation::Unknown {
        reason: "journal unreadable".into(),
    });
    m.reconcile().await.unwrap();
    assert_eq!(row(&m).state, SandboxState::Quarantined);
    assert_eq!(charged(&m), 1);
}

#[test]
fn a_crash_during_execution_needs_a_stop_barrier_before_interrupted() {
    for stopped in [true, false] {
        let (_tmp, dir) = state_dir();
        let fake = FakeRuntime::fenced();
        let daemon = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let m = Arc::new(Manager::new(
            fake.clone(),
            Store::open(&dir).unwrap(),
            Limits::default(),
        ));
        let gate = FakeGate::default();
        let id = daemon.block_on({
            let m = m.clone();
            async move { m.create(CreateRequest::default()).await.unwrap().id }
        });
        fake.state().exec_before_run = Some(gate.clone());
        let waiter = {
            let (m, id) = (m.clone(), id.clone());
            daemon.spawn(async move { m.exec(exec_req(&id, &["echo", "once"], 60_000)).await })
        };
        daemon.block_on(gate.entered());
        // The crash: RUNNING is durable and no later line of the supervisor runs.
        drop(waiter);
        drop(m);
        drop(daemon);

        let restarted = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let m = Arc::new(Manager::new(
            fake.clone(),
            Store::reopen_after_restart(&dir),
            Limits::default(),
        ));
        restarted.block_on(async {
            assert_eq!(m.store.count_running_executions().unwrap(), 1);
            let allocation = row(&m).accounting.allocation.unwrap().allocation_id;
            {
                let mut state = fake.state();
                let entry = state.fenced.allocations.get_mut(&allocation).unwrap();
                if stopped {
                    entry.phase = FakePhase::Stopped;
                } else {
                    entry.uncertain_execution = true;
                }
            }
            let calls = fake.state().exec_calls.len();
            let reconciled = m.reconcile().await.unwrap();
            assert_eq!(reconciled.interrupted_executions, 1);
            let (sandbox, executions) = m.get(&id, 10).unwrap();
            let execution = &executions[0];
            assert_eq!(execution.sandbox_reusable, Some(false));
            if stopped {
                assert_eq!(execution.state, ExecutionState::Interrupted);
                assert_eq!(execution.cleanup_evidence, CleanupEvidence::SandboxStopped);
                assert_eq!(sandbox.state, SandboxState::Lost);
            } else {
                assert_eq!(execution.state, ExecutionState::Failed);
                assert_eq!(execution.cleanup_evidence, CleanupEvidence::Unknown);
                assert_eq!(
                    execution.runtime_error.as_ref().map(|d| d.kind),
                    Some(RuntimeErrorKind::CleanupFailed)
                );
                assert_eq!(sandbox.state, SandboxState::Quarantined);
            }
            assert!(sandbox.is_charged());
            assert_eq!(m.store.count_running_executions().unwrap(), 0);
            assert_eq!(
                fake.state().exec_calls.len(),
                calls,
                "a command was replayed"
            );
            assert!(matches!(
                m.exec(exec_req(&id, &["echo"], 5000)).await,
                Err(Error::FailedPrecondition(_))
            ));
        });
    }
}

#[tokio::test]
async fn legacy_receipt_or_regime_cannot_mix_with_allocation_rows() {
    // A legacy row's Delete takes legacy proof and never a fenced store path.
    let fake = FakeRuntime::default();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(sandbox.accounting.regime, AccountingRegime::Legacy);
    assert_eq!(sandbox.accounting.allocation, None);
    assert_eq!(sandbox.accounting.reservation.host_cpu_millis, 0);
    assert_eq!(sandbox.accounting.reservation.virtual_cpu_slots, 0);
    assert_eq!(sandbox.accounting.reservation.host_pids, 0);
    assert_eq!(
        sandbox.accounting.reservation.memory_bytes,
        sandbox.spec.memory_bytes
    );
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_eq!(
        deleted.accounting.release,
        ReservationRelease::Legacy(crate::model::LegacyRelease::Deleted)
    );
    assert!(matches!(
        fake.inspect_allocation(
            &context_for_legacy(),
            &Digest::of(b""),
            deadline(),
            &CancellationToken::new()
        )
        .await,
        Ok(AllocationObservation::Unsupported)
    ));
    assert!(matches!(
        fake.fence_absent(
            &context_for_legacy(),
            &Digest::of(b""),
            deadline(),
            &CancellationToken::new()
        )
        .await,
        Err(RuntimeError::Unsupported(_))
    ));
}

fn context_for_legacy() -> CreateContext {
    CreateContext {
        instance_id: Id128::random(),
        allocation_id: Id128::random(),
        sandbox_id: new_id("sb"),
    }
}

#[tokio::test]
async fn an_unexplained_allocation_blocks_admission_and_is_left_alone() {
    let (m, fake) = manager();
    let foreign = Id128::random();
    let id = format!("fc-{foreign}");
    fake.state().fenced.inventory_extra.push(BackendRecord {
        id: id.clone(),
        status: BackendStatus::Busy,
        allocation_id: Some(foreign),
        plan_digest: None,
        generation: 1,
    });
    let reconciled = m.reconcile().await.unwrap();
    assert!(reconciled.admission_blocked);
    assert_eq!(reconciled.unmanaged, vec![id]);
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error}");
    assert_eq!(fake.state().fenced.prepare_calls, 0);
    let health = m.health().await.unwrap();
    assert!(!health.serving);
    assert!(
        health.detail.contains("no row explains"),
        "{}",
        health.detail
    );
    {
        let state = fake.state();
        assert!(state.remove_attempts.is_empty());
        assert!(state.gc_requests.is_empty());
    }
    // A clean inventory clears the block.
    fake.state().fenced.inventory_extra.clear();
    assert!(!m.reconcile().await.unwrap().admission_blocked);
    m.create(CreateRequest::default()).await.unwrap();

    // An Unknown record is never read as stale or absent, even without an allocation.
    fake.state().fenced.inventory_extra.push(BackendRecord {
        id: "mystery".into(),
        status: BackendStatus::Unknown,
        allocation_id: None,
        plan_digest: None,
        generation: 1,
    });
    assert!(m.reconcile().await.unwrap().admission_blocked);
    assert!(fake.state().gc_requests.is_empty());
}

#[tokio::test]
async fn a_row_from_another_instance_quarantines_rather_than_trusting_its_plan() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let mut foreign = sandbox.clone();
    foreign.id = new_id("sb");
    foreign.state = SandboxState::Creating;
    foreign.backend_id = None;
    foreign.accounting.boot_id = None;
    {
        let binding = foreign.accounting.allocation.as_mut().unwrap();
        binding.allocation_id = Id128::random();
        binding.instance_id = Id128::random();
    }
    m.store.insert_sandbox(&foreign).unwrap();
    let reconciled = m.reconcile().await.unwrap();
    assert_eq!(reconciled.quarantined, vec![foreign.id.clone()]);
    assert_eq!(
        m.get(&foreign.id, 0).unwrap().0.state,
        SandboxState::Quarantined
    );
    assert_eq!(m.store.sandbox_resources().unwrap().sandboxes, 2);
    assert_eq!(
        fake.state().fenced.fence_calls,
        0,
        "no fence on a foreign namespace"
    );
}

#[tokio::test]
async fn health_reports_unavailable_accounting_for_a_node_authority_backend() {
    let (m, _fake) = manager();
    m.create(CreateRequest::default()).await.unwrap();
    let health = m.health().await.unwrap();
    assert!(!health.serving);
    assert!(
        health.detail.contains("node accounting"),
        "{}",
        health.detail
    );
    assert_eq!(
        health.node_resources.accounting,
        NodeAccountingStatus::Unavailable
    );
    assert!(!health.capabilities.interruption_preserves_session);
    assert_eq!(health.capabilities.network_modes, vec![Network::None]);

    let fake = FakeRuntime::default();
    let m = Arc::new(Manager::new(
        fake,
        Store::open_in_memory().unwrap(),
        Limits::default(),
    ));
    let health = m.health().await.unwrap();
    assert!(health.serving);
    assert_eq!(
        health.node_resources.accounting,
        NodeAccountingStatus::LocalLegacy
    );
    assert!(health.capabilities.interruption_preserves_session);
}

#[tokio::test]
async fn pruning_history_keeps_every_fence_a_replay_could_need() {
    let (m, fake) = manager_with(Limits {
        retention: Retention {
            sandbox_max_count: 0,
            execution_max_count: 0,
            ..Retention::default()
        },
        ..Limits::default()
    });
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let prepared = prepared_of(&fake, &sandbox).await;
    let context = context_of(&sandbox);
    m.delete(&sandbox.id).await.unwrap();
    assert_eq!(m.prune().unwrap().sandboxes, 1);
    assert!(m.list(true).unwrap().is_empty());
    // API history is gone; the delayed Create still meets the permanent fence.
    let failure = fake
        .create(&context, &prepared, deadline(), &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(failure.absence().is_some());
    assert_eq!(fake.state().fenced.claims_made, 1);
}

#[tokio::test]
async fn fenced_gc_receipts_cover_only_named_stopped_allocations() {
    let (m, fake) = manager();
    let live = m.create(CreateRequest::default()).await.unwrap();
    let stopped = m.create(CreateRequest::default()).await.unwrap();
    let unnamed = m.create(CreateRequest::default()).await.unwrap();
    for sandbox in [&stopped, &unnamed] {
        let allocation = sandbox
            .accounting
            .allocation
            .as_ref()
            .unwrap()
            .allocation_id;
        fake.state()
            .fenced
            .allocations
            .get_mut(&allocation)
            .unwrap()
            .phase = FakePhase::Stopped;
    }
    let ids = [
        live.backend_id.clone().unwrap(),
        stopped.backend_id.clone().unwrap(),
        "fc-00000000000000000000000000000000".to_string(),
    ];
    assert!(
        fake.gc(&[], deadline(), &CancellationToken::new())
            .await
            .unwrap()
            .is_empty()
    );
    let receipts = fake
        .gc(&ids, deadline(), &CancellationToken::new())
        .await
        .unwrap();
    let [AbsenceReceipt::Fenced(receipt)] = receipts.as_slice() else {
        panic!("{receipts:?}");
    };
    assert!(receipt.matches(stopped.accounting.allocation.as_ref().unwrap()));
    let state = fake.state();
    assert_eq!(
        state.fenced.allocations.len(),
        2,
        "live and unnamed allocations remain"
    );
}

#[tokio::test]
async fn a_worker_released_after_a_fence_cannot_resurrect_its_allocation() {
    let fake = FakeRuntime::fenced();
    let prepared_context = context_for_legacy();
    let spec = SandboxSpec {
        image: "alpine".into(),
        memory_bytes: 512 << 20,
        cpu_millis: 1000,
        pids: 128,
        disk_bytes: 1 << 30,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: Default::default(),
    };
    let prepared = fake
        .prepare(
            &prepared_context,
            &spec,
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let gate = FakeGate::default();
    fake.state()
        .fenced
        .phase_gates
        .insert(FakePhase::Preparing, gate.clone());
    let worker = tokio::spawn({
        let (fake, context, prepared) = (fake.clone(), prepared_context.clone(), prepared.clone());
        async move {
            fake.create(&context, &prepared, deadline(), &CancellationToken::new())
                .await
        }
    });
    gate.entered().await;
    let generation_before = fake.state().fenced.node_generation;
    let backend_id = format!("fc-{}", prepared_context.allocation_id);
    let AbsenceReceipt::Fenced(receipt) = fake
        .remove(&backend_id, deadline(), &CancellationToken::new())
        .await
        .unwrap()
    else {
        panic!("a fenced backend returns fenced proof");
    };
    assert!(receipt.helper_generation() > generation_before);
    gate.release();
    assert!(
        worker.await.unwrap().is_err(),
        "the late worker reached READY"
    );
    let state = fake.state();
    assert!(state.fenced.allocations.is_empty());
    assert!(state.sandboxes.is_empty());
    assert_eq!(
        state.fenced.fences[&prepared_context.allocation_id],
        receipt
    );
}

#[tokio::test]
async fn create_rejection_with_unusable_absence_evidence_stays_charged() {
    let (m, fake) = manager();
    fake.state().fenced.rejection = Some(FakeRejection::Collision);
    let sandbox_context = {
        // Commit a fence first, so this token's create replies with the forged copy.
        fake.state().fenced.forge = Some(FakeForgery::Plan);
        m.create(CreateRequest::default()).await.unwrap_err();
        context_of(&row(&m))
    };
    let failed = row(&m);
    assert_eq!(failed.state, SandboxState::Failed);
    assert!(
        failed.is_charged(),
        "a mismatched fence receipt released the row"
    );
    assert_eq!(
        failed.accounting.allocation.as_ref().unwrap().allocation_id,
        sandbox_context.allocation_id
    );
    assert_eq!(charged(&m), 1);
    fake.state().fenced.forge = None;
    m.reconcile().await.unwrap();
    assert_eq!(charged(&m), 0);
    assert_released_by_its_fence(&fake, &row(&m));
}

#[tokio::test]
async fn invalid_exec_claims_fail_cleanup_and_quarantine_end_to_end() {
    use CleanupEvidence as C;
    use SandboxDisposition as D;
    // (command, how the finish arises, claim)
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Finish {
        Completed,
        TimedOut,
        Canceled,
    }
    for (finish, claim) in [
        (Finish::TimedOut, (D::Reusable, C::RuntimeDrained)),
        (Finish::TimedOut, (D::Reusable, C::Unknown)),
        (Finish::TimedOut, (D::Stopped, C::Unknown)),
        (Finish::TimedOut, (D::Quarantined, C::Unknown)),
        (Finish::Canceled, (D::Reusable, C::RuntimeDrained)),
        (Finish::Canceled, (D::Reusable, C::Unknown)),
        (Finish::Canceled, (D::Stopped, C::RuntimeDrained)),
        (Finish::Completed, (D::Reusable, C::Unknown)),
        (Finish::Completed, (D::Reusable, C::NoChildStarted)),
        (Finish::Completed, (D::Stopped, C::Unknown)),
        (Finish::Completed, (D::Quarantined, C::SandboxStopped)),
    ] {
        let case = format!("{finish:?} {claim:?}");
        let (m, fake) = manager();
        let sandbox = m.create(CreateRequest::default()).await.unwrap();
        fake.state().fenced.forge_exec_claim = Some(claim);
        let execution = match finish {
            Finish::Completed => m
                .exec(exec_req(&sandbox.id, &["echo", "kept"], 5000))
                .await
                .unwrap(),
            Finish::TimedOut => m.exec(exec_req(&sandbox.id, &["sleep"], 20)).await.unwrap(),
            Finish::Canceled => {
                let waiter = tokio::spawn({
                    let (m, id) = (m.clone(), sandbox.id.clone());
                    async move { m.exec(exec_req(&id, &["sleep"], 60_000)).await }
                });
                let f = fake.clone();
                wait_until(move || f.state().active_execs == 1).await;
                waiter.abort();
                let _ = waiter.await;
                let id = m.get(&sandbox.id, 1).unwrap().1[0].id.clone();
                let observed = m.clone();
                wait_until(move || {
                    observed.execution(&id).unwrap().state != ExecutionState::Running
                })
                .await;
                m.get(&sandbox.id, 1).unwrap().1.remove(0)
            }
        };
        assert_eq!(execution.state, ExecutionState::Failed, "{case}");
        assert_eq!(execution.exit_code, None, "{case}");
        let diagnostic = execution.runtime_error.as_ref().expect("a typed failure");
        assert_eq!(diagnostic.kind, RuntimeErrorKind::CleanupFailed, "{case}");
        assert_eq!(diagnostic.stage, RuntimeStage::Cleanup, "{case}");
        assert_eq!(execution.sandbox_reusable, Some(false), "{case}");
        assert_eq!(execution.cleanup_evidence, C::Unknown, "{case}");
        if finish == Finish::Completed {
            // Observed status and bytes survive as separate evidence.
            assert_eq!(
                execution.command_status,
                Some(CommandStatus::Exited(0)),
                "{case}"
            );
            assert_eq!(execution.stdout.data, b"kept\n", "{case}");
        }
        let after = row(&m);
        assert_eq!(after.state, SandboxState::Quarantined, "{case}");
        assert!(after.is_charged(), "{case}");
        assert_eq!(charged(&m), 1, "{case}");
        // No successor reaches the backend of that session.
        let calls = fake.state().exec_calls.len();
        let refused = m
            .exec(exec_req(&sandbox.id, &["echo", "next"], 5000))
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::FailedPrecondition(_)), "{case}");
        assert_eq!(fake.state().exec_calls.len(), calls, "{case}");
    }

    // An existing failure keeps its own kind while still quarantining.
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().fenced.forge_exec_claim = Some((D::Reusable, C::RuntimeDrained));
    let failed = m
        .exec(exec_req(&sandbox.id, &["runtime-failure"], 5000))
        .await
        .unwrap();
    assert_eq!(failed.state, ExecutionState::Failed);
    let diagnostic = failed.runtime_error.as_ref().unwrap();
    assert_eq!(diagnostic.kind, RuntimeErrorKind::Io);
    assert_eq!(diagnostic.stage, RuntimeStage::Capture);
    assert_eq!(failed.command_status, Some(CommandStatus::Exited(125)));
    assert_eq!(row(&m).state, SandboxState::Quarantined);

    // Proof that no child started is the only way a clean interruption stays clean.
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().fenced.forge_exec_claim = Some((D::Reusable, C::NoChildStarted));
    let timed_out = m.exec(exec_req(&sandbox.id, &["sleep"], 20)).await.unwrap();
    assert_eq!(timed_out.state, ExecutionState::TimedOut);
    assert_eq!(timed_out.sandbox_reusable, Some(true));
    assert_eq!(row(&m).state, SandboxState::Ready);
}

#[tokio::test]
async fn invalid_ready_generation_or_boot_never_publishes() {
    for forgery in [FakeForgery::StaleGeneration, FakeForgery::EmptyBoot] {
        let (m, fake) = manager();
        // Compensation must use a real receipt so only publication is under test.
        fake.state().fenced.forge = Some(forgery);
        fake.state().fail_remove = true;
        let error = m.create(CreateRequest::default()).await.unwrap_err();
        assert!(
            error.to_string().contains("invalid generation or boot"),
            "{forgery:?}: {error}"
        );
        let failed = row(&m);
        assert_eq!(failed.state, SandboxState::Failed, "{forgery:?}");
        assert_eq!(failed.backend_id, None, "{forgery:?}");
        assert_eq!(failed.accounting.boot_id, None, "{forgery:?}");
        assert_eq!(
            failed.accounting.last_helper_generation,
            Some(0),
            "{forgery:?}"
        );
        assert_eq!(charged(&m), 1, "{forgery:?}");
    }
}

#[tokio::test]
async fn stale_absence_generation_fails_closed_end_to_end() {
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let published = sandbox.accounting.last_helper_generation.unwrap();
    assert!(published > 1, "the forged generation below must be older");
    fake.state().fenced.forge = Some(FakeForgery::StaleGeneration);
    // The helper really fenced, but what arrives is older than READY: unusable.
    let error = m.delete(&sandbox.id).await.unwrap_err();
    assert!(error.to_string().contains("not newer"), "{error}");
    assert_eq!(row(&m).state, SandboxState::Deleting);
    assert!(row(&m).is_charged());
    assert_eq!(charged(&m), 1);
    let before = m.list(true).unwrap();
    // Recovery refuses the same evidence before changing anything.
    let error = m.reconcile().await.unwrap_err();
    assert!(error.to_string().contains("not newer"), "{error}");
    assert_eq!(m.list(true).unwrap(), before);

    // The genuine receipt replays and is newer than READY.
    fake.state().fenced.forge = None;
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_released_by_its_fence(&fake, &deleted);
    assert!(deleted.accounting.last_helper_generation.unwrap() > published);
    assert_eq!(charged(&m), 0);
    // Its replay stays idempotent across restart-style recovery.
    m.reconcile().await.unwrap();
    assert_eq!(row(&m), deleted);
}

#[tokio::test]
async fn reconcile_refuses_a_generation_that_moved_backward() {
    let stale_present = |fake: &FakeRuntime, sandbox: &Sandbox| {
        let binding = sandbox.accounting.allocation.as_ref().unwrap();
        fake.state().fenced.observation_override = Some(AllocationObservation::Present {
            receipt: ReadyReceipt {
                node_id: binding.node_id,
                instance_id: binding.instance_id,
                allocation_id: binding.allocation_id,
                plan_digest: binding.plan_digest,
                helper_generation: 1,
                boot_id: sandbox.accounting.boot_id.clone().unwrap(),
            },
            healthy_idle: true,
            uncertain_execution: false,
        });
    };
    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    stale_present(&fake, &sandbox);
    let before = m.list(true).unwrap();
    assert!(m.reconcile().await.is_err());
    assert_eq!(m.list(true).unwrap(), before);

    let (m, fake) = manager();
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().fenced.observation_override = Some(AllocationObservation::StoppedWithResources {
        helper_generation: 1,
    });
    let before = m.list(true).unwrap();
    assert!(m.reconcile().await.is_err());
    assert_eq!(m.list(true).unwrap(), before);
    assert_eq!(row(&m).state, sandbox.state);
}
