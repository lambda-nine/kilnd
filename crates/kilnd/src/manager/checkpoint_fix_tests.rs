//! Checkpoint milestone C5a-1, fix round 1: regressions for the adversarial review's
//! findings (eight HIGH, one MEDIUM) and their controls. Each test that targets a
//! finding asserts the corrected behaviour, so it failed on the reviewed engine.

use super::*;
use crate::checkpoint::wire::{Activity, ExclusiveOp, OpKind, TrackedArtifact};

/// `main.rs::serve_with`'s startup order without the sweeper task: reconcile, the
/// clock rebase, the request-record rebase (its count), a prune, then what
/// `start_expiry` does before it spawns.
async fn startup_like_main(m: &M) -> (Reconciled, usize) {
    let r = m.reconcile().await.unwrap();
    m.rebase_expiry_clocks().unwrap();
    let rebased = m.rebase_create_requests().unwrap();
    m.prune().unwrap();
    m.rebuild_expiry().unwrap();
    m.start_checkpoints().unwrap();
    (r, rebased)
}

async fn stop(m: M) -> Limits {
    let limits = m.limits.clone();
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    limits
}

fn off(mut limits: Limits) -> Limits {
    limits.checkpoints = None;
    limits
}

/// An ordinary Create refused while allocation is blocked.
async fn create_is_blocked(m: &M) -> bool {
    match m.create_owned(CreateRequest::default(), 2000).await {
        Err(Error::FailedPrecondition(_)) => true,
        Ok(_) => false,
        Err(e) => panic!("{e:?}"),
    }
}

/// Retries an ordinary Create until allocation opens, with no restart.
async fn until_allocation_opens(m: &M, what: &str) -> Sandbox {
    for _ in 0..400 {
        match m.create_owned(CreateRequest::default(), 2000).await {
            Ok(s) => return s,
            Err(Error::FailedPrecondition(_)) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    panic!("allocation stayed blocked: {what}");
}

fn tracked(id: &CheckpointId, generation: u64, activity: Activity) -> TrackedArtifact {
    TrackedArtifact {
        checkpoint: id.clone(),
        generation,
        activity,
    }
}

fn exclusive(kind: OpKind, operation: Id128) -> Activity {
    Activity {
        exclusive: Some(ExclusiveOp { kind, operation }),
        ..Activity::default()
    }
}

/// A fork row and its live pin on `c` (store only: C5a-1 has no fork path).
fn pin(m: &M, s: &Sandbox, c: &Checkpoint) -> HelperDispatch {
    let mut fork = m.store.sandbox(&s.id).unwrap().unwrap();
    fork.id = new_id("sb");
    fork.state = SandboxState::Creating;
    fork.backend_id = None;
    fork.lifecycle = SandboxLifecycle {
        from_checkpoint: Some(crate::model::CheckpointProvenance {
            checkpoint: c.id.clone(),
            content_sha256: c.seal.as_ref().unwrap().content_sha256,
        }),
        ..SandboxLifecycle::default()
    };
    let reader = HelperDispatch {
        operation: Id128::random(),
        helper_epoch: Id128::random(),
        boot_id: Id128::random(),
    };
    let reserved = m
        .store
        .reserve_fork_sandbox(&fork, m.sandbox_budgets(), None, &[], &reader)
        .unwrap();
    assert!(
        matches!(
            reserved,
            crate::store::ReserveFork::Sandbox(ReserveSandbox::Inserted)
        ),
        "{reserved:?}"
    );
    reader
}

// --- HIGH 1: a departed Delete leaves a supervisor ------------------------------------

#[tokio::test]
async fn a_departed_delete_leaves_a_supervisor_that_reaches_absent() {
    for release in [false, true] {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        let r = req(&s);
        let c = m
            .capture_checkpoint(r.clone(), 1000, Some(key("departs", &r)), None)
            .await
            .unwrap();
        let remove_gate = FakeGate::default();
        fake.checkpoints(|g| g.remove_gate = Some(remove_gate.clone()));
        let deleting = {
            let m = Arc::clone(&m);
            let id = c.id.to_string();
            tokio::spawn(async move { m.delete_checkpoint(&id, 1000, release).await })
        };
        remove_gate.entered().await;
        // The caller departs (a deadline or a disconnect drops the handler future).
        deleting.abort();
        assert!(deleting.await.unwrap_err().is_cancelled());
        assert!(
            m.checkpoint
                .retrying
                .lock()
                .unwrap()
                .contains(c.id.as_str()),
            "a supervisor owns the removal once the waiter is gone"
        );
        remove_gate.release();
        until("DELETED without another Delete", || {
            row(&m, c.id.as_str()).state == CheckpointState::Deleted
        })
        .await;
        assert_eq!(charge(&m), (0, 0));
        assert_eq!(calls(&fake, "remove"), 1);
        until("the supervisor ends", || {
            m.checkpoint.retrying.lock().unwrap().is_empty()
        })
        .await;
        // The departed caller's release of its key is done by the supervisor, once
        // DELETED.
        assert_eq!(
            m.store
                .checkpoint_request(1000, "departs")
                .unwrap()
                .is_none(),
            release
        );
        assert_eq!(
            row(&m, c.id.as_str()).request_id_released_at_ms.is_some(),
            release
        );
    }
}

// --- HIGH 2: the feature off still maintains existing checkpoints --------------------

#[tokio::test]
async fn feature_off_still_expires_existing_checkpoints() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = m
        .capture_checkpoint(short(&s, 60, 30), 1000, None, None)
        .await
        .unwrap();
    let limits = off(stop(m).await);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let (r, _) = startup_like_main(&m).await;
    assert!(!r.checkpoints_blocked && !r.admission_blocked, "{r:?}");
    clock.advance(7 * 86_400 * SEC);
    m.expire_checkpoints_due();
    until("lifetime expiry with the feature off", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(charge(&m), (0, 0));
    assert!(m.checkpoint_timer_head().is_none());
    // New captures stay off.
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
}

#[tokio::test]
async fn feature_off_resumes_a_pending_removal_and_create_is_not_blocked() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = capture(&m, &s, 1000).await.unwrap();
    // D1 committed; the removal had not finished when the daemon stopped.
    m.store
        .publish_checkpoint_delete_intent(c.id.as_str(), DeletionReason::Requested)
        .unwrap();
    let limits = off(stop(m).await);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let (r, _) = startup_like_main(&m).await;
    assert!(
        !r.checkpoints_blocked && !r.admission_blocked,
        "a DELETING row the helper accounts for blocks nothing: {r:?}"
    );
    until("the resumed removal", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(charge(&m), (0, 0));
    assert!(
        !create_is_blocked(&m).await,
        "another user's ordinary Create"
    );
}

// --- HIGH 3: capture keys from an earlier boot age out --------------------------------

#[tokio::test]
async fn capture_keys_from_an_earlier_boot_age_out_after_restart() {
    let (_tmp, dir) = state_dir();
    let fake = FakeRuntime::default().with_checkpoints();
    let clock = ManualClock::default();
    let m = on_disk(&dir, &fake, &clock, &test_limits());
    startup_like_main(&m).await;
    let s = source(&m, 1000).await;
    let keyed_and_deleted = |m: M, k: &'static str| {
        let s = s.clone();
        async move {
            let r = req(&s);
            let c = m
                .capture_checkpoint(r.clone(), 1000, Some(key(k, &r)), None)
                .await
                .unwrap();
            let d = m
                .delete_checkpoint(c.id.as_str(), 1000, false)
                .await
                .unwrap();
            assert_eq!(d.state, CheckpointState::Deleted);
            c
        }
    };

    // Control, same boot: a settled row's key ages out after its retention.
    keyed_and_deleted(Arc::clone(&m), "same-boot").await;
    clock.advance(2 * 86_400 * SEC);
    assert_eq!(
        m.prune().unwrap().checkpoint_requests,
        1,
        "same-boot control"
    );
    assert!(
        m.store
            .checkpoint_request(1000, "same-boot")
            .unwrap()
            .is_none()
    );

    // Two anchored in this boot, and one left unanchored (a crash before its anchor).
    keyed_and_deleted(Arc::clone(&m), "seed-1").await;
    keyed_and_deleted(Arc::clone(&m), "seed-2").await;
    let loose = keyed_and_deleted(Arc::clone(&m), "unanchored").await;
    m.store
        .unanchor_checkpoint_request_for_test(loose.id.as_str())
        .unwrap();
    assert_eq!(m.store.checkpoint_usage(1000).unwrap().uid.keys, 3);

    // A reboot: startup gives every record from another boot (or none) a fresh window.
    let limits = stop(m).await;
    fake.state().sandboxes.clear();
    clock.reboot("boot-b", 5_000, 60 * SEC);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let (_, rebased) = startup_like_main(&m).await;
    assert_eq!(
        rebased, 3,
        "the earlier boot's and the unanchored capture keys"
    );
    for k in ["seed-1", "seed-2", "unanchored"] {
        assert!(
            m.store.checkpoint_request(1000, k).unwrap().is_some(),
            "{k} is not pruned early"
        );
    }
    // A second start in the same boot rebases nothing and prunes nothing early.
    let limits = stop(m).await;
    let m = on_disk(&dir, &fake, &clock, &limits);
    let (_, again) = startup_like_main(&m).await;
    assert_eq!(again, 0, "idempotent");
    assert_eq!(m.store.checkpoint_usage(1000).unwrap().uid.keys, 3);
    // Their retention passes in this boot: all three age out.
    clock.advance(2 * 86_400 * SEC);
    assert_eq!(m.prune().unwrap().checkpoint_requests, 3);
    assert_eq!(m.store.checkpoint_usage(1000).unwrap().uid.keys, 0);
    let s2 = source(&m, 1000).await;
    let r = req(&s2);
    m.capture_checkpoint(r.clone(), 1000, Some(key("seed-1", &r)), None)
        .await
        .unwrap();
}

// --- HIGH 4: a keyed retry is answered from its record with the feature off ----------

#[tokio::test]
async fn feature_off_answers_a_keyed_retry_from_its_durable_record() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let r = req(&s);
    let k = key("accepted", &r);
    let c = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    let limits = off(stop(m).await);
    let m = on_disk(&dir, &fake, &clock, &limits);
    startup_like_main(&m).await;
    let again = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    assert_eq!(
        (again.id.clone(), again.state, again.activity_seq),
        (c.id.clone(), CheckpointState::Ready, c.activity_seq)
    );
    // A different request under the key still conflicts.
    let mut other = r.clone();
    other.max_size_bytes = 1 << 20;
    let e = m
        .capture_checkpoint(other.clone(), 1000, Some(key("accepted", &other)), None)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("request_id_conflict"));
    // An unknown key is a new capture, which stays off.
    let e = m
        .capture_checkpoint(r.clone(), 1000, Some(key("never-seen", &r)), None)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
    assert!(
        m.store
            .checkpoint_request(1000, "never-seen")
            .unwrap()
            .is_none()
    );
    assert_eq!(calls(&fake, "capture"), 1);
}

// --- HIGH 5: a transient Inspect fault is unknown, not corrupt -----------------------

#[tokio::test]
async fn transient_inspect_io_keeps_ready_blocks_and_recovers() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = capture(&m, &s, 1000).await.unwrap();
    // A restart while `kiln checkpoint ls` briefly cannot run; the artifact is intact.
    fake.checkpoints(|g| g.inspect_io = true);
    let m = restart(m, &dir, &fake, &clock).await;
    let kept = row(&m, c.id.as_str());
    assert_eq!(kept.state, CheckpointState::Ready, "{:?}", kept.failure);
    assert!(kept.failure.is_none() && kept.is_charged());
    assert_eq!(charge(&m), (1, S));
    assert!(
        create_is_blocked(&m).await,
        "unknown storage blocks allocation"
    );
    assert!(matches!(
        capture(&m, &s, 1000).await,
        Err(Error::FailedPrecondition(_))
    ));
    // The fault clears; the barrier's retry reopens allocation with no restart.
    fake.checkpoints(|g| g.inspect_io = false);
    until_allocation_opens(&m, "the barrier retry never cleared the Inspect fault").await;
    let got = m.get_checkpoint(c.id.as_str(), 1000).unwrap();
    assert_eq!(got.state, CheckpointState::Ready);
    assert_eq!(charge(&m), (1, S));
    capture(&m, &s, 1000).await.unwrap();
}

#[tokio::test]
async fn authoritative_inspect_results_still_quarantine() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let corrupt = capture(&m, &s, 1000).await.unwrap();
    let missing = capture(&m, &s, 1000).await.unwrap();
    fake.checkpoints(|g| {
        g.unreadable.insert(corrupt.id.to_string());
        g.published.remove(missing.id.as_str());
    });
    let m = restart(m, &dir, &fake, &clock).await;
    for c in [&corrupt, &missing] {
        let q = row(&m, c.id.as_str());
        assert_eq!(q.state, CheckpointState::Quarantined);
        assert_eq!(q.failure.unwrap().token, "checkpoint_corrupt");
    }
    assert_eq!(charge(&m), (2, 2 * S));
    assert!(!create_is_blocked(&m).await, "a verdict, not an unknown");
}

// --- HIGH 6: a transient barrier failure clears without a restart --------------------

#[tokio::test]
async fn a_transient_incomplete_inventory_clears_without_restart() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    assert_eq!(charge(&m), (0, 0));
    let limits = stop(m).await;
    // At startup the helper's listing is briefly incomplete.
    fake.checkpoints(|g| g.inventory_incomplete = true);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let (r, _) = startup_like_main(&m).await;
    assert!(r.checkpoints_blocked && r.admission_blocked);
    assert!(create_is_blocked(&m).await);
    // The helper recovers a moment later.
    fake.checkpoints(|g| g.inventory_incomplete = false);
    until_allocation_opens(&m, "no barrier retry after the helper recovered").await;
    assert_eq!(
        capture(&m, &s, 1000).await.unwrap().state,
        CheckpointState::Ready
    );
}

#[tokio::test]
async fn a_persistent_unexplained_artifact_stays_blocked_across_retries() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let limits = stop(m).await;
    fake.checkpoints(|g| g.inventory_extra.push(CheckpointId::random()));
    let m = on_disk(&dir, &fake, &clock, &limits);
    let (r, _) = startup_like_main(&m).await;
    assert!(r.checkpoints_blocked && r.admission_blocked);
    until("three barrier retry passes", || {
        calls(&fake, "inventory") >= 4
    })
    .await;
    assert!(create_is_blocked(&m).await);
    // Explained away (here: gone), the next pass reopens allocation.
    fake.checkpoints(|g| g.inventory_extra.clear());
    until_allocation_opens(&m, "the artifact is gone").await;
}

// --- HIGH 7: shutdown keeps the source gated until the capture is ABSENT -------------

#[tokio::test]
async fn shutdown_keeps_the_source_gated_until_the_capture_is_absent() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let backend = s.backend_id.clone().unwrap();
    let gate = gate_capture(&fake);
    let remove_gate = FakeGate::default();
    fake.checkpoints(|g| g.remove_gate = Some(remove_gate.clone()));
    let capturing = {
        let (m, s) = (Arc::clone(&m), s.clone());
        tokio::spawn(async move { capture(&m, &s, 1000).await })
    };
    gate.entered().await;
    let c = only(&m);
    // A source Delete arrives as the daemon starts shutting down.
    let deleting = {
        let (m, id) = (Arc::clone(&m), s.id.clone());
        tokio::spawn(async move { m.delete(&id).await })
    };
    m.begin_shutdown();
    let draining = {
        let m = Arc::clone(&m);
        tokio::spawn(async move { m.drain_operations().await })
    };
    let e = capturing.await.unwrap().unwrap_err();
    assert!(matches!(e, Error::ShuttingDown), "{e:?}");
    // The capture's storage is being removed; its worker is gone; the source's storage
    // is untouched, and shutdown has not drained.
    tokio::time::timeout(Duration::from_secs(2), remove_gate.entered())
        .await
        .expect("shutdown must remove the capture's storage");
    assert!(fake.checkpoints(|g| !g.workers.contains_key(c.id.as_str())));
    assert!(!fake.state().removed.contains(&backend));
    assert!(fake.state().sandboxes.contains_key(&backend));
    assert!(!draining.is_finished() && !deleting.is_finished());
    remove_gate.release();
    let deleted = deleting.await.unwrap().unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    tokio::time::timeout(Duration::from_secs(2), draining)
        .await
        .expect("drain completes after the cleanup")
        .unwrap();
    // The order in the fake's logs: the checkpoint's removal, then the source's.
    let done = row(&m, c.id.as_str());
    assert_eq!(done.state, CheckpointState::Failed);
    assert_eq!(done.failure.unwrap().token, "checkpoint_io");
    assert_eq!(charge(&m), (0, 0));
    assert_eq!(calls(&fake, "remove"), 1);
    assert!(fake.state().removed.contains(&backend));
    assert!(fake.checkpoints(|g| g.workers.is_empty() && g.staging.is_empty()));
}

// --- HIGH 8: the barrier accounts for every artifact and operation -------------------

#[tokio::test]
async fn failed_capabilities_block_allocation_even_with_an_empty_db() {
    let (m, fake, _) = engine();
    let unknown = CheckpointId::random();
    fake.checkpoints(|g| {
        g.inventory_extra.push(unknown.clone());
        g.unavailable = true;
    });
    let r = m.reconcile().await.unwrap();
    assert!(r.checkpoints_blocked && r.admission_blocked, "{r:?}");
    assert!(create_is_blocked(&m).await);
    // The helper comes back: the retry inventories and finds the unexplained artifact.
    m.start_checkpoints().unwrap();
    fake.checkpoints(|g| g.unavailable = false);
    until("a retry inventory", || calls(&fake, "inventory") >= 2).await;
    assert!(create_is_blocked(&m).await);
    fake.checkpoints(|g| g.inventory_extra.clear());
    until_allocation_opens(&m, "the artifact is gone").await;
}

#[tokio::test]
async fn an_unexplained_tracked_operation_blocks_allocation() {
    let (m, fake, _) = engine();
    let unknown = CheckpointId::random();
    fake.checkpoints(|g| {
        g.inventory_tracked.push(tracked(
            &unknown,
            1,
            exclusive(OpKind::Capture, Id128::random()),
        ))
    });
    let r = m.reconcile().await.unwrap();
    assert!(r.checkpoints_blocked && r.admission_blocked, "{r:?}");
    assert!(create_is_blocked(&m).await);
}

/// Controls: activity the rows explain blocks nothing.
#[tokio::test]
async fn tracked_activity_that_matches_its_row_does_not_block() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    // An interrupted capture's own operation.
    let capturing = c1_only(&m, &fake, &s).await;
    // A removal and its tombstone on a DELETING row.
    let deleting = capture(&m, &s, 1000).await.unwrap();
    m.store
        .publish_checkpoint_delete_intent(deleting.id.as_str(), DeletionReason::Requested)
        .unwrap();
    // A tombstone left on a DELETED row.
    let deleted = capture(&m, &s, 1000).await.unwrap();
    m.delete_checkpoint(deleted.id.as_str(), 1000, false)
        .await
        .unwrap();
    // A reader under a live pin of a READY row.
    let ready = capture(&m, &s, 1000).await.unwrap();
    let reader = pin(&m, &s, &ready);
    let cases = [
        tracked(
            &capturing.id,
            1,
            exclusive(OpKind::Capture, capturing.capture.operation),
        ),
        tracked(
            &deleting.id,
            1,
            Activity {
                tombstone: Some(Id128::random()),
                ..exclusive(OpKind::Remove, Id128::random())
            },
        ),
        tracked(
            &deleted.id,
            1,
            Activity {
                tombstone: Some(Id128::random()),
                ..Activity::default()
            },
        ),
        tracked(
            &ready.id,
            1,
            Activity {
                readers: vec![reader.operation],
                ..Activity::default()
            },
        ),
    ];
    for case in cases {
        fake.checkpoints(|g| g.inventory_tracked = vec![case.clone()]);
        assert!(!m.reconcile_checkpoints().await.unwrap(), "{case:?}");
    }
}

#[tokio::test]
async fn tracked_activity_that_does_not_match_its_row_blocks() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let capturing = c1_only(&m, &fake, &s).await;
    let ready = capture(&m, &s, 1000).await.unwrap();
    let cases = [
        // Another generation under a READY row's name.
        tracked(&ready.id, 2, Activity::default()),
        // A capture under another operation than the row's.
        tracked(
            &capturing.id,
            1,
            exclusive(OpKind::Capture, Id128::random()),
        ),
        // A capture or removal of a READY row.
        tracked(
            &ready.id,
            1,
            exclusive(OpKind::Capture, ready.capture.operation),
        ),
        tracked(&ready.id, 1, exclusive(OpKind::Remove, Id128::random())),
        // A tombstone on a READY row.
        tracked(
            &ready.id,
            1,
            Activity {
                tombstone: Some(Id128::random()),
                ..Activity::default()
            },
        ),
        // A reader no live pin names.
        tracked(
            &ready.id,
            1,
            Activity {
                readers: vec![Id128::random()],
                ..Activity::default()
            },
        ),
    ];
    for case in cases {
        fake.checkpoints(|g| g.inventory_tracked = vec![case.clone()]);
        assert!(m.reconcile_checkpoints().await.unwrap(), "{case:?}");
    }
}

// --- MEDIUM 1: a waiter departing before C1 allocates nothing -------------------------

#[tokio::test]
async fn a_waiter_departing_before_c1_allocates_nothing() {
    for keyed in [false, true] {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        let gate = FakeGate::default();
        fake.checkpoints(|g| g.source_gate = Some(gate.clone()));
        let waiter = tokio::spawn({
            let m = Arc::clone(&m);
            let r = req(&s);
            async move {
                let k = keyed.then(|| key("departed-c0", &r));
                m.capture_checkpoint(r, 1000, k, None).await
            }
        });
        gate.entered().await;
        assert_eq!(charge(&m), (0, 0));
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        gate.release();
        until("the supervisor stops", || !m.slot(&s.id).capturing()).await;
        assert!(
            m.store
                .checkpoint_page(None, None, None, 10)
                .unwrap()
                .rows
                .is_empty(),
            "keyed={keyed}: no row"
        );
        assert_eq!(charge(&m), (0, 0));
        assert!(
            m.store
                .sandbox(&s.id)
                .unwrap()
                .unwrap()
                .lifecycle
                .image_identity
                .is_none()
        );
        assert!(
            m.store
                .checkpoint_request(1000, "departed-c0")
                .unwrap()
                .is_none()
        );
        assert!(m.checkpoint.keys.lock().unwrap().is_empty());
        assert_eq!(calls(&fake, "capture"), 0);
        // Nothing is left held: the worker permit and the source gate are free.
        assert_eq!(
            capture(&m, &s, 1000).await.unwrap().state,
            CheckpointState::Ready
        );
    }
}

#[tokio::test]
async fn a_waiter_departing_after_c1_does_not_cancel() {
    for keyed in [false, true] {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        let gate = gate_capture(&fake);
        let waiter = tokio::spawn({
            let m = Arc::clone(&m);
            let r = req(&s);
            async move {
                let k = keyed.then(|| key("departed-c1", &r));
                m.capture_checkpoint(r, 1000, k, None).await
            }
        });
        gate.entered().await;
        waiter.abort();
        let _ = waiter.await;
        gate.release();
        until("READY without its waiter", || {
            only(&m).state == CheckpointState::Ready
        })
        .await;
        assert_eq!(charge(&m), (1, S));
        assert_eq!(
            m.store
                .checkpoint_request(1000, "departed-c1")
                .unwrap()
                .is_some(),
            keyed
        );
    }
}

#[tokio::test]
async fn a_source_delete_at_c0_prevents_allocation() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.source_gate = Some(gate.clone()));
    let waiter = tokio::spawn({
        let m = Arc::clone(&m);
        let s = s.clone();
        async move { capture(&m, &s, 1000).await }
    });
    gate.entered().await;
    m.slot(&s.id).cancel_capture(); // The token a published source Delete cancels.
    gate.release();
    let err = waiter.await.unwrap().unwrap_err();
    assert_eq!(reason(&err), Some("checkpoint_not_ready"));
    assert_eq!(charge(&m), (0, 0));
    assert!(
        m.store
            .checkpoint_page(None, None, None, 10)
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(!m.slot(&s.id).capturing());
}

// --- Off by default ---------------------------------------------------------------------

#[tokio::test]
async fn feature_off_with_no_rows_makes_no_store_query_on_request_paths() {
    let (m, fake, _) = engine_with(
        FakeRuntime::default().with_checkpoints(),
        off(test_limits()),
    );
    let queries = || m.checkpoint.store_calls.swap(0, Ordering::Relaxed);
    queries();
    let (r, rebased) = startup_like_main(&m).await;
    assert!(!r.checkpoints_blocked && !r.admission_blocked);
    assert_eq!(rebased, 0);
    assert!(queries() <= 1, "startup: at most the existence check");
    let s = source(&m, 1000).await;
    queries();
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
    let r = req(&s);
    let e = m
        .capture_checkpoint(r.clone(), 1000, Some(key("off", &r)), None)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
    m.exec(exec_req(&s.id, &["echo"])).await.unwrap();
    m.create_owned(CreateRequest::default(), 1001)
        .await
        .unwrap();
    m.expire_checkpoints_due();
    assert_eq!(queries(), 0, "no checkpoint store query on a request path");
    assert!(
        fake.checkpoints(|g| g.calls.is_empty()),
        "the helper is never called"
    );
    assert!(m.checkpoint_timer_head().is_none());
}
