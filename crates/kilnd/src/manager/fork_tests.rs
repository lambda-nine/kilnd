//! Checkpoint milestone C5a-2: create from a checkpoint (fork) end to end against the
//! fake backend's scripted helper group, with the real schema 16 store. The restore,
//! ownership, compatibility refusals, the Firecracker refusal, the feature off, keys
//! (digest version 2), quotas and workers, every helper outcome, races and
//! cancellation, the pass's fork rule, ownership loss and crash recovery.

use super::*;
use crate::checkpoint::wire::RestoreReply;
use crate::runtime::fake::FakeRestore;
use crate::store::CheckpointPin;

/// A fork of `c` with the source's (default) spec.
fn fork_req(c: &Checkpoint) -> CreateRequest {
    CreateRequest {
        from_checkpoint: Some(c.id.to_string()),
        ..CreateRequest::default()
    }
}

async fn fork(m: &M, c: &Checkpoint, uid: u32) -> Result<Sandbox> {
    m.create_owned(fork_req(c), uid).await
}

/// A ready checkpoint of a fresh source owned by `uid`.
async fn ready(m: &M, uid: u32) -> (Sandbox, Checkpoint) {
    let s = source(m, uid).await;
    let c = capture(m, &s, uid).await.unwrap();
    assert_eq!(c.state, CheckpointState::Ready);
    (s, c)
}

fn pin_of(m: &M, sandbox: &str) -> Option<CheckpointPin> {
    m.store.checkpoint_pin(sandbox).unwrap()
}

fn live_pins(m: &M, c: &Checkpoint) -> usize {
    m.store
        .checkpoint_pins(c.id.as_str())
        .unwrap()
        .iter()
        .filter(|p| p.released_at_ms.is_none())
        .count()
}

fn rows(m: &M) -> usize {
    m.store.sandboxes(true).unwrap().len()
}

fn gate_restore(fake: &FakeRuntime) -> FakeGate {
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.restore_gate = Some(gate.clone()));
    gate
}

fn script(fake: &FakeRuntime, outcomes: &[FakeRestore]) {
    fake.checkpoints(|g| g.restores.extend(outcomes.iter().cloned()));
}

/// The fork rows of `c`, newest last.
fn forks_of(m: &M, c: &Checkpoint) -> Vec<Sandbox> {
    let mut v: Vec<Sandbox> = m
        .store
        .sandboxes(true)
        .unwrap()
        .into_iter()
        .filter(|s| {
            s.lifecycle
                .from_checkpoint
                .as_ref()
                .is_some_and(|p| p.checkpoint == c.id)
        })
        .collect();
    v.sort_by_key(|s| s.created_at_ms);
    v
}

fn spawn_fork(m: &M, c: &Checkpoint, uid: u32) -> tokio::task::JoinHandle<Result<Sandbox>> {
    let m = Arc::clone(m);
    let r = fork_req(c);
    tokio::spawn(async move { m.create_owned(r, uid).await })
}

fn restores(m: &M) -> usize {
    m.live_restores().len()
}

// --- The restore -----------------------------------------------------------------------

#[tokio::test]
async fn a_fork_is_restored_before_ready_with_its_provenance_identity_and_pin() {
    let (m, fake, _) = engine();
    let (s, c) = ready(&m, 1000).await;
    let disk_before = m.store_resources_for_test().disk_bytes;
    let activity = row(&m, c.id.as_str()).activity_seq;
    let f = fork(&m, &c, 1000).await.unwrap();
    assert_eq!(f.state, SandboxState::Ready);
    assert_eq!(f.owner_uid, 1000);
    let backend = f.backend_id.clone().unwrap();
    assert!(fake.state().sandboxes.contains_key(&backend));
    // Immutable provenance and the checkpoint's image identity.
    let p = f.lifecycle.from_checkpoint.clone().unwrap();
    assert_eq!(p.checkpoint, c.id);
    assert_eq!(p.content_sha256, c.seal.as_ref().unwrap().content_sha256);
    let identity = f.lifecycle.image_identity.unwrap();
    assert_eq!(identity.content_sha256, c.image_content_sha256);
    assert_eq!(identity.checkpoint_format_version, c.format_version);
    // One restore, through the helper, and no Runtime::create for it.
    assert_eq!(calls(&fake, "restore"), 1);
    assert_eq!(
        fake.state().created.len(),
        2,
        "source create plus the restore"
    );
    // Its pin was released by its reader's COMPLETE, and the activity was recorded.
    let pin = pin_of(&m, &f.id).unwrap();
    assert_eq!(pin.released_by.as_deref(), Some("complete"));
    assert!(row(&m, c.id.as_str()).activity_seq > activity);
    assert_eq!(restores(&m), 0);
    // The fork reserves its full disk on top of the checkpoint's S.
    assert_eq!(
        m.store_resources_for_test().disk_bytes,
        disk_before + f.spec.disk_bytes
    );
    // A fork can be captured in turn, without a `source` call (identity recorded).
    let sources = calls(&fake, "source");
    let again = capture(&m, &f, 1000).await.unwrap();
    assert_eq!(again.state, CheckpointState::Ready);
    assert_eq!(calls(&fake, "source"), sources);
    // Independence: deleting the source, then the checkpoint, leaves the fork.
    m.delete(&s.id).await.unwrap();
    m.delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(m.load(&f.id).unwrap().state, SandboxState::Ready);
    let out = m.exec(exec_req(&f.id, &["echo", "fork"])).await.unwrap();
    assert_eq!(out.exit_code, Some(0));
}

#[tokio::test]
async fn a_foreign_fork_is_not_found_and_root_follows_the_design() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = (rows(&m), m.store_resources_for_test());
    // Another user: NotFound, exactly as a missing ID, with nothing reserved or called.
    let foreign = fork(&m, &c, 2000).await.unwrap_err();
    let missing = m
        .create_owned(
            CreateRequest {
                from_checkpoint: Some(CheckpointId::random().to_string()),
                ..CreateRequest::default()
            },
            2000,
        )
        .await
        .unwrap_err();
    for e in [&foreign, &missing] {
        assert!(matches!(e, Error::NotFound(_)), "{e:?}");
    }
    let malformed = m
        .create_owned(
            CreateRequest {
                from_checkpoint: Some("../cp".into()),
                ..CreateRequest::default()
            },
            2000,
        )
        .await
        .unwrap_err();
    assert!(matches!(malformed, Error::NotFound(_)), "{malformed:?}");
    assert_eq!((rows(&m), m.store_resources_for_test()), before);
    assert_eq!(calls(&fake, "restore"), 0);
    // Root may fork anyone's checkpoint into a root-owned sandbox (design 5.2).
    let r = fork(&m, &c, 0).await.unwrap();
    assert_eq!(r.owner_uid, 0);
    // The owner's own fork.
    assert_eq!(fork(&m, &c, 1000).await.unwrap().owner_uid, 1000);
}

#[tokio::test]
async fn compatibility_refusals_allocate_nothing() {
    let (m, fake, clock) = engine();
    let (_, c) = ready(&m, 1000).await;
    let seal = c.seal.clone().unwrap();
    let cases: Vec<(CreateRequest, &str)> = vec![
        (
            CreateRequest {
                image: "other".into(),
                ..fork_req(&c)
            },
            "checkpoint_spec_mismatch",
        ),
        (
            CreateRequest {
                read_only_root: true,
                writable_paths: vec!["/workspace".into()],
                ..fork_req(&c)
            },
            "checkpoint_spec_mismatch",
        ),
        (
            CreateRequest {
                disk_bytes: seal.charge_bytes - 1,
                ..fork_req(&c)
            },
            "checkpoint_disk_too_small",
        ),
    ];
    let before = (rows(&m), m.store_resources_for_test());
    for (r, token) in cases {
        let e = m.create_owned(r, 1000).await.unwrap_err();
        assert_eq!(reason(&e), Some(token), "{e:?}");
    }
    // Disk exactly S is enough.
    let exact = m
        .create_owned(
            CreateRequest {
                disk_bytes: seal.charge_bytes,
                ..fork_req(&c)
            },
            1000,
        )
        .await
        .unwrap();
    m.delete(&exact.id).await.unwrap();
    let before_restores = calls(&fake, "restore");
    // Quarantined: corrupt. Not ready: DELETING. Expired: becomes DELETING first.
    let (_, q) = ready(&m, 1000).await;
    fake.checkpoints(|g| {
        g.unreadable.insert(q.id.to_string());
    });
    m.reconcile_checkpoints().await.unwrap();
    fake.checkpoints(|g| g.unreadable.clear());
    assert!(!m.reconcile_checkpoints().await.unwrap());
    assert!(!m.set_checkpoint_barrier(false).unwrap());
    assert_eq!(row(&m, q.id.as_str()).state, CheckpointState::Quarantined);
    let e = fork(&m, &q, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_corrupt"), "{e:?}");
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.remove_gate = Some(gate.clone()));
    let deleting = {
        let m = Arc::clone(&m);
        let id = c.id.to_string();
        tokio::spawn(async move { m.delete_checkpoint(&id, 1000, false).await })
    };
    gate.entered().await;
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"), "{e:?}");
    gate.release();
    deleting.await.unwrap().unwrap();
    let (_, x) = ready(&m, 1000).await;
    clock.advance(DEFAULT_CHECKPOINT_LIFETIME_MS as i64 + SEC);
    let e = fork(&m, &x, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_expired"), "{e:?}");
    until("the expired checkpoint's removal", || {
        row(&m, x.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(calls(&fake, "restore"), before_restores);
    let after = m.store.sandboxes(true).unwrap();
    assert_eq!(
        after
            .iter()
            .filter(|s| s.lifecycle.from_checkpoint.is_some())
            .count(),
        1,
        "only the exact-disk fork was ever reserved"
    );
    let _ = before;
}

#[tokio::test]
async fn firecracker_refuses_a_fork_before_prepare_and_any_effect() {
    // A kiln node accepts a keyed fork; then the backend becomes an allocation-token
    // one (with a checkpoint group scripted anyway).
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let r = fork_req(&c);
    let pb = pb_of(&r);
    let k = CreateKey {
        request_id: "fc-fork".into(),
        sha256: crate::idempotency::create_digest(&pb, r.from_checkpoint.as_deref()),
    };
    let accepted = m
        .create_keyed(Ok(r.clone()), 1000, k.clone(), None)
        .await
        .unwrap();
    {
        let mut st = fake.state();
        st.mode = crate::runtime::fake::FakeEvidenceMode::Fenced;
        st.fenced.node_id = Some(Id128::random());
    }
    assert!(!m.runtime.checkpoint_backend());
    let before = {
        let st = fake.state();
        (
            st.fenced.claims_made,
            st.fenced.issued,
            st.fenced.prepare_calls,
            st.fenced.allocations.len(),
        )
    };
    let resources = m.store_resources_for_test();
    let rows_before = rows(&m);
    let helper_calls = fake.checkpoints(|g| g.calls.len());
    let counts = m.store.create_request_counts(1000).unwrap();
    // An already accepted keyed fork is answered first, as usual (M2).
    let again = m.create_keyed(Ok(r.clone()), 1000, k, None).await.unwrap();
    assert_eq!(again.id, accepted.id);
    // A new fork, keyed or not, is refused UNIMPLEMENTED before prepare.
    for keyed in [false, true] {
        let e = match keyed {
            false => m.create_owned(r.clone(), 1000).await.unwrap_err(),
            true => m
                .create_keyed(
                    Ok(r.clone()),
                    1000,
                    CreateKey {
                        request_id: "fc-new".into(),
                        sha256: crate::idempotency::create_digest(
                            &pb,
                            r.from_checkpoint.as_deref(),
                        ),
                    },
                    None,
                )
                .await
                .unwrap_err(),
        };
        assert_eq!(
            reason(&e),
            Some("backend_unsupported:workspace_checkpoint"),
            "{e:?}"
        );
        assert!(matches!(e, Error::Refused(RefusalCode::Unimplemented, _)));
    }
    let after = {
        let st = fake.state();
        (
            st.fenced.claims_made,
            st.fenced.issued,
            st.fenced.prepare_calls,
            st.fenced.allocations.len(),
        )
    };
    assert_eq!(after, before, "no token, claim, prepare or allocation");
    assert_eq!(m.store_resources_for_test(), resources);
    assert_eq!(rows(&m), rows_before);
    assert_eq!(
        fake.checkpoints(|g| g.calls.len()),
        helper_calls,
        "no helper call"
    );
    let now = m.store.create_request_counts(1000).unwrap();
    assert_eq!(
        (now.uid, now.node),
        (counts.uid, counts.node),
        "no request record"
    );
    assert_eq!(live_pins(&m, &c), 0);
}

#[tokio::test]
async fn feature_off_refuses_a_fork_without_a_store_query_and_create_is_unchanged() {
    let limits = Limits {
        checkpoints: None,
        ..test_limits()
    };
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    m.reconcile().await.unwrap();
    let queries = m.checkpoint.store_calls.load(Ordering::Relaxed);
    let s = m
        .create_owned(CreateRequest::default(), 1000)
        .await
        .unwrap();
    assert_eq!(s.state, SandboxState::Ready);
    assert!(s.lifecycle.from_checkpoint.is_none() && s.lifecycle.image_identity.is_none());
    let e = m
        .create_owned(
            CreateRequest {
                from_checkpoint: Some(CheckpointId::random().to_string()),
                ..CreateRequest::default()
            },
            1000,
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
    // An empty `from_checkpoint` is the legacy create.
    let empty = m
        .create_owned(
            CreateRequest {
                from_checkpoint: Some(String::new()),
                ..CreateRequest::default()
            },
            1000,
        )
        .await
        .unwrap();
    assert!(empty.lifecycle.from_checkpoint.is_none());
    assert_eq!(
        m.checkpoint.store_calls.load(Ordering::Relaxed),
        queries,
        "no checkpoint store query on a request path"
    );
    assert!(fake.checkpoints(|g| g.calls.is_empty()));
    assert_eq!(fake.state().created.len(), 2);
}

// --- Keys -------------------------------------------------------------------------------

/// The proto request `r` stands for (no proto field for `from_checkpoint` yet).
fn pb_of(r: &CreateRequest) -> kilnd_api::v1::CreateSandboxRequest {
    kilnd_api::v1::CreateSandboxRequest {
        spec: Some(kilnd_api::v1::SandboxSpec {
            image: r.image.clone(),
            writable_paths: r.writable_paths.clone(),
            read_only_root: r.read_only_root,
            limits: Some(kilnd_api::v1::ResourceLimits {
                disk_bytes: r.disk_bytes,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn fork_key(id: &str, r: &CreateRequest) -> CreateKey {
    CreateKey {
        request_id: id.into(),
        sha256: crate::idempotency::create_digest(&pb_of(r), r.from_checkpoint.as_deref()),
    }
}

#[tokio::test]
async fn fork_keys_return_their_row_conflict_and_release_only_once_deleted() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let r = fork_req(&c);
    let k = fork_key("fork-1", &r);
    // Version 2 is not version 1 of the same spec.
    assert_ne!(k.sha256, crate::idempotency::request_digest(&pb_of(&r)));
    let first = m
        .create_keyed(Ok(r.clone()), 1000, k.clone(), None)
        .await
        .unwrap();
    assert_eq!(first.state, SandboxState::Ready);
    // A retry returns the same row, with no second restore or row.
    let rows_now = rows(&m);
    let again = m
        .create_keyed(Ok(r.clone()), 1000, k.clone(), None)
        .await
        .unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(calls(&fake, "restore"), 1);
    assert_eq!(rows(&m), rows_now);
    // Another checkpoint, or the legacy digest of the same spec, under the key conflicts.
    let (_, c2) = ready(&m, 1000).await;
    for sha256 in [
        fork_key("fork-1", &fork_req(&c2)).sha256,
        crate::idempotency::request_digest(&pb_of(&r)),
    ] {
        let e = m
            .create_keyed(
                Ok(r.clone()),
                1000,
                CreateKey {
                    request_id: "fork-1".into(),
                    sha256,
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(reason(&e), Some("request_id_conflict"), "{e:?}");
    }
    // The checkpoint deleted: a retry still returns the original fork.
    m.delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    let after = m
        .create_keyed(Ok(r.clone()), 1000, k.clone(), None)
        .await
        .unwrap();
    assert_eq!(after.id, first.id);
    // ...but a new key needs a live checkpoint.
    let e = m
        .create_keyed(Ok(r.clone()), 1000, fork_key("fork-2", &r), None)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"), "{e:?}");
    // The key is released only once the fork is DELETED.
    let deleted = m.delete_releasing(&first.id, true).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert!(deleted.lifecycle.request_id_released_at_ms.is_some());
    assert!(m.store.create_request(1000, "fork-1").unwrap().is_none());
    // A failed keyed fork is the settled FAILED row for the original and every retry.
    let (_, c3) = ready(&m, 1000).await;
    script(&fake, &[FakeRestore::NotCreated(Reason::ImageUnavailable)]);
    let r3 = fork_req(&c3);
    let k3 = fork_key("fork-3", &r3);
    let failed = m
        .create_keyed(Ok(r3.clone()), 1000, k3.clone(), None)
        .await
        .unwrap();
    assert_eq!(failed.state, SandboxState::Failed);
    let retried = m.create_keyed(Ok(r3), 1000, k3, None).await.unwrap();
    assert_eq!(retried.id, failed.id);
}

// --- Quotas and workers -------------------------------------------------------------------

#[tokio::test]
async fn concurrent_captures_and_forks_never_overspend_the_shared_disk() {
    const X: u64 = 256 << 20;
    let source_disk = X;
    // Room for exactly three X-byte reservations beside the source and its checkpoint
    // (its capture's R = X fits while it runs, and shrinks to S).
    let limits = Limits {
        max_node_disk_bytes: source_disk + S + 3 * X,
        checkpoints: Some(CheckpointLimits {
            max_workers: 8,
            max_workers_per_uid: 8,
            ..ckpt_limits()
        }),
        ..test_limits()
    };
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    let s = m
        .create_owned(
            CreateRequest {
                disk_bytes: X,
                ..CreateRequest::default()
            },
            1000,
        )
        .await
        .unwrap();
    let c = capture(&m, &s, 1000).await.unwrap();
    let base = m.store_resources_for_test().disk_bytes;
    assert_eq!(base, source_disk + S);
    let budget = m.limits.max_node_disk_bytes;
    // Five forks of X and a capture of R = X race for three X of room.
    let gate = gate_restore(&fake);
    let mut forks = Vec::new();
    for _ in 0..5 {
        let r = CreateRequest {
            disk_bytes: X,
            ..fork_req(&c)
        };
        let m = Arc::clone(&m);
        forks.push(tokio::spawn(async move { m.create_owned(r, 1000).await }));
    }
    let capture = {
        let m = Arc::clone(&m);
        let r = CaptureRequest {
            max_size_bytes: X,
            ..req(&s)
        };
        tokio::spawn(async move { m.capture_checkpoint(r, 1000, None, None).await })
    };
    gate.entered().await;
    assert!(m.store_resources_for_test().disk_bytes <= budget);
    gate.release();
    let mut admitted = Vec::new();
    for t in forks {
        match t.await.unwrap() {
            Ok(f) => {
                assert_eq!(f.state, SandboxState::Ready);
                admitted.push(f);
            }
            Err(Error::ResourceExhausted(_)) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    let captured = match capture.await.unwrap() {
        Ok(c) => Some(c),
        Err(e) => {
            assert_eq!(reason(&e), Some("checkpoint_quota"), "{e:?}");
            None
        }
    };
    let n = admitted.len() as u64 + u64::from(captured.is_some());
    assert_eq!(n, 3, "exactly three of six fit");
    let sealed = captured
        .as_ref()
        .map_or(0, |c| c.seal.as_ref().unwrap().charge_bytes);
    let total = m.store_resources_for_test().disk_bytes;
    assert_eq!(total, base + admitted.len() as u64 * X + sealed);
    assert!(total <= budget);
    // The boundary: free one fork's X, then X + 1 is refused and X admitted.
    let freed = admitted.pop().unwrap();
    m.delete(&freed.id).await.unwrap();
    let room = budget - m.store_resources_for_test().disk_bytes;
    assert!(room >= X);
    let e = m
        .create_owned(
            CreateRequest {
                disk_bytes: room + 1,
                ..fork_req(&c)
            },
            1000,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ResourceExhausted(_)), "{e:?}");
    let f = m
        .create_owned(
            CreateRequest {
                disk_bytes: room,
                ..fork_req(&c)
            },
            1000,
        )
        .await
        .unwrap();
    assert_eq!(f.state, SandboxState::Ready);
    assert_eq!(m.store_resources_for_test().disk_bytes, budget);
    // A capture now finds no room either, and every pin was released exactly once.
    let e = m
        .capture_checkpoint(
            CaptureRequest {
                max_size_bytes: MIN_LIMIT_BYTES,
                ..req(&s)
            },
            1000,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_quota"), "{e:?}");
    assert_eq!(live_pins(&m, &c), 0);
    assert!(
        m.store
            .checkpoint_pins(c.id.as_str())
            .unwrap()
            .iter()
            .all(|p| p.released_by.as_deref() == Some("complete"))
    );
}

#[tokio::test]
async fn restore_workers_are_shared_with_captures_and_refuse_at_once() {
    let (m, fake, _) = engine();
    let (s, c) = ready(&m, 1000).await;
    let gate = gate_restore(&fake);
    let first = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    // The same uid's second fork, or a capture, has no worker (1 per uid).
    let before = (rows(&m), m.store_resources_for_test());
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_workers"), "{e:?}");
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_workers"), "{e:?}");
    assert_eq!((rows(&m), m.store_resources_for_test()), before);
    // Root's fork takes the node's second worker.
    let gate2 = gate_restore(&fake);
    let second = spawn_fork(&m, &c, 0);
    gate2.entered().await;
    let (_, other) = ready_while_busy(&m).await;
    assert!(other.is_err(), "the node's two workers are busy");
    gate.release();
    gate2.release();
    assert_eq!(first.await.unwrap().unwrap().state, SandboxState::Ready);
    assert_eq!(second.await.unwrap().unwrap().state, SandboxState::Ready);
    assert_eq!(live_pins(&m, &c), 0);
    // Workers are returned: a fork of the same uid now runs.
    assert_eq!(fork(&m, &c, 1000).await.unwrap().state, SandboxState::Ready);
}

/// A third uid's capture while two workers are busy.
async fn ready_while_busy(m: &M) -> (Sandbox, Result<Checkpoint>) {
    let s = source(m, 3000).await;
    let c = capture(m, &s, 3000).await;
    (s, c)
}

// --- Helper outcomes ---------------------------------------------------------------------

#[tokio::test]
async fn not_created_fails_definitely_and_releases_the_pin() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = m.store_resources_for_test();
    script(&fake, &[FakeRestore::NotCreated(Reason::ImageUnavailable)]);
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_image_unavailable"), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    assert!(
        f.failure_reason
            .as_deref()
            .is_some_and(|failure| failure.starts_with("checkpoint_image_unavailable:")),
        "the durable failure lost its typed reason token: {:?}",
        f.failure_reason
    );
    assert_eq!(f.create_certainty, CreateCertainty::DefinitelyNotCreated);
    assert_eq!(m.store_resources_for_test(), before, "reservation released");
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("not_started")
    );
    assert_eq!(restores(&m), 0);
}

/// Design 7.3: every stored fork failure (NotCreated, a typed refusal, ambiguous)
/// carries the returned error's token, so a keyed retry's FAILED row is still typed.
#[tokio::test]
async fn stored_fork_failures_keep_the_returned_token() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let cases = [
        (
            "nc",
            FakeRestore::NotCreated(Reason::ImageUnavailable),
            "checkpoint_image_unavailable",
        ),
        (
            "refused",
            FakeRestore::Refuse(CheckpointErrorKind::Workers),
            "checkpoint_workers",
        ),
        (
            "ambiguous",
            FakeRestore::Ambiguous(Reason::Io),
            "checkpoint_io",
        ),
    ];
    for (key, outcome, token) in cases {
        script(&fake, &[outcome]);
        let r = fork_req(&c);
        let k = fork_key(key, &r);
        let first = m.create_keyed(Ok(r.clone()), 1000, k.clone(), None).await;
        let stored = match first {
            Ok(row) => row,
            Err(e) => {
                assert_eq!(reason(&e), Some(token), "{e:?}");
                m.create_keyed(Ok(r.clone()), 1000, k.clone(), None)
                    .await
                    .unwrap()
            }
        };
        let retried = m.create_keyed(Ok(r), 1000, k, None).await.unwrap();
        assert_eq!(retried.id, stored.id);
        assert_eq!(retried.state, SandboxState::Failed);
        let failure = retried.failure_reason.unwrap_or_default();
        assert!(
            failure.starts_with(&format!("{token}: ")),
            "{key}: stored {failure:?}"
        );
    }
}

/// Restore-proven corruption quarantines the checkpoint at once (charge kept): no new
/// fork is admitted or pinned, and the owner's Delete still reaches ABSENT.
#[tokio::test]
async fn restore_detected_corruption_quarantines_the_checkpoint() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = charge(&m);
    script(&fake, &[FakeRestore::NotCreated(Reason::Corrupt)]);

    let error = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&error), Some("checkpoint_corrupt"), "{error:?}");
    let checkpoint = row(&m, c.id.as_str());
    assert_eq!(
        checkpoint.state,
        CheckpointState::Quarantined,
        "restore proved corrupt content but the checkpoint remained usable: {checkpoint:?}"
    );
    assert_eq!(
        checkpoint.failure.as_ref().map(|f| f.token.as_str()),
        Some("checkpoint_corrupt")
    );
    assert_eq!(charge(&m), before, "quarantine must retain the charge");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.create_certainty, CreateCertainty::DefinitelyNotCreated);
    assert!(
        f.failure_reason
            .unwrap()
            .starts_with("checkpoint_corrupt: ")
    );
    // No new fork: refused before anything is reserved or pinned.
    let pins = m.store.checkpoint_pins(c.id.as_str()).unwrap().len();
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_corrupt"), "{e:?}");
    assert_eq!(m.store.checkpoint_pins(c.id.as_str()).unwrap().len(), pins);
    assert_eq!(calls(&fake, "restore"), 1);
    // The owner's Delete reaches ABSENT and releases the charge.
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(charge(&m), (0, 0));
    assert!(!m.allocation_blocked());
}

#[tokio::test]
async fn an_ambiguous_restore_stays_charged_and_its_pin_waits_for_absent() {
    let (m, fake, clock) = engine();
    let (_, c) = ready(&m, 1000).await;
    script(&fake, &[FakeRestore::Ambiguous(Reason::Io)]);
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_io"), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    assert_eq!(f.create_certainty, CreateCertainty::AllocationAmbiguous);
    // READER_ENDED `unknown` never releases (C4): the pin pauses idle...
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    clock.advance(DEFAULT_CHECKPOINT_IDLE_MS as i64 + SEC);
    m.expire_checkpoints_due();
    assert_eq!(row(&m, c.id.as_str()).state, CheckpointState::Ready);
    // ...and no barrier: the reader was reaped and nothing else can explain it.
    assert!(!m.allocation_blocked());
    // Lifetime is never paused: ABSENT releases the pin and the charge.
    clock.advance(DEFAULT_CHECKPOINT_LIFETIME_MS as i64);
    m.expire_checkpoints_due();
    until("lifetime ABSENT", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("absent")
    );
    assert_eq!(charge(&m), (0, 0));
}

/// C6b V16: kiln's shim checks object digests after allocation, so a corrupt
/// artifact comes back as an ambiguous restore. Its corrupt verdict still quarantines
/// the checkpoint (design 10): the next fork is refused before admission, the charge
/// stays, and the owner's Delete releases it.
#[tokio::test]
async fn an_ambiguous_corrupt_restore_quarantines_the_checkpoint_and_keeps_its_charge() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let charged = charge(&m);
    script(&fake, &[FakeRestore::Ambiguous(Reason::Corrupt)]);
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_corrupt"), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    assert_eq!(f.create_certainty, CreateCertainty::AllocationAmbiguous);
    let q = row(&m, c.id.as_str());
    assert_eq!(q.state, CheckpointState::Quarantined, "{q:?}");
    assert_eq!(q.failure.unwrap().token, "checkpoint_corrupt");
    assert_eq!(charge(&m), charged, "the charge stays while quarantined");
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    // Refused before admission: no row, reservation or restore.
    let (forks, resources) = (forks_of(&m, &c).len(), m.store_resources_for_test());
    let restores = fake.checkpoints(|g| g.calls.iter().filter(|op| op.starts_with("restore ")).count());
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_corrupt"), "{e:?}");
    assert_eq!(forks_of(&m, &c).len(), forks);
    assert_eq!(m.store_resources_for_test(), resources);
    assert_eq!(
        fake.checkpoints(|g| g.calls.iter().filter(|op| op.starts_with("restore ")).count()),
        restores
    );
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("absent")
    );
    assert_eq!(charge(&m), (0, 0));
}

/// Any other ambiguous reason leaves the checkpoint READY (C6b V16's control).
#[tokio::test]
async fn an_ambiguous_io_restore_leaves_the_checkpoint_ready() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    script(&fake, &[FakeRestore::Ambiguous(Reason::Io)]);
    fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(row(&m, c.id.as_str()).state, CheckpointState::Ready);
}

#[tokio::test]
async fn a_typed_helper_refusal_fails_definitely_and_delete_still_reaches_absent() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = m.store_resources_for_test();
    script(
        &fake,
        &[FakeRestore::Refuse(
            crate::checkpoint::wire::CheckpointErrorKind::Workers,
        )],
    );
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_workers"), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    assert_eq!(m.store_resources_for_test(), before);
    // No fact says the reader never ran: the pin stays, and Delete releases it.
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("absent")
    );
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn a_lost_or_pending_reply_follows_the_reader_to_its_record() {
    for outcome in [FakeRestore::LoseReply, FakeRestore::Pending] {
        let (m, fake, _) = engine();
        let (_, c) = ready(&m, 1000).await;
        script(&fake, std::slice::from_ref(&outcome));
        let f = fork(&m, &c, 1000).await.unwrap();
        assert_eq!(f.state, SandboxState::Ready, "{outcome:?}");
        assert_eq!(
            pin_of(&m, &f.id).unwrap().released_by.as_deref(),
            Some("complete")
        );
        assert!(calls(&fake, "inspect") >= 1, "{outcome:?}");
        assert_eq!(restores(&m), 0);
    }
}

#[tokio::test]
async fn a_helper_restart_mid_restore_is_ambiguous_and_its_pin_waits() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    // The helper restarts under the reader: its connection drops (the fake's reply
    // then fails the epoch check), and the old epoch is gone when asked about.
    fake.checkpoints(|g| g.restart());
    gate.release();
    let e = running.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_io"), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    assert_eq!(f.create_certainty, CreateCertainty::AllocationAmbiguous);
    // A dead epoch's reader cannot certify anything: only ABSENT releases its pin.
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    assert!(!m.allocation_blocked());
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("absent")
    );
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn unproven_default_env_on_a_restored_sandbox_is_compensated() {
    let (m, fake, _) = engine();
    fake.state().proven_features = Ok(vec![
        Feature::ExecCwd,
        Feature::ExecEnv,
        Feature::SandboxDefaultEnv,
    ]);
    assert!(m.health().await.unwrap().serving);
    let (_, c) = ready(&m, 1000).await;
    fake.state().create_exec_features = None;
    let r = CreateRequest {
        default_env: vec![crate::exec_env::EnvVar {
            name: "A".into(),
            value: "1".into(),
        }],
        ..fork_req(&c)
    };
    let e = m.create_owned(r, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some(SANDBOX_FEATURE_PROBE_FAILED), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    let backend = f.backend_id.unwrap();
    assert!(!fake.state().sandboxes.contains_key(&backend), "removed");
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("complete")
    );
}

// --- Races and cancellation ----------------------------------------------------------------

/// After a fork settled: nothing restoring, no pin live on `c` and every charge exact.
fn settled(m: &M, c: &Checkpoint) {
    assert_eq!(restores(m), 0, "a restore left in the live set");
    assert_eq!(live_pins(m, c), 0, "a leaked pin");
}

#[tokio::test]
async fn checkpoint_delete_during_a_restore_fails_the_fork_and_reaches_absent() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = m.store_resources_for_test();
    let backends = fake.state().sandboxes.len();
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    assert_eq!(restores(&m), 1);
    assert_eq!(live_pins(&m, &c), 1);
    // Delete publishes intent, cancels the fork; the removal's tombstone stops the
    // reader, waits for it, and only then proves ABSENT.
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    let e = running.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"), "{e:?}");
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    assert_eq!(f.create_certainty, CreateCertainty::DefinitelyNotCreated);
    assert_eq!(
        m.store_resources_for_test().disk_bytes,
        before.disk_bytes - S
    );
    assert_eq!(charge(&m), (0, 0));
    assert_eq!(
        fake.state().sandboxes.len(),
        backends,
        "no stranded backend"
    );
    assert!(fake.checkpoints(|g| g.readers.is_empty() && g.published.is_empty()));
    settled(&m, &c);
    drop(gate);
}

#[tokio::test]
async fn checkpoint_delete_after_the_copy_and_before_ready_compensates_the_fork() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let backends = fake.state().sandboxes.len();
    let gate = FakeGate::default();
    fake.state().restored_features_gate = Some(gate.clone());
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    // The copy is complete: its pin is already released, so Delete needs no reader.
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("complete")
    );
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    gate.release();
    let e = running.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"), "{e:?}");
    let f = m.load(&f.id).unwrap();
    assert_eq!(f.state, SandboxState::Failed, "{f:?}");
    assert_eq!(
        fake.state().sandboxes.len(),
        backends,
        "the restored backend was removed"
    );
    assert_eq!(charge(&m), (0, 0));
    settled(&m, &c);
}

#[tokio::test]
async fn checkpoint_delete_during_the_preflight_await_allocates_nothing() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = (rows(&m), m.store_resources_for_test());
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.capabilities_gate = Some(gate.clone()));
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    m.delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    gate.release();
    // The accepting transaction rechecks the checkpoint after the preflight's await.
    let e = running.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"), "{e:?}");
    assert_eq!(rows(&m), before.0);
    // Only the deleted checkpoint's S came back; the fork reserved nothing.
    assert_eq!(
        m.store_resources_for_test().disk_bytes,
        before.1.disk_bytes - S
    );
    assert_eq!(m.store_resources_for_test().sandboxes, before.1.sandboxes);
    assert_eq!(calls(&fake, "restore"), 0);
    assert!(m.store.checkpoint_pins(c.id.as_str()).unwrap().is_empty());
}

/// The adversarial review's HIGH 2: a barrier raised while a fork's preflight awaits refuses at the
/// accepting reservation: no row, pin, charge or Restore.
#[tokio::test]
async fn allocation_barrier_raised_during_fork_preflight_blocks_reservation() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let before = (rows(&m), m.store_resources_for_test());
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.capabilities_gate = Some(gate.clone()));
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;

    assert!(m.set_checkpoint_barrier(true).unwrap());
    gate.release();

    let error = running.await.unwrap().unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error:?}");
    assert_eq!(rows(&m), before.0, "a blocked fork wrote a sandbox row");
    assert_eq!(
        m.store_resources_for_test(),
        before.1,
        "a blocked fork changed accounting"
    );
    assert_eq!(calls(&fake, "restore"), 0);
    assert!(m.store.checkpoint_pins(c.id.as_str()).unwrap().is_empty());
}

/// The same for an ordinary create (paused in its preparation) and a capture (paused
/// asking for its source): the barrier's admission is atomic with every reservation.
#[tokio::test]
async fn allocation_barrier_raised_during_a_create_or_capture_preflight_blocks_it() {
    let (m, fake, _) = engine_with(FakeRuntime::fenced().with_checkpoints(), test_limits());
    let gate = FakeGate::default();
    fake.state().fenced.prepare_gate = Some(gate.clone());
    let before = (rows(&m), m.store_resources_for_test());
    let running = tokio::spawn({
        let m = Arc::clone(&m);
        async move { m.create_owned(CreateRequest::default(), 1000).await }
    });
    gate.entered().await;
    assert!(m.set_checkpoint_barrier(true).unwrap());
    gate.release();
    let error = running.await.unwrap().unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error:?}");
    assert_eq!((rows(&m), m.store_resources_for_test()), before);
    assert!(fake.state().fenced.allocations.is_empty());

    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let before = (charge(&m), m.store.unsettled_checkpoints().unwrap().len());
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.source_gate = Some(gate.clone()));
    let running = tokio::spawn({
        let m = Arc::clone(&m);
        let r = req(&s);
        async move { m.capture_checkpoint(r, 1000, None, None).await }
    });
    gate.entered().await;
    assert!(m.set_checkpoint_barrier(true).unwrap());
    gate.release();
    let error = running.await.unwrap().unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error:?}");
    assert_eq!(
        (charge(&m), m.store.unsettled_checkpoints().unwrap().len()),
        before
    );
    assert_eq!(calls(&fake, "capture"), 0);
}

#[tokio::test]
async fn checkpoint_expiry_during_a_restore_waits_for_lifetime_and_fails_the_fork() {
    let (m, fake, clock) = engine();
    let s = source(&m, 1000).await;
    let c = m
        .capture_checkpoint(short(&s, 60, 10), 1000, None, None)
        .await
        .unwrap();
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    // Idle is paused while the pin is live; lifetime never is.
    clock.advance(30 * SEC);
    m.expire_checkpoints_due();
    assert_eq!(row(&m, c.id.as_str()).state, CheckpointState::Ready);
    clock.advance(31 * SEC);
    m.expire_checkpoints_due();
    let e = running.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"), "{e:?}");
    until("lifetime ABSENT", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(
        row(&m, c.id.as_str()).deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );
    assert_eq!(charge(&m), (0, 0));
    settled(&m, &c);
    drop(gate);
}

#[tokio::test]
async fn source_delete_departed_waiter_and_shutdown_never_disturb_a_restore() {
    let (m, fake, _) = engine();
    let (s, c) = ready(&m, 1000).await;
    // The source's Delete: the fork reads the checkpoint, never the source.
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
    gate.release();
    assert_eq!(running.await.unwrap().unwrap().state, SandboxState::Ready);
    // A departed waiter only detaches.
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    running.abort();
    let _ = running.await;
    gate.release();
    until("the detached fork's READY", || {
        forks_of(&m, &c).len() == 2 && forks_of(&m, &c)[1].state == SandboxState::Ready
    })
    .await;
    // Shutdown does not cancel it either: the drain waits for its outcome.
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    m.begin_shutdown();
    let drained = {
        let m = Arc::clone(&m);
        tokio::spawn(async move { m.drain_operations().await })
    };
    gate.release();
    assert_eq!(running.await.unwrap().unwrap().state, SandboxState::Ready);
    drained.await.unwrap();
    settled(&m, &c);
}

// --- The pass's fork rule, ownership and the epoch -------------------------------------------

#[tokio::test]
async fn a_panicking_fork_supervisor_arms_the_barrier_until_its_reader_settles() {
    let (m, fake, _) = engine();
    m.reconcile().await.unwrap();
    m.start_checkpoints().unwrap();
    let (_, c) = ready(&m, 1000).await;
    // The restore's reply is pending, and the supervisor panics asking about it.
    script(&fake, &[FakeRestore::Pending]);
    fake.checkpoints(|g| g.panic_on = Some("inspect"));
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert!(matches!(e, Error::Internal(_)), "{e:?}");
    // Its reader may still run with no one following it: allocation blocks at once.
    assert!(m.allocation_blocked());
    assert!(m.store.checkpoint_barrier_marked().unwrap());
    assert_eq!(restores(&m), 0, "the live set lost it on unwind");
    // The barrier's pass reads the reader's record, releases the pin and clears.
    until("the barrier clears", || !m.allocation_blocked()).await;
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("complete")
    );
    assert!(!m.store.checkpoint_barrier_marked().unwrap());
}

#[tokio::test]
async fn a_panic_in_the_restore_call_is_followed_by_its_nonce() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    fake.checkpoints(|g| g.panic_on = Some("restore"));
    let e = fork(&m, &c, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_io"), "{e:?}");
    // Asked about, the nonce was unknown and is retired: it can never start.
    let f = forks_of(&m, &c).pop().unwrap();
    assert_eq!(f.state, SandboxState::Failed);
    let pin = pin_of(&m, &f.id).unwrap();
    assert!(pin.released_at_ms.is_none());
    assert!(fake.checkpoints(|g| g.retired.contains(&pin.reader.operation)));
    assert!(!m.allocation_blocked());
    settled_but_pinned(&m, &c, 1);
}

fn settled_but_pinned(m: &M, c: &Checkpoint, pins: usize) {
    assert_eq!(restores(m), 0);
    assert_eq!(live_pins(m, c), pins);
}

#[tokio::test]
async fn a_fork_leaving_after_the_pass_snapshot_refuses_the_clear() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let restore = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    restore.entered().await;
    // A pass snapshots the fork as live, then waits in its inventory.
    let inventory = FakeGate::default();
    fake.checkpoints(|g| g.inventory_gate = Some(inventory.clone()));
    let pass = {
        let m = Arc::clone(&m);
        tokio::spawn(async move { m.reconcile_checkpoints().await })
    };
    inventory.entered().await;
    // The fork leaves the live set meanwhile (here: READY).
    restore.release();
    assert_eq!(running.await.unwrap().unwrap().state, SandboxState::Ready);
    inventory.release();
    assert!(
        !pass.await.unwrap().unwrap(),
        "the pass's own verdict is clean"
    );
    // ...but its snapshot is stale: the clear is refused, and the next pass clears.
    assert!(
        m.set_checkpoint_barrier(false).unwrap(),
        "stale clear refused"
    );
    assert!(m.allocation_blocked());
    assert!(!m.reconcile_checkpoints().await.unwrap());
    assert!(!m.set_checkpoint_barrier(false).unwrap());
    assert!(!m.allocation_blocked());
}

#[tokio::test]
async fn an_orphaned_reader_in_the_inventory_is_explained_by_its_pin() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let gate = gate_restore(&fake);
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    // A pass while the reader runs: the reader is the fork's pin's, and the fork is
    // live in this process, so the pass is clean.
    assert!(!m.reconcile_checkpoints().await.unwrap());
    gate.release();
    assert_eq!(running.await.unwrap().unwrap().state, SandboxState::Ready);
    // An inventory reader no live pin names blocks.
    let stray = Id128::random();
    fake.checkpoints(|g| {
        g.readers
            .entry(c.id.to_string())
            .or_default()
            .insert(stray, CancellationToken::new());
    });
    assert!(m.reconcile_checkpoints().await.unwrap());
    fake.checkpoints(|g| g.readers.clear());
    assert!(!m.reconcile_checkpoints().await.unwrap());
}

// --- Crash recovery (design 10) -----------------------------------------------------------

/// What C5a-2 commits before dispatch, written directly: a fork's CREATING row and its
/// pin under the helper's current epoch (a daemon that died right after its commit).
fn committed_fork(
    m: &M,
    c: &Checkpoint,
    s: &Sandbox,
    epoch: Id128,
    boot: Id128,
) -> (Sandbox, HelperDispatch) {
    committed_keyed_fork(m, c, s, epoch, boot, None)
}

/// The same, with its create key's record committed beside it.
fn committed_keyed_fork(
    m: &M,
    c: &Checkpoint,
    s: &Sandbox,
    epoch: Id128,
    boot: Id128,
    key: Option<&CreateKey>,
) -> (Sandbox, HelperDispatch) {
    let mut fork = m.store.sandbox(&s.id).unwrap().unwrap();
    fork.id = new_id("sb");
    fork.state = SandboxState::Creating;
    fork.backend_id = None;
    fork.lifecycle = SandboxLifecycle {
        from_checkpoint: Some(crate::model::CheckpointProvenance {
            checkpoint: c.id.clone(),
            content_sha256: c.seal.as_ref().unwrap().content_sha256,
        }),
        image_identity: Some(crate::model::ImageIdentity {
            content_sha256: c.image_content_sha256,
            checkpoint_format_version: c.format_version,
        }),
        request_id: key.map(|k| k.request_id.clone()),
        ..SandboxLifecycle::default()
    };
    let reader = HelperDispatch {
        operation: Id128::random(),
        helper_epoch: epoch,
        boot_id: boot,
    };
    let admission = key.map(|k| crate::store::RequestAdmission {
        sha256: k.sha256,
        max_per_uid: m.limits.create_requests.max_per_uid,
        max_node: m.limits.create_requests.max_node,
    });
    let reserved = m
        .store
        .reserve_fork_sandbox(&fork, m.sandbox_budgets(), admission.as_ref(), &[], &reader)
        .unwrap();
    assert!(
        matches!(
            reserved,
            crate::store::ReserveFork::Sandbox(ReserveSandbox::Inserted)
        ),
        "{reserved:?}"
    );
    (fork, reader)
}

/// The helper's `Restore` for that reader, as the dead daemon had sent it.
fn orphan_restore(
    fake: &FakeRuntime,
    c: &Checkpoint,
    fork: &Sandbox,
    reader: &HelperDispatch,
) -> tokio::task::JoinHandle<()> {
    let fake = fake.clone();
    let op = CheckpointOperation::Restore {
        target: c.target(),
        content_sha256: c.seal.as_ref().unwrap().content_sha256,
        reader: reader.operation,
        spec: fork.spec.clone(),
    };
    let epoch = reader.helper_epoch;
    tokio::spawn(async move {
        let _ = fake
            .checkpoint(
                Some(epoch),
                op,
                Instant::now() + Duration::from_secs(60),
                &CancellationToken::new(),
            )
            .await;
    })
}

async fn on_disk_engine() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    M,
    FakeRuntime,
    ManualClock,
) {
    let (tmp, dir) = state_dir();
    let fake = FakeRuntime::default().with_checkpoints();
    let clock = ManualClock::default();
    let m = on_disk(&dir, &fake, &clock, &test_limits());
    m.reconcile().await.unwrap();
    m.start_checkpoints().unwrap();
    (tmp, dir, m, fake, clock)
}

#[tokio::test]
async fn a_crash_after_the_pin_and_before_dispatch_retires_the_reader_and_keeps_the_pin() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
    let m = restart(m, &dir, &fake, &clock).await;
    // The CREATING row settles as any interrupted legacy create; the pass asks the
    // helper about the reader, which retires it (it can never start now). No fact
    // says it never ran, so the pin stays (C4), and nothing blocks.
    assert_eq!(m.load(&f.id).unwrap().state, SandboxState::Failed);
    assert!(fake.checkpoints(|g| g.retired.contains(&reader.operation)));
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    assert!(!m.allocation_blocked());
    // Delete reaches ABSENT and releases it.
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("absent")
    );
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn a_crash_mid_restore_blocks_until_the_orphaned_reader_settles() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
    let gate = gate_restore(&fake);
    let orphan = orphan_restore(&fake, &c, &f, &reader);
    gate.entered().await;
    let limits = m.limits.clone();
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    // The reader runs with no supervisor: the restart blocks allocation, and the row
    // stays CREATING (charged) for the reader's final answer.
    assert!(reconciled.checkpoints_blocked, "{reconciled:?}");
    assert_eq!(m.load(&f.id).unwrap().state, SandboxState::Creating);
    m.rebase_expiry_clocks().unwrap();
    m.rebuild_expiry().unwrap();
    m.start_checkpoints().unwrap();
    assert!(m.allocation_blocked());
    assert!(matches!(
        m.create_owned(CreateRequest::default(), 2000).await,
        Err(Error::FailedPrecondition(_))
    ));
    // It settles (the backend made): the retry's pass compensates that exact backend,
    // releases the pin and clears.
    gate.release();
    orphan.await.unwrap();
    until("the barrier clears", || !m.allocation_blocked()).await;
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("complete")
    );
    compensated(&m, &f);
    // Nothing is left for the next start: no unmanaged backend, nothing charged.
    let limits = m.limits.clone();
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(&dir, &fake, &clock, &limits);
    let reconciled = m.reconcile().await.unwrap();
    assert!(reconciled.unmanaged.is_empty(), "{reconciled:?}");
    compensated(&m, &f);
    deleted_with_nothing_left(&m, &f).await;
}

/// A fork the restart (or the pass) settled from a `Created` record: its exact backend
/// removed, the row FAILED with its typed reason and released, Delete reaching DELETED.
fn compensated(m: &M, f: &Sandbox) {
    let row = m.load(&f.id).unwrap();
    assert_eq!(row.state, SandboxState::Failed, "{row:?}");
    assert_ne!(
        row.accounting.release,
        ReservationRelease::Charged,
        "{row:?}"
    );
    assert!(
        row.failure_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("checkpoint_io: ") && r.ends_with("backend removed")),
        "{row:?}"
    );
    assert!(row.backend_id.is_some());
    assert!(!row.is_charged(), "{row:?}");
}

/// Delete releases whatever the settlement left, and no pin of the fork stays live.
async fn deleted_with_nothing_left(m: &M, f: &Sandbox) {
    let d = m.delete(&f.id).await.unwrap();
    assert!(matches!(d.state, SandboxState::Deleted), "{d:?}");
    assert!(pin_of(m, &f.id).unwrap().released_at_ms.is_some());
}

/// The adversarial review's HIGH 1, `Created`: the helper settled the restore and the daemon died
/// before the backend ID reached the row. Startup reads the record before the legacy
/// CREATING rule: that exact backend is compensated and the pin released.
#[tokio::test]
async fn a_crash_after_the_copy_and_before_ready_compensates_the_exact_backend_at_startup() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
    orphan_restore(&fake, &c, &f, &reader).await.unwrap();
    let m = stop_and_reopen(m, &dir, &fake, &clock);
    let reconciled = m.reconcile().await.unwrap();
    assert!(!reconciled.checkpoints_blocked, "{reconciled:?}");
    assert!(reconciled.unmanaged.is_empty(), "{reconciled:?}");
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("complete")
    );
    compensated(&m, &f);
    deleted_with_nothing_left(&m, &f).await;
}

/// The adversarial review's HIGH 1, `NotCreated`: the record proves nothing was allocated, so the
/// restart fails the fork definitely and releases its reservation, then the pin.
#[tokio::test]
async fn a_crash_after_known_not_created_releases_the_reservation_at_startup() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
    script(&fake, &[FakeRestore::NotCreated(Reason::ImageUnavailable)]);
    orphan_restore(&fake, &c, &f, &reader).await.unwrap();
    let before = m.store_resources_for_test();
    let m = stop_and_reopen(m, &dir, &fake, &clock);
    let reconciled = m.reconcile().await.unwrap();
    let recovered = m.load(&f.id).unwrap();
    assert_eq!(recovered.state, SandboxState::Failed, "{reconciled:?}");
    assert_eq!(
        recovered.create_certainty,
        CreateCertainty::DefinitelyNotCreated,
        "the helper's final NotCreated outcome was discarded: {reconciled:?}"
    );
    assert!(
        recovered
            .failure_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("checkpoint_image_unavailable: ")),
        "{recovered:?}"
    );
    assert!(!recovered.is_charged());
    assert_eq!(m.store_resources_for_test().sandboxes, before.sandboxes - 1);
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("not_started")
    );
    assert!(reconciled.unmanaged.is_empty() && !reconciled.checkpoints_blocked);
    deleted_with_nothing_left(&m, &f).await;
}

/// Crashes between each new write and the pin's release: after the backend ID was
/// recorded, after the pin was released too (before the acknowledgment), and after
/// NotCreated's definite failure. Each restart ends settled: exact charge, no live pin,
/// no unmanaged backend, Delete releasing.
#[tokio::test]
async fn a_crash_between_each_settlement_write_and_the_pin_release_recovers() {
    for (case, outcome) in [
        ("recorded", None),
        ("released", None),
        ("not created", Some(Reason::ImageUnavailable)),
    ] {
        let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
        let (s, c) = ready(&m, 1000).await;
        let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
        let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
        if let Some(reason) = outcome {
            script(&fake, &[FakeRestore::NotCreated(reason)]);
        }
        orphan_restore(&fake, &c, &f, &reader).await.unwrap();
        let reply = settled_record(&fake, &c, &reader).await;
        match (&reply, case) {
            (
                RestoreReply::Created {
                    backend_id,
                    evidence,
                },
                _,
            ) => {
                m.store.record_fork_backend(&f.id, backend_id).unwrap();
                if case == "released" {
                    m.store.release_checkpoint_pin(&f.id, evidence).unwrap();
                }
            }
            (RestoreReply::NotCreated { .. }, _) => {
                m.store
                    .fail_create_definitely(&f.id, "checkpoint_image_unavailable: scripted")
                    .unwrap();
            }
            other => panic!("{other:?}"),
        }
        let m = stop_and_reopen(m, &dir, &fake, &clock);
        let reconciled = m.reconcile().await.unwrap();
        assert!(reconciled.unmanaged.is_empty(), "{case}: {reconciled:?}");
        assert!(!reconciled.checkpoints_blocked, "{case}: {reconciled:?}");
        let row = m.load(&f.id).unwrap();
        assert!(!row.is_charged(), "{case}: {row:?}");
        if outcome.is_none() {
            compensated(&m, &f);
        } else {
            assert_eq!(row.create_certainty, CreateCertainty::DefinitelyNotCreated);
        }
        deleted_with_nothing_left(&m, &f).await;
        settled(&m, &c);
    }
}

/// The reader's settled record, as the helper keeps it until acknowledged.
async fn settled_record(
    fake: &FakeRuntime,
    c: &Checkpoint,
    reader: &HelperDispatch,
) -> RestoreReply {
    let reply = fake
        .checkpoint(
            Some(reader.helper_epoch),
            CheckpointOperation::Inspect {
                target: c.target(),
                verify: false,
                operation: Some(reader.operation),
            },
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let CheckpointResponse::Inspected(view) = reply else {
        panic!("{reply:?}")
    };
    match view.operation {
        Some(crate::checkpoint::wire::OperationState::Settled(reply)) => match *reply {
            CheckpointResponse::Restored(r) => *r,
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

fn stop_and_reopen(m: M, dir: &std::path::Path, fake: &FakeRuntime, clock: &ManualClock) -> M {
    let limits = m.limits.clone();
    m.begin_shutdown();
    drop(m);
    on_disk(dir, fake, clock, &limits)
}

#[tokio::test]
async fn a_crash_with_a_helper_restart_leaves_a_dead_epoch_pin_for_absent() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, _) = committed_fork(&m, &c, &s, epoch, boot);
    fake.checkpoints(|g| g.restart());
    let inspects = calls(&fake, "inspect");
    let m = restart(m, &dir, &fake, &clock).await;
    // No helper call about a dead epoch's reader; nothing blocks; the pin waits.
    assert!(!m.allocation_blocked());
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    assert_eq!(
        calls(&fake, "inspect") - inspects,
        1,
        "only the READY row's own inspection"
    );
    m.delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(
        pin_of(&m, &f.id).unwrap().released_by.as_deref(),
        Some("absent")
    );
}

#[tokio::test]
async fn a_crash_after_ready_keeps_the_fork() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (_, c) = ready(&m, 1000).await;
    let f = fork(&m, &c, 1000).await.unwrap();
    let m = restart(m, &dir, &fake, &clock).await;
    assert_eq!(m.load(&f.id).unwrap().state, SandboxState::Ready);
    assert!(!m.allocation_blocked());
    settled(&m, &c);
}

/// The independent review's MEDIUM: a checkpoint that becomes due while the preflight
/// awaits the helper is expired before the accepting transaction, never pinned.
#[tokio::test]
async fn a_checkpoint_due_during_the_preflight_await_is_expired_not_pinned() {
    let (m, fake, clock) = engine();
    let s = source(&m, 1000).await;
    let c = m
        .capture_checkpoint(short(&s, 60, 10), 1000, None, None)
        .await
        .unwrap();
    clock.advance(9 * SEC);
    let before = (rows(&m), m.store_resources_for_test());
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.capabilities_gate = Some(gate.clone()));
    let running = spawn_fork(&m, &c, 1000);
    gate.entered().await;
    // Idle passes while the preflight waits, and no sweeper runs before it resumes.
    clock.advance(2 * SEC);
    gate.release();
    let e = running.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_expired"), "{e:?}");
    assert_eq!(rows(&m), before.0);
    assert_eq!(calls(&fake, "restore"), 0);
    assert!(m.store.checkpoint_pins(c.id.as_str()).unwrap().is_empty());
    until("the expired checkpoint's removal", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(
        row(&m, c.id.as_str()).deletion_reason,
        Some(DeletionReason::ExpiredIdle)
    );
    assert_eq!(
        m.store_resources_for_test().disk_bytes,
        before.1.disk_bytes - S
    );
}

// --- Fix round 2 (the adversarial review's recheck 1) --------------------------------------

/// The production retry pacing (1 s, doubling to 60 s), so the barrier's pass runs on
/// its own schedule and the checkpoint's removal lands before it.
fn r2_prod_pacing() -> Limits {
    Limits {
        checkpoints: Some(CheckpointLimits::default()),
        ..test_limits()
    }
}

async fn r2_until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..3000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn record_of(fake: &FakeRuntime, reader: &HelperDispatch) -> Option<RestoreReply> {
    fake.checkpoints(|g| g.restore_records.get(&reader.operation).cloned())
}

/// The recheck's HIGH: a restart keeps a fork CREATING while its reader runs; then the
/// checkpoint's Delete or its lifetime expiry reaches ABSENT, which releases the pin,
/// before any pass consumed the reader's record (`NotCreated`, the reader stopped by
/// the removal's tombstone; or `Created`, the reader done first). The pass is driven
/// by the CREATING row, not the pin: it settles the fork from the record (definite
/// failure, or that exact backend compensated) and only then clears. Each ends with
/// the exact charge, Delete reaching DELETED, and no unmanaged backend on the next start.
#[tokio::test]
async fn checkpoint_absent_before_the_pass_still_settles_a_kept_fork() {
    for (created, expiry) in [(false, false), (false, true), (true, false), (true, true)] {
        let case = format!("created {created}, expiry {expiry}");
        let (tmp, dir) = state_dir();
        let fake = FakeRuntime::default().with_checkpoints();
        let clock = ManualClock::default();
        let m = on_disk(&dir, &fake, &clock, &r2_prod_pacing());
        m.reconcile().await.unwrap();
        m.start_checkpoints().unwrap();
        let s = source(&m, 1000).await;
        let c = m
            .capture_checkpoint(short(&s, 60, 10), 1000, None, None)
            .await
            .unwrap();
        let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
        let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
        let gate = gate_restore(&fake);
        let orphan = orphan_restore(&fake, &c, &f, &reader);
        gate.entered().await;
        let m = restart(m, &dir, &fake, &clock).await;
        assert_eq!(
            m.load(&f.id).unwrap().state,
            SandboxState::Creating,
            "{case}"
        );
        assert!(m.allocation_blocked(), "{case}");
        let mut orphan = Some(orphan);
        if created {
            gate.release();
            orphan.take().unwrap().await.unwrap();
            assert!(matches!(
                record_of(&fake, &reader),
                Some(RestoreReply::Created { .. })
            ));
        }
        if expiry {
            clock.advance(61 * SEC);
            m.expire_checkpoints_due();
        } else {
            m.delete_checkpoint(c.id.as_str(), 1000, false)
                .await
                .unwrap();
        }
        r2_until("the checkpoint's ABSENT", || {
            row(&m, c.id.as_str()).state == CheckpointState::Deleted
        })
        .await;
        if let Some(orphan) = orphan {
            orphan.await.unwrap();
        }
        // ABSENT came first: it, not the reader's evidence, released the pin.
        assert_eq!(
            pin_of(&m, &f.id).unwrap().released_by.as_deref(),
            Some("absent"),
            "{case}"
        );
        let record = record_of(&fake, &reader).unwrap();
        // The barrier clears only once the row is settled.
        r2_until("the barrier clears", || !m.allocation_blocked()).await;
        let settled_row = m.load(&f.id).unwrap();
        assert_ne!(settled_row.state, SandboxState::Creating, "{case}");
        match record {
            RestoreReply::Created { backend_id, .. } => {
                compensated(&m, &f);
                assert_eq!(settled_row.backend_id.as_deref(), Some(backend_id.as_str()));
                assert!(!fake.state().sandboxes.contains_key(&backend_id), "{case}");
            }
            RestoreReply::NotCreated { .. } => {
                assert_eq!(
                    settled_row.create_certainty,
                    CreateCertainty::DefinitelyNotCreated,
                    "{case}: {settled_row:?}"
                );
                assert!(!settled_row.is_charged(), "{case}");
                assert!(
                    settled_row
                        .failure_reason
                        .as_deref()
                        .is_some_and(|r| r.starts_with("checkpoint_")),
                    "{case}: {settled_row:?}"
                );
            }
            other => panic!("{case}: {other:?}"),
        }
        assert_eq!(charge(&m), (0, 0), "{case}");
        deleted_with_nothing_left(&m, &f).await;
        let m = stop_and_reopen(m, &dir, &fake, &clock);
        let reconciled = m.reconcile().await.unwrap();
        assert!(reconciled.unmanaged.is_empty(), "{case}: {reconciled:?}");
        assert!(!reconciled.checkpoints_blocked, "{case}: {reconciled:?}");
        drop((gate, tmp));
    }
}

/// The recheck's HIGH, a crash at each step of the row-driven path once ABSENT has
/// released the pin: before any settlement, after compensation's intent (DELETING with
/// the exact backend, not yet removed), and after the settlement write. Each restart
/// ends with the exact charge, no unmanaged backend, nothing blocked and Delete
/// reaching DELETED.
#[tokio::test]
async fn a_crash_at_each_step_after_absent_released_the_pin_recovers() {
    for (case, not_created) in [
        ("before", false),
        ("before", true),
        ("intent", false),
        ("settled", false),
        ("settled", true),
    ] {
        let case = format!("{case}, not created {not_created}");
        let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
        let (s, c) = ready(&m, 1000).await;
        let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
        let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
        if not_created {
            script(&fake, &[FakeRestore::NotCreated(Reason::ImageUnavailable)]);
        }
        orphan_restore(&fake, &c, &f, &reader).await.unwrap();
        let reply = settled_record(&fake, &c, &reader).await;
        m.delete_checkpoint(c.id.as_str(), 1000, false)
            .await
            .unwrap();
        assert_eq!(
            pin_of(&m, &f.id).unwrap().released_by.as_deref(),
            Some("absent")
        );
        assert_eq!(m.load(&f.id).unwrap().state, SandboxState::Creating);
        match (case.as_str(), &reply) {
            (c, RestoreReply::Created { backend_id, .. }) if c.starts_with("intent") => {
                m.store
                    .set_sandbox_state(
                        &f.id,
                        SandboxState::Deleting,
                        Some(backend_id),
                        Some("checkpoint_io: kilnd lost the fork before it was ready"),
                    )
                    .unwrap();
            }
            (c, _) if c.starts_with("settled") => {
                assert!(!m.reconcile_checkpoints().await.unwrap(), "{case}");
                assert_ne!(m.load(&f.id).unwrap().state, SandboxState::Creating);
            }
            _ => {}
        }
        let m = stop_and_reopen(m, &dir, &fake, &clock);
        let reconciled = m.reconcile().await.unwrap();
        assert!(reconciled.unmanaged.is_empty(), "{case}: {reconciled:?}");
        assert!(!reconciled.checkpoints_blocked, "{case}: {reconciled:?}");
        let row = m.load(&f.id).unwrap();
        assert!(!row.is_charged(), "{case}: {row:?}");
        match &reply {
            RestoreReply::Created { backend_id, .. } => {
                assert!(!fake.state().sandboxes.contains_key(backend_id), "{case}");
            }
            _ => assert_eq!(row.create_certainty, CreateCertainty::DefinitelyNotCreated),
        }
        assert_eq!(charge(&m), (0, 0), "{case}");
        let d = m.delete(&f.id).await.unwrap();
        assert_eq!(d.state, SandboxState::Deleted, "{case}");
    }
}

/// The recheck's M1 remainder: a keyed fork dispatched in a helper epoch that has since
/// ended is settled at startup with its typed failure (not the legacy text), and a
/// keyed retry returns that FAILED row.
#[tokio::test]
async fn a_dead_epoch_fork_at_startup_keeps_its_token_for_a_keyed_retry() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let r = fork_req(&c);
    let k = fork_key("dead-epoch", &r);
    let boot = fake.checkpoints(|g| g.boot);
    let (f, _) = committed_keyed_fork(&m, &c, &s, Id128::random(), boot, Some(&k));
    let m = restart(m, &dir, &fake, &clock).await;
    let retried = m.create_keyed(Ok(r), 1000, k, None).await.unwrap();
    assert_eq!(retried.id, f.id);
    assert_eq!(retried.state, SandboxState::Failed);
    assert!(
        retried
            .failure_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("checkpoint_io: ")),
        "{retried:?}"
    );
    assert!(!m.allocation_blocked());
}

/// The recheck's MEDIUM: an orphaned CREATING fork whose backend ID is recorded (its
/// supervisor unwound between the record and the pin's release) and whose helper then
/// restarted. The pass never fails such a row beside its backend: it compensates that
/// exact backend, so the reservation goes only with it.
#[tokio::test]
async fn an_orphan_with_a_recorded_backend_is_compensated_not_failed() {
    let (m, fake, _) = engine();
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
    orphan_restore(&fake, &c, &f, &reader).await.unwrap();
    let backend = match settled_record(&fake, &c, &reader).await {
        RestoreReply::Created { backend_id, .. } => backend_id,
        other => panic!("{other:?}"),
    };
    m.store.record_fork_backend(&f.id, &backend).unwrap();
    fake.checkpoints(|g| g.restart());
    assert!(!m.reconcile_checkpoints().await.unwrap());
    assert!(!fake.state().sandboxes.contains_key(&backend));
    compensated(&m, &f);
    // The dead epoch's pin waits for ABSENT, as C4's strict rule says.
    assert!(pin_of(&m, &f.id).unwrap().released_at_ms.is_none());
    m.delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    deleted_with_nothing_left(&m, &f).await;
    assert_eq!(charge(&m), (0, 0));
}

/// The recheck's MEDIUM: a settlement write that fails (injected: a trigger refusing
/// the fork row's FAILED write) leaves the row CREATING, and the pass is blocked, not
/// clean, until a later pass records it: for the pass's `NotCreated` and unproven
/// (dead epoch) rules, and for a live supervisor whose ambiguous FAILED write failed
/// (its exit arms the barrier).
#[tokio::test]
async fn a_failed_settlement_write_keeps_allocation_blocked() {
    for case in ["not created", "unproven", "live ambiguous"] {
        let (_tmp, dir, m, fake, _clock) = on_disk_engine().await;
        let (s, c) = ready(&m, 1000).await;
        let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
        let external = rusqlite::Connection::open(dir.join("kilnd.db")).unwrap();
        let inject = |id: &str| {
            external
                .execute_batch(&format!(
                    "CREATE TRIGGER inject_fork_failure BEFORE UPDATE OF state ON sandboxes
                     WHEN NEW.id = '{id}' AND NEW.state = 'failed'
                     BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;"
                ))
                .unwrap();
        };
        let f = if case == "live ambiguous" {
            m.start_checkpoints().unwrap();
            script(&fake, &[FakeRestore::Ambiguous(Reason::Io)]);
            let gate = gate_restore(&fake);
            let running = spawn_fork(&m, &c, 1000);
            gate.entered().await;
            let f = forks_of(&m, &c).pop().unwrap();
            inject(&f.id);
            gate.release();
            assert!(running.await.unwrap().is_err());
            assert!(m.allocation_blocked(), "{case}: the exit check arms");
            f
        } else {
            let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
            if case == "not created" {
                script(&fake, &[FakeRestore::NotCreated(Reason::ImageUnavailable)]);
                orphan_restore(&fake, &c, &f, &reader).await.unwrap();
            } else {
                fake.checkpoints(|g| g.restart());
            }
            inject(&f.id);
            assert!(
                m.reconcile_checkpoints().await.unwrap(),
                "{case}: a pass beside an unsettled fork is blocked"
            );
            f
        };
        assert_eq!(
            m.load(&f.id).unwrap().state,
            SandboxState::Creating,
            "{case}"
        );
        external
            .execute_batch("DROP TRIGGER inject_fork_failure")
            .unwrap();
        if case == "live ambiguous" {
            r2_until("the barrier clears", || !m.allocation_blocked()).await;
        } else {
            assert!(!m.reconcile_checkpoints().await.unwrap(), "{case}");
        }
        let row = m.load(&f.id).unwrap();
        assert_eq!(row.state, SandboxState::Failed, "{case}");
        assert!(
            row.failure_reason
                .as_deref()
                .is_some_and(|r| r.starts_with("checkpoint_")),
            "{case}: {row:?}"
        );
        if case == "not created" {
            assert_eq!(row.create_certainty, CreateCertainty::DefinitelyNotCreated);
        }
    }
}


/// C5a-2 recheck 2 (MEDIUM, the reviewer's reproduction): startup must not publish a CREATING fork that
/// row-driven settlement deliberately kept blocked after both its DELETING write
/// and exact-backend removal failed.
#[tokio::test]
async fn startup_does_not_promote_a_kept_recorded_backend_fork() {
    let (_tmp, dir, m, fake, clock) = on_disk_engine().await;
    let (s, c) = ready(&m, 1000).await;
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let (f, reader) = committed_fork(&m, &c, &s, epoch, boot);
    orphan_restore(&fake, &c, &f, &reader).await.unwrap();
    let backend = match settled_record(&fake, &c, &reader).await {
        RestoreReply::Created { backend_id, .. } => backend_id,
        other => panic!("{other:?}"),
    };
    m.store.record_fork_backend(&f.id, &backend).unwrap();

    let external = rusqlite::Connection::open(dir.join("kilnd.db")).unwrap();
    external
        .execute_batch(&format!(
            "CREATE TRIGGER inject_deleting_failure BEFORE UPDATE OF state ON sandboxes
             WHEN NEW.id = '{}' AND NEW.state = 'deleting'
             BEGIN SELECT RAISE(ABORT, 'injected deleting write failure'); END;",
            f.id
        ))
        .unwrap();
    fake.state().fail_remove = true;

    let m = stop_and_reopen(m, &dir, &fake, &clock);
    let reconciled = m.reconcile().await.unwrap();
    let row = m.load(&f.id).unwrap();

    assert_eq!(
        row.state,
        SandboxState::Creating,
        "settlement kept this fork blocked, so legacy startup must not publish it: {row:?}; {reconciled:?}"
    );
    assert!(row.is_charged());
    assert!(fake.state().sandboxes.contains_key(&backend));
}

/// C5a-2 recheck 2 (MEDIUM, the reviewer's reproduction): every durable fork failure, including failed READY
/// publication after Created, must keep a checkpoint_* token for keyed retries.
#[tokio::test]
async fn failed_fork_publication_keeps_a_typed_failure_for_keyed_retry() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let request = fork_req(&c);
    let key = fork_key("typed-publication", &request);
    m.store.reject_ready_updates().unwrap();

    let first = m
        .create_keyed(Ok(request.clone()), 1000, key.clone(), None)
        .await
        .unwrap();
    assert_eq!(first.state, SandboxState::Failed);
    assert!(fake.state().sandboxes.len() == 1, "only the source remains");
    let row = forks_of(&m, &c).pop().unwrap();
    assert_eq!(row.state, SandboxState::Failed);
    let retried = m
        .create_keyed(Ok(request), 1000, key, None)
        .await
        .unwrap();
    assert_eq!(retried.id, row.id);
    assert!(
        row.failure_reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("checkpoint_")),
        "fork failure lost its typed token: {row:?}; retry: {retried:?}"
    );
    assert!(
        retried
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("checkpoint_"))
    );
}

/// The same rule for the other publication write: a failed backend-ID write after
/// `Created` compensates the exact backend, and the FAILED row, the first answer and
/// a keyed retry all carry `checkpoint_io`.
#[tokio::test]
async fn a_failed_fork_backend_write_keeps_a_typed_failure_for_keyed_retry() {
    let (m, fake, _) = engine();
    let (_, c) = ready(&m, 1000).await;
    let request = fork_req(&c);
    let key = fork_key("typed-backend-write", &request);
    m.store.reject_fork_backend_writes().unwrap();
    let first = m
        .create_keyed(Ok(request.clone()), 1000, key.clone(), None)
        .await
        .unwrap();
    assert_eq!(first.state, SandboxState::Failed);
    assert_eq!(fake.state().sandboxes.len(), 1, "only the source remains");
    let typed = |s: &Sandbox| {
        s.failure_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("checkpoint_io: "))
    };
    assert!(typed(&first), "{first:?}");
    let retried = m.create_keyed(Ok(request), 1000, key, None).await.unwrap();
    assert_eq!(retried.id, first.id);
    assert!(typed(&retried), "{retried:?}");
    // Unkeyed, the error itself is typed.
    let err = m.create_owned(fork_req(&c), 1000).await.unwrap_err();
    assert!(
        matches!(&err, Error::Refused(RefusalCode::Unavailable, r) if r.reason() == Some("checkpoint_io")),
        "{err:?}"
    );
    assert_eq!(fake.state().sandboxes.len(), 1);
}
