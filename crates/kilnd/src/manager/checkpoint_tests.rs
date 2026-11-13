//! Checkpoint milestone C5a: the engine end to end against the fake backend's
//! scripted helper group (`runtime/fake_checkpoint.rs`) and the real schema 15 store.
//! Races, cancellation, ownership, keys, quotas, crash recovery, expiry, the
//! Firecracker refusal and the feature off.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::expiry::ManualClock;
use crate::runtime::fake::{FakeGate, FakeRemoval, FakeRuntime, fake_image_sha};

const SEC: i64 = 1000;
const S: u64 = 64 << 10;

fn ckpt_limits() -> CheckpointLimits {
    CheckpointLimits {
        removal_retry: Duration::from_millis(5),
        max_removal_retry: Duration::from_millis(20),
        ..CheckpointLimits::default()
    }
}

fn test_limits() -> Limits {
    Limits {
        max_node_memory_bytes: 1 << 40,
        max_node_pids: 1 << 20,
        max_node_disk_bytes: 1 << 50,
        expiry: ExpiryLimits {
            restart_grace: Duration::ZERO,
            ..ExpiryLimits::default()
        },
        checkpoints: Some(ckpt_limits()),
        ..Limits::default()
    }
}

type M = Arc<Manager<FakeRuntime>>;

fn engine_with(fake: FakeRuntime, limits: Limits) -> (M, FakeRuntime, ManualClock) {
    let clock = ManualClock::default();
    let m = Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        limits,
        Arc::new(clock.clone()),
    );
    (Arc::new(m), fake, clock)
}

fn engine() -> (M, FakeRuntime, ManualClock) {
    engine_with(FakeRuntime::default().with_checkpoints(), test_limits())
}

fn state_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = tmp.path().join("state");
    (tmp, state)
}

fn on_disk(dir: &std::path::Path, fake: &FakeRuntime, clock: &ManualClock, limits: &Limits) -> M {
    Arc::new(Manager::with_clock(
        fake.clone(),
        Store::reopen_after_restart(dir),
        limits.clone(),
        Arc::new(clock.clone()),
    ))
}

async fn restart(m: M, dir: &std::path::Path, fake: &FakeRuntime, clock: &ManualClock) -> M {
    let limits = m.limits.clone();
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(dir, fake, clock, &limits);
    m.reconcile().await.unwrap();
    m.rebase_expiry_clocks().unwrap();
    m.rebuild_expiry().unwrap();
    m.start_checkpoints().unwrap();
    m
}

async fn source(m: &M, uid: u32) -> Sandbox {
    m.create_owned(CreateRequest::default(), uid).await.unwrap()
}

async fn source_with(m: &M, uid: u32, lifetime_s: u64, idle_s: u64) -> Sandbox {
    m.create_owned(
        CreateRequest {
            expiry: Some(RequestedExpiry {
                max_lifetime_ms: lifetime_s * 1000,
                idle_timeout_ms: idle_s * 1000,
            }),
            ..CreateRequest::default()
        },
        uid,
    )
    .await
    .unwrap()
}

fn req(sandbox: &Sandbox) -> CaptureRequest {
    CaptureRequest {
        sandbox_id: sandbox.id.clone(),
        expiry: Some(RequestedExpiry::default()),
        max_size_bytes: 0,
    }
}

fn key(id: &str, r: &CaptureRequest) -> CaptureKey {
    CaptureKey {
        request_id: id.into(),
        sha256: crate::idempotency::capture_request_digest(r),
    }
}

async fn capture(m: &M, s: &Sandbox, uid: u32) -> Result<Checkpoint> {
    m.capture_checkpoint(req(s), uid, None, None).await
}

fn exec_req(id: &str, argv: &[&str]) -> ExecRequest {
    ExecRequest {
        cwd: String::new(),
        env: Vec::new(),
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms: 0,
    }
}

fn reason(e: &Error) -> Option<&'static str> {
    match e {
        Error::FailedPrecondition(r) | Error::Refused(_, r) => r.reason(),
        _ => None,
    }
}

fn row(m: &M, id: &str) -> Checkpoint {
    m.store.checkpoint(id).unwrap().unwrap()
}

/// (live count, charged bytes) on the node.
fn charge(m: &M) -> (u64, u64) {
    let u = m.store.checkpoint_usage(0).unwrap().node;
    (u.live, u.charged_bytes)
}

fn calls(fake: &FakeRuntime, prefix: &str) -> usize {
    fake.checkpoints(|g| g.calls.iter().filter(|c| c.starts_with(prefix)).count())
}

/// The only checkpoint on the node (or the newest).
fn only(m: &M) -> Checkpoint {
    m.store
        .checkpoint_page(None, None, None, 1)
        .unwrap()
        .rows
        .pop()
        .expect("a checkpoint")
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..2000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("timed out waiting for {what}");
}

fn gate_capture(fake: &FakeRuntime) -> FakeGate {
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.capture_gate = Some(gate.clone()));
    gate
}

// --- Typed reasons and the gate ------------------------------------------------------

#[test]
fn every_reason_has_one_token_and_the_designs_code() {
    use CheckpointCode as C;
    let expected = [
        ("backend_unsupported:workspace_checkpoint", C::Unimplemented),
        (
            "sandbox_unsupported:workspace_checkpoint",
            C::FailedPrecondition,
        ),
        ("checkpoint_busy", C::FailedPrecondition),
        ("checkpoint_not_ready", C::FailedPrecondition),
        ("checkpoint_expired", C::FailedPrecondition),
        ("checkpoint_layout_unsupported", C::FailedPrecondition),
        ("checkpoint_metadata_unsupported", C::FailedPrecondition),
        ("checkpoint_image_unavailable", C::FailedPrecondition),
        ("checkpoint_spec_mismatch", C::InvalidArgument),
        ("checkpoint_disk_too_small", C::InvalidArgument),
        ("checkpoint_expiry_required", C::InvalidArgument),
        ("checkpoint_quota", C::ResourceExhausted),
        ("checkpoint_size_limit", C::ResourceExhausted),
        ("checkpoint_workers", C::ResourceExhausted),
        ("checkpoint_corrupt", C::DataLoss),
        ("checkpoint_io", C::Unavailable),
        ("checkpoint_in_flight", C::DeadlineExceeded),
    ];
    assert_eq!(CheckpointReason::ALL.len(), expected.len());
    for (r, (token, code)) in CheckpointReason::ALL.iter().zip(expected) {
        assert_eq!((r.token(), r.code()), (token, code));
        let e = r.error("x");
        assert_eq!(reason(&e), Some(token));
        let status_code = match &e {
            Error::FailedPrecondition(_) => C::FailedPrecondition,
            Error::Refused(RefusalCode::InvalidArgument, _) => C::InvalidArgument,
            Error::Refused(RefusalCode::ResourceExhausted, _) => C::ResourceExhausted,
            Error::Refused(RefusalCode::DataLoss, _) => C::DataLoss,
            Error::Refused(RefusalCode::Unavailable, _) => C::Unavailable,
            Error::Refused(RefusalCode::Unimplemented, _) => C::Unimplemented,
            Error::Refused(RefusalCode::DeadlineExceeded, _) => C::DeadlineExceeded,
            other => panic!("{other:?}"),
        };
        assert_eq!(status_code, code);
    }
    // Every token a stored failure can carry is one schema 15 accepts.
    for r in CheckpointReason::ALL {
        if !matches!(
            r,
            CheckpointReason::BackendUnsupported
                | CheckpointReason::ExpiryRequired
                | CheckpointReason::InFlight
        ) {
            assert!(r.token().starts_with("checkpoint_") || r.token().starts_with("sandbox_"));
        }
    }
}

#[tokio::test]
async fn off_by_default_nothing_changes_and_nothing_is_called() {
    assert!(Limits::default().checkpoints.is_none());
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), Limits::default());
    let s = source(&m, 1000).await;
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
    assert!(matches!(e, Error::Refused(RefusalCode::Unimplemented, _)));
    assert!(
        fake.checkpoints(|g| g.calls.is_empty()),
        "the helper is never called"
    );
    assert_eq!(charge(&m), (0, 0));
    // Exec and the sandbox lifecycle are untouched; the capture flag is never set.
    let ran = m.exec(exec_req(&s.id, &["echo", "hi"])).await.unwrap();
    assert_eq!(ran.state, ExecutionState::Exited);
    assert!(!m.slot(&s.id).capturing());
    // Startup does no checkpoint work either.
    let reconciled = m.reconcile().await.unwrap();
    assert!(!reconciled.checkpoints_blocked && !reconciled.admission_blocked);
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 0);
    m.start_checkpoints().unwrap();
    assert!(m.checkpoint_timer_head().is_none());
    assert!(fake.checkpoints(|g| g.calls.is_empty()));
}

// --- Capture ---------------------------------------------------------------------------

#[tokio::test]
async fn a_capture_is_ready_charged_s_and_records_the_source_identity_once() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    assert!(
        m.store
            .sandbox(&s.id)
            .unwrap()
            .unwrap()
            .lifecycle
            .image_identity
            .is_none()
    );
    let c = capture(&m, &s, 1000).await.unwrap();
    assert_eq!(c.state, CheckpointState::Ready);
    assert_eq!(c.owner_uid, 1000);
    assert_eq!(c.max_size_bytes, 1 << 30, "R = min(source disk, 1 GiB)");
    assert_eq!(c.charge_bytes(), S);
    assert_eq!(c.excluded_paths, EXCLUDED_PATHS.map(String::from));
    assert_eq!(charge(&m), (1, S));
    let identity = m
        .store
        .sandbox(&s.id)
        .unwrap()
        .unwrap()
        .lifecycle
        .image_identity
        .unwrap();
    assert_eq!(identity.content_sha256, fake_image_sha());
    // A second capture reuses the recorded identity: no second `source`.
    let again = capture(&m, &s, 1000).await.unwrap();
    assert_ne!(again.id, c.id);
    assert_eq!(calls(&fake, "source"), 1);
    assert_eq!(charge(&m), (2, 2 * S));
    // The source was never renewed and runs commands again.
    assert!(!m.slot(&s.id).capturing());
    m.exec(exec_req(&s.id, &["echo"])).await.unwrap();
}

type Script = Box<dyn Fn(&FakeRuntime, &str)>;

#[tokio::test]
async fn source_record_problems_refuse_before_any_reservation() {
    use crate::checkpoint::wire::SourceReply;
    let cases: [(Script, &str); 4] = [
        (
            Box::new(|f, b| {
                let b = b.to_string();
                f.checkpoints(|g| {
                    g.sources.insert(
                        b,
                        SourceReply::Unsupported {
                            reason: crate::checkpoint::Reason::SandboxUnsupported,
                            detail: "no identity".into(),
                        },
                    )
                });
            }),
            "sandbox_unsupported:workspace_checkpoint",
        ),
        (
            Box::new(|f, b| {
                let b = b.to_string();
                f.checkpoints(|g| {
                    g.sources.insert(
                        b,
                        SourceReply::Unsupported {
                            reason: crate::checkpoint::Reason::Corrupt,
                            detail: "a symlinked record".into(),
                        },
                    )
                });
            }),
            "checkpoint_corrupt",
        ),
        (
            Box::new(|f, b| {
                let b = b.to_string();
                f.checkpoints(|g| {
                    g.sources.insert(
                        b,
                        SourceReply::Capable {
                            image: "other".into(),
                            image_sha256: fake_image_sha(),
                        },
                    )
                });
            }),
            "checkpoint_image_unavailable",
        ),
        // An older helper without `source` closes the frame unanswered.
        (
            Box::new(|f, _| f.checkpoints(|g| g.source_unanswered = true)),
            "checkpoint_io",
        ),
    ];
    for (script, token) in cases {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        script(&fake, s.backend_id.as_deref().unwrap());
        let e = capture(&m, &s, 1000).await.unwrap_err();
        assert_eq!(reason(&e), Some(token), "{e:?}");
        assert_eq!(charge(&m), (0, 0));
        assert_eq!(
            m.store
                .checkpoint_page(None, None, None, 10)
                .unwrap()
                .rows
                .len(),
            0
        );
        assert_eq!(calls(&fake, "capture"), 0);
        assert!(
            m.store
                .sandbox(&s.id)
                .unwrap()
                .unwrap()
                .lifecycle
                .image_identity
                .is_none()
        );
        assert!(!m.slot(&s.id).capturing());
    }
}

/// The lead's condition: kiln's rehash at capture disagreeing with the recorded
/// identity ends FAILED with the charge released, never READY.
#[tokio::test]
async fn an_image_rehash_mismatch_fails_releases_and_is_never_ready() {
    for keyed in [false, true] {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        fake.checkpoints(|g| g.capture_image_sha = Some(Digest::of(b"changed tree")));
        let r = req(&s);
        let k = keyed.then(|| key("k1", &r));
        let result = m.capture_checkpoint(r, 1000, k, None).await;
        let c = match (keyed, result) {
            (false, Err(e)) => {
                assert_eq!(reason(&e), Some("checkpoint_image_unavailable"));
                only(&m)
            }
            (true, Ok(row)) => row,
            other => panic!("{other:?}"),
        };
        until("the failed capture's removal", || {
            row(&m, c.id.as_str()).state == CheckpointState::Failed
        })
        .await;
        let c = row(&m, c.id.as_str());
        assert!(c.seal.is_none() && c.ready_at_ms.is_none(), "never READY");
        assert_eq!(c.failure.unwrap().token, "checkpoint_image_unavailable");
        assert_eq!(charge(&m), (0, 0));
        assert!(fake.checkpoints(|g| g.published.is_empty()));
        assert!(!m.slot(&s.id).capturing());
    }
}

#[tokio::test]
async fn a_helper_failure_settles_failed_with_its_reason_and_no_charge() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    fake.checkpoints(|g| {
        g.capture_fail = Some((
            crate::checkpoint::Reason::MetadataUnsupported,
            "an ACL".into(),
        ))
    });
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_metadata_unsupported"));
    let c = only(&m);
    until("FAILED", || {
        row(&m, c.id.as_str()).state == CheckpointState::Failed
    })
    .await;
    assert_eq!(charge(&m), (0, 0));
    // Delete of an already absent FAILED row: DELETED, idempotently.
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
}

#[tokio::test]
async fn c0_refusals_allocate_nothing() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let mut r = req(&s);
    r.expiry = None;
    let e = m.capture_checkpoint(r, 1000, None, None).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_expiry_required"));
    assert!(matches!(e, Error::Refused(RefusalCode::InvalidArgument, _)));
    let mut r = req(&s);
    r.expiry = Some(RequestedExpiry {
        max_lifetime_ms: 8 * 86_400_000,
        idle_timeout_ms: 0,
    });
    assert!(matches!(
        m.capture_checkpoint(r, 1000, None, None).await,
        Err(Error::InvalidArgument(_))
    ));
    let mut r = req(&s);
    r.max_size_bytes = (1 << 30) + 1;
    let e = m.capture_checkpoint(r, 1000, None, None).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_size_limit"));
    let mut r = req(&s);
    r.max_size_bytes = 4096;
    assert!(matches!(
        m.capture_checkpoint(r, 1000, None, None).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(fake.checkpoints(|g| g.calls.is_empty()));
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn firecracker_refuses_before_any_helper_call_allocation_or_row() {
    // An allocation-token backend with a checkpoint group scripted anyway: the
    // refusal must not depend on the helper answering.
    let fake = FakeRuntime::fenced().with_checkpoints();
    let (m, fake, _) = engine_with(fake, test_limits());
    m.reconcile().await.unwrap();
    let s = source(&m, 1000).await;
    let before = {
        let ledger = {
            let st = fake.state();
            (
                st.fenced.claims_made,
                st.fenced.issued,
                st.fenced.prepare_calls,
                st.fenced.allocations.len(),
            )
        };
        (
            m.store_resources_for_test(),
            ledger,
            m.store.sandbox(&s.id).unwrap(),
        )
    };
    for keyed in [false, true] {
        let r = req(&s);
        let k = keyed.then(|| key("fc", &r));
        let e = m.capture_checkpoint(r, 1000, k, None).await.unwrap_err();
        assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
        assert!(matches!(e, Error::Refused(RefusalCode::Unimplemented, _)));
    }
    assert!(
        fake.checkpoints(|g| g.calls.is_empty()),
        "no helper call at all"
    );
    let after = {
        let ledger = {
            let st = fake.state();
            (
                st.fenced.claims_made,
                st.fenced.issued,
                st.fenced.prepare_calls,
                st.fenced.allocations.len(),
            )
        };
        (
            m.store_resources_for_test(),
            ledger,
            m.store.sandbox(&s.id).unwrap(),
        )
    };
    assert_eq!(
        before, after,
        "ledger, reservations, rows and runtime unchanged"
    );
    assert_eq!(charge(&m), (0, 0));
    assert!(m.store.checkpoint_request(1000, "fc").unwrap().is_none());
    // A backend with no checkpoint group at all refuses the same way.
    let (m, _, _) = engine_with(FakeRuntime::default(), test_limits());
    let s = source(&m, 1000).await;
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
}

#[tokio::test]
async fn a_disabled_helper_group_or_old_kiln_refuses_before_reserving() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    fake.checkpoints(|g| g.enabled = false);
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("backend_unsupported:workspace_checkpoint"));
    fake.checkpoints(|g| {
        g.enabled = true;
        g.supported = false;
    });
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("sandbox_unsupported:workspace_checkpoint"));
    fake.checkpoints(|g| {
        g.supported = true;
        g.unavailable = true;
    });
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_io"));
    assert_eq!(charge(&m), (0, 0));
    assert_eq!(calls(&fake, "capture"), 0);
}

// --- Races (design 8.2) -------------------------------------------------------------------

#[tokio::test]
async fn capture_and_exec_exclude_each_other() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    // A running Exec: capture refuses busy at once, without waiting or reserving.
    let exec_gate = FakeGate::default();
    fake.state().exec_before_run = Some(exec_gate.clone());
    let running = tokio::spawn({
        let m = Arc::clone(&m);
        let id = s.id.clone();
        async move { m.exec(exec_req(&id, &["echo"])).await }
    });
    exec_gate.entered().await;
    let e = capture(&m, &s, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_busy"));
    exec_gate.release();
    running.await.unwrap().unwrap();
    assert_eq!(charge(&m), (0, 0));
    // A capture holding the source: Exec (and ExecStream's admission) refuses busy.
    let gate = gate_capture(&fake);
    let capturing = tokio::spawn({
        let m = Arc::clone(&m);
        let s = s.clone();
        async move { capture(&m, &s, 1000).await }
    });
    gate.entered().await;
    let e = m.exec(exec_req(&s.id, &["echo"])).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_busy"));
    assert!(matches!(e, Error::FailedPrecondition(_)));
    // Two captures of one source: the second refuses busy, with no queue (root's,
    // since this uid's one worker permit is taken first, as design 4.1 orders).
    let e = capture(&m, &s, 0).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_busy"));
    gate.release();
    assert_eq!(
        capturing.await.unwrap().unwrap().state,
        CheckpointState::Ready
    );
    m.exec(exec_req(&s.id, &["echo"])).await.unwrap();
    assert_eq!(charge(&m), (1, S));
}

#[tokio::test]
async fn source_delete_cancels_the_capture_and_waits_for_its_reader() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let backend = s.backend_id.clone().unwrap();
    let gate = gate_capture(&fake);
    let remove_gate = FakeGate::default();
    fake.checkpoints(|g| g.remove_gate = Some(remove_gate.clone()));
    let capturing = tokio::spawn({
        let m = Arc::clone(&m);
        let s = s.clone();
        async move { capture(&m, &s, 1000).await }
    });
    gate.entered().await;
    let deleting = tokio::spawn({
        let m = Arc::clone(&m);
        let id = s.id.clone();
        async move { m.delete(&id).await }
    });
    // The capture's reader is being removed; the source's storage is still there.
    remove_gate.entered().await;
    assert!(fake.state().sandboxes.contains_key(&backend));
    assert!(!fake.state().removed.contains(&backend));
    remove_gate.release();
    let e = capturing.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"));
    let deleted = deleting.await.unwrap().unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    let c = only(&m);
    assert_eq!(c.state, CheckpointState::Failed);
    assert_eq!(charge(&m), (0, 0));
    assert!(fake.checkpoints(|g| g.workers.is_empty() && g.staging.is_empty()));
    // The source row is gone; the failed checkpoint keeps its provenance.
    assert_eq!(c.source_sandbox_id, s.id);
}

#[tokio::test]
async fn source_lifetime_expiry_cancels_a_capture_and_idle_waits_for_it() {
    let (m, fake, clock) = engine();
    let s = source_with(&m, 1000, 60, 0).await;
    let gate = gate_capture(&fake);
    let capturing = tokio::spawn({
        let m = Arc::clone(&m);
        let s = s.clone();
        async move { capture(&m, &s, 1000).await }
    });
    gate.entered().await;
    clock.advance(61 * SEC);
    m.expire_due();
    let e = capturing.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"));
    until("source expiry", || {
        m.store.sandbox(&s.id).unwrap().unwrap().state == SandboxState::Deleted
    })
    .await;
    assert_eq!(charge(&m), (0, 0));

    // Idle: the source's idle timer is paused while a capture holds it, and resumes
    // from the old activity (a capture is not a renewal).
    let s = source_with(&m, 1000, 0, 30).await;
    let gate = gate_capture(&fake);
    let capturing = tokio::spawn({
        let m = Arc::clone(&m);
        let s = s.clone();
        async move { capture(&m, &s, 1000).await }
    });
    gate.entered().await;
    clock.advance(31 * SEC);
    m.expire_due();
    tokio::task::yield_now().await;
    assert_eq!(
        m.store.sandbox(&s.id).unwrap().unwrap().state,
        SandboxState::Ready
    );
    gate.release();
    assert_eq!(
        capturing.await.unwrap().unwrap().state,
        CheckpointState::Ready
    );
    m.expire_due();
    until("idle expiry after the capture", || {
        m.store.sandbox(&s.id).unwrap().unwrap().state == SandboxState::Deleted
    })
    .await;
    // The checkpoint survives its source.
    assert_eq!(charge(&m), (1, S));
}

#[tokio::test]
async fn checkpoint_delete_during_capture_wins_and_releases() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let gate = gate_capture(&fake);
    let capturing = tokio::spawn({
        let m = Arc::clone(&m);
        let s = s.clone();
        async move { capture(&m, &s, 1000).await }
    });
    gate.entered().await;
    let c = only(&m);
    assert_eq!(c.state, CheckpointState::Capturing);
    assert_eq!(charge(&m), (1, 1 << 30), "charged R while capturing");
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(d.deletion_reason, Some(DeletionReason::Requested));
    let e = capturing.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_not_ready"));
    assert_eq!(charge(&m), (0, 0));
    assert!(fake.checkpoints(|g| g.published.is_empty() && g.workers.is_empty()));
    m.exec(exec_req(&s.id, &["echo"])).await.unwrap();
}

#[tokio::test]
async fn a_departed_waiter_never_cancels_a_capture_or_a_removal() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let gate = gate_capture(&fake);
    let waiter = {
        let m = Arc::clone(&m);
        let s = s.clone();
        tokio::spawn(async move { capture(&m, &s, 1000).await })
    };
    gate.entered().await;
    waiter.abort();
    let _ = waiter.await;
    gate.release();
    until("READY without its waiter", || {
        m.store
            .checkpoint_page(None, None, None, 1)
            .unwrap()
            .rows
            .first()
            .is_some_and(|c| c.state == CheckpointState::Ready)
    })
    .await;
    assert!(!m.slot(&s.id).capturing());
    // Delete's waiter leaves while the helper removes: the retrier still finishes.
    let c = only(&m);
    fake.checkpoints(|g| {
        g.removals
            .push_back(FakeRemoval::Retained(crate::checkpoint::Reason::Busy))
    });
    let deleting = {
        let m = Arc::clone(&m);
        let id = c.id.to_string();
        tokio::spawn(async move { m.delete_checkpoint(&id, 1000, false).await })
    };
    let e = deleting.await.unwrap().unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_busy"));
    until("the background removal", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(charge(&m), (0, 0));
}

// --- Delete (D1-D3) ---------------------------------------------------------------------

#[tokio::test]
async fn removal_retries_busy_and_unavailable_until_absent_keeping_the_charge() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let c = capture(&m, &s, 1000).await.unwrap();
    fake.checkpoints(|g| {
        g.removals.extend([
            FakeRemoval::Retained(crate::checkpoint::Reason::Busy),
            FakeRemoval::Unavailable,
            FakeRemoval::LoseReply,
        ])
    });
    let e = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_busy"));
    let deleting = row(&m, c.id.as_str());
    assert_eq!(deleting.state, CheckpointState::Deleting);
    assert!(deleting.is_charged());
    until("ABSENT after retries", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(charge(&m), (0, 0));
    assert!(calls(&fake, "remove") >= 4);
    // Every removal dispatch had a fresh nonce; only the last one's ABSENT released.
    let done = row(&m, c.id.as_str());
    let evidence = m
        .store
        .checkpoint_evidence(&done.release_evidence_id.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(evidence.evidence.operation, done.removal.unwrap().operation);
}

#[tokio::test]
async fn generation_mismatch_or_corrupt_keeps_the_charge_records_it_and_blocks_allocation() {
    for (scripted, token) in [
        (
            crate::checkpoint::Reason::GenerationMismatch,
            "checkpoint_generation_mismatch",
        ),
        (crate::checkpoint::Reason::Corrupt, "checkpoint_corrupt"),
    ] {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        let c = capture(&m, &s, 1000).await.unwrap();
        fake.checkpoints(|g| g.removals.push_back(FakeRemoval::Retained(scripted)));
        let e = m
            .delete_checkpoint(c.id.as_str(), 1000, false)
            .await
            .unwrap_err();
        assert_eq!(reason(&e), Some("checkpoint_corrupt"));
        assert!(matches!(e, Error::Refused(RefusalCode::DataLoss, _)));
        let kept = row(&m, c.id.as_str());
        assert_eq!(kept.state, CheckpointState::Deleting);
        assert_eq!(kept.failure.unwrap().token, token);
        assert_eq!(charge(&m), (1, S), "the charge is kept");
        // An unexplained artifact blocks new allocations: sandboxes and captures.
        assert!(matches!(
            m.create_owned(CreateRequest::default(), 1000).await,
            Err(Error::FailedPrecondition(_))
        ));
        assert!(matches!(
            capture(&m, &s, 1000).await,
            Err(Error::FailedPrecondition(_))
        ));
        // No background retrier hides it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(calls(&fake, "remove"), 1);
    }
}

// --- Ownership --------------------------------------------------------------------------

#[tokio::test]
async fn foreign_ids_are_not_found_and_root_follows_the_design() {
    let (m, _, _) = engine();
    let mine = source(&m, 1000).await;
    let c = capture(&m, &mine, 1000).await.unwrap();
    // Another user: NotFound for the source and for the checkpoint, like a missing ID.
    assert!(matches!(
        capture(&m, &mine, 1001).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        m.get_checkpoint(c.id.as_str(), 1001),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        m.delete_checkpoint(c.id.as_str(), 1001, false).await,
        Err(Error::NotFound(_))
    ));
    let missing = CheckpointId::random();
    assert!(matches!(
        m.get_checkpoint(missing.as_str(), 1000),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        m.get_checkpoint("cp-nope", 1000),
        Err(Error::NotFound(_))
    ));
    assert!(
        m.list_checkpoints(1001, None, None, 10)
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(
        m.list_checkpoints(1001, Some(&mine.id), None, 10)
            .unwrap()
            .rows
            .is_empty()
    );
    // Root captures another user's source: a root-owned checkpoint the user can't see.
    let rooted = capture(&m, &mine, 0).await.unwrap();
    assert_eq!(rooted.owner_uid, 0);
    assert!(matches!(
        m.get_checkpoint(rooted.id.as_str(), 1000),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        m.list_checkpoints(1000, None, None, 10).unwrap().rows.len(),
        1
    );
    assert_eq!(
        m.list_checkpoints(0, Some(&mine.id), None, 10)
            .unwrap()
            .rows
            .len(),
        2
    );
    // Root may inspect and delete the user's.
    m.get_checkpoint(c.id.as_str(), 0).unwrap();
    assert_eq!(
        m.delete_checkpoint(c.id.as_str(), 0, false)
            .await
            .unwrap()
            .state,
        CheckpointState::Deleted
    );
    // Workers and caps are the caller's: root's capture was charged to root.
    assert_eq!(m.store.checkpoint_usage(0).unwrap().uid.live, 1);
}

// --- Keys ---------------------------------------------------------------------------------

#[tokio::test]
async fn capture_keys_return_their_row_conflict_and_release_only_once_deleted() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let r = req(&s);
    let k = key("eval-seed", &r);
    let first = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    assert_eq!(first.request_id.as_deref(), Some("eval-seed"));
    // A retry: the same row, no new capture, no idle refresh.
    let seq = first.activity_seq;
    let again = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    assert_eq!(
        (again.id.clone(), again.activity_seq),
        (first.id.clone(), seq)
    );
    assert_eq!(calls(&fake, "capture"), 1);
    // Another user's identical key is its own scope.
    let theirs = source(&m, 1001).await;
    let rt = req(&theirs);
    m.capture_checkpoint(rt.clone(), 1001, Some(key("eval-seed", &rt)), None)
        .await
        .unwrap();
    // A different request under the key conflicts, even though it is valid.
    let mut other = r.clone();
    other.max_size_bytes = 1 << 20;
    let e = m
        .capture_checkpoint(other.clone(), 1000, Some(key("eval-seed", &other)), None)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("request_id_conflict"));
    // The retry is answered before the source is looked at: even after it is gone.
    m.delete(&s.id).await.unwrap();
    let after = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    assert_eq!(after.id, first.id);
    // Release is refused until DELETED, then frees the key for a new request.
    assert!(
        m.store
            .release_checkpoint_request_id(first.id.as_str())
            .unwrap()
            == crate::store::ReleaseRequestId::NotDeleted
    );
    let deleted = m
        .delete_checkpoint(first.id.as_str(), 1000, true)
        .await
        .unwrap();
    assert_eq!(deleted.state, CheckpointState::Deleted);
    assert!(deleted.request_id_released_at_ms.is_some());
    let s2 = source(&m, 1000).await;
    let r2 = req(&s2);
    let fresh = m
        .capture_checkpoint(r2.clone(), 1000, Some(key("eval-seed", &r2)), None)
        .await
        .unwrap();
    assert_ne!(fresh.id, first.id);
}

#[tokio::test]
async fn a_keyed_retry_joins_the_running_capture_or_reports_in_flight() {
    let (m, fake, _) = engine();
    let s = source(&m, 1000).await;
    let r = req(&s);
    let k = key("join", &r);
    let gate = gate_capture(&fake);
    let original = {
        let (m, r, k) = (Arc::clone(&m), r.clone(), k.clone());
        tokio::spawn(async move { m.capture_checkpoint(r, 1000, Some(k), None).await })
    };
    gate.entered().await;
    // With a deadline: in flight. A different digest: conflict at once.
    let e = m
        .capture_checkpoint(
            r.clone(),
            1000,
            Some(k.clone()),
            Some(Instant::now() + Duration::from_millis(20)),
        )
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_in_flight"));
    let mut other = r.clone();
    other.max_size_bytes = 1 << 20;
    let e = m
        .capture_checkpoint(other.clone(), 1000, Some(key("join", &other)), None)
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some("request_id_conflict"));
    let joined = {
        let (m, r, k) = (Arc::clone(&m), r.clone(), k.clone());
        tokio::spawn(async move { m.capture_checkpoint(r, 1000, Some(k), None).await })
    };
    tokio::task::yield_now().await;
    gate.release();
    let a = original.await.unwrap().unwrap();
    let b = joined.await.unwrap().unwrap();
    assert_eq!((a.id.clone(), a.state), (b.id, CheckpointState::Ready));
    assert_eq!(calls(&fake, "capture"), 1);
}

#[test]
fn the_capture_digest_is_canonical_and_pinned() {
    let r = CaptureRequest {
        sandbox_id: "sb-0123456789abcdef".into(),
        expiry: Some(RequestedExpiry::default()),
        max_size_bytes: 0,
    };
    assert_eq!(
        String::from_utf8(crate::idempotency::canonical_capture_request(&r)).unwrap(),
        r#"{"expiry":{"idle_timeout_ms":0,"max_lifetime_ms":0},"max_size_bytes":0,"sandbox_id":"sb-0123456789abcdef"}"#
    );
    // Golden: python3 -c 'import hashlib;print(hashlib.sha256(b"kilnd.v1.checkpoint-request.1\0"+J).hexdigest())'
    assert_eq!(
        crate::idempotency::capture_request_digest(&r).to_string(),
        CAPTURE_GOLDEN
    );
    let mut absent = r.clone();
    absent.expiry = None;
    let mut sized = r.clone();
    sized.max_size_bytes = 1;
    let mut other = r.clone();
    other.sandbox_id = "sb-0123456789abcdee".into();
    let digests: HashSet<String> = [&r, &absent, &sized, &other]
        .iter()
        .map(|r| crate::idempotency::capture_request_digest(r).to_string())
        .collect();
    assert_eq!(
        digests.len(),
        4,
        "absent and empty expiry differ; every field counts"
    );
}

const CAPTURE_GOLDEN: &str = "cb4f90c24bd81701efe03859020f4934fd026acc22aab8b809da1b5096d13a0d";

// --- Quotas -----------------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_captures_and_creates_never_overspend_any_cap_or_the_shared_disk() {
    let mut limits = test_limits();
    // Room for the sources, then a node disk budget the captures and creates share.
    limits.max_node_disk_bytes = 12 << 30;
    limits.default_disk_bytes = 1 << 30;
    let mut ck = ckpt_limits();
    ck.max_workers = 8;
    ck.max_workers_per_uid = 8;
    ck.budgets.max_per_uid = 3;
    ck.budgets.max_bytes_node = 5 << 30;
    limits.checkpoints = Some(ck);
    let (m, _, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    let mut sources = Vec::new();
    for uid in [1000, 1001] {
        for _ in 0..4 {
            sources.push((uid, source(&m, uid).await));
        }
    }
    // 8 GiB of sandbox promises now; captures reserve R = 1 GiB each until sealed.
    let mut tasks = Vec::new();
    for (uid, s) in sources.clone() {
        let mc = Arc::clone(&m);
        tasks.push(tokio::spawn(async move {
            capture(&mc, &s, uid).await.map(|_| ())
        }));
        let m = Arc::clone(&m);
        tasks.push(tokio::spawn(async move {
            m.create_owned(CreateRequest::default(), uid)
                .await
                .map(|_| ())
        }));
    }
    let mut refused = 0;
    for t in tasks {
        if let Err(e) = t.await.unwrap() {
            refused += 1;
            assert!(
                matches!(e, Error::ResourceExhausted(_)) || reason(&e) == Some("checkpoint_quota"),
                "{e:?}"
            );
        }
        let disk = m.store_resources_for_test().disk_bytes;
        assert!(
            disk <= 12 << 30,
            "the shared disk total never overspends: {disk}"
        );
    }
    assert!(refused > 0, "the budget was contended");
    for uid in [1000, 1001] {
        assert!(m.store.checkpoint_usage(uid).unwrap().uid.live <= 3);
    }
    assert!(m.store.checkpoint_usage(0).unwrap().node.charged_bytes <= 5 << 30);
    assert!(m.store_resources_for_test().disk_bytes <= 12 << 30);
}

#[tokio::test]
async fn worker_permits_refuse_at_once_per_uid() {
    let (m, fake, _) = engine();
    let a = source(&m, 1000).await;
    let b = source(&m, 1000).await;
    let gate = gate_capture(&fake);
    let first = {
        let (m, a) = (Arc::clone(&m), a.clone());
        tokio::spawn(async move { capture(&m, &a, 1000).await })
    };
    gate.entered().await;
    let e = capture(&m, &b, 1000).await.unwrap_err();
    assert_eq!(reason(&e), Some("checkpoint_workers"));
    assert!(matches!(
        e,
        Error::Refused(RefusalCode::ResourceExhausted, _)
    ));
    gate.release();
    first.await.unwrap().unwrap();
    capture(&m, &b, 1000).await.unwrap();
}

// --- Expiry -----------------------------------------------------------------------------------

fn short(s: &Sandbox, lifetime_s: u64, idle_s: u64) -> CaptureRequest {
    CaptureRequest {
        sandbox_id: s.id.clone(),
        expiry: Some(RequestedExpiry {
            max_lifetime_ms: lifetime_s * 1000,
            idle_timeout_ms: idle_s * 1000,
        }),
        max_size_bytes: 0,
    }
}

#[tokio::test]
async fn lifetime_and_idle_expiry_take_the_same_removal_and_get_refreshes_only_idle() {
    let (m, fake, clock) = engine();
    let s = source(&m, 1000).await;
    let c = m
        .capture_checkpoint(short(&s, 100, 30), 1000, None, None)
        .await
        .unwrap();
    assert_eq!(c.expiry.lifetime_ms, 100_000);
    // Get within idle refreshes it.
    clock.advance(20 * SEC);
    let got = m.get_checkpoint(c.id.as_str(), 1000).unwrap();
    assert!(got.activity_seq > c.activity_seq);
    // A foreign probe refreshes nothing.
    let _ = m.get_checkpoint(c.id.as_str(), 1001);
    assert_eq!(row(&m, c.id.as_str()).activity_seq, got.activity_seq);
    clock.advance(25 * SEC);
    m.expire_checkpoints_due();
    assert_eq!(
        row(&m, c.id.as_str()).state,
        CheckpointState::Ready,
        "idle restarted at the Get"
    );
    // List never refreshes.
    m.list_checkpoints(1000, None, None, 10).unwrap();
    clock.advance(6 * SEC);
    m.expire_checkpoints_due();
    until("idle expiry", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    let gone = row(&m, c.id.as_str());
    assert_eq!(gone.deletion_reason, Some(DeletionReason::ExpiredIdle));
    assert!(gone.expiry_intent_at_ms.is_some());
    assert_eq!(charge(&m), (0, 0));

    // Lifetime: Gets keep idle alive but never extend it; a Get once due expires.
    let c = m
        .capture_checkpoint(short(&s, 40, 30), 1000, None, None)
        .await
        .unwrap();
    for _ in 0..2 {
        clock.advance(15 * SEC);
        assert_eq!(
            m.get_checkpoint(c.id.as_str(), 1000).unwrap().state,
            CheckpointState::Ready
        );
        m.expire_checkpoints_due();
    }
    clock.advance(10 * SEC);
    let got = m.get_checkpoint(c.id.as_str(), 1000).unwrap();
    assert_eq!(got.state, CheckpointState::Deleting, "no resurrection");
    until("lifetime expiry", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(
        row(&m, c.id.as_str()).deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );
    assert_eq!(calls(&fake, "remove"), 2, "expiry removes through D1-D3");
}

/// Item 6: a pin whose helper epoch died before dispatch is released only by ABSENT.
/// Idle expiry pauses while it is live; lifetime does not, so the checkpoint still
/// reaches ABSENT and the pin cannot hold disk forever.
#[tokio::test]
async fn a_pin_under_a_dead_epoch_pauses_idle_but_lifetime_still_reaches_absent() {
    let (m, fake, clock) = engine();
    let s = source(&m, 1000).await;
    let c = m
        .capture_checkpoint(short(&s, 120, 20), 1000, None, None)
        .await
        .unwrap();
    // A fork row and its pin under a helper epoch that then dies (store only: C5a has
    // no fork path).
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
    m.checkpoint_timer_refresh(c.id.as_str());
    clock.advance(60 * SEC);
    m.expire_checkpoints_due();
    assert_eq!(
        row(&m, c.id.as_str()).state,
        CheckpointState::Ready,
        "idle paused by the pin"
    );
    clock.advance(61 * SEC);
    m.expire_checkpoints_due();
    until("lifetime ABSENT", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    let pin = m.store.checkpoint_pin(&fork.id).unwrap().unwrap();
    assert_eq!(pin.released_by.as_deref(), Some("absent"));
    assert_eq!(charge(&m), (0, 0));
    assert!(fake.checkpoints(|g| g.published.is_empty()));
}

// --- Crash recovery (design 10) -----------------------------------------------------------

async fn persistent() -> (
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
    (tmp, dir, m, fake, clock)
}

/// Commits C1 directly (a crash right after it): a CAPTURING row bound to the
/// helper's current epoch, with no dispatch.
async fn c1_only(m: &M, fake: &FakeRuntime, s: &Sandbox) -> Checkpoint {
    // Record the identity the way a first capture does.
    let (epoch, boot) = fake.checkpoints(|g| (g.epoch, g.boot));
    let new = NewCheckpoint {
        id: CheckpointId::random(),
        owner_uid: 1000,
        generation: 1,
        source_sandbox_id: s.id.clone(),
        capture: HelperDispatch {
            operation: Id128::random(),
            helper_epoch: epoch,
            boot_id: boot,
        },
        max_size_bytes: 1 << 20,
        writable_paths: normalized_paths(&s.spec.writable_paths),
        excluded_paths: EXCLUDED_PATHS.map(String::from).to_vec(),
        expiry: CheckpointExpiry {
            lifetime_ms: 86_400_000,
            idle_ms: 3_600_000,
        },
        request_id: None,
        source_identity: Some(crate::model::ImageIdentity {
            content_sha256: fake_image_sha(),
            checkpoint_format_version: 1,
        }),
    };
    match m
        .store
        .reserve_checkpoint(&new, &ckpt_limits().budgets, m.sandbox_budgets(), None)
        .unwrap()
    {
        crate::store::ReserveCheckpoint::Inserted(c) => *c,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn crash_after_c1_before_the_helper_settles_failed_with_no_recapture() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = c1_only(&m, &fake, &s).await;
    assert_eq!(charge(&m), (1, 1 << 20));
    let m = restart(m, &dir, &fake, &clock).await;
    until("FAILED", || {
        row(&m, c.id.as_str()).state == CheckpointState::Failed
    })
    .await;
    assert_eq!(
        row(&m, c.id.as_str()).failure.unwrap().token,
        "checkpoint_io"
    );
    assert_eq!(charge(&m), (0, 0));
    assert_eq!(
        calls(&fake, "capture"),
        0,
        "never re-captured under the old binding"
    );
}

#[tokio::test]
async fn crash_mid_copy_reaps_the_worker_removes_staging_and_fails() {
    for helper_restarts in [false, true] {
        let (_tmp, dir, m, fake, clock) = persistent().await;
        let s = source(&m, 1000).await;
        let gate = gate_capture(&fake);
        let capturing = {
            let (m, s) = (Arc::clone(&m), s.clone());
            tokio::spawn(async move { capture(&m, &s, 1000).await })
        };
        gate.entered().await;
        let c = only(&m);
        capturing.abort();
        if helper_restarts {
            fake.checkpoints(|g| g.restart());
        }
        let m = restart(m, &dir, &fake, &clock).await;
        until("FAILED", || {
            row(&m, c.id.as_str()).state == CheckpointState::Failed
        })
        .await;
        assert_eq!(charge(&m), (0, 0));
        assert!(fake.checkpoints(|g| g.staging.is_empty() && g.workers.is_empty()));
        assert!(row(&m, c.id.as_str()).seal.is_none());
    }
}

#[tokio::test]
async fn crash_between_complete_and_ready_discards_the_artifact() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = c1_only(&m, &fake, &s).await;
    // C3 published, C4 never committed.
    fake.checkpoints(|g| {
        g.published.insert(c.id.to_string(), 1);
    });
    let m = restart(m, &dir, &fake, &clock).await;
    until("FAILED", || {
        row(&m, c.id.as_str()).state == CheckpointState::Failed
    })
    .await;
    assert!(
        fake.checkpoints(|g| g.published.is_empty()),
        "discarded, not promoted"
    );
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn crash_after_ready_keeps_it_and_a_key_retry_returns_it() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let r = req(&s);
    let k = key("lost-reply", &r);
    let c = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    let m = restart(m, &dir, &fake, &clock).await;
    let again = m.capture_checkpoint(r, 1000, Some(k), None).await.unwrap();
    assert_eq!(
        (again.id.clone(), again.state),
        (c.id, CheckpointState::Ready)
    );
    assert_eq!(
        again.activity_seq, c.activity_seq,
        "no idle refresh from a retry"
    );
    assert_eq!(calls(&fake, "capture"), 1);
    assert_eq!(charge(&m), (1, S));
}

#[tokio::test]
async fn crash_after_d1_or_after_d2_completes_the_removal() {
    for d2_done in [false, true] {
        let (_tmp, dir, m, fake, clock) = persistent().await;
        let s = source(&m, 1000).await;
        let c = capture(&m, &s, 1000).await.unwrap();
        m.store
            .publish_checkpoint_delete_intent(c.id.as_str(), DeletionReason::Requested)
            .unwrap();
        if d2_done {
            // The helper removed it and certified ABSENT; the reply never arrived.
            fake.checkpoints(|g| g.removals.push_back(FakeRemoval::LoseReply));
            let _ = m.removal_attempt(c.id.as_str()).await;
            assert!(fake.checkpoints(|g| g.published.is_empty()));
        }
        assert_eq!(charge(&m), (1, S), "no credit at D1 or D2");
        let m = restart(m, &dir, &fake, &clock).await;
        until("DELETED", || {
            row(&m, c.id.as_str()).state == CheckpointState::Deleted
        })
        .await;
        assert_eq!(charge(&m), (0, 0));
    }
}

#[tokio::test]
async fn a_ready_row_with_a_missing_artifact_is_quarantined_until_deleted() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = capture(&m, &s, 1000).await.unwrap();
    fake.checkpoints(|g| {
        g.published.clear();
    });
    let m = restart(m, &dir, &fake, &clock).await;
    let q = row(&m, c.id.as_str());
    assert_eq!(q.state, CheckpointState::Quarantined);
    assert_eq!(q.failure.unwrap().token, "checkpoint_corrupt");
    assert_eq!(charge(&m), (1, S), "quarantine keeps the charge");
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, false)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn unexplained_artifacts_or_an_incomplete_inventory_block_allocation() {
    for incomplete in [false, true] {
        let (_tmp, dir, m, fake, clock) = persistent().await;
        let s = source(&m, 1000).await;
        capture(&m, &s, 1000).await.unwrap();
        fake.checkpoints(|g| {
            if incomplete {
                g.inventory_incomplete = true;
            } else {
                g.inventory_extra.push(CheckpointId::random());
            }
        });
        let limits = m.limits.clone();
        m.begin_shutdown();
        m.drain_operations().await;
        drop(m);
        let m = on_disk(&dir, &fake, &clock, &limits);
        let reconciled = m.reconcile().await.unwrap();
        assert!(reconciled.checkpoints_blocked && reconciled.admission_blocked);
        assert!(matches!(
            m.create_owned(CreateRequest::default(), 1000).await,
            Err(Error::FailedPrecondition(_))
        ));
        assert!(matches!(
            capture(&m, &s, 1000).await,
            Err(Error::FailedPrecondition(_))
        ));
        assert_eq!(charge(&m), (1, S), "nothing silently swept or freed");
    }
}

#[tokio::test]
async fn a_reboot_rebases_checkpoint_anchors_without_extending_lifetime() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let s = source(&m, 1000).await;
    let c = m
        .capture_checkpoint(short(&s, 100, 60), 1000, None, None)
        .await
        .unwrap();
    clock.advance(30 * SEC);
    let limits = m.limits.clone();
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    fake.state().sandboxes.clear();
    clock.reboot("boot-b", 5_000, 20 * SEC);
    let m = on_disk(&dir, &fake, &clock, &limits);
    m.reconcile().await.unwrap();
    assert_eq!(
        m.rebase_expiry_clocks().unwrap(),
        2,
        "the source and the checkpoint"
    );
    let rebased = row(&m, c.id.as_str());
    assert_eq!(rebased.clock_boot_id.as_deref(), Some("boot-b"));
    assert_eq!(rebased.ready_boottime_ms, Some(5_000 - 50 * SEC));
    assert_eq!(rebased.activity_boottime_ms, Some(5_000 - 50 * SEC));
    assert_eq!(m.rebase_expiry_clocks().unwrap(), 0, "once");
    m.rebuild_expiry().unwrap();
    m.start_checkpoints().unwrap();
    clock.advance(10 * SEC - 1);
    m.expire_checkpoints_due();
    assert_eq!(row(&m, c.id.as_str()).state, CheckpointState::Ready);
    clock.advance(1);
    m.expire_checkpoints_due();
    until("idle after the reboot", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
}

#[path = "checkpoint_fix_tests.rs"]
mod fix;
