//! Checkpoint milestone C5b-1: the checkpoint RPCs and `CreateSandboxRequest.
//! from_checkpoint` end to end through the gRPC service (`service.rs`,
//! `service/checkpoint.rs`), over the C5a engine, the fake backend's scripted helper
//! group and the real schema 16 store: capture, fork, independence and delete; forks
//! racing checkpoint delete, expiry, source delete and a daemon restart; ownership;
//! keys; quotas at the boundary; cancellation; the feature off, with and without
//! durable state; the Firecracker refusal; and list pages.

use kilnd_api::v1 as pb;
use pb::kilnd_service_server::KilndService;
use prost::Message;
use tonic::{Code, Request, Status};

use super::*;
use crate::admission::ConnectionLane;
use crate::server::PeerIdentity;
use crate::service::{REASON_KEY, Service};

type Api = Arc<Service<FakeRuntime>>;

fn api(m: &M) -> Api {
    Arc::new(Service::new(Arc::clone(m)))
}

fn as_uid<T>(message: T, uid: u32) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(PeerIdentity {
        uid: Some(uid),
        lane: ConnectionLane::General,
    });
    request
}

/// A request carrying the caller's `grpc-timeout`, as tonic receives it.
fn with_timeout<T>(message: T, uid: u32, timeout: &'static str) -> Request<T> {
    let mut request = as_uid(message, uid);
    request
        .metadata_mut()
        .insert("grpc-timeout", timeout.parse().unwrap());
    request
}

fn trailer(s: &Status) -> Option<&str> {
    s.metadata().get(REASON_KEY).map(|v| v.to_str().unwrap())
}

/// A typed refusal: its code, its trailer and its message's token prefix agree.
#[track_caller]
fn refused(s: &Status, code: Code, token: &str) {
    assert_eq!(s.code(), code, "{s:?}");
    assert_eq!(trailer(s), Some(token), "{s:?}");
    assert!(
        s.message().starts_with(&format!("{token}: ")),
        "{s:?}"
    );
}

const UNSUPPORTED: &str = "backend_unsupported:workspace_checkpoint";

async fn api_source(s: &Api, uid: u32) -> pb::Sandbox {
    s.create_sandbox(as_uid(pb::CreateSandboxRequest::default(), uid))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
}

fn capture_msg(sandbox_id: &str) -> pb::CheckpointSandboxRequest {
    pb::CheckpointSandboxRequest {
        sandbox_id: sandbox_id.into(),
        expiry: Some(pb::ExpiryPolicy::default()),
        ..Default::default()
    }
}

async fn api_capture(s: &Api, sandbox_id: &str, uid: u32) -> Result<pb::Checkpoint, Status> {
    s.checkpoint_sandbox(as_uid(capture_msg(sandbox_id), uid))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap())
}

async fn api_get(s: &Api, id: &str, uid: u32) -> Result<pb::Checkpoint, Status> {
    s.get_checkpoint(as_uid(pb::GetCheckpointRequest { id: id.into() }, uid))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap())
}

async fn api_delete(s: &Api, id: &str, uid: u32) -> Result<pb::Checkpoint, Status> {
    s.delete_checkpoint(as_uid(
        pb::DeleteCheckpointRequest {
            id: id.into(),
            release_request_id: false,
        },
        uid,
    ))
    .await
    .map(|r| r.into_inner().checkpoint.unwrap())
}

fn fork_msg(checkpoint: &str) -> pb::CreateSandboxRequest {
    pb::CreateSandboxRequest {
        from_checkpoint: checkpoint.into(),
        ..Default::default()
    }
}

async fn api_fork(s: &Api, checkpoint: &str, uid: u32) -> Result<pb::Sandbox, Status> {
    s.create_sandbox(as_uid(fork_msg(checkpoint), uid))
        .await
        .map(|r| r.into_inner().sandbox.unwrap())
}

async fn api_sandbox(s: &Api, id: &str, uid: u32) -> pb::Sandbox {
    s.get_sandbox(as_uid(
        pb::GetSandboxRequest {
            id: id.into(),
            execution_limit: 0,
        },
        uid,
    ))
    .await
    .unwrap()
    .into_inner()
    .sandbox
    .unwrap()
}

async fn api_exec(s: &Api, id: &str, uid: u32) -> Result<pb::Execution, Status> {
    s.exec(as_uid(
        pb::ExecRequest {
            sandbox_id: id.into(),
            argv: vec!["true".into()],
            ..Default::default()
        },
        uid,
    ))
    .await
    .map(|r| r.into_inner().execution.unwrap())
}

async fn api_list(
    s: &Api,
    uid: u32,
    sandbox_id: &str,
    page_size: u32,
    page_token: &str,
) -> Result<pb::ListCheckpointsResponse, Status> {
    s.list_checkpoints(as_uid(
        pb::ListCheckpointsRequest {
            sandbox_id: sandbox_id.into(),
            page_size,
            page_token: page_token.into(),
        },
        uid,
    ))
    .await
    .map(|r| r.into_inner())
}

/// Every checkpoint ID the caller can see, newest first, page by page.
async fn ids(s: &Api, uid: u32, sandbox_id: &str) -> Vec<String> {
    let (mut out, mut token) = (Vec::new(), String::new());
    loop {
        let page = api_list(s, uid, sandbox_id, 2, &token).await.unwrap();
        out.extend(page.checkpoints.into_iter().map(|c| c.id));
        token = page.next_page_token;
        if token.is_empty() {
            return out;
        }
    }
}

fn state(c: &pb::Checkpoint) -> pb::CheckpointState {
    pb::CheckpointState::try_from(c.state).unwrap()
}

fn sandbox_state(s: &pb::Sandbox) -> pb::SandboxState {
    pb::SandboxState::try_from(s.state).unwrap()
}

fn gate_restore(fake: &FakeRuntime) -> FakeGate {
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.restore_gate = Some(gate.clone()));
    gate
}

/// Startup as `main.rs` runs it.
async fn startup(m: &M) {
    m.reconcile().await.unwrap();
    m.rebase_expiry_clocks().unwrap();
    m.rebase_create_requests().unwrap();
    m.prune().unwrap();
    m.rebuild_expiry().unwrap();
    m.start_checkpoints().unwrap();
}

/// A clean stop and a start on the same state with `limits`.
async fn restart_with(
    m: M,
    dir: &std::path::Path,
    fake: &FakeRuntime,
    clock: &ManualClock,
    limits: Limits,
) -> M {
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    let m = on_disk(dir, fake, clock, &limits);
    startup(&m).await;
    m
}

fn store_calls(m: &M) -> usize {
    m.checkpoint.store_calls.swap(0, Ordering::Relaxed)
}

// --- Capture, fork, independence, delete ----------------------------------------------

#[tokio::test]
async fn capture_fork_independence_and_delete_through_the_api() {
    let (m, fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    assert!(src.from_checkpoint.is_empty() && src.checkpoint_content_sha256.is_empty());
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    assert_eq!(state(&c), pb::CheckpointState::Ready);
    assert!(CheckpointId::parse(&c.id).is_ok(), "{}", c.id);
    assert_eq!((c.owner_uid, c.sandbox_id.as_str()), (1000, src.id.as_str()));
    assert_eq!((c.size_bytes, c.content_sha256.len()), (S, 64));
    assert!(c.logical_bytes <= c.size_bytes && c.ready_at_unix_ms != 0);
    assert_eq!(c.image, "alpine");
    assert_eq!(c.image_content_sha256, fake_image_sha().to_string());
    assert_eq!(c.scope, pb::CheckpointScope::PersistentOverlay as i32);
    assert_eq!(c.format_version, crate::checkpoint::FORMAT_VERSION);
    assert_eq!(c.excluded_paths, EXCLUDED_PATHS);
    assert_eq!(
        c.max_size_bytes,
        src.reservation.unwrap().disk_bytes.min(1 << 30),
        "R: min(the source's disk, the per-checkpoint limit)"
    );
    let e = c.expiry.unwrap();
    let policy = e.effective.unwrap();
    assert_eq!(
        (policy.max_lifetime_ms, policy.idle_timeout_ms),
        (DEFAULT_CHECKPOINT_LIFETIME_MS, DEFAULT_CHECKPOINT_IDLE_MS)
    );
    assert!(e.lifetime_expires_at_unix_ms > e.idle_expires_at_unix_ms);
    assert!(e.idle_expires_at_unix_ms > 0 && !e.idle_paused);
    assert_eq!(e.last_activity_at_unix_ms, c.ready_at_unix_ms);
    assert!(c.failure_reason.is_empty() && c.request_id.is_empty());
    assert_eq!(api_get(&s, &c.id, 1000).await.unwrap().content_sha256, c.content_sha256);

    // Two forks: independent READY sandboxes with immutable provenance.
    let f1 = api_fork(&s, &c.id, 1000).await.unwrap();
    let f2 = api_fork(&s, &c.id, 1000).await.unwrap();
    for f in [&f1, &f2] {
        assert_eq!(sandbox_state(f), pb::SandboxState::Ready);
        assert_eq!(f.from_checkpoint, c.id);
        assert_eq!(f.checkpoint_content_sha256, c.content_sha256);
        assert_eq!(f.owner_uid, 1000);
        api_exec(&s, &f.id, 1000).await.unwrap();
    }
    assert_ne!(f1.backend_id, f2.backend_id);
    assert_eq!(calls(&fake, "restore"), 2);
    // An ordinary create beside them is unchanged.
    let plain = api_source(&s, 1000).await;
    assert!(plain.from_checkpoint.is_empty() && plain.checkpoint_content_sha256.is_empty());

    // The source's deletion leaves the checkpoint and its forks.
    s.delete_sandbox(as_uid(
        pb::DeleteSandboxRequest {
            id: src.id.clone(),
            release_request_id: false,
        },
        1000,
    ))
    .await
    .unwrap();
    assert_eq!(state(&api_get(&s, &c.id, 1000).await.unwrap()), pb::CheckpointState::Ready);
    // A fork from a checkpoint whose source is gone still works.
    let f3 = api_fork(&s, &c.id, 1000).await.unwrap();
    assert_eq!(sandbox_state(&f3), pb::SandboxState::Ready);

    // The checkpoint's deletion leaves every fork.
    let d = api_delete(&s, &c.id, 1000).await.unwrap();
    assert_eq!(state(&d), pb::CheckpointState::Deleted);
    assert_eq!(d.deletion_reason, pb::DeletionReason::Requested as i32);
    assert_eq!(d.size_bytes, S, "S is retained in history");
    for f in [&f1, &f2, &f3] {
        let now = api_sandbox(&s, &f.id, 1000).await;
        assert_eq!(sandbox_state(&now), pb::SandboxState::Ready);
        assert_eq!(now.from_checkpoint, c.id);
        api_exec(&s, &f.id, 1000).await.unwrap();
    }
    assert_eq!(charge(&m), (0, 0));
    // Deleting again is idempotent; a fork from it is refused before allocation.
    assert_eq!(
        state(&api_delete(&s, &c.id, 1000).await.unwrap()),
        pb::CheckpointState::Deleted
    );
    let rows = m.store.sandboxes(true).unwrap().len();
    let e = api_fork(&s, &c.id, 1000).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_not_ready");
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows);
    // A fork's own deletion leaves the others.
    s.delete_sandbox(as_uid(
        pb::DeleteSandboxRequest {
            id: f1.id.clone(),
            release_request_id: false,
        },
        1000,
    ))
    .await
    .unwrap();
    assert_eq!(
        sandbox_state(&api_sandbox(&s, &f2.id, 1000).await),
        pb::SandboxState::Ready
    );
}

// --- Races ---------------------------------------------------------------------------

#[tokio::test]
async fn a_fork_racing_its_checkpoint_s_delete_fails_typed_and_nothing_leaks() {
    let (m, fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    let backends = fake.state().sandboxes.len();
    let gate = gate_restore(&fake);
    let running = {
        let s = Arc::clone(&s);
        let id = c.id.clone();
        tokio::spawn(async move { api_fork(&s, &id, 1000).await })
    };
    gate.entered().await;
    let d = api_delete(&s, &c.id, 1000).await.unwrap();
    assert_eq!(state(&d), pb::CheckpointState::Deleted);
    let e = running.await.unwrap().unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_not_ready");
    assert_eq!(fake.state().sandboxes.len(), backends, "no stranded backend");
    assert_eq!(charge(&m), (0, 0));
    assert!(m.live_restores().is_empty());
    drop(gate);
}

#[tokio::test]
async fn a_fork_racing_expiry_waits_for_lifetime_then_fails_typed() {
    let (m, fake, clock) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let mut msg = capture_msg(&src.id);
    msg.expiry = Some(pb::ExpiryPolicy {
        max_lifetime_ms: 60_000,
        idle_timeout_ms: 10_000,
    });
    let c = s
        .checkpoint_sandbox(as_uid(msg, 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    let gate = gate_restore(&fake);
    let running = {
        let s = Arc::clone(&s);
        let id = c.id.clone();
        tokio::spawn(async move { api_fork(&s, &id, 1000).await })
    };
    gate.entered().await;
    // Idle pauses while the restore pins it, and Get says so; lifetime never pauses.
    let pinned = api_get(&s, &c.id, 1000).await.unwrap().expiry.unwrap();
    assert!(pinned.idle_paused && pinned.idle_expires_at_unix_ms == 0);
    clock.advance(30 * SEC);
    m.expire_checkpoints_due();
    assert_eq!(state(&api_get(&s, &c.id, 1000).await.unwrap()), pb::CheckpointState::Ready);
    clock.advance(31 * SEC);
    m.expire_checkpoints_due();
    let e = running.await.unwrap().unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_not_ready");
    until("lifetime ABSENT", || {
        row(&m, c.id.as_str()).state == CheckpointState::Deleted
    })
    .await;
    let d = api_get(&s, &c.id, 1000).await.unwrap();
    assert_eq!(d.deletion_reason, pb::DeletionReason::ExpiredLifetime as i32);
    // A fork after expiry is refused before any allocation.
    let e = api_fork(&s, &c.id, 1000).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_not_ready");
    assert_eq!(charge(&m), (0, 0));
    drop(gate);
}

#[tokio::test]
async fn get_of_a_due_checkpoint_expires_it_and_never_resurrects_it() {
    let (m, _fake, clock) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let mut msg = capture_msg(&src.id);
    msg.expiry = Some(pb::ExpiryPolicy {
        max_lifetime_ms: 600_000,
        idle_timeout_ms: 10_000,
    });
    let c = s
        .checkpoint_sandbox(as_uid(msg, 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    // Get refreshes idle: 9 s later, then 9 s more, still READY.
    clock.advance(9 * SEC);
    let first = api_get(&s, &c.id, 1000).await.unwrap();
    assert!(first.expiry.unwrap().last_activity_at_unix_ms > c.ready_at_unix_ms);
    clock.advance(9 * SEC);
    assert_eq!(state(&api_get(&s, &c.id, 1000).await.unwrap()), pb::CheckpointState::Ready);
    // List does not refresh it: due 10 s after that Get.
    clock.advance(11 * SEC);
    api_list(&s, 1000, "", 0, "").await.unwrap();
    let due = api_get(&s, &c.id, 1000).await.unwrap();
    assert!(
        matches!(
            state(&due),
            pb::CheckpointState::Deleting | pb::CheckpointState::Deleted
        ),
        "{due:?}"
    );
    assert_eq!(due.deletion_reason, pb::DeletionReason::ExpiredIdle as i32);
    let e = api_fork(&s, &c.id, 1000).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_not_ready");
}

/// What a daemon that died mid-fork left: the fork's row, reservation, key record and
/// pin, committed together; then the helper restarted (its reader died with it).
fn committed_fork_of_a_dead_daemon(m: &M, c: &Checkpoint, src: &Sandbox, key: &CreateKey) -> Sandbox {
    let (epoch, boot) = m
        .runtime
        .checkpoints(|g| (g.epoch, g.boot));
    let mut fork = m.store.sandbox(&src.id).unwrap().unwrap();
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
        request_id: Some(key.request_id.clone()),
        ..SandboxLifecycle::default()
    };
    let reader = HelperDispatch {
        operation: Id128::random(),
        helper_epoch: epoch,
        boot_id: boot,
    };
    let admission = crate::store::RequestAdmission {
        sha256: key.sha256,
        max_per_uid: m.limits.create_requests.max_per_uid,
        max_node: m.limits.create_requests.max_node,
    };
    let reserved = m
        .store
        .reserve_fork_sandbox(&fork, m.sandbox_budgets(), Some(&admission), &[], &reader)
        .unwrap();
    assert!(
        matches!(
            reserved,
            crate::store::ReserveFork::Sandbox(ReserveSandbox::Inserted)
        ),
        "{reserved:?}"
    );
    fork
}

#[tokio::test]
async fn a_daemon_restart_keeps_checkpoints_keys_and_settles_an_interrupted_fork_typed() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    startup(&m).await;
    let s = api(&m);
    let src_pb = api_source(&s, 1000).await;
    let mut keyed = capture_msg(&src_pb.id);
    keyed.request_id = "restart-capture".into();
    let c_pb = s
        .checkpoint_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    let ready_fork = api_fork(&s, &c_pb.id, 1000).await.unwrap();
    // A keyed fork the daemon accepted and then lost, with its reader's helper.
    let fork_req = fork_msg(&c_pb.id);
    let mut keyed_fork = fork_req.clone();
    keyed_fork.request_id = "restart-fork".into();
    let key = CreateKey {
        request_id: keyed_fork.request_id.clone(),
        sha256: crate::idempotency::create_digest(&keyed_fork, Some(&c_pb.id)),
    };
    let c = row(&m, &c_pb.id);
    let src = m.load(&src_pb.id).unwrap();
    let lost = committed_fork_of_a_dead_daemon(&m, &c, &src, &key);
    fake.checkpoints(|g| g.restart());
    drop(s);
    let limits = m.limits.clone();
    let m = restart_with(m, &dir, &fake, &clock, limits).await;
    let s = api(&m);
    // The capture key, the checkpoint and the earlier fork survive the restart.
    let again = s
        .checkpoint_sandbox(as_uid(keyed, 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!(again.id, c_pb.id);
    assert_eq!(state(&again), pb::CheckpointState::Ready);
    assert_eq!(
        sandbox_state(&api_sandbox(&s, &ready_fork.id, 1000).await),
        pb::SandboxState::Ready
    );
    // The interrupted fork settled typed; its key's retry returns that row.
    let settled = s
        .create_sandbox(as_uid(keyed_fork, 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(settled.id, lost.id);
    assert_eq!(sandbox_state(&settled), pb::SandboxState::Failed);
    assert!(
        settled.failure_reason.starts_with("checkpoint_io: "),
        "{settled:?}"
    );
    // New forks work after the restart.
    let f = api_fork(&s, &c_pb.id, 1000).await.unwrap();
    assert_eq!(sandbox_state(&f), pb::SandboxState::Ready);
    assert!(!m.allocation_blocked());
}

// --- Ownership -----------------------------------------------------------------------

#[tokio::test]
async fn foreign_ids_are_not_found_and_root_follows_the_design() {
    let (m, _fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    let missing = format!("cp-{}", "0".repeat(32));
    let not_found = |e: Status, id: &str| {
        assert_eq!(e.code(), Code::NotFound, "{e:?}");
        assert_eq!(e.message(), format!("checkpoint {id} not found"));
    };
    // Another uid: every operation NOT_FOUND, exactly as for a missing ID.
    not_found(api_get(&s, &c.id, 2000).await.unwrap_err(), &c.id);
    not_found(api_get(&s, &missing, 2000).await.unwrap_err(), &missing);
    not_found(api_delete(&s, &c.id, 2000).await.unwrap_err(), &c.id);
    let rows = m.store.sandboxes(true).unwrap().len();
    let e = api_fork(&s, &c.id, 2000).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{e:?}");
    let e = api_fork(&s, &missing, 2000).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{e:?}");
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows, "no fork row");
    let e = api_capture(&s, &src.id, 2000).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{e:?}");
    assert!(ids(&s, 2000, "").await.is_empty());
    assert!(ids(&s, 2000, &src.id).await.is_empty());
    // A malformed ID is NOT_FOUND too.
    not_found(api_get(&s, "cp-x", 1000).await.unwrap_err(), "cp-x");
    // The owner's continuation does not work for another caller.
    api_capture(&s, &src.id, 1000).await.unwrap();
    api_capture(&s, &src.id, 1000).await.unwrap();
    let page = api_list(&s, 1000, "", 2, "").await.unwrap();
    assert!(!page.next_page_token.is_empty());
    let e = api_list(&s, 2000, "", 2, &page.next_page_token)
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    // Root sees and uses everyone's; its own captures are root's.
    assert_eq!(api_get(&s, &c.id, 0).await.unwrap().owner_uid, 1000);
    assert_eq!(ids(&s, 0, "").await.len(), 3);
    let mine = api_capture(&s, &src.id, 0).await.unwrap();
    assert_eq!(mine.owner_uid, 0);
    assert_eq!(ids(&s, 1000, "").await.len(), 3, "root's is not 1000's");
    let f = api_fork(&s, &c.id, 0).await.unwrap();
    assert_eq!(f.owner_uid, 0);
    let e = api_get(&s, &mine.id, 1000).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    assert_eq!(
        state(&api_delete(&s, &c.id, 0).await.unwrap()),
        pb::CheckpointState::Deleted
    );
}

// --- Keys ----------------------------------------------------------------------------

#[tokio::test]
async fn keyed_captures_and_forks_retry_to_the_same_result_and_conflict_otherwise() {
    let (m, fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let mut keyed = capture_msg(&src.id);
    keyed.request_id = "capture-1".into();
    let first = s
        .checkpoint_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!(first.request_id, "capture-1");
    let captures = calls(&fake, "capture");
    let retry = s
        .checkpoint_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!(retry.id, first.id);
    assert_eq!(calls(&fake, "capture"), captures, "no second capture");
    // Another uid has its own namespace.
    let src2 = api_source(&s, 2000).await;
    let mut theirs = capture_msg(&src2.id);
    theirs.request_id = "capture-1".into();
    let other = s
        .checkpoint_sandbox(as_uid(theirs, 2000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_ne!(other.id, first.id);
    // A different request under the key conflicts.
    let mut changed = keyed.clone();
    changed.max_size_bytes = 1 << 20;
    let e = s
        .checkpoint_sandbox(as_uid(changed, 1000))
        .await
        .unwrap_err();
    refused(&e, Code::AlreadyExists, "request_id_conflict");
    // The key's grammar is checked.
    let mut bad = keyed.clone();
    bad.request_id = "has space".into();
    let e = s.checkpoint_sandbox(as_uid(bad, 1000)).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);

    // A keyed fork: digest version 2 covers from_checkpoint.
    let mut fork = fork_msg(&first.id);
    fork.request_id = "fork-1".into();
    let f = s
        .create_sandbox(as_uid(fork.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(f.request_id, "fork-1");
    let restores = calls(&fake, "restore");
    let again = s
        .create_sandbox(as_uid(fork.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(again.id, f.id);
    assert_eq!(calls(&fake, "restore"), restores);
    // The same spec without from_checkpoint (version 1) or from another checkpoint is
    // another request.
    let mut legacy = fork.clone();
    legacy.from_checkpoint.clear();
    let e = s.create_sandbox(as_uid(legacy, 1000)).await.unwrap_err();
    refused(&e, Code::AlreadyExists, "request_id_conflict");
    let other_c = api_capture(&s, &src.id, 1000).await.unwrap();
    let mut elsewhere = fork.clone();
    elsewhere.from_checkpoint = other_c.id.clone();
    let e = s.create_sandbox(as_uid(elsewhere, 1000)).await.unwrap_err();
    refused(&e, Code::AlreadyExists, "request_id_conflict");
    // An ordinary keyed create keeps version 1 (its golden digest): its retry matches.
    let plain = pb::CreateSandboxRequest {
        request_id: "plain-1".into(),
        ..Default::default()
    };
    let p = s
        .create_sandbox(as_uid(plain.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    let stored = m.store.create_request(1000, "plain-1").unwrap().unwrap();
    assert_eq!(stored.0, crate::idempotency::request_digest(&plain));
    assert_eq!(
        s.create_sandbox(as_uid(plain, 1000))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
            .id,
        p.id
    );

    // After the checkpoint's deletion: the keyed fork still answers its sandbox, the
    // keyed capture its DELETED row; released, the key makes a new checkpoint.
    api_delete(&s, &first.id, 1000).await.unwrap();
    let after = s
        .create_sandbox(as_uid(fork, 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(after.id, f.id);
    let deleted = s
        .checkpoint_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!((deleted.id.as_str(), state(&deleted)), (first.id.as_str(), pb::CheckpointState::Deleted));
    let released = s
        .delete_checkpoint(as_uid(
            pb::DeleteCheckpointRequest {
                id: first.id.clone(),
                release_request_id: true,
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert!(released.request_id_released);
    let fresh = s
        .checkpoint_sandbox(as_uid(keyed, 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_ne!(fresh.id, first.id);
    assert_eq!(state(&fresh), pb::CheckpointState::Ready);
}

// --- Quotas at the boundary ----------------------------------------------------------

#[tokio::test]
async fn quotas_admit_x_and_refuse_x_plus_one() {
    let mut limits = test_limits();
    let budgets = &mut limits.checkpoints.as_mut().unwrap().budgets;
    budgets.max_bytes_per_uid = 2 * S;
    budgets.max_per_uid = 3;
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let disk = src.reservation.unwrap().disk_bytes;
    let sized = |bytes: u64| {
        let mut msg = capture_msg(&src.id);
        msg.max_size_bytes = bytes;
        msg
    };
    // The size cap: the source's disk is admitted (as R) in principle, one more byte is
    // checkpoint_size_limit, before any reservation.
    let captures = calls(&fake, "capture");
    let e = s
        .checkpoint_sandbox(as_uid(sized(disk.min(1 << 30) + 1), 1000))
        .await
        .unwrap_err();
    refused(&e, Code::ResourceExhausted, "checkpoint_size_limit");
    assert_eq!(calls(&fake, "capture"), captures);
    assert_eq!(charge(&m), (0, 0));
    // Bytes per uid: X = 2S. S, then S + 1 (charged R while capturing) is refused,
    // then S is admitted: exactly X.
    s.checkpoint_sandbox(as_uid(sized(S), 1000)).await.unwrap();
    let e = s
        .checkpoint_sandbox(as_uid(sized(S + 1), 1000))
        .await
        .unwrap_err();
    refused(&e, Code::ResourceExhausted, "checkpoint_quota");
    assert_eq!(charge(&m), (1, S));
    let second = s
        .checkpoint_sandbox(as_uid(sized(S), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!(charge(&m), (2, 2 * S));
    let e = s
        .checkpoint_sandbox(as_uid(sized(S), 1000))
        .await
        .unwrap_err();
    refused(&e, Code::ResourceExhausted, "checkpoint_quota");
    // Another uid has its own budget.
    let theirs = api_source(&s, 2000).await;
    let mut msg = capture_msg(&theirs.id);
    msg.max_size_bytes = S;
    s.checkpoint_sandbox(as_uid(msg, 2000)).await.unwrap();
    // Deleting one frees exactly its charge.
    api_delete(&s, &second.id, 1000).await.unwrap();
    s.checkpoint_sandbox(as_uid(sized(S), 1000)).await.unwrap();
    // The count per uid: 3 live (one deleted does not count).
    let mut limits = test_limits();
    limits.checkpoints.as_mut().unwrap().budgets.max_per_uid = 2;
    let (m, _fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let a = api_capture(&s, &src.id, 1000).await.unwrap();
    api_capture(&s, &src.id, 1000).await.unwrap();
    let e = api_capture(&s, &src.id, 1000).await.unwrap_err();
    refused(&e, Code::ResourceExhausted, "checkpoint_quota");
    api_delete(&s, &a.id, 1000).await.unwrap();
    api_capture(&s, &src.id, 1000).await.unwrap();
    // The count cap holds for every source of the uid.
    let other = api_source(&s, 1000).await;
    let e = api_capture(&s, &other.id, 1000).await.unwrap_err();
    refused(&e, Code::ResourceExhausted, "checkpoint_quota");
    // A fork's disk: exactly S is admitted, S - 1 refused typed before any row.
    let ready = ids(&s, 1000, "")
        .await
        .into_iter()
        .find(|id| *id != a.id)
        .unwrap();
    let sized_fork = |disk: u64| {
        let mut msg = fork_msg(&ready);
        msg.spec = Some(pb::SandboxSpec {
            limits: Some(pb::ResourceLimits {
                disk_bytes: disk,
                ..Default::default()
            }),
            ..Default::default()
        });
        msg
    };
    let rows = m.store.sandboxes(true).unwrap().len();
    let e = s
        .create_sandbox(as_uid(sized_fork(S - 1), 1000))
        .await
        .unwrap_err();
    refused(&e, Code::InvalidArgument, "checkpoint_disk_too_small");
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows, "no row");
    let f = s
        .create_sandbox(as_uid(sized_fork(S), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(sandbox_state(&f), pb::SandboxState::Ready);
    assert_eq!(f.reservation.unwrap().disk_bytes, S);
}

// --- Cancellation and deadlines ------------------------------------------------------

#[tokio::test]
async fn a_canceled_capture_rpc_only_detaches_and_a_keyed_retry_reports_in_flight() {
    let (m, fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let gate = gate_capture(&fake);
    let mut keyed = capture_msg(&src.id);
    keyed.request_id = "slow".into();
    let waiter = {
        let s = Arc::clone(&s);
        let keyed = keyed.clone();
        tokio::spawn(async move { s.checkpoint_sandbox(as_uid(keyed, 1000)).await })
    };
    gate.entered().await;
    // The caller goes away: the capture keeps running.
    waiter.abort();
    let _ = waiter.await;
    let listed = api_list(&s, 1000, "", 0, "").await.unwrap();
    assert_eq!(listed.checkpoints.len(), 1);
    assert_eq!(state(&listed.checkpoints[0]), pb::CheckpointState::Capturing);
    // A keyed retry whose deadline passes first is DEADLINE_EXCEEDED checkpoint_in_flight;
    // the source is busy for a new capture and for Exec.
    let e = s
        .checkpoint_sandbox(with_timeout(keyed.clone(), 1000, "50m"))
        .await
        .unwrap_err();
    refused(&e, Code::DeadlineExceeded, "checkpoint_in_flight");
    let e = api_capture(&s, &src.id, 1000).await.unwrap_err();
    assert!(
        matches!(trailer(&e), Some("checkpoint_busy" | "checkpoint_workers")),
        "{e:?}"
    );
    let e = api_exec(&s, &src.id, 1000).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    gate.release();
    until("the detached capture's READY", || {
        m.store
            .checkpoint(&listed.checkpoints[0].id)
            .unwrap()
            .unwrap()
            .state
            == CheckpointState::Ready
    })
    .await;
    let done = s
        .checkpoint_sandbox(as_uid(keyed, 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!(done.id, listed.checkpoints[0].id);
    assert_eq!(state(&done), pb::CheckpointState::Ready);
    api_exec(&s, &src.id, 1000).await.unwrap();
}

#[tokio::test]
async fn a_canceled_delete_rpc_leaves_the_removal_running() {
    let (m, fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.remove_gate = Some(gate.clone()));
    let waiter = {
        let s = Arc::clone(&s);
        let id = c.id.clone();
        tokio::spawn(async move { api_delete(&s, &id, 1000).await })
    };
    gate.entered().await;
    waiter.abort();
    let _ = waiter.await;
    assert_eq!(state(&api_get(&s, &c.id, 1000).await.unwrap()), pb::CheckpointState::Deleting);
    // DELETING refuses new forks at once.
    let e = api_fork(&s, &c.id, 1000).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_not_ready");
    gate.release();
    until("the detached removal's ABSENT", || {
        row(&m, &c.id).state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(charge(&m), (0, 0));
}

// --- The feature off -----------------------------------------------------------------

#[tokio::test]
async fn feature_off_with_nothing_durable_refuses_every_checkpoint_rpc_before_any_store_query() {
    let mut limits = test_limits();
    limits.checkpoints = None;
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    startup(&m).await;
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let missing = format!("cp-{}", "0".repeat(32));
    store_calls(&m);
    let e = api_capture(&s, &src.id, 1000).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let mut keyed = capture_msg(&src.id);
    keyed.request_id = "off".into();
    let e = s.checkpoint_sandbox(as_uid(keyed, 1000)).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    refused(
        &api_get(&s, &missing, 1000).await.unwrap_err(),
        Code::Unimplemented,
        UNSUPPORTED,
    );
    refused(
        &api_delete(&s, &missing, 1000).await.unwrap_err(),
        Code::Unimplemented,
        UNSUPPORTED,
    );
    refused(
        &api_list(&s, 1000, "", 0, "").await.unwrap_err(),
        Code::Unimplemented,
        UNSUPPORTED,
    );
    let rows = m.store.sandboxes(true).unwrap().len();
    let e = api_fork(&s, &missing, 1000).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let mut keyed_fork = fork_msg(&missing);
    keyed_fork.request_id = "off-fork".into();
    let e = s.create_sandbox(as_uid(keyed_fork, 1000)).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows, "no fork row");
    assert!(m.store.create_request(1000, "off-fork").unwrap().is_none());
    // Ordinary work, keyed included, is as before.
    let plain = pb::CreateSandboxRequest {
        request_id: "plain".into(),
        ..Default::default()
    };
    let p = s
        .create_sandbox(as_uid(plain, 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert!(p.from_checkpoint.is_empty() && p.checkpoint_content_sha256.is_empty());
    api_exec(&s, &p.id, 1000).await.unwrap();
    api_sandbox(&s, &p.id, 1000).await;
    s.list_sandboxes(as_uid(pb::ListSandboxesRequest::default(), 1000))
        .await
        .unwrap();
    assert_eq!(store_calls(&m), 0, "no checkpoint store query on any request path");
    assert!(fake.checkpoints(|g| g.calls.is_empty()), "the helper is never called");
    let caps = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner()
        .runtime_capabilities
        .unwrap();
    assert!(!caps.checkpoint);
    assert!(!caps.features.contains(&(pb::Feature::WorkspaceCheckpoint as i32)));
    assert!(caps.limits.unwrap().checkpoint.is_none());
}

/// The feature turned off over existing checkpoints: Get, List,
/// Delete and keyed retries are served; new captures and forks are refused; nothing
/// else changes.
#[tokio::test]
async fn feature_off_with_rows_serves_get_list_delete_and_keyed_retries_only() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    startup(&m).await;
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let mut keyed = capture_msg(&src.id);
    keyed.request_id = "kept".into();
    let c1 = s
        .checkpoint_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    let c2 = api_capture(&s, &src.id, 1000).await.unwrap();
    let mut keyed_fork = fork_msg(&c1.id);
    keyed_fork.request_id = "kept-fork".into();
    let f = s
        .create_sandbox(as_uid(keyed_fork.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    drop(s);
    let mut limits = m.limits.clone();
    limits.checkpoints = None;
    let m = restart_with(m, &dir, &fake, &clock, limits).await;
    assert!(!m.allocation_blocked());
    let s = api(&m);
    let charged = charge(&m);
    let helper_captures = calls(&fake, "capture");
    let helper_restores = calls(&fake, "restore");
    // Served: Get, List, keyed retries of a capture and of a fork.
    assert_eq!(state(&api_get(&s, &c1.id, 1000).await.unwrap()), pb::CheckpointState::Ready);
    assert_eq!(ids(&s, 1000, "").await, vec![c2.id.clone(), c1.id.clone()]);
    let again = s
        .checkpoint_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .checkpoint
        .unwrap();
    assert_eq!(again.id, c1.id);
    let f_again = s
        .create_sandbox(as_uid(keyed_fork, 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(f_again.id, f.id);
    // Refused: a new capture, keyed or not, and a new fork, keyed or not.
    let e = api_capture(&s, &src.id, 1000).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let mut new_key = keyed.clone();
    new_key.request_id = "new".into();
    let e = s.checkpoint_sandbox(as_uid(new_key, 1000)).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let rows = m.store.sandboxes(true).unwrap().len();
    let e = api_fork(&s, &c1.id, 1000).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let mut new_fork = fork_msg(&c1.id);
    new_fork.request_id = "new-fork".into();
    let e = s.create_sandbox(as_uid(new_fork, 1000)).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows, "no fork row");
    assert_eq!(calls(&fake, "capture"), helper_captures);
    assert_eq!(calls(&fake, "restore"), helper_restores);
    assert_eq!(charge(&m), charged, "nothing reserved");
    // Nothing else changes: the fork runs, ordinary creates work, Health lists no
    // checkpoint feature.
    api_exec(&s, &f.id, 1000).await.unwrap();
    let plain = api_source(&s, 1000).await;
    assert!(plain.from_checkpoint.is_empty());
    let caps = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner()
        .runtime_capabilities
        .unwrap();
    assert!(!caps.checkpoint);
    assert!(!caps.features.contains(&(pb::Feature::WorkspaceCheckpoint as i32)));
    // Served: Delete reaches ABSENT and releases exactly that charge.
    let d = api_delete(&s, &c2.id, 1000).await.unwrap();
    assert_eq!(state(&d), pb::CheckpointState::Deleted);
    assert_eq!(charge(&m), (charged.0 - 1, charged.1 - S));
    assert_eq!(
        sandbox_state(&api_sandbox(&s, &f.id, 1000).await),
        pb::SandboxState::Ready
    );
}

// --- Firecracker ---------------------------------------------------------------------

#[tokio::test]
async fn firecracker_refuses_capture_and_fork_before_any_allocation() {
    let (m, fake, _) = engine();
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    let mut keyed = fork_msg(&c.id);
    keyed.request_id = "fc".into();
    let accepted = s
        .create_sandbox(as_uid(keyed.clone(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    // The backend becomes an allocation-token one (Firecracker's shape).
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
    let rows = m.store.sandboxes(true).unwrap().len();
    let resources = m.store_resources_for_test();
    let helper = fake.checkpoints(|g| g.calls.len());
    let requests = m.store.create_request_counts(1000).unwrap();
    // An accepted keyed fork is answered first, as usual.
    let again = s
        .create_sandbox(as_uid(keyed, 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(again.id, accepted.id);
    // New work is refused UNIMPLEMENTED before prepare.
    let e = api_fork(&s, &c.id, 1000).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let mut new_key = fork_msg(&c.id);
    new_key.request_id = "fc-new".into();
    let e = s.create_sandbox(as_uid(new_key, 1000)).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let e = api_capture(&s, &src.id, 1000).await.unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let after = {
        let st = fake.state();
        (
            st.fenced.claims_made,
            st.fenced.issued,
            st.fenced.prepare_calls,
            st.fenced.allocations.len(),
        )
    };
    assert_eq!(after, before, "no token, preparation or allocation");
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows);
    assert_eq!(m.store_resources_for_test(), resources);
    assert_eq!(fake.checkpoints(|g| g.calls.len()), helper);
    assert_eq!(m.store.create_request_counts(1000).unwrap(), requests);
    // Existing metadata stays readable and deletable.
    assert_eq!(state(&api_get(&s, &c.id, 1000).await.unwrap()), pb::CheckpointState::Ready);
    assert_eq!(ids(&s, 1000, "").await, vec![c.id.clone()]);
}

// --- Lists -----------------------------------------------------------------------------

#[tokio::test]
async fn list_pages_are_newest_first_filter_bound_and_bounded() {
    let mut limits = test_limits();
    limits.max_list_page_size = 3;
    let (m, _fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    let s = api(&m);
    let a = api_source(&s, 1000).await;
    let b = api_source(&s, 1000).await;
    let mut made = Vec::new();
    for _ in 0..4 {
        made.push(api_capture(&s, &a.id, 1000).await.unwrap().id);
    }
    let only_b = api_capture(&s, &b.id, 1000).await.unwrap().id;
    made.push(only_b.clone());
    made.reverse();
    assert_eq!(ids(&s, 1000, "").await, made, "newest first");
    assert_eq!(ids(&s, 1000, &b.id).await, vec![only_b.clone()]);
    assert_eq!(ids(&s, 1000, &a.id).await, made[1..].to_vec());
    // A capture after the first page never shifts a later one.
    let first = api_list(&s, 1000, "", 2, "").await.unwrap();
    assert_eq!(
        first.checkpoints.iter().map(|c| &c.id).collect::<Vec<_>>(),
        made[..2].iter().collect::<Vec<_>>()
    );
    let newer = api_capture(&s, &a.id, 1000).await.unwrap().id;
    let second = api_list(&s, 1000, "", 2, &first.next_page_token).await.unwrap();
    assert_eq!(
        second.checkpoints.iter().map(|c| &c.id).collect::<Vec<_>>(),
        made[2..4].iter().collect::<Vec<_>>()
    );
    assert!(!second.checkpoints.iter().any(|c| c.id == newer));
    // DELETED history is still listed (listing never keeps a checkpoint alive).
    api_delete(&s, &made[4], 1000).await.unwrap();
    let third = api_list(&s, 1000, "", 2, &second.next_page_token).await.unwrap();
    assert_eq!(third.checkpoints.len(), 1);
    assert_eq!(state(&third.checkpoints[0]), pb::CheckpointState::Deleted);
    assert!(third.next_page_token.is_empty());
    // Bounds and refusals.
    let invalid = |e: Status| assert_eq!(e.code(), Code::InvalidArgument, "{e:?}");
    let e = api_list(&s, 1000, "", 0, "").await.unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted, "legacy list over the count bound");
    invalid(api_list(&s, 1000, "", 4, "").await.unwrap_err());
    invalid(api_list(&s, 1000, "", 0, &first.next_page_token).await.unwrap_err());
    invalid(api_list(&s, 1000, &b.id, 2, &first.next_page_token).await.unwrap_err());
    invalid(api_list(&s, 1000, "sb-x", 2, "").await.unwrap_err());
    invalid(api_list(&s, 1000, "", 2, "c1:garbage").await.unwrap_err());
    // The byte bound: one item per page still makes progress; a legacy list fails.
    let mut limits = test_limits();
    let one = pb::ListCheckpointsResponse {
        checkpoints: vec![api_get(&s, &newer, 1000).await.unwrap()],
        next_page_token: crate::service::checkpoint_token_for_tests(1000, "", 1),
    }
    .encoded_len();
    limits.max_list_response_bytes = one + 8;
    let (m2, _fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    let s2 = api(&m2);
    let src = api_source(&s2, 1000).await;
    for _ in 0..3 {
        api_capture(&s2, &src.id, 1000).await.unwrap();
    }
    let page = api_list(&s2, 1000, "", 3, "").await.unwrap();
    assert_eq!(page.checkpoints.len(), 1);
    assert_eq!(ids(&s2, 1000, "").await.len(), 3);
    let e = api_list(&s2, 1000, "", 0, "").await.unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted);
}

// --- The backlog's multi-thread exit check -------------------------------------------

/// Two supervisors of one charged CAPTURING row leave "at once": whichever leaves
/// second sees the first gone and arms, in either order, because each one's removal,
/// its read of the other and its arm are one critical section. (On the current-thread
/// runtime no interleaving can split them; this pins the rule for any runtime.)
#[tokio::test]
async fn of_two_supervisors_leaving_the_later_sees_the_earlier_gone_and_arms() {
    for capture_first in [true, false] {
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        let c = c1_only(&m, &fake, &s).await;
        let id = c.id.to_string();
        let register = |m: &M| {
            m.checkpoint
                .captures
                .lock()
                .unwrap()
                .insert(id.clone(), CancellationToken::new());
            m.checkpoint.retrying.lock().unwrap().insert(id.clone());
        };
        register(&m);
        let (first, second) = if capture_first {
            (Supervisor::Capture, Supervisor::Removal)
        } else {
            (Supervisor::Removal, Supervisor::Capture)
        };
        m.supervisor_exit(&id, first, true);
        assert!(!m.allocation_blocked(), "the other still owns it ({first:?} first)");
        m.supervisor_exit(&id, second, true);
        assert!(m.allocation_blocked(), "nobody owns it ({first:?} first)");
        assert!(m.store.checkpoint_barrier_marked().unwrap());
        assert!(m.checkpoint.captures.lock().unwrap().is_empty());
        assert!(m.checkpoint.retrying.lock().unwrap().is_empty());
        // A settled exit (check false) leaves its entry and arms nothing.
        let (m, fake, _) = engine();
        let s = source(&m, 1000).await;
        let c = c1_only(&m, &fake, &s).await;
        let id = c.id.to_string();
        m.checkpoint.retrying.lock().unwrap().insert(id.clone());
        m.supervisor_exit(&id, Supervisor::Removal, false);
        assert!(!m.allocation_blocked());
        assert!(m.checkpoint.retrying.lock().unwrap().is_empty());
    }
}
