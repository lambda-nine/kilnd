//! Checkpoint milestone C5b-2 through the gRPC service: feature discovery and its
//! withdrawal, Health's checkpoint limits and stats after every C5b-1 scenario, the
//! physical-capacity headroom at its boundary and under concurrent admissions, and
//! Firecracker never advertising.

use super::*;
use crate::checkpoint::wire::StorageFree;
use crate::runtime::fake::FakeCheckpoints;

const GIB: u64 = 1 << 30;
const FEATURE: i32 = pb::Feature::WorkspaceCheckpoint as i32;
const SANDBOX_UNSUPPORTED: &str = "sandbox_unsupported:workspace_checkpoint";

/// Health's probe cache, short enough that [`health`] always sees a fresh probe.
const PROBE_CACHE: Duration = Duration::from_millis(20);

fn fresh_limits() -> Limits {
    Limits {
        health_success_cache: PROBE_CACHE,
        health_failure_cache: PROBE_CACHE,
        ..test_limits()
    }
}

async fn ready_engine() -> (M, FakeRuntime, ManualClock, Api) {
    let (m, fake, clock) = engine_with(FakeRuntime::default().with_checkpoints(), fresh_limits());
    startup(&m).await;
    let s = api(&m);
    (m, fake, clock, s)
}

/// A Health answer from a probe that started after this call (the cache expired).
async fn health(s: &Api, uid: u32) -> pb::HealthResponse {
    tokio::time::sleep(PROBE_CACHE + Duration::from_millis(5)).await;
    s.health(as_uid(pb::HealthRequest {}, uid))
        .await
        .unwrap()
        .into_inner()
}

/// Whether Health lists the feature, after checking that the boolean and the limits
/// agree with the list (design Appendix A).
#[track_caller]
fn advertised(h: &pb::HealthResponse) -> bool {
    let caps = h.runtime_capabilities.as_ref().unwrap();
    let listed = caps.features.contains(&FEATURE);
    assert_eq!(caps.checkpoint, listed, "{caps:?}");
    assert_eq!(
        caps.limits.as_ref().unwrap().checkpoint.is_some(),
        listed,
        "{caps:?}"
    );
    listed
}

#[track_caller]
fn stats(h: &pb::HealthResponse) -> pb::CheckpointStats {
    let s = h
        .admission
        .as_ref()
        .unwrap()
        .checkpoints
        .expect("checkpoint stats");
    assert_eq!(
        h.node_resources
            .as_ref()
            .unwrap()
            .checkpoint_reserved_disk_bytes,
        s.reserved_bytes,
        "the breakdown is the stats' bytes"
    );
    s
}

fn plenty() -> Option<StorageFree> {
    Some(StorageFree {
        runs_free_bytes: 1 << 50,
        backing_free_bytes: Some(1 << 50),
    })
}

fn heal(g: &mut FakeCheckpoints) {
    g.unavailable = false;
    g.enabled = true;
    g.supported = true;
    g.format_version = crate::checkpoint::FORMAT_VERSION;
    g.storage = plenty();
}

/// Free space of exactly `bytes` on runs (the backing has plenty).
fn free(fake: &FakeRuntime, runs: u64, backing: u64) {
    fake.checkpoints(|g| {
        g.storage = Some(StorageFree {
            runs_free_bytes: runs,
            backing_free_bytes: Some(backing),
        })
    });
}

fn sized(sandbox_id: &str, bytes: u64) -> pb::CheckpointSandboxRequest {
    pb::CheckpointSandboxRequest {
        max_size_bytes: bytes,
        ..capture_msg(sandbox_id)
    }
}

async fn capture_sized(
    s: &Api,
    sandbox_id: &str,
    bytes: u64,
    uid: u32,
) -> Result<pb::Checkpoint, Status> {
    s.checkpoint_sandbox(as_uid(sized(sandbox_id, bytes), uid))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap())
}

// --- Discovery -------------------------------------------------------------------------

/// The probe → advertise/withdraw table, through Health: with the flag on and every
/// probe passing, the feature, the boolean and the limits are listed; each failed probe
/// withdraws all three (Health stays SERVING, stats stay, `detail` says why) and new
/// captures and forks are refused typed with nothing reserved, while Get and List are
/// served; the next passing probe advertises again.
#[tokio::test]
async fn discovery_advertises_after_its_probes_and_withdraws_on_each_failure() {
    let (m, fake, _, s) = ready_engine().await;
    let src = api_source(&s, 1000).await;
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    let h = health(&s, 1000).await;
    assert_eq!(h.status, pb::health_response::Status::Serving as i32);
    assert!(advertised(&h), "{h:?}");
    assert!(h.detail.is_empty(), "{}", h.detail);
    let l = h
        .runtime_capabilities
        .unwrap()
        .limits
        .unwrap()
        .checkpoint
        .unwrap();
    assert_eq!(l.max_size_bytes, GIB);
    assert_eq!(
        (l.default_lifetime_ms, l.max_lifetime_ms),
        (86_400_000, 7 * 86_400_000)
    );
    assert_eq!((l.default_idle_ms, l.max_idle_ms), (3_600_000, 86_400_000));
    assert_eq!((l.min_lifetime_ms, l.min_idle_ms), (10_000, 10_000));
    assert_eq!((l.max_entries, l.max_manifest_bytes), (65_536, 16 << 20));
    assert_eq!(
        (
            l.max_path_bytes,
            l.max_directory_depth,
            l.max_link_target_bytes
        ),
        (4096, 128, 1023)
    );
    assert_eq!(
        (l.max_xattrs_per_entry, l.max_xattr_bytes_per_entry),
        (32, 4096)
    );
    assert_eq!(
        (l.operation_timeout_ms, l.helper_timeout_ceiling_ms),
        (120_000, 300_000)
    );
    assert_eq!(
        (l.max_fork_depth, l.worker_memory_bytes, l.worker_max_fds),
        (0, 64 << 20, 256)
    );
    assert_eq!(l.request_retention_ms, 86_400_000);

    type Break = fn(&mut FakeCheckpoints);
    let cases: [(&str, Break, Code, &str); 6] = [
        (
            "the helper is unreachable",
            |g| g.unavailable = true,
            Code::Unavailable,
            "checkpoint_io",
        ),
        (
            "the helper's group is disabled",
            |g| g.enabled = false,
            Code::Unimplemented,
            UNSUPPORTED,
        ),
        (
            "the CLI or the host fails a probe (leases, listing, removal, XFS + project quota, registry trust)",
            |g| {
                g.supported = false;
                g.unsupported_reason = "/var/lib/kiln/runs is mounted without project quotas";
            },
            Code::FailedPrecondition,
            SANDBOX_UNSUPPORTED,
        ),
        (
            "another checkpoint format",
            |g| g.format_version = 2,
            Code::FailedPrecondition,
            SANDBOX_UNSUPPORTED,
        ),
        (
            "capacity unknown (an older helper sends no storage)",
            |g| g.storage = None,
            Code::Unavailable,
            "checkpoint_io",
        ),
        (
            "the loop backing's free space is unknown",
            |g| {
                g.storage = Some(StorageFree {
                    runs_free_bytes: 1 << 50,
                    backing_free_bytes: None,
                })
            },
            Code::Unavailable,
            "checkpoint_io",
        ),
    ];
    for (what, broken, code, token) in cases {
        fake.checkpoints(broken);
        let h = health(&s, 1000).await;
        assert!(!advertised(&h), "{what}: still advertised");
        assert_eq!(
            h.status,
            pb::health_response::Status::Serving as i32,
            "{what}"
        );
        assert!(
            h.detail.starts_with("workspace checkpoints withdrawn: "),
            "{what}: {}",
            h.detail
        );
        let before = stats(&h);
        assert_eq!(before.current_count, 1, "{what}: stats stay visible");
        let (charged, rows) = (charge(&m), m.store.sandboxes(true).unwrap().len());
        let captures = calls(&fake, "capture");
        refused(
            &api_capture(&s, &src.id, 1000).await.unwrap_err(),
            code,
            token,
        );
        refused(&api_fork(&s, &c.id, 1000).await.unwrap_err(), code, token);
        assert_eq!(charge(&m), charged, "{what}: nothing charged");
        assert_eq!(
            m.store.sandboxes(true).unwrap().len(),
            rows,
            "{what}: no fork row"
        );
        assert_eq!(calls(&fake, "capture"), captures, "{what}: no capture");
        let after = stats(&health(&s, 1000).await);
        assert_eq!(
            after.rejected_captures,
            before.rejected_captures + 1,
            "{what}"
        );
        assert_eq!(after.rejected_forks, before.rejected_forks + 1, "{what}");
        // Existing checkpoints stay readable.
        if what != "the helper is unreachable" {
            assert_eq!(api_get(&s, &c.id, 1000).await.unwrap().id, c.id);
        }
        assert_eq!(ids(&s, 1000, "").await, vec![c.id.clone()]);
        fake.checkpoints(heal);
        let h = health(&s, 1000).await;
        assert!(
            advertised(&h),
            "{what}: re-advertised once the probe passes"
        );
        assert!(h.detail.is_empty(), "{what}: {}", h.detail);
    }
    // Admission never trusts the cached bit: with a long cache, Health still lists the
    // feature after the helper lost capacity, and a capture is refused.
    let mut limits = test_limits();
    limits.health_success_cache = Duration::from_secs(3600);
    let (m2, fake2, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    startup(&m2).await;
    let s2 = api(&m2);
    let src2 = api_source(&s2, 1000).await;
    assert!(advertised(&health(&s2, 1000).await));
    fake2.checkpoints(|g| g.storage = None);
    assert!(advertised(&health(&s2, 1000).await), "cached");
    refused(
        &api_capture(&s2, &src2.id, 1000).await.unwrap_err(),
        Code::Unavailable,
        "checkpoint_io",
    );
}

/// A failed or late whole Health probe withdraws the feature with every dynamic one;
/// a slow checkpoint probe withdraws only its own feature.
#[tokio::test]
async fn a_slow_checkpoint_probe_withdraws_only_checkpoints() {
    let mut limits = fresh_limits();
    limits.health_probe_timeout = Duration::from_millis(200);
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    startup(&m).await;
    let s = api(&m);
    assert!(advertised(&health(&s, 1000).await));
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.capabilities_gate = Some(gate.clone()));
    let h = health(&s, 1000).await;
    assert!(!advertised(&h));
    assert_eq!(h.status, pb::health_response::Status::Serving as i32);
    assert_eq!(
        h.detail,
        "workspace checkpoints withdrawn: checkpoint probe timed out"
    );
    gate.release();
    assert!(advertised(&health(&s, 1000).await));
    // The backend's own probe failing: not serving, nothing dynamic listed.
    fake.state().unavailable = true;
    let h = health(&s, 1000).await;
    assert!(!advertised(&h));
    assert_ne!(h.status, pb::health_response::Status::Serving as i32);
    fake.state().unavailable = false;
    assert!(advertised(&health(&s, 1000).await));
}

/// Capture request records are pruned by `--create-request-retention-secs`, so Health
/// advertises that configured value for them, not the one-day minimum, and the same
/// value as `create_request_retention_ms`.
#[tokio::test]
async fn health_reports_the_configured_capture_request_retention() {
    let mut limits = fresh_limits();
    limits.retention.create_request_retention_secs = 3 * 86_400;
    let (m, _, _) = engine_with(FakeRuntime::default().with_checkpoints(), limits);
    startup(&m).await;
    let s = api(&m);
    let h = health(&s, 1000).await;
    assert!(advertised(&h), "{h:?}");
    let l = h.runtime_capabilities.unwrap().limits.unwrap();
    assert_eq!(l.create_request_retention_ms, 3 * 86_400_000);
    assert_eq!(l.checkpoint.unwrap().request_retention_ms, 3 * 86_400_000);
}

/// Design 11.1: Firecracker advertises neither the feature nor the boolean, with the
/// flag on, and Health never asks a checkpoint helper.
#[tokio::test]
async fn firecracker_never_advertises_checkpoints() {
    let (m, fake, _) = engine_with(FakeRuntime::fenced().with_checkpoints(), fresh_limits());
    startup(&m).await;
    let s = api(&m);
    for uid in [0, 1000] {
        let h = health(&s, uid).await;
        assert!(!advertised(&h), "{h:?}");
        assert!(!h.detail.contains("checkpoint"), "{}", h.detail);
    }
    assert_eq!(calls(&fake, "capabilities"), 0, "no checkpoint probe");
}

/// With the flag off, Health lists nothing, reads no checkpoint state and never asks
/// the helper, over many probes (the bytes are pinned by `flag_off_health_bytes_are_
/// unchanged`). With checkpoint rows left from a run with the flag on, the stats come
/// back for cleanup, with no limits and no feature.
#[tokio::test]
async fn flag_off_health_lists_nothing_and_stats_return_only_with_durable_state() {
    let mut off = fresh_limits();
    off.checkpoints = None;
    let (m, fake, _) = engine_with(FakeRuntime::default().with_checkpoints(), off.clone());
    startup(&m).await;
    let s = api(&m);
    store_calls(&m);
    for _ in 0..3 {
        let h = health(&s, 1000).await;
        assert!(!advertised(&h));
        assert!(h.admission.unwrap().checkpoints.is_none());
        assert_eq!(h.node_resources.unwrap().checkpoint_reserved_disk_bytes, 0);
    }
    assert_eq!(store_calls(&m), 0);
    assert!(fake.checkpoints(|g| g.calls.is_empty()));

    let (_tmp, dir, m, fake, clock) = persistent().await;
    startup(&m).await;
    let s = api(&m);
    let src = api_source(&s, 1000).await;
    let c = api_capture(&s, &src.id, 1000).await.unwrap();
    drop(s);
    let m = restart_with(m, &dir, &fake, &clock, off).await;
    let s = api(&m);
    let h = health(&s, 1000).await;
    assert!(!advertised(&h));
    let st = stats(&h);
    assert_eq!((st.current_count, st.reserved_bytes), (1, c.size_bytes));
    assert_eq!(st.current_cleanup_workers, 0);
}

// --- Stats ------------------------------------------------------------------------------

/// Health and its stats after each C5b-1 scenario, for the actor and a bystander: a
/// capture (workers while it runs, then count, bytes, records), a keyed capture's
/// request record, a fork (a restore worker), refusals at quota X/X+1 and at the
/// headroom, a delete (pending while its removal runs), expiry and a restart (counts
/// kept, counters reset). The breakdown is always the stats' bytes, inside the node's
/// reserved disk.
#[tokio::test]
async fn health_stats_follow_every_scenario() {
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let m = restart_with(m, &dir, &fake, &clock, fresh_limits()).await;
    let s = api(&m);
    let st = stats(&health(&s, 1000).await);
    assert_eq!(
        (
            st.max_count,
            st.max_count_per_uid,
            st.max_bytes,
            st.max_bytes_per_uid
        ),
        (128, 32, 8 * GIB, 4 * GIB)
    );
    assert_eq!(
        (
            st.max_workers,
            st.max_workers_per_uid,
            st.max_cleanup_workers
        ),
        (2, 1, 2)
    );
    assert_eq!((st.max_records, st.max_records_per_uid), (32_768, 4096));
    assert_eq!(
        (st.max_request_records, st.max_request_records_per_uid),
        (32_768, 4096)
    );
    assert_eq!(
        (
            st.current_count,
            st.reserved_bytes,
            st.current_records,
            st.request_records
        ),
        (0, 0, 0, 0)
    );
    let src = api_source(&s, 1000).await;
    let disk_before = health(&s, 1000)
        .await
        .node_resources
        .unwrap()
        .reserved_disk_bytes;

    // Capture: one worker while it runs, R charged; then S, one record.
    let gate = gate_capture(&fake);
    let running = {
        let s = Arc::clone(&s);
        let id = src.id.clone();
        tokio::spawn(async move { capture_sized(&s, &id, S, 1000).await })
    };
    gate.entered().await;
    let (mine, other) = (
        stats(&health(&s, 1000).await),
        stats(&health(&s, 1001).await),
    );
    assert_eq!(
        (
            mine.current_workers,
            mine.caller_workers,
            other.caller_workers
        ),
        (1, 1, 0)
    );
    assert_eq!(
        (mine.current_count, mine.caller_count, other.caller_count),
        (1, 1, 0)
    );
    assert_eq!((mine.reserved_bytes, mine.caller_reserved_bytes), (S, S));
    gate.release();
    let c = running.await.unwrap().unwrap();
    let h = health(&s, 1000).await;
    let st = stats(&h);
    assert_eq!(
        (st.current_workers, st.current_count, st.reserved_bytes),
        (0, 1, c.size_bytes)
    );
    assert_eq!(
        (st.current_records, st.caller_records, st.request_records),
        (1, 1, 0)
    );
    assert_eq!(
        h.node_resources.unwrap().reserved_disk_bytes,
        disk_before + c.size_bytes,
        "checkpoint charges are part of the node's reserved disk"
    );
    // A keyed capture adds a request record, the caller's.
    let mut keyed = capture_msg(&src.id);
    keyed.request_id = "stats".into();
    s.checkpoint_sandbox(as_uid(keyed, 1000)).await.unwrap();
    let (mine, other) = (
        stats(&health(&s, 1000).await),
        stats(&health(&s, 1001).await),
    );
    assert_eq!((mine.request_records, mine.caller_request_records), (1, 1));
    assert_eq!(
        (other.request_records, other.caller_request_records),
        (1, 0)
    );
    assert_eq!(
        (mine.current_count, other.current_count, other.caller_count),
        (2, 2, 0)
    );

    // A fork: one restore worker while it restores; the checkpoint count is unchanged.
    let gate = gate_restore(&fake);
    let running = {
        let s = Arc::clone(&s);
        let id = c.id.clone();
        tokio::spawn(async move { api_fork(&s, &id, 1000).await })
    };
    gate.entered().await;
    let st = stats(&health(&s, 1000).await);
    assert_eq!(
        (st.current_workers, st.caller_workers, st.current_count),
        (1, 1, 2)
    );
    gate.release();
    running.await.unwrap().unwrap();
    assert_eq!(stats(&health(&s, 1000).await).current_workers, 0);

    // Refusals: the size cap, a too-small fork, the headroom; each counted once.
    let before = stats(&health(&s, 1000).await);
    refused(
        &capture_sized(&s, &src.id, 2 * GIB, 1000).await.unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_size_limit",
    );
    let small = pb::CreateSandboxRequest {
        spec: Some(pb::SandboxSpec {
            limits: Some(pb::ResourceLimits {
                disk_bytes: c.size_bytes - 1,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..fork_msg(&c.id)
    };
    refused(
        &s.create_sandbox(as_uid(small, 1000)).await.unwrap_err(),
        Code::InvalidArgument,
        "checkpoint_disk_too_small",
    );
    free(&fake, GIB + S - 1, 1 << 50);
    refused(
        &capture_sized(&s, &src.id, S, 1000).await.unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_quota",
    );
    fake.checkpoints(heal);
    let st = stats(&health(&s, 1000).await);
    assert_eq!(st.rejected_captures, before.rejected_captures + 2);
    assert_eq!(st.rejected_forks, before.rejected_forks + 1);
    assert_eq!(
        (st.current_count, st.reserved_bytes),
        (before.current_count, before.reserved_bytes)
    );

    // Delete: pending while its removal runs, then released; history kept.
    let gate = FakeGate::default();
    fake.checkpoints(|g| g.remove_gate = Some(gate.clone()));
    let deleting = {
        let s = Arc::clone(&s);
        let id = c.id.clone();
        tokio::spawn(async move { api_delete(&s, &id, 1000).await })
    };
    gate.entered().await;
    let st = stats(&health(&s, 1000).await);
    assert_eq!(
        (st.pending_deletes, st.current_count),
        (1, 2),
        "DELETING stays charged"
    );
    gate.release();
    deleting.await.unwrap().unwrap();
    let st = stats(&health(&s, 1000).await);
    assert_eq!(
        (st.pending_deletes, st.current_count, st.current_records),
        (0, 1, 2)
    );

    // Expiry: the keyed capture's expiry counts once.
    clock.advance(86_400 * SEC + SEC);
    m.expire_checkpoints_due();
    until("the expiry's release", || charge(&m) == (0, 0)).await;
    let st = stats(&health(&s, 1000).await);
    assert_eq!((st.expired, st.current_count, st.reserved_bytes), (1, 0, 0));
    assert_eq!(st.current_records, 2, "terminal history is retained");
    let rejected = (st.rejected_captures, st.rejected_forks);
    assert!(rejected.0 > 0 && rejected.1 > 0);

    // Restart: counts and records persist; counters since startup reset.
    let src2 = api_source(&s, 1000).await;
    let kept = capture_sized(&s, &src2.id, S, 1000).await.unwrap();
    drop(s);
    let m = restart_with(m, &dir, &fake, &clock, fresh_limits()).await;
    let s = api(&m);
    let st = stats(&health(&s, 1000).await);
    assert_eq!((st.current_count, st.reserved_bytes), (1, kept.size_bytes));
    assert_eq!((st.current_records, st.request_records), (3, 1));
    assert_eq!(
        (st.rejected_captures, st.rejected_forks, st.expired),
        (0, 0, 0)
    );
}

// --- Headroom ---------------------------------------------------------------------------

/// Design 6.3 at the boundary, with headroom H = 1 GiB: a capture of R and a fork of S
/// are admitted with exactly H + R (H + S) free on the lesser of runs and its backing,
/// and refused `checkpoint_quota` one byte short, with nothing reserved and no helper
/// work; capacity unknown is `checkpoint_io`. R is rounded down to 512 bytes.
#[tokio::test]
async fn headroom_admits_exactly_enough_and_refuses_one_byte_short() {
    let (m, fake, _, s) = ready_engine().await;
    let src = api_source(&s, 1000).await;
    let h = GIB;
    for (runs, backing) in [(h + S - 1, 1 << 50), (1 << 50, h + S - 1)] {
        free(&fake, runs, backing);
        let captures = calls(&fake, "capture");
        refused(
            &capture_sized(&s, &src.id, S, 1000).await.unwrap_err(),
            Code::ResourceExhausted,
            "checkpoint_quota",
        );
        assert_eq!(calls(&fake, "capture"), captures);
        assert_eq!(charge(&m), (0, 0));
    }
    free(&fake, h + S, h + S);
    let c = capture_sized(&s, &src.id, S, 1000).await.unwrap();
    assert_eq!(c.max_size_bytes, S);
    // R is rounded down to a multiple of 512 bytes, so kiln's quota is exactly R.
    free(&fake, 1 << 50, 1 << 50);
    let r = capture_sized(&s, &src.id, S + 511, 1000).await.unwrap();
    assert_eq!(r.max_size_bytes, S);
    let r = capture_sized(&s, &src.id, S + 513, 1000).await.unwrap();
    assert_eq!(r.max_size_bytes, S + 512);
    // A fork restores S = the checkpoint's size.
    let rows = m.store.sandboxes(true).unwrap().len();
    free(&fake, h + c.size_bytes - 1, 1 << 50);
    refused(
        &api_fork(&s, &c.id, 1000).await.unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_quota",
    );
    free(&fake, 1 << 50, h + c.size_bytes - 1);
    refused(
        &api_fork(&s, &c.id, 1000).await.unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_quota",
    );
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows, "no fork row");
    assert!(m.store.checkpoint_pins(&c.id).unwrap().is_empty());
    free(&fake, h + c.size_bytes, h + c.size_bytes);
    assert_eq!(
        sandbox_state(&api_fork(&s, &c.id, 1000).await.unwrap()),
        pb::SandboxState::Ready
    );
    // Unknown capacity: refused UNAVAILABLE.
    for storage in [
        None,
        Some(StorageFree {
            runs_free_bytes: 1 << 50,
            backing_free_bytes: None,
        }),
    ] {
        fake.checkpoints(|g| g.storage = storage);
        refused(
            &capture_sized(&s, &src.id, S, 1000).await.unwrap_err(),
            Code::Unavailable,
            "checkpoint_io",
        );
        refused(
            &api_fork(&s, &c.id, 1000).await.unwrap_err(),
            Code::Unavailable,
            "checkpoint_io",
        );
    }
    // Ordinary Create is unaffected by headroom.
    free(&fake, 0, 0);
    api_source(&s, 1000).await;
}

/// Two concurrent admissions cannot spend the same free bytes: a running capture's R
/// and a restoring fork's S count against headroom, and so does one that settled after
/// a later admission's helper answer was asked for (its writes may not show in it).
#[tokio::test]
async fn concurrent_admissions_cannot_share_headroom() {
    let (m, fake, _, s) = ready_engine().await;
    let h = GIB;
    let a = api_source(&s, 1000).await;
    let b = api_source(&s, 1001).await;
    // A running capture holds R = S.
    let gate = gate_capture(&fake);
    let first = {
        let s = Arc::clone(&s);
        let id = a.id.clone();
        tokio::spawn(async move { capture_sized(&s, &id, S, 1000).await })
    };
    gate.entered().await;
    free(&fake, h + 2 * S - 1, 1 << 50);
    refused(
        &capture_sized(&s, &b.id, S, 1001).await.unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_quota",
    );
    // The second capture's answer is asked while the first still runs; the first then
    // settles; the second is still charged with it.
    let caps = FakeGate::default();
    fake.checkpoints(|g| g.capabilities_gate = Some(caps.clone()));
    let second = {
        let s = Arc::clone(&s);
        let id = b.id.clone();
        tokio::spawn(async move { capture_sized(&s, &id, S, 1001).await })
    };
    caps.entered().await;
    gate.release();
    let c = first.await.unwrap().unwrap();
    caps.release();
    refused(
        &second.await.unwrap().unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_quota",
    );
    // A fresh answer, asked after the first settled, admits with H + S.
    free(&fake, h + S, 1 << 50);
    capture_sized(&s, &b.id, S, 1001).await.unwrap();
    // A restoring fork holds S; root's second fork needs H + 2S.
    free(&fake, h + 2 * c.size_bytes - 1, 1 << 50);
    let gate = gate_restore(&fake);
    let fork = {
        let s = Arc::clone(&s);
        let id = c.id.clone();
        tokio::spawn(async move { api_fork(&s, &id, 1000).await })
    };
    gate.entered().await;
    let rows = m.store.sandboxes(true).unwrap().len();
    refused(
        &api_fork(&s, &c.id, 0).await.unwrap_err(),
        Code::ResourceExhausted,
        "checkpoint_quota",
    );
    assert_eq!(m.store.sandboxes(true).unwrap().len(), rows);
    gate.release();
    fork.await.unwrap().unwrap();
    free(&fake, h + c.size_bytes, 1 << 50);
    api_fork(&s, &c.id, 0).await.unwrap();
    // Nothing is left counted once everything settled.
    free(&fake, h + S, h + S);
    capture_sized(&s, &a.id, S, 1000).await.unwrap();
}

// --- Removal while new work is withdrawn (C5b-2 round 1) ------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Removal {
    Delete,
    Expiry,
    Startup,
}

/// C5b-2 adversarial review MEDIUM 1 (the review's PoC, extended). A failed new-work
/// probe (runs not XFS, no project quota, an untrusted registry, free space unknown)
/// withdraws the feature and refuses captures and forks, but removal keeps its own
/// gate (the group, its epoch, a kiln that lists format 1 and checks generations): a
/// Delete, an expiry and startup cleanup each reach DELETED with the charge released,
/// while each probe is withdrawn in turn.
async fn removal_while_withdrawn(how: Removal) {
    type Break = fn(&mut FakeCheckpoints);
    let probes: [(&str, Break); 4] = [
        ("runs is not XFS", |g| {
            g.supported = false;
            g.unsupported_reason = "/var/lib/kiln/runs is not XFS (f_type 0x9123683e)";
        }),
        ("no project quota", |g| {
            g.supported = false;
            g.unsupported_reason = "/var/lib/kiln/runs is mounted without project quotas";
        }),
        ("an untrusted registry", |g| {
            g.supported = false;
            g.unsupported_reason = "kiln's image registry is writable by group or others";
        }),
        ("free space unknown", |g| g.storage = None),
    ];
    let (_tmp, dir, m, fake, clock) = persistent().await;
    let mut m = restart_with(m, &dir, &fake, &clock, fresh_limits()).await;
    let src = api_source(&api(&m), 1000).await;
    let released =
        |m: &M, id: &str| row(m, id).state == CheckpointState::Deleted && charge(m) == (0, 0);
    for (what, broken) in probes {
        let s = api(&m);
        let c = api_capture(&s, &src.id, 1000).await.unwrap();
        let removals = calls(&fake, "remove");
        match how {
            Removal::Delete => {
                fake.checkpoints(broken);
                refuses_new_work(&s, &fake, &src.id, &c.id, what).await;
                let deleted = api_delete(&s, &c.id, 1000).await.unwrap();
                assert_eq!(state(&deleted), pb::CheckpointState::Deleted, "{what}");
                assert!(released(&m, &c.id), "{what}");
            }
            Removal::Expiry => {
                fake.checkpoints(broken);
                refuses_new_work(&s, &fake, &src.id, &c.id, what).await;
                clock.advance(86_400 * SEC + SEC);
                m.expire_checkpoints_due();
                until("the expiry's release", || released(&m, &c.id)).await;
            }
            Removal::Startup => {
                // A Delete the helper could not serve, resumed by the next start while
                // the probe is withdrawn.
                fake.checkpoints(|g| g.unavailable = true);
                assert!(api_delete(&s, &c.id, 1000).await.is_err(), "{what}");
                assert_eq!(row(&m, &c.id).state, CheckpointState::Deleting, "{what}");
                assert!(charge(&m).1 > 0, "{what}: DELETING keeps its charge");
                drop(s);
                m.begin_shutdown();
                m.drain_operations().await;
                drop(m);
                fake.checkpoints(|g| g.unavailable = false);
                fake.checkpoints(broken);
                m = on_disk(&dir, &fake, &clock, &fresh_limits());
                startup(&m).await;
                until("startup cleanup's release", || released(&m, &c.id)).await;
            }
        }
        assert_eq!(calls(&fake, "remove"), removals + 1, "{what}: one Remove");
        // New work is still refused, typed as before.
        let s = api(&m);
        assert!(!advertised(&health(&s, 1000).await), "{what}: advertised");
        let (code, token) = if what == "free space unknown" {
            (Code::Unavailable, "checkpoint_io")
        } else {
            (Code::FailedPrecondition, SANDBOX_UNSUPPORTED)
        };
        refused(
            &api_capture(&s, &src.id, 1000).await.unwrap_err(),
            code,
            token,
        );
        fake.checkpoints(heal);
    }
}

#[tokio::test]
async fn a_delete_proceeds_while_a_new_work_probe_is_withdrawn() {
    removal_while_withdrawn(Removal::Delete).await;
}

#[tokio::test]
async fn an_expiry_proceeds_while_a_new_work_probe_is_withdrawn() {
    removal_while_withdrawn(Removal::Expiry).await;
}

#[tokio::test]
async fn startup_cleanup_proceeds_while_a_new_work_probe_is_withdrawn() {
    removal_while_withdrawn(Removal::Startup).await;
}

/// The feature is withdrawn, and a capture and a fork are refused with nothing sent.
async fn refuses_new_work(s: &Api, fake: &FakeRuntime, source: &str, ready: &str, what: &str) {
    assert!(!advertised(&health(s, 1000).await), "{what}: advertised");
    let captures = calls(fake, "capture");
    assert!(
        api_capture(s, source, 1000).await.is_err(),
        "{what}: captured"
    );
    assert!(api_fork(s, ready, 1000).await.is_err(), "{what}: forked");
    assert_eq!(calls(fake, "capture"), captures, "{what}");
}

/// An older helper does not send `removal_supported`: removal keeps the broad gate it
/// had (fail closed). Delete records its intent, sends no Remove and keeps the charge;
/// it completes once the probe passes again.
#[tokio::test]
async fn an_older_helper_keeps_the_broad_removal_gate() {
    let (m, fake, _, s) = ready_engine().await;
    let src = api_source(&s, 1000).await;
    let checkpoint = api_capture(&s, &src.id, 1000).await.unwrap();
    let charged = charge(&m);
    let removals = calls(&fake, "remove");
    fake.checkpoints(|g| {
        g.removal_supported = false;
        g.supported = false;
        g.unsupported_reason = "/var/lib/kiln/runs is mounted without project quotas";
    });
    let error = api_delete(&s, &checkpoint.id, 1000).await.unwrap_err();
    refused(&error, Code::FailedPrecondition, SANDBOX_UNSUPPORTED);
    assert_eq!(calls(&fake, "remove"), removals, "Remove was never sent");
    assert_eq!(charge(&m), charged, "the checkpoint remains charged");
    assert_eq!(
        state(&api_get(&s, &checkpoint.id, 1000).await.unwrap()),
        pb::CheckpointState::Deleting
    );
    fake.checkpoints(heal);
    until("the retried removal", || charge(&m) == (0, 0)).await;
    assert_eq!(row(&m, &checkpoint.id).state, CheckpointState::Deleted);
}
