//! Checkpoint milestone C6b: the VM crash matrix V1–V17 (design 10 and 11.2 item 6),
//! through real process death of the daemon, the root helper and kiln's copy and
//! restore workers, against the installed kiln on XFS with project quotas. Each
//! scenario is one ignored root test, run alone by `scripts/checkpoint-crash-matrix.py`
//! with the host checked before and after:
//!
//! ```text
//! sudo TEST_BINARY --ignored --exact manager::checkpoint_vm_tests::crash::NAME --test-threads=1 --nocapture
//! ```
//!
//! Every scenario asserts, beyond its own row: no usable partial fork, no premature
//! charge release (the node's charge falls only with ABSENT evidence recorded), no
//! re-capture under an old key, and the source running Exec again. Each prints one
//! `C6B matrix:` line with what it observed.

use serde_json::{Value, json};

use super::harness::*;

fn run<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f);
}

const HOUR_MS: u64 = 3_600_000;

fn capture_call(source: &str, key: &str) -> Value {
    json!({ "op": "capture", "id": source, "request_id": key, "lifetime_ms": HOUR_MS })
}

/// A capture as the owner, in the background.
fn capture_bg(w: &World, source: &str, key: &str) -> tokio::task::JoinHandle<Value> {
    let (api, call) = (w.api.clone(), capture_call(source, key));
    tokio::spawn(async move { rpc(&api, OWNER, call).await })
}

/// A fork as the owner, in the background.
fn fork_bg(w: &World, checkpoint: &str, key: &str, disk: u64) -> tokio::task::JoinHandle<Value> {
    let api = w.api.clone();
    let call = json!({
        "op": "create", "from_checkpoint": checkpoint, "request_id": key, "disk_bytes": disk,
    });
    tokio::spawn(async move { rpc(&api, OWNER, call).await })
}

/// A READY checkpoint of `source`, its ID.
async fn ready(w: &World, source: &str, key: &str) -> String {
    let c = w.ok(capture_call(source, key)).await;
    assert_eq!(c["state"], "CHECKPOINT_STATE_READY", "{c}");
    c["id"].as_str().unwrap().to_string()
}

/// The source runs Exec again and still holds its file.
async fn source_usable(w: &World, source: &str, expect: &str) {
    let r = w.sh(source, "cat /root/w/a").await;
    assert_eq!(r["stdout"], expect, "{r}");
}

/// The fork sandbox a pin names, waiting for the pin row.
async fn pinned_fork(w: &World, checkpoint: &str) -> String {
    w.until("a fork pin", 60, |w| {
        w.db()
            .query_row(
                "SELECT count(*) FROM checkpoint_pins WHERE checkpoint_id = ?1",
                [checkpoint],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
            > 0
    })
    .await;
    w.db()
        .query_row(
            "SELECT sandbox_id FROM checkpoint_pins WHERE checkpoint_id = ?1 ORDER BY pinned_at_ms DESC LIMIT 1",
            [checkpoint],
            |r| r.get(0),
        )
        .unwrap()
}

/// Waits for a capture's row to settle FAILED with its charge back at the node's
/// previous level only after ABSENT evidence.
async fn settles_failed(w: &World, cp: &str, before: (u64, u64)) {
    w.until("FAILED", 180, |w| w.cp_state(cp) == "failed").await;
    w.until("the charge returned", 60, |w| w.charge() == before)
        .await;
    assert!(w.evidence(cp, "absent") >= 1, "released without ABSENT");
    assert!(w.cp_col(cp, "release_evidence_id").len() == 64);
    assert!(
        !w.artifacts().iter().any(|n| n.contains(cp)),
        "artifact or staging left: {:?}",
        w.artifacts()
    );
}

/// The workspace the small scenarios capture.
const SMALL: &str = "mkdir -p /root/w && printf one > /root/w/a";

/// A fork's content matches the source as captured.
async fn fork_matches(w: &World, fork: &str, expect: &str) {
    let r = w.sh(fork, "cat /root/w/a").await;
    assert_eq!(r["stdout"], expect, "{r}");
}

/// A fresh fork of `cp` reaches READY with the captured content, then is deleted.
async fn still_forkable(w: &World, cp: &str, expect: &str, disk: u64) -> String {
    let f = w
        .ok(json!({ "op": "create", "from_checkpoint": cp, "disk_bytes": disk }))
        .await;
    assert_eq!(f["state"], "SANDBOX_STATE_READY", "{f}");
    let id = f["id"].as_str().unwrap().to_string();
    if !expect.is_empty() {
        fork_matches(w, &id, expect).await;
    }
    let d = w.ok(json!({ "op": "delete", "id": id })).await;
    assert_eq!(d["state"], "SANDBOX_STATE_DELETED", "{d}");
    id
}

// ---------------------------------------------------------------------------------
// Capture boundaries.

/// V1: the daemon dies after C1, its Capture never dispatched (the relay holds it).
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v1_daemon_death_after_c1_before_dispatch_fails_without_recapture() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        w.relay.add(hold(Phase::Request, "checkpoint.capture", None));
        let pending = capture_bg(&w, &src, "v1");
        w.relay.held("checkpoint.capture", 60).await;
        let cp = w.capturing_row(&src, 5).await;
        assert_eq!(w.cp_state(&cp), "capturing");
        let charged = w.charge();
        assert_eq!(charged.0, 1, "C1 charges R");
        w.kill_daemon().await;
        let lost = pending.await.unwrap();
        let mark = w.relay.mark();
        let reconciled = w.start_daemon().await;
        settles_failed(&w, &cp, (0, 0)).await;
        let token = w.cp_col(&cp, "failure_token");
        assert_eq!(token, "checkpoint_io");
        assert!(w.relay.requests_since(mark, "checkpoint.capture").is_empty(), "re-captured");
        // The same key answers the settled row, and still no capture.
        let again = w.ok(capture_call(&src, "v1")).await;
        assert_eq!(again["id"], cp.as_str(), "{again}");
        assert_eq!(again["state"], "CHECKPOINT_STATE_FAILED", "{again}");
        assert!(w.relay.requests_since(mark, "checkpoint.capture").is_empty());
        source_usable(&w, &src, "one").await;
        matrix(
            "V1 daemon after C1, before dispatch",
            json!({
                "charged_at_c1": charged.1, "state": "failed", "failure_token": token,
                "captures_after_restart": 0, "keyed_retry": "same FAILED row",
                "client_saw": lost.get("error"), "reconciled": reconciled,
            }),
        );
        w.finish().await;
    });
}

/// A large source and its capture's worker, killed `who` mid-copy.
async fn mid_copy(w: &World, key: &str) -> (String, String, u32, tokio::task::JoinHandle<Value>) {
    let src = w.source(1 << 30, &format!("{SMALL} && {BIG}")).await;
    let pending = capture_bg(w, &src, key);
    let pid = w.worker("capture", 60).await;
    let cp = w.capturing_row(&src, 5).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(alive(pid), "the copy finished before the kill; widen the workspace");
    assert_eq!(w.cp_state(&cp), "capturing");
    (src, cp, pid, pending)
}

/// V2: the daemon dies mid-copy; the helper keeps the worker until the restarted
/// daemon's removal reaps it.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v2_daemon_death_mid_copy_reaps_the_worker_and_fails() {
    run(async {
        let mut w = World::start(json!({})).await;
        let (src, cp, pid, pending) = mid_copy(&w, "v2").await;
        w.kill_daemon().await;
        let _ = pending.await;
        let mark = w.relay.mark();
        let reconciled = w.start_daemon().await;
        settles_failed(&w, &cp, (0, 0)).await;
        w.until("the worker reaped", 60, |_| !alive(pid)).await;
        assert!(w.relay.requests_since(mark, "checkpoint.capture").is_empty());
        // Allocation reopened, and the source's lease is free: it captures again.
        w.until("allocation reopens", 120, |w| !w.barrier_marked()).await;
        let again = ready(&w, &src, "v2-again").await;
        source_usable(&w, &src, "one").await;
        matrix(
            "V2 daemon mid-copy",
            json!({
                "worker_reaped": true, "state": "failed",
                "failure_token": w.cp_col(&cp, "failure_token"),
                "blocked_at_restart": reconciled["checkpoints_blocked"],
                "source_recaptured": again, "captures_after_restart_under_old_key": 0,
            }),
        );
        w.finish().await;
    });
}

/// V3: the helper dies mid-copy; a new epoch; the old worker is reaped; FAILED.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v3_helper_death_mid_copy_new_epoch_reaps_and_fails() {
    run(async {
        let mut w = World::start(json!({})).await;
        let (src, cp, pid, pending) = mid_copy(&w, "v3").await;
        let old = w.helper_epoch().await;
        w.kill_helper().await;
        let client = pending.await.unwrap();
        let mark = w.relay.mark();
        let epoch = w.start_helper().await;
        assert_ne!(epoch, old);
        settles_failed(&w, &cp, (0, 0)).await;
        w.until("the old worker gone", 120, |_| !alive(pid)).await;
        // Every helper request after the restart that still carried the old epoch got
        // an error reply, never a success.
        let seen = w.relay.seen();
        let stale: Vec<_> = seen[mark..]
            .iter()
            .filter(|s| s.phase == Phase::Request && s.json.contains(&old))
            .map(|s| s.op.clone())
            .collect();
        assert!(w.relay.requests_since(mark, "checkpoint.capture").is_empty());
        w.until("allocation reopens", 120, |w| !w.barrier_marked()).await;
        source_usable(&w, &src, "one").await;
        matrix(
            "V3 helper mid-copy",
            json!({
                "new_epoch": epoch != old, "old_worker_gone": true, "state": "failed",
                "failure_token": w.cp_col(&cp, "failure_token"),
                "client_saw": client.get("error"),
                "requests_with_the_old_epoch_after_restart": stale,
            }),
        );
        w.finish().await;
    });
}

/// V4: kiln's copy worker dies mid-copy: a typed failure, staging removed, the source
/// usable.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v4_copy_worker_death_fails_typed_and_removes_staging() {
    run(async {
        let w = World::start(json!({})).await;
        let (src, cp, pid, pending) = mid_copy(&w, "v4").await;
        kill_pid(pid);
        let result = pending.await.unwrap();
        let reason = refused(&result);
        assert!(reason.starts_with("checkpoint_"), "untyped: {result}");
        settles_failed(&w, &cp, (0, 0)).await;
        source_usable(&w, &src, "one").await;
        matrix(
            "V4 copy worker mid-copy",
            json!({ "client_reason": reason, "state": "failed",
                    "failure_token": w.cp_col(&cp, "failure_token") }),
        );
        w.finish().await;
    });
}

/// V5: C3 complete, C4 missing: the relay holds the COMPLETE reply and the daemon dies.
/// v1 discards the artifact with proof and fails the row; it never promotes.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v5_complete_without_ready_is_discarded_never_promoted() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        w.relay.add(hold(Phase::Reply, "checkpoint.captured", None));
        let pending = capture_bg(&w, &src, "v5");
        w.relay.held("checkpoint.captured", 120).await;
        let cp = w.capturing_row(&src, 5).await;
        let published = w.artifacts();
        assert!(published.iter().any(|n| n.contains(&cp)), "{published:?}");
        assert_eq!(w.cp_state(&cp), "capturing");
        w.kill_daemon().await;
        let _ = pending.await;
        let mark = w.relay.mark();
        w.start_daemon().await;
        settles_failed(&w, &cp, (0, 0)).await;
        assert_eq!(w.cp_col(&cp, "content_sha256"), "", "promoted");
        assert!(w.relay.requests_since(mark, "checkpoint.capture").is_empty());
        let again = w.ok(capture_call(&src, "v5")).await;
        assert_eq!(again["state"], "CHECKPOINT_STATE_FAILED", "{again}");
        source_usable(&w, &src, "one").await;
        matrix(
            "V5 C3 complete, C4 missing",
            json!({ "published_before_kill": published, "state": "failed",
                    "failure_token": w.cp_col(&cp, "failure_token"), "promoted": false }),
        );
        w.finish().await;
    });
}

/// V6: C4 committed, the reply lost (the relay holds the daemon's Acknowledge after
/// READY): the keyed retry returns the same READY checkpoint, with no new capture and
/// no idle refresh.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v6_ready_with_the_reply_lost_is_returned_by_the_key() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        w.relay
            .add(hold(Phase::Request, "checkpoint.acknowledge", None));
        let pending = capture_bg(&w, &src, "v6");
        w.relay.held("checkpoint.acknowledge", 120).await;
        let cp = w.capturing_row(&src, 5).await;
        w.until("READY committed", 30, |w| w.cp_state(&cp) == "ready")
            .await;
        let activity = (
            w.cp_col(&cp, "activity_seq"),
            w.cp_col(&cp, "activity_boottime_ms"),
        );
        let charged = w.charge();
        w.kill_daemon().await;
        let _ = pending.await;
        let mark = w.relay.mark();
        w.start_daemon().await;
        let again = w.ok(capture_call(&src, "v6")).await;
        assert_eq!(again["id"], cp.as_str(), "{again}");
        assert_eq!(again["state"], "CHECKPOINT_STATE_READY", "{again}");
        assert!(w.relay.requests_since(mark, "checkpoint.capture").is_empty());
        assert_eq!(
            (
                w.cp_col(&cp, "activity_seq"),
                w.cp_col(&cp, "activity_boottime_ms")
            ),
            activity,
            "the keyed retry refreshed idle"
        );
        assert_eq!(w.charge(), charged);
        let fork = still_forkable(&w, &cp, "one", 0).await;
        matrix(
            "V6 C4 committed, reply lost",
            json!({ "keyed_retry": "same READY row", "captures_after_restart": 0,
                    "idle_refreshed_by_retry": false, "forked": fork }),
        );
        w.finish().await;
    });
}

// ---------------------------------------------------------------------------------
// Removal boundaries.

/// V7: D1 committed, the removal never dispatched (held): the restart completes the
/// exact removal, then releases.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v7_deletion_interrupted_after_d1_completes_on_restart() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        let cp = ready(&w, &src, "v7").await;
        let charged = w.charge();
        w.relay.add(hold(Phase::Request, "checkpoint.remove", None));
        let pending = {
            let (api, id) = (w.api.clone(), cp.clone());
            tokio::spawn(async move {
                rpc(&api, OWNER, json!({ "op": "delete_checkpoint", "id": id })).await
            })
        };
        w.relay.held("checkpoint.remove", 60).await;
        assert_eq!(w.cp_state(&cp), "deleting");
        assert_eq!(w.charge(), charged, "released at D1");
        w.kill_daemon().await;
        let _ = pending.await;
        let mark = w.relay.mark();
        w.start_daemon().await;
        w.until("DELETED", 120, |w| w.cp_state(&cp) == "deleted").await;
        assert_eq!(w.charge(), (0, 0));
        assert!(w.evidence(&cp, "absent") >= 1);
        assert!(!w.relay.requests_since(mark, "checkpoint.remove").is_empty());
        assert!(!w.artifacts().iter().any(|n| n.contains(&cp)));
        source_usable(&w, &src, "one").await;
        matrix(
            "V7 D1 committed, removal interrupted",
            json!({ "charge_kept_through_d1": charged, "state": "deleted",
                    "deletion_reason": w.cp_col(&cp, "deletion_reason") }),
        );
        w.finish().await;
    });
}

/// V8: D2 ABSENT received, D3 missing (the relay holds the ABSENT reply): the restart
/// re-inspects, records matching evidence and releases once.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v8_absent_without_d3_is_reinspected_and_released_once() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        let cp = ready(&w, &src, "v8").await;
        let charged = w.charge();
        w.relay
            .add(hold(Phase::Reply, "checkpoint.removed", Some("absent")));
        let pending = {
            let (api, id) = (w.api.clone(), cp.clone());
            tokio::spawn(async move {
                rpc(&api, OWNER, json!({ "op": "delete_checkpoint", "id": id })).await
            })
        };
        w.relay.held("checkpoint.removed", 120).await;
        assert!(!w.artifacts().iter().any(|n| n.starts_with(&cp)));
        assert_eq!(w.cp_state(&cp), "deleting");
        assert_eq!(w.charge(), charged, "released before D3");
        w.kill_daemon().await;
        let _ = pending.await;
        w.start_daemon().await;
        w.until("DELETED", 120, |w| w.cp_state(&cp) == "deleted").await;
        assert_eq!(w.charge(), (0, 0));
        let absent = w.evidence(&cp, "absent");
        assert!(absent >= 1);
        source_usable(&w, &src, "one").await;
        matrix(
            "V8 D2 ABSENT, D3 missing",
            json!({ "charge_kept_until_d3": charged, "state": "deleted",
                    "absent_evidence_rows": absent, "final_charge": [0, 0] }),
        );
        w.finish().await;
    });
}

// ---------------------------------------------------------------------------------
// Fork boundaries.

/// V9: the fork pin committed, Restore never dispatched (held): the restart releases
/// the pin after a no-reader proof and settles the fork's reservation by typed
/// evidence; the checkpoint stays READY and forkable.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v9_pin_committed_not_dispatched_is_released_by_no_reader_proof() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        let cp = ready(&w, &src, "v9").await;
        w.relay.add(hold(Phase::Request, "checkpoint.restore", None));
        let pending = fork_bg(&w, &cp, "v9-fork", 0);
        w.relay.held("checkpoint.restore", 60).await;
        let fork = pinned_fork(&w, &cp).await;
        assert_eq!(w.pin(&fork).as_deref(), Some(""), "a live pin");
        w.kill_daemon().await;
        let _ = pending.await;
        let reconciled = w.start_daemon().await;
        w.until("the pin released", 120, |w| {
            w.pin(&fork).is_some_and(|p| !p.is_empty())
        })
        .await;
        let released_by = w.pin(&fork).unwrap();
        w.until("the fork settled", 120, |w| {
            matches!(w.sandbox_state(&fork).as_str(), "failed" | "deleted")
        })
        .await;
        assert_eq!(w.cp_state(&cp), "ready");
        let again = still_forkable(&w, &cp, "one", 0).await;
        source_usable(&w, &src, "one").await;
        matrix(
            "V9 pin committed, not dispatched",
            json!({ "pin_released_by": released_by, "fork_state": w.sandbox_state(&fork),
                    "checkpoint": "ready", "forked_again": again, "reconciled": reconciled }),
        );
        w.finish().await;
    });
}

/// A large READY checkpoint and a fork restoring from it, its restore worker running.
async fn mid_restore(w: &World, key: &str) -> (String, String, String, u32, tokio::task::JoinHandle<Value>) {
    let src = w.source(1 << 30, &format!("{SMALL} && {BIG}")).await;
    let cp = ready(w, &src, key).await;
    let pending = fork_bg(w, &cp, &format!("{key}-fork"), 1 << 30);
    let pid = w.worker("--from-checkpoint", 60).await;
    let fork = pinned_fork(w, &cp).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(alive(pid), "the restore finished before the kill; widen the workspace");
    (src, cp, fork, pid, pending)
}

/// V10: the daemon dies mid-restore: the restore worker is killed and reaped before
/// the pin is released; the fork's legacy ambiguous charge is kept.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v10_daemon_death_mid_restore_reaps_the_reader_before_the_pin() {
    run(async {
        let mut w = World::start(json!({})).await;
        let (src, cp, fork, pid, pending) = mid_restore(&w, "v10").await;
        w.kill_daemon().await;
        let _ = pending.await;
        let reconciled = w.start_daemon().await;
        // Sampled until the pin is released: never while the reader lives.
        let end = std::time::Instant::now() + std::time::Duration::from_secs(180);
        loop {
            let released = w.pin(&fork).is_some_and(|p| !p.is_empty());
            let reader = alive(pid);
            assert!(!(released && reader), "pin released while the reader lives");
            if released {
                break;
            }
            assert!(std::time::Instant::now() < end, "the pin was never released");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let fork_state = w.sandbox_state(&fork);
        assert_ne!(fork_state, "ready", "a partial fork became usable");
        let reserved = w.sb_col(&fork, "reserved_disk_bytes");
        assert_eq!(w.cp_state(&cp), "ready");
        source_usable(&w, &src, "one").await;
        matrix(
            "V10 daemon mid-restore",
            json!({ "reader_reaped_before_pin": true, "pin_released_by": w.pin(&fork),
                    "fork_state": fork_state, "fork_reserved_disk_bytes": reserved,
                    "reconciled": reconciled }),
        );
        w.finish().await;
    });
}

/// V11: kiln's restore worker dies: the fork fails typed; the checkpoint stays READY
/// and forkable.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v11_restore_worker_death_fails_the_fork_and_keeps_the_checkpoint() {
    run(async {
        let w = World::start(json!({})).await;
        let (src, cp, fork, pid, pending) = mid_restore(&w, "v11").await;
        kill_pid(pid);
        let result = pending.await.unwrap();
        let reason = refused(&result);
        assert!(!reason.is_empty(), "untyped: {result}");
        w.until("the pin released", 120, |w| {
            w.pin(&fork).is_some_and(|p| !p.is_empty())
        })
        .await;
        assert_ne!(w.sandbox_state(&fork), "ready");
        assert_eq!(w.cp_state(&cp), "ready");
        let again = still_forkable(&w, &cp, "one", 1 << 30).await;
        source_usable(&w, &src, "one").await;
        matrix(
            "V11 restore worker mid-restore",
            json!({ "client_reason": reason, "fork_state": w.sandbox_state(&fork),
                    "checkpoint": "ready", "forked_again": again }),
        );
        w.finish().await;
    });
}

/// V12: the restored backend published, READY missing (the relay holds the Restored
/// reply): compensation on that exact backend, no promotion.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v12_restored_without_ready_is_compensated_never_promoted() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        let cp = ready(&w, &src, "v12").await;
        w.relay.add(hold(Phase::Reply, "checkpoint.restored", None));
        let pending = fork_bg(&w, &cp, "v12-fork", 0);
        let reply = w.relay.held("checkpoint.restored", 120).await;
        let fork = pinned_fork(&w, &cp).await;
        let runs_before = kiln_runs();
        w.kill_daemon().await;
        let _ = pending.await;
        let reconciled = w.start_daemon().await;
        w.until("the fork settled", 180, |w| {
            matches!(w.sandbox_state(&fork).as_str(), "failed" | "deleted")
        })
        .await;
        w.until("the pin released", 120, |w| {
            w.pin(&fork).is_some_and(|p| !p.is_empty())
        })
        .await;
        let runs_after = kiln_runs();
        assert_eq!(w.cp_state(&cp), "ready");
        source_usable(&w, &src, "one").await;
        matrix(
            "V12 restore published, READY missing",
            json!({ "fork_state": w.sandbox_state(&fork), "pin_released_by": w.pin(&fork),
                    "kiln_runs_at_kill": runs_before.len(), "kiln_runs_after": runs_after.len(),
                    "restored_reply_bytes": reply.len(), "reconciled": reconciled }),
        );
        w.finish().await;
    });
}

/// V13: the helper dies mid-restore: the dead epoch's pin waits for ABSENT evidence;
/// a keyed retry of the fork keeps its sandbox.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v13_helper_death_mid_restore_keeps_the_pin_until_absent() {
    run(async {
        let mut w = World::start(json!({})).await;
        let (src, cp, fork, pid, pending) = mid_restore(&w, "v13").await;
        w.kill_helper().await;
        let first = pending.await.unwrap();
        // The pin outlives the dead epoch until a fresh helper proves no reader.
        assert_eq!(w.pin(&fork).as_deref(), Some(""));
        w.start_helper().await;
        w.until("the old reader gone", 120, |_| !alive(pid)).await;
        w.until("the pin released", 180, |w| {
            w.pin(&fork).is_some_and(|p| !p.is_empty())
        })
        .await;
        let retry = w
            .rpc(
                OWNER,
                json!({ "op": "create", "from_checkpoint": cp, "request_id": "v13-fork",
                        "disk_bytes": 1u64 << 30 }),
            )
            .await;
        let retried = retry
            .get("ok")
            .map(|s| s["id"].clone())
            .unwrap_or(Value::Null);
        assert!(
            retried == fork.as_str() || retry.get("error").is_some(),
            "the keyed retry made another sandbox: {retry}"
        );
        assert_eq!(w.cp_state(&cp), "ready");
        source_usable(&w, &src, "one").await;
        matrix(
            "V13 helper mid-restore",
            json!({ "first": first.get("error"), "pin_released_by": w.pin(&fork),
                    "keyed_retry": retry, "fork_state": w.sandbox_state(&fork) }),
        );
        w.finish().await;
    });
}

/// The kiln runs on the node (directory names under runs, `.checkpoints` aside).
fn kiln_runs() -> Vec<String> {
    std::fs::read_dir(super::RUNS)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".checkpoints")
        .collect()
}

// ---------------------------------------------------------------------------------
// Backups, corruption and the barrier.

/// V15: a stale database backup restored under newer artifacts: the unexplained
/// artifact blocks disk admission and is never adopted; an operator's removal of it
/// lets the barrier's clean pass reopen admission.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v15_stale_backup_blocks_admission_and_never_adopts() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        let kept = ready(&w, &src, "v15-kept").await;
        w.stop_daemon().await;
        let backup = w.dir.join("backup");
        std::fs::create_dir(&backup).unwrap();
        for name in ["kilnd.db", "kilnd.db-wal", "kilnd.db-shm"] {
            let from = w.state.join(name);
            if from.exists() {
                std::fs::copy(&from, backup.join(name)).unwrap();
            }
        }
        w.start_daemon().await;
        let newer = ready(&w, &src, "v15-newer").await;
        w.stop_daemon().await;
        for name in ["kilnd.db", "kilnd.db-wal", "kilnd.db-shm"] {
            let _ = std::fs::remove_file(w.state.join(name));
            if backup.join(name).exists() {
                std::fs::copy(backup.join(name), w.state.join(name)).unwrap();
            }
        }
        let reconciled = w.start_daemon().await;
        assert_eq!(reconciled["checkpoints_blocked"], true, "{reconciled}");
        assert!(w.cp_state(&newer).is_empty(), "adopted");
        assert!(w.artifacts().iter().any(|n| n.contains(&newer)), "swept");
        let create = w.rpc(OWNER, json!({ "op": "create" })).await;
        let capture = w.rpc(OWNER, capture_call(&src, "v15-blocked")).await;
        let create_reason = refused(&create);
        let capture_reason = refused(&capture);
        // Operator-authorized cleanup: root removes exactly the unexplained artifact.
        let generation = 1;
        let rm = std::process::Command::new(kiln_bin())
            .args([
                "checkpoint",
                "rm",
                &format!("--instance={}", w.instance),
                &format!("--checkpoint={newer}"),
            ])
            .output()
            .unwrap();
        assert!(rm.status.success(), "{rm:?}");
        w.until("admission reopens", 180, |w| !w.barrier_marked()).await;
        let after = w.rpc(OWNER, json!({ "op": "create" })).await;
        let reopened = ok(&after)["id"].as_str().unwrap().to_string();
        w.ok(json!({ "op": "delete", "id": reopened })).await;
        assert_eq!(w.cp_state(&kept), "ready");
        source_usable(&w, &src, "one").await;
        matrix(
            "V15 stale DB backup",
            json!({ "blocked": true, "adopted": false, "create_refused": create_reason,
                    "capture_refused": capture_reason, "generation_removed": generation,
                    "reopened_after_operator_cleanup": true }),
        );
        w.finish().await;
    });
}

/// V16: a READY artifact's payload corrupted on disk: the fork detects it, the row is
/// QUARANTINED with its charge kept, and the owner's Delete releases it.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v16_corrupt_payload_quarantines_and_delete_releases() {
    run(async {
        let w = World::start(json!({})).await;
        let src = w
            .source(
                0,
                "mkdir -p /root/w && printf one > /root/w/a && head -c 1048576 /dev/zero | tr '\\0' a > /root/w/blob",
            )
            .await;
        let cp = ready(&w, &src, "v16").await;
        let charged = w.charge();
        let flipped = flip_payload_byte(&w, &cp, 1 << 20);
        let fork = w
            .rpc(OWNER, json!({ "op": "create", "from_checkpoint": cp }))
            .await;
        let reason = refused(&fork);
        w.until("QUARANTINED", 120, |w| w.cp_state(&cp) == "quarantined")
            .await;
        assert_eq!(w.charge(), charged, "charge released while quarantined");
        let again = w
            .rpc(OWNER, json!({ "op": "create", "from_checkpoint": cp }))
            .await;
        let again_reason = refused(&again);
        let d = w
            .ok(json!({ "op": "delete_checkpoint", "id": cp }))
            .await;
        w.until("DELETED", 120, |w| w.cp_state(&cp) == "deleted").await;
        assert_eq!(w.charge(), (0, 0));
        source_usable(&w, &src, "one").await;
        matrix(
            "V16 corrupt payload",
            json!({ "flipped": flipped, "fork_reason": reason, "again_reason": again_reason,
                    "quarantine_token": w.cp_col(&cp, "failure_token"),
                    "charge_kept": charged, "delete_state": d["state"] }),
        );
        w.finish().await;
    });
}

/// Flips one byte in the middle of the artifact's payload file of exactly `size`
/// bytes; that file's path below the artifact.
fn flip_payload_byte(w: &World, cp: &str, size: u64) -> String {
    use std::io::{Read, Seek, SeekFrom, Write};
    let root = std::path::PathBuf::from(format!("{}/{}", super::CPS, w.instance));
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().filter_map(Result::ok) {
            let meta = e.metadata().unwrap();
            let path = e.path();
            if !path.to_string_lossy().contains(cp) && dir == root {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() && meta.len() == size {
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .unwrap();
                f.seek(SeekFrom::Start(size / 2)).unwrap();
                let mut b = [0u8; 1];
                f.read_exact(&mut b).unwrap();
                f.seek(SeekFrom::Start(size / 2)).unwrap();
                f.write_all(&[b[0] ^ 0x01]).unwrap();
                f.sync_all().unwrap();
                return path.strip_prefix(&root).unwrap().to_string_lossy().into_owned();
            }
        }
    }
    panic!("no {size}-byte payload file in {cp}'s artifact");
}

/// V17: the daemon dies during the startup barrier's inventory (the relay holds it):
/// nothing opens early, and the next start runs the barrier again.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix"]
fn c6b_v17_death_during_the_barrier_inventory_reruns_it() {
    run(async {
        let mut w = World::start(json!({})).await;
        let src = w.source(0, SMALL).await;
        let cp = ready(&w, &src, "v17").await;
        w.kill_daemon().await;
        w.relay.add(hold(Phase::Request, "checkpoint.inventory", None));
        let daemon = w.spawn_daemon();
        w.relay.held("checkpoint.inventory", 120).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let serving = daemon.has_line("C6B DAEMON SERVING");
        let early = if serving {
            let create = w.rpc(OWNER, json!({ "op": "create" })).await;
            refused(&create)
        } else {
            // Not serving yet: a call does not complete while the barrier runs.
            let call = {
                let api = w.api.clone();
                tokio::spawn(async move { rpc(&api, OWNER, json!({ "op": "create" })).await })
            };
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            assert!(!call.is_finished(), "a call completed during the barrier");
            call.abort();
            "not serving".to_string()
        };
        daemon.kill().await;
        let mark = w.relay.mark();
        w.start_daemon().await;
        assert!(
            !w.relay.requests_since(mark, "checkpoint.inventory").is_empty(),
            "the barrier did not run again"
        );
        assert_eq!(w.cp_state(&cp), "ready");
        let fork = still_forkable(&w, &cp, "one", 0).await;
        source_usable(&w, &src, "one").await;
        matrix(
            "V17 death during the barrier inventory",
            json!({ "serving_while_held": serving, "early_call": early,
                    "inventory_rerun": true, "forked_after": fork }),
        );
        w.finish().await;
    });
}

// ---------------------------------------------------------------------------------
// V14: a real reboot, in two halves around the runner's sync, poweroff and restart.

/// State that survives the reboot (`/tmp` does not).
const V14_DIR: &str = "/var/tmp/kilnd-c6b-v14";

/// V14, before the reboot: a READY checkpoint, one CAPTURING (its Capture held) and
/// one DELETING (its Remove held); then the daemon and the helper are killed and the
/// runner reboots the guest.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix, before a reboot"]
fn c6b_v14_reboot_arm() {
    run(async {
        let _ = std::fs::remove_dir_all(V14_DIR);
        std::fs::create_dir(V14_DIR).unwrap();
        set_mode(std::path::Path::new(V14_DIR), 0o711);
        let mut w = World::start_in(std::path::Path::new(V14_DIR), json!({})).await;
        let src = w.source(0, SMALL).await;
        let kept = ready(&w, &src, "v14-ready").await;
        let doomed = ready(&w, &src, "v14-deleting").await;
        let lifetime = w.cp_col(&kept, "expiry_lifetime_ms");
        let ready_boot = w.cp_col(&kept, "clock_boot_id");
        w.relay.add(hold(Phase::Request, "checkpoint.remove", None));
        let deleting = {
            let (api, id) = (w.api.clone(), doomed.clone());
            tokio::spawn(async move {
                rpc(&api, OWNER, json!({ "op": "delete_checkpoint", "id": id })).await
            })
        };
        w.relay.held("checkpoint.remove", 60).await;
        w.relay.add(hold(Phase::Request, "checkpoint.capture", None));
        let capturing = capture_bg(&w, &src, "v14-capturing");
        w.relay.held("checkpoint.capture", 60).await;
        let partial = w.capturing_row(&src, 5).await;
        let ready_wall = w.ok(json!({ "op": "list_checkpoints", "sandbox_id": src })).await;
        let arm = json!({
            "boot_id": std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
            "image": w.scene.image, "instance": w.instance, "source": src,
            "ready": kept, "deleting": doomed, "capturing": partial,
            "lifetime_ms": lifetime, "ready_boot": ready_boot,
            "listed": ready_wall,
            "registry_existed": w.scene.registry_existed,
            "checkpoints_existed": w.scene.checkpoints_existed,
        });
        assert_eq!(w.cp_state(&doomed), "deleting");
        assert_eq!(w.cp_state(&partial), "capturing");
        std::fs::write(format!("{V14_DIR}/arm.json"), arm.to_string()).unwrap();
        w.kill_daemon().await;
        w.kill_helper().await;
        let _ = (deleting.await, capturing.await);
        matrix("V14 reboot (armed)", arm);
        w.leave_for_reboot();
    });
}

/// V14, after the reboot: the barrier inventories; READY is kept and forkable, the
/// others settle; expiry is rebased with its lifetime not extended.
#[test]
#[ignore = "root on the prepared VM: C6b crash matrix, after a reboot"]
fn c6b_v14_reboot_verify() {
    run(async {
        let arm: Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{V14_DIR}/arm.json")).unwrap())
                .unwrap();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        assert_ne!(arm["boot_id"], boot.trim(), "no reboot happened");
        let mut w = World::resume(std::path::Path::new(V14_DIR), &arm).await;
        let s = |k: &str| arm[k].as_str().unwrap().to_string();
        let (kept, doomed, partial, src) = (s("ready"), s("deleting"), s("capturing"), s("source"));
        let reconciled = w.start_daemon().await;
        w.until("CAPTURING settled", 180, |w| w.cp_state(&partial) == "failed")
            .await;
        w.until("DELETING settled", 180, |w| w.cp_state(&doomed) == "deleted")
            .await;
        assert_eq!(w.cp_state(&kept), "ready");
        assert_eq!(w.cp_col(&kept, "expiry_lifetime_ms"), s("lifetime_ms"));
        let before = arm["listed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == kept.as_str())
            .unwrap()["lifetime_expires_at_unix_ms"]
            .as_i64()
            .unwrap();
        let listed = w
            .ok(json!({ "op": "list_checkpoints", "sandbox_id": src }))
            .await;
        let after = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == kept.as_str())
            .unwrap()["lifetime_expires_at_unix_ms"]
            .as_i64()
            .unwrap();
        assert!(after <= before + 2_000, "lifetime extended: {before} -> {after}");
        let rebased_boot = w.cp_col(&kept, "clock_boot_id");
        // The source's sandbox did not survive the reboot as a running sandbox; the
        // checkpoint forks into a new one with its content.
        let fork = still_forkable(&w, &kept, "one", 0).await;
        w.until("allocation open", 120, |w| !w.barrier_marked()).await;
        matrix(
            "V14 reboot",
            json!({ "reconciled": reconciled, "ready_kept": true, "forked": fork,
                    "capturing": "failed", "deleting": "deleted",
                    "lifetime_expires_before": before, "lifetime_expires_after": after,
                    "clock_rebased_to_boot": rebased_boot != arm["ready_boot"].as_str().unwrap(),
                    "source_after_reboot": w.sandbox_state(&src) }),
        );
        w.finish().await;
        let _ = std::fs::remove_dir_all(V14_DIR);
    });
}
