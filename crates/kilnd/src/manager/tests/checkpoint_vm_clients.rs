//! Checkpoint milestone C6b: the harness's three uses (design 1, 11.2 item 7) against
//! the installed kiln, through the real socket as an unprivileged uid, with the call
//! shapes `checkpoint_client_fixtures.rs` pins on the fake runtime, now checking
//! workspace content byte for byte; and the kiln half of the legacy-behavior check
//! (11.2 item 8): Create and Exec answer the same with the feature off and on. Root
//! only, on the prepared VM; run by `scripts/checkpoint-crash-matrix.py --set clients`.

use serde_json::{Value, json};

use super::harness::*;

fn run<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f);
}

const MIN: u64 = 60_000;

fn keyed_create(key: &str) -> Value {
    json!({ "op": "create", "request_id": key, "lifetime_ms": 120 * MIN, "idle_ms": 30 * MIN })
}

fn keyed_fork(key: &str, cp: &str) -> Value {
    json!({ "op": "create", "request_id": key, "lifetime_ms": 120 * MIN, "idle_ms": 30 * MIN,
            "from_checkpoint": cp })
}

fn capture(id: &str, key: &str, lifetime_ms: u64, idle_ms: u64) -> Value {
    json!({ "op": "capture", "id": id, "request_id": key, "lifetime_ms": lifetime_ms, "idle_ms": idle_ms })
}

/// One ExecStream turn; its exit code.
async fn turn(w: &World, id: &str, script: &str) -> i64 {
    let r = w
        .ok(json!({ "op": "exec_stream", "id": id, "script": script }))
        .await;
    r["exit_code"].as_i64().unwrap_or(-1)
}

async fn tree(w: &World, id: &str) -> Vec<Vec<u8>> {
    let exec = w.sh(id, &listing_script(&["/root/repo"])).await;
    tree_records(&exec).unwrap_or_else(|e| panic!("listing {id}: {e}"))
}

/// The harness's cleanup: Delete, then Delete again with `release_request_id` once
/// absence is confirmed.
async fn cleanup_sandbox(w: &World, id: &str) {
    let d = w.ok(json!({ "op": "delete", "id": id })).await;
    assert_eq!(d["state"], "SANDBOX_STATE_DELETED", "{d}");
    let r = w
        .ok(json!({ "op": "delete", "id": id, "release": true }))
        .await;
    assert_eq!(r["state"], "SANDBOX_STATE_DELETED", "{r}");
}

async fn cleanup_checkpoint(w: &World, id: &str) {
    let d = w.ok(json!({ "op": "delete_checkpoint", "id": id })).await;
    assert_eq!(d["state"], "CHECKPOINT_STATE_DELETED", "{d}");
    let r = w
        .ok(json!({ "op": "delete_checkpoint", "id": id, "release": true }))
        .await;
    assert_eq!(r["request_id_released"], true, "{r}");
}

/// F1, rewind.
#[test]
#[ignore = "root on the prepared VM: C6b client fixtures"]
fn c6b_f1_rewind_on_real_kiln() {
    run(async {
        let w = World::start(json!({})).await;
        let s = w.ok(keyed_create("kiln-harness:f1")).await;
        let src = s["id"].as_str().unwrap().to_string();
        // Turn 1 writes a small repository.
        assert_eq!(
            turn(
                &w,
                &src,
                "mkdir -p /root/repo/src && cd /root/repo && printf 'fn main() {}\\n' > main.rs \
                 && printf 'pub fn f() {}\\n' > src/lib.rs && ln -s main.rs link && chmod 0755 main.rs \
                 && ln main.rs hard && printf '' > empty"
            )
            .await,
            0
        );
        let git = w.sh(&src, "command -v git || echo none").await["stdout"].clone();
        let turn1 = tree(&w, &src).await;
        let c1 = w.ok(capture(&src, "kiln-harness:f1:cp1", 120 * MIN, 30 * MIN)).await;
        let cp1 = c1["id"].as_str().unwrap().to_string();
        let digest = c1["content_sha256"].as_str().unwrap().to_string();
        assert_eq!(c1["state"], "CHECKPOINT_STATE_READY", "{c1}");
        // A capture while a turn runs is busy; after it, it succeeds.
        let running = {
            let (api, id) = (w.api.clone(), src.clone());
            tokio::spawn(async move {
                rpc(&api, OWNER, json!({ "op": "exec_stream", "id": id, "script": "sleep 4" })).await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let busy = w
            .rpc(OWNER, capture(&src, "kiln-harness:f1:cp-busy", 120 * MIN, 30 * MIN))
            .await;
        assert_eq!(refused(&busy), "checkpoint_busy", "{busy}");
        assert_eq!(ok(&running.await.unwrap())["exit_code"], 0);
        let after = w
            .ok(capture(&src, "kiln-harness:f1:cp-after", 120 * MIN, 30 * MIN))
            .await;
        assert_eq!(after["content_sha256"], digest.as_str(), "the turn changed nothing");
        // Turn 2 is destructive; then the source goes.
        assert_eq!(
            turn(
                &w,
                &src,
                "cd /root/repo && rm -rf src && chmod 000 main.rs && rm link && ln -s /etc link && rm hard"
            )
            .await,
            0
        );
        assert_ne!(tree(&w, &src).await, turn1);
        cleanup_sandbox(&w, &src).await;
        // Rewind: fork turn 1 after its source is gone, byte for byte.
        let f = w.ok(keyed_fork("kiln-harness:f1-rewind", &cp1)).await;
        let fork = f["id"].as_str().unwrap().to_string();
        assert_eq!(f["from_checkpoint"], cp1.as_str());
        assert_eq!(f["checkpoint_content_sha256"], digest.as_str());
        assert_eq!(tree(&w, &fork).await, turn1, "the rewound tree differs");
        let keyed = w.ok(keyed_fork("kiln-harness:f1-rewind", &cp1)).await;
        assert_eq!(keyed["id"], fork.as_str(), "a keyed fork retry made another sandbox");
        // Continue, then depth 2: checkpoint the fork and fork that.
        assert_eq!(turn(&w, &fork, "printf more > /root/repo/next").await, 0);
        let fork_tree = tree(&w, &fork).await;
        let c2 = w.ok(capture(&fork, "kiln-harness:f1:cp2", 120 * MIN, 30 * MIN)).await;
        let cp2 = c2["id"].as_str().unwrap().to_string();
        let g = w.ok(keyed_fork("kiln-harness:f1-depth2", &cp2)).await;
        let grand = g["id"].as_str().unwrap().to_string();
        assert_eq!(tree(&w, &grand).await, fork_tree, "the depth-2 fork differs");
        for id in [&grand, &fork] {
            cleanup_sandbox(&w, id).await;
        }
        let cpa = after["id"].as_str().unwrap().to_string();
        for id in [&cp2, &cp1, &cpa] {
            cleanup_checkpoint(&w, id).await;
        }
        matrix(
            "F1 rewind (real kiln)",
            json!({ "busy_while_a_turn_runs": "checkpoint_busy", "digest_stable": true,
                    "rewound_byte_for_byte": true, "depth2_byte_for_byte": true,
                    "keyed_fork_retry": "same sandbox", "git_in_image": git,
                    "turn1_entries": turn1.len() }),
        );
        w.finish().await;
    });
}

/// F2, best-of-four.
#[test]
#[ignore = "root on the prepared VM: C6b client fixtures"]
fn c6b_f2_best_of_four_on_real_kiln() {
    run(async {
        let w = World::start(json!({})).await;
        let baseline = w.ok(json!({ "op": "health" })).await["checkpoints"].clone();
        let s = w.ok(keyed_create("kiln-harness:f2")).await;
        let src = s["id"].as_str().unwrap().to_string();
        assert_eq!(turn(&w, &src, "mkdir -p /root/repo && printf seed > /root/repo/seed").await, 0);
        let seed = tree(&w, &src).await;
        let c = w.ok(capture(&src, "kiln-harness:f2:seed", 120 * MIN, 30 * MIN)).await;
        let cp = c["id"].as_str().unwrap().to_string();
        // Four concurrent forks against one restore worker per uid; refusals retried
        // with backoff, as the harness must.
        let mut tasks = Vec::new();
        for n in 0..4 {
            let (api, cp) = (w.api.clone(), cp.clone());
            tasks.push(tokio::spawn(async move {
                let mut refusals = Vec::new();
                for attempt in 0..60u64 {
                    let r = rpc(&api, OWNER, keyed_fork(&format!("kiln-harness:f2-{n}"), &cp)).await;
                    match r.get("error") {
                        None => return (r["ok"]["id"].as_str().unwrap().to_string(), refusals),
                        Some(e) => {
                            assert_eq!(e["reason"], "checkpoint_workers", "{r}");
                            assert_eq!(e["code"], "ResourceExhausted", "{r}");
                            refusals.push(attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(100 + 50 * attempt)).await;
                        }
                    }
                }
                panic!("fork {n} never got a worker");
            }));
        }
        let mut forks = Vec::new();
        let mut refused_total = 0;
        for t in tasks {
            let (id, refusals) = t.await.unwrap();
            refused_total += refusals.len();
            forks.push(id);
        }
        for (n, id) in forks.iter().enumerate() {
            assert_eq!(tree(&w, id).await, seed);
            assert_eq!(turn(&w, id, &format!("printf {n} > /root/repo/attempt")).await, 0);
        }
        // The check passes in exactly one.
        let mut winners = Vec::new();
        for id in &forks {
            let r = w
                .ok(json!({ "op": "exec", "id": id, "script": "test \"$(cat /root/repo/attempt)\" = 2" }))
                .await;
            if r["exit_code"] == 0 {
                winners.push(id.clone());
            }
        }
        assert_eq!(winners.len(), 1);
        for id in forks.iter().filter(|id| **id != winners[0]) {
            cleanup_sandbox(&w, id).await;
        }
        cleanup_checkpoint(&w, &cp).await;
        let r = w.sh(&winners[0], "cat /root/repo/attempt /root/repo/seed").await;
        assert_eq!(r["stdout"], "2seed");
        cleanup_sandbox(&w, &winners[0]).await;
        cleanup_sandbox(&w, &src).await;
        let after = w.ok(json!({ "op": "health" })).await["checkpoints"].clone();
        let counts = |v: &Value| {
            let t = v.as_str().unwrap_or("");
            ["current_count", "reserved_bytes", "current_workers", "pending_deletes"]
                .map(|k| t.split(&format!("{k}: ")).nth(1).and_then(|r| r.split(',').next()).map(str::to_string))
        };
        assert_eq!(counts(&after), counts(&baseline), "accounting did not return: {after}");
        matrix(
            "F2 best-of-four (real kiln)",
            json!({ "forks": 4, "worker_refusals_retried": refused_total, "winner": 1,
                    "seed_byte_for_byte": true, "accounting_back_to_baseline": true }),
        );
        w.finish().await;
    });
}

/// F3, eval reset.
#[test]
#[ignore = "root on the prepared VM: C6b client fixtures"]
fn c6b_f3_eval_reset_on_real_kiln() {
    run(async {
        let w = World::start(json!({})).await;
        let s = w.ok(keyed_create("kiln-harness:f3")).await;
        let src = s["id"].as_str().unwrap().to_string();
        assert_eq!(turn(&w, &src, "mkdir -p /root/repo && printf seed > /root/repo/seed").await, 0);
        let seed = tree(&w, &src).await;
        // A short lifetime, so the run ends past it.
        let lifetime = 90_000;
        // Idle longer than the lifetime, so the lifetime is what ends it.
        let c = w.ok(capture(&src, "kiln-harness:f3:seed", lifetime, 2 * lifetime)).await;
        let cp = c["id"].as_str().unwrap().to_string();
        let digest = c["content_sha256"].as_str().unwrap().to_string();
        cleanup_sandbox(&w, &src).await;
        let mut activity = Vec::new();
        for run in 0..5 {
            let f = w.ok(keyed_fork(&format!("kiln-harness:f3-run{run}"), &cp)).await;
            let id = f["id"].as_str().unwrap().to_string();
            assert_eq!(f["checkpoint_content_sha256"], digest.as_str());
            assert_eq!(tree(&w, &id).await, seed, "run {run} saw a previous run's change");
            assert_eq!(turn(&w, &id, &format!("printf run{run} > /root/repo/seed && touch /root/repo/r{run}")).await, 0);
            cleanup_sandbox(&w, &id).await;
            activity.push(w.cp_col(&cp, "activity_seq"));
        }
        let seqs: Vec<u64> = activity.iter().map(|a| a.parse().unwrap()).collect();
        assert!(seqs.windows(2).all(|p| p[1] > p[0]), "forks did not refresh idle: {seqs:?}");
        // Past the lifetime: a typed refusal, then a re-seed.
        let ready_at: i64 = w.cp_col(&cp, "ready_at_ms").parse().unwrap();
        let wait = (ready_at + lifetime as i64 + 1_000 - crate::model::now_ms()).max(0) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        let late = w.rpc(OWNER, keyed_fork("kiln-harness:f3-late", &cp)).await;
        let late_reason = refused(&late);
        assert!(
            matches!(late_reason.as_str(), "checkpoint_expired" | "checkpoint_not_ready"),
            "{late}"
        );
        let s = w.ok(keyed_create("kiln-harness:f3-reseed")).await;
        let src = s["id"].as_str().unwrap().to_string();
        assert_eq!(turn(&w, &src, "mkdir -p /root/repo && printf seed > /root/repo/seed").await, 0);
        // The re-seed is a new tree (new mtimes): the fork must equal it.
        let reseed = tree(&w, &src).await;
        let c = w.ok(capture(&src, "kiln-harness:f3:reseed", 120 * MIN, 30 * MIN)).await;
        let reseeded = c["id"].as_str().unwrap().to_string();
        let f = w.ok(keyed_fork("kiln-harness:f3-after", &reseeded)).await;
        let id = f["id"].as_str().unwrap().to_string();
        assert_eq!(tree(&w, &id).await, reseed);
        cleanup_sandbox(&w, &id).await;
        cleanup_sandbox(&w, &src).await;
        cleanup_checkpoint(&w, &reseeded).await;
        w.until("the expired seed deleted", 120, |w| w.cp_state(&cp) == "deleted").await;
        assert_eq!(w.cp_col(&cp, "deletion_reason"), "expired_lifetime");
        matrix(
            "F3 eval reset (real kiln)",
            json!({ "runs": 5, "same_digest_every_run": true, "no_run_saw_another": true,
                    "idle_refreshed_by_forks": seqs, "past_lifetime": late_reason,
                    "expired_seed": w.cp_col(&cp, "deletion_reason"), "reseeded": true }),
        );
        w.finish().await;
    });
}

/// What Create and Exec answer, with the variable parts (IDs, times) left out.
async fn legacy_answers(w: &World) -> Value {
    let s = w.ok(json!({ "op": "create" })).await;
    let id = s["id"].as_str().unwrap().to_string();
    let r = w
        .ok(json!({ "op": "exec", "id": id,
                    "script": "id; echo $PATH; ls -la / | awk '{print $1, $NF}'; cat /etc/os-release; printf x > /root/f; cat /root/f; exit 3" }))
        .await;
    let g = w.ok(json!({ "op": "get", "id": id })).await;
    let d = w.ok(json!({ "op": "delete", "id": id })).await;
    json!({
        "created": s["state"], "from_checkpoint": s["from_checkpoint"],
        "exec": r, "get": g["state"], "deleted": d["state"],
    })
}

/// 11.2 item 8, kiln half: Create and Exec are unchanged by the feature; only Health's
/// feature list and checkpoint fields differ.
#[test]
#[ignore = "root on the prepared VM: C6b legacy behavior"]
fn c6b_legacy_create_and_exec_are_unchanged_with_the_flag() {
    run(async {
        let mut w = World::start(json!({ "checkpoints_off": true })).await;
        let off = legacy_answers(&w).await;
        let health_off = w.ok(json!({ "op": "health" })).await;
        w.stop_daemon().await;
        w.daemon_args = json!({});
        w.start_daemon().await;
        let on = legacy_answers(&w).await;
        let health_on = w.ok(json!({ "op": "health" })).await;
        assert_eq!(on, off, "Create/Exec differ with the feature on");
        let mut features_on: Vec<Value> = health_on["features"].as_array().unwrap().clone();
        features_on.retain(|f| f != "FEATURE_WORKSPACE_CHECKPOINT");
        assert_eq!(&features_on, health_off["features"].as_array().unwrap());
        assert_eq!(health_off["checkpoint"], false);
        assert_eq!(health_on["checkpoint"], true);
        assert!(health_off["checkpoints"].is_null());
        matrix(
            "legacy Create/Exec, kiln (flag off vs on)",
            json!({ "equal": true, "exec": on["exec"], "features_off": health_off["features"],
                    "only_difference": "workspace_checkpoint feature, checkpoint capability and stats" }),
        );
        w.finish().await;
    });
}
