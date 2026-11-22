//! M3-2: the node `scripts/firecracker-two-daemon-stress.py` drives. One test helper (the
//! real node under the test approval gate, built as `session.rs` builds it) and two real
//! daemons, `fctest` and `fctest2`, each its own account, unit, database and enrollment,
//! under the default node policy. This test starts them, describes them in `node.json`,
//! and then only serves the script's requests until it is told to stop: kill or start a
//! daemon, kill and restart the helper, list allocations. Every Create, Exec and Delete
//! comes from `kilndctl` over the daemons' sockets; the scenarios and their checks are
//! the script's.
//!
//! Requests are files `requests/<seq>-<verb>` (the file holds the argument), answered
//! in `responses/<seq>.json`, both written by rename. On `stop` the daemons stop cleanly,
//! their databases are copied to `final/`, the helper stops, root's offline inventory runs
//! over the ledger and those copies, and the deployment is dropped, which removes the
//! units, accounts, state directories, daemon image and helper root.
use super::lifecycle::host_leftovers;
use super::session::{Deployment, SECOND};
use super::*;
use crate::helper::firecracker::offline;

/// The directory the script and this test share: `node.json`, requests, responses.
const NODE_ENV: &str = "KILND_M32_NODE";
/// The helper's root, on the script's own filesystem (`deployment_at`).
const HELPER_ROOT_ENV: &str = "KILND_M32_HELPER_ROOT";
const SCHEMA: &str = "kilnd-m32-node/1";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Written whole, then renamed into place, so a reader never sees half a file.
fn write_json(path: &Path, value: &Value) {
    let partial = path.with_extension("partial");
    std::fs::write(&partial, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    std::fs::rename(&partial, path).unwrap();
}

/// Whether H's process exists and is not a zombie.
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
        })
        .is_some_and(|state| state != 'Z')
}

/// Everything the script needs to find: sockets, units, accounts, instance IDs, the
/// helper's PID, ledger and logs, and the policy the node runs under.
fn describe(deployment: &Deployment, generation: u64, events: &[Value]) -> Value {
    let real = &deployment.real;
    let root = &real.fixture.root;
    let config = real.config();
    let ledger = ledger_config(&config);
    json!({
        "schema": SCHEMA,
        "generation": generation,
        "written_unix_ms": now_ms(),
        "helper": {
            "root": root,
            "socket": root.join("helper.sock"),
            "control": root.join("control.sock"),
            "ledger": ledger.directory.join("node.db"),
            "log": root.join("child.log"),
            "pid": real.fixture.helper_pid(),
        },
        "policy": {
            "node_id": config.node_id.to_string(),
            "ceilings": config.options.ceilings,
            "shared": ledger.shared,
            "max_enrolled": config.options.max_enrolled,
            "compaction": config.options.compaction,
            "heartbeat_timeout_ms": config.options.heartbeat_timeout_ms,
            "compaction_tick_ms": config.options.compaction_tick_ms,
        },
        "image": deployment.image,
        "bin": deployment.bin,
        "daemons": deployment.daemons.iter().map(|d| json!({
            "name": d.name,
            "instance": d.instance.to_string(),
            "unit": d.unit(),
            "account": d.deployment.kilnd.account,
            "uid": d.uid,
            "gid": d.gid,
            "socket": d.socket(),
            "state_dir": d.state_dir(),
            "cgroup": d.deployment.kilnd.cgroup,
            "log": d.log,
            "active": d.active(),
        })).collect::<Vec<_>>(),
        "events": events,
    })
}

/// The ledger's allocations with their phases and host paths; `all` adds the ABSENT ones
/// and, for each, what of it is still on the host.
fn allocations(deployment: &Deployment, all: bool) -> Value {
    let real = &deployment.real;
    let rows: Vec<(String, String, String, String)> = real.fixture.read(|view| {
        let mut statement = view.prepare(
            "SELECT instance_id, allocation_id, sandbox_id, phase FROM allocations
             ORDER BY created_generation",
        )?;
        let rows = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    });
    let claims = deployment.claims();
    let listed: Vec<Value> = rows
        .into_iter()
        .filter(|row| all || row.3 != "absent")
        .map(|(instance, allocation, sandbox, phase)| {
            let (instance_id, allocation_id) = (
                Id128::parse(&instance).unwrap(),
                Id128::parse(&allocation).unwrap(),
            );
            let (paths, cgroup) = super::super::inventory::real_paths(instance_id, allocation_id);
            let mut row = json!({
                "instance": instance,
                "allocation": allocation,
                "sandbox": sandbox,
                "phase": phase,
                "jail_dir": paths.jail_dir,
                "work_dir": paths.work_dir,
                "cgroup": cgroup,
            });
            if all {
                let context = CreateContext {
                    instance_id,
                    allocation_id,
                    sandbox_id: sandbox.clone(),
                };
                row["present"] = json!(host_leftovers(real, &context, real.vmm(allocation_id)));
            }
            row
        })
        .collect();
    json!({"unreleased_claims": claims, "allocations": listed})
}

/// Root's offline inventory over the stopped helper's ledger and the daemons' copied
/// databases, retried while the killed helper's L still closes the ledger.
async fn offline_inventory(deployment: &Deployment, copies: &Path) -> Value {
    let real = &deployment.real;
    let config = ledger_config(&real.config());
    let mut databases = BTreeMap::new();
    for daemon in &deployment.daemons {
        databases.insert(daemon.instance, copies.join(&daemon.name).join("kilnd.db"));
    }
    let reports = real.fixture.root.join("reports");
    private_dir(&reports);
    for attempt in 0..1000 {
        let path = reports.join(format!("inventory-{attempt}.json"));
        match offline::offline_inventory(&config, &ObservationBackend::Real, &databases, &path) {
            Err(error) if error.contains("stop kilnd-helper") || error.contains("unsafe") => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return json!({"error": error}),
            Ok(report) => {
                let text = std::fs::read_to_string(&path).unwrap();
                std::fs::write(copies.join("offline-inventory.json"), &text).unwrap();
                return json!({
                    "verdict": report.verdict,
                    "unexplained": report.unexplained,
                    "faults": report.faults.len(),
                    "failstop": report.failstop,
                    "ledger_generation": report.ledger_generation,
                });
            }
        }
    }
    json!({"error": "the ledger stayed locked"})
}

/// One request: its reply, and whether it ends the serving loop.
async fn serve(deployment: &Deployment, verb: &str, argument: &str) -> (Value, bool) {
    let daemon = || {
        deployment
            .daemons
            .iter()
            .find(|d| d.name == argument)
            .unwrap_or_else(|| panic!("no daemon {argument:?}"))
    };
    match verb {
        "kill-daemon" => {
            daemon().kill().await;
            (json!({"killed": argument}), false)
        }
        "start-daemon" => {
            let daemon = daemon();
            daemon.start(&deployment.image);
            daemon.wait_serving(&deployment.real).await;
            (json!({"serving": argument}), false)
        }
        // SIGKILL H alone, as a crash would; then a new H on the same ledger, as the
        // installed socket unit would start one.
        "kill-helper" => {
            let before = deployment.real.fixture.helper_pid();
            let killing = std::time::Instant::now();
            deployment.real.fixture.kill_helper().await;
            let killed_ms = killing.elapsed().as_millis() as u64;
            let starting = std::time::Instant::now();
            deployment.real.start().await;
            (
                json!({
                    "killed_pid": before,
                    "kill_ms": killed_ms,
                    "listening_ms": starting.elapsed().as_millis() as u64,
                    "pid": deployment.real.fixture.helper_pid(),
                }),
                false,
            )
        }
        "allocations" => (allocations(deployment, argument == "all"), false),
        "stop" => (json!({"stopping": true}), true),
        other => (
            json!({"error": format!("unknown request {other:?}")}),
            false,
        ),
    }
}

#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-two-daemon-stress.py setup"]
async fn m3_linux_root_two_daemon_stress_node() {
    let dir =
        PathBuf::from(std::env::var(NODE_ENV).expect("KILND_M32_NODE names the node directory"));
    let helper_root = PathBuf::from(
        std::env::var(HELPER_ROOT_ENV).expect("KILND_M32_HELPER_ROOT names the helper root"),
    );
    for name in ["requests", "responses"] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
    }
    // The default node policy (ceilings, shared reserve, shares, lease), and production's
    // timings where the fixture lets a test set them: H's one-second worker heartbeat
    // timeout and L's compaction tick, a quarter pass and at least 250 ms.
    let options = NodeOptions {
        heartbeat_timeout_ms: 1_000,
        compaction_tick_ms: (CompactionPolicy::default().pass_ms / 4).max(250),
        ..NodeOptions::default()
    };
    let deployment = Deployment::at(&["fctest", SECOND], options, Some(&helper_root)).await;
    for daemon in &deployment.daemons {
        daemon.start(&deployment.image);
        daemon.wait_serving(&deployment.real).await;
    }
    let mut generation = 1;
    let mut events: Vec<Value> = vec![json!({"event": "serving", "unix_ms": now_ms()})];
    write_json(
        &dir.join("node.json"),
        &describe(&deployment, generation, &events),
    );
    eprintln!("M3-2 node: serving");
    let mut helper_gone = false;
    'serving: loop {
        let mut names: Vec<String> = std::fs::read_dir(dir.join("requests"))
            .unwrap()
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| !name.ends_with(".partial"))
            .collect();
        names.sort();
        for name in names {
            let path = dir.join("requests").join(&name);
            let argument = std::fs::read_to_string(&path).unwrap_or_default();
            let argument = argument.trim();
            let (seq, verb) = name.split_once('-').unwrap_or((name.as_str(), ""));
            let started = now_ms();
            let (reply, stop) = serve(&deployment, verb, argument).await;
            let finished = now_ms();
            write_json(
                &dir.join("responses").join(format!("{seq}.json")),
                &json!({
                    "seq": seq,
                    "verb": verb,
                    "argument": argument,
                    "started_unix_ms": started,
                    "finished_unix_ms": finished,
                    "reply": reply,
                }),
            );
            std::fs::remove_file(&path).unwrap();
            if verb == "kill-helper" {
                generation += 1;
                helper_gone = false;
            }
            if verb != "allocations" {
                events.push(json!({"event": verb, "argument": argument,
                                   "started_unix_ms": started, "finished_unix_ms": finished}));
                write_json(
                    &dir.join("node.json"),
                    &describe(&deployment, generation, &events),
                );
            }
            if stop {
                break 'serving;
            }
        }
        // H is never restarted behind the script's back: a death it did not ask for is
        // recorded, and the script's checks see it.
        if !helper_gone && !alive(deployment.real.fixture.helper_pid()) {
            helper_gone = true;
            events.push(json!({"event": "helper exited unasked", "unix_ms": now_ms()}));
            write_json(
                &dir.join("node.json"),
                &describe(&deployment, generation, &events),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("M3-2 node: stopping");
    for daemon in &deployment.daemons {
        if daemon.active() {
            daemon.stop().await;
        }
    }
    let copies = dir.join("final");
    std::fs::create_dir_all(&copies).unwrap();
    for daemon in &deployment.daemons {
        daemon.copy_state(&copies.join(&daemon.name));
        let _ = std::fs::copy(
            &daemon.log,
            copies.join(format!("kilnd-{}.log", daemon.name)),
        );
    }
    let listed = allocations(&deployment, true);
    let claims = deployment.claims();
    deployment.real.fixture.kill_helper().await;
    let _ = std::fs::copy(
        deployment.real.fixture.root.join("child.log"),
        copies.join("helper.log"),
    );
    let inventory = offline_inventory(&deployment, &copies).await;
    write_json(
        &dir.join("final.json"),
        &json!({
            "unix_ms": now_ms(),
            "unreleased_claims": claims,
            "allocations": listed["allocations"],
            "offline_inventory": inventory,
        }),
    );
    drop(deployment);
    write_json(&dir.join("dropped.json"), &json!({"unix_ms": now_ms()}));
    eprintln!("M3-2 node: stopped");
}
