//! B6 milestone 1: the first whole Firecracker session through the public API, as root in
//! the VM (`scripts/b4-vm-tests.sh b6_linux_root`). Everything a caller touches is real:
//! the `kilnd` daemon binary, running as its own account in its own systemd unit with
//! `kilnd@.service`'s hardening, and `kilndctl` over kilnd's socket. Root enrolls that
//! account, unit and image, and the helper attests the daemon by its real cgroup, account
//! and image digest. The helper is the real node (H and its L/P/S/M/K, R and D workers, the
//! patched jailer, the release VMM and the pinned production guest bundle) under the test
//! approval gate, which exists only in test builds: this is the isolated test deployment
//! of `deploy/firecracker-test/`, and nothing here can run in production.
use super::lifecycle::{Real, host_leftovers, install_root_file, root_dir};
use super::*;
use crate::helper::firecracker::peer::{self, Enrollment};
use crate::test_deployment::{CHECKED_IN, TestDeployment};

/// A directory holding the `kilnd` and `kilndctl` binaries under test.
const BIN_ENV: &str = "KILND_B6_BIN";
/// Optional: where the transcript and the SQLite and journal evidence are written.
const EVIDENCE_ENV: &str = "KILND_B6_EVIDENCE";
/// The root-owned, protected place the enrolled daemon image is installed.
const IMAGE_DIR: &str = "/opt/kilnd/b6-session";

fn evidence(name: &str, value: impl std::fmt::Display) {
    eprintln!("B6 evidence: {name}: {value}");
}

fn output(command: &mut Command) -> std::process::Output {
    command
        .output()
        .unwrap_or_else(|e| panic!("{command:?}: {e}"))
}

fn checked(command: &mut Command) -> String {
    let out = output(command);
    assert!(
        out.status.success(),
        "{command:?}: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Every command the caller ran, with its output and exit code, in order.
#[derive(Default)]
struct Transcript {
    text: String,
}

struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Transcript {
    fn kilndctl(&mut self, bin: &Path, socket: &Path, args: &[&str], stdin: Option<&[u8]>) -> Ran {
        use std::io::Write;
        let started = std::time::Instant::now();
        let mut command = Command::new(bin.join("kilndctl"));
        command
            .arg("--socket")
            .arg(socket)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let ran = Ran {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        let shown = args
            .iter()
            .map(|a| {
                if a.contains(' ') || a.contains(';') || a.contains('>') {
                    format!("'{a}'")
                } else {
                    a.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        self.text.push_str(&format!("$ kilndctl {shown}"));
        if let Some(bytes) = stdin {
            self.text
                .push_str(&format!("   # stdin: {:?}", String::from_utf8_lossy(bytes)));
        }
        self.text.push('\n');
        self.text.push_str(&ran.stdout);
        if !ran.stderr.is_empty() {
            for line in ran.stderr.lines() {
                self.text.push_str(&format!("[stderr] {line}\n"));
            }
        }
        self.text.push_str(&format!(
            "[exit {}, {} ms]\n\n",
            ran.code,
            started.elapsed().as_millis()
        ));
        ran
    }
}

/// Health after its one-second cache, and the node's reserved sandbox slots from it.
async fn node_sandboxes(transcript: &mut Transcript, bin: &Path, socket: &Path) -> u64 {
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let health = transcript.kilndctl(bin, socket, &["health"], None);
    assert!(health.stdout.contains("authoritative"), "{}", health.stdout);
    health
        .stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("node reservations:"))
        .and_then(|l| l.trim().strip_prefix("sandboxes "))
        .and_then(|l| l.split('/').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{}", health.stdout))
}

/// `kilnd@.service`'s `[Service]` settings for instance `name`, minus the lines a
/// transient unit can't take or that `ExecStart` replaces. The daemon runs under exactly
/// the hardening an installed further instance has.
fn unit_properties(name: &str) -> Vec<String> {
    let unit = include_str!("../../../../../../deploy/kilnd@.service");
    let mut in_service = false;
    let mut properties = Vec::new();
    for line in unit.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line == "[Service]";
            continue;
        }
        if !in_service || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, _) = line.split_once('=').unwrap();
        if matches!(key, "ExecStart" | "Restart" | "RestartSec") {
            continue;
        }
        properties.push(line.replace("%i", name));
    }
    properties
}

/// Removes everything this test made for the daemon, whatever state it stopped in.
struct DaemonGuard {
    unit: String,
    account: String,
    state_dir: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = Command::new("systemctl")
            .args(["stop", &self.unit])
            .status();
        let _ = Command::new("systemctl")
            .args(["reset-failed", &self.unit])
            .status();
        let _ = std::fs::remove_dir_all(&self.state_dir);
        let _ = std::fs::remove_dir_all(IMAGE_DIR);
        let _ = Command::new("userdel").arg(&self.account).status();
        let _ = Command::new("groupdel").arg(&self.account).status();
    }
}

fn account_ids(account: &str) -> (u32, u32) {
    let id = |flag| -> u32 {
        checked(Command::new("id").args([flag, account]))
            .trim()
            .parse()
            .unwrap()
    };
    (id("-u"), id("-g"))
}

/// Every row a query returns, as JSON: integers, text, and blobs as their length and,
/// when UTF-8, their text.
fn dump(view: &rusqlite::Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Value {
    let mut statement = view.prepare(sql).unwrap();
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|n| n.to_string())
        .collect();
    let rows = statement
        .query_map(params, |row| {
            let mut object = serde_json::Map::new();
            for (index, name) in names.iter().enumerate() {
                use rusqlite::types::ValueRef;
                let value = match row.get_ref(index)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(i) => json!(i),
                    ValueRef::Real(f) => json!(f),
                    ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                    ValueRef::Blob(b) => match std::str::from_utf8(b) {
                        Ok(text) if name != "stdout" && name != "stderr" => {
                            json!({"bytes": b.len(), "text": text})
                        }
                        _ => json!({"bytes": b.len()}),
                    },
                };
                object.insert(name.clone(), value);
            }
            Ok(Value::Object(object))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    Value::Array(rows)
}

fn kilnd_view(state_dir: &Path) -> rusqlite::Connection {
    let view = rusqlite::Connection::open_with_flags(
        state_dir.join("kilnd.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .unwrap();
    view.pragma_update(None, "query_only", "ON").unwrap();
    view
}

fn write_evidence(name: &str, contents: &str) {
    if let Ok(dir) = std::env::var(EVIDENCE_ENV) {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Path::new(&dir).join(name), contents).unwrap();
    }
}

/// B6 exit, milestone 1: create, persistent executions, a timeout that retires the VM,
/// and removal to ABSENT with the charge released and nothing left behind, all through
/// `kilndctl` and the real daemon.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh b6_linux_root"]
async fn b6_linux_root_a_whole_session_through_kilnd_and_kilndctl() {
    let deployment = TestDeployment::parse(CHECKED_IN.as_bytes()).unwrap();
    let bin = PathBuf::from(std::env::var(BIN_ENV).expect("KILND_B6_BIN names kilnd and kilndctl"));
    let account = deployment.kilnd.account.clone();
    let unit = deployment.kilnd.unit.clone();
    let instance_name = account.strip_prefix("kilnd-").unwrap().to_string();
    assert_eq!(unit, format!("kilnd-{instance_name}.service"));
    let socket = deployment.kilnd.socket.clone();
    let state_dir = deployment.kilnd.state_dir.clone();
    for leftover in [&state_dir, &deployment.helper.root, Path::new(IMAGE_DIR)] {
        assert!(
            !leftover.exists(),
            "{} exists: run scripts/b4-vm-cleanup.py",
            leftover.display()
        );
    }
    assert!(
        !output(Command::new("id").arg(&account)).status.success(),
        "account {account} exists: run scripts/b4-vm-cleanup.py"
    );

    // The daemon's account, its protected image and its deployment file.
    let _cleanup = DaemonGuard {
        unit: unit.clone(),
        account: account.clone(),
        state_dir: state_dir.clone(),
    };
    checked(Command::new("useradd").args([
        "--system",
        "--user-group",
        "--no-create-home",
        "--home-dir",
        "/nonexistent",
        "--shell",
        "/usr/sbin/nologin",
        &account,
    ]));
    let (uid, gid) = account_ids(&account);
    root_dir(Path::new("/opt/kilnd"), 0o755);
    root_dir(Path::new(IMAGE_DIR), 0o755);
    let image = Path::new(IMAGE_DIR).join("kilnd");
    install_root_file(&bin.join("kilnd"), &image, 0o755);
    let deployment_file = Path::new(IMAGE_DIR).join("deployment.json");
    std::fs::write(&deployment_file, CHECKED_IN).unwrap();
    std::fs::set_permissions(&deployment_file, std::fs::Permissions::from_mode(0o444)).unwrap();
    let instance = Id128::parse(
        checked(
            Command::new(&image)
                .args(["init-state", "--state-dir"])
                .arg(&state_dir)
                .args(["--account", &account]),
        )
        .trim(),
    )
    .unwrap();
    evidence("instance", instance);

    // The helper, at the deployment's root, attesting real peers; root enrolls the
    // daemon's account, unit and image before it starts, as add-instance.sh does.
    let options = NodeOptions {
        peers: PeerEvidence::Real,
        auto_enroll: false,
        hash_peers: true,
        ..NodeOptions::default()
    };
    let real = Real::unstarted(options, None, Some(&deployment.helper.root));
    let config = real.config();
    let executable = peer::read_installed_kilnd(&WalkPolicy::production(), &image).unwrap();
    let enrollment = Enrollment {
        instance_id: instance,
        unit: unit.clone(),
        cgroup: format!("/system.slice/{unit}"),
        uid,
        gid,
        executable,
    };
    let enrolled = super::super::with_node_lock(&ledger_config(&config), |ledger| {
        ledger
            .enroll_instance(&enrollment, config.options.max_enrolled)
            .map_err(|e| e.to_string())
    })
    .unwrap();
    evidence("enrolled", format!("{enrolled:?} {enrollment:?}"));
    real.fixture.allow_other_accounts();
    real.start().await;

    // The daemon, in its own unit, with kilnd@.service's hardening.
    let log = deployment.helper.root.join("kilnd.log");
    let mut run = Command::new("systemd-run");
    run.args(["--unit", &unit, "--collect", "--quiet"]);
    for property in unit_properties(&instance_name) {
        run.arg(format!("--property={property}"));
    }
    run.arg(format!(
        "--property=StandardOutput=append:{}",
        log.display()
    ))
    .arg(format!("--property=StandardError=append:{}", log.display()))
    .arg("--")
    .arg(&image)
    .arg("--socket")
    .arg(&socket)
    .args(["--socket-group", &deployment.kilnd.socket_group])
    .arg("--state-dir")
    .arg(&state_dir)
    .arg("--helper-socket")
    .arg(&deployment.helper.socket)
    .args(["--log-format", "json", "--backend", "firecracker"])
    // A one-second Health cache, so the transcript's Health calls show each step's charge.
    .args(["--health-success-cache-secs", "1"])
    .arg("--firecracker-test-deployment")
    .arg(&deployment_file);
    checked(&mut run);
    let mut transcript = Transcript::default();
    let started = std::time::Instant::now();
    loop {
        let probe = output(
            Command::new(bin.join("kilndctl"))
                .arg("--socket")
                .arg(&socket)
                .arg("health"),
        );
        // Any answer ends the wait; the transcript's first Health must say serving.
        if String::from_utf8_lossy(&probe.stdout).contains("status:") {
            break;
        }
        let active = output(Command::new("systemctl").args(["is-active", &unit]));
        assert!(
            started.elapsed() < Duration::from_secs(60)
                && matches!(
                    String::from_utf8_lossy(&active.stdout).trim(),
                    "active" | "activating"
                ),
            "kilnd never served: {}\n{}\n{}",
            String::from_utf8_lossy(&probe.stderr),
            std::fs::read_to_string(&log).unwrap_or_default(),
            real.fixture.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let daemon_pid =
        checked(Command::new("systemctl").args(["show", "--property=MainPID", "--value", &unit]));
    evidence(
        "daemon cgroup",
        std::fs::read_to_string(format!("/proc/{}/cgroup", daemon_pid.trim())).unwrap(),
    );

    // The session.
    let health = transcript.kilndctl(&bin, &socket, &["health"], None);
    assert_eq!(health.code, 0, "{}", health.stdout);
    assert!(
        health.stdout.contains("status:             serving"),
        "{}",
        health.stdout
    );
    assert!(health.stdout.contains("firecracker"), "{}", health.stdout);
    assert!(health.stdout.contains("authoritative"), "{}", health.stdout);
    let created = transcript.kilndctl(&bin, &socket, &["create", "--net", "none"], None);
    assert_eq!(created.code, 0, "{}{}", created.stderr, real.fixture.log());
    let id = created.stdout.trim().to_string();
    assert!(id.starts_with("sb-"), "{id}");
    let got = transcript.kilndctl(&bin, &socket, &["get", &id], None);
    assert!(got.stdout.contains("ready"), "{}", got.stdout);
    assert_eq!(node_sandboxes(&mut transcript, &bin, &socket).await, 1);
    let wrote = transcript.kilndctl(
        &bin,
        &socket,
        &[
            "exec",
            &id,
            "--",
            "sh",
            "-c",
            "echo persistent > /root/kept && echo written",
        ],
        None,
    );
    assert_eq!((wrote.code, wrote.stdout.as_str()), (0, "written\n"));
    let read = transcript.kilndctl(
        &bin,
        &socket,
        &["exec", &id, "--", "cat", "/root/kept"],
        None,
    );
    assert_eq!((read.code, read.stdout.as_str()), (0, "persistent\n"));
    let appended = transcript.kilndctl(
        &bin,
        &socket,
        &[
            "exec",
            "--stdin",
            &id,
            "--",
            "sh",
            "-c",
            "cat >> /root/kept; cat /root/kept",
        ],
        Some(b"appended over stdin\n"),
    );
    assert_eq!(
        (appended.code, appended.stdout.as_str()),
        (0, "persistent\nappended over stdin\n")
    );
    let failed = transcript.kilndctl(
        &bin,
        &socket,
        &["exec", &id, "--", "sh", "-c", "echo to stderr >&2; exit 3"],
        None,
    );
    assert_eq!((failed.code, failed.stderr.as_str()), (3, "to stderr\n"));
    let still = transcript.kilndctl(
        &bin,
        &socket,
        &["exec", &id, "--", "cat", "/root/kept"],
        None,
    );
    assert_eq!(still.code, 0, "a nonzero exit keeps the session reusable");
    let timed_out = transcript.kilndctl(
        &bin,
        &socket,
        &["exec", "--timeout", "3s", "-v", &id, "--", "sleep", "60"],
        None,
    );
    assert_eq!(timed_out.code, 124, "{}", timed_out.stderr);
    let retired = transcript.kilndctl(&bin, &socket, &["get", &id], None);
    assert!(retired.stdout.contains("lost"), "{}", retired.stdout);
    let refused = transcript.kilndctl(&bin, &socket, &["exec", &id, "--", "true"], None);
    assert_ne!(
        refused.code, 0,
        "a retired session refuses its next command"
    );
    assert_eq!(
        node_sandboxes(&mut transcript, &bin, &socket).await,
        1,
        "a retired VM stays charged until Delete proves its resources absent"
    );

    // The VM is gone before Delete; its disk, jail and charge are not.
    let view = kilnd_view(&state_dir);
    let row = |column: &str| -> Option<String> {
        view.query_row(
            &format!("SELECT {column} FROM sandboxes WHERE id = ?1"),
            [&id],
            |r| r.get(0),
        )
        .unwrap()
    };
    let allocation = Id128::parse(&row("allocation_id").unwrap()).unwrap();
    let context = CreateContext {
        instance_id: instance,
        allocation_id: allocation,
        sandbox_id: id.clone(),
    };
    let vmm = real.vmm(allocation);
    let before_rm = host_leftovers(&real, &context, vmm);
    evidence("owned before Delete", format!("{before_rm:?}"));
    assert!(
        !before_rm.is_empty(),
        "the retired VM's resources await Delete"
    );
    let charged_before: i64 = real.fixture.read(|v| {
        v.query_row(
            "SELECT COUNT(*) FROM capacity_claims WHERE allocation_id = ?1 AND released_generation IS NULL",
            [allocation.to_string()],
            |r| r.get(0),
        )
    });
    assert_eq!(
        charged_before, 1,
        "the node claim survives the VM until ABSENT"
    );

    let removed = transcript.kilndctl(&bin, &socket, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}{}", removed.stderr, real.fixture.log());
    let deleted = transcript.kilndctl(&bin, &socket, &["get", &id], None);
    assert!(deleted.stdout.contains("deleted"), "{}", deleted.stdout);
    transcript.kilndctl(&bin, &socket, &["ls", "--all"], None);
    assert_eq!(node_sandboxes(&mut transcript, &bin, &socket).await, 0);

    // Nothing is left: no VMM, loop, mount, cgroup or file, no node claim, and the
    // daemon's row released by its matching ABSENT receipt.
    let left = host_leftovers(&real, &context, vmm);
    evidence("owned after Delete", format!("{left:?}"));
    assert!(left.is_empty(), "left behind: {left:?}");
    let phase = real.phase(allocation);
    assert_eq!(phase, "absent");
    let unreleased: i64 = real.fixture.read(|v| {
        v.query_row(
            "SELECT COUNT(*) FROM capacity_claims WHERE released_generation IS NULL",
            [],
            |r| r.get(0),
        )
    });
    assert_eq!(unreleased, 0, "every node claim is released");
    assert_eq!(row("state").as_deref(), Some("deleted"));
    let evidence_id = row("release_evidence_id").expect("released by a receipt");
    let receipt: String = view
        .query_row(
            "SELECT receipt_id FROM release_evidence WHERE allocation_id = ?1",
            [allocation.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(evidence_id, receipt);
    let local_charged: i64 = view
        .query_row(
            "SELECT COUNT(*) FROM sandboxes WHERE release_evidence_id IS NULL AND state != 'deleted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(local_charged, 0, "no local reservation remains");

    // Evidence, before the daemon stops.
    let sandbox_rows = dump(&view, "SELECT * FROM sandboxes WHERE id = ?1", &[&id]);
    let executions = dump(
        &view,
        "SELECT id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes, started_at_ms,
                finished_at_ms, stdout, stdout_bytes, stdout_truncated, stderr, stderr_bytes,
                command_status_kind, command_status_value, runtime_error, sandbox_reusable,
                cleanup_evidence
         FROM executions WHERE sandbox_id = ?1 ORDER BY started_at_ms",
        &[&id],
    );
    let releases = dump(
        &view,
        "SELECT * FROM release_evidence WHERE allocation_id = ?1",
        &[&allocation.to_string()],
    );
    let journal = real.fixture.read(|v| {
        let allocation = allocation.to_string();
        Ok(json!({
            "instance": dump(v, "SELECT * FROM instances", &[]),
            "allocation": dump(v, "SELECT * FROM allocations WHERE allocation_id = ?1", &[&allocation]),
            "capacity_claim": dump(v, "SELECT * FROM capacity_claims WHERE allocation_id = ?1", &[&allocation]),
            "identity_leases": dump(v, "SELECT * FROM identity_leases WHERE allocation_id = ?1", &[&allocation]),
            "stop_events": dump(v, "SELECT * FROM stop_events WHERE allocation_id = ?1", &[&allocation]),
            "resource_events": dump(v, "SELECT generation, kind, detail FROM resource_events WHERE allocation_id = ?1 ORDER BY generation", &[&allocation]),
            "retired_token": dump(v, "SELECT * FROM retired_tokens WHERE allocation_id = ?1", &[&allocation]),
            "unreleased_claims": dump(v, "SELECT * FROM capacity_claims WHERE released_generation IS NULL", &[]),
        }))
    });
    let timed_out_row = executions
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["state"] == "timed_out")
        .expect("one execution timed out")
        .clone();
    assert_eq!(timed_out_row["sandbox_reusable"], json!(0));
    assert_eq!(timed_out_row["cleanup_evidence"], json!("sandbox_stopped"));
    for execution in executions.as_array().unwrap() {
        if execution["state"] == "exited" {
            assert_eq!(execution["sandbox_reusable"], json!(1), "{execution}");
            assert_eq!(execution["cleanup_evidence"], json!("runtime_drained"));
        }
    }
    let stop_reasons: Vec<String> = journal["stop_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["reason"].as_str().unwrap().to_string())
        .collect();
    evidence("stop reasons", format!("{stop_reasons:?}"));

    checked(Command::new("systemctl").args(["stop", &unit]));
    let daemon_log = std::fs::read_to_string(&log).unwrap_or_default();
    write_evidence("transcript.txt", &transcript.text);
    write_evidence(
        "kilnd-db.json",
        &serde_json::to_string_pretty(&json!({
            "sandbox": sandbox_rows,
            "executions": executions,
            "release_evidence": releases,
        }))
        .unwrap(),
    );
    write_evidence(
        "helper-journal.json",
        &serde_json::to_string_pretty(&journal).unwrap(),
    );
    write_evidence("kilnd.log", &daemon_log);
    write_evidence("helper.log", &real.fixture.log());
    eprintln!("B6 transcript:\n{}", transcript.text);
    evidence("journal", serde_json::to_string(&journal).unwrap());
}
