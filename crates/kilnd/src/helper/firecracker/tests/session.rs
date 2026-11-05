//! B6 milestone 1: the first whole Firecracker session through the public API, as root in
//! the VM (`scripts/b4-vm-tests.sh b6_linux_root`). Everything a caller touches is real:
//! the `kilnd` daemon binary, running as its own account in its own systemd unit with
//! `kilnd@.service`'s hardening, and `kilndctl` over kilnd's socket. Root enrolls that
//! account, unit and image, and the helper attests the daemon by its real cgroup, account
//! and image digest. The helper is the real node (H and its L/P/S/M/K, R and D workers, the
//! patched jailer, the release VMM and the pinned production guest bundle) under the test
//! approval gate, which exists only in test builds: this is the isolated test deployment
//! of `deploy/firecracker-test/`, and nothing here can run in production.
//!
//! The harness here (`Deployment` and `Daemon`) is shared with B6 milestone 2's crash
//! matrix and attack regressions (`recovery.rs`): any number of daemons, each its own
//! account, unit, state and enrollment, against one helper.
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

pub(super) fn evidence(name: &str, value: impl std::fmt::Display) {
    eprintln!("B6 evidence: {name}: {value}");
}

pub(super) fn output(command: &mut Command) -> std::process::Output {
    command
        .output()
        .unwrap_or_else(|e| panic!("{command:?}: {e}"))
}

pub(super) fn checked(command: &mut Command) -> String {
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
pub(super) struct Transcript {
    pub(super) text: String,
}

pub(super) struct Ran {
    pub(super) code: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

impl Drop for Transcript {
    fn drop(&mut self) {
        if std::thread::panicking() && !self.text.is_empty() {
            eprintln!("--- kilndctl transcript ---\n{}", self.text);
        }
    }
}

impl Transcript {
    pub(super) fn kilndctl(
        &mut self,
        bin: &Path,
        socket: &Path,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Ran {
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
pub(super) async fn node_sandboxes(transcript: &mut Transcript, bin: &Path, socket: &Path) -> u64 {
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

/// The second daemon's instance name, beside the checked-in `fctest`.
pub(super) const SECOND: &str = "fctest2";

/// The checked-in deployment for `fctest`; any other name is the same deployment with
/// that name in the account, group, unit, socket and state, and the same helper.
pub(super) fn deployment_for(name: &str) -> TestDeployment {
    let checked_in = TestDeployment::parse(CHECKED_IN.as_bytes()).unwrap();
    if name == "fctest" {
        return checked_in;
    }
    let mut value: Value = serde_json::from_str(CHECKED_IN).unwrap();
    for field in [
        "socket",
        "socket_group",
        "state_dir",
        "account",
        "unit",
        "cgroup",
    ] {
        let text = value["kilnd"][field]
            .as_str()
            .unwrap()
            .replace("fctest", name);
        value["kilnd"][field] = json!(text);
    }
    TestDeployment::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

/// Removes everything a daemon of the test deployment owned, whatever state it is in.
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
        let _ = Command::new("userdel").arg(&self.account).status();
        let _ = Command::new("groupdel").arg(&self.account).status();
    }
}

/// Removes the shared image directory last.
struct ImageGuard;
impl Drop for ImageGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(IMAGE_DIR);
    }
}

/// One test daemon: its deployment, enrolled instance and account.
pub(super) struct Daemon {
    pub(super) name: String,
    pub(super) deployment: TestDeployment,
    pub(super) file: PathBuf,
    pub(super) instance: Id128,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) log: PathBuf,
    pub(super) bin: PathBuf,
}

/// The helper and its daemons, none started yet.
pub(super) struct Deployment {
    pub(super) daemons: Vec<Daemon>,
    // Fields drop in order: the daemons stop before the helper goes, the image last.
    _guards: Vec<DaemonGuard>,
    pub(super) real: Real,
    pub(super) bin: PathBuf,
    pub(super) image: PathBuf,
    _image: ImageGuard,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if std::thread::panicking() {
            for daemon in &self.daemons {
                let log = std::fs::read_to_string(&daemon.log).unwrap_or_default();
                let tail: Vec<&str> = log.lines().rev().take(60).collect();
                eprintln!(
                    "--- {} daemon log (last 60 lines) ---\n{}",
                    daemon.name,
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                );
            }
        }
    }
}

impl Deployment {
    /// Accounts, the protected daemon image, each instance's state and the real helper at
    /// the deployment's root; root enrolls every daemon's account, unit, cgroup and image
    /// with the helper stopped, as add-instance.sh does, then starts it.
    pub(super) async fn new(names: &[&str], options: NodeOptions) -> Self {
        let bin =
            PathBuf::from(std::env::var(BIN_ENV).expect("KILND_B6_BIN names kilnd and kilndctl"));
        let first = deployment_for("fctest");
        for name in names {
            let deployment = deployment_for(name);
            for leftover in [&deployment.kilnd.state_dir, &first.helper.root] {
                assert!(
                    !leftover.exists(),
                    "{} exists: run scripts/b4-vm-cleanup.py",
                    leftover.display()
                );
            }
            assert!(
                !output(Command::new("id").arg(&deployment.kilnd.account))
                    .status
                    .success(),
                "account {} exists: run scripts/b4-vm-cleanup.py",
                deployment.kilnd.account
            );
        }
        assert!(!Path::new(IMAGE_DIR).exists(), "{IMAGE_DIR} exists");
        let image_guard = ImageGuard;
        root_dir(Path::new("/opt/kilnd"), 0o755);
        root_dir(Path::new(IMAGE_DIR), 0o755);
        let image = Path::new(IMAGE_DIR).join("kilnd");
        install_root_file(&bin.join("kilnd"), &image, 0o755);
        let mut guards = Vec::new();
        let mut daemons = Vec::new();
        for name in names {
            let deployment = deployment_for(name);
            let account = deployment.kilnd.account.clone();
            guards.push(DaemonGuard {
                unit: deployment.kilnd.unit.clone(),
                account: account.clone(),
                state_dir: deployment.kilnd.state_dir.clone(),
            });
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
            let file = Path::new(IMAGE_DIR).join(format!("{name}.json"));
            std::fs::write(
                &file,
                serde_json::to_vec_pretty(&deployment_json(&deployment)).unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
            let instance = init_state(&image, &deployment);
            daemons.push(Daemon {
                name: name.to_string(),
                log: first.helper.root.join(format!("kilnd-{name}.log")),
                deployment,
                file,
                instance,
                uid,
                gid,
                bin: bin.clone(),
            });
        }
        let real = Real::unstarted(
            NodeOptions {
                peers: PeerEvidence::Real,
                auto_enroll: false,
                hash_peers: true,
                ..options
            },
            None,
            Some(&first.helper.root),
        );
        let config = real.config();
        for daemon in &daemons {
            enroll(&real, &config, &image, daemon);
        }
        real.fixture.allow_other_accounts();
        real.start().await;
        Self {
            daemons,
            _guards: guards,
            real,
            bin,
            image,
            _image: image_guard,
        }
    }

    pub(super) fn daemon(&self, name: &str) -> &Daemon {
        self.daemons.iter().find(|d| d.name == name).unwrap()
    }

    /// Unreleased node claims, across every instance.
    pub(super) fn claims(&self) -> i64 {
        self.real.fixture.read(|v| {
            v.query_row(
                "SELECT COUNT(*) FROM capacity_claims WHERE released_generation IS NULL",
                [],
                |r| r.get(0),
            )
        })
    }

    /// This instance's allocations and their phases, oldest first.
    pub(super) fn allocations(&self, instance: Id128) -> Vec<(Id128, String)> {
        self.real.fixture.read(|v| {
            let mut statement = v.prepare(
                "SELECT allocation_id, phase FROM allocations WHERE instance_id = ?1
                 ORDER BY created_generation",
            )?;
            let rows = statement
                .query_map([instance.to_string()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows
                .into_iter()
                .map(|(a, p)| (Id128::parse(&a).unwrap(), p))
                .collect())
        })
    }

    /// Waits until one of this instance's allocations reaches one of `phases`.
    pub(super) async fn wait_allocation(
        &self,
        instance: Id128,
        phases: &[&str],
        seconds: u64,
    ) -> Id128 {
        let end = std::time::Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some((allocation, _)) = self
                .allocations(instance)
                .into_iter()
                .find(|(_, phase)| phases.contains(&phase.as_str()))
            {
                return allocation;
            }
            assert!(
                std::time::Instant::now() < end,
                "no allocation reached {phases:?}: {:?}\n{}",
                self.allocations(instance),
                self.real.fixture.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub(super) async fn wait_phase(&self, allocation: Id128, phases: &[&str], seconds: u64) {
        let end = std::time::Instant::now() + Duration::from_secs(seconds);
        loop {
            let phase = self.real.phase(allocation);
            if phases.contains(&phase.as_str()) {
                return;
            }
            assert!(
                std::time::Instant::now() < end,
                "allocation stayed {phase}, never {phases:?}\n{}",
                self.real.fixture.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Kills the helper process H alone, then starts a new one on the same ledger.
    pub(super) async fn restart_helper(&self) {
        self.real.fixture.kill_helper().await;
        self.real.start().await;
    }
}

/// The deployment as its daemon reads it.
fn deployment_json(deployment: &TestDeployment) -> Value {
    json!({
        "schema": deployment.schema,
        "deployment": deployment.deployment,
        "profile": deployment.profile,
        "kilnd": {
            "socket": deployment.kilnd.socket,
            "socket_group": deployment.kilnd.socket_group,
            "state_dir": deployment.kilnd.state_dir,
            "account": deployment.kilnd.account,
            "unit": deployment.kilnd.unit,
            "cgroup": deployment.kilnd.cgroup,
        },
        "helper": {
            "root": deployment.helper.root,
            "socket": deployment.helper.socket,
        },
    })
}

/// `kilnd init-state` as root, for the instance ID to enroll.
pub(super) fn init_state(image: &Path, deployment: &TestDeployment) -> Id128 {
    Id128::parse(
        checked(
            Command::new(image)
                .args(["init-state", "--state-dir"])
                .arg(&deployment.kilnd.state_dir)
                .args(["--account", &deployment.kilnd.account]),
        )
        .trim(),
    )
    .unwrap()
}

/// Root's enrollment of one daemon, with the helper stopped.
fn enroll(real: &Real, config: &ChildConfig, image: &Path, daemon: &Daemon) {
    let executable = peer::read_installed_kilnd(&WalkPolicy::production(), image).unwrap();
    let enrollment = Enrollment {
        instance_id: daemon.instance,
        unit: daemon.deployment.kilnd.unit.clone(),
        cgroup: daemon.deployment.kilnd.cgroup.clone(),
        uid: daemon.uid,
        gid: daemon.gid,
        executable,
    };
    let enrolled = super::super::with_node_lock(&ledger_config(config), |ledger| {
        ledger
            .enroll_instance(&enrollment, config.options.max_enrolled)
            .map_err(|e| e.to_string())
    })
    .unwrap();
    evidence(
        "enrolled",
        format!("{} {enrolled:?} {enrollment:?}", daemon.name),
    );
    let _ = real;
}

impl Daemon {
    pub(super) fn unit(&self) -> &str {
        &self.deployment.kilnd.unit
    }

    pub(super) fn socket(&self) -> &Path {
        &self.deployment.kilnd.socket
    }

    pub(super) fn state_dir(&self) -> &Path {
        &self.deployment.kilnd.state_dir
    }

    /// Starts the daemon in its own transient unit with kilnd@.service's hardening.
    pub(super) fn start(&self, image: &Path) {
        let _ = Command::new("systemctl")
            .args(["reset-failed", self.unit()])
            .status();
        let mut run = Command::new("systemd-run");
        run.args(["--unit", self.unit(), "--collect", "--quiet"]);
        for property in unit_properties(&self.name) {
            run.arg(format!("--property={property}"));
        }
        run.arg(format!(
            "--property=StandardOutput=append:{}",
            self.log.display()
        ))
        .arg(format!(
            "--property=StandardError=append:{}",
            self.log.display()
        ))
        .arg("--")
        .arg(image)
        .arg("--socket")
        .arg(self.socket())
        .args(["--socket-group", &self.deployment.kilnd.socket_group])
        .arg("--state-dir")
        .arg(self.state_dir())
        .arg("--helper-socket")
        .arg(&self.deployment.helper.socket)
        .args(["--log-format", "json", "--backend", "firecracker"])
        // A one-second Health cache, so Health shows each step's charge.
        .args(["--health-success-cache-secs", "1"])
        .arg("--firecracker-test-deployment")
        .arg(&self.file);
        checked(&mut run);
    }

    /// Whether systemd still runs the unit.
    pub(super) fn active(&self) -> bool {
        let state = output(Command::new("systemctl").args(["is-active", self.unit()]));
        matches!(
            String::from_utf8_lossy(&state.stdout).trim(),
            "active" | "activating" | "deactivating"
        )
    }

    /// Waits until Health answers, failing early if the unit died.
    pub(super) async fn wait_serving(&self, real: &Real) {
        let started = std::time::Instant::now();
        loop {
            let probe = output(
                Command::new(self.bin.join("kilndctl"))
                    .arg("--socket")
                    .arg(self.socket())
                    .arg("health"),
            );
            if String::from_utf8_lossy(&probe.stdout).contains("status:") {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(90) && self.active(),
                "{} never served: {}\n{}\n{}",
                self.name,
                String::from_utf8_lossy(&probe.stderr),
                std::fs::read_to_string(&self.log).unwrap_or_default(),
                real.fixture.log()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Waits until the unit is no longer running, at most `seconds`.
    pub(super) async fn wait_inactive(&self, seconds: u64) -> bool {
        let end = std::time::Instant::now() + Duration::from_secs(seconds);
        while self.active() {
            if std::time::Instant::now() > end {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        true
    }

    /// A clean stop through systemd (SIGTERM and the shutdown grace).
    pub(super) async fn stop(&self) {
        checked(Command::new("systemctl").args(["stop", self.unit()]));
        assert!(self.wait_inactive(60).await);
    }

    /// The daemon's death: SIGKILL to every process of its unit, no shutdown at all.
    pub(super) async fn kill(&self) {
        checked(Command::new("systemctl").args([
            "kill",
            "--signal=SIGKILL",
            "--kill-whom=all",
            self.unit(),
        ]));
        assert!(
            self.wait_inactive(30).await,
            "{} survived SIGKILL",
            self.name
        );
        let _ = Command::new("systemctl")
            .args(["reset-failed", self.unit()])
            .status();
    }

    pub(super) fn kilndctl(
        &self,
        transcript: &mut Transcript,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Ran {
        transcript.text.push_str(&format!("# {}\n", self.name));
        transcript.kilndctl(&self.bin, self.socket(), args, stdin)
    }

    /// One kilndctl call on its own thread, for a request a crash interrupts.
    pub(super) fn kilndctl_background(
        &self,
        args: &[&str],
    ) -> std::thread::JoinHandle<(String, Ran)> {
        let (bin, socket, name) = (
            self.bin.clone(),
            self.socket().to_path_buf(),
            self.name.clone(),
        );
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        std::thread::spawn(move || {
            let mut transcript = Transcript::default();
            transcript
                .text
                .push_str(&format!("# {name} (in the background)\n"));
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let ran = transcript.kilndctl(&bin, &socket, &args, None);
            (std::mem::take(&mut transcript.text), ran)
        })
    }

    /// A query-only view of the daemon's own database.
    pub(super) fn view(&self) -> rusqlite::Connection {
        kilnd_view(self.state_dir())
    }

    /// One column of one sandbox row.
    pub(super) fn row(&self, id: &str, column: &str) -> Option<String> {
        self.view()
            .query_row(
                &format!("SELECT {column} FROM sandboxes WHERE id = ?1"),
                [id],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Every sandbox ID in the daemon's database, oldest first.
    pub(super) fn sandbox_ids(&self) -> Vec<String> {
        let view = self.view();
        let mut statement = view
            .prepare("SELECT id FROM sandboxes ORDER BY list_seq")
            .unwrap();
        statement
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    /// A byte copy of the stopped daemon's database files, owner and mode kept.
    pub(super) fn copy_state(&self, to: &Path) {
        assert!(!self.active(), "copy only a stopped daemon's state");
        let _ = std::fs::remove_dir_all(to);
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(self.state_dir()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    /// Puts a byte copy back in place of the daemon's database files.
    pub(super) fn restore_state(&self, from: &Path) {
        assert!(!self.active(), "restore only a stopped daemon's state");
        for entry in std::fs::read_dir(self.state_dir()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = self.state_dir().join(entry.file_name());
            std::fs::copy(entry.path(), &target).unwrap();
            std::os::unix::fs::chown(&target, Some(self.uid), Some(self.gid)).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

pub(super) fn account_ids(account: &str) -> (u32, u32) {
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
pub(super) fn dump(
    view: &rusqlite::Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Value {
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

pub(super) fn kilnd_view(state_dir: &Path) -> rusqlite::Connection {
    let view = rusqlite::Connection::open_with_flags(
        state_dir.join("kilnd.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .unwrap();
    view.pragma_update(None, "query_only", "ON").unwrap();
    view
}

pub(super) fn write_evidence(name: &str, contents: &str) {
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
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let (real, bin) = (&deployment.real, deployment.bin.clone());
    let instance = daemon.instance;
    let unit = daemon.unit().to_string();
    let socket = daemon.socket().to_path_buf();
    let state_dir = daemon.state_dir().to_path_buf();
    let log = daemon.log.clone();
    evidence("instance", instance);
    daemon.start(&deployment.image);
    let mut transcript = Transcript::default();
    daemon.wait_serving(real).await;
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
    let before_rm = host_leftovers(real, &context, vmm);
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
    let left = host_leftovers(real, &context, vmm);
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
    eprintln!(
        "B6 matrix: {}",
        json!({"scenario": "whole session through kilnd and kilndctl", "passed": true,
            "outcome": {"persistent_files": true, "timeout": "exit 124, lost, sandbox_stopped",
                "release": {"phase": phase, "receipt": evidence_id}}})
    );
}
