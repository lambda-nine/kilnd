//! Root on the prepared VM: the request floors, the writable-path refusals and
//! `kilnd release-ambiguous` against real kiln, on a private instance (its own state
//! directory and in-process helpers), never the node's own kilnd.
//!
//! Each step prints one `AMBIG VM` JSON line, the window's record. The test needs an
//! empty `kiln ls` and an empty kiln runs directory to start, and leaves both so.
//! `KILND_AMBIG_KILND` names the `kilnd` binary under test.

#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::runtime::kiln::KilnRuntime;

const KILN: &str = "/usr/local/bin/kiln";
const RUNS: &str = "/var/lib/kiln/runs";
/// The private instance's directory: fixed, so the window's cleanup can name it.
const DIR: &str = "/var/tmp/kilnd-ambig-vm";
/// A run directory without `shim.pid`, which `kiln ls` skips.
const STRAY: &str = "ambigvm-stray";
const OWNER: u32 = 1001;
const OTHER: u32 = 1002;
const ROLE: &str = "KILND_AMBIG_ROLE";

type M = Arc<Manager<KilnRuntime>>;

fn record(step: &str, outcome: Value) {
    println!("AMBIG VM {}", json!({ "step": step, "outcome": outcome }));
}

fn kilnd_bin() -> PathBuf {
    PathBuf::from(std::env::var("KILND_AMBIG_KILND").expect("KILND_AMBIG_KILND"))
}

fn kiln(args: &[&str]) -> std::process::Output {
    Command::new(KILN).args(args).output().unwrap()
}

/// `kiln ls` without its header.
fn kiln_ls() -> Vec<String> {
    let out = kiln(&["ls"]);
    assert!(out.status.success(), "kiln ls: {out:?}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(str::to_string)
        .collect()
}

/// kiln's runs directory by its entries, whatever `kiln ls` skips.
fn runs_entries() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(RUNS)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn kiln_state() -> Value {
    json!({ "kiln_ls": kiln_ls(), "runs": runs_entries() })
}

fn assert_clean(step: &str) {
    assert_eq!(kiln_ls(), Vec::<String>::new(), "{step}: kiln ls");
    assert_eq!(
        runs_entries(),
        Vec::<String>::new(),
        "{step}: runs directory"
    );
}

fn code(e: &Error) -> &'static str {
    match e {
        Error::InvalidArgument(_) => "INVALID_ARGUMENT",
        Error::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
        Error::FailedPrecondition(_) => "FAILED_PRECONDITION",
        Error::NotFound(_) => "NOT_FOUND",
        Error::Backend(_) => "backend",
        _ => "other",
    }
}

fn nobody() -> (u32, u32) {
    let name = std::ffi::CString::new("nobody").unwrap();
    // SAFETY: name is NUL-terminated; the entry is copied out at once.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    assert!(!pw.is_null(), "no nobody account");
    // SAFETY: pw is a live passwd entry.
    unsafe { ((*pw).pw_uid, (*pw).pw_gid) }
}

/// The state directory and everything in it to `owner`.
fn chown_state(state: &Path, owner: (u32, u32)) {
    fn walk(path: &Path, owner: (u32, u32)) {
        std::os::unix::fs::lchown(path, Some(owner.0), Some(owner.1)).unwrap();
        if std::fs::symlink_metadata(path).unwrap().is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                walk(&entry.unwrap().path(), owner);
            }
        }
    }
    walk(state, owner);
}

/// A private root helper serving the kiln group to `uid` alone.
async fn helper(socket: &Path, uid: u32, stop: &CancellationToken) {
    let listener = UnixListener::bind(socket).unwrap();
    std::os::unix::fs::chown(socket, Some(uid), None).unwrap();
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    tokio::spawn(crate::helper::serve_with_groups(
        listener,
        uid,
        PathBuf::from(KILN),
        None,
        None,
        stop.clone(),
    ));
}

struct Instance {
    state: PathBuf,
    daemon_socket: PathBuf,
    release_socket: PathBuf,
}

impl Instance {
    /// The private instance, started as `main.rs` starts kilnd (without its API).
    async fn start(&self) -> M {
        let m = Arc::new(Manager::new(
            KilnRuntime::with_helper_uid(self.daemon_socket.clone(), 0),
            Store::open(&self.state).unwrap(),
            Limits::default(),
        ));
        let r = m.reconcile().await.unwrap();
        assert!(r.unmanaged.is_empty() && !r.admission_blocked, "{r:?}");
        m.rebase_expiry_clocks().unwrap();
        m.rebase_create_requests().unwrap();
        m.prune().unwrap();
        m
    }

    /// Stops it: everything it supervises drains and its state lock is released.
    async fn stop(&self, m: M) {
        m.begin_shutdown();
        tokio::time::timeout(Duration::from_secs(30), m.drain_operations())
            .await
            .expect("drain");
        let mut m = m;
        for _ in 0..100 {
            match Arc::try_unwrap(m) {
                Ok(manager) => {
                    drop(manager);
                    return;
                }
                Err(again) => {
                    m = again;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        panic!("the private instance is still referenced");
    }

    /// `kilnd release-ambiguous` as root against this instance: (exit, stdout, stderr).
    /// Off the runtime's thread: the command calls this process's own helper.
    async fn release(&self, sandbox: &str, as_uid: Option<u32>) -> (i32, String, String) {
        let mut command = Command::new(kilnd_bin());
        command.args([
            "release-ambiguous",
            "--sandbox",
            sandbox,
            "--reason",
            "VM check: kiln ls and the runs directory are clean after the create",
            "--state-dir",
            self.state.to_str().unwrap(),
            "--helper-socket",
            self.release_socket.to_str().unwrap(),
        ]);
        if let Some(uid) = as_uid {
            command.uid(uid).gid(uid);
        }
        let out = tokio::task::spawn_blocking(move || command.output())
            .await
            .unwrap()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )
    }

    /// The release refused with `exit`, its message naming `names`, and the row still
    /// charged as before.
    async fn refused(
        &self,
        step: &str,
        sandbox: &str,
        exit: i32,
        names: &[&str],
        charged: &SandboxResources,
    ) {
        let (rc, out, err) = self.release(sandbox, None).await;
        record(step, json!({ "exit": rc, "stdout": out, "stderr": err }));
        assert_eq!(rc, exit, "{step}: {out} {err}");
        assert!(out.is_empty(), "{step}: {out}");
        for name in names {
            assert!(err.contains(name), "{step}: {err} does not name {name}");
        }
        assert_eq!(&self.charge_as_root().await, charged, "{step}");
    }

    /// The instance's reservations, read by starting it as root and stopping it again.
    async fn charge_as_root(&self) -> SandboxResources {
        let owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        let had = std::fs::metadata(&self.state).unwrap();
        chown_state(&self.state, owner);
        let m = self.start().await;
        let reserved = m.health().await.unwrap().node_resources.reserved;
        self.stop(m).await;
        use std::os::unix::fs::MetadataExt as _;
        chown_state(&self.state, (had.uid(), had.gid()));
        reserved
    }
}

async fn reserved(m: &M) -> SandboxResources {
    m.health().await.unwrap().node_resources.reserved
}

fn sh(sandbox_id: &str, script: &str) -> ExecRequest {
    ExecRequest {
        sandbox_id: sandbox_id.into(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        stdin: vec![],
        timeout_ms: 0,
        cwd: String::new(),
        env: vec![],
    }
}

/// Create, one exec, delete: everything released and kiln clean again.
async fn round_trip(m: &M, step: &str, request: CreateRequest, script: &str, expect: &str) {
    let zero = reserved(m).await;
    let sandbox = m.create_owned(request, OWNER).await.unwrap_or_else(|e| {
        record(
            step,
            json!({ "create": format!("{} {e}", code(&e)), "kiln": kiln_state() }),
        );
        panic!("{step}: create refused: {e:?}")
    });
    assert_eq!(sandbox.state, SandboxState::Ready, "{step}");
    let spec = &sandbox.spec;
    let exec = m.exec(sh(&sandbox.id, script)).await.unwrap();
    let stdout = String::from_utf8_lossy(&exec.stdout.data).into_owned();
    let stderr = String::from_utf8_lossy(&exec.stderr.data).into_owned();
    let deleted = m.delete(&sandbox.id).await.unwrap();
    let after = reserved(m).await;
    record(
        step,
        json!({
            "id": sandbox.id, "cpu_millis": spec.cpu_millis, "memory_bytes": spec.memory_bytes,
            "pids": spec.pids, "disk_bytes": spec.disk_bytes, "writable": spec.writable_paths,
            "exec": { "exit": exec.exit_code, "stdout": stdout, "stderr": stderr },
            "delete": format!("{:?}", deleted.state), "released": after == zero,
            "kiln": kiln_state(),
        }),
    );
    assert_eq!(exec.exit_code, Some(0), "{step}: {stderr}");
    assert_eq!(stdout, expect, "{step}");
    assert_eq!(deleted.state, SandboxState::Deleted, "{step}");
    assert_eq!(after, zero, "{step}");
    assert_clean(step);
}

fn paths(path: &str) -> CreateRequest {
    CreateRequest {
        read_only_root: true,
        writable_paths: vec![path.into()],
        ..Default::default()
    }
}

#[test]
#[ignore = "a child role of the ambiguous-create VM test"]
fn ambig_vm_lock_holder_child() {
    if std::env::var(ROLE).as_deref() != Ok("hold") {
        return;
    }
    let state = PathBuf::from(std::env::var("KILND_AMBIG_STATE").unwrap());
    let (uid, gid) = nobody();
    // SAFETY: plain credential calls at the start of a child process, checked.
    unsafe {
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setresgid(gid, gid, gid), 0);
        assert_eq!(libc::setresuid(uid, uid, uid), 0);
    }
    // The private instance's own open: its state lock, as kilnd takes it first.
    let _store = Store::open(&state).unwrap();
    println!("AMBIG HOLDING");
    std::io::stdout().flush().unwrap();
    let mut sink = String::new();
    while std::io::stdin().read_line(&mut sink).unwrap() > 0 {}
}

#[test]
#[ignore = "root on the prepared VM: ambiguous-create floors, paths and release"]
fn ambig_vm_floors_paths_and_audited_release() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    assert_clean("start");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(scenario());
}

async fn scenario() {
    let dir = Path::new(DIR);
    std::fs::create_dir(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711)).unwrap();
    let instance = Instance {
        state: dir.join("state"),
        daemon_socket: dir.join("helper-daemon.sock"),
        release_socket: dir.join("helper-release.sock"),
    };
    std::fs::create_dir(&instance.state).unwrap();
    std::fs::set_permissions(&instance.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (nobody_uid, nobody_gid) = nobody();
    let stop = CancellationToken::new();
    // The daemon's helper answers this root process; the release's answers the account
    // the command drops to, the state directory's owner.
    helper(&instance.daemon_socket, 0, &stop).await;
    helper(&instance.release_socket, nobody_uid, &stop).await;

    let m = instance.start().await;
    let zero = reserved(&m).await;
    assert_eq!(zero, SandboxResources::default());

    // 1. Below every floor, and over kiln's own mounts: INVALID_ARGUMENT, nothing
    //    charged, nothing in kiln.
    let below = [
        (
            "cpu_millis 1",
            CreateRequest {
                cpu_millis: 1,
                ..Default::default()
            },
        ),
        (
            "cpu_millis 9",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS - 1,
                ..Default::default()
            },
        ),
        (
            "memory 1 MiB",
            CreateRequest {
                memory_bytes: 1 << 20,
                ..Default::default()
            },
        ),
        (
            "memory floor - 1",
            CreateRequest {
                memory_bytes: MIN_MEMORY_BYTES - 1,
                ..Default::default()
            },
        ),
        (
            "pids 1",
            CreateRequest {
                pids: 1,
                ..Default::default()
            },
        ),
        (
            "pids 15",
            CreateRequest {
                pids: MIN_PIDS - 1,
                ..Default::default()
            },
        ),
        (
            "disk 1",
            CreateRequest {
                disk_bytes: 1,
                ..Default::default()
            },
        ),
        (
            "disk 12288",
            CreateRequest {
                disk_bytes: 12288,
                ..Default::default()
            },
        ),
        (
            "disk floor - 1",
            CreateRequest {
                disk_bytes: MIN_DISK_BYTES - 1,
                ..Default::default()
            },
        ),
        ("/proc", paths("/proc")),
        ("/proc/x", paths("/proc/x")),
        ("/sys/x", paths("/sys/x")),
        ("/sys/fs/cgroup/x", paths("/sys/fs/cgroup/x")),
        ("/dev/x", paths("/dev/x")),
    ];
    for (name, request) in below {
        let error = m.create_owned(request, OWNER).await.unwrap_err();
        let rows = m.list(true).unwrap().len();
        let charged = reserved(&m).await;
        record(
            &format!("refused {name}"),
            json!({ "code": code(&error), "message": error.to_string(), "rows": rows,
                    "charged": charged != zero, "kiln": kiln_state() }),
        );
        assert_eq!(code(&error), "INVALID_ARGUMENT", "{name}: {error:?}");
        assert_eq!((rows, charged), (0, zero), "{name}");
        assert_clean(name);
    }

    // 2. Exactly at each floor, then all together: create, one exec, delete.
    let at = [
        (
            "at cpu floor",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS,
                ..Default::default()
            },
        ),
        (
            "at memory floor",
            CreateRequest {
                memory_bytes: MIN_MEMORY_BYTES,
                ..Default::default()
            },
        ),
        (
            "at pids floor",
            CreateRequest {
                pids: MIN_PIDS,
                ..Default::default()
            },
        ),
        (
            "at disk floor",
            CreateRequest {
                disk_bytes: MIN_DISK_BYTES,
                ..Default::default()
            },
        ),
        (
            "at every floor",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS,
                memory_bytes: MIN_MEMORY_BYTES,
                pids: MIN_PIDS,
                disk_bytes: MIN_DISK_BYTES,
                ..Default::default()
            },
        ),
    ];
    for (name, request) in at {
        round_trip(&m, name, request, "echo ok", "ok\n").await;
    }
    // /dev/shm is kiln's writable tmpfs: a path under it creates and is writable.
    round_trip(
        &m,
        "/dev/shm/x writable",
        paths("/dev/shm/x"),
        "echo hi > /dev/shm/x/f && cat /dev/shm/x/f",
        "hi\n",
    )
    .await;
    let deleted_id = m.list(true).unwrap()[0].id.clone();

    // 3. A path kiln refuses only after allocating still leaves an ambiguous FAILED row,
    //    charged; at the node's whole memory budget it refuses every other uid.
    let limits = Limits::default();
    let error = m
        .create_owned(
            CreateRequest {
                memory_bytes: limits.max_node_memory_bytes,
                ..paths("/etc/passwd/x")
            },
            OWNER,
        )
        .await
        .unwrap_err();
    let row = m
        .list(true)
        .unwrap()
        .into_iter()
        .find(|s| s.state == SandboxState::Failed)
        .expect("a FAILED row");
    let charged = reserved(&m).await;
    let other = m
        .create_owned(CreateRequest::default(), OTHER)
        .await
        .unwrap_err();
    let delete = m.delete(&row.id).await.unwrap_err();
    record(
        "ambiguous /etc/passwd/x",
        json!({
            "code": code(&error), "message": error.to_string(), "id": row.id,
            "state": format!("{:?}", row.state), "backend_id": row.backend_id,
            "certainty": format!("{:?}", row.create_certainty), "charged": row.is_charged(),
            "reserved_memory": charged.memory_bytes, "kiln": kiln_state(),
            "other_uid": format!("{} {other}", code(&other)),
            "delete": format!("{} {delete}", code(&delete)),
        }),
    );
    assert_eq!(row.backend_id, None);
    assert_eq!(row.create_certainty, CreateCertainty::AllocationAmbiguous);
    assert!(row.is_charged());
    assert_eq!(charged.memory_bytes, limits.max_node_memory_bytes);
    assert_eq!(code(&other), "RESOURCE_EXHAUSTED", "{other:?}");
    assert!(
        delete.to_string().contains("kilnd release-ambiguous"),
        "{delete}"
    );
    assert_clean("ambiguous create");

    // 4. With the instance stopped and its state its account's, release-ambiguous
    //    refuses until the node is proved clean.
    instance.stop(m).await;
    chown_state(&instance.state, (nobody_uid, nobody_gid));

    let (rc, out, err) = instance.release(&row.id, Some(OTHER)).await;
    record(
        "refused non-root",
        json!({ "exit": rc, "stdout": out, "stderr": err }),
    );
    assert_eq!(rc, 77, "{err}");

    // The instance holds its lock.
    let mut holder = Command::new(std::env::current_exe().unwrap());
    holder
        .args([
            "--ignored",
            "--exact",
            "manager::ambiguous_vm_tests::ambig_vm_lock_holder_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, "hold")
        .env("KILND_AMBIG_STATE", &instance.state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut holder = holder.spawn().unwrap();
    let mut lines = BufReader::new(holder.stdout.take().unwrap()).lines();
    loop {
        let line = lines
            .next()
            .expect("the holder ended before holding")
            .unwrap();
        if line.contains("AMBIG HOLDING") {
            break;
        }
    }
    instance
        .refused(
            "refused lock held",
            &row.id,
            75,
            &["already owned", "kilnd.lock"],
            &charged,
        )
        .await;
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());

    // A run kiln lists that no row owns: created by kiln itself, then removed by ID.
    let out = kiln(&[
        "create",
        "--image=alpine",
        "--memory=67108864",
        "--cpus=0.100",
        "--pids=32",
        "--disk=67108864",
        "--net=none",
    ]);
    assert!(out.status.success(), "kiln create: {out:?}");
    let run = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(kiln_ls().iter().any(|l| l.starts_with(&run)), "{run}");
    instance
        .refused(
            "refused unexplained run",
            &row.id,
            69,
            &[&run, "kiln rm"],
            &charged,
        )
        .await;
    let rm = kiln(&["rm", &run]);
    record(
        "removed unexplained run",
        json!({ "id": run, "rm": rm.status.code(), "kiln": kiln_state() }),
    );
    assert!(rm.status.success(), "{rm:?}");
    assert_clean("after kiln rm");

    // A run directory without shim.pid, which kiln ls skips.
    let stray = Path::new(RUNS).join(STRAY);
    std::fs::create_dir(&stray).unwrap();
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(kiln_ls(), Vec::<String>::new());
    instance
        .refused(
            "refused pid-less run directory",
            &row.id,
            69,
            &[STRAY],
            &charged,
        )
        .await;
    std::fs::remove_dir(&stray).unwrap();
    assert_clean("after the stray directory");

    // Not an ambiguous reservation, and no such sandbox.
    instance
        .refused(
            "refused deleted row",
            &deleted_id,
            65,
            &["not FAILED"],
            &charged,
        )
        .await;
    instance
        .refused(
            "refused unknown id",
            "sb-00000000000000ff",
            65,
            &["no such sandbox"],
            &charged,
        )
        .await;

    // 5. Proved clean: released once, with its audit row.
    let (rc, out, err) = instance.release(&row.id, None).await;
    record(
        "released",
        json!({ "exit": rc, "stdout": out, "stderr": err }),
    );
    assert_eq!(rc, 0, "{err}");
    assert!(
        out.starts_with(&format!(
            "released {} owner_uid={OWNER} sandboxes=1 ",
            row.id
        )) && out.contains(&format!(" memory_bytes={} ", limits.max_node_memory_bytes)),
        "{out}"
    );
    instance
        .refused(
            "refused already released",
            &row.id,
            65,
            &["already released"],
            &zero,
        )
        .await;

    // 6. The instance again, as root: nothing charged, one audit row, and every uid
    //    creates; the released row deletes.
    chown_state(&instance.state, (0, 0));
    let m = instance.start().await;
    let audits = m.store.operator_release_count().unwrap();
    let (released, _) = m.get(&row.id, 0).unwrap();
    let after = reserved(&m).await;
    record(
        "after release",
        json!({ "audit_rows": audits, "state": format!("{:?}", released.state),
                "accounting": format!("{:?}", released.accounting),
                "charged": released.is_charged(), "reserved_zero": after == zero }),
    );
    assert_eq!(audits, 1);
    assert!(!released.is_charged());
    assert_eq!(after, zero);
    let sandbox = m
        .create_owned(CreateRequest::default(), OTHER)
        .await
        .unwrap();
    let exec = m.exec(sh(&sandbox.id, "echo ok")).await.unwrap();
    assert_eq!(exec.exit_code, Some(0));
    m.delete(&sandbox.id).await.unwrap();
    let deleted = m.delete(&row.id).await.unwrap();
    record(
        "other uid creates; released row deletes",
        json!({ "other": sandbox.id, "exec_exit": exec.exit_code,
                "released_row": format!("{:?}", deleted.state), "kiln": kiln_state() }),
    );
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(reserved(&m).await, zero);
    assert_clean("end");
    instance.stop(m).await;
    stop.cancel();
    std::fs::remove_dir_all(dir).unwrap();
}
