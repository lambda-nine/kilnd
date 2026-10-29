//! Opt-in, privileged: the manager against the real kiln CLI. It needs root,
//! a prepared kiln host (the Lima VM after kiln's setup) and
//! `KILND_INTEGRATION=1`. Run it with `scripts/integration-test.sh`.
//!
//! It uses its own temporary database, never /var/lib/kilnd, and removes
//! every sandbox it creates.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kilnd::manager::{CreateRequest, ExecRequest, Limits, Manager};
use kilnd::model::{CommandStatus, ExecutionState, RuntimeErrorKind, RuntimeStage, SandboxState};
use kilnd::runtime::Runtime;
use kilnd::runtime::kiln::KilnRuntime;
use kilnd::store::Store;

fn enabled() -> bool {
    if std::env::var_os("KILND_INTEGRATION").is_none_or(|v| v != "1") {
        eprintln!("skipped: set KILND_INTEGRATION=1 (needs root and kiln)");
        return false;
    }
    // SAFETY: geteuid has no preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "the kiln integration test must run as root"
    );
    true
}

fn kiln() -> KilnRuntime {
    KilnRuntime::new(PathBuf::from(
        std::env::var("KILN_BIN").unwrap_or_else(|_| "/usr/local/bin/kiln".into()),
    ))
}

fn exec(id: &str, argv: &[&str], timeout_ms: u32) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms,
    }
}

fn exec_scope_populated(backend_id: &str) -> bool {
    std::fs::read_to_string(format!(
        "/sys/fs/cgroup/kiln/{backend_id}/exec/cgroup.events"
    ))
    .is_ok_and(|events| events.lines().any(|line| line == "populated 1"))
}

fn io_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|target| {
            let target = target.to_string_lossy();
            target.starts_with("pipe:[") || target.starts_with("socket:[")
        })
        .count()
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn lifecycle_against_real_kiln() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let limits = Limits {
        max_output_bytes: 4096,
        ..Limits::default()
    };
    let m = Arc::new(Manager::new(
        kiln(),
        Store::open(&tmp.path().join("state")).unwrap(),
        limits,
    ));
    m.reconcile().await.unwrap();
    assert!(m.health().await.unwrap().serving);

    let req = CreateRequest {
        memory_bytes: 128 << 20,
        pids: 64,
        disk_bytes: 64 << 20,
        ..Default::default()
    };
    let s = m.create(req).await.unwrap();
    assert_eq!(s.state, SandboxState::Ready);
    let backend_id = s.backend_id.clone().unwrap();
    let listed = m.runtime().list().await.unwrap();
    assert!(
        listed.iter().any(|b| b.id == backend_id),
        "kiln ls shows {backend_id}"
    );

    // Output, exit codes and stdin.
    let e = m
        .exec(exec(
            &s.id,
            &["sh", "-c", "echo out; echo err >&2; exit 3"],
            10_000,
        ))
        .await
        .unwrap();
    assert_eq!((e.state, e.exit_code), (ExecutionState::Exited, Some(3)));
    assert_eq!(
        (e.stdout.data.as_slice(), e.stderr.data.as_slice()),
        (&b"out\n"[..], &b"err\n"[..])
    );
    let mut with_stdin = exec(
        &s.id,
        &["sh", "-c", "cat > /workspace/note && cat /workspace/note"],
        10_000,
    );
    with_stdin.stdin = b"persisted".to_vec();
    assert_eq!(m.exec(with_stdin).await.unwrap().stdout.data, b"persisted");
    let e = m
        .exec(exec(&s.id, &["cat", "/workspace/note"], 10_000))
        .await
        .unwrap();
    assert_eq!(
        e.stdout.data, b"persisted",
        "state survives between executions"
    );

    // Arguments are passed as a vector: shell syntax in one is just text.
    let e = m
        .exec(exec(
            &s.id,
            &["echo", "$(id -u); touch /tmp/injected"],
            10_000,
        ))
        .await
        .unwrap();
    assert_eq!(e.stdout.data, b"$(id -u); touch /tmp/injected\n");
    let e = m
        .exec(exec(&s.id, &["test", "-e", "/tmp/injected"], 10_000))
        .await
        .unwrap();
    assert_eq!(e.exit_code, Some(1));

    // Bounded output.
    let e = m
        .exec(exec(&s.id, &["head", "-c", "100000", "/dev/zero"], 10_000))
        .await
        .unwrap();
    assert_eq!((e.stdout.data.len(), e.stdout.total_bytes), (4096, 100_000));
    assert!(e.stdout.truncated());
    assert!(e.stdout.total_bytes_known);
    let e=m.exec(exec(&s.id,&["sh","-c","printf '\\000\\377'; head -c 100000 /dev/zero; { printf '\\000\\376'; head -c 100000 /dev/zero; } >&2"],10_000)).await.unwrap();
    assert_eq!(
        (
            e.stdout.data.len(),
            e.stdout.total_bytes,
            e.stderr.data.len(),
            e.stderr.total_bytes
        ),
        (4096, 100002, 4096, 100002)
    );
    assert_eq!(&e.stdout.data[..2], b"\0\xff");
    assert_eq!(&e.stderr.data[..2], b"\0\xfe");
    assert!(e.stdout.truncated() && e.stderr.truncated());
    assert!(e.stdout.total_bytes_known && e.stderr.total_bytes_known);
    let exit125 = m
        .exec(exec(
            &s.id,
            &[
                "sh",
                "-c",
                "printf '\\000\\377out'; printf '\\000\\376err' >&2; exit 125",
            ],
            10_000,
        ))
        .await
        .unwrap();
    assert_eq!(
        (exit125.state, exit125.exit_code),
        (ExecutionState::Exited, Some(125))
    );
    assert_eq!(exit125.command_status, Some(CommandStatus::Exited(125)));
    assert!(exit125.runtime_error.is_none());
    assert_eq!(exit125.stdout.data, b"\0\xffout");
    assert_eq!(exit125.stderr.data, b"\0\xfeerr");
    let wire125 = kilnd::service::execution_pb(exit125.clone());
    assert_eq!(
        wire125.command_status.as_ref().unwrap().termination,
        Some(kilnd_api::v1::command_status::Termination::ExitCode(125))
    );
    let exit143 = m
        .exec(exec(&s.id, &["sh", "-c", "exit 143"], 10_000))
        .await
        .unwrap();
    let signal15 = m
        .exec(exec(&s.id, &["sh", "-c", "kill -TERM $$"], 10_000))
        .await
        .unwrap();
    assert_eq!(exit143.exit_code, signal15.exit_code);
    assert_eq!(exit143.command_status, Some(CommandStatus::Exited(143)));
    assert_eq!(
        signal15.command_status,
        Some(CommandStatus::Signaled {
            signal: 15,
            core_dumped: false
        })
    );

    // A timeout kills the command inside the sandbox, including what it
    // started in the background, and the sandbox keeps serving.
    let start = Instant::now();
    let baseline_io = io_fd_count();
    let e = m
        .exec(exec(
            &s.id,
            &[
                "sh",
                "-c",
                "printf '\\000\\377out'; printf '\\000\\376err' >&2; sleep 30 & sleep 30",
            ],
            1000,
        ))
        .await
        .unwrap();
    assert_eq!(e.state, ExecutionState::TimedOut);
    assert_eq!(e.stdout.data, b"\0\xffout");
    assert_eq!(e.stderr.data, b"\0\xfeerr");
    assert_eq!(
        io_fd_count(),
        baseline_io,
        "timeout leaked private sockets or CLI pipes"
    );
    assert!(start.elapsed() < Duration::from_secs(10));
    let e = m
        .exec(exec(
            &s.id,
            &["sh", "-c", "pgrep sleep || echo none"],
            10_000,
        ))
        .await
        .unwrap();
    assert_eq!(
        e.stdout.data, b"none\n",
        "the timed-out command was stopped"
    );

    // PID1 reports execvp failure separately from a real command exit 127.
    let e = m
        .exec(exec(&s.id, &["/no/such/program"], 10_000))
        .await
        .unwrap();
    assert_eq!((e.state, e.exit_code), (ExecutionState::Failed, None));
    let error = e.runtime_error.as_ref().unwrap();
    assert_eq!(
        (error.kind, error.stage),
        (RuntimeErrorKind::LaunchFailed, RuntimeStage::Exec)
    );
    assert!(e.command_status.is_none());

    // Restart: a new manager over the same database keeps the sandbox.
    drop(m);
    let m = Arc::new(Manager::new(
        kiln(),
        Store::open(&tmp.path().join("state")).unwrap(),
        Limits::default(),
    ));
    let r = m.reconcile().await.unwrap();
    assert!(r.lost.is_empty(), "{r:?}");
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Ready);
    assert_eq!(m.execution(&exit125.id).unwrap(), exit125);
    assert_eq!(
        kilnd::service::execution_pb(m.execution(&exit125.id).unwrap()),
        wire125
    );
    assert_eq!(
        m.execution(&e.id).unwrap(),
        e,
        "failed exec evidence survives reopen"
    );
    assert_eq!(
        m.exec(exec(&s.id, &["true"], 10_000))
            .await
            .unwrap()
            .exit_code,
        Some(0)
    );

    let d = m.delete(&s.id).await.unwrap();
    assert_eq!(d.state, SandboxState::Deleted);
    let listed = m.runtime().list().await.unwrap();
    assert!(
        !listed.iter().any(|b| b.id == backend_id),
        "kiln rm removed {backend_id}"
    );
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn a_sandbox_killed_behind_kilnds_back_is_lost_after_reconcile() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let m = Arc::new(Manager::new(
        kiln(),
        Store::open(&tmp.path().join("state")).unwrap(),
        Limits::default(),
    ));
    let s = m
        .create(CreateRequest {
            memory_bytes: 64 << 20,
            disk_bytes: 16 << 20,
            ..Default::default()
        })
        .await
        .unwrap();
    // Remove it with kiln directly, as an operator or a reboot would.
    m.runtime()
        .remove(s.backend_id.as_ref().unwrap())
        .await
        .unwrap();

    let r = m.reconcile().await.unwrap();
    assert_eq!(r.lost, vec![s.id.clone()]);
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Lost);
    let again = m.reconcile().await.unwrap();
    assert!(again.lost.is_empty(), "reconcile is repeatable");
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn a_reappeared_backend_recovers_after_manager_restart_once() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let sandbox = {
        let manager = Arc::new(Manager::new(
            kiln(),
            Store::open(&state_dir).unwrap(),
            Limits::default(),
        ));
        manager.reconcile().await.unwrap();
        manager
            .create(CreateRequest {
                memory_bytes: 64 << 20,
                disk_bytes: 16 << 20,
                ..Default::default()
            })
            .await
            .unwrap()
    };
    {
        let store = Store::open(&state_dir).unwrap();
        store
            .set_sandbox_state(
                &sandbox.id,
                SandboxState::Lost,
                None,
                Some("injected false absence before restart"),
            )
            .unwrap();
    }

    let manager = Arc::new(Manager::new(
        kiln(),
        Store::open(&state_dir).unwrap(),
        Limits::default(),
    ));
    let first = manager.reconcile().await.unwrap();
    assert_eq!(first.recovered, vec![sandbox.id.clone()]);
    assert_eq!(
        manager.get(&sandbox.id, 0).unwrap().0.state,
        SandboxState::Ready
    );
    assert!(manager.reconcile().await.unwrap().recovered.is_empty());
    assert_eq!(
        manager
            .exec(exec(&sandbox.id, &["true"], 10_000))
            .await
            .unwrap()
            .exit_code,
        Some(0)
    );
    assert_eq!(
        manager.delete(&sandbox.id).await.unwrap().state,
        SandboxState::Deleted
    );
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn hidden_registry_mount_does_not_mark_a_live_sandbox_lost() {
    const CHILD: &str = "KILND_HIDDEN_REGISTRY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let state_dir = PathBuf::from(std::env::var_os("KILND_TEST_STATE").unwrap());
        let empty = PathBuf::from(std::env::var_os("KILND_TEST_EMPTY").unwrap());
        let status = std::process::Command::new("mount")
            .args(["--bind", empty.to_str().unwrap(), "/var/lib/kiln/runs"])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to hide the registry in child namespace"
        );

        let manager = Arc::new(Manager::new(
            kiln(),
            Store::open(&state_dir).unwrap(),
            Limits::default(),
        ));
        let error = manager.reconcile().await.unwrap_err();
        assert!(error.to_string().contains("cgroup"), "{error}");
        let sandbox_id = std::env::var("KILND_TEST_SANDBOX").unwrap();
        assert_eq!(
            manager.get(&sandbox_id, 0).unwrap().0.state,
            SandboxState::Ready
        );
        return;
    }
    if !enabled() {
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let empty = tmp.path().join("empty-registry");
    std::fs::create_dir(&empty).unwrap();
    let sandbox = {
        let manager = Arc::new(Manager::new(
            kiln(),
            Store::open(&state_dir).unwrap(),
            Limits::default(),
        ));
        manager.reconcile().await.unwrap();
        manager
            .create(CreateRequest {
                memory_bytes: 64 << 20,
                disk_bytes: 16 << 20,
                ..Default::default()
            })
            .await
            .unwrap()
    };

    let output = std::process::Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            std::env::current_exe().unwrap().to_str().unwrap(),
            "--exact",
            "hidden_registry_mount_does_not_mark_a_live_sandbox_lost",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("KILND_TEST_STATE", &state_dir)
        .env("KILND_TEST_EMPTY", &empty)
        .env("KILND_TEST_SANDBOX", &sandbox.id)
        .output()
        .unwrap();

    let manager = Arc::new(Manager::new(
        kiln(),
        Store::open(&state_dir).unwrap(),
        Limits::default(),
    ));
    manager.reconcile().await.unwrap();
    assert_eq!(
        manager.delete(&sandbox.id).await.unwrap().state,
        SandboxState::Deleted
    );
    assert!(
        output.status.success(),
        "hidden-registry child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn dropping_exec_waiter_cleans_detached_descendants_and_pipes() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let m = Arc::new(Manager::new(
        kiln(),
        Store::open(&tmp.path().join("state")).unwrap(),
        Limits::default(),
    ));
    let s = m
        .create(CreateRequest {
            memory_bytes: 64 << 20,
            pids: 64,
            disk_bytes: 16 << 20,
            ..Default::default()
        })
        .await
        .unwrap();
    let backend_id = s.backend_id.clone().unwrap();
    let baseline_pipes = io_fd_count();
    let waiter = tokio::spawn({
        let m = m.clone();
        let id = s.id.clone();
        async move {
            m.exec(exec(
                &id,
                &["sh", "-c", "printf '\\000\\377out'; printf '\\000\\376err' >&2; setsid sh -c 'sleep 30 & wait' & sleep 30"],
                60_000,
            ))
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        while !exec_scope_populated(&backend_id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached descendant never entered the exec cgroup");
    let execution_id = m.get(&s.id, 1).unwrap().1[0].id.clone();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());

    let execution = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let execution = m.execution(&execution_id).unwrap();
            if execution.state != ExecutionState::Running {
                break execution;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client-disconnected execution did not finalize");
    assert_eq!(execution.state, ExecutionState::Canceled);
    assert_eq!(execution.stdout.data, b"\0\xffout");
    assert_eq!(execution.stderr.data, b"\0\xfeerr");
    assert_eq!(
        execution.failure_reason.as_deref(),
        Some("client disconnected")
    );
    assert!(
        !exec_scope_populated(&backend_id),
        "execution cgroup still has descendants"
    );
    assert_eq!(
        io_fd_count(),
        baseline_pipes,
        "backend stdout/stderr pipe descriptors leaked"
    );

    let reuse = m
        .exec(exec(
            &s.id,
            &["sh", "-c", "pgrep sleep || echo none"],
            10_000,
        ))
        .await
        .unwrap();
    assert_eq!(
        reuse.stdout.data, b"none\n",
        "canceled descendants survived into the next exec"
    );
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
}
