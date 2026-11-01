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
use kilnd::model::{
    CommandStatus, CreateCertainty, ExecutionState, Network, RuntimeErrorKind, RuntimeStage,
    SandboxState,
};
use kilnd::runtime::Runtime;
use kilnd::runtime::kiln_direct::DirectKilnRuntime as KilnRuntime;
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

fn kiln_bin() -> PathBuf {
    PathBuf::from(std::env::var("KILN_BIN").unwrap_or_else(|_| "/usr/local/bin/kiln".into()))
}

fn kiln() -> KilnRuntime {
    KilnRuntime::new(kiln_bin())
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

// A second exec would queue behind the command under test. Inspect PID 1's
// root through /proc so readiness is observed before requesting cancellation.
fn workspace_marker_exists(backend_id: &str, marker: &str) -> bool {
    std::fs::read_to_string(format!("/sys/fs/cgroup/kiln/{backend_id}/cgroup.procs"))
        .unwrap()
        .lines()
        .any(|pid| {
            std::fs::metadata(format!("/proc/{pid}/root/workspace/{marker}"))
                .is_ok_and(|metadata| metadata.len() > 0)
        })
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
    let listed = m
        .runtime()
        .list(
            tokio::time::Instant::now() + Duration::from_secs(30),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap()
        .records;
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

    // Prove the detached child is alive before the timeout, then check
    // drainage and sandbox reuse.
    let start = Instant::now();
    let baseline_io = io_fd_count();
    let e = m
        .exec(exec(
            &s.id,
            &[
                "sh",
                "-c",
                r#"
                    rm -f /workspace/timeout-ready
                    setsid sh -c '
                        sleep 30 & child=$!
                        kill -0 "$child" || exit 91
                        printf "\000\377out"
                        printf "\000\376err" >&2
                        echo "$child" >/workspace/timeout-ready
                        wait
                    ' &
                    for attempt in $(seq 100); do
                        [ -s /workspace/timeout-ready ] && break
                        sleep 0.01
                    done
                    [ -s /workspace/timeout-ready ] || exit 90
                    sleep 30
                "#,
            ],
            1000,
        ))
        .await
        .unwrap();
    assert_eq!(e.state, ExecutionState::TimedOut);
    assert!(
        workspace_marker_exists(&backend_id, "timeout-ready"),
        "timeout preceded detached-child readiness"
    );
    assert!(e.stdout.total_bytes_known && e.stderr.total_bytes_known);
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
    let listed = m
        .runtime()
        .list(
            tokio::time::Instant::now() + Duration::from_secs(30),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap()
        .records;
    assert!(
        !listed.iter().any(|b| b.id == backend_id),
        "kiln rm removed {backend_id}"
    );
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn leader_exit_stops_detached_descendants_and_closes_output() {
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
    let script = r#"
        rm -f /workspace/leader-exit-ready
        nohup setsid sh -c '
            sleep 30 & child=$!
            kill -0 "$child" || exit 91
            echo detached-stdout
            echo detached-stderr >&2
            echo "$child" >/workspace/leader-exit-ready
            wait
        ' &
        for attempt in $(seq 100); do
            [ -s /workspace/leader-exit-ready ] && break
            sleep 0.01
        done
        [ -s /workspace/leader-exit-ready ] || exit 90
        echo leader-exit
        exit 23
    "#;
    // Read the real CLI's pipes to EOF, bypassing process::run's bounded
    // drain. Inherited stdout/stderr must close without waiting 30 seconds
    // for the detached sleep, and the leader's status must survive cleanup.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(kiln_bin())
            .args([
                "exec",
                s.backend_id.as_deref().unwrap(),
                "--",
                "sh",
                "-c",
                script,
            ])
            .env_clear()
            .env("PATH", kilnd::process::SAFE_PATH)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let typed = m.exec(exec(&s.id, &["sh", "-c", script], 10_000)).await;
    let survivors = m
        .exec(exec(
            &s.id,
            &["sh", "-c", "pgrep sleep || echo none"],
            10_000,
        ))
        .await;
    // Remove the sandbox even if the raw CLI timed out or left descendants.
    let deleted = m.delete(&s.id).await;
    let out = result
        .expect("kiln exec must close inherited output promptly")
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(out.stdout, b"detached-stdout\nleader-exit\n");
    assert_eq!(out.stderr, b"detached-stderr\n");
    let typed = typed.unwrap();
    assert_eq!(
        (typed.state, typed.exit_code),
        (ExecutionState::Exited, Some(23))
    );
    assert_eq!(typed.stdout.data, b"detached-stdout\nleader-exit\n");
    assert_eq!(typed.stderr.data, b"detached-stderr\n");
    assert!(typed.stdout.total_bytes_known && typed.stderr.total_bytes_known);
    let survivors = survivors.unwrap();
    assert_eq!(survivors.exit_code, Some(0));
    assert_eq!(
        survivors.stdout.data, b"none\n",
        "normal leader exit stopped its detached descendants"
    );
    assert_eq!(deleted.unwrap().state, SandboxState::Deleted);
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
        .remove(
            s.backend_id.as_ref().unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(120),
            &tokio_util::sync::CancellationToken::new(),
        )
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
        let error = manager.delete(&sandbox_id).await.unwrap_err();
        assert!(error.to_string().contains("cgroup"), "{error}");
        assert_eq!(
            manager.get(&sandbox_id, 0).unwrap().0.state,
            SandboxState::Deleting
        );
        assert_eq!(
            manager
                .health()
                .await
                .unwrap()
                .node_resources
                .reserved
                .sandboxes,
            1
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
                &[
                    "sh",
                    "-c",
                    r#"
                    setsid sh -c '
                        sleep 30 & child=$!
                        kill -0 "$child" || exit 91
                        printf "\000\377out"
                        printf "\000\376err" >&2
                        echo "$child" >/workspace/cancel-ready
                        wait
                    ' &
                    wait
                "#,
                ],
                60_000,
            ))
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        while !workspace_marker_exists(&backend_id, "cancel-ready") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached child never proved readiness after setsid and live child creation");
    assert!(exec_scope_populated(&backend_id));
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
    assert!(
        execution.stdout.total_bytes_known && execution.stderr.total_bytes_known,
        "both workload streams must reach real EOF before cancellation completes"
    );
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

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn node_reservations_bound_concurrent_real_creates_and_survive_restart() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let limits = Limits {
        max_sandboxes: 8,
        max_node_memory_bytes: 1 << 30,
        max_node_pids: 256,
        max_node_disk_bytes: 2 << 30,
        ..Limits::default()
    };
    let manager = Arc::new(Manager::new(
        kiln(),
        Store::open(&state_dir).unwrap(),
        limits.clone(),
    ));
    manager.reconcile().await.unwrap();

    let mut creates = Vec::new();
    for _ in 0..8 {
        let manager = manager.clone();
        creates.push(tokio::spawn(async move {
            manager
                .create(CreateRequest {
                    memory_bytes: 512 << 20,
                    pids: 128,
                    disk_bytes: 1 << 30,
                    ..Default::default()
                })
                .await
        }));
    }
    let mut sandboxes = Vec::new();
    let mut rejected = 0;
    for create in creates {
        match create.await.unwrap() {
            Ok(sandbox) => sandboxes.push(sandbox),
            Err(kilnd::manager::Error::ResourceExhausted(_)) => rejected += 1,
            Err(error) => panic!("unexpected create result: {error}"),
        }
    }
    assert_eq!((sandboxes.len(), rejected), (2, 6));
    let resources = manager.health().await.unwrap().node_resources;
    assert_eq!(resources.reserved.memory_bytes, 1 << 30);
    assert_eq!(resources.reserved.pids, 256);
    assert_eq!(resources.reserved.disk_bytes, 2 << 30);
    assert_eq!(resources.rejected_creates, 6);

    drop(manager);
    let manager = Arc::new(Manager::new(
        kiln(),
        Store::open(&state_dir).unwrap(),
        limits,
    ));
    manager.reconcile().await.unwrap();
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        2
    );
    assert!(matches!(
        manager
            .create(CreateRequest {
                memory_bytes: 512 << 20,
                pids: 128,
                disk_bytes: 1 << 30,
                ..Default::default()
            })
            .await,
        Err(kilnd::manager::Error::ResourceExhausted(_))
    ));

    let removed = sandboxes.pop().unwrap();
    manager.delete(&removed.id).await.unwrap();
    sandboxes.push(
        manager
            .create(CreateRequest {
                memory_bytes: 512 << 20,
                pids: 128,
                disk_bytes: 1 << 30,
                ..Default::default()
            })
            .await
            .unwrap(),
    );
    for sandbox in sandboxes {
        manager.delete(&sandbox.id).await.unwrap();
    }
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        0
    );
}

// A budget one small sandbox fills exactly, so any leaked charge is visible.
fn one_small_sandbox() -> (Limits, CreateRequest) {
    (
        Limits {
            max_sandboxes: 1,
            max_node_memory_bytes: 128 << 20,
            max_node_pids: 64,
            max_node_disk_bytes: 64 << 20,
            ..Limits::default()
        },
        CreateRequest {
            memory_bytes: 128 << 20,
            pids: 64,
            disk_bytes: 64 << 20,
            ..Default::default()
        },
    )
}

async fn listed_ids(manager: &Manager<KilnRuntime>) -> Vec<String> {
    let mut ids: Vec<String> = manager
        .runtime()
        .list(
            tokio::time::Instant::now() + Duration::from_secs(30),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap()
        .records
        .into_iter()
        .map(|sandbox| sandbox.id)
        .collect();
    ids.sort();
    ids
}

// What an allocation would leave behind, beyond the listing it could miss.
fn kiln_host_state() -> Vec<Vec<String>> {
    ["/sys/fs/cgroup/kiln", "/var/lib/kiln/runs"]
        .iter()
        .map(|dir| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        })
        .collect()
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn real_kiln_preflight_failures_release_reservations_across_restart() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let (limits, request) = one_small_sandbox();
    let manager = Arc::new(Manager::new(
        kiln(),
        Store::open(&state_dir).unwrap(),
        limits.clone(),
    ));
    manager.reconcile().await.unwrap();
    let host_before = kiln_host_state();
    let listed_before = listed_ids(&manager).await;

    // Both pass kilnd's validation and fail inside kiln before it picks an ID.
    let preflight_failures = [
        CreateRequest {
            image: "kilnd-regression-definitely-missing".into(),
            ..request.clone()
        },
        CreateRequest {
            network: Network::Allow(vec!["10.0.0.1:443".into()]),
            ..request.clone()
        },
    ];
    for failing in &preflight_failures {
        // Twice: a retained charge would turn the second into ResourceExhausted.
        for _ in 0..2 {
            let error = manager.create(failing.clone()).await.unwrap_err();
            assert!(
                matches!(error, kilnd::manager::Error::Backend(_)),
                "{error}"
            );
        }
    }
    assert_eq!(listed_ids(&manager).await, listed_before);
    assert_eq!(kiln_host_state(), host_before);
    assert_eq!(
        manager.health().await.unwrap().node_resources.reserved,
        Default::default()
    );

    drop(manager);
    let manager = Arc::new(Manager::new(
        kiln(),
        Store::open(&state_dir).unwrap(),
        limits,
    ));
    let reconciled = manager.reconcile().await.unwrap();
    assert!(reconciled.failed.is_empty() && reconciled.lost.is_empty());
    let rows = manager.list(false).unwrap();
    assert_eq!(rows.len(), 2 * preflight_failures.len());
    for row in &rows {
        assert_eq!((row.state, &row.backend_id), (SandboxState::Failed, &None));
        assert_eq!(row.create_certainty, CreateCertainty::DefinitelyNotCreated);
    }
    assert_eq!(
        manager.health().await.unwrap().node_resources.reserved,
        Default::default()
    );

    // The whole budget is still usable, and retiring the history leaves that
    // live sandbox alone.
    let live = manager.create(request).await.unwrap();
    let backend_id = live.backend_id.clone().unwrap();
    for row in &rows {
        assert_eq!(
            manager.delete(&row.id).await.unwrap().state,
            SandboxState::Deleted
        );
    }
    assert!(listed_ids(&manager).await.contains(&backend_id));
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        1
    );
    manager.delete(&live.id).await.unwrap();
    assert_eq!(listed_ids(&manager).await, listed_before);
    assert_eq!(kiln_host_state(), host_before);
}

// kilnd can no longer see the backend this test leaks on purpose.
struct RemoveCapturedBackend(PathBuf);

impl Drop for RemoveCapturedBackend {
    fn drop(&mut self) {
        if let Ok(id) = std::fs::read_to_string(&self.0)
            && !id.trim().is_empty()
        {
            let _ = std::process::Command::new(kiln_bin())
                .args(["rm", id.trim()])
                .status();
        }
    }
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn real_kiln_post_allocation_failure_stays_charged_across_restart() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_dir = tmp.path().join("state");
    let captured = tmp.path().join("backend-id");
    let _cleanup = RemoveCapturedBackend(captured.clone());
    // Allocates for real, then loses the result the way a dying CLI would.
    let wrapper = tmp.path().join("kiln-loses-its-result");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nif [ \"$1\" = create ]; then\n    '{real}' \"$@\" >'{captured}' || exit 99\n    echo 'lost after allocation' >&2\n    exit 1\nfi\nexec '{real}' \"$@\"\n",
            real = kiln_bin().display(),
            captured = captured.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (limits, request) = one_small_sandbox();
    let manager = Arc::new(Manager::new(
        KilnRuntime::new(wrapper.clone()),
        Store::open(&state_dir).unwrap(),
        limits.clone(),
    ));
    manager.reconcile().await.unwrap();

    let error = manager.create(request.clone()).await.unwrap_err();
    assert!(
        matches!(&error, kilnd::manager::Error::Backend(message) if message.contains("lost after allocation")),
        "{error}"
    );
    let row = manager.list(true).unwrap().remove(0);
    assert_eq!((row.state, &row.backend_id), (SandboxState::Failed, &None));
    assert_eq!(row.create_certainty, CreateCertainty::AllocationAmbiguous);
    let backend_id = std::fs::read_to_string(&captured)
        .unwrap()
        .trim()
        .to_string();

    drop(manager);
    let manager = Arc::new(Manager::new(
        KilnRuntime::new(wrapper),
        Store::open(&state_dir).unwrap(),
        limits,
    ));
    // The hidden backend is visible but unowned: not adopted, not removed.
    assert!(
        manager
            .reconcile()
            .await
            .unwrap()
            .unmanaged
            .contains(&backend_id)
    );
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        1
    );
    assert!(matches!(
        manager.delete(&row.id).await,
        Err(kilnd::manager::Error::FailedPrecondition(_))
    ));
    assert!(matches!(
        manager.create(request).await,
        Err(kilnd::manager::Error::ResourceExhausted(_))
    ));
    assert!(listed_ids(&manager).await.contains(&backend_id));

    // An operator's own cleanup is no evidence kilnd can use either.
    kiln()
        .remove(
            &backend_id,
            tokio::time::Instant::now() + Duration::from_secs(120),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    manager.reconcile().await.unwrap();
    assert_eq!(
        manager
            .health()
            .await
            .unwrap()
            .node_resources
            .reserved
            .sandboxes,
        1
    );
    assert!(matches!(
        manager.delete(&row.id).await,
        Err(kilnd::manager::Error::FailedPrecondition(_))
    ));
}
