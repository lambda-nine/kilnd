//! Opt-in, privileged: the manager against the real kiln CLI. It needs root,
//! a prepared kiln host (the Lima VM after kiln's setup) and
//! `KILND_INTEGRATION=1`. Run it with `scripts/integration-test.sh`.
//!
//! It uses its own temporary database, never /var/lib/kilnd, and removes
//! every sandbox it creates.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kilnd::manager::{CreateRequest, ExecRequest, Limits, Manager};
use kilnd::model::{ExecutionState, SandboxState};
use kilnd::runtime::Runtime;
use kilnd::runtime::kiln::KilnRuntime;
use kilnd::store::Store;

fn enabled() -> bool {
    if std::env::var_os("KILND_INTEGRATION").is_none_or(|v| v != "1") {
        eprintln!("skipped: set KILND_INTEGRATION=1 (needs root and kiln)");
        return false;
    }
    // SAFETY: geteuid has no preconditions.
    assert_eq!(unsafe { libc::geteuid() }, 0, "the kiln integration test must run as root");
    true
}

fn kiln() -> KilnRuntime {
    KilnRuntime::new(PathBuf::from(std::env::var("KILN_BIN").unwrap_or_else(|_| "/usr/local/bin/kiln".into())))
}

fn exec(id: &str, argv: &[&str], timeout_ms: u32) -> ExecRequest {
    ExecRequest { sandbox_id: id.into(), argv: argv.iter().map(|s| s.to_string()).collect(), stdin: vec![], timeout_ms }
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn lifecycle_against_real_kiln() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let limits = Limits { max_output_bytes: 4096, ..Limits::default() };
    let m = Arc::new(Manager::new(kiln(), Store::open(&tmp.path().join("state")).unwrap(), limits));
    m.reconcile().await.unwrap();
    assert!(m.health().await.unwrap().serving);

    let req = CreateRequest { memory_bytes: 128 << 20, pids: 64, disk_bytes: 64 << 20, ..Default::default() };
    let s = m.create(req).await.unwrap();
    assert_eq!(s.state, SandboxState::Ready);
    let backend_id = s.backend_id.clone().unwrap();
    let listed = m.runtime().list().await.unwrap();
    assert!(listed.iter().any(|b| b.id == backend_id), "kiln ls shows {backend_id}");

    // Output, exit codes and stdin.
    let e = m.exec(exec(&s.id, &["sh", "-c", "echo out; echo err >&2; exit 3"], 10_000)).await.unwrap();
    assert_eq!((e.state, e.exit_code), (ExecutionState::Exited, Some(3)));
    assert_eq!((e.stdout.data.as_slice(), e.stderr.data.as_slice()), (&b"out\n"[..], &b"err\n"[..]));
    let mut with_stdin = exec(&s.id, &["sh", "-c", "cat > /workspace/note && cat /workspace/note"], 10_000);
    with_stdin.stdin = b"persisted".to_vec();
    assert_eq!(m.exec(with_stdin).await.unwrap().stdout.data, b"persisted");
    let e = m.exec(exec(&s.id, &["cat", "/workspace/note"], 10_000)).await.unwrap();
    assert_eq!(e.stdout.data, b"persisted", "state survives between executions");

    // Arguments are passed as a vector: shell syntax in one is just text.
    let e = m.exec(exec(&s.id, &["echo", "$(id -u); touch /tmp/injected"], 10_000)).await.unwrap();
    assert_eq!(e.stdout.data, b"$(id -u); touch /tmp/injected\n");
    let e = m.exec(exec(&s.id, &["test", "-e", "/tmp/injected"], 10_000)).await.unwrap();
    assert_eq!(e.exit_code, Some(1));

    // Bounded output.
    let e = m.exec(exec(&s.id, &["head", "-c", "100000", "/dev/zero"], 10_000)).await.unwrap();
    assert_eq!((e.stdout.data.len(), e.stdout.total_bytes), (4096, 100_000));

    // A timeout kills the command inside the sandbox, including what it
    // started in the background, and the sandbox keeps serving.
    let start = Instant::now();
    let e = m.exec(exec(&s.id, &["sh", "-c", "sleep 30 & sleep 30"], 1000)).await.unwrap();
    assert_eq!(e.state, ExecutionState::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(10));
    let e = m.exec(exec(&s.id, &["sh", "-c", "pgrep sleep || echo none"], 10_000)).await.unwrap();
    assert_eq!(e.stdout.data, b"none\n", "the timed-out command was stopped");

    // A missing program is the command's failure (127), not kiln's.
    let e = m.exec(exec(&s.id, &["/no/such/program"], 10_000)).await.unwrap();
    assert_eq!((e.state, e.exit_code), (ExecutionState::Exited, Some(127)));

    // Restart: a new manager over the same database keeps the sandbox.
    drop(m);
    let m = Arc::new(Manager::new(kiln(), Store::open(&tmp.path().join("state")).unwrap(), Limits::default()));
    let r = m.reconcile().await.unwrap();
    assert!(r.lost.is_empty(), "{r:?}");
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Ready);
    assert_eq!(m.exec(exec(&s.id, &["true"], 10_000)).await.unwrap().exit_code, Some(0));

    let d = m.delete(&s.id).await.unwrap();
    assert_eq!(d.state, SandboxState::Deleted);
    let listed = m.runtime().list().await.unwrap();
    assert!(!listed.iter().any(|b| b.id == backend_id), "kiln rm removed {backend_id}");
}

#[tokio::test]
#[ignore = "privileged; run scripts/integration-test.sh in the VM"]
async fn a_sandbox_killed_behind_kilnds_back_is_lost_after_reconcile() {
    if !enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let m = Arc::new(Manager::new(kiln(), Store::open(&tmp.path().join("state")).unwrap(), Limits::default()));
    let s = m.create(CreateRequest { memory_bytes: 64 << 20, disk_bytes: 16 << 20, ..Default::default() }).await.unwrap();
    // Remove it with kiln directly, as an operator or a reboot would.
    m.runtime().remove(s.backend_id.as_ref().unwrap()).await.unwrap();

    let r = m.reconcile().await.unwrap();
    assert_eq!(r.lost, vec![s.id.clone()]);
    assert_eq!(m.get(&s.id, 0).unwrap().0.state, SandboxState::Lost);
    let again = m.reconcile().await.unwrap();
    assert!(again.lost.is_empty(), "reconcile is repeatable");
    assert_eq!(m.delete(&s.id).await.unwrap().state, SandboxState::Deleted);
}
