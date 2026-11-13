//! Root only, on the prepared Linux VM: the C5a checkpoint engine end to end, a real
//! `Manager<KilnRuntime>` on a private state directory talking to a private in-process
//! root helper (kiln and checkpoint groups) on a private socket, against the installed
//! kiln. Run with the built test binary:
//!
//! ```text
//! sudo TEST_BINARY --ignored --exact manager::checkpoint_vm_tests::c5a_vm_engine --test-threads=1 --nocapture
//! ```
//!
//! It registers a private copy of the alpine image, creates and deletes its own
//! sandboxes through the manager, uses a fresh daemon instance (so its artifacts are
//! its own), and puts the image registry and the artifact namespace back as it found
//! them. It never touches the node's kilnd, kilnd-helper or their state.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::expiry::ManualClock;
use crate::helper::checkpoint::{KilnWorkers, Node};
use crate::runtime::kiln::KilnRuntime;
use crate::store::CheckpointState;

const RUNS: &str = "/var/lib/kiln/runs";
const CPS: &str = "/var/lib/kiln/runs/.checkpoints";
const IMAGES: &str = "/var/lib/kiln/images";
const REGISTRY: &str = "/var/lib/kiln/image-registry";

fn kiln_bin() -> String {
    std::env::var("KILND_C5A_KILN").unwrap_or_else(|_| "/usr/local/bin/kiln".into())
}

fn kiln(args: &[&str]) -> std::process::Output {
    Command::new(kiln_bin()).args(args).output().unwrap()
}

struct Scene {
    image: String,
    registry_existed: bool,
    checkpoints_existed: bool,
    instance: Option<String>,
}

impl Scene {
    fn new() -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run as root on the VM");
        assert!(
            std::fs::read_dir(RUNS)
                .unwrap()
                .filter_map(Result::ok)
                .all(|e| e.file_name() == ".checkpoints"),
            "run with no other sandboxes"
        );
        let image = format!("c5a-engine-{}", std::process::id());
        let scene = Self {
            image: image.clone(),
            registry_existed: std::path::Path::new(REGISTRY).exists(),
            checkpoints_existed: std::path::Path::new(CPS).exists(),
            instance: None,
        };
        let copied = Command::new("cp")
            .args([
                "-a",
                &format!("{IMAGES}/alpine"),
                &format!("{IMAGES}/{image}"),
            ])
            .status()
            .unwrap();
        assert!(copied.success());
        let registered = kiln(&["image", "register", &image]);
        assert!(registered.status.success(), "{registered:?}");
        scene
    }

    /// The registered tree digest, from kiln's own registry entry.
    fn image_sha(&self) -> String {
        let out = kiln(&["image", "inspect", &self.image]);
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("sha256 ").map(str::to_string))
            .expect("a sha256 line")
    }

    /// `kiln checkpoint ls` lines naming this daemon instance's artifacts.
    fn listed(&self) -> Vec<String> {
        let Some(instance) = &self.instance else {
            return Vec::new();
        };
        let out = kiln(&["checkpoint", "ls"]);
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .skip(1)
            .filter(|l| l.contains(instance.as_str()))
            .map(str::to_string)
            .collect()
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        // Anything a failed run left: its sandboxes are this test's only ones.
        if let Ok(entries) = std::fs::read_dir(RUNS) {
            for e in entries.filter_map(Result::ok) {
                let name = e.file_name().to_string_lossy().into_owned();
                if name != ".checkpoints" {
                    let _ = kiln(&["rm", &name]);
                }
            }
        }
        if let Some(instance) = &self.instance {
            for line in self.listed() {
                if let Some(at) = line.find("cp-") {
                    let checkpoint = &line[at..(at + 35).min(line.len())];
                    let _ = kiln(&[
                        "checkpoint",
                        "rm",
                        &format!("--instance={instance}"),
                        &format!("--checkpoint={checkpoint}"),
                    ]);
                }
            }
            let _ = std::fs::remove_dir(format!("{CPS}/{instance}"));
        }
        if !self.checkpoints_existed {
            let _ = std::fs::remove_dir(CPS);
        }
        let _ = kiln(&["image", "rm", &self.image]);
        let _ = std::fs::remove_dir_all(format!("{IMAGES}/{}", self.image));
        for leftover in [
            format!("{REGISTRY}/{}", self.image),
            format!("{REGISTRY}/.{}.tmp", self.image),
        ] {
            let _ = std::fs::remove_file(leftover);
        }
        if !self.registry_existed {
            let _ = std::fs::remove_dir(REGISTRY);
        }
        eprintln!("C5a VM: cleaned up image {}", self.image);
    }
}

struct HelperProcess {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    node: Arc<Node>,
}

fn start_helper(socket: &std::path::Path) -> HelperProcess {
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let node = Node::new(Arc::new(KilnWorkers::new(kiln_bin().into()))).unwrap();
    let stop = CancellationToken::new();
    let task = tokio::spawn(crate::helper::serve_with_groups(
        listener,
        0,
        kiln_bin().into(),
        None,
        Some(node.clone()),
        stop.clone(),
    ));
    HelperProcess { stop, task, node }
}

fn limits(image: &str) -> Limits {
    Limits {
        default_image: image.into(),
        default_memory_bytes: 256 << 20,
        default_disk_bytes: 256 << 20,
        expiry: ExpiryLimits {
            restart_grace: Duration::ZERO,
            ..ExpiryLimits::default()
        },
        checkpoints: Some(CheckpointLimits {
            removal_retry: Duration::from_millis(200),
            max_removal_retry: Duration::from_secs(2),
            ..CheckpointLimits::default()
        }),
        ..Limits::default()
    }
}

fn manager(
    dir: &std::path::Path,
    socket: &std::path::Path,
    clock: &ManualClock,
    image: &str,
) -> Arc<Manager<KilnRuntime>> {
    Arc::new(Manager::with_clock(
        KilnRuntime::with_helper_uid(socket.to_path_buf(), 0),
        Store::reopen_after_restart(dir),
        limits(image),
        Arc::new(clock.clone()),
    ))
}

async fn until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn exec(id: &str, script: &str) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: vec!["sh".into(), "-c".into(), script.into()],
        stdin: Vec::new(),
        timeout_ms: 120_000,
        cwd: String::new(),
        env: Vec::new(),
    }
}

fn capture_req(id: &str, lifetime_s: u64) -> CaptureRequest {
    CaptureRequest {
        sandbox_id: id.into(),
        expiry: Some(RequestedExpiry {
            max_lifetime_ms: lifetime_s * 1000,
            idle_timeout_ms: 0,
        }),
        max_size_bytes: 0,
    }
}

fn charged(m: &Manager<KilnRuntime>) -> (u64, u64) {
    let u = m.store.checkpoint_usage(0).unwrap().node;
    (u.live, u.charged_bytes)
}

fn token(e: &Error) -> Option<&'static str> {
    match e {
        Error::FailedPrecondition(r) | Error::Refused(_, r) => r.reason(),
        _ => None,
    }
}

async fn big_source(m: &Arc<Manager<KilnRuntime>>) -> Sandbox {
    let s = m
        .create_owned(
            CreateRequest {
                disk_bytes: 1 << 30,
                ..CreateRequest::default()
            },
            1000,
        )
        .await
        .unwrap();
    let wrote = m
        .exec(exec(
            &s.id,
            "mkdir -p /root/big && head -c 419430400 /dev/urandom > /root/big/blob && sync",
        ))
        .await
        .unwrap();
    assert_eq!(wrote.exit_code, Some(0), "{wrote:?}");
    s
}

#[test]
#[ignore = "root on the prepared VM with kiln's checkpoint format installed"]
fn c5a_vm_engine() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

async fn run() {
    let mut scene = Scene::new();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        tmp.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let state = tmp.path().join("state");
    let socket = tmp.path().join("helper.sock");
    let helper = start_helper(&socket);
    let clock = ManualClock::default();
    let m = manager(&state, &socket, &clock, &scene.image);
    scene.instance = Some(m.store.identity().unwrap().instance_id.to_string());
    m.reconcile().await.unwrap();

    // 1. A real capture: READY, S charged, identity from the run's own records.
    let s = m
        .create_owned(CreateRequest::default(), 1000)
        .await
        .unwrap();
    let wrote = m
        .exec(exec(
            &s.id,
            "mkdir -p /root/w && echo hello > /root/w/a && ln -s a /root/w/l",
        ))
        .await
        .unwrap();
    assert_eq!(wrote.exit_code, Some(0));
    let r = capture_req(&s.id, 0);
    let k = CaptureKey {
        request_id: "c5a-vm".into(),
        sha256: crate::idempotency::capture_request_digest(&r),
    };
    let c = m
        .capture_checkpoint(r.clone(), 1000, Some(k.clone()), None)
        .await
        .unwrap();
    assert_eq!(c.state, CheckpointState::Ready, "{c:?}");
    let seal = c.seal.clone().unwrap();
    let identity = m
        .store
        .sandbox(&s.id)
        .unwrap()
        .unwrap()
        .lifecycle
        .image_identity
        .unwrap();
    assert_eq!(identity.content_sha256.to_string(), scene.image_sha());
    assert_eq!(c.image_content_sha256, identity.content_sha256);
    assert_eq!(charged(&m), (1, seal.charge_bytes));
    eprintln!(
        "C5a VM 1: READY {} S={} logical={} allocated={} entries={}",
        c.id, seal.charge_bytes, seal.logical_bytes, seal.allocated_bytes, seal.entries
    );
    // A verifying inspection agrees with the seal.
    let session = m.checkpoint_session().await.unwrap();
    match m
        .runtime
        .checkpoint(
            Some(session.epoch),
            crate::checkpoint::wire::CheckpointOperation::Inspect {
                target: c.target(),
                verify: true,
                operation: None,
            },
            Instant::now() + Duration::from_secs(300),
            &CancellationToken::new(),
        )
        .await
        .unwrap()
    {
        crate::checkpoint::wire::CheckpointResponse::Inspected(view) => match view.artifact {
            crate::checkpoint::wire::ArtifactView::Published { record } => {
                assert_eq!(record.content_sha256, seal.content_sha256);
                assert_eq!(record.charge_bytes, seal.charge_bytes);
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
    // A keyed retry: the same row, no second capture.
    let again = m.capture_checkpoint(r, 1000, Some(k), None).await.unwrap();
    assert_eq!(again.id, c.id);
    assert_eq!(scene.listed().len(), 1, "{:?}", scene.listed());
    eprintln!("C5a VM 1 PASS");

    // 2. A running Exec: capture refuses busy and reserves nothing.
    let sleeper = {
        let m = Arc::clone(&m);
        let id = s.id.clone();
        tokio::spawn(async move { m.exec(exec(&id, "sleep 3")).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let e = m
        .capture_checkpoint(capture_req(&s.id, 0), 1000, None, None)
        .await
        .unwrap_err();
    assert_eq!(token(&e), Some("checkpoint_busy"), "{e:?}");
    sleeper.await.unwrap().unwrap();
    assert_eq!(charged(&m).0, 1);
    eprintln!("C5a VM 2 PASS");

    // 3. Delete: D1-D3 through the real helper; storage absent, charge released.
    let d = m
        .delete_checkpoint(c.id.as_str(), 1000, true)
        .await
        .unwrap();
    assert_eq!(d.state, CheckpointState::Deleted);
    assert!(d.request_id_released_at_ms.is_some());
    assert_eq!(charged(&m), (0, 0));
    assert!(scene.listed().is_empty(), "{:?}", scene.listed());
    eprintln!("C5a VM 3 PASS");

    // 4. Lifetime expiry takes the same removal.
    let c = m
        .capture_checkpoint(capture_req(&s.id, 10), 1000, None, None)
        .await
        .unwrap();
    clock.advance(11_000);
    m.expire_checkpoints_due();
    let id = c.id.to_string();
    until("lifetime expiry", 60, || {
        m.store.checkpoint(&id).unwrap().unwrap().state == CheckpointState::Deleted
    })
    .await;
    assert_eq!(
        m.store.checkpoint(&id).unwrap().unwrap().deletion_reason,
        Some(DeletionReason::ExpiredLifetime)
    );
    assert_eq!(charged(&m), (0, 0));
    assert!(scene.listed().is_empty());
    eprintln!("C5a VM 4 PASS");

    // 5. Source Delete during a long capture: canceled, its worker reaped and storage
    // proved absent before the source is removed; FAILED, released.
    let big = big_source(&m).await;
    let capturing = {
        let m = Arc::clone(&m);
        let id = big.id.clone();
        tokio::spawn(async move {
            m.capture_checkpoint(capture_req(&id, 0), 1000, None, None)
                .await
        })
    };
    until("CAPTURING", 30, || {
        m.store
            .checkpoint_page(None, Some(&big.id), None, 1)
            .unwrap()
            .rows
            .first()
            .is_some_and(|c| c.state == CheckpointState::Capturing)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let deleted = m.delete(&big.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    let e = capturing.await.unwrap().unwrap_err();
    assert_eq!(token(&e), Some("checkpoint_not_ready"), "{e:?}");
    let failed = m
        .store
        .checkpoint_page(None, Some(&big.id), None, 1)
        .unwrap()
        .rows
        .remove(0);
    assert_eq!(failed.state, CheckpointState::Failed, "{failed:?}");
    assert_eq!(charged(&m), (0, 0));
    assert!(scene.listed().is_empty(), "{:?}", scene.listed());
    eprintln!("C5a VM 5 PASS");

    // 6. A daemon crash mid-capture: the restarted engine fails the row, the helper's
    // removal reaps the still-running worker, and the charge is released.
    let big = big_source(&m).await;
    let capturing = {
        let m = Arc::clone(&m);
        let id = big.id.clone();
        tokio::spawn(async move {
            m.capture_checkpoint(capture_req(&id, 0), 1000, None, None)
                .await
        })
    };
    until("CAPTURING", 30, || {
        m.store
            .checkpoint_page(None, Some(&big.id), None, 1)
            .unwrap()
            .rows
            .first()
            .is_some_and(|c| c.state == CheckpointState::Capturing)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let cid = m
        .store
        .checkpoint_page(None, Some(&big.id), None, 1)
        .unwrap()
        .rows[0]
        .id
        .to_string();
    m.begin_shutdown();
    m.drain_operations().await;
    let _ = capturing.await;
    drop(m);
    let m = manager(&state, &socket, &clock, &scene.image);
    let reconciled = m.reconcile().await.unwrap();
    assert!(!reconciled.checkpoints_blocked, "{reconciled:?}");
    m.rebase_expiry_clocks().unwrap();
    m.rebuild_expiry().unwrap();
    m.start_checkpoints().unwrap();
    until("FAILED after restart", 120, || {
        m.store.checkpoint(&cid).unwrap().unwrap().state == CheckpointState::Failed
    })
    .await;
    assert_eq!(charged(&m), (0, 0));
    assert!(scene.listed().is_empty(), "{:?}", scene.listed());
    eprintln!("C5a VM 6 PASS");

    // Cleanup through the manager, then the helper.
    for id in [s.id.clone(), big.id.clone()] {
        assert_eq!(m.delete(&id).await.unwrap().state, SandboxState::Deleted);
    }
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);
    helper.stop.cancel();
    helper.task.await.unwrap().unwrap();
    helper.node.shutdown().await;
    assert!(
        std::fs::read_dir(RUNS)
            .unwrap()
            .filter_map(Result::ok)
            .all(|e| e.file_name() == ".checkpoints")
    );
    eprintln!("C5a VM PASS");
}
