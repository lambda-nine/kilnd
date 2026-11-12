//! Root only, on the prepared Linux VM: the checkpoint group against the installed kiln
//! (format v1). Run with the built test binary:
//!
//! ```text
//! sudo TEST_BINARY --ignored --exact helper::checkpoint::tests::vm::c3_vm_checkpoint_group --test-threads=1 --nocapture
//! ```
//!
//! It registers a private copy of the alpine image, makes and removes its own sandboxes
//! and artifacts under a random instance ID, and puts the registry and the artifact
//! namespace back as it found them.
use super::super::*;
use crate::model::Id128;
use std::process::Command;

const KILN: &str = "/usr/local/bin/kiln";
const RUNS: &str = "/var/lib/kiln/runs";
const CPS: &str = "/var/lib/kiln/runs/.checkpoints";
const IMAGES: &str = "/var/lib/kiln/images";
const REGISTRY: &str = "/var/lib/kiln/image-registry";
const CHILD: &str = "KILND_C3_VM_CHILD";

fn kiln(args: &[&str]) -> std::process::Output {
    Command::new(KILN).args(args).output().unwrap()
}

struct Scene {
    image: String,
    instance: Id128,
    sandboxes: Vec<String>,
    registry_existed: bool,
    checkpoints_existed: bool,
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
        let image = format!("c3-helper-{}", std::process::id());
        let scene = Self {
            image: image.clone(),
            instance: Id128::random(),
            sandboxes: Vec::new(),
            registry_existed: std::path::Path::new(REGISTRY).exists(),
            checkpoints_existed: std::path::Path::new(CPS).exists(),
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

    fn create(&mut self, disk: &str) -> String {
        let out = kiln(&[
            "create",
            "--require-exec-protocol=1",
            "--image",
            &self.image,
            "--memory",
            "256M",
            "--pids",
            "64",
            "--disk",
            disk,
        ]);
        assert!(out.status.success(), "{out:?}");
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        self.sandboxes.push(id.clone());
        id
    }

    fn remove(&mut self, id: &str) {
        assert!(kiln(&["rm", id]).status.success());
        self.sandboxes.retain(|s| s != id);
    }

    fn sh(&self, id: &str, script: &str) -> (i32, String) {
        let out = kiln(&["exec", id, "sh", "-c", script]);
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    fn spec(&self, disk_bytes: u64) -> SandboxSpec {
        serde_json::from_value(serde_json::json!({
            "image": self.image, "memory_bytes": 268435456, "cpu_millis": 1000, "pids": 64,
            "disk_bytes": disk_bytes, "network": "none", "read_only_root": false,
            "writable_paths": [], "labels": {}
        }))
        .unwrap()
    }

    fn target(&self, n: u8) -> ArtifactTarget {
        ArtifactTarget {
            instance: self.instance,
            checkpoint: CheckpointId::parse(&format!("cp-{:032x}", u128::from(n) + 0xc3_0000))
                .unwrap(),
            generation: 1,
        }
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        for id in std::mem::take(&mut self.sandboxes) {
            let _ = kiln(&["rm", &id]);
        }
        let instance = self.instance.to_string();
        let listing = String::from_utf8_lossy(&kiln(&["checkpoint", "ls"]).stdout).into_owned();
        for line in listing.lines().skip(1) {
            let mut parts = line.splitn(3, ' ');
            let (_, owner, name) = (parts.next(), parts.next(), parts.next().unwrap_or(""));
            if owner == Some(instance.as_str())
                && let Some(at) = name.find("cp-")
            {
                let checkpoint = &name[at..(at + 35).min(name.len())];
                let _ = kiln(&[
                    "checkpoint",
                    "rm",
                    &format!("--instance={instance}"),
                    &format!("--checkpoint={checkpoint}"),
                ]);
            }
        }
        let _ = std::fs::remove_dir(format!("{CPS}/{instance}"));
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
        eprintln!(
            "C3 VM: cleaned up image {} and instance {instance}",
            self.image
        );
    }
}

fn new_node() -> Arc<Node> {
    Node::new(Arc::new(KilnWorkers::new(KILN.into()))).unwrap()
}

async fn call(
    node: &Arc<Node>,
    operation: CheckpointOperation,
    seconds: u64,
) -> CheckpointResponse {
    let request = CheckpointRequest {
        group_version: crate::checkpoint::GROUP_VERSION,
        helper_epoch: (!matches!(operation, CheckpointOperation::Capabilities))
            .then(|| node.epoch()),
        operation: operation.clone(),
    };
    request.validate().unwrap();
    let reply = node
        .handle(
            request,
            Instant::now() + Duration::from_secs(seconds),
            &CancellationToken::new(),
        )
        .await;
    reply
        .check(&operation, Some(node.epoch()))
        .unwrap_or_else(|e| panic!("{e}: {reply:?}"));
    eprintln!("C3 VM: {}", serde_json::to_string(&reply).unwrap());
    reply
}

fn binding(target: &ArtifactTarget, source: &str, limit: u64) -> CaptureBinding {
    CaptureBinding {
        target: target.clone(),
        operation: Id128::random(),
        source: source.into(),
        limit_bytes: limit,
    }
}

fn named(target: &ArtifactTarget) -> bool {
    kiln::process_table().unwrap().iter().any(|p| {
        kiln::named_artifact(p).is_some_and(|(i, c)| {
            i == target.instance.to_string() && c == target.checkpoint.as_str()
        })
    })
}

async fn absent(node: &Arc<Node>, target: &ArtifactTarget) -> bool {
    let reply = call(
        node,
        CheckpointOperation::Remove {
            target: target.clone(),
            operation: Id128::random(),
        },
        60,
    )
    .await;
    matches!(&reply, CheckpointResponse::Removed(r) if matches!(r.as_ref(), RemoveReply::Absent { .. }))
}

async fn listed(node: &Arc<Node>, instance: Id128) -> Vec<InventoryEntry> {
    match call(node, CheckpointOperation::Inventory { instance }, 30).await {
        CheckpointResponse::Inventory(inventory) => {
            assert!(inventory.complete, "{inventory:?}");
            inventory.entries
        }
        other => panic!("{other:?}"),
    }
}

/// The helper process the main test kills mid-capture: a capture with a long deadline.
#[test]
#[ignore = "a child of c3_vm_checkpoint_group, not a test by itself"]
fn c3_vm_child() {
    let Ok(spec) = std::env::var(CHILD) else {
        return;
    };
    let binding: CaptureBinding = serde_json::from_str(&spec).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let node = new_node();
            call(&node, CheckpointOperation::Capture { binding }, 120).await;
        });
}

#[test]
#[ignore = "root on the prepared VM with kiln's checkpoint format installed"]
fn c3_vm_checkpoint_group() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

async fn run() {
    let mut scene = Scene::new();
    let node = new_node();
    let CheckpointResponse::Capabilities(caps) =
        call(&node, CheckpointOperation::Capabilities, 5).await
    else {
        panic!()
    };
    assert!(caps.supported && caps.untracked_workers == 0, "{caps:?}");

    // 1. A real capture: COMPLETE evidence for exactly its binding.
    let source = scene.create("256M");
    let (rc, _) = scene.sh(
        &source,
        "mkdir -p /workspace/d && echo hello > /workspace/a && ln -s a /workspace/l && echo x > /workspace/d/b",
    );
    assert_eq!(rc, 0);
    let one = scene.target(1);
    let b = binding(&one, &source, 64 << 20);
    let reply = call(
        &node,
        CheckpointOperation::Capture { binding: b.clone() },
        120,
    )
    .await;
    let CheckpointResponse::Captured(captured) = &reply else {
        panic!()
    };
    let CaptureReply::Complete { evidence } = captured.as_ref() else {
        panic!("{reply:?}")
    };
    let fact = evidence.verify_complete(&b).unwrap().clone();
    eprintln!(
        "C3 VM evidence {} charge {} logical {} allocated {} entries {}",
        evidence.id, fact.charge_bytes, fact.logical_bytes, fact.allocated_bytes, fact.entries
    );
    let reply = call(
        &node,
        CheckpointOperation::Inspect {
            target: one.clone(),
            verify: true,
            operation: Some(b.operation),
        },
        120,
    )
    .await;
    let CheckpointResponse::Inspected(view) = &reply else {
        panic!()
    };
    assert!(
        matches!(&view.artifact, ArtifactView::Published { record } if record.content_sha256 == fact.content_sha256)
    );

    // 2. Busy source: a running command makes kiln refuse the lease, typed.
    let mut running = Command::new(KILN)
        .args(["exec", &source, "sleep", "4"])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(700));
    let two = scene.target(2);
    let reply = call(
        &node,
        CheckpointOperation::Capture {
            binding: binding(&two, &source, 64 << 20),
        },
        60,
    )
    .await;
    assert!(
        matches!(&reply, CheckpointResponse::Captured(r) if matches!(r.as_ref(), CaptureReply::Failed { reason: Reason::Busy, .. })),
        "{reply:?}"
    );
    running.wait().unwrap();

    // 3. Restore: a real fork with the captured files, and two refusals before allocation.
    let content = fact.content_sha256;
    let restore = |target: &ArtifactTarget, content, spec| CheckpointOperation::Restore {
        target: target.clone(),
        content_sha256: content,
        reader: Id128::random(),
        spec,
    };
    let reply = call(&node, restore(&one, content, scene.spec(256 << 20)), 120).await;
    let CheckpointResponse::Restored(restored) = &reply else {
        panic!()
    };
    let RestoreReply::Created { backend_id, .. } = restored.as_ref() else {
        panic!("{reply:?}")
    };
    let fork = backend_id.clone();
    scene.sandboxes.push(fork.clone());
    let (rc, out) = scene.sh(
        &fork,
        "cat /workspace/a /workspace/d/b; readlink /workspace/l",
    );
    assert_eq!((rc, out.as_str()), (0, "hello\nx\na\n"));
    let reply = call(&node, restore(&one, content, scene.spec(64 << 10)), 120).await;
    assert!(
        matches!(&reply, CheckpointResponse::Restored(r) if matches!(r.as_ref(), RestoreReply::NotCreated { reason: Reason::DiskTooSmall, .. })),
        "{reply:?}"
    );
    let other = crate::model::Digest::of(b"other");
    let reply = call(&node, restore(&one, other, scene.spec(256 << 20)), 120).await;
    assert!(
        matches!(&reply, CheckpointResponse::Restored(r) if matches!(r.as_ref(), RestoreReply::NotCreated { reason: Reason::Corrupt, .. })),
        "{reply:?}"
    );
    scene.remove(&fork);

    // 4. Removal: ABSENT, and the namespace lists nothing of it.
    assert!(absent(&node, &one).await);
    assert!(listed(&node, scene.instance).await.is_empty());

    // 5. A worker killed at its deadline mid-copy: reaped, the source works again, and
    //    whatever it staged is removed to ABSENT.
    let big = scene.create("1G");
    let (rc, _) = scene.sh(&big, "head -c 700000000 /dev/urandom > /workspace/big");
    assert_eq!(rc, 0);
    let three = scene.target(3);
    let started = Instant::now();
    let reply = call(
        &node,
        CheckpointOperation::Capture {
            binding: binding(&three, &big, 1 << 30),
        },
        1,
    )
    .await;
    eprintln!("C3 VM killed capture settled after {:?}", started.elapsed());
    assert!(
        matches!(&reply, CheckpointResponse::Captured(r) if matches!(r.as_ref(), CaptureReply::Failed { reason: Reason::Io, .. })),
        "{reply:?}"
    );
    assert!(!named(&three));
    assert_eq!(node.copy.available_permits(), COPY_WORKERS);
    eprintln!(
        "C3 VM after the kill: {:?}",
        listed(&node, scene.instance).await
    );
    assert_eq!(scene.sh(&big, "true").0, 0);
    assert!(absent(&node, &three).await);
    assert!(listed(&node, scene.instance).await.is_empty());

    // 6. The helper dies mid-capture: its worker dies with it (parent-death SIGKILL), and
    //    a new epoch proves absence once no process names the artifact.
    let four = scene.target(4);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "helper::checkpoint::tests::vm::c3_vm_child",
            "--include-ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(
            CHILD,
            serde_json::to_string(&binding(&four, &big, 1 << 30)).unwrap(),
        )
        .spawn()
        .unwrap();
    let mut seen = false;
    for _ in 0..200 {
        if named(&four) {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(seen, "the child's capture worker never started");
    std::thread::sleep(Duration::from_millis(500));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut gone = false;
    for _ in 0..400 {
        if !named(&four) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(gone, "the killed helper's worker outlived it");
    let restarted = new_node();
    assert_ne!(restarted.epoch(), node.epoch());
    eprintln!(
        "C3 VM after the helper died: {:?}",
        listed(&restarted, scene.instance).await
    );
    assert!(absent(&restarted, &four).await);
    assert!(listed(&restarted, scene.instance).await.is_empty());
    assert_eq!(scene.sh(&big, "true").0, 0);

    // 7. A live process naming an artifact (root's own command, say) blocks absence.
    let five = scene.target(5);
    let mut stray = Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import time; time.sleep(60)",
            "checkpoint",
            "inspect",
            &format!("--instance={}", five.instance),
            &format!("--checkpoint={}", five.checkpoint),
        ])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!absent(&restarted, &five).await);
    stray.kill().unwrap();
    stray.wait().unwrap();
    assert!(absent(&restarted, &five).await);

    node.shutdown().await;
    restarted.shutdown().await;
    drop(scene);
    eprintln!("C3 VM PASS");
}
