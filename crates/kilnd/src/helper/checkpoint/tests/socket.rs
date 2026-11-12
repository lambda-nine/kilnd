//! The checkpoint group end to end: the real listener, framing and slots, the real
//! subprocess runner killing and reaping a fixture kiln CLI, and the unprivileged runtime
//! adapter checking every reply.
use super::*;
use crate::checkpoint::tests::{CHECKPOINT, INSTANCE, binding, content, target};
use crate::runtime::Runtime;
use crate::runtime::kiln::KilnRuntime;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const CAPS_WITH_LEASE: &str =
    "4b494c4e45584f00010002001d0000007f000000010001000500080000000000302e312e306769742074657374";

fn fixture(dir: &Path) -> PathBuf {
    let bin = dir.join("kiln");
    std::fs::write(
        &bin,
        format!(
            r#"#!/usr/bin/python3
import os,sys,time
D=os.path.dirname(os.path.abspath(__file__))
a=sys.argv[1:]
def opt(n):
    for x in a:
        if x.startswith(n+'='): return x[len(n)+1:]
def mode():
    try: return open(os.path.join(D,'mode')).read().strip()
    except FileNotFoundError: return 'ok'
def record(i,c,g,r):
    return ("kiln-checkpoint-record 1\ninstance %s\ncheckpoint %s\ngeneration %s\n"
        "content-sha256 {content}\nbinding-sha256 {content}\nimage alpine\nimage-sha256 {content}\n"
        "entries 3\nlogical-bytes 4096\nallocated-bytes 65536\ncharge-bytes 98304\nlimit-bytes %s\n") % (i,c,g,r)
ART=os.path.join(D,'art')
art=lambda i,c: os.path.join(ART,i+'_'+c)
if a[:1]==['capabilities']:
    os.write(1,bytes.fromhex('{CAPS_WITH_LEASE}')); sys.exit(0)
if a==['gc','--help']:
    print('Usage: kiln gc [ID]...'); sys.exit(0)
if a[:2]==['checkpoint','capture']:
    i,c,g,r=opt('--instance'),opt('--checkpoint'),opt('--generation'),opt('--max-bytes')
    with open(os.path.join(D,'pid'),'w') as f: f.write(str(os.getpid()))
    if mode()=='hang': time.sleep(60)
    if mode()=='slow': time.sleep(1)
    os.makedirs(ART,exist_ok=True)
    with open(art(i,c),'w') as f: f.write(g+' '+r)
    sys.stdout.write(record(i,c,g,r)); sys.exit(0)
if a[:2]==['checkpoint','inspect']:
    i,c=opt('--instance'),opt('--checkpoint')
    try: g,r=open(art(i,c)).read().split()
    except FileNotFoundError:
        sys.stdout.write("kiln-checkpoint-failure 1\nreason invalid_request\ndetail missing\n"); sys.exit(125)
    sys.stdout.write(record(i,c,g,r)); sys.exit(0)
if a[:2]==['checkpoint','rm']:
    p=art(opt('--instance'),opt('--checkpoint')); e=os.path.exists(p)
    if e: os.remove(p)
    sys.stdout.write("kiln-checkpoint-removed 1\nexisted %s\n" % ('yes' if e else 'no')); sys.exit(0)
if a[:2]==['checkpoint','ls']:
    out="kiln-checkpoint-inventory 1\n"
    for n in (sorted(os.listdir(ART)) if os.path.isdir(ART) else []):
        i,c=n.split('_'); out+="published %s %s\n" % (i,c)
    sys.stdout.write(out); sys.exit(0)
if a[:1]==['create']:
    sys.stdout.write("0123456789abcdef\n"); sys.exit(0)
sys.exit(2)
"#,
            content = content(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

struct Helper {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    runtime: KilnRuntime,
    socket: PathBuf,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<io::Result<()>>,
    node: Option<Arc<Node>>,
}

async fn helper(enabled: bool) -> Helper {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap();
    let bin = fixture(&dir);
    let socket = dir.join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let uid = unsafe { libc::geteuid() };
    let node = enabled.then(|| Node::new(Arc::new(KilnWorkers::new(bin.clone()))).unwrap());
    let stop = CancellationToken::new();
    let task = tokio::spawn(crate::helper::serve_with_groups(
        listener,
        uid,
        bin,
        None,
        node.clone(),
        stop.clone(),
    ));
    Helper {
        _dir: temp,
        dir,
        runtime: KilnRuntime::with_helper_uid(socket.clone(), uid),
        socket,
        stop,
        task,
        node,
    }
}

impl Helper {
    async fn call(
        &self,
        epoch: Option<Id128>,
        operation: CheckpointOperation,
        seconds: u64,
    ) -> CheckpointResponse {
        self.runtime
            .checkpoint(
                epoch,
                operation,
                Instant::now() + Duration::from_secs(seconds),
                &CancellationToken::new(),
            )
            .await
            .unwrap()
    }

    async fn epoch(&self) -> Id128 {
        match self.call(None, CheckpointOperation::Capabilities, 5).await {
            CheckpointResponse::Capabilities(caps) => {
                assert!(caps.enabled && caps.supported, "{caps:?}");
                caps.helper_epoch.unwrap()
            }
            other => panic!("{other:?}"),
        }
    }

    fn mode(&self, mode: &str) {
        std::fs::write(self.dir.join("mode"), mode).unwrap();
    }

    async fn stop(self) {
        self.stop.cancel();
        self.task.await.unwrap().unwrap();
        if let Some(node) = self.node {
            node.shutdown().await;
        }
    }
}

#[tokio::test]
async fn capture_restore_inspect_and_remove_cross_the_socket() {
    let helper = helper(true).await;
    let epoch = helper.epoch().await;
    let b = binding();
    let reply = helper
        .call(Some(epoch), CheckpointOperation::Capture { binding: b.clone() }, 60)
        .await;
    let CheckpointResponse::Captured(captured) = &reply else {
        panic!("{reply:?}")
    };
    let CaptureReply::Complete { evidence } = captured.as_ref() else {
        panic!("{reply:?}")
    };
    // What C4 would store: canonical bytes under their ID, verified for this binding.
    let bytes = evidence.evidence.canonical_bytes().unwrap();
    let stored = crate::checkpoint::SealedEvidence::decode(&bytes, evidence.id).unwrap();
    stored.verify_complete(&b).unwrap();
    let view = helper
        .call(
            Some(epoch),
            CheckpointOperation::Inspect {
                target: target(),
                verify: true,
                operation: Some(b.operation),
            },
            60,
        )
        .await;
    let CheckpointResponse::Inspected(view) = view else {
        panic!()
    };
    assert!(matches!(&view.artifact, ArtifactView::Published { record } if record.content_sha256 == content()));
    assert!(matches!(view.operation, Some(OperationState::Settled(_))));
    let reader = Id128::random();
    let reply = helper
        .call(
            Some(epoch),
            CheckpointOperation::Restore {
                target: target(),
                content_sha256: content(),
                reader,
                spec: serde_json::from_value(serde_json::json!({
                    "image": "alpine", "memory_bytes": 268435456, "cpu_millis": 1000,
                    "pids": 64, "disk_bytes": 1073741824, "network": "none",
                    "read_only_root": false, "writable_paths": [], "labels": {}
                }))
                .unwrap(),
            },
            60,
        )
        .await;
    assert!(
        matches!(&reply, CheckpointResponse::Restored(r) if matches!(r.as_ref(), RestoreReply::Created { backend_id, .. } if backend_id == "0123456789abcdef")),
        "{reply:?}"
    );
    let removal = Id128::random();
    let reply = helper
        .call(
            Some(epoch),
            CheckpointOperation::Remove {
                target: target(),
                operation: removal,
            },
            30,
        )
        .await;
    let CheckpointResponse::Removed(removed) = &reply else {
        panic!()
    };
    // Linux reads the process table; elsewhere nothing can prove absence.
    if cfg!(target_os = "linux") {
        assert!(
            matches!(removed.as_ref(), RemoveReply::Absent { evidence } if evidence.evidence.fact == crate::checkpoint::Fact::Absent { existed: true }),
            "{reply:?}"
        );
    } else {
        assert!(matches!(removed.as_ref(), RemoveReply::Retained { reason: Reason::Io, .. }));
    }
    assert!(!helper.dir.join("art").join(format!("{INSTANCE}_{CHECKPOINT}")).exists());
    helper.stop().await;
}

/// A real worker past its deadline is killed and reaped before the reply.
#[tokio::test]
async fn a_hung_worker_is_killed_and_reaped_at_its_deadline() {
    let helper = helper(true).await;
    let epoch = helper.epoch().await;
    helper.mode("hang");
    let started = Instant::now();
    let reply = helper
        .call(Some(epoch), CheckpointOperation::Capture { binding: binding() }, 2)
        .await;
    assert!(
        matches!(&reply, CheckpointResponse::Captured(r) if matches!(r.as_ref(), CaptureReply::Failed { reason: Reason::Io, .. })),
        "{reply:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(8));
    let pid: i32 = std::fs::read_to_string(helper.dir.join("pid"))
        .unwrap()
        .parse()
        .unwrap();
    // Not even a zombie: the runner reaped it.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    assert_eq!(helper.node.as_ref().unwrap().copy.available_permits(), COPY_WORKERS);
    helper.stop().await;
}

/// The waiter's cancellation byte detaches it; the worker finishes and settles.
#[tokio::test]
async fn a_cancelled_waiter_gets_pending_and_the_outcome_settles() {
    let helper = helper(true).await;
    let epoch = helper.epoch().await;
    helper.mode("slow");
    let b = binding();
    let cancel = CancellationToken::new();
    let waiter = {
        let (runtime, cancel, b) = (
            KilnRuntime::with_helper_uid(helper.socket.clone(), unsafe { libc::geteuid() }),
            cancel.clone(),
            b.clone(),
        );
        tokio::spawn(async move {
            runtime
                .checkpoint(
                    Some(epoch),
                    CheckpointOperation::Capture { binding: b },
                    Instant::now() + Duration::from_secs(30),
                    &cancel,
                )
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    let reply = waiter.await.unwrap().unwrap();
    assert!(
        matches!(&reply, CheckpointResponse::Captured(r) if **r == CaptureReply::Pending),
        "{reply:?}"
    );
    let mut settled = None;
    for _ in 0..100 {
        let view = helper
            .call(
                Some(epoch),
                CheckpointOperation::Inspect {
                    target: target(),
                    verify: false,
                    operation: Some(b.operation),
                },
                10,
            )
            .await;
        if let CheckpointResponse::Inspected(view) = view
            && let Some(OperationState::Settled(reply)) = &view.operation
        {
            settled = Some(reply.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(matches!(
        settled.as_deref(),
        Some(CheckpointResponse::Captured(r)) if matches!(r.as_ref(), CaptureReply::Complete { .. })
    ));
    helper.stop().await;
}

#[tokio::test]
async fn a_disabled_group_and_malformed_frames_get_nothing() {
    let helper = helper(false).await;
    let reply = helper.call(None, CheckpointOperation::Capabilities, 5).await;
    assert!(matches!(&reply, CheckpointResponse::Capabilities(c) if !c.enabled));
    let reply = helper
        .call(
            Some(Id128::random()),
            CheckpointOperation::Capture { binding: binding() },
            5,
        )
        .await;
    assert!(matches!(&reply, CheckpointResponse::Error(e) if e.kind == CheckpointErrorKind::Disabled));
    // A duplicate key anywhere in a group frame closes the connection unanswered, as
    // does a request outside the group's schema.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let deadline = crate::helper::monotonic_ns().unwrap() + 2_000_000_000;
    for frame in [
        format!(
            r#"{{"version":3,"timeout_ms":2000,"deadline_ns":{deadline},"operation":{{"checkpoint":{{"group_version":1,"group_version":1,"helper_epoch":null,"operation":"capabilities"}}}}}}"#
        ),
        format!(
            r#"{{"version":3,"timeout_ms":2000,"deadline_ns":{deadline},"operation":{{"checkpoint":{{"group_version":2,"helper_epoch":null,"operation":"capabilities"}}}}}}"#
        ),
        format!(
            r#"{{"version":3,"timeout_ms":2000,"deadline_ns":{deadline},"operation":{{"checkpoint":{{"group_version":1,"helper_epoch":null,"operation":{{"remove":{{"target":{{"instance":"{INSTANCE}","checkpoint":"{CHECKPOINT}","generation":1}},"operation":"{INSTANCE}"}}}}}}}}}}"#
        ),
        format!(
            r#"{{"version":3,"timeout_ms":2000,"deadline_ns":{deadline},"operation":{{"checkpoint":{{"group_version":1,"helper_epoch":null,"operation":"capabilities","path":"/"}}}}}}"#
        ),
    ] {
        let mut stream = tokio::net::UnixStream::connect(&helper.socket).await.unwrap();
        crate::helper::fds::send(&stream, &[]).await.unwrap();
        stream.write_u32(frame.len() as u32).await.unwrap();
        stream.write_all(frame.as_bytes()).await.unwrap();
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
        assert!(rest.is_empty(), "{frame} got a reply");
    }
    helper.stop().await;
}

/// The process-table proof on Linux: a live process naming the artifact blocks absence
/// until it is gone.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_live_process_naming_the_artifact_blocks_absence() {
    let helper = helper(true).await;
    let epoch = helper.epoch().await;
    let mut stray = std::process::Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import time; time.sleep(60)",
            "checkpoint",
            "rm",
            &format!("--instance={INSTANCE}"),
            &format!("--checkpoint={CHECKPOINT}"),
        ])
        .spawn()
        .unwrap();
    let remove = |operation| CheckpointOperation::Remove {
        target: target(),
        operation,
    };
    let reply = helper.call(Some(epoch), remove(Id128::random()), 30).await;
    assert!(
        matches!(&reply, CheckpointResponse::Removed(r) if matches!(r.as_ref(), RemoveReply::Retained { reason: Reason::Busy, .. })),
        "{reply:?}"
    );
    stray.kill().unwrap();
    stray.wait().unwrap();
    let reply = helper.call(Some(epoch), remove(Id128::random()), 30).await;
    assert!(
        matches!(&reply, CheckpointResponse::Removed(r) if matches!(r.as_ref(), RemoveReply::Absent { .. })),
        "{reply:?}"
    );
    helper.stop().await;
}
