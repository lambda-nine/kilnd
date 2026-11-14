//! Root only, on the prepared Linux VM (checkpoint milestone C5b-1): the checkpoint API
//! end to end over a real socket. A private daemon (`Manager<KilnRuntime>` with
//! checkpoints on, served by `server::serve` on a private socket) and a private
//! in-process root helper, against the installed kiln; `kilndctl` run as unprivileged
//! numeric uids drives capture, get, list and delete, and forks go through the
//! CreateSandbox handler with the caller's uid. Run with the built test binary and
//! kilndctl:
//!
//! ```text
//! sudo KILND_C5B_KILNDCTL=/path/to/kilndctl TEST_BINARY --ignored --exact \
//!     manager::checkpoint_vm_tests::api::c5b_vm_api --test-threads=1 --nocapture
//! ```

use kilnd_api::v1 as pb;
use pb::kilnd_service_server::KilndService;

use super::*;
use crate::admission::ConnectionLane;
use crate::server::PeerIdentity;
use crate::service::Service;

const OWNER: u32 = 1000;
const STRANGER: u32 = 1001;

/// `kilndctl --socket SOCKET ARGS` as `uid` (and that gid, no other groups).
async fn ctl(bin: &std::path::Path, socket: &std::path::Path, uid: u32, args: &[&str]) -> (i32, String, String) {
    let id = uid.to_string();
    let out = tokio::process::Command::new("setpriv")
        .args(["--reuid", &id, "--regid", &id, "--clear-groups"])
        .arg(bin)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .await
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The same, requiring success; its standard output.
async fn ok(bin: &std::path::Path, socket: &std::path::Path, uid: u32, args: &[&str]) -> String {
    let (code, stdout, stderr) = ctl(bin, socket, uid, args).await;
    assert_eq!(code, 0, "kilndctl {args:?}: {stdout}{stderr}");
    stdout
}

fn as_uid<T>(message: T, uid: u32) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.extensions_mut().insert(PeerIdentity {
        uid: Some(uid),
        lane: ConnectionLane::General,
    });
    request
}

#[test]
#[ignore = "root on the prepared VM with kiln's checkpoint format installed"]
fn c5b_vm_api() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_api());
}

async fn run_api() {
    let mut scene = Scene::new();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        tmp.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let state = tmp.path().join("state");
    let helper_socket = tmp.path().join("helper.sock");
    let helper = start_helper(&helper_socket);
    let clock = ManualClock::default();
    let m = manager(&state, &helper_socket, &clock, &scene.image);
    scene.instance = Some(m.store.identity().unwrap().instance_id.to_string());
    m.reconcile().await.unwrap();
    m.start_checkpoints().unwrap();

    // The API socket: its directory group-owned by the owner's gid (0750, socket 0660),
    // under a directory the unprivileged callers can traverse; kilndctl copied beside it.
    let public = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(
        public.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o711),
    )
    .unwrap();
    let bin = public.path().join("kilndctl");
    std::fs::copy(
        std::env::var("KILND_C5B_KILNDCTL").expect("KILND_C5B_KILNDCTL: a built kilndctl"),
        &bin,
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let socket = public.path().join("api").join("kilnd.sock");
    let bound = crate::server::bind(&socket, Some(OWNER)).await.unwrap();
    let stop = CancellationToken::new();
    let server = tokio::spawn(crate::server::serve(
        Arc::clone(&m),
        bound,
        stop.clone().cancelled_owned(),
        Duration::from_secs(5),
    ));
    let api = Service::new(Arc::clone(&m));

    // 1. Over the socket, as the owner: a source with files, then a keyed capture whose
    // retry returns the same checkpoint.
    let src = ok(&bin, &socket, OWNER, &["create"]).await.trim().to_string();
    ok(
        &bin,
        &socket,
        OWNER,
        &[
            "exec",
            &src,
            "--",
            "sh",
            "-c",
            "mkdir -p /root/w && echo hello > /root/w/a && ln -s a /root/w/l",
        ],
    )
    .await;
    let capture = ["checkpoint", "create", &src, "--request-id", "c5b-vm", "--max-lifetime", "1h"];
    let cp = ok(&bin, &socket, OWNER, &capture).await.trim().to_string();
    assert!(crate::checkpoint::CheckpointId::parse(&cp).is_ok(), "{cp}");
    assert_eq!(ok(&bin, &socket, OWNER, &capture).await.trim(), cp, "a keyed retry");
    let shown = ok(&bin, &socket, OWNER, &["checkpoint", "get", &cp]).await;
    assert!(shown.contains("state:      ready"), "{shown}");
    assert!(shown.contains(&format!("sandbox:    {src}")), "{shown}");
    assert!(shown.contains("content:    sha256 "), "{shown}");
    assert!(shown.contains("expiry:     lifetime 3600 s, idle 3600 s"), "{shown}");
    let listed = ok(&bin, &socket, OWNER, &["checkpoint", "ls", "--sandbox", &src]).await;
    assert_eq!(listed.lines().count(), 2, "{listed}");
    assert!(listed.contains(&cp), "{listed}");
    eprintln!("C5b VM 1 PASS: kilndctl capture {cp}, keyed retry, get, ls");

    // 2. Another uid sees nothing and changes nothing.
    let (code, _, stderr) = ctl(&bin, &socket, STRANGER, &["checkpoint", "get", &cp]).await;
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("notfound") || stderr.contains("not found"), "{stderr}");
    let (code, _, stderr) = ctl(&bin, &socket, STRANGER, &["checkpoint", "rm", &cp]).await;
    assert_eq!(code, 1, "{stderr}");
    let theirs = ok(&bin, &socket, STRANGER, &["checkpoint", "ls"]).await;
    assert_eq!(theirs.lines().count(), 1, "only the header: {theirs}");
    let (code, _, stderr) = ctl(&bin, &socket, STRANGER, &["checkpoint", "create", &src]).await;
    assert_eq!(code, 1, "{stderr}");
    eprintln!("C5b VM 2 PASS: a foreign caller gets not found");

    // 3. Forks through the CreateSandbox handler as the owner: the files are there,
    // provenance is recorded, and each is independent of the source and of the other.
    let fork = |uid: u32| {
        let api = &api;
        let cp = cp.clone();
        async move {
            api.create_sandbox(as_uid(
                pb::CreateSandboxRequest {
                    from_checkpoint: cp,
                    ..Default::default()
                },
                uid,
            ))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
        }
    };
    let f1 = fork(OWNER).await;
    let f2 = fork(OWNER).await;
    for f in [&f1, &f2] {
        assert_eq!(f.state, pb::SandboxState::Ready as i32, "{f:?}");
        assert_eq!(f.from_checkpoint, cp);
        assert_eq!(f.checkpoint_content_sha256.len(), 64);
        let seen = ok(
            &bin,
            &socket,
            OWNER,
            &["exec", &f.id, "--", "sh", "-c", "cat /root/w/a; readlink /root/w/l"],
        )
        .await;
        assert_eq!(seen, "hello\na\n", "{seen:?}");
    }
    let shown = ok(&bin, &socket, OWNER, &["get", &f1.id]).await;
    assert!(shown.contains(&format!("from:       {cp}")), "{shown}");
    ok(&bin, &socket, OWNER, &["exec", &f1.id, "--", "sh", "-c", "echo one > /root/w/a"]).await;
    ok(&bin, &socket, OWNER, &["exec", &src, "--", "sh", "-c", "echo src > /root/w/a"]).await;
    let read = |id: String| {
        let (bin, socket) = (bin.clone(), socket.clone());
        async move { ok(&bin, &socket, OWNER, &["exec", &id, "--", "cat", "/root/w/a"]).await }
    };
    assert_eq!(read(f1.id.clone()).await, "one\n");
    assert_eq!(read(f2.id.clone()).await, "hello\n");
    assert_eq!(read(src.clone()).await, "src\n");
    // A stranger cannot fork it.
    let e = api
        .create_sandbox(as_uid(
            pb::CreateSandboxRequest {
                from_checkpoint: cp.clone(),
                ..Default::default()
            },
            STRANGER,
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), tonic::Code::NotFound, "{e:?}");
    eprintln!("C5b VM 3 PASS: forks READY with the files, independent, provenance recorded");

    // 4. Delete the checkpoint over the socket: DELETED, its artifact gone, forks live.
    let removed = ok(&bin, &socket, OWNER, &["checkpoint", "rm", &cp]).await;
    assert_eq!(removed.trim(), format!("{cp} deleted"));
    assert!(scene.listed().is_empty(), "{:?}", scene.listed());
    assert_eq!(charged(&m), (0, 0));
    assert_eq!(read(f1.id.clone()).await, "one\n");
    assert_eq!(read(f2.id.clone()).await, "hello\n");
    let shown = ok(&bin, &socket, OWNER, &["checkpoint", "get", &cp]).await;
    assert!(shown.contains("state:      deleted"), "{shown}");
    let (code, _, stderr) = ctl(&bin, &socket, OWNER, &capture).await;
    assert_eq!(code, 1, "the key returns its DELETED checkpoint: {stderr}");
    assert!(stderr.contains("is deleted"), "{stderr}");
    eprintln!("C5b VM 4 PASS: checkpoint deleted and absent; forks unaffected");

    // Cleanup over the socket, then the server, the manager and the helper.
    for id in [&f1.id, &f2.id, &src] {
        let out = ok(&bin, &socket, OWNER, &["rm", id]).await;
        assert!(out.trim().ends_with("deleted"), "{out}");
    }
    assert_eq!(charged(&m), (0, 0));
    drop(api);
    stop.cancel();
    server.await.unwrap().unwrap();
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
    assert!(!socket.exists(), "the API socket is removed");
    eprintln!("C5b VM PASS");
}
