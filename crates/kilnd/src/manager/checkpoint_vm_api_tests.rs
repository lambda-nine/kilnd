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
/// The API socket's group. Both callers run in it, as members of a deployment's socket
/// group would, so the socket is reachable and kilnd authorizes by the peer's uid.
const SOCKET_GID: u32 = OWNER;

/// `kilndctl --socket SOCKET ARGS` as `uid`, with gid `SOCKET_GID` and no other groups.
async fn ctl(bin: &std::path::Path, socket: &std::path::Path, uid: u32, args: &[&str]) -> (i32, String, String) {
    let (id, gid) = (uid.to_string(), SOCKET_GID.to_string());
    let out = tokio::process::Command::new("setpriv")
        .args(["--reuid", &id, "--regid", &gid, "--clear-groups"])
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
    let bound = crate::server::bind(&socket, Some(SOCKET_GID)).await.unwrap();
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

// --- C5b-2: discovery, stats, headroom and `create --from-checkpoint` ----------------------

/// A private daemon with checkpoints on, a short Health cache, list pages capped at 3
/// and `headroom` bytes of headroom, over the helper at `helper_socket`.
fn discovery_manager(
    state: &std::path::Path,
    helper_socket: &std::path::Path,
    clock: &ManualClock,
    image: &str,
    headroom: u64,
) -> Arc<Manager<KilnRuntime>> {
    let mut l = limits(image);
    l.health_success_cache = Duration::from_millis(100);
    l.health_failure_cache = Duration::from_millis(100);
    l.max_list_page_size = 3;
    l.checkpoints.as_mut().unwrap().headroom_bytes = headroom;
    Arc::new(Manager::with_clock(
        KilnRuntime::with_helper_uid(helper_socket.to_path_buf(), 0),
        Store::reopen_after_restart(state),
        l,
        Arc::new(clock.clone()),
    ))
}

/// The private API socket and a kilndctl copy the unprivileged callers can run.
struct PublicSocket {
    _dir: tempfile::TempDir,
    bin: std::path::PathBuf,
    socket: std::path::PathBuf,
}

fn public_socket() -> PublicSocket {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o711))
        .unwrap();
    let bin = dir.path().join("kilndctl");
    std::fs::copy(
        std::env::var("KILND_C5B_KILNDCTL").expect("KILND_C5B_KILNDCTL: a built kilndctl"),
        &bin,
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let socket = dir.path().join("api").join("kilnd.sock");
    PublicSocket {
        _dir: dir,
        bin,
        socket,
    }
}

/// `kilndctl health` after the probe cache expired.
async fn health_text(p: &PublicSocket, uid: u32) -> (i32, String) {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let (code, stdout, stderr) = ctl(&p.bin, &p.socket, uid, &["health"]).await;
    (code, format!("{stdout}{stderr}"))
}

fn line<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix:?} line in {text}"))
}

#[test]
#[ignore = "root on the prepared VM with kiln's checkpoint format installed"]
fn c5b2_vm_discovery() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_discovery());
}

async fn run_discovery() {
    let mut scene = Scene::new();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .unwrap();
    let helper_socket = tmp.path().join("helper.sock");
    let mut helper = start_helper(&helper_socket);
    let clock = ManualClock::default();
    let m = discovery_manager(&tmp.path().join("state"), &helper_socket, &clock, &scene.image, 1 << 30);
    scene.instance = Some(m.store.identity().unwrap().instance_id.to_string());
    m.reconcile().await.unwrap();
    m.start_checkpoints().unwrap();
    // The helper's own probes on this host: XFS with project quotas, the registry, and
    // free space on runs and its loop backing.
    let caps = m
        .checkpoint_caps(
            tokio::time::Instant::now() + Duration::from_secs(10),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    eprintln!(
        "C5b-2 VM: helper supported {} ({:?}), storage {:?}",
        caps.supported, caps.unsupported_reason, caps.storage
    );
    assert!(caps.supported, "{caps:?}");
    assert!(
        caps.storage.is_some_and(|s| s.backing_free_bytes.is_some()),
        "{caps:?}"
    );
    let p = public_socket();
    let bound = crate::server::bind(&p.socket, Some(SOCKET_GID)).await.unwrap();
    let stop = CancellationToken::new();
    let server = tokio::spawn(crate::server::serve(
        Arc::clone(&m),
        bound,
        stop.clone().cancelled_owned(),
        Duration::from_secs(5),
    ));
    let (bin, socket) = (p.bin.clone(), p.socket.clone());

    // 1. Health advertises the feature with its limits once the probes pass.
    let (code, h) = health_text(&p, OWNER).await;
    assert_eq!(code, 0, "{h}");
    assert!(line(&h, "features:").contains("workspace_checkpoint"), "{h}");
    assert!(line(&h, "checkpoint limits:").contains("1073741824 bytes each"), "{h}");
    assert!(line(&h, "checkpoints:").contains("node 0/128"), "{h}");
    assert!(!h.contains("withdrawn"), "{h}");
    eprintln!("C5b-2 VM 1 PASS: Health lists workspace_checkpoint and its limits\n{h}");

    // 2. Capture as the owner; Health's stats for the owner and a bystander.
    let src = ok(&bin, &socket, OWNER, &["create"]).await.trim().to_string();
    ok(&bin, &socket, OWNER, &["exec", &src, "--", "sh", "-c", "mkdir -p /root/w && echo hello > /root/w/a"]).await;
    let cp = ok(&bin, &socket, OWNER, &["checkpoint", "create", &src]).await.trim().to_string();
    let (_, mine) = health_text(&p, OWNER).await;
    let (_, theirs) = health_text(&p, STRANGER).await;
    let size = m.store.checkpoint(&cp).unwrap().unwrap().seal.unwrap().charge_bytes;
    assert!(line(&mine, "checkpoints:").contains(&format!("node 1/128, {size}/")), "{mine}");
    assert!(line(&mine, "checkpoints:").contains(&format!("yours 1/32, {size}/")), "{mine}");
    assert!(line(&theirs, "checkpoints:").contains("yours 0/32, 0/"), "{theirs}");
    eprintln!("C5b-2 VM 2 PASS: capture {cp} ({size} bytes); stats for owner and bystander");

    // 3. Two forks through `kilndctl create --from-checkpoint`, independent.
    let f1 = ok(&bin, &socket, OWNER, &["create", "--from-checkpoint", &cp]).await.trim().to_string();
    let f2 = ok(&bin, &socket, OWNER, &["create", "--from-checkpoint", &cp]).await.trim().to_string();
    let read = |id: String| {
        let (bin, socket) = (bin.clone(), socket.clone());
        async move { ok(&bin, &socket, OWNER, &["exec", &id, "--", "cat", "/root/w/a"]).await }
    };
    assert_eq!(read(f1.clone()).await, "hello\n");
    assert_eq!(read(f2.clone()).await, "hello\n");
    ok(&bin, &socket, OWNER, &["exec", &f1, "--", "sh", "-c", "echo one > /root/w/a"]).await;
    assert_eq!(read(f2.clone()).await, "hello\n");
    assert_eq!(read(src.clone()).await, "hello\n");
    let shown = ok(&bin, &socket, OWNER, &["get", &f2]).await;
    assert!(shown.contains(&format!("from:       {cp}")), "{shown}");
    let (code, _, stderr) = ctl(&bin, &socket, STRANGER, &["create", "--from-checkpoint", &cp]).await;
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("notfound") || stderr.contains("not found"), "{stderr}");
    let (_, h) = health_text(&p, OWNER).await;
    assert!(line(&h, "                    workers").starts_with("                    workers 0/2"), "{h}");
    eprintln!("C5b-2 VM 3 PASS: two forks via kilndctl, independent; a stranger's fork not found");

    // 4. The other uid's own capture and fork; then more of the owner's captures than one
    // list page holds (the daemon's page cap is 3).
    let theirs_src = ok(&bin, &socket, STRANGER, &["create"]).await.trim().to_string();
    let theirs_cp = ok(&bin, &socket, STRANGER, &["checkpoint", "create", &theirs_src]).await.trim().to_string();
    let theirs_fork = ok(&bin, &socket, STRANGER, &["create", "--from-checkpoint", &theirs_cp]).await.trim().to_string();
    let mut mine_cps = vec![cp.clone()];
    for _ in 0..3 {
        mine_cps.push(ok(&bin, &socket, OWNER, &["checkpoint", "create", &src]).await.trim().to_string());
    }
    let listed = ok(&bin, &socket, OWNER, &["checkpoint", "ls"]).await;
    assert_eq!(listed.lines().count(), 1 + mine_cps.len(), "{listed}");
    assert!(mine_cps.iter().all(|c| listed.contains(c.as_str())) && !listed.contains(&theirs_cp), "{listed}");
    let listed = ok(&bin, &socket, OWNER, &["checkpoint", "ls", "--page-size", "2"]).await;
    assert_eq!(listed.lines().count(), 1 + mine_cps.len(), "{listed}");
    let (code, _, stderr) = ctl(&bin, &socket, OWNER, &["checkpoint", "ls", "--page-size", "4"]).await;
    assert_eq!(code, 1, "an explicit page above the cap is refused as is: {stderr}");
    let (_, h) = health_text(&p, STRANGER).await;
    assert!(line(&h, "checkpoints:").contains("node 5/128"), "{h}");
    assert!(line(&h, "checkpoints:").contains("yours 1/32"), "{h}");
    eprintln!("C5b-2 VM 4 PASS: uid {STRANGER}'s capture and fork; ls pages under a cap of 3");

    // 5. Withdrawal and re-advertising: the root helper restarted without its
    // checkpoint group, then with it.
    let stop_helper = |h: HelperProcess| async move {
        h.stop.cancel();
        h.task.await.unwrap().unwrap();
        h.node.shutdown().await;
    };
    stop_helper(helper).await;
    std::fs::remove_file(&helper_socket).ok();
    let plain = {
        let listener = tokio::net::UnixListener::bind(&helper_socket).unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(crate::helper::serve_with_groups(
            listener,
            0,
            kiln_bin().into(),
            None,
            None,
            stop.clone(),
        ));
        (stop, task)
    };
    let (code, h) = health_text(&p, OWNER).await;
    assert_eq!(code, 0, "still serving: {h}");
    assert!(!line(&h, "features:").contains("workspace_checkpoint"), "{h}");
    assert!(line(&h, "detail:").contains("workspace checkpoints withdrawn"), "{h}");
    assert!(!h.contains("checkpoint limits:"), "{h}");
    assert!(line(&h, "checkpoints:").contains("node 5/128"), "stats stay: {h}");
    let (code, _, stderr) = ctl(&bin, &socket, OWNER, &["create", "--from-checkpoint", &cp]).await;
    assert_eq!(code, 1);
    assert!(stderr.contains("does not advertise workspace_checkpoint"), "{stderr}");
    let (code, _, stderr) = ctl(&bin, &socket, OWNER, &["checkpoint", "create", &src]).await;
    assert_eq!(code, 1);
    assert!(stderr.contains("backend_unsupported:workspace_checkpoint"), "{stderr}");
    let shown = ok(&bin, &socket, OWNER, &["checkpoint", "get", &cp]).await;
    assert!(shown.contains("state:      ready"), "Get still served: {shown}");
    plain.0.cancel();
    plain.1.await.unwrap().unwrap();
    std::fs::remove_file(&helper_socket).ok();
    helper = start_helper(&helper_socket);
    let (_, h) = health_text(&p, OWNER).await;
    assert!(line(&h, "features:").contains("workspace_checkpoint"), "re-advertised: {h}");
    let f3 = ok(&bin, &socket, OWNER, &["create", "--from-checkpoint", &cp]).await.trim().to_string();
    eprintln!("C5b-2 VM 5 PASS: withdrawn without the helper's group, re-advertised with it");

    // 6. Delete: the checkpoint goes, the forks stay, the stats follow.
    for c in &mine_cps {
        let out = ok(&bin, &socket, OWNER, &["checkpoint", "rm", c]).await;
        assert_eq!(out.trim(), format!("{c} deleted"));
    }
    ok(&bin, &socket, STRANGER, &["checkpoint", "rm", &theirs_cp]).await;
    assert_eq!(read(f1.clone()).await, "one\n");
    let (_, h) = health_text(&p, OWNER).await;
    assert!(line(&h, "checkpoints:").contains("node 0/128, 0/"), "{h}");
    assert!(line(&h, "checkpoints:").ends_with("0 deleting"), "{h}");
    assert!(line(&h, "                    workers").contains("records 5/32768 (yours 4/4096)"), "{h}");
    assert!(scene.listed().is_empty(), "{:?}", scene.listed());
    eprintln!("C5b-2 VM 6 PASS: checkpoints deleted and absent; forks live; stats back to zero");

    for (uid, id) in [(OWNER, &f1), (OWNER, &f2), (OWNER, &f3), (OWNER, &src), (STRANGER, &theirs_fork), (STRANGER, &theirs_src)] {
        let out = ok(&bin, &socket, uid, &["rm", id]).await;
        assert!(out.trim().ends_with("deleted"), "{out}");
    }
    assert_eq!(charged(&m), (0, 0));
    stop.cancel();
    server.await.unwrap().unwrap();
    m.begin_shutdown();
    m.drain_operations().await;
    drop(m);

    // The first instance's artifact directory, now empty, as the scene removes its own.
    if let Some(first) = scene.instance.take() {
        let _ = std::fs::remove_dir(format!("{CPS}/{first}"));
    }

    // 7. Headroom above the real free space: still advertised (capacity is known), but
    // a capture is refused checkpoint_quota with nothing charged.
    let m = discovery_manager(&tmp.path().join("state2"), &helper_socket, &clock, &scene.image, 1 << 60);
    scene.instance = Some(m.store.identity().unwrap().instance_id.to_string());
    m.reconcile().await.unwrap();
    m.start_checkpoints().unwrap();
    let p = public_socket();
    let bound = crate::server::bind(&p.socket, Some(SOCKET_GID)).await.unwrap();
    let stop = CancellationToken::new();
    let server = tokio::spawn(crate::server::serve(
        Arc::clone(&m),
        bound,
        stop.clone().cancelled_owned(),
        Duration::from_secs(5),
    ));
    let (bin, socket) = (p.bin.clone(), p.socket.clone());
    let src = ok(&bin, &socket, OWNER, &["create"]).await.trim().to_string();
    let (_, h) = health_text(&p, OWNER).await;
    assert!(line(&h, "features:").contains("workspace_checkpoint"), "{h}");
    let (code, _, stderr) = ctl(&bin, &socket, OWNER, &["checkpoint", "create", &src]).await;
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("checkpoint_quota") && stderr.contains("not enough free space"), "{stderr}");
    let (_, h) = health_text(&p, OWNER).await;
    assert!(line(&h, "checkpoints:").contains("node 0/128, 0/"), "{h}");
    assert!(line(&h, "                    1 captures").contains("1 captures and 0 forks refused"), "{h}");
    assert_eq!(charged(&m), (0, 0));
    assert!(scene.listed().is_empty());
    eprintln!("C5b-2 VM 7 PASS: headroom 2^60 refuses a capture checkpoint_quota: {}", stderr.trim());
    ok(&bin, &socket, OWNER, &["rm", &src]).await;
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
    eprintln!("C5b-2 VM PASS");
}
