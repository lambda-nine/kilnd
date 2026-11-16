//! Checkpoint milestone C6b: the VM acceptance harness (design 11.2 item 6). Root only,
//! on the prepared Linux VM, against the installed kiln. Every scenario runs alone, as
//! one ignored root test, through `scripts/checkpoint-crash-matrix.py`, which checks the
//! host before and after it.
//!
//! Real process death needs real processes, so the daemon and the helper are children
//! of the test binary (the same binary, re-run with a role in its environment):
//!
//! - the **daemon** role: `Manager<KilnRuntime>` and the gRPC server on a private state
//!   directory and socket, started in `main`'s order (state, socket, reconcile, the two
//!   rebases, a prune, the sweeper with the checkpoint engine, then serve);
//! - the **helper** role: the kiln and checkpoint groups on a private socket, with a
//!   fresh epoch per process;
//! - the **rpc** role: one typed gRPC call as an unprivileged uid, printed as JSON with
//!   its code and `kilnd-reason` trailer.
//!
//! Between daemon and helper sits a **boundary relay** (test code only, no production
//! failpoint): it forwards each helper connection, descriptors included, parses the
//! request and the reply and can hold a named operation or its reply. Holding is how a
//! scenario stops the daemon at an exact boundary (after C1, before dispatch; COMPLETE
//! or ABSENT received but not delivered; a restore published but not answered) before
//! killing it with SIGKILL.
//!
//! The node's kilnd, kilnd-helper and their state are never touched: everything here
//! is private to the test's temporary directory, its own registered image copy and its
//! own daemon instance.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use kilnd_api::v1 as pb;

use super::*;

/// The roles' environment variables.
const ROLE: &str = "KILND_C6B_ROLE";
const ARGS: &str = "KILND_C6B_ARGS";
/// The unprivileged callers. Both are in the API socket's group, as members of a
/// deployment's socket group would be; kilnd authorizes by the peer's uid.
pub(super) const OWNER: u32 = 1000;
const SOCKET_GID: u32 = 1000;
/// The kiln-side large workspace that widens copy and restore windows: 300 MiB of
/// random data in one file and 10,000 small files.
pub(super) const BIG: &str = "mkdir -p /root/big && head -c 314572800 /dev/urandom > /root/big/blob \
    && mkdir -p /root/big/many && cd /root/big/many && seq 1 10000 | sed 's/^/f/' | xargs touch && sync";

pub(super) fn kiln_bin() -> String {
    super::kiln_bin()
}

/// One `C6B matrix:` line, the runner's record of a scenario.
pub(super) fn matrix(scenario: &str, outcome: Value) {
    println!(
        "C6B matrix: {}",
        json!({ "scenario": scenario, "outcome": outcome })
    );
}

// ---------------------------------------------------------------------------------
// Child roles.

fn role_args() -> Option<Value> {
    let args = std::env::var(ARGS).ok()?;
    Some(serde_json::from_str(&args).unwrap())
}

fn role_is(role: &str) -> bool {
    std::env::var(ROLE).as_deref() == Ok(role)
}

fn arg(args: &Value, name: &str) -> String {
    args[name]
        .as_str()
        .unwrap_or_else(|| panic!("role argument {name}"))
        .to_string()
}

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Waits for SIGTERM (a graceful stop); SIGKILL needs no handler.
async fn terminated() {
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    term.recv().await;
}

/// The helper role: a private root helper serving the kiln and checkpoint groups.
#[test]
#[ignore = "a C6b child role, run by the VM scenarios"]
fn c6b_helper_child() {
    if !role_is("helper") {
        return;
    }
    let args = role_args().unwrap();
    let socket = PathBuf::from(arg(&args, "socket"));
    let kiln = PathBuf::from(arg(&args, "kiln"));
    current_thread().block_on(async move {
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let node = crate::helper::checkpoint::Node::new(Arc::new(
            crate::helper::checkpoint::KilnWorkers::new(kiln.clone()),
        ))
        .unwrap();
        let stop = tokio_util::sync::CancellationToken::new();
        println!("C6B HELPER READY epoch={}", node.epoch());
        let serving = tokio::spawn(crate::helper::serve_with_groups(
            listener,
            0,
            kiln,
            None,
            Some(node.clone()),
            stop.clone(),
        ));
        terminated().await;
        stop.cancel();
        let _ = serving.await;
        node.shutdown().await;
        println!("C6B HELPER STOPPED");
    });
}

/// The daemon's limits: the design's checkpoint limits with shorter removal retries,
/// adjustable per scenario.
pub(super) fn daemon_limits(image: &str, args: &Value) -> Limits {
    let mut checkpoints = CheckpointLimits {
        removal_retry: Duration::from_millis(200),
        max_removal_retry: Duration::from_secs(2),
        ..CheckpointLimits::default()
    };
    if let Some(n) = args["max_workers"].as_u64() {
        checkpoints.max_workers = n as usize;
    }
    if let Some(n) = args["max_workers_per_uid"].as_u64() {
        checkpoints.max_workers_per_uid = n as usize;
    }
    if let Some(n) = args["max_per_uid"].as_u64() {
        checkpoints.budgets.max_per_uid = n;
    }
    if let Some(n) = args["max_bytes_per_uid"].as_u64() {
        checkpoints.budgets.max_bytes_per_uid = n;
    }
    Limits {
        default_image: image.into(),
        default_memory_bytes: 256 << 20,
        default_disk_bytes: 256 << 20,
        expiry: ExpiryLimits {
            restart_grace: Duration::ZERO,
            ..ExpiryLimits::default()
        },
        checkpoints: (!args["checkpoints_off"].as_bool().unwrap_or(false)).then_some(checkpoints),
        ..Limits::default()
    }
}

/// The daemon role: `main.rs::serve_with`'s order on private state and sockets. With
/// `fake`, the fake runtime instead of the helper (the harness's own Mac test).
#[test]
#[ignore = "a C6b child role, run by the VM scenarios"]
fn c6b_daemon_child() {
    if !role_is("daemon") {
        return;
    }
    let args = role_args().unwrap();
    let state = PathBuf::from(arg(&args, "state"));
    current_thread().block_on(async move {
        let store = Store::open(&state).unwrap();
        println!(
            "C6B DAEMON STORE instance={}",
            store.identity().unwrap().instance_id
        );
        if args["fake"].as_bool().unwrap_or(false) {
            let fake = crate::runtime::fake::FakeRuntime::default().with_checkpoints();
            fake.state().proven_features = Ok(vec![Feature::ExecStream]);
            let clock = Arc::new(crate::expiry::ManualClock::default());
            serve_role(fake, store, clock, &args).await;
        } else {
            let helper = PathBuf::from(arg(&args, "helper"));
            let clock = Arc::new(crate::expiry::SystemClock::new().unwrap());
            let runtime = crate::runtime::kiln::KilnRuntime::with_helper_uid(helper, 0);
            serve_role(runtime, store, clock, &args).await;
        }
    });
}

async fn serve_role<R: Runtime>(runtime: R, store: Store, clock: Arc<dyn Clock>, args: &Value) {
    let api = PathBuf::from(arg(args, "api"));
    let gid = args["gid"].as_u64().map_or(SOCKET_GID, |g| g as u32);
    let socket = crate::server::bind(&api, Some(gid)).await.unwrap();
    let manager = Arc::new(Manager::with_clock(
        runtime,
        store,
        daemon_limits(&arg(args, "image"), args),
        clock,
    ));
    let started = StdInstant::now();
    let r = manager.reconcile().await.unwrap();
    println!(
        "C6B DAEMON RECONCILED {}",
        json!({
            "ms": started.elapsed().as_millis() as u64,
            "failed": r.failed, "lost": r.lost, "recovered": r.recovered,
            "deleted": r.deleted, "still_deleting": r.still_deleting,
            "released": r.released, "quarantined": r.quarantined,
            "admission_blocked": r.admission_blocked,
            "checkpoints_blocked": r.checkpoints_blocked,
            "unmanaged": r.unmanaged,
        })
    );
    manager.rebase_expiry_clocks().unwrap();
    manager.rebase_create_requests().unwrap();
    manager.prune().unwrap();
    let sweeper = manager.start_expiry().unwrap();
    println!(
        "C6B DAEMON SERVING blocked={}",
        manager.allocation_blocked()
    );
    let sweeping = Arc::clone(&manager);
    crate::server::serve(manager, socket, terminated(), Duration::from_secs(5))
        .await
        .unwrap();
    sweeping.begin_shutdown();
    let _ = sweeper.await;
    println!("C6B DAEMON STOPPED");
}

/// Gives up root for `uid` (gid `SOCKET_GID`, no other groups) before anything else.
fn become_caller(uid: u32) {
    // SAFETY: plain credential calls at the start of a child process; failures are
    // checked.
    unsafe {
        if libc::geteuid() == uid {
            return; // already the caller (the harness's own Mac test)
        }
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setgid(SOCKET_GID), 0);
        assert_eq!(libc::setuid(uid), 0);
        assert_eq!(libc::geteuid(), uid);
    }
}

type Client = kilnd_api::v1::kilnd_service_client::KilndServiceClient<tonic::transport::Channel>;

async fn connect(path: &Path) -> Client {
    let path = path.to_path_buf();
    let channel = tonic::transport::Endpoint::try_from("http://kilnd.invalid")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    UnixStream::connect(path).await?,
                ))
            }
        }))
        .await
        .unwrap();
    Client::new(channel).max_decoding_message_size(8 << 20)
}

fn status_json(s: &tonic::Status) -> Value {
    json!({
        "code": format!("{:?}", s.code()),
        "reason": s.metadata().get(crate::service::REASON_KEY)
            .and_then(|v| v.to_str().ok()).unwrap_or(""),
        "message": s.message(),
    })
}

pub(super) fn checkpoint_json(c: &pb::Checkpoint) -> Value {
    json!({
        "id": c.id,
        "state": pb::CheckpointState::try_from(c.state).map(|s| s.as_str_name()).unwrap_or("?"),
        "sandbox_id": c.sandbox_id,
        "owner_uid": c.owner_uid,
        "failure_reason": c.failure_reason,
        "content_sha256": c.content_sha256,
        "size_bytes": c.size_bytes,
        "logical_bytes": c.logical_bytes,
        "allocated_bytes": c.allocated_bytes,
        "max_size_bytes": c.max_size_bytes,
        "request_id": c.request_id,
        "request_id_released": c.request_id_released,
        "deletion_reason": c.deletion_reason,
        "idle_expires_at_unix_ms": c.expiry.as_ref().map(|e| e.idle_expires_at_unix_ms),
        "lifetime_expires_at_unix_ms": c.expiry.as_ref().map(|e| e.lifetime_expires_at_unix_ms),
        "last_activity_at_unix_ms": c.expiry.as_ref().map(|e| e.last_activity_at_unix_ms),
    })
}

pub(super) fn sandbox_json(s: &pb::Sandbox) -> Value {
    json!({
        "id": s.id,
        "state": pb::SandboxState::try_from(s.state).map(|s| s.as_str_name()).unwrap_or("?"),
        "from_checkpoint": s.from_checkpoint,
        "checkpoint_content_sha256": s.checkpoint_content_sha256,
        "failure_reason": s.failure_reason,
        "backend_id": s.backend_id,
    })
}

/// An execution as JSON. `stdout` and `stderr` are lossy text for messages and simple
/// comparisons; `stdout_hex` and `stderr_hex` carry the exact bytes (C6b review HIGH 3),
/// which every fidelity comparison uses ([`output_bytes`]).
pub(super) fn exec_json(
    state: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    failure_reason: &str,
) -> Value {
    json!({
        "state": state,
        "exit_code": exit_code,
        "stdout": String::from_utf8_lossy(stdout),
        "stderr": String::from_utf8_lossy(stderr),
        "stdout_hex": hex(stdout),
        "stderr_hex": hex(stderr),
        "failure_reason": failure_reason,
    })
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digits"))
        .collect()
}

/// An execution's exact stdout bytes.
#[track_caller]
pub(super) fn output_bytes(exec: &Value) -> Vec<u8> {
    unhex(
        exec["stdout_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("no stdout_hex in {exec}")),
    )
}

/// The tree a fidelity comparison covers, as one line per entry, every byte of every
/// name kept: type, mode, owner, group, link count and nanosecond mtime of every entry,
/// directories included; the size of every entry but a directory (a directory's size
/// is its filesystem's layout, not its content); a symlink's target and a regular
/// file's SHA-256. Paths that do not exist print nothing.
pub(super) fn listing_script(paths: &[&str]) -> String {
    let quoted: Vec<String> = paths.iter().map(|p| format!("'{p}'")).collect();
    format!(
        "for p in {}; do [ -e \"$p\" ] || [ -L \"$p\" ] || continue; \
         find \"$p\" -xdev | LC_ALL=C sort | while IFS= read -r f; do \
           if [ -d \"$f\" ] && [ ! -L \"$f\" ]; then stat -c '%n|%F|%a|%u|%g|%h|%y' \"$f\"; \
           else stat -c '%n|%F|%a|%u|%g|%s|%h|%y' \"$f\"; fi; \
           [ -L \"$f\" ] && printf 'link %s\\n' \"$(readlink \"$f\")\"; \
           if [ -f \"$f\" ] && [ ! -L \"$f\" ]; then sha256sum < \"$f\"; fi; \
         done; done; true",
        quoted.join(" ")
    )
}

/// The fidelity oracle: the fork's listing and behaviour are the source's, byte for
/// byte. The error names the first differing line, escaped.
pub(super) fn same_tree(source: &[Value; 2], fork: &[Value; 2]) -> Result<(), String> {
    for (what, a, b) in [
        ("tree", &source[0], &fork[0]),
        ("behaviour", &source[1], &fork[1]),
    ] {
        let (a, b) = (output_bytes(a), output_bytes(b));
        if a != b {
            let (la, lb): (Vec<&[u8]>, Vec<&[u8]>) =
                (a.split(|c| *c == b'\n').collect(), b.split(|c| *c == b'\n').collect());
            let at = (0..la.len().max(lb.len()))
                .find(|i| la.get(*i) != lb.get(*i))
                .unwrap_or(0);
            let show = |l: Option<&&[u8]>| l.map(|l| l.escape_ascii().to_string()).unwrap_or_default();
            return Err(format!(
                "the fork's {what} differs at line {at}: source {:?}, fork {:?}",
                show(la.get(at)),
                show(lb.get(at))
            ));
        }
    }
    Ok(())
}

fn expiry(op: &Value, lifetime: &str, idle: &str) -> Option<pb::ExpiryPolicy> {
    let (l, i) = (op[lifetime].as_u64(), op[idle].as_u64());
    (l.is_some() || i.is_some()).then(|| pb::ExpiryPolicy {
        max_lifetime_ms: l.unwrap_or(0),
        idle_timeout_ms: i.unwrap_or(0),
    })
}

/// One call. `ok` holds what the call returned, `error` its status.
async fn perform(client: &mut Client, op: &Value) -> Result<Value, tonic::Status> {
    let s = |name: &str| op[name].as_str().unwrap_or("").to_string();
    Ok(match op["op"].as_str().unwrap() {
        "health" => {
            let h = client.health(pb::HealthRequest {}).await?.into_inner();
            let caps = h.runtime_capabilities.clone().unwrap_or_default();
            json!({
                "status": h.status,
                "checkpoint": caps.checkpoint,
                "features": caps.features.iter()
                    .map(|f| pb::Feature::try_from(*f).map(|f| f.as_str_name()).unwrap_or("?"))
                    .collect::<Vec<_>>(),
                "checkpoints": h.admission.as_ref().and_then(|a| a.checkpoints.as_ref()).map(|c| format!("{c:?}")),
                "debug": format!("{h:?}"),
            })
        }
        "create" => {
            let mut spec = pb::SandboxSpec::default();
            let mut with_spec = false;
            if op["read_only_root"].as_bool() == Some(true) {
                spec.read_only_root = true;
                spec.writable_paths = op["writable_paths"]
                    .as_array()
                    .map(|a| a.iter().map(|p| p.as_str().unwrap().to_string()).collect())
                    .unwrap_or_default();
                with_spec = true;
            }
            if let Some(d) = op["disk_bytes"].as_u64().filter(|d| *d > 0) {
                spec.limits = Some(pb::ResourceLimits {
                    disk_bytes: d,
                    ..Default::default()
                });
                with_spec = true;
            }
            let r = client
                .create_sandbox(pb::CreateSandboxRequest {
                    spec: with_spec.then_some(spec),
                    request_id: s("request_id"),
                    expiry: expiry(op, "lifetime_ms", "idle_ms"),
                    default_env: Vec::new(),
                    from_checkpoint: s("from_checkpoint"),
                })
                .await?
                .into_inner();
            sandbox_json(r.sandbox.as_ref().unwrap())
        }
        "get" => {
            let r = client
                .get_sandbox(pb::GetSandboxRequest {
                    id: s("id"),
                    execution_limit: 0,
                })
                .await?
                .into_inner();
            sandbox_json(r.sandbox.as_ref().unwrap())
        }
        "delete" => {
            let r = client
                .delete_sandbox(pb::DeleteSandboxRequest {
                    id: s("id"),
                    release_request_id: op["release"].as_bool().unwrap_or(false),
                })
                .await?
                .into_inner();
            sandbox_json(r.sandbox.as_ref().unwrap())
        }
        "exec" => {
            let r = client
                .exec(pb::ExecRequest {
                    sandbox_id: s("id"),
                    argv: vec!["sh".into(), "-c".into(), s("script")],
                    stdin: Vec::new(),
                    timeout_ms: op["timeout_ms"].as_u64().unwrap_or(300_000) as u32,
                    cwd: String::new(),
                    env: Vec::new(),
                })
                .await?
                .into_inner();
            let e = r.execution.unwrap();
            exec_json(
                pb::ExecutionState::try_from(e.state).map(|s| s.as_str_name()).unwrap_or("?"),
                e.exit_code,
                &e.stdout.map(|o| o.data).unwrap_or_default(),
                &e.stderr.map(|o| o.data).unwrap_or_default(),
                &e.failure_reason,
            )
        }
        "exec_stream" => {
            use tokio_stream::StreamExt;
            let mut stream = client
                .exec_stream(pb::ExecStreamRequest {
                    exec: Some(pb::ExecRequest {
                        sandbox_id: s("id"),
                        argv: vec!["sh".into(), "-c".into(), s("script")],
                        stdin: Vec::new(),
                        timeout_ms: op["timeout_ms"].as_u64().unwrap_or(300_000) as u32,
                        cwd: String::new(),
                        env: Vec::new(),
                    }),
                })
                .await?
                .into_inner();
            let mut events = 0;
            let mut exit = None;
            while let Some(event) = stream.next().await {
                let event = event?;
                events += 1;
                if let Some(pb::exec_stream_response::Event::Finished(f)) = event.event {
                    exit = f.execution.and_then(|e| e.exit_code);
                }
            }
            json!({ "events": events, "exit_code": exit })
        }
        "capture" => {
            let r = client
                .checkpoint_sandbox(pb::CheckpointSandboxRequest {
                    sandbox_id: s("id"),
                    request_id: s("request_id"),
                    expiry: Some(expiry(op, "lifetime_ms", "idle_ms").unwrap_or_default()),
                    max_size_bytes: op["max_size_bytes"].as_u64().unwrap_or(0),
                })
                .await?
                .into_inner();
            checkpoint_json(r.checkpoint.as_ref().unwrap())
        }
        "get_checkpoint" => {
            let r = client
                .get_checkpoint(pb::GetCheckpointRequest { id: s("id") })
                .await?
                .into_inner();
            checkpoint_json(r.checkpoint.as_ref().unwrap())
        }
        "list_checkpoints" => {
            let r = client
                .list_checkpoints(pb::ListCheckpointsRequest {
                    sandbox_id: s("sandbox_id"),
                    page_size: 0,
                    page_token: String::new(),
                })
                .await?
                .into_inner();
            Value::Array(r.checkpoints.iter().map(checkpoint_json).collect())
        }
        "delete_checkpoint" => {
            let r = client
                .delete_checkpoint(pb::DeleteCheckpointRequest {
                    id: s("id"),
                    release_request_id: op["release"].as_bool().unwrap_or(false),
                })
                .await?
                .into_inner();
            checkpoint_json(r.checkpoint.as_ref().unwrap())
        }
        other => panic!("unknown rpc op {other}"),
    })
}

/// The rpc role: one call as an unprivileged uid.
#[test]
#[ignore = "a C6b child role, run by the VM scenarios"]
fn c6b_rpc_child() {
    if !role_is("rpc") {
        return;
    }
    let args = role_args().unwrap();
    become_caller(args["uid"].as_u64().unwrap() as u32);
    let socket = PathBuf::from(arg(&args, "socket"));
    current_thread().block_on(async move {
        let mut client = connect(&socket).await;
        let started = StdInstant::now();
        let result = perform(&mut client, &args["call"]).await;
        let elapsed_us = started.elapsed().as_micros() as u64;
        let out = match result {
            Ok(ok) => json!({ "ok": ok, "elapsed_us": elapsed_us }),
            Err(e) => json!({ "error": status_json(&e), "elapsed_us": elapsed_us }),
        };
        println!("C6B RPC {out}");
    });
}

// ---------------------------------------------------------------------------------
// The parent's side of the roles.

/// A child of the test binary in one role, its stdout lines collected.
pub(super) struct Proc {
    child: tokio::process::Child,
    pub(super) pid: i32,
    lines: Arc<Mutex<Vec<String>>>,
    seen: Arc<Notify>,
    role: String,
}

fn role_command(test: &str, role: &str, args: &Value) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &format!("manager::checkpoint_vm_tests::harness::{test}"),
            "--include-ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(ROLE, role)
        .env(ARGS, args.to_string())
        .env("RUST_LOG", "warn")
        .stdin(std::process::Stdio::null());
    command
}

impl Proc {
    pub(super) fn spawn(test: &str, role: &str, args: &Value) -> Self {
        let mut child = role_command(test, role, args)
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Notify::new());
        let stdout = child.stdout.take().unwrap();
        let (l, s, r) = (Arc::clone(&lines), Arc::clone(&seen), role.to_string());
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                // libtest prints `test NAME ... ` before the first captured line.
                let line = match line.find("C6B ") {
                    Some(at) => line[at..].to_string(),
                    None => line,
                };
                if line.starts_with("C6B ") {
                    eprintln!("[{r} {pid}] {line}");
                }
                l.lock().unwrap().push(line);
                s.notify_waiters();
            }
            l.lock().unwrap().push("C6B EOF".into());
            s.notify_waiters();
        });
        Self {
            child,
            pid,
            lines,
            seen,
            role: role.into(),
        }
    }

    /// The first line starting with `prefix` (its rest), waiting up to `secs`.
    pub(super) async fn line(&self, prefix: &str, secs: u64) -> String {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let notified = self.seen.notified();
            if let Some(l) = self
                .lines
                .lock()
                .unwrap()
                .iter()
                .find_map(|l| l.strip_prefix(prefix))
            {
                return l.trim().to_string();
            }
            if self.has_line("C6B EOF") {
                panic!("{} {} exited before a {prefix:?} line", self.role, self.pid);
            }
            if tokio::time::timeout_at(end, notified).await.is_err() {
                panic!("{} {}: no {prefix:?} line in {secs} s", self.role, self.pid);
            }
        }
    }

    pub(super) fn has_line(&self, prefix: &str) -> bool {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with(prefix))
    }

    /// SIGKILL, then reap.
    pub(super) async fn kill(mut self) {
        // SAFETY: our own child's pid, not yet reaped.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let _ = self.child.wait().await;
        eprintln!("C6B killed {} {}", self.role, self.pid);
    }

    /// SIGTERM, then reap within `secs`.
    pub(super) async fn stop(mut self, secs: u64) -> std::process::ExitStatus {
        // SAFETY: our own child's pid, not yet reaped.
        unsafe { libc::kill(self.pid, libc::SIGTERM) };
        tokio::time::timeout(Duration::from_secs(secs), self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("{} {} did not stop", self.role, self.pid))
            .unwrap()
    }
}

/// One rpc child's result.
pub(super) async fn rpc(socket: &Path, uid: u32, call: Value) -> Value {
    let args = json!({ "socket": socket.to_str().unwrap(), "uid": uid, "call": call });
    let out = role_command("c6b_rpc_child", "rpc", &args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find_map(|l| l.find("C6B RPC ").map(|at| &l[at + 8..]))
        .unwrap_or_else(|| {
            panic!(
                "rpc {call}: no result: {stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
    serde_json::from_str(line).unwrap()
}

/// The call's result, which must have succeeded.
#[track_caller]
pub(super) fn ok(result: &Value) -> &Value {
    assert!(result.get("ok").is_some(), "expected success: {result}");
    &result["ok"]
}

/// The refusal's `kilnd-reason` token ("" if none), which must have failed.
#[track_caller]
pub(super) fn refused(result: &Value) -> String {
    assert!(result.get("error").is_some(), "expected a refusal: {result}");
    result["error"]["reason"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------------
// The boundary relay.

/// Which side of an exchange a rule watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Request,
    Reply,
}

/// A held exchange: the relay never forwards it, and keeps the daemon's side open until
/// the daemon goes away. Each rule fires once.
#[derive(Clone, Debug)]
pub(super) struct Rule {
    pub(super) phase: Phase,
    /// `group.operation` for a request, `group.reply` for a reply (see [`op_name`]).
    pub(super) op: String,
    /// The exchange's JSON must contain this text, if set.
    pub(super) containing: Option<String>,
    fired: bool,
}

pub(super) fn hold(phase: Phase, op: &str, containing: Option<&str>) -> Rule {
    Rule {
        phase,
        op: op.into(),
        containing: containing.map(str::to_string),
        fired: false,
    }
}

/// One exchange the relay saw.
#[derive(Clone, Debug)]
pub(super) struct Seen {
    pub(super) phase: Phase,
    pub(super) op: String,
    pub(super) held: bool,
    pub(super) json: String,
}

#[derive(Default)]
struct RelayState {
    rules: Vec<Rule>,
    seen: Vec<Seen>,
}

pub(super) struct Relay {
    state: Arc<Mutex<RelayState>>,
    changed: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

/// `group.name` of a request's operation or a reply: the externally tagged enum's
/// variant (a unit variant is a string), inside the group's own `operation` field.
pub(super) fn op_name(v: &Value) -> String {
    let Some((group, inner)) = v.as_object().and_then(|m| m.iter().next()) else {
        return v.as_str().unwrap_or("?").to_string();
    };
    let op = inner.get("operation").unwrap_or(inner);
    let name = match op {
        Value::String(s) => s.clone(),
        Value::Object(m) => m.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    };
    format!("{group}.{name}")
}

async fn read_frame_raw(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > crate::helper::protocol::MAX_FRAME {
        return Err(std::io::Error::other("bad frame length"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

async fn write_frame_raw(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(body).await
}

/// The helper protocol's descriptor envelope (`helper::fds`, which is private to the
/// helper): one marker byte with up to four descriptors.
async fn send_envelope(stream: &UnixStream, fds: &[RawFd]) -> std::io::Result<()> {
    stream
        .async_io(tokio::io::Interest::WRITABLE, || {
            let mut marker = crate::helper::protocol::STDIO_RECEIVED;
            let mut iov = libc::iovec {
                iov_base: (&mut marker as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0usize; 16];
            // SAFETY: zero is a valid initial msghdr; every pointer below is live.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                msg.msg_control = control.as_mut_ptr().cast();
                // SAFETY: CMSG macros over our own control buffer, sized for 4 fds.
                unsafe {
                    msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of_val(fds) as _) as _;
                    let cmsg = libc::CMSG_FIRSTHDR(&msg);
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as _) as _;
                    std::ptr::copy_nonoverlapping(
                        fds.as_ptr(),
                        libc::CMSG_DATA(cmsg).cast(),
                        fds.len(),
                    );
                }
            }
            // SAFETY: a live socket and message.
            let rc = unsafe {
                libc::sendmsg(
                    stream.as_raw_fd(),
                    &msg,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            match rc {
                1 => Ok(()),
                rc if rc < 0 => Err(std::io::Error::last_os_error()),
                _ => Err(std::io::Error::other("short envelope")),
            }
        })
        .await
}

async fn receive_envelope(stream: &UnixStream) -> std::io::Result<Vec<OwnedFd>> {
    stream
        .async_io(tokio::io::Interest::READABLE, || {
            let mut marker = 0u8;
            let mut iov = libc::iovec {
                iov_base: (&mut marker as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0usize; 16];
            // SAFETY: zero is a valid initial msghdr; every pointer below is live.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of::<[usize; 16]>() as _;
            // SAFETY: a live socket and message.
            let rc = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut fds = Vec::new();
            // SAFETY: walking the control messages recvmsg filled in.
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                    {
                        let len =
                            ((*cmsg).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                        for i in 0..len / std::mem::size_of::<RawFd>() {
                            let fd = *libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i);
                            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                            fds.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }
            if rc != 1 || marker != crate::helper::protocol::STDIO_RECEIVED {
                return Err(std::io::Error::other("invalid envelope"));
            }
            Ok(fds)
        })
        .await
}

impl Relay {
    /// Listens at `at` and forwards each connection to the helper at `helper`.
    pub(super) fn start(at: &Path, helper: &Path) -> Self {
        let _ = std::fs::remove_file(at);
        let listener = UnixListener::bind(at).unwrap();
        let state = Arc::new(Mutex::new(RelayState::default()));
        let changed = Arc::new(Notify::new());
        let (s, c, helper) = (Arc::clone(&state), Arc::clone(&changed), helper.to_path_buf());
        let task = tokio::spawn(async move {
            while let Ok((daemon, _)) = listener.accept().await {
                let (s, c, helper) = (Arc::clone(&s), Arc::clone(&c), helper.clone());
                tokio::spawn(async move {
                    if let Err(e) = relay_one(daemon, &helper, &s, &c).await {
                        eprintln!("C6B relay: connection ended: {e}");
                    }
                });
            }
        });
        Self {
            state,
            changed,
            task,
        }
    }

    pub(super) fn add(&self, rule: Rule) {
        self.state.lock().unwrap().rules.push(rule);
    }

    pub(super) fn clear_rules(&self) {
        self.state.lock().unwrap().rules.clear();
    }

    /// Every exchange so far.
    pub(super) fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// The position after the exchanges so far, for [`Self::since`].
    pub(super) fn mark(&self) -> usize {
        self.state.lock().unwrap().seen.len()
    }

    /// Requests named `op` since `mark`.
    pub(super) fn requests_since(&self, mark: usize, op: &str) -> Vec<Seen> {
        self.state.lock().unwrap().seen[mark..]
            .iter()
            .filter(|s| s.phase == Phase::Request && s.op == op)
            .cloned()
            .collect()
    }

    /// Waits up to `secs` for a rule on `op` to fire; the held exchange's JSON.
    pub(super) async fn held(&self, op: &str, secs: u64) -> String {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let notified = self.changed.notified();
            if let Some(s) = self
                .state
                .lock()
                .unwrap()
                .seen
                .iter()
                .find(|s| s.held && s.op == op)
            {
                return s.json.clone();
            }
            if tokio::time::timeout_at(end, notified).await.is_err() {
                panic!("the relay never held {op} in {secs} s");
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Records an exchange and says whether a rule holds it.
fn observe(state: &Mutex<RelayState>, changed: &Notify, phase: Phase, op: &str, text: &str) -> bool {
    let mut state = state.lock().unwrap();
    let mut held = false;
    for rule in state.rules.iter_mut() {
        if !rule.fired
            && rule.phase == phase
            && rule.op == op
            && rule.containing.as_ref().is_none_or(|c| text.contains(c.as_str()))
        {
            rule.fired = true;
            held = true;
            break;
        }
    }
    state.seen.push(Seen {
        phase,
        op: op.into(),
        held,
        json: text.into(),
    });
    drop(state);
    changed.notify_waiters();
    if held {
        eprintln!("C6B relay: holding {phase:?} {op}");
    }
    held
}

/// Keeps a held exchange's daemon side open until the daemon goes away.
async fn wait_for_close(stream: &mut UnixStream) {
    let mut sink = [0u8; 64];
    while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
}

async fn relay_one(
    mut daemon: UnixStream,
    helper: &Path,
    state: &Mutex<RelayState>,
    changed: &Notify,
) -> std::io::Result<()> {
    // The caller's marker carries no descriptor; then its one request frame.
    if !receive_envelope(&daemon).await?.is_empty() {
        return Err(std::io::Error::other("the daemon sent descriptors"));
    }
    let request = read_frame_raw(&mut daemon).await?;
    let parsed: Value = serde_json::from_slice(&request).map_err(std::io::Error::other)?;
    let op = op_name(&parsed["operation"]);
    let text = String::from_utf8_lossy(&request).into_owned();
    if observe(state, changed, Phase::Request, &op, &text) {
        // Never dispatched: the helper sees no connection at all.
        wait_for_close(&mut daemon).await;
        return Ok(());
    }
    let mut upstream = UnixStream::connect(helper).await?;
    send_envelope(&upstream, &[]).await?;
    write_frame_raw(&mut upstream, &request).await?;
    // The helper's envelope, with Exec's descriptors, passed on as they are.
    let fds = receive_envelope(&upstream).await?;
    let raw: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
    send_envelope(&daemon, &raw).await?;
    drop(fds);
    let (mut d_read, mut d_write) = daemon.into_split();
    let (mut u_read, mut u_write) = upstream.into_split();
    // The daemon's receipt, cancellation bytes and EOF go on unchanged.
    let to_helper = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut d_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
        d_read
    });
    // The reply frame, then whatever follows (EOF).
    let mut len = [0u8; 4];
    u_read.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    let mut reply = vec![0u8; n];
    u_read.read_exact(&mut reply).await?;
    let parsed: Value = serde_json::from_slice(&reply).map_err(std::io::Error::other)?;
    let name = op_name(&parsed);
    let text = String::from_utf8_lossy(&reply).into_owned();
    if observe(state, changed, Phase::Reply, &name, &text) {
        // Received from the helper, never delivered: wait for the daemon to go.
        let d_read = to_helper.await.map_err(std::io::Error::other)?;
        drop(d_read);
        let mut sink = [0u8; 64];
        while matches!(u_read.read(&mut sink).await, Ok(n) if n > 0) {}
        return Ok(());
    }
    d_write.write_all(&len).await?;
    d_write.write_all(&reply).await?;
    tokio::io::copy(&mut u_read, &mut d_write).await?;
    d_write.shutdown().await?;
    let _ = to_helper.await;
    Ok(())
}

// ---------------------------------------------------------------------------------
// The world: scene, helper, relay and daemon.

pub(super) struct World {
    pub(super) scene: Scene,
    _tmp: Option<tempfile::TempDir>,
    pub(super) epoch: String,
    pub(super) dir: PathBuf,
    pub(super) state: PathBuf,
    pub(super) api: PathBuf,
    pub(super) helper_socket: PathBuf,
    pub(super) relay_socket: PathBuf,
    pub(super) helper: Option<Proc>,
    pub(super) daemon: Option<Proc>,
    pub(super) relay: Relay,
    pub(super) instance: String,
    pub(super) daemon_args: Value,
}

impl World {
    /// A scene, a helper, the relay and a first daemon (with these limit overrides).
    pub(super) async fn start(daemon_args: Value) -> Self {
        // Traversable by the unprivileged callers, who need only the API socket's
        // directory (group-owned by their gid); state stays root's.
        let tmp = tempfile::tempdir_in("/tmp").unwrap();
        let dir = tmp.path().to_path_buf();
        Self::start_at(dir, Some(tmp), daemon_args).await
    }

    /// The same in `dir` (kept, for a reboot).
    pub(super) async fn start_in(dir: &Path, daemon_args: Value) -> Self {
        Self::start_at(dir.to_path_buf(), None, daemon_args).await
    }

    async fn start_at(dir: PathBuf, tmp: Option<tempfile::TempDir>, daemon_args: Value) -> Self {
        let mut scene = Scene::new();
        scene.fallback_only = true;
        let mut world = Self::assemble(scene, dir, tmp, daemon_args);
        std::fs::create_dir(&world.state).unwrap();
        set_mode(&world.state, 0o700);
        world.start_helper().await;
        world.start_daemon().await;
        world
    }

    fn assemble(scene: Scene, dir: PathBuf, tmp: Option<tempfile::TempDir>, daemon_args: Value) -> Self {
        set_mode(&dir, 0o711);
        let state = dir.join("state");
        let api = dir.join("api").join("kilnd.sock");
        let helper_socket = dir.join("helper.sock");
        let relay_socket = dir.join("relay.sock");
        let relay = Relay::start(&relay_socket, &helper_socket);
        Self {
            scene,
            _tmp: tmp,
            epoch: String::new(),
            dir,
            state,
            api,
            helper_socket,
            relay_socket,
            helper: None,
            daemon: None,
            relay,
            instance: String::new(),
            daemon_args,
        }
    }

    /// After a reboot: the world [`Self::leave_for_reboot`] left in `dir`, with a fresh
    /// helper and relay and no daemon yet.
    pub(super) async fn resume(dir: &Path, arm: &Value) -> Self {
        let scene = Scene {
            image: arm["image"].as_str().unwrap().into(),
            registry_existed: arm["registry_existed"].as_bool().unwrap(),
            checkpoints_existed: arm["checkpoints_existed"].as_bool().unwrap(),
            instance: Some(arm["instance"].as_str().unwrap().into()),
            fallback_only: true,
        };
        let mut world = Self::assemble(scene, dir.to_path_buf(), None, json!({}));
        world.instance = arm["instance"].as_str().unwrap().into();
        world.start_helper().await;
        world
    }

    /// Leaves everything as it is for the reboot: no cleanup.
    pub(super) fn leave_for_reboot(mut self) {
        assert!(self.daemon.is_none() && self.helper.is_none());
        let scene = std::mem::replace(
            &mut self.scene,
            Scene {
                image: String::new(),
                registry_existed: true,
                checkpoints_existed: true,
                instance: None,
                fallback_only: false,
            },
        );
        std::mem::forget(scene);
        // The placeholder scene's cleanup removes nothing of ours.
        std::mem::forget(self);
    }

    /// The current helper's epoch.
    pub(super) async fn helper_epoch(&self) -> String {
        self.epoch.clone()
    }

    pub(super) async fn start_helper(&mut self) -> String {
        assert!(self.helper.is_none());
        let helper = Proc::spawn(
            "c6b_helper_child",
            "helper",
            &json!({ "socket": self.helper_socket.to_str().unwrap(), "kiln": kiln_bin() }),
        );
        let epoch = helper.line("C6B HELPER READY epoch=", 30).await;
        self.helper = Some(helper);
        self.epoch = epoch.clone();
        epoch
    }

    pub(super) async fn kill_helper(&mut self) {
        self.helper.take().unwrap().kill().await;
    }

    fn daemon_spawn_args(&self) -> Value {
        let mut args = self.daemon_args.clone();
        let m = args.as_object_mut().unwrap();
        m.insert("state".into(), json!(self.state.to_str().unwrap()));
        m.insert("api".into(), json!(self.api.to_str().unwrap()));
        m.insert("helper".into(), json!(self.relay_socket.to_str().unwrap()));
        m.insert("image".into(), json!(self.scene.image));
        args
    }

    /// Starts a daemon and waits for it to serve; its reconciliation line.
    pub(super) async fn start_daemon(&mut self) -> Value {
        let daemon = self.spawn_daemon();
        let reconciled = daemon.line("C6B DAEMON RECONCILED ", 300).await;
        daemon.line("C6B DAEMON SERVING", 60).await;
        let instance = daemon.line("C6B DAEMON STORE instance=", 5).await;
        self.instance = instance.clone();
        self.scene.instance = Some(instance);
        self.daemon = Some(daemon);
        // Clients read Health first, as the harness does: dynamic features such as
        // ExecStream are proven there.
        let h = self.rpc(OWNER, json!({ "op": "health" })).await;
        assert!(h.get("ok").is_some(), "Health after start: {h}");
        serde_json::from_str(&reconciled).unwrap()
    }

    /// Starts a daemon without waiting for it.
    pub(super) fn spawn_daemon(&mut self) -> Proc {
        Proc::spawn("c6b_daemon_child", "daemon", &self.daemon_spawn_args())
    }

    pub(super) async fn kill_daemon(&mut self) {
        self.daemon.take().unwrap().kill().await;
    }

    pub(super) async fn stop_daemon(&mut self) {
        let status = self.daemon.take().unwrap().stop(60).await;
        assert!(status.success(), "daemon stopped with {status}");
    }

    pub(super) async fn rpc(&self, uid: u32, call: Value) -> Value {
        rpc(&self.api, uid, call).await
    }

    /// Ok's value of a call as the owner.
    pub(super) async fn ok(&self, call: Value) -> Value {
        let r = self.rpc(OWNER, call).await;
        ok(&r).clone()
    }

    pub(super) async fn sh(&self, id: &str, script: &str) -> Value {
        let r = self
            .ok(json!({ "op": "exec", "id": id, "script": script }))
            .await;
        assert_eq!(r["exit_code"], 0, "{script}: {r}");
        r
    }

    /// A source sandbox as the owner, with `script` run in it.
    pub(super) async fn source(&self, disk_bytes: u64, script: &str) -> String {
        let s = self
            .ok(json!({ "op": "create", "disk_bytes": disk_bytes }))
            .await;
        let id = s["id"].as_str().unwrap().to_string();
        if !script.is_empty() {
            self.sh(&id, script).await;
        }
        id
    }

    /// The daemon's database, read only, as an observer (never written).
    pub(super) fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(
            self.state.join("kilnd.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap()
    }

    /// A checkpoint row's state, or "" if none.
    pub(super) fn cp_state(&self, id: &str) -> String {
        self.db()
            .query_row("SELECT state FROM checkpoints WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap_or_default()
    }

    /// One column of a checkpoint row as text ("" if NULL or no row).
    pub(super) fn cp_col(&self, id: &str, column: &str) -> String {
        assert!(column.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
        self.db()
            .query_row(
                &format!("SELECT coalesce(CAST({column} AS TEXT), '') FROM checkpoints WHERE id = ?1"),
                [id],
                |r| r.get(0),
            )
            .unwrap_or_default()
    }

    /// One column of a sandbox row as text ("" if NULL or no row).
    pub(super) fn sb_col(&self, id: &str, column: &str) -> String {
        assert!(column.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
        self.db()
            .query_row(
                &format!("SELECT coalesce(CAST({column} AS TEXT), '') FROM sandboxes WHERE id = ?1"),
                [id],
                |r| r.get(0),
            )
            .unwrap_or_default()
    }

    /// The node's checkpoint count and charged bytes.
    pub(super) fn charge(&self) -> (u64, u64) {
        self.db()
            .query_row(
                "SELECT live, charged_bytes FROM checkpoint_counts WHERE owner_uid = -1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
            )
            .unwrap()
    }

    /// Every checkpoint row: (id, state).
    pub(super) fn rows(&self) -> Vec<(String, String)> {
        let db = self.db();
        let mut q = db
            .prepare("SELECT id, state FROM checkpoints ORDER BY creation_seq")
            .unwrap();
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The checkpoint the source's newest row names, waiting for it to exist.
    pub(super) async fn capturing_row(&self, source: &str, secs: u64) -> String {
        let end = StdInstant::now() + Duration::from_secs(secs);
        loop {
            let found: Option<String> = self
                .db()
                .query_row(
                    "SELECT id FROM checkpoints WHERE source_sandbox_id = ?1 ORDER BY creation_seq DESC LIMIT 1",
                    [source],
                    |r| r.get(0),
                )
                .ok();
            if let Some(id) = found {
                return id;
            }
            assert!(StdInstant::now() < end, "no checkpoint row for {source}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Absence evidence rows recorded for a checkpoint.
    pub(super) fn evidence(&self, id: &str, kind: &str) -> u64 {
        self.db()
            .query_row(
                "SELECT count(*) FROM checkpoint_evidence WHERE checkpoint_id = ?1 AND kind = ?2",
                [id, kind],
                |r| r.get::<_, i64>(0),
            )
            .unwrap() as u64
    }

    pub(super) fn barrier_marked(&self) -> bool {
        self.db()
            .query_row("SELECT count(*) FROM checkpoint_barrier", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
            > 0
    }

    /// A sandbox row's state, or "" if none.
    pub(super) fn sandbox_state(&self, id: &str) -> String {
        self.db()
            .query_row("SELECT state FROM sandboxes WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap_or_default()
    }

    /// A fork pin's release (`released_by`, or "" while live), if the sandbox has one.
    pub(super) fn pin(&self, sandbox: &str) -> Option<String> {
        self.db()
            .query_row(
                "SELECT coalesce(released_by, '') FROM checkpoint_pins WHERE sandbox_id = ?1",
                [sandbox],
                |r| r.get(0),
            )
            .ok()
    }

    /// Waits until `done` holds, polling every 50 ms.
    pub(super) async fn until(&self, what: &str, secs: u64, mut done: impl FnMut(&Self) -> bool) {
        let end = StdInstant::now() + Duration::from_secs(secs);
        while StdInstant::now() < end {
            if done(self) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out after {secs} s waiting for {what}");
    }

    /// kiln processes reading or writing one of this instance's artifacts: (pid, argv).
    pub(super) fn workers(&self) -> Vec<(u32, Vec<String>)> {
        artifact_processes()
            .into_iter()
            .filter(|(_, argv)| argv.iter().any(|a| a.contains(self.instance.as_str())))
            .collect()
    }

    /// Waits for a worker of the current helper (a descendant of its process) whose
    /// arguments contain `word` (e.g. `capture` or `--from-checkpoint`), and returns the
    /// outermost one: the CLI, never a restored sandbox's shim it started.
    pub(super) async fn worker(&self, word: &str, secs: u64) -> u32 {
        let end = StdInstant::now() + Duration::from_secs(secs);
        let helper = self.helper.as_ref().expect("a helper").pid as u32;
        loop {
            let matches: Vec<u32> = self
                .workers()
                .into_iter()
                .filter(|(pid, argv)| {
                    argv.iter().any(|a| a.contains(word)) && descends_from(*pid, helper)
                })
                .map(|(pid, _)| pid)
                .collect();
            if let Some(pid) = matches
                .iter()
                .find(|pid| !matches.iter().any(|other| other != *pid && descends_from(**pid, *other)))
            {
                return *pid;
            }
            assert!(StdInstant::now() < end, "no {word} worker in {secs} s");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The instance's artifact directory entries (published, staging and tombstones).
    pub(super) fn artifacts(&self) -> Vec<String> {
        let dir = format!("{}/{}", super::CPS, self.instance);
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// What [`Self::finish`] checks: the kiln runs, the daemon's rows and the instance's
    /// artifact entries, read without changing anything.
    pub(super) fn host_state(&self) -> HostState {
        let db = self.db();
        let mut q = db
            .prepare(
                "SELECT id, state, backend_id, owner_uid, \
                 legacy_release IS NOT NULL OR release_evidence_id IS NOT NULL \
                 FROM sandboxes ORDER BY list_seq",
            )
            .unwrap();
        let sandboxes = q
            .query_map([], |r| {
                Ok(SandboxRow {
                    id: r.get(0)?,
                    state: r.get(1)?,
                    backend_id: r.get(2)?,
                    owner_uid: r.get::<_, i64>(3)? as u32,
                    released: r.get(4)?,
                })
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut q = db
            .prepare("SELECT id, state, owner_uid FROM checkpoints ORDER BY creation_seq")
            .unwrap();
        let checkpoints = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u32)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        HostState {
            runs: run_dirs(),
            listed: kiln_listed(),
            sandboxes,
            checkpoints,
            artifacts: self.artifacts(),
        }
    }

    /// Ends a scenario that passed (C6b review HIGH 6). Before any cleanup it requires
    /// the exact expected state ([`residue_before_cleanup`]): every kiln run a live
    /// sandbox's backend, every READY sandbox's backend a run, and no artifact entry
    /// but each live checkpoint's own. Then it deletes every checkpoint and sandbox
    /// through the API as its owner, each answer checked, and requires nothing left
    /// ([`residue_after_cleanup`]) before stopping the daemon and the helper. The
    /// scene's root cleanup is a fallback only: needed after this, it fails the test.
    pub(super) async fn finish(mut self) {
        // A kiln child a scenario orphaned holds its artifact until it exits.
        self.until("no process naming the artifacts", 180, |w| w.workers().is_empty())
            .await;
        if self.daemon.is_none() {
            self.relay.clear_rules();
            self.start_daemon().await;
        }
        self.until("no checkpoint capturing or deleting", 120, |w| {
            w.rows().iter().all(|(_, s)| s != "capturing" && s != "deleting")
        })
        .await;
        let before = self.host_state();
        assert_clean(&residue_before_cleanup(&before), "before cleanup", &before);
        for (id, state, owner) in &before.checkpoints {
            if matches!(state.as_str(), "ready" | "quarantined") {
                let d = self.rpc(*owner, json!({ "op": "delete_checkpoint", "id": id })).await;
                assert!(
                    matches!(
                        ok(&d)["state"].as_str(),
                        Some("CHECKPOINT_STATE_DELETED" | "CHECKPOINT_STATE_DELETING")
                    ),
                    "Delete of {id}: {d}"
                );
            }
        }
        for row in before.sandboxes.iter().filter(|s| s.state != "deleted") {
            let d = self.rpc(row.owner_uid, json!({ "op": "delete", "id": row.id })).await;
            assert_eq!(ok(&d)["state"], "SANDBOX_STATE_DELETED", "Delete of {}: {d}", row.id);
        }
        self.until("every checkpoint settled", 120, |w| {
            w.rows()
                .iter()
                .all(|(_, s)| matches!(s.as_str(), "deleted" | "failed"))
        })
        .await;
        assert_eq!(self.charge(), (0, 0), "charge left: {:?}", self.rows());
        let after = self.host_state();
        assert_clean(&residue_after_cleanup(&after), "after cleanup", &after);
        self.stop_daemon().await;
        if let Some(helper) = self.helper.take() {
            let status = helper.stop(60).await;
            assert!(status.success(), "helper stopped with {status}");
        }
        assert!(self.workers().is_empty(), "{:?}", self.workers());
        assert_eq!(self.artifacts(), Vec::<String>::new(), "artifacts left");
        drop(self);
    }
}

/// One sandbox row as [`World::finish`] reads it.
#[derive(Clone, Debug)]
pub(super) struct SandboxRow {
    pub(super) id: String,
    pub(super) state: String,
    pub(super) backend_id: Option<String>,
    pub(super) owner_uid: u32,
    /// Its backend is proven gone (compensated, deleted or never created, or ABSENT
    /// evidence recorded).
    pub(super) released: bool,
}

/// The state [`World::finish`] judges.
#[derive(Clone, Debug, Default)]
pub(super) struct HostState {
    /// Run directories under the runs root, `.checkpoints` aside.
    pub(super) runs: Vec<String>,
    /// The IDs `kiln ls` lists.
    pub(super) listed: Vec<String>,
    pub(super) sandboxes: Vec<SandboxRow>,
    /// (id, state, owner uid).
    pub(super) checkpoints: Vec<(String, String, u32)>,
    /// The daemon instance's artifact directory entries.
    pub(super) artifacts: Vec<String>,
}

/// Every way the state before cleanup differs from the expected one: a run (in the
/// runs root or `kiln ls`) that no live, unreleased sandbox names; a READY sandbox
/// without its run; an artifact entry that is not a READY or QUARANTINED
/// checkpoint's completed artifact (staging, tombstones, a settled checkpoint's); a
/// live checkpoint without its artifact; a checkpoint still capturing or deleting.
pub(super) fn residue_before_cleanup(s: &HostState) -> Vec<String> {
    let mut found = Vec::new();
    let named: Vec<&str> = s
        .sandboxes
        .iter()
        .filter(|r| r.state != "deleted" && !r.released)
        .filter_map(|r| r.backend_id.as_deref())
        .collect();
    let mut runs: Vec<&String> = s.runs.iter().chain(&s.listed).collect();
    runs.sort();
    runs.dedup();
    for run in runs {
        if !named.contains(&run.as_str()) {
            found.push(format!("run {run} is no live sandbox's backend"));
        }
    }
    for r in s.sandboxes.iter().filter(|r| r.state == "ready") {
        match r.backend_id.as_deref() {
            Some(b) if s.runs.iter().any(|x| x == b) && s.listed.iter().any(|x| x == b) => {}
            b => found.push(format!("READY sandbox {} has no run (backend {b:?})", r.id)),
        }
    }
    let live: Vec<&str> = s
        .checkpoints
        .iter()
        .filter(|(_, st, _)| matches!(st.as_str(), "ready" | "quarantined"))
        .map(|(id, _, _)| id.as_str())
        .collect();
    for name in &s.artifacts {
        if !live.contains(&name.as_str()) {
            found.push(format!("artifact entry {name} is no live checkpoint's"));
        }
    }
    for id in &live {
        if !s.artifacts.iter().any(|a| a == id) {
            found.push(format!("live checkpoint {id} has no artifact"));
        }
    }
    for (id, st, _) in &s.checkpoints {
        if matches!(st.as_str(), "capturing" | "deleting") {
            found.push(format!("checkpoint {id} still {st}"));
        }
    }
    found
}

/// Every way the state after the API's deletes is not empty: any run, any artifact
/// entry, a sandbox not deleted, a checkpoint neither deleted nor failed.
pub(super) fn residue_after_cleanup(s: &HostState) -> Vec<String> {
    let mut found: Vec<String> = s.runs.iter().map(|r| format!("run {r} left")).collect();
    found.extend(s.listed.iter().map(|r| format!("kiln ls lists {r}")));
    found.extend(s.artifacts.iter().map(|a| format!("artifact entry {a} left")));
    found.extend(
        s.sandboxes
            .iter()
            .filter(|r| r.state != "deleted")
            .map(|r| format!("sandbox {} is {}", r.id, r.state)),
    );
    found.extend(
        s.checkpoints
            .iter()
            .filter(|(_, st, _)| !matches!(st.as_str(), "deleted" | "failed"))
            .map(|(id, st, _)| format!("checkpoint {id} is {st}")),
    );
    found
}

#[track_caller]
pub(super) fn assert_clean(residue: &[String], when: &str, state: &HostState) {
    assert!(residue.is_empty(), "residue {when}: {residue:?} in {state:?}");
}

/// The run directories under the runs root, `.checkpoints` aside, sorted.
pub(super) fn run_dirs() -> Vec<String> {
    let mut runs: Vec<String> = std::fs::read_dir(super::RUNS)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != ".checkpoints")
                .collect()
        })
        .unwrap_or_default();
    runs.sort();
    runs
}

/// The IDs `kiln ls` lists, sorted.
pub(super) fn kiln_listed() -> Vec<String> {
    let out = std::process::Command::new(kiln_bin()).arg("ls").output().unwrap();
    assert!(out.status.success(), "kiln ls: {out:?}");
    let mut ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

#[cfg(test)]
mod finish_tests {
    //! `World::finish`'s residue checks on any host (C6b review HIGH 6): an injected
    //! run, a staging or tombstone entry, a settled checkpoint's artifact or a READY
    //! sandbox without its run fails it.
    use super::*;

    fn sandbox(id: &str, state: &str, backend: Option<&str>, released: bool) -> SandboxRow {
        SandboxRow {
            id: id.into(),
            state: state.into(),
            backend_id: backend.map(str::to_string),
            owner_uid: OWNER,
            released,
        }
    }

    /// A clean state: one READY sandbox and its run, a FAILED fork whose backend was
    /// compensated, one READY checkpoint and its artifact, a settled one.
    fn clean() -> HostState {
        HostState {
            runs: vec!["run-a".into()],
            listed: vec!["run-a".into()],
            sandboxes: vec![
                sandbox("sb-a", "ready", Some("run-a"), false),
                sandbox("sb-f", "failed", Some("run-f"), true),
                sandbox("sb-d", "deleted", Some("run-d"), true),
            ],
            checkpoints: vec![
                ("cp-1".into(), "ready".into(), OWNER),
                ("cp-2".into(), "deleted".into(), OWNER),
            ],
            artifacts: vec!["cp-1".into()],
        }
    }

    #[test]
    fn finish_refuses_any_residue_before_cleanup() {
        assert_eq!(residue_before_cleanup(&clean()), Vec::<String>::new());
        let with = |f: &dyn Fn(&mut HostState)| {
            let mut s = clean();
            f(&mut s);
            residue_before_cleanup(&s)
        };
        // An injected extra run, in the runs root or only in `kiln ls`.
        assert_eq!(with(&|s| s.runs.push("run-x".into())).len(), 1);
        assert_eq!(with(&|s| s.listed.push("run-x".into())).len(), 1);
        // A run of a deleted or compensated sandbox.
        assert_eq!(with(&|s| s.runs.push("run-d".into())).len(), 1);
        assert_eq!(with(&|s| s.runs.push("run-f".into())).len(), 1);
        // A READY sandbox without its run.
        assert_eq!(with(&|s| s.runs.clear()).len(), 1);
        // Staging, tombstones and a settled checkpoint's artifact.
        for name in [".staging-cp-1-1-00ff", ".removing-cp-1-1-2-3", "cp-2"] {
            assert_eq!(with(&|s| s.artifacts.push(name.into())).len(), 1, "{name}");
        }
        // A live checkpoint without its artifact, and an unsettled one.
        assert_eq!(with(&|s| s.artifacts.clear()).len(), 1);
        assert_eq!(with(&|s| s.checkpoints[1].1 = "deleting".into()).len(), 1);
    }

    #[test]
    fn an_injected_run_makes_finish_fail() {
        let mut s = clean();
        s.runs.push("run-x".into());
        let failed = std::panic::catch_unwind(|| {
            assert_clean(&residue_before_cleanup(&s), "before cleanup", &s)
        })
        .expect_err("finish passed with an injected run");
        let message = failed
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert!(message.contains("residue before cleanup") && message.contains("run-x"), "{message}");
    }

    #[test]
    fn finish_requires_nothing_left_after_cleanup() {
        let empty = HostState {
            sandboxes: vec![sandbox("sb-a", "deleted", Some("run-a"), true)],
            checkpoints: vec![("cp-1".into(), "deleted".into(), OWNER)],
            ..HostState::default()
        };
        assert_eq!(residue_after_cleanup(&empty), Vec::<String>::new());
        let mut s = empty.clone();
        s.runs.push("run-a".into());
        assert_eq!(residue_after_cleanup(&s), vec!["run run-a left".to_string()]);
        let mut s = empty;
        s.artifacts.push(".removing-cp-1-1-2-3".into());
        assert_eq!(residue_after_cleanup(&s).len(), 1);
    }
}

pub(super) fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
}

/// Every live process of the trusted kiln executable whose arguments name an
/// artifact (`--instance=`, `--from-checkpoint=` or an `INSTANCE/CHECKPOINT` word): (pid,
/// argv). A scan of our own, since the helper's table has no pids.
pub(super) fn artifact_processes() -> Vec<(u32, Vec<String>)> {
    let kiln = std::fs::canonicalize(kiln_bin()).unwrap();
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().filter_map(Result::ok) {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if std::fs::read_link(entry.path().join("exe")).ok().as_deref() != Some(kiln.as_path()) {
            continue;
        }
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let argv: Vec<String> = cmdline
            .split(|b| *b == 0)
            .filter(|w| !w.is_empty())
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect();
        if argv.iter().any(|a| a.contains("checkpoint")) {
            out.push((pid, argv));
        }
    }
    out
}

/// SIGKILL to a process that is not our child (a kiln worker).
pub(super) fn kill_pid(pid: u32) {
    // SAFETY: a pid read from /proc just before; a reused pid is the test's risk.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    eprintln!("C6B killed pid {pid}");
}

/// Whether a pid is alive (and not a zombie).
pub(super) fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state != "Z" && state != "X")
    })
}

/// A pid's parent, from `/proc/PID/stat`.
pub(super) fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

/// Whether `ancestor` is `pid`'s parent, grandparent or great-grandparent.
pub(super) fn descends_from(pid: u32, ancestor: u32) -> bool {
    let mut at = pid;
    for _ in 0..4 {
        match parent_of(at) {
            Some(p) if p == ancestor => return true,
            Some(p) if p > 1 => at = p,
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod relay_tests {
    //! The relay on any host, with no kiln: a frame parsed, forwarded and answered; a
    //! held request never reaching the helper; a held reply never delivered;
    //! descriptors passed through.
    use super::*;

    fn uid() -> u32 {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn op_names_follow_the_tagged_enums() {
        assert_eq!(
            op_name(&json!({"checkpoint": {"group_version": 1, "helper_epoch": null, "operation": "capabilities"}})),
            "checkpoint.capabilities"
        );
        assert_eq!(
            op_name(&json!({"checkpoint": {"group_version": 1, "operation": {"capture": {"binding": {}}}}})),
            "checkpoint.capture"
        );
        assert_eq!(op_name(&json!({"kiln": {"exec": {"id": "x"}}})), "kiln.exec");
        assert_eq!(op_name(&json!({"kiln": "ls"})), "kiln.ls");
        assert_eq!(
            op_name(&json!({"checkpoint": {"removed": {"absent": {}}}})),
            "checkpoint.removed"
        );
        assert_eq!(op_name(&json!({"checkpoint": "acknowledged"})), "checkpoint.acknowledged");
    }

    /// A fake helper: reads one request, sends an envelope with `fds` socket pairs'
    /// ends, then the reply frame and EOF.
    async fn fake_helper(listener: UnixListener, fds: usize, reply: &'static [u8]) -> Vec<String> {
        let mut requests = Vec::new();
        while let Ok(Ok((mut stream, _))) =
            tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
        {
            assert!(receive_envelope(&stream).await.unwrap().is_empty());
            let body = read_frame_raw(&mut stream).await.unwrap();
            requests.push(String::from_utf8(body).unwrap());
            let pairs: Vec<(std::os::unix::net::UnixStream, std::os::unix::net::UnixStream)> =
                (0..fds).map(|_| std::os::unix::net::UnixStream::pair().unwrap()).collect();
            let raw: Vec<RawFd> = pairs.iter().map(|(a, _)| a.as_raw_fd()).collect();
            send_envelope(&stream, &raw).await.unwrap();
            for (_, b) in &pairs {
                use std::io::Write;
                let mut b = b;
                b.write_all(b"pong").unwrap();
            }
            write_frame_raw(&mut stream, reply).await.unwrap();
            // The sender keeps its ends until the exchange is over, as the helper does
            // until the receipt (an in-flight last reference reads EOF on Darwin).
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.shutdown().await.unwrap();
            drop(pairs);
        }
        requests
    }

    async fn call(relay: &Path, body: &str) -> std::io::Result<(Vec<OwnedFd>, Vec<u8>)> {
        let mut s = UnixStream::connect(relay).await?;
        send_envelope(&s, &[]).await?;
        write_frame_raw(&mut s, body.as_bytes()).await?;
        let fds = receive_envelope(&s).await?;
        let reply = read_frame_raw(&mut s).await?;
        Ok((fds, reply))
    }

    /// The daemon and rpc roles over a real socket with the fake runtime: typed results
    /// and refusals as JSON, a SIGKILL and a restart on the same state.
    #[tokio::test]
    async fn the_roles_serve_answer_and_survive_a_kill() {
        let tmp = tempfile::tempdir().unwrap();
        set_mode(tmp.path(), 0o700);
        let state = tmp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        set_mode(&state, 0o700);
        let api = tmp.path().join("api").join("kilnd.sock");
        // SAFETY: no preconditions.
        let (me, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let args = json!({
            "fake": true, "state": state.to_str().unwrap(), "api": api.to_str().unwrap(),
            "image": "alpine", "gid": gid,
        });
        let daemon = Proc::spawn("c6b_daemon_child", "daemon", &args);
        daemon.line("C6B DAEMON SERVING", 60).await;
        let h = rpc(&api, me, json!({"op": "health"})).await;
        assert_eq!(ok(&h)["checkpoint"], true, "{h}");
        let s = rpc(&api, me, json!({"op": "create", "request_id": "k1"})).await;
        let id = ok(&s)["id"].as_str().unwrap().to_string();
        assert_eq!(ok(&s)["state"], "SANDBOX_STATE_READY", "{s}");
        let c = rpc(&api, me, json!({"op": "capture", "id": id, "request_id": "c1"})).await;
        let cp = ok(&c)["id"].as_str().unwrap().to_string();
        assert_eq!(ok(&c)["state"], "CHECKPOINT_STATE_READY", "{c}");
        let e = rpc(&api, me, json!({"op": "get_checkpoint", "id": "cp-00000000000000000000000000000000"})).await;
        assert_eq!(e["error"]["code"], "NotFound", "{e}");
        let f = rpc(&api, me, json!({"op": "create", "from_checkpoint": cp})).await;
        assert_eq!(ok(&f)["from_checkpoint"], cp.as_str(), "{f}");
        let busy = rpc(&api, me, json!({"op": "capture", "id": id, "request_id": "c1", "lifetime_ms": 20_000})).await;
        assert_eq!(refused(&busy), "request_id_conflict", "a key reused with another request: {busy}");
        daemon.kill().await;
        // Linux probes and replaces a dead daemon's socket; Darwin fails closed.
        #[cfg(not(target_os = "linux"))]
        std::fs::remove_file(&api).unwrap();
        let daemon = Proc::spawn("c6b_daemon_child", "daemon", &args);
        let r: Value = serde_json::from_str(&daemon.line("C6B DAEMON RECONCILED ", 60).await).unwrap();
        assert_eq!(r["checkpoints_blocked"], false, "{r}");
        daemon.line("C6B DAEMON SERVING", 60).await;
        let again = rpc(&api, me, json!({"op": "capture", "id": id, "request_id": "c1"})).await;
        assert_eq!(ok(&again)["id"], cp.as_str(), "{again}");
        let d = rpc(&api, me, json!({"op": "delete_checkpoint", "id": cp, "release": true})).await;
        assert_eq!(ok(&d)["state"], "CHECKPOINT_STATE_DELETED", "{d}");
        assert!(daemon.stop(30).await.success());
    }

    #[tokio::test]
    async fn the_relay_forwards_holds_and_passes_descriptors() {
        let tmp = tempfile::tempdir().unwrap();
        let helper = tmp.path().join("h.sock");
        let relay_at = tmp.path().join("r.sock");
        let listener = UnixListener::bind(&helper).unwrap();
        let reply: &'static [u8] = br#"{"checkpoint":{"captured":{"x":1}}}"#;
        let fake = tokio::spawn(fake_helper(listener, 3, reply));
        let relay = Relay::start(&relay_at, &helper);
        let capture =
            r#"{"version":3,"timeout_ms":1,"deadline_ns":1,"operation":{"checkpoint":{"group_version":1,"helper_epoch":null,"operation":{"capture":{"binding":{}}}}}}"#;
        // 1. Forwarded both ways, three descriptors passed through and readable.
        let (fds, got) = call(&relay_at, capture).await.unwrap();
        assert_eq!(got, reply);
        assert_eq!(fds.len(), 3);
        for fd in fds {
            use std::io::Read;
            let mut s = std::os::unix::net::UnixStream::from(fd);
            let mut b = [0u8; 4];
            s.read_exact(&mut b).unwrap();
            assert_eq!(&b, b"pong");
        }
        // 2. A held reply: received from the helper, never delivered.
        relay.add(hold(Phase::Reply, "checkpoint.captured", None));
        let pending = tokio::spawn({
            let relay_at = relay_at.clone();
            async move { call(&relay_at, capture).await }
        });
        relay.held("checkpoint.captured", 5).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!pending.is_finished());
        pending.abort();
        // 3. A held request never reaches the helper.
        let mark = relay.mark();
        relay.add(hold(Phase::Request, "checkpoint.capture", Some("binding")));
        let pending = tokio::spawn({
            let relay_at = relay_at.clone();
            async move { call(&relay_at, capture).await }
        });
        relay.held("checkpoint.capture", 5).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!pending.is_finished());
        pending.abort();
        assert_eq!(relay.requests_since(mark, "checkpoint.capture").len(), 1);
        let requests = fake.await.unwrap();
        assert_eq!(requests.len(), 2, "the held request was forwarded: {requests:?}");
        let _ = uid();
    }
}

#[cfg(test)]
mod oracle_tests {
    //! The fidelity oracle's own negative tests, on any host (C6b review HIGH 3): it
    //! sees one swapped invalid filename byte and one directory mtime.
    use super::*;

    fn exec(stdout: &[u8]) -> Value {
        exec_json("EXECUTION_STATE_SUCCEEDED", Some(0), stdout, b"", "")
    }

    #[test]
    fn the_fidelity_oracle_sees_swapped_invalid_filename_bytes() {
        let a = exec(b"/root/w/n\xff\xfe|regular file|644|0|0|1|1|2026-11-15 12:00:00.000000001 +0000\n");
        let b = exec(b"/root/w/n\xfe\xff|regular file|644|0|0|1|1|2026-11-15 12:00:00.000000001 +0000\n");
        // The lossy text, all the old oracle compared, cannot tell them apart.
        assert_eq!(a["stdout"], b["stdout"]);
        let behaviour = exec(b"same\n");
        let e = same_tree(&[a.clone(), behaviour.clone()], &[b, behaviour.clone()]).unwrap_err();
        assert!(e.contains("tree differs at line 0") && e.contains("xff") && e.contains("xfe"), "{e}");
        same_tree(&[a.clone(), behaviour.clone()], &[a.clone(), behaviour]).unwrap();
        // And the behaviour output too.
        let e = same_tree(&[a.clone(), exec(b"n\xff\xfe\n")], &[a, exec(b"n\xfe\xff\n")]).unwrap_err();
        assert!(e.contains("behaviour differs"), "{e}");
    }

    #[test]
    fn the_fidelity_oracle_sees_one_directory_mtime() {
        let tree = |mtime: &str| {
            exec(format!(
                "/root/w|directory|755|0|0|3|{mtime}\n/root/w/d|directory|755|0|0|2|2026-11-15 12:00:00.000000000 +0000\n"
            ).as_bytes())
        };
        let behaviour = exec(b"");
        let e = same_tree(
            &[tree("2026-11-15 12:00:00.000000001 +0000"), behaviour.clone()],
            &[tree("2026-11-15 12:00:00.000000002 +0000"), behaviour.clone()],
        )
        .unwrap_err();
        assert!(e.contains("line 0"), "{e}");
        // The listing prints a directory's mtime (and every entry's link count).
        let script = listing_script(&["/root/w"]);
        assert!(script.contains("stat -c '%n|%F|%a|%u|%g|%h|%y'"), "{script}");
    }

    /// The listing itself, run for real where GNU stat is the system's (Linux): one
    /// swapped invalid name byte and one directory mtime change its bytes.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_listing_records_name_bytes_and_directory_mtimes() {
        use std::os::unix::ffi::OsStrExt;
        let run = |root: &Path| -> Vec<u8> {
            let out = std::process::Command::new("sh")
                .args(["-c", &listing_script(&[root.to_str().unwrap()])])
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
            out.stdout
                .split(|c| *c == b'\n')
                .map(|l| l.strip_prefix(root.as_os_str().as_bytes()).unwrap_or(l).to_vec())
                .collect::<Vec<_>>()
                .join(&b'\n')
        };
        let tree = |name: &[u8]| {
            let t = tempfile::tempdir().unwrap();
            let dir = t.path().join("d");
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join(std::ffi::OsStr::from_bytes(name)), b"a").unwrap();
            let pin = |p: &Path| {
                let f = std::fs::File::open(p).unwrap();
                f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000)).unwrap();
            };
            pin(&dir.join(std::ffi::OsStr::from_bytes(name)));
            pin(&dir);
            pin(t.path());
            t
        };
        let (a, b) = (tree(b"n\xff\xfe"), tree(b"n\xfe\xff"));
        assert_ne!(run(a.path()), run(b.path()), "swapped invalid bytes");
        let c = tree(b"n\xff\xfe");
        assert_eq!(run(a.path()), run(c.path()), "the same tree");
        std::fs::File::open(c.path().join("d"))
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_001))
            .unwrap();
        assert_ne!(run(a.path()), run(c.path()), "one directory mtime");
    }
}
