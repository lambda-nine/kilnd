//! B5's exit criteria against the real chain, as root in the VM (scripts/b4-vm-tests.sh
//! with the `b5_linux_root` filter): the patched jailer, the release Firecracker VMM and
//! the kiln-guest bundle whose `/init` starts the guest broker. A boot now ends at READY
//! through the broker handshake; executions run in the one persistent kiln sandbox; any
//! interruption after dispatch retires the VM. The hostile-source fairness test uses the
//! real relay and drainer code in real cgroups against protocol fakes (design 10.2 item
//! 13 allows them; four 896 MiB VMs do not fit this 4 GiB VM), beside one real healthy
//! allocation whose Inspect, Validate, Exec and Remove must meet their deadlines.
use super::lifecycle::{Real, create, host_leftovers, remove, worker_pid};
use super::*;
use crate::helper::firecracker::broker::{Expected, RelayJob, RelayReport, relay};
use crate::helper::firecracker::{cgroup, identity};
use crate::helper::protocol::{ExecCleanup, ExecReply, ValidateReply, WireFinishFc};
use crate::model::CommandStatus;
use kilnd_broker_protocol::message::{Exec, SessionBinding};
use std::os::fd::{FromRawFd, OwnedFd};

const MIB: usize = 1024 * 1024;

fn evidence(name: &str, value: impl std::fmt::Display) {
    eprintln!("B5 evidence: {name}: {value}");
}

async fn inspect_reply(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
) -> InspectReply {
    match raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::Inspect {
            allocation_id: context.allocation_id,
            plan_digest: super::lifecycle::ledger_digest(&real.fixture, context.allocation_id),
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap()
    {
        FirecrackerResponse::Inspect(reply) => reply,
        other => panic!("{other:?}"),
    }
}

/// Inspect until READY; the boot and inner sandbox the helper journaled.
async fn wait_ready(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
) -> (String, String) {
    let end = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let InspectReply::PresentReady {
            boot_id, inner_id, ..
        } = inspect_reply(real, runtime, context).await
        {
            return (boot_id, inner_id);
        }
        let phase = real.phase(context.allocation_id);
        assert!(
            std::time::Instant::now() < end && phase != "stop_intent",
            "never READY: phase {phase}, stop reasons {:?}\n{}",
            stop_reasons(real, context),
            real.fixture.log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn stop_reasons(real: &Real, context: &CreateContext) -> Vec<String> {
    real.fixture.read(|view| {
        let mut statement = view.prepare(
            "SELECT reason FROM stop_events WHERE allocation_id = ?1 ORDER BY generation",
        )?;
        let rows = statement
            .query_map([context.allocation_id.to_string()], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
}

async fn validate(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    boot: &str,
    inner: &str,
) -> ValidateReply {
    match raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::Validate {
            allocation_id: context.allocation_id,
            expected_boot_id: boot.into(),
            expected_inner_id: inner.into(),
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap()
    {
        FirecrackerResponse::Validate(reply) => reply,
        other => panic!("{other:?}"),
    }
}

struct Ran {
    reply: Option<ExecReply>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// One Exec as kilnd sends it: the frame, the three stdio descriptors and the receipt
/// byte, stdin, then output and the reply. `abandon` drops the connection after that
/// long instead, as a disconnected caller does.
#[allow(clippy::too_many_arguments)]
async fn exec_with(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    boot: &str,
    argv: &[&str],
    stdin: Vec<u8>,
    max_output: usize,
    seconds: u64,
    abandon: Option<Duration>,
) -> Ran {
    let request = Request {
        version: VERSION,
        timeout_ms: (seconds * 1000) as u32,
        deadline_ns: wire_deadline(seconds),
        operation: Operation::Firecracker(FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: context.instance_id,
            connection_epoch: Some(epoch_of(runtime).await),
            operation: FirecrackerOperation::Exec {
                allocation_id: context.allocation_id,
                expected_boot_id: boot.into(),
                execution_token: Id128::random(),
                execution_id: new_id("ex"),
                argv: argv.iter().map(|a| a.to_string()).collect(),
                stdin_bytes: stdin.len(),
                max_output,
            },
        }),
    };
    let mut stream = UnixStream::connect(real.fixture.root.join("helper.sock"))
        .await
        .unwrap();
    fds::send(&stream, &[]).await.unwrap();
    write_frame(&mut stream, &request).await.unwrap();
    let mut stdio: Vec<UnixStream> = fds::receive(&stream)
        .await
        .unwrap()
        .into_iter()
        .map(|fd| {
            let s = std::os::unix::net::UnixStream::from(fd);
            s.set_nonblocking(true).unwrap();
            UnixStream::from_std(s).unwrap()
        })
        .collect();
    assert_eq!(stdio.len(), 3);
    stream.write_u8(STDIO_RECEIVED).await.unwrap();
    let mut stderr = stdio.pop().unwrap();
    let mut stdout = stdio.pop().unwrap();
    let mut input = stdio.pop().unwrap();
    input.write_all(&stdin).await.unwrap();
    input.shutdown().await.unwrap();
    if let Some(after) = abandon {
        tokio::time::sleep(after).await;
        drop(stream);
        return Ran {
            reply: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let (reply, _, _) = tokio::join!(
        read_frame::<Response>(&mut stream),
        stdout.read_to_end(&mut out),
        stderr.read_to_end(&mut err)
    );
    let reply = match reply.unwrap() {
        Response::Firecracker(FirecrackerResponse::Exec(reply)) => *reply,
        other => panic!("{other:?}"),
    };
    Ran {
        reply: Some(reply),
        stdout: out,
        stderr: err,
    }
}

async fn exec(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    boot: &str,
    argv: &[&str],
    stdin: Vec<u8>,
) -> Ran {
    exec_with(real, runtime, context, boot, argv, stdin, MIB, 60, None).await
}

fn exit_of(ran: &Ran) -> Option<CommandStatus> {
    ran.reply.as_ref().and_then(|r| r.status.clone())
}

fn cgroup_file(allocation: &CreateContext, leaf: &str, file: &str) -> String {
    let path = format!(
        "/sys/fs/cgroup/{}/{}/{leaf}/{file}",
        cgroup::FIRECRACKER_TREE,
        lifecycle_cgroup(allocation)
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn lifecycle_cgroup(context: &CreateContext) -> String {
    format!(
        "{}/{}",
        context.instance_id,
        identity::host_name(context.instance_id, context.allocation_id)
    )
}

fn usage_usec(stat: &str) -> u64 {
    stat.lines()
        .find_map(|l| l.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn vm_subtree_gone(context: &CreateContext) -> bool {
    let path = format!(
        "/sys/fs/cgroup/{}/{}/vm/cgroup.events",
        cgroup::FIRECRACKER_TREE,
        lifecycle_cgroup(context)
    );
    match std::fs::read_to_string(path) {
        Ok(events) => events.lines().any(|l| l == "populated 0"),
        Err(_) => true,
    }
}

async fn removed_cleanly(real: &Real, runtime: &FirecrackerRuntime, context: &CreateContext) {
    let vmm = real.vmm(context.allocation_id);
    let reply = remove(real, runtime, context).await;
    assert!(
        matches!(reply, FenceReply::Absent { .. }),
        "{reply:?}\n{}",
        real.fixture.log()
    );
    let left = host_leftovers(real, context, vmm);
    assert!(left.is_empty(), "left behind: {left:?}");
}

/// B7 integrated recheck HIGH-2 on the real chain, Exec's final boundary: an Exec has
/// written EXEC_INTENT and is held immediately before its last latch check. A
/// fault-bearing FenceAbsent's answer is lost after L wrote the fail-stop marker, L is
/// killed before giving it, and the replacement is held before Handover. Released, the
/// Exec hands over no descriptors and dispatches nothing: the hold transferred from the
/// dead L refuses it at its own deadline and the VM is retired. Only the replacement's
/// Handover lifts the hold, after latching H from the durable marker.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b7_linux_root_crash_exec_after_intent_waits_for_the_replacement_handover() {
    use super::compaction::{b7_matrix, census_until, spawn_raw_fence};
    use std::sync::atomic::{AtomicBool, Ordering};
    let real = Real::new(NodeOptions::default()).await;
    let (runtime, context, _) = create(&real).await;
    let (boot, _) = wait_ready(&real, &runtime, &context).await;
    let instance = context.instance_id;
    let (fenced, fenced_plan) = issued(&runtime, instance).await;
    let epoch = epoch_of(&runtime).await;
    let fixture = &real.fixture;
    fixture.fault("H.exec.before_dispatch.hold");
    let done = AtomicBool::new(false);
    let exec = async {
        let ran = exec_with(
            &real,
            &runtime,
            &context,
            &boot,
            &["sh", "-c", "echo dispatched"],
            Vec::new(),
            MIB,
            15,
            None,
        )
        .await;
        done.store(true, Ordering::SeqCst);
        ran
    };
    let drive = async {
        fixture.wait_reached("H.exec.before_dispatch").await;
        fixture.fault("L.fence.sync_fail");
        fixture.fault("L.sync_failed_reply.stall");
        let fence = spawn_raw_fence(fixture, instance, epoch, &fenced, &fenced_plan, 2);
        fixture.wait_reached("L.sync_failed_reply").await;
        let reply = fence.await.unwrap().unwrap();
        assert!(matches!(reply, FirecrackerResponse::Fence(FenceReply::Ambiguous { .. })), "{reply:?}");
        let old_l = fixture.census().await["ledger"].as_i64().unwrap();
        fixture.fault("H.ledger.before_publish.hold");
        signal(old_l, libc::SIGKILL);
        fixture.clear("L.sync_failed_reply.stall");
        fixture.clear("L.fence.sync_fail");
        fixture.wait_reached("H.ledger.before_publish").await;
        // On the real chain S's own fault-bearing records may also have been in flight to
        // the dead L: each is transferred too.
        let census = fixture.census().await;
        assert!(census["transferred_holds"].as_u64() >= Some(1), "{census}");
        assert_eq!(census["latched"], json!(false), "{census}");
        fixture.clear("H.exec.before_dispatch.hold");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!done.load(Ordering::SeqCst), "the Exec waits at its final boundary");
        while !done.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let census = fixture.census().await;
        assert!(census["transferred_holds"].as_u64() >= Some(1), "still held: {census}");
        fixture.clear("H.ledger.before_publish.hold");
        census_until(fixture, "the replacement never imported the latch", |c| {
            c["latched"] == json!(true) && c["transferred_holds"] == json!(0)
        })
        .await
    };
    let (ran, census) = tokio::join!(exec, drive);
    let reply = ran.reply.expect("an Exec reply");
    assert!(!reply.dispatched, "nothing dispatched: {reply:?}");
    assert!(!reply.reusable, "{reply:?}");
    assert!(
        format!("{:?}", reply.finish).contains("latched node-wide after EXEC_INTENT"),
        "{reply:?}"
    );
    assert!(ran.stdout.is_empty(), "the broker never ran it: {:?}", ran.stdout);
    assert_eq!(census["latch_kind"], json!("fail_stop"), "{census}");
    evidence("exec cleanup", format!("{:?}", reply.cleanup));
    let removed = remove(&real, &runtime, &context).await;
    evidence("remove under the latch", format!("{removed:?}"));
    b7_matrix(
        "B7 integrated recheck HIGH-2: Exec after EXEC_INTENT, L death, replacement before Handover",
        json!({"exec": "refused at its deadline, not dispatched", "cleanup": format!("{:?}", reply.cleanup), "h_latched": "at Handover"}),
    );
}

/// B5 exit: actual persistent execution through the real chain.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_ready_and_persistent_execution() {
    let real = Real::new(NodeOptions::default()).await;
    let (runtime, context, _) = create(&real).await;
    let (boot, inner) = wait_ready(&real, &runtime, &context).await;
    evidence("ready", format!("boot {boot} inner {inner}"));
    assert_eq!(real.phase(context.allocation_id), "ready");
    assert!(matches!(
        validate(&real, &runtime, &context, &boot, &inner).await,
        ValidateReply::Ready { .. }
    ));
    // Validate never accepts another boot or inner sandbox.
    assert!(matches!(
        validate(
            &real,
            &runtime,
            &context,
            "00000000-0000-4000-8000-000000000000",
            &inner
        )
        .await,
        ValidateReply::Incompatible { .. }
    ));
    // A file one command writes, the next reads: one persistent sandbox.
    let ran = exec(
        &real,
        &runtime,
        &context,
        &boot,
        &["sh", "-c", "cat > /root/kept; echo written"],
        b"persistent bytes".to_vec(),
    )
    .await;
    let reply = ran.reply.as_ref().unwrap();
    assert_eq!(reply.finish, WireFinishFc::Completed, "{reply:?}");
    assert!(reply.reusable && reply.dispatched);
    assert_eq!(reply.cleanup, ExecCleanup::GuestCgroupDrained);
    assert_eq!(ran.stdout, b"written\n");
    let ran = exec(
        &real,
        &runtime,
        &context,
        &boot,
        &["cat", "/root/kept"],
        Vec::new(),
    )
    .await;
    assert_eq!(ran.stdout, b"persistent bytes");
    evidence(
        "persistence",
        "a later execution read the earlier one's file",
    );
    // Binary stdin and stdout, every byte value, 1 MiB.
    let binary: Vec<u8> = (0..MIB).map(|i| (i % 256) as u8).collect();
    let ran = exec(&real, &runtime, &context, &boot, &["cat"], binary.clone()).await;
    assert_eq!(ran.stdout, binary);
    // Output beyond the retained prefix is counted, not kept.
    let ran = exec(
        &real,
        &runtime,
        &context,
        &boot,
        &["head", "-c", "3000000", "/dev/zero"],
        Vec::new(),
    )
    .await;
    let reply = ran.reply.as_ref().unwrap();
    assert_eq!(ran.stdout.len(), MIB);
    assert_eq!(reply.stdout.kept, MIB);
    assert_eq!(reply.stdout.total, 3_000_000);
    assert!(reply.stdout.truncated);
    assert_eq!(ran.stderr.len(), 0);
    // Genuine exits 124 to 127, distinct from a signal, and from exit 143.
    for code in [0, 1, 124, 125, 126, 127, 143] {
        let ran = exec(
            &real,
            &runtime,
            &context,
            &boot,
            &["sh", "-c", &format!("exit {code}")],
            Vec::new(),
        )
        .await;
        assert_eq!(
            exit_of(&ran),
            Some(CommandStatus::Exited(code)),
            "{:?}",
            ran.reply
        );
        assert!(ran.reply.unwrap().reusable);
    }
    let ran = exec(
        &real,
        &runtime,
        &context,
        &boot,
        &["sh", "-c", "kill -TERM $$"],
        Vec::new(),
    )
    .await;
    assert_eq!(
        exit_of(&ran),
        Some(CommandStatus::Signaled {
            signal: 15,
            core_dumped: false
        })
    );
    let ran = exec(
        &real,
        &runtime,
        &context,
        &boot,
        &["/nonexistent"],
        Vec::new(),
    )
    .await;
    let reply = ran.reply.unwrap();
    evidence(
        "missing executable",
        format!("{:?} {:?}", reply.finish, reply.status),
    );
    assert!(reply.reusable);
    // stderr is its own stream.
    let ran = exec(
        &real,
        &runtime,
        &context,
        &boot,
        &["sh", "-c", "echo out; echo err >&2"],
        Vec::new(),
    )
    .await;
    assert_eq!(
        (ran.stdout.as_slice(), ran.stderr.as_slice()),
        (&b"out\n"[..], &b"err\n"[..])
    );
    // R's and D's CPU is charged to the allocation, outside H.
    let relay = usage_usec(&cgroup_file(&context, "relay", "cpu.stat"));
    let console = usage_usec(&cgroup_file(&context, "vm/console", "cpu.stat"));
    evidence(
        "cpu charged outside H",
        format!("relay {relay} usec, console {console} usec"),
    );
    assert!(relay > 0 && console > 0);
    assert!(worker_pid(&real, context.allocation_id, "relay").is_some());
    assert!(worker_pid(&real, context.allocation_id, "console").is_some());
    assert!(matches!(
        validate(&real, &runtime, &context, &boot, &inner).await,
        ValidateReply::Ready { .. }
    ));
    removed_cleanly(&real, &runtime, &context).await;
}

/// B5-01 in the real chain: 3,000 short executions in one session leave one
/// execution summary in the journal, and Remove still reaches ABSENT.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_three_thousand_executions_keep_the_ledger_bounded() {
    let real = Real::new(NodeOptions::default()).await;
    let (runtime, context, _) = create(&real).await;
    let (boot, inner) = wait_ready(&real, &runtime, &context).await;
    const EXECUTIONS: u64 = 3_000;
    let began = std::time::Instant::now();
    for index in 0..EXECUTIONS {
        let ran = exec(&real, &runtime, &context, &boot, &["true"], Vec::new()).await;
        let reply = ran.reply.unwrap();
        assert!(
            reply.reusable && reply.finish == WireFinishFc::Completed,
            "execution {index}: {reply:?}"
        );
    }
    evidence(
        "three thousand executions",
        format!("{EXECUTIONS} in {:?}", began.elapsed()),
    );
    let rows: Vec<String> = real.fixture.read(|view| {
        let mut statement = view.prepare(
            "SELECT detail FROM resource_events WHERE allocation_id = ?1
               AND kind IN ('exec','exec_history') ORDER BY generation",
        )?;
        let rows = statement
            .query_map([context.allocation_id.to_string()], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    });
    evidence("execution rows after the run", format!("{rows:?}"));
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].contains(&format!("\"settled\":{EXECUTIONS}")),
        "{rows:?}"
    );
    assert!(matches!(
        validate(&real, &runtime, &context, &boot, &inner).await,
        ValidateReply::Ready { .. }
    ));
    removed_cleanly(&real, &runtime, &context).await;
}

/// B5-04 (the break-it reviewer's live PoC): the test guest's root wrapper kills the persistent
/// sandbox's init five seconds after it appears, leaving the broker Idle. Validate
/// must not call that sandbox Ready: the broker's liveness check faults the session,
/// and H retires the VM. The guest comes from `scripts/b5-test-guest.sh`.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_a_killed_inner_sandbox_is_never_ready() {
    let guest = std::env::var("KILND_B5_KILL_INNER_GUEST")
        .ok()
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .expect("KILND_B5_KILL_INNER_GUEST names the test guest (scripts/b5-test-guest.sh)");
    let real = Real::with_guest(NodeOptions::default(), Some(&guest)).await;
    let (runtime, context, _) = create(&real).await;
    let (boot, inner) = wait_ready(&real, &runtime, &context).await;
    evidence(
        "kill-inner guest",
        format!("READY boot {boot} inner {inner}"),
    );
    // The wrapper kills init five seconds after it appears; eight is past that.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let reply = validate(&real, &runtime, &context, &boot, &inner).await;
    evidence(
        "validate after the inner sandbox died",
        format!("{reply:?}"),
    );
    assert!(
        !matches!(reply, ValidateReply::Ready { .. }),
        "a dead inner sandbox was reported Ready"
    );
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while !vm_subtree_gone(&context) {
        assert!(std::time::Instant::now() < end, "the VM was not retired");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stop_reasons(&real, &context)
            .iter()
            .any(|reason| reason.contains("not idle"))
    );
    let ran = exec(&real, &runtime, &context, &boot, &["true"], Vec::new()).await;
    assert!(
        !ran.reply.unwrap().dispatched,
        "nothing runs in the retired boot"
    );
    removed_cleanly(&real, &runtime, &context).await;
}

/// The real guest console flood the break-it reviewer ran beside the healthy path: a guest-root
/// writer at about 128 KiB/s, past D's 64 KiB prefix and under its 1 MiB/s rate. D keeps
/// draining with flat memory and RSS, executions stay reusable, and nothing retires.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_a_real_guest_console_flood_keeps_the_drainer_flat() {
    let guest = std::env::var("KILND_B5_CONSOLE_FLOOD_GUEST")
        .ok()
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .expect("KILND_B5_CONSOLE_FLOOD_GUEST names the test guest (scripts/b5-test-guest.sh)");
    let real = Real::with_guest(NodeOptions::default(), Some(&guest)).await;
    let (runtime, context, _) = create(&real).await;
    let (boot, inner) = wait_ready(&real, &runtime, &context).await;
    let drainer = worker_pid(&real, context.allocation_id, "console")
        .expect("D runs")
        .pid;
    let rss_kib = || -> u64 {
        std::fs::read_to_string(format!("/proc/{drainer}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix("VmRSS:"))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            })
            .unwrap_or(0)
    };
    let mut samples = Vec::new();
    for round in 0..30 {
        let ran = exec(&real, &runtime, &context, &boot, &["true"], Vec::new()).await;
        let reply = ran.reply.unwrap();
        assert!(reply.reusable, "round {round}: {reply:?}");
        let memory: u64 = cgroup_file(&context, "vm/console", "memory.current")
            .trim()
            .parse()
            .unwrap();
        let cpu = usage_usec(&cgroup_file(&context, "vm/console", "cpu.stat"));
        samples.push((memory, cpu, rss_kib()));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    evidence(
        "console flood (memory bytes, cpu usec, rss KiB) per second",
        format!("{samples:?}"),
    );
    let settled = &samples[10..];
    let memory_max = settled.iter().map(|s| s.0).max().unwrap();
    let memory_min = settled.iter().map(|s| s.0).min().unwrap();
    let rss_max = settled.iter().map(|s| s.2).max().unwrap();
    let rss_min = settled.iter().map(|s| s.2).min().unwrap();
    assert!(memory_max < MIB as u64, "{samples:?}");
    assert!(memory_max - memory_min <= 256 * 1024, "{samples:?}");
    assert!(rss_max - rss_min <= 512, "{samples:?}");
    assert!(
        settled.last().unwrap().1 > settled[0].1,
        "D kept reading: {samples:?}"
    );
    assert!(matches!(
        validate(&real, &runtime, &context, &boot, &inner).await,
        ValidateReply::Ready { .. }
    ));
    removed_cleanly(&real, &runtime, &context).await;
}

/// B5 exit: timeout, the caller's disconnect and a Stop during execution each retire
/// the VM (design 5.5): reusable = false, VM stopped, no second dispatch.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_timeout_cancel_and_kill_retire_the_vm() {
    let real = Real::new(NodeOptions::default()).await;
    // Timeout: a detached descendant (setsid, double fork, inherited pipe) included.
    let (runtime, context, _) = create(&real).await;
    let (boot, _) = wait_ready(&real, &runtime, &context).await;
    let started = std::time::Instant::now();
    let ran = exec_with(
        &real,
        &runtime,
        &context,
        &boot,
        &["sh", "-c", "(setsid sh -c 'sleep 600' &) ; sleep 600"],
        Vec::new(),
        MIB,
        3,
        None,
    )
    .await;
    let reply = ran.reply.unwrap();
    evidence(
        "timeout",
        format!("{:?} after {:?}", reply, started.elapsed()),
    );
    assert_eq!(reply.finish, WireFinishFc::TimedOut);
    assert!(!reply.reusable && reply.dispatched);
    assert_eq!(reply.cleanup, ExecCleanup::VmStopped);
    assert!(vm_subtree_gone(&context));
    let ran = exec(&real, &runtime, &context, &boot, &["true"], Vec::new()).await;
    assert!(
        !ran.reply.unwrap().dispatched,
        "no successor runs in the retired boot"
    );
    removed_cleanly(&real, &runtime, &context).await;

    // The caller disconnects mid-command: the helper still retires the VM.
    let (runtime, context, _) = create(&real).await;
    let (boot, _) = wait_ready(&real, &runtime, &context).await;
    exec_with(
        &real,
        &runtime,
        &context,
        &boot,
        &["sleep", "600"],
        Vec::new(),
        MIB,
        600,
        Some(Duration::from_secs(2)),
    )
    .await;
    let end = std::time::Instant::now() + Duration::from_secs(15);
    while !vm_subtree_gone(&context) {
        assert!(
            std::time::Instant::now() < end,
            "the VM survived a disconnect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    evidence("disconnect", "the VM subtree emptied after the caller left");
    assert!(!matches!(
        inspect_reply(&real, &runtime, &context).await,
        InspectReply::PresentReady { .. }
    ));
    removed_cleanly(&real, &runtime, &context).await;

    // Stop during an execution: the execution is interrupted, never reused.
    let (runtime, context, _) = create(&real).await;
    let (boot, _) = wait_ready(&real, &runtime, &context).await;
    let generation = real.fixture.read(|view| {
        view.query_row(
            "SELECT created_generation FROM allocations WHERE allocation_id = ?1",
            [context.allocation_id.to_string()],
            |r| r.get::<_, i64>(0),
        )
    }) as u64;
    let stopper = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        raw_call(
            &real.fixture,
            context.instance_id,
            Some(epoch_of(&runtime).await),
            FirecrackerOperation::Stop {
                allocation_id: context.allocation_id,
                expected_generation: generation,
                reason: StopReason::Operator,
            },
            wire_deadline(60),
            60_000,
        )
        .await
        .unwrap()
    };
    let (ran, stopped) = tokio::join!(
        exec_with(
            &real,
            &runtime,
            &context,
            &boot,
            &["sleep", "600"],
            Vec::new(),
            MIB,
            600,
            None
        ),
        stopper
    );
    let reply = ran.reply.unwrap();
    evidence("stop during exec", format!("{reply:?} / {stopped:?}"));
    assert!(!reply.reusable);
    assert!(vm_subtree_gone(&context));
    removed_cleanly(&real, &runtime, &context).await;
}

/// B5: a dead relay or console drainer retires a real READY VM.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_a_dead_relay_or_drainer_retires_the_vm() {
    let real = Real::new(NodeOptions::default()).await;
    for mode in ["relay", "console"] {
        let (runtime, context, _) = create(&real).await;
        wait_ready(&real, &runtime, &context).await;
        let worker = worker_pid(&real, context.allocation_id, mode).expect("worker row");
        unsafe { libc::kill(worker.pid, libc::SIGKILL) };
        let end = std::time::Instant::now() + Duration::from_secs(15);
        while !vm_subtree_gone(&context) {
            assert!(
                std::time::Instant::now() < end,
                "{mode}: the VM survived its worker"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        evidence("worker death", format!("{mode}: VM retired"));
        removed_cleanly(&real, &runtime, &context).await;
    }
}

/// Two warmups and twenty measured cold boots through the real chain: create to READY
/// (the broker handshake and Initialize done) and READY to the first tool result.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_boot_timings() {
    let real = Real::new(NodeOptions::default()).await;
    let mut rows = Vec::new();
    for run in 0..22 {
        let started = std::time::Instant::now();
        let (runtime, context, _) = create(&real).await;
        // BOOTING (the VMM validated, hardened and running) apart from READY.
        let mut booting = None;
        while booting.is_none() {
            let phase = real.phase(context.allocation_id);
            if phase == "booting" || phase == "ready" {
                booting = Some(started.elapsed());
            }
            assert!(
                started.elapsed() < Duration::from_secs(120),
                "never booted: {phase}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let booting = booting.unwrap();
        let (boot, _) = wait_ready(&real, &runtime, &context).await;
        let ready = started.elapsed();
        let ran = exec(&real, &runtime, &context, &boot, &["true"], Vec::new()).await;
        let first = started.elapsed() - ready;
        assert_eq!(ran.reply.unwrap().finish, WireFinishFc::Completed);
        let kind = if run < 2 { "warmup" } else { "measured" };
        eprintln!(
            "B5 boot: {{\"run\":{run},\"kind\":\"{kind}\",\"create_booting_ms\":{},\"create_ready_ms\":{},\"first_tool_result_ms\":{}}}",
            booting.as_millis(),
            ready.as_millis(),
            first.as_millis()
        );
        rows.push((kind, ready, first));
        removed_cleanly(&real, &runtime, &context).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut ready: Vec<_> = rows
        .iter()
        .filter(|r| r.0 == "measured")
        .map(|r| r.1)
        .collect();
    ready.sort();
    let p = |q: f64| ready[((q * ready.len() as f64).ceil() as usize).max(1) - 1];
    evidence(
        "boot timings",
        format!(
            "20 measured: create-ready p50 {:?} p95 {:?} max {:?}",
            p(0.5),
            p(0.95),
            ready[19]
        ),
    );
}

// ---- hostile sources -------------------------------------------------------------------

const HOSTILE_ENV: &str = "KILND_B5_HOSTILE";

/// A test-only cgroup with the contract's relay or console limits.
struct TestCgroup(PathBuf);

impl TestCgroup {
    fn new(parent: &Path, name: &str, memory: u64, pids: u64) -> Self {
        let path = parent.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("memory.max"), memory.to_string()).unwrap();
        std::fs::write(path.join("memory.swap.max"), "0").unwrap();
        std::fs::write(path.join("pids.max"), pids.to_string()).unwrap();
        std::fs::write(path.join("cpu.max"), "5000 100000").unwrap();
        Self(path)
    }
    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.0.join(file)).unwrap()
    }
    fn memory(&self) -> u64 {
        self.read("memory.current").trim().parse().unwrap()
    }
    fn cpu(&self) -> u64 {
        usage_usec(&self.read("cpu.stat"))
    }
}

impl Drop for TestCgroup {
    fn drop(&mut self) {
        let _ = std::fs::write(self.0.join("cgroup.kill"), "1");
        for _ in 0..200 {
            if std::fs::remove_dir(&self.0).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Starts the real R or D code in `cgroup`, as an unprivileged UID, from this test
/// binary: descriptors 3 and 4 are its two sockets or pipes.
fn spawn_worker(
    role: &str,
    cgroup: &TestCgroup,
    uid: u32,
    three: OwnedFd,
    four: OwnedFd,
) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let (a, b) = (three.as_raw_fd(), four.as_raw_fd());
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "helper::firecracker::tests::broker::b5_hostile_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HOSTILE_ENV, format!("{role}:{}:{uid}", cgroup.0.display()));
    // SAFETY: only dup2 between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(three);
    drop(four);
    child
}

/// The child half: enter the cgroup, drop to the UID, run R or D on fds 3 and 4.
#[test]
#[ignore = "a child of the B5 hostile-source regression, not a test by itself"]
fn b5_hostile_child() {
    let Ok(spec) = std::env::var(HOSTILE_ENV) else {
        return;
    };
    let mut parts = spec.split(':');
    let (role, cgroup, uid) = (
        parts.next().unwrap().to_string(),
        parts.next().unwrap().to_string(),
        parts.next().unwrap().parse::<u32>().unwrap(),
    );
    std::fs::write(Path::new(&cgroup).join("cgroup.procs"), "0").unwrap();
    unsafe {
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setresgid(uid, uid, uid), 0);
        assert_eq!(libc::setresuid(uid, uid, uid), 0);
    }
    assert_eq!(crate::sys::prctl::set_no_new_privs(), 0);
    // SAFETY: the parent placed these two descriptors.
    let (three, four) = unsafe { (OwnedFd::from_raw_fd(3), OwnedFd::from_raw_fd(4)) };
    match role.as_str() {
        "relay" => relay::relay_main(
            std::os::unix::net::UnixStream::from(three),
            std::os::unix::net::UnixDatagram::from(four),
        ),
        _ => super::super::console::drainer_main(three, four),
    }
}

fn hostile_expected() -> Expected {
    let spec = kilnd_broker_protocol::message::GuestExecSpec {
        image: "alpine".into(),
        memory_bytes: 1,
        cpu_millis: 1,
        pids: 1,
        disk_bytes: 1,
        network: "none".into(),
        read_only_root: false,
        writable_paths: vec![],
    };
    Expected {
        binding: SessionBinding {
            instance_id: kilnd_broker_protocol::Id128([1; 16]),
            allocation_id: kilnd_broker_protocol::Id128([2; 16]),
            sandbox_id: kilnd_broker_protocol::SandboxId::new("sb-0123456789abcdef").unwrap(),
            boot_nonce: kilnd_broker_protocol::Hex32([3; 32]),
            manifest_sha256: kilnd_broker_protocol::Hex32([4; 32]),
            launch_sha256: kilnd_broker_protocol::Hex32([5; 32]),
            guest_exec_spec_sha256: spec.sha256(),
        },
        work_uuid: kilnd_broker_protocol::WorkUuid::new("51b8e65e-23b9-4eba-a21c-7c1cce2c5f94")
            .unwrap(),
        broker_sha256: kilnd_broker_protocol::Hex32([7; 32]),
        boot_id: None,
        inner_id: None,
    }
}

/// A hostile "VMM and guest" on one end of a socket pair: an endless stream of valid
/// empty output frames after a valid handshake, or total silence.
async fn hostile_peer(stream: std::os::unix::net::UnixStream, endless: bool) {
    use kilnd_broker_protocol::Direction;
    use kilnd_broker_protocol::budget::HostBudget;
    use kilnd_broker_protocol::exchange::{GuestConnection, GuestEvent};
    use kilnd_broker_protocol::message::*;
    use kilnd_broker_protocol::stream::{Due, FrameReader, FrameWriter};
    stream.set_nonblocking(true).unwrap();
    let stream = UnixStream::from_std(stream).unwrap();
    if !endless {
        // Never reads, never writes: the relay's CONNECT stage must end it.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
        return;
    }
    let (mut read, mut write) = stream.into_split();
    let mut line = Vec::new();
    while !line.ends_with(b"\n") {
        let mut b = [0u8; 1];
        if read.read(&mut b).await.unwrap_or(0) == 0 {
            return;
        }
        line.push(b[0]);
    }
    let _ = write.write_all(b"OK 1\n").await;
    let far = Instant::now() + Duration::from_secs(600);
    let mut reader = FrameReader::new(read, Direction::HostToGuest);
    let mut writer = FrameWriter::new(write, Direction::GuestToHost);
    let mut conn = GuestConnection::default();
    let mut budget = HostBudget::default();
    let Ok(Some(frame)) = reader.read_frame(Due::By(far), &mut budget).await else {
        return;
    };
    let id = frame.request_id();
    let Ok(GuestEvent::Hello(hello)) = conn.received(frame) else {
        return;
    };
    let expected = hostile_expected();
    let identity = GuestIdentity {
        instance_id: expected.binding.instance_id,
        allocation_id: expected.binding.allocation_id,
        sandbox_id: expected.binding.sandbox_id.clone(),
        boot_nonce: expected.binding.boot_nonce,
        manifest_sha256: expected.binding.manifest_sha256,
        launch_sha256: expected.binding.launch_sha256,
        work_uuid: expected.work_uuid.clone(),
        guest_exec_spec_sha256: expected.binding.guest_exec_spec_sha256,
    };
    let reply = HelloReply {
        protocol: 1,
        challenge: hello.challenge,
        identity,
        boot_id: kilnd_broker_protocol::BootId::new("0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6")
            .unwrap(),
        broker_sha256: kilnd_broker_protocol::Hex32([7; 32]),
        kiln: KilnFacts {
            protocol: 1,
            features: 0x1f,
        },
        hardening: kilnd_broker_protocol::identity::hardening_from_mask(0x7f),
        work: WorkMount {
            uuid: expected.work_uuid.clone(),
            nosuid: true,
            nodev: true,
            noexec: true,
            prjquota: true,
        },
        state: BrokerState::Idle,
        inner_id: None,
    };
    if writer
        .send(id, &Message::HelloReply(Box::new(reply)), far)
        .await
        .is_err()
    {
        return;
    }
    let Ok(Some(frame)) = reader.read_frame(Due::By(far), &mut budget).await else {
        return;
    };
    let Ok(GuestEvent::Exec(exec)) = conn.received(frame) else {
        return;
    };
    let token = exec.token;
    if writer
        .send(token, &Message::Accepted(Accepted { token }), far)
        .await
        .is_err()
    {
        return;
    }
    // Endless, otherwise valid, empty frames.
    while writer
        .send(token, &Message::Stdout(Vec::new()), far)
        .await
        .is_ok()
    {}
}

struct HostileRelay {
    child: std::process::Child,
    control: super::super::workers::Endpoint,
    fds: std::os::unix::net::UnixDatagram,
    endless: bool,
    next: u64,
    refused: u32,
}

impl HostileRelay {
    fn submit(&mut self) {
        self.next += 1;
        let (relay_end, peer_end) = std::os::unix::net::UnixStream::pair().unwrap();
        tokio::spawn(hostile_peer(peer_end, self.endless));
        let mut stdio = Vec::new();
        let mut keep = Vec::new();
        for _ in 0..3 {
            let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
            stdio.push(a);
            keep.push(b);
        }
        // Empty stdin: the kilnd end closes at once.
        drop(keep.remove(0));
        let mut fds = vec![relay_end.as_raw_fd()];
        fds.extend(stdio.iter().map(|s| s.as_raw_fd()));
        relay::send_fds(&self.fds, self.next, &fds).unwrap();
        let job = RelayJob::Exec {
            job: self.next,
            expected: hostile_expected(),
            exec: Exec {
                token: kilnd_broker_protocol::Id128([9; 16]),
                execution_id: kilnd_broker_protocol::ExecutionId::new("ex-0123456789abcdef")
                    .unwrap(),
                argv: vec!["x".into()],
                stdin_bytes: 0,
                max_output: 1024,
                remaining_ms: 1,
            },
            deadline_ns: super::super::workers::monotonic_ns() + 30_000_000_000,
        };
        self.control.send(0, &job, Duration::from_secs(1)).unwrap();
    }

    /// Collects reports; every finished job counts as one retired offender, and the
    /// next starts at once, so the attack never pauses.
    fn pump(&mut self) {
        while let Ok(super::super::workers::Received::Message { body, .. }) =
            self.control.receive::<RelayReport>(Duration::ZERO)
        {
            if body.is_final() {
                assert!(
                    matches!(body, RelayReport::Failed { .. }),
                    "a hostile job must fail: {body:?}"
                );
                self.refused += 1;
                self.submit();
            }
        }
    }
}

fn helper_rss_kib(real: &Real) -> u64 {
    let pid = real.fixture.helper_pid();
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok())
        .unwrap_or(0)
}

/// B5 exit: three concurrent hostile transport and console sources (an endless valid
/// frame stream, a silent never-reading peer, a serial flood) leave memory flat and
/// each offender is ended at its bound, while a healthy fourth allocation's Inspect,
/// Validate, Exec and Remove meet their deadlines.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/b4-vm-tests.sh"]
async fn b5_linux_root_hostile_sources_leave_memory_flat_and_a_healthy_fourth_meets_deadlines() {
    let real = Real::new(NodeOptions::default()).await;
    let (runtime, context, _) = create(&real).await;
    let (boot, inner) = wait_ready(&real, &runtime, &context).await;
    let mut hostile = HostileSources::start(&real).await;
    // The healthy fourth, under attack. Each operation against its own deadline.
    let healthy = async {
        let mut timings = Vec::new();
        for _ in 0..5 {
            let t = std::time::Instant::now();
            assert!(matches!(
                inspect_reply(&real, &runtime, &context).await,
                InspectReply::PresentReady { .. }
            ));
            timings.push(("inspect", t.elapsed(), Duration::from_secs(5)));
            let t = std::time::Instant::now();
            assert!(matches!(
                validate(&real, &runtime, &context, &boot, &inner).await,
                ValidateReply::Ready { .. }
            ));
            timings.push(("validate", t.elapsed(), Duration::from_secs(5)));
            let t = std::time::Instant::now();
            let ran = exec(
                &real,
                &runtime,
                &context,
                &boot,
                &["echo", "healthy"],
                Vec::new(),
            )
            .await;
            assert_eq!(ran.stdout, b"healthy\n");
            timings.push(("exec", t.elapsed(), Duration::from_secs(60)));
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let t = std::time::Instant::now();
        removed_cleanly(&real, &runtime, &context).await;
        timings.push(("remove", t.elapsed(), Duration::from_secs(60)));
        timings
    };
    let timings = hostile.beside(healthy).await;
    hostile.finish(&real, &timings, &["inspect", "validate", "exec", "remove"]);
}

/// B5's three simultaneous hostile sources, each in its own capped cgroup under its own
/// UID: a relay fed endless valid frames, a relay whose peer never sends, and a 64 KiB
/// write console flood into a real drainer. B6 runs them beside real lifecycle requests.
pub(super) struct HostileSources {
    relays: Vec<HostileRelay>,
    drainer: std::process::Child,
    report_read: OwnedFd,
    flooded: Arc<std::sync::atomic::AtomicU64>,
    stop_flood: Arc<std::sync::atomic::AtomicBool>,
    flood: Option<std::thread::JoinHandle<()>>,
    cgroups: Option<[TestCgroup; 3]>,
    memory_before: [u64; 3],
    cpu_before: [u64; 3],
    helper_before: u64,
    flood_before: u64,
    parent_guard: Option<DirGuard>,
}

impl HostileSources {
    /// Starts all three and warms them up, then takes the baseline.
    pub(super) async fn start(real: &Real) -> Self {
        // The isolated hostile tree, with the contract's relay and console limits.
        let parent = PathBuf::from(format!(
            "/sys/fs/cgroup/kilnd-b5-hostile-{}",
            Id128::random()
        ));
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("cgroup.subtree_control"), "+memory +pids +cpu").unwrap();
        let parent_guard = scopeguard_dir(parent.clone());
        let relay_a = TestCgroup::new(&parent, "relay-endless", 16 << 20, 4);
        let relay_b = TestCgroup::new(&parent, "relay-silent", 16 << 20, 4);
        let console = TestCgroup::new(&parent, "console-flood", 4 << 20, 2);
        let mut relays = Vec::new();
        for (cgroup, endless, uid) in [(&relay_a, true, 300_990), (&relay_b, false, 300_991)] {
            let (control_s, control_r) = std::os::unix::net::UnixStream::pair().unwrap();
            let (fds_s, fds_r) = std::os::unix::net::UnixDatagram::pair().unwrap();
            let child = spawn_worker("relay", cgroup, uid, control_r.into(), fds_r.into());
            let mut hostile = HostileRelay {
                child,
                control: super::super::workers::Endpoint::new(control_s),
                fds: fds_s,
                endless,
                next: 0,
                refused: 0,
            };
            hostile.submit();
            relays.push(hostile);
        }
        let mut pipe = [0; 2];
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) };
        let mut report = [0; 2];
        unsafe { libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        let (console_read, console_write) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let (report_read, report_write) = unsafe {
            (
                OwnedFd::from_raw_fd(report[0]),
                OwnedFd::from_raw_fd(report[1]),
            )
        };
        let drainer = spawn_worker("drainer", &console, 300_992, console_read, report_write);
        let flooded = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stop_flood = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flood = {
            let flooded = flooded.clone();
            let stop = stop_flood.clone();
            std::thread::spawn(move || {
                let chunk = vec![b'#'; 64 * 1024];
                let mut file = std::fs::File::from(console_write);
                use std::io::Write;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if file.write_all(&chunk).is_err() {
                        return;
                    }
                    flooded.fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };
        // Warm up, then take the baseline.
        for _ in 0..40 {
            for relay in relays.iter_mut() {
                relay.pump();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let memory_before = [relay_a.memory(), relay_b.memory(), console.memory()];
        let cpu_before = [relay_a.cpu(), relay_b.cpu(), console.cpu()];
        Self {
            relays,
            drainer,
            report_read,
            flood_before: flooded.load(std::sync::atomic::Ordering::Relaxed),
            flooded,
            stop_flood,
            flood: Some(flood),
            cgroups: Some([relay_a, relay_b, console]),
            memory_before,
            cpu_before,
            helper_before: helper_rss_kib(real),
            parent_guard: Some(parent_guard),
        }
    }

    /// Runs `work` while the hostile relays keep being fed.
    pub(super) async fn beside<T>(&mut self, work: impl std::future::Future<Output = T>) -> T {
        let relays = &mut self.relays;
        let pump = async {
            loop {
                for relay in relays.iter_mut() {
                    relay.pump();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::select! {
            done = work => done,
            _ = pump => unreachable!(),
        }
    }

    /// Checks every operation met its deadline, memory stayed flat, CPU was charged to
    /// the hostile cgroups, each offender ended at its bound and the console drained.
    pub(super) fn finish(
        mut self,
        real: &Real,
        timings: &[(&'static str, Duration, Duration)],
        names: &[&str],
    ) {
        for relay in self.relays.iter_mut() {
            relay.pump();
        }
        let [relay_a, relay_b, console] = self.cgroups.take().unwrap();
        let memory_after = [relay_a.memory(), relay_b.memory(), console.memory()];
        let helper_after = helper_rss_kib(real);
        let flood_after = self.flooded.load(std::sync::atomic::Ordering::Relaxed);
        let cpu_after = [relay_a.cpu(), relay_b.cpu(), console.cpu()];
        let (memory_before, cpu_before, helper_before, flood_before) = (
            self.memory_before,
            self.cpu_before,
            self.helper_before,
            self.flood_before,
        );
        for (name, took, limit) in timings {
            assert!(took < limit, "{name} took {took:?} against {limit:?}");
        }
        let worst: Vec<_> = names
            .iter()
            .map(|n| {
                let max = timings
                    .iter()
                    .filter(|t| t.0 == *n)
                    .map(|t| t.1)
                    .max()
                    .unwrap();
                format!("{n} max {max:?}")
            })
            .collect();
        evidence("healthy fourth under attack", worst.join(", "));
        evidence(
            "hostile memory",
            format!(
                "before {memory_before:?} after {memory_after:?} bytes; helper RSS {helper_before} -> {helper_after} KiB"
            ),
        );
        for (before, after) in memory_before.iter().zip(memory_after) {
            assert!(
                after <= before + (2 << 20),
                "a hostile source grew: {before} -> {after}"
            );
        }
        assert!(
            helper_after <= helper_before + 8 * 1024,
            "H grew: {helper_before} -> {helper_after} KiB"
        );
        evidence(
            "hostile cpu (usec, charged to their own cgroups)",
            format!("{cpu_before:?} -> {cpu_after:?}"),
        );
        assert!(cpu_after.iter().zip(cpu_before).all(|(a, b)| *a > b));
        // Every offender was ended at its bound, again and again.
        evidence(
            "offenders ended",
            format!(
                "endless frames {} jobs, silent peer {} jobs",
                self.relays[0].refused, self.relays[1].refused
            ),
        );
        assert!(self.relays[0].refused >= 5 && self.relays[1].refused >= 2);
        // The console was drained after its prefix, far past 64 KiB, and the flood was
        // reported once.
        let mut byte = [0u8; 1];
        let reported =
            unsafe { libc::read(self.report_read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        evidence(
            "console flood",
            format!(
                "{} bytes drained during the healthy run; report {:?}",
                flood_after - flood_before,
                (reported, byte[0] as char)
            ),
        );
        assert_eq!((reported, byte[0]), (1, b'R'));
        assert!(flood_after - flood_before > 1 << 20);
        drop((relay_a, relay_b, console));
    }
}

impl Drop for HostileSources {
    fn drop(&mut self) {
        self.stop_flood
            .store(true, std::sync::atomic::Ordering::Relaxed);
        for relay in self.relays.iter_mut() {
            let _ = relay.child.kill();
            let _ = relay.child.wait();
        }
        let _ = self.drainer.kill();
        let _ = self.drainer.wait();
        // The flood thread's writes fail once the drainer's read end is gone.
        if let Some(flood) = self.flood.take() {
            let _ = flood.join();
        }
        drop(self.cgroups.take());
        drop(self.parent_guard.take());
    }
}

/// Removes a test cgroup directory when dropped.
struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        for _ in 0..200 {
            if std::fs::remove_dir(&self.0).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn scopeguard_dir(path: PathBuf) -> DirGuard {
    DirGuard(path)
}

/// B7 on the real chain (design 16.6, `b7_linux_root_compaction_cycles`): real sessions
/// (boot to READY, one execution, Remove to ABSENT) against a 64-entry fence allowance,
/// `max_enrolled_instances` 1 (so the one instance's share is all 47 admitted entries)
/// and a 3-minute lease on the real boot clock. 300 sessions cross the old count limit
/// about five times and many compaction cycles; retained rows never exceed the share,
/// and every session's rows are eventually compacted. `KILND_B7_CYCLES` overrides the
/// count for a shorter run.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b7_linux_root_compaction_cycles() {
    use super::super::journal::{CompactionPolicy, FENCE_ENTRY_BOUND};
    let sessions: usize = std::env::var("KILND_B7_CYCLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let real = Arc::new(
        Real::new(NodeOptions {
            fence_allowance_bytes: Some(64 * FENCE_ENTRY_BOUND),
            max_enrolled: 1,
            compaction: CompactionPolicy {
                lease_ms: 180_000,
                pass_ms: 30_000,
            },
            compaction_tick_ms: 1_000,
            ..NodeOptions::default()
        })
        .await,
    );
    let instance = Id128::random();
    let runtime = real.fixture.runtime(instance, instance);
    let started = std::time::Instant::now();
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let refused = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut lanes = Vec::new();
    for lane in 0..3usize {
        let (real, runtime, done, refused, peak) = (
            real.clone(),
            runtime.clone(),
            done.clone(),
            refused.clone(),
            peak.clone(),
        );
        lanes.push(tokio::spawn(async move {
            loop {
                if done.load(std::sync::atomic::Ordering::SeqCst) >= sessions {
                    return;
                }
                // Headroom fills to the share while a lease matures: an honest daemon
                // waits and tries again. A full preparation slot is the same.
                let plan = match runtime
                    .prepare(&prep(instance), &spec(), deadline(20), &no_cancel())
                    .await
                {
                    Ok(plan) => plan,
                    Err(error) => {
                        let text = error.to_string();
                        assert!(
                            text.contains("headroom") || text.contains("preparation slot"),
                            "lane {lane}: {text}"
                        );
                        refused.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };
                let context = CreateContext {
                    instance_id: instance,
                    allocation_id: plan.allocation_id().unwrap(),
                    sandbox_id: {
                        let document: Value = serde_json::from_slice(plan.backend_plan()).unwrap();
                        document["substitutions"]["sandbox_id"].as_str().unwrap().into()
                    },
                };
                match raw_create(&real.fixture, &context, epoch_of(&runtime).await, &plan).await {
                    CreateReply::Accepted { .. } => {}
                    other => {
                        // A capacity race between lanes is a post-C1 refusal: fenced.
                        assert_eq!(class_of(&other), AmbiguousClass::Capacity, "{other:?}");
                        runtime
                            .fence_absent(&context, &plan.plan_digest(), deadline(30), &no_cancel())
                            .await
                            .unwrap();
                        refused.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        continue;
                    }
                }
                let (boot, _) = wait_ready(&real, &runtime, &context).await;
                let ran = exec(&real, &runtime, &context, &boot, &["/bin/echo", "cycle"], vec![]).await;
                assert_eq!(ran.stdout, b"cycle\n", "{:?}", ran.reply);
                let mut reply = super::lifecycle::remove(&real, &runtime, &context).await;
                for _ in 0..5 {
                    if matches!(reply, FenceReply::Absent { .. }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    reply = super::lifecycle::remove(&real, &runtime, &context).await;
                }
                assert!(matches!(reply, FenceReply::Absent { .. }), "{reply:?}");
                let snapshot = runtime.node_accounting(deadline(5), &no_cancel()).await.unwrap();
                let tokens = snapshot.tokens.unwrap();
                assert!(tokens.retained_admitted <= snapshot.share, "{tokens:?}");
                peak.fetch_max(tokens.retained_admitted, std::sync::atomic::Ordering::SeqCst);
                let finished = done.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if finished % 25 == 0 {
                    eprintln!(
                        "B7 real chain: {finished} sessions, W {} of {}, retained {} in {:?}",
                        tokens.watermark,
                        tokens.issue_next,
                        tokens.retained_admitted,
                        started.elapsed()
                    );
                }
            }
        }));
    }
    for lane in lanes {
        lane.await.unwrap();
    }
    let tokens = runtime
        .node_accounting(deadline(5), &no_cancel())
        .await
        .unwrap()
        .tokens
        .unwrap();
    let entries = 64;
    assert!(done.load(std::sync::atomic::Ordering::SeqCst) >= sessions);
    assert!(tokens.issue_next as usize > sessions);
    assert!(tokens.watermark > 1, "compaction cycled: {tokens:?}");
    let compactions: i64 = real.fixture.count("SELECT COUNT(*) FROM compaction_log");
    eprintln!(
        "B7 evidence: {} real sessions ({}x the {entries}-entry allowance) in {:?}; {} refusals retried; retained peak {} of 47; W {} of {}; {compactions} compaction records kept",
        sessions,
        sessions / entries,
        started.elapsed(),
        refused.load(std::sync::atomic::Ordering::SeqCst),
        peak.load(std::sync::atomic::Ordering::SeqCst),
        tokens.watermark,
        tokens.issue_next
    );
    eprintln!(
        "B6 matrix: {}",
        json!({"scenario": "b7_linux_root_compaction_cycles", "passed": true, "outcome": {
            "sessions": sessions, "retained_peak": peak.load(std::sync::atomic::Ordering::SeqCst),
            "watermark": tokens.watermark, "issue_next": tokens.issue_next
        }})
    );
}
