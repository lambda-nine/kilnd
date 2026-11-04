//! B6 milestone 2: section 10's attacks and the global-ledger crash matrix on the real
//! chain, through real daemons and `kilndctl` (the isolated test deployment of
//! `deploy/firecracker-test/`, as in `session.rs`). `scripts/firecracker-crash-matrix.py`
//! runs the `b6_linux_root_crash_` tests and `scripts/firecracker-regressions.py` the
//! `b6_linux_root_attack_` ones; each test prints one `B6 matrix:` JSON line that the
//! scripts collect, and writes its transcript to `KILND_B6_EVIDENCE` when set.
//!
//! Every scenario ends the same way: no reservation is freed while a VM, disk or worker
//! may still exist, only a matching ABSENT receipt releases a row, and nothing is left on
//! the host.
use super::broker::HostileSources;
use super::lifecycle::host_leftovers;
use super::session::{
    Daemon, Deployment, SECOND, Transcript, checked, dump, node_sandboxes, output, write_evidence,
};
use super::*;

/// Byte copies of daemon state; scripts/b4-vm-cleanup.py removes this too.
const COPIES: &str = "/var/lib/kilnd-b6-copies";

/// One scenario's outcome, for the scripts' matrix.
fn matrix(scenario: &str, outcome: Value) {
    eprintln!(
        "B6 matrix: {}",
        json!({"scenario": scenario, "passed": true, "outcome": outcome})
    );
}

fn copies(name: &str) -> PathBuf {
    let root = Path::new(COPIES);
    std::fs::create_dir_all(root).unwrap();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    root.join(name)
}

/// A READY session through `kilndctl create`: its sandbox ID and allocation.
fn ready_session(daemon: &Daemon, transcript: &mut Transcript) -> (String, Id128) {
    let created = daemon.kilndctl(transcript, &["create", "--net", "none"], None);
    assert_eq!(created.code, 0, "{}", created.stderr);
    let id = created.stdout.trim().to_string();
    assert!(id.starts_with("sb-"), "{id}");
    let allocation = Id128::parse(&daemon.row(&id, "allocation_id").unwrap()).unwrap();
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("ready"));
    (id, allocation)
}

fn context(daemon: &Daemon, id: &str, allocation: Id128) -> CreateContext {
    CreateContext {
        instance_id: daemon.instance,
        allocation_id: allocation,
        sandbox_id: id.into(),
    }
}

/// The release standard: the helper's phase is ABSENT with its claim released and its
/// receipt retired, the row is terminal with exactly that receipt, and nothing owned
/// remains on the host.
fn assert_released(
    deployment: &Deployment,
    daemon: &Daemon,
    id: &str,
    allocation: Id128,
    terminal: &str,
) -> Value {
    let real = &deployment.real;
    assert_eq!(real.phase(allocation), "absent");
    let (released, retired): (Option<i64>, String) = real.fixture.read(|v| {
        Ok((
            v.query_row(
                "SELECT released_generation FROM capacity_claims WHERE allocation_id = ?1",
                [allocation.to_string()],
                |r| r.get(0),
            )?,
            v.query_row(
                "SELECT receipt_id FROM retired_tokens WHERE allocation_id = ?1",
                [allocation.to_string()],
                |r| r.get(0),
            )?,
        ))
    });
    assert!(released.is_some(), "the node claim is released");
    assert_eq!(daemon.row(id, "state").as_deref(), Some(terminal));
    assert_eq!(
        daemon.row(id, "release_evidence_id").as_deref(),
        Some(retired.as_str()),
        "the row is released by exactly the helper's receipt"
    );
    let vmm = real.vmm(allocation);
    let left = host_leftovers(real, &context(daemon, id, allocation), vmm);
    assert!(left.is_empty(), "left behind: {left:?}");
    json!({"phase": "absent", "claim_released_generation": released, "receipt": retired, "row": terminal})
}

/// How a refused Create ended: refused at C0 with no row at all, or refused after C1 and
/// released only by its token's fence. Anything else (a charged or ready row) fails.
fn refusal(daemon: &Daemon, known: &[String]) -> Value {
    let rows: Vec<String> = daemon
        .sandbox_ids()
        .into_iter()
        .filter(|id| !known.contains(id))
        .collect();
    match rows.as_slice() {
        [] => json!("refused at C0: no row, no reservation"),
        [id] => {
            assert_eq!(daemon.row(id, "state").as_deref(), Some("failed"));
            let receipt = daemon
                .row(id, "release_evidence_id")
                .expect("a post-C1 refusal is released only by its fence");
            json!({"refused_after_c1": id, "fence": receipt})
        }
        more => panic!("one refused Create left {more:?}"),
    }
}

/// Whether the row is still charged: no release evidence.
fn charged(daemon: &Daemon, id: &str) -> bool {
    daemon.row(id, "release_evidence_id").is_none()
}

fn unreleased_claim(deployment: &Deployment, allocation: Id128) -> bool {
    deployment.real.fixture.read(|v| {
        v.query_row(
            "SELECT COUNT(*) FROM capacity_claims WHERE allocation_id = ?1 AND released_generation IS NULL",
            [allocation.to_string()],
            |r| r.get::<_, i64>(0),
        )
    }) == 1
}

fn executions(daemon: &Daemon, id: &str) -> Value {
    dump(
        &daemon.view(),
        "SELECT id, argv, state, exit_code, failure_reason, sandbox_reusable, cleanup_evidence
         FROM executions WHERE sandbox_id = ?1 ORDER BY started_at_ms",
        &[&id],
    )
}

fn finish(name: &str, transcript: &Transcript, deployment: &Deployment) {
    write_evidence(&format!("{name}.txt"), &transcript.text);
    let logs: Vec<String> = deployment
        .daemons
        .iter()
        .map(|d| std::fs::read_to_string(&d.log).unwrap_or_default())
        .collect();
    write_evidence(&format!("{name}.kilnd.log"), &logs.join("\n"));
    write_evidence(
        &format!("{name}.helper.log"),
        &deployment.real.fixture.log(),
    );
}

/// Daemon death while its VM boots. The VM keeps booting under the helper; the restarted
/// daemon adopts exactly that READY boot (C6), and no second VM exists.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_daemon_death_while_booting_adopts_only_the_same_boot() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(&deployment.real).await;
    let create = daemon.kilndctl_background(&["create", "--net", "none"]);
    let allocation = deployment
        .wait_allocation(daemon.instance, &["booting", "spawn_intent"], 60)
        .await;
    daemon.kill().await;
    let (text, interrupted) = create.join().unwrap();
    transcript.text.push_str(&text);
    assert_ne!(interrupted.code, 0, "the caller lost its daemon");
    transcript
        .text
        .push_str("# kilnd SIGKILLed while the VM booted\n\n");
    let ids = daemon.sandbox_ids();
    assert_eq!(ids.len(), 1);
    let id = ids[0].clone();
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("creating"));
    deployment.wait_phase(allocation, &["ready"], 60).await;
    daemon.start(&deployment.image);
    daemon.wait_serving(&deployment.real).await;
    let got = daemon.kilndctl(&mut transcript, &["get", &id], None);
    assert!(got.stdout.contains("state:      ready"), "{}", got.stdout);
    let ran = daemon.kilndctl(
        &mut transcript,
        &["exec", &id, "--", "echo", "adopted"],
        None,
    );
    assert_eq!((ran.code, ran.stdout.as_str()), (0, "adopted\n"));
    assert_eq!(
        deployment.allocations(daemon.instance).len(),
        1,
        "no second VM for one sandbox"
    );
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("crash-daemon-death-while-booting", &transcript, &deployment);
    matrix(
        "daemon death while booting",
        json!({"row_after_restart": "ready (adopted the same boot)", "allocations": 1, "release": released}),
    );
}

/// Daemon death mid-execution. Its connection's EOF interrupts the command, so the helper
/// retires the VM; the restarted daemon publishes the execution interrupted and the
/// sandbox stopped, never replays the command, and Delete releases it.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_daemon_death_mid_execution_interrupts_without_replay() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(&deployment.real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    let marker = "/root/ran-once";
    let exec = daemon.kilndctl_background(&[
        "exec",
        &id,
        "--",
        "sh",
        "-c",
        &format!("echo x >> {marker}; sleep 60"),
    ]);
    deployment.wait_phase(allocation, &["busy"], 30).await;
    daemon.kill().await;
    let (text, ran) = exec.join().unwrap();
    transcript.text.push_str(&text);
    assert_ne!(ran.code, 0);
    transcript
        .text
        .push_str("# kilnd SIGKILLed during the execution\n\n");
    // The disconnect is an interruption: the helper stops the VM by itself.
    deployment
        .wait_phase(allocation, &["stop_intent", "stopped", "cleaning"], 30)
        .await;
    assert!(unreleased_claim(&deployment, allocation));
    daemon.start(&deployment.image);
    daemon.wait_serving(&deployment.real).await;
    let state = daemon.row(&id, "state").unwrap();
    assert!(
        state == "lost" || state == "quarantined",
        "a retired session is never READY again: {state}"
    );
    let rows = executions(daemon, &id);
    let last = rows
        .as_array()
        .unwrap()
        .last()
        .unwrap_or_else(|| {
            panic!(
                "no execution row; sandbox {}",
                dump(&daemon.view(), "SELECT * FROM sandboxes", &[])
            )
        })
        .clone();
    assert_ne!(last["state"], json!("running"), "{last}");
    assert_eq!(last["sandbox_reusable"], json!(0), "{last}");
    let refused = daemon.kilndctl(&mut transcript, &["exec", &id, "--", "true"], None);
    assert_ne!(refused.code, 0, "no successor runs in the old boot");
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    assert!(charged(daemon, &id));
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("crash-daemon-death-mid-execution", &transcript, &deployment);
    matrix(
        "daemon death mid-execution",
        json!({"row_after_restart": state, "execution": last, "release": released}),
    );
}

/// Daemon death after C1 and before C2. The restarted daemon fences the exact token (it
/// was never admitted) and releases the row; the Create still held inside the helper then
/// finds the fence and allocates nothing.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_daemon_death_before_c2_fences_and_a_late_create_cannot_resurrect() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let hold = format!("H.create.enter.{}", daemon.instance);
    real.fixture.fault(&format!("{hold}.hold"));
    let create = daemon.kilndctl_background(&["create", "--net", "none"]);
    real.fixture.wait_reached(&hold).await;
    daemon.kill().await;
    let (text, _) = create.join().unwrap();
    transcript.text.push_str(&text);
    transcript
        .text
        .push_str("# kilnd SIGKILLed after C1, with its Create held before C2\n\n");
    let id = daemon.sandbox_ids()[0].clone();
    let allocation = Id128::parse(&daemon.row(&id, "allocation_id").unwrap()).unwrap();
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("creating"));
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    // Reconciliation fenced the never-admitted token and released the row.
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("failed"));
    let evidence_id = daemon
        .row(&id, "release_evidence_id")
        .expect("released only by the token's fence");
    // The late Create now proceeds and must find the fence.
    real.fixture.clear(&format!("{hold}.hold"));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        deployment.allocations(daemon.instance).is_empty(),
        "a late Create after the fence allocated something"
    );
    assert_eq!(deployment.claims(), 0);
    let retired: String = real.fixture.read(|v| {
        v.query_row(
            "SELECT receipt_id FROM retired_tokens WHERE allocation_id = ?1",
            [allocation.to_string()],
            |r| r.get(0),
        )
    });
    assert_eq!(retired, evidence_id);
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    finish("crash-daemon-death-before-c2", &transcript, &deployment);
    matrix(
        "daemon death after C1, before C2; late Create",
        json!({"row": "failed, released by the never-admitted fence", "late_create_allocated": false, "claims": 0}),
    );
}

/// ABSENT commits, then the daemon dies before its terminal transaction. The helper's claim
/// is already released; the daemon stays charged until its restart replays the receipt.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_absent_committed_but_publication_lost_replays_the_receipt() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    let hold = format!("H.fence.after_commit.{allocation}");
    real.fixture.fault(&format!("{hold}.hold"));
    let remove = daemon.kilndctl_background(&["rm", &id]);
    real.fixture.wait_reached(&hold).await;
    assert_eq!(real.phase(allocation), "absent");
    assert!(!unreleased_claim(&deployment, allocation));
    assert!(charged(daemon, &id), "the daemon has not published yet");
    daemon.kill().await;
    real.fixture.clear(&format!("{hold}.hold"));
    let (text, _) = remove.join().unwrap();
    transcript.text.push_str(&text);
    transcript
        .text
        .push_str("# kilnd SIGKILLed after ABSENT committed, before its own terminal write\n\n");
    let state = daemon.row(&id, "state").unwrap();
    assert_eq!(state, "deleting");
    assert!(
        charged(daemon, &id),
        "still charged without its own receipt"
    );
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    finish("crash-absent-publication-lost", &transcript, &deployment);
    matrix(
        "ABSENT committed, daemon publication lost",
        json!({"before_restart": "deleting, charged", "release": released}),
    );
}

/// The ABSENT transaction's sync fails. Nothing is released anywhere; the row stays
/// DELETING and charged, and a later Delete finishes the fence.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_absent_sync_failure_stays_charged_until_retried() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    real.fixture.fault("L.fence.sync_fail");
    let failed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_ne!(failed.code, 0, "no success without a durable ABSENT");
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("deleting"));
    assert!(charged(daemon, &id));
    assert!(unreleased_claim(&deployment, allocation));
    assert_ne!(real.phase(allocation), "absent");
    real.fixture.clear("L.fence.sync_fail");
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("crash-absent-sync-failure", &transcript, &deployment);
    matrix(
        "ABSENT sync fails",
        json!({"first_delete": "error, deleting and charged on both ledgers", "release": released}),
    );
}

/// L dies right after committing a capacity claim, so its reply is lost. The claim
/// survives L's death and the helper's restart as exactly one claim, never a second; the
/// row is charged until the token's removal proves it absent.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_capacity_commit_reply_lost_keeps_one_claim() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    real.fixture.fault("L.admit.after_commit.panic");
    let created = daemon.kilndctl(&mut transcript, &["create", "--net", "none"], None);
    assert_ne!(created.code, 0, "no READY without the reply");
    real.fixture.clear("L.admit.after_commit.panic");
    let id = daemon.sandbox_ids()[0].clone();
    let allocation = Id128::parse(&daemon.row(&id, "allocation_id").unwrap()).unwrap();
    assert!(charged(daemon, &id), "an ambiguous create stays charged");
    assert!(
        unreleased_claim(&deployment, allocation),
        "the claim committed"
    );
    assert_eq!(deployment.claims(), 1);
    transcript
        .text
        .push_str("# the helper restarts on the same ledger\n\n");
    deployment.restart_helper().await;
    assert_eq!(
        deployment.claims(),
        1,
        "the restarted helper replays the one claim"
    );
    daemon.wait_serving(real).await;
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(
        removed.code,
        0,
        "{}\n{}",
        removed.stderr,
        real.fixture.log()
    );
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    assert_eq!(deployment.claims(), 0);
    finish("crash-capacity-reply-lost", &transcript, &deployment);
    matrix(
        "capacity commit, reply lost (L dies after commit)",
        json!({"claims_after_helper_restart": 1, "release": released}),
    );
}

/// The helper restarts under a READY session. Its supervisor stops the VM on H's death,
/// the new helper replays every claim, and the daemon reattaches; the session is never
/// READY again, and Delete releases it only with ABSENT.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_helper_restart_keeps_every_claim() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    let ran = daemon.kilndctl(&mut transcript, &["exec", &id, "--", "true"], None);
    assert_eq!(ran.code, 0);
    transcript
        .text
        .push_str("# the helper (H) is killed and restarted on the same ledger\n\n");
    let vmm = deployment
        .real
        .vmm(allocation)
        .expect("a VMM was journaled");
    deployment.restart_helper().await;
    assert_eq!(deployment.claims(), 1);
    // The new helper replays the claim and adopts the old supervisor as an orphan; the
    // journal keeps its phase. Whatever the old VM's state, it is never reused.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let vmm_alive = Path::new(&format!("/proc/{}", vmm.pid)).exists();
    let phase_after = real.phase(allocation);
    daemon.wait_serving(real).await;
    let after = daemon.kilndctl(&mut transcript, &["exec", &id, "--", "true"], None);
    assert_ne!(
        after.code, 0,
        "no command runs in a boot the new helper never supervised"
    );
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    let state_after = daemon.row(&id, "state").unwrap();
    assert_ne!(state_after, "ready", "the session is never reusable again");
    assert!(charged(daemon, &id));
    assert!(unreleased_claim(&deployment, allocation));
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("crash-helper-restart", &transcript, &deployment);
    matrix(
        "helper restart under a READY session",
        json!({"claims_after_restart": 1, "phase_after_restart": phase_after, "old_vmm_alive_after_restart": vmm_alive, "exec_after_restart": after.code, "row_after_exec": state_after, "release": released}),
    );
}

/// Whether S ever journaled the broker's handshake for this allocation: the record READY
/// is published from, written just before the phase moves to `ready`.
fn broker_recorded(deployment: &Deployment, allocation: Id128) -> bool {
    deployment.real.fixture.read(|v| {
        v.query_row(
            "SELECT COUNT(*) FROM resource_events WHERE allocation_id = ?1 AND kind = 'broker'",
            [allocation.to_string()],
            |r| r.get::<_, i64>(0),
        )
    }) > 0
}

/// Waits until a process no longer exists, at most `seconds`.
async fn wait_gone(pid: i32, seconds: u64) -> bool {
    let end = std::time::Instant::now() + Duration::from_secs(seconds);
    while std::time::Instant::now() < end {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    !Path::new(&format!("/proc/{pid}")).exists()
}

/// B6-BI-04 (1): the helper restarts after C2, while the public Create is still polling
/// for READY. H's death stops the booting VM; the new helper replays the one claim and
/// never supervises that boot, so the Create can never see READY. It ends ambiguous and
/// charged, with no second allocation, and the one claim is released only by an ABSENT
/// receipt for the exact token.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_helper_restart_while_create_polls_never_publishes_ready() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let create = daemon.kilndctl_background(&["create", "--net", "none"]);
    // Booting is past C2: the claim is committed, S has spawned the VMM, and the daemon's
    // Create is polling Inspect for READY.
    let allocation = deployment
        .wait_allocation(daemon.instance, &["booting"], 60)
        .await;
    let vmm = real
        .vmm(allocation)
        .expect("a booting allocation has a VMM");
    deployment.restart_helper().await;
    assert!(
        !broker_recorded(&deployment, allocation),
        "the boot reached READY before the helper was killed: the scenario did not run"
    );
    transcript.text.push_str(
        "# the helper (H) killed and restarted after C2, while Create polled for READY\n\n",
    );
    let phase_after_restart = real.phase(allocation);
    assert_eq!(
        deployment.claims(),
        1,
        "the new helper replays the one claim"
    );
    assert!(
        wait_gone(vmm.pid, 30).await,
        "the old VMM {} survived its helper",
        vmm.pid
    );
    let id = daemon.sandbox_ids()[0].clone();
    // While the Create still polls, the row is CREATING and charged on both ledgers.
    let polling = daemon.row(&id, "state").unwrap();
    let polling_charged = charged(daemon, &id) && unreleased_claim(&deployment, allocation);
    let (text, created) = create.join().unwrap();
    transcript.text.push_str(&text);
    assert_ne!(created.code, 0, "no READY from a boot no helper supervises");
    let state = daemon.row(&id, "state").unwrap();
    assert_ne!(state, "ready");
    assert_ne!(state, "creating", "the Create ended");
    assert!(
        !broker_recorded(&deployment, allocation),
        "READY never came"
    );
    assert_eq!(
        deployment.allocations(daemon.instance).len(),
        1,
        "no second allocation for one Create"
    );
    // Whatever released the claim (the failed Create's own settlement by exact token, or
    // Delete below), it was the token's ABSENT receipt, and only then.
    let released_by_create = !charged(daemon, &id);
    if released_by_create {
        assert!(!unreleased_claim(&deployment, allocation));
    } else {
        assert!(
            unreleased_claim(&deployment, allocation),
            "the claim stays while the row is charged"
        );
        assert_eq!(deployment.claims(), 1);
    }
    let failure = daemon.row(&id, "failure_reason");
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    assert_eq!(deployment.claims(), 0);
    assert!(
        polling == "creating" && polling_charged,
        "charged and CREATING while the Create polled: {polling}"
    );
    finish(
        "crash-helper-restart-while-create-polls",
        &transcript,
        &deployment,
    );
    matrix(
        "helper restart after C2, while Create polls for READY",
        json!({
            "phase_after_restart": phase_after_restart,
            "old_vmm_stopped": true,
            "while_polling": "creating, charged on both ledgers",
            "create_exit": created.code,
            "row_after_create": state,
            "failure": failure,
            "broker_handshake_recorded": false,
            "allocations": 1,
            "released_by": if released_by_create {
                "the failed Create's settlement by exact token (ABSENT receipt)"
            } else {
                "Delete (ABSENT receipt)"
            },
            "release": released,
        }),
    );
}

/// B6-BI-04 (2): the daemon is killed while its Delete's Remove is held inside the
/// helper, after the helper owns the removal and before ABSENT. The row stays DELETING
/// and charged through the kill, a restart whose reconciliation meets the removal still
/// in progress, and the old removal's end; the next reconciliation finishes it only from
/// the matching ABSENT receipt.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_daemon_death_mid_remove_stays_charged_until_absent() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    let vmm = real.vmm(allocation).expect("a VMM was journaled");
    // Held in the helper's detached Remove, after it read the journal and before it
    // stops anything: the removal is the helper's, and nothing is ABSENT yet.
    let hold = "H.remove.after_state";
    real.fixture.fault(&format!("{hold}.hold"));
    let remove = daemon.kilndctl_background(&["rm", &id]);
    real.fixture.wait_reached(hold).await;
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("deleting"));
    daemon.kill().await;
    let (text, interrupted) = remove.join().unwrap();
    transcript.text.push_str(&text);
    assert_ne!(interrupted.code, 0, "the caller lost its daemon");
    transcript
        .text
        .push_str("# kilnd SIGKILLed with its Delete's Remove held in the helper\n\n");
    let check_charged = |when: &str| {
        assert_eq!(
            daemon.row(&id, "state").as_deref(),
            Some("deleting"),
            "{when}"
        );
        assert!(charged(daemon, &id), "{when}: the row stays charged");
        assert!(
            unreleased_claim(&deployment, allocation),
            "{when}: the node claim stays"
        );
        assert_ne!(real.phase(allocation), "absent", "{when}");
    };
    check_charged("after the kill");
    // The restart's reconciliation meets the held removal: nothing is proven absent.
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    check_charged("after a restart with the removal still held");
    let phase_held = real.phase(allocation);
    // The old removal resumes for a daemon that is gone, and ends without a receipt the
    // daemon could have seen. Still nothing is released.
    real.fixture.clear(&format!("{hold}.hold"));
    tokio::time::sleep(Duration::from_secs(5)).await;
    let phase_after_old_removal = real.phase(allocation);
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("deleting"));
    assert!(
        charged(daemon, &id),
        "no release without the daemon's own receipt"
    );
    let get = daemon.kilndctl(&mut transcript, &["get", &id], None);
    assert!(get.stdout.contains("deleting"), "{}", get.stdout);
    // Reconciliation at the next start finishes it, from the matching ABSENT receipt.
    transcript
        .text
        .push_str("# kilnd restarted: its reconciliation settles the DELETING row\n\n");
    daemon.stop().await;
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    assert!(wait_gone(vmm.pid, 30).await, "the VMM survived ABSENT");
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    assert_eq!(deployment.claims(), 0);
    daemon.kilndctl(&mut transcript, &["get", &id], None);
    finish("crash-daemon-death-mid-remove", &transcript, &deployment);
    matrix(
        "daemon killed mid-Remove (helper-owned, before ABSENT)",
        json!({
            "after_kill": "deleting, charged on both ledgers",
            "after_restart_while_held": "deleting, charged",
            "phase_while_held": phase_held,
            "phase_after_old_removal_ended": phase_after_old_removal,
            "settled_by": "startup reconciliation, ABSENT receipt",
            "release": released,
        }),
    );
}

/// An operator restores a stale database. The surviving node ledger still holds the
/// session the old database never heard of: the daemon blocks its own admission, the node
/// keeps the charge, and a second daemon sees one slot fewer. Restoring the current
/// database lets Delete release it.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_restored_stale_db_blocks_admission_and_keeps_the_charge() {
    let options = NodeOptions {
        ceilings: NodeCeilings {
            slots: 2,
            ..NodeCeilings::default()
        },
        ..NodeOptions::default()
    };
    let deployment = Deployment::new(&["fctest", SECOND], options).await;
    let a = deployment.daemon("fctest");
    let b = deployment.daemon(SECOND);
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    let stale = copies("stale");
    let current = copies("current");
    a.start(&deployment.image);
    a.wait_serving(real).await;
    a.stop().await;
    a.copy_state(&stale);
    transcript
        .text
        .push_str("# a byte copy of fctest's database, before any session\n\n");
    a.start(&deployment.image);
    a.wait_serving(real).await;
    let (id, allocation) = ready_session(a, &mut transcript);
    a.stop().await;
    a.copy_state(&current);
    a.restore_state(&stale);
    transcript
        .text
        .push_str("# fctest stopped and its database replaced by the stale copy\n\n");
    a.start(&deployment.image);
    a.wait_serving(real).await;
    let health = a.kilndctl(&mut transcript, &["health"], None);
    assert!(
        health.stdout.contains("backend resources no row explains"),
        "{}",
        health.stdout
    );
    let refused = a.kilndctl(&mut transcript, &["create", "--net", "none"], None);
    assert_ne!(refused.code, 0, "the stale daemon must not admit beside it");
    assert!(
        unreleased_claim(&deployment, allocation),
        "the node keeps the charge"
    );
    // The other daemon sees the node's truth, not fctest's local sum.
    b.start(&deployment.image);
    b.wait_serving(real).await;
    assert_eq!(node_sandboxes(&mut transcript, &b.bin, b.socket()).await, 1);
    let (b_id, b_allocation) = ready_session(b, &mut transcript);
    let full = b.kilndctl(&mut transcript, &["create", "--net", "none"], None);
    assert_ne!(full.code, 0, "two slots: the stale session's and fctest2's");
    let refused = refusal(b, std::slice::from_ref(&b_id));
    assert_eq!(deployment.claims(), 2);
    a.stop().await;
    a.restore_state(&current);
    transcript
        .text
        .push_str("# fctest's current database restored\n\n");
    a.start(&deployment.image);
    a.wait_serving(real).await;
    let removed = a.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, a, &id, allocation, "deleted");
    let removed = b.kilndctl(&mut transcript, &["rm", &b_id], None);
    assert_eq!(removed.code, 0);
    assert_released(&deployment, b, &b_id, b_allocation, "deleted");
    assert_eq!(deployment.claims(), 0);
    finish("crash-restored-stale-db", &transcript, &deployment);
    matrix(
        "stale database restored",
        json!({"stale_daemon": "admission blocked, charge kept", "second_daemon_slots": "1 of 2 free", "second_daemons_extra_create": refused, "release": released}),
    );
}

/// A daemon's database is lost entirely. Its replacement is another instance, which the
/// helper refuses; the node ledger keeps the lost daemon's claim and its live VM, and a
/// second daemon is never given that capacity. Restoring the database restores control.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-crash-matrix.py"]
async fn b6_linux_root_crash_lost_db_never_discounts_the_node_claim() {
    let options = NodeOptions {
        ceilings: NodeCeilings {
            slots: 1,
            ..NodeCeilings::default()
        },
        ..NodeOptions::default()
    };
    let deployment = Deployment::new(&["fctest", SECOND], options).await;
    let a = deployment.daemon("fctest");
    let b = deployment.daemon(SECOND);
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    a.start(&deployment.image);
    a.wait_serving(real).await;
    let (id, allocation) = ready_session(a, &mut transcript);
    a.stop().await;
    let saved = copies("lost");
    a.copy_state(&saved);
    for entry in std::fs::read_dir(a.state_dir()).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let fresh = super::session::init_state(&deployment.image, &a.deployment);
    assert_ne!(fresh, a.instance, "a new database is another instance");
    transcript.text.push_str(&format!(
        "# fctest's database deleted; init-state made a new instance {fresh}\n\n"
    ));
    a.start(&deployment.image);
    assert!(
        a.wait_inactive(60).await,
        "an unenrolled instance must not serve"
    );
    let log = std::fs::read_to_string(&a.log).unwrap_or_default();
    assert!(
        log.contains("reconciliation") || log.contains("attach"),
        "{log}"
    );
    assert_eq!(
        real.phase(allocation),
        "ready",
        "the lost daemon's VM is untouched"
    );
    assert!(unreleased_claim(&deployment, allocation));
    b.start(&deployment.image);
    b.wait_serving(real).await;
    assert_eq!(node_sandboxes(&mut transcript, &b.bin, b.socket()).await, 1);
    let full = b.kilndctl(&mut transcript, &["create", "--net", "none"], None);
    assert_ne!(full.code, 0, "the lost daemon's slot is never discounted");
    let refused = refusal(b, &[]);
    assert_eq!(deployment.claims(), 1);
    for entry in std::fs::read_dir(a.state_dir()).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    a.restore_state(&saved);
    transcript.text.push_str("# fctest's database restored\n\n");
    a.start(&deployment.image);
    a.wait_serving(real).await;
    let removed = a.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, a, &id, allocation, "deleted");
    assert_eq!(deployment.claims(), 0);
    finish("crash-lost-db", &transcript, &deployment);
    matrix(
        "database lost; node ledger survives",
        json!({"replacement_instance": "refused", "second_daemon": refused, "release": released}),
    );
}

/// Section 10.2 item 15: two daemons with their own databases race four 896 MiB requests
/// for three node slots. Exactly three reach INTENT; the fourth gets a durable fence
/// before its row releases. The admitted ones are held before their disks exist, then
/// failed, so no VM boots here.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-regressions.py"]
async fn b6_linux_root_attack_two_daemons_race_four_requests_for_three_slots() {
    let deployment = Deployment::new(&["fctest", SECOND], NodeOptions::default()).await;
    let a = deployment.daemon("fctest");
    let b = deployment.daemon(SECOND);
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    for daemon in [a, b] {
        daemon.start(&deployment.image);
        daemon.wait_serving(real).await;
    }
    // Preflight runs in P's two node-wide slots (design 6.4), so four Creates at once
    // are mostly refused at C0 for P's capacity, with no row. The race that matters is
    // for the node's last slot: two sessions first, one per daemon, then the last two
    // together, so both pass Preflight and contend at C2 for slot three.
    let first: Vec<_> = [a, b]
        .iter()
        .map(|d| d.kilndctl_background(&["create", "--net", "none"]))
        .collect();
    let mut ready = Vec::new();
    for (racer, daemon) in first.into_iter().zip([a, b]) {
        let (text, ran) = racer.join().unwrap();
        transcript.text.push_str(&text);
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        ready.push((ran.stdout.trim().to_string(), daemon));
    }
    assert_eq!(deployment.claims(), 2);
    // The contenders are held before their disks exist once admitted, so no third VM
    // boots in this 4 GiB test VM.
    real.fixture.fault("S.step.work_dir.stall");
    let racers: Vec<_> = [a, b]
        .iter()
        .map(|d| d.kilndctl_background(&["create", "--net", "none"]))
        .collect();
    // Three claims, never a fourth. The loser is refused either at C0 (its Preflight
    // already saw the node full: no row) or at C2 (released only by its fence).
    let end = std::time::Instant::now() + Duration::from_secs(90);
    let mut finished = Vec::new();
    let mut racers: Vec<_> = racers.into_iter().map(Some).collect();
    loop {
        assert!(
            deployment.claims() <= 3,
            "a fourth claim: {}",
            deployment.claims()
        );
        for racer in racers.iter_mut() {
            if racer.as_ref().is_some_and(|r| r.is_finished()) {
                finished.push(racer.take().unwrap().join().unwrap());
            }
        }
        if deployment.claims() == 3 && finished.len() == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < end,
            "claims {} finished {}",
            deployment.claims(),
            finished.len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (text, fourth) = finished.pop().unwrap();
    transcript.text.push_str(&text);
    assert_ne!(fourth.code, 0, "the fourth request failed");
    let admitted: i64 = real
        .fixture
        .read(|v| v.query_row("SELECT COUNT(*) FROM allocations", [], |r| r.get(0)));
    assert_eq!(admitted, 3, "exactly three reached INTENT");
    let admitted_ids: Vec<String> = real.fixture.read(|v| {
        let mut statement = v.prepare("SELECT sandbox_id FROM allocations")?;
        let rows = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    });
    // Its row, if it has one, settles to FAILED released by the fence shortly after.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let c0 = json!("refused at C0: no row, no reservation");
    let refusals: Vec<Value> = [a, b]
        .iter()
        .map(|d| refusal(d, &admitted_ids))
        .filter(|r| r != &c0)
        .collect();
    let rejected_evidence = match refusals.as_slice() {
        [] => c0,
        [one] => {
            let id = one["refused_after_c1"].as_str().unwrap();
            let daemon = if a.sandbox_ids().iter().any(|i| i == id) {
                a
            } else {
                b
            };
            let allocation = Id128::parse(&daemon.row(id, "allocation_id").unwrap()).unwrap();
            let fenced: String = real.fixture.read(|v| {
                v.query_row(
                    "SELECT receipt_id FROM retired_tokens WHERE allocation_id = ?1",
                    [allocation.to_string()],
                    |r| r.get(0),
                )
            });
            assert_eq!(json!(fenced), one["fence"]);
            one.clone()
        }
        more => panic!("more than one refusal: {more:?}"),
    };
    // Fail the held contender before its disk exists; its daemon settles it.
    real.fixture.fault("S.step.work_file.panic");
    real.fixture.clear("S.step.work_dir.stall");
    for racer in racers.into_iter().flatten() {
        let (text, _) = racer.join().unwrap();
        transcript.text.push_str(&text);
    }
    real.fixture.clear("S.step.work_file.panic");
    for (id, daemon) in &ready {
        let removed = daemon.kilndctl(&mut transcript, &["rm", id], None);
        assert_eq!(removed.code, 0, "{}", removed.stderr);
    }
    let end = std::time::Instant::now() + Duration::from_secs(120);
    while deployment.claims() != 0 {
        assert!(
            std::time::Instant::now() < end,
            "claims stayed {}",
            deployment.claims()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    for daemon in [a, b] {
        for id in daemon.sandbox_ids() {
            assert!(!charged(daemon, &id), "{id} stayed charged");
        }
        daemon.kilndctl(&mut transcript, &["ls", "--all"], None);
    }
    finish("attack-four-request-race", &transcript, &deployment);
    matrix(
        "two daemons race four requests for three slots",
        json!({"intent": 3, "rejected_fenced": rejected_evidence, "claims_after": 0}),
    );
}

/// Disk and vCPU exhaustion on a node whose other dimensions are free: the second session
/// is refused at C2, released only by its fence, and the node never holds more than its
/// ceiling.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-regressions.py"]
async fn b6_linux_root_attack_disk_and_vcpu_exhaustion_never_oversubscribe() {
    let mut outcomes = Vec::new();
    for (dimension, ceilings) in [
        (
            "disk",
            NodeCeilings {
                // The 1.5 GiB shared reserve plus one 1408 MiB session, not two.
                disk_bytes: (1536 + 1408 + 512) << 20,
                ..NodeCeilings::default()
            },
        ),
        (
            "vcpu",
            NodeCeilings {
                virtual_cpu_slots: 1,
                ..NodeCeilings::default()
            },
        ),
    ] {
        let deployment = Deployment::new(
            &["fctest"],
            NodeOptions {
                ceilings,
                ..NodeOptions::default()
            },
        )
        .await;
        let daemon = deployment.daemon("fctest");
        let mut transcript = Transcript::default();
        daemon.start(&deployment.image);
        daemon.wait_serving(&deployment.real).await;
        let (id, allocation) = ready_session(daemon, &mut transcript);
        let second = daemon.kilndctl(&mut transcript, &["create", "--net", "none"], None);
        assert_ne!(second.code, 0, "{dimension} would be oversubscribed");
        assert!(
            second.stderr.contains("resourceexhausted"),
            "design 9.2: {}",
            second.stderr
        );
        let refused = refusal(daemon, std::slice::from_ref(&id));
        assert_eq!(deployment.claims(), 1);
        daemon.kilndctl(&mut transcript, &["health"], None);
        let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
        assert_eq!(removed.code, 0);
        assert_released(&deployment, daemon, &id, allocation, "deleted");
        finish(
            &format!("attack-{dimension}-exhaustion"),
            &transcript,
            &deployment,
        );
        outcomes.push(
            json!({"dimension": dimension, "second": refused, "error": second.stderr.trim(), "claims_max": 1}),
        );
        drop(deployment);
    }
    matrix("disk and vCPU exhaustion", json!(outcomes));
}

/// Section 4.1's one live holder: a second process that is the enrolled account, in the
/// enrolled unit's own cgroup, running the enrolled image, with a byte copy of the
/// daemon's files, is still refused while the daemon holds the instance; so is one outside
/// the unit's cgroup. The serving daemon keeps working.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-regressions.py"]
async fn b6_linux_root_attack_duplicate_instance_attachment_is_refused() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    // A copy of the daemon's files, owned by its account, taken while it runs.
    let copy = copies("duplicate");
    std::fs::create_dir_all(&copy).unwrap();
    for entry in std::fs::read_dir(daemon.state_dir()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
        }
    }
    std::fs::set_permissions(Path::new(COPIES), std::fs::Permissions::from_mode(0o755)).unwrap();
    for entry in std::fs::read_dir(&copy).unwrap() {
        std::os::unix::fs::chown(entry.unwrap().path(), Some(daemon.uid), Some(daemon.gid))
            .unwrap();
    }
    std::os::unix::fs::chown(&copy, Some(daemon.uid), Some(daemon.gid)).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cgroup = format!("/sys/fs/cgroup/system.slice/{}/cgroup.procs", daemon.unit());
    let attach = |inside: bool| {
        let enter = if inside {
            format!("echo $$ > {cgroup} && ")
        } else {
            String::new()
        };
        let script = format!(
            "{enter}exec setpriv --reuid={} --regid={} --clear-groups {} check-attachment --state-dir {} --helper-socket {}",
            daemon.uid,
            daemon.gid,
            deployment.image.display(),
            copy.display(),
            daemon.deployment.helper.socket.display()
        );
        output(Command::new("sh").args(["-c", &script]))
    };
    let inside = attach(true);
    let outside = attach(false);
    for (name, out) in [
        ("inside the unit's cgroup", &inside),
        ("outside it", &outside),
    ] {
        transcript.text.push_str(&format!(
            "$ kilnd check-attachment ({name}, a byte copy of the daemon's files)\n{}{}[exit {}]\n\n",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            out.status.code().unwrap_or(-1)
        ));
        assert!(!out.status.success(), "a duplicate attached {name}");
    }
    let ran = daemon.kilndctl(
        &mut transcript,
        &["exec", &id, "--", "echo", "still mine"],
        None,
    );
    assert_eq!((ran.code, ran.stdout.as_str()), (0, "still mine\n"));
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0);
    assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("attack-duplicate-attachment", &transcript, &deployment);
    matrix(
        "duplicate instance attachment",
        json!({
            "inside_unit_cgroup": String::from_utf8_lossy(&inside.stderr).trim(),
            "outside": String::from_utf8_lossy(&outside.stderr).trim(),
            "holder_kept_serving": true
        }),
    );
}

/// B5's simultaneous hostile I/O, now beside real lifecycle requests through the daemon:
/// Create, Health, Get, Exec and Delete each meet their deadlines while two hostile relays
/// and a console flood run, memory stays flat and each offender ends at its bound.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-regressions.py"]
async fn b6_linux_root_attack_hostile_io_beside_real_lifecycle_requests() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let mut hostile = HostileSources::start(real).await;
    let (bin, socket) = (daemon.bin.clone(), daemon.socket().to_path_buf());
    let call = move |args: Vec<String>| {
        let (bin, socket) = (bin.clone(), socket.clone());
        tokio::task::spawn_blocking(move || {
            let mut transcript = Transcript::default();
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let started = std::time::Instant::now();
            let ran = transcript.kilndctl(&bin, &socket, &args, None);
            (ran, started.elapsed(), std::mem::take(&mut transcript.text))
        })
    };
    let work = async {
        let mut timings = Vec::new();
        let mut text = String::new();
        let (ran, took, t) = call(vec!["create".into(), "--net".into(), "none".into()])
            .await
            .unwrap();
        text.push_str(&t);
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        timings.push(("create", took, Duration::from_secs(120)));
        let id = ran.stdout.trim().to_string();
        for _ in 0..5 {
            for (name, args, limit) in [
                ("health", vec!["health".to_string()], 5),
                ("get", vec!["get".into(), id.clone()], 5),
                (
                    "exec",
                    vec![
                        "exec".into(),
                        id.clone(),
                        "--".into(),
                        "echo".into(),
                        "healthy".into(),
                    ],
                    60,
                ),
            ] {
                let (ran, took, t) = call(args).await.unwrap();
                text.push_str(&t);
                assert!(ran.code == 0 || name == "health", "{name}: {}", ran.stderr);
                timings.push((name, took, Duration::from_secs(limit)));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let (ran, took, t) = call(vec!["rm".into(), id.clone()]).await.unwrap();
        text.push_str(&t);
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        timings.push(("delete", took, Duration::from_secs(60)));
        (timings, text, id)
    };
    let (timings, text, id) = hostile.beside(work).await;
    hostile.finish(
        real,
        &timings,
        &["create", "health", "get", "exec", "delete"],
    );
    let allocation = Id128::parse(&daemon.row(&id, "allocation_id").unwrap()).unwrap();
    assert_released(&deployment, daemon, &id, allocation, "deleted");
    let transcript = Transcript { text };
    finish("attack-hostile-io", &transcript, &deployment);
    let worst: Vec<_> = ["create", "health", "get", "exec", "delete"]
        .iter()
        .map(|n| {
            let max = timings
                .iter()
                .filter(|t| t.0 == *n)
                .map(|t| t.1)
                .max()
                .unwrap();
            json!({"request": n, "worst_ms": max.as_millis()})
        })
        .collect();
    matrix("hostile I/O beside real lifecycle requests", json!(worst));
}

/// B5-R1 on the real chain: L stalls inside Remove's final fence. Delete answers within
/// its bound with the row DELETING and charged, the helper gives back its detached slot
/// and removing claim while L is still stalled, and once L recovers a second Delete
/// finishes with ABSENT.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-regressions.py"]
async fn b6_linux_root_attack_a_stalled_ledger_fence_never_holds_remove() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    let free = real.fixture.census().await["detached_available"]
        .as_u64()
        .unwrap();
    real.fixture.fault("L.fence.before_commit.stall");
    let started = std::time::Instant::now();
    let stalled = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    let took = started.elapsed();
    assert_ne!(stalled.code, 0);
    assert!(took < Duration::from_secs(75), "Delete took {took:?}");
    assert_eq!(daemon.row(&id, "state").as_deref(), Some("deleting"));
    assert!(charged(daemon, &id));
    let census = real.fixture.census().await;
    assert_eq!(census["removing"], json!(0), "{census}");
    assert_eq!(
        census["detached_available"].as_u64(),
        Some(free),
        "{census}"
    );
    real.fixture.clear("L.fence.before_commit.stall");
    let removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("attack-stalled-ledger-remove", &transcript, &deployment);
    matrix(
        "ledger stalls in Remove's fence (B5-R1)",
        json!({"first_delete_ms": took.as_millis(), "slot_and_claim_released_while_stalled": true, "release": released}),
    );
}

/// Quarantine stays controllable through Delete, and blocked proof is answered honestly.
/// With both recovery K slots stalled, a timed-out execution cannot prove the VM gone: the
/// execution fails with unknown cleanup and the sandbox is quarantined, still charged.
/// Delete then answers with an error rather than success while proof is blocked, and once
/// K recovers Delete reaches ABSENT.
#[tokio::test]
#[ignore = "needs root with the B4 launch capabilities: run scripts/firecracker-regressions.py"]
async fn b6_linux_root_attack_quarantine_stays_deletable_and_unknown_is_honest() {
    let deployment = Deployment::new(&["fctest"], NodeOptions::default()).await;
    let daemon = deployment.daemon("fctest");
    let real = &deployment.real;
    let mut transcript = Transcript::default();
    daemon.start(&deployment.image);
    daemon.wait_serving(real).await;
    let (id, allocation) = ready_session(daemon, &mut transcript);
    real.fixture.fault("K.kill.stall");
    real.fixture.fault("K.cgroup_kill.stall");
    let timed_out = daemon.kilndctl(
        &mut transcript,
        &["exec", "--timeout", "2s", &id, "--", "sleep", "60"],
        None,
    );
    assert_ne!(timed_out.code, 0);
    let state = daemon.row(&id, "state").unwrap();
    let last = executions(daemon, &id)
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last["sandbox_reusable"], json!(0), "{last}");
    let blocked = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    let while_blocked = daemon.row(&id, "state").unwrap();
    assert!(charged(daemon, &id), "no release while proof is blocked");
    assert!(unreleased_claim(&deployment, allocation));
    if blocked.code == 0 {
        panic!(
            "Delete claimed success with K stalled:\n{}",
            transcript.text
        );
    }
    real.fixture.clear("K.kill.stall");
    real.fixture.clear("K.cgroup_kill.stall");
    let mut removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    for _ in 0..5 {
        if removed.code == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        removed = daemon.kilndctl(&mut transcript, &["rm", &id], None);
    }
    assert_eq!(
        removed.code,
        0,
        "{}\n{}",
        removed.stderr,
        real.fixture.log()
    );
    let released = assert_released(&deployment, daemon, &id, allocation, "deleted");
    finish("attack-quarantine-and-unknown", &transcript, &deployment);
    matrix(
        "quarantine stays deletable; blocked proof is Unknown",
        json!({
            "after_timeout": state,
            "execution": last,
            "delete_while_blocked": {"exit": blocked.code, "stderr": blocked.stderr.trim(), "row": while_blocked},
            "release": released
        }),
    );
}

#[test]
fn b6_scenario_names_match_the_scripts() {
    // The scripts refuse to report a matrix with a missing scenario; keep both in step.
    let crash = include_str!("../../../../../../scripts/firecracker-crash-matrix.py");
    let attacks = include_str!("../../../../../../scripts/firecracker-regressions.py");
    let source = include_str!("recovery.rs");
    for line in source.lines() {
        let line = line.trim();
        if let Some(name) = line
            .strip_prefix("async fn ")
            .and_then(|rest| rest.split('(').next())
        {
            if name.starts_with("b6_linux_root_crash_") {
                assert!(crash.contains(name), "{name} missing from the crash matrix");
            } else if name.starts_with("b6_linux_root_attack_") {
                assert!(
                    attacks.contains(name),
                    "{name} missing from the regressions"
                );
            }
        }
    }
    let _ = checked;
}
