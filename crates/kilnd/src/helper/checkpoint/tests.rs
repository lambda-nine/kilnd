//! Fault injection for the checkpoint group: scripted workers that exit, fail, hang
//! until killed, exit late regardless, or never die, and a scripted process table.
//! Every reply also passes the daemon-side `CheckpointResponse::check`.
use super::*;
use crate::checkpoint::tests::{CHECKPOINT, INSTANCE, binding, content, record_text, target};
use crate::checkpoint::{GROUP_VERSION, MAX_INVENTORY_ENTRIES};
use crate::model::{Captured, Id128};
use crate::process::CaptureCompletion;
use std::os::unix::process::ExitStatusExt;
use tokio::sync::watch;

#[derive(Clone)]
struct Gate(watch::Sender<bool>);

impl Gate {
    fn new() -> Self {
        Self(watch::channel(false).0)
    }
    fn open(&self) {
        self.0.send_replace(true);
    }
    async fn wait(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|open| *open).await;
    }
}

#[derive(Clone)]
enum Act {
    Exit(i32, String, String),
    /// A capture or inspect record built from the worker's own arguments.
    Echo,
    /// Runs `then` once the gate opens; killed on cancellation or at the deadline.
    Gated(Gate, Box<Act>),
    /// Runs `then` once the gate opens, whatever happened meanwhile: a worker that
    /// still exits 0 after it was told to stop.
    Late(Gate, Box<Act>),
    /// Never resolves: a worker stuck in the kernel.
    Unkillable,
    SpawnError,
}

#[derive(Default)]
struct Fake {
    defaults: Mutex<HashMap<&'static str, Act>>,
    events: Mutex<Vec<String>>,
    /// `None`: the process table cannot be read.
    processes: Mutex<Option<Vec<ProcessArgs>>>,
}

fn kind(argv: &[String]) -> &'static str {
    match (argv[0].as_str(), argv.get(1).map(String::as_str)) {
        ("checkpoint", Some("capture")) => "capture",
        ("checkpoint", Some("inspect")) => "inspect",
        ("checkpoint", Some("rm")) => "rm",
        ("checkpoint", Some("ls")) => "ls",
        ("create", _) => "create",
        _ => "other",
    }
}

fn outcome(finish: Finish, out: &str, err: &str) -> Outcome {
    let captured = |s: &str| Captured {
        data: s.as_bytes().to_vec(),
        total_bytes: s.len() as u64,
        truncated: false,
        total_bytes_known: true,
    };
    let completion = match finish {
        Finish::Exited(_) => CaptureCompletion::Eof,
        _ => CaptureCompletion::Stopped("killed"),
    };
    Outcome {
        finish,
        stdout: captured(out),
        stderr: captured(err),
        stdout_completion: completion.clone(),
        stderr_completion: completion,
    }
}

fn exited(code: i32, out: &str, err: &str) -> Outcome {
    outcome(
        Finish::Exited(std::process::ExitStatus::from_raw(code << 8)),
        out,
        err,
    )
}

fn flag(argv: &[String], name: &str) -> Option<String> {
    argv.iter()
        .find_map(|a| a.strip_prefix(&format!("{name}=")).map(String::from))
}

fn echo(argv: &[String]) -> Outcome {
    let generation = flag(argv, "--generation").unwrap_or_else(|| "1".into());
    let limit = flag(argv, "--max-bytes").unwrap_or_else(|| (1u64 << 30).to_string());
    let text = record_text(generation.parse().unwrap(), limit.parse().unwrap())
        .replace(INSTANCE, &flag(argv, "--instance").unwrap())
        .replace(CHECKPOINT, &flag(argv, "--checkpoint").unwrap());
    exited(0, &text, "")
}

impl Fake {
    fn new() -> Arc<Self> {
        let fake = Self::default();
        {
            let mut d = fake.defaults.lock().unwrap();
            d.insert("capture", Act::Echo);
            d.insert("inspect", Act::Echo);
            d.insert(
                "rm",
                Act::Exit(
                    0,
                    "kiln-checkpoint-removed 1\nexisted yes\n".into(),
                    "".into(),
                ),
            );
            d.insert(
                "ls",
                Act::Exit(0, "kiln-checkpoint-inventory 1\n".into(), "".into()),
            );
            d.insert(
                "create",
                Act::Exit(0, "0123456789abcdef\n".into(), "".into()),
            );
        }
        *fake.processes.lock().unwrap() = Some(Vec::new());
        Arc::new(fake)
    }
    fn set(&self, kind: &'static str, act: Act) {
        self.defaults.lock().unwrap().insert(kind, act);
    }
    fn starts(&self, kind: &str) -> usize {
        let started = format!("start {kind}");
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == started)
            .count()
    }
    fn position(&self, event: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .position(|e| e == event)
            .unwrap_or_else(|| panic!("no event {event}"))
    }
    fn argv(&self, kind: &str) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find_map(|e| e.strip_prefix(&format!("argv {kind} ")).map(String::from))
            .unwrap()
            .split(' ')
            .map(String::from)
            .collect()
    }
    fn set_processes(&self, processes: Option<Vec<ProcessArgs>>) {
        *self.processes.lock().unwrap() = processes;
    }
}

struct Workers(Arc<Fake>);

fn play(
    fake: Arc<Fake>,
    kind: &'static str,
    argv: Vec<String>,
    act: Act,
    deadline: Instant,
    cancel: CancellationToken,
) -> kiln::WorkerFuture {
    Box::pin(async move {
        let result = match act {
            Act::Exit(code, out, err) => Ok(exited(code, &out, &err)),
            Act::Echo => Ok(echo(&argv)),
            Act::SpawnError => Err(io::Error::other("spawn failed")),
            Act::Unkillable => std::future::pending().await,
            Act::Gated(gate, then) => {
                tokio::select! {
                    () = gate.wait() => return play(fake, kind, argv, *then, deadline, cancel).await,
                    () = cancel.cancelled() => Ok(outcome(Finish::Canceled, "", "")),
                    () = tokio::time::sleep_until(deadline) => Ok(outcome(Finish::TimedOut, "", "")),
                }
            }
            Act::Late(gate, then) => {
                gate.wait().await;
                return play(fake, kind, argv, *then, deadline, cancel).await;
            }
        };
        fake.events.lock().unwrap().push(format!("end {kind}"));
        result
    })
}

impl kiln::Workers for Workers {
    fn run(
        &self,
        args: KilnArgs,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> kiln::WorkerFuture {
        let argv = args.as_slice().to_vec();
        let kind = kind(&argv);
        let act = self
            .0
            .defaults
            .lock()
            .unwrap()
            .get(kind)
            .cloned()
            .unwrap_or(Act::Exit(1, String::new(), String::new()));
        {
            let mut events = self.0.events.lock().unwrap();
            events.push(format!("start {kind}"));
            events.push(format!("argv {kind} {}", argv.join(" ")));
        }
        // The real runner refuses to spawn under a canceled token.
        if cancel.is_cancelled() {
            return Box::pin(async { Ok(outcome(Finish::Canceled, "", "")) });
        }
        play(self.0.clone(), kind, argv, act, deadline, cancel)
    }
    fn processes(&self) -> io::Result<Vec<ProcessArgs>> {
        self.0
            .processes
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| io::Error::other("no process table"))
    }
    fn support(&self, _deadline: Instant, _cancel: CancellationToken) -> kiln::SupportFuture {
        Box::pin(async { Ok(()) })
    }
}

fn setup() -> (Arc<Node>, Arc<Fake>) {
    let fake = Fake::new();
    (Node::new(Arc::new(Workers(fake.clone()))).unwrap(), fake)
}

fn request(node: &Node, operation: &CheckpointOperation) -> CheckpointRequest {
    let request = CheckpointRequest {
        group_version: GROUP_VERSION,
        helper_epoch: (!matches!(operation, CheckpointOperation::Capabilities))
            .then(|| node.epoch()),
        operation: operation.clone(),
    };
    request.validate().unwrap();
    request
}

/// One request, with the daemon's check of its reply.
async fn call_with(
    node: &Arc<Node>,
    operation: CheckpointOperation,
    seconds: u64,
    waiter: &CancellationToken,
) -> CheckpointResponse {
    let reply = node
        .handle(
            request(node, &operation),
            Instant::now() + Duration::from_secs(seconds),
            waiter,
        )
        .await;
    reply
        .check(&operation, Some(node.epoch()))
        .unwrap_or_else(|e| panic!("{e}: {reply:?}"));
    reply
}

async fn call(node: &Arc<Node>, operation: CheckpointOperation) -> CheckpointResponse {
    call_with(node, operation, 60, &CancellationToken::new()).await
}

fn spawn_call(
    node: &Arc<Node>,
    operation: CheckpointOperation,
) -> tokio::task::JoinHandle<CheckpointResponse> {
    let node = node.clone();
    tokio::spawn(async move { call(&node, operation).await })
}

async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition never held");
}

fn capture(binding: &CaptureBinding) -> CheckpointOperation {
    CheckpointOperation::Capture {
        binding: binding.clone(),
    }
}

fn remove(target: &ArtifactTarget, operation: Id128) -> CheckpointOperation {
    CheckpointOperation::Remove {
        target: target.clone(),
        operation,
    }
}

fn spec() -> SandboxSpec {
    serde_json::from_value(serde_json::json!({
        "image": "alpine", "memory_bytes": 268435456, "cpu_millis": 1000, "pids": 64,
        "disk_bytes": 1073741824, "network": "none", "read_only_root": false,
        "writable_paths": [], "labels": {}
    }))
    .unwrap()
}

fn restore(target: &ArtifactTarget, reader: Id128) -> CheckpointOperation {
    CheckpointOperation::Restore {
        target: target.clone(),
        content_sha256: content(),
        reader,
        spec: spec(),
    }
}

fn inspect(target: &ArtifactTarget, operation: Option<Id128>) -> CheckpointOperation {
    CheckpointOperation::Inspect {
        target: target.clone(),
        verify: false,
        operation,
    }
}

fn other_target() -> ArtifactTarget {
    ArtifactTarget {
        checkpoint: CheckpointId::random(),
        ..target()
    }
}

fn captured(reply: &CheckpointResponse) -> &CaptureReply {
    match reply {
        CheckpointResponse::Captured(reply) => reply,
        other => panic!("not a capture reply: {other:?}"),
    }
}

fn removed(reply: &CheckpointResponse) -> &RemoveReply {
    match reply {
        CheckpointResponse::Removed(reply) => reply,
        other => panic!("not a removal reply: {other:?}"),
    }
}

fn restored(reply: &CheckpointResponse) -> &RestoreReply {
    match reply {
        CheckpointResponse::Restored(reply) => reply,
        other => panic!("not a restore reply: {other:?}"),
    }
}

fn inspected(reply: &CheckpointResponse) -> &ArtifactInspectReply {
    match reply {
        CheckpointResponse::Inspected(reply) => reply,
        other => panic!("not an inspection: {other:?}"),
    }
}

fn error_kind(reply: &CheckpointResponse) -> CheckpointErrorKind {
    match reply {
        CheckpointResponse::Error(e) => e.kind,
        other => panic!("not an error: {other:?}"),
    }
}

fn copy_of(evidence: &SealedEvidence) -> CopyOutcome {
    match evidence.evidence.fact {
        Fact::ReaderEnded { copy } => copy,
        ref other => panic!("not reader evidence: {other:?}"),
    }
}

#[tokio::test]
async fn a_complete_capture_certifies_exactly_its_binding_and_replays() {
    let (node, fake) = setup();
    let b = binding();
    let reply = call(&node, capture(&b)).await;
    let CaptureReply::Complete { evidence } = captured(&reply) else {
        panic!("{reply:?}");
    };
    let fact = evidence.verify_complete(&b).unwrap();
    assert_eq!(fact.charge_bytes, 98304);
    assert_eq!(evidence.evidence.helper_epoch, node.epoch());
    assert_eq!(
        fake.argv("capture"),
        [
            "checkpoint",
            "capture",
            &format!("--instance={INSTANCE}"),
            &format!("--checkpoint={CHECKPOINT}"),
            "--generation=1",
            "--max-bytes=1073741824",
            "0123456789abcdef",
        ]
    );
    // The same nonce replays the settled reply and starts nothing.
    assert_eq!(call(&node, capture(&b)).await, reply);
    assert_eq!(fake.starts("capture"), 1);
    // The nonce is bound to its artifact.
    let mut elsewhere = b.clone();
    elsewhere.target = other_target();
    assert_eq!(
        error_kind(&call(&node, capture(&elsewhere)).await),
        CheckpointErrorKind::Conflict
    );
    assert_eq!(
        call(
            &node,
            CheckpointOperation::Acknowledge {
                target: target(),
                operation: b.operation,
            },
        )
        .await,
        CheckpointResponse::Acknowledged
    );
}

#[tokio::test(start_paused = true)]
async fn every_capture_without_a_valid_matching_record_fails() {
    let failure =
        "kiln-checkpoint-failure 1\nreason checkpoint_metadata_unsupported\ndetail entry 7\n";
    let gate = Gate::new();
    let cases = [
        (
            Act::Exit(125, failure.into(), "".into()),
            Reason::MetadataUnsupported,
        ),
        (Act::Exit(125, "garbage\n".into(), "".into()), Reason::Io),
        (Act::Exit(0, "garbage\n".into(), "".into()), Reason::Io),
        (Act::Exit(0, record_text(2, 1 << 30), "".into()), Reason::Io),
        (Act::Exit(0, record_text(1, 2 << 30), "".into()), Reason::Io),
        (Act::Exit(1, "".into(), "".into()), Reason::Io),
        (Act::SpawnError, Reason::Io),
        // Killed at the deadline and reaped: the waiter sees it settle, not Pending.
        (Act::Gated(gate, Box::new(Act::Echo)), Reason::Io),
    ];
    for (act, expected) in cases {
        let (node, fake) = setup();
        fake.set("capture", act);
        let reply = call_with(&node, capture(&binding()), 5, &CancellationToken::new()).await;
        match captured(&reply) {
            CaptureReply::Failed { reason, .. } => assert_eq!(*reason, expected, "{reply:?}"),
            other => panic!("{other:?}"),
        }
        // Its slot is free again.
        assert_eq!(node.copy.available_permits(), COPY_WORKERS);
    }
}

#[tokio::test]
async fn lanes_refuse_at_once_and_cleanup_never_waits_for_copying() {
    let (node, fake) = setup();
    let gate = Gate::new();
    fake.set("capture", Act::Gated(gate.clone(), Box::new(Act::Echo)));
    let first = binding();
    let mut second = binding();
    second.target = other_target();
    second.operation = Id128::random();
    let a = spawn_call(&node, capture(&first));
    let b = spawn_call(&node, capture(&second));
    until(|| fake.starts("capture") == 2).await;
    // Both copy slots are held: everything else on that lane is refused, not queued.
    let mut third = binding();
    third.target = other_target();
    third.operation = Id128::random();
    assert_eq!(
        error_kind(&call(&node, capture(&third)).await),
        CheckpointErrorKind::Workers
    );
    assert_eq!(
        error_kind(&call(&node, restore(&third.target, Id128::random())).await),
        CheckpointErrorKind::Workers
    );
    // The same checkpoint under another nonce is busy, whatever the lanes.
    let mut again = first.clone();
    again.operation = Id128::random();
    assert_eq!(
        error_kind(&call(&node, capture(&again)).await),
        CheckpointErrorKind::Busy
    );
    assert_eq!(
        error_kind(&call(&node, restore(&target(), Id128::random())).await),
        CheckpointErrorKind::Busy
    );
    // Health, inspection, inventory and removal keep their own lane.
    let CheckpointResponse::Capabilities(caps) =
        call(&node, CheckpointOperation::Capabilities).await
    else {
        panic!()
    };
    assert_eq!((caps.copy_workers_busy, caps.cleanup_workers_busy), (2, 0));
    assert!(matches!(
        inspected(&call(&node, inspect(&target(), None)).await).artifact,
        ArtifactView::Withheld
    ));
    let unrelated = other_target();
    assert!(matches!(
        removed(&call(&node, remove(&unrelated, Id128::random())).await),
        RemoveReply::Absent { .. }
    ));
    assert_eq!(fake.starts("capture"), 2);
    gate.open();
    for handle in [a, b] {
        assert!(matches!(
            captured(&handle.await.unwrap()),
            CaptureReply::Complete { .. }
        ));
    }
    assert_eq!(node.copy.available_permits(), COPY_WORKERS);
}

/// Design 10.1: removal tombstones first, so a capture whose worker still exits 0 after
/// the removal began never publishes, and absence is certified only after its reap.
#[tokio::test]
async fn a_tombstone_stops_late_completion_and_everything_after_it() {
    let (node, fake) = setup();
    let gate = Gate::new();
    fake.set("capture", Act::Late(gate.clone(), Box::new(Act::Echo)));
    let b = binding();
    let capturing = spawn_call(&node, capture(&b));
    until(|| fake.starts("capture") == 1).await;
    let removal = Id128::random();
    let removing = spawn_call(&node, remove(&target(), removal));
    until(|| {
        node.lock()
            .artifacts
            .get(&key(&target()))
            .is_some_and(|a| a.tombstone.is_some())
    })
    .await;
    // Nothing new starts on a tombstoned checkpoint.
    let mut retry = b.clone();
    retry.operation = Id128::random();
    assert_eq!(
        error_kind(&call(&node, capture(&retry)).await),
        CheckpointErrorKind::Conflict
    );
    assert_eq!(
        error_kind(&call(&node, restore(&target(), Id128::random())).await),
        CheckpointErrorKind::Conflict
    );
    let view = call(&node, inspect(&target(), None)).await;
    let view = inspected(&view);
    assert_eq!(view.artifact, ArtifactView::Withheld);
    assert_eq!(view.activity.tombstone, Some(removal));
    assert_eq!(
        view.activity.exclusive,
        Some(ExclusiveOp {
            kind: OpKind::Capture,
            operation: b.operation,
        })
    );
    // No removal ran while the worker could still write.
    assert_eq!(fake.starts("rm"), 0);
    gate.open();
    match captured(&capturing.await.unwrap()) {
        CaptureReply::Failed { reason, detail } => {
            assert_eq!(*reason, Reason::Io);
            assert!(detail.contains("canceled"), "{detail}");
        }
        other => panic!("a late exit 0 was certified: {other:?}"),
    }
    let RemoveReply::Absent { evidence } = removed(&removing.await.unwrap()).clone() else {
        panic!()
    };
    assert_eq!(evidence.evidence.fact, Fact::Absent { existed: true });
    assert!(fake.position("end capture") < fake.position("start rm"));
    assert!(fake.position("start rm") < fake.position("start ls"));
    // Still tombstoned after the daemon's acknowledgment.
    call(
        &node,
        CheckpointOperation::Acknowledge {
            target: target(),
            operation: removal,
        },
    )
    .await;
    assert_eq!(
        error_kind(&call(&node, capture(&retry)).await),
        CheckpointErrorKind::Conflict
    );
}

#[tokio::test]
async fn removal_cancels_readers_and_waits_for_their_reap() {
    let (node, fake) = setup();
    fake.set("create", Act::Gated(Gate::new(), Box::new(Act::Echo)));
    let reader = Id128::random();
    let restoring = spawn_call(&node, restore(&target(), reader));
    until(|| fake.starts("create") == 1).await;
    let view = call(&node, inspect(&target(), Some(reader))).await;
    let view = inspected(&view);
    assert_eq!(view.operation, Some(OperationState::Active));
    assert!(view.activity.readers.contains(&reader));
    let removing = spawn_call(&node, remove(&target(), Id128::random()));
    // The killed create is ambiguous, and so is its copy: a detached shim may read on.
    match restored(&restoring.await.unwrap()) {
        RestoreReply::Ambiguous { evidence, .. } => {
            assert_eq!(copy_of(evidence), CopyOutcome::Unknown)
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        removed(&removing.await.unwrap()),
        RemoveReply::Absent { .. }
    ));
    assert!(fake.position("end create") < fake.position("start rm"));
}

#[tokio::test]
async fn restore_outcomes_name_the_copy_exactly() {
    let preflight = "Error: persistent create rejected before allocation\n\nCaused by:\n    checkpoint_spec_mismatch: the image differs\n";
    let cases = [
        (
            Act::Exit(0, "0123456789abcdef\n".into(), "".into()),
            "created",
            None,
            CopyOutcome::Complete,
        ),
        (
            Act::Exit(124, "".into(), preflight.into()),
            "not_created",
            Some(Reason::SpecMismatch),
            CopyOutcome::NotStarted,
        ),
        (
            Act::Exit(124, "".into(), "Error: no such image\n".into()),
            "not_created",
            Some(Reason::InvalidRequest),
            CopyOutcome::NotStarted,
        ),
        (
            Act::Exit(
                1,
                "".into(),
                "sandbox shim failed during setup: checkpoint_disk_too_small: full\n".into(),
            ),
            "ambiguous",
            Some(Reason::DiskTooSmall),
            CopyOutcome::Unknown,
        ),
        // exit 0 with no valid ID is no proof of anything.
        (
            Act::Exit(0, "not an id\n".into(), "".into()),
            "ambiguous",
            Some(Reason::Io),
            CopyOutcome::Unknown,
        ),
    ];
    for (act, kind, expected, copy) in cases {
        let (node, fake) = setup();
        fake.set("create", act);
        let reader = Id128::random();
        let reply = call(&node, restore(&target(), reader)).await;
        let (seen, reason, evidence) = match restored(&reply) {
            RestoreReply::Created { evidence, .. } => ("created", None, evidence),
            RestoreReply::NotCreated {
                reason, evidence, ..
            } => ("not_created", Some(*reason), evidence),
            RestoreReply::Ambiguous {
                reason, evidence, ..
            } => ("ambiguous", Some(*reason), evidence),
            RestoreReply::Pending => panic!(),
        };
        assert_eq!((seen, reason, copy_of(evidence)), (kind, expected, copy));
        // The artifact was checked before kiln create, which got the fork flag last.
        assert!(fake.position("start inspect") < fake.position("start create"));
        assert_eq!(
            fake.argv("create").last().unwrap(),
            &format!("--from-checkpoint={INSTANCE}/{CHECKPOINT}")
        );
        // Settled: its reader lease is gone and the nonce replays.
        assert!(
            node.lock()
                .artifacts
                .get(&key(&target()))
                .is_none_or(Artifact::idle)
        );
        assert_eq!(call(&node, restore(&target(), reader)).await, reply);
    }
}

#[tokio::test]
async fn restore_reads_nothing_it_cannot_match() {
    let mismatch = record_text(1, 1 << 30).replace(
        "content-sha256 a4a64bb84cfc3abc7a7604ebcafccea446513ab0f2265036c677eda37c8ed3ba",
        &format!("content-sha256 {}", "0".repeat(64)),
    );
    let busy = "kiln-checkpoint-failure 1\nreason checkpoint_corrupt\ndetail object 3\n";
    for (act, expected) in [
        (Act::Exit(0, mismatch, "".into()), Reason::Corrupt),
        (
            Act::Exit(0, record_text(2, 1 << 30), "".into()),
            Reason::Corrupt,
        ),
        (Act::Exit(125, busy.into(), "".into()), Reason::Corrupt),
        (Act::Exit(0, "junk".into(), "".into()), Reason::Io),
    ] {
        let (node, fake) = setup();
        fake.set("inspect", act);
        let reply = call(&node, restore(&target(), Id128::random())).await;
        match restored(&reply) {
            RestoreReply::NotCreated {
                reason, evidence, ..
            } => {
                assert_eq!(*reason, expected);
                assert_eq!(copy_of(evidence), CopyOutcome::NotStarted);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.starts("create"), 0);
    }
}

/// Design 4.1: an unkillable I/O worker keeps its slot, charge and the artifact's
/// dependency; nothing claims cleanup.
#[tokio::test(start_paused = true)]
async fn an_unkillable_worker_keeps_its_slot_and_blocks_absence() {
    let (node, fake) = setup();
    fake.set("capture", Act::Unkillable);
    let b = binding();
    let reply = call_with(&node, capture(&b), 5, &CancellationToken::new()).await;
    assert_eq!(*captured(&reply), CaptureReply::Pending);
    let CheckpointResponse::Capabilities(caps) =
        call(&node, CheckpointOperation::Capabilities).await
    else {
        panic!()
    };
    assert_eq!(caps.copy_workers_busy, 1);
    let reply = call_with(
        &node,
        remove(&target(), Id128::random()),
        10,
        &CancellationToken::new(),
    )
    .await;
    match removed(&reply) {
        RemoveReply::Retained { reason, .. } => assert_eq!(*reason, Reason::Busy),
        other => panic!("{other:?}"),
    }
    assert_eq!(fake.starts("rm"), 0);
    let view = call(&node, inspect(&target(), Some(b.operation))).await;
    assert_eq!(inspected(&view).operation, Some(OperationState::Active));
    let CheckpointResponse::Inventory(inventory) = call(
        &node,
        CheckpointOperation::Inventory {
            instance: target().instance,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(inventory.tracked.len(), 1);
    assert_eq!(
        inventory.tracked[0].activity.exclusive,
        Some(ExclusiveOp {
            kind: OpKind::Capture,
            operation: b.operation,
        })
    );
    assert_eq!(node.copy.available_permits(), COPY_WORKERS - 1);
}

fn process(session_leader: bool, argv: &[&str]) -> ProcessArgs {
    ProcessArgs {
        session_leader,
        argv: argv.iter().map(|a| a.to_string()).collect(),
    }
}

/// An earlier helper epoch's worker, or root's own command, still names the artifact:
/// no absence until it is gone. A restored sandbox's shim does not count.
#[tokio::test]
async fn untracked_processes_block_absence_until_they_are_gone() {
    let (node, fake) = setup();
    let instance = format!("--instance={INSTANCE}");
    let checkpoint = format!("--checkpoint={CHECKPOINT}");
    let source = format!("{INSTANCE}/{CHECKPOINT}");
    fake.set_processes(Some(vec![process(
        false,
        &[
            "/usr/local/bin/kiln",
            "checkpoint",
            "capture",
            &instance,
            &checkpoint,
            "--generation=1",
        ],
    )]));
    let reply = call(&node, remove(&target(), Id128::random())).await;
    assert!(matches!(
        removed(&reply),
        RemoveReply::Retained {
            reason: Reason::Busy,
            ..
        }
    ));
    let CheckpointResponse::Inventory(inventory) = call(
        &node,
        CheckpointOperation::Inventory {
            instance: target().instance,
        },
    )
    .await
    else {
        panic!()
    };
    assert!(!inventory.complete);
    assert_eq!(inventory.untracked_workers, [target().checkpoint]);
    let CheckpointResponse::Capabilities(caps) =
        call(&node, CheckpointOperation::Capabilities).await
    else {
        panic!()
    };
    assert_eq!(caps.untracked_workers, 1);
    // A create CLI in the space-separated form blocks too.
    fake.set_processes(Some(vec![process(
        false,
        &[
            "kiln",
            "create",
            "--image=alpine",
            "--from-checkpoint",
            &source,
        ],
    )]));
    assert!(matches!(
        removed(&call(&node, remove(&target(), Id128::random())).await),
        RemoveReply::Retained { .. }
    ));
    // An unreadable process table proves nothing.
    fake.set_processes(None);
    assert!(matches!(
        removed(&call(&node, remove(&target(), Id128::random())).await),
        RemoveReply::Retained {
            reason: Reason::Io,
            ..
        }
    ));
    // Only a restored sandbox's shim (a session leader) is left: absent.
    fake.set_processes(Some(vec![process(
        true,
        &["kiln", "create", &format!("--from-checkpoint={source}")],
    )]));
    assert!(matches!(
        removed(&call(&node, remove(&target(), Id128::random())).await),
        RemoveReply::Absent { .. }
    ));
}

#[tokio::test]
async fn kiln_failures_keep_the_charge() {
    for (act, expected) in [
        (
            Act::Exit(
                125,
                "kiln-checkpoint-failure 1\nreason checkpoint_busy\ndetail locked\n".into(),
                "".into(),
            ),
            Reason::Busy,
        ),
        (
            Act::Exit(0, "kiln-checkpoint-removed 1\n".into(), "".into()),
            Reason::Io,
        ),
        (Act::SpawnError, Reason::Io),
    ] {
        let (node, fake) = setup();
        fake.set("rm", act);
        match removed(&call(&node, remove(&target(), Id128::random())).await) {
            RemoveReply::Retained { reason, .. } => assert_eq!(*reason, expected),
            other => panic!("{other:?}"),
        }
    }
    // The namespace still lists it after kiln said it removed it.
    let (node, fake) = setup();
    fake.set(
        "ls",
        Act::Exit(
            0,
            format!(
                "kiln-checkpoint-inventory 1\nstaging {INSTANCE} .staging-{CHECKPOINT}-1-00ff\n"
            ),
            "".into(),
        ),
    );
    assert!(matches!(
        removed(&call(&node, remove(&target(), Id128::random())).await),
        RemoveReply::Retained {
            reason: Reason::Io,
            ..
        }
    ));
}

#[tokio::test]
async fn epochs_and_retired_nonces_refuse_before_any_worker() {
    let (node, fake) = setup();
    let mut stale = request(&node, &capture(&binding()));
    stale.helper_epoch = Some(Id128::random());
    let reply = node
        .handle(
            stale,
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .await;
    assert_eq!(error_kind(&reply), CheckpointErrorKind::StaleEpoch);
    // A restarted helper has a new epoch, and the old one's requests are refused.
    let (restarted, _) = setup();
    assert_ne!(restarted.epoch(), node.epoch());
    let reply = restarted
        .handle(
            request(&node, &capture(&binding())),
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .await;
    assert_eq!(error_kind(&reply), CheckpointErrorKind::StaleEpoch);
    // Asking about an unknown nonce retires it: a delayed request can't start later.
    let delayed = Id128::random();
    let view = call(&node, inspect(&target(), Some(delayed))).await;
    assert_eq!(inspected(&view).operation, Some(OperationState::Retired));
    assert_eq!(
        error_kind(&call(&node, restore(&target(), delayed)).await),
        CheckpointErrorKind::Conflict
    );
    let mut b = binding();
    b.operation = delayed;
    assert_eq!(
        error_kind(&call(&node, capture(&b)).await),
        CheckpointErrorKind::Conflict
    );
    assert_eq!(fake.starts("create") + fake.starts("capture"), 0);
    // While the epoch tracks a checkpoint, another generation of it is refused. (Once
    // idle it is forgotten; kiln's record, which names its generation, decides then.)
    fake.set("capture", Act::Gated(Gate::new(), Box::new(Act::Echo)));
    let held = binding();
    let _capturing = spawn_call(&node, capture(&held));
    until(|| fake.starts("capture") == 1).await;
    let mut generation = target();
    generation.generation = 2;
    assert_eq!(
        error_kind(&call(&node, remove(&generation, Id128::random())).await),
        CheckpointErrorKind::Conflict
    );
    assert_eq!(fake.starts("rm"), 0);
}

#[tokio::test]
async fn a_departed_waiter_leaves_the_worker_supervised() {
    let (node, fake) = setup();
    let gate = Gate::new();
    fake.set("capture", Act::Gated(gate.clone(), Box::new(Act::Echo)));
    let b = binding();
    let waiter = CancellationToken::new();
    let handle = {
        let (node, waiter, op) = (node.clone(), waiter.clone(), capture(&b));
        tokio::spawn(async move { call_with(&node, op, 60, &waiter).await })
    };
    until(|| fake.starts("capture") == 1).await;
    waiter.cancel();
    assert_eq!(*captured(&handle.await.unwrap()), CaptureReply::Pending);
    let view = call(&node, inspect(&target(), Some(b.operation))).await;
    assert_eq!(inspected(&view).operation, Some(OperationState::Active));
    gate.open();
    until(|| node.lock().settled.contains_key(&b.operation)).await;
    let view = call(&node, inspect(&target(), Some(b.operation))).await;
    match &inspected(&view).operation {
        Some(OperationState::Settled(reply)) => {
            assert!(matches!(captured(reply), CaptureReply::Complete { .. }))
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(inspected(&view).artifact, ArtifactView::NotListed));
}

#[tokio::test(start_paused = true)]
async fn tombstones_and_records_expire_only_after_their_quiet_period() {
    let (node, _fake) = setup();
    let removal = Id128::random();
    assert!(matches!(
        removed(&call(&node, remove(&target(), removal)).await),
        RemoveReply::Absent { .. }
    ));
    call(
        &node,
        CheckpointOperation::Acknowledge {
            target: target(),
            operation: removal,
        },
    )
    .await;
    let mut late = binding();
    late.operation = Id128::random();
    tokio::time::advance(TOMBSTONE_QUIET - Duration::from_secs(1)).await;
    assert_eq!(
        error_kind(&call(&node, capture(&late)).await),
        CheckpointErrorKind::Conflict
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(node.lock().artifacts.is_empty());
    assert!(node.lock().settled.is_empty());
    // Unacknowledged, a tombstone stays for an hour.
    let other = other_target();
    call(&node, remove(&other, Id128::random())).await;
    tokio::time::advance(TOMBSTONE_QUIET * 2).await;
    assert!(node.lock().artifacts.contains_key(&key(&other)));
    tokio::time::advance(UNACKED_RETENTION).await;
    assert!(node.lock().artifacts.is_empty());
    // The settled table is bounded: full of records it may not drop, new work is refused.
    {
        let mut state = node.lock();
        for _ in 0..MAX_SETTLED {
            state.settled.insert(
                Id128::random(),
                Settled {
                    key: key(&target()),
                    reply: None,
                    at: Instant::now(),
                    acked: false,
                },
            );
        }
    }
    let mut full = binding();
    full.target = other_target();
    assert_eq!(
        error_kind(&call(&node, capture(&full)).await),
        CheckpointErrorKind::Capacity
    );
}

#[tokio::test]
async fn the_inventory_lists_one_instance_within_its_bound() {
    let (node, fake) = setup();
    let [a, b, c, d] = std::array::from_fn::<_, 4, _>(|_| CheckpointId::random());
    let foreign = Id128::random();
    fake.set(
        "ls",
        Act::Exit(
            0,
            format!(
                "kiln-checkpoint-inventory 1\npublished {INSTANCE} {a}\nstaging {INSTANCE} .staging-{b}-1-00ff\n\
                 removing {INSTANCE} .removing-{c}-77-1\nunknown {INSTANCE} stray file\n\
                 published {foreign} {d}\nunknown - junk\n"
            ),
            "".into(),
        ),
    );
    let instance = target().instance;
    let CheckpointResponse::Inventory(inventory) =
        call(&node, CheckpointOperation::Inventory { instance }).await
    else {
        panic!()
    };
    assert!(inventory.complete, "{inventory:?}");
    let mut expected = vec![
        InventoryEntry {
            checkpoint: a,
            kind: ItemKind::Published,
        },
        InventoryEntry {
            checkpoint: b,
            kind: ItemKind::Staging,
        },
        InventoryEntry {
            checkpoint: c,
            kind: ItemKind::Removing,
        },
    ];
    expected.sort_by(|x, y| x.checkpoint.cmp(&y.checkpoint));
    assert_eq!(inventory.entries, expected);
    assert_eq!((inventory.unknown_entries, inventory.other_entries), (1, 2));
    // More than the bound: listed up to it, and incomplete.
    let mut text = String::from("kiln-checkpoint-inventory 1\n");
    for _ in 0..=MAX_INVENTORY_ENTRIES {
        text.push_str(&format!(
            "published {INSTANCE} {}\n",
            CheckpointId::random()
        ));
    }
    fake.set("ls", Act::Exit(0, text, "".into()));
    let CheckpointResponse::Inventory(inventory) =
        call(&node, CheckpointOperation::Inventory { instance }).await
    else {
        panic!()
    };
    assert!(!inventory.complete);
    assert_eq!(inventory.entries.len(), MAX_INVENTORY_ENTRIES);
    // An unreadable listing is never complete.
    for broken in [
        "kiln-checkpoint-inventory 1\npublished x\n",
        "kiln-checkpoint-inventory 2\n",
        "kiln-checkpoint-inventory 1\nstaging - .staging-x\n",
    ] {
        fake.set("ls", Act::Exit(0, broken.into(), "".into()));
        let CheckpointResponse::Inventory(inventory) =
            call(&node, CheckpointOperation::Inventory { instance }).await
        else {
            panic!()
        };
        assert!(
            !inventory.complete && inventory.entries.is_empty(),
            "{broken}"
        );
    }
}

#[tokio::test]
async fn shutdown_kills_and_reaps_every_worker() {
    let (node, fake) = setup();
    fake.set("capture", Act::Gated(Gate::new(), Box::new(Act::Echo)));
    let handle = spawn_call(&node, capture(&binding()));
    until(|| fake.starts("capture") == 1).await;
    node.shutdown().await;
    assert!(matches!(
        captured(&handle.await.unwrap()),
        CaptureReply::Failed { .. }
    ));
    assert_eq!(
        fake.position("end capture"),
        fake.position("start capture") + 2
    );
}

#[test]
fn the_disabled_group_answers_capabilities_only() {
    let CheckpointResponse::Capabilities(caps) = disabled(&CheckpointOperation::Capabilities)
    else {
        panic!()
    };
    assert!(!caps.enabled && !caps.supported && caps.helper_epoch.is_none());
    assert!(
        CheckpointResponse::Capabilities(caps.clone())
            .check(&CheckpointOperation::Capabilities, None)
            .is_ok()
    );
    assert_eq!(
        error_kind(&disabled(&capture(&binding()))),
        CheckpointErrorKind::Disabled
    );
}

#[test]
fn the_kiln_adapter_parses_strictly() {
    use kiln::*;
    let args = |a: &[&str]| -> Vec<String> { a.iter().map(|s| s.to_string()).collect() };
    let i = INSTANCE;
    let c = CHECKPOINT;
    for (argv, named) in [
        (
            args(&[
                "kiln",
                "checkpoint",
                "rm",
                &format!("--instance={i}"),
                &format!("--checkpoint={c}"),
            ]),
            true,
        ),
        (
            args(&[
                "kiln",
                "checkpoint",
                "inspect",
                "--instance",
                i,
                "--checkpoint",
                c,
            ]),
            true,
        ),
        (
            args(&["kiln", "create", &format!("--from-checkpoint={i}/{c}")]),
            true,
        ),
        (args(&["kiln", "checkpoint", "ls"]), false),
        (args(&["kiln", "exec", "--checkpoint", c]), false),
        (
            args(&[
                "kiln",
                "checkpoint",
                "capture",
                "--checkpoint-x=1",
                "--instance",
                i,
            ]),
            false,
        ),
    ] {
        let found = named_artifact(&ProcessArgs {
            session_leader: false,
            argv,
        });
        assert_eq!(found.is_some(), named);
        if let Some((instance, checkpoint)) = found {
            assert_eq!((instance.as_str(), checkpoint.as_str()), (i, c));
        }
    }
    assert_eq!(
        parse_removed("kiln-checkpoint-removed 1\nexisted no\n"),
        Ok(false)
    );
    assert!(parse_removed("kiln-checkpoint-removed 1\nexisted maybe\n").is_err());
    let lines = parse_inventory(&format!(
        "kiln-checkpoint-inventory 1\nstaging {i} .staging-{c}-12-00aa\nunknown - x y\n"
    ))
    .unwrap();
    assert_eq!(lines[0].checkpoint().unwrap().as_str(), c);
    assert_eq!((lines[1].instance, lines[1].name.as_str()), (None, "x y"));
    for bad in [
        "kiln-checkpoint-inventory 1\npublished - cp-x\n",
        "kiln-checkpoint-inventory 1\nfresh {i} {c}\n",
        "kiln-checkpoint-inventory 1\npublished {i} \n",
        "kiln-checkpoint-inventory 1",
    ] {
        let bad = bad.replace("{i}", i).replace("{c}", c);
        assert!(parse_inventory(&bad).is_err(), "{bad}");
    }
    assert_eq!(
        create_reason(
            b"Error: x\n\nCaused by:\n    0: sandbox_unsupported:workspace_checkpoint: old\n"
        ),
        Some(Reason::SandboxUnsupported)
    );
    assert_eq!(create_reason(b"checkpoint_busyness: no\n"), None);
    // The worker arguments are typed: nothing malformed reaches kiln.
    assert!(KilnArgs::checkpoint_capture(i, c, 0, 1 << 30, "ab").is_err());
    assert!(KilnArgs::checkpoint_capture("x", c, 1, 1 << 30, "ab").is_err());
    assert!(KilnArgs::checkpoint_rm(i, "cp-../../etc").is_err());
    assert!(
        KilnArgs::checkpoint_inspect(i, c, true)
            .unwrap()
            .as_slice()
            .ends_with(&["--verify".to_string()])
    );
    assert!(KilnArgs::checkpoint_capture(i, c, 1, 1 << 30, "--ab").is_err());
}

#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They write their
// fixture CLI, spawn and signal their own stray processes and remove their scratch files.
#[allow(clippy::disallowed_methods)]
mod socket;

#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). The root VM test
// copies and removes its own image, sandboxes, artifacts and stray processes.
#[allow(clippy::disallowed_methods)]
mod vm;
