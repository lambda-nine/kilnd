//! Validate and Exec against a scripted relay and ledger, on a paused clock: the B5
//! break-it regressions that need H's own decisions (B5-02, B5-05 to B5-09). A test
//! answers each broker command the way R would, and holds or refuses journal writes.

use super::*;
use kilnd_broker_protocol::message::{ErrorCode, ErrorReply, ProbeReply};
use kilnd_broker_protocol::{BootId, InnerId, WireText};
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

const BOOT: &str = "0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6";
const INNER: &str = "abcd-1";

/// How the scripted ledger answers one kind of write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    Durable,
    Refused,
    /// Never answers: a stalled L or fsync (Daybreak's `stalled_busy`).
    Stall,
}

struct Scripted {
    /// By the record state or phase target the write carries.
    writes: StdMutex<HashMap<String, Write>>,
    journal: StdMutex<Vec<String>>,
    jobs: StdMutex<HashMap<u64, mpsc::UnboundedSender<RelayReport>>>,
    commands: mpsc::UnboundedSender<BrokerCommand>,
    contained: StdMutex<Vec<String>>,
    ended: std::sync::atomic::AtomicBool,
    busy: StdMutex<Option<Id128>>,
    control: Arc<Semaphore>,
    /// B7 RTC-14: the node latch as this host reports it.
    latched: std::sync::atomic::AtomicBool,
    /// Writes held open until the test releases them, then durable.
    holds: StdMutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    /// How many times descriptors were handed to S.
    handed: std::sync::atomic::AtomicUsize,
}

impl Scripted {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<BrokerCommand>) {
        let (commands, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                writes: StdMutex::default(),
                journal: StdMutex::default(),
                jobs: StdMutex::default(),
                commands,
                contained: StdMutex::default(),
                ended: Default::default(),
                busy: StdMutex::default(),
                control: Arc::new(Semaphore::new(1)),
                latched: Default::default(),
                holds: StdMutex::default(),
                handed: Default::default(),
            }),
            rx,
        )
    }

    fn on(&self, what: &str, write: Write) {
        self.writes.lock().unwrap().insert(what.into(), write);
    }

    /// Holds `what` open until the returned handle is notified; then it is durable.
    fn hold(&self, what: &str) -> Arc<tokio::sync::Notify> {
        let release = Arc::new(tokio::sync::Notify::new());
        self.holds
            .lock()
            .unwrap()
            .insert(what.into(), release.clone());
        release
    }

    /// R's report for `job`, as S forwards it; a final one closes the waiter.
    fn report(&self, report: RelayReport) {
        let job = report.job();
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(waiter) = jobs.get(&job) {
            let _ = waiter.send(report.clone());
        }
        if report.is_final() {
            jobs.remove(&job);
        }
    }

    fn contained(&self) -> bool {
        !self.contained.lock().unwrap().is_empty()
    }

    fn journal(&self) -> Vec<String> {
        self.journal.lock().unwrap().clone()
    }
}

fn label(request: &LedgerRequest) -> String {
    match request {
        LedgerRequest::RecordResource {
            record: ResourceRecord::Exec { state, .. },
            ..
        } => format!("record:{state}"),
        LedgerRequest::SetPhase { to, .. } => format!("phase:{to}"),
        other => format!("{other:?}"),
    }
}

impl Host for Scripted {
    fn allocation(&self) -> (Id128, Id128) {
        (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]))
    }

    fn journal(&self, request: LedgerRequest, by: Instant) -> BoxedJournal {
        let what = label(&request);
        let write = self
            .writes
            .lock()
            .unwrap()
            .get(&what)
            .copied()
            .unwrap_or(Write::Durable);
        let held = self.holds.lock().unwrap().get(&what).cloned();
        self.journal.lock().unwrap().push(what);
        let _ = by;
        Box::pin(async move {
            if let Some(release) = held {
                release.notified().await;
            }
            match write {
                Write::Durable => Journaled::Durable,
                Write::Refused => Journaled::Refused,
                Write::Stall => std::future::pending().await,
            }
        })
    }

    fn job(
        &self,
        job: u64,
        command: BrokerCommand,
    ) -> Option<mpsc::UnboundedReceiver<RelayReport>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.jobs.lock().unwrap().insert(job, tx);
        self.commands.send(command).ok()?;
        Some(rx)
    }

    fn forget(&self, job: u64) {
        self.jobs.lock().unwrap().remove(&job);
    }

    fn pending(&self, job: u64) -> bool {
        self.jobs.lock().unwrap().contains_key(&job)
    }

    fn session_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst) || self.contained()
    }

    fn ready(&self) -> Result<(String, String), String> {
        if self.session_ended() {
            return Err("ended".into());
        }
        if let Some(token) = *self.busy.lock().unwrap() {
            return Err(format!("execution {token} is in flight"));
        }
        Ok((BOOT.into(), INNER.into()))
    }

    fn busy(&self) -> Option<Id128> {
        *self.busy.lock().unwrap()
    }

    fn set_busy(&self, token: Id128) -> bool {
        let mut busy = self.busy.lock().unwrap();
        if busy.is_some() {
            return false;
        }
        *busy = Some(token);
        true
    }

    fn clear_busy(&self) {
        *self.busy.lock().unwrap() = None;
    }

    fn control(&self) -> Option<Arc<Semaphore>> {
        Some(self.control.clone())
    }

    fn hand_stdio(&self, _: u64, fds: &[RawFd]) -> bool {
        self.handed.fetch_add(1, Ordering::SeqCst);
        fds.len() == 3
    }

    fn contain(&self, reason: &str) {
        self.contained.lock().unwrap().push(reason.into());
    }

    fn contained(&self) -> Option<bool> {
        self.contained().then_some(true)
    }

    fn latched(&self) -> bool {
        self.latched.load(Ordering::SeqCst)
    }
}

fn stdio() -> [std::os::fd::OwnedFd; 3] {
    let pair = || {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        std::os::fd::OwnedFd::from(a)
    };
    [pair(), pair(), pair()]
}

fn request() -> ExecRequest {
    ExecRequest {
        expected_boot_id: BOOT.into(),
        token: Id128::from_bytes([9; 16]),
        execution_id: "ex-0123456789abcdef".into(),
        argv: vec!["true".into()],
        stdin_bytes: 0,
        max_output: 1 << 20,
    }
}

fn wire(id: Id128) -> kilnd_broker_protocol::Id128 {
    kilnd_broker_protocol::Id128::parse(&id.to_string()).unwrap()
}

fn soon(seconds: u64) -> WireDeadline {
    WireDeadline::from_instant(Instant::now() + Duration::from_secs(seconds))
}

fn facts(kept: u64) -> CaptureFacts {
    CaptureFacts {
        kept,
        total: kept,
        total_known: true,
        truncated: false,
    }
}

fn result(token: Id128, inner: &str, out: u64) -> Box<ExecResult> {
    Box::new(ExecResult {
        token: wire(token),
        finish: Finish::Completed,
        termination: Some(kilnd_broker_protocol::message::Termination::Exited { code: 0 }),
        diagnostic: None,
        stdout: facts(out),
        stderr: facts(0),
        cleanup: Cleanup::GuestCgroupDrained,
        inner_id: InnerId::new(inner).unwrap(),
    })
}

fn exec_job(command: &BrokerCommand) -> u64 {
    match command {
        BrokerCommand::Exec { job, .. } => *job,
        other => panic!("expected Exec, got {other:?}"),
    }
}

fn spawn_exec(
    host: &Arc<Scripted>,
    deadline: WireDeadline,
    waiter: &CancellationToken,
) -> tokio::task::JoinHandle<ExecReply> {
    let host = host.clone();
    let waiter = waiter.clone();
    tokio::spawn(async move { exec(host, request(), stdio(), deadline, waiter).await })
}

/// The happy path still returns READY and journals in order.
#[tokio::test(start_paused = true)]
async fn a_delivered_result_with_drain_evidence_is_reusable() {
    let (host, mut commands) = Scripted::new();
    let waiter = CancellationToken::new();
    let task = spawn_exec(&host, soon(60), &waiter);
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    host.report(RelayReport::Executed {
        job,
        result: result(Id128::from_bytes([9; 16]), INNER, 3),
        delivered: true,
        stdout_delivered: 3,
        stderr_delivered: 0,
    });
    let reply = task.await.unwrap();
    assert!(reply.reusable && reply.dispatched, "{reply:?}");
    assert!(!host.contained());
    assert_eq!(
        host.journal(),
        [
            "record:intent",
            "phase:exec_intent",
            "record:busy",
            "phase:busy",
            "record:idle",
            "phase:ready"
        ]
    );
}

/// B5-02 (Daybreak's `stalled_busy`): after `Accepted`, BUSY stalls forever and the
/// caller cancels. The VM is retired at once, not after the stall.
#[tokio::test(start_paused = true)]
async fn b5_02_a_stalled_busy_write_never_blocks_cancellation() {
    for trigger in ["cancel", "deadline", "session"] {
        let (host, mut commands) = Scripted::new();
        host.on("record:busy", Write::Stall);
        let waiter = CancellationToken::new();
        let began = Instant::now();
        let task = spawn_exec(&host, soon(3), &waiter);
        let job = exec_job(&commands.recv().await.unwrap());
        host.report(RelayReport::Accepted {
            job,
            token: wire(Id128::from_bytes([9; 16])),
        });
        tokio::task::yield_now().await;
        match trigger {
            "cancel" => waiter.cancel(),
            // The deadline passes on its own.
            "deadline" => {}
            // S or V died: the session watch fires.
            _ => host.ended.store(true, Ordering::SeqCst),
        }
        let reply = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap_or_else(|_| panic!("{trigger}: the execution stayed blocked"))
            .unwrap();
        assert!(host.contained(), "{trigger}: never contained");
        assert!(!reply.reusable && reply.dispatched, "{trigger}: {reply:?}");
        assert_eq!(reply.cleanup, ExecCleanup::VmStopped, "{trigger}");
        // Cancel's two seconds plus containment: bounded, nowhere near a stall.
        assert!(
            began.elapsed() <= Duration::from_secs(6),
            "{trigger}: {:?}",
            began.elapsed()
        );
        match trigger {
            "cancel" => assert_eq!(reply.finish, WireFinishFc::Canceled),
            "deadline" => assert_eq!(reply.finish, WireFinishFc::TimedOut),
            _ => assert!(matches!(reply.finish, WireFinishFc::Failed(_))),
        }
    }
}

/// B5-02: a BUSY write that never answers is itself uncertainty: with no cancel and a
/// long deadline, the VM is retired within the write's bound.
#[tokio::test(start_paused = true)]
async fn b5_02_a_busy_write_past_its_bound_retires_the_vm() {
    let (host, mut commands) = Scripted::new();
    host.on("phase:busy", Write::Stall);
    let waiter = CancellationToken::new();
    let began = Instant::now();
    let task = spawn_exec(&host, soon(3600), &waiter);
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    let reply = task.await.unwrap();
    assert!(host.contained());
    assert!(!reply.reusable);
    assert!(began.elapsed() <= LEDGER_WRITE + SETTLE + Duration::from_secs(1));
    assert!(
        host.contained.lock().unwrap()[0].contains("ledger stalled"),
        "{:?}",
        host.contained.lock().unwrap()
    );
}

/// B5-02: an EXEC_INTENT whose outcome is unknown retires the VM before anything is
/// dispatched; a refused one leaves it reusable.
#[tokio::test(start_paused = true)]
async fn b5_02_an_unanswered_exec_intent_retires_without_dispatch() {
    let (host, mut commands) = Scripted::new();
    host.on("phase:exec_intent", Write::Stall);
    let reply = spawn_exec(&host, soon(60), &CancellationToken::new())
        .await
        .unwrap();
    assert!(host.contained());
    assert!(!reply.reusable && !reply.dispatched, "{reply:?}");
    assert!(commands.try_recv().is_err(), "nothing was sent to S");

    let (host, mut commands) = Scripted::new();
    host.on("record:intent", Write::Refused);
    let reply = spawn_exec(&host, soon(60), &CancellationToken::new())
        .await
        .unwrap();
    assert!(!host.contained());
    assert!(reply.reusable && !reply.dispatched, "{reply:?}");
    assert!(commands.try_recv().is_err());
}

/// B5-06: a well-formed Result about another inner sandbox is a protocol failure.
#[tokio::test(start_paused = true)]
async fn b5_06_a_result_for_another_inner_sandbox_retires_the_vm() {
    let (host, mut commands) = Scripted::new();
    let task = spawn_exec(&host, soon(60), &CancellationToken::new());
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    host.report(RelayReport::Executed {
        job,
        result: result(Id128::from_bytes([9; 16]), "ffff-9", 0),
        delivered: true,
        stdout_delivered: 0,
        stderr_delivered: 0,
    });
    let reply = task.await.unwrap();
    assert!(host.contained());
    assert!(!reply.reusable, "{reply:?}");
    assert!(matches!(&reply.finish, WireFinishFc::Failed(d) if d.kind == Kind::Protocol));
}

/// B5-07: a guest protocol violation before dispatch retires the VM though nothing
/// ran; only a local failure such as short stdin restores READY.
#[tokio::test(start_paused = true)]
async fn b5_07_pre_dispatch_guest_violations_retire_and_local_failures_do_not() {
    let guest = [
        RelayReport::Failed {
            job: 0,
            reason: "the guest booted again: its boot ID changed".into(),
            reach: Reach::Guest,
        },
        RelayReport::Refused {
            job: 0,
            error: ErrorReply {
                code: ErrorCode::Admission,
                state: BrokerState::Faulted,
                message: WireText::narrow("faulted").0,
            },
            reach: Reach::Guest,
        },
    ];
    for template in guest {
        let (host, mut commands) = Scripted::new();
        let task = spawn_exec(&host, soon(60), &CancellationToken::new());
        let job = exec_job(&commands.recv().await.unwrap());
        let report = match template {
            RelayReport::Failed { reason, reach, .. } => RelayReport::Failed { job, reason, reach },
            RelayReport::Refused { error, reach, .. } => RelayReport::Refused { job, error, reach },
            _ => unreachable!(),
        };
        host.report(report);
        let reply = task.await.unwrap();
        assert!(host.contained());
        assert!(!reply.reusable && !reply.dispatched, "{reply:?}");
        assert_eq!(reply.stdout, empty_capture(), "nothing ran");
        // Nothing was dispatched: no Cancel to a guest that broke the protocol.
        assert!(commands.try_recv().is_err());
    }
    let (host, mut commands) = Scripted::new();
    let task = spawn_exec(&host, soon(60), &CancellationToken::new());
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Failed {
        job,
        reason: "stdin: expected 3 bytes, observed 1".into(),
        reach: Reach::Local,
    });
    let reply = task.await.unwrap();
    assert!(!host.contained());
    assert!(reply.reusable && !reply.dispatched, "{reply:?}");
    assert_eq!(host.journal()[2..], ["record:undispatched", "phase:ready"]);
}

/// B5-03 at H: a failure whose reach is uncertain (a torn S→R frame) is never
/// treated as undispatched.
#[tokio::test(start_paused = true)]
async fn b5_03_an_uncertain_dispatch_failure_retires_the_vm() {
    let (host, mut commands) = Scripted::new();
    let task = spawn_exec(&host, soon(60), &CancellationToken::new());
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Failed {
        job,
        reason: "worker frame write deadline after a partial frame".into(),
        reach: Reach::Dispatched,
    });
    let reply = task.await.unwrap();
    assert!(host.contained());
    assert!(!reply.reusable && reply.dispatched, "{reply:?}");
    assert!(!host.journal().contains(&"record:undispatched".to_string()));
}

/// B5-08: a connection that fails before Result claims nothing about output, and a
/// partly delivered output reports the bytes delivered, truncated.
#[tokio::test(start_paused = true)]
async fn b5_08_capture_evidence_is_never_fabricated() {
    let (host, mut commands) = Scripted::new();
    let task = spawn_exec(&host, soon(60), &CancellationToken::new());
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    host.report(RelayReport::Failed {
        job,
        reason: "EOF before Result".into(),
        reach: Reach::Dispatched,
    });
    let reply = task.await.unwrap();
    assert!(!reply.stdout.known && !reply.stderr.known, "{reply:?}");

    let (host, mut commands) = Scripted::new();
    let task = spawn_exec(&host, soon(60), &CancellationToken::new());
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    host.report(RelayReport::Executed {
        job,
        result: result(Id128::from_bytes([9; 16]), INNER, 1000),
        delivered: false,
        stdout_delivered: 400,
        stderr_delivered: 0,
    });
    let reply = task.await.unwrap();
    assert!(host.contained() && !reply.reusable);
    assert_eq!(reply.stdout.kept, 400, "{reply:?}");
    assert!(reply.stdout.truncated);
    assert_eq!(reply.stdout.total, 1000);
}

fn probe_job(command: &BrokerCommand) -> u64 {
    match command {
        BrokerCommand::Probe { job, .. } => *job,
        other => panic!("expected Probe, got {other:?}"),
    }
}

fn idle(job: u64) -> RelayReport {
    RelayReport::Probed {
        job,
        reply: ProbeReply {
            boot_id: BootId::new(BOOT).unwrap(),
            inner_id: InnerId::new(INNER).unwrap(),
            state: BrokerState::Idle,
            active: None,
        },
    }
}

/// B5-05: a second Validate waits for the control slot instead of reaching R's busy
/// channel; R's local refusal is never a breach; a probe holding the slot delays an
/// Exec's admission, so the probe never sees our own execution.
#[tokio::test(start_paused = true)]
async fn b5_05_control_operations_are_serialized_per_allocation() {
    let (host, mut commands) = Scripted::new();
    let first = tokio::spawn(validate(host.clone(), BOOT.into(), INNER.into(), soon(5)));
    let one = probe_job(&commands.recv().await.unwrap());
    let second = tokio::spawn(validate(host.clone(), BOOT.into(), INNER.into(), soon(5)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(commands.try_recv().is_err(), "the second probe waited");
    host.report(idle(one));
    assert!(matches!(first.await.unwrap(), ValidateReply::Ready { .. }));
    let two = probe_job(&commands.recv().await.unwrap());
    host.report(idle(two));
    assert!(matches!(second.await.unwrap(), ValidateReply::Ready { .. }));
    assert!(!host.contained());

    // R's own "channel busy" refusal is local scheduling: Unknown, never containment.
    let task = tokio::spawn(validate(host.clone(), BOOT.into(), INNER.into(), soon(5)));
    let job = probe_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Failed {
        job,
        reason: "that channel already has a job".into(),
        reach: Reach::Local,
    });
    assert!(matches!(task.await.unwrap(), ValidateReply::Unknown { .. }));
    assert!(!host.contained());

    // Probe in flight, then an Exec: the Exec is admitted only after the probe ends.
    let probe = tokio::spawn(validate(host.clone(), BOOT.into(), INNER.into(), soon(5)));
    let job = probe_job(&commands.recv().await.unwrap());
    let task = spawn_exec(&host, soon(60), &CancellationToken::new());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(host.busy().is_none(), "Exec waited for the probe");
    assert!(commands.try_recv().is_err());
    host.report(idle(job));
    assert!(matches!(probe.await.unwrap(), ValidateReply::Ready { .. }));
    let job = exec_job(&commands.recv().await.unwrap());
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    host.report(RelayReport::Executed {
        job,
        result: result(Id128::from_bytes([9; 16]), INNER, 0),
        delivered: true,
        stdout_delivered: 0,
        stderr_delivered: 0,
    });
    assert!(task.await.unwrap().reusable);
    assert!(!host.contained());

    // A queued Validate whose deadline passes is ControlBusy, not a breach.
    let held = host.control.clone().try_acquire_owned().unwrap();
    let reply = validate(host.clone(), BOOT.into(), INNER.into(), soon(1)).await;
    assert_eq!(reply, ValidateReply::ControlBusy);
    drop(held);
    assert!(!host.contained());
}

/// B5-09: a malformed Hello that R establishes after Validate's deadline still
/// retires the VM, and the control slot stays held until R's job ends.
#[tokio::test(start_paused = true)]
async fn b5_09_a_late_probe_failure_is_still_recorded() {
    let (host, mut commands) = Scripted::new();
    let reply = {
        let task = tokio::spawn(validate(host.clone(), BOOT.into(), INNER.into(), soon(1)));
        let job = probe_job(&commands.recv().await.unwrap());
        let reply = task.await.unwrap();
        assert!(matches!(reply, ValidateReply::Unknown { .. }), "{reply:?}");
        assert!(!host.contained());
        assert!(
            host.control.clone().try_acquire_owned().is_err(),
            "the slot stays with the late probe"
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        host.report(RelayReport::Failed {
            job,
            reason: "malformed HelloReply".into(),
            reach: Reach::Guest,
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        reply
    };
    let _ = reply;
    assert!(host.contained(), "the late breach retired the VM");
    assert!(host.control.clone().try_acquire_owned().is_ok());

    // A relay that never finishes its probe is itself a breach once its bound passes.
    let (host, mut commands) = Scripted::new();
    let reply = validate(host.clone(), BOOT.into(), INNER.into(), soon(1)).await;
    let _ = commands.recv().await.unwrap();
    assert!(matches!(reply, ValidateReply::Unknown { .. }));
    tokio::time::sleep(LATE_PROBE + Duration::from_secs(1)).await;
    assert!(host.contained());
}

/// B6: a session the helper can't run a command in again (fenced, stopped, or never
/// supervised by this helper after a restart) is refused before anything is journaled
/// or sent, and is not reusable, so the daemon stops treating it as READY. Another
/// execution in flight is transient and keeps the session.
#[tokio::test(start_paused = true)]
async fn b6_an_unsupervised_session_is_refused_and_not_reusable() {
    let (host, mut commands) = Scripted::new();
    host.ended.store(true, std::sync::atomic::Ordering::SeqCst);
    let reply = spawn_exec(&host, soon(60), &CancellationToken::new())
        .await
        .unwrap();
    assert!(!reply.reusable && !reply.dispatched, "{reply:?}");
    assert_eq!(reply.cleanup, ExecCleanup::NoChildStarted);
    assert!(host.journal().is_empty(), "nothing was journaled");
    assert!(commands.try_recv().is_err(), "nothing was sent");

    let (host, mut commands) = Scripted::new();
    *host.busy.lock().unwrap() = Some(Id128::random());
    let reply = spawn_exec(&host, soon(60), &CancellationToken::new())
        .await
        .unwrap();
    assert!(reply.reusable && !reply.dispatched, "{reply:?}");
    assert!(commands.try_recv().is_err());
}

/// B7 RTC-14 (B7 M1 break-it finding 2): Exec rechecks the node latch after its
/// EXEC_INTENT write and immediately before the descriptors and the broker Exec. Held
/// at the write, latched, then released: nothing is dispatched and the VM, whose
/// journal now says EXEC_INTENT, is retired rather than reused.
#[tokio::test(start_paused = true)]
async fn b7_rtc14_a_latch_during_exec_intent_dispatches_nothing_and_retires_the_vm() {
    let (host, mut commands) = Scripted::new();
    let release = host.hold("phase:exec_intent");
    let waiter = CancellationToken::new();
    let task = spawn_exec(&host, soon(60), &waiter);
    while !host.journal().iter().any(|w| w == "phase:exec_intent") {
        tokio::task::yield_now().await;
    }
    // The latch linearizes while EXEC_INTENT is held; then the write becomes durable.
    host.latched.store(true, Ordering::SeqCst);
    release.notify_one();
    let reply = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the execution answered")
        .unwrap();
    assert!(!reply.dispatched && !reply.reusable, "{reply:?}");
    assert!(matches!(reply.finish, WireFinishFc::Failed(_)), "{reply:?}");
    assert_eq!(reply.cleanup, ExecCleanup::VmStopped, "{reply:?}");
    assert!(host.contained(), "the VM was retired");
    assert_eq!(host.handed.load(Ordering::SeqCst), 0, "no descriptor reached S");
    assert!(commands.try_recv().is_err(), "no broker Exec was sent");
    let journal = host.journal();
    assert!(!journal.iter().any(|w| w == "record:busy" || w == "phase:busy"), "{journal:?}");
}

/// The control for the test above: unlatched, the recheck lets the execution hand its
/// descriptors over once and run to a reusable result.
#[tokio::test(start_paused = true)]
async fn b7_rtc14_an_unlatched_exec_still_dispatches_after_the_recheck() {
    let (host, mut commands) = Scripted::new();
    let waiter = CancellationToken::new();
    let task = spawn_exec(&host, soon(60), &waiter);
    let job = exec_job(&commands.recv().await.unwrap());
    assert_eq!(host.handed.load(Ordering::SeqCst), 1);
    host.report(RelayReport::Accepted {
        job,
        token: wire(Id128::from_bytes([9; 16])),
    });
    host.report(RelayReport::Executed {
        job,
        result: result(Id128::from_bytes([9; 16]), INNER, 0),
        delivered: true,
        stdout_delivered: 0,
        stderr_delivered: 0,
    });
    let reply = task.await.unwrap();
    assert!(reply.dispatched && reply.reusable, "{reply:?}");
}
