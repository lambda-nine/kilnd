//! H's B5 operations on a READY allocation: Validate and Exec (sections 5.5 and 6.1).
//!
//! Exec journals EXEC_INTENT (`ready -> exec_intent` and an `exec` record carrying the
//! token, public execution ID and boot ID) **before** any Exec byte can be sent, and
//! BUSY on the broker's acceptance. Only a fully validated, delivered result with the
//! guest core's own cleanup evidence returns the allocation to READY. Every other
//! ending after dispatch (timeout, the caller's disconnect, a protocol or transport
//! failure, a guest-side timeout or cancel, an uncertain cleanup, a ledger that does
//! not answer) is an interruption: Cancel on the reserved control channel, at most two
//! seconds for the guest to settle, then the existing stop fence and K's kill of the
//! `vm` subtree. The answer is then `reusable = false`; it is `VmStopped` only once K
//! proved the subtree gone. The caller's disconnect never drops this: the work runs on
//! its own task.
//!
//! B5 break-it corrections:
//!
//! - **Containment is always polled (B5-02).** No ledger call is awaited inside the
//!   execution's `select!`: BUSY is its own future polled beside cancellation, the
//!   deadline and the session watch, and every journal write is bounded. A write that
//!   does not become durable within its bound is uncertainty and retires the VM through
//!   the stop fence and K, which need no ledger.
//! - **Pre-dispatch split (B5-07).** Only a local, guest-independent failure before
//!   dispatch ([`Reach::Local`]) restores READY. A guest that broke the session protocol
//!   is retired even though nothing ran.
//! - **One control operation at a time (B5-05).** Each allocation's control slot is
//!   held by a Probe until R's job ends, and Exec admission waits for it, so a Probe
//!   never races our own Exec and a second Validate never reaches R's busy channel.
//! - **A late probe failure still counts (B5-09)**, the Result's inner sandbox is
//!   checked (B5-06), and capture evidence is never fabricated (B5-08).
//!
//! The logic is written against [`Host`], so the unit tests drive it with a scripted
//! relay and ledger; [`Node`] implements it for one allocation.

use super::broker::{BrokerCommand, Reach, RelayReport};
use super::supervisor::ResourceRecord;
use super::*;
use crate::helper::protocol::{CaptureInfo, ExecCleanup, ExecReply, ValidateReply, WireFinishFc};
use crate::model::{CommandStatus, RuntimeDiagnostic, RuntimeErrorKind as Kind, RuntimeStage};
use kilnd_broker_protocol::message::{
    BrokerState, Cancel, CancelReason, CaptureFacts, Cleanup, Exec, ExecResult, Finish,
};
use std::future::Future;
use std::pin::Pin;
use tokio::sync::Semaphore;

static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

/// The cooperative settlement window after Cancel, before the stop barrier.
const SETTLE: Duration = Duration::from_secs(2);
/// How long an interrupted Exec waits for K's proof before answering without it.
const STOP_PROOF: Duration = Duration::from_secs(5);
/// Every journal write on the Validate and Exec paths is answered within this, or
/// counts as uncertain (B5-02).
pub(super) const LEDGER_WRITE: Duration = Duration::from_secs(5);
/// How long after Validate's deadline its probe job may still report (B5-09). R's
/// connect and Hello stages take at most six seconds from the job's start.
pub(super) const LATE_PROBE: Duration = Duration::from_secs(10);

fn diagnostic(kind: Kind, stage: RuntimeStage, message: impl Into<String>) -> RuntimeDiagnostic {
    RuntimeDiagnostic::new(kind, stage, message)
}

/// Nothing ran: exactly zero bytes, known.
fn empty_capture() -> CaptureInfo {
    CaptureInfo {
        kept: 0,
        total: 0,
        known: true,
        truncated: false,
    }
}

/// The command may have run, but no validated Result arrived (B5-08): no claim about
/// its output at all, and certainly not "known zero".
fn unknown_capture() -> CaptureInfo {
    CaptureInfo {
        kept: 0,
        total: 0,
        known: false,
        truncated: false,
    }
}

fn capture(facts: &CaptureFacts) -> CaptureInfo {
    CaptureInfo {
        kept: facts.kept as usize,
        total: facts.total,
        known: facts.total_known,
        truncated: facts.truncated,
    }
}

/// A validated Result whose output only partly reached the caller (B5-08): the bytes
/// actually delivered, marked truncated.
fn delivered_capture(facts: &CaptureFacts, delivered: u64) -> CaptureInfo {
    CaptureInfo {
        kept: delivered.min(facts.kept) as usize,
        total: facts.total,
        known: facts.total_known,
        truncated: true,
    }
}

/// Refused before anything was journaled or sent: the VM is untouched and reusable.
fn refused(kind: Kind, message: impl Into<String>) -> ExecReply {
    ExecReply {
        finish: WireFinishFc::Failed(diagnostic(kind, RuntimeStage::Validate, message)),
        status: None,
        stdout: empty_capture(),
        stderr: empty_capture(),
        cleanup: ExecCleanup::NoChildStarted,
        reusable: true,
        dispatched: false,
    }
}

/// Refused before anything was journaled or sent, because this session can never run
/// another command: fenced, stopped, unsupervised (a restarted helper never supervised
/// it), booted again or its supervisor gone. Nothing reached the guest, but unlike
/// `refused` this is not reusable (B6), so the daemon stops sending commands and the
/// session waits, charged, for Delete.
fn unusable(kind: Kind, message: impl Into<String>) -> ExecReply {
    ExecReply {
        reusable: false,
        ..refused(kind, message)
    }
}

/// `ready()`'s refusal: another execution in flight is transient and keeps the session;
/// anything else means it can't run a command again.
fn not_ready<H: Host + ?Sized>(host: &H, reason: String) -> ExecReply {
    if host.busy().is_some() {
        refused(Kind::Busy, reason)
    } else {
        unusable(Kind::Unavailable, reason)
    }
}

/// How the interruption is reported once the VM is retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interrupted {
    TimedOut,
    Canceled,
    Failed(Kind),
}

/// One journal write's answer. Only `Durable` is progress; `Refused` means L answered
/// and changed nothing; `Unknown` means no answer within the bound, so the write may
/// still commit later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Journaled {
    Durable,
    Refused,
    Unknown,
}

pub(super) type BoxedJournal = Pin<Box<dyn Future<Output = Journaled> + Send>>;
pub(super) type BoxedLatch = Pin<Box<dyn Future<Output = bool> + Send>>;

/// What Validate and Exec need from H for one allocation.
pub(super) trait Host: Send + Sync + 'static {
    /// The instance and allocation the ledger records name.
    fn allocation(&self) -> (Id128, Id128);
    /// One journal write, answered by `by` (`Unknown` if not).
    fn journal(&self, request: LedgerRequest, by: Instant) -> BoxedJournal;
    /// Registers a waiter for `job`'s relay reports and sends its command to S; `None`
    /// if S cannot take it.
    fn job(&self, job: u64, command: BrokerCommand)
    -> Option<mpsc::UnboundedReceiver<RelayReport>>;
    fn forget(&self, job: u64);
    /// The job's waiter is still registered: R has not sent its final report.
    fn pending(&self, job: u64) -> bool;
    /// The boot can no longer answer: fenced, S gone or V gone.
    fn session_ended(&self) -> bool;
    /// The journaled boot and inner sandbox, if READY and reusable.
    fn ready(&self) -> Result<(String, String), String>;
    fn busy(&self) -> Option<Id128>;
    /// Marks `token` in flight; false if another one is.
    fn set_busy(&self, token: Id128) -> bool;
    fn clear_busy(&self);
    /// The allocation's control slot (B5-05).
    fn control(&self) -> Option<Arc<Semaphore>>;
    /// Hands an execution's three stdio descriptors to S, tagged with `job`.
    fn hand_stdio(&self, job: u64, fds: &[RawFd]) -> bool;
    /// The stop fence and K's kill, without the ledger (section 4.4's emergency path).
    fn contain(&self, reason: &str);
    /// K's verdict once dispatched: `Some(true)` is proof the subtree is gone.
    fn contained(&self) -> Option<bool>;
    /// B7 RTC-14: forward effects are latched node-wide, once any lost ledger answer
    /// is consumed (recheck R1); still held at `until`, latched.
    fn latched(&self, until: Instant) -> BoxedLatch;
}

/// One allocation of this node, as [`Host`].
pub(super) struct NodeHost {
    node: Arc<Node>,
    key: AllocationKey,
}

impl Host for NodeHost {
    fn allocation(&self) -> (Id128, Id128) {
        (self.key.instance, self.key.allocation)
    }

    fn journal(&self, request: LedgerRequest, by: Instant) -> BoxedJournal {
        let node = self.node.clone();
        Box::pin(async move {
            let deadline_ns = workers::monotonic_ns()
                .saturating_add(by.saturating_duration_since(Instant::now()).as_nanos() as u64);
            match tokio::time::timeout_at(by, node.ledger_call(Lane::Normal, &request, deadline_ns))
                .await
            {
                Ok(Ok(LedgerReply::Generation(_))) => Journaled::Durable,
                Ok(Ok(
                    LedgerReply::Failed { .. }
                    | LedgerReply::Expired
                    | LedgerReply::Unavailable { .. },
                ))
                | Ok(Err(CallError::Full)) => Journaled::Refused,
                _ => Journaled::Unknown,
            }
        })
    }

    fn job(
        &self,
        job: u64,
        command: BrokerCommand,
    ) -> Option<mpsc::UnboundedReceiver<RelayReport>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut supervisors = self.node.supervisors.lock().unwrap();
        let entry = supervisors.get_mut(&self.key)?;
        entry.jobs.insert(job, tx);
        if !entry.channel.notify(&SupervisorCommand::Broker(command)) {
            entry.jobs.remove(&job);
            return None;
        }
        Some(rx)
    }

    fn forget(&self, job: u64) {
        if let Some(entry) = self.node.supervisors.lock().unwrap().get_mut(&self.key) {
            entry.jobs.remove(&job);
        }
    }

    fn pending(&self, job: u64) -> bool {
        self.node
            .supervisors
            .lock()
            .unwrap()
            .get(&self.key)
            .is_some_and(|entry| entry.jobs.contains_key(&job))
    }

    fn session_ended(&self) -> bool {
        self.node
            .supervisors
            .lock()
            .unwrap()
            .get(&self.key)
            .is_none_or(|entry| {
                entry.stop_fenced || entry.exit.is_some() || entry.vm_gone || entry.revoked
            })
    }

    fn ready(&self) -> Result<(String, String), String> {
        if !self.node.reusable_dispatch(self.key) {
            return Err("the allocation is fenced, stopped or unsupervised".into());
        }
        let supervisors = self.node.supervisors.lock().unwrap();
        let entry = supervisors
            .get(&self.key)
            .ok_or_else(|| "no supervisor for this allocation".to_string())?;
        if let Some(token) = entry.busy {
            return Err(format!("execution {token} is in flight"));
        }
        entry
            .ready
            .clone()
            .ok_or_else(|| "the allocation is not READY".to_string())
    }

    fn busy(&self) -> Option<Id128> {
        self.node
            .supervisors
            .lock()
            .unwrap()
            .get(&self.key)
            .and_then(|entry| entry.busy)
    }

    fn set_busy(&self, token: Id128) -> bool {
        match self.node.supervisors.lock().unwrap().get_mut(&self.key) {
            Some(entry) if entry.busy.is_none() => {
                entry.busy = Some(token);
                true
            }
            _ => false,
        }
    }

    fn clear_busy(&self) {
        if let Some(entry) = self.node.supervisors.lock().unwrap().get_mut(&self.key) {
            entry.busy = None;
        }
    }

    fn control(&self) -> Option<Arc<Semaphore>> {
        self.node
            .supervisors
            .lock()
            .unwrap()
            .get(&self.key)
            .map(|entry| entry.control.clone())
    }

    fn hand_stdio(&self, job: u64, fds: &[RawFd]) -> bool {
        let descriptors = self
            .node
            .supervisors
            .lock()
            .unwrap()
            .get(&self.key)
            .and_then(|entry| entry.descriptors.clone());
        descriptors.is_some_and(|socket| super::broker::relay::send_fds(&socket, job, fds).is_ok())
    }

    fn contain(&self, reason: &str) {
        self.node.contain_allocation(self.key, reason);
    }

    fn contained(&self) -> Option<bool> {
        self.node
            .supervisors
            .lock()
            .unwrap()
            .get(&self.key)
            .and_then(|entry| entry.contained)
    }

    fn latched(&self, until: Instant) -> BoxedLatch {
        let node = self.node.clone();
        Box::pin(async move { node.latched_once_answered(until).await })
    }
}

impl Node {
    /// Validate (section 6.1) on this allocation; see [`validate`].
    pub(super) async fn validate_op(
        self: &Arc<Self>,
        key: AllocationKey,
        expected_boot_id: String,
        expected_inner_id: String,
        deadline: WireDeadline,
    ) -> ValidateReply {
        let host = Arc::new(NodeHost {
            node: self.clone(),
            key,
        });
        validate(host, expected_boot_id, expected_inner_id, deadline).await
    }

    /// Exec (sections 5.4, 5.5) on this allocation; see [`exec`]. `stdio` are the
    /// helper-side ends of the three pairs already handed to the caller.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn exec_op(
        self: Arc<Self>,
        key: AllocationKey,
        expected_boot_id: String,
        token: Id128,
        execution_id: String,
        argv: Vec<String>,
        stdin_bytes: usize,
        max_output: usize,
        stdio: [std::os::fd::OwnedFd; 3],
        deadline: WireDeadline,
        waiter: CancellationToken,
    ) -> ExecReply {
        let host = Arc::new(NodeHost { node: self, key });
        let request = ExecRequest {
            expected_boot_id,
            token,
            execution_id,
            argv,
            stdin_bytes,
            max_output,
        };
        exec(host, request, stdio, deadline, waiter).await
    }
}

fn next_job() -> u64 {
    NEXT_JOB.fetch_add(1, Ordering::Relaxed)
}

/// What a probe report means. Only a local scheduling refusal or a session that ended
/// under it is not a breach; everything else that is not an idle broker on the
/// journaled boot and inner sandbox retires the VM.
fn judge_probe<H: Host>(
    host: &H,
    report: Option<RelayReport>,
    boot: &str,
    inner: &str,
) -> ValidateReply {
    match report {
        Some(RelayReport::Probed { reply, .. })
            if reply.state == BrokerState::Idle
                && reply.boot_id.as_str() == boot
                && reply.inner_id.as_str() == inner
                && reply.active.is_none() =>
        {
            ValidateReply::Ready {
                boot_id: boot.into(),
                inner_id: inner.into(),
            }
        }
        Some(RelayReport::Probed { reply, .. }) => {
            host.contain("the broker is not idle with no execution");
            ValidateReply::Unknown {
                reason: format!("the broker reported {:?}", reply.state),
            }
        }
        Some(RelayReport::Refused { error, .. }) => {
            host.contain("the broker refused a probe");
            ValidateReply::Unknown {
                reason: format!("the broker refused: {}", error.message),
            }
        }
        // A local scheduling refusal is never a broker breach (B5-05).
        Some(RelayReport::Failed {
            reason,
            reach: Reach::Local,
            ..
        }) => ValidateReply::Unknown { reason },
        Some(RelayReport::Failed { reason, .. }) => {
            host.contain(&format!("probe failed: {reason}"));
            ValidateReply::Unknown { reason }
        }
        Some(other) => {
            host.contain("the relay answered a probe with another report");
            ValidateReply::Unknown {
                reason: format!("unexpected relay report {other:?}"),
            }
        }
        None => {
            if !host.session_ended() {
                host.contain("a probe's waiter closed without its report");
            }
            ValidateReply::Unknown {
                reason: "the supervisor ended before the probe answered".into(),
            }
        }
    }
}

/// Validate (section 6.1): process and journal state, then a broker Probe on the
/// reserved control channel. During an execution the recorded busy state answers.
/// A failed probe never reads as absence; any broker breach retires the VM, even one
/// that arrives after Validate's own deadline (B5-09).
pub(super) async fn validate<H: Host>(
    host: Arc<H>,
    expected_boot_id: String,
    expected_inner_id: String,
    deadline: WireDeadline,
) -> ValidateReply {
    if let Some(execution_token) = host.busy() {
        return ValidateReply::Busy { execution_token };
    }
    let (boot, inner) = match host.ready() {
        Ok(session) => session,
        Err(reason) => return ValidateReply::Unknown { reason },
    };
    if boot != expected_boot_id || inner != expected_inner_id {
        return ValidateReply::Incompatible {
            message: "the allocation booted again or holds another inner sandbox".into(),
        };
    }
    let Some(slot) = host.control() else {
        return ValidateReply::Unknown {
            reason: "the supervisor is gone".into(),
        };
    };
    // B5-05: one control operation per allocation; a second Validate queues for the
    // slot within its own deadline and nothing is asked of the guest meanwhile.
    let permit = tokio::select! {
        permit = slot.acquire_owned() => permit.ok(),
        _ = tokio::time::sleep_until(deadline.instant) => None,
    };
    let Some(permit) = permit else {
        return ValidateReply::ControlBusy;
    };
    // Exec admission holds the same slot, so this is ordered against it.
    if let Some(execution_token) = host.busy() {
        return ValidateReply::Busy { execution_token };
    }
    if let Err(reason) = host.ready() {
        return ValidateReply::Unknown { reason };
    }
    let job = next_job();
    let deadline_ns = deadline
        .ns
        .min(workers::monotonic_ns().saturating_add(5_000_000_000));
    let Some(mut rx) = host.job(job, BrokerCommand::Probe { job, deadline_ns }) else {
        return ValidateReply::Unknown {
            reason: "the supervisor is gone".into(),
        };
    };
    match tokio::time::timeout_at(deadline.instant, rx.recv()).await {
        Ok(report) => {
            host.forget(job);
            drop(permit);
            judge_probe(&*host, report, &boot, &inner)
        }
        Err(_) => {
            // B5-09: R's stages can still end in a breach. A standing handler keeps
            // the waiter and the control slot until R reports or its bound passes.
            let late = host.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(LATE_PROBE, rx.recv()).await {
                    Ok(report) => {
                        let _ = judge_probe(&*late, report, &boot, &inner);
                    }
                    Err(_) => {
                        if !late.session_ended() {
                            late.contain("the relay never finished a probe");
                        }
                    }
                }
                late.forget(job);
                drop(permit);
            });
            ValidateReply::Unknown {
                reason: "no probe answer within the deadline".into(),
            }
        }
    }
}

/// One Exec request as H received it.
pub(super) struct ExecRequest {
    pub expected_boot_id: String,
    pub token: Id128,
    pub execution_id: String,
    pub argv: Vec<String>,
    pub stdin_bytes: usize,
    pub max_output: usize,
}

/// Why the execution's wait ended.
#[derive(Debug)]
enum End {
    Report(RelayReport),
    Canceled,
    TimedOut,
    /// S, V or the waiter is gone.
    Gone,
    /// A journal write did not become durable within its bound (B5-02).
    LedgerStall(&'static str),
}

/// What an interruption knows of the command's output.
enum Evidence<'a> {
    /// The command may have run; no validated Result.
    Unknown,
    /// A validated Result, with what actually reached the caller.
    Result {
        result: &'a ExecResult,
        stdout: CaptureInfo,
        stderr: CaptureInfo,
    },
}

/// Exec (sections 5.4, 5.5): see the module documentation.
pub(super) async fn exec<H: Host>(
    host: Arc<H>,
    request: ExecRequest,
    stdio: [std::os::fd::OwnedFd; 3],
    deadline: WireDeadline,
    waiter: CancellationToken,
) -> ExecReply {
    if waiter.is_cancelled() {
        return refused(Kind::Unavailable, "canceled before dispatch");
    }
    if deadline.expired() {
        return ExecReply {
            finish: WireFinishFc::TimedOut,
            ..refused(Kind::Unavailable, "")
        };
    }
    if let Err(reason) = host.ready() {
        return not_ready(&*host, reason);
    }
    let Some(token_wire) = kilnd_broker_protocol::Id128::parse(&request.token.to_string()) else {
        return refused(Kind::InvalidRequest, "token");
    };
    let Some(execution_wire) =
        kilnd_broker_protocol::ExecutionId::new(request.execution_id.clone())
    else {
        return refused(Kind::InvalidRequest, "execution ID");
    };
    let Some(slot) = host.control() else {
        return unusable(Kind::Unavailable, "the supervisor is gone");
    };
    // B5-05: admission waits for any probe in flight, so a probe can never observe
    // our own execution starting.
    let permit = tokio::select! {
        biased;
        _ = waiter.cancelled() => return refused(Kind::Unavailable, "canceled before dispatch"),
        _ = tokio::time::sleep_until(deadline.instant) => {
            return ExecReply {
                finish: WireFinishFc::TimedOut,
                ..refused(Kind::Unavailable, "a control operation held the allocation")
            };
        }
        permit = slot.acquire_owned() => permit,
    };
    let Ok(permit) = permit else {
        return unusable(Kind::Unavailable, "the supervisor is gone");
    };
    let (boot, inner) = match host.ready() {
        Ok(session) => session,
        Err(reason) => return not_ready(&*host, reason),
    };
    if boot != request.expected_boot_id {
        return unusable(Kind::Incompatible, "the allocation booted again");
    }
    // Busy before the journal, so no second Exec or Validate slips between.
    if !host.set_busy(request.token) {
        return refused(Kind::Busy, "another execution is in flight");
    }
    drop(permit);
    let run = Execution {
        host: host.clone(),
        token: request.token,
        token_wire,
        execution_id: request.execution_id.clone(),
        boot,
        inner,
        deadline,
        waiter,
    };
    let exec = Exec {
        token: token_wire,
        execution_id: execution_wire,
        argv: request.argv,
        stdin_bytes: request.stdin_bytes as u64,
        max_output: request.max_output as u64,
        // R computes the real budget at send time; this placeholder never leaves S.
        remaining_ms: 1,
    };
    let reply = run.run(exec, stdio).await;
    host.clear_busy();
    reply
}

/// Both writes, in order, each within `by`; the first that is not durable answers.
fn write_pair<H: Host>(
    host: Arc<H>,
    first: LedgerRequest,
    second: LedgerRequest,
    by: Instant,
) -> BoxedJournal {
    // Bounded here too, whatever the host does: an unanswered write is Unknown.
    Box::pin(async move {
        let pair = async {
            match host.journal(first, by).await {
                Journaled::Durable => host.journal(second, by).await,
                other => other,
            }
        };
        tokio::time::timeout_at(by, pair)
            .await
            .unwrap_or(Journaled::Unknown)
    })
}

struct Execution<H> {
    host: Arc<H>,
    token: Id128,
    token_wire: kilnd_broker_protocol::Id128,
    execution_id: String,
    boot: String,
    inner: String,
    deadline: WireDeadline,
    waiter: CancellationToken,
}

impl<H: Host> Execution<H> {
    fn record(&self, state: &str) -> LedgerRequest {
        let key = self.key();
        LedgerRequest::RecordResource {
            instance: key.0,
            allocation: key.1,
            record: ResourceRecord::Exec {
                token: self.token.to_string(),
                execution_id: self.execution_id.clone(),
                boot_id: self.boot.clone(),
                state: state.into(),
            },
        }
    }

    fn phase(&self, from: &str, to: &str) -> LedgerRequest {
        let key = self.key();
        LedgerRequest::SetPhase {
            instance: key.0,
            allocation: key.1,
            from: vec![from.into()],
            to: to.into(),
        }
    }

    fn key(&self) -> (Id128, Id128) {
        self.host.allocation()
    }

    async fn settle_writes(&self, state: &str, from: &str, to: &str) -> Journaled {
        write_pair(
            self.host.clone(),
            self.record(state),
            self.phase(from, to),
            Instant::now() + LEDGER_WRITE,
        )
        .await
    }

    async fn run(self, exec: Exec, stdio: [std::os::fd::OwnedFd; 3]) -> ExecReply {
        // EXEC_INTENT before any byte can be sent.
        match self.settle_writes("intent", "ready", "exec_intent").await {
            Journaled::Durable => {}
            Journaled::Refused => return refused(Kind::Unavailable, "EXEC_INTENT is not durable"),
            Journaled::Unknown => {
                // L may still commit EXEC_INTENT: this allocation's journal and memory
                // can no longer agree, so it is not reused (B5-02).
                return self
                    .retire_undispatched(
                        Kind::Unavailable,
                        "the ledger did not answer EXEC_INTENT; the VM was retired",
                    )
                    .await;
            }
        }
        // B7 RTC-14: the node latch, rechecked after EXEC_INTENT and immediately before
        // the descriptors and the broker Exec. A latch that linearized while EXEC_INTENT
        // was being written dispatches nothing; the journal now says EXEC_INTENT, so the
        // VM is retired under the uncertainty rule rather than put back to READY.
        #[cfg(test)]
        workers::faults::hold("H.exec.before_dispatch").await;
        if self.host.latched(self.deadline.instant).await {
            return self
                .retire_undispatched(
                    Kind::Unavailable,
                    "forward effects were latched node-wide after EXEC_INTENT; nothing was \
                     dispatched and the VM was retired",
                )
                .await;
        }
        let job = next_job();
        let raw: Vec<RawFd> = stdio.iter().map(AsRawFd::as_raw_fd).collect();
        let handed = self.host.hand_stdio(job, &raw);
        drop(stdio);
        let rx = if handed {
            self.host.job(
                job,
                BrokerCommand::Exec {
                    job,
                    exec,
                    deadline_ns: self.deadline.ns,
                },
            )
        } else {
            None
        };
        let Some(mut rx) = rx else {
            // Nothing reached S's relay: still provably undispatched.
            return self
                .undispatched_local(job, "the supervisor could not take the execution")
                .await;
        };
        let mut accepted = false;
        let mut busy: Option<BoxedJournal> = None;
        let mut busy_by = self.deadline.instant;
        let end = loop {
            tokio::select! {
                biased;
                report = rx.recv() => match report {
                    Some(RelayReport::Accepted { .. }) => {
                        if !accepted {
                            accepted = true;
                            // BUSY is its own future, polled beside containment.
                            let by = Instant::now() + LEDGER_WRITE;
                            busy_by = by;
                            busy = Some(write_pair(
                                self.host.clone(),
                                self.record("busy"),
                                self.phase("exec_intent", "busy"),
                                by,
                            ));
                        }
                    }
                    Some(report) => break End::Report(report),
                    None => break End::Gone,
                },
                _ = self.waiter.cancelled() => break End::Canceled,
                _ = tokio::time::sleep_until(self.deadline.instant) => break End::TimedOut,
                written = async {
                    match busy.as_mut() {
                        Some(write) => write.await,
                        None => std::future::pending().await,
                    }
                }, if busy.is_some() => {
                    busy = None;
                    if written != Journaled::Durable {
                        break End::LedgerStall("BUSY was not journaled");
                    }
                }
                _ = tokio::time::sleep_until(busy_by), if busy.is_some() => {
                    break End::LedgerStall("BUSY was not durable within its bound");
                }
                // A stop, S's exit or V's death ends the execution: its relay is gone
                // with it, so no report may ever come.
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if self.host.session_ended() {
                        break End::Gone;
                    }
                }
            }
        };
        // A result that arrived while BUSY was still being written waits for it, but
        // only within its bound: the command has already finished.
        let end = match (end, busy.take()) {
            (End::Report(report @ RelayReport::Executed { .. }), Some(write)) => {
                match tokio::time::timeout_at(busy_by, write).await {
                    Ok(Journaled::Durable) => End::Report(report),
                    _ => End::LedgerStall("BUSY was not durable within its bound"),
                }
            }
            (end, _) => end,
        };
        let reply = self.conclude(end, job, accepted).await;
        self.host.forget(job);
        reply
    }

    async fn conclude(&self, end: End, job: u64, accepted: bool) -> ExecReply {
        match end {
            End::Report(RelayReport::Executed {
                result,
                delivered,
                stdout_delivered,
                stderr_delivered,
                ..
            }) => match self.settle_result(&result, delivered) {
                Ok(reply) => {
                    let from = if accepted { "busy" } else { "exec_intent" };
                    if self.settle_writes("idle", from, "ready").await == Journaled::Durable {
                        reply
                    } else {
                        // IDLE or READY is not durable: never reuse.
                        let evidence = Evidence::Result {
                            result: &result,
                            stdout: capture(&result.stdout),
                            stderr: capture(&result.stderr),
                        };
                        self.interrupt(job, Interrupted::Failed(Kind::Unavailable), evidence)
                            .await
                    }
                }
                Err(how) => {
                    let evidence = if delivered {
                        Evidence::Result {
                            result: &result,
                            stdout: capture(&result.stdout),
                            stderr: capture(&result.stderr),
                        }
                    } else {
                        Evidence::Result {
                            result: &result,
                            stdout: delivered_capture(&result.stdout, stdout_delivered),
                            stderr: delivered_capture(&result.stderr, stderr_delivered),
                        }
                    };
                    self.interrupt(job, how, evidence).await
                }
            },
            // B5-07: only a local, guest-independent failure restores READY.
            End::Report(RelayReport::Failed {
                reach: Reach::Local,
                reason,
                ..
            }) if !accepted => self.undispatched_local(job, &reason).await,
            End::Report(
                RelayReport::Failed {
                    reach: Reach::Local | Reach::Guest,
                    ..
                }
                | RelayReport::Refused {
                    reach: Reach::Local | Reach::Guest,
                    ..
                },
            ) if !accepted => {
                self.retire_undispatched(
                    Kind::Protocol,
                    "the guest broke the session protocol before dispatch; the VM was retired",
                )
                .await
            }
            End::Report(_) => {
                self.interrupt(job, Interrupted::Failed(Kind::Protocol), Evidence::Unknown)
                    .await
            }
            End::Canceled => {
                self.interrupt(job, Interrupted::Canceled, Evidence::Unknown)
                    .await
            }
            End::TimedOut => {
                self.interrupt(job, Interrupted::TimedOut, Evidence::Unknown)
                    .await
            }
            End::LedgerStall(why) => {
                // Uncertainty: the fence and K first, needing no ledger (B5-02).
                self.host
                    .contain(&format!("the ledger stalled during an execution: {why}"));
                self.interrupt(
                    job,
                    Interrupted::Failed(Kind::Unavailable),
                    Evidence::Unknown,
                )
                .await
            }
            End::Gone => {
                self.interrupt(
                    job,
                    Interrupted::Failed(Kind::Unavailable),
                    Evidence::Unknown,
                )
                .await
            }
        }
    }

    /// A local failure before any byte reached the guest: back to READY if that is
    /// durable, otherwise retired.
    async fn undispatched_local(&self, job: u64, reason: &str) -> ExecReply {
        self.host.forget(job);
        match self
            .settle_writes("undispatched", "exec_intent", "ready")
            .await
        {
            Journaled::Durable => refused(Kind::Unavailable, reason),
            _ => {
                self.retire_undispatched(
                    Kind::Unavailable,
                    "READY could not be journaled after an undispatched execution; the VM was retired",
                )
                .await
            }
        }
    }

    /// Nothing was dispatched, but the VM may not be reused: stop fence and K, no
    /// Cancel (there is nothing to cancel), and no ledger wait before containment.
    async fn retire_undispatched(&self, kind: Kind, message: &str) -> ExecReply {
        self.host.contain(message);
        let stopped = self.stop_proof().await;
        self.record_later("undispatched");
        ExecReply {
            finish: WireFinishFc::Failed(diagnostic(kind, RuntimeStage::Validate, message)),
            status: None,
            stdout: empty_capture(),
            stderr: empty_capture(),
            cleanup: if stopped {
                ExecCleanup::VmStopped
            } else {
                ExecCleanup::Unknown
            },
            reusable: false,
            dispatched: false,
        }
    }

    /// The settlement record, written in the background within its bound: the reply
    /// never waits on the ledger after containment.
    fn record_later(&self, state: &str) {
        let by = Instant::now() + LEDGER_WRITE;
        let write = self.host.journal(self.record(state), by);
        tokio::spawn(tokio::time::timeout_at(by, write));
    }

    async fn stop_proof(&self) -> bool {
        let proof_by = Instant::now() + STOP_PROOF;
        loop {
            if self.host.contained() == Some(true) {
                return true;
            }
            if Instant::now() >= proof_by {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A delivered result is reusable only with the guest core's own cleanup evidence
    /// and a completed or failed-but-drained finish, on the journaled inner sandbox; a
    /// guest-side timeout or cancel is an interruption like the host's own.
    fn settle_result(
        &self,
        result: &ExecResult,
        delivered: bool,
    ) -> Result<ExecReply, Interrupted> {
        if result.token != self.token_wire {
            return Err(Interrupted::Failed(Kind::Protocol));
        }
        // B5-06: a Result about another inner sandbox is a protocol failure.
        if result.inner_id.as_str() != self.inner {
            return Err(Interrupted::Failed(Kind::Protocol));
        }
        let finish = match &result.finish {
            Finish::Completed => WireFinishFc::Completed,
            Finish::TimedOut => return Err(Interrupted::TimedOut),
            Finish::Canceled => return Err(Interrupted::Canceled),
            Finish::Failed { kind, stage } => WireFinishFc::Failed(match &result.diagnostic {
                Some(d) => {
                    let mut diagnostic = diagnostic(d.kind, d.stage, d.message.as_str());
                    diagnostic.message_truncated |= d.message_truncated;
                    diagnostic
                }
                None => diagnostic(*kind, *stage, "the guest reported a failure"),
            }),
        };
        let cleanup = match result.cleanup {
            Cleanup::GuestCgroupDrained => ExecCleanup::GuestCgroupDrained,
            Cleanup::NoChildStarted => ExecCleanup::NoChildStarted,
            Cleanup::Unknown => return Err(Interrupted::Failed(Kind::CleanupFailed)),
        };
        if !delivered {
            return Err(Interrupted::Failed(Kind::Io));
        }
        Ok(ExecReply {
            finish,
            status: result.termination.map(CommandStatus::from),
            stdout: capture(&result.stdout),
            stderr: capture(&result.stderr),
            cleanup,
            reusable: true,
            dispatched: true,
        })
    }

    /// Cancel on the reserved control channel, two seconds for the guest to settle,
    /// then the stop fence and K's kill. Reports `VmStopped` only with K's proof.
    /// Nothing here waits on the ledger (B5-02).
    async fn interrupt(
        &self,
        exec_job: u64,
        how: Interrupted,
        evidence: Evidence<'_>,
    ) -> ExecReply {
        let reason = match how {
            Interrupted::TimedOut => CancelReason::Timeout,
            Interrupted::Canceled => CancelReason::Disconnect,
            Interrupted::Failed(_) => CancelReason::Protocol,
        };
        let settle = Instant::now() + SETTLE;
        // Cancel only on a free control slot: an occupied one never delays escalation.
        let permit = self
            .host
            .control()
            .and_then(|slot| slot.try_acquire_owned().ok());
        if permit.is_some() {
            let job = next_job();
            let deadline_ns = workers::monotonic_ns().saturating_add(SETTLE.as_nanos() as u64);
            if let Some(mut rx) = self.host.job(
                job,
                BrokerCommand::Cancel {
                    job,
                    cancel: Cancel {
                        token: self.token_wire,
                        reason,
                    },
                    deadline_ns,
                },
            ) {
                let _ = tokio::time::timeout_at(settle, rx.recv()).await;
                self.host.forget(job);
            }
        }
        drop(permit);
        let _ = tokio::time::timeout_at(settle, async {
            while self.host.pending(exec_job) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        // Default policy (section 5.5): retire this VM even if the guest drained.
        self.host.contain("execution interrupted after dispatch");
        let stopped = self.stop_proof().await;
        self.record_later("interrupted");
        let finish = match how {
            Interrupted::TimedOut => WireFinishFc::TimedOut,
            Interrupted::Canceled => WireFinishFc::Canceled,
            Interrupted::Failed(kind) => WireFinishFc::Failed(diagnostic(
                kind,
                RuntimeStage::Report,
                "the execution was interrupted after dispatch; the VM was retired",
            )),
        };
        let (status, stdout, stderr) = match evidence {
            Evidence::Unknown => (None, unknown_capture(), unknown_capture()),
            // Observed termination and prefixes stay separate evidence.
            Evidence::Result {
                result,
                stdout,
                stderr,
            } => (result.termination.map(CommandStatus::from), stdout, stderr),
        };
        ExecReply {
            finish,
            status,
            stdout,
            stderr,
            cleanup: if stopped {
                ExecCleanup::VmStopped
            } else {
                ExecCleanup::Unknown
            },
            reusable: false,
            dispatched: true,
        }
    }
}

#[cfg(test)]
mod tests;
