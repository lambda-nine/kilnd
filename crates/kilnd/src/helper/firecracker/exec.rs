//! H's B5 operations on a READY allocation: Validate and Exec (sections 5.5 and 6.1).
//!
//! Exec journals EXEC_INTENT (`ready -> exec_intent` and an `exec` record carrying the
//! token, public execution ID and boot ID) **before** any Exec byte can be sent, and
//! BUSY on the broker's acceptance. Only a fully validated, delivered result with the
//! guest core's own cleanup evidence returns the allocation to READY. Every other
//! ending after dispatch (timeout, the caller's disconnect, a protocol or transport
//! failure, a guest-side timeout or cancel, an uncertain cleanup) is an interruption:
//! Cancel on the reserved control channel, at most two seconds for the guest to settle,
//! then the existing stop fence and K's kill of the `vm` subtree. The answer is then
//! `reusable = false`; it is `VmStopped` only once K proved the subtree gone. The
//! caller's disconnect never drops this: the work runs on its own task.

use super::broker::{BrokerCommand, RelayReport};
use super::supervisor::ResourceRecord;
use super::*;
use crate::helper::protocol::{CaptureInfo, ExecCleanup, ExecReply, ValidateReply, WireFinishFc};
use crate::model::{CommandStatus, RuntimeDiagnostic, RuntimeErrorKind as Kind, RuntimeStage};
use kilnd_broker_protocol::message::{
    BrokerState, Cancel, CancelReason, CaptureFacts, Cleanup, Exec, ExecResult, Finish,
};

static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

/// The cooperative settlement window after Cancel, before the stop barrier.
const SETTLE: Duration = Duration::from_secs(2);
/// How long an interrupted Exec waits for K's proof before answering without it.
const STOP_PROOF: Duration = Duration::from_secs(5);

fn diagnostic(kind: Kind, stage: RuntimeStage, message: impl Into<String>) -> RuntimeDiagnostic {
    RuntimeDiagnostic::new(kind, stage, message)
}

fn empty_capture() -> CaptureInfo {
    CaptureInfo {
        kept: 0,
        total: 0,
        known: true,
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

/// How the interruption is reported once the VM is retired.
#[derive(Clone, Copy, Debug)]
enum Interrupted {
    TimedOut,
    Canceled,
    Failed(Kind),
}

impl Node {
    fn next_job() -> u64 {
        NEXT_JOB.fetch_add(1, Ordering::Relaxed)
    }

    /// Registers a job's report waiter and sends its command; `None` if S is gone.
    fn broker_job(
        &self,
        key: AllocationKey,
        job: u64,
        command: BrokerCommand,
    ) -> Option<mpsc::UnboundedReceiver<RelayReport>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut supervisors = self.supervisors.lock().unwrap();
        let entry = supervisors.get_mut(&key)?;
        entry.jobs.insert(job, tx);
        if !entry.channel.notify(&SupervisorCommand::Broker(command)) {
            entry.jobs.remove(&job);
            return None;
        }
        Some(rx)
    }

    fn forget_job(&self, key: AllocationKey, job: u64) {
        if let Some(entry) = self.supervisors.lock().unwrap().get_mut(&key) {
            entry.jobs.remove(&job);
        }
    }

    async fn journal(&self, request: LedgerRequest, deadline_ns: u64) -> bool {
        matches!(
            self.ledger_call(Lane::Normal, &request, deadline_ns).await,
            Ok(LedgerReply::Generation(_))
        )
    }

    async fn record_exec(
        &self,
        key: AllocationKey,
        token: Id128,
        execution_id: &str,
        boot_id: &str,
        state: &str,
    ) -> bool {
        self.journal(
            LedgerRequest::RecordResource {
                instance: key.instance,
                allocation: key.allocation,
                record: ResourceRecord::Exec {
                    token: token.to_string(),
                    execution_id: execution_id.into(),
                    boot_id: boot_id.into(),
                    state: state.into(),
                },
            },
            u64::MAX,
        )
        .await
    }

    async fn set_phase(&self, key: AllocationKey, from: &str, to: &str) -> bool {
        self.journal(
            LedgerRequest::SetPhase {
                instance: key.instance,
                allocation: key.allocation,
                from: vec![from.into()],
                to: to.into(),
            },
            u64::MAX,
        )
        .await
    }

    /// The journaled boot and inner sandbox, if this allocation is READY and its
    /// supervision healthy enough to admit a reusable dispatch.
    fn ready_session(&self, key: AllocationKey) -> Result<(String, String), String> {
        if !self.reusable_dispatch(key) {
            return Err("the allocation is fenced, stopped or unsupervised".into());
        }
        let supervisors = self.supervisors.lock().unwrap();
        let entry = supervisors
            .get(&key)
            .ok_or_else(|| "no supervisor for this allocation".to_string())?;
        if let Some(token) = entry.busy {
            return Err(format!("execution {token} is in flight"));
        }
        entry
            .ready
            .clone()
            .ok_or_else(|| "the allocation is not READY".to_string())
    }

    /// Validate (section 6.1): process and journal state, then a broker Probe on the
    /// reserved control channel. During an execution the recorded busy state answers.
    /// A failed probe never reads as absence; any broker breach retires the VM.
    pub(super) async fn validate_op(
        self: &Arc<Self>,
        key: AllocationKey,
        expected_boot_id: String,
        expected_inner_id: String,
        deadline: WireDeadline,
    ) -> ValidateReply {
        let busy = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .and_then(|entry| entry.busy);
        if let Some(execution_token) = busy {
            return ValidateReply::Busy { execution_token };
        }
        let (boot, inner) = match self.ready_session(key) {
            Ok(session) => session,
            Err(reason) => return ValidateReply::Unknown { reason },
        };
        if boot != expected_boot_id || inner != expected_inner_id {
            return ValidateReply::Incompatible {
                message: "the allocation booted again or holds another inner sandbox".into(),
            };
        }
        let job = Self::next_job();
        let deadline_ns = deadline
            .ns
            .min(workers::monotonic_ns().saturating_add(5_000_000_000));
        let Some(mut rx) = self.broker_job(key, job, BrokerCommand::Probe { job, deadline_ns })
        else {
            return ValidateReply::Unknown {
                reason: "the supervisor is gone".into(),
            };
        };
        let report = tokio::time::timeout_at(deadline.instant, rx.recv()).await;
        self.forget_job(key, job);
        match report {
            Ok(Some(RelayReport::Probed { reply, .. }))
                if reply.state == BrokerState::Idle
                    && reply.boot_id.as_str() == boot
                    && reply.inner_id.as_str() == inner
                    && reply.active.is_none() =>
            {
                ValidateReply::Ready {
                    boot_id: boot,
                    inner_id: inner,
                }
            }
            Ok(Some(RelayReport::Probed { reply, .. })) => {
                self.contain_allocation(key, "the broker is not idle with no execution");
                ValidateReply::Unknown {
                    reason: format!("the broker reported {:?}", reply.state),
                }
            }
            Ok(Some(RelayReport::Refused { error, .. })) => {
                self.contain_allocation(key, "the broker refused a probe");
                ValidateReply::Unknown {
                    reason: format!("the broker refused: {}", error.message),
                }
            }
            Ok(Some(RelayReport::Failed { reason, .. })) => {
                self.contain_allocation(key, &format!("probe failed: {reason}"));
                ValidateReply::Unknown { reason }
            }
            _ => ValidateReply::Unknown {
                reason: "no probe answer within the deadline".into(),
            },
        }
    }

    /// Exec (sections 5.4, 5.5): see the module documentation. `stdio` are the
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
        if waiter.is_cancelled() {
            return refused(Kind::Unavailable, "canceled before dispatch");
        }
        if deadline.expired() {
            return ExecReply {
                finish: WireFinishFc::TimedOut,
                ..refused(Kind::Unavailable, "")
            };
        }
        let (boot, _inner) = match self.ready_session(key) {
            Ok(session) => session,
            Err(reason) => return refused(Kind::Unavailable, reason),
        };
        if boot != expected_boot_id {
            return refused(Kind::Incompatible, "the allocation booted again");
        }
        let Some(token_wire) = kilnd_broker_protocol::Id128::parse(&token.to_string()) else {
            return refused(Kind::InvalidRequest, "token");
        };
        let Some(execution_wire) = kilnd_broker_protocol::ExecutionId::new(execution_id.clone())
        else {
            return refused(Kind::InvalidRequest, "execution ID");
        };
        // Mark busy before the journal, so no second Exec or Validate slips between.
        {
            let mut supervisors = self.supervisors.lock().unwrap();
            match supervisors.get_mut(&key) {
                Some(entry) if entry.busy.is_none() => entry.busy = Some(token),
                _ => return refused(Kind::Busy, "another execution is in flight"),
            }
        }
        let clear_busy = |node: &Node| {
            if let Some(entry) = node.supervisors.lock().unwrap().get_mut(&key) {
                entry.busy = None;
            }
        };
        // EXEC_INTENT before any byte can be sent.
        if !self
            .record_exec(key, token, &execution_id, &boot, "intent")
            .await
            || !self.set_phase(key, "ready", "exec_intent").await
        {
            clear_busy(&self);
            return refused(Kind::Unavailable, "EXEC_INTENT is not durable");
        }
        let job = Self::next_job();
        let descriptors = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .and_then(|entry| entry.descriptors.clone());
        let raw: Vec<RawFd> = stdio.iter().map(AsRawFd::as_raw_fd).collect();
        let handed = descriptors
            .is_some_and(|socket| super::broker::relay::send_fds(&socket, job, &raw).is_ok());
        drop(stdio);
        let exec = Exec {
            token: token_wire,
            execution_id: execution_wire,
            argv,
            stdin_bytes: stdin_bytes as u64,
            max_output: max_output as u64,
            // R computes the real budget at send time; this placeholder never leaves S.
            remaining_ms: 1,
        };
        let rx = if handed {
            self.broker_job(
                key,
                job,
                BrokerCommand::Exec {
                    job,
                    exec,
                    deadline_ns: deadline.ns,
                },
            )
        } else {
            None
        };
        let Some(mut rx) = rx else {
            // Nothing reached S: still provably undispatched.
            self.record_exec(key, token, &execution_id, &boot, "undispatched")
                .await;
            self.set_phase(key, "exec_intent", "ready").await;
            clear_busy(&self);
            return refused(
                Kind::Unavailable,
                "the supervisor could not take the execution",
            );
        };
        let mut accepted = false;
        let outcome = loop {
            tokio::select! {
                biased;
                report = rx.recv() => match report {
                    Some(RelayReport::Accepted { .. }) => {
                        if !accepted {
                            accepted = true;
                            self.record_exec(key, token, &execution_id, &boot, "busy").await;
                            self.set_phase(key, "exec_intent", "busy").await;
                        }
                    }
                    Some(report) => break Some(report),
                    None => break None,
                },
                _ = waiter.cancelled() => break None,
                _ = tokio::time::sleep_until(deadline.instant) => break None,
            }
        };
        let reply = match outcome {
            Some(RelayReport::Executed {
                result, delivered, ..
            }) => {
                let settled = self.settle_result(&result, delivered, token_wire);
                match settled {
                    Ok(reply) => {
                        let from = if accepted { "busy" } else { "exec_intent" };
                        self.record_exec(key, token, &execution_id, &boot, "idle")
                            .await;
                        if self.set_phase(key, from, "ready").await {
                            reply
                        } else {
                            // READY is not durable: never reuse.
                            self.interrupt(
                                key,
                                job,
                                token_wire,
                                Interrupted::Failed(Kind::Unavailable),
                                Some(&result),
                                &waiter,
                            )
                            .await
                        }
                    }
                    Err(how) => {
                        self.interrupt(key, job, token_wire, how, Some(&result), &waiter)
                            .await
                    }
                }
            }
            Some(RelayReport::Failed {
                dispatched: false,
                reason,
                ..
            }) => {
                self.record_exec(key, token, &execution_id, &boot, "undispatched")
                    .await;
                self.set_phase(key, "exec_intent", "ready").await;
                refused(Kind::Unavailable, reason)
            }
            Some(RelayReport::Refused { error, .. }) => {
                let _ = error;
                self.interrupt(
                    key,
                    job,
                    token_wire,
                    Interrupted::Failed(Kind::Protocol),
                    None,
                    &waiter,
                )
                .await
            }
            Some(_) => {
                self.interrupt(
                    key,
                    job,
                    token_wire,
                    Interrupted::Failed(Kind::Protocol),
                    None,
                    &waiter,
                )
                .await
            }
            None if waiter.is_cancelled() => {
                self.interrupt(key, job, token_wire, Interrupted::Canceled, None, &waiter)
                    .await
            }
            None if deadline.expired() => {
                self.interrupt(key, job, token_wire, Interrupted::TimedOut, None, &waiter)
                    .await
            }
            None => {
                self.interrupt(
                    key,
                    job,
                    token_wire,
                    Interrupted::Failed(Kind::Unavailable),
                    None,
                    &waiter,
                )
                .await
            }
        };
        if !reply.reusable {
            self.record_exec(key, token, &execution_id, &boot, "interrupted")
                .await;
        }
        self.forget_job(key, job);
        clear_busy(&self);
        reply
    }

    /// A delivered result is reusable only with the guest core's own cleanup evidence
    /// and a completed or failed-but-drained finish; a guest-side timeout or cancel is
    /// an interruption like the host's own.
    fn settle_result(
        &self,
        result: &ExecResult,
        delivered: bool,
        token: kilnd_broker_protocol::Id128,
    ) -> Result<ExecReply, Interrupted> {
        if result.token != token {
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
    async fn interrupt(
        self: &Arc<Self>,
        key: AllocationKey,
        exec_job: u64,
        token: kilnd_broker_protocol::Id128,
        how: Interrupted,
        result: Option<&ExecResult>,
        waiter: &CancellationToken,
    ) -> ExecReply {
        let _ = waiter;
        let reason = match how {
            Interrupted::TimedOut => CancelReason::Timeout,
            Interrupted::Canceled => CancelReason::Disconnect,
            Interrupted::Failed(_) => CancelReason::Protocol,
        };
        let job = Self::next_job();
        let settle = Instant::now() + SETTLE;
        let deadline_ns = workers::monotonic_ns().saturating_add(SETTLE.as_nanos() as u64);
        if let Some(mut rx) = self.broker_job(
            key,
            job,
            BrokerCommand::Cancel {
                job,
                cancel: Cancel { token, reason },
                deadline_ns,
            },
        ) {
            let _ = tokio::time::timeout_at(settle, rx.recv()).await;
            self.forget_job(key, job);
        }
        let _ = tokio::time::timeout_at(settle, async {
            loop {
                let pending = self
                    .supervisors
                    .lock()
                    .unwrap()
                    .get(&key)
                    .is_some_and(|entry| entry.jobs.contains_key(&exec_job));
                if !pending {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        // Default policy (section 5.5): retire this VM even if the guest drained.
        self.contain_allocation(key, "execution interrupted after dispatch");
        let proof_by = Instant::now() + STOP_PROOF;
        let stopped = loop {
            let contained = self
                .supervisors
                .lock()
                .unwrap()
                .get(&key)
                .and_then(|entry| entry.contained);
            if contained == Some(true) {
                break true;
            }
            if Instant::now() >= proof_by {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let finish = match how {
            Interrupted::TimedOut => WireFinishFc::TimedOut,
            Interrupted::Canceled => WireFinishFc::Canceled,
            Interrupted::Failed(kind) => WireFinishFc::Failed(diagnostic(
                kind,
                RuntimeStage::Report,
                "the execution was interrupted after dispatch; the VM was retired",
            )),
        };
        ExecReply {
            finish,
            // Observed termination and prefixes stay separate evidence.
            status: result.and_then(|r| r.termination).map(CommandStatus::from),
            stdout: result.map_or_else(empty_capture, |r| capture(&r.stdout)),
            stderr: result.map_or_else(empty_capture, |r| capture(&r.stderr)),
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
