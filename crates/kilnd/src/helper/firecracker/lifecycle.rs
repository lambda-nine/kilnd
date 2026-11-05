//! H's half of the B4 lifecycle: S's journaled records (C3–C5), Stop, Remove and
//! scoped Gc (sections 4.3, 6.1, 8.1 and 8.2). Every durable record precedes the
//! effect it authorizes; every release is the existing ABSENT fence, after S and K
//! proved the subtree empty and the real namespace observation found nothing owned.
//! Nothing here reports READY: that needs B5's broker.
use super::monitor::StopTarget;
use super::supervisor::{ChildRole, RecordedResources, ResourceRecord, SupervisorRecord};
use super::*;
use crate::helper::protocol::{GcOutcome, GcResult, StopReason, StopReply};

/// Phases from which a stop may be recorded as complete.
const STOPPABLE: [&str; 10] = [
    "intent",
    "preparing",
    "spawn_intent",
    "booting",
    "ready",
    "exec_intent",
    "busy",
    "stop_intent",
    "stopped",
    "cleaning",
];

pub(super) struct RemoveToken {
    pub instance: Id128,
    pub epoch: Option<Id128>,
    pub peer: PeerCredentials,
    pub allocation: Id128,
    /// B7: the daemon Store's immutable plan digest for this token.
    pub plan_digest: crate::model::Digest,
    pub deadline: WireDeadline,
}

impl RemoveToken {
    fn key(&self) -> AllocationKey {
        AllocationKey {
            instance: self.instance,
            allocation: self.allocation,
        }
    }
}

/// The relative cgroup path of an allocation, from its instance-scoped host name.
pub(super) fn allocation_cgroup(key: AllocationKey) -> String {
    format!(
        "{}/{}/{}",
        super::cgroup::FIRECRACKER_TREE,
        key.instance,
        identity::host_name(key.instance, key.allocation)
    )
}

/// Why a supervisor was contained at a record under the node latch (B7 recheck R2).
const LATCHED_RECORD: &str = "forward effects are latched node-wide";

/// How long a record of S's waits for a lost ledger answer to be consumed before it is
/// treated as latched (B7 recheck R1).
const LOST_ANSWER_WAIT: Duration = Duration::from_secs(2);

/// B7 recheck R2: whether L still journals this record of S's under its latch
/// (`workers::allowed_under_latch`). H does not send any other while latched.
fn recorded_under_latch(record: &SupervisorRecord) -> bool {
    match record {
        SupervisorRecord::Resource(resource) => workers::resource_allowed_under_latch(resource),
        SupervisorRecord::Phase { from, to } => workers::phase_allowed_under_latch(from, to),
        SupervisorRecord::Child { .. }
        | SupervisorRecord::Observed(_)
        | SupervisorRecord::InferredFromRetainedFd(_) => true,
        SupervisorRecord::Initialize => false,
    }
}

/// B7 recheck R2: the only records H acknowledges under the latch, the explicit
/// teardown set. A cleanup S proves a loop generation gone; nothing else S sends is
/// teardown, so every other answer under the latch is `false` and S stops.
fn acknowledged_under_latch(record: &SupervisorRecord) -> bool {
    matches!(
        record,
        SupervisorRecord::Resource(ResourceRecord::LoopReleased { .. })
    )
}

impl Node {
    /// One record from S, answered in order. A fenced boot gets no further authority:
    /// the answer is `false` and S stops forward work.
    pub(super) async fn on_record(
        self: &Arc<Self>,
        key: AllocationKey,
        record: SupervisorRecord,
    ) -> bool {
        let fenced = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .is_none_or(|entry| entry.stop_fenced);
        // Observations, child identities and a cleanup's loop release are evidence,
        // recorded even after a fence (a cleanup S is always fenced), but they never
        // authorize a further effect.
        let evidence_only = matches!(
            record,
            SupervisorRecord::Observed(_)
                | SupervisorRecord::InferredFromRetainedFd(_)
                | SupervisorRecord::Child { .. }
                | SupervisorRecord::Resource(ResourceRecord::LoopReleased { .. })
        );
        // B7 recheck R2: under the node latch S gets no further authority. A record L
        // would refuse is not sent; one it still takes (an identity cleanup needs) is
        // journaled, but only teardown is acknowledged, and the latch is read again
        // after L answers, so a latch set while H waited is never missed.
        let acknowledged_latched = acknowledged_under_latch(&record);
        let settle = Instant::now() + LOST_ANSWER_WAIT;
        if !recorded_under_latch(&record) && self.latched_once_answered(settle).await {
            self.contain_allocation(key, LATCHED_RECORD);
            return false;
        }
        let lane = Lane::Normal;
        let ok = match record {
            SupervisorRecord::Initialize => matches!(
                self.ledger_call(
                    lane,
                    &LedgerRequest::AuthorizeInitialize {
                        instance: key.instance,
                        allocation: key.allocation,
                    },
                    u64::MAX,
                )
                .await,
                Ok(LedgerReply::Done)
            ),
            SupervisorRecord::Resource(resource) => {
                if let ResourceRecord::Cgroup(identity) = &resource {
                    // M must hold the subtree before J could clone anything into it.
                    // The whole journaled tree identity: K proves the parent, `vm`,
                    // `vm/vmm` and `vm/console` and the boot before any cgroup.kill.
                    let target = StopTarget {
                        process: None,
                        cgroup: Some(super::cgroup::CgroupStopTarget {
                            relative: allocation_cgroup(key),
                            identity: Some(identity.clone()),
                        }),
                    };
                    if !self.register_target(key, target).await {
                        return false;
                    }
                }
                matches!(
                    self.ledger_call(
                        lane,
                        &LedgerRequest::RecordResource {
                            instance: key.instance,
                            allocation: key.allocation,
                            record: resource,
                        },
                        u64::MAX,
                    )
                    .await,
                    Ok(LedgerReply::Generation(_))
                )
            }
            SupervisorRecord::Phase { from, to } => matches!(
                self.ledger_call(
                    lane,
                    &LedgerRequest::SetPhase {
                        instance: key.instance,
                        allocation: key.allocation,
                        from,
                        to,
                    },
                    u64::MAX,
                )
                .await,
                Ok(LedgerReply::Generation(_))
            ),
            SupervisorRecord::Child { role, process } => {
                let (expected, mode) = {
                    let supervisors = self.supervisors.lock().unwrap();
                    let Some(entry) = supervisors.get(&key) else {
                        return false;
                    };
                    let wanted = match role {
                        ChildRole::Jailer => Some(Role::Jailer),
                        ChildRole::Vm => Some(Role::Firecracker),
                        // Fork-only from S: the verified helper image they inherit.
                        ChildRole::Relay | ChildRole::Console => None,
                    };
                    (
                        match wanted {
                            Some(wanted) => {
                                entry.expected.iter().find(|e| e.role == wanted).copied()
                            }
                            None => self.config.helper_image,
                        },
                        match role {
                            ChildRole::Jailer => "jailer",
                            ChildRole::Vm => "vm",
                            ChildRole::Relay => "relay",
                            ChildRole::Console => "console",
                        },
                    )
                };
                let Some(image) = expected else {
                    return false;
                };
                let host = identity::host_name(key.instance, key.allocation);
                let reply = self
                    .ledger_call(
                        lane,
                        &LedgerRequest::RecordChild {
                            instance: key.instance,
                            allocation: key.allocation,
                            spec: Box::new(WorkerIntentSpec {
                                mode: mode.into(),
                                allowed_names: vec![
                                    match role {
                                        ChildRole::Relay => "relay",
                                        _ => "vm",
                                    }
                                    .into(),
                                ],
                                cgroup: match role {
                                    ChildRole::Relay => format!("{host}/relay"),
                                    ChildRole::Console => format!("{host}/vm/console"),
                                    _ => format!("{host}/vm/vmm"),
                                },
                                image,
                            }),
                            target: process,
                        },
                        u64::MAX,
                    )
                    .await;
                match reply {
                    Ok(LedgerReply::Generation(id)) => {
                        let mut supervisors = self.supervisors.lock().unwrap();
                        if let Some(entry) = supervisors.get_mut(&key) {
                            entry.children.push((id as i64, process));
                            if role == ChildRole::Vm {
                                entry.vm_worker = Some(id as i64);
                            }
                        }
                        true
                    }
                    _ => false,
                }
            }
            SupervisorRecord::Observed(actual) => matches!(
                self.ledger_call(
                    lane,
                    &LedgerRequest::RecordObserved {
                        instance: key.instance,
                        allocation: key.allocation,
                        actual,
                    },
                    u64::MAX,
                )
                .await,
                Ok(LedgerReply::Done)
            ),
            SupervisorRecord::InferredFromRetainedFd(inferred) => matches!(
                self.ledger_call(
                    lane,
                    &LedgerRequest::RecordInferred {
                        instance: key.instance,
                        allocation: key.allocation,
                        inferred,
                    },
                    u64::MAX,
                )
                .await,
                Ok(LedgerReply::Done)
            ),
        };
        // B7 recheck R2: holds H between L's answer and the latch check after it.
        #[cfg(test)]
        workers::faults::hold("H.record.after_ledger").await;
        let latched = !acknowledged_latched
            && self
                .latched_once_answered(Instant::now() + LOST_ANSWER_WAIT)
                .await;
        if !ok {
            self.contain_allocation(key, "a supervisor record could not be journaled");
        } else if latched {
            self.contain_allocation(key, LATCHED_RECORD);
        }
        ok && !latched && (evidence_only || !fenced)
    }

    /// Gives M a concrete stop target (merged with anything it already had).
    pub(super) async fn register_target(
        self: &Arc<Self>,
        key: AllocationKey,
        target: StopTarget,
    ) -> bool {
        {
            let mut supervisors = self.supervisors.lock().unwrap();
            if let Some(entry) = supervisors.get_mut(&key) {
                match entry.vm.as_mut() {
                    Some(known) => known.merge(&target),
                    None => entry.vm = Some(target.clone()),
                }
            }
        }
        let channel = self.monitor.lock().unwrap().worker.channel.clone();
        let registered = tokio::time::timeout(
            Duration::from_secs(1),
            channel.call::<MonitorReply>(
                Lane::Normal,
                &MonitorCommand::RegisterTarget {
                    allocation: key,
                    target,
                },
                u64::MAX,
            ),
        )
        .await;
        matches!(registered, Ok(Ok(MonitorReply::Registered)))
    }

    /// A ledger call that gives up at the original deadline: a stalled L must never
    /// hold a stop's containment hostage (section 4.4).
    async fn bounded_ledger(
        &self,
        request: &LedgerRequest,
        deadline: WireDeadline,
    ) -> Result<LedgerReply, CallError> {
        tokio::time::timeout_at(
            deadline.instant,
            self.ledger_call(Lane::Reserved, request, deadline.ns),
        )
        .await
        .unwrap_or(Err(CallError::Full))
    }

    pub(super) async fn allocation_state(
        &self,
        key: AllocationKey,
        deadline: WireDeadline,
    ) -> Result<Option<journal::AllocationState>, String> {
        match self
            .bounded_ledger(
                &LedgerRequest::AllocationState {
                    instance: key.instance,
                    allocation: key.allocation,
                },
                deadline,
            )
            .await
        {
            Ok(LedgerReply::State(state)) => Ok(state.map(|state| *state)),
            Ok(LedgerReply::Unavailable { reason } | LedgerReply::Failed { reason }) => Err(reason),
            _ => Err("the node ledger gave no allocation state".into()),
        }
    }

    /// Everything known about where this allocation's VM could be: H's live target and
    /// the journal's recorded cgroup and VMM, so a restarted helper can stop it too.
    fn stop_target(&self, key: AllocationKey, state: &journal::AllocationState) -> StopTarget {
        let mut recorded = RecordedResources::default();
        for record in &state.resources {
            recorded.absorb(record);
        }
        // The journaled identities as they are: K proves each against the kernel and
        // the current boot (section 7.1). A tree recorded in another boot, a replaced
        // node or child, an unreadable boot ID or a tree with only an intent journaled
        // is never signaled; a process without its boot ID never is either.
        let mut target = StopTarget {
            process: recorded.vmm,
            cgroup: (recorded.cgroup.is_some() || recorded.cgroup_intent).then(|| {
                super::cgroup::CgroupStopTarget {
                    relative: allocation_cgroup(key),
                    identity: recorded.cgroup.clone(),
                }
            }),
        };
        if let Some(known) = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .and_then(|entry| entry.vm.clone())
        {
            target.merge(&known);
        }
        target
    }

    /// STOP_INTENT durably first, then the irrevocable in-memory fence, then K until the
    /// subtree is proven empty and S has exited, then STOPPED. A deadline returns the
    /// honest answer; the requested stop and the charge both remain.
    pub(super) async fn stop_allocation(
        self: &Arc<Self>,
        key: AllocationKey,
        reason: &str,
        deadline: WireDeadline,
    ) -> StopReply {
        // Normally STOP_INTENT is durable before the kill. A ledger that cannot answer
        // within a second must not delay containment: C2's conditional stop authority is
        // already durable, so H revokes in memory and dispatches K, and answers Unknown.
        let quick = WireDeadline::from_instant(
            deadline
                .instant
                .min(Instant::now() + Duration::from_secs(1)),
        );
        let state = match self.allocation_state(key, quick).await {
            Ok(Some(state)) => state,
            Ok(None) => {
                return StopReply::Unknown {
                    reason: "no active journal record".into(),
                };
            }
            Err(reason) => {
                self.contain_allocation(key, "stop requested with the ledger unavailable");
                return StopReply::Unknown {
                    reason: format!(
                        "the ledger did not answer; containment was dispatched: {reason}"
                    ),
                };
            }
        };
        let durable = self
            .bounded_ledger(
                &LedgerRequest::RecordStop {
                    instance: key.instance,
                    allocation: key.allocation,
                    reason: reason.into(),
                },
                quick,
            )
            .await;
        self.fence_in_memory(key);
        let target = self.stop_target(key, &state);
        if !matches!(durable, Ok(LedgerReply::Generation(_))) {
            self.dispatch_target(key, target);
            return StopReply::Unknown {
                reason: "the stop intent is not durable; containment was dispatched".into(),
            };
        }
        let began = std::time::Instant::now();
        loop {
            let gone = target.process.is_none() && target.cgroup.is_none()
                || self.dispatch_kill(target.clone()).await.unwrap_or(false);
            let supervisor_done = self
                .supervisors
                .lock()
                .unwrap()
                .get(&key)
                .is_none_or(|entry| entry.exit.is_some());
            if gone && supervisor_done {
                break;
            }
            // A tree at the path with only an intent journaled is never ours: no retry
            // can prove it stopped, so the honest answer comes now (section 7.1).
            if !gone
                && target
                    .cgroup
                    .as_ref()
                    .is_some_and(|cgroup| cgroup.identity.is_none())
            {
                return StopReply::Unknown {
                    reason: "a cgroup tree is at the allocation's path but no generation was \
                             journaled: it is Unknown and stays charged"
                        .into(),
                };
            }
            if deadline.expired() {
                return StopReply::Unknown {
                    reason: format!(
                        "no stop proof before the deadline (subtree gone: {gone}, supervisor exited: {supervisor_done})"
                    ),
                };
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        {
            let mut supervisors = self.supervisors.lock().unwrap();
            if let Some(entry) = supervisors.get_mut(&key) {
                entry.vm_gone = true;
                entry.contained = Some(true);
            }
        }
        // A boot that never recorded a cgroup or VMM has nothing that could run: S's
        // exit was the last owner of forward effects.
        let stopped = self
            .bounded_ledger(
                &LedgerRequest::SetPhase {
                    instance: key.instance,
                    allocation: key.allocation,
                    from: STOPPABLE.iter().map(|s| s.to_string()).collect(),
                    to: "stopped".into(),
                },
                deadline,
            )
            .await;
        match stopped {
            Ok(LedgerReply::Generation(generation)) => StopReply::Stopped {
                generation,
                observations: format!(
                    "subtree=empty;vmm={};supervisor=exited;elapsed_ms={}",
                    if target.process.is_some() {
                        "gone"
                    } else {
                        "never-published"
                    },
                    began.elapsed().as_millis()
                ),
            },
            _ => StopReply::Unknown {
                reason: "the subtree is empty but STOPPED is not durable".into(),
            },
        }
    }

    /// The in-memory half of a fence, after its durable record was written.
    fn fence_in_memory(&self, key: AllocationKey) {
        let mut supervisors = self.supervisors.lock().unwrap();
        if let Some(entry) = supervisors.get_mut(&key) {
            entry.stop_fenced = true;
            entry.revoked = true;
            if entry.exit.is_none() {
                entry.revoke_sent = entry.channel.notify(&SupervisorCommand::Revoke);
            }
        }
        drop(supervisors);
        if let Some(gate) = self.gate(key.instance, key.allocation) {
            gate.close(AmbiguousClass::GateClosed);
        }
    }

    /// K dispatch for a target that may not be in H's table (after a restart).
    fn dispatch_target(self: &Arc<Self>, key: AllocationKey, target: StopTarget) {
        let node = self.clone();
        tokio::spawn(async move {
            let gone = node.dispatch_kill(target).await;
            if let Some(entry) = node.supervisors.lock().unwrap().get_mut(&key) {
                entry.contained = Some(gone.unwrap_or(false));
            }
        });
    }

    pub(super) async fn stop_flow(
        self: &Arc<Self>,
        key: AllocationKey,
        expected_generation: u64,
        reason: StopReason,
        deadline: WireDeadline,
    ) -> StopReply {
        let quick = WireDeadline::from_instant(
            deadline
                .instant
                .min(Instant::now() + Duration::from_secs(1)),
        );
        match self.allocation_state(key, quick).await {
            Ok(Some(state)) if state.created_generation != expected_generation => {
                return StopReply::Unknown {
                    reason: "expected generation names another boot".into(),
                };
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                return StopReply::Unknown {
                    reason: "no active journal record; this is not evidence of absence".into(),
                };
            }
            Err(error) => {
                // One allocation has one boot: C2's conditional authority covers it
                // whatever generation the caller named.
                self.contain_allocation(key, "stop requested with the ledger unavailable");
                return StopReply::Unknown {
                    reason: format!(
                        "the ledger did not answer; containment was dispatched: {error}"
                    ),
                };
            }
        }
        self.stop_allocation(key, reason.as_str(), deadline).await
    }

    /// Settles J's and V's worker rows once each is provably gone.
    async fn settle_children(&self, key: AllocationKey) -> Result<(), String> {
        let children: Vec<(i64, ProcessId)> = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .map(|entry| entry.children.clone())
            .unwrap_or_default();
        for (worker_id, process) in children {
            let gone = self
                .probe_process(StopTarget::process(process))
                .await
                .unwrap_or(false);
            if !gone {
                return Err(format!("child {} is still running", process.pid));
            }
            self.queue_record(LedgerRequest::Settle {
                worker_id,
                settlement: "gone".into(),
            });
        }
        Ok(())
    }

    /// The detached body of Remove.
    pub(super) async fn remove_flow(self: Arc<Self>, token: RemoveToken) -> FenceReply {
        let key = token.key();
        if !self.removing.lock().unwrap().insert(key) {
            return ambiguous_fence(AmbiguousClass::Pending, "a removal is already in progress");
        }
        let reply = self.clone().remove_inner(&token).await;
        self.removing.lock().unwrap().remove(&key);
        reply
    }

    async fn remove_inner(self: Arc<Self>, token: &RemoveToken) -> FenceReply {
        let key = token.key();
        let state = match self.allocation_state(key, token.deadline).await {
            // B7 RTC-6: rows win, and evidence for one plan never releases another's.
            Ok(Some(state)) if state.plan_digest != token.plan_digest => {
                return ambiguous_fence(
                    AmbiguousClass::Conflict,
                    "token is active with a different plan",
                );
            }
            Ok(Some(state)) => state,
            Ok(None) => {
                // A retired token answers with its fence, a compacted one with a receipt
                // synthesized for this digest (RTC-8); anything else is unknown here, and
                // Remove never acts on a token with no rows.
                let lookup = self
                    .bounded_ledger(
                        &LedgerRequest::Inspect {
                            instance: key.instance,
                            allocation: key.allocation,
                            plan_digest: token.plan_digest,
                        },
                        token.deadline,
                    )
                    .await;
                return match lookup {
                    Ok(LedgerReply::Lookup(
                        TokenLookup::Fenced { receipt } | TokenLookup::Compacted { receipt },
                    )) => FenceReply::Absent {
                        receipt: WireBytes(receipt),
                    },
                    Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                        ambiguous_fence(AmbiguousClass::Conflict, reason)
                    }
                    Ok(LedgerReply::Lookup(TokenLookup::NotIssued)) => ambiguous_fence(
                        AmbiguousClass::NotIssued,
                        "this token was never issued by this node ledger",
                    ),
                    _ => ambiguous_fence(
                        AmbiguousClass::Conflict,
                        "no journal record: only FenceAbsent can fence an unknown token",
                    ),
                };
            }
            Err(reason) => return ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason),
        };
        #[cfg(test)]
        workers::faults::hold("H.remove.after_state").await;
        if state.phase == "quarantined" {
            return ambiguous_fence(
                AmbiguousClass::Conflict,
                "a quarantined allocation has uncertain identity",
            );
        }
        if !self.epoch_valid(token.instance, token.epoch, token.peer) {
            return ambiguous_fence(AmbiguousClass::OldEpoch, "connection epoch is not current");
        }
        match self
            .stop_allocation(key, StopReason::Delete.as_str(), token.deadline)
            .await
        {
            StopReply::Stopped { .. } => {}
            StopReply::Unknown { reason } => {
                return ambiguous_fence(AmbiguousClass::PermitsUnsettled, reason);
            }
        }
        if let Err(reason) = self.settle_children(key).await {
            return ambiguous_fence(AmbiguousClass::PermitsUnsettled, reason);
        }
        let cleaning = self
            .bounded_ledger(
                &LedgerRequest::SetPhase {
                    instance: key.instance,
                    allocation: key.allocation,
                    from: STOPPABLE.iter().map(|s| s.to_string()).collect(),
                    to: "cleaning".into(),
                },
                token.deadline,
            )
            .await;
        if !matches!(cleaning, Ok(LedgerReply::Generation(_))) {
            return ambiguous_fence(AmbiguousClass::LedgerUnavailable, "CLEANING is not durable");
        }
        // The snapshot read before the fence is stale: S could journal a resource until
        // the fence stopped it. Cleanup acts on the complete journal as it is now, after
        // the stop fence, so a record committed in between is honoured (B4 recheck 3).
        let state = match self.allocation_state(key, token.deadline).await {
            Ok(Some(state)) => state,
            Ok(None) => {
                return ambiguous_fence(
                    AmbiguousClass::Conflict,
                    "the journal record vanished after the stop fence",
                );
            }
            Err(reason) => return ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason),
        };
        let mut recorded = RecordedResources::default();
        for record in &state.resources {
            recorded.absorb(record);
        }
        if let Err(reason) = self
            .run_cleanup(key, &state, &recorded, token.deadline)
            .await
        {
            return ambiguous_fence(AmbiguousClass::ResourcesPresent, reason);
        }
        // K removes the empty tree now that no S is inside it.
        let relative = allocation_cgroup(key);
        let removed = self
            .recovery_remove_cgroup(&relative, recorded.cgroup.clone())
            .await;
        match removed {
            Some(super::cgroup::NodeState::Absent) => {}
            other => {
                return ambiguous_fence(
                    AmbiguousClass::ResourcesPresent,
                    format!("the allocation cgroup was not removed: {other:?}"),
                );
            }
        }
        let fence = FenceToken {
            instance: token.instance,
            epoch: token.epoch,
            peer: token.peer,
            allocation: token.allocation,
            sandbox_id: state.sandbox_id.clone(),
            plan_digest: state.plan_digest,
            deadline: token.deadline,
        };
        self.fence_flow(fence).await
    }

    async fn recovery_remove_cgroup(
        &self,
        relative: &str,
        identity: Option<super::cgroup::CgroupIdentity>,
    ) -> Option<super::cgroup::NodeState> {
        for slot in &self.recovery {
            let channel = {
                let slot = slot.lock().unwrap();
                if slot.reaped {
                    continue;
                }
                slot.channel.clone()
            };
            let request = RecoveryRequest::RemoveCgroup {
                relative: relative.to_string(),
                identity: identity.clone(),
            };
            let call = channel.call::<RecoveryReply>(Lane::Normal, &request, u64::MAX);
            if let Ok(Ok(RecoveryReply::Removed { state })) =
                tokio::time::timeout(Duration::from_secs(2), call).await
            {
                return state;
            }
        }
        None
    }

    /// A cleanup-only S: journaled intent, fork, watch, identity, then the Cleanup
    /// command. Its exit is awaited within the deadline and settles like any S.
    async fn run_cleanup(
        self: &Arc<Self>,
        key: AllocationKey,
        state: &journal::AllocationState,
        recorded: &RecordedResources,
        deadline: WireDeadline,
    ) -> Result<(), String> {
        let image = self
            .config
            .helper_image
            .ok_or("no verified helper image is pinned")?;
        let profile = "profile";
        let plan_value = crate::firecracker::strict_json(&state.plan).map_err(|e| e.to_string())?;
        let profile_name = plan_value[profile]
            .as_str()
            .ok_or("plan profile")?
            .to_string();
        let host = identity::host_name(key.instance, key.allocation);
        let intent = self
            .bounded_ledger(
                &LedgerRequest::AllocationWorkerIntent {
                    instance: key.instance,
                    allocation: key.allocation,
                    spec: Box::new(WorkerIntentSpec {
                        mode: "supervisor".into(),
                        allowed_names: ALLOWED_RESOURCES.iter().map(|n| n.to_string()).collect(),
                        cgroup: format!(
                            "kilnd-firecracker/{}/{host}/{SUPERVISOR_CGROUP_LEAF}",
                            key.instance
                        ),
                        image,
                    }),
                },
                deadline,
            )
            .await;
        let Ok(LedgerReply::WorkerIntent { worker_id, .. }) = intent else {
            return Err("the cleanup worker's intent is not durable".into());
        };
        let (host_end, child) = StdUnixStream::pair().map_err(|e| e.to_string())?;
        let (watch_monitor, watch_child) = StdUnixStream::pair().map_err(|e| e.to_string())?;
        watch_child
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        let mut keep = vec![child.as_raw_fd(), watch_child.as_raw_fd()];
        keep.extend(self.config.table_fds());
        let inherited = self.config.clone();
        let pid = workers::spawn_process(&keep, move || {
            workers::supervisor_main(SupervisorContext {
                config: inherited,
                instance: key.instance,
                allocation: key.allocation,
                profile: profile_name,
                control: Endpoint::new(child),
                watch: watch_child,
                descriptors: None,
            });
        })
        .map_err(|e| e.to_string())?;
        let (channel, events) =
            Channel::spawn(host_end, CONTROL_QUEUE, 0).map_err(|e| e.to_string())?;
        let exited = Arc::new(CancellationToken::new());
        let outcome: CleanupOutcome = Arc::new(Mutex::new(None));
        {
            let mut supervisors = self.supervisors.lock().unwrap();
            let entry = supervisors
                .entry(key)
                .or_insert_with(|| SupervisorEntry::new(pid, channel.clone(), worker_id));
            if entry.exit.is_none() && entry.pid != pid {
                return Err("the previous supervisor has not exited".into());
            }
            entry.pid = pid;
            entry.channel = channel.clone();
            entry.worker_id = worker_id;
            entry.exit = None;
            entry.exited = exited.clone();
            entry.settle_queued = false;
            entry.revoked = true;
            entry.revoke_sent = true;
            entry.stop_fenced = true;
            entry.cleanup = Some(outcome.clone());
        }
        tokio::spawn(Self::supervisor_events(self.clone(), key, events));
        let (monitor_channel, descriptors) = {
            let monitor = self.monitor.lock().unwrap();
            (monitor.worker.channel.clone(), monitor.descriptors.clone())
        };
        let handoff = tokio::time::timeout_at(
            deadline.instant,
            crate::helper::fds::send(&descriptors, &[watch_monitor.as_raw_fd()]),
        )
        .await;
        let watched = matches!(handoff, Ok(Ok(())))
            && matches!(
                tokio::time::timeout_at(
                    deadline.instant,
                    monitor_channel.call::<MonitorReply>(
                        Lane::Normal,
                        &MonitorCommand::RegisterWatch { allocation: key },
                        deadline.ns,
                    ),
                )
                .await,
                Ok(Ok(MonitorReply::Registered))
            );
        drop(watch_monitor);
        let identified = watched
            && matches!(
                tokio::time::timeout_at(
                    deadline.instant,
                    self.ledger_call(
                        Lane::Reserved,
                        &LedgerRequest::RecordWorker { worker_id, pid },
                        deadline.ns,
                    ),
                )
                .await,
                Ok(Ok(LedgerReply::Identity { .. }))
            );
        if !identified {
            channel.close();
            return Err("the cleanup worker could not be watched and recorded".into());
        }
        let plan = String::from_utf8(state.plan.clone()).map_err(|e| e.to_string())?;
        if !channel.notify(&SupervisorCommand::Cleanup {
            deadline_ns: deadline.ns,
            plan,
            resources: Box::new(recorded.clone()),
        }) {
            channel.close();
            return Err("the cleanup worker could not be given its work".into());
        }
        if tokio::time::timeout_at(deadline.instant, exited.cancelled())
            .await
            .is_err()
        {
            return Err("the cleanup worker has not finished; it stays owned".into());
        }
        // Its events are processed before its exit is: give the queue a moment.
        for _ in 0..50 {
            if outcome.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        match outcome.lock().unwrap().clone() {
            Some(Ok(())) => Ok(()),
            Some(Err(reason)) => Err(reason),
            None => Err("the cleanup worker exited without a result".into()),
        }
    }

    /// Scoped collection: each named allocation of this instance, only when proven dead
    /// or already stopped, through Remove's exact path. Live or uncertain ones are left.
    pub(super) async fn gc_flow(
        self: Arc<Self>,
        instance: Id128,
        epoch: Option<Id128>,
        peer: PeerCredentials,
        targets: Vec<crate::helper::protocol::GcTarget>,
        deadline: WireDeadline,
    ) -> Vec<GcResult> {
        let mut results = Vec::new();
        for target in targets {
            let allocation = target.allocation_id;
            let key = AllocationKey {
                instance,
                allocation,
            };
            if deadline.expired() {
                results.push(GcResult {
                    allocation_id: allocation,
                    outcome: GcOutcome::Skipped {
                        reason: "deadline expired before this allocation".into(),
                    },
                });
                continue;
            }
            let outcome = match self.allocation_state(key, deadline).await {
                // B7 RTC-8: a rowless token is answered as Remove would answer it: a
                // retired one by its fence, a compacted one by a receipt synthesized for
                // this target's digest. Nothing acts on it.
                Ok(None) => match self
                    .bounded_ledger(
                        &LedgerRequest::Inspect {
                            instance,
                            allocation,
                            plan_digest: target.plan_digest,
                        },
                        deadline,
                    )
                    .await
                {
                    Ok(LedgerReply::Lookup(
                        TokenLookup::Fenced { receipt } | TokenLookup::Compacted { receipt },
                    )) => GcOutcome::Removed {
                        receipt: WireBytes(receipt),
                    },
                    Ok(LedgerReply::Lookup(TokenLookup::Conflict { reason })) => {
                        GcOutcome::Failed {
                            class: AmbiguousClass::Conflict,
                            message: reason,
                        }
                    }
                    _ => GcOutcome::Skipped {
                        reason: "not an active allocation of this instance".into(),
                    },
                },
                Ok(Some(state)) if state.plan_digest != target.plan_digest => GcOutcome::Failed {
                    class: AmbiguousClass::Conflict,
                    message: "token is active with a different plan".into(),
                },
                Err(reason) => GcOutcome::Failed {
                    class: AmbiguousClass::LedgerUnavailable,
                    message: reason,
                },
                Ok(Some(state)) if state.phase == "quarantined" => GcOutcome::Skipped {
                    reason: "quarantined: identity is uncertain".into(),
                },
                Ok(Some(state)) => {
                    let live = self.proven_live(key, &state).await;
                    if live {
                        GcOutcome::Skipped {
                            reason: "live or not proven dead".into(),
                        }
                    } else {
                        let token = RemoveToken {
                            instance,
                            epoch,
                            peer,
                            allocation,
                            plan_digest: target.plan_digest,
                            deadline,
                        };
                        match self.clone().remove_flow(token).await {
                            FenceReply::Absent { receipt } => GcOutcome::Removed { receipt },
                            FenceReply::Ambiguous { class, message } => {
                                GcOutcome::Failed { class, message }
                            }
                        }
                    }
                }
            };
            results.push(GcResult {
                allocation_id: allocation,
                outcome,
            });
        }
        results
    }

    /// Whether an allocation could still be running: a live, unfenced supervisor, or a
    /// recorded subtree K cannot prove empty. Unknown counts as live.
    async fn proven_live(&self, key: AllocationKey, state: &journal::AllocationState) -> bool {
        let stopped = ["stop_intent", "stopped", "cleaning"].contains(&state.phase.as_str());
        let supervisor_live = self
            .supervisors
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|entry| entry.exit.is_none() && !entry.stop_fenced);
        if supervisor_live && !stopped {
            return true;
        }
        let target = self.stop_target(key, state);
        if target.process.is_none() && target.cgroup.is_none() {
            return supervisor_live;
        }
        !self.probe_process(target).await.unwrap_or(false)
    }

    /// The dispatch-time check every Exec passes (B5; B4 exposed it to tests only). It
    /// reads only memory: the stop fence, S's exit, V's known exit and both monitors'
    /// health.
    pub(super) fn reusable_dispatch(&self, key: AllocationKey) -> bool {
        // B7 RTC-14 and RTC-R2-03: once the latch linearizes, no Validate or Exec frame
        // goes to a guest, whenever the request was queued.
        if self.is_latched() {
            return false;
        }
        let healthy = self.monitor_healthy();
        self.supervisors
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|entry| {
                healthy
                    && !entry.stop_fenced
                    && entry.exit.is_none()
                    && !entry.vm_gone
                    && entry.booted
            })
    }
}
