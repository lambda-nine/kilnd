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
const STOPPABLE: [&str; 7] = [
    "intent",
    "preparing",
    "spawn_intent",
    "booting",
    "stop_intent",
    "stopped",
    "cleaning",
];

pub(super) struct RemoveToken {
    pub instance: Id128,
    pub epoch: Option<Id128>,
    pub peer: PeerCredentials,
    pub allocation: Id128,
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
        // Observations and child identities are evidence, recorded even after a fence,
        // but they never authorize a further effect.
        let evidence_only = matches!(
            record,
            SupervisorRecord::Observed(_) | SupervisorRecord::Child { .. }
        );
        let lane = Lane::Normal;
        let ok = match record {
            SupervisorRecord::Resource(resource) => {
                if let ResourceRecord::Cgroup(identity) = &resource {
                    // M must hold the subtree before J could clone anything into it.
                    let target = StopTarget {
                        process: None,
                        cgroup: Some(super::cgroup::CgroupTarget {
                            path: format!("{}/vm", allocation_cgroup(key)),
                            st_ino: identity.vm_ino,
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
                        ChildRole::Jailer => Role::Jailer,
                        ChildRole::Vm => Role::Firecracker,
                    };
                    (
                        entry.expected.iter().find(|e| e.role == wanted).copied(),
                        match role {
                            ChildRole::Jailer => "jailer",
                            ChildRole::Vm => "vm",
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
                                allowed_names: vec!["vm".into()],
                                cgroup: format!("{host}/vm/vmm"),
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
        };
        if !ok {
            self.contain_allocation(key, "a supervisor record could not be journaled");
        }
        ok && (evidence_only || !fenced)
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

    async fn allocation_state(
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
        let mut target = StopTarget {
            process: recorded.vmm,
            cgroup: recorded.cgroup.map(|identity| super::cgroup::CgroupTarget {
                path: format!("{}/vm", allocation_cgroup(key)),
                st_ino: identity.vm_ino,
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
                .probe_process(StopTarget::process(process), None)
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
            Ok(Some(state)) => state,
            Ok(None) => {
                // A retired token answers with its fence; anything else is unknown here.
                let lookup = self
                    .ledger_call(
                        Lane::Reserved,
                        &LedgerRequest::Inspect {
                            instance: key.instance,
                            allocation: key.allocation,
                        },
                        token.deadline.ns,
                    )
                    .await;
                return match lookup {
                    Ok(LedgerReply::Lookup(TokenLookup::Fenced { receipt })) => {
                        FenceReply::Absent {
                            receipt: WireBytes(receipt),
                        }
                    }
                    _ => ambiguous_fence(
                        AmbiguousClass::Conflict,
                        "no journal record: only FenceAbsent can fence an unknown token",
                    ),
                };
            }
            Err(reason) => return ambiguous_fence(AmbiguousClass::LedgerUnavailable, reason),
        };
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
            .ledger_call(
                Lane::Reserved,
                &LedgerRequest::SetPhase {
                    instance: key.instance,
                    allocation: key.allocation,
                    from: STOPPABLE.iter().map(|s| s.to_string()).collect(),
                    to: "cleaning".into(),
                },
                token.deadline.ns,
            )
            .await;
        if !matches!(cleaning, Ok(LedgerReply::Generation(_))) {
            return ambiguous_fence(AmbiguousClass::LedgerUnavailable, "CLEANING is not durable");
        }
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
            .recovery_remove_cgroup(&relative, recorded.cgroup)
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
                identity,
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
            .ledger_call(
                Lane::Reserved,
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
                deadline.ns,
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
        allocations: Vec<Id128>,
        deadline: WireDeadline,
    ) -> Vec<GcResult> {
        let mut results = Vec::new();
        for allocation in allocations {
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
                Ok(None) => GcOutcome::Skipped {
                    reason: "not an active allocation of this instance".into(),
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
        !self.probe_process(target, None).await.unwrap_or(false)
    }

    /// Test-only: the dispatch-time check a later Exec must pass. It reads only memory:
    /// the stop fence, S's exit, V's known exit and both monitors' health.
    #[cfg(test)]
    pub(super) fn reusable_dispatch(&self, key: AllocationKey) -> bool {
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
