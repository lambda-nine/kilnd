//! Create from a checkpoint (design `kilnd-checkpoint-fork` sections 4.2, 7.2, 8.2, 10
//! and 11.1; milestone C5a-2): a fork is an ordinary create whose CREATING row, full
//! reservation, key record (digest version 2), provenance and durable read-pin commit
//! together, and whose backend is made by the root helper's `Restore` instead of
//! `Runtime::create`. Reachable only from Rust, and only with `Limits::checkpoints`.
//!
//! Ownership (the C5a-1 round-9 rule, extended): from the reservation until its outcome
//! the fork's supervisor owns its CREATING row, its pin, its worker permit and its
//! entry in the live restore set; its exit leaves the set inside `epoch_transition`.
//! A pin is released only by its reader's READER_ENDED (`complete` or `not_started`,
//! from the pin's own helper epoch) or by the checkpoint's ABSENT (C4); a supervisor
//! that ends while its reader may still run arms the barrier, whose pass inspects the
//! reader by nonce until it settles.
//!
//! The race rules below rely on `main.rs` running every manager task on one
//! current-thread runtime: the reservation and the registration in the live set, and
//! the delete-intent check and READY publication, each happen with no await between
//! them, so a checkpoint Delete or expiry (whose intent and cancellation are also
//! synchronous) is wholly before or wholly after each.

use super::*;
use crate::checkpoint::wire::OperationState;
use crate::checkpoint::wire::RestoreReply;
use crate::model::CheckpointProvenance;
use crate::store::{CheckpointPin, ForkRefusal, ReleasePin};

/// What a fork's preflight resolved, before anything is reserved.
pub(in crate::manager) struct ForkPlan<'a> {
    checkpoint: Checkpoint,
    session: Session,
    /// The pin's reader: its nonce, and the helper epoch and boot it is dispatched in.
    pub(in crate::manager) reader: HelperDispatch,
    _worker: WorkerPermit<'a>,
    /// The preflight's fresh helper answer, for the headroom check (design 6.3); its
    /// sample ends at the check.
    admission: Option<super::capacity::Admission<'a>>,
    /// The restore's charge against headroom, from admission until the fork settles.
    headroom: Option<super::capacity::HeadroomCharge<'a>>,
}

impl ForkPlan<'_> {
    /// The fork row's immutable provenance (design 7.2).
    pub(in crate::manager) fn provenance(&self) -> Option<CheckpointProvenance> {
        Some(CheckpointProvenance {
            checkpoint: self.checkpoint.id.clone(),
            content_sha256: self.checkpoint.seal.as_ref()?.content_sha256,
        })
    }

    /// Design 6.3, under the barrier's lock with no await before the accepting
    /// transaction: the restore's S against the preflight's free space, less what other
    /// admitted captures and forks may still write. Counted until the fork settles.
    pub(in crate::manager) fn admit_headroom(&mut self, headroom: u64) -> Result<()> {
        let charge = self
            .checkpoint
            .seal
            .as_ref()
            .map_or(u64::MAX, |s| s.charge_bytes);
        if let Some(admission) = self.admission.take() {
            self.headroom = Some(admission.admit(headroom, charge)?);
        }
        Ok(())
    }

    /// A fork runs the checkpoint's image identity, so it can be captured in turn.
    pub(in crate::manager) fn identity(&self) -> ImageIdentity {
        ImageIdentity {
            content_sha256: self.checkpoint.image_content_sha256,
            checkpoint_format_version: self.checkpoint.format_version,
        }
    }
}

/// How a restore's reader ended, as far as the daemon can prove it.
enum Restored {
    /// The helper's final reply, with its READER_ENDED evidence.
    Final(RestoreReply),
    /// The helper refused before admitting the reader: kiln never ran, no evidence.
    Refused(CheckpointReason, String),
    /// The reader cannot run any more (the helper restarted, or the nonce was retired),
    /// but nothing says whether kiln allocated: ambiguous, and no evidence.
    Unproven(String),
    /// Shutdown while the reader's end was still unknown: startup reconciles it.
    Abandoned,
}

/// A fork's entry in the live restore set, removed on every exit, unwind included,
/// with the epoch moved. Leaving while the reader may still run takes the exit check.
struct Restoring<'a, R: Runtime> {
    manager: &'a Arc<Manager<R>>,
    checkpoint: String,
    sandbox: String,
    /// The reader's end is known (a final reply, or proof it cannot run).
    settled: bool,
}

impl<R: Runtime> Drop for Restoring<'_, R> {
    fn drop(&mut self) {
        // No longer a live fork: a pass that saw it as one is stale.
        self.manager.epoch_transition(|| {
            let mut restores = self
                .manager
                .checkpoint
                .restores
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(forks) = restores.get_mut(&self.checkpoint) {
                forks.remove(&self.sandbox);
                if forks.is_empty() {
                    restores.remove(&self.checkpoint);
                }
            }
        });
        self.manager.fork_exit_check(&self.sandbox, self.settled);
    }
}

impl<R: Runtime> Manager<R> {
    /// Design 7.2 and 11.1, after the spec's defaults are resolved and before
    /// `prepare_create` (which on a fenced backend issues a token), any row, key record,
    /// pin or helper restore: the feature, then a backend without checkpoints, then
    /// ownership (a foreign ID is `NotFound`, as a missing one; root may fork anyone's,
    /// design 5.2), READY and unexpired, the format, the image name, root-write policy
    /// and writable set, disk >= S, a worker permit and the helper session.
    pub(in crate::manager) async fn fork_preflight(
        self: &Arc<Self>,
        id: &str,
        spec: &SandboxSpec,
        owner_uid: u32,
    ) -> Result<ForkPlan<'_>> {
        let refused = |e: Error| {
            self.checkpoint
                .rejected_forks
                .fetch_add(1, Ordering::Relaxed);
            e
        };
        let limits = self.checkpoint_limits().map_err(refused)?.clone();
        if !self.runtime.checkpoint_backend() {
            return Err(refused(
                CheckpointReason::BackendUnsupported
                    .error("this backend cannot create a sandbox from a checkpoint"),
            ));
        }
        let c = self.visible_checkpoint(id, owner_uid).map_err(refused)?;
        self.fork_compatible(&c, spec).map_err(refused)?;
        let worker = self
            .take_capture_worker(owner_uid, &limits)
            .map_err(refused)?;
        let admission = self.admission_probe().await.map_err(refused)?;
        let session = admission.session;
        Ok(ForkPlan {
            checkpoint: c,
            reader: HelperDispatch {
                operation: Id128::random(),
                helper_epoch: session.epoch,
                boot_id: session.boot,
            },
            session,
            _worker: worker,
            admission: Some(admission),
            headroom: None,
        })
    }

    /// The preflight's checks again, on the checkpoint as it stands, after the
    /// preflight's and prepare's awaits and with none before the accepting
    /// transaction: a checkpoint that became due meanwhile is expired, not pinned.
    pub(in crate::manager) fn fork_recheck(
        self: &Arc<Self>,
        plan: &ForkPlan<'_>,
        spec: &SandboxSpec,
    ) -> Result<()> {
        let id = plan.checkpoint.id.as_str();
        let c = self
            .db()
            .checkpoint(id)?
            .ok_or_else(|| Error::NotFound(format!("checkpoint {id}")))?;
        self.fork_compatible(&c, spec).inspect_err(|_| {
            self.checkpoint
                .rejected_forks
                .fetch_add(1, Ordering::Relaxed);
        })
    }

    /// The checkpoint's state and the resolved spec's compatibility with it. A due
    /// checkpoint is expired here, into DELETING, before any fork is admitted (8.1).
    fn fork_compatible(self: &Arc<Self>, c: &Checkpoint, spec: &SandboxSpec) -> Result<()> {
        let id = c.id.as_str();
        match (c.state, &c.seal) {
            (CheckpointState::Quarantined, _) => {
                return Err(CheckpointReason::Corrupt.error(format!(
                    "checkpoint {id} is quarantined and cannot be forked"
                )));
            }
            (CheckpointState::Ready, Some(_)) if c.is_charged() && !c.accounting_quarantined => {}
            (state, _) => {
                return Err(CheckpointReason::NotReady
                    .error(format!("checkpoint {id} is {}", state.as_str())));
            }
        }
        let pinned = self.db().checkpoint_has_live_pins(id)?;
        if self
            .checkpoint_due(c, pinned)
            .is_some_and(|(due, _)| due <= self.clock.boottime_ms())
        {
            self.expire_checkpoint(id);
            return Err(CheckpointReason::Expired.error(format!("checkpoint {id} expired")));
        }
        if c.format_version != crate::checkpoint::FORMAT_VERSION {
            return Err(CheckpointReason::SandboxUnsupported.error(format!(
                "checkpoint {id} has format {}, this daemon restores {}",
                c.format_version,
                crate::checkpoint::FORMAT_VERSION
            )));
        }
        if spec.image != c.image
            || spec.read_only_root != c.read_only_root
            || normalized_paths(&spec.writable_paths) != c.writable_paths
        {
            return Err(CheckpointReason::SpecMismatch.error(format!(
                "a fork of checkpoint {id} needs its image, root-write policy and writable paths"
            )));
        }
        let required = c.seal.as_ref().map_or(u64::MAX, |s| s.charge_bytes);
        if spec.disk_bytes < required {
            return Err(CheckpointReason::DiskTooSmall.error(format!(
                "a fork of checkpoint {id} needs disk_bytes of at least {required}"
            )));
        }
        Ok(())
    }

    /// The accepting transaction's own refusals (it rechecks after the preflight's
    /// await); nothing was inserted.
    pub(in crate::manager) fn fork_refusal(&self, id: &str, refusal: ForkRefusal) -> Error {
        self.checkpoint
            .rejected_forks
            .fetch_add(1, Ordering::Relaxed);
        match refusal {
            ForkRefusal::NotFound => Error::NotFound(format!("checkpoint {id}")),
            ForkRefusal::NotReady(state) => {
                CheckpointReason::NotReady.error(format!("checkpoint {id} is {}", state.as_str()))
            }
            ForkRefusal::Changed => {
                CheckpointReason::NotReady.error(format!("checkpoint {id} changed"))
            }
            ForkRefusal::SpecMismatch => CheckpointReason::SpecMismatch
                .error(format!("the fork does not match checkpoint {id}")),
            ForkRefusal::DiskTooSmall { required } => CheckpointReason::DiskTooSmall.error(
                format!("a fork of checkpoint {id} needs disk_bytes of at least {required}"),
            ),
        }
    }

    /// After the fork's row, reservation, key record, provenance and pin committed: the
    /// helper restores the checkpoint into a new kiln sandbox before READY (design 4.2),
    /// and the create settles as an ordinary legacy create would. Runs to the outcome
    /// whatever the waiter does; Delete or expiry of the checkpoint cancels it before
    /// READY (8.2).
    pub(in crate::manager) async fn finish_fork(
        self: &Arc<Self>,
        sandbox: Sandbox,
        plan: ForkPlan<'_>,
    ) -> Result<Sandbox> {
        let checkpoint = plan.checkpoint.id.to_string();
        let cancel = CancellationToken::new();
        // Registered with no await since the commit, so a Delete or expiry intent is
        // either before the commit (which refused the pin) or after this (and cancels).
        self.checkpoint
            .restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(checkpoint.clone())
            .or_default()
            .insert(sandbox.id.clone(), cancel.clone());
        let mut restoring = Restoring {
            manager: self,
            checkpoint: checkpoint.clone(),
            sandbox: sandbox.id.clone(),
            settled: false,
        };
        // The accepted fork refreshed the checkpoint's activity; its pin pauses idle.
        self.checkpoint_timer_refresh(&checkpoint);
        info!(sandbox = %sandbox.id, checkpoint = %checkpoint, owner_uid = sandbox.owner_uid, "creating sandbox from checkpoint");
        let restored = self.restore_reader(&sandbox, &plan).await;
        let sandbox_id = sandbox.id.clone();
        // A Delete or expiry that canceled it is why it failed; the stored diagnostic
        // carries the same token as the error (design 7.3).
        let reason_of = |reason: CheckpointReason| {
            if cancel.is_cancelled() {
                CheckpointReason::NotReady
            } else {
                reason
            }
        };
        let refused = |reason: CheckpointReason, detail: &str| {
            reason.error(format!(
                "create sandbox {sandbox_id} from checkpoint {checkpoint}: {detail}"
            ))
        };
        let (reason, detail) = match restored {
            Restored::Final(RestoreReply::Created {
                backend_id,
                evidence,
            }) => {
                restoring.settled = true;
                // The exact backend is the row's before the pin can go, so a restart
                // finds it there or in the helper's record (design 10).
                if let Err(e) = self.store.record_fork_backend(&sandbox.id, &backend_id) {
                    return Err(self
                        .compensate_failed_publication_as(
                            &sandbox.id,
                            &backend_id,
                            e,
                            Some(CheckpointReason::Io),
                        )
                        .await);
                }
                // The copy is complete: the pin goes, even if READY never comes (8.2).
                self.release_fork_pin(&sandbox.id, &plan, &evidence).await;
                return self
                    .publish_fork(sandbox, &backend_id, &checkpoint, &cancel)
                    .await;
            }
            Restored::Final(RestoreReply::NotCreated {
                reason,
                detail,
                evidence,
            }) => {
                restoring.settled = true;
                let reason = reason_of(CheckpointReason::from_helper(reason));
                // Settled before the pin goes: a restart finds it here or in the record.
                // Unrecorded, the pin and record stay for the barrier's pass to settle.
                if let Err(e) =
                    self.fork_not_created(&plan.checkpoint, &sandbox.id, reason, &detail)
                {
                    restoring.settled = false;
                    return Err(e);
                }
                self.release_fork_pin(&sandbox.id, &plan, &evidence).await;
                return Err(refused(reason, &detail));
            }
            Restored::Refused(reason, detail) => {
                // Nothing ran, but no fact says so: the pin waits for the checkpoint's
                // ABSENT (C4's strict rule; its lifetime is never paused).
                restoring.settled = true;
                let reason = reason_of(reason);
                self.store
                    .fail_create_definitely(&sandbox.id, &fork_failure(reason, &detail))?;
                return Err(refused(reason, &detail));
            }
            Restored::Final(RestoreReply::Ambiguous { reason, detail, .. }) => {
                // The reader was reaped, but kiln may have allocated: a legacy ambiguous
                // create, charged; READER_ENDED `unknown` never releases the pin.
                restoring.settled = true;
                (reason_of(CheckpointReason::from_helper(reason)), detail)
            }
            Restored::Unproven(detail) => {
                restoring.settled = true;
                (reason_of(CheckpointReason::Io), detail)
            }
            Restored::Final(RestoreReply::Pending) | Restored::Abandoned => {
                // Shutdown with the reader's end unknown: CREATING and charged for
                // startup, which settles it from the reader's record.
                return Err(Error::ShuttingDown);
            }
        };
        warn!(sandbox = %sandbox.id, checkpoint = %checkpoint, reason = reason.token(), detail = %detail, "sandbox creation from checkpoint failed");
        self.store.set_sandbox_state(
            &sandbox.id,
            SandboxState::Failed,
            None,
            Some(&fork_failure(reason, &detail)),
        )?;
        Err(refused(reason, &detail))
    }

    /// A restore that proved nothing was allocated: the row fails definitely (its
    /// reservation released), and restore-proven corruption first quarantines the
    /// checkpoint, charge kept, so no new fork is admitted (design 10.2's verdict).
    fn fork_not_created(
        &self,
        c: &Checkpoint,
        sandbox: &str,
        reason: CheckpointReason,
        detail: &str,
    ) -> Result<()> {
        if reason == CheckpointReason::Corrupt
            && self.db().record_checkpoint_failure_token(
                c.id.as_str(),
                reason.token(),
                &format!("a restore found the artifact corrupt: {detail}"),
                true,
            )?
        {
            warn!(checkpoint = %c.id, sandbox, "a restore proved the checkpoint corrupt; quarantined, charge kept");
        }
        self.store
            .fail_create_definitely(sandbox, &fork_failure(reason, detail))?;
        Ok(())
    }

    /// The helper's `Restore` in its own task (a panic there is a lost reply, not a
    /// lost supervisor), then, if its reply is not final, the reader by nonce.
    async fn restore_reader(self: &Arc<Self>, sandbox: &Sandbox, plan: &ForkPlan<'_>) -> Restored {
        let c = &plan.checkpoint;
        let Some(seal) = &c.seal else {
            return Restored::Refused(CheckpointReason::NotReady, "unsealed checkpoint".into());
        };
        let operation = CheckpointOperation::Restore {
            target: c.target(),
            content_sha256: seal.content_sha256,
            reader: plan.reader.operation,
            spec: sandbox.spec.clone(),
        };
        let deadline = Instant::now() + self.maintenance_limits().operation_timeout;
        let epoch = plan.session.epoch;
        let call = {
            let manager = Arc::clone(self);
            // Never canceled from here: a canceled call only detaches the waiter. The
            // helper's tombstoning removal stops the reader, which then replies.
            tokio::spawn(async move {
                manager
                    .runtime
                    .checkpoint(Some(epoch), operation, deadline, &CancellationToken::new())
                    .await
            })
        };
        match call.await {
            Ok(Ok(CheckpointResponse::Restored(reply))) if *reply != RestoreReply::Pending => {
                return Restored::Final(*reply);
            }
            Ok(Ok(CheckpointResponse::Error(e))) => {
                let reason = match e.kind {
                    CheckpointErrorKind::Workers => CheckpointReason::Workers,
                    CheckpointErrorKind::Busy => CheckpointReason::Busy,
                    CheckpointErrorKind::Conflict => CheckpointReason::NotReady,
                    _ => CheckpointReason::Io,
                };
                return Restored::Refused(reason, e.message);
            }
            // Pending, a lost reply or a transport failure: the reader may still run.
            other => {
                warn!(sandbox = %sandbox.id, reply = ?other.map(|r| r.map(|r| format!("{r:?}"))), "restore reply not final; following the reader");
            }
        }
        self.follow_reader(plan).await
    }

    /// Asks the helper about the reader's nonce until it settles, with backoff. The
    /// supervisor keeps everything meanwhile; an unkillable reader keeps it forever.
    async fn follow_reader(&self, plan: &ForkPlan<'_>) -> Restored {
        let limits = self.maintenance_limits();
        let mut delay = limits.removal_retry;
        loop {
            if self.shutting_down.is_cancelled() {
                return Restored::Abandoned;
            }
            match self.inspect_reader(&plan.checkpoint, &plan.reader).await {
                Ok(Some(restored)) => return restored,
                Ok(None) => {}
                Err(e) => {
                    warn!(checkpoint = %plan.checkpoint.id, error = %e, "could not inspect a restore's reader; retrying")
                }
            }
            tokio::select! {
                () = self.shutting_down.cancelled() => return Restored::Abandoned,
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(limits.max_removal_retry);
        }
    }

    /// One `Inspect` of a reader nonce in its own epoch: `Some` once its end is known,
    /// `None` while it runs. An unknown nonce is retired by the asking, so it can
    /// never start later.
    async fn inspect_reader(
        &self,
        c: &Checkpoint,
        reader: &HelperDispatch,
    ) -> Result<Option<Restored>> {
        let reply = self
            .runtime
            .checkpoint(
                Some(reader.helper_epoch),
                CheckpointOperation::Inspect {
                    target: c.target(),
                    verify: false,
                    operation: Some(reader.operation),
                },
                Instant::now() + HELPER_QUICK_TIMEOUT,
                &self.shutting_down.child_token(),
            )
            .await
            .map_err(|e| helper_unavailable("root helper restore inspection", e))?;
        match reply {
            CheckpointResponse::Inspected(view) => Ok(match view.operation {
                Some(OperationState::Settled(reply)) => match *reply {
                    CheckpointResponse::Restored(r) if *r != RestoreReply::Pending => {
                        Some(Restored::Final(*r))
                    }
                    other => Some(Restored::Unproven(format!(
                        "the restore's record is not a restore: {other:?}"
                    ))),
                },
                Some(OperationState::Retired) => Some(Restored::Unproven(
                    "the helper has no record of the restore; it can no longer start".into(),
                )),
                Some(OperationState::Active) | None => None,
            }),
            // That helper is gone, and its workers with it (PDEATHSIG).
            CheckpointResponse::Error(e) if e.kind == CheckpointErrorKind::StaleEpoch => {
                Ok(Some(Restored::Unproven(
                    "the helper restarted during the restore; its reader ended with it".into(),
                )))
            }
            other => Err(helper_unavailable(
                "root helper restore inspection",
                format!("{other:?}"),
            )),
        }
    }

    /// Releases the fork's pin with its reader's evidence, then lets the helper drop its
    /// record. A refused or failed release keeps the pin: the checkpoint's ABSENT
    /// releases it later.
    async fn release_fork_pin(
        &self,
        sandbox: &str,
        plan: &ForkPlan<'_>,
        evidence: &SealedEvidence,
    ) {
        match self.db().release_checkpoint_pin(sandbox, evidence) {
            Ok(_) => {
                self.checkpoint_timer_refresh(plan.checkpoint.id.as_str());
                self.acknowledge(
                    &plan.checkpoint,
                    plan.reader.operation,
                    plan.session,
                    &self.shutting_down.child_token(),
                )
                .await;
            }
            Err(e) => {
                warn!(sandbox, checkpoint = %plan.checkpoint.id, error = %format!("{e:#}"), "fork pin kept: its reader evidence was not recorded; the checkpoint's removal releases it");
            }
        }
    }

    /// The restored backend becomes READY, as a legacy create's does (design 4.1's
    /// exec-feature proof included), unless the checkpoint's Delete or expiry canceled
    /// the fork first: then it is compensated like a failed publication.
    async fn publish_fork(
        self: &Arc<Self>,
        sandbox: Sandbox,
        backend_id: &str,
        checkpoint: &str,
        cancel: &CancellationToken,
    ) -> Result<Sandbox> {
        let canceled = || {
            CheckpointReason::NotReady.error(format!(
                "create sandbox {} from checkpoint {checkpoint}: the checkpoint is being deleted",
                sandbox.id
            ))
        };
        if cancel.is_cancelled() {
            let _ = self
                .compensate_legacy_create(
                    &sandbox.id,
                    backend_id,
                    "checkpoint_not_ready: the checkpoint is being deleted",
                )
                .await;
            return Err(canceled());
        }
        let exec_features = self.runtime.restored_exec_features(backend_id).await;
        if let Some(why) = unproven_default_env(&sandbox, exec_features) {
            return Err(self
                .compensate_unproven_features(&sandbox.id, backend_id, &why)
                .await);
        }
        // Checked again after that await, with none before the publication.
        if cancel.is_cancelled() {
            let _ = self
                .compensate_legacy_create(
                    &sandbox.id,
                    backend_id,
                    "checkpoint_not_ready: the checkpoint is being deleted",
                )
                .await;
            return Err(canceled());
        }
        if let Err(e) = self
            .store
            .publish_legacy_ready(&sandbox.id, backend_id, exec_features)
        {
            return Err(self
                .compensate_failed_publication_as(
                    &sandbox.id,
                    backend_id,
                    e,
                    Some(CheckpointReason::Io),
                )
                .await);
        }
        info!(sandbox = %sandbox.id, backend_id, checkpoint, "sandbox ready from checkpoint");
        let id = sandbox.id.clone();
        let fallback = Sandbox {
            backend_id: Some(backend_id.to_string()),
            state: SandboxState::Ready,
            ..sandbox
        };
        Ok(self.store.sandbox(&id)?.unwrap_or(fallback))
    }

    /// Checkpoint Delete and expiry (D1): every fork restoring it fails before READY.
    pub(in crate::manager) fn cancel_restores(&self, checkpoint: &str) {
        if let Some(forks) = self
            .checkpoint
            .restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(checkpoint)
        {
            for cancel in forks.values() {
                cancel.cancel();
            }
        }
    }

    /// The forks restoring in this process, by sandbox ID.
    pub(in crate::manager) fn live_restores(&self) -> HashSet<String> {
        self.checkpoint
            .restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .flat_map(|forks| forks.keys().cloned())
            .collect()
    }

    /// A fork's supervisor ended (unwind, or shutdown included) and no one in this
    /// process follows it any more: if its row is still CREATING, or its reader may
    /// still run with its pin live, the barrier is armed and its pass settles the fork
    /// from its reader's record. Shutdown leaves it to startup; an unreadable row or
    /// pin counts as unsettled.
    fn fork_exit_check(self: &Arc<Self>, sandbox: &str, settled: bool) {
        if self.shutting_down.is_cancelled() {
            return;
        }
        let creating = self
            .store
            .sandbox(sandbox)
            .map(|s| s.is_some_and(|s| s.state == SandboxState::Creating));
        let pinned = || {
            self.db()
                .checkpoint_pin(sandbox)
                .map(|pin| pin.is_some_and(|p| p.released_at_ms.is_none()))
        };
        let live = creating.unwrap_or(true) || (!settled && pinned().unwrap_or(true));
        if live {
            warn!(
                sandbox,
                "a fork left its restore untracked; allocation blocked until the barrier's pass settles its reader"
            );
            if let Err(e) = self.set_checkpoint_barrier(true) {
                warn!(sandbox, error = %format!("{e:#}"), "could not write the checkpoint barrier's marker; allocation stays blocked in memory");
            }
            self.spawn_barrier_retry();
        }
    }

    /// The pass's fork rule (startup and the barrier retry), driven by fork rows, not
    /// by live pins alone: every fork in `forks` (each CREATING fork row, and each live
    /// pin's sandbox) that no supervisor in this process owns (`restoring`, from the
    /// pass's snapshot) is settled by [`Self::settle_unowned_fork`]. Returns those
    /// that block: no pass is clean beside an unowned CREATING fork row.
    pub(in crate::manager) async fn reconcile_forks(
        &self,
        forks: &BTreeSet<String>,
        restoring: &HashSet<String>,
        session: Option<Session>,
    ) -> Result<HashSet<String>> {
        let mut blocked = HashSet::new();
        for id in forks.iter().filter(|id| !restoring.contains(*id)) {
            if self.settle_unowned_fork(id, session).await? {
                blocked.insert(id.clone());
            }
        }
        Ok(blocked)
    }

    /// Startup, before the sandbox pass (design 10): every CREATING fork is settled
    /// from what is durably known, so its exact backend is owned before inventory and
    /// its reservation is never left to the legacy no-ID rule. Those still CREATING (a
    /// reader that may run, a helper that cannot be asked, a failed settlement write)
    /// are returned: the legacy rule skips them, and the barrier's pass blocks on them.
    pub(in crate::manager) async fn settle_interrupted_forks(&self) -> Result<HashSet<String>> {
        if !self.maintained() {
            return Ok(HashSet::new());
        }
        let forks: BTreeSet<String> = self
            .db()
            .creating_forks(self.runtime.name())?
            .into_iter()
            .collect();
        if forks.is_empty() {
            return Ok(HashSet::new());
        }
        let session = self.checkpoint_session().await.inspect_err(|e| {
            warn!(error = %e, "the checkpoint helper cannot be asked about interrupted forks; they wait for the barrier's pass");
        });
        self.reconcile_forks(&forks, &HashSet::new(), session.ok())
            .await
    }

    /// One fork no supervisor here owns, sandbox first and pin second, so every crash
    /// point leaves a fact to resume from. Its settlement handle is its pin row (the
    /// reader's nonce, epoch and boot), live or released: the checkpoint's ABSENT
    /// releases it only once no reader remains, so the reader's record is final then,
    /// and the row is settled from it all the same. A recorded backend is compensated
    /// first; then the reader's record in its own live helper epoch settles the row,
    /// and a dead epoch fails it, typed. Returns whether it blocks: its row is still
    /// CREATING, or its live pin's reader cannot be asked.
    async fn settle_unowned_fork(&self, id: &str, session: Option<Session>) -> Result<bool> {
        let creating = || -> Result<Option<Sandbox>> {
            Ok(self.store.sandbox(id)?.filter(|s| {
                s.state == SandboxState::Creating && s.lifecycle.from_checkpoint.is_some()
            }))
        };
        if let Some(backend_id) = creating()?.and_then(|s| s.backend_id) {
            self.compensate_lost_fork(id, &backend_id).await;
            // A failed compensation's intent stays CREATING: retried by the next pass.
            if creating()?.is_some() {
                return Ok(true);
            }
        }
        let row = creating()?;
        let Some(pin) = self.db().checkpoint_pin(id)? else {
            // A fork's pin commits with its row; without one nothing can be asked.
            if row.is_some()
                && let Err(e) = self
                    .fail_orphaned_fork(id, CheckpointReason::Io, "its read pin is missing")
                    .await
            {
                warn!(sandbox = id, error = %format!("{e:#}"), "could not fail an orphaned fork");
            }
            return Ok(creating()?.is_some());
        };
        if row.is_none() && pin.released_at_ms.is_some() {
            return Ok(false);
        }
        let c = self
            .db()
            .checkpoint(pin.checkpoint.as_str())?
            .ok_or_else(|| {
                Error::Internal(anyhow::anyhow!("fork {id}'s checkpoint row is missing"))
            })?;
        let inspected = match session {
            Some(s) if pin.reader.helper_epoch == s.epoch && pin.reader.boot_id == s.boot => {
                self.inspect_reader(&c, &pin.reader).await
            }
            Some(_) => Ok(Some(Restored::Unproven(
                "the helper restarted during the restore; its reader ended with it".into(),
            ))),
            None => Err(helper_unavailable(
                "root helper restore inspection",
                "no helper session",
            )),
        };
        let blocked = self.settle_orphaned_fork(&c, &pin, inspected).await;
        Ok(blocked || creating()?.is_some())
    }

    /// A fork no supervisor in this process owns, settled from its reader's record:
    /// `Created` compensates that exact backend (a fork whose waiter and READY checks
    /// were lost is a failed create, as legacy compensation makes it); `NotCreated`
    /// fails it definitely, releasing its reservation; an ambiguous or unproven end
    /// fails a still-CREATING row as a legacy ambiguous create, charged. Then a live
    /// pin goes with the evidence (an ABSENT-released one answers `AlreadyReleased`).
    /// Returns whether it blocks: the reader may still run, or a settlement write
    /// failed (the row stays CREATING for the next pass).
    async fn settle_orphaned_fork(
        &self,
        c: &Checkpoint,
        pin: &CheckpointPin,
        inspected: Result<Option<Restored>>,
    ) -> bool {
        let id = pin.sandbox_id.as_str();
        let restored = match inspected {
            Ok(Some(restored)) => restored,
            Ok(None) => {
                warn!(sandbox = id, checkpoint = %c.id, "a restore reader runs with no fork supervising it; allocation blocked until it settles");
                return true;
            }
            Err(e) => {
                warn!(sandbox = id, checkpoint = %c.id, error = %e, "could not inspect a fork's reader; allocation blocked");
                return true;
            }
        };
        let row = self.store.sandbox(id).ok().flatten();
        let creating = row
            .as_ref()
            .is_some_and(|s| s.state == SandboxState::Creating);
        let unsettled = |e: Error| {
            warn!(sandbox = id, error = %format!("{e:#}"), "could not record an orphaned fork's settlement; allocation blocked");
            true
        };
        let evidence = match restored {
            Restored::Final(RestoreReply::Created {
                backend_id,
                evidence,
            }) => {
                if creating
                    && row
                        .and_then(|s| s.backend_id)
                        .is_none_or(|recorded| recorded == backend_id)
                {
                    self.compensate_lost_fork(id, &backend_id).await;
                }
                evidence
            }
            Restored::Final(RestoreReply::NotCreated {
                reason,
                detail,
                evidence,
            }) => {
                let reason = CheckpointReason::from_helper(reason);
                if creating && let Err(e) = self.fork_not_created(c, id, reason, &detail) {
                    return unsettled(e);
                }
                evidence
            }
            Restored::Final(RestoreReply::Ambiguous { reason, detail, .. }) => {
                let reason = CheckpointReason::from_helper(reason);
                return self
                    .fail_orphaned_fork(id, reason, &detail)
                    .await
                    .is_err_and(unsettled);
            }
            Restored::Unproven(detail) => {
                return self
                    .fail_orphaned_fork(id, CheckpointReason::Io, &detail)
                    .await
                    .is_err_and(unsettled);
            }
            Restored::Final(RestoreReply::Pending)
            | Restored::Refused(..)
            | Restored::Abandoned => {
                return false;
            }
        };
        match self.db().release_checkpoint_pin(id, &evidence) {
            Ok(ReleasePin::Released) => {
                info!(sandbox = id, checkpoint = %c.id, "settled a fork and released its pin from its reader's record");
                self.checkpoint_timer_refresh(c.id.as_str());
            }
            Ok(_) => {
                info!(sandbox = id, checkpoint = %c.id, "settled a fork from its reader's record; its pin was already released");
            }
            Err(e) => {
                warn!(sandbox = id, error = %format!("{e:#}"), "a fork's settled reader evidence was refused; its pin waits for the checkpoint's removal")
            }
        }
        false
    }

    /// An orphaned fork whose reader ended without proof either way: a still-CREATING
    /// row fails as a legacy ambiguous create, typed and charged (its pin waits for
    /// ABSENT). A row with a recorded backend is never failed beside it (the legacy
    /// tag would call it compensated and release it): that exact backend is
    /// compensated instead.
    async fn fail_orphaned_fork(
        &self,
        id: &str,
        reason: CheckpointReason,
        detail: &str,
    ) -> Result<()> {
        let Some(row) = self
            .store
            .sandbox(id)?
            .filter(|s| s.state == SandboxState::Creating)
        else {
            return Ok(());
        };
        if let Some(backend_id) = &row.backend_id {
            self.compensate_lost_fork(id, backend_id).await;
            return Ok(());
        }
        let failure = fork_failure(reason, &format!("kilnd lost the fork: {detail}"));
        self.store
            .set_sandbox_state(id, SandboxState::Failed, None, Some(&failure))?;
        Ok(())
    }

    /// An orphaned fork's exact restored backend is removed, as a failed publication's
    /// is; a failed removal stays DELETING and charged, which Delete and startup retry.
    async fn compensate_lost_fork(&self, id: &str, backend_id: &str) {
        let reason = fork_failure(
            CheckpointReason::Io,
            "kilnd lost the fork before it was ready",
        );
        match self.compensate_legacy_create(id, backend_id, &reason).await {
            Ok(()) => {
                warn!(
                    sandbox = id,
                    backend_id, "compensated a fork that lost its supervisor before READY"
                );
            }
            Err(e) => {
                warn!(sandbox = id, backend_id, error = %e, "an orphaned fork's backend could not be removed; kept DELETING and charged");
            }
        }
    }
}

/// A fork failure's stored diagnostic: the same `checkpoint_*` token as its error,
/// then the bounded detail (design 7.3), so a keyed retry's FAILED row stays typed.
fn fork_failure(reason: CheckpointReason, detail: &str) -> String {
    format!(
        "{}: {}",
        reason.token(),
        crate::checkpoint::bounded_detail(detail)
    )
}
