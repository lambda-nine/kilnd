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
use crate::store::{CheckpointPin, ForkRefusal};

/// What a fork's preflight resolved, before anything is reserved.
pub(in crate::manager) struct ForkPlan<'a> {
    checkpoint: Checkpoint,
    session: Session,
    /// The pin's reader: its nonce, and the helper epoch and boot it is dispatched in.
    pub(in crate::manager) reader: HelperDispatch,
    _worker: WorkerPermit<'a>,
}

impl ForkPlan<'_> {
    /// The fork row's immutable provenance (design 7.2).
    pub(in crate::manager) fn provenance(&self) -> Option<CheckpointProvenance> {
        Some(CheckpointProvenance {
            checkpoint: self.checkpoint.id.clone(),
            content_sha256: self.checkpoint.seal.as_ref()?.content_sha256,
        })
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
        if !self.settled {
            self.manager.fork_exit_check(&self.sandbox);
        }
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
        let session = self.checkpoint_session().await.map_err(refused)?;
        Ok(ForkPlan {
            checkpoint: c,
            reader: HelperDispatch {
                operation: Id128::random(),
                helper_epoch: session.epoch,
                boot_id: session.boot,
            },
            session,
            _worker: worker,
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
        let refused = |reason: CheckpointReason, detail: &str| {
            // A Delete or expiry that canceled it is why it failed.
            let reason = if cancel.is_cancelled() {
                CheckpointReason::NotReady
            } else {
                reason
            };
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
                self.release_fork_pin(&sandbox.id, &plan, &evidence).await;
                self.store.fail_create_definitely(&sandbox.id, &detail)?;
                return Err(refused(CheckpointReason::from_helper(reason), &detail));
            }
            Restored::Refused(reason, detail) => {
                // Nothing ran, but no fact says so: the pin waits for the checkpoint's
                // ABSENT (C4's strict rule; its lifetime is never paused).
                restoring.settled = true;
                self.store.fail_create_definitely(&sandbox.id, &detail)?;
                return Err(refused(reason, &detail));
            }
            Restored::Final(RestoreReply::Ambiguous { reason, detail, .. }) => {
                // The reader was reaped, but kiln may have allocated: a legacy ambiguous
                // create, charged; READER_ENDED `unknown` never releases the pin.
                restoring.settled = true;
                (CheckpointReason::from_helper(reason), detail)
            }
            Restored::Unproven(detail) => {
                restoring.settled = true;
                (CheckpointReason::Io, detail)
            }
            Restored::Final(RestoreReply::Pending) | Restored::Abandoned => {
                // Shutdown with the reader's end unknown: CREATING and charged for
                // startup, which fails the row and inspects the pin's reader.
                return Err(Error::ShuttingDown);
            }
        };
        warn!(sandbox = %sandbox.id, checkpoint = %checkpoint, reason = reason.token(), detail = %detail, "sandbox creation from checkpoint failed");
        self.store
            .set_sandbox_state(&sandbox.id, SandboxState::Failed, None, Some(&detail))?;
        Err(refused(reason, &detail))
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
                .compensate_failed_publication(&sandbox.id, backend_id, e)
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

    /// A fork's supervisor ended while its reader may still run (unwind, or shutdown):
    /// with its pin still live, no one in this process follows the reader, so the
    /// barrier is armed and its pass inspects the reader until it settles. Shutdown
    /// leaves it to startup's pass; an unreadable pin counts as live.
    fn fork_exit_check(self: &Arc<Self>, sandbox: &str) {
        if self.shutting_down.is_cancelled() {
            return;
        }
        let live = match self.db().checkpoint_pin(sandbox) {
            Ok(pin) => pin.is_some_and(|p| p.released_at_ms.is_none()),
            Err(_) => true,
        };
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

    /// The pass's fork rule (startup and the barrier retry). A live pin whose fork is
    /// not restoring in this process (`restoring`, from the pass's snapshot) is settled
    /// from its reader's record when the helper still has it: a final `Created` or
    /// `NotCreated` releases the pin with its evidence. A reader still running with no
    /// supervisor blocks the pass; a dead epoch's reader died with its helper, and a
    /// retired or ambiguous one cannot run: their pins wait for the checkpoint's ABSENT
    /// (C4's strict rule) without blocking. Returns whether the pass is blocked.
    pub(in crate::manager) async fn reconcile_fork_pins(
        &self,
        pins: &[(Checkpoint, CheckpointPin)],
        restoring: &HashSet<String>,
        session: Session,
    ) -> Result<bool> {
        let mut blocked = false;
        for (c, pin) in pins {
            if restoring.contains(&pin.sandbox_id)
                || pin.reader.helper_epoch != session.epoch
                || pin.reader.boot_id != session.boot
            {
                continue;
            }
            match self.inspect_reader(c, &pin.reader).await {
                Ok(Some(Restored::Final(
                    RestoreReply::Created { evidence, .. }
                    | RestoreReply::NotCreated { evidence, .. },
                ))) => match self.db().release_checkpoint_pin(&pin.sandbox_id, &evidence) {
                    Ok(_) => {
                        info!(sandbox = %pin.sandbox_id, checkpoint = %c.id, "released a fork's pin from its reader's settled record");
                        self.checkpoint_timer_refresh(c.id.as_str());
                    }
                    Err(e) => {
                        warn!(sandbox = %pin.sandbox_id, error = %format!("{e:#}"), "a fork's settled reader evidence was refused; its pin waits for the checkpoint's removal")
                    }
                },
                Ok(Some(_)) => {}
                Ok(None) => {
                    warn!(sandbox = %pin.sandbox_id, checkpoint = %c.id, "a restore reader runs with no fork supervising it; allocation blocked until it settles");
                    blocked = true;
                }
                Err(e) => {
                    warn!(sandbox = %pin.sandbox_id, checkpoint = %c.id, error = %e, "could not inspect a fork's reader; allocation blocked");
                    blocked = true;
                }
            }
        }
        Ok(blocked)
    }
}
