//! The fake backend's checkpoint group (milestone C5a): a scripted root helper with
//! the C3 contract the daemon relies on. Each helper process has an epoch and boot;
//! requests naming another epoch are refused; every fact is sealed evidence about the
//! dispatched nonce from this epoch; a removal tombstones the artifact, so a capture
//! still running then can never complete; and every reply passes the daemon-side
//! `CheckpointResponse::check`, as `KilnRuntime` requires. No files, no workers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tokio_util::sync::CancellationToken;

use super::super::RuntimeError;
use super::{FakeGate, FakeRuntime};
use crate::checkpoint::wire::{
    Activity, ArtifactInspectReply, ArtifactView, CaptureReply, CheckpointCapabilities,
    CheckpointError, CheckpointErrorKind, CheckpointOperation, CheckpointResponse, InventoryEntry,
    InventoryReply, ItemKind, RemoveReply, SourceReply, TrackedArtifact,
};
use crate::checkpoint::{
    ArtifactRecord, ArtifactTarget, CaptureBinding, CheckpointId, CompleteFact, Evidence, Fact,
    Reason, SealedEvidence,
};
use crate::model::{Digest, Id128};

/// The image digest every fake source run records unless a test says otherwise.
pub fn fake_image_sha() -> Digest {
    Digest::of(b"fake image tree")
}

/// One scripted removal outcome; the default is a clean ABSENT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeRemoval {
    Absent,
    Retained(Reason),
    /// The helper did not answer (transport failure); nothing happened.
    Unavailable,
    /// ABSENT committed in the helper, but the reply was lost.
    LoseReply,
}

/// The scripted helper. `None` on [`super::FakeState::checkpoints`] is a
/// backend without the group, like Firecracker.
pub struct FakeCheckpoints {
    /// `kilnd-helper --enable-checkpoints`.
    pub enabled: bool,
    /// The CLI grants leases and lists format 1.
    pub supported: bool,
    pub epoch: Id128,
    pub boot: Id128,
    /// Per source backend ID; absent means a capable `alpine` run.
    pub sources: BTreeMap<String, SourceReply>,
    /// The helper answers nothing to `source` (an older helper closes the frame).
    pub source_unanswered: bool,
    /// One-shot pause in the next `source`, before it answers (a cancellation of the
    /// call ends it as unavailable).
    pub source_gate: Option<FakeGate>,
    /// One-shot pause inside the next capture's worker, before it settles. A daemon
    /// cancellation stops the wait (the reply is `pending`); the worker stays until a
    /// removal tombstones it.
    pub capture_gate: Option<FakeGate>,
    pub capture_fail: Option<(Reason, String)>,
    /// COMPLETE certifies this image digest instead of the run's recorded one, as a
    /// kiln rehash that disagrees with the daemon's record would.
    pub capture_image_sha: Option<Digest>,
    /// The capture published, but its reply was lost.
    pub capture_lose_reply: bool,
    /// The helper is unreachable for every operation.
    pub unavailable: bool,
    /// S as kiln measures it (clamped to R).
    pub charge_bytes: u64,
    pub removals: VecDeque<FakeRemoval>,
    /// One-shot pause in the next removal, after its tombstone and before its outcome.
    pub remove_gate: Option<FakeGate>,
    /// One-shot pause before the next inventory replies.
    pub inventory_gate: Option<FakeGate>,
    /// Published artifacts by checkpoint ID: their generation.
    pub published: BTreeMap<String, u64>,
    /// Admitted captures not yet published or removed (staging may exist).
    pub staging: BTreeSet<String>,
    /// Captures whose worker is still running in this epoch.
    pub workers: BTreeMap<String, CancellationToken>,
    /// Checkpoints removal tombstoned in this epoch.
    pub tombstones: BTreeSet<String>,
    pub inventory_extra: Vec<CheckpointId>,
    /// This epoch's private operation records `inventory` reports, as given.
    pub inventory_tracked: Vec<TrackedArtifact>,
    pub inventory_incomplete: bool,
    /// `inspect` says the published artifact is unreadable.
    pub unreadable: BTreeSet<String>,
    /// `inspect` cannot read the namespace for a moment (`kiln checkpoint ls` could
    /// not run): `Unreadable { Io }` for every artifact.
    pub inspect_io: bool,
    /// Every operation the daemon sent, as `kind` or `kind <id>`.
    pub calls: Vec<String>,
}

impl Default for FakeCheckpoints {
    fn default() -> Self {
        Self {
            enabled: true,
            supported: true,
            epoch: Id128::random(),
            boot: Id128::random(),
            sources: BTreeMap::new(),
            source_unanswered: false,
            source_gate: None,
            capture_gate: None,
            capture_fail: None,
            capture_image_sha: None,
            capture_lose_reply: false,
            unavailable: false,
            charge_bytes: 64 << 10,
            removals: VecDeque::new(),
            remove_gate: None,
            inventory_gate: None,
            published: BTreeMap::new(),
            staging: BTreeSet::new(),
            workers: BTreeMap::new(),
            tombstones: BTreeSet::new(),
            inventory_extra: Vec::new(),
            inventory_tracked: Vec::new(),
            inventory_incomplete: false,
            unreadable: BTreeSet::new(),
            inspect_io: false,
            calls: Vec::new(),
        }
    }
}

impl FakeCheckpoints {
    /// A helper restart: a new epoch; its workers died with the old one (PDEATHSIG),
    /// leaving any staging behind; tombstones and records are gone.
    pub fn restart(&mut self) {
        self.epoch = Id128::random();
        for (_, worker) in std::mem::take(&mut self.workers) {
            worker.cancel();
        }
        self.tombstones.clear();
    }

    fn seal(&self, target: &ArtifactTarget, operation: Id128, fact: Fact) -> SealedEvidence {
        Evidence {
            version: crate::checkpoint::EVIDENCE_VERSION,
            instance: target.instance,
            checkpoint: target.checkpoint.clone(),
            generation: target.generation,
            operation,
            helper_epoch: self.epoch,
            boot_id: self.boot,
            fact,
        }
        .seal()
        .expect("fake evidence fits")
    }

    fn source_of(&self, backend_id: &str) -> SourceReply {
        self.sources
            .get(backend_id)
            .cloned()
            .unwrap_or(SourceReply::Capable {
                image: "alpine".into(),
                image_sha256: fake_image_sha(),
            })
    }

    fn complete(&self, binding: &CaptureBinding) -> SealedEvidence {
        let (image, image_sha256) = match self.source_of(&binding.source) {
            SourceReply::Capable {
                image,
                image_sha256,
            } => (image, image_sha256),
            SourceReply::Unsupported { .. } => ("alpine".into(), fake_image_sha()),
        };
        let id = binding.target.checkpoint.as_str().as_bytes();
        let fact = CompleteFact {
            source: binding.source.clone(),
            content_sha256: Digest::of(&[b"content ", id].concat()),
            binding_sha256: Digest::of(&[b"binding ", id].concat()),
            image,
            image_sha256: self.capture_image_sha.unwrap_or(image_sha256),
            entries: 3,
            logical_bytes: 4096,
            allocated_bytes: 8192.min(self.charge_bytes.min(binding.limit_bytes)),
            charge_bytes: self.charge_bytes.min(binding.limit_bytes),
            limit_bytes: binding.limit_bytes,
        };
        self.seal(
            &binding.target,
            binding.operation,
            Fact::Complete(Box::new(fact)),
        )
    }

    fn record(&self, target: &ArtifactTarget) -> ArtifactRecord {
        let id = target.checkpoint.as_str().as_bytes();
        ArtifactRecord {
            instance: target.instance,
            checkpoint: target.checkpoint.clone(),
            generation: target.generation,
            content_sha256: Digest::of(&[b"content ", id].concat()),
            binding_sha256: Digest::of(&[b"binding ", id].concat()),
            image: "alpine".into(),
            image_sha256: fake_image_sha(),
            entries: 3,
            logical_bytes: 4096,
            allocated_bytes: 8192,
            charge_bytes: self.charge_bytes,
            limit_bytes: self.charge_bytes.max(1 << 20),
        }
    }
}

fn helper_error(kind: CheckpointErrorKind, message: &str) -> CheckpointResponse {
    CheckpointResponse::Error(CheckpointError::new(kind, message))
}

fn unavailable() -> RuntimeError {
    RuntimeError::Backend("root helper checkpoint group unavailable".into())
}

impl FakeRuntime {
    /// Installs a healthy scripted checkpoint group and returns `self`.
    pub fn with_checkpoints(self) -> Self {
        self.state().checkpoints = Some(FakeCheckpoints::default());
        self
    }

    /// Reads or scripts the group (tests); panics when the backend has none.
    pub fn checkpoints<T>(&self, f: impl FnOnce(&mut FakeCheckpoints) -> T) -> T {
        f(self
            .state()
            .checkpoints
            .as_mut()
            .expect("the fake has a checkpoint group"))
    }

    pub(crate) async fn fake_checkpoint(
        &self,
        epoch: Option<Id128>,
        operation: CheckpointOperation,
        cancel: &CancellationToken,
    ) -> Result<CheckpointResponse, RuntimeError> {
        if matches!(
            &operation,
            CheckpointOperation::Source { .. } | CheckpointOperation::Inventory { .. }
        ) {
            let gate = self.checkpoints(|g| match &operation {
                CheckpointOperation::Source { .. } => g.source_gate.take(),
                _ => g.inventory_gate.take(),
            });
            if let Some(gate) = gate {
                tokio::select! {
                    () = gate.hold() => {}
                    () = cancel.cancelled() => return Err(unavailable()),
                }
            }
        }
        let response = self
            .fake_checkpoint_inner(epoch, &operation, cancel)
            .await?;
        let epoch = match &response {
            CheckpointResponse::Capabilities(caps) => caps.helper_epoch,
            _ => epoch,
        };
        response
            .check(&operation, epoch)
            .map_err(|e| RuntimeError::Backend(format!("root helper checkpoint reply: {e}")))?;
        Ok(response)
    }

    async fn fake_checkpoint_inner(
        &self,
        epoch: Option<Id128>,
        operation: &CheckpointOperation,
        cancel: &CancellationToken,
    ) -> Result<CheckpointResponse, RuntimeError> {
        use CheckpointOperation as Op;
        let gate = {
            let mut state = self.state();
            let Some(group) = state.checkpoints.as_mut() else {
                return Err(RuntimeError::Unsupported(
                    crate::checkpoint::BACKEND_UNSUPPORTED.into(),
                ));
            };
            group.calls.push(match operation {
                Op::Capabilities => "capabilities".into(),
                Op::Capture { binding } => format!("capture {}", binding.target.checkpoint),
                Op::Restore { target, .. } => format!("restore {}", target.checkpoint),
                Op::Inspect { target, .. } => format!("inspect {}", target.checkpoint),
                Op::Remove { target, .. } => format!("remove {}", target.checkpoint),
                Op::Inventory { .. } => "inventory".into(),
                Op::Acknowledge { target, .. } => format!("acknowledge {}", target.checkpoint),
                Op::Source { backend_id } => format!("source {backend_id}"),
            });
            if group.unavailable {
                return Err(unavailable());
            }
            if !group.enabled {
                return Ok(match operation {
                    Op::Capabilities => {
                        crate::helper::checkpoint::disabled(&CheckpointOperation::Capabilities)
                    }
                    _ => helper_error(CheckpointErrorKind::Disabled, "disabled"),
                });
            }
            if epoch.is_some_and(|e| e != group.epoch) {
                return Ok(helper_error(
                    CheckpointErrorKind::StaleEpoch,
                    "the request names another helper epoch",
                ));
            }
            match operation {
                Op::Capabilities => {
                    return Ok(CheckpointResponse::Capabilities(Box::new(
                        CheckpointCapabilities {
                            group_version: crate::checkpoint::GROUP_VERSION,
                            enabled: true,
                            helper_epoch: Some(group.epoch),
                            boot_id: Some(group.boot),
                            format_version: crate::checkpoint::FORMAT_VERSION,
                            supported: group.supported,
                            unsupported_reason: (!group.supported)
                                .then(|| "kiln without leases".into()),
                            limits: crate::helper::checkpoint::limits(),
                            copy_workers_busy: 0,
                            cleanup_workers_busy: 0,
                            untracked_workers: 0,
                        },
                    )));
                }
                Op::Source { backend_id } => {
                    if group.source_unanswered {
                        return Err(RuntimeError::Backend(
                            "the root helper closed the connection without a reply".into(),
                        ));
                    }
                    return Ok(CheckpointResponse::Source(Box::new(
                        group.source_of(backend_id),
                    )));
                }
                Op::Capture { binding } => {
                    let id = binding.target.checkpoint.to_string();
                    if group.tombstones.contains(&id) {
                        return Ok(helper_error(CheckpointErrorKind::Busy, "tombstoned"));
                    }
                    group.staging.insert(id.clone());
                    let worker = CancellationToken::new();
                    group.workers.insert(id, worker.clone());
                    Some((group.capture_gate.take(), worker))
                }
                Op::Remove { .. } => None,
                Op::Inspect { target, .. } => {
                    let id = target.checkpoint.to_string();
                    let artifact = if group.inspect_io {
                        ArtifactView::Unreadable {
                            reason: Reason::Io,
                            detail: "kiln checkpoint ls could not be started".into(),
                        }
                    } else if group.unreadable.contains(&id) {
                        ArtifactView::Unreadable {
                            reason: Reason::Corrupt,
                            detail: "unreadable header".into(),
                        }
                    } else if group.published.get(&id) == Some(&target.generation) {
                        ArtifactView::Published {
                            record: group.record(target),
                        }
                    } else if group.staging.contains(&id) {
                        ArtifactView::Partial {
                            staging: 1,
                            removing: 0,
                        }
                    } else {
                        ArtifactView::NotListed
                    };
                    return Ok(CheckpointResponse::Inspected(Box::new(
                        ArtifactInspectReply {
                            helper_epoch: group.epoch,
                            artifact,
                            activity: Activity::default(),
                            operation: None,
                        },
                    )));
                }
                Op::Inventory { .. } => {
                    let mut entries: Vec<InventoryEntry> = group
                        .published
                        .keys()
                        .map(|id| (id, ItemKind::Published))
                        .chain(group.staging.iter().map(|id| (id, ItemKind::Staging)))
                        .map(|(id, kind)| InventoryEntry {
                            checkpoint: CheckpointId::parse(id).expect("fake IDs are valid"),
                            kind,
                        })
                        .collect();
                    entries.extend(group.inventory_extra.iter().map(|c| InventoryEntry {
                        checkpoint: c.clone(),
                        kind: ItemKind::Published,
                    }));
                    return Ok(CheckpointResponse::Inventory(Box::new(InventoryReply {
                        helper_epoch: group.epoch,
                        complete: !group.inventory_incomplete,
                        incomplete_reason: group
                            .inventory_incomplete
                            .then(|| "listing incomplete".into()),
                        entries,
                        unknown_entries: 0,
                        other_entries: 0,
                        tracked: group.inventory_tracked.clone(),
                        untracked_workers: Vec::new(),
                    })));
                }
                Op::Acknowledge { .. } => return Ok(CheckpointResponse::Acknowledged),
                Op::Restore { .. } => {
                    return Ok(helper_error(
                        CheckpointErrorKind::Invalid,
                        "restore is not reachable in this milestone",
                    ));
                }
            }
        };
        match operation {
            Op::Capture { binding } => {
                let (gate, worker) = gate.expect("capture set its worker above");
                self.fake_capture(binding, gate, worker, cancel).await
            }
            Op::Remove { target, operation } => self.fake_remove(target, *operation, cancel).await,
            _ => unreachable!("answered above"),
        }
    }

    async fn fake_capture(
        &self,
        binding: &CaptureBinding,
        gate: Option<FakeGate>,
        worker: CancellationToken,
        cancel: &CancellationToken,
    ) -> Result<CheckpointResponse, RuntimeError> {
        let id = binding.target.checkpoint.to_string();
        if let Some(gate) = gate {
            tokio::select! {
                () = gate.hold() => {}
                // The waiter left; the worker runs on until a removal stops it.
                () = cancel.cancelled() => {
                    return Ok(CheckpointResponse::Captured(Box::new(CaptureReply::Pending)));
                }
                () = worker.cancelled() => {}
            }
        }
        let mut state = self.state();
        let group = state.checkpoints.as_mut().expect("checked above");
        // A removal tombstoned it, or the helper restarted: never COMPLETE.
        if worker.is_cancelled() || group.tombstones.contains(&id) {
            return Ok(CheckpointResponse::Captured(Box::new(
                CaptureReply::Failed {
                    reason: Reason::Busy,
                    detail: "the capture was stopped".into(),
                },
            )));
        }
        group.workers.remove(&id);
        if let Some((reason, detail)) = group.capture_fail.take() {
            return Ok(CheckpointResponse::Captured(Box::new(
                CaptureReply::Failed { reason, detail },
            )));
        }
        group.staging.remove(&id);
        group.published.insert(id, binding.target.generation);
        let evidence = group.complete(binding);
        if std::mem::take(&mut group.capture_lose_reply) {
            return Err(unavailable());
        }
        Ok(CheckpointResponse::Captured(Box::new(
            CaptureReply::Complete { evidence },
        )))
    }

    async fn fake_remove(
        &self,
        target: &ArtifactTarget,
        operation: Id128,
        cancel: &CancellationToken,
    ) -> Result<CheckpointResponse, RuntimeError> {
        let id = target.checkpoint.to_string();
        let gate = {
            let mut state = self.state();
            let group = state.checkpoints.as_mut().expect("checked above");
            group.tombstones.insert(id.clone());
            if let Some(worker) = group.workers.remove(&id) {
                worker.cancel();
            }
            group.remove_gate.take()
        };
        if let Some(gate) = gate {
            tokio::select! {
                () = gate.hold() => {}
                () = cancel.cancelled() => {
                    return Ok(CheckpointResponse::Removed(Box::new(RemoveReply::Pending)));
                }
            }
        }
        let mut state = self.state();
        let group = state.checkpoints.as_mut().expect("checked above");
        let outcome = group.removals.pop_front().unwrap_or(FakeRemoval::Absent);
        let absent = |group: &mut FakeCheckpoints| {
            let existed = group.published.remove(&id).is_some() | group.staging.remove(&id);
            group.seal(target, operation, Fact::Absent { existed })
        };
        Ok(CheckpointResponse::Removed(Box::new(match outcome {
            FakeRemoval::Absent => RemoveReply::Absent {
                evidence: absent(group),
            },
            FakeRemoval::Retained(reason) => {
                // kiln removed nothing; a fresh tombstone is taken back (C3 L1).
                group.tombstones.remove(&id);
                RemoveReply::Retained {
                    reason,
                    detail: format!("scripted {}", reason.token()),
                }
            }
            FakeRemoval::Unavailable => {
                group.tombstones.remove(&id);
                return Err(unavailable());
            }
            FakeRemoval::LoseReply => {
                absent(group);
                return Err(unavailable());
            }
        })))
    }
}
