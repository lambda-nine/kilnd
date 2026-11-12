//! The checkpoint group's wire types inside the helper's v3 envelope (milestone C3;
//! design sections 4.3, 10 and 10.1). Replies are on their own `Response::Checkpoint`
//! branch, so every kiln and Firecracker frame stays byte-identical.
use super::{
    ArtifactRecord, ArtifactTarget, CaptureBinding, CheckpointId, CopyOutcome, Fact, Reason,
    SealedEvidence,
};
use crate::helper::protocol::validate_spec;
use crate::model::{Digest, Id128, SandboxSpec};
use serde::{Deserialize, Serialize};

/// One checkpoint request, strict JSON within the v3 frame. No path, flag, command,
/// descriptor or environment: the artifact is named by typed IDs, and the helper picks
/// the storage root and the executable.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRequest {
    pub group_version: u32,
    /// The epoch Capabilities reported, required on every other operation. Another
    /// epoch's request is refused before anything else: that helper is gone, and its
    /// workers with it.
    pub helper_epoch: Option<Id128>,
    pub operation: CheckpointOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointOperation {
    /// The group's version, this helper's epoch and boot, whether the installed CLI
    /// supports checkpoints, the limits and the workers in use. No other effect.
    Capabilities,
    /// `kiln checkpoint capture` for this binding, in a supervised worker.
    Capture { binding: CaptureBinding },
    /// `kiln create --from-checkpoint` as the reader `reader`, after checking that the
    /// artifact is this generation with this content digest.
    Restore {
        target: ArtifactTarget,
        content_sha256: Digest,
        reader: Id128,
        spec: SandboxSpec,
    },
    /// What the namespace and this helper know about one artifact, and optionally one
    /// operation nonce. An unknown nonce is retired by the asking.
    Inspect {
        target: ArtifactTarget,
        verify: bool,
        operation: Option<Id128>,
    },
    /// Tombstone, cancel every worker, wait for their reap, then exact removal.
    Remove {
        target: ArtifactTarget,
        operation: Id128,
    },
    /// The instance's bounded inventory: artifacts, partials, tracked operations and
    /// untracked workers.
    Inventory { instance: Id128 },
    /// The daemon has stored this operation's evidence.
    Acknowledge {
        target: ArtifactTarget,
        operation: Id128,
    },
}

impl CheckpointOperation {
    /// Per-operation ceilings; a wire deadline can only be shorter. Capture, restore and
    /// a verifying inspect take the design's 300-second helper ceiling.
    pub fn timeout_ms(&self) -> u32 {
        match self {
            Self::Capabilities | Self::Acknowledge { .. } => 5_000,
            Self::Inspect { verify: false, .. } | Self::Inventory { .. } => 30_000,
            Self::Remove { .. } => 60_000,
            Self::Capture { .. } | Self::Restore { .. } | Self::Inspect { verify: true, .. } => {
                super::HELPER_CEILING_MS
            }
        }
    }

    /// Health, inspection and cleanup keep the reserved slots; copying never does.
    pub fn is_recovery(&self) -> bool {
        matches!(
            self,
            Self::Capabilities
                | Self::Inspect { verify: false, .. }
                | Self::Remove { .. }
                | Self::Inventory { .. }
                | Self::Acknowledge { .. }
        )
    }
}

impl CheckpointRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.group_version != super::GROUP_VERSION {
            return Err("unsupported checkpoint group version".into());
        }
        let capabilities = matches!(self.operation, CheckpointOperation::Capabilities);
        if capabilities != self.helper_epoch.is_none() {
            return Err("the helper epoch is required on every operation but Capabilities".into());
        }
        match &self.operation {
            CheckpointOperation::Capabilities | CheckpointOperation::Inventory { .. } => Ok(()),
            CheckpointOperation::Capture { binding } => binding.validate(),
            CheckpointOperation::Restore { target, spec, .. } => {
                target.validate()?;
                validate_spec(spec)
            }
            CheckpointOperation::Inspect { target, .. }
            | CheckpointOperation::Remove { target, .. }
            | CheckpointOperation::Acknowledge { target, .. } => target.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointResponse {
    Capabilities(Box<CheckpointCapabilities>),
    Captured(Box<CaptureReply>),
    Restored(Box<RestoreReply>),
    Inspected(Box<ArtifactInspectReply>),
    Removed(Box<RemoveReply>),
    Inventory(Box<InventoryReply>),
    Acknowledged,
    Error(CheckpointError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCapabilities {
    pub group_version: u32,
    /// False unless root started the helper with checkpoints enabled.
    pub enabled: bool,
    pub helper_epoch: Option<Id128>,
    pub boot_id: Option<Id128>,
    pub format_version: u32,
    /// The installed CLI grants operation 6 leases (bit 0x40) and lists the artifact
    /// namespace in format 1.
    pub supported: bool,
    pub unsupported_reason: Option<String>,
    pub limits: HelperLimits,
    pub copy_workers_busy: u32,
    pub cleanup_workers_busy: u32,
    /// Processes naming an artifact that this epoch did not start: an earlier helper's
    /// workers, or root's own commands. While any exists, no absence is certified for
    /// the artifact it names.
    pub untracked_workers: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperLimits {
    pub copy_workers: u32,
    pub cleanup_workers: u32,
    pub max_tracked_artifacts: u32,
    pub max_settled_operations: u32,
    pub max_inventory_entries: u32,
    pub helper_ceiling_ms: u32,
    pub tombstone_quiet_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureReply {
    Complete {
        evidence: SealedEvidence,
    },
    /// No COMPLETE evidence. Staging may remain: only Remove proves absence.
    Failed {
        reason: Reason,
        detail: String,
    },
    /// The waiter stopped (its deadline or disconnect); the supervised worker keeps
    /// running to its own deadline, and Inspect with this operation reads its outcome.
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreReply {
    /// The new sandbox exists; its reader ended with the copy complete.
    Created {
        backend_id: String,
        evidence: SealedEvidence,
    },
    /// Definitely nothing was allocated (a refusal before `kiln create`, or its exit 124).
    NotCreated {
        reason: Reason,
        detail: String,
        evidence: SealedEvidence,
    },
    /// A sandbox may exist (legacy create ambiguity), and the copy's end is unknown.
    Ambiguous {
        reason: Reason,
        detail: String,
        evidence: SealedEvidence,
    },
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoveReply {
    Absent {
        evidence: SealedEvidence,
    },
    /// Not proven absent: the charge stays. The tombstone stays too, so retry.
    Retained {
        reason: Reason,
        detail: String,
    },
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInspectReply {
    pub helper_epoch: Id128,
    pub artifact: ArtifactView,
    pub activity: Activity,
    pub operation: Option<OperationState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactView {
    Published {
        record: ArtifactRecord,
    },
    /// Published but not readable as this artifact: a typed kiln refusal, or a record
    /// that names another generation.
    Unreadable {
        reason: Reason,
        detail: String,
    },
    /// Only staging or removal directories: an interrupted capture or removal.
    Partial {
        staging: u32,
        removing: u32,
    },
    /// The namespace lists nothing for it. An observation, never ABSENT evidence.
    NotListed,
    /// Not read: a capture or removal holds it.
    Withheld,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    Capture,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusiveOp {
    pub kind: OpKind,
    pub operation: Id128,
}

/// This helper epoch's private operation record for one artifact.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub exclusive: Option<ExclusiveOp>,
    /// Reader leases: restores and inspections, each until its worker is reaped.
    pub readers: Vec<Id128>,
    /// The removal nonce once a removal began. Nothing can capture, read or publish
    /// this artifact again in this epoch.
    pub tombstone: Option<Id128>,
    pub untracked_workers: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationState {
    Active,
    /// Its final reply, exactly as it was or would have been sent.
    Settled(Box<CheckpointResponse>),
    /// Unknown to this epoch, and retired by this inspection: a request naming it is
    /// refused from now on.
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Published,
    Staging,
    Removing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEntry {
    pub checkpoint: CheckpointId,
    pub kind: ItemKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedArtifact {
    pub checkpoint: CheckpointId,
    pub generation: u64,
    pub activity: Activity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryReply {
    pub helper_epoch: Id128,
    /// False when the listing could not be read whole, exceeded its bound, or a
    /// worker this epoch did not start names one of the instance's artifacts.
    pub complete: bool,
    pub incomplete_reason: Option<String>,
    pub entries: Vec<InventoryEntry>,
    /// Names in this instance's directory that are no artifact, staging or removal.
    pub unknown_entries: u32,
    /// Everything else in the namespace: other instances' entries and unknown names.
    pub other_entries: u32,
    pub tracked: Vec<TrackedArtifact>,
    pub untracked_workers: Vec<CheckpointId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointErrorKind {
    /// Root did not enable the group.
    Disabled,
    Invalid,
    /// The request names another helper epoch.
    StaleEpoch,
    /// Another operation holds the artifact: `checkpoint_busy`.
    Busy,
    /// A tombstoned artifact, another generation, or a retired or reused nonce.
    Conflict,
    /// No worker slot; nothing queues: `checkpoint_workers`.
    Workers,
    /// The helper's bounded tables are full of records it may not drop yet.
    Capacity,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointError {
    pub kind: CheckpointErrorKind,
    pub message: String,
}

impl CheckpointError {
    pub fn new(kind: CheckpointErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into().chars().take(512).collect(),
        }
    }
}

impl CheckpointResponse {
    /// The daemon's check of one reply against the request it sent (C3's runtime
    /// adapter): the right kind, this helper epoch, and every piece of evidence about
    /// exactly the artifact, nonce and fact asked about. Anything else is refused, and
    /// the caller keeps whatever it had charged.
    pub fn check(
        &self,
        operation: &CheckpointOperation,
        epoch: Option<Id128>,
    ) -> Result<(), String> {
        use CheckpointOperation as Op;
        let epoch_is = |seen: Id128| {
            if Some(seen) == epoch {
                Ok(())
            } else {
                Err("a checkpoint reply from another helper epoch".to_string())
            }
        };
        let replying =
            || epoch.ok_or_else(|| "a checkpoint fact without a helper epoch".to_string());
        let fact = |evidence: &SealedEvidence, target, operation, kind| {
            evidence
                .verify_reply(target, operation, kind, replying()?)
                .map(drop)
        };
        let restore = |reply: &RestoreReply, target, reader| {
            let (evidence, copy) = match reply {
                RestoreReply::Pending => return Ok(()),
                RestoreReply::Created {
                    backend_id,
                    evidence,
                } => {
                    if !crate::runtime::kiln_direct::valid_kiln_id(backend_id) {
                        return Err("a restore reply with an invalid backend ID".to_string());
                    }
                    (evidence, CopyOutcome::Complete)
                }
                RestoreReply::NotCreated { evidence, .. } => (evidence, CopyOutcome::NotStarted),
                RestoreReply::Ambiguous { evidence, .. } => (evidence, CopyOutcome::Unknown),
            };
            fact(evidence, target, reader, "reader_ended")?;
            match evidence.evidence.fact {
                Fact::ReaderEnded { copy: seen } if seen == copy => Ok(()),
                _ => Err("a restore reply whose evidence disagrees with it".to_string()),
            }
        };
        // A settled reply replayed by Inspect: final, never Pending, and about this nonce.
        let settled = |reply: &Self, target, nonce| match reply {
            Self::Captured(reply) => match reply.as_ref() {
                CaptureReply::Complete { evidence } => fact(evidence, target, nonce, "complete"),
                CaptureReply::Failed { .. } => Ok(()),
                CaptureReply::Pending => Err("an inspected capture that is not final".into()),
            },
            Self::Restored(reply) if **reply != RestoreReply::Pending => {
                restore(reply, target, nonce)
            }
            Self::Removed(reply) => match reply.as_ref() {
                RemoveReply::Absent { evidence } => fact(evidence, target, nonce, "absent"),
                RemoveReply::Retained { .. } => Ok(()),
                RemoveReply::Pending => Err("an inspected removal that is not final".into()),
            },
            _ => Err("an inspected operation that is not final".to_string()),
        };
        match (operation, self) {
            (_, Self::Error(_)) => Ok(()),
            (Op::Capabilities, Self::Capabilities(caps)) => {
                if caps.group_version != super::GROUP_VERSION
                    || caps.enabled != (caps.helper_epoch.is_some() && caps.boot_id.is_some())
                {
                    return Err("malformed checkpoint capabilities".into());
                }
                Ok(())
            }
            (Op::Capture { binding }, Self::Captured(reply)) => match reply.as_ref() {
                CaptureReply::Complete { evidence } => evidence
                    .verify_complete_reply(binding, replying()?)
                    .map(drop),
                CaptureReply::Failed { .. } | CaptureReply::Pending => Ok(()),
            },
            (Op::Restore { target, reader, .. }, Self::Restored(reply)) => {
                restore(reply, target, *reader)
            }
            (Op::Remove { target, operation }, Self::Removed(reply)) => match reply.as_ref() {
                RemoveReply::Absent { evidence } => fact(evidence, target, *operation, "absent"),
                RemoveReply::Retained { .. } | RemoveReply::Pending => Ok(()),
            },
            (
                Op::Inspect {
                    target, operation, ..
                },
                Self::Inspected(reply),
            ) => {
                epoch_is(reply.helper_epoch)?;
                if let ArtifactView::Published { record } = &reply.artifact
                    && !record.names(target)
                {
                    return Err("an inspection of another artifact".into());
                }
                match (operation, &reply.operation) {
                    (None, None)
                    | (Some(_), Some(OperationState::Active | OperationState::Retired)) => Ok(()),
                    (Some(nonce), Some(OperationState::Settled(reply))) => {
                        settled(reply, target, *nonce)
                    }
                    _ => Err("an inspection that does not answer its question".into()),
                }
            }
            (Op::Inventory { .. }, Self::Inventory(reply)) => {
                epoch_is(reply.helper_epoch)?;
                if reply.entries.len() > super::MAX_INVENTORY_ENTRIES
                    || reply.tracked.len() > super::MAX_TRACKED_ARTIFACTS
                    || (reply.complete && reply.incomplete_reason.is_some())
                {
                    return Err("an inventory outside its bounds".into());
                }
                Ok(())
            }
            (Op::Acknowledge { .. }, Self::Acknowledged) => Ok(()),
            _ => Err("a checkpoint reply of another kind".into()),
        }
    }
}
