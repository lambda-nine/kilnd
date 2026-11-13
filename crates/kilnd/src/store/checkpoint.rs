//! Schema 15's store for workspace checkpoints (design section 9; milestone C4): the
//! checkpoint rows and their charge, helper evidence, capture keys, fork pins and fork
//! provenance, and the audits every accounting decision runs over them. The API here is
//! what C5's RPCs and supervisors call; nothing calls it yet, so the feature stays off.
//!
//! Charge composes with the sandbox reservations in one budget: the node disk total
//! every sandbox admission, Health and checkpoint admission compare against is
//! sandbox disk promises plus checkpoint charges ([`checkpoint_charge`], added in
//! `sandbox_resources`). A checkpoint is charged R from its CAPTURING insert until
//! the READY seal, S from then on, and nothing only once matching ABSENT evidence is
//! stored. An empty table adds zero.

use super::*;
use crate::checkpoint::{
    ArtifactTarget, CaptureBinding, CheckpointId, CopyOutcome, Dispatched, Expected,
    FORMAT_VERSION, Fact, Reason, SealedEvidence,
};
use crate::model::{CheckpointProvenance, ImageIdentity};

pub(super) use super::checkpoint_schema::MIGRATE_V15;

/// The approved defaults (design 6.2; decision 4).
pub const DEFAULT_MAX_CHECKPOINT_BYTES: u64 = 1 << 30;
pub const DEFAULT_MAX_CHECKPOINTS_PER_UID: u64 = 32;
pub const DEFAULT_MAX_CHECKPOINTS: u64 = 128;
pub const DEFAULT_MAX_CHECKPOINT_BYTES_PER_UID: u64 = 4 << 30;
pub const DEFAULT_MAX_CHECKPOINT_BYTES_NODE: u64 = 8 << 30;
pub const DEFAULT_MAX_CHECKPOINT_RECORDS_PER_UID: u64 = 4096;
pub const DEFAULT_MAX_CHECKPOINT_RECORDS: u64 = 32_768;
/// Decision 3 and design 8.1: finite lifetimes only.
pub const MIN_CHECKPOINT_EXPIRY_MS: u64 = 10_000;
pub const MAX_CHECKPOINT_LIFETIME_MS: u64 = 7 * 86_400_000;
pub const MAX_CHECKPOINT_IDLE_MS: u64 = 86_400_000;
/// Terminal checkpoint history is kept at least a day (design 6.2).
pub const MIN_CHECKPOINT_HISTORY_SECS: u64 = 86_400;

pub(super) const CHECKPOINT_MEMBERSHIP_MISMATCH: &str = "degraded accounting: checkpoint membership or counts do not match the rows; admission and pruning disabled";

/// Every column of a checkpoint row, in [`checkpoint_row`]'s order, and whether its
/// release evidence is quarantined.
const CHECKPOINT_COLUMNS: &str = "id, creation_seq, owner_uid, instance_id, generation, format_version,
    source_sandbox_id, source_backend, source_backend_id, capture_operation, capture_helper_epoch,
    capture_boot_id, max_size_bytes, image, image_content_sha256, read_only_root, writable_paths,
    excluded_paths, expiry_lifetime_ms, expiry_idle_ms, state, created_at_ms, updated_at_ms,
    deleted_at_ms, complete_evidence_id, content_sha256, binding_sha256, charge_bytes, logical_bytes,
    allocated_bytes, entry_count, ready_at_ms, ready_boottime_ms, activity_at_ms, activity_boottime_ms,
    clock_boot_id, activity_seq, deletion_reason, expiry_intent_at_ms, expiry_intent_boottime_ms,
    failure_token, failure_reason, removal_operation, removal_helper_epoch, removal_boot_id,
    release_evidence_id, released_at_ms, request_id, request_id_released_at_ms,
    id IN (SELECT id FROM temp.checkpoint_quarantine)";

// A checkpoint's membership: its immutable identity, binding and cap, and its READY
// seal and charge, written once. Lifecycle (state, anchors, activity, reasons,
// removal dispatch and the release reference) is not membership.
const CHECKPOINT_MEMBERSHIP_COLUMNS: &str = "id, creation_seq, owner_uid, instance_id, generation,
    format_version, source_sandbox_id, source_backend, source_backend_id, capture_operation,
    capture_helper_epoch, capture_boot_id, max_size_bytes, image, image_content_sha256,
    read_only_root, writable_paths, excluded_paths, created_at_ms, request_id,
    complete_evidence_id, content_sha256, binding_sha256, charge_bytes, logical_bytes,
    allocated_bytes, entry_count";
const CHECKPOINT_MEMBERSHIP_WIDTH: usize = 27;

/// The rows a checkpoint accounting decision depends on: every charged row (through
/// the partial index), and every row released since the last full audit.
const CHECKPOINT_LIVE_IDS: &str = "SELECT id FROM checkpoints WHERE release_evidence_id IS NULL UNION SELECT id FROM checkpoint_unsettled";

const PIN_COLUMNS: &str = "sandbox_id, checkpoint_id, generation, content_sha256, reader_operation,
    helper_epoch, boot_id, pinned_at_ms, released_at_ms, released_by, release_evidence_id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointState {
    Capturing,
    Ready,
    Deleting,
    Deleted,
    Failed,
    Quarantined,
}

impl CheckpointState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capturing => "capturing",
            Self::Ready => "ready",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "capturing" => Self::Capturing,
            "ready" => Self::Ready,
            "deleting" => Self::Deleting,
            "deleted" => Self::Deleted,
            "failed" => Self::Failed,
            "quarantined" => Self::Quarantined,
            _ => return None,
        })
    }
}

/// A resolved checkpoint expiry policy: both finite (design 8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointExpiry {
    pub lifetime_ms: u64,
    pub idle_ms: u64,
}

impl CheckpointExpiry {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_CHECKPOINT_EXPIRY_MS..=MAX_CHECKPOINT_LIFETIME_MS).contains(&self.lifetime_ms)
            || !(MIN_CHECKPOINT_EXPIRY_MS..=MAX_CHECKPOINT_IDLE_MS).contains(&self.idle_ms)
        {
            bail!("a checkpoint lifetime is 10 s to 7 days and its idle timeout 10 s to 24 h");
        }
        Ok(())
    }
}

/// The READY seal: COMPLETE evidence's facts, written once with READY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSeal {
    pub evidence_id: Digest,
    pub content_sha256: Digest,
    pub binding_sha256: Digest,
    /// S: the conservative independent-restore and storage charge.
    pub charge_bytes: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub entries: u64,
}

/// The helper epoch and boot an operation was dispatched under, and its nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelperDispatch {
    pub operation: Id128,
    pub helper_epoch: Id128,
    pub boot_id: Id128,
}

/// A failure or quarantine: a design 7.3 token and redacted detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointFailure {
    pub token: String,
    pub detail: String,
}

/// One checkpoint row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub creation_seq: i64,
    pub owner_uid: u32,
    pub instance_id: Id128,
    pub generation: u64,
    pub format_version: u32,
    /// Provenance only: the source may be deleted.
    pub source_sandbox_id: String,
    pub source_backend: String,
    pub source_backend_id: String,
    pub capture: HelperDispatch,
    /// R, resolved once at capture admission.
    pub max_size_bytes: u64,
    pub image: String,
    pub image_content_sha256: Digest,
    pub read_only_root: bool,
    pub writable_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub expiry: CheckpointExpiry,
    pub state: CheckpointState,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
    pub seal: Option<CheckpointSeal>,
    pub ready_at_ms: Option<i64>,
    pub ready_boottime_ms: Option<i64>,
    pub activity_at_ms: Option<i64>,
    pub activity_boottime_ms: Option<i64>,
    pub clock_boot_id: Option<String>,
    pub activity_seq: i64,
    pub deletion_reason: Option<DeletionReason>,
    pub expiry_intent_at_ms: Option<i64>,
    pub expiry_intent_boottime_ms: Option<i64>,
    pub failure: Option<CheckpointFailure>,
    /// The latest removal dispatched, whose ABSENT evidence alone can release it.
    pub removal: Option<HelperDispatch>,
    pub release_evidence_id: Option<Digest>,
    pub released_at_ms: Option<i64>,
    pub request_id: Option<String>,
    pub request_id_released_at_ms: Option<i64>,
    /// Its release evidence failed the audit: it is charged again and admission is off.
    pub accounting_quarantined: bool,
}

impl HelperDispatch {
    /// The helper epoch and boot a fact about this dispatch must come from.
    pub fn dispatched(&self) -> Dispatched {
        Dispatched {
            helper_epoch: self.helper_epoch,
            boot_id: self.boot_id,
        }
    }

    /// What a fact about this dispatch must be: its nonce, kind, epoch and boot.
    pub fn expected<'a>(&self, target: &'a ArtifactTarget, kind: &'static str) -> Expected<'a> {
        Expected {
            target,
            operation: self.operation,
            kind,
            helper_epoch: self.helper_epoch,
            boot_id: self.boot_id,
        }
    }
}

impl Checkpoint {
    pub fn target(&self) -> ArtifactTarget {
        ArtifactTarget {
            instance: self.instance_id,
            checkpoint: self.id.clone(),
            generation: self.generation,
        }
    }

    /// What C1 bound and the helper certifies at C3.
    pub fn capture_binding(&self) -> CaptureBinding {
        CaptureBinding {
            target: self.target(),
            operation: self.capture.operation,
            source: self.source_backend_id.clone(),
            limit_bytes: self.max_size_bytes,
        }
    }

    pub fn is_charged(&self) -> bool {
        self.release_evidence_id.is_none() || self.accounting_quarantined
    }

    /// R until the seal, S after it, whatever the state, until released.
    pub fn charge_bytes(&self) -> u64 {
        if !self.is_charged() {
            return 0;
        }
        self.seal
            .as_ref()
            .map_or(self.max_size_bytes, |seal| seal.charge_bytes)
    }
}

/// What a capture's admitting transaction (C1) inserts. The source's backend and
/// backend ID, the instance, the format and the creation sequence come from the store,
/// never from the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCheckpoint {
    pub id: CheckpointId,
    pub owner_uid: u32,
    pub generation: u64,
    pub source_sandbox_id: String,
    pub capture: HelperDispatch,
    pub max_size_bytes: u64,
    /// Normalized: sorted and deduplicated.
    pub writable_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub expiry: CheckpointExpiry,
    pub request_id: Option<String>,
    /// The source run's image identity, read from its own records by the helper at the
    /// first capture (C5a). Recorded write-once in the admitting transaction, before the
    /// source is checked; `None` when the row already has one.
    pub source_identity: Option<ImageIdentity>,
}

/// Checkpoint caps (design 6.2), checked with the insert in one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointBudgets {
    pub max_size_bytes: u64,
    pub max_per_uid: u64,
    pub max_node: u64,
    pub max_bytes_per_uid: u64,
    pub max_bytes_node: u64,
    pub max_records_per_uid: u64,
    pub max_records_node: u64,
    pub max_request_records_per_uid: u64,
    pub max_request_records_node: u64,
}

impl Default for CheckpointBudgets {
    fn default() -> Self {
        Self {
            max_size_bytes: DEFAULT_MAX_CHECKPOINT_BYTES,
            max_per_uid: DEFAULT_MAX_CHECKPOINTS_PER_UID,
            max_node: DEFAULT_MAX_CHECKPOINTS,
            max_bytes_per_uid: DEFAULT_MAX_CHECKPOINT_BYTES_PER_UID,
            max_bytes_node: DEFAULT_MAX_CHECKPOINT_BYTES_NODE,
            max_records_per_uid: DEFAULT_MAX_CHECKPOINT_RECORDS_PER_UID,
            max_records_node: DEFAULT_MAX_CHECKPOINT_RECORDS,
            max_request_records_per_uid: DEFAULT_MAX_CHECKPOINT_RECORDS_PER_UID,
            max_request_records_node: DEFAULT_MAX_CHECKPOINT_RECORDS,
        }
    }
}

/// A cap a capture admission met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointExhausted {
    /// `uid` or `node`.
    pub scope: &'static str,
    /// `checkpoints`, `checkpoint bytes`, `checkpoint records` or `disk bytes`.
    pub resource: &'static str,
    pub reserved: u64,
    pub requested: u64,
    pub limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveCheckpoint {
    /// CAPTURING, charged R, with its key record if keyed.
    Inserted(Box<Checkpoint>),
    Exhausted(CheckpointExhausted),
    RequestQuota(RequestQuota),
    RequestIdTaken,
    /// R above the node's per-checkpoint limit or the source's disk limit.
    SizeLimit {
        requested: u64,
        limit: u64,
    },
    /// The source is not a READY, checkpoint-capable sandbox of this node.
    SourceUnavailable,
}

/// The node's and one uid's checkpoint usage, from the trigger-kept counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointCounts {
    pub live: u64,
    pub charged_bytes: u64,
    pub records: u64,
    pub keys: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointUsage {
    pub node: CheckpointCounts,
    pub uid: CheckpointCounts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishCheckpoint {
    Published(Box<Checkpoint>),
    /// The row is not CAPTURING (a delete intent won, or it settled).
    NotCapturing(CheckpointState),
    /// The source is no longer READY under the bound backend ID (design 8.2).
    SourceChanged,
    /// The evidence is not this binding's COMPLETE fact. Nothing was written.
    Refused(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettleAbsence {
    /// FAILED from CAPTURING or DELETED from DELETING, charge released, pins released.
    Released(Box<Checkpoint>),
    /// Already released by this same evidence.
    AlreadyReleased(Box<Checkpoint>),
    NotReleasable(CheckpointState),
    /// No removal was dispatched, or the evidence is about something else.
    Refused(String),
}

/// A fork's durable read-pin, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointPin {
    pub sandbox_id: String,
    pub checkpoint: CheckpointId,
    pub generation: u64,
    pub content_sha256: Digest,
    pub reader: HelperDispatch,
    pub pinned_at_ms: i64,
    pub released_at_ms: Option<i64>,
    /// `complete`, `not_started` or `absent`.
    pub released_by: Option<String>,
    pub release_evidence_id: Option<Digest>,
}

/// Why a fork's admitting transaction refused before inserting anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkRefusal {
    /// Missing, or another user's: indistinguishable (design 5.2).
    NotFound,
    NotReady(CheckpointState),
    /// Its generation or content is not what the fork was resolved against.
    Changed,
    SpecMismatch,
    DiskTooSmall {
        required: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveFork {
    Sandbox(ReserveSandbox),
    Refused(ForkRefusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleasePin {
    Released,
    AlreadyReleased,
    NoPin,
}

pub struct CheckpointPage {
    pub rows: Vec<Checkpoint>,
    pub has_more: bool,
}

/// The evidence validator SQL function, mirroring schema 9's receipt validator: the
/// insert trigger refuses bytes [`SealedEvidence::decode`] rejects or whose columns
/// say something else. Not an authenticity boundary: another connection can replace
/// the function, and the audits decode in Rust independently of it.
pub(super) fn register_evidence_validator(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "kilnd_checkpoint_evidence_valid",
        9,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            let (Ok(bytes), Ok(id)) = (ctx.get::<Vec<u8>>(0), ctx.get::<String>(1)) else {
                return Ok(false);
            };
            let Ok(id) = Digest::parse(&id) else {
                return Ok(false);
            };
            let Ok(sealed) = SealedEvidence::decode(&bytes, id) else {
                return Ok(false);
            };
            let e = &sealed.evidence;
            Ok(ctx.get::<String>(2).ok() == Some(e.instance.to_string())
                && ctx.get::<String>(3).ok().as_deref() == Some(e.checkpoint.as_str())
                && ctx.get::<i64>(4).ok() == i64::try_from(e.generation).ok()
                && ctx.get::<String>(5).ok() == Some(e.operation.to_string())
                && ctx.get::<String>(6).ok() == Some(e.helper_epoch.to_string())
                && ctx.get::<String>(7).ok() == Some(e.boot_id.to_string())
                && ctx.get::<String>(8).ok().as_deref() == Some(e.fact.kind()))
        },
    )
}

/// A capture source's backend, backend ID, state, reserved disk, image digest and
/// checkpoint format.
type SourceRow = (
    String,
    Option<String>,
    String,
    i64,
    Option<String>,
    Option<i64>,
);

fn bad(what: &str, e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("checkpoint row: bad {what}: {e}")
}

fn id128(text: String, what: &str) -> Result<Id128> {
    Id128::parse(&text).map_err(|e| bad(what, e))
}

fn digest(text: String, what: &str) -> Result<Digest> {
    Digest::parse(&text).map_err(|e| bad(what, e))
}

fn unsigned(value: i64, what: &str) -> Result<u64> {
    u64::try_from(value).map_err(|e| bad(what, e))
}

fn checkpoint_row(row: &Row<'_>) -> rusqlite::Result<Result<Checkpoint>> {
    // Read every column first, so a SQLite error stays one, then decode.
    let text = |i: usize| row.get::<_, String>(i);
    let opt_text = |i: usize| row.get::<_, Option<String>>(i);
    let int = |i: usize| row.get::<_, i64>(i);
    let opt_int = |i: usize| row.get::<_, Option<i64>>(i);
    let raw = (
        (
            text(0)?,
            int(1)?,
            int(2)?,
            text(3)?,
            int(4)?,
            int(5)?,
            text(6)?,
            text(7)?,
            text(8)?,
            text(9)?,
            text(10)?,
            text(11)?,
        ),
        (
            int(12)?,
            text(13)?,
            text(14)?,
            int(15)?,
            text(16)?,
            text(17)?,
            int(18)?,
            int(19)?,
            text(20)?,
            int(21)?,
            int(22)?,
            opt_int(23)?,
        ),
        (
            opt_text(24)?,
            opt_text(25)?,
            opt_text(26)?,
            opt_int(27)?,
            opt_int(28)?,
            opt_int(29)?,
            opt_int(30)?,
        ),
        (
            opt_int(31)?,
            opt_int(32)?,
            opt_int(33)?,
            opt_int(34)?,
            opt_text(35)?,
            int(36)?,
            opt_text(37)?,
            opt_int(38)?,
            opt_int(39)?,
        ),
        (
            opt_text(40)?,
            opt_text(41)?,
            opt_text(42)?,
            opt_text(43)?,
            opt_text(44)?,
            opt_text(45)?,
            opt_int(46)?,
            opt_text(47)?,
            opt_int(48)?,
            row.get::<_, bool>(49)?,
        ),
    );
    Ok((|| -> Result<Checkpoint> {
        let (
            (
                id,
                seq,
                owner,
                instance,
                generation,
                format,
                source,
                backend,
                backend_id,
                op,
                epoch,
                boot,
            ),
            (
                limit,
                image,
                image_sha,
                ro,
                writable,
                excluded,
                lifetime,
                idle,
                state,
                created,
                updated,
                deleted,
            ),
            (complete, content, binding, charge, logical, allocated, entries),
            (
                ready_at,
                ready_boot,
                activity_at,
                activity_boot,
                clock_boot,
                activity_seq,
                reason,
                intent_at,
                intent_boot,
            ),
            (
                token,
                detail,
                rm_op,
                rm_epoch,
                rm_boot,
                release,
                released_at,
                request_id,
                request_released,
                quarantined,
            ),
        ) = raw;
        let id = CheckpointId::parse(&id).map_err(|e| bad("ID", e))?;
        let paths = |text: String, what: &str| -> Result<Vec<String>> {
            serde_json::from_str(&text).map_err(|e| bad(what, e))
        };
        let seal = match (
            complete, content, binding, charge, logical, allocated, entries,
        ) {
            (None, None, None, None, None, None, None) => None,
            (Some(e), Some(c), Some(b), Some(s), Some(l), Some(a), Some(n)) => {
                Some(CheckpointSeal {
                    evidence_id: digest(e, "complete evidence ID")?,
                    content_sha256: digest(c, "content digest")?,
                    binding_sha256: digest(b, "binding digest")?,
                    charge_bytes: unsigned(s, "charge")?,
                    logical_bytes: unsigned(l, "logical bytes")?,
                    allocated_bytes: unsigned(a, "allocated bytes")?,
                    entries: unsigned(n, "entries")?,
                })
            }
            _ => bail!("checkpoint {id}: partial READY seal"),
        };
        let removal = match (rm_op, rm_epoch, rm_boot) {
            (None, None, None) => None,
            (Some(o), Some(e), Some(b)) => Some(HelperDispatch {
                operation: id128(o, "removal nonce")?,
                helper_epoch: id128(e, "removal epoch")?,
                boot_id: id128(b, "removal boot")?,
            }),
            _ => bail!("checkpoint {id}: partial removal dispatch"),
        };
        let failure = match (token, detail) {
            (None, None) => None,
            (Some(token), Some(detail)) => Some(CheckpointFailure { token, detail }),
            _ => bail!("checkpoint {id}: partial failure"),
        };
        Ok(Checkpoint {
            creation_seq: seq,
            owner_uid: u32::try_from(owner).map_err(|e| bad("owner", e))?,
            instance_id: id128(instance, "instance")?,
            generation: unsigned(generation, "generation")?,
            format_version: u32::try_from(format).map_err(|e| bad("format", e))?,
            source_sandbox_id: source,
            source_backend: backend,
            source_backend_id: backend_id,
            capture: HelperDispatch {
                operation: id128(op, "capture nonce")?,
                helper_epoch: id128(epoch, "capture epoch")?,
                boot_id: id128(boot, "capture boot")?,
            },
            max_size_bytes: unsigned(limit, "cap")?,
            image,
            image_content_sha256: digest(image_sha, "image digest")?,
            read_only_root: ro != 0,
            writable_paths: paths(writable, "writable paths")?,
            excluded_paths: paths(excluded, "excluded paths")?,
            expiry: CheckpointExpiry {
                lifetime_ms: unsigned(lifetime, "lifetime")?,
                idle_ms: unsigned(idle, "idle timeout")?,
            },
            state: CheckpointState::parse(&state)
                .with_context(|| format!("checkpoint {id}: unknown state {state:?}"))?,
            created_at_ms: created,
            updated_at_ms: updated,
            deleted_at_ms: deleted,
            seal,
            ready_at_ms: ready_at,
            ready_boottime_ms: ready_boot,
            activity_at_ms: activity_at,
            activity_boottime_ms: activity_boot,
            clock_boot_id: clock_boot,
            activity_seq,
            deletion_reason: reason
                .map(|r| {
                    DeletionReason::parse(&r)
                        .with_context(|| format!("checkpoint {id}: unknown deletion reason {r:?}"))
                })
                .transpose()?,
            expiry_intent_at_ms: intent_at,
            expiry_intent_boottime_ms: intent_boot,
            failure,
            removal,
            release_evidence_id: release
                .map(|r| digest(r, "release evidence ID"))
                .transpose()?,
            released_at_ms: released_at,
            request_id,
            request_id_released_at_ms: request_released,
            accounting_quarantined: quarantined,
            id,
        })
    })())
}

fn load_checkpoint(conn: &Connection, id: &str) -> Result<Option<Checkpoint>> {
    conn.query_row(
        &format!("SELECT {CHECKPOINT_COLUMNS} FROM checkpoints WHERE id = ?1"),
        [id],
        checkpoint_row,
    )
    .optional()?
    .transpose()
}

fn pin_row(row: &Row<'_>) -> rusqlite::Result<Result<CheckpointPin>> {
    let raw = (
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, i64>(2)?,
        row.get::<_, String>(3)?,
        row.get::<_, String>(4)?,
        row.get::<_, String>(5)?,
        row.get::<_, String>(6)?,
        row.get::<_, i64>(7)?,
        row.get::<_, Option<i64>>(8)?,
        row.get::<_, Option<String>>(9)?,
        row.get::<_, Option<String>>(10)?,
    );
    Ok((|| {
        let (
            sandbox_id,
            checkpoint,
            generation,
            content,
            op,
            epoch,
            boot,
            pinned,
            released,
            by,
            evidence,
        ) = raw;
        Ok(CheckpointPin {
            sandbox_id,
            checkpoint: CheckpointId::parse(&checkpoint).map_err(|e| bad("pin checkpoint", e))?,
            generation: unsigned(generation, "pin generation")?,
            content_sha256: digest(content, "pin digest")?,
            reader: HelperDispatch {
                operation: id128(op, "reader nonce")?,
                helper_epoch: id128(epoch, "reader epoch")?,
                boot_id: id128(boot, "reader boot")?,
            },
            pinned_at_ms: pinned,
            released_at_ms: released,
            released_by: by,
            release_evidence_id: evidence.map(|e| digest(e, "pin evidence ID")).transpose()?,
        })
    })())
}

// --- Membership, counts and evidence audits --------------------------------------

fn hash_checkpoint_row(row: &Row<'_>) -> Result<Membership> {
    use rusqlite::types::ValueRef;
    let mut hash = Sha256::new();
    hash.update(b"kilnd-checkpoint-membership-v1");
    for i in 0..CHECKPOINT_MEMBERSHIP_WIDTH {
        match row.get_ref(i)? {
            ValueRef::Null => hash.update([0]),
            ValueRef::Integer(n) => {
                hash.update([1]);
                hash.update(n.to_le_bytes());
            }
            ValueRef::Real(_) => bail!("{CHECKPOINT_MEMBERSHIP_MISMATCH}"),
            ValueRef::Text(bytes) => {
                hash.update([2]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
            ValueRef::Blob(bytes) => {
                hash.update([3]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
        }
    }
    Ok(Membership {
        count: 1,
        sum: hash.finalize().into(),
    })
}

fn checkpoint_membership_where(
    conn: &Connection,
    filter: &str,
    params: impl rusqlite::Params,
) -> Result<Membership> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {CHECKPOINT_MEMBERSHIP_COLUMNS} FROM checkpoints WHERE {filter}"
    ))?;
    let mut rows = stmt.query(params)?;
    let mut membership = Membership::default();
    while let Some(row) = rows.next()? {
        membership = membership.plus(hash_checkpoint_row(row)?);
    }
    Ok(membership)
}

fn stored_checkpoint_membership(conn: &Connection) -> Result<(Membership, Membership)> {
    let (version, count, sum, settled_count, settled_sum): (i64, i64, Vec<u8>, i64, Vec<u8>) = conn
        .prepare_cached(
            "SELECT version, row_count, row_sum, settled_count, settled_sum FROM checkpoint_membership WHERE id = 1",
        )?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .optional()?
        .context(CHECKPOINT_MEMBERSHIP_MISMATCH)?;
    if version != 1 {
        bail!("{CHECKPOINT_MEMBERSHIP_MISMATCH}");
    }
    let array = |bytes: Vec<u8>| -> Result<[u8; 32]> {
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{CHECKPOINT_MEMBERSHIP_MISMATCH}"))
    };
    Ok((
        Membership {
            count,
            sum: array(sum)?,
        },
        Membership {
            count: settled_count,
            sum: array(settled_sum)?,
        },
    ))
}

fn store_checkpoint_membership(
    conn: &Connection,
    all: Membership,
    settled: Membership,
) -> Result<()> {
    let n = conn.execute(
        "UPDATE checkpoint_membership SET row_count = ?1, row_sum = ?2, settled_count = ?3, settled_sum = ?4 WHERE id = 1",
        params![all.count, &all.sum[..], settled.count, &settled.sum[..]],
    )?;
    if n != 1 {
        bail!("{CHECKPOINT_MEMBERSHIP_MISMATCH}");
    }
    Ok(())
}

/// The one row's membership, for an insert or a seal in the same transaction.
fn row_membership(conn: &Connection, id: &str) -> Result<Membership> {
    let m = checkpoint_membership_where(conn, "id = ?1", [id])?;
    if m.count != 1 {
        bail!("checkpoint {id} is missing");
    }
    Ok(m)
}

/// Every charged checkpoint and every one whose release evidence is quarantined: how
/// many, and the bytes they hold (R or S). Bounded by the charged set.
pub(super) fn checkpoint_charge(conn: &Connection) -> Result<(u64, u64)> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, COALESCE(charge_bytes, max_size_bytes) FROM checkpoints
         WHERE id IN (SELECT id FROM checkpoints WHERE release_evidence_id IS NULL
             UNION SELECT id FROM temp.checkpoint_quarantine)",
    )?;
    let mut rows = stmt.query([])?;
    let (mut count, mut bytes) = (0u64, 0u64);
    while let Some(row) = rows.next()? {
        let amount = u64::try_from(row.get::<_, i64>(1)?).with_context(|| {
            format!(
                "checkpoint {}: negative charge",
                row.get::<_, String>(0).unwrap_or_default()
            )
        })?;
        count += 1;
        bytes = bytes
            .checked_add(amount)
            .context("checkpoint charge overflow")?;
    }
    Ok((count, bytes))
}

/// The cached counters against the rows. `full` compares every column, records and
/// keys included (O(history)); otherwise only the charged columns of the charged rows,
/// through the partial index (bounded by the charged set).
fn verify_counts(conn: &Connection, full: bool) -> Result<()> {
    let sql = if full {
        "WITH rows(owner_uid, live, bytes, records, keys) AS (
             SELECT owner_uid, release_evidence_id IS NULL,
                 CASE WHEN release_evidence_id IS NULL THEN COALESCE(charge_bytes, max_size_bytes) ELSE 0 END, 1, 0
             FROM checkpoints
             UNION ALL SELECT owner_uid, 0, 0, 0, 1 FROM checkpoint_requests),
         actual(owner_uid, live, bytes, records, keys) AS (
             SELECT owner_uid, SUM(live), SUM(bytes), SUM(records), SUM(keys) FROM rows GROUP BY owner_uid
             UNION ALL SELECT -1, COALESCE(SUM(live), 0), COALESCE(SUM(bytes), 0), COALESCE(SUM(records), 0),
                 COALESCE(SUM(keys), 0) FROM rows)
         SELECT EXISTS (SELECT * FROM actual EXCEPT SELECT owner_uid, live, charged_bytes, records, keys FROM checkpoint_counts)
             OR EXISTS (SELECT owner_uid, live, charged_bytes, records, keys FROM checkpoint_counts EXCEPT SELECT * FROM actual)"
    } else {
        "WITH charged(owner_uid, bytes) AS (
             SELECT owner_uid, COALESCE(charge_bytes, max_size_bytes) FROM checkpoints
             WHERE id IN (SELECT id FROM checkpoints WHERE release_evidence_id IS NULL)),
         actual(owner_uid, live, bytes) AS (
             SELECT owner_uid, COUNT(*), SUM(bytes) FROM charged GROUP BY owner_uid
             UNION ALL SELECT -1, COUNT(*), COALESCE(SUM(bytes), 0) FROM charged),
         cached(owner_uid, live, bytes) AS (
             SELECT owner_uid, live, charged_bytes FROM checkpoint_counts
             WHERE live > 0 OR charged_bytes > 0 OR owner_uid = -1)
         SELECT EXISTS (SELECT * FROM actual EXCEPT SELECT * FROM cached)
             OR EXISTS (SELECT * FROM cached EXCEPT SELECT * FROM actual)"
    };
    if conn.query_row(sql, [], |r| r.get::<_, bool>(0))? {
        bail!("{CHECKPOINT_MEMBERSHIP_MISMATCH}");
    }
    Ok(())
}

fn load_evidence(conn: &Connection, id: &Digest) -> Result<Option<(SealedEvidence, [String; 3])>> {
    let row: Option<(Vec<u8>, String, String, String)> = conn
        .query_row(
            "SELECT evidence, helper_epoch, boot_id, kind FROM checkpoint_evidence WHERE evidence_id = ?1",
            [id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((bytes, epoch, boot, kind)) = row else {
        return Ok(None);
    };
    match SealedEvidence::decode(&bytes, *id) {
        Ok(sealed) => Ok(Some((sealed, [epoch, boot, kind]))),
        Err(_) => Ok(None),
    }
}

/// Decoded in Rust, independently of any SQL function: the stored evidence of one
/// row, against the row. Any failure is false.
fn checkpoint_evidence_valid(conn: &Connection, c: &Checkpoint) -> Result<bool> {
    let columns_match = |sealed: &SealedEvidence, stored: &[String; 3]| {
        stored[0] == sealed.evidence.helper_epoch.to_string()
            && stored[1] == sealed.evidence.boot_id.to_string()
            && stored[2] == sealed.evidence.fact.kind()
    };
    if let Some(seal) = &c.seal {
        let Some((sealed, stored)) = load_evidence(conn, &seal.evidence_id)? else {
            return Ok(false);
        };
        let Ok(fact) = sealed.verify_complete(&c.capture_binding(), c.capture.dispatched()) else {
            return Ok(false);
        };
        if !columns_match(&sealed, &stored)
            || fact.content_sha256 != seal.content_sha256
            || fact.binding_sha256 != seal.binding_sha256
            || fact.charge_bytes != seal.charge_bytes
            || fact.logical_bytes != seal.logical_bytes
            || fact.allocated_bytes != seal.allocated_bytes
            || fact.entries != seal.entries
            || fact.image != c.image
            || fact.image_sha256 != c.image_content_sha256
        {
            return Ok(false);
        }
    }
    if let Some(release) = &c.release_evidence_id {
        let (Some(removal), Some((sealed, stored))) = (c.removal, load_evidence(conn, release)?)
        else {
            return Ok(false);
        };
        let target = c.target();
        if sealed.verify(&removal.expected(&target, "absent")).is_err()
            || !columns_match(&sealed, &stored)
            || !matches!(c.state, CheckpointState::Failed | CheckpointState::Deleted)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A released pin's evidence, against the pin and its checkpoint as the store holds
/// them: the target is the checkpoint's own instance, generation and ID, and the fact
/// must come from the reader's dispatch (or the checkpoint's recorded removal), never
/// from anything the evidence says about itself.
fn pin_evidence_valid(conn: &Connection, pin: &CheckpointPin, c: &Checkpoint) -> Result<bool> {
    let (Some(by), Some(id)) = (pin.released_by.as_deref(), pin.release_evidence_id) else {
        return Ok(true);
    };
    let Some((sealed, _)) = load_evidence(conn, &id)? else {
        return Ok(false);
    };
    if pin.checkpoint != c.id || pin.generation != c.generation {
        return Ok(false);
    }
    let target = c.target();
    Ok(match by {
        "complete" | "not_started" => {
            let copy = match &sealed.evidence.fact {
                Fact::ReaderEnded { copy } => *copy,
                _ => return Ok(false),
            };
            sealed
                .verify(&pin.reader.expected(&target, "reader_ended"))
                .is_ok()
                && copy_token(copy) == Some(by)
        }
        "absent" => c
            .removal
            .is_some_and(|removal| sealed.verify(&removal.expected(&target, "absent")).is_ok()),
        _ => false,
    })
}

fn copy_token(copy: CopyOutcome) -> Option<&'static str> {
    match copy {
        CopyOutcome::Complete => Some("complete"),
        CopyOutcome::NotStarted => Some("not_started"),
        CopyOutcome::Unknown => None,
    }
}

fn quarantine(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO temp.checkpoint_quarantine VALUES (?1)",
        [id],
    )?;
    Ok(())
}

/// Rows, their evidence and their pins' evidence: an invalid one is quarantined
/// (charged, and admission refused) for the caller's `quarantined()` check.
fn evidence_checks(conn: &Connection, filter: &str) -> Result<()> {
    let rows: Vec<Checkpoint> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHECKPOINT_COLUMNS} FROM checkpoints WHERE {filter}"
        ))?;
        let rows = stmt.query_map([], checkpoint_row)?;
        rows.map(|r| r?).collect::<Result<_>>()?
    };
    for c in &rows {
        let pins: Vec<CheckpointPin> = {
            let mut stmt = conn.prepare(&format!(
                "SELECT {PIN_COLUMNS} FROM checkpoint_pins WHERE checkpoint_id = ?1 AND released_at_ms IS NOT NULL"
            ))?;
            let pins = stmt.query_map([c.id.as_str()], pin_row)?;
            pins.map(|r| r?).collect::<Result<_>>()?
        };
        let mut valid = checkpoint_evidence_valid(conn, c)?;
        for pin in &pins {
            valid &= pin_evidence_valid(conn, pin, c)?;
        }
        if !valid {
            quarantine(conn, c.id.as_str())?;
        }
    }
    Ok(())
}

/// Every stored evidence row decodes, with its ID, to what its columns say.
fn all_evidence_decodes(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT evidence_id, evidence, instance_id, checkpoint_id, generation, operation, helper_epoch, boot_id, kind
         FROM checkpoint_evidence",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let checkpoint: String = row.get(3)?;
        let valid = (|| -> Result<bool> {
            let id = Digest::parse(&row.get::<_, String>(0)?).map_err(anyhow::Error::msg)?;
            let sealed = SealedEvidence::decode(&row.get::<_, Vec<u8>>(1)?, id)
                .map_err(anyhow::Error::msg)?;
            let e = &sealed.evidence;
            Ok(row.get::<_, String>(2)? == e.instance.to_string()
                && checkpoint == e.checkpoint.as_str()
                && row.get::<_, i64>(4)? == i64::try_from(e.generation)?
                && row.get::<_, String>(5)? == e.operation.to_string()
                && row.get::<_, String>(6)? == e.helper_epoch.to_string()
                && row.get::<_, String>(7)? == e.boot_id.to_string()
                && row.get::<_, String>(8)? == e.fact.kind())
        })()
        .unwrap_or(false);
        if !valid {
            quarantine(conn, &checkpoint)?;
        }
    }
    Ok(())
}

/// The checkpoint half of every accounting audit (design 9.2 item 5). `full`: every
/// row against the stored total, the settled/live partition, every counter, and every
/// evidence row, from which the quarantine is rebuilt (startup, external SQLite changes,
/// prune). Otherwise only what a decision depends on: the partition over the charged
/// and recently released rows, their counters and their evidence. A mismatch is an
/// error: accounting is degraded and nothing is admitted.
pub(super) fn verify_checkpoints(conn: &Connection, full: bool) -> Result<()> {
    let (all, settled) = stored_checkpoint_membership(conn)?;
    // A decision with nothing live to check (no charged or unsettled row, no cached
    // charge, and the stored total equal to the settled one) costs one cached lookup:
    // an idle or unused feature must not slow sandbox admission.
    if !full && all == settled && nothing_live(conn)? {
        return Ok(());
    }
    let live = checkpoint_membership_where(conn, &format!("id IN ({CHECKPOINT_LIVE_IDS})"), [])?;
    if settled.plus(live) != all {
        bail!("{CHECKPOINT_MEMBERSHIP_MISMATCH}");
    }
    if full && checkpoint_membership_where(conn, "1", [])? != all {
        bail!("{CHECKPOINT_MEMBERSHIP_MISMATCH}");
    }
    verify_counts(conn, full)?;
    if full {
        conn.execute("DELETE FROM temp.checkpoint_quarantine", [])?;
        all_evidence_decodes(conn)?;
        evidence_checks(conn, "1")?;
    } else {
        conn.execute(
            &format!("DELETE FROM temp.checkpoint_quarantine WHERE id IN ({CHECKPOINT_LIVE_IDS})"),
            [],
        )?;
        evidence_checks(conn, &format!("id IN ({CHECKPOINT_LIVE_IDS})"))?;
    }
    Ok(())
}

fn nothing_live(conn: &Connection) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT NOT EXISTS (SELECT 1 FROM checkpoints WHERE release_evidence_id IS NULL)
                 AND NOT EXISTS (SELECT 1 FROM checkpoint_unsettled)
                 AND NOT EXISTS (SELECT 1 FROM checkpoint_counts WHERE live != 0 OR charged_bytes != 0)
                 AND EXISTS (SELECT 1 FROM checkpoint_counts WHERE owner_uid = -1)",
        )?
        .query_row([], |r| r.get(0))?)
}

/// In a write decision's transaction, after its audit: released rows join the settled
/// aggregate, as `settle_unsettled` does for sandboxes.
pub(super) fn settle_checkpoints(conn: &Connection) -> Result<()> {
    let any: bool = conn
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM checkpoint_unsettled)")?
        .query_row([], |r| r.get(0))?;
    if !any {
        return Ok(());
    }
    let unsettled = checkpoint_membership_where(
        conn,
        "id IN (SELECT id FROM checkpoint_unsettled) AND release_evidence_id IS NOT NULL",
        [],
    )?;
    if unsettled.count != 0 {
        let (all, settled) = stored_checkpoint_membership(conn)?;
        store_checkpoint_membership(conn, all, settled.plus(unsettled))?;
    }
    conn.execute("DELETE FROM checkpoint_unsettled", [])?;
    Ok(())
}

/// After a full verification: the settled aggregate rebuilt from the rows.
pub(super) fn reseed_settled_checkpoints(conn: &Connection) -> Result<()> {
    let (all, _) = stored_checkpoint_membership(conn)?;
    let settled = checkpoint_membership_where(conn, "release_evidence_id IS NOT NULL", [])?;
    store_checkpoint_membership(conn, all, settled)?;
    conn.execute("DELETE FROM checkpoint_unsettled", [])?;
    Ok(())
}

fn counts_row(conn: &Connection, owner: i64) -> Result<CheckpointCounts> {
    let row: Option<(i64, i64, i64, i64)> = conn
        .query_row(
            "SELECT live, charged_bytes, records, keys FROM checkpoint_counts WHERE owner_uid = ?1",
            [owner],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((live, bytes, records, keys)) = row else {
        return Ok(CheckpointCounts::default());
    };
    Ok(CheckpointCounts {
        live: u64::try_from(live)?,
        charged_bytes: u64::try_from(bytes)?,
        records: u64::try_from(records)?,
        keys: u64::try_from(keys)?,
    })
}

fn usage(conn: &Connection, owner_uid: u32) -> Result<CheckpointUsage> {
    Ok(CheckpointUsage {
        node: counts_row(conn, -1)?,
        uid: counts_row(conn, i64::from(owner_uid))?,
    })
}

fn stored_paths(paths: &[String]) -> Result<String> {
    Ok(serde_json::to_string(paths)?)
}

/// Sorted, deduplicated: the canonical writable-path set compared at fork (design 7.2).
pub fn normalized_paths(paths: &[String]) -> Vec<String> {
    let mut paths = paths.to_vec();
    paths.sort();
    paths.dedup();
    paths
}

/// Records one activity on a READY or pinned checkpoint, in the caller's transaction.
fn record_checkpoint_activity(conn: &Connection, id: &str, now: &ClockReading) -> Result<()> {
    conn.execute(
        "UPDATE checkpoints SET activity_seq = activity_seq + 1, activity_at_ms = ?2,
             activity_boottime_ms = CASE WHEN clock_boot_id IS ?4 THEN ?3 ELSE activity_boottime_ms END
         WHERE id = ?1 AND ready_at_ms IS NOT NULL",
        params![id, now.wall_ms, now.boottime_ms, now.boot_id],
    )?;
    Ok(())
}

pub(super) fn insert_evidence(
    conn: &Connection,
    sealed: &SealedEvidence,
    bytes: &[u8],
    now: i64,
) -> Result<()> {
    let exists: Option<Vec<u8>> = conn
        .query_row(
            "SELECT evidence FROM checkpoint_evidence WHERE evidence_id = ?1",
            [sealed.id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(stored) = exists {
        if stored != bytes {
            bail!(
                "checkpoint evidence {} is stored with other bytes",
                sealed.id
            );
        }
        return Ok(());
    }
    let e = &sealed.evidence;
    conn.execute(
        "INSERT INTO checkpoint_evidence (evidence_id, instance_id, checkpoint_id, generation, operation,
             helper_epoch, boot_id, kind, evidence, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            sealed.id.to_string(),
            e.instance.to_string(),
            e.checkpoint.as_str(),
            i64_amount(e.generation, "checkpoint generation")?,
            e.operation.to_string(),
            e.helper_epoch.to_string(),
            e.boot_id.to_string(),
            e.fact.kind(),
            bytes,
            now,
        ],
    )?;
    Ok(())
}

/// Prunes terminal checkpoint history, in prune's transaction after its full audit:
/// released, unquarantined rows with no capture key and no pins left, last changed
/// before `cutoff_ms`. Their released pins go first; their evidence after them.
pub(super) fn prune_checkpoints(tx: &Connection, cutoff_ms: i64) -> Result<usize> {
    tx.execute_batch("CREATE TEMP TABLE retention_checkpoints (id TEXT PRIMARY KEY);")?;
    tx.execute(
        "INSERT INTO retention_checkpoints SELECT id FROM checkpoints
         WHERE state IN ('deleted', 'failed') AND release_evidence_id IS NOT NULL
           AND id NOT IN (SELECT id FROM temp.checkpoint_quarantine)
           AND NOT EXISTS (SELECT 1 FROM checkpoint_requests WHERE checkpoint_id = checkpoints.id)
           AND NOT EXISTS (SELECT 1 FROM checkpoint_pins WHERE checkpoint_id = checkpoints.id AND released_at_ms IS NULL)
           AND updated_at_ms <= ?1",
        [cutoff_ms],
    )?;
    let removed =
        checkpoint_membership_where(tx, "id IN (SELECT id FROM temp.retention_checkpoints)", [])?;
    tx.execute(
        "DELETE FROM checkpoint_pins WHERE checkpoint_id IN (SELECT id FROM temp.retention_checkpoints)",
        [],
    )?;
    let pruned = tx.execute(
        "DELETE FROM checkpoints WHERE id IN (SELECT id FROM temp.retention_checkpoints)",
        [],
    )?;
    if i64::try_from(pruned)? != removed.count {
        bail!("prune removed a checkpoint row it did not account for");
    }
    tx.execute(
        "DELETE FROM checkpoint_evidence WHERE checkpoint_id IN (SELECT id FROM temp.retention_checkpoints)",
        [],
    )?;
    tx.execute_batch("DROP TABLE temp.retention_checkpoints;")?;
    let (all, settled) = stored_checkpoint_membership(tx)?;
    store_checkpoint_membership(tx, all.minus(removed), settled.minus(removed))?;
    Ok(pruned)
}

/// R3 for capture keys: this boot's records retained at least to `cutoff`, of DELETED
/// or FAILED (released) checkpoints, never a quarantined one.
pub(super) fn prune_checkpoint_requests(
    tx: &Connection,
    boot_id: &str,
    cutoff_boottime_ms: i64,
) -> Result<usize> {
    Ok(tx.execute(
        "DELETE FROM checkpoint_requests WHERE retain_boot_id = ?1 AND retain_from_boottime_ms <= ?2
         AND checkpoint_id IN (SELECT id FROM checkpoints WHERE state IN ('deleted', 'failed')
             AND release_evidence_id IS NOT NULL AND id NOT IN (SELECT id FROM temp.checkpoint_quarantine))",
        params![boot_id, cutoff_boottime_ms],
    )?)
}

pub(super) fn anchor_unanchored_checkpoint_requests(
    tx: &Connection,
    now: &ClockReading,
) -> Result<usize> {
    Ok(tx.execute(
        "UPDATE checkpoint_requests SET retain_boot_id = ?1, retain_from_boottime_ms = ?2 WHERE retain_boot_id IS NULL",
        params![now.boot_id, now.boottime_ms],
    )?)
}

/// The fork checks of design 7.2 at the accepting transaction: READY, the same
/// generation and content the fork was resolved against, its owner (or root), the
/// image name and root-write policy, the canonical writable-path set, and disk >= S.
pub(super) fn check_fork(
    conn: &Connection,
    s: &Sandbox,
    from: &CheckpointProvenance,
) -> Result<Result<Checkpoint, ForkRefusal>> {
    let Some(c) = load_checkpoint(conn, from.checkpoint.as_str())? else {
        return Ok(Err(ForkRefusal::NotFound));
    };
    if c.owner_uid != s.owner_uid && s.owner_uid != 0 {
        return Ok(Err(ForkRefusal::NotFound));
    }
    if c.state != CheckpointState::Ready || c.accounting_quarantined {
        return Ok(Err(ForkRefusal::NotReady(c.state)));
    }
    let Some(seal) = &c.seal else {
        return Ok(Err(ForkRefusal::NotReady(c.state)));
    };
    if seal.content_sha256 != from.content_sha256 {
        return Ok(Err(ForkRefusal::Changed));
    }
    if s.spec.image != c.image
        || s.spec.read_only_root != c.read_only_root
        || normalized_paths(&s.spec.writable_paths) != c.writable_paths
    {
        return Ok(Err(ForkRefusal::SpecMismatch));
    }
    if s.accounting.reservation.disk_bytes < seal.charge_bytes {
        return Ok(Err(ForkRefusal::DiskTooSmall {
            required: seal.charge_bytes,
        }));
    }
    Ok(Ok(c))
}

/// A fork's pin, inserted after its CREATING row in the same transaction, with the
/// checkpoint's activity (design 8.1: an accepted fork refreshes idle).
pub(super) fn insert_pin(
    conn: &Connection,
    sandbox_id: &str,
    c: &Checkpoint,
    reader: &HelperDispatch,
    now: &ClockReading,
) -> Result<()> {
    let seal = c.seal.as_ref().context("a pin needs a sealed checkpoint")?;
    conn.execute(
        &format!(
            "INSERT INTO checkpoint_pins ({PIN_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL)"
        ),
        params![
            sandbox_id,
            c.id.as_str(),
            i64_amount(c.generation, "checkpoint generation")?,
            seal.content_sha256.to_string(),
            reader.operation.to_string(),
            reader.helper_epoch.to_string(),
            reader.boot_id.to_string(),
            now.wall_ms,
        ],
    )?;
    record_checkpoint_activity(conn, c.id.as_str(), now)
}

impl Store {
    /// Design 10's C1: in one IMMEDIATE transaction, after the accounting audit, check
    /// the source, the key, every cap and the shared node disk budget, then insert the
    /// CAPTURING row charged R, its key record and its membership. A refusal changes
    /// nothing. Keyed records are anchored after the commit, as create's are.
    pub fn reserve_checkpoint(
        &self,
        new: &NewCheckpoint,
        budgets: &CheckpointBudgets,
        sandbox_budgets: SandboxBudgets,
        request: Option<&RequestAdmission>,
    ) -> Result<ReserveCheckpoint> {
        new.expiry.validate()?;
        if new.generation == 0 || i64::try_from(new.generation).is_err() {
            bail!("checkpoint generation must be nonzero and within the stored range");
        }
        if !(crate::checkpoint::MIN_LIMIT_BYTES..=crate::checkpoint::MAX_LIMIT_BYTES)
            .contains(&new.max_size_bytes)
        {
            bail!(
                "checkpoint cap {} outside the format's 64 KiB to 1 TiB",
                new.max_size_bytes
            );
        }
        if new.writable_paths != normalized_paths(&new.writable_paths) {
            bail!("checkpoint writable paths must be normalized");
        }
        if request.is_some() != new.request_id.is_some() {
            bail!("a keyed capture names its request ID, and only a keyed one");
        }
        if new
            .source_identity
            .is_some_and(|i| i.checkpoint_format_version != FORMAT_VERSION)
        {
            bail!("unsupported checkpoint format for the source identity");
        }
        let reading = self.clock_reading()?;
        let now = reading.wall_ms;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if audit_accounting(&tx)? {
            bail!("degraded accounting: quarantined release evidence; admission disabled");
        }
        settle_unsettled(&tx)?;
        let outcome = (|| -> Result<Option<ReserveCheckpoint>> {
            if let Some(identity) = new.source_identity {
                // Write-once (`sandboxes_checkpoint_fixed`): a row that already has an
                // identity keeps it, and the source check below compares against it.
                tx.execute(
                    "UPDATE sandboxes SET image_content_sha256 = ?2, checkpoint_format_version = ?3
                     WHERE id = ?1 AND image_content_sha256 IS NULL",
                    params![
                        new.source_sandbox_id,
                        identity.content_sha256.to_string(),
                        identity.checkpoint_format_version
                    ],
                )?;
            }
            if let (Some(request), Some(request_id)) = (request, &new.request_id) {
                let taken: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM checkpoint_requests WHERE owner_uid = ?1 AND request_id = ?2)",
                    params![new.owner_uid, request_id],
                    |r| r.get(0),
                )?;
                if taken {
                    return Ok(Some(ReserveCheckpoint::RequestIdTaken));
                }
                let counts = usage(&tx, new.owner_uid)?;
                for (scope, count, limit) in [
                    (
                        "uid",
                        counts.uid.keys,
                        request.max_per_uid.min(budgets.max_request_records_per_uid),
                    ),
                    (
                        "node",
                        counts.node.keys,
                        request.max_node.min(budgets.max_request_records_node),
                    ),
                ] {
                    if count >= limit {
                        return Ok(Some(ReserveCheckpoint::RequestQuota(RequestQuota {
                            scope,
                            count,
                            limit,
                        })));
                    }
                }
            }
            let source: Option<SourceRow> = tx
                .query_row(
                    "SELECT backend, backend_id, state, reserved_disk_bytes, image_content_sha256, checkpoint_format_version
                     FROM sandboxes WHERE id = ?1 AND id NOT IN (SELECT id FROM temp.accounting_quarantine)",
                    [&new.source_sandbox_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .optional()?;
            let spec: Option<String> = tx
                .query_row(
                    "SELECT spec FROM sandboxes WHERE id = ?1",
                    [&new.source_sandbox_id],
                    |r| r.get(0),
                )
                .optional()?;
            let (
                Some((
                    backend,
                    Some(backend_id),
                    state,
                    source_disk,
                    Some(image_sha),
                    Some(format),
                )),
                Some(spec),
            ) = (source, spec)
            else {
                return Ok(Some(ReserveCheckpoint::SourceUnavailable));
            };
            let spec: SandboxSpec = serde_json::from_str(&spec)?;
            if state != "ready" || format != i64::from(FORMAT_VERSION) {
                return Ok(Some(ReserveCheckpoint::SourceUnavailable));
            }
            if normalized_paths(&spec.writable_paths) != new.writable_paths {
                bail!("checkpoint writable paths are not the source's");
            }
            let source_disk = u64::try_from(source_disk)?;
            let limit = budgets.max_size_bytes.min(source_disk);
            if new.max_size_bytes > limit {
                return Ok(Some(ReserveCheckpoint::SizeLimit {
                    requested: new.max_size_bytes,
                    limit,
                }));
            }
            let counts = usage(&tx, new.owner_uid)?;
            let r = new.max_size_bytes;
            let disk = sandbox_resources(&tx)?.disk_bytes;
            for (scope, resource, reserved, requested, limit) in [
                (
                    "uid",
                    "checkpoints",
                    counts.uid.live,
                    1,
                    budgets.max_per_uid,
                ),
                ("node", "checkpoints", counts.node.live, 1, budgets.max_node),
                (
                    "uid",
                    "checkpoint bytes",
                    counts.uid.charged_bytes,
                    r,
                    budgets.max_bytes_per_uid,
                ),
                (
                    "node",
                    "checkpoint bytes",
                    counts.node.charged_bytes,
                    r,
                    budgets.max_bytes_node,
                ),
                (
                    "uid",
                    "checkpoint records",
                    counts.uid.records,
                    1,
                    budgets.max_records_per_uid,
                ),
                (
                    "node",
                    "checkpoint records",
                    counts.node.records,
                    1,
                    budgets.max_records_node,
                ),
                // The one node disk budget: sandbox promises plus checkpoint charges.
                ("node", "disk bytes", disk, r, sandbox_budgets.disk_bytes),
            ] {
                let total = reserved
                    .checked_add(requested)
                    .with_context(|| format!("{resource} reservation overflow"))?;
                if total > limit {
                    return Ok(Some(ReserveCheckpoint::Exhausted(CheckpointExhausted {
                        scope,
                        resource,
                        reserved,
                        requested,
                        limit,
                    })));
                }
            }
            tx.execute(
                "UPDATE checkpoint_sequence SET value = value + 1 WHERE id = 1",
                [],
            )?;
            tx.execute(
                "INSERT INTO checkpoints (id, creation_seq, owner_uid, instance_id, generation, format_version,
                     source_sandbox_id, source_backend, source_backend_id, capture_operation, capture_helper_epoch,
                     capture_boot_id, max_size_bytes, image, image_content_sha256, read_only_root, writable_paths,
                     excluded_paths, expiry_lifetime_ms, expiry_idle_ms, state, created_at_ms, updated_at_ms, request_id)
                 VALUES (?1, (SELECT value FROM checkpoint_sequence WHERE id = 1),
                     ?2, (SELECT instance_id FROM daemon_identity WHERE id = 1), ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16, ?17, ?18, 'capturing', ?19, ?19, ?20)",
                params![
                    new.id.as_str(),
                    new.owner_uid,
                    i64_amount(new.generation, "checkpoint generation")?,
                    FORMAT_VERSION,
                    new.source_sandbox_id,
                    backend,
                    backend_id,
                    new.capture.operation.to_string(),
                    new.capture.helper_epoch.to_string(),
                    new.capture.boot_id.to_string(),
                    i64_amount(r, "checkpoint cap")?,
                    spec.image,
                    image_sha,
                    spec.read_only_root,
                    stored_paths(&new.writable_paths)?,
                    stored_paths(&new.excluded_paths)?,
                    i64_amount(new.expiry.lifetime_ms, "checkpoint lifetime")?,
                    i64_amount(new.expiry.idle_ms, "checkpoint idle timeout")?,
                    now,
                    new.request_id,
                ],
            )?;
            if let (Some(request), Some(request_id)) = (request, &new.request_id) {
                tx.execute(
                    "INSERT INTO checkpoint_requests (owner_uid, request_id, request_sha256, digest_version, checkpoint_id, created_at_ms)
                     VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                    params![new.owner_uid, request_id, request.sha256.to_string(), new.id.as_str(), now],
                )?;
            }
            // Membership includes every admission, in its own transaction.
            let (all, settled) = stored_checkpoint_membership(&tx)?;
            store_checkpoint_membership(
                &tx,
                all.plus(row_membership(&tx, new.id.as_str())?),
                settled,
            )?;
            Ok(None)
        })()?;
        if let Some(refused) = outcome {
            // A refusal commits too, so the settling and a fresh verification are kept.
            tx.commit()?;
            return Ok(refused);
        }
        let inserted =
            load_checkpoint(&tx, new.id.as_str())?.context("the checkpoint was just inserted")?;
        tx.commit()?;
        if request.is_some() {
            let anchored = (|| -> Result<()> {
                let clock = self.clock_source()?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                anchor_unanchored_checkpoint_requests(&tx, &ClockReading::now(&*clock))?;
                tx.commit()?;
                Ok(())
            })();
            if let Err(error) = anchored {
                tracing::warn!(checkpoint = %new.id, error = %format!("{error:#}"), "capture request record left unanchored until the next prune");
            }
        }
        Ok(ReserveCheckpoint::Inserted(Box::new(inserted)))
    }

    /// The caller's capture record for `request_id` and its checkpoint, in one snapshot.
    pub fn checkpoint_request(
        &self,
        owner_uid: u32,
        request_id: &str,
    ) -> Result<Option<(Digest, Checkpoint)>> {
        self.audited_read(|conn| {
            let record: Option<(String, String)> = conn
                .query_row(
                    "SELECT request_sha256, checkpoint_id FROM checkpoint_requests WHERE owner_uid = ?1 AND request_id = ?2",
                    params![owner_uid, request_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((sha256, id)) = record else {
                return Ok(None);
            };
            let checkpoint = load_checkpoint(conn, &id)?
                .with_context(|| format!("capture request record names missing checkpoint {id}"))?;
            Ok(Some((Digest::parse(&sha256).map_err(anyhow::Error::msg)?, checkpoint)))
        })
    }

    pub fn checkpoint(&self, id: &str) -> Result<Option<Checkpoint>> {
        self.audited_read(|conn| load_checkpoint(conn, id))
    }

    /// Newest first, filtered in SQL before paging (design 5.2): by owner unless root
    /// lists everything, and optionally by immutable source ID, which works after the
    /// source is gone. `before_seq` is the previous page's last creation sequence.
    pub fn checkpoint_page(
        &self,
        owner: Option<u32>,
        source: Option<&str>,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<CheckpointPage> {
        self.audited_read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {CHECKPOINT_COLUMNS} FROM checkpoints
                 WHERE (?1 IS NULL OR owner_uid = ?1) AND (?2 IS NULL OR source_sandbox_id = ?2)
                   AND (?3 IS NULL OR creation_seq < ?3)
                 ORDER BY creation_seq DESC LIMIT ?4"
            ))?;
            let rows = stmt.query_map(
                params![owner, source, before_seq, i64::from(limit) + 1],
                checkpoint_row,
            )?;
            let mut rows: Vec<Checkpoint> = rows.map(|r| r?).collect::<Result<_>>()?;
            let has_more = rows.len() > usize::try_from(limit)?;
            rows.truncate(usize::try_from(limit)?);
            Ok(CheckpointPage { rows, has_more })
        })
    }

    /// Rows startup reconciliation must settle: CAPTURING, DELETING and QUARANTINED.
    pub fn unsettled_checkpoints(&self) -> Result<Vec<Checkpoint>> {
        self.audited_read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {CHECKPOINT_COLUMNS} FROM checkpoints WHERE state IN ('capturing', 'deleting', 'quarantined')
                 ORDER BY creation_seq"
            ))?;
            let rows = stmt.query_map([], checkpoint_row)?;
            rows.map(|r| r?).collect()
        })
    }

    /// The node's and `owner_uid`'s counters, after the audit that vouches for them.
    pub fn checkpoint_usage(&self, owner_uid: u32) -> Result<CheckpointUsage> {
        self.audited_read(|conn| usage(conn, owner_uid))
    }

    /// Stored evidence, reloaded through [`SealedEvidence::decode`].
    pub fn checkpoint_evidence(&self, id: &Digest) -> Result<Option<SealedEvidence>> {
        self.audited_read(|conn| Ok(load_evidence(conn, id)?.map(|(sealed, _)| sealed)))
    }

    pub fn checkpoint_pin(&self, sandbox_id: &str) -> Result<Option<CheckpointPin>> {
        self.audited_read(|conn| {
            conn.query_row(
                &format!("SELECT {PIN_COLUMNS} FROM checkpoint_pins WHERE sandbox_id = ?1"),
                [sandbox_id],
                pin_row,
            )
            .optional()?
            .transpose()
        })
    }

    pub fn checkpoint_pins(&self, checkpoint: &str) -> Result<Vec<CheckpointPin>> {
        self.audited_read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {PIN_COLUMNS} FROM checkpoint_pins WHERE checkpoint_id = ?1 ORDER BY pinned_at_ms, sandbox_id"
            ))?;
            let rows = stmt.query_map([checkpoint], pin_row)?;
            rows.map(|r| r?).collect()
        })
    }

    /// Records a sandbox's image identity and checkpoint format once (design 4.2): only
    /// for a new checkpoint-capable sandbox, never inferred for an older row.
    pub fn record_sandbox_image_identity(&self, id: &str, identity: ImageIdentity) -> Result<bool> {
        if identity.checkpoint_format_version != FORMAT_VERSION {
            bail!(
                "unsupported checkpoint format {}",
                identity.checkpoint_format_version
            );
        }
        let n = self.conn().execute(
            "UPDATE sandboxes SET image_content_sha256 = ?2, checkpoint_format_version = ?3
             WHERE id = ?1 AND image_content_sha256 IS NULL",
            params![
                id,
                identity.content_sha256.to_string(),
                identity.checkpoint_format_version
            ],
        )?;
        Ok(n == 1)
    }

    /// A capture's typed failure while CAPTURING (before its absence is proved), or a
    /// quarantine with it. Written once; the charge stays.
    pub fn record_checkpoint_failure(
        &self,
        id: &str,
        reason: Reason,
        detail: &str,
        quarantine: bool,
    ) -> Result<bool> {
        let detail = crate::checkpoint::bounded_detail(detail);
        let detail = if detail.is_empty() {
            reason.token().to_string()
        } else {
            detail
        };
        let from = if quarantine {
            "('capturing', 'ready')"
        } else {
            "('capturing')"
        };
        let n = self.conn().execute(
            &format!(
                "UPDATE checkpoints SET failure_token = ?2, failure_reason = ?3, updated_at_ms = ?4,
                     state = CASE WHEN ?5 THEN 'quarantined' ELSE state END
                 WHERE id = ?1 AND failure_token IS NULL AND state IN {from}"
            ),
            params![id, reason.token(), detail, now_ms(), quarantine],
        )?;
        Ok(n == 1)
    }

    /// C4 (design 10): validate the helper's COMPLETE evidence against this row's own
    /// binding in Rust, then in one IMMEDIATE transaction CAS CAPTURING to READY while
    /// the source is still READY under the bound backend, store the evidence, seal S and
    /// the digests once, stamp the READY anchors, and move the row's membership.
    pub fn publish_checkpoint_ready(
        &self,
        id: &str,
        evidence: &SealedEvidence,
    ) -> Result<PublishCheckpoint> {
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_accounting(&tx)?;
        let outcome = (|| -> Result<PublishCheckpoint> {
            let c = load_checkpoint(&tx, id)?.with_context(|| format!("no checkpoint {id}"))?;
            if c.state != CheckpointState::Capturing {
                return Ok(PublishCheckpoint::NotCapturing(c.state));
            }
            let fact = match evidence.verify_complete(&c.capture_binding(), c.capture.dispatched())
            {
                Ok(fact) => fact.clone(),
                Err(e) => return Ok(PublishCheckpoint::Refused(e)),
            };
            if fact.image != c.image || fact.image_sha256 != c.image_content_sha256 {
                return Ok(PublishCheckpoint::Refused(
                    "COMPLETE evidence for another image".into(),
                ));
            }
            let source_ready: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM sandboxes WHERE id = ?1 AND state = 'ready' AND backend_id = ?2)",
                params![c.source_sandbox_id, c.source_backend_id],
                |r| r.get(0),
            )?;
            if !source_ready {
                return Ok(PublishCheckpoint::SourceChanged);
            }
            let bytes = evidence
                .evidence
                .canonical_bytes()
                .map_err(anyhow::Error::msg)?;
            insert_evidence(&tx, evidence, &bytes, reading.wall_ms)?;
            let before = row_membership(&tx, id)?;
            let n = tx.execute(
                "UPDATE checkpoints SET state = 'ready', complete_evidence_id = ?2, content_sha256 = ?3,
                     binding_sha256 = ?4, charge_bytes = ?5, logical_bytes = ?6, allocated_bytes = ?7,
                     entry_count = ?8, ready_at_ms = ?9, ready_boottime_ms = ?10, clock_boot_id = ?11,
                     activity_at_ms = ?9, activity_boottime_ms = ?10, updated_at_ms = ?9
                 WHERE id = ?1 AND state = 'capturing' AND complete_evidence_id IS NULL",
                params![
                    id,
                    evidence.id.to_string(),
                    fact.content_sha256.to_string(),
                    fact.binding_sha256.to_string(),
                    i64_amount(fact.charge_bytes, "checkpoint charge")?,
                    i64_amount(fact.logical_bytes, "checkpoint logical bytes")?,
                    i64_amount(fact.allocated_bytes, "checkpoint allocated bytes")?,
                    i64_amount(fact.entries, "checkpoint entries")?,
                    reading.wall_ms,
                    reading.boottime_ms,
                    reading.boot_id,
                ],
            )?;
            if n != 1 {
                bail!("checkpoint {id} changed while publishing");
            }
            // The one-time charge change: its own seal, audited with the row.
            let (all, settled) = stored_checkpoint_membership(&tx)?;
            store_checkpoint_membership(
                &tx,
                all.minus(before).plus(row_membership(&tx, id)?),
                settled,
            )?;
            Ok(PublishCheckpoint::Published(Box::new(
                load_checkpoint(&tx, id)?.context("published checkpoint vanished")?,
            )))
        })()?;
        match outcome {
            PublishCheckpoint::Published(_) => tx.commit()?,
            _ => drop(tx),
        }
        Ok(outcome)
    }

    /// D1: DELETING with its first reason, from CAPTURING (cancel), READY or
    /// QUARANTINED. From here no pin is admitted. Returns the row as it stands.
    pub fn publish_checkpoint_delete_intent(
        &self,
        id: &str,
        reason: DeletionReason,
    ) -> Result<Option<Checkpoint>> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE checkpoints SET state = 'deleting', deletion_reason = COALESCE(deletion_reason, ?2), updated_at_ms = ?3
             WHERE id = ?1 AND state IN ('capturing', 'ready', 'quarantined')",
            params![id, reason.as_str(), now_ms()],
        )?;
        let row = load_checkpoint(&tx, id)?;
        tx.commit()?;
        Ok(row)
    }

    /// Records the removal about to be dispatched (its fresh nonce, epoch and boot):
    /// only its ABSENT evidence can release the row.
    pub fn record_checkpoint_removal(&self, id: &str, removal: &HelperDispatch) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE checkpoints SET removal_operation = ?2, removal_helper_epoch = ?3, removal_boot_id = ?4, updated_at_ms = ?5
             WHERE id = ?1 AND state IN ('capturing', 'deleting') AND release_evidence_id IS NULL",
            params![
                id,
                removal.operation.to_string(),
                removal.helper_epoch.to_string(),
                removal.boot_id.to_string(),
                now_ms()
            ],
        )?;
        Ok(n == 1)
    }

    /// D3: the recorded removal's ABSENT evidence, validated in Rust, settles the row
    /// in one IMMEDIATE transaction: CAPTURING (with its failure recorded) to FAILED, or
    /// DELETING to DELETED. Every pin still live is released by the same evidence (no
    /// reader can remain), then the charge and count are released.
    pub fn settle_checkpoint_absence(
        &self,
        id: &str,
        evidence: &SealedEvidence,
    ) -> Result<SettleAbsence> {
        let now = now_ms();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_accounting(&tx)?;
        let outcome = (|| -> Result<SettleAbsence> {
            let c = load_checkpoint(&tx, id)?.with_context(|| format!("no checkpoint {id}"))?;
            if c.release_evidence_id == Some(evidence.id) {
                return Ok(SettleAbsence::AlreadyReleased(Box::new(c)));
            }
            let terminal = match c.state {
                CheckpointState::Capturing if c.failure.is_some() => "failed",
                CheckpointState::Deleting => "deleted",
                state => return Ok(SettleAbsence::NotReleasable(state)),
            };
            let Some(removal) = c.removal else {
                return Ok(SettleAbsence::Refused("no removal was dispatched".into()));
            };
            let target = c.target();
            let bytes = match evidence.verify(&removal.expected(&target, "absent")) {
                Ok(bytes) => bytes,
                Err(e) => return Ok(SettleAbsence::Refused(e)),
            };
            insert_evidence(&tx, evidence, &bytes, now)?;
            tx.execute(
                "UPDATE checkpoint_pins SET released_at_ms = ?2, released_by = 'absent', release_evidence_id = ?3
                 WHERE checkpoint_id = ?1 AND released_at_ms IS NULL",
                params![id, now, evidence.id.to_string()],
            )?;
            tx.execute(
                "UPDATE checkpoints SET state = ?2, release_evidence_id = ?3, released_at_ms = ?4, updated_at_ms = ?4,
                     deleted_at_ms = CASE WHEN ?2 = 'deleted' THEN ?4 ELSE NULL END
                 WHERE id = ?1",
                params![id, terminal, evidence.id.to_string(), now],
            )?;
            Ok(SettleAbsence::Released(Box::new(
                load_checkpoint(&tx, id)?.context("settled checkpoint vanished")?,
            )))
        })()?;
        match outcome {
            SettleAbsence::Released(_) => tx.commit()?,
            _ => drop(tx),
        }
        Ok(outcome)
    }

    /// Delete of an already absent FAILED row (design 9.1): DELETED, keeping its
    /// evidence, with reason `requested`.
    pub fn delete_failed_checkpoint(&self, id: &str) -> Result<bool> {
        let now = now_ms();
        let n = self.conn().execute(
            "UPDATE checkpoints SET state = 'deleted', deletion_reason = COALESCE(deletion_reason, 'requested'),
                 deleted_at_ms = ?2, updated_at_ms = ?2
             WHERE id = ?1 AND state = 'failed'",
            params![id, now],
        )?;
        Ok(n == 1)
    }

    /// Get's activity CAS (design 8.2): only a READY row whose sequence is still
    /// `expected_seq`. Lifetime and idle checks are the caller's, before this.
    pub fn touch_checkpoint(&self, id: &str, expected_seq: i64) -> Result<bool> {
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ready: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM checkpoints WHERE id = ?1 AND state = 'ready' AND activity_seq = ?2)",
            params![id, expected_seq],
            |r| r.get(0),
        )?;
        if ready {
            record_checkpoint_activity(&tx, id, &reading)?;
        }
        tx.commit()?;
        Ok(ready)
    }

    /// Design 7.2's accepting transaction for a fork: the ordinary CREATING row and
    /// full reservation (the shared disk budget included), its key record (digest
    /// version 2), its immutable provenance and its durable pin, all or nothing, after
    /// rechecking the checkpoint at this commit.
    pub fn reserve_fork_sandbox(
        &self,
        s: &Sandbox,
        budgets: SandboxBudgets,
        request: Option<&RequestAdmission>,
        default_env: &[crate::exec_env::EnvVar],
        reader: &HelperDispatch,
    ) -> Result<ReserveFork> {
        if s.lifecycle.from_checkpoint.is_none() {
            bail!("a fork names its checkpoint");
        }
        self.reserve_sandbox_inner(s, budgets, request, default_env, Some(reader))
    }

    /// Releases a fork's pin with its reader's evidence (C3's READER_ENDED with copy
    /// `complete` or `not_started`; `unknown` never releases). The last live pin's
    /// release records finish activity.
    pub fn release_checkpoint_pin(
        &self,
        sandbox_id: &str,
        evidence: &SealedEvidence,
    ) -> Result<ReleasePin> {
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_accounting(&tx)?;
        let pin = tx
            .query_row(
                &format!("SELECT {PIN_COLUMNS} FROM checkpoint_pins WHERE sandbox_id = ?1"),
                [sandbox_id],
                pin_row,
            )
            .optional()?
            .transpose()?;
        let Some(pin) = pin else {
            return Ok(ReleasePin::NoPin);
        };
        if pin.released_at_ms.is_some() {
            return Ok(ReleasePin::AlreadyReleased);
        }
        let instance = Store::identity_in(&tx)?.instance_id;
        let target = ArtifactTarget {
            instance,
            checkpoint: pin.checkpoint.clone(),
            generation: pin.generation,
        };
        let bytes = evidence
            .verify(&pin.reader.expected(&target, "reader_ended"))
            .map_err(anyhow::Error::msg)?;
        let by = match &evidence.evidence.fact {
            Fact::ReaderEnded { copy } => copy_token(*copy),
            _ => None,
        }
        .context("a pin is released only by a reader that completed or never started")?;
        insert_evidence(&tx, evidence, &bytes, reading.wall_ms)?;
        tx.execute(
            "UPDATE checkpoint_pins SET released_at_ms = ?2, released_by = ?3, release_evidence_id = ?4
             WHERE sandbox_id = ?1 AND released_at_ms IS NULL",
            params![sandbox_id, reading.wall_ms, by, evidence.id.to_string()],
        )?;
        let live: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM checkpoint_pins WHERE checkpoint_id = ?1 AND released_at_ms IS NULL)",
            [pin.checkpoint.as_str()],
            |r| r.get(0),
        )?;
        if !live {
            record_checkpoint_activity(&tx, pin.checkpoint.as_str(), &reading)?;
        }
        tx.commit()?;
        Ok(ReleasePin::Released)
    }

    /// Design 7.1: once the checkpoint is DELETED, drop its capture key record and
    /// stamp the release, in one IMMEDIATE transaction.
    pub fn release_checkpoint_request_id(&self, id: &str) -> Result<ReleaseRequestId> {
        let now = now_ms();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_accounting(&tx)?;
        settle_unsettled(&tx)?;
        let deleted: Option<bool> = tx
            .query_row(
                "SELECT state = 'deleted' AND id NOT IN (SELECT id FROM temp.checkpoint_quarantine) FROM checkpoints WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        let answer = match deleted {
            None => ReleaseRequestId::NoSandbox,
            Some(false) => ReleaseRequestId::NotDeleted,
            Some(true) => {
                if tx.execute(
                    "DELETE FROM checkpoint_requests WHERE checkpoint_id = ?1",
                    [id],
                )? == 0
                {
                    ReleaseRequestId::NoRecord
                } else {
                    tx.execute(
                        "UPDATE checkpoints SET request_id_released_at_ms = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    ReleaseRequestId::Released
                }
            }
        };
        tx.commit()?;
        Ok(answer)
    }

    /// Design 3.3 R2 for capture keys, at startup: every record anchored in another
    /// boot (or not at all) gets this boot's ID and current boottime.
    pub fn rebase_checkpoint_requests(&self) -> Result<usize> {
        let clock = self.clock_source()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = ClockReading::now(&*clock);
        let rebased = tx.execute(
            "UPDATE checkpoint_requests SET retain_boot_id = ?1, retain_from_boottime_ms = ?2 WHERE retain_boot_id IS NOT ?1",
            params![now.boot_id, now.boottime_ms],
        )?;
        tx.commit()?;
        Ok(rebased)
    }

    /// Leaves a capture key's record unanchored, as a crash between its insert and its
    /// anchoring transaction would (tests). The update trigger forbids it, so it is
    /// dropped and recreated from its own text around the update.
    #[cfg(test)]
    pub(crate) fn unanchor_checkpoint_request_for_test(&self, checkpoint: &str) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let trigger: String = tx.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'checkpoint_requests_fixed'",
            [],
            |r| r.get(0),
        )?;
        tx.execute_batch("DROP TRIGGER checkpoint_requests_fixed")?;
        tx.execute(
            "UPDATE checkpoint_requests SET retain_boot_id = NULL, retain_from_boottime_ms = NULL WHERE checkpoint_id = ?1",
            [checkpoint],
        )?;
        tx.execute_batch(&trigger)?;
        tx.commit()?;
        Ok(())
    }

    /// A failure token (design 7.3) recorded once on a CAPTURING row, or with
    /// `quarantine` on a CAPTURING or READY row; the charge stays. The engine's tokens
    /// include ones the helper never sends (`checkpoint_not_ready`, `checkpoint_expired`).
    pub fn record_checkpoint_failure_token(
        &self,
        id: &str,
        token: &'static str,
        detail: &str,
        quarantine: bool,
    ) -> Result<bool> {
        self.write_failure(id, token, detail, if quarantine { "('capturing', 'ready')" } else { "('capturing')" }, quarantine)
    }

    /// A removal's `checkpoint_generation_mismatch` or `checkpoint_corrupt` (C3), recorded
    /// once on the DELETING row it was dispatched for. Nothing is released: the
    /// artifact under that name is not this row's to prove absent.
    pub fn record_checkpoint_removal_failure(
        &self,
        id: &str,
        reason: Reason,
        detail: &str,
    ) -> Result<bool> {
        self.write_failure(id, reason.token(), detail, "('deleting')", false)
    }

    fn write_failure(
        &self,
        id: &str,
        token: &str,
        detail: &str,
        from: &str,
        quarantine: bool,
    ) -> Result<bool> {
        let detail = crate::checkpoint::bounded_detail(detail);
        let detail = if detail.is_empty() {
            token.to_string()
        } else {
            detail
        };
        let n = self.conn().execute(
            &format!(
                "UPDATE checkpoints SET failure_token = ?2, failure_reason = ?3, updated_at_ms = ?4,
                     state = CASE WHEN ?5 THEN 'quarantined' ELSE state END
                 WHERE id = ?1 AND failure_token IS NULL AND state IN {from}"
            ),
            params![id, token, detail, now_ms(), quarantine],
        )?;
        Ok(n == 1)
    }

    /// Design 8.1's expiry intent: DELETING with an expiry reason and its intent
    /// anchors, in one IMMEDIATE transaction. Lifetime takes READY or QUARANTINED rows;
    /// idle only a READY row whose activity sequence is still `idle_seq` and that has
    /// no live pin (pins pause idle). `false`: something else won first.
    pub fn publish_checkpoint_expiry_intent(
        &self,
        id: &str,
        reason: DeletionReason,
        idle_seq: Option<i64>,
    ) -> Result<bool> {
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = match (reason, idle_seq) {
            (DeletionReason::ExpiredLifetime, None) => tx.execute(
                "UPDATE checkpoints SET state = 'deleting', deletion_reason = 'expired_lifetime',
                     expiry_intent_at_ms = ?2, expiry_intent_boottime_ms = ?3, updated_at_ms = ?2
                 WHERE id = ?1 AND state IN ('ready', 'quarantined') AND ready_at_ms IS NOT NULL
                   AND clock_boot_id IS ?4",
                params![id, reading.wall_ms, reading.boottime_ms, reading.boot_id],
            )?,
            (DeletionReason::ExpiredIdle, Some(seq)) => tx.execute(
                "UPDATE checkpoints SET state = 'deleting', deletion_reason = 'expired_idle',
                     expiry_intent_at_ms = ?2, expiry_intent_boottime_ms = ?3, updated_at_ms = ?2
                 WHERE id = ?1 AND state = 'ready' AND activity_seq = ?5 AND clock_boot_id IS ?4
                   AND NOT EXISTS (SELECT 1 FROM checkpoint_pins WHERE checkpoint_id = ?1 AND released_at_ms IS NULL)",
                params![id, reading.wall_ms, reading.boottime_ms, reading.boot_id, seq],
            )?,
            _ => bail!("an expiry intent is lifetime without a sequence or idle with one"),
        };
        tx.commit()?;
        Ok(n == 1)
    }

    /// The cross-boot rebase for checkpoints (design 8.1, as M1's `rebase_clocks`): every
    /// row anchored in another boot gets its READY, activity and expiry-intent anchors
    /// moved onto this boot's clock by the wall time elapsed since, clamped to its own
    /// lifetime and idle limits so nothing is ever extended. One IMMEDIATE transaction.
    pub fn rebase_checkpoint_clocks(&self) -> Result<usize> {
        let now = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        type Foreign = (String, i64, i64, Option<i64>, Option<i64>, Option<i64>);
        let rows: Vec<Foreign> = {
            let mut stmt = tx.prepare(
                "SELECT id, expiry_lifetime_ms, expiry_idle_ms, ready_at_ms, activity_at_ms, expiry_intent_at_ms
                 FROM checkpoints WHERE clock_boot_id IS NOT NULL AND clock_boot_id != ?1",
            )?;
            stmt.query_map([&now.boot_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let elapsed = |limit: Option<i64>, anchor: Option<i64>| -> Option<i64> {
            let spent = now.wall_ms.saturating_sub(anchor?).max(0);
            Some(limit.map_or(spent, |limit| spent.min(limit)))
        };
        for (id, lifetime, idle, ready_at, activity_at, intent_at) in &rows {
            let ready =
                elapsed(Some(*lifetime), *ready_at).map(|e| now.boottime_ms.saturating_sub(e));
            let activity = elapsed(Some(*idle), activity_at.or(*ready_at))
                .map(|e| now.boottime_ms.saturating_sub(e));
            let intent = elapsed(None, *intent_at).map(|e| now.boottime_ms.saturating_sub(e));
            tx.execute(
                "UPDATE checkpoints SET ready_boottime_ms = ?2, activity_boottime_ms = ?3, clock_boot_id = ?4,
                     expiry_intent_boottime_ms = ?5
                 WHERE id = ?1",
                params![id, ready, activity, now.boot_id, intent],
            )?;
        }
        tx.commit()?;
        Ok(rows.len())
    }

    /// Charged rows the checkpoint expiry queue may need an entry for: READY,
    /// QUARANTINED and DELETING, each with whether a live pin pauses its idle timer.
    pub fn checkpoint_expiry_rows(&self) -> Result<Vec<(Checkpoint, bool)>> {
        self.audited_read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {CHECKPOINT_COLUMNS}, EXISTS (SELECT 1 FROM checkpoint_pins p
                     WHERE p.checkpoint_id = checkpoints.id AND p.released_at_ms IS NULL)
                 FROM checkpoints WHERE release_evidence_id IS NULL
                   AND state IN ('ready', 'quarantined', 'deleting') ORDER BY creation_seq"
            ))?;
            let rows = stmt.query_map([], |r| Ok((checkpoint_row(r)?, r.get::<_, bool>(50)?)))?;
            rows.map(|r| {
                let (row, pinned) = r?;
                Ok((row?, pinned))
            })
            .collect()
        })
    }

    /// Whether any durable checkpoint state exists: a row in any state, or a capture
    /// key record. Read-only; the feature-off startup's only checkpoint query.
    pub fn checkpoint_state_exists(&self) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM checkpoints) OR EXISTS (SELECT 1 FROM checkpoint_requests)",
            [],
            |r| r.get(0),
        )?)
    }

    /// Whether a live pin pauses this checkpoint's idle timer.
    pub fn checkpoint_has_live_pins(&self, id: &str) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM checkpoint_pins WHERE checkpoint_id = ?1 AND released_at_ms IS NULL)",
            [id],
            |r| r.get(0),
        )?)
    }

    fn identity_in(conn: &Connection) -> Result<DaemonIdentity> {
        let (database_uuid, instance_id): (String, String) = conn.query_row(
            "SELECT database_uuid, instance_id FROM daemon_identity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(DaemonIdentity {
            database_uuid: Id128::parse(&database_uuid).map_err(anyhow::Error::msg)?,
            instance_id: Id128::parse(&instance_id).map_err(anyhow::Error::msg)?,
        })
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
