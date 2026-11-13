//! The workspace checkpoint engine (design `kilnd-checkpoint-fork` sections 4, 6.3, 7,
//! 8 and 10; milestone C5a): supervised capture, the D1-D3 removal shared by Delete,
//! expiry and failed captures, checkpoint expiry and its cross-boot rebase, and startup
//! reconciliation. It drives C3's helper group through `Runtime::checkpoint` and C4's
//! store; it is reachable only from Rust. No RPC, kilndctl command, Health field or
//! feature names it until C5b, and it is off unless `Limits::checkpoints` is set.
//!
//! Lock order (design 8.3): a capture takes the source's exec mutex (try-lock), then the
//! short admission gate, then short store transactions; nothing awaits under the gate,
//! and no store transaction calls the helper. Removal serializes per checkpoint on its
//! own async lock, then a cleanup permit; it never takes a sandbox's exec mutex.

use super::*;
use crate::checkpoint::wire::{
    ArtifactView, CaptureReply, CheckpointErrorKind, CheckpointOperation, CheckpointResponse,
    ExclusiveOp, OpKind, RemoveReply, SourceReply, TrackedArtifact,
};
use crate::checkpoint::{CheckpointId, Fact, MIN_LIMIT_BYTES, Reason, SealedEvidence};
use crate::model::ImageIdentity;
use crate::store::{
    Checkpoint, CheckpointBudgets, CheckpointExpiry, CheckpointState, HelperDispatch,
    MAX_CHECKPOINT_IDLE_MS, MAX_CHECKPOINT_LIFETIME_MS, MIN_CHECKPOINT_EXPIRY_MS, NewCheckpoint,
    PublishCheckpoint, ReserveCheckpoint, SettleAbsence, normalized_paths,
};

/// Decision 3: 24 hours of lifetime and one hour idle unless the request says less.
pub const DEFAULT_CHECKPOINT_LIFETIME_MS: u64 = 86_400_000;
pub const DEFAULT_CHECKPOINT_IDLE_MS: u64 = 3_600_000;
/// Design 2.1: never persistent overlay data; recreated by every new sandbox.
pub const EXCLUDED_PATHS: [&str; 5] = ["/dev", "/dev/shm", "/etc/resolv.conf", "/proc", "/sys"];
/// A removal's own wire ceiling (C3's `remove`).
const REMOVE_TIMEOUT: Duration = Duration::from_secs(60);
/// Capabilities, `source`, `inspect`, `inventory` and `acknowledge`.
const HELPER_QUICK_TIMEOUT: Duration = Duration::from_secs(30);

/// Operator policy (design 6.2). `Limits::checkpoints = None` is the feature off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointLimits {
    pub budgets: CheckpointBudgets,
    pub default_lifetime_ms: u64,
    pub default_idle_ms: u64,
    /// Lease, image checks, copy, hash, sync and publication (design 6.2: 120 s).
    pub operation_timeout: Duration,
    /// Capture and restore workers: per node and per uid (design 6.2: 2 and 1).
    pub max_workers: usize,
    pub max_workers_per_uid: usize,
    /// The separate cleanup lane (design 6.2: 2).
    pub cleanup_workers: usize,
    /// A retried removal's first and largest backoff.
    pub removal_retry: Duration,
    pub max_removal_retry: Duration,
}

impl Default for CheckpointLimits {
    fn default() -> Self {
        Self {
            budgets: CheckpointBudgets::default(),
            default_lifetime_ms: DEFAULT_CHECKPOINT_LIFETIME_MS,
            default_idle_ms: DEFAULT_CHECKPOINT_IDLE_MS,
            operation_timeout: Duration::from_secs(120),
            max_workers: 2,
            max_workers_per_uid: 1,
            cleanup_workers: 2,
            removal_retry: Duration::from_secs(1),
            max_removal_retry: Duration::from_secs(60),
        }
    }
}

/// `CheckpointSandboxRequest` (design Appendix A) as sent, before any default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureRequest {
    pub sandbox_id: String,
    /// Required (design 8.1); zero fields select the checkpoint defaults.
    pub expiry: Option<RequestedExpiry>,
    /// Zero: min(the source's disk, the per-checkpoint limit).
    pub max_size_bytes: u64,
}

/// A keyed capture's identity in its owner's scope, separate from create keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureKey {
    /// Already checked by `idempotency::validate_request_id`.
    pub request_id: String,
    /// `idempotency::capture_request_digest` of the request as sent.
    pub sha256: Digest,
}

/// The gRPC code each design 7.3 token maps to, one-to-one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointCode {
    FailedPrecondition,
    InvalidArgument,
    ResourceExhausted,
    DataLoss,
    Unavailable,
    Unimplemented,
    DeadlineExceeded,
}

/// Design 7.3's typed reasons. C5b maps [`Self::token`] to the `kilnd-reason` trailer
/// and [`Self::code`] to the status, with nothing to reshape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointReason {
    BackendUnsupported,
    SandboxUnsupported,
    Busy,
    NotReady,
    Expired,
    LayoutUnsupported,
    MetadataUnsupported,
    ImageUnavailable,
    SpecMismatch,
    DiskTooSmall,
    ExpiryRequired,
    Quota,
    SizeLimit,
    Workers,
    Corrupt,
    Io,
    InFlight,
}

impl CheckpointReason {
    pub const ALL: [Self; 17] = [
        Self::BackendUnsupported,
        Self::SandboxUnsupported,
        Self::Busy,
        Self::NotReady,
        Self::Expired,
        Self::LayoutUnsupported,
        Self::MetadataUnsupported,
        Self::ImageUnavailable,
        Self::SpecMismatch,
        Self::DiskTooSmall,
        Self::ExpiryRequired,
        Self::Quota,
        Self::SizeLimit,
        Self::Workers,
        Self::Corrupt,
        Self::Io,
        Self::InFlight,
    ];

    pub fn token(self) -> &'static str {
        match self {
            Self::BackendUnsupported => crate::checkpoint::BACKEND_UNSUPPORTED,
            Self::SandboxUnsupported => "sandbox_unsupported:workspace_checkpoint",
            Self::Busy => "checkpoint_busy",
            Self::NotReady => "checkpoint_not_ready",
            Self::Expired => "checkpoint_expired",
            Self::LayoutUnsupported => "checkpoint_layout_unsupported",
            Self::MetadataUnsupported => "checkpoint_metadata_unsupported",
            Self::ImageUnavailable => "checkpoint_image_unavailable",
            Self::SpecMismatch => "checkpoint_spec_mismatch",
            Self::DiskTooSmall => "checkpoint_disk_too_small",
            Self::ExpiryRequired => "checkpoint_expiry_required",
            Self::Quota => "checkpoint_quota",
            Self::SizeLimit => "checkpoint_size_limit",
            Self::Workers => "checkpoint_workers",
            Self::Corrupt => "checkpoint_corrupt",
            Self::Io => "checkpoint_io",
            Self::InFlight => "checkpoint_in_flight",
        }
    }

    pub fn code(self) -> CheckpointCode {
        use CheckpointCode as C;
        match self {
            Self::BackendUnsupported => C::Unimplemented,
            Self::SandboxUnsupported
            | Self::Busy
            | Self::NotReady
            | Self::Expired
            | Self::LayoutUnsupported
            | Self::MetadataUnsupported
            | Self::ImageUnavailable => C::FailedPrecondition,
            Self::SpecMismatch | Self::DiskTooSmall | Self::ExpiryRequired => C::InvalidArgument,
            Self::Quota | Self::SizeLimit | Self::Workers => C::ResourceExhausted,
            Self::Corrupt => C::DataLoss,
            Self::Io => C::Unavailable,
            Self::InFlight => C::DeadlineExceeded,
        }
    }

    /// The manager error carrying this token and code.
    pub fn error(self, message: impl Into<String>) -> Error {
        let refusal = Refusal::typed(self.token(), message);
        match self.code() {
            CheckpointCode::FailedPrecondition => Error::FailedPrecondition(refusal),
            CheckpointCode::InvalidArgument => {
                Error::Refused(RefusalCode::InvalidArgument, refusal)
            }
            CheckpointCode::ResourceExhausted => {
                Error::Refused(RefusalCode::ResourceExhausted, refusal)
            }
            CheckpointCode::DataLoss => Error::Refused(RefusalCode::DataLoss, refusal),
            CheckpointCode::Unavailable => Error::Refused(RefusalCode::Unavailable, refusal),
            CheckpointCode::Unimplemented => Error::Refused(RefusalCode::Unimplemented, refusal),
            CheckpointCode::DeadlineExceeded => {
                Error::Refused(RefusalCode::DeadlineExceeded, refusal)
            }
        }
    }

    /// A helper (kiln) failure token as the engine reports it. A removal's
    /// generation mismatch is an unexplained artifact: corrupt.
    pub fn from_helper(reason: Reason) -> Self {
        match reason {
            Reason::SandboxUnsupported => Self::SandboxUnsupported,
            Reason::Busy => Self::Busy,
            Reason::LayoutUnsupported => Self::LayoutUnsupported,
            Reason::MetadataUnsupported => Self::MetadataUnsupported,
            Reason::ImageUnavailable => Self::ImageUnavailable,
            Reason::SizeLimit => Self::SizeLimit,
            Reason::SpecMismatch => Self::SpecMismatch,
            Reason::DiskTooSmall => Self::DiskTooSmall,
            Reason::Corrupt | Reason::GenerationMismatch => Self::Corrupt,
            Reason::Workers => Self::Workers,
            Reason::Io | Reason::InvalidRequest => Self::Io,
        }
    }
}

/// A keyed capture in flight: its digest, and a watch closed when it is answered.
type InFlightCapture = (Digest, watch::Sender<()>);

/// In-memory engine state. Everything durable is in the store.
#[derive(Default)]
pub(super) struct CheckpointEngine {
    /// Keyed captures in flight: their digest and a watch closed when they finish.
    keys: Mutex<HashMap<(u32, String), InFlightCapture>>,
    /// Capture and restore workers in use: the node's and each uid's.
    workers: Mutex<(usize, HashMap<u32, usize>)>,
    /// Running captures by checkpoint ID: D1 cancels them.
    captures: Mutex<HashMap<String, CancellationToken>>,
    /// One removal attempt at a time per checkpoint.
    removal_locks: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
    /// Checkpoints with a background removal retrier running.
    retrying: Mutex<HashSet<String>>,
    /// The expiry timers: each charged checkpoint's next due boottime.
    timers: Mutex<BTreeMap<String, i64>>,
    /// Durable checkpoint state exists (a row or a capture key): it is maintained,
    /// and its keys answered, with the feature off (design 11.1).
    pub(super) present: AtomicBool,
    /// Held around C1's insert and every recount of `present`, so a recount that finds
    /// nothing can never hide a capture admitted while it ran.
    presence: Mutex<()>,
    /// The checkpoint barrier's part of the allocation block (design 10.2), apart from
    /// `Manager::admission_blocked`. Startup and the barrier retry set and clear it;
    /// a removal's Retained verdict sets it.
    pub(super) barrier_blocked: AtomicBool,
    barrier_retrying: AtomicBool,
    /// Every arm of the barrier counts here; `pass_arm` is the count at the latest
    /// pass's own arm. A clear is refused once anything armed after that pass began
    /// (a removal's Retained verdict), so a stale clean verdict cannot discharge it.
    arms: AtomicU64,
    pass_arm: AtomicU64,
    /// Wakes the barrier retry early: a removal settled, or one found retained state.
    barrier_kick: tokio::sync::Notify,
    pub(super) rejected_captures: AtomicU64,
    pub(super) expired: AtomicU64,
    /// The engine's store calls (tests: the feature off makes none on request paths).
    #[cfg(test)]
    pub(super) store_calls: std::sync::atomic::AtomicUsize,
}

/// A capture or restore worker permit (design 6.2), returned on drop.
struct WorkerPermit<'a> {
    engine: &'a CheckpointEngine,
    uid: u32,
}

impl Drop for WorkerPermit<'_> {
    fn drop(&mut self) {
        let mut w = self
            .engine
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        w.0 = w.0.saturating_sub(1);
        if let Some(n) = w.1.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                w.1.remove(&self.uid);
            }
        }
    }
}

/// Clears the source's capture flag and resumes its idle timer from its old activity
/// (design 8.2: capture is not a renewal).
struct CapturingFlag<'a, R: Runtime> {
    manager: &'a Manager<R>,
    slot: Arc<Slot>,
    source: String,
    checkpoint: Option<String>,
}

impl<R: Runtime> Drop for CapturingFlag<'_, R> {
    fn drop(&mut self) {
        *self
            .slot
            .capturing
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(id) = &self.checkpoint {
            self.manager
                .checkpoint
                .captures
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(id);
        }
        self.manager.expiry_refresh(&self.source);
    }
}

/// The helper epoch and boot this daemon's dispatches name.
#[derive(Clone, Copy, Debug)]
pub(super) struct Session {
    pub(super) epoch: Id128,
    pub(super) boot: Id128,
}

/// One removal attempt's result.
enum Removal {
    /// Released by matching ABSENT evidence (now or earlier).
    Released(Box<Checkpoint>),
    /// Not a removable row (READY with no intent, or already settled otherwise).
    NotRemovable(Box<Checkpoint>),
    /// Worth retrying later: busy, helper unavailable, stale epoch.
    Retry(Error),
    /// The helper found an artifact under the name it cannot prove this row's: kept
    /// charged and the barrier armed; its retry's backoff paces the next attempt.
    Blocked(Error),
}

/// Design 8.1: a present policy is required; zero fields choose the defaults; a
/// nonzero field is 10 s to 7 days (lifetime) or 24 hours (idle).
pub fn resolve_checkpoint_expiry(
    requested: Option<RequestedExpiry>,
    limits: &CheckpointLimits,
) -> Result<CheckpointExpiry> {
    let requested = requested.ok_or_else(|| {
        CheckpointReason::ExpiryRequired
            .error("a checkpoint needs an expiry policy; send an empty one for the defaults")
    })?;
    let pick = |value: u64, default: u64| if value == 0 { default } else { value };
    let expiry = CheckpointExpiry {
        lifetime_ms: pick(requested.max_lifetime_ms, limits.default_lifetime_ms),
        idle_ms: pick(requested.idle_timeout_ms, limits.default_idle_ms),
    };
    if !(MIN_CHECKPOINT_EXPIRY_MS..=MAX_CHECKPOINT_LIFETIME_MS).contains(&expiry.lifetime_ms)
        || !(MIN_CHECKPOINT_EXPIRY_MS..=MAX_CHECKPOINT_IDLE_MS).contains(&expiry.idle_ms)
    {
        return Err(Error::InvalidArgument(format!(
            "checkpoint max_lifetime_ms must be {MIN_CHECKPOINT_EXPIRY_MS} to {MAX_CHECKPOINT_LIFETIME_MS} and idle_timeout_ms {MIN_CHECKPOINT_EXPIRY_MS} to {MAX_CHECKPOINT_IDLE_MS}"
        )));
    }
    Ok(expiry)
}

fn helper_unavailable(what: &str, error: impl std::fmt::Display) -> Error {
    CheckpointReason::Io.error(format!("{what}: {error}"))
}

fn may_see(c: &Checkpoint, uid: u32) -> bool {
    uid == 0 || c.owner_uid == uid
}

/// A capture that never sealed: CAPTURING, or DELETING through D1 from CAPTURING. Only
/// the READY transition writes a seal, so a READY-origin DELETING row always has one.
/// Until its release (authoritative ABSENT), a helper worker may still read its source.
/// QUARANTINED is reached only from a sealed READY row (reconciliation's Inspect), so
/// it never needs the hold; the store's broader CAPTURING to QUARANTINED transition is
/// unused, and a caller that used it would have to extend this predicate.
fn capture_origin(c: &Checkpoint) -> bool {
    c.seal.is_none()
        && matches!(
            c.state,
            CheckpointState::Capturing | CheckpointState::Deleting
        )
}

/// Whether `c` holds its source sandbox: a charged capture-origin row (design 8.2).
fn holds_its_source(c: &Checkpoint) -> bool {
    capture_origin(c) && c.is_charged()
}

impl<R: Runtime> Manager<R> {
    /// The store, as the engine reads and writes it (tests count these calls).
    pub(super) fn db(&self) -> &Store {
        #[cfg(test)]
        self.checkpoint.store_calls.fetch_add(1, Ordering::Relaxed);
        &self.store
    }

    /// Existing checkpoints get expiry, removal, rebase and reconciliation while the
    /// feature is on, any durable state exists, or the barrier is blocked; only new
    /// work needs the feature. A blocked barrier is an obligation only a complete clean
    /// inventory discharges, so durable state falling to none (a prune) never ends it.
    pub(super) fn maintained(&self) -> bool {
        self.limits.checkpoints.is_some()
            || self.checkpoint.present.load(Ordering::Relaxed)
            || self.checkpoint.barrier_blocked.load(Ordering::Relaxed)
    }

    /// No new sandbox or capture is admitted while reconciliation or a removal found
    /// resources no row explains, or the checkpoint barrier is not clean.
    pub(super) fn allocation_blocked(&self) -> bool {
        self.admission_blocked.load(Ordering::Relaxed)
            || self.checkpoint.barrier_blocked.load(Ordering::Relaxed)
    }

    /// Recounts whether durable checkpoint state exists: at startup, before each
    /// barrier retry, and after a prune removed rows or keys. C1 inserts under the same
    /// lock, so it either committed before the read, which sees it, or sets `present`
    /// after it.
    pub(super) fn refresh_checkpoint_presence(&self) -> Result<()> {
        let _presence = self.presence();
        self.recount_presence()
    }

    fn presence(&self) -> std::sync::MutexGuard<'_, ()> {
        self.checkpoint
            .presence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Under the presence lock.
    fn recount_presence(&self) -> Result<()> {
        let exists = self.db().checkpoint_state_exists()?;
        self.checkpoint.present.store(exists, Ordering::Relaxed);
        Ok(())
    }

    /// Sets or clears the checkpoint barrier, under the presence lock, so no prune
    /// runs across the change (see [`Self::prune_under_barrier`]). Its durable marker
    /// (schema 16) is the obligation a restart reads, rows or none: setting blocks in
    /// memory first, so nothing is admitted while the marker is written. The pass arms
    /// it (write-ahead) before it asks the helper anything, so no verdict exists before
    /// the marker does, and so does a removal's Retained verdict; clearing deletes the
    /// marker first, so a failure keeps allocation blocked and a crash costs only one
    /// more inventory. A clear is refused, and the barrier stays blocked, when anything
    /// armed it after the latest pass's own arm: that pass's clean verdict is stale.
    /// With nothing durable (`present` false, recounted at startup), clearing makes no
    /// query. Returns whether the barrier is blocked afterwards.
    pub(super) fn set_checkpoint_barrier(&self, blocked: bool) -> Result<bool> {
        let _presence = self.presence();
        let engine = &self.checkpoint;
        if blocked {
            self.arm_barrier_locked(false)?;
            return Ok(true);
        }
        if engine.arms.load(Ordering::SeqCst) != engine.pass_arm.load(Ordering::SeqCst) {
            return Ok(true);
        }
        if engine.present.load(Ordering::Relaxed) {
            self.db().clear_checkpoint_barrier()?;
            engine.barrier_blocked.store(false, Ordering::Relaxed);
            // The marker may have been the last durable state: the fast path returns.
            // A failed recount leaves `present` set, which only costs queries.
            if let Err(e) = self.recount_presence() {
                warn!(error = %format!("{e:#}"), "could not recount checkpoint state after the barrier cleared");
            }
        } else {
            engine.barrier_blocked.store(false, Ordering::Relaxed);
        }
        Ok(false)
    }

    /// Under the presence lock: blocks in memory, counts the arm (as the pass's own
    /// when `pass`), then commits the marker.
    fn arm_barrier_locked(&self, pass: bool) -> Result<()> {
        let engine = &self.checkpoint;
        engine.barrier_blocked.store(true, Ordering::SeqCst);
        let arm = engine.arms.fetch_add(1, Ordering::SeqCst) + 1;
        if pass {
            engine.pass_arm.store(arm, Ordering::SeqCst);
        }
        self.db().mark_checkpoint_barrier()?;
        engine.present.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Retention's prune. While the barrier is blocked it keeps every checkpoint row
    /// and capture key, with the barrier's marker (never pruned), for the restart to
    /// reconcile; only a complete clean inventory, which clears the barrier, lets prune
    /// remove the last one (design 10.2). The barrier
    /// read, the prune and the recount share the presence lock with the barrier's set
    /// and clear. Startup sets the barrier before main's first prune, so no prune ran
    /// before it was set.
    pub(super) fn prune_under_barrier(&self) -> Result<crate::retention::Pruned> {
        let _presence = self.presence();
        let blocked = self.checkpoint.barrier_blocked.load(Ordering::Relaxed);
        let pruned = self
            .store
            .prune_history(&self.limits.retention, now_ms(), !blocked)?;
        // The last checkpoint row or key may be gone: with the feature off and the
        // barrier clean, that restores the no-query fast path (checkpoint design 11.1).
        if (pruned.checkpoints != 0 || pruned.checkpoint_requests != 0)
            && self.checkpoint.present.load(Ordering::Relaxed)
        {
            self.recount_presence()?;
        }
        Ok(pruned)
    }

    fn live_captures(&self) -> HashSet<String> {
        self.checkpoint
            .captures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// The charged captures not yet proved absent (CAPTURING, or DELETING through D1
    /// before any seal) that are not this process's live captures, by source sandbox:
    /// a helper worker may still read each source, so its storage must be proved absent
    /// before the source is removed (design 8.2). Nothing maintained, no query.
    pub(super) fn held_sources(&self) -> Result<HashMap<String, CheckpointId>> {
        if !self.maintained() {
            return Ok(HashMap::new());
        }
        let live = self.live_captures();
        Ok(self
            .db()
            .unsettled_checkpoints()?
            .into_iter()
            .filter(|c| holds_its_source(c) && !live.contains(c.id.as_str()))
            .map(|c| (c.source_sandbox_id, c.id))
            .collect())
    }

    /// Keeps a held source DELETING, saying why; its removal resumes once the capture
    /// is released (see [`Self::spawn_removal`]).
    pub(super) fn hold_deleting_source(
        &self,
        id: &str,
        checkpoint: &CheckpointId,
    ) -> Result<String> {
        let reason =
            format!("held until checkpoint {checkpoint}'s capture storage is proved absent");
        warn!(sandbox = %id, checkpoint = %checkpoint, "source removal held until its interrupted capture is absent");
        self.store.compare_and_set_sandbox_state(
            id,
            SandboxState::Deleting,
            SandboxState::Deleting,
            None,
            Some(&reason),
        )?;
        Ok(reason)
    }

    fn maintenance_limits(&self) -> CheckpointLimits {
        self.limits.checkpoints.clone().unwrap_or_default()
    }

    fn checkpoint_limits(&self) -> Result<&CheckpointLimits> {
        self.limits.checkpoints.as_ref().ok_or_else(|| {
            CheckpointReason::BackendUnsupported.error("workspace checkpoints are not enabled")
        })
    }

    /// A checkpoint the caller may see, or `NotFound` for missing and foreign IDs alike
    /// (design 5.2).
    fn visible_checkpoint(&self, id: &str, uid: u32) -> Result<Checkpoint> {
        let not_found = || Error::NotFound(format!("checkpoint {id}"));
        CheckpointId::parse(id).map_err(|_| not_found())?;
        match self.db().checkpoint(id)? {
            Some(c) if may_see(&c, uid) => Ok(c),
            _ => Err(not_found()),
        }
    }

    /// The helper group's epoch and boot, from `capabilities`. A disabled group or a
    /// kiln without leases refuses before anything is reserved.
    pub(super) async fn checkpoint_session(&self) -> Result<Session> {
        self.checkpoint_session_with(&self.shutting_down.child_token())
            .await
    }

    /// As [`Self::checkpoint_session`], canceled by `cancel`.
    async fn checkpoint_session_with(&self, cancel: &CancellationToken) -> Result<Session> {
        let reply = self
            .runtime
            .checkpoint(
                None,
                CheckpointOperation::Capabilities,
                Instant::now() + HELPER_QUICK_TIMEOUT,
                cancel,
            )
            .await
            .map_err(|e| helper_unavailable("root helper checkpoint capabilities", e))?;
        match reply {
            CheckpointResponse::Capabilities(caps) => match (caps.helper_epoch, caps.boot_id) {
                (Some(epoch), Some(boot)) if caps.enabled && caps.supported => {
                    Ok(Session { epoch, boot })
                }
                (Some(_), Some(_)) if caps.enabled => Err(CheckpointReason::SandboxUnsupported
                    .error(format!(
                        "the installed kiln cannot capture: {}",
                        caps.unsupported_reason.as_deref().unwrap_or("unsupported")
                    ))),
                _ => Err(CheckpointReason::BackendUnsupported
                    .error("the root helper's checkpoint group is disabled")),
            },
            other => Err(helper_unavailable(
                "root helper checkpoint capabilities",
                format!("unexpected reply {other:?}"),
            )),
        }
    }

    /// The source run's image identity, from its own records (C5a `source`). Only a
    /// capable run of exactly the row's image is recorded.
    async fn source_identity(&self, source: &Sandbox, session: Session) -> Result<ImageIdentity> {
        let backend_id = source.backend_id.clone().ok_or_else(|| {
            CheckpointReason::SandboxUnsupported.error("the source has no backend ID")
        })?;
        let reply = self
            .runtime
            .checkpoint(
                Some(session.epoch),
                CheckpointOperation::Source { backend_id },
                Instant::now() + HELPER_QUICK_TIMEOUT,
                &self.shutting_down.child_token(),
            )
            .await
            .map_err(|e| helper_unavailable("root helper source records", e))?;
        match reply {
            CheckpointResponse::Source(reply) => match *reply {
                SourceReply::Capable {
                    image,
                    image_sha256,
                } if image == source.spec.image => Ok(ImageIdentity {
                    content_sha256: image_sha256,
                    checkpoint_format_version: crate::checkpoint::FORMAT_VERSION,
                }),
                SourceReply::Capable { .. } => Err(CheckpointReason::ImageUnavailable
                    .error("the source run records another image")),
                SourceReply::Unsupported { reason, detail } => {
                    let reason = match reason {
                        Reason::Io => CheckpointReason::Io,
                        Reason::Corrupt => CheckpointReason::Corrupt,
                        _ => CheckpointReason::SandboxUnsupported,
                    };
                    Err(reason.error(format!("the source is not a checkpoint source: {detail}")))
                }
            },
            CheckpointResponse::Error(e) => {
                Err(helper_unavailable("root helper source records", e.message))
            }
            other => Err(helper_unavailable(
                "root helper source records",
                format!("unexpected reply {other:?}"),
            )),
        }
    }

    fn take_capture_worker(&self, uid: u32, limits: &CheckpointLimits) -> Result<WorkerPermit<'_>> {
        let mut w = self
            .checkpoint
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mine = w.1.get(&uid).copied().unwrap_or(0);
        if w.0 >= limits.max_workers || mine >= limits.max_workers_per_uid {
            return Err(CheckpointReason::Workers.error(format!(
                "checkpoint workers busy ({} on the node, {} per uid)",
                limits.max_workers, limits.max_workers_per_uid
            )));
        }
        w.0 += 1;
        *w.1.entry(uid).or_insert(0) += 1;
        Ok(WorkerPermit {
            engine: &self.checkpoint,
            uid,
        })
    }

    // --- Capture -----------------------------------------------------------------

    /// CheckpointSandbox (design 7.1). Once admitted, the capture is a supervised
    /// operation: dropping this future only detaches the waiter. Unkeyed: the READY
    /// checkpoint, or the typed reason it failed. Keyed: the settled row, whatever its
    /// state, once its row committed; retries of the same key return it.
    pub async fn capture_checkpoint(
        self: &Arc<Self>,
        req: CaptureRequest,
        owner_uid: u32,
        key: Option<CaptureKey>,
        deadline: Option<Instant>,
    ) -> Result<Checkpoint> {
        let Some(key) = key else {
            self.checkpoint_limits()?;
            return self.spawn_capture(req, owner_uid, None).await;
        };
        // An accepted key is answered from its record even with the feature off (design
        // 7.1); with nothing durable, the refusal needs no lookup.
        if !self.checkpoint.present.load(Ordering::Relaxed) {
            self.checkpoint_limits()?;
        }
        let map_key = (owner_uid, key.request_id.clone());
        loop {
            // The lookup and the registration happen under one lock with no await.
            let mut done = {
                let mut keys = self.checkpoint.keys.lock().unwrap();
                match keys.get(&map_key) {
                    Some((sha, _)) if *sha != key.sha256 => {
                        return Err(capture_key_conflict(&key.request_id));
                    }
                    Some((_, done)) => Some(done.subscribe()),
                    None => {
                        // Before the source, its policy or capability is looked at.
                        if let Some((sha, row)) =
                            self.db().checkpoint_request(owner_uid, &key.request_id)?
                        {
                            if sha != key.sha256 {
                                return Err(capture_key_conflict(&key.request_id));
                            }
                            return settled_capture(row);
                        }
                        // No accepted operation: a new capture, which the feature gates.
                        self.checkpoint_limits()?;
                        keys.insert(map_key.clone(), (key.sha256, watch::Sender::new(())));
                        None
                    }
                }
            };
            let Some(mut done) = done.take() else {
                match self
                    .spawn_capture(req.clone(), owner_uid, Some(key.clone()))
                    .await
                {
                    Err(Error::RequestIdTaken) => continue,
                    other => return other,
                }
            };
            let finished = done.changed();
            match deadline {
                Some(deadline) => {
                    if tokio::time::timeout_at(deadline, finished).await.is_err() {
                        return Err(CheckpointReason::InFlight.error(format!(
                            "the capture with request_id {:?} is still running; retry to get its result",
                            key.request_id
                        )));
                    }
                }
                None => {
                    let _ = finished.await;
                }
            }
        }
    }

    async fn spawn_capture(
        self: &Arc<Self>,
        req: CaptureRequest,
        owner_uid: u32,
        key: Option<CaptureKey>,
    ) -> Result<Checkpoint> {
        self.check_serving()?;
        let (tx, rx) = oneshot::channel();
        // Design 8.2: before durable admission, a departed waiter stops the capture.
        let waiter_gone = CancellationToken::new();
        let manager = Arc::clone(self);
        let gone = waiter_gone.clone();
        self.operations.spawn(async move {
            manager
                .capture_supervised(req, owner_uid, key, tx, gone)
                .await;
        });
        let departed = waiter_gone.drop_guard();
        let answer = rx.await;
        departed.disarm();
        answer.map_err(|_| {
            Error::Internal(anyhow::anyhow!(
                "capture supervisor stopped without a result"
            ))
        })?
    }

    /// The supervised capture: C0 checks, the source gate, C1, the helper's capture,
    /// and READY or the failure path. The reply goes to `reply` as soon as the outcome
    /// is known; a failed capture then keeps the source gate until the helper proves
    /// its worker gone and its storage absent.
    async fn capture_supervised(
        self: Arc<Self>,
        req: CaptureRequest,
        owner_uid: u32,
        key: Option<CaptureKey>,
        reply: oneshot::Sender<Result<Checkpoint>>,
        waiter_gone: CancellationToken,
    ) {
        let mut reply = Some(reply);
        let keyed = key.as_ref().map(|k| (owner_uid, k.request_id.clone()));
        let engine = &self.checkpoint;
        // The answer, and with it the end of a keyed attempt's in-flight entry: its
        // retries now read the durable record (or nothing, if nothing committed).
        let mut send = |result: Result<Checkpoint>| {
            if let Some(reply) = reply.take() {
                if let Some(map_key) = &keyed {
                    engine
                        .keys
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(map_key);
                }
                let _ = reply.send(result);
            }
        };
        let limits = match self.checkpoint_limits() {
            Ok(limits) => limits.clone(),
            Err(e) => return send(Err(e)),
        };
        // C0: validation, ownership and capability checks; nothing allocated.
        let admitted = match self.capture_admission(&req, owner_uid, &limits) {
            Ok(admitted) => admitted,
            Err(e) => {
                self.checkpoint
                    .rejected_captures
                    .fetch_add(1, Ordering::Relaxed);
                return send(Err(e));
            }
        };
        let (source, expiry, r) = admitted;
        let _worker = match self.take_capture_worker(owner_uid, &limits) {
            Ok(w) => w,
            Err(e) => {
                self.checkpoint
                    .rejected_captures
                    .fetch_add(1, Ordering::Relaxed);
                return send(Err(e));
            }
        };
        // The source gate (design 4.1 step 1 and 8.2): try the exec mutex, then under
        // the admission gate require READY, no admitted or queued Exec and no other
        // capture, and set the flag that makes new Exec refuse `checkpoint_busy`.
        let slot = self.slot(&source.id);
        let Ok(_exec) = slot.exec_lock.try_lock() else {
            self.checkpoint
                .rejected_captures
                .fetch_add(1, Ordering::Relaxed);
            return send(Err(CheckpointReason::Busy.error(format!(
                "sandbox {} is running or queuing an execution",
                source.id
            ))));
        };
        let cancel = CancellationToken::new();
        let source = {
            let _gate = slot.admission.lock().unwrap_or_else(|e| e.into_inner());
            let row = match self
                .load(&source.id)
                .and_then(|row| ready(&row).map(|()| row))
            {
                Ok(row) => row,
                Err(e) => return send(Err(e)),
            };
            if slot.busy() {
                self.checkpoint
                    .rejected_captures
                    .fetch_add(1, Ordering::Relaxed);
                return send(Err(CheckpointReason::Busy.error(format!(
                    "sandbox {} is running, queuing or capturing",
                    row.id
                ))));
            }
            *slot.capturing.lock().unwrap_or_else(|e| e.into_inner()) = Some(cancel.clone());
            row
        };
        let mut flag = CapturingFlag {
            manager: &self,
            slot: Arc::clone(&slot),
            source: source.id.clone(),
            checkpoint: None,
        };
        let session = match self.checkpoint_session().await {
            Ok(s) => s,
            Err(e) => return send(Err(e)),
        };
        let departed = || {
            CheckpointReason::NotReady.error("the caller departed before the capture was admitted")
        };
        if waiter_gone.is_cancelled() {
            return send(Err(departed()));
        }
        // Recorded once, in C1's transaction, from the run's own records.
        let identity = match source.lifecycle.image_identity {
            Some(_) => None,
            None => match self.source_identity(&source, session).await {
                Ok(identity) => Some(identity),
                Err(e) => return send(Err(e)),
            },
        };
        if cancel.is_cancelled() {
            return send(Err(
                CheckpointReason::NotReady.error("the source is being deleted")
            ));
        }
        // C1: the CAPTURING row charged R, its key record and the dispatch binding.
        let new = NewCheckpoint {
            id: CheckpointId::random(),
            owner_uid,
            generation: 1,
            source_sandbox_id: source.id.clone(),
            capture: HelperDispatch {
                operation: Id128::random(),
                helper_epoch: session.epoch,
                boot_id: session.boot,
            },
            max_size_bytes: r,
            writable_paths: normalized_paths(&source.spec.writable_paths),
            excluded_paths: EXCLUDED_PATHS.iter().map(|p| p.to_string()).collect(),
            expiry,
            request_id: key.as_ref().map(|k| k.request_id.clone()),
            source_identity: identity,
        };
        let admission = key.as_ref().map(|k| RequestAdmission {
            sha256: k.sha256,
            max_per_uid: limits.budgets.max_request_records_per_uid,
            max_node: limits.budgets.max_request_records_node,
        });
        // After the source identity's await, and the last look before C1: from C1 on, a
        // departed waiter only detaches.
        if waiter_gone.is_cancelled() {
            return send(Err(departed()));
        }
        let presence = self.presence();
        let reserved = self.db().reserve_checkpoint(
            &new,
            &limits.budgets,
            self.sandbox_budgets(),
            admission.as_ref(),
        );
        if matches!(reserved, Ok(ReserveCheckpoint::Inserted(_))) {
            self.checkpoint.present.store(true, Ordering::Relaxed);
        }
        drop(presence);
        let checkpoint = match reserved {
            Ok(ReserveCheckpoint::Inserted(c)) => *c,
            Ok(refused) => {
                self.checkpoint
                    .rejected_captures
                    .fetch_add(1, Ordering::Relaxed);
                return send(Err(self.reserve_refusal(refused, &source.id)));
            }
            Err(e) => return send(Err(e.into())),
        };
        let id = checkpoint.id.to_string();
        flag.checkpoint = Some(id.clone());
        self.checkpoint
            .captures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), cancel.clone());
        // A Delete or source removal may have published intent between the gate and
        // the registration above: its cancellation must still be seen.
        if !cancel.is_cancelled()
            && self
                .db()
                .checkpoint(&id)
                .ok()
                .flatten()
                .is_some_and(|c| c.state != CheckpointState::Capturing)
        {
            cancel.cancel();
        }
        info!(checkpoint = %id, sandbox = %source.id, owner_uid, "capturing checkpoint");
        let failure = self
            .run_capture(&checkpoint, session, &limits, &cancel)
            .await;
        let (reason, detail) = match failure {
            Ok(ready) => {
                self.checkpoint_timer_refresh(&id);
                return send(Ok(ready));
            }
            // Shutdown answers the waiter but not the supervision: the capture is
            // failed and removed like any other before its source is released.
            Err(CaptureFailure::ShuttingDown) => {
                send(Err(Error::ShuttingDown));
                (
                    CheckpointReason::Io,
                    "kilnd shut down during the capture; its storage is removed".into(),
                )
            }
            Err(CaptureFailure::Failed(reason, detail)) => (reason, detail),
        };
        warn!(checkpoint = %id, reason = reason.token(), detail = %detail, "capture failed; removing its storage");
        // Keyed callers get the row (failure recorded); unkeyed the typed reason.
        let recorded =
            self.db()
                .record_checkpoint_failure_token(&id, reason.token(), &detail, false);
        if let Err(e) = recorded {
            warn!(checkpoint = %id, error = %format!("{e:#}"), "could not record the capture failure");
        }
        send(match &key {
            Some(_) => self
                .db()
                .checkpoint(&id)
                .map_err(Error::from)
                .and_then(|row| {
                    row.ok_or_else(|| Error::Internal(anyhow::anyhow!("checkpoint {id} vanished")))
                }),
            None => Err(reason.error(detail)),
        });
        // The source stays gated until the capture's worker is proved gone (design 8.2:
        // stop the reader before the source's storage is removed), through shutdown
        // too: each helper call is bounded by its own deadline, not by shutdown.
        let released = self
            .remove_until_absent(&id, None, false, &CancellationToken::new())
            .await;
        self.barrier_after_removal(released.is_some());
        drop(flag);
    }

    /// C0 (design 10): nothing is allocated and the helper is not called. Returns the
    /// source row, the resolved expiry and R.
    fn capture_admission(
        &self,
        req: &CaptureRequest,
        owner_uid: u32,
        limits: &CheckpointLimits,
    ) -> Result<(Sandbox, CheckpointExpiry, u64)> {
        self.check_serving()?;
        let expiry = resolve_checkpoint_expiry(req.expiry, limits)?;
        let source = match self.load(&req.sandbox_id) {
            Ok(s) if may_use(&s, owner_uid) => s,
            Ok(_) | Err(Error::NotFound(_)) => {
                return Err(Error::NotFound(format!("sandbox {}", req.sandbox_id)));
            }
            Err(e) => return Err(e),
        };
        // Design 11.1: a backend without checkpoints refuses before any helper call,
        // reservation, row or allocation.
        if !self.runtime.checkpoint_backend()
            || source.is_fenced()
            || source.backend != self.runtime.name()
        {
            return Err(CheckpointReason::BackendUnsupported
                .error("this sandbox's backend has no workspace checkpoints"));
        }
        if self.allocation_blocked() {
            return Err(Error::FailedPrecondition(
                "backend resources or checkpoint artifacts no row explains block new allocations until reconciled".into(),
            ));
        }
        ready(&source)?;
        let cap = limits
            .budgets
            .max_size_bytes
            .min(source.accounting.reservation.disk_bytes);
        let r = if req.max_size_bytes == 0 {
            cap
        } else {
            req.max_size_bytes
        };
        if r > cap {
            return Err(CheckpointReason::SizeLimit.error(format!(
                "max_size_bytes {r} exceeds the limit {cap} (the source's disk or the per-checkpoint limit)"
            )));
        }
        if r < MIN_LIMIT_BYTES {
            return Err(Error::InvalidArgument(format!(
                "max_size_bytes {r} is below the {MIN_LIMIT_BYTES}-byte minimum"
            )));
        }
        Ok((source, expiry, r))
    }

    fn reserve_refusal(&self, refused: ReserveCheckpoint, source: &str) -> Error {
        match refused {
            ReserveCheckpoint::Exhausted(e) => CheckpointReason::Quota.error(format!(
                "{} {} cap: {} reserved + {} requested exceeds {}",
                e.scope, e.resource, e.reserved, e.requested, e.limit
            )),
            ReserveCheckpoint::RequestQuota(q) => Error::Refused(
                RefusalCode::ResourceExhausted,
                Refusal::typed(
                    "request_id_quota",
                    format!(
                        "capture request records at the {} cap: {} of {}",
                        q.scope, q.count, q.limit
                    ),
                ),
            ),
            ReserveCheckpoint::RequestIdTaken => Error::RequestIdTaken,
            ReserveCheckpoint::SizeLimit { requested, limit } => CheckpointReason::SizeLimit.error(
                format!("max_size_bytes {requested} exceeds the limit {limit}"),
            ),
            ReserveCheckpoint::SourceUnavailable => match self.load(source) {
                Ok(row) if row.state != SandboxState::Ready => {
                    let reason = not_ready_reason(&row);
                    Error::FailedPrecondition(Refusal::typed(
                        reason,
                        format!("sandbox {source} is {}", row.state.as_str()),
                    ))
                }
                Ok(_) => CheckpointReason::SandboxUnsupported
                    .error("the source has no recorded image identity"),
                Err(e) => e,
            },
            ReserveCheckpoint::Inserted(_) => {
                Error::Internal(anyhow::anyhow!("an inserted capture is not a refusal"))
            }
        }
    }

    /// C2-C4: dispatch under the recorded epoch, then READY only with this binding's
    /// COMPLETE evidence while the source is still READY under its backend.
    async fn run_capture(
        &self,
        c: &Checkpoint,
        session: Session,
        limits: &CheckpointLimits,
        cancel: &CancellationToken,
    ) -> std::result::Result<Checkpoint, CaptureFailure> {
        let deadline = Instant::now() + limits.operation_timeout;
        if cancel.is_cancelled() {
            return Err(CaptureFailure::Failed(
                CheckpointReason::NotReady,
                "the capture was canceled before dispatch".into(),
            ));
        }
        let call = self.runtime.checkpoint(
            Some(session.epoch),
            CheckpointOperation::Capture {
                binding: c.capture_binding(),
            },
            deadline,
            cancel,
        );
        tokio::pin!(call);
        // Shutdown cancels the capture and still takes its reply: the helper reports
        // the worker's end, and the cleanup follows it.
        let reply = tokio::select! {
            reply = &mut call => reply,
            () = self.shutting_down.cancelled() => {
                cancel.cancel();
                call.await
            }
        };
        let stopped = || {
            if self.shutting_down.is_cancelled() {
                return CaptureFailure::ShuttingDown;
            }
            CaptureFailure::Failed(
                CheckpointReason::NotReady,
                "the capture was canceled: its source or the checkpoint is being deleted".into(),
            )
        };
        let evidence = match reply {
            Ok(CheckpointResponse::Captured(reply)) => match *reply {
                CaptureReply::Complete { evidence } => evidence,
                // Canceled by a Delete or a source removal: that, not the
                // worker's own stop, is why it failed.
                CaptureReply::Failed { .. } if cancel.is_cancelled() => return Err(stopped()),
                CaptureReply::Failed { reason, detail } => {
                    return Err(CaptureFailure::Failed(
                        CheckpointReason::from_helper(reason),
                        detail,
                    ));
                }
                CaptureReply::Pending if cancel.is_cancelled() => return Err(stopped()),
                CaptureReply::Pending => {
                    return Err(CaptureFailure::Failed(
                        CheckpointReason::Io,
                        "the capture did not settle within its deadline".into(),
                    ));
                }
            },
            Ok(CheckpointResponse::Error(e)) if e.kind == CheckpointErrorKind::Workers => {
                return Err(CaptureFailure::Failed(CheckpointReason::Workers, e.message));
            }
            Ok(CheckpointResponse::Error(e)) if e.kind == CheckpointErrorKind::Busy => {
                return Err(CaptureFailure::Failed(CheckpointReason::Busy, e.message));
            }
            Ok(other) => {
                let detail = format!("unexpected capture reply {other:?}");
                return Err(CaptureFailure::Failed(CheckpointReason::Io, detail));
            }
            Err(_) if cancel.is_cancelled() => return Err(stopped()),
            Err(e) => return Err(CaptureFailure::Failed(CheckpointReason::Io, e.to_string())),
        };
        // An image the source's record does not name is never READY (C5a).
        let reason = match &evidence.evidence.fact {
            Fact::Complete(fact)
                if fact.image != c.image || fact.image_sha256 != c.image_content_sha256 =>
            {
                CheckpointReason::ImageUnavailable
            }
            _ => CheckpointReason::Corrupt,
        };
        match self.db().publish_checkpoint_ready(c.id.as_str(), &evidence) {
            Ok(PublishCheckpoint::Published(row)) => {
                self.acknowledge(
                    c,
                    c.capture.operation,
                    session,
                    &self.shutting_down.child_token(),
                )
                .await;
                info!(checkpoint = %c.id, size = row.charge_bytes(), "checkpoint ready");
                Ok(*row)
            }
            Ok(PublishCheckpoint::NotCapturing(_)) => Err(stopped()),
            Ok(PublishCheckpoint::SourceChanged) => Err(CaptureFailure::Failed(
                CheckpointReason::NotReady,
                "the source changed during the capture".into(),
            )),
            Ok(PublishCheckpoint::Refused(why)) => Err(CaptureFailure::Failed(reason, why)),
            Err(e) => Err(CaptureFailure::Failed(
                CheckpointReason::Io,
                format!("publication failed: {e:#}"),
            )),
        }
    }

    /// Best effort: lets the helper drop its record of a stored fact.
    async fn acknowledge(
        &self,
        c: &Checkpoint,
        operation: Id128,
        session: Session,
        cancel: &CancellationToken,
    ) {
        let _ = self
            .runtime
            .checkpoint(
                Some(session.epoch),
                CheckpointOperation::Acknowledge {
                    target: c.target(),
                    operation,
                },
                Instant::now() + HELPER_QUICK_TIMEOUT,
                cancel,
            )
            .await;
    }

    // --- Get, List and Delete ------------------------------------------------------

    /// GetCheckpoint (design 7.1 and 8.2): owner or root. A usable READY row refreshes
    /// its idle activity through the store's CAS; a row already due expires instead,
    /// without resurrection. Lifetime is checked first.
    pub fn get_checkpoint(self: &Arc<Self>, id: &str, uid: u32) -> Result<Checkpoint> {
        let row = self.visible_checkpoint(id, uid)?;
        if row.state != CheckpointState::Ready || !row.is_charged() {
            return Ok(row);
        }
        let pinned = self.db().checkpoint_has_live_pins(id)?;
        if let Some((due, _)) = self.checkpoint_due(&row, pinned) {
            if due <= self.clock.boottime_ms() {
                self.expire_checkpoint(id);
            } else if self.db().touch_checkpoint(id, row.activity_seq)? {
                self.checkpoint_timer_refresh(id);
            }
        }
        self.visible_checkpoint(id, uid)
    }

    /// ListCheckpoints' store page (design 5.2): filtered by owner unless root, and by
    /// immutable source ID, before paging. Side-effect-free.
    pub fn list_checkpoints(
        &self,
        uid: u32,
        source: Option<&str>,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<crate::store::CheckpointPage> {
        let owner = (uid != 0).then_some(uid);
        Ok(self
            .db()
            .checkpoint_page(owner, source, before_seq, limit)?)
    }

    /// DeleteCheckpoint (design 7.1, D1-D3): publish DELETING (no pin is admitted from
    /// here), cancel a running capture, then hand the removal to a supervisor and wait
    /// for its first attempt. A failed attempt keeps the row DELETING and charged while
    /// the supervisor retries; a departed waiter leaves it running. Idempotent for
    /// DELETED rows; a FAILED (already absent) row becomes DELETED. `release_request_id`
    /// releases the capture key only once the row is DELETED.
    pub async fn delete_checkpoint(
        self: &Arc<Self>,
        id: &str,
        uid: u32,
        release_request_id: bool,
    ) -> Result<Checkpoint> {
        let row = self.visible_checkpoint(id, uid)?;
        match row.state {
            CheckpointState::Deleted => {}
            CheckpointState::Failed => {
                self.db().delete_failed_checkpoint(id)?;
            }
            CheckpointState::Capturing
            | CheckpointState::Ready
            | CheckpointState::Quarantined
            | CheckpointState::Deleting => {
                self.db()
                    .publish_checkpoint_delete_intent(id, DeletionReason::Requested)?;
                self.cancel_capture(id);
                self.checkpoint_timer_refresh(id);
                let (tx, rx) = oneshot::channel();
                if self.spawn_removal(id, Some(tx), release_request_id) {
                    rx.await.map_err(|_| {
                        Error::Internal(anyhow::anyhow!(
                            "checkpoint removal supervisor stopped without a result"
                        ))
                    })??;
                    return self.visible_checkpoint(id, uid);
                }
                // A supervisor already owns its retries (or the daemon is stopping, and
                // startup resumes it): one attempt of this caller's own.
                match self.removal_attempt(id).await {
                    Removal::Released(_) => {}
                    Removal::NotRemovable(row) => return Err(not_removable(&row)),
                    Removal::Retry(e) => return Err(e),
                    Removal::Blocked(e) => {
                        self.barrier_after_removal(false);
                        return Err(e);
                    }
                }
            }
        }
        if release_request_id {
            self.db().release_checkpoint_request_id(id)?;
        }
        self.visible_checkpoint(id, uid)
    }

    fn cancel_capture(&self, id: &str) {
        if let Some(cancel) = self
            .checkpoint
            .captures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
        {
            cancel.cancel();
        }
    }

    // --- Removal (D1-D3) -------------------------------------------------------------

    fn removal_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .checkpoint
            .removal_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(id.to_string(), Arc::downgrade(&lock));
        lock
    }

    /// One D2-D3 attempt: a fresh removal nonce recorded under the current helper
    /// epoch, the helper's tombstoning removal, and the release only with that
    /// removal's ABSENT evidence. Serialized per checkpoint.
    async fn removal_attempt(&self, id: &str) -> Removal {
        self.removal_attempt_with(id, &self.shutting_down.child_token())
            .await
    }

    /// As [`Self::removal_attempt`], its helper calls canceled by `cancel`.
    async fn removal_attempt_with(&self, id: &str, cancel: &CancellationToken) -> Removal {
        let lock = self.removal_lock(id);
        let _one = lock.lock().await;
        match self.removal_attempt_locked(id, cancel).await {
            Ok(removal) => removal,
            Err(e) => Removal::Retry(e),
        }
    }

    async fn removal_attempt_locked(
        &self,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<Removal> {
        let row = self
            .db()
            .checkpoint(id)?
            .ok_or_else(|| Error::NotFound(format!("checkpoint {id}")))?;
        if !row.is_charged() {
            return Ok(Removal::Released(Box::new(row)));
        }
        let removable = match row.state {
            CheckpointState::Deleting => true,
            CheckpointState::Capturing => row.failure.is_some(),
            _ => false,
        };
        if !removable {
            return Ok(Removal::NotRemovable(Box::new(row)));
        }
        let session = self.checkpoint_session_with(cancel).await?;
        let dispatch = HelperDispatch {
            operation: Id128::random(),
            helper_epoch: session.epoch,
            boot_id: session.boot,
        };
        if !self.db().record_checkpoint_removal(id, &dispatch)? {
            return Err(CheckpointReason::Busy.error(format!("checkpoint {id} changed")));
        }
        let reply = self
            .runtime
            .checkpoint(
                Some(session.epoch),
                CheckpointOperation::Remove {
                    target: row.target(),
                    operation: dispatch.operation,
                },
                Instant::now() + REMOVE_TIMEOUT,
                cancel,
            )
            .await
            .map_err(|e| helper_unavailable("root helper checkpoint removal", e))?;
        let evidence: SealedEvidence = match reply {
            CheckpointResponse::Removed(reply) => match *reply {
                RemoveReply::Absent { evidence } => evidence,
                RemoveReply::Retained { reason, detail }
                    if matches!(reason, Reason::GenerationMismatch | Reason::Corrupt) =>
                {
                    // C3: not this row's artifact to prove absent. Keep the charge and
                    // arm the barrier (durable, blocked in memory first): its retry's
                    // pass holds it while this row is charged, and a clean pass after
                    // the row proves ABSENT reopens admission. The row's reason is for
                    // readers only; a restart blocks on the charged row itself.
                    if row.state == CheckpointState::Deleting {
                        let _ = self
                            .db()
                            .record_checkpoint_removal_failure(id, reason, &detail);
                    }
                    if let Err(e) = self.set_checkpoint_barrier(true) {
                        warn!(checkpoint = %id, error = %format!("{e:#}"), "could not write the checkpoint barrier's marker; allocation stays blocked in memory");
                    }
                    warn!(checkpoint = %id, reason = reason.token(), "checkpoint removal found an artifact it cannot prove this row's; charge kept and allocation blocked");
                    return Ok(Removal::Blocked(
                        CheckpointReason::Corrupt
                            .error(format!("checkpoint {id}: {}: {detail}", reason.token())),
                    ));
                }
                RemoveReply::Retained { reason, detail } => {
                    return Err(CheckpointReason::from_helper(reason)
                        .error(format!("checkpoint {id} removal retained: {detail}")));
                }
                RemoveReply::Pending => {
                    return Err(CheckpointReason::Io
                        .error(format!("checkpoint {id} removal did not settle in time")));
                }
            },
            CheckpointResponse::Error(e) if e.kind == CheckpointErrorKind::Workers => {
                return Err(CheckpointReason::Workers.error(e.message));
            }
            other => {
                return Err(helper_unavailable(
                    "root helper checkpoint removal",
                    format!("{other:?}"),
                ));
            }
        };
        match self.db().settle_checkpoint_absence(id, &evidence)? {
            SettleAbsence::Released(c) | SettleAbsence::AlreadyReleased(c) => {
                self.acknowledge(&c, dispatch.operation, session, cancel)
                    .await;
                self.checkpoint_timer_refresh(id);
                info!(checkpoint = %id, state = c.state.as_str(), "checkpoint storage proved absent; charge released");
                Ok(Removal::Released(c))
            }
            SettleAbsence::NotReleasable(state) => Ok(Removal::NotRemovable(Box::new(
                self.db().checkpoint(id)?.ok_or_else(|| {
                    Error::NotFound(format!("checkpoint {id} ({})", state.as_str()))
                })?,
            ))),
            SettleAbsence::Refused(why) => Err(CheckpointReason::Io.error(format!(
                "checkpoint {id}: the helper's absence evidence was refused: {why}"
            ))),
        }
    }

    /// Removes until ABSENT releases the row, the removal is blocked or the row is not
    /// removable, retrying anything else with backoff: a charged DELETING row (and any
    /// pin on it) must always reach ABSENT. `first` gets the first attempt's answer;
    /// `release_request_id` releases the capture key once DELETED, before answering.
    /// `cancel` bounds the helper calls and ends the retries: shutdown for a background
    /// supervisor (startup resumes it), never for a capture's own cleanup. Returns the
    /// released row.
    async fn remove_until_absent(
        &self,
        id: &str,
        mut first: Option<oneshot::Sender<Result<Checkpoint>>>,
        release_request_id: bool,
        cancel: &CancellationToken,
    ) -> Option<Checkpoint> {
        let limits = self.maintenance_limits();
        let mut delay = limits.removal_retry;
        let mut answer = |result: Result<Checkpoint>| {
            if let Some(first) = first.take() {
                let _ = first.send(result);
            }
        };
        loop {
            let error = match self.removal_attempt_with(id, cancel).await {
                Removal::Released(c) => {
                    let released = match release_request_id {
                        true => self.db().release_checkpoint_request_id(id).map(|_| ()),
                        false => Ok(()),
                    };
                    if let Err(e) = &released {
                        warn!(checkpoint = %id, error = %format!("{e:#}"), "could not release the deleted checkpoint's capture key");
                    }
                    answer(released.map(|()| (*c).clone()).map_err(Error::from));
                    return Some(*c);
                }
                Removal::NotRemovable(c) => {
                    answer(Err(not_removable(&c)));
                    return None;
                }
                Removal::Blocked(e) => {
                    answer(Err(e));
                    return None;
                }
                Removal::Retry(e) => e,
            };
            warn!(checkpoint = %id, error = %error, delay_ms = delay.as_millis() as u64, "checkpoint removal will be retried; its charge is kept");
            answer(Err(error));
            tokio::select! {
                () = cancel.cancelled() => return None,
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(limits.max_removal_retry);
        }
    }

    /// Hands a removal to a tracked supervisor, at most one per checkpoint, which
    /// owns its lock, retries and charge from now on (see [`Self::remove_until_absent`]).
    /// False when one already runs or the daemon is stopping.
    pub(super) fn spawn_removal(
        self: &Arc<Self>,
        id: &str,
        first: Option<oneshot::Sender<Result<Checkpoint>>>,
        release_request_id: bool,
    ) -> bool {
        if self.shutting_down.is_cancelled()
            || !self
                .checkpoint
                .retrying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id.to_string())
        {
            return false;
        }
        let manager = Arc::clone(self);
        let id = id.to_string();
        self.operations.spawn(async move {
            let cancel = manager.shutting_down.child_token();
            let released = manager
                .remove_until_absent(&id, first, release_request_id, &cancel)
                .await;
            manager
                .checkpoint
                .retrying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            manager.barrier_after_removal(released.is_some());
            // A capture's source whose removal was held for this ABSENT (a failed or
            // D1-canceled capture, after a restart) is removed now; a failure leaves it
            // DELETING for a later Delete. A sealed (READY-origin) row never held one.
            let Some(c) = released.filter(|c| c.seal.is_none()) else {
                return;
            };
            let source = c.source_sandbox_id.as_str();
            if matches!(manager.store.sandbox(source), Ok(Some(s)) if s.state == SandboxState::Deleting)
                && let Err(e) = manager.delete(source).await
            {
                warn!(sandbox = %source, error = %e, "the held source's delete failed; it stays DELETING");
            }
        });
        true
    }

    // --- Expiry ---------------------------------------------------------------------

    /// The next due boottime and whether it is the lifetime, for a charged READY or
    /// QUARANTINED row anchored in this boot. Idle is paused while a pin is live and
    /// never falls inside the restart grace; lifetime never pauses.
    fn checkpoint_due(&self, c: &Checkpoint, pinned: bool) -> Option<(i64, DeletionReason)> {
        if !c.is_charged()
            || !matches!(
                c.state,
                CheckpointState::Ready | CheckpointState::Quarantined
            )
            || c.clock_boot_id.as_deref() != Some(self.clock.boot_id().as_str())
        {
            return None;
        }
        let lifetime = c
            .ready_boottime_ms?
            .saturating_add(i64::try_from(c.expiry.lifetime_ms).unwrap_or(i64::MAX));
        let grace = self
            .expiry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .grace_until;
        let idle = (c.state == CheckpointState::Ready && !pinned)
            .then(|| {
                c.activity_boottime_ms.or(c.ready_boottime_ms).map(|a| {
                    a.saturating_add(i64::try_from(c.expiry.idle_ms).unwrap_or(i64::MAX))
                        .max(grace)
                })
            })
            .flatten();
        match idle {
            Some(idle) if idle < lifetime => Some((idle, DeletionReason::ExpiredIdle)),
            _ => Some((lifetime, DeletionReason::ExpiredLifetime)),
        }
    }

    /// Recomputes one checkpoint's timer from its row.
    pub(super) fn checkpoint_timer_refresh(&self, id: &str) {
        if !self.maintained() {
            return;
        }
        let next = match (
            self.db().checkpoint(id),
            self.db().checkpoint_has_live_pins(id),
        ) {
            (Ok(Some(c)), Ok(pinned)) => self.checkpoint_due(&c, pinned).map(|(due, _)| due),
            (Ok(None), _) => None,
            _ => Some(self.clock.boottime_ms().saturating_add(5_000)),
        };
        let mut timers = self
            .checkpoint
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match next {
            Some(due) => {
                timers.insert(id.to_string(), due);
            }
            None => {
                timers.remove(id);
            }
        }
        drop(timers);
        self.expiry_changed.notify_one();
    }

    /// The earliest checkpoint timer, for the sweeper's wait.
    pub(super) fn checkpoint_timer_head(&self) -> Option<i64> {
        self.checkpoint
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .min()
            .copied()
    }

    /// The sweeper's checkpoint pass: every timer due now. Never awaits.
    pub(super) fn expire_checkpoints_due(self: &Arc<Self>) {
        if !self.maintained() {
            return;
        }
        let now = self.clock.boottime_ms();
        let due: Vec<String> = self
            .checkpoint
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            if self.shutting_down.is_cancelled() {
                break;
            }
            self.expire_checkpoint(&id);
        }
    }

    /// Design 8.1: a due checkpoint becomes DELETING with its expiry reason (idle by
    /// CAS on its activity sequence, refused while pinned), then takes the same
    /// D1-D3 removal as Delete.
    pub(super) fn expire_checkpoint(self: &Arc<Self>, id: &str) {
        let now = self.clock.boottime_ms();
        let published = (|| -> Result<bool> {
            let Some(c) = self.db().checkpoint(id)? else {
                return Ok(false);
            };
            let pinned = self.db().checkpoint_has_live_pins(id)?;
            Ok(match self.checkpoint_due(&c, pinned) {
                Some((due, reason)) if due <= now => {
                    let seq = (reason == DeletionReason::ExpiredIdle).then_some(c.activity_seq);
                    self.db()
                        .publish_checkpoint_expiry_intent(id, reason, seq)?
                }
                _ => false,
            })
        })();
        match published {
            Ok(true) => {
                self.checkpoint.expired.fetch_add(1, Ordering::Relaxed);
                info!(checkpoint = %id, "checkpoint expired; deleting");
                self.cancel_capture(id);
                self.checkpoint_timer_refresh(id);
                self.spawn_removal(id, None, false);
            }
            Ok(false) => self.checkpoint_timer_refresh(id),
            Err(e) => {
                warn!(checkpoint = %id, error = %e, "checkpoint expiry could not publish its intent; retrying");
                let mut timers = self
                    .checkpoint
                    .timers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                timers.insert(id.to_string(), now.saturating_add(5_000));
            }
        }
    }

    /// Startup, after reconciliation and the rebase: one timer per charged READY or
    /// QUARANTINED row, a removal for every DELETING row and failed capture, and the
    /// barrier's retry while it is blocked. With the feature off, as long as any durable
    /// state exists (design 11.1).
    pub(super) fn start_checkpoints(self: &Arc<Self>) -> Result<()> {
        if !self.maintained() {
            return Ok(());
        }
        self.resume_checkpoints()?;
        self.spawn_barrier_retry();
        Ok(())
    }

    fn resume_checkpoints(self: &Arc<Self>) -> Result<()> {
        for (c, _) in self.db().checkpoint_expiry_rows()? {
            match c.state {
                CheckpointState::Deleting => {
                    self.spawn_removal(c.id.as_str(), None, false);
                }
                _ => self.checkpoint_timer_refresh(c.id.as_str()),
            }
        }
        for c in self.db().unsettled_checkpoints()? {
            if c.state == CheckpointState::Capturing && c.failure.is_some() {
                self.spawn_removal(c.id.as_str(), None, false);
            }
        }
        Ok(())
    }

    /// After a removal settled or was blocked: a blocked barrier gets its retry (a
    /// Retained verdict armed it), whose backoff paces the next removal attempt, and
    /// an early pass once a row was released (it may make the pass clean).
    fn barrier_after_removal(self: &Arc<Self>, released: bool) {
        if self.checkpoint.barrier_blocked.load(Ordering::SeqCst) {
            self.spawn_barrier_retry();
            if released {
                self.checkpoint.barrier_kick.notify_one();
            }
        }
    }

    /// While the barrier is blocked: its pass again with backoff, each followed by the
    /// timers and removals it may have made due, until a clean pass clears the
    /// checkpoint part of the allocation block (never `admission_blocked`). Delete, Get,
    /// List and removals stay available meanwhile.
    fn spawn_barrier_retry(self: &Arc<Self>) {
        let engine = &self.checkpoint;
        if !engine.barrier_blocked.load(Ordering::Relaxed)
            || !self.runtime.checkpoint_backend()
            || self.shutting_down.is_cancelled()
            || engine.barrier_retrying.swap(true, Ordering::SeqCst)
        {
            return;
        }
        let manager = Arc::clone(self);
        self.operations.spawn(async move {
            let limits = manager.maintenance_limits();
            let mut delay = limits.removal_retry;
            loop {
                tokio::select! {
                    () = manager.shutting_down.cancelled() => break,
                    () = tokio::time::sleep(delay) => {}
                    () = manager.checkpoint.barrier_kick.notified() => {}
                }
                let pass = match manager.refresh_checkpoint_presence() {
                    Ok(()) => manager.reconcile_checkpoints().await,
                    Err(e) => Err(e),
                };
                let blocked = pass.unwrap_or_else(|e| {
                    warn!(error = %format!("{e:#}"), "checkpoint reconciliation failed; allocation stays blocked");
                    true
                });
                if let Err(e) = manager.resume_checkpoints() {
                    warn!(error = %format!("{e:#}"), "could not resume checkpoint timers and removals");
                }
                if !blocked {
                    match manager.set_checkpoint_barrier(false) {
                        Ok(false) => {
                            info!("checkpoint reconciliation is clean; new allocations are admitted");
                            break;
                        }
                        // Armed again since this pass began: the next pass decides.
                        Ok(true) => {}
                        Err(e) => warn!(error = %format!("{e:#}"), "could not clear the checkpoint barrier's marker; allocation stays blocked"),
                    }
                }
                delay = (delay * 2).min(limits.max_removal_retry);
            }
            manager
                .checkpoint
                .barrier_retrying
                .store(false, Ordering::SeqCst);
            // An arm that raced this retry's exit found it still running: retry again.
            manager.spawn_barrier_retry();
        });
    }

    // --- Startup reconciliation (design 10.2) -----------------------------------------

    /// The barrier, at startup and in its retry. It reads every charged row first, then
    /// needs a session, a complete inventory whose every entry names a charged row and
    /// whose every tracked operation, reader and tombstone its row explains, an
    /// Inspect of every READY row, and no charged row other than a sealed one or a
    /// capture running in this process: a dead or failed CAPTURING row and any DELETING
    /// row block until their removal proves ABSENT. An interrupted capture is failed (C3 complete without
    /// C4 is discarded, never promoted); a READY row whose artifact is authoritatively
    /// missing, corrupt or another generation's is quarantined; anything unknown keeps
    /// its row and charge and blocks allocation. Returns whether allocation stays
    /// blocked. With the feature off and no durable state (`present`, recounted by the
    /// caller): no query, no pass, no marker.
    pub(super) async fn reconcile_checkpoints(&self) -> Result<bool> {
        if !self.maintained() {
            return Ok(false);
        }
        // A backend with no checkpoint group (Firecracker): no helper call, so its
        // verdict is the durable state alone. It cannot inventory, so it never
        // discharges an outstanding marker: only a checkpoint backend's complete clean
        // inventory does (design 11.1), and the operator switches back for it.
        if !self.runtime.checkpoint_backend() {
            let unsettled = self.db().unsettled_checkpoints()?;
            if self.db().checkpoint_barrier_marked()? {
                warn!(
                    "the checkpoint barrier is outstanding and this backend has no checkpoints to inventory; allocation stays blocked until a clean inventory on a checkpoint backend clears it"
                );
                return Ok(true);
            }
            if unsettled.is_empty() {
                return Ok(false);
            }
            warn!(
                rows = unsettled.len(),
                "unsettled checkpoints exist but this backend has no checkpoints; their charges are kept and admission is blocked"
            );
            return Ok(true);
        }
        // Write-ahead: the obligation is durable, and allocation blocked, before the
        // pass can observe anything that blocks, so a crash at any point in the pass
        // leaves a restart that reconciles. A complete clean pass lets the caller clear it.
        {
            let _presence = self.presence();
            self.arm_barrier_locked(true)?;
        }
        let mut rows: BTreeMap<String, Checkpoint> = BTreeMap::new();
        let charged = self.db().unsettled_checkpoints()?.into_iter().chain(
            self.db()
                .checkpoint_expiry_rows()?
                .into_iter()
                .map(|(c, _)| c),
        );
        for c in charged {
            rows.entry(c.id.to_string()).or_insert(c);
        }
        let live = self.live_captures();
        let session = match self.checkpoint_session().await {
            Ok(s) => s,
            Err(e) => {
                // On, or with any durable state: storage no row names may exist.
                warn!(error = %e, "checkpoint reconciliation could not reach the helper; allocation blocked");
                return Ok(true);
            }
        };
        let mut blocked = false;
        let instance = self.db().identity()?.instance_id;
        let inventory = self
            .runtime
            .checkpoint(
                Some(session.epoch),
                CheckpointOperation::Inventory { instance },
                Instant::now() + HELPER_QUICK_TIMEOUT,
                &self.shutting_down.child_token(),
            )
            .await;
        match inventory {
            Ok(CheckpointResponse::Inventory(inv)) if inv.complete => {
                for entry in &inv.entries {
                    if !rows.contains_key(entry.checkpoint.as_str()) {
                        warn!(checkpoint = %entry.checkpoint, "checkpoint artifact no charged row explains; allocation blocked");
                        blocked = true;
                    }
                }
                if inv.unknown_entries != 0
                    || inv
                        .untracked_workers
                        .iter()
                        .any(|c| !rows.contains_key(c.as_str()))
                {
                    warn!(
                        "checkpoint entries or workers no charged row explains; allocation blocked"
                    );
                    blocked = true;
                }
                for t in &inv.tracked {
                    let fetched;
                    let row = match rows.get(t.checkpoint.as_str()) {
                        Some(row) => Some(row),
                        None => {
                            fetched = self.db().checkpoint(t.checkpoint.as_str())?;
                            fetched.as_ref()
                        }
                    };
                    if let Some(why) = self.unexplained(t, row, &live)? {
                        warn!(checkpoint = %t.checkpoint, why, "helper activity no row explains; allocation blocked");
                        blocked = true;
                    }
                }
            }
            other => {
                warn!(reply = ?other.map(|r| format!("{r:?}")), "checkpoint inventory incomplete or unavailable; allocation blocked");
                blocked = true;
            }
        }
        for c in rows.values() {
            // The clean rule: every charged row is sealed (READY, inspected below, or
            // QUARANTINED, design 10.2's verdict with its charge S kept) or a capture
            // this process is running. Any other charged row (CAPTURING dead or failed, DELETING
            // whatever its reason) has storage no removal has yet proved ABSENT, so the
            // barrier holds until that removal releases the row and a later pass is
            // clean. No failure token is read for this.
            let running = c.state == CheckpointState::Capturing
                && c.failure.is_none()
                && live.contains(c.id.as_str());
            if c.is_charged()
                && !running
                && !matches!(c.state, CheckpointState::Ready | CheckpointState::Quarantined)
            {
                warn!(checkpoint = %c.id, state = c.state.as_str(), "a checkpoint's storage is not yet proved absent; allocation blocked until its removal settles");
                blocked = true;
            }
            if !holds_its_source(c) || live.contains(c.id.as_str()) {
                continue;
            }
            if c.state == CheckpointState::Capturing && c.failure.is_none() {
                self.db().record_checkpoint_failure_token(
                    c.id.as_str(),
                    CheckpointReason::Io.token(),
                    "kilnd stopped during the capture; its storage is removed",
                    false,
                )?;
            }
            // Its source's removal waits for this capture's ABSENT: until then, block.
            let source = self.store.sandbox(&c.source_sandbox_id)?;
            if source.is_some_and(|s| s.state == SandboxState::Deleting) {
                warn!(checkpoint = %c.id, sandbox = %c.source_sandbox_id, "a source waits for its interrupted capture's removal; allocation blocked");
                blocked = true;
            }
        }
        for c in rows.values().filter(|c| c.state == CheckpointState::Ready) {
            let reply = self
                .runtime
                .checkpoint(
                    Some(session.epoch),
                    CheckpointOperation::Inspect {
                        target: c.target(),
                        verify: false,
                        operation: None,
                    },
                    Instant::now() + HELPER_QUICK_TIMEOUT,
                    &self.shutting_down.child_token(),
                )
                .await;
            // Only an authoritative answer is a verdict; I/O, a busy or withheld
            // artifact, a transport failure or an odd reply is unknown.
            let intact = match reply {
                Ok(CheckpointResponse::Inspected(view)) => match view.artifact {
                    ArtifactView::Published { record } => Ok(c.seal.as_ref().is_some_and(|seal| {
                        record.content_sha256 == seal.content_sha256
                            && record.binding_sha256 == seal.binding_sha256
                    })),
                    ArtifactView::Unreadable {
                        reason: Reason::Corrupt | Reason::GenerationMismatch,
                        ..
                    }
                    | ArtifactView::Partial { .. }
                    | ArtifactView::NotListed => Ok(false),
                    other => Err(format!("{other:?}")),
                },
                other => Err(format!("{:?}", other.map(|r| format!("{r:?}")))),
            };
            match intact {
                Ok(true) => {}
                Ok(false) => {
                    // The only quarantine: QUARANTINED is reached from a sealed READY
                    // row alone, never an unsealed capture, whose source hold
                    // (`holds_its_source`) covers only CAPTURING and DELETING.
                    debug_assert!(c.seal.is_some(), "quarantine of an unsealed row");
                    warn!(checkpoint = %c.id, "READY checkpoint's artifact is missing or does not match; quarantined, charge kept");
                    self.db().record_checkpoint_failure_token(
                        c.id.as_str(),
                        CheckpointReason::Corrupt.token(),
                        "the artifact is missing or does not match its seal",
                        true,
                    )?;
                }
                Err(reply) => {
                    warn!(checkpoint = %c.id, reply, "READY checkpoint's artifact could not be inspected; kept READY and charged, allocation blocked");
                    blocked = true;
                }
            }
        }
        Ok(blocked)
    }

    /// Why a tracked artifact's activity is not its row's, if it is not (design 10.2):
    /// the row must exist at its generation; a capture must be the CAPTURING row's own;
    /// a removal or tombstone needs a row being removed (a failed capture's included);
    /// every reader a live pin; a worker a charge.
    fn unexplained(
        &self,
        t: &TrackedArtifact,
        row: Option<&Checkpoint>,
        live: &HashSet<String>,
    ) -> Result<Option<&'static str>> {
        let Some(row) = row else {
            return Ok(Some("no row names it"));
        };
        if t.generation != row.generation {
            return Ok(Some("another generation"));
        }
        let charged = row.is_charged();
        let failing = row.state == CheckpointState::Capturing
            && (row.failure.is_some() || !live.contains(row.id.as_str()));
        let removing = failing
            || matches!(
                row.state,
                CheckpointState::Deleting | CheckpointState::Failed | CheckpointState::Deleted
            );
        let a = &t.activity;
        let why = match &a.exclusive {
            Some(ExclusiveOp {
                kind: OpKind::Capture,
                operation,
            }) if !(charged
                && row.state == CheckpointState::Capturing
                && *operation == row.capture.operation) =>
            {
                Some("a capture that is not its row's")
            }
            Some(ExclusiveOp {
                kind: OpKind::Remove,
                ..
            }) if !(charged && (failing || row.state == CheckpointState::Deleting)) => {
                Some("a removal of a row not being removed")
            }
            _ if a.tombstone.is_some() && !removing => {
                Some("a tombstone on a row not being removed")
            }
            _ if a.untracked_workers && !charged => Some("a worker of an uncharged row"),
            _ => None,
        };
        if why.is_some() || a.readers.is_empty() {
            return Ok(why);
        }
        let pins: HashSet<Id128> = self
            .db()
            .checkpoint_pins(row.id.as_str())?
            .into_iter()
            .filter(|p| p.released_at_ms.is_none())
            .map(|p| p.reader.operation)
            .collect();
        Ok(a.readers
            .iter()
            .any(|r| !pins.contains(r))
            .then_some("a reader no live pin names"))
    }
}

enum CaptureFailure {
    Failed(CheckpointReason, String),
    ShuttingDown,
}

fn not_removable(c: &Checkpoint) -> Error {
    Error::Internal(anyhow::anyhow!(
        "checkpoint {} is {} after its delete intent",
        c.id,
        c.state.as_str()
    ))
}

fn capture_key_conflict(request_id: &str) -> Error {
    Error::Refused(
        RefusalCode::AlreadyExists,
        Refusal::typed(
            "request_id_conflict",
            format!("request_id {request_id:?} was used for a different checkpoint request"),
        ),
    )
}

/// A recorded key's row as its retries see it. A CAPTURING row with no failure
/// recorded is still settling (or settles at the next start): in flight.
fn settled_capture(row: Checkpoint) -> Result<Checkpoint> {
    if row.state == CheckpointState::Capturing && row.failure.is_none() {
        return Err(CheckpointReason::InFlight.error(format!(
            "checkpoint {} is still capturing; retry to get its result",
            row.id
        )));
    }
    Ok(row)
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
