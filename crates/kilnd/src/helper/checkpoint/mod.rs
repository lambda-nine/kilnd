//! The root helper's checkpoint group (milestone C3; design sections 4.1-4.3, 8.3, 10
//! and 10.1). It supervises kiln's capture, restore, inspection and removal workers and
//! certifies what happened to one artifact as [`Evidence`].
//!
//! The rules it enforces, whatever the daemon asks:
//! - **Admission without queues.** Two copy slots (capture, restore, verification) and
//!   two cleanup slots (removal, inspection, inventory). A full lane refuses at once;
//!   cleanup never waits for copying.
//! - **One writer or many readers per artifact.** A capture is exclusive; restores and
//!   inspections are reader leases, each until its worker is reaped.
//! - **Supervision is not the waiter.** Admitted capture, restore and removal run in
//!   tasks the node owns. A waiter's deadline or disconnect only detaches it: the slot,
//!   lease and outcome stay with the node until the worker is reaped, and an unkillable
//!   worker keeps them forever.
//! - **Tombstones.** A removal first tombstones the artifact: nothing can capture,
//!   restore or publish it again in this epoch. It cancels every worker, waits for each
//!   reap, and only then removes. A capture that settles after the tombstone is never
//!   COMPLETE, even if its worker exited 0.
//! - **Epochs.** Each helper process has a fresh epoch; a request for another is refused
//!   first. Workers die with their helper (parent-death SIGKILL), and before certifying
//!   absence the node scans the process table for any process still naming the
//!   artifact, so an earlier epoch's straggler, or root's own command, blocks it.
//! - **Retirement.** An operation nonce is unique for the epoch: a settled one replays
//!   its reply, and inspecting an unknown one retires it, so a delayed request can never
//!   start after the daemon was told it had not.
use crate::checkpoint::{
    ArtifactRecord, ArtifactTarget, CaptureBinding, CheckpointId, CompleteFact, CopyOutcome,
    Evidence, Fact, Reason, SealedEvidence, bounded_detail, parse_failure,
};
use crate::helper::protocol::*;
use crate::model::{Digest, Id128, SandboxSpec};
use crate::process::{Finish, KilnArgs, Outcome};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub mod kiln;
use kiln::{
    CHECKPOINT_FAILED, CREATE_PREFLIGHT_FAILED, create_reason, exit_code, named_artifact,
    parse_inventory, parse_removed, success_stdout,
};
pub use kiln::{KilnWorkers, ProcessArgs, Workers};

/// Design 6.2: two capture and restore workers per node.
pub const COPY_WORKERS: usize = 2;
/// Design 6.2: a separate cleanup lane of two.
pub const CLEANUP_WORKERS: usize = 2;
/// Artifacts this epoch tracks at once (live operations, readers and tombstones).
pub const MAX_TRACKED: usize = crate::checkpoint::MAX_TRACKED_ARTIFACTS;
/// Settled and retired operation nonces kept for replay.
pub const MAX_SETTLED: usize = 4096;
/// Entries one inventory reply lists; more is an incomplete inventory.
pub const MAX_INVENTORY: usize = crate::checkpoint::MAX_INVENTORY_ENTRIES;
/// Design 10.1: a tombstone outlives its last worker by at least the 300-second
/// maximum request validity, and an acknowledged record is kept as long.
pub const TOMBSTONE_QUIET: Duration = Duration::from_secs(300);
/// Records the daemon never acknowledged are dropped after an hour. Losing one only
/// costs the daemon a retry (removal is idempotent) or a retained pin.
pub const UNACKED_RETENTION: Duration = Duration::from_secs(3600);
/// A worker killed at its deadline is reaped and settled within this.
const SETTLE_GRACE: Duration = Duration::from_secs(2);
/// `kiln create`'s own ceiling, as for an ordinary create.
const CREATE_CEILING: Duration = Duration::from_secs(120);

type Key = (Id128, CheckpointId);

fn key(target: &ArtifactTarget) -> Key {
    (target.instance, target.checkpoint.clone())
}

struct Exclusive {
    operation: Id128,
    cancel: CancellationToken,
}

struct Tombstone {
    operation: Id128,
    /// When its last worker was reaped and its removal settled.
    quiet_since: Option<Instant>,
    acked: bool,
}

struct Artifact {
    generation: u64,
    capture: Option<Exclusive>,
    removing: Option<Id128>,
    readers: BTreeMap<Id128, CancellationToken>,
    tombstone: Option<Tombstone>,
}

impl Artifact {
    fn idle(&self) -> bool {
        self.capture.is_none() && self.readers.is_empty() && self.removing.is_none()
    }

    fn activity(&self, untracked: bool) -> Activity {
        let exclusive = match (&self.capture, self.removing) {
            (Some(capture), _) => Some(ExclusiveOp {
                kind: OpKind::Capture,
                operation: capture.operation,
            }),
            (None, Some(operation)) => Some(ExclusiveOp {
                kind: OpKind::Remove,
                operation,
            }),
            (None, None) => None,
        };
        Activity {
            exclusive,
            readers: self.readers.keys().copied().collect(),
            tombstone: self.tombstone.as_ref().map(|t| t.operation),
            untracked_workers: untracked,
        }
    }
}

struct Settled {
    key: Key,
    /// `None`: retired by an inspection, never started.
    reply: Option<CheckpointResponse>,
    at: Instant,
    acked: bool,
}

#[derive(Default)]
struct State {
    artifacts: HashMap<Key, Artifact>,
    settled: HashMap<Id128, Settled>,
    /// Admitted capture, restore and removal nonces, until they settle.
    active: HashMap<Id128, Key>,
}

impl State {
    fn prune(&mut self, now: Instant) {
        let expired = |at: Instant, acked: bool| {
            let age = now.saturating_duration_since(at);
            (acked && age >= TOMBSTONE_QUIET) || age >= UNACKED_RETENTION
        };
        self.settled.retain(|_, s| !expired(s.at, s.acked));
        self.artifacts.retain(|_, a| {
            !a.idle()
                || match &a.tombstone {
                    None => false,
                    Some(t) => !t.quiet_since.is_some_and(|q| expired(q, t.acked)),
                }
        });
    }

    /// The artifact's entry, created on first use, refusing another generation while
    /// this epoch tracks it. That is only a fast refusal: idle entries are pruned and a
    /// new epoch starts empty, so the binding is kiln's own check of the generation
    /// recorded in the artifact (inspect's record, and generation-checked removal).
    fn artifact(&mut self, target: &ArtifactTarget) -> Result<&mut Artifact, CheckpointError> {
        let tracked = self.artifacts.len();
        let artifact = match self.artifacts.entry(key(target)) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(_) if tracked >= MAX_TRACKED => {
                return Err(CheckpointError::new(
                    CheckpointErrorKind::Capacity,
                    "the helper tracks its maximum number of artifacts",
                ));
            }
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(Artifact {
                generation: target.generation,
                capture: None,
                removing: None,
                readers: BTreeMap::new(),
                tombstone: None,
            }),
        };
        if artifact.generation != target.generation {
            return Err(CheckpointError::new(
                CheckpointErrorKind::Conflict,
                "another generation of this checkpoint",
            ));
        }
        Ok(artifact)
    }

    /// A nonce already used in this epoch: its settled reply, a join, or a conflict.
    fn prior(&self, nonce: Id128, key: &Key) -> Option<Prior> {
        if let Some(settled) = self.settled.get(&nonce) {
            return Some(match &settled.reply {
                Some(reply) if settled.key == *key => Prior::Replay(reply.clone()),
                _ => Prior::Refused(CheckpointError::new(
                    CheckpointErrorKind::Conflict,
                    "this operation nonce was retired or names another artifact",
                )),
            });
        }
        match self.active.get(&nonce) {
            Some(active) if active == key => Some(Prior::Join),
            Some(_) => Some(Prior::Refused(CheckpointError::new(
                CheckpointErrorKind::Conflict,
                "this operation nonce names another artifact",
            ))),
            None => None,
        }
    }

    fn room_for_operation(&self) -> Result<(), CheckpointError> {
        if self.settled.len() + self.active.len() >= MAX_SETTLED {
            return Err(CheckpointError::new(
                CheckpointErrorKind::Capacity,
                "the helper holds its maximum number of unacknowledged operations",
            ));
        }
        Ok(())
    }

    /// Settles one operation. A tombstoned artifact whose last worker this was starts
    /// its quiet period now.
    fn settle(&mut self, nonce: Id128, key: Key, reply: CheckpointResponse) {
        if let Some(artifact) = self.artifacts.get_mut(&key)
            && artifact.idle()
            && let Some(tombstone) = &mut artifact.tombstone
        {
            tombstone.quiet_since.get_or_insert_with(Instant::now);
        }
        self.active.remove(&nonce);
        self.settled.insert(
            nonce,
            Settled {
                key,
                reply: Some(reply),
                at: Instant::now(),
                acked: false,
            },
        );
    }
}

enum Prior {
    Replay(CheckpointResponse),
    Join,
    Refused(CheckpointError),
}

pub struct Node {
    epoch: Id128,
    boot_id: Id128,
    workers: Arc<dyn Workers>,
    copy: Arc<Semaphore>,
    cleanup: Arc<Semaphore>,
    state: Mutex<State>,
    changed: Notify,
    tasks: TaskTracker,
    shutdown: CancellationToken,
}

fn error(kind: CheckpointErrorKind, message: &str) -> CheckpointResponse {
    CheckpointResponse::Error(CheckpointError::new(kind, message))
}

/// This boot's identity, the kernel's boot ID read beneath the private procfs instance.
/// Elsewhere (unit tests on a development Mac only) a random one.
fn boot_id() -> io::Result<Id128> {
    #[cfg(target_os = "linux")]
    {
        let text = crate::sys::procfs::boot_id()?;
        Id128::parse(&text.trim().replace('-', "")).map_err(io::Error::other)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(Id128::random())
}

impl Node {
    pub fn new(workers: Arc<dyn Workers>) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            epoch: Id128::random(),
            boot_id: boot_id()?,
            workers,
            copy: Arc::new(Semaphore::new(COPY_WORKERS)),
            cleanup: Arc::new(Semaphore::new(CLEANUP_WORKERS)),
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            tasks: TaskTracker::new(),
            shutdown: CancellationToken::new(),
        }))
    }

    pub fn epoch(&self) -> Id128 {
        self.epoch
    }

    /// Cancels every worker and waits until each was reaped.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune(Instant::now());
        state
    }

    fn evidence(&self, target: &ArtifactTarget, operation: Id128, fact: Fact) -> SealedEvidence {
        Evidence {
            version: crate::checkpoint::EVIDENCE_VERSION,
            instance: target.instance,
            checkpoint: target.checkpoint.clone(),
            generation: target.generation,
            operation,
            helper_epoch: self.epoch,
            boot_id: self.boot_id,
            fact,
        }
        .seal()
        // Every field is bounded far below 16 KiB: an image name is at most 128 bytes.
        .expect("checkpoint evidence fits its bound")
    }

    pub async fn handle(
        self: &Arc<Self>,
        request: CheckpointRequest,
        deadline: Instant,
        waiter: &CancellationToken,
    ) -> CheckpointResponse {
        if request
            .helper_epoch
            .is_some_and(|epoch| epoch != self.epoch)
        {
            return error(
                CheckpointErrorKind::StaleEpoch,
                "the request names another helper epoch",
            );
        }
        match request.operation {
            CheckpointOperation::Capabilities => self.capabilities(deadline).await,
            CheckpointOperation::Capture { binding } => {
                self.capture(binding, deadline, waiter).await
            }
            CheckpointOperation::Restore {
                target,
                content_sha256,
                reader,
                spec,
            } => {
                self.restore(target, content_sha256, reader, spec, deadline, waiter)
                    .await
            }
            CheckpointOperation::Inspect {
                target,
                verify,
                operation,
            } => self.inspect(target, verify, operation, deadline).await,
            CheckpointOperation::Remove { target, operation } => {
                self.remove(target, operation, deadline, waiter).await
            }
            CheckpointOperation::Inventory { instance } => self.inventory(instance, deadline).await,
            CheckpointOperation::Acknowledge { target, operation } => {
                self.acknowledge(&target, operation)
            }
        }
    }

    /// Waits for an admitted operation's settlement, at most until the wire deadline
    /// and its kill-and-reap grace, or until the waiter leaves.
    async fn settled(
        &self,
        nonce: Id128,
        deadline: Instant,
        waiter: &CancellationToken,
        pending: CheckpointResponse,
    ) -> CheckpointResponse {
        let until = deadline + SETTLE_GRACE;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(reply) = self
                .lock()
                .settled
                .get(&nonce)
                .and_then(|s| s.reply.clone())
            {
                return reply;
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(until) => return pending,
                () = waiter.cancelled() => return pending,
            }
        }
    }

    // --- Capture ------------------------------------------------------------------

    async fn capture(
        self: &Arc<Self>,
        binding: CaptureBinding,
        deadline: Instant,
        waiter: &CancellationToken,
    ) -> CheckpointResponse {
        let nonce = binding.operation;
        let pending = CheckpointResponse::Captured(Box::new(CaptureReply::Pending));
        let admitted = (|| {
            let mut state = self.lock();
            let key = key(&binding.target);
            match state.prior(nonce, &key) {
                Some(Prior::Replay(reply)) => return Err(reply),
                Some(Prior::Join) => return Ok(None),
                Some(Prior::Refused(e)) => return Err(CheckpointResponse::Error(e)),
                None => {}
            }
            state
                .room_for_operation()
                .map_err(CheckpointResponse::Error)?;
            let artifact = state
                .artifact(&binding.target)
                .map_err(CheckpointResponse::Error)?;
            if artifact.tombstone.is_some() {
                return Err(error(
                    CheckpointErrorKind::Conflict,
                    "this checkpoint is being or was removed",
                ));
            }
            if !artifact.idle() {
                return Err(error(
                    CheckpointErrorKind::Busy,
                    "another operation holds this checkpoint",
                ));
            }
            let permit = self.copy.clone().try_acquire_owned().map_err(|_| {
                error(
                    CheckpointErrorKind::Workers,
                    "every capture and restore worker is busy",
                )
            })?;
            let cancel = self.shutdown.child_token();
            artifact.capture = Some(Exclusive {
                operation: nonce,
                cancel: cancel.clone(),
            });
            state.active.insert(nonce, key);
            Ok(Some((permit, cancel)))
        })();
        match admitted {
            Err(reply) => return reply,
            Ok(None) => {}
            Ok(Some((permit, cancel))) => {
                let node = self.clone();
                let binding = binding.clone();
                self.tasks.spawn(async move {
                    node.run_capture(binding, permit, cancel, deadline).await;
                });
            }
        }
        self.settled(nonce, deadline, waiter, pending).await
    }

    async fn run_capture(
        &self,
        binding: CaptureBinding,
        permit: OwnedSemaphorePermit,
        cancel: CancellationToken,
        deadline: Instant,
    ) {
        let target = &binding.target;
        let outcome = match KilnArgs::checkpoint_capture(
            &target.instance.to_string(),
            target.checkpoint.as_str(),
            target.generation,
            binding.limit_bytes,
            &binding.source,
        ) {
            Ok(args) => self.workers.run(args, deadline, cancel.clone()).await,
            Err(e) => Err(e),
        };
        // Reaped: the slot is free again.
        drop(permit);
        let mut state = self.lock();
        // Under the lock that a removal takes to tombstone: a removal that began first
        // has canceled this token, and nothing it sees afterwards can be COMPLETE.
        let reply = if cancel.is_cancelled() {
            CaptureReply::Failed {
                reason: Reason::Io,
                detail: "the capture was canceled by a removal or shutdown".into(),
            }
        } else {
            self.capture_reply(&binding, outcome)
        };
        let key = key(target);
        if let Some(artifact) = state.artifacts.get_mut(&key) {
            artifact.capture = None;
        }
        state.settle(
            binding.operation,
            key,
            CheckpointResponse::Captured(Box::new(reply)),
        );
        drop(state);
        self.changed.notify_waiters();
    }

    fn capture_reply(
        &self,
        binding: &CaptureBinding,
        outcome: io::Result<Outcome>,
    ) -> CaptureReply {
        let failed = |detail: &str| CaptureReply::Failed {
            reason: Reason::Io,
            detail: detail.into(),
        };
        let out = match outcome {
            Ok(out) => out,
            Err(_) => return failed("the capture worker could not be started"),
        };
        match exit_code(&out) {
            Some(0) => {
                let Some(record) = success_stdout(&out).and_then(|t| ArtifactRecord::parse(t).ok())
                else {
                    return failed("the capture worker printed no valid record");
                };
                if !record.names(&binding.target) || record.limit_bytes != binding.limit_bytes {
                    return failed("the capture record does not match its binding");
                }
                let fact = CompleteFact {
                    source: binding.source.clone(),
                    content_sha256: record.content_sha256,
                    binding_sha256: record.binding_sha256,
                    image: record.image,
                    image_sha256: record.image_sha256,
                    entries: record.entries,
                    logical_bytes: record.logical_bytes,
                    allocated_bytes: record.allocated_bytes,
                    charge_bytes: record.charge_bytes,
                    limit_bytes: record.limit_bytes,
                };
                CaptureReply::Complete {
                    evidence: self.evidence(
                        &binding.target,
                        binding.operation,
                        Fact::Complete(Box::new(fact)),
                    ),
                }
            }
            Some(CHECKPOINT_FAILED) => match std::str::from_utf8(&out.stdout.data)
                .ok()
                .and_then(|t| parse_failure(t).ok())
            {
                Some((reason, detail)) => CaptureReply::Failed { reason, detail },
                None => failed("the capture worker failed without a valid failure record"),
            },
            _ => match out.finish {
                Finish::TimedOut => failed("the capture deadline expired; the worker was killed"),
                Finish::Canceled => failed("the capture was canceled; the worker was killed"),
                Finish::Exited(_) => failed("the capture worker ended abnormally"),
            },
        }
    }

    // --- Restore ------------------------------------------------------------------

    async fn restore(
        self: &Arc<Self>,
        target: ArtifactTarget,
        content: Digest,
        reader: Id128,
        spec: SandboxSpec,
        deadline: Instant,
        waiter: &CancellationToken,
    ) -> CheckpointResponse {
        let pending = CheckpointResponse::Restored(Box::new(RestoreReply::Pending));
        let admitted = (|| {
            let mut state = self.lock();
            let key = key(&target);
            match state.prior(reader, &key) {
                Some(Prior::Replay(reply)) => return Err(reply),
                Some(Prior::Join) => return Ok(None),
                Some(Prior::Refused(e)) => return Err(CheckpointResponse::Error(e)),
                None => {}
            }
            state
                .room_for_operation()
                .map_err(CheckpointResponse::Error)?;
            let artifact = state.artifact(&target).map_err(CheckpointResponse::Error)?;
            if artifact.tombstone.is_some() {
                return Err(error(
                    CheckpointErrorKind::Conflict,
                    "this checkpoint is being or was removed",
                ));
            }
            if artifact.capture.is_some() {
                return Err(error(
                    CheckpointErrorKind::Busy,
                    "a capture holds this checkpoint",
                ));
            }
            let permit = self.copy.clone().try_acquire_owned().map_err(|_| {
                error(
                    CheckpointErrorKind::Workers,
                    "every capture and restore worker is busy",
                )
            })?;
            let cancel = self.shutdown.child_token();
            artifact.readers.insert(reader, cancel.clone());
            state.active.insert(reader, key);
            Ok(Some((permit, cancel)))
        })();
        match admitted {
            Err(reply) => return reply,
            Ok(None) => {}
            Ok(Some((permit, cancel))) => {
                let node = self.clone();
                let target = target.clone();
                self.tasks.spawn(async move {
                    let reply = node
                        .run_restore(&target, content, reader, &spec, cancel, deadline)
                        .await;
                    drop(permit);
                    let mut state = node.lock();
                    let key = key(&target);
                    if let Some(artifact) = state.artifacts.get_mut(&key) {
                        artifact.readers.remove(&reader);
                    }
                    state.settle(reader, key, CheckpointResponse::Restored(Box::new(reply)));
                    drop(state);
                    node.changed.notify_waiters();
                });
            }
        }
        self.settled(reader, deadline, waiter, pending).await
    }

    /// The restore reader: check the artifact is the daemon's, then `kiln create`.
    /// Returns once every worker it started was reaped.
    async fn run_restore(
        &self,
        target: &ArtifactTarget,
        content: Digest,
        reader: Id128,
        spec: &SandboxSpec,
        cancel: CancellationToken,
        deadline: Instant,
    ) -> RestoreReply {
        let ended = |copy| self.evidence(target, reader, Fact::ReaderEnded { copy });
        let not_created = |reason, detail: &str| RestoreReply::NotCreated {
            reason,
            detail: detail.into(),
            evidence: ended(CopyOutcome::NotStarted),
        };
        let instance = target.instance.to_string();
        let inspected = match self
            .inspect_published(target, false, &cancel, deadline)
            .await
        {
            Ok(record) => record,
            Err((reason, detail)) => return not_created(reason, &detail),
        };
        if inspected.content_sha256 != content {
            return not_created(
                Reason::Corrupt,
                "the artifact's content digest is not the checkpoint's",
            );
        }
        if cancel.is_cancelled() {
            return not_created(Reason::Busy, "the restore was canceled before kiln create");
        }
        let args =
            match KilnArgs::create_from_checkpoint(spec, &instance, target.checkpoint.as_str()) {
                Ok(args) => args,
                Err(_) => return not_created(Reason::InvalidRequest, "invalid restore arguments"),
            };
        let out = match self
            .workers
            .run(args, deadline.min(Instant::now() + CREATE_CEILING), cancel)
            .await
        {
            Ok(out) => out,
            // The runner failed before or at spawn: kiln never ran.
            Err(_) => return not_created(Reason::Io, "kiln create could not be started"),
        };
        let detail = bounded_detail(&String::from_utf8_lossy(&out.stderr.data));
        match exit_code(&out) {
            Some(0) => {
                let id = success_stdout(&out)
                    .unwrap_or_default()
                    .trim_end_matches('\n');
                if crate::runtime::kiln_direct::valid_kiln_id(id) && !id.contains('\n') {
                    return RestoreReply::Created {
                        backend_id: id.to_string(),
                        evidence: ended(CopyOutcome::Complete),
                    };
                }
            }
            // Before allocation and before the shim's fork: nothing read the artifact
            // after the CLI's own preflight, and the CLI is reaped.
            Some(CREATE_PREFLIGHT_FAILED) if out.stdout.total_bytes == 0 => {
                return RestoreReply::NotCreated {
                    reason: create_reason(&out.stderr.data).unwrap_or(Reason::InvalidRequest),
                    detail,
                    evidence: ended(CopyOutcome::NotStarted),
                };
            }
            _ => {}
        }
        RestoreReply::Ambiguous {
            reason: create_reason(&out.stderr.data).unwrap_or(Reason::Io),
            detail,
            evidence: ended(CopyOutcome::Unknown),
        }
    }

    /// `kiln checkpoint inspect` of one published artifact, which must be this
    /// generation.
    async fn inspect_published(
        &self,
        target: &ArtifactTarget,
        verify: bool,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<ArtifactRecord, (Reason, String)> {
        let args = KilnArgs::checkpoint_inspect(
            &target.instance.to_string(),
            target.checkpoint.as_str(),
            verify,
        )
        .map_err(|_| {
            (
                Reason::InvalidRequest,
                "invalid inspect arguments".to_string(),
            )
        })?;
        let out = self
            .workers
            .run(args, deadline, cancel.clone())
            .await
            .map_err(|_| {
                (
                    Reason::Io,
                    "kiln checkpoint inspect could not be started".into(),
                )
            })?;
        match exit_code(&out) {
            Some(0) => {
                let record = success_stdout(&out)
                    .and_then(|t| ArtifactRecord::parse(t).ok())
                    .ok_or((Reason::Io, "kiln printed no valid record".to_string()))?;
                if !record.names(target) {
                    return Err((
                        Reason::Corrupt,
                        "the artifact is another generation or checkpoint".into(),
                    ));
                }
                Ok(record)
            }
            Some(CHECKPOINT_FAILED) => Err(std::str::from_utf8(&out.stdout.data)
                .ok()
                .and_then(|t| parse_failure(t).ok())
                .unwrap_or((Reason::Io, "malformed failure record".into()))),
            _ => Err((Reason::Io, "kiln checkpoint inspect did not finish".into())),
        }
    }

    // --- Removal ------------------------------------------------------------------

    async fn remove(
        self: &Arc<Self>,
        target: ArtifactTarget,
        nonce: Id128,
        deadline: Instant,
        waiter: &CancellationToken,
    ) -> CheckpointResponse {
        let pending = CheckpointResponse::Removed(Box::new(RemoveReply::Pending));
        let admitted = (|| {
            let mut state = self.lock();
            let key = key(&target);
            match state.prior(nonce, &key) {
                Some(Prior::Replay(reply)) => return Err(reply),
                Some(Prior::Join) => return Ok(None),
                Some(Prior::Refused(e)) => return Err(CheckpointResponse::Error(e)),
                None => {}
            }
            state
                .room_for_operation()
                .map_err(CheckpointResponse::Error)?;
            // Whether this epoch knew the artifact. If it didn't, nothing of it runs here,
            // and a removal kiln refuses as another generation takes its tombstone back.
            let fresh = !state.artifacts.contains_key(&key);
            let artifact = state.artifact(&target).map_err(CheckpointResponse::Error)?;
            if artifact.removing.is_some() {
                return Err(error(
                    CheckpointErrorKind::Busy,
                    "another removal of this checkpoint is running",
                ));
            }
            // Like every lane, cleanup refuses at once when full, before any state
            // changes. The slot is held until the removal settles.
            let Ok(slot) = self.cleanup.clone().try_acquire_owned() else {
                return Err(error(
                    CheckpointErrorKind::Workers,
                    "every cleanup worker is busy",
                ));
            };
            let artifact = state
                .artifacts
                .get_mut(&key)
                .expect("the artifact entry was just made");
            // D1: the tombstone first, then cancellation. From here nothing can start
            // on this artifact, and a capture settling later is never COMPLETE.
            artifact.tombstone = Some(Tombstone {
                operation: nonce,
                quiet_since: None,
                acked: false,
            });
            if let Some(capture) = &artifact.capture {
                capture.cancel.cancel();
            }
            for cancel in artifact.readers.values() {
                cancel.cancel();
            }
            artifact.removing = Some(nonce);
            state.active.insert(nonce, key);
            Ok(Some((slot, fresh)))
        })();
        match admitted {
            Err(reply) => return reply,
            Ok(None) => {}
            Ok(Some((slot, fresh))) => {
                let node = self.clone();
                let target = target.clone();
                self.tasks.spawn(async move {
                    let reply = node.run_remove(&target, nonce, deadline).await;
                    // Held through cancellation, every reap, kiln's removal, the listing
                    // and the process table.
                    drop(slot);
                    let mut state = node.lock();
                    let key = key(&target);
                    let mismatch = matches!(
                        reply,
                        RemoveReply::Retained {
                            reason: Reason::GenerationMismatch,
                            ..
                        }
                    );
                    if let Some(artifact) = state.artifacts.get_mut(&key) {
                        artifact.removing = None;
                        // The name holds another generation, untouched: this removal's
                        // tombstone would only block that generation's own operations.
                        if mismatch && fresh {
                            artifact.tombstone = None;
                        }
                    }
                    state.settle(nonce, key, CheckpointResponse::Removed(Box::new(reply)));
                    drop(state);
                    node.changed.notify_waiters();
                });
            }
        }
        self.settled(nonce, deadline, waiter, pending).await
    }

    /// D2: wait for every worker's reap, then exact removal and the absence checks.
    async fn run_remove(
        &self,
        target: &ArtifactTarget,
        nonce: Id128,
        deadline: Instant,
    ) -> RemoveReply {
        let retained = |reason, detail: &str| RemoveReply::Retained {
            reason,
            detail: detail.into(),
        };
        let key = key(target);
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let busy = self
                .lock()
                .artifacts
                .get(&key)
                .is_some_and(|a| a.capture.is_some() || !a.readers.is_empty());
            if !busy {
                break;
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline) => {
                    return retained(Reason::Busy, "a worker of this checkpoint has not been reaped");
                }
            }
        }
        let cancel = self.shutdown.child_token();
        let instance = target.instance.to_string();
        // kiln checks the generation under the artifact's exclusive lock: the helper's
        // memory of it is only a fast refusal, never the binding.
        let Ok(args) =
            KilnArgs::checkpoint_rm(&instance, target.checkpoint.as_str(), target.generation)
        else {
            return retained(Reason::InvalidRequest, "invalid removal arguments");
        };
        let existed = match self.workers.run(args, deadline, cancel.clone()).await {
            Ok(out) => match exit_code(&out) {
                Some(0) => match success_stdout(&out).map(parse_removed) {
                    Some(Ok(existed)) => existed,
                    _ => return retained(Reason::Io, "kiln printed no valid removal record"),
                },
                Some(CHECKPOINT_FAILED) => {
                    let (reason, detail) = std::str::from_utf8(&out.stdout.data)
                        .ok()
                        .and_then(|t| parse_failure(t).ok())
                        .unwrap_or((Reason::Io, "malformed failure record".into()));
                    return RemoveReply::Retained { reason, detail };
                }
                // An older kiln refuses `--generation` as a usage error, removing nothing.
                Some(_) => {
                    return retained(
                        Reason::Io,
                        "kiln checkpoint rm refused its arguments (a kiln without generation-checked removal?)",
                    );
                }
                None => return retained(Reason::Io, "kiln checkpoint rm did not finish"),
            },
            Err(_) => return retained(Reason::Io, "kiln checkpoint rm could not be started"),
        };
        // The namespace must list nothing of this generation: no artifact, and no
        // staging or removal whose name doesn't prove another generation.
        match self.listing(&cancel, deadline).await {
            Ok(lines)
                if lines.iter().any(|l| {
                    l.instance == Some(target.instance)
                        && l.checkpoint().as_ref() == Some(&target.checkpoint)
                        && l.generation().is_none_or(|g| g == target.generation)
                }) =>
            {
                return retained(Reason::Io, "the namespace still lists this checkpoint");
            }
            Ok(_) => {}
            Err(detail) => return retained(Reason::Io, &detail),
        }
        // Every worker this epoch started for it is reaped; any process still naming
        // it is an earlier epoch's or root's own, whose lifetime nothing here bounds.
        match self.untracked(Some(&key)) {
            Ok(names) if names.is_empty() => {}
            Ok(_) => {
                return retained(
                    Reason::Busy,
                    "a process this helper did not start names this checkpoint",
                );
            }
            Err(_) => return retained(Reason::Io, "the process table could not be read"),
        }
        RemoveReply::Absent {
            evidence: self.evidence(target, nonce, Fact::Absent { existed }),
        }
    }

    async fn listing(
        &self,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Vec<kiln::InventoryLine>, String> {
        let out = self
            .workers
            .run(KilnArgs::checkpoint_ls(), deadline, cancel.clone())
            .await
            .map_err(|_| "kiln checkpoint ls could not be started".to_string())?;
        let text = success_stdout(&out).ok_or("kiln checkpoint ls did not finish")?;
        parse_inventory(text)
    }

    /// Artifacts named by live processes this epoch is not running a worker for (all
    /// of them when `only` is set, since its workers were reaped), deduplicated.
    fn untracked(&self, only: Option<&Key>) -> io::Result<Vec<Key>> {
        let processes = self.workers.processes()?;
        let state = self.lock();
        let mut out: Vec<Key> = Vec::new();
        for process in &processes {
            let Some((instance, checkpoint)) = named_artifact(process) else {
                continue;
            };
            let (Ok(instance), Ok(checkpoint)) =
                (Id128::parse(&instance), CheckpointId::parse(&checkpoint))
            else {
                continue;
            };
            let named = (instance, checkpoint);
            let ours = state.artifacts.get(&named).is_some_and(|a| !a.idle());
            let wanted = match only {
                Some(only) => *only == named,
                None => !ours,
            };
            if wanted && !out.contains(&named) {
                out.push(named);
            }
        }
        Ok(out)
    }

    // --- Inspection, inventory and acknowledgment ---------------------------------

    async fn inspect(
        self: &Arc<Self>,
        target: ArtifactTarget,
        verify: bool,
        operation: Option<Id128>,
        deadline: Instant,
    ) -> CheckpointResponse {
        let key = key(&target);
        let untracked = match self.untracked(None) {
            Ok(names) => names.contains(&key),
            Err(_) => true,
        };
        let lane = if verify { &self.copy } else { &self.cleanup };
        // A reader lease for this inspection, unless the artifact is held.
        let lease = {
            let mut state = self.lock();
            let operation = match operation {
                None => None,
                Some(nonce) => Some(match state.prior(nonce, &key) {
                    Some(Prior::Replay(reply)) => OperationState::Settled(Box::new(reply)),
                    Some(Prior::Join) => OperationState::Active,
                    Some(Prior::Refused(_)) => OperationState::Retired,
                    None => {
                        if let Err(e) = state.room_for_operation() {
                            return CheckpointResponse::Error(e);
                        }
                        state.settled.insert(
                            nonce,
                            Settled {
                                key: key.clone(),
                                reply: None,
                                at: Instant::now(),
                                acked: false,
                            },
                        );
                        OperationState::Retired
                    }
                }),
            };
            let artifact = match state.artifact(&target) {
                Ok(artifact) => artifact,
                Err(e) => return CheckpointResponse::Error(e),
            };
            if artifact.tombstone.is_some() || artifact.capture.is_some() {
                let reply = ArtifactInspectReply {
                    helper_epoch: self.epoch,
                    artifact: ArtifactView::Withheld,
                    activity: artifact.activity(untracked),
                    operation,
                };
                return CheckpointResponse::Inspected(Box::new(reply));
            }
            let Ok(slot) = lane.clone().try_acquire_owned() else {
                return error(CheckpointErrorKind::Workers, "no inspection worker is free");
            };
            let lease = Id128::random();
            let cancel = self.shutdown.child_token();
            artifact.readers.insert(lease, cancel.clone());
            ReaderLease {
                node: self.clone(),
                key: key.clone(),
                lease,
                cancel,
                operation,
                _slot: slot,
            }
        };
        let view = self.view(&target, verify, &lease.cancel, deadline).await;
        let activity = {
            let mut state = self.lock();
            state
                .artifacts
                .get_mut(&key)
                .map(|a| {
                    a.readers.remove(&lease.lease);
                    a.activity(untracked)
                })
                .unwrap_or_default()
        };
        let reply = ArtifactInspectReply {
            helper_epoch: self.epoch,
            artifact: view,
            activity,
            operation: lease.operation.clone(),
        };
        drop(lease);
        CheckpointResponse::Inspected(Box::new(reply))
    }

    async fn view(
        &self,
        target: &ArtifactTarget,
        verify: bool,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> ArtifactView {
        let lines = match self.listing(cancel, deadline).await {
            Ok(lines) => lines,
            Err(detail) => {
                return ArtifactView::Unreadable {
                    reason: Reason::Io,
                    detail,
                };
            }
        };
        let (mut published, mut staging, mut removing) = (false, 0u32, 0u32);
        for line in &lines {
            if line.instance != Some(target.instance)
                || line.checkpoint().as_ref() != Some(&target.checkpoint)
            {
                continue;
            }
            match line.kind {
                Some(ItemKind::Published) => published = true,
                Some(ItemKind::Staging) => staging = staging.saturating_add(1),
                Some(ItemKind::Removing) => removing = removing.saturating_add(1),
                None => {}
            }
        }
        if !published {
            return if staging + removing > 0 {
                ArtifactView::Partial { staging, removing }
            } else {
                ArtifactView::NotListed
            };
        }
        match self
            .inspect_published(target, verify, cancel, deadline)
            .await
        {
            Ok(record) => ArtifactView::Published { record },
            Err((reason, detail)) => ArtifactView::Unreadable { reason, detail },
        }
    }

    async fn inventory(self: &Arc<Self>, instance: Id128, deadline: Instant) -> CheckpointResponse {
        let Ok(_slot) = self.cleanup.clone().try_acquire_owned() else {
            return error(CheckpointErrorKind::Workers, "no inventory worker is free");
        };
        let cancel = self.shutdown.child_token();
        let mut reply = InventoryReply {
            helper_epoch: self.epoch,
            complete: true,
            incomplete_reason: None,
            entries: Vec::new(),
            unknown_entries: 0,
            other_entries: 0,
            tracked: Vec::new(),
            untracked_workers: Vec::new(),
        };
        fn incomplete(reply: &mut InventoryReply, why: &str) {
            reply.complete = false;
            reply
                .incomplete_reason
                .get_or_insert_with(|| why.to_string());
        }
        match self.listing(&cancel, deadline).await {
            Err(detail) => incomplete(&mut reply, &detail),
            Ok(lines) => {
                for line in lines {
                    match (
                        line.instance == Some(instance),
                        line.checkpoint(),
                        line.kind,
                    ) {
                        (true, Some(checkpoint), Some(kind)) => {
                            if reply.entries.len() < MAX_INVENTORY {
                                reply.entries.push(InventoryEntry { checkpoint, kind });
                            } else {
                                incomplete(&mut reply, "more entries than one inventory lists");
                            }
                        }
                        (true, _, _) => {
                            reply.unknown_entries = reply.unknown_entries.saturating_add(1)
                        }
                        (false, _, _) => {
                            reply.other_entries = reply.other_entries.saturating_add(1)
                        }
                    }
                }
            }
        }
        match self.untracked(None) {
            Ok(names) => {
                reply.untracked_workers = names
                    .into_iter()
                    .filter(|(i, _)| *i == instance)
                    .map(|(_, c)| c)
                    .collect();
                if !reply.untracked_workers.is_empty() {
                    incomplete(
                        &mut reply,
                        "a process this helper did not start names an artifact",
                    );
                }
            }
            Err(_) => incomplete(&mut reply, "the process table could not be read"),
        }
        let state = self.lock();
        let mut tracked: Vec<_> = state
            .artifacts
            .iter()
            .filter(|((i, _), _)| *i == instance)
            .map(|((_, checkpoint), artifact)| TrackedArtifact {
                checkpoint: checkpoint.clone(),
                generation: artifact.generation,
                activity: artifact.activity(reply.untracked_workers.contains(checkpoint)),
            })
            .collect();
        tracked.sort_by(|a, b| a.checkpoint.cmp(&b.checkpoint));
        reply.tracked = tracked;
        reply
            .entries
            .sort_by(|a, b| a.checkpoint.cmp(&b.checkpoint));
        CheckpointResponse::Inventory(Box::new(reply))
    }

    fn acknowledge(&self, target: &ArtifactTarget, operation: Id128) -> CheckpointResponse {
        let mut state = self.lock();
        let key = key(target);
        if let Some(settled) = state.settled.get_mut(&operation)
            && settled.key == key
        {
            settled.acked = true;
        }
        if let Some(tombstone) = state
            .artifacts
            .get_mut(&key)
            .and_then(|a| a.tombstone.as_mut())
            && tombstone.operation == operation
        {
            tombstone.acked = true;
        }
        CheckpointResponse::Acknowledged
    }

    async fn capabilities(&self, deadline: Instant) -> CheckpointResponse {
        let support = self
            .workers
            .support(deadline, self.shutdown.child_token())
            .await;
        let untracked = self.untracked(None).map(|n| n.len()).unwrap_or(usize::MAX);
        let busy = |lane: &Semaphore, total: usize| (total - lane.available_permits()) as u32;
        CheckpointResponse::Capabilities(Box::new(CheckpointCapabilities {
            group_version: crate::checkpoint::GROUP_VERSION,
            enabled: true,
            helper_epoch: Some(self.epoch),
            boot_id: Some(self.boot_id),
            format_version: crate::checkpoint::FORMAT_VERSION,
            supported: support.is_ok(),
            unsupported_reason: support.err(),
            limits: limits(),
            copy_workers_busy: busy(&self.copy, COPY_WORKERS),
            cleanup_workers_busy: busy(&self.cleanup, CLEANUP_WORKERS),
            untracked_workers: u32::try_from(untracked).unwrap_or(u32::MAX),
        }))
    }
}

/// An inspection's reader lease: released when dropped, even if the request is.
struct ReaderLease {
    node: Arc<Node>,
    key: Key,
    lease: Id128,
    cancel: CancellationToken,
    operation: Option<OperationState>,
    _slot: OwnedSemaphorePermit,
}

impl Drop for ReaderLease {
    fn drop(&mut self) {
        let mut state = self.node.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(artifact) = state.artifacts.get_mut(&self.key) {
            artifact.readers.remove(&self.lease);
        }
        drop(state);
        self.node.changed.notify_waiters();
    }
}

pub fn limits() -> HelperLimits {
    HelperLimits {
        copy_workers: COPY_WORKERS as u32,
        cleanup_workers: CLEANUP_WORKERS as u32,
        max_tracked_artifacts: MAX_TRACKED as u32,
        max_settled_operations: MAX_SETTLED as u32,
        max_inventory_entries: MAX_INVENTORY as u32,
        helper_ceiling_ms: crate::checkpoint::HELPER_CEILING_MS,
        tombstone_quiet_ms: TOMBSTONE_QUIET.as_millis() as u64,
    }
}

/// The group's answer when root has not enabled it: Capabilities says so, and every
/// other operation is refused.
pub fn disabled(operation: &CheckpointOperation) -> CheckpointResponse {
    match operation {
        CheckpointOperation::Capabilities => {
            CheckpointResponse::Capabilities(Box::new(CheckpointCapabilities {
                group_version: crate::checkpoint::GROUP_VERSION,
                enabled: false,
                helper_epoch: None,
                boot_id: None,
                format_version: crate::checkpoint::FORMAT_VERSION,
                supported: false,
                unsupported_reason: Some("checkpoints are disabled on this helper".into()),
                limits: limits(),
                copy_workers_busy: 0,
                cleanup_workers_busy: 0,
                untracked_workers: 0,
            }))
        }
        _ => error(
            CheckpointErrorKind::Disabled,
            "checkpoints are disabled on this helper",
        ),
    }
}

#[cfg(test)]
mod tests;
