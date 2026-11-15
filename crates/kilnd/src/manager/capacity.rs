//! Checkpoint discovery, physical-capacity headroom and Health's checkpoint stats
//! (design `kilnd-checkpoint-fork` sections 6.3, 7 "Discovery" and Appendix A;
//! milestone C5b-2).
//!
//! **Discovery.** Every Health probe (cached like the rest of it) asks the root helper's
//! checkpoint Capabilities when `--enable-workspace-checkpoints` is on and the backend
//! has the checkpoint group (never Firecracker). `FEATURE_WORKSPACE_CHECKPOINT` is
//! listed only while that answer passes [`new_work`]: the group enabled; `supported`,
//! which the helper sets only when kiln grants leases, lists format 1, checks
//! generations on removal, runs is XFS with project quotas and kiln's image registry is
//! trustworthy; this daemon's format; and free space known on both runs and its loop
//! backing. A failed check, or a failed or late probe, withdraws only this feature
//! until a later probe passes. Admission never reads the cached bit: each capture and
//! fork asks the helper again and applies the same checks.
//!
//! **Headroom.** A capture (its R) or fork (its checkpoint's S) is admitted only if the
//! fresh answer's free space, the lesser of runs and its loop backing, covers
//! `--checkpoint-headroom-bytes` plus every charge admitted here whose bytes that
//! answer may not show, plus the new charge. Such charges are those still running and
//! those that settled after the answer was asked for (their writes may have happened
//! after the helper read). The check and the registration are one critical section,
//! with no await before the accepting transaction, so two admissions cannot both
//! spend the same free bytes.

use super::*;
use crate::checkpoint::wire::{CheckpointCapabilities, StorageFree};

/// A fresh Capabilities answer's verdict on new captures and forks: the helper session
/// and the free bytes it saw, or the typed reason new work is refused.
pub(super) fn new_work(caps: &CheckpointCapabilities) -> Result<(Session, u64)> {
    let session = session_of(caps)?;
    if caps.format_version != crate::checkpoint::FORMAT_VERSION {
        return Err(CheckpointReason::SandboxUnsupported.error(format!(
            "the root helper writes checkpoint format {}, this daemon reads {}",
            caps.format_version,
            crate::checkpoint::FORMAT_VERSION
        )));
    }
    match caps.storage {
        Some(StorageFree {
            runs_free_bytes,
            backing_free_bytes: Some(backing),
        }) => Ok((session, runs_free_bytes.min(backing))),
        _ => Err(CheckpointReason::Io
            .error("free space on the checkpoint filesystem or its loop backing is unknown")),
    }
}

/// The helper group's epoch and boot. A disabled group or an unsupported kiln or host
/// refuses before anything is reserved.
pub(super) fn session_of(caps: &CheckpointCapabilities) -> Result<Session> {
    match (caps.helper_epoch, caps.boot_id) {
        (Some(epoch), Some(boot)) if caps.enabled && caps.supported => Ok(Session { epoch, boot }),
        (Some(_), Some(_)) if caps.enabled => {
            Err(CheckpointReason::SandboxUnsupported.error(format!(
                "the installed kiln cannot capture: {}",
                caps.unsupported_reason.as_deref().unwrap_or("unsupported")
            )))
        }
        _ => Err(CheckpointReason::BackendUnsupported
            .error("the root helper's checkpoint group is disabled")),
    }
}

/// The helper session for maintenance: removal, the barrier's inventory pass and
/// interrupted-fork settlement, none of which starts new work (design 11: disablement
/// is not permission to strand charged objects). It needs the group, its epoch and a
/// kiln that lists format 1 and checks generations on removal, not new work's storage
/// probes or leases (C5b-2 adversarial review MEDIUM 1). An older helper does not say
/// (`removal_supported` false): then [`session_of`]'s broad gate, as before.
pub(super) fn maintenance_session(caps: &CheckpointCapabilities) -> Result<Session> {
    match (caps.helper_epoch, caps.boot_id) {
        (Some(epoch), Some(boot)) if caps.enabled && caps.removal_supported => {
            Ok(Session { epoch, boot })
        }
        _ => session_of(caps),
    }
}

/// What a fresh Capabilities answer allows a new capture or fork, with the headroom
/// sample it is checked against.
pub(in crate::manager) struct Admission<'a> {
    pub(in crate::manager) session: Session,
    free: u64,
    sample: Sample<'a>,
}

/// Charges this daemon admitted whose bytes a free-space answer may not show yet.
#[derive(Default)]
pub(super) struct Headroom {
    /// Moves at every settlement.
    seq: u64,
    next: u64,
    /// Admitted and not yet settled, by registration.
    live: HashMap<u64, u64>,
    /// Settled charges, at the `seq` they settled at, kept while a sample older than
    /// that is outstanding.
    settled: Vec<(u64, u64)>,
    /// Outstanding samples by the `seq` they were taken at.
    samples: BTreeMap<u64, usize>,
}

impl Headroom {
    fn prune(&mut self) {
        match self.samples.keys().next().copied() {
            Some(oldest) => self.settled.retain(|(at, _)| *at > oldest),
            None => self.settled.clear(),
        }
    }
}

/// A free-space answer in flight or held: registered before the helper is asked.
pub(super) struct Sample<'a> {
    engine: &'a CheckpointEngine,
    seq: u64,
}

impl Drop for Sample<'_> {
    fn drop(&mut self) {
        let mut h = self
            .engine
            .headroom
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = h.samples.get_mut(&self.seq) {
            *n -= 1;
            if *n == 0 {
                h.samples.remove(&self.seq);
            }
        }
        h.prune();
    }
}

/// An admitted charge, counted against headroom until its operation settles.
pub(in crate::manager) struct HeadroomCharge<'a> {
    engine: &'a CheckpointEngine,
    id: u64,
}

impl Drop for HeadroomCharge<'_> {
    fn drop(&mut self) {
        let mut h = self
            .engine
            .headroom
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(charge) = h.live.remove(&self.id) {
            h.seq += 1;
            let at = h.seq;
            h.settled.push((at, charge));
            h.prune();
        }
    }
}

impl CheckpointEngine {
    fn sample(&self) -> Sample<'_> {
        let mut h = self.headroom.lock().unwrap_or_else(|e| e.into_inner());
        let seq = h.seq;
        *h.samples.entry(seq).or_insert(0) += 1;
        Sample { engine: self, seq }
    }
}

impl<'a> Admission<'a> {
    /// Design 6.3: admits `charge` against this answer's free space, or refuses
    /// `checkpoint_quota`. Call with no await before the accepting transaction; the
    /// returned charge must live until the operation settles.
    pub(in crate::manager) fn admit(
        &self,
        headroom: u64,
        charge: u64,
    ) -> Result<HeadroomCharge<'a>> {
        let engine = self.sample.engine;
        let mut h = engine.headroom.lock().unwrap_or_else(|e| e.into_inner());
        let pending = h
            .live
            .values()
            .chain(
                h.settled
                    .iter()
                    .filter(|(at, _)| *at > self.sample.seq)
                    .map(|(_, c)| c),
            )
            .fold(0u64, |sum, c| sum.saturating_add(*c));
        let need = headroom.saturating_add(pending).saturating_add(charge);
        if self.free < need {
            return Err(CheckpointReason::Quota.error(format!(
                "not enough free space for checkpoints: {} free, {headroom} headroom + {pending} admitted + {charge} requested",
                self.free
            )));
        }
        h.next += 1;
        let id = h.next;
        h.live.insert(id, charge);
        Ok(HeadroomCharge { engine, id })
    }
}

impl<R: Runtime> Manager<R> {
    /// Checkpoint discovery for the Health probe: `None` unless enabled on a backend
    /// with checkpoints; otherwise whether new work passes [`new_work`], or why not.
    pub(in crate::manager) async fn checkpoint_discovery(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Option<std::result::Result<(), String>> {
        self.limits.checkpoints.as_ref()?;
        if !self.runtime.checkpoint_backend() {
            return None;
        }
        Some(match self.checkpoint_caps(deadline, cancel).await {
            Ok(caps) => {
                self.checkpoint
                    .cleanup_busy
                    .store(u64::from(caps.cleanup_workers_busy), Ordering::Relaxed);
                new_work(&caps).map(|_| ()).map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        })
    }

    /// The helper's checkpoint Capabilities, asked now.
    pub(in crate::manager) async fn checkpoint_caps(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Box<CheckpointCapabilities>> {
        let what = "root helper checkpoint capabilities";
        match self
            .runtime
            .checkpoint(None, CheckpointOperation::Capabilities, deadline, cancel)
            .await
            .map_err(|e| helper_unavailable(what, e))?
        {
            CheckpointResponse::Capabilities(caps) => Ok(caps),
            other => Err(helper_unavailable(
                what,
                format!("unexpected reply {other:?}"),
            )),
        }
    }

    /// A new capture's or fork's fresh helper answer (lead ruling: never the cached
    /// Health bit), its headroom sample registered before the helper is asked.
    pub(in crate::manager) async fn admission_probe(&self) -> Result<Admission<'_>> {
        let sample = self.checkpoint.sample();
        let caps = self
            .checkpoint_caps(
                Instant::now() + HELPER_QUICK_TIMEOUT,
                &self.shutting_down.child_token(),
            )
            .await?;
        let (session, free) = new_work(&caps)?;
        Ok(Admission {
            session,
            free,
            sample,
        })
    }

    /// Health's `CheckpointStats` and `checkpoint_reserved_disk_bytes` (design Appendix
    /// A), for `caller` (the peer uid, root's own included). `None` with the feature
    /// off and nothing durable: Health then reads no checkpoint state at all.
    pub fn checkpoint_stats(&self, caller: Option<u32>) -> Result<Option<CheckpointStats>> {
        if !self.maintained() {
            return Ok(None);
        }
        let limits = self.maintenance_limits();
        let b = &limits.budgets;
        let usage = self.db().checkpoint_usage(caller.unwrap_or(0))?;
        let mine = if caller.is_some() {
            usage.uid
        } else {
            Default::default()
        };
        let (workers, caller_workers) = {
            let w = self
                .checkpoint
                .workers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let caller_workers = caller.and_then(|uid| w.1.get(&uid).copied()).unwrap_or(0);
            (w.0, caller_workers)
        };
        let enabled = self.limits.checkpoints.is_some();
        Ok(Some(CheckpointStats {
            max_count: b.max_node,
            current_count: usage.node.live,
            max_count_per_uid: b.max_per_uid,
            caller_count: mine.live,
            max_bytes: b.max_bytes_node,
            reserved_bytes: usage.node.charged_bytes,
            max_bytes_per_uid: b.max_bytes_per_uid,
            caller_reserved_bytes: mine.charged_bytes,
            max_workers: limits.max_workers as u64,
            current_workers: workers as u64,
            max_workers_per_uid: limits.max_workers_per_uid as u64,
            caller_workers: caller_workers as u64,
            pending_deletes: self.db().checkpoint_pending_deletes()?,
            rejected_captures: self.checkpoint.rejected_captures.load(Ordering::Relaxed),
            rejected_forks: self.checkpoint.rejected_forks.load(Ordering::Relaxed),
            max_records: b.max_records_node,
            current_records: usage.node.records,
            max_records_per_uid: b.max_records_per_uid,
            caller_records: mine.records,
            max_request_records: b.max_request_records_node,
            request_records: usage.node.keys,
            max_request_records_per_uid: b.max_request_records_per_uid,
            caller_request_records: mine.keys,
            max_cleanup_workers: limits.cleanup_workers as u64,
            current_cleanup_workers: if enabled {
                self.checkpoint.cleanup_busy.load(Ordering::Relaxed)
            } else {
                0
            },
            expired: self.checkpoint.expired.load(Ordering::Relaxed),
        }))
    }
}

/// Health's checkpoint stats (design Appendix A `CheckpointStats`, plus `expired`).
/// Count and bytes include charged partial, quarantined and deleting checkpoints;
/// records include terminal history; rejections and expirations count since startup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointStats {
    pub max_count: u64,
    pub current_count: u64,
    pub max_count_per_uid: u64,
    pub caller_count: u64,
    pub max_bytes: u64,
    pub reserved_bytes: u64,
    pub max_bytes_per_uid: u64,
    pub caller_reserved_bytes: u64,
    pub max_workers: u64,
    pub current_workers: u64,
    pub max_workers_per_uid: u64,
    pub caller_workers: u64,
    pub pending_deletes: u64,
    pub rejected_captures: u64,
    pub rejected_forks: u64,
    pub max_records: u64,
    pub current_records: u64,
    pub max_records_per_uid: u64,
    pub caller_records: u64,
    pub max_request_records: u64,
    pub request_records: u64,
    pub max_request_records_per_uid: u64,
    pub caller_request_records: u64,
    pub max_cleanup_workers: u64,
    /// The helper's busy cleanup workers at the latest discovery probe.
    pub current_cleanup_workers: u64,
    pub expired: u64,
}
