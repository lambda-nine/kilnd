//! Non-waiting resource admission. Permits follow the resource owner.
//!
//! Ingress fairness (Phase 1b B7, B6-BI-03). Connections and ordinary RPCs are shared
//! by every principal the socket's filesystem gate lets in, so each budget is split:
//!
//! - **Connections.** `reserved_connections` of the `max_connections` slots are held
//!   back from the general pool. A connection takes a general slot while its UID holds
//!   fewer than `max_connections_per_uid` of them; otherwise it may take one reserved
//!   slot (at most one per UID), and that connection then serves only Health and the
//!   cleanup RPCs (`GetSandbox`, `DeleteSandbox`). The UID is the kernel's
//!   `SO_PEERCRED` answer, read once at accept; a connection whose credentials are
//!   unavailable shares one bucket with every other such connection. The reserve is
//!   first-come and bounded per UID, not per caller: UIDs that collude can hold all of
//!   it (the threat model accepts colluding UIDs filling shared capacity).
//! - **Root.** Beyond `max_connections`, one more slot only UID 0 may take, once the
//!   general and reserved slots refuse it, and one RPC permit only UID 0 may use for
//!   Health, `GetSandbox` and `DeleteSandbox` once their own lanes refuse it. So the
//!   operator can always reach Health and cleanup (B7 milestone 2, MEDIUM-2).
//! - **RPCs.** Health keeps its own reserved lane. An ordinary RPC needs a global
//!   permit and its UID's share (`max_concurrent_rpcs_per_uid`). A cleanup RPC tries
//!   the ordinary lane first and, when that is full or its UID's share is spent, one
//!   permit of the cleanup lane (`max_concurrent_cleanup`, at most one per UID).
//!
//! [`validate_ingress`] holds the invariants that make these shares fair; kilnd refuses
//! to start without them (B7 milestone 2, HIGH-2).
//!
//! The server also drops a connection that has not sent the HTTP/2 client preface
//! within `connection_preface_timeout`, releasing its slot (`server.rs`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::manager::Limits;

/// A UID's share in one lane. `None` is the one bucket for connections whose peer
/// credentials were unavailable.
pub type ShareKey = Option<u32>;

/// The kernel's UID for root, the only caller of the root slot and the root RPC permit.
const ROOT: ShareKey = Some(0);

/// Reserved connection slots one UID may hold.
pub const RESERVED_CONNECTIONS_PER_UID: usize = 1;

/// B7 milestone 2 (HIGH-2): the ingress flag invariants. Without them one UID could
/// hold every connection slot, or every ordinary RPC, and starve every other UID's
/// fresh Health and cleanup connections. kilnd refuses to start on a violation; the
/// error names the flags.
///
/// - `--reserved-connections` is at least 1 and below `--max-connections`;
/// - `--max-connections-per-uid` is below the general pool
///   (`--max-connections` minus `--reserved-connections`);
/// - `--max-connections-per-uid` plus one UID's reserved allowance is below
///   `--max-connections`;
/// - `--max-concurrent-rpcs-per-uid` is below `--max-concurrent-rpcs`;
/// - `--max-concurrent-cleanup` is at least 1.
pub fn validate_ingress(limits: &Limits) -> Result<(), String> {
    let (total, reserved, per_uid) = (
        limits.max_connections,
        limits.reserved_connections,
        limits.max_connections_per_uid,
    );
    if reserved < 1 {
        return Err("--reserved-connections must be at least 1, so Health and cleanup always have a held-back slot".into());
    }
    if reserved >= total {
        return Err(format!(
            "--reserved-connections ({reserved}) must be below --max-connections ({total})"
        ));
    }
    let general = total - reserved;
    if per_uid >= general {
        return Err(format!(
            "--max-connections-per-uid ({per_uid}) must be below the general connection slots \
             (--max-connections {total} - --reserved-connections {reserved} = {general}), \
             so no one UID holds every general slot"
        ));
    }
    if per_uid.saturating_add(RESERVED_CONNECTIONS_PER_UID) >= total {
        return Err(format!(
            "--max-connections-per-uid ({per_uid}) plus one UID's {RESERVED_CONNECTIONS_PER_UID} \
             reserved slot must be below --max-connections ({total})"
        ));
    }
    if limits.max_concurrent_rpcs_per_uid >= limits.max_concurrent_rpcs {
        return Err(format!(
            "--max-concurrent-rpcs-per-uid ({}) must be below --max-concurrent-rpcs ({}), \
             so no one UID holds every ordinary RPC",
            limits.max_concurrent_rpcs_per_uid, limits.max_concurrent_rpcs
        ));
    }
    if limits.max_concurrent_cleanup < 1 {
        return Err("--max-concurrent-cleanup must be at least 1".into());
    }
    Ok(())
}

struct Budget {
    max: usize,
    permits: Arc<Semaphore>,
    rejected: AtomicU64,
}

impl Budget {
    fn new(max: usize) -> Self {
        assert!(
            max <= Semaphore::MAX_PERMITS,
            "admission capacity exceeds semaphore range"
        );
        Self {
            max,
            permits: Arc::new(Semaphore::new(max)),
            rejected: AtomicU64::new(0),
        }
    }

    fn acquire(&self, count: u32) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.permits
            .clone()
            .try_acquire_many_owned(count)
            .inspect_err(|_| {
                self.rejected.fetch_add(1, Ordering::Relaxed);
            })
    }

    fn current(&self) -> usize {
        self.max - self.permits.available_permits()
    }

    fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            max: u64::try_from(self.max).expect("capacity fits u64"),
            current: u64::try_from(self.current()).expect("usage fits u64"),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}

/// One budget split into per-UID shares: a permit needs both a global permit and room
/// in its key's share. Counting rejections is the caller's, since a request may fall
/// through to another lane.
struct Lane {
    max: usize,
    per_key: usize,
    permits: Arc<Semaphore>,
    held: Arc<Mutex<HashMap<ShareKey, usize>>>,
}

/// Why a lane refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The key already holds its whole share.
    Share,
    /// The lane has no global permit left.
    Global,
}

impl Lane {
    fn new(max: usize, per_key: usize) -> Self {
        assert!(
            max <= Semaphore::MAX_PERMITS,
            "admission capacity exceeds semaphore range"
        );
        Self {
            max,
            per_key: per_key.min(max),
            permits: Arc::new(Semaphore::new(max)),
            held: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn try_acquire(&self, key: ShareKey) -> Result<SharedPermit, Refusal> {
        // The map lock orders every share check with its increment, so two callers of
        // one key cannot both take the last unit of its share.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.get(&key).copied().unwrap_or(0);
        if count >= self.per_key {
            return Err(Refusal::Share);
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refusal::Global)?;
        held.insert(key, count + 1);
        Ok(SharedPermit {
            _permit: permit,
            held: self.held.clone(),
            key,
        })
    }

    fn current(&self) -> usize {
        self.max - self.permits.available_permits()
    }

    fn held_by(&self, key: ShareKey) -> usize {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .copied()
            .unwrap_or(0)
    }
}

/// A global permit and one unit of a key's share; dropping it returns both.
pub struct SharedPermit {
    _permit: OwnedSemaphorePermit,
    held: Arc<Mutex<HashMap<ShareKey, usize>>>,
    key: ShareKey,
}

impl Drop for SharedPermit {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

/// Which connection slot a connection holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionLane {
    /// Any RPC.
    General,
    /// A held-back slot: Health and the cleanup RPCs only.
    Reserved,
    /// The one slot beyond `max_connections` that only UID 0 may hold: Health and the
    /// cleanup RPCs only.
    Root,
}

impl ConnectionLane {
    /// Whether this connection serves only Health, `GetSandbox` and `DeleteSandbox`.
    pub fn health_and_cleanup_only(self) -> bool {
        self != Self::General
    }
}

/// What a connection's slot holds: a lane permit with its UID's share, or the root slot.
enum ConnectionSlot {
    Shared { _permit: SharedPermit },
    Root { _permit: OwnedSemaphorePermit },
}

/// A connection's slot, held for the connection's life.
pub struct ConnectionPermit {
    lane: ConnectionLane,
    _slot: ConnectionSlot,
}

impl ConnectionPermit {
    fn shared(lane: ConnectionLane, permit: SharedPermit) -> Self {
        Self {
            lane,
            _slot: ConnectionSlot::Shared { _permit: permit },
        }
    }

    pub fn lane(&self) -> ConnectionLane {
        self.lane
    }
}

/// What an RPC is, for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcClass {
    /// Create, List, Exec and GetExecution.
    Ordinary,
    /// GetSandbox and DeleteSandbox: the calls a caller needs to observe and clean up,
    /// which may fall back to the cleanup lane.
    Cleanup,
}

/// An admitted RPC's permit; dropping it releases the lane and the share.
pub enum RpcPermit {
    Shared(SharedPermit),
    Health(OwnedSemaphorePermit),
    /// UID 0's own Health or cleanup permit, once the shared lanes refuse it.
    Root(OwnedSemaphorePermit),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub max: u64,
    pub current: u64,
    pub rejected: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    /// Every connection slot, general and reserved.
    pub connections: BudgetSnapshot,
    /// The held-back Health and cleanup slots (part of `connections`).
    pub reserved_connections: BudgetSnapshot,
    /// UID 0's own slot, beyond `connections`.
    pub root_connection: BudgetSnapshot,
    /// Connections refused because their UID held its whole general share and a
    /// reserved slot already (part of `connections.rejected`).
    pub rejected_connection_shares: u64,
    /// Ordinary RPC permits, including cleanup RPCs admitted there.
    pub rpcs: BudgetSnapshot,
    /// RPCs refused for their UID's ordinary share (part of `rpcs.rejected`).
    pub rejected_rpc_shares: u64,
    /// The cleanup lane, used once the ordinary lane refuses a cleanup RPC.
    pub cleanup: BudgetSnapshot,
    pub health: BudgetSnapshot,
    /// UID 0's own Health and cleanup RPC permit.
    pub root_rpc: BudgetSnapshot,
    pub execs: BudgetSnapshot,
    pub stdin: BudgetSnapshot,
    pub max_queued_execs_per_sandbox: u64,
    pub rejected_sandbox_execs: u64,
}

pub struct Admission {
    general_connections: Lane,
    reserved_connections: Lane,
    root_connection: Budget,
    rejected_connections: AtomicU64,
    rejected_reserved: AtomicU64,
    rejected_connection_shares: AtomicU64,
    rpcs: Lane,
    rejected_rpcs: AtomicU64,
    rejected_rpc_shares: AtomicU64,
    cleanup: Lane,
    rejected_cleanup: AtomicU64,
    health: Budget,
    root_rpc: Budget,
    execs: Budget,
    stdin: Budget,
    max_queued_execs_per_sandbox: usize,
    rejected_sandbox_execs: AtomicU64,
}

/// The reserved Health and cleanup connection slots this budget holds back: the
/// configured count, but always leaving one general slot (and none of a one-slot
/// budget, which only unit tests build; the CLI requires at least two).
fn reserved_slots(limits: &Limits) -> usize {
    limits
        .reserved_connections
        .min(limits.max_connections.saturating_sub(1))
}

impl Admission {
    pub fn new(limits: &Limits) -> Self {
        u32::try_from(limits.max_queued_exec_stdin_bytes)
            .expect("aggregate stdin capacity fits u32");
        let reserved = reserved_slots(limits);
        let general = limits.max_connections - reserved;
        Self {
            general_connections: Lane::new(general, limits.max_connections_per_uid.max(1)),
            reserved_connections: Lane::new(reserved, RESERVED_CONNECTIONS_PER_UID),
            root_connection: Budget::new(1),
            rejected_connections: AtomicU64::new(0),
            rejected_reserved: AtomicU64::new(0),
            rejected_connection_shares: AtomicU64::new(0),
            rpcs: Lane::new(
                limits.max_concurrent_rpcs,
                limits.max_concurrent_rpcs_per_uid.max(1),
            ),
            rejected_rpcs: AtomicU64::new(0),
            rejected_rpc_shares: AtomicU64::new(0),
            cleanup: Lane::new(limits.max_concurrent_cleanup, 1),
            rejected_cleanup: AtomicU64::new(0),
            health: Budget::new(limits.max_concurrent_health),
            root_rpc: Budget::new(1),
            execs: Budget::new(limits.max_concurrent_execs),
            stdin: Budget::new(limits.max_queued_exec_stdin_bytes),
            max_queued_execs_per_sandbox: limits.max_queued_execs_per_sandbox,
            rejected_sandbox_execs: AtomicU64::new(0),
        }
    }

    /// A connection slot for `uid`: a general one within its share, else one reserved
    /// Health and cleanup slot, else (UID 0 only) the root slot, else none (the server
    /// closes the socket).
    pub fn try_connection(&self, uid: ShareKey) -> Result<ConnectionPermit, TryAcquireError> {
        let general = match self.general_connections.try_acquire(uid) {
            Ok(permit) => return Ok(ConnectionPermit::shared(ConnectionLane::General, permit)),
            Err(refusal) => refusal,
        };
        let reserved = match self.reserved_connections.try_acquire(uid) {
            Ok(permit) => return Ok(ConnectionPermit::shared(ConnectionLane::Reserved, permit)),
            Err(refusal) => refusal,
        };
        if uid == ROOT
            && let Ok(permit) = self.root_connection.acquire(1)
        {
            return Ok(ConnectionPermit {
                lane: ConnectionLane::Root,
                _slot: ConnectionSlot::Root { _permit: permit },
            });
        }
        self.rejected_connections.fetch_add(1, Ordering::Relaxed);
        if reserved == Refusal::Global {
            self.rejected_reserved.fetch_add(1, Ordering::Relaxed);
        }
        if general == Refusal::Share {
            self.rejected_connection_shares
                .fetch_add(1, Ordering::Relaxed);
        }
        Err(TryAcquireError::NoPermits)
    }

    /// Health's own reserved lane, shared by every caller; once it is full, UID 0's
    /// root permit.
    pub fn try_health(&self, uid: ShareKey) -> Result<RpcPermit, TryAcquireError> {
        match self.health.acquire(1) {
            Ok(permit) => Ok(RpcPermit::Health(permit)),
            Err(_) if uid == ROOT => self.root_rpc.acquire(1).map(RpcPermit::Root),
            Err(error) => Err(error),
        }
    }

    /// An ordinary or cleanup RPC for `uid`.
    pub fn try_rpc(&self, class: RpcClass, uid: ShareKey) -> Result<RpcPermit, TryAcquireError> {
        let ordinary = match self.rpcs.try_acquire(uid) {
            Ok(permit) => return Ok(RpcPermit::Shared(permit)),
            Err(refusal) => refusal,
        };
        if class == RpcClass::Cleanup
            && let Ok(permit) = self.cleanup.try_acquire(uid)
        {
            return Ok(RpcPermit::Shared(permit));
        }
        if class == RpcClass::Cleanup
            && uid == ROOT
            && let Ok(permit) = self.root_rpc.acquire(1)
        {
            return Ok(RpcPermit::Root(permit));
        }
        self.rejected_rpcs.fetch_add(1, Ordering::Relaxed);
        if ordinary == Refusal::Share {
            self.rejected_rpc_shares.fetch_add(1, Ordering::Relaxed);
        }
        if class == RpcClass::Cleanup {
            self.rejected_cleanup.fetch_add(1, Ordering::Relaxed);
        }
        Err(TryAcquireError::NoPermits)
    }

    pub fn try_exec(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.execs.acquire(1)
    }

    pub fn try_stdin(&self, bytes: usize) -> Result<Option<OwnedSemaphorePermit>, TryAcquireError> {
        if bytes == 0 {
            return Ok(None);
        }
        let Ok(count) = u32::try_from(bytes) else {
            self.stdin.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(TryAcquireError::NoPermits);
        };
        self.stdin.acquire(count).map(Some)
    }

    pub fn reject_sandbox_exec(&self) {
        self.rejected_sandbox_execs.fetch_add(1, Ordering::Relaxed);
    }

    /// Connection slots `uid` holds now, general and reserved.
    pub fn connections_held_by(&self, uid: ShareKey) -> (usize, usize) {
        (
            self.general_connections.held_by(uid),
            self.reserved_connections.held_by(uid),
        )
    }

    pub fn snapshot(&self) -> AdmissionSnapshot {
        let count = |n: usize| u64::try_from(n).expect("count fits u64");
        let max = self.general_connections.max + self.reserved_connections.max;
        AdmissionSnapshot {
            connections: BudgetSnapshot {
                max: count(max),
                current: count(
                    self.general_connections.current() + self.reserved_connections.current(),
                ),
                rejected: self.rejected_connections.load(Ordering::Relaxed),
            },
            reserved_connections: BudgetSnapshot {
                max: count(self.reserved_connections.max),
                current: count(self.reserved_connections.current()),
                rejected: self.rejected_reserved.load(Ordering::Relaxed),
            },
            root_connection: self.root_connection.snapshot(),
            rejected_connection_shares: self.rejected_connection_shares.load(Ordering::Relaxed),
            rpcs: BudgetSnapshot {
                max: count(self.rpcs.max),
                current: count(self.rpcs.current()),
                rejected: self.rejected_rpcs.load(Ordering::Relaxed),
            },
            rejected_rpc_shares: self.rejected_rpc_shares.load(Ordering::Relaxed),
            cleanup: BudgetSnapshot {
                max: count(self.cleanup.max),
                current: count(self.cleanup.current()),
                rejected: self.rejected_cleanup.load(Ordering::Relaxed),
            },
            health: self.health.snapshot(),
            root_rpc: self.root_rpc.snapshot(),
            execs: self.execs.snapshot(),
            stdin: self.stdin.snapshot(),
            max_queued_execs_per_sandbox: count(self.max_queued_execs_per_sandbox),
            rejected_sandbox_execs: self.rejected_sandbox_execs.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_reject_without_waiting_and_release_on_drop() {
        let admission = Arc::new(Admission::new(&Limits {
            max_connections: 1,
            max_concurrent_rpcs: 1,
            max_concurrent_health: 1,
            max_concurrent_cleanup: 1,
            max_concurrent_execs: 1,
            max_queued_exec_stdin_bytes: 3,
            ..Limits::default()
        }));
        let shared = admission.clone();
        let connection = shared.try_connection(Some(7)).unwrap();
        assert_eq!(connection.lane(), ConnectionLane::General);
        let rpc = shared.try_rpc(RpcClass::Ordinary, Some(7)).unwrap();
        let health = shared.try_health(Some(7)).unwrap();
        let exec = shared.try_exec().unwrap();
        let stdin = shared.try_stdin(3).unwrap();
        assert!(admission.try_stdin(0).unwrap().is_none());
        assert!(admission.try_connection(Some(7)).is_err());
        assert!(admission.try_rpc(RpcClass::Ordinary, Some(7)).is_err());
        assert!(admission.try_health(Some(7)).is_err());
        assert!(admission.try_exec().is_err());
        assert!(admission.try_stdin(1).is_err());
        let snapshot = admission.snapshot();
        for budget in [
            snapshot.connections,
            snapshot.rpcs,
            snapshot.health,
            snapshot.execs,
        ] {
            assert_eq!(
                budget,
                BudgetSnapshot {
                    max: 1,
                    current: 1,
                    rejected: 1
                }
            );
        }
        // A one-slot budget holds nothing back.
        assert_eq!(snapshot.reserved_connections.max, 0);
        assert_eq!(
            snapshot.stdin,
            BudgetSnapshot {
                max: 3,
                current: 3,
                rejected: 1
            }
        );
        drop((connection, rpc, health, exec, stdin));
        let snapshot = admission.snapshot();
        assert_eq!(
            (
                snapshot.connections.current,
                snapshot.rpcs.current,
                snapshot.health.current,
                snapshot.execs.current,
                snapshot.stdin.current
            ),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(admission.connections_held_by(Some(7)), (0, 0));
        assert!(admission.try_connection(Some(7)).is_ok());
        assert!(admission.try_stdin(3).is_ok());
        assert!(admission.try_stdin(usize::MAX).is_err());
        assert_eq!(admission.snapshot().stdin.rejected, 2);
        admission.reject_sandbox_exec();
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.max_queued_execs_per_sandbox, 8);
        assert_eq!(snapshot.rejected_sandbox_execs, 1);
    }

    /// B6-BI-03: one UID holding every connection it can still leaves general slots and
    /// the reserved Health/cleanup slots to every other UID; the reserved slot takes at
    /// most one connection per UID, and unknown credentials share one bucket.
    #[test]
    fn b7_one_uid_cannot_exhaust_connections() {
        let admission = Admission::new(&Limits {
            max_connections: 8,
            reserved_connections: 2,
            max_connections_per_uid: 3,
            ..Limits::default()
        });
        let hostile = Some(1000);
        let mut held = Vec::new();
        for _ in 0..64 {
            if let Ok(permit) = admission.try_connection(hostile) {
                held.push(permit);
            }
        }
        let lanes: Vec<_> = held.iter().map(ConnectionPermit::lane).collect();
        assert_eq!(
            lanes,
            [
                ConnectionLane::General,
                ConnectionLane::General,
                ConnectionLane::General,
                ConnectionLane::Reserved
            ]
        );
        assert_eq!(admission.connections_held_by(hostile), (3, 1));
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.connections.current, 4);
        assert_eq!(snapshot.connections.rejected, 60);
        assert_eq!(snapshot.rejected_connection_shares, 60);
        // Another UID still gets general slots up to the pool, then the last reserved one.
        let victim = Some(0);
        let a = admission.try_connection(victim).unwrap();
        let b = admission.try_connection(victim).unwrap();
        let c = admission.try_connection(victim).unwrap();
        assert_eq!(
            [a.lane(), b.lane(), c.lane()],
            [
                ConnectionLane::General,
                ConnectionLane::General,
                ConnectionLane::General
            ]
        );
        let reserved = admission.try_connection(None).unwrap();
        assert_eq!(reserved.lane(), ConnectionLane::Reserved);
        // Everything is held now: general by shares, reserved by two UIDs.
        assert!(admission.try_connection(Some(5)).is_err());
        assert_eq!(admission.snapshot().reserved_connections.rejected, 1);
        drop(held);
        assert_eq!(admission.connections_held_by(hostile), (0, 0));
        assert_eq!(
            admission.try_connection(Some(5)).unwrap().lane(),
            ConnectionLane::General
        );
    }

    /// B6-BI-03: a UID's ordinary RPCs stop at its share while another UID's proceed;
    /// a cleanup RPC falls back to the cleanup lane, one per UID.
    #[test]
    fn b7_rpc_shares_and_the_cleanup_lane() {
        let admission = Admission::new(&Limits {
            max_concurrent_rpcs: 4,
            max_concurrent_rpcs_per_uid: 2,
            max_concurrent_cleanup: 2,
            ..Limits::default()
        });
        let hostile = Some(1000);
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(admission.try_rpc(RpcClass::Ordinary, hostile).unwrap());
        }
        assert!(admission.try_rpc(RpcClass::Ordinary, hostile).is_err());
        assert_eq!(admission.snapshot().rejected_rpc_shares, 1);
        // The hostile UID's own cleanup still gets one cleanup-lane permit, not two.
        held.push(admission.try_rpc(RpcClass::Cleanup, hostile).unwrap());
        assert!(admission.try_rpc(RpcClass::Cleanup, hostile).is_err());
        assert_eq!(admission.snapshot().cleanup.current, 1);
        // Another UID: its whole share of the ordinary lane, then the cleanup lane once
        // the ordinary lane is full.
        let victim = Some(0);
        let a = admission.try_rpc(RpcClass::Ordinary, victim).unwrap();
        let b = admission.try_rpc(RpcClass::Ordinary, victim).unwrap();
        assert_eq!(admission.snapshot().rpcs.current, 4);
        assert!(admission.try_rpc(RpcClass::Ordinary, Some(5)).is_err());
        let cleanup = admission.try_rpc(RpcClass::Cleanup, Some(5)).unwrap();
        assert_eq!(admission.snapshot().cleanup.current, 2);
        assert!(admission.try_rpc(RpcClass::Cleanup, Some(6)).is_err());
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.rpcs.rejected, 4);
        assert_eq!(snapshot.cleanup.rejected, 2);
        drop((held, a, b, cleanup));
        let snapshot = admission.snapshot();
        assert_eq!((snapshot.rpcs.current, snapshot.cleanup.current), (0, 0));
        for _ in 0..2 {
            assert!(admission.try_rpc(RpcClass::Ordinary, hostile).is_ok());
        }
    }

    /// Concurrent callers of one UID never overshoot its share.
    #[test]
    fn b7_shares_hold_under_concurrent_callers() {
        let admission = Arc::new(Admission::new(&Limits {
            max_connections: 64,
            reserved_connections: 4,
            max_connections_per_uid: 5,
            ..Limits::default()
        }));
        let barrier = Arc::new(std::sync::Barrier::new(32));
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let (admission, barrier) = (admission.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    admission.try_connection(Some(1)).ok()
                })
            })
            .collect();
        let held: Vec<_> = threads
            .into_iter()
            .filter_map(|t| t.join().unwrap())
            .collect();
        assert_eq!(held.len(), 6);
        assert_eq!(admission.connections_held_by(Some(1)), (5, 1));
        drop(held);
        assert_eq!(admission.snapshot().connections.current, 0);
    }

    /// B7 milestone 2 (MEDIUM-2): at the defaults, four UIDs holding 33, 29, 1 and 1
    /// connections take all 64 slots, the whole reserve included; a fifth UID is
    /// refused, but root still gets its own slot, and only one.
    #[test]
    fn b7m2_root_gets_its_slot_after_a_four_uid_fill() {
        let limits = Limits::default();
        validate_ingress(&limits).unwrap();
        let admission = Admission::new(&limits);
        let mut held = Vec::new();
        for (uid, count, expected) in [
            (1001, 33, (32, 1)),
            (1002, 29, (28, 1)),
            (1003, 1, (0, 1)),
            (1004, 1, (0, 1)),
        ] {
            for _ in 0..count {
                held.push(admission.try_connection(Some(uid)).unwrap());
            }
            assert_eq!(admission.connections_held_by(Some(uid)), expected, "{uid}");
        }
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.connections.current, 64);
        assert_eq!(snapshot.reserved_connections.current, 4);
        assert!(admission.try_connection(Some(1005)).is_err());
        assert!(admission.try_connection(None).is_err());
        let root = admission.try_connection(Some(0)).unwrap();
        assert_eq!(root.lane(), ConnectionLane::Root);
        assert!(root.lane().health_and_cleanup_only());
        assert!(admission.try_connection(Some(0)).is_err());
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.root_connection.current, 1);
        assert_eq!(
            snapshot.connections.current, 64,
            "the root slot is beyond the budget"
        );
        drop(root);
        assert_eq!(admission.snapshot().root_connection.current, 0);
        // While general or reserved slots are free, root takes those like anyone else.
        drop(held);
        assert_eq!(
            admission.try_connection(Some(0)).unwrap().lane(),
            ConnectionLane::General
        );
    }

    /// B7 milestone 2 (MEDIUM-2): with Health, the ordinary RPCs and the cleanup lane
    /// all held by other UIDs, root still gets one Health or cleanup permit; another UID
    /// does not, and no UID gets an ordinary RPC from it.
    #[test]
    fn b7m2_root_keeps_one_health_and_cleanup_permit() {
        let admission = Admission::new(&Limits {
            max_concurrent_rpcs: 2,
            max_concurrent_rpcs_per_uid: 1,
            max_concurrent_cleanup: 2,
            max_concurrent_health: 1,
            ..Limits::default()
        });
        let mut held = Vec::new();
        for uid in [1001, 1002] {
            held.push(admission.try_rpc(RpcClass::Ordinary, Some(uid)).unwrap());
            held.push(admission.try_rpc(RpcClass::Cleanup, Some(uid)).unwrap());
        }
        held.push(admission.try_health(Some(1003)).unwrap());
        assert!(admission.try_health(Some(1004)).is_err());
        assert!(admission.try_rpc(RpcClass::Cleanup, Some(1004)).is_err());
        assert!(admission.try_rpc(RpcClass::Ordinary, Some(0)).is_err());
        let health = admission.try_health(Some(0)).unwrap();
        assert!(matches!(health, RpcPermit::Root(_)));
        assert!(admission.try_rpc(RpcClass::Cleanup, Some(0)).is_err());
        drop(health);
        let cleanup = admission.try_rpc(RpcClass::Cleanup, Some(0)).unwrap();
        assert!(matches!(cleanup, RpcPermit::Root(_)));
        assert_eq!(admission.snapshot().root_rpc.current, 1);
        drop((cleanup, held));
        let snapshot = admission.snapshot();
        assert_eq!(
            (
                snapshot.rpcs.current,
                snapshot.cleanup.current,
                snapshot.health.current,
                snapshot.root_rpc.current
            ),
            (0, 0, 0, 0)
        );
    }

    /// B7 milestone 2 (HIGH-2): each invariant, refused at equality and accepted one
    /// below it.
    #[test]
    fn b7m2_ingress_invariants() {
        let with = |total, reserved, per_uid| Limits {
            max_connections: total,
            reserved_connections: reserved,
            max_connections_per_uid: per_uid,
            ..Limits::default()
        };
        let error = validate_ingress(&with(33, 1, 32)).unwrap_err();
        assert!(error.contains("--max-connections-per-uid (32)"), "{error}");
        validate_ingress(&with(33, 1, 31)).unwrap();
        assert!(
            validate_ingress(&with(33, 0, 16))
                .unwrap_err()
                .contains("at least 1")
        );
        assert!(
            validate_ingress(&with(4, 4, 1))
                .unwrap_err()
                .contains("below --max-connections")
        );
        let error = validate_ingress(&Limits {
            max_concurrent_rpcs: 4,
            max_concurrent_rpcs_per_uid: 4,
            ..Limits::default()
        })
        .unwrap_err();
        assert!(
            error.contains("--max-concurrent-rpcs-per-uid (4)"),
            "{error}"
        );
        let error = validate_ingress(&Limits {
            max_concurrent_cleanup: 0,
            ..Limits::default()
        })
        .unwrap_err();
        assert!(error.contains("--max-concurrent-cleanup"), "{error}");
        // Under the accepted 33/1/31, one UID cannot hold every slot: one general slot
        // stays for another UID.
        let admission = Admission::new(&with(33, 1, 31));
        let held: Vec<_> = (0..64)
            .filter_map(|_| admission.try_connection(Some(1001)).ok())
            .collect();
        assert_eq!(held.len(), 32);
        assert_eq!(
            admission.try_connection(Some(1002)).unwrap().lane(),
            ConnectionLane::General
        );
    }
}
