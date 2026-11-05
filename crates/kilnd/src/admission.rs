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
//!   unavailable shares one bucket with every other such connection.
//! - **RPCs.** Health keeps its own reserved lane. An ordinary RPC needs a global
//!   permit and its UID's share (`max_concurrent_rpcs_per_uid`). A cleanup RPC tries
//!   the ordinary lane first and, when that is full or its UID's share is spent, one
//!   permit of the cleanup lane (`max_concurrent_cleanup`, at most one per UID).
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
}

/// A connection's slot, held for the connection's life.
pub struct ConnectionPermit {
    lane: ConnectionLane,
    _permit: SharedPermit,
}

impl ConnectionPermit {
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
    pub execs: BudgetSnapshot,
    pub stdin: BudgetSnapshot,
    pub max_queued_execs_per_sandbox: u64,
    pub rejected_sandbox_execs: u64,
}

pub struct Admission {
    general_connections: Lane,
    reserved_connections: Lane,
    rejected_connections: AtomicU64,
    rejected_reserved: AtomicU64,
    rejected_connection_shares: AtomicU64,
    rpcs: Lane,
    rejected_rpcs: AtomicU64,
    rejected_rpc_shares: AtomicU64,
    cleanup: Lane,
    rejected_cleanup: AtomicU64,
    health: Budget,
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
            reserved_connections: Lane::new(reserved, 1),
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
            execs: Budget::new(limits.max_concurrent_execs),
            stdin: Budget::new(limits.max_queued_exec_stdin_bytes),
            max_queued_execs_per_sandbox: limits.max_queued_execs_per_sandbox,
            rejected_sandbox_execs: AtomicU64::new(0),
        }
    }

    /// A connection slot for `uid`: a general one within its share, else one reserved
    /// Health and cleanup slot, else none (the server closes the socket).
    pub fn try_connection(&self, uid: ShareKey) -> Result<ConnectionPermit, TryAcquireError> {
        let general = match self.general_connections.try_acquire(uid) {
            Ok(permit) => {
                return Ok(ConnectionPermit {
                    lane: ConnectionLane::General,
                    _permit: permit,
                });
            }
            Err(refusal) => refusal,
        };
        match self.reserved_connections.try_acquire(uid) {
            Ok(permit) => Ok(ConnectionPermit {
                lane: ConnectionLane::Reserved,
                _permit: permit,
            }),
            Err(reserved) => {
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
        }
    }

    /// Health's own reserved lane, shared by every caller.
    pub fn try_health(&self) -> Result<RpcPermit, TryAcquireError> {
        self.health.acquire(1).map(RpcPermit::Health)
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
        let health = shared.try_health().unwrap();
        let exec = shared.try_exec().unwrap();
        let stdin = shared.try_stdin(3).unwrap();
        assert!(admission.try_stdin(0).unwrap().is_none());
        assert!(admission.try_connection(Some(7)).is_err());
        assert!(admission.try_rpc(RpcClass::Ordinary, Some(7)).is_err());
        assert!(admission.try_health().is_err());
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
}
