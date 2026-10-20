//! Non-waiting resource admission. Permits follow the resource owner.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::manager::Limits;

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

    fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            max: u64::try_from(self.max).expect("capacity fits u64"),
            current: u64::try_from(self.max - self.permits.available_permits())
                .expect("usage fits u64"),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub max: u64,
    pub current: u64,
    pub rejected: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    pub connections: BudgetSnapshot,
    pub rpcs: BudgetSnapshot,
    pub health: BudgetSnapshot,
    pub execs: BudgetSnapshot,
    pub stdin: BudgetSnapshot,
    pub max_queued_execs_per_sandbox: u64,
    pub rejected_sandbox_execs: u64,
}

pub struct Admission {
    connections: Budget,
    rpcs: Budget,
    health: Budget,
    execs: Budget,
    stdin: Budget,
    max_queued_execs_per_sandbox: usize,
    rejected_sandbox_execs: AtomicU64,
}

impl Admission {
    pub fn new(limits: &Limits) -> Self {
        u32::try_from(limits.max_queued_exec_stdin_bytes)
            .expect("aggregate stdin capacity fits u32");
        Self {
            connections: Budget::new(limits.max_connections),
            rpcs: Budget::new(limits.max_concurrent_rpcs),
            health: Budget::new(limits.max_concurrent_health),
            execs: Budget::new(limits.max_concurrent_execs),
            stdin: Budget::new(limits.max_queued_exec_stdin_bytes),
            max_queued_execs_per_sandbox: limits.max_queued_execs_per_sandbox,
            rejected_sandbox_execs: AtomicU64::new(0),
        }
    }

    pub fn try_connection(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.connections.acquire(1)
    }

    pub fn try_rpc(&self, health: bool) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        if health {
            self.health.acquire(1)
        } else {
            self.rpcs.acquire(1)
        }
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

    pub fn snapshot(&self) -> AdmissionSnapshot {
        AdmissionSnapshot {
            connections: self.connections.snapshot(),
            rpcs: self.rpcs.snapshot(),
            health: self.health.snapshot(),
            execs: self.execs.snapshot(),
            stdin: self.stdin.snapshot(),
            max_queued_execs_per_sandbox: u64::try_from(self.max_queued_execs_per_sandbox)
                .expect("sandbox queue capacity fits u64"),
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
            max_concurrent_execs: 1,
            max_queued_exec_stdin_bytes: 3,
            ..Limits::default()
        }));
        let shared = admission.clone();
        let connection = shared.try_connection().unwrap();
        let rpc = shared.try_rpc(false).unwrap();
        let health = shared.try_rpc(true).unwrap();
        let exec = shared.try_exec().unwrap();
        let stdin = shared.try_stdin(3).unwrap();
        assert!(admission.try_stdin(0).unwrap().is_none());
        assert!(admission.try_connection().is_err());
        assert!(admission.try_rpc(false).is_err());
        assert!(admission.try_rpc(true).is_err());
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
        assert!(admission.try_connection().is_ok());
        assert!(admission.try_stdin(3).is_ok());
        assert!(admission.try_stdin(usize::MAX).is_err());
        assert_eq!(admission.snapshot().stdin.rejected, 2);
        admission.reject_sandbox_exec();
        let snapshot = admission.snapshot();
        assert_eq!(snapshot.max_queued_execs_per_sandbox, 8);
        assert_eq!(snapshot.rejected_sandbox_execs, 1);
    }
}
