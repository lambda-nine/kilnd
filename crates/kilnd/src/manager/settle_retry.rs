//! Charged absence-fenced rows whose settlement failed are retried behind the caller.
//!
//! A Delete of a READY session, or a refused Create's fence, can fail for a reason that
//! goes away on its own: the helper had no fresh namespace observation, its ledger did
//! not answer in time. The caller gets that error, and the row stays visibly DELETING or
//! FAILED and charged, as before. What changed is that someone retries it: each such
//! row is retried here, one attempt at a time, with a backoff from one second doubling
//! to thirty, until its absence receipt is recorded and its charge released (or the row
//! is no longer a charged fenced row for some other reason). A retry is exactly what a
//! client could do: a DELETING row gets the same Delete, and a FAILED row the same
//! settlement that reconciliation runs, under the row's exec lock. Nothing here ever
//! releases without the receipt. Legacy rows are never queued.

use super::*;

/// The first retry comes this long after the failure; each later failure doubles it.
pub(super) const SETTLE_RETRY_FIRST: Duration = Duration::from_secs(1);
/// The longest wait between two attempts on one row.
pub(super) const SETTLE_RETRY_CAP: Duration = Duration::from_secs(30);

/// One charged row waiting for its next settlement attempt.
#[derive(Clone, Copy, Debug)]
pub(super) struct SettleRetry {
    /// Attempts made here that failed (zero before the first).
    pub(super) failures: u32,
    pub(super) at: Instant,
}

/// The wait after `failures` consecutive failed attempts here (zero for the first one,
/// after the caller's own failure): 1, 2, 4, 8, 16, then 30 seconds.
pub(super) fn settle_retry_delay(failures: u32) -> Duration {
    SETTLE_RETRY_FIRST
        .saturating_mul(1u32.checked_shl(failures.min(31)).unwrap_or(u32::MAX))
        .min(SETTLE_RETRY_CAP)
}

/// What one attempt found.
enum Attempt {
    /// Released, gone, or not a charged fenced row any more: nothing left to retry.
    Settled,
    Failed(String),
}

impl<R: Runtime> Manager<R> {
    /// Queues `id` for a retry after its settlement failed. A row already queued keeps
    /// its own schedule. Only charged absence-fenced rows are ever queued.
    pub(super) fn schedule_settle_retry(&self, id: &str) {
        let mut retries = self.settle_retries.lock().unwrap();
        if retries.contains_key(id) {
            return;
        }
        retries.insert(
            id.to_string(),
            SettleRetry {
                failures: 0,
                at: Instant::now() + settle_retry_delay(0),
            },
        );
        drop(retries);
        self.settle_changed.notify_one();
    }

    /// Rows waiting for a retry, and their failures so far (tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn settle_retries(&self) -> Vec<(String, u32)> {
        let mut rows: Vec<_> = self
            .settle_retries
            .lock()
            .unwrap()
            .iter()
            .map(|(id, retry)| (id.clone(), retry.failures))
            .collect();
        rows.sort();
        rows
    }

    /// Starts the retry task. It first queues every charged fenced row that is FAILED or
    /// DELETING (what startup reconciliation could not settle), then runs until
    /// shutdown.
    pub fn start_settle_retries(self: &Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        for row in self.list(false)? {
            if row.is_fenced()
                && row.is_charged()
                && matches!(row.state, SandboxState::Failed | SandboxState::Deleting)
            {
                self.schedule_settle_retry(&row.id);
            }
        }
        let manager = Arc::clone(self);
        Ok(tokio::spawn(
            async move { manager.settle_retry_loop().await },
        ))
    }

    async fn settle_retry_loop(self: Arc<Self>) {
        loop {
            if self.shutting_down.is_cancelled() {
                break;
            }
            let now = Instant::now();
            let due = {
                let retries = self.settle_retries.lock().unwrap();
                let mut due: Vec<(Instant, String)> = retries
                    .iter()
                    .filter(|(_, retry)| retry.at <= now)
                    .map(|(id, retry)| (retry.at, id.clone()))
                    .collect();
                due.sort();
                due
            };
            // One attempt at a time, earliest first; each reschedules or ends its row.
            for (_, id) in due {
                // Shutdown drops an attempt as a departing client's RPC would be.
                tokio::select! {
                    biased;
                    () = self.shutting_down.cancelled() => return,
                    () = self.settle_retry_once(&id) => {}
                }
            }
            let next = self
                .settle_retries
                .lock()
                .unwrap()
                .values()
                .map(|retry| retry.at)
                .min();
            tokio::select! {
                biased;
                () = self.shutting_down.cancelled() => break,
                () = self.settle_changed.notified() => {}
                () = sleep_until_or_forever(next) => {}
            }
        }
    }

    async fn settle_retry_once(self: &Arc<Self>, id: &str) {
        let attempt = self.settle_attempt(id).await;
        let mut retries = self.settle_retries.lock().unwrap();
        match attempt {
            Attempt::Settled => {
                retries.remove(id);
            }
            Attempt::Failed(error) => {
                let Some(retry) = retries.get_mut(id) else {
                    return;
                };
                retry.failures = retry.failures.saturating_add(1);
                let delay = settle_retry_delay(retry.failures);
                retry.at = Instant::now() + delay;
                warn!(sandbox = %id, error = %error, failures = retry.failures, retry_ms = delay.as_millis() as u64, "allocation stays charged; settlement retry scheduled");
            }
        }
    }

    async fn settle_attempt(self: &Arc<Self>, id: &str) -> Attempt {
        let row = match self.store.sandbox(id) {
            Ok(Some(row)) => row,
            Ok(None) => return Attempt::Settled,
            Err(error) => return Attempt::Failed(format!("{error:#}")),
        };
        if !row.is_fenced() || !row.is_charged() {
            return Attempt::Settled;
        }
        match row.state {
            // The same Delete a client would send.
            SandboxState::Deleting => match self.delete(id).await {
                Ok(row) if row.state == SandboxState::Deleted || !row.is_charged() => {
                    Attempt::Settled
                }
                Ok(row) => Attempt::Failed(format!("the row is still {}", row.state.as_str())),
                Err(error) => Attempt::Failed(error.to_string()),
            },
            // Reconciliation's settlement, which keeps the row FAILED.
            SandboxState::Failed => {
                let slot = self.slot(id);
                let _guard = slot.exec_lock.lock().await;
                let row = match self.load(id) {
                    Ok(row) => row,
                    Err(error) => return Attempt::Failed(error.to_string()),
                };
                if row.state != SandboxState::Failed || !row.is_fenced() || !row.is_charged() {
                    // A Delete took it over, or it was released meanwhile.
                    return Attempt::Settled;
                }
                match self.settle_fenced(&row, SandboxState::Failed, None).await {
                    Ok(()) => Attempt::Settled,
                    Err(error) => Attempt::Failed(error.to_string()),
                }
            }
            // CREATING and READY belong to their own operation; LOST and QUARANTINED
            // wait for a Delete, which queues them again if it fails.
            _ => Attempt::Settled,
        }
    }
}

async fn sleep_until_or_forever(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_retry_backoff_runs_from_one_second_to_thirty() {
        let delays: Vec<u64> = (0..8).map(|n| settle_retry_delay(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(settle_retry_delay(u32::MAX), SETTLE_RETRY_CAP);
    }
}
