//! Charged absence-fenced rows whose settlement failed are retried behind the caller.
//!
//! A Delete of a READY session, or a refused Create's fence, can fail for a reason that
//! goes away on its own: the helper had no fresh namespace observation, its ledger did
//! not answer in time. The caller gets that error, and the row stays visibly DELETING or
//! FAILED and charged, as before. What changed is that someone retries it: each such
//! row is retried here, one attempt at a time, with a backoff from one second doubling
//! to thirty, until its charge is released or the row is gone. A row that is still
//! charged stays queued whatever state it moved to meanwhile (a client's Delete may have
//! taken a FAILED row to DELETING and then departed), and the next attempt follows its
//! current state. A retry is exactly what a client could do: a DELETING row gets the
//! same Delete, and a FAILED row the same settlement that reconciliation runs, under the
//! row's exec lock. Nothing here ever releases without the receipt. Legacy rows, and rows
//! another backend wrote, are never queued or retried: like reconciliation, only rows of
//! the running backend are this daemon's to settle.

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
    /// Times this row was queued, its first time included. An attempt that ends while a
    /// newer request arrived keeps the row queued, so no request coalesced into an entry
    /// about to be removed is lost.
    pub(super) requests: u64,
}

/// The wait after `failures` consecutive failed attempts here (zero for the first one,
/// after the caller's own failure): 1, 2, 4, 8, 16, then 30 seconds.
pub(super) fn settle_retry_delay(failures: u32) -> Duration {
    SETTLE_RETRY_FIRST
        .saturating_mul(1u32.checked_shl(failures.min(31)).unwrap_or(u32::MAX))
        .min(SETTLE_RETRY_CAP)
}

/// What one attempt found.
#[derive(Debug)]
pub(super) enum Attempt {
    /// The charge is released, or the row is gone: nothing left to retry.
    Settled,
    /// Not this retry's row: another backend's, or a legacy one. It is left untouched.
    NotOurs(&'static str),
    /// Still charged: retried after the backoff, following its state then.
    Failed(String),
}

impl<R: Runtime> Manager<R> {
    /// Whether a row is this retry's: a charged absence-fenced row of the running
    /// backend (the same backend check reconciliation makes).
    fn settle_retry_eligible(&self, row: &Sandbox) -> bool {
        row.backend == self.runtime.name() && row.is_fenced() && row.is_charged()
    }

    /// Queues `id` for a retry after its settlement failed. A row already queued keeps
    /// its own schedule, and counts the request. Only charged absence-fenced rows of the
    /// running backend are queued; a row that can't be read is queued, and its attempt
    /// checks it again.
    pub(super) fn schedule_settle_retry(&self, id: &str) {
        match self.store.sandbox(id) {
            Ok(Some(row)) if !self.settle_retry_eligible(&row) => return,
            Ok(None) => return,
            Ok(Some(_)) | Err(_) => {}
        }
        let mut retries = self.settle_retries.lock().unwrap();
        if let Some(retry) = retries.get_mut(id) {
            retry.requests = retry.requests.saturating_add(1);
            return;
        }
        retries.insert(
            id.to_string(),
            SettleRetry {
                failures: 0,
                at: Instant::now() + settle_retry_delay(0),
                requests: 1,
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
            if self.settle_retry_eligible(&row)
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
        let requests = self
            .settle_retries
            .lock()
            .unwrap()
            .get(id)
            .map(|retry| retry.requests);
        let attempt = self.settle_attempt(id).await;
        self.finish_settle_retry(id, requests, attempt);
    }

    /// Ends one attempt on `id`. `requests` is the entry's request count when the
    /// attempt began: a settled row stays queued for one more look if a request arrived
    /// meanwhile, and a charged row is always rescheduled.
    pub(super) fn finish_settle_retry(&self, id: &str, requests: Option<u64>, attempt: Attempt) {
        let mut retries = self.settle_retries.lock().unwrap();
        let Some(retry) = retries.get_mut(id) else {
            return;
        };
        match attempt {
            Attempt::Settled | Attempt::NotOurs(_) if Some(retry.requests) != requests => {
                // A request coalesced into this entry during the attempt: look again.
                retry.failures = 0;
                retry.at = Instant::now() + settle_retry_delay(0);
            }
            Attempt::Settled => {
                retries.remove(id);
            }
            Attempt::NotOurs(why) => {
                retries.remove(id);
                tracing::debug!(sandbox = %id, why, "not this daemon's to settle; left untouched");
            }
            Attempt::Failed(error) => {
                retry.failures = retry.failures.saturating_add(1);
                let delay = settle_retry_delay(retry.failures);
                retry.at = Instant::now() + delay;
                warn!(sandbox = %id, error = %error, failures = retry.failures, retry_ms = delay.as_millis() as u64, "allocation stays charged; settlement retry scheduled");
            }
        }
    }

    /// One attempt: what a client could do for the row's current state, then the row's
    /// charge decides. Only a released charge or a gone row settles it.
    pub(super) async fn settle_attempt(self: &Arc<Self>, id: &str) -> Attempt {
        let row = match self.store.sandbox(id) {
            Ok(Some(row)) => row,
            Ok(None) => return Attempt::Settled,
            Err(error) => return Attempt::Failed(format!("{error:#}")),
        };
        if !row.is_charged() {
            return Attempt::Settled;
        }
        // Checked before any work: a row another backend wrote is never touched, so its
        // visible failure stays what that backend recorded.
        if row.backend != self.runtime.name() {
            return Attempt::NotOurs("another backend's row");
        }
        if !row.is_fenced() {
            return Attempt::NotOurs("a legacy row");
        }
        let error = match row.state {
            // The same Delete a client would send.
            SandboxState::Deleting => self.delete(id).await.err().map(|e| e.to_string()),
            // Reconciliation's settlement, which keeps the row FAILED.
            SandboxState::Failed => {
                let slot = self.slot(id);
                let _guard = slot.exec_lock.lock().await;
                match self.load(id) {
                    // A Delete may have taken it to DELETING meanwhile: the charge below
                    // decides, and the next attempt follows its new state.
                    Ok(row) if row.state == SandboxState::Failed && row.is_charged() => self
                        .settle_fenced(&row, SandboxState::Failed, None)
                        .await
                        .err()
                        .map(|e| e.to_string()),
                    Ok(_) => None,
                    Err(error) => Some(error.to_string()),
                }
            }
            // CREATING and READY belong to their own operation; LOST and QUARANTINED
            // wait for a Delete. A charged one stays queued and is looked at again.
            _ => None,
        };
        match self.store.sandbox(id) {
            Ok(None) => Attempt::Settled,
            Ok(Some(row)) if !row.is_charged() => Attempt::Settled,
            Ok(Some(row)) => Attempt::Failed(error.unwrap_or_else(|| {
                format!("the row is {} and still charged", row.state.as_str())
            })),
            Err(read) => Attempt::Failed(format!("{read:#}")),
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
