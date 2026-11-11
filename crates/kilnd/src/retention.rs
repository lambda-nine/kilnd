//! Durable history policy. This never releases resource reservations.
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputStorage {
    #[default]
    Full,
    Metadata,
    None,
}

#[derive(Clone, Debug)]
pub struct Retention {
    pub execution_max_age_secs: u64,
    pub execution_max_count: u32,
    pub sandbox_max_age_secs: u64,
    pub sandbox_max_count: u32,
    pub prune_interval_secs: u64,
    pub output_storage: OutputStorage,
    /// The least age, on the boot clock, at which a create request record of a
    /// DELETED or released FAILED sandbox may be pruned (`--create-request-retention-secs`,
    /// at least a day). Pruning waits a further 0.1 % (API additions design 3.3).
    pub create_request_retention_secs: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            execution_max_age_secs: 7 * 86400,
            execution_max_count: 10_000,
            sandbox_max_age_secs: 7 * 86400,
            sandbox_max_count: 1000,
            prune_interval_secs: 60,
            output_storage: OutputStorage::Full,
            create_request_retention_secs: MIN_CREATE_REQUEST_RETENTION_SECS,
        }
    }
}

/// The shortest create request retention a node may configure: one day.
pub const MIN_CREATE_REQUEST_RETENTION_SECS: u64 = 86_400;

/// The boottime age a record must reach before pruning: R + ceil(R / 1000), which
/// takes more than R of real time at NTP's worst slew of 500 ppm (design 3.3).
pub fn create_request_prune_age_ms(retention_secs: u64) -> Option<i64> {
    let r = retention_secs.checked_mul(1000)?;
    let margin = r.div_ceil(1000);
    i64::try_from(r.checked_add(margin)?).ok()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub executions: usize,
    pub sandboxes: usize,
    /// Create request records whose retention ended.
    pub create_requests: usize,
}
