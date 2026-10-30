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
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub executions: usize,
    pub sandboxes: usize,
}
