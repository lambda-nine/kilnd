//! The runtime adapter: the only part of kilnd that knows how sandboxes are
//! actually made. kiln is the first implementation; a microVM backend would
//! implement the same trait.

use std::future::Future;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::model::{Captured, SandboxSpec};

pub mod fake;
pub mod kiln;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The backend refused or failed the operation; the message is for
    /// operators and API callers.
    #[error("{0}")]
    Backend(String),
    /// The backend doesn't know this sandbox.
    #[error("sandbox {0} not found in backend")]
    NotFound(String),
    /// Running the backend at all failed (missing binary, I/O error).
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub struct ExecSpec<'a> {
    pub argv: &'a [String],
    pub stdin: &'a [u8],
    pub timeout: Duration,
    /// Bytes kept per output stream.
    pub max_output: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecFinish {
    /// The command's exit code, or 128 + signal number.
    Exited(i32),
    TimedOut,
    Canceled,
}

#[derive(Debug)]
pub struct ExecOutcome {
    pub finish: ExecFinish,
    pub stdout: Captured,
    pub stderr: Captured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendStatus {
    /// Alive and able to accept commands.
    Running,
    /// Known to the backend but no longer alive; `gc` removes it.
    Stale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendSandbox {
    pub id: String,
    pub status: BackendStatus,
}

/// Futures are `Send` because tonic requires it of service handlers.
pub trait Runtime: Send + Sync + 'static {
    /// Short backend name stored with each sandbox, like "kiln".
    fn name(&self) -> &'static str;

    fn version(&self) -> impl Future<Output = Result<String, RuntimeError>> + Send;

    /// Creates a fresh sandbox owned by this invocation, returning once it
    /// accepts commands. A successful call returns that new backend's ID.
    /// An error may be ambiguous if the backend made a resource before it
    /// lost the ability to report the ID.
    fn create(&self, spec: &SandboxSpec) -> impl Future<Output = Result<String, RuntimeError>> + Send;

    /// Runs one command and waits for it. When the timeout passes or `cancel`
    /// fires, the command must be stopped inside the sandbox, not just
    /// abandoned, and the sandbox left usable.
    fn exec(
        &self,
        id: &str,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<ExecOutcome, RuntimeError>> + Send;

    /// Removes a sandbox and waits until its resources are released.
    fn remove(&self, id: &str) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// Every sandbox the backend knows about, including ones kilnd didn't
    /// create.
    fn list(&self) -> impl Future<Output = Result<Vec<BackendSandbox>, RuntimeError>> + Send;

    /// Removes what dead sandboxes left behind. Must never touch a live one.
    /// Returns the IDs it removed.
    fn gc(&self) -> impl Future<Output = Result<Vec<String>, RuntimeError>> + Send;
}
