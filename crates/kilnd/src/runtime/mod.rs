//! The runtime adapter: the only part of kilnd that knows how sandboxes are
//! actually made. kiln is the first implementation; a microVM backend would
//! implement the same trait.

use std::future::Future;
use tokio::time::Instant;

use tokio_util::sync::CancellationToken;

use crate::model::{Captured, CommandStatus, RuntimeDiagnostic, SandboxSpec};

pub use crate::model::CreateCertainty;

pub mod fake;
pub mod kiln;
#[doc(hidden)]
pub mod kiln_direct;
mod kiln_process;
mod kiln_protocol;

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
    #[error("{0}")]
    Incompatible(String),
}

/// A create that returned no backend ID. The fields are private so an ordinary
/// error can only become `AllocationAmbiguous`: claiming that nothing was
/// allocated takes the explicit constructor and the evidence behind it.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct CreateFailure {
    certainty: CreateCertainty,
    error: RuntimeError,
}

impl CreateFailure {
    /// Use only with proof that no backend resource exists or can appear
    /// later because of this call. kilnd releases the reservation on this.
    pub fn definitely_not_created(error: RuntimeError) -> Self {
        Self {
            certainty: CreateCertainty::DefinitelyNotCreated,
            error,
        }
    }

    pub fn certainty(&self) -> CreateCertainty {
        self.certainty
    }

    pub fn error(&self) -> &RuntimeError {
        &self.error
    }
}

impl From<RuntimeError> for CreateFailure {
    fn from(error: RuntimeError) -> Self {
        Self {
            certainty: CreateCertainty::AllocationAmbiguous,
            error,
        }
    }
}

impl From<std::io::Error> for CreateFailure {
    fn from(error: std::io::Error) -> Self {
        RuntimeError::from(error).into()
    }
}

pub struct ExecSpec<'a> {
    pub argv: &'a [String],
    pub stdin: &'a [u8],
    pub deadline: Instant,
    /// Bytes kept per output stream.
    pub max_output: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecFinish {
    Completed,
    TimedOut,
    Canceled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecOutcome {
    pub finish: Result<ExecFinish, RuntimeDiagnostic>,
    pub command_status: Option<CommandStatus>,
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

    /// Returns the backend version. Deadline or cancellation must stop and
    /// reap any subprocess before the future returns.
    fn version(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<String, RuntimeError>> + Send;

    /// Creates a fresh sandbox owned by this invocation, returning once it
    /// accepts commands. A successful call returns that new backend's ID.
    /// A failure is `AllocationAmbiguous` unless the implementation can prove
    /// otherwise: the backend may have made a resource before it lost the
    /// ability to report the ID.
    fn create(
        &self,
        spec: &SandboxSpec,
    ) -> impl Future<Output = Result<String, CreateFailure>> + Send;

    /// Side-effect-free validation of an existing sandbox's execution protocol.
    fn validate_sandbox(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// Runs one command and waits for it. A pre-canceled token must be honored.
    /// When the timeout passes or `cancel` fires, the command and all of its
    /// descendants must be stopped inside the sandbox, all I/O resources must
    /// be released, and the sandbox left usable before this future returns.
    /// Return an error rather than success when cleanup cannot be confirmed.
    fn exec(
        &self,
        id: &str,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> impl Future<Output = ExecOutcome> + Send;

    /// Removes a sandbox and waits until its resources are released.
    fn remove(&self, id: &str) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// Every sandbox the backend knows about, including ones kilnd didn't
    /// create.
    fn list(&self) -> impl Future<Output = Result<Vec<BackendSandbox>, RuntimeError>> + Send;

    /// Removes stale state only for the named backend sandboxes. An empty
    /// scope is a no-op. Must never touch a live or unlisted sandbox. Returns
    /// the IDs it removed.
    fn gc(&self, ids: &[String]) -> impl Future<Output = Result<Vec<String>, RuntimeError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_errors_default_to_ambiguous_and_definite_is_explicit() {
        let ordinary = CreateFailure::from(RuntimeError::Backend("image missing".into()));
        assert_eq!(ordinary.certainty(), CreateCertainty::AllocationAmbiguous);
        assert_eq!(ordinary.to_string(), "image missing");
        let io = CreateFailure::from(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(io.certainty(), CreateCertainty::AllocationAmbiguous);
        assert!(matches!(io.error(), RuntimeError::Io(_)));
        let definite =
            CreateFailure::definitely_not_created(RuntimeError::Backend("no image".into()));
        assert_eq!(definite.certainty(), CreateCertainty::DefinitelyNotCreated);
        assert_eq!(definite.to_string(), "no image");
    }
}
