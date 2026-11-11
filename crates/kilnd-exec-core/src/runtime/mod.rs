//! The direct-kiln core's runtime value types: the error, execution request and outcome,
//! and the backend listing it parses. Moved from `kilnd::runtime` (Phase 1b B5); kilnd
//! re-exports them unchanged, so its `Runtime` trait keeps the same signatures.

use tokio::time::Instant;

use crate::model::{
    Captured, CleanupEvidence, CommandStatus, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage,
    SandboxDisposition,
};

pub mod kiln_direct;
pub mod kiln_process;
pub mod kiln_protocol;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The backend refused or failed the operation; the message is for
    /// operators and API callers.
    #[error("{0}")]
    Backend(String),
    /// The backend doesn't know this sandbox. Never proof of absence for an
    /// allocation-token backend.
    #[error("sandbox {0} not found in backend")]
    NotFound(String),
    /// Running the backend at all failed (missing binary, I/O error).
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Incompatible(String),
    /// The backend has no such capability, like allocation-token recovery on
    /// legacy kiln.
    #[error("{0}")]
    Unsupported(String),
    /// The backend has no room for the operation now and did nothing; the caller may
    /// retry later. The daemon answers it as RESOURCE_EXHAUSTED.
    #[error("{0}")]
    Exhausted(String),
}

pub struct ExecSpec<'a> {
    pub argv: &'a [String],
    pub stdin: &'a [u8],
    pub deadline: Instant,
    /// Bytes kept per output stream.
    pub max_output: usize,
    /// The cwd and effective env overrides; `ExecOptions::EMPTY` is today's operation 4.
    pub options: &'a crate::exec_options::ExecOptions,
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
    /// Whether the next queued command may use this sandbox.
    pub disposition: SandboxDisposition,
    pub cleanup: CleanupEvidence,
}

/// The legacy kiln mapping from the existing cleanup contract: every outcome but
/// `CleanupFailed` passed the adapter's barrier or never started a child. kiln's
/// wire protocol carries no separate evidence, so client and direct share this.
pub fn legacy_exec_evidence(
    finish: &Result<ExecFinish, RuntimeDiagnostic>,
) -> (SandboxDisposition, CleanupEvidence) {
    match finish {
        Err(d) if d.kind == RuntimeErrorKind::CleanupFailed => {
            (SandboxDisposition::Quarantined, CleanupEvidence::Unknown)
        }
        // kiln proved this sandbox gone; LOST stays charged until Delete.
        Err(d) if d.kind == RuntimeErrorKind::NotFound => {
            (SandboxDisposition::Stopped, CleanupEvidence::Unknown)
        }
        Err(d)
            if matches!(
                d.stage,
                RuntimeStage::Validate | RuntimeStage::Handshake | RuntimeStage::Prepare
            ) =>
        {
            (
                SandboxDisposition::Reusable,
                CleanupEvidence::NoChildStarted,
            )
        }
        _ => (
            SandboxDisposition::Reusable,
            CleanupEvidence::RuntimeDrained,
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendStatus {
    /// Alive and able to accept commands.
    Running,
    /// Known to the backend but no longer alive; `gc` removes it.
    Stale,
    /// Allocation-token states. `Busy` is not reusable; only a healthy idle
    /// handshake is.
    Ready,
    Busy,
    StoppedWithResources,
    Quarantined,
    /// Never to be read as Stale or absent.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendSandbox {
    pub id: String,
    pub status: BackendStatus,
}
