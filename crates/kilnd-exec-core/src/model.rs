//! The backend-neutral value types the direct-kiln core reports in: the sandbox spec it
//! creates from, captured output and typed runtime diagnostics. Moved from
//! `kilnd::model` (Phase 1b B5); kilnd re-exports them unchanged.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a caller asked for, with every default filled in. Stored as JSON in
/// the `sandboxes.spec` column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    pub image: String,
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub pids: u32,
    pub disk_bytes: u64,
    pub network: Network,
    pub read_only_root: bool,
    pub writable_paths: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    #[default]
    None,
    Full,
    Allow(Vec<String>),
}

/// What the runtime knows about the sandbox after an execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxDisposition {
    Reusable,
    /// No command remains; resources may remain.
    Stopped,
    /// Cleanup or reuse cannot be established.
    Quarantined,
}

impl SandboxDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reusable => "reusable",
            Self::Stopped => "stopped",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "reusable" => Self::Reusable,
            "stopped" => Self::Stopped,
            "quarantined" => Self::Quarantined,
            _ => return None,
        })
    }
}

/// How execution cleanup was established. This names evidence, never a stronger
/// attestation: `RuntimeDrained` trusts the runtime inside the session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CleanupEvidence {
    #[default]
    Unknown,
    NoChildStarted,
    RuntimeDrained,
    SandboxStopped,
}

impl CleanupEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NoChildStarted => "no_child_started",
            Self::RuntimeDrained => "runtime_drained",
            Self::SandboxStopped => "sandbox_stopped",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "unknown" => Self::Unknown,
            "no_child_started" => Self::NoChildStarted,
            "runtime_drained" => Self::RuntimeDrained,
            "sandbox_stopped" => Self::SandboxStopped,
            _ => return None,
        })
    }
}

/// The first bytes observed from one output stream and its accounting evidence.
///
/// `total_bytes` is exact only when `total_bytes_known` is true. `truncated`
/// records whether the retention limit discarded bytes that were actually
/// observed; an unknown tail is represented independently.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub data: Vec<u8>,
    pub total_bytes: u64,
    pub truncated: bool,
    pub total_bytes_known: bool,
}

impl Captured {
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn known_empty() -> Self {
        Self {
            total_bytes_known: true,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Exited(i32),
    Signaled { signal: i32, core_dumped: bool },
}

impl CommandStatus {
    pub fn legacy_projection(&self) -> i32 {
        match self {
            Self::Exited(code) => *code,
            Self::Signaled { signal, .. } => 128 + signal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeErrorKind {
    InvalidRequest,
    Unavailable,
    NotFound,
    Incompatible,
    Busy,
    LaunchFailed,
    Io,
    Protocol,
    CleanupFailed,
    Internal,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStage {
    None,
    Validate,
    Connect,
    Request,
    Prepare,
    Fork,
    Admission,
    Stdio,
    Exec,
    Wait,
    Cleanup,
    Report,
    Capture,
    Handshake,
    /// kiln's stage 14 `Chdir`: the command's working directory could not be entered.
    Cwd,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RuntimeDiagnostic {
    pub kind: RuntimeErrorKind,
    pub stage: RuntimeStage,
    pub message: String,
    pub native_code: Option<String>,
    pub message_truncated: bool,
}

impl RuntimeDiagnostic {
    pub fn new(kind: RuntimeErrorKind, stage: RuntimeStage, message: impl Into<String>) -> Self {
        let mut message = message.into();
        let message_truncated = message.len() > 2048;
        if message_truncated {
            let mut end = 2048;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self {
            kind,
            stage,
            message,
            native_code: None,
            message_truncated,
        }
    }
}
