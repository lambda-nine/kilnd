//! Private, versioned privilege boundary. No caller-supplied executable or flags.
use crate::model::{CommandStatus, RuntimeDiagnostic, SandboxSpec};
use crate::runtime::{BackendSandbox, BackendStatus, RuntimeError};
use crate::validation::{
    MAX_ALLOWLIST_ENTRIES, MAX_WRITABLE_PATHS, validate_allowlist_entry, validate_argv,
    validate_image_name, validate_writable_path,
};
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 3;
pub const STDIO_RECEIVED: u8 = 0x4b;

pub const MAX_FRAME: usize = 2 << 20;
pub const MAX_STDIN: usize = 1 << 20;
pub const MAX_OUTPUT: usize = 1 << 20;
pub const MAX_ARGV: usize = 256 << 10;
pub const MAX_GC_IDS: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub timeout_ms: u32,
    pub deadline_ns: u64,
    pub operation: Operation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Kiln(KilnRequest),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KilnRequest {
    Capabilities {
        id: Option<String>,
    },
    Create {
        spec: SandboxSpec,
    },
    Exec {
        id: String,
        argv: Vec<String>,
        stdin_bytes: usize,
        max_output: usize,
    },
    Ls,
    Rm {
        id: String,
    },
    Gc {
        ids: Vec<String>,
    },
}

impl Request {
    pub fn validate(&self, fds: usize) -> Result<(), String> {
        let Operation::Kiln(op) = &self.operation;
        let exec = matches!(op, KilnRequest::Exec { .. });
        if self.version != VERSION
            || self.timeout_ms == 0
            || self.timeout_ms > if exec { 3_600_000 } else { 120_000 }
        {
            return Err("unsupported version or timeout".into());
        }
        if fds != 0 {
            return Err("wrong descriptor count".into());
        }
        match op {
            KilnRequest::Capabilities { id: Some(id) } | KilnRequest::Rm { id } => {
                if !crate::runtime::kiln_direct::valid_kiln_id(id) {
                    return Err("invalid backend ID".into());
                }
            }
            KilnRequest::Capabilities { id: None } | KilnRequest::Ls => {}
            KilnRequest::Gc { ids } => {
                if ids.len() > MAX_GC_IDS
                    || ids
                        .iter()
                        .any(|id| !crate::runtime::kiln_direct::valid_kiln_id(id))
                {
                    return Err("invalid scoped GC IDs".into());
                }
                let unique: std::collections::HashSet<_> = ids.iter().collect();
                if unique.len() != ids.len() {
                    return Err("duplicate GC IDs".into());
                }
            }
            KilnRequest::Exec {
                id,
                argv,
                stdin_bytes,
                max_output,
            } => {
                if !crate::runtime::kiln_direct::valid_kiln_id(id)
                    || *stdin_bytes > MAX_STDIN
                    || *max_output == 0
                    || *max_output > MAX_OUTPUT
                {
                    return Err("invalid exec bounds".into());
                }
                validate_argv(argv, MAX_ARGV)?;
            }
            KilnRequest::Create { spec } => validate_spec(spec)?,
        }
        Ok(())
    }
}

fn validate_spec(spec: &SandboxSpec) -> Result<(), String> {
    validate_image_name(&spec.image)?;
    if spec.memory_bytes == 0
        || spec.memory_bytes > 8 << 30
        || spec.cpu_millis == 0
        || spec.cpu_millis > 8000
        || spec.pids == 0
        || spec.pids > 4096
        || spec.disk_bytes == 0
        || spec.disk_bytes > 32 << 30
    {
        return Err("invalid resource limits".into());
    }
    if let crate::model::Network::Allow(entries) = &spec.network {
        if entries.is_empty() || entries.len() > MAX_ALLOWLIST_ENTRIES {
            return Err("invalid allowlist count".into());
        }
        for entry in entries {
            validate_allowlist_entry(entry)?;
        }
    }
    if spec.writable_paths.len() > MAX_WRITABLE_PATHS
        || (!spec.writable_paths.is_empty() && !spec.read_only_root)
    {
        return Err("invalid writable paths".into());
    }
    for path in &spec.writable_paths {
        validate_writable_path(path)?;
    }
    if spec.labels.len() > 32 {
        return Err("too many labels".into());
    }
    for (key, value) in &spec.labels {
        if key.is_empty()
            || key.len() > 63
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
            || value.len() > 256
            || value.chars().any(char::is_control)
        {
            return Err("invalid label".into());
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WireError {
    Backend(String),
    NotFound(String),
    Io(String),
    Incompatible(String),
}
impl From<RuntimeError> for WireError {
    fn from(e: RuntimeError) -> Self {
        let text: String = e.to_string().chars().take(2048).collect();
        match e {
            RuntimeError::NotFound(_) => Self::NotFound(text),
            RuntimeError::Incompatible(_) => Self::Incompatible(text),
            RuntimeError::Io(_) => Self::Io(text),
            RuntimeError::Backend(_) => Self::Backend(text),
        }
    }
}
impl From<WireError> for RuntimeError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Backend(s) => Self::Backend(s),
            WireError::NotFound(s) => Self::NotFound(s),
            WireError::Incompatible(s) => Self::Incompatible(s),
            WireError::Io(s) => Self::Io(std::io::Error::other(s)),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureInfo {
    pub kept: usize,
    pub total: u64,
    pub known: bool,
    pub truncated: bool,
}
impl CaptureInfo {
    pub fn of(c: &crate::model::Captured) -> Self {
        Self {
            kept: c.data.len(),
            total: c.total_bytes,
            known: c.total_bytes_known,
            truncated: c.truncated(),
        }
    }
    pub fn capture(self, data: Vec<u8>, max: usize) -> std::io::Result<crate::model::Captured> {
        if data.len() != self.kept
            || self.kept > max
            || self.total < self.kept as u64
            || (self.truncated && self.total <= self.kept as u64)
        {
            return Err(std::io::Error::other("invalid helper capture evidence"));
        }
        Ok(crate::model::Captured {
            data,
            total_bytes: self.total,
            total_bytes_known: self.known,
            truncated: self.truncated,
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WireFinish {
    Completed,
    TimedOut,
    Canceled,
    Failed(RuntimeDiagnostic),
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSandbox {
    pub id: String,
    pub stale: bool,
}
impl From<BackendSandbox> for WireSandbox {
    fn from(s: BackendSandbox) -> Self {
        Self {
            id: s.id,
            stale: s.status == BackendStatus::Stale,
        }
    }
}
impl From<WireSandbox> for BackendSandbox {
    fn from(s: WireSandbox) -> Self {
        Self {
            id: s.id,
            status: if s.stale {
                BackendStatus::Stale
            } else {
                BackendStatus::Running
            },
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Version(String),
    Validated,
    Created(String),
    Removed,
    Listed(Vec<WireSandbox>),
    Collected(Vec<String>),
    Executed {
        finish: WireFinish,
        status: Option<CommandStatus>,
        stdout: CaptureInfo,
        stderr: CaptureInfo,
    },
    Error {
        error: WireError,
        definitely_not_created: bool,
    },
}
