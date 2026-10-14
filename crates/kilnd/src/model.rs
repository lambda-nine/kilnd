//! kilnd's own types, independent of the wire format and of any backend.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// What a caller asked for, with every default filled in. Stored as JSON in
/// the `sandboxes.spec` column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxState {
    Creating,
    Ready,
    Deleting,
    Deleted,
    Failed,
    Lost,
}

impl SandboxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
            Self::Lost => "lost",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "creating" => Self::Creating,
            "ready" => Self::Ready,
            "deleting" => Self::Deleting,
            "deleted" => Self::Deleted,
            "failed" => Self::Failed,
            "lost" => Self::Lost,
            _ => return None,
        })
    }

    /// States that hold, or may hold, backend resources.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Creating | Self::Ready | Self::Deleting)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sandbox {
    pub id: String,
    pub state: SandboxState,
    pub spec: SandboxSpec,
    pub backend: String,
    pub backend_id: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
    pub failure_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionState {
    Running,
    Exited,
    TimedOut,
    Canceled,
    Failed,
    Interrupted,
}

impl ExecutionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Exited => "exited",
            Self::TimedOut => "timed_out",
            Self::Canceled => "canceled",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "running" => Self::Running,
            "exited" => Self::Exited,
            "timed_out" => Self::TimedOut,
            "canceled" => Self::Canceled,
            "failed" => Self::Failed,
            "interrupted" => Self::Interrupted,
            _ => return None,
        })
    }
}

/// The first bytes of one output stream and how much there was in total.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub data: Vec<u8>,
    pub total_bytes: u64,
}

impl Captured {
    pub fn truncated(&self) -> bool {
        self.total_bytes > self.data.len() as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    pub id: String,
    pub sandbox_id: String,
    pub argv: Vec<String>,
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub failure_reason: Option<String>,
    pub started_at_ms: i64,
    pub finished_at_ms: Option<i64>,
    pub timeout_ms: u32,
    pub stdin_bytes: u64,
    pub stdout: Captured,
    pub stderr: Captured,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A random ID like `sb-1f3a9c0d5e7b2a46`: a two-letter kind, then 64 bits
/// from the kernel's CSPRNG in hex.
pub fn new_id(kind: &str) -> String {
    use std::io::Read;
    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("read /dev/urandom");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{kind}-{hex}")
}

/// Checks the shape of an ID before it reaches a query or a log line.
pub fn valid_id(kind: &str, id: &str) -> bool {
    id.len() == kind.len() + 17
        && id.starts_with(kind)
        && id.as_bytes()[kind.len()] == b'-'
        && id[kind.len() + 1..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_a_fixed_shape() {
        let id = new_id("sb");
        assert!(valid_id("sb", &id), "{id}");
        assert!(!valid_id("ex", &id));
        assert_ne!(id, new_id("sb"));
        for bad in ["", "sb-", "sb-1234", "sb-1f3a9c0d5e7b2a4G", "sb_1f3a9c0d5e7b2a46", "sb-1f3a9c0d5e7b2a46/"] {
            assert!(!valid_id("sb", bad), "{bad}");
        }
    }

    #[test]
    fn states_round_trip() {
        for s in [
            SandboxState::Creating,
            SandboxState::Ready,
            SandboxState::Deleting,
            SandboxState::Deleted,
            SandboxState::Failed,
            SandboxState::Lost,
        ] {
            assert_eq!(SandboxState::parse(s.as_str()), Some(s));
        }
        for s in [
            ExecutionState::Running,
            ExecutionState::Exited,
            ExecutionState::TimedOut,
            ExecutionState::Canceled,
            ExecutionState::Failed,
            ExecutionState::Interrupted,
        ] {
            assert_eq!(ExecutionState::parse(s.as_str()), Some(s));
        }
    }
}
