//! Private, versioned privilege boundary. No caller-supplied executable or flags.
use crate::model::{
    CommandStatus, Digest, Id128, ResourceReservation, RuntimeDiagnostic, SandboxSpec,
};
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
/// The Firecracker group's own schema inside the v3 envelope.
pub const FIRECRACKER_GROUP_VERSION: u32 = 1;

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
    Firecracker(FirecrackerRequest),
}

impl KilnRequest {
    /// Health and cleanup keep working when normal operations fill every other slot.
    pub fn is_recovery(&self) -> bool {
        matches!(
            self,
            Self::Capabilities { .. } | Self::Rm { .. } | Self::Gc { .. }
        )
    }
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
        let op = match &self.operation {
            Operation::Kiln(op) => op,
            Operation::Firecracker(request) => {
                if self.version != VERSION
                    || self.timeout_ms == 0
                    || self.timeout_ms > request.operation.timeout_ms()
                {
                    return Err("unsupported version or timeout".into());
                }
                if fds != 0 {
                    return Err("wrong descriptor count".into());
                }
                return request.validate();
            }
        };
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

/// Lowercase hexadecimal bytes on the wire, bounded before anything is allocated. No
/// other spelling decodes, so one logical value has exactly one encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireBytes<const MAX: usize>(pub Vec<u8>);

impl<const MAX: usize> Serialize for WireBytes<MAX> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(self.0.len() * 2);
        for byte in &self.0 {
            use std::fmt::Write;
            write!(text, "{byte:02x}").expect("writing to a string");
        }
        s.serialize_str(&text)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for WireBytes<MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let text = String::deserialize(d)?;
        if text.len() % 2 != 0 || text.len() > MAX * 2 {
            return Err(D::Error::custom("hexadecimal bytes outside their bound"));
        }
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(D::Error::custom("bytes must be lowercase hexadecimal")),
        };
        let mut bytes = Vec::with_capacity(text.len() / 2);
        for pair in text.as_bytes().as_chunks::<2>().0 {
            bytes.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
        }
        Ok(Self(bytes))
    }
}

pub type PlanBytes = WireBytes<{ crate::runtime::MAX_BACKEND_PLAN_BYTES }>;
pub type ReceiptBytes = WireBytes<{ crate::runtime::MAX_RECEIPT_BYTES }>;

/// One Firecracker request, always strict JSON within the v3 frame. Every operation
/// but AttachInstance carries the helper-issued epoch of the live attachment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerRequest {
    pub group_version: u32,
    pub instance_id: Id128,
    pub connection_epoch: Option<Id128>,
    pub operation: FirecrackerOperation,
}

/// The whole B3 surface. There is no path, UID, CID, PID, flag, command, environment
/// or descriptor anywhere in these fields, and no raw verb or fixture selector.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FirecrackerOperation {
    AttachInstance {
        database_uuid: Id128,
    },
    Capabilities,
    Accounting,
    Preflight {
        allocation_id: Id128,
        sandbox_id: String,
        profile: String,
        spec: SandboxSpec,
    },
    Create {
        allocation_id: Id128,
        sandbox_id: String,
        plan: PlanBytes,
        plan_digest: Digest,
    },
    Inspect {
        allocation_id: Id128,
    },
    List,
    FenceAbsent {
        allocation_id: Id128,
        sandbox_id: String,
        plan_digest: Digest,
    },
}

impl FirecrackerOperation {
    /// Section 6.1's per-operation budget; a wire deadline can only be shorter.
    pub fn timeout_ms(&self) -> u32 {
        match self {
            Self::AttachInstance { .. } | Self::Accounting | Self::Inspect { .. } => 5_000,
            Self::Capabilities => 2_000,
            Self::Preflight { .. } | Self::List | Self::FenceAbsent { .. } => 30_000,
            Self::Create { .. } => 120_000,
        }
    }

    /// Reserved dispatch slots serve these under load: read-only health and the
    /// operations that move an allocation toward proof.
    pub fn is_recovery(&self) -> bool {
        matches!(
            self,
            Self::Capabilities | Self::Inspect { .. } | Self::FenceAbsent { .. }
        )
    }
}

impl FirecrackerRequest {
    fn validate(&self) -> Result<(), String> {
        if self.group_version != FIRECRACKER_GROUP_VERSION {
            return Err("unsupported Firecracker group version".into());
        }
        let attach = matches!(self.operation, FirecrackerOperation::AttachInstance { .. });
        if attach != self.connection_epoch.is_none() {
            return Err("connection epoch is required exactly after attachment".into());
        }
        let sandbox = |id: &str| {
            if crate::model::valid_id("sb", id) {
                Ok(())
            } else {
                Err("invalid sandbox ID".to_string())
            }
        };
        match &self.operation {
            FirecrackerOperation::AttachInstance { .. }
            | FirecrackerOperation::Capabilities
            | FirecrackerOperation::Accounting
            | FirecrackerOperation::Inspect { .. }
            | FirecrackerOperation::List => Ok(()),
            FirecrackerOperation::Preflight {
                sandbox_id,
                profile,
                spec,
                ..
            } => {
                sandbox(sandbox_id)?;
                if !crate::helper::firecracker::config::valid_profile(profile) {
                    return Err("invalid profile name".into());
                }
                validate_spec(spec)
            }
            // P verifies the digest with everything else: H hashes nothing.
            FirecrackerOperation::Create {
                sandbox_id, plan, ..
            } => {
                sandbox(sandbox_id)?;
                if plan.0.is_empty() {
                    return Err("empty plan".into());
                }
                Ok(())
            }
            FirecrackerOperation::FenceAbsent { sandbox_id, .. } => sandbox(sandbox_id),
        }
    }
}

/// Why a token that passed C1 was rejected or could not be answered. Each of these
/// keeps the daemon charged; none can stand in for an absence receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguousClass {
    Collision,
    CatalogMismatch,
    Expired,
    WorkerPanic,
    Capacity,
    OldEpoch,
    AdmissionBlocked,
    WorkerExhausted,
    LedgerUnavailable,
    MonitorUnavailable,
    Conflict,
    GateClosed,
    Pending,
    PermitsUnsettled,
    ResourcesPresent,
    ObservationUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupErrorKind {
    Disabled,
    Invalid,
    StaleEpoch,
    AlreadyAttached,
    OwnershipConflict,
    Unavailable,
    ResourceExhausted,
    Incompatible,
    /// Not root-enrolled, or the connecting process is not the enrolled service.
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupError {
    pub kind: GroupErrorKind,
    pub message: String,
}

impl GroupError {
    pub fn new(kind: GroupErrorKind, message: impl Into<String>) -> Self {
        let message: String = message.into().chars().take(2048).collect();
        Self { kind, message }
    }
}

/// One worker class's state as H last knew it, without any identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHealth {
    Healthy,
    Busy,
    Stalled,
    Dead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkersHealth {
    pub ledger: WorkerHealth,
    pub preparation: [WorkerHealth; 2],
    pub monitor: WorkerHealth,
    pub recovery: [WorkerHealth; 2],
    pub supervisors: u64,
    pub ledger_fault: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesReply {
    pub group_version: u32,
    pub broker_protocol: u32,
    pub helper_version: String,
    pub enabled: bool,
    /// Always false in B3: no operation here can launch a VM.
    pub launch_enabled: bool,
    pub profiles: Vec<String>,
    pub health: Option<WorkersHealth>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountingReply {
    Fresh(Box<super::firecracker::journal::AccountingSnapshot>),
    Unknown { reason: String },
}

/// The prepared plan's wire form. The client reconstructs and verifies every field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedReply {
    pub node_id: Id128,
    pub profile: String,
    pub manifest_sha256: Digest,
    pub plan_version: u32,
    pub plan: PlanBytes,
    pub plan_digest: Digest,
    pub host_spec_sha256: Digest,
    pub guest_exec_spec_sha256: Digest,
    pub reservation: ResourceReservation,
}

/// B3 has no READY variant at all: fake effects cannot publish one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CreateReply {
    /// Durable INTENT and claim exist; `replay` means no second claim was made.
    Accepted {
        generation: u64,
        phase: String,
        replay: bool,
    },
    /// The token's permanent fence, byte for byte as first committed.
    Absent { receipt: ReceiptBytes },
    /// Charged until the exact token has an ABSENT receipt.
    Ambiguous {
        class: AmbiguousClass,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FenceReply {
    Absent {
        receipt: ReceiptBytes,
    },
    Ambiguous {
        class: AmbiguousClass,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InspectReply {
    PresentBusy {
        generation: u64,
        phase: String,
        plan_digest: Option<Digest>,
    },
    StoppedWithResources {
        generation: u64,
    },
    AbsentFenced {
        receipt: ReceiptBytes,
    },
    Incompatible {
        message: String,
    },
    /// No record, a stale source or a stop in progress. Never absence.
    Unknown {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListStatus {
    Busy,
    StoppedWithResources,
    Stale,
    Quarantined,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRecord {
    pub allocation_id: Id128,
    pub plan_digest: Digest,
    pub generation: u64,
    pub status: ListStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReply {
    pub generation: u64,
    pub complete: bool,
    pub incomplete_reason: Option<String>,
    pub records: Vec<ListRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FirecrackerResponse {
    Attached {
        node_id: Id128,
        connection_epoch: Id128,
        /// False when another database once owned this namespace.
        admission_open: bool,
    },
    Capabilities(CapabilitiesReply),
    Accounting(AccountingReply),
    Prepared(Box<PreparedReply>),
    Create(CreateReply),
    Inspect(InspectReply),
    List(ListReply),
    Fence(FenceReply),
    Error(GroupError),
}

impl FirecrackerResponse {
    /// The safe default: without a root policy the group exists but does nothing.
    pub fn disabled(operation: &FirecrackerOperation) -> Self {
        match operation {
            FirecrackerOperation::Capabilities => Self::Capabilities(CapabilitiesReply {
                group_version: FIRECRACKER_GROUP_VERSION,
                broker_protocol: 1,
                helper_version: env!("CARGO_PKG_VERSION").into(),
                enabled: false,
                launch_enabled: false,
                profiles: vec![],
                health: None,
            }),
            _ => Self::Error(GroupError::new(
                GroupErrorKind::Disabled,
                "the Firecracker backend is disabled on this helper",
            )),
        }
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
            RuntimeError::Incompatible(_) | RuntimeError::Unsupported(_) => {
                Self::Incompatible(text)
            }
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
    /// A separate branch: every legacy kiln reply above stays byte-identical.
    Firecracker(FirecrackerResponse),
}
