//! The message set of broker protocol version 1 (design 5.3). Control payloads are
//! strict JSON objects with `deny_unknown_fields`; `Stdin`, `Stdout` and `Stderr` are
//! raw bytes. Every message has a `validate` that bounds its fields, run on decode and
//! before encode, so neither side sends or accepts what the other must refuse.

use serde::{Deserialize, Serialize};

use kilnd_exec_core::model::{CommandStatus, RuntimeErrorKind, RuntimeStage};

use crate::error::{ProtocolError, Result};
use crate::header::Kind;
use crate::json;
use crate::types::{BootId, ExecutionId, Hex32, Id128, InnerId, SandboxId, WireText, WorkUuid};
use crate::{
    MAX_ARGC, MAX_ARGV_BYTES, MAX_OUTPUT_BYTES, MAX_REMAINING_MS, MAX_STDIN_BYTES, PROTOCOL_VERSION,
};

/// What a connection is for, named in its `Hello`. A connection carries exactly one
/// operation: an exec channel one execution, a control channel one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Exec,
    Control,
}

/// The session the host expects to reach: the identity fields of the vdc record that
/// the host derives from its own journal (all of them but the work UUID).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub sandbox_id: SandboxId,
    pub boot_nonce: Hex32,
    pub manifest_sha256: Hex32,
    pub launch_sha256: Hex32,
    pub guest_exec_spec_sha256: Hex32,
}

/// The vdc identity record (contract `identity.fields`), as the guest read it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestIdentity {
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub sandbox_id: SandboxId,
    pub boot_nonce: Hex32,
    pub manifest_sha256: Hex32,
    pub launch_sha256: Hex32,
    pub work_uuid: WorkUuid,
    pub guest_exec_spec_sha256: Hex32,
}

impl GuestIdentity {
    pub fn binding(&self) -> SessionBinding {
        SessionBinding {
            instance_id: self.instance_id,
            allocation_id: self.allocation_id,
            sandbox_id: self.sandbox_id.clone(),
            boot_nonce: self.boot_nonce,
            manifest_sha256: self.manifest_sha256,
            launch_sha256: self.launch_sha256,
            guest_exec_spec_sha256: self.guest_exec_spec_sha256,
        }
    }
}

/// `Hello` (1): one per connection, before anything else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol: u32,
    pub channel: Channel,
    pub challenge: Hex32,
    pub expected: SessionBinding,
}

/// The kiln CLI's negotiated persistent-exec protocol and feature bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KilnFacts {
    pub protocol: u32,
    pub features: u32,
}

/// `/init`'s runtime-hardening checks (kiln-guest `runtime_contract`), each of which
/// must hold before the broker starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hardening {
    pub cmdline: bool,
    pub kernel_log_bounded: bool,
    pub kaslr: bool,
    pub memory_initialization: bool,
    pub kstack_offset: bool,
    pub lockdown_confidentiality: bool,
    pub kexec_absent: bool,
}

impl Hardening {
    pub fn all(&self) -> bool {
        self.cmdline
            && self.kernel_log_bounded
            && self.kaslr
            && self.memory_initialization
            && self.kstack_offset
            && self.lockdown_confidentiality
            && self.kexec_absent
    }
}

/// The private work mount as the guest observes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkMount {
    pub uuid: WorkUuid,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub prjquota: bool,
}

/// The broker's state machine (design B5): Uninitialized, Initializing, Idle,
/// Executing, Draining and back to Idle; Faulted is terminal until the VM stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerState {
    Uninitialized,
    Initializing,
    Idle,
    Executing,
    Draining,
    Faulted,
}

/// `HelloReply` (2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReply {
    pub protocol: u32,
    pub challenge: Hex32,
    pub identity: GuestIdentity,
    pub boot_id: BootId,
    pub broker_sha256: Hex32,
    pub kiln: KilnFacts,
    pub hardening: Hardening,
    pub work: WorkMount,
    pub state: BrokerState,
    pub inner_id: Option<InnerId>,
}

/// The exact label-free execution spec: kilnd's `SandboxSpec` without labels, whose
/// canonical JSON digest is `guest_exec_spec_sha256` (B1 contract).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestExecSpec {
    pub image: String,
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub pids: u32,
    pub disk_bytes: u64,
    pub network: String,
    pub read_only_root: bool,
    pub writable_paths: Vec<String>,
}

impl GuestExecSpec {
    /// B1's `validate_guest_exec_spec`: the offline profile only.
    pub fn validate(&self) -> Result<()> {
        if self.image != "alpine"
            || self.network != "none"
            || self.memory_bytes == 0
            || self.memory_bytes > 512 * 1024 * 1024
            || self.cpu_millis == 0
            || self.cpu_millis > 1000
            || self.pids == 0
            || self.disk_bytes == 0
            || self.writable_paths.len() > 16
            || (!self.writable_paths.is_empty() && !self.read_only_root)
        {
            return Err(ProtocolError::InvalidField("execution spec"));
        }
        for (i, path) in self.writable_paths.iter().enumerate() {
            kilnd_exec_core::validation::validate_writable_path(path)
                .map_err(|_| ProtocolError::InvalidField("writable path"))?;
            if self.writable_paths[..i].contains(path) {
                return Err(ProtocolError::InvalidField("duplicate writable path"));
            }
        }
        Ok(())
    }

    /// B1's canonical JSON: sorted keys, compact, ASCII with Python-style escapes.
    pub fn canonical_json(&self) -> Vec<u8> {
        let mut out = String::from("{");
        out.push_str(&format!("\"cpu_millis\":{},", self.cpu_millis));
        out.push_str(&format!("\"disk_bytes\":{},", self.disk_bytes));
        out.push_str("\"image\":");
        canonical_string(&mut out, &self.image);
        out.push_str(&format!(",\"memory_bytes\":{},", self.memory_bytes));
        out.push_str("\"network\":");
        canonical_string(&mut out, &self.network);
        out.push_str(&format!(",\"pids\":{},", self.pids));
        out.push_str(&format!("\"read_only_root\":{},", self.read_only_root));
        out.push_str("\"writable_paths\":[");
        for (i, path) in self.writable_paths.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            canonical_string(&mut out, path);
        }
        out.push_str("]}");
        out.into_bytes()
    }

    pub fn sha256(&self) -> Hex32 {
        Hex32::sha256(&self.canonical_json())
    }
}

/// B1's canonical string: printable ASCII as itself, short escapes, every other
/// scalar as lowercase `\uXXXX` UTF-16 units.
pub(crate) fn canonical_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            _ => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// `Initialize` (3): once per cold boot, after `Hello`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Initialize {
    pub spec: GuestExecSpec,
    pub guest_exec_spec_sha256: Hex32,
}

/// `Ready` (4): after the persistent create and a supervised `true` smoke exec drained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub binding: SessionBinding,
    pub boot_id: BootId,
    pub inner_id: InnerId,
    pub kiln: KilnFacts,
    pub idle: bool,
    pub work_quota_verified: bool,
}

/// `Probe` (5): no create, restart or mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub boot_id: BootId,
    pub inner_id: InnerId,
}

/// `ProbeReply` (6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReply {
    pub boot_id: BootId,
    pub inner_id: InnerId,
    pub state: BrokerState,
    pub active: Option<Id128>,
}

/// `Exec` (7): only on an exec channel of an initialized idle broker. Its request ID
/// is the execution token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exec {
    pub token: Id128,
    pub execution_id: ExecutionId,
    pub argv: Vec<String>,
    pub stdin_bytes: u64,
    pub max_output: u64,
    pub remaining_ms: u64,
}

impl Exec {
    pub fn validate(&self) -> Result<()> {
        if self.argv.len() > MAX_ARGC {
            return Err(ProtocolError::FieldBound("argv count"));
        }
        kilnd_exec_core::validation::validate_argv(&self.argv, MAX_ARGV_BYTES)
            .map_err(|_| ProtocolError::InvalidField("argv"))?;
        if self.stdin_bytes > MAX_STDIN_BYTES {
            return Err(ProtocolError::FieldBound("stdin_bytes"));
        }
        if self.max_output > MAX_OUTPUT_BYTES {
            return Err(ProtocolError::FieldBound("max_output"));
        }
        if self.remaining_ms == 0 || self.remaining_ms > MAX_REMAINING_MS {
            return Err(ProtocolError::FieldBound("remaining_ms"));
        }
        Ok(())
    }
}

/// `Accepted` (8): the token was accepted, not a promise that a child started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub token: Id128,
}

/// `StdinEnd` (10): exactly the declared bytes were sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdinEnd {
    pub token: Id128,
    pub total: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    Timeout,
    Disconnect,
    Delete,
    Shutdown,
    Protocol,
}

/// `Cancel` (11): idempotent on the active token, never another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub token: Id128,
    pub reason: CancelReason,
}

/// `CancelAck` (12): not cleanup proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelAck {
    pub token: Id128,
    pub active: bool,
}

/// How an execution finished (design 5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Finish {
    Completed,
    TimedOut,
    Canceled,
    Failed {
        kind: RuntimeErrorKind,
        stage: RuntimeStage,
    },
}

/// One stream's capture facts: kept prefix length, observed total, whether the total
/// is exact, and whether the retention limit discarded observed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFacts {
    pub kept: u64,
    pub total: u64,
    pub total_known: bool,
    pub truncated: bool,
}

impl CaptureFacts {
    fn validate(&self) -> Result<()> {
        if self.kept > MAX_OUTPUT_BYTES || self.kept > self.total {
            return Err(ProtocolError::InvalidField("capture facts"));
        }
        // As kilnd counts it: truncation is exactly "observed more than was kept".
        if self.truncated != (self.total > self.kept) {
            return Err(ProtocolError::InvalidField("capture truncation"));
        }
        Ok(())
    }
}

/// How the command itself ended, independent of `Finish` (design 5.4). kilnd's
/// `CommandStatus` without its lenient serde shape: unknown fields are refused here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Termination {
    Exited { code: i32 },
    Signaled { signal: i32, core_dumped: bool },
}

impl From<&CommandStatus> for Termination {
    fn from(status: &CommandStatus) -> Self {
        match *status {
            CommandStatus::Exited(code) => Self::Exited { code },
            CommandStatus::Signaled {
                signal,
                core_dumped,
            } => Self::Signaled {
                signal,
                core_dumped,
            },
        }
    }
}

impl From<Termination> for CommandStatus {
    fn from(termination: Termination) -> Self {
        match termination {
            Termination::Exited { code } => Self::Exited(code),
            Termination::Signaled {
                signal,
                core_dumped,
            } => Self::Signaled {
                signal,
                core_dumped,
            },
        }
    }
}

/// Cleanup evidence only trusted guest core logic may claim (design 5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cleanup {
    NoChildStarted,
    GuestCgroupDrained,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub kind: RuntimeErrorKind,
    pub stage: RuntimeStage,
    pub message: WireText,
    pub message_truncated: bool,
}

/// `Result` (15): one final frame, then a clean write EOF.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecResult {
    pub token: Id128,
    pub finish: Finish,
    pub termination: Option<Termination>,
    pub diagnostic: Option<Diagnostic>,
    pub stdout: CaptureFacts,
    pub stderr: CaptureFacts,
    pub cleanup: Cleanup,
    pub inner_id: InnerId,
}

impl ExecResult {
    pub fn validate(&self) -> Result<()> {
        self.stdout.validate()?;
        self.stderr.validate()?;
        match self.termination {
            Some(Termination::Exited { code }) if !(0..=255).contains(&code) => {
                Err(ProtocolError::InvalidField("exit code"))
            }
            Some(Termination::Signaled { signal, .. }) if !(1..=64).contains(&signal) => {
                Err(ProtocolError::InvalidField("signal"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The peer broke this protocol.
    Protocol,
    /// Refused before dispatch: busy, not initialized or faulted.
    Admission,
    /// The expected identity, protocol or capability does not match.
    Incompatible,
    /// The broker cannot say; never an inference of success or absence.
    Internal,
}

/// `Error` (16): a bounded typed protocol, admission or incompatibility error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorReply {
    pub code: ErrorCode,
    pub state: BrokerState,
    pub message: WireText,
}

/// One decoded frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    HelloReply(Box<HelloReply>),
    Initialize(Initialize),
    Ready(Box<Ready>),
    Probe(Probe),
    ProbeReply(ProbeReply),
    Exec(Exec),
    Accepted(Accepted),
    Stdin(Vec<u8>),
    StdinEnd(StdinEnd),
    Cancel(Cancel),
    CancelAck(CancelAck),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Result(Box<ExecResult>),
    Error(ErrorReply),
}

impl Message {
    pub fn kind(&self) -> Kind {
        match self {
            Message::Hello(_) => Kind::Hello,
            Message::HelloReply(_) => Kind::HelloReply,
            Message::Initialize(_) => Kind::Initialize,
            Message::Ready(_) => Kind::Ready,
            Message::Probe(_) => Kind::Probe,
            Message::ProbeReply(_) => Kind::ProbeReply,
            Message::Exec(_) => Kind::Exec,
            Message::Accepted(_) => Kind::Accepted,
            Message::Stdin(_) => Kind::Stdin,
            Message::StdinEnd(_) => Kind::StdinEnd,
            Message::Cancel(_) => Kind::Cancel,
            Message::CancelAck(_) => Kind::CancelAck,
            Message::Stdout(_) => Kind::Stdout,
            Message::Stderr(_) => Kind::Stderr,
            Message::Result(_) => Kind::Result,
            Message::Error(_) => Kind::Error,
        }
    }

    /// Field bounds beyond what the types already enforce.
    pub fn validate(&self) -> Result<()> {
        match self {
            Message::Hello(hello) if hello.protocol != PROTOCOL_VERSION => {
                Err(ProtocolError::InvalidField("protocol"))
            }
            Message::HelloReply(reply) if reply.protocol != PROTOCOL_VERSION => {
                Err(ProtocolError::InvalidField("protocol"))
            }
            Message::Initialize(init) => init.spec.validate(),
            Message::Exec(exec) => exec.validate(),
            Message::StdinEnd(end) if end.total > MAX_STDIN_BYTES => {
                Err(ProtocolError::FieldBound("stdin total"))
            }
            Message::Result(result) => result.validate(),
            _ => Ok(()),
        }
    }

    /// Decodes and validates a payload whose header was already checked.
    pub fn decode(kind: Kind, payload: Vec<u8>) -> Result<Self> {
        let message = match kind {
            Kind::Stdin => Message::Stdin(payload),
            Kind::Stdout => Message::Stdout(payload),
            Kind::Stderr => Message::Stderr(payload),
            Kind::Hello => Message::Hello(json::from_slice(&payload)?),
            Kind::HelloReply => Message::HelloReply(Box::new(json::from_slice(&payload)?)),
            Kind::Initialize => Message::Initialize(json::from_slice(&payload)?),
            Kind::Ready => Message::Ready(Box::new(json::from_slice(&payload)?)),
            Kind::Probe => Message::Probe(json::from_slice(&payload)?),
            Kind::ProbeReply => Message::ProbeReply(json::from_slice(&payload)?),
            Kind::Exec => Message::Exec(json::from_slice(&payload)?),
            Kind::Accepted => Message::Accepted(json::from_slice(&payload)?),
            Kind::StdinEnd => Message::StdinEnd(json::from_slice(&payload)?),
            Kind::Cancel => Message::Cancel(json::from_slice(&payload)?),
            Kind::CancelAck => Message::CancelAck(json::from_slice(&payload)?),
            Kind::Result => Message::Result(Box::new(json::from_slice(&payload)?)),
            Kind::Error => Message::Error(json::from_slice(&payload)?),
        };
        message.validate()?;
        Ok(message)
    }

    /// The payload bytes. Validates first, so a sender cannot emit a message its peer
    /// must refuse; the frame encoder then checks the encoded size against the bound.
    pub fn encode_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(match self {
            Message::Stdin(bytes) | Message::Stdout(bytes) | Message::Stderr(bytes) => {
                bytes.clone()
            }
            Message::Hello(m) => json::to_vec(m),
            Message::HelloReply(m) => json::to_vec(m),
            Message::Initialize(m) => json::to_vec(m),
            Message::Ready(m) => json::to_vec(m),
            Message::Probe(m) => json::to_vec(m),
            Message::ProbeReply(m) => json::to_vec(m),
            Message::Exec(m) => json::to_vec(m),
            Message::Accepted(m) => json::to_vec(m),
            Message::StdinEnd(m) => json::to_vec(m),
            Message::Cancel(m) => json::to_vec(m),
            Message::CancelAck(m) => json::to_vec(m),
            Message::Result(m) => json::to_vec(m),
            Message::Error(m) => json::to_vec(m),
        })
    }
}
