//! Private, versioned privilege boundary. No caller-supplied executable or flags.
use crate::model::{
    CommandStatus, Digest, Id128, ResourceReservation, RuntimeDiagnostic, SandboxSpec,
};
use crate::runtime::{BackendSandbox, BackendStatus, RuntimeError};
use crate::validation::{
    MAX_ALLOWLIST_ENTRIES, MAX_WRITABLE_PATHS, MIN_CPU_MILLIS, MIN_DISK_BYTES, MIN_MEMORY_BYTES,
    MIN_PIDS, validate_allowlist_entry, validate_argv, validate_image_name,
    validate_writable_path,
};
use kilnd_exec_core::exec_options::{EnvLimits, EnvVar, ExecOptions, MAX_CWD_BYTES};
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 3;
pub const STDIO_RECEIVED: u8 = 0x4b;

pub const MAX_FRAME: usize = 2 << 20;
pub const MAX_STDIN: usize = 1 << 20;
pub const MAX_OUTPUT: usize = 1 << 20;
pub const MAX_ARGV: usize = 256 << 10;
pub const MAX_GC_IDS: usize = 1024;
/// A unary Exec's helper ceiling: one hour.
pub const MAX_EXEC_MS: u32 = 3_600_000;
/// A live (ExecStream) Exec's helper ceiling, decision 4: four hours.
pub const MAX_LIVE_EXEC_MS: u32 = 14_400_000;
/// The Firecracker group's own schema inside the v3 envelope.
/// Group schema 2 (B7): helper-issued tokens, digests on Inspect, Remove and Gc, and
/// the verified highest token on AttachInstance. Schema 1 daemons are refused.
pub const FIRECRACKER_GROUP_VERSION: u32 = 2;

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
    /// Workspace checkpoints (milestone C3): a separate group, so every kiln and
    /// Firecracker frame and reply is byte-identical, and an older helper closes the
    /// connection on it unanswered.
    Checkpoint(CheckpointRequest),
}

impl KilnRequest {
    /// Health and cleanup keep working when normal operations fill every other slot.
    pub fn is_recovery(&self) -> bool {
        matches!(
            self,
            Self::Capabilities { .. } | Self::Features { .. } | Self::Rm { .. } | Self::Gc { .. }
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
    /// API additions design 4.1: `cwd` and `env` are sandbox-interior data, never host
    /// paths, flags or environment, and are omitted when empty, so a request without
    /// them is byte-identical to before. `env` is the effective overrides, strictly
    /// ascending by name; values are redacted from `Debug`.
    Exec {
        id: String,
        argv: Vec<String>,
        stdin_bytes: usize,
        max_output: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        env: Vec<EnvVar>,
        /// ExecStream (design 5.1): a fourth descriptor, the live socket, and the
        /// four-hour ceiling. Omitted when false, so unary requests are byte-identical.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        live: bool,
    },
    /// The exec features the installed CLI (`id: null`) or one sandbox's PID 1 proves
    /// now, and whether this helper can deliver exec options to it. New in M3b; an
    /// older helper closes the connection on it.
    Features {
        id: Option<String>,
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
            Operation::Checkpoint(request) => {
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
        let ceiling = match op {
            KilnRequest::Exec { live: true, .. } => MAX_LIVE_EXEC_MS,
            KilnRequest::Exec { .. } => MAX_EXEC_MS,
            _ => 120_000,
        };
        if self.version != VERSION || self.timeout_ms == 0 || self.timeout_ms > ceiling {
            return Err("unsupported version or timeout".into());
        }
        if fds != 0 {
            return Err("wrong descriptor count".into());
        }
        match op {
            KilnRequest::Capabilities { id: Some(id) }
            | KilnRequest::Features { id: Some(id) }
            | KilnRequest::Rm { id } => {
                if !crate::runtime::kiln_direct::valid_kiln_id(id) {
                    return Err("invalid backend ID".into());
                }
            }
            KilnRequest::Capabilities { id: None }
            | KilnRequest::Features { id: None }
            | KilnRequest::Ls => {}
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
                cwd,
                env,
                live: _,
            } => {
                if !crate::runtime::kiln_direct::valid_kiln_id(id)
                    || *stdin_bytes > MAX_STDIN
                    || *max_output == 0
                    || *max_output > MAX_OUTPUT
                {
                    return Err("invalid exec bounds".into());
                }
                validate_argv(argv, MAX_ARGV)?;
                // The same shared validators as the daemon, at the code ceilings, in
                // the one strict form kiln accepts: sorted, unique, bounded.
                ExecOptions {
                    cwd: cwd.clone(),
                    env: env.clone(),
                }
                .validate_strict(&EnvLimits::CEILINGS, MAX_CWD_BYTES)?;
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
    /// B7 RTC-14: `highest_token` is the complete token with the highest seq among the
    /// daemon's Firecracker rows and release evidence, or none. There is no bare
    /// sequence field: H and L verify the tag before its seq means anything.
    AttachInstance {
        database_uuid: Id128,
        highest_token: Option<Id128>,
    },
    Capabilities,
    Accounting,
    /// B7 RTC-2: no allocation ID. The helper issues the token and the reply names it.
    Preflight {
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
    /// B7 RTC-8: the plan digest from the daemon Store's immutable binding.
    Inspect {
        allocation_id: Id128,
        plan_digest: Digest,
    },
    List,
    FenceAbsent {
        allocation_id: Id128,
        sandbox_id: String,
        plan_digest: Digest,
    },
    /// Authorized containment: journal the stop, kill the VM subtree and prove it
    /// empty. No disk deletion and never a release. `expected_generation` is the
    /// allocation's C2 generation, naming the exact boot.
    Stop {
        allocation_id: Id128,
        expected_generation: u64,
        reason: StopReason,
    },
    /// Stop, remove exactly the owned resources and persist ABSENT. Idempotent. B7: it
    /// acts only on the journaled resources of a row whose digest is `plan_digest`.
    Remove {
        allocation_id: Id128,
        plan_digest: Digest,
    },
    /// Section 8.2's scoped collection: only named, proven dead or stopped allocations.
    /// B7: each target carries its Store digest; validation is all-or-nothing.
    Gc {
        targets: Vec<GcTarget>,
    },
    /// B5: the broker's process and idle validation. During an execution the recorded
    /// busy state answers, with no guest polling. Never absence on a socket failure.
    Validate {
        allocation_id: Id128,
        expected_boot_id: String,
        expected_inner_id: String,
    },
    /// B5: one execution in the persistent sandbox. The helper hands the caller three
    /// stdio sockets first, as for kiln's Exec. It owns cancellation through the stop
    /// barrier: any interruption after dispatch retires the VM.
    Exec {
        allocation_id: Id128,
        expected_boot_id: String,
        execution_token: Id128,
        execution_id: String,
        argv: Vec<String>,
        stdin_bytes: usize,
        max_output: usize,
    },
    /// Test-only: whether a reusable dispatch would be admitted at this instant. There
    /// is no Exec in B4; this exposes the fence that a later Exec must consult.
    #[cfg(test)]
    TestDispatchProbe {
        allocation_id: Id128,
    },
}

/// One Gc target: an allocation token and the plan digest its Store row binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcTarget {
    pub allocation_id: Id128,
    pub plan_digest: Digest,
}

/// Why a stop was requested. Typed, never free text from a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Delete,
    Interrupted,
    Unhealthy,
    Operator,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Interrupted => "interrupted",
            Self::Unhealthy => "unhealthy",
            Self::Operator => "operator",
        }
    }
}

/// The most allocations one Firecracker Gc may name (section 6.1).
pub const MAX_FIRECRACKER_GC_IDS: usize = 1024;

impl FirecrackerOperation {
    /// Section 6.1's per-operation budget; a wire deadline can only be shorter.
    pub fn timeout_ms(&self) -> u32 {
        match self {
            Self::AttachInstance { .. } | Self::Accounting | Self::Inspect { .. } => 5_000,
            Self::Capabilities => 2_000,
            Self::Preflight { .. } | Self::List | Self::FenceAbsent { .. } | Self::Gc { .. } => {
                30_000
            }
            Self::Create { .. } => 120_000,
            Self::Stop { .. } | Self::Remove { .. } => 60_000,
            Self::Validate { .. } => 5_000,
            Self::Exec { .. } => 3_600_000,
            #[cfg(test)]
            Self::TestDispatchProbe { .. } => 2_000,
        }
    }

    /// Reserved dispatch slots serve these under load: read-only health and the
    /// operations that move an allocation toward proof.
    pub fn is_recovery(&self) -> bool {
        matches!(
            self,
            Self::Capabilities
                | Self::Inspect { .. }
                | Self::FenceAbsent { .. }
                | Self::Stop { .. }
                | Self::Remove { .. }
                | Self::Gc { .. }
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
            FirecrackerOperation::Stop { .. } | FirecrackerOperation::Remove { .. } => Ok(()),
            FirecrackerOperation::Gc { targets } => {
                let unique: std::collections::BTreeSet<_> =
                    targets.iter().map(|t| t.allocation_id).collect();
                if targets.len() > MAX_FIRECRACKER_GC_IDS || unique.len() != targets.len() {
                    return Err("Gc takes at most 1024 unique allocation IDs".into());
                }
                Ok(())
            }
            FirecrackerOperation::Validate {
                expected_boot_id,
                expected_inner_id,
                ..
            } => {
                if kilnd_broker_protocol::BootId::new(expected_boot_id.as_str()).is_none()
                    || kilnd_broker_protocol::InnerId::new(expected_inner_id.as_str()).is_none()
                {
                    return Err("invalid boot or inner sandbox ID".into());
                }
                Ok(())
            }
            FirecrackerOperation::Exec {
                expected_boot_id,
                execution_id,
                argv,
                stdin_bytes,
                max_output,
                ..
            } => {
                if kilnd_broker_protocol::BootId::new(expected_boot_id.as_str()).is_none()
                    || !crate::model::valid_id("ex", execution_id)
                    || *stdin_bytes > MAX_STDIN
                    || *max_output == 0
                    || *max_output > MAX_OUTPUT
                {
                    return Err("invalid exec bounds".into());
                }
                validate_argv(argv, MAX_ARGV)?;
                Ok(())
            }
            #[cfg(test)]
            FirecrackerOperation::TestDispatchProbe { .. } => Ok(()),
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
    /// This instance has used its quota of fences for never-admitted tokens.
    ResourceExhausted,
    /// B7 RTC-3: a valid tag at or above the durable issue pointer. The daemon's charge
    /// stays; the adapter reports it as Incompatible.
    NotIssued,
    /// B7 RTC-14: forward effects are latched node-wide.
    Latched,
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
pub struct WorkersHealth {
    pub ledger: WorkerHealth,
    pub preparation: [WorkerHealth; 2],
    pub monitor: WorkerHealth,
    pub recovery: [WorkerHealth; 2],
    pub supervisors: u64,
    pub ledger_fault: Option<String>,
    /// B7 RTC-16: a durable or in-memory RTC-14 latch. Other instances see only its
    /// kind; the detecting instance also sees that its own token detected it.
    pub node_fault: Option<String>,
    /// B7: a compaction health fault naming a token that cannot be compacted.
    pub compaction_fault: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[serde(rename_all = "snake_case")]
pub enum AccountingReply {
    Fresh(Box<super::firecracker::journal::AccountingSnapshot>),
    Unknown { reason: String },
}

/// The prepared plan's wire form. The client reconstructs and verifies every field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedReply {
    pub node_id: Id128,
    /// B7 RTC-2: the token the helper issued, also bound into the plan's substitutions.
    pub allocation_id: Id128,
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub enum InspectReply {
    /// B5: READY with no execution in flight, on the journaled boot and inner sandbox.
    PresentReady {
        generation: u64,
        boot_id: String,
        inner_id: String,
    },
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

/// B5's Validate: never absence, never a restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidateReply {
    /// The broker answered idle on the journaled boot and inner sandbox.
    Ready { boot_id: String, inner_id: String },
    /// An execution is in flight: the recorded state, without guest polling.
    Busy { execution_token: Id128 },
    /// Another control operation held this allocation's control slot until the
    /// deadline (B5-05). Nothing was asked of the guest; not a breach.
    ControlBusy,
    /// Booted again, another inner sandbox, or not READY.
    Incompatible { message: String },
    /// No proof either way: stays charged and is not reusable.
    Unknown { reason: String },
}

/// How an execution's cleanup was established (design 5.4). `VmStopped` is the host's
/// own proof; the first two are the trusted guest core's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecCleanup {
    NoChildStarted,
    GuestCgroupDrained,
    VmStopped,
    Unknown,
}

/// B5's Exec answer: the typed outcome, both capture facts, and whether the next
/// command may reuse this VM. Output bytes travel only on the stdio sockets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecReply {
    pub finish: WireFinishFc,
    pub status: Option<CommandStatus>,
    pub stdout: CaptureInfo,
    pub stderr: CaptureInfo,
    pub cleanup: ExecCleanup,
    pub reusable: bool,
    /// False only with proof that no Exec byte reached the guest.
    pub dispatched: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFinishFc {
    Completed,
    TimedOut,
    Canceled,
    Failed(RuntimeDiagnostic),
}

/// A host stop receipt, or why there is none. Never a release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReply {
    /// STOPPED is durable: the VM subtree is proven empty and the VMM gone.
    Stopped {
        generation: u64,
        observations: String,
    },
    /// No proof yet. The stop stays requested and the allocation stays charged.
    Unknown { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcOutcome {
    Removed {
        receipt: ReceiptBytes,
    },
    /// Live, quarantined, unknown or another instance's: untouched.
    Skipped {
        reason: String,
    },
    Failed {
        class: AmbiguousClass,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcResult {
    pub allocation_id: Id128,
    pub outcome: GcOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListStatus {
    /// B5: READY and idle.
    Ready,
    Busy,
    StoppedWithResources,
    Stale,
    Quarantined,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRecord {
    pub allocation_id: Id128,
    pub plan_digest: Digest,
    pub generation: u64,
    pub status: ListStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListReply {
    pub generation: u64,
    pub complete: bool,
    pub incomplete_reason: Option<String>,
    pub records: Vec<ListRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    Stop(StopReply),
    /// Remove's answer has Fence's shape: ABSENT's receipt, or charged and ambiguous.
    Remove(FenceReply),
    Gc(Vec<GcResult>),
    Validate(ValidateReply),
    Exec(Box<ExecReply>),
    #[cfg(test)]
    TestDispatch {
        admitted: bool,
    },
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

pub(crate) fn validate_spec(spec: &SandboxSpec) -> Result<(), String> {
    validate_image_name(&spec.image)?;
    if spec.memory_bytes < MIN_MEMORY_BYTES
        || spec.memory_bytes > 8 << 30
        || spec.cpu_millis < MIN_CPU_MILLIS
        || spec.cpu_millis > 8000
        || spec.pids < MIN_PIDS
        || spec.pids > 4096
        || spec.disk_bytes < MIN_DISK_BYTES
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
#[serde(rename_all = "snake_case")]
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
            // The kiln wire has no exhausted class; the helper never produces one.
            RuntimeError::Backend(_) | RuntimeError::Exhausted(_) => Self::Backend(text),
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[serde(rename_all = "snake_case")]
pub enum WireFinish {
    Completed,
    TimedOut,
    Canceled,
    Failed(RuntimeDiagnostic),
}
#[derive(Debug, Serialize, Deserialize)]
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
/// The helper's reply. Replies tolerate unknown fields, so a newer helper that adds an
/// optional field still works with an older daemon; an unknown variant or a missing
/// field still fails to decode. Requests stay strict (`deny_unknown_fields`) because
/// the helper is the privileged side. A type used in both directions, a stored format
/// or root's policy stays strict.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// The answer to `features`: the advertised kiln feature bits, and whether the
    /// helper can deliver exec options (bit 0x20 and a host whose memfds kiln accepts).
    Features {
        features: u32,
        exec_options: bool,
        /// Whether this helper can carry ExecStream's live output (design 5.1). Omitted
        /// when false, so the reply is byte-identical where it cannot.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        exec_stream: bool,
    },
    Error {
        error: WireError,
        definitely_not_created: bool,
        /// A create the backend's own preflight refused (kiln's trusted exit 124):
        /// definitely not created, and the caller's input. Omitted when false, so every
        /// other error reply is byte-identical; daemon and helper upgrade together.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        preflight_refused: bool,
    },
    /// A separate branch: every legacy kiln reply above stays byte-identical.
    Firecracker(FirecrackerResponse),
    /// The checkpoint group's own branch (C3).
    Checkpoint(CheckpointResponse),
}

/// The checkpoint group's wire types (milestone C3) live with its facts, so the runtime
/// adapter can name them.
pub use crate::checkpoint::wire::*;

#[cfg(test)]
mod reply_compat_tests {
    use super::*;
    use crate::checkpoint::{
        ArtifactRecord, ArtifactTarget, CaptureBinding, CheckpointId, CompleteFact, CopyOutcome,
        Evidence, Fact, Reason, SealedEvidence,
    };
    use crate::helper::firecracker::config::{NodeCeilings, ProfileCatalog, SharedReserve};
    use crate::helper::firecracker::journal::{AccountingSnapshot, ClaimTotals, TokenAccounting};
    use crate::model::Network;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    /// The field a newer helper might add to any reply.
    const FUTURE: &str = "future_optional";

    fn refused(reply: Value) {
        assert!(
            serde_json::from_value::<Response>(reply.clone()).is_err(),
            "{reply}"
        );
    }

    fn value(item: impl Serialize) -> Value {
        serde_json::to_value(item).unwrap()
    }

    type Decode = fn(Value) -> serde_json::Result<()>;

    fn decode<T: DeserializeOwned>(item: Value) -> serde_json::Result<()> {
        serde_json::from_value::<T>(item).map(drop)
    }

    /// One named-field boundary: a valid sample, the JSON pointer to the object that type
    /// owns in it, and how the daemon or helper decodes the sample.
    struct Case {
        boundary: &'static str,
        sample: Value,
        at: &'static str,
        decode: Decode,
    }

    fn case(boundary: &'static str, sample: &Value, at: &'static str, decode: Decode) -> Case {
        Case {
            boundary,
            sample: sample.clone(),
            at,
            decode,
        }
    }

    /// `sample` with `FUTURE` added to the object at `at`, which must not have it yet.
    fn injected(sample: &Value, at: &str) -> Value {
        let mut sample = sample.clone();
        let object = sample
            .pointer_mut(at)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("no object at {at:?}"));
        assert!(object.insert(FUTURE.into(), 1.into()).is_none(), "{at}");
        sample
    }

    fn id() -> Id128 {
        Id128::random()
    }

    fn spec() -> SandboxSpec {
        SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 256 << 20,
            cpu_millis: 1000,
            pids: 64,
            disk_bytes: 1 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: Default::default(),
        }
    }

    fn target() -> ArtifactTarget {
        ArtifactTarget {
            instance: id(),
            checkpoint: CheckpointId::random(),
            generation: 1,
        }
    }

    fn evidence(fact: Fact) -> Evidence {
        Evidence {
            version: 1,
            instance: id(),
            checkpoint: CheckpointId::random(),
            generation: 1,
            operation: id(),
            helper_epoch: id(),
            boot_id: id(),
            fact,
        }
    }

    fn sealed(fact: Fact) -> SealedEvidence {
        evidence(fact).seal().unwrap()
    }

    fn complete() -> Fact {
        Fact::Complete(Box::new(CompleteFact {
            source: "ab".into(),
            content_sha256: Digest::of(b"content"),
            binding_sha256: Digest::of(b"binding"),
            image: "alpine".into(),
            image_sha256: Digest::of(b"image"),
            entries: 1,
            logical_bytes: 2,
            allocated_bytes: 3,
            charge_bytes: 4,
            limit_bytes: 1 << 20,
        }))
    }

    fn absent() -> Fact {
        Fact::Absent { existed: true }
    }

    fn reader_ended() -> Fact {
        Fact::ReaderEnded {
            copy: CopyOutcome::Complete,
        }
    }

    fn receipt() -> ReceiptBytes {
        WireBytes(vec![0xab, 0xcd])
    }

    fn prepared() -> Value {
        value(Response::Firecracker(FirecrackerResponse::Prepared(
            Box::new(PreparedReply {
                node_id: id(),
                allocation_id: id(),
                profile: "default".into(),
                manifest_sha256: Digest::of(b"manifest"),
                plan_version: 1,
                plan: WireBytes(vec![1, 2, 3]),
                plan_digest: Digest::of(b"plan"),
                host_spec_sha256: Digest::of(b"host"),
                guest_exec_spec_sha256: Digest::of(b"guest"),
                reservation: ResourceReservation {
                    memory_bytes: 1,
                    disk_bytes: 2,
                    pids: 3,
                    host_cpu_millis: 4,
                    virtual_cpu_slots: 5,
                    host_pids: 6,
                },
            }),
        )))
    }

    fn accounting() -> Value {
        let totals = ClaimTotals {
            slots: 1,
            memory_bytes: 2,
            ..ClaimTotals::default()
        };
        value(Response::Firecracker(FirecrackerResponse::Accounting(
            AccountingReply::Fresh(Box::new(AccountingSnapshot {
                node_id: id(),
                generation: 7,
                ceilings: NodeCeilings::default(),
                shared: SharedReserve::default(),
                claimed: totals,
                committed: totals,
                over_committed: false,
                retired_tokens: 1,
                ledger_bytes: 2,
                tokens: Some(TokenAccounting {
                    issue_next: 3,
                    ..TokenAccounting::default()
                }),
                retained_admitted_total: 4,
                retained_never_admitted_total: 5,
                admitted_entries: 6,
                share: 7,
                share_shortfall: 0,
                node_fault: None,
                degraded: Some("lag".into()),
            })),
        )))
    }

    fn captured(fact: Fact) -> Value {
        value(Response::Checkpoint(CheckpointResponse::Captured(
            Box::new(CaptureReply::Complete {
                evidence: sealed(fact),
            }),
        )))
    }

    /// Every reply-only struct and struct variant, decoded as the daemon decodes a reply.
    /// `corpora_cover_every_named_field_boundary` keeps the list complete.
    fn reply_corpus() -> Vec<Case> {
        let reply = decode::<Response>;
        let fc = |r: FirecrackerResponse| value(Response::Firecracker(r));
        let cp = |r: CheckpointResponse| value(Response::Checkpoint(r));
        let capture = CaptureInfo {
            kept: 1,
            total: 2,
            known: true,
            truncated: true,
        };
        let executed = value(Response::Executed {
            finish: WireFinish::Completed,
            status: Some(CommandStatus::Exited(0)),
            stdout: capture.clone(),
            stderr: capture.clone(),
        });
        let health = WorkerHealth::Healthy;
        let capabilities = fc(FirecrackerResponse::Capabilities(CapabilitiesReply {
            group_version: FIRECRACKER_GROUP_VERSION,
            broker_protocol: 1,
            helper_version: "0.1.0".into(),
            enabled: true,
            launch_enabled: false,
            profiles: vec!["default".into()],
            health: Some(WorkersHealth {
                ledger: health,
                preparation: [health; 2],
                monitor: health,
                recovery: [health; 2],
                supervisors: 1,
                ledger_fault: None,
                node_fault: None,
                compaction_fault: Some("stuck".into()),
            }),
        }));
        let accounting = accounting();
        let create = |r| fc(FirecrackerResponse::Create(r));
        let fence = |r| fc(FirecrackerResponse::Fence(r));
        let inspect = |r| fc(FirecrackerResponse::Inspect(r));
        let validate = |r| fc(FirecrackerResponse::Validate(r));
        let stop = |r| fc(FirecrackerResponse::Stop(r));
        let gc = |outcome| {
            fc(FirecrackerResponse::Gc(vec![GcResult {
                allocation_id: id(),
                outcome,
            }]))
        };
        let list = fc(FirecrackerResponse::List(ListReply {
            generation: 3,
            complete: false,
            incomplete_reason: Some("bound".into()),
            records: vec![ListRecord {
                allocation_id: id(),
                plan_digest: Digest::of(b"plan"),
                generation: 2,
                status: ListStatus::Ready,
            }],
        }));
        let exec = fc(FirecrackerResponse::Exec(Box::new(ExecReply {
            finish: WireFinishFc::Completed,
            status: Some(CommandStatus::Exited(1)),
            stdout: capture.clone(),
            stderr: capture,
            cleanup: ExecCleanup::GuestCgroupDrained,
            reusable: true,
            dispatched: true,
        })));
        let detail = || "detail".to_string();
        let checkpoint_capabilities = cp(CheckpointResponse::Capabilities(Box::new(
            CheckpointCapabilities {
                group_version: crate::checkpoint::GROUP_VERSION,
                enabled: true,
                helper_epoch: Some(id()),
                boot_id: Some(id()),
                format_version: 1,
                supported: true,
                unsupported_reason: None,
                limits: HelperLimits {
                    copy_workers: 1,
                    cleanup_workers: 2,
                    max_tracked_artifacts: 3,
                    max_settled_operations: 4,
                    max_inventory_entries: 5,
                    helper_ceiling_ms: 6,
                    tombstone_quiet_ms: 7,
                },
                copy_workers_busy: 0,
                cleanup_workers_busy: 0,
                untracked_workers: 0,
                storage: Some(StorageFree {
                    runs_free_bytes: 8,
                    backing_free_bytes: Some(9),
                }),
                removal_supported: true,
            },
        )));
        let captured_complete = captured(complete());
        let captured_failed = cp(CheckpointResponse::Captured(Box::new(
            CaptureReply::Failed {
                reason: Reason::Busy,
                detail: detail(),
            },
        )));
        let restored = |r| cp(CheckpointResponse::Restored(Box::new(r)));
        let removed = |r| cp(CheckpointResponse::Removed(Box::new(r)));
        let source = |r| cp(CheckpointResponse::Source(Box::new(r)));
        let activity = Activity {
            exclusive: Some(ExclusiveOp {
                kind: OpKind::Capture,
                operation: id(),
            }),
            readers: vec![id()],
            tombstone: None,
            untracked_workers: false,
        };
        let inspected = |artifact| {
            cp(CheckpointResponse::Inspected(Box::new(
                ArtifactInspectReply {
                    helper_epoch: id(),
                    artifact,
                    activity: activity.clone(),
                    operation: Some(OperationState::Settled(Box::new(
                        CheckpointResponse::Error(CheckpointError::new(
                            CheckpointErrorKind::Busy,
                            "busy",
                        )),
                    ))),
                },
            )))
        };
        let published = inspected(ArtifactView::Published {
            record: ArtifactRecord {
                instance: id(),
                checkpoint: CheckpointId::random(),
                generation: 1,
                content_sha256: Digest::of(b"content"),
                binding_sha256: Digest::of(b"binding"),
                image: "alpine".into(),
                image_sha256: Digest::of(b"image"),
                entries: 1,
                logical_bytes: 2,
                allocated_bytes: 3,
                charge_bytes: 4,
                limit_bytes: 5,
            },
        });
        let inventory = cp(CheckpointResponse::Inventory(Box::new(InventoryReply {
            helper_epoch: id(),
            complete: true,
            incomplete_reason: None,
            entries: vec![InventoryEntry {
                checkpoint: CheckpointId::random(),
                kind: ItemKind::Staging,
            }],
            unknown_entries: 0,
            other_entries: 1,
            tracked: vec![TrackedArtifact {
                checkpoint: CheckpointId::random(),
                generation: 2,
                activity: Activity::default(),
            }],
            untracked_workers: vec![CheckpointId::random()],
        })));
        let checkpoint_error = cp(CheckpointResponse::Error(CheckpointError::new(
            CheckpointErrorKind::Capacity,
            "full",
        )));
        let (class, message) = (AmbiguousClass::Capacity, "full".to_string());
        vec![
            // The kiln group and the envelope.
            case("Response::Executed", &executed, "/executed", reply),
            case("CaptureInfo", &executed, "/executed/stdout", reply),
            case("CaptureInfo", &executed, "/executed/stderr", reply),
            case(
                "Response::Features",
                &value(Response::Features {
                    features: 0x20,
                    exec_options: true,
                    exec_stream: true,
                }),
                "/features",
                reply,
            ),
            case(
                "Response::Error",
                &value(Response::Error {
                    error: WireError::Backend("refused".into()),
                    definitely_not_created: true,
                    preflight_refused: true,
                }),
                "/error",
                reply,
            ),
            case(
                "WireSandbox",
                &value(Response::Listed(vec![WireSandbox {
                    id: "ab".into(),
                    stale: true,
                }])),
                "/listed/0",
                reply,
            ),
            // The Firecracker group.
            case(
                "FirecrackerResponse::Attached",
                &fc(FirecrackerResponse::Attached {
                    node_id: id(),
                    connection_epoch: id(),
                    admission_open: true,
                }),
                "/firecracker/attached",
                reply,
            ),
            case(
                "FirecrackerResponse::TestDispatch",
                &fc(FirecrackerResponse::TestDispatch { admitted: true }),
                "/firecracker/test_dispatch",
                reply,
            ),
            case(
                "GroupError",
                &fc(FirecrackerResponse::Error(GroupError::new(
                    GroupErrorKind::Unavailable,
                    "unavailable",
                ))),
                "/firecracker/error",
                reply,
            ),
            case(
                "CapabilitiesReply",
                &capabilities,
                "/firecracker/capabilities",
                reply,
            ),
            case(
                "WorkersHealth",
                &capabilities,
                "/firecracker/capabilities/health",
                reply,
            ),
            case(
                "AccountingSnapshot",
                &accounting,
                "/firecracker/accounting/fresh",
                reply,
            ),
            case(
                "ClaimTotals",
                &accounting,
                "/firecracker/accounting/fresh/claimed",
                reply,
            ),
            case(
                "ClaimTotals",
                &accounting,
                "/firecracker/accounting/fresh/committed",
                reply,
            ),
            case(
                "TokenAccounting",
                &accounting,
                "/firecracker/accounting/fresh/tokens",
                reply,
            ),
            case(
                "AccountingReply::Unknown",
                &fc(FirecrackerResponse::Accounting(AccountingReply::Unknown {
                    reason: "ledger".into(),
                })),
                "/firecracker/accounting/unknown",
                reply,
            ),
            case("PreparedReply", &prepared(), "/firecracker/prepared", reply),
            case(
                "CreateReply::Accepted",
                &create(CreateReply::Accepted {
                    generation: 1,
                    phase: "intent".into(),
                    replay: false,
                }),
                "/firecracker/create/accepted",
                reply,
            ),
            case(
                "CreateReply::Absent",
                &create(CreateReply::Absent { receipt: receipt() }),
                "/firecracker/create/absent",
                reply,
            ),
            case(
                "CreateReply::Ambiguous",
                &create(CreateReply::Ambiguous {
                    class,
                    message: message.clone(),
                }),
                "/firecracker/create/ambiguous",
                reply,
            ),
            case(
                "FenceReply::Absent",
                &fence(FenceReply::Absent { receipt: receipt() }),
                "/firecracker/fence/absent",
                reply,
            ),
            case(
                "FenceReply::Ambiguous",
                &fc(FirecrackerResponse::Remove(FenceReply::Ambiguous {
                    class,
                    message: message.clone(),
                })),
                "/firecracker/remove/ambiguous",
                reply,
            ),
            case(
                "InspectReply::PresentReady",
                &inspect(InspectReply::PresentReady {
                    generation: 1,
                    boot_id: "boot".into(),
                    inner_id: "inner".into(),
                }),
                "/firecracker/inspect/present_ready",
                reply,
            ),
            case(
                "InspectReply::PresentBusy",
                &inspect(InspectReply::PresentBusy {
                    generation: 1,
                    phase: "booting".into(),
                    plan_digest: Some(Digest::of(b"plan")),
                }),
                "/firecracker/inspect/present_busy",
                reply,
            ),
            case(
                "InspectReply::StoppedWithResources",
                &inspect(InspectReply::StoppedWithResources { generation: 1 }),
                "/firecracker/inspect/stopped_with_resources",
                reply,
            ),
            case(
                "InspectReply::AbsentFenced",
                &inspect(InspectReply::AbsentFenced { receipt: receipt() }),
                "/firecracker/inspect/absent_fenced",
                reply,
            ),
            case(
                "InspectReply::Incompatible",
                &inspect(InspectReply::Incompatible {
                    message: "schema".into(),
                }),
                "/firecracker/inspect/incompatible",
                reply,
            ),
            case(
                "InspectReply::Unknown",
                &inspect(InspectReply::Unknown {
                    reason: "stale".into(),
                }),
                "/firecracker/inspect/unknown",
                reply,
            ),
            case(
                "ValidateReply::Ready",
                &validate(ValidateReply::Ready {
                    boot_id: "boot".into(),
                    inner_id: "inner".into(),
                }),
                "/firecracker/validate/ready",
                reply,
            ),
            case(
                "ValidateReply::Busy",
                &validate(ValidateReply::Busy {
                    execution_token: id(),
                }),
                "/firecracker/validate/busy",
                reply,
            ),
            case(
                "ValidateReply::Incompatible",
                &validate(ValidateReply::Incompatible {
                    message: "booted again".into(),
                }),
                "/firecracker/validate/incompatible",
                reply,
            ),
            case(
                "ValidateReply::Unknown",
                &validate(ValidateReply::Unknown {
                    reason: "socket".into(),
                }),
                "/firecracker/validate/unknown",
                reply,
            ),
            case("ExecReply", &exec, "/firecracker/exec", reply),
            case("CaptureInfo", &exec, "/firecracker/exec/stdout", reply),
            case(
                "StopReply::Stopped",
                &stop(StopReply::Stopped {
                    generation: 1,
                    observations: "empty".into(),
                }),
                "/firecracker/stop/stopped",
                reply,
            ),
            case(
                "StopReply::Unknown",
                &stop(StopReply::Unknown {
                    reason: "pending".into(),
                }),
                "/firecracker/stop/unknown",
                reply,
            ),
            case(
                "GcResult",
                &gc(GcOutcome::Skipped {
                    reason: "live".into(),
                }),
                "/firecracker/gc/0",
                reply,
            ),
            case(
                "GcOutcome::Removed",
                &gc(GcOutcome::Removed { receipt: receipt() }),
                "/firecracker/gc/0/outcome/removed",
                reply,
            ),
            case(
                "GcOutcome::Skipped",
                &gc(GcOutcome::Skipped {
                    reason: "live".into(),
                }),
                "/firecracker/gc/0/outcome/skipped",
                reply,
            ),
            case(
                "GcOutcome::Failed",
                &gc(GcOutcome::Failed { class, message }),
                "/firecracker/gc/0/outcome/failed",
                reply,
            ),
            case("ListReply", &list, "/firecracker/list", reply),
            case("ListRecord", &list, "/firecracker/list/records/0", reply),
            // The checkpoint group.
            case(
                "CheckpointCapabilities",
                &checkpoint_capabilities,
                "/checkpoint/capabilities",
                reply,
            ),
            case(
                "HelperLimits",
                &checkpoint_capabilities,
                "/checkpoint/capabilities/limits",
                reply,
            ),
            case(
                "StorageFree",
                &checkpoint_capabilities,
                "/checkpoint/capabilities/storage",
                reply,
            ),
            case(
                "CaptureReply::Complete",
                &captured_complete,
                "/checkpoint/captured/complete",
                reply,
            ),
            case(
                "SealedEvidence",
                &captured_complete,
                "/checkpoint/captured/complete/evidence",
                reply,
            ),
            case(
                "CaptureReply::Failed",
                &captured_failed,
                "/checkpoint/captured/failed",
                reply,
            ),
            case(
                "RestoreReply::Created",
                &restored(RestoreReply::Created {
                    backend_id: "ab".into(),
                    evidence: sealed(reader_ended()),
                }),
                "/checkpoint/restored/created",
                reply,
            ),
            case(
                "RestoreReply::NotCreated",
                &restored(RestoreReply::NotCreated {
                    reason: Reason::ImageUnavailable,
                    detail: detail(),
                    evidence: sealed(reader_ended()),
                }),
                "/checkpoint/restored/not_created",
                reply,
            ),
            case(
                "RestoreReply::Ambiguous",
                &restored(RestoreReply::Ambiguous {
                    reason: Reason::Busy,
                    detail: detail(),
                    evidence: sealed(reader_ended()),
                }),
                "/checkpoint/restored/ambiguous",
                reply,
            ),
            case(
                "RemoveReply::Absent",
                &removed(RemoveReply::Absent {
                    evidence: sealed(absent()),
                }),
                "/checkpoint/removed/absent",
                reply,
            ),
            case(
                "RemoveReply::Retained",
                &removed(RemoveReply::Retained {
                    reason: Reason::Busy,
                    detail: detail(),
                }),
                "/checkpoint/removed/retained",
                reply,
            ),
            case(
                "SourceReply::Capable",
                &source(SourceReply::Capable {
                    image: "alpine".into(),
                    image_sha256: Digest::of(b"image"),
                }),
                "/checkpoint/source/capable",
                reply,
            ),
            case(
                "SourceReply::Unsupported",
                &source(SourceReply::Unsupported {
                    reason: Reason::LayoutUnsupported,
                    detail: detail(),
                }),
                "/checkpoint/source/unsupported",
                reply,
            ),
            case(
                "ArtifactInspectReply",
                &published,
                "/checkpoint/inspected",
                reply,
            ),
            case(
                "ArtifactView::Published",
                &published,
                "/checkpoint/inspected/artifact/published",
                reply,
            ),
            case(
                "ArtifactRecord",
                &published,
                "/checkpoint/inspected/artifact/published/record",
                reply,
            ),
            case(
                "Activity",
                &published,
                "/checkpoint/inspected/activity",
                reply,
            ),
            case(
                "ExclusiveOp",
                &published,
                "/checkpoint/inspected/activity/exclusive",
                reply,
            ),
            case(
                "CheckpointError",
                &published,
                "/checkpoint/inspected/operation/settled/error",
                reply,
            ),
            case(
                "ArtifactView::Unreadable",
                &inspected(ArtifactView::Unreadable {
                    reason: Reason::MetadataUnsupported,
                    detail: detail(),
                }),
                "/checkpoint/inspected/artifact/unreadable",
                reply,
            ),
            case(
                "ArtifactView::Partial",
                &inspected(ArtifactView::Partial {
                    staging: 1,
                    removing: 2,
                }),
                "/checkpoint/inspected/artifact/partial",
                reply,
            ),
            case("InventoryReply", &inventory, "/checkpoint/inventory", reply),
            case(
                "InventoryEntry",
                &inventory,
                "/checkpoint/inventory/entries/0",
                reply,
            ),
            case(
                "TrackedArtifact",
                &inventory,
                "/checkpoint/inventory/tracked/0",
                reply,
            ),
            case(
                "Activity",
                &inventory,
                "/checkpoint/inventory/tracked/0/activity",
                reply,
            ),
            case(
                "CheckpointError",
                &checkpoint_error,
                "/checkpoint/error",
                reply,
            ),
        ]
    }

    /// A newer helper adds an optional field to a reply: this daemon ignores it at every
    /// reply-only struct and struct variant, top-level or nested, and keeps every field
    /// it knows.
    #[test]
    fn replies_tolerate_unknown_fields() {
        let mut failures = Vec::new();
        for Case {
            boundary,
            sample,
            at,
            decode,
        } in reply_corpus()
        {
            assert!(decode(sample.clone()).is_ok(), "{boundary}: {sample}");
            match serde_json::from_value::<Response>(injected(&sample, at)) {
                Ok(decoded) if value(&decoded) == sample => {}
                Ok(decoded) => failures.push(format!(
                    "{boundary} at {at}: decoded as {}",
                    value(&decoded)
                )),
                Err(e) => failures.push(format!("{boundary} at {at}: {e}")),
            }
        }
        assert!(
            failures.is_empty(),
            "replies that refuse a new optional field:\n{}",
            failures.join("\n")
        );
    }

    /// Every request struct and struct variant, and the stored, journalled, policy and
    /// plan types: decoded where the helper or daemon decodes them, alone or nested
    /// inside a tolerant reply. `corpora_cover_every_named_field_boundary` keeps the list
    /// complete.
    fn strict_corpus() -> Vec<Case> {
        let request = decode::<Request>;
        let reply = decode::<Response>;
        let envelope = |operation| {
            value(Request {
                version: VERSION,
                timeout_ms: 1000,
                deadline_ns: 1,
                operation,
            })
        };
        let kiln = |r| envelope(Operation::Kiln(r));
        let fc = |operation| {
            envelope(Operation::Firecracker(FirecrackerRequest {
                group_version: FIRECRACKER_GROUP_VERSION,
                instance_id: id(),
                connection_epoch: Some(id()),
                operation,
            }))
        };
        let cp = |operation| {
            envelope(Operation::Checkpoint(CheckpointRequest {
                group_version: crate::checkpoint::GROUP_VERSION,
                helper_epoch: Some(id()),
                operation,
            }))
        };
        let rm = kiln(KilnRequest::Rm { id: "ab".into() });
        let kiln_create = kiln(KilnRequest::Create { spec: spec() });
        let preflight = fc(FirecrackerOperation::Preflight {
            sandbox_id: "sb-0123456789abcdef".into(),
            profile: "default".into(),
            spec: spec(),
        });
        let fc_gc = fc(FirecrackerOperation::Gc {
            targets: vec![GcTarget {
                allocation_id: id(),
                plan_digest: Digest::of(b"plan"),
            }],
        });
        let capture = cp(CheckpointOperation::Capture {
            binding: CaptureBinding {
                target: target(),
                operation: id(),
                source: "ab".into(),
                limit_bytes: 1 << 20,
            },
        });
        let restore = cp(CheckpointOperation::Restore {
            target: target(),
            content_sha256: Digest::of(b"content"),
            reader: id(),
            spec: spec(),
        });
        let prepared = prepared();
        let accounting = accounting();
        let stored_absent = value(evidence(absent()));
        let stored_reader = value(evidence(reader_ended()));
        let stored_complete = value(evidence(complete()));
        let captured_complete = captured(complete());
        let removed_absent = value(Response::Checkpoint(CheckpointResponse::Removed(Box::new(
            RemoveReply::Absent {
                evidence: sealed(absent()),
            },
        ))));
        let restored = value(Response::Checkpoint(CheckpointResponse::Restored(
            Box::new(RestoreReply::Created {
                backend_id: "ab".into(),
                evidence: sealed(reader_ended()),
            }),
        )));
        vec![
            // Requests: the helper is the privileged side.
            case("Request", &rm, "", request),
            case(
                "KilnRequest::Capabilities",
                &kiln(KilnRequest::Capabilities {
                    id: Some("ab".into()),
                }),
                "/operation/kiln/capabilities",
                request,
            ),
            case(
                "KilnRequest::Create",
                &kiln_create,
                "/operation/kiln/create",
                request,
            ),
            case(
                "SandboxSpec",
                &kiln_create,
                "/operation/kiln/create/spec",
                request,
            ),
            case(
                "KilnRequest::Exec",
                &kiln(KilnRequest::Exec {
                    id: "ab".into(),
                    argv: vec!["true".into()],
                    stdin_bytes: 0,
                    max_output: 1024,
                    cwd: Some("/".into()),
                    env: vec![],
                    live: true,
                }),
                "/operation/kiln/exec",
                request,
            ),
            case(
                "KilnRequest::Features",
                &kiln(KilnRequest::Features { id: None }),
                "/operation/kiln/features",
                request,
            ),
            case("KilnRequest::Rm", &rm, "/operation/kiln/rm", request),
            case(
                "KilnRequest::Gc",
                &kiln(KilnRequest::Gc {
                    ids: vec!["ab".into()],
                }),
                "/operation/kiln/gc",
                request,
            ),
            case(
                "FirecrackerRequest",
                &fc(FirecrackerOperation::List),
                "/operation/firecracker",
                request,
            ),
            case(
                "FirecrackerOperation::AttachInstance",
                &fc(FirecrackerOperation::AttachInstance {
                    database_uuid: id(),
                    highest_token: Some(id()),
                }),
                "/operation/firecracker/operation/attach_instance",
                request,
            ),
            case(
                "FirecrackerOperation::Preflight",
                &preflight,
                "/operation/firecracker/operation/preflight",
                request,
            ),
            case(
                "SandboxSpec",
                &preflight,
                "/operation/firecracker/operation/preflight/spec",
                request,
            ),
            case(
                "FirecrackerOperation::Create",
                &fc(FirecrackerOperation::Create {
                    allocation_id: id(),
                    sandbox_id: "sb-0123456789abcdef".into(),
                    plan: WireBytes(vec![1]),
                    plan_digest: Digest::of(b"plan"),
                }),
                "/operation/firecracker/operation/create",
                request,
            ),
            case(
                "FirecrackerOperation::Inspect",
                &fc(FirecrackerOperation::Inspect {
                    allocation_id: id(),
                    plan_digest: Digest::of(b"plan"),
                }),
                "/operation/firecracker/operation/inspect",
                request,
            ),
            case(
                "FirecrackerOperation::FenceAbsent",
                &fc(FirecrackerOperation::FenceAbsent {
                    allocation_id: id(),
                    sandbox_id: "sb-0123456789abcdef".into(),
                    plan_digest: Digest::of(b"plan"),
                }),
                "/operation/firecracker/operation/fence_absent",
                request,
            ),
            case(
                "FirecrackerOperation::Stop",
                &fc(FirecrackerOperation::Stop {
                    allocation_id: id(),
                    expected_generation: 1,
                    reason: StopReason::Delete,
                }),
                "/operation/firecracker/operation/stop",
                request,
            ),
            case(
                "FirecrackerOperation::Remove",
                &fc(FirecrackerOperation::Remove {
                    allocation_id: id(),
                    plan_digest: Digest::of(b"plan"),
                }),
                "/operation/firecracker/operation/remove",
                request,
            ),
            case(
                "FirecrackerOperation::Gc",
                &fc_gc,
                "/operation/firecracker/operation/gc",
                request,
            ),
            case(
                "GcTarget",
                &fc_gc,
                "/operation/firecracker/operation/gc/targets/0",
                request,
            ),
            case(
                "FirecrackerOperation::Validate",
                &fc(FirecrackerOperation::Validate {
                    allocation_id: id(),
                    expected_boot_id: "boot".into(),
                    expected_inner_id: "inner".into(),
                }),
                "/operation/firecracker/operation/validate",
                request,
            ),
            case(
                "FirecrackerOperation::Exec",
                &fc(FirecrackerOperation::Exec {
                    allocation_id: id(),
                    expected_boot_id: "boot".into(),
                    execution_token: id(),
                    execution_id: "ex-0123456789abcdef".into(),
                    argv: vec!["true".into()],
                    stdin_bytes: 0,
                    max_output: 1024,
                }),
                "/operation/firecracker/operation/exec",
                request,
            ),
            case(
                "FirecrackerOperation::TestDispatchProbe",
                &fc(FirecrackerOperation::TestDispatchProbe {
                    allocation_id: id(),
                }),
                "/operation/firecracker/operation/test_dispatch_probe",
                request,
            ),
            case(
                "CheckpointRequest",
                &capture,
                "/operation/checkpoint",
                request,
            ),
            case(
                "CheckpointOperation::Capture",
                &capture,
                "/operation/checkpoint/operation/capture",
                request,
            ),
            case(
                "CaptureBinding",
                &capture,
                "/operation/checkpoint/operation/capture/binding",
                request,
            ),
            case(
                "ArtifactTarget",
                &capture,
                "/operation/checkpoint/operation/capture/binding/target",
                request,
            ),
            case(
                "CheckpointOperation::Restore",
                &restore,
                "/operation/checkpoint/operation/restore",
                request,
            ),
            case(
                "ArtifactTarget",
                &restore,
                "/operation/checkpoint/operation/restore/target",
                request,
            ),
            case(
                "SandboxSpec",
                &restore,
                "/operation/checkpoint/operation/restore/spec",
                request,
            ),
            case(
                "CheckpointOperation::Inspect",
                &cp(CheckpointOperation::Inspect {
                    target: target(),
                    verify: true,
                    operation: Some(id()),
                }),
                "/operation/checkpoint/operation/inspect",
                request,
            ),
            case(
                "CheckpointOperation::Remove",
                &cp(CheckpointOperation::Remove {
                    target: target(),
                    operation: id(),
                }),
                "/operation/checkpoint/operation/remove",
                request,
            ),
            case(
                "CheckpointOperation::Inventory",
                &cp(CheckpointOperation::Inventory { instance: id() }),
                "/operation/checkpoint/operation/inventory",
                request,
            ),
            case(
                "CheckpointOperation::Source",
                &cp(CheckpointOperation::Source {
                    backend_id: "ab".into(),
                }),
                "/operation/checkpoint/operation/source",
                request,
            ),
            case(
                "CheckpointOperation::Acknowledge",
                &cp(CheckpointOperation::Acknowledge {
                    target: target(),
                    operation: id(),
                }),
                "/operation/checkpoint/operation/acknowledge",
                request,
            ),
            // The spec as stored in `sandboxes.spec`.
            case("SandboxSpec", &value(spec()), "", decode::<SandboxSpec>),
            // The reservation: stored, and inside the prepared plan's reply.
            case(
                "ResourceReservation",
                &value(ResourceReservation::default()),
                "",
                decode::<ResourceReservation>,
            ),
            case(
                "ResourceReservation",
                &prepared,
                "/firecracker/prepared/reservation",
                reply,
            ),
            // Root's policy, alone and inside the accounting reply.
            case(
                "NodeCeilings",
                &value(NodeCeilings::default()),
                "",
                decode::<NodeCeilings>,
            ),
            case(
                "NodeCeilings",
                &accounting,
                "/firecracker/accounting/fresh/ceilings",
                reply,
            ),
            case(
                "SharedReserve",
                &value(SharedReserve::default()),
                "",
                decode::<SharedReserve>,
            ),
            case(
                "SharedReserve",
                &accounting,
                "/firecracker/accounting/fresh/shared",
                reply,
            ),
            case(
                "ProfileCatalog",
                &value(ProfileCatalog {
                    profile: "default".into(),
                    approved_manifest_sha256: Digest::of(b"manifest"),
                    bundle_directory: "/var/lib/bundle".into(),
                    exec_store: "/var/lib/exec".into(),
                    catalog_generation: 1,
                    installation_generations: Default::default(),
                }),
                "",
                decode::<ProfileCatalog>,
            ),
            // Checkpoint evidence: stored as strict `Evidence` bytes, and carried inside
            // the tolerant `SealedEvidence` of a reply.
            case("Evidence", &stored_absent, "", decode::<Evidence>),
            case(
                "Evidence",
                &captured_complete,
                "/checkpoint/captured/complete/evidence/evidence",
                reply,
            ),
            case(
                "Fact::Absent",
                &stored_absent,
                "/fact/absent",
                decode::<Evidence>,
            ),
            case(
                "Fact::Absent",
                &removed_absent,
                "/checkpoint/removed/absent/evidence/evidence/fact/absent",
                reply,
            ),
            case(
                "Fact::ReaderEnded",
                &stored_reader,
                "/fact/reader_ended",
                decode::<Evidence>,
            ),
            case(
                "Fact::ReaderEnded",
                &restored,
                "/checkpoint/restored/created/evidence/evidence/fact/reader_ended",
                reply,
            ),
            case(
                "CompleteFact",
                &stored_complete,
                "/fact/complete",
                decode::<Evidence>,
            ),
            case(
                "CompleteFact",
                &captured_complete,
                "/checkpoint/captured/complete/evidence/evidence/fact/complete",
                reply,
            ),
        ]
    }

    /// Requests stay strict because the helper is the privileged side; stored,
    /// journalled, policy and plan types stay strict wherever they are decoded, even
    /// nested inside a tolerant reply. A dropped field there would be a wrong charge or
    /// an unverified fact.
    #[test]
    fn strict_types_refuse_unknown_fields() {
        let unknown = format!("unknown field `{FUTURE}`");
        let mut failures = Vec::new();
        for Case {
            boundary,
            sample,
            at,
            decode,
        } in strict_corpus()
        {
            assert!(decode(sample.clone()).is_ok(), "{boundary}: {sample}");
            match decode(injected(&sample, at)) {
                Err(e) if e.to_string().contains(&unknown) => {}
                Err(e) => failures.push(format!("{boundary} at {at:?}: another error: {e}")),
                Ok(()) => failures.push(format!("{boundary} at {at:?}: accepted")),
            }
        }
        assert!(
            failures.is_empty(),
            "strict types that accept an unknown field:\n{}",
            failures.join("\n")
        );
    }

    /// The files whose `Deserialize` types the corpora cover. Any type in them that
    /// tolerates unknown fields must be in the reply corpus.
    const SOURCES: [(&str, &str); 6] = [
        ("helper/protocol.rs", include_str!("protocol.rs")),
        ("checkpoint/wire.rs", include_str!("../checkpoint/wire.rs")),
        ("checkpoint.rs", include_str!("../checkpoint.rs")),
        ("model.rs", include_str!("../model.rs")),
        (
            "helper/firecracker/journal.rs",
            include_str!("firecracker/journal.rs"),
        ),
        (
            "helper/firecracker/config.rs",
            include_str!("firecracker/config.rs"),
        ),
    ];

    /// The files whose strict types must all be in the strict corpus: the requests, the
    /// checkpoint facts and the reservation. The journal's and the policy file's own
    /// strict formats have their own tests.
    const STRICT_SOURCES: [&str; 4] = [
        "helper/protocol.rs",
        "checkpoint/wire.rs",
        "checkpoint.rs",
        "model.rs",
    ];

    /// Strict types the strict corpus covers from elsewhere: root's policy types a reply
    /// or the policy carries, and the spec (kilnd-exec-core), in requests and stored.
    const STRICT_ELSEWHERE: [&str; 4] = [
        "NodeCeilings",
        "SharedReserve",
        "ProfileCatalog",
        "SandboxSpec",
    ];

    /// The named-field boundaries a file's `Deserialize` types declare, and whether each
    /// denies unknown fields: `Type` for a struct with named fields, `Type::Variant` for
    /// an enum's struct variant. A line-based reading of rustfmt'd source, comment lines
    /// dropped first.
    fn boundaries(source: &str) -> Vec<(String, bool)> {
        let ident = |text: &str| -> String {
            text.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        };
        let lines: Vec<&str> = source
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect();
        let mut found = Vec::new();
        let mut attributes = String::new();
        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("#[") {
                attributes.push_str(line);
                continue;
            }
            let attributes = std::mem::take(&mut attributes);
            let item = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub(super) "))
                .or_else(|| line.strip_prefix("pub "))
                .unwrap_or(line);
            let Some((kind, rest)) = item.split_once(' ') else {
                continue;
            };
            if !matches!(kind, "struct" | "enum") || !attributes.contains("Deserialize") {
                continue;
            }
            let deny = attributes.contains("deny_unknown_fields");
            let name = ident(rest);
            let after = &rest[name.len()..];
            if kind == "struct" {
                let brace = after.find('{');
                if brace.is_some_and(|b| after.find(['(', ';']).is_none_or(|p| b < p)) {
                    found.push((name, deny));
                }
                continue;
            }
            // An enum: its variants are the lines one brace deep.
            let mut depth = 0usize;
            for line in &lines[i..] {
                if depth == 1 {
                    let variant = ident(line);
                    if !variant.is_empty() && line[variant.len()..].trim_start().starts_with('{') {
                        found.push((format!("{name}::{variant}"), deny));
                    }
                }
                depth += line.matches('{').count();
                depth -= line.matches('}').count();
                if depth == 0 {
                    break;
                }
            }
        }
        found
    }

    /// The corpora name exactly the boundaries the source declares: a type made tolerant
    /// or strict, or a new reply or request type, fails here until its case is added on
    /// the right side.
    #[test]
    fn corpora_cover_every_named_field_boundary() {
        let mut tolerant = BTreeSet::new();
        let mut strict: BTreeSet<String> = STRICT_ELSEWHERE.map(String::from).into();
        for (file, source) in SOURCES {
            for (boundary, deny) in boundaries(source) {
                if !deny {
                    tolerant.insert(boundary);
                } else if STRICT_SOURCES.contains(&file) {
                    strict.insert(boundary);
                }
            }
        }
        let named = |corpus: Vec<Case>| -> BTreeSet<String> {
            corpus.iter().map(|c| c.boundary.to_string()).collect()
        };
        let replies = named(reply_corpus());
        let stricts = named(strict_corpus());
        let missing: Vec<_> = tolerant.difference(&replies).collect();
        let extra: Vec<_> = replies.difference(&tolerant).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "tolerant types without a reply case: {missing:?}; reply cases for types that are not tolerant: {extra:?}"
        );
        let missing: Vec<_> = strict.difference(&stricts).collect();
        let extra: Vec<_> = stricts.difference(&strict).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "strict types without a strict case: {missing:?}; strict cases for types that are not strict: {extra:?}"
        );
        // The policy types the strict corpus names are strict in their own file too.
        let (_, config) = SOURCES
            .iter()
            .find(|(file, _)| *file == "helper/firecracker/config.rs")
            .unwrap();
        for (boundary, deny) in boundaries(config) {
            if STRICT_ELSEWHERE.contains(&boundary.as_str()) {
                assert!(deny, "{boundary}");
            }
        }
    }

    /// Tolerance is for fields only: a reply this daemon cannot name still fails.
    #[test]
    fn replies_refuse_unknown_variants() {
        refused(json!({"future_reply": {}}));
        refused(json!("future_reply"));
        refused(json!({"error": {
            "error": {"future_class": "x"},
            "definitely_not_created": true,
        }}));
        refused(json!({"executed": {
            "finish": "future_finish",
            "status": null,
            "stdout": {"kept": 0, "total": 0, "known": true, "truncated": false},
            "stderr": {"kept": 0, "total": 0, "known": true, "truncated": false},
        }}));
        refused(json!({"firecracker": {"future": {}}}));
        refused(json!({"firecracker": {"create": {"ready": {"generation": 1}}}}));
        refused(json!({"firecracker": {"create": {"ambiguous": {
            "class": "future_class", "message": "m",
        }}}}));
        refused(json!({"checkpoint": {"future": {}}}));
        refused(json!({"checkpoint": {"error": {"kind": "future_kind", "message": "m"}}}));
    }

    /// No field gained a default: a reply missing a required field still fails.
    #[test]
    fn replies_refuse_missing_fields() {
        refused(json!({"error": {"error": {"backend": "x"}}}));
        refused(json!({"error": {"definitely_not_created": true}}));
        refused(json!({"features": {"features": 0}}));
        refused(json!({"executed": {
            "finish": "completed",
            "status": null,
            "stdout": {"kept": 0, "total": 0, "known": true},
            "stderr": {"kept": 0, "total": 0, "known": true, "truncated": false},
        }}));
        refused(json!({"listed": [{"id": "ab"}]}));
        refused(json!({"firecracker": {"create": {"ambiguous": {"class": "capacity"}}}}));
        refused(json!({"firecracker": {"error": {"kind": "unavailable"}}}));
        refused(json!({"checkpoint": {"error": {"kind": "busy"}}}));
    }
}
