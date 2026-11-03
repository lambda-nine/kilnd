//! kilnd's own types, independent of the wire format and of any backend.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// Phase 1b B5 moved these to the direct-kiln core crate, which the guest broker shares.
pub use kilnd_exec_core::model::{
    Captured, CleanupEvidence, CommandStatus, Network, RuntimeDiagnostic, RuntimeErrorKind,
    RuntimeStage, SandboxDisposition, SandboxSpec,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxState {
    Creating,
    Ready,
    Deleting,
    Deleted,
    Failed,
    Lost,
    /// A backend may still own resources, but cleanup or reuse cannot be
    /// established. Refuses Exec and stays charged until Delete proves absence.
    Quarantined,
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
            Self::Quarantined => "quarantined",
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
            "quarantined" => Self::Quarantined,
            _ => return None,
        })
    }

    /// States that hold, or may hold, backend resources.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Ready | Self::Deleting | Self::Quarantined
        )
    }
}

/// What a failed create proved about backend allocation. Only the runtime's
/// typed result can establish `DefinitelyNotCreated`; every other path,
/// including all rows older than schema 5, stays `AllocationAmbiguous`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CreateCertainty {
    /// The backend proved the failure preceded any allocation.
    DefinitelyNotCreated,
    /// A backend may exist without kilnd knowing its ID.
    #[default]
    AllocationAmbiguous,
}

impl CreateCertainty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefinitelyNotCreated => "definitely_not_created",
            Self::AllocationAmbiguous => "allocation_ambiguous",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "definitely_not_created" => Self::DefinitelyNotCreated,
            "allocation_ambiguous" => Self::AllocationAmbiguous,
            _ => return None,
        })
    }
}

fn parse_lower_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N], String> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(format!(
            "{what} must be exactly {} lowercase hexadecimal digits",
            N * 2
        ));
    }
    let nibble = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = nibble(bytes[2 * i]) << 4 | nibble(bytes[2 * i + 1]);
    }
    Ok(out)
}

fn write_lower_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

/// A typed 128-bit identity: instance, allocation, node, receipt or execution
/// token. The only text form is 32 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id128([u8; 16]);

impl Id128 {
    pub fn random() -> Self {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("read /dev/urandom");
        Self(bytes)
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        parse_lower_hex(value, "128-bit ID").map(Self)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Id128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, f)
    }
}

impl fmt::Debug for Id128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Id128 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Id128 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// A typed SHA-256 digest. The only text form is 64 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::digest(bytes).into())
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        parse_lower_hex(value, "SHA-256 digest").map(Self)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, f)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// Effective host commitments, stored independently of the spec. `pids` is the
/// conservative aggregate; `host_pids` is a component of it, not another amount
/// to add. Zero CPU, vCPU and host-PID values on a legacy row mean "not
/// reserved", never "free of cost".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReservation {
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub pids: u64,
    pub host_cpu_millis: u64,
    pub virtual_cpu_slots: u64,
    pub host_pids: u64,
}

impl ResourceReservation {
    /// The exact amounts schema 7 charged for a kiln sandbox.
    pub fn legacy_for_spec(spec: &SandboxSpec) -> Self {
        Self {
            memory_bytes: spec.memory_bytes,
            disk_bytes: spec.disk_bytes,
            pids: u64::from(spec.pids),
            ..Self::default()
        }
    }
}

/// Which release rule governs a row. It is fixed at reservation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountingRegime {
    /// Schema 7 semantics with an explicit stored release tag.
    #[default]
    Legacy,
    /// Every release after C1 needs a matching durable ABSENT receipt.
    AbsenceFenced,
}

/// Explicit legacy release provenance, computed only from schema 7's predicate.
/// It can never satisfy an absence-fenced row's evidence reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyRelease {
    Deleted,
    /// Compensation proved the exact recorded backend ID gone.
    Compensated,
    /// The typed create result proved nothing was allocated.
    DefinitelyNotCreated,
}

impl LegacyRelease {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Compensated => "compensated",
            Self::DefinitelyNotCreated => "definitely_not_created",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "deleted" => Self::Deleted,
            "compensated" => Self::Compensated,
            "definitely_not_created" => Self::DefinitelyNotCreated,
            _ => return None,
        })
    }

    /// Exactly schema 7's `RESERVED_SANDBOX_WHERE`, negated.
    pub fn for_row(
        state: SandboxState,
        backend_id: Option<&str>,
        certainty: CreateCertainty,
    ) -> Option<Self> {
        match state {
            SandboxState::Deleted => Some(Self::Deleted),
            SandboxState::Failed if backend_id.is_some() => Some(Self::Compensated),
            SandboxState::Failed if certainty == CreateCertainty::DefinitelyNotCreated => {
                Some(Self::DefinitelyNotCreated)
            }
            _ => None,
        }
    }
}

/// Why, if at all, a row stopped being charged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReservationRelease {
    #[default]
    Charged,
    Legacy(LegacyRelease),
    /// References the immutable `release_evidence` row with this receipt ID.
    Fenced(Id128),
}

/// The immutable identity and plan of an absence-fenced allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationBinding {
    pub node_id: Id128,
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub plan_version: u32,
    pub plan_digest: Digest,
    /// The exact stored plan. Reads of a released row leave this empty: its
    /// digest stays, and nothing recovers a released allocation from its plan.
    pub plan: Vec<u8>,
}

impl AllocationBinding {
    /// The only backend ID this allocation can ever publish.
    pub fn backend_id(&self) -> String {
        format!("fc-{}", self.allocation_id)
    }
}

/// Durable accounting and provenance stored with each sandbox row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxAccounting {
    pub regime: AccountingRegime,
    pub reservation: ResourceReservation,
    pub host_spec_sha256: Digest,
    pub guest_exec_spec_sha256: Digest,
    pub runtime_profile: String,
    pub runtime_artifact_digest: String,
    pub allocation: Option<AllocationBinding>,
    pub boot_id: Option<String>,
    pub disposition: SandboxDisposition,
    pub release: ReservationRelease,
    /// The newest durable helper generation this row has published: none on a
    /// legacy row, zero before READY, then the ready and absence receipts'.
    pub last_helper_generation: Option<u64>,
}

impl SandboxAccounting {
    /// A legacy row: the spec's own amounts and no allocation token.
    pub fn legacy(spec: &SandboxSpec, runtime_profile: &str) -> Self {
        let (host_spec_sha256, guest_exec_spec_sha256) = spec_digests(spec);
        Self {
            regime: AccountingRegime::Legacy,
            reservation: ResourceReservation::legacy_for_spec(spec),
            host_spec_sha256,
            guest_exec_spec_sha256,
            runtime_profile: runtime_profile.into(),
            runtime_artifact_digest: String::new(),
            allocation: None,
            boot_id: None,
            disposition: SandboxDisposition::Reusable,
            release: ReservationRelease::Charged,
            last_helper_generation: None,
        }
    }
}

/// `host_spec_sha256` and `guest_exec_spec_sha256` under B1's canonical bytes.
/// This does not apply the Firecracker offline profile: legacy kiln specs may use
/// any image or network the kiln backend supports.
pub fn spec_digests(spec: &SandboxSpec) -> (Digest, Digest) {
    let (host, guest) =
        crate::firecracker::spec_digests(spec).expect("a typed spec has canonical JSON");
    (
        Digest::parse(&host).expect("sha256 renders as lowercase hex"),
        Digest::parse(&guest).expect("sha256 renders as lowercase hex"),
    )
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
    pub create_certainty: CreateCertainty,
    /// The creating caller's kernel-reported uid, fixed for the row's life.
    /// Rows older than schema 7 belong to root.
    pub owner_uid: u32,
    pub accounting: SandboxAccounting,
}

impl Sandbox {
    pub fn is_fenced(&self) -> bool {
        self.accounting.regime == AccountingRegime::AbsenceFenced
    }

    pub fn is_charged(&self) -> bool {
        self.accounting.release == ReservationRelease::Charged
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    pub id: String,
    pub sandbox_id: String,
    pub argv: Vec<String>,
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub command_status: Option<CommandStatus>,
    pub runtime_error: Option<RuntimeDiagnostic>,
    pub failure_reason: Option<String>,
    pub started_at_ms: i64,
    pub finished_at_ms: Option<i64>,
    pub timeout_ms: u32,
    pub stdin_bytes: u64,
    pub stdout: Captured,
    pub stderr: Captured,
    /// None for historical rows and for executions with no reuse evidence.
    pub sandbox_reusable: Option<bool>,
    pub cleanup_evidence: CleanupEvidence,
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
        && id[kind.len() + 1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_truncation_keeps_utf8_boundaries() {
        let message = format!("{}é", "x".repeat(2047));
        let d = RuntimeDiagnostic::new(RuntimeErrorKind::Io, RuntimeStage::Capture, message);
        assert_eq!(d.message.len(), 2047);
        assert!(d.message_truncated);
    }

    #[test]
    fn ids_have_a_fixed_shape() {
        let id = new_id("sb");
        assert!(valid_id("sb", &id), "{id}");
        assert!(!valid_id("ex", &id));
        assert_ne!(id, new_id("sb"));
        for bad in [
            "",
            "sb-",
            "sb-1234",
            "sb-1f3a9c0d5e7b2a4G",
            "sb_1f3a9c0d5e7b2a46",
            "sb-1f3a9c0d5e7b2a46/",
        ] {
            assert!(!valid_id("sb", bad), "{bad}");
        }
    }

    #[test]
    fn typed_ids_and_digests_accept_only_their_exact_lowercase_form() {
        let id = Id128::random();
        assert_eq!(Id128::parse(&id.to_string()), Ok(id));
        assert_ne!(id, Id128::random());
        let digest = Digest::of(b"plan");
        assert_eq!(Digest::parse(&digest.to_string()), Ok(digest));
        for bad in ["", "abc", &"A".repeat(32), &"g".repeat(32), &"0".repeat(31)] {
            assert!(Id128::parse(bad).is_err(), "{bad}");
        }
        for bad in ["", &"A".repeat(64), &"0".repeat(63), &"0".repeat(65)] {
            assert!(Digest::parse(bad).is_err(), "{bad}");
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
            SandboxState::Quarantined,
        ] {
            assert_eq!(SandboxState::parse(s.as_str()), Some(s));
        }
        for d in [
            SandboxDisposition::Reusable,
            SandboxDisposition::Stopped,
            SandboxDisposition::Quarantined,
        ] {
            assert_eq!(SandboxDisposition::parse(d.as_str()), Some(d));
        }
        for e in [
            CleanupEvidence::Unknown,
            CleanupEvidence::NoChildStarted,
            CleanupEvidence::RuntimeDrained,
            CleanupEvidence::SandboxStopped,
        ] {
            assert_eq!(CleanupEvidence::parse(e.as_str()), Some(e));
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
