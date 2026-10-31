//! The runtime adapter: the only part of kilnd that knows how sandboxes are
//! actually made. kiln is the first implementation; a microVM backend would
//! implement the same trait.

use std::future::Future;
use tokio::time::Instant;

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::model::{
    AllocationBinding, Captured, CleanupEvidence, CommandStatus, Digest, Id128,
    ResourceReservation, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage, SandboxDisposition,
    SandboxSpec,
};

pub use crate::model::CreateCertainty;

pub mod fake;
pub mod firecracker;
pub mod kiln;
#[doc(hidden)]
pub mod kiln_direct;
mod kiln_process;
mod kiln_protocol;

/// The strict bound on a private backend plan.
pub const MAX_BACKEND_PLAN_BYTES: usize = 128 * 1024;
/// The encoded bound on any runtime receipt.
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;
/// The bound on a ready receipt's boot identity.
pub const MAX_BOOT_ID_BYTES: usize = 128;

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
}

/// A create that returned no backend ID. The fields are private so an ordinary
/// error can only become `AllocationAmbiguous`: claiming that nothing was
/// allocated takes the explicit constructor and the evidence behind it.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct CreateFailure {
    certainty: CreateCertainty,
    error: RuntimeError,
    absence: Option<Box<FencedAbsence>>,
}

impl CreateFailure {
    /// Use only with proof that no backend resource exists or can appear
    /// later because of this call. kilnd releases a legacy reservation on this.
    /// An absence-fenced row ignores it: only `absent_fenced` can release one.
    pub fn definitely_not_created(error: RuntimeError) -> Self {
        Self {
            certainty: CreateCertainty::DefinitelyNotCreated,
            error,
            absence: None,
        }
    }

    /// A rejected token that already holds a durable ABSENT fence.
    pub fn absent_fenced(absence: FencedAbsence, error: RuntimeError) -> Self {
        Self {
            certainty: CreateCertainty::DefinitelyNotCreated,
            error,
            absence: Some(Box::new(absence)),
        }
    }

    pub fn certainty(&self) -> CreateCertainty {
        self.certainty
    }

    pub fn error(&self) -> &RuntimeError {
        &self.error
    }

    pub fn absence(&self) -> Option<&FencedAbsence> {
        self.absence.as_deref()
    }
}

impl From<RuntimeError> for CreateFailure {
    fn from(error: RuntimeError) -> Self {
        Self {
            certainty: CreateCertainty::AllocationAmbiguous,
            error,
            absence: None,
        }
    }
}

impl From<std::io::Error> for CreateFailure {
    fn from(error: std::io::Error) -> Self {
        RuntimeError::from(error).into()
    }
}

/// Generated in memory before preparation, without inserting a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateContext {
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub sandbox_id: String,
}

/// Which release rule a prepared create commits its row to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceRegime {
    /// The local schema-7-compatible rule; the backend reports a backend ID.
    LegacyLocal,
    /// Release needs a matching receipt from this node's authority.
    AbsenceFenced { node_id: Id128 },
}

/// A complete immutable create plan. Everything the reservation transaction
/// stores and `create` executes comes from here; nothing is recalculated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCreate {
    spec: SandboxSpec,
    host_spec_sha256: Digest,
    guest_exec_spec_sha256: Digest,
    reservation: ResourceReservation,
    plan_version: u32,
    plan_digest: Digest,
    backend_plan: Vec<u8>,
    runtime_profile: String,
    runtime_artifact_digest: String,
    regime: EvidenceRegime,
}

impl PreparedCreate {
    /// Unchanged spec commitments with an empty plan: legacy kiln allocates
    /// nothing from a plan and reserves no CPU, vCPU or host-PID amounts.
    pub fn legacy(spec: SandboxSpec, runtime_profile: &str) -> Self {
        let (host_spec_sha256, guest_exec_spec_sha256) = crate::model::spec_digests(&spec);
        Self {
            reservation: ResourceReservation::legacy_for_spec(&spec),
            spec,
            host_spec_sha256,
            guest_exec_spec_sha256,
            plan_version: 0,
            plan_digest: Digest::of(b""),
            backend_plan: Vec::new(),
            runtime_profile: runtime_profile.into(),
            runtime_artifact_digest: String::new(),
            regime: EvidenceRegime::LegacyLocal,
        }
    }

    /// An absence-fenced plan. B1's `SpecBinding` supplies both digests and
    /// applies the offline execution profile; the plan digest covers exact bytes.
    pub fn fenced(
        spec: SandboxSpec,
        reservation: ResourceReservation,
        plan_version: u32,
        backend_plan: Vec<u8>,
        runtime_profile: &str,
        runtime_artifact_digest: Digest,
        node_id: Id128,
    ) -> Result<Self, RuntimeError> {
        if backend_plan.is_empty() || backend_plan.len() > MAX_BACKEND_PLAN_BYTES {
            return Err(RuntimeError::Backend(format!(
                "backend plan is {} bytes; the bound is 1 to {MAX_BACKEND_PLAN_BYTES}",
                backend_plan.len()
            )));
        }
        let binding = crate::firecracker::SpecBinding::new(&spec)
            .map_err(|e| RuntimeError::Incompatible(format!("spec binding: {e}")))?;
        let digest = |value: &str| {
            Digest::parse(value).map_err(|e| RuntimeError::Backend(format!("spec digest: {e}")))
        };
        Ok(Self {
            host_spec_sha256: digest(binding.host_spec_sha256())?,
            guest_exec_spec_sha256: digest(binding.guest_exec_spec_sha256())?,
            spec,
            reservation,
            plan_version,
            plan_digest: Digest::of(&backend_plan),
            backend_plan,
            runtime_profile: runtime_profile.into(),
            runtime_artifact_digest: runtime_artifact_digest.to_string(),
            regime: EvidenceRegime::AbsenceFenced { node_id },
        })
    }

    pub fn spec(&self) -> &SandboxSpec {
        &self.spec
    }
    pub fn host_spec_sha256(&self) -> Digest {
        self.host_spec_sha256
    }
    pub fn guest_exec_spec_sha256(&self) -> Digest {
        self.guest_exec_spec_sha256
    }
    pub fn reservation(&self) -> ResourceReservation {
        self.reservation
    }
    pub fn plan_version(&self) -> u32 {
        self.plan_version
    }
    pub fn plan_digest(&self) -> Digest {
        self.plan_digest
    }
    pub fn backend_plan(&self) -> &[u8] {
        &self.backend_plan
    }
    pub fn runtime_profile(&self) -> &str {
        &self.runtime_profile
    }
    pub fn runtime_artifact_digest(&self) -> &str {
        &self.runtime_artifact_digest
    }
    pub fn regime(&self) -> EvidenceRegime {
        self.regime
    }

    /// The immutable identity this plan commits a row to, if fenced.
    pub fn binding(&self, context: &CreateContext) -> Option<AllocationBinding> {
        match self.regime {
            EvidenceRegime::LegacyLocal => None,
            EvidenceRegime::AbsenceFenced { node_id } => Some(AllocationBinding {
                node_id,
                instance_id: context.instance_id,
                allocation_id: context.allocation_id,
                plan_version: self.plan_version,
                plan_digest: self.plan_digest,
                plan: self.backend_plan.clone(),
            }),
        }
    }
}

fn hex_string<S: serde::Serializer>(value: impl ToString, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&value.to_string())
}

fn encode_id<S: serde::Serializer>(value: &Id128, s: S) -> Result<S::Ok, S::Error> {
    hex_string(value, s)
}

fn encode_digest<S: serde::Serializer>(value: &Digest, s: S) -> Result<S::Ok, S::Error> {
    hex_string(value, s)
}

fn bounded_receipt(encoded: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
    if encoded.len() > MAX_RECEIPT_BYTES {
        return Err(RuntimeError::Backend(format!(
            "runtime receipt is {} bytes; the bound is {MAX_RECEIPT_BYTES}",
            encoded.len()
        )));
    }
    Ok(encoded)
}

/// Durable proof that an exact allocation, its plan and every delayed writer are
/// gone. Fields are private: a receipt comes from the backend's typed evidence
/// or the store's decoded row, never a caller string. `kind` is implicitly
/// AbsentFenced; legacy proof is a separate type and cannot become one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FencedAbsence {
    #[serde(serialize_with = "encode_id")]
    receipt_id: Id128,
    #[serde(serialize_with = "encode_id")]
    node_id: Id128,
    #[serde(serialize_with = "encode_id")]
    instance_id: Id128,
    #[serde(serialize_with = "encode_id")]
    allocation_id: Id128,
    #[serde(serialize_with = "encode_digest")]
    plan_digest: Digest,
    helper_generation: u64,
    observations: String,
}

impl FencedAbsence {
    pub fn new(
        receipt_id: Id128,
        node_id: Id128,
        instance_id: Id128,
        allocation_id: Id128,
        plan_digest: Digest,
        helper_generation: u64,
        observations: String,
    ) -> Result<Self, RuntimeError> {
        if helper_generation == 0 || helper_generation > i64::MAX as u64 {
            return Err(RuntimeError::Backend(format!(
                "invalid helper generation {helper_generation}"
            )));
        }
        let receipt = Self {
            receipt_id,
            node_id,
            instance_id,
            allocation_id,
            plan_digest,
            helper_generation,
            observations,
        };
        receipt.encode()?;
        Ok(receipt)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RuntimeError> {
        bounded_receipt(serde_json::to_vec(self).map_err(std::io::Error::other)?)
    }

    /// Decode the sole durable AbsentFenced encoding. Its kind is implicit in
    /// this type; unknown/duplicate fields and alternate encodings are refused.
    pub fn decode(encoded: &[u8]) -> Result<Self, RuntimeError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            receipt_id: String,
            node_id: String,
            instance_id: String,
            allocation_id: String,
            plan_digest: String,
            helper_generation: u64,
            observations: String,
        }
        let invalid =
            |message: String| RuntimeError::Backend(format!("invalid FencedAbsence: {message}"));
        if encoded.len() > MAX_RECEIPT_BYTES {
            return Err(invalid("receipt exceeds size bound".into()));
        }
        let wire: Wire = serde_json::from_slice(encoded).map_err(|e| invalid(e.to_string()))?;
        let receipt = Self::new(
            Id128::parse(&wire.receipt_id).map_err(invalid)?,
            Id128::parse(&wire.node_id).map_err(invalid)?,
            Id128::parse(&wire.instance_id).map_err(invalid)?,
            Id128::parse(&wire.allocation_id).map_err(invalid)?,
            Digest::parse(&wire.plan_digest).map_err(invalid)?,
            wire.helper_generation,
            wire.observations,
        )?;
        if receipt.encode()? != encoded {
            return Err(invalid("noncanonical encoding".into()));
        }
        Ok(receipt)
    }

    pub fn receipt_id(&self) -> Id128 {
        self.receipt_id
    }
    pub fn node_id(&self) -> Id128 {
        self.node_id
    }
    pub fn instance_id(&self) -> Id128 {
        self.instance_id
    }
    pub fn allocation_id(&self) -> Id128 {
        self.allocation_id
    }
    pub fn plan_digest(&self) -> Digest {
        self.plan_digest
    }
    pub fn helper_generation(&self) -> u64 {
        self.helper_generation
    }

    /// Node, instance, allocation and plan must all be exactly this row's.
    pub fn matches(&self, binding: &AllocationBinding) -> bool {
        self.node_id == binding.node_id
            && self.instance_id == binding.instance_id
            && self.allocation_id == binding.allocation_id
            && self.plan_digest == binding.plan_digest
    }
}

/// How a legacy adapter proved a backend gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyProof {
    /// The adapter's strict removal: direct probe, complete listing, absent cgroup.
    StrictRemoval,
    /// The adapter's scoped garbage collection reported this exact ID removed.
    ScopedGc,
}

/// Legacy removal evidence. It deliberately carries no node, allocation or plan:
/// it can release only a legacy row, and only through its explicit tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyAbsence {
    pub backend_id: String,
    pub proof: LegacyProof,
}

/// A typed absence result from `remove` and `gc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbsenceReceipt {
    Legacy(LegacyAbsence),
    Fenced(FencedAbsence),
}

/// Bound identity of a READY allocation, reported at C6 and republished at C7.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadyReceipt {
    #[serde(serialize_with = "encode_id")]
    pub node_id: Id128,
    #[serde(serialize_with = "encode_id")]
    pub instance_id: Id128,
    #[serde(serialize_with = "encode_id")]
    pub allocation_id: Id128,
    #[serde(serialize_with = "encode_digest")]
    pub plan_digest: Digest,
    pub helper_generation: u64,
    pub boot_id: String,
}

impl ReadyReceipt {
    pub fn matches(&self, binding: &AllocationBinding) -> bool {
        self.node_id == binding.node_id
            && self.instance_id == binding.instance_id
            && self.allocation_id == binding.allocation_id
            && self.plan_digest == binding.plan_digest
    }

    /// A durable helper generation and a bounded printable boot identity.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.helper_generation == 0 || self.helper_generation > i64::MAX as u64 {
            return Err(RuntimeError::Backend(format!(
                "invalid helper generation {}",
                self.helper_generation
            )));
        }
        if self.boot_id.is_empty()
            || self.boot_id.len() > MAX_BOOT_ID_BYTES
            || !self.boot_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(RuntimeError::Backend("invalid boot identity".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, RuntimeError> {
        self.validate()?;
        bounded_receipt(serde_json::to_vec(self).map_err(std::io::Error::other)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeReceipt {
    /// The backend reported an ID and nothing more.
    Legacy,
    Ready(ReadyReceipt),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedSandbox {
    pub backend_id: String,
    pub receipt: RuntimeReceipt,
}

/// One allocation-token lookup. `Unsupported` and `Unknown` are not absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationObservation {
    Present {
        receipt: ReadyReceipt,
        /// True only for a healthy idle handshake on an identical boot.
        healthy_idle: bool,
        /// An execution may be in flight or its result was never settled.
        uncertain_execution: bool,
    },
    /// No execution remains, but disk, jail or cgroup state may.
    StoppedWithResources {
        helper_generation: u64,
    },
    AbsentFenced(FencedAbsence),
    Unknown {
        reason: String,
    },
    Unsupported,
}

pub struct ExecSpec<'a> {
    pub argv: &'a [String],
    pub stdin: &'a [u8],
    pub deadline: Instant,
    /// Bytes kept per output stream.
    pub max_output: usize,
}

/// Binds one dispatch to its public execution row and a single-use token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionContext {
    pub execution_id: String,
    pub execution_token: Id128,
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
pub(crate) fn legacy_exec_evidence(
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

/// One inventory record. Allocation-token backends also bind the allocation,
/// plan and record generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendRecord {
    pub id: String,
    pub status: BackendStatus,
    pub allocation_id: Option<Id128>,
    pub plan_digest: Option<Digest>,
    pub generation: u64,
}

impl From<BackendSandbox> for BackendRecord {
    fn from(sandbox: BackendSandbox) -> Self {
        Self {
            id: sandbox.id,
            status: sandbox.status,
            allocation_id: None,
            plan_digest: None,
            generation: 0,
        }
    }
}

/// `complete` is an explicit claim. An incomplete or corrupt inventory never
/// implies absence, and callers must validate it before acting on any record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendInventory {
    pub records: Vec<BackendRecord>,
    pub generation: u64,
    pub complete: bool,
}

/// Where node accounting totals come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountingAuthority {
    /// This daemon's own durable sum is the promise, with CPU unreserved.
    LocalLegacy,
    /// A node authority owns totals; a local sum must never stand in for it.
    Node,
}

/// Backend-neutral facts for Health; no raw provider details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    pub network_modes: Vec<crate::model::Network>,
    /// False when any interruption after dispatch retires the session.
    pub interruption_preserves_session: bool,
    pub checkpoint: bool,
    pub accounting: AccountingAuthority,
}

/// Futures are `Send` because tonic requires it of service handlers.
pub trait Runtime: Send + Sync + 'static {
    /// Short backend name stored with each sandbox, like "kiln".
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> RuntimeCapabilities;

    /// Returns the backend version. Deadline or cancellation must stop and
    /// reap any subprocess before the future returns.
    fn version(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<String, RuntimeError>> + Send;

    /// Read-only preflight before any reservation: must allocate nothing.
    /// Returning an error leaves no row and no charge.
    fn prepare(
        &self,
        context: &CreateContext,
        spec: &SandboxSpec,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PreparedCreate, RuntimeError>> + Send;

    /// Creates a fresh sandbox owned by this invocation, returning once it
    /// accepts commands. A failure is `AllocationAmbiguous` unless the
    /// implementation can prove otherwise: the backend may have made a resource
    /// before it lost the ability to report the ID. A repeated call with the same
    /// allocation and plan is a query or continuation, never a second allocation.
    fn create(
        &self,
        context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<CreatedSandbox, CreateFailure>> + Send;

    /// Looks up one exact allocation token. No restart or cleanup.
    fn inspect_allocation(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<AllocationObservation, RuntimeError>> + Send;

    /// Excludes every delayed writer of this token, proves its resources absent
    /// and persists a permanent fence. Replays return the same receipt. Any
    /// conflict is an error and leaves the allocation ambiguous.
    fn fence_absent(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<AbsenceReceipt, RuntimeError>> + Send;

    /// Side-effect-free validation of an existing sandbox's execution protocol.
    fn validate_sandbox(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// Runs one command and waits for it. A pre-canceled token must be honored.
    /// When the timeout passes or `cancel` fires, the command and all of its
    /// descendants must be stopped, and all I/O resources released, before this
    /// future returns. The outcome's disposition says whether the sandbox stays
    /// usable: claim `Reusable` only with cleanup evidence, `Quarantined` when
    /// cleanup cannot be confirmed, and `Stopped` when no command can remain.
    fn exec(
        &self,
        id: &str,
        execution: &ExecutionContext,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> impl Future<Output = ExecOutcome> + Send;

    /// Removes a sandbox and waits until its resources are released.
    fn remove(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<AbsenceReceipt, RuntimeError>> + Send;

    /// Every sandbox the backend knows about, including ones kilnd didn't
    /// create.
    fn list(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BackendInventory, RuntimeError>> + Send;

    /// Removes stale state only for the named backend sandboxes. An empty
    /// scope is a no-op. Must never touch a live or unlisted sandbox. Returns
    /// one receipt per sandbox it removed.
    fn gc(
        &self,
        ids: &[String],
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Vec<AbsenceReceipt>, RuntimeError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Network;

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
        assert!(definite.absence().is_none());
    }

    fn spec() -> SandboxSpec {
        SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 512 << 20,
            cpu_millis: 1000,
            pids: 128,
            disk_bytes: 1 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: Default::default(),
        }
    }

    #[test]
    fn prepared_create_bounds_its_plan_and_binds_both_spec_digests() {
        let reservation = crate::firecracker::offline_768_v1_reservation(&spec()).unwrap();
        let node = Id128::random();
        let digest = Digest::of(b"bundle");
        let bad = |plan: Vec<u8>| {
            PreparedCreate::fenced(spec(), reservation, 1, plan, "p", digest, node).unwrap_err()
        };
        assert!(bad(Vec::new()).to_string().contains("backend plan"));
        assert!(
            bad(vec![0; MAX_BACKEND_PLAN_BYTES + 1])
                .to_string()
                .contains("backend plan")
        );
        let prepared = PreparedCreate::fenced(
            spec(),
            reservation,
            1,
            vec![0; MAX_BACKEND_PLAN_BYTES],
            "p",
            digest,
            node,
        )
        .unwrap();
        assert_eq!(
            (
                prepared.host_spec_sha256(),
                prepared.guest_exec_spec_sha256()
            ),
            crate::model::spec_digests(&spec())
        );
        assert_eq!(
            prepared.plan_digest(),
            Digest::of(&vec![0; MAX_BACKEND_PLAN_BYTES])
        );

        // A label changes only the host digest.
        let mut labeled = spec();
        labeled.labels.insert("k".into(), "v".into());
        let (host, guest) = crate::model::spec_digests(&labeled);
        assert_ne!(host, prepared.host_spec_sha256());
        assert_eq!(guest, prepared.guest_exec_spec_sha256());

        // A non-offline spec cannot enter a fenced plan, but stays legal for kiln.
        let mut networked = spec();
        networked.network = Network::Full;
        let refused = PreparedCreate::fenced(
            networked.clone(),
            reservation,
            1,
            vec![1],
            "p",
            digest,
            node,
        );
        assert!(matches!(refused, Err(RuntimeError::Incompatible(_))));
        let legacy = PreparedCreate::legacy(networked.clone(), "kiln");
        assert_eq!(
            legacy.reservation(),
            ResourceReservation::legacy_for_spec(&networked)
        );
        assert_eq!(legacy.regime(), EvidenceRegime::LegacyLocal);
        assert_eq!(legacy.reservation().host_cpu_millis, 0);
    }

    #[test]
    fn receipts_are_bounded_and_match_only_their_exact_identity() {
        let (node, instance, allocation, receipt_id) = (
            Id128::random(),
            Id128::random(),
            Id128::random(),
            Id128::random(),
        );
        let plan = Digest::of(b"plan");
        let new = |generation, observations: String| {
            FencedAbsence::new(
                receipt_id,
                node,
                instance,
                allocation,
                plan,
                generation,
                observations,
            )
        };
        assert!(new(0, String::new()).is_err());
        assert!(new(u64::MAX, String::new()).is_err());
        assert!(new(1, "x".repeat(MAX_RECEIPT_BYTES)).is_err());
        let receipt = new(1, "x".repeat(1024)).unwrap();
        assert!(receipt.encode().unwrap().len() <= MAX_RECEIPT_BYTES);
        let binding = AllocationBinding {
            node_id: node,
            instance_id: instance,
            allocation_id: allocation,
            plan_version: 1,
            plan_digest: plan,
            plan: vec![1],
        };
        assert!(receipt.matches(&binding));
        for wrong in [
            AllocationBinding {
                node_id: Id128::random(),
                ..binding.clone()
            },
            AllocationBinding {
                instance_id: Id128::random(),
                ..binding.clone()
            },
            AllocationBinding {
                allocation_id: Id128::random(),
                ..binding.clone()
            },
            AllocationBinding {
                plan_digest: Digest::of(b"other"),
                ..binding.clone()
            },
        ] {
            assert!(!receipt.matches(&wrong));
        }
    }

    #[test]
    fn ready_receipts_need_a_durable_generation_and_bounded_boot_identity() {
        let good = ReadyReceipt {
            node_id: Id128::random(),
            instance_id: Id128::random(),
            allocation_id: Id128::random(),
            plan_digest: Digest::of(b"plan"),
            helper_generation: 1,
            boot_id: "x".repeat(MAX_BOOT_ID_BYTES),
        };
        assert!(good.encode().is_ok());
        assert!(
            ReadyReceipt {
                helper_generation: i64::MAX as u64,
                ..good.clone()
            }
            .encode()
            .is_ok()
        );
        for bad in [
            ReadyReceipt {
                helper_generation: 0,
                ..good.clone()
            },
            ReadyReceipt {
                helper_generation: i64::MAX as u64 + 1,
                ..good.clone()
            },
            ReadyReceipt {
                boot_id: String::new(),
                ..good.clone()
            },
            ReadyReceipt {
                boot_id: "x".repeat(MAX_BOOT_ID_BYTES + 1),
                ..good.clone()
            },
            ReadyReceipt {
                boot_id: "boot id".into(),
                ..good.clone()
            },
            ReadyReceipt {
                boot_id: "boot\n".into(),
                ..good.clone()
            },
        ] {
            assert!(bad.encode().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn legacy_evidence_quarantines_only_unconfirmed_cleanup() {
        let failed = |kind, stage| Err(RuntimeDiagnostic::new(kind, stage, "x"));
        for (finish, expected) in [
            (Ok(ExecFinish::Completed), SandboxDisposition::Reusable),
            (Ok(ExecFinish::TimedOut), SandboxDisposition::Reusable),
            (Ok(ExecFinish::Canceled), SandboxDisposition::Reusable),
            (
                failed(RuntimeErrorKind::CleanupFailed, RuntimeStage::Cleanup),
                SandboxDisposition::Quarantined,
            ),
            (
                failed(RuntimeErrorKind::NotFound, RuntimeStage::Handshake),
                SandboxDisposition::Stopped,
            ),
            (
                failed(RuntimeErrorKind::Incompatible, RuntimeStage::Handshake),
                SandboxDisposition::Reusable,
            ),
            (
                failed(RuntimeErrorKind::Io, RuntimeStage::Capture),
                SandboxDisposition::Reusable,
            ),
        ] {
            assert_eq!(legacy_exec_evidence(&finish).0, expected, "{finish:?}");
        }
    }
}
