//! An in-memory backend for tests. Commands are simulated by name:
//!
//! - `echo ARGS...`: prints its arguments and exits 0
//! - `cat`: copies stdin to stdout
//! - `exit N`: exits with N
//! - `sleep`: waits until the timeout or cancellation
//! - `spew N`: writes N bytes to stdout
//! - `vanish`: the sandbox disappears mid-command, like a crashed shim
//! - `cleanup-fail`: the command ends but its cleanup cannot be confirmed
//! - anything else: exits 127
//!
//! Evidence comes in two modes. The default [`FakeEvidenceMode::Legacy`] behaves
//! like kiln: a backend ID and legacy proof. [`FakeEvidenceMode::Fenced`] models the
//! allocation-token contract: an immutable plan per token, a monotonic node
//! generation and permanent absence fences, with no real workers or helper ledger.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use kilnd_exec_core::live::LiveStream;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{
    AbsenceReceipt, AccountingAuthority, AllocationObservation, BackendInventory, BackendRecord,
    BackendStatus, CreateContext, CreateFailure, CreatedSandbox, ExecFinish, ExecOutcome, ExecSpec,
    ExecutionContext, FencedAbsence, LegacyAbsence, LegacyProof, PrepareContext, PreparedCreate,
    ReadyReceipt, RemoveTarget, Runtime, RuntimeCapabilities, RuntimeError, RuntimeReceipt, legacy_exec_evidence,
};
use crate::model::{
    Captured, CleanupEvidence, CommandStatus, Digest, Id128, Network, RuntimeDiagnostic,
    RuntimeErrorKind, RuntimeStage, SandboxDisposition, SandboxSpec,
};

/// A deterministic one-shot pause for lifecycle tests. Tests wait for
/// `entered`, cancel a caller or begin shutdown, then explicitly `release`.
#[derive(Clone)]
pub struct FakeGate {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl Default for FakeGate {
    fn default() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }
}

impl FakeGate {
    pub async fn entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("fake gate closed")
            .forget();
    }

    pub fn release(&self) {
        self.release.add_permits(1);
    }

    async fn hold(&self) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("fake gate closed")
            .forget();
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FakeEvidenceMode {
    #[default]
    Legacy,
    Fenced,
}

/// A durable helper phase, in order. Reaching one means its journal write landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FakePhase {
    /// C2: the node claim and INTENT committed in one transaction.
    Intent,
    /// C3: PREPARING; partial files, mounts or cgroups may exist.
    Preparing,
    /// C4: SPAWN_INTENT.
    SpawnIntent,
    /// C5: BOOTING.
    Booting,
    /// C6: READY.
    Ready,
    /// No process remains, but resources do.
    Stopped,
}

impl FakePhase {
    const CREATE_PATH: [Self; 5] = [
        Self::Intent,
        Self::Preparing,
        Self::SpawnIntent,
        Self::Booting,
        Self::Ready,
    ];
}

/// A post-C1 rejection before INTENT. Each stays ambiguous until fenced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeRejection {
    Collision,
    CatalogMismatch,
    DeadlineExpired,
    CapacityExhausted,
    Panic,
}

/// One allocation in the modeled helper ledger. Its plan never changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeAllocation {
    pub instance_id: Id128,
    pub plan_digest: Digest,
    pub phase: FakePhase,
    pub generation: u64,
    pub boot_id: String,
    pub uncertain_execution: bool,
}

/// How a test corrupts an otherwise valid receipt identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeForgery {
    Node,
    Instance,
    Allocation,
    Plan,
    /// A positive absence generation older than anything the helper has since
    /// published. On a ready reply this is generation zero, which no ledger issues.
    StaleGeneration,
    /// A ready reply with no boot identity.
    EmptyBoot,
}

/// Fault switches for the fenced mode. Everything is explicit and deterministic;
/// the defaults model a healthy helper.
#[derive(Default)]
pub struct FakeFenced {
    pub node_id: Option<Id128>,
    pub node_generation: u64,
    pub allocations: BTreeMap<Id128, FakeAllocation>,
    /// Permanent retired-token fences; nothing removes an entry.
    pub fences: BTreeMap<Id128, FencedAbsence>,
    /// Allocations ever claimed. A retried token never increases this.
    pub claims_made: u64,
    pub fail_prepare: Option<String>,
    /// Prepare refuses as Exhausted, as a full adapter cache does before Preflight.
    pub exhaust_prepare: Option<String>,
    pub prepare_gate: Option<FakeGate>,
    pub prepare_panics: bool,
    /// Preflight finishes even after cancellation, so only the manager's own
    /// recheck stands between it and an allocation.
    pub prepare_ignores_cancel: bool,
    pub prepare_calls: u32,
    /// B7: tokens the fake authority has issued (its exact pointer, less one).
    pub issued: u64,
    /// Holds the next create calls, in order, before their fence lookup.
    pub queued_create_gates: VecDeque<FakeGate>,
    pub rejection: Option<FakeRejection>,
    /// One-shot pause just after a phase's journal write lands.
    pub phase_gates: BTreeMap<FakePhase, FakeGate>,
    /// Returns an ambiguous error just after reaching this phase.
    pub stop_at: Option<FakePhase>,
    /// READY commits but the reply is lost, once.
    pub lose_ready_reply: bool,
    /// The fence transaction cannot commit.
    pub fence_unavailable: Option<String>,
    /// One-shot pause after quiescence, before the fence's durable commit.
    pub fence_gate: Option<FakeGate>,
    /// The fence commits but its reply is lost, once.
    pub lose_fence_reply: bool,
    /// Removal finished and ABSENT committed, but the reply is lost, once.
    pub lose_remove_reply: bool,
    pub fence_calls: u32,
    pub forge: Option<FakeForgery>,
    /// One-shot: the next exec reports this disposition and evidence, whatever
    /// actually happened, as a broken or compromised backend could.
    pub forge_exec_claim: Option<(SandboxDisposition, CleanupEvidence)>,
    pub inspect_unavailable: bool,
    /// Replaces every observation, for evidence a real helper could report.
    pub observation_override: Option<AllocationObservation>,
    pub inventory_incomplete: bool,
    pub inventory_duplicates: bool,
    pub inventory_extra: Vec<BackendRecord>,
}

pub struct FakeState {
    pub mode: FakeEvidenceMode,
    pub fenced: FakeFenced,
    /// B6: what `node_totals` answers; `None` models an unreadable authority.
    pub node_totals: Option<super::NodeTotals>,
    pub sandboxes: BTreeMap<String, BackendStatus>,
    /// Specs passed to `create`, in order.
    pub created: Vec<SandboxSpec>,
    pub removed: Vec<String>,
    /// Removal attempts, including failed ones.
    pub remove_attempts: Vec<String>,
    /// B7: every `remove` target as `legacy:<backend id>` or `fenced:<allocation>`,
    /// including the ones a regime refused before acting.
    pub remove_targets: Vec<String>,
    /// Commands whose backend execution was entered, in order.
    pub exec_calls: Vec<Vec<String>>,
    /// The exec options each entered execution was given, in order.
    pub exec_options: Vec<kilnd_exec_core::exec_options::ExecOptions>,
    /// What a legacy create reports as the new sandbox's exec feature bits.
    pub create_exec_features: Option<u32>,
    pub exec_deadlines: Vec<tokio::time::Instant>,
    pub version_calls: u32,
    pub active_version_calls: u32,
    pub version_gate: Option<FakeGate>,
    pub version_cleanup_gate: Option<FakeGate>,
    pub panic_version: bool,
    pub active_execs: u32,
    pub canceled_execs: u32,
    pub gc_runs: u32,
    /// Explicit ID scopes passed to garbage collection, in call order.
    pub gc_requests: Vec<Vec<String>>,
    /// When set, `create` fails ambiguously with this message before allocating.
    pub fail_create: Option<String>,
    /// When set, `create` proves it failed before allocating anything.
    pub fail_create_definitely: Option<String>,
    /// When set, `create` allocates a backend, then fails without reporting
    /// its ID.
    pub fail_create_after_allocation: Option<String>,
    /// Panics before allocating a backend, for supervisor recovery tests.
    pub panic_create: bool,
    /// Panics after the optional exec gate. Without a gate this is before the
    /// backend future's first await; with one it exercises a polling panic.
    pub panic_exec: bool,
    /// When set, `remove` fails while the sandbox stays.
    pub fail_remove: bool,
    /// Optional one-shot pause before create allocates a backend.
    pub create_before_allocation: Option<FakeGate>,
    /// Optional one-shot pause after allocation but before create returns.
    pub create_after_allocation: Option<FakeGate>,
    /// Optional one-shot pause after exec entry and before observing cancel.
    pub exec_before_run: Option<FakeGate>,
    /// Optional one-shot pause before remove changes backend state.
    pub remove_before_delete: Option<FakeGate>,
    /// Optional one-shot pause after remove changes backend state but before
    /// it reports success.
    pub remove_after_delete: Option<FakeGate>,
    /// When set, `list` and `version` fail, like a missing kiln binary.
    pub unavailable: bool,
    /// Backend IDs deliberately omitted from `list` while direct validation
    /// still observes them. Reconciliation tests use this to model an
    /// incomplete but otherwise successful backend listing.
    pub hidden_from_list: Vec<String>,
    pub incompatible_sandboxes: Vec<String>,
    /// What the dynamic feature probe proves; `Err` models a failed or older probe.
    pub proven_features: Result<Vec<crate::manager::Feature>, String>,
    /// Removals running now and the most seen at once (mass-expiry bound).
    pub active_removes: u32,
    pub max_active_removes: u32,
    /// Holds every legacy removal until released, so tests see them overlap.
    pub remove_hold: Option<std::sync::Arc<tokio::sync::Notify>>,
    next: u64,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            mode: Default::default(),
            fenced: Default::default(),
            node_totals: None,
            sandboxes: Default::default(),
            created: Vec::new(),
            removed: Vec::new(),
            remove_attempts: Vec::new(),
            remove_targets: Vec::new(),
            exec_calls: Vec::new(),
            exec_options: Vec::new(),
            create_exec_features: Some(0x3f),
            exec_deadlines: Vec::new(),
            version_calls: 0,
            active_version_calls: 0,
            version_gate: None,
            version_cleanup_gate: None,
            panic_version: false,
            active_execs: 0,
            canceled_execs: 0,
            gc_runs: 0,
            gc_requests: Vec::new(),
            fail_create: None,
            fail_create_definitely: None,
            fail_create_after_allocation: None,
            panic_create: false,
            panic_exec: false,
            fail_remove: false,
            create_before_allocation: None,
            create_after_allocation: None,
            exec_before_run: None,
            remove_before_delete: None,
            remove_after_delete: None,
            unavailable: false,
            hidden_from_list: Vec::new(),
            incompatible_sandboxes: Vec::new(),
            proven_features: Ok(Vec::new()),
            active_removes: 0,
            max_active_removes: 0,
            remove_hold: None,
            next: 0,
        }
    }
}

#[derive(Clone, Default)]
pub struct FakeRuntime {
    state: Arc<Mutex<FakeState>>,
}

struct ActiveExec {
    state: Arc<Mutex<FakeState>>,
}

struct ActiveVersion(Arc<Mutex<FakeState>>);

impl Drop for ActiveVersion {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_version_calls -= 1;
    }
}

impl Drop for ActiveExec {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active_execs -= 1;
    }
}

impl FakeRuntime {
    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A healthy allocation-token backend for one fixed node.
    pub fn fenced() -> Self {
        let fake = Self::default();
        {
            let mut state = fake.state();
            state.mode = FakeEvidenceMode::Fenced;
            state.fenced.node_id = Some(Id128::random());
        }
        fake
    }

    fn fenced_node(state: &FakeState) -> Id128 {
        state.fenced.node_id.expect("fenced mode has a node ID")
    }

    fn next_generation(fenced: &mut FakeFenced) -> u64 {
        fenced.node_generation += 1;
        fenced.node_generation
    }

    /// The commit of one fence: a permanent ledger entry and its receipt. Fences
    /// are never rewritten, so a replay can only observe this exact value.
    fn commit_fence(
        fenced: &mut FakeFenced,
        node_id: Id128,
        instance_id: Id128,
        allocation_id: Id128,
        plan_digest: Digest,
    ) -> Result<FencedAbsence, RuntimeError> {
        let generation = Self::next_generation(fenced);
        let receipt = FencedAbsence::new(
            Id128::random(),
            node_id,
            instance_id,
            allocation_id,
            plan_digest,
            generation,
            "fake: no owned process, file, mount or cgroup remains".into(),
        )?;
        fenced.fences.insert(allocation_id, receipt.clone());
        fenced.allocations.remove(&allocation_id);
        Ok(receipt)
    }

    /// A forged result leaves the ledger untouched: it models a wrong answer.
    fn delivered(
        fenced: &FakeFenced,
        receipt: FencedAbsence,
    ) -> Result<FencedAbsence, RuntimeError> {
        let Some(forgery) = fenced.forge else {
            return Ok(receipt);
        };
        let other = Id128::random();
        FencedAbsence::new(
            receipt.receipt_id(),
            if forgery == FakeForgery::Node {
                other
            } else {
                receipt.node_id()
            },
            if forgery == FakeForgery::Instance {
                other
            } else {
                receipt.instance_id()
            },
            if forgery == FakeForgery::Allocation {
                other
            } else {
                receipt.allocation_id()
            },
            if forgery == FakeForgery::Plan {
                Digest::of(b"forged")
            } else {
                receipt.plan_digest()
            },
            if forgery == FakeForgery::StaleGeneration {
                1
            } else {
                receipt.helper_generation()
            },
            String::new(),
        )
    }

    fn ready_receipt(
        state: &FakeState,
        allocation_id: Id128,
        allocation: &FakeAllocation,
    ) -> ReadyReceipt {
        ReadyReceipt {
            node_id: Self::fenced_node(state),
            instance_id: allocation.instance_id,
            allocation_id,
            plan_digest: allocation.plan_digest,
            helper_generation: allocation.generation,
            boot_id: allocation.boot_id.clone(),
        }
    }

    async fn create_fenced(
        &self,
        context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: tokio::time::Instant,
    ) -> Result<CreatedSandbox, CreateFailure> {
        let allocation_id = context.allocation_id;
        let queued = self.state().fenced.queued_create_gates.pop_front();
        if let Some(gate) = queued {
            gate.hold().await;
        }
        {
            let mut guard = self.state();
            let state = &mut *guard;
            // Every lookup precedes revalidation, so a fence wins over any cause
            // and an existing token never selects a new claim.
            if let Some(fence) = state.fenced.fences.get(&allocation_id) {
                let error = RuntimeError::Backend(format!("allocation {allocation_id} is fenced"));
                return Err(CreateFailure::absent_fenced(fence.clone(), error));
            }
            if let Some(existing) = state.fenced.allocations.get(&allocation_id) {
                if existing.plan_digest != prepared.plan_digest() {
                    return Err(RuntimeError::Backend(format!(
                        "allocation {allocation_id} has a conflicting plan"
                    ))
                    .into());
                }
                if existing.phase == FakePhase::Ready {
                    let backend_id = format!("fc-{allocation_id}");
                    let receipt = Self::ready_receipt(state, allocation_id, existing);
                    return Ok(CreatedSandbox {
                        backend_id,
                        receipt: RuntimeReceipt::Ready(receipt),
                        exec_features: None,
                    });
                }
                return Err(RuntimeError::Backend(format!(
                    "allocation {allocation_id} is still in {:?}",
                    existing.phase
                ))
                .into());
            }
            let rejected = match state.fenced.rejection {
                Some(FakeRejection::Panic) => panic!("injected fake create panic"),
                Some(FakeRejection::Collision) => Some("identity candidate was claimed first"),
                Some(FakeRejection::CatalogMismatch) => Some("deployment catalog changed"),
                Some(FakeRejection::DeadlineExpired) => Some("create deadline expired"),
                Some(FakeRejection::CapacityExhausted) => Some("node capacity exhausted"),
                None if tokio::time::Instant::now() >= deadline => Some("create deadline expired"),
                None => None,
            };
            if let Some(reason) = rejected {
                let error = RuntimeError::Backend(reason.into());
                return Err(
                    if state.fenced.rejection == Some(FakeRejection::CapacityExhausted) {
                        CreateFailure::exhausted(error)
                    } else {
                        error.into()
                    },
                );
            }
            state.fenced.claims_made += 1;
            let generation = Self::next_generation(&mut state.fenced);
            state.fenced.allocations.insert(
                allocation_id,
                FakeAllocation {
                    instance_id: context.instance_id,
                    plan_digest: prepared.plan_digest(),
                    phase: FakePhase::Intent,
                    generation,
                    boot_id: format!("boot-{}", Id128::random()),
                    uncertain_execution: false,
                },
            );
            state.created.push(prepared.spec().clone());
        }
        for phase in FakePhase::CREATE_PATH {
            let (gate, stop) = {
                let mut guard = self.state();
                let state = &mut *guard;
                let generation = Self::next_generation(&mut state.fenced);
                let Some(allocation) = state.fenced.allocations.get_mut(&allocation_id) else {
                    return Err(RuntimeError::Backend(format!(
                        "allocation {allocation_id} was fenced during create"
                    ))
                    .into());
                };
                allocation.phase = phase;
                allocation.generation = generation;
                if phase == FakePhase::Ready {
                    state
                        .sandboxes
                        .insert(format!("fc-{allocation_id}"), BackendStatus::Ready);
                }
                (
                    state.fenced.phase_gates.remove(&phase),
                    state.fenced.stop_at == Some(phase),
                )
            };
            if let Some(gate) = gate {
                gate.hold().await;
            }
            if stop {
                return Err(RuntimeError::Backend(format!(
                    "injected create failure after {phase:?}"
                ))
                .into());
            }
        }
        let mut guard = self.state();
        let state = &mut *guard;
        if std::mem::take(&mut state.fenced.lose_ready_reply) {
            return Err(RuntimeError::Backend("helper reply lost after READY".into()).into());
        }
        let allocation = state
            .fenced
            .allocations
            .get(&allocation_id)
            .expect("just reached READY");
        let mut receipt = Self::ready_receipt(state, allocation_id, allocation);
        match state.fenced.forge {
            Some(FakeForgery::Node) => receipt.node_id = Id128::random(),
            Some(FakeForgery::Instance) => receipt.instance_id = Id128::random(),
            Some(FakeForgery::Allocation) => receipt.allocation_id = Id128::random(),
            Some(FakeForgery::Plan) => receipt.plan_digest = Digest::of(b"forged"),
            Some(FakeForgery::StaleGeneration) => receipt.helper_generation = 0,
            Some(FakeForgery::EmptyBoot) => receipt.boot_id = String::new(),
            None => {}
        }
        Ok(CreatedSandbox {
            backend_id: format!("fc-{allocation_id}"),
            receipt: RuntimeReceipt::Ready(receipt),
            exec_features: None,
        })
    }

    async fn remove_fenced(&self, id: &str) -> Result<AbsenceReceipt, RuntimeError> {
        let parsed = id
            .strip_prefix("fc-")
            .and_then(|hex| Id128::parse(hex).ok());
        let Some(allocation_id) = parsed else {
            return Err(RuntimeError::NotFound(id.to_string()));
        };
        let gate = {
            let mut guard = self.state();
            let state = &mut *guard;
            state.remove_attempts.push(id.to_string());
            if let Some(fence) = state.fenced.fences.get(&allocation_id).cloned() {
                return Ok(AbsenceReceipt::Fenced(Self::delivered(
                    &state.fenced,
                    fence,
                )?));
            }
            if !state.fenced.allocations.contains_key(&allocation_id) {
                return Err(RuntimeError::NotFound(id.to_string()));
            }
            state.remove_before_delete.take()
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        let (receipt, after) = {
            let mut guard = self.state();
            let state = &mut *guard;
            let node_id = Self::fenced_node(state);
            let Some(allocation) = state.fenced.allocations.get_mut(&allocation_id) else {
                return Err(RuntimeError::NotFound(id.to_string()));
            };
            if state.fail_remove {
                // The VMM stopped; its disk and jail did not go away.
                allocation.phase = FakePhase::Stopped;
                state
                    .sandboxes
                    .insert(id.to_string(), BackendStatus::StoppedWithResources);
                return Err(RuntimeError::Backend("fake remove failed".into()));
            }
            let (instance_id, plan_digest) = (allocation.instance_id, allocation.plan_digest);
            let receipt = Self::commit_fence(
                &mut state.fenced,
                node_id,
                instance_id,
                allocation_id,
                plan_digest,
            )?;
            state.sandboxes.remove(id);
            state.removed.push(id.to_string());
            (receipt, state.remove_after_delete.take())
        };
        if let Some(gate) = after {
            gate.hold().await;
        }
        let mut state = self.state();
        if std::mem::take(&mut state.fenced.lose_remove_reply) {
            return Err(RuntimeError::Backend(
                "helper reply lost after ABSENT".into(),
            ));
        }
        Ok(AbsenceReceipt::Fenced(Self::delivered(
            &state.fenced,
            receipt,
        )?))
    }

    fn fenced_inventory(&self) -> Result<BackendInventory, RuntimeError> {
        let state = self.state();
        if state.unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        let mut records: Vec<BackendRecord> = state
            .fenced
            .allocations
            .iter()
            .map(|(allocation_id, allocation)| BackendRecord {
                id: format!("fc-{allocation_id}"),
                status: match allocation.phase {
                    FakePhase::Ready if allocation.uncertain_execution => BackendStatus::Busy,
                    FakePhase::Ready => BackendStatus::Ready,
                    FakePhase::Stopped => BackendStatus::StoppedWithResources,
                    _ => BackendStatus::Busy,
                },
                allocation_id: Some(*allocation_id),
                plan_digest: Some(allocation.plan_digest),
                generation: allocation.generation,
            })
            .collect();
        records.extend(state.fenced.inventory_extra.iter().cloned());
        if state.fenced.inventory_duplicates
            && let Some(first) = records.first().cloned()
        {
            records.push(first);
        }
        Ok(BackendInventory {
            records,
            generation: state.fenced.node_generation,
            complete: !state.fenced.inventory_incomplete,
        })
    }

    /// Applies the fenced mode's reuse rules to a finished simulation.
    fn fenced_evidence(&self, id: &str, outcome: &mut ExecOutcome) {
        use SandboxDisposition::{Quarantined, Reusable, Stopped};
        (outcome.disposition, outcome.cleanup) = match &outcome.finish {
            Ok(ExecFinish::Completed) => (Reusable, CleanupEvidence::RuntimeDrained),
            Ok(ExecFinish::TimedOut | ExecFinish::Canceled) => {
                (Stopped, CleanupEvidence::SandboxStopped)
            }
            Err(d) if d.kind == RuntimeErrorKind::NotFound => {
                (Stopped, CleanupEvidence::SandboxStopped)
            }
            Err(_) => (Quarantined, CleanupEvidence::Unknown),
        };
        if outcome.disposition == Stopped {
            let mut guard = self.state();
            let state = &mut *guard;
            let token = id
                .strip_prefix("fc-")
                .and_then(|hex| Id128::parse(hex).ok());
            if let Some(allocation) = token.and_then(|t| state.fenced.allocations.get_mut(&t)) {
                allocation.phase = FakePhase::Stopped;
                state
                    .sandboxes
                    .insert(id.to_string(), BackendStatus::StoppedWithResources);
            }
        }
    }

    /// Adds a sandbox the way something other than kilnd would.
    pub fn insert(&self, status: BackendStatus) -> String {
        let mut s = self.state();
        s.next += 1;
        let id = format!("f00d-{}", s.next);
        s.sandboxes.insert(id.clone(), status);
        id
    }

    fn running(&self, id: &str) -> Result<(), RuntimeError> {
        match self.state().sandboxes.get(id) {
            Some(BackendStatus::Running | BackendStatus::Ready) => Ok(()),
            _ => Err(RuntimeError::NotFound(id.to_string())),
        }
    }

    /// Runs one simulated command. A fresh legacy execution keeps kiln's mapping;
    /// the fenced mode applies its own reuse rules afterward.
    fn with_evidence(&self, id: &str, mut outcome: ExecOutcome) -> ExecOutcome {
        if self.state().mode == FakeEvidenceMode::Fenced {
            self.fenced_evidence(id, &mut outcome);
            if let Some(claim) = self.state().fenced.forge_exec_claim.take() {
                (outcome.disposition, outcome.cleanup) = claim;
            }
        } else {
            (outcome.disposition, outcome.cleanup) = legacy_exec_evidence(&outcome.finish);
        }
        outcome
    }
}

fn exited(code: i32, stdout: Vec<u8>, max: usize) -> ExecOutcome {
    let total = stdout.len() as u64;
    let data = stdout[..stdout.len().min(max)].to_vec();
    let truncated = total > data.len() as u64;
    ExecOutcome {
        finish: Ok(ExecFinish::Completed),
        command_status: Some(CommandStatus::Exited(code)),
        stdout: Captured {
            data,
            total_bytes: total,
            truncated,
            total_bytes_known: true,
        },
        stderr: Captured::known_empty(),
        disposition: SandboxDisposition::Reusable,
        cleanup: CleanupEvidence::RuntimeDrained,
    }
}

/// One fake output stream as a capture reader keeps it: counted, the prefix retained,
/// then offered to the live tap.
struct FakeCapture {
    captured: Captured,
    max: usize,
}

impl FakeCapture {
    fn new(max: usize) -> Self {
        Self {
            captured: Captured::known_empty(),
            max,
        }
    }

    fn write(&mut self, spec: &ExecSpec<'_>, stream: LiveStream, bytes: &[u8]) {
        let offset = self.captured.total_bytes;
        self.captured.total_bytes += bytes.len() as u64;
        let room = self.max.saturating_sub(self.captured.data.len());
        self.captured.truncated |= bytes.len() > room;
        self.captured
            .data
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
        if let Some(tap) = &spec.live {
            tap.offer(stream, offset, bytes);
        }
    }

    fn outcome(self, finish: ExecFinish, stderr: FakeCapture) -> ExecOutcome {
        ExecOutcome {
            command_status: (finish == ExecFinish::Completed).then_some(CommandStatus::Exited(0)),
            finish: Ok(finish),
            stdout: self.captured,
            stderr: stderr.captured,
            disposition: SandboxDisposition::Reusable,
            cleanup: CleanupEvidence::RuntimeDrained,
        }
    }
}

/// Waits `pause` (yielding at least once), or stops for the deadline or cancellation.
async fn fake_pause(
    spec: &ExecSpec<'_>,
    cancel: &CancellationToken,
    pause: Duration,
) -> Option<ExecFinish> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Some(ExecFinish::Canceled),
        () = tokio::time::sleep_until(spec.deadline) => Some(ExecFinish::TimedOut),
        () = async {
            tokio::task::yield_now().await;
            tokio::time::sleep(pause).await;
        } => None,
    }
}

fn no_output(finish: Result<ExecFinish, RuntimeDiagnostic>) -> ExecOutcome {
    ExecOutcome {
        finish,
        command_status: None,
        stdout: Captured::known_empty(),
        stderr: Captured::known_empty(),
        disposition: SandboxDisposition::Reusable,
        cleanup: CleanupEvidence::RuntimeDrained,
    }
}

impl Runtime for FakeRuntime {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        let fenced = self.state().mode == FakeEvidenceMode::Fenced;
        RuntimeCapabilities {
            network_modes: if fenced {
                vec![Network::None]
            } else {
                vec![Network::None, Network::Full, Network::Allow(Vec::new())]
            },
            interruption_preserves_session: !fenced,
            checkpoint: false,
            accounting: if fenced {
                AccountingAuthority::Node
            } else {
                AccountingAuthority::LocalLegacy
            },
        }
    }

    async fn node_totals(
        &self,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<Option<super::NodeTotals>, RuntimeError> {
        match self.state().node_totals.clone() {
            Some(totals) => Ok(Some(totals)),
            None => Err(RuntimeError::Backend("node authority unavailable".into())),
        }
    }

    async fn version(
        &self,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<String, RuntimeError> {
        let (gate, panic_version) = {
            let mut state = self.state();
            state.version_calls += 1;
            state.active_version_calls += 1;
            (state.version_gate.take(), state.panic_version)
        };
        let _active = ActiveVersion(self.state.clone());
        if let Some(gate) = gate {
            let error = tokio::select! {
                biased;
                () = cancel.cancelled() => Some("version probe canceled"),
                () = tokio::time::sleep_until(deadline) => Some("version probe timed out"),
                () = gate.hold() => None,
            };
            if let Some(error) = error {
                let cleanup = self.state().version_cleanup_gate.take();
                if let Some(cleanup) = cleanup {
                    cleanup.hold().await;
                }
                return Err(RuntimeError::Backend(error.into()));
            }
        }
        assert!(!panic_version, "injected fake version panic");
        if self.state().unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        Ok("fake 1.0".into())
    }

    async fn proven_features(
        &self,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<crate::manager::ProvenFeatures, RuntimeError> {
        self.state()
            .proven_features
            .clone()
            .map(crate::manager::ProvenFeatures)
            .map_err(RuntimeError::Backend)
    }

    async fn prepare(
        &self,
        _context: &PrepareContext,
        spec: &SandboxSpec,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<PreparedCreate, RuntimeError> {
        let (node_id, gate, fail, panics, ignores_cancel, token) = {
            let mut state = self.state();
            if state.mode == FakeEvidenceMode::Legacy {
                return Ok(PreparedCreate::legacy(spec.clone(), "fake"));
            }
            if let Some(message) = state.fenced.exhaust_prepare.clone() {
                return Err(RuntimeError::Exhausted(message));
            }
            state.fenced.prepare_calls += 1;
            // B7: the fake authority issues the token, as the helper does: a sequence
            // followed by a tag, never a daemon-minted ID.
            state.fenced.issued += 1;
            let mut bytes = *Id128::random().as_bytes();
            bytes[..8].copy_from_slice(&state.fenced.issued.to_be_bytes());
            (
                Self::fenced_node(&state),
                state.fenced.prepare_gate.take(),
                state.fenced.fail_prepare.clone(),
                state.fenced.prepare_panics,
                state.fenced.prepare_ignores_cancel,
                Id128::from_bytes(bytes),
            )
        };
        if let Some(gate) = gate {
            if ignores_cancel {
                gate.hold().await;
            } else {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        return Err(RuntimeError::Backend("preflight canceled".into()));
                    }
                    () = tokio::time::sleep_until(deadline) => {
                        return Err(RuntimeError::Backend("preflight timed out".into()));
                    }
                    () = gate.hold() => {}
                }
            }
        }
        assert!(!panics, "injected fake prepare panic");
        if let Some(message) = fail {
            return Err(RuntimeError::Incompatible(message));
        }
        let reservation =
            crate::firecracker::offline_768_v1_reservation(spec).map_err(RuntimeError::Backend)?;
        // Bound to the spec so a changed spec can never share a plan digest.
        let plan = serde_json::to_vec(&(spec, reservation)).map_err(std::io::Error::other)?;
        PreparedCreate::fenced(
            spec.clone(),
            reservation,
            1,
            plan,
            "offline-768-v1",
            Digest::of(b"fake approved bundle"),
            node_id,
            token,
        )
    }

    async fn create(
        &self,
        context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<CreatedSandbox, CreateFailure> {
        if self.state().mode == FakeEvidenceMode::Fenced {
            return self.create_fenced(context, prepared, deadline).await;
        }
        let spec = prepared.spec();
        let before = self.state().create_before_allocation.take();
        if let Some(gate) = before {
            gate.hold().await;
        }
        let (id, after) = {
            let mut s = self.state();
            assert!(!s.panic_create, "injected fake create panic");
            if let Some(msg) = &s.fail_create_definitely {
                return Err(CreateFailure::definitely_not_created(
                    RuntimeError::Backend(msg.clone()),
                ));
            }
            if let Some(msg) = &s.fail_create {
                return Err(RuntimeError::Backend(msg.clone()).into());
            }
            s.created.push(spec.clone());
            s.next += 1;
            let id = format!("f00d-{}", s.next);
            s.sandboxes.insert(id.clone(), BackendStatus::Running);
            if let Some(msg) = &s.fail_create_after_allocation {
                return Err(RuntimeError::Backend(msg.clone()).into());
            }
            (id, s.create_after_allocation.take())
        };
        if let Some(gate) = after {
            gate.hold().await;
        }
        let exec_features = self.state().create_exec_features;
        Ok(CreatedSandbox {
            backend_id: id,
            receipt: RuntimeReceipt::Legacy,
            exec_features,
        })
    }

    async fn inspect_allocation(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<AllocationObservation, RuntimeError> {
        let mut guard = self.state();
        let state = &mut *guard;
        if state.mode == FakeEvidenceMode::Legacy {
            return Ok(AllocationObservation::Unsupported);
        }
        if state.fenced.inspect_unavailable {
            return Err(RuntimeError::Backend("fake helper unavailable".into()));
        }
        if let Some(observation) = state.fenced.observation_override.clone() {
            return Ok(observation);
        }
        let allocation_id = context.allocation_id;
        if let Some(fence) = state.fenced.fences.get(&allocation_id).cloned() {
            return Ok(AllocationObservation::AbsentFenced(Self::delivered(
                &state.fenced,
                fence,
            )?));
        }
        let Some(allocation) = state.fenced.allocations.get(&allocation_id) else {
            return Ok(AllocationObservation::Unknown {
                reason: format!("no record for allocation {allocation_id}"),
            });
        };
        if allocation.plan_digest != *prepared_digest {
            return Ok(AllocationObservation::Unknown {
                reason: format!("allocation {allocation_id} has a different plan"),
            });
        }
        Ok(if allocation.phase == FakePhase::Stopped {
            AllocationObservation::StoppedWithResources {
                helper_generation: allocation.generation,
            }
        } else {
            AllocationObservation::Present {
                receipt: Self::ready_receipt(state, allocation_id, allocation),
                healthy_idle: allocation.phase == FakePhase::Ready
                    && !allocation.uncertain_execution,
                uncertain_execution: allocation.uncertain_execution,
            }
        })
    }

    async fn fence_absent(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        let allocation_id = context.allocation_id;
        let gate = {
            let mut guard = self.state();
            let state = &mut *guard;
            if state.mode == FakeEvidenceMode::Legacy {
                return Err(RuntimeError::Unsupported(
                    "the legacy fake has no allocation-token recovery".into(),
                ));
            }
            state.fenced.fence_calls += 1;
            if let Some(fence) = state.fenced.fences.get(&allocation_id).cloned() {
                return Ok(AbsenceReceipt::Fenced(Self::delivered(
                    &state.fenced,
                    fence,
                )?));
            }
            if state.fenced.allocations.contains_key(&allocation_id) {
                return Err(RuntimeError::Backend(format!(
                    "allocation {allocation_id} still owns resources"
                )));
            }
            if let Some(message) = &state.fenced.fence_unavailable {
                return Err(RuntimeError::Backend(message.clone()));
            }
            state.fenced.fence_gate.take()
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        let mut guard = self.state();
        let state = &mut *guard;
        // Another caller may have committed while this one waited at the gate.
        if let Some(fence) = state.fenced.fences.get(&allocation_id).cloned() {
            return Ok(AbsenceReceipt::Fenced(Self::delivered(
                &state.fenced,
                fence,
            )?));
        }
        let node_id = Self::fenced_node(state);
        let receipt = Self::commit_fence(
            &mut state.fenced,
            node_id,
            context.instance_id,
            allocation_id,
            *prepared_digest,
        )?;
        if std::mem::take(&mut state.fenced.lose_fence_reply) {
            return Err(RuntimeError::Backend(
                "helper reply lost after fence".into(),
            ));
        }
        Ok(AbsenceReceipt::Fenced(Self::delivered(
            &state.fenced,
            receipt,
        )?))
    }

    async fn validate_sandbox(
        &self,
        id: &str,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if self.state().incompatible_sandboxes.iter().any(|s| s == id) {
            return Err(RuntimeError::Incompatible(format!(
                "sandbox {id} incompatible"
            )));
        }
        self.running(id)
    }

    async fn exec(
        &self,
        id: &str,
        _execution: &ExecutionContext,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        if let Err(e) = self.running(id) {
            return self.with_evidence(
                id,
                no_output(Err(RuntimeDiagnostic::new(
                    RuntimeErrorKind::NotFound,
                    RuntimeStage::Connect,
                    e.to_string(),
                ))),
            );
        }
        if cancel.is_cancelled() {
            self.state().canceled_execs += 1;
            // Proof no bytes were dispatched, so even a fenced session survives.
            return ExecOutcome {
                disposition: SandboxDisposition::Reusable,
                cleanup: CleanupEvidence::NoChildStarted,
                ..no_output(Ok(ExecFinish::Canceled))
            };
        }
        let (gate, panic_exec) = {
            let mut state = self.state();
            state.exec_calls.push(spec.argv.to_vec());
            state.exec_options.push(spec.options.clone());
            state.exec_deadlines.push(spec.deadline);
            state.active_execs += 1;
            (state.exec_before_run.take(), state.panic_exec)
        };
        let _active = ActiveExec {
            state: self.state.clone(),
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        assert!(!panic_exec, "injected fake exec panic");
        let args = &spec.argv[1..];
        let arg = |i: usize, default: u64| -> u64 {
            args.get(i).and_then(|a| a.parse().ok()).unwrap_or(default)
        };
        let live_command = matches!(spec.argv[0].as_str(), "stream" | "flood" | "torn");
        let outcome = match spec.argv[0].as_str() {
            // ExecStream (design 5): `stream CHUNKS BYTES MS` writes CHUNKS stdout chunks
            // of BYTES (each the chunk number's byte) and a short stderr line each, MS
            // apart, like a capture reader would offer them.
            "stream" => {
                let mut out = FakeCapture::new(spec.max_output);
                let mut err = FakeCapture::new(spec.max_output);
                let finish = 'run: {
                    for i in 0..arg(0, 1) {
                        out.write(spec, LiveStream::Stdout, &vec![i as u8; arg(1, 1) as usize]);
                        err.write(spec, LiveStream::Stderr, format!("e{i}\n").as_bytes());
                        if let Some(stop) =
                            fake_pause(spec, cancel, Duration::from_millis(arg(2, 0))).await
                        {
                            break 'run stop;
                        }
                    }
                    ExecFinish::Completed
                };
                out.outcome(finish, err)
            }
            // `flood MS`: 16 KiB stdout writes at full rate for MS, yielding between.
            "flood" => {
                let mut out = FakeCapture::new(spec.max_output);
                let until = tokio::time::Instant::now() + Duration::from_millis(arg(0, 100));
                let chunk = vec![b'f'; 16 * 1024];
                let finish = loop {
                    if tokio::time::Instant::now() >= until {
                        break ExecFinish::Completed;
                    }
                    out.write(spec, LiveStream::Stdout, &chunk);
                    if let Some(stop) = fake_pause(spec, cancel, Duration::ZERO).await {
                        break stop;
                    }
                };
                out.outcome(finish, FakeCapture::new(spec.max_output))
            }
            // `torn`: a helper that died after a live drop and before settlement. Bytes
            // 0..10 and 30..33 reach the tap, the capture total is not known.
            "torn" => {
                if let Some(tap) = &spec.live {
                    tap.offer(LiveStream::Stdout, 0, b"0123456789");
                    tap.offer(LiveStream::Stdout, 30, b"abc");
                }
                ExecOutcome {
                    finish: Err(RuntimeDiagnostic::new(
                        RuntimeErrorKind::CleanupFailed,
                        RuntimeStage::Cleanup,
                        "helper execution/cleanup could not be confirmed: injected helper death",
                    )),
                    command_status: None,
                    stdout: Captured {
                        data: b"0123456789"[..10.min(spec.max_output)].to_vec(),
                        total_bytes: 10,
                        truncated: spec.max_output < 10,
                        total_bytes_known: false,
                    },
                    stderr: Captured::default(),
                    disposition: SandboxDisposition::Quarantined,
                    cleanup: CleanupEvidence::Unknown,
                }
            }
            "echo" => exited(
                0,
                format!("{}\n", args.join(" ")).into_bytes(),
                spec.max_output,
            ),
            "cat" => exited(0, spec.stdin.to_vec(), spec.max_output),
            // kiln's operation 5 environment: the base overlaid by the overrides.
            "env" => {
                let mut env: BTreeMap<String, String> = [
                    ("HOME", "/root"),
                    ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
                    ("TERM", "xterm"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
                for e in &spec.options.env {
                    env.insert(e.name.clone(), e.value.clone());
                }
                let text: String = env.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
                exited(0, text.into_bytes(), spec.max_output)
            }
            // kiln's chdir: a cwd under /missing cannot be entered.
            "pwd" => match spec.options.cwd.as_deref() {
                Some(cwd) if cwd.starts_with("/missing") => ExecOutcome {
                    finish: Err(RuntimeDiagnostic {
                        native_code: Some("ENOENT".into()),
                        ..RuntimeDiagnostic::new(
                            RuntimeErrorKind::LaunchFailed,
                            RuntimeStage::Cwd,
                            "chdir: No such file or directory",
                        )
                    }),
                    command_status: None,
                    stdout: Captured::known_empty(),
                    stderr: Captured::known_empty(),
                    disposition: SandboxDisposition::Reusable,
                    cleanup: CleanupEvidence::RuntimeDrained,
                },
                cwd => exited(0, format!("{}\n", cwd.unwrap_or("/")).into_bytes(), spec.max_output),
            },
            "exit" => exited(
                args.first().and_then(|a| a.parse().ok()).unwrap_or(1),
                vec![],
                spec.max_output,
            ),
            "spew" => exited(
                0,
                vec![b'x'; args.first().and_then(|a| a.parse().ok()).unwrap_or(0)],
                spec.max_output,
            ),
            "spew-both" => {
                let total = args.first().and_then(|a| a.parse().ok()).unwrap_or(0);
                let kept = total.min(spec.max_output);
                ExecOutcome {
                    finish: Ok(ExecFinish::Completed),
                    command_status: Some(CommandStatus::Exited(0)),
                    stdout: Captured {
                        data: vec![b'x'; kept],
                        total_bytes: total as u64,
                        truncated: kept < total,
                        total_bytes_known: true,
                    },
                    stderr: Captured {
                        data: vec![b'y'; kept],
                        total_bytes: total as u64,
                        truncated: kept < total,
                        total_bytes_known: true,
                    },
                    disposition: SandboxDisposition::Reusable,
                    cleanup: CleanupEvidence::RuntimeDrained,
                }
            }
            "sleep" => {
                let finish = tokio::select! {
                    () = tokio::time::sleep_until(spec.deadline) => ExecFinish::TimedOut,
                    () = cancel.cancelled() => {
                        self.state().canceled_execs += 1;
                        ExecFinish::Canceled
                    },
                };
                no_output(Ok(finish))
            }
            "vanish" => {
                self.state().sandboxes.remove(id);
                no_output(Err(RuntimeDiagnostic::new(
                    RuntimeErrorKind::NotFound,
                    RuntimeStage::Connect,
                    format!("sandbox {id} not found in backend"),
                )))
            }
            "cleanup-fail" => no_output(Err(RuntimeDiagnostic::new(
                RuntimeErrorKind::CleanupFailed,
                RuntimeStage::Cleanup,
                "injected cleanup failure",
            ))),
            "signal" => ExecOutcome {
                command_status: Some(CommandStatus::Signaled {
                    signal: args.first().and_then(|s| s.parse().ok()).unwrap_or(15),
                    core_dumped: args.get(1).is_some_and(|s| s == "core"),
                }),
                ..exited(0, vec![], spec.max_output)
            },
            "invalid-completed" => ExecOutcome {
                command_status: None,
                ..exited(0, b"saved".to_vec(), spec.max_output)
            },
            "runtime-failure" => ExecOutcome {
                finish: Err(RuntimeDiagnostic::new(
                    RuntimeErrorKind::Io,
                    RuntimeStage::Capture,
                    "injected binary evidence failure",
                )),
                command_status: Some(CommandStatus::Exited(125)),
                stdout: Captured {
                    data: b"\0\xffout"[..5.min(spec.max_output)].to_vec(),
                    total_bytes: 99,
                    truncated: 5.min(spec.max_output) < 99,
                    total_bytes_known: false,
                },
                stderr: Captured {
                    data: b"\0\xfeerr"[..5.min(spec.max_output)].to_vec(),
                    total_bytes: 101,
                    truncated: 5.min(spec.max_output) < 101,
                    total_bytes_known: false,
                },
                disposition: SandboxDisposition::Reusable,
                cleanup: CleanupEvidence::RuntimeDrained,
            },
            _ => ExecOutcome {
                finish: Ok(ExecFinish::Completed),
                command_status: Some(CommandStatus::Exited(127)),
                stdout: Captured::known_empty(),
                stderr: Captured {
                    data: b"not found\n".to_vec(),
                    total_bytes: 10,
                    truncated: false,
                    total_bytes_known: true,
                },
                disposition: SandboxDisposition::Reusable,
                cleanup: CleanupEvidence::RuntimeDrained,
            },
        };
        // Every other command's output reaches a live tap whole, after the fact, at the
        // offsets a capture reader would give it.
        if let Some(tap) = &spec.live
            && !live_command
        {
            for (stream, captured) in [
                (LiveStream::Stdout, &outcome.stdout),
                (LiveStream::Stderr, &outcome.stderr),
            ] {
                let filler = captured.data.last().copied().unwrap_or(b'x');
                let mut offset = 0u64;
                for piece in captured.data.chunks(16 * 1024) {
                    tap.offer(stream, offset, piece);
                    offset += piece.len() as u64;
                }
                while offset < captured.total_bytes {
                    let n = (captured.total_bytes - offset).min(16 * 1024) as usize;
                    tap.offer(stream, offset, &vec![filler; n]);
                    offset += n as u64;
                }
            }
        }
        self.with_evidence(id, outcome)
    }

    async fn remove(
        &self,
        target: RemoveTarget<'_>,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        self.state().remove_targets.push(match target {
            RemoveTarget::Legacy { backend_id } => format!("legacy:{backend_id}"),
            RemoveTarget::Fenced { binding } => format!("fenced:{}", binding.allocation_id),
        });
        // B7: each regime accepts only its own target, refused before anything happens.
        if self.state().mode == FakeEvidenceMode::Fenced {
            let binding = target.fenced()?;
            return self
                .remove_fenced(&format!("fc-{}", binding.allocation_id))
                .await;
        }
        let id = target.legacy()?;
        let (gate, hold) = {
            let mut s = self.state();
            s.remove_attempts.push(id.to_string());
            if !s.sandboxes.contains_key(id) {
                return Err(RuntimeError::NotFound(id.to_string()));
            }
            s.active_removes += 1;
            s.max_active_removes = s.max_active_removes.max(s.active_removes);
            (s.remove_before_delete.take(), s.remove_hold.clone())
        };
        struct Active(Arc<Mutex<FakeState>>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .active_removes -= 1;
            }
        }
        let _active = Active(self.state.clone());
        if let Some(hold) = hold {
            hold.notified().await;
        }
        if let Some(gate) = gate {
            gate.hold().await;
        }
        let after = {
            let mut s = self.state();
            if !s.sandboxes.contains_key(id) {
                return Err(RuntimeError::NotFound(id.to_string()));
            }
            if s.fail_remove {
                return Err(RuntimeError::Backend("fake remove failed".into()));
            }
            s.sandboxes.remove(id);
            s.removed.push(id.to_string());
            s.remove_after_delete.take()
        };
        if let Some(gate) = after {
            gate.hold().await;
        }
        Ok(AbsenceReceipt::Legacy(LegacyAbsence {
            backend_id: id.to_string(),
            proof: LegacyProof::StrictRemoval,
        }))
    }

    async fn list(
        &self,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<BackendInventory, RuntimeError> {
        if self.state().mode == FakeEvidenceMode::Fenced {
            return self.fenced_inventory();
        }
        let s = self.state();
        if s.unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        Ok(BackendInventory {
            records: s
                .sandboxes
                .iter()
                .filter(|(id, _)| !s.hidden_from_list.iter().any(|hidden| hidden == *id))
                .map(|(id, status)| BackendRecord {
                    id: id.clone(),
                    status: *status,
                    allocation_id: None,
                    plan_digest: None,
                    generation: 0,
                })
                .collect(),
            generation: 0,
            complete: true,
        })
    }

    async fn gc(
        &self,
        targets: &[RemoveTarget<'_>],
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<Vec<AbsenceReceipt>, RuntimeError> {
        let mut guard = self.state();
        let s = &mut *guard;
        // B7: all or nothing: one target of the other regime refuses the whole call.
        let ids: Vec<String> = if s.mode == FakeEvidenceMode::Fenced {
            targets
                .iter()
                .map(|t| t.fenced().map(|b| format!("fc-{}", b.allocation_id)))
                .collect::<Result<_, _>>()?
        } else {
            super::legacy_targets(targets)?
        };
        let ids = ids.as_slice();
        if s.unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        s.gc_runs += 1;
        s.gc_requests.push(ids.to_vec());
        if s.mode == FakeEvidenceMode::Fenced {
            // Only named allocations individually proven stopped; never a live one.
            let node_id = Self::fenced_node(s);
            let mut receipts = Vec::new();
            for id in ids {
                let token = id
                    .strip_prefix("fc-")
                    .and_then(|hex| Id128::parse(hex).ok());
                let Some(allocation_id) = token else { continue };
                let Some(allocation) = s.fenced.allocations.get(&allocation_id) else {
                    continue;
                };
                if allocation.phase != FakePhase::Stopped {
                    continue;
                }
                let (instance_id, plan_digest) = (allocation.instance_id, allocation.plan_digest);
                let receipt = Self::commit_fence(
                    &mut s.fenced,
                    node_id,
                    instance_id,
                    allocation_id,
                    plan_digest,
                )?;
                s.sandboxes.remove(id);
                receipts.push(AbsenceReceipt::Fenced(receipt));
            }
            return Ok(receipts);
        }
        let stale: Vec<String> = s
            .sandboxes
            .iter()
            .filter(|(id, st)| {
                **st == BackendStatus::Stale && ids.iter().any(|requested| requested == *id)
            })
            .map(|(id, _)| id.to_string())
            .collect();
        for id in &stale {
            s.sandboxes.remove(id);
        }
        Ok(stale
            .into_iter()
            .map(|backend_id| {
                AbsenceReceipt::Legacy(LegacyAbsence {
                    backend_id,
                    proof: LegacyProof::ScopedGc,
                })
            })
            .collect())
    }
}
