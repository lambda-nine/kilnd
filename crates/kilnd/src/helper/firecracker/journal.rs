//! The root node ledger: section 4.1's one authority for node capacity, identities,
//! worker intents, receipts and permanent fences. Only the L process opens it. All SQL
//! is fixed text here. Every release after a claim goes through `commit_fence`, in one
//! FULL-sync transaction that also writes the permanent retired-token entry.
use super::config::{NodeCeilings, SharedReserve, validate_ceilings};
use super::executable::{ExecutableIdentity, ProtectedDir, Role, WalkPolicy, walk_directory};
use super::identity::{ClaimedIdentities, IdentityLeases, LeaseKind};
use crate::model::{Digest, Id128, ResourceReservation, now_ms};
use crate::runtime::FencedAbsence;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const LEDGER_DB: &str = "node.db";
pub const LEDGER_LOCK: &str = "node.lock";
const APPLICATION_ID: i64 = 0x4b46_4331; // "KFC1"
const SCHEMA_VERSION: i64 = 1;
/// The most space one retired token can need, across all its rows.
pub const FENCE_ENTRY_BOUND: u64 = 4096;
/// Headroom kept for tokens the helper has not seen yet: a daemon may hold a C1 row
/// that never reached L. Admission stops before fencing them would not fit.
pub const PRE_INTENT_TOKEN_MARGIN: u64 = 1024;
/// A complete inventory is bounded to this many active allocations.
pub const MAX_ACTIVE_LISTED: usize = 1024;

const SCHEMA: &str = "
CREATE TABLE node_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    node_id TEXT NOT NULL UNIQUE,
    created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE generation_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL CHECK (value >= 1)
) STRICT;
CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    database_uuid TEXT NOT NULL,
    first_generation INTEGER NOT NULL CHECK (first_generation >= 1)
) STRICT;
CREATE TABLE allocations (
    allocation_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    sandbox_id TEXT NOT NULL UNIQUE,
    backend_id TEXT NOT NULL UNIQUE,
    plan_version INTEGER NOT NULL,
    plan_digest TEXT NOT NULL,
    profile TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    host_spec_sha256 TEXT NOT NULL,
    guest_exec_spec_sha256 TEXT NOT NULL,
    work_uuid TEXT NOT NULL,
    stop_authority TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN
        ('intent','preparing','stop_intent','stopped','quarantined','absent')),
    created_generation INTEGER NOT NULL CHECK (created_generation >= 1),
    updated_generation INTEGER NOT NULL CHECK (updated_generation >= created_generation)
) STRICT;
CREATE TABLE allocation_plans (
    allocation_id TEXT PRIMARY KEY REFERENCES allocations(allocation_id),
    plan BLOB NOT NULL
) STRICT;
CREATE TABLE capacity_claims (
    allocation_id TEXT PRIMARY KEY REFERENCES allocations(allocation_id),
    memory_bytes INTEGER NOT NULL CHECK (memory_bytes >= 0),
    disk_bytes INTEGER NOT NULL CHECK (disk_bytes >= 0),
    pids INTEGER NOT NULL CHECK (pids >= 0),
    host_cpu_millis INTEGER NOT NULL CHECK (host_cpu_millis >= 0),
    virtual_cpu_slots INTEGER NOT NULL CHECK (virtual_cpu_slots >= 0),
    host_pids INTEGER NOT NULL CHECK (host_pids >= 0),
    claimed_generation INTEGER NOT NULL CHECK (claimed_generation >= 1),
    released_generation INTEGER CHECK (released_generation IS NULL
        OR released_generation > claimed_generation)
) STRICT;
CREATE TABLE identity_leases (
    id INTEGER PRIMARY KEY,
    namespace TEXT NOT NULL CHECK (namespace IN ('uid','gid','cid')),
    kind TEXT NOT NULL CHECK (kind IN ('vmm_uid','relay_uid','vmm_gid','relay_gid','cid')),
    value INTEGER NOT NULL,
    allocation_id TEXT NOT NULL REFERENCES allocations(allocation_id),
    claimed_generation INTEGER NOT NULL CHECK (claimed_generation >= 1),
    released_generation INTEGER CHECK (released_generation IS NULL
        OR released_generation > claimed_generation),
    UNIQUE (allocation_id, kind)
) STRICT;
CREATE UNIQUE INDEX identity_leases_active
    ON identity_leases(namespace, value) WHERE released_generation IS NULL;
CREATE TABLE executable_leases (
    allocation_id TEXT NOT NULL REFERENCES allocations(allocation_id),
    role TEXT NOT NULL,
    st_dev INTEGER NOT NULL,
    st_ino INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    installation_generation INTEGER NOT NULL CHECK (installation_generation >= 1),
    observed_st_dev INTEGER,
    observed_st_ino INTEGER,
    observed_bytes INTEGER,
    observed_sha256 TEXT,
    released_generation INTEGER,
    PRIMARY KEY (allocation_id, role)
) STRICT;
CREATE TABLE worker_intents (
    id INTEGER PRIMARY KEY,
    allocation_id TEXT REFERENCES allocations(allocation_id),
    mode TEXT NOT NULL,
    operation_generation INTEGER NOT NULL UNIQUE CHECK (operation_generation >= 1),
    allowed_names TEXT NOT NULL,
    cgroup TEXT NOT NULL,
    exec_role TEXT NOT NULL,
    exec_st_dev INTEGER NOT NULL,
    exec_st_ino INTEGER NOT NULL,
    exec_bytes INTEGER NOT NULL,
    exec_sha256 TEXT NOT NULL,
    host_boot_id TEXT,
    pid INTEGER,
    start_time INTEGER,
    settled_generation INTEGER,
    settlement TEXT
) STRICT;
CREATE TABLE retired_tokens (
    allocation_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    sandbox_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    helper_generation INTEGER NOT NULL UNIQUE CHECK (helper_generation >= 1),
    receipt BLOB NOT NULL
) STRICT;
CREATE TABLE stop_events (
    id INTEGER PRIMARY KEY,
    allocation_id TEXT NOT NULL REFERENCES allocations(allocation_id),
    generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    reason TEXT NOT NULL
) STRICT;

-- Collision guards run before any conflict algorithm can implicitly delete a row.
CREATE TRIGGER node_identity_no_replace BEFORE INSERT ON node_identity
WHEN EXISTS (SELECT 1 FROM node_identity WHERE rowid = NEW.rowid OR id = NEW.id OR node_id = NEW.node_id)
BEGIN SELECT RAISE(ABORT, 'node identity is immutable'); END;
CREATE TRIGGER node_identity_no_update BEFORE UPDATE ON node_identity
BEGIN SELECT RAISE(ABORT, 'node identity is immutable'); END;
CREATE TRIGGER node_identity_no_delete BEFORE DELETE ON node_identity
BEGIN SELECT RAISE(ABORT, 'node identity is immutable'); END;

CREATE TRIGGER generation_no_replace BEFORE INSERT ON generation_counter
WHEN EXISTS (SELECT 1 FROM generation_counter WHERE rowid = NEW.rowid OR id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'the generation counter cannot be replaced'); END;
CREATE TRIGGER generation_is_monotonic BEFORE UPDATE ON generation_counter
WHEN NEW.id IS NOT OLD.id OR NEW.rowid IS NOT OLD.rowid OR NEW.value <= OLD.value
BEGIN SELECT RAISE(ABORT, 'generations only increase'); END;
CREATE TRIGGER generation_no_delete BEFORE DELETE ON generation_counter
BEGIN SELECT RAISE(ABORT, 'the generation counter is permanent'); END;

CREATE TRIGGER instances_no_replace BEFORE INSERT ON instances
WHEN EXISTS (SELECT 1 FROM instances WHERE rowid = NEW.rowid OR instance_id = NEW.instance_id)
BEGIN SELECT RAISE(ABORT, 'an instance binding cannot be replaced'); END;
CREATE TRIGGER instances_no_update BEFORE UPDATE ON instances
BEGIN SELECT RAISE(ABORT, 'an instance binding is immutable'); END;
CREATE TRIGGER instances_no_delete BEFORE DELETE ON instances
BEGIN SELECT RAISE(ABORT, 'an instance binding is permanent'); END;

CREATE TRIGGER allocations_no_replace BEFORE INSERT ON allocations
WHEN EXISTS (SELECT 1 FROM allocations WHERE rowid = NEW.rowid
    OR allocation_id = NEW.allocation_id OR sandbox_id = NEW.sandbox_id OR backend_id = NEW.backend_id)
BEGIN SELECT RAISE(ABORT, 'an allocation cannot be replaced'); END;
CREATE TRIGGER allocations_no_replace_update BEFORE UPDATE ON allocations
WHEN EXISTS (SELECT 1 FROM allocations WHERE rowid != OLD.rowid AND (rowid = NEW.rowid
    OR allocation_id = NEW.allocation_id OR sandbox_id = NEW.sandbox_id OR backend_id = NEW.backend_id))
BEGIN SELECT RAISE(ABORT, 'an allocation cannot be replaced'); END;
CREATE TRIGGER allocations_no_resurrection BEFORE INSERT ON allocations
WHEN EXISTS (SELECT 1 FROM retired_tokens WHERE allocation_id = NEW.allocation_id)
BEGIN SELECT RAISE(ABORT, 'a retired token cannot be allocated'); END;
CREATE TRIGGER allocations_immutable BEFORE UPDATE ON allocations
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.allocation_id IS NOT OLD.allocation_id
    OR NEW.instance_id IS NOT OLD.instance_id OR NEW.sandbox_id IS NOT OLD.sandbox_id
    OR NEW.backend_id IS NOT OLD.backend_id OR NEW.plan_version IS NOT OLD.plan_version
    OR NEW.plan_digest IS NOT OLD.plan_digest OR NEW.profile IS NOT OLD.profile
    OR NEW.manifest_sha256 IS NOT OLD.manifest_sha256
    OR NEW.host_spec_sha256 IS NOT OLD.host_spec_sha256
    OR NEW.guest_exec_spec_sha256 IS NOT OLD.guest_exec_spec_sha256
    OR NEW.work_uuid IS NOT OLD.work_uuid OR NEW.stop_authority IS NOT OLD.stop_authority
    OR NEW.created_generation IS NOT OLD.created_generation
BEGIN SELECT RAISE(ABORT, 'allocation identity is immutable'); END;
CREATE TRIGGER allocations_generation_compare BEFORE UPDATE ON allocations
WHEN NEW.updated_generation <= OLD.updated_generation
BEGIN SELECT RAISE(ABORT, 'allocation generations only increase'); END;
CREATE TRIGGER allocations_absent_is_final BEFORE UPDATE ON allocations
WHEN OLD.phase = 'absent'
BEGIN SELECT RAISE(ABORT, 'an absent allocation cannot change'); END;
CREATE TRIGGER allocations_absent_needs_release BEFORE UPDATE OF phase ON allocations
WHEN NEW.phase = 'absent' AND EXISTS (SELECT 1 FROM capacity_claims
    WHERE allocation_id = NEW.allocation_id AND released_generation IS NULL)
BEGIN SELECT RAISE(ABORT, 'absence requires its claim release'); END;
CREATE TRIGGER allocations_no_delete BEFORE DELETE ON allocations
BEGIN SELECT RAISE(ABORT, 'an allocation record is permanent'); END;

CREATE TRIGGER allocation_plans_no_replace BEFORE INSERT ON allocation_plans
WHEN EXISTS (SELECT 1 FROM allocation_plans WHERE rowid = NEW.rowid OR allocation_id = NEW.allocation_id)
BEGIN SELECT RAISE(ABORT, 'a plan cannot be replaced'); END;
CREATE TRIGGER allocation_plans_no_update BEFORE UPDATE ON allocation_plans
BEGIN SELECT RAISE(ABORT, 'a plan is immutable'); END;
-- Plan bytes alone leave when a permanent fence has retired the token.
CREATE TRIGGER allocation_plans_retained_until_fence BEFORE DELETE ON allocation_plans
WHEN NOT EXISTS (SELECT 1 FROM retired_tokens WHERE allocation_id = OLD.allocation_id)
BEGIN SELECT RAISE(ABORT, 'a plan stays until its absence fence'); END;

CREATE TRIGGER capacity_claims_no_replace BEFORE INSERT ON capacity_claims
WHEN EXISTS (SELECT 1 FROM capacity_claims WHERE rowid = NEW.rowid OR allocation_id = NEW.allocation_id)
BEGIN SELECT RAISE(ABORT, 'a capacity claim cannot be replaced'); END;
CREATE TRIGGER capacity_claims_immutable BEFORE UPDATE ON capacity_claims
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.allocation_id IS NOT OLD.allocation_id
    OR NEW.memory_bytes IS NOT OLD.memory_bytes OR NEW.disk_bytes IS NOT OLD.disk_bytes
    OR NEW.pids IS NOT OLD.pids OR NEW.host_cpu_millis IS NOT OLD.host_cpu_millis
    OR NEW.virtual_cpu_slots IS NOT OLD.virtual_cpu_slots OR NEW.host_pids IS NOT OLD.host_pids
    OR NEW.claimed_generation IS NOT OLD.claimed_generation
    OR OLD.released_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a capacity claim only changes by its one release'); END;
CREATE TRIGGER capacity_claims_no_delete BEFORE DELETE ON capacity_claims
BEGIN SELECT RAISE(ABORT, 'a capacity claim is permanent'); END;

CREATE TRIGGER identity_leases_no_replace BEFORE INSERT ON identity_leases
WHEN EXISTS (SELECT 1 FROM identity_leases WHERE rowid = NEW.rowid
    OR (allocation_id = NEW.allocation_id AND kind = NEW.kind)
    OR (namespace = NEW.namespace AND value = NEW.value AND released_generation IS NULL))
BEGIN SELECT RAISE(ABORT, 'an identity lease collides'); END;
CREATE TRIGGER identity_leases_immutable BEFORE UPDATE ON identity_leases
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.namespace IS NOT OLD.namespace OR NEW.kind IS NOT OLD.kind
    OR NEW.value IS NOT OLD.value OR NEW.allocation_id IS NOT OLD.allocation_id
    OR NEW.claimed_generation IS NOT OLD.claimed_generation
    OR OLD.released_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an identity lease only changes by its one release'); END;
CREATE TRIGGER identity_leases_no_delete BEFORE DELETE ON identity_leases
BEGIN SELECT RAISE(ABORT, 'an identity lease is permanent'); END;

CREATE TRIGGER executable_leases_no_replace BEFORE INSERT ON executable_leases
WHEN EXISTS (SELECT 1 FROM executable_leases WHERE rowid = NEW.rowid
    OR (allocation_id = NEW.allocation_id AND role = NEW.role))
BEGIN SELECT RAISE(ABORT, 'an executable lease cannot be replaced'); END;
CREATE TRIGGER executable_leases_immutable BEFORE UPDATE ON executable_leases
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.allocation_id IS NOT OLD.allocation_id OR NEW.role IS NOT OLD.role
    OR NEW.st_dev IS NOT OLD.st_dev OR NEW.st_ino IS NOT OLD.st_ino OR NEW.bytes IS NOT OLD.bytes
    OR NEW.sha256 IS NOT OLD.sha256
    OR NEW.installation_generation IS NOT OLD.installation_generation
    OR (OLD.observed_st_dev IS NOT NULL AND NEW.observed_st_dev IS NOT OLD.observed_st_dev)
    OR OLD.released_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an executable lease is immutable'); END;
CREATE TRIGGER executable_leases_no_delete BEFORE DELETE ON executable_leases
BEGIN SELECT RAISE(ABORT, 'an executable lease is permanent'); END;

CREATE TRIGGER worker_intents_no_replace BEFORE INSERT ON worker_intents
WHEN EXISTS (SELECT 1 FROM worker_intents WHERE rowid = NEW.rowid
    OR operation_generation = NEW.operation_generation)
BEGIN SELECT RAISE(ABORT, 'a worker intent cannot be replaced'); END;
CREATE TRIGGER worker_intents_immutable BEFORE UPDATE ON worker_intents
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.allocation_id IS NOT OLD.allocation_id OR NEW.mode IS NOT OLD.mode
    OR NEW.operation_generation IS NOT OLD.operation_generation
    OR NEW.allowed_names IS NOT OLD.allowed_names OR NEW.cgroup IS NOT OLD.cgroup
    OR NEW.exec_role IS NOT OLD.exec_role OR NEW.exec_st_dev IS NOT OLD.exec_st_dev
    OR NEW.exec_st_ino IS NOT OLD.exec_st_ino OR NEW.exec_bytes IS NOT OLD.exec_bytes
    OR NEW.exec_sha256 IS NOT OLD.exec_sha256
    OR (OLD.pid IS NOT NULL AND (NEW.pid IS NOT OLD.pid OR NEW.start_time IS NOT OLD.start_time
        OR NEW.host_boot_id IS NOT OLD.host_boot_id))
    OR OLD.settled_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a worker record is immutable once identified or settled'); END;
CREATE TRIGGER worker_intents_no_delete BEFORE DELETE ON worker_intents
BEGIN SELECT RAISE(ABORT, 'a worker record is permanent'); END;

CREATE TRIGGER retired_tokens_no_replace BEFORE INSERT ON retired_tokens
WHEN EXISTS (SELECT 1 FROM retired_tokens WHERE rowid = NEW.rowid OR allocation_id = NEW.allocation_id
    OR receipt_id = NEW.receipt_id OR helper_generation = NEW.helper_generation)
BEGIN SELECT RAISE(ABORT, 'a fence cannot be replaced'); END;
CREATE TRIGGER retired_tokens_need_release BEFORE INSERT ON retired_tokens
WHEN EXISTS (SELECT 1 FROM capacity_claims WHERE allocation_id = NEW.allocation_id
    AND released_generation IS NULL)
BEGIN SELECT RAISE(ABORT, 'a fence cannot coexist with a held claim'); END;
CREATE TRIGGER retired_tokens_no_update BEFORE UPDATE ON retired_tokens
BEGIN SELECT RAISE(ABORT, 'a fence is immutable'); END;
CREATE TRIGGER retired_tokens_no_delete BEFORE DELETE ON retired_tokens
BEGIN SELECT RAISE(ABORT, 'a fence is permanent'); END;

CREATE TRIGGER stop_events_no_replace BEFORE INSERT ON stop_events
WHEN EXISTS (SELECT 1 FROM stop_events WHERE rowid = NEW.rowid OR generation = NEW.generation)
BEGIN SELECT RAISE(ABORT, 'a stop event cannot be replaced'); END;
CREATE TRIGGER stop_events_no_update BEFORE UPDATE ON stop_events
BEGIN SELECT RAISE(ABORT, 'a stop event is immutable'); END;
CREATE TRIGGER stop_events_no_delete BEFORE DELETE ON stop_events
BEGIN SELECT RAISE(ABORT, 'a stop event is permanent'); END;
";

/// Every table with its write-guard surface, for the guard matrix.
pub const GUARDED_TABLES: [&str; 11] = [
    "node_identity",
    "generation_counter",
    "instances",
    "allocations",
    "allocation_plans",
    "capacity_claims",
    "identity_leases",
    "executable_leases",
    "worker_intents",
    "retired_tokens",
    "stop_events",
];

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("node ledger is not provisioned at {0}; refusing to create an empty authority")]
    Missing(PathBuf),
    #[error("node ledger is corrupt: {0}")]
    Corrupt(String),
    #[error("node ledger directory or files are unsafe: {0}")]
    Unsafe(String),
    #[error("node ledger already exists: {0}")]
    Exists(PathBuf),
    #[error("node ledger store: {0}")]
    Store(#[from] rusqlite::Error),
    #[error("node ledger arithmetic overflow in {0}")]
    Overflow(&'static str),
    #[error("node ledger configuration: {0}")]
    Config(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("generation was not current")]
    StaleGeneration,
    #[error("no such allocation")]
    NoSuchAllocation,
    #[error("durable commit failed")]
    CommitFailed,
}

/// Each exhaustible dimension, named so tests prove which limit refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Slots,
    Memory,
    Disk,
    HostCpu,
    VirtualCpu,
    Pids,
    HostPids,
    LedgerSpace,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTotals {
    pub slots: u64,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub host_cpu_millis: u64,
    pub virtual_cpu_slots: u64,
    pub pids: u64,
    pub host_pids: u64,
}

impl ClaimTotals {
    fn add(&mut self, r: &ResourceReservation) -> Result<(), LedgerError> {
        let add = |total: u64, amount: u64, what| {
            total.checked_add(amount).ok_or(LedgerError::Overflow(what))
        };
        self.slots = add(self.slots, 1, "slots")?;
        self.memory_bytes = add(self.memory_bytes, r.memory_bytes, "memory")?;
        self.disk_bytes = add(self.disk_bytes, r.disk_bytes, "disk")?;
        self.host_cpu_millis = add(self.host_cpu_millis, r.host_cpu_millis, "cpu")?;
        self.virtual_cpu_slots = add(self.virtual_cpu_slots, r.virtual_cpu_slots, "vcpu")?;
        self.pids = add(self.pids, r.pids, "pids")?;
        self.host_pids = add(self.host_pids, r.host_pids, "host pids")?;
        Ok(())
    }

    /// Claims plus the once-only shared reserve, in checked arithmetic.
    fn with_shared(mut self, shared: &SharedReserve) -> Result<Self, LedgerError> {
        let add = |total: u64, amount: u64, what| {
            total.checked_add(amount).ok_or(LedgerError::Overflow(what))
        };
        self.memory_bytes = add(self.memory_bytes, shared.memory_bytes, "memory")?;
        let disk = shared.total_disk().ok_or(LedgerError::Overflow("disk"))?;
        self.disk_bytes = add(self.disk_bytes, disk, "disk")?;
        self.host_cpu_millis = add(self.host_cpu_millis, shared.host_cpu_millis, "cpu")?;
        self.pids = add(self.pids, shared.pids, "pids")?;
        self.host_pids = add(self.host_pids, shared.host_pids, "host pids")?;
        Ok(self)
    }

    fn exceeded(&self, ceilings: &NodeCeilings) -> Option<Dimension> {
        if self.slots > ceilings.slots {
            Some(Dimension::Slots)
        } else if self.memory_bytes > ceilings.memory_bytes {
            Some(Dimension::Memory)
        } else if self.disk_bytes > ceilings.disk_bytes {
            Some(Dimension::Disk)
        } else if self.host_cpu_millis > ceilings.host_cpu_millis {
            Some(Dimension::HostCpu)
        } else if self.virtual_cpu_slots > ceilings.virtual_cpu_slots {
            Some(Dimension::VirtualCpu)
        } else if self.pids > ceilings.pids {
            Some(Dimension::Pids)
        } else if self.host_pids > ceilings.host_pids {
            Some(Dimension::HostPids)
        } else {
            None
        }
    }
}

/// The precommitted emergency authority recorded at C2. K can execute it without any
/// further fsync; it names the conditions, never a command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopAuthority {
    pub conditions: Vec<String>,
    pub cgroup: String,
}

impl StopAuthority {
    pub fn standard(cgroup: String) -> Self {
        Self {
            conditions: [
                "supervisor-loss",
                "monitor-loss",
                "helper-loss",
                "timeout",
                "protocol-breach",
                "resource-breach",
            ]
            .map(String::from)
            .to_vec(),
            cgroup,
        }
    }
}

/// C2's one transaction input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitRequest {
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub sandbox_id: String,
    pub plan_version: u32,
    pub plan_digest: Digest,
    pub plan: Vec<u8>,
    pub profile: String,
    pub manifest_sha256: Digest,
    pub host_spec_sha256: Digest,
    pub guest_exec_spec_sha256: Digest,
    pub reservation: ResourceReservation,
    pub leases: IdentityLeases,
    pub work_uuid: String,
    pub executables: Vec<ExecutableIdentity>,
    pub stop_authority: StopAuthority,
    pub supervisor: WorkerIntentSpec,
}

/// A gated worker's durable intent, journaled before its spawn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIntentSpec {
    pub mode: String,
    pub allowed_names: Vec<String>,
    pub cgroup: String,
    pub image: ExecutableIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AdmitOutcome {
    /// `replay` is true for an exact active token: no second claim was made.
    Accepted {
        generation: u64,
        worker_id: i64,
        operation_generation: u64,
        phase: String,
        replay: bool,
    },
    Fenced {
        receipt: Vec<u8>,
    },
    Conflict {
        reason: String,
    },
    Capacity {
        dimension: Dimension,
    },
    Collision {
        kind: LeaseKind,
    },
    InstanceMismatch,
    /// The attachment that asked was revoked before this could commit. Nothing changed.
    Revoked,
}

/// What one exact token means right now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TokenLookup {
    Unknown,
    Fenced {
        receipt: Vec<u8>,
    },
    Conflict {
        reason: String,
    },
    Active {
        generation: u64,
        phase: String,
        unsettled_workers: u64,
        supervisor_operation: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceRequest {
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub sandbox_id: String,
    pub plan_digest: Digest,
    pub observations: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FenceOutcome {
    /// `replay` is true when an existing fence was returned unchanged.
    Absent {
        receipt: Vec<u8>,
        replay: bool,
    },
    Conflict {
        reason: String,
    },
    Unsettled {
        workers: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachOutcome {
    /// First binding, or the same database again.
    Bound { node_id: Id128, generation: u64 },
    /// Another database once owned this namespace: claims survive and admission is
    /// blocked until an operator resolves it. The binding itself never changes.
    DatabaseMismatch { node_id: Id128, generation: u64 },
}

/// Node totals; no other instance's session identities appear here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingSnapshot {
    pub node_id: Id128,
    pub generation: u64,
    pub ceilings: NodeCeilings,
    pub shared: SharedReserve,
    pub claimed: ClaimTotals,
    pub committed: ClaimTotals,
    /// A lowered ceiling never discounts commitments: this just denies admission.
    pub over_committed: bool,
    pub retired_tokens: u64,
    pub ledger_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRecord {
    pub allocation_id: Id128,
    pub plan_digest: Digest,
    pub phase: String,
    pub generation: u64,
    pub unsettled_workers: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySnapshot {
    pub generation: u64,
    pub records: Vec<InventoryRecord>,
    pub overflow: bool,
}

/// One unsettled worker, for restart recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRecord {
    pub worker_id: i64,
    pub allocation_id: Option<Id128>,
    pub mode: String,
    pub operation_generation: u64,
    pub pid: Option<i32>,
    pub start_time: Option<u64>,
    pub host_boot_id: Option<String>,
}

/// Everything a helper restart replays before serving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySnapshot {
    pub generation: u64,
    pub active_allocations: Vec<InventoryRecord>,
    pub unsettled_workers: Vec<WorkerRecord>,
    pub executable_leases: Vec<ExecutableIdentity>,
}

/// Parameters a ledger runs under. The ceilings come from root policy each open, so
/// a lowered limit applies at once and existing claims are not recalculated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerConfig {
    pub directory: PathBuf,
    pub policy: WalkPolicy,
    pub node_id: Id128,
    pub ceilings: NodeCeilings,
    pub shared: SharedReserve,
}

pub struct Ledger {
    conn: Connection,
    config: LedgerConfig,
    _directory: ProtectedDir,
    /// Only tests can set this: it models a failed durable commit.
    fail_next_commit: std::cell::Cell<bool>,
}

fn commit_tx(tx: Transaction<'_>, fail: &std::cell::Cell<bool>) -> Result<(), LedgerError> {
    if fail.replace(false) {
        drop(tx);
        return Err(LedgerError::CommitFailed);
    }
    tx.commit()?;
    Ok(())
}

/// Inspects an entry without opening it. Closing any descriptor for a file drops all
/// of this process's POSIX record locks on it, including SQLite's own, so nothing here
/// may ever open the database or its sidecars once a connection could exist.
fn stat_entry(directory: &File, name: &str) -> Result<Option<libc::stat>, LedgerError> {
    let name_c = CString::new(name).map_err(|_| LedgerError::Unsafe("name".into()))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory and name are live, and stat points to writable storage.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(LedgerError::Unsafe(format!("{name}: {error}")));
    }
    // SAFETY: fstatat initialized stat on success.
    Ok(Some(unsafe { stat.assume_init() }))
}

fn check_ledger_files(directory: &File, owner: u32) -> Result<(), LedgerError> {
    let meta = directory.metadata()?;
    if meta.uid() != owner || meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(LedgerError::Unsafe(
            "ledger directory must have mode 0700".into(),
        ));
    }
    for name in [LEDGER_DB, "node.db-wal", "node.db-shm", "node.db-journal"] {
        if let Some(stat) = stat_entry(directory, name)? {
            #[allow(clippy::unnecessary_cast)]
            if stat.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFREG as u32
                || stat.st_nlink != 1
                || stat.st_uid != owner
                || stat.st_mode as u32 & 0o7777 != 0o600
            {
                return Err(LedgerError::Unsafe(format!(
                    "{name} must be a single-link regular file with mode 0600"
                )));
            }
        }
    }
    Ok(())
}

fn configure(conn: &Connection) -> Result<(), LedgerError> {
    let require = |pragma: &str, value: i64| -> Result<(), LedgerError> {
        let actual: i64 = conn.pragma_query_value(None, pragma, |r| r.get(0))?;
        if actual != value {
            return Err(LedgerError::Corrupt(format!(
                "SQLite refused {pragma}={value}"
            )));
        }
        Ok(())
    };
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    require("trusted_schema", 0)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    require("foreign_keys", 1)?;
    conn.pragma_update(None, "recursive_triggers", "ON")?;
    require("recursive_triggers", 1)?;
    conn.busy_timeout(std::time::Duration::from_secs(1))?;
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if mode != "wal" {
        return Err(LedgerError::Corrupt(format!("journal mode {mode}")));
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    require("synchronous", 2)?;
    // Bound WAL and file growth inside the shared 512 MiB ledger reserve.
    conn.pragma_update(None, "wal_autocheckpoint", 1024)?;
    conn.pragma_update(None, "journal_size_limit", 16 * 1024 * 1024)?;
    Ok(())
}

fn schema_digest(conn: &Connection) -> Result<Digest, rusqlite::Error> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let mut rows = statement.query([])?;
    let mut text = String::new();
    while let Some(row) = rows.next()? {
        for index in 0..4 {
            let cell: String = row.get(index)?;
            text.push_str(&cell);
            text.push('\u{0}');
        }
    }
    Ok(Digest::of(text.as_bytes()))
}

/// The digest of exactly the schema this binary would create: any dropped or changed
/// table, index or trigger fails open as corruption.
fn expected_schema_digest() -> Result<Digest, rusqlite::Error> {
    let scratch = Connection::open_in_memory()?;
    scratch.execute_batch(SCHEMA)?;
    schema_digest(&scratch)
}

fn parse_id(text: String) -> Result<Id128, LedgerError> {
    Id128::parse(&text).map_err(LedgerError::Corrupt)
}

fn parse_sha(text: String) -> Result<Digest, LedgerError> {
    Digest::parse(&text).map_err(LedgerError::Corrupt)
}

fn signed(value: u64, what: &'static str) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::Overflow(what))
}

fn unsigned(value: i64) -> Result<u64, LedgerError> {
    u64::try_from(value).map_err(|_| LedgerError::Corrupt("negative stored amount".into()))
}

fn next_generation(tx: &Transaction<'_>) -> Result<u64, LedgerError> {
    let current: i64 = tx.query_row(
        "SELECT value FROM generation_counter WHERE id = 1",
        [],
        |r| r.get(0),
    )?;
    let next = current
        .checked_add(1)
        .ok_or(LedgerError::Overflow("generation"))?;
    tx.prepare_cached("UPDATE generation_counter SET value = ?1 WHERE id = 1")?
        .execute([next])?;
    unsigned(next)
}

fn claim_totals(conn: &Connection) -> Result<ClaimTotals, LedgerError> {
    let mut totals = ClaimTotals::default();
    let mut statement = conn.prepare_cached(
        "SELECT memory_bytes, disk_bytes, pids, host_cpu_millis, virtual_cpu_slots, host_pids
         FROM capacity_claims WHERE released_generation IS NULL",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        totals.add(&ResourceReservation {
            memory_bytes: unsigned(row.get(0)?)?,
            disk_bytes: unsigned(row.get(1)?)?,
            pids: unsigned(row.get(2)?)?,
            host_cpu_millis: unsigned(row.get(3)?)?,
            virtual_cpu_slots: unsigned(row.get(4)?)?,
            host_pids: unsigned(row.get(5)?)?,
        })?;
    }
    Ok(totals)
}

impl Ledger {
    /// The explicit one-time creation of an authority. Refuses if any ledger file
    /// exists, so an empty registry can never appear over possibly live resources.
    pub fn provision(config: &LedgerConfig) -> Result<(), LedgerError> {
        let directory = walk_directory(&config.policy, &config.directory)
            .map_err(|e| LedgerError::Unsafe(e.to_string()))?;
        let meta = directory.file().metadata()?;
        if meta.permissions().mode() & 0o7777 != 0o700 {
            return Err(LedgerError::Unsafe(
                "ledger directory must have mode 0700".into(),
            ));
        }
        for name in [LEDGER_DB, "node.db-wal", "node.db-shm", "node.db-journal"] {
            if stat_entry(directory.file(), name)?.is_some() {
                return Err(LedgerError::Exists(config.directory.join(name)));
            }
        }
        let name = CString::new(LEDGER_DB).unwrap();
        // SAFETY: directory and name are live, and O_EXCL refuses any existing entry.
        let fd = unsafe {
            libc::openat(
                directory.file().as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new owned descriptor.
        let created = unsafe { File::from_raw_fd(fd) };
        created.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mut conn = Connection::open_with_flags(
            config.directory.join(LEDGER_DB),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.execute(
            "INSERT INTO node_identity (id, node_id, created_at_ms) VALUES (1, ?1, ?2)",
            params![config.node_id.to_string(), now_ms()],
        )?;
        tx.execute(
            "INSERT INTO generation_counter (id, value) VALUES (1, 1)",
            [],
        )?;
        tx.commit()?;
        drop(conn);
        created.sync_all()?;
        directory.file().sync_all()?;
        Ok(())
    }

    /// Opens an existing ledger, or refuses. Missing, partial, corrupt, foreign-node or
    /// wrong-schema files all fail closed; nothing here ever creates a fresh ledger.
    pub fn open(config: LedgerConfig) -> Result<Self, LedgerError> {
        validate_ceilings(&config.ceilings, &config.shared).map_err(LedgerError::Config)?;
        let directory = walk_directory(&config.policy, &config.directory)
            .map_err(|e| LedgerError::Unsafe(e.to_string()))?;
        let owner = config.policy.owner_uid;
        check_ledger_files(directory.file(), owner)?;
        if stat_entry(directory.file(), LEDGER_DB)?.is_none() {
            return Err(LedgerError::Missing(config.directory.join(LEDGER_DB)));
        }
        let path: PathBuf = config.directory.join(LEDGER_DB);
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| LedgerError::Corrupt(e.to_string()))?;
        configure(&conn).map_err(corrupt)?;
        check_ledger_files(directory.file(), owner)?;
        let ledger = Self {
            conn,
            config,
            _directory: directory,
            fail_next_commit: std::cell::Cell::new(false),
        };
        ledger.audit().map_err(corrupt)?;
        Ok(ledger)
    }

    /// Integrity plus semantic checks, inside one read snapshot.
    fn audit(&self) -> Result<(), LedgerError> {
        let conn = &self.conn;
        let application: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(LedgerError::Corrupt("not this ledger format".into()));
        }
        let quick: String = conn.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if quick != "ok" {
            return Err(LedgerError::Corrupt(quick));
        }
        if schema_digest(conn)? != expected_schema_digest()? {
            return Err(LedgerError::Corrupt("ledger schema differs".into()));
        }
        let node: String =
            conn.query_row("SELECT node_id FROM node_identity WHERE id = 1", [], |r| {
                r.get(0)
            })?;
        if node != self.config.node_id.to_string() {
            return Err(LedgerError::Corrupt(format!(
                "ledger belongs to node {node}"
            )));
        }
        let generation = self.generation()?;
        // Every stored generation must be behind the counter: a rolled-back counter
        // could otherwise reissue a receipt generation.
        let highest: i64 = conn.query_row(
            "SELECT MAX(g) FROM (
                SELECT MAX(updated_generation) AS g FROM allocations
                UNION ALL SELECT MAX(helper_generation) FROM retired_tokens
                UNION ALL SELECT MAX(operation_generation) FROM worker_intents
                UNION ALL SELECT MAX(generation) FROM stop_events
                UNION ALL SELECT 1)",
            [],
            |r| r.get(0),
        )?;
        if unsigned(highest)? > generation {
            return Err(LedgerError::Corrupt(
                "generation counter rolled back".into(),
            ));
        }
        // Every durable receipt must decode canonically and bind its own row.
        let mut fences = conn.prepare(
            "SELECT allocation_id, instance_id, plan_digest, receipt_id, helper_generation, receipt
             FROM retired_tokens",
        )?;
        let mut rows = fences.query([])?;
        while let Some(row) = rows.next()? {
            let receipt: Vec<u8> = row.get(5)?;
            let decoded = FencedAbsence::decode(&receipt)
                .map_err(|e| LedgerError::Corrupt(format!("retired token receipt: {e}")))?;
            if decoded.node_id() != self.config.node_id
                || decoded.allocation_id() != parse_id(row.get(0)?)?
                || decoded.instance_id() != parse_id(row.get(1)?)?
                || decoded.plan_digest() != parse_sha(row.get(2)?)?
                || decoded.receipt_id() != parse_id(row.get(3)?)?
                || decoded.helper_generation() != unsigned(row.get(4)?)?
            {
                return Err(LedgerError::Corrupt("receipt differs from its row".into()));
            }
        }
        // An unreleased allocation has its plan, its claim and all five identities.
        let incomplete: i64 = conn.query_row(
            "SELECT COUNT(*) FROM allocations a
             WHERE a.phase != 'absent' AND (
               NOT EXISTS (SELECT 1 FROM allocation_plans p WHERE p.allocation_id = a.allocation_id)
               OR NOT EXISTS (SELECT 1 FROM capacity_claims c WHERE c.allocation_id = a.allocation_id
                              AND c.released_generation IS NULL)
               OR (SELECT COUNT(*) FROM identity_leases l WHERE l.allocation_id = a.allocation_id
                   AND l.released_generation IS NULL) != 5)",
            [],
            |r| r.get(0),
        )?;
        if incomplete != 0 {
            return Err(LedgerError::Corrupt(
                "an active allocation lost its plan, claim or leases".into(),
            ));
        }
        let mut plans = conn.prepare(
            "SELECT a.plan_digest, p.plan FROM allocations a
             JOIN allocation_plans p ON p.allocation_id = a.allocation_id",
        )?;
        let mut rows = plans.query([])?;
        while let Some(row) = rows.next()? {
            let plan: Vec<u8> = row.get(1)?;
            if Digest::of(&plan) != parse_sha(row.get(0)?)? {
                return Err(LedgerError::Corrupt(
                    "plan bytes differ from their digest".into(),
                ));
            }
        }
        claim_totals(conn)?;
        Ok(())
    }

    pub fn node_id(&self) -> Id128 {
        self.config.node_id
    }

    pub fn generation(&self) -> Result<u64, LedgerError> {
        let value: i64 = self
            .conn
            .prepare_cached("SELECT value FROM generation_counter WHERE id = 1")?
            .query_row([], |r| r.get(0))?;
        unsigned(value)
    }

    #[cfg(test)]
    pub(super) fn fail_next_commit(&self) {
        self.fail_next_commit.set(true);
    }

    /// Binds a namespace to its database once. A mismatched database is reported and
    /// never overwrites the binding: its claims stay attributed to that namespace.
    pub fn attach_instance(
        &mut self,
        instance: Id128,
        database_uuid: Id128,
    ) -> Result<AttachOutcome, LedgerError> {
        let node_id = self.config.node_id;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let bound: Option<String> = tx
            .prepare_cached("SELECT database_uuid FROM instances WHERE instance_id = ?1")?
            .query_row([instance.to_string()], |r| r.get(0))
            .optional()?;
        let outcome = match bound {
            Some(existing) if existing == database_uuid.to_string() => {
                let generation: i64 = tx.query_row(
                    "SELECT value FROM generation_counter WHERE id = 1",
                    [],
                    |r| r.get(0),
                )?;
                AttachOutcome::Bound {
                    node_id,
                    generation: unsigned(generation)?,
                }
            }
            Some(_) => {
                let generation: i64 = tx.query_row(
                    "SELECT value FROM generation_counter WHERE id = 1",
                    [],
                    |r| r.get(0),
                )?;
                AttachOutcome::DatabaseMismatch {
                    node_id,
                    generation: unsigned(generation)?,
                }
            }
            None => {
                let generation = next_generation(&tx)?;
                tx.prepare_cached(
                    "INSERT INTO instances (instance_id, database_uuid, first_generation)
                     VALUES (?1, ?2, ?3)",
                )?
                .execute(params![
                    instance.to_string(),
                    database_uuid.to_string(),
                    signed(generation, "generation")?
                ])?;
                AttachOutcome::Bound {
                    node_id,
                    generation,
                }
            }
        };
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(outcome)
    }

    fn lookup_on(
        conn: &Connection,
        instance: Id128,
        allocation: Id128,
        plan_digest: &Digest,
    ) -> Result<TokenLookup, LedgerError> {
        let fence = conn
            .prepare_cached(
                "SELECT instance_id, plan_digest, receipt FROM retired_tokens WHERE allocation_id = ?1",
            )?
            .query_row([allocation.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .optional()?;
        if let Some((fence_instance, digest, receipt)) = fence {
            if fence_instance != instance.to_string() || digest != plan_digest.to_string() {
                return Ok(TokenLookup::Conflict {
                    reason: "token was retired with a different identity".into(),
                });
            }
            return Ok(TokenLookup::Fenced { receipt });
        }
        let active = conn
            .prepare_cached(
                "SELECT instance_id, plan_digest, phase, updated_generation
                 FROM allocations WHERE allocation_id = ?1",
            )?
            .query_row([allocation.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .optional()?;
        let Some((active_instance, digest, phase, generation)) = active else {
            return Ok(TokenLookup::Unknown);
        };
        if active_instance != instance.to_string() || digest != plan_digest.to_string() {
            return Ok(TokenLookup::Conflict {
                reason: "token is active with a different identity or plan".into(),
            });
        }
        let unsettled: i64 = conn
            .prepare_cached(
                "SELECT COUNT(*) FROM worker_intents
                 WHERE allocation_id = ?1 AND settled_generation IS NULL",
            )?
            .query_row([allocation.to_string()], |r| r.get(0))?;
        let operation: Option<i64> = conn
            .prepare_cached(
                "SELECT MIN(operation_generation) FROM worker_intents
                 WHERE allocation_id = ?1 AND mode = 'supervisor' AND settled_generation IS NULL",
            )?
            .query_row([allocation.to_string()], |r| r.get(0))?;
        Ok(TokenLookup::Active {
            generation: unsigned(generation)?,
            phase,
            unsettled_workers: unsigned(unsettled)?,
            supervisor_operation: operation.map(unsigned).transpose()?,
        })
    }

    /// The first thing Create and FenceAbsent ask about a token.
    pub fn lookup_token(
        &self,
        instance: Id128,
        allocation: Id128,
        plan_digest: &Digest,
    ) -> Result<TokenLookup, LedgerError> {
        Self::lookup_on(&self.conn, instance, allocation, plan_digest)
    }

    /// Inspect's allocation-only lookup, under exact namespace privacy.
    pub fn inspect(&self, instance: Id128, allocation: Id128) -> Result<TokenLookup, LedgerError> {
        let digest: Option<String> = self
            .conn
            .prepare_cached(
                "SELECT plan_digest FROM retired_tokens WHERE allocation_id = ?1 AND instance_id = ?2
                 UNION ALL
                 SELECT plan_digest FROM allocations WHERE allocation_id = ?1 AND instance_id = ?2
                 LIMIT 1",
            )?
            .query_row([allocation.to_string(), instance.to_string()], |r| r.get(0))
            .optional()?;
        match digest {
            // Another namespace's token and a never-seen one are indistinguishable.
            None => Ok(TokenLookup::Unknown),
            Some(digest) => Self::lookup_on(&self.conn, instance, allocation, &parse_sha(digest)?),
        }
    }

    /// The set preflight avoids. Selecting from it reserves nothing.
    pub fn claimed_identities(&self) -> Result<ClaimedIdentities, LedgerError> {
        let mut claimed = ClaimedIdentities::default();
        let mut statement = self.conn.prepare_cached(
            "SELECT namespace, value FROM identity_leases WHERE released_generation IS NULL",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let namespace: String = row.get(0)?;
            let value = u32::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| LedgerError::Corrupt("identity value".into()))?;
            match namespace.as_str() {
                "uid" => claimed.uids.insert(value),
                "gid" => claimed.gids.insert(value),
                "cid" => claimed.cids.insert(value),
                _ => return Err(LedgerError::Corrupt("identity namespace".into())),
            };
        }
        Ok(claimed)
    }

    /// Whether one more token still fits, with every active token and the pre-intent
    /// margin already counted. Permanent fences never give their space back.
    pub fn fence_headroom(&self) -> Result<bool, LedgerError> {
        let retired: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM retired_tokens")?
            .query_row([], |r| r.get(0))?;
        let active: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM allocations WHERE phase != 'absent'")?
            .query_row([], |r| r.get(0))?;
        let needed = unsigned(retired)?
            .checked_add(unsigned(active)?)
            .and_then(|tokens| tokens.checked_add(PRE_INTENT_TOKEN_MARGIN + 1))
            .and_then(|tokens| tokens.checked_mul(FENCE_ENTRY_BOUND))
            .ok_or(LedgerError::Overflow("fence headroom"))?;
        Ok(needed <= self.config.shared.fence_allowance_bytes)
    }

    fn ledger_bytes(&self) -> Result<u64, LedgerError> {
        let pages: i64 = self
            .conn
            .pragma_query_value(None, "page_count", |r| r.get(0))?;
        let size: i64 = self
            .conn
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        unsigned(pages)?
            .checked_mul(unsigned(size)?)
            .ok_or(LedgerError::Overflow("ledger size"))
    }

    /// C2: full capacity vector, every identity, INTENT, names, stop authority and the
    /// supervisor's worker intent, in one transaction. A rejection changes nothing.
    #[cfg(test)]
    pub fn admit_intent(&mut self, request: &AdmitRequest) -> Result<AdmitOutcome, LedgerError> {
        self.admit_intent_authorized(request, &|| true)
    }

    /// `authorized` is read at the commit linearization point, after everything that
    /// could have kept this request queued, so a revocation published before then wins.
    /// A revocation that lands just after it is H's to catch, before any effect.
    pub fn admit_intent_authorized(
        &mut self,
        request: &AdmitRequest,
        authorized: &dyn Fn() -> bool,
    ) -> Result<AdmitOutcome, LedgerError> {
        let ceilings = self.config.ceilings;
        let shared = self.config.shared;
        let has_headroom = self.fence_headroom()?;
        let ledger_bytes = self.ledger_bytes()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The existing token comes first, before capacity and before any identity.
        match Self::lookup_on(
            &tx,
            request.instance_id,
            request.allocation_id,
            &request.plan_digest,
        )? {
            TokenLookup::Fenced { receipt } => return Ok(AdmitOutcome::Fenced { receipt }),
            TokenLookup::Conflict { reason } => return Ok(AdmitOutcome::Conflict { reason }),
            TokenLookup::Active {
                generation, phase, ..
            } => {
                let sandbox: String = tx.query_row(
                    "SELECT sandbox_id FROM allocations WHERE allocation_id = ?1",
                    [request.allocation_id.to_string()],
                    |r| r.get(0),
                )?;
                if sandbox != request.sandbox_id {
                    return Ok(AdmitOutcome::Conflict {
                        reason: "token is active under another sandbox".into(),
                    });
                }
                let (worker_id, operation): (i64, i64) = tx.query_row(
                    "SELECT id, operation_generation FROM worker_intents
                     WHERE allocation_id = ?1 AND mode = 'supervisor' ORDER BY id LIMIT 1",
                    [request.allocation_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                return Ok(AdmitOutcome::Accepted {
                    generation,
                    worker_id,
                    operation_generation: unsigned(operation)?,
                    phase,
                    replay: true,
                });
            }
            TokenLookup::Unknown => {}
        }
        let bound: Option<String> = tx
            .prepare_cached("SELECT database_uuid FROM instances WHERE instance_id = ?1")?
            .query_row([request.instance_id.to_string()], |r| r.get(0))
            .optional()?;
        if bound.is_none() {
            return Ok(AdmitOutcome::InstanceMismatch);
        }
        let taken: i64 = tx
            .prepare_cached("SELECT COUNT(*) FROM allocations WHERE sandbox_id = ?1")?
            .query_row([&request.sandbox_id], |r| r.get(0))?;
        if taken != 0 {
            return Ok(AdmitOutcome::Conflict {
                reason: "sandbox ID is bound to another allocation".into(),
            });
        }
        if !has_headroom
            || ledger_bytes
                > shared
                    .disk_bytes
                    .saturating_sub(shared.fence_allowance_bytes)
        {
            return Ok(AdmitOutcome::Capacity {
                dimension: Dimension::LedgerSpace,
            });
        }
        let mut committed = claim_totals(&tx)?;
        committed.add(&request.reservation)?;
        if let Some(dimension) = committed.with_shared(&shared)?.exceeded(&ceilings) {
            return Ok(AdmitOutcome::Capacity { dimension });
        }
        for (kind, value) in request.leases.rows() {
            let collision: i64 = tx
                .prepare_cached(
                    "SELECT COUNT(*) FROM identity_leases
                     WHERE namespace = ?1 AND value = ?2 AND released_generation IS NULL",
                )?
                .query_row(params![kind.namespace(), i64::from(value)], |r| r.get(0))?;
            if collision != 0 {
                return Ok(AdmitOutcome::Collision { kind });
            }
        }
        // VMM and relay leases of this one plan also cannot share a value.
        let rows = request.leases.rows();
        for (index, (kind, value)) in rows.iter().enumerate() {
            if rows[..index]
                .iter()
                .any(|(other, seen)| other.namespace() == kind.namespace() && seen == value)
            {
                return Ok(AdmitOutcome::Collision { kind: *kind });
            }
        }
        let generation = next_generation(&tx)?;
        let generation_i = signed(generation, "generation")?;
        let allocation = request.allocation_id.to_string();
        tx.prepare_cached(
            "INSERT INTO allocations (allocation_id, instance_id, sandbox_id, backend_id,
                plan_version, plan_digest, profile, manifest_sha256, host_spec_sha256,
                guest_exec_spec_sha256, work_uuid, stop_authority, phase,
                created_generation, updated_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'intent', ?13, ?13)",
        )?
        .execute(params![
            allocation,
            request.instance_id.to_string(),
            request.sandbox_id,
            super::identity::backend_id(request.allocation_id),
            i64::from(request.plan_version),
            request.plan_digest.to_string(),
            request.profile,
            request.manifest_sha256.to_string(),
            request.host_spec_sha256.to_string(),
            request.guest_exec_spec_sha256.to_string(),
            request.work_uuid,
            serde_json::to_string(&request.stop_authority)
                .map_err(|e| LedgerError::Config(e.to_string()))?,
            generation_i,
        ])?;
        tx.prepare_cached("INSERT INTO allocation_plans (allocation_id, plan) VALUES (?1, ?2)")?
            .execute(params![allocation, request.plan])?;
        let r = &request.reservation;
        tx.prepare_cached(
            "INSERT INTO capacity_claims (allocation_id, memory_bytes, disk_bytes, pids,
                host_cpu_millis, virtual_cpu_slots, host_pids, claimed_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            allocation,
            signed(r.memory_bytes, "memory")?,
            signed(r.disk_bytes, "disk")?,
            signed(r.pids, "pids")?,
            signed(r.host_cpu_millis, "cpu")?,
            signed(r.virtual_cpu_slots, "vcpu")?,
            signed(r.host_pids, "host pids")?,
            generation_i,
        ])?;
        for (kind, value) in request.leases.rows() {
            tx.prepare_cached(
                "INSERT INTO identity_leases (namespace, kind, value, allocation_id, claimed_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![
                kind.namespace(),
                kind.as_str(),
                i64::from(value),
                allocation,
                generation_i
            ])?;
        }
        for identity in &request.executables {
            tx.prepare_cached(
                "INSERT INTO executable_leases (allocation_id, role, st_dev, st_ino, bytes, sha256,
                    installation_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?
            .execute(params![
                allocation,
                identity.role.as_str(),
                signed(identity.st_dev, "device")?,
                signed(identity.st_ino, "inode")?,
                signed(identity.bytes, "size")?,
                identity.sha256.to_string(),
                signed(identity.installation_generation, "installation generation")?,
            ])?;
        }
        let operation = next_generation(&tx)?;
        let worker_id = Self::insert_worker_intent(
            &tx,
            Some(request.allocation_id),
            &request.supervisor,
            operation,
        )?;
        crate::helper::firecracker::workers::fault_point("L.admit.before_commit");
        if !authorized() {
            drop(tx);
            return Ok(AdmitOutcome::Revoked);
        }
        commit_tx(tx, &self.fail_next_commit)?;
        crate::helper::firecracker::workers::fault_point("L.admit.after_commit");
        Ok(AdmitOutcome::Accepted {
            generation,
            worker_id,
            operation_generation: operation,
            phase: "intent".into(),
            replay: false,
        })
    }

    fn insert_worker_intent(
        tx: &Transaction<'_>,
        allocation: Option<Id128>,
        spec: &WorkerIntentSpec,
        operation: u64,
    ) -> Result<i64, LedgerError> {
        tx.prepare_cached(
            "INSERT INTO worker_intents (allocation_id, mode, operation_generation, allowed_names,
                cgroup, exec_role, exec_st_dev, exec_st_ino, exec_bytes, exec_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?
        .execute(params![
            allocation.map(|id| id.to_string()),
            spec.mode,
            signed(operation, "operation generation")?,
            serde_json::to_string(&spec.allowed_names)
                .map_err(|e| LedgerError::Config(e.to_string()))?,
            spec.cgroup,
            spec.image.role.as_str(),
            signed(spec.image.st_dev, "device")?,
            signed(spec.image.st_ino, "inode")?,
            signed(spec.image.bytes, "size")?,
            spec.image.sha256.to_string(),
        ])?;
        Ok(tx.last_insert_rowid())
    }

    /// Journals a startup infrastructure worker's intent before it is released.
    pub fn record_infrastructure_worker(
        &mut self,
        spec: &WorkerIntentSpec,
        pid: i32,
        start_time: u64,
        boot_id: &str,
    ) -> Result<i64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = next_generation(&tx)?;
        let id = Self::insert_worker_intent(&tx, None, spec, operation)?;
        tx.prepare_cached(
            "UPDATE worker_intents SET pid = ?2, start_time = ?3, host_boot_id = ?4 WHERE id = ?1",
        )?
        .execute(params![id, pid, signed(start_time, "start time")?, boot_id])?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(id)
    }

    /// A replacement worker's expected image and intent, before it is forked. Its
    /// identity follows through `record_worker_identity`, before it is given any work.
    pub fn record_infrastructure_intent(
        &mut self,
        spec: &WorkerIntentSpec,
    ) -> Result<i64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = next_generation(&tx)?;
        let id = Self::insert_worker_intent(&tx, None, spec, operation)?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(id)
    }

    /// Records a spawned worker's identity before its gate opens.
    pub fn record_worker_identity(
        &mut self,
        worker_id: i64,
        pid: i32,
        start_time: u64,
        boot_id: &str,
    ) -> Result<(), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx
            .prepare_cached(
                "UPDATE worker_intents SET pid = ?2, start_time = ?3, host_boot_id = ?4
                 WHERE id = ?1 AND settled_generation IS NULL",
            )?
            .execute(params![
                worker_id,
                pid,
                signed(start_time, "start time")?,
                boot_id
            ])?;
        if changed != 1 {
            return Err(LedgerError::StaleGeneration);
        }
        commit_tx(tx, &self.fail_next_commit)
    }

    /// Adds an effect's owned child (S's fake VM) to the worker table, with identity.
    pub fn record_child_worker(
        &mut self,
        allocation: Id128,
        spec: &WorkerIntentSpec,
        pid: i32,
        start_time: u64,
        boot_id: &str,
    ) -> Result<i64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = next_generation(&tx)?;
        let id = Self::insert_worker_intent(&tx, Some(allocation), spec, operation)?;
        tx.prepare_cached(
            "UPDATE worker_intents SET pid = ?2, start_time = ?3, host_boot_id = ?4 WHERE id = ?1",
        )?
        .execute(params![id, pid, signed(start_time, "start time")?, boot_id])?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(id)
    }

    /// C3: PREPARING with its permits precedes every session side effect. The update
    /// compares the generation, so a stale writer cannot pass a newer phase.
    pub fn advance_phase(
        &mut self,
        allocation: Id128,
        expected_generation: u64,
        phase: &str,
    ) -> Result<u64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        let changed = tx
            .prepare_cached(
                "UPDATE allocations SET phase = ?2, updated_generation = ?3
                 WHERE allocation_id = ?1 AND updated_generation = ?4 AND phase != 'absent'",
            )?
            .execute(params![
                allocation.to_string(),
                phase,
                signed(generation, "generation")?,
                signed(expected_generation, "generation")?,
            ])?;
        if changed != 1 {
            return Err(LedgerError::StaleGeneration);
        }
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// The later durable record of a stop: an emergency already ran under C2's
    /// authority if the writer was blocked. It never releases anything.
    pub fn record_stop(&mut self, allocation: Id128, reason: &str) -> Result<u64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        let changed = tx
            .prepare_cached(
                "UPDATE allocations SET phase = 'stop_intent', updated_generation = ?2
                 WHERE allocation_id = ?1 AND phase != 'absent'",
            )?
            .execute(params![
                allocation.to_string(),
                signed(generation, "generation")?
            ])?;
        if changed != 1 {
            return Err(LedgerError::NoSuchAllocation);
        }
        tx.prepare_cached(
            "INSERT INTO stop_events (allocation_id, generation, reason) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![
            allocation.to_string(),
            signed(generation, "generation")?,
            reason
        ])?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// The tuple that actually ran, attached to its lease. A mismatch is refused here
    /// as well as at the dispatch point; nothing may launder a different identity.
    pub fn record_observed_executable(
        &mut self,
        allocation: Id128,
        actual: &ExecutableIdentity,
    ) -> Result<(), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx
            .prepare_cached(
                "UPDATE executable_leases
                 SET observed_st_dev = ?3, observed_st_ino = ?4, observed_bytes = ?5, observed_sha256 = ?6
                 WHERE allocation_id = ?1 AND role = ?2 AND st_dev = ?3 AND st_ino = ?4
                   AND bytes = ?5 AND sha256 = ?6 AND installation_generation = ?7",
            )?
            .execute(params![
                allocation.to_string(),
                actual.role.as_str(),
                signed(actual.st_dev, "device")?,
                signed(actual.st_ino, "inode")?,
                signed(actual.bytes, "size")?,
                actual.sha256.to_string(),
                signed(actual.installation_generation, "installation generation")?,
            ])?;
        if changed != 1 {
            return Err(LedgerError::Corrupt(
                "observed executable differs from its journal record".into(),
            ));
        }
        commit_tx(tx, &self.fail_next_commit)
    }

    /// Exit and reap evidence. ABSENT cannot commit while any worker row is unsettled.
    pub fn settle_worker(&mut self, worker_id: i64, settlement: &str) -> Result<(), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        tx.prepare_cached(
            "UPDATE worker_intents SET settled_generation = ?2, settlement = ?3
             WHERE id = ?1 AND settled_generation IS NULL",
        )?
        .execute(params![
            worker_id,
            signed(generation, "generation")?,
            settlement
        ])?;
        commit_tx(tx, &self.fail_next_commit)
    }

    /// Rows with no recorded identity never had an open gate: S's gate opens only after
    /// that record. These can settle once no process with a permit could exist.
    pub fn settle_unstarted(&mut self, allocation: Id128) -> Result<(), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        tx.prepare_cached(
            "UPDATE worker_intents SET settled_generation = ?2, settlement = 'never-started'
             WHERE allocation_id = ?1 AND pid IS NULL AND settled_generation IS NULL",
        )?
        .execute(params![
            allocation.to_string(),
            signed(generation, "generation")?
        ])?;
        commit_tx(tx, &self.fail_next_commit)
    }

    /// The only release path: permanent retired token, matching receipt, and for an
    /// existing allocation its claim, leases and ABSENT phase, in one FULL-sync
    /// transaction. Replays return the original bytes unchanged. A failed commit
    /// leaves no receipt and the claim held.
    pub fn commit_fence(&mut self, request: &FenceRequest) -> Result<FenceOutcome, LedgerError> {
        let node_id = self.config.node_id;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match Self::lookup_on(
            &tx,
            request.instance_id,
            request.allocation_id,
            &request.plan_digest,
        )? {
            TokenLookup::Fenced { receipt } => {
                return Ok(FenceOutcome::Absent {
                    receipt,
                    replay: true,
                });
            }
            TokenLookup::Conflict { reason } => return Ok(FenceOutcome::Conflict { reason }),
            TokenLookup::Active {
                unsettled_workers,
                phase,
                ..
            } => {
                if unsettled_workers != 0 {
                    return Ok(FenceOutcome::Unsettled {
                        workers: unsettled_workers,
                    });
                }
                if phase == "quarantined" {
                    return Ok(FenceOutcome::Conflict {
                        reason: "a quarantined allocation has uncertain identity".into(),
                    });
                }
                let sandbox: String = tx.query_row(
                    "SELECT sandbox_id FROM allocations WHERE allocation_id = ?1",
                    [request.allocation_id.to_string()],
                    |r| r.get(0),
                )?;
                if sandbox != request.sandbox_id {
                    return Ok(FenceOutcome::Conflict {
                        reason: "token is active under another sandbox".into(),
                    });
                }
            }
            TokenLookup::Unknown => {
                let bound: i64 = tx
                    .prepare_cached("SELECT COUNT(*) FROM instances WHERE instance_id = ?1")?
                    .query_row([request.instance_id.to_string()], |r| r.get(0))?;
                if bound != 1 {
                    return Ok(FenceOutcome::Conflict {
                        reason: "this namespace was never attached".into(),
                    });
                }
            }
        }
        let generation = next_generation(&tx)?;
        let generation_i = signed(generation, "generation")?;
        let allocation = request.allocation_id.to_string();
        tx.prepare_cached(
            "UPDATE capacity_claims SET released_generation = ?2
             WHERE allocation_id = ?1 AND released_generation IS NULL",
        )?
        .execute(params![allocation, generation_i])?;
        tx.prepare_cached(
            "UPDATE identity_leases SET released_generation = ?2
             WHERE allocation_id = ?1 AND released_generation IS NULL",
        )?
        .execute(params![allocation, generation_i])?;
        tx.prepare_cached(
            "UPDATE executable_leases SET released_generation = ?2
             WHERE allocation_id = ?1 AND released_generation IS NULL",
        )?
        .execute(params![allocation, generation_i])?;
        tx.prepare_cached(
            "UPDATE allocations SET phase = 'absent', updated_generation = ?2 WHERE allocation_id = ?1",
        )?
        .execute(params![allocation, generation_i])?;
        let receipt_id = Id128::random();
        let receipt = FencedAbsence::new(
            receipt_id,
            node_id,
            request.instance_id,
            request.allocation_id,
            request.plan_digest,
            generation,
            request.observations.clone(),
        )
        .and_then(|fence| fence.encode())
        .map_err(|e| LedgerError::Config(e.to_string()))?;
        tx.prepare_cached(
            "INSERT INTO retired_tokens (allocation_id, instance_id, sandbox_id, plan_digest,
                receipt_id, helper_generation, receipt) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?
        .execute(params![
            allocation,
            request.instance_id.to_string(),
            request.sandbox_id,
            request.plan_digest.to_string(),
            receipt_id.to_string(),
            generation_i,
            receipt,
        ])?;
        tx.prepare_cached("DELETE FROM allocation_plans WHERE allocation_id = ?1")?
            .execute([&allocation])?;
        crate::helper::firecracker::workers::fault_point("L.fence.before_commit");
        if crate::helper::firecracker::workers::fault_enabled("L.fence.sync_fail") {
            drop(tx);
            return Err(LedgerError::CommitFailed);
        }
        commit_tx(tx, &self.fail_next_commit)?;
        crate::helper::firecracker::workers::fault_point("L.fence.after_commit");
        Ok(FenceOutcome::Absent {
            receipt,
            replay: false,
        })
    }

    /// Node totals with once-only shared reserves; no session identities.
    pub fn accounting(&self) -> Result<AccountingSnapshot, LedgerError> {
        let claimed = claim_totals(&self.conn)?;
        let committed = claimed.with_shared(&self.config.shared)?;
        let retired: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM retired_tokens")?
            .query_row([], |r| r.get(0))?;
        Ok(AccountingSnapshot {
            node_id: self.config.node_id,
            generation: self.generation()?,
            ceilings: self.config.ceilings,
            shared: self.config.shared,
            claimed,
            committed,
            over_committed: committed.exceeded(&self.config.ceilings).is_some(),
            retired_tokens: unsigned(retired)?,
            ledger_bytes: self.ledger_bytes()?,
        })
    }

    /// One namespace's active allocations, read from one snapshot.
    pub fn inventory(&self, instance: Id128) -> Result<InventorySnapshot, LedgerError> {
        let mut statement = self.conn.prepare_cached(
            "SELECT a.allocation_id, a.plan_digest, a.phase, a.updated_generation,
                (SELECT COUNT(*) FROM worker_intents w WHERE w.allocation_id = a.allocation_id
                    AND w.settled_generation IS NULL)
             FROM allocations a WHERE a.instance_id = ?1 AND a.phase != 'absent'
             ORDER BY a.allocation_id LIMIT ?2",
        )?;
        let mut rows =
            statement.query(params![instance.to_string(), MAX_ACTIVE_LISTED as i64 + 1])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            records.push(InventoryRecord {
                allocation_id: parse_id(row.get(0)?)?,
                plan_digest: parse_sha(row.get(1)?)?,
                phase: row.get(2)?,
                generation: unsigned(row.get(3)?)?,
                unsettled_workers: unsigned(row.get(4)?)?,
            });
        }
        let overflow = records.len() > MAX_ACTIVE_LISTED;
        records.truncate(MAX_ACTIVE_LISTED);
        Ok(InventorySnapshot {
            generation: self.generation()?,
            records,
            overflow,
        })
    }

    /// Whether an installer could safely touch this object: a held lease forbids it.
    pub fn executable_leased(&self, identity: &ExecutableIdentity) -> Result<bool, LedgerError> {
        let count: i64 = self
            .conn
            .prepare_cached(
                "SELECT COUNT(*) FROM executable_leases WHERE released_generation IS NULL
                   AND role = ?1 AND st_dev = ?2 AND st_ino = ?3",
            )?
            .query_row(
                params![
                    identity.role.as_str(),
                    signed(identity.st_dev, "device")?,
                    signed(identity.st_ino, "inode")?
                ],
                |r| r.get(0),
            )?;
        Ok(count != 0)
    }

    /// Replays every unreleased claim, worker and lease. A restart serves nothing
    /// before this, and never recalculates capacity from what happens to be visible.
    pub fn replay(&self) -> Result<ReplaySnapshot, LedgerError> {
        let mut statement = self.conn.prepare(
            "SELECT a.allocation_id, a.plan_digest, a.phase, a.updated_generation,
                (SELECT COUNT(*) FROM worker_intents w WHERE w.allocation_id = a.allocation_id
                    AND w.settled_generation IS NULL)
             FROM allocations a WHERE a.phase != 'absent' ORDER BY a.allocation_id",
        )?;
        let mut rows = statement.query([])?;
        let mut active_allocations = Vec::new();
        while let Some(row) = rows.next()? {
            active_allocations.push(InventoryRecord {
                allocation_id: parse_id(row.get(0)?)?,
                plan_digest: parse_sha(row.get(1)?)?,
                phase: row.get(2)?,
                generation: unsigned(row.get(3)?)?,
                unsettled_workers: unsigned(row.get(4)?)?,
            });
        }
        let mut statement = self.conn.prepare(
            "SELECT id, allocation_id, mode, operation_generation, pid, start_time, host_boot_id
             FROM worker_intents WHERE settled_generation IS NULL ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        let mut unsettled_workers = Vec::new();
        while let Some(row) = rows.next()? {
            unsettled_workers.push(WorkerRecord {
                worker_id: row.get(0)?,
                allocation_id: row.get::<_, Option<String>>(1)?.map(parse_id).transpose()?,
                mode: row.get(2)?,
                operation_generation: unsigned(row.get(3)?)?,
                pid: row.get(4)?,
                start_time: row.get::<_, Option<i64>>(5)?.map(unsigned).transpose()?,
                host_boot_id: row.get(6)?,
            });
        }
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT role, st_dev, st_ino, bytes, sha256, installation_generation
             FROM executable_leases WHERE released_generation IS NULL ORDER BY role",
        )?;
        let mut rows = statement.query([])?;
        let mut executable_leases = Vec::new();
        while let Some(row) = rows.next()? {
            let role: String = row.get(0)?;
            executable_leases.push(ExecutableIdentity {
                role: Role::parse(&role)
                    .ok_or_else(|| LedgerError::Corrupt("executable role".into()))?,
                st_dev: unsigned(row.get(1)?)?,
                st_ino: unsigned(row.get(2)?)?,
                bytes: unsigned(row.get(3)?)?,
                sha256: parse_sha(row.get(4)?)?,
                installation_generation: unsigned(row.get(5)?)?,
            });
        }
        Ok(ReplaySnapshot {
            generation: self.generation()?,
            active_allocations,
            unsettled_workers,
            executable_leases,
        })
    }

    /// Test access to the plan bytes for the replay checks.
    #[cfg(test)]
    pub(super) fn connection(&self) -> &Connection {
        &self.conn
    }
}

fn corrupt(error: LedgerError) -> LedgerError {
    match error {
        LedgerError::Store(e) => LedgerError::Corrupt(e.to_string()),
        other => other,
    }
}

/// The ledger's fixed directory, for the startup lock.
pub fn ledger_lock_path(directory: &Path) -> PathBuf {
    directory.join(LEDGER_LOCK)
}

#[cfg(test)]
pub(super) mod tests;
