//! The root node ledger: section 4.1's one authority for node capacity, identities,
//! worker intents, receipts and permanent fences. Only the L process opens it. All SQL
//! is fixed text here. Every release after a claim goes through `commit_fence`, in one
//! FULL-sync transaction that also writes the permanent retired-token entry.
use super::config::{NodeCeilings, SharedReserve, validate_ceilings};
use super::executable::{ExecutableIdentity, ProtectedDir, Role, WalkPolicy, walk_directory};
use super::identity::{ClaimedIdentities, IdentityLeases, LeaseKind};
use super::peer::{EnrolledExecutable, Enrollment};
use super::token::{self, TokenKey};
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
const SCHEMA_VERSION: i64 = 2;
/// The most space one retained token can need across all its rows. B7 measures the
/// worst case (`b7_fence_entry_bound_is_the_measured_worst_case`: every bounded
/// per-allocation family at its cap, every field at its widest) at about 18.0 KB, above
/// the design's 16 KiB estimate, against about 9.8 KB for a typical session; the bound
/// is that measurement rounded up to the next 4 KiB.
pub const FENCE_ENTRY_BOUND: u64 = 20 * 1024;
/// A quarter of the fence allowance's entries is set aside for tokens that never reach
/// admission, divided equally among possible instances (RTC-12).
const NEVER_ADMITTED_SHARE: u64 = 4;
/// B7 defaults (design 16.4), all root policy: a token's lease before W may pass it, one
/// compaction pass per instance, and at most this many tokens per delete transaction.
pub const DEFAULT_COMPACTION_LEASE_MS: u64 = 15 * 60 * 1000;
pub const DEFAULT_COMPACTION_PASS_MS: u64 = 60 * 1000;
/// RTC-18 caps one delete transaction at 100 ms. A full 256-token batch of admitted
/// sessions measured 310 to 580 ms on mini-one (FULL sync, every trigger), and 32 tokens
/// about 40 ms idle but up to 195 ms on a loaded host, so B7 lowers the batch to 16 as
/// the rule requires (`b7_rtc18_..._stays_under_100_ms` measures it).
pub const COMPACTION_BATCH: u64 = 16;
/// The newest compaction records kept per instance.
pub const COMPACTION_LOG_KEPT: i64 = 64;
/// A complete inventory is bounded to this many active allocations.
pub const MAX_ACTIVE_LISTED: usize = 1024;
/// B5-01's per-allocation retention: the stop reasons and settled worker rows kept.
pub const STOP_REASONS_KEPT: i64 = 16;
pub const SETTLED_WORKERS_KEPT: i64 = 8;
/// An execution's settlement states: the last row of its token.
pub const EXEC_TERMINAL: [&str; 3] = ["idle", "undispatched", "interrupted"];

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
    unit TEXT NOT NULL UNIQUE,
    cgroup TEXT NOT NULL UNIQUE,
    uid INTEGER NOT NULL UNIQUE CHECK (uid > 0),
    gid INTEGER NOT NULL UNIQUE CHECK (gid > 0),
    exe_st_dev INTEGER NOT NULL,
    exe_st_ino INTEGER NOT NULL,
    exe_bytes INTEGER NOT NULL,
    exe_sha256 TEXT NOT NULL,
    database_uuid TEXT,
    first_generation INTEGER NOT NULL CHECK (first_generation >= 1)
) STRICT;
CREATE TABLE allocations (
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    allocation_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    plan_digest TEXT NOT NULL,
    profile TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    host_spec_sha256 TEXT NOT NULL,
    guest_exec_spec_sha256 TEXT NOT NULL,
    work_uuid TEXT NOT NULL,
    stop_authority TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN
        ('intent','preparing','spawn_intent','booting','ready','exec_intent','busy',
         'stop_intent','stopped','cleaning','quarantined','absent')),
    created_generation INTEGER NOT NULL CHECK (created_generation >= 1),
    updated_generation INTEGER NOT NULL CHECK (updated_generation >= created_generation),
    -- B7 (RTC-1): the helper-issued sequence the token's hex prefix names.
    issue_seq INTEGER NOT NULL CHECK (issue_seq BETWEEN 1 AND 9223372036854775806
        AND substr(allocation_id, 1, 16) = printf('%016x', issue_seq)),
    PRIMARY KEY (instance_id, allocation_id),
    UNIQUE (instance_id, sandbox_id),
    UNIQUE (instance_id, backend_id)
) STRICT;
CREATE INDEX allocations_issue_seq ON allocations(instance_id, issue_seq);
CREATE TABLE allocation_plans (
    instance_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    plan BLOB NOT NULL,
    PRIMARY KEY (instance_id, allocation_id),
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
CREATE TABLE capacity_claims (
    instance_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    memory_bytes INTEGER NOT NULL CHECK (memory_bytes >= 0),
    disk_bytes INTEGER NOT NULL CHECK (disk_bytes >= 0),
    pids INTEGER NOT NULL CHECK (pids >= 0),
    host_cpu_millis INTEGER NOT NULL CHECK (host_cpu_millis >= 0),
    virtual_cpu_slots INTEGER NOT NULL CHECK (virtual_cpu_slots >= 0),
    host_pids INTEGER NOT NULL CHECK (host_pids >= 0),
    claimed_generation INTEGER NOT NULL CHECK (claimed_generation >= 1),
    released_generation INTEGER CHECK (released_generation IS NULL
        OR released_generation > claimed_generation),
    PRIMARY KEY (instance_id, allocation_id),
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
CREATE TABLE identity_leases (
    id INTEGER PRIMARY KEY,
    namespace TEXT NOT NULL CHECK (namespace IN ('uid','gid','cid')),
    kind TEXT NOT NULL CHECK (kind IN ('vmm_uid','relay_uid','vmm_gid','relay_gid','cid')),
    value INTEGER NOT NULL,
    instance_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    claimed_generation INTEGER NOT NULL CHECK (claimed_generation >= 1),
    released_generation INTEGER CHECK (released_generation IS NULL
        OR released_generation > claimed_generation),
    UNIQUE (instance_id, allocation_id, kind),
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
-- The one node-wide uniqueness a claim can meet: these are real kernel identities, and
-- a preflight picks free ones. A collision is answered exactly, and can then be fenced.
CREATE UNIQUE INDEX identity_leases_active
    ON identity_leases(namespace, value) WHERE released_generation IS NULL;
CREATE TABLE executable_leases (
    instance_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
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
    -- How the observed tuple is known: 'proc_exe' was read from the running process's
    -- image; 'retained_fd' is the verified retained descriptor's tuple, inferred from a
    -- confirmed execveat of it (a short-lived formatter has no stable image to read).
    observation TEXT CHECK (observation IS NULL OR observation IN ('proc_exe','retained_fd')),
    released_generation INTEGER,
    CHECK ((observation IS NULL) = (observed_st_dev IS NULL)),
    PRIMARY KEY (instance_id, allocation_id, role),
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
CREATE TABLE worker_intents (
    id INTEGER PRIMARY KEY,
    instance_id TEXT,
    allocation_id TEXT,
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
    settlement TEXT,
    CHECK ((instance_id IS NULL) = (allocation_id IS NULL)),
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
CREATE TABLE retired_tokens (
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    allocation_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    helper_generation INTEGER NOT NULL UNIQUE CHECK (helper_generation >= 1),
    receipt BLOB NOT NULL,
    issue_seq INTEGER NOT NULL CHECK (issue_seq BETWEEN 1 AND 9223372036854775806
        AND substr(allocation_id, 1, 16) = printf('%016x', issue_seq)),
    PRIMARY KEY (instance_id, allocation_id)
) STRICT;
CREATE INDEX retired_tokens_issue_seq ON retired_tokens(instance_id, issue_seq);
CREATE TABLE stop_events (
    id INTEGER PRIMARY KEY,
    instance_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    reason TEXT NOT NULL,
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
-- What S owns, journaled before or as it comes to own it: append-only, the latest row
-- of a kind is current. Cleanup and absence observation compare against these.
CREATE TABLE resource_events (
    id INTEGER PRIMARY KEY,
    instance_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN
        ('intent','cgroup','work_dir','work_file','private_files','loop_intent','loop',
         'loop_released','jail_intent','jail_dir','jail_mount','jail_binds','vmm','broker',
         'exec','exec_history')),
    detail TEXT NOT NULL,
    generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    FOREIGN KEY (instance_id, allocation_id) REFERENCES allocations(instance_id, allocation_id)
) STRICT;
-- B7 (design 16.6): the node's token key, written once at provisioning.
CREATE TABLE token_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key BLOB NOT NULL CHECK (length(key) = 32),
    key_check BLOB NOT NULL CHECK (length(key_check) = 16),
    created_generation INTEGER NOT NULL CHECK (created_generation >= 1)
) STRICT;
-- Each instance's exact exclusive issue pointer, its watermark W and W's generation G_W,
-- and the trigger-kept count of its retained allocation rows (RTC-4, RTC-5, RTC-17).
CREATE TABLE instance_tokens (
    instance_id TEXT PRIMARY KEY REFERENCES instances(instance_id),
    issue_next INTEGER NOT NULL CHECK (issue_next >= 1 AND issue_next <= 9223372036854775807),
    watermark INTEGER NOT NULL CHECK (watermark >= 1),
    watermark_generation INTEGER NOT NULL CHECK (watermark_generation >= 1),
    retained_admitted INTEGER NOT NULL CHECK (retained_admitted >= 0),
    CHECK (watermark <= issue_next)
) STRICT;
CREATE TABLE compaction_log (
    id INTEGER PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    from_w INTEGER NOT NULL CHECK (from_w >= 1),
    to_w INTEGER NOT NULL CHECK (to_w >= from_w),
    generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    tokens_deleted INTEGER NOT NULL CHECK (tokens_deleted >= 0),
    rows_deleted INTEGER NOT NULL CHECK (rows_deleted >= 0)
) STRICT;
-- RTC-14: insert-only durable faults. Only the root offline clear deletes them.
CREATE TABLE node_faults (
    id INTEGER PRIMARY KEY,
    generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('rollback')),
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    token TEXT NOT NULL,
    issue_next_seen INTEGER NOT NULL CHECK (issue_next_seen >= 1),
    detail TEXT NOT NULL,
    UNIQUE (kind, instance_id, token)
) STRICT;
CREATE TABLE node_fault_clears (
    id INTEGER PRIMARY KEY,
    generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    cleared_through_generation INTEGER NOT NULL CHECK (cleared_through_generation >= 0),
    inventory_sha256 TEXT NOT NULL,
    raised_pointers TEXT NOT NULL
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
WHEN EXISTS (SELECT 1 FROM instances WHERE rowid = NEW.rowid OR instance_id = NEW.instance_id
    OR unit = NEW.unit OR cgroup = NEW.cgroup OR uid = NEW.uid OR gid = NEW.gid)
BEGIN SELECT RAISE(ABORT, 'an instance binding cannot be replaced'); END;
CREATE TRIGGER instances_no_replace_update BEFORE UPDATE ON instances
WHEN EXISTS (SELECT 1 FROM instances WHERE rowid != OLD.rowid AND (rowid = NEW.rowid
    OR instance_id = NEW.instance_id OR unit = NEW.unit OR cgroup = NEW.cgroup
    OR uid = NEW.uid OR gid = NEW.gid))
BEGIN SELECT RAISE(ABORT, 'an instance binding cannot be replaced'); END;
-- Root may re-enroll a unit or image. Identity never changes, and a database binding
-- is written once, by that instance's first attachment.
CREATE TRIGGER instances_no_update BEFORE UPDATE ON instances
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.first_generation IS NOT OLD.first_generation
    OR (OLD.database_uuid IS NOT NULL AND NEW.database_uuid IS NOT OLD.database_uuid)
BEGIN SELECT RAISE(ABORT, 'an instance binding is immutable'); END;
CREATE TRIGGER instances_no_delete BEFORE DELETE ON instances
BEGIN SELECT RAISE(ABORT, 'an instance binding is permanent'); END;

CREATE TRIGGER allocations_no_replace BEFORE INSERT ON allocations
WHEN EXISTS (SELECT 1 FROM allocations WHERE rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND (allocation_id = NEW.allocation_id
        OR sandbox_id = NEW.sandbox_id OR backend_id = NEW.backend_id)))
BEGIN SELECT RAISE(ABORT, 'an allocation cannot be replaced'); END;
CREATE TRIGGER allocations_no_replace_update BEFORE UPDATE ON allocations
WHEN EXISTS (SELECT 1 FROM allocations WHERE rowid != OLD.rowid AND (rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND (allocation_id = NEW.allocation_id
        OR sandbox_id = NEW.sandbox_id OR backend_id = NEW.backend_id))))
BEGIN SELECT RAISE(ABORT, 'an allocation cannot be replaced'); END;
CREATE TRIGGER allocations_no_resurrection BEFORE INSERT ON allocations
WHEN EXISTS (SELECT 1 FROM retired_tokens WHERE instance_id = NEW.instance_id
    AND allocation_id = NEW.allocation_id)
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
    OR NEW.issue_seq IS NOT OLD.issue_seq
BEGIN SELECT RAISE(ABORT, 'allocation identity is immutable'); END;
CREATE TRIGGER allocations_generation_compare BEFORE UPDATE ON allocations
WHEN NEW.updated_generation <= OLD.updated_generation
BEGIN SELECT RAISE(ABORT, 'allocation generations only increase'); END;
CREATE TRIGGER allocations_absent_is_final BEFORE UPDATE ON allocations
WHEN OLD.phase = 'absent'
BEGIN SELECT RAISE(ABORT, 'an absent allocation cannot change'); END;
CREATE TRIGGER allocations_absent_needs_release BEFORE UPDATE OF phase ON allocations
WHEN NEW.phase = 'absent' AND EXISTS (SELECT 1 FROM capacity_claims
    WHERE instance_id = NEW.instance_id AND allocation_id = NEW.allocation_id
    AND released_generation IS NULL)
BEGIN SELECT RAISE(ABORT, 'absence requires its claim release'); END;
-- B7 RTC-7: C2 commits INTENT only for W <= seq < issue_next.
CREATE TRIGGER allocations_issued_above_watermark BEFORE INSERT ON allocations
WHEN NOT EXISTS (SELECT 1 FROM instance_tokens t WHERE t.instance_id = NEW.instance_id
    AND NEW.issue_seq >= t.watermark AND NEW.issue_seq < t.issue_next)
BEGIN SELECT RAISE(ABORT, 'an allocation must be issued and at or above its watermark'); END;
CREATE TRIGGER allocations_count_insert AFTER INSERT ON allocations
BEGIN UPDATE instance_tokens SET retained_admitted = retained_admitted + 1
    WHERE instance_id = NEW.instance_id; END;
CREATE TRIGGER allocations_count_delete AFTER DELETE ON allocations
BEGIN UPDATE instance_tokens SET retained_admitted = retained_admitted - 1
    WHERE instance_id = OLD.instance_id; END;
-- B7 RTC-10: an allocation record goes only once absent and compactable, and after every
-- child row of its token. The child order is checked here, not left to foreign keys.
CREATE TRIGGER allocations_no_delete BEFORE DELETE ON allocations
WHEN NOT (OLD.phase = 'absent' AND EXISTS (SELECT 1 FROM retired_tokens r
    JOIN instance_tokens t ON t.instance_id = r.instance_id
    WHERE r.instance_id = OLD.instance_id AND r.allocation_id = OLD.allocation_id
      AND r.issue_seq < t.watermark AND r.helper_generation < t.watermark_generation)
    AND NOT EXISTS (SELECT 1 FROM allocation_plans c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM capacity_claims c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM identity_leases c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM executable_leases c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM worker_intents c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM stop_events c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM resource_events c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id))
BEGIN SELECT RAISE(ABORT, 'an allocation record is permanent until compactable'); END;

CREATE TRIGGER allocation_plans_no_replace BEFORE INSERT ON allocation_plans
WHEN EXISTS (SELECT 1 FROM allocation_plans WHERE rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND allocation_id = NEW.allocation_id))
BEGIN SELECT RAISE(ABORT, 'a plan cannot be replaced'); END;
CREATE TRIGGER allocation_plans_no_update BEFORE UPDATE ON allocation_plans
BEGIN SELECT RAISE(ABORT, 'a plan is immutable'); END;
-- Plan bytes alone leave when a permanent fence has retired the token.
CREATE TRIGGER allocation_plans_retained_until_fence BEFORE DELETE ON allocation_plans
WHEN NOT EXISTS (SELECT 1 FROM retired_tokens WHERE instance_id = OLD.instance_id
    AND allocation_id = OLD.allocation_id)
BEGIN SELECT RAISE(ABORT, 'a plan stays until its absence fence'); END;

CREATE TRIGGER capacity_claims_no_replace BEFORE INSERT ON capacity_claims
WHEN EXISTS (SELECT 1 FROM capacity_claims WHERE rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND allocation_id = NEW.allocation_id))
BEGIN SELECT RAISE(ABORT, 'a capacity claim cannot be replaced'); END;
CREATE TRIGGER capacity_claims_immutable BEFORE UPDATE ON capacity_claims
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.allocation_id IS NOT OLD.allocation_id
    OR NEW.memory_bytes IS NOT OLD.memory_bytes OR NEW.disk_bytes IS NOT OLD.disk_bytes
    OR NEW.pids IS NOT OLD.pids OR NEW.host_cpu_millis IS NOT OLD.host_cpu_millis
    OR NEW.virtual_cpu_slots IS NOT OLD.virtual_cpu_slots OR NEW.host_pids IS NOT OLD.host_pids
    OR NEW.claimed_generation IS NOT OLD.claimed_generation
    OR OLD.released_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a capacity claim only changes by its one release'); END;
CREATE TRIGGER capacity_claims_no_delete BEFORE DELETE ON capacity_claims
WHEN NOT (OLD.released_generation IS NOT NULL AND EXISTS (SELECT 1 FROM allocations a
        JOIN retired_tokens r ON r.instance_id = a.instance_id AND r.allocation_id = a.allocation_id
        JOIN instance_tokens t ON t.instance_id = r.instance_id
        WHERE a.instance_id = OLD.instance_id AND a.allocation_id = OLD.allocation_id
          AND a.phase = 'absent' AND r.issue_seq < t.watermark
          AND r.helper_generation < t.watermark_generation))
BEGIN SELECT RAISE(ABORT, 'a capacity claim is permanent until compactable'); END;

CREATE TRIGGER identity_leases_no_replace BEFORE INSERT ON identity_leases
WHEN EXISTS (SELECT 1 FROM identity_leases WHERE rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND allocation_id = NEW.allocation_id AND kind = NEW.kind)
    OR (namespace = NEW.namespace AND value = NEW.value AND released_generation IS NULL))
BEGIN SELECT RAISE(ABORT, 'an identity lease collides'); END;
CREATE TRIGGER identity_leases_immutable BEFORE UPDATE ON identity_leases
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.namespace IS NOT OLD.namespace OR NEW.kind IS NOT OLD.kind
    OR NEW.value IS NOT OLD.value OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.allocation_id IS NOT OLD.allocation_id
    OR NEW.claimed_generation IS NOT OLD.claimed_generation
    OR OLD.released_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an identity lease only changes by its one release'); END;
CREATE TRIGGER identity_leases_no_delete BEFORE DELETE ON identity_leases
WHEN NOT (OLD.released_generation IS NOT NULL AND EXISTS (SELECT 1 FROM allocations a
        JOIN retired_tokens r ON r.instance_id = a.instance_id AND r.allocation_id = a.allocation_id
        JOIN instance_tokens t ON t.instance_id = r.instance_id
        WHERE a.instance_id = OLD.instance_id AND a.allocation_id = OLD.allocation_id
          AND a.phase = 'absent' AND r.issue_seq < t.watermark
          AND r.helper_generation < t.watermark_generation))
BEGIN SELECT RAISE(ABORT, 'an identity lease is permanent until compactable'); END;

CREATE TRIGGER executable_leases_no_replace BEFORE INSERT ON executable_leases
WHEN EXISTS (SELECT 1 FROM executable_leases WHERE rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND allocation_id = NEW.allocation_id AND role = NEW.role))
BEGIN SELECT RAISE(ABORT, 'an executable lease cannot be replaced'); END;
CREATE TRIGGER executable_leases_immutable BEFORE UPDATE ON executable_leases
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.allocation_id IS NOT OLD.allocation_id OR NEW.role IS NOT OLD.role
    OR NEW.st_dev IS NOT OLD.st_dev OR NEW.st_ino IS NOT OLD.st_ino OR NEW.bytes IS NOT OLD.bytes
    OR NEW.sha256 IS NOT OLD.sha256
    OR NEW.installation_generation IS NOT OLD.installation_generation
    OR (OLD.observed_st_dev IS NOT NULL AND NEW.observed_st_dev IS NOT OLD.observed_st_dev)
    OR (OLD.observation IS NOT NULL AND NEW.observation IS NOT OLD.observation)
    OR OLD.released_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an executable lease is immutable'); END;
CREATE TRIGGER executable_leases_no_delete BEFORE DELETE ON executable_leases
WHEN NOT (OLD.released_generation IS NOT NULL AND EXISTS (SELECT 1 FROM allocations a
        JOIN retired_tokens r ON r.instance_id = a.instance_id AND r.allocation_id = a.allocation_id
        JOIN instance_tokens t ON t.instance_id = r.instance_id
        WHERE a.instance_id = OLD.instance_id AND a.allocation_id = OLD.allocation_id
          AND a.phase = 'absent' AND r.issue_seq < t.watermark
          AND r.helper_generation < t.watermark_generation))
BEGIN SELECT RAISE(ABORT, 'an executable lease is permanent until compactable'); END;

CREATE TRIGGER worker_intents_no_replace BEFORE INSERT ON worker_intents
WHEN EXISTS (SELECT 1 FROM worker_intents WHERE rowid = NEW.rowid
    OR operation_generation = NEW.operation_generation)
BEGIN SELECT RAISE(ABORT, 'a worker intent cannot be replaced'); END;
CREATE TRIGGER worker_intents_immutable BEFORE UPDATE ON worker_intents
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.allocation_id IS NOT OLD.allocation_id OR NEW.mode IS NOT OLD.mode
    OR NEW.operation_generation IS NOT OLD.operation_generation
    OR NEW.allowed_names IS NOT OLD.allowed_names OR NEW.cgroup IS NOT OLD.cgroup
    OR NEW.exec_role IS NOT OLD.exec_role OR NEW.exec_st_dev IS NOT OLD.exec_st_dev
    OR NEW.exec_st_ino IS NOT OLD.exec_st_ino OR NEW.exec_bytes IS NOT OLD.exec_bytes
    OR NEW.exec_sha256 IS NOT OLD.exec_sha256
    OR (OLD.pid IS NOT NULL AND (NEW.pid IS NOT OLD.pid OR NEW.start_time IS NOT OLD.start_time
        OR NEW.host_boot_id IS NOT OLD.host_boot_id))
    OR OLD.settled_generation IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a worker record is immutable once identified or settled'); END;
-- B5-01: an allocation's settled worker rows are compacted to its newest eight settled
-- rows of the same mode; an unsettled or node-level row is permanent. B7 RTC-10: a
-- compactable token's settled rows go with it.
CREATE TRIGGER worker_intents_no_delete BEFORE DELETE ON worker_intents
WHEN NOT (OLD.allocation_id IS NOT NULL AND OLD.settled_generation IS NOT NULL
    AND ((SELECT COUNT(*) FROM worker_intents w WHERE w.instance_id = OLD.instance_id
        AND w.allocation_id = OLD.allocation_id AND w.mode = OLD.mode
        AND w.settled_generation IS NOT NULL AND w.id > OLD.id) >= 8
      OR EXISTS (SELECT 1 FROM allocations a
        JOIN retired_tokens r ON r.instance_id = a.instance_id AND r.allocation_id = a.allocation_id
        JOIN instance_tokens t ON t.instance_id = r.instance_id
        WHERE a.instance_id = OLD.instance_id AND a.allocation_id = OLD.allocation_id
          AND a.phase = 'absent' AND r.issue_seq < t.watermark
          AND r.helper_generation < t.watermark_generation)))
BEGIN SELECT RAISE(ABORT, 'a worker record is permanent'); END;

CREATE TRIGGER retired_tokens_no_replace BEFORE INSERT ON retired_tokens
WHEN EXISTS (SELECT 1 FROM retired_tokens WHERE rowid = NEW.rowid
    OR (instance_id = NEW.instance_id AND allocation_id = NEW.allocation_id)
    OR receipt_id = NEW.receipt_id OR helper_generation = NEW.helper_generation)
BEGIN SELECT RAISE(ABORT, 'a fence cannot be replaced'); END;
CREATE TRIGGER retired_tokens_need_release BEFORE INSERT ON retired_tokens
WHEN EXISTS (SELECT 1 FROM capacity_claims WHERE instance_id = NEW.instance_id
    AND allocation_id = NEW.allocation_id AND released_generation IS NULL)
BEGIN SELECT RAISE(ABORT, 'a fence cannot coexist with a held claim'); END;
CREATE TRIGGER retired_tokens_no_update BEFORE UPDATE ON retired_tokens
BEGIN SELECT RAISE(ABORT, 'a fence is immutable'); END;
-- B7 RTC-7: a fence row is written only for an issued token, and below W only for one
-- with an allocation row (a pinned allocation reaching ABSENT).
CREATE TRIGGER retired_tokens_issued BEFORE INSERT ON retired_tokens
WHEN NOT EXISTS (SELECT 1 FROM instance_tokens t WHERE t.instance_id = NEW.instance_id
    AND NEW.issue_seq < t.issue_next AND (NEW.issue_seq >= t.watermark
        OR EXISTS (SELECT 1 FROM allocations a WHERE a.instance_id = NEW.instance_id
                   AND a.allocation_id = NEW.allocation_id)))
BEGIN SELECT RAISE(ABORT, 'a fence needs an issued token, and below W its allocation'); END;
-- B7 RTC-10: the fence row goes last, below W, behind G_W, with no allocation and no
-- child row of its token left, whether or not foreign keys are enforced.
CREATE TRIGGER retired_tokens_no_delete BEFORE DELETE ON retired_tokens
WHEN NOT (NOT EXISTS (SELECT 1 FROM allocations a WHERE a.instance_id = OLD.instance_id
        AND a.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM allocation_plans c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM capacity_claims c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM identity_leases c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM executable_leases c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM worker_intents c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM stop_events c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND NOT EXISTS (SELECT 1 FROM resource_events c WHERE c.instance_id = OLD.instance_id
        AND c.allocation_id = OLD.allocation_id)
    AND EXISTS (SELECT 1 FROM instance_tokens t WHERE t.instance_id = OLD.instance_id
        AND OLD.issue_seq < t.watermark AND OLD.helper_generation < t.watermark_generation))
BEGIN SELECT RAISE(ABORT, 'a fence is permanent until compactable'); END;

CREATE TRIGGER stop_events_no_replace BEFORE INSERT ON stop_events
WHEN EXISTS (SELECT 1 FROM stop_events WHERE rowid = NEW.rowid OR generation = NEW.generation)
BEGIN SELECT RAISE(ABORT, 'a stop event cannot be replaced'); END;
CREATE TRIGGER stop_events_no_update BEFORE UPDATE ON stop_events
BEGIN SELECT RAISE(ABORT, 'a stop event is immutable'); END;
CREATE TRIGGER stop_events_no_delete BEFORE DELETE ON stop_events
WHEN NOT EXISTS (SELECT 1 FROM allocations a
        JOIN retired_tokens r ON r.instance_id = a.instance_id AND r.allocation_id = a.allocation_id
        JOIN instance_tokens t ON t.instance_id = r.instance_id
        WHERE a.instance_id = OLD.instance_id AND a.allocation_id = OLD.allocation_id
          AND a.phase = 'absent' AND r.issue_seq < t.watermark
          AND r.helper_generation < t.watermark_generation)
BEGIN SELECT RAISE(ABORT, 'a stop event is permanent until compactable'); END;

CREATE TRIGGER resource_events_no_replace BEFORE INSERT ON resource_events
WHEN EXISTS (SELECT 1 FROM resource_events WHERE rowid = NEW.rowid OR generation = NEW.generation)
BEGIN SELECT RAISE(ABORT, 'a resource event cannot be replaced'); END;
CREATE TRIGGER resource_events_not_after_absent BEFORE INSERT ON resource_events
WHEN EXISTS (SELECT 1 FROM allocations WHERE instance_id = NEW.instance_id
    AND allocation_id = NEW.allocation_id AND phase = 'absent')
BEGIN SELECT RAISE(ABORT, 'an absent allocation owns nothing new'); END;
CREATE TRIGGER resource_events_no_update BEFORE UPDATE ON resource_events
BEGIN SELECT RAISE(ABORT, 'a resource event is immutable'); END;
-- B5-01: execution evidence is compacted, nothing else. An `exec` or `exec_history` row
-- may go only once a newer `exec_history` row of the same allocation holds its summary.
CREATE TRIGGER resource_events_no_delete BEFORE DELETE ON resource_events
WHEN NOT ((OLD.kind IN ('exec','exec_history') AND EXISTS (SELECT 1 FROM resource_events r
    WHERE r.instance_id = OLD.instance_id AND r.allocation_id = OLD.allocation_id
      AND r.kind = 'exec_history' AND r.generation > OLD.generation))
    OR EXISTS (SELECT 1 FROM allocations a
        JOIN retired_tokens r ON r.instance_id = a.instance_id AND r.allocation_id = a.allocation_id
        JOIN instance_tokens t ON t.instance_id = r.instance_id
        WHERE a.instance_id = OLD.instance_id AND a.allocation_id = OLD.allocation_id
          AND a.phase = 'absent' AND r.issue_seq < t.watermark
          AND r.helper_generation < t.watermark_generation))
BEGIN SELECT RAISE(ABORT, 'a resource event is permanent'); END;

CREATE TRIGGER token_key_no_replace BEFORE INSERT ON token_key
WHEN EXISTS (SELECT 1 FROM token_key)
BEGIN SELECT RAISE(ABORT, 'the token key is written once'); END;
CREATE TRIGGER token_key_no_update BEFORE UPDATE ON token_key
BEGIN SELECT RAISE(ABORT, 'the token key is immutable'); END;
CREATE TRIGGER token_key_no_delete BEFORE DELETE ON token_key
BEGIN SELECT RAISE(ABORT, 'the token key is permanent'); END;

CREATE TRIGGER instance_tokens_no_replace BEFORE INSERT ON instance_tokens
WHEN EXISTS (SELECT 1 FROM instance_tokens WHERE rowid = NEW.rowid
    OR instance_id = NEW.instance_id)
    OR NEW.issue_next != 1 OR NEW.watermark != 1
    OR NEW.retained_admitted != (SELECT COUNT(*) FROM allocations
        WHERE instance_id = NEW.instance_id)
BEGIN SELECT RAISE(ABORT, 'an instance token row is written once, at enrollment'); END;
-- RTC-4/RTC-5: the pointer and W only increase, W only with a fresh G_W, and the
-- retained count always equals the instance's allocation rows.
CREATE TRIGGER instance_tokens_monotonic BEFORE UPDATE ON instance_tokens
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.issue_next < OLD.issue_next OR NEW.watermark < OLD.watermark
    OR NEW.watermark_generation < OLD.watermark_generation
    OR (NEW.watermark != OLD.watermark
        AND NEW.watermark_generation <= OLD.watermark_generation)
BEGIN SELECT RAISE(ABORT, 'issue pointers and watermarks only increase'); END;
CREATE TRIGGER instance_tokens_counted BEFORE UPDATE ON instance_tokens
WHEN NEW.retained_admitted != (SELECT COUNT(*) FROM allocations
    WHERE instance_id = NEW.instance_id)
BEGIN SELECT RAISE(ABORT, 'the retained count must equal the allocation rows'); END;
CREATE TRIGGER instance_tokens_no_delete BEFORE DELETE ON instance_tokens
BEGIN SELECT RAISE(ABORT, 'an instance token row is permanent'); END;

CREATE TRIGGER compaction_log_no_replace BEFORE INSERT ON compaction_log
WHEN EXISTS (SELECT 1 FROM compaction_log WHERE rowid = NEW.rowid
    OR generation = NEW.generation)
BEGIN SELECT RAISE(ABORT, 'a compaction record cannot be replaced'); END;
CREATE TRIGGER compaction_log_counts_only BEFORE UPDATE ON compaction_log
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.from_w IS NOT OLD.from_w OR NEW.to_w IS NOT OLD.to_w
    OR NEW.generation IS NOT OLD.generation
    OR NEW.tokens_deleted < OLD.tokens_deleted OR NEW.rows_deleted < OLD.rows_deleted
BEGIN SELECT RAISE(ABORT, 'a compaction record only adds counts'); END;
CREATE TRIGGER compaction_log_newest_kept BEFORE DELETE ON compaction_log
WHEN (SELECT COUNT(*) FROM compaction_log c WHERE c.instance_id = OLD.instance_id
    AND c.generation > OLD.generation) < 64
BEGIN SELECT RAISE(ABORT, 'the newest 64 compaction records are kept'); END;

CREATE TRIGGER node_faults_no_replace BEFORE INSERT ON node_faults
WHEN EXISTS (SELECT 1 FROM node_faults WHERE rowid = NEW.rowid
    OR generation = NEW.generation
    OR (kind = NEW.kind AND instance_id = NEW.instance_id AND token = NEW.token))
BEGIN SELECT RAISE(ABORT, 'a node fault cannot be replaced'); END;
CREATE TRIGGER node_faults_no_update BEFORE UPDATE ON node_faults
BEGIN SELECT RAISE(ABORT, 'a node fault is immutable'); END;
-- RTC-14: deleted only in the offline clear's own transaction, under its clear row.
CREATE TRIGGER node_faults_cleared_only BEFORE DELETE ON node_faults
WHEN NOT EXISTS (SELECT 1 FROM node_fault_clears c
    WHERE c.generation = (SELECT value FROM generation_counter WHERE id = 1)
      AND c.cleared_through_generation >= OLD.generation)
BEGIN SELECT RAISE(ABORT, 'a node fault is cleared only by the offline clear'); END;

-- Written only by the root offline clear: its connection alone registers the function.
CREATE TRIGGER node_fault_clears_offline_only BEFORE INSERT ON node_fault_clears
WHEN EXISTS (SELECT 1 FROM node_fault_clears WHERE rowid = NEW.rowid
    OR generation = NEW.generation)
    OR NEW.generation != (SELECT value FROM generation_counter WHERE id = 1)
    OR kilnd_offline_fault_clear() IS NOT 1
BEGIN SELECT RAISE(ABORT, 'a fault clear is written only by the offline clear'); END;
CREATE TRIGGER node_fault_clears_no_update BEFORE UPDATE ON node_fault_clears
BEGIN SELECT RAISE(ABORT, 'a fault clear is immutable'); END;
CREATE TRIGGER node_fault_clears_no_delete BEFORE DELETE ON node_fault_clears
BEGIN SELECT RAISE(ABORT, 'a fault clear is permanent'); END;
";

/// Every table with its write-guard surface, for the guard matrix.
pub const GUARDED_TABLES: [&str; 17] = [
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
    "resource_events",
    "token_key",
    "instance_tokens",
    "compaction_log",
    "node_faults",
    "node_fault_clears",
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
    #[error("durable commit failed: {0}")]
    SyncFailed(String),
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
    /// B7 RTC-8: below W with no rows, so absent forever. The receipt is synthesized
    /// for the caller's plan digest and generation G_W; nothing was written.
    Compacted {
        receipt: Vec<u8>,
    },
    /// The tag does not verify in this instance, or seq is 0 (RTC-3).
    Malformed,
    /// A valid tag at or above the durable issue pointer: never issued (RTC-3).
    NotIssued,
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

/// One active allocation as cleanup sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationState {
    pub sandbox_id: String,
    pub plan_digest: Digest,
    pub phase: String,
    pub created_generation: u64,
    pub plan: Vec<u8>,
    pub resources: Vec<super::supervisor::ResourceRecord>,
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
    /// A token the ledger never admitted, from an instance that has used its whole quota
    /// of those fences. Nothing was written, and the daemon keeps its charge.
    QuotaExhausted {
        quota: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachOutcome {
    /// First binding, or the same database again.
    Bound { node_id: Id128, generation: u64 },
    /// B7 RTC-14: the reported highest token does not verify in this instance. This
    /// attachment alone fails; nothing was written.
    Malformed,
    /// B7 RTC-14: a verified token at or above the issue pointer. Nothing was written
    /// yet: L latches, H latches, and only then is the fault committed.
    RollbackDetected { token: Id128, issue_next: u64 },
    /// B7 RTC-14: the node's forward effects are latched; a first binding is one.
    Latched,
    /// Another database once owned this namespace: claims survive and admission is
    /// blocked until an operator resolves it. The binding itself never changes.
    DatabaseMismatch { node_id: Id128, generation: u64 },
    /// Root never enrolled this instance. Nothing was written.
    NotEnrolled,
}

/// Root's enrollment command, in one transaction. Only root reaches this: the helper
/// serves it over no socket, and it needs the node lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled {
        generation: u64,
    },
    /// The same instance again, with this unit and image now expected.
    Updated {
        generation: u64,
    },
    /// Root policy's total is reached. Enrolled instances stay as they are.
    LimitReached {
        limit: u32,
    },
    /// Another instance has this unit: one unit serves one instance, or compromising
    /// it would give both.
    UnitTaken,
    /// Another instance has this UID or GID. Two instances under one account could
    /// reach each other's memory and files, whatever else separates them.
    AccountTaken,
    /// Past the fence floor: the space already promised to fences stays promised.
    NoSpace,
}

/// B7: Preflight's issuance transaction (RTC-4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IssueOutcome {
    /// The pointer durably passed `token`'s seq before this answer existed.
    Issued {
        token: Id128,
        claimed: ClaimedIdentities,
    },
    /// Nothing was written and no seq was consumed.
    Refused { refusal: IssueRefusal },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueRefusal {
    /// RTC-17: no admitted headroom for this instance.
    Headroom,
    /// RTC-12: the never-admitted issuance floor for this window.
    NeverAdmittedFloor,
    /// RTC-4: the pointer is at 2^63 − 1 and never wraps.
    Exhausted,
    /// RTC-14: forward effects are latched node-wide.
    Latched,
    /// The ledger's live size is past its share of the reservation.
    LedgerSpace,
    NotEnrolled,
}

/// What one instance's token pointers read now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPointers {
    pub issue_next: u64,
    pub watermark: u64,
    pub watermark_generation: u64,
    pub retained_admitted: u64,
}

/// One delete transaction's result (RTC-10, RTC-11).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactBatch {
    pub tokens_deleted: u64,
    pub rows_deleted: u64,
    /// Fenced tokens below W whose allocation is not compactable: never deleted, named
    /// in Health. Only a corrupt ledger can have one.
    pub stuck: Vec<Id128>,
    /// Compactable rows remain after this batch.
    pub more: bool,
}

/// A watermark transaction's result (RTC-5, RTC-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advance {
    pub from: u64,
    pub to: u64,
    pub generation: u64,
}

/// RTC-16: the caller's own instance, never another's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenAccounting {
    pub issue_next: u64,
    pub watermark: u64,
    pub watermark_generation: u64,
    pub retained_admitted: u64,
    pub retained_never_admitted: u64,
    pub reserved_share: u64,
    pub pinned_below_watermark: u64,
    /// L's in-memory watermark checkpoints for this instance (RTC-13).
    pub checkpoints: u64,
    /// How long the oldest issuance not yet below W has waited, by L's boot clock.
    pub compaction_lag_ms: u64,
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
    /// B7 RTC-16: the caller's own instance, filled when the request names one.
    pub tokens: Option<TokenAccounting>,
    pub retained_admitted_total: u64,
    pub retained_never_admitted_total: u64,
    /// RTC-17's E and the per-slot share it reserves.
    pub admitted_entries: u64,
    pub share: u64,
    /// Entries by which retained rows exceed the reserved shares after a policy change.
    pub share_shortfall: u64,
    /// A durable or in-memory RTC-14 latch, by kind only.
    pub node_fault: Option<String>,
    /// Retained headroom below 25%, compaction lag past two leases, a stuck token or a
    /// share shortfall: Health degrades with this reason.
    pub degraded: Option<String>,
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
    pub instance_id: Option<Id128>,
    pub allocation_id: Option<Id128>,
    pub mode: String,
    pub operation_generation: u64,
    pub pid: Option<i32>,
    pub start_time: Option<u64>,
    pub host_boot_id: Option<String>,
}

/// Root's whole-node image update, in one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolledImagesOutcome {
    Updated {
        generation: u64,
        instances: usize,
    },
    /// The rows named aren't exactly the ones enrolled, with the same identity, unit and
    /// account. Nothing was written.
    IdentityChanged,
}

/// One enrolled instance and its account, which is what H partitions by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledAccount {
    pub instance_id: Id128,
    pub uid: u32,
    pub gid: u32,
}

/// Everything a helper restart replays before serving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySnapshot {
    pub generation: u64,
    /// B7 RTC-14: durable fault kinds, which latch H at once.
    pub node_faults: Vec<String>,
    pub enrolled: Vec<EnrolledAccount>,
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
    /// Root policy's enrollment limit, which sizes each instance's share of the allowance.
    pub max_enrolled: u32,
    /// B7: L's checkpoint and lease timing. The ledger itself never reads a clock.
    pub compaction: CompactionPolicy,
}

/// B7 compaction timing, root policy only (design 16.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPolicy {
    pub lease_ms: u64,
    pub pass_ms: u64,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            lease_ms: DEFAULT_COMPACTION_LEASE_MS,
            pass_ms: DEFAULT_COMPACTION_PASS_MS,
        }
    }
}

impl CompactionPolicy {
    /// RTC-13: LEASE / PASS + 2 checkpoints per instance (17 at the defaults).
    pub fn checkpoint_bound(&self) -> usize {
        (self.lease_ms / self.pass_ms.max(1)) as usize + 2
    }
}

pub struct Ledger {
    conn: Connection,
    config: LedgerConfig,
    /// K, read and checked at open (RTC-1). Never regenerated here.
    key: TokenKey,
    _directory: ProtectedDir,
    /// Only tests can set this: it models a failed durable commit.
    fail_next_commit: std::cell::Cell<bool>,
}

fn commit_tx(tx: Transaction<'_>, fail: &std::cell::Cell<bool>) -> Result<(), LedgerError> {
    if fail.replace(false) {
        drop(tx);
        return Err(LedgerError::CommitFailed);
    }
    tx.commit()
        .map_err(|error| LedgerError::SyncFailed(error.to_string()))
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

/// One account serves one instance. The schema already says so; this is the startup
/// refusal for a ledger that doesn't, however it came to be that way.
fn audit_accounts(conn: &Connection) -> Result<(), LedgerError> {
    let shared: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM (SELECT uid FROM instances GROUP BY uid HAVING COUNT(*) > 1))
              + (SELECT COUNT(*) FROM (SELECT gid FROM instances GROUP BY gid HAVING COUNT(*) > 1))
              + (SELECT COUNT(*) FROM instances WHERE uid <= 0 OR gid <= 0)",
        [],
        |r| r.get(0),
    )?;
    if shared != 0 {
        return Err(LedgerError::Corrupt(
            "enrolled instances share a Unix account".into(),
        ));
    }
    Ok(())
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

/// Every entry the fence allowance holds at the measured per-token bound.
fn allowance_entries(config: &LedgerConfig) -> u64 {
    config.shared.fence_allowance_bytes / FENCE_ENTRY_BOUND
}

/// Allowance entries set aside for all instances' never-admitted fences together: a
/// quarter of the allowance (2,048 of 8,192 at the default 128 MiB).
fn never_admitted_pool(config: &LedgerConfig) -> u64 {
    allowance_entries(config) / NEVER_ADMITTED_SHARE
}

/// RTC-17's E: the admitted entries, less the never-admitted pool, less one.
fn admitted_entries(config: &LedgerConfig) -> u64 {
    allowance_entries(config)
        .saturating_sub(never_admitted_pool(config))
        .saturating_sub(1)
}

/// RTC-17's slot arithmetic over one snapshot of the retained counters.
struct Shares {
    entries: u64,
    slots: u64,
    share: u64,
    enrolled: u64,
    retained: Vec<(String, u64)>,
}

impl Shares {
    fn read(conn: &Connection, config: &LedgerConfig) -> Result<Self, LedgerError> {
        let mut statement =
            conn.prepare_cached("SELECT instance_id, retained_admitted FROM instance_tokens")?;
        let mut rows = statement.query([])?;
        let mut retained = Vec::new();
        while let Some(row) = rows.next()? {
            retained.push((row.get::<_, String>(0)?, unsigned(row.get(1)?)?));
        }
        let enrolled = retained.len() as u64;
        let slots = enrolled.max(u64::from(config.max_enrolled)).max(1);
        let entries = admitted_entries(config);
        Ok(Self {
            entries,
            slots,
            share: entries / slots,
            enrolled,
            retained,
        })
    }

    fn total(&self) -> u64 {
        self.retained.iter().map(|(_, r)| *r).sum()
    }

    fn of(&self, instance: &str) -> u64 {
        self.retained
            .iter()
            .find(|(id, _)| id == instance)
            .map_or(0, |(_, r)| *r)
    }

    /// RTC-17: an instance below its share always fits; above it, only while free − 1
    /// still covers every other slot's unused share, enrolled or not.
    fn admits(&self, instance: &str) -> bool {
        let free = self.entries.saturating_sub(self.total());
        let reserve: u64 = self
            .retained
            .iter()
            .filter(|(id, _)| id != instance)
            .map(|(_, r)| self.share.saturating_sub(*r))
            .sum::<u64>()
            + self.slots.saturating_sub(self.enrolled) * self.share;
        free >= 1 && (self.of(instance) < self.share || free > reserve)
    }

    /// Σ max(retained, share) over every slot, less E: positive only after a policy
    /// change shrank the share under existing rows.
    fn shortfall(&self) -> u64 {
        let held: u64 = self
            .retained
            .iter()
            .map(|(_, r)| (*r).max(self.share))
            .sum::<u64>()
            + self.slots.saturating_sub(self.enrolled) * self.share;
        held.saturating_sub(self.entries)
    }
}

/// One instance's share. A lowered policy can leave more rows than its limit, so the
/// divisor follows the rows too, and the quotas always sum to within the pool.
fn never_admitted_quota(conn: &Connection, config: &LedgerConfig) -> Result<u64, LedgerError> {
    let enrolled: i64 = conn
        .prepare_cached("SELECT COUNT(*) FROM instances")?
        .query_row([], |r| r.get(0))?;
    let capacity = unsigned(enrolled)?
        .max(u64::from(config.max_enrolled))
        .max(1);
    Ok(never_admitted_pool(config) / capacity)
}

/// Retained fences this instance holds for tokens with no admission record (RTC-12:
/// compacted ones no longer count).
fn never_admitted_fences(conn: &Connection, instance: Id128) -> Result<u64, LedgerError> {
    let used: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM retired_tokens r WHERE r.instance_id = ?1 AND NOT EXISTS
                (SELECT 1 FROM allocations a WHERE a.instance_id = r.instance_id
                    AND a.allocation_id = r.allocation_id)",
        )?
        .query_row([instance.to_string()], |r| r.get(0))?;
    unsigned(used)
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

fn generation_of(conn: &Connection) -> Result<u64, LedgerError> {
    let value: i64 = conn
        .prepare_cached("SELECT value FROM generation_counter WHERE id = 1")?
        .query_row([], |r| r.get(0))?;
    unsigned(value)
}

/// RTC-1/RTC-16: K is present, exactly 32 bytes, and its check value verifies for
/// this node. A missing, truncated or substituted key fails the open audit.
fn audit_token_key(conn: &Connection, node_id: Id128) -> Result<TokenKey, LedgerError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT key, key_check FROM token_key WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((key, check)) = row else {
        return Err(LedgerError::Corrupt("the token key is missing".into()));
    };
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| LedgerError::Corrupt("the token key has the wrong length".into()))?;
    let key = TokenKey::from_parts(node_id, key);
    if !key.check_matches(&check) {
        return Err(LedgerError::Corrupt(
            "the token key does not match its check value".into(),
        ));
    }
    Ok(key)
}

/// RTC-16's token checks: one pointer row per instance, every stored seq's prefix and
/// tag, W <= pointer, every seq below its pointer, no absent allocation below W without
/// its fence, every retained counter equal to its rows, and no fault row the clears
/// already cover.
fn audit_tokens(conn: &Connection, key: &TokenKey) -> Result<(), LedgerError> {
    let unpaired: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM instances i WHERE NOT EXISTS
                    (SELECT 1 FROM instance_tokens t WHERE t.instance_id = i.instance_id))
              + (SELECT COUNT(*) FROM instance_tokens t WHERE NOT EXISTS
                    (SELECT 1 FROM instances i WHERE i.instance_id = t.instance_id))",
        [],
        |r| r.get(0),
    )?;
    if unpaired != 0 {
        return Err(LedgerError::Corrupt(
            "an instance has no token pointers, or pointers have no instance".into(),
        ));
    }
    let broken: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM instance_tokens WHERE watermark > issue_next)
              + (SELECT COUNT(*) FROM allocations a JOIN instance_tokens t USING (instance_id)
                 WHERE a.issue_seq >= t.issue_next)
              + (SELECT COUNT(*) FROM retired_tokens r JOIN instance_tokens t USING (instance_id)
                 WHERE r.issue_seq >= t.issue_next)
              + (SELECT COUNT(*) FROM allocations a JOIN instance_tokens t USING (instance_id)
                 WHERE a.issue_seq < t.watermark AND a.phase = 'absent' AND NOT EXISTS
                    (SELECT 1 FROM retired_tokens r WHERE r.instance_id = a.instance_id
                     AND r.allocation_id = a.allocation_id))
              + (SELECT COUNT(*) FROM instance_tokens t WHERE t.retained_admitted !=
                    (SELECT COUNT(*) FROM allocations a WHERE a.instance_id = t.instance_id))
              + (SELECT COUNT(*) FROM node_faults f WHERE f.generation <=
                    (SELECT COALESCE(MAX(cleared_through_generation), 0) FROM node_fault_clears))",
        [],
        |r| r.get(0),
    )?;
    if broken != 0 {
        return Err(LedgerError::Corrupt(
            "token pointers, sequences, counters or fault clears are inconsistent".into(),
        ));
    }
    for table in ["allocations", "retired_tokens"] {
        let mut statement =
            conn.prepare(&format!("SELECT instance_id, allocation_id, issue_seq FROM {table}"))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let instance = parse_id(row.get(0)?)?;
            let allocation = parse_id(row.get(1)?)?;
            let seq = unsigned(row.get(2)?)?;
            if key.verify(instance, allocation) != Some(seq) {
                return Err(LedgerError::Corrupt(format!(
                    "a stored token's tag does not verify ({table})"
                )));
            }
        }
    }
    Ok(())
}

fn pointers_on(conn: &Connection, instance: Id128) -> Result<Option<TokenPointers>, LedgerError> {
    let row: Option<(i64, i64, i64, i64)> = conn
        .prepare_cached(
            "SELECT issue_next, watermark, watermark_generation, retained_admitted
             FROM instance_tokens WHERE instance_id = ?1",
        )?
        .query_row([instance.to_string()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    row.map(|(issue_next, watermark, generation, retained)| {
        Ok(TokenPointers {
            issue_next: unsigned(issue_next)?,
            watermark: unsigned(watermark)?,
            watermark_generation: unsigned(generation)?,
            retained_admitted: unsigned(retained)?,
        })
    })
    .transpose()
}

/// RTC-8's synthesized `AbsentFenced`: generation G_W, a receipt ID derived from every
/// input, the caller's own plan digest and no other source. It writes nothing.
fn compacted_receipt(
    node: Id128,
    instance: Id128,
    allocation: Id128,
    plan_digest: &Digest,
    seq: u64,
    pointers: &TokenPointers,
) -> Result<Vec<u8>, LedgerError> {
    let generation = pointers.watermark_generation;
    FencedAbsence::new(
        token::compacted_receipt_id(node, instance, allocation, plan_digest, generation),
        node,
        instance,
        allocation,
        *plan_digest,
        generation,
        format!(
            "compacted;watermark={};issue_seq={seq}",
            pointers.watermark
        ),
    )
    .and_then(|receipt| receipt.encode())
    .map_err(|e| LedgerError::Config(e.to_string()))
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
        // RTC-1: K from the kernel's CSPRNG, with its check value, in this same
        // transaction. Nothing else ever writes it, and open never makes another.
        let key = TokenKey::generate(config.node_id)?;
        tx.execute(
            "INSERT INTO token_key (id, key, key_check, created_generation) VALUES (1, ?1, ?2, 1)",
            params![&key.secret_bytes()[..], &key.check_value()[..]],
        )?;
        crate::helper::firecracker::workers::fault_point("ledger.provision.before_commit");
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
        let key = Self::audit(&conn, &config).map_err(corrupt)?;
        Ok(Self {
            conn,
            config,
            key,
            _directory: directory,
            fail_next_commit: std::cell::Cell::new(false),
        })
    }

    /// Integrity plus semantic checks, inside one read snapshot. Returns K once its
    /// presence, length and check value are proven (RTC-16).
    fn audit(conn: &Connection, config: &LedgerConfig) -> Result<TokenKey, LedgerError> {
        let application: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application == APPLICATION_ID && version == 1 {
            return Err(LedgerError::Corrupt(
                "this is a schema 1 node ledger, which B7 replaced: settle every Firecracker \
                 session and re-provision it"
                    .into(),
            ));
        }
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
        if node != config.node_id.to_string() {
            return Err(LedgerError::Corrupt(format!(
                "ledger belongs to node {node}"
            )));
        }
        audit_accounts(conn)?;
        let key = audit_token_key(conn, config.node_id)?;
        let generation = generation_of(conn)?;
        // Every stored generation must be behind the counter: a rolled-back counter
        // could otherwise reissue a receipt generation.
        let highest: i64 = conn.query_row(
            "SELECT MAX(g) FROM (
                SELECT MAX(updated_generation) AS g FROM allocations
                UNION ALL SELECT MAX(helper_generation) FROM retired_tokens
                UNION ALL SELECT MAX(operation_generation) FROM worker_intents
                UNION ALL SELECT MAX(generation) FROM stop_events
                UNION ALL SELECT MAX(watermark_generation) FROM instance_tokens
                UNION ALL SELECT MAX(generation) FROM compaction_log
                UNION ALL SELECT MAX(generation) FROM node_faults
                UNION ALL SELECT MAX(generation) FROM node_fault_clears
                UNION ALL SELECT MAX(created_generation) FROM token_key
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
            if decoded.node_id() != config.node_id
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
               NOT EXISTS (SELECT 1 FROM allocation_plans p WHERE p.instance_id = a.instance_id
                           AND p.allocation_id = a.allocation_id)
               OR NOT EXISTS (SELECT 1 FROM capacity_claims c WHERE c.instance_id = a.instance_id
                              AND c.allocation_id = a.allocation_id
                              AND c.released_generation IS NULL)
               OR (SELECT COUNT(*) FROM identity_leases l WHERE l.instance_id = a.instance_id
                   AND l.allocation_id = a.allocation_id
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
             JOIN allocation_plans p ON p.instance_id = a.instance_id
                 AND p.allocation_id = a.allocation_id",
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
        audit_tokens(conn, &key)?;
        Ok(key)
    }

    pub fn node_id(&self) -> Id128 {
        self.config.node_id
    }

    /// K, for L to hand to H over their private channel (RTC-3) and nothing else.
    pub fn token_key(&self) -> &TokenKey {
        &self.key
    }

    pub fn generation(&self) -> Result<u64, LedgerError> {
        generation_of(&self.conn)
    }

    #[cfg(test)]
    pub(super) fn fail_next_commit(&self) {
        self.fail_next_commit.set(true);
    }

    /// Long-history tests only: commits without fsync, so 100,000 executions run in
    /// seconds. Nothing else changes; production always opens FULL-sync.
    #[cfg(test)]
    pub(super) fn test_unsynchronized(&self) {
        self.conn.pragma_update(None, "synchronous", "OFF").unwrap();
    }

    /// The root enrollment command. `limit` comes from the root policy; lowering it
    /// later refuses new enrollments and removes nothing.
    pub fn enroll_instance(
        &mut self,
        enrollment: &Enrollment,
        limit: u32,
    ) -> Result<EnrollOutcome, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let instance = enrollment.instance_id.to_string();
        let exists: i64 = tx
            .prepare_cached("SELECT COUNT(*) FROM instances WHERE instance_id = ?1")?
            .query_row([&instance], |r| r.get(0))?;
        let taken: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM instances
                 WHERE instance_id != ?1 AND (unit = ?2 OR cgroup = ?3)",
            )?
            .query_row(params![instance, enrollment.unit, enrollment.cgroup], |r| {
                r.get(0)
            })?;
        if taken != 0 {
            return Ok(EnrollOutcome::UnitTaken);
        }
        let account_taken: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM instances
                 WHERE instance_id != ?1 AND (uid = ?2 OR gid = ?3)",
            )?
            .query_row(params![instance, enrollment.uid, enrollment.gid], |r| {
                r.get(0)
            })?;
        if account_taken != 0 {
            return Ok(EnrollOutcome::AccountTaken);
        }
        let image = &enrollment.executable;
        let (dev, ino, bytes) = (
            signed(image.st_dev, "st_dev")?,
            signed(image.st_ino, "st_ino")?,
            signed(image.bytes, "bytes")?,
        );
        let generation = if exists == 0 {
            let total: i64 = tx
                .prepare_cached("SELECT COUNT(*) FROM instances")?
                .query_row([], |r| r.get(0))?;
            if unsigned(total)? >= u64::from(limit) {
                return Ok(EnrollOutcome::LimitReached { limit });
            }
            let generation = next_generation(&tx)?;
            tx.prepare_cached(
                "INSERT INTO instances (instance_id, unit, cgroup, uid, gid, exe_st_dev, exe_st_ino,
                    exe_bytes, exe_sha256, first_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?
            .execute(params![
                instance,
                enrollment.unit,
                enrollment.cgroup,
                enrollment.uid,
                enrollment.gid,
                dev,
                ino,
                bytes,
                image.sha256.to_string(),
                signed(generation, "generation")?
            ])?;
            // B7: the instance's exact pointer starts at 1, W at 1 under this generation.
            tx.prepare_cached(
                "INSERT INTO instance_tokens (instance_id, issue_next, watermark,
                    watermark_generation, retained_admitted) VALUES (?1, 1, 1, ?2, 0)",
            )?
            .execute(params![instance, signed(generation, "generation")?])?;
            // RTC-17: within the policy maximum this only gives a reserved slot an owner.
            // Past it, the slots grow and the share shrinks; refuse if that leaves any
            // slot short of its share.
            if Shares::read(&tx, &self.config)?.shortfall() != 0 {
                return Ok(EnrollOutcome::NoSpace);
            }
            EnrollOutcome::Enrolled { generation }
        } else {
            let generation = next_generation(&tx)?;
            tx.prepare_cached(
                "UPDATE instances SET unit = ?2, cgroup = ?3, uid = ?4, gid = ?5, exe_st_dev = ?6,
                    exe_st_ino = ?7, exe_bytes = ?8, exe_sha256 = ?9
                 WHERE instance_id = ?1",
            )?
            .execute(params![
                instance,
                enrollment.unit,
                enrollment.cgroup,
                enrollment.uid,
                enrollment.gid,
                dev,
                ino,
                bytes,
                image.sha256.to_string(),
            ])?;
            EnrollOutcome::Updated { generation }
        };
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// What root enrolled for one instance. L reads this fresh for every attachment.
    pub fn enrollment(&self, instance: Id128) -> Result<Option<Enrollment>, LedgerError> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT unit, cgroup, uid, gid, exe_st_dev, exe_st_ino, exe_bytes, exe_sha256
                 FROM instances WHERE instance_id = ?1",
            )?
            .query_row([instance.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, u32>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .optional()?;
        let Some((unit, cgroup, uid, gid, dev, ino, bytes, sha)) = row else {
            return Ok(None);
        };
        Ok(Some(Enrollment {
            instance_id: instance,
            unit,
            cgroup,
            uid,
            gid,
            executable: EnrolledExecutable {
                st_dev: unsigned(dev)?,
                st_ino: unsigned(ino)?,
                bytes: unsigned(bytes)?,
                sha256: parse_sha(sha)?,
            },
        }))
    }

    /// Every enrollment, for root's upgrade: what to refresh, and what to put back.
    pub fn enrollments(&self) -> Result<Vec<Enrollment>, LedgerError> {
        let mut rows = Vec::new();
        for account in self.enrolled_instances()? {
            rows.extend(self.enrollment(account.instance_id)?);
        }
        Ok(rows)
    }

    /// Replaces the image of every enrolled instance at once, and nothing else about
    /// them. `rows` must name every enrolled instance with its stored unit, cgroup and
    /// account, or nothing changes: an upgrade can't rebind anything, and can't leave
    /// the node half on one image.
    pub fn set_enrolled_images(
        &mut self,
        rows: &[Enrollment],
    ) -> Result<EnrolledImagesOutcome, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let total: i64 = tx
            .prepare_cached("SELECT COUNT(*) FROM instances")?
            .query_row([], |r| r.get(0))?;
        let named: std::collections::BTreeSet<_> = rows.iter().map(|r| r.instance_id).collect();
        if unsigned(total)? != rows.len() as u64 || named.len() != rows.len() {
            return Ok(EnrolledImagesOutcome::IdentityChanged);
        }
        for row in rows {
            let image = &row.executable;
            let changed = tx
                .prepare_cached(
                    "UPDATE instances SET exe_st_dev = ?6, exe_st_ino = ?7, exe_bytes = ?8,
                        exe_sha256 = ?9
                     WHERE instance_id = ?1 AND unit = ?2 AND cgroup = ?3 AND uid = ?4 AND gid = ?5",
                )?
                .execute(params![
                    row.instance_id.to_string(),
                    row.unit,
                    row.cgroup,
                    row.uid,
                    row.gid,
                    signed(image.st_dev, "st_dev")?,
                    signed(image.st_ino, "st_ino")?,
                    signed(image.bytes, "bytes")?,
                    image.sha256.to_string(),
                ])?;
            if changed != 1 {
                return Ok(EnrolledImagesOutcome::IdentityChanged);
            }
        }
        let generation = next_generation(&tx)?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(EnrolledImagesOutcome::Updated {
            generation,
            instances: rows.len(),
        })
    }

    fn enrolled_instances(&self) -> Result<Vec<EnrolledAccount>, LedgerError> {
        let mut statement = self
            .conn
            .prepare_cached("SELECT instance_id, uid, gid FROM instances ORDER BY instance_id")?;
        let mut rows = statement.query([])?;
        let mut enrolled = Vec::new();
        while let Some(row) = rows.next()? {
            enrolled.push(EnrolledAccount {
                instance_id: parse_id(row.get(0)?)?,
                uid: row.get(1)?,
                gid: row.get(2)?,
            });
        }
        Ok(enrolled)
    }

    /// An attested peer's database claim. The UUID identifies reconciliation state and
    /// authorizes nothing. The first attachment records it on the instance's own row,
    /// which is the one write attach can make; every later one writes nothing. A
    /// mismatch is reported and never overwrites: claims stay with that namespace.
    ///
    /// B7 RTC-14: `highest_token` is the daemon's highest recorded complete token. Its
    /// tag is checked in this instance before its seq means anything; only a verified
    /// token at or above the issue pointer is rollback evidence, and that is answered
    /// before any write, so L and H can latch before the fault commits. `latched` is
    /// L's in-memory latch; a first binding is refused under it or any fault row.
    pub fn attach_instance(
        &mut self,
        instance: Id128,
        database_uuid: Id128,
        highest_token: Option<Id128>,
        latched: bool,
    ) -> Result<AttachOutcome, LedgerError> {
        let node_id = self.config.node_id;
        let bound: Option<Option<String>> = self
            .conn
            .prepare_cached("SELECT database_uuid FROM instances WHERE instance_id = ?1")?
            .query_row([instance.to_string()], |r| r.get(0))
            .optional()?;
        let Some(bound) = bound else {
            return Ok(AttachOutcome::NotEnrolled);
        };
        if let Some(token) = highest_token {
            let Some(seq) = self.key.verify(instance, token) else {
                return Ok(AttachOutcome::Malformed);
            };
            let issue_next = self.pointers(instance)?.issue_next;
            if seq >= issue_next {
                return Ok(AttachOutcome::RollbackDetected { token, issue_next });
            }
        }
        match bound {
            Some(existing) if existing == database_uuid.to_string() => Ok(AttachOutcome::Bound {
                node_id,
                generation: self.generation()?,
            }),
            Some(_) => Ok(AttachOutcome::DatabaseMismatch {
                node_id,
                generation: self.generation()?,
            }),
            None => {
                if latched || self.durable_faults()? != 0 {
                    return Ok(AttachOutcome::Latched);
                }
                let tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.prepare_cached(
                    "UPDATE instances SET database_uuid = ?2
                     WHERE instance_id = ?1 AND database_uuid IS NULL",
                )?
                .execute(params![instance.to_string(), database_uuid.to_string()])?;
                commit_tx(tx, &self.fail_next_commit)?;
                Ok(AttachOutcome::Bound {
                    node_id,
                    generation: self.generation()?,
                })
            }
        }
    }

    /// Everything here is keyed by (instance, allocation): the caller's authenticated
    /// instance is the only namespace a token resolves in. Another instance's row with
    /// the same allocation ID is a different token, and this cannot see it.
    ///
    /// B7 (RTC-3, RTC-6): L classifies here, inside the transaction that reads the
    /// token. The tag first (Malformed), then the durable pointer (NotIssued), then the
    /// rows, which always outrank W, then below W (Compacted, synthesized for the
    /// caller's digest), and only then Unknown.
    fn lookup_on(
        conn: &Connection,
        tokens: &TokenKey,
        instance: Id128,
        allocation: Id128,
        plan_digest: &Digest,
    ) -> Result<TokenLookup, LedgerError> {
        let Some(seq) = tokens.verify(instance, allocation) else {
            return Ok(TokenLookup::Malformed);
        };
        let Some(pointers) = pointers_on(conn, instance)? else {
            return Ok(TokenLookup::Malformed);
        };
        if seq >= pointers.issue_next {
            return Ok(TokenLookup::NotIssued);
        }
        let (owner, token) = (instance.to_string(), allocation.to_string());
        let key = [&owner, &token];
        let fence = conn
            .prepare_cached(
                "SELECT plan_digest, receipt FROM retired_tokens
                 WHERE instance_id = ?1 AND allocation_id = ?2",
            )?
            .query_row(key, |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .optional()?;
        if let Some((digest, receipt)) = fence {
            if digest != plan_digest.to_string() {
                return Ok(TokenLookup::Conflict {
                    reason: "token was retired with a different plan".into(),
                });
            }
            return Ok(TokenLookup::Fenced { receipt });
        }
        let active = conn
            .prepare_cached(
                "SELECT plan_digest, phase, updated_generation FROM allocations
                 WHERE instance_id = ?1 AND allocation_id = ?2",
            )?
            .query_row(key, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .optional()?;
        let Some((digest, phase, generation)) = active else {
            if seq < pointers.watermark {
                return Ok(TokenLookup::Compacted {
                    receipt: compacted_receipt(
                        tokens.node_id(),
                        instance,
                        allocation,
                        plan_digest,
                        seq,
                        &pointers,
                    )?,
                });
            }
            return Ok(TokenLookup::Unknown);
        };
        if digest != plan_digest.to_string() {
            return Ok(TokenLookup::Conflict {
                reason: "token is active with a different plan".into(),
            });
        }
        let unsettled: i64 = conn
            .prepare_cached(
                "SELECT COUNT(*) FROM worker_intents
                 WHERE instance_id = ?1 AND allocation_id = ?2 AND settled_generation IS NULL",
            )?
            .query_row(key, |r| r.get(0))?;
        let operation: Option<i64> = conn
            .prepare_cached(
                "SELECT MIN(operation_generation) FROM worker_intents
                 WHERE instance_id = ?1 AND allocation_id = ?2 AND mode = 'supervisor'
                   AND settled_generation IS NULL",
            )?
            .query_row(key, |r| r.get(0))?;
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
        Self::lookup_on(&self.conn, &self.key, instance, allocation, plan_digest)
    }

    /// Inspect, Remove and Gc's lookup (group schema 2): the request carries the plan
    /// digest from the daemon Store's immutable binding. Rows answer when it matches and
    /// Conflict when it does not; a compacted token gets a receipt for that digest.
    pub fn inspect(
        &self,
        instance: Id128,
        allocation: Id128,
        plan_digest: &Digest,
    ) -> Result<TokenLookup, LedgerError> {
        Self::lookup_on(&self.conn, &self.key, instance, allocation, plan_digest)
    }

    /// One instance's pointers, as committed.
    pub fn pointers(&self, instance: Id128) -> Result<TokenPointers, LedgerError> {
        pointers_on(&self.conn, instance)?.ok_or(LedgerError::NoSuchAllocation)
    }

    /// Durable RTC-14 fault rows. Any one latches every forward effect node-wide.
    pub fn durable_faults(&self) -> Result<u64, LedgerError> {
        let count: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM node_faults")?
            .query_row([], |r| r.get(0))?;
        unsigned(count)
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

    /// RTC-17: whether this instance may take one more admitted entry now.
    pub fn admitted_headroom(&self, instance: Id128) -> Result<bool, LedgerError> {
        Ok(Shares::read(&self.conn, &self.config)?.admits(&instance.to_string()))
    }

    /// Whether this instance may still fence a token the ledger never admitted.
    pub fn never_admitted_fence_allowed(&self, instance: Id128) -> Result<bool, LedgerError> {
        let used = never_admitted_fences(&self.conn, instance)?;
        Ok(used < never_admitted_quota(&self.conn, &self.config)?)
    }

    /// New tokens stop while a quarter of the quota remains, for tokens a daemon already
    /// charged at C1. Fences for those keep working up to the quota itself.
    pub fn pre_intent_headroom(&self, instance: Id128) -> Result<bool, LedgerError> {
        let quota = never_admitted_quota(&self.conn, &self.config)?;
        let used = never_admitted_fences(&self.conn, instance)?;
        Ok(used < quota - quota / 4)
    }

    /// Live pages only, (page_count − freelist_count) × page_size: SQLite reuses the
    /// pages compaction frees without shrinking the file (design 16.6).
    fn ledger_bytes(&self) -> Result<u64, LedgerError> {
        let pages: i64 = self
            .conn
            .pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = self
            .conn
            .pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        let size: i64 = self
            .conn
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        unsigned(pages)?
            .saturating_sub(unsigned(free)?)
            .checked_mul(unsigned(size)?)
            .ok_or(LedgerError::Overflow("ledger size"))
    }

    fn over_ledger_space(&self) -> Result<bool, LedgerError> {
        let shared = self.config.shared;
        Ok(self.ledger_bytes()?
            > shared
                .disk_bytes
                .saturating_sub(shared.fence_allowance_bytes))
    }

    /// B7 RTC-4: Preflight's one issuance transaction. It takes the identity snapshot,
    /// checks headroom (RTC-17) and the never-admitted issuance floor (RTC-12), and
    /// raises the exact pointer by one, committed before the token exists outside L.
    /// A refusal writes nothing and consumes no seq. `latched` is L's RTC-14 latch.
    pub fn issue_and_snapshot(
        &mut self,
        instance: Id128,
        latched: bool,
    ) -> Result<IssueOutcome, LedgerError> {
        let refused = |refusal| Ok(IssueOutcome::Refused { refusal });
        let over_space = self.over_ledger_space()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let faults: i64 = tx
            .prepare_cached("SELECT COUNT(*) FROM node_faults")?
            .query_row([], |r| r.get(0))?;
        if latched || faults != 0 {
            return refused(IssueRefusal::Latched);
        }
        let Some(pointers) = pointers_on(&tx, instance)? else {
            return refused(IssueRefusal::NotEnrolled);
        };
        let seq = pointers.issue_next;
        if seq > token::MAX_SEQ {
            return refused(IssueRefusal::Exhausted);
        }
        if over_space {
            return refused(IssueRefusal::LedgerSpace);
        }
        if !Shares::read(&tx, &self.config)?.admits(&instance.to_string()) {
            return refused(IssueRefusal::Headroom);
        }
        let quota = never_admitted_quota(&tx, &self.config)?;
        if never_admitted_fences(&tx, instance)? >= quota - quota / 4 {
            return refused(IssueRefusal::NeverAdmittedFloor);
        }
        let mut claimed = ClaimedIdentities::default();
        {
            let mut statement = tx.prepare_cached(
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
        }
        let changed = tx
            .prepare_cached(
                "UPDATE instance_tokens SET issue_next = ?2 WHERE instance_id = ?1 AND issue_next = ?3",
            )?
            .execute(params![
                instance.to_string(),
                signed(seq + 1, "issue pointer")?,
                signed(seq, "issue pointer")?
            ])?;
        if changed != 1 {
            return Err(LedgerError::StaleGeneration);
        }
        crate::helper::firecracker::workers::fault_point("L.issue.before_commit");
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(IssueOutcome::Issued {
            token: self.key.issue(instance, seq),
            claimed,
        })
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
        let over_space = self.over_ledger_space()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The existing token comes first, before capacity and before any identity.
        match Self::lookup_on(
            &tx,
            &self.key,
            request.instance_id,
            request.allocation_id,
            &request.plan_digest,
        )? {
            TokenLookup::Fenced { receipt } => return Ok(AdmitOutcome::Fenced { receipt }),
            // RTC-7: W passed this rowless token first; it is absent forever.
            TokenLookup::Compacted { receipt } => return Ok(AdmitOutcome::Fenced { receipt }),
            TokenLookup::Conflict { reason } => return Ok(AdmitOutcome::Conflict { reason }),
            TokenLookup::Malformed => {
                return Ok(AdmitOutcome::Conflict {
                    reason: "the token does not verify in this instance".into(),
                });
            }
            TokenLookup::NotIssued => {
                return Ok(AdmitOutcome::Conflict {
                    reason: "the token was never issued".into(),
                });
            }
            TokenLookup::Active {
                generation, phase, ..
            } => {
                let sandbox: String = tx.query_row(
                    "SELECT sandbox_id FROM allocations WHERE instance_id = ?1 AND allocation_id = ?2",
                    [
                        request.instance_id.to_string(),
                        request.allocation_id.to_string(),
                    ],
                    |r| r.get(0),
                )?;
                if sandbox != request.sandbox_id {
                    return Ok(AdmitOutcome::Conflict {
                        reason: "token is active under another sandbox".into(),
                    });
                }
                let (worker_id, operation): (i64, i64) = tx.query_row(
                    "SELECT id, operation_generation FROM worker_intents
                     WHERE instance_id = ?1 AND allocation_id = ?2 AND mode = 'supervisor'
                     ORDER BY id LIMIT 1",
                    [
                        request.instance_id.to_string(),
                        request.allocation_id.to_string(),
                    ],
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
        // Admission follows an attachment, which recorded a database on this row.
        let bound: Option<Option<String>> = tx
            .prepare_cached("SELECT database_uuid FROM instances WHERE instance_id = ?1")?
            .query_row([request.instance_id.to_string()], |r| r.get(0))
            .optional()?;
        if bound.flatten().is_none() {
            return Ok(AdmitOutcome::InstanceMismatch);
        }
        let taken: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM allocations WHERE instance_id = ?1 AND sandbox_id = ?2",
            )?
            .query_row(
                params![request.instance_id.to_string(), request.sandbox_id],
                |r| r.get(0),
            )?;
        if taken != 0 {
            return Ok(AdmitOutcome::Conflict {
                reason: "sandbox ID is bound to another allocation".into(),
            });
        }
        // RTC-17's recheck, inside this transaction: Preflight's was only early.
        if over_space
            || !Shares::read(&tx, &self.config)?.admits(&request.instance_id.to_string())
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
        let instance = request.instance_id.to_string();
        let allocation = request.allocation_id.to_string();
        tx.prepare_cached(
            "INSERT INTO allocations (allocation_id, instance_id, sandbox_id, backend_id,
                plan_version, plan_digest, profile, manifest_sha256, host_spec_sha256,
                guest_exec_spec_sha256, work_uuid, stop_authority, phase,
                created_generation, updated_generation, issue_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'intent', ?13, ?13, ?14)",
        )?
        .execute(params![
            allocation,
            instance,
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
            signed(token::seq_of(request.allocation_id), "issue seq")?,
        ])?;
        tx.prepare_cached(
            "INSERT INTO allocation_plans (instance_id, allocation_id, plan) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![instance, allocation, request.plan])?;
        let r = &request.reservation;
        tx.prepare_cached(
            "INSERT INTO capacity_claims (instance_id, allocation_id, memory_bytes, disk_bytes, pids,
                host_cpu_millis, virtual_cpu_slots, host_pids, claimed_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?
        .execute(params![
            instance,
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
                "INSERT INTO identity_leases (namespace, kind, value, instance_id, allocation_id,
                    claimed_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![
                kind.namespace(),
                kind.as_str(),
                i64::from(value),
                instance,
                allocation,
                generation_i
            ])?;
        }
        for identity in &request.executables {
            tx.prepare_cached(
                "INSERT INTO executable_leases (instance_id, allocation_id, role, st_dev, st_ino, bytes,
                    sha256, installation_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                instance,
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
            Some((request.instance_id, request.allocation_id)),
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
        owner: Option<(Id128, Id128)>,
        spec: &WorkerIntentSpec,
        operation: u64,
    ) -> Result<i64, LedgerError> {
        tx.prepare_cached(
            "INSERT INTO worker_intents (instance_id, allocation_id, mode, operation_generation,
                allowed_names, cgroup, exec_role, exec_st_dev, exec_st_ino, exec_bytes, exec_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?
        .execute(params![
            owner.map(|(instance, _)| instance.to_string()),
            owner.map(|(_, allocation)| allocation.to_string()),
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
        instance: Id128,
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
        let id = Self::insert_worker_intent(&tx, Some((instance, allocation)), spec, operation)?;
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
        instance: Id128,
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
                "UPDATE allocations SET phase = ?3, updated_generation = ?4
                 WHERE instance_id = ?1 AND allocation_id = ?2 AND updated_generation = ?5
                   AND phase != 'absent'",
            )?
            .execute(params![
                instance.to_string(),
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

    /// One owned resource, appended. Refused once the allocation is absent.
    pub fn record_resource(
        &mut self,
        instance: Id128,
        allocation: Id128,
        record: &super::supervisor::ResourceRecord,
    ) -> Result<u64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        let detail =
            serde_json::to_string(record).map_err(|e| LedgerError::Config(e.to_string()))?;
        let changed = tx
            .prepare_cached(
                "UPDATE allocations SET updated_generation = ?3
                 WHERE instance_id = ?1 AND allocation_id = ?2
                   AND phase IN ('preparing','spawn_intent','booting','ready','exec_intent','busy',
                                 'stop_intent','stopped','cleaning')",
            )?
            .execute(params![
                instance.to_string(),
                allocation.to_string(),
                signed(generation, "generation")?
            ])?;
        if changed != 1 {
            return Err(LedgerError::NoSuchAllocation);
        }
        tx.prepare_cached(
            "INSERT INTO resource_events (instance_id, allocation_id, kind, detail, generation)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(params![
            instance.to_string(),
            allocation.to_string(),
            record.kind(),
            detail,
            signed(generation, "generation")?
        ])?;
        if let super::supervisor::ResourceRecord::Exec {
            token,
            execution_id,
            state,
            ..
        } = record
            && EXEC_TERMINAL.contains(&state.as_str())
        {
            Self::compact_exec(&tx, instance, allocation, token, execution_id, state)?;
        }
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// B5-01's retention rule, in the transaction that records an execution's
    /// settlement: one `exec_history` summary (how many executions settled and the
    /// last one's token, ID and state) replaces every `exec` row and the previous
    /// summary. An allocation therefore holds at most the in-flight execution's
    /// `intent` and `busy` rows plus one summary, whatever its history.
    fn compact_exec(
        tx: &Transaction<'_>,
        instance: Id128,
        allocation: Id128,
        token: &str,
        execution_id: &str,
        state: &str,
    ) -> Result<(), LedgerError> {
        let key = [instance.to_string(), allocation.to_string()];
        let previous: Option<String> = tx
            .prepare_cached(
                "SELECT detail FROM resource_events WHERE instance_id = ?1 AND allocation_id = ?2
                   AND kind = 'exec_history' ORDER BY generation DESC LIMIT 1",
            )?
            .query_row(key.clone(), |r| r.get(0))
            .optional()?;
        let (settled, last_token) = match previous {
            Some(detail) => match serde_json::from_str(&detail)
                .map_err(|e| LedgerError::Corrupt(format!("exec history: {e}")))?
            {
                super::supervisor::ResourceRecord::ExecHistory {
                    settled,
                    last_token,
                    ..
                } => (settled, last_token),
                _ => return Err(LedgerError::Corrupt("exec history kind".into())),
            },
            None => (0, String::new()),
        };
        // A second settlement of the same token (`idle`, then `interrupted` when READY
        // could not be journaled) updates the state without counting it twice.
        let settled = if last_token == token {
            settled
        } else {
            settled
                .checked_add(1)
                .ok_or(LedgerError::Overflow("settled executions"))?
        };
        let summary = super::supervisor::ResourceRecord::ExecHistory {
            settled,
            last_token: token.into(),
            last_execution_id: execution_id.into(),
            last_state: state.into(),
        };
        let generation = next_generation(tx)?;
        let detail =
            serde_json::to_string(&summary).map_err(|e| LedgerError::Config(e.to_string()))?;
        tx.prepare_cached(
            "INSERT INTO resource_events (instance_id, allocation_id, kind, detail, generation)
             VALUES (?1, ?2, 'exec_history', ?3, ?4)",
        )?
        .execute(params![
            instance.to_string(),
            allocation.to_string(),
            detail,
            signed(generation, "generation")?
        ])?;
        tx.prepare_cached(
            "UPDATE allocations SET updated_generation = ?3
             WHERE instance_id = ?1 AND allocation_id = ?2",
        )?
        .execute(params![
            instance.to_string(),
            allocation.to_string(),
            signed(generation, "generation")?
        ])?;
        tx.prepare_cached(
            "DELETE FROM resource_events WHERE instance_id = ?1 AND allocation_id = ?2
               AND kind IN ('exec','exec_history') AND generation < ?3",
        )?
        .execute(params![
            instance.to_string(),
            allocation.to_string(),
            signed(generation, "generation")?
        ])?;
        Ok(())
    }

    /// A conditional phase change: only from one of `from`, never out of `absent`.
    pub fn set_phase(
        &mut self,
        instance: Id128,
        allocation: Id128,
        from: &[String],
        to: &str,
    ) -> Result<u64, LedgerError> {
        if to == "absent" || from.iter().any(|f| f == "absent") || from.is_empty() {
            return Err(LedgerError::Config(
                "absence is committed only by a fence".into(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<String> = tx
            .prepare_cached(
                "SELECT phase FROM allocations WHERE instance_id = ?1 AND allocation_id = ?2",
            )?
            .query_row([instance.to_string(), allocation.to_string()], |r| r.get(0))
            .optional()?;
        let Some(current) = current else {
            return Err(LedgerError::NoSuchAllocation);
        };
        if !from.contains(&current) {
            return Err(LedgerError::StaleGeneration);
        }
        let generation = next_generation(&tx)?;
        tx.prepare_cached(
            "UPDATE allocations SET phase = ?3, updated_generation = ?4
             WHERE instance_id = ?1 AND allocation_id = ?2",
        )?
        .execute(params![
            instance.to_string(),
            allocation.to_string(),
            to,
            signed(generation, "generation")?
        ])?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// Everything cleanup needs for one active allocation: its plan, identity and every
    /// recorded resource, in order.
    pub fn allocation_state(
        &self,
        instance: Id128,
        allocation: Id128,
    ) -> Result<Option<AllocationState>, LedgerError> {
        let key = [instance.to_string(), allocation.to_string()];
        let row = self
            .conn
            .prepare_cached(
                "SELECT a.sandbox_id, a.plan_digest, a.phase, a.created_generation, p.plan
                 FROM allocations a JOIN allocation_plans p
                   ON p.instance_id = a.instance_id AND p.allocation_id = a.allocation_id
                 WHERE a.instance_id = ?1 AND a.allocation_id = ?2",
            )?
            .query_row(key.clone(), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })
            .optional()?;
        let Some((sandbox_id, digest, phase, created, plan)) = row else {
            return Ok(None);
        };
        // Defense in depth for B5-01: only execution rows newer than the latest summary
        // (the in-flight execution's), whatever compaction left behind.
        let mut statement = self.conn.prepare_cached(
            "SELECT detail FROM resource_events WHERE instance_id = ?1 AND allocation_id = ?2
               AND (kind NOT IN ('exec','exec_history')
                    OR generation >= COALESCE((SELECT MAX(generation) FROM resource_events
                        WHERE instance_id = ?1 AND allocation_id = ?2
                          AND kind = 'exec_history'), 0))
             ORDER BY generation",
        )?;
        let mut rows = statement.query(key)?;
        let mut resources = Vec::new();
        while let Some(row) = rows.next()? {
            let detail: String = row.get(0)?;
            resources.push(
                serde_json::from_str(&detail)
                    .map_err(|e| LedgerError::Corrupt(format!("resource record: {e}")))?,
            );
        }
        Ok(Some(AllocationState {
            sandbox_id,
            plan_digest: parse_sha(digest)?,
            phase,
            created_generation: unsigned(created)?,
            plan,
            resources,
        }))
    }

    /// A cleanup worker's intent for one allocation, journaled before it is forked.
    pub fn record_allocation_worker_intent(
        &mut self,
        instance: Id128,
        allocation: Id128,
        spec: &WorkerIntentSpec,
    ) -> Result<(i64, u64), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let phase: Option<String> = tx
            .prepare_cached(
                "SELECT phase FROM allocations WHERE instance_id = ?1 AND allocation_id = ?2",
            )?
            .query_row([instance.to_string(), allocation.to_string()], |r| r.get(0))
            .optional()?;
        if phase.is_none() || phase.as_deref() == Some("absent") {
            return Err(LedgerError::NoSuchAllocation);
        }
        let operation = next_generation(&tx)?;
        let id = Self::insert_worker_intent(&tx, Some((instance, allocation)), spec, operation)?;
        // Each cleanup attempt adds a row; settlement compacts (B5-01, B5-R2).
        Self::compact_settled_workers(
            &tx,
            &instance.to_string(),
            &allocation.to_string(),
            &spec.mode,
        )?;
        commit_tx(tx, &self.fail_next_commit)?;
        Ok((id, operation))
    }

    /// Keeps exactly the newest eight settled rows of one allocation's worker mode
    /// (section 7.4). It runs where a row becomes settled as well as on insert, so a
    /// row settling after its successor was journaled can't leave a ninth (B5-R2).
    /// `worker_intents_no_delete` permits exactly these deletions; unsettled and
    /// node-level rows are never touched.
    fn compact_settled_workers(
        tx: &rusqlite::Transaction<'_>,
        instance: &str,
        allocation: &str,
        mode: &str,
    ) -> Result<(), LedgerError> {
        tx.prepare_cached(
            "DELETE FROM worker_intents WHERE instance_id = ?1 AND allocation_id = ?2
               AND mode = ?3 AND settled_generation IS NOT NULL
               AND id NOT IN (SELECT id FROM worker_intents WHERE instance_id = ?1
                   AND allocation_id = ?2 AND mode = ?3 AND settled_generation IS NOT NULL
                   ORDER BY id DESC LIMIT ?4)",
        )?
        .execute(params![instance, allocation, mode, SETTLED_WORKERS_KEPT])?;
        Ok(())
    }

    /// The later durable record of a stop: an emergency already ran under C2's
    /// authority if the writer was blocked. It never releases anything.
    pub fn record_stop(
        &mut self,
        instance: Id128,
        allocation: Id128,
        reason: &str,
    ) -> Result<u64, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        let changed = tx
            .prepare_cached(
                "UPDATE allocations SET phase = 'stop_intent', updated_generation = ?3
                 WHERE instance_id = ?1 AND allocation_id = ?2 AND phase != 'absent'",
            )?
            .execute(params![
                instance.to_string(),
                allocation.to_string(),
                signed(generation, "generation")?
            ])?;
        if changed != 1 {
            return Err(LedgerError::NoSuchAllocation);
        }
        // Each Stop or Remove attempt may record a reason; the first sixteen are kept
        // and later stops only move the phase (B5-01).
        let recorded: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM stop_events WHERE instance_id = ?1 AND allocation_id = ?2",
            )?
            .query_row([instance.to_string(), allocation.to_string()], |r| r.get(0))?;
        if recorded < STOP_REASONS_KEPT {
            tx.prepare_cached(
                "INSERT INTO stop_events (instance_id, allocation_id, generation, reason)
                 VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![
                instance.to_string(),
                allocation.to_string(),
                signed(generation, "generation")?,
                reason
            ])?;
        }
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// The tuple that actually ran, read from the running process's image, attached to
    /// its lease. A mismatch is refused here as well as at the dispatch point; nothing
    /// may launder a different identity.
    pub fn record_observed_executable(
        &mut self,
        instance: Id128,
        allocation: Id128,
        actual: &ExecutableIdentity,
    ) -> Result<(), LedgerError> {
        self.record_executable_evidence(instance, allocation, actual, "proc_exe")
    }

    /// The retained descriptor's verified tuple, inferred as what ran from a confirmed
    /// `execveat` of exactly that descriptor, and recorded as such: never as observed.
    pub fn record_inferred_executable(
        &mut self,
        instance: Id128,
        allocation: Id128,
        inferred: &ExecutableIdentity,
    ) -> Result<(), LedgerError> {
        self.record_executable_evidence(instance, allocation, inferred, "retained_fd")
    }

    fn record_executable_evidence(
        &mut self,
        instance: Id128,
        allocation: Id128,
        actual: &ExecutableIdentity,
        observation: &str,
    ) -> Result<(), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx
            .prepare_cached(
                "UPDATE executable_leases
                 SET observed_st_dev = ?4, observed_st_ino = ?5, observed_bytes = ?6,
                     observed_sha256 = ?7, observation = ?9
                 WHERE instance_id = ?1 AND allocation_id = ?2 AND role = ?3 AND st_dev = ?4
                   AND st_ino = ?5 AND bytes = ?6 AND sha256 = ?7 AND installation_generation = ?8",
            )?
            .execute(params![
                instance.to_string(),
                allocation.to_string(),
                actual.role.as_str(),
                signed(actual.st_dev, "device")?,
                signed(actual.st_ino, "inode")?,
                signed(actual.bytes, "size")?,
                actual.sha256.to_string(),
                signed(actual.installation_generation, "installation generation")?,
                observation,
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
        let settled = tx
            .prepare_cached(
                "UPDATE worker_intents SET settled_generation = ?2, settlement = ?3
                 WHERE id = ?1 AND settled_generation IS NULL",
            )?
            .execute(params![
                worker_id,
                signed(generation, "generation")?,
                settlement
            ])?;
        if settled == 1 {
            let owner: Option<(Option<String>, Option<String>, String)> = tx
                .prepare_cached(
                    "SELECT instance_id, allocation_id, mode FROM worker_intents WHERE id = ?1",
                )?
                .query_row([worker_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?;
            if let Some((Some(instance), Some(allocation), mode)) = owner {
                Self::compact_settled_workers(&tx, &instance, &allocation, &mode)?;
            }
        }
        commit_tx(tx, &self.fail_next_commit)
    }

    /// Rows with no recorded identity never had an open gate: S's gate opens only after
    /// that record. These can settle once no process with a permit could exist.
    pub fn settle_unstarted(
        &mut self,
        instance: Id128,
        allocation: Id128,
    ) -> Result<(), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let generation = next_generation(&tx)?;
        tx.prepare_cached(
            "UPDATE worker_intents SET settled_generation = ?3, settlement = 'never-started'
             WHERE instance_id = ?1 AND allocation_id = ?2 AND pid IS NULL
               AND settled_generation IS NULL",
        )?
        .execute(params![
            instance.to_string(),
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
            &self.key,
            request.instance_id,
            request.allocation_id,
            &request.plan_digest,
        )? {
            TokenLookup::Fenced { receipt } | TokenLookup::Compacted { receipt } => {
                return Ok(FenceOutcome::Absent {
                    receipt,
                    replay: true,
                });
            }
            TokenLookup::Conflict { reason } => return Ok(FenceOutcome::Conflict { reason }),
            TokenLookup::Malformed => {
                return Ok(FenceOutcome::Conflict {
                    reason: "the token does not verify in this instance".into(),
                });
            }
            TokenLookup::NotIssued => {
                return Ok(FenceOutcome::Conflict {
                    reason: "the token was never issued".into(),
                });
            }
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
                    "SELECT sandbox_id FROM allocations WHERE instance_id = ?1 AND allocation_id = ?2",
                    [
                        request.instance_id.to_string(),
                        request.allocation_id.to_string(),
                    ],
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
                // Inside this transaction, so racing fences can't pass it together.
                let quota = never_admitted_quota(&tx, &self.config)?;
                if never_admitted_fences(&tx, request.instance_id)? >= quota {
                    return Ok(FenceOutcome::QuotaExhausted { quota });
                }
            }
        }
        let generation = next_generation(&tx)?;
        let generation_i = signed(generation, "generation")?;
        let instance = request.instance_id.to_string();
        let allocation = request.allocation_id.to_string();
        tx.prepare_cached(
            "UPDATE capacity_claims SET released_generation = ?3
             WHERE instance_id = ?1 AND allocation_id = ?2 AND released_generation IS NULL",
        )?
        .execute(params![instance, allocation, generation_i])?;
        tx.prepare_cached(
            "UPDATE identity_leases SET released_generation = ?3
             WHERE instance_id = ?1 AND allocation_id = ?2 AND released_generation IS NULL",
        )?
        .execute(params![instance, allocation, generation_i])?;
        tx.prepare_cached(
            "UPDATE executable_leases SET released_generation = ?3
             WHERE instance_id = ?1 AND allocation_id = ?2 AND released_generation IS NULL",
        )?
        .execute(params![instance, allocation, generation_i])?;
        tx.prepare_cached(
            "UPDATE allocations SET phase = 'absent', updated_generation = ?3
             WHERE instance_id = ?1 AND allocation_id = ?2",
        )?
        .execute(params![instance, allocation, generation_i])?;
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
                receipt_id, helper_generation, receipt, issue_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            allocation,
            instance,
            request.sandbox_id,
            request.plan_digest.to_string(),
            receipt_id.to_string(),
            generation_i,
            receipt,
            signed(token::seq_of(request.allocation_id), "issue seq")?,
        ])?;
        tx.prepare_cached(
            "DELETE FROM allocation_plans WHERE instance_id = ?1 AND allocation_id = ?2",
        )?
        .execute([&instance, &allocation])?;
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

    /// Node totals with once-only shared reserves; no session identities. `instance`
    /// is the authenticated caller: only its own token figures appear (RTC-16).
    pub fn accounting(&self, instance: Option<Id128>) -> Result<AccountingSnapshot, LedgerError> {
        let claimed = claim_totals(&self.conn)?;
        let committed = claimed.with_shared(&self.config.shared)?;
        let retired: i64 = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM retired_tokens")?
            .query_row([], |r| r.get(0))?;
        let never_admitted_total: i64 = self
            .conn
            .prepare_cached(
                "SELECT COUNT(*) FROM retired_tokens r WHERE NOT EXISTS
                    (SELECT 1 FROM allocations a WHERE a.instance_id = r.instance_id
                        AND a.allocation_id = r.allocation_id)",
            )?
            .query_row([], |r| r.get(0))?;
        let shares = Shares::read(&self.conn, &self.config)?;
        let mut degraded = None;
        let tokens = match instance.map(|i| (i, pointers_on(&self.conn, i))) {
            Some((instance, pointers)) => match pointers? {
                Some(pointers) => {
                    let pinned: i64 = self
                        .conn
                        .prepare_cached(
                            "SELECT COUNT(*) FROM allocations WHERE instance_id = ?1
                               AND phase != 'absent' AND issue_seq < ?2",
                        )?
                        .query_row(
                            params![
                                instance.to_string(),
                                signed(pointers.watermark, "watermark")?
                            ],
                            |r| r.get(0),
                        )?;
                    let ceiling = shares.share
                        + shares
                            .entries
                            .saturating_sub(shares.slots.saturating_mul(shares.share));
                    if pointers.issue_next > token::MAX_SEQ {
                        degraded = Some(
                            "this instance's issue sequence is exhausted: Preflight refuses"
                                .to_string(),
                        );
                    } else if pointers.retained_admitted.saturating_mul(4)
                        > ceiling.saturating_mul(3)
                    {
                        degraded = Some(format!(
                            "retained admitted rows {} of {ceiling}: under 25% headroom left",
                            pointers.retained_admitted
                        ));
                    }
                    Some(TokenAccounting {
                        issue_next: pointers.issue_next,
                        watermark: pointers.watermark,
                        watermark_generation: pointers.watermark_generation,
                        retained_admitted: pointers.retained_admitted,
                        retained_never_admitted: never_admitted_fences(&self.conn, instance)?,
                        reserved_share: shares.share,
                        pinned_below_watermark: unsigned(pinned)?,
                        checkpoints: 0,
                        compaction_lag_ms: 0,
                    })
                }
                None => None,
            },
            None => None,
        };
        let shortfall = shares.shortfall();
        if shortfall != 0 {
            degraded = Some(format!(
                "a policy change left {shortfall} retained rows above the reserved shares"
            ));
        }
        let node_fault = (self.durable_faults()? != 0).then(|| "rollback".to_string());
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
            tokens,
            retained_admitted_total: shares.total(),
            retained_never_admitted_total: unsigned(never_admitted_total)?,
            admitted_entries: shares.entries,
            share: shares.share,
            share_shortfall: shortfall,
            node_fault,
            degraded,
        })
    }

    /// One namespace's active allocations, read from one snapshot.
    pub fn inventory(&self, instance: Id128) -> Result<InventorySnapshot, LedgerError> {
        let mut statement = self.conn.prepare_cached(
            "SELECT a.allocation_id, a.plan_digest, a.phase, a.updated_generation,
                (SELECT COUNT(*) FROM worker_intents w WHERE w.instance_id = a.instance_id
                    AND w.allocation_id = a.allocation_id AND w.settled_generation IS NULL)
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
                (SELECT COUNT(*) FROM worker_intents w WHERE w.instance_id = a.instance_id
                    AND w.allocation_id = a.allocation_id AND w.settled_generation IS NULL)
             FROM allocations a WHERE a.phase != 'absent' ORDER BY a.instance_id, a.allocation_id",
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
            "SELECT id, instance_id, allocation_id, mode, operation_generation, pid, start_time,
                host_boot_id
             FROM worker_intents WHERE settled_generation IS NULL ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        let mut unsettled_workers = Vec::new();
        while let Some(row) = rows.next()? {
            unsettled_workers.push(WorkerRecord {
                worker_id: row.get(0)?,
                instance_id: row.get::<_, Option<String>>(1)?.map(parse_id).transpose()?,
                allocation_id: row.get::<_, Option<String>>(2)?.map(parse_id).transpose()?,
                mode: row.get(3)?,
                operation_generation: unsigned(row.get(4)?)?,
                pid: row.get(5)?,
                start_time: row.get::<_, Option<i64>>(6)?.map(unsigned).transpose()?,
                host_boot_id: row.get(7)?,
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
        let mut statement = self
            .conn
            .prepare("SELECT kind FROM node_faults ORDER BY generation")?;
        let node_faults = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ReplaySnapshot {
            generation: self.generation()?,
            node_faults,
            enrolled: self.enrolled_instances()?,
            active_allocations,
            unsettled_workers,
            executable_leases,
        })
    }

    /// The newest compaction record of one instance, for `ledger-stats`.
    pub fn last_compaction(&self, instance: Id128) -> Result<Option<serde_json::Value>, LedgerError> {
        let row: Option<(i64, i64, i64, i64, i64)> = self
            .conn
            .prepare_cached(
                "SELECT from_w, to_w, generation, tokens_deleted, rows_deleted FROM compaction_log
                 WHERE instance_id = ?1 ORDER BY generation DESC LIMIT 1",
            )?
            .query_row([instance.to_string()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .optional()?;
        Ok(row.map(|(from, to, generation, tokens, rows)| {
            serde_json::json!({
                "from_w": from, "to_w": to, "generation": generation,
                "tokens_deleted": tokens, "rows_deleted": rows,
            })
        }))
    }

    /// Every enrolled instance, for the compactor and the offline commands.
    pub fn instance_ids(&self) -> Result<Vec<Id128>, LedgerError> {
        Ok(self
            .enrolled_instances()?
            .into_iter()
            .map(|account| account.instance_id)
            .collect())
    }

    /// B7 RTC-5 and RTC-9: raises W toward `target` (never past the pointer, never
    /// down), with a fresh G_W, in its own FULL-sync transaction. With W unchanged it
    /// still takes a fresh G_W when a pinned allocation was fenced at or after the last
    /// one, so nothing is compacted until a synthesized receipt would be newer than every
    /// generation the token was ever reported with. Nothing else writes W.
    pub fn advance_watermark(
        &mut self,
        instance: Id128,
        target: u64,
    ) -> Result<Option<Advance>, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pointers = pointers_on(&tx, instance)?.ok_or(LedgerError::NoSuchAllocation)?;
        let to = target.max(pointers.watermark).min(pointers.issue_next);
        let late: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM retired_tokens WHERE instance_id = ?1 AND issue_seq < ?2
                   AND helper_generation >= ?3",
            )?
            .query_row(
                params![
                    instance.to_string(),
                    signed(pointers.watermark, "watermark")?,
                    signed(pointers.watermark_generation, "generation")?
                ],
                |r| r.get(0),
            )?;
        if to == pointers.watermark && late == 0 {
            return Ok(None);
        }
        let generation = next_generation(&tx)?;
        let changed = tx
            .prepare_cached(
                "UPDATE instance_tokens SET watermark = ?2, watermark_generation = ?3
                 WHERE instance_id = ?1 AND watermark = ?4",
            )?
            .execute(params![
                instance.to_string(),
                signed(to, "watermark")?,
                signed(generation, "generation")?,
                signed(pointers.watermark, "watermark")?
            ])?;
        if changed != 1 {
            return Err(LedgerError::StaleGeneration);
        }
        tx.prepare_cached(
            "INSERT INTO compaction_log (instance_id, from_w, to_w, generation, tokens_deleted,
                rows_deleted) VALUES (?1, ?2, ?3, ?4, 0, 0)",
        )?
        .execute(params![
            instance.to_string(),
            signed(pointers.watermark, "watermark")?,
            signed(to, "watermark")?,
            signed(generation, "generation")?
        ])?;
        tx.prepare_cached(
            "DELETE FROM compaction_log WHERE instance_id = ?1 AND id NOT IN
                (SELECT id FROM compaction_log WHERE instance_id = ?1
                 ORDER BY generation DESC LIMIT ?2)",
        )?
        .execute(params![instance.to_string(), COMPACTION_LOG_KEPT])?;
        crate::helper::firecracker::workers::fault_point("L.compact.advance.before_commit");
        commit_tx(tx, &self.fail_next_commit)?;
        crate::helper::firecracker::workers::fault_point("L.compact.advance.after_commit");
        Ok(Some(Advance {
            from: pointers.watermark,
            to,
            generation,
        }))
    }

    /// B7 RTC-10 and RTC-11: deletes up to `max_tokens` compactable tokens' rows in one
    /// FULL-sync transaction: children first, then the allocation, then the fence row.
    /// Only tokens below W whose fence generation is below G_W and whose allocation, if
    /// any, is absent with every claim, lease and worker released or settled; the
    /// triggers enforce each condition again. Ledger SQL only: no host action.
    pub fn compact_batch(
        &mut self,
        instance: Id128,
        max_tokens: u64,
    ) -> Result<CompactBatch, LedgerError> {
        use crate::helper::firecracker::workers::{fault_enabled, fault_point};
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pointers = pointers_on(&tx, instance)?.ok_or(LedgerError::NoSuchAllocation)?;
        let owner = instance.to_string();
        let (w, g) = (
            signed(pointers.watermark, "watermark")?,
            signed(pointers.watermark_generation, "generation")?,
        );
        const COMPACTABLE: &str = "NOT EXISTS (SELECT 1 FROM allocations a
                WHERE a.instance_id = r.instance_id AND a.allocation_id = r.allocation_id)
            OR EXISTS (SELECT 1 FROM allocations a
                WHERE a.instance_id = r.instance_id AND a.allocation_id = r.allocation_id
                  AND a.phase = 'absent'
                  AND NOT EXISTS (SELECT 1 FROM capacity_claims c WHERE c.instance_id = a.instance_id
                      AND c.allocation_id = a.allocation_id AND c.released_generation IS NULL)
                  AND NOT EXISTS (SELECT 1 FROM identity_leases l WHERE l.instance_id = a.instance_id
                      AND l.allocation_id = a.allocation_id AND l.released_generation IS NULL)
                  AND NOT EXISTS (SELECT 1 FROM executable_leases e WHERE e.instance_id = a.instance_id
                      AND e.allocation_id = a.allocation_id AND e.released_generation IS NULL)
                  AND NOT EXISTS (SELECT 1 FROM worker_intents w WHERE w.instance_id = a.instance_id
                      AND w.allocation_id = a.allocation_id AND w.settled_generation IS NULL))";
        let candidates: Vec<(String, bool)> = {
            let mut statement = tx.prepare_cached(&format!(
                "SELECT r.allocation_id, EXISTS (SELECT 1 FROM allocations a
                        WHERE a.instance_id = r.instance_id AND a.allocation_id = r.allocation_id)
                 FROM retired_tokens r
                 WHERE r.instance_id = ?1 AND r.issue_seq < ?2 AND r.helper_generation < ?3
                   AND ({COMPACTABLE})
                 ORDER BY r.issue_seq LIMIT ?4"
            ))?;
            statement
                .query_map(
                    params![owner, w, g, signed(max_tokens, "batch")? + 1],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?
                .collect::<Result<_, _>>()?
        };
        let more = candidates.len() as u64 > max_tokens;
        let mut batch = CompactBatch {
            more,
            ..CompactBatch::default()
        };
        for (allocation, admitted) in candidates.into_iter().take(max_tokens as usize) {
            let key = params![owner, allocation];
            if admitted {
                for family in [
                    "resource_events",
                    "stop_events",
                    "worker_intents",
                    "executable_leases",
                    "identity_leases",
                    "capacity_claims",
                    "allocation_plans",
                ] {
                    batch.rows_deleted += tx
                        .prepare_cached(&format!(
                            "DELETE FROM {family} WHERE instance_id = ?1 AND allocation_id = ?2"
                        ))?
                        .execute(key)? as u64;
                    fault_point(&format!("L.compact.delete.after_{family}"));
                }
                batch.rows_deleted += tx
                    .prepare_cached(
                        "DELETE FROM allocations WHERE instance_id = ?1 AND allocation_id = ?2",
                    )?
                    .execute(key)? as u64;
                fault_point("L.compact.delete.after_allocation");
            }
            let fences = tx
                .prepare_cached(
                    "DELETE FROM retired_tokens WHERE instance_id = ?1 AND allocation_id = ?2",
                )?
                .execute(key)? as u64;
            fault_point("L.compact.delete.after_fence");
            batch.rows_deleted += fences;
            batch.tokens_deleted += fences;
        }
        {
            let mut statement = tx.prepare_cached(&format!(
                "SELECT r.allocation_id FROM retired_tokens r
                 WHERE r.instance_id = ?1 AND r.issue_seq < ?2 AND r.helper_generation < ?3
                   AND NOT ({COMPACTABLE})
                 ORDER BY r.issue_seq LIMIT 8"
            ))?;
            let stuck = statement
                .query_map(params![owner, w, g], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            batch.stuck = stuck.into_iter().map(parse_id).collect::<Result<_, _>>()?;
        }
        if batch.tokens_deleted != 0 {
            tx.prepare_cached(
                "UPDATE compaction_log SET tokens_deleted = tokens_deleted + ?2,
                    rows_deleted = rows_deleted + ?3
                 WHERE id = (SELECT id FROM compaction_log WHERE instance_id = ?1
                             ORDER BY generation DESC LIMIT 1)",
            )?
            .execute(params![
                owner,
                signed(batch.tokens_deleted, "tokens")?,
                signed(batch.rows_deleted, "rows")?
            ])?;
        }
        if fault_enabled("L.compact.sync_fail") {
            drop(tx);
            return Err(LedgerError::CommitFailed);
        }
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(batch)
    }

    /// B7 RTC-14: commits a rollback fault, idempotently keyed by instance and token, so
    /// a replacement L replaying H's pending fault writes it at most once.
    pub fn commit_fault(
        &mut self,
        instance: Id128,
        token: Id128,
        issue_next_seen: u64,
    ) -> Result<u64, LedgerError> {
        use crate::helper::firecracker::workers::{fault_enabled, fault_point};
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<i64> = tx
            .prepare_cached(
                "SELECT generation FROM node_faults
                 WHERE kind = 'rollback' AND instance_id = ?1 AND token = ?2",
            )?
            .query_row([instance.to_string(), token.to_string()], |r| r.get(0))
            .optional()?;
        if let Some(generation) = existing {
            return unsigned(generation);
        }
        let generation = next_generation(&tx)?;
        tx.prepare_cached(
            "INSERT INTO node_faults (generation, kind, instance_id, token, issue_next_seen, detail)
             VALUES (?1, 'rollback', ?2, ?3, ?4, ?5)",
        )?
        .execute(params![
            signed(generation, "generation")?,
            instance.to_string(),
            token.to_string(),
            signed(issue_next_seen.max(1), "issue pointer")?,
            "a verified token at or above the issue pointer: the ledger is behind",
        ])?;
        fault_point("L.fault.before_commit");
        if fault_enabled("L.fault.sync_fail") {
            drop(tx);
            return Err(LedgerError::CommitFailed);
        }
        commit_tx(tx, &self.fail_next_commit)?;
        Ok(generation)
    }

    /// Every durable fault, for the offline inventory: (generation, kind, instance, token).
    pub fn faults(&self) -> Result<Vec<(u64, String, Id128, Id128)>, LedgerError> {
        let mut statement = self.conn.prepare(
            "SELECT generation, kind, instance_id, token FROM node_faults ORDER BY generation",
        )?;
        let mut rows = statement.query([])?;
        let mut faults = Vec::new();
        while let Some(row) = rows.next()? {
            faults.push((
                unsigned(row.get(0)?)?,
                row.get(1)?,
                parse_id(row.get(2)?)?,
                parse_id(row.get(3)?)?,
            ));
        }
        Ok(faults)
    }

    /// B7 RTC-14's single exception to insert-only faults, for root's offline clear
    /// (design 16.6). One FULL-sync transaction: nothing may have moved since the
    /// inventory (`ledger_generation` and the fault set), each pointer is raised past
    /// the daemon's highest verified token and never lowered, W is untouched, the clear
    /// row is written, and only then can the trigger allow the fault rows' deletion.
    pub fn clear_node_faults(
        &mut self,
        ledger_generation: u64,
        fault_generations: &[u64],
        highest: &[(Id128, Option<Id128>)],
        inventory_sha256: Digest,
    ) -> Result<ClearOutcome, LedgerError> {
        use rusqlite::functions::FunctionFlags;
        self.conn.create_scalar_function(
            "kilnd_offline_fault_clear",
            0,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(1i64),
        )?;
        let outcome = self.clear_in_transaction(
            ledger_generation,
            fault_generations,
            highest,
            inventory_sha256,
        );
        let _ = self
            .conn
            .remove_function("kilnd_offline_fault_clear", 0);
        outcome
    }

    fn clear_in_transaction(
        &mut self,
        ledger_generation: u64,
        fault_generations: &[u64],
        highest: &[(Id128, Option<Id128>)],
        inventory_sha256: Digest,
    ) -> Result<ClearOutcome, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if generation_of(&tx)? != ledger_generation {
            return Ok(ClearOutcome::Stale);
        }
        let present: Vec<u64> = {
            let mut statement =
                tx.prepare("SELECT generation FROM node_faults ORDER BY generation")?;
            statement
                .query_map([], |r| r.get::<_, i64>(0))?
                .map(|g| g.map_err(LedgerError::from).and_then(unsigned))
                .collect::<Result<_, _>>()?
        };
        let mut named = fault_generations.to_vec();
        named.sort_unstable();
        if named != present {
            return Ok(ClearOutcome::Stale);
        }
        let mut raised = Vec::new();
        for (instance, token) in highest {
            let pointers = pointers_on(&tx, *instance)?.ok_or(LedgerError::NoSuchAllocation)?;
            let floor = match token {
                None => 0,
                Some(token) => match self.key.verify(*instance, *token) {
                    Some(seq) => seq + 1,
                    None => return Ok(ClearOutcome::Malformed { instance: *instance }),
                },
            };
            let next = pointers.issue_next.max(floor);
            if next > token::POINTER_CEILING {
                return Ok(ClearOutcome::Malformed { instance: *instance });
            }
            if next != pointers.issue_next {
                tx.prepare_cached(
                    "UPDATE instance_tokens SET issue_next = ?2 WHERE instance_id = ?1",
                )?
                .execute(params![instance.to_string(), signed(next, "issue pointer")?])?;
            }
            raised.push(serde_json::json!({
                "instance_id": instance.to_string(),
                "from": pointers.issue_next,
                "to": next,
            }));
        }
        let generation = next_generation(&tx)?;
        let through = present.last().copied().unwrap_or(0);
        tx.execute(
            "INSERT INTO node_fault_clears (generation, cleared_through_generation,
                inventory_sha256, raised_pointers) VALUES (?1, ?2, ?3, ?4)",
            params![
                signed(generation, "generation")?,
                signed(through, "generation")?,
                inventory_sha256.to_string(),
                serde_json::Value::Array(raised.clone()).to_string(),
            ],
        )?;
        tx.execute(
            "DELETE FROM node_faults WHERE generation <= ?1",
            [signed(through, "generation")?],
        )?;
        crate::helper::firecracker::workers::fault_point("clear.before_commit");
        commit_tx(tx, &self.fail_next_commit)?;
        crate::helper::firecracker::workers::fault_point("clear.after_commit");
        Ok(ClearOutcome::Cleared {
            generation,
            cleared_through: through,
            raised: serde_json::Value::Array(raised).to_string(),
        })
    }

    /// Test access to the plan bytes for the replay checks.
    #[cfg(test)]
    pub(super) fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// The offline clear's result. Anything but `Cleared` changed nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClearOutcome {
    Cleared {
        generation: u64,
        cleared_through: u64,
        raised: String,
    },
    /// The ledger moved since the inventory: its generation or fault set differs.
    Stale,
    /// A reported highest token does not verify for its instance.
    Malformed { instance: Id128 },
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

#[cfg(test)]
mod b7_tests;
