//! SQLite state: one row per sandbox and per execution. kilnd is the only
//! writer; the database lives in a kilnd-owned private directory.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use crate::expiry::{Clock, ClockReading, RENEW_COALESCE_MS};
use crate::lock::ExclusiveFileLock;
use crate::model::{
    AccountingRegime, AllocationBinding, CancelReason, Captured, CleanupEvidence, CommandStatus,
    CreateCertainty, DeletionReason, Digest, Execution, ExecutionState, ExpiryPolicy, Id128,
    LegacyRelease, ReservationRelease, ResourceReservation, RuntimeDiagnostic, RuntimeErrorKind,
    RuntimeStage, Sandbox, SandboxAccounting, SandboxDisposition, SandboxLifecycle, SandboxSpec,
    SandboxState, now_ms,
};
use crate::retention::{OutputStorage, Pruned, Retention};
use crate::runtime::{CreatedSandbox, FencedAbsence, RuntimeReceipt};

const SCHEMA_VERSION: i64 = 14;

const MIGRATE_V6: &str =
    "CREATE TABLE history_sequence (id INTEGER PRIMARY KEY CHECK(id = 1), value INTEGER NOT NULL);
INSERT INTO history_sequence VALUES (1, (SELECT COALESCE(MAX(list_seq), 0) FROM sandboxes));
PRAGMA user_version = 6;";

// A row stays charged until its release is explicit. A legacy row's tag was
// computed from schema 7's predicate: `state != 'deleted' AND NOT (state = 'failed'
// AND (backend_id IS NOT NULL OR create_certainty = 'definitely_not_created'))`.
// Every other FAILED without an ID stays reserved as ambiguous. An absence-fenced
// row needs its evidence reference, whatever its state, backend ID or certainty.
const RESERVED_SANDBOX_WHERE: &str = "((accounting_kind = 'legacy' AND legacy_release IS NULL) OR (accounting_kind = 'fenced' AND release_evidence_id IS NULL))";
// Only these lifecycle states can still explain a listed backend ID. In
// particular, compensated FAILED must not hide a backend that reappeared.
const OWNED_BACKEND_WHERE: &str =
    "state IN ('creating', 'ready', 'deleting', 'lost', 'quarantined')";

// Schema 8 rebuilds both tables because SQLite cannot add a composite foreign key.
// `sandboxes_v8` is the parent while `executions_v8` is copied, so no violation
// exists at any instant and foreign keys stay enforced throughout the transaction.
const MIGRATE_V8_TABLES: &str = "
CREATE TABLE daemon_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    database_uuid TEXT NOT NULL CHECK (length(database_uuid) = 32 AND database_uuid NOT GLOB '*[^0-9a-f]*'),
    instance_id TEXT NOT NULL CHECK (length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*')
);
CREATE TABLE release_evidence (
    receipt_id TEXT PRIMARY KEY NOT NULL CHECK (length(receipt_id) = 32 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    node_id TEXT NOT NULL CHECK (length(node_id) = 32 AND node_id NOT GLOB '*[^0-9a-f]*'),
    instance_id TEXT NOT NULL CHECK (length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*'),
    allocation_id TEXT NOT NULL UNIQUE CHECK (length(allocation_id) = 32 AND allocation_id NOT GLOB '*[^0-9a-f]*'),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'),
    helper_generation INTEGER NOT NULL CHECK (typeof(helper_generation) = 'integer' AND helper_generation >= 1),
    kind TEXT NOT NULL CHECK (kind = 'absent_fenced'),
    receipt BLOB NOT NULL CHECK (typeof(receipt) = 'blob' AND length(receipt) BETWEEN 1 AND 16384),
    recorded_at_ms INTEGER NOT NULL,
    UNIQUE (node_id, instance_id, allocation_id, plan_digest, helper_generation, kind),
    UNIQUE (receipt_id, node_id, instance_id, allocation_id, plan_digest, kind)
);
CREATE TABLE sandboxes_v8 (
    id             TEXT PRIMARY KEY,
    backend        TEXT NOT NULL,
    backend_id     TEXT,
    state          TEXT NOT NULL,
    spec           TEXT NOT NULL,
    failure_reason TEXT,
    created_at_ms  INTEGER NOT NULL,
    updated_at_ms  INTEGER NOT NULL,
    deleted_at_ms  INTEGER,
    list_seq       INTEGER NOT NULL,
    create_certainty TEXT NOT NULL DEFAULT 'allocation_ambiguous' CHECK (create_certainty = 'allocation_ambiguous' OR (create_certainty = 'definitely_not_created' AND backend_id IS NULL AND state IN ('failed', 'deleted'))),
    owner_uid INTEGER NOT NULL DEFAULT 0 CHECK (owner_uid BETWEEN 0 AND 4294967295),
    accounting_kind TEXT NOT NULL CHECK (accounting_kind IN ('legacy', 'fenced')),
    reserved_memory_bytes INTEGER NOT NULL CHECK (typeof(reserved_memory_bytes) = 'integer' AND reserved_memory_bytes >= 0),
    reserved_disk_bytes INTEGER NOT NULL CHECK (typeof(reserved_disk_bytes) = 'integer' AND reserved_disk_bytes >= 0),
    reserved_pids INTEGER NOT NULL CHECK (typeof(reserved_pids) = 'integer' AND reserved_pids >= 0),
    reserved_host_cpu_millis INTEGER NOT NULL CHECK (typeof(reserved_host_cpu_millis) = 'integer' AND reserved_host_cpu_millis >= 0),
    reserved_virtual_cpu_slots INTEGER NOT NULL CHECK (typeof(reserved_virtual_cpu_slots) = 'integer' AND reserved_virtual_cpu_slots >= 0),
    reserved_host_pids INTEGER NOT NULL CHECK (typeof(reserved_host_pids) = 'integer' AND reserved_host_pids >= 0),
    host_spec_sha256 TEXT NOT NULL CHECK (length(host_spec_sha256) = 64 AND host_spec_sha256 NOT GLOB '*[^0-9a-f]*'),
    guest_exec_spec_sha256 TEXT NOT NULL CHECK (length(guest_exec_spec_sha256) = 64 AND guest_exec_spec_sha256 NOT GLOB '*[^0-9a-f]*'),
    runtime_profile TEXT NOT NULL DEFAULT '',
    runtime_artifact_digest TEXT NOT NULL DEFAULT '',
    disposition TEXT NOT NULL DEFAULT 'reusable' CHECK (disposition IN ('reusable', 'stopped', 'quarantined')),
    boot_id TEXT,
    runtime_receipt BLOB CHECK (runtime_receipt IS NULL OR length(runtime_receipt) <= 16384),
    legacy_release TEXT,
    node_id TEXT CHECK (node_id IS NULL OR (length(node_id) = 32 AND node_id NOT GLOB '*[^0-9a-f]*')),
    instance_id TEXT CHECK (instance_id IS NULL OR (length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*')),
    allocation_id TEXT CHECK (allocation_id IS NULL OR (length(allocation_id) = 32 AND allocation_id NOT GLOB '*[^0-9a-f]*')),
    plan_version INTEGER CHECK (plan_version IS NULL OR plan_version BETWEEN 0 AND 4294967295),
    plan_digest TEXT CHECK (plan_digest IS NULL OR (length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*')),
    plan BLOB CHECK (plan IS NULL OR (typeof(plan) = 'blob' AND length(plan) BETWEEN 1 AND 131072)),
    release_evidence_id TEXT,
    release_evidence_kind TEXT NOT NULL DEFAULT 'absent_fenced' CHECK (release_evidence_kind = 'absent_fenced'),
    last_helper_generation INTEGER CHECK (last_helper_generation IS NULL OR (typeof(last_helper_generation) = 'integer' AND last_helper_generation >= 0)),
    CHECK (legacy_release IS NULL
        OR (legacy_release = 'deleted' AND state = 'deleted')
        OR (legacy_release = 'compensated' AND state = 'failed' AND backend_id IS NOT NULL)
        OR (legacy_release = 'definitely_not_created' AND state = 'failed' AND backend_id IS NULL AND create_certainty = 'definitely_not_created')),
    CHECK (accounting_kind = 'fenced' OR state != 'deleted' OR legacy_release IS 'deleted'),
    CHECK (accounting_kind = 'fenced' OR (release_evidence_id IS NULL AND node_id IS NULL AND instance_id IS NULL AND allocation_id IS NULL AND plan_version IS NULL AND plan_digest IS NULL AND plan IS NULL AND last_helper_generation IS NULL)),
    CHECK (accounting_kind = 'legacy' OR (legacy_release IS NULL AND create_certainty = 'allocation_ambiguous'
        AND node_id IS NOT NULL AND instance_id IS NOT NULL AND allocation_id IS NOT NULL
        AND plan_version IS NOT NULL AND plan_digest IS NOT NULL AND plan IS NOT NULL AND last_helper_generation IS NOT NULL)),
    CHECK (release_evidence_id IS NULL OR state IN ('failed', 'deleted')),
    CHECK (accounting_kind = 'legacy' OR state != 'deleted' OR release_evidence_id IS NOT NULL),
    CHECK (accounting_kind = 'legacy' OR state != 'creating' OR backend_id IS NULL),
    CHECK (accounting_kind = 'legacy' OR backend_id IS NULL OR backend_id = 'fc-' || allocation_id),
    CHECK (accounting_kind = 'legacy' OR state != 'ready' OR (backend_id IS NOT NULL AND boot_id IS NOT NULL AND runtime_receipt IS NOT NULL AND last_helper_generation >= 1)),
    FOREIGN KEY (release_evidence_id, node_id, instance_id, allocation_id, plan_digest, release_evidence_kind)
        REFERENCES release_evidence (receipt_id, node_id, instance_id, allocation_id, plan_digest, kind)
);
CREATE TABLE executions_v8 (
    id               TEXT PRIMARY KEY,
    sandbox_id       TEXT NOT NULL REFERENCES sandboxes_v8 (id),
    argv             TEXT NOT NULL,
    state            TEXT NOT NULL,
    exit_code        INTEGER,
    failure_reason   TEXT,
    timeout_ms       INTEGER NOT NULL,
    stdin_bytes      INTEGER NOT NULL,
    started_at_ms    INTEGER NOT NULL,
    finished_at_ms   INTEGER,
    stdout           BLOB NOT NULL DEFAULT x'',
    stdout_bytes     INTEGER NOT NULL DEFAULT 0,
    stdout_truncated INTEGER NOT NULL DEFAULT 0,
    stdout_total_bytes_known INTEGER NOT NULL DEFAULT 0,
    stderr           BLOB NOT NULL DEFAULT x'',
    stderr_bytes     INTEGER NOT NULL DEFAULT 0,
    stderr_truncated INTEGER NOT NULL DEFAULT 0,
    stderr_total_bytes_known INTEGER NOT NULL DEFAULT 0,
    command_status_kind TEXT,
    command_status_value INTEGER,
    command_core_dumped INTEGER,
    runtime_error TEXT,
    sandbox_reusable INTEGER CHECK (sandbox_reusable IS NULL OR sandbox_reusable IN (0, 1)),
    cleanup_evidence TEXT NOT NULL DEFAULT 'unknown' CHECK (cleanup_evidence IN ('unknown', 'no_child_started', 'runtime_drained', 'sandbox_stopped'))
);
";

// Runs after every row is copied, so history never trips a constraint meant for
// new writes. These are defense in depth against malformed direct SQL; the typed
// API is still what produces valid evidence.
const MIGRATE_V8_FINISH: &str = "
INSERT INTO executions_v8 (id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, stdout, stdout_bytes, stdout_truncated, stdout_total_bytes_known,
    stderr, stderr_bytes, stderr_truncated, stderr_total_bytes_known,
    command_status_kind, command_status_value, command_core_dumped, runtime_error)
SELECT id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, stdout, stdout_bytes, stdout_truncated, stdout_total_bytes_known,
    stderr, stderr_bytes, stderr_truncated, stderr_total_bytes_known,
    command_status_kind, command_status_value, command_core_dumped, runtime_error
FROM executions;
DROP TABLE executions;
DROP TABLE sandboxes;
ALTER TABLE sandboxes_v8 RENAME TO sandboxes;
ALTER TABLE executions_v8 RENAME TO executions;
CREATE UNIQUE INDEX sandboxes_backend_id ON sandboxes (backend, backend_id) WHERE backend_id IS NOT NULL;
CREATE INDEX sandboxes_state ON sandboxes (state);
CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);
CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';
CREATE INDEX sandboxes_owner_list_seq ON sandboxes (owner_uid, list_seq DESC);
CREATE UNIQUE INDEX sandboxes_allocation ON sandboxes (allocation_id) WHERE allocation_id IS NOT NULL;
CREATE INDEX executions_sandbox ON executions (sandbox_id, started_at_ms);
CREATE INDEX executions_state ON executions (state);
CREATE TRIGGER daemon_identity_no_update BEFORE UPDATE ON daemon_identity
BEGIN SELECT RAISE(ABORT, 'daemon identity is immutable'); END;
CREATE TRIGGER daemon_identity_no_delete BEFORE DELETE ON daemon_identity
BEGIN SELECT RAISE(ABORT, 'daemon identity is immutable'); END;
CREATE TRIGGER release_evidence_no_update BEFORE UPDATE ON release_evidence
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_no_delete BEFORE DELETE ON release_evidence
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_no_replace BEFORE INSERT ON release_evidence
WHEN EXISTS (SELECT 1 FROM release_evidence WHERE receipt_id = NEW.receipt_id OR allocation_id = NEW.allocation_id)
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_not_stale BEFORE INSERT ON release_evidence
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE allocation_id = NEW.allocation_id AND last_helper_generation >= NEW.helper_generation)
BEGIN SELECT RAISE(ABORT, 'absence evidence is older than this allocation''s published generation'); END;
CREATE TRIGGER sandboxes_no_replace BEFORE INSERT ON sandboxes
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'a sandbox row cannot be replaced'); END;
CREATE TRIGGER sandboxes_immutable BEFORE UPDATE ON sandboxes
WHEN NEW.id IS NOT OLD.id OR NEW.backend IS NOT OLD.backend OR NEW.spec IS NOT OLD.spec
    OR NEW.created_at_ms IS NOT OLD.created_at_ms OR NEW.list_seq IS NOT OLD.list_seq
    OR NEW.owner_uid IS NOT OLD.owner_uid OR NEW.accounting_kind IS NOT OLD.accounting_kind
    OR NEW.reserved_memory_bytes IS NOT OLD.reserved_memory_bytes
    OR NEW.reserved_disk_bytes IS NOT OLD.reserved_disk_bytes
    OR NEW.reserved_pids IS NOT OLD.reserved_pids
    OR NEW.reserved_host_cpu_millis IS NOT OLD.reserved_host_cpu_millis
    OR NEW.reserved_virtual_cpu_slots IS NOT OLD.reserved_virtual_cpu_slots
    OR NEW.reserved_host_pids IS NOT OLD.reserved_host_pids
    OR NEW.host_spec_sha256 IS NOT OLD.host_spec_sha256
    OR NEW.guest_exec_spec_sha256 IS NOT OLD.guest_exec_spec_sha256
    OR NEW.runtime_profile IS NOT OLD.runtime_profile
    OR NEW.runtime_artifact_digest IS NOT OLD.runtime_artifact_digest
    OR NEW.node_id IS NOT OLD.node_id OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.allocation_id IS NOT OLD.allocation_id OR NEW.plan_version IS NOT OLD.plan_version
    OR NEW.plan_digest IS NOT OLD.plan_digest OR NEW.plan IS NOT OLD.plan
    OR NEW.release_evidence_kind IS NOT OLD.release_evidence_kind
BEGIN SELECT RAISE(ABORT, 'sandbox identity, plan, spec and reservation are immutable'); END;
CREATE TRIGGER sandboxes_evidence_matches_update BEFORE UPDATE ON sandboxes
WHEN NEW.release_evidence_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM release_evidence
    WHERE receipt_id = NEW.release_evidence_id AND node_id = NEW.node_id AND instance_id = NEW.instance_id
      AND allocation_id = NEW.allocation_id AND plan_digest = NEW.plan_digest AND kind = 'absent_fenced')
BEGIN SELECT RAISE(ABORT, 'release evidence does not match this allocation'); END;
CREATE TRIGGER sandboxes_evidence_matches_insert BEFORE INSERT ON sandboxes
WHEN NEW.release_evidence_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM release_evidence
    WHERE receipt_id = NEW.release_evidence_id AND node_id = NEW.node_id AND instance_id = NEW.instance_id
      AND allocation_id = NEW.allocation_id AND plan_digest = NEW.plan_digest AND kind = 'absent_fenced'
      AND helper_generation IS NEW.last_helper_generation)
BEGIN SELECT RAISE(ABORT, 'release evidence does not match this allocation'); END;
CREATE TRIGGER sandboxes_generation_is_monotonic BEFORE UPDATE ON sandboxes
WHEN NEW.last_helper_generation IS NOT OLD.last_helper_generation AND (
        OLD.last_helper_generation IS NULL OR NEW.last_helper_generation IS NULL
        OR NEW.last_helper_generation <= OLD.last_helper_generation
        OR NOT ((OLD.runtime_receipt IS NULL AND NEW.runtime_receipt IS NOT NULL)
            OR (OLD.release_evidence_id IS NULL AND NEW.release_evidence_id IS NOT NULL)))
BEGIN SELECT RAISE(ABORT, 'a helper generation only advances with its ready or absence receipt'); END;
CREATE TRIGGER sandboxes_release_is_fresh BEFORE UPDATE ON sandboxes
WHEN OLD.release_evidence_id IS NULL AND NEW.release_evidence_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM release_evidence
    WHERE receipt_id = NEW.release_evidence_id
      AND (helper_generation <= OLD.last_helper_generation OR helper_generation IS NOT NEW.last_helper_generation))
BEGIN SELECT RAISE(ABORT, 'absence evidence is not newer than this allocation''s published generation'); END;
CREATE TRIGGER sandboxes_release_is_permanent BEFORE UPDATE ON sandboxes
WHEN (OLD.release_evidence_id IS NOT NULL
        AND (NEW.release_evidence_id IS NOT OLD.release_evidence_id OR NEW.state NOT IN ('failed', 'deleted')))
    OR (OLD.legacy_release IS NOT NULL AND NEW.legacy_release IS NULL)
    OR (OLD.state = 'deleted' AND NEW.state != 'deleted')
BEGIN SELECT RAISE(ABORT, 'a released reservation cannot be charged or reused again'); END;
CREATE TRIGGER sandboxes_no_legacy_laundering BEFORE UPDATE ON sandboxes
WHEN OLD.accounting_kind = 'legacy' AND OLD.state != 'creating' AND (
        (OLD.backend_id IS NULL AND NEW.backend_id IS NOT NULL)
        OR NEW.create_certainty IS NOT OLD.create_certainty
        OR (OLD.state = 'failed' AND OLD.legacy_release IS NULL AND NEW.state = 'deleted'))
BEGIN SELECT RAISE(ABORT, 'an ambiguous legacy reservation cannot acquire release provenance'); END;
CREATE TRIGGER sandboxes_fenced_publication BEFORE UPDATE ON sandboxes
WHEN OLD.accounting_kind = 'fenced' AND (
        (OLD.backend_id IS NOT NULL AND NEW.backend_id IS NOT OLD.backend_id)
        OR (OLD.boot_id IS NOT NULL AND NEW.boot_id IS NOT OLD.boot_id)
        OR (OLD.runtime_receipt IS NOT NULL AND NEW.runtime_receipt IS NOT OLD.runtime_receipt))
BEGIN SELECT RAISE(ABORT, 'a published allocation identity is immutable'); END;
CREATE TRIGGER sandboxes_no_resurrection BEFORE UPDATE ON sandboxes
WHEN NEW.state = 'ready' AND OLD.state != 'ready' AND (OLD.state = 'quarantined'
        OR (OLD.accounting_kind = 'fenced' AND OLD.state != 'creating'))
BEGIN SELECT RAISE(ABORT, 'a stopped or quarantined session cannot become ready'); END;
CREATE TRIGGER sandboxes_fenced_disposition BEFORE UPDATE ON sandboxes
WHEN OLD.accounting_kind = 'fenced' AND OLD.disposition != 'reusable' AND NEW.disposition = 'reusable'
BEGIN SELECT RAISE(ABORT, 'a retired allocation cannot become reusable'); END;
CREATE TRIGGER sandboxes_no_charged_delete BEFORE DELETE ON sandboxes
WHEN (OLD.accounting_kind = 'legacy' AND OLD.legacy_release IS NULL)
    OR (OLD.accounting_kind = 'fenced' AND OLD.release_evidence_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'a charged sandbox row cannot be deleted'); END;
PRAGMA user_version = 8;";

// Every UNIQUE key must be guarded before SQLite resolves conflicts: implicit
// REPLACE deletes skip DELETE triggers when recursive_triggers is off. ABORT
// in a BEFORE trigger also cannot be weakened by OR IGNORE/FAIL/ROLLBACK.
const MIGRATE_V9: &str = "
DROP TRIGGER sandboxes_no_replace;
CREATE TRIGGER sandboxes_no_replace BEFORE INSERT ON sandboxes
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE rowid = NEW.rowid OR id = NEW.id OR list_seq = NEW.list_seq
    OR (NEW.backend_id IS NOT NULL AND backend = NEW.backend AND backend_id = NEW.backend_id)
    OR (NEW.allocation_id IS NOT NULL AND allocation_id = NEW.allocation_id))
BEGIN SELECT RAISE(ABORT, 'a sandbox row cannot be replaced'); END;
CREATE TRIGGER sandboxes_no_replace_update BEFORE UPDATE ON sandboxes
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE rowid != OLD.rowid AND (
    rowid = NEW.rowid OR id = NEW.id OR list_seq = NEW.list_seq
    OR (NEW.backend_id IS NOT NULL AND backend = NEW.backend AND backend_id = NEW.backend_id)
    OR (NEW.allocation_id IS NOT NULL AND allocation_id = NEW.allocation_id)))
BEGIN SELECT RAISE(ABORT, 'a sandbox row cannot be replaced'); END;
CREATE TRIGGER daemon_identity_no_replace BEFORE INSERT ON daemon_identity
WHEN EXISTS (SELECT 1 FROM daemon_identity WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'daemon identity is immutable'); END;
CREATE TRIGGER executions_no_replace BEFORE INSERT ON executions
WHEN EXISTS (SELECT 1 FROM executions WHERE rowid = NEW.rowid OR id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'an execution row cannot be replaced'); END;
CREATE TRIGGER executions_no_replace_update BEFORE UPDATE ON executions
WHEN EXISTS (SELECT 1 FROM executions WHERE rowid != OLD.rowid AND (rowid = NEW.rowid OR id = NEW.id))
BEGIN SELECT RAISE(ABORT, 'an execution row cannot be replaced'); END;
CREATE TRIGGER history_sequence_no_replace BEFORE INSERT ON history_sequence
WHEN EXISTS (SELECT 1 FROM history_sequence WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'history sequence cannot be replaced'); END;
CREATE TRIGGER history_sequence_identity BEFORE UPDATE OF id ON history_sequence
WHEN NEW.id IS NOT OLD.id
BEGIN SELECT RAISE(ABORT, 'history sequence identity is immutable'); END;
DROP TRIGGER release_evidence_no_replace;
CREATE TRIGGER release_evidence_no_replace BEFORE INSERT ON release_evidence
WHEN EXISTS (SELECT 1 FROM release_evidence WHERE rowid = NEW.rowid
    OR receipt_id = NEW.receipt_id OR allocation_id = NEW.allocation_id)
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_validate BEFORE INSERT ON release_evidence
WHEN kilnd_fenced_absence_valid(NEW.receipt, NEW.receipt_id, NEW.node_id,
    NEW.instance_id, NEW.allocation_id, NEW.plan_digest, NEW.helper_generation, NEW.kind) IS NOT 1
BEGIN SELECT RAISE(ABORT, 'invalid encoded AbsentFenced evidence'); END;
PRAGMA user_version = 9;";

/// Register before preparing any schema statement. An independent connection
/// without this function cannot insert evidence while triggers are enabled.
/// This name is not an authenticity boundary: another connection can replace it.
fn register_receipt_validator(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "kilnd_fenced_absence_valid",
        8,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            let bytes = ctx.get::<Vec<u8>>(0)?;
            let Ok(receipt) = FencedAbsence::decode(&bytes) else {
                return Ok(false);
            };
            Ok(receipt.receipt_id().to_string() == ctx.get::<String>(1)?
                && receipt.node_id().to_string() == ctx.get::<String>(2)?
                && receipt.instance_id().to_string() == ctx.get::<String>(3)?
                && receipt.allocation_id().to_string() == ctx.get::<String>(4)?
                && receipt.plan_digest().to_string() == ctx.get::<String>(5)?
                && receipt.helper_generation() as i64 == ctx.get::<i64>(6)?
                && ctx.get::<String>(7)? == "absent_fenced")
        },
    )
}

// Only trusted Store insert/prune transactions refresh this marker, never a
// trigger. It detects accidental/missing membership, not hostile file authority.
const MIGRATE_V10: &str = "
CREATE TABLE reservation_integrity (id INTEGER PRIMARY KEY CHECK (id = 1), digest BLOB NOT NULL CHECK (length(digest) = 32));
PRAGMA user_version = 10;";

// Schema 11 (API additions design 2.6): expiry policy, its clock anchors, the
// activity CAS guard and typed deletion and cancel reasons. None of these enters the
// reservation digest or the fenced identity triggers: they are lifecycle data, not
// reservation membership. Historical rows get nulls and seq 0: never expires, reason
// unknown. Fresh databases reach it through the same step.
const MIGRATE_V11: &str = "
ALTER TABLE sandboxes ADD COLUMN expiry_lifetime_ms INTEGER CHECK (expiry_lifetime_ms IS NULL OR (typeof(expiry_lifetime_ms) = 'integer' AND expiry_lifetime_ms > 0));
ALTER TABLE sandboxes ADD COLUMN expiry_idle_ms INTEGER CHECK (expiry_idle_ms IS NULL OR (typeof(expiry_idle_ms) = 'integer' AND expiry_idle_ms > 0));
ALTER TABLE sandboxes ADD COLUMN ready_at_ms INTEGER CHECK (ready_at_ms IS NULL OR typeof(ready_at_ms) = 'integer');
ALTER TABLE sandboxes ADD COLUMN ready_boottime_ms INTEGER CHECK (ready_boottime_ms IS NULL OR typeof(ready_boottime_ms) = 'integer');
ALTER TABLE sandboxes ADD COLUMN activity_at_ms INTEGER CHECK (activity_at_ms IS NULL OR typeof(activity_at_ms) = 'integer');
ALTER TABLE sandboxes ADD COLUMN activity_boottime_ms INTEGER CHECK (activity_boottime_ms IS NULL OR typeof(activity_boottime_ms) = 'integer');
ALTER TABLE sandboxes ADD COLUMN clock_boot_id TEXT CHECK (clock_boot_id IS NULL OR (typeof(clock_boot_id) = 'text' AND length(clock_boot_id) BETWEEN 1 AND 64));
ALTER TABLE sandboxes ADD COLUMN activity_seq INTEGER NOT NULL DEFAULT 0 CHECK (typeof(activity_seq) = 'integer' AND activity_seq >= 0);
ALTER TABLE sandboxes ADD COLUMN deletion_reason TEXT CHECK (deletion_reason IS NULL OR deletion_reason IN ('requested', 'expired_idle', 'expired_lifetime'));
ALTER TABLE sandboxes ADD COLUMN expiry_intent_at_ms INTEGER CHECK (expiry_intent_at_ms IS NULL OR typeof(expiry_intent_at_ms) = 'integer');
ALTER TABLE sandboxes ADD COLUMN expiry_intent_boottime_ms INTEGER CHECK (expiry_intent_boottime_ms IS NULL OR typeof(expiry_intent_boottime_ms) = 'integer');
ALTER TABLE executions ADD COLUMN cancel_reason TEXT CHECK (cancel_reason IS NULL OR cancel_reason IN ('client_disconnected', 'sandbox_deleted', 'daemon_shutdown', 'sandbox_expired_lifetime'));
CREATE INDEX sandboxes_expiry ON sandboxes (id)
    WHERE state IN ('ready', 'lost', 'quarantined', 'deleting')
      AND (expiry_lifetime_ms IS NOT NULL OR expiry_idle_ms IS NOT NULL);
CREATE TRIGGER sandboxes_expiry_policy_immutable BEFORE UPDATE ON sandboxes
WHEN NEW.expiry_lifetime_ms IS NOT OLD.expiry_lifetime_ms OR NEW.expiry_idle_ms IS NOT OLD.expiry_idle_ms
BEGIN SELECT RAISE(ABORT, 'a sandbox expiry policy is immutable'); END;
CREATE TRIGGER sandboxes_deletion_reason_once BEFORE UPDATE ON sandboxes
WHEN (OLD.deletion_reason IS NOT NULL AND NEW.deletion_reason IS NOT OLD.deletion_reason)
    OR (OLD.deletion_reason IS NULL AND NEW.deletion_reason IS NOT NULL AND NEW.state NOT IN ('deleting', 'deleted'))
BEGIN SELECT RAISE(ABORT, 'a deletion reason is written once, with DELETING or DELETED'); END;
CREATE TRIGGER sandboxes_deletion_reason_insert BEFORE INSERT ON sandboxes
WHEN NEW.deletion_reason IS NOT NULL AND NEW.state NOT IN ('deleting', 'deleted')
BEGIN SELECT RAISE(ABORT, 'a deletion reason is written once, with DELETING or DELETED'); END;
CREATE TRIGGER sandboxes_activity_seq_monotonic BEFORE UPDATE ON sandboxes
WHEN NEW.activity_seq < OLD.activity_seq
BEGIN SELECT RAISE(ABORT, 'activity_seq only increases'); END;
CREATE TRIGGER sandboxes_ready_anchor_fixed BEFORE UPDATE ON sandboxes
WHEN (OLD.ready_at_ms IS NOT NULL AND NEW.ready_at_ms IS NOT OLD.ready_at_ms)
    OR (OLD.ready_boottime_ms IS NOT NULL AND NEW.ready_boottime_ms IS NOT OLD.ready_boottime_ms
        AND NEW.clock_boot_id IS OLD.clock_boot_id)
BEGIN SELECT RAISE(ABORT, 'a READY anchor changes only in the cross-boot rebase'); END;
CREATE TRIGGER sandboxes_expiry_intent_anchor BEFORE UPDATE ON sandboxes
WHEN (OLD.expiry_intent_at_ms IS NOT NULL AND NEW.expiry_intent_at_ms IS NOT OLD.expiry_intent_at_ms)
    OR (OLD.expiry_intent_boottime_ms IS NOT NULL AND NEW.expiry_intent_boottime_ms IS NOT OLD.expiry_intent_boottime_ms
        AND NEW.clock_boot_id IS OLD.clock_boot_id)
    OR ((NEW.expiry_intent_at_ms IS NOT NULL OR NEW.expiry_intent_boottime_ms IS NOT NULL)
        AND (NEW.deletion_reason IS NULL OR NEW.deletion_reason NOT IN ('expired_idle', 'expired_lifetime')))
BEGIN SELECT RAISE(ABORT, 'an expiry intent anchor is written once, with its reason, and moves only in the cross-boot rebase'); END;
CREATE TRIGGER sandboxes_expiry_intent_insert BEFORE INSERT ON sandboxes
WHEN NEW.expiry_intent_at_ms IS NOT NULL OR NEW.expiry_intent_boottime_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an expiry intent anchor is written only by the expiry intent'); END;
CREATE TRIGGER executions_cancel_reason_once BEFORE UPDATE ON executions
WHEN OLD.cancel_reason IS NOT NULL AND NEW.cancel_reason IS NOT OLD.cancel_reason
BEGIN SELECT RAISE(ABORT, 'a cancel reason is written once'); END;
PRAGMA user_version = 11;";

// Schema 12 (API additions design 3.2 and 3.3): create request records for idempotent
// create. A record names its sandbox, which it pins: the row is deleted only after the
// record. A record is inserted unanchored (both retention columns null, never
// prunable) and gets its retention anchor only in a later transaction, after the one
// that inserted it committed (break-it HIGH 1: no pause before the commit can shorten
// the window). After that it changes only in the startup cross-boot rebase, and is
// deleted only once its sandbox is DELETED or released FAILED (by prune or release).
// `sandboxes.request_id` is fixed at insert, so history keeps it after its record is
// gone; `request_id_released_at_ms` is written once, after its record, from DELETED.
// None of this enters the reservation membership: it is lifecycle data.
//
// Break-it M2 MEDIUM 2: schema 12 replaces the schema 10 marker, one hash over all
// history that every accounting decision recomputed, with `reservation_membership`:
// O(1)-updatable aggregates of every row and of the rows settled (uncharged) at the
// last full audit. A row that leaves the charged set is noted in
// `reservation_unsettled` by the one trigger that can see every such update, kilnd's
// or anyone's; it only notes the ID, so it cannot vouch for a row. The partial index
// finds the charged rows without a scan. Only Store transactions write the
// aggregates, after verifying the older marker in the migration.
const MIGRATE_V12: &str = "
CREATE TABLE create_requests (
    owner_uid INTEGER NOT NULL CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN 0 AND 4294967295),
    request_id TEXT NOT NULL CHECK (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 64 AND request_id NOT GLOB '*[^!-~]*'),
    request_sha256 TEXT NOT NULL CHECK (typeof(request_sha256) = 'text' AND length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    sandbox_id TEXT NOT NULL UNIQUE REFERENCES sandboxes (id),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer'),
    retain_boot_id TEXT CHECK (retain_boot_id IS NULL OR (typeof(retain_boot_id) = 'text' AND length(retain_boot_id) BETWEEN 1 AND 64)),
    retain_from_boottime_ms INTEGER CHECK (retain_from_boottime_ms IS NULL OR typeof(retain_from_boottime_ms) = 'integer'),
    CHECK ((retain_boot_id IS NULL) = (retain_from_boottime_ms IS NULL)),
    PRIMARY KEY (owner_uid, request_id)
) WITHOUT ROWID;
ALTER TABLE sandboxes ADD COLUMN request_id TEXT CHECK (request_id IS NULL OR (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 64 AND request_id NOT GLOB '*[^!-~]*'));
ALTER TABLE sandboxes ADD COLUMN request_id_released_at_ms INTEGER CHECK (request_id_released_at_ms IS NULL OR typeof(request_id_released_at_ms) = 'integer');
CREATE TRIGGER create_requests_no_replace BEFORE INSERT ON create_requests
WHEN EXISTS (SELECT 1 FROM create_requests
    WHERE (owner_uid = NEW.owner_uid AND request_id = NEW.request_id) OR sandbox_id = NEW.sandbox_id)
BEGIN SELECT RAISE(ABORT, 'a create request record cannot be replaced'); END;
CREATE TRIGGER create_requests_own_sandbox BEFORE INSERT ON create_requests
WHEN NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.sandbox_id AND owner_uid = NEW.owner_uid
    AND request_id = NEW.request_id AND state = 'creating')
BEGIN SELECT RAISE(ABORT, 'a create request record is inserted with its own CREATING sandbox'); END;
CREATE INDEX create_requests_unanchored ON create_requests (sandbox_id) WHERE retain_boot_id IS NULL;
CREATE TRIGGER create_requests_unanchored_insert BEFORE INSERT ON create_requests
WHEN NEW.retain_boot_id IS NOT NULL OR NEW.retain_from_boottime_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a create request record is inserted unanchored and anchored only after it commits'); END;
CREATE TRIGGER create_requests_fixed BEFORE UPDATE ON create_requests
WHEN NEW.owner_uid IS NOT OLD.owner_uid OR NEW.request_id IS NOT OLD.request_id
    OR NEW.request_sha256 IS NOT OLD.request_sha256 OR NEW.sandbox_id IS NOT OLD.sandbox_id
    OR NEW.created_at_ms IS NOT OLD.created_at_ms
    OR (OLD.retain_boot_id IS NOT NULL AND NEW.retain_boot_id IS NULL)
    OR (NEW.retain_from_boottime_ms IS NOT OLD.retain_from_boottime_ms AND NEW.retain_boot_id IS OLD.retain_boot_id)
BEGIN SELECT RAISE(ABORT, 'a create request record changes only when anchored or in the cross-boot retention rebase'); END;
CREATE TRIGGER create_requests_settled_delete BEFORE DELETE ON create_requests
WHEN NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = OLD.sandbox_id AND (state = 'deleted'
    OR (state = 'failed' AND NOT ((accounting_kind = 'legacy' AND legacy_release IS NULL)
        OR (accounting_kind = 'fenced' AND release_evidence_id IS NULL)))))
BEGIN SELECT RAISE(ABORT, 'a create request record is kept until its sandbox is DELETED or released FAILED'); END;
CREATE TRIGGER sandboxes_pinned_by_request BEFORE DELETE ON sandboxes
WHEN EXISTS (SELECT 1 FROM create_requests WHERE sandbox_id = OLD.id)
BEGIN SELECT RAISE(ABORT, 'a sandbox with a create request record cannot be deleted'); END;
CREATE TRIGGER sandboxes_request_id_fixed BEFORE UPDATE ON sandboxes
WHEN NEW.request_id IS NOT OLD.request_id
    OR (OLD.request_id_released_at_ms IS NOT NULL AND NEW.request_id_released_at_ms IS NOT OLD.request_id_released_at_ms)
    OR (OLD.request_id_released_at_ms IS NULL AND NEW.request_id_released_at_ms IS NOT NULL
        AND (NEW.state != 'deleted' OR NEW.request_id IS NULL
            OR EXISTS (SELECT 1 FROM create_requests WHERE sandbox_id = NEW.id)))
BEGIN SELECT RAISE(ABORT, 'a request ID is fixed at create and released once, after its record, from DELETED'); END;
CREATE TRIGGER sandboxes_request_insert BEFORE INSERT ON sandboxes
WHEN NEW.request_id_released_at_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a request ID is released only after its sandbox is DELETED'); END;
CREATE TABLE create_request_counts (
    owner_uid INTEGER PRIMARY KEY CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN -1 AND 4294967295),
    records INTEGER NOT NULL CHECK (typeof(records) = 'integer' AND records >= 0)
);
INSERT INTO create_request_counts VALUES (-1, 0);
CREATE TRIGGER create_requests_count_insert AFTER INSERT ON create_requests
BEGIN
    INSERT INTO create_request_counts VALUES (NEW.owner_uid, 1)
        ON CONFLICT(owner_uid) DO UPDATE SET records = records + 1;
    UPDATE create_request_counts SET records = records + 1 WHERE owner_uid = -1;
END;
CREATE TRIGGER create_requests_count_delete AFTER DELETE ON create_requests
BEGIN
    UPDATE create_request_counts SET records = records - 1 WHERE owner_uid IN (OLD.owner_uid, -1);
    DELETE FROM create_request_counts WHERE owner_uid = OLD.owner_uid AND records = 0;
END;
DROP TABLE reservation_integrity;
CREATE TABLE reservation_membership (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    row_count INTEGER NOT NULL CHECK (typeof(row_count) = 'integer' AND row_count >= 0),
    row_sum BLOB NOT NULL CHECK (typeof(row_sum) = 'blob' AND length(row_sum) = 32),
    settled_count INTEGER NOT NULL CHECK (typeof(settled_count) = 'integer' AND settled_count >= 0),
    settled_sum BLOB NOT NULL CHECK (typeof(settled_sum) = 'blob' AND length(settled_sum) = 32)
);
CREATE TABLE reservation_unsettled (id TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE INDEX sandboxes_charged ON sandboxes (id)
WHERE ((accounting_kind = 'legacy' AND legacy_release IS NULL) OR (accounting_kind = 'fenced' AND release_evidence_id IS NULL));
CREATE TRIGGER sandboxes_released_unsettled AFTER UPDATE ON sandboxes
WHEN ((OLD.accounting_kind = 'legacy' AND OLD.legacy_release IS NULL) OR (OLD.accounting_kind = 'fenced' AND OLD.release_evidence_id IS NULL))
    AND NOT ((NEW.accounting_kind = 'legacy' AND NEW.legacy_release IS NULL) OR (NEW.accounting_kind = 'fenced' AND NEW.release_evidence_id IS NULL))
BEGIN INSERT OR IGNORE INTO reservation_unsettled VALUES (NEW.id); END;
PRAGMA user_version = 12;";

// Schema 13 (API additions design 4.2): exec cwd and env. A sandbox's default env
// values are plaintext while it is live, by design, and set to null in the same
// statement that moves the row to FAILED or DELETED; the CHECK makes a FAILED or
// DELETED row with values impossible. Their names and digest, and an execution's cwd,
// names and digest, are fixed at insert; history never holds a value.
// `exec_features` is the sandbox runtime's feature bits, recorded once at READY. None
// of this is reservation membership.
const MIGRATE_V13: &str = "
ALTER TABLE sandboxes ADD COLUMN default_env_names TEXT CHECK (default_env_names IS NULL OR (typeof(default_env_names) = 'text' AND json_valid(default_env_names) AND json_type(default_env_names) = 'array' AND json_array_length(default_env_names) BETWEEN 1 AND 64));
ALTER TABLE sandboxes ADD COLUMN default_env_sha256 TEXT CHECK ((default_env_sha256 IS NULL) = (default_env_names IS NULL) AND (default_env_sha256 IS NULL OR (typeof(default_env_sha256) = 'text' AND length(default_env_sha256) = 64 AND default_env_sha256 NOT GLOB '*[^0-9a-f]*')));
ALTER TABLE sandboxes ADD COLUMN default_env TEXT CHECK (default_env IS NULL OR (typeof(default_env) = 'text' AND default_env_names IS NOT NULL AND state NOT IN ('failed', 'deleted')));
ALTER TABLE sandboxes ADD COLUMN exec_features INTEGER CHECK (exec_features IS NULL OR (typeof(exec_features) = 'integer' AND exec_features BETWEEN 0 AND 4294967295));
ALTER TABLE executions ADD COLUMN cwd TEXT CHECK (cwd IS NULL OR (typeof(cwd) = 'text' AND substr(cwd, 1, 1) = '/' AND length(CAST(cwd AS BLOB)) <= 4096));
ALTER TABLE executions ADD COLUMN env_names TEXT CHECK (env_names IS NULL OR (typeof(env_names) = 'text' AND json_valid(env_names) AND json_type(env_names) = 'array' AND json_array_length(env_names) BETWEEN 1 AND 64));
ALTER TABLE executions ADD COLUMN env_sha256 TEXT CHECK ((env_sha256 IS NULL) = (env_names IS NULL) AND (env_sha256 IS NULL OR (typeof(env_sha256) = 'text' AND length(env_sha256) = 64 AND env_sha256 NOT GLOB '*[^0-9a-f]*')));
CREATE TRIGGER sandboxes_default_env_insert BEFORE INSERT ON sandboxes
WHEN (NEW.default_env IS NOT NULL OR NEW.default_env_names IS NOT NULL) AND NEW.state != 'creating'
BEGIN SELECT RAISE(ABORT, 'a default env is inserted with its CREATING sandbox'); END;
CREATE TRIGGER sandboxes_default_env_fixed BEFORE UPDATE ON sandboxes
WHEN NEW.default_env_names IS NOT OLD.default_env_names OR NEW.default_env_sha256 IS NOT OLD.default_env_sha256
    OR (NEW.default_env IS NOT OLD.default_env AND NEW.default_env IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'a default env is fixed at insert; its values are only cleared'); END;
CREATE TRIGGER sandboxes_exec_features_once BEFORE UPDATE ON sandboxes
WHEN OLD.exec_features IS NOT NULL AND NEW.exec_features IS NOT OLD.exec_features
BEGIN SELECT RAISE(ABORT, 'exec features are recorded once'); END;
CREATE TRIGGER executions_env_fixed BEFORE UPDATE ON executions
WHEN NEW.cwd IS NOT OLD.cwd OR NEW.env_names IS NOT OLD.env_names OR NEW.env_sha256 IS NOT OLD.env_sha256
BEGIN SELECT RAISE(ABORT, 'an execution cwd and env names and digest are fixed at insert'); END;
PRAGMA user_version = 13;";

// Schema 14 (API additions design 5): how an execution was requested, unary Exec or
// ExecStream, fixed at insert. Rows written before it keep NULL, which the API shows as
// EXECUTION_MODE_UNSPECIFIED; every new row names its mode. Live drop counts belong to
// one delivery, not to the execution, and are not stored.
const MIGRATE_V14: &str = "
ALTER TABLE executions ADD COLUMN mode TEXT CHECK (mode IS NULL OR (typeof(mode) = 'text' AND mode IN ('unary', 'stream')));
CREATE TRIGGER executions_mode_fixed BEFORE UPDATE ON executions
WHEN NEW.mode IS NOT OLD.mode
BEGIN SELECT RAISE(ABORT, 'an execution mode is fixed at insert'); END;
PRAGMA user_version = 14;";

/// Clears a sandbox's default env values in the statement that moves it to `?2`, when
/// that is FAILED or DELETED (schema 13's CHECK requires it).
const DEFAULT_ENV_TRANSITION: &str =
    "default_env = CASE WHEN ?2 IN ('failed', 'deleted') THEN NULL ELSE default_env END";

// The immutable reservation and identity columns of a sandbox row: its membership.
// Lifecycle transitions and release references are not membership.
const MEMBERSHIP_COLUMNS: &str = "id, list_seq, backend, spec, created_at_ms, owner_uid,
        accounting_kind, reserved_memory_bytes, reserved_disk_bytes, reserved_pids,
        reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids,
        host_spec_sha256, guest_exec_spec_sha256, runtime_profile, runtime_artifact_digest,
        node_id, instance_id, allocation_id, plan_version, plan_digest, plan";

/// The schema 10 and 11 encoding of one row's membership columns, kept by schema 12.
fn hash_membership_row(hash: &mut Sha256, row: &rusqlite::Row<'_>) -> Result<()> {
    hash.update(b"row");
    for i in 0..23 {
        use rusqlite::types::ValueRef;
        match row.get_ref(i)? {
            ValueRef::Null => hash.update([0]),
            ValueRef::Integer(n) => {
                hash.update([1]);
                hash.update(n.to_le_bytes());
            }
            ValueRef::Real(_) => bail!("degraded accounting: real in immutable reservation"),
            ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                hash.update([if matches!(row.get_ref(i)?, ValueRef::Text(_)) {
                    2
                } else {
                    3
                }]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
        }
    }
    Ok(())
}

/// Schemas 10 and 11: one hash over every row's membership in ID order. Schema 12
/// keeps it only to verify such a marker before it migrates (break-it MEDIUM 3).
fn reservation_digest(conn: &Connection) -> Result<Vec<u8>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes ORDER BY id COLLATE BINARY"
    ))?;
    let mut rows = stmt.query([])?;
    let mut hash = Sha256::new();
    hash.update(b"kilnd-reservation-membership-v1");
    while let Some(row) = rows.next()? {
        hash_membership_row(&mut hash, row)?;
    }
    Ok(hash.finalize().to_vec())
}

/// Schemas 10 and 11's marker, written only where an older schema is built.
fn refresh_reservation_integrity(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT INTO reservation_integrity (id, digest) VALUES (1, ?1)
        ON CONFLICT(id) DO UPDATE SET digest = excluded.digest",
        [reservation_digest(conn)?],
    )?;
    Ok(())
}

/// Schemas 10 and 11: the marker must match the rows exactly.
fn audit_reservation_integrity_v1(conn: &Connection) -> Result<()> {
    let expected: Option<Vec<u8>> = conn
        .query_row(
            "SELECT digest FROM reservation_integrity WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if expected.as_deref() != Some(reservation_digest(conn)?.as_slice()) {
        bail!("{MEMBERSHIP_MISMATCH}");
    }
    Ok(())
}

const MEMBERSHIP_MISMATCH: &str = "degraded accounting: reservation integrity mismatch (missing or changed rows); admission and pruning disabled";

/// A multiset of rows' membership (schema 12, break-it M2 MEDIUM 2): their number
/// and the sum, modulo 2^256, of each row's own SHA-256. Adding or removing one row
/// is O(1), so admission never rehashes history. Like the schema 10 marker it
/// detects accidental or missing membership, not a hostile writer with file
/// authority (who could rewrite either).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Membership {
    count: i64,
    /// Little-endian.
    sum: [u8; 32],
}

impl Membership {
    fn add_row(&mut self, row: &rusqlite::Row<'_>) -> Result<()> {
        let mut hash = Sha256::new();
        hash.update(b"kilnd-reservation-membership-v2");
        hash_membership_row(&mut hash, row)?;
        let digest: [u8; 32] = hash.finalize().into();
        *self = self.plus(Membership {
            count: 1,
            sum: digest,
        });
        Ok(())
    }

    fn plus(self, other: Membership) -> Membership {
        let mut sum = [0u8; 32];
        let mut carry = 0u16;
        for (i, out) in sum.iter_mut().enumerate() {
            let total = u16::from(self.sum[i]) + u16::from(other.sum[i]) + carry;
            *out = total as u8;
            carry = total >> 8;
        }
        Membership {
            count: self.count.wrapping_add(other.count),
            sum,
        }
    }

    fn minus(self, other: Membership) -> Membership {
        let mut sum = [0u8; 32];
        let mut borrow = 0i16;
        for (i, out) in sum.iter_mut().enumerate() {
            let mut total = i16::from(self.sum[i]) - i16::from(other.sum[i]) - borrow;
            borrow = i16::from(total < 0);
            if total < 0 {
                total += 256;
            }
            *out = total as u8;
        }
        Membership {
            count: self.count.wrapping_sub(other.count),
            sum,
        }
    }
}

/// The membership of the sandbox rows a query selects. `select` returns
/// MEMBERSHIP_COLUMNS, in order, of distinct rows.
fn membership_of(conn: &Connection, select: &str, params: impl rusqlite::Params) -> Result<Membership> {
    let mut stmt = conn.prepare(select)?;
    let mut rows = stmt.query(params)?;
    let mut membership = Membership::default();
    while let Some(row) = rows.next()? {
        membership.add_row(row)?;
        #[cfg(test)]
        MEMBERSHIP_ROWS_HASHED.with(|n| n.set(n.get() + 1));
    }
    Ok(membership)
}

#[cfg(test)]
thread_local! {
    /// How many rows this thread has hashed for membership: the scale tests' measure
    /// of how much history an admission reads.
    pub(crate) static MEMBERSHIP_ROWS_HASHED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The stored aggregates: every row, and the rows settled at the last full audit.
fn stored_membership(conn: &Connection) -> Result<Option<(Membership, Membership)>> {
    let row: Option<(i64, Vec<u8>, i64, Vec<u8>)> = conn
        .query_row(
            "SELECT row_count, row_sum, settled_count, settled_sum FROM reservation_membership WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((count, sum, settled_count, settled_sum)) = row else {
        return Ok(None);
    };
    let array = |bytes: Vec<u8>| -> Result<[u8; 32]> {
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{MEMBERSHIP_MISMATCH}"))
    };
    Ok(Some((
        Membership {
            count,
            sum: array(sum)?,
        },
        Membership {
            count: settled_count,
            sum: array(settled_sum)?,
        },
    )))
}

fn store_membership(conn: &Connection, all: Membership, settled: Membership) -> Result<()> {
    conn.execute(
        "INSERT INTO reservation_membership (id, row_count, row_sum, settled_count, settled_sum)
         VALUES (1, ?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET row_count = excluded.row_count, row_sum = excluded.row_sum,
             settled_count = excluded.settled_count, settled_sum = excluded.settled_sum",
        params![all.count, &all.sum[..], settled.count, &settled.sum[..]],
    )?;
    Ok(())
}

fn all_membership(conn: &Connection) -> Result<Membership> {
    membership_of(conn, &format!("SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes"), [])
}

fn settled_membership(conn: &Connection) -> Result<Membership> {
    membership_of(
        conn,
        &format!("SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes WHERE NOT ({RESERVED_SANDBOX_WHERE})"),
        [],
    )
}

/// Trusted (re)seeding from the rows as they stand: the schema 12 migration, after
/// it verified the older marker, and test fixtures modelling a trusted writer.
fn refresh_membership(conn: &Connection) -> Result<()> {
    store_membership(conn, all_membership(conn)?, settled_membership(conn)?)?;
    conn.execute("DELETE FROM reservation_unsettled", [])?;
    Ok(())
}

/// Every Store insert of a sandbox row, in its transaction: add the row to the
/// aggregate, and note it unsettled if it is inserted uncharged. O(1) in history.
fn note_inserted_sandbox(conn: &Connection, id: &str) -> Result<()> {
    let (all, settled) = stored_membership(conn)?.context(MEMBERSHIP_MISMATCH)?;
    let added = membership_of(
        conn,
        &format!("SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes WHERE id = ?1"),
        [id],
    )?;
    if added.count != 1 {
        bail!("sandbox {id} was not inserted");
    }
    store_membership(conn, all.plus(added), settled)?;
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO reservation_unsettled
             SELECT id FROM sandboxes WHERE id = ?1 AND NOT ({RESERVED_SANDBOX_WHERE})"
        ),
        [id],
    )?;
    Ok(())
}

// The rows an accounting decision depends on: every charged row (through the
// partial index), and every row released or inserted uncharged since the last full
// audit. Bounded by reservations and recent activity, never by retained history.
fn live_ids() -> String {
    format!(
        "SELECT id FROM sandboxes WHERE {RESERVED_SANDBOX_WHERE} UNION SELECT id FROM reservation_unsettled"
    )
}

fn fenced_release_checks(conn: &Connection, rows: &str) -> Result<bool> {
    let mut stmt = conn.prepare(rows)?;
    let mut rows = stmt.query([])?;
    let mut degraded = false;
    while let Some(row) = rows.next()? {
        let valid = (|| -> Result<bool> {
            let Some(bytes) = row.get::<_, Option<Vec<u8>>>(14)? else {
                return Ok(false);
            };
            let Ok(receipt) = FencedAbsence::decode(&bytes) else {
                return Ok(false);
            };
            let fields = [
                receipt.node_id().to_string(),
                receipt.instance_id().to_string(),
                receipt.allocation_id().to_string(),
                receipt.plan_digest().to_string(),
                receipt.receipt_id().to_string(),
            ];
            for (column, field) in (1..=5).zip(&fields) {
                if row.get::<_, Option<String>>(column)?.as_ref() != Some(field) {
                    return Ok(false);
                }
            }
            for (column, field) in
                (7..=11).zip([&fields[4], &fields[0], &fields[1], &fields[2], &fields[3]])
            {
                if row.get::<_, Option<String>>(column)?.as_ref() != Some(field) {
                    return Ok(false);
                }
            }
            Ok(
                row.get::<_, Option<i64>>(6)? == Some(receipt.helper_generation() as i64)
                    && row.get::<_, Option<i64>>(12)? == Some(receipt.helper_generation() as i64)
                    && row.get::<_, Option<String>>(13)?.as_deref() == Some("absent_fenced")
                    && matches!(row.get::<_, String>(15)?.as_str(), "failed" | "deleted"),
            )
        })()
        .unwrap_or(false);
        if !valid {
            degraded = true;
            conn.execute(
                "INSERT OR IGNORE INTO temp.accounting_quarantine VALUES (?1)",
                [row.get::<_, String>(0)?],
            )?;
        }
    }
    Ok(degraded)
}

const FENCED_RELEASE_COLUMNS: &str = "s.id, s.node_id, s.instance_id, s.allocation_id,
        s.plan_digest, s.release_evidence_id, s.last_helper_generation,
        e.receipt_id, e.node_id, e.instance_id, e.allocation_id, e.plan_digest,
        e.helper_generation, e.kind, e.receipt, s.state";
const FENCED_RELEASE_WHERE: &str =
    "s.accounting_kind = 'fenced' AND (s.release_evidence_id IS NOT NULL OR s.state = 'deleted')";

fn latched_lost(conn: &Connection) -> Result<()> {
    let lost: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM temp.membership_lost)",
        [],
        |r| r.get(0),
    )?;
    if lost {
        bail!("{MEMBERSHIP_MISMATCH}");
    }
    Ok(())
}

// SQLite's count of commits by *other* connections, as this connection's snapshot
// sees it. kilnd writes only through its one connection, so an unchanged value means
// every byte of state since the last full verification is kilnd's own writing.
fn data_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA data_version", [], |r| r.get(0))?)
}

fn live_membership(conn: &Connection) -> Result<Membership> {
    membership_of(
        conn,
        &format!("SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes WHERE id IN ({})", live_ids()),
        [],
    )
}

fn quarantined(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM temp.accounting_quarantine)",
        [],
        |r| r.get(0),
    )?)
}

/// Everything, without rewriting anything durable: every row's membership against
/// the stored total, the partition (settled + live = all, so a charged row released
/// or lost past the triggers is caught, break-it review MEDIUM 1 of the fix), the
/// quota counters against the records, and every fenced release's evidence, from
/// which the quarantine is rebuilt. O(N). Stamps the data version it verified.
fn verify_membership(conn: &Connection) -> Result<bool> {
    latched_lost(conn)?;
    let (all, settled) = stored_membership(conn)?.context(MEMBERSHIP_MISMATCH)?;
    if all_membership(conn)? != all || settled.plus(live_membership(conn)?) != all {
        bail!("{MEMBERSHIP_MISMATCH}");
    }
    // The quota counters against the records they count: no uid missing, none
    // extra, the node total their sum.
    let miscounted: bool = conn.query_row(
        "WITH actual(owner_uid, records) AS (
             SELECT owner_uid, COUNT(*) FROM create_requests GROUP BY owner_uid
             UNION ALL SELECT -1, COUNT(*) FROM create_requests)
         SELECT EXISTS (SELECT owner_uid, records FROM actual EXCEPT SELECT owner_uid, records FROM create_request_counts)
             OR EXISTS (SELECT owner_uid, records FROM create_request_counts EXCEPT SELECT owner_uid, records FROM actual)",
        [],
        |r| r.get(0),
    )?;
    if miscounted {
        bail!("degraded accounting: create request counters do not match the records; admission and pruning disabled");
    }
    conn.execute_batch("DELETE FROM temp.accounting_quarantine;")?;
    fenced_release_checks(
        conn,
        &format!(
            "SELECT {FENCED_RELEASE_COLUMNS} FROM sandboxes s
             LEFT JOIN release_evidence e ON e.receipt_id = s.release_evidence_id WHERE {FENCED_RELEASE_WHERE}"
        ),
    )?;
    // In the caller's transaction with the quarantine it rebuilt: if that rolls
    // back, so does the stamp, and the next decision verifies again.
    conn.execute(
        "INSERT INTO temp.membership_verified VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET data_version = excluded.data_version",
        [data_version(conn)?],
    )?;
    quarantined(conn)
}

// Call inside the same transaction/snapshot as every accounting decision. Decode
// in Rust, independently of whichever SQL function an external writer registered.
// Quarantine is a read projection: retain the corrupt reference for investigation.
//
// Bounded (break-it M2 MEDIUM 2). If any other connection has committed since this
// one last verified everything (`PRAGMA data_version`: an operator's sqlite3, a
// restore, an attacker past the triggers), the decision verifies everything again,
// as every decision used to. Otherwise all state since that verification is kilnd's
// own writing, so it checks only the live rows: their membership against the
// aggregates and their release evidence. A charged row lost or released behind
// kilnd's back is caught by the next decision either way.
fn audit_accounting(conn: &Connection) -> Result<bool> {
    latched_lost(conn)?;
    let (all, settled) = stored_membership(conn)?.context(MEMBERSHIP_MISMATCH)?;
    let verified: Option<i64> = conn
        .query_row(
            "SELECT data_version FROM temp.membership_verified WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if verified != Some(data_version(conn)?) {
        return verify_membership(conn);
    }
    if settled.plus(live_membership(conn)?) != all {
        bail!("{MEMBERSHIP_MISMATCH}");
    }
    conn.execute(
        &format!(
            "DELETE FROM temp.accounting_quarantine WHERE id IN ({})",
            live_ids()
        ),
        [],
    )?;
    fenced_release_checks(
        conn,
        &format!(
            "SELECT {FENCED_RELEASE_COLUMNS} FROM sandboxes s
             LEFT JOIN release_evidence e ON e.receipt_id = s.release_evidence_id
             WHERE s.id IN ({}) AND {FENCED_RELEASE_WHERE}",
            live_ids()
        ),
    )?;
    quarantined(conn)
}

/// In a write decision's transaction, after its audit verified the partition: move
/// every unsettled row into the settled aggregate. Each released row is then hashed
/// by decisions only until the next write decision, not until the next prune
/// (break-it review MEDIUM 2 of the fix): a decision's cost is bounded by the charged
/// rows and the releases since the last committed write.
fn settle_unsettled(conn: &Connection) -> Result<()> {
    let unsettled = membership_of(
        conn,
        &format!(
            "SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes WHERE id IN (SELECT id FROM reservation_unsettled)
             AND NOT ({RESERVED_SANDBOX_WHERE})"
        ),
        [],
    )?;
    if unsettled.count == 0 {
        conn.execute("DELETE FROM reservation_unsettled", [])?;
        return Ok(());
    }
    let (all, settled) = stored_membership(conn)?.context(MEMBERSHIP_MISMATCH)?;
    store_membership(conn, all, settled.plus(unsettled))?;
    conn.execute("DELETE FROM reservation_unsettled", [])?;
    Ok(())
}

/// The full audit: [`verify_membership`], then the settled aggregate rebuilt from the
/// rows as they stand and the unsettled list cleared. O(N); only at startup and
/// before each prune, in a write transaction.
fn audit_accounting_full(conn: &Connection) -> Result<bool> {
    let degraded = verify_membership(conn)?;
    let (all, _) = stored_membership(conn)?.context(MEMBERSHIP_MISMATCH)?;
    store_membership(conn, all, settled_membership(conn)?)?;
    conn.execute("DELETE FROM reservation_unsettled", [])?;
    Ok(degraded)
}

// The explicit legacy tag and reuse state for an update binding ?2 = new state and
// ?3 = optional backend ID. An absence-fenced row never takes this path's tag.
const LEGACY_TRANSITION: &str = "legacy_release = CASE WHEN accounting_kind = 'legacy' THEN CASE
        WHEN ?2 = 'deleted' THEN 'deleted'
        WHEN ?2 = 'failed' AND COALESCE(?3, backend_id) IS NOT NULL THEN 'compensated'
        WHEN ?2 = 'failed' AND create_certainty = 'definitely_not_created' THEN 'definitely_not_created'
    END END,
    disposition = CASE WHEN accounting_kind = 'legacy' AND ?2 = 'ready' THEN 'reusable' ELSE disposition END";

const MIGRATE_V3: &str = "
ALTER TABLE executions ADD COLUMN command_status_kind TEXT;
ALTER TABLE executions ADD COLUMN command_status_value INTEGER;
ALTER TABLE executions ADD COLUMN command_core_dumped INTEGER;
ALTER TABLE executions ADD COLUMN runtime_error TEXT;
PRAGMA user_version = 3;";

const MIGRATE_V4: &str = "
ALTER TABLE executions ADD COLUMN stdout_total_bytes_known INTEGER NOT NULL DEFAULT 0;
ALTER TABLE executions ADD COLUMN stderr_total_bytes_known INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version = 4;";

// Never inferred from history: every existing row becomes ambiguous, whatever
// its failure text says. The CHECK keeps the marker off any row that could own
// a backend. Keep this column definition identical to SCHEMA.
const MIGRATE_V5: &str = "
ALTER TABLE sandboxes ADD COLUMN create_certainty TEXT NOT NULL DEFAULT 'allocation_ambiguous' CHECK (create_certainty = 'allocation_ambiguous' OR (create_certainty = 'definitely_not_created' AND backend_id IS NULL AND state IN ('failed', 'deleted')));
PRAGMA user_version = 5;";

// Never inferred from history or the upgrading caller: every existing row
// belongs to root. Keep this column and index identical to SCHEMA.
const MIGRATE_V7: &str = "
ALTER TABLE sandboxes ADD COLUMN owner_uid INTEGER NOT NULL DEFAULT 0 CHECK (owner_uid BETWEEN 0 AND 4294967295);
CREATE INDEX sandboxes_owner_list_seq ON sandboxes (owner_uid, list_seq DESC);
PRAGMA user_version = 7;";

const SCHEMA: &str = "
CREATE TABLE history_sequence (id INTEGER PRIMARY KEY CHECK(id = 1), value INTEGER NOT NULL);
INSERT INTO history_sequence VALUES (1, 0);
CREATE TABLE sandboxes (
    id             TEXT PRIMARY KEY,
    backend        TEXT NOT NULL,
    backend_id     TEXT,
    state          TEXT NOT NULL,
    spec           TEXT NOT NULL,
    failure_reason TEXT,
    created_at_ms  INTEGER NOT NULL,
    updated_at_ms  INTEGER NOT NULL,
    deleted_at_ms  INTEGER,
    list_seq       INTEGER NOT NULL,
    create_certainty TEXT NOT NULL DEFAULT 'allocation_ambiguous' CHECK (create_certainty = 'allocation_ambiguous' OR (create_certainty = 'definitely_not_created' AND backend_id IS NULL AND state IN ('failed', 'deleted'))),
    owner_uid INTEGER NOT NULL DEFAULT 0 CHECK (owner_uid BETWEEN 0 AND 4294967295)
);
CREATE UNIQUE INDEX sandboxes_backend_id ON sandboxes (backend, backend_id) WHERE backend_id IS NOT NULL;
CREATE INDEX sandboxes_state ON sandboxes (state);
CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);
CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';
CREATE INDEX sandboxes_owner_list_seq ON sandboxes (owner_uid, list_seq DESC);

CREATE TABLE executions (
    id               TEXT PRIMARY KEY,
    sandbox_id       TEXT NOT NULL REFERENCES sandboxes (id),
    argv             TEXT NOT NULL,
    state            TEXT NOT NULL,
    exit_code        INTEGER,
    failure_reason   TEXT,
    timeout_ms       INTEGER NOT NULL,
    stdin_bytes      INTEGER NOT NULL,
    started_at_ms    INTEGER NOT NULL,
    finished_at_ms   INTEGER,
    stdout           BLOB NOT NULL DEFAULT x'',
    stdout_bytes     INTEGER NOT NULL DEFAULT 0,
    stdout_truncated INTEGER NOT NULL DEFAULT 0,
    stdout_total_bytes_known INTEGER NOT NULL DEFAULT 0,
    stderr           BLOB NOT NULL DEFAULT x'',
    stderr_bytes     INTEGER NOT NULL DEFAULT 0,
    stderr_truncated INTEGER NOT NULL DEFAULT 0,
    stderr_total_bytes_known INTEGER NOT NULL DEFAULT 0,
    command_status_kind TEXT,
    command_status_value INTEGER,
    command_core_dumped INTEGER,
    runtime_error TEXT
);
CREATE INDEX executions_sandbox ON executions (sandbox_id, started_at_ms);
CREATE INDEX executions_state ON executions (state);
";

pub struct Store {
    conn: Mutex<Connection>,
    // Declared after the connection so SQLite closes before state ownership
    // is released.
    _instance_lock: Option<ExclusiveFileLock>,
    // Keeps the validated directory inode pinned until after SQLite and the
    // instance lock close.
    _state_directory: Option<File>,
    /// The clocks lifecycle anchors are stamped with; the manager shares its own.
    /// `None` only when the kernel's boot ID could not be read: then nothing is stamped.
    clock: std::sync::RwLock<Option<std::sync::Arc<dyn Clock>>>,
    #[cfg(test)]
    reject_execution_finishes: Arc<AtomicBool>,
    #[cfg(test)]
    reject_evidence_commits: Arc<AtomicBool>,
    /// Runs inside a keyed create's admission transaction, just before it commits:
    /// tests use it to stand for a pause (suspend, SIGSTOP, a stall) at that point.
    #[cfg(test)]
    pub(crate) before_request_commit: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// Makes the next `start_execution` insert nothing, as if the sandbox changed
    /// state just before it: the execution_start_raced path.
    #[cfg(test)]
    pub(crate) lose_execution_starts: AtomicBool,
}

/// How an execution ended, written in one transaction with what it means for its
/// sandbox, so a queued successor reloads the outcome before the slot is released.
pub struct ExecutionResult<'a> {
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub command_status: Option<&'a CommandStatus>,
    pub runtime_error: Option<&'a RuntimeDiagnostic>,
    pub failure_reason: Option<&'a str>,
    pub stdout: &'a Captured,
    pub stderr: &'a Captured,
    pub sandbox_reusable: Option<bool>,
    pub cleanup_evidence: CleanupEvidence,
    /// `None` leaves the sandbox unchanged. `Stopped` turns READY into LOST and
    /// `Quarantined` into QUARANTINED; both stay charged, and DELETING stays DELETING.
    pub disposition: Option<SandboxDisposition>,
    pub disposition_reason: Option<&'a str>,
    /// Why a CANCELED execution was canceled.
    pub cancel_reason: Option<CancelReason>,
}

pub struct SandboxPageRow {
    pub list_seq: i64,
    pub sandbox: Sandbox,
}

pub struct SandboxPage {
    pub rows: Vec<SandboxPageRow>,
    pub upper_seq: i64,
    pub has_more: bool,
}

/// Aggregate resources promised to sandboxes whose lifecycle may still own a
/// backend. This is reservation accounting, not measured live consumption.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SandboxResources {
    pub sandboxes: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub disk_bytes: u64,
    pub host_cpu_millis: u64,
    pub virtual_cpu_slots: u64,
    pub host_pids: u64,
}

impl SandboxResources {
    pub fn for_reservation(r: &ResourceReservation) -> Self {
        Self {
            sandboxes: 1,
            memory_bytes: r.memory_bytes,
            pids: r.pids,
            disk_bytes: r.disk_bytes,
            host_cpu_millis: r.host_cpu_millis,
            virtual_cpu_slots: r.virtual_cpu_slots,
            host_pids: r.host_pids,
        }
    }

    #[cfg(test)]
    fn for_spec(spec: &SandboxSpec) -> Self {
        Self::for_reservation(&ResourceReservation::legacy_for_spec(spec))
    }

    fn checked_add(self, other: Self) -> Result<Self> {
        Ok(Self {
            sandboxes: self
                .sandboxes
                .checked_add(other.sandboxes)
                .context("sandbox reservation count overflow")?,
            memory_bytes: self
                .memory_bytes
                .checked_add(other.memory_bytes)
                .context("sandbox memory reservation overflow")?,
            pids: self
                .pids
                .checked_add(other.pids)
                .context("sandbox PID reservation overflow")?,
            disk_bytes: self
                .disk_bytes
                .checked_add(other.disk_bytes)
                .context("sandbox disk reservation overflow")?,
            host_cpu_millis: self
                .host_cpu_millis
                .checked_add(other.host_cpu_millis)
                .context("sandbox host CPU reservation overflow")?,
            virtual_cpu_slots: self
                .virtual_cpu_slots
                .checked_add(other.virtual_cpu_slots)
                .context("sandbox vCPU reservation overflow")?,
            host_pids: self
                .host_pids
                .checked_add(other.host_pids)
                .context("sandbox host PID reservation overflow")?,
        })
    }
}

/// The durable node-wide reservation ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxBudgets {
    pub sandboxes: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub disk_bytes: u64,
    pub host_cpu_millis: u64,
    pub virtual_cpu_slots: u64,
    pub host_pids: u64,
}

/// This database's durable identity, generated once and never changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaemonIdentity {
    pub database_uuid: Id128,
    pub instance_id: Id128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    pub resource: &'static str,
    pub reserved: u64,
    pub requested: u64,
    pub limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveSandbox {
    Inserted,
    Exhausted(BudgetExhausted),
    /// The request records are at a cap (design 3.3): nothing was inserted.
    RequestQuota(RequestQuota),
    /// Another create already recorded this key: nothing was inserted.
    RequestIdTaken,
}

/// What a keyed create's admitting transaction checks and records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestAdmission {
    pub sha256: Digest,
    pub max_per_uid: u64,
    pub max_node: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestQuota {
    /// `uid` or `node`.
    pub scope: &'static str,
    pub count: u64,
    pub limit: u64,
}

/// Durable create request records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestCounts {
    pub node: u64,
    pub uid: u64,
}

/// What `release_request_id` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRequestId {
    Released,
    /// The sandbox is DELETED and has no record: never keyed, released or pruned.
    NoRecord,
    /// Not DELETED (or quarantined): nothing is released and nothing remembered.
    NotDeleted,
    NoSandbox,
}

// From the counters the record triggers keep (break-it M2 MEDIUM 2): two primary-key
// reads, never a count over the records. The full audit checks them against the
// records themselves.
fn request_counts(conn: &Connection, owner_uid: u32) -> Result<RequestCounts> {
    let (node, uid): (i64, i64) = conn.query_row(
        "SELECT (SELECT records FROM create_request_counts WHERE owner_uid = -1),
                COALESCE((SELECT records FROM create_request_counts WHERE owner_uid = ?1), 0)",
        [owner_uid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(RequestCounts {
        node: u64::try_from(node)?,
        uid: u64::try_from(uid)?,
    })
}

/// Which create request records [`remove_request_records`] may delete.
enum RecordRemoval<'a> {
    /// R3: this boot's records retained at least to `cutoff_boottime_ms`.
    Prune {
        boot_id: &'a str,
        cutoff_boottime_ms: i64,
    },
    /// Design 3.4: one sandbox's record.
    Release { sandbox_id: &'a str },
}

/// R5: the only path that deletes create request records. In the caller's IMMEDIATE
/// transaction, after `audit_accounting`, it rechecks each record's sandbox: DELETED
/// or released FAILED for prune, DELETED for release, never a quarantined row. A
/// trigger refuses any other delete.
fn remove_request_records(tx: &Connection, removal: RecordRemoval<'_>) -> Result<usize> {
    Ok(match removal {
        RecordRemoval::Prune {
            boot_id,
            cutoff_boottime_ms,
        } => tx.execute(
            &format!(
                "DELETE FROM create_requests WHERE retain_boot_id = ?1 AND retain_from_boottime_ms <= ?2
                 AND sandbox_id IN (SELECT id FROM sandboxes
                     WHERE id NOT IN (SELECT id FROM temp.accounting_quarantine)
                       AND (state = 'deleted' OR (state = 'failed' AND NOT ({RESERVED_SANDBOX_WHERE}))))"
            ),
            params![boot_id, cutoff_boottime_ms],
        )?,
        RecordRemoval::Release { sandbox_id } => tx.execute(
            "DELETE FROM create_requests WHERE sandbox_id = ?1
             AND sandbox_id IN (SELECT id FROM sandboxes WHERE id = ?1 AND state = 'deleted'
                 AND id NOT IN (SELECT id FROM temp.accounting_quarantine))",
            [sandbox_id],
        )?,
    })
}

/// Design 3.3 R1 (break-it HIGH 1): give every unanchored create request record
/// this boot's ID and current boottime, in an IMMEDIATE transaction of its own that
/// reads the clocks only once it holds the write lock. Every record it can see was
/// committed before then, so each anchor is no earlier than its record's commit.
fn anchor_create_requests(conn: &mut Connection, clock: &dyn Clock) -> Result<usize> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let anchored = anchor_unanchored(&tx, clock)?;
    tx.commit()?;
    Ok(anchored)
}

/// As [`anchor_create_requests`], in the caller's IMMEDIATE transaction.
fn anchor_unanchored(tx: &Connection, clock: &dyn Clock) -> Result<usize> {
    let now = ClockReading::now(clock);
    Ok(tx.execute(
        "UPDATE create_requests SET retain_boot_id = ?1, retain_from_boottime_ms = ?2 WHERE retain_boot_id IS NULL",
        params![now.boot_id, now.boottime_ms],
    )?)
}

fn i64_amount(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{what} {value} exceeds the stored range"))
}

fn insert_sandbox(conn: &Connection, sandbox: &Sandbox) -> Result<()> {
    insert_sandbox_env(conn, sandbox, None)
}

/// [`insert_sandbox`] with the sandbox's default env values, the stored form of
/// `exec_env::encode_stored`; its names and digest come from the row itself.
fn insert_sandbox_env(conn: &Connection, sandbox: &Sandbox, default_env: Option<&str>) -> Result<()> {
    let accounting = &sandbox.accounting;
    let lifecycle = &sandbox.lifecycle;
    let reservation = accounting.reservation;
    let allocation = accounting.allocation.as_ref();
    let fenced = sandbox.is_fenced();
    // The tag is schema 7's predicate over this row, never a caller's claim.
    let legacy_release = (!fenced)
        .then(|| {
            LegacyRelease::for_row(
                sandbox.state,
                sandbox.backend_id.as_deref(),
                sandbox.create_certainty,
            )
        })
        .flatten();
    let release_evidence_id = match accounting.release {
        ReservationRelease::Fenced(receipt) => Some(receipt.to_string()),
        _ => None,
    };
    // The counter survives retention, so an old page watermark excludes new inserts.
    conn.execute(
        "UPDATE history_sequence SET value = value + 1 WHERE id = 1",
        [],
    )?;
    conn.execute(
        "INSERT INTO sandboxes (id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, create_certainty, owner_uid,
            accounting_kind, reserved_memory_bytes, reserved_disk_bytes, reserved_pids, reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids,
            host_spec_sha256, guest_exec_spec_sha256, runtime_profile, runtime_artifact_digest, disposition, boot_id, legacy_release,
            node_id, instance_id, allocation_id, plan_version, plan_digest, plan, release_evidence_id, last_helper_generation,
            expiry_lifetime_ms, expiry_idle_ms, ready_at_ms, ready_boottime_ms, activity_at_ms, activity_boottime_ms, clock_boot_id,
            activity_seq, deletion_reason, request_id, default_env, default_env_names, default_env_sha256, exec_features, list_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33,
            ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, (SELECT value FROM history_sequence WHERE id = 1))",
        params![
            sandbox.id,
            sandbox.backend,
            sandbox.backend_id,
            sandbox.state.as_str(),
            serde_json::to_string(&sandbox.spec)?,
            sandbox.failure_reason,
            sandbox.created_at_ms,
            sandbox.updated_at_ms,
            sandbox.deleted_at_ms,
            sandbox.create_certainty.as_str(),
            sandbox.owner_uid,
            if fenced { "fenced" } else { "legacy" },
            i64_amount(reservation.memory_bytes, "reserved memory")?,
            i64_amount(reservation.disk_bytes, "reserved disk")?,
            i64_amount(reservation.pids, "reserved PIDs")?,
            i64_amount(reservation.host_cpu_millis, "reserved host CPU")?,
            i64_amount(reservation.virtual_cpu_slots, "reserved vCPU slots")?,
            i64_amount(reservation.host_pids, "reserved host PIDs")?,
            accounting.host_spec_sha256.to_string(),
            accounting.guest_exec_spec_sha256.to_string(),
            accounting.runtime_profile,
            accounting.runtime_artifact_digest,
            accounting.disposition.as_str(),
            accounting.boot_id,
            legacy_release.map(LegacyRelease::as_str),
            allocation.map(|a| a.node_id.to_string()),
            allocation.map(|a| a.instance_id.to_string()),
            allocation.map(|a| a.allocation_id.to_string()),
            allocation.map(|a| a.plan_version),
            allocation.map(|a| a.plan_digest.to_string()),
            allocation.map(|a| a.plan.as_slice()),
            release_evidence_id,
            accounting
                .last_helper_generation
                .map(|generation| i64_amount(generation, "helper generation"))
                .transpose()?,
            lifecycle
                .expiry
                .max_lifetime_ms
                .map(|ms| i64_amount(ms, "expiry lifetime"))
                .transpose()?,
            lifecycle
                .expiry
                .idle_timeout_ms
                .map(|ms| i64_amount(ms, "expiry idle timeout"))
                .transpose()?,
            lifecycle.ready_at_ms,
            lifecycle.ready_boottime_ms,
            lifecycle.activity_at_ms,
            lifecycle.activity_boottime_ms,
            lifecycle.clock_boot_id,
            lifecycle.activity_seq,
            lifecycle.deletion_reason.map(DeletionReason::as_str),
            lifecycle.request_id,
            default_env,
            names_column(&lifecycle.default_env_names)?,
            lifecycle.default_env_sha256,
            lifecycle.exec_features,
        ],
    )?;
    Ok(())
}

/// A names column: a JSON array, or null for none.
fn names_column(names: &[String]) -> Result<Option<String>> {
    Ok((!names.is_empty())
        .then(|| serde_json::to_string(names))
        .transpose()?)
}

fn parse_names(text: Option<String>, what: &str) -> Result<Vec<String>> {
    match text {
        None => Ok(Vec::new()),
        Some(text) => serde_json::from_str(&text).with_context(|| format!("bad {what}")),
    }
}

/// A schema 8-10 row, for migration tests of those schemas.
#[cfg(test)]
fn insert_sandbox_before_v11(conn: &Connection, sandbox: &Sandbox) -> Result<()> {
    let accounting = &sandbox.accounting;
    let reservation = accounting.reservation;
    let allocation = accounting.allocation.as_ref();
    let fenced = sandbox.is_fenced();
    // The tag is schema 7's predicate over this row, never a caller's claim.
    let legacy_release = (!fenced)
        .then(|| {
            LegacyRelease::for_row(
                sandbox.state,
                sandbox.backend_id.as_deref(),
                sandbox.create_certainty,
            )
        })
        .flatten();
    let release_evidence_id = match accounting.release {
        ReservationRelease::Fenced(receipt) => Some(receipt.to_string()),
        _ => None,
    };
    // The counter survives retention, so an old page watermark excludes new inserts.
    conn.execute(
        "UPDATE history_sequence SET value = value + 1 WHERE id = 1",
        [],
    )?;
    conn.execute(
        "INSERT INTO sandboxes (id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, create_certainty, owner_uid,
            accounting_kind, reserved_memory_bytes, reserved_disk_bytes, reserved_pids, reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids,
            host_spec_sha256, guest_exec_spec_sha256, runtime_profile, runtime_artifact_digest, disposition, boot_id, legacy_release,
            node_id, instance_id, allocation_id, plan_version, plan_digest, plan, release_evidence_id, last_helper_generation, list_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33,
            (SELECT value FROM history_sequence WHERE id = 1))",
        params![
            sandbox.id,
            sandbox.backend,
            sandbox.backend_id,
            sandbox.state.as_str(),
            serde_json::to_string(&sandbox.spec)?,
            sandbox.failure_reason,
            sandbox.created_at_ms,
            sandbox.updated_at_ms,
            sandbox.deleted_at_ms,
            sandbox.create_certainty.as_str(),
            sandbox.owner_uid,
            if fenced { "fenced" } else { "legacy" },
            i64_amount(reservation.memory_bytes, "reserved memory")?,
            i64_amount(reservation.disk_bytes, "reserved disk")?,
            i64_amount(reservation.pids, "reserved PIDs")?,
            i64_amount(reservation.host_cpu_millis, "reserved host CPU")?,
            i64_amount(reservation.virtual_cpu_slots, "reserved vCPU slots")?,
            i64_amount(reservation.host_pids, "reserved host PIDs")?,
            accounting.host_spec_sha256.to_string(),
            accounting.guest_exec_spec_sha256.to_string(),
            accounting.runtime_profile,
            accounting.runtime_artifact_digest,
            accounting.disposition.as_str(),
            accounting.boot_id,
            legacy_release.map(LegacyRelease::as_str),
            allocation.map(|a| a.node_id.to_string()),
            allocation.map(|a| a.instance_id.to_string()),
            allocation.map(|a| a.allocation_id.to_string()),
            allocation.map(|a| a.plan_version),
            allocation.map(|a| a.plan_digest.to_string()),
            allocation.map(|a| a.plan.as_slice()),
            release_evidence_id,
            accounting
                .last_helper_generation
                .map(|generation| i64_amount(generation, "helper generation"))
                .transpose()?,
        ],
    )?;
    Ok(())
}

/// The host's clocks, or none: without a boot ID nothing may be stamped as this
/// boot's (a fixed stand-in would let another boot's anchors pass as ours), so every
/// write that stamps an anchor then fails instead.
fn default_clock() -> Option<std::sync::Arc<dyn Clock>> {
    crate::expiry::SystemClock::new()
        .ok()
        .map(|clock| std::sync::Arc::new(clock) as std::sync::Arc<dyn Clock>)
}

/// Stamps the first READY publication's anchors, in the caller's transaction. Later
/// READY publications (a recovered LOST row) keep the first.
fn stamp_first_ready(conn: &Connection, id: &str, now: &ClockReading) -> Result<()> {
    conn.execute(
        "UPDATE sandboxes SET ready_at_ms = ?2, ready_boottime_ms = ?3, activity_at_ms = ?2,
             activity_boottime_ms = ?3, clock_boot_id = ?4
         WHERE id = ?1 AND state = 'ready' AND ready_boottime_ms IS NULL",
        params![id, now.wall_ms, now.boottime_ms, now.boot_id],
    )?;
    Ok(())
}

/// Records one activity (design 2.1) in the caller's transaction. A row that was
/// never READY only bumps its sequence: no clock runs before READY.
///
/// MEDIUM 2: startup's terminal publications run before the cross-boot rebase. A row
/// still anchored in another boot gets only the wall anchor, and keeps that boot's
/// boottime and ID; the rebase then derives this boot's activity anchor from the new
/// wall time, so neither anchor is stranded in a boot the other has left. Without a
/// clock (no boot ID), only the sequence moves.
fn record_activity(conn: &Connection, id: &str, now: Option<&ClockReading>) -> Result<()> {
    let Some(now) = now else {
        conn.execute(
            "UPDATE sandboxes SET activity_seq = activity_seq + 1 WHERE id = ?1",
            [id],
        )?;
        return Ok(());
    };
    conn.execute(
        "UPDATE sandboxes SET activity_seq = activity_seq + 1,
             activity_at_ms = CASE WHEN ready_boottime_ms IS NULL THEN activity_at_ms ELSE ?2 END,
             activity_boottime_ms = CASE WHEN ready_boottime_ms IS NULL OR clock_boot_id IS NOT ?4
                 THEN activity_boottime_ms ELSE ?3 END
         WHERE id = ?1",
        params![id, now.wall_ms, now.boottime_ms, now.boot_id],
    )?;
    Ok(())
}

fn sandbox_resources(conn: &Connection) -> Result<SandboxResources> {
    // Amounts come only from the stored vector: a later change to defaults, a
    // bundle or a formula cannot reprice an existing commitment.
    let mut statement = conn.prepare(&format!(
        "SELECT id, reserved_memory_bytes, reserved_disk_bytes, reserved_pids, reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids
         FROM sandboxes WHERE id IN (SELECT id FROM sandboxes WHERE {RESERVED_SANDBOX_WHERE}
             UNION SELECT id FROM temp.accounting_quarantine)"
    ))?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            [
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ],
        ))
    })?;
    let mut resources = SandboxResources::default();
    for row in rows {
        let (id, amounts) = row?;
        let amount = |index: usize| {
            u64::try_from(amounts[index])
                .with_context(|| format!("sandbox {id}: negative stored reservation"))
        };
        resources =
            resources.checked_add(SandboxResources::for_reservation(&ResourceReservation {
                memory_bytes: amount(0)?,
                disk_bytes: amount(1)?,
                pids: amount(2)?,
                host_cpu_millis: amount(3)?,
                virtual_cpu_slots: amount(4)?,
                host_pids: amount(5)?,
            }))?;
    }
    Ok(resources)
}

fn exhausted_budget(
    reserved: SandboxResources,
    requested: SandboxResources,
    budgets: SandboxBudgets,
) -> Result<Option<BudgetExhausted>> {
    for (resource, reserved, requested, limit) in [
        (
            "sandboxes",
            reserved.sandboxes,
            requested.sandboxes,
            budgets.sandboxes,
        ),
        (
            "memory bytes",
            reserved.memory_bytes,
            requested.memory_bytes,
            budgets.memory_bytes,
        ),
        ("PIDs", reserved.pids, requested.pids, budgets.pids),
        (
            "disk bytes",
            reserved.disk_bytes,
            requested.disk_bytes,
            budgets.disk_bytes,
        ),
        (
            "host CPU millis",
            reserved.host_cpu_millis,
            requested.host_cpu_millis,
            budgets.host_cpu_millis,
        ),
        (
            "vCPU slots",
            reserved.virtual_cpu_slots,
            requested.virtual_cpu_slots,
            budgets.virtual_cpu_slots,
        ),
        (
            "host PIDs",
            reserved.host_pids,
            requested.host_pids,
            budgets.host_pids,
        ),
    ] {
        let total = reserved
            .checked_add(requested)
            .with_context(|| format!("{resource} reservation overflow"))?;
        if total > limit {
            return Ok(Some(BudgetExhausted {
                resource,
                reserved,
                requested,
                limit,
            }));
        }
    }
    Ok(None)
}

impl Store {
    /// Opens or creates the database in `dir`. Existing path components are
    /// validated before missing components are created descriptor-relatively;
    /// the final directory must be owned by the effective uid and exactly
    /// 0700. A process-lifetime lock is acquired before SQLite is opened.
    pub fn open(dir: &Path) -> Result<Self> {
        let directory = prepare_directory(dir)?;
        let instance_lock = ExclusiveFileLock::acquire_at(
            &directory.file,
            OsStr::new("kilnd.lock"),
            &directory.path.join("kilnd.lock"),
            "state directory",
        )?;
        let database_path = directory.path.join("kilnd.db");
        let expected_uid = unsafe { libc::geteuid() };
        // Nothing below opens a descriptor to the database or a sidecar, before SQLite
        // or after: closing any descriptor to a file drops every POSIX lock this process
        // holds on it, SQLite's included. A dropped lock lets another connection (an
        // operator's sqlite3, a backup) believe it is the last one, checkpoint and unlink
        // the live WAL, and everything the daemon commits afterwards would then go to an
        // unlinked file and be lost at its next crash (B6). Entries are only stat'ed.
        let existing = inspect_database_entry(
            &directory.file,
            OsStr::new("kilnd.db"),
            &database_path,
            expected_uid,
        )?;
        inspect_sqlite_sidecars(&directory, expected_uid)?;
        // A new database is created here, exclusively and 0600 whatever the umask, and
        // closed before SQLite opens it; SQLite gives its sidecars the same mode.
        let existing = match existing {
            Some(existing) => existing,
            None => create_database_entry(&directory.file, &database_path, expected_uid)?,
        };
        let conn = Connection::open_with_flags(
            &database_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("open database without following symlinks")?;
        let opened = inspect_database_entry(
            &directory.file,
            OsStr::new("kilnd.db"),
            &database_path,
            expected_uid,
        )?
        .context("kilnd.db vanished while opening")?;
        if existing.identity() != opened.identity() {
            bail!("{} changed while opening", database_path.display());
        }
        let store = Self::init_with_directory(
            conn,
            Some(instance_lock),
            Some(directory.file.try_clone()?),
        )?;
        validate_directory(
            &directory.file.metadata()?,
            &directory.path,
            expected_uid,
            true,
            "state",
        )?;
        let reopened = inspect_database_entry(
            &directory.file,
            OsStr::new("kilnd.db"),
            &database_path,
            expected_uid,
        )?
        .context("kilnd.db vanished after opening")?;
        if reopened.identity() != opened.identity() {
            bail!("{} changed while opening", database_path.display());
        }
        inspect_sqlite_sidecars(&directory, expected_uid)?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?, None)
    }

    /// Device/inode identity of the pinned on-disk state directory. In-memory
    /// stores have no directory identity.
    pub fn state_directory_identity(&self) -> Result<Option<(u64, u64)>> {
        self._state_directory
            .as_ref()
            .map(|directory| {
                directory
                    .metadata()
                    .map(|metadata| (metadata.dev(), metadata.ino()))
                    .context("inspect pinned state directory")
            })
            .transpose()
    }

    fn init(conn: Connection, instance_lock: Option<ExclusiveFileLock>) -> Result<Self> {
        Self::init_with_directory(conn, instance_lock, None)
    }

    fn init_with_directory(
        conn: Connection,
        instance_lock: Option<ExclusiveFileLock>,
        state_directory: Option<File>,
    ) -> Result<Self> {
        // Move both resources into their final drop order before any
        // fallible SQLite setup. This also makes initialization failures
        // close SQLite before releasing state-directory ownership.
        let store = Self {
            conn: Mutex::new(conn),
            _instance_lock: instance_lock,
            _state_directory: state_directory,
            clock: std::sync::RwLock::new(default_clock()),
            #[cfg(test)]
            reject_execution_finishes: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            reject_evidence_commits: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            before_request_commit: Mutex::new(None),
            #[cfg(test)]
            lose_execution_starts: AtomicBool::new(false),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<()> {
        let mut conn = self.conn();
        register_receipt_validator(&conn)?;
        conn.pragma_update(None, "trusted_schema", "OFF")?;
        let trusted: i64 = conn.pragma_query_value(None, "trusted_schema", |r| r.get(0))?;
        if trusted != 0 {
            bail!("SQLite refused trusted_schema=OFF");
        }
        conn.execute_batch(
            "CREATE TEMP TABLE accounting_quarantine (id TEXT PRIMARY KEY);
             CREATE TEMP TABLE membership_lost (id INTEGER PRIMARY KEY CHECK (id = 1));
             CREATE TEMP TABLE membership_verified (id INTEGER PRIMARY KEY CHECK (id = 1), data_version INTEGER NOT NULL);",
        )?;
        // Evidence references depend on this, and SQLite ignores it inside a
        // transaction and defaults it off per connection. Set and verify it first.
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let foreign_keys: i64 = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
        if foreign_keys != 1 {
            bail!("SQLite refused to enforce foreign keys on this connection");
        }
        // Defense in depth; BEFORE collision guards protect other connections too.
        conn.pragma_update(None, "recursive_triggers", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == SCHEMA_VERSION {
            let tx = conn.transaction()?;
            audit_accounting_full(&tx)?;
            tx.commit()?;
            return Ok(());
        }
        if !(0..SCHEMA_VERSION).contains(&version) {
            bail!("database schema version {version} is newer than this kilnd ({SCHEMA_VERSION})");
        }
        // Every older schema reaches 7 through its existing steps, then the one v8
        // step, all in one transaction: any failure leaves the old database intact.
        let tx = conn.transaction()?;
        if version == 0 {
            tx.execute_batch(SCHEMA)?;
        }
        if version == 1 {
            tx.execute_batch("ALTER TABLE sandboxes ADD COLUMN list_seq INTEGER;
                WITH ordered AS (
                    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at_ms ASC, id DESC) AS seq FROM sandboxes
                )
                UPDATE sandboxes SET list_seq = (SELECT seq FROM ordered WHERE ordered.id = sandboxes.id);
                CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);
                CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';
                PRAGMA user_version = 2;")?;
        }
        if (1..3).contains(&version) {
            tx.execute_batch(MIGRATE_V3)?;
        }
        if (1..4).contains(&version) {
            tx.execute_batch(MIGRATE_V4)?;
        }
        if (1..5).contains(&version) {
            tx.execute_batch(MIGRATE_V5)?;
        }
        if (1..6).contains(&version) {
            tx.execute_batch(MIGRATE_V6)?;
        }
        if (1..7).contains(&version) {
            tx.execute_batch(MIGRATE_V7)?;
        }
        if version < 8 {
            migrate_v8(&tx)?;
        }
        if version < 9 {
            // Use the production decoder directly, including unreferenced evidence.
            let mut stmt = tx.prepare("SELECT receipt, receipt_id, node_id, instance_id, allocation_id, plan_digest, helper_generation, kind FROM release_evidence")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let valid = (|| -> Result<bool> {
                    let receipt = FencedAbsence::decode(&row.get::<_, Vec<u8>>(0)?)
                        .map_err(anyhow::Error::msg)?;
                    let fields = [
                        receipt.receipt_id().to_string(),
                        receipt.node_id().to_string(),
                        receipt.instance_id().to_string(),
                        receipt.allocation_id().to_string(),
                        receipt.plan_digest().to_string(),
                    ];
                    for (i, field) in (1..=5).zip(fields) {
                        if row.get::<_, String>(i)? != field {
                            return Ok(false);
                        }
                    }
                    Ok(row.get::<_, i64>(6)? == receipt.helper_generation() as i64
                        && row.get::<_, String>(7)? == "absent_fenced")
                })()
                .unwrap_or(false);
                if !valid {
                    bail!("schema 8 contains invalid AbsentFenced receipts");
                }
            }
            drop(rows);
            drop(stmt);
            tx.execute_batch(MIGRATE_V9)?;
        }
        if version >= 12 {
            // Schema 12's aggregates are audited as they stand below, after the
            // additive steps: the schema 13 and 14 columns are not membership.
        } else if version < 10 {
            // Schema 10 introduces the membership marker: seed it from the rows
            // this one transaction has just migrated.
            tx.execute_batch(MIGRATE_V10)?;
            refresh_reservation_integrity(&tx)?;
        } else {
            // Break-it MEDIUM 3: a schema 10 or 11 database already has a marker.
            // Audit it as it stands, before anything else changes: the schema 11 and
            // 12 columns are not membership. A mismatch refuses startup and rolls the
            // whole migration back, leaving the old schema and its marker untouched.
            audit_reservation_integrity_v1(&tx).with_context(|| {
                format!(
                    "schema {version} reservation integrity does not match; refusing to migrate to schema {SCHEMA_VERSION}"
                )
            })?;
        }
        if version < 11 {
            tx.execute_batch(MIGRATE_V11)?;
        }
        // The marker verified above (or just written from the migrated rows) is
        // replaced by schema 12's aggregates, seeded from the same rows.
        if version < 12 {
            tx.execute_batch(MIGRATE_V12)?;
            refresh_membership(&tx)?;
        }
        if version < 13 {
            tx.execute_batch(MIGRATE_V13)?;
        }
        tx.execute_batch(MIGRATE_V14)?;
        audit_accounting_full(&tx)?;
        tx.commit()
            .with_context(|| format!("migrate schema v{version} to v{SCHEMA_VERSION}"))?;
        Ok(())
    }

    /// A read decision: one snapshot, audited first, then `read`. It commits on
    /// success, so a full verification the audit ran (its stamp and the quarantine
    /// it rebuilt, both temp-only) is kept and the next read stays bounded (M2 fix
    /// review); on an error everything it did rolls back together.
    fn audited_read<T>(&self, read: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut connection = self.conn();
        let tx = connection.transaction()?;
        audit_accounting(&tx)?;
        let value = read(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock can't leave SQLite inconsistent;
        // each statement is atomic.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn identity(&self) -> Result<DaemonIdentity> {
        let (database_uuid, instance_id): (String, String) = self.conn().query_row(
            "SELECT database_uuid, instance_id FROM daemon_identity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(DaemonIdentity {
            database_uuid: Id128::parse(&database_uuid).map_err(anyhow::Error::msg)?,
            instance_id: Id128::parse(&instance_id).map_err(anyhow::Error::msg)?,
        })
    }

    /// B7 RTC-14: the complete allocation token with the highest sequence among this
    /// instance's fenced rows and its permanent release evidence, or none. A token's hex
    /// prefix is its big-endian sequence, so the text maximum is the sequence maximum.
    /// It is rollback evidence for the helper, which verifies its tag; never authority.
    pub fn highest_fenced_token(&self, instance: Id128) -> Result<Option<Id128>> {
        let highest: Option<String> = self.conn().query_row(
            "SELECT MAX(allocation_id) FROM (
                SELECT allocation_id FROM sandboxes
                 WHERE accounting_kind = 'fenced' AND instance_id = ?1
                UNION ALL
                SELECT allocation_id FROM release_evidence WHERE instance_id = ?1)",
            [instance.to_string()],
            |row| row.get(0),
        )?;
        highest
            .map(|text| Id128::parse(&text).map_err(anyhow::Error::msg))
            .transpose()
    }

    pub fn insert_sandbox(&self, s: &Sandbox) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if audit_accounting(&tx)? {
            bail!("degraded accounting: quarantined release evidence");
        }
        settle_unsettled(&tx)?;
        insert_sandbox(&tx, s)?;
        note_inserted_sandbox(&tx, &s.id)?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically checks every durable node reservation and inserts the new
    /// CREATING row. The IMMEDIATE transaction makes the sum-and-insert one
    /// decision even if another SQLite writer ignores kilnd's instance lock.
    pub fn reserve_sandbox(&self, s: &Sandbox, budgets: SandboxBudgets) -> Result<ReserveSandbox> {
        self.reserve_keyed_sandbox(s, budgets, None)
    }

    /// As [`Self::reserve_sandbox`], and for a keyed create (design 3.1 step 6) the
    /// same transaction recounts the durable request records against both caps,
    /// refuses a key another create already holds, and inserts the record: the
    /// CREATING row and its record commit together. The record commits unanchored,
    /// so no prune can select it, and gets this boot's retention anchor in a second
    /// transaction that reads the boot clock only after the first committed (design
    /// 3.3 R1; break-it HIGH 1). No pause anywhere before that commit can eat into
    /// the window, which therefore starts no earlier than the commit.
    pub fn reserve_keyed_sandbox(
        &self,
        s: &Sandbox,
        budgets: SandboxBudgets,
        request: Option<&RequestAdmission>,
    ) -> Result<ReserveSandbox> {
        self.reserve_sandbox_with_env(s, budgets, request, &[])
    }

    /// As [`Self::reserve_keyed_sandbox`], inserting the sandbox's default env values
    /// with its row (design 4.2). Their names and digest must be the row's own.
    pub fn reserve_sandbox_with_env(
        &self,
        s: &Sandbox,
        budgets: SandboxBudgets,
        request: Option<&RequestAdmission>,
        default_env: &[crate::exec_env::EnvVar],
    ) -> Result<ReserveSandbox> {
        let stored = if default_env.is_empty() {
            None
        } else {
            if s.lifecycle.default_env_names != crate::exec_env::env_names(default_env)
                || s.lifecycle.default_env_sha256 != crate::exec_env::env_sha256(default_env)
            {
                bail!("sandbox {}: default env names or digest do not match its values", s.id);
            }
            Some(crate::exec_env::encode_stored(default_env)?)
        };
        // A keyed create needs the boot clock to anchor its record: refuse before
        // anything is written if there is none. This reading is display only.
        let reading = match request {
            Some(_) => Some(self.clock_reading()?),
            None => None,
        };
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if audit_accounting(&tx)? {
            bail!("degraded accounting: quarantined release evidence; admission disabled");
        }
        // A refusal below commits too, so the settling (and a fresh verification's
        // stamp) is kept: refusals at a cap never pile up rehashing.
        settle_unsettled(&tx)?;
        if let Some(request) = request {
            let request_id = s
                .lifecycle
                .request_id
                .as_deref()
                .context("a keyed create's row names its request ID")?;
            let taken: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM create_requests WHERE owner_uid = ?1 AND request_id = ?2)",
                params![s.owner_uid, request_id],
                |r| r.get(0),
            )?;
            if taken {
                tx.commit()?;
                return Ok(ReserveSandbox::RequestIdTaken);
            }
            let counts = request_counts(&tx, s.owner_uid)?;
            if counts.uid >= request.max_per_uid {
                tx.commit()?;
                return Ok(ReserveSandbox::RequestQuota(RequestQuota {
                    scope: "uid",
                    count: counts.uid,
                    limit: request.max_per_uid,
                }));
            }
            if counts.node >= request.max_node {
                tx.commit()?;
                return Ok(ReserveSandbox::RequestQuota(RequestQuota {
                    scope: "node",
                    count: counts.node,
                    limit: request.max_node,
                }));
            }
        } else if s.lifecycle.request_id.is_some() {
            bail!("an unkeyed create cannot name a request ID");
        }
        let reserved = sandbox_resources(&tx)?;
        let requested = SandboxResources::for_reservation(&s.accounting.reservation);
        if let Some(exhausted) = exhausted_budget(reserved, requested, budgets)? {
            tx.commit()?;
            return Ok(ReserveSandbox::Exhausted(exhausted));
        }
        insert_sandbox_env(&tx, s, stored.as_deref())?;
        if let (Some(request), Some(now)) = (request, &reading) {
            tx.execute(
                "INSERT INTO create_requests (owner_uid, request_id, request_sha256, sandbox_id, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    s.owner_uid,
                    s.lifecycle.request_id,
                    request.sha256.to_string(),
                    s.id,
                    now.wall_ms,
                ],
            )?;
        }
        note_inserted_sandbox(&tx, &s.id)?;
        #[cfg(test)]
        if let (Some(_), Some(pause)) = (request, &*self.before_request_commit.lock().unwrap()) {
            pause();
        }
        tx.commit()?;
        if request.is_some() {
            // The row and its record are committed: whatever happens here, the create
            // goes on. A record left unanchored is never pruned; the next prune or the
            // startup rebase anchors it, later still.
            let anchored = self
                .clock_source()
                .and_then(|clock| anchor_create_requests(&mut conn, &*clock));
            if let Err(error) = anchored {
                tracing::warn!(sandbox = %s.id, error = %format!("{error:#}"), "create request record left unanchored until the next prune");
            }
        }
        Ok(ReserveSandbox::Inserted)
    }

    /// Design 3.1 step 3: the caller's record for `request_id` and its sandbox, read in
    /// one snapshot, so the answer and the record it came from are one observation.
    pub fn create_request(
        &self,
        owner_uid: u32,
        request_id: &str,
    ) -> Result<Option<(Digest, Sandbox)>> {
        self.audited_read(|conn| {
            let record: Option<(String, String)> = conn
                .query_row(
                    "SELECT request_sha256, sandbox_id FROM create_requests WHERE owner_uid = ?1 AND request_id = ?2",
                    params![owner_uid, request_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((sha256, sandbox_id)) = record else {
                return Ok(None);
            };
            let sha256 = Digest::parse(&sha256).map_err(anyhow::Error::msg)?;
            let sandbox = conn
                .query_row(
                    &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                    [&sandbox_id],
                    sandbox_row,
                )
                .optional()?
                .transpose()?
                .with_context(|| format!("create request record names missing sandbox {sandbox_id}"))?;
            Ok(Some((sha256, sandbox)))
        })
    }

    /// Durable request records on the node and of `owner_uid`.
    pub fn create_request_counts(&self, owner_uid: u32) -> Result<RequestCounts> {
        request_counts(&self.conn(), owner_uid)
    }

    /// Design 3.3 R2: after reconciliation and before admission, any prune or any keyed
    /// lookup, one IMMEDIATE transaction gives every record anchored in another boot
    /// this boot's ID and current boottime, a fresh full retention window, never a
    /// wall-clock estimate. A crash leaves every record rebased or still foreign, and
    /// a foreign record is never pruned. Returns how many it rebased.
    /// An unanchored record (its create's anchor transaction never ran) is
    /// anchored the same way. The clocks are read inside the transaction, after
    /// every record it can see committed.
    pub fn rebase_create_requests(&self) -> Result<usize> {
        let clock = self.clock_source()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = ClockReading::now(&*clock);
        let rebased = tx.execute(
            "UPDATE create_requests SET retain_boot_id = ?1, retain_from_boottime_ms = ?2 WHERE retain_boot_id IS NOT ?1",
            params![now.boot_id, now.boottime_ms],
        )?;
        tx.commit()?;
        Ok(rebased)
    }

    /// Design 3.4: if the sandbox is DELETED, in one IMMEDIATE transaction that sees
    /// it DELETED, drop its create request record through the prune-safe path and
    /// stamp `request_id_released_at_ms`. Anything else changes nothing.
    pub fn release_request_id(&self, sandbox_id: &str) -> Result<ReleaseRequestId> {
        let now = now_ms();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_accounting(&tx)?;
        settle_unsettled(&tx)?;
        let deleted: Option<bool> = tx
            .query_row(
                "SELECT state = 'deleted' AND id NOT IN (SELECT id FROM temp.accounting_quarantine)
                 FROM sandboxes WHERE id = ?1",
                [sandbox_id],
                |r| r.get(0),
            )
            .optional()?;
        // Every answer commits: the audit's and the settling's bookkeeping is kept.
        let answer = match deleted {
            None => Some(ReleaseRequestId::NoSandbox),
            Some(false) => Some(ReleaseRequestId::NotDeleted),
            Some(true) if remove_request_records(&tx, RecordRemoval::Release { sandbox_id })? == 0 => {
                Some(ReleaseRequestId::NoRecord)
            }
            Some(true) => None,
        };
        if let Some(answer) = answer {
            tx.commit()?;
            return Ok(answer);
        }
        tx.execute(
            "UPDATE sandboxes SET request_id_released_at_ms = ?2 WHERE id = ?1",
            params![sandbox_id, now],
        )?;
        tx.commit()?;
        Ok(ReleaseRequestId::Released)
    }

    /// Reservations survive daemon restart because they are stored with the
    /// lifecycle rows. On a legacy row, LOST stays reserved because it may recover
    /// to READY; FAILED without a backend ID stays reserved because Runtime::create
    /// errors may be ambiguous after allocating an unreported backend, unless
    /// `fail_create_definitely` recorded typed proof that nothing was allocated.
    /// FAILED with a backend ID is written only after compensation proved
    /// that exact backend gone, so it releases capacity while retaining the
    /// historical row. Ambiguous no-ID failures require authoritative resource
    /// reconciliation, which legacy kiln does not support; Delete retains them.
    /// An absence-fenced row is charged until it references a matching receipt.
    pub fn sandbox_resources(&self) -> Result<SandboxResources> {
        self.accounting_snapshot().map(|(resources, _)| resources)
    }

    /// A single trusted snapshot for Health: invalid releases remain charged and
    /// return degraded=true. Lost membership has unknown totals and is an error.
    pub fn accounting_snapshot(&self) -> Result<(SandboxResources, bool)> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let degraded = audit_accounting(&tx)?;
        let resources = sandbox_resources(&tx)?;
        tx.commit()?;
        Ok((resources, degraded))
    }

    /// Backend IDs that a nonterminal lifecycle row can still own. This is
    /// deliberately narrower than reservations: ambiguous FAILED has no ID,
    /// while compensated FAILED has an ID but proved it absent.
    pub fn owned_backend_ids(&self, backend: &str) -> Result<Vec<String>> {
        self.audited_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT backend_id FROM sandboxes
                 WHERE backend = ?1 AND backend_id IS NOT NULL AND ({OWNED_BACKEND_WHERE} OR id IN (SELECT id FROM temp.accounting_quarantine))"
            ))?;
            let rows = statement.query_map([backend], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
    }

    /// Moves a sandbox to `state`. `backend_id` is only written when given;
    /// `failure_reason` is always replaced, so success clears it.
    pub fn set_sandbox_state(
        &self,
        id: &str,
        state: SandboxState,
        backend_id: Option<&str>,
        failure_reason: Option<&str>,
    ) -> Result<()> {
        let now = now_ms();
        let deleted_at = (state == SandboxState::Deleted).then_some(now);
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            &format!(
                "UPDATE sandboxes SET state = ?2, backend_id = COALESCE(?3, backend_id), failure_reason = ?4,
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(?6, deleted_at_ms), {LEGACY_TRANSITION},
                 {DEFAULT_ENV_TRANSITION}
             WHERE id = ?1"
            ),
            params![id, state.as_str(), backend_id, failure_reason, now, deleted_at],
        )?;
        if n != 1 {
            bail!("sandbox {id} not found");
        }
        stamp_first_ready(&tx, id, &reading)?;
        tx.commit()?;
        Ok(())
    }

    /// A legacy create's READY publication (design 4.1): `set_sandbox_state` to READY
    /// with the backend ID, recording the sandbox runtime's exec feature bits in the
    /// same statement. A row that already has them keeps them.
    pub fn publish_legacy_ready(
        &self,
        id: &str,
        backend_id: &str,
        exec_features: Option<u32>,
    ) -> Result<()> {
        let now = now_ms();
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            &format!(
                "UPDATE sandboxes SET state = ?2, backend_id = COALESCE(?3, backend_id), failure_reason = ?4,
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(?6, deleted_at_ms), {LEGACY_TRANSITION},
                 exec_features = COALESCE(exec_features, ?7)
             WHERE id = ?1"
            ),
            params![
                id,
                SandboxState::Ready.as_str(),
                backend_id,
                Option::<&str>::None,
                now,
                Option::<i64>::None,
                exec_features
            ],
        )?;
        if n != 1 {
            bail!("sandbox {id} not found");
        }
        stamp_first_ready(&tx, id, &reading)?;
        tx.commit()?;
        Ok(())
    }

    /// A sandbox's default env values (design 4.2), for one execution: empty when it has
    /// none, or when they were cleared at FAILED or DELETED. A stored list that does not
    /// decode is an error, so an execution never runs without its defaults.
    pub fn sandbox_default_env(&self, id: &str) -> Result<Vec<crate::exec_env::EnvVar>> {
        let stored: Option<Option<String>> = self
            .conn()
            .query_row(
                "SELECT default_env FROM sandboxes WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        match stored.with_context(|| format!("sandbox {id} not found"))? {
            None => Ok(Vec::new()),
            Some(text) => crate::exec_env::decode_stored(&text)
                .with_context(|| format!("sandbox {id}")),
        }
    }

    /// The clocks lifecycle anchors use. The manager installs its own before serving.
    pub fn set_clock(&self, clock: std::sync::Arc<dyn Clock>) {
        *self.clock.write().unwrap_or_else(|e| e.into_inner()) = Some(clock);
    }

    fn clock_reading(&self) -> Result<ClockReading> {
        Ok(ClockReading::now(&*self.clock_source()?))
    }

    /// The installed clock, to read later: inside a transaction, after a commit.
    fn clock_source(&self) -> Result<std::sync::Arc<dyn Clock>> {
        match &*self.clock.read().unwrap_or_else(|e| e.into_inner()) {
            Some(clock) => Ok(clock.clone()),
            None => bail!("the kernel boot ID could not be read, so no clock anchor can be stamped"),
        }
    }

    /// A user Delete's intent (or a FAILED/unreleased row's direct DELETED), as
    /// `compare_and_set_sandbox_state`, recording `reason` in the same statement if
    /// the row has none. An expiry that published first keeps its reason.
    pub fn publish_delete_intent(
        &self,
        id: &str,
        expected: SandboxState,
        state: SandboxState,
        failure_reason: Option<&str>,
        reason: DeletionReason,
    ) -> Result<bool> {
        if !matches!(state, SandboxState::Deleting | SandboxState::Deleted) {
            bail!("sandbox {id}: a delete intent is DELETING or DELETED");
        }
        let now = now_ms();
        let deleted_at = (state == SandboxState::Deleted).then_some(now);
        let n = self.conn().execute(
            &format!(
                "UPDATE sandboxes SET state = ?2, backend_id = COALESCE(?3, backend_id), failure_reason = ?4,
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(?6, deleted_at_ms), {LEGACY_TRANSITION},
                 {DEFAULT_ENV_TRANSITION}, deletion_reason = COALESCE(deletion_reason, ?8)
             WHERE id = ?1 AND state = ?7"
            ),
            params![
                id,
                state.as_str(),
                Option::<&str>::None,
                failure_reason,
                now,
                deleted_at,
                expected.as_str(),
                reason.as_str(),
            ],
        )?;
        Ok(n == 1)
    }

    /// Expiry's first-wins delete intent (design 2.4): DELETING and `reason` in one
    /// statement, only from a live state with no reason yet, only for a row Delete can
    /// remove, and for idle only if `activity_seq` is still `expected_seq`.
    pub fn publish_expiry_intent(
        &self,
        id: &str,
        reason: DeletionReason,
        expected_seq: Option<i64>,
    ) -> Result<bool> {
        if reason == DeletionReason::Requested {
            bail!("sandbox {id}: expiry publishes an expiry reason");
        }
        // MEDIUM 1: the intent's own anchor, in this boot, so Health's stale-delete
        // age survives a restart and is rebased with the other anchors after a reboot.
        let now = self.clock_reading()?;
        let n = self.conn().execute(
            "UPDATE sandboxes SET state = 'deleting', deletion_reason = ?2, updated_at_ms = ?3,
                 expiry_intent_at_ms = ?3,
                 expiry_intent_boottime_ms = CASE WHEN clock_boot_id IS NULL OR clock_boot_id = ?6 THEN ?5 END,
                 clock_boot_id = COALESCE(clock_boot_id, ?6)
             WHERE id = ?1 AND state IN ('ready', 'lost', 'quarantined') AND deletion_reason IS NULL
               AND (expiry_lifetime_ms IS NOT NULL OR expiry_idle_ms IS NOT NULL)
               AND (accounting_kind = 'fenced' OR backend_id IS NOT NULL)
               AND (?4 IS NULL OR activity_seq = ?4)",
            params![
                id,
                reason.as_str(),
                now.wall_ms,
                expected_seq,
                now.boottime_ms,
                now.boot_id
            ],
        )?;
        Ok(n == 1)
    }

    /// RenewSandbox (design 2.6): one UPDATE, committed before the reply, only on a
    /// READY row. Within a second of the last durable activity it writes nothing.
    /// Returns the row as it stands after, or `None` if it does not exist.
    pub fn renew(&self, id: &str) -> Result<Option<(Sandbox, bool)>> {
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let read = |tx: &Connection| -> Result<Option<Sandbox>> {
            audit_accounting(tx)?;
            tx.query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [id],
                sandbox_row,
            )
            .optional()?
            .transpose()
        };
        let Some(row) = read(&tx)? else {
            tx.commit()?;
            return Ok(None);
        };
        if row.state != SandboxState::Ready {
            tx.commit()?;
            return Ok(Some((row, false)));
        }
        let recent = row
            .lifecycle
            .activity_boottime_ms
            .is_some_and(|last| reading.boottime_ms.saturating_sub(last) < RENEW_COALESCE_MS);
        if !recent {
            tx.execute(
                "UPDATE sandboxes SET activity_seq = activity_seq + 1,
                     activity_at_ms = CASE WHEN ready_boottime_ms IS NULL THEN activity_at_ms ELSE ?2 END,
                     activity_boottime_ms = CASE WHEN ready_boottime_ms IS NULL THEN activity_boottime_ms ELSE ?3 END
                 WHERE id = ?1 AND state = 'ready'",
                params![id, reading.wall_ms, reading.boottime_ms],
            )?;
        }
        let row = read(&tx)?.with_context(|| format!("sandbox {id} vanished during renew"))?;
        tx.commit()?;
        Ok(Some((row, true)))
    }

    /// The cross-boot rebase (design 2.3), one IMMEDIATE transaction run once at
    /// startup before the sweeper, admission or any prune. Every row anchored in
    /// another boot gets, for lifetime and for idle, the elapsed part
    /// `min(limit, max(0, now_wall - anchor_wall))` subtracted from current boottime,
    /// with the current boot ID: both anchors in one statement. Returns how many rows
    /// it rebased. A crash leaves every row either rebased or still foreign.
    pub fn rebase_clocks(&self) -> Result<usize> {
        let now = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // (id, lifetime limit, idle limit, ready wall anchor, activity wall anchor,
        // expiry intent wall anchor)
        type Foreign = (
            String,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        );
        let rows: Vec<Foreign> = {
            let mut stmt = tx.prepare(
                "SELECT id, expiry_lifetime_ms, expiry_idle_ms, ready_at_ms, activity_at_ms, expiry_intent_at_ms
                 FROM sandboxes WHERE clock_boot_id IS NOT NULL AND clock_boot_id != ?1",
            )?;
            stmt.query_map([&now.boot_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let elapsed = |limit: Option<i64>, anchor: Option<i64>| -> Option<i64> {
            let spent = now.wall_ms.saturating_sub(anchor?).max(0);
            Some(limit.map_or(spent, |limit| spent.min(limit)))
        };
        for (id, lifetime, idle, ready_at, activity_at, intent_at) in &rows {
            let ready = elapsed(*lifetime, *ready_at).map(|e| now.boottime_ms.saturating_sub(e));
            let activity = elapsed(*idle, activity_at.or(*ready_at))
                .map(|e| now.boottime_ms.saturating_sub(e));
            // A pending expiry delete keeps its whole wall age: it only grows.
            let intent = elapsed(None, *intent_at).map(|e| now.boottime_ms.saturating_sub(e));
            tx.execute(
                "UPDATE sandboxes SET ready_boottime_ms = ?2, activity_boottime_ms = ?3, clock_boot_id = ?4,
                     expiry_intent_boottime_ms = ?5
                 WHERE id = ?1",
                params![id, ready, activity, now.boot_id, intent],
            )?;
        }
        tx.commit()?;
        Ok(rows.len())
    }

    /// MEDIUM 1: each expiry-owned DELETING row's intent boottime, in this boot (run
    /// after the rebase), or `None` when it has none or another boot's.
    pub fn expiry_intent_ages(&self) -> Result<HashMap<String, Option<i64>>> {
        let reading = self.clock_reading().ok();
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, expiry_intent_boottime_ms, clock_boot_id FROM sandboxes INDEXED BY sandboxes_expiry
             WHERE state IN ('ready', 'lost', 'quarantined', 'deleting')
               AND (expiry_lifetime_ms IS NOT NULL OR expiry_idle_ms IS NOT NULL)
               AND state = 'deleting' AND deletion_reason IN ('expired_idle', 'expired_lifetime')",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut ages = HashMap::new();
        for row in rows {
            let (id, since, boot) = row?;
            let ours = reading.as_ref().is_some_and(|r| boot.as_deref() == Some(&r.boot_id));
            ages.insert(id, since.filter(|_| ours));
        }
        Ok(ages)
    }

    /// Rows the expiry queue may need an entry for, read through the partial index:
    /// a policy and a live or DELETING state. Bounded by durable reservations.
    pub fn expiry_rows(&self) -> Result<Vec<Sandbox>> {
        self.audited_read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {SANDBOX_COLUMNS} FROM sandboxes INDEXED BY sandboxes_expiry
                 WHERE state IN ('ready', 'lost', 'quarantined', 'deleting')
                   AND (expiry_lifetime_ms IS NOT NULL OR expiry_idle_ms IS NOT NULL)"
            ))?;
            let rows = stmt.query_map([], sandbox_row)?;
            rows.map(|r| r?).collect()
        })
    }

    /// Moves a sandbox to `state` only when its current state still matches
    /// `expected`. A failed comparison leaves every column, including the
    /// lifecycle timestamps, unchanged.
    pub fn compare_and_set_sandbox_state(
        &self,
        id: &str,
        expected: SandboxState,
        state: SandboxState,
        backend_id: Option<&str>,
        failure_reason: Option<&str>,
    ) -> Result<bool> {
        let now = now_ms();
        let deleted_at = (state == SandboxState::Deleted).then_some(now);
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            &format!(
                "UPDATE sandboxes SET state = ?2, backend_id = COALESCE(?3, backend_id), failure_reason = ?4,
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(?6, deleted_at_ms), {LEGACY_TRANSITION},
                 {DEFAULT_ENV_TRANSITION}
             WHERE id = ?1 AND state = ?7"
            ),
            params![
                id,
                state.as_str(),
                backend_id,
                failure_reason,
                now,
                deleted_at,
                expected.as_str()
            ],
        )?;
        if n == 1 {
            stamp_first_ready(&tx, id, &reading)?;
        }
        tx.commit()?;
        Ok(n == 1)
    }

    /// Publishes a typed no-allocation result: FAILED and its marker are one
    /// durable update, which is the moment capacity is released. On any error
    /// the row keeps its reservation, and restart treats it as ambiguous.
    pub fn fail_create_definitely(&self, id: &str, failure_reason: &str) -> Result<()> {
        let n = self.conn().execute(
            "UPDATE sandboxes SET state = 'failed', create_certainty = ?2, failure_reason = ?3, updated_at_ms = ?4,
                 legacy_release = 'definitely_not_created', default_env = NULL
             WHERE id = ?1 AND state = 'creating' AND backend_id IS NULL AND accounting_kind = 'legacy'",
            params![
                id,
                CreateCertainty::DefinitelyNotCreated.as_str(),
                failure_reason,
                now_ms()
            ],
        )?;
        if n != 1 {
            bail!("sandbox {id} is not a CREATING row without a backend ID");
        }
        Ok(())
    }

    /// C7: publishes READY, the exact backend ID and the ready receipt in one
    /// update. Only a CREATING row can take it, so a lost race never overwrites a
    /// newer state. Returns whether this call published.
    pub fn publish_fenced_ready(&self, id: &str, created: &CreatedSandbox) -> Result<bool> {
        let RuntimeReceipt::Ready(receipt) = &created.receipt else {
            bail!("sandbox {id}: a legacy create receipt cannot publish an allocation");
        };
        let encoded = receipt.encode()?;
        let generation = i64_amount(receipt.helper_generation, "helper generation")?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx
            .query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [id],
                sandbox_row,
            )
            .optional()?
            .transpose()?
            .with_context(|| format!("sandbox {id} not found"))?;
        let Some(binding) = row.accounting.allocation.as_ref() else {
            bail!("sandbox {id}: a legacy row cannot publish an allocation");
        };
        if !receipt.matches(binding) {
            bail!("sandbox {id}: ready receipt does not match its allocation identity and plan");
        }
        if created.backend_id != binding.backend_id() {
            bail!(
                "sandbox {id}: backend ID {} is not its allocation's",
                created.backend_id
            );
        }
        if row.state != SandboxState::Creating {
            return Ok(false);
        }
        let last = row.accounting.last_helper_generation.unwrap_or(0);
        if receipt.helper_generation <= last {
            bail!(
                "sandbox {id}: ready generation {} is not newer than recorded generation {last}",
                receipt.helper_generation
            );
        }
        tx.execute(
            "UPDATE sandboxes SET state = 'ready', backend_id = ?2, boot_id = ?3, runtime_receipt = ?4,
                 last_helper_generation = ?5, failure_reason = NULL, updated_at_ms = ?6
             WHERE id = ?1",
            params![id, created.backend_id, receipt.boot_id, encoded, generation, now_ms()],
        )?;
        stamp_first_ready(&tx, id, &self.clock_reading()?)?;
        tx.commit()?;
        Ok(true)
    }

    /// The only way an absence-fenced row stops being charged: validated evidence
    /// and the terminal reference commit in one transaction. A replay of the same
    /// receipt is idempotent; any mismatch changes nothing and stays charged.
    pub fn release_fenced(
        &self,
        id: &str,
        terminal: SandboxState,
        receipt: &FencedAbsence,
        failure_reason: Option<&str>,
    ) -> Result<()> {
        if !matches!(terminal, SandboxState::Failed | SandboxState::Deleted) {
            bail!(
                "sandbox {id}: release is terminal-only, not {}",
                terminal.as_str()
            );
        }
        #[cfg(test)]
        if self.reject_evidence_commits.load(Ordering::SeqCst) {
            bail!("injected evidence commit failure");
        }
        let encoded = receipt.encode()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if audit_accounting(&tx)? {
            bail!("degraded accounting: quarantined release evidence");
        }
        let row = tx
            .query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [id],
                sandbox_row,
            )
            .optional()?
            .transpose()?
            .with_context(|| format!("sandbox {id} not found"))?;
        let Some(binding) = row.accounting.allocation.as_ref() else {
            bail!("sandbox {id}: legacy provenance cannot take an absence receipt");
        };
        if !receipt.matches(binding) {
            bail!("sandbox {id}: absence receipt does not match its allocation identity and plan");
        }
        // Only the row's own recorded evidence replays. Any other receipt must be
        // strictly newer than what this row last published: a helper generation that
        // moves backward contradicts its own ledger, so it fails closed.
        let generation = i64_amount(receipt.helper_generation(), "helper generation")?;
        let last = row.accounting.last_helper_generation.unwrap_or(0);
        match row.accounting.release {
            ReservationRelease::Fenced(existing) if existing != receipt.receipt_id() => {
                bail!("sandbox {id}: already released by receipt {existing}");
            }
            ReservationRelease::Fenced(_) => {}
            _ if receipt.helper_generation() <= last => bail!(
                "sandbox {id}: absence generation {} is not newer than recorded generation {last}",
                receipt.helper_generation()
            ),
            _ => {}
        }
        let recorded: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT helper_generation, receipt FROM release_evidence WHERE receipt_id = ?1",
                [receipt.receipt_id().to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match recorded {
            Some((stored, bytes)) if stored == generation && bytes == encoded => {}
            Some(_) => bail!("sandbox {id}: conflicting release evidence for this receipt ID"),
            None => {
                tx.execute(
                    "INSERT INTO release_evidence (receipt_id, node_id, instance_id, allocation_id, plan_digest, helper_generation, kind, receipt, recorded_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'absent_fenced', ?7, ?8)",
                    params![
                        receipt.receipt_id().to_string(),
                        receipt.node_id().to_string(),
                        receipt.instance_id().to_string(),
                        receipt.allocation_id().to_string(),
                        receipt.plan_digest().to_string(),
                        generation,
                        encoded,
                        now_ms(),
                    ],
                )?;
            }
        }
        // A terminal row keeps its first terminal evidence; only FAILED can still
        // advance to DELETED, without rewriting that reference. An exact replay
        // leaves every column, including timestamps, unchanged.
        let state = if row.state == SandboxState::Deleted {
            SandboxState::Deleted
        } else {
            terminal
        };
        if row.state == state
            && row.accounting.release == ReservationRelease::Fenced(receipt.receipt_id())
        {
            tx.commit()?;
            return Ok(());
        }
        let now = now_ms();
        let deleted_at = (state == SandboxState::Deleted).then_some(now);
        tx.execute(
            &format!(
                "UPDATE sandboxes SET state = ?2, release_evidence_id = ?3, failure_reason = COALESCE(?4, failure_reason),
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(deleted_at_ms, ?6), last_helper_generation = ?7,
                 {DEFAULT_ENV_TRANSITION}
             WHERE id = ?1"
            ),
            params![
                id,
                state.as_str(),
                receipt.receipt_id().to_string(),
                failure_reason,
                now,
                deleted_at,
                generation,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Settles every RUNNING execution of one absence-fenced sandbox across a
    /// crash, in one transaction with the sandbox's own disposition. `stopped`
    /// is host proof that no command remains: INTERRUPTED and LOST. Without it the
    /// execution is FAILED with CleanupFailed and the sandbox QUARANTINED.
    pub fn conclude_running_executions(
        &self,
        sandbox_id: &str,
        stopped: bool,
        reason: &str,
    ) -> Result<usize> {
        let reading = self.clock_reading().ok();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_ms();
        let concluded = if stopped {
            tx.execute(
                "UPDATE executions SET state = 'interrupted', failure_reason = ?2, finished_at_ms = ?3,
                     sandbox_reusable = 0, cleanup_evidence = 'sandbox_stopped'
                 WHERE sandbox_id = ?1 AND state = 'running'",
                params![sandbox_id, reason, now],
            )?
        } else {
            let diagnostic = serde_json::to_string(&RuntimeDiagnostic::new(
                RuntimeErrorKind::CleanupFailed,
                RuntimeStage::Cleanup,
                reason,
            ))?;
            tx.execute(
                "UPDATE executions SET state = 'failed', failure_reason = ?2, finished_at_ms = ?3,
                     runtime_error = ?4, sandbox_reusable = 0, cleanup_evidence = 'unknown'
                 WHERE sandbox_id = ?1 AND state = 'running'",
                params![sandbox_id, reason, now, diagnostic],
            )?
        };
        if concluded != 0 {
            // MEDIUM 2: a terminal publication is finish activity, even at startup.
            record_activity(&tx, sandbox_id, reading.as_ref())?;
            apply_disposition(
                &tx,
                sandbox_id,
                if stopped {
                    SandboxDisposition::Stopped
                } else {
                    SandboxDisposition::Quarantined
                },
                Some(reason),
                now,
            )?;
        }
        tx.commit()?;
        Ok(concluded)
    }

    /// Retires a READY or LOST sandbox without touching any execution.
    pub fn retire_sandbox(
        &self,
        id: &str,
        disposition: SandboxDisposition,
        reason: &str,
    ) -> Result<()> {
        let conn = self.conn();
        apply_disposition(&conn, id, disposition, Some(reason), now_ms())
    }

    pub fn has_running_execution(&self, sandbox_id: &str) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM executions WHERE sandbox_id = ?1 AND state = 'running')",
            [sandbox_id],
            |r| r.get(0),
        )?)
    }

    pub fn sandbox(&self, id: &str) -> Result<Option<Sandbox>> {
        self.audited_read(|conn| {
            conn.query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [id],
                sandbox_row,
            )
            .optional()?
            .transpose()
        })
    }

    /// Newest first.
    pub fn sandboxes(&self, include_deleted: bool) -> Result<Vec<Sandbox>> {
        self.audited_read(|conn| {
            let filter = if include_deleted {
                ""
            } else {
                "WHERE (state != 'deleted' OR id IN (SELECT id FROM temp.accounting_quarantine))"
            };
            let mut stmt = conn.prepare(&format!(
                "SELECT {SANDBOX_COLUMNS} FROM sandboxes {filter} ORDER BY list_seq DESC"
            ))?;
            let rows = stmt.query_map([], sandbox_row)?;
            rows.map(|r| r?).collect()
        })
    }

    /// Every owner's sandboxes, as root sees them.
    pub fn sandbox_page(
        &self,
        include_deleted: bool,
        upper_seq: Option<i64>,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<SandboxPage> {
        self.sandbox_page_owned(include_deleted, upper_seq, before_seq, limit, None)
    }

    /// A stable insertion watermark, bounded fetch, and exclusive cursor.
    /// `owner` is `None` for every owner or one exact uid. It filters in SQL,
    /// before the watermark, LIMIT and `has_more` can observe another owner.
    pub fn sandbox_page_owned(
        &self,
        include_deleted: bool,
        upper_seq: Option<i64>,
        before_seq: Option<i64>,
        limit: u32,
        owner: Option<u32>,
    ) -> Result<SandboxPage> {
        self.audited_read(|conn| {
            let filter = if include_deleted {
                ""
            } else {
                "(state != 'deleted' OR id IN (SELECT id FROM temp.accounting_quarantine)) AND "
            };
            let owned = if owner.is_some() {
                "owner_uid = ?1 AND "
            } else {
                "?1 IS NULL AND "
            };
            let upper_seq = match upper_seq {
                Some(upper) => upper,
                None => conn.query_row(
                    &format!("SELECT COALESCE(MAX(list_seq), 0) FROM sandboxes WHERE {filter}{owned}1"),
                    [owner],
                    |row| row.get(0),
                )?,
            };
            let before = if before_seq.is_some() {
                "AND list_seq < ?3"
            } else {
                "AND ?3 IS NULL"
            };
            let mut stmt = conn.prepare(&format!(
                "SELECT {SANDBOX_COLUMNS}, list_seq FROM sandboxes
                WHERE {filter}{owned}list_seq <= ?2 {before} ORDER BY list_seq DESC LIMIT ?4"
            ))?;
            let rows = stmt.query_map(
                params![owner, upper_seq, before_seq, i64::from(limit) + 1],
                |row| {
                    let list_seq = row.get(SANDBOX_COLUMN_COUNT)?;
                    Ok(sandbox_row(row)?.map(|sandbox| SandboxPageRow { sandbox, list_seq }))
                },
            )?;
            let mut rows: Vec<_> = rows.map(|row| row?).collect::<Result<_>>()?;
            let limit = usize::try_from(limit)?;
            let has_more = rows.len() > limit;
            rows.truncate(limit);
            Ok(SandboxPage {
                rows,
                upper_seq,
                has_more,
            })
        })
    }

    pub fn count_active_sandboxes(&self) -> Result<u32> {
        self.audited_read(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM sandboxes WHERE state IN ('creating', 'ready', 'deleting', 'quarantined') OR id IN (SELECT id FROM temp.accounting_quarantine)",
                [],
                |r| r.get(0),
            )?)
        })
    }

    /// Inserts a RUNNING execution only while its sandbox is READY, with the start
    /// activity (design 2.1) in the same transaction. False: the sandbox is no longer
    /// READY (an expiry or Delete intent committed first) and nothing was written.
    pub fn start_execution(&self, e: &Execution) -> Result<bool> {
        let reading = self.clock_reading()?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(test)]
        if self.lose_execution_starts.swap(false, Ordering::SeqCst) {
            // Stands for a state change between the manager's READY check and this
            // insert that a reload then sees undone (execution_start_raced).
            return Ok(false);
        }
        let n = tx.execute(
            "INSERT INTO executions (id, sandbox_id, argv, state, timeout_ms, stdin_bytes, started_at_ms,
                 cwd, env_names, env_sha256, mode)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
             WHERE EXISTS (SELECT 1 FROM sandboxes WHERE id = ?2 AND state = 'ready')",
            params![
                e.id,
                e.sandbox_id,
                serde_json::to_string(&e.argv)?,
                e.state.as_str(),
                e.timeout_ms,
                e.stdin_bytes as i64,
                e.started_at_ms,
                e.cwd,
                names_column(&e.env_names)?,
                e.env_sha256,
                e.mode.map(crate::model::ExecutionMode::as_str),
            ],
        )?;
        if n == 1 {
            record_activity(&tx, &e.sandbox_id, Some(&reading))?;
        }
        tx.commit()?;
        Ok(n == 1)
    }

    pub fn insert_execution(&self, e: &Execution) -> Result<()> {
        self.conn().execute(
            "INSERT INTO executions (id, sandbox_id, argv, state, timeout_ms, stdin_bytes, started_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                e.id,
                e.sandbox_id,
                serde_json::to_string(&e.argv)?,
                e.state.as_str(),
                e.timeout_ms,
                e.stdin_bytes as i64,
                e.started_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn finish_execution(&self, id: &str, r: &ExecutionResult<'_>) -> Result<()> {
        self.finish_execution_with_storage(id, r, OutputStorage::Full)
    }

    pub fn finish_execution_with_storage(
        &self,
        id: &str,
        r: &ExecutionResult<'_>,
        storage: OutputStorage,
    ) -> Result<()> {
        #[cfg(test)]
        if self.reject_execution_finishes.load(Ordering::SeqCst) {
            bail!("injected execution finalization failure");
        }
        let (status_kind, status_value, core_dumped) = match r.command_status {
            Some(CommandStatus::Exited(code)) => (Some("exited"), Some(*code), None),
            Some(CommandStatus::Signaled {
                signal,
                core_dumped,
            }) => (Some("signaled"), Some(*signal), Some(*core_dumped)),
            None => (None, None, None),
        };
        // Bound diagnostics again at the persistence boundary.
        let runtime_error = r
            .runtime_error
            .map(|d| {
                let mut bounded = RuntimeDiagnostic::new(d.kind, d.stage, &d.message);
                bounded.native_code = d.native_code.as_ref().map(|code| {
                    let mut end = code.len().min(128);
                    while !code.is_char_boundary(end) {
                        end -= 1;
                    }
                    if end < code.len() {
                        bounded = RuntimeDiagnostic::new(
                            d.kind,
                            d.stage,
                            format!(
                                "native_code truncated to 128 UTF-8 bytes; {}",
                                bounded.message
                            ),
                        );
                        bounded.message_truncated = true;
                    }
                    code[..end].to_owned()
                });
                bounded.message_truncated |= d.message_truncated;
                serde_json::to_string(&bounded)
            })
            .transpose()?;
        let empty = Captured::default();
        let (stdout, stderr) = if storage == OutputStorage::None {
            (&empty, &empty)
        } else {
            (r.stdout, r.stderr)
        };
        let output = |c: &Captured| {
            if storage == OutputStorage::Full {
                c.data.clone()
            } else {
                Vec::new()
            }
        };
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            "UPDATE executions SET state = ?2, exit_code = ?3, failure_reason = ?4, finished_at_ms = ?5,
                 stdout = ?6, stdout_bytes = ?7, stdout_truncated = ?8, stdout_total_bytes_known = ?9,
                 stderr = ?10, stderr_bytes = ?11, stderr_truncated = ?12, stderr_total_bytes_known = ?13,
                 command_status_kind = ?14, command_status_value = ?15, command_core_dumped = ?16, runtime_error = ?17,
                 sandbox_reusable = ?18, cleanup_evidence = ?19, cancel_reason = ?20
             WHERE id = ?1 AND state = 'running'",
            params![
                id,
                r.state.as_str(),
                r.exit_code,
                r.failure_reason,
                now_ms(),
                output(stdout),
                stdout.total_bytes as i64,
                stdout.truncated(),
                stdout.total_bytes_known,
                output(stderr),
                stderr.total_bytes as i64,
                stderr.truncated(),
                stderr.total_bytes_known,
                status_kind,
                status_value,
                core_dumped,
                runtime_error,
                r.sandbox_reusable,
                r.cleanup_evidence.as_str(),
                (r.state == ExecutionState::Canceled)
                    .then_some(r.cancel_reason)
                    .flatten()
                    .map(CancelReason::as_str),
            ],
        )?;
        if n != 1 {
            bail!("execution {id} is not running");
        }
        let sandbox_id: String = tx.query_row(
            "SELECT sandbox_id FROM executions WHERE id = ?1",
            [id],
            |row| row.get(0),
        )?;
        // The terminal publication is activity (design 2.1).
        record_activity(&tx, &sandbox_id, Some(&self.clock_reading()?))?;
        if let Some(disposition) = r.disposition {
            apply_disposition(
                &tx,
                &sandbox_id,
                disposition,
                r.disposition_reason,
                now_ms(),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// One atomic prune: terminal executions, then terminal uncharged sandbox
    /// history and its terminal children. Unknown states and unfinished rows stay.
    pub fn prune(&self, policy: &Retention, now: i64) -> Result<Pruned> {
        let cutoff = |secs: u64| -> Result<i64> {
            let ms = secs
                .checked_mul(1000)
                .and_then(|n| i64::try_from(n).ok())
                .context("retention age exceeds timestamp range")?;
            Ok(now.saturating_sub(ms))
        };
        let execution_cutoff = cutoff(policy.execution_max_age_secs)?;
        let sandbox_cutoff = cutoff(policy.sandbox_max_age_secs)?;
        // Without the boot clock no record is pruned: its age is unknowable.
        let request_cutoff = self.clock_reading().ok().and_then(|now| {
            crate::retention::create_request_prune_age_ms(policy.create_request_retention_secs)
                .map(|age| (now.boottime_ms.saturating_sub(age), now.boot_id))
        });
        let clock = self.clock_source().ok();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The full audit (MEDIUM 2): all history against the aggregate. A mismatch
        // latches this connection degraded, so admission stops too, as it did when
        // every decision rehashed history.
        if let Err(error) = audit_accounting_full(&tx) {
            drop(tx);
            conn.execute("INSERT OR IGNORE INTO temp.membership_lost VALUES (1)", [])?;
            return Err(error);
        }
        // A record whose own anchor transaction failed is anchored now, from a
        // reading taken under the write lock: after its commit, so never early. The
        // cutoff above was read before this, so it cannot select one it anchors.
        if let Some(clock) = &clock {
            anchor_unanchored(&tx, &**clock)?;
        }
        let terminal = "state IN ('exited','timed_out','canceled','failed','interrupted') AND finished_at_ms IS NOT NULL";
        let mut result = Pruned {
            executions: tx.execute(&format!("DELETE FROM executions WHERE id IN (
                SELECT id FROM (SELECT id, finished_at_ms, ROW_NUMBER() OVER (ORDER BY finished_at_ms DESC, rowid DESC) AS n
                FROM executions WHERE {terminal}) WHERE finished_at_ms <= ?1 OR n > ?2)"),
                params![execution_cutoff, policy.execution_max_count])?,
            sandboxes: 0,
            create_requests: 0,
        };
        // Design 3.3 R3, before the age and count prune so a row whose record ends
        // here follows ordinary retention from now on.
        if let Some((cutoff, boot_id)) = &request_cutoff {
            result.create_requests = remove_request_records(
                &tx,
                RecordRemoval::Prune {
                    boot_id,
                    cutoff_boottime_ms: *cutoff,
                },
            )?;
        }
        tx.execute_batch("CREATE TEMP TABLE retention_sandboxes (id TEXT PRIMARY KEY);")?;
        // R4: a row with a record is pinned, outside both the age and the count.
        tx.execute(&format!("INSERT INTO retention_sandboxes
            SELECT id FROM (SELECT id, updated_at_ms, ROW_NUMBER() OVER (ORDER BY updated_at_ms DESC, list_seq DESC) AS n
            FROM sandboxes WHERE state IN ('deleted','failed') AND NOT ({RESERVED_SANDBOX_WHERE})
            AND id NOT IN (SELECT id FROM temp.accounting_quarantine)
            AND NOT EXISTS (SELECT 1 FROM create_requests WHERE sandbox_id = sandboxes.id)
            AND NOT EXISTS (SELECT 1 FROM executions WHERE sandbox_id = sandboxes.id AND NOT ({terminal})))
            WHERE updated_at_ms <= ?1 OR n > ?2"), params![sandbox_cutoff, policy.sandbox_max_count])?;
        result.executions += tx.execute(
            "DELETE FROM executions WHERE sandbox_id IN (SELECT id FROM retention_sandboxes)",
            [],
        )?;
        // Every row pruned is uncharged, so settled since the full audit above:
        // it leaves both aggregates.
        let removed = membership_of(
            &tx,
            &format!(
                "SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes WHERE id IN (SELECT id FROM retention_sandboxes)"
            ),
            [],
        )?;
        result.sandboxes = tx.execute(
            "DELETE FROM sandboxes WHERE id IN (SELECT id FROM retention_sandboxes)",
            [],
        )?;
        if i64::try_from(result.sandboxes)? != removed.count {
            bail!("prune removed a sandbox row it did not account for");
        }
        tx.execute_batch("DROP TABLE retention_sandboxes;")?;
        let (all, settled) = stored_membership(&tx)?.context(MEMBERSHIP_MISMATCH)?;
        store_membership(&tx, all.minus(removed), settled.minus(removed))?;
        tx.commit()?;
        Ok(result)
    }

    pub fn execution(&self, id: &str) -> Result<Option<Execution>> {
        self.conn()
            .query_row(
                &format!("SELECT {EXECUTION_COLUMNS} FROM executions WHERE id = ?1"),
                [id],
                execution_row,
            )
            .optional()?
            .transpose()
    }

    /// Which sandbox an execution belongs to, read without its output.
    pub fn execution_sandbox_id(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT sandbox_id FROM executions WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// The newest `limit` executions of a sandbox, without their output data.
    pub fn recent_executions(&self, sandbox_id: &str, limit: u32) -> Result<Vec<Execution>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {EXECUTION_METADATA_COLUMNS} FROM executions WHERE sandbox_id = ?1
             ORDER BY started_at_ms DESC, rowid DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![sandbox_id, limit], execution_row)?;
        rows.map(|r| r?).collect()
    }

    pub fn count_running_executions(&self) -> Result<u32> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM executions WHERE state = 'running'",
            [],
            |r| r.get(0),
        )?)
    }

    /// Opens `dir` again after a simulated restart. The instance lock belongs
    /// to its open file description, so a backend spawn on another test thread
    /// holds a copy between fork and exec. Tests wait out that brief window.
    #[cfg(test)]
    pub(crate) fn reopen_after_restart(dir: &Path) -> Self {
        for _ in 0..1000 {
            match Self::open(dir) {
                Err(error) if error.to_string().contains("state directory already owned") => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                opened => return opened.unwrap(),
            }
        }
        panic!("{} stayed owned after restart", dir.display());
    }

    #[cfg(test)]
    pub(crate) fn reject_ready_updates(&self) -> Result<()> {
        self.conn().execute_batch(
            "CREATE TEMP TRIGGER reject_ready_updates
             BEFORE UPDATE OF state ON sandboxes
             WHEN NEW.state = 'ready'
             BEGIN SELECT RAISE(FAIL, 'injected ready publication failure'); END;",
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn reject_failed_updates(&self) -> Result<()> {
        self.conn().execute_batch(
            "CREATE TEMP TRIGGER reject_failed_updates
             BEFORE UPDATE OF state ON sandboxes
             WHEN NEW.state = 'failed'
             BEGIN SELECT RAISE(FAIL, 'injected failed publication failure'); END;",
        )?;
        Ok(())
    }

    /// Every `table.column` of every row, temp tables included, whose text or bytes
    /// contain `needle`: the canary tests' logical-column scan (design 8, L1). WAL and
    /// free pages are deliberately not read.
    #[cfg(test)]
    pub(crate) fn columns_containing_for_test(&self, needle: &[u8]) -> Vec<String> {
        let conn = self.conn();
        let mut tables: Vec<(String, String)> = Vec::new();
        for schema in ["main", "temp"] {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT name FROM {schema}.sqlite_master WHERE type = 'table'"
                ))
                .unwrap();
            let names: Vec<String> = stmt
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            tables.extend(names.into_iter().map(|n| (schema.to_string(), n)));
        }
        let mut hits = Vec::new();
        for (schema, table) in tables {
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM {schema}.\"{table}\""))
                .unwrap();
            let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for (i, column) in columns.iter().enumerate() {
                    let bytes = match row.get_ref(i).unwrap() {
                        rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) => b.to_vec(),
                        _ => continue,
                    };
                    if bytes.windows(needle.len()).any(|w| w == needle) {
                        hits.push(format!("{table}.{column}"));
                    }
                }
            }
        }
        hits.sort();
        hits.dedup();
        hits
    }

    /// One test query on the live connection.
    #[cfg(test)]
    pub(crate) fn query_for_test<T: rusqlite::types::FromSql>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> rusqlite::Result<T> {
        self.conn().query_row(sql, params, |r| r.get(0))
    }

    #[cfg(test)]
    pub(crate) fn reject_execution_finishes(&self) -> Result<()> {
        self.reject_execution_finishes.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn allow_execution_finishes(&self) -> Result<()> {
        self.reject_execution_finishes
            .store(false, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn execute_for_test(&self, sql: &str, id: &str) -> rusqlite::Result<usize> {
        self.conn().execute(sql, [id])
    }

    #[cfg(test)]
    pub(crate) fn is_charged_for_test(&self, id: &str) -> bool {
        self.sandbox(id).unwrap().unwrap().is_charged()
    }

    #[cfg(test)]
    pub(crate) fn evidence_commit_rejection_flag(&self) -> Arc<AtomicBool> {
        self.reject_evidence_commits.clone()
    }

    #[cfg(test)]
    pub(crate) fn execution_finish_rejection_flag(&self) -> Arc<AtomicBool> {
        self.reject_execution_finishes.clone()
    }

    /// Marks this backend's legacy executions still recorded as running as
    /// interrupted. Only valid at startup, before any new execution begins. An
    /// absence-fenced execution needs a stop barrier first; see
    /// `conclude_running_executions`.
    pub fn interrupt_running_executions_for_backend(
        &self,
        backend: &str,
        reason: &str,
    ) -> Result<usize> {
        let reading = self.clock_reading().ok();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parents: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT e.sandbox_id FROM executions e JOIN sandboxes s ON s.id = e.sandbox_id
                 WHERE e.state = 'running' AND s.backend = ?1 AND s.accounting_kind = 'legacy'",
            )?;
            stmt.query_map([backend], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let n = tx.execute(
            "UPDATE executions
             SET state = 'interrupted', failure_reason = ?2, finished_at_ms = ?3
             WHERE state = 'running'
               AND EXISTS (
                   SELECT 1 FROM sandboxes
                   WHERE sandboxes.id = executions.sandbox_id
                     AND sandboxes.backend = ?1
                     AND sandboxes.accounting_kind = 'legacy'
               )",
            params![backend, reason, now_ms()],
        )?;
        // MEDIUM 2: each parent's terminal publication is its finish activity, in
        // the same transaction.
        for parent in &parents {
            record_activity(&tx, parent, reading.as_ref())?;
        }
        tx.commit()?;
        Ok(n)
    }
}

pub(crate) struct PreparedDirectory {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
}

/// One directory entry's metadata, read with `fstatat` and never by opening it.
struct EntryStat {
    regular: bool,
    symlink: bool,
    mode: u32,
    uid: u32,
    nlink: u64,
    dev: u64,
    ino: u64,
}

impl EntryStat {
    fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

fn prepare_directory(dir: &Path) -> Result<PreparedDirectory> {
    let prepared = walk_trusted_directory(dir, true, true, "state")?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    validate_directory(
        &prepared.file.metadata()?,
        &prepared.path,
        euid,
        true,
        "state",
    )?;
    Ok(prepared)
}

pub(crate) fn prepare_socket_directory(dir: &Path) -> Result<PreparedDirectory> {
    walk_trusted_directory(dir, false, false, "socket")
}

fn walk_trusted_directory(
    dir: &Path,
    reject_parent: bool,
    create_parents: bool,
    resource: &str,
) -> Result<PreparedDirectory> {
    if !dir.is_absolute() {
        bail!("{resource} directory must be absolute: {}", dir.display());
    }
    let mut pending = VecDeque::new();
    for component in dir.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => pending.push_back(PathStep::Normal(name.to_owned())),
            Component::ParentDir if reject_parent => {
                bail!("state directory must not contain '..': {}", dir.display());
            }
            Component::ParentDir => pending.push_back(PathStep::Parent),
            Component::Prefix(_) => bail!("unsupported {resource} directory: {}", dir.display()),
        }
    }

    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let root = open_directory_path(Path::new("/"))?;
    validate_directory(&root.metadata()?, Path::new("/"), euid, false, resource)?;
    let mut directories = vec![root];
    let mut resolved = PathBuf::from("/");
    let mut followed_symlinks = 0;

    while let Some(step) = pending.pop_front() {
        match step {
            PathStep::Root => {
                directories.truncate(1);
                resolved = PathBuf::from("/");
            }
            PathStep::Parent => {
                if directories.len() > 1 {
                    directories.pop();
                    resolved.pop();
                }
            }
            PathStep::Normal(name) => {
                let path = resolved.join(&name);
                let stat = match stat_at_no_follow(directories.last().unwrap(), &name) {
                    Ok(stat) => Some(stat),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("inspect {resource} path {}", path.display())
                        });
                    }
                };
                if let Some(stat) = stat
                    && stat.st_mode & libc::S_IFMT == libc::S_IFLNK
                {
                    if pending.is_empty() {
                        bail!(
                            "{resource} directory must not be a symlink: {}",
                            path.display()
                        );
                    }
                    if stat.st_uid != 0 && stat.st_uid != euid {
                        bail!(
                            "{resource} path symlink {} must be owned by root or uid {euid}, found uid {}",
                            path.display(),
                            stat.st_uid
                        );
                    }
                    followed_symlinks += 1;
                    if followed_symlinks > 40 {
                        bail!(
                            "too many symlinks while resolving {resource} path {}",
                            dir.display()
                        );
                    }
                    let target = read_link_at(directories.last().unwrap(), &name, &path, resource)?;
                    let target_steps = path_steps(&target)?;
                    for target_step in target_steps.into_iter().rev() {
                        pending.push_front(target_step);
                    }
                    continue;
                }

                let next = match stat {
                    Some(_) => open_directory_at(directories.last().unwrap(), &name).with_context(
                        || {
                            format!(
                                "open {resource} path {} without following symlinks",
                                path.display()
                            )
                        },
                    )?,
                    None => {
                        if !create_parents && !pending.is_empty() {
                            bail!("socket directory parent does not exist: {}", path.display());
                        }
                        create_directory_at(directories.last().unwrap(), &name, &path)?;
                        open_directory_at(directories.last().unwrap(), &name)
                            .with_context(|| format!("open newly created {}", path.display()))?
                    }
                };
                validate_directory(
                    &next
                        .metadata()
                        .with_context(|| format!("inspect {}", path.display()))?,
                    &path,
                    euid,
                    false,
                    resource,
                )?;
                directories.push(next);
                resolved.push(name);
            }
        }
    }

    let current = directories.pop().unwrap();
    Ok(PreparedDirectory {
        path: resolved,
        file: current,
    })
}

enum PathStep {
    Root,
    Parent,
    Normal(OsString),
}

fn path_steps(path: &Path) -> Result<Vec<PathStep>> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => Some(Ok(PathStep::Root)),
            Component::CurDir => None,
            Component::ParentDir => Some(Ok(PathStep::Parent)),
            Component::Normal(name) => Some(Ok(PathStep::Normal(name.to_owned()))),
            Component::Prefix(_) => Some(Err(anyhow::anyhow!(
                "unsupported symlink target: {}",
                path.display()
            ))),
        })
        .collect()
}

fn stat_at_no_follow(directory: &File, name: &OsStr) -> std::io::Result<libc::stat> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "directory name contains NUL",
        )
    })?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory and name are live, stat is writable, and the flag
    // makes the result describe the link itself rather than its target.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstatat initialized stat on success.
    Ok(unsafe { stat.assume_init() })
}

fn read_link_at(directory: &File, name: &OsStr, path: &Path, resource: &str) -> Result<PathBuf> {
    let name = CString::new(name.as_bytes()).context("symlink name contains NUL")?;
    let mut capacity = 256;
    loop {
        let mut target = Vec::<u8>::with_capacity(capacity);
        // SAFETY: directory and name are live and target has capacity bytes of
        // writable storage. readlinkat does not append a terminator.
        let length = unsafe {
            libc::readlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                target.as_mut_ptr().cast(),
                capacity,
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("read {resource} path symlink {}", path.display()));
        }
        let length = length as usize;
        if length < capacity {
            // SAFETY: readlinkat initialized exactly length bytes.
            unsafe { target.set_len(length) };
            return Ok(PathBuf::from(OsString::from_vec(target)));
        }
        capacity *= 2;
        if capacity > 65_536 {
            bail!(
                "{resource} path symlink target is too long: {}",
                path.display()
            );
        }
    }
}

fn validate_directory(
    metadata: &std::fs::Metadata,
    path: &Path,
    euid: u32,
    is_state_directory: bool,
    resource: &str,
) -> Result<()> {
    if !metadata.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if is_state_directory {
        if metadata.uid() != euid {
            bail!(
                "{resource} directory {} must be owned by uid {euid}, found uid {}",
                path.display(),
                metadata.uid()
            );
        }
        if mode != 0o700 {
            bail!(
                "{resource} directory {} must have mode 0700, found {mode:04o}",
                path.display()
            );
        }
        return Ok(());
    }
    if metadata.uid() != 0 && metadata.uid() != euid {
        bail!(
            "{resource} path ancestor {} must be owned by root or uid {euid}, found uid {}",
            path.display(),
            metadata.uid()
        );
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        bail!(
            "{resource} path ancestor {} is writable by group or others without the sticky bit (mode {mode:04o})",
            path.display(),
        );
    }
    Ok(())
}

fn open_directory_path(path: &Path) -> Result<File> {
    let path = CString::new(path.as_os_str().as_bytes()).context("directory path contains NUL")?;
    // SAFETY: path is NUL-terminated and flags are valid for open.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open filesystem root");
    }
    // SAFETY: open returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory_at(directory: &File, name: &OsStr) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "directory name contains NUL",
        )
    })?;
    // SAFETY: directory is live, name is NUL-terminated, and flags are valid.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn create_directory_at(directory: &File, name: &OsStr, path: &Path) -> Result<()> {
    let name = CString::new(name.as_bytes()).context("directory name contains NUL")?;
    // SAFETY: directory and name are live and mode is valid for mkdirat.
    if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).with_context(|| format!("create {}", path.display()));
        }
    }
    Ok(())
}

/// Stats one entry beneath the held directory without following a link and without
/// opening it, so a FIFO cannot block and no descriptor is ever closed on a file SQLite
/// holds locks on (see `Store::open`).
// libc's stat field widths differ between Linux and macOS, so these casts widen on one
// and are identities on the other.
#[allow(clippy::unnecessary_cast)]
fn stat_entry_no_follow(directory: &File, name: &OsStr, path: &Path) -> Result<Option<EntryStat>> {
    let name = CString::new(name.as_bytes()).context("database filename contains NUL")?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory and name are live, and stat is writable for one libc::stat.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error)
            .with_context(|| format!("inspect {} without following symlinks", path.display()));
    }
    // SAFETY: fstatat succeeded and initialized the whole structure.
    let stat = unsafe { stat.assume_init() };
    Ok(Some(EntryStat {
        regular: stat.st_mode & libc::S_IFMT == libc::S_IFREG,
        symlink: stat.st_mode & libc::S_IFMT == libc::S_IFLNK,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        nlink: stat.st_nlink as u64,
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    }))
}

/// Creates a new, empty database entry, exclusively, mode 0600, not following a link,
/// and closes it before any SQLite connection exists.
fn create_database_entry(directory: &File, path: &Path, expected_uid: u32) -> Result<EntryStat> {
    let name = CString::new("kilnd.db").unwrap();
    // SAFETY: directory and name are live and the flags are valid for openat.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("create {}", path.display()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set {} to 0600", path.display()))?;
    drop(file);
    inspect_database_entry(directory, OsStr::new("kilnd.db"), path, expected_uid)?
        .with_context(|| format!("{} vanished after creation", path.display()))
}

fn validate_database_entry(entry: &EntryStat, path: &Path, expected_uid: u32) -> Result<()> {
    if entry.symlink {
        bail!(
            "{} is a symbolic link: refused without following symlinks",
            path.display()
        );
    }
    if !entry.regular {
        bail!("{} must be a regular file", path.display());
    }
    if entry.uid != expected_uid {
        bail!(
            "{} must be owned by uid {expected_uid}, found uid {}",
            path.display(),
            entry.uid
        );
    }
    let mode = entry.mode & 0o7777;
    if mode != 0o600 {
        bail!("{} must have mode 0600, found {mode:04o}", path.display());
    }
    if entry.nlink != 1 {
        bail!("{} must have exactly one link", path.display());
    }
    Ok(())
}

fn inspect_database_entry(
    directory: &File,
    name: &OsStr,
    path: &Path,
    expected_uid: u32,
) -> Result<Option<EntryStat>> {
    let entry = stat_entry_no_follow(directory, name, path)?;
    if let Some(entry) = entry.as_ref() {
        validate_database_entry(entry, path, expected_uid)?;
    }
    Ok(entry)
}

fn inspect_sqlite_sidecars(directory: &PreparedDirectory, expected_uid: u32) -> Result<()> {
    for name in ["kilnd.db-wal", "kilnd.db-shm", "kilnd.db-journal"] {
        inspect_database_entry(
            &directory.file,
            OsStr::new(name),
            &directory.path.join(name),
            expected_uid,
        )?;
    }
    Ok(())
}

// A plan can be 128 KiB, and only recovery of a charged row reads one. A charged
// row count is bounded by the sandbox budget; released history's is bounded only by
// retention, so listings leave its stored plan out.
const SANDBOX_COLUMNS: &str = "id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, create_certainty, owner_uid,
    accounting_kind, reserved_memory_bytes, reserved_disk_bytes, reserved_pids, reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids,
    host_spec_sha256, guest_exec_spec_sha256, runtime_profile, runtime_artifact_digest, disposition, boot_id, legacy_release,
    node_id, instance_id, allocation_id, plan_version, plan_digest,
    CASE WHEN plan IS NULL OR release_evidence_id IS NULL THEN plan ELSE x'' END, release_evidence_id, last_helper_generation,
    id IN (SELECT id FROM temp.accounting_quarantine),
    expiry_lifetime_ms, expiry_idle_ms, ready_at_ms, ready_boottime_ms, activity_at_ms, activity_boottime_ms,
    clock_boot_id, activity_seq, deletion_reason, request_id, request_id_released_at_ms,
    default_env_names, default_env_sha256, exec_features";
const SANDBOX_COLUMN_COUNT: usize = 48;

/// Row decoding errors are reported per row rather than as SQLite errors.
fn sandbox_row(row: &Row<'_>) -> rusqlite::Result<Result<Sandbox>> {
    let state: String = row.get(3)?;
    let spec: String = row.get(4)?;
    let id: String = row.get(0)?;
    let create_certainty: String = row.get(9)?;
    let accounting_kind: String = row.get(11)?;
    let amounts = [
        row.get::<_, i64>(12)?,
        row.get::<_, i64>(13)?,
        row.get::<_, i64>(14)?,
        row.get::<_, i64>(15)?,
        row.get::<_, i64>(16)?,
        row.get::<_, i64>(17)?,
    ];
    let host_digest: String = row.get(18)?;
    let guest_digest: String = row.get(19)?;
    let disposition: String = row.get(22)?;
    let legacy_release: Option<String> = row.get(24)?;
    let identity: [Option<String>; 3] = [row.get(25)?, row.get(26)?, row.get(27)?];
    let plan_version: Option<u32> = row.get(28)?;
    let plan_digest: Option<String> = row.get(29)?;
    let plan: Option<Vec<u8>> = row.get(30)?;
    let release_evidence_id: Option<String> = row.get(31)?;
    let last_helper_generation: Option<i64> = row.get(32)?;
    let expiry: [Option<i64>; 2] = [row.get(34)?, row.get(35)?];
    let anchors: [Option<i64>; 4] = [row.get(36)?, row.get(37)?, row.get(38)?, row.get(39)?];
    let clock_boot_id: Option<String> = row.get(40)?;
    let activity_seq: i64 = row.get(41)?;
    let deletion_reason: Option<String> = row.get(42)?;
    let request_id: Option<String> = row.get(43)?;
    let request_id_released_at_ms: Option<i64> = row.get(44)?;
    let default_env_names: Option<String> = row.get(45)?;
    let default_env_sha256: Option<String> = row.get(46)?;
    let exec_features: Option<i64> = row.get(47)?;
    Ok((|| {
        let bad = |what: &str, why: String| anyhow::anyhow!("sandbox {id}: bad {what}: {why}");
        let amount = |index: usize| {
            u64::try_from(amounts[index]).map_err(|e| bad("reservation", e.to_string()))
        };
        let regime = match accounting_kind.as_str() {
            "legacy" => AccountingRegime::Legacy,
            "fenced" => AccountingRegime::AbsenceFenced,
            other => bail!("sandbox {id}: unknown accounting kind {other:?}"),
        };
        let allocation = match (identity, plan_version, plan_digest, plan) {
            (
                [Some(node), Some(instance), Some(allocation)],
                Some(version),
                Some(digest),
                Some(plan),
            ) => {
                let parse = |what: &str, value: &str| Id128::parse(value).map_err(|e| bad(what, e));
                Some(AllocationBinding {
                    node_id: parse("node ID", &node)?,
                    instance_id: parse("instance ID", &instance)?,
                    allocation_id: parse("allocation ID", &allocation)?,
                    plan_version: version,
                    plan_digest: Digest::parse(&digest).map_err(|e| bad("plan digest", e))?,
                    plan,
                })
            }
            ([None, None, None], None, None, None) => None,
            _ => bail!("sandbox {id}: partial allocation identity"),
        };
        let release = match (legacy_release, release_evidence_id) {
            (None, None) => ReservationRelease::Charged,
            (Some(tag), None) => ReservationRelease::Legacy(
                LegacyRelease::parse(&tag)
                    .with_context(|| format!("sandbox {id}: unknown legacy release {tag:?}"))?,
            ),
            (None, Some(receipt)) => ReservationRelease::Fenced(
                Id128::parse(&receipt).map_err(|e| bad("release evidence ID", e))?,
            ),
            (Some(_), Some(_)) => bail!("sandbox {id}: conflicting release provenance"),
        };
        let mut sandbox = Sandbox {
            create_certainty: CreateCertainty::parse(&create_certainty).with_context(|| {
                format!("sandbox {id}: unknown create certainty {create_certainty:?}")
            })?,
            state: SandboxState::parse(&state)
                .with_context(|| format!("sandbox {id}: unknown state {state:?}"))?,
            spec: serde_json::from_str::<SandboxSpec>(&spec)
                .with_context(|| format!("sandbox {id}: bad spec"))?,
            backend: row.get(1)?,
            backend_id: row.get(2)?,
            failure_reason: row.get(5)?,
            created_at_ms: row.get(6)?,
            updated_at_ms: row.get(7)?,
            deleted_at_ms: row.get(8)?,
            owner_uid: row.get(10)?,
            accounting: SandboxAccounting {
                regime,
                reservation: ResourceReservation {
                    memory_bytes: amount(0)?,
                    disk_bytes: amount(1)?,
                    pids: amount(2)?,
                    host_cpu_millis: amount(3)?,
                    virtual_cpu_slots: amount(4)?,
                    host_pids: amount(5)?,
                },
                host_spec_sha256: Digest::parse(&host_digest)
                    .map_err(|e| bad("host spec digest", e))?,
                guest_exec_spec_sha256: Digest::parse(&guest_digest)
                    .map_err(|e| bad("guest spec digest", e))?,
                runtime_profile: row.get(20)?,
                runtime_artifact_digest: row.get(21)?,
                allocation,
                boot_id: row.get(23)?,
                disposition: SandboxDisposition::parse(&disposition).with_context(|| {
                    format!("sandbox {id}: unknown disposition {disposition:?}")
                })?,
                release,
                last_helper_generation: last_helper_generation
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|e| bad("helper generation", e.to_string()))?,
            },
            lifecycle: SandboxLifecycle {
                expiry: ExpiryPolicy {
                    max_lifetime_ms: expiry[0]
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|e| bad("expiry lifetime", e.to_string()))?,
                    idle_timeout_ms: expiry[1]
                        .map(u64::try_from)
                        .transpose()
                        .map_err(|e| bad("expiry idle timeout", e.to_string()))?,
                },
                ready_at_ms: anchors[0],
                ready_boottime_ms: anchors[1],
                activity_at_ms: anchors[2],
                activity_boottime_ms: anchors[3],
                clock_boot_id,
                activity_seq,
                deletion_reason: deletion_reason
                    .map(|reason| {
                        DeletionReason::parse(&reason).with_context(|| {
                            format!("sandbox {id}: unknown deletion reason {reason:?}")
                        })
                    })
                    .transpose()?,
                request_id,
                request_id_released_at_ms,
                default_env_names: parse_names(default_env_names, "default env names")
                    .with_context(|| format!("sandbox {id}"))?,
                default_env_sha256,
                exec_features: exec_features
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|e| bad("exec features", e.to_string()))?,
            },
            id: id.clone(),
        };
        if row.get::<_, bool>(33)? {
            sandbox.state = SandboxState::Quarantined;
            sandbox.accounting.disposition = SandboxDisposition::Quarantined;
            sandbox.accounting.release = ReservationRelease::Charged;
            sandbox.failure_reason =
                Some("degraded accounting: invalid or missing AbsentFenced receipt".into());
        }
        Ok(sandbox)
    })())
}

/// One schema 7 row in its schema 8 form. Amounts are exactly the stored spec's;
/// the release tag is exactly schema 7's predicate over the stored row. The spec
/// text is copied verbatim, and a spec no reader could decode fails the migration.
fn migrate_v8(tx: &Connection) -> Result<()> {
    tx.execute_batch(MIGRATE_V8_TABLES)?;
    tx.execute(
        "INSERT INTO daemon_identity (id, database_uuid, instance_id) VALUES (1, ?1, ?2)",
        params![Id128::random().to_string(), Id128::random().to_string()],
    )?;
    let mut rows = tx.prepare(
        "SELECT id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, list_seq, create_certainty, owner_uid FROM sandboxes",
    )?;
    let mut insert = tx.prepare(
        "INSERT INTO sandboxes_v8 (id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, list_seq, create_certainty, owner_uid,
            accounting_kind, reserved_memory_bytes, reserved_disk_bytes, reserved_pids, reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids,
            host_spec_sha256, guest_exec_spec_sha256, legacy_release)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'legacy', ?13, ?14, ?15, 0, 0, 0, ?16, ?17, ?18)",
    )?;
    let mut cursor = rows.query([])?;
    while let Some(row) = cursor.next()? {
        let id: String = row.get(0)?;
        let backend_id: Option<String> = row.get(2)?;
        let state: String = row.get(3)?;
        let encoded: String = row.get(4)?;
        let certainty: String = row.get(10)?;
        let spec: SandboxSpec = serde_json::from_str(&encoded)
            .with_context(|| format!("migrate sandbox {id}: bad spec"))?;
        let reservation = ResourceReservation::legacy_for_spec(&spec);
        let (host, guest) = crate::model::spec_digests(&spec);
        // An unrecognized historical state stays charged rather than guessed.
        let tag = SandboxState::parse(&state).and_then(|state| {
            LegacyRelease::for_row(
                state,
                backend_id.as_deref(),
                CreateCertainty::parse(&certainty).unwrap_or_default(),
            )
        });
        insert
            .execute(params![
                id,
                row.get::<_, String>(1)?,
                backend_id,
                state,
                encoded,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, i64>(9)?,
                certainty,
                row.get::<_, i64>(11)?,
                i64_amount(reservation.memory_bytes, "reserved memory")?,
                i64_amount(reservation.disk_bytes, "reserved disk")?,
                i64_amount(reservation.pids, "reserved PIDs")?,
                host.to_string(),
                guest.to_string(),
                tag.map(LegacyRelease::as_str),
            ])
            .with_context(|| format!("migrate sandbox {id}"))?;
    }
    drop(cursor);
    drop(rows);
    drop(insert);
    tx.execute_batch(MIGRATE_V8_FINISH)?;
    Ok(())
}

/// Maps a disposition onto the row in the caller's transaction. Only READY changes
/// state: DELETING keeps its intent, and LOST or QUARANTINED already refuse Exec.
fn apply_disposition(
    conn: &Connection,
    sandbox_id: &str,
    disposition: SandboxDisposition,
    reason: Option<&str>,
    now: i64,
) -> Result<()> {
    match disposition {
        SandboxDisposition::Reusable => {}
        SandboxDisposition::Stopped | SandboxDisposition::Quarantined => {
            let state = if disposition == SandboxDisposition::Stopped {
                SandboxState::Lost
            } else {
                SandboxState::Quarantined
            };
            conn.execute(
                "UPDATE sandboxes SET disposition = ?2,
                     state = CASE WHEN state = 'ready' THEN ?3
                                  WHEN state = 'lost' AND ?3 = 'quarantined' THEN ?3
                                  ELSE state END,
                     failure_reason = CASE WHEN state IN ('ready', 'lost') THEN COALESCE(?4, failure_reason) ELSE failure_reason END,
                     updated_at_ms = ?5
                 WHERE id = ?1",
                params![sandbox_id, disposition.as_str(), state.as_str(), reason, now],
            )?;
        }
    }
    Ok(())
}

const EXECUTION_COLUMNS: &str =
    "id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, stdout, stdout_bytes, stdout_truncated, stdout_total_bytes_known,
    stderr, stderr_bytes, stderr_truncated, stderr_total_bytes_known,
    command_status_kind, command_status_value, command_core_dumped, runtime_error,
    sandbox_reusable, cleanup_evidence, cancel_reason, cwd, env_names, env_sha256, mode";

const EXECUTION_METADATA_COLUMNS: &str =
    "id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, x'', stdout_bytes, stdout_truncated, stdout_total_bytes_known,
    x'', stderr_bytes, stderr_truncated, stderr_total_bytes_known,
    command_status_kind, command_status_value, command_core_dumped, runtime_error,
    sandbox_reusable, cleanup_evidence, cancel_reason, cwd, env_names, env_sha256, mode";

fn execution_row(row: &Row<'_>) -> rusqlite::Result<Result<Execution>> {
    let id: String = row.get(0)?;
    let argv: String = row.get(2)?;
    let state: String = row.get(3)?;
    let cleanup_evidence: String = row.get(23)?;
    let cancel_reason: Option<String> = row.get(24)?;
    let cwd: Option<String> = row.get(25)?;
    let env_names: Option<String> = row.get(26)?;
    let env_sha256: Option<String> = row.get(27)?;
    let mode: Option<String> = row.get(28)?;
    Ok((|| {
        Ok(Execution {
            sandbox_id: row.get(1)?,
            argv: serde_json::from_str(&argv)
                .with_context(|| format!("execution {id}: bad argv"))?,
            state: ExecutionState::parse(&state)
                .with_context(|| format!("execution {id}: unknown state {state:?}"))?,
            exit_code: row.get(4)?,
            command_status: match (
                row.get::<_, Option<String>>(18)?.as_deref(),
                row.get::<_, Option<i32>>(19)?,
                row.get::<_, Option<bool>>(20)?,
            ) {
                (None, None, None) => None,
                (Some("exited"), Some(code), None) => Some(CommandStatus::Exited(code)),
                (Some("signaled"), Some(signal), Some(core_dumped)) => {
                    Some(CommandStatus::Signaled {
                        signal,
                        core_dumped,
                    })
                }
                _ => bail!("execution {id}: invalid command status"),
            },
            runtime_error: row
                .get::<_, Option<String>>(21)?
                .map(|json| serde_json::from_str::<RuntimeDiagnostic>(&json))
                .transpose()
                .context("invalid runtime diagnostic")?,
            failure_reason: row.get(5)?,
            timeout_ms: row.get(6)?,
            stdin_bytes: row.get::<_, i64>(7)? as u64,
            started_at_ms: row.get(8)?,
            finished_at_ms: row.get(9)?,
            stdout: Captured {
                data: row.get(10)?,
                total_bytes: row.get::<_, i64>(11)? as u64,
                truncated: row.get(12)?,
                total_bytes_known: row.get(13)?,
            },
            stderr: Captured {
                data: row.get(14)?,
                total_bytes: row.get::<_, i64>(15)? as u64,
                truncated: row.get(16)?,
                total_bytes_known: row.get(17)?,
            },
            sandbox_reusable: row.get(22)?,
            cleanup_evidence: CleanupEvidence::parse(&cleanup_evidence).with_context(|| {
                format!("execution {id}: unknown cleanup evidence {cleanup_evidence:?}")
            })?,
            cancel_reason: cancel_reason
                .map(|reason| {
                    CancelReason::parse(&reason).with_context(|| {
                        format!("execution {id}: unknown cancel reason {reason:?}")
                    })
                })
                .transpose()?,
            id: id.clone(),
            cwd,
            env_names: parse_names(env_names, "env names")
                .with_context(|| format!("execution {id}"))?,
            env_sha256,
            mode: mode
                .map(|mode| {
                    crate::model::ExecutionMode::parse(&mode)
                        .with_context(|| format!("execution {id}: unknown mode {mode:?}"))
                })
                .transpose()?,
        })
    })())
}

#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They create,
// overwrite and remove their own scratch files directly.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::model::{Network, new_id};
    use crate::runtime::CreatedSandbox;
    use std::collections::BTreeMap;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn retention_keeps_reservations_and_unfinished_evidence() {
        let store = Store::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for (state, backend, certainty) in [
            (
                SandboxState::Creating,
                None,
                CreateCertainty::AllocationAmbiguous,
            ),
            (
                SandboxState::Ready,
                Some("ab1"),
                CreateCertainty::AllocationAmbiguous,
            ),
            (
                SandboxState::Deleting,
                Some("ab2"),
                CreateCertainty::AllocationAmbiguous,
            ),
            (
                SandboxState::Lost,
                Some("ab3"),
                CreateCertainty::AllocationAmbiguous,
            ),
            (
                SandboxState::Failed,
                None,
                CreateCertainty::AllocationAmbiguous,
            ),
            (
                SandboxState::Failed,
                None,
                CreateCertainty::DefinitelyNotCreated,
            ),
            (
                SandboxState::Failed,
                Some("ab4"),
                CreateCertainty::AllocationAmbiguous,
            ),
            (
                SandboxState::Deleted,
                None,
                CreateCertainty::AllocationAmbiguous,
            ),
        ] {
            let mut sb = sandbox();
            sb.state = state;
            sb.backend_id = backend.map(str::to_owned);
            sb.create_certainty = certainty;
            store.insert_sandbox(&sb).unwrap();
            ids.push(sb.id);
        }
        // Even otherwise removable history must keep a non-terminal child.
        let pending = execution(&ids[7]);
        store.insert_execution(&pending).unwrap();
        let before = store.sandbox_resources().unwrap();
        let policy = Retention {
            execution_max_count: 0,
            sandbox_max_count: 0,
            ..Retention::default()
        };
        let result = store.prune(&policy, now_ms()).unwrap();
        assert_eq!(result.sandboxes, 2);
        assert_eq!(store.sandbox_resources().unwrap(), before);
        for id in &ids[..5] {
            assert!(store.sandbox(id).unwrap().is_some());
        }
        assert!(store.sandbox(&ids[7]).unwrap().is_some());
        assert!(store.execution(&pending.id).unwrap().is_some());
    }

    #[test]
    fn retention_age_count_and_watermark_survive_restart() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let sb = sandbox();
        store.insert_sandbox(&sb).unwrap();
        let mut ids = Vec::new();
        for time in [1, 8000, 9000, 10000] {
            let e = execution(&sb.id);
            store.insert_execution(&e).unwrap();
            store
                .conn()
                .execute(
                    "UPDATE executions SET state='exited', finished_at_ms=?2 WHERE id=?1",
                    params![e.id, time],
                )
                .unwrap();
            ids.push(e.id);
        }
        let policy = Retention {
            execution_max_age_secs: 5,
            execution_max_count: 2,
            ..Retention::default()
        };
        assert_eq!(store.prune(&policy, 10000).unwrap().executions, 2);
        assert!(store.execution(&ids[1]).unwrap().is_none());
        assert!(store.execution(&ids[2]).unwrap().is_some());
        store
            .conn()
            .execute("UPDATE executions SET finished_at_ms=1", [])
            .unwrap();
        assert_eq!(store.prune(&policy, 10000).unwrap().executions, 2);
        let upper = store.sandbox_page(true, None, None, 10).unwrap().upper_seq;
        store
            .set_sandbox_state(&sb.id, SandboxState::Deleted, None, None)
            .unwrap();
        let zero = Retention {
            sandbox_max_count: 0,
            ..policy
        };
        assert_eq!(store.prune(&zero, 10000).unwrap().sandboxes, 1);
        drop(store);
        let store = Store::reopen_after_restart(&dir);
        store.insert_sandbox(&sandbox()).unwrap();
        assert!(
            store
                .sandbox_page(true, Some(upper), None, 10)
                .unwrap()
                .rows
                .is_empty()
        );
    }

    #[test]
    fn output_storage_modes_keep_truthful_metadata() {
        for mode in [
            OutputStorage::Full,
            OutputStorage::Metadata,
            OutputStorage::None,
        ] {
            let store = Store::open_in_memory().unwrap();
            let sb = sandbox();
            store.insert_sandbox(&sb).unwrap();
            let e = execution(&sb.id);
            store.insert_execution(&e).unwrap();
            let capture = Captured {
                data: b"secret".to_vec(),
                total_bytes: 20,
                total_bytes_known: true,
                truncated: true,
            };
            store
                .finish_execution_with_storage(
                    &e.id,
                    &ExecutionResult {
                        state: ExecutionState::Exited,
                        exit_code: Some(0),
                        command_status: Some(&CommandStatus::Exited(0)),
                        runtime_error: None,
                        failure_reason: None,
                        stdout: &capture,
                        stderr: &capture,
                        sandbox_reusable: None,
                        cleanup_evidence: CleanupEvidence::Unknown,
                        disposition: None,
                        disposition_reason: None,
                        cancel_reason: None,
                    },
                    mode,
                )
                .unwrap();
            let got = store.execution(&e.id).unwrap().unwrap();
            assert_eq!(
                got.stdout.data,
                if mode == OutputStorage::Full {
                    b"secret".to_vec()
                } else {
                    vec![]
                }
            );
            if mode == OutputStorage::None {
                assert_eq!(got.stdout.total_bytes, 0);
                assert!(!got.stdout.total_bytes_known);
                assert!(!got.stdout.truncated());
            } else {
                assert_eq!(got.stdout.total_bytes, 20);
                assert!(got.stdout.total_bytes_known && got.stdout.truncated());
            }
        }
    }

    fn schema_v6() -> String {
        SCHEMA
            .replace(
                ",\n    owner_uid INTEGER NOT NULL DEFAULT 0 CHECK (owner_uid BETWEEN 0 AND 4294967295)",
                "",
            )
            .replace(
                "CREATE INDEX sandboxes_owner_list_seq ON sandboxes (owner_uid, list_seq DESC);\n",
                "",
            )
    }

    fn schema_v5() -> String {
        schema_v6().replace("CREATE TABLE history_sequence (id INTEGER PRIMARY KEY CHECK(id = 1), value INTEGER NOT NULL);\nINSERT INTO history_sequence VALUES (1, 0);\n", "")
    }

    fn schema_v4() -> String {
        let schema = schema_v5();
        let start = schema.find(",\n    create_certainty").unwrap();
        let end = start + schema[start..].find("\n);").unwrap();
        format!("{}{}", &schema[..start], &schema[end..])
    }

    fn schema_v3() -> String {
        schema_v4()
            .replace(
                "\n    stdout_total_bytes_known INTEGER NOT NULL DEFAULT 0,",
                "",
            )
            .replace(
                "\n    stderr_total_bytes_known INTEGER NOT NULL DEFAULT 0,",
                "",
            )
    }

    fn schema_v2() -> String {
        schema_v3().replace(",\n    command_status_kind TEXT,\n    command_status_value INTEGER,\n    command_core_dumped INTEGER,\n    runtime_error TEXT", "")
    }

    #[test]
    fn fresh_v5_and_historical_v1_v2_v3_keep_unknown_evidence() {
        let fresh = Store::open_in_memory().unwrap();
        assert_eq!(
            fresh
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        for version in [1, 2, 3] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
            let mut schema = if version == 3 {
                schema_v3()
            } else {
                schema_v2()
            };
            if version == 1 {
                schema=schema.replace(",\n    list_seq       INTEGER NOT NULL","")
                    .replace("CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);","")
                    .replace("CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';","");
            }
            conn.execute_batch(&schema).unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            let mut s = sandbox();
            s.state = SandboxState::Ready;
            let list_column = if version >= 2 { ", list_seq" } else { "" };
            let list_value = if version >= 2 { ", 1" } else { "" };
            conn.execute(&format!("INSERT INTO sandboxes (id,backend,state,spec,created_at_ms,updated_at_ms{list_column}) VALUES (?1,'fake','ready',?2,1,1{list_value})"),params![s.id,serde_json::to_string(&s.spec).unwrap()]).unwrap();
            conn.execute("INSERT INTO executions (id,sandbox_id,argv,state,exit_code,timeout_ms,stdin_bytes,started_at_ms) VALUES ('old',?1,'[]','exited',143,1,0,1)",[&s.id]).unwrap();
            conn.execute("INSERT INTO executions (id,sandbox_id,argv,state,timeout_ms,stdin_bytes,started_at_ms) VALUES ('running',?1,'[]','running',1,0,2)",[&s.id]).unwrap();
            drop(conn);
            std::fs::set_permissions(
                tmp.path().join("kilnd.db"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let store = Store::open(tmp.path()).unwrap();
            assert_eq!(
                store
                    .conn()
                    .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            assert_eq!(
                store.sandboxes(true).unwrap()[0].create_certainty,
                CreateCertainty::AllocationAmbiguous
            );
            let historical = store.execution("old").unwrap().unwrap();
            assert_eq!(historical.exit_code, Some(143));
            assert!(historical.command_status.is_none() && historical.runtime_error.is_none());
            assert!(!historical.stdout.total_bytes_known);
            assert!(!historical.stderr.total_bytes_known);
            store
                .interrupt_running_executions_for_backend("fake", "restart")
                .unwrap();
            let interrupted = store.execution("running").unwrap().unwrap();
            assert_eq!(interrupted.state, ExecutionState::Interrupted);
            assert!(interrupted.command_status.is_none() && interrupted.runtime_error.is_none());
            drop(store);
            let reopened = Store::reopen_after_restart(tmp.path());
            assert_eq!(reopened.execution("old").unwrap().unwrap(), historical);
            assert_eq!(reopened.execution("running").unwrap().unwrap(), interrupted);
        }
    }

    #[test]
    fn typed_failure_binary_capture_and_utf8_bounded_diagnostic_reopen_atomically() {
        use crate::model::{RuntimeErrorKind, RuntimeStage};
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        let e = execution(&s.id);
        store.insert_execution(&e).unwrap();
        let mut d = RuntimeDiagnostic::new(
            RuntimeErrorKind::Io,
            RuntimeStage::Capture,
            "é".repeat(1025),
        );
        d.native_code = Some("errno:5".into());
        assert_eq!(d.message.len(), 2048);
        assert!(d.message_truncated);
        let out = Captured {
            data: b"\0\xffout".to_vec(),
            total_bytes: 999,
            truncated: true,
            total_bytes_known: false,
        };
        let err = Captured {
            data: b"\0\xfeerr".to_vec(),
            total_bytes: 1001,
            truncated: true,
            total_bytes_known: true,
        };
        let status = CommandStatus::Signaled {
            signal: 15,
            core_dumped: true,
        };
        store
            .finish_execution(
                &e.id,
                &ExecutionResult {
                    state: ExecutionState::Failed,
                    exit_code: None,
                    command_status: Some(&status),
                    runtime_error: Some(&d),
                    failure_reason: Some(&d.message),
                    stdout: &out,
                    stderr: &err,
                    sandbox_reusable: None,
                    cleanup_evidence: CleanupEvidence::Unknown,
                    disposition: None,
                    disposition_reason: None,
                    cancel_reason: None,
                },
            )
            .unwrap();
        let full = store.execution(&e.id).unwrap().unwrap();
        let meta = store.recent_executions(&s.id, 1).unwrap().remove(0);
        assert_eq!(meta.command_status, Some(status));
        assert_eq!(meta.runtime_error, Some(d));
        assert!(meta.stdout.data.is_empty());
        assert_eq!(meta.stdout.total_bytes, 999);
        assert!(meta.stdout.truncated());
        assert!(!meta.stdout.total_bytes_known);
        assert!(meta.stderr.total_bytes_known);
        assert_eq!(full.stdout, out);
        assert_eq!(full.stderr, err);
        drop(store);
        let store = Store::reopen_after_restart(tmp.path());
        assert_eq!(store.execution(&e.id).unwrap().unwrap(), full);
    }

    #[test]
    fn oversized_native_diagnostic_is_bounded_without_blocking_terminal_publication() {
        use crate::model::{RuntimeErrorKind, RuntimeStage};
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        for code in [
            format!("{}é{}", "x".repeat(127), "é".repeat(100_000)),
            "\0".repeat(200_000),
        ] {
            let e = execution(&s.id);
            store.insert_execution(&e).unwrap();
            let d = RuntimeDiagnostic {
                kind: RuntimeErrorKind::Io,
                stage: RuntimeStage::Capture,
                message: "\0".repeat(20_000),
                native_code: Some(code),
                message_truncated: false,
            };
            store
                .finish_execution(
                    &e.id,
                    &ExecutionResult {
                        state: ExecutionState::Failed,
                        exit_code: None,
                        command_status: None,
                        runtime_error: Some(&d),
                        failure_reason: None,
                        stdout: &Captured::default(),
                        stderr: &Captured::default(),
                        sandbox_reusable: None,
                        cleanup_evidence: CleanupEvidence::Unknown,
                        disposition: None,
                        disposition_reason: None,
                        cancel_reason: None,
                    },
                )
                .unwrap();
            let got = store
                .execution(&e.id)
                .unwrap()
                .unwrap()
                .runtime_error
                .unwrap();
            assert!(got.native_code.as_ref().unwrap().len() <= 128);
            assert!(got.message.len() <= 2048);
            assert!(got.message_truncated);
            assert!(got.message.starts_with("native_code truncated"));
            let json: String = store
                .conn()
                .query_row(
                    "SELECT runtime_error FROM executions WHERE id=?1",
                    [&e.id],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                json.len() <= 6 * (2048 + 128) + 256,
                "JSON unexpectedly large: {}",
                json.len()
            );
            assert_eq!(
                store.recent_executions(&s.id, 1).unwrap()[0].runtime_error,
                Some(got)
            );
        }
    }

    fn sandbox() -> Sandbox {
        let now = now_ms();
        Sandbox {
            id: new_id("sb"),
            state: SandboxState::Creating,
            spec: SandboxSpec {
                image: "alpine".into(),
                memory_bytes: 1 << 29,
                cpu_millis: 1000,
                pids: 128,
                disk_bytes: 1 << 30,
                network: Network::Allow(vec!["example.com:443".into()]),
                read_only_root: true,
                writable_paths: vec!["/data".into()],
                labels: BTreeMap::from([("owner".into(), "tests".into())]),
            },
            backend: "fake".into(),
            backend_id: None,
            created_at_ms: now,
            updated_at_ms: now,
            deleted_at_ms: None,
            failure_reason: None,
            create_certainty: CreateCertainty::AllocationAmbiguous,
            owner_uid: 0,
            accounting: SandboxAccounting::legacy(
                &SandboxSpec {
                    image: "alpine".into(),
                    memory_bytes: 1 << 29,
                    cpu_millis: 1000,
                    pids: 128,
                    disk_bytes: 1 << 30,
                    network: Network::Allow(vec!["example.com:443".into()]),
                    read_only_root: true,
                    writable_paths: vec!["/data".into()],
                    labels: BTreeMap::from([("owner".into(), "tests".into())]),
                },
                "",
            ),
            lifecycle: Default::default(),
        }
    }

    fn execution(sandbox_id: &str) -> Execution {
        Execution {
            id: new_id("ex"),
            sandbox_id: sandbox_id.into(),
            argv: vec!["sh".into(), "-c".into(), "echo 'hi'".into()],
            state: ExecutionState::Running,
            exit_code: None,
            command_status: None,
            runtime_error: None,
            failure_reason: None,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            timeout_ms: 1000,
            stdin_bytes: 3,
            stdout: Captured::default(),
            stderr: Captured::default(),
            sandbox_reusable: None,
            cleanup_evidence: CleanupEvidence::Unknown,
            cancel_reason: None,
            cwd: None,
            env_names: Vec::new(),
            env_sha256: None,
            mode: None,
        }
    }

    fn v4_database(dir: &Path) -> Connection {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.execute_batch(&schema_v4()).unwrap();
        conn.pragma_update(None, "user_version", 4).unwrap();
        conn
    }

    #[test]
    fn v5_column_matches_the_migration_exactly() {
        let column = MIGRATE_V5
            .split("ADD COLUMN ")
            .nth(1)
            .unwrap()
            .split(";\n")
            .next()
            .unwrap();
        assert!(SCHEMA.contains(column), "{column}");
    }

    #[test]
    fn v7_column_and_index_match_the_migration_exactly() {
        let column = MIGRATE_V7
            .split("ADD COLUMN ")
            .nth(1)
            .unwrap()
            .split(";\n")
            .next()
            .unwrap();
        assert!(SCHEMA.contains(column), "{column}");
        let index = MIGRATE_V7
            .lines()
            .find(|l| l.starts_with("CREATE INDEX"))
            .unwrap();
        assert!(SCHEMA.contains(index), "{index}");
    }

    /// The schema exactly as that version created it.
    fn schema_at(version: i64) -> String {
        match version {
            1 => schema_v2()
                .replace(",\n    list_seq       INTEGER NOT NULL", "")
                .replace("CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);", "")
                .replace("CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';", ""),
            2 => schema_v2(),
            3 => schema_v3(),
            4 => schema_v4(),
            5 => schema_v5(),
            6 => schema_v6(),
            7 => SCHEMA.to_string(),
            _ => unreachable!(),
        }
    }

    fn disk_database_at(dir: &Path, version: i64) -> Connection {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.execute_batch(&schema_at(version)).unwrap();
        conn.pragma_update(None, "user_version", version).unwrap();
        conn
    }

    fn release_database(conn: Connection, dir: &Path) {
        drop(conn);
        std::fs::set_permissions(dir.join("kilnd.db"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn column_descriptions(conn: &Connection) -> Vec<(String, String, bool, Option<String>)> {
        conn.prepare("SELECT name, type, \"notnull\", dflt_value FROM pragma_table_info('sandboxes') ORDER BY cid")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    fn sandbox_index_sql(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'sandboxes' AND sql IS NOT NULL ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn every_older_schema_gives_history_to_root_and_keeps_its_evidence() {
        let fresh = Store::open_in_memory().unwrap();
        let owner_column = |conn: &Connection| {
            column_descriptions(conn)
                .into_iter()
                .find(|column| column.0 == "owner_uid")
        };
        let (fresh_owner, fresh_indexes) = {
            let conn = fresh.conn();
            (owner_column(&conn), sandbox_index_sql(&conn))
        };
        assert!(fresh_owner.is_some());
        for version in 1..=6 {
            let tmp = tempfile::tempdir().unwrap();
            let conn = disk_database_at(tmp.path(), version);
            let spec = serde_json::to_string(&sandbox().spec).unwrap();
            let list_column = if version >= 2 { ", list_seq" } else { "" };
            let certainty_column = if version >= 5 {
                ", create_certainty"
            } else {
                ""
            };
            for (seq, (id, state, backend_id, certainty)) in [
                ("sb-ready", "ready", Some("ab-1"), "allocation_ambiguous"),
                ("sb-ambiguous", "failed", None, "allocation_ambiguous"),
                (
                    "sb-compensated",
                    "failed",
                    Some("ab-2"),
                    "allocation_ambiguous",
                ),
                ("sb-definite", "failed", None, "definitely_not_created"),
                ("sb-deleted", "deleted", None, "allocation_ambiguous"),
            ]
            .into_iter()
            .enumerate()
            {
                // A definite row cannot predate the marker's schema.
                if version < 5 && certainty == "definitely_not_created" {
                    continue;
                }
                let list_value = if version >= 2 {
                    format!(", {}", seq + 1)
                } else {
                    String::new()
                };
                let certainty_value = if version >= 5 {
                    format!(", '{certainty}'")
                } else {
                    String::new()
                };
                conn.execute(
                    &format!("INSERT INTO sandboxes (id,backend,backend_id,state,spec,created_at_ms,updated_at_ms{list_column}{certainty_column}) VALUES (?1,'fake',?2,?3,?4,?5,?5{list_value}{certainty_value})"),
                    params![id, backend_id, state, spec, seq as i64 + 1],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO executions (id,sandbox_id,argv,state,exit_code,timeout_ms,stdin_bytes,started_at_ms,stdout,stdout_bytes) VALUES ('ex-old','sb-ready','[\"echo\"]','exited',0,1,0,1,x'6b657074',4)",
                [],
            )
            .unwrap();
            // Retention may have advanced the counter past every surviving row.
            if version == 6 {
                conn.execute("UPDATE history_sequence SET value = 40", [])
                    .unwrap();
            }
            let expected_rows = if version >= 5 { 5 } else { 4 };
            // ambiguous FAILED and READY stay charged; the rest released capacity.
            let expected_reserved = 2;
            release_database(conn, tmp.path());
            for _reopen in 0..2 {
                let store = Store::reopen_after_restart(tmp.path());
                {
                    let conn = store.conn();
                    assert_eq!(
                        conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                            .unwrap(),
                        SCHEMA_VERSION
                    );
                    assert_eq!(owner_column(&conn), fresh_owner, "v{version}");
                    assert_eq!(sandbox_index_sql(&conn), fresh_indexes, "v{version}");
                }
                let rows = store.sandboxes(true).unwrap();
                assert_eq!(rows.len(), expected_rows, "v{version}");
                assert!(rows.iter().all(|row| row.owner_uid == 0), "v{version}");
                for row in &rows {
                    let definite = row.id == "sb-definite";
                    assert_eq!(
                        row.create_certainty,
                        if definite {
                            CreateCertainty::DefinitelyNotCreated
                        } else {
                            CreateCertainty::AllocationAmbiguous
                        },
                        "v{version} {}",
                        row.id
                    );
                }
                assert_eq!(
                    store.sandbox_resources().unwrap().sandboxes,
                    expected_reserved,
                    "v{version}"
                );
                let kept = store.execution("ex-old").unwrap().unwrap();
                assert_eq!(kept.sandbox_id, "sb-ready");
                assert_eq!(kept.stdout.data, b"kept");
                // Only root can see history; no other uid inherited anything.
                assert_eq!(
                    store.sandbox_page(true, None, None, 10).unwrap().rows.len(),
                    expected_rows
                );
                assert!(
                    store
                        .sandbox_page_owned(true, None, None, 10, Some(1001))
                        .unwrap()
                        .rows
                        .is_empty()
                );
            }
            let store = Store::reopen_after_restart(tmp.path());
            let mut inserted = sandbox();
            inserted.owner_uid = 1001;
            store.insert_sandbox(&inserted).unwrap();
            let page = store
                .sandbox_page_owned(true, None, None, 10, Some(1001))
                .unwrap();
            assert_eq!(page.rows[0].sandbox.id, inserted.id);
            if version == 6 {
                assert_eq!(page.rows[0].list_seq, 41);
            }
        }
    }

    /// Every statement of one absence-fenced row and matching evidence.
    fn fenced_sandbox() -> Sandbox {
        let spec = SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 512 << 20,
            cpu_millis: 1000,
            pids: 128,
            disk_bytes: 1 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: BTreeMap::new(),
        };
        let plan = b"immutable plan".to_vec();
        let mut row = Sandbox {
            spec: spec.clone(),
            accounting: SandboxAccounting::legacy(&spec, "offline-768-v1"),
            ..sandbox()
        };
        row.accounting.regime = AccountingRegime::AbsenceFenced;
        row.accounting.last_helper_generation = Some(0);
        row.accounting.reservation = crate::firecracker::offline_768_v1_reservation(&spec).unwrap();
        row.accounting.allocation = Some(AllocationBinding {
            node_id: Id128::random(),
            instance_id: Id128::random(),
            allocation_id: Id128::random(),
            plan_version: 1,
            plan_digest: Digest::of(&plan),
            plan,
        });
        row
    }

    fn receipt_for(row: &Sandbox) -> FencedAbsence {
        let binding = row.accounting.allocation.as_ref().unwrap();
        FencedAbsence::new(
            Id128::random(),
            binding.node_id,
            binding.instance_id,
            binding.allocation_id,
            binding.plan_digest,
            7,
            String::new(),
        )
        .unwrap()
    }

    fn insert_evidence(
        conn: &Connection,
        (receipt, node, instance, allocation, plan): (&str, &str, &str, &str, &str),
        generation: &str,
        kind: &str,
    ) -> rusqlite::Result<usize> {
        let encoded = FencedAbsence::new(
            Id128::parse(receipt).unwrap_or_else(|_| Id128::random()),
            Id128::parse(node).unwrap_or_else(|_| Id128::random()),
            Id128::parse(instance).unwrap_or_else(|_| Id128::random()),
            Id128::parse(allocation).unwrap_or_else(|_| Id128::random()),
            Digest::parse(plan).unwrap_or_else(|_| Digest::of(b"invalid")),
            generation
                .parse::<u64>()
                .ok()
                .filter(|n| *n >= 1)
                .unwrap_or(1),
            String::new(),
        )
        .unwrap()
        .encode()
        .unwrap();
        conn.execute(
            &format!(
                "INSERT INTO release_evidence (receipt_id, node_id, instance_id, allocation_id, plan_digest, helper_generation, kind, receipt, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, {generation}, {kind}, ?6, 1)"
            ),
            params![receipt, node, instance, allocation, plan, encoded],
        )
    }

    #[test]
    fn schema8_migration_preserves_every_legacy_version_charge_and_root_owner() {
        // The reported production row: a real ambiguous failure with no ID.
        const KNOWN_REAL: &str = "sb-7d028a9321df8d7b";
        let spec = sandbox().spec;
        let encoded = serde_json::to_string(&spec).unwrap();
        let expected = ResourceReservation::legacy_for_spec(&spec);
        let (host, guest) = crate::model::spec_digests(&spec);
        for version in 1..=7 {
            let tmp = tempfile::tempdir().unwrap();
            let conn = disk_database_at(tmp.path(), version);
            let list_column = if version >= 2 { ", list_seq" } else { "" };
            let certainty_column = if version >= 5 {
                ", create_certainty"
            } else {
                ""
            };
            let owner_column = if version >= 7 { ", owner_uid" } else { "" };
            // (id, state, backend, certainty, charged, tag)
            let rows = [
                (
                    "sb-creating",
                    "creating",
                    None,
                    "allocation_ambiguous",
                    true,
                    None,
                ),
                (
                    "sb-ready",
                    "ready",
                    Some("ab-1"),
                    "allocation_ambiguous",
                    true,
                    None,
                ),
                (
                    "sb-lost",
                    "lost",
                    Some("ab-2"),
                    "allocation_ambiguous",
                    true,
                    None,
                ),
                (
                    "sb-deleting",
                    "deleting",
                    Some("ab-3"),
                    "allocation_ambiguous",
                    true,
                    None,
                ),
                (
                    KNOWN_REAL,
                    "failed",
                    None,
                    "allocation_ambiguous",
                    true,
                    None,
                ),
                (
                    "sb-comp",
                    "failed",
                    Some("ab-4"),
                    "allocation_ambiguous",
                    false,
                    Some(LegacyRelease::Compensated),
                ),
                (
                    "sb-definite",
                    "failed",
                    None,
                    "definitely_not_created",
                    false,
                    Some(LegacyRelease::DefinitelyNotCreated),
                ),
                (
                    "sb-deleted",
                    "deleted",
                    Some("ab-5"),
                    "allocation_ambiguous",
                    false,
                    Some(LegacyRelease::Deleted),
                ),
            ];
            let mut kept = Vec::new();
            for (seq, row) in rows.iter().enumerate() {
                // A definite row cannot predate the marker's schema.
                if version < 5 && row.3 == "definitely_not_created" {
                    continue;
                }
                let list_value = if version >= 2 {
                    format!(", {}", seq + 1)
                } else {
                    String::new()
                };
                let certainty_value = if version >= 5 {
                    format!(", '{}'", row.3)
                } else {
                    String::new()
                };
                let owner_value = if version >= 7 {
                    ", 0".to_string()
                } else {
                    String::new()
                };
                conn.execute(
                    &format!("INSERT INTO sandboxes (id,backend,backend_id,state,spec,created_at_ms,updated_at_ms{list_column}{certainty_column}{owner_column}) VALUES (?1,'kiln',?2,?3,?4,?5,?5{list_value}{certainty_value}{owner_value})"),
                    params![row.0, row.2, row.1, encoded, seq as i64 + 1],
                )
                .unwrap();
                kept.push(row);
            }
            conn.execute(
                "INSERT INTO executions (id,sandbox_id,argv,state,exit_code,timeout_ms,stdin_bytes,started_at_ms,stdout,stdout_bytes) VALUES ('ex-old','sb-ready','[\"echo\"]','exited',0,1,0,1,x'6b657074',4)",
                [],
            )
            .unwrap();
            let charged = kept.iter().filter(|row| row.4).count() as u64;
            release_database(conn, tmp.path());
            let store = Store::reopen_after_restart(tmp.path());
            let identity = store.identity().unwrap();
            assert_eq!(
                store.sandbox_resources().unwrap(),
                SandboxResources {
                    sandboxes: charged,
                    memory_bytes: expected.memory_bytes * charged,
                    pids: expected.pids * charged,
                    disk_bytes: expected.disk_bytes * charged,
                    host_cpu_millis: 0,
                    virtual_cpu_slots: 0,
                    host_pids: 0,
                },
                "v{version}"
            );
            for row in &kept {
                let got = store.sandbox(row.0).unwrap().unwrap();
                assert_eq!(got.owner_uid, 0, "v{version} {}", row.0);
                assert_eq!(got.state.as_str(), row.1, "v{version} {}", row.0);
                assert_eq!(got.backend_id.as_deref(), row.2, "v{version} {}", row.0);
                assert_eq!(got.spec, spec, "v{version} {}", row.0);
                assert_eq!(got.accounting.regime, AccountingRegime::Legacy);
                assert_eq!(got.accounting.reservation, expected);
                assert_eq!(got.accounting.host_spec_sha256, host);
                assert_eq!(got.accounting.guest_exec_spec_sha256, guest);
                assert_eq!(got.accounting.allocation, None);
                assert_eq!(got.accounting.runtime_profile, "");
                assert_eq!(got.accounting.runtime_artifact_digest, "");
                assert_eq!(
                    got.accounting.release,
                    row.5
                        .map_or(ReservationRelease::Charged, ReservationRelease::Legacy),
                    "v{version} {}",
                    row.0
                );
                assert_eq!(got.is_charged(), row.4, "v{version} {}", row.0);
            }
            assert!(store.sandbox(KNOWN_REAL).unwrap().unwrap().is_charged());
            {
                let conn = store.conn();
                let stored: String = conn
                    .query_row(
                        "SELECT spec FROM sandboxes WHERE id = 'sb-ready'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(stored, encoded, "spec text is copied verbatim");
                assert!(
                    conn.execute("INSERT INTO executions (id,sandbox_id,argv,state,timeout_ms,stdin_bytes,started_at_ms) VALUES ('ex-orphan','sb-missing','[]','running',1,0,1)", [])
                        .is_err(),
                    "v{version} kept the executions foreign key"
                );
            }
            let history = store.execution("ex-old").unwrap().unwrap();
            assert_eq!(history.stdout.data, b"kept");
            assert_eq!(history.sandbox_reusable, None, "v{version}");
            assert_eq!(
                history.cleanup_evidence,
                CleanupEvidence::Unknown,
                "v{version}"
            );
            // Foreign callers inherit nothing.
            assert!(
                store
                    .sandbox_page_owned(true, None, None, 10, Some(1001))
                    .unwrap()
                    .rows
                    .is_empty()
            );
            drop(store);
            let store = Store::reopen_after_restart(tmp.path());
            assert_eq!(
                store.identity().unwrap(),
                identity,
                "v{version}: identity is durable"
            );
            assert_eq!(store.sandbox_resources().unwrap().sandboxes, charged);
            // Delete of the real ambiguous row is still not something Store infers.
            store
                .set_sandbox_state(
                    KNOWN_REAL,
                    SandboxState::Failed,
                    None,
                    Some("still ambiguous"),
                )
                .unwrap();
            assert!(store.sandbox(KNOWN_REAL).unwrap().unwrap().is_charged());
        }
    }

    #[test]
    fn schema9_fresh_and_migrated_schemas_are_identical() {
        let schema_sql = |conn: &Connection| -> Vec<(String, String)> {
            conn.prepare(
                "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        let fresh = Store::open_in_memory().unwrap();
        let expected = schema_sql(&fresh.conn());
        for version in 1..=8 {
            let tmp = tempfile::tempdir().unwrap();
            let mut conn = disk_database_at(tmp.path(), version.min(7));
            if version == 8 {
                let tx = conn.transaction().unwrap();
                migrate_v8(&tx).unwrap();
                tx.commit().unwrap();
            }
            release_database(conn, tmp.path());
            let store = Store::reopen_after_restart(tmp.path());
            // Compare after every supported historical schema reaches schema 9.
            assert_eq!(schema_sql(&store.conn()), expected, "v{version}");
        }
    }

    /// Schema 11 from schemas 9 and 10 (the earlier ones are covered above) equals a
    /// fresh schema, and history gets nulls and seq 0: never expires, reason unknown.
    #[test]
    fn schema11_from_9_and_10_matches_fresh_and_history_never_expires() {
        let schema_sql = |conn: &Connection| -> Vec<(String, String)> {
            conn.prepare(
                "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        let fresh = Store::open_in_memory().unwrap();
        let expected = schema_sql(&fresh.conn());
        for version in [9, 10] {
            let tmp = tempfile::tempdir().unwrap();
            let mut conn = disk_database_at(tmp.path(), 7);
            register_receipt_validator(&conn).unwrap();
            let tx = conn.transaction().unwrap();
            migrate_v8(&tx).unwrap();
            tx.execute_batch(MIGRATE_V9).unwrap();
            if version == 10 {
                tx.execute_batch(MIGRATE_V10).unwrap();
            }
            let mut history = sandbox();
            history.state = SandboxState::Ready;
            history.backend_id = Some(format!("old-{version}"));
            insert_sandbox_before_v11(&tx, &history).unwrap();
            if version == 10 {
                refresh_reservation_integrity(&tx).unwrap();
            }
            tx.commit().unwrap();
            release_database(conn, tmp.path());
            let store = Store::reopen_after_restart(tmp.path());
            assert_eq!(schema_sql(&store.conn()), expected, "v{version}");
            let row = store.sandbox(&history.id).unwrap().unwrap();
            assert_eq!(row.lifecycle, SandboxLifecycle::default(), "v{version}");
            assert!(!row.lifecycle.expiry.expires());
            assert!(store.expiry_rows().unwrap().is_empty());
        }
    }

    /// Break-it MEDIUM 3 regression (the review's PoC): a schema 10 marker that no
    /// longer matches refuses the upgrade, which rolls back whole: still schema 10,
    /// the same rows and the same marker, so the evidence survives for an operator.
    #[test]
    fn schema11_upgrade_refuses_a_v10_reservation_mismatch() {
        for corruption in ["missing charged row", "changed marker"] {
            let tmp = tempfile::tempdir().unwrap();
            let mut conn = disk_database_at(tmp.path(), 7);
            register_receipt_validator(&conn).unwrap();
            let tx = conn.transaction().unwrap();
            migrate_v8(&tx).unwrap();
            tx.execute_batch(MIGRATE_V9).unwrap();
            tx.execute_batch(MIGRATE_V10).unwrap();
            let mut charged = sandbox();
            charged.state = SandboxState::Failed;
            charged.failure_reason = Some("ambiguous create".into());
            insert_sandbox_before_v11(&tx, &charged).unwrap();
            refresh_reservation_integrity(&tx).unwrap();
            tx.commit().unwrap();
            conn.execute_batch("CREATE TEMP TABLE accounting_quarantine (id TEXT PRIMARY KEY);")
                .unwrap();
            assert!(audit_reservation_integrity_v1(&conn).is_ok(), "{corruption}: intact first");
            match corruption {
                "missing charged row" => {
                    // Membership lost after v10 last wrote its marker, past the triggers.
                    conn.set_db_config(
                        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                        false,
                    )
                    .unwrap();
                    conn.execute("DELETE FROM sandboxes WHERE id = ?1", [&charged.id])
                        .unwrap();
                }
                _ => {
                    conn.execute(
                        "UPDATE reservation_integrity SET digest = ?1 WHERE id = 1",
                        [vec![7u8; 32]],
                    )
                    .unwrap();
                }
            }
            assert!(audit_reservation_integrity_v1(&conn).is_err(), "{corruption}: v10 detects it");
            let rows = table_snapshot(&conn, "sandboxes");
            let marker = table_snapshot(&conn, "reservation_integrity");
            release_database(conn, tmp.path());

            let error = Store::open(tmp.path()).err().expect(corruption);
            let message = format!("{error:#}");
            assert!(message.contains("reservation integrity"), "{message}");

            let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
            let version: i64 = conn
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!(version, 10, "{corruption}: the migration rolled back");
            assert_eq!(table_snapshot(&conn, "sandboxes"), rows, "{corruption}");
            assert_eq!(
                table_snapshot(&conn, "reservation_integrity"),
                marker,
                "{corruption}: the marker is never rewritten"
            );
            drop(conn);
        }
    }

    /// MEDIUM 3: an intact schema 10 marker is verified as it stands (the schema 11
    /// columns are not membership); schema 12 then replaces it with aggregates
    /// seeded from the same rows (M2 MEDIUM 2).
    #[test]
    fn schema12_upgrade_verifies_an_intact_v10_marker_and_seeds_membership() {
        let tmp = tempfile::tempdir().unwrap();
        let mut conn = disk_database_at(tmp.path(), 7);
        register_receipt_validator(&conn).unwrap();
        let tx = conn.transaction().unwrap();
        migrate_v8(&tx).unwrap();
        tx.execute_batch(MIGRATE_V9).unwrap();
        tx.execute_batch(MIGRATE_V10).unwrap();
        let mut charged = sandbox();
        charged.state = SandboxState::Failed;
        charged.failure_reason = Some("ambiguous create".into());
        insert_sandbox_before_v11(&tx, &charged).unwrap();
        refresh_reservation_integrity(&tx).unwrap();
        tx.commit().unwrap();
        release_database(conn, tmp.path());
        let store = Store::open(tmp.path()).unwrap();
        assert_seeded_membership(&store.conn(), 1, 0);
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);
    }

    /// Schema 12's aggregates match the rows as they stand: `rows` in all, `settled`
    /// of them uncharged, nothing unsettled, and no schema 10 marker left.
    fn assert_seeded_membership(conn: &Connection, rows: i64, settled: i64) {
        let (all, settled_stored) = stored_membership(conn).unwrap().unwrap();
        assert_eq!(all, all_membership(conn).unwrap());
        assert_eq!(settled_stored, settled_membership(conn).unwrap());
        assert_eq!((all.count, settled_stored.count), (rows, settled));
        let unsettled: i64 = conn
            .query_row("SELECT COUNT(*) FROM reservation_unsettled", [], |r| r.get(0))
            .unwrap();
        assert_eq!(unsettled, 0);
        let old: bool = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 'reservation_integrity')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!old);
    }

    /// MEDIUM 2: both startup publications of a terminal execution record the
    /// parent's finish activity in their own transaction, legacy and fenced.
    #[test]
    fn startup_terminal_publications_record_finish_activity() {
        let store = Store::open_in_memory().unwrap();
        let clock = crate::expiry::ManualClock::default();
        store.set_clock(std::sync::Arc::new(clock.clone()));
        let mut legacy = sandbox();
        legacy.lifecycle.expiry.idle_timeout_ms = Some(60_000);
        store.insert_sandbox(&legacy).unwrap();
        store
            .set_sandbox_state(&legacy.id, SandboxState::Ready, Some("b-1"), None)
            .unwrap();
        let e = execution(&legacy.id);
        assert!(store.start_execution(&e).unwrap());
        let before = store.sandbox(&legacy.id).unwrap().unwrap().lifecycle;
        clock.advance(900_000);
        assert_eq!(
            store
                .interrupt_running_executions_for_backend(&legacy.backend, "restart")
                .unwrap(),
            1
        );
        let after = store.sandbox(&legacy.id).unwrap().unwrap().lifecycle;
        assert_eq!(after.activity_seq, before.activity_seq + 1);
        assert_eq!(after.activity_boottime_ms, Some(clock.boottime_ms()));

        let mut fenced = fenced_sandbox();
        fenced.lifecycle.expiry.idle_timeout_ms = Some(60_000);
        store.insert_sandbox(&fenced).unwrap();
        let binding = fenced.accounting.allocation.clone().unwrap();
        let created = CreatedSandbox {
            backend_id: binding.backend_id(),
            receipt: RuntimeReceipt::Ready(crate::runtime::ReadyReceipt {
                node_id: binding.node_id,
                instance_id: binding.instance_id,
                allocation_id: binding.allocation_id,
                plan_digest: binding.plan_digest,
                helper_generation: 3,
                boot_id: "boot-1".into(),
            }),
            exec_features: None,
        };
        assert!(store.publish_fenced_ready(&fenced.id, &created).unwrap());
        let e = execution(&fenced.id);
        assert!(store.start_execution(&e).unwrap());
        let before = store.sandbox(&fenced.id).unwrap().unwrap().lifecycle;
        clock.advance(900_000);
        assert_eq!(
            store
                .conclude_running_executions(&fenced.id, true, "restart")
                .unwrap(),
            1
        );
        let after = store.sandbox(&fenced.id).unwrap().unwrap().lifecycle;
        assert_eq!(after.activity_seq, before.activity_seq + 1);
        assert_eq!(after.activity_boottime_ms, Some(clock.boottime_ms()));
    }

    #[test]
    fn schema11_triggers_defend_policy_reasons_sequence_and_anchors() {
        let store = Store::open_in_memory().unwrap();
        let clock = crate::expiry::ManualClock::default();
        store.set_clock(std::sync::Arc::new(clock.clone()));
        let mut row = sandbox();
        row.lifecycle.expiry = ExpiryPolicy {
            max_lifetime_ms: Some(60_000),
            idle_timeout_ms: Some(30_000),
        };
        store.insert_sandbox(&row).unwrap();
        store
            .set_sandbox_state(&row.id, SandboxState::Ready, Some("b-1"), None)
            .unwrap();
        let ready = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(ready.lifecycle.ready_boottime_ms, Some(1_000_000));
        assert_eq!(ready.lifecycle.activity_boottime_ms, Some(1_000_000));
        assert_eq!(ready.lifecycle.clock_boot_id.as_deref(), Some("boot-a"));
        let conn = store.conn();
        for attack in [
            "UPDATE sandboxes SET expiry_lifetime_ms = 1 WHERE id = ?1",
            "UPDATE sandboxes SET expiry_idle_ms = NULL WHERE id = ?1",
            "UPDATE sandboxes SET deletion_reason = 'expired_idle' WHERE id = ?1",
            "UPDATE sandboxes SET deletion_reason = 'bogus', state = 'deleting' WHERE id = ?1",
            "UPDATE sandboxes SET activity_seq = -1 WHERE id = ?1",
            "UPDATE sandboxes SET ready_at_ms = ready_at_ms + 1 WHERE id = ?1",
            "UPDATE sandboxes SET ready_boottime_ms = ready_boottime_ms + 1 WHERE id = ?1",
            "UPDATE sandboxes SET expiry_lifetime_ms = 'x' WHERE id = ?1",
        ] {
            assert!(conn.execute(attack, [&row.id]).is_err(), "{attack}");
        }
        conn.execute(
            "UPDATE sandboxes SET activity_seq = 5 WHERE id = ?1",
            [&row.id],
        )
        .unwrap();
        assert!(
            conn.execute(
                "UPDATE sandboxes SET activity_seq = 4 WHERE id = ?1",
                [&row.id]
            )
            .is_err()
        );
        // Only a rebase, which moves the boot ID with them, moves a READY anchor.
        conn.execute(
            "UPDATE sandboxes SET ready_boottime_ms = 7, activity_boottime_ms = 7, clock_boot_id = 'boot-b' WHERE id = ?1",
            [&row.id],
        )
        .unwrap();
        drop(conn);
        assert!(
            store
                .publish_expiry_intent(&row.id, DeletionReason::ExpiredIdle, Some(5))
                .unwrap()
        );
        let conn = store.conn();
        // MEDIUM 1: the intent's wall anchor is written; its boottime only in the
        // row's own boot (this one is boot-b's), and both move only with a rebase.
        let (intent_at, intent_boot): (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT expiry_intent_at_ms, expiry_intent_boottime_ms FROM sandboxes WHERE id = ?1",
                [&row.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(intent_at.is_some());
        assert_eq!(intent_boot, None);
        conn.execute(
            "UPDATE sandboxes SET expiry_intent_boottime_ms = 9, clock_boot_id = 'boot-c' WHERE id = ?1",
            [&row.id],
        )
        .unwrap();
        for attack in [
            "UPDATE sandboxes SET deletion_reason = 'expired_lifetime' WHERE id = ?1",
            "UPDATE sandboxes SET deletion_reason = NULL WHERE id = ?1",
            "UPDATE sandboxes SET expiry_intent_at_ms = expiry_intent_at_ms + 1 WHERE id = ?1",
            "UPDATE sandboxes SET expiry_intent_boottime_ms = 10 WHERE id = ?1",
            "UPDATE sandboxes SET expiry_intent_at_ms = NULL WHERE id = ?1",
        ] {
            assert!(conn.execute(attack, [&row.id]).is_err(), "{attack}");
        }
        let mut inserted = sandbox();
        inserted.lifecycle.deletion_reason = Some(DeletionReason::Requested);
        drop(conn);
        assert!(
            store.insert_sandbox(&inserted).is_err(),
            "a reason needs DELETING or DELETED"
        );
        // A cancel reason is written once.
        let mut other = sandbox();
        other.state = SandboxState::Ready;
        other.backend_id = Some("b-2".into());
        store.insert_sandbox(&other).unwrap();
        let e = execution(&other.id);
        assert!(store.start_execution(&e).unwrap());
        store
            .finish_execution(
                &e.id,
                &ExecutionResult {
                    state: ExecutionState::Canceled,
                    exit_code: None,
                    command_status: None,
                    runtime_error: None,
                    failure_reason: Some("canceled"),
                    stdout: &Captured::default(),
                    stderr: &Captured::default(),
                    sandbox_reusable: Some(true),
                    cleanup_evidence: CleanupEvidence::NoChildStarted,
                    disposition: None,
                    disposition_reason: None,
                    cancel_reason: Some(CancelReason::ClientDisconnected),
                },
            )
            .unwrap();
        assert_eq!(
            store.execution(&e.id).unwrap().unwrap().cancel_reason,
            Some(CancelReason::ClientDisconnected)
        );
        let conn = store.conn();
        for attack in [
            "UPDATE executions SET cancel_reason = 'daemon_shutdown' WHERE id = ?1",
            "UPDATE executions SET cancel_reason = NULL WHERE id = ?1",
        ] {
            assert!(conn.execute(attack, [&e.id]).is_err(), "{attack}");
        }
    }

    #[test]
    fn renew_writes_only_on_ready_and_coalesces_within_a_second() {
        let store = Store::open_in_memory().unwrap();
        let clock = crate::expiry::ManualClock::default();
        store.set_clock(std::sync::Arc::new(clock.clone()));
        let row = sandbox();
        store.insert_sandbox(&row).unwrap();
        let (creating, renewed) = store.renew(&row.id).unwrap().unwrap();
        assert!(!renewed);
        assert_eq!(creating.lifecycle.activity_seq, 0);
        store
            .set_sandbox_state(&row.id, SandboxState::Ready, Some("b-1"), None)
            .unwrap();
        clock.advance(999);
        let (same, renewed) = store.renew(&row.id).unwrap().unwrap();
        assert!(renewed);
        assert_eq!(same.lifecycle.activity_seq, 0, "coalesced with READY");
        clock.advance(1);
        let (moved, _) = store.renew(&row.id).unwrap().unwrap();
        assert_eq!(moved.lifecycle.activity_seq, 1);
        assert_eq!(
            moved.lifecycle.activity_boottime_ms,
            Some(clock.boottime_ms())
        );
        assert!(store.renew("sb-0000000000000000").unwrap().is_none());
    }

    #[test]
    fn schema8_migration_failure_rolls_back_the_whole_upgrade() {
        for version in 1..=7 {
            let tmp = tempfile::tempdir().unwrap();
            let conn = disk_database_at(tmp.path(), version);
            let list = if version >= 2 { ",list_seq" } else { "" };
            let value = if version >= 2 { ",1" } else { "" };
            conn.execute(
                &format!("INSERT INTO sandboxes (id,backend,state,spec,created_at_ms,updated_at_ms{list}) VALUES ('sb-corrupt','kiln','failed','not json',1,1{value})"),
                [],
            )
            .unwrap();
            release_database(conn, tmp.path());
            let error = Store::open(tmp.path())
                .err()
                .expect("a corrupt spec cannot migrate");
            assert!(format!("{error:#}").contains("sb-corrupt"), "{error:#}");
            let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
            assert_eq!(
                conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                version
            );
            let leftovers: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('release_evidence','daemon_identity','sandboxes_v8','executions_v8')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(leftovers, 0, "v{version}");
        }
    }

    #[test]
    fn every_store_connection_enforces_foreign_keys() {
        fn assert_enforced(store: &Store, label: &str) {
            let conn = store.conn();
            assert_eq!(
                conn.pragma_query_value::<i64, _>(None, "foreign_keys", |r| r.get(0))
                    .unwrap(),
                1,
                "{label}"
            );
            assert!(
                conn.execute(
                    "INSERT INTO executions (id,sandbox_id,argv,state,timeout_ms,stdin_bytes,started_at_ms) VALUES ('ex-orphan','sb-missing','[]','running',1,0,1)",
                    [],
                )
                .is_err(),
                "{label}"
            );
        }
        assert_enforced(&Store::open_in_memory().unwrap(), "in memory");
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let created = Store::open(&dir).unwrap();
        assert_enforced(&created, "created on disk");
        drop(created);
        assert_enforced(
            &Store::reopen_after_restart(&dir),
            "reopened at the current schema",
        );
        for version in 1..=7 {
            let tmp = tempfile::tempdir().unwrap();
            let conn = disk_database_at(tmp.path(), version);
            release_database(conn, tmp.path());
            assert_enforced(
                &Store::reopen_after_restart(tmp.path()),
                &format!("migrated v{version}"),
            );
        }
    }

    #[test]
    fn direct_sql_cannot_release_without_matching_evidence() {
        let store = Store::open_in_memory().unwrap();
        let row = fenced_sandbox();
        let binding = row.accounting.allocation.clone().unwrap();
        store.insert_sandbox(&row).unwrap();
        let charged = SandboxResources::for_reservation(&row.accounting.reservation);
        assert_eq!(store.sandbox_resources().unwrap(), charged);
        let id = row.id.clone();
        let (node, instance, allocation, plan) = (
            binding.node_id.to_string(),
            binding.instance_id.to_string(),
            binding.allocation_id.to_string(),
            binding.plan_digest.to_string(),
        );
        let other = Id128::random().to_string();
        let other_digest = Digest::of(b"other").to_string();

        {
            let conn = store.conn();
            // FAILED, a backend ID and a definite claim all leave it charged or refused.
            conn.execute("UPDATE sandboxes SET state = 'failed' WHERE id = ?1", [&id])
                .unwrap();
            conn.execute(
                "UPDATE sandboxes SET backend_id = 'fc-' || allocation_id WHERE id = ?1",
                [&id],
            )
            .unwrap();
            drop(conn);
            assert_eq!(
                store.sandbox_resources().unwrap(),
                charged,
                "FAILED with a backend ID"
            );
            let conn = store.conn();
            for attack in [
                // The certainty marker and every legacy tag.
                "UPDATE sandboxes SET create_certainty = 'definitely_not_created' WHERE id = ?1",
                "UPDATE sandboxes SET backend_id = NULL, create_certainty = 'definitely_not_created' WHERE id = ?1",
                "UPDATE sandboxes SET legacy_release = 'compensated' WHERE id = ?1",
                "UPDATE sandboxes SET legacy_release = 'definitely_not_created' WHERE id = ?1",
                "UPDATE sandboxes SET state = 'deleted', legacy_release = 'deleted' WHERE id = ?1",
                // Laundering the row into another regime.
                "UPDATE sandboxes SET accounting_kind = 'legacy' WHERE id = ?1",
                "UPDATE sandboxes SET accounting_kind = 'legacy', legacy_release = 'compensated', node_id = NULL, instance_id = NULL, allocation_id = NULL, plan_version = NULL, plan_digest = NULL, plan = NULL WHERE id = ?1",
                // A boolean does not exist to set.
                "UPDATE sandboxes SET reservation_released = 1 WHERE id = ?1",
                // DELETED always needs evidence.
                "UPDATE sandboxes SET state = 'deleted' WHERE id = ?1",
                // A missing receipt.
                "UPDATE sandboxes SET release_evidence_id = '00000000000000000000000000000000' WHERE id = ?1",
                // Direct deletion of a charged row.
                "DELETE FROM sandboxes WHERE id = ?1",
                // Every immutable identity, plan, spec and reservation field.
                "UPDATE sandboxes SET allocation_id = '00000000000000000000000000000000' WHERE id = ?1",
                "UPDATE sandboxes SET node_id = '00000000000000000000000000000000' WHERE id = ?1",
                "UPDATE sandboxes SET instance_id = '00000000000000000000000000000000' WHERE id = ?1",
                "UPDATE sandboxes SET plan_digest = '0000000000000000000000000000000000000000000000000000000000000000' WHERE id = ?1",
                "UPDATE sandboxes SET plan = x'00' WHERE id = ?1",
                "UPDATE sandboxes SET plan_version = 2 WHERE id = ?1",
                "UPDATE sandboxes SET spec = '{}' WHERE id = ?1",
                "UPDATE sandboxes SET host_spec_sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE id = ?1",
                "UPDATE sandboxes SET guest_exec_spec_sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE id = ?1",
                "UPDATE sandboxes SET reserved_memory_bytes = 0 WHERE id = ?1",
                "UPDATE sandboxes SET reserved_disk_bytes = 0 WHERE id = ?1",
                "UPDATE sandboxes SET reserved_pids = 0 WHERE id = ?1",
                "UPDATE sandboxes SET reserved_host_cpu_millis = 0 WHERE id = ?1",
                "UPDATE sandboxes SET reserved_virtual_cpu_slots = 0 WHERE id = ?1",
                "UPDATE sandboxes SET reserved_host_pids = 0 WHERE id = ?1",
                "UPDATE sandboxes SET owner_uid = 1 WHERE id = ?1",
                "UPDATE sandboxes SET backend = 'other' WHERE id = ?1",
                "UPDATE sandboxes SET runtime_profile = 'other' WHERE id = ?1",
                // Another allocation's backend ID.
                "UPDATE sandboxes SET backend_id = 'fc-00000000000000000000000000000000' WHERE id = ?1",
            ] {
                assert!(conn.execute(attack, [&id]).is_err(), "{attack}");
            }
            // Malformed evidence cannot even enter the table.
            let good = (
                other.as_str(),
                node.as_str(),
                instance.as_str(),
                allocation.as_str(),
                plan.as_str(),
            );
            assert!(
                conn.execute(
                    "INSERT INTO release_evidence (node_id,instance_id,allocation_id,plan_digest,helper_generation,kind,receipt,recorded_at_ms) VALUES (?1,?2,?3,?4,1,'absent_fenced',x'00',0)",
                    params![node, instance, allocation, plan],
                ).is_err(),
                "missing receipt ID"
            );
            assert!(
                insert_evidence(&conn, good, "1", "'stopped'").is_err(),
                "wrong kind"
            );
            assert!(
                insert_evidence(&conn, good, "1", "NULL").is_err(),
                "missing kind"
            );
            assert!(
                insert_evidence(&conn, good, "0", "'absent_fenced'").is_err(),
                "generation 0"
            );
            assert!(
                insert_evidence(&conn, good, "-1", "'absent_fenced'").is_err(),
                "negative generation"
            );
            assert!(
                insert_evidence(&conn, good, "NULL", "'absent_fenced'").is_err(),
                "missing generation"
            );
            assert!(
                insert_evidence(&conn, good, "1.5", "'absent_fenced'").is_err(),
                "fractional generation"
            );
            for (column, position) in [
                ("receipt_id", 0),
                ("node_id", 1),
                ("instance_id", 2),
                ("allocation_id", 3),
                ("plan_digest", 4),
            ] {
                let mut fields = [good.0, good.1, good.2, good.3, good.4];
                fields[position] = "not hex";
                assert!(
                    insert_evidence(
                        &conn,
                        (fields[0], fields[1], fields[2], fields[3], fields[4]),
                        "1",
                        "'absent_fenced'"
                    )
                    .is_err(),
                    "malformed {column}"
                );
            }

            // Well-formed evidence for another identity cannot satisfy this row.
            for (i, (node, instance, allocation, plan)) in [
                (
                    other.as_str(),
                    instance.as_str(),
                    allocation.as_str(),
                    plan.as_str(),
                ),
                (
                    node.as_str(),
                    other.as_str(),
                    allocation.as_str(),
                    plan.as_str(),
                ),
                (
                    node.as_str(),
                    instance.as_str(),
                    other.as_str(),
                    plan.as_str(),
                ),
                (
                    node.as_str(),
                    instance.as_str(),
                    allocation.as_str(),
                    other_digest.as_str(),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let receipt = Id128::random().to_string();
                // Evidence for this exact allocation may exist only once, so give
                // each mismatched case a distinct allocation when it is not the field.
                let alloc = if i == 2 {
                    allocation.to_string()
                } else {
                    Id128::random().to_string()
                };
                insert_evidence(
                    &conn,
                    (&receipt, node, instance, &alloc, plan),
                    "1",
                    "'absent_fenced'",
                )
                .unwrap();
                assert!(
                    conn.execute(
                        "UPDATE sandboxes SET release_evidence_id = ?2 WHERE id = ?1",
                        params![id, receipt],
                    )
                    .is_err(),
                    "mismatched identity {i}"
                );
            }
        }
        assert_eq!(store.sandbox_resources().unwrap(), charged);

        // A legacy row can never reference evidence, and its tag must fit its state.
        let legacy = sandbox();
        store.insert_sandbox(&legacy).unwrap();
        store
            .set_sandbox_state(&legacy.id, SandboxState::Failed, None, Some("ambiguous"))
            .unwrap();
        {
            let conn = store.conn();
            let evidence = Id128::random().to_string();
            insert_evidence(
                &conn,
                (
                    &evidence,
                    &node,
                    &instance,
                    &Id128::random().to_string(),
                    &plan,
                ),
                "1",
                "'absent_fenced'",
            )
            .unwrap();
            assert!(
                conn.execute(
                    "UPDATE sandboxes SET release_evidence_id = ?2 WHERE id = ?1",
                    params![legacy.id, evidence]
                )
                .is_err()
            );
            for laundering in [
                "UPDATE sandboxes SET legacy_release = 'compensated' WHERE id = ?1",
                "UPDATE sandboxes SET legacy_release = 'definitely_not_created' WHERE id = ?1",
                "UPDATE sandboxes SET legacy_release = 'deleted' WHERE id = ?1",
                "UPDATE sandboxes SET legacy_release = 'freed' WHERE id = ?1",
                "UPDATE sandboxes SET state = 'deleted' WHERE id = ?1",
                "DELETE FROM sandboxes WHERE id = ?1",
                "UPDATE sandboxes SET accounting_kind = 'fenced' WHERE id = ?1",
                // Forging the facts a tag would need does not work either.
                "UPDATE sandboxes SET backend_id = 'f00d', legacy_release = 'compensated' WHERE id = ?1",
                "UPDATE sandboxes SET create_certainty = 'definitely_not_created', legacy_release = 'definitely_not_created' WHERE id = ?1",
                "UPDATE sandboxes SET state = 'deleted', legacy_release = 'deleted' WHERE id = ?1",
            ] {
                assert!(
                    conn.execute(laundering, [&legacy.id]).is_err(),
                    "{laundering}"
                );
            }
        }
        // A conflict clause cannot delete another charged row by its unique index.
        let (victim, attacker) = (sandbox(), sandbox());
        store.insert_sandbox(&victim).unwrap();
        store.insert_sandbox(&attacker).unwrap();
        store
            .set_sandbox_state(&victim.id, SandboxState::Ready, Some("taken"), None)
            .unwrap();
        store
            .set_sandbox_state(&attacker.id, SandboxState::Ready, Some("mine"), None)
            .unwrap();
        assert!(
            store
                .conn()
                .execute(
                    "UPDATE OR REPLACE sandboxes SET backend_id = 'taken' WHERE id = ?1",
                    [&attacker.id],
                )
                .is_err()
        );
        assert!(store.sandbox(&victim.id).unwrap().is_some());
        store
            .set_sandbox_state(&victim.id, SandboxState::Deleted, None, None)
            .unwrap();
        store
            .set_sandbox_state(&attacker.id, SandboxState::Deleted, None, None)
            .unwrap();

        // The typed path, then everything that would undo it.
        let receipt = receipt_for(&row);
        store
            .release_fenced(&id, SandboxState::Failed, &receipt, None)
            .unwrap();
        let released = store.sandbox(&id).unwrap().unwrap();
        assert_eq!(
            released.accounting.release,
            ReservationRelease::Fenced(receipt.receipt_id())
        );
        assert_eq!(
            store.sandbox_resources().unwrap().sandboxes,
            1,
            "only the legacy row is left"
        );
        let receipt_id = receipt.receipt_id().to_string();
        {
            let conn = store.conn();
            for attack in [
                "UPDATE sandboxes SET release_evidence_id = NULL WHERE id = ?1",
                "UPDATE sandboxes SET state = 'ready' WHERE id = ?1",
                "UPDATE sandboxes SET state = 'deleting' WHERE id = ?1",
                "UPDATE sandboxes SET state = 'creating' WHERE id = ?1",
                "UPDATE sandboxes SET state = 'quarantined' WHERE id = ?1",
                "UPDATE sandboxes SET release_evidence_kind = 'other' WHERE id = ?1",
            ] {
                assert!(conn.execute(attack, [&id]).is_err(), "{attack}");
            }
            // Evidence itself is permanent, including through a conflict clause.
            for attack in [
                "UPDATE release_evidence SET helper_generation = 8 WHERE receipt_id = ?1",
                "UPDATE release_evidence SET plan_digest = '0000000000000000000000000000000000000000000000000000000000000000' WHERE receipt_id = ?1",
                "UPDATE release_evidence SET kind = 'stopped' WHERE receipt_id = ?1",
                "DELETE FROM release_evidence WHERE receipt_id = ?1",
                "INSERT OR REPLACE INTO release_evidence SELECT receipt_id, node_id, instance_id, allocation_id, plan_digest, 9, kind, receipt, recorded_at_ms FROM release_evidence WHERE receipt_id = ?1",
            ] {
                assert!(conn.execute(attack, [&receipt_id]).is_err(), "{attack}");
            }
        }

        // A receipt for another identity or a second receipt changes nothing.
        let unreleased = fenced_sandbox();
        store.insert_sandbox(&unreleased).unwrap();
        let before = store.sandbox_resources().unwrap();
        let b = unreleased.accounting.allocation.clone().unwrap();
        let forged = |node, instance, allocation, plan| {
            FencedAbsence::new(
                Id128::random(),
                node,
                instance,
                allocation,
                plan,
                1,
                String::new(),
            )
            .unwrap()
        };
        let (other_id, other_plan) = (Id128::random(), Digest::of(b"x"));
        for wrong in [
            forged(other_id, b.instance_id, b.allocation_id, b.plan_digest),
            forged(b.node_id, other_id, b.allocation_id, b.plan_digest),
            forged(b.node_id, b.instance_id, other_id, b.plan_digest),
            forged(b.node_id, b.instance_id, b.allocation_id, other_plan),
            receipt.clone(),
        ] {
            assert!(
                store
                    .release_fenced(&unreleased.id, SandboxState::Failed, &wrong, None)
                    .is_err()
            );
        }
        assert!(
            store
                .release_fenced(
                    &legacy.id,
                    SandboxState::Failed,
                    &receipt_for(&unreleased),
                    None
                )
                .is_err()
        );
        assert!(
            store
                .release_fenced(
                    &unreleased.id,
                    SandboxState::Ready,
                    &receipt_for(&unreleased),
                    None
                )
                .is_err()
        );
        assert_eq!(store.sandbox_resources().unwrap(), before);
        let second = receipt_for(&row);
        assert!(
            store
                .release_fenced(&id, SandboxState::Deleted, &second, None)
                .is_err()
        );

        // An exact replay is a true no-op, and FAILED can advance keeping evidence.
        let row_before = store.sandbox(&id).unwrap().unwrap();
        store
            .release_fenced(&id, SandboxState::Failed, &receipt, None)
            .unwrap();
        assert_eq!(store.sandbox(&id).unwrap().unwrap(), row_before);
        store
            .release_fenced(&id, SandboxState::Deleted, &receipt, None)
            .unwrap();
        let deleted = store.sandbox(&id).unwrap().unwrap();
        assert_eq!(deleted.state, SandboxState::Deleted);
        assert_eq!(
            deleted.accounting.release,
            ReservationRelease::Fenced(receipt.receipt_id())
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
        store
            .release_fenced(&id, SandboxState::Deleted, &receipt, None)
            .unwrap();
        assert_eq!(
            store.sandbox(&id).unwrap().unwrap(),
            deleted,
            "replay keeps timestamps"
        );
        assert!(
            store
                .conn()
                .execute("UPDATE sandboxes SET state = 'failed' WHERE id = ?1", [&id])
                .is_err()
        );
    }

    #[test]
    fn triggers_defend_evidence_even_on_a_foreign_key_disabled_connection() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        let charged = store.sandbox_resources().unwrap();
        drop(store);
        // Bypasses Store deliberately, as a stray writer with foreign keys off would.
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        assert_eq!(
            conn.pragma_query_value::<i64, _>(None, "foreign_keys", |r| r.get(0))
                .unwrap(),
            0
        );
        for attack in [
            "UPDATE sandboxes SET state = 'failed', release_evidence_id = '00000000000000000000000000000000' WHERE id = ?1",
            "DELETE FROM sandboxes WHERE id = ?1",
        ] {
            assert!(conn.execute(attack, [&row.id]).is_err(), "{attack}");
        }
        drop(conn);
        let store = Store::reopen_after_restart(&dir);
        assert_eq!(store.sandbox_resources().unwrap(), charged);
    }

    #[test]
    fn external_replace_cannot_release_charged_row_without_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);

        // A concurrent non-Store SQLite connection can choose both protections off.
        // Reusing list_seq selects the charged row as OR REPLACE's conflict
        // victim. Neither per-connection pragma may weaken the BEFORE guard.
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.pragma_update(None, "recursive_triggers", "OFF")
            .unwrap();
        assert_eq!(
            conn.pragma_query_value::<i64, _>(None, "foreign_keys", |r| r.get(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.pragma_query_value::<i64, _>(None, "recursive_triggers", |r| r.get(0))
                .unwrap(),
            0
        );
        conn.execute(
            "INSERT OR REPLACE INTO sandboxes (
                id, backend, backend_id, state, spec, failure_reason,
                created_at_ms, updated_at_ms, deleted_at_ms, list_seq,
                create_certainty, owner_uid, accounting_kind,
                reserved_memory_bytes, reserved_disk_bytes, reserved_pids,
                reserved_host_cpu_millis, reserved_virtual_cpu_slots, reserved_host_pids,
                host_spec_sha256, guest_exec_spec_sha256,
                runtime_profile, runtime_artifact_digest, disposition,
                boot_id, runtime_receipt, legacy_release,
                node_id, instance_id, allocation_id, plan_version, plan_digest, plan,
                release_evidence_id, release_evidence_kind, last_helper_generation
             )
             SELECT
                'sb-0000000000000000', backend, NULL, 'failed', spec, 'forged release',
                created_at_ms, updated_at_ms, NULL, list_seq,
                'definitely_not_created', owner_uid, 'legacy',
                reserved_memory_bytes, reserved_disk_bytes, reserved_pids,
                0, 0, 0,
                host_spec_sha256, guest_exec_spec_sha256,
                '', '', 'reusable',
                NULL, NULL, 'definitely_not_created',
                NULL, NULL, NULL, NULL, NULL, NULL,
                NULL, 'absent_fenced', NULL
             FROM sandboxes WHERE id = ?1",
            [&row.id],
        )
        .unwrap_err();
        drop(conn);

        assert!(store.sandbox(&row.id).unwrap().unwrap().is_charged());
        assert_eq!(
            store.sandbox_resources().unwrap().sandboxes,
            1,
            "charged capacity was released without any release_evidence row"
        );
        assert_eq!(
            store
                .conn()
                .query_row("SELECT COUNT(*) FROM release_evidence", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn external_trigger_disabled_delete_degrades_reads_and_restart() {
        use rusqlite::config::DbConfig;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);

        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.pragma_update(None, "recursive_triggers", "OFF")
            .unwrap();
        conn.pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        assert!(
            !conn
                .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
                .unwrap()
        );
        assert!(
            !conn
                .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
                .unwrap()
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='sandboxes_no_charged_delete'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            1,
            "the schema itself was not changed"
        );

        conn.execute("DELETE FROM sandboxes WHERE id=?1", [&row.id])
            .unwrap();
        assert!(
            store
                .sandbox(&row.id)
                .unwrap_err()
                .to_string()
                .contains("degraded accounting")
        );
        assert!(store.sandbox_resources().is_err());
        assert!(store.sandboxes(true).is_err());
        assert!(store.sandbox_page(false, None, None, 1).is_err());
        assert!(
            store
                .reserve_sandbox(&fenced_sandbox(), roomy_budgets())
                .is_err()
        );
        assert!(
            store
                .prune(
                    &Retention {
                        sandbox_max_age_secs: 0,
                        sandbox_max_count: 0,
                        ..Retention::default()
                    },
                    now_ms()
                )
                .is_err()
        );
        // A trusted write must not silently rebaseline the missing commitment.
        assert!(store.insert_sandbox(&fenced_sandbox()).is_err());
        drop(conn);
        drop(store);
        let error = Store::open(&dir)
            .err()
            .expect("missing row survived restart");
        assert!(format!("{error:#}").contains("degraded accounting"));
    }

    #[test]
    fn spoofed_validator_remains_charged_quarantined_and_degraded() {
        use rusqlite::functions::FunctionFlags;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let row = fenced_sandbox();
        let binding = row.accounting.allocation.clone().unwrap();
        store.insert_sandbox(&row).unwrap();
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);

        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.create_scalar_function(
            "kilnd_fenced_absence_valid",
            8,
            FunctionFlags::SQLITE_UTF8
                | FunctionFlags::SQLITE_DETERMINISTIC
                | FunctionFlags::SQLITE_INNOCUOUS,
            |_ctx| Ok(true),
        )
        .unwrap();
        let receipt_id = Id128::random().to_string();
        conn.execute(
            "INSERT INTO release_evidence (
                receipt_id, node_id, instance_id, allocation_id, plan_digest,
                helper_generation, kind, receipt, recorded_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 'absent_fenced', x'00', 1)",
            params![
                receipt_id,
                binding.node_id.to_string(),
                binding.instance_id.to_string(),
                binding.allocation_id.to_string(),
                binding.plan_digest.to_string(),
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE sandboxes
             SET state='failed', failure_reason='forged release',
                 release_evidence_id=?2, last_helper_generation=1
             WHERE id=?1",
            params![row.id, receipt_id],
        )
        .unwrap();
        assert_eq!(
            store.sandbox_resources().unwrap().sandboxes,
            1,
            "Rust accounting refuses the spoofed connection-local validator"
        );
        assert_eq!(
            conn.query_row::<Vec<u8>, _, _>(
                "SELECT receipt FROM release_evidence WHERE receipt_id=?1",
                [&receipt_id],
                |r| r.get(0),
            )
            .unwrap(),
            vec![0]
        );
        assert_quarantined_reads(&store, &row);
        assert!(store.accounting_snapshot().unwrap().1);
        assert!(
            store
                .reserve_sandbox(&fenced_sandbox(), roomy_budgets())
                .is_err()
        );
        assert_eq!(
            store
                .prune(
                    &Retention {
                        sandbox_max_age_secs: 0,
                        sandbox_max_count: 0,
                        ..Retention::default()
                    },
                    now_ms()
                )
                .unwrap()
                .sandboxes,
            0
        );
        drop(conn);
        drop(store);
        let store = Store::open(&dir).unwrap();
        assert_quarantined_reads(&store, &row);
        assert!(store.accounting_snapshot().unwrap().1);
    }

    #[test]
    fn legitimate_fenced_release_works_with_untrusted_schema_on_every_connection() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for memory in [false, true] {
            let store = if memory {
                Store::open_in_memory().unwrap()
            } else {
                Store::open(tmp.path()).unwrap()
            };
            assert_eq!(
                store
                    .conn()
                    .pragma_query_value::<i64, _>(None, "trusted_schema", |r| r.get(0))
                    .unwrap(),
                0
            );
            let row = fenced_sandbox();
            store.insert_sandbox(&row).unwrap();
            store
                .release_fenced(&row.id, SandboxState::Failed, &receipt_for(&row), None)
                .unwrap();
            assert_eq!(
                store.accounting_snapshot().unwrap(),
                (SandboxResources::default(), false)
            );
            assert!(!store.sandbox(&row.id).unwrap().unwrap().is_charged());
            drop(store);
            if !memory {
                let reopened = Store::open(tmp.path()).unwrap();
                assert_eq!(
                    reopened
                        .conn()
                        .pragma_query_value::<i64, _>(None, "trusted_schema", |r| r.get(0))
                        .unwrap(),
                    0
                );
                assert_eq!(
                    reopened.accounting_snapshot().unwrap(),
                    (SandboxResources::default(), false)
                );
            }
        }
    }

    fn roomy_budgets() -> SandboxBudgets {
        SandboxBudgets {
            sandboxes: 100,
            memory_bytes: u64::MAX,
            disk_bytes: u64::MAX,
            pids: u64::MAX,
            host_cpu_millis: u64::MAX,
            virtual_cpu_slots: u64::MAX,
            host_pids: u64::MAX,
        }
    }

    fn assert_quarantined_reads(store: &Store, original: &Sandbox) {
        let check = |row: &Sandbox| {
            assert_eq!(row.id, original.id);
            assert!(row.is_charged());
            assert_eq!(row.state, SandboxState::Quarantined);
            assert_eq!(row.accounting.disposition, SandboxDisposition::Quarantined);
        };
        check(&store.sandbox(&original.id).unwrap().unwrap());
        for include_deleted in [false, true] {
            let rows = store.sandboxes(include_deleted).unwrap();
            assert_eq!(rows.len(), 1);
            check(&rows[0]);
            let page = store
                .sandbox_page_owned(include_deleted, None, None, 1, Some(original.owner_uid))
                .unwrap();
            assert_eq!(page.rows.len(), 1);
            check(&page.rows[0].sandbox);
            assert!(!page.has_more);
            assert!(
                store
                    .sandbox_page_owned(
                        include_deleted,
                        None,
                        None,
                        1,
                        Some(original.owner_uid + 1)
                    )
                    .unwrap()
                    .rows
                    .is_empty()
            );
        }
        assert_eq!(
            store.sandbox_resources().unwrap(),
            SandboxResources::for_reservation(&original.accounting.reservation)
        );
    }

    #[test]
    fn trusted_reads_validate_all_receipt_fields_and_missing_evidence() {
        // Start with a real release, then model out-of-scope file authority.
        // Every side column, encoded field and the row's generation is checked.
        for (attack, settled) in [
            "DELETE FROM release_evidence",
            "UPDATE release_evidence SET receipt=x'00'",
            "UPDATE release_evidence SET receipt=x''",
            "UPDATE release_evidence SET receipt=CAST('{}' AS BLOB)",
            "UPDATE release_evidence SET receipt_id='11111111111111111111111111111111'",
            "UPDATE release_evidence SET node_id='11111111111111111111111111111111'",
            "UPDATE release_evidence SET instance_id='11111111111111111111111111111111'",
            "UPDATE release_evidence SET allocation_id='11111111111111111111111111111111'",
            "UPDATE release_evidence SET plan_digest='1111111111111111111111111111111111111111111111111111111111111111'",
            "UPDATE release_evidence SET helper_generation=8",
            "UPDATE release_evidence SET kind='other'",
            "UPDATE sandboxes SET last_helper_generation=8",
            "UPDATE sandboxes SET release_evidence_id=NULL",
        ]
        .into_iter()
        // M2 fix review MEDIUM 3: also once a retaining prune has settled the row,
        // so its evidence is outside the live set when it is corrupted.
        .flat_map(|attack| [(attack, false), (attack, true)])
        {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let store = Store::open(tmp.path()).unwrap();
            let row = fenced_sandbox();
            store.insert_sandbox(&row).unwrap();
            store
                .release_fenced(&row.id, SandboxState::Deleted, &receipt_for(&row), None)
                .unwrap();
            if settled {
                store.prune(&Retention::default(), now_ms()).unwrap();
                assert!(!store.accounting_snapshot().unwrap().1);
            }
            let external = Connection::open(tmp.path().join("kilnd.db")).unwrap();
            external
                .set_db_config(
                    rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                    false,
                )
                .unwrap();
            external
                .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
                .unwrap();
            external.execute(attack, []).unwrap();
            if settled && attack.contains("release_evidence_id=NULL") {
                // Charged again behind kilnd's back while settled: the partition no
                // longer adds up, which refuses outright rather than quarantining.
                let error = store.sandbox_resources().unwrap_err().to_string();
                assert!(error.contains("reservation integrity"), "{attack}: {error}");
                continue;
            }
            assert_quarantined_reads(&store, &row);
            assert!(store.accounting_snapshot().unwrap().1, "{attack} settled={settled}");
            assert_eq!(
                store
                    .prune(
                        &Retention {
                            sandbox_max_age_secs: 0,
                            sandbox_max_count: 0,
                            ..Retention::default()
                        },
                        now_ms()
                    )
                    .unwrap()
                    .sandboxes,
                0,
                "{attack}"
            );
        }
    }

    #[test]
    fn schema_rewrite_control_is_out_of_scope_but_missing_row_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);

        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.execute_batch("DROP TRIGGER sandboxes_no_charged_delete;")
            .unwrap();
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='sandboxes_no_charged_delete'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            0,
            "this control deliberately rewrote the schema"
        );
        conn.execute("DELETE FROM sandboxes WHERE id=?1", [&row.id])
            .unwrap();
        assert!(store.sandbox(&row.id).is_err());
        assert!(store.sandbox_resources().is_err());
    }

    fn defenseless_connection(dir: &Path) -> Connection {
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        for pragma in ["foreign_keys", "recursive_triggers"] {
            conn.pragma_update(None, pragma, "OFF").unwrap();
            assert_eq!(
                conn.pragma_query_value::<i64, _>(None, pragma, |r| r.get(0))
                    .unwrap(),
                0
            );
        }
        // Recheck PoC configuration: host-API-controlled connections remain
        // outside the boundary, but these ordinary SQL conflicts still fail.
        for pragma in [
            "ignore_check_constraints",
            "writable_schema",
            "trusted_schema",
            "legacy_alter_table",
            "defer_foreign_keys",
        ] {
            conn.pragma_update(None, pragma, "ON").unwrap();
        }
        assert!(
            !conn
                .set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
                .unwrap()
        );
        assert!(
            conn.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                true
            )
            .unwrap()
        );
        conn
    }

    fn table_snapshot(conn: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let mut stmt = conn
            .prepare(&format!("SELECT rowid, * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        stmt.query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// Clone a valid row with selected SQL expressions substituted. All other
    /// columns remain valid, so a refusal proves conflict handling, not a missing
    /// NOT NULL fixture field. `source` and substitutions are test-owned literals.
    fn clone_row_sql(
        conn: &Connection,
        table: &str,
        algorithm: &str,
        source: &str,
        changes: &[(&str, &str)],
    ) -> String {
        let columns: Vec<String> = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |r| r.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut names = vec!["rowid".to_string()];
        names.extend(columns);
        let select: Vec<&str> = names
            .iter()
            .map(|name| {
                changes
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map_or(name.as_str(), |(_, expr)| *expr)
            })
            .collect();
        format!(
            "INSERT OR {algorithm} INTO {table} ({}) SELECT {} FROM {table} WHERE {source}",
            names.join(","),
            select.join(",")
        )
    }

    #[test]
    fn external_conflict_algorithms_preserve_every_unique_key_and_fence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let victim = fenced_sandbox();
        store.insert_sandbox(&victim).unwrap();
        // Publish a backend key without releasing capacity.
        store
            .conn()
            .execute(
                "UPDATE sandboxes SET state='failed', backend_id='fc-' || allocation_id WHERE id=?1",
                [&victim.id],
            )
            .unwrap();
        let attacker = sandbox();
        store.insert_sandbox(&attacker).unwrap();
        let e1 = execution(&victim.id);
        let e2 = execution(&victim.id);
        store.insert_execution(&e1).unwrap();
        store.insert_execution(&e2).unwrap();
        let retired = fenced_sandbox();
        store.insert_sandbox(&retired).unwrap();
        let fence = receipt_for(&retired);
        store
            .release_fenced(&retired.id, SandboxState::Deleted, &fence, None)
            .unwrap();
        // History can expire while the fence remains permanent. With the API row
        // gone, no freshness trigger can mask a missing collision guard.
        store
            .conn()
            .execute("DELETE FROM sandboxes WHERE id=?1", [&retired.id])
            .unwrap();
        // Fixture-only trusted deletion models Store::prune's atomic marker update.
        refresh_membership(&store.conn()).unwrap();
        let other_fence = receipt_for(&fenced_sandbox());
        insert_evidence(
            &store.conn(),
            (
                &other_fence.receipt_id().to_string(),
                &other_fence.node_id().to_string(),
                &other_fence.instance_id().to_string(),
                &other_fence.allocation_id().to_string(),
                &other_fence.plan_digest().to_string(),
            ),
            "7",
            "'absent_fenced'",
        )
        .unwrap();
        let charged = store.sandbox_resources().unwrap();
        let conn = defenseless_connection(&dir);
        // Register the real decoder here so evidence conflict tests cannot pass
        // merely because an independent connection lacks the function.
        register_receipt_validator(&conn).unwrap();
        let tables = [
            "sandboxes",
            "daemon_identity",
            "release_evidence",
            "history_sequence",
            "executions",
        ];
        // Freeze the audited UNIQUE inventory so an added index demands review.
        for (table, expected) in [
            (
                "sandboxes",
                vec!["id", "backend,backend_id", "list_seq", "allocation_id"],
            ),
            (
                "release_evidence",
                vec![
                    "receipt_id",
                    "allocation_id",
                    "node_id,instance_id,allocation_id,plan_digest,helper_generation,kind",
                    "receipt_id,node_id,instance_id,allocation_id,plan_digest,kind",
                ],
            ),
            ("executions", vec!["id"]),
            ("daemon_identity", vec![]), // INTEGER PRIMARY KEY aliases rowid.
            ("history_sequence", vec![]),
        ] {
            let indexes: Vec<String> = conn
                .prepare(&format!(
                    "SELECT name FROM pragma_index_list('{table}') WHERE \"unique\"=1"
                ))
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let mut actual: Vec<String> = indexes
                .iter()
                .map(|name| {
                    conn.query_row(
                        "SELECT group_concat(name, ',') FROM pragma_index_info(?1)",
                        [name],
                        |r| r.get(0),
                    )
                    .unwrap()
                })
                .collect();
            actual.sort();
            let mut expected: Vec<String> = expected.into_iter().map(String::from).collect();
            expected.sort();
            assert_eq!(actual, expected, "unaudited unique key on {table}");
        }
        let snapshots: Vec<_> = tables.iter().map(|t| table_snapshot(&conn, t)).collect();
        let source = format!("id='{}'", victim.id);
        let victim_rowid: i64 = conn
            .query_row(
                "SELECT rowid FROM sandboxes WHERE id=?1",
                [&victim.id],
                |r| r.get(0),
            )
            .unwrap();
        for algorithm in ["REPLACE", "IGNORE", "ABORT", "FAIL", "ROLLBACK"] {
            // Isolate each declared unique key; also cover SQLite's implicit rowid.
            for key in ["id", "list_seq", "backend_id", "allocation_id", "rowid"] {
                let id = if key == "id" { "id" } else { "'sb-candidate'" };
                let seq = if key == "list_seq" {
                    "list_seq"
                } else {
                    "1000000"
                };
                let backend = if key == "backend_id" {
                    "(SELECT backend_id FROM sandboxes WHERE accounting_kind='fenced')"
                } else {
                    "NULL"
                };
                let alloc = if key == "backend_id" {
                    "NULL"
                } else if key == "allocation_id" {
                    "allocation_id"
                } else {
                    "'ffffffffffffffffffffffffffffffff'"
                };
                let rowid = if key == "rowid" { "rowid" } else { "1000000" };
                let sql = clone_row_sql(
                    &conn,
                    "sandboxes",
                    algorithm,
                    &if key == "backend_id" {
                        format!("id='{}'", attacker.id)
                    } else {
                        source.clone()
                    },
                    &[
                        ("id", id),
                        ("list_seq", seq),
                        ("backend_id", backend),
                        ("allocation_id", alloc),
                        ("rowid", rowid),
                    ],
                );
                assert!(conn.execute(&sql, []).is_err(), "{algorithm} insert {key}");
                let value = match key {
                    "id" => format!("'{}'", victim.id),
                    "list_seq" => format!("(SELECT list_seq FROM sandboxes WHERE {source})"),
                    "backend_id" => format!("(SELECT backend_id FROM sandboxes WHERE {source})"),
                    "allocation_id" => {
                        format!("(SELECT allocation_id FROM sandboxes WHERE {source})")
                    }
                    "rowid" => victim_rowid.to_string(),
                    _ => unreachable!(),
                };
                let sql = format!("UPDATE OR {algorithm} sandboxes SET {key}={value} WHERE id=?1");
                assert!(
                    conn.execute(&sql, [&attacker.id]).is_err(),
                    "{algorithm} update {key}"
                );
            }
            for table in ["daemon_identity", "history_sequence"] {
                let source = format!("rowid=(SELECT MIN(rowid) FROM {table})");
                let sql = clone_row_sql(&conn, table, algorithm, &source, &[]);
                assert!(
                    conn.execute(&sql, []).is_err(),
                    "{algorithm} insert {table}"
                );
            }
            for key in ["id", "rowid"] {
                let source = format!("id='{}'", e1.id);
                let changes = if key == "id" {
                    vec![("rowid", "1000000")]
                } else {
                    vec![("id", "'exec-candidate'")]
                };
                let sql = clone_row_sql(&conn, "executions", algorithm, &source, &changes);
                assert!(
                    conn.execute(&sql, []).is_err(),
                    "{algorithm} insert executions {key}"
                );
                let sql = format!(
                    "UPDATE OR {algorithm} executions SET {key}=(SELECT {key} FROM executions WHERE id=?1) WHERE id=?2"
                );
                assert!(
                    conn.execute(&sql, params![e1.id, e2.id]).is_err(),
                    "{algorithm} update executions {key}"
                );
            }
            // release_evidence's two composite unique indexes both contain the
            // globally unique allocation_id, so its guard covers those too.
            for key in [
                "receipt_id",
                "allocation_id",
                "identity_tuple",
                "reference_tuple",
                "rowid",
            ] {
                let receipt = FencedAbsence::new(
                    if matches!(key, "receipt_id" | "reference_tuple") {
                        fence.receipt_id()
                    } else {
                        Id128::random()
                    },
                    fence.node_id(),
                    fence.instance_id(),
                    if matches!(key, "receipt_id" | "rowid") {
                        Id128::random()
                    } else {
                        fence.allocation_id()
                    },
                    fence.plan_digest(),
                    7,
                    String::new(),
                )
                .unwrap();
                let blob = receipt.encode().unwrap();
                let rowid = if key == "rowid" {
                    format!(
                        "(SELECT rowid FROM release_evidence WHERE receipt_id='{}')",
                        fence.receipt_id()
                    )
                } else {
                    "1000000".to_string()
                };
                let sql = format!(
                    "INSERT OR {algorithm} INTO release_evidence (rowid,receipt_id,node_id,instance_id,allocation_id,plan_digest,helper_generation,kind,receipt,recorded_at_ms) VALUES ({rowid},?1,?2,?3,?4,?5,7,'absent_fenced',?6,1)"
                );
                assert!(
                    conn.execute(
                        &sql,
                        params![
                            receipt.receipt_id().to_string(),
                            receipt.node_id().to_string(),
                            receipt.instance_id().to_string(),
                            receipt.allocation_id().to_string(),
                            receipt.plan_digest().to_string(),
                            blob
                        ]
                    )
                    .is_err(),
                    "{algorithm} insert evidence {key}"
                );
            }
            for key in [
                "receipt_id",
                "allocation_id",
                "node_id",
                "instance_id",
                "plan_digest",
                "helper_generation",
                "kind",
                "rowid",
            ] {
                let sql = format!(
                    "UPDATE OR {algorithm} release_evidence SET {key}=(SELECT {key} FROM release_evidence WHERE receipt_id=?1) WHERE receipt_id=?2"
                );
                assert!(
                    conn.execute(
                        &sql,
                        params![
                            fence.receipt_id().to_string(),
                            other_fence.receipt_id().to_string()
                        ]
                    )
                    .is_err(),
                    "{algorithm} update evidence {key}"
                );
            }
            assert!(
                conn.execute(
                    &format!("UPDATE OR {algorithm} daemon_identity SET id=1"),
                    []
                )
                .is_err()
            );
            assert!(
                conn.execute(
                    &format!("UPDATE OR {algorithm} daemon_identity SET instance_id=?1"),
                    [Id128::random().to_string()]
                )
                .is_err()
            );
            assert!(
                conn.execute(
                    &format!("UPDATE OR {algorithm} release_evidence SET recorded_at_ms=0"),
                    []
                )
                .is_err()
            );
            for (table, before) in tables.iter().zip(&snapshots) {
                assert_eq!(
                    &table_snapshot(&conn, table),
                    before,
                    "{algorithm}: {table}"
                );
            }
            assert_eq!(store.sandbox_resources().unwrap(), charged);
        }
    }

    #[test]
    fn encoded_absence_is_validated_on_store_and_independent_connections() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        let receipt = receipt_for(&row);
        let valid = receipt.encode().unwrap();
        assert_eq!(FencedAbsence::decode(&valid).unwrap(), receipt);
        let text = String::from_utf8(valid.clone()).unwrap();
        let mut malformed = vec![
            vec![0],
            b"{}".to_vec(),
            vec![],
            vec![b'x'; 16385],
            valid[..valid.len() - 1].to_vec(),
            format!(" {text}").into_bytes(),
        ];
        let mut unknown = serde_json::from_slice::<serde_json::Value>(&valid).unwrap();
        unknown["kind"] = "stopped".into();
        malformed.push(serde_json::to_vec(&unknown).unwrap());
        // Duplicate fields, alternate field order, escaped IDs and floating
        // generation spellings cannot round-trip to the production encoding.
        malformed.push(
            text.replacen('{', "{\"observations\":\"\",", 1)
                .into_bytes(),
        );
        malformed.push(
            serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(&valid).unwrap())
                .unwrap(),
        );
        malformed.push(
            text.replace("\"helper_generation\":7", "\"helper_generation\":7.0")
                .into_bytes(),
        );
        let receipt_id = receipt.receipt_id().to_string();
        malformed.push(
            text.replacen(
                &format!("\"receipt_id\":\"{receipt_id}"),
                &format!(
                    "\"receipt_id\":\"\\u00{:02x}{}",
                    receipt_id.as_bytes()[0],
                    &receipt_id[1..]
                ),
                1,
            )
            .into_bytes(),
        );
        let external = defenseless_connection(&dir);
        let insert = |conn: &Connection, blob: &[u8], fields: &[String]| {
            conn.execute("INSERT INTO release_evidence (receipt_id,node_id,instance_id,allocation_id,plan_digest,helper_generation,kind,receipt,recorded_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1)",
                params![fields[0],fields[1],fields[2],fields[3],fields[4],fields[5],fields[6],blob])
        };
        let fields = vec![
            receipt.receipt_id().to_string(),
            receipt.node_id().to_string(),
            receipt.instance_id().to_string(),
            receipt.allocation_id().to_string(),
            receipt.plan_digest().to_string(),
            "7".into(),
            "absent_fenced".into(),
        ];
        // No function is a hard failure even for a valid receipt.
        let err = insert(&external, &valid, &fields).unwrap_err();
        assert!(err.to_string().contains("no such function"), "{err}");
        for blob in &malformed {
            assert!(insert(&external, blob, &fields).is_err());
        }
        register_receipt_validator(&external).unwrap();
        for conn in [&*store.conn(), &external] {
            let before = table_snapshot(conn, "sandboxes");
            for blob in &malformed {
                assert!(FencedAbsence::decode(blob).is_err(), "{blob:?}");
                assert!(insert(conn, blob, &fields).is_err(), "{blob:?}");
                // The original x'00' PoC's release UPDATE must fail too.
                assert!(conn.execute("UPDATE sandboxes SET state='failed', release_evidence_id=?2, last_helper_generation=7 WHERE id=?1", params![row.id,fields[0]]).is_err());
            }
            for position in 0..fields.len() {
                let mut mismatched = fields.clone();
                mismatched[position] = match position {
                    4 => Digest::of(b"other").to_string(),
                    5 => "8".into(),
                    6 => "stopped".into(),
                    _ => Id128::random().to_string(),
                };
                assert!(
                    insert(conn, &valid, &mismatched).is_err(),
                    "column {position}"
                );
            }
            assert_eq!(table_snapshot(conn, "sandboxes"), before);
            assert!(table_snapshot(conn, "release_evidence").is_empty());
        }
        assert!(store.sandbox(&row.id).unwrap().unwrap().is_charged());
        // Prove the gate accepts the canonical receipt and normal release path.
        store
            .release_fenced(&row.id, SandboxState::Failed, &receipt, None)
            .unwrap();
        assert!(!store.sandbox(&row.id).unwrap().unwrap().is_charged());
    }

    #[test]
    fn schema9_upgrade_validates_existing_schema8_receipts_atomically() {
        for valid in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let mut conn = disk_database_at(tmp.path(), 7);
            let tx = conn.transaction().unwrap();
            migrate_v8(&tx).unwrap();
            tx.commit().unwrap();
            let row = fenced_sandbox();
            insert_sandbox_before_v11(&conn, &row).unwrap();
            let receipt = receipt_for(&row);
            let encoded = if valid {
                receipt.encode().unwrap()
            } else {
                vec![0]
            };
            conn.execute("INSERT INTO release_evidence (receipt_id,node_id,instance_id,allocation_id,plan_digest,helper_generation,kind,receipt,recorded_at_ms) VALUES (?1,?2,?3,?4,?5,7,'absent_fenced',?6,1)", params![receipt.receipt_id().to_string(),receipt.node_id().to_string(),receipt.instance_id().to_string(),receipt.allocation_id().to_string(),receipt.plan_digest().to_string(),encoded]).unwrap();
            let before = table_snapshot(&conn, "sandboxes");
            let evidence = table_snapshot(&conn, "release_evidence");
            release_database(conn, tmp.path());
            let upgraded = Store::open(tmp.path());
            if valid {
                let store = upgraded.unwrap();
                // Schemas 11, 12 and 13 append lifecycle columns; history gets their
                // nulls, seq 0, no request ID, no default env and no exec features.
                let after = table_snapshot(&store.conn(), "sandboxes");
                assert_eq!(after.len(), before.len());
                for (after, before) in after.iter().zip(&before) {
                    assert_eq!(&after[..before.len()], &before[..]);
                    use rusqlite::types::Value::{Integer, Null};
                    assert_eq!(
                        &after[before.len()..],
                        &[
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Integer(0),
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Null,
                            Null
                        ]
                    );
                }
                assert_eq!(table_snapshot(&store.conn(), "release_evidence"), evidence);
                assert_eq!(
                    store
                        .conn()
                        .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                        .unwrap(),
                    SCHEMA_VERSION
                );
                assert!(store.sandbox(&row.id).unwrap().unwrap().is_charged());
            } else {
                let error = upgraded
                    .err()
                    .expect("corrupt schema 8 must not be accepted");
                assert!(
                    error.to_string().contains("invalid AbsentFenced"),
                    "{error:#}"
                );
                let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
                assert_eq!(
                    conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                        .unwrap(),
                    8
                );
                assert_eq!(table_snapshot(&conn, "sandboxes"), before);
                assert_eq!(table_snapshot(&conn, "release_evidence"), evidence);
                assert_eq!(
                    conn.query_row::<i64, _, _>(
                        "SELECT COUNT(*) FROM sqlite_master WHERE name='release_evidence_validate'",
                        [],
                        |r| r.get(0)
                    )
                    .unwrap(),
                    0
                );
            }
        }
    }

    #[test]
    fn fenced_lifecycle_forbids_prefill_resurrection_and_blind_publication() {
        let store = Store::open_in_memory().unwrap();
        let row = fenced_sandbox();
        let binding = row.accounting.allocation.clone().unwrap();
        // C1 can never prefill a backend ID, nor can a fenced row be legacy-tagged at insert.
        let mut prefilled = row.clone();
        prefilled.backend_id = Some(binding.backend_id());
        assert!(store.insert_sandbox(&prefilled).is_err());
        store.insert_sandbox(&row).unwrap();
        // Allocation IDs are never reused by another row.
        let mut duplicate = fenced_sandbox();
        duplicate
            .accounting
            .allocation
            .as_mut()
            .unwrap()
            .allocation_id = binding.allocation_id;
        assert!(store.insert_sandbox(&duplicate).is_err());
        // The legacy fast paths cannot release or publish it.
        assert!(store.fail_create_definitely(&row.id, "claimed").is_err());
        assert!(
            store
                .set_sandbox_state(&row.id, SandboxState::Deleted, None, None)
                .is_err()
        );
        assert!(
            store
                .set_sandbox_state(
                    &row.id,
                    SandboxState::Ready,
                    Some(&binding.backend_id()),
                    None
                )
                .is_err()
        );
        assert!(store.is_charged_for_test(&row.id));
        assert!(
            store
                .compare_and_set_sandbox_state(
                    &row.id,
                    SandboxState::Creating,
                    SandboxState::Deleted,
                    None,
                    None
                )
                .is_err()
        );
        // A legacy create receipt cannot publish it.
        let legacy_created = CreatedSandbox {
            backend_id: binding.backend_id(),
            receipt: RuntimeReceipt::Legacy,
            exec_features: None,
        };
        assert!(
            store
                .publish_fenced_ready(&row.id, &legacy_created)
                .is_err()
        );
        // Typed publication writes the exact identity once.
        let created = CreatedSandbox {
            backend_id: binding.backend_id(),
            receipt: RuntimeReceipt::Ready(crate::runtime::ReadyReceipt {
                node_id: binding.node_id,
                instance_id: binding.instance_id,
                allocation_id: binding.allocation_id,
                plan_digest: binding.plan_digest,
                helper_generation: 3,
                boot_id: "boot-1".into(),
            }),
            exec_features: None,
        };
        assert!(store.publish_fenced_ready(&row.id, &created).unwrap());
        assert!(
            !store.publish_fenced_ready(&row.id, &created).unwrap(),
            "CAS"
        );
        let ready = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(ready.state, SandboxState::Ready);
        assert_eq!(
            ready.backend_id.as_deref(),
            Some(binding.backend_id().as_str())
        );
        assert_eq!(ready.accounting.boot_id.as_deref(), Some("boot-1"));
        // A retired allocation never returns to READY or to reusable.
        store
            .retire_sandbox(&row.id, SandboxDisposition::Stopped, "stopped")
            .unwrap();
        let lost = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(
            (lost.state, lost.accounting.disposition),
            (SandboxState::Lost, SandboxDisposition::Stopped)
        );
        assert!(
            store
                .set_sandbox_state(&row.id, SandboxState::Ready, None, None)
                .is_err()
        );
        assert!(
            store
                .conn()
                .execute(
                    "UPDATE sandboxes SET disposition = 'reusable' WHERE id = ?1",
                    [&row.id]
                )
                .is_err()
        );
        // Quarantine cannot return to READY on any regime.
        let legacy = sandbox();
        store.insert_sandbox(&legacy).unwrap();
        store
            .set_sandbox_state(&legacy.id, SandboxState::Ready, Some("kiln-1"), None)
            .unwrap();
        store
            .retire_sandbox(
                &legacy.id,
                SandboxDisposition::Quarantined,
                "unknown cleanup",
            )
            .unwrap();
        assert_eq!(
            store.sandbox(&legacy.id).unwrap().unwrap().state,
            SandboxState::Quarantined
        );
        assert!(
            store
                .set_sandbox_state(&legacy.id, SandboxState::Ready, None, None)
                .is_err()
        );
    }

    fn ready_for(row: &Sandbox, generation: u64) -> crate::runtime::ReadyReceipt {
        let binding = row.accounting.allocation.as_ref().unwrap();
        crate::runtime::ReadyReceipt {
            node_id: binding.node_id,
            instance_id: binding.instance_id,
            allocation_id: binding.allocation_id,
            plan_digest: binding.plan_digest,
            helper_generation: generation,
            boot_id: "boot-1".into(),
        }
    }

    fn created_for(row: &Sandbox, generation: u64) -> CreatedSandbox {
        CreatedSandbox {
            backend_id: row.accounting.allocation.as_ref().unwrap().backend_id(),
            receipt: RuntimeReceipt::Ready(ready_for(row, generation)),
            exec_features: None,
        }
    }

    fn absence_for(row: &Sandbox, generation: u64) -> FencedAbsence {
        let binding = row.accounting.allocation.as_ref().unwrap();
        FencedAbsence::new(
            Id128::random(),
            binding.node_id,
            binding.instance_id,
            binding.allocation_id,
            binding.plan_digest,
            generation,
            String::new(),
        )
        .unwrap()
    }

    #[test]
    fn publish_fenced_ready_checks_its_own_identity_plan_backend_and_generation() {
        let store = Store::open_in_memory().unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        let good = ready_for(&row, 3);
        let backend_id = row.accounting.allocation.as_ref().unwrap().backend_id();
        let wrong = |receipt: crate::runtime::ReadyReceipt| CreatedSandbox {
            backend_id: backend_id.clone(),
            receipt: RuntimeReceipt::Ready(receipt),
            exec_features: None,
        };
        // None of these goes through the manager's own check.
        for (case, created) in [
            (
                "node",
                wrong(crate::runtime::ReadyReceipt {
                    node_id: Id128::random(),
                    ..good.clone()
                }),
            ),
            (
                "instance",
                wrong(crate::runtime::ReadyReceipt {
                    instance_id: Id128::random(),
                    ..good.clone()
                }),
            ),
            (
                "allocation",
                wrong(crate::runtime::ReadyReceipt {
                    allocation_id: Id128::random(),
                    ..good.clone()
                }),
            ),
            (
                "plan",
                wrong(crate::runtime::ReadyReceipt {
                    plan_digest: Digest::of(b"other"),
                    ..good.clone()
                }),
            ),
            (
                "generation zero",
                wrong(crate::runtime::ReadyReceipt {
                    helper_generation: 0,
                    ..good.clone()
                }),
            ),
            (
                "generation range",
                wrong(crate::runtime::ReadyReceipt {
                    helper_generation: i64::MAX as u64 + 1,
                    ..good.clone()
                }),
            ),
            (
                "empty boot",
                wrong(crate::runtime::ReadyReceipt {
                    boot_id: String::new(),
                    ..good.clone()
                }),
            ),
            (
                "long boot",
                wrong(crate::runtime::ReadyReceipt {
                    boot_id: "b".repeat(129),
                    ..good.clone()
                }),
            ),
            (
                "backend",
                CreatedSandbox {
                    backend_id: format!("fc-{}", Id128::random()),
                    receipt: RuntimeReceipt::Ready(good.clone()),
                    exec_features: None,
                },
            ),
            (
                "legacy",
                CreatedSandbox {
                    backend_id: backend_id.clone(),
                    receipt: RuntimeReceipt::Legacy,
                    exec_features: None,
                },
            ),
        ] {
            assert!(
                store.publish_fenced_ready(&row.id, &created).is_err(),
                "{case}"
            );
            let after = store.sandbox(&row.id).unwrap().unwrap();
            assert_eq!(after, row, "{case} changed the row");
        }
        // A legacy row can't publish an allocation, even with a coherent receipt.
        let legacy = sandbox();
        store.insert_sandbox(&legacy).unwrap();
        assert!(
            store
                .publish_fenced_ready(&legacy.id, &created_for(&row, 3))
                .is_err()
        );

        // An older generation than the row recorded is stale, never just ignored.
        let mut advanced = fenced_sandbox();
        advanced.accounting.last_helper_generation = Some(5);
        store.insert_sandbox(&advanced).unwrap();
        for stale in [1, 4, 5] {
            assert!(
                store
                    .publish_fenced_ready(&advanced.id, &created_for(&advanced, stale))
                    .is_err(),
                "{stale}"
            );
            assert_eq!(
                store.sandbox(&advanced.id).unwrap().unwrap().state,
                SandboxState::Creating
            );
        }
        assert!(
            store
                .publish_fenced_ready(&advanced.id, &created_for(&advanced, 6))
                .unwrap()
        );
        let ready = store.sandbox(&advanced.id).unwrap().unwrap();
        assert_eq!(ready.accounting.last_helper_generation, Some(6));
        // Identity is checked before the state comparison, and repeats change nothing.
        assert!(
            store
                .publish_fenced_ready(&advanced.id, &created_for(&row, 7))
                .is_err()
        );
        assert!(
            !store
                .publish_fenced_ready(&advanced.id, &created_for(&advanced, 7))
                .unwrap()
        );
        assert_eq!(store.sandbox(&advanced.id).unwrap().unwrap(), ready);
    }

    #[test]
    fn release_requires_a_generation_newer_than_any_published() {
        let store = Store::open_in_memory().unwrap();
        let row = fenced_sandbox();
        store.insert_sandbox(&row).unwrap();
        assert!(
            store
                .publish_fenced_ready(&row.id, &created_for(&row, 7))
                .unwrap()
        );
        for stale in [1, 6, 7] {
            let receipt = absence_for(&row, stale);
            let error = store
                .release_fenced(&row.id, SandboxState::Failed, &receipt, None)
                .unwrap_err();
            assert!(error.to_string().contains("not newer"), "{error:#}");
            assert!(
                store.sandbox(&row.id).unwrap().unwrap().is_charged(),
                "{stale}"
            );
            // The rejected receipt left no evidence that could block the real one.
            let evidence: i64 = store
                .conn()
                .query_row("SELECT COUNT(*) FROM release_evidence", [], |r| r.get(0))
                .unwrap();
            assert_eq!(evidence, 0, "{stale}");
        }
        let receipt = absence_for(&row, 8);
        store
            .release_fenced(&row.id, SandboxState::Failed, &receipt, None)
            .unwrap();
        let released = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(released.accounting.last_helper_generation, Some(8));
        assert_eq!(
            released.accounting.release,
            ReservationRelease::Fenced(receipt.receipt_id())
        );
        assert_eq!(
            store.sandbox_resources().unwrap(),
            SandboxResources::default()
        );

        // The exact release replays idempotently even though 8 is no longer newer.
        std::thread::sleep(std::time::Duration::from_millis(2));
        store
            .release_fenced(&row.id, SandboxState::Failed, &receipt, None)
            .unwrap();
        assert_eq!(store.sandbox(&row.id).unwrap().unwrap(), released);
        store
            .release_fenced(&row.id, SandboxState::Deleted, &receipt, None)
            .unwrap();
        let deleted = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(deleted.state, SandboxState::Deleted);
        assert_eq!(deleted.accounting.last_helper_generation, Some(8));
        std::thread::sleep(std::time::Duration::from_millis(2));
        store
            .release_fenced(&row.id, SandboxState::Deleted, &receipt, None)
            .unwrap();
        assert_eq!(store.sandbox(&row.id).unwrap().unwrap(), deleted);
        // A different receipt, newer or not, can't replace it.
        assert!(
            store
                .release_fenced(&row.id, SandboxState::Deleted, &absence_for(&row, 9), None)
                .is_err()
        );
        assert_eq!(store.sandbox(&row.id).unwrap().unwrap(), deleted);
    }

    #[test]
    fn direct_sql_cannot_use_stale_generation_evidence_or_roll_back_a_generation() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        let stale_attacks = |conn: &Connection, id: &str, evidence: &str| {
            for attack in [
                // Referencing it alone, and carrying its stale generation with it.
                "UPDATE sandboxes SET state = 'failed', release_evidence_id = ?2 WHERE id = ?1",
                "UPDATE sandboxes SET state = 'failed', release_evidence_id = ?2, last_helper_generation = 5 WHERE id = ?1",
                // Claiming a newer generation than the referenced evidence has.
                "UPDATE sandboxes SET state = 'failed', release_evidence_id = ?2, last_helper_generation = 8 WHERE id = ?1",
            ] {
                assert!(
                    conn.execute(attack, params![id, evidence]).is_err(),
                    "{attack}"
                );
            }
        };
        // Evidence that entered while the row recorded nothing is positive, and stale
        // once READY publishes a newer generation.
        let row = fenced_sandbox();
        let binding = row.accounting.allocation.clone().unwrap();
        store.insert_sandbox(&row).unwrap();
        let evidence = Id128::random().to_string();
        let (node, instance, allocation, plan) = (
            binding.node_id.to_string(),
            binding.instance_id.to_string(),
            binding.allocation_id.to_string(),
            binding.plan_digest.to_string(),
        );
        insert_evidence(
            &store.conn(),
            (&evidence, &node, &instance, &allocation, &plan),
            "5",
            "'absent_fenced'",
        )
        .unwrap();
        assert!(
            store
                .publish_fenced_ready(&row.id, &created_for(&row, 7))
                .unwrap()
        );
        stale_attacks(&store.conn(), &row.id, &evidence);
        assert!(store.sandbox(&row.id).unwrap().unwrap().is_charged());

        // Evidence no newer than the published generation can't enter at all.
        let other = fenced_sandbox();
        let other_binding = other.accounting.allocation.clone().unwrap();
        store.insert_sandbox(&other).unwrap();
        assert!(
            store
                .publish_fenced_ready(&other.id, &created_for(&other, 7))
                .unwrap()
        );
        for stale in ["1", "7"] {
            assert!(
                insert_evidence(
                    &store.conn(),
                    (
                        &Id128::random().to_string(),
                        &other_binding.node_id.to_string(),
                        &other_binding.instance_id.to_string(),
                        &other_binding.allocation_id.to_string(),
                        &other_binding.plan_digest.to_string(),
                    ),
                    stale,
                    "'absent_fenced'",
                )
                .is_err(),
                "{stale}"
            );
        }

        // A generation moves only forward, and only with its receipt.
        {
            let conn = store.conn();
            for attack in [
                "UPDATE sandboxes SET last_helper_generation = 6 WHERE id = ?1",
                "UPDATE sandboxes SET last_helper_generation = 0 WHERE id = ?1",
                "UPDATE sandboxes SET last_helper_generation = NULL WHERE id = ?1",
                "UPDATE sandboxes SET last_helper_generation = 8 WHERE id = ?1",
                "UPDATE sandboxes SET last_helper_generation = -1 WHERE id = ?1",
                "UPDATE sandboxes SET last_helper_generation = 'x' WHERE id = ?1",
            ] {
                assert!(conn.execute(attack, [&other.id]).is_err(), "{attack}");
            }
            let creating = fenced_sandbox();
            insert_sandbox(&conn, &creating).unwrap();
            assert!(
                conn.execute(
                    "UPDATE sandboxes SET last_helper_generation = 3 WHERE id = ?1",
                    [&creating.id]
                )
                .is_err()
            );
            // READY always carries a real generation.
            assert!(
                conn.execute(
                    "UPDATE sandboxes SET state = 'ready', backend_id = 'fc-' || allocation_id, boot_id = 'b', runtime_receipt = x'7b7d' WHERE id = ?1",
                    [&creating.id]
                )
                .is_err()
            );
            // A legacy row has none, and a fenced row must have one.
            let legacy = sandbox();
            insert_sandbox(&conn, &legacy).unwrap();
            refresh_membership(&conn).unwrap();
            assert!(
                conn.execute(
                    "UPDATE sandboxes SET last_helper_generation = 1 WHERE id = ?1",
                    [&legacy.id]
                )
                .is_err()
            );
        }
        let mut no_generation = fenced_sandbox();
        no_generation.accounting.last_helper_generation = None;
        assert!(store.insert_sandbox(&no_generation).is_err());
        let mut legacy_generation = sandbox();
        legacy_generation.accounting.last_helper_generation = Some(1);
        assert!(store.insert_sandbox(&legacy_generation).is_err());
        // The trigger isn't overbroad: strictly newer evidence commits by direct SQL.
        {
            let conn = store.conn();
            let fresh = Id128::random().to_string();
            insert_evidence(
                &conn,
                (
                    &fresh,
                    &other_binding.node_id.to_string(),
                    &other_binding.instance_id.to_string(),
                    &other_binding.allocation_id.to_string(),
                    &other_binding.plan_digest.to_string(),
                ),
                "8",
                "'absent_fenced'",
            )
            .unwrap();
            conn.execute(
                "UPDATE sandboxes SET state = 'failed', release_evidence_id = ?2, last_helper_generation = 8 WHERE id = ?1",
                params![other.id, fresh],
            )
            .unwrap();
            assert!(
                conn.execute(
                    "UPDATE sandboxes SET last_helper_generation = 9 WHERE id = ?1",
                    [&other.id]
                )
                .is_err()
            );
        }
        // The freshness triggers hold with foreign keys off too.
        drop(store);
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        stale_attacks(&conn, &row.id, &evidence);
        drop(conn);
        let store = Store::reopen_after_restart(&dir);
        assert!(store.sandbox(&row.id).unwrap().unwrap().is_charged());
    }

    #[test]
    fn terminal_execution_and_its_sandbox_disposition_commit_atomically() {
        let store = Store::open_in_memory().unwrap();
        let row = sandbox();
        store.insert_sandbox(&row).unwrap();
        store
            .set_sandbox_state(&row.id, SandboxState::Ready, Some("kiln-1"), None)
            .unwrap();
        let e = execution(&row.id);
        store.insert_execution(&e).unwrap();
        let capture = Captured::known_empty();
        let result = ExecutionResult {
            state: ExecutionState::TimedOut,
            exit_code: None,
            command_status: None,
            runtime_error: None,
            failure_reason: Some("timed out"),
            stdout: &capture,
            stderr: &capture,
            sandbox_reusable: Some(false),
            cleanup_evidence: CleanupEvidence::SandboxStopped,
            disposition: Some(SandboxDisposition::Stopped),
            disposition_reason: Some("retired"),
            cancel_reason: None,
        };
        store
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_lost BEFORE UPDATE OF state ON sandboxes WHEN NEW.state = 'lost'
                 BEGIN SELECT RAISE(FAIL, 'injected'); END;",
            )
            .unwrap();
        assert!(store.finish_execution(&e.id, &result).is_err());
        assert_eq!(
            store.execution(&e.id).unwrap().unwrap().state,
            ExecutionState::Running
        );
        assert_eq!(
            store.sandbox(&row.id).unwrap().unwrap().state,
            SandboxState::Ready
        );
        store
            .conn()
            .execute_batch("DROP TRIGGER reject_lost;")
            .unwrap();
        store.finish_execution(&e.id, &result).unwrap();
        let finished = store.execution(&e.id).unwrap().unwrap();
        assert_eq!(finished.state, ExecutionState::TimedOut);
        assert_eq!(finished.sandbox_reusable, Some(false));
        assert_eq!(finished.cleanup_evidence, CleanupEvidence::SandboxStopped);
        let lost = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(lost.state, SandboxState::Lost);
        assert_eq!(lost.failure_reason.as_deref(), Some("retired"));
        assert!(lost.is_charged());

        // DELETING keeps its intent; the disposition is still recorded.
        let row = sandbox();
        store.insert_sandbox(&row).unwrap();
        store
            .set_sandbox_state(&row.id, SandboxState::Deleting, Some("kiln-2"), None)
            .unwrap();
        let e = execution(&row.id);
        store.insert_execution(&e).unwrap();
        store
            .finish_execution(
                &e.id,
                &ExecutionResult {
                    disposition: Some(SandboxDisposition::Quarantined),
                    ..result
                },
            )
            .unwrap();
        let deleting = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(deleting.state, SandboxState::Deleting);
        assert_eq!(
            deleting.accounting.disposition,
            SandboxDisposition::Quarantined
        );
    }

    #[test]
    fn zero_age_and_count_prune_retains_charged_rows_and_permanent_evidence() {
        let store = Store::open_in_memory().unwrap();
        let mut kept = Vec::new();
        // Charged absence-fenced rows, FAILED or deleting, whatever they say.
        for state in [
            SandboxState::Creating,
            SandboxState::Failed,
            SandboxState::Deleting,
            SandboxState::Lost,
            SandboxState::Quarantined,
        ] {
            let row = fenced_sandbox();
            store.insert_sandbox(&row).unwrap();
            store
                .set_sandbox_state(&row.id, state, None, Some("x"))
                .unwrap();
            kept.push(row.id);
        }
        // A FAILED fenced row that knows its backend ID is still charged.
        let cleanup_failed = fenced_sandbox();
        let binding = cleanup_failed.accounting.allocation.clone().unwrap();
        store.insert_sandbox(&cleanup_failed).unwrap();
        store
            .set_sandbox_state(
                &cleanup_failed.id,
                SandboxState::Failed,
                Some(&binding.backend_id()),
                Some("cleanup failed"),
            )
            .unwrap();
        kept.push(cleanup_failed.id.clone());
        // Charged legacy rows, including the ambiguous failure and quarantine.
        let ambiguous = sandbox();
        store.insert_sandbox(&ambiguous).unwrap();
        store
            .set_sandbox_state(&ambiguous.id, SandboxState::Failed, None, Some("x"))
            .unwrap();
        kept.push(ambiguous.id);
        let quarantined = sandbox();
        store.insert_sandbox(&quarantined).unwrap();
        store
            .set_sandbox_state(
                &quarantined.id,
                SandboxState::Quarantined,
                Some("q-1"),
                Some("x"),
            )
            .unwrap();
        kept.push(quarantined.id);
        // A released row with a publication-pending execution stays too.
        let pending_parent = fenced_sandbox();
        store.insert_sandbox(&pending_parent).unwrap();
        let pending_receipt = receipt_for(&pending_parent);
        store
            .release_fenced(
                &pending_parent.id,
                SandboxState::Failed,
                &pending_receipt,
                None,
            )
            .unwrap();
        let pending = execution(&pending_parent.id);
        store.insert_execution(&pending).unwrap();
        // Released history is removable, but its evidence is permanent.
        let released = fenced_sandbox();
        store.insert_sandbox(&released).unwrap();
        let receipt = receipt_for(&released);
        store
            .release_fenced(&released.id, SandboxState::Deleted, &receipt, None)
            .unwrap();
        let legacy_released = sandbox();
        store.insert_sandbox(&legacy_released).unwrap();
        store
            .set_sandbox_state(&legacy_released.id, SandboxState::Deleted, None, None)
            .unwrap();

        let before = store.sandbox_resources().unwrap();
        let policy = Retention {
            execution_max_age_secs: 0,
            execution_max_count: 0,
            sandbox_max_age_secs: 0,
            sandbox_max_count: 0,
            ..Retention::default()
        };
        let pruned = store.prune(&policy, now_ms() + 1_000_000).unwrap();
        assert_eq!(
            pruned.sandboxes, 2,
            "only uncharged history without unfinished children"
        );
        assert_eq!(store.sandbox_resources().unwrap(), before);
        for id in &kept {
            assert!(store.sandbox(id).unwrap().is_some(), "{id}");
        }
        assert!(store.sandbox(&pending_parent.id).unwrap().is_some());
        assert!(store.execution(&pending.id).unwrap().is_some());
        assert!(store.sandbox(&released.id).unwrap().is_none());
        assert!(store.sandbox(&legacy_released.id).unwrap().is_none());
        let conn = store.conn();
        let evidence: i64 = conn
            .query_row("SELECT COUNT(*) FROM release_evidence", [], |r| r.get(0))
            .unwrap();
        assert_eq!(evidence, 2, "pruning history erases no replay evidence");
        assert!(conn.execute("DELETE FROM release_evidence", []).is_err());
    }

    #[test]
    fn budget_arithmetic_uses_stored_vectors_and_checks_overflow() {
        let store = Store::open_in_memory().unwrap();
        let shared_memory = 128u64 << 20;
        let budgets = SandboxBudgets {
            sandboxes: 16,
            // 3072 MiB less the once-per-node shared reserve.
            memory_bytes: (3072u64 << 20) - shared_memory,
            pids: 2048,
            disk_bytes: 16 << 30,
            host_cpu_millis: 3000,
            virtual_cpu_slots: 3,
            host_pids: 96,
        };
        for _ in 0..3 {
            let row = fenced_sandbox();
            assert_eq!(
                store.reserve_sandbox(&row, budgets).unwrap(),
                ReserveSandbox::Inserted
            );
        }
        let reserved = store.sandbox_resources().unwrap();
        assert_eq!(reserved.memory_bytes, 3 * (896 << 20));
        assert_eq!(reserved.memory_bytes + shared_memory, 2816 << 20);
        assert_eq!(reserved.host_cpu_millis, 3000);
        assert_eq!(reserved.virtual_cpu_slots, 3);
        assert_eq!(reserved.host_pids, 96);
        assert_eq!(reserved.pids, 3 * 192);
        assert_eq!(reserved.disk_bytes, 3 * (1408u64 << 20));
        let fourth = fenced_sandbox();
        assert!(matches!(
            store.reserve_sandbox(&fourth, budgets).unwrap(),
            ReserveSandbox::Exhausted(BudgetExhausted { resource: "memory bytes", reserved, requested, limit })
                if reserved == 3 * (896 << 20) && requested == 896 << 20 && limit == 2944 << 20
        ));
        assert!(store.sandbox(&fourth.id).unwrap().is_none());
        // Each other dimension is independently enforced on a fresh sum.
        for (resource, budgets) in [
            (
                "host CPU millis",
                SandboxBudgets {
                    host_cpu_millis: 3000 - 1,
                    ..budgets
                },
            ),
            (
                "vCPU slots",
                SandboxBudgets {
                    virtual_cpu_slots: 2,
                    ..budgets
                },
            ),
            (
                "host PIDs",
                SandboxBudgets {
                    host_pids: 95,
                    ..budgets
                },
            ),
        ] {
            let store = Store::open_in_memory().unwrap();
            let roomy = SandboxBudgets {
                memory_bytes: 1 << 40,
                ..budgets
            };
            let mut outcome = ReserveSandbox::Inserted;
            for _ in 0..3 {
                outcome = store.reserve_sandbox(&fenced_sandbox(), roomy).unwrap();
            }
            assert!(
                matches!(outcome, ReserveSandbox::Exhausted(e) if e.resource == resource),
                "{resource}: {outcome:?}"
            );
        }
        // Summation overflow is an error, not a wrap that frees capacity.
        let store = Store::open_in_memory().unwrap();
        let huge = |row: &mut Sandbox| row.accounting.reservation.memory_bytes = i64::MAX as u64;
        let mut first = fenced_sandbox();
        huge(&mut first);
        let mut second = fenced_sandbox();
        huge(&mut second);
        let mut third = fenced_sandbox();
        huge(&mut third);
        store.insert_sandbox(&first).unwrap();
        store.insert_sandbox(&second).unwrap();
        store.insert_sandbox(&third).unwrap();
        assert!(store.sandbox_resources().is_err());
        // An amount outside the stored range fails rather than truncating.
        let mut too_big = fenced_sandbox();
        too_big.accounting.reservation.disk_bytes = u64::MAX;
        assert!(
            Store::open_in_memory()
                .unwrap()
                .insert_sandbox(&too_big)
                .is_err()
        );
    }

    #[test]
    fn a_failed_owner_migration_rolls_back_the_whole_upgrade() {
        for version in [4, 5, 6] {
            let tmp = tempfile::tempdir().unwrap();
            let conn = disk_database_at(tmp.path(), version);
            // Collides only with the last step, after every earlier one ran.
            conn.execute_batch("CREATE INDEX sandboxes_owner_list_seq ON sandboxes (state);")
                .unwrap();
            release_database(conn, tmp.path());
            assert!(Store::open(tmp.path()).is_err(), "v{version}");

            let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
            assert_eq!(
                conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                version
            );
            let columns = column_descriptions(&conn);
            assert!(!columns.iter().any(|c| c.0 == "owner_uid"), "v{version}");
            assert_eq!(
                columns.iter().any(|c| c.0 == "create_certainty"),
                version >= 5,
                "v{version}"
            );
            let sequences: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'history_sequence'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(sequences == 1, version >= 6, "v{version}");

            // Removing the obstacle lets the same database upgrade normally.
            conn.execute_batch("DROP INDEX sandboxes_owner_list_seq;")
                .unwrap();
            drop(conn);
            let store = Store::reopen_after_restart(tmp.path());
            assert!(store.sandboxes(true).unwrap().is_empty());
        }
    }

    #[test]
    fn owner_round_trips_every_uid_and_never_follows_state() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let mut ids = Vec::new();
        for uid in [0, 1001, i32::MAX as u32 + 1, u32::MAX] {
            let mut s = sandbox();
            s.owner_uid = uid;
            store.insert_sandbox(&s).unwrap();
            assert_eq!(store.sandbox(&s.id).unwrap().unwrap(), s);
            ids.push((s.id, uid));
        }
        for (id, _) in &ids {
            store
                .set_sandbox_state(id, SandboxState::Ready, Some(id), None)
                .unwrap();
            store
                .set_sandbox_state(id, SandboxState::Deleted, None, None)
                .unwrap();
        }
        drop(store);
        let store = Store::reopen_after_restart(tmp.path());
        for (id, uid) in ids {
            assert_eq!(store.sandbox(&id).unwrap().unwrap().owner_uid, uid);
        }
        let conn = store.conn();
        let spec = serde_json::to_string(&sandbox().spec).unwrap();
        for bad in ["-1", "4294967296", "'root'", "NULL"] {
            assert!(
                conn.execute(
                    &format!("INSERT INTO sandboxes (id,backend,state,spec,created_at_ms,updated_at_ms,list_seq,owner_uid) VALUES ('sb-bad','fake','ready',?1,1,1,1000,{bad})"),
                    [&spec],
                )
                .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn owned_pages_filter_before_the_watermark_limit_and_has_more() {
        let store = Store::open_in_memory().unwrap();
        // list_seq:  1     2     3   4     5     6   7
        let owners = [1001, 1002, 0, 1001, 1002, 0, 1001];
        let mut ids = Vec::new();
        for owner_uid in owners {
            let mut s = sandbox();
            s.owner_uid = owner_uid;
            store.insert_sandbox(&s).unwrap();
            ids.push(s.id);
        }
        let page = |deleted, upper, before, limit, owner| {
            let page = store
                .sandbox_page_owned(deleted, upper, before, limit, owner)
                .unwrap();
            let seqs: Vec<i64> = page.rows.iter().map(|r| r.list_seq).collect();
            (seqs, page.upper_seq, page.has_more)
        };
        assert_eq!(
            page(false, None, None, 2, Some(1002)),
            (vec![5, 2], 5, false)
        );
        assert_eq!(page(false, None, None, 1, Some(1002)), (vec![5], 5, true));
        assert_eq!(
            page(false, Some(5), Some(5), 1, Some(1002)),
            (vec![2], 5, false)
        );
        assert_eq!(page(false, None, None, 10, Some(1003)), (vec![], 0, false));
        // Some(0) is exactly root's own rows; None is everyone's, which only
        // the root caller is ever given.
        assert_eq!(page(false, None, None, 10, Some(0)), (vec![6, 3], 6, false));
        assert_eq!(page(false, None, None, 2, None), (vec![7, 6], 7, true));

        // A deleted newest row leaves the watermark to the newest visible one,
        // as it does for root, but include_deleted still counts it.
        store
            .set_sandbox_state(&ids[4], SandboxState::Deleted, None, None)
            .unwrap();
        assert_eq!(page(false, None, None, 10, Some(1002)), (vec![2], 2, false));
        assert_eq!(
            page(true, None, None, 10, Some(1002)),
            (vec![5, 2], 5, false)
        );
        assert_eq!(page(false, None, None, 10, None).1, 7);

        // The bounded walk reads the caller's index entries, not the node's.
        let conn = store.conn();
        for filter in ["", "state != 'deleted' AND "] {
            let plan: String = conn
                .query_row(
                    &format!("EXPLAIN QUERY PLAN SELECT id FROM sandboxes WHERE {filter}owner_uid = 1 AND list_seq <= 9 ORDER BY list_seq DESC LIMIT 3"),
                    [],
                    |row| row.get(3),
                )
                .unwrap();
            assert!(plan.contains("sandboxes_owner_list_seq"), "{plan}");
        }
    }

    #[test]
    fn execution_parent_lookup_does_not_read_the_execution_row() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        let e = execution(&s.id);
        store.insert_execution(&e).unwrap();
        assert_eq!(
            store.execution_sandbox_id(&e.id).unwrap().as_deref(),
            Some(s.id.as_str())
        );
        assert_eq!(store.execution_sandbox_id("ex-missing").unwrap(), None);
        // Undecodable contents prove the lookup never touches them.
        store
            .conn()
            .execute("UPDATE executions SET argv = 'not json', stdout = 1", [])
            .unwrap();
        assert!(store.execution(&e.id).is_err());
        assert_eq!(
            store.execution_sandbox_id(&e.id).unwrap().as_deref(),
            Some(s.id.as_str())
        );
    }

    #[test]
    fn v4_migration_makes_every_historical_row_ambiguous_whatever_its_text() {
        let tmp = tempfile::tempdir().unwrap();
        let conn = v4_database(tmp.path());
        let spec = serde_json::to_string(&sandbox().spec).unwrap();
        for (seq, (id, state, backend_id, reason)) in [
            // Reads exactly like a preflight failure, but no typed result exists.
            (
                "sb-preflight",
                "failed",
                None,
                Some("kiln create failed (exit status: 124): image \"nope\" is missing"),
            ),
            ("sb-claim", "failed", None, Some("definitely_not_created")),
            (
                "sb-panic",
                "failed",
                None,
                Some("backend create task panicked"),
            ),
            (
                "sb-compensated",
                "failed",
                Some("ab-1"),
                Some("backend removed"),
            ),
            ("sb-creating", "creating", None, None),
            ("sb-ready", "ready", Some("ab-2"), None),
            ("sb-deleting", "deleting", None, None),
            ("sb-lost", "lost", Some("ab-3"), None),
            ("sb-deleted", "deleted", None, None),
        ]
        .into_iter()
        .enumerate()
        {
            conn.execute(
                "INSERT INTO sandboxes (id,backend,backend_id,state,spec,failure_reason,created_at_ms,updated_at_ms,list_seq) VALUES (?1,'fake',?2,?3,?4,?5,1,1,?6)",
                params![id, backend_id, state, spec, reason, seq as i64 + 1],
            )
            .unwrap();
        }
        drop(conn);
        std::fs::set_permissions(
            tmp.path().join("kilnd.db"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        for _reopen in 0..2 {
            let store = Store::reopen_after_restart(tmp.path());
            let rows = store.sandboxes(true).unwrap();
            assert_eq!(rows.len(), 9);
            assert!(
                rows.iter()
                    .all(|row| row.create_certainty == CreateCertainty::AllocationAmbiguous)
            );
            // Everything but compensated FAILED and DELETED stays charged.
            assert_eq!(store.sandbox_resources().unwrap().sandboxes, 7);
            assert_eq!(
                store
                    .conn()
                    .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
        }
    }

    #[test]
    fn definite_create_failure_is_one_durable_update_that_releases_the_reservation() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let s = sandbox();
        {
            let store = Store::open(tmp.path()).unwrap();
            store.insert_sandbox(&s).unwrap();
            assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);
            store
                .fail_create_definitely(&s.id, "image missing")
                .unwrap();
        }
        let store = Store::reopen_after_restart(tmp.path());
        let failed = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!(failed.state, SandboxState::Failed);
        assert_eq!(
            failed.create_certainty,
            CreateCertainty::DefinitelyNotCreated
        );
        assert_eq!(failed.failure_reason.as_deref(), Some("image missing"));
        assert_eq!(
            store.sandbox_resources().unwrap(),
            SandboxResources::default()
        );
        assert!(store.owned_backend_ids("fake").unwrap().is_empty());
        // Terminal history keeps the marker without any effect on accounting.
        assert!(
            store
                .compare_and_set_sandbox_state(
                    &s.id,
                    SandboxState::Failed,
                    SandboxState::Deleted,
                    None,
                    None
                )
                .unwrap()
        );
        let deleted = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!(
            deleted.create_certainty,
            CreateCertainty::DefinitelyNotCreated
        );
        assert_eq!(
            store.sandbox_resources().unwrap(),
            SandboxResources::default()
        );
    }

    #[test]
    fn definite_marker_applies_only_to_a_creating_row_without_a_backend_id() {
        let store = Store::open_in_memory().unwrap();
        let mut allocated = sandbox();
        allocated.backend_id = Some("ab-1".into());
        store.insert_sandbox(&allocated).unwrap();
        let mut ready = sandbox();
        ready.state = SandboxState::Ready;
        store.insert_sandbox(&ready).unwrap();
        for id in [&allocated.id, &ready.id, &"sb-missing".to_string()] {
            assert!(store.fail_create_definitely(id, "reason").is_err());
        }
        for row in store.sandboxes(true).unwrap() {
            assert_eq!(row.create_certainty, CreateCertainty::AllocationAmbiguous);
            assert_ne!(row.state, SandboxState::Failed);
        }
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 2);
    }

    #[test]
    fn failed_definite_publication_changes_nothing_and_stays_charged() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        store.reject_failed_updates().unwrap();
        store
            .fail_create_definitely(&s.id, "image missing")
            .unwrap_err();
        let row = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!(row.state, SandboxState::Creating);
        assert_eq!(row.create_certainty, CreateCertainty::AllocationAmbiguous);
        assert_eq!(row.failure_reason, None);
        assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);
    }

    #[test]
    fn schema_refuses_a_definite_marker_on_any_row_that_could_own_a_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let conn = v4_database(tmp.path());
        drop(conn);
        std::fs::set_permissions(
            tmp.path().join("kilnd.db"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        for store in [
            Store::open_in_memory().unwrap(),
            Store::open(tmp.path()).unwrap(),
        ] {
            let s = sandbox();
            store.insert_sandbox(&s).unwrap();
            let conn = store.conn();
            assert!(
                conn.execute(
                    "UPDATE sandboxes SET create_certainty = 'definitely_not_created'",
                    []
                )
                .is_err()
            );
            assert!(
                conn.execute("UPDATE sandboxes SET create_certainty = 'other'", [])
                    .is_err()
            );
            drop(conn);
            store
                .fail_create_definitely(&s.id, "image missing")
                .unwrap();
            for state in [
                SandboxState::Creating,
                SandboxState::Ready,
                SandboxState::Deleting,
                SandboxState::Lost,
            ] {
                assert!(
                    store.set_sandbox_state(&s.id, state, None, None).is_err(),
                    "{state:?}"
                );
            }
            assert!(
                store
                    .set_sandbox_state(&s.id, SandboxState::Failed, Some("ab-1"), None)
                    .is_err()
            );
            let row = store.sandbox(&s.id).unwrap().unwrap();
            assert_eq!(row.state, SandboxState::Failed);
            assert_eq!(row.backend_id, None);
            assert_eq!(row.create_certainty, CreateCertainty::DefinitelyNotCreated);
        }
    }

    #[test]
    fn v1_disk_migration_preserves_legacy_order_and_reopens_as_current() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let legacy = schema_v2().replace(",\n    list_seq       INTEGER NOT NULL", "")
            .replace("CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);", "")
            .replace("CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';", "");
        let conn = Connection::open(temp.path().join("kilnd.db")).unwrap();
        conn.execute_batch(&legacy).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        for (id, timestamp) in [("sb-b", 10), ("sb-d", 20), ("sb-a", 10), ("sb-c", 20)] {
            conn.execute("INSERT INTO sandboxes (id, backend, state, spec, created_at_ms, updated_at_ms) VALUES (?1, 'fake', 'ready', ?2, ?3, ?3)",
                params![id, serde_json::to_string(&sandbox().spec).unwrap(), timestamp]).unwrap();
        }
        let expected: Vec<String> = conn
            .prepare("SELECT id FROM sandboxes ORDER BY created_at_ms DESC, id ASC")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(conn);
        std::fs::set_permissions(
            temp.path().join("kilnd.db"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        {
            let store = Store::open(temp.path()).unwrap();
            assert_eq!(
                store
                    .sandboxes(true)
                    .unwrap()
                    .iter()
                    .map(|s| s.id.clone())
                    .collect::<Vec<_>>(),
                expected
            );
            let seqs: Vec<i64> = store
                .conn()
                .prepare("SELECT list_seq FROM sandboxes ORDER BY list_seq")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert_eq!(seqs, [1, 2, 3, 4]);
        }
        let store = Store::reopen_after_restart(temp.path());
        assert_eq!(
            store
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(
            store
                .sandboxes(true)
                .unwrap()
                .iter()
                .map(|s| s.id.clone())
                .collect::<Vec<_>>(),
            expected
        );
        let inserted = sandbox();
        store.insert_sandbox(&inserted).unwrap();
        assert_eq!(
            store.sandbox_page(true, None, None, 1).unwrap().rows[0].list_seq,
            5
        );
    }

    #[test]
    fn page_watermark_and_cursor_survive_equal_timestamps_and_state_changes() {
        let store = Store::open_in_memory().unwrap();
        let mut expected = Vec::new();
        for _ in 0..7 {
            let mut s = sandbox();
            s.created_at_ms = 10;
            store.insert_sandbox(&s).unwrap();
            expected.push(s.id);
        }
        expected.reverse();
        let first = store.sandbox_page(false, None, None, 2).unwrap();
        assert!(first.has_more);
        assert_eq!(first.upper_seq, 7);
        let upper = first.upper_seq;
        let mut before = first.rows.last().unwrap().list_seq;
        let mut got: Vec<String> = first.rows.into_iter().map(|r| r.sandbox.id).collect();
        store.insert_sandbox(&sandbox()).unwrap();
        store
            .set_sandbox_state(&expected[3], SandboxState::Failed, None, Some("changed"))
            .unwrap();
        loop {
            let page = store
                .sandbox_page(false, Some(upper), Some(before), 2)
                .unwrap();
            assert_eq!(page.upper_seq, upper);
            assert!(page.rows.len() <= 2);
            before = page.rows.last().unwrap().list_seq;
            got.extend(page.rows.into_iter().map(|r| r.sandbox.id));
            if !page.has_more {
                break;
            }
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn deleted_filter_and_exclusive_page_boundary() {
        let store = Store::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for _ in 0..4 {
            let s = sandbox();
            store.insert_sandbox(&s).unwrap();
            ids.push(s.id);
        }
        store
            .set_sandbox_state(&ids[2], SandboxState::Deleted, None, None)
            .unwrap();
        let first = store.sandbox_page(false, None, None, 1).unwrap();
        assert_eq!(first.rows[0].sandbox.id, ids[3]);
        assert!(first.has_more);
        let second = store
            .sandbox_page(
                false,
                Some(first.upper_seq),
                Some(first.rows[0].list_seq),
                2,
            )
            .unwrap();
        assert_eq!(
            second
                .rows
                .iter()
                .map(|r| &r.sandbox.id)
                .collect::<Vec<_>>(),
            [&ids[1], &ids[0]]
        );
        assert!(!second.has_more);
        assert_eq!(
            store.sandbox_page(true, None, None, 4).unwrap().rows.len(),
            4
        );
        assert!(!store.sandbox_page(false, None, None, 3).unwrap().has_more);
    }

    #[test]
    fn node_reservations_are_atomic_and_only_deleted_releases_them() {
        let store = Store::open_in_memory().unwrap();
        let first = sandbox();
        let budgets = SandboxBudgets {
            sandboxes: 4,
            memory_bytes: first.spec.memory_bytes,
            pids: u64::from(first.spec.pids) * 4,
            disk_bytes: first.spec.disk_bytes * 4,
            host_cpu_millis: 0,
            virtual_cpu_slots: 0,
            host_pids: 0,
        };
        assert_eq!(
            store.reserve_sandbox(&first, budgets).unwrap(),
            ReserveSandbox::Inserted
        );
        let expected = SandboxResources::for_spec(&first.spec);
        assert_eq!(store.sandbox_resources().unwrap(), expected);

        for state in [
            SandboxState::Ready,
            SandboxState::Lost,
            SandboxState::Failed,
            SandboxState::Deleting,
        ] {
            store
                .set_sandbox_state(&first.id, state, None, Some("injected"))
                .unwrap();
            assert_eq!(
                store.sandbox_resources().unwrap(),
                expected,
                "{state:?} released an ambiguous reservation"
            );
        }

        let second = sandbox();
        assert_eq!(
            store.reserve_sandbox(&second, budgets).unwrap(),
            ReserveSandbox::Exhausted(BudgetExhausted {
                resource: "memory bytes",
                reserved: first.spec.memory_bytes,
                requested: second.spec.memory_bytes,
                limit: budgets.memory_bytes,
            })
        );
        assert!(store.sandbox(&second.id).unwrap().is_none());

        store
            .set_sandbox_state(&first.id, SandboxState::Deleted, None, None)
            .unwrap();
        assert_eq!(
            store.sandbox_resources().unwrap(),
            SandboxResources::default()
        );
        assert_eq!(
            store.reserve_sandbox(&second, budgets).unwrap(),
            ReserveSandbox::Inserted
        );
    }

    #[test]
    fn every_node_budget_is_checked_before_the_creating_insert() {
        let first = sandbox();
        let requested = SandboxResources::for_spec(&first.spec);
        for (resource, budgets) in [
            (
                "sandboxes",
                SandboxBudgets {
                    sandboxes: 1,
                    memory_bytes: requested.memory_bytes * 2,
                    pids: requested.pids * 2,
                    disk_bytes: requested.disk_bytes * 2,
                    host_cpu_millis: 0,
                    virtual_cpu_slots: 0,
                    host_pids: 0,
                },
            ),
            (
                "memory bytes",
                SandboxBudgets {
                    sandboxes: 2,
                    memory_bytes: requested.memory_bytes,
                    pids: requested.pids * 2,
                    disk_bytes: requested.disk_bytes * 2,
                    host_cpu_millis: 0,
                    virtual_cpu_slots: 0,
                    host_pids: 0,
                },
            ),
            (
                "PIDs",
                SandboxBudgets {
                    sandboxes: 2,
                    memory_bytes: requested.memory_bytes * 2,
                    pids: requested.pids,
                    disk_bytes: requested.disk_bytes * 2,
                    host_cpu_millis: 0,
                    virtual_cpu_slots: 0,
                    host_pids: 0,
                },
            ),
            (
                "disk bytes",
                SandboxBudgets {
                    sandboxes: 2,
                    memory_bytes: requested.memory_bytes * 2,
                    pids: requested.pids * 2,
                    disk_bytes: requested.disk_bytes,
                    host_cpu_millis: 0,
                    virtual_cpu_slots: 0,
                    host_pids: 0,
                },
            ),
        ] {
            let store = Store::open_in_memory().unwrap();
            store.reserve_sandbox(&first, budgets).unwrap();
            let second = sandbox();
            let result = store.reserve_sandbox(&second, budgets).unwrap();
            assert!(
                matches!(result, ReserveSandbox::Exhausted(e) if e.resource == resource),
                "expected {resource}, got {result:?}"
            );
            assert!(store.sandbox(&second.id).unwrap().is_none());
            assert_eq!(store.sandbox_resources().unwrap(), requested);
        }
    }

    #[test]
    fn sandbox_round_trip_and_state_changes() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        assert_eq!(store.sandbox(&s.id).unwrap().unwrap(), s);
        assert_eq!(store.count_active_sandboxes().unwrap(), 1);

        store
            .set_sandbox_state(&s.id, SandboxState::Ready, Some("f00d-1"), None)
            .unwrap();
        let got = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!(
            (got.state, got.backend_id.as_deref()),
            (SandboxState::Ready, Some("f00d-1"))
        );

        store
            .set_sandbox_state(&s.id, SandboxState::Deleted, None, None)
            .unwrap();
        let got = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!(
            got.backend_id.as_deref(),
            Some("f00d-1"),
            "backend ID is kept"
        );
        assert!(got.deleted_at_ms.is_some());
        assert_eq!(store.count_active_sandboxes().unwrap(), 0);
        assert!(store.sandboxes(false).unwrap().is_empty());
        assert_eq!(store.sandboxes(true).unwrap().len(), 1);
        assert!(store.sandbox("sb-0000000000000000").unwrap().is_none());
        assert!(
            store
                .set_sandbox_state("sb-0000000000000000", SandboxState::Ready, None, None)
                .is_err()
        );
    }

    #[test]
    fn conditional_state_changes_do_not_rewrite_a_newer_terminal_state() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        store
            .set_sandbox_state(&s.id, SandboxState::Ready, Some("f00d-1"), None)
            .unwrap();

        assert!(
            store
                .compare_and_set_sandbox_state(
                    &s.id,
                    SandboxState::Ready,
                    SandboxState::Deleting,
                    None,
                    None,
                )
                .unwrap()
        );
        assert!(
            !store
                .compare_and_set_sandbox_state(
                    &s.id,
                    SandboxState::Ready,
                    SandboxState::Deleting,
                    None,
                    Some("stale transition"),
                )
                .unwrap()
        );
        assert!(
            store
                .compare_and_set_sandbox_state(
                    &s.id,
                    SandboxState::Deleting,
                    SandboxState::Deleted,
                    None,
                    None,
                )
                .unwrap()
        );
        let deleted = store.sandbox(&s.id).unwrap().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));

        assert!(
            !store
                .compare_and_set_sandbox_state(
                    &s.id,
                    SandboxState::Deleting,
                    SandboxState::Deleting,
                    None,
                    Some("late failure"),
                )
                .unwrap()
        );
        assert!(
            !store
                .compare_and_set_sandbox_state(
                    &s.id,
                    SandboxState::Deleting,
                    SandboxState::Deleted,
                    None,
                    None,
                )
                .unwrap()
        );
        assert_eq!(store.sandbox(&s.id).unwrap().unwrap(), deleted);
    }

    #[test]
    fn backend_ids_are_unique() {
        let store = Store::open_in_memory().unwrap();
        let (mut a, mut b) = (sandbox(), sandbox());
        a.backend_id = Some("f00d-1".into());
        b.backend_id = Some("f00d-1".into());
        store.insert_sandbox(&a).unwrap();
        assert!(store.insert_sandbox(&b).is_err());
    }

    #[test]
    fn execution_lifecycle() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        let e = execution(&s.id);
        store.insert_execution(&e).unwrap();
        assert_eq!(store.count_running_executions().unwrap(), 1);
        assert_eq!(store.execution(&e.id).unwrap().unwrap(), e);

        let out = Captured {
            data: b"hi\n".to_vec(),
            total_bytes: 3,
            truncated: false,
            total_bytes_known: true,
        };
        let err = Captured {
            data: b"ab".to_vec(),
            total_bytes: 900,
            truncated: true,
            total_bytes_known: true,
        };
        let result = ExecutionResult {
            state: ExecutionState::Exited,
            exit_code: Some(0),
            command_status: Some(&CommandStatus::Exited(0)),
            runtime_error: None,
            failure_reason: None,
            stdout: &out,
            stderr: &err,
            sandbox_reusable: None,
            cleanup_evidence: CleanupEvidence::Unknown,
            disposition: None,
            disposition_reason: None,
            cancel_reason: None,
        };
        store.finish_execution(&e.id, &result).unwrap();
        assert!(
            store.finish_execution(&e.id, &result).is_err(),
            "only running executions finish"
        );

        let got = store.execution(&e.id).unwrap().unwrap();
        assert_eq!(
            (got.state, got.exit_code),
            (ExecutionState::Exited, Some(0))
        );
        assert_eq!(got.stdout, out);
        assert!(got.stderr.truncated());
        assert!(got.finished_at_ms.is_some());

        let recent = store.recent_executions(&s.id, 10).unwrap();
        assert_eq!(recent.len(), 1);
        assert!(
            recent[0].stdout.data.is_empty(),
            "lists leave output data out"
        );
        assert_eq!(recent[0].stdout.total_bytes, 3);
        assert!(recent[0].stdout.total_bytes_known);
        assert_eq!(
            recent[0].stdout.truncated(),
            got.stdout.truncated(),
            "metadata projection must preserve the persisted truncation fact"
        );
        assert!(recent[0].stderr.data.is_empty());
        assert_eq!(recent[0].stderr.total_bytes, 900);
        assert!(recent[0].stderr.total_bytes_known);
        assert_eq!(
            recent[0].stderr.truncated(),
            got.stderr.truncated(),
            "metadata projection must preserve the persisted truncation fact"
        );
    }

    #[test]
    fn executions_need_their_sandbox() {
        let store = Store::open_in_memory().unwrap();
        assert!(
            store
                .insert_execution(&execution("sb-0000000000000000"))
                .is_err()
        );
    }

    #[test]
    fn interrupts_only_running_executions_for_the_selected_backend() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        let e = execution(&s.id);
        store.insert_execution(&e).unwrap();
        let mut other = sandbox();
        other.id = new_id("sb");
        other.backend = "firecracker".into();
        store.insert_sandbox(&other).unwrap();
        let foreign = execution(&other.id);
        store.insert_execution(&foreign).unwrap();

        assert_eq!(
            store
                .interrupt_running_executions_for_backend("fake", "restart")
                .unwrap(),
            1
        );
        let got = store.execution(&e.id).unwrap().unwrap();
        assert_eq!(got.state, ExecutionState::Interrupted);
        assert_eq!(got.failure_reason.as_deref(), Some("restart"));
        assert_eq!(
            store.execution(&foreign.id).unwrap().unwrap().state,
            ExecutionState::Running
        );
        assert_eq!(
            store
                .interrupt_running_executions_for_backend("fake", "restart")
                .unwrap(),
            0
        );
    }

    #[test]
    fn opens_a_private_directory_and_reopens() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let s = sandbox();
        {
            let store = Store::open(&dir).unwrap();
            store.insert_sandbox(&s).unwrap();
        }
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let store = Store::reopen_after_restart(&dir);
        assert_eq!(store.sandbox(&s.id).unwrap().unwrap(), s);
    }

    #[test]
    fn refuses_a_shared_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Store::open(tmp.path()).is_err());
    }

    #[test]
    fn refuses_a_non_private_state_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = Store::open(tmp.path())
            .err()
            .expect("0755 state directory was accepted");
        assert!(error.to_string().contains("0700"), "{error:#}");
    }

    #[test]
    fn refuses_a_relative_or_symlinked_state_directory() {
        let relative = Store::open(Path::new("relative-state"))
            .err()
            .expect("relative state directory was accepted");
        assert!(relative.to_string().contains("absolute"), "{relative:#}");

        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = tmp.path().join("target");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .unwrap();
        let alias = tmp.path().join("state");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        let symlink = Store::open(&alias)
            .err()
            .expect("symlinked state directory was accepted");
        assert!(symlink.to_string().contains("symlink"), "{symlink:#}");
    }

    #[test]
    fn resolves_every_trusted_symlink_hop_and_bounds_cycles() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = tmp.path().join("target");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .unwrap();
        let state = target.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        std::os::unix::fs::symlink("target", tmp.path().join("inner")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("inner"), tmp.path().join("outer")).unwrap();

        let store = Store::open(&tmp.path().join("outer/state")).unwrap();
        assert_eq!(store.state_directory_identity().unwrap().unwrap(), {
            let metadata = std::fs::metadata(&state).unwrap();
            (metadata.dev(), metadata.ino())
        });
        drop(store);

        std::os::unix::fs::symlink("cycle-b", tmp.path().join("cycle-a")).unwrap();
        std::os::unix::fs::symlink("cycle-a", tmp.path().join("cycle-b")).unwrap();
        let cycle = Store::open(&tmp.path().join("cycle-a/state"))
            .err()
            .expect("symlink cycle was accepted");
        assert!(cycle.to_string().contains("too many symlinks"), "{cycle:#}");
    }

    #[test]
    fn metadata_checks_reject_foreign_owners() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ancestor_path = tmp.path().to_path_buf();
        let mut metadata = std::fs::metadata(&ancestor_path).unwrap();
        if metadata.uid() == 0 {
            ancestor_path.push("foreign");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&ancestor_path)
                .unwrap();
            std::os::unix::fs::chown(&ancestor_path, Some(1), None).unwrap();
            metadata = std::fs::metadata(&ancestor_path).unwrap();
        }
        let ancestor = validate_directory(&metadata, &ancestor_path, 0, false, "state")
            .expect_err("foreign-owned ancestor was accepted");
        assert!(ancestor.to_string().contains("ancestor"), "{ancestor:#}");

        let database = tmp.path().join("kilnd.db");
        std::fs::File::create(&database).unwrap();
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
        let directory = std::fs::File::open(tmp.path()).unwrap();
        let entry = stat_entry_no_follow(&directory, OsStr::new("kilnd.db"), &database)
            .unwrap()
            .unwrap();
        let foreign_uid = if entry.uid == 0 { 1 } else { 0 };
        let database_error = validate_database_entry(&entry, &database, foreign_uid)
            .expect_err("foreign-owned database was accepted");
        assert!(
            database_error.to_string().contains("owned"),
            "{database_error:#}"
        );
    }

    /// B6: once SQLite has opened the database, nothing in kilnd may open and close its
    /// own descriptor to it or a sidecar. Closing one drops every POSIX lock the process
    /// holds on that file, SQLite's included, and another process's connection (an
    /// operator's sqlite3, a backup) then believes it is the last one: it checkpoints and
    /// unlinks the live WAL, every later commit goes to an unlinked file, and a crash
    /// loses them. The VM crash matrix found this when a SIGKILLed daemon came back
    /// without rows it had committed. POSIX locks belong to a process, so the reader here
    /// is a separate one: this test binary, re-executed as `wal_reader_child`.
    #[test]
    fn another_process_never_unlinks_the_live_wal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let database = tmp.path().join("kilnd.db");
        let read = || -> i64 {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "store::tests::wal_reader_child",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(WAL_READER_ENV, &database)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .find_map(|l| l.split("wal reader: ").nth(1))
                .and_then(|rest| rest.split_whitespace().next())
                .unwrap_or_else(|| {
                    panic!("no reading: {text}{}", String::from_utf8_lossy(&out.stderr))
                })
                .parse()
                .unwrap()
        };
        let before = read();
        assert!(
            tmp.path().join("kilnd.db-wal").exists(),
            "another process's close unlinked the live WAL: kilnd had lost its locks"
        );
        // A commit after that reader must reach the real WAL, so another process sees it.
        store
            .conn()
            .execute("UPDATE history_sequence SET value = value + 1", [])
            .unwrap();
        assert_eq!(
            read(),
            before + 1,
            "another process must see a committed write"
        );
        drop(store);
    }

    const WAL_READER_ENV: &str = "KILND_TEST_WAL_READER";

    /// The separate reader process for `another_process_never_unlinks_the_live_wal`.
    #[test]
    #[ignore = "re-exec target for another_process_never_unlinks_the_live_wal"]
    fn wal_reader_child() {
        let Ok(path) = std::env::var(WAL_READER_ENV) else {
            return;
        };
        let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        reader.pragma_update(None, "query_only", "ON").unwrap();
        let value: i64 = reader
            .query_row("SELECT value FROM history_sequence", [], |r| r.get(0))
            .unwrap();
        drop(reader);
        println!("wal reader: {value}");
    }

    #[test]
    fn creates_a_private_database_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(tmp.path()).unwrap();
        drop(store);
        let database = std::fs::symlink_metadata(tmp.path().join("kilnd.db")).unwrap();
        assert!(database.is_file());
        assert_eq!(database.permissions().mode() & 0o7777, 0o600);
        assert_eq!(database.nlink(), 1);
    }

    #[test]
    fn refuses_a_database_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        let target = tmp.path().join("forged.db");
        std::fs::File::create(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, state.join("kilnd.db")).unwrap();

        let error = Store::open(&state)
            .err()
            .expect("database symlink was followed");
        assert!(error.to_string().contains("kilnd.db"), "{error:#}");
        // scripts/state-path-regressions.sh matches this diagnostic.
        assert!(
            error.to_string().contains("without following symlinks"),
            "{error:#}"
        );
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn refuses_a_database_sidecar_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        let target = tmp.path().join("forged-wal");
        std::fs::File::create(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, state.join("kilnd.db-wal")).unwrap();

        let error = Store::open(&state)
            .err()
            .expect("database sidecar symlink was followed");
        assert!(error.to_string().contains("kilnd.db-wal"), "{error:#}");
        // scripts/state-path-regressions.sh matches this diagnostic.
        assert!(
            error.to_string().contains("without following symlinks"),
            "{error:#}"
        );
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn refuses_a_non_regular_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(state.join("kilnd.db"))
            .unwrap();

        let error = Store::open(&state)
            .err()
            .expect("database directory was accepted");
        assert!(error.to_string().contains("kilnd.db"), "{error:#}");
    }

    #[test]
    fn refuses_a_non_private_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        let database = state.join("kilnd.db");
        std::fs::File::create(&database).unwrap();
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = Store::open(&state)
            .err()
            .expect("0644 database was accepted");
        assert!(error.to_string().contains("0600"), "{error:#}");
    }

    #[test]
    fn refuses_a_hard_linked_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        let target = tmp.path().join("forged.db");
        std::fs::File::create(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&target, state.join("kilnd.db")).unwrap();

        let error = Store::open(&state)
            .err()
            .expect("hard-linked database was accepted");
        assert!(error.to_string().contains("one link"), "{error:#}");
    }

    #[test]
    fn refuses_a_newer_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        assert!(Store::init(conn, None).is_err());
    }

    #[test]
    fn failed_initialization_closes_sqlite_before_releasing_ownership() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let database = dir.join("kilnd.db");
        let conn = Connection::open(&database).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; PRAGMA user_version=99;",
        )
        .unwrap();
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let lock = ExclusiveFileLock::acquire(&dir.join("kilnd.lock"), "state directory")
            .unwrap()
            .with_drop_probe({
                let observed = observed.clone();
                move || {
                    let contender = Connection::open(&database).unwrap();
                    contender.busy_timeout(std::time::Duration::ZERO).unwrap();
                    let sqlite_was_closed = contender.execute_batch("BEGIN EXCLUSIVE").is_ok();
                    observed.store(
                        if sqlite_was_closed { 1 } else { 2 },
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
            });

        assert!(Store::init(conn, Some(lock)).is_err());
        assert_eq!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "state ownership was released while the failed SQLite connection was still open"
        );
    }

    #[test]
    fn state_directory_has_one_owner_and_keeps_a_stable_lock_inode() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let first = Store::open(&dir).unwrap();
        let lock = dir.join("kilnd.lock");
        let inode = std::fs::symlink_metadata(&lock).unwrap().ino();

        let error = Store::open(&dir)
            .err()
            .expect("a second store acquired the same state directory");
        assert!(
            error.to_string().contains("state directory already owned"),
            "{error:#}"
        );
        assert_eq!(std::fs::symlink_metadata(&lock).unwrap().ino(), inode);

        drop(first);
        let _next = Store::reopen_after_restart(&dir);
        assert_eq!(std::fs::symlink_metadata(&lock).unwrap().ino(), inode);
    }

    #[test]
    fn simultaneous_state_directory_starts_have_one_owner() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(3));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut threads = Vec::new();

        for _ in 0..2 {
            let dir = dir.clone();
            let start = start.clone();
            let release = release.clone();
            let tx = tx.clone();
            threads.push(std::thread::spawn(move || {
                start.wait();
                let store = Store::open(&dir);
                let outcome = store.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"));
                tx.send(outcome).unwrap();
                release.wait();
                drop(store);
            }));
        }
        drop(tx);

        let outcomes: Vec<_> = (0..2).map(|_| rx.recv().unwrap()).collect();
        assert_eq!(
            outcomes.iter().filter(|result| result.is_ok()).count(),
            1,
            "{outcomes:?}"
        );
        let loser = outcomes
            .iter()
            .find_map(|result| result.as_ref().err())
            .unwrap();
        assert!(loser.contains("state directory already owned"), "{loser}");
        release.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    fn keyed_row(request_id: &str, owner_uid: u32) -> Sandbox {
        let mut row = sandbox();
        row.owner_uid = owner_uid;
        row.lifecycle.request_id = Some(request_id.into());
        row
    }

    fn admission(per_uid: u64, node: u64) -> RequestAdmission {
        RequestAdmission {
            sha256: Digest::of(b"request"),
            max_per_uid: per_uid,
            max_node: node,
        }
    }

    /// Schema 12 reached from 9, 10 and 11 is the fresh schema; history has no
    /// request ID and no record, and an existing integrity marker is kept as is.
    #[test]
    fn schema14_from_9_through_13_matches_fresh() {
        let schema_sql = |conn: &Connection| -> Vec<(String, String)> {
            conn.prepare(
                "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        let fresh = Store::open_in_memory().unwrap();
        let expected = schema_sql(&fresh.conn());
        assert!(expected.iter().any(|(name, _)| name == "create_requests"));
        for version in [9, 10, 11, 12, 13] {
            let tmp = tempfile::tempdir().unwrap();
            let mut conn = disk_database_at(tmp.path(), 7);
            register_receipt_validator(&conn).unwrap();
            let tx = conn.transaction().unwrap();
            migrate_v8(&tx).unwrap();
            tx.execute_batch(MIGRATE_V9).unwrap();
            if version >= 10 {
                tx.execute_batch(MIGRATE_V10).unwrap();
            }
            let mut history = sandbox();
            history.state = SandboxState::Ready;
            history.backend_id = Some(format!("old-{version}"));
            insert_sandbox_before_v11(&tx, &history).unwrap();
            if version >= 10 {
                refresh_reservation_integrity(&tx).unwrap();
            }
            if version >= 11 {
                tx.execute_batch(MIGRATE_V11).unwrap();
            }
            if version >= 12 {
                tx.execute_batch(MIGRATE_V12).unwrap();
                refresh_membership(&tx).unwrap();
            }
            if version == 13 {
                tx.execute_batch(MIGRATE_V13).unwrap();
            }
            tx.execute(
                "INSERT INTO executions (id, sandbox_id, argv, state, timeout_ms, stdin_bytes, started_at_ms)
                 VALUES (?1, ?2, '[\"true\"]', 'exited', 1000, 0, 1)",
                params![format!("ex-{version:016x}"), history.id],
            )
            .unwrap();
            tx.commit().unwrap();
            release_database(conn, tmp.path());
            let store = Store::reopen_after_restart(tmp.path());
            assert_eq!(schema_sql(&store.conn()), expected, "v{version}");
            // Schema 14: history has no mode, which the API shows as unspecified.
            let old = store
                .execution(&format!("ex-{version:016x}"))
                .unwrap()
                .unwrap();
            assert_eq!(old.mode, None, "v{version}");
            assert_seeded_membership(&store.conn(), 1, 0);
            let row = store.sandbox(&history.id).unwrap().unwrap();
            assert_eq!(row.lifecycle, SandboxLifecycle::default(), "v{version}");
            assert_eq!(store.create_request_counts(0).unwrap(), RequestCounts::default());
        }
    }

    #[test]
    fn keyed_reservation_commits_the_row_and_record_together() {
        let store = Store::open_in_memory().unwrap();
        let row = keyed_row("k", 1000);
        assert_eq!(
            store
                .reserve_keyed_sandbox(&row, roomy_budgets(), Some(&admission(4, 8)))
                .unwrap(),
            ReserveSandbox::Inserted
        );
        let (digest, found) = store.create_request(1000, "k").unwrap().unwrap();
        assert_eq!(digest, Digest::of(b"request"));
        assert_eq!(found.id, row.id);
        assert_eq!(found.lifecycle.request_id.as_deref(), Some("k"));
        assert!(store.create_request(1001, "k").unwrap().is_none(), "per uid");
        // An exhausted node budget inserts neither.
        let exhausted = keyed_row("other", 1000);
        let mut tight = roomy_budgets();
        tight.sandboxes = 1;
        assert!(matches!(
            store
                .reserve_keyed_sandbox(&exhausted, tight, Some(&admission(4, 8)))
                .unwrap(),
            ReserveSandbox::Exhausted(_)
        ));
        assert!(store.sandbox(&exhausted.id).unwrap().is_none());
        assert!(store.create_request(1000, "other").unwrap().is_none());
        // A keyed row needs its admission, and an unkeyed one may not carry a key.
        assert!(store.reserve_sandbox(&keyed_row("x", 1), roomy_budgets()).is_err());
        assert_eq!(store.create_request_counts(1000).unwrap(), RequestCounts { node: 1, uid: 1 });
    }

    /// Release and prune are the only deletes, and both recheck the row in their
    /// own IMMEDIATE transaction.
    #[test]
    fn release_requires_deleted_and_runs_once() {
        let store = Store::open_in_memory().unwrap();
        let row = keyed_row("k", 1000);
        store
            .reserve_keyed_sandbox(&row, roomy_budgets(), Some(&admission(4, 8)))
            .unwrap();
        assert_eq!(store.release_request_id(&row.id).unwrap(), ReleaseRequestId::NotDeleted);
        store
            .set_sandbox_state(&row.id, SandboxState::Ready, Some("b-1"), None)
            .unwrap();
        assert_eq!(store.release_request_id(&row.id).unwrap(), ReleaseRequestId::NotDeleted);
        store
            .set_sandbox_state(&row.id, SandboxState::Deleting, None, None)
            .unwrap();
        assert_eq!(store.release_request_id(&row.id).unwrap(), ReleaseRequestId::NotDeleted);
        store
            .set_sandbox_state(&row.id, SandboxState::Deleted, None, None)
            .unwrap();
        assert_eq!(store.release_request_id(&row.id).unwrap(), ReleaseRequestId::Released);
        let released = store.sandbox(&row.id).unwrap().unwrap();
        assert!(released.lifecycle.request_id_released_at_ms.is_some());
        assert_eq!(released.lifecycle.request_id.as_deref(), Some("k"));
        assert_eq!(store.release_request_id(&row.id).unwrap(), ReleaseRequestId::NoRecord);
        assert_eq!(
            store.sandbox(&row.id).unwrap().unwrap(),
            released,
            "a repeat changes nothing"
        );
        assert_eq!(
            store.release_request_id("sb-0000000000000000").unwrap(),
            ReleaseRequestId::NoSandbox
        );
    }

    /// Schema 14 (design 5): every new row names its mode, which is fixed at insert and
    /// limited to the two modes; reads return it.
    #[test]
    fn schema14_records_each_mode_once() {
        use crate::model::ExecutionMode;
        let store = Store::open_in_memory().unwrap();
        let mut row = sandbox();
        row.state = SandboxState::Ready;
        insert_sandbox(&store.conn(), &row).unwrap();
        for (i, mode) in [ExecutionMode::Unary, ExecutionMode::Stream]
            .into_iter()
            .enumerate()
        {
            let mut e = execution(&row.id);
            e.id = format!("ex-{i:016x}");
            e.mode = Some(mode);
            assert!(store.start_execution(&e).unwrap());
            assert_eq!(store.execution(&e.id).unwrap().unwrap().mode, Some(mode));
            assert_eq!(
                store
                    .query_for_test::<String>("SELECT mode FROM executions WHERE id = ?1", [&e.id])
                    .unwrap(),
                mode.as_str()
            );
        }
        for sql in [
            "UPDATE executions SET mode = 'stream' WHERE id = 'ex-0000000000000000'",
            "UPDATE executions SET mode = NULL WHERE id = 'ex-0000000000000001'",
        ] {
            let error = store.conn().execute(sql, []).unwrap_err().to_string();
            assert!(error.contains("fixed at insert"), "{sql}: {error}");
        }
        let error = store
            .conn()
            .execute(
                "INSERT INTO executions (id, sandbox_id, argv, state, timeout_ms, stdin_bytes, started_at_ms, mode)
                 VALUES ('ex-00000000000000ff', ?1, '[]', 'running', 1, 0, 1, 'detached')",
                [&row.id],
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("CHECK"), "{error}");
        // Finishing an execution keeps its mode.
        let first = store.execution("ex-0000000000000000").unwrap().unwrap();
        assert_eq!(first.mode, Some(ExecutionMode::Unary));
    }

    /// Schema 13 (design 4.2): default env values only on a live row and only cleared;
    /// names, digests and exec features fixed; history never takes a value afterwards.
    #[test]
    fn schema13_keeps_default_env_values_only_while_live() {
        use crate::exec_env::EnvVar;
        let store = Store::open_in_memory().unwrap();
        let env = vec![EnvVar::new("B", "2"), EnvVar::new("A", "1")];
        let mut row = sandbox();
        row.lifecycle.default_env_names = crate::exec_env::env_names(&env);
        row.lifecycle.default_env_sha256 = crate::exec_env::env_sha256(&env);
        // Names and digest must be the values' own.
        let mut wrong = row.clone();
        wrong.id = new_id("sb");
        wrong.lifecycle.default_env_names = vec!["A".into()];
        assert!(
            store
                .reserve_sandbox_with_env(&wrong, roomy_budgets(), None, &env)
                .is_err()
        );
        assert_eq!(
            store
                .reserve_sandbox_with_env(&row, roomy_budgets(), None, &env)
                .unwrap(),
            ReserveSandbox::Inserted
        );
        assert_eq!(
            store.sandbox_default_env(&row.id).unwrap(),
            crate::exec_env::sorted_env(&env)
        );
        let conn = store.conn();
        for sql in [
            // Names, digest and values are fixed at insert; values may only be cleared.
            "UPDATE sandboxes SET default_env_names = '[\"A\"]' WHERE id = ?1",
            "UPDATE sandboxes SET default_env_sha256 = NULL, default_env_names = NULL WHERE id = ?1",
            "UPDATE sandboxes SET default_env = '[[\"A\",\"x\"]]' WHERE id = ?1",
            // FAILED or DELETED with values is impossible.
            "UPDATE sandboxes SET state = 'failed' WHERE id = ?1",
        ] {
            assert!(conn.execute(sql, [&row.id]).is_err(), "{sql}");
        }
        drop(conn);
        store
            .publish_legacy_ready(&row.id, "b-13", Some(0x3f))
            .unwrap();
        assert_eq!(
            store.sandbox(&row.id).unwrap().unwrap().lifecycle.exec_features,
            Some(0x3f)
        );
        // Recorded once: a later READY (a recovered row) keeps the first.
        store.publish_legacy_ready(&row.id, "b-13", Some(0x0f)).unwrap();
        assert_eq!(
            store.sandbox(&row.id).unwrap().unwrap().lifecycle.exec_features,
            Some(0x3f)
        );
        assert!(
            store
                .conn()
                .execute("UPDATE sandboxes SET exec_features = 1 WHERE id = ?1", [&row.id])
                .is_err()
        );
        // An execution's cwd and names are fixed at insert.
        let mut e = execution(&row.id);
        e.cwd = Some("/w".into());
        e.env_names = vec!["A".into()];
        e.env_sha256 = Some("ab".repeat(32));
        assert!(store.start_execution(&e).unwrap());
        let stored = store.execution(&e.id).unwrap().unwrap();
        assert_eq!((stored.cwd, stored.env_names), (e.cwd.clone(), e.env_names.clone()));
        for sql in [
            "UPDATE executions SET cwd = '/x' WHERE id = ?1",
            "UPDATE executions SET env_names = NULL, env_sha256 = NULL WHERE id = ?1",
        ] {
            assert!(store.conn().execute(sql, [&e.id]).is_err(), "{sql}");
        }
        // Moving to DELETED clears the values in the same statement.
        store
            .set_sandbox_state(&row.id, SandboxState::Deleting, None, None)
            .unwrap();
        assert!(store.sandbox_default_env(&row.id).unwrap().len() == 2);
        store
            .set_sandbox_state(&row.id, SandboxState::Deleted, None, None)
            .unwrap();
        assert!(store.sandbox_default_env(&row.id).unwrap().is_empty());
        let kept = store.sandbox(&row.id).unwrap().unwrap();
        assert_eq!(kept.lifecycle.default_env_names, ["A", "B"]);
        // A row can't be inserted past CREATING with values, or with values but no names.
        let mut late = sandbox();
        late.state = SandboxState::Ready;
        late.backend_id = Some("late".into());
        late.lifecycle.default_env_names = vec!["A".into()];
        late.lifecycle.default_env_sha256 = crate::exec_env::env_sha256(&env[1..]);
        assert!(
            store
                .reserve_sandbox_with_env(&late, roomy_budgets(), None, &env[1..])
                .is_err()
        );
    }

    /// The schema 12 triggers hold even on a connection with foreign keys, recursive
    /// triggers and CHECK constraints off.
    #[test]
    fn schema12_triggers_defend_records_on_a_defenseless_connection() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let live = keyed_row("live", 1000);
        store
            .reserve_keyed_sandbox(&live, roomy_budgets(), Some(&admission(4, 8)))
            .unwrap();
        let conn = defenseless_connection(tmp.path());
        let refused = |sql: &str| {
            let error = conn.execute_batch(sql).unwrap_err().to_string();
            assert!(
                error.contains("create request")
                    || error.contains("request ID")
                    || error.contains("sandbox"),
                "{sql}: {error}"
            );
        };
        let id = &live.id;
        // No replace, in either key; no record for a foreign or non-CREATING row.
        refused(&format!(
            "INSERT OR REPLACE INTO create_requests VALUES (1000, 'live', '{}', '{id}', 1, 'b', 1)",
            "0".repeat(64)
        ));
        refused(&format!(
            "INSERT OR REPLACE INTO create_requests VALUES (1000, 'other', '{}', '{id}', 1, 'b', 1)",
            "0".repeat(64)
        ));
        refused(&format!(
            "INSERT INTO create_requests VALUES (1001, 'other', '{}', '{id}', 1, 'b', 1)",
            "0".repeat(64)
        ));
        // A record changes only in the cross-boot rebase.
        refused(&format!(
            "UPDATE create_requests SET request_sha256 = '{}' WHERE sandbox_id = '{id}'",
            "1".repeat(64)
        ));
        refused(&format!(
            "UPDATE create_requests SET retain_from_boottime_ms = 0 WHERE sandbox_id = '{id}'"
        ));
        conn.execute_batch(&format!(
            "UPDATE create_requests SET retain_boot_id = 'boot-z', retain_from_boottime_ms = 0 WHERE sandbox_id = '{id}'"
        ))
        .unwrap();
        // An anchored record is never unanchored (HIGH 1: anchors are written only
        // after the inserting commit, so an insert carrying one is refused above).
        refused(&format!(
            "UPDATE create_requests SET retain_boot_id = NULL, retain_from_boottime_ms = NULL WHERE sandbox_id = '{id}'"
        ));
        // Neither a live record nor its pinned row can be deleted.
        refused(&format!("DELETE FROM create_requests WHERE sandbox_id = '{id}'"));
        refused(&format!("DELETE FROM sandboxes WHERE id = '{id}'"));
        // The request ID is fixed, and released only from DELETED, after its record.
        refused(&format!("UPDATE sandboxes SET request_id = 'changed' WHERE id = '{id}'"));
        refused(&format!("UPDATE sandboxes SET request_id = NULL WHERE id = '{id}'"));
        refused(&format!(
            "UPDATE sandboxes SET request_id_released_at_ms = 1 WHERE id = '{id}'"
        ));
        drop(conn);
        store
            .set_sandbox_state(id, SandboxState::Deleted, None, None)
            .unwrap();
        let conn = defenseless_connection(tmp.path());
        let refused = |sql: &str| assert!(conn.execute_batch(sql).is_err(), "{sql}");
        refused(&format!(
            "UPDATE sandboxes SET request_id_released_at_ms = 1 WHERE id = '{id}'"
        ));
        // A DELETED row's record may go; then the stamp may be written, once.
        conn.execute_batch(&format!("DELETE FROM create_requests WHERE sandbox_id = '{id}'"))
            .unwrap();
        conn.execute_batch(&format!(
            "UPDATE sandboxes SET request_id_released_at_ms = 1 WHERE id = '{id}'"
        ))
        .unwrap();
        refused(&format!(
            "UPDATE sandboxes SET request_id_released_at_ms = 2 WHERE id = '{id}'"
        ));
    }

    #[test]
    fn rebase_gives_foreign_records_this_boot_and_keeps_ours() {
        let store = Store::open_in_memory().unwrap();
        let clock = crate::expiry::ManualClock::default();
        store.set_clock(std::sync::Arc::new(clock.clone()));
        let first = keyed_row("first", 1);
        store
            .reserve_keyed_sandbox(&first, roomy_budgets(), Some(&admission(4, 8)))
            .unwrap();
        let anchor = |store: &Store, id: &str| -> (String, i64) {
            store
                .conn()
                .query_row(
                    "SELECT retain_boot_id, retain_from_boottime_ms FROM create_requests WHERE sandbox_id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert_eq!(anchor(&store, &first.id), ("boot-a".into(), 1_000_000));
        assert_eq!(store.rebase_create_requests().unwrap(), 0);
        clock.reboot("boot-b", 7_000, 1_000);
        let second = keyed_row("second", 1);
        store
            .reserve_keyed_sandbox(&second, roomy_budgets(), Some(&admission(4, 8)))
            .unwrap();
        clock.advance(500);
        assert_eq!(store.rebase_create_requests().unwrap(), 1);
        assert_eq!(anchor(&store, &first.id), ("boot-b".into(), 7_500));
        assert_eq!(anchor(&store, &second.id), ("boot-b".into(), 7_000));
    }

    fn record_anchor(store: &Store, id: &str) -> (Option<String>, Option<i64>) {
        store
            .conn()
            .query_row(
                "SELECT retain_boot_id, retain_from_boottime_ms FROM create_requests WHERE sandbox_id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    /// Break-it HIGH 1 regression: a pause inside the admission transaction, just
    /// before it commits, is not counted against the window. The record commits
    /// unanchored and is anchored from a reading taken after the commit.
    #[test]
    fn a_pause_before_the_admission_commit_does_not_shorten_retention() {
        let store = Store::open_in_memory().unwrap();
        let clock = crate::expiry::ManualClock::default();
        store.set_clock(std::sync::Arc::new(clock.clone()));
        let paused = clock.clone();
        *store.before_request_commit.lock().unwrap() =
            Some(Box::new(move || paused.advance(3_600_000)));
        let row = keyed_row("paused", 1);
        store
            .reserve_keyed_sandbox(&row, roomy_budgets(), Some(&admission(4, 8)))
            .unwrap();
        assert_eq!(
            record_anchor(&store, &row.id),
            (Some("boot-a".into()), Some(1_000_000 + 3_600_000)),
            "anchored at the boottime after the pause, not before it"
        );
    }

    /// A record whose anchor transaction never ran (the daemon died between the
    /// two) stays unanchored and is never pruned as such; the next prune anchors it
    /// from a reading under its write lock, or the startup rebase does: a full
    /// window from then, never earlier.
    #[test]
    fn an_unanchored_record_is_anchored_late_never_early() {
        let store = Store::open_in_memory().unwrap();
        let clock = crate::expiry::ManualClock::default();
        store.set_clock(std::sync::Arc::new(clock.clone()));
        for (name, by_prune) in [("by-prune", true), ("by-rebase", false)] {
            let row = keyed_row(name, 1);
            store
                .reserve_keyed_sandbox(&row, roomy_budgets(), Some(&admission(4, 8)))
                .unwrap();
            {
                let conn = store.conn();
                conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
                    .unwrap();
                conn.execute(
                    "UPDATE create_requests SET retain_boot_id = NULL, retain_from_boottime_ms = NULL WHERE sandbox_id = ?1",
                    [&row.id],
                )
                .unwrap();
                conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)
                    .unwrap();
            }
            for state in [SandboxState::Ready, SandboxState::Deleting, SandboxState::Deleted] {
                let backend = (state == SandboxState::Ready).then(|| format!("b-{name}"));
                store
                    .set_sandbox_state(&row.id, state, backend.as_deref(), None)
                    .unwrap();
            }
            clock.advance(10 * 86_400_000);
            let anchored_at = clock.boottime_ms();
            if by_prune {
                let pruned = store.prune(&Retention::default(), now_ms()).unwrap();
                assert_eq!(pruned.create_requests, 0, "{name}: never pruned unanchored");
            } else {
                assert_eq!(store.rebase_create_requests().unwrap(), 1, "{name}");
            }
            assert_eq!(
                record_anchor(&store, &row.id),
                (Some("boot-a".into()), Some(anchored_at)),
                "{name}"
            );
        }
    }

    /// A connection that ignores kilnd's triggers: an operator's sqlite3 past them.
    fn trigger_free_connection(dir: &Path) -> Connection {
        let conn = Connection::open(dir.join("kilnd.db")).unwrap();
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .unwrap();
        conn
    }

    /// Break-it M2 MEDIUM 2: after any other connection commits, the next decision
    /// verifies everything, as every decision used to: a lost settled row, a lost
    /// charged row and a charged row released past the triggers are each caught
    /// there. A prune or a restart that comes first refuses too, and never folds a
    /// bypassed release into settled history (fix review MEDIUM 1); prune latches.
    #[test]
    fn external_changes_are_caught_by_the_next_decision_prune_or_restart() {
        // What happens first after the external change.
        #[derive(Clone, Copy, Debug)]
        enum First {
            Decision,
            Prune,
            Restart,
        }
        for (change, first) in ["lose settled", "lose charged", "release charged"]
            .into_iter()
            .flat_map(|c| [(c, First::Decision), (c, First::Prune), (c, First::Restart)])
        {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let dir = tmp.path().join("state");
            let store = Store::open(&dir).unwrap();
            let charged = sandbox();
            store.insert_sandbox(&charged).unwrap();
            let settled = sandbox();
            store.insert_sandbox(&settled).unwrap();
            for state in [SandboxState::Ready, SandboxState::Deleting, SandboxState::Deleted] {
                let backend = (state == SandboxState::Ready).then_some("b-settled");
                store.set_sandbox_state(&settled.id, state, backend, None).unwrap();
            }
            store.prune(&Retention::default(), now_ms()).unwrap();
            assert_eq!(store.sandbox_resources().unwrap().sandboxes, 1);
            let outside = trigger_free_connection(&dir);
            match change {
                "lose settled" => outside.execute("DELETE FROM sandboxes WHERE id = ?1", [&settled.id]),
                "lose charged" => outside.execute("DELETE FROM sandboxes WHERE id = ?1", [&charged.id]),
                _ => outside.execute(
                    "UPDATE sandboxes SET legacy_release = 'deleted', state = 'deleted' WHERE id = ?1",
                    [&charged.id],
                ),
            }
            .unwrap();
            drop(outside);
            let label = format!("{change}, then {first:?}");
            let refused = |error: anyhow::Error| {
                let error = format!("{error:#}");
                assert!(error.contains("reservation integrity"), "{label}: {error}");
            };
            match first {
                First::Decision => {
                    refused(store.sandbox_resources().unwrap_err());
                    match store.reserve_sandbox(&sandbox(), roomy_budgets()) {
                        Err(error) => refused(error),
                        Ok(_) => panic!("{label}: admitted"),
                    }
                }
                First::Prune => {
                    refused(store.prune(&Retention::default(), now_ms()).unwrap_err());
                    refused(store.sandbox_resources().unwrap_err());
                    refused(store.prune(&Retention::default(), now_ms()).unwrap_err());
                }
                First::Restart => {}
            }
            drop(store);
            refused(Store::open(&dir).err().expect("startup refuses"));
        }
    }

    /// The request quota reads trigger-kept counters, not a count over the records;
    /// the full audit checks them against the records and refuses a mismatch.
    #[test]
    fn request_counters_follow_the_records_and_the_full_audit_checks_them() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tmp.path().join("state");
        let store = Store::open(&dir).unwrap();
        store.set_clock(std::sync::Arc::new(crate::expiry::ManualClock::default()));
        let mut rows = Vec::new();
        for (key, uid) in [("a", 1000), ("b", 1000), ("c", 1001)] {
            let row = keyed_row(key, uid);
            store
                .reserve_keyed_sandbox(&row, roomy_budgets(), Some(&admission(8, 8)))
                .unwrap();
            rows.push(row);
        }
        let counts = |uid| store.create_request_counts(uid).unwrap();
        assert_eq!((counts(1000).node, counts(1000).uid, counts(1001).uid, counts(7).uid), (3, 2, 1, 0));
        for state in [SandboxState::Ready, SandboxState::Deleting, SandboxState::Deleted] {
            let backend = (state == SandboxState::Ready).then_some("b-c");
            store.set_sandbox_state(&rows[2].id, state, backend, None).unwrap();
        }
        assert_eq!(store.release_request_id(&rows[2].id).unwrap(), ReleaseRequestId::Released);
        assert_eq!((counts(1000).node, counts(1001).uid), (2, 0));
        let leftover: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM create_request_counts WHERE owner_uid = 1001", [], |r| r.get(0))
            .unwrap();
        assert_eq!(leftover, 0, "a uid with no records has no counter");
        store.prune(&Retention::default(), now_ms()).unwrap();

        let outside = trigger_free_connection(&dir);
        outside
            .execute("UPDATE create_request_counts SET records = 0 WHERE owner_uid = 1000", [])
            .unwrap();
        let error = store.prune(&Retention::default(), now_ms()).unwrap_err().to_string();
        assert!(error.contains("counters"), "{error}");
        assert!(store.sandbox_resources().is_err(), "latched off");
        drop((outside, store));
        let error = Store::open(&dir).err().expect("startup refuses").to_string();
        assert!(error.contains("counters"), "{error}");
    }

    /// The bounded audit and the reservation sum read only live rows: SQLite finds
    /// the charged ones through the partial index, never by scanning history.
    #[test]
    fn live_set_queries_use_the_charged_index() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.conn();
        let plan = |sql: &str| -> String {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            stmt.query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>()
                .join("\n")
        };
        for sql in [
            format!("SELECT {MEMBERSHIP_COLUMNS} FROM sandboxes WHERE id IN ({})", live_ids()),
            format!(
                "SELECT {FENCED_RELEASE_COLUMNS} FROM sandboxes s
                 LEFT JOIN release_evidence e ON e.receipt_id = s.release_evidence_id
                 WHERE s.id IN ({}) AND {FENCED_RELEASE_WHERE}",
                live_ids()
            ),
            format!(
                "SELECT id FROM sandboxes WHERE id IN (SELECT id FROM sandboxes WHERE {RESERVED_SANDBOX_WHERE}
                 UNION SELECT id FROM temp.accounting_quarantine)"
            ),
        ] {
            let plan = plan(&sql);
            assert!(plan.contains("sandboxes_charged"), "{sql}\n{plan}");
            // Every pass over the sandboxes table goes through the charged index.
            let table_scan = |line: &str| {
                (line == "SCAN s" || line.starts_with("SCAN s ") || line.starts_with("SCAN sandboxes"))
                    && !line.contains("USING INDEX sandboxes_charged")
            };
            assert!(!plan.lines().any(table_scan), "{sql}\n{plan}");
        }
    }

    /// M2 fix re-review: after one benign commit by another connection, only the
    /// first decision verifies all history; it commits its stamp even when it only
    /// reads (a keyed lookup that finds nothing or a record) or refuses, so later
    /// lookups and refusals stay bounded.
    #[test]
    fn one_external_commit_costs_one_full_verification() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(tmp.path()).unwrap();
        store.set_clock(std::sync::Arc::new(crate::expiry::ManualClock::default()));
        let mut history = Vec::new();
        for i in 0..200 {
            let row = keyed_row(&format!("old-{i}"), 1000);
            store
                .reserve_keyed_sandbox(&row, roomy_budgets(), Some(&admission(4096, 4096)))
                .unwrap();
            for state in [SandboxState::Ready, SandboxState::Deleting, SandboxState::Deleted] {
                let backend = (state == SandboxState::Ready).then(|| format!("b-old-{i}"));
                store.set_sandbox_state(&row.id, state, backend.as_deref(), None).unwrap();
            }
            history.push(row);
        }
        store.prune(&Retention::default(), now_ms()).unwrap();
        let hashed = |f: &mut dyn FnMut()| {
            let before = MEMBERSHIP_ROWS_HASHED.with(|n| n.get());
            f();
            MEMBERSHIP_ROWS_HASHED.with(|n| n.get()) - before
        };
        let lookup = |key: &str| store.create_request(1000, key).unwrap().is_some();
        assert_eq!(hashed(&mut || assert!(!lookup("none"))), 0);

        Connection::open(tmp.path().join("kilnd.db"))
            .unwrap()
            .execute(
                "UPDATE sandboxes SET updated_at_ms = updated_at_ms + 1 WHERE id = ?1",
                [&history[0].id],
            )
            .unwrap();
        // The first decision after it verifies everything; the rest do not.
        assert!(hashed(&mut || assert!(!lookup("none"))) >= 200);
        for _ in 0..3 {
            assert_eq!(hashed(&mut || assert!(!lookup("none"))), 0);
            assert_eq!(hashed(&mut || assert!(lookup("old-7"))), 0);
            let taken = hashed(&mut || {
                assert!(matches!(
                    store
                        .reserve_keyed_sandbox(&keyed_row("old-7", 1000), roomy_budgets(), Some(&admission(4096, 4096)))
                        .unwrap(),
                    ReserveSandbox::RequestIdTaken
                ))
            });
            assert_eq!(taken, 0);
            let full = hashed(&mut || {
                assert!(matches!(
                    store
                        .reserve_keyed_sandbox(&keyed_row("over", 1000), roomy_budgets(), Some(&admission(200, 4096)))
                        .unwrap(),
                    ReserveSandbox::RequestQuota(_)
                ))
            });
            assert_eq!(full, 0);
            assert!(store.sandbox(&history[0].id).unwrap().is_some());
            assert_eq!(store.sandboxes(true).unwrap().len(), 200);
        }
    }

    /// M2 fix review MEDIUM 2: filling the quota by ordinary keyed create and
    /// delete, with no prune in between (and no fixture reseed), keeps each
    /// admission's work flat: a write decision settles the releases before it.
    #[test]
    fn create_and_delete_without_a_prune_keeps_admission_flat() {
        let store = Store::open_in_memory().unwrap();
        store.set_clock(std::sync::Arc::new(crate::expiry::ManualClock::default()));
        let caps = admission(4096, 32_768);
        let mut most = 0;
        let mut last = 0;
        for i in 0..2048 {
            let row = keyed_row(&format!("fill-{i}"), 1000);
            let before = MEMBERSHIP_ROWS_HASHED.with(|n| n.get());
            assert!(store.create_request(1000, &format!("fill-{i}")).unwrap().is_none());
            assert!(matches!(
                store.reserve_keyed_sandbox(&row, roomy_budgets(), Some(&caps)).unwrap(),
                ReserveSandbox::Inserted
            ));
            last = MEMBERSHIP_ROWS_HASHED.with(|n| n.get()) - before;
            most = most.max(last);
            for state in [SandboxState::Ready, SandboxState::Deleting, SandboxState::Deleted] {
                let backend = (state == SandboxState::Ready).then(|| format!("b-fill-{i}"));
                store.set_sandbox_state(&row.id, state, backend.as_deref(), None).unwrap();
            }
        }
        assert_eq!(store.create_request_counts(1000).unwrap().uid, 2048);
        println!("rows hashed per admission over 2,048 create/delete cycles: at most {most}, last {last}");
        assert!(most <= 8, "{most}");
    }

    /// Break-it M2 MEDIUM 2 scale regression: keyed admission at the request caps
    /// (4,096 records for one uid, 32,768 on the node, all retained DELETED history)
    /// hashes no history, and costs about what it does on an empty node.
    #[test]
    fn keyed_admission_cost_does_not_grow_with_retained_history() {
        fn seed(store: &Store, per_uid: usize, node: usize) {
            let mut conn = store.conn();
            let tx = conn.transaction().unwrap();
            for i in 0..node {
                let uid = if i < per_uid { 1000 } else { 2000 };
                let row = keyed_row(&format!("seed-{i}"), uid);
                insert_sandbox(&tx, &row).unwrap();
                tx.execute(
                    "INSERT INTO create_requests (owner_uid, request_id, request_sha256, sandbox_id, created_at_ms)
                     VALUES (?1, ?2, ?3, ?4, 1)",
                    params![uid, row.lifecycle.request_id, "0".repeat(64), row.id],
                )
                .unwrap();
                tx.execute(
                    &format!(
                        "UPDATE sandboxes SET state = ?2, deleted_at_ms = 1, {LEGACY_TRANSITION} WHERE id = ?1"
                    ),
                    params![row.id, "deleted", Option::<String>::None],
                )
                .unwrap();
            }
            anchor_unanchored(&tx, &crate::expiry::ManualClock::default()).unwrap();
            // The trusted writer's own account of what it inserted, then settled.
            refresh_membership(&tx).unwrap();
            tx.commit().unwrap();
        }
        // One admission: the keyed lookup, then the admitting transaction, which
        // refuses at a cap or inserts.
        fn admit(store: &Store, uid: u32, key: &str, caps: &RequestAdmission) -> (Duration, u64) {
            let hashed = MEMBERSHIP_ROWS_HASHED.with(|n| n.get());
            let started = std::time::Instant::now();
            assert!(store.create_request(uid, key).unwrap().is_none());
            store
                .reserve_keyed_sandbox(&keyed_row(key, uid), roomy_budgets(), Some(caps))
                .unwrap();
            (started.elapsed(), MEMBERSHIP_ROWS_HASHED.with(|n| n.get()) - hashed)
        }
        fn median(mut samples: Vec<Duration>) -> Duration {
            samples.sort();
            samples[samples.len() / 2]
        }
        use std::time::Duration;
        let roomy = admission(1 << 20, 1 << 20);
        let measure = |per_uid: usize, node: usize| -> (Duration, Duration, u64) {
            let store = Store::open_in_memory().unwrap();
            store.set_clock(std::sync::Arc::new(crate::expiry::ManualClock::default()));
            seed(&store, per_uid, node);
            let mut most_hashed = 0;
            // Thirty-two refusals at the caps (the review's last-slot race, in turn).
            let mut refused = Vec::new();
            for k in 0..32 {
                let (took, hashed) = admit(&store, 2000, &format!("late-{k}"), &admission(per_uid as u64, node as u64));
                refused.push(took);
                most_hashed = most_hashed.max(hashed);
            }
            // Thirty-two admitted creates under caps with room, each one more live row.
            let mut admitted = Vec::new();
            for k in 0..32 {
                let (took, hashed) = admit(&store, 3000, &format!("new-{k}"), &roomy);
                admitted.push(took);
                most_hashed = most_hashed.max(hashed);
            }
            (median(refused), median(admitted), most_hashed)
        };
        let (small_refused, small_admitted, small_hashed) = measure(64, 128);
        let (big_refused, big_admitted, big_hashed) = measure(4_096, 32_768);
        println!(
            "keyed admission, median of 32: 128 records: refused {small_refused:?}, admitted {small_admitted:?}; \
             32,768 records (4,096 for one uid): refused {big_refused:?}, admitted {big_admitted:?}; \
             most rows hashed by one admission: {small_hashed} and {big_hashed}"
        );
        // Deterministic: an admission hashes its live rows (here at most the 32
        // charged creates of this test and the one it inserts, three times), never
        // the 32,768 retained ones.
        assert!(big_hashed <= 3 * 33 + 1, "{big_hashed}");
        assert_eq!(small_hashed, big_hashed);
        // And in time, with room for a loaded machine: before the fix one admission
        // at this size hashed the whole history three times.
        for (small, big) in [(small_refused, big_refused), (small_admitted, big_admitted)] {
            assert!(big < small * 8 + Duration::from_millis(20), "{small:?} -> {big:?}");
        }
    }

    #[test]
    fn prune_age_is_r_plus_a_thousandth_rounded_up() {
        use crate::retention::create_request_prune_age_ms;
        assert_eq!(create_request_prune_age_ms(86_400), Some(86_400_000 + 86_400));
        assert_eq!(create_request_prune_age_ms(86_401), Some(86_401_000 + 86_401));
        assert_eq!(create_request_prune_age_ms(u64::MAX), None);
    }
}
