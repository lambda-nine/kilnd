//! SQLite state: one row per sandbox and per execution. kilnd is the only
//! writer; the database lives in a root-only directory.

use std::collections::VecDeque;
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
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, params,
};

use crate::lock::ExclusiveFileLock;
use crate::model::{
    Captured, CommandStatus, Execution, ExecutionState, RuntimeDiagnostic, Sandbox, SandboxSpec,
    SandboxState, now_ms,
};

const SCHEMA_VERSION: i64 = 4;

// A non-deleted row reserves capacity unless a successful compensation
// recorded the exact removed backend ID on FAILED. FAILED without an ID stays
// reserved because Runtime::create errors can be ambiguous.
const RESERVED_SANDBOX_WHERE: &str =
    "state != 'deleted' AND NOT (state = 'failed' AND backend_id IS NOT NULL)";
// Only these lifecycle states can still explain a listed backend ID. In
// particular, compensated FAILED must not hide a backend that reappeared.
const OWNED_BACKEND_WHERE: &str = "state IN ('creating', 'ready', 'deleting', 'lost')";

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

const SCHEMA: &str = "
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
    list_seq       INTEGER NOT NULL
);
CREATE UNIQUE INDEX sandboxes_backend_id ON sandboxes (backend, backend_id) WHERE backend_id IS NOT NULL;
CREATE INDEX sandboxes_state ON sandboxes (state);
CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);
CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';

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
    #[cfg(test)]
    reject_execution_finishes: Arc<AtomicBool>,
}

/// How an execution ended, written in one update.
pub struct ExecutionResult<'a> {
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub command_status: Option<&'a CommandStatus>,
    pub runtime_error: Option<&'a RuntimeDiagnostic>,
    pub failure_reason: Option<&'a str>,
    pub stdout: &'a Captured,
    pub stderr: &'a Captured,
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
}

impl SandboxResources {
    fn for_spec(spec: &SandboxSpec) -> Self {
        Self {
            sandboxes: 1,
            memory_bytes: spec.memory_bytes,
            pids: u64::from(spec.pids),
            disk_bytes: spec.disk_bytes,
        }
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
}

fn insert_sandbox(conn: &Connection, sandbox: &Sandbox) -> Result<()> {
    conn.execute(
        "INSERT INTO sandboxes (id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, list_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, (SELECT COALESCE(MAX(list_seq), 0) + 1 FROM sandboxes))",
        params![
            sandbox.id,
            sandbox.backend,
            sandbox.backend_id,
            sandbox.state.as_str(),
            serde_json::to_string(&sandbox.spec)?,
            sandbox.failure_reason,
            sandbox.created_at_ms,
            sandbox.updated_at_ms,
            sandbox.deleted_at_ms
        ],
    )?;
    Ok(())
}

fn sandbox_resources(conn: &Connection) -> Result<SandboxResources> {
    let mut statement = conn.prepare(&format!(
        "SELECT id, spec FROM sandboxes WHERE {RESERVED_SANDBOX_WHERE}"
    ))?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut resources = SandboxResources::default();
    for row in rows {
        let (id, encoded) = row?;
        let spec: SandboxSpec = serde_json::from_str(&encoded)
            .with_context(|| format!("sandbox {id}: bad spec while accounting resources"))?;
        resources = resources.checked_add(SandboxResources::for_spec(&spec))?;
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
        let existing = inspect_database_entry(
            &directory.file,
            OsStr::new("kilnd.db"),
            &database_path,
            expected_uid,
        )?;
        inspect_sqlite_sidecars(&directory, expected_uid)?;
        let conn = Connection::open_with_flags(
            &database_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("open database without following symlinks")?;
        let mut opened = open_entry_no_follow(
            &directory.file,
            OsStr::new("kilnd.db"),
            &database_path,
        )?
        .context("SQLite did not create kilnd.db")?;
        if existing.is_none() {
            opened
                .file
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("set {} to 0600", database_path.display()))?;
            opened.refresh()?;
        }
        validate_database_entry(&opened, &database_path, expected_uid)?;
        if let Some(existing) = existing
            && existing.identity() != opened.identity()
        {
            bail!("{} changed while opening", database_path.display());
        }
        Self::init_with_directory(conn, Some(instance_lock), Some(directory.file))
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
            #[cfg(test)]
            reject_execution_finishes: Arc::new(AtomicBool::new(false)),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<()> {
        let mut conn = self.conn();
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match version {
            0 => {
                conn.execute_batch(&format!(
                    "BEGIN; {SCHEMA} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
                ))
                .context("create schema")?;
            }
            1 => {
                let tx = conn.transaction()?;
                tx.execute_batch("ALTER TABLE sandboxes ADD COLUMN list_seq INTEGER;
                    WITH ordered AS (
                        SELECT id, ROW_NUMBER() OVER (ORDER BY created_at_ms ASC, id DESC) AS seq FROM sandboxes
                    )
                    UPDATE sandboxes SET list_seq = (SELECT seq FROM ordered WHERE ordered.id = sandboxes.id);
                    CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);
                    CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';
                    PRAGMA user_version = 2;")?;
                tx.execute_batch(MIGRATE_V3)?;
                tx.execute_batch(MIGRATE_V4)?;
                tx.commit().context("migrate schema v1 to v4")?;
            }
            2 => {
                let tx = conn.transaction()?;
                tx.execute_batch(MIGRATE_V3)?;
                tx.execute_batch(MIGRATE_V4)?;
                tx.commit().context("migrate schema v2 to v4")?;
            }
            3 => {
                let tx = conn.transaction()?;
                tx.execute_batch(MIGRATE_V4)?;
                tx.commit().context("migrate schema v3 to v4")?;
            }
            SCHEMA_VERSION => {}
            v => bail!("database schema version {v} is newer than this kilnd ({SCHEMA_VERSION})"),
        }
        Ok(())
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock can't leave SQLite inconsistent;
        // each statement is atomic.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert_sandbox(&self, s: &Sandbox) -> Result<()> {
        insert_sandbox(&self.conn(), s)
    }

    /// Atomically checks every durable node reservation and inserts the new
    /// CREATING row. The IMMEDIATE transaction makes the sum-and-insert one
    /// decision even if another SQLite writer ignores kilnd's instance lock.
    pub fn reserve_sandbox(
        &self,
        s: &Sandbox,
        budgets: SandboxBudgets,
    ) -> Result<ReserveSandbox> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let reserved = sandbox_resources(&tx)?;
        let requested = SandboxResources::for_spec(&s.spec);
        if let Some(exhausted) = exhausted_budget(reserved, requested, budgets)? {
            return Ok(ReserveSandbox::Exhausted(exhausted));
        }
        insert_sandbox(&tx, s)?;
        tx.commit()?;
        Ok(ReserveSandbox::Inserted)
    }

    /// Reservations survive daemon restart because they are derived from the
    /// lifecycle rows. LOST stays reserved because it may recover to READY;
    /// FAILED without a backend ID stays reserved because Runtime::create
    /// errors may be ambiguous after allocating an unreported backend.
    /// FAILED with a backend ID is written only after compensation proved
    /// that exact backend gone, so it releases capacity while retaining the
    /// historical row. Explicit deletion resolves an ambiguous FAILED row.
    pub fn sandbox_resources(&self) -> Result<SandboxResources> {
        sandbox_resources(&self.conn())
    }

    /// Backend IDs that a nonterminal lifecycle row can still own. This is
    /// deliberately narrower than reservations: ambiguous FAILED has no ID,
    /// while compensated FAILED has an ID but proved it absent.
    pub fn owned_backend_ids(&self, backend: &str) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut statement = conn.prepare(&format!(
            "SELECT backend_id FROM sandboxes
             WHERE backend = ?1 AND backend_id IS NOT NULL AND {OWNED_BACKEND_WHERE}"
        ))?;
        let rows = statement.query_map([backend], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
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
        let n = self.conn().execute(
            "UPDATE sandboxes SET state = ?2, backend_id = COALESCE(?3, backend_id), failure_reason = ?4,
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(?6, deleted_at_ms)
             WHERE id = ?1",
            params![id, state.as_str(), backend_id, failure_reason, now, deleted_at],
        )?;
        if n != 1 {
            bail!("sandbox {id} not found");
        }
        Ok(())
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
        let n = self.conn().execute(
            "UPDATE sandboxes SET state = ?2, backend_id = COALESCE(?3, backend_id), failure_reason = ?4,
                 updated_at_ms = ?5, deleted_at_ms = COALESCE(?6, deleted_at_ms)
             WHERE id = ?1 AND state = ?7",
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
        Ok(n == 1)
    }

    /// Marks a sandbox lost only if it is still READY. Delete publishes
    /// DELETING before waiting for a running exec, so a late NotFound result
    /// must not overwrite that cleanup intent.
    pub fn mark_sandbox_lost_if_ready(&self, id: &str, failure_reason: &str) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE sandboxes SET state = 'lost', failure_reason = ?2, updated_at_ms = ?3
             WHERE id = ?1 AND state = 'ready'",
            params![id, failure_reason, now_ms()],
        )?;
        Ok(n == 1)
    }

    pub fn sandbox(&self, id: &str) -> Result<Option<Sandbox>> {
        self.conn()
            .query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [id],
                sandbox_row,
            )
            .optional()?
            .transpose()
    }

    /// Newest first.
    pub fn sandboxes(&self, include_deleted: bool) -> Result<Vec<Sandbox>> {
        let conn = self.conn();
        let filter = if include_deleted {
            ""
        } else {
            "WHERE state != 'deleted'"
        };
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS} FROM sandboxes {filter} ORDER BY list_seq DESC"
        ))?;
        let rows = stmt.query_map([], sandbox_row)?;
        rows.map(|r| r?).collect()
    }

    /// A stable insertion watermark, bounded fetch, and exclusive cursor.
    pub fn sandbox_page(
        &self,
        include_deleted: bool,
        upper_seq: Option<i64>,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<SandboxPage> {
        let conn = self.conn();
        let filter = if include_deleted {
            ""
        } else {
            "state != 'deleted' AND "
        };
        let upper_seq = match upper_seq {
            Some(upper) => upper,
            None => conn.query_row(
                &format!("SELECT COALESCE(MAX(list_seq), 0) FROM sandboxes WHERE {filter}1"),
                [],
                |row| row.get(0),
            )?,
        };
        let before = if before_seq.is_some() {
            "AND list_seq < ?2"
        } else {
            "AND ?2 IS NULL"
        };
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS}, list_seq FROM sandboxes
            WHERE {filter}list_seq <= ?1 {before} ORDER BY list_seq DESC LIMIT ?3"
        ))?;
        let rows = stmt.query_map(
            params![upper_seq, before_seq, i64::from(limit) + 1],
            |row| {
                let list_seq = row.get(9)?;
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
    }

    pub fn count_active_sandboxes(&self) -> Result<u32> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM sandboxes WHERE state IN ('creating', 'ready', 'deleting')",
            [],
            |r| r.get(0),
        )?)
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
        let n = self.conn().execute(
            "UPDATE executions SET state = ?2, exit_code = ?3, failure_reason = ?4, finished_at_ms = ?5,
                 stdout = ?6, stdout_bytes = ?7, stdout_truncated = ?8, stdout_total_bytes_known = ?9,
                 stderr = ?10, stderr_bytes = ?11, stderr_truncated = ?12, stderr_total_bytes_known = ?13,
                 command_status_kind = ?14, command_status_value = ?15, command_core_dumped = ?16, runtime_error = ?17
             WHERE id = ?1 AND state = 'running'",
            params![
                id,
                r.state.as_str(),
                r.exit_code,
                r.failure_reason,
                now_ms(),
                r.stdout.data,
                r.stdout.total_bytes as i64,
                r.stdout.truncated(),
                r.stdout.total_bytes_known,
                r.stderr.data,
                r.stderr.total_bytes as i64,
                r.stderr.truncated(),
                r.stderr.total_bytes_known,
                status_kind,
                status_value,
                core_dumped,
                runtime_error
            ],
        )?;
        if n != 1 {
            bail!("execution {id} is not running");
        }
        Ok(())
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
    pub(crate) fn execution_finish_rejection_flag(&self) -> Arc<AtomicBool> {
        self.reject_execution_finishes.clone()
    }

    /// Marks this backend's executions still recorded as running as
    /// interrupted. Only valid at startup, before any new execution begins.
    pub fn interrupt_running_executions_for_backend(
        &self,
        backend: &str,
        reason: &str,
    ) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE executions
             SET state = 'interrupted', failure_reason = ?2, finished_at_ms = ?3
             WHERE state = 'running'
               AND EXISTS (
                   SELECT 1 FROM sandboxes
                   WHERE sandboxes.id = executions.sandbox_id
                     AND sandboxes.backend = ?1
               )",
            params![backend, reason, now_ms()],
        )?)
    }
}

pub(crate) struct PreparedDirectory {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
}

struct OpenedEntry {
    file: File,
    metadata: std::fs::Metadata,
}

impl OpenedEntry {
    fn refresh(&mut self) -> Result<()> {
        self.metadata = self.file.metadata().context("inspect opened database")?;
        Ok(())
    }

    fn identity(&self) -> (u64, u64) {
        (self.metadata.dev(), self.metadata.ino())
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
                        return Err(error)
                            .with_context(|| format!("inspect {resource} path {}", path.display()));
                    }
                };
                if let Some(stat) = stat
                    && stat.st_mode & libc::S_IFMT == libc::S_IFLNK
                {
                    if pending.is_empty() {
                        bail!("{resource} directory must not be a symlink: {}", path.display());
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
                        bail!("too many symlinks while resolving {resource} path {}", dir.display());
                    }
                    let target =
                        read_link_at(directories.last().unwrap(), &name, &path, resource)?;
                    let target_steps = path_steps(&target)?;
                    for target_step in target_steps.into_iter().rev() {
                        pending.push_front(target_step);
                    }
                    continue;
                }

                let next = match stat {
                    Some(_) => open_directory_at(directories.last().unwrap(), &name)
                        .with_context(|| {
                            format!("open {resource} path {} without following symlinks", path.display())
                        })?,
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
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "directory name contains NUL"))?;
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
            bail!("{resource} path symlink target is too long: {}", path.display());
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
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "directory name contains NUL"))?;
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

fn open_entry_no_follow(directory: &File, name: &OsStr, path: &Path) -> Result<Option<OpenedEntry>> {
    let name = CString::new(name.as_bytes()).context("database filename contains NUL")?;
    // O_NONBLOCK makes inspecting a pre-created FIFO fail safely rather than
    // hanging startup. O_NOFOLLOW rejects a symbolic link before SQLite sees
    // the path.
    // SAFETY: directory and name are live and flags are valid for openat.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error)
            .with_context(|| format!("inspect {} without following symlinks", path.display()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    Ok(Some(OpenedEntry { file, metadata }))
}

fn validate_database_entry(entry: &OpenedEntry, path: &Path, expected_uid: u32) -> Result<()> {
    if !entry.metadata.is_file() {
        bail!("{} must be a regular file", path.display());
    }
    if entry.metadata.uid() != expected_uid {
        bail!(
            "{} must be owned by uid {expected_uid}, found uid {}",
            path.display(),
            entry.metadata.uid()
        );
    }
    let mode = entry.metadata.permissions().mode() & 0o7777;
    if mode != 0o600 {
        bail!("{} must have mode 0600, found {mode:04o}", path.display());
    }
    if entry.metadata.nlink() != 1 {
        bail!("{} must have exactly one link", path.display());
    }
    Ok(())
}

fn inspect_database_entry(
    directory: &File,
    name: &OsStr,
    path: &Path,
    expected_uid: u32,
) -> Result<Option<OpenedEntry>> {
    let entry = open_entry_no_follow(directory, name, path)?;
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

const SANDBOX_COLUMNS: &str = "id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms";

/// Row decoding errors are reported per row rather than as SQLite errors.
fn sandbox_row(row: &Row<'_>) -> rusqlite::Result<Result<Sandbox>> {
    let state: String = row.get(3)?;
    let spec: String = row.get(4)?;
    let id: String = row.get(0)?;
    Ok((|| {
        Ok(Sandbox {
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
            id: id.clone(),
        })
    })())
}

const EXECUTION_COLUMNS: &str =
    "id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, stdout, stdout_bytes, stdout_truncated, stdout_total_bytes_known,
    stderr, stderr_bytes, stderr_truncated, stderr_total_bytes_known,
    command_status_kind, command_status_value, command_core_dumped, runtime_error";

const EXECUTION_METADATA_COLUMNS: &str =
    "id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, x'', stdout_bytes, stdout_truncated, stdout_total_bytes_known,
    x'', stderr_bytes, stderr_truncated, stderr_total_bytes_known,
    command_status_kind, command_status_value, command_core_dumped, runtime_error";

fn execution_row(row: &Row<'_>) -> rusqlite::Result<Result<Execution>> {
    let id: String = row.get(0)?;
    let argv: String = row.get(2)?;
    let state: String = row.get(3)?;
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
            id: id.clone(),
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Network, new_id};
    use std::collections::BTreeMap;
    use std::os::unix::fs::DirBuilderExt;

    fn schema_v3() -> String {
        SCHEMA
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
    fn fresh_v4_and_historical_v1_v2_v3_keep_unknown_evidence() {
        let fresh = Store::open_in_memory().unwrap();
        assert_eq!(
            fresh
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            4
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
                4
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
            let reopened = Store::open(tmp.path()).unwrap();
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
        let store = Store::open(tmp.path()).unwrap();
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
        }
    }

    #[test]
    fn v1_disk_migration_preserves_legacy_order_and_reopens_as_v4() {
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
        let store = Store::open(temp.path()).unwrap();
        assert_eq!(
            store
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            4
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
        assert_eq!(store.sandbox_resources().unwrap(), SandboxResources::default());
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
                },
            ),
            (
                "memory bytes",
                SandboxBudgets {
                    sandboxes: 2,
                    memory_bytes: requested.memory_bytes,
                    pids: requested.pids * 2,
                    disk_bytes: requested.disk_bytes * 2,
                },
            ),
            (
                "PIDs",
                SandboxBudgets {
                    sandboxes: 2,
                    memory_bytes: requested.memory_bytes * 2,
                    pids: requested.pids,
                    disk_bytes: requested.disk_bytes * 2,
                },
            ),
            (
                "disk bytes",
                SandboxBudgets {
                    sandboxes: 2,
                    memory_bytes: requested.memory_bytes * 2,
                    pids: requested.pids * 2,
                    disk_bytes: requested.disk_bytes,
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
        let store = Store::open(&dir).unwrap();
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
        let error = Store::open(tmp.path()).err().expect("0755 state directory was accepted");
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
        std::fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
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
        std::fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        let state = target.join("state");
        std::fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        std::os::unix::fs::symlink("target", tmp.path().join("inner")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("inner"), tmp.path().join("outer")).unwrap();

        let store = Store::open(&tmp.path().join("outer/state")).unwrap();
        assert_eq!(
            store.state_directory_identity().unwrap().unwrap(),
            {
                let metadata = std::fs::metadata(&state).unwrap();
                (metadata.dev(), metadata.ino())
            }
        );
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
        let file = std::fs::File::open(&database).unwrap();
        let entry = OpenedEntry {
            metadata: file.metadata().unwrap(),
            file,
        };
        let foreign_uid = if entry.metadata.uid() == 0 { 1 } else { 0 };
        let database_error = validate_database_entry(&entry, &database, foreign_uid)
            .expect_err("foreign-owned database was accepted");
        assert!(database_error.to_string().contains("owned"), "{database_error:#}");
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
        std::fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        let target = tmp.path().join("forged.db");
        std::fs::File::create(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, state.join("kilnd.db")).unwrap();

        let error = Store::open(&state).err().expect("database symlink was followed");
        assert!(error.to_string().contains("kilnd.db"), "{error:#}");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn refuses_a_database_sidecar_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        let target = tmp.path().join("forged-wal");
        std::fs::File::create(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, state.join("kilnd.db-wal")).unwrap();

        let error = Store::open(&state)
            .err()
            .expect("database sidecar symlink was followed");
        assert!(error.to_string().contains("kilnd.db-wal"), "{error:#}");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn refuses_a_non_regular_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(state.join("kilnd.db"))
            .unwrap();

        let error = Store::open(&state).err().expect("database directory was accepted");
        assert!(error.to_string().contains("kilnd.db"), "{error:#}");
    }

    #[test]
    fn refuses_a_non_private_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        let database = state.join("kilnd.db");
        std::fs::File::create(&database).unwrap();
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = Store::open(&state).err().expect("0644 database was accepted");
        assert!(error.to_string().contains("0600"), "{error:#}");
    }

    #[test]
    fn refuses_a_hard_linked_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = tmp.path().join("state");
        std::fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        let target = tmp.path().join("forged.db");
        std::fs::File::create(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&target, state.join("kilnd.db")).unwrap();

        let error = Store::open(&state).err().expect("hard-linked database was accepted");
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
        let _next = Store::open(&dir).unwrap();
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
}
