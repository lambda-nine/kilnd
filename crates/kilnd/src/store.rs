//! SQLite state: one row per sandbox and per execution. kilnd is the only
//! writer; the database lives in a root-only directory.

use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::lock::ExclusiveFileLock;
use crate::model::{
    Captured, CommandStatus, Execution, ExecutionState, RuntimeDiagnostic, Sandbox, SandboxSpec,
    SandboxState, now_ms,
};

const SCHEMA_VERSION: i64 = 3;

const MIGRATE_V3: &str = "
ALTER TABLE executions ADD COLUMN command_status_kind TEXT;
ALTER TABLE executions ADD COLUMN command_status_value INTEGER;
ALTER TABLE executions ADD COLUMN command_core_dumped INTEGER;
ALTER TABLE executions ADD COLUMN runtime_error TEXT;
PRAGMA user_version = 3;";

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
    stderr           BLOB NOT NULL DEFAULT x'',
    stderr_bytes     INTEGER NOT NULL DEFAULT 0,
    stderr_truncated INTEGER NOT NULL DEFAULT 0,
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

impl Store {
    /// Opens or creates the database in `dir`, which is created 0700 if
    /// missing and refused if anyone but its owner can write to it. A
    /// process-lifetime lock is acquired before SQLite is opened.
    pub fn open(dir: &Path) -> Result<Self> {
        prepare_directory(dir)?;
        let instance_lock = ExclusiveFileLock::acquire(&dir.join("kilnd.lock"), "state directory")?;
        let conn = Connection::open(dir.join("kilnd.db")).context("open database")?;
        Self::init(conn, Some(instance_lock))
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(conn: Connection, instance_lock: Option<ExclusiveFileLock>) -> Result<Self> {
        // Move both resources into their final drop order before any
        // fallible SQLite setup. This also makes initialization failures
        // close SQLite before releasing state-directory ownership.
        let store = Self {
            conn: Mutex::new(conn),
            _instance_lock: instance_lock,
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
                tx.commit().context("migrate schema v1 to v3")?;
            }
            2 => {
                let tx = conn.transaction()?;
                tx.execute_batch(MIGRATE_V3)?;
                tx.commit().context("migrate schema v2 to v3")?;
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
        self.conn().execute(
            "INSERT INTO sandboxes (id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms, list_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, (SELECT COALESCE(MAX(list_seq), 0) + 1 FROM sandboxes))",
            params![
                s.id,
                s.backend,
                s.backend_id,
                s.state.as_str(),
                serde_json::to_string(&s.spec)?,
                s.failure_reason,
                s.created_at_ms,
                s.updated_at_ms,
                s.deleted_at_ms
            ],
        )?;
        Ok(())
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
                 stdout = ?6, stdout_bytes = ?7, stdout_truncated = ?8,
                 stderr = ?9, stderr_bytes = ?10, stderr_truncated = ?11,
                 command_status_kind = ?12, command_status_value = ?13, command_core_dumped = ?14, runtime_error = ?15
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
                r.stderr.data,
                r.stderr.total_bytes as i64,
                r.stderr.truncated(), status_kind, status_value, core_dumped, runtime_error
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

    /// Marks every execution still recorded as running as interrupted.
    /// Only valid at startup, before any new execution begins.
    pub fn interrupt_running_executions(&self, reason: &str) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE executions SET state = 'interrupted', failure_reason = ?1, finished_at_ms = ?2 WHERE state = 'running'",
            params![reason, now_ms()],
        )?)
    }
}

fn prepare_directory(dir: &Path) -> Result<()> {
    if !dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    let meta = std::fs::symlink_metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if meta.uid() != euid {
        bail!(
            "{} must be owned by uid {euid}, found uid {}",
            dir.display(),
            meta.uid()
        );
    }
    if meta.permissions().mode() & 0o022 != 0 {
        bail!(
            "{} is writable by group or others; expected 0700",
            dir.display()
        );
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
    started_at_ms, finished_at_ms, stdout, stdout_bytes, stderr, stderr_bytes,
    command_status_kind, command_status_value, command_core_dumped, runtime_error";

const EXECUTION_METADATA_COLUMNS: &str =
    "id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, x'', stdout_bytes, x'', stderr_bytes,
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
                row.get::<_, Option<String>>(14)?.as_deref(),
                row.get::<_, Option<i32>>(15)?,
                row.get::<_, Option<bool>>(16)?,
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
                .get::<_, Option<String>>(17)?
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
            },
            stderr: Captured {
                data: row.get(12)?,
                total_bytes: row.get::<_, i64>(13)? as u64,
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

    fn schema_v2() -> String {
        SCHEMA.replace(",\n    command_status_kind TEXT,\n    command_status_value INTEGER,\n    command_core_dumped INTEGER,\n    runtime_error TEXT", "")
    }

    #[test]
    fn fresh_v3_and_historical_v1_v2_keep_unknown_status_null() {
        let fresh = Store::open_in_memory().unwrap();
        assert_eq!(
            fresh
                .conn()
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            3
        );
        for version in [1, 2] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
            let mut schema = schema_v2();
            if version == 1 {
                schema=schema.replace(",\n    list_seq       INTEGER NOT NULL","")
                    .replace("CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);","")
                    .replace("CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';","");
            }
            conn.execute_batch(&schema).unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            let mut s = sandbox();
            s.state = SandboxState::Ready;
            let list_column = if version == 2 { ", list_seq" } else { "" };
            let list_value = if version == 2 { ", 1" } else { "" };
            conn.execute(&format!("INSERT INTO sandboxes (id,backend,state,spec,created_at_ms,updated_at_ms{list_column}) VALUES (?1,'fake','ready',?2,1,1{list_value})"),params![s.id,serde_json::to_string(&s.spec).unwrap()]).unwrap();
            conn.execute("INSERT INTO executions (id,sandbox_id,argv,state,exit_code,timeout_ms,stdin_bytes,started_at_ms) VALUES ('old',?1,'[]','exited',143,1,0,1)",[&s.id]).unwrap();
            conn.execute("INSERT INTO executions (id,sandbox_id,argv,state,timeout_ms,stdin_bytes,started_at_ms) VALUES ('running',?1,'[]','running',1,0,2)",[&s.id]).unwrap();
            drop(conn);
            let store = Store::open(tmp.path()).unwrap();
            assert_eq!(
                store
                    .conn()
                    .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                3
            );
            let historical = store.execution("old").unwrap().unwrap();
            assert_eq!(historical.exit_code, Some(143));
            assert!(historical.command_status.is_none() && historical.runtime_error.is_none());
            store.interrupt_running_executions("restart").unwrap();
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
        };
        let err = Captured {
            data: b"\0\xfeerr".to_vec(),
            total_bytes: 1001,
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
    fn v1_disk_migration_preserves_legacy_order_and_reopens_as_v3() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let legacy = SCHEMA.replace(",\n    command_status_kind TEXT,\n    command_status_value INTEGER,\n    command_core_dumped INTEGER,\n    runtime_error TEXT", "").replace(",\n    list_seq       INTEGER NOT NULL", "")
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
            3
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
        };
        let err = Captured {
            data: b"ab".to_vec(),
            total_bytes: 900,
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
        assert!(recent[0].stderr.data.is_empty());
        assert_eq!(recent[0].stderr.total_bytes, 900);
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
    fn interrupts_running_executions() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        let e = execution(&s.id);
        store.insert_execution(&e).unwrap();
        assert_eq!(store.interrupt_running_executions("restart").unwrap(), 1);
        let got = store.execution(&e.id).unwrap().unwrap();
        assert_eq!(got.state, ExecutionState::Interrupted);
        assert_eq!(got.failure_reason.as_deref(), Some("restart"));
        assert_eq!(store.interrupt_running_executions("restart").unwrap(), 0);
    }

    #[test]
    fn opens_a_private_directory_and_reopens() {
        let tmp = tempfile::tempdir().unwrap();
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
