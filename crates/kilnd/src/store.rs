//! SQLite state: one row per sandbox and per execution. kilnd is the only
//! writer; the database lives in a root-only directory.

use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::model::{Captured, Execution, ExecutionState, Sandbox, SandboxSpec, SandboxState, now_ms};

const SCHEMA_VERSION: i64 = 1;

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
    deleted_at_ms  INTEGER
);
CREATE UNIQUE INDEX sandboxes_backend_id ON sandboxes (backend, backend_id) WHERE backend_id IS NOT NULL;
CREATE INDEX sandboxes_state ON sandboxes (state);

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
    stderr_truncated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX executions_sandbox ON executions (sandbox_id, started_at_ms);
CREATE INDEX executions_state ON executions (state);
";

pub struct Store {
    conn: Mutex<Connection>,
}

/// How an execution ended, written in one update.
pub struct ExecutionResult<'a> {
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub failure_reason: Option<&'a str>,
    pub stdout: &'a Captured,
    pub stderr: &'a Captured,
}

impl Store {
    /// Opens or creates the database in `dir`, which is created 0700 if
    /// missing and refused if anyone but its owner can write to it.
    pub fn open(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            DirBuilder::new().recursive(true).mode(0o700).create(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let meta = std::fs::symlink_metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
        if !meta.is_dir() {
            bail!("{} is not a directory", dir.display());
        }
        if meta.permissions().mode() & 0o022 != 0 {
            bail!("{} is writable by group or others; expected 0700", dir.display());
        }
        let conn = Connection::open(dir.join("kilnd.db")).context("open database")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match version {
            0 => {
                conn.execute_batch(&format!("BEGIN; {SCHEMA} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"))
                    .context("create schema")?;
            }
            SCHEMA_VERSION => {}
            v => bail!("database schema version {v} is newer than this kilnd ({SCHEMA_VERSION})"),
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock can't leave SQLite inconsistent;
        // each statement is atomic.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert_sandbox(&self, s: &Sandbox) -> Result<()> {
        self.conn().execute(
            "INSERT INTO sandboxes (id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
            .query_row(&format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"), [id], sandbox_row)
            .optional()?
            .transpose()
    }

    /// Newest first.
    pub fn sandboxes(&self, include_deleted: bool) -> Result<Vec<Sandbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE ?1 OR state != 'deleted' ORDER BY created_at_ms DESC, id"
        ))?;
        let rows = stmt.query_map([include_deleted], sandbox_row)?;
        rows.map(|r| r?).collect()
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
        let n = self.conn().execute(
            "UPDATE executions SET state = ?2, exit_code = ?3, failure_reason = ?4, finished_at_ms = ?5,
                 stdout = ?6, stdout_bytes = ?7, stdout_truncated = ?8,
                 stderr = ?9, stderr_bytes = ?10, stderr_truncated = ?11
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
                r.stderr.truncated()
            ],
        )?;
        if n != 1 {
            bail!("execution {id} is not running");
        }
        Ok(())
    }

    pub fn execution(&self, id: &str) -> Result<Option<Execution>> {
        self.conn()
            .query_row(&format!("SELECT {EXECUTION_COLUMNS} FROM executions WHERE id = ?1"), [id], execution_row)
            .optional()?
            .transpose()
    }

    /// The newest `limit` executions of a sandbox, without their output data.
    pub fn recent_executions(&self, sandbox_id: &str, limit: u32) -> Result<Vec<Execution>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {EXECUTION_COLUMNS} FROM executions WHERE sandbox_id = ?1
             ORDER BY started_at_ms DESC, rowid DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![sandbox_id, limit], execution_row)?;
        rows.map(|r| {
            let mut e = r??;
            e.stdout.data.clear();
            e.stderr.data.clear();
            Ok(e)
        })
        .collect()
    }

    pub fn count_running_executions(&self) -> Result<u32> {
        Ok(self.conn().query_row("SELECT COUNT(*) FROM executions WHERE state = 'running'", [], |r| r.get(0))?)
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
        self.conn().execute_batch(
            "CREATE TEMP TRIGGER reject_execution_finishes
             BEFORE UPDATE OF state ON executions
             WHEN OLD.state = 'running' AND NEW.state != 'running'
             BEGIN SELECT RAISE(FAIL, 'injected execution finalization failure'); END;",
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn allow_execution_finishes(&self) -> Result<()> {
        self.conn().execute_batch("DROP TRIGGER reject_execution_finishes")?;
        Ok(())
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

const SANDBOX_COLUMNS: &str =
    "id, backend, backend_id, state, spec, failure_reason, created_at_ms, updated_at_ms, deleted_at_ms";

/// Row decoding errors are reported per row rather than as SQLite errors.
fn sandbox_row(row: &Row<'_>) -> rusqlite::Result<Result<Sandbox>> {
    let state: String = row.get(3)?;
    let spec: String = row.get(4)?;
    let id: String = row.get(0)?;
    Ok((|| {
        Ok(Sandbox {
            state: SandboxState::parse(&state).with_context(|| format!("sandbox {id}: unknown state {state:?}"))?,
            spec: serde_json::from_str::<SandboxSpec>(&spec).with_context(|| format!("sandbox {id}: bad spec"))?,
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

const EXECUTION_COLUMNS: &str = "id, sandbox_id, argv, state, exit_code, failure_reason, timeout_ms, stdin_bytes,
    started_at_ms, finished_at_ms, stdout, stdout_bytes, stderr, stderr_bytes";

fn execution_row(row: &Row<'_>) -> rusqlite::Result<Result<Execution>> {
    let id: String = row.get(0)?;
    let argv: String = row.get(2)?;
    let state: String = row.get(3)?;
    Ok((|| {
        Ok(Execution {
            sandbox_id: row.get(1)?,
            argv: serde_json::from_str(&argv).with_context(|| format!("execution {id}: bad argv"))?,
            state: ExecutionState::parse(&state).with_context(|| format!("execution {id}: unknown state {state:?}"))?,
            exit_code: row.get(4)?,
            failure_reason: row.get(5)?,
            timeout_ms: row.get(6)?,
            stdin_bytes: row.get::<_, i64>(7)? as u64,
            started_at_ms: row.get(8)?,
            finished_at_ms: row.get(9)?,
            stdout: Captured { data: row.get(10)?, total_bytes: row.get::<_, i64>(11)? as u64 },
            stderr: Captured { data: row.get(12)?, total_bytes: row.get::<_, i64>(13)? as u64 },
            id: id.clone(),
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Network, new_id};
    use std::collections::BTreeMap;

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
    fn sandbox_round_trip_and_state_changes() {
        let store = Store::open_in_memory().unwrap();
        let s = sandbox();
        store.insert_sandbox(&s).unwrap();
        assert_eq!(store.sandbox(&s.id).unwrap().unwrap(), s);
        assert_eq!(store.count_active_sandboxes().unwrap(), 1);

        store.set_sandbox_state(&s.id, SandboxState::Ready, Some("f00d-1"), None).unwrap();
        let got = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!((got.state, got.backend_id.as_deref()), (SandboxState::Ready, Some("f00d-1")));

        store.set_sandbox_state(&s.id, SandboxState::Deleted, None, None).unwrap();
        let got = store.sandbox(&s.id).unwrap().unwrap();
        assert_eq!(got.backend_id.as_deref(), Some("f00d-1"), "backend ID is kept");
        assert!(got.deleted_at_ms.is_some());
        assert_eq!(store.count_active_sandboxes().unwrap(), 0);
        assert!(store.sandboxes(false).unwrap().is_empty());
        assert_eq!(store.sandboxes(true).unwrap().len(), 1);
        assert!(store.sandbox("sb-0000000000000000").unwrap().is_none());
        assert!(store.set_sandbox_state("sb-0000000000000000", SandboxState::Ready, None, None).is_err());
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

        let out = Captured { data: b"hi\n".to_vec(), total_bytes: 3 };
        let err = Captured { data: b"ab".to_vec(), total_bytes: 900 };
        let result = ExecutionResult {
            state: ExecutionState::Exited,
            exit_code: Some(0),
            failure_reason: None,
            stdout: &out,
            stderr: &err,
        };
        store.finish_execution(&e.id, &result).unwrap();
        assert!(store.finish_execution(&e.id, &result).is_err(), "only running executions finish");

        let got = store.execution(&e.id).unwrap().unwrap();
        assert_eq!((got.state, got.exit_code), (ExecutionState::Exited, Some(0)));
        assert_eq!(got.stdout, out);
        assert!(got.stderr.truncated());
        assert!(got.finished_at_ms.is_some());

        let recent = store.recent_executions(&s.id, 10).unwrap();
        assert_eq!(recent.len(), 1);
        assert!(recent[0].stdout.data.is_empty(), "lists leave output data out");
        assert_eq!(recent[0].stdout.total_bytes, 3);
    }

    #[test]
    fn executions_need_their_sandbox() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.insert_execution(&execution("sb-0000000000000000")).is_err());
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
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
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
        assert!(Store::init(conn).is_err());
    }
}
