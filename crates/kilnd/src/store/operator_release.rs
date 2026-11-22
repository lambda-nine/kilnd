//! Schema 17: the operator's release of an ambiguous reservation (`kilnd
//! release-ambiguous`). A FAILED legacy create with no backend ID and
//! `allocation_ambiguous` certainty stays charged because nothing kilnd can observe
//! proves its allocation absent. The operator proves it instead, with kilnd and
//! kilnd-helper stopped: the startup reconciliation pass, a complete kiln inventory
//! and a scan of kiln's runs directory, all clean. The release is the insert of one append-only audit row,
//! whose own trigger moves the row to `legacy_release = 'operator_attested'` in the
//! same statement. Nothing else can set that tag: no kilnd transition derives it, the
//! CHECK allows it only on such a row, and an UPDATE or INSERT that writes it without
//! its audit row aborts.
//!
//! Like schemas 8-16, the triggers are defense in depth against malformed direct SQL
//! by a writer with the database's own file authority, not a tamperproof ledger.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{SANDBOX_COLUMNS, Store, audit_accounting, sandbox_row, settle_unsettled};
use crate::model::{
    AccountingRegime, CreateCertainty, LegacyRelease, ReservationRelease, ResourceReservation,
    Sandbox, SandboxState, now_ms,
};

/// The longest operator reason the audit row keeps, in bytes.
pub const MAX_RELEASE_REASON_BYTES: usize = 512;

/// Schema 8's legacy-release CHECK, as every schema 8-16 database stores it (the fresh
/// path builds it too, so there is exactly one form), and the schema 17 CHECK.
const V16_LEGACY_RELEASE_CHECK: &str = "OR (legacy_release = 'definitely_not_created' AND state = 'failed' AND backend_id IS NULL AND create_certainty = 'definitely_not_created')),";
const V17_LEGACY_RELEASE_CHECK: &str = "OR (legacy_release = 'definitely_not_created' AND state = 'failed' AND backend_id IS NULL AND create_certainty = 'definitely_not_created')
        OR (legacy_release = 'operator_attested' AND state = 'failed' AND backend_id IS NULL AND create_certainty = 'allocation_ambiguous' AND accounting_kind = 'legacy')),";

const MIGRATE_V17: &str = "
CREATE TABLE operator_releases (
    sandbox_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(sandbox_id) = 'text' AND length(CAST(sandbox_id AS BLOB)) BETWEEN 1 AND 64 AND sandbox_id NOT GLOB '*[^!-~]*'),
    owner_uid INTEGER NOT NULL CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN 0 AND 4294967295),
    released_sandboxes INTEGER NOT NULL CHECK (typeof(released_sandboxes) = 'integer' AND released_sandboxes = 1),
    released_host_cpu_millis INTEGER NOT NULL CHECK (typeof(released_host_cpu_millis) = 'integer' AND released_host_cpu_millis >= 0),
    released_memory_bytes INTEGER NOT NULL CHECK (typeof(released_memory_bytes) = 'integer' AND released_memory_bytes >= 0),
    released_pids INTEGER NOT NULL CHECK (typeof(released_pids) = 'integer' AND released_pids >= 0),
    released_disk_bytes INTEGER NOT NULL CHECK (typeof(released_disk_bytes) = 'integer' AND released_disk_bytes >= 0),
    released_virtual_cpu_slots INTEGER NOT NULL CHECK (typeof(released_virtual_cpu_slots) = 'integer' AND released_virtual_cpu_slots >= 0),
    released_host_pids INTEGER NOT NULL CHECK (typeof(released_host_pids) = 'integer' AND released_host_pids >= 0),
    operator_uid INTEGER NOT NULL CHECK (typeof(operator_uid) = 'integer' AND operator_uid BETWEEN 0 AND 4294967295),
    released_at_ms INTEGER NOT NULL CHECK (typeof(released_at_ms) = 'integer'),
    reason TEXT NOT NULL CHECK (typeof(reason) = 'text' AND length(CAST(reason AS BLOB)) BETWEEN 1 AND 512 AND reason NOT GLOB '*[^ -~]*' AND trim(reason) != ''),
    inventory_sha256 TEXT NOT NULL CHECK (typeof(inventory_sha256) = 'text' AND length(inventory_sha256) = 64 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*')
) WITHOUT ROWID;
CREATE TRIGGER operator_releases_no_replace BEFORE INSERT ON operator_releases
WHEN EXISTS (SELECT 1 FROM operator_releases WHERE sandbox_id = NEW.sandbox_id)
BEGIN SELECT RAISE(ABORT, 'an operator release is recorded once'); END;
CREATE TRIGGER operator_releases_eligible BEFORE INSERT ON operator_releases
WHEN NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.sandbox_id
    AND accounting_kind = 'legacy' AND state = 'failed' AND backend_id IS NULL
    AND create_certainty = 'allocation_ambiguous' AND legacy_release IS NULL
    AND owner_uid = NEW.owner_uid
    AND reserved_host_cpu_millis = NEW.released_host_cpu_millis
    AND reserved_memory_bytes = NEW.released_memory_bytes
    AND reserved_pids = NEW.released_pids
    AND reserved_disk_bytes = NEW.released_disk_bytes
    AND reserved_virtual_cpu_slots = NEW.released_virtual_cpu_slots
    AND reserved_host_pids = NEW.released_host_pids)
BEGIN SELECT RAISE(ABORT, 'an operator release names a charged ambiguous FAILED legacy row with no backend ID, with its owner and exact charges'); END;
CREATE TRIGGER operator_releases_release AFTER INSERT ON operator_releases
BEGIN
    UPDATE sandboxes SET legacy_release = 'operator_attested', updated_at_ms = NEW.released_at_ms
        WHERE id = NEW.sandbox_id;
    SELECT RAISE(ABORT, 'an operator release releases its row in its own statement')
        WHERE NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.sandbox_id AND legacy_release = 'operator_attested');
END;
CREATE TRIGGER operator_releases_no_update BEFORE UPDATE ON operator_releases
BEGIN SELECT RAISE(ABORT, 'the operator release audit is append-only'); END;
CREATE TRIGGER operator_releases_no_delete BEFORE DELETE ON operator_releases
BEGIN SELECT RAISE(ABORT, 'the operator release audit is append-only'); END;
CREATE TRIGGER sandboxes_operator_release_audited BEFORE UPDATE ON sandboxes
WHEN NEW.legacy_release IS 'operator_attested' AND OLD.legacy_release IS NOT 'operator_attested'
    AND NOT EXISTS (SELECT 1 FROM operator_releases WHERE sandbox_id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'an operator release is written only by its audit row'); END;
CREATE TRIGGER sandboxes_operator_release_insert BEFORE INSERT ON sandboxes
WHEN NEW.legacy_release IS 'operator_attested'
    OR EXISTS (SELECT 1 FROM operator_releases WHERE sandbox_id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'an operator release is written only by its audit row, for the one row that had its ID'); END;
PRAGMA user_version = 17;";

/// Schema 17. The legacy-release CHECK is part of `sandboxes`' own definition, so it is
/// widened in place by SQLite's documented procedure for a change that no stored row
/// can violate (<https://www.sqlite.org/lang_altertable.html#otheralter>): a new
/// disjunct only admits more. The old text must be there exactly once, the schema
/// cookie advances so every statement reparses, and an integrity check runs before
/// the migration's one transaction can commit. Rebuilding `sandboxes` instead would
/// have to recreate every trigger, index and foreign key schemas 8-16 attached to it.
pub(super) fn migrate_v17(tx: &Transaction<'_>) -> Result<()> {
    let sql: String = tx.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'sandboxes'",
        [],
        |r| r.get(0),
    )?;
    if sql.matches(V16_LEGACY_RELEASE_CHECK).count() != 1 || sql.contains("operator_attested") {
        bail!(
            "the sandboxes table does not have schema 16's legacy-release CHECK; refusing to migrate to schema 17"
        );
    }
    let widened = sql.replacen(V16_LEGACY_RELEASE_CHECK, V17_LEGACY_RELEASE_CHECK, 1);
    let cookie: i64 = tx.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
    tx.execute_batch("PRAGMA writable_schema = ON")?;
    let changed = tx.execute(
        "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'sandboxes' AND sql = ?2",
        params![widened, sql],
    );
    let bumped = tx.execute_batch(&format!("PRAGMA schema_version = {}", cookie + 1));
    tx.execute_batch("PRAGMA writable_schema = OFF")?;
    if changed? != 1 {
        bail!("schema 17 could not widen the legacy-release CHECK");
    }
    bumped?;
    let integrity: Vec<String> = tx
        .prepare("PRAGMA integrity_check")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if integrity != ["ok"] {
        bail!("schema 17's CHECK change failed the integrity check: {integrity:?}");
    }
    tx.execute_batch(MIGRATE_V17)?;
    Ok(())
}

/// Why a row can't be released by an operator, or `None` when it can: exactly the
/// rows the audit trigger accepts.
pub fn operator_release_refusal(s: &Sandbox) -> Option<String> {
    let why = if s.accounting.regime != AccountingRegime::Legacy {
        "it is an absence-fenced allocation, released only by its absence receipt".into()
    } else if s.state != SandboxState::Failed {
        format!("it is {}, not FAILED", s.state.as_str().to_uppercase())
    } else if let Some(backend) = &s.backend_id {
        format!("it has backend ID {backend}; Delete removes that exact backend")
    } else if s.create_certainty != CreateCertainty::AllocationAmbiguous {
        "its create was definitely not created; it is already released".into()
    } else if !s.is_charged() {
        "it is already released".into()
    } else {
        return None;
    };
    Some(why)
}

/// What the operator states for one release.
#[derive(Clone, Debug)]
pub struct OperatorRelease<'a> {
    pub sandbox_id: &'a str,
    pub operator_uid: u32,
    pub reason: &'a str,
    /// Hex SHA-256 of the canonical inventory the release was proved against.
    pub inventory_sha256: &'a str,
}

/// The release as committed: the row's owner and every charge it gave back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorReleased {
    pub owner_uid: u32,
    pub reservation: ResourceReservation,
}

/// Why a release committed nothing.
#[derive(Debug)]
pub enum OperatorReleaseError {
    NoSandbox,
    Ineligible(String),
    Store(anyhow::Error),
}

impl std::fmt::Display for OperatorReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSandbox => write!(f, "no such sandbox"),
            Self::Ineligible(why) => write!(f, "{why}"),
            Self::Store(e) => write!(f, "{e:#}"),
        }
    }
}

/// A reason the audit row can keep: 1 to 512 printable ASCII bytes, not all spaces.
pub fn valid_release_reason(reason: &str) -> std::result::Result<(), String> {
    if reason.is_empty() || reason.len() > MAX_RELEASE_REASON_BYTES {
        return Err(format!(
            "--reason must be 1 to {MAX_RELEASE_REASON_BYTES} bytes"
        ));
    }
    if !reason.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err("--reason must be printable ASCII, with no control characters".into());
    }
    if reason.trim().is_empty() {
        return Err("--reason must say why".into());
    }
    Ok(())
}

impl Store {
    /// The release itself, in one IMMEDIATE transaction after the accounting audit:
    /// recheck the row, insert its audit row (whose trigger releases it), and confirm
    /// the reloaded row is released and uncharged before committing.
    pub fn release_ambiguous_by_operator(
        &self,
        release: &OperatorRelease<'_>,
    ) -> std::result::Result<OperatorReleased, OperatorReleaseError> {
        valid_release_reason(release.reason).map_err(OperatorReleaseError::Ineligible)?;
        let mut conn = self.conn();
        let store = |e: anyhow::Error| OperatorReleaseError::Store(e);
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| store(e.into()))?;
        if audit_accounting(&tx).map_err(store)? {
            return Err(store(anyhow::anyhow!(
                "degraded accounting: quarantined release evidence"
            )));
        }
        settle_unsettled(&tx).map_err(store)?;
        let load = |tx: &Transaction<'_>| -> Result<Option<Sandbox>> {
            tx.query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [release.sandbox_id],
                sandbox_row,
            )
            .optional()?
            .transpose()
        };
        let row = load(&tx)
            .map_err(store)?
            .ok_or(OperatorReleaseError::NoSandbox)?;
        if let Some(why) = operator_release_refusal(&row) {
            return Err(OperatorReleaseError::Ineligible(why));
        }
        let r = row.accounting.reservation;
        let amount = |n: u64| i64::try_from(n).context("reservation exceeds SQLite's range");
        (|| -> Result<()> {
            tx.execute(
                "INSERT INTO operator_releases (sandbox_id, owner_uid, released_sandboxes,
                     released_host_cpu_millis, released_memory_bytes, released_pids, released_disk_bytes,
                     released_virtual_cpu_slots, released_host_pids, operator_uid, released_at_ms,
                     reason, inventory_sha256)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    row.id,
                    row.owner_uid,
                    amount(r.host_cpu_millis)?,
                    amount(r.memory_bytes)?,
                    amount(r.pids)?,
                    amount(r.disk_bytes)?,
                    amount(r.virtual_cpu_slots)?,
                    amount(r.host_pids)?,
                    release.operator_uid,
                    now_ms(),
                    release.reason,
                    release.inventory_sha256,
                ],
            )?;
            Ok(())
        })()
        .map_err(store)?;
        let released = load(&tx)
            .map_err(store)?
            .ok_or(OperatorReleaseError::NoSandbox)?;
        if released.is_charged()
            || released.accounting.release
                != ReservationRelease::Legacy(LegacyRelease::OperatorAttested)
        {
            return Err(store(anyhow::anyhow!(
                "sandbox {}: the audit row did not release it",
                row.id
            )));
        }
        tx.commit().map_err(|e| store(e.into()))?;
        Ok(OperatorReleased {
            owner_uid: row.owner_uid,
            reservation: r,
        })
    }

    /// How many operator releases this database has ever recorded.
    pub fn operator_release_count(&self) -> Result<u64> {
        let n: i64 = self.audited_read(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM operator_releases", [], |r| r.get(0))?)
        })?;
        Ok(u64::try_from(n)?)
    }
}

/// For migration tests: a schema 17 database put back to exactly schema 16 (an empty
/// audit table and its triggers dropped, the CHECK narrowed again by the same
/// procedure), so an older database can be built with this Store's own API.
#[cfg(test)]
pub(crate) fn undo_v17(conn: &rusqlite::Connection) {
    let tx = conn.unchecked_transaction().unwrap();
    let audited: i64 = tx
        .query_row("SELECT COUNT(*) FROM operator_releases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(audited, 0, "schema 16 has no operator releases");
    tx.execute_batch(
        "DROP TRIGGER sandboxes_operator_release_audited;
         DROP TRIGGER sandboxes_operator_release_insert;
         DROP TABLE operator_releases;",
    )
    .unwrap();
    let sql: String = tx
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'sandboxes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sql.matches(V17_LEGACY_RELEASE_CHECK).count(), 1);
    let narrowed = sql.replacen(V17_LEGACY_RELEASE_CHECK, V16_LEGACY_RELEASE_CHECK, 1);
    let cookie: i64 = tx
        .query_row("PRAGMA schema_version", [], |r| r.get(0))
        .unwrap();
    tx.execute_batch("PRAGMA writable_schema = ON").unwrap();
    tx.execute(
        "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'sandboxes'",
        [narrowed],
    )
    .unwrap();
    tx.execute_batch(&format!(
        "PRAGMA schema_version = {}; PRAGMA writable_schema = OFF; PRAGMA user_version = 16;",
        cookie + 1
    ))
    .unwrap();
    tx.commit().unwrap();
}
