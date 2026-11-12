//! Schema 15 (checkpoint milestone C4): migration from a real schema 14 database,
//! zero charge when empty, the shared admission and its concurrency, capture keys,
//! fork pins and provenance, and SQL tampering against the triggers and the audits.

use super::*;
use crate::checkpoint::{CompleteFact, EVIDENCE_VERSION, Evidence};
use crate::expiry::ManualClock;
use crate::model::{Network, new_id};
use rusqlite::types::Value;
use std::collections::BTreeMap;

const GIB: u64 = 1 << 30;
const SCHEMA14: &str = include_str!("fixtures/schema14.sql");

fn spec() -> SandboxSpec {
    SandboxSpec {
        image: "alpine".into(),
        memory_bytes: 256 << 20,
        cpu_millis: 500,
        pids: 64,
        disk_bytes: 2 * GIB,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec!["/workspace".into(), "/data".into()],
        labels: BTreeMap::new(),
    }
}

fn row(state: SandboxState, owner_uid: u32) -> Sandbox {
    let now = now_ms();
    let spec = spec();
    Sandbox {
        id: new_id("sb"),
        state,
        accounting: SandboxAccounting::legacy(&spec, ""),
        spec,
        backend: "kiln".into(),
        backend_id: None,
        created_at_ms: now,
        updated_at_ms: now,
        deleted_at_ms: None,
        failure_reason: None,
        create_certainty: CreateCertainty::AllocationAmbiguous,
        owner_uid,
        lifecycle: Default::default(),
    }
}

fn kiln_id() -> String {
    Id128::random().to_string()[..16].to_string()
}

fn image_sha() -> Digest {
    Digest::of(b"alpine image tree")
}

fn roomy() -> SandboxBudgets {
    SandboxBudgets {
        sandboxes: 10_000,
        memory_bytes: u64::MAX,
        pids: u64::MAX,
        disk_bytes: 1 << 50,
        host_cpu_millis: u64::MAX,
        virtual_cpu_slots: u64::MAX,
        host_pids: u64::MAX,
    }
}

fn store() -> (Store, ManualClock) {
    let store = Store::open_in_memory().unwrap();
    let clock = ManualClock::default();
    store.set_clock(std::sync::Arc::new(clock.clone()));
    (store, clock)
}

/// A READY, checkpoint-capable source.
fn source(store: &Store, owner_uid: u32) -> Sandbox {
    let mut s = row(SandboxState::Ready, owner_uid);
    s.backend_id = Some(kiln_id());
    s.lifecycle.image_identity = Some(ImageIdentity {
        content_sha256: image_sha(),
        checkpoint_format_version: 1,
    });
    store.insert_sandbox(&s).unwrap();
    s
}

fn dispatch() -> HelperDispatch {
    HelperDispatch {
        operation: Id128::random(),
        helper_epoch: Id128::random(),
        boot_id: Id128::random(),
    }
}

fn new_checkpoint(source: &Sandbox, owner_uid: u32, r: u64) -> NewCheckpoint {
    NewCheckpoint {
        id: CheckpointId::random(),
        owner_uid,
        generation: 1,
        source_sandbox_id: source.id.clone(),
        capture: dispatch(),
        max_size_bytes: r,
        writable_paths: normalized_paths(&source.spec.writable_paths),
        excluded_paths: vec![
            "/dev".into(),
            "/dev/shm".into(),
            "/proc".into(),
            "/sys".into(),
        ],
        expiry: CheckpointExpiry {
            lifetime_ms: 86_400_000,
            idle_ms: 3_600_000,
        },
        request_id: None,
    }
}

fn reserve(store: &Store, new: &NewCheckpoint) -> ReserveCheckpoint {
    store
        .reserve_checkpoint(new, &CheckpointBudgets::default(), roomy(), None)
        .unwrap()
}

fn inserted(outcome: ReserveCheckpoint) -> Checkpoint {
    match outcome {
        ReserveCheckpoint::Inserted(c) => *c,
        other => panic!("{other:?}"),
    }
}

/// The helper's fact about one dispatch: its nonce, from its helper epoch and boot.
fn evidence(c: &Checkpoint, dispatch: &HelperDispatch, fact: Fact) -> SealedEvidence {
    Evidence {
        version: EVIDENCE_VERSION,
        instance: c.instance_id,
        checkpoint: c.id.clone(),
        generation: c.generation,
        operation: dispatch.operation,
        helper_epoch: dispatch.helper_epoch,
        boot_id: dispatch.boot_id,
        fact,
    }
    .seal()
    .unwrap()
}

fn complete(c: &Checkpoint, charge: u64) -> SealedEvidence {
    evidence(
        c,
        &c.capture,
        Fact::Complete(Box::new(CompleteFact {
            source: c.source_backend_id.clone(),
            content_sha256: Digest::of(c.id.as_str().as_bytes()),
            binding_sha256: Digest::of(b"binding"),
            image: c.image.clone(),
            image_sha256: c.image_content_sha256,
            entries: 7,
            logical_bytes: charge / 2,
            allocated_bytes: charge / 2,
            charge_bytes: charge,
            limit_bytes: c.max_size_bytes,
        })),
    )
}

fn absent(c: &Checkpoint, removal: &HelperDispatch) -> SealedEvidence {
    evidence(c, removal, Fact::Absent { existed: true })
}

fn ready(store: &Store, source: &Sandbox, owner_uid: u32, charge: u64) -> Checkpoint {
    let c = inserted(reserve(store, &new_checkpoint(source, owner_uid, GIB)));
    match store
        .publish_checkpoint_ready(c.id.as_str(), &complete(&c, charge))
        .unwrap()
    {
        PublishCheckpoint::Published(c) => *c,
        other => panic!("{other:?}"),
    }
}

/// Removes `c` the typed way: D1 intent, the dispatched removal, D3 evidence.
fn remove(store: &Store, c: &Checkpoint) -> Checkpoint {
    store
        .publish_checkpoint_delete_intent(c.id.as_str(), DeletionReason::Requested)
        .unwrap();
    let removal = dispatch();
    assert!(
        store
            .record_checkpoint_removal(c.id.as_str(), &removal)
            .unwrap()
    );
    match store
        .settle_checkpoint_absence(c.id.as_str(), &absent(c, &removal))
        .unwrap()
    {
        SettleAbsence::Released(c) => *c,
        other => panic!("{other:?}"),
    }
}

fn fork_row(c: &Checkpoint, owner_uid: u32) -> Sandbox {
    let mut s = row(SandboxState::Creating, owner_uid);
    s.spec.writable_paths = vec!["/data".into(), "/workspace".into(), "/data".into()];
    s.lifecycle.from_checkpoint = Some(CheckpointProvenance {
        checkpoint: c.id.clone(),
        content_sha256: c.seal.as_ref().unwrap().content_sha256,
    });
    s
}

fn disk(store: &Store) -> u64 {
    store.sandbox_resources().unwrap().disk_bytes
}

fn usage(store: &Store, uid: u32) -> CheckpointUsage {
    store.checkpoint_usage(uid).unwrap()
}

fn table_snapshot(conn: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    let columns = stmt.column_count();
    stmt.query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    tmp
}

fn private_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The schema 14 fixture, written by kilnd `2562a53`'s own Store API (legacy rows
/// in every state, keyed creates, a released key, default env, an execution, fenced
/// rows charged and released, settled and unsettled releases), loaded into `dir`.
fn schema14_database(dir: &Path) {
    let conn = Connection::open(dir.join("kilnd.db")).unwrap();
    conn.execute_batch(SCHEMA14).unwrap();
    assert_eq!(
        conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        14
    );
    drop(conn);
    private_file(&dir.join("kilnd.db"));
}

/// Everything schema 14 holds that schema 15 must keep exactly: every table's rows,
/// the membership aggregates and their recomputation, and the charge predicates.
#[derive(Debug, PartialEq)]
struct Schema14Facts {
    tables: Vec<(String, Vec<Vec<Value>>)>,
    all_membership: Membership,
    settled_membership: Membership,
    charged: Vec<Vec<Value>>,
}

const SCHEMA14_TABLES: [&str; 9] = [
    "history_sequence",
    "daemon_identity",
    "release_evidence",
    "executions",
    "create_request_counts",
    "reservation_unsettled",
    "sandboxes",
    "create_requests",
    "reservation_membership",
];

fn schema14_facts(
    conn: &Connection,
    sandbox_columns: usize,
    request_columns: usize,
) -> Schema14Facts {
    let truncate =
        |rows: Vec<Vec<Value>>, n: usize| rows.into_iter().map(|r| r[..n].to_vec()).collect();
    Schema14Facts {
        tables: SCHEMA14_TABLES
            .iter()
            .map(|t| {
                let rows = table_snapshot(conn, t);
                let rows = match *t {
                    "sandboxes" => truncate(rows, sandbox_columns),
                    "create_requests" => truncate(rows, request_columns),
                    _ => rows,
                };
                (t.to_string(), rows)
            })
            .collect(),
        all_membership: all_membership(conn).unwrap(),
        settled_membership: settled_membership(conn).unwrap(),
        // Schema 7's predicate and the stored vector: the legacy charge, row by row.
        charged: {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT id, reserved_memory_bytes, reserved_disk_bytes, reserved_pids, reserved_host_cpu_millis,
                         reserved_virtual_cpu_slots, reserved_host_pids FROM sandboxes WHERE {RESERVED_SANDBOX_WHERE} ORDER BY id"
                ))
                .unwrap();
            let columns = stmt.column_count();
            stmt.query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
                .unwrap()
                .map(Result::unwrap)
                .collect()
        },
    }
}

fn column_count(conn: &Connection, table: &str) -> usize {
    conn.prepare(&format!("SELECT * FROM {table}"))
        .unwrap()
        .column_count()
}

/// The migration proof, for the fixture here and for a copy of a live database in
/// the VM: every schema 14 row, digest, aggregate and charge predicate unchanged;
/// schema 15's columns empty on history; zero checkpoint charge.
fn assert_migration_preserves(dir: &Path) {
    let before_conn = Connection::open(dir.join("kilnd.db")).unwrap();
    assert_eq!(
        before_conn
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        14
    );
    let sandbox_columns = column_count(&before_conn, "sandboxes");
    let request_columns = column_count(&before_conn, "create_requests");
    let before = schema14_facts(&before_conn, sandbox_columns, request_columns);
    drop(before_conn);
    let store = Store::reopen_after_restart(dir);
    let conn = store.conn();
    assert_eq!(
        conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        15
    );
    let after = schema14_facts(&conn, sandbox_columns, request_columns);
    // The startup full audit settles anything released since the last one, exactly as
    // schema 14's own startup does: compare the settled aggregate to a recount.
    let mut expected = before;
    expected
        .tables
        .retain(|(t, _)| t != "reservation_membership" && t != "reservation_unsettled");
    let mut actual = after;
    actual
        .tables
        .retain(|(t, _)| t != "reservation_membership" && t != "reservation_unsettled");
    assert_eq!(
        actual.tables, expected.tables,
        "every schema 14 row is unchanged"
    );
    assert_eq!(
        actual.all_membership, expected.all_membership,
        "membership of every row"
    );
    assert_eq!(actual.settled_membership, expected.settled_membership);
    assert_eq!(
        actual.charged, expected.charged,
        "schema 7's charge predicate"
    );
    let (all, settled) = stored_membership(&conn).unwrap().unwrap();
    assert_eq!(
        all, expected.all_membership,
        "the stored total is schema 14's"
    );
    assert_eq!(settled, expected.settled_membership);
    // New columns are empty on history.
    let new_columns: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sandboxes WHERE from_checkpoint IS NOT NULL OR checkpoint_content_sha256 IS NOT NULL
                 OR image_content_sha256 IS NOT NULL OR checkpoint_format_version IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(new_columns, 0);
    let versions: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM create_requests WHERE digest_version IS NOT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(versions, 0, "every existing request digest is version 1");
    for table in [
        "checkpoints",
        "checkpoint_evidence",
        "checkpoint_pins",
        "checkpoint_requests",
        "checkpoint_unsettled",
    ] {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
    assert_eq!(
        table_snapshot(&conn, "checkpoint_counts"),
        vec![vec![
            Value::Integer(-1),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0)
        ]]
    );
    assert_eq!(
        stored_checkpoint_membership_for_tests(&conn),
        (Membership::default(), Membership::default())
    );
    drop(conn);
    // Zero added charge: the totals are schema 14's own predicate, summed.
    let mut sum = SandboxResources::default();
    for r in &expected.charged {
        let v = |i: usize| match r[i] {
            Value::Integer(n) => u64::try_from(n).unwrap(),
            _ => panic!(),
        };
        sum = sum
            .checked_add(SandboxResources {
                sandboxes: 1,
                memory_bytes: v(1),
                disk_bytes: v(2),
                pids: v(3),
                host_cpu_millis: v(4),
                virtual_cpu_slots: v(5),
                host_pids: v(6),
            })
            .unwrap();
    }
    let (resources, degraded) = store.accounting_snapshot().unwrap();
    assert_eq!(resources, sum, "an empty checkpoint table adds zero");
    assert!(!degraded);
    assert_eq!(
        store.checkpoint_usage(0).unwrap(),
        CheckpointUsage::default()
    );
}

fn stored_checkpoint_membership_for_tests(conn: &Connection) -> (Membership, Membership) {
    let (count, sum, settled_count, settled_sum): (i64, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT row_count, row_sum, settled_count, settled_sum FROM checkpoint_membership WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    (
        Membership {
            count,
            sum: sum.try_into().unwrap(),
        },
        Membership {
            count: settled_count,
            sum: settled_sum.try_into().unwrap(),
        },
    )
}

#[test]
fn schema15_from_a_real_schema14_database_keeps_every_digest_and_charge() {
    let tmp = private_dir();
    schema14_database(tmp.path());
    assert_migration_preserves(tmp.path());
    // The fixture has what it claims: charged and released rows of both regimes, keys,
    // a released key, and an unsettled release.
    let store = Store::reopen_after_restart(tmp.path());
    let rows = store.sandboxes(true).unwrap();
    assert!(rows.len() >= 15, "{}", rows.len());
    assert!(rows.iter().any(|r| r.is_fenced() && r.is_charged()));
    assert!(rows.iter().any(|r| r.is_fenced() && !r.is_charged()));
    assert!(
        rows.iter()
            .any(|r| r.lifecycle.request_id_released_at_ms.is_some())
    );
    assert_eq!(store.create_request_counts(1000).unwrap().uid, 2);
    let (digest, keyed) = store.create_request(1000, "key-ready").unwrap().unwrap();
    assert_eq!(keyed.state, SandboxState::Ready);
    assert_eq!(digest, Digest::of(b"request"));
}

/// The same proof for a copy of a real node's database, in a private state directory
/// (VM phase): `KILND_C4_SCHEMA14_COPY=/private/dir` holding `kilnd.db` at schema 14.
#[test]
#[ignore]
fn c4_vm_migrate_a_copy_of_a_live_schema14_database() {
    let dir = PathBuf::from(std::env::var("KILND_C4_SCHEMA14_COPY").unwrap());
    let before = Connection::open(dir.join("kilnd.db")).unwrap();
    let rows: i64 = before
        .query_row("SELECT COUNT(*) FROM sandboxes", [], |r| r.get(0))
        .unwrap();
    let charged: i64 = before
        .query_row(
            &format!("SELECT COUNT(*) FROM sandboxes WHERE {RESERVED_SANDBOX_WHERE}"),
            [],
            |r| r.get(0),
        )
        .unwrap();
    let records: i64 = before
        .query_row("SELECT COUNT(*) FROM create_requests", [], |r| r.get(0))
        .unwrap();
    drop(before);
    println!("live copy: {rows} sandbox rows, {charged} charged, {records} create request records");
    assert_migration_preserves(&dir);
    println!("migrated to schema 15: every schema 14 row, aggregate and charge unchanged");
}

#[test]
fn schema15_migrated_from_14_is_the_fresh_schema() {
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
    let tmp = private_dir();
    schema14_database(tmp.path());
    let migrated = Store::reopen_after_restart(tmp.path());
    assert_eq!(schema_sql(&migrated.conn()), schema_sql(&fresh.conn()));
}

/// Design 9: the migration audits the schema 14 membership before it changes
/// anything. A mismatch refuses startup and leaves the database at schema 14.
#[test]
fn schema15_refuses_to_migrate_a_mismatched_schema14_database() {
    let tmp = private_dir();
    schema14_database(tmp.path());
    let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
        false,
    )
    .unwrap();
    conn.execute(
        "UPDATE sandboxes SET reserved_disk_bytes = 1 WHERE id = (SELECT MIN(id) FROM sandboxes)",
        [],
    )
    .unwrap();
    drop(conn);
    let error = format!("{:#}", Store::open(tmp.path()).err().unwrap());
    assert!(
        error.contains("schema 14 reservation membership does not match"),
        "{error}"
    );
    let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
    assert_eq!(
        conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        14
    );
    let tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'checkpoint%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "nothing of schema 15 was committed");
}

#[test]
fn a_newer_schema_is_refused() {
    let tmp = private_dir();
    drop(Store::open(tmp.path()).unwrap());
    let conn = Connection::open(tmp.path().join("kilnd.db")).unwrap();
    conn.pragma_update(None, "user_version", 16).unwrap();
    drop(conn);
    let error = format!("{:#}", Store::open(tmp.path()).err().unwrap());
    assert!(
        error.contains("schema version 16 is newer than this kilnd (15)"),
        "{error}"
    );
}

#[test]
fn empty_checkpoint_tables_add_zero_charge() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let mut other = row(SandboxState::Creating, 1000);
    other.spec.disk_bytes = 3 * GIB;
    other.accounting = SandboxAccounting::legacy(&other.spec, "");
    store.insert_sandbox(&other).unwrap();
    assert_eq!(disk(&store), s.accounting.reservation.disk_bytes + 3 * GIB);
    assert_eq!(usage(&store, 1000), CheckpointUsage::default());
}

/// Design 6 and 9.1: R from the CAPTURING insert, S from the READY seal, through
/// DELETING, and nothing only after ABSENT evidence of the recorded removal. The node
/// disk total every sandbox admission and Health use includes it.
#[test]
fn a_checkpoint_is_charged_r_then_s_until_its_absence_is_proved() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let base = disk(&store);
    let c = inserted(reserve(&store, &new_checkpoint(&s, 1000, GIB)));
    assert_eq!(c.state, CheckpointState::Capturing);
    assert_eq!(c.source_backend_id, s.backend_id.clone().unwrap());
    assert_eq!(c.instance_id, store.identity().unwrap().instance_id);
    assert_eq!(c.image, "alpine");
    assert_eq!(
        c.writable_paths,
        vec!["/data".to_string(), "/workspace".to_string()]
    );
    assert_eq!(disk(&store), base + GIB);
    let u = usage(&store, 1000);
    assert_eq!(
        (u.uid.live, u.uid.charged_bytes, u.node.live, u.node.records),
        (1, GIB, 1, 1)
    );
    let published = match store
        .publish_checkpoint_ready(c.id.as_str(), &complete(&c, 40 << 20))
        .unwrap()
    {
        PublishCheckpoint::Published(c) => *c,
        other => panic!("{other:?}"),
    };
    assert_eq!(published.state, CheckpointState::Ready);
    assert_eq!(published.seal.as_ref().unwrap().charge_bytes, 40 << 20);
    assert!(published.ready_at_ms.is_some());
    assert_eq!(disk(&store), base + (40 << 20));
    assert_eq!(usage(&store, 1000).node.charged_bytes, 40 << 20);
    // Stored evidence reloads through the decoder.
    let sealed = store
        .checkpoint_evidence(&published.seal.as_ref().unwrap().evidence_id)
        .unwrap()
        .unwrap();
    assert!(
        sealed
            .verify_complete(&published.capture_binding(), published.capture.dispatched())
            .is_ok()
    );
    // DELETING keeps the charge; only the removal's ABSENT evidence releases it.
    let deleting = store
        .publish_checkpoint_delete_intent(c.id.as_str(), DeletionReason::Requested)
        .unwrap()
        .unwrap();
    assert_eq!(deleting.state, CheckpointState::Deleting);
    assert_eq!(disk(&store), base + (40 << 20));
    // Without a recorded removal there is nothing to match.
    assert!(matches!(
        store
            .settle_checkpoint_absence(c.id.as_str(), &absent(&c, &dispatch()))
            .unwrap(),
        SettleAbsence::Refused(_)
    ));
    let removal = dispatch();
    assert!(
        store
            .record_checkpoint_removal(c.id.as_str(), &removal)
            .unwrap()
    );
    // Another removal's absence, or a COMPLETE fact, is not this removal's.
    assert!(matches!(
        store
            .settle_checkpoint_absence(c.id.as_str(), &absent(&c, &dispatch()))
            .unwrap(),
        SettleAbsence::Refused(_)
    ));
    assert!(matches!(
        store
            .settle_checkpoint_absence(c.id.as_str(), &complete(&c, 40 << 20))
            .unwrap(),
        SettleAbsence::Refused(_)
    ));
    assert_eq!(disk(&store), base + (40 << 20));
    let proof = absent(&c, &removal);
    let deleted = match store
        .settle_checkpoint_absence(c.id.as_str(), &proof)
        .unwrap()
    {
        SettleAbsence::Released(c) => *c,
        other => panic!("{other:?}"),
    };
    assert_eq!(deleted.state, CheckpointState::Deleted);
    assert_eq!(deleted.charge_bytes(), 0);
    assert_eq!(disk(&store), base);
    let u = usage(&store, 1000);
    assert_eq!(
        (u.node.live, u.node.charged_bytes, u.node.records),
        (0, 0, 1)
    );
    assert!(matches!(
        store
            .settle_checkpoint_absence(c.id.as_str(), &proof)
            .unwrap(),
        SettleAbsence::AlreadyReleased(_)
    ));
}

#[test]
fn a_failed_capture_stays_charged_r_until_its_absence_then_may_be_deleted() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let base = disk(&store);
    let c = inserted(reserve(&store, &new_checkpoint(&s, 1000, GIB)));
    // FAILED needs a failure first, then absence; nothing is released before.
    let removal = dispatch();
    assert!(
        store
            .record_checkpoint_removal(c.id.as_str(), &removal)
            .unwrap()
    );
    assert!(matches!(
        store
            .settle_checkpoint_absence(c.id.as_str(), &absent(&c, &removal))
            .unwrap(),
        SettleAbsence::NotReleasable(CheckpointState::Capturing)
    ));
    assert!(
        store
            .record_checkpoint_failure(
                c.id.as_str(),
                Reason::LayoutUnsupported,
                "a FIFO under /workspace",
                false
            )
            .unwrap()
    );
    assert!(
        !store
            .record_checkpoint_failure(c.id.as_str(), Reason::Io, "again", false)
            .unwrap()
    );
    assert_eq!(disk(&store), base + GIB);
    let failed = match store
        .settle_checkpoint_absence(c.id.as_str(), &absent(&c, &removal))
        .unwrap()
    {
        SettleAbsence::Released(c) => *c,
        other => panic!("{other:?}"),
    };
    assert_eq!(failed.state, CheckpointState::Failed);
    assert_eq!(
        failed.failure.as_ref().unwrap().token,
        "checkpoint_layout_unsupported"
    );
    assert_eq!(disk(&store), base);
    assert!(store.delete_failed_checkpoint(c.id.as_str()).unwrap());
    let deleted = store.checkpoint(c.id.as_str()).unwrap().unwrap();
    assert_eq!(
        (deleted.state, deleted.deletion_reason),
        (CheckpointState::Deleted, Some(DeletionReason::Requested))
    );
    assert_eq!(deleted.release_evidence_id, failed.release_evidence_id);
}

#[test]
fn publication_needs_this_bindings_complete_fact_and_a_ready_source() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let c = inserted(reserve(&store, &new_checkpoint(&s, 1000, GIB)));
    let other = inserted(reserve(&store, &new_checkpoint(&s, 1000, GIB)));
    for wrong in [
        complete(&other, 1 << 20),
        evidence(
            &c,
            &HelperDispatch {
                operation: Id128::random(),
                ..c.capture
            },
            complete(&c, 1 << 20).evidence.fact,
        ),
        absent(&c, &c.capture),
    ] {
        assert!(matches!(
            store
                .publish_checkpoint_ready(c.id.as_str(), &wrong)
                .unwrap(),
            PublishCheckpoint::Refused(_)
        ));
    }
    // R is the binding's: a fact for another cap is another binding.
    let mut fact = match complete(&c, 1 << 20).evidence.fact {
        Fact::Complete(f) => f,
        _ => unreachable!(),
    };
    fact.limit_bytes = 2 * GIB;
    fact.charge_bytes = 2 * GIB;
    assert!(matches!(
        store
            .publish_checkpoint_ready(
                c.id.as_str(),
                &evidence(&c, &c.capture, Fact::Complete(fact))
            )
            .unwrap(),
        PublishCheckpoint::Refused(_)
    ));
    assert_eq!(
        store.checkpoint(c.id.as_str()).unwrap().unwrap().state,
        CheckpointState::Capturing
    );
    // The source moved on: no READY (design 8.2's publication CAS).
    store
        .set_sandbox_state(&s.id, SandboxState::Deleting, None, None)
        .unwrap();
    assert_eq!(
        store
            .publish_checkpoint_ready(c.id.as_str(), &complete(&c, 1 << 20))
            .unwrap(),
        PublishCheckpoint::SourceChanged
    );
    // A delete intent wins over a later completion.
    store
        .publish_checkpoint_delete_intent(c.id.as_str(), DeletionReason::Requested)
        .unwrap();
    assert_eq!(
        store
            .publish_checkpoint_ready(c.id.as_str(), &complete(&c, 1 << 20))
            .unwrap(),
        PublishCheckpoint::NotCapturing(CheckpointState::Deleting)
    );
    assert_eq!(disk(&store), store.sandbox_resources().unwrap().disk_bytes);
}

#[test]
fn capture_admission_refuses_unready_or_unsupported_sources() {
    let (store, _) = store();
    let s = source(&store, 1000);
    // No image identity: an older sandbox can't be captured.
    let mut old = row(SandboxState::Ready, 1000);
    old.backend_id = Some(kiln_id());
    store.insert_sandbox(&old).unwrap();
    assert_eq!(
        reserve(&store, &new_checkpoint(&old, 1000, GIB)),
        ReserveCheckpoint::SourceUnavailable
    );
    let mut missing = new_checkpoint(&s, 1000, GIB);
    missing.source_sandbox_id = "sb-0000000000000000".into();
    assert_eq!(
        reserve(&store, &missing),
        ReserveCheckpoint::SourceUnavailable
    );
    store
        .set_sandbox_state(&s.id, SandboxState::Lost, None, None)
        .unwrap();
    assert_eq!(
        reserve(&store, &new_checkpoint(&s, 1000, GIB)),
        ReserveCheckpoint::SourceUnavailable
    );
    assert_eq!(usage(&store, 1000), CheckpointUsage::default());
    // The capture's compatibility record is the source's own.
    let s = source(&store, 1000);
    let mut paths = new_checkpoint(&s, 1000, GIB);
    paths.writable_paths = vec!["/other".into()];
    assert!(
        store
            .reserve_checkpoint(&paths, &CheckpointBudgets::default(), roomy(), None)
            .is_err()
    );
    // Expiry is always finite and bounded.
    for (lifetime_ms, idle_ms) in [
        (0, 3_600_000),
        (8 * 86_400_000, 3_600_000),
        (86_400_000, 25 * 3_600_000),
        (86_400_000, 9_999),
    ] {
        let mut n = new_checkpoint(&s, 1000, GIB);
        n.expiry = CheckpointExpiry {
            lifetime_ms,
            idle_ms,
        };
        assert!(
            store
                .reserve_checkpoint(&n, &CheckpointBudgets::default(), roomy(), None)
                .is_err()
        );
    }
    assert_eq!(usage(&store, 1000), CheckpointUsage::default());
}

/// Design 6.2 and 6.3: per checkpoint, per uid and per node, counts and bytes,
/// records, and the one node disk budget shared with sandbox reservations, each in
/// the admitting transaction. A refusal changes nothing.
#[test]
fn admission_enforces_every_cap_and_the_shared_disk_budget() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let t = source(&store, 1001);
    let b = CheckpointBudgets::default();
    assert_eq!(b.max_size_bytes, GIB);
    assert_eq!((b.max_per_uid, b.max_node), (32, 128));
    assert_eq!((b.max_bytes_per_uid, b.max_bytes_node), (4 * GIB, 8 * GIB));
    assert_eq!((b.max_records_per_uid, b.max_records_node), (4096, 32_768));
    // Per checkpoint: the node limit and the source's own disk.
    assert_eq!(
        reserve(&store, &new_checkpoint(&s, 1000, GIB + 4096)),
        ReserveCheckpoint::SizeLimit {
            requested: GIB + 4096,
            limit: GIB
        }
    );
    let small = CheckpointBudgets {
        max_size_bytes: 4 * GIB,
        ..b
    };
    let mut over_source = new_checkpoint(&s, 1000, 3 * GIB);
    over_source.max_size_bytes = 3 * GIB;
    assert_eq!(
        store
            .reserve_checkpoint(&over_source, &small, roomy(), None)
            .unwrap(),
        ReserveCheckpoint::SizeLimit {
            requested: 3 * GIB,
            limit: 2 * GIB
        }
    );
    // Bytes per uid: four 1 GiB captures, then refused.
    for _ in 0..4 {
        inserted(reserve(&store, &new_checkpoint(&s, 1000, GIB)));
    }
    let refused = reserve(&store, &new_checkpoint(&s, 1000, GIB));
    assert!(
        matches!(
            refused,
            ReserveCheckpoint::Exhausted(CheckpointExhausted {
                scope: "uid",
                resource: "checkpoint bytes",
                ..
            })
        ),
        "{refused:?}"
    );
    // Bytes per node: another uid fills the node's 8 GiB.
    for _ in 0..4 {
        inserted(reserve(&store, &new_checkpoint(&t, 1001, GIB)));
    }
    let u = source(&store, 1002);
    assert!(matches!(
        reserve(&store, &new_checkpoint(&u, 1002, GIB)),
        ReserveCheckpoint::Exhausted(CheckpointExhausted {
            scope: "node",
            resource: "checkpoint bytes",
            ..
        })
    ));
    assert_eq!(usage(&store, 1002).uid, CheckpointCounts::default());
    // Counts: small charges up to the per-uid count.
    let tight = CheckpointBudgets {
        max_per_uid: 2,
        max_node: 3,
        ..b
    };
    let (store, _) = self::store();
    let s = source(&store, 1000);
    let t = source(&store, 1001);
    for _ in 0..2 {
        inserted(
            store
                .reserve_checkpoint(&new_checkpoint(&s, 1000, 1 << 20), &tight, roomy(), None)
                .unwrap(),
        );
    }
    assert!(matches!(
        store
            .reserve_checkpoint(&new_checkpoint(&s, 1000, 1 << 20), &tight, roomy(), None)
            .unwrap(),
        ReserveCheckpoint::Exhausted(CheckpointExhausted {
            scope: "uid",
            resource: "checkpoints",
            ..
        })
    ));
    inserted(
        store
            .reserve_checkpoint(&new_checkpoint(&t, 1001, 1 << 20), &tight, roomy(), None)
            .unwrap(),
    );
    assert!(matches!(
        store
            .reserve_checkpoint(&new_checkpoint(&t, 1001, 1 << 20), &tight, roomy(), None)
            .unwrap(),
        ReserveCheckpoint::Exhausted(CheckpointExhausted {
            scope: "node",
            resource: "checkpoints",
            ..
        })
    ));
    // Records: retained history counts, so a released row still holds its record.
    let records = CheckpointBudgets {
        max_records_per_uid: 1,
        ..b
    };
    let (store, _) = self::store();
    let s = source(&store, 1000);
    let c = ready(&store, &s, 1000, 1 << 20);
    remove(&store, &c);
    assert!(matches!(
        store
            .reserve_checkpoint(&new_checkpoint(&s, 1000, 1 << 20), &records, roomy(), None)
            .unwrap(),
        ReserveCheckpoint::Exhausted(CheckpointExhausted {
            scope: "uid",
            resource: "checkpoint records",
            ..
        })
    ));
    // The shared node disk budget, both ways.
    let (store, _) = self::store();
    let s = source(&store, 1000);
    let budget = SandboxBudgets {
        disk_bytes: s.spec.disk_bytes + GIB + (GIB / 2),
        ..roomy()
    };
    inserted(
        store
            .reserve_checkpoint(&new_checkpoint(&s, 1000, GIB), &b, budget, None)
            .unwrap(),
    );
    // A sandbox of 1 GiB no longer fits beside the checkpoint's R.
    let mut sandbox = row(SandboxState::Creating, 1000);
    sandbox.spec.disk_bytes = GIB;
    sandbox.accounting = SandboxAccounting::legacy(&sandbox.spec, "");
    assert!(matches!(
        store.reserve_sandbox(&sandbox, budget).unwrap(),
        ReserveSandbox::Exhausted(BudgetExhausted {
            resource: "disk bytes",
            ..
        })
    ));
    // And a checkpoint does not fit beside sandbox promises.
    sandbox.spec.disk_bytes = GIB / 4;
    sandbox.accounting = SandboxAccounting::legacy(&sandbox.spec, "");
    assert_eq!(
        store.reserve_sandbox(&sandbox, budget).unwrap(),
        ReserveSandbox::Inserted
    );
    assert!(matches!(
        store
            .reserve_checkpoint(&new_checkpoint(&s, 1000, GIB / 2), &b, budget, None)
            .unwrap(),
        ReserveCheckpoint::Exhausted(CheckpointExhausted {
            resource: "disk bytes",
            ..
        })
    ));
}

/// Admission is one IMMEDIATE transaction: racing captures and creates from two
/// store handles on one database (the second ignoring kilnd's instance lock, as
/// another SQLite writer would) never overspend a cap or the shared disk budget.
#[test]
fn concurrent_admissions_never_overspend_caps_or_the_shared_disk() {
    let tmp = private_dir();
    let first = std::sync::Arc::new(Store::open(tmp.path()).unwrap());
    let second = std::sync::Arc::new(
        Store::init(Connection::open(tmp.path().join("kilnd.db")).unwrap(), None).unwrap(),
    );
    let clock = ManualClock::default();
    for s in [&first, &second] {
        s.set_clock(std::sync::Arc::new(clock.clone()));
    }
    let sources: Vec<Sandbox> = (0..4).map(|i| source(&first, 1000 + i)).collect();
    let base = disk(&first);
    // Room for exactly 6 GiB more on the node; checkpoints may take at most 5 of it.
    let disk_budget = base + 6 * GIB;
    let budgets = CheckpointBudgets {
        max_bytes_node: 5 * GIB,
        max_per_uid: 3,
        ..CheckpointBudgets::default()
    };
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let store = if i % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            let source = sources[i % 4].clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                let (mut checkpoints, mut sandboxes) = (0u64, 0u64);
                for round in 0..6 {
                    if (i + round) % 3 == 0 {
                        let mut s = row(SandboxState::Creating, source.owner_uid);
                        s.spec.disk_bytes = GIB / 2;
                        s.accounting = SandboxAccounting::legacy(&s.spec, "");
                        let budget = SandboxBudgets {
                            disk_bytes: disk_budget,
                            ..roomy()
                        };
                        if store.reserve_sandbox(&s, budget).unwrap() == ReserveSandbox::Inserted {
                            sandboxes += 1;
                        }
                    } else {
                        let budget = SandboxBudgets {
                            disk_bytes: disk_budget,
                            ..roomy()
                        };
                        match store
                            .reserve_checkpoint(
                                &new_checkpoint(&source, source.owner_uid, GIB / 2),
                                &budgets,
                                budget,
                                None,
                            )
                            .unwrap()
                        {
                            ReserveCheckpoint::Inserted(_) => checkpoints += 1,
                            ReserveCheckpoint::Exhausted(_) => {}
                            other => panic!("{other:?}"),
                        }
                    }
                }
                (checkpoints, sandboxes)
            })
        })
        .collect();
    let (mut checkpoints, mut sandboxes) = (0, 0);
    for t in threads {
        let (c, s) = t.join().unwrap();
        checkpoints += c;
        sandboxes += s;
    }
    let total = disk(&first);
    assert!(total <= disk_budget, "{total} > {disk_budget}");
    assert_eq!(
        total,
        base + checkpoints * (GIB / 2) + sandboxes * (GIB / 2)
    );
    let u = first.checkpoint_usage(1000).unwrap();
    assert_eq!(u.node.live, checkpoints);
    assert!(u.node.charged_bytes <= 5 * GIB);
    for uid in 1000..1004 {
        assert!(first.checkpoint_usage(uid).unwrap().uid.live <= 3);
    }
    // The node is full: something was refused.
    assert!(
        checkpoints * (GIB / 2) + sandboxes * (GIB / 2) > 5 * GIB,
        "{checkpoints} {sandboxes}"
    );
    // Both handles' audits agree with the rows after the race.
    drop(second);
    let first = std::sync::Arc::try_unwrap(first).ok().unwrap();
    drop(first);
    let reopened = Store::reopen_after_restart(tmp.path());
    assert_eq!(disk(&reopened), total);
}

/// Design 7.1: capture keys, M2's grammar and rules in their own namespace.
#[test]
fn capture_keys_return_their_row_conflict_and_release_only_when_deleted() {
    let (store, clock) = store();
    let s = source(&store, 1000);
    let mut keyed = new_checkpoint(&s, 1000, GIB);
    keyed.request_id = Some("retry-1".into());
    let admission = RequestAdmission {
        sha256: Digest::of(b"capture"),
        max_per_uid: 4096,
        max_node: 32_768,
    };
    let c = inserted(
        store
            .reserve_checkpoint(
                &keyed,
                &CheckpointBudgets::default(),
                roomy(),
                Some(&admission),
            )
            .unwrap(),
    );
    let (digest, found) = store.checkpoint_request(1000, "retry-1").unwrap().unwrap();
    assert_eq!(
        (digest, found.id.clone()),
        (Digest::of(b"capture"), c.id.clone())
    );
    assert!(
        store.checkpoint_request(1001, "retry-1").unwrap().is_none(),
        "per uid"
    );
    // The same key again, for any capture, is taken: nothing is inserted.
    let mut again = new_checkpoint(&s, 1000, GIB);
    again.request_id = Some("retry-1".into());
    assert_eq!(
        store
            .reserve_checkpoint(
                &again,
                &CheckpointBudgets::default(),
                roomy(),
                Some(&admission)
            )
            .unwrap(),
        ReserveCheckpoint::RequestIdTaken
    );
    assert_eq!(usage(&store, 1000).uid.live, 1);
    // Create keys are another namespace.
    let mut create = row(SandboxState::Creating, 1000);
    create.lifecycle.request_id = Some("retry-1".into());
    assert_eq!(
        store
            .reserve_keyed_sandbox(&create, roomy(), Some(&admission))
            .unwrap(),
        ReserveSandbox::Inserted
    );
    // A key's own quota.
    let quota = RequestAdmission {
        max_per_uid: 1,
        ..admission
    };
    let mut more = new_checkpoint(&s, 1000, GIB);
    more.request_id = Some("retry-2".into());
    assert!(matches!(
        store
            .reserve_checkpoint(&more, &CheckpointBudgets::default(), roomy(), Some(&quota))
            .unwrap(),
        ReserveCheckpoint::RequestQuota(RequestQuota {
            scope: "uid",
            count: 1,
            limit: 1
        })
    ));
    // A keyed row needs its admission and an unkeyed one may not name a key.
    assert!(
        store
            .reserve_checkpoint(&more, &CheckpointBudgets::default(), roomy(), None)
            .is_err()
    );
    // Release only once DELETED; the key's record pins the row's history.
    assert_eq!(
        store.release_checkpoint_request_id(c.id.as_str()).unwrap(),
        ReleaseRequestId::NotDeleted
    );
    let c = store.checkpoint(c.id.as_str()).unwrap().unwrap();
    let ready_c = match store
        .publish_checkpoint_ready(c.id.as_str(), &complete(&c, 1 << 20))
        .unwrap()
    {
        PublishCheckpoint::Published(c) => *c,
        other => panic!("{other:?}"),
    };
    remove(&store, &ready_c);
    // The record's own retention has not run (no boot time passed): it pins the row.
    let pruned = store
        .prune(&Retention::default(), clock.wall_ms() + 30 * 86_400_000)
        .unwrap();
    assert_eq!(
        pruned.checkpoints, 0,
        "a keyed checkpoint is pinned by its record"
    );
    assert_eq!(
        store.release_checkpoint_request_id(c.id.as_str()).unwrap(),
        ReleaseRequestId::Released
    );
    assert_eq!(
        store.release_checkpoint_request_id(c.id.as_str()).unwrap(),
        ReleaseRequestId::NoRecord
    );
    assert!(store.checkpoint_request(1000, "retry-1").unwrap().is_none());
    let released = store.checkpoint(c.id.as_str()).unwrap().unwrap();
    assert_eq!(
        released.request_id.as_deref(),
        Some("retry-1"),
        "history keeps its key"
    );
    assert!(released.request_id_released_at_ms.is_some());
    assert_eq!(usage(&store, 1000).uid.keys, 0);
}

/// Design 7.2: the fork's CREATING row, reservation, key record (digest version 2),
/// provenance and pin commit together after the checkpoint is rechecked; a refusal
/// inserts nothing.
#[test]
fn a_fork_commits_its_row_provenance_and_pin_together() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let c = ready(&store, &s, 1000, 64 << 20);
    let seq = c.activity_seq;
    let refused = |fork: &Sandbox, expected: ForkRefusal| {
        assert_eq!(
            store
                .reserve_fork_sandbox(fork, roomy(), None, &[], &dispatch())
                .unwrap(),
            ReserveFork::Refused(expected)
        );
        assert!(store.sandbox(&fork.id).unwrap().is_none());
    };
    // Another user's checkpoint is not found; root may fork it.
    refused(&fork_row(&c, 1001), ForkRefusal::NotFound);
    let mut changed = fork_row(&c, 1000);
    changed
        .lifecycle
        .from_checkpoint
        .as_mut()
        .unwrap()
        .content_sha256 = Digest::of(b"other");
    refused(&changed, ForkRefusal::Changed);
    let mut image = fork_row(&c, 1000);
    image.spec.image = "busybox".into();
    refused(&image, ForkRefusal::SpecMismatch);
    let mut root = fork_row(&c, 1000);
    root.spec.read_only_root = true;
    refused(&root, ForkRefusal::SpecMismatch);
    let mut paths = fork_row(&c, 1000);
    paths.spec.writable_paths = vec!["/workspace".into()];
    refused(&paths, ForkRefusal::SpecMismatch);
    let mut small = fork_row(&c, 1000);
    small.spec.disk_bytes = 1 << 20;
    small.accounting = SandboxAccounting::legacy(&small.spec, "");
    refused(&small, ForkRefusal::DiskTooSmall { required: 64 << 20 });
    // A fork goes only through its own path, and that path only takes forks.
    assert!(store.reserve_sandbox(&fork_row(&c, 1000), roomy()).is_err());
    assert!(
        store
            .reserve_fork_sandbox(
                &row(SandboxState::Creating, 1000),
                roomy(),
                None,
                &[],
                &dispatch()
            )
            .is_err()
    );
    // Accepted, keyed: version 2.
    let mut fork = fork_row(&c, 0);
    fork.lifecycle.request_id = Some("fork-1".into());
    let admission = RequestAdmission {
        sha256: Digest::of(b"fork"),
        max_per_uid: 64,
        max_node: 64,
    };
    let reader = dispatch();
    assert_eq!(
        store
            .reserve_fork_sandbox(&fork, roomy(), Some(&admission), &[], &reader)
            .unwrap(),
        ReserveFork::Sandbox(ReserveSandbox::Inserted)
    );
    let stored = store.sandbox(&fork.id).unwrap().unwrap();
    assert_eq!(
        stored.lifecycle.from_checkpoint,
        fork.lifecycle.from_checkpoint
    );
    let version: i64 = store
        .conn()
        .query_row(
            "SELECT digest_version FROM create_requests WHERE sandbox_id = ?1",
            [&fork.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, 2);
    assert!(
        store
            .conn()
            .execute(
                "UPDATE create_requests SET digest_version = 1 WHERE sandbox_id = ?1",
                [&fork.id]
            )
            .is_err()
    );
    let pin = store.checkpoint_pin(&fork.id).unwrap().unwrap();
    assert_eq!(
        (pin.checkpoint.clone(), pin.generation, pin.reader),
        (c.id.clone(), 1, reader)
    );
    assert!(pin.released_at_ms.is_none());
    // Accepted fork = activity.
    assert_eq!(
        store
            .checkpoint(c.id.as_str())
            .unwrap()
            .unwrap()
            .activity_seq,
        seq + 1
    );
    // Both reservations stand: the checkpoint's S and the fork's full disk.
    assert_eq!(
        disk(&store),
        s.accounting.reservation.disk_bytes + (64 << 20) + fork.accounting.reservation.disk_bytes
    );
    // A reader that may still read never releases; one that completed does.
    let unknown = evidence(
        &c,
        &reader,
        Fact::ReaderEnded {
            copy: CopyOutcome::Unknown,
        },
    );
    assert!(store.release_checkpoint_pin(&fork.id, &unknown).is_err());
    let other = evidence(
        &c,
        &dispatch(),
        Fact::ReaderEnded {
            copy: CopyOutcome::Complete,
        },
    );
    assert!(store.release_checkpoint_pin(&fork.id, &other).is_err());
    let done = evidence(
        &c,
        &reader,
        Fact::ReaderEnded {
            copy: CopyOutcome::Complete,
        },
    );
    assert_eq!(
        store.release_checkpoint_pin(&fork.id, &done).unwrap(),
        ReleasePin::Released
    );
    assert_eq!(
        store.release_checkpoint_pin(&fork.id, &done).unwrap(),
        ReleasePin::AlreadyReleased
    );
    let pin = store.checkpoint_pin(&fork.id).unwrap().unwrap();
    assert_eq!(pin.released_by.as_deref(), Some("complete"));
    assert_eq!(
        store
            .checkpoint(c.id.as_str())
            .unwrap()
            .unwrap()
            .activity_seq,
        seq + 2,
        "last pin's finish activity"
    );
    // After delete intent no pin is admitted.
    store
        .publish_checkpoint_delete_intent(c.id.as_str(), DeletionReason::Requested)
        .unwrap();
    refused(
        &fork_row(&c, 1000),
        ForkRefusal::NotReady(CheckpointState::Deleting),
    );
}

/// D3 releases every live pin with the checkpoint's own ABSENT evidence: no reader
/// can remain. A completed fork survives the checkpoint's deletion.
#[test]
fn absence_releases_live_pins_and_forks_survive_deletion() {
    let (store, _) = store();
    let s = source(&store, 1000);
    let c = ready(&store, &s, 1000, 64 << 20);
    let forks: Vec<Sandbox> = (0..3)
        .map(|_| {
            let fork = fork_row(&c, 1000);
            assert_eq!(
                store
                    .reserve_fork_sandbox(&fork, roomy(), None, &[], &dispatch())
                    .unwrap(),
                ReserveFork::Sandbox(ReserveSandbox::Inserted)
            );
            fork
        })
        .collect();
    store
        .set_sandbox_state(&forks[0].id, SandboxState::Ready, Some(&kiln_id()), None)
        .unwrap();
    let deleted = remove(&store, &c);
    assert_eq!(deleted.state, CheckpointState::Deleted);
    for fork in &forks {
        let pin = store.checkpoint_pin(&fork.id).unwrap().unwrap();
        assert_eq!(pin.released_by.as_deref(), Some("absent"));
        assert_eq!(pin.release_evidence_id, deleted.release_evidence_id);
    }
    let survivor = store.sandbox(&forks[0].id).unwrap().unwrap();
    assert_eq!(survivor.state, SandboxState::Ready);
    assert_eq!(survivor.lifecycle.from_checkpoint.unwrap().checkpoint, c.id);
}

#[test]
fn prune_keeps_charged_keyed_and_pinned_checkpoints_and_drops_old_history() {
    let (store, clock) = store();
    let s = source(&store, 1000);
    let charged = ready(&store, &s, 1000, 1 << 20);
    let old = ready(&store, &s, 1000, 1 << 20);
    remove(&store, &old);
    let pinned = ready(&store, &s, 1000, 1 << 20);
    let fork = fork_row(&pinned, 1000);
    store
        .reserve_fork_sandbox(&fork, roomy(), None, &[], &dispatch())
        .unwrap();
    // The pinned checkpoint is DELETING with a live pin: not releasable, not prunable.
    store
        .publish_checkpoint_delete_intent(pinned.id.as_str(), DeletionReason::Requested)
        .unwrap();
    let now = now_ms() + 2 * 86_400_000;
    clock.advance(2 * 86_400_000);
    // One day of history at least, whatever the sandbox policy says.
    let short = Retention {
        sandbox_max_age_secs: 60,
        ..Retention::default()
    };
    let pruned = store.prune(&short, now_ms()).unwrap();
    assert_eq!(pruned.checkpoints, 0, "history younger than a day stays");
    let pruned = store
        .prune(&Retention::default(), now + 7 * 86_400_000)
        .unwrap();
    assert_eq!(pruned.checkpoints, 1);
    assert!(store.checkpoint(old.id.as_str()).unwrap().is_none());
    assert!(store.checkpoint(charged.id.as_str()).unwrap().is_some());
    assert!(store.checkpoint(pinned.id.as_str()).unwrap().is_some());
    let evidence: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM checkpoint_evidence WHERE checkpoint_id = ?1",
            [old.id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(evidence, 0, "its evidence went with it");
    let u = usage(&store, 1000);
    assert_eq!((u.node.records, u.node.live), (2, 2));
    // And the audits agree after a restart-style full verification.
    store
        .conn()
        .execute("DELETE FROM temp.membership_verified", [])
        .unwrap();
    assert!(!store.accounting_snapshot().unwrap().1);
}

// --- SQL tampering -----------------------------------------------------------------

/// A disk store with one checkpoint in each interesting state and a live pin.
struct Fixture {
    _tmp: tempfile::TempDir,
    store: Store,
    source: Sandbox,
    capturing: Checkpoint,
    ready: Checkpoint,
    deleted: Checkpoint,
    keyed: Checkpoint,
    fork: Sandbox,
    /// DELETING with a removal recorded, its ABSENT evidence stored, and a live pin.
    deleting: Checkpoint,
}

fn fixture() -> Fixture {
    let tmp = private_dir();
    let store = Store::open(tmp.path()).unwrap();
    store.set_clock(std::sync::Arc::new(ManualClock::default()));
    let source = source(&store, 1000);
    let capturing = inserted(reserve(&store, &new_checkpoint(&source, 1000, GIB)));
    let ready = self::ready(&store, &source, 1000, 32 << 20);
    let deleted = remove(&store, &self::ready(&store, &source, 1000, 16 << 20));
    let mut keyed = new_checkpoint(&source, 1000, GIB);
    keyed.request_id = Some("k".into());
    let admission = RequestAdmission {
        sha256: Digest::of(b"k"),
        max_per_uid: 64,
        max_node: 64,
    };
    let keyed = inserted(
        store
            .reserve_checkpoint(
                &keyed,
                &CheckpointBudgets::default(),
                roomy(),
                Some(&admission),
            )
            .unwrap(),
    );
    let fork = fork_row(&ready, 1000);
    store
        .reserve_fork_sandbox(&fork, roomy(), None, &[], &dispatch())
        .unwrap();
    let deleting = self::ready(&store, &source, 1000, 8 << 20);
    store
        .reserve_fork_sandbox(&fork_row(&deleting, 1000), roomy(), None, &[], &dispatch())
        .unwrap();
    store
        .publish_checkpoint_delete_intent(deleting.id.as_str(), DeletionReason::Requested)
        .unwrap();
    let removal = dispatch();
    store
        .record_checkpoint_removal(deleting.id.as_str(), &removal)
        .unwrap();
    let proof = absent(&deleting, &removal);
    checkpoint::insert_evidence(
        &store.conn(),
        &proof,
        &proof.evidence.canonical_bytes().unwrap(),
        1,
    )
    .unwrap();
    let deleting = store.checkpoint(deleting.id.as_str()).unwrap().unwrap();
    Fixture {
        _tmp: tmp,
        store,
        source,
        capturing,
        ready,
        deleted,
        keyed,
        fork,
        deleting,
    }
}

/// A connection with kilnd's triggers but every other defense off, as the schema 12
/// tests use: foreign keys and CHECKs ignored, writable schema on.
fn defenseless(dir: &Path) -> Connection {
    let conn = Connection::open(dir.join("kilnd.db")).unwrap();
    for pragma in ["foreign_keys", "recursive_triggers"] {
        conn.pragma_update(None, pragma, "OFF").unwrap();
    }
    for pragma in [
        "ignore_check_constraints",
        "trusted_schema",
        "defer_foreign_keys",
    ] {
        conn.pragma_update(None, pragma, "ON").unwrap();
    }
    // The validator is registered, as a writer that wants its forged evidence to pass
    // the insert trigger would.
    checkpoint::register_evidence_validator(&conn).unwrap();
    conn
}

fn snapshot_all(conn: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "checkpoints",
        "checkpoint_evidence",
        "checkpoint_pins",
        "checkpoint_requests",
        "checkpoint_counts",
        "checkpoint_membership",
        "sandboxes",
    ]
    .iter()
    .map(|t| table_snapshot(conn, t))
    .collect()
}

/// Design 9.2 items 1-4 through ordinary SQL, both on kilnd's own connection and on
/// a defenseless one: every statement is refused and nothing changes.
#[test]
fn sql_tampering_is_refused_by_the_triggers() {
    let f = fixture();
    let (cap, rdy, del, key) = (
        f.capturing.id.as_str(),
        f.ready.id.as_str(),
        f.deleted.id.as_str(),
        f.keyed.id.as_str(),
    );
    let complete_id = f.ready.seal.as_ref().unwrap().evidence_id.to_string();
    let release_id = f.deleted.release_evidence_id.unwrap().to_string();
    let fork = f.fork.id.as_str();
    let src = f.source.id.as_str();
    let dlg = f.deleting.id.as_str();
    let hex64 = "a".repeat(64);
    let hex32 = "b".repeat(32);
    let statements: Vec<String> = vec![
        // Replacement and resurrection by insert.
        format!("INSERT OR REPLACE INTO checkpoints SELECT * FROM checkpoints WHERE id = '{rdy}'"),
        format!("INSERT INTO checkpoints (id, creation_seq, owner_uid, instance_id, generation, format_version, source_sandbox_id,
             source_backend, source_backend_id, capture_operation, capture_helper_epoch, capture_boot_id, max_size_bytes, image,
             image_content_sha256, read_only_root, writable_paths, excluded_paths, expiry_lifetime_ms, expiry_idle_ms, state,
             created_at_ms, updated_at_ms) SELECT 'cp-{h}', creation_seq + 100, owner_uid, instance_id, 1, 1, source_sandbox_id,
             source_backend, source_backend_id, '{hex32}', capture_helper_epoch, capture_boot_id, max_size_bytes, image,
             image_content_sha256, read_only_root, writable_paths, excluded_paths, expiry_lifetime_ms, expiry_idle_ms, 'ready',
             1, 1 FROM checkpoints WHERE id = '{rdy}'", h = "c".repeat(32)),
        // Identity, owner, source, cap, format, compatibility, expiry, key.
        format!("UPDATE checkpoints SET owner_uid = 0 WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET max_size_bytes = 65536 WHERE id = '{cap}'"),
        format!("UPDATE checkpoints SET source_backend_id = 'ffff' WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET image_content_sha256 = '{hex64}' WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET writable_paths = '[]' WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET generation = 2 WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET expiry_lifetime_ms = 604800000 WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET request_id = NULL WHERE id = '{key}'"),
        format!("UPDATE checkpoints SET capture_operation = '{hex32}' WHERE id = '{cap}'"),
        // Repricing and sealing without matching evidence.
        format!("UPDATE checkpoints SET charge_bytes = 1 WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET charge_bytes = 1 WHERE id = '{cap}'"),
        format!("UPDATE checkpoints SET content_sha256 = '{hex64}' WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET state = 'ready', complete_evidence_id = '{complete_id}', content_sha256 = '{hex64}',
             binding_sha256 = '{hex64}', charge_bytes = 1, logical_bytes = 1, allocated_bytes = 1, entry_count = 1,
             ready_at_ms = 1, ready_boottime_ms = 1, clock_boot_id = 'x' WHERE id = '{cap}'"),
        // Illegal transitions, resurrection.
        format!("UPDATE checkpoints SET state = 'capturing' WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET state = 'ready' WHERE id = '{del}'"),
        format!("UPDATE checkpoints SET state = 'deleting' WHERE id = '{del}'"),
        format!("UPDATE checkpoints SET state = 'failed', failure_token = 'checkpoint_io', failure_reason = 'x' WHERE id = '{rdy}'"),
        // Release without matching ABSENT evidence, or with a live pin.
        format!("UPDATE checkpoints SET state = 'deleted', deletion_reason = 'requested', deleted_at_ms = 1,
             release_evidence_id = '{complete_id}', released_at_ms = 1, removal_operation = '{hex32}',
             removal_helper_epoch = '{hex32}', removal_boot_id = '{hex32}' WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET state = 'deleted', deletion_reason = 'requested', deleted_at_ms = 1,
             release_evidence_id = '{release_id}', released_at_ms = 1, removal_operation = '{hex32}',
             removal_helper_epoch = '{hex32}', removal_boot_id = '{hex32}' WHERE id = '{cap}'"),
        format!("UPDATE checkpoints SET release_evidence_id = NULL, released_at_ms = NULL WHERE id = '{del}'"),
        // Its own removal's ABSENT evidence, but a pin is live; another checkpoint's evidence.
        format!("UPDATE checkpoints SET state = 'deleted', deleted_at_ms = 1, released_at_ms = 1,
             release_evidence_id = (SELECT evidence_id FROM checkpoint_evidence WHERE checkpoint_id = '{dlg}' AND kind = 'absent')
             WHERE id = '{dlg}'"),
        format!("UPDATE checkpoints SET state = 'deleted', deleted_at_ms = 1, released_at_ms = 1,
             release_evidence_id = '{release_id}' WHERE id = '{dlg}'"),
        format!("UPDATE checkpoints SET state = 'deleted', deleted_at_ms = 1, released_at_ms = 1,
             release_evidence_id = (SELECT evidence_id FROM checkpoint_evidence WHERE checkpoint_id = '{dlg}' AND kind = 'complete')
             WHERE id = '{dlg}'"),
        // A pin may not be added once delete intent is published.
        format!("INSERT INTO checkpoint_pins SELECT '{src}', '{dlg}', generation, content_sha256, '{h}', helper_epoch, boot_id,
             1, NULL, NULL, NULL FROM checkpoint_pins WHERE checkpoint_id = '{dlg}'", h = "d".repeat(32)),
        format!("UPDATE checkpoints SET removal_operation = '{hex32}' WHERE id = '{del}'"),
        format!("UPDATE checkpoints SET removal_operation = '{hex32}', removal_helper_epoch = '{hex32}', removal_boot_id = '{hex32}' WHERE id = '{rdy}'"),
        // Deletion of charged, keyed or pinned rows; reasons and sequences.
        format!("DELETE FROM checkpoints WHERE id = '{cap}'"),
        format!("DELETE FROM checkpoints WHERE id = '{rdy}'"),
        format!("UPDATE checkpoints SET deletion_reason = 'expired_idle' WHERE id = '{del}'"),
        format!("UPDATE checkpoints SET activity_seq = 0 WHERE id = '{rdy}'"),
        "UPDATE checkpoint_sequence SET value = 0".to_string(),
        // Evidence: immutable, bound, decodable.
        format!("UPDATE checkpoint_evidence SET evidence = x'7b7d' WHERE evidence_id = '{complete_id}'"),
        format!("DELETE FROM checkpoint_evidence WHERE evidence_id = '{release_id}'"),
        format!("INSERT OR REPLACE INTO checkpoint_evidence SELECT * FROM checkpoint_evidence WHERE evidence_id = '{complete_id}'"),
        format!("INSERT INTO checkpoint_evidence SELECT '{hex64}', instance_id, checkpoint_id, generation, operation, helper_epoch,
             boot_id, kind, evidence, recorded_at_ms FROM checkpoint_evidence WHERE evidence_id = '{complete_id}'"),
        format!("INSERT INTO checkpoint_evidence SELECT evidence_id, instance_id, '{cap}', generation, operation, helper_epoch,
             boot_id, kind, evidence, recorded_at_ms FROM checkpoint_evidence WHERE evidence_id = '{complete_id}'"),
        // Pins: no target change, no release without evidence, no live delete, none on DELETED.
        format!("UPDATE checkpoint_pins SET checkpoint_id = '{del}' WHERE sandbox_id = '{fork}'"),
        format!("UPDATE checkpoint_pins SET content_sha256 = '{hex64}' WHERE sandbox_id = '{fork}'"),
        format!("UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'complete', release_evidence_id = '{complete_id}' WHERE sandbox_id = '{fork}'"),
        format!("UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'absent', release_evidence_id = '{release_id}' WHERE sandbox_id = '{fork}'"),
        format!("DELETE FROM checkpoint_pins WHERE sandbox_id = '{fork}'"),
        format!("INSERT OR REPLACE INTO checkpoint_pins SELECT * FROM checkpoint_pins WHERE sandbox_id = '{fork}'"),
        format!("INSERT INTO checkpoint_pins SELECT '{src}', '{del}', generation, content_sha256, '{hex32}', helper_epoch, boot_id,
             1, NULL, NULL, NULL FROM checkpoint_pins WHERE sandbox_id = '{fork}'"),
        // Capture keys.
        format!("UPDATE checkpoint_requests SET request_sha256 = '{hex64}' WHERE checkpoint_id = '{key}'"),
        format!("UPDATE checkpoint_requests SET digest_version = 2 WHERE checkpoint_id = '{key}'"),
        format!("DELETE FROM checkpoint_requests WHERE checkpoint_id = '{key}'"),
        format!("INSERT OR REPLACE INTO checkpoint_requests SELECT * FROM checkpoint_requests WHERE checkpoint_id = '{key}'"),
        // Fork provenance and image identity.
        format!("UPDATE sandboxes SET from_checkpoint = NULL, checkpoint_content_sha256 = NULL WHERE id = '{fork}'"),
        format!("UPDATE sandboxes SET image_content_sha256 = '{hex64}' WHERE id = '{src}'"),
        // The aggregates' identities.
        "INSERT OR REPLACE INTO checkpoint_membership VALUES (1, 1, 0, zeroblob(32), 0, zeroblob(32))".to_string(),
        "UPDATE checkpoint_counts SET owner_uid = 7 WHERE owner_uid = -1".to_string(),
    ];
    let dir = f._tmp.path().to_path_buf();
    let before = snapshot_all(&f.store.conn());
    for conn in [
        defenseless(&dir),
        Connection::open(dir.join("kilnd.db")).unwrap(),
    ] {
        checkpoint::register_evidence_validator(&conn).unwrap();
        for sql in &statements {
            let error = conn.execute_batch(sql).expect_err(sql).to_string();
            // Refused by a trigger or constraint, never by a mistake in the statement.
            for mistake in [
                "syntax error",
                "no such",
                "values were supplied",
                "has no column",
            ] {
                assert!(!error.contains(mistake), "{sql}: {error}");
            }
            println!(
                "refused: {}\n    {error}",
                sql.split_whitespace().collect::<Vec<_>>().join(" ")
            );
        }
    }
    assert_eq!(snapshot_all(&f.store.conn()), before, "nothing changed");
    // And the typed paths still work afterwards.
    assert!(!f.store.accounting_snapshot().unwrap().1);
    let _ = (&f.ready, &f.keyed);
}

type Tamper = Box<dyn Fn(&Fixture) -> String>;

/// Design 9.2 item 5: a writer past the triggers. Each change below is caught by the
/// next accounting decision, which then refuses both capture and sandbox Create and
/// never frees the charge; and a restart refuses too.
#[test]
fn tampering_past_the_triggers_is_caught_and_never_frees_capacity() {
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "delete a charged row",
            Box::new(|f: &Fixture| {
                format!("DELETE FROM checkpoints WHERE id = '{}'", f.capturing.id)
            }),
        ),
        (
            "reprice a sealed charge",
            Box::new(|f: &Fixture| {
                format!(
                    "UPDATE checkpoints SET charge_bytes = 1 WHERE id = '{}'",
                    f.ready.id
                )
            }),
        ),
        (
            "lower an unsealed cap",
            Box::new(|f: &Fixture| {
                format!(
                    "UPDATE checkpoints SET max_size_bytes = 65536 WHERE id = '{}'",
                    f.capturing.id
                )
            }),
        ),
        (
            "release with its own COMPLETE evidence",
            Box::new(|f: &Fixture| {
                format!(
                    "UPDATE checkpoints SET release_evidence_id = complete_evidence_id, released_at_ms = 1 WHERE id = '{}'",
                    f.ready.id
                )
            }),
        ),
        (
            "release with another checkpoint's ABSENT evidence",
            Box::new(|f: &Fixture| {
                format!(
                "UPDATE checkpoints SET release_evidence_id = '{}', released_at_ms = 1, removal_operation = '{}',
                     removal_helper_epoch = '{}', removal_boot_id = '{}' WHERE id = '{}'",
                f.deleted.release_evidence_id.unwrap(),
                f.deleted.removal.unwrap().operation,
                f.deleted.removal.unwrap().helper_epoch,
                f.deleted.removal.unwrap().boot_id,
                f.ready.id
            )
            }),
        ),
        (
            "lower the cached counts",
            Box::new(|_: &Fixture| {
                "UPDATE checkpoint_counts SET live = 0, charged_bytes = 0".to_string()
            }),
        ),
        (
            "rewrite the membership",
            Box::new(|_: &Fixture| {
                "UPDATE checkpoint_membership SET row_count = row_count - 1".to_string()
            }),
        ),
        (
            "replace stored evidence bytes",
            Box::new(|f: &Fixture| {
                format!(
                "UPDATE checkpoint_evidence SET evidence = CAST(replace(CAST(evidence AS TEXT), '\"entries\":7', '\"entries\":8') AS BLOB)
                 WHERE evidence_id = '{}'",
                f.ready.seal.as_ref().unwrap().evidence_id
            )
            }),
        ),
        (
            "forge a released pin",
            Box::new(|f: &Fixture| {
                format!(
                "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'complete', release_evidence_id = '{}'
                 WHERE sandbox_id = '{}'",
                f.ready.seal.as_ref().unwrap().evidence_id,
                f.fork.id
            )
            }),
        ),
    ];
    for (name, sql) in &cases {
        for restart in [false, true] {
            let f = fixture();
            let src = f.source.clone();
            let charged_before = disk(&f.store);
            let conn = Connection::open(f._tmp.path().join("kilnd.db")).unwrap();
            conn.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                false,
            )
            .unwrap();
            conn.pragma_update(None, "ignore_check_constraints", "ON")
                .unwrap();
            conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
            conn.execute_batch(&sql(&f)).unwrap();
            drop(conn);
            let store = if restart {
                let dir = f._tmp.path().to_path_buf();
                let Fixture { _tmp, store, .. } = f;
                drop(store);
                match Store::open(&dir) {
                    Err(error) => {
                        // Refused startup: nothing is admitted.
                        println!("{name} (restart): startup refused: {error:#}");
                        continue;
                    }
                    Ok(store) => (store, _tmp),
                }
            } else {
                let Fixture { _tmp, store, .. } = f;
                (store, _tmp)
            };
            let (store, tmp) = store;
            store.set_clock(std::sync::Arc::new(ManualClock::default()));
            // Health: degraded or totals unavailable, never a smaller charge.
            match store.accounting_snapshot() {
                Ok((resources, degraded)) => {
                    assert!(degraded, "{name} (restart {restart}): not degraded");
                    assert!(
                        resources.disk_bytes >= charged_before,
                        "{name}: freed capacity"
                    );
                    println!(
                        "{name} (restart {restart}): degraded, {} charged bytes kept",
                        resources.disk_bytes
                    );
                }
                Err(error) => println!("{name} (restart {restart}): totals unavailable: {error:#}"),
            }
            // Admission refuses capture and sandbox Create alike.
            let sandbox = row(SandboxState::Creating, 1000);
            assert!(
                store.reserve_sandbox(&sandbox, roomy()).is_err(),
                "{name}: sandbox admitted"
            );
            assert!(
                store
                    .reserve_checkpoint(
                        &new_checkpoint(&src, 1000, 1 << 20),
                        &CheckpointBudgets::default(),
                        roomy(),
                        None
                    )
                    .is_err(),
                "{name}: capture admitted"
            );
            drop(tmp);
        }
    }
}

/// Unknown or stale evidence never enters: the validator and the binding trigger.
#[test]
fn evidence_is_bound_to_this_instance_and_an_existing_checkpoint() {
    let f = fixture();
    let conn = f.store.conn();
    let insert = |sealed: &SealedEvidence| {
        let bytes = sealed.evidence.canonical_bytes().unwrap();
        let e = &sealed.evidence;
        conn.execute(
            "INSERT INTO checkpoint_evidence VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
            params![
                sealed.id.to_string(),
                e.instance.to_string(),
                e.checkpoint.as_str(),
                e.generation as i64,
                e.operation.to_string(),
                e.helper_epoch.to_string(),
                e.boot_id.to_string(),
                e.fact.kind(),
                bytes
            ],
        )
    };
    // About a checkpoint that does not exist, another instance, another generation.
    let mut unknown = f.ready.clone();
    unknown.id = CheckpointId::random();
    assert!(insert(&absent(&unknown, &dispatch())).is_err());
    let mut foreign = f.ready.clone();
    foreign.instance_id = Id128::random();
    assert!(insert(&absent(&foreign, &dispatch())).is_err());
    let mut stale = f.ready.clone();
    stale.generation = 2;
    assert!(insert(&absent(&stale, &dispatch())).is_err());
    // Bytes that are not the ID's, or columns that say something else.
    let good = absent(&f.ready, &dispatch());
    let mut wrong_id = good.clone();
    wrong_id.id = Digest::of(b"x");
    assert!(insert(&wrong_id).is_err());
    assert!(
        conn.execute(
            "INSERT INTO checkpoint_evidence VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 'complete', ?7, 1)",
            params![
                good.id.to_string(),
                good.evidence.instance.to_string(),
                f.ready.id.as_str(),
                good.evidence.operation.to_string(),
                good.evidence.helper_epoch.to_string(),
                good.evidence.boot_id.to_string(),
                good.evidence.canonical_bytes().unwrap()
            ],
        )
        .is_err()
    );
    // The real thing enters, once.
    insert(&good).unwrap();
    assert!(insert(&good).is_err());
}

// --- Fix round 1: evidence is bound to the dispatch's helper epoch and boot ----------

/// The three ways a fact can come from somewhere other than the dispatch: another
/// helper epoch and boot, another epoch in the same boot, the same epoch on another boot.
fn foreign_certifiers(d: &HelperDispatch) -> [(HelperDispatch, &'static str); 3] {
    [
        (
            HelperDispatch {
                helper_epoch: Id128::random(),
                boot_id: Id128::random(),
                ..*d
            },
            "another epoch and boot",
        ),
        (
            HelperDispatch {
                helper_epoch: Id128::random(),
                ..*d
            },
            "another epoch, same boot",
        ),
        (
            HelperDispatch {
                boot_id: Id128::random(),
                ..*d
            },
            "same epoch, another boot",
        ),
    ]
}

/// Adversarial review HIGH 1 (adopted PoC): COMPLETE evidence about the right capture
/// nonce, certified by another helper epoch or boot, does not seal READY.
#[test]
fn complete_evidence_from_another_helper_epoch_is_refused() {
    let (store, _) = store();
    let source = source(&store, 1000);
    let checkpoint = inserted(reserve(&store, &new_checkpoint(&source, 1000, 1 << 30)));
    for (other, case) in foreign_certifiers(&checkpoint.capture) {
        let wrong = evidence(
            &checkpoint,
            &other,
            complete(&checkpoint, 1 << 20).evidence.fact,
        );
        let outcome = store
            .publish_checkpoint_ready(checkpoint.id.as_str(), &wrong)
            .unwrap();
        assert!(
            matches!(outcome, PublishCheckpoint::Refused(_)),
            "{case}: mismatched-epoch COMPLETE evidence was accepted: {outcome:?}"
        );
    }
    let row = store.checkpoint(checkpoint.id.as_str()).unwrap().unwrap();
    assert_eq!(
        (row.state, row.charge_bytes()),
        (CheckpointState::Capturing, 1 << 30)
    );
    // The dispatch's own fact still seals it.
    assert!(matches!(
        store
            .publish_checkpoint_ready(checkpoint.id.as_str(), &complete(&checkpoint, 1 << 20))
            .unwrap(),
        PublishCheckpoint::Published(_)
    ));
}

/// Adversarial review HIGH 1 (adopted PoC): ABSENT evidence about the recorded removal
/// nonce, certified by another helper epoch or boot, releases nothing.
#[test]
fn absent_evidence_from_another_helper_epoch_is_refused() {
    let (store, _) = store();
    let source = source(&store, 1000);
    let checkpoint = ready(&store, &source, 1000, 1 << 20);
    store
        .publish_checkpoint_delete_intent(checkpoint.id.as_str(), DeletionReason::Requested)
        .unwrap();
    let removal = dispatch();
    store
        .record_checkpoint_removal(checkpoint.id.as_str(), &removal)
        .unwrap();
    let charged = disk(&store);
    for (other, case) in foreign_certifiers(&removal) {
        let outcome = store
            .settle_checkpoint_absence(checkpoint.id.as_str(), &absent(&checkpoint, &other))
            .unwrap();
        assert!(
            matches!(outcome, SettleAbsence::Refused(_)),
            "{case}: mismatched-epoch ABSENT evidence was accepted: {outcome:?}"
        );
    }
    let row = store.checkpoint(checkpoint.id.as_str()).unwrap().unwrap();
    assert_eq!(row.state, CheckpointState::Deleting);
    assert_eq!(disk(&store), charged, "no charge released");
    // A later removal redispatched under a new epoch: only that dispatch's fact counts.
    let again = dispatch();
    store
        .record_checkpoint_removal(checkpoint.id.as_str(), &again)
        .unwrap();
    assert!(matches!(
        store
            .settle_checkpoint_absence(checkpoint.id.as_str(), &absent(&checkpoint, &removal))
            .unwrap(),
        SettleAbsence::Refused(_)
    ));
    assert!(matches!(
        store
            .settle_checkpoint_absence(checkpoint.id.as_str(), &absent(&checkpoint, &again))
            .unwrap(),
        SettleAbsence::Released(_)
    ));
}

/// Adversarial review HIGH 1 (adopted PoC): a reader's end certified by another helper
/// epoch or boot does not release its pin. In particular, a pin whose dispatch epoch
/// died can't be released by a new epoch's word about its nonce: only its checkpoint's
/// ABSENT evidence releases it.
#[test]
fn reader_evidence_from_another_helper_epoch_is_refused() {
    let (store, _) = store();
    let source = source(&store, 1000);
    let checkpoint = ready(&store, &source, 1000, 1 << 20);
    let fork = fork_row(&checkpoint, 1000);
    let reader = dispatch();
    assert_eq!(
        store
            .reserve_fork_sandbox(&fork, roomy(), None, &[], &reader)
            .unwrap(),
        ReserveFork::Sandbox(ReserveSandbox::Inserted)
    );
    for copy in [CopyOutcome::Complete, CopyOutcome::NotStarted] {
        for (other, case) in foreign_certifiers(&reader) {
            let wrong = evidence(&checkpoint, &other, Fact::ReaderEnded { copy });
            let outcome = store.release_checkpoint_pin(&fork.id, &wrong);
            assert!(
                outcome.is_err(),
                "{case}: mismatched-epoch READER_ENDED evidence was accepted: {outcome:?}"
            );
        }
    }
    assert!(
        store
            .checkpoint_pin(&fork.id)
            .unwrap()
            .unwrap()
            .released_at_ms
            .is_none()
    );
    // The pin holds the checkpoint: nothing releases it but its removal's absence.
    let deleted = remove(&store, &checkpoint);
    assert_eq!(deleted.state, CheckpointState::Deleted);
    let pin = store.checkpoint_pin(&fork.id).unwrap().unwrap();
    assert_eq!(pin.released_by.as_deref(), Some("absent"));
}

/// The SQL triggers refuse the same wrong-epoch facts on their own (a writer that
/// skips the typed API), for each of the three paths.
#[test]
fn the_triggers_bind_each_fact_to_its_dispatch_epoch_and_boot() {
    let f = fixture();
    // A DELETING checkpoint with its removal recorded and no pin.
    let lone = ready(&f.store, &f.source, 1000, 1 << 20);
    f.store
        .publish_checkpoint_delete_intent(lone.id.as_str(), DeletionReason::Requested)
        .unwrap();
    let lone_removal = dispatch();
    f.store
        .record_checkpoint_removal(lone.id.as_str(), &lone_removal)
        .unwrap();
    let conn = f.store.conn();
    let store_evidence = |sealed: &SealedEvidence| {
        checkpoint::insert_evidence(
            &conn,
            sealed,
            &sealed.evidence.canonical_bytes().unwrap(),
            1,
        )
        .unwrap();
        sealed.id.to_string()
    };
    for (other, case) in foreign_certifiers(&f.capturing.capture) {
        let wrong = evidence(
            &f.capturing,
            &other,
            complete(&f.capturing, 1 << 20).evidence.fact,
        );
        let id = store_evidence(&wrong);
        let error = conn
            .execute(
                "UPDATE checkpoints SET state = 'ready', complete_evidence_id = ?2, content_sha256 = ?3,
                     binding_sha256 = ?4, charge_bytes = ?5, logical_bytes = ?6, allocated_bytes = ?6,
                     entry_count = 7, ready_at_ms = 1, ready_boottime_ms = 1, clock_boot_id = 'b'
                 WHERE id = ?1",
                params![
                    f.capturing.id.as_str(),
                    id,
                    Digest::of(f.capturing.id.as_str().as_bytes()).to_string(),
                    Digest::of(b"binding").to_string(),
                    1i64 << 20,
                    1i64 << 19
                ],
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("helper epoch and boot"), "{case}: {error}");
    }
    let removal = f.deleting.removal.unwrap();
    for (other, case) in foreign_certifiers(&removal) {
        // Release the pin the way D3 does, but with the wrong certifier.
        let id = store_evidence(&absent(&f.deleting, &other));
        let error = conn
            .execute(
                "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'absent', release_evidence_id = ?2
                 WHERE checkpoint_id = ?1",
                params![f.deleting.id.as_str(), id],
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("pin is released only"), "{case}: {error}");
    }
    let pin = conn
        .query_row(
            &format!("SELECT {PIN_COLUMNS} FROM checkpoint_pins WHERE sandbox_id = ?1"),
            [&f.fork.id],
            pin_row,
        )
        .unwrap()
        .unwrap();
    for (other, case) in foreign_certifiers(&pin.reader) {
        let id = store_evidence(&evidence(
            &f.ready,
            &other,
            Fact::ReaderEnded {
                copy: CopyOutcome::Complete,
            },
        ));
        let error = conn
            .execute(
                "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'complete', release_evidence_id = ?2
                 WHERE sandbox_id = ?1",
                params![f.fork.id, id],
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("pin is released only"), "{case}: {error}");
    }
    // The right certifier passes the same statements: each refusal above was the binding.
    let id = store_evidence(&evidence(
        &f.ready,
        &pin.reader,
        Fact::ReaderEnded {
            copy: CopyOutcome::Complete,
        },
    ));
    conn.execute(
        "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'complete', release_evidence_id = ?2
         WHERE sandbox_id = ?1",
        params![f.fork.id, id],
    )
    .unwrap();
    let id = store_evidence(&absent(&f.deleting, &removal));
    conn.execute(
        "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'absent', release_evidence_id = ?2
         WHERE checkpoint_id = ?1",
        params![f.deleting.id.as_str(), id],
    )
    .unwrap();
    // The charge release, on a checkpoint with no pin.
    let release = |id: &str| {
        conn.execute(
            "UPDATE checkpoints SET state = 'deleted', deleted_at_ms = 1, released_at_ms = 1, release_evidence_id = ?2
             WHERE id = ?1",
            params![lone.id.as_str(), id],
        )
    };
    for (other, case) in foreign_certifiers(&lone_removal) {
        let id = store_evidence(&absent(&lone, &other));
        let error = release(&id).unwrap_err().to_string();
        assert!(error.contains("helper epoch and boot"), "{case}: {error}");
    }
    release(&store_evidence(&absent(&lone, &lone_removal))).unwrap();
}

/// Past the triggers: a writer that releases a pin or a charge, or seals READY, with a
/// self-consistent fact from the wrong helper epoch or boot, and keeps every aggregate
/// consistent so that only the evidence binding can catch it. The next decision and a
/// restart's full audit both quarantine it: degraded, charge kept, admission refused.
#[test]
fn wrong_epoch_facts_past_the_triggers_are_caught_by_the_audits() {
    #[derive(Clone, Copy, Debug)]
    enum Path {
        Complete,
        Absent,
        Pin,
    }
    for path in [Path::Complete, Path::Absent, Path::Pin] {
        for restart in [false, true] {
            let f = fixture();
            let src = f.source.clone();
            let charged_before = disk(&f.store);
            {
                let conn = Connection::open(f._tmp.path().join("kilnd.db")).unwrap();
                checkpoint::register_evidence_validator(&conn).unwrap();
                let store_evidence = |sealed: &SealedEvidence| {
                    checkpoint::insert_evidence(
                        &conn,
                        sealed,
                        &sealed.evidence.canonical_bytes().unwrap(),
                        1,
                    )
                    .unwrap();
                    sealed.id.to_string()
                };
                // Evidence rows are inserted with the triggers on: they pass, being
                // self-consistent and about an existing checkpoint generation.
                let wrong_id = match path {
                    Path::Complete => {
                        let mut other = f.capturing.capture;
                        other.helper_epoch = Id128::random();
                        store_evidence(&evidence(
                            &f.capturing,
                            &other,
                            complete(&f.capturing, 1 << 30).evidence.fact,
                        ))
                    }
                    Path::Absent => String::new(),
                    Path::Pin => {
                        let pin_reader: (String, String, String) = conn
                            .query_row(
                                "SELECT reader_operation, helper_epoch, boot_id FROM checkpoint_pins WHERE sandbox_id = ?1",
                                [&f.fork.id],
                                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                            )
                            .unwrap();
                        let reader = HelperDispatch {
                            operation: Id128::parse(&pin_reader.0).unwrap(),
                            helper_epoch: Id128::random(),
                            boot_id: Id128::parse(&pin_reader.2).unwrap(),
                        };
                        store_evidence(&evidence(
                            &f.ready,
                            &reader,
                            Fact::ReaderEnded {
                                copy: CopyOutcome::Complete,
                            },
                        ))
                    }
                };
                conn.set_db_config(
                    rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                    false,
                )
                .unwrap();
                match path {
                    Path::Complete => {
                        // Seal READY at S = R (no count change), and move the row's
                        // membership exactly as the typed path would.
                        let id = f.capturing.id.as_str();
                        let before = checkpoint::row_membership(&conn, id).unwrap();
                        conn.execute(
                            "UPDATE checkpoints SET state = 'ready', complete_evidence_id = ?2, content_sha256 = ?3,
                                 binding_sha256 = ?4, charge_bytes = max_size_bytes, logical_bytes = ?5,
                                 allocated_bytes = ?5, entry_count = 7, ready_at_ms = 1, ready_boottime_ms = 1,
                                 clock_boot_id = 'b'
                             WHERE id = ?1",
                            params![
                                id,
                                wrong_id,
                                Digest::of(id.as_bytes()).to_string(),
                                Digest::of(b"binding").to_string(),
                                1i64 << 29
                            ],
                        )
                        .unwrap();
                        let (all, settled) =
                            checkpoint::stored_checkpoint_membership(&conn).unwrap();
                        let after = checkpoint::row_membership(&conn, id).unwrap();
                        checkpoint::store_checkpoint_membership(
                            &conn,
                            all.minus(before).plus(after),
                            settled,
                        )
                        .unwrap();
                    }
                    Path::Absent => {
                        // Release `deleting`: its pins with the wrong fact, then the
                        // charge, noting it unsettled and lowering the counters the way
                        // the triggers would have.
                        let removal = f.deleting.removal.unwrap();
                        let wrong = HelperDispatch {
                            boot_id: Id128::random(),
                            ..removal
                        };
                        let id = store_evidence(&absent(&f.deleting, &wrong));
                        let charge = f.deleting.charge_bytes() as i64;
                        conn.execute_batch(&format!(
                            "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'absent', release_evidence_id = '{id}'
                                 WHERE checkpoint_id = '{c}';
                             UPDATE checkpoints SET state = 'deleted', deleted_at_ms = 1, released_at_ms = 1,
                                 release_evidence_id = '{id}' WHERE id = '{c}';
                             INSERT INTO checkpoint_unsettled VALUES ('{c}');
                             UPDATE checkpoint_counts SET live = live - 1, charged_bytes = charged_bytes - {charge}
                                 WHERE owner_uid IN (1000, -1);",
                            c = f.deleting.id
                        ))
                        .unwrap();
                    }
                    Path::Pin => {
                        conn.execute(
                            "UPDATE checkpoint_pins SET released_at_ms = 1, released_by = 'complete', release_evidence_id = ?2
                             WHERE sandbox_id = ?1",
                            params![f.fork.id, wrong_id],
                        )
                        .unwrap();
                    }
                }
            }
            let Fixture { _tmp, store, .. } = f;
            let store = if restart {
                drop(store);
                Store::open(_tmp.path()).unwrap()
            } else {
                store
            };
            store.set_clock(std::sync::Arc::new(ManualClock::default()));
            let (resources, degraded) = store.accounting_snapshot().unwrap();
            assert!(degraded, "{path:?} (restart {restart}): not degraded");
            assert!(
                resources.disk_bytes >= charged_before,
                "{path:?} (restart {restart}): freed capacity {} < {charged_before}",
                resources.disk_bytes
            );
            assert!(
                store
                    .reserve_sandbox(&row(SandboxState::Creating, 1000), roomy())
                    .is_err()
            );
            assert!(
                store
                    .reserve_checkpoint(
                        &new_checkpoint(&src, 1000, 1 << 20),
                        &CheckpointBudgets::default(),
                        roomy(),
                        None
                    )
                    .is_err()
            );
            println!(
                "{path:?} (restart {restart}): degraded, {} charged bytes kept",
                resources.disk_bytes
            );
        }
    }
}
