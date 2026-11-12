//! Ledger authority tests, with real SQLite files and no fakes of its behavior.
#![allow(clippy::type_complexity)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#![allow(clippy::disallowed_methods)]
use super::*;
use crate::helper::firecracker::config::tests::{sample_leases, sample_vector};
use crate::helper::firecracker::config::{DEFAULT_MAX_ENROLLED, MAX_ENROLLED_HARD};
use crate::helper::firecracker::identity::{GuestCid, RelayGid, RelayUid, VmmGid, VmmUid};
use crate::runtime::FencedAbsence;
use rusqlite::config::DbConfig;
use std::os::unix::fs::symlink;

const MIB: u64 = 1024 * 1024;

thread_local! {
    /// B7: the token key of the ledger this test thread provisioned last, read back
    /// from its file, so fixtures can compute helper-issued tokens the way L does.
    static TEST_KEY: std::cell::RefCell<Option<TokenKey>> = const { std::cell::RefCell::new(None) };
}

/// Reads K straight from a provisioned ledger file (tests only).
pub(in crate::helper::firecracker) fn key_from_file(config: &LedgerConfig) -> TokenKey {
    let conn = Connection::open(config.directory.join(LEDGER_DB)).unwrap();
    let key: Vec<u8> = conn
        .query_row("SELECT key FROM token_key WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    TokenKey::from_parts(config.node_id, key.try_into().unwrap())
}

/// The token L would issue for `seq` in `instance` under this thread's test ledger.
pub(in crate::helper::firecracker) fn token(instance: Id128, seq: u64) -> Id128 {
    TEST_KEY.with(|key| key.borrow().as_ref().expect("a provisioned test ledger").issue(instance, seq))
}

/// Raises an instance's exact pointer to at least `next`, as that many issuances would.
pub(in crate::helper::firecracker) fn issue_through(ledger: &Ledger, instance: Id128, next: u64) {
    ledger
        .connection()
        .execute(
            "UPDATE instance_tokens SET issue_next = MAX(issue_next, ?2) WHERE instance_id = ?1",
            params![instance.to_string(), next as i64],
        )
        .unwrap();
}

/// The pointer every fixture instance is raised to, so `request(i)`'s tokens are issued.
pub(in crate::helper::firecracker) const ISSUED_THROUGH: u64 = 1 << 16;

pub(in crate::helper::firecracker) struct TempLedger {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
    pub config: LedgerConfig,
}

pub(in crate::helper::firecracker) fn temp_ledger(ceilings: NodeCeilings) -> TempLedger {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = root.join("ledger");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = LedgerConfig {
        directory,
        policy: WalkPolicy::test_rooted(&root),
        node_id: Id128::from_bytes([0x11; 16]),
        ceilings,
        shared: SharedReserve::default(),
        max_enrolled: DEFAULT_MAX_ENROLLED,
        compaction: CompactionPolicy::default(),
    };
    Ledger::provision(&config).unwrap();
    let key = key_from_file(&config);
    TEST_KEY.with(|slot| *slot.borrow_mut() = Some(key));
    TempLedger {
        _temp: temp,
        root,
        config,
    }
}

fn instance() -> Id128 {
    Id128::from_bytes([0x22; 16])
}

fn database() -> Id128 {
    Id128::from_bytes([0x33; 16])
}

/// What root's enrollment command writes, with a unit derived from the instance.
fn enrollment_of(instance: Id128) -> Enrollment {
    Enrollment {
        instance_id: instance,
        unit: format!("kilnd-{instance}.service"),
        cgroup: format!("/system.slice/kilnd-{instance}.service"),
        uid: crate::helper::firecracker::peer::fixture_account(instance).0,
        gid: crate::helper::firecracker::peer::fixture_account(instance).1,
        executable: EnrolledExecutable {
            st_dev: 1,
            st_ino: 2,
            bytes: 3,
            sha256: Digest::of(b"kilnd"),
        },
    }
}

fn enroll(ledger: &mut Ledger, instance: Id128) {
    assert!(matches!(
        ledger
            .enroll_instance(&enrollment_of(instance), MAX_ENROLLED_HARD)
            .unwrap(),
        EnrollOutcome::Enrolled { .. }
    ));
}

fn attached(config: &LedgerConfig) -> Ledger {
    let mut ledger = Ledger::open(config.clone()).unwrap();
    enroll(&mut ledger, instance());
    issue_through(&ledger, instance(), ISSUED_THROUGH);
    assert!(matches!(
        ledger
            .attach_instance(instance(), database(), None, false)
            .unwrap(),
        AttachOutcome::Bound { .. }
    ));
    ledger
}

fn reservation() -> ResourceReservation {
    ResourceReservation {
        memory_bytes: 896 * MIB,
        disk_bytes: 1408 * MIB,
        pids: 192,
        host_cpu_millis: 1000,
        virtual_cpu_slots: 1,
        host_pids: 32,
    }
}

/// `index`'s token is seq `index + 1`, issued once `issue_through` has run.
pub(in crate::helper::firecracker) fn request(index: u8) -> AdmitRequest {
    let allocation = token(instance(), u64::from(index) + 1);
    let plan = format!("plan-{index}").into_bytes();
    AdmitRequest {
        instance_id: instance(),
        allocation_id: allocation,
        sandbox_id: format!("sb-{index:016x}"),
        plan_version: 1,
        plan_digest: Digest::of(&plan),
        plan,
        profile: "offline-768-v1".into(),
        manifest_sha256: Digest::of(b"manifest"),
        host_spec_sha256: Digest::of(b"host"),
        guest_exec_spec_sha256: Digest::of(b"guest"),
        reservation: reservation(),
        leases: sample_leases(index as u32),
        work_uuid: "12345678-1234-4234-8234-123456789abc".into(),
        executables: sample_vector(),
        stop_authority: StopAuthority::standard(format!("kilnd-firecracker/x/fc-{allocation}")),
        supervisor: WorkerIntentSpec {
            mode: "supervisor".into(),
            allowed_names: vec!["work.xfs".into()],
            cgroup: "control".into(),
            image: sample_vector()[3],
        },
    }
}

fn accepted(outcome: AdmitOutcome) -> (u64, i64, bool) {
    match outcome {
        AdmitOutcome::Accepted {
            generation,
            worker_id,
            replay,
            ..
        } => (generation, worker_id, replay),
        other => panic!("not accepted: {other:?}"),
    }
}

fn fence_request(index: u8) -> FenceRequest {
    let admitted = request(index);
    FenceRequest {
        instance_id: admitted.instance_id,
        allocation_id: admitted.allocation_id,
        sandbox_id: admitted.sandbox_id,
        plan_digest: admitted.plan_digest,
        observations: "permits=settled;namespace=absent".into(),
    }
}

/// B7: `request(index)` in another instance, under that instance's own issued token
/// (call `issue_through` for it first). Tokens are bound to their instance, so the
/// same seq there is a different token.
fn request_in(owner: Id128, index: u8) -> AdmitRequest {
    let mut admitted = request(index);
    admitted.instance_id = owner;
    admitted.allocation_id = token(owner, u64::from(index) + 1);
    admitted.stop_authority = StopAuthority::standard(format!(
        "kilnd-firecracker/x/fc-{}",
        admitted.allocation_id
    ));
    admitted
}

/// `fence_request(index)` for `request_in(owner, index)`.
fn fence_request_in(owner: Id128, index: u8) -> FenceRequest {
    let admitted = request_in(owner, index);
    FenceRequest {
        instance_id: admitted.instance_id,
        allocation_id: admitted.allocation_id,
        sandbox_id: admitted.sandbox_id,
        plan_digest: admitted.plan_digest,
        observations: "permits=settled;namespace=absent".into(),
    }
}

fn absent(outcome: FenceOutcome) -> (Vec<u8>, bool) {
    match outcome {
        FenceOutcome::Absent { receipt, replay } => (receipt, replay),
        other => panic!("not absent: {other:?}"),
    }
}

fn unrestricted() -> NodeCeilings {
    NodeCeilings {
        slots: 1 << 20,
        memory_bytes: 1 << 60,
        disk_bytes: 1 << 60,
        host_cpu_millis: 1 << 60,
        virtual_cpu_slots: 1 << 60,
        pids: 1 << 60,
        host_pids: 1 << 60,
    }
}

#[test]
fn exit6_missing_partial_or_corrupt_ledgers_refuse_and_never_recreate() {
    let fixture = temp_ledger(NodeCeilings::default());
    let db = fixture.config.directory.join(LEDGER_DB);
    let good = {
        let mut ledger = attached(&fixture.config);
        accepted(ledger.admit_intent(&request(1)).unwrap());
        drop(ledger);
        std::fs::read(&db).unwrap()
    };
    let restore = |bytes: &[u8]| {
        for sidecar in ["node.db-wal", "node.db-shm"] {
            let _ = std::fs::remove_file(fixture.config.directory.join(sidecar));
        }
        let _ = std::fs::remove_file(&db);
        std::fs::write(&db, bytes).unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    };

    // Missing: a clear error, and the missing file stays missing.
    std::fs::remove_file(&db).unwrap();
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Missing(_))
    ));
    assert!(!db.exists(), "open must never create an empty authority");

    // Zero-length, truncated and scribbled files.
    for damaged in [Vec::new(), good[..good.len() / 2].to_vec(), {
        let mut header = good.clone();
        header[0] ^= 0xff;
        header
    }] {
        restore(&damaged);
        assert!(Ledger::open(fixture.config.clone()).is_err());
    }

    // A foreign node's ledger.
    restore(&good);
    let mut foreign = fixture.config.clone();
    foreign.node_id = Id128::from_bytes([0x99; 16]);
    assert!(matches!(
        Ledger::open(foreign),
        Err(LedgerError::Corrupt(reason)) if reason.contains("belongs to node")
    ));

    // A dropped guard is a changed schema, even if the data is untouched.
    restore(&good);
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("DROP TRIGGER retired_tokens_no_delete;")
            .unwrap();
    }
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Corrupt(reason)) if reason.contains("schema differs")
    ));

    // A row-level rewrite that SQLite's own checks cannot see.
    restore(&good);
    {
        let conn = Connection::open(&db).unwrap();
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .unwrap();
        conn.execute("UPDATE allocation_plans SET plan = x'00'", [])
            .unwrap();
    }
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Corrupt(reason)) if reason.contains("digest")
    ));

    // A lost claim on an active allocation.
    restore(&good);
    {
        let conn = Connection::open(&db).unwrap();
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.execute("DELETE FROM capacity_claims", []).unwrap();
    }
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Corrupt(reason)) if reason.contains("lost its plan")
    ));

    // A rolled-back generation counter could reissue a receipt generation.
    restore(&good);
    {
        let conn = Connection::open(&db).unwrap();
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .unwrap();
        conn.execute("UPDATE generation_counter SET value = 1", [])
            .unwrap();
    }
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Corrupt(reason)) if reason.contains("rolled back")
    ));

    // The intact copy still works, so these refusals were about their damage.
    restore(&good);
    assert!(Ledger::open(fixture.config.clone()).is_ok());
}

#[test]
fn exit6_a_corrupt_receipt_row_fails_the_open() {
    let fixture = temp_ledger(NodeCeilings::default());
    let db = fixture.config.directory.join(LEDGER_DB);
    {
        let mut ledger = attached(&fixture.config);
        absent(ledger.commit_fence(&fence_request(1)).unwrap());
    }
    {
        let conn = Connection::open(&db).unwrap();
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .unwrap();
        conn.execute("UPDATE retired_tokens SET receipt = x'7b7d'", [])
            .unwrap();
    }
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Corrupt(reason)) if reason.contains("receipt")
    ));
}

#[test]
fn exit6_unsafe_ledger_files_refuse_before_sqlite_touches_them() {
    let fixture = temp_ledger(NodeCeilings::default());
    let db = fixture.config.directory.join(LEDGER_DB);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Unsafe(_))
    ));
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = fixture.root.join("alias");
    std::fs::hard_link(&db, &alias).unwrap();
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Unsafe(_))
    ));
    std::fs::remove_file(alias).unwrap();
    std::fs::set_permissions(
        &fixture.config.directory,
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Unsafe(_))
    ));
    std::fs::set_permissions(
        &fixture.config.directory,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let moved = fixture.root.join("real.db");
    std::fs::rename(&db, &moved).unwrap();
    symlink(&moved, &db).unwrap();
    assert!(Ledger::open(fixture.config.clone()).is_err());
    std::fs::remove_file(&db).unwrap();
    std::fs::rename(&moved, &db).unwrap();
    // A sidecar with a wider mode is refused the same way.
    let wal = fixture.config.directory.join("node.db-wal");
    std::fs::write(&wal, b"").unwrap();
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Unsafe(_))
    ));
    std::fs::remove_file(&wal).unwrap();
    assert!(Ledger::open(fixture.config.clone()).is_ok());
}

#[test]
fn exit6_provisioning_refuses_any_existing_file_and_connection_pragmas_hold() {
    let fixture = temp_ledger(NodeCeilings::default());
    assert!(matches!(
        Ledger::provision(&fixture.config),
        Err(LedgerError::Exists(_))
    ));
    let ledger = Ledger::open(fixture.config.clone()).unwrap();
    let conn = ledger.connection();
    let pragma = |name: &str| -> i64 { conn.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
    assert_eq!(pragma("foreign_keys"), 1);
    assert_eq!(pragma("trusted_schema"), 0);
    assert_eq!(pragma("synchronous"), 2);
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    for name in [LEDGER_DB, "node.db-wal", "node.db-shm"] {
        let meta = std::fs::symlink_metadata(fixture.config.directory.join(name)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600, "{name}");
        assert_eq!(meta.nlink(), 1, "{name}");
    }
}

#[test]
fn exit6_replay_after_commit_and_reply_loss_returns_the_identical_bytes() {
    let fixture = temp_ledger(NodeCeilings::default());
    let (first, replayed) = {
        let mut ledger = attached(&fixture.config);
        accepted(ledger.admit_intent(&request(1)).unwrap());
        ledger
            .settle_unstarted(instance(), request(1).allocation_id)
            .unwrap();
        // Commit, then lose the reply by dropping everything before anyone sees it.
        absent(ledger.commit_fence(&fence_request(1)).unwrap())
    };
    assert!(!replayed);
    let mut reopened = Ledger::open(fixture.config.clone()).unwrap();
    let (again, replayed) = absent(reopened.commit_fence(&fence_request(1)).unwrap());
    assert!(replayed);
    assert_eq!(
        again, first,
        "a replay is the original receipt, byte for byte"
    );
    let receipt = FencedAbsence::decode(&first).unwrap();
    assert_eq!(receipt.node_id(), fixture.config.node_id);
    assert_eq!(receipt.instance_id(), instance());
    assert_eq!(receipt.allocation_id(), request(1).allocation_id);
    assert_eq!(receipt.plan_digest(), request(1).plan_digest);
    assert!(receipt.helper_generation() > 0);
    // A late Create finds it unchanged, even after a process restart.
    match reopened.admit_intent(&request(1)).unwrap() {
        AdmitOutcome::Fenced { receipt } => assert_eq!(receipt, first),
        other => panic!("{other:?}"),
    }
    // And its claim and identities stayed released.
    let snapshot = reopened.accounting(None).unwrap();
    assert_eq!(snapshot.claimed, ClaimTotals::default());
    assert!(reopened.claimed_identities().unwrap().uids.is_empty());
    assert_eq!(snapshot.retired_tokens, 1);
}

#[test]
fn exit6_a_failed_commit_leaves_no_receipt_and_the_claim_held() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    accepted(ledger.admit_intent(&request(1)).unwrap());
    ledger
        .settle_unstarted(instance(), request(1).allocation_id)
        .unwrap();
    let before = ledger.accounting(None).unwrap();
    ledger.fail_next_commit();
    assert!(matches!(
        ledger.commit_fence(&fence_request(1)),
        Err(LedgerError::CommitFailed)
    ));
    assert_eq!(ledger.accounting(None).unwrap().claimed, before.claimed);
    assert!(matches!(
        ledger
            .lookup_token(
                instance(),
                request(1).allocation_id,
                &request(1).plan_digest
            )
            .unwrap(),
        TokenLookup::Active { .. }
    ));
    let (receipt, replay) = absent(ledger.commit_fence(&fence_request(1)).unwrap());
    assert!(!replay);
    assert!(FencedAbsence::decode(&receipt).is_ok());
}

#[test]
fn exit6_unsettled_workers_and_conflicts_forbid_the_fence() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    let (_, worker, _) = accepted(ledger.admit_intent(&request(1)).unwrap());
    ledger
        .record_worker_identity(worker, 123, 456, "boot")
        .unwrap();
    assert_eq!(
        ledger.commit_fence(&fence_request(1)).unwrap(),
        FenceOutcome::Unsettled { workers: 1 }
    );
    // An identified worker is not "unstarted".
    ledger
        .settle_unstarted(instance(), request(1).allocation_id)
        .unwrap();
    assert_eq!(
        ledger.commit_fence(&fence_request(1)).unwrap(),
        FenceOutcome::Unsettled { workers: 1 }
    );
    // A different plan or namespace is a conflict, never absence.
    let mut wrong_plan = fence_request(1);
    wrong_plan.plan_digest = Digest::of(b"other");
    assert!(matches!(
        ledger.commit_fence(&wrong_plan).unwrap(),
        FenceOutcome::Conflict { .. }
    ));
    let mut wrong_instance = fence_request(1);
    wrong_instance.instance_id = Id128::from_bytes([0x77; 16]);
    assert!(matches!(
        ledger.commit_fence(&wrong_instance).unwrap(),
        FenceOutcome::Conflict { .. }
    ));
    let mut wrong_sandbox = fence_request(1);
    wrong_sandbox.sandbox_id = "sb-ffffffffffffffff".into();
    ledger.settle_worker(worker, "exit:0").unwrap();
    assert!(matches!(
        ledger.commit_fence(&wrong_sandbox).unwrap(),
        FenceOutcome::Conflict { .. }
    ));
    // A quarantined allocation has uncertain identity.
    let generation = match ledger
        .lookup_token(
            instance(),
            request(1).allocation_id,
            &request(1).plan_digest,
        )
        .unwrap()
    {
        TokenLookup::Active { generation, .. } => generation,
        other => panic!("{other:?}"),
    };
    ledger
        .advance_phase(
            instance(),
            request(1).allocation_id,
            generation,
            "quarantined",
        )
        .unwrap();
    assert!(matches!(
        ledger.commit_fence(&fence_request(1)).unwrap(),
        FenceOutcome::Conflict { .. }
    ));
    // Nothing above released anything.
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
}

#[test]
fn exit6_receipts_generations_and_fences_never_move_backward() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = attached(&fixture.config);
    let mut last = 0;
    for index in 1..=5u8 {
        let (receipt, _) = absent(ledger.commit_fence(&fence_request(index)).unwrap());
        let generation = FencedAbsence::decode(&receipt).unwrap().helper_generation();
        assert!(
            generation > last,
            "generations are strictly monotonic and never zero"
        );
        last = generation;
    }
    assert!(ledger.generation().unwrap() >= last);
    // A retired token cannot come back, even through direct SQL.
    let conn = ledger.connection();
    assert!(
        conn.execute(
            "INSERT INTO allocations (allocation_id, instance_id, sandbox_id, backend_id,
                plan_version, plan_digest, profile, manifest_sha256, host_spec_sha256,
                guest_exec_spec_sha256, work_uuid, stop_authority, phase,
                created_generation, updated_generation)
             VALUES (?1, ?2, 'sb-x', 'fc-x', 1, 'd', 'p', 'm', 'h', 'g', 'u', 's', 'intent', 1, 1)",
            params![request(1).allocation_id.to_string(), instance().to_string()],
        )
        .is_err()
    );
}

#[test]
fn exit6_stale_writers_lose_the_generation_compare() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    let (generation, _, _) = accepted(ledger.admit_intent(&request(1)).unwrap());
    let allocation = request(1).allocation_id;
    let newer = ledger
        .advance_phase(instance(), allocation, generation, "preparing")
        .unwrap();
    assert!(newer > generation);
    assert!(matches!(
        ledger.advance_phase(instance(), allocation, generation, "stopped"),
        Err(LedgerError::StaleGeneration)
    ));
    match ledger
        .lookup_token(instance(), allocation, &request(1).plan_digest)
        .unwrap()
    {
        TokenLookup::Active { phase, .. } => assert_eq!(phase, "preparing"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn exit6_lowered_limits_deny_new_work_and_discount_nothing() {
    let fixture = temp_ledger(NodeCeilings::default());
    let claimed = {
        let mut ledger = attached(&fixture.config);
        for index in 1..=3u8 {
            accepted(ledger.admit_intent(&request(index)).unwrap());
        }
        ledger.accounting(None).unwrap().claimed
    };
    assert_eq!(claimed.slots, 3);
    let mut lowered = fixture.config.clone();
    lowered.ceilings.slots = 1;
    lowered.ceilings.memory_bytes = 1024 * MIB;
    let mut ledger = Ledger::open(lowered).unwrap();
    let snapshot = ledger.accounting(None).unwrap();
    assert_eq!(
        snapshot.claimed, claimed,
        "existing commitments are untouched"
    );
    assert!(snapshot.over_committed);
    assert!(matches!(
        ledger.admit_intent(&request(4)).unwrap(),
        AdmitOutcome::Capacity { .. }
    ));
    // Cleanup still works under the lowered limit, and only ABSENT frees anything.
    ledger
        .settle_unstarted(instance(), request(1).allocation_id)
        .unwrap();
    absent(ledger.commit_fence(&fence_request(1)).unwrap());
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 2);
}

#[test]
fn exit6_fence_allowance_stops_new_tokens_before_accepted_ones_cannot_fence() {
    let fixture = temp_ledger(unrestricted());
    let mut tight = fixture.config.clone();
    tight.shared.fence_allowance_bytes = 16 * FENCE_ENTRY_BOUND;
    let mut ledger = Ledger::open(tight.clone()).unwrap();
    enroll(&mut ledger, instance());
    issue_through(&ledger, instance(), ISSUED_THROUGH);
    assert!(matches!(
        ledger.attach_instance(instance(), database(), None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
    // B7 (RTC-17): 16 entries, a pool of 4 and one spare leave E = 11; 8 policy slots
    // give a share of 1, and one instance may also borrow the 3-entry remainder.
    let slots = u64::from(tight.max_enrolled);
    let entries = 16 - 16 / 4 - 1;
    let fits = entries / slots + entries % slots;
    assert_eq!(fits, 4);
    for index in 1..=fits as u8 {
        assert!(ledger.admitted_headroom(instance()).unwrap(), "{index}");
        accepted(ledger.admit_intent(&request(index)).unwrap());
    }
    assert!(!ledger.admitted_headroom(instance()).unwrap());
    let refused = fits as u8 + 1;
    assert_eq!(
        ledger.admit_intent(&request(refused)).unwrap(),
        AdmitOutcome::Capacity {
            dimension: Dimension::LedgerSpace
        }
    );
    // Every token already accepted can still reach its permanent fence.
    for index in 1..=fits as u8 {
        ledger
            .settle_unstarted(instance(), request(index).allocation_id)
            .unwrap();
        let (_, replay) = absent(ledger.commit_fence(&fence_request(index)).unwrap());
        assert!(!replay);
    }
    // Retained fences keep their space until compaction passes them: still no new token.
    assert_eq!(
        ledger.admit_intent(&request(refused)).unwrap(),
        AdmitOutcome::Capacity {
            dimension: Dimension::LedgerSpace
        }
    );
}

#[test]
fn exit3_each_dimension_exhausts_independently_with_checked_arithmetic() {
    let reserve = SharedReserve::default();
    let free = unrestricted();
    let cases: [(&str, Dimension, Box<dyn Fn(&mut NodeCeilings)>); 7] = [
        ("slots", Dimension::Slots, Box::new(|c| c.slots = 1)),
        (
            "memory",
            Dimension::Memory,
            Box::new(move |c| c.memory_bytes = reserve.memory_bytes + 896 * MIB),
        ),
        (
            "disk",
            Dimension::Disk,
            Box::new(move |c| c.disk_bytes = reserve.total_disk().unwrap() + 1408 * MIB),
        ),
        (
            "cpu",
            Dimension::HostCpu,
            Box::new(move |c| c.host_cpu_millis = reserve.host_cpu_millis + 1000),
        ),
        (
            "vcpu",
            Dimension::VirtualCpu,
            Box::new(|c| c.virtual_cpu_slots = 1),
        ),
        (
            "pids",
            Dimension::Pids,
            Box::new(move |c| c.pids = reserve.pids + 192),
        ),
        (
            "host pids",
            Dimension::HostPids,
            Box::new(move |c| c.host_pids = reserve.host_pids + 32),
        ),
    ];
    for (name, dimension, restrict) in cases {
        let mut ceilings = free;
        restrict(&mut ceilings);
        let fixture = temp_ledger(ceilings);
        let mut ledger = attached(&fixture.config);
        accepted(ledger.admit_intent(&request(1)).unwrap());
        assert_eq!(
            ledger.admit_intent(&request(2)).unwrap(),
            AdmitOutcome::Capacity { dimension },
            "{name} must be the refusing dimension"
        );
        let snapshot = ledger.accounting(None).unwrap();
        assert_eq!(snapshot.claimed.slots, 1, "{name}");
        assert!(!snapshot.over_committed, "{name}");
        // Rejection left no partial row behind.
        assert!(matches!(
            ledger
                .lookup_token(
                    instance(),
                    request(2).allocation_id,
                    &request(2).plan_digest
                )
                .unwrap(),
            TokenLookup::Unknown
        ));
    }
    // A sum that would overflow fails closed rather than wrapping to a small charge.
    let fixture = temp_ledger(NodeCeilings {
        memory_bytes: u64::MAX,
        ..free
    });
    let mut ledger = attached(&fixture.config);
    let mut huge = request(1);
    huge.reservation.memory_bytes = i64::MAX as u64;
    accepted(ledger.admit_intent(&huge).unwrap());
    let mut more = request(2);
    more.reservation.memory_bytes = i64::MAX as u64;
    let refused = ledger.admit_intent(&more);
    assert!(
        matches!(refused, Err(LedgerError::Overflow(_))),
        "{refused:?}"
    );
    let mut negative = request(3);
    negative.reservation.memory_bytes = u64::MAX;
    assert!(ledger.admit_intent(&negative).is_err());
}

#[test]
fn exit3_every_identity_type_collides_atomically_and_never_substitutes() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = attached(&fixture.config);
    accepted(ledger.admit_intent(&request(1)).unwrap());
    let held = sample_leases(1);
    let mutations: [(LeaseKind, Box<dyn Fn(&mut AdmitRequest)>); 5] = [
        (
            LeaseKind::VmmUid,
            Box::new(move |r| r.leases.vmm_uid = held.vmm_uid),
        ),
        (
            LeaseKind::RelayUid,
            Box::new(move |r| r.leases.relay_uid = RelayUid(held.vmm_uid.0)),
        ),
        (
            LeaseKind::VmmGid,
            Box::new(move |r| r.leases.vmm_gid = held.vmm_gid),
        ),
        (
            LeaseKind::RelayGid,
            Box::new(move |r| r.leases.relay_gid = RelayGid(held.vmm_gid.0)),
        ),
        (LeaseKind::Cid, Box::new(move |r| r.leases.cid = held.cid)),
    ];
    for (index, (kind, mutate)) in mutations.into_iter().enumerate() {
        let mut colliding = request(10 + index as u8);
        mutate(&mut colliding);
        assert_eq!(
            ledger.admit_intent(&colliding).unwrap(),
            AdmitOutcome::Collision { kind },
            "{kind:?}"
        );
        assert!(matches!(
            ledger
                .lookup_token(instance(), colliding.allocation_id, &colliding.plan_digest)
                .unwrap(),
            TokenLookup::Unknown
        ));
    }
    // One plan's VMM and relay identities cannot share a value either.
    let mut own = request(20);
    own.leases.relay_uid = RelayUid(own.leases.vmm_uid.0);
    assert!(matches!(
        ledger.admit_intent(&own).unwrap(),
        AdmitOutcome::Collision {
            kind: LeaseKind::RelayUid
        }
    ));
    // A UID and GID of the same number are separate namespaces and may coexist.
    let mut equal = request(21);
    equal.leases.vmm_uid = VmmUid(400_000);
    equal.leases.relay_uid = RelayUid(400_001);
    equal.leases.vmm_gid = VmmGid(400_000);
    equal.leases.relay_gid = RelayGid(400_001);
    equal.leases.cid = GuestCid(9000);
    accepted(ledger.admit_intent(&equal).unwrap());
    // Fencing the holder frees its identities for a later claim, and only then.
    ledger
        .settle_unstarted(instance(), request(1).allocation_id)
        .unwrap();
    absent(ledger.commit_fence(&fence_request(1)).unwrap());
    let mut reuse = request(22);
    reuse.leases = held;
    accepted(ledger.admit_intent(&reuse).unwrap());
}

#[test]
fn exit2_a_revocation_seen_at_the_commit_point_leaves_no_row_or_claim() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    assert_eq!(
        ledger
            .admit_intent_authorized(&request(1), &|| false)
            .unwrap(),
        AdmitOutcome::Revoked
    );
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 0);
    assert!(ledger.claimed_identities().unwrap().uids.is_empty());
    assert!(matches!(
        ledger
            .lookup_token(
                instance(),
                request(1).allocation_id,
                &request(1).plan_digest
            )
            .unwrap(),
        TokenLookup::Unknown
    ));
    // Nothing about the token was burned: an authorized attempt can still commit.
    accepted(
        ledger
            .admit_intent_authorized(&request(1), &|| true)
            .unwrap(),
    );
    // An existing record answers before authority is even asked.
    assert!(matches!(
        ledger
            .admit_intent_authorized(&request(1), &|| false)
            .unwrap(),
        AdmitOutcome::Accepted { replay: true, .. }
    ));
}

#[test]
fn exit3_allocation_and_sandbox_are_unique_within_an_instance_and_nowhere_else() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = attached(&fixture.config);
    let other = Id128::from_bytes([0x44; 16]);
    enroll(&mut ledger, other);
    assert!(matches!(
        ledger
            .attach_instance(other, Id128::from_bytes([0x55; 16]), None, false)
            .unwrap(),
        AttachOutcome::Bound { .. }
    ));
    let (generation, worker, replay) = accepted(ledger.admit_intent(&request(1)).unwrap());
    assert!(!replay);
    // The exact token is idempotent: same generation and worker, no second claim.
    assert_eq!(
        accepted(ledger.admit_intent(&request(1)).unwrap()),
        (generation, worker, true)
    );
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
    // Same allocation, another plan or another sandbox, in this instance.
    let mut replanned = request(1);
    replanned.plan = b"other".to_vec();
    replanned.plan_digest = Digest::of(&replanned.plan);
    assert!(matches!(
        ledger.admit_intent(&replanned).unwrap(),
        AdmitOutcome::Conflict { .. }
    ));
    let mut resandboxed = request(1);
    resandboxed.sandbox_id = "sb-ffffffffffffffff".into();
    assert!(matches!(
        ledger.admit_intent(&resandboxed).unwrap(),
        AdmitOutcome::Conflict { .. }
    ));
    let mut same_sandbox = request(2);
    same_sandbox.sandbox_id = request(1).sandbox_id;
    assert!(matches!(
        ledger.admit_intent(&same_sandbox).unwrap(),
        AdmitOutcome::Conflict { .. }
    ));
    // An instance nobody attached cannot hold capacity.
    // B7: a never-enrolled instance has no issue pointer, so nothing verifies there;
    // an enrolled one that never attached still answers InstanceMismatch.
    let stranger = Id128::from_bytes([0x66; 16]);
    let mut unenrolled = request(3);
    unenrolled.instance_id = stranger;
    assert!(matches!(
        ledger.admit_intent(&unenrolled).unwrap(),
        AdmitOutcome::Conflict { .. }
    ));
    enroll(&mut ledger, stranger);
    issue_through(&ledger, stranger, ISSUED_THROUGH);
    assert_eq!(
        ledger.admit_intent(&request_in(stranger, 3)).unwrap(),
        AdmitOutcome::InstanceMismatch
    );
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
    // The same seq and sandbox in another instance are another token entirely.
    // B7: a copy of this instance's token does not verify there and changes nothing.
    issue_through(&ledger, other, ISSUED_THROUGH);
    let mut copied = request(1);
    copied.instance_id = other;
    copied.leases = sample_leases(9);
    assert!(matches!(
        ledger.admit_intent(&copied).unwrap(),
        AdmitOutcome::Conflict { .. }
    ));
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
    let mut foreign = request_in(other, 1);
    foreign.leases = sample_leases(9);
    assert_eq!(foreign.sandbox_id, request(1).sandbox_id);
    let (_, _, replay) = accepted(ledger.admit_intent(&foreign).unwrap());
    assert!(!replay);
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 2);
    // Host identities really are one namespace, so those alone still collide.
    let mut same_lease = request_in(other, 4);
    same_lease.leases = sample_leases(9);
    assert!(matches!(
        ledger.admit_intent(&same_lease).unwrap(),
        AdmitOutcome::Collision { .. }
    ));
}

#[test]
fn b3r_01_a_fence_from_another_instance_never_reaches_a_token() {
    let fixture = temp_ledger(unrestricted());
    let attacker = Id128::from_bytes([0x44; 16]);
    {
        let mut ledger = attached(&fixture.config);
        enroll(&mut ledger, attacker);
        ledger
            .attach_instance(attacker, Id128::from_bytes([0x55; 16]), None, false)
            .unwrap();
        issue_through(&ledger, attacker, ISSUED_THROUGH);
        // The attacker copied the victim's token before C2.
        // B7: it does not verify in the attacker's instance, so the fence is refused
        // and writes nothing at all: no row, no generation, no quota spent.
        let copied = request(1);
        let mut aimed = fence_request(1);
        aimed.instance_id = attacker;
        let generation = ledger.generation().unwrap();
        let changes = ledger.connection().total_changes();
        assert!(matches!(
            ledger.commit_fence(&aimed).unwrap(),
            FenceOutcome::Conflict { .. }
        ));
        assert_eq!(ledger.connection().total_changes(), changes);
        assert_eq!(ledger.generation().unwrap(), generation);
        assert_eq!(
            never_admitted_fences(ledger.connection(), attacker).unwrap(),
            0
        );
        // The attacker's own token with the same seq is another token: its namespace
        // honestly has nothing by that name, so that fence commits, in its namespace.
        let own = fence_request_in(attacker, 1);
        assert_ne!(own.allocation_id, copied.allocation_id);
        let FenceOutcome::Absent { receipt, .. } = ledger.commit_fence(&own).unwrap() else {
            panic!("the attacker's namespace is absent");
        };
        let receipt = FencedAbsence::decode(&receipt).unwrap();
        assert_eq!(receipt.instance_id(), attacker);
        // Visible only in that namespace, and the victim's Create finds nothing.
        assert_eq!(
            ledger
                .lookup_token(instance(), copied.allocation_id, &copied.plan_digest)
                .unwrap(),
            TokenLookup::Unknown
        );
        assert_eq!(
            ledger
                .inspect(instance(), copied.allocation_id, &copied.plan_digest)
                .unwrap(),
            TokenLookup::Unknown
        );
        // That is a permanent row, and it still means nothing to the victim's token.
        drop(ledger);
    }
    let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
    let copied = request(1);
    let (_, worker, replay) = accepted(ledger.admit_intent(&copied).unwrap());
    assert!(!replay);
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
    assert!(matches!(
        ledger.commit_fence(&fence_request(1)).unwrap(),
        FenceOutcome::Unsettled { workers: 1 }
    ));
    ledger.settle_worker(worker, "exit:0").unwrap();
    let FenceOutcome::Absent { receipt, replay } = ledger.commit_fence(&fence_request(1)).unwrap()
    else {
        panic!("the victim fences its own token exactly");
    };
    assert!(!replay);
    let receipt = FencedAbsence::decode(&receipt).unwrap();
    assert_eq!(receipt.instance_id(), instance());
    assert_eq!(receipt.allocation_id(), copied.allocation_id);
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 0);
    // The quota the attacker spent is its own.
    assert_eq!(
        never_admitted_fences(ledger.connection(), attacker).unwrap(),
        1
    );
    assert_eq!(
        never_admitted_fences(ledger.connection(), instance()).unwrap(),
        0
    );
}

#[test]
fn b3r_01_every_row_a_claim_or_fence_writes_names_its_instance() {
    let fixture = temp_ledger(unrestricted());
    let other = Id128::from_bytes([0x44; 16]);
    let mut ledger = attached(&fixture.config);
    enroll(&mut ledger, other);
    ledger
        .attach_instance(other, Id128::from_bytes([0x55; 16]), None, false)
        .unwrap();
    let mine = request(1);
    let (generation, worker, _) = accepted(ledger.admit_intent(&mine).unwrap());
    // B7: the other instance's token for the same seq is its own, not a copy.
    issue_through(&ledger, other, ISSUED_THROUGH);
    let mut theirs = request_in(other, 1);
    theirs.leases = sample_leases(9);
    let (their_generation, their_worker, _) = accepted(ledger.admit_intent(&theirs).unwrap());
    // Advancing, stopping or settling one leaves the other's row exactly as it was.
    ledger
        .advance_phase(other, theirs.allocation_id, their_generation, "preparing")
        .unwrap();
    assert!(matches!(
        ledger.advance_phase(instance(), mine.allocation_id, their_generation, "stopped"),
        Err(LedgerError::StaleGeneration)
    ));
    // Naming the victim's token from the other namespace reaches no row either.
    assert!(matches!(
        ledger.advance_phase(other, mine.allocation_id, generation, "stopped"),
        Err(LedgerError::StaleGeneration)
    ));
    ledger.settle_unstarted(other, theirs.allocation_id).unwrap();
    ledger.settle_unstarted(other, mine.allocation_id).unwrap();
    let lookup = ledger
        .lookup_token(instance(), mine.allocation_id, &mine.plan_digest)
        .unwrap();
    let TokenLookup::Active {
        generation: current,
        phase,
        unsettled_workers,
        ..
    } = lookup
    else {
        panic!("{lookup:?}");
    };
    assert_eq!((current, phase.as_str()), (generation, "intent"));
    assert_eq!(
        unsettled_workers, 1,
        "the other instance settled only its own"
    );
    ledger.settle_worker(their_worker, "exit:0").unwrap();
    let their_fence = fence_request_in(other, 1);
    assert!(matches!(
        ledger.commit_fence(&their_fence).unwrap(),
        FenceOutcome::Absent { .. }
    ));
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
    let conn = ledger.connection();
    let held: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM capacity_claims WHERE instance_id = ?1
             AND released_generation IS NULL",
            [instance().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(held, 1);
    let leases: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM identity_leases WHERE instance_id = ?1
             AND released_generation IS NULL",
            [instance().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leases, 5);
    let plans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM allocation_plans WHERE instance_id = ?1",
            [instance().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(plans, 1);
    ledger.settle_worker(worker, "exit:0").unwrap();
    assert!(matches!(
        ledger.commit_fence(&fence_request(1)).unwrap(),
        FenceOutcome::Absent { .. }
    ));
}

#[test]
fn b3r_02_one_account_serves_one_instance() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
    let first = enrollment_of(instance());
    assert!(matches!(
        ledger.enroll_instance(&first, 8).unwrap(),
        EnrollOutcome::Enrolled { .. }
    ));
    let other = Id128::from_bytes([0x44; 16]);
    // The same UID, or the same GID, under another instance and another unit.
    let mut same_uid = enrollment_of(other);
    same_uid.uid = first.uid;
    assert_eq!(
        ledger.enroll_instance(&same_uid, 8).unwrap(),
        EnrollOutcome::AccountTaken
    );
    let mut same_gid = enrollment_of(other);
    same_gid.gid = first.gid;
    assert_eq!(
        ledger.enroll_instance(&same_gid, 8).unwrap(),
        EnrollOutcome::AccountTaken
    );
    assert!(ledger.enrollment(other).unwrap().is_none());
    // Nor can a later re-enrollment move onto an account someone else holds.
    assert!(matches!(
        ledger.enroll_instance(&enrollment_of(other), 8).unwrap(),
        EnrollOutcome::Enrolled { .. }
    ));
    let mut moved = enrollment_of(other);
    moved.uid = first.uid;
    assert_eq!(
        ledger.enroll_instance(&moved, 8).unwrap(),
        EnrollOutcome::AccountTaken
    );
    // Its own account again is fine, and root can never be one.
    assert!(matches!(
        ledger.enroll_instance(&first, 8).unwrap(),
        EnrollOutcome::Updated { .. }
    ));
    let mut root = enrollment_of(Id128::from_bytes([0x45; 16]));
    root.uid = 0;
    assert!(ledger.enroll_instance(&root, 8).is_err());
    // What H partitions by comes back with every instance.
    let enrolled = ledger.replay().unwrap().enrolled;
    assert_eq!(enrolled.len(), 2);
    assert!(enrolled.iter().any(|account| {
        account.instance_id == instance() && account.uid == first.uid && account.gid == first.gid
    }));
}

/// B3F-03: a whole-node image change is one transaction, and it can change nothing else.
#[test]
fn b3f_03_images_change_for_all_enrolled_instances_or_for_none() {
    let temp = temp_ledger(NodeCeilings::default());
    let mut ledger = Ledger::open(temp.config.clone()).unwrap();
    let (first, second) = (Id128::from_bytes([0x41; 16]), Id128::from_bytes([0x42; 16]));
    enroll(&mut ledger, first);
    enroll(&mut ledger, second);
    let before = ledger.enrollments().unwrap();
    assert_eq!(before.len(), 2);
    let image = EnrolledExecutable {
        st_dev: 7,
        st_ino: 8,
        bytes: 9,
        sha256: Digest::of(b"next kilnd"),
    };
    let next: Vec<Enrollment> = before
        .iter()
        .cloned()
        .map(|row| Enrollment {
            executable: image,
            ..row
        })
        .collect();
    let refused = |ledger: &mut Ledger, rows: &[Enrollment]| {
        let generation = ledger.generation().unwrap();
        assert_eq!(
            ledger.set_enrolled_images(rows).unwrap(),
            EnrolledImagesOutcome::IdentityChanged
        );
        assert_eq!(ledger.enrollments().unwrap(), before, "nothing was written");
        assert_eq!(ledger.generation().unwrap(), generation);
    };
    // Every row is named, and only rows that exist.
    refused(&mut ledger, &next[..1]);
    refused(&mut ledger, &[next[0].clone(), next[0].clone()]);
    refused(&mut ledger, &[]);
    let stranger = Enrollment {
        instance_id: Id128::from_bytes([0x43; 16]),
        ..next[1].clone()
    };
    refused(&mut ledger, &[next[0].clone(), stranger]);
    // No binding can travel with the image: one bad row leaves the good one unwritten.
    for changed in [
        Enrollment {
            unit: "other.service".into(),
            ..next[1].clone()
        },
        Enrollment {
            cgroup: "/system.slice/other.service".into(),
            ..next[1].clone()
        },
        Enrollment {
            uid: next[1].uid + 1000,
            ..next[1].clone()
        },
        Enrollment {
            gid: next[1].gid + 1000,
            ..next[1].clone()
        },
    ] {
        refused(&mut ledger, &[next[0].clone(), changed]);
    }
    let generation = ledger.generation().unwrap();
    assert!(matches!(
        ledger.set_enrolled_images(&next).unwrap(),
        EnrolledImagesOutcome::Updated { instances: 2, .. }
    ));
    assert_eq!(ledger.enrollments().unwrap(), next);
    assert!(ledger.generation().unwrap() > generation);
    // The way back is the same transaction with the earlier rows.
    assert!(matches!(
        ledger.set_enrolled_images(&before).unwrap(),
        EnrolledImagesOutcome::Updated { instances: 2, .. }
    ));
    assert_eq!(ledger.enrollments().unwrap(), before);
}

#[test]
fn b3r_02_startup_refuses_a_ledger_whose_instances_share_an_account() {
    let table = |rows: &str| {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE instances (instance_id TEXT, uid INTEGER, gid INTEGER);
             INSERT INTO instances VALUES {rows};"
        ))
        .unwrap();
        audit_accounts(&conn)
    };
    assert!(table("('a', 1000, 1000), ('b', 1001, 1001)").is_ok());
    for (what, rows) in [
        ("uid", "('a', 1000, 1000), ('b', 1000, 1001)"),
        ("gid", "('a', 1000, 1000), ('b', 1001, 1000)"),
        ("root", "('a', 0, 1000)"),
    ] {
        let refused = table(rows).unwrap_err().to_string();
        assert!(
            refused.contains("share a Unix account"),
            "{what}: {refused}"
        );
    }
    // In a real file the schema itself says so, and rewriting it fails the digest first.
    let fixture = temp_ledger(unrestricted());
    {
        let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
        enroll(&mut ledger, instance());
        let conn = ledger.connection();
        conn.pragma_update(None, "writable_schema", "ON").unwrap();
        conn.execute(
            "UPDATE sqlite_schema SET sql = replace(sql, 'uid INTEGER NOT NULL UNIQUE', 'uid INTEGER NOT NULL')
             WHERE name = 'instances'",
            [],
        )
        .unwrap();
    }
    assert!(matches!(
        Ledger::open(fixture.config.clone()),
        Err(LedgerError::Corrupt(_))
    ));
}

#[test]
fn exit3_a_different_database_cannot_rebind_a_namespace_or_clear_its_claims() {
    let fixture = temp_ledger(NodeCeilings::default());
    {
        let mut ledger = attached(&fixture.config);
        accepted(ledger.admit_intent(&request(1)).unwrap());
    }
    let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
    let stale = Id128::from_bytes([0x88; 16]);
    assert!(matches!(
        ledger.attach_instance(instance(), stale, None, false).unwrap(),
        AttachOutcome::DatabaseMismatch { .. }
    ));
    // The binding did not move, and the same mismatch reports again.
    assert!(matches!(
        ledger.attach_instance(instance(), stale, None, false).unwrap(),
        AttachOutcome::DatabaseMismatch { .. }
    ));
    assert!(matches!(
        ledger.attach_instance(instance(), database(), None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 1);
}

#[test]
fn exit3_shared_reserve_counts_once_and_three_of_four_fit_the_default_vector() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    for index in 1..=3u8 {
        accepted(ledger.admit_intent(&request(index)).unwrap());
    }
    assert!(matches!(
        ledger.admit_intent(&request(4)).unwrap(),
        AdmitOutcome::Capacity { .. }
    ));
    let snapshot = ledger.accounting(None).unwrap();
    assert_eq!(snapshot.committed.memory_bytes, 3 * 896 * MIB + 128 * MIB);
    assert_eq!(snapshot.committed.host_cpu_millis, 3500);
    assert_eq!(snapshot.committed.host_pids, 3 * 32 + 32);
    assert_eq!(snapshot.committed.pids, 3 * 192 + 32);
    assert_eq!(snapshot.committed.virtual_cpu_slots, 3);
    assert_eq!(
        snapshot.committed.disk_bytes,
        3 * 1408 * MIB + (512 + 1024) * MIB
    );
    assert_eq!(snapshot.committed.slots, 3);
    assert!(!snapshot.over_committed);
}

#[test]
fn exit6_restart_replays_every_unreleased_claim_worker_and_lease() {
    let fixture = temp_ledger(NodeCeilings::default());
    let worker = {
        let mut ledger = attached(&fixture.config);
        let (_, worker, _) = accepted(ledger.admit_intent(&request(1)).unwrap());
        ledger
            .record_worker_identity(worker, 321, 654, "boot-a")
            .unwrap();
        accepted(ledger.admit_intent(&request(2)).unwrap());
        worker
    };
    let ledger = Ledger::open(fixture.config.clone()).unwrap();
    let replay = ledger.replay().unwrap();
    assert_eq!(replay.active_allocations.len(), 2);
    assert_eq!(replay.unsettled_workers.len(), 2);
    let record = replay
        .unsettled_workers
        .iter()
        .find(|w| w.worker_id == worker)
        .unwrap();
    assert_eq!(record.pid, Some(321));
    assert_eq!(record.start_time, Some(654));
    assert_eq!(record.host_boot_id.as_deref(), Some("boot-a"));
    assert_eq!(replay.executable_leases.len(), 4);
    assert!(ledger.executable_leased(&sample_vector()[0]).unwrap());
    assert_eq!(ledger.accounting(None).unwrap().claimed.slots, 2);
}

#[test]
fn exit5_generation_leases_hold_until_the_absence_commit_and_observed_tuples_must_match() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    accepted(ledger.admit_intent(&request(1)).unwrap());
    let allocation = request(1).allocation_id;
    let identity = sample_vector()[0];
    assert!(ledger.executable_leased(&identity).unwrap());
    // Only the journaled tuple can be attached as what ran.
    ledger
        .record_observed_executable(instance(), allocation, &identity)
        .unwrap();
    for mutate in [
        Box::new(|i: &mut ExecutableIdentity| i.st_ino += 1)
            as Box<dyn Fn(&mut ExecutableIdentity)>,
        Box::new(|i| i.st_dev += 1),
        Box::new(|i| i.bytes += 1),
        Box::new(|i| i.sha256 = Digest::of(b"other")),
        Box::new(|i| i.installation_generation += 1),
    ] {
        let mut other = sample_vector()[1];
        mutate(&mut other);
        assert!(
            ledger
                .record_observed_executable(instance(), allocation, &other)
                .is_err()
        );
    }
    // A recorded observation's kind is permanent: no later inference relabels it.
    assert!(
        ledger
            .record_inferred_executable(instance(), allocation, &identity)
            .is_err()
    );
    ledger.settle_unstarted(instance(), allocation).unwrap();
    absent(ledger.commit_fence(&fence_request(1)).unwrap());
    assert!(!ledger.executable_leased(&identity).unwrap());
}

/// B4 break-it finding 5: a retained descriptor's tuple inferred from a confirmed exec
/// is recorded as `retained_fd`, distinct from a `proc_exe` observation, under the
/// same exact-match rule, and it cannot be relabelled afterwards.
#[test]
fn inferred_executables_are_recorded_as_retained_fd_not_observed() {
    let fixture = temp_ledger(NodeCeilings::default());
    let mut ledger = attached(&fixture.config);
    accepted(ledger.admit_intent(&request(1)).unwrap());
    let allocation = request(1).allocation_id;
    let vector = sample_vector();
    let mut other = vector[1];
    other.st_ino += 1;
    assert!(
        ledger
            .record_inferred_executable(instance(), allocation, &other)
            .is_err(),
        "an inference must still match the lease exactly"
    );
    ledger
        .record_inferred_executable(instance(), allocation, &vector[1])
        .unwrap();
    ledger
        .record_observed_executable(instance(), allocation, &vector[0])
        .unwrap();
    let kinds: Vec<(String, Option<String>)> = {
        let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
        let mut statement = conn
            .prepare("SELECT role, observation FROM executable_leases ORDER BY role")
            .unwrap();
        statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert!(kinds.contains(&(
        vector[1].role.as_str().to_string(),
        Some("retained_fd".into())
    )));
    assert!(kinds.contains(&(vector[0].role.as_str().to_string(), Some("proc_exe".into()))));
    assert!(
        ledger
            .record_observed_executable(instance(), allocation, &vector[1])
            .is_err(),
        "an inference is never relabelled as observed"
    );
}

/// A connection with every optional defense off that plain SQL can set, as the
/// migration attacks in B2 used. Triggers stay on: disabling them through the host
/// API is file authority, outside SQL's reach.
fn defenseless(config: &LedgerConfig) -> Connection {
    let conn = Connection::open(config.directory.join(LEDGER_DB)).unwrap();
    for pragma in ["foreign_keys", "recursive_triggers", "trusted_schema"] {
        conn.pragma_update(None, pragma, "OFF").unwrap();
    }
    conn.pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    conn
}

fn table_digest(conn: &Connection, table: &str) -> String {
    let mut statement = conn
        .prepare(&format!("SELECT rowid, * FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    let mut rows = statement.query([]).unwrap();
    let mut text = String::new();
    while let Some(row) = rows.next().unwrap() {
        for index in 0..columns {
            let value: rusqlite::types::Value = row.get(index).unwrap();
            text.push_str(&format!("{value:?}|"));
        }
        text.push('\n');
    }
    text
}

/// Rewrites one row's identity through a named conflict algorithm, naming the columns
/// that make up each unique key plus the rowid.
const CONFLICTS: [&str; 5] = ["REPLACE", "IGNORE", "ABORT", "FAIL", "ROLLBACK"];

#[test]
fn exit6_every_unique_key_and_conflict_algorithm_is_guarded() {
    let fixture = temp_ledger(NodeCeilings::default());
    {
        let mut ledger = attached(&fixture.config);
        let (_, worker, _) = accepted(ledger.admit_intent(&request(1)).unwrap());
        ledger.record_worker_identity(worker, 1, 2, "boot").unwrap();
        ledger
            .record_stop(instance(), request(1).allocation_id, "test")
            .unwrap();
        ledger.settle_worker(worker, "exit:0").unwrap();
        accepted(ledger.admit_intent(&request(2)).unwrap());
        ledger
            .settle_unstarted(instance(), request(2).allocation_id)
            .unwrap();
        absent(ledger.commit_fence(&fence_request(2)).unwrap());
    }
    let conn = defenseless(&fixture.config);
    // Every INSERT copies an existing row with a colliding key and otherwise valid
    // values, so a conflict algorithm is what decides the outcome if nothing stops it.
    let probes: Vec<(&str, String)> = vec![
        ("node_identity", "INSERT OR {c} INTO node_identity SELECT * FROM node_identity".into()),
        (
            "node_identity",
            "INSERT OR {c} INTO node_identity (id, node_id, created_at_ms) VALUES (1, 'x', 0)".into(),
        ),
        (
            "generation_counter",
            "INSERT OR {c} INTO generation_counter (id, value) VALUES (1, 99)".into(),
        ),
        (
            "instances",
            "INSERT OR {c} INTO instances SELECT instance_id, unit, cgroup, uid, gid, exe_st_dev, exe_st_ino,
                exe_bytes, exe_sha256, 'other', first_generation FROM instances".into(),
        ),
        (
            "instances",
            "INSERT OR {c} INTO instances (rowid, instance_id, unit, cgroup, uid, gid, exe_st_dev, exe_st_ino,
                exe_bytes, exe_sha256, database_uuid, first_generation)
             SELECT rowid, 'new', 'new.service', '/new', 77, 77, 1, 1, 1, 'x', 'other', 1 FROM instances".into(),
        ),
        (
            "allocations",
            "INSERT OR {c} INTO allocations SELECT instance_id, 'new', sandbox_id, 'new-b', plan_version,
                plan_digest, profile, manifest_sha256, host_spec_sha256, guest_exec_spec_sha256, work_uuid,
                stop_authority, 'absent', created_generation, updated_generation FROM allocations LIMIT 1".into(),
        ),
        (
            "allocations",
            "INSERT OR {c} INTO allocations SELECT instance_id, 'new', 'new-s', backend_id, plan_version,
                plan_digest, profile, manifest_sha256, host_spec_sha256, guest_exec_spec_sha256, work_uuid,
                stop_authority, 'absent', created_generation, updated_generation FROM allocations LIMIT 1".into(),
        ),
        (
            "allocations",
            "INSERT OR {c} INTO allocations SELECT instance_id, allocation_id, 'new-s', 'new-b', plan_version,
                plan_digest, profile, manifest_sha256, host_spec_sha256, guest_exec_spec_sha256, work_uuid,
                stop_authority, 'absent', created_generation, updated_generation FROM allocations LIMIT 1".into(),
        ),
        (
            "allocations",
            "INSERT OR {c} INTO allocations (rowid, allocation_id, instance_id, sandbox_id, backend_id,
                plan_version, plan_digest, profile, manifest_sha256, host_spec_sha256, guest_exec_spec_sha256,
                work_uuid, stop_authority, phase, created_generation, updated_generation)
             SELECT rowid, 'new', instance_id, 'new-s', 'new-b', plan_version, plan_digest, profile,
                manifest_sha256, host_spec_sha256, guest_exec_spec_sha256, work_uuid, stop_authority,
                'absent', created_generation, updated_generation FROM allocations LIMIT 1".into(),
        ),
        (
            "allocation_plans",
            "INSERT OR {c} INTO allocation_plans SELECT instance_id, allocation_id, x'00' FROM allocation_plans".into(),
        ),
        (
            "capacity_claims",
            "INSERT OR {c} INTO capacity_claims SELECT instance_id, allocation_id, 0, 0, 0, 0, 0, 0, 1, NULL FROM capacity_claims LIMIT 1".into(),
        ),
        (
            "identity_leases",
            "INSERT OR {c} INTO identity_leases (namespace, kind, value, instance_id, allocation_id, claimed_generation)
             SELECT namespace, kind, value, instance_id, 'other', 1 FROM identity_leases WHERE released_generation IS NULL LIMIT 1".into(),
        ),
        (
            "identity_leases",
            "INSERT OR {c} INTO identity_leases (namespace, kind, value, instance_id, allocation_id, claimed_generation)
             SELECT namespace, kind, 999999, instance_id, allocation_id, 1 FROM identity_leases LIMIT 1".into(),
        ),
        (
            "identity_leases",
            "INSERT OR {c} INTO identity_leases (id, namespace, kind, value, instance_id, allocation_id, claimed_generation)
             SELECT id, namespace, kind, 999999, instance_id, 'other', 1 FROM identity_leases LIMIT 1".into(),
        ),
        (
            "executable_leases",
            "INSERT OR {c} INTO executable_leases (instance_id, allocation_id, role, st_dev, st_ino, bytes, sha256, installation_generation)
             SELECT instance_id, allocation_id, role, 0, 0, 0, 'x', 1 FROM executable_leases LIMIT 1".into(),
        ),
        (
            "worker_intents",
            "INSERT OR {c} INTO worker_intents (instance_id, allocation_id, mode, operation_generation, allowed_names, cgroup,
                exec_role, exec_st_dev, exec_st_ino, exec_bytes, exec_sha256)
             SELECT instance_id, allocation_id, mode, operation_generation, '[]', 'x', 'x', 0, 0, 0, 'x' FROM worker_intents LIMIT 1".into(),
        ),
        (
            "worker_intents",
            "INSERT OR {c} INTO worker_intents (id, instance_id, allocation_id, mode, operation_generation, allowed_names, cgroup,
                exec_role, exec_st_dev, exec_st_ino, exec_bytes, exec_sha256)
             SELECT id, instance_id, allocation_id, mode, 999999, '[]', 'x', 'x', 0, 0, 0, 'x' FROM worker_intents LIMIT 1".into(),
        ),
        (
            "retired_tokens",
            "INSERT OR {c} INTO retired_tokens SELECT instance_id, allocation_id, sandbox_id, plan_digest,
                'new-r', 999999, x'00' FROM retired_tokens".into(),
        ),
        (
            "retired_tokens",
            "INSERT OR {c} INTO retired_tokens SELECT instance_id, 'new', sandbox_id, plan_digest,
                receipt_id, 999999, x'00' FROM retired_tokens".into(),
        ),
        (
            "retired_tokens",
            "INSERT OR {c} INTO retired_tokens SELECT instance_id, 'new', sandbox_id, plan_digest,
                'new-r', helper_generation, x'00' FROM retired_tokens".into(),
        ),
        (
            "stop_events",
            "INSERT OR {c} INTO stop_events (instance_id, allocation_id, generation, reason)
             SELECT instance_id, allocation_id, generation, 'x' FROM stop_events LIMIT 1".into(),
        ),
        (
            "stop_events",
            "INSERT OR {c} INTO stop_events (id, instance_id, allocation_id, generation, reason)
             SELECT id, instance_id, allocation_id, 999999, 'x' FROM stop_events LIMIT 1".into(),
        ),
        // UPDATE OR <algorithm>: moving a row onto another key.
        (
            "allocations",
            "UPDATE OR {c} allocations SET sandbox_id = (SELECT MAX(sandbox_id) FROM allocations)
             WHERE sandbox_id = (SELECT MIN(sandbox_id) FROM allocations)".into(),
        ),
        (
            "allocations",
            "UPDATE OR {c} allocations SET rowid = rowid + 1 WHERE rowid = (SELECT MIN(rowid) FROM allocations)".into(),
        ),
        (
            "identity_leases",
            "UPDATE OR {c} identity_leases SET value = (SELECT MAX(value) FROM identity_leases WHERE namespace = 'uid')
             WHERE namespace = 'uid' AND value = (SELECT MIN(value) FROM identity_leases WHERE namespace = 'uid')".into(),
        ),
        (
            "retired_tokens",
            "UPDATE OR {c} retired_tokens SET helper_generation = helper_generation + 1".into(),
        ),
        (
            "retired_tokens",
            "UPDATE OR {c} retired_tokens SET receipt = x'00'".into(),
        ),
        (
            "worker_intents",
            "UPDATE OR {c} worker_intents SET operation_generation = 999999".into(),
        ),
        (
            "capacity_claims",
            "UPDATE OR {c} capacity_claims SET released_generation = 999999 WHERE released_generation IS NULL".into(),
        ),
        (
            "generation_counter",
            "UPDATE OR {c} generation_counter SET value = 1".into(),
        ),
        (
            "generation_counter",
            "UPDATE OR {c} generation_counter SET id = 2".into(),
        ),
        (
            "node_identity",
            "UPDATE OR {c} node_identity SET node_id = 'other'".into(),
        ),
        (
            "allocation_plans",
            "UPDATE OR {c} allocation_plans SET plan = x'00'".into(),
        ),
        (
            "executable_leases",
            "UPDATE OR {c} executable_leases SET st_ino = st_ino + 1".into(),
        ),
        (
            "executable_leases",
            "UPDATE OR {c} executable_leases SET rowid = rowid + 1".into(),
        ),
        (
            "stop_events",
            "UPDATE OR {c} stop_events SET generation = generation + 1".into(),
        ),
        (
            "worker_intents",
            "UPDATE OR {c} worker_intents SET pid = 999 WHERE pid IS NOT NULL".into(),
        ),
        (
            "worker_intents",
            "UPDATE OR {c} worker_intents SET rowid = rowid + 100".into(),
        ),
        (
            "instances",
            "UPDATE OR {c} instances SET database_uuid = 'other'".into(),
        ),
    ];
    for (table, template) in &probes {
        for conflict in CONFLICTS {
            // A trigger-allowed release is covered by the fence-only test below.
            if template.contains("released_generation = 999999") {
                continue;
            }
            let statement = template.replace("{c}", conflict);
            let before = table_digest(&conn, table);
            let tx = conn.unchecked_transaction().unwrap();
            let outcome = tx.execute_batch(&statement);
            let after = table_digest(&tx, table);
            drop(tx);
            assert_eq!(
                before, after,
                "{conflict}: `{statement}` changed {table} (returned {outcome:?})"
            );
        }
    }
    // Deletes of durable evidence fail outright.
    for table in GUARDED_TABLES {
        if table == "allocation_plans" {
            continue;
        }
        let before = table_digest(&conn, table);
        let outcome = conn.execute_batch(&format!("DELETE FROM {table};"));
        if !before.is_empty() {
            assert!(outcome.is_err(), "DELETE FROM {table} succeeded");
        }
        assert_eq!(before, table_digest(&conn, table), "{table}");
    }
    // A plan may leave only after its token's permanent fence.
    let held = table_digest(&conn, "allocation_plans");
    assert!(!held.is_empty());
    assert!(conn.execute_batch("DELETE FROM allocation_plans;").is_err());
    assert_eq!(held, table_digest(&conn, "allocation_plans"));
}

#[test]
fn exit6_a_held_claim_cannot_coexist_with_a_fence_or_absent_phase() {
    let fixture = temp_ledger(NodeCeilings::default());
    {
        let mut ledger = attached(&fixture.config);
        accepted(ledger.admit_intent(&request(1)).unwrap());
    }
    let conn = defenseless(&fixture.config);
    let allocation = request(1).allocation_id.to_string();
    // Absent with a held claim, and a fence over a held claim, both raise.
    assert!(
        conn.execute(
            "UPDATE allocations SET phase = 'absent', updated_generation = updated_generation + 1
             WHERE allocation_id = ?1",
            [&allocation],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO retired_tokens VALUES (?1, ?2, 'sb', 'd', 'r', 999, x'00')",
            params![instance().to_string(), allocation],
        )
        .is_err()
    );
    // Identity columns of an allocation are immutable.
    for column in [
        "instance_id",
        "plan_digest",
        "sandbox_id",
        "backend_id",
        "stop_authority",
        "host_spec_sha256",
    ] {
        assert!(
            conn.execute(
                &format!(
                    "UPDATE allocations SET {column} = 'x', updated_generation = updated_generation + 1"
                ),
                [],
            )
            .is_err(),
            "{column}"
        );
    }
    // A generation update that does not advance is refused.
    assert!(
        conn.execute("UPDATE allocations SET phase = 'stopped'", [])
            .is_err(),
        "a phase change without a newer generation"
    );
}

#[test]
fn b3_01_attach_authenticates_nothing_and_refuses_an_unenrolled_instance() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(
        ledger.attach_instance(instance(), database(), None, false).unwrap(),
        AttachOutcome::NotEnrolled
    );
    assert_eq!(ledger.enrollment(instance()).unwrap(), None);
    let rows = |ledger: &Ledger| -> i64 {
        ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM instances", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(rows(&ledger), 0, "an attempt creates no row");
    enroll(&mut ledger, instance());
    assert_eq!(
        ledger.enrollment(instance()).unwrap(),
        Some(enrollment_of(instance()))
    );
    // Enrollment names no database: the first attested attachment records one.
    assert!(matches!(
        ledger.attach_instance(instance(), database(), None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
    let copied = Id128::from_bytes([0x99; 16]);
    assert!(matches!(
        ledger.attach_instance(instance(), copied, None, false).unwrap(),
        AttachOutcome::DatabaseMismatch { .. }
    ));
}

#[test]
fn b3_02_enrollment_is_bounded_and_one_unit_serves_one_instance() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
    let id = |byte| Id128::from_bytes([byte; 16]);
    for byte in 0..8 {
        assert!(matches!(
            ledger.enroll_instance(&enrollment_of(id(byte)), 8).unwrap(),
            EnrollOutcome::Enrolled { .. }
        ));
    }
    assert_eq!(
        ledger.enroll_instance(&enrollment_of(id(8)), 8).unwrap(),
        EnrollOutcome::LimitReached { limit: 8 }
    );
    // A unit, or its cgroup, can't serve a second instance.
    let mut same_unit = enrollment_of(id(8));
    same_unit.unit = enrollment_of(id(0)).unit;
    assert_eq!(
        ledger.enroll_instance(&same_unit, 16).unwrap(),
        EnrollOutcome::UnitTaken
    );
    let mut same_cgroup = enrollment_of(id(8));
    same_cgroup.cgroup = enrollment_of(id(0)).cgroup;
    assert_eq!(
        ledger.enroll_instance(&same_cgroup, 16).unwrap(),
        EnrollOutcome::UnitTaken
    );
    // An upgrade re-enrolls the new image, at the limit, and the binding is unaffected.
    ledger.attach_instance(id(0), database(), None, false).unwrap();
    let mut upgraded = enrollment_of(id(0));
    upgraded.executable.st_ino = 99;
    assert!(matches!(
        ledger.enroll_instance(&upgraded, 8).unwrap(),
        EnrollOutcome::Updated { .. }
    ));
    assert_eq!(
        ledger.enrollment(id(0)).unwrap().unwrap().executable.st_ino,
        99
    );
    assert!(matches!(
        ledger.attach_instance(id(0), database(), None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
    // A lowered limit removes nothing and still lets existing rows re-enroll.
    assert!(matches!(
        ledger.enroll_instance(&upgraded, 1).unwrap(),
        EnrollOutcome::Updated { .. }
    ));
    assert_eq!(ledger.replay().unwrap().enrolled.len(), 8);
}

#[test]
fn b3_02_attach_writes_only_its_own_row_once_and_respects_the_fence_floor() {
    let fixture = temp_ledger(unrestricted());
    let mut tight = fixture.config.clone();
    tight.shared.fence_allowance_bytes = 16 * FENCE_ENTRY_BOUND;
    let mut ledger = Ledger::open(tight).unwrap();
    enroll(&mut ledger, instance());
    let other = Id128::from_bytes([0x44; 16]);
    enroll(&mut ledger, other);
    assert!(matches!(
        ledger.attach_instance(instance(), database(), None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
    let generation = ledger.generation().unwrap();
    let changes = ledger.connection().total_changes();
    for _ in 0..100 {
        assert!(matches!(
            ledger.attach_instance(instance(), database(), None, false).unwrap(),
            AttachOutcome::Bound { .. }
        ));
        assert!(matches!(
            ledger
                .attach_instance(instance(), Id128::from_bytes([0x99; 16]), None, false)
                .unwrap(),
            AttachOutcome::DatabaseMismatch { .. }
        ));
        assert_eq!(
            ledger.attach_instance(Id128::random(), database(), None, false).unwrap(),
            AttachOutcome::NotEnrolled
        );
    }
    assert_eq!(
        ledger.connection().total_changes(),
        changes,
        "a reattachment and a refusal write nothing"
    );
    assert_eq!(ledger.generation().unwrap(), generation);
    // Accepted tokens have used this instance's headroom, its share and the remainder.
    issue_through(&ledger, instance(), ISSUED_THROUGH);
    let mut index = 1u8;
    while ledger.admitted_headroom(instance()).unwrap() {
        accepted(ledger.admit_intent(&request(index)).unwrap());
        index += 1;
    }
    assert_eq!(index - 1, 4, "a share of 1 and the 3-entry remainder");
    // B7 (RTC-17): enrollment reserved the other slot's share, so its first binding
    // is not refused and it can still admit; enrolling past the policy maximum, which
    // would shrink every share under the rows already held, is what's refused.
    assert!(matches!(
        ledger
            .attach_instance(other, Id128::from_bytes([0x55; 16]), None, false)
            .unwrap(),
        AttachOutcome::Bound { .. }
    ));
    assert!(ledger.admitted_headroom(other).unwrap());
    for byte in 0x60..0x66 {
        enroll(&mut ledger, Id128::from_bytes([byte; 16]));
    }
    let generation = ledger.generation().unwrap();
    assert_eq!(
        ledger
            .enroll_instance(&enrollment_of(Id128::random()), MAX_ENROLLED_HARD)
            .unwrap(),
        EnrollOutcome::NoSpace
    );
    assert_eq!(ledger.generation().unwrap(), generation, "the refusal wrote nothing");
    assert_eq!(ledger.replay().unwrap().enrolled.len(), 8);
    // The instance already bound keeps working at the floor: it needs no write.
    assert!(matches!(
        ledger.attach_instance(instance(), database(), None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
}

/// B7: an issued token the ledger never admitted, each with its own seq below
/// `ISSUED_THROUGH` and above every `request(i)`'s.
fn never_admitted_request(instance: Id128) -> FenceRequest {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(40_000);
    let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert!(seq < ISSUED_THROUGH);
    FenceRequest {
        instance_id: instance,
        allocation_id: token(instance, seq),
        sandbox_id: crate::model::new_id("sb"),
        plan_digest: Digest::of(b"never admitted"),
        observations: "permits=settled;namespace=absent".into(),
    }
}

#[test]
fn b3_02_never_admitted_fence_quotas_sum_within_the_allowance_and_reserve_their_space() {
    let allowance = SharedReserve::default().fence_allowance_bytes;
    // B7: the default allowance is 128 MiB.
    assert_eq!(allowance, 128 * MIB);
    for limit in [1, 2, DEFAULT_MAX_ENROLLED, MAX_ENROLLED_HARD] {
        let fixture = temp_ledger(unrestricted());
        let mut config = fixture.config.clone();
        config.max_enrolled = limit;
        let ledger = Ledger::open(config.clone()).unwrap();
        let quota = never_admitted_quota(ledger.connection(), &config).unwrap();
        assert!(quota > 0, "{limit}");
        assert!(
            quota * u64::from(limit) * FENCE_ENTRY_BOUND <= allowance,
            "{limit}: {quota}"
        );
        // Admission reserves the whole pool, used or not, so the pool and every
        // admitted token's entry together can never exceed the allowance.
        assert!(never_admitted_pool(&config) * FENCE_ENTRY_BOUND <= allowance);
        assert!(ledger.admitted_headroom(instance()).unwrap());
    }
    // A policy lowered under its existing rows shrinks shares; it can't inflate the sum.
    let fixture = temp_ledger(unrestricted());
    let mut config = fixture.config.clone();
    config.max_enrolled = 1;
    let mut ledger = Ledger::open(config.clone()).unwrap();
    let solo = never_admitted_quota(ledger.connection(), &config).unwrap();
    for byte in 0..4 {
        enroll(&mut ledger, Id128::from_bytes([byte; 16]));
    }
    let shared = never_admitted_quota(ledger.connection(), &config).unwrap();
    assert_eq!(shared, solo / 4);
    // B7: the pool is a quarter of any allowance's entries, with no floor.
    config.shared.fence_allowance_bytes = 100 * FENCE_ENTRY_BOUND;
    assert_eq!(never_admitted_pool(&config), 25);
}

#[test]
fn b3_02_never_admitted_fences_stop_at_the_quota_and_admitted_ones_never_do() {
    let fixture = temp_ledger(unrestricted());
    let mut config = fixture.config.clone();
    config.max_enrolled = MAX_ENROLLED_HARD;
    let mut ledger = Ledger::open(config.clone()).unwrap();
    enroll(&mut ledger, instance());
    issue_through(&ledger, instance(), ISSUED_THROUGH);
    ledger.attach_instance(instance(), database(), None, false).unwrap();
    let other = Id128::from_bytes([0x44; 16]);
    enroll(&mut ledger, other);
    issue_through(&ledger, other, ISSUED_THROUGH);
    accepted(ledger.admit_intent(&request(1)).unwrap());
    let quota = never_admitted_quota(ledger.connection(), &config).unwrap();
    // B7: the pool is a quarter of the default allowance's entries, with no floor.
    assert_eq!(
        quota,
        128 * MIB / FENCE_ENTRY_BOUND / 4 / u64::from(MAX_ENROLLED_HARD)
    );
    for used in 0..quota {
        assert!(ledger.never_admitted_fence_allowed(instance()).unwrap());
        // New tokens stop early, with a quarter left for tokens already charged at C1.
        assert_eq!(
            ledger.pre_intent_headroom(instance()).unwrap(),
            used < quota - quota / 4,
            "{used}"
        );
        absent(
            ledger
                .commit_fence(&never_admitted_request(instance()))
                .unwrap(),
        );
    }
    assert!(!ledger.never_admitted_fence_allowed(instance()).unwrap());
    // At the quota: refused, and nothing written, not even a generation.
    let generation = ledger.generation().unwrap();
    let changes = ledger.connection().total_changes();
    let refused = never_admitted_request(instance());
    for _ in 0..3 {
        assert_eq!(
            ledger.commit_fence(&refused).unwrap(),
            FenceOutcome::QuotaExhausted { quota }
        );
    }
    assert_eq!(ledger.connection().total_changes(), changes);
    assert_eq!(ledger.generation().unwrap(), generation);
    assert_eq!(
        ledger
            .lookup_token(instance(), refused.allocation_id, &refused.plan_digest)
            .unwrap(),
        TokenLookup::Unknown
    );
    // Fences for tokens the ledger admitted are outside this quota, before and after.
    accepted(ledger.admit_intent(&request(2)).unwrap());
    for index in [1u8, 2] {
        ledger
            .settle_unstarted(instance(), request(index).allocation_id)
            .unwrap();
        let (_, replay) = absent(ledger.commit_fence(&fence_request(index)).unwrap());
        assert!(!replay);
    }
    // They don't count against it either, and neither does a replay.
    assert!(!ledger.never_admitted_fence_allowed(instance()).unwrap());
    assert_eq!(
        never_admitted_fences(ledger.connection(), instance()).unwrap(),
        quota
    );
    // Another instance's quota is its own.
    assert_eq!(
        never_admitted_fences(ledger.connection(), other).unwrap(),
        0
    );
    assert!(ledger.never_admitted_fence_allowed(other).unwrap());
    assert!(ledger.pre_intent_headroom(other).unwrap());
    absent(ledger.commit_fence(&never_admitted_request(other)).unwrap());
    // The count survives reopening: it is durable, not remembered.
    drop(ledger);
    let reopened = Ledger::open(config).unwrap();
    assert!(!reopened.never_admitted_fence_allowed(instance()).unwrap());
    assert!(reopened.never_admitted_fence_allowed(other).unwrap());
}

fn exec_record(token: u64, state: &str) -> super::super::supervisor::ResourceRecord {
    super::super::supervisor::ResourceRecord::Exec {
        token: format!("{token:032x}"),
        execution_id: format!("ex-{token:016x}"),
        boot_id: "0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6".into(),
        state: state.into(),
    }
}

fn state_frame_bytes(ledger: &Ledger, allocation: Id128) -> usize {
    let state = ledger.allocation_state(instance(), allocation).unwrap();
    super::super::workers::encode_frame(&super::super::workers::Envelope {
        id: 1,
        deadline_ns: 0,
        body: &super::super::workers::LedgerReply::State(state.map(Box::new)),
    })
    .unwrap()
    .len()
}

fn phase(ledger: &mut Ledger, allocation: Id128, from: &str, to: &str) {
    ledger
        .set_phase(instance(), allocation, &[from.to_string()], to)
        .unwrap();
}

/// B5-01 (the break-it reviewer's `ledger_growth`): 100,000 executions in one session leave an
/// `AllocationState` whose size does not depend on the history, so its reply fits one
/// worker frame and Stop and Remove still reach ABSENT.
#[test]
fn b5_01_execution_history_never_grows_the_allocation_state() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = attached(&fixture.config);
    ledger.test_unsynchronized();
    let allocation = request(1).allocation_id;
    accepted(ledger.admit_intent(&request(1)).unwrap());
    phase(&mut ledger, allocation, "intent", "ready");
    let mut sizes = Vec::new();
    const EXECUTIONS: u64 = 100_000;
    for token in 1..=EXECUTIONS {
        ledger
            .record_resource(instance(), allocation, &exec_record(token, "intent"))
            .unwrap();
        phase(&mut ledger, allocation, "ready", "exec_intent");
        ledger
            .record_resource(instance(), allocation, &exec_record(token, "busy"))
            .unwrap();
        phase(&mut ledger, allocation, "exec_intent", "busy");
        if token == 3 || token == EXECUTIONS {
            // In flight: the current execution's two rows plus the summary.
            let state = ledger
                .allocation_state(instance(), allocation)
                .unwrap()
                .unwrap();
            let execs: Vec<_> = state
                .resources
                .iter()
                .filter(|r| {
                    matches!(
                        r,
                        super::super::supervisor::ResourceRecord::Exec { .. }
                            | super::super::supervisor::ResourceRecord::ExecHistory { .. }
                    )
                })
                .collect();
            assert_eq!(execs.len(), 3, "{execs:?}");
        }
        // Every fourth one is interrupted after reporting idle, as when READY is not
        // durable: one settlement, counted once.
        ledger
            .record_resource(instance(), allocation, &exec_record(token, "idle"))
            .unwrap();
        if token % 4 == 0 {
            ledger
                .record_resource(instance(), allocation, &exec_record(token, "interrupted"))
                .unwrap();
        }
        phase(&mut ledger, allocation, "busy", "ready");
        if token == 3 || token == EXECUTIONS {
            sizes.push(state_frame_bytes(&ledger, allocation));
        }
    }
    let state = ledger
        .allocation_state(instance(), allocation)
        .unwrap()
        .unwrap();
    let history: Vec<_> = state
        .resources
        .iter()
        .filter(|r| {
            matches!(
                r,
                super::super::supervisor::ResourceRecord::Exec { .. }
                    | super::super::supervisor::ResourceRecord::ExecHistory { .. }
            )
        })
        .collect();
    assert_eq!(
        history,
        [&super::super::supervisor::ResourceRecord::ExecHistory {
            settled: EXECUTIONS,
            last_token: format!("{EXECUTIONS:032x}"),
            last_execution_id: format!("ex-{EXECUTIONS:016x}"),
            last_state: "interrupted".into(),
        }]
    );
    // Only the summary's digits grew between 3 and 100,000 executions.
    // ("3" to "100000", and "idle" to "interrupted").
    assert!(sizes[1] - sizes[0] <= 12, "{sizes:?}");
    assert!(sizes[1] < 64 * 1024, "{sizes:?}");
    // The table itself holds no history either.
    let rows: i64 = ledger
        .conn
        .query_row(
            "SELECT COUNT(*) FROM resource_events WHERE kind IN ('exec','exec_history')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
    // Stop and Remove: STOP_INTENT, the workers settled, the fence: ABSENT.
    ledger
        .record_stop(instance(), allocation, "remove")
        .unwrap();
    assert!(state_frame_bytes(&ledger, allocation) < 64 * 1024);
    ledger.settle_unstarted(instance(), allocation).unwrap();
    absent(ledger.commit_fence(&fence_request(1)).unwrap());
    assert!(matches!(
        ledger
            .lookup_token(instance(), allocation, &request(1).plan_digest)
            .unwrap(),
        TokenLookup::Fenced { .. }
    ));
}

/// B5-01's audit of the other per-allocation rows: repeated Stop and Remove attempts
/// keep at most sixteen stop reasons and eight settled cleanup workers, and an
/// execution row cannot be deleted without a newer summary.
#[test]
fn b5_01_stop_reasons_and_cleanup_workers_are_bounded() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = attached(&fixture.config);
    let allocation = request(1).allocation_id;
    accepted(ledger.admit_intent(&request(1)).unwrap());
    for attempt in 0..40 {
        ledger
            .record_stop(instance(), allocation, &format!("attempt {attempt}"))
            .unwrap();
        let (worker, _) = ledger
            .record_allocation_worker_intent(instance(), allocation, &request(1).supervisor)
            .unwrap();
        ledger.settle_worker(worker, "exited").unwrap();
    }
    fn count(ledger: &Ledger, sql: &str) -> i64 {
        ledger.conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }
    assert_eq!(
        count(&ledger, "SELECT COUNT(*) FROM stop_events"),
        STOP_REASONS_KEPT
    );
    // Exactly eight, the design's number, not eight plus the newest (B5-R2).
    assert_eq!(
        count(
            &ledger,
            "SELECT COUNT(*) FROM worker_intents WHERE settled_generation IS NOT NULL"
        ),
        SETTLED_WORKERS_KEPT
    );
    // Rows that settle out of order, after their successors were journaled, still
    // leave exactly eight; unsettled rows are never removed.
    let unsettled_before = count(
        &ledger,
        "SELECT COUNT(*) FROM worker_intents WHERE settled_generation IS NULL",
    );
    let mut open = Vec::new();
    for _ in 0..12 {
        let (worker, _) = ledger
            .record_allocation_worker_intent(instance(), allocation, &request(1).supervisor)
            .unwrap();
        open.push(worker);
    }
    assert_eq!(
        count(
            &ledger,
            "SELECT COUNT(*) FROM worker_intents WHERE settled_generation IS NULL"
        ),
        unsettled_before + 12
    );
    for worker in open.into_iter().rev() {
        ledger.settle_worker(worker, "exited").unwrap();
        assert!(
            count(
                &ledger,
                "SELECT COUNT(*) FROM worker_intents WHERE settled_generation IS NOT NULL"
            ) <= SETTLED_WORKERS_KEPT
        );
    }
    assert_eq!(
        count(
            &ledger,
            "SELECT COUNT(*) FROM worker_intents WHERE settled_generation IS NOT NULL"
        ),
        SETTLED_WORKERS_KEPT
    );
    assert_eq!(
        ledger
            .allocation_state(instance(), allocation)
            .unwrap()
            .unwrap()
            .phase,
        "stop_intent"
    );
    // The triggers allow only that compaction.
    ledger
        .record_resource(
            instance(),
            allocation,
            &super::super::supervisor::ResourceRecord::Intent(
                super::super::supervisor::IntentKind::WorkDir,
            ),
        )
        .unwrap();
    ledger
        .record_resource(instance(), allocation, &exec_record(1, "intent"))
        .unwrap();
    assert!(
        ledger
            .conn
            .execute("DELETE FROM resource_events WHERE kind = 'exec'", [])
            .is_err(),
        "no execution row goes without a newer summary"
    );
    assert!(
        ledger
            .conn
            .execute("DELETE FROM resource_events WHERE kind = 'intent'", [])
            .is_err()
    );
    assert!(
        ledger
            .conn
            .execute(
                "DELETE FROM worker_intents WHERE settled_generation IS NULL",
                []
            )
            .is_err()
            || count(
                &ledger,
                "SELECT COUNT(*) FROM worker_intents WHERE settled_generation IS NULL"
            ) == 0
    );
    ledger.settle_unstarted(instance(), allocation).unwrap();
    absent(ledger.commit_fence(&fence_request(1)).unwrap());
}
