//! B7 retired-token compaction at the ledger (design 16.5, 16.6): token issuance and
//! classification, the watermark, compaction and its triggers, RTC-17 shares, the
//! RTC-14 fault rows and their offline clear, and the open audit. Real SQLite files,
//! no fakes of the ledger's behavior. Each test names the rule it would catch.
use super::tests::{issue_through, key_from_file, request, temp_ledger, token};
use super::*;
use crate::helper::firecracker::config::MAX_ENROLLED_HARD;

const MIB: u64 = 1024 * 1024;

fn instance() -> Id128 {
    Id128::from_bytes([0x22; 16])
}

fn database() -> Id128 {
    Id128::from_bytes([0x33; 16])
}

fn other() -> Id128 {
    Id128::from_bytes([0x44; 16])
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

/// A ledger with `instance()` enrolled and attached, opened under `config`. Nothing is
/// issued yet: the pointer is 1 and W is 1.
fn fresh(config: &LedgerConfig) -> Ledger {
    let mut ledger = Ledger::open(config.clone()).unwrap();
    attach_new(&mut ledger, instance());
    ledger
}

fn attach_new(ledger: &mut Ledger, who: Id128) {
    assert!(matches!(
        ledger
            .enroll_instance(&enrollment_of(who), MAX_ENROLLED_HARD)
            .unwrap(),
        EnrollOutcome::Enrolled { .. }
    ));
    let db = Id128::from_bytes([who.as_bytes()[0] ^ 0x5a; 16]);
    assert!(matches!(
        ledger.attach_instance(who, db, None, false).unwrap(),
        AttachOutcome::Bound { .. }
    ));
}

/// One issuance through the real transaction.
fn issue(ledger: &mut Ledger, who: Id128) -> Id128 {
    match ledger.issue_and_snapshot(who, false).unwrap() {
        IssueOutcome::Issued { token, .. } => token,
        other => panic!("not issued: {other:?}"),
    }
}

/// An admission request for `who`'s `token`, with identities unique to `index`.
fn admit_request(who: Id128, token: Id128, index: u32) -> AdmitRequest {
    let base = request((index % 200) as u8 + 1);
    let plan = format!("plan-{who}-{token}").into_bytes();
    AdmitRequest {
        instance_id: who,
        allocation_id: token,
        sandbox_id: format!("sb-{:016x}", u64::from(index) + 1),
        plan_digest: Digest::of(&plan),
        plan,
        leases: crate::helper::firecracker::config::tests::sample_leases(index),
        ..base
    }
}

fn fence_for(request: &AdmitRequest) -> FenceRequest {
    FenceRequest {
        instance_id: request.instance_id,
        allocation_id: request.allocation_id,
        sandbox_id: request.sandbox_id.clone(),
        plan_digest: request.plan_digest,
        observations: "permits=settled;namespace=absent".into(),
    }
}

fn never_admitted(who: Id128, token: Id128) -> FenceRequest {
    FenceRequest {
        instance_id: who,
        allocation_id: token,
        sandbox_id: crate::model::new_id("sb"),
        plan_digest: Digest::of(b"never admitted"),
        observations: "permits=settled;namespace=absent".into(),
    }
}

/// Issues, admits and fences one session: its rows all exist, absent and released.
fn finished(ledger: &mut Ledger, who: Id128, index: u32) -> AdmitRequest {
    let token = issue(ledger, who);
    let request = admit_request(who, token, index);
    assert!(matches!(
        ledger.admit_intent(&request).unwrap(),
        AdmitOutcome::Accepted { .. }
    ));
    ledger.settle_unstarted(who, token).unwrap();
    assert!(matches!(
        ledger.commit_fence(&fence_for(&request)).unwrap(),
        FenceOutcome::Absent { replay: false, .. }
    ));
    request
}

fn admitted(ledger: &mut Ledger, who: Id128, index: u32) -> AdmitRequest {
    let token = issue(ledger, who);
    let request = admit_request(who, token, index);
    assert!(matches!(
        ledger.admit_intent(&request).unwrap(),
        AdmitOutcome::Accepted { .. }
    ));
    request
}

fn count(ledger: &Ledger, sql: &str) -> i64 {
    ledger.connection().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Moves W to `target` the way the compactor does, with the pointer as ceiling.
fn advance_to(ledger: &mut Ledger, who: Id128, target: u64) -> Option<Advance> {
    ledger.advance_watermark(who, target).unwrap()
}

fn compact_all(ledger: &mut Ledger, who: Id128) -> (u64, u64) {
    let (mut tokens, mut rows) = (0, 0);
    loop {
        let batch = ledger.compact_batch(who, COMPACTION_BATCH).unwrap();
        tokens += batch.tokens_deleted;
        rows += batch.rows_deleted;
        if !batch.more {
            return (tokens, rows);
        }
    }
}

fn receipt_of(lookup: TokenLookup) -> FencedAbsence {
    match lookup {
        TokenLookup::Compacted { receipt } | TokenLookup::Fenced { receipt } => {
            FencedAbsence::decode(&receipt).unwrap()
        }
        other => panic!("no receipt: {other:?}"),
    }
}

/// Runs `sql` on a raw connection with the named trigger dropped and then restored to
/// its exact original text, so the schema digest is unchanged: this is how a test models
/// a root-level edit that the triggers would otherwise refuse.
fn behind_trigger(config: &LedgerConfig, trigger: &str, sql: &str) {
    let conn = Connection::open(config.directory.join(LEDGER_DB)).unwrap();
    let text: String = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [trigger],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute_batch(&format!(
        "PRAGMA ignore_check_constraints = ON; BEGIN; DROP TRIGGER {trigger}; {sql}; {text}; COMMIT;"
    ))
    .unwrap();
}

// ---------------------------------------------------------------- RTC-1: the key

#[test]
fn rtc1_provisioning_writes_one_checked_key_and_open_never_makes_another() {
    let fixture = temp_ledger(unrestricted());
    let key = key_from_file(&fixture.config);
    let ledger = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(ledger.token_key(), &key, "open reads K back; it never regenerates it");
    let (length, check): (i64, Vec<u8>) = ledger
        .connection()
        .query_row(
            "SELECT length(key), key_check FROM token_key WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(length, 32);
    assert_eq!(check, key.check_value().to_vec());
    // Two provisionings of the same node draw independent keys from the kernel.
    let second = temp_ledger(unrestricted());
    assert_ne!(key_from_file(&second.config), key);
    drop(ledger);
    let reopened = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(reopened.token_key(), &key);
}

#[test]
fn rtc1_standard_sql_cannot_update_delete_or_replace_the_key() {
    let fixture = temp_ledger(unrestricted());
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    for sql in [
        "UPDATE token_key SET key = zeroblob(32)",
        "UPDATE token_key SET key_check = zeroblob(16)",
        "DELETE FROM token_key",
        "INSERT OR REPLACE INTO token_key (id, key, key_check, created_generation)
             VALUES (1, zeroblob(32), zeroblob(16), 1)",
        "INSERT INTO token_key (id, key, key_check, created_generation)
             VALUES (2, zeroblob(32), zeroblob(16), 1)",
    ] {
        assert!(conn.execute(sql, []).is_err(), "{sql}");
    }
    drop(conn);
    assert_eq!(key_from_file(&fixture.config).check_value().len(), 16);
    Ledger::open(fixture.config.clone()).unwrap();
}

#[test]
fn rtc1_missing_truncated_or_substituted_keys_fail_the_open_audit() {
    // Missing.
    let fixture = temp_ledger(unrestricted());
    behind_trigger(&fixture.config, "token_key_no_delete", "DELETE FROM token_key");
    let error = Ledger::open(fixture.config.clone()).err().unwrap();
    assert!(error.to_string().contains("missing"), "{error}");
    // Truncated (past its CHECK, as root could).
    let fixture = temp_ledger(unrestricted());
    behind_trigger(
        &fixture.config,
        "token_key_no_update",
        "UPDATE token_key SET key = zeroblob(16)",
    );
    let error = Ledger::open(fixture.config.clone()).err().unwrap();
    // quick_check reports the violated CHECK before the key audit even runs.
    assert!(matches!(error, LedgerError::Corrupt(_)), "{error}");
    // Substituted, same length, rowless: the check value catches it.
    let fixture = temp_ledger(unrestricted());
    behind_trigger(
        &fixture.config,
        "token_key_no_update",
        "UPDATE token_key SET key = zeroblob(32)",
    );
    let error = Ledger::open(fixture.config.clone()).err().unwrap();
    assert!(error.to_string().contains("check value"), "{error}");
    // Substituted with a matching check value, with rows left: their tags catch it.
    let fixture = temp_ledger(unrestricted());
    {
        let mut ledger = fresh(&fixture.config);
        finished(&mut ledger, instance(), 1);
    }
    let forged = TokenKey::from_parts(fixture.config.node_id, [7; 32]);
    let check: String = forged.check_value().iter().map(|b| format!("{b:02x}")).collect();
    behind_trigger(
        &fixture.config,
        "token_key_no_update",
        &format!(
            "UPDATE token_key SET key = x'{}', key_check = x'{check}'",
            "07".repeat(32)
        ),
    );
    let error = Ledger::open(fixture.config.clone()).err().unwrap();
    assert!(error.to_string().contains("tag"), "{error}");
    // The documented limit (16.7): substituted with its check value and no rows left to
    // check against opens, and every old token is then Malformed and stays charged.
    let fixture = temp_ledger(unrestricted());
    let old = {
        let mut ledger = fresh(&fixture.config);
        issue(&mut ledger, instance())
    };
    behind_trigger(
        &fixture.config,
        "token_key_no_update",
        &format!("UPDATE token_key SET key = x'{}', key_check = x'{check}'", "07".repeat(32)),
    );
    let ledger = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(
        ledger
            .lookup_token(instance(), old, &Digest::of(b"x"))
            .unwrap(),
        TokenLookup::Malformed
    );
}

#[test]
fn rtc1_a_crash_during_provisioning_leaves_no_ledger_that_opens() {
    let fixture = temp_ledger(unrestricted());
    // What a crash between the exclusive create and the provisioning commit leaves.
    let config = LedgerConfig {
        directory: fixture.root.join("half"),
        ..fixture.config.clone()
    };
    std::fs::create_dir(&config.directory).unwrap();
    std::fs::set_permissions(&config.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = config.directory.join(LEDGER_DB);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Ledger::open(config.clone()).is_err(), "an empty file is no ledger");
    assert!(matches!(
        Ledger::provision(&config),
        Err(LedgerError::Exists(_))
    ));
}

#[test]
fn rtc1_schema_1_ledgers_refuse_with_a_reprovision_message() {
    let fixture = temp_ledger(unrestricted());
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    let error = Ledger::open(fixture.config.clone()).err().unwrap();
    assert!(error.to_string().contains("re-provision"), "{error}");
}

// ------------------------------------------------- RTC-3, RTC-4, RTC-6: issue and read

#[test]
fn rtc4_issuance_raises_the_exact_pointer_once_and_refusals_write_nothing() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    for expected in 1..=5u64 {
        let token = issue(&mut ledger, instance());
        assert_eq!(token::seq_of(token), expected);
        assert_eq!(ledger.token_key().verify(instance(), token), Some(expected));
        assert_eq!(ledger.pointers(instance()).unwrap().issue_next, expected + 1);
    }
    // A latched issuance is refused before any write: no seq is consumed.
    let changes = ledger.connection().total_changes();
    let generation = ledger.generation().unwrap();
    assert_eq!(
        ledger.issue_and_snapshot(instance(), true).unwrap(),
        IssueOutcome::Refused {
            refusal: IssueRefusal::Latched
        }
    );
    assert_eq!(ledger.connection().total_changes(), changes);
    assert_eq!(ledger.generation().unwrap(), generation);
    assert_eq!(ledger.pointers(instance()).unwrap().issue_next, 6);
    // A failed commit leaves the pointer unchanged: the next issuance reuses nothing,
    // because nothing was issued.
    ledger.fail_next_commit();
    assert!(ledger.issue_and_snapshot(instance(), false).is_err());
    assert_eq!(ledger.pointers(instance()).unwrap().issue_next, 6);
    assert_eq!(token::seq_of(issue(&mut ledger, instance())), 6);
    // Reopened, the pointer is exactly the committed one.
    drop(ledger);
    let mut ledger = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(ledger.pointers(instance()).unwrap().issue_next, 7);
    assert_eq!(token::seq_of(issue(&mut ledger, instance())), 7);
}

#[test]
fn rtc4_the_pointer_never_wraps_and_never_moves_back() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    issue_through(&ledger, instance(), token::MAX_SEQ);
    assert_eq!(token::seq_of(issue(&mut ledger, instance())), token::MAX_SEQ);
    assert_eq!(
        ledger.pointers(instance()).unwrap().issue_next,
        token::POINTER_CEILING
    );
    assert_eq!(
        ledger.issue_and_snapshot(instance(), false).unwrap(),
        IssueOutcome::Refused {
            refusal: IssueRefusal::Exhausted
        }
    );
    for sql in [
        "UPDATE instance_tokens SET issue_next = 5",
        "UPDATE instance_tokens SET issue_next = 9223372036854775807 + 1",
        "UPDATE instance_tokens SET watermark = watermark - 1 WHERE watermark > 1",
        "UPDATE instance_tokens SET watermark = 3, watermark_generation = watermark_generation",
        "UPDATE instance_tokens SET watermark_generation = 0",
        "DELETE FROM instance_tokens",
    ] {
        let result = ledger.connection().execute(sql, []);
        assert!(
            result.is_err() || result == Ok(0),
            "{sql} changed a row: {result:?}"
        );
    }
    assert_eq!(
        ledger.pointers(instance()).unwrap().issue_next,
        token::POINTER_CEILING
    );
}

#[test]
fn rtc3_rtc6_l_classifies_malformed_not_issued_rows_compacted_then_unknown() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    attach_new(&mut ledger, other());
    let digest = Digest::of(b"plan");
    let lookup = |ledger: &Ledger, token: Id128, digest: &Digest| {
        ledger.lookup_token(instance(), token, digest).unwrap()
    };
    // Malformed: an old random ID, seq 0, a flipped tag bit, another instance's token.
    let issued = issue(&mut ledger, instance());
    let mut flipped = *issued.as_bytes();
    flipped[15] ^= 1;
    let foreign = issue(&mut ledger, other());
    let mut zero = *issued.as_bytes();
    zero[..8].copy_from_slice(&[0; 8]);
    for token in [
        Id128::random(),
        Id128::from_bytes(zero),
        Id128::from_bytes(flipped),
        foreign,
    ] {
        assert_eq!(lookup(&ledger, token, &digest), TokenLookup::Malformed);
    }
    // NotIssued: a valid tag at and beyond the durable pointer, before and after reopen.
    let next = ledger.pointers(instance()).unwrap().issue_next;
    let key = ledger.token_key().clone();
    for seq in [next, next + 1, token::MAX_SEQ] {
        assert_eq!(
            lookup(&ledger, key.issue(instance(), seq), &digest),
            TokenLookup::NotIssued
        );
    }
    // Issued and rowless, at or above W: Unknown (admittable).
    assert_eq!(lookup(&ledger, issued, &digest), TokenLookup::Unknown);
    // Rows answer, and a different digest is Conflict.
    let active = admitted(&mut ledger, instance(), 1);
    assert!(matches!(
        lookup(&ledger, active.allocation_id, &active.plan_digest),
        TokenLookup::Active { .. }
    ));
    assert!(matches!(
        lookup(&ledger, active.allocation_id, &digest),
        TokenLookup::Conflict { .. }
    ));
    let done = finished(&mut ledger, instance(), 2);
    assert!(matches!(
        lookup(&ledger, done.allocation_id, &done.plan_digest),
        TokenLookup::Fenced { .. }
    ));
    assert!(matches!(
        lookup(&ledger, done.allocation_id, &digest),
        TokenLookup::Conflict { .. }
    ));
    // W passes the rowless token: Compacted, for the caller's own digest.
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    advance_to(&mut ledger, instance(), pointer).unwrap();
    let receipt = receipt_of(lookup(&ledger, issued, &digest));
    assert_eq!(receipt.plan_digest(), digest);
    // Rows still outrank W: the active and the fenced token answer from their rows.
    assert!(matches!(
        lookup(&ledger, active.allocation_id, &active.plan_digest),
        TokenLookup::Active { .. }
    ));
    assert!(matches!(
        lookup(&ledger, done.allocation_id, &done.plan_digest),
        TokenLookup::Fenced { .. }
    ));
    drop(ledger);
    let ledger = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(
        lookup(&ledger, key.issue(instance(), pointer), &digest),
        TokenLookup::NotIssued
    );
}

// ------------------------------------------------- RTC-7, RTC-8, RTC-9: below W

#[test]
fn rtc8_compacted_receipts_bind_the_callers_digest_generation_and_write_nothing() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let rowless = issue(&mut ledger, instance());
    issue(&mut ledger, instance());
    let advance = advance_to(&mut ledger, instance(), 3).unwrap();
    let pointers = ledger.pointers(instance()).unwrap();
    assert_eq!((pointers.watermark, pointers.watermark_generation), (3, advance.generation));
    let changes = ledger.connection().total_changes();
    let generation = ledger.generation().unwrap();
    let (a, b) = (Digest::of(b"store binding"), Digest::of(b"another digest"));
    let first = receipt_of(ledger.inspect(instance(), rowless, &a).unwrap());
    let again = receipt_of(ledger.inspect(instance(), rowless, &a).unwrap());
    let elsewhere = receipt_of(ledger.inspect(instance(), rowless, &b).unwrap());
    assert_eq!(first, again, "the same inputs answer the same receipt, from no cache");
    assert_eq!(first.plan_digest(), a);
    assert_eq!(elsewhere.plan_digest(), b);
    assert_ne!(first.receipt_id(), elsewhere.receipt_id());
    assert_eq!(first.helper_generation(), advance.generation);
    assert_eq!(
        first.receipt_id(),
        token::compacted_receipt_id(
            fixture.config.node_id,
            instance(),
            rowless,
            &a,
            advance.generation
        )
    );
    assert_eq!(first.node_id(), fixture.config.node_id);
    assert_eq!(first.instance_id(), instance());
    assert_eq!(first.allocation_id(), rowless);
    let binding = crate::model::AllocationBinding {
        node_id: fixture.config.node_id,
        instance_id: instance(),
        allocation_id: rowless,
        plan_version: 1,
        plan_digest: a,
        plan: vec![],
    };
    assert!(first.matches(&binding));
    assert!(!elsewhere.matches(&binding), "the daemon's match refuses another digest");
    // FenceAbsent and Create get the same answer, and nothing is written by any of them.
    assert!(matches!(
        ledger.commit_fence(&never_admitted(instance(), rowless)).unwrap(),
        FenceOutcome::Absent { replay: true, .. }
    ));
    let mut late = admit_request(instance(), rowless, 9);
    late.plan_digest = a;
    let AdmitOutcome::Fenced { receipt } = ledger.admit_intent(&late).unwrap() else {
        panic!("a compacted token is never admitted");
    };
    assert_eq!(FencedAbsence::decode(&receipt).unwrap(), first);
    assert_eq!(ledger.connection().total_changes(), changes);
    assert_eq!(ledger.generation().unwrap(), generation);
    assert_eq!(count(&ledger, "SELECT COUNT(*) FROM allocations"), 0);
    assert_eq!(count(&ledger, "SELECT COUNT(*) FROM retired_tokens"), 0);
    // A later advance gives a later, different receipt for the same token (RTC-9).
    issue(&mut ledger, instance());
    let later = advance_to(&mut ledger, instance(), 4).unwrap();
    let newer = receipt_of(ledger.inspect(instance(), rowless, &a).unwrap());
    assert_eq!(newer.helper_generation(), later.generation);
    assert!(newer.helper_generation() > first.helper_generation());
    assert_ne!(newer.receipt_id(), first.receipt_id());
}

#[test]
fn rtc7_nothing_below_w_is_admitted_or_newly_fenced_even_by_raw_sql() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let below = issue(&mut ledger, instance());
    let above = issue(&mut ledger, instance());
    advance_to(&mut ledger, instance(), token::seq_of(above)).unwrap();
    // C2's lookup refuses it with the synthesized receipt, before capacity.
    assert!(matches!(
        ledger.admit_intent(&admit_request(instance(), below, 1)).unwrap(),
        AdmitOutcome::Fenced { .. }
    ));
    // At W it is admitted.
    assert!(matches!(
        ledger.admit_intent(&admit_request(instance(), above, 2)).unwrap(),
        AdmitOutcome::Accepted { .. }
    ));
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    let seq = token::seq_of(below);
    // The INSERT triggers refuse what the lookup would: below W, and at the pointer.
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    let unissued = ledger.token_key().issue(instance(), pointer);
    for (token, seq) in [(below, seq), (unissued, pointer)] {
        assert!(
            conn.execute(
                "INSERT INTO allocations (allocation_id, instance_id, sandbox_id, backend_id,
                    plan_version, plan_digest, profile, manifest_sha256, host_spec_sha256,
                    guest_exec_spec_sha256, work_uuid, stop_authority, phase,
                    created_generation, updated_generation, issue_seq)
                 VALUES (?1, ?2, 'sb-x', 'fc-x', 1, 'd', 'p', 'm', 'h', 'g', 'w', 's', 'intent',
                    1000, 1000, ?3)",
                params![token.to_string(), instance().to_string(), seq as i64],
            )
            .is_err(),
            "allocation {seq}"
        );
        assert!(
            conn.execute(
                "INSERT INTO retired_tokens (allocation_id, instance_id, sandbox_id, plan_digest,
                    receipt_id, helper_generation, receipt, issue_seq)
                 VALUES (?1, ?2, 'sb-y', 'd', ?3, 99999, x'00', ?4)",
                params![
                    token.to_string(),
                    instance().to_string(),
                    Id128::random().to_string(),
                    seq as i64
                ],
            )
            .is_err(),
            "fence {seq}"
        );
    }
    // A hex prefix that disagrees with its seq is refused by the CHECK.
    assert!(
        conn.execute(
            "INSERT INTO retired_tokens (allocation_id, instance_id, sandbox_id, plan_digest,
                receipt_id, helper_generation, receipt, issue_seq)
             VALUES (?1, ?2, 'sb-z', 'd', ?3, 99998, x'00', 2)",
            params![
                above.to_string(),
                instance().to_string(),
                Id128::random().to_string()
            ],
        )
        .is_err()
    );
    // A pinned allocation below W still reaches ABSENT with its own fence row.
    let pinned_request = admit_request(instance(), above, 2);
    issue(&mut ledger, instance());
    advance_to(&mut ledger, instance(), 1 << 20).unwrap();
    ledger.settle_unstarted(instance(), above).unwrap();
    assert!(matches!(
        ledger.commit_fence(&fence_for(&pinned_request)).unwrap(),
        FenceOutcome::Absent { replay: false, .. }
    ));
}

#[test]
fn rtc9_a_late_pinned_fence_refreshes_g_w_before_anything_is_compacted() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let pinned = admitted(&mut ledger, instance(), 1);
    issue(&mut ledger, instance());
    let first = advance_to(&mut ledger, instance(), 3).unwrap();
    // W passed the READY allocation, which is pinned by its rows.
    assert!(matches!(
        ledger
            .lookup_token(instance(), pinned.allocation_id, &pinned.plan_digest)
            .unwrap(),
        TokenLookup::Active { .. }
    ));
    ledger.settle_unstarted(instance(), pinned.allocation_id).unwrap();
    let (original, _) = match ledger.commit_fence(&fence_for(&pinned)).unwrap() {
        FenceOutcome::Absent { receipt, replay } => (FencedAbsence::decode(&receipt).unwrap(), replay),
        other => panic!("{other:?}"),
    };
    assert!(original.helper_generation() > first.generation);
    // Nothing compacts while its fence generation is at or above G_W.
    let batch = ledger.compact_batch(instance(), COMPACTION_BATCH).unwrap();
    assert_eq!(batch.tokens_deleted, 0);
    assert!(batch.stuck.is_empty());
    // The refresh: same W, fresh G_W.
    let refresh = advance_to(&mut ledger, instance(), 3).unwrap();
    assert_eq!((refresh.from, refresh.to), (3, 3));
    assert!(refresh.generation > original.helper_generation());
    assert_eq!(compact_all(&mut ledger, instance()).0, 1);
    let synthesized = receipt_of(
        ledger
            .inspect(instance(), pinned.allocation_id, &pinned.plan_digest)
            .unwrap(),
    );
    assert!(synthesized.helper_generation() > original.helper_generation());
    assert!(synthesized.matches(&crate::model::AllocationBinding {
        node_id: fixture.config.node_id,
        instance_id: instance(),
        allocation_id: pinned.allocation_id,
        plan_version: 1,
        plan_digest: pinned.plan_digest,
        plan: vec![],
    }));
    // Nothing to refresh now: the next pass writes nothing.
    assert_eq!(advance_to(&mut ledger, instance(), 3), None);
}

// ------------------------------------------------- RTC-10, RTC-11: compaction

#[test]
fn rtc10_only_absent_released_settled_rows_compact_children_first() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let done = finished(&mut ledger, instance(), 1);
    ledger
        .record_stop(instance(), done.allocation_id, "x")
        .unwrap_err();
    let ready = admitted(&mut ledger, instance(), 2);
    let stopped = admitted(&mut ledger, instance(), 3);
    ledger
        .record_stop(instance(), stopped.allocation_id, "delete")
        .unwrap();
    let quarantined = admitted(&mut ledger, instance(), 4);
    ledger
        .set_phase(
            instance(),
            quarantined.allocation_id,
            &["intent".to_string()],
            "quarantined",
        )
        .unwrap();
    let never = issue(&mut ledger, instance());
    assert!(matches!(
        ledger.commit_fence(&never_admitted(instance(), never)).unwrap(),
        FenceOutcome::Absent { .. }
    ));
    issue(&mut ledger, instance());
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    advance_to(&mut ledger, instance(), pointer).unwrap();
    let before = count(&ledger, "SELECT COUNT(*) FROM allocations");
    let (tokens, rows) = compact_all(&mut ledger, instance());
    assert_eq!(tokens, 2, "the finished session and the never-admitted fence");
    assert!(rows > 2);
    assert_eq!(count(&ledger, "SELECT COUNT(*) FROM allocations"), before - 1);
    for kept in [&ready, &stopped, &quarantined] {
        assert!(matches!(
            ledger
                .lookup_token(instance(), kept.allocation_id, &kept.plan_digest)
                .unwrap(),
            TokenLookup::Active { .. }
        ));
    }
    for gone in [done.allocation_id, never] {
        for table in [
            "allocations",
            "capacity_claims",
            "identity_leases",
            "executable_leases",
            "worker_intents",
            "stop_events",
            "resource_events",
            "retired_tokens",
        ] {
            let left: i64 = ledger
                .connection()
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE allocation_id = ?1"),
                    [gone.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(left, 0, "{table}");
        }
    }
    assert_eq!(ledger.pointers(instance()).unwrap().retained_admitted, 3);
    // Idempotent: a rerun deletes nothing more.
    assert_eq!(compact_all(&mut ledger, instance()), (0, 0));
    // The open audit accepts the compacted ledger.
    drop(ledger);
    Ledger::open(fixture.config.clone()).unwrap();
}

#[test]
fn rtc10_trigger_matrix_refuses_every_delete_of_a_non_compactable_row() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let ready = admitted(&mut ledger, instance(), 1);
    let done = finished(&mut ledger, instance(), 2);
    let above = finished(&mut ledger, instance(), 3);
    // W passes `ready` and `done` but not `above`.
    advance_to(&mut ledger, instance(), token::seq_of(above.allocation_id)).unwrap();
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    let families = [
        "resource_events",
        "stop_events",
        "worker_intents",
        "executable_leases",
        "identity_leases",
        "capacity_claims",
        "allocations",
        "retired_tokens",
    ];
    // Active, below W: nothing of it may go.
    for table in families {
        let result = conn.execute(
            &format!("DELETE FROM {table} WHERE allocation_id = ?1"),
            [ready.allocation_id.to_string()],
        );
        assert!(result.is_err() || result == Ok(0), "{table}: {result:?}");
    }
    // Fenced at or above W: still permanent.
    for table in families {
        let result = conn.execute(
            &format!("DELETE FROM {table} WHERE allocation_id = ?1"),
            [above.allocation_id.to_string()],
        );
        assert!(result.is_err() || result == Ok(0), "{table}: {result:?}");
    }
    // Fenced below W, but its fence generation is not behind G_W? It is (the advance came
    // after), so children may go; the allocation may not go before its children, nor the
    // fence before the allocation.
    assert!(
        conn.execute(
            "DELETE FROM retired_tokens WHERE allocation_id = ?1",
            [done.allocation_id.to_string()],
        )
        .is_err(),
        "the fence row goes last"
    );
    assert!(
        conn.execute(
            "DELETE FROM allocations WHERE allocation_id = ?1",
            [done.allocation_id.to_string()],
        )
        .is_err(),
        "the allocation goes after its children"
    );
    // A released lease row may go; an unreleased one never.
    assert!(
        conn.execute(
            "DELETE FROM identity_leases WHERE allocation_id = ?1",
            [done.allocation_id.to_string()],
        )
        .is_ok()
    );
    // Counter drift and pointer lowering fail through standard SQL.
    for sql in [
        "UPDATE instance_tokens SET retained_admitted = retained_admitted + 1",
        "UPDATE instance_tokens SET retained_admitted = 0",
        "UPDATE instance_tokens SET issue_next = 1",
        "UPDATE instance_tokens SET watermark = 1",
    ] {
        assert!(conn.execute(sql, []).is_err(), "{sql}");
    }
}

#[test]
fn rtc11_a_failed_delete_or_advance_commit_rolls_back_whole() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    for index in 1..=5 {
        finished(&mut ledger, instance(), index);
    }
    issue(&mut ledger, instance());
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    ledger.fail_next_commit();
    assert!(ledger.advance_watermark(instance(), pointer).is_err());
    assert_eq!(ledger.pointers(instance()).unwrap().watermark, 1);
    advance_to(&mut ledger, instance(), pointer).unwrap();
    let rows = count(&ledger, "SELECT COUNT(*) FROM allocations")
        + count(&ledger, "SELECT COUNT(*) FROM retired_tokens");
    ledger.fail_next_commit();
    assert!(ledger.compact_batch(instance(), COMPACTION_BATCH).is_err());
    assert_eq!(
        count(&ledger, "SELECT COUNT(*) FROM allocations")
            + count(&ledger, "SELECT COUNT(*) FROM retired_tokens"),
        rows,
        "the uncommitted batch rolled back whole"
    );
    assert_eq!(compact_all(&mut ledger, instance()).0, 5);
    assert_eq!(compact_all(&mut ledger, instance()), (0, 0));
    // Every answer is the same whatever the crash left: rows gone answer Compacted.
    let probe = admit_request(instance(), token(instance(), 1), 1);
    assert!(matches!(
        ledger
            .lookup_token(instance(), probe.allocation_id, &probe.plan_digest)
            .unwrap(),
        TokenLookup::Compacted { .. }
    ));
}

#[test]
fn rtc11_batches_are_bounded_and_more_reports_what_is_left() {
    let fixture = temp_ledger(unrestricted());
    let mut config = fixture.config.clone();
    config.max_enrolled = 1;
    let mut ledger = fresh(&config);
    for index in 1..=10 {
        finished(&mut ledger, instance(), index);
    }
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    advance_to(&mut ledger, instance(), pointer).unwrap();
    let first = ledger.compact_batch(instance(), 4).unwrap();
    assert_eq!(first.tokens_deleted, 4);
    assert!(first.more);
    let second = ledger.compact_batch(instance(), 4).unwrap();
    assert_eq!(second.tokens_deleted, 4);
    assert!(second.more);
    let third = ledger.compact_batch(instance(), 4).unwrap();
    assert_eq!(third.tokens_deleted, 2);
    assert!(!third.more);
    let log = ledger.last_compaction(instance()).unwrap().unwrap();
    assert_eq!(log["tokens_deleted"], 10);
}

#[test]
fn rtc10_a_corrupt_fenced_row_is_named_stuck_and_never_deleted() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let done = finished(&mut ledger, instance(), 1);
    issue(&mut ledger, instance());
    // Root "un-settles" a worker of the fenced allocation behind the trigger.
    behind_trigger(
        &fixture.config,
        "worker_intents_immutable",
        &format!(
            "UPDATE worker_intents SET settled_generation = NULL, settlement = NULL
             WHERE allocation_id = '{}'",
            done.allocation_id
        ),
    );
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    advance_to(&mut ledger, instance(), pointer).unwrap();
    let batch = ledger.compact_batch(instance(), COMPACTION_BATCH).unwrap();
    assert_eq!(batch.tokens_deleted, 0);
    assert_eq!(batch.stuck, vec![done.allocation_id]);
    assert!(matches!(
        ledger
            .lookup_token(instance(), done.allocation_id, &done.plan_digest)
            .unwrap(),
        TokenLookup::Fenced { .. }
    ));
}

// ------------------------------------------------- RTC-12: quotas per window

#[test]
fn rtc12_the_never_admitted_quota_counts_retained_rows_and_refills_after_compaction() {
    let fixture = temp_ledger(unrestricted());
    let mut config = fixture.config.clone();
    config.shared.fence_allowance_bytes = 64 * FENCE_ENTRY_BOUND;
    config.max_enrolled = 1;
    let mut ledger = fresh(&config);
    let quota = never_admitted_quota(ledger.connection(), &config).unwrap();
    assert_eq!(quota, 16);
    let mut issued = Vec::new();
    // Issuance stops at the floor, three quarters of the quota.
    loop {
        match ledger.issue_and_snapshot(instance(), false).unwrap() {
            IssueOutcome::Issued { token, .. } => {
                assert!(matches!(
                    ledger.commit_fence(&never_admitted(instance(), token)).unwrap(),
                    FenceOutcome::Absent { .. }
                ));
                issued.push(token);
            }
            IssueOutcome::Refused { refusal } => {
                assert_eq!(refusal, IssueRefusal::NeverAdmittedFloor);
                break;
            }
        }
    }
    assert_eq!(issued.len() as u64, quota - quota / 4);
    // The window refills once W passes them and their rows compact.
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    advance_to(&mut ledger, instance(), pointer).unwrap();
    assert_eq!(compact_all(&mut ledger, instance()).0, issued.len() as u64);
    assert!(matches!(
        ledger.issue_and_snapshot(instance(), false).unwrap(),
        IssueOutcome::Issued { .. }
    ));
    // Admitted tokens are never refused a fence, whatever the quota.
    let session = admitted(&mut ledger, instance(), 7);
    ledger.settle_unstarted(instance(), session.allocation_id).unwrap();
    assert!(matches!(
        ledger.commit_fence(&fence_for(&session)).unwrap(),
        FenceOutcome::Absent { .. }
    ));
}

// ------------------------------------------------- RTC-13: the compactor in L

#[test]
fn rtc13_nothing_advances_for_a_lease_after_start_and_an_idle_tail_compacts() {
    use crate::helper::firecracker::compaction::Compactor;
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    let policy = CompactionPolicy {
        lease_ms: 60_000,
        pass_ms: 10_000,
    };
    for index in 1..=3 {
        finished(&mut ledger, instance(), index);
    }
    let mut compactor = Compactor::start(policy, Some(&ledger), 0);
    assert_eq!(compactor.checkpoints(instance()), 1, "the restart point");
    for now in (0..60_000).step_by(10_000) {
        let reply = compactor.pass(&mut ledger, instance(), 256, now).unwrap();
        assert!(reply.advanced.is_none(), "nothing advances inside the first lease");
    }
    let reply = compactor.pass(&mut ledger, instance(), 256, 60_000).unwrap();
    assert_eq!(reply.advanced.unwrap().to, 4);
    assert_eq!(reply.batch.tokens_deleted, 3);
    assert_eq!(compactor.checkpoints(instance()), 0, "pruned at or below W");
    // RTC-R2-02: fully idle and drained, then one token much later.
    let last = finished(&mut ledger, instance(), 9);
    let now = 10_000_000;
    let mut advanced_at = None;
    for step in 0..20 {
        let at = now + step * 10_000;
        let reply = compactor.pass(&mut ledger, instance(), 256, at).unwrap();
        assert!(compactor.checkpoints(instance()) <= compactor.bound() as u64);
        if reply.advanced.is_some() && reply.batch.tokens_deleted == 1 {
            advanced_at = Some(at);
            break;
        }
    }
    let at = advanced_at.expect("the last token compacts");
    assert!(at - now <= policy.lease_ms + 2 * policy.pass_ms);
    assert!(matches!(
        ledger
            .lookup_token(instance(), last.allocation_id, &last.plan_digest)
            .unwrap(),
        TokenLookup::Compacted { .. }
    ));
    assert_eq!(ledger.pointers(instance()).unwrap().retained_admitted, 0);
    assert_eq!(count(&ledger, "SELECT COUNT(*) FROM retired_tokens"), 0);
}

// ------------------------------------------------- RTC-14: rollback faults

#[test]
fn rtc14_only_a_verified_future_token_is_rollback_evidence_and_nothing_is_written_first() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    attach_new(&mut ledger, other());
    let own = issue(&mut ledger, instance());
    let newest = issue(&mut ledger, instance());
    let foreign = issue(&mut ledger, other());
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    let key = ledger.token_key().clone();
    let mut flipped = *newest.as_bytes();
    flipped[12] ^= 0x10;
    let mut guessed = *key.issue(instance(), pointer).as_bytes();
    guessed[8..].copy_from_slice(&[0xaa; 8]);
    let mut high = *key.issue(instance(), token::MAX_SEQ).as_bytes();
    high[8..].copy_from_slice(&[0x55; 8]);
    let changes = ledger.connection().total_changes();
    let generation = ledger.generation().unwrap();
    for spoof in [
        Id128::from_bytes([0; 16]),
        Id128::from_bytes(guessed),
        Id128::from_bytes(high),
        foreign,
        Id128::from_bytes(flipped),
    ] {
        assert_eq!(
            ledger
                .attach_instance(instance(), database_of(&ledger), Some(spoof), false)
                .unwrap(),
            AttachOutcome::Malformed,
            "{spoof}"
        );
    }
    // A past and the newest legitimate token are the normal case.
    for honest in [own, newest] {
        assert!(matches!(
            ledger
                .attach_instance(instance(), database_of(&ledger), Some(honest), false)
                .unwrap(),
            AttachOutcome::Bound { .. }
        ));
    }
    assert_eq!(ledger.connection().total_changes(), changes, "no write, no fault");
    assert_eq!(ledger.generation().unwrap(), generation);
    assert_eq!(ledger.durable_faults().unwrap(), 0);
    // A verified token at the pointer: evidence, answered before any write.
    let future = key.issue(instance(), pointer);
    assert_eq!(
        ledger
            .attach_instance(instance(), database_of(&ledger), Some(future), false)
            .unwrap(),
        AttachOutcome::RollbackDetected {
            token: future,
            issue_next: pointer
        }
    );
    assert_eq!(ledger.connection().total_changes(), changes);
    // The commit is idempotent by instance and token.
    let fault = ledger.commit_fault(instance(), future, pointer).unwrap();
    assert_eq!(ledger.commit_fault(instance(), future, pointer).unwrap(), fault);
    assert_eq!(ledger.durable_faults().unwrap(), 1);
    // Latched: no issuance anywhere, and no first binding; reattachment still works.
    assert_eq!(
        ledger.issue_and_snapshot(other(), false).unwrap(),
        IssueOutcome::Refused {
            refusal: IssueRefusal::Latched
        }
    );
    let late = Id128::from_bytes([0x66; 16]);
    assert!(matches!(
        ledger
            .enroll_instance(&enrollment_of(late), MAX_ENROLLED_HARD)
            .unwrap(),
        EnrollOutcome::Enrolled { .. }
    ));
    assert_eq!(
        ledger.attach_instance(late, database(), None, false).unwrap(),
        AttachOutcome::Latched
    );
    assert!(matches!(
        ledger
            .attach_instance(other(), database_of_other(&ledger), None, false)
            .unwrap(),
        AttachOutcome::Bound { .. }
    ));
    // Insert-only, through standard SQL.
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    for sql in [
        "UPDATE node_faults SET detail = 'x'",
        "DELETE FROM node_faults",
        "INSERT OR REPLACE INTO node_faults (id, generation, kind, instance_id, token,
            issue_next_seen, detail) SELECT id, generation, kind, instance_id, token, 1, 'x'
            FROM node_faults",
        "INSERT INTO node_fault_clears (generation, cleared_through_generation,
            inventory_sha256, raised_pointers)
            SELECT value, 1000000, 'x', '[]' FROM generation_counter",
    ] {
        assert!(conn.execute(sql, []).is_err(), "{sql}");
    }
    drop(conn);
    assert_eq!(ledger.durable_faults().unwrap(), 1);
    // A durable fault survives reopen, and the replay snapshot latches H.
    drop(ledger);
    let ledger = Ledger::open(fixture.config.clone()).unwrap();
    assert_eq!(ledger.replay().unwrap().node_faults, vec!["rollback"]);
}

fn database_of(_ledger: &Ledger) -> Id128 {
    Id128::from_bytes([instance().as_bytes()[0] ^ 0x5a; 16])
}

fn database_of_other(_ledger: &Ledger) -> Id128 {
    Id128::from_bytes([other().as_bytes()[0] ^ 0x5a; 16])
}

#[test]
fn rtc14_the_offline_clear_is_current_only_raises_pointers_and_deletes_faults() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    issue(&mut ledger, instance());
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    let key = ledger.token_key().clone();
    let recorded = key.issue(instance(), pointer + 5);
    let fault = ledger.commit_fault(instance(), recorded, pointer).unwrap();
    let generation = ledger.generation().unwrap();
    let w_before = ledger.pointers(instance()).unwrap().watermark;
    // Stale reports change nothing.
    for (stale_generation, faults) in [
        (generation - 1, vec![fault]),
        (generation, vec![]),
        (generation, vec![fault, fault + 1]),
    ] {
        assert_eq!(
            ledger
                .clear_node_faults(
                    stale_generation,
                    &faults,
                    &[(instance(), Some(recorded))],
                    Digest::of(b"r")
                )
                .unwrap(),
            ClearOutcome::Stale
        );
    }
    // A foreign or forged token refuses.
    let mut forged = *recorded.as_bytes();
    forged[9] ^= 1;
    assert_eq!(
        ledger
            .clear_node_faults(
                generation,
                &[fault],
                &[(instance(), Some(Id128::from_bytes(forged)))],
                Digest::of(b"r")
            )
            .unwrap(),
        ClearOutcome::Malformed {
            instance: instance()
        }
    );
    assert_eq!(ledger.durable_faults().unwrap(), 1);
    assert_eq!(ledger.generation().unwrap(), generation);
    // The clear: pointer raised past the recorded token, W untouched, faults gone.
    let ClearOutcome::Cleared {
        cleared_through, ..
    } = ledger
        .clear_node_faults(
            generation,
            &[fault],
            &[(instance(), Some(recorded))],
            Digest::of(b"r"),
        )
        .unwrap()
    else {
        panic!("not cleared");
    };
    assert_eq!(cleared_through, fault);
    assert_eq!(ledger.durable_faults().unwrap(), 0);
    let after = ledger.pointers(instance()).unwrap();
    assert_eq!(after.issue_next, pointer + 6);
    assert_eq!(after.watermark, w_before);
    // Nothing recorded is ever issued again.
    assert!(token::seq_of(issue(&mut ledger, instance())) > token::seq_of(recorded));
    // The clear row is permanent, and the audit accepts the cleared ledger.
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    assert!(conn.execute("DELETE FROM node_fault_clears", []).is_err());
    assert!(conn.execute("UPDATE node_fault_clears SET raised_pointers = ''", []).is_err());
    drop(conn);
    drop(ledger);
    Ledger::open(fixture.config.clone()).unwrap();
}

// ------------------------------------------------- RTC-16: the open audit

#[test]
fn rtc16_the_audit_refuses_drifted_counters_bad_tags_and_uncovered_clears() {
    // A retained counter that disagrees with its rows.
    let fixture = temp_ledger(unrestricted());
    {
        let mut ledger = fresh(&fixture.config);
        admitted(&mut ledger, instance(), 1);
    }
    behind_trigger(
        &fixture.config,
        "instance_tokens_counted",
        "UPDATE instance_tokens SET retained_admitted = 0",
    );
    assert!(Ledger::open(fixture.config.clone()).is_err());
    // A stored token whose tag was forged in place.
    let fixture = temp_ledger(unrestricted());
    let session = {
        let mut ledger = fresh(&fixture.config);
        finished(&mut ledger, instance(), 1)
    };
    let mut forged = session.allocation_id.to_string();
    forged.replace_range(30..32, if &forged[30..32] == "00" { "01" } else { "00" });
    let conn = Connection::open(fixture.config.directory.join(LEDGER_DB)).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA recursive_triggers = OFF;")
        .unwrap();
    drop(conn);
    behind_trigger(
        &fixture.config,
        "retired_tokens_no_update",
        &format!(
            "UPDATE retired_tokens SET allocation_id = '{forged}' WHERE allocation_id = '{}'",
            session.allocation_id
        ),
    );
    let error = Ledger::open(fixture.config.clone()).err().unwrap();
    assert!(
        error.to_string().contains("tag") || error.to_string().contains("receipt"),
        "{error}"
    );
}

// ------------------------------------------------- RTC-17: reserved shares

/// A tiny policy: E = 7 admitted entries and two slots, so share 3 and remainder 1.
fn tiny(config: &LedgerConfig) -> LedgerConfig {
    let mut tiny = config.clone();
    tiny.shared.fence_allowance_bytes = 10 * FENCE_ENTRY_BOUND;
    tiny.max_enrolled = 2;
    tiny
}

#[test]
fn rtc17_an_enrolled_instance_finds_its_whole_share_while_a_borrower_keeps_its_rows() {
    let fixture = temp_ledger(unrestricted());
    let config = tiny(&fixture.config);
    let mut ledger = fresh(&config);
    assert_eq!(admitted_entries(&config), 7);
    // A takes its share and the one unreserved entry, and is refused the fifth.
    let mut held = Vec::new();
    for index in 0..4 {
        held.push(admitted(&mut ledger, instance(), index));
    }
    assert!(!ledger.admitted_headroom(instance()).unwrap());
    assert_eq!(
        ledger.issue_and_snapshot(instance(), false).unwrap(),
        IssueOutcome::Refused {
            refusal: IssueRefusal::Headroom
        }
    );
    // B is enrolled (root, helper stopped) while A keeps every row: its share is free.
    attach_new(&mut ledger, other());
    for index in 10..13 {
        admitted(&mut ledger, other(), index);
    }
    assert!(!ledger.admitted_headroom(other()).unwrap(), "B holds its share");
    assert!(!ledger.admitted_headroom(instance()).unwrap(), "A is still at its ceiling");
    // C2 rechecks inside its own transaction: a token issued earlier cannot exceed it.
    let mut late = admit_request(instance(), token(instance(), 1), 50);
    late.allocation_id = {
        // Issued before the space filled: raise A's pointer and take a valid token.
        issue_through(&ledger, instance(), 100);
        ledger.token_key().issue(instance(), 99)
    };
    assert_eq!(
        ledger.admit_intent(&late).unwrap(),
        AdmitOutcome::Capacity {
            dimension: Dimension::LedgerSpace
        }
    );
    // Every admitted token still fences (no admitted token is refused a fence).
    for request in held {
        ledger.settle_unstarted(instance(), request.allocation_id).unwrap();
        assert!(matches!(
            ledger.commit_fence(&fence_for(&request)).unwrap(),
            FenceOutcome::Absent { .. }
        ));
    }
    // Fenced rows still count until they compact; afterwards A has room again.
    assert!(!ledger.admitted_headroom(instance()).unwrap());
    let pointer = ledger.pointers(instance()).unwrap().issue_next;
    advance_to(&mut ledger, instance(), pointer).unwrap();
    compact_all(&mut ledger, instance());
    assert!(ledger.admitted_headroom(instance()).unwrap());
}

#[test]
fn rtc17_a_hog_never_starves_a_victim_below_its_share_at_the_default_policy() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    ledger.test_unsynchronized();
    attach_new(&mut ledger, other());
    let shares = Shares::read(ledger.connection(), &fixture.config).unwrap();
    assert_eq!((shares.entries, shares.slots, shares.share), (4914, 8, 614));
    let ceiling = 614 + 2;
    // The hog takes everything it may: its share plus the unreserved remainder.
    let mut hog = 0;
    while ledger.admitted_headroom(instance()).unwrap() {
        admitted(&mut ledger, instance(), hog);
        hog += 1;
    }
    assert_eq!(hog, ceiling);
    // The victim, below its share, is never refused.
    for index in 0..614 {
        assert!(ledger.admitted_headroom(other()).unwrap(), "{index}");
        admitted(&mut ledger, other(), 100_000 + index);
    }
    assert!(!ledger.admitted_headroom(other()).unwrap());
}

#[test]
fn rtc17_enrolling_past_the_policy_maximum_is_refused_when_shares_would_shrink() {
    let fixture = temp_ledger(unrestricted());
    let config = tiny(&fixture.config);
    let mut ledger = fresh(&config);
    for index in 0..4 {
        admitted(&mut ledger, instance(), index);
    }
    attach_new(&mut ledger, other());
    // A third slot would shrink every share to 2; A's four rows would not fit it.
    assert_eq!(
        ledger
            .enroll_instance(&enrollment_of(Id128::from_bytes([0x77; 16])), MAX_ENROLLED_HARD)
            .unwrap(),
        EnrollOutcome::NoSpace
    );
    // A policy lowered under existing rows is reported as a shortfall, not hidden.
    let mut shrunk = config.clone();
    shrunk.shared.fence_allowance_bytes = 8 * FENCE_ENTRY_BOUND;
    drop(ledger);
    let ledger = Ledger::open(shrunk).unwrap();
    let snapshot = ledger.accounting(Some(instance())).unwrap();
    assert!(snapshot.share_shortfall > 0);
    assert!(snapshot.degraded.is_some());
}

// ------------------------------------------------- accounting (RTC-16) and bounds

#[test]
fn rtc16_accounting_reports_only_the_callers_token_figures() {
    let fixture = temp_ledger(unrestricted());
    let mut ledger = fresh(&fixture.config);
    attach_new(&mut ledger, other());
    finished(&mut ledger, instance(), 1);
    let pinned = admitted(&mut ledger, instance(), 2);
    let never = issue(&mut ledger, instance());
    ledger
        .commit_fence(&never_admitted(instance(), never))
        .unwrap();
    admitted(&mut ledger, other(), 3);
    issue(&mut ledger, instance());
    advance_to(&mut ledger, instance(), 3).unwrap();
    let mine = ledger.accounting(Some(instance())).unwrap();
    let tokens = mine.tokens.clone().unwrap();
    assert_eq!(tokens.issue_next, 5);
    assert_eq!(tokens.watermark, 3);
    assert_eq!(tokens.retained_admitted, 2);
    assert_eq!(tokens.retained_never_admitted, 1);
    assert_eq!(tokens.reserved_share, 614);
    assert_eq!(tokens.pinned_below_watermark, 1, "{pinned:?}");
    assert_eq!(mine.retained_admitted_total, 3);
    assert_eq!(mine.retained_never_admitted_total, 1);
    let theirs = ledger.accounting(Some(other())).unwrap().tokens.unwrap();
    assert_eq!(theirs.retained_admitted, 1);
    assert_eq!(theirs.retained_never_admitted, 0);
    assert!(ledger.accounting(None).unwrap().tokens.is_none());
    let text = serde_json::to_string(&mine).unwrap();
    let key: String = ledger.token_key().secret_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&key), "K never appears in accounting");
}

/// Design 16.6: the per-token bound is the measured worst case. Every bounded family
/// of one allocation filled to its cap: sixteen stop reasons, eight settled workers per
/// mode in several modes with B5-01's retention applied, every resource kind the
/// supervisor writes, the executions' summary, every executable observation and a long
/// receipt. (Adapted from the design's byte probe, which measured a typical session.)
#[test]
fn b7_fence_entry_bound_is_the_measured_worst_case() {
    use crate::helper::firecracker::cgroup::CgroupIdentity;
    use crate::helper::firecracker::storage::*;
    use crate::helper::firecracker::supervisor::{IntentKind, ResourceRecord as R};
    use crate::helper::firecracker::workers::ProcessId;
    let fixture = temp_ledger(unrestricted());
    let mut config = fixture.config.clone();
    config.max_enrolled = 1;
    let mut ledger = fresh(&config);
    ledger.test_unsynchronized();
    let boot = "0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6".to_string();
    let fid = |n: u64| FileIdentity {
        st_dev: u64::MAX / 3,
        st_ino: u64::MAX / 5 + n,
        bytes: u64::MAX / 7,
        btime_sec: i64::MAX / 11,
        btime_nsec: 999_999_999,
    };
    let real_plan = crate::helper::firecracker::config::build_plan(
        crate::helper::firecracker::config::tests::sample_inputs(),
    )
    .unwrap();
    for index in 0..20 {
        finished(&mut ledger, instance(), 900 + index);
    }
    let before = ledger.ledger_bytes().unwrap();
    let sessions = 100u32;
    for index in 0..sessions {
        let token = issue(&mut ledger, instance());
        let mut request = admit_request(instance(), token, index);
        request.plan = {
            let mut plan = real_plan.bytes.clone();
            plan.extend_from_slice(format!("{index}").as_bytes());
            plan
        };
        request.plan_digest = Digest::of(&request.plan);
        assert!(matches!(
            ledger.admit_intent(&request).unwrap(),
            AdmitOutcome::Accepted { .. }
        ));
        let who = instance();
        let rec = |ledger: &mut Ledger, record: R| {
            ledger.record_resource(who, token, &record).unwrap();
        };
        ledger
            .set_phase(who, token, &["intent".into()], "preparing")
            .unwrap();
        for kind in [
            IntentKind::Cgroup,
            IntentKind::WorkDir,
            IntentKind::WorkFile,
            IntentKind::PrivateFiles,
            IntentKind::JailDir,
        ] {
            rec(&mut ledger, R::Intent(kind));
        }
        rec(
            &mut ledger,
            R::Cgroup(CgroupIdentity {
                boot_id: boot.clone(),
                parent_ino: u64::MAX,
                control_ino: u64::MAX,
                relay_ino: u64::MAX,
                vm_ino: u64::MAX,
                vmm_ino: u64::MAX,
                console_ino: u64::MAX,
            }),
        );
        rec(&mut ledger, R::WorkDir(fid(1)));
        rec(&mut ledger, R::WorkFile(fid(2)));
        rec(
            &mut ledger,
            R::PrivateFiles {
                identity: fid(3),
                config: fid(4),
            },
        );
        let binding = LoopBinding {
            major: u32::MAX,
            minor: u32::MAX,
            backing_dev: u64::MAX,
            backing_ino: u64::MAX,
            offset: 0,
            size_limit: u64::MAX,
            block_size: 4096,
        };
        let generation = LoopGeneration {
            boot_id: boot.clone(),
            diskseq: u64::MAX,
        };
        rec(&mut ledger, R::LoopIntent(binding));
        rec(
            &mut ledger,
            R::Loop {
                binding,
                generation: generation.clone(),
            },
        );
        rec(&mut ledger, R::JailIntent(JailIdentity { nonce: "ab".repeat(16) }));
        rec(&mut ledger, R::JailDir(fid(5)));
        rec(
            &mut ledger,
            R::JailMount(JailMount {
                boot_id: boot.clone(),
                unique_id: u64::MAX,
                mount_id: u64::MAX,
                st_dev: u64::MAX,
                st_ino: u64::MAX,
                root_ino: u64::MAX,
            }),
        );
        rec(
            &mut ledger,
            R::JailBinds(
                (0..5)
                    .map(|k| BindMount {
                        name: format!("artifact-{k}"),
                        boot_id: boot.clone(),
                        unique_id: u64::MAX - k,
                        mount_id: u64::MAX - k,
                        st_dev: u64::MAX,
                        st_ino: u64::MAX - k,
                    })
                    .collect(),
            ),
        );
        rec(
            &mut ledger,
            R::Vmm {
                process: ProcessId {
                    pid: i32::MAX,
                    start_time: u64::MAX,
                    boot_id: None,
                },
                credentials: Credentials {
                    uid: [u32::MAX; 4],
                    gid: [u32::MAX; 4],
                    groups: vec![u32::MAX; 4],
                    cap_inh: u64::MAX,
                    cap_prm: u64::MAX,
                    cap_eff: u64::MAX,
                    cap_bnd: u64::MAX,
                    cap_amb: u64::MAX,
                    no_new_privs: 1,
                    seccomp: 2,
                },
            },
        );
        for executable in crate::helper::firecracker::config::tests::sample_vector() {
            ledger
                .record_observed_executable(who, token, &executable)
                .unwrap();
        }
        rec(
            &mut ledger,
            R::Broker {
                boot_id: boot.clone(),
                inner_id: "in-0123456789abcdef".into(),
            },
        );
        for execution in 0..6u64 {
            for state in ["intent", "busy", "idle"] {
                rec(
                    &mut ledger,
                    R::Exec {
                        token: format!("{execution:032x}"),
                        execution_id: format!("ex-{execution:016x}"),
                        boot_id: boot.clone(),
                        state: state.into(),
                    },
                );
            }
        }
        // The longest stop reason H journals is under 64 bytes; pad to that.
        for _ in 0..24 {
            ledger.record_stop(who, token, &"r".repeat(64)).unwrap();
        }
        // An execution left in flight by a crash keeps its intent and busy rows.
        for state in ["intent", "busy"] {
            rec(
                &mut ledger,
                R::Exec {
                    token: format!("{:032x}", u128::MAX),
                    execution_id: format!("ex-{:016x}", u64::MAX),
                    boot_id: boot.clone(),
                    state: state.into(),
                },
            );
        }
        for mode in ["supervisor", "vm"] {
            let mut spec = request.supervisor.clone();
            spec.mode = mode.into();
            for _ in 0..12 {
                let (worker, _) = ledger
                    .record_allocation_worker_intent(who, token, &spec)
                    .unwrap();
                ledger
                    .settle_worker(worker, "exited-and-reaped-after-a-long-stop")
                    .unwrap();
            }
        }
        rec(
            &mut ledger,
            R::LoopReleased {
                binding,
                generation: generation.clone(),
            },
        );
        ledger.settle_unstarted(who, token).unwrap();
        let open: Vec<i64> = {
            let mut statement = ledger
                .connection()
                .prepare(
                    "SELECT id FROM worker_intents WHERE settled_generation IS NULL
                       AND allocation_id = ?1",
                )
                .unwrap();
            statement
                .query_map([token.to_string()], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        for worker in open {
            ledger.settle_worker(worker, "exited").unwrap();
        }
        let mut fence = fence_for(&request);
        fence.observations =
            "vmm=exited;cgroup=absent;loop=released;jail=unmounted;files=absent;workers=settled"
                .repeat(3);
        assert!(matches!(
            ledger.commit_fence(&fence).unwrap(),
            FenceOutcome::Absent { .. }
        ));
    }
    let per_token = (ledger.ledger_bytes().unwrap() - before) / u64::from(sessions);
    eprintln!("B7 measured worst-case bytes per retained token: {per_token}");
    assert!(
        per_token <= FENCE_ENTRY_BOUND,
        "{per_token} bytes per token exceeds the {FENCE_ENTRY_BOUND}-byte bound"
    );
    assert!(per_token > 4096, "the old 4 KiB bound really was too small");
    let _ = MIB;
}
