//! B7 retired-token compaction through the real H and L processes behind the real
//! listener (design 16.6): issuance, classification, compaction on its lane, digests
//! on Inspect, Remove and Gc, the RTC-14 latch, and the lifetime test.
use super::*;
use crate::helper::firecracker::journal::{COMPACTION_BATCH, TokenAccounting};
use crate::helper::firecracker::offline;

/// A fixture whose L uses `policy` on its boot clock, which the test can step.
fn compacting(policy: CompactionPolicy) -> NodeOptions {
    NodeOptions {
        // Room for many concurrent fake sessions: capacity is not what is tested here.
        ceilings: NodeCeilings {
            slots: 64,
            memory_bytes: 1 << 50,
            disk_bytes: 1 << 50,
            host_cpu_millis: 1 << 40,
            virtual_cpu_slots: 1 << 20,
            pids: 1 << 30,
            host_pids: 1 << 30,
        },
        compaction: policy,
        compaction_tick_ms: 20,
        max_enrolled: 2,
        ..NodeOptions::default()
    }
}

/// Steps L's boot clock: the fixture's L adds this offset to `CLOCK_BOOTTIME`.
fn set_boot_clock(fixture: &Fixture, offset_ms: i64) {
    std::fs::write(
        fixture.root.join("faults/L.boot_clock_offset_ms"),
        offset_ms.to_string(),
    )
    .unwrap();
}

/// Preflight as an honest daemon under contention would: a full preparation slot is
/// refused before issuance (no seq is spent), so it simply tries again.
async fn issued_retrying(
    runtime: &FirecrackerRuntime,
    instance: Id128,
) -> (CreateContext, PreparedCreate) {
    loop {
        let context = prep(instance);
        match runtime
            .prepare(&context, &spec(), deadline(10), &no_cancel())
            .await
        {
            Ok(plan) => {
                let token = plan.allocation_id().unwrap();
                return (
                    CreateContext {
                        instance_id: instance,
                        allocation_id: token,
                        sandbox_id: context.sandbox_id,
                    },
                    plan,
                );
            }
            Err(error) if error.to_string().contains("preparation slot") => {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            // A ledger being replaced after an injected death answers nothing for a moment.
            Err(error) if error.to_string().contains("did not answer") => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("{error}"),
        }
    }
}

/// Retried as reconciliation would: a busy node's observation slot leaves the token
/// charged and ambiguous, never absent, until a later attempt proves it.
async fn fence_retrying(
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> FencedAbsence {
    for attempt in 0.. {
        match runtime
            .fence_absent(context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
        {
            Ok(receipt) => return fenced(receipt),
            Err(error) if attempt < 500 => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("{error}"),
        }
    }
    unreachable!()
}

/// One whole session through the real adapter, H and L: Preflight issues the token,
/// Create commits C2 and starts S, and the adapter's fence removes it to ABSENT.
async fn session(
    fixture: &Fixture,
    runtime: &FirecrackerRuntime,
    instance: Id128,
) -> (CreateContext, PreparedCreate, FencedAbsence) {
    let (context, plan) = loop {
        let (context, plan) = issued_retrying(runtime, instance).await;
        match raw_create(fixture, &context, epoch_of(runtime).await, &plan).await {
            CreateReply::Accepted { .. } => break (context, plan),
            // Two concurrent Preflights can pick the same free identity; C2 refuses the
            // second exactly, and an honest daemon fences that token and tries again.
            CreateReply::Ambiguous {
                class: AmbiguousClass::Collision,
                ..
            } => {
                fence_retrying(runtime, &context, &plan).await;
            }
            other => panic!("not accepted: {other:?}"),
        }
    };
    let receipt = fence_retrying(runtime, &context, &plan).await;
    (context, plan, receipt)
}

#[tokio::test]
#[ignore = "throughput probe for sizing the lifetime test"]
async fn b7_probe_session_throughput() {
    let fixture = Fixture::new(compacting(CompactionPolicy::default())).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let began = std::time::Instant::now();
    for _ in 0..50 {
        session(&fixture, &runtime, instance).await;
    }
    eprintln!("B7 probe: 50 sequential sessions in {:?}", began.elapsed());
    let fixture = Arc::new(fixture);
    let began = std::time::Instant::now();
    let mut lanes = Vec::new();
    for _ in 0..12 {
        let (fixture, runtime) = (fixture.clone(), runtime.clone());
        lanes.push(tokio::spawn(async move {
            for _ in 0..25 {
                session(&fixture, &runtime, instance).await;
            }
        }));
    }
    for lane in lanes {
        lane.await.unwrap();
    }
    eprintln!("B7 probe: 300 sessions 12 wide in {:?}", began.elapsed());
}

/// A C2 request for an issued token, with identities unique to `index`, for tests that
/// drive the ledger directly.
fn ledger_request(instance: Id128, token: Id128, index: u32) -> super::super::journal::AdmitRequest {
    use super::super::config::tests::{sample_leases, sample_vector};
    use super::super::journal::{AdmitRequest, StopAuthority, WorkerIntentSpec};
    let plan = format!("plan-{token}").into_bytes();
    AdmitRequest {
        instance_id: instance,
        allocation_id: token,
        sandbox_id: format!("sb-{:016x}", u64::from(index) + 1),
        plan_version: 1,
        plan_digest: Digest::of(&plan),
        plan,
        profile: PROFILE.into(),
        manifest_sha256: Digest::of(b"manifest"),
        host_spec_sha256: Digest::of(b"host"),
        guest_exec_spec_sha256: Digest::of(b"guest"),
        reservation: ResourceReservation {
            memory_bytes: 896 * MIB,
            disk_bytes: 1408 * MIB,
            pids: 192,
            host_cpu_millis: 1000,
            virtual_cpu_slots: 1,
            host_pids: 32,
        },
        leases: sample_leases(index),
        work_uuid: "12345678-1234-4234-8234-123456789abc".into(),
        executables: sample_vector(),
        stop_authority: StopAuthority::standard(format!("kilnd-firecracker/x/fc-{token}")),
        supervisor: WorkerIntentSpec {
            mode: "supervisor".into(),
            allowed_names: vec!["work.xfs".into()],
            cgroup: "control".into(),
            image: sample_vector()[3],
        },
    }
}

/// The fixture's ledger configuration, as its helper process opens it.
fn fixture_ledger(fixture: &Fixture) -> LedgerConfig {
    let config: ChildConfig =
        serde_json::from_slice(&std::fs::read(fixture.root.join("config.json")).unwrap()).unwrap();
    ledger_config(&config)
}

fn census_u64(census: &Value, field: &str) -> u64 {
    census[field].as_u64().unwrap_or_else(|| panic!("{field}: {census}"))
}

fn incompatible(reply: &FirecrackerResponse) -> bool {
    matches!(
        reply,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::Incompatible,
            ..
        })
    )
}

fn with_token(context: &CreateContext, token: Id128) -> CreateContext {
    CreateContext {
        allocation_id: token,
        ..context.clone()
    }
}

fn binding_of(context: &CreateContext, plan: &PreparedCreate) -> crate::model::AllocationBinding {
    plan.binding(context).unwrap()
}

/// Kills the ledger worker and waits for its journaled replacement to serve.
async fn replace_ledger(fixture: &Fixture) {
    let before = fixture.census().await["ledger"].as_i64().unwrap();
    signal(before, libc::SIGKILL);
    for _ in 0..2000 {
        let census = fixture.census().await;
        if census["ledger"].as_i64() != Some(before) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the ledger was not replaced");
}

/// Waits until this instance's watermark passes `seq`, stepping nothing itself.
async fn wait_watermark_past(runtime: &FirecrackerRuntime, seq: u64) -> TokenAccounting {
    for _ in 0..3000 {
        let tokens = tokens_soon(runtime).await;
        if tokens.watermark > seq {
            return tokens;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the watermark never passed {seq}");
}

/// This instance's token figures, waiting out a ledger that is being replaced.
async fn tokens_soon(runtime: &FirecrackerRuntime) -> TokenAccounting {
    for _ in 0..500 {
        if let Ok(snapshot) = runtime.node_accounting(deadline(2), &no_cancel()).await {
            return snapshot.tokens.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the ledger never answered Accounting");
}

/// Under load a pass may run after the clock moved again, so this keeps maturing (one
/// pass, one lease) until W passes `seq`. Extra steps are safe: they only move W sooner.
async fn drive_watermark_past(
    fixture: &Fixture,
    clock: &mut i64,
    runtime: &FirecrackerRuntime,
    seq: u64,
) -> TokenAccounting {
    for _ in 0..20 {
        mature(fixture, clock, POLICY).await;
        for _ in 0..400 {
            let tokens = tokens_soon(runtime).await;
            if tokens.watermark > seq {
                return tokens;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    panic!("the watermark never passed {seq}");
}

/// Matures everything issued so far on the injected clock: one pass for the
/// checkpoint, then one lease, as RTC-13 requires.
async fn mature(fixture: &Fixture, clock: &mut i64, policy: CompactionPolicy) {
    *clock += policy.pass_ms as i64 + 1;
    set_boot_clock(fixture, *clock);
    tokio::time::sleep(Duration::from_millis(120)).await;
    *clock += policy.lease_ms as i64 + 1;
    set_boot_clock(fixture, *clock);
}

const POLICY: CompactionPolicy = CompactionPolicy {
    lease_ms: 60_000,
    pass_ms: 10_000,
};

#[tokio::test]
async fn b7_rtc3_forged_foreign_and_seq_zero_tokens_never_reach_a_gate_or_l() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    let (context, plan) = issued(&runtime_a, a).await;
    let (foreign, _) = issued(&runtime_b, b).await;
    let epoch = epoch_of(&runtime_a).await;
    let mut flipped = *context.allocation_id.as_bytes();
    flipped[15] ^= 1;
    let mut zero = *context.allocation_id.as_bytes();
    zero[..8].copy_from_slice(&[0; 8]);
    let digest = plan.plan_digest();
    let before = fixture.census().await;
    let mut refused = 0;
    for token in [
        Id128::random(),
        Id128::from_bytes(flipped),
        Id128::from_bytes(zero),
        foreign.allocation_id,
    ] {
        let forged = with_token(&context, token);
        for operation in [
            FirecrackerOperation::Inspect {
                allocation_id: token,
                plan_digest: digest,
            },
            create_operation(&forged, &plan),
            FirecrackerOperation::FenceAbsent {
                allocation_id: token,
                sandbox_id: context.sandbox_id.clone(),
                plan_digest: digest,
            },
            FirecrackerOperation::Remove {
                allocation_id: token,
                plan_digest: digest,
            },
            // One bad target refuses the whole vector, the valid one included.
            FirecrackerOperation::Gc {
                targets: vec![
                    GcTarget {
                        allocation_id: context.allocation_id,
                        plan_digest: digest,
                    },
                    GcTarget {
                        allocation_id: token,
                        plan_digest: digest,
                    },
                ],
            },
        ] {
            let reply = raw_call(&fixture, a, Some(epoch), operation, wire_deadline(5), 5_000)
                .await
                .unwrap();
            assert!(incompatible(&reply), "{token}: {reply:?}");
            refused += 1;
        }
    }
    let after = fixture.census().await;
    assert_eq!(
        census_u64(&after, "ledger_calls"),
        census_u64(&before, "ledger_calls"),
        "no L call for any of them"
    );
    assert_eq!(
        census_u64(&after, "tag_refusals"),
        census_u64(&before, "tag_refusals") + refused
    );
    assert_eq!(after["closed_gates"], before["closed_gates"], "no gate retained");
    assert_eq!(after["open_gates"], json!(0));
    assert_eq!(fixture.count("SELECT COUNT(*) FROM allocations"), 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    // The valid token itself still works afterwards.
    create_accepted(&fixture, &runtime_a, &context, &plan).await;
    b7_matrix(
        "RTC-3: forged, foreign and seq-0 tokens",
        json!({"refused_by_h": refused, "ledger_calls": 0, "gates_retained": 0}),
    );
}

#[tokio::test]
async fn b7_rtc3_a_valid_tag_at_the_pointer_reaches_l_and_is_not_issued_across_restarts() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (_, plan) = issued(&runtime, instance).await;
    let key = super::super::journal::tests::key_from_file(&fixture_ledger(&fixture));
    let pointer = node_totals(&runtime).await.tokens.unwrap().issue_next;
    let not_issued = |pointer: u64| FirecrackerOperation::Inspect {
        allocation_id: key.issue(instance, pointer),
        plan_digest: plan.plan_digest(),
    };
    for round in 0..3 {
        let epoch = epoch_of(&runtime).await;
        let before = census_u64(&fixture.census().await, "ledger_calls");
        for seq in [pointer, pointer + 1, super::super::token::MAX_SEQ] {
            let reply = raw_call(&fixture, instance, Some(epoch), not_issued(seq), wire_deadline(5), 5_000)
                .await
                .unwrap();
            assert!(
                matches!(
                    &reply,
                    FirecrackerResponse::Inspect(InspectReply::Incompatible { message })
                        if message.contains("never issued")
                ),
                "round {round}: {reply:?}"
            );
        }
        assert!(census_u64(&fixture.census().await, "ledger_calls") >= before + 3);
        assert_eq!(fixture.census().await["closed_gates"], json!(0));
        match round {
            0 => replace_ledger(&fixture).await,
            1 => {
                fixture.kill_helper().await;
                fixture.start().await;
                runtime.test_reattach().await;
            }
            _ => {}
        }
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM allocations"), 0);
    // The exact pointer survived both restarts: the next issuance is `pointer`.
    let (next, _) = issued(&runtime, instance).await;
    assert_eq!(super::super::token::seq_of(next.allocation_id), pointer);
    b7_matrix(
        "RTC-3: a valid tag at the pointer is NotIssued across restarts",
        json!({"pointer": pointer, "restarts": ["ledger", "helper"], "next_issued": pointer}),
    );
}

#[tokio::test]
async fn b7_rtc8_real_wire_digests_after_compaction_and_a_helper_restart() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (done, done_plan, original) = session(&fixture, &runtime, instance).await;
    let (active, active_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &active, &active_plan).await;
    let (_, _) = issued(&runtime, instance).await;
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    wait_watermark_past(&runtime, super::super::token::seq_of(active.allocation_id)).await;
    wait_until("the finished session compacts", || {
        fixture.count("SELECT COUNT(*) FROM retired_tokens") == 0
    })
    .await;
    // H and L restart: no request may depend on a digest the helper remembered.
    fixture.kill_helper().await;
    fixture.start().await;
    runtime.test_reattach().await;
    let binding = binding_of(&done, &done_plan);
    let check = |receipt: &FencedAbsence| {
        assert!(receipt.matches(&binding), "{receipt:?}");
        assert_ne!(receipt.receipt_id(), original.receipt_id(), "a synthesized receipt");
    };
    // Inspect (as reconciliation calls it), FenceAbsent, Create, Remove and Gc.
    let AllocationObservation::AbsentFenced(inspected) = runtime
        .inspect_allocation(&done, &done_plan.plan_digest(), deadline(5), &no_cancel())
        .await
        .unwrap()
    else {
        panic!("compacted means absent");
    };
    check(&inspected);
    check(&fenced(
        runtime
            .fence_absent(&done, &done_plan.plan_digest(), deadline(10), &no_cancel())
            .await
            .unwrap(),
    ));
    let created = raw_create(&fixture, &done, epoch_of(&runtime).await, &done_plan).await;
    check(&FencedAbsence::decode(&receipt_of(&created)).unwrap());
    check(&fenced(
        runtime
            .remove(
                RemoveTarget::Fenced { binding: &binding },
                deadline(10),
                &no_cancel(),
            )
            .await
            .unwrap(),
    ));
    let collected = runtime
        .gc(
            &[RemoveTarget::Fenced { binding: &binding }],
            deadline(10),
            &no_cancel(),
        )
        .await
        .unwrap();
    let [AbsenceReceipt::Fenced(collected)] = collected.as_slice() else {
        panic!("{collected:?}");
    };
    check(collected);
    // No cache supplies the digest: another digest gets a receipt for that digest, which
    // the daemon's match refuses.
    let other = Digest::of(b"some other plan");
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Inspect {
            allocation_id: done.allocation_id,
            plan_digest: other,
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    let FirecrackerResponse::Inspect(InspectReply::AbsentFenced { receipt }) = reply else {
        panic!("{reply:?}");
    };
    let elsewhere = FencedAbsence::decode(&receipt.0).unwrap();
    assert_eq!(elsewhere.plan_digest(), other);
    assert!(!elsewhere.matches(&binding));
    // While rows exist, a mismatched digest is Conflict and nothing acts.
    let epoch = epoch_of(&runtime).await;
    for operation in [
        FirecrackerOperation::Inspect {
            allocation_id: active.allocation_id,
            plan_digest: other,
        },
        FirecrackerOperation::Remove {
            allocation_id: active.allocation_id,
            plan_digest: other,
        },
    ] {
        let reply = raw_call(&fixture, instance, Some(epoch), operation, wire_deadline(5), 5_000)
            .await
            .unwrap();
        assert!(
            matches!(
                &reply,
                FirecrackerResponse::Inspect(InspectReply::Incompatible { .. })
                    | FirecrackerResponse::Remove(FenceReply::Ambiguous {
                        class: AmbiguousClass::Conflict,
                        ..
                    })
            ),
            "{reply:?}"
        );
    }
    let gc = raw_call(
        &fixture,
        instance,
        Some(epoch),
        FirecrackerOperation::Gc {
            targets: vec![GcTarget {
                allocation_id: active.allocation_id,
                plan_digest: other,
            }],
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(
        matches!(&gc, FirecrackerResponse::Gc(results) if matches!(
            results.as_slice(),
            [GcResult { outcome: GcOutcome::Failed { class: AmbiguousClass::Conflict, .. }, .. }]
        )),
        "{gc:?}"
    );
    assert_eq!(fixture.active_allocations(), 1, "the active session was untouched");
    assert!(matches!(
        runtime
            .inspect_allocation(&active, &active_plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. } | AllocationObservation::Present { .. }
    ));
    b7_matrix(
        "RTC-8: real-wire Inspect, Remove and Gc digests after compaction and a restart",
        json!({"right_digest": "AbsentFenced", "wrong_digest": "Conflict", "active_untouched": true}),
    );
}

#[tokio::test]
async fn b7_rtc14_spoofed_highest_tokens_fail_only_their_own_attachment() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (db_a, db_b) = (Id128::random(), Id128::random());
    let runtime_b = fixture.runtime(b, db_b);
    let runtime_a = fixture.runtime(a, db_a);
    let (own, _) = issued(&runtime_a, a).await;
    let (foreign, _) = issued(&runtime_b, b).await;
    runtime_a.test_reattach().await;
    let key = super::super::journal::tests::key_from_file(&fixture_ledger(&fixture));
    let pointer = node_totals(&runtime_b).await.tokens.unwrap();
    let _ = pointer;
    let a_pointer = super::super::token::seq_of(own.allocation_id) + 1;
    let guessed = |seq: u64| {
        let mut bytes = *key.issue(a, seq).as_bytes();
        bytes[8..].copy_from_slice(&[0x5a; 8]);
        Id128::from_bytes(bytes)
    };
    let mut flipped = *own.allocation_id.as_bytes();
    flipped[13] ^= 0x40;
    for spoof in [
        Id128::from_bytes([0; 16]),
        guessed(a_pointer),
        guessed(super::super::token::MAX_SEQ),
        foreign.allocation_id,
        Id128::from_bytes(flipped),
    ] {
        let attempt = fixture.runtime(a, db_a);
        attempt.record_token(Some(spoof));
        let error = attempt.prove_attachment(deadline(5)).await.unwrap_err();
        assert!(matches!(error, RuntimeError::Incompatible(_)), "{spoof}: {error}");
        let census = fixture.census().await;
        assert_eq!(census["latched"], json!(false), "{spoof}");
        assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
        // B is unaffected throughout: it preflights, creates and fences.
        session(&fixture, &runtime_b, b).await;
        let health = timed_capabilities(&runtime_b, &fixture).await.health.unwrap();
        assert_eq!(health.node_fault, None);
    }
    // The old bare-sequence field is refused by the strict codec.
    let frame = format!(
        r#"{{"version":{VERSION},"timeout_ms":5000,"deadline_ns":{},"operation":{{"firecracker":{{"group_version":{FIRECRACKER_GROUP_VERSION},"instance_id":"{a}","connection_epoch":null,"operation":{{"attach_instance":{{"database_uuid":"{db_a}","highest_issue_seq":5}}}}}}}}}}"#,
        wire_deadline(5)
    );
    assert_frame_refused(&fixture, frame.as_bytes(), None).await;
    // A then reattaches with its honest highest token and works.
    let honest = fixture.runtime(a, db_a);
    honest.record_token(Some(own.allocation_id));
    honest.prove_attachment(deadline(5)).await.unwrap();
    let (next, _) = issued(&honest, a).await;
    assert!(super::super::token::seq_of(next.allocation_id) > super::super::token::seq_of(own.allocation_id));
    b7_matrix(
        "RTC-14: spoofed highest tokens fail only their own attachment",
        json!({"spoofs_refused": true, "node_fault": null, "honest_reattach": "issues above its token"}),
    );
}

const LEDGER_FILES: [&str; 3] = ["node.db", "node.db-wal", "node.db-shm"];

/// Byte copies of the ledger's files, taken with the helper stopped.
fn copy_ledger(fixture: &Fixture, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for name in LEDGER_FILES {
        let from = fixture.root.join("ledger").join(name);
        if from.exists() {
            std::fs::copy(&from, to.join(name)).unwrap();
        }
    }
}

/// Root's restore of an older copy over the live ledger: outside the fault model, and
/// exactly what RTC-14 detects when a daemon recorded a later token.
fn restore_ledger(fixture: &Fixture, from: &Path) {
    for name in LEDGER_FILES {
        let live = fixture.root.join("ledger").join(name);
        let _ = std::fs::remove_file(&live);
        if from.join(name).exists() {
            std::fs::copy(from.join(name), &live).unwrap();
            std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

/// Kills H and waits for its L to exit, so the ledger's files are closed and settled
/// (SQLite removes the WAL and index when the last connection closes).
async fn stop_helper(fixture: &Fixture) {
    let ledger = fixture.census().await["ledger"].as_i64().unwrap();
    fixture.kill_helper().await;
    wait_until("L exits", || !alive(ledger)).await;
}

/// A daemon database reduced to what the offline inventory reads: fenced rows and
/// release evidence, with this instance's recorded tokens.
fn daemon_db(path: &Path, instance: Id128, tokens: &[Id128]) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE sandboxes (accounting_kind TEXT, instance_id TEXT, allocation_id TEXT);
         CREATE TABLE release_evidence (instance_id TEXT, allocation_id TEXT);",
    )
    .unwrap();
    for token in tokens {
        conn.execute(
            "INSERT INTO sandboxes VALUES ('fenced', ?1, ?2)",
            [instance.to_string(), token.to_string()],
        )
        .unwrap();
    }
}

fn reports(fixture: &Fixture) -> PathBuf {
    let directory = fixture.root.join("reports");
    private_dir(&directory);
    directory
}

/// A node whose ledger is restored behind a token A recorded, with B holding an active
/// session. Returns A's recorded token and B's active session.
async fn rolled_back(
    fixture: &Fixture,
    runtime_a: &FirecrackerRuntime,
    runtime_b: &FirecrackerRuntime,
    (a, b): (Id128, Id128),
) -> (Id128, CreateContext, PreparedCreate) {
    let (active, plan) = issued(runtime_b, b).await;
    create_accepted(fixture, runtime_b, &active, &plan).await;
    issued(runtime_a, a).await;
    stop_helper(fixture).await;
    let copy = fixture.root.join("ledger-copy");
    copy_ledger(fixture, &copy);
    fixture.start().await;
    runtime_a.test_reattach().await;
    runtime_b.test_reattach().await;
    let (recorded, _) = issued(runtime_a, a).await;
    assert_eq!(runtime_a.test_highest_token(), Some(recorded.allocation_id));
    stop_helper(fixture).await;
    restore_ledger(fixture, &copy);
    fixture.start().await;
    runtime_a.test_reattach().await;
    runtime_b.test_reattach().await;
    (recorded.allocation_id, active, plan)
}

#[tokio::test]
async fn b7_rtc14_a_real_rollback_latches_every_forward_effect_until_the_offline_clear() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b, c) = (Id128::random(), Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    let (recorded, active, active_plan) =
        rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
    // A's attachment reports a verified token at or above the restored pointer.
    let error = runtime_a.prove_attachment(deadline(5)).await.unwrap_err();
    assert!(error.to_string().contains("rollback"), "{error}");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 1);
    assert_eq!(fixture.census().await["latched"], json!(true));
    // Node-wide: B's Preflight and Create, and C's first binding, are refused.
    let refused = runtime_b
        .prepare(&prep(b), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("latched"), "{refused}");
    let runtime_c = fixture.runtime(c, Id128::random());
    assert!(runtime_c.prove_attachment(deadline(5)).await.is_err());
    let health = timed_capabilities(&runtime_b, &fixture).await.health.unwrap();
    assert_eq!(health.node_fault.as_deref(), Some("rollback"));
    // Cleanup drains: B's Inspect, Remove (through the adapter's fence) and List work.
    runtime_b
        .inspect_allocation(&active, &active_plan.plan_digest(), deadline(5), &no_cancel())
        .await
        .unwrap();
    runtime_b.list(deadline(10), &no_cancel()).await.unwrap();
    let receipt = fenced(
        runtime_b
            .fence_absent(&active, &active_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert!(receipt.matches(&binding_of(&active, &active_plan)));
    // The latch survives a whole-helper restart: the durable row latches at open.
    fixture.kill_helper().await;
    fixture.start().await;
    runtime_b.test_reattach().await;
    assert_eq!(fixture.census().await["latched"], json!(true), "latched at open");
    assert!(
        runtime_b
            .prepare(&prep(b), &spec(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    assert_eq!(fixture.census().await["latched"], json!(true));
    // The offline clear: refused while the helper runs, for a stale report, and for an
    // unexplained one; then the inventory and the clear.
    let config = fixture_ledger(&fixture);
    let directory = reports(&fixture);
    let observation = ObservationBackend::FakeDirectory(fixture.root.join("fake"));
    let mut databases = BTreeMap::new();
    for (instance, tokens) in [(a, vec![recorded]), (b, vec![]), (c, vec![])] {
        let path = directory.join(format!("{instance}.db"));
        daemon_db(&path, instance, &tokens);
        databases.insert(instance, path);
    }
    let held = offline::offline_inventory(
        &config,
        &observation,
        &databases,
        &directory.join("running.json"),
    );
    assert!(held.unwrap_err().contains("stop kilnd-helper"));
    fixture.kill_helper().await;
    let stale = directory.join("stale.json");
    offline_when_stopped(|| offline::offline_inventory(&config, &observation, &databases, &stale))
        .await
        .unwrap();
    fixture.start().await; // a helper start journals its workers: the ledger moved
    fixture.kill_helper().await;
    let error = offline_when_stopped(|| offline::clear_node_faults(&config, &stale))
        .await
        .unwrap_err();
    assert!(error.contains("changed since the inventory"), "{error}");
    let stray = fixture.root.join("fake").join(b.to_string()).join(format!("fc-{}", Id128::random()));
    std::fs::create_dir_all(&stray).unwrap();
    let unexplained = directory.join("unexplained.json");
    let report =
        offline::offline_inventory(&config, &observation, &databases, &unexplained).unwrap();
    assert_eq!(report.verdict, "unexplained");
    assert!(offline::clear_node_faults(&config, &unexplained).is_err());
    std::fs::remove_dir_all(&stray).unwrap();
    let good = directory.join("good.json");
    let report = offline::offline_inventory(&config, &observation, &databases, &good).unwrap();
    assert_eq!(report.verdict, "explained");
    assert_eq!(
        report.instances.iter().find(|i| i.instance_id == a).unwrap().highest_token,
        Some(recorded)
    );
    // A tampered report fails its digest; a symlink is refused by the protected walk.
    let raw = std::fs::read(&good).unwrap();
    let tampered = directory.join("tampered.json");
    std::fs::write(&tampered, String::from_utf8(raw).unwrap().replace("explained", "explainee")).unwrap();
    assert!(offline::clear_node_faults(&config, &tampered).is_err());
    let link = directory.join("link.json");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    assert!(offline::clear_node_faults(&config, &link).is_err());
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 1, "nothing changed");
    let cleared = offline::clear_node_faults(&config, &good).unwrap();
    assert!(cleared.contains("raised_pointers"), "{cleared}");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_fault_clears"), 1);
    // Every daemon reattaches at once with no new fault, and A's next token is above the
    // one it recorded: nothing is reissued.
    fixture.start().await;
    let honest_a = fixture.runtime(a, runtime_a_database(&runtime_a));
    honest_a.record_token(Some(recorded));
    honest_a.prove_attachment(deadline(5)).await.unwrap();
    runtime_b.test_reattach().await;
    runtime_b.prove_attachment(deadline(5)).await.unwrap();
    runtime_c.prove_attachment(deadline(5)).await.unwrap();
    let (next, _) = issued(&honest_a, a).await;
    assert!(
        super::super::token::seq_of(next.allocation_id) > super::super::token::seq_of(recorded)
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
    assert_eq!(fixture.census().await["latched"], json!(false));
    b7_matrix(
        "RTC-14: a real rollback latches forward effects until the offline clear",
        json!({"latched": "until offline-inventory and clear-node-faults", "after_clear": "issues above the recorded token"}),
    );
}

/// Root's offline command once the stopped helper's L has let go of the node lock.
async fn offline_when_stopped<T>(mut command: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    for _ in 0..1000 {
        match command() {
            // The stopped helper's L may still be closing the ledger's files.
            Err(error) if error.contains("stop kilnd-helper") || error.contains("unsafe") => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            other => return other,
        }
    }
    command()
}

fn runtime_a_database(runtime: &FirecrackerRuntime) -> Id128 {
    runtime.test_database()
}

#[tokio::test]
async fn b7_rtc_r2_03_h_latches_before_the_commit_and_queued_work_starts_nothing() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    // B's token is issued before the copy, so the restored ledger admits it normally.
    let (queued, queued_plan) = issued(&runtime_b, b).await;
    let (_recorded, _, _) = rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
    let epoch_b = epoch_of(&runtime_b).await;
    // B's Create commits C2 and is held just before its host effects; a Preflight is held
    // before its issuance.
    fixture.fault("H.create.before_effects.hold");
    let create = {
        let (fixture_root, context, plan) = (fixture.root.clone(), queued.clone(), queued_plan.clone());
        let _ = fixture_root;
        let request = create_operation(&context, &plan);
        let socket = fixture.root.join("helper.sock");
        tokio::spawn(async move {
            let request = Request {
                version: VERSION,
                timeout_ms: 25_000,
                deadline_ns: wire_deadline(25),
                operation: Operation::Firecracker(FirecrackerRequest {
                    group_version: FIRECRACKER_GROUP_VERSION,
                    instance_id: b,
                    connection_epoch: Some(epoch_b),
                    operation: request,
                }),
            };
            let mut stream = UnixStream::connect(socket).await.unwrap();
            fds::send(&stream, &[]).await.unwrap();
            write_frame(&mut stream, &request).await.unwrap();
            assert!(fds::receive(&stream).await.unwrap().is_empty());
            read_frame::<Response>(&mut stream).await.unwrap()
        })
    };
    fixture.wait_reached("H.create.before_effects").await;
    // A's attachment detects the rollback; H latches and is held before the commit.
    fixture.fault("H.fault.latched_before_commit.hold");
    let attach = {
        let runtime_a = runtime_a.clone();
        tokio::spawn(async move { runtime_a.prove_attachment(deadline(20)).await })
    };
    fixture.wait_reached("H.fault.latched_before_commit").await;
    assert_eq!(fixture.census().await["latched"], json!(true));
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM node_faults"),
        0,
        "H latched before L attempted the commit"
    );
    // The queued Create, released after the latch, starts no effect.
    fixture.clear("H.create.before_effects.hold");
    let Response::Firecracker(FirecrackerResponse::Create(reply)) = create.await.unwrap() else {
        panic!("not a create reply");
    };
    assert_eq!(class_of(&reply), AmbiguousClass::Latched, "{reply:?}");
    assert!(!fixture.fake_dir(&queued).exists(), "no host effect started");
    let census = fixture.census().await;
    assert!(
        census["supervisors"][queued.allocation_id.to_string()]["pid"].is_null(),
        "no supervisor was released: {census}"
    );
    // Now the commit happens, and the attachment fails.
    fixture.clear("H.fault.latched_before_commit.hold");
    assert!(attach.await.unwrap().is_err());
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 1);
    // The C2 claim is held for an exact fence, which still works under the latch.
    fenced(
        runtime_b
            .fence_absent(&queued, &queued_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    b7_matrix(
        "RTC-R2-03: H latches before the fault commit",
        json!({"queued_create": "no supervisor released", "fence_under_latch": "Absent"}),
    );
}

#[tokio::test]
async fn b7_rtc_r2_01_an_uncertain_fault_commit_fails_stop_across_every_restart() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    let (_recorded, active, active_plan) =
        rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
    // The fault's FULL-sync commit fails: L writes the fail-stop marker and exits, and H
    // keeps the pending fault for every replacement L.
    fixture.fault("L.fault.sync_fail");
    assert!(runtime_a.prove_attachment(deadline(10)).await.is_err());
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
    let census = fixture.census().await;
    assert_eq!(census["latched"], json!(true));
    assert_eq!(census["pending_fault"], json!(true));
    assert!(
        std::fs::read(fixture.root.join("ledger").join(super::super::compaction::FAILSTOP_MARKER))
            .unwrap()
            .starts_with(b"latched")
    );
    // Replacements cannot commit it while the storage fault lasts, and serve nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        runtime_b
            .prepare(&prep(b), &spec(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    // The storage recovers: the next replacement commits the pending fault first.
    fixture.clear("L.fault.sync_fail");
    wait_until("the pending fault is committed", || {
        fixture.count("SELECT COUNT(*) FROM node_faults") == 1
    })
    .await;
    // Fail-stop: even had the commit never landed, the marker latches every later helper.
    fixture.kill_helper().await;
    fixture.start().await;
    runtime_b.test_reattach().await;
    assert!(
        runtime_b
            .prepare(&prep(b), &spec(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    let health = timed_capabilities(&runtime_b, &fixture).await.health.unwrap();
    assert!(health.node_fault.is_some());
    // Cleanup still drains.
    fenced(
        runtime_b
            .fence_absent(&active, &active_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    b7_matrix(
        "RTC-R2-01: an uncertain fault commit fails stop across restarts",
        json!({"forward_effects": "refused", "health": "node_fault", "cleanup": "drains"}),
    );
}

#[tokio::test]
async fn b7_rtc13_a_five_lease_flood_keeps_checkpoints_bounded_and_the_tail_matures() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let runtimes = [
        (a, fixture.runtime(a, Id128::random())),
        (b, fixture.runtime(b, Id128::random())),
    ];
    let bound = POLICY.checkpoint_bound() as u64;
    let mut clock = 0i64;
    // Five leases of passes: every pass, both instances issue tokens every way B3's
    // limits allow: abandoned before C1, refused by P after issuance, reply dropped,
    // and whole sessions.
    for pass in 0..(5 * POLICY.lease_ms / POLICY.pass_ms) {
        for (instance, runtime) in &runtimes {
            issued(runtime, *instance).await; // abandoned before C1
            let epoch = epoch_of(runtime).await;
            let refused = raw_call(
                &fixture,
                *instance,
                Some(epoch),
                FirecrackerOperation::Preflight {
                    sandbox_id: new_id("sb"),
                    profile: "other-profile".into(),
                    spec: spec(),
                },
                wire_deadline(5),
                5_000,
            )
            .await
            .unwrap();
            assert!(matches!(refused, FirecrackerResponse::Error(_)));
            fixture.fault("H.preflight.drop_public_reply");
            assert!(
                runtime
                    .prepare(&prep(*instance), &spec(), deadline(5), &no_cancel())
                    .await
                    .is_err()
            );
            fixture.clear("H.preflight.drop_public_reply");
            if pass % 3 == 0 {
                session(&fixture, runtime, *instance).await;
            }
            let tokens = node_totals(runtime).await.tokens.unwrap();
            assert!(tokens.checkpoints <= bound, "pass {pass}: {}", tokens.checkpoints);
        }
        clock += POLICY.pass_ms as i64 + 1;
        set_boot_clock(&fixture, clock);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    // Once the flood stops, W reaches each final pointer within a lease plus two passes.
    let finals: Vec<u64> = {
        let mut finals = Vec::new();
        for (_, runtime) in &runtimes {
            finals.push(node_totals(runtime).await.tokens.unwrap().issue_next);
        }
        finals
    };
    clock += (POLICY.lease_ms + 2 * POLICY.pass_ms) as i64 + 2;
    set_boot_clock(&fixture, clock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    clock += POLICY.pass_ms as i64 + 1;
    set_boot_clock(&fixture, clock);
    for ((_, runtime), last) in runtimes.iter().zip(finals) {
        let tokens = wait_watermark_past(runtime, last - 1).await;
        assert_eq!(tokens.watermark, last);
        assert!(tokens.checkpoints <= bound);
    }
    b7_matrix(
        "RTC-13: a five-lease flood keeps checkpoints bounded",
        json!({"checkpoint_bound": bound, "tail": "matures to issue_next"}),
    );
}

#[tokio::test]
async fn b7_rtc12_a_never_admitted_flood_stops_at_the_floor_and_refills_after_a_lease() {
    let fixture = Fixture::new(NodeOptions {
        fence_allowance_bytes: Some(64 * super::super::journal::FENCE_ENTRY_BOUND),
        max_enrolled: 1,
        ..compacting(POLICY)
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let mut fenced_tokens = 0;
    // Preflight then FenceAbsent, as a daemon whose C2 never happened: each spends one
    // never-admitted fence until Preflight's floor refuses new tokens.
    loop {
        match runtime
            .prepare(&prep(instance), &spec(), deadline(5), &no_cancel())
            .await
        {
            Ok(plan) => {
                let context = CreateContext {
                    instance_id: instance,
                    allocation_id: plan.allocation_id().unwrap(),
                    sandbox_id: new_id("sb"),
                };
                fenced(
                    runtime
                        .fence_absent(&context, &plan.plan_digest(), deadline(10), &no_cancel())
                        .await
                        .unwrap(),
                );
                fenced_tokens += 1;
            }
            Err(error) => {
                assert!(error.to_string().contains("window quota"), "{error}");
                break;
            }
        }
    }
    assert_eq!(fenced_tokens, 12, "a quota of 16 stops new tokens at 12");
    // One pass and one lease later the window refills.
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    wait_until("the never-admitted rows compact", || {
        fixture.count("SELECT COUNT(*) FROM retired_tokens") == 0
    })
    .await;
    runtime
        .prepare(&prep(instance), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap();
    b7_matrix(
        "RTC-12: a never-admitted flood stops at the floor",
        json!({"quota": 16, "stopped_at": fenced_tokens, "refilled": "after one lease"}),
    );
}

#[tokio::test]
async fn b7_rtc17_an_instance_enrolled_beside_a_borrower_finds_its_share_at_once() {
    // E = 7 admitted entries and two policy slots: share 3, remainder 1.
    let fixture = Fixture::new(NodeOptions {
        fence_allowance_bytes: Some(10 * super::super::journal::FENCE_ENTRY_BOUND),
        max_enrolled: 2,
        ..compacting(POLICY)
    })
    .await;
    let (a, b) = (Id128::random(), Id128::random());
    let runtime_a = fixture.runtime(a, Id128::random());
    let mut held = Vec::new();
    for _ in 0..4 {
        let (context, plan) = issued(&runtime_a, a).await;
        create_accepted(&fixture, &runtime_a, &context, &plan).await;
        held.push((context, plan));
    }
    let refused = runtime_a
        .prepare(&prep(a), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("headroom"), "{refused}");
    // B arrives (the fixture enrolls on first attach) while A keeps its four rows.
    let runtime_b = fixture.runtime(b, Id128::random());
    for _ in 0..3 {
        let (context, plan) = issued(&runtime_b, b).await;
        create_accepted(&fixture, &runtime_b, &context, &plan).await;
    }
    assert!(
        runtime_a
            .prepare(&prep(a), &spec(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    // Every admitted token still fences.
    for (context, plan) in held {
        fenced(
            runtime_a
                .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
    b7_matrix(
        "RTC-17: an instance enrolled beside a borrower finds its share",
        json!({"newcomer": "admitted at once", "borrower": "refused past its share"}),
    );
}

#[tokio::test]
async fn b7_rtc18_compaction_has_its_own_lane_and_a_full_batch_stays_under_100_ms() {
    let fixture = Fixture::new(NodeOptions {
        max_enrolled: 1,
        ..compacting(POLICY)
    })
    .await;
    let instance = Id128::random();
    let runtime = Arc::new(fixture.runtime(instance, Id128::random()));
    let fixture = Arc::new(fixture);
    // 600 finished sessions: many full batches.
    let mut lanes = Vec::new();
    for _ in 0..12 {
        let (fixture, runtime) = (fixture.clone(), runtime.clone());
        lanes.push(tokio::spawn(async move {
            for _ in 0..50 {
                session(&fixture, &runtime, instance).await;
            }
        }));
    }
    for lane in lanes {
        lane.await.unwrap();
    }
    // Saturate the other lanes while the compaction comes due: normal Preflights and
    // reserved Inspects keep L busy, and the batch still runs.
    fixture.fault("L.frame_log");
    let busy = {
        let (fixture, runtime) = (fixture.clone(), runtime.clone());
        tokio::spawn(async move {
            for _ in 0..200 {
                let _ = runtime.prepare(&prep(instance), &spec(), deadline(5), &no_cancel()).await;
                let _ = node_totals(&runtime).await;
            }
            drop(fixture);
        })
    };
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    let began = std::time::Instant::now();
    wait_until("600 tokens compact while the other lanes are busy", || {
        fixture.count("SELECT COUNT(*) FROM retired_tokens") == 0
    })
    .await;
    let took = began.elapsed();
    busy.abort();
    let frames = std::fs::read_to_string(fixture.root.join("faults/L.frames")).unwrap();
    let compacts: Vec<usize> = frames
        .lines()
        .enumerate()
        .filter(|(_, kind)| *kind == "compact")
        .map(|(index, _)| index)
        .collect();
    assert!(compacts.len() >= 3, "{}", compacts.len());
    // Between consecutive compaction frames there are never more than the other lanes'
    // 96 permits' worth of frames.
    for pair in compacts.windows(2) {
        assert!(pair[1] - pair[0] <= 97, "{pair:?}");
    }
    // Batch duration: time one full 256-token batch directly on the ledger.
    eprintln!("B7 RTC-18: 600 tokens compacted in {took:?} beside a busy normal lane");
    let config = fixture_ledger(&fixture);
    fixture.kill_helper().await;
    let mut ledger = offline_when_stopped(|| {
        super::super::journal::Ledger::open(config.clone()).map_err(|e| e.to_string())
    })
    .await
    .unwrap();
    let mut durations = Vec::new();
    for round in 0..5u32 {
        // A full batch of admitted, finished sessions: every child family has rows.
        for index in 0..COMPACTION_BATCH as u32 {
            let token = match ledger.issue_and_snapshot(instance, false).unwrap() {
                super::super::journal::IssueOutcome::Issued { token, .. } => token,
                other => panic!("{other:?}"),
            };
            let request = ledger_request(instance, token, round * 1000 + index);
            assert!(matches!(
                ledger.admit_intent(&request).unwrap(),
                super::super::journal::AdmitOutcome::Accepted { .. }
            ));
            ledger.settle_unstarted(instance, token).unwrap();
            ledger.record_stop(instance, token, "delete").unwrap();
            let fence = super::super::journal::FenceRequest {
                instance_id: instance,
                allocation_id: token,
                sandbox_id: request.sandbox_id.clone(),
                plan_digest: request.plan_digest,
                observations: "permits=settled;namespace=absent".into(),
            };
            assert!(matches!(
                ledger.commit_fence(&fence).unwrap(),
                super::super::journal::FenceOutcome::Absent { .. }
            ));
        }
        let pointer = ledger.pointers(instance).unwrap().issue_next;
        ledger.advance_watermark(instance, pointer).unwrap();
        let start = std::time::Instant::now();
        let batch = ledger.compact_batch(instance, COMPACTION_BATCH).unwrap();
        durations.push(start.elapsed());
        assert_eq!(batch.tokens_deleted, COMPACTION_BATCH, "round {round}");
    }
    durations.sort();
    eprintln!("B7 RTC-18: compact_batch p50 {:?}, max {:?}", durations[2], durations[4]);
    // Four of five full batches under the cap, so one scheduling hiccup of a loaded
    // machine is not mistaken for a batch that is too large.
    assert!(durations[3] < Duration::from_millis(100), "{durations:?}");
    b7_matrix(
        "RTC-18: compaction's own lane, a full batch under 100 ms",
        json!({"batch": COMPACTION_BATCH, "p50_ms": durations[2].as_secs_f64() * 1e3, "max_ms": durations[4].as_secs_f64() * 1e3}),
    );
}

/// Preflight then FenceAbsent with no Create: the never-admitted fence a post-C1
/// refusal leaves (design 16.1's second and third flows), spending window quota.
async fn refusal(runtime: &FirecrackerRuntime, instance: Id128) {
    let (context, plan) = issued_retrying(runtime, instance).await;
    fence_retrying(runtime, &context, &plan).await;
}

/// Design 16.6's lifetime test, through the real H and L processes behind the real
/// listener and adapter, a FULL-sync ledger and B3's fake host effects. Each of two
/// instances drives 14,000 admitted sessions and 2,500 never-admitted fences (16,500
/// issuances each, 33,000 in all), under the default policy (8 slots), with lease 60 s
/// on the injected boot clock; after every 500 sessions per instance the clock moves one
/// pass and one lease so the next pass advances W and compacts. The fake effects cannot
/// run executions: B5's broker needs the real chain, which `b7_linux_root_compaction_cycles`
/// covers. Run it explicitly: about 45 minutes on mini-one.
#[tokio::test]
#[ignore = "B7 lifetime test: run explicitly (about 45 minutes on mini-one)"]
async fn b7_lifetime_past_16384_sessions() {
    lifetime(14_000, 2_500, 500).await;
}

/// The same schedule at 1/20 scale, in every ordinary test run.
#[tokio::test]
async fn b7_lifetime_smoke_three_windows() {
    lifetime(300, 54, 100).await;
}

#[allow(non_snake_case)]
async fn lifetime(sessions_per_instance: u32, refusals_per_instance: u32, window_size: u32) {
    let (SESSIONS, REFUSALS, WINDOW) = (sessions_per_instance, refusals_per_instance, window_size);
    const LANES: u32 = 6;
    let policy = POLICY;
    let fixture = Arc::new(
        Fixture::new(NodeOptions {
            max_enrolled: DEFAULT_MAX_ENROLLED,
            ..compacting(policy)
        })
        .await,
    );
    let instances = [Id128::random(), Id128::random()];
    let runtimes: Vec<Arc<FirecrackerRuntime>> = instances
        .iter()
        .map(|instance| fixture.runtime(*instance, Id128::random()))
        .collect();
    let started = std::time::Instant::now();
    let mut clock = 0i64;
    let mut live_bytes = Vec::new();
    let mut audit_times = Vec::new();
    let mut retained_peak = 0u64;
    let (mut done_sessions, mut done_refusals) = (0u32, 0u32);
    let mut window = 0u32;
    while done_sessions < SESSIONS {
        let sessions = WINDOW.min(SESSIONS - done_sessions);
        // Interleaved on a fixed schedule: one refusal after roughly every 5.6 sessions.
        let refusals = (u64::from(done_sessions + sessions) * u64::from(REFUSALS)
            / u64::from(SESSIONS)) as u32
            - done_refusals;
        assert!(refusals <= 90, "{refusals}");
        let mut lanes = Vec::new();
        for (instance, runtime) in instances.iter().zip(&runtimes) {
            for lane in 0..LANES {
                let (fixture, runtime, instance) = (fixture.clone(), runtime.clone(), *instance);
                let mine = (sessions + LANES - 1 - lane) / LANES;
                let my_refusals = (refusals + LANES - 1 - lane) / LANES;
                lanes.push(tokio::spawn(async move {
                    let mut receipts = 0;
                    for index in 0..mine {
                        let (context, plan, receipt) = session(&fixture, &runtime, instance).await;
                        assert!(receipt.matches(&binding_of(&context, &plan)));
                        receipts += 1;
                        if my_refusals != 0 && index % (mine / my_refusals).max(1) == 0
                            && index / (mine / my_refusals).max(1) < my_refusals
                        {
                            refusal(&runtime, instance).await;
                        }
                    }
                    receipts
                }));
            }
        }
        let mut released = 0;
        for lane in lanes {
            released += lane.await.unwrap();
        }
        assert_eq!(released, 2 * sessions, "every session released by a matching receipt");
        done_sessions += sessions;
        done_refusals += refusals;
        window += 1;
        // Window boundary: never-admitted rows stay under the issuance floor.
        for runtime in &runtimes {
            let snapshot = node_totals(runtime).await;
            let tokens = snapshot.tokens.clone().unwrap();
            assert!(tokens.retained_never_admitted <= 153, "{tokens:?}");
            retained_peak = retained_peak
                .max(snapshot.retained_admitted_total + snapshot.retained_never_admitted_total);
            assert!(
                snapshot.retained_admitted_total <= snapshot.admitted_entries,
                "{snapshot:?}"
            );
        }
        // One pass and one lease: the next pass advances W past the whole window.
        let targets: Vec<u64> = {
            let mut targets = Vec::new();
            for runtime in &runtimes {
                targets.push(node_totals(runtime).await.tokens.unwrap().issue_next);
            }
            targets
        };
        let _ = policy;
        for (runtime, target) in runtimes.iter().zip(&targets) {
            drive_watermark_past(&fixture, &mut clock, runtime, target - 1).await;
            for _ in 0..6000 {
                let tokens = node_totals(runtime).await.tokens.unwrap();
                if tokens.retained_admitted == 0 && tokens.retained_never_admitted == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let tokens = node_totals(runtime).await.tokens.unwrap();
            assert_eq!(
                (tokens.retained_admitted, tokens.retained_never_admitted),
                (0, 0),
                "window {window} compacted"
            );
        }
        live_bytes.push(node_totals(&runtimes[0]).await.ledger_bytes);
        if window == 2 || done_sessions == SESSIONS {
            // Open-audit time, with the helper stopped.
            let config = fixture_ledger(&fixture);
            stop_helper(&fixture).await;
            let began = std::time::Instant::now();
            offline_when_stopped(|| {
                super::super::journal::Ledger::open(config.clone())
                    .map(drop)
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap();
            audit_times.push(began.elapsed());
            fixture.start().await;
            for runtime in &runtimes {
                runtime.test_reattach().await;
            }
        }
        eprintln!(
            "B7 lifetime: window {window}, {done_sessions} sessions and {done_refusals} refusals per instance, {:?}",
            started.elapsed()
        );
    }
    // Per instance: past the old count, every issuance accounted for.
    for runtime in &runtimes {
        let tokens = node_totals(runtime).await.tokens.unwrap();
        if SESSIONS + REFUSALS > 16_384 {
            assert!(tokens.issue_next > 16_385, "{tokens:?}");
        }
        assert!(tokens.issue_next > u64::from(SESSIONS + REFUSALS));
    }
    // Node: 28,000 admitted sessions, live bytes flat after the first lease, audit flat.
    let flat = *live_bytes[..3].iter().max().unwrap();
    assert!(
        *live_bytes.last().unwrap() <= flat + flat / 4,
        "live bytes grew: {live_bytes:?}"
    );
    assert!(
        audit_times[1] <= audit_times[0] * 3 + Duration::from_millis(50),
        "{audit_times:?}"
    );
    // The idle tail (RTC-DR-06): one more token, then two leases idle.
    let (last, last_plan) = issued(&runtimes[0], instances[0]).await;
    let tokens = drive_watermark_past(
        &fixture,
        &mut clock,
        &runtimes[0],
        super::super::token::seq_of(last.allocation_id),
    )
    .await;
    assert_eq!(tokens.watermark, tokens.issue_next);
    assert_eq!(tokens.retained_admitted + tokens.retained_never_admitted, 0);
    let AllocationObservation::AbsentFenced(_) = runtimes[0]
        .inspect_allocation(&last, &last_plan.plan_digest(), deadline(5), &no_cancel())
        .await
        .unwrap()
    else {
        panic!("the last token compacts");
    };
    eprintln!(
        "B7 lifetime: {} admitted sessions and {} refusals in {:?}; retained peak {retained_peak}; live bytes {live_bytes:?}; open audit {audit_times:?}",
        2 * SESSIONS,
        2 * REFUSALS,
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------------------
// B7 crash scenarios (design 16.6, "Crash points"): each through the real H, L, listener
// and adapter with B3's fake effects and a FULL-sync ledger, each at an exact fault point.
// scripts/firecracker-crash-matrix.py runs them in the kiln VM beside B6's eleven; each
// prints one matrix line. They run on macOS and in CI too.

/// One scenario's outcome, for the crash matrix.
fn b7_matrix(scenario: &str, outcome: Value) {
    eprintln!(
        "B7 matrix: {}",
        json!({"scenario": scenario, "passed": true, "outcome": outcome})
    );
}

async fn pointers(runtime: &FirecrackerRuntime) -> TokenAccounting {
    tokens_soon(runtime).await
}

/// The answer an issued token gets from Inspect with some digest.
async fn inspect_reply(fixture: &Fixture, runtime: &FirecrackerRuntime, token: Id128) -> InspectReply {
    let instance = runtime.test_instance();
    match raw_call(
        fixture,
        instance,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::Inspect {
            allocation_id: token,
            plan_digest: Digest::of(b"any plan"),
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap()
    {
        FirecrackerResponse::Inspect(reply) => reply,
        other => panic!("{other:?}"),
    }
}

/// An abandoned seq: Unknown while W is at or below it, Compacted once W passes it,
/// never NotIssued, never reissued, and no row, gate or claim for it.
async fn assert_abandoned(fixture: &Fixture, runtime: &FirecrackerRuntime, token: Id128, clock: &mut i64) {
    assert!(
        matches!(inspect_reply(fixture, runtime, token).await, InspectReply::Unknown { .. }),
        "Unknown before W passes it"
    );
    let rows = fixture.count(&format!(
        "SELECT (SELECT COUNT(*) FROM allocations WHERE allocation_id = '{token}')
              + (SELECT COUNT(*) FROM retired_tokens WHERE allocation_id = '{token}')"
    ));
    assert_eq!(rows, 0);
    let instance = runtime.test_instance();
    let (next, _) = issued(runtime, instance).await;
    assert!(super::super::token::seq_of(next.allocation_id) > super::super::token::seq_of(token));
    mature(fixture, clock, POLICY).await;
    wait_watermark_past(runtime, super::super::token::seq_of(token)).await;
    assert!(
        matches!(inspect_reply(fixture, runtime, token).await, InspectReply::AbsentFenced { .. }),
        "Compacted once W passes it"
    );
    assert_eq!(fixture.census().await["closed_gates"], json!(0));
}

#[tokio::test]
async fn b7_crash_issuance_before_commit_issues_nothing() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    issued(&runtime, instance).await;
    let before = pointers(&runtime).await.issue_next;
    fixture.fault("L.issue.before_commit.panic");
    assert!(runtime.prepare(&prep(instance), &spec(), deadline(5), &no_cancel()).await.is_err());
    fixture.clear("L.issue.before_commit.panic");
    let after = loop {
        if let Ok(snapshot) = runtime.node_accounting(deadline(2), &no_cancel()).await {
            break snapshot.tokens.unwrap().issue_next;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(after, before, "pointer unchanged: no token exists");
    let (next, _) = issued(&runtime, instance).await;
    assert_eq!(super::super::token::seq_of(next.allocation_id), before, "not a reuse");
    b7_matrix("issuance before commit", json!({"pointer": after, "next_seq": before}));
}

#[tokio::test]
async fn b7_crash_issuance_committed_before_the_private_reply_is_abandoned() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    issued(&runtime, instance).await;
    let n = pointers(&runtime).await.issue_next;
    fixture.fault("L.issue.after_commit_before_reply.panic");
    assert!(runtime.prepare(&prep(instance), &spec(), deadline(5), &no_cancel()).await.is_err());
    fixture.clear("L.issue.after_commit_before_reply.panic");
    let key = super::super::journal::tests::key_from_file(&fixture_ledger(&fixture));
    let abandoned = key.issue(instance, n);
    wait_until("the replacement L serves", || true).await;
    loop {
        if runtime.node_accounting(deadline(2), &no_cancel()).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(pointers(&runtime).await.issue_next, n + 1);
    let mut clock = 0;
    assert_abandoned(&fixture, &runtime, abandoned, &mut clock).await;
    b7_matrix("issuance committed, private reply lost", json!({"abandoned_seq": n}));
}

#[tokio::test]
async fn b7_crash_issuance_private_reply_before_the_public_reply_is_abandoned() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    issued(&runtime, instance).await;
    let key = super::super::journal::tests::key_from_file(&fixture_ledger(&fixture));
    let mut clock = 0;
    // The public reply dropped.
    let n = pointers(&runtime).await.issue_next;
    fixture.fault("H.preflight.drop_public_reply");
    assert!(runtime.prepare(&prep(instance), &spec(), deadline(5), &no_cancel()).await.is_err());
    fixture.clear("H.preflight.drop_public_reply");
    assert_abandoned(&fixture, &runtime, key.issue(instance, n), &mut clock).await;
    // The H process killed between L's reply and the public one.
    let n = pointers(&runtime).await.issue_next;
    fixture.fault("H.preflight.after_l_reply_before_public.hold");
    let pending = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.prepare(&prep(instance), &spec(), deadline(10), &no_cancel()).await })
    };
    fixture.wait_reached("H.preflight.after_l_reply_before_public").await;
    fixture.kill_helper().await;
    fixture.clear("H.preflight.after_l_reply_before_public.hold");
    assert!(pending.await.unwrap().is_err(), "no row or charge: a C0 refusal");
    fixture.start().await;
    runtime.test_reattach().await;
    assert_eq!(pointers(&runtime).await.issue_next, n + 1);
    assert_abandoned(&fixture, &runtime, key.issue(instance, n), &mut clock).await;
    b7_matrix("issuance, private reply before the public reply", json!({"abandoned": 2}));
}

#[tokio::test]
async fn b7_crash_issuance_public_reply_before_c1_is_never_presented_again() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    // The daemon got its token and died before C1: nothing recorded it.
    let (lost, _) = issued(&runtime, instance).await;
    drop(runtime);
    let restarted = fixture.runtime(instance, database);
    let (next, _) = issued(&restarted, instance).await;
    assert!(super::super::token::seq_of(next.allocation_id) > super::super::token::seq_of(lost.allocation_id));
    let mut clock = 0;
    assert_abandoned(&fixture, &restarted, lost.allocation_id, &mut clock).await;
    b7_matrix("issuance, public reply before C1", json!({"lost": super::super::token::seq_of(lost.allocation_id)}));
}

#[tokio::test]
async fn b7_crash_issuance_then_a_preparation_refusal_consumes_one_seq_and_no_quota() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    issued(&runtime, instance).await;
    let before = pointers(&runtime).await;
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Preflight {
            sandbox_id: new_id("sb"),
            profile: "other-profile".into(),
            spec: spec(),
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(matches!(reply, FirecrackerResponse::Error(_)), "{reply:?}");
    let after = pointers(&runtime).await;
    assert_eq!(after.issue_next, before.issue_next + 1, "the seq was consumed");
    assert_eq!(after.retained_never_admitted, before.retained_never_admitted);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    let (next, _) = issued(&runtime, instance).await;
    assert_eq!(super::super::token::seq_of(next.allocation_id), before.issue_next + 1);
    b7_matrix("issuance then a preparation refusal", json!({"gap": before.issue_next}));
}

#[tokio::test]
async fn b7_crash_ledger_replaced_while_h_lives_serves_nothing_before_publication() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (active, active_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &active, &active_plan).await;
    // The replacement journals itself, then is held just before H publishes it.
    fixture.fault("H.ledger.before_publish.hold");
    let old = fixture.census().await["ledger"].as_i64().unwrap();
    signal(old, libc::SIGKILL);
    // Nothing is served meanwhile: the dead channel refuses every ledger request.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(runtime.node_accounting(deadline(1), &no_cancel()).await.is_err());
    assert!(runtime.prepare(&prep(instance), &spec(), deadline(2), &no_cancel()).await.is_err());
    let census = fixture.census().await;
    assert_eq!(census["ledger"].as_i64(), Some(old), "not yet published");
    fixture.clear("H.ledger.before_publish.hold");
    wait_until("the replacement is published", || true).await;
    let mut published = false;
    for _ in 0..1000 {
        if fixture.census().await["ledger"].as_i64() != Some(old) {
            published = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(published);
    // Every answer comes from the committed ledger, with K from the new channel.
    assert!(matches!(
        runtime
            .inspect_allocation(&active, &active_plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. } | AllocationObservation::Present { .. }
    ));
    let (next, _) = issued(&runtime, instance).await;
    assert!(super::super::token::seq_of(next.allocation_id) > super::super::token::seq_of(active.allocation_id));
    fenced(
        runtime
            .fence_absent(&active, &active_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    b7_matrix("L replaced while H lives", json!({"published_after_handover": true}));
}

#[tokio::test]
async fn b7_crash_h_process_death_ends_l_and_a_restart_reuses_no_seq() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    for _ in 0..3 {
        session(&fixture, &runtime, instance).await;
    }
    let before = pointers(&runtime).await;
    let ledger = fixture.census().await["ledger"].as_i64().unwrap();
    fixture.kill_helper().await;
    wait_until("L exits once H's socket closes", || !alive(ledger)).await;
    // The restarted L's boot clock is far past every earlier checkpoint, and still
    // nothing advances for one lease after it starts.
    let mut clock = 10 * POLICY.lease_ms as i64;
    set_boot_clock(&fixture, clock);
    fixture.start().await;
    runtime.test_reattach().await;
    clock += POLICY.lease_ms as i64 / 2;
    set_boot_clock(&fixture, clock);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let restarted = pointers(&runtime).await;
    assert_eq!(restarted.issue_next, before.issue_next, "the exact pointer");
    assert_eq!(restarted.watermark, before.watermark, "nothing advanced");
    assert_eq!(restarted.checkpoints, 1, "only the restart checkpoint");
    let (next, _) = issued(&runtime, instance).await;
    assert_eq!(super::super::token::seq_of(next.allocation_id), before.issue_next);
    clock += POLICY.lease_ms as i64 + 1;
    set_boot_clock(&fixture, clock);
    wait_watermark_past(&runtime, before.issue_next - 1).await;
    b7_matrix("H process death", json!({"pointer": before.issue_next}));
}

#[tokio::test]
async fn b7_crash_watermark_advance_before_and_after_its_commit() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (rowless, rowless_plan) = issued(&runtime, instance).await;
    let (active, active_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &active, &active_plan).await;
    issued(&runtime, instance).await;
    let mut clock = 0;
    // Before the commit: W unchanged, and the replacement L starts its lease again.
    fixture.fault("L.compact.advance.before_commit.panic");
    mature(&fixture, &mut clock, POLICY).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    fixture.clear("L.compact.advance.before_commit.panic");
    let w = loop {
        if let Ok(snapshot) = runtime.node_accounting(deadline(2), &no_cancel()).await {
            break snapshot.tokens.unwrap().watermark;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(w, 1, "W unchanged");
    // After the commit: W durable; rows still answer from rows; a Create below W gets
    // the synthesized receipt and allocates nothing.
    fixture.fault("L.compact.advance.after_commit.panic");
    mature(&fixture, &mut clock, POLICY).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    fixture.clear("L.compact.advance.after_commit.panic");
    let tokens = wait_watermark_past(&runtime, super::super::token::seq_of(active.allocation_id)).await;
    assert!(tokens.watermark > 1);
    assert!(matches!(
        runtime
            .inspect_allocation(&active, &active_plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. } | AllocationObservation::Present { .. }
    ));
    let reply = raw_create(&fixture, &rowless, epoch_of(&runtime).await, &rowless_plan).await;
    let receipt = FencedAbsence::decode(&receipt_of(&reply)).unwrap();
    assert!(receipt.matches(&binding_of(&rowless, &rowless_plan)));
    assert_eq!(fixture.active_allocations(), 1);
    b7_matrix("watermark advance", json!({"watermark": tokens.watermark}));
}

#[tokio::test]
async fn b7_crash_delete_batch_rolls_back_whole_at_every_boundary() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    for _ in 0..4 {
        session(&fixture, &runtime, instance).await;
    }
    let rows = || {
        fixture.count("SELECT COUNT(*) FROM allocations") + fixture.count("SELECT COUNT(*) FROM retired_tokens")
    };
    let before = rows();
    let mut clock = 0;
    let points = [
        "L.compact.delete.after_resource_events",
        "L.compact.delete.after_stop_events",
        "L.compact.delete.after_worker_intents",
        "L.compact.delete.after_executable_leases",
        "L.compact.delete.after_identity_leases",
        "L.compact.delete.after_capacity_claims",
        "L.compact.delete.after_allocation_plans",
        "L.compact.delete.after_allocation",
        "L.compact.delete.after_fence",
    ];
    for point in points {
        fixture.fault(&format!("{point}.panic"));
        mature(&fixture, &mut clock, POLICY).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(rows(), before, "{point}: the uncommitted batch rolled back whole");
        fixture.clear(&format!("{point}.panic"));
    }
    // After the commit, a lost reply changes nothing; the rerun is idempotent.
    fixture.fault("L.compact.after_commit_before_reply.panic");
    mature(&fixture, &mut clock, POLICY).await;
    wait_until("the batch committed before L died", || rows() == 0).await;
    fixture.clear("L.compact.after_commit_before_reply.panic");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rows(), 0);
    // A sync failure rolls back whole too, and fail-stops forward effects.
    for _ in 0..2 {
        session(&fixture, &runtime, instance).await;
    }
    let before = rows();
    fixture.fault("L.compact.sync_fail");
    mature(&fixture, &mut clock, POLICY).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rows(), before);
    assert_eq!(fixture.census().await["latched"], json!(true));
    fixture.clear("L.compact.sync_fail");
    b7_matrix("delete batch, every boundary", json!({"points": points.len() + 2}));
}

#[tokio::test]
async fn b7_crash_non_compactable_allocations_below_w_are_never_deleted() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (live, live_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &live, &live_plan).await;
    let (stopped, stopped_plan) = issued(&runtime, instance).await;
    let generation = create_accepted(&fixture, &runtime, &stopped, &stopped_plan).await;
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Stop {
            allocation_id: stopped.allocation_id,
            expected_generation: generation,
            reason: StopReason::Operator,
        },
        wire_deadline(20),
        20_000,
    )
    .await
    .unwrap();
    assert!(matches!(reply, FirecrackerResponse::Stop(_)), "{reply:?}");
    session(&fixture, &runtime, instance).await;
    issued(&runtime, instance).await;
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    wait_watermark_past(&runtime, super::super::token::seq_of(stopped.allocation_id)).await;
    wait_until("the finished one compacts", || {
        fixture.count("SELECT COUNT(*) FROM retired_tokens") == 0
    })
    .await;
    assert_eq!(fixture.active_allocations(), 2, "the live and the stopped one stay");
    for (context, plan) in [(&live, &live_plan), (&stopped, &stopped_plan)] {
        fenced(
            runtime
                .fence_absent(context, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
    b7_matrix("non-compactable rows in a batch", json!({"kept": 2}));
}

#[tokio::test]
async fn b7_crash_a_create_racing_compaction_is_fenced_or_pinned_by_commit_order() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let mut clock = 0;
    // W commits first: C2's lookup gives the synthesized receipt and claims nothing.
    let (late, late_plan) = issued(&runtime, instance).await;
    issued(&runtime, instance).await;
    fixture.fault("H.create.before_admit.hold");
    let creating = {
        let (runtime, context, plan) = (runtime.clone(), late.clone(), late_plan.clone());
        tokio::spawn(async move { runtime.create(&context, &plan, deadline(30), &no_cancel()).await })
    };
    fixture.wait_reached("H.create.before_admit").await;
    mature(&fixture, &mut clock, POLICY).await;
    wait_watermark_past(&runtime, super::super::token::seq_of(late.allocation_id)).await;
    fixture.clear("H.create.before_admit.hold");
    let failure = creating.await.unwrap().unwrap_err();
    let receipt = failure.absence().expect("absent, fenced by W").clone();
    assert!(receipt.matches(&binding_of(&late, &late_plan)));
    assert_eq!(node_totals(&runtime).await.claimed.slots, 0, "zero claims");
    // C2 commits first: the allocation is admitted and pinned by its rows.
    let (pinned, pinned_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &pinned, &pinned_plan).await;
    issued(&runtime, instance).await;
    mature(&fixture, &mut clock, POLICY).await;
    wait_watermark_past(&runtime, super::super::token::seq_of(pinned.allocation_id)).await;
    assert_eq!(fixture.active_allocations(), 1, "pinned below W");
    fenced(
        runtime
            .fence_absent(&pinned, &pinned_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    b7_matrix("Create racing compaction", json!({"fenced": 1, "pinned": 1}));
}

#[tokio::test]
async fn b7_crash_a_remove_racing_compaction_keeps_its_rows_and_its_own_receipt() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (target, plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &target, &plan).await;
    issued(&runtime, instance).await;
    fixture.fault("H.remove.after_state.hold");
    let removing = {
        let (runtime, binding) = (runtime.clone(), binding_of(&target, &plan));
        let digest = binding.plan_digest;
        let context = target.clone();
        tokio::spawn(async move {
            // The adapter's exact-token removal: Remove first, then its fence.
            runtime
                .fence_absent(&context, &digest, deadline(30), &no_cancel())
                .await
        })
    };
    fixture.wait_reached("H.remove.after_state").await;
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    wait_watermark_past(&runtime, super::super::token::seq_of(target.allocation_id)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(fixture.active_allocations(), 1, "not absent yet: the batch skips it");
    // Hold every G_W refresh until the fence row has been read.
    fixture.fault("L.compact.advance.before_commit.panic");
    fixture.clear("H.remove.after_state.hold");
    let receipt = fenced(removing.await.unwrap().unwrap());
    let durable = fixture.retired_receipt(target.allocation_id).expect("its own fence row");
    assert_eq!(receipt, FencedAbsence::decode(&durable).unwrap(), "its own receipt");
    fixture.clear("L.compact.advance.before_commit.panic");
    // Its fence came after the advance: a refresh precedes its compaction (RTC-9).
    mature(&fixture, &mut clock, POLICY).await;
    wait_until("compacted after the refresh", || {
        fixture.retired_receipt(target.allocation_id).is_none()
    })
    .await;
    b7_matrix("Remove racing compaction", json!({"own_receipt": receipt.receipt_id().to_string()}));
}

#[tokio::test]
async fn b7_crash_a_helper_restart_resets_checkpoints_to_one_restart_point() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let mut clock = 0i64;
    for _ in 0..(POLICY.checkpoint_bound() + 3) {
        issued(&runtime, instance).await;
        clock += POLICY.pass_ms as i64 + 1;
        set_boot_clock(&fixture, clock);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    let before = pointers(&runtime).await;
    assert!(before.checkpoints as usize <= POLICY.checkpoint_bound());
    fixture.kill_helper().await;
    fixture.start().await;
    runtime.test_reattach().await;
    clock += POLICY.lease_ms as i64 / 2;
    set_boot_clock(&fixture, clock);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = pointers(&runtime).await;
    assert_eq!(after.issue_next, before.issue_next);
    assert_eq!(after.checkpoints, 1);
    assert_eq!(after.watermark, before.watermark, "no advance inside the first lease");
    let (next, _) = issued(&runtime, instance).await;
    assert_eq!(super::super::token::seq_of(next.allocation_id), before.issue_next);
    b7_matrix("helper restart resets checkpoints", json!({"before": before.checkpoints, "after": 1}));
}

#[tokio::test]
async fn b7_crash_rollback_fault_commit_at_every_boundary_keeps_forward_effects_refused() {
    for (point, kill) in [
        ("L.fault.before_commit.panic", false),
        ("L.fault.after_commit_before_reply.panic", false),
        ("L.fault.sync_fail", false),
        ("L.fault.before_commit.panic", true),
    ] {
        let fixture = Fixture::new(compacting(POLICY)).await;
        let (a, b) = (Id128::random(), Id128::random());
        let (runtime_a, runtime_b) = (
            fixture.runtime(a, Id128::random()),
            fixture.runtime(b, Id128::random()),
        );
        let (_recorded, active, active_plan) =
            rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
        fixture.fault(point);
        assert!(runtime_a.prove_attachment(deadline(10)).await.is_err(), "{point}");
        // Refused from the moment of detection, whatever the commit's fate.
        assert!(
            runtime_b.prepare(&prep(b), &spec(), deadline(5), &no_cancel()).await.is_err(),
            "{point}"
        );
        fixture.clear(point);
        if kill {
            // The whole helper restarts before any replacement could commit the fault:
            // the fail-stop marker written at detection still latches it (RTC-R2-01).
            fixture.kill_helper().await;
            fixture.start().await;
            runtime_b.test_reattach().await;
        } else {
            wait_until("a replacement L commits the pending fault", || {
                fixture.count("SELECT COUNT(*) FROM node_faults") == 1
            })
            .await;
            fixture.kill_helper().await;
            fixture.start().await;
            runtime_b.test_reattach().await;
        }
        assert!(
            runtime_b.prepare(&prep(b), &spec(), deadline(5), &no_cancel()).await.is_err(),
            "{point}: latched after the restart"
        );
        // Inspect, Stop's cleanup path, Remove, Gc and FenceAbsent keep working.
        runtime_b
            .inspect_allocation(&active, &active_plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap();
        fenced(
            runtime_b
                .fence_absent(&active, &active_plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
    b7_matrix("rollback fault commit", json!({"boundaries": 4}));
}

#[tokio::test]
async fn b7_crash_g_w_refresh_for_a_late_pinned_fence_before_and_after_its_commit() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (pinned, plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &pinned, &plan).await;
    issued(&runtime, instance).await;
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    let first = wait_watermark_past(&runtime, super::super::token::seq_of(pinned.allocation_id)).await;
    // Every refresh crashes before its commit from here on, so no pass can slip in
    // between the fence and the crash under test.
    fixture.fault("L.compact.advance.before_commit.panic");
    // Fenced after the advance: its generation is at or above G_W.
    let original = fenced(
        runtime
            .fence_absent(&pinned, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert!(original.helper_generation() > first.watermark_generation);
    // A crash before the refresh commits: nothing is compacted, the original answers.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(fixture.retired_receipt(pinned.allocation_id).is_some());
    // A crash after the refresh, before its delete commits: still the original.
    fixture.fault("L.compact.delete.after_fence.panic");
    fixture.clear("L.compact.advance.before_commit.panic");
    wait_until("the refresh commits", || {
        fixture.count(&format!(
            "SELECT COUNT(*) FROM instance_tokens WHERE watermark_generation > {}",
            original.helper_generation()
        )) == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(fixture.retired_receipt(pinned.allocation_id).is_some());
    // L keeps dying at the delete point each pass; between deaths the rows answer.
    let mut answer = None;
    for _ in 0..400 {
        if let Ok(AllocationObservation::AbsentFenced(receipt)) = runtime
            .inspect_allocation(&pinned, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
        {
            answer = Some(receipt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(answer, Some(original.clone()), "rows answer while they exist");
    fixture.clear("L.compact.delete.after_fence.panic");
    wait_until("compacted after the refresh", || {
        fixture.retired_receipt(pinned.allocation_id).is_none()
    })
    .await;
    let AllocationObservation::AbsentFenced(synthesized) = runtime
        .inspect_allocation(&pinned, &plan.plan_digest(), deadline(5), &no_cancel())
        .await
        .unwrap()
    else {
        panic!("absent");
    };
    assert!(synthesized.helper_generation() > original.helper_generation());
    assert!(synthesized.matches(&binding_of(&pinned, &plan)));
    b7_matrix("G_W refresh for a late pinned fence", json!({
        "original": original.helper_generation(), "synthesized": synthesized.helper_generation()
    }));
}

#[tokio::test]
async fn b7_crash_a_restored_stale_daemon_db_after_compaction_releases_by_synthesized_receipts() {
    let fixture = Fixture::new(NodeOptions {
        ceilings: NodeCeilings {
            slots: 1,
            ..NodeCeilings::default()
        },
        ..compacting(POLICY)
    })
    .await;
    // Another namespace holds the only slot, so every Create below is refused at C2.
    let other = Id128::random();
    let holder_runtime = fixture.runtime(other, Id128::random());
    let (holder, holder_plan) = issued(&holder_runtime, other).await;
    create_accepted(&fixture, &holder_runtime, &holder, &holder_plan).await;
    let state = fixture.root.join("daemon-state");
    private_dir(&state);
    let copy = fixture.root.join("daemon-copy");
    private_dir(&copy);
    let request = || CreateRequest {
        image: "alpine".into(),
        memory_bytes: 512 * MIB,
        cpu_millis: 1000,
        pids: 128,
        disk_bytes: 1 << 30,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: BTreeMap::new(),
    };
    let manager_over = |store: Store| {
        let identity = store.identity().unwrap();
        let runtime = FirecrackerRuntime::with_helper_uid(
            fixture.root.join("helper.sock"),
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() },
            identity.instance_id,
            identity.database_uuid,
        );
        Arc::new(Manager::new(runtime, store, Limits::default()))
    };
    let manager = manager_over(Store::open(&state).unwrap());
    // Each refused Create's fence is held before its commit while the daemon database
    // is copied: the copy holds charged FAILED rows.
    fixture.fault("H.fence.before_commit.hold");
    let creating = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.create(request()).await })
    };
    fixture.wait_reached("H.fence.before_commit").await;
    for name in ["kilnd.db", "kilnd.db-wal", "kilnd.db-shm"] {
        if state.join(name).exists() {
            std::fs::copy(state.join(name), copy.join(name)).unwrap();
        }
    }
    fixture.clear("H.fence.before_commit.hold");
    assert!(creating.await.unwrap().is_err());
    let rows = manager.list(true).unwrap();
    assert!(rows.iter().all(|row| !row.is_charged()), "released by its fence");
    drop(manager);
    // Compaction passes those tokens and their fence rows go.
    let mut clock = 0;
    mature(&fixture, &mut clock, POLICY).await;
    wait_until("the refused tokens compact", || {
        fixture.count("SELECT COUNT(*) FROM retired_tokens") == 0
    })
    .await;
    // H and L restart, and the stale copy comes back.
    fixture.kill_helper().await;
    fixture.start().await;
    let restored = manager_over(Store::open(&copy).unwrap());
    let stale = restored.list(true).unwrap();
    assert!(!stale.is_empty() && stale.iter().all(|row| row.is_charged()), "{stale:?}");
    holder_runtime.test_reattach().await;
    restored.reconcile().await.unwrap();
    for row in restored.list(true).unwrap() {
        assert!(!row.is_charged(), "{row:?}");
        let binding = row.accounting.allocation.clone().unwrap();
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM allocations WHERE allocation_id = '{}'",
                binding.allocation_id
            )),
            0,
            "no claim, VM or disk for a compacted token"
        );
    }
    assert_eq!(node_totals(&holder_runtime).await.claimed.slots, 1);
    b7_matrix("restored stale DB after compaction", json!({"released": stale.len()}));
}

#[tokio::test]
async fn b7_crash_the_offline_clear_killed_before_or_after_its_commit() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    let (recorded, _, _) = rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
    assert!(runtime_a.prove_attachment(deadline(5)).await.is_err());
    fixture.kill_helper().await;
    let config = fixture_ledger(&fixture);
    let directory = reports(&fixture);
    let observation = ObservationBackend::FakeDirectory(fixture.root.join("fake"));
    let mut databases = BTreeMap::new();
    for (instance, tokens) in [(a, vec![recorded]), (b, vec![])] {
        let path = directory.join(format!("{instance}.db"));
        daemon_db(&path, instance, &tokens);
        databases.insert(instance, path);
    }
    let first = directory.join("first.json");
    offline_when_stopped(|| offline::offline_inventory(&config, &observation, &databases, &first))
        .await
        .unwrap();
    // The clear runs in this process: its fault points read this test's own directory.
    let faults = fixture.root.join("clear-faults");
    private_dir(&faults);
    super::super::workers::faults::install(faults.clone());
    let pointer_before = |fixture: &Fixture| {
        fixture.count(&format!(
            "SELECT issue_next FROM instance_tokens WHERE instance_id = '{a}'"
        ))
    };
    let before = pointer_before(&fixture);
    std::fs::write(faults.join("clear.before_commit.panic"), b"").unwrap();
    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        offline::clear_node_faults(&config, &first)
    }));
    std::fs::remove_file(faults.join("clear.before_commit.panic")).unwrap();
    assert!(killed.is_err(), "the clear died before its commit");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 1, "nothing changed");
    assert_eq!(pointer_before(&fixture), before);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_fault_clears"), 0);
    std::fs::write(faults.join("clear.after_commit.panic"), b"").unwrap();
    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        offline::clear_node_faults(&config, &first)
    }));
    std::fs::remove_file(faults.join("clear.after_commit.panic")).unwrap();
    assert!(killed.is_err(), "the clear died after its commit");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_fault_clears"), 1);
    assert!(pointer_before(&fixture) > before, "pointers raised");
    // The marker was not reset yet: the same report is now stale, a fresh inventory
    // and clear finish the job.
    assert!(offline::clear_node_faults(&config, &first).is_err());
    let second = directory.join("second.json");
    offline::offline_inventory(&config, &observation, &databases, &second).unwrap();
    offline::clear_node_faults(&config, &second).unwrap();
    fixture.start().await;
    let honest = fixture.runtime(a, runtime_a.test_database());
    honest.record_token(Some(recorded));
    honest.prove_attachment(deadline(5)).await.unwrap();
    runtime_b.test_reattach().await;
    issued(&runtime_b, b).await;
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
    b7_matrix("offline fault clear", json!({"before_commit": "unchanged", "after_commit": "cleared"}));
}

/// Design 16.6, 16.7 (B7 M1 break-it finding 3): the offline inventory walks every
/// owned resource family node-wide, through the real walk over a fake host tree. An
/// orphan whose name matches no work directory or cgroup still makes the report
/// unexplained, and the clear refuses it.
#[tokio::test]
async fn b7_offline_inventory_walks_every_host_family_before_the_clear() {
    use crate::helper::firecracker::identity::host_name;
    use crate::helper::firecracker::inventory::{HostRoots, ProcSource};
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    let (recorded, active, _) = rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
    assert!(runtime_a.prove_attachment(deadline(5)).await.is_err());
    fixture.kill_helper().await;
    let config = fixture_ledger(&fixture);
    let directory = reports(&fixture);
    let mut databases = BTreeMap::new();
    for (instance, tokens) in [(a, vec![recorded]), (b, vec![])] {
        let path = directory.join(format!("{instance}.db"));
        daemon_db(&path, instance, &tokens);
        databases.insert(instance, path);
    }
    // B's live allocation on the host: jail, work file, cgroup, loop and VMM.
    let root = fixture.root.join("host");
    let roots = HostRoots {
        jail_base: root.join("jails"),
        work_base: root.join("work"),
        cgroup_tree: root.join("cgroup/kilnd-firecracker"),
        sys_block: root.join("block"),
        proc: ProcSource::Directory(root.join("proc")),
        mountinfo: String::new(),
    };
    let file = |path: PathBuf, text: String| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    let live = host_name(b, active.allocation_id);
    std::fs::create_dir_all(roots.jail_base.join("firecracker").join(&live)).unwrap();
    let work = roots.work_base.join(b.to_string()).join(&live).join("work.xfs");
    file(work.clone(), String::new());
    file(roots.sys_block.join("loop3/loop/backing_file"), format!("{}\n", work.display()));
    std::fs::create_dir_all(roots.cgroup_tree.join(b.to_string()).join(&live).join("vm/vmm"))
        .unwrap();
    let process = |pid: u32, cgroup: String, comm: &str| {
        file(root.join(format!("proc/{pid}/cgroup")), format!("0::{cgroup}\n"));
        file(root.join(format!("proc/{pid}/comm")), format!("{comm}\n"));
    };
    process(1, "/init.scope".into(), "systemd");
    process(70, format!("/kilnd-firecracker/{b}/{live}/vm/vmm"), "firecracker");
    let observation = ObservationBackend::FakeHost(roots.clone());
    let inventory = |name: &str| {
        offline::offline_inventory(&config, &observation, &databases, &directory.join(name))
    };
    // An orphan jail directory alone, with no work directory or cgroup of its name.
    let orphan = roots
        .jail_base
        .join("firecracker")
        .join(host_name(b, Id128::random()));
    std::fs::create_dir(&orphan).unwrap();
    let report = offline_when_stopped(|| inventory("orphan-jail.json")).await.unwrap();
    assert_eq!(report.verdict, "unexplained");
    assert_eq!(report.unexplained.len(), 1, "{:?}", report.unexplained);
    assert!(report.unexplained[0].starts_with("jail directory: "), "{:?}", report.unexplained);
    let error = offline::clear_node_faults(&config, &directory.join("orphan-jail.json")).unwrap_err();
    assert!(error.contains("unexplained"), "{error}");
    std::fs::remove_dir(&orphan).unwrap();
    // An orphan VMM outside every allocation's cgroup alone.
    process(71, "/system.slice/stray.service".into(), "firecracker");
    let report = inventory("orphan-vmm.json").unwrap();
    assert_eq!(report.verdict, "unexplained");
    assert!(report.unexplained[0].starts_with("process: 71 (firecracker)"), "{:?}", report.unexplained);
    assert!(offline::clear_node_faults(&config, &directory.join("orphan-vmm.json")).is_err());
    std::fs::remove_dir_all(root.join("proc/71")).unwrap();
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 1, "nothing cleared");
    // Every family explained: the clear goes through.
    let report = inventory("good.json").unwrap();
    assert_eq!(report.verdict, "explained", "{:?}", report.unexplained);
    offline::clear_node_faults(&config, &directory.join("good.json")).unwrap();
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_faults"), 0);
    b7_matrix(
        "offline inventory walks every host family",
        json!({"orphan_jail": "unexplained", "orphan_vmm": "unexplained", "all_explained": "cleared"}),
    );
}

#[tokio::test]
async fn b7_rtc18_a_busy_normal_lane_from_two_instances_never_starves_a_third_instances_refill() {
    let fixture = Arc::new(
        Fixture::new(NodeOptions {
            fence_allowance_bytes: Some(128 * super::super::journal::FENCE_ENTRY_BOUND),
            max_enrolled: 3,
            ..compacting(POLICY)
        })
        .await,
    );
    let (a, b, c) = (Id128::random(), Id128::random(), Id128::random());
    let runtime_c = fixture.runtime(c, Id128::random());
    // C spends its never-admitted window until Preflight's floor refuses it.
    loop {
        match runtime_c.prepare(&prep(c), &spec(), deadline(5), &no_cancel()).await {
            Ok(plan) => {
                let context = CreateContext {
                    instance_id: c,
                    allocation_id: plan.allocation_id().unwrap(),
                    sandbox_id: new_id("sb"),
                };
                fenced(
                    runtime_c
                        .fence_absent(&context, &plan.plan_digest(), deadline(10), &no_cancel())
                        .await
                        .unwrap(),
                );
            }
            Err(error) if error.to_string().contains("window quota") => break,
            Err(error) if error.to_string().contains("preparation slot") => {}
            Err(error) => panic!("{error}"),
        }
    }
    // A and B keep L's normal lane busy, continuously, for several leases.
    let stop = CancellationToken::new();
    let mut load = Vec::new();
    for instance in [a, b] {
        let runtime = fixture.runtime(instance, Id128::random());
        for _ in 0..8 {
            let (fixture, runtime, stop) = (fixture.clone(), runtime.clone(), stop.clone());
            load.push(tokio::spawn(async move {
                let mut done = 0u64;
                while !stop.is_cancelled() {
                    let Ok(plan) = runtime
                        .prepare(&prep(instance), &spec(), deadline(5), &no_cancel())
                        .await
                    else {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        continue;
                    };
                    let context = CreateContext {
                        instance_id: instance,
                        allocation_id: plan.allocation_id().unwrap(),
                        sandbox_id: plan_sandbox(&plan),
                    };
                    let epoch = epoch_of(&runtime).await;
                    if let CreateReply::Accepted { .. } = raw_create(&fixture, &context, epoch, &plan).await {
                        for _ in 0..200 {
                            if runtime
                                .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
                                .await
                                .is_ok()
                            {
                                break;
                            }
                        }
                        done += 1;
                    }
                }
                done
            }));
        }
    }
    let mut clock = 0i64;
    let mut refilled_at = None;
    for lease in 0..4 {
        clock += POLICY.pass_ms as i64 + 1;
        set_boot_clock(&fixture, clock);
        tokio::time::sleep(Duration::from_millis(250)).await;
        clock += POLICY.lease_ms as i64 + 1;
        set_boot_clock(&fixture, clock);
        // Within a lease plus two passes of C's last issuance, its window refills.
        let began = std::time::Instant::now();
        while began.elapsed() < Duration::from_secs(10) {
            if runtime_c.prepare(&prep(c), &spec(), deadline(5), &no_cancel()).await.is_ok() {
                refilled_at.get_or_insert(lease);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    stop.cancel();
    let mut sessions = 0;
    for task in load {
        sessions += task.await.unwrap();
    }
    assert_eq!(refilled_at, Some(0), "refilled in the first lease, beside {sessions} sessions");
    assert!(sessions >= 8, "the normal lane really was busy: {sessions}");
    b7_matrix(
        "RTC-18: a busy normal lane never starves another instance's refill",
        json!({"refilled_in_lease": 0, "concurrent_sessions": sessions}),
    );
}

/// Reads an allocation as reconciliation would, retrying a busy observation slot.
async fn observe(
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> AllocationObservation {
    for _ in 0..500 {
        if let Ok(observation) = runtime
            .inspect_allocation(context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
        {
            return observation;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("no observation of {}", context.allocation_id)
}

/// B7 RTC-13, the daemon's side (Daybreak B7 M1 finding 4): the adapter's digest cache
/// holds only allocations past C1 that are not yet settled. Completed sessions, a
/// Preflight dropped before C1, and every terminal path (fence, AbsentFenced Inspect,
/// Remove, Gc) leave no entry; only Create and a non-terminal Inspect learn one, and
/// Remove and Gc never (re)insert the Store digest they are given.
#[tokio::test]
async fn b7_rtc13_completed_sessions_leave_no_digest_entries() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    for _ in 0..8 {
        session(&fixture, &runtime, instance).await;
    }
    assert_eq!(runtime.test_digest_count(), 0, "eight completed sessions");
    // A Preflight the manager refuses or abandons before C1 records nothing.
    let (dropped, _) = issued(&runtime, instance).await;
    assert_eq!(runtime.test_highest_token(), Some(dropped.allocation_id));
    assert_eq!(runtime.test_digest_count(), 0, "a prepared, dropped Preflight");
    // Create learns it past C1 and a non-terminal Inspect keeps it; the fence forgets
    // it, and the AbsentFenced Inspect after it relearns nothing.
    let (context, plan) = issued(&runtime, instance).await;
    let failure = runtime
        .create(&context, &plan, deadline(2), &no_cancel())
        .await
        .unwrap_err();
    assert!(failure.absence().is_none(), "fake effects never reach READY");
    assert_eq!(runtime.test_digest_count(), 1, "learned at create");
    let observed = observe(&runtime, &context, &plan).await;
    assert!(!matches!(observed, AllocationObservation::AbsentFenced(_)), "{observed:?}");
    assert_eq!(runtime.test_digest_count(), 1);
    fence_retrying(&runtime, &context, &plan).await;
    assert_eq!(runtime.test_digest_count(), 0, "the fence forgets it");
    let observed = observe(&runtime, &context, &plan).await;
    assert!(matches!(observed, AllocationObservation::AbsentFenced(_)), "{observed:?}");
    assert_eq!(runtime.test_digest_count(), 0, "an absent answer relearns nothing");
    // As after a daemon restart: Inspect relearns a live allocation; its fence forgets it.
    let (context, plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    assert_eq!(runtime.test_digest_count(), 0, "the raw Create bypassed the adapter");
    observe(&runtime, &context, &plan).await;
    assert_eq!(runtime.test_digest_count(), 1, "relearned by a live Inspect");
    fence_retrying(&runtime, &context, &plan).await;
    assert_eq!(runtime.test_digest_count(), 0);
    // Remove and Gc forget what their absence settles. (A live Remove needs Linux
    // cleanup; a retired token's Remove and Gc answer with its fence on any host.)
    let binding = binding_of(&context, &plan);
    runtime.test_learn_digest(context.allocation_id, plan.plan_digest());
    let target = RemoveTarget::Fenced { binding: &binding };
    fenced(runtime.remove(target, deadline(10), &no_cancel()).await.unwrap());
    assert_eq!(runtime.test_digest_count(), 0, "Remove forgets it");
    runtime.test_learn_digest(context.allocation_id, plan.plan_digest());
    let targets = [RemoveTarget::Fenced { binding: &binding }];
    let collected = runtime.gc(&targets, deadline(10), &no_cancel()).await.unwrap();
    assert_eq!(collected.len(), 1);
    assert_eq!(runtime.test_digest_count(), 0, "Gc forgets it");
    let target = RemoveTarget::Fenced { binding: &binding };
    fenced(runtime.remove(target, deadline(10), &no_cancel()).await.unwrap());
    assert_eq!(runtime.test_digest_count(), 0, "Remove never inserts the Store digest");
    b7_matrix(
        "RTC-13: completed sessions leave no daemon digest entries",
        json!({"sessions": 8, "entries_after": 0}),
    );
}

/// The daemon's digest cap mirrors the helper's bounds it is the sum of.
#[test]
fn b7_digest_cap_is_the_listed_bound_plus_the_token_gates() {
    use crate::runtime::firecracker::{HELPER_TOKEN_GATES, MAX_DIGESTS};
    assert_eq!(HELPER_TOKEN_GATES, super::super::MAX_TOKEN_GATES);
    assert_eq!(MAX_DIGESTS, super::super::journal::MAX_ACTIVE_LISTED + super::super::MAX_TOKEN_GATES);
}

/// The sandbox ID a prepared plan's substitutions name.
fn plan_sandbox(plan: &PreparedCreate) -> String {
    let document: Value = serde_json::from_slice(plan.backend_plan()).unwrap();
    document["substitutions"]["sandbox_id"].as_str().unwrap().into()
}

#[test]
fn b7_scenario_names_match_the_scripts() {
    // The scripts refuse to report a matrix with a missing scenario; keep all in step.
    let crash = include_str!("../../../../../../scripts/firecracker-crash-matrix.py");
    let attacks = include_str!("../../../../../../scripts/firecracker-regressions.py");
    // B7 milestone 2's real-chain hostile public caller lives with B6's attacks.
    let source = [include_str!("compaction.rs"), include_str!("recovery.rs")].concat();
    let mut names = Vec::new();
    for line in source.lines() {
        if let Some(name) = line
            .trim()
            .strip_prefix("async fn ")
            .and_then(|rest| rest.split('(').next())
        {
            names.push(name.to_string());
            if name.starts_with("b7_crash_") {
                assert!(crash.contains(name), "{name} missing from the crash matrix");
            }
        }
    }
    for script in [crash, attacks] {
        for quoted in script.split('\'').skip(1).step_by(2) {
            if quoted.starts_with("b7_") {
                assert!(names.iter().any(|n| n == quoted), "{quoted} has no test");
            }
        }
    }
}

/// B7 M1 recheck R1 (`reviews/poc-b7m1-recheck`, `poc_b7m1_timed_out_syncfailed_is_not_
/// propagated_to_h`, now a regression): a Create is queued immediately before its final
/// `OpenGate` check; an unrelated FenceAbsent's commit fails, L writes the fail-stop
/// marker and stalls before its `SyncFailed` reply, and the FenceAbsent's five-second
/// deadline drops H's wait. The same L lives on. From the lost answer H holds every
/// forward effect: the queued Create waits at its final boundary instead of crossing it.
/// When L answers, nobody waits for the `SyncFailed`, but H consumes it all the same and
/// latches; the Create is then refused with no gate and no host effect.
#[tokio::test]
async fn b7_crash_a_timed_out_syncfailed_latches_h_while_the_same_l_lives() {
    let mut options = compacting(POLICY);
    options.compaction_tick_ms = 60_000;
    let fixture = Fixture::new(options).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (queued, queued_plan) = issued(&runtime, instance).await;
    let (faulted, faulted_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &faulted, &faulted_plan).await;
    let epoch = epoch_of(&runtime).await;

    fixture.fault("H.create.before_open_gate.hold");
    let create = spawn_raw_create(&fixture, instance, epoch, &queued, &queued_plan);
    fixture.wait_reached("H.create.before_open_gate").await;

    fixture.fault("L.fence.sync_fail");
    fixture.fault("L.sync_failed_reply.stall");
    let fence = spawn_raw_fence(&fixture, instance, epoch, &faulted, &faulted_plan, 5);
    fixture.wait_reached("L.sync_failed_reply").await;
    let marker = fixture
        .root
        .join("ledger")
        .join(super::super::compaction::FAILSTOP_MARKER);
    assert!(std::fs::read(&marker).unwrap().starts_with(b"latched"));
    let old_l = fixture.census().await["ledger"].as_i64().unwrap();
    let reply = fence.await.unwrap().unwrap();
    assert!(matches!(reply, FirecrackerResponse::Fence(FenceReply::Ambiguous { .. })), "{reply:?}");
    // The answer is lost and L is still stalled before it: forward effects are held.
    let census = fixture.census().await;
    assert_eq!(census["lost_answers"], json!(1), "{census}");
    assert_eq!(census["ledger"].as_i64(), Some(old_l), "the same L");
    fixture.clear("H.create.before_open_gate.hold");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!create.is_finished(), "the queued Create waits at its final boundary");
    assert!(!fixture.fake_dir(&queued).exists(), "nothing started during the hold");

    // L answers: the abandoned SyncFailed is consumed, H latches, the Create is refused.
    fixture.clear("L.sync_failed_reply.stall");
    fixture.clear("L.fence.sync_fail");
    let Response::Firecracker(FirecrackerResponse::Create(reply)) = create.await.unwrap() else {
        panic!("not a create reply");
    };
    assert_eq!(class_of(&reply), AmbiguousClass::Latched, "{reply:?}");
    assert!(!fixture.fake_dir(&queued).exists(), "no host effect after the latch");
    let census = fixture.census().await;
    assert_eq!(census["latched"], json!(true), "H imported the lost SyncFailed: {census}");
    assert_eq!(census["latch_kind"], json!("fail_stop"), "{census}");
    assert_eq!(census["lost_answers"], json!(0), "{census}");
    assert_eq!(census["ledger"].as_i64(), Some(old_l), "L survived");
    assert!(std::fs::read(&marker).unwrap().starts_with(b"latched"));
    let refused = runtime.prepare(&prep(instance), &spec(), deadline(10), &no_cancel()).await;
    assert!(refused.is_err(), "Preflight is refused under the latch: {refused:?}");
    b7_matrix(
        "B7 M1 recheck R1: lost SyncFailed, same L",
        json!({"hold_on_lost_answer": true, "queued_create": "held, then Latched", "h_latched": "on the consumed answer"}),
    );
}

/// B7 M1 recheck R1's control: a lost answer that carries no fault holds forward effects
/// only until it arrives, and never latches. A FenceAbsent's deadline lapses while L is
/// held inside its fence; a Create queued at its final boundary waits; when L answers
/// the fence normally the hold lifts, the Create is accepted, and a client that lets its
/// own deadline lapse has fail-stopped nothing.
#[tokio::test]
async fn b7_crash_a_timed_out_benign_answer_holds_forward_effects_only_until_it_arrives() {
    let mut options = compacting(POLICY);
    options.compaction_tick_ms = 60_000;
    let fixture = Fixture::new(options).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (queued, queued_plan) = issued(&runtime, instance).await;
    let (fenced_token, fenced_plan) = issued(&runtime, instance).await;
    let epoch = epoch_of(&runtime).await;
    fixture.fault("H.create.before_open_gate.hold");
    let create = spawn_raw_create(&fixture, instance, epoch, &queued, &queued_plan);
    fixture.wait_reached("H.create.before_open_gate").await;
    // L holds the fence itself, so the request whose deadline lapses is a write.
    fixture.fault("L.fence.stall");
    let fence = spawn_raw_fence(&fixture, instance, epoch, &fenced_token, &fenced_plan, 2);
    fixture.wait_reached("L.fence").await;
    let reply = fence.await.unwrap().unwrap();
    assert!(matches!(reply, FirecrackerResponse::Fence(FenceReply::Ambiguous { .. })), "{reply:?}");
    assert_eq!(fixture.census().await["lost_answers"], json!(1));
    fixture.clear("H.create.before_open_gate.hold");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!create.is_finished(), "held, not refused");
    fixture.clear("L.fence.stall");
    let Response::Firecracker(FirecrackerResponse::Create(reply)) = create.await.unwrap() else {
        panic!("not a create reply");
    };
    assert!(matches!(reply, CreateReply::Accepted { .. }), "{reply:?}");
    let census = fixture.census().await;
    assert_eq!(census["latched"], json!(false), "{census}");
    assert_eq!(census["lost_answers"], json!(0), "{census}");
    issued(&runtime, instance).await;
    b7_matrix(
        "B7 M1 recheck R1: lost benign answer",
        json!({"hold": "until the answer", "queued_create": "Accepted", "latched": false}),
    );
}

fn spawn_raw_create(
    fixture: &Fixture,
    instance: Id128,
    epoch: Id128,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> tokio::task::JoinHandle<Response> {
    let socket = fixture.root.join("helper.sock");
    let operation = create_operation(context, plan);
    tokio::spawn(async move {
        let request = Request {
            version: VERSION,
            timeout_ms: 25_000,
            deadline_ns: wire_deadline(25),
            operation: Operation::Firecracker(FirecrackerRequest {
                group_version: FIRECRACKER_GROUP_VERSION,
                instance_id: instance,
                connection_epoch: Some(epoch),
                operation,
            }),
        };
        let mut stream = UnixStream::connect(socket).await.unwrap();
        fds::send(&stream, &[]).await.unwrap();
        write_frame(&mut stream, &request).await.unwrap();
        assert!(fds::receive(&stream).await.unwrap().is_empty());
        read_frame::<Response>(&mut stream).await.unwrap()
    })
}

fn spawn_raw_fence(
    fixture: &Fixture,
    instance: Id128,
    epoch: Id128,
    context: &CreateContext,
    plan: &PreparedCreate,
    seconds: u64,
) -> tokio::task::JoinHandle<std::io::Result<FirecrackerResponse>> {
    let socket = fixture.root.join("helper.sock");
    let operation = FirecrackerOperation::FenceAbsent {
        allocation_id: context.allocation_id,
        sandbox_id: context.sandbox_id.clone(),
        plan_digest: plan.plan_digest(),
    };
    tokio::spawn(async move {
        let request = Request {
            version: VERSION,
            timeout_ms: (seconds * 1_000) as u32,
            deadline_ns: wire_deadline(seconds),
            operation: Operation::Firecracker(FirecrackerRequest {
                group_version: FIRECRACKER_GROUP_VERSION,
                instance_id: instance,
                connection_epoch: Some(epoch),
                operation,
            }),
        };
        let mut stream = UnixStream::connect(socket).await.unwrap();
        fds::send(&stream, &[]).await.unwrap();
        write_frame(&mut stream, &request).await.unwrap();
        assert!(fds::receive(&stream).await.unwrap().is_empty());
        match read_frame::<Response>(&mut stream).await.unwrap() {
            Response::Firecracker(reply) => Ok(reply),
            other => Err(std::io::Error::other(format!("not Firecracker: {other:?}"))),
        }
    })
}

/// B7 M1 break-it finding 1 (`reviews/poc-b7m1/run-failstop-replacement.sh`, now a
/// regression): an uncertain commit makes L write the durable fail-stop marker, and L
/// is killed at `L.reply` before H receives `SyncFailed`. H sees only a closed channel.
/// The replacement L hands its latch over with K, and H imports it before it publishes
/// the channel, so the previously prepared token's Create, and any Preflight, are
/// refused; the marker was never cleared.
#[tokio::test]
async fn b7_crash_a_lost_syncfailed_then_a_replaced_l_keeps_forward_effects_latched() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (prepared, plan) = issued(&runtime, instance).await;
    let old_l = fixture.census().await["ledger"].as_i64().unwrap();
    // Any uncertain ledger commit takes the same path; the compactor's is the one that
    // needs no caller. Hold at the common reply boundary, after L latched and wrote the
    // marker, and kill L there.
    fixture.fault("H.ledger.latch_imported.hold");
    fixture.fault("L.compact.sync_fail");
    fixture.fault("L.reply.stall");
    fixture.wait_reached("L.reply").await;
    let marker = fixture
        .root
        .join("ledger")
        .join(super::super::compaction::FAILSTOP_MARKER);
    assert!(std::fs::read(&marker).unwrap().starts_with(b"latched"));
    assert_eq!(fixture.census().await["latched"], json!(false), "H never saw SyncFailed");
    signal(old_l, libc::SIGKILL);
    fixture.clear("L.reply.stall");
    fixture.clear("L.compact.sync_fail");
    // The replacement's handover: H has imported the latch and the channel is not yet
    // published, so nothing could have reached the new L unlatched.
    fixture.wait_reached("H.ledger.latch_imported").await;
    let census = fixture.census().await;
    assert_eq!(census["latched"], json!(true), "the latch came over with K: {census}");
    fixture.clear("H.ledger.latch_imported.hold");
    let mut replaced = false;
    for _ in 0..2_000 {
        let census = fixture.census().await;
        if census["ledger"].as_i64().is_some_and(|pid| pid != old_l) {
            replaced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(replaced, "the replacement L was never published");
    // The prepared token's Create starts nothing: no C2, no supervisor, no effect.
    let calls = census_u64(&fixture.census().await, "ledger_calls");
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        create_operation(&prepared, &plan),
        wire_deadline(25),
        25_000,
    )
    .await
    .unwrap();
    assert!(
        !matches!(reply, FirecrackerResponse::Create(CreateReply::Accepted { .. })),
        "a Create was admitted through the fail-stop marker: {reply:?}"
    );
    assert_eq!(
        census_u64(&fixture.census().await, "ledger_calls"),
        calls,
        "refused before any L call"
    );
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM allocations WHERE allocation_id = '{}'",
            prepared.allocation_id
        )),
        0,
        "no C2 claim"
    );
    assert!(!fixture.fake_dir(&prepared).exists(), "no host effect started");
    assert!(
        runtime
            .prepare(&prep(instance), &spec(), deadline(5), &no_cancel())
            .await
            .is_err(),
        "Preflight is refused too"
    );
    // Cleanup still works under the latch, and the marker stays until root's clear.
    fenced(
        runtime
            .fence_absent(&prepared, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert!(std::fs::read(&marker).unwrap().starts_with(b"latched"));
    b7_matrix(
        "B7 M1 finding 1: lost SyncFailed, L replaced",
        json!({"h_latched_before_publication": true, "prepared_create": "refused", "fence_under_latch": "Absent"}),
    );
}

/// B7 M1 break-it finding 2: Create passed its first latch check, committed C2 and is
/// held after supervisor setup, immediately before `OpenGate`. A rollback latches H
/// meanwhile. Released, the Create rechecks the latch, never opens S's gate and starts
/// no host effect; its C2 claim is held for an exact fence, which still works.
#[tokio::test]
async fn b7_rtc14_a_latch_during_create_setup_is_rechecked_before_open_gate() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let (a, b) = (Id128::random(), Id128::random());
    let (runtime_a, runtime_b) = (
        fixture.runtime(a, Id128::random()),
        fixture.runtime(b, Id128::random()),
    );
    let (queued, queued_plan) = issued(&runtime_b, b).await;
    let (_recorded, _, _) = rolled_back(&fixture, &runtime_a, &runtime_b, (a, b)).await;
    let epoch_b = epoch_of(&runtime_b).await;
    fixture.fault("H.create.before_open_gate.hold");
    let create = {
        let request = create_operation(&queued, &queued_plan);
        let socket = fixture.root.join("helper.sock");
        tokio::spawn(async move {
            let request = Request {
                version: VERSION,
                timeout_ms: 25_000,
                deadline_ns: wire_deadline(25),
                operation: Operation::Firecracker(FirecrackerRequest {
                    group_version: FIRECRACKER_GROUP_VERSION,
                    instance_id: b,
                    connection_epoch: Some(epoch_b),
                    operation: request,
                }),
            };
            let mut stream = UnixStream::connect(socket).await.unwrap();
            fds::send(&stream, &[]).await.unwrap();
            write_frame(&mut stream, &request).await.unwrap();
            assert!(fds::receive(&stream).await.unwrap().is_empty());
            read_frame::<Response>(&mut stream).await.unwrap()
        })
    };
    fixture.wait_reached("H.create.before_open_gate").await;
    assert_eq!(fixture.census().await["latched"], json!(false));
    // A's attachment detects the rollback: H latches while the Create is held.
    assert!(runtime_a.prove_attachment(deadline(20)).await.is_err());
    assert_eq!(fixture.census().await["latched"], json!(true));
    fixture.clear("H.create.before_open_gate.hold");
    let Response::Firecracker(FirecrackerResponse::Create(reply)) = create.await.unwrap() else {
        panic!("not a create reply");
    };
    assert_eq!(class_of(&reply), AmbiguousClass::Latched, "{reply:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!fixture.fake_dir(&queued).exists(), "no host effect after the latch");
    fenced(
        runtime_b
            .fence_absent(&queued, &queued_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    b7_matrix(
        "B7 M1 finding 2: latch rechecked before OpenGate",
        json!({"queued_create": "Latched, gate never opened", "fence_under_latch": "Absent"}),
    );
}

/// B7 M1 recheck R3 through the real adapter and helper: an Inspect's answer is read
/// from L and then held in H while a Remove of the same allocation completes and its
/// terminal answer forgets the digest. Released, the stale non-terminal answer does not
/// bring the digest back. With the cap lowered to two, two such races used to leave two
/// permanent entries and refuse the next Preflight with no live allocation; now none is
/// left and Preflight is served. A complete List also drops a digest whose allocation
/// the helper no longer holds.
#[tokio::test]
async fn b7_rtc13_stale_inspects_racing_removes_never_fill_the_digest_cap() {
    let fixture = Fixture::new(compacting(POLICY)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    runtime.test_set_max_digests(2);
    for _ in 0..2 {
        let (context, plan) = issued(&runtime, instance).await;
        create_accepted(&fixture, &runtime, &context, &plan).await;
        let digest = plan.plan_digest();
        fixture.clear("H.inspect.after_lookup.reached");
        fixture.fault("H.inspect.after_lookup.hold");
        let cancel = no_cancel();
        let (observed, ()) = tokio::join!(
            runtime.inspect_allocation(&context, &digest, deadline(20), &cancel),
            async {
                fixture.wait_reached("H.inspect.after_lookup").await;
                fenced(
                    runtime
                        .fence_absent(&context, &digest, deadline(20), &no_cancel())
                        .await
                        .unwrap(),
                );
                fixture.clear("H.inspect.after_lookup.hold");
            }
        );
        // The held answer predates the Remove: not terminal, so it would have relearned.
        let observed = observed.unwrap();
        assert!(
            !matches!(observed, AllocationObservation::AbsentFenced(_)),
            "{observed:?}"
        );
    }
    assert_eq!(runtime.test_digest_count(), 0, "no stale digest survives");
    let (live, live_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &live, &live_plan).await;
    // Reconciliation's recovery: seeded entries for a retired and an unknown token are
    // dropped by a complete List; the live allocation's entry stays.
    runtime.test_learn_digest(live.allocation_id, live_plan.plan_digest());
    let (retired, retired_plan) = issued(&runtime, instance).await;
    fenced(
        runtime
            .fence_absent(&retired, &retired_plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    runtime.test_learn_digest(retired.allocation_id, retired_plan.plan_digest());
    assert_eq!(runtime.test_digest_count(), 2, "at the cap");
    let listed = runtime.list(deadline(20), &no_cancel()).await.unwrap();
    assert!(listed.complete);
    assert_eq!(runtime.test_digest_count(), 1, "the retired token's digest is dropped");
    issued(&runtime, instance).await;
    b7_matrix(
        "B7 M1 recheck R3: stale Inspects racing Removes",
        json!({"stale_entries": 0, "next_preflight": "served", "list_recovery": "retired dropped"}),
    );
}

/// B7 M1 recheck R2's real-chain regressions (the kiln VM, as root).
#[cfg(target_os = "linux")]
mod linux_root {
    use super::*;

    /// B7 M1 recheck R2, real chain: latches H by a real failed commit, the never-admitted
    /// fence of another token of this instance (RTC-R2-01's fail-stop).
    async fn latch_by_a_failed_commit(fixture: &Fixture, runtime: &FirecrackerRuntime) {
        let instance = runtime.test_instance();
        let (other, other_plan) = issued(runtime, instance).await;
        fixture.fault("L.fence.sync_fail");
        let failed = runtime
            .fence_absent(&other, &other_plan.plan_digest(), deadline(20), &no_cancel())
            .await;
        fixture.clear("L.fence.sync_fail");
        assert!(!matches!(failed, Ok(AbsenceReceipt::Fenced(_))), "{failed:?}");
        assert_eq!(fixture.census().await["latched"], json!(true), "H latched");
    }

    /// Waits until H has seen S exit, and returns the census entry.
    async fn supervisor_exited(fixture: &Fixture, allocation: Id128) -> Value {
        for _ in 0..1_200 {
            let census = fixture.census().await;
            let entry = census["supervisors"][allocation.to_string()].clone();
            if !entry["exit"].is_null() {
                return entry;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("S never exited: {}", fixture.log());
    }

    fn intents(real: &super::super::lifecycle::Real, allocation: Id128) -> Vec<String> {
        real.fixture.read(|view| {
            let mut statement = view.prepare(
                "SELECT detail FROM resource_events WHERE allocation_id = ?1 ORDER BY generation",
            )?;
            let rows = statement
                .query_map([allocation.to_string()], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// B7 M1 recheck R2, real chain, H's check before L: S is held at its cgroup step, then
    /// the node latches. Released, S's cgroup intent is never journaled or acknowledged, so
    /// no cgroup tree is created; S is contained and the allocation still removes to ABSENT
    /// under the latch.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs root, KVM and the B4 artifacts: run scripts/firecracker-regressions.py"]
    async fn b7_rtc14_linux_root_a_latch_while_s_waits_grants_no_resource_authority() {
        use super::super::lifecycle::{Real, create, host_leftovers, remove};
        let real = Real::new(NodeOptions::default()).await;
        real.fixture.fault("S.step.cgroup.stall");
        let (runtime, context, _plan) = create(&real).await;
        real.fixture.wait_reached("S.step.cgroup").await;
        latch_by_a_failed_commit(&real.fixture, &runtime).await;
        real.fixture.clear("S.step.cgroup.stall");
        let entry = supervisor_exited(&real.fixture, context.allocation_id).await;
        assert_eq!(entry["stop_fenced"], json!(true), "S was contained: {entry}");
        // Contained at its refused record: the stop fence's record, never further.
        assert!(
            ["preparing", "stop_intent"].contains(&real.phase(context.allocation_id).as_str()),
            "{}",
            real.phase(context.allocation_id)
        );
        assert_eq!(intents(&real, context.allocation_id), Vec::<String>::new(), "no intent");
        assert_eq!(host_leftovers(&real, &context, None), Vec::<String>::new(), "no host effect");
        let removed = remove(&real, &runtime, &context).await;
        assert!(matches!(removed, FenceReply::Absent { .. }), "{removed:?}");
        eprintln!();
        b7_matrix(
            "B7 M1 recheck R2: latch before S's cgroup intent",
            json!({"cgroup_intent": "never sent", "host_effect": "none", "remove": "Absent"}),
        );
    }

    /// B7 M1 recheck R2, real chain, H's check after L: S's cgroup intent is journaled by
    /// an unlatched L, and H is held between that answer and its acknowledgement while
    /// the node latches. H reads the latch again after the answer and refuses the
    /// acknowledgement: S never creates the tree, is contained, and Remove reaches ABSENT.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs root, KVM and the B4 artifacts: run scripts/firecracker-regressions.py"]
    async fn b7_rtc14_linux_root_a_latch_while_h_awaits_l_refuses_the_acknowledgement() {
        use super::super::lifecycle::{Real, create, host_leftovers, remove};
        let real = Real::new(NodeOptions::default()).await;
        real.fixture.fault("S.step.cgroup.stall");
        let (runtime, context, _plan) = create(&real).await;
        real.fixture.wait_reached("S.step.cgroup").await;
        real.fixture.fault("H.record.after_ledger.hold");
        real.fixture.clear("S.step.cgroup.stall");
        real.fixture.wait_reached("H.record.after_ledger").await;
        let recorded = intents(&real, context.allocation_id);
        assert_eq!(recorded.len(), 1, "L journaled the intent: {recorded:?}");
        assert!(recorded[0].contains("cgroup"), "{recorded:?}");
        latch_by_a_failed_commit(&real.fixture, &runtime).await;
        real.fixture.clear("H.record.after_ledger.hold");
        let entry = supervisor_exited(&real.fixture, context.allocation_id).await;
        assert_eq!(entry["stop_fenced"], json!(true), "S was contained: {entry}");
        assert_eq!(intents(&real, context.allocation_id), recorded, "nothing after it");
        assert_eq!(host_leftovers(&real, &context, None), Vec::<String>::new(), "no tree");
        let removed = remove(&real, &runtime, &context).await;
        assert!(matches!(removed, FenceReply::Absent { .. }), "{removed:?}");
        eprintln!();
        b7_matrix(
            "B7 M1 recheck R2: latch while H awaits the cgroup intent",
            json!({"intent": "journaled", "acknowledgement": "refused", "host_effect": "none", "remove": "Absent"}),
        );
    }

    /// B7 M1 recheck R2, real chain, Initialize: the VM is BOOTING and S is held at its
    /// broker readiness step, before any Initialize. The node latches; released, S's
    /// Initialize check is refused, so no Initialize is sent: the allocation never reaches
    /// READY, its VMM is contained, and Remove reaches ABSENT under the latch.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs root, KVM and the B4 artifacts: run scripts/firecracker-regressions.py"]
    async fn b7_rtc14_linux_root_a_latch_before_initialize_sends_none() {
        use super::super::lifecycle::{Real, create, host_leftovers, remove};
        let real = Real::new(NodeOptions::default()).await;
        real.fixture.fault("S.step.broker_ready.stall");
        let (runtime, context, _plan) = create(&real).await;
        real.fixture.wait_reached("S.step.broker_ready").await;
        assert_eq!(real.phase(context.allocation_id), "booting");
        let vmm = real.vmm(context.allocation_id).expect("the VMM is journaled");
        latch_by_a_failed_commit(&real.fixture, &runtime).await;
        real.fixture.clear("S.step.broker_ready.stall");
        let entry = supervisor_exited(&real.fixture, context.allocation_id).await;
        assert_eq!(entry["stop_fenced"], json!(true), "S was contained: {entry}");
        assert!(
            ["booting", "stop_intent"].contains(&real.phase(context.allocation_id).as_str()),
            "never READY: {}",
            real.phase(context.allocation_id)
        );
        assert!(
            !intents(&real, context.allocation_id)
                .iter()
                .any(|detail| detail.contains("\"broker\"")),
            "no broker identity journaled"
        );
        let removed = remove(&real, &runtime, &context).await;
        assert!(matches!(removed, FenceReply::Absent { .. }), "{removed:?}");
        assert_eq!(host_leftovers(&real, &context, Some(vmm)), Vec::<String>::new());
        eprintln!();
        b7_matrix(
            "B7 M1 recheck R2: latch before Initialize",
            json!({"initialize": "never sent", "phase": "booting", "remove": "Absent"}),
        );
    }
}
