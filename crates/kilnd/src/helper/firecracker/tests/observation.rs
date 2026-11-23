//! The absence observation Delete, cleanup and a refused Create's fence depend on, under
//! Create pressure (M3-2 findings F1 and F2), through the real H, L and P processes with
//! fake effects. Create's own work (Preflight, Revalidate, S's session preparation) never
//! takes the observation slot, and an observation waits a bounded time for a slot rather
//! than failing at once.
use super::*;

/// A Preflight from `runtime` that the `P.preflight.stall` marker holds inside P.
fn stalled_preflight(
    runtime: &Arc<FirecrackerRuntime>,
    instance: Id128,
) -> tokio::task::JoinHandle<Result<PreparedCreate, RuntimeError>> {
    let runtime = runtime.clone();
    tokio::spawn(async move {
        runtime
            .prepare(&prep(instance), &spec(), deadline(30), &no_cancel())
            .await
    })
}

/// Holds Create's preparation slot with one stalled Preflight, and shows a second one is
/// refused at once: Create pressure can take every slot but the observation slot.
async fn hold_every_create_slot(
    fixture: &Fixture,
    runtime: &Arc<FirecrackerRuntime>,
    instance: Id128,
) -> tokio::task::JoinHandle<Result<PreparedCreate, RuntimeError>> {
    fixture.fault("P.preflight.stall");
    let held = stalled_preflight(runtime, instance);
    fixture.wait_reached("P.preflight").await;
    let began = std::time::Instant::now();
    let refused = stalled_preflight(runtime, instance).await.unwrap();
    let error = refused.expect_err("a second Preflight must not get the observation slot");
    assert!(error.to_string().contains("preparation slot"), "{error}");
    assert!(began.elapsed() < Duration::from_millis(500));
    held
}

/// F1: Create pressure and a concurrent observation hold both preparation slots when an
/// accepted session's fence needs its absence observation: the step Delete ends with
/// after cleanup (`remove` runs this same fence flow), and the one a daemon's settlement
/// runs for a token with no record. It waits for the observation slot instead of
/// failing, records ABSENT and releases the claim. (A host build can't clean up a READY
/// fake session, which needs Linux cgroups; the VM's M3-2 rerun covers that whole chain.)
#[tokio::test]
async fn f1_a_fence_records_absence_under_create_pressure() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (context, plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    // Another daemon's Creates hold every slot they may.
    let other = Id128::random();
    let pressure = fixture.runtime(other, Id128::random());
    let held = hold_every_create_slot(&fixture, &pressure, other).await;
    // A List holds the observation slot inside P while the fence starts.
    fixture.fault("P.observe_node.stall");
    let listing = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.list(deadline(30), &no_cancel()).await })
    };
    fixture.wait_reached("P.observe_node").await;
    let fencing = {
        let (runtime, context, digest) = (runtime.clone(), context.clone(), plan.plan_digest());
        tokio::spawn(async move {
            runtime
                .fence_absent(&context, &digest, deadline(30), &no_cancel())
                .await
        })
    };
    // Both slots stay busy for a while: the fence waits rather than failing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!fencing.is_finished(), "{:?}", fencing.await);
    fixture.clear("P.observe_node.stall");
    let receipt = fenced(fencing.await.unwrap().expect("the fence records absence"));
    assert!(
        receipt.matches(&plan.binding(&context).unwrap()),
        "{receipt:?}"
    );
    assert!(listing.await.unwrap().is_ok());
    assert_eq!(node_totals(&runtime).await.claimed.slots, 0);
    assert_eq!(fixture.active_allocations(), 0);
    // Create's slot was never taken away from the stalled Preflight.
    assert!(!held.is_finished());
    fixture.clear("P.preflight.stall");
    let _ = held.await;
}

/// F2: a Create the node refuses for capacity, while Create pressure holds every slot it
/// may, ends FAILED with ABSENT recorded and nothing charged, with no Delete.
#[tokio::test]
async fn f2_a_capacity_refusal_under_create_pressure_records_absence_without_delete() {
    let fixture = Fixture::new(NodeOptions {
        ceilings: NodeCeilings {
            slots: 1,
            ..NodeCeilings::default()
        },
        ..NodeOptions::default()
    })
    .await;
    // Another namespace holds the node's only slot.
    let other = Id128::random();
    let holder_runtime = fixture.runtime(other, Id128::random());
    let (holder, holder_plan) = issued(&holder_runtime, other).await;
    create_accepted(&fixture, &holder_runtime, &holder, &holder_plan).await;

    let store = Store::open_in_memory().unwrap();
    let identity = store.identity().unwrap();
    let runtime = FirecrackerRuntime::with_helper_uid(
        fixture.root.join("helper.sock"),
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() },
        identity.instance_id,
        identity.database_uuid,
    );
    let manager = Arc::new(Manager::new(runtime, store, Limits::default()));
    // The Create gets past its own Preflight and Revalidate, then waits before C2.
    fixture.fault("H.create.before_admit.hold");
    let creating = {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .create(CreateRequest {
                    default_env: Vec::new(),
                    from_checkpoint: None,
                    image: "alpine".into(),
                    memory_bytes: 512 * MIB,
                    cpu_millis: 1000,
                    pids: 128,
                    disk_bytes: 1 << 30,
                    network: Network::None,
                    read_only_root: false,
                    writable_paths: vec![],
                    labels: BTreeMap::new(),
                    expiry: None,
                })
                .await
        })
    };
    fixture.wait_reached("H.create.before_admit").await;
    let held = hold_every_create_slot(&fixture, &holder_runtime, other).await;
    fixture.clear("H.create.before_admit.hold");
    let error = creating.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("Capacity"), "{error}");
    let rows = manager.list(true).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.state, SandboxState::Failed, "no Delete ran");
    assert!(!row.is_charged(), "the refusal's own fence released it");
    let ReservationRelease::Fenced(receipt) = row.accounting.release else {
        panic!("{:?}", row.accounting.release);
    };
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM retired_tokens WHERE receipt_id = '{receipt}'"
        )),
        1
    );
    // The holder's claim did not move.
    assert_eq!(node_totals(&holder_runtime).await.claimed.slots, 1);
    fixture.clear("P.preflight.stall");
    let _ = held.await;
}

/// A manager over the real helper for its own new namespace.
fn real_manager(fixture: &Fixture, limits: Limits) -> (Arc<Manager<FirecrackerRuntime>>, Id128) {
    let store = Store::open_in_memory().unwrap();
    let identity = store.identity().unwrap();
    let runtime = FirecrackerRuntime::with_helper_uid(
        fixture.root.join("helper.sock"),
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() },
        identity.instance_id,
        identity.database_uuid,
    );
    (
        Arc::new(Manager::new(runtime, store, limits)),
        identity.instance_id,
    )
}

fn small_create() -> CreateRequest {
    CreateRequest {
        default_env: Vec::new(),
        from_checkpoint: None,
        image: "alpine".into(),
        memory_bytes: 512 * MIB,
        cpu_millis: 1000,
        pids: 128,
        disk_bytes: 1 << 30,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: BTreeMap::new(),
        expiry: None,
    }
}

/// Every sequence the ledger issued to `instance`, below its pointer, that has neither an
/// allocation row nor a retired token: an issued token with no durable outcome.
fn unaccounted(fixture: &Fixture, instance: Id128) -> Vec<i64> {
    let issue_next = fixture.count(&format!(
        "SELECT issue_next FROM instance_tokens WHERE instance_id = '{instance}'"
    ));
    (1..issue_next)
        .filter(|seq| {
            let prefix = format!("{seq:016x}");
            fixture.count(&format!(
                "SELECT (SELECT COUNT(*) FROM allocations WHERE instance_id = '{instance}'
                           AND substr(allocation_id, 1, 16) = '{prefix}')
                      + (SELECT COUNT(*) FROM retired_tokens WHERE instance_id = '{instance}'
                           AND substr(allocation_id, 1, 16) = '{prefix}')"
            )) == 0
        })
        .collect()
}

fn issue_next(fixture: &Fixture, instance: Id128) -> i64 {
    fixture.count(&format!(
        "SELECT issue_next FROM instance_tokens WHERE instance_id = '{instance}'"
    ))
}

/// F3: M3-2's fctest seqs 4 and 5 were Creates the daemon's own node budget refused
/// after their Preflight issued a token (`node memory bytes budget exhausted`): no row
/// and no fence ever named them. A refusal the daemon can predict, from the reservation
/// the helper's Preflight would make (larger than the spec here), now comes before the
/// Preflight and consumes no sequence.
#[tokio::test]
async fn f3_a_predictable_budget_refusal_consumes_no_sequence() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    // The spec's 512 MiB fits the daemon's budget; the helper's reservation does not.
    let (manager, instance) = real_manager(
        &fixture,
        Limits {
            max_node_memory_bytes: 600 * MIB,
            ..Limits::default()
        },
    );
    // Attached first, as a serving daemon is: its pointer exists before any Create.
    manager.reconcile().await.unwrap();
    assert_eq!(issue_next(&fixture, instance), 1);
    for _ in 0..3 {
        let error = manager.create(small_create()).await.unwrap_err();
        assert!(
            error.to_string().contains("memory bytes budget exhausted"),
            "{error}"
        );
    }
    assert!(manager.list(true).unwrap().is_empty(), "no row");
    // The instance is attached (its first Preflight would take seq 1), yet nothing
    // was issued.
    assert_eq!(issue_next(&fixture, instance), 1, "no sequence consumed");
    assert_eq!(unaccounted(&fixture, instance), Vec::<i64>::new());
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
}
