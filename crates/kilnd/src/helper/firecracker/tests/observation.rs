//! The absence observation Delete, cleanup and a refused Create's fence depend on, under
//! Create pressure (M3-2 findings F1 and F2), through the real H, L and P processes with
//! fake effects. Create's own work (Preflight, Revalidate, S's session preparation) never
//! takes the observation slot; a Preflight or an observation that finds no slot waits a
//! bounded time for one rather than failing at once, and a waiter that leaves early never
//! stays counted.
use super::super::{SlotWait, wait_for_slot};
use super::*;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

/// A Preflight from `runtime` that the `P.preflight.stall` marker holds inside P.
fn stalled_preflight(
    runtime: &Arc<FirecrackerRuntime>,
    instance: Id128,
) -> tokio::task::JoinHandle<Result<PreparedCreate, RuntimeError>> {
    cancellable_preflight(runtime, instance, deadline(30), no_cancel())
}

fn cancellable_preflight(
    runtime: &Arc<FirecrackerRuntime>,
    instance: Id128,
    until: Instant,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<Result<PreparedCreate, RuntimeError>> {
    let runtime = runtime.clone();
    tokio::spawn(async move {
        runtime
            .prepare(&prep(instance), &spec(), until, &cancel)
            .await
    })
}

/// The preparation workers' health as Capabilities reports it.
async fn preparation_health(fixture: &Fixture, runtime: &FirecrackerRuntime) -> Vec<WorkerHealth> {
    timed_capabilities(runtime, fixture)
        .await
        .health
        .unwrap()
        .preparation
        .to_vec()
}

/// Holds Create's preparation slot with one stalled Preflight, and a second one waiting
/// for it: Create pressure can take every slot but the observation slot, and the waiting
/// Preflight neither fails at once nor takes the observation slot.
async fn hold_every_create_slot(
    fixture: &Fixture,
    runtime: &Arc<FirecrackerRuntime>,
    instance: Id128,
) -> [tokio::task::JoinHandle<Result<PreparedCreate, RuntimeError>>; 2] {
    fixture.fault("P.preflight.stall");
    let held = stalled_preflight(runtime, instance);
    fixture.wait_reached("P.preflight").await;
    let waiting = stalled_preflight(runtime, instance);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished(), "{:?}", waiting.await);
    assert_eq!(
        preparation_health(fixture, runtime).await,
        [WorkerHealth::Busy, WorkerHealth::Healthy],
        "the waiting Preflight never takes the observation slot"
    );
    [held, waiting]
}

/// Ends what [`hold_every_create_slot`] started.
async fn release_create_slots(
    fixture: &Fixture,
    held: [tokio::task::JoinHandle<Result<PreparedCreate, RuntimeError>>; 2],
) {
    fixture.clear("P.preflight.stall");
    for handle in held {
        let _ = handle.await;
    }
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
    assert!(!held[0].is_finished());
    release_create_slots(&fixture, held).await;
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
    release_create_slots(&fixture, held).await;
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

fn spawn_list(
    runtime: &Arc<FirecrackerRuntime>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<Result<crate::runtime::BackendInventory, RuntimeError>> {
    let runtime = runtime.clone();
    tokio::spawn(async move { runtime.list(deadline(30), &cancel).await })
}

/// The wait itself: a waiter dropped while suspended (as H drops a request's future on
/// the client's cancellation, its EOF or the wire deadline) gives its place back, a full
/// queue refuses at once, and an expired wait gives its place back too.
#[tokio::test(start_paused = true)]
async fn a_slot_waiter_dropped_mid_wait_never_stays_counted() {
    let freed = Notify::new();
    let waiters = AtomicUsize::new(0);
    let until = Instant::now() + Duration::from_secs(5);
    {
        let first = wait_for_slot(|| None::<()>, &freed, &waiters, 2, until);
        let second = wait_for_slot(|| None::<()>, &freed, &waiters, 2, until);
        tokio::pin!(first, second);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut first).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut second).await.is_err());
        assert_eq!(waiters.load(Ordering::SeqCst), 2, "both suspended in the wait");
        // Full: refused at once, never counted.
        let third = wait_for_slot(|| None::<()>, &freed, &waiters, 2, until).await;
        assert_eq!(third, Err(SlotWait::QueueFull));
        assert_eq!(waiters.load(Ordering::SeqCst), 2);
        // A wake with nothing free leaves both waiting, still counted.
        freed.notify_waiters();
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut first).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut second).await.is_err());
        assert_eq!(waiters.load(Ordering::SeqCst), 2);
    }
    assert_eq!(waiters.load(Ordering::SeqCst), 0, "dropped waiters leave the queue");
    // A free slot is taken at once, without a place in the queue.
    assert_eq!(wait_for_slot(|| Some(7), &freed, &waiters, 0, until).await, Ok(7));
    // An expired wait answers Expired at its bound and gives its place back.
    let expired = wait_for_slot(|| None::<()>, &freed, &waiters, 2, until).await;
    assert_eq!(expired, Err(SlotWait::Expired));
    assert!(Instant::now() >= until);
    assert_eq!(waiters.load(Ordering::SeqCst), 0);
    // A slot released during the wait is taken at the release.
    let start = Instant::now();
    let free = Cell::new(false);
    let release = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        free.set(true);
        freed.notify_waiters();
    };
    let wait = wait_for_slot(
        || free.get().then_some("slot"),
        &freed,
        &waiters,
        1,
        start + Duration::from_secs(5),
    );
    let (taken, ()) = tokio::join!(wait, release);
    assert_eq!(taken, Ok("slot"));
    assert_eq!(start.elapsed(), Duration::from_secs(1), "taken at the release");
    assert_eq!(waiters.load(Ordering::SeqCst), 0);
}

/// The cutoff holds on every look. A waiter woken late, with the clock already past its
/// cutoff, gets `Expired` and its place back, even though a slot is free by then: that
/// slot first came free after the cutoff. (Every caller, observation, Preflight,
/// revalidation and session preparation, waits through this one function.)
#[tokio::test(start_paused = true)]
async fn a_slot_first_free_after_the_cutoff_is_never_taken() {
    let freed = Notify::new();
    let waiters = AtomicUsize::new(0);
    let cutoff = Instant::now() + Duration::from_secs(5);
    let looks_past_cutoff = Cell::new(0);
    let wait = wait_for_slot(
        || {
            let free = Instant::now() > cutoff;
            looks_past_cutoff.set(looks_past_cutoff.get() + usize::from(free));
            free.then_some(())
        },
        &freed,
        &waiters,
        1,
        cutoff,
    );
    tokio::pin!(wait);
    tokio::select! {
        biased;
        result = &mut wait => panic!("unexpected initial result {result:?}"),
        () = std::future::ready(()) => {}
    }
    assert_eq!(waiters.load(Ordering::SeqCst), 1);
    // The runtime runs the waiter again only 5,001 ms later, after a release.
    tokio::time::advance(Duration::from_millis(5_001)).await;
    freed.notify_waiters();
    assert_eq!(wait.await, Err(SlotWait::Expired));
    assert_eq!(looks_past_cutoff.get(), 0, "no look for a slot past the cutoff");
    assert_eq!(waiters.load(Ordering::SeqCst), 0);
    // Past the cutoff before the first look: no look at all, and nothing taken.
    let past = Instant::now() - Duration::from_millis(1);
    let looks = Cell::new(0);
    let refused = wait_for_slot(
        || {
            looks.set(looks.get() + 1);
            Some(())
        },
        &freed,
        &waiters,
        1,
        past,
    )
    .await;
    assert_eq!(refused, Err(SlotWait::Expired));
    assert_eq!(looks.get(), 0, "no look once past the cutoff");
    assert_eq!(waiters.load(Ordering::SeqCst), 0);
}

/// A waiter woken by its own deadline at the cutoff makes one last look there: a slot
/// free by then is taken, one that never frees is refused at the cutoff and not later,
/// and a slot released (and announced) just before the cutoff is taken at its release.
#[tokio::test(start_paused = true)]
async fn the_last_look_lands_at_the_cutoff() {
    let freed = Notify::new();
    let waiters = AtomicUsize::new(0);
    let wait = Duration::from_millis(5_001);
    let start = Instant::now();
    let cutoff = start + wait;
    let free_at_cutoff = || (Instant::now() >= cutoff).then_some("slot");
    let taken = wait_for_slot(free_at_cutoff, &freed, &waiters, 1, cutoff).await;
    assert_eq!(taken, Ok("slot"), "free at the cutoff: taken");
    assert_eq!(start.elapsed(), wait);
    assert_eq!(waiters.load(Ordering::SeqCst), 0);

    let start = Instant::now();
    let expired = wait_for_slot(|| None::<()>, &freed, &waiters, 1, start + wait).await;
    assert_eq!(expired, Err(SlotWait::Expired));
    assert_eq!(start.elapsed(), wait, "refused at the cutoff, not after it");
    assert_eq!(waiters.load(Ordering::SeqCst), 0);

    let start = Instant::now();
    let cutoff = start + wait;
    let free = Cell::new(false);
    let release = async {
        tokio::time::sleep_until(cutoff - Duration::from_millis(1)).await;
        free.set(true);
        freed.notify_waiters();
    };
    let wait_for = wait_for_slot(|| free.get().then_some(1), &freed, &waiters, 1, cutoff);
    let (taken, ()) = tokio::join!(wait_for, release);
    assert_eq!(taken, Ok(1), "released 1 ms before the cutoff: taken");
    assert_eq!(start.elapsed(), wait - Duration::from_millis(1), "at the release");
    assert_eq!(waiters.load(Ordering::SeqCst), 0);
}

/// Pre-review 3's finding: Tokio rounds a timer up to the next millisecond, so a wait
/// that starts 0.5 ms into a tick has its own deadline wake land up to a millisecond past
/// its cutoff. Releasing the slot wakes the waiter at the release, so the answer doesn't
/// depend on that timer: a slot released 1 ms before the cutoff, or exactly at it, and
/// still free is granted.
async fn check_fractional_cutoff(release_ms: u64, strictly_before: bool) {
    let freed = Notify::new();
    let epoch = Instant::now();
    tokio::time::advance(Duration::from_micros(500)).await;
    let start = Instant::now();
    let cutoff = start + Duration::from_secs(5);
    let free_at = epoch + Duration::from_millis(release_ms);
    let free = Cell::new(false);
    let last_look = Cell::new(start);
    let waiters = AtomicUsize::new(0);
    let wait = wait_for_slot(
        || {
            last_look.set(Instant::now());
            free.get().then_some(())
        },
        &freed,
        &waiters,
        1,
        cutoff,
    );
    let release = async {
        tokio::time::sleep_until(free_at).await;
        free.set(true);
        freed.notify_waiters();
        Instant::now()
    };
    let (result, released) = tokio::join!(wait, release);
    if strictly_before {
        assert!(released < cutoff, "the release must actually run before the cutoff");
    } else {
        assert_eq!(released, cutoff, "the release must run exactly at the cutoff");
    }
    assert_eq!(waiters.load(Ordering::SeqCst), 0);
    assert_eq!(result, Ok(()), "a slot released by the cutoff stayed free");
    assert_eq!(last_look.get(), released, "taken by the look at the release");
}

#[tokio::test(start_paused = true)]
async fn a_slot_freed_before_a_fractional_cutoff_is_taken() {
    check_fractional_cutoff(4_999, true).await;
}

#[tokio::test(start_paused = true)]
async fn a_slot_freed_at_a_fractional_cutoff_is_taken() {
    check_fractional_cutoff(5_000, false).await;
}

/// The exact-at-cutoff rule, without timer rounding in play: a release at the cutoff is
/// taken when the waiter's look after it still reads the cutoff, and refused, with no
/// look at all, when the waiter only runs once the clock has moved past it.
#[tokio::test(start_paused = true)]
async fn a_release_exactly_at_the_cutoff_is_taken_only_by_a_look_at_the_cutoff() {
    for runs_late in [false, true] {
        let freed = Notify::new();
        let waiters = AtomicUsize::new(0);
        let start = Instant::now();
        let cutoff = start + Duration::from_secs(5);
        let free = Cell::new(false);
        let looks = Cell::new(0);
        let wait = wait_for_slot(
            || {
                looks.set(looks.get() + 1);
                free.get().then_some(())
            },
            &freed,
            &waiters,
            1,
            cutoff,
        );
        tokio::pin!(wait);
        tokio::select! {
            biased;
            result = &mut wait => panic!("unexpected initial result {result:?}"),
            () = std::future::ready(()) => {}
        }
        assert_eq!((looks.get(), waiters.load(Ordering::SeqCst)), (1, 1));
        tokio::time::advance(cutoff - Instant::now()).await;
        free.set(true);
        freed.notify_waiters();
        if runs_late {
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        let result = wait.await;
        assert_eq!(waiters.load(Ordering::SeqCst), 0);
        if runs_late {
            assert_eq!(result, Err(SlotWait::Expired), "the waiter ran past the cutoff");
            assert_eq!(looks.get(), 1, "no look past the cutoff");
        } else {
            assert_eq!(result, Ok(()), "looked at the cutoff, after the release");
            assert_eq!(Instant::now(), cutoff);
            assert_eq!(looks.get(), 2);
        }
    }
}

/// The waiter registers for the wake before each look, so a release that lands between
/// a look that found the slot busy and the wait that follows it still wakes it: the slot
/// is taken at the release, not at the cutoff. This happens on the first look and on a
/// look after an earlier wake (one that found the slot taken again).
#[tokio::test(start_paused = true)]
async fn a_release_between_a_look_and_the_wait_is_never_lost() {
    for busy_looks in [1, 2] {
        let freed = Notify::new();
        let waiters = AtomicUsize::new(0);
        let start = Instant::now();
        // A cutoff 0.5 ms into a tick: a lost wake would end past it, Expired.
        let cutoff = start + Duration::from_micros(5_000_500);
        let looks = Cell::new(0);
        let wake_without_slot = async {
            if busy_looks > 1 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                freed.notify_waiters();
            }
        };
        let wait = wait_for_slot(
            || {
                looks.set(looks.get() + 1);
                if looks.get() > busy_looks {
                    return Some(());
                }
                if looks.get() == busy_looks {
                    // Released right after this look, before the waiter waits.
                    freed.notify_waiters();
                }
                None
            },
            &freed,
            &waiters,
            1,
            cutoff,
        );
        let (taken, ()) = tokio::join!(wait, wake_without_slot);
        assert_eq!(taken, Ok(()), "busy looks {busy_looks}");
        let at = Duration::from_secs(u64::from(busy_looks > 1));
        assert_eq!(start.elapsed(), at, "taken at the release, busy looks {busy_looks}");
        assert_eq!(looks.get(), busy_looks + 1);
        assert_eq!(waiters.load(Ordering::SeqCst), 0);
    }
}

/// Pre-review 3's MEDIUM: a synchronous look that starts before the cutoff but finishes
/// after it (a busy runtime) holds a slot past the cutoff. It is given back, which wakes
/// the other waiters, and the answer is `Expired`, on the immediate path and after a
/// wake. Real time: the look blocks its thread.
#[tokio::test]
async fn a_look_that_finishes_past_the_cutoff_gives_its_slot_back() {
    let mut outcomes = Vec::new();
    for first_busy in [false, true] {
        let freed = Notify::new();
        let start = Instant::now();
        let cutoff = start + Duration::from_millis(150);
        let waiters = AtomicUsize::new(0);
        let held = Arc::new(());
        let mut looks = 0;
        let mut began = None;
        let mut acquired = None;
        // Registered as another waiter would be, once the slot is held.
        let mut other_waiter = None;
        let result = wait_for_slot(
            || {
                looks += 1;
                if looks == 1 && first_busy {
                    // Released right after the first look: the waiter looks again.
                    freed.notify_waiters();
                    return None;
                }
                began = Some(Instant::now());
                std::thread::sleep(
                    cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
                );
                acquired = Some(Instant::now());
                let mut notified = Box::pin(freed.notified());
                notified.as_mut().enable();
                other_waiter = Some(notified);
                Some(held.clone())
            },
            &freed,
            &waiters,
            1,
            cutoff,
        )
        .await;
        outcomes.push(result.map(drop));
        assert!(began.is_some_and(|t| t < cutoff), "{first_busy}");
        assert!(acquired.is_some_and(|t| t > cutoff), "{first_busy}");
        assert_eq!(Arc::strong_count(&held), 1, "the slot was given back");
        let woken = tokio::time::timeout(Duration::from_secs(1), other_waiter.unwrap()).await;
        assert!(woken.is_ok(), "{first_busy}: the give-back woke the other waiters");
        assert_eq!(waiters.load(Ordering::SeqCst), 0);
    }
    assert_eq!(outcomes, vec![Err(SlotWait::Expired); 2]);
}

/// A second Preflight while Create's slot is busy waits for it, and succeeds once the
/// first finishes within the wait. The first's lease, given back, wakes it at once: it
/// doesn't sit out the rest of its five seconds.
#[tokio::test]
async fn a_second_preflight_waits_for_creates_slot_and_succeeds_once_it_frees() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let held = hold_every_create_slot(&fixture, &runtime, instance).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!held[1].is_finished(), "still waiting after a second");
    let released = std::time::Instant::now();
    fixture.clear("P.preflight.stall");
    for handle in held {
        let plan = handle.await.unwrap().expect("both Preflights succeed");
        assert!(plan.allocation_id().is_some());
    }
    // The wait's cutoff is about four seconds after the release.
    let after = released.elapsed();
    assert!(after < Duration::from_millis(2_500), "woken by the release: {after:?}");
}

/// A replacement P is a slot made usable too: a Preflight waiting while Create's P is
/// dead (its replacement deferred while L can't settle the prior permit) is woken when
/// the replacement is published, not at its cutoff.
#[tokio::test]
async fn a_replacement_preparation_worker_wakes_its_waiters() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    // Attached and issuing already, so the waiting Preflight below waits only for P.
    issued(&runtime, instance).await;
    let prep_pid = fixture.census().await["prep"][0].as_i64().unwrap();
    fixture.fault("L.loop.stall");
    tokio::time::sleep(Duration::from_millis(100)).await;
    signal(prep_pid, libc::SIGKILL);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fixture.census().await["prep"][0].as_i64(), Some(prep_pid));
    let waiting = stalled_preflight(&runtime, instance);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!waiting.is_finished(), "{:?}", waiting.await);
    let released = std::time::Instant::now();
    fixture.clear("L.loop.stall");
    let plan = waiting.await.unwrap().expect("the Preflight gets the replacement");
    assert!(plan.allocation_id().is_some());
    let after = released.elapsed();
    assert!(after < Duration::from_millis(2_500), "woken by the replacement: {after:?}");
    assert_ne!(fixture.census().await["prep"][0].as_i64(), Some(prep_pid));
}

/// A Preflight is refused only once its wait (five seconds) has passed with Create's
/// slot still busy, and never by taking the observation slot.
#[tokio::test]
async fn a_waiting_preflight_is_refused_only_past_its_wait() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    fixture.fault("P.preflight.stall");
    let held = stalled_preflight(&runtime, instance);
    fixture.wait_reached("P.preflight").await;
    let began = std::time::Instant::now();
    let error = runtime
        .prepare(&prep(instance), &spec(), deadline(30), &no_cancel())
        .await
        .unwrap_err();
    let waited = began.elapsed();
    assert!(
        error.to_string().contains("no preparation slot came free within the wait"),
        "{error}"
    );
    assert!(waited >= Duration::from_millis(4_900), "{waited:?}");
    assert!(waited < Duration::from_millis(7_000), "{waited:?}");
    // Create's worker is still held (by now it may read as stalled); the observation
    // worker was never taken.
    let health = preparation_health(&fixture, &runtime).await;
    assert_ne!(health[0], WorkerHealth::Healthy, "{health:?}");
    assert_eq!(health[1], WorkerHealth::Healthy, "{health:?}");
    fixture.clear("P.preflight.stall");
    assert!(held.await.unwrap().is_ok());
}

/// Sixteen Preflights may wait for Create's slot; the seventeenth is refused at once.
/// Waiters whose clients cancel leave the queue, so the next Preflight waits again
/// instead of finding it full.
#[tokio::test]
async fn a_full_preflight_queue_refuses_at_once_and_canceled_waiters_leave_it() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    fixture.fault("P.preflight.stall");
    let held = stalled_preflight(&runtime, instance);
    fixture.wait_reached("P.preflight").await;
    let cancels: Vec<CancellationToken> = (0..16).map(|_| CancellationToken::new()).collect();
    let waiting: Vec<_> = cancels
        .iter()
        .map(|cancel| cancellable_preflight(&runtime, instance, deadline(30), cancel.clone()))
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(waiting.iter().all(|w| !w.is_finished()));
    let began = std::time::Instant::now();
    let error = runtime
        .prepare(&prep(instance), &spec(), deadline(30), &no_cancel())
        .await
        .unwrap_err();
    assert!(began.elapsed() < Duration::from_millis(1_000));
    assert!(error.to_string().contains("wait queue is full"), "{error}");
    for cancel in &cancels {
        cancel.cancel();
    }
    for waiter in waiting {
        assert!(waiter.await.unwrap().is_err());
    }
    // Every canceled waiter left: a new Preflight waits rather than being refused.
    let next = stalled_preflight(&runtime, instance);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!next.is_finished(), "{:?}", next.await);
    fixture.clear("P.preflight.stall");
    assert!(held.await.unwrap().is_ok());
    assert!(next.await.unwrap().is_ok());
}

/// The same for observations: sixteen Lists may wait while both slots are busy, the
/// seventeenth reports itself incomplete at once, and canceled waiters leave the queue,
/// so a later observation waits and completes.
#[tokio::test]
async fn a_full_observation_queue_refuses_at_once_and_canceled_waiters_leave_it() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    fixture.fault("P.preflight.stall");
    let held = stalled_preflight(&runtime, instance);
    fixture.wait_reached("P.preflight").await;
    fixture.fault("P.observe_node.stall");
    let first = spawn_list(&runtime, no_cancel());
    fixture.wait_reached("P.observe_node").await;
    let cancels: Vec<CancellationToken> = (0..16).map(|_| CancellationToken::new()).collect();
    let waiting: Vec<_> = cancels
        .iter()
        .map(|cancel| spawn_list(&runtime, cancel.clone()))
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(waiting.iter().all(|w| !w.is_finished()));
    let began = std::time::Instant::now();
    let refused = runtime.list(deadline(30), &no_cancel()).await.unwrap();
    assert!(!refused.complete, "{refused:?}");
    assert!(began.elapsed() < Duration::from_millis(1_000));
    for cancel in &cancels {
        cancel.cancel();
    }
    for waiter in waiting {
        let _ = waiter.await.unwrap();
    }
    // Every canceled waiter left: a new List waits for a slot and completes.
    let next = spawn_list(&runtime, no_cancel());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!next.is_finished(), "{:?}", next.await);
    fixture.clear("P.observe_node.stall");
    assert!(first.await.unwrap().unwrap().complete);
    assert!(next.await.unwrap().unwrap().complete);
    fixture.clear("P.preflight.stall");
    assert!(held.await.unwrap().is_ok());
}

/// An observation that arrives first, with both slots idle, takes the observation slot
/// and leaves Create's free: a Preflight right behind it proceeds at once.
#[tokio::test]
async fn an_observation_first_leaves_creates_slot_free() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    fixture.fault("P.observe_node.stall");
    let listing = spawn_list(&runtime, no_cancel());
    fixture.wait_reached("P.observe_node").await;
    assert_eq!(
        preparation_health(&fixture, &runtime).await,
        [WorkerHealth::Healthy, WorkerHealth::Busy]
    );
    let prepared = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.prepare(&prep(instance), &spec(), deadline(5), &no_cancel()),
    )
    .await
    .expect("the Preflight did not wait behind the observation");
    fixture.clear("P.observe_node.stall");
    assert!(prepared.is_ok(), "{prepared:?}");
    assert!(listing.await.unwrap().unwrap().complete);
}

/// S's session preparation holds Create's slot, not the observation slot. The marker
/// makes a fake plan take the same lease a real plan does.
#[tokio::test]
async fn the_session_preparation_lease_takes_creates_slot() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (context, plan) = issued(&runtime, instance).await;
    fixture.fault("H.create.prep_lease_without_plan");
    fixture.fault("H.create.before_open_gate.hold");
    let epoch = epoch_of(&runtime).await;
    let creating = raw_create(&fixture, &context, epoch, &plan);
    tokio::pin!(creating);
    let reached = async {
        fixture.wait_reached("H.create.before_open_gate").await;
        preparation_health(&fixture, &runtime).await
    };
    let health = tokio::select! {
        reply = &mut creating => panic!("the create ended at the gate: {reply:?}"),
        health = reached => health,
    };
    assert_eq!(
        health,
        [WorkerHealth::Busy, WorkerHealth::Healthy],
        "S's lease is on Create's slot and the observation slot is free"
    );
    // An observation proceeds meanwhile on its own slot.
    let cancel = no_cancel();
    let listed = tokio::select! {
        reply = &mut creating => panic!("the create ended at the gate: {reply:?}"),
        listed = runtime.list(deadline(5), &cancel) => listed,
    };
    assert!(listed.unwrap().complete);
    fixture.clear("H.create.before_open_gate.hold");
    assert!(matches!(creating.await, CreateReply::Accepted { .. }));
}

/// F3 on the disk dimension: a 1 GiB disk fits a 1 GiB node disk budget, but the
/// reservation the helper's Preflight would make (with its overhead) does not, so the
/// refusal comes before the Preflight and consumes no sequence.
#[tokio::test]
async fn f3_a_predictable_disk_budget_refusal_consumes_no_sequence() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let (manager, instance) = real_manager(
        &fixture,
        Limits {
            max_node_disk_bytes: 1 << 30,
            ..Limits::default()
        },
    );
    manager.reconcile().await.unwrap();
    let before = issue_next(&fixture, instance);
    let request = small_create();
    assert_eq!(request.disk_bytes, 1 << 30, "the spec alone fits the budget");
    let error = manager.create(request).await.unwrap_err();
    assert!(
        error.to_string().contains("disk bytes budget exhausted"),
        "{error}"
    );
    assert!(manager.list(true).unwrap().is_empty(), "no row");
    assert_eq!(issue_next(&fixture, instance), before, "no sequence consumed");
    assert_eq!(unaccounted(&fixture, instance), Vec::<i64>::new());
}

/// One profile spec at a given disk, PID count, guest CPU and guest memory, as a
/// request and as a spec.
fn sized(
    disk_bytes: u64,
    pids: u32,
    cpu_millis: u32,
    memory_bytes: u64,
) -> (CreateRequest, SandboxSpec) {
    let request = CreateRequest {
        disk_bytes,
        pids,
        cpu_millis,
        memory_bytes,
        ..small_create()
    };
    let spec = SandboxSpec {
        disk_bytes,
        pids,
        cpu_millis,
        memory_bytes,
        ..spec()
    };
    (request, spec)
}

/// Node budgets equal to `charge` on every dimension, room for one sandbox.
fn exact_fit(charge: &crate::model::ResourceReservation) -> Limits {
    Limits {
        max_sandboxes: 1,
        max_node_memory_bytes: charge.memory_bytes,
        max_node_pids: charge.pids,
        max_node_disk_bytes: charge.disk_bytes,
        max_node_host_cpu_millis: charge.host_cpu_millis,
        max_node_virtual_cpu_slots: charge.virtual_cpu_slots,
        max_node_host_pids: charge.host_pids,
        ..Limits::default()
    }
}

/// F3, the whole vector: the manager's budget pre-check predicts exactly what the
/// helper's Preflight charges, on every dimension and on both sides of each rounding
/// boundary of `offline-768-v1` (the 512 MiB disk floor, the 64 MiB multiple, the PID
/// addend). The charge is what a real Preflight through H and P returns, which is what
/// the accepting transaction reserves. Then, through the real pre-check: budgets that
/// fit the charge exactly admit the Create to its Preflight (an over-prediction on any
/// dimension would refuse it), and one unit less on any single dimension is refused
/// before the Preflight, naming that dimension, with no sequence consumed (an
/// under-prediction would let it reach the Preflight and be refused only at commit).
#[tokio::test]
async fn f3_the_prediction_is_the_preparation_charge_on_every_dimension() {
    check_prediction(&[
        (256 * MIB, 16, 1000, 512 * MIB),
        (256 * MIB + 1, 17, 1000, 512 * MIB),
        (1 << 30, 128, 1000, 512 * MIB),
        ((1 << 30) + 1, 129, 1000, 512 * MIB),
        (64 * MIB, 4096, 1000, 512 * MIB),
    ])
    .await;
}

/// Pre-review 3: the same, with guest CPU and guest memory varied independently of disk
/// and PIDs, of each other, and of the profile's fixed host charge (1,000 host CPU
/// millis, 896 MiB): a forecast field taken from a guest request field, which matches
/// the charge only on the usual 1,000-milli, 512 MiB request, is caught too. (Its own
/// fixture: each case enrolls eight instances, and a node takes at most 64.)
#[tokio::test]
async fn f3_the_prediction_ignores_guest_cpu_and_memory() {
    check_prediction(&[
        (1 << 30, 128, 500, 512 * MIB),
        (1 << 30, 128, 1000, 256 * MIB),
        (256 * MIB + 1, 17, 250, 384 * MIB),
        (64 * MIB, 4096, 10, 32 * MIB),
    ])
    .await;
}

/// The body of the two tests above, for (disk, PIDs, guest CPU millis, guest memory).
async fn check_prediction(cases: &[(u64, u32, u32, u64)]) {
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
    for &(disk, pids, cpu, memory) in cases {
        let (request, spec) = sized(disk, pids, cpu, memory);
        let instance = Id128::random();
        let runtime = fixture.runtime(instance, Id128::random());
        let at = format!("disk {disk} pids {pids} cpu {cpu} memory {memory}");
        let charge = runtime
            .prepare(&prep(instance), &spec, deadline(10), &no_cancel())
            .await
            .unwrap_or_else(|error| panic!("{at}: {error}"))
            .reservation();
        let predicted = runtime
            .predicted_reservation(&spec)
            .expect("Firecracker predicts its reservation");
        assert_eq!(predicted.memory_bytes, charge.memory_bytes, "memory, {at}");
        assert_eq!(predicted.disk_bytes, charge.disk_bytes, "disk, {at}");
        assert_eq!(predicted.pids, charge.pids, "PIDs, {at}");
        assert_eq!(predicted.host_cpu_millis, charge.host_cpu_millis, "host CPU, {at}");
        assert_eq!(predicted.virtual_cpu_slots, charge.virtual_cpu_slots, "vCPU slots, {at}");
        assert_eq!(predicted.host_pids, charge.host_pids, "host PIDs, {at}");
        assert_eq!(predicted, charge, "{at}");

        // An exact fit passes the pre-check: its Preflight runs and the transaction
        // reserves exactly the charge.
        let (manager, instance) = real_manager(&fixture, exact_fit(&charge));
        manager.reconcile().await.unwrap();
        let before = issue_next(&fixture, instance);
        // The node's only slot is held, so the helper refuses it at admission once
        // the row is reserved, and its own fence releases it: nothing boots.
        let error = manager.create(request.clone()).await.unwrap_err();
        assert!(error.to_string().contains("Capacity"), "{at}: {error}");
        assert_eq!(issue_next(&fixture, instance), before + 1, "{at}: Preflight ran");
        let rows = manager.list(true).unwrap();
        assert_eq!(rows.len(), 1, "{at}: the transaction admitted it");
        assert_eq!(rows[0].accounting.reservation, charge, "{at}");
        assert!(!rows[0].is_charged(), "{at}: its own fence released it");

        // One unit short on any one dimension: refused at the pre-check.
        type Short = fn(&mut Limits);
        let shorts: [(&str, Short); 6] = [
            ("memory bytes", |l| l.max_node_memory_bytes -= 1),
            ("PIDs", |l| l.max_node_pids -= 1),
            ("disk bytes", |l| l.max_node_disk_bytes -= 1),
            ("host CPU millis", |l| l.max_node_host_cpu_millis -= 1),
            ("vCPU slots", |l| l.max_node_virtual_cpu_slots -= 1),
            ("host PIDs", |l| l.max_node_host_pids -= 1),
        ];
        for (resource, short) in shorts {
            let mut limits = exact_fit(&charge);
            short(&mut limits);
            let (manager, instance) = real_manager(&fixture, limits);
            manager.reconcile().await.unwrap();
            let before = issue_next(&fixture, instance);
            let error = manager.create(request.clone()).await.unwrap_err();
            assert!(
                error.to_string().contains(&format!("node {resource} budget exhausted")),
                "{at}, {resource}: {error}"
            );
            assert_eq!(
                issue_next(&fixture, instance),
                before,
                "{at}, {resource}: refused before its Preflight"
            );
            assert!(manager.list(true).unwrap().is_empty(), "{at}, {resource}");
        }
    }
}

/// Pre-review 3: a valid 500-milli guest still reserves a whole host CPU, in the real
/// Preflight and in the forecast.
#[tokio::test]
async fn a_partial_guest_cpu_still_reserves_a_whole_host_cpu() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let mut partial = spec();
    partial.cpu_millis = 500;
    let prepared = runtime
        .prepare(&prep(instance), &partial, deadline(10), &no_cancel())
        .await
        .unwrap()
        .reservation();
    assert_eq!(prepared.host_cpu_millis, 1000);
    assert_eq!(runtime.predicted_reservation(&partial).unwrap(), prepared);
}

/// Pre-review 3: with 999 host CPU millis left, a 500-milli guest is refused before its
/// Preflight, so no sequence is consumed.
#[tokio::test]
async fn a_partial_guest_cpu_is_refused_before_preflight_when_the_host_budget_is_short() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let (manager, instance) = real_manager(
        &fixture,
        Limits {
            max_node_host_cpu_millis: 999,
            ..Limits::default()
        },
    );
    manager.reconcile().await.unwrap();
    let before = issue_next(&fixture, instance);
    let mut request = small_create();
    request.cpu_millis = 500;
    let error = manager.create(request).await.unwrap_err();
    assert!(
        error.to_string().contains("node host CPU millis budget exhausted"),
        "{error}"
    );
    assert!(manager.list(true).unwrap().is_empty());
    assert_eq!(issue_next(&fixture, instance), before, "the refusal is predictable");
}
