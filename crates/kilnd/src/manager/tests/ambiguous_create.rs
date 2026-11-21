//! One ambiguous create must not be able to block a node for good. Inputs kiln would
//! refuse only after allocating are refused here first, as `INVALID_ARGUMENT` with
//! nothing charged and no runtime call; the per-sandbox maxima never exceed the node
//! budgets; and an ambiguous reservation that does occur has an audited operator
//! release (`release_ambiguous`).
//!
//! The fake's `fail_create` stands in for kiln's exit 1 after allocation with nothing
//! left behind, the shape the VM records for a setup-time refusal in kiln's shim.

use std::sync::Arc;

use super::*;
use crate::runtime::fake::FakeRuntime;
use crate::store::Checkpoint;

type M = Arc<Manager<FakeRuntime>>;

fn manager(fake: &FakeRuntime, limits: Limits) -> M {
    Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        limits,
    ))
}

async fn reserved(m: &M) -> SandboxResources {
    m.health().await.unwrap().node_resources.reserved
}

async fn drain(m: &M) {
    m.begin_shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(5), m.drain_operations())
        .await
        .expect("supervised operations did not drain");
}

/// Everything a refused request must leave untouched: rows, charges and the runtime.
async fn untouched(m: &M, fake: &FakeRuntime) -> (usize, SandboxResources, usize, u32) {
    let (created, prepares) = {
        let s = fake.state();
        (s.created.len(), s.fenced.prepare_calls)
    };
    (
        m.list(true).unwrap().len(),
        reserved(m).await,
        created,
        prepares,
    )
}

fn below_floor_requests() -> Vec<(&'static str, CreateRequest)> {
    vec![
        (
            "cpu",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS - 1,
                ..Default::default()
            },
        ),
        (
            "cpu 1",
            CreateRequest {
                cpu_millis: 1,
                ..Default::default()
            },
        ),
        (
            "memory",
            CreateRequest {
                memory_bytes: MIN_MEMORY_BYTES - 1,
                ..Default::default()
            },
        ),
        (
            "memory 1 MiB",
            CreateRequest {
                memory_bytes: 1 << 20,
                ..Default::default()
            },
        ),
        (
            "pids",
            CreateRequest {
                pids: MIN_PIDS - 1,
                ..Default::default()
            },
        ),
        (
            "pids 1",
            CreateRequest {
                pids: 1,
                ..Default::default()
            },
        ),
        (
            "disk",
            CreateRequest {
                disk_bytes: MIN_DISK_BYTES - 1,
                ..Default::default()
            },
        ),
    ]
}

fn at_floor_request() -> CreateRequest {
    CreateRequest {
        cpu_millis: MIN_CPU_MILLIS,
        memory_bytes: MIN_MEMORY_BYTES,
        pids: MIN_PIDS,
        disk_bytes: MIN_DISK_BYTES,
        ..Default::default()
    }
}

#[test]
fn the_floors_are_what_kiln_can_start() {
    // kiln's cpu.max quota is round(cpus * 100000) us per 100000 us; cgroup v2 refuses a
    // quota below 1000 us, so 10 millis (0.010 cpus, a 1000 us quota) is the least.
    assert_eq!(MIN_CPU_MILLIS, 10);
    assert_eq!(u64::from(MIN_CPU_MILLIS) * 100, 1000);
    assert_eq!(MIN_MEMORY_BYTES, 32 << 20);
    assert_eq!(MIN_PIDS, 16);
    assert_eq!(MIN_DISK_BYTES, 64 << 20);
    // kilnd's own defaults are above every floor, and startup checks that.
    Limits::default().check_default_floors().unwrap();
    for low in [
        Limits {
            default_cpu_millis: MIN_CPU_MILLIS - 1,
            ..Limits::default()
        },
        Limits {
            default_memory_bytes: MIN_MEMORY_BYTES - 1,
            ..Limits::default()
        },
        Limits {
            default_pids: MIN_PIDS - 1,
            ..Limits::default()
        },
        Limits {
            default_disk_bytes: MIN_DISK_BYTES - 1,
            ..Limits::default()
        },
    ] {
        let error = low.check_default_floors().unwrap_err();
        assert!(error.contains("below the request minimum"), "{error}");
    }
}

#[tokio::test]
async fn inputs_below_a_floor_are_refused_before_any_charge_or_runtime_call() {
    let fake = FakeRuntime::default();
    let m = manager(&fake, Limits::default());
    let before = untouched(&m, &fake).await;
    for (name, request) in below_floor_requests() {
        for uid in [1001, 0] {
            let error = m.create_owned(request.clone(), uid).await.unwrap_err();
            assert!(
                matches!(&error, Error::InvalidArgument(message) if message.contains("below the minimum")),
                "{name}: {error:?}"
            );
            assert_eq!(untouched(&m, &fake).await, before, "{name}");
        }
    }
    // 0 still means the default, which is above every floor.
    let defaulted = m
        .create_owned(CreateRequest::default(), 1001)
        .await
        .unwrap();
    assert_eq!(
        defaulted.spec.cpu_millis,
        Limits::default().default_cpu_millis
    );
    m.delete(&defaulted.id).await.unwrap();
    drain(&m).await;
}

#[tokio::test]
async fn values_exactly_at_each_floor_create() {
    let fake = FakeRuntime::default();
    let m = manager(&fake, Limits::default());
    let sandbox = m.create_owned(at_floor_request(), 1001).await.unwrap();
    assert_eq!(sandbox.state, SandboxState::Ready);
    let spec = fake.state().created.last().cloned().unwrap();
    assert_eq!(
        (
            spec.cpu_millis,
            spec.memory_bytes,
            spec.pids,
            spec.disk_bytes
        ),
        (MIN_CPU_MILLIS, MIN_MEMORY_BYTES, MIN_PIDS, MIN_DISK_BYTES)
    );
    // kiln gets 0.010 cpus: a 1 ms quota per 100 ms period, the least cgroup v2 takes.
    assert!(crate::runtime::kiln_direct::create_args(&spec).contains(&"--cpus=0.010".to_string()));
    m.delete(&sandbox.id).await.unwrap();
    drain(&m).await;
}

#[test]
fn the_helper_refuses_the_same_floors() {
    use crate::helper::protocol::validate_spec;
    let spec = |r: CreateRequest| SandboxSpec {
        image: "alpine".into(),
        memory_bytes: r.memory_bytes,
        cpu_millis: r.cpu_millis,
        pids: r.pids,
        disk_bytes: r.disk_bytes,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: Default::default(),
    };
    let at = at_floor_request();
    validate_spec(&spec(at.clone())).unwrap();
    for (name, below) in [
        (
            "cpu",
            CreateRequest {
                cpu_millis: MIN_CPU_MILLIS - 1,
                ..at.clone()
            },
        ),
        (
            "memory",
            CreateRequest {
                memory_bytes: MIN_MEMORY_BYTES - 1,
                ..at.clone()
            },
        ),
        (
            "pids",
            CreateRequest {
                pids: MIN_PIDS - 1,
                ..at.clone()
            },
        ),
        (
            "disk",
            CreateRequest {
                disk_bytes: MIN_DISK_BYTES - 1,
                ..at.clone()
            },
        ),
    ] {
        assert_eq!(
            validate_spec(&spec(below)).unwrap_err(),
            "invalid resource limits",
            "{name}"
        );
    }
}

/// A checkpoint of a fresh default sandbox owned by `uid`, on a manager with
/// checkpoints enabled.
async fn ready_checkpoint(m: &M, uid: u32) -> Checkpoint {
    let source = m.create_owned(CreateRequest::default(), uid).await.unwrap();
    m.capture_checkpoint(
        CaptureRequest {
            sandbox_id: source.id.clone(),
            expiry: Some(RequestedExpiry::default()),
            max_size_bytes: 0,
        },
        uid,
        None,
        None,
    )
    .await
    .unwrap()
}

fn checkpoint_limits() -> Limits {
    Limits {
        checkpoints: Some(CheckpointLimits::default()),
        ..Limits::default()
    }
}

fn restores(fake: &FakeRuntime) -> usize {
    fake.checkpoints(|g| g.calls.iter().filter(|c| c.starts_with("restore")).count())
}

#[tokio::test]
async fn a_fork_below_a_floor_is_refused_before_any_pin_charge_or_restore() {
    let fake = FakeRuntime::default().with_checkpoints();
    let m = manager(&fake, checkpoint_limits());
    let checkpoint = ready_checkpoint(&m, 1001).await;
    let before = untouched(&m, &fake).await;
    let restores_before = restores(&fake);
    let pins_before = m
        .store
        .checkpoint_pins(checkpoint.id.as_str())
        .unwrap()
        .len();
    for (name, request) in below_floor_requests() {
        let error = m
            .create_owned(
                CreateRequest {
                    from_checkpoint: Some(checkpoint.id.to_string()),
                    ..request
                },
                1001,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::InvalidArgument(message) if message.contains("below the minimum")),
            "{name}: {error:?}"
        );
        assert_eq!(untouched(&m, &fake).await, before, "{name}");
        assert_eq!(restores(&fake), restores_before, "{name}");
        assert_eq!(
            m.store
                .checkpoint_pins(checkpoint.id.as_str())
                .unwrap()
                .len(),
            pins_before,
            "{name}"
        );
    }
    drain(&m).await;
}
