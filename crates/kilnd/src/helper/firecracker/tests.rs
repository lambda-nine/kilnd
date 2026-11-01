//! B3's exit tests against the real stack: a dedicated helper process (H) with its real
//! forked L/P/S/M/K workers and listener, a real ledger file and a real client. Fake
//! parts are only the resources S creates and the catalog this file injects; stalls
//! are real blocked or stopped processes. Nothing here launches a VM.
#![allow(clippy::type_complexity)]
use super::config::{DEFAULT_MAX_ENROLLED, NodeCeilings, ProfileCatalog, SharedReserve};
use super::executable::tests::{all_pins, fixture_bytes, pin_of};
use super::executable::{self, Role, WalkPolicy};
use super::identity::IdentityRanges;
use super::inventory::{ObservationBackend, fake};
use super::journal::{Ledger, LedgerConfig};
use super::manifest::ManifestGate;
use super::peer::{TestPeers, fixture_digest};
use super::workers::{FakeEffect, NodeConfig, TestInjection, Timings, faults};
use super::{Node, load_profile};
use crate::helper::protocol::*;
use crate::helper::{Client, fds, read_frame, serve_with_firecracker, write_frame};
use crate::manager::{CreateRequest, Limits, Manager};
use crate::model::{
    AccountingRegime, CreateCertainty, Digest, Id128, Network, ReservationRelease,
    ResourceReservation, Sandbox, SandboxAccounting, SandboxDisposition, SandboxSpec, SandboxState,
    new_id, now_ms,
};
use crate::runtime::firecracker::FirecrackerRuntime;
use crate::runtime::{
    AbsenceReceipt, AllocationObservation, BackendStatus, CreateContext, FencedAbsence,
    PreparedCreate, Runtime, RuntimeError,
};
use crate::store::{ReserveSandbox, SandboxBudgets, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const FIXTURE_ENV: &str = "KILND_B3_FIXTURE";
const PROFILE: &str = "offline-768-v1";
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeOptions {
    ceilings: NodeCeilings,
    cid: (u32, u32),
    /// `marker:<name>` or `vm`, in order.
    effects: Vec<String>,
    heartbeat_timeout_ms: u64,
    /// Restrict the fence allowance to exercise node headroom end to end.
    fence_allowance_bytes: Option<u64>,
    startup_journal_ms: u64,
    max_enrolled: u32,
    /// Enroll on first attach, for tests that are about something else.
    auto_enroll: bool,
    peers: PeerEvidence,
}

/// Where a fixture helper reads an attaching peer's cgroup. The UID, start time, image
/// and connection pin are real in all three.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum PeerEvidence {
    /// Whatever the instance enrolled.
    AnyCgroup,
    /// `<root>/peers/<pid>`, for hosts where a test can't place a process in a cgroup.
    Markers,
    /// The kernel's `/proc/<pid>/cgroup`.
    Real,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            ceilings: NodeCeilings::default(),
            cid: (3, 65_535),
            effects: vec![],
            heartbeat_timeout_ms: 5_000,
            fence_allowance_bytes: None,
            startup_journal_ms: 30_000,
            max_enrolled: DEFAULT_MAX_ENROLLED,
            auto_enroll: true,
            peers: PeerEvidence::AnyCgroup,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChildConfig {
    root: PathBuf,
    node_id: Id128,
    catalog: ProfileCatalog,
    options: NodeOptions,
}

fn walk_for(root: &Path) -> WalkPolicy {
    WalkPolicy::test_rooted(root)
}

fn ledger_config(config: &ChildConfig) -> LedgerConfig {
    let mut shared = SharedReserve::default();
    if let Some(bytes) = config.options.fence_allowance_bytes {
        shared.fence_allowance_bytes = bytes;
    }
    LedgerConfig {
        directory: config.root.join("ledger"),
        policy: walk_for(&config.root),
        node_id: config.node_id,
        ceilings: config.options.ceilings,
        shared,
        max_enrolled: config.options.max_enrolled,
    }
}

/// The dedicated helper process. `--test-threads=1` makes libtest run this on the
/// process's main thread, so H forks from a single-threaded current-thread runtime,
/// as the installed service does. Test injection exists only in this binary.
#[test]
#[ignore = "re-exec target for node fixtures"]
fn node_fixture_child() {
    let Ok(path) = std::env::var(FIXTURE_ENV) else {
        return;
    };
    let config: ChildConfig =
        serde_json::from_slice(&std::fs::read(Path::new(&path).join("config.json")).unwrap())
            .unwrap();
    faults::install(config.root.join("faults"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let walk = walk_for(&config.root);
        let profile = load_profile(&walk, ManifestGate::TestApproved, &config.catalog).unwrap();
        let helper_image = profile.table.identity(Role::KilndHelper);
        let effects = config
            .options
            .effects
            .iter()
            .map(|effect| match effect.strip_prefix("marker:") {
                Some(name) => FakeEffect::Marker(name.to_string()),
                None => FakeEffect::Vm,
            })
            .collect();
        let node_config = NodeConfig {
            node_id: config.node_id,
            ledger: ledger_config(&config),
            ranges: IdentityRanges {
                cid: config.options.cid.0..=config.options.cid.1,
                ..IdentityRanges::default()
            },
            profiles: vec![profile],
            walk,
            gate: ManifestGate::TestApproved,
            observation: ObservationBackend::FakeDirectory(config.root.join("fake")),
            timings: Timings {
                tick: Duration::from_millis(20),
                heartbeat: Duration::from_millis(100),
                heartbeat_timeout: Duration::from_millis(config.options.heartbeat_timeout_ms),
                startup_journal: Duration::from_millis(config.options.startup_journal_ms),
            },
            helper_image,
            // SAFETY: geteuid has no preconditions.
            service_uid: unsafe { libc::geteuid() },
            max_enrolled: config.options.max_enrolled,
            test: TestInjection {
                effects,
                fake_root: Some(config.root.join("fake")),
                auto_enroll: config.options.auto_enroll,
                peers: match config.options.peers {
                    PeerEvidence::AnyCgroup => TestPeers {
                        directory: None,
                        any_cgroup: true,
                        assumed_digest: Some(fixture_digest()),
                    },
                    PeerEvidence::Markers => TestPeers {
                        directory: Some(config.root.join("peers")),
                        any_cgroup: false,
                        assumed_digest: Some(fixture_digest()),
                    },
                    PeerEvidence::Real => TestPeers {
                        directory: None,
                        any_cgroup: false,
                        assumed_digest: Some(fixture_digest()),
                    },
                },
            },
        };
        let node = match Node::start(node_config).await {
            Ok(node) => Some(node),
            Err(error) => {
                std::fs::write(config.root.join("start-error"), error.to_string()).unwrap();
                None
            }
        };
        if let Some(node) = node.clone() {
            let control = config.root.join("control.sock");
            let _ = std::fs::remove_file(&control);
            let listener = tokio::net::UnixListener::bind(&control).unwrap();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let census = serde_json::to_vec(&node.census()).unwrap();
                    let _ = stream.write_all(&census).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
        // A test process that died cannot leave this fixture behind.
        let parent_root = config.root.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                // SAFETY: getppid has no preconditions; _exit runs no destructors.
                if !parent_root.exists() || unsafe { libc::getppid() } == 1 {
                    unsafe { libc::_exit(0) };
                }
            }
        });
        let socket = config.root.join("helper.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        serve_with_firecracker(
            listener,
            uid,
            config.root.join("missing-kiln"),
            node,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    });
}

struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    child: Mutex<Option<Child>>,
    seen: Mutex<Vec<i32>>,
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn bundle_source(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/firecracker/bundle")
        .join(name)
}

/// A production-shaped manifest made at test time from the fixture's fields. It passes
/// the schema checks only with the test gate; the fixture bytes themselves never do.
fn test_manifest() -> Vec<u8> {
    let raw = std::fs::read(bundle_source("manifest.json")).unwrap();
    let mut manifest = crate::firecracker::strict_json(&raw).unwrap();
    manifest["schema"] = json!(2);
    manifest["fixture_only"] = json!(false);
    manifest["inputs"]["provenance"] = json!("b3-test-injected-catalog");
    crate::firecracker::canonical(&manifest).unwrap()
}

fn prepare_tree(options: NodeOptions) -> (tempfile::TempDir, PathBuf, ChildConfig) {
    let temp = tempfile::Builder::new()
        .prefix("b3")
        .tempdir_in("/tmp")
        .unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "exec",
        "exec/sha256",
        "bundle",
        "ledger",
        "fake",
        "faults",
        "peers",
        "source",
    ] {
        private_dir(&root.join(name));
    }
    let walk = walk_for(&root);
    let store = root.join("exec/sha256");
    for role in Role::ALL {
        let source = root.join("source").join(role.as_str());
        std::fs::write(&source, fixture_bytes(role)).unwrap();
        executable::publish_object(
            &walk,
            &store,
            &std::fs::File::open(&source).unwrap(),
            &pin_of(role),
        )
        .unwrap();
    }
    for name in [
        "Image",
        "kernel.config",
        "kiln",
        "kilnd-guest-broker",
        "rootfs.squashfs",
    ] {
        std::fs::copy(bundle_source(name), root.join("bundle").join(name)).unwrap();
        std::fs::set_permissions(
            root.join("bundle").join(name),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
    }
    let manifest = test_manifest();
    std::fs::write(root.join("bundle/manifest.json"), &manifest).unwrap();
    std::fs::set_permissions(
        root.join("bundle/manifest.json"),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    let config = ChildConfig {
        root: root.clone(),
        node_id: Id128::random(),
        catalog: ProfileCatalog {
            profile: PROFILE.into(),
            approved_manifest_sha256: Digest::of(&manifest),
            bundle_directory: root.join("bundle"),
            exec_store: store,
            catalog_generation: 1,
            installation_generations: Role::ALL.iter().map(|role| (*role, 1)).collect(),
        },
        options,
    };
    std::fs::write(
        root.join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    (temp, root, config)
}

impl Fixture {
    async fn new(options: NodeOptions) -> Self {
        let (temp, root, config) = prepare_tree(options);
        Ledger::provision(&ledger_config(&config)).unwrap();
        let fixture = Self {
            temp,
            root,
            child: Mutex::new(None),
            seen: Mutex::default(),
        };
        fixture.start().await;
        fixture
    }

    /// Provisioned, with the helper not yet running: root's enrollment happens here.
    fn unstarted(options: NodeOptions) -> Self {
        let (temp, root, config) = prepare_tree(options);
        Ledger::provision(&ledger_config(&config)).unwrap();
        Self {
            temp,
            root,
            child: Mutex::new(None),
            seen: Mutex::default(),
        }
    }

    fn spawn_helper(&self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("child.log"))
            .unwrap();
        let child = {
            let _guard = crate::process::spawn_guard();
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "helper::firecracker::tests::node_fixture_child",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(FIXTURE_ENV, &self.root)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap()
        };
        *self.child.lock().unwrap() = Some(child);
    }

    async fn start(&self) {
        let _ = std::fs::remove_file(self.root.join("helper.sock"));
        self.spawn_helper();
        wait_until("the helper listens", || {
            std::os::unix::net::UnixStream::connect(self.root.join("helper.sock")).is_ok()
        })
        .await;
    }

    fn helper_pid(&self) -> i32 {
        self.child.lock().unwrap().as_ref().unwrap().id() as i32
    }

    /// SIGKILL H only. Its workers learn from the EOF on their own sockets.
    async fn kill_helper(&self) {
        let mut child = self.child.lock().unwrap().take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        let _ = std::fs::remove_file(self.root.join("helper.sock"));
    }

    fn fault(&self, name: &str) {
        std::fs::write(self.root.join("faults").join(name), b"").unwrap();
    }

    fn clear(&self, name: &str) {
        let _ = std::fs::remove_file(self.root.join("faults").join(name));
    }

    fn reached(&self, name: &str) -> bool {
        self.root
            .join("faults")
            .join(format!("{name}.reached"))
            .exists()
    }

    async fn wait_reached(&self, name: &str) {
        wait_until(name, || self.reached(name)).await;
    }

    async fn census(&self) -> Value {
        let mut stream = UnixStream::connect(self.root.join("control.sock"))
            .await
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let census: Value = serde_json::from_slice(&bytes).unwrap();
        let mut seen = self.seen.lock().unwrap();
        for pid in all_census_pids(&census) {
            seen.push(pid);
        }
        census
    }

    fn runtime(&self, instance: Id128, database: Id128) -> Arc<FirecrackerRuntime> {
        Arc::new(FirecrackerRuntime::with_helper_uid(
            self.root.join("helper.sock"),
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() },
            instance,
            database,
        ))
    }

    /// A query-only view for assertions; the ledger's writer stays L alone. SQLite's
    /// read-only open can spin on the WAL index while a writer transaction is open.
    fn ledger_view(&self) -> rusqlite::Connection {
        let view = rusqlite::Connection::open_with_flags(
            self.root.join("ledger/node.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .unwrap();
        view.pragma_update(None, "query_only", "ON").unwrap();
        view
    }

    /// SQLite can briefly report a locking-protocol error to a read-only connection
    /// racing the writer's WAL index; that says nothing about this view's content.
    fn read<T>(&self, query: impl Fn(&rusqlite::Connection) -> rusqlite::Result<T>) -> T {
        let mut attempts = 0;
        loop {
            match query(&self.ledger_view()) {
                Ok(value) => return value,
                Err(error) if attempts < 200 => {
                    attempts += 1;
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("ledger view: {error}"),
            }
        }
    }

    fn count(&self, sql: &str) -> i64 {
        self.read(|view| view.query_row(sql, [], |r| r.get(0)))
    }

    fn retired_receipt(&self, allocation: Id128) -> Option<Vec<u8>> {
        use rusqlite::OptionalExtension;
        self.read(|view| {
            view.query_row(
                "SELECT receipt FROM retired_tokens WHERE allocation_id = ?1",
                [allocation.to_string()],
                |r| r.get(0),
            )
            .optional()
        })
    }

    fn active_allocations(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM allocations WHERE phase != 'absent'")
    }

    fn fake_dir(&self, context: &CreateContext) -> PathBuf {
        fake::allocation_dir(
            &self.root.join("fake"),
            context.instance_id,
            context.allocation_id,
        )
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.root.join("child.log")).unwrap_or_default()
    }
}

fn all_census_pids(census: &Value) -> Vec<i32> {
    let mut pids = vec![
        census["ledger"].as_i64().unwrap_or(0) as i32,
        census["monitor"].as_i64().unwrap_or(0) as i32,
    ];
    for key in ["prep", "recovery"] {
        for pid in census[key].as_array().into_iter().flatten() {
            pids.push(pid.as_i64().unwrap_or(0) as i32);
        }
    }
    for entry in census["supervisors"].as_object().into_iter().flatten() {
        pids.push(entry.1["pid"].as_i64().unwrap_or(0) as i32);
        if let Some(vm) = entry.1["vm"].as_i64() {
            pids.push(vm as i32);
        }
    }
    pids.retain(|pid| *pid > 1);
    pids
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("--- helper fixture log ---\n{}", self.log());
            if let Ok(peers) = std::fs::read_to_string(self.root.join("peer.log")) {
                eprintln!("--- peer log ---\n{peers}");
            }
        }
        // Clear every stall first, so nothing outlives this fixture.
        let _ = std::fs::remove_dir_all(self.root.join("faults"));
        let _ = std::fs::remove_dir_all(self.root.join("fake"));
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for pid in self.seen.lock().unwrap().drain(..) {
            // SAFETY: only pids this fixture's own census named; stopped ones need the
            // continue before a kill can be delivered and acted on.
            unsafe {
                libc::kill(pid, libc::SIGCONT);
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let _ = &self.temp;
    }
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(std::time::Instant::now() < end, "timed out waiting: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

fn no_cancel() -> CancellationToken {
    CancellationToken::new()
}

fn spec() -> SandboxSpec {
    SandboxSpec {
        image: "alpine".into(),
        memory_bytes: 512 * MIB,
        cpu_millis: 1000,
        pids: 128,
        disk_bytes: 1 << 30,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: BTreeMap::new(),
    }
}

fn token(instance: Id128) -> CreateContext {
    CreateContext {
        instance_id: instance,
        allocation_id: Id128::random(),
        sandbox_id: new_id("sb"),
    }
}

async fn prepared(runtime: &FirecrackerRuntime, context: &CreateContext) -> PreparedCreate {
    runtime
        .prepare(context, &spec(), deadline(10), &no_cancel())
        .await
        .unwrap()
}

async fn epoch_of(runtime: &FirecrackerRuntime) -> Id128 {
    runtime.test_epoch(deadline(5)).await.unwrap()
}

/// One real v3 frame with an arbitrary wire deadline, including one already past.
async fn raw_call(
    fixture: &Fixture,
    instance: Id128,
    epoch: Option<Id128>,
    operation: FirecrackerOperation,
    deadline_ns: u64,
    timeout_ms: u32,
) -> std::io::Result<FirecrackerResponse> {
    let request = Request {
        version: VERSION,
        timeout_ms,
        deadline_ns,
        operation: Operation::Firecracker(FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: instance,
            connection_epoch: epoch,
            operation,
        }),
    };
    let mut stream = UnixStream::connect(fixture.root.join("helper.sock")).await?;
    fds::send(&stream, &[]).await?;
    write_frame(&mut stream, &request).await?;
    assert!(
        fds::receive(&stream).await?.is_empty(),
        "no descriptors cross"
    );
    match read_frame::<Response>(&mut stream).await? {
        Response::Firecracker(response) => Ok(response),
        other => Err(std::io::Error::other(format!(
            "not a group reply: {other:?}"
        ))),
    }
}

fn create_operation(context: &CreateContext, plan: &PreparedCreate) -> FirecrackerOperation {
    FirecrackerOperation::Create {
        allocation_id: context.allocation_id,
        sandbox_id: context.sandbox_id.clone(),
        plan: WireBytes(plan.backend_plan().to_vec()),
        plan_digest: plan.plan_digest(),
    }
}

fn wire_deadline(seconds: u64) -> u64 {
    crate::helper::monotonic_ns().unwrap() + seconds * 1_000_000_000
}

async fn raw_create(
    fixture: &Fixture,
    context: &CreateContext,
    epoch: Id128,
    plan: &PreparedCreate,
) -> CreateReply {
    match raw_call(
        fixture,
        context.instance_id,
        Some(epoch),
        create_operation(context, plan),
        wire_deadline(25),
        25_000,
    )
    .await
    .unwrap()
    {
        FirecrackerResponse::Create(reply) => reply,
        other => panic!("{other:?}"),
    }
}

async fn create_accepted(
    fixture: &Fixture,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> u64 {
    match raw_create(fixture, context, epoch_of(runtime).await, plan).await {
        CreateReply::Accepted { generation, .. } => generation,
        other => panic!("not accepted: {other:?}"),
    }
}

fn class_of(reply: &CreateReply) -> AmbiguousClass {
    match reply {
        CreateReply::Ambiguous { class, .. } => *class,
        other => panic!("not ambiguous: {other:?}"),
    }
}

fn receipt_of(reply: &CreateReply) -> Vec<u8> {
    match reply {
        CreateReply::Absent { receipt } => receipt.0.clone(),
        other => panic!("not absent: {other:?}"),
    }
}

fn fenced(receipt: AbsenceReceipt) -> FencedAbsence {
    match receipt {
        AbsenceReceipt::Fenced(receipt) => receipt,
        other => panic!("{other:?}"),
    }
}

/// C1 for this token: the exact row the manager commits, through the same Store API.
fn c1_row(store: &Store, context: &CreateContext, plan: &PreparedCreate) -> Sandbox {
    let now = now_ms();
    let row = Sandbox {
        id: context.sandbox_id.clone(),
        state: SandboxState::Creating,
        spec: plan.spec().clone(),
        backend: "firecracker".into(),
        backend_id: None,
        created_at_ms: now,
        updated_at_ms: now,
        deleted_at_ms: None,
        failure_reason: None,
        create_certainty: CreateCertainty::AllocationAmbiguous,
        owner_uid: 0,
        accounting: SandboxAccounting {
            regime: AccountingRegime::AbsenceFenced,
            reservation: plan.reservation(),
            host_spec_sha256: plan.host_spec_sha256(),
            guest_exec_spec_sha256: plan.guest_exec_spec_sha256(),
            runtime_profile: plan.runtime_profile().into(),
            runtime_artifact_digest: plan.runtime_artifact_digest().into(),
            allocation: plan.binding(context),
            boot_id: None,
            disposition: SandboxDisposition::Reusable,
            release: ReservationRelease::Charged,
            last_helper_generation: Some(0),
        },
    };
    let budgets = SandboxBudgets {
        sandboxes: 64,
        memory_bytes: u64::MAX,
        pids: u64::MAX,
        disk_bytes: u64::MAX,
        host_cpu_millis: u64::MAX,
        virtual_cpu_slots: u64::MAX,
        host_pids: u64::MAX,
    };
    assert!(matches!(
        store.reserve_sandbox(&row, budgets).unwrap(),
        ReserveSandbox::Inserted
    ));
    row
}

fn charged(store: &Store) -> u64 {
    store.sandbox_resources().unwrap().sandboxes
}

async fn node_totals(runtime: &FirecrackerRuntime) -> super::journal::AccountingSnapshot {
    runtime
        .node_accounting(deadline(5), &no_cancel())
        .await
        .unwrap()
}

/// The classes of section 4.5 and 10.1. Each sets up a real cause, makes the token's
/// Create reject for that cause and later removes the cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Collision,
    Catalog,
    Expired,
    PrepPanic,
    LedgerPanic,
    Capacity,
    LostReply,
    OldEpoch,
}

struct Cause {
    /// The other allocation holding the contested resource, fenced to clear the cause.
    holder: Option<(CreateContext, PreparedCreate)>,
    /// The installed tree moved aside for the catalog class.
    parked: Option<(PathBuf, PathBuf)>,
    /// What queued duplicates carry: the old epoch for that class.
    duplicate_epoch: Id128,
}

async fn trigger(
    class: Class,
    fixture: &Fixture,
    runtime: &Arc<FirecrackerRuntime>,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> Cause {
    let epoch = epoch_of(runtime).await;
    let mut cause = Cause {
        holder: None,
        parked: None,
        duplicate_epoch: epoch,
    };
    let reply = match class {
        Class::Collision | Class::Capacity => {
            // Prepared before the holder's claim, so its plan really names what the
            // holder takes; the helper must refuse rather than substitute.
            let holder = token(context.instance_id);
            let holder_plan = prepared(runtime, &holder).await;
            create_accepted(fixture, runtime, &holder, &holder_plan).await;
            cause.holder = Some((holder, holder_plan));
            raw_create(fixture, context, epoch, plan).await
        }
        Class::Catalog => {
            let directory = fixture
                .root
                .join("exec/sha256")
                .join(pin_of(Role::Firecracker).sha256.to_string());
            let parked = fixture.root.join("parked-exec");
            std::fs::rename(&directory, &parked).unwrap();
            cause.parked = Some((parked, directory));
            raw_create(fixture, context, epoch, plan).await
        }
        Class::Expired => {
            let past = crate::helper::monotonic_ns().unwrap() - 1_000_000_000;
            match raw_call(
                fixture,
                context.instance_id,
                Some(epoch),
                create_operation(context, plan),
                past,
                1_000,
            )
            .await
            .unwrap()
            {
                FirecrackerResponse::Create(reply) => reply,
                other => panic!("{other:?}"),
            }
        }
        Class::PrepPanic => {
            fixture.fault("P.revalidate.panic");
            let reply = raw_create(fixture, context, epoch, plan).await;
            fixture.clear("P.revalidate.panic");
            reply
        }
        Class::LedgerPanic => {
            fixture.fault("L.admit.panic");
            let reply = raw_create(fixture, context, epoch, plan).await;
            fixture.clear("L.admit.panic");
            // Exit, reap, then the same fixed slot restarts and reopens the ledger.
            let live = fixture.census().await["ledger"].clone();
            let mut replaced = false;
            for _ in 0..1500 {
                let census = fixture.census().await;
                if census["ledger"] != live || runtime_ledger_healthy(runtime).await {
                    replaced = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                replaced,
                "the ledger slot did not restart after a real exit"
            );
            reply
        }
        Class::LostReply => {
            // The transaction commits and L stops before replying: the waiter times
            // out with no evidence, and the claim is durable all the same.
            fixture.fault("L.admit.after_commit.stall");
            let reply = match raw_call(
                fixture,
                context.instance_id,
                Some(epoch),
                create_operation(context, plan),
                wire_deadline(1),
                1_000,
            )
            .await
            .unwrap()
            {
                FirecrackerResponse::Create(reply) => reply,
                other => panic!("{other:?}"),
            };
            assert_eq!(class_of(&reply), AmbiguousClass::Pending);
            fixture.wait_reached("L.admit.after_commit").await;
            assert_eq!(
                fixture.active_allocations(),
                1,
                "the commit survived its lost reply"
            );
            fixture.clear("L.admit.after_commit.stall");
            // Retrying the exact token finds that claim and makes no second one.
            let replay = raw_create(fixture, context, epoch, plan).await;
            match &replay {
                CreateReply::Accepted { replay: true, .. } => {}
                other => panic!("{other:?}"),
            }
            assert_eq!(fixture.active_allocations(), 1);
            assert_eq!(node_totals(runtime).await.claimed.slots, 1);
            reply
        }
        Class::OldEpoch => {
            // Replaced after the Preflight: a real new attachment, a real old epoch.
            let reply = raw_create_after_replacement(fixture, runtime, context, plan, epoch).await;
            cause.duplicate_epoch = epoch;
            reply
        }
    };
    match class {
        Class::Collision => assert_eq!(class_of(&reply), AmbiguousClass::Collision),
        Class::Catalog => assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch),
        Class::Expired => assert_eq!(class_of(&reply), AmbiguousClass::Expired),
        Class::PrepPanic | Class::LedgerPanic => {
            assert_eq!(class_of(&reply), AmbiguousClass::WorkerPanic)
        }
        Class::Capacity => assert_eq!(class_of(&reply), AmbiguousClass::Capacity),
        Class::LostReply => assert_eq!(class_of(&reply), AmbiguousClass::Pending),
        Class::OldEpoch => assert_eq!(class_of(&reply), AmbiguousClass::OldEpoch),
    }
    cause
}

async fn raw_create_after_replacement(
    fixture: &Fixture,
    runtime: &Arc<FirecrackerRuntime>,
    context: &CreateContext,
    plan: &PreparedCreate,
    old_epoch: Id128,
) -> CreateReply {
    runtime.test_reattach().await;
    wait_until_attached(runtime).await;
    assert_ne!(epoch_of(runtime).await, old_epoch);
    raw_create(fixture, context, old_epoch, plan).await
}

async fn wait_until_attached(runtime: &FirecrackerRuntime) {
    for _ in 0..2000 {
        if runtime.test_epoch(deadline(2)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the namespace was not released after the holder detached");
}

async fn runtime_ledger_healthy(runtime: &FirecrackerRuntime) -> bool {
    runtime
        .node_accounting(Instant::now() + Duration::from_millis(200), &no_cancel())
        .await
        .is_ok()
}

async fn clear_cause(runtime: &Arc<FirecrackerRuntime>, cause: Cause) {
    if let Some((parked, directory)) = cause.parked {
        std::fs::rename(parked, directory).unwrap();
    }
    if let Some((holder, plan)) = cause.holder {
        // Clearing the contested identity or capacity takes that holder's own fence.
        fenced(
            runtime
                .fence_absent(&holder, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
}

fn options_for(class: Class) -> NodeOptions {
    let mut options = NodeOptions::default();
    match class {
        // One CID in range: both plans must name it, so C2 is the first to know.
        Class::Collision => options.cid = (3, 3),
        // One slot: a second plan always prepares, then always fails C2.
        Class::Capacity => options.ceilings.slots = 1,
        _ => {}
    }
    options
}

/// Section 10.1's forced race for one class: reject, publish charged FAILED, pause the
/// ABSENT sync, queue two identical Creates, make the fence durable, remove the cause,
/// release the duplicates. Both must return the same fence and create no resources.
async fn post_c1_race(class: Class) {
    let fixture = Fixture::new(options_for(class)).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let store = Store::open_in_memory().unwrap();
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let digest = plan.plan_digest();
    let row = c1_row(&store, &context, &plan);
    assert_eq!(charged(&store), 1, "C1 charged it");
    let cause = trigger(class, &fixture, &runtime, &context, &plan).await;

    // The rejection stays charged and its row publishes as FAILED, not released.
    store
        .set_sandbox_state(
            &row.id,
            SandboxState::Failed,
            None,
            Some("rejected after C1"),
        )
        .unwrap();
    assert_eq!(charged(&store), 1);

    // Pause inside the fence's transaction, before COMMIT and its sync.
    fixture.fault("L.fence.before_commit.stall");
    let hold = format!("H.fence.after_commit.{}", context.allocation_id);
    fixture.fault(&format!("{hold}.hold"));
    let fencing = {
        let (runtime, context) = (runtime.clone(), context.clone());
        tokio::spawn(async move {
            runtime
                .fence_absent(&context, &digest, deadline(25), &no_cancel())
                .await
        })
    };
    fixture.wait_reached("L.fence.before_commit").await;
    assert!(fixture.retired_receipt(context.allocation_id).is_none());
    assert!(!fencing.is_finished());
    assert_eq!(
        charged(&store),
        1,
        "failure publication stays charged during the pause"
    );

    // Two identical Creates queue behind this token's serialization.
    let duplicates: Vec<_> = (0..2)
        .map(|_| {
            let (root, config) = (fixture.root.clone(), context.clone());
            let operation = create_operation(&config, &plan);
            let epoch = cause.duplicate_epoch;
            tokio::spawn(async move { raw_at(&root, config.instance_id, epoch, operation).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(duplicates.iter().all(|handle| !handle.is_finished()));

    // The fence commits. It is durable, yet the serialized holder has not answered.
    fixture.clear("L.fence.before_commit.stall");
    fixture.wait_reached(&hold).await;
    let durable = fixture
        .retired_receipt(context.allocation_id)
        .expect("the fence committed");
    let receipt = FencedAbsence::decode(&durable).unwrap();
    assert_eq!(receipt.plan_digest(), digest);
    assert!(receipt.helper_generation() > 0);
    assert_eq!(
        charged(&store),
        1,
        "the daemon holds its charge until it commits too"
    );
    assert!(duplicates.iter().all(|handle| !handle.is_finished()));

    // The cause goes away only now, and nothing about the token reopens.
    clear_cause(&runtime, cause).await;
    fixture.clear(&format!("{hold}.hold"));

    let fence = fenced(fencing.await.unwrap().unwrap());
    assert_eq!(fence.encode().unwrap(), durable);
    for handle in duplicates {
        assert_eq!(
            receipt_of(&handle.await.unwrap()),
            durable,
            "a queued duplicate returns the same fence"
        );
    }
    // A later one, with a healthy cause-free node, also gets exactly those bytes.
    let late = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
    assert_eq!(receipt_of(&late), durable);
    store
        .release_fenced(&row.id, SandboxState::Failed, &fence, None)
        .unwrap();
    assert_eq!(
        charged(&store),
        0,
        "only the exact receipt released the C1 charge"
    );

    // No session resources exist, and no claim or supervisor survives for this token.
    assert!(!fixture.fake_dir(&context).exists());
    let census = fixture.census().await;
    assert!(census["supervisors"][context.allocation_id.to_string()].is_null());
    assert_eq!(fixture.active_allocations(), 0);
    let totals = node_totals(&runtime).await;
    assert_eq!(totals.claimed, Default::default());
    let inspected = runtime
        .inspect_allocation(&context, &digest, deadline(5), &no_cancel())
        .await
        .unwrap();
    assert_eq!(
        inspected,
        AllocationObservation::AbsentFenced(FencedAbsence::decode(&durable).unwrap())
    );
}

async fn raw_at(
    root: &Path,
    instance: Id128,
    epoch: Id128,
    operation: FirecrackerOperation,
) -> CreateReply {
    let request = Request {
        version: VERSION,
        timeout_ms: 28_000,
        deadline_ns: wire_deadline(28),
        operation: Operation::Firecracker(FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: instance,
            connection_epoch: Some(epoch),
            operation,
        }),
    };
    let mut stream = UnixStream::connect(root.join("helper.sock")).await.unwrap();
    fds::send(&stream, &[]).await.unwrap();
    write_frame(&mut stream, &request).await.unwrap();
    assert!(fds::receive(&stream).await.unwrap().is_empty());
    match read_frame::<Response>(&mut stream).await.unwrap() {
        Response::Firecracker(FirecrackerResponse::Create(reply)) => reply,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn exit2_collision_race_returns_one_fence_and_creates_nothing() {
    post_c1_race(Class::Collision).await;
}

#[tokio::test]
async fn exit2_catalog_mismatch_race_returns_one_fence_after_restoration() {
    post_c1_race(Class::Catalog).await;
}

#[tokio::test]
async fn exit2_expired_request_race_returns_one_fence() {
    post_c1_race(Class::Expired).await;
}

#[tokio::test]
async fn exit2_preparation_panic_race_returns_one_fence() {
    post_c1_race(Class::PrepPanic).await;
}

#[tokio::test]
async fn exit2_ledger_panic_race_returns_one_fence() {
    post_c1_race(Class::LedgerPanic).await;
}

#[tokio::test]
async fn exit2_capacity_exhaustion_race_returns_one_fence() {
    post_c1_race(Class::Capacity).await;
}

#[tokio::test]
async fn exit2_lost_capacity_reply_race_keeps_one_claim_then_one_fence() {
    post_c1_race(Class::LostReply).await;
}

#[tokio::test]
async fn exit2_old_epoch_race_returns_one_fence_to_old_and_new_callers() {
    post_c1_race(Class::OldEpoch).await;
}

/// Waits until H has really retired this epoch: its next use answers StaleEpoch.
async fn wait_epoch_retired(fixture: &Fixture, instance: Id128, epoch: Id128) {
    for _ in 0..2000 {
        let reply = raw_call(
            fixture,
            instance,
            Some(epoch),
            FirecrackerOperation::Capabilities,
            wire_deadline(1),
            1_000,
        )
        .await
        .unwrap();
        if matches!(
            reply,
            FirecrackerResponse::Error(GroupError {
                kind: GroupErrorKind::StaleEpoch,
                ..
            })
        ) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the detach did not retire the epoch");
}

#[tokio::test]
async fn exit2_old_epoch_revoked_during_revalidate_cannot_cross_c2() {
    // The same namespace comes back owned by a different database while P is stuck: the
    // old request must not be able to use that attachment's admission, closed or open.
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let epoch = epoch_of(&runtime).await;
    fixture.fault("P.revalidate.stall");
    let creating = {
        let (root, operation) = (fixture.root.clone(), create_operation(&context, &plan));
        tokio::spawn(async move { raw_at(&root, instance, epoch, operation).await })
    };
    fixture.wait_reached("P.revalidate").await;
    runtime.test_reattach().await;
    wait_epoch_retired(&fixture, instance, epoch).await;
    let restored = fixture.runtime(instance, Id128::random());
    wait_until_attached(&restored).await;
    fixture.clear("P.revalidate.stall");
    assert_eq!(class_of(&creating.await.unwrap()), AmbiguousClass::OldEpoch);
    assert_eq!(fixture.active_allocations(), 0);
    assert!(fixture.census().await["supervisors"][context.allocation_id.to_string()].is_null());
    assert!(!fixture.fake_dir(&context).exists());
    // A request sent under that closed attachment's own epoch is refused as well.
    let reply = raw_create(&fixture, &token(instance), epoch_of(&restored).await, &plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::AdmissionBlocked);
    // The real owner comes back, and the rejected token is still its to fence.
    restored.test_reattach().await;
    let owner = fixture.runtime(instance, database);
    wait_until_attached(&owner).await;
    fenced(
        owner
            .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn exit2_old_epoch_revoked_while_queued_in_the_ledger_cannot_cross_c2() {
    // Queued before the transaction, and inside it right up to COMMIT. H retires the epoch
    // with no help from the stuck L, and L sees that at its commit point.
    for stall in ["L.admit", "L.admit.before_commit"] {
        let fixture = Fixture::new(NodeOptions {
            effects: vec!["vm".into()],
            ..NodeOptions::default()
        })
        .await;
        let instance = Id128::random();
        let database = Id128::random();
        let runtime = fixture.runtime(instance, database);
        let context = token(instance);
        let plan = prepared(&runtime, &context).await;
        let epoch = epoch_of(&runtime).await;
        fixture.fault(&format!("{stall}.stall"));
        let creating = {
            let (root, operation) = (fixture.root.clone(), create_operation(&context, &plan));
            tokio::spawn(async move { raw_at(&root, instance, epoch, operation).await })
        };
        fixture.wait_reached(stall).await;
        runtime.test_reattach().await;
        wait_epoch_retired(&fixture, instance, epoch).await;
        fixture.clear(&format!("{stall}.stall"));
        assert_eq!(
            class_of(&creating.await.unwrap()),
            AmbiguousClass::OldEpoch,
            "{stall}"
        );
        assert_eq!(fixture.active_allocations(), 0, "{stall}");
        assert_eq!(
            fixture.count("SELECT COUNT(*) FROM capacity_claims"),
            0,
            "{stall}"
        );
        assert!(!fixture.fake_dir(&context).exists(), "{stall}");
        let owner = fixture.runtime(instance, database);
        wait_until_attached(&owner).await;
        fenced(
            owner
                .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn exit2_old_epoch_revoked_as_c2_commits_holds_the_claim_with_no_effects() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let epoch = epoch_of(&runtime).await;
    // The commit already happened, so only H's recheck stands between it and an S.
    fixture.fault("L.admit.after_commit.stall");
    let creating = {
        let (root, operation) = (fixture.root.clone(), create_operation(&context, &plan));
        tokio::spawn(async move { raw_at(&root, instance, epoch, operation).await })
    };
    fixture.wait_reached("L.admit.after_commit").await;
    runtime.test_reattach().await;
    wait_epoch_retired(&fixture, instance, epoch).await;
    fixture.clear("L.admit.after_commit.stall");
    assert_eq!(class_of(&creating.await.unwrap()), AmbiguousClass::OldEpoch);
    assert_eq!(fixture.active_allocations(), 1, "the claim stays held");
    assert!(fixture.census().await["supervisors"][context.allocation_id.to_string()].is_null());
    assert!(!fixture.fake_dir(&context).exists());
    // Compensation goes through the ordinary exact fence.
    let owner = fixture.runtime(instance, database);
    wait_until_attached(&owner).await;
    assert_eq!(node_totals(&owner).await.claimed.slots, 1);
    fenced(
        owner
            .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(node_totals(&owner).await.claimed.slots, 0);
}

#[tokio::test]
async fn exit2_real_manager_publishes_charged_failure_and_only_a_fence_releases_it() {
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
    let holder = token(other);
    let holder_plan = prepared(&holder_runtime, &holder).await;
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
    // The node ledger refuses, then its durable commit fails. The manager must leave
    // a visibly FAILED charged row and return no success.
    fixture.fault("L.fence.sync_fail");
    let request = CreateRequest {
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
    let error = manager.create(request).await.unwrap_err();
    assert!(error.to_string().contains("Capacity"), "{error}");
    let rows = manager.list(true).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.is_charged(), "no ABSENT receipt, so it stays charged");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    // Cause cleared and sync restored: Delete uses the exact token and receipt.
    fixture.clear("L.fence.sync_fail");
    let deleted = manager.delete(&row.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert!(!deleted.is_charged());
    match deleted.accounting.release {
        ReservationRelease::Fenced(receipt) => {
            assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 1);
            assert_eq!(
                fixture.count(&format!(
                    "SELECT COUNT(*) FROM retired_tokens WHERE receipt_id = '{receipt}'"
                )),
                1
            );
        }
        other => panic!("{other:?}"),
    }
    // The other namespace's claim did not move through any of that.
    assert_eq!(node_totals(&holder_runtime).await.claimed.slots, 1);
}

#[tokio::test]
async fn exit2_a_queued_fence_cannot_release_while_a_create_holds_the_token() {
    // The opposite order of the race: Create is inside C2 when the fence arrives.
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    fixture.fault("L.admit.stall");
    let epoch = epoch_of(&runtime).await;
    let creating = {
        let (root, context) = (fixture.root.clone(), context.clone());
        let operation = create_operation(&context, &plan);
        tokio::spawn(async move { raw_at(&root, context.instance_id, epoch, operation).await })
    };
    fixture.wait_reached("L.admit").await;
    // The fence waits on this token's serialization and answers honestly at deadline.
    let short = Instant::now() + Duration::from_millis(400);
    let error = runtime
        .fence_absent(&context, &plan.plan_digest(), short, &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("charged"), "{error}");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    fixture.clear("L.admit.stall");
    assert!(matches!(
        creating.await.unwrap(),
        CreateReply::Accepted { .. }
    ));
    // That expired attempt had no authority left once it got the lock: it did nothing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    assert_eq!(fixture.active_allocations(), 1);
    fenced(
        runtime
            .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(fixture.active_allocations(), 0);
    let replay = raw_create(&fixture, &context, epoch, &plan).await;
    assert_eq!(
        receipt_of(&replay),
        fixture.retired_receipt(context.allocation_id).unwrap()
    );
}

#[tokio::test]
async fn exit3_race_of_four_across_two_instances_gives_three_intents_and_one_absent() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let (first, second) = (Id128::random(), Id128::random());
    let runtimes = [
        fixture.runtime(first, Id128::random()),
        fixture.runtime(second, Id128::random()),
    ];
    let mut tokens = Vec::new();
    for index in 0..4usize {
        let runtime = runtimes[index % 2].clone();
        let context = token(runtime_instance(index, first, second));
        let plan = prepared(&runtime, &context).await;
        tokens.push((runtime, context, plan));
    }
    let root = fixture.root.clone();
    let mut racers = Vec::new();
    for (runtime, context, plan) in &tokens {
        let epoch = epoch_of(runtime).await;
        let (root, context, operation) = (
            root.clone(),
            context.clone(),
            create_operation(context, plan),
        );
        racers.push(tokio::spawn(async move {
            raw_at(&root, context.instance_id, epoch, operation).await
        }));
    }
    let mut accepted = 0;
    let mut refused = Vec::new();
    for (index, racer) in racers.into_iter().enumerate() {
        match racer.await.unwrap() {
            CreateReply::Accepted { .. } => accepted += 1,
            reply => {
                assert_eq!(class_of(&reply), AmbiguousClass::Capacity);
                refused.push(index);
            }
        }
    }
    assert_eq!(accepted, 3, "exactly three of four reach INTENT");
    assert_eq!(refused.len(), 1);
    assert_eq!(fixture.active_allocations(), 3);
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM capacity_claims WHERE released_generation IS NULL"),
        3
    );
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM identity_leases WHERE released_generation IS NULL"),
        15,
        "five identities each"
    );
    let totals = node_totals(&runtimes[0]).await;
    assert_eq!(totals.committed.memory_bytes, 3 * 896 * MIB + 128 * MIB);
    assert_eq!(totals.committed.virtual_cpu_slots, 3);
    assert!(!totals.over_committed);
    // The refused token holds no claim, and gets a durable ABSENT rather than release.
    let (runtime, context, plan) = &tokens[refused[0]];
    let fence = fenced(
        runtime
            .fence_absent(context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(fence.allocation_id(), context.allocation_id);
    assert_eq!(
        fixture.retired_receipt(context.allocation_id).unwrap(),
        fence.encode().unwrap()
    );
    assert_eq!(node_totals(runtime).await.claimed.slots, 3);
    // Node totals are global, but no record of the other instance is visible here.
    for (runtime, _, _) in &tokens[..2] {
        let listed = runtime.list(deadline(10), &no_cancel()).await.unwrap();
        assert!(listed.records.len() <= 2);
        for record in &listed.records {
            assert!(tokens.iter().any(|(owner, context, _)| {
                Arc::ptr_eq(owner, runtime) && Some(context.allocation_id) == record.allocation_id
            }));
        }
    }
}

fn runtime_instance(index: usize, first: Id128, second: Id128) -> Id128 {
    [first, second][index % 2]
}

#[tokio::test]
async fn exit3_one_live_holder_per_namespace_and_epochs_die_with_their_holder() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let database = Id128::random();
    let holder = fixture.runtime(instance, database);
    let epoch = epoch_of(&holder).await;
    // A second live attachment can't take this namespace, even from the enrolled
    // service. A process that isn't that service is refused outright: see control_plane.
    let successor = fixture.runtime(instance, database);
    let refused = successor
        .version(deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("live holder"), "{refused}");
    // An epoch from a wrong or missing value never authorizes anything.
    let wrong = raw_call(
        &fixture,
        instance,
        Some(Id128::random()),
        FirecrackerOperation::Accounting,
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        wrong,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::StaleEpoch,
            ..
        })
    ));
    // An attached namespace's epoch on another namespace is stale too.
    let elsewhere = raw_call(
        &fixture,
        Id128::random(),
        Some(epoch),
        FirecrackerOperation::Accounting,
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        elsewhere,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::StaleEpoch,
            ..
        })
    ));
    let context = token(instance);
    let plan = prepared(&holder, &context).await;
    create_accepted(&fixture, &holder, &context, &plan).await;
    // Detach invalidates the epoch; ledger-owned work and its claim remain.
    holder.test_reattach().await;
    let after = successor.test_epoch(deadline(5)).await;
    let replacement = match after {
        Ok(epoch) => epoch,
        Err(_) => {
            wait_until_attached(&successor).await;
            epoch_of(&successor).await
        }
    };
    assert_ne!(replacement, epoch);
    let stale = raw_call(
        &fixture,
        instance,
        Some(epoch),
        FirecrackerOperation::Accounting,
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        stale,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::StaleEpoch,
            ..
        })
    ));
    assert_eq!(node_totals(&successor).await.claimed.slots, 1);
    assert_eq!(fixture.active_allocations(), 1);
    // Reattaching does not clear or adopt: the same token still answers identically.
    match raw_create(&fixture, &context, replacement, &plan).await {
        CreateReply::Accepted { replay: true, .. } => {}
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn exit3_helper_restart_invalidates_epochs_and_replays_every_claim() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let generation = create_accepted(&fixture, &runtime, &context, &plan).await;
    let epoch = epoch_of(&runtime).await;
    fixture.kill_helper().await;
    // The persistent lock frees when its inherited holders notice and exit.
    fixture.start().await;
    wait_until("no start error", || {
        !fixture.root.join("start-error").exists()
    })
    .await;
    let stale = raw_call(
        &fixture,
        instance,
        Some(epoch),
        FirecrackerOperation::Accounting,
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        stale,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::StaleEpoch,
            ..
        })
    ));
    let renewed = fixture.runtime(instance, database);
    let totals = node_totals(&renewed).await;
    assert_eq!(
        totals.claimed.slots, 1,
        "a restart replays claims before serving"
    );
    assert!(totals.generation >= generation);
    let replacement = epoch_of(&renewed).await;
    match raw_create(&fixture, &context, replacement, &plan).await {
        CreateReply::Accepted { replay: true, .. } => {}
        other => panic!("{other:?}"),
    }
    // A worker from the old helper settled, so this fence can complete now.
    let fence = fenced(
        renewed
            .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(fence.instance_id(), instance);
    assert_eq!(node_totals(&renewed).await.claimed.slots, 0);
}

#[tokio::test]
async fn exit3_second_helper_is_refused_by_the_persistent_node_lock() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let first = fixture.helper_pid();
    // A second helper on this exact ledger, with its own listener.
    fixture.spawn_helper();
    wait_until("the second helper's lock failure", || {
        fixture.root.join("start-error").exists()
    })
    .await;
    let reason = std::fs::read_to_string(fixture.root.join("start-error")).unwrap();
    assert!(reason.contains("already owned"), "{reason}");
    // The first helper's L still owns the ledger.
    // SAFETY: only this fixture's process; signal 0 checks it is alive.
    assert_eq!(unsafe { libc::kill(first, 0) }, 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM node_identity"), 1);
    // SAFETY: stopping the first helper's process, which spawn_helper replaced in the
    // fixture's bookkeeping and so would otherwise be left running.
    unsafe { libc::kill(first, libc::SIGKILL) };
}

#[tokio::test]
async fn exit3_stale_or_restored_database_blocks_admission_and_leaves_claims() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    runtime.test_reattach().await;
    // The same namespace comes back claiming a new database: lost, restored or stale.
    let restored = fixture.runtime(instance, Id128::random());
    wait_until_attached(&restored).await;
    assert_eq!(
        node_totals(&restored).await.claimed.slots,
        1,
        "a lost DB discounts nothing"
    );
    let error = restored
        .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("another database"), "{error}");
    // It can read, but can neither take new work nor fence this token.
    assert!(
        restored
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    let reply = raw_create(&fixture, &context, epoch_of(&restored).await, &plan).await;
    assert!(matches!(reply, CreateReply::Accepted { replay: true, .. }));
    let new_token = token(instance);
    let reply = raw_create(&fixture, &new_token, epoch_of(&restored).await, &plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::AdmissionBlocked);
    assert_eq!(fixture.active_allocations(), 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    assert!(restored.list(deadline(10), &no_cancel()).await.is_ok());
}

async fn timed_capabilities(runtime: &FirecrackerRuntime, fixture: &Fixture) -> CapabilitiesReply {
    let epoch = epoch_of(runtime).await;
    let began = std::time::Instant::now();
    let reply = raw_call(
        fixture,
        runtime_id(runtime),
        Some(epoch),
        FirecrackerOperation::Capabilities,
        wire_deadline(2),
        2_000,
    )
    .await
    .unwrap();
    assert!(
        began.elapsed() < Duration::from_millis(900),
        "H stalled: {:?}",
        began.elapsed()
    );
    match reply {
        FirecrackerResponse::Capabilities(reply) => reply,
        other => panic!("{other:?}"),
    }
}

fn runtime_id(runtime: &FirecrackerRuntime) -> Id128 {
    runtime.test_instance()
}

fn stalled(reply: &CapabilitiesReply, class: fn(&WorkersHealth) -> WorkerHealth) -> WorkerHealth {
    class(reply.health.as_ref().unwrap())
}

#[tokio::test]
async fn exit4_ledger_sync_stall_leaves_h_responsive_and_every_durable_answer_honest() {
    let fixture = Fixture::new(NodeOptions {
        heartbeat_timeout_ms: 1000,
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let before = fixture.census().await;
    let epoch = epoch_of(&runtime).await;
    fixture.fault("L.admit.before_commit.stall");
    let creating = {
        let (root, context) = (fixture.root.clone(), context.clone());
        let operation = create_operation(&context, &plan);
        tokio::spawn(async move { raw_at(&root, context.instance_id, epoch, operation).await })
    };
    fixture.wait_reached("L.admit.before_commit").await;
    // Cached and in-memory answers need nothing from L.
    let reply = timed_capabilities(&runtime, &fixture).await;
    assert!(reply.enabled && !reply.launch_enabled);
    // Durable ones say what they can prove, and on time.
    let began = std::time::Instant::now();
    let inspected = runtime
        .inspect_allocation(
            &context,
            &plan.plan_digest(),
            Instant::now() + Duration::from_millis(400),
            &no_cancel(),
        )
        .await;
    assert!(began.elapsed() < Duration::from_millis(1500));
    assert!(
        matches!(
            &inspected,
            Ok(AllocationObservation::Unknown { .. }) | Err(RuntimeError::Backend(_))
        ),
        "{inspected:?}"
    );
    let accounting = runtime
        .node_accounting(Instant::now() + Duration::from_millis(400), &no_cancel())
        .await;
    assert!(accounting.is_err(), "no totals without a fresh ledger read");
    let fence = runtime
        .fence_absent(
            &context,
            &plan.plan_digest(),
            Instant::now() + Duration::from_millis(400),
            &no_cancel(),
        )
        .await;
    assert!(fence.is_err(), "a stalled ledger forbids any receipt");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    let mut seen_stalled = false;
    for _ in 0..500 {
        let reply = timed_capabilities(&runtime, &fixture).await;
        if stalled(&reply, |h| h.ledger) == WorkerHealth::Stalled {
            seen_stalled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        seen_stalled,
        "M reports L's missing heartbeat through cached health"
    );
    // No replacement took L's slot, whatever the wait.
    assert_eq!(fixture.census().await["ledger"], before["ledger"]);
    fixture.clear("L.admit.before_commit.stall");
    // The original work finishes, and ownership never moved.
    assert!(matches!(
        creating.await.unwrap(),
        CreateReply::Accepted { .. }
    ));
    assert_eq!(fixture.active_allocations(), 1);
}

#[tokio::test]
async fn exit4_full_preparation_slots_refuse_quickly_and_are_never_replaced() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let before = fixture.census().await;
    fixture.fault("P.preflight.stall");
    let mut stuck = Vec::new();
    for _ in 0..2 {
        let (runtime, context) = (runtime.clone(), token(instance));
        stuck.push(tokio::spawn(async move {
            runtime
                .prepare(
                    &context,
                    &spec(),
                    Instant::now() + Duration::from_millis(800),
                    &no_cancel(),
                )
                .await
        }));
    }
    fixture.wait_reached("P.preflight").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Both slots are busy: a third is refused at once, not queued or given a third P.
    let began = std::time::Instant::now();
    let error = runtime
        .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(began.elapsed() < Duration::from_millis(500));
    assert!(error.to_string().contains("preparation slot"), "{error}");
    let reply = timed_capabilities(&runtime, &fixture).await;
    let health = reply.health.unwrap();
    assert_eq!(health.preparation, [WorkerHealth::Busy, WorkerHealth::Busy]);
    // Waiters leave; the jobs stay owned and their slots stay occupied.
    for handle in stuck {
        assert!(handle.await.unwrap().is_err());
    }
    let error = runtime
        .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("preparation slot"), "{error}");
    let during = fixture.census().await;
    assert_eq!(
        during["prep"], before["prep"],
        "no replacement over the count"
    );
    // A recovery operation doesn't take a slot it has no claim on: K is untouched.
    assert_eq!(during["recovery"], before["recovery"]);
    // Inspect still answers because it needs no P.
    let context = token(instance);
    assert!(matches!(
        runtime
            .inspect_allocation(&context, &Digest::of(b"none"), deadline(5), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    // List reports inconclusive rather than complete without its worker.
    let listed = runtime.list(deadline(5), &no_cancel()).await.unwrap();
    assert!(!listed.complete);
    // Fresh progress only when those original processes finish.
    fixture.clear("P.preflight.stall");
    let mut progressed = false;
    for _ in 0..200 {
        if runtime
            .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
            .await
            .is_ok()
        {
            progressed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(progressed);
    assert_eq!(fixture.census().await["prep"], before["prep"]);
}

#[tokio::test]
async fn exit4_stuck_supervisor_keeps_its_permit_and_no_receipt_escapes_until_it_settles() {
    let fixture = Fixture::new(NodeOptions {
        heartbeat_timeout_ms: 1000,
        effects: vec!["vm".into(), "marker:work.xfs".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    fixture.fault("S.effect.work.xfs.stall");
    let (supervisor_pid, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    fixture.wait_reached("S.effect.work.xfs").await;
    let key = context.allocation_id.to_string();
    let supervisor = fixture.census().await["supervisors"][&key]["pid"].clone();
    assert_eq!(supervisor.as_i64(), Some(supervisor_pid));
    // Its heartbeat stops, which is an irrevocable stop of the running subtree, without
    // any help from S. S itself keeps its slot and its permit stays charged.
    wait_until("the stale S's subtree to be contained", || !alive(vm)).await;
    assert!(
        alive(supervisor_pid),
        "the stuck S is not killed or replaced"
    );
    let mut census = fixture.census().await;
    for _ in 0..500 {
        if census["supervisors"][&key]["stop_fenced"] == json!(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        census = fixture.census().await;
    }
    assert_eq!(census["supervisors"][&key]["stop_fenced"], json!(true));
    assert_eq!(census["supervisors"][&key]["pid"], supervisor);
    assert!(alive(supervisor_pid));
    // And fresh inspection is Unknown, never Present or absent.
    assert!(matches!(
        runtime
            .inspect_allocation(&context, &plan.plan_digest(), deadline(2), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    assert!(timed_capabilities(&runtime, &fixture).await.enabled);
    // Fence revokes, but the same stuck process still holds the permit.
    let error = runtime
        .fence_absent(
            &context,
            &plan.plan_digest(),
            Instant::now() + Duration::from_millis(600),
            &no_cancel(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("charged"), "{error}");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    let census = fixture.census().await;
    assert_eq!(
        census["supervisors"][&key]["pid"], supervisor,
        "S was not replaced"
    );
    assert!(census["supervisors"][&key]["exit"].is_null());
    assert_eq!(fixture.active_allocations(), 1);
    // S finishes its one in-progress effect and then honors the revoked permit: it
    // performs no later effect, and exit settles it.
    fixture.clear("S.effect.work.xfs.stall");
    wait_until("S to exit after its revoke", || {
        fixture.fake_dir(&context).join("work.xfs").exists()
    })
    .await;
    // Its real resource remains, so absence cannot be proved. It stays charged.
    let mut waited = None;
    for _ in 0..200 {
        match runtime
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
        {
            Err(error) if error.to_string().contains("ResourcesPresent") => {
                waited = Some(error);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            Ok(other) => panic!("fenced over a live resource: {other:?}"),
        }
    }
    assert!(
        waited.is_some(),
        "the fence must see the resource and refuse"
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    // Later cleanup (B4's Remove) would own this; removing it here proves the refusal
    // was the resource and that positive absence then lets the fence commit.
    std::fs::remove_dir_all(fixture.fake_dir(&context)).unwrap();
    let fence = fenced(
        runtime
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(fence.allocation_id(), context.allocation_id);
    assert_eq!(node_totals(&runtime).await.claimed.slots, 0);
}

fn signal(pid: i64, signal: libc::c_int) {
    // SAFETY: only pids this fixture's census reported for its own workers.
    assert_eq!(unsafe { libc::kill(pid as i32, signal) }, 0);
}

fn alive(pid: i64) -> bool {
    use super::workers::{ProcessState, process_state};
    matches!(process_state(pid as i32), ProcessState::Running { .. })
}

async fn started_vm(
    fixture: &Fixture,
    runtime: &Arc<FirecrackerRuntime>,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> (i64, i64) {
    create_accepted(fixture, runtime, context, plan).await;
    let key = context.allocation_id.to_string();
    let mut vm = None;
    for _ in 0..1000 {
        let census = fixture.census().await;
        let entry = &census["supervisors"][&key];
        if let (Some(pid), Some(supervisor)) = (entry["vm"].as_i64(), entry["pid"].as_i64()) {
            vm = Some((supervisor, pid));
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (supervisor, pid) = vm.expect("S started its fake VM subtree");
    assert!(alive(pid));
    // M must hold the precommitted target before an emergency can use it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (supervisor, pid)
}

#[tokio::test]
async fn exit4_emergency_stop_runs_with_ledger_blocked_and_no_durable_claim_escapes() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let (supervisor, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    let key = context.allocation_id.to_string();
    let before = fixture.census().await;
    fixture.fault("L.loop.stall");
    tokio::time::sleep(Duration::from_millis(200)).await;
    // S dies with H healthy and the ledger writer blocked: K acts on C2's authority.
    let began = std::time::Instant::now();
    signal(supervisor, libc::SIGKILL);
    wait_until("K to stop the owned subtree", || !alive(vm)).await;
    let elapsed = began.elapsed();
    // Well within a loaded CI host's headroom around section 4.4's 250 ms target.
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    // Everything durable is honest: nothing was recorded, nothing released.
    let census = fixture.census().await;
    assert_eq!(
        census["recovery"], before["recovery"],
        "no recovery replacement"
    );
    assert_eq!(census["supervisors"][&key]["stop_fenced"], json!(true));
    let inspected = runtime
        .inspect_allocation(
            &context,
            &plan.plan_digest(),
            Instant::now() + Duration::from_millis(400),
            &no_cancel(),
        )
        .await;
    assert!(
        matches!(
            &inspected,
            Ok(AllocationObservation::Unknown { .. }) | Err(RuntimeError::Backend(_))
        ),
        "{inspected:?}"
    );
    assert!(
        runtime
            .node_accounting(Instant::now() + Duration::from_millis(400), &no_cancel())
            .await
            .is_err()
    );
    let fence = runtime
        .fence_absent(
            &context,
            &plan.plan_digest(),
            Instant::now() + Duration::from_millis(400),
            &no_cancel(),
        )
        .await;
    assert!(fence.is_err(), "no receipt can exist while L is blocked");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM allocations WHERE phase = 'stop_intent'"),
        0,
        "the durable record has to wait"
    );
    // L returns: the later record arrives, and the claim stays until proved absence.
    fixture.clear("L.loop.stall");
    wait_until("the later stop record", || {
        fixture.count("SELECT COUNT(*) FROM allocations WHERE phase = 'stop_intent'") == 1
    })
    .await;
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    // The subtree's marker stays until owned cleanup: charged until then.
    let refused = runtime
        .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("charged"), "{refused}");
    std::fs::remove_dir_all(fixture.fake_dir(&context)).unwrap();
    let mut fenced_now = None;
    for _ in 0..200 {
        if let Ok(receipt) = runtime
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
        {
            fenced_now = Some(receipt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fenced(fenced_now.expect("all workers settled"));
    assert_eq!(node_totals(&runtime).await.claimed.slots, 0);
}

#[tokio::test]
async fn exit4_stalled_monitor_denies_admission_and_contains_through_k_without_replacement() {
    let fixture = Fixture::new(NodeOptions {
        heartbeat_timeout_ms: 800,
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let (_, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    let census = fixture.census().await;
    let monitor = census["monitor"].as_i64().unwrap();
    signal(monitor, libc::SIGSTOP);
    // H notices the missing status within its heartbeat, and stops through K.
    wait_until("H to contain with M stalled", || !alive(vm)).await;
    let reply = timed_capabilities(&runtime, &fixture).await;
    assert_eq!(stalled(&reply, |h| h.monitor), WorkerHealth::Stalled);
    assert_eq!(fixture.census().await["monitor"].as_i64().unwrap(), monitor);
    // New work is refused for as long as supervision is absent.
    let next = token(instance);
    let next_plan = prepared(&runtime, &next).await;
    let reply = raw_create(&fixture, &next, epoch_of(&runtime).await, &next_plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::MonitorUnavailable);
    assert_eq!(fixture.active_allocations(), 1);
    assert!(matches!(
        runtime
            .inspect_allocation(&context, &plan.plan_digest(), deadline(2), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    signal(monitor, libc::SIGCONT);
    // M's return doesn't resurrect the contained boot; it stays stop-fenced and charged.
    wait_until("the monitor status", || alive(monitor)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let census = fixture.census().await;
    assert_eq!(
        census["supervisors"][context.allocation_id.to_string()]["stop_fenced"],
        json!(true)
    );
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
}

#[tokio::test]
async fn exit4_recovery_slots_are_independent_fixed_and_a_stuck_slot_is_not_replaced() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let census = fixture.census().await;
    let recovery: Vec<i64> = census["recovery"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pid| pid.as_i64().unwrap())
        .collect();
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let (supervisor, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    // One stuck K: the other fixed slot still contains.
    signal(recovery[0], libc::SIGSTOP);
    signal(supervisor, libc::SIGKILL);
    wait_until("the second K to contain", || !alive(vm)).await;
    assert_eq!(
        fixture.census().await["recovery"],
        census["recovery"],
        "a stopped K keeps its slot"
    );
    signal(recovery[0], libc::SIGCONT);
    // Both stuck: no third K exists, H still answers, and containment is reported as
    // unfinished rather than successful, until those exact processes return.
    let second = token(instance);
    let second_plan = prepared(&runtime, &second).await;
    let (supervisor, vm) = started_vm(&fixture, &runtime, &second, &second_plan).await;
    signal(recovery[0], libc::SIGSTOP);
    signal(recovery[1], libc::SIGSTOP);
    signal(supervisor, libc::SIGKILL);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        alive(vm),
        "nothing else may kill it, and nothing can claim it did"
    );
    assert!(timed_capabilities(&runtime, &fixture).await.enabled);
    let census = fixture.census().await;
    let key = second.allocation_id.to_string();
    assert_eq!(census["recovery"].as_array().unwrap().len(), 2);
    assert_eq!(census["supervisors"][&key]["stop_fenced"], json!(true));
    assert_ne!(census["supervisors"][&key]["contained"], json!(true));
    let refused = runtime
        .fence_absent(
            &second,
            &second_plan.plan_digest(),
            deadline(5),
            &no_cancel(),
        )
        .await;
    assert!(refused.is_err(), "no fence while an owned subtree may live");
    signal(recovery[0], libc::SIGCONT);
    signal(recovery[1], libc::SIGCONT);
    wait_until("the recovered slot to stop the subtree", || !alive(vm)).await;
}

#[tokio::test]
async fn exit4_stalled_helper_fails_closed_in_supervisor_and_monitor() {
    let fixture = Fixture::new(NodeOptions {
        heartbeat_timeout_ms: 800,
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let (supervisor, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    // A live-but-stopped H is not supervision: S and M both act on its silence.
    let helper = fixture.helper_pid() as i64;
    signal(helper, libc::SIGSTOP);
    wait_until("S or M to stop the subtree", || !alive(vm)).await;
    wait_until("S to give up", || !alive(supervisor)).await;
    signal(helper, libc::SIGCONT);
    // H sees it, and the claim is exactly where it was.
    let reply = timed_capabilities(&runtime, &fixture).await;
    assert!(reply.enabled);
    wait_until_supervisor_exit(&fixture, &context).await;
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
}

async fn wait_until_supervisor_exit(fixture: &Fixture, context: &CreateContext) {
    for _ in 0..500 {
        let census = fixture.census().await;
        if !census["supervisors"][context.allocation_id.to_string()]["exit"].is_null() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("H did not observe S's exit");
}

#[tokio::test]
async fn exit4_helper_death_stops_owned_work_and_restart_keeps_the_charge() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let (supervisor, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    let census = fixture.census().await;
    let ledger = census["ledger"].as_i64().unwrap();
    fixture.kill_helper().await;
    wait_until("S to contain after H died", || !alive(supervisor)).await;
    wait_until("the subtree to stop", || !alive(vm)).await;
    wait_until("L to leave after EOF", || !alive(ledger)).await;
    fixture.start().await;
    let renewed = fixture.runtime(instance, database);
    assert_eq!(node_totals(&renewed).await.claimed.slots, 1);
    // No command is replayed: the record comes back, but S does not.
    let census = fixture.census().await;
    assert!(census["supervisors"][context.allocation_id.to_string()].is_null());
    assert!(matches!(
        renewed
            .inspect_allocation(&context, &plan.plan_digest(), deadline(2), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    // Old worker rows settle as gone-after-restart; only then, and only with its
    // resources gone, does a fence commit.
    assert!(
        renewed
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    std::fs::remove_dir_all(fixture.fake_dir(&context)).unwrap();
    let mut done = None;
    for _ in 0..200 {
        if let Ok(receipt) = renewed
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
        {
            done = Some(receipt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fenced(done.expect("restart recovery settled the old workers"));
    assert_eq!(node_totals(&renewed).await.claimed.slots, 0);
}

/// M by itself, with a test standing in for a live H that keeps ticking and never asks
/// for anything: the stop must come from M's own watch on S.
#[tokio::test]
async fn exit4_monitor_requests_a_stale_supervisors_stop_without_help_from_h() {
    use super::workers::{
        Channel, Endpoint, Heartbeat, MonitorCommand, MonitorReply, MonitorSockets, ProcessId,
        RecoveryDatagram, datagram_pair, monitor_main, spawn_process,
    };
    use std::os::unix::net::UnixStream as StdStream;
    struct ReapMonitor(i32);
    impl Drop for ReapMonitor {
        fn drop(&mut self) {
            // SAFETY: our unreaped child; also cleans up if an assertion fails.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(self.0, &mut status, 0);
            }
        }
    }
    let (host, child) = StdStream::pair().unwrap();
    let (descriptors_host, descriptors_child) = StdStream::pair().unwrap();
    let (recovery_monitor, recovery_worker) = datagram_pair().unwrap();
    let (heartbeat_worker, _heartbeat_monitor) = datagram_pair().unwrap();
    recovery_worker.set_nonblocking(true).unwrap();
    let timings = Timings {
        startup_journal: Duration::from_secs(5),
        tick: Duration::from_millis(20),
        heartbeat: Duration::from_millis(50),
        heartbeat_timeout: Duration::from_millis(400),
    };
    let keep = [
        child.as_raw_fd(),
        descriptors_child.as_raw_fd(),
        recovery_monitor.as_raw_fd(),
        heartbeat_worker.as_raw_fd(),
    ];
    let monitor = spawn_process(&keep, move || {
        monitor_main(
            MonitorSockets {
                control: Endpoint::new(child),
                descriptors: descriptors_child.into(),
                heartbeats: vec![],
                recovery: vec![recovery_monitor],
            },
            timings,
            Heartbeat::new(heartbeat_worker, timings.heartbeat),
        );
    })
    .unwrap();
    let _monitor_guard = ReapMonitor(monitor);
    let (channel, _events) = Channel::spawn(host, 8, 0).unwrap();
    descriptors_host.set_nonblocking(true).unwrap();
    let descriptors = UnixStream::from_std(descriptors_host).unwrap();
    let (watch_monitor, watch_supervisor) = StdStream::pair().unwrap();
    let allocation = Id128::random();
    fds::send(&descriptors, &[watch_monitor.as_raw_fd()])
        .await
        .unwrap();
    let registered: MonitorReply = channel
        .call(
            super::workers::Lane::Normal,
            &MonitorCommand::RegisterWatch { allocation },
            u64::MAX,
        )
        .await
        .unwrap();
    assert!(matches!(registered, MonitorReply::Registered));
    drop(watch_monitor);
    let target = ProcessId {
        pid: i32::MAX - 11,
        start_time: 5,
    };
    let registered: MonitorReply = channel
        .call(
            super::workers::Lane::Normal,
            &MonitorCommand::RegisterTarget { allocation, target },
            u64::MAX,
        )
        .await
        .unwrap();
    assert!(matches!(registered, MonitorReply::Registered));
    let mut bytes = [0u8; 1024];
    // Quiet while S is beating.
    let healthy_until = Instant::now() + Duration::from_millis(600);
    while Instant::now() < healthy_until {
        channel.notify(&MonitorCommand::Tick);
        std::io::Write::write_all(&mut (&watch_supervisor), b"h").unwrap();
        while let Ok(n) = recovery_worker.recv(&mut bytes) {
            assert_eq!(n, 0, "only a keepalive is allowed for a live S");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // S goes silent while its socket stays open, and H keeps ticking.
    let stale_until = Instant::now() + Duration::from_secs(5);
    let mut dispatched = None;
    while Instant::now() < stale_until {
        channel.notify(&MonitorCommand::Tick);
        if let Ok(n) = recovery_worker.recv(&mut bytes)
            && n != 0
        {
            dispatched = Some(serde_json::from_slice::<RecoveryDatagram>(&bytes[..n]).unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let dispatched = dispatched.expect("M dispatched K on its own");
    assert_eq!(dispatched.allocation, allocation);
    assert_eq!(dispatched.target, target);
    drop(watch_supervisor);
}

#[tokio::test]
async fn exit4_monitor_exit_fences_before_replacement() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let (_, vm) = started_vm(&fixture, &runtime, &context, &plan).await;
    let key = context.allocation_id.to_string();
    let monitor = fixture.census().await["monitor"].as_i64().unwrap();
    signal(monitor, libc::SIGKILL);
    // The moment any replacement is visible, this boot is already fenced.
    let mut replacement = None;
    for _ in 0..3000 {
        let census = fixture.census().await;
        let current = census["monitor"].as_i64().unwrap();
        if current != monitor {
            assert_eq!(
                census["supervisors"][&key]["stop_fenced"],
                json!(true),
                "a replacement M appeared before the fence"
            );
            replacement = Some(current);
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let replacement = replacement.expect("the exited M's slot was reassigned");
    wait_until("K to contain with no monitor involved", || !alive(vm)).await;
    wait_until_supervisor_exit(&fixture, &context).await;
    // The repaired M never takes these boots back: fenced and charged, for good.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fixture.census().await["supervisors"][&key]["stop_fenced"],
        json!(true)
    );
    assert!(matches!(
        runtime
            .inspect_allocation(&context, &plan.plan_digest(), deadline(2), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    // Prior permit settled after its reap; the successor was journaled, with its image.
    wait_until("the prior monitor's settlement", || {
        fixture.count(&format!(
            "SELECT COUNT(*) FROM worker_intents WHERE mode = 'monitor' AND pid = {monitor}
             AND settled_generation IS NOT NULL"
        )) == 1
    })
    .await;
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM worker_intents WHERE mode = 'monitor' AND pid = {replacement}
             AND settled_generation IS NULL AND start_time IS NOT NULL
             AND exec_sha256 = '{}'",
            pin_of(Role::KilndHelper).sha256
        )),
        1
    );
    // New work gets real supervision from the replacement: a fresh boot has its watch.
    let next = token(instance);
    let next_plan = prepared(&runtime, &next).await;
    let (next_supervisor, next_vm) = started_vm(&fixture, &runtime, &next, &next_plan).await;
    signal(next_supervisor, libc::SIGKILL);
    wait_until("the new M's containment", || !alive(next_vm)).await;
}

#[tokio::test]
async fn exit4_each_replacement_is_journaled_and_a_stuck_ledger_defers_it() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let census = fixture.census().await;
    let prep = census["prep"][0].as_i64().unwrap();
    let recovery = census["recovery"][1].as_i64().unwrap();
    // L cannot settle the prior permit, so no replacement may start.
    fixture.fault("L.loop.stall");
    tokio::time::sleep(Duration::from_millis(100)).await;
    signal(prep, libc::SIGKILL);
    signal(recovery, libc::SIGKILL);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let during = fixture.census().await;
    assert_eq!(
        during["prep"][0].as_i64(),
        Some(prep),
        "the slot stays with its exited worker"
    );
    assert_eq!(during["recovery"][1].as_i64(), Some(recovery));
    fixture.clear("L.loop.stall");
    let mut replaced = None;
    for _ in 0..3000 {
        let current = fixture.census().await;
        if current["prep"][0].as_i64() != Some(prep)
            && current["recovery"][1].as_i64() != Some(recovery)
        {
            replaced = Some(current);
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let replaced = replaced.expect("both slots were reassigned");
    for (mode, old, new) in [
        ("prep", prep, replaced["prep"][0].as_i64().unwrap()),
        (
            "recovery",
            recovery,
            replaced["recovery"][1].as_i64().unwrap(),
        ),
    ] {
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM worker_intents WHERE mode = '{mode}' AND pid = {old}
                 AND settled_generation IS NOT NULL"
            )),
            1,
            "{mode}"
        );
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM worker_intents WHERE mode = '{mode}' AND pid = {new}
                 AND start_time IS NOT NULL AND settled_generation IS NULL"
            )),
            1,
            "{mode}"
        );
    }
    // The ledger's own slot: it restarts first, then writes its own and its predecessor's rows.
    let ledger = replaced["ledger"].as_i64().unwrap();
    signal(ledger, libc::SIGKILL);
    let mut new_ledger = None;
    for _ in 0..3000 {
        let current = fixture.census().await["ledger"].as_i64().unwrap();
        if current != ledger {
            new_ledger = Some(current);
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let new_ledger = new_ledger.expect("L's slot was reassigned");
    assert!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM worker_intents WHERE mode = 'ledger' AND pid = {ledger}
             AND settled_generation IS NOT NULL"
        )) == 1
    );
    assert!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM worker_intents WHERE mode = 'ledger' AND pid = {new_ledger}
             AND start_time IS NOT NULL"
        )) == 1
    );
    assert!(
        runtime
            .node_accounting(deadline(5), &no_cancel())
            .await
            .is_ok()
    );
}

/// Three real subtrees under the default vector, with all three supervisors stopped so
/// only M and two K processes can act, against a helper lost by `lose`.
async fn three_stopped_supervisors(
    fixture: &Fixture,
    runtime: &Arc<FirecrackerRuntime>,
    instance: Id128,
) -> (Vec<i64>, Vec<i64>) {
    let mut supervisors = Vec::new();
    let mut vms = Vec::new();
    for _ in 0..3 {
        let context = token(instance);
        let plan = prepared(runtime, &context).await;
        let (supervisor, vm) = started_vm(fixture, runtime, &context, &plan).await;
        supervisors.push(supervisor);
        vms.push(vm);
    }
    for supervisor in &supervisors {
        signal(*supervisor, libc::SIGSTOP);
    }
    (supervisors, vms)
}

#[tokio::test]
async fn exit4_helper_loss_contains_all_three_allocations_with_two_recovery_slots() {
    // H stalled, then H killed: M has only K's two fixed slots either way.
    for killed in [false, true] {
        let fixture = Fixture::new(NodeOptions {
            heartbeat_timeout_ms: 800,
            effects: vec!["vm".into()],
            ..NodeOptions::default()
        })
        .await;
        let instance = Id128::random();
        let runtime = fixture.runtime(instance, Id128::random());
        let (supervisors, vms) = three_stopped_supervisors(&fixture, &runtime, instance).await;
        let census = fixture.census().await;
        let monitor = census["monitor"].as_i64().unwrap();
        let recovery: Vec<i64> = census["recovery"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pid| pid.as_i64().unwrap())
            .collect();
        let helper = fixture.helper_pid() as i64;
        if killed {
            // Both K slots busy past H's death, so ownership has to outlast its EOF.
            signal(recovery[0], libc::SIGSTOP);
            signal(recovery[1], libc::SIGSTOP);
            fixture.kill_helper().await;
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert!(alive(monitor), "M owns unfinished stops through H's death");
            assert!(
                vms.iter().all(|vm| alive(*vm)),
                "nothing else could have stopped them"
            );
            signal(recovery[0], libc::SIGCONT);
            signal(recovery[1], libc::SIGCONT);
        } else {
            signal(helper, libc::SIGSTOP);
        }
        wait_until("all three subtrees to be contained", || {
            vms.iter().all(|vm| !alive(*vm))
        })
        .await;
        if killed {
            // M owned its pending stops to completion, and only then left, K after it.
            wait_until("M to leave once its stops settled", || !alive(monitor)).await;
            for pid in &recovery {
                wait_until("K to leave once M stopped sending", || !alive(*pid)).await;
            }
        } else {
            signal(helper, libc::SIGCONT);
        }
        for supervisor in &supervisors {
            signal(*supervisor, libc::SIGCONT);
        }
    }
}

#[tokio::test]
async fn exit4_helper_loss_retains_pending_stops_without_an_ownership_timeout() {
    let fixture = Fixture::new(NodeOptions {
        heartbeat_timeout_ms: 800,
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (supervisors, vms) = three_stopped_supervisors(&fixture, &runtime, instance).await;
    let census = fixture.census().await;
    let monitor = census["monitor"].as_i64().unwrap();
    let recovery: Vec<i64> = census["recovery"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pid| pid.as_i64().unwrap())
        .collect();
    for pid in &recovery {
        signal(*pid, libc::SIGSTOP);
    }
    fixture.kill_helper().await;
    // Regression: neither ownership nor a fixed slot may time out at 30 seconds.
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(alive(monitor), "M abandoned its pending containment work");
    assert!(vms.iter().all(|vm| alive(*vm)));
    signal(recovery[0], libc::SIGCONT);
    wait_until("one K to contain two queued targets", || {
        vms.iter().filter(|vm| !alive(**vm)).count() == 2
    })
    .await;
    // The other K remains stuck. M must keep the available K's original slot alive.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(alive(monitor));
    assert!(
        alive(recovery[0]),
        "an available K left pending work unowned"
    );
    signal(recovery[1], libc::SIGCONT);
    wait_until("every target to settle", || {
        vms.iter().all(|vm| !alive(*vm))
    })
    .await;
    wait_until("M to leave only after settlement", || !alive(monitor)).await;
    for pid in &recovery {
        wait_until("K to leave after M", || !alive(*pid)).await;
    }
    for pid in &supervisors {
        signal(*pid, libc::SIGCONT);
    }
}

#[tokio::test]
async fn exit4_waiter_disconnect_leaves_accepted_work_owned_and_charged() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let cancel = no_cancel();
    fixture.fault("L.admit.stall");
    let waiter = {
        let (runtime, context, plan, cancel) = (
            runtime.clone(),
            context.clone(),
            plan.clone(),
            cancel.clone(),
        );
        tokio::spawn(async move { runtime.create(&context, &plan, deadline(30), &cancel).await })
    };
    fixture.wait_reached("L.admit").await;
    // The waiter disconnects. Its ownership doesn't move, and its answer says so.
    cancel.cancel();
    let failure = waiter.await.unwrap().unwrap_err();
    assert_eq!(failure.certainty(), CreateCertainty::AllocationAmbiguous);
    assert!(failure.absence().is_none());
    fixture.clear("L.admit.stall");
    wait_until("the detached admission", || {
        fixture.active_allocations() == 1
    })
    .await;
    let mut supervised = false;
    for _ in 0..500 {
        let census = fixture.census().await;
        if !census["supervisors"][context.allocation_id.to_string()].is_null() {
            supervised = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(supervised, "detached work continued past its gone waiter");
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
}

#[test]
fn exit4_h_side_source_has_no_blocking_filesystem_sqlite_hash_or_proc_calls() {
    let source = include_str!("mod.rs");
    let source = source.split("#[cfg(test)]\nmod tests;").next().unwrap();
    let source: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // Everything before the startup-only loader must stay dispatch: the loader runs
    // before any traffic and the policy reader before the socket loop.
    let serving = source.split("pub fn load_profile(").next().unwrap();
    for banned in [
        "std::fs",
        "rusqlite",
        "Connection",
        "hash_descriptor",
        "/proc",
        "read_to_string",
        ".canonicalize",
        "Sha256",
        "spawn_blocking",
        "block_on",
    ] {
        // `walk_directory` in `Node::start` is the one startup lock acquisition.
        assert!(!serving.contains(banned), "H's serving code uses {banned}");
    }
    let without_start: String = serving
        .split("pub async fn start(config: NodeConfig)")
        .enumerate()
        .map(|(index, part)| {
            if index == 0 {
                part.to_string()
            } else {
                part.split("async fn replay_at_startup")
                    .nth(1)
                    .unwrap_or("")
                    .to_string()
            }
        })
        .collect();
    assert!(!without_start.contains("walk_directory"));
}

#[tokio::test]
async fn exit5_installed_replacement_after_preflight_refuses_create_with_zero_effects() {
    for role in Role::ALL {
        let fixture = Fixture::new(NodeOptions::default()).await;
        let instance = Id128::random();
        let runtime = fixture.runtime(instance, Id128::random());
        let context = token(instance);
        let plan = prepared(&runtime, &context).await;
        // The same bytes at a new inode: digest and argv would all still match.
        let object = fixture
            .root
            .join("exec/sha256")
            .join(pin_of(role).sha256.to_string())
            .join(role.as_str());
        let parked = fixture.root.join("parked-object");
        std::fs::rename(&object, &parked).unwrap();
        std::fs::copy(&parked, &object).unwrap();
        std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o555)).unwrap();
        let reply = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
        assert_eq!(
            class_of(&reply),
            AmbiguousClass::CatalogMismatch,
            "{role:?}"
        );
        assert_eq!(fixture.active_allocations(), 0);
        assert!(!fixture.fake_dir(&context).exists());
        // Post-C1 it stays ambiguous until its exact fence; restoring doesn't reopen it.
        std::fs::remove_file(&object).unwrap();
        std::fs::rename(&parked, &object).unwrap();
        let reply = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
        assert_eq!(class_of(&reply), AmbiguousClass::GateClosed, "{role:?}");
        fenced(
            runtime
                .fence_absent(&context, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn exit5_installed_replacement_before_preflight_is_a_c0_refusal_for_every_role() {
    for role in Role::ALL {
        let fixture = Fixture::new(NodeOptions::default()).await;
        let instance = Id128::random();
        let runtime = fixture.runtime(instance, Id128::random());
        let object = fixture
            .root
            .join("exec/sha256")
            .join(pin_of(role).sha256.to_string())
            .join(role.as_str());
        let parked = fixture.root.join("parked-object");
        std::fs::rename(&object, &parked).unwrap();
        std::fs::copy(&parked, &object).unwrap();
        std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o555)).unwrap();
        let error = runtime
            .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
            .await
            .unwrap_err();
        assert!(
            matches!(error, RuntimeError::Incompatible(_)),
            "{role:?}: {error}"
        );
        assert_eq!(fixture.count("SELECT COUNT(*) FROM allocations"), 0);
        assert_eq!(
            std::fs::read_dir(fixture.root.join("fake"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fixture.census().await["supervisors"]
                .as_object()
                .unwrap()
                .len(),
            0
        );
    }
}

#[tokio::test]
async fn exit5_source_tree_swap_after_preflight_changes_nothing() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    std::fs::rename(
        fixture.root.join("source"),
        fixture.root.join("source-moved"),
    )
    .unwrap();
    std::fs::create_dir(fixture.root.join("source")).unwrap();
    for role in Role::ALL {
        std::fs::write(fixture.root.join("source").join(role.as_str()), b"attacker").unwrap();
    }
    create_accepted(&fixture, &runtime, &context, &plan).await;
}

#[tokio::test]
async fn exit5_journal_records_expected_and_actual_tuples_for_dispatch_and_workers() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    wait_until("S to record what ran", || {
        fixture.count(
            "SELECT COUNT(*) FROM executable_leases WHERE observed_st_ino IS NOT NULL
             AND observed_st_ino = st_ino AND observed_st_dev = st_dev
             AND observed_sha256 = sha256 AND observed_bytes = bytes",
        ) == 4
    })
    .await;
    let view = fixture.ledger_view();
    // The stored expected tuples are exactly the installed objects' real identities.
    for role in Role::ALL {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(
            fixture
                .root
                .join("exec/sha256")
                .join(pin_of(role).sha256.to_string())
                .join(role.as_str()),
        )
        .unwrap();
        let (dev, ino, bytes, sha): (i64, i64, i64, String) = view
            .query_row(
                "SELECT observed_st_dev, observed_st_ino, observed_bytes, observed_sha256
                 FROM executable_leases WHERE role = ?1",
                [role.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (dev as u64, ino as u64, bytes as u64, sha),
            (
                meta.dev(),
                meta.ino(),
                meta.len(),
                pin_of(role).sha256.to_string()
            ),
            "{role:?}"
        );
    }
    // L, P×2, M, K×2 and S each record the inherited helper image as their identity.
    let helper = pin_of(Role::KilndHelper).sha256.to_string();
    let workers = view
        .query_row(
            "SELECT COUNT(*) FROM worker_intents WHERE exec_role = 'kilnd-helper' AND exec_sha256 = ?1
             AND pid IS NOT NULL AND start_time IS NOT NULL AND host_boot_id IS NOT NULL",
            [&helper],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(workers, 7);
    // The plan these came from named those same tuples.
    let document = crate::firecracker::strict_json(plan.backend_plan()).unwrap();
    for role in Role::ALL {
        let record = &document["substitutions"]["executables"][role.as_str()];
        let stored: i64 = view
            .query_row(
                "SELECT st_ino FROM executable_leases WHERE role = ?1",
                [role.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(record["st_ino"].as_i64(), Some(stored));
    }
}

#[tokio::test]
async fn exit5_descriptor_reuse_at_dispatch_refuses_and_keeps_the_charge() {
    for role in [
        Role::Jailer,
        Role::Firecracker,
        Role::MkfsXfs,
        Role::KilndHelper,
    ] {
        let fixture = Fixture::new(NodeOptions::default()).await;
        let instance = Id128::random();
        let runtime = fixture.runtime(instance, Id128::random());
        let context = token(instance);
        let plan = prepared(&runtime, &context).await;
        fixture.fault(&format!("S.reuse_fd.{}", role.as_str()));
        create_accepted(&fixture, &runtime, &context, &plan).await;
        // S refuses, with no alternate object tried, and that fences the allocation.
        wait_until_supervisor_exit(&fixture, &context).await;
        wait_until("the stop record", || {
            fixture.count("SELECT COUNT(*) FROM allocations WHERE phase = 'stop_intent'") == 1
        })
        .await;
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM executable_leases WHERE role = '{}' AND observed_st_ino IS NOT NULL",
                role.as_str()
            )),
            0,
            "{role:?} never ran, so no observation exists"
        );
        assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
        // Post-C1 the charge lasts until the exact ABSENT.
        fixture.clear(&format!("S.reuse_fd.{}", role.as_str()));
        let mut done = None;
        for _ in 0..200 {
            if let Ok(receipt) = runtime
                .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
                .await
            {
                done = Some(receipt);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        fenced(done.expect("S settled"));
    }
}

#[tokio::test]
async fn exit5_restart_generation_recovery_refuses_a_replacement_inode_and_accepts_the_exact_one() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    fixture.kill_helper().await;
    let role = Role::Firecracker;
    let object = fixture
        .root
        .join("exec/sha256")
        .join(pin_of(role).sha256.to_string())
        .join(role.as_str());
    let parked = fixture.root.join("parked-object");
    std::fs::rename(&object, &parked).unwrap();
    std::fs::copy(&parked, &object).unwrap();
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o555)).unwrap();
    fixture.start().await;
    let restarted = fixture.runtime(instance, database);
    // A lease exists on the old tuple: identical bytes at a new inode cannot satisfy it.
    let reply = timed_capabilities(&restarted, &fixture).await;
    let fault = reply
        .health
        .unwrap()
        .ledger_fault
        .expect("generation fault");
    assert!(fault.contains("firecracker"), "{fault}");
    let error = restarted
        .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reopened"), "{error}");
    assert_eq!(node_totals(&restarted).await.claimed.slots, 1);
    fixture.kill_helper().await;
    std::fs::remove_file(&object).unwrap();
    std::fs::rename(&parked, &object).unwrap();
    fixture.start().await;
    let healthy = fixture.runtime(instance, database);
    assert!(
        timed_capabilities(&healthy, &fixture)
            .await
            .health
            .unwrap()
            .ledger_fault
            .is_none(),
        "the exact tuple restores service"
    );
    // A successor can then fence it, with leases held to the end.
    let mut done = None;
    for _ in 0..200 {
        if let Ok(receipt) = healthy
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
        {
            done = Some(receipt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fenced(done.expect("settled"));
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM executable_leases WHERE released_generation IS NULL"),
        0
    );
}

#[tokio::test]
async fn exit6_fence_reply_loss_replays_the_same_bytes_after_helper_restart() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    // The commit lands; L stalls before replying; the waiter gets no receipt.
    fixture.fault("L.fence.after_commit.stall");
    let error = runtime
        .fence_absent(
            &context,
            &plan.plan_digest(),
            Instant::now() + Duration::from_millis(600),
            &no_cancel(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("charged"), "{error}");
    fixture.wait_reached("L.fence.after_commit").await;
    let durable = fixture.retired_receipt(context.allocation_id).unwrap();
    fixture.clear("L.fence.after_commit.stall");
    fixture.kill_helper().await;
    fixture.start().await;
    let renewed = fixture.runtime(instance, database);
    let replay = fenced(
        renewed
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(replay.encode().unwrap(), durable);
    assert_eq!(node_totals(&renewed).await.claimed.slots, 0);
    // Inspect, Create and FenceAbsent all read one receipt.
    assert_eq!(
        renewed
            .inspect_allocation(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::AbsentFenced(FencedAbsence::decode(&durable).unwrap())
    );
    let reply = raw_create(&fixture, &context, epoch_of(&renewed).await, &plan).await;
    assert_eq!(receipt_of(&reply), durable);
    // A token used by a fence can never preflight again.
    let error = renewed
        .prepare(&context, &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("already used"), "{error}");
}

#[tokio::test]
async fn exit6_sync_failure_keeps_every_charge_and_a_retry_completes() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    fixture.fault("L.fence.sync_fail");
    let error = runtime
        .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("charged"), "{error}");
    assert!(fixture.retired_receipt(context.allocation_id).is_none());
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    fixture.clear("L.fence.sync_fail");
    let fence = fenced(
        runtime
            .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(
        fixture.retired_receipt(context.allocation_id).unwrap(),
        fence.encode().unwrap()
    );
}

#[tokio::test]
async fn exit6_a_missing_or_corrupt_ledger_is_unavailable_never_an_empty_answer() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    fixture.kill_helper().await;
    let db = fixture.root.join("ledger/node.db");
    let saved = std::fs::read(&db).unwrap();
    for name in ["node.db-wal", "node.db-shm"] {
        let _ = std::fs::remove_file(fixture.root.join("ledger").join(name));
    }
    for damage in [None, Some(b"not a database".to_vec())] {
        match &damage {
            None => std::fs::remove_file(&db).unwrap(),
            Some(bytes) => {
                std::fs::write(&db, bytes).unwrap();
                std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        fixture.start().await;
        // Attach cannot succeed, so no totals, no list and no receipt exist.
        let renewed = fixture.runtime(instance, database);
        let error = renewed
            .node_accounting(deadline(5), &no_cancel())
            .await
            .unwrap_err();
        assert!(!error.to_string().is_empty());
        assert!(renewed.list(deadline(5), &no_cancel()).await.is_err());
        assert!(
            renewed
                .fence_absent(&context, &plan.plan_digest(), deadline(5), &no_cancel())
                .await
                .is_err()
        );
        match &damage {
            // The open refused and never re-created it.
            None => assert!(!db.exists(), "no fresh empty ledger appeared"),
            Some(bytes) => assert_eq!(&std::fs::read(&db).unwrap(), bytes),
        }
        fixture.kill_helper().await;
    }
    std::fs::write(&db, &saved).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn exit6_lowered_policy_limits_on_restart_deny_admission_and_keep_claims() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let database = Id128::random();
    let runtime = fixture.runtime(instance, database);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    fixture.kill_helper().await;
    // The root policy now lowers the node below this claim's size.
    let mut config: ChildConfig =
        serde_json::from_slice(&std::fs::read(fixture.root.join("config.json")).unwrap()).unwrap();
    config.options.ceilings.memory_bytes = 512 * MIB;
    std::fs::write(
        fixture.root.join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    fixture.start().await;
    let renewed = fixture.runtime(instance, database);
    let totals = node_totals(&renewed).await;
    assert_eq!(totals.claimed.slots, 1);
    assert_eq!(
        totals.claimed.memory_bytes,
        896 * MIB,
        "a lower limit discounts nothing"
    );
    assert!(totals.over_committed);
    let next = token(instance);
    let next_plan = prepared(&renewed, &next).await;
    let reply = raw_create(&fixture, &next, epoch_of(&renewed).await, &next_plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::Capacity);
    assert_eq!(fixture.active_allocations(), 1);
}

#[tokio::test]
async fn exit1_c0_rejection_creates_zero_session_resources() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["marker:work.xfs".into(), "vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let refused = |mutate: fn(&mut SandboxSpec)| {
        let mut bad = spec();
        mutate(&mut bad);
        bad
    };
    for bad in [
        refused(|s| s.network = Network::Full),
        refused(|s| s.network = Network::Allow(vec!["1.1.1.1".into()])),
        refused(|s| s.image = "ubuntu".into()),
        refused(|s| s.memory_bytes = 512 * MIB + 1),
        refused(|s| s.cpu_millis = 1001),
    ] {
        let context = token(instance);
        let error = runtime
            .prepare(&context, &bad, deadline(5), &no_cancel())
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Incompatible(_)), "{error}");
    }
    // Any unapproved profile, too.
    let context = token(instance);
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Preflight {
            allocation_id: context.allocation_id,
            sandbox_id: context.sandbox_id.clone(),
            profile: "other-profile".into(),
            spec: spec(),
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        reply,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::Incompatible,
            ..
        })
    ));
    // Bundle damage is a C0 refusal too. Each is restored before the next.
    let artifact = fixture.root.join("bundle/kiln");
    let saved = std::fs::read(&artifact).unwrap();
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&artifact, b"other").unwrap();
    assert!(
        runtime
            .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    std::fs::write(&artifact, &saved).unwrap();
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::write(fixture.root.join("bundle/extra"), b"x").unwrap();
    assert!(
        runtime
            .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
            .await
            .is_err()
    );
    std::fs::remove_file(fixture.root.join("bundle/extra")).unwrap();
    assert!(
        runtime
            .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
            .await
            .is_ok()
    );

    // Zero session side effects: no process, no resource, no claim, no row. Preflight's
    // success above changed nothing either.
    let census = fixture.census().await;
    assert_eq!(census["supervisors"].as_object().unwrap().len(), 0);
    assert_eq!(
        std::fs::read_dir(fixture.root.join("fake"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(fixture.active_allocations(), 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM allocations"), 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    let totals = node_totals(&runtime).await;
    assert_eq!(totals.claimed, Default::default());
    assert_eq!(totals.committed.slots, 0);
    assert_eq!(
        totals.committed.memory_bytes,
        128 * MIB,
        "only the shared reserve"
    );
    let listed = runtime.list(deadline(5), &no_cancel()).await.unwrap();
    assert!(listed.complete, "an observed, empty namespace is complete");
    assert!(listed.records.is_empty());
}

#[tokio::test]
async fn exit1_plan_substitution_is_refused_at_create_by_recomputation() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let epoch = epoch_of(&runtime).await;
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    let document = crate::firecracker::strict_json(plan.backend_plan()).unwrap();
    let attacks: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "uid",
            Box::new(|d| d["substitutions"]["uid"]["value"] = json!(300_999)),
        ),
        ("cid", Box::new(|d| d["substitutions"]["cid"] = json!(4444))),
        (
            "nonce",
            Box::new(|d| d["substitutions"]["boot_nonce"] = json!("aa".repeat(32))),
        ),
        (
            "spec memory",
            Box::new(|d| d["host_spec"]["memory_bytes"] = json!(1)),
        ),
        (
            "labels",
            Box::new(|d| d["host_spec"]["labels"] = json!({"a": "b"})),
        ),
        (
            "manifest",
            Box::new(|d| d["manifest_sha256"] = json!("00".repeat(32))),
        ),
        (
            "catalog generation",
            Box::new(|d| d["catalog_generation"] = json!(2)),
        ),
        ("profile", Box::new(|d| d["profile"] = json!("other"))),
        (
            "inode",
            Box::new(|d| {
                d["substitutions"]["executables"]["jailer"]["st_ino"] = json!(1);
            }),
        ),
        (
            "argv",
            Box::new(|d| {
                d["launch"]["jailer_argv"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("--seccomp-filter"));
            }),
        ),
    ];
    for (name, attack) in attacks {
        let target = token(instance);
        let mut mutated = document.clone();
        attack(&mut mutated);
        let raw = crate::firecracker::canonical(&mutated).unwrap();
        let reply = raw_call(
            &fixture,
            instance,
            Some(epoch),
            FirecrackerOperation::Create {
                allocation_id: target.allocation_id,
                sandbox_id: target.sandbox_id.clone(),
                plan: WireBytes(raw.clone()),
                plan_digest: Digest::of(&raw),
            },
            wire_deadline(10),
            10_000,
        )
        .await
        .unwrap();
        match reply {
            FirecrackerResponse::Create(reply) => {
                assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch, "{name}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    // Bytes that do not hash to their digest reach P, which H trusts for that check.
    let target = token(instance);
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch),
        FirecrackerOperation::Create {
            allocation_id: target.allocation_id,
            sandbox_id: target.sandbox_id.clone(),
            plan: WireBytes(plan.backend_plan().to_vec()),
            plan_digest: Digest::of(b"another plan"),
        },
        wire_deadline(10),
        10_000,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Create(reply) => {
            assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch);
        }
        other => panic!("{other:?}"),
    }
    // The exact plan under another token's identity is the same as a substitution.
    let elsewhere = token(instance);
    let reply = raw_create(&fixture, &elsewhere, epoch, &plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch);
    // A fixture plan never verifies, even with its own correct digest.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/firecracker/plan.json"
    );
    let fixture_plan = std::fs::read(path).unwrap();
    let target = token(instance);
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch),
        FirecrackerOperation::Create {
            allocation_id: target.allocation_id,
            sandbox_id: target.sandbox_id.clone(),
            plan_digest: Digest::of(&fixture_plan),
            plan: WireBytes(fixture_plan),
        },
        wire_deadline(10),
        10_000,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Create(reply) => {
            assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fixture.active_allocations(), 0);
    // The original remains admissible: nothing leaked between tokens.
    create_accepted(&fixture, &runtime, &context, &plan).await;
}

#[tokio::test]
async fn exit1_toctou_manifest_or_artifact_change_after_preflight_is_refused() {
    for target in ["manifest.json", "rootfs.squashfs"] {
        let fixture = Fixture::new(NodeOptions::default()).await;
        let instance = Id128::random();
        let runtime = fixture.runtime(instance, Id128::random());
        let context = token(instance);
        let plan = prepared(&runtime, &context).await;
        let path = fixture.root.join("bundle").join(target);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed.push(b' ');
        std::fs::write(&path, &changed).unwrap();
        let reply = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
        assert_eq!(
            class_of(&reply),
            AmbiguousClass::CatalogMismatch,
            "{target}"
        );
        assert_eq!(fixture.active_allocations(), 0);
        std::fs::write(&path, &original).unwrap();
        // The cause clearing does not reopen a rejected token.
        let reply = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
        assert_eq!(class_of(&reply), AmbiguousClass::GateClosed, "{target}");
    }
}

/// Writes raw bytes as one v3 frame, optionally with an SCM_RIGHTS descriptor in the
/// marker; returns the connection after confirming the helper closes without a reply.
async fn assert_frame_refused(fixture: &Fixture, body: &[u8], descriptor: Option<i32>) {
    let mut stream = UnixStream::connect(fixture.root.join("helper.sock"))
        .await
        .unwrap();
    match descriptor {
        Some(fd) => fds::send(&stream, &[fd]).await.unwrap(),
        None => fds::send(&stream, &[]).await.unwrap(),
    }
    stream.write_u32(body.len() as u32).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut buffer = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .expect("a refusal must be prompt")
        .unwrap_or(0);
    assert_eq!(n, 0, "no reply to {}", String::from_utf8_lossy(body));
}

#[tokio::test]
async fn exit1_framing_refuses_noncanonical_group_frames_and_every_caller_descriptor() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let epoch = epoch_of(&runtime).await;
    let context = token(instance);
    let group = |operation: Value, group_version: Value, epoch: Value| {
        serde_json::to_vec(&json!({
            "version": 3,
            "timeout_ms": 1000,
            "deadline_ns": wire_deadline(1),
            "operation": {"firecracker": {
                "group_version": group_version,
                "instance_id": instance.to_string(),
                "connection_epoch": epoch,
                "operation": operation,
            }}
        }))
        .unwrap()
    };
    let epoch_text = json!(epoch.to_string());
    for body in [
        // Unknown fields and verbs, at every level.
        group(
            json!({"exec_raw": {"argv": ["/bin/sh"]}}),
            json!(1),
            epoch_text.clone(),
        ),
        group(
            json!({"inspect": {"allocation_id": "00".repeat(16), "path": "/etc"}}),
            json!(1),
            epoch_text.clone(),
        ),
        group(
            json!({"accounting": {"fixture": true}}),
            json!(1),
            epoch_text.clone(),
        ),
        // Wrong group schema, missing or misplaced epoch.
        group(json!("accounting"), json!(2), epoch_text.clone()),
        group(json!("accounting"), json!(1), Value::Null),
        group(
            json!({"attach_instance": {"database_uuid": "00".repeat(16)}}),
            json!(1),
            epoch_text.clone(),
        ),
        // A bad typed ID and uppercase hex.
        group(
            json!({"inspect": {"allocation_id": "not-hex"}}),
            json!(1),
            epoch_text.clone(),
        ),
        group(
            json!({"inspect": {"allocation_id": "AB".repeat(16)}}),
            json!(1),
            epoch_text.clone(),
        ),
        // A bad sandbox ID or path-shaped profile.
        group(
            json!({"preflight": {
                "allocation_id": context.allocation_id.to_string(),
                "sandbox_id": "../sb",
                "profile": PROFILE,
                "spec": serde_json::to_value(spec()).unwrap(),
            }}),
            json!(1),
            epoch_text.clone(),
        ),
        group(
            json!({"preflight": {
                "allocation_id": context.allocation_id.to_string(),
                "sandbox_id": context.sandbox_id,
                "profile": "/etc/passwd",
                "spec": serde_json::to_value(spec()).unwrap(),
            }}),
            json!(1),
            epoch_text.clone(),
        ),
        // Plan bytes that are not lowercase hex.
        group(
            json!({"create": {
                "allocation_id": context.allocation_id.to_string(),
                "sandbox_id": context.sandbox_id,
                "plan": "AA",
                "plan_digest": Digest::of(&[0xaa]).to_string(),
            }}),
            json!(1),
            epoch_text.clone(),
        ),
    ] {
        assert_frame_refused(&fixture, &body, None).await;
    }
    // Strict JSON over the whole group frame: duplicate keys, even deep in labels.
    let frame_with_labels = |labels: &str| {
        serde_json::to_string(&Request {
            version: VERSION,
            timeout_ms: 5_000,
            deadline_ns: wire_deadline(5),
            operation: Operation::Firecracker(FirecrackerRequest {
                group_version: FIRECRACKER_GROUP_VERSION,
                instance_id: instance,
                connection_epoch: Some(epoch),
                operation: FirecrackerOperation::Preflight {
                    allocation_id: context.allocation_id,
                    sandbox_id: context.sandbox_id.clone(),
                    profile: PROFILE.into(),
                    spec: spec(),
                },
            }),
        })
        .unwrap()
        .replace(r#""labels":{}"#, &format!(r#""labels":{labels}"#))
    };
    assert_frame_refused(
        &fixture,
        frame_with_labels(r#"{"a":"1","a":"2"}"#).as_bytes(),
        None,
    )
    .await;
    // The control: this exact frame with distinct keys is valid, so that refusal was the
    // duplicate and not some other mistake in it.
    let control = frame_with_labels(r#"{"a":"1","b":"2"}"#);
    let mut stream = UnixStream::connect(fixture.root.join("helper.sock"))
        .await
        .unwrap();
    fds::send(&stream, &[]).await.unwrap();
    stream.write_u32(control.len() as u32).await.unwrap();
    stream.write_all(control.as_bytes()).await.unwrap();
    assert!(fds::receive(&stream).await.unwrap().is_empty());
    assert!(matches!(
        read_frame::<Response>(&mut stream).await.unwrap(),
        Response::Firecracker(FirecrackerResponse::Prepared(_))
    ));
    // A correct frame with any caller descriptor is refused before dispatch.
    let good = serde_json::to_vec(&Request {
        version: VERSION,
        timeout_ms: 2000,
        deadline_ns: wire_deadline(2),
        operation: Operation::Firecracker(FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: instance,
            connection_epoch: Some(epoch),
            operation: FirecrackerOperation::Accounting,
        }),
    })
    .unwrap();
    let file = std::fs::File::open("/dev/null").unwrap();
    assert_frame_refused(&fixture, &good, Some(file.as_raw_fd())).await;
    // A timeout beyond this operation's own budget is refused.
    let long = serde_json::to_vec(&Request {
        version: VERSION,
        timeout_ms: 5_001,
        deadline_ns: wire_deadline(5),
        operation: Operation::Firecracker(FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: instance,
            connection_epoch: Some(epoch),
            operation: FirecrackerOperation::Accounting,
        }),
    })
    .unwrap();
    assert_frame_refused(&fixture, &long, None).await;
    // The listener survived all of it, and nothing was admitted.
    assert!(timed_capabilities(&runtime, &fixture).await.enabled);
    assert_eq!(fixture.active_allocations(), 0);
}

#[tokio::test]
async fn exit1_absolute_wire_deadlines_are_never_replaced_by_a_fresh_budget() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    // An already-past Preflight is a refusal with no worker dispatch.
    let past = crate::helper::monotonic_ns().unwrap() - 1_000_000_000;
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Preflight {
            allocation_id: context.allocation_id,
            sandbox_id: context.sandbox_id.clone(),
            profile: PROFILE.into(),
            spec: spec(),
        },
        past,
        1_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        reply,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::Unavailable,
            ..
        })
    ));
    // A deadline farther out than the declared timeout is refused, not trusted.
    let far = wire_deadline(5);
    let mut stream = UnixStream::connect(fixture.root.join("helper.sock"))
        .await
        .unwrap();
    fds::send(&stream, &[]).await.unwrap();
    write_frame(
        &mut stream,
        &Request {
            version: VERSION,
            timeout_ms: 100,
            deadline_ns: far,
            operation: Operation::Firecracker(FirecrackerRequest {
                group_version: FIRECRACKER_GROUP_VERSION,
                instance_id: instance,
                connection_epoch: Some(epoch_of(&runtime).await),
                operation: FirecrackerOperation::Accounting,
            }),
        },
    )
    .await
    .unwrap();
    let mut buffer = [0u8; 8];
    assert_eq!(stream.read(&mut buffer).await.unwrap_or(0), 0);
    // A stuck worker's wait ends at the original deadline, not a new one.
    fixture.fault("P.preflight.stall");
    let began = std::time::Instant::now();
    let error = runtime
        .prepare(
            &token(instance),
            &spec(),
            Instant::now() + Duration::from_millis(300),
            &no_cancel(),
        )
        .await
        .unwrap_err();
    assert!(began.elapsed() < Duration::from_millis(2500), "{error}");
    fixture.clear("P.preflight.stall");
}

#[tokio::test]
async fn exit1_absolute_wire_deadlines_end_start_authority_after_c2() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into(), "marker:work.xfs".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    // The claim commits, and L holds the reply past the 300 ms deadline.
    fixture.fault("L.admit.after_commit.stall");
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        create_operation(&context, &plan),
        crate::helper::monotonic_ns().unwrap() + 300_000_000,
        300,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Create(reply) => {
            assert_eq!(class_of(&reply), AmbiguousClass::Pending);
        }
        other => panic!("{other:?}"),
    }
    fixture.wait_reached("L.admit.after_commit").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.clear("L.admit.after_commit.stall");
    wait_until("the expired start's stop record", || {
        fixture.count("SELECT COUNT(*) FROM allocations WHERE phase = 'stop_intent'") == 1
    })
    .await;
    wait_until("its never-started permit", || {
        fixture.count(
            "SELECT COUNT(*) FROM worker_intents WHERE mode = 'supervisor'
             AND settlement = 'never-started' AND pid IS NULL",
        ) == 1
    })
    .await;
    // No S, subtree or effect was ever started, and the claim is exactly as durable.
    let census = fixture.census().await;
    assert!(census["supervisors"][context.allocation_id.to_string()].is_null());
    assert!(!fixture.fake_dir(&context).exists());
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
    // An expired retry gets no success out of the earlier commit.
    let past = crate::helper::monotonic_ns().unwrap() - 1_000_000_000;
    let expired = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        create_operation(&context, &plan),
        past,
        1_000,
    )
    .await
    .unwrap();
    match expired {
        FirecrackerResponse::Create(reply) => {
            assert_eq!(class_of(&reply), AmbiguousClass::Expired);
        }
        other => panic!("{other:?}"),
    }
    // Cleanup authority is separate: the token still reaches its fence.
    fenced(
        runtime
            .fence_absent(&context, &plan.plan_digest(), deadline(10), &no_cancel())
            .await
            .unwrap(),
    );
    assert_eq!(node_totals(&runtime).await.claimed.slots, 0);
}

#[tokio::test]
async fn exit1_absolute_wire_deadlines_end_forward_effects_inside_s() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["marker:work.xfs".into(), "marker:identity.bin".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    fixture.fault("S.effect.work.xfs.stall");
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        create_operation(&context, &plan),
        crate::helper::monotonic_ns().unwrap() + 1_000_000_000,
        1_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        reply,
        FirecrackerResponse::Create(CreateReply::Accepted { .. })
    ));
    fixture.wait_reached("S.effect.work.xfs").await;
    // The deadline passes during the first effect. That one finishes; no other begins.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    fixture.clear("S.effect.work.xfs.stall");
    wait_until_supervisor_exit(&fixture, &context).await;
    let directory = fixture.fake_dir(&context);
    assert!(directory.join("work.xfs").exists());
    assert!(!directory.join("identity.bin").exists());
    wait_until("the stop record", || {
        fixture.count("SELECT COUNT(*) FROM allocations WHERE phase = 'stop_intent'") == 1
    })
    .await;
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
}

#[tokio::test]
async fn exit1_a_start_that_expires_in_c3_opens_no_gate() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["vm".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    // M acknowledges nothing, so C3's first handoff uses up the original deadline.
    let monitor = fixture.census().await["monitor"].as_i64().unwrap();
    signal(monitor, libc::SIGSTOP);
    let reply = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        create_operation(&context, &plan),
        crate::helper::monotonic_ns().unwrap() + 800_000_000,
        800,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Create(reply) => {
            let class = class_of(&reply);
            assert!(
                matches!(class, AmbiguousClass::Expired | AmbiguousClass::Pending),
                "{class:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    signal(monitor, libc::SIGCONT);
    wait_until_supervisor_exit(&fixture, &context).await;
    let census = fixture.census().await;
    assert!(
        census["supervisors"][context.allocation_id.to_string()]["vm"].is_null(),
        "a gate that never opened started nothing"
    );
    assert!(!fixture.fake_dir(&context).exists());
    assert_eq!(node_totals(&runtime).await.claimed.slots, 1);
}

#[tokio::test]
async fn exit1_a_full_operation_budget_keeps_four_slots_for_recovery_only() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let epoch = epoch_of(&runtime).await;
    // Sixty-four silent connections, replaced as each hits its two-second framing bound.
    // These occupy framing capacity only: nothing has classified them as an operation.
    let socket = fixture.root.join("helper.sock");
    let silent: Vec<_> = (0..64)
        .map(|_| {
            let socket = socket.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok(mut stream) = UnixStream::connect(&socket).await {
                        let mut byte = [0u8; 1];
                        let _ = stream.read(&mut byte).await;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let began = std::time::Instant::now();
    let mut answered = 0;
    while began.elapsed() < Duration::from_secs(3) {
        let round = std::time::Instant::now();
        let reply = raw_call(
            &fixture,
            instance,
            Some(epoch),
            FirecrackerOperation::Inspect {
                allocation_id: Id128::random(),
            },
            wire_deadline(5),
            5_000,
        )
        .await
        .expect("a recovery request gets through under the silent flood");
        assert!(
            round.elapsed() < Duration::from_secs(5),
            "{:?}",
            round.elapsed()
        );
        assert!(
            matches!(
                reply,
                FirecrackerResponse::Inspect(InspectReply::Unknown { .. })
            ),
            "{reply:?}"
        );
        answered += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(answered >= 3, "{answered}");
    // A new attachment is not an operation, and gets through as well.
    let other = fixture.runtime(Id128::random(), Id128::random());
    assert!(other.version(deadline(5), &no_cancel()).await.is_ok());
    for task in silent {
        task.abort();
    }

    // Saturated normal operations: all sixty held open, inside H, on real connections.
    fixture.fault("H.list.hold");
    let held: Vec<_> = (0..60)
        .map(|_| {
            let socket = socket.clone();
            tokio::spawn(async move {
                let request = Request {
                    version: VERSION,
                    timeout_ms: 20_000,
                    deadline_ns: wire_deadline(20),
                    operation: Operation::Firecracker(FirecrackerRequest {
                        group_version: FIRECRACKER_GROUP_VERSION,
                        instance_id: instance,
                        connection_epoch: Some(epoch),
                        operation: FirecrackerOperation::List,
                    }),
                };
                let mut stream = UnixStream::connect(&socket).await.unwrap();
                fds::send(&stream, &[]).await.unwrap();
                write_frame(&mut stream, &request).await.unwrap();
                assert!(fds::receive(&stream).await.unwrap().is_empty());
                read_frame::<Response>(&mut stream).await.unwrap()
            })
        })
        .collect();
    let normal = || {
        raw_call(
            &fixture,
            instance,
            Some(epoch),
            FirecrackerOperation::Accounting,
            wire_deadline(2),
            2_000,
        )
    };
    // Let all sixty take their slots first: a probe racing them would take one itself.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut full = false;
    for _ in 0..500 {
        if matches!(
            normal().await.unwrap(),
            FirecrackerResponse::Error(GroupError {
                kind: GroupErrorKind::ResourceExhausted,
                ..
            })
        ) {
            full = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(full, "a sixty-first normal operation must find no slot");
    assert!(held.iter().all(|task| !task.is_finished()));
    // Recovery still has its reserve, four at once, with every normal slot occupied.
    let mut inspections = Vec::new();
    for _ in 0..4 {
        inspections.push(raw_call(
            &fixture,
            instance,
            Some(epoch),
            FirecrackerOperation::Inspect {
                allocation_id: Id128::random(),
            },
            wire_deadline(5),
            5_000,
        ));
    }
    for inspection in inspections {
        assert!(matches!(
            inspection.await.unwrap(),
            FirecrackerResponse::Inspect(InspectReply::Unknown { .. })
        ));
    }
    assert!(timed_capabilities(&runtime, &fixture).await.enabled);
    assert!(matches!(
        normal().await.unwrap(),
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::ResourceExhausted,
            ..
        })
    ));
    fixture.clear("H.list.hold");
    // All sixty now reach L at once. Its bounded queue may refuse some honestly.
    for task in held {
        assert!(
            matches!(
                task.await.unwrap(),
                Response::Firecracker(
                    FirecrackerResponse::List(_)
                        | FirecrackerResponse::Error(GroupError {
                            kind: GroupErrorKind::Unavailable,
                            ..
                        })
                )
            ),
            "a held operation ended in something other than its answer"
        );
    }
    // Slots came back: the same normal request now runs.
    assert!(matches!(
        normal().await.unwrap(),
        FirecrackerResponse::Accounting(_)
    ));
}

#[tokio::test]
async fn exit1_prepared_wire_is_reconstructed_and_verified_field_by_field() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let reply = match raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Preflight {
            allocation_id: context.allocation_id,
            sandbox_id: context.sandbox_id.clone(),
            profile: PROFILE.into(),
            spec: spec(),
        },
        wire_deadline(10),
        10_000,
    )
    .await
    .unwrap()
    {
        FirecrackerResponse::Prepared(reply) => *reply,
        other => panic!("{other:?}"),
    };
    use crate::runtime::firecracker::test_verify_prepared as verify;
    let accepted = verify(&context, &spec(), reply.clone()).unwrap();
    assert_eq!(accepted.plan_digest(), reply.plan_digest);
    assert_eq!(accepted.reservation().memory_bytes, 896 * MIB);
    assert_eq!(
        accepted.regime(),
        crate::runtime::EvidenceRegime::AbsenceFenced {
            node_id: reply.node_id
        }
    );
    let mutations: Vec<(&str, Box<dyn Fn(&mut PreparedReply)>)> = vec![
        ("version", Box::new(|r| r.plan_version = 2)),
        ("plan bytes", Box::new(|r| r.plan.0.push(b' '))),
        ("digest", Box::new(|r| r.plan_digest = Digest::of(b"x"))),
        ("profile", Box::new(|r| r.profile = "other".into())),
        (
            "manifest",
            Box::new(|r| r.manifest_sha256 = Digest::of(b"x")),
        ),
        ("node", Box::new(|r| r.node_id = Id128::random())),
        (
            "host digest",
            Box::new(|r| r.host_spec_sha256 = Digest::of(b"x")),
        ),
        (
            "guest digest",
            Box::new(|r| r.guest_exec_spec_sha256 = Digest::of(b"x")),
        ),
        (
            "reservation",
            Box::new(|r| r.reservation = ResourceReservation::default()),
        ),
        (
            "smaller charge",
            Box::new(|r| r.reservation.memory_bytes = 1),
        ),
        (
            "fixture schema",
            Box::new(|r| {
                let path = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/firecracker/plan.json"
                );
                let raw = std::fs::read(path).unwrap();
                r.plan_digest = Digest::of(&raw);
                r.plan.0 = raw;
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut bad = reply.clone();
        mutate(&mut bad);
        assert!(
            verify(&context, &spec(), bad).is_err(),
            "{name} was accepted"
        );
    }
    // The right plan for the wrong token or spec.
    assert!(verify(&token(instance), &spec(), reply.clone()).is_err());
    let mut other_spec = spec();
    other_spec.labels.insert("a".into(), "b".into());
    assert!(verify(&context, &other_spec, reply).is_err());
}

#[test]
fn exit1_group_wire_bytes_are_strict_and_bounded() {
    // Fixed-size digests and IDs, lowercase only, and an exact byte-field form.
    let request: FirecrackerOperation = serde_json::from_value(json!({"inspect": {
        "allocation_id": "ab".repeat(16)
    }}))
    .unwrap();
    assert!(matches!(request, FirecrackerOperation::Inspect { .. }));
    for bad in ["", "AB", "abc", "zz"] {
        assert!(serde_json::from_value::<PlanBytes>(json!(bad)).is_err() || bad.is_empty());
    }
    let too_big = "00".repeat(crate::runtime::MAX_BACKEND_PLAN_BYTES + 1);
    assert!(serde_json::from_value::<PlanBytes>(json!(too_big)).is_err());
    let receipt_too_big = "00".repeat(crate::runtime::MAX_RECEIPT_BYTES + 1);
    assert!(serde_json::from_value::<ReceiptBytes>(json!(receipt_too_big)).is_err());
    let bytes: PlanBytes = serde_json::from_value(json!("00ff")).unwrap();
    assert_eq!(bytes.0, [0x00, 0xff]);
    assert_eq!(serde_json::to_value(&bytes).unwrap(), json!("00ff"));
    // No field in the group can carry a descriptor, path, UID, CID, PID, command or env.
    let names = serde_json::to_string(&FirecrackerRequest {
        group_version: 1,
        instance_id: Id128::from_bytes([1; 16]),
        connection_epoch: None,
        operation: FirecrackerOperation::AttachInstance {
            database_uuid: Id128::from_bytes([2; 16]),
        },
    })
    .unwrap();
    assert!(names.contains("database_uuid"));
    // Every timeout budget is the table's.
    assert_eq!(FirecrackerOperation::Capabilities.timeout_ms(), 2_000);
    assert_eq!(FirecrackerOperation::Accounting.timeout_ms(), 5_000);
    assert_eq!(FirecrackerOperation::List.timeout_ms(), 30_000);
}

#[test]
fn exit1_legacy_kiln_request_and_reply_bytes_are_unchanged() {
    // Golden encodings from protocol v3 as landed in B2. Changing one needs a whole
    // helper protocol bump, not a silent broadening of the kiln contract.
    let cases: Vec<(KilnRequest, &str)> = vec![
        (KilnRequest::Ls, r#""ls""#),
        (
            KilnRequest::Capabilities { id: None },
            r#"{"capabilities":{"id":null}}"#,
        ),
        (
            KilnRequest::Capabilities {
                id: Some("abcd".into()),
            },
            r#"{"capabilities":{"id":"abcd"}}"#,
        ),
        (
            KilnRequest::Rm { id: "abcd".into() },
            r#"{"rm":{"id":"abcd"}}"#,
        ),
        (
            KilnRequest::Gc {
                ids: vec!["abcd".into()],
            },
            r#"{"gc":{"ids":["abcd"]}}"#,
        ),
        (
            KilnRequest::Exec {
                id: "abcd".into(),
                argv: vec!["true".into()],
                stdin_bytes: 1,
                max_output: 2,
            },
            r#"{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":1,"max_output":2}}"#,
        ),
    ];
    for (request, operation) in cases {
        let bytes = serde_json::to_string(&Request {
            version: 3,
            timeout_ms: 1000,
            deadline_ns: 5,
            operation: Operation::Kiln(request),
        })
        .unwrap();
        assert_eq!(
            bytes,
            format!(
                r#"{{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{{"kiln":{operation}}}}}"#
            )
        );
    }
    let replies: Vec<(Response, &str)> = vec![
        (Response::Version("v".into()), r#"{"version":"v"}"#),
        (Response::Validated, r#""validated""#),
        (Response::Created("id".into()), r#"{"created":"id"}"#),
        (Response::Removed, r#""removed""#),
        (
            Response::Listed(vec![WireSandbox {
                id: "a".into(),
                stale: true,
            }]),
            r#"{"listed":[{"id":"a","stale":true}]}"#,
        ),
        (
            Response::Collected(vec!["a".into()]),
            r#"{"collected":["a"]}"#,
        ),
        (
            Response::Executed {
                finish: WireFinish::Completed,
                status: None,
                stdout: CaptureInfo {
                    kept: 1,
                    total: 2,
                    known: true,
                    truncated: false,
                },
                stderr: CaptureInfo {
                    kept: 0,
                    total: 0,
                    known: true,
                    truncated: false,
                },
            },
            r#"{"executed":{"finish":"completed","status":null,"stdout":{"kept":1,"total":2,"known":true,"truncated":false},"stderr":{"kept":0,"total":0,"known":true,"truncated":false}}}"#,
        ),
        (
            Response::Error {
                error: WireError::Incompatible("x".into()),
                definitely_not_created: true,
            },
            r#"{"error":{"error":{"incompatible":"x"},"definitely_not_created":true}}"#,
        ),
    ];
    for (reply, golden) in replies {
        assert_eq!(serde_json::to_string(&reply).unwrap(), golden);
    }
    // A kiln frame's parser stays exactly as it was: not the group's strict JSON.
    let mut request = serde_json::to_value(Request {
        version: 3,
        timeout_ms: 1000,
        deadline_ns: 5,
        operation: Operation::Kiln(KilnRequest::Ls),
    })
    .unwrap();
    request["operation"] = json!({"firecracker": {"group_version": 1}});
    assert!(serde_json::from_value::<Request>(request).is_err());
}

#[tokio::test]
async fn exit1_legacy_kiln_still_runs_with_the_group_enabled_and_disabled_by_default() {
    use crate::runtime::{Runtime, kiln::KilnRuntime};
    // Default: no policy. The group answers Disabled and kiln frames work untouched.
    let temp = tempfile::Builder::new()
        .prefix("b3")
        .tempdir_in("/tmp")
        .unwrap();
    let path = temp.path().join("helper.sock");
    let stop = CancellationToken::new();
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let server = tokio::spawn(crate::helper::serve(
        tokio::net::UnixListener::bind(&path).unwrap(),
        uid,
        temp.path().join("missing-kiln"),
        stop.clone(),
    ));
    let client = Client {
        path: path.clone(),
        expected_uid: uid,
    };
    let instance = Id128::random();
    let group = |operation| FirecrackerRequest {
        group_version: FIRECRACKER_GROUP_VERSION,
        instance_id: instance,
        connection_epoch: Some(Id128::random()),
        operation,
    };
    match client
        .firecracker(
            group(FirecrackerOperation::Capabilities),
            deadline(2),
            &no_cancel(),
        )
        .await
        .unwrap()
    {
        FirecrackerResponse::Capabilities(reply) => {
            assert!(!reply.enabled && !reply.launch_enabled);
            assert!(reply.profiles.is_empty());
            assert!(reply.health.is_none());
        }
        other => panic!("{other:?}"),
    }
    for operation in [
        FirecrackerOperation::Accounting,
        FirecrackerOperation::List,
        FirecrackerOperation::Inspect {
            allocation_id: Id128::random(),
        },
    ] {
        assert!(matches!(
            client
                .firecracker(group(operation), deadline(2), &no_cancel())
                .await
                .unwrap(),
            FirecrackerResponse::Error(GroupError {
                kind: GroupErrorKind::Disabled,
                ..
            })
        ));
    }
    let disabled =
        FirecrackerRuntime::with_helper_uid(path.clone(), uid, instance, Id128::random());
    assert!(matches!(
        disabled.version(deadline(2), &no_cancel()).await,
        Err(RuntimeError::Incompatible(_))
    ));
    // A real kiln request gets its usual typed failure for the missing kiln executable.
    let reply = client
        .call(KilnRequest::Ls, deadline(2), &no_cancel())
        .await
        .unwrap();
    assert!(matches!(reply, Response::Error { .. }), "{reply:?}");
    // A duplicate key in a kiln frame still parses as before (and reaches its error).
    let mut stream = UnixStream::connect(&path).await.unwrap();
    fds::send(&stream, &[]).await.unwrap();
    let frame = format!(
        r#"{{"version":3,"timeout_ms":1000,"deadline_ns":{},"operation":{{"kiln":{{"create":{{"spec":{{"image":"alpine","memory_bytes":67108864,"cpu_millis":1000,"pids":64,"disk_bytes":16777216,"network":"none","read_only_root":false,"writable_paths":[],"labels":{{"a":"1","a":"2"}}}}}}}}}}}}"#,
        wire_deadline(1),
    );
    stream.write_u32(frame.len() as u32).await.unwrap();
    stream.write_all(frame.as_bytes()).await.unwrap();
    assert!(fds::receive(&stream).await.unwrap().is_empty());
    assert!(matches!(
        read_frame::<Response>(&mut stream).await.unwrap(),
        Response::Error { .. }
    ));
    stop.cancel();
    server.await.unwrap().unwrap();
    let _ = KilnRuntime::new(path).name();
}

#[tokio::test]
async fn exit1_preflight_or_listing_needs_no_session_side_effect_and_no_ready_exists() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    // Every Create outcome here is ambiguous from the caller's side: B3 has no READY.
    let failure = runtime
        .create(&context, &plan, deadline(10), &no_cancel())
        .await
        .unwrap_err();
    assert_eq!(failure.certainty(), CreateCertainty::AllocationAmbiguous);
    assert!(failure.absence().is_none());
    assert!(failure.to_string().contains("no VM launch"), "{failure}");
    let capabilities = timed_capabilities(&runtime, &fixture).await;
    assert!(!capabilities.launch_enabled);
    assert_eq!(capabilities.profiles, [PROFILE]);
    // The inventory marks it Busy and complete, with its real fake namespace absent.
    wait_until_listed_complete(&runtime).await;
    let listed = runtime.list(deadline(5), &no_cancel()).await.unwrap();
    assert_eq!(listed.records.len(), 1);
    assert_eq!(listed.records[0].status, BackendStatus::Busy);
    assert_eq!(listed.records[0].allocation_id, Some(context.allocation_id));
    assert_eq!(listed.records[0].plan_digest, Some(plan.plan_digest()));
    assert!(listed.complete);
    // An unexplained resource blocks a complete answer, and a missing record there is
    // no evidence of absence.
    let stray = fake::allocation_dir(&fixture.root.join("fake"), instance, Id128::random());
    std::fs::create_dir_all(&stray).unwrap();
    let listed = runtime.list(deadline(5), &no_cancel()).await.unwrap();
    assert!(!listed.complete);
    std::fs::remove_dir_all(stray).unwrap();
    // Another instance's list holds nothing of this one's, and it stays complete.
    let other = fixture.runtime(Id128::random(), Id128::random());
    let listed = other.list(deadline(5), &no_cancel()).await.unwrap();
    assert!(listed.records.is_empty());
    let foreign = other
        .inspect_allocation(
            &CreateContext {
                instance_id: other.test_instance(),
                ..context.clone()
            },
            &plan.plan_digest(),
            deadline(5),
            &no_cancel(),
        )
        .await
        .unwrap();
    assert!(
        matches!(foreign, AllocationObservation::Unknown { .. }),
        "another namespace's token must look unknown: {foreign:?}"
    );
    // Node totals do count it, without naming it.
    let totals = serde_json::to_string(&node_totals(&other).await).unwrap();
    assert!(!totals.contains(&context.allocation_id.to_string()));
    assert!(!totals.contains(&context.sandbox_id));
    assert!(totals.contains("\"slots\":1"));
    // The accepted token is present and busy to its owner, which is no readiness.
    let inspected = raw_call(
        &fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Inspect {
            allocation_id: context.allocation_id,
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            &inspected,
            FirecrackerResponse::Inspect(InspectReply::PresentBusy { phase, .. }) if phase == "preparing"
        ),
        "{inspected:?}"
    );
    assert!(matches!(
        runtime
            .inspect_allocation(&context, &plan.plan_digest(), deadline(5), &no_cancel())
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    // Unsupported until B4/B5, never a fake success.
    assert!(matches!(
        runtime
            .validate_sandbox("fc-x", deadline(1), &no_cancel())
            .await,
        Err(RuntimeError::Unsupported(_))
    ));
    assert!(matches!(
        runtime.remove("fc-x", deadline(1), &no_cancel()).await,
        Err(RuntimeError::Unsupported(_))
    ));
    assert!(
        runtime
            .gc(&[], deadline(1), &no_cancel())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        runtime
            .gc(&["fc-x".into()], deadline(1), &no_cancel())
            .await
            .is_err()
    );
}

async fn wait_until_listed_complete(runtime: &FirecrackerRuntime) {
    for _ in 0..500 {
        if runtime
            .list(deadline(5), &no_cancel())
            .await
            .is_ok_and(|listed| listed.complete)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the inventory never became complete");
}

#[test]
fn exit1_production_gate_leaves_every_catalog_profile_refused() {
    let (_temp, root, config) = prepare_tree(NodeOptions::default());
    let walk = walk_for(&root);
    let error = load_profile(&walk, ManifestGate::ProductionDisabled, &config.catalog).unwrap_err();
    assert!(error.contains("production disabled"), "{error}");
    // Only the test gate gets further, and it still requires the whole catalog.
    let loaded = load_profile(&walk, ManifestGate::TestApproved, &config.catalog).unwrap();
    assert_eq!(loaded.table.vector().len(), all_pins().len());
    let mut wrong = config.catalog.clone();
    wrong.approved_manifest_sha256 = Digest::of(b"other");
    assert!(load_profile(&walk, ManifestGate::TestApproved, &wrong).is_err());
    // There is no route from policy to a non-production gate.
    let source = include_str!("mod.rs");
    let production = source
        .split("pub fn production_config")
        .nth(1)
        .unwrap()
        .split("pub fn read_policy")
        .next()
        .unwrap();
    assert!(!production.contains("TestApproved"));
    assert!(production.contains("ManifestGate::ProductionDisabled"));
    // The daemon's entry point still has no way to select this backend.
    let main = include_str!("../../main.rs").to_lowercase();
    assert!(!main.contains("firecracker"));
}

#[tokio::test]
async fn exit6_tight_fence_allowance_stops_new_tokens_end_to_end() {
    let allowance =
        (super::journal::PRE_INTENT_TOKEN_MARGIN + 2) * super::journal::FENCE_ENTRY_BOUND;
    let fixture = Fixture::new(NodeOptions {
        fence_allowance_bytes: Some(allowance),
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let first = token(instance);
    let first_plan = prepared(&runtime, &first).await;
    create_accepted(&fixture, &runtime, &first, &first_plan).await;
    let second = token(instance);
    let second_plan = prepared(&runtime, &second).await;
    create_accepted(&fixture, &runtime, &second, &second_plan).await;
    // A third token is refused at C0, before it could ever need a fence.
    let error = runtime
        .prepare(&token(instance), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("headroom"), "{error}");
    // Those accepted ones can still fence.
    for (context, plan) in [(&first, &first_plan), (&second, &second_plan)] {
        fenced(
            runtime
                .fence_absent(context, &plan.plan_digest(), deadline(10), &no_cancel())
                .await
                .unwrap(),
        );
    }
}

/// The installed code path, as root: real policy parsing from a protected directory,
/// one-time provisioning, and a production configuration that serves no profile.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root on Linux: run in the VM"]
fn exit5_linux_root_production_policy_provisions_once_and_serves_no_profile() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    let root = PathBuf::from(format!("/var/lib/kilnd-b3-policy-{}", std::process::id()));
    private_dir(&root);
    let ledger = root.join("ledger");
    private_dir(&ledger);
    let profile = json!({
        "profile": PROFILE,
        "approved_manifest_sha256": Digest::of(b"never approved").to_string(),
        "bundle_directory": root.join("bundle"),
        "exec_store": root.join("exec"),
        "catalog_generation": 1,
        "installation_generations": {"jailer": 1, "firecracker": 1, "mkfs.xfs": 1, "kilnd-helper": 1},
    });
    let policy = json!({
        "schema": super::config::POLICY_SCHEMA,
        "node_id": Id128::random().to_string(),
        "ledger_dir": ledger,
        "ceilings": NodeCeilings::default(),
        "uid_range": {"first": 300000, "last": 365535},
        "gid_range": {"first": 300000, "last": 365535},
        "cid_range": {"first": 3, "last": 65535},
        "profiles": [profile],
    });
    let path = root.join("policy.json");
    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let parsed = super::read_policy(&path, 999).unwrap();
    super::provision_ledger(&parsed).unwrap();
    assert!(
        super::provision_ledger(&parsed).is_err(),
        "provisioning happens once"
    );
    let config = super::production_config(parsed, 999);
    assert!(
        config.profiles.is_empty(),
        "the disabled gate leaves no profile"
    );
    assert!(config.helper_image.is_none());
    assert_eq!(config.gate, ManifestGate::ProductionDisabled);
    assert_eq!(config.observation, ObservationBackend::Disabled);
    drop(config);
    // A writable ancestor refuses the policy itself.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o720)).unwrap();
    assert!(super::read_policy(&path, 999).is_err());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn fixture_child_does_nothing_without_its_environment() {
    assert!(std::env::var(FIXTURE_ENV).is_err());
    node_fixture_child();
}

mod control_plane;
