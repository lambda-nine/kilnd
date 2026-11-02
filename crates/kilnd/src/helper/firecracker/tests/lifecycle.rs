//! B4's exit criteria against the real chain, as root in the VM: the patched jailer,
//! the release Firecracker VMM, the static formatter and this static test binary as
//! the helper image, all installed in the protected store and executed by retained
//! descriptor. The guest is the schema-1 kiln-guest kernel and root, which listen for
//! nothing; production READY needs B5's broker, so a boot ends at BOOTING. Approval is
//! the test-only gate. `scripts/b4-vm-tests.sh` prepares the artifacts and runs these.
use super::*;
use crate::helper::firecracker::executable::ExecutablePin;
use crate::helper::firecracker::protocol::{GcOutcome, StopReason, StopReply};
use crate::helper::firecracker::storage;
use crate::helper::firecracker::workers::{ProcessId, ProcessState};
use std::os::unix::fs::MetadataExt;

const ARTIFACTS_ENV: &str = "KILND_B4_ARTIFACTS";
pub(super) const STORE: &str = "/opt/kilnd/exec/sha256";
const BUNDLES: &str = "/opt/kilnd/b4-bundles";

fn artifacts() -> PathBuf {
    PathBuf::from(std::env::var(ARTIFACTS_ENV).expect("KILND_B4_ARTIFACTS names the artifacts"))
}

fn root_dir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    std::os::unix::fs::chown(path, Some(0), Some(0)).unwrap();
}

fn digest_file(path: &Path) -> (u64, Digest) {
    let file = std::fs::File::open(path).unwrap();
    let bytes = file.metadata().unwrap().len();
    (
        bytes,
        super::super::executable::hash_descriptor(&file, bytes).unwrap(),
    )
}

/// Installs one role into the protected store from an authenticated source.
pub(super) fn install(role: Role, source: &Path) -> ExecutablePin {
    let (bytes, sha256) = digest_file(source);
    let pin = ExecutablePin {
        role,
        bytes,
        sha256,
        installation_generation: 1,
    };
    root_dir(Path::new("/opt/kilnd"), 0o755);
    root_dir(Path::new("/opt/kilnd/exec"), 0o700);
    root_dir(Path::new(STORE), 0o700);
    executable::publish_object(
        &WalkPolicy::production(),
        Path::new(STORE),
        &std::fs::File::open(source).unwrap(),
        &pin,
    )
    .unwrap();
    pin
}

pub(super) fn installed_path(pin: &ExecutablePin) -> PathBuf {
    Path::new(STORE)
        .join(pin.sha256.to_string())
        .join(pin.role.as_str())
}

/// Every source the real chain runs, named by role.
pub(super) fn sources() -> BTreeMap<Role, PathBuf> {
    let dir = artifacts();
    BTreeMap::from([
        (Role::Jailer, dir.join("jailer")),
        (Role::Firecracker, dir.join("firecracker")),
        (Role::MkfsXfs, dir.join("mkfs.xfs")),
        (Role::KilndHelper, std::env::current_exe().unwrap()),
    ])
}

/// A production-shaped schema 2 manifest binding the real kernel, root and executables.
fn real_manifest(pins: &BTreeMap<Role, ExecutablePin>, bundle: &Path) -> Vec<u8> {
    let raw = std::fs::read(bundle_source("manifest.json")).unwrap();
    let mut manifest = crate::firecracker::strict_json(&raw).unwrap();
    manifest["schema"] = json!(2);
    manifest["fixture_only"] = json!(false);
    manifest["inputs"]["provenance"] = json!("b4-test-injected-catalog");
    for name in [
        "Image",
        "rootfs.squashfs",
        "kernel.config",
        "kiln",
        "kilnd-guest-broker",
    ] {
        let (bytes, sha256) = digest_file(&bundle.join(name));
        manifest["artifacts"][name] = json!({"bytes": bytes, "sha256": sha256.to_string()});
    }
    for (role, pin) in pins {
        manifest["executables"][role.as_str()]["bytes"] = json!(pin.bytes);
        manifest["executables"][role.as_str()]["sha256"] = json!(pin.sha256.to_string());
    }
    crate::firecracker::canonical(&manifest).unwrap()
}

/// The real tree: store objects, a bundle and a fixture root whose helper runs from
/// the installed image. Each fixture gets its own bundle directory.
fn real_tree(options: NodeOptions) -> (tempfile::TempDir, PathBuf, ChildConfig) {
    let temp = tempfile::Builder::new()
        .prefix("b4")
        .tempdir_in("/tmp")
        .unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["ledger", "faults", "peers", "fake"] {
        private_dir(&root.join(name));
    }
    let mut pins = BTreeMap::new();
    for (role, source) in sources() {
        pins.insert(role, install(role, &source));
    }
    root_dir(Path::new(BUNDLES), 0o755);
    let bundle = Path::new(BUNDLES).join(Id128::random().to_string());
    root_dir(&bundle, 0o755);
    for name in ["Image", "rootfs.squashfs"] {
        std::fs::copy(artifacts().join(name), bundle.join(name)).unwrap();
    }
    for name in ["kernel.config", "kiln", "kilnd-guest-broker"] {
        std::fs::copy(bundle_source(name), bundle.join(name)).unwrap();
    }
    let manifest = real_manifest(&pins, &bundle);
    std::fs::write(bundle.join("manifest.json"), &manifest).unwrap();
    for entry in std::fs::read_dir(&bundle).unwrap() {
        let path = entry.unwrap().path();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::os::unix::fs::chown(&path, Some(0), Some(0)).unwrap();
    }
    let config = ChildConfig {
        root: root.clone(),
        node_id: Id128::random(),
        catalog: ProfileCatalog {
            profile: PROFILE.into(),
            approved_manifest_sha256: Digest::of(&manifest),
            bundle_directory: bundle,
            exec_store: PathBuf::from(STORE),
            catalog_generation: 1,
            installation_generations: Role::ALL.iter().map(|role| (*role, 1)).collect(),
        },
        options: NodeOptions {
            real: true,
            ..options
        },
    };
    std::fs::write(
        root.join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("helper-image"),
        installed_path(&pins[&Role::KilndHelper]).to_str().unwrap(),
    )
    .unwrap();
    (temp, root, config)
}

pub(super) struct Real {
    pub fixture: Fixture,
    pub bundle: PathBuf,
}

impl Drop for Real {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.bundle);
    }
}

impl Real {
    pub async fn new(options: NodeOptions) -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
        // scripts/b4-vm-tests.sh starts this process with only the helper unit's bounding
        // set, so every thread, client and child holds no more than the unit grants.
        limit_to_unit_capabilities();
        let (temp, root, config) = real_tree(options);
        std::fs::write(root.join("faults/L.keep_launch_capabilities"), b"").unwrap();
        Ledger::provision(&ledger_config(&config)).unwrap();
        let fixture = Fixture {
            temp,
            root,
            child: Mutex::new(None),
            seen: Mutex::default(),
        };
        fixture.start().await;
        if let Ok(error) = std::fs::read_to_string(fixture.root.join("start-error")) {
            panic!("the real helper did not start: {error}");
        }
        Self {
            fixture,
            bundle: config.catalog.bundle_directory,
        }
    }

    fn phase(&self, allocation: Id128) -> String {
        self.fixture.read(|view| {
            view.query_row(
                "SELECT phase FROM allocations WHERE allocation_id = ?1",
                [allocation.to_string()],
                |r| r.get(0),
            )
        })
    }

    fn resources(&self, allocation: Id128) -> Vec<super::super::supervisor::ResourceRecord> {
        self.fixture.read(|view| {
            let mut statement = view.prepare(
                "SELECT detail FROM resource_events WHERE allocation_id = ?1 ORDER BY generation",
            )?;
            let rows = statement
                .query_map([allocation.to_string()], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows
                .into_iter()
                .map(|text| serde_json::from_str(&text).unwrap())
                .collect())
        })
    }

    fn vmm(&self, allocation: Id128) -> Option<ProcessId> {
        self.resources(allocation)
            .into_iter()
            .find_map(|record| match record {
                super::super::supervisor::ResourceRecord::Vmm { process, .. } => Some(process),
                _ => None,
            })
    }

    /// Expected and observed tuples for one role, from the journal's lease.
    fn lease(&self, allocation: Id128, role: Role) -> (Value, Value) {
        self.fixture.read(|view| {
            view.query_row(
                "SELECT st_dev, st_ino, bytes, sha256, observed_st_dev, observed_st_ino,
                        observed_bytes, observed_sha256
                 FROM executable_leases WHERE allocation_id = ?1 AND role = ?2",
                params![allocation.to_string(), role.as_str()],
                |r| {
                    Ok((
                        json!([
                            r.get::<_, i64>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, String>(3)?
                        ]),
                        json!([
                            r.get::<_, Option<i64>>(4)?,
                            r.get::<_, Option<i64>>(5)?,
                            r.get::<_, Option<i64>>(6)?,
                            r.get::<_, Option<String>>(7)?
                        ]),
                    ))
                },
            )
        })
    }

    /// How the lease's observed tuple is known: `proc_exe` or `retained_fd`.
    fn evidence(&self, allocation: Id128, role: Role) -> Option<String> {
        self.fixture.read(|view| {
            view.query_row(
                "SELECT observation FROM executable_leases WHERE allocation_id = ?1 AND role = ?2",
                params![allocation.to_string(), role.as_str()],
                |r| r.get(0),
            )
        })
    }

    async fn wait_phase(&self, allocation: Id128, phase: &str) {
        let end = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let now = self.phase(allocation);
            if now == phase {
                return;
            }
            assert!(
                std::time::Instant::now() < end,
                "allocation stayed {now}, never {phase}\n{}",
                self.fixture.log()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

use rusqlite::params;
use std::collections::BTreeMap;

/// One accepted real Create, by a fresh attached instance.
pub(super) async fn create(
    real: &Real,
) -> (Arc<FirecrackerRuntime>, CreateContext, PreparedCreate) {
    let instance = Id128::random();
    // The database UUID is the instance ID, so a client after a helper restart can
    // present the same one.
    let runtime = real.fixture.runtime(instance, instance);
    let context = token(instance);
    let plan = prepared(&runtime, &context).await;
    create_accepted(&real.fixture, &runtime, &context, &plan).await;
    (runtime, context, plan)
}

pub(super) async fn remove(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
) -> FenceReply {
    let reply = raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::Remove {
            allocation_id: context.allocation_id,
        },
        wire_deadline(60),
        60_000,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Remove(reply) => reply,
        other => panic!("not a removal: {other:?}"),
    }
}

fn created_generation(real: &Real, allocation: Id128) -> u64 {
    real.fixture.read(|view| {
        view.query_row(
            "SELECT created_generation FROM allocations WHERE allocation_id = ?1",
            [allocation.to_string()],
            |r| r.get::<_, i64>(0),
        )
    }) as u64
}

/// Everything this allocation could own on the host. Empty is the absence barrier's
/// own evidence, read independently of the helper.
pub(super) fn host_leftovers(context: &CreateContext, vmm: Option<ProcessId>) -> Vec<String> {
    let (paths, cgroup) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    let mut left = storage::observe_presence(&paths, &cgroup).unwrap().names;
    if let Some(vmm) = vmm
        && let ProcessState::Running { start_time } = super::super::workers::process_state(vmm.pid)
        && start_time == vmm.start_time
    {
        left.push(format!("vmm:{}", vmm.pid));
    }
    left
}

/// `/proc/<V>/exe` is a ptrace-read check: read it with V's filesystem IDs, as S does.
fn vmm_image(
    real: &Real,
    allocation: Id128,
    pid: i32,
) -> super::super::executable::ExecutableIdentity {
    let (uid, gid) = real.fixture.read(|view| {
        view.query_row(
            "SELECT
               (SELECT value FROM identity_leases WHERE allocation_id = ?1 AND kind = 'vmm_uid'),
               (SELECT value FROM identity_leases WHERE allocation_id = ?1 AND kind = 'vmm_gid')",
            [allocation.to_string()],
            |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u32)),
        )
    });
    super::super::supervisor::as_fs_ids(uid, gid, || {
        executable::observe_process_image(pid, Role::Firecracker, 1).unwrap()
    })
}

fn is_absent(reply: &FenceReply) -> bool {
    matches!(reply, FenceReply::Absent { .. })
}

/// Exit 1, the happy path: the real chain boots to BOOTING with every actual executed
/// identity journaled, the VMM's real credentials match the contract, and Remove
/// reports ABSENT only after nothing owned remains.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_create_boots_and_remove_leaves_nothing() {
    {
        let real = Real::new(NodeOptions::default()).await;
        let (runtime, context, _plan) = create(&real).await;
        real.wait_phase(context.allocation_id, "booting").await;
        let vmm = real.vmm(context.allocation_id).expect("V recorded");
        let status = std::fs::read_to_string(format!("/proc/{}/status", vmm.pid)).unwrap();
        let credentials = storage::parse_status(&status).unwrap();
        assert_eq!(credentials.groups, Vec::<u32>::new());
        assert_eq!(
            (
                credentials.cap_inh,
                credentials.cap_prm,
                credentials.cap_eff,
                credentials.cap_bnd,
                credentials.cap_amb
            ),
            (0, 0, 0, 0, 0)
        );
        assert_eq!((credentials.no_new_privs, credentials.seccomp), (1, 2));
        assert_ne!(
            credentials.uid[0], credentials.gid[0],
            "typed U and G stay distinct"
        );
        for role in [Role::Jailer, Role::Firecracker, Role::MkfsXfs] {
            let (expected, observed) = real.lease(context.allocation_id, role);
            assert_eq!(expected, observed, "{} actual identity", role.as_str());
        }
        // J and V were read from their running images; the short-lived formatter's
        // tuple is the retained descriptor's, recorded as inferred from its confirmed
        // exec, never as observed (B4 break-it finding 5).
        for (role, kind) in [
            (Role::Jailer, "proc_exe"),
            (Role::Firecracker, "proc_exe"),
            (Role::MkfsXfs, "retained_fd"),
        ] {
            assert_eq!(
                real.evidence(context.allocation_id, role).as_deref(),
                Some(kind),
                "{} evidence",
                role.as_str()
            );
        }
        let actual = vmm_image(&real, context.allocation_id, vmm.pid);
        let (expected, _) = real.lease(context.allocation_id, Role::Firecracker);
        assert_eq!(
            json!([
                actual.st_dev,
                actual.st_ino,
                actual.bytes,
                actual.sha256.to_string()
            ]),
            expected
        );
        // Readiness does not exist without the broker.
        assert_eq!(real.phase(context.allocation_id), "booting");
        let reply = remove(&real, &runtime, &context).await;
        assert!(is_absent(&reply), "{reply:?}\n{}", real.fixture.log());
        assert_eq!(host_leftovers(&context, Some(vmm)), Vec::<String>::new());
        // Idempotent: the same receipt again.
        let again = remove(&real, &runtime, &context).await;
        assert_eq!(again, reply);
    }
}

/// B4 recheck finding 4 (was `poc_b4_recheck_preexec_death_falsifies_retained_fd_evidence`):
/// the report pipe's unwritten end of file does not distinguish a successful exec from a
/// child that died before `execveat`. The formatter's tuple is recorded only after its
/// exit status 0, so this child's `_exit(126)` before exec leaves no executable evidence
/// and the launch never boots.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_formatter_death_before_exec_records_no_evidence() {
    let real = Real::new(NodeOptions::default()).await;
    real.fixture.fault("S.formatter_die_before_exec");
    let (runtime, context, _plan) = create(&real).await;
    wait_until("formatter supervisor exit", || {
        worker_pid(&real, context.allocation_id, "supervisor").is_some_and(|s| !running(s))
    })
    .await;
    real.fixture.clear("S.formatter_die_before_exec");
    assert_ne!(real.phase(context.allocation_id), "booting");
    assert_eq!(
        real.evidence(context.allocation_id, Role::MkfsXfs),
        None,
        "the child exited before exec, so no executable evidence is truthful"
    );
    eprintln!("B4 evidence: formatter _exit(126) before execveat: no mkfs evidence recorded");
    remove_to_absent(&real, &runtime, &context, "formatter death before exec").await;
}

// Shared helpers for the exit tests below.

async fn inspect(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    seconds: u64,
) -> InspectReply {
    let reply = raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::Inspect {
            allocation_id: context.allocation_id,
        },
        wire_deadline(seconds),
        (seconds * 1000) as u32,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Inspect(reply) => reply,
        other => panic!("not an inspection: {other:?}"),
    }
}

async fn stop_within(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    seconds: u64,
) -> StopReply {
    let generation = created_generation(real, context.allocation_id);
    let reply = raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::Stop {
            allocation_id: context.allocation_id,
            expected_generation: generation,
            reason: StopReason::Operator,
        },
        wire_deadline(seconds),
        (seconds * 1000) as u32,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Stop(reply) => reply,
        other => panic!("not a stop: {other:?}"),
    }
}

async fn dispatch_admitted(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
) -> bool {
    match raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(runtime).await),
        FirecrackerOperation::TestDispatchProbe {
            allocation_id: context.allocation_id,
        },
        wire_deadline(2),
        2_000,
    )
    .await
    .unwrap()
    {
        FirecrackerResponse::TestDispatch { admitted } => admitted,
        other => panic!("{other:?}"),
    }
}

fn running(process: ProcessId) -> bool {
    matches!(
        super::super::workers::process_state(process.pid),
        ProcessState::Running { start_time } if start_time == process.start_time
    )
}

/// The allocation's `vm` subtree holds no task (or no longer exists).
fn vm_subtree_empty(context: &CreateContext) -> bool {
    let (_, cgroup) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    match super::super::cgroup::open_node(&format!("{cgroup}/vm")) {
        Err(_) => true,
        Ok(node) => !super::super::cgroup::populated(&node).unwrap(),
    }
}

fn worker_pid(real: &Real, allocation: Id128, mode: &str) -> Option<ProcessId> {
    real.fixture.read(|view| {
        use rusqlite::OptionalExtension;
        view.query_row(
            "SELECT pid, start_time FROM worker_intents
             WHERE allocation_id = ?1 AND mode = ?2 AND pid IS NOT NULL ORDER BY id LIMIT 1",
            params![allocation.to_string(), mode],
            |r| {
                Ok(ProcessId {
                    pid: r.get(0)?,
                    start_time: r.get::<_, i64>(1)? as u64,
                })
            },
        )
        .optional()
    })
}

fn claim_held(real: &Real, allocation: Id128) -> bool {
    real.fixture.count(&format!(
        "SELECT COUNT(*) FROM capacity_claims WHERE allocation_id = '{allocation}'
         AND released_generation IS NULL"
    )) == 1
}

fn unsettled(real: &Real, allocation: Id128) -> i64 {
    real.fixture.count(&format!(
        "SELECT COUNT(*) FROM worker_intents WHERE allocation_id = '{allocation}'
         AND settled_generation IS NULL"
    ))
}

async fn restart_helper(real: &Real) {
    if let Some(mut child) = real.fixture.child.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    real.fixture.start().await;
    if let Ok(error) = std::fs::read_to_string(real.fixture.root.join("start-error")) {
        panic!("the restarted helper did not start: {error}");
    }
}

/// Removes and proves the absence barrier: ABSENT, nothing owned on the host, no
/// unsettled worker and the claim released, in that order of evidence.
async fn remove_to_absent(
    real: &Real,
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    label: &str,
) {
    let vmm = real.vmm(context.allocation_id);
    let mut reply = remove(real, runtime, context).await;
    // A helper that was just restarted may still be settling earlier workers.
    for _ in 0..5 {
        if is_absent(&reply) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        reply = remove(real, runtime, context).await;
    }
    assert!(
        is_absent(&reply),
        "{label}: {reply:?}\n{}",
        real.fixture.log()
    );
    assert_eq!(
        host_leftovers(context, vmm),
        Vec::<String>::new(),
        "{label}"
    );
    assert_eq!(unsettled(real, context.allocation_id), 0, "{label}");
    assert!(!claim_held(real, context.allocation_id), "{label}");
    assert_eq!(real.phase(context.allocation_id), "absent", "{label}");
}

/// Exit 1: a crash at every boundary — before each forward step, between each effect
/// and its journal record, after BOOTING, and with the helper itself killed mid-way —
/// is contained and stays charged, and Remove reports ABSENT only when nothing owned
/// remains on the host.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_every_crash_boundary_reaches_absent_with_nothing_left() {
    let real = Real::new(NodeOptions::default()).await;
    let mut boundaries: Vec<String> = [
        "cgroup",
        "join",
        "artifacts",
        "work_dir",
        "work_file",
        "fallocate",
        "mkfs",
        "private_files",
        "loop",
        "loop_configure",
        "jail",
        "jail_mount",
        "binds",
        "spawn_intent",
        "release_jailer",
        "continue_jailer",
        "adopt",
        "harden",
    ]
    .iter()
    .map(|step| format!("S.step.{step}.panic"))
    .collect();
    boundaries.extend(
        [
            "cgroup",
            "work_file",
            "loop_configure",
            "loop_record",
            "jail_record",
            "jail",
            "bind_record",
            "first_bind",
            "binds",
            "fork_jailer",
            "continue_jailer",
            "adopt",
            "harden",
        ]
        .iter()
        .map(|point| format!("S.after.{point}.panic")),
    );
    for boundary in &boundaries {
        real.fixture.fault(boundary);
        let (runtime, context, _plan) = create(&real).await;
        // S dies at the boundary: wait for its exit and the containment that follows.
        wait_until(boundary, || {
            worker_pid(&real, context.allocation_id, "supervisor").is_some_and(|s| !running(s))
        })
        .await;
        real.fixture.clear(boundary);
        assert!(
            claim_held(&real, context.allocation_id),
            "{boundary}: charged until ABSENT"
        );
        assert_ne!(real.phase(context.allocation_id), "booting", "{boundary}");
        wait_until("contained", || vm_subtree_empty(&context)).await;
        remove_to_absent(&real, &runtime, &context, boundary).await;
    }
    // After BOOTING: S killed outright.
    let (runtime, context, _plan) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let supervisor = worker_pid(&real, context.allocation_id, "supervisor").unwrap();
    signal(supervisor.pid as i64, libc::SIGKILL);
    wait_until("contained after S", || vm_subtree_empty(&context)).await;
    remove_to_absent(&real, &runtime, &context, "S killed after BOOTING").await;
    // The helper killed while a boot runs: S and M contain it, and a new helper
    // replays the claim and removes it.
    let (runtime_before, context, _plan) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let vmm = real.vmm(context.allocation_id).unwrap();
    restart_helper(&real).await;
    let runtime = real
        .fixture
        .runtime(context.instance_id, context.instance_id);
    drop(runtime_before);
    wait_until("VMM gone after helper loss", || !running(vmm)).await;
    assert!(claim_held(&real, context.allocation_id));
    remove_to_absent(&real, &runtime, &context, "helper killed while BOOTING").await;
    // The helper killed while S is mid-preparation, stalled inside mkfs's step.
    real.fixture.fault("S.step.mkfs.stall");
    let (runtime, context, _plan) = create(&real).await;
    real.fixture.wait_reached("S.step.mkfs").await;
    drop(runtime);
    restart_helper(&real).await;
    let runtime = real
        .fixture
        .runtime(context.instance_id, context.instance_id);
    real.fixture.clear("S.step.mkfs.stall");
    assert!(claim_held(&real, context.allocation_id));
    remove_to_absent(
        &real,
        &runtime,
        &context,
        "helper killed during preparation",
    )
    .await;
}

/// Exit 2: with H healthy, SIGKILL of S before J exits and after it, each fences at
/// once, contains the VM subtree (including a VMM that appears only after S died) and
/// admits no new dispatch. J's normal zero exit leaves a healthy V running.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_supervisor_death_before_and_after_jailer_exit_fences_and_contains() {
    let real = Real::new(NodeOptions::default()).await;
    // After J exits: V is live, J exited zero, and the boot is reusable until S dies.
    let (runtime, context, _plan) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let vmm = real.vmm(context.allocation_id).unwrap();
    let jailer = worker_pid(&real, context.allocation_id, "jailer").unwrap();
    assert!(!running(jailer), "J exited");
    assert!(running(vmm), "J's zero exit is not V's exit");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(running(vmm), "V stays up after J");
    assert!(
        dispatch_admitted(&real, &runtime, &context).await,
        "healthy boot admits"
    );
    let supervisor = worker_pid(&real, context.allocation_id, "supervisor").unwrap();
    let killed = std::time::Instant::now();
    signal(supervisor.pid as i64, libc::SIGKILL);
    while running(vmm) {
        assert!(killed.elapsed() < Duration::from_secs(5), "V outlived S");
        std::thread::sleep(Duration::from_millis(1));
    }
    let contained_ms = killed.elapsed().as_millis();
    eprintln!("B4 evidence: S killed after J exit -> V exit in {contained_ms} ms");
    assert!(
        !dispatch_admitted(&real, &runtime, &context).await,
        "no dispatch after the fence"
    );
    wait_until("subtree empty", || vm_subtree_empty(&context)).await;
    wait_until("stop intent", || {
        real.phase(context.allocation_id) == "stop_intent"
    })
    .await;
    assert!(claim_held(&real, context.allocation_id));
    remove_to_absent(&real, &runtime, &context, "S killed after J exit").await;

    // Before J exits: J is held stopped with CONT already in its socket, S dies, and
    // only then does J run on to clone V. The precommitted cgroup target contains it.
    real.fixture.fault("S.after.continue_jailer.stall");
    let (runtime, context, _plan) = create(&real).await;
    real.fixture.wait_reached("S.after.continue_jailer").await;
    let jailer = worker_pid(&real, context.allocation_id, "jailer").unwrap();
    signal(jailer.pid as i64, libc::SIGSTOP);
    let supervisor = worker_pid(&real, context.allocation_id, "supervisor").unwrap();
    signal(supervisor.pid as i64, libc::SIGKILL);
    real.fixture.clear("S.after.continue_jailer.stall");
    signal(jailer.pid as i64, libc::SIGCONT);
    wait_until("J gone", || !running(jailer)).await;
    wait_until("subtree empty before J's exit was observed", || {
        vm_subtree_empty(&context)
    })
    .await;
    // Nothing of this boot runs, ever: watch for a while.
    for _ in 0..20 {
        assert!(vm_subtree_empty(&context));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!dispatch_admitted(&real, &runtime, &context).await);
    assert_ne!(real.phase(context.allocation_id), "booting");
    remove_to_absent(&real, &runtime, &context, "S killed before J exit").await;

    // V dies on its own while S lives: fenced, contained, charged.
    let (runtime, context, _plan) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let vmm = real.vmm(context.allocation_id).unwrap();
    signal(vmm.pid as i64, libc::SIGKILL);
    wait_until("fenced on V exit", || {
        real.phase(context.allocation_id) == "stop_intent"
    })
    .await;
    assert!(!dispatch_admitted(&real, &runtime, &context).await);
    assert!(claim_held(&real, context.allocation_id));
    remove_to_absent(&real, &runtime, &context, "V killed").await;
}

/// Exit 3: the real UID, GID, Groups and every capability mask, for an unequal and an
/// equal numeric typed pair; a single bounding bit left set stops the launch before
/// BOOTING and the allocation stays charged until ABSENT.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_real_credentials_and_a_bounding_mismatch_stops_the_launch() {
    for (uid, gid, equal) in [
        ((300_100, 300_101), (300_200, 300_201), false),
        ((300_300, 300_301), (300_300, 300_301), true),
    ] {
        let real = Real::new(NodeOptions {
            uid: Some(uid),
            gid: Some(gid),
            ..NodeOptions::default()
        })
        .await;
        // Two-value ranges give the VMM and relay leases one value each, in a random
        // order: retry until this run's VMM pair is (un)equal as wanted.
        let (runtime, context, plan, vmm, status, credentials) = loop {
            let (runtime, context, plan) = create(&real).await;
            real.wait_phase(context.allocation_id, "booting").await;
            let vmm = real.vmm(context.allocation_id).unwrap();
            let status = std::fs::read_to_string(format!("/proc/{}/status", vmm.pid)).unwrap();
            let credentials = storage::parse_status(&status).unwrap();
            if (credentials.uid[0] == credentials.gid[0]) == equal {
                break (runtime, context, plan, vmm, status, credentials);
            }
            remove_to_absent(&real, &runtime, &context, "retry for the wanted pair").await;
        };
        let _ = vmm;
        let launch =
            crate::firecracker::strict_json(plan.backend_plan()).unwrap()["launch"].clone();
        let recipe = &launch["resource_recipe"]["vmm_credentials"];
        storage::check_vmm_credentials(&credentials, recipe).unwrap();
        assert_eq!(credentials.uid[0] == credentials.gid[0], equal, "{status}");
        eprintln!(
            "B4 evidence: VMM Uid {:?} Gid {:?} Groups {:?} CapInh {:016x} CapPrm {:016x} CapEff {:016x} CapBnd {:016x} CapAmb {:016x} NoNewPrivs {} Seccomp {}",
            credentials.uid,
            credentials.gid,
            credentials.groups,
            credentials.cap_inh,
            credentials.cap_prm,
            credentials.cap_eff,
            credentials.cap_bnd,
            credentials.cap_amb,
            credentials.no_new_privs,
            credentials.seccomp
        );
        remove_to_absent(&real, &runtime, &context, "credentials").await;
        if equal {
            continue;
        }
        // One bounding bit observed: S refuses, contains and never reaches BOOTING.
        real.fixture.fault("S.credentials.capbnd");
        let (runtime, context, _plan) = create(&real).await;
        wait_until("refused", || {
            worker_pid(&real, context.allocation_id, "supervisor").is_some_and(|s| !running(s))
        })
        .await;
        real.fixture.clear("S.credentials.capbnd");
        wait_until("contained", || vm_subtree_empty(&context)).await;
        assert!(
            ["spawn_intent", "stop_intent"].contains(&real.phase(context.allocation_id).as_str())
        );
        if let Some(vmm) = real.vmm(context.allocation_id) {
            assert!(!running(vmm), "the mismatched VMM was stopped");
        }
        assert!(claim_held(&real, context.allocation_id));
        remove_to_absent(&real, &runtime, &context, "bounding mismatch").await;
    }
}

const PAYLOAD_ENV: &str = "KILND_B4_PAYLOAD";

#[derive(Debug, Serialize, Deserialize)]
struct PayloadPlan {
    root: PathBuf,
    uid: u32,
    gid: u32,
    work_bytes: u64,
}

/// The attack payload: exactly the VMM's credentials (U, G, no groups, no capabilities,
/// no_new_privs) inside the hardened jail, without Firecracker's seccomp filter, so
/// only the mandatory bounds can stop it. It prints one JSON line of results.
#[test]
#[ignore = "re-exec target for the VMM-credential attack test"]
fn b4_payload_child() {
    let Ok(raw) = std::env::var(PAYLOAD_ENV) else {
        return;
    };
    let plan: PayloadPlan = serde_json::from_str(&raw).unwrap();
    let path = std::ffi::CString::new(plan.root.to_str().unwrap()).unwrap();
    // Opened before the chroot; procfs answers each read with the current credentials.
    // This thread's: libtest may run the test off the main thread, and the bounding set
    // and no_new_privs are per thread.
    let mut status_file = std::fs::File::open("/proc/thread-self/status").unwrap();
    // SAFETY: plain credential syscalls in this dedicated process.
    unsafe {
        assert_eq!(libc::chroot(path.as_ptr()), 0, "chroot");
        assert_eq!(libc::chdir(c"/".as_ptr()), 0);
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        for cap in 0..64 {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                break;
            }
        }
        assert_eq!(libc::setresgid(plan.gid, plan.gid, plan.gid), 0);
        assert_eq!(libc::setresuid(plan.uid, plan.uid, plan.uid), 0);
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
    }
    let errno = |result: std::io::Result<()>| match result {
        Ok(()) => "ok".to_string(),
        Err(error) => format!("{:?}", error.raw_os_error().unwrap_or(0)),
    };
    let mut out = serde_json::Map::new();
    let status = {
        use std::io::{Read, Seek};
        let mut text = String::new();
        status_file.seek(std::io::SeekFrom::Start(0)).unwrap();
        status_file.read_to_string(&mut text).unwrap();
        text
    };
    out.insert(
        "status_ids".into(),
        json!(
            status
                .lines()
                .filter(|l| l.starts_with("Uid")
                    || l.starts_with("Gid")
                    || l.starts_with("Groups")
                    || l.starts_with("NoNewPrivs"))
                .collect::<Vec<_>>()
        ),
    );
    out.insert(
        "status_caps".into(),
        json!(
            status
                .lines()
                .filter(|l| l.starts_with("Cap"))
                .collect::<Vec<_>>()
        ),
    );
    // Outside /run nothing is writable, and the read-only binds stay immutable.
    for target in [
        "/x",
        "/dev/x",
        "/dev/net/x",
        "/sys/x",
        "/kernel",
        "/firecracker",
        "/identity",
        "/config.json",
        "/rootfs",
    ] {
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(target)
            .map(|_| ());
        out.insert(format!("write:{target}"), json!(errno(result)));
    }
    let chmod = std::fs::set_permissions("/firecracker", std::fs::Permissions::from_mode(0o777));
    out.insert("chmod:/firecracker".into(), json!(errno(chmod)));
    // Bytes: one file until the whole-jail cap refuses.
    let mut written: u64 = 0;
    let mut bytes_error = String::new();
    if let Ok(mut file) = std::fs::File::create("/run/fill") {
        use std::io::Write;
        let chunk = vec![0x5a_u8; 1 << 20];
        loop {
            match file.write(&chunk) {
                Ok(0) => break,
                Ok(n) => written += n as u64,
                Err(error) => {
                    bytes_error = format!("{:?}", error.raw_os_error());
                    break;
                }
            }
            if written > 64 << 20 {
                break;
            }
        }
    }
    out.insert("bytes_written".into(), json!(written));
    out.insert("bytes_error".into(), json!(bytes_error));
    let _ = std::fs::remove_file("/run/fill");
    // Sockets and links: bounded like any inode, and never followed by teardown.
    let mut sockets = 0;
    for n in 0..32 {
        if std::os::unix::net::UnixListener::bind(format!("/run/s{n}")).is_ok() {
            sockets += 1;
        }
    }
    out.insert("sockets".into(), json!(sockets));
    for (name, target) in [
        ("l-shadow", "/etc/shadow"),
        ("l-jail", "/"),
        ("l-host", "/var/lib/kilnd-helper"),
    ] {
        let result = std::os::unix::fs::symlink(target, format!("/run/{name}"));
        out.insert(format!("symlink:{name}"), json!(errno(result)));
    }
    // Inodes: empty files until the inode cap refuses.
    let mut inodes = 0;
    let mut inode_error = String::new();
    for n in 0..4096 {
        match std::fs::File::create(format!("/run/i{n}")) {
            Ok(_) => inodes += 1,
            Err(error) => {
                inode_error = format!("{:?}", error.raw_os_error());
                break;
            }
        }
    }
    out.insert("inodes".into(), json!(inodes));
    out.insert("inode_error".into(), json!(inode_error));
    let mknod = std::ffi::CString::new("/run/node").unwrap();
    // SAFETY: a refused mknod changes nothing.
    let rc = unsafe { libc::mknod(mknod.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(7, 0)) };
    out.insert(
        "mknod".into(),
        json!(if rc == 0 {
            "ok".into()
        } else {
            format!("{:?}", std::io::Error::last_os_error().raw_os_error())
        }),
    );
    // The work device: fixed size, no resize, no deallocation.
    let work = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/work")
        .unwrap();
    let fd = std::os::fd::AsRawFd::as_raw_fd(&work);
    let size = |fd| {
        let mut size: u64 = 0;
        // SAFETY: size is writable for BLKGETSIZE64.
        unsafe { libc::ioctl(fd, 0x8008_1272, &mut size) };
        size
    };
    out.insert("size_before".into(), json!(size(fd)));
    let ioctl = |request: libc::c_ulong, arg: usize| -> String {
        // SAFETY: each request is given its documented argument shape.
        let rc = unsafe { libc::ioctl(fd, request, arg) };
        if rc == 0 {
            "ok".into()
        } else {
            format!("{:?}", std::io::Error::last_os_error().raw_os_error())
        }
    };
    let range: [u64; 2] = [0, 64 << 20];
    out.insert(
        "blkdiscard".into(),
        json!(ioctl(0x1277, range.as_ptr() as usize)),
    );
    out.insert("loop_set_capacity".into(), json!(ioctl(0x4C07, 0)));
    // SAFETY: fallocate on the owned descriptor.
    let punch = unsafe {
        libc::fallocate(
            fd,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            0,
            64 << 20,
        )
    };
    out.insert(
        "punch_hole".into(),
        json!(if punch == 0 {
            "ok".into()
        } else {
            format!("{:?}", std::io::Error::last_os_error().raw_os_error())
        }),
    );
    // SAFETY: as above.
    let grow = unsafe { libc::fallocate(fd, 0, plan.work_bytes as i64, 1 << 20) };
    out.insert(
        "grow".into(),
        json!(if grow == 0 {
            "ok".into()
        } else {
            format!("{:?}", std::io::Error::last_os_error().raw_os_error())
        }),
    );
    // LOOP_SET_STATUS64 rewrites the loop's limits for any writer. Firecracker's seccomp
    // filter has no loop ioctl, so the real VMM cannot issue it; this payload, which
    // lacks that filter, records what the kernel alone allows and whether a hole could
    // then be punched.
    let mut info = [0u8; 232];
    // SAFETY: LOOP_GET_STATUS64 fills a loop_info64 (232 bytes on 64-bit).
    let got = unsafe { libc::ioctl(fd, 0x4C05, info.as_mut_ptr()) };
    out.insert("loop_get_status".into(), json!(got));
    out.insert(
        "loop_set_status".into(),
        json!(ioctl(0x4C04, info.as_ptr() as usize)),
    );
    // SAFETY: as above.
    let punch = unsafe {
        libc::fallocate(
            fd,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            0,
            64 << 20,
        )
    };
    out.insert(
        "punch_after_set_status".into(),
        json!(if punch == 0 {
            "ok".into()
        } else {
            format!("{:?}", std::io::Error::last_os_error().raw_os_error())
        }),
    );
    let past = std::os::unix::fs::FileExt::write_at(&work, &[1u8; 4096], plan.work_bytes);
    out.insert(
        "write_past_w".into(),
        json!(match past {
            Ok(0) => "nothing written".to_string(),
            other => errno(other.map(|_| ())),
        }),
    );
    out.insert("size_after".into(), json!(size(fd)));
    println!("B4PAYLOAD {}", serde_json::to_string(&out).unwrap());
}

/// Exit 4: VMM-credential byte, inode, socket, symlink and work-resize attacks meet
/// the mandatory whole-jail tmpfs and fixed-size loop bounds, W stays fully allocated,
/// and the journal's headroom is untouched: Remove still journals ABSENT.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_vmm_credential_attacks_hit_the_mandatory_bounds() {
    let real = Real::new(NodeOptions::default()).await;
    let (runtime, context, plan) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let launch = crate::firecracker::strict_json(plan.backend_plan()).unwrap()["launch"].clone();
    let credentials = &launch["resource_recipe"]["vmm_credentials"];
    let (paths, _) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    let work_bytes = launch["work_bytes"].as_u64().unwrap();
    let backing = std::fs::File::open(&paths.work_file).unwrap();
    let allocated_before = storage::allocated_bytes(&backing).unwrap();
    assert!(allocated_before >= work_bytes, "W is fully preallocated");
    let ledger_before = nix_free(&real.fixture.root);
    let payload = PayloadPlan {
        root: paths.jail_root.clone(),
        uid: credentials["uid"].as_u64().unwrap() as u32,
        gid: credentials["gid"].as_u64().unwrap() as u32,
        work_bytes,
    };
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "helper::firecracker::tests::lifecycle::b4_payload_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(PAYLOAD_ENV, serde_json::to_string(&payload).unwrap())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find_map(|l| l.split_once("B4PAYLOAD ").map(|(_, json)| json))
        .unwrap_or_else(|| {
            panic!(
                "payload output: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let results: Value = serde_json::from_str(line).unwrap();
    eprintln!("B4 evidence: VMM-credential attacks {results}");
    assert!(
        results["status_ids"]
            .to_string()
            .contains("NoNewPrivs:\\t1"),
        "{results}"
    );
    let caps = results["status_caps"].as_array().unwrap();
    assert_eq!(caps.len(), 5, "{results}");
    for caps in caps {
        assert!(
            caps.as_str().unwrap().ends_with("0000000000000000"),
            "{caps}"
        );
    }
    for target in [
        "/x",
        "/dev/x",
        "/dev/net/x",
        "/sys/x",
        "/kernel",
        "/firecracker",
        "/identity",
        "/config.json",
        "/rootfs",
    ] {
        assert_ne!(
            results[format!("write:{target}")],
            "ok",
            "{target} is writable"
        );
    }
    assert_ne!(results["chmod:/firecracker"], "ok");
    let written = results["bytes_written"].as_u64().unwrap();
    assert!(
        written <= 16 << 20,
        "{written} bytes exceeded the 16 MiB jail cap"
    );
    assert_eq!(results["bytes_error"], format!("Some({})", libc::ENOSPC));
    assert!(
        results["inodes"].as_u64().unwrap() < 1024,
        "the inode cap held"
    );
    assert_eq!(results["inode_error"], format!("Some({})", libc::ENOSPC));
    assert_ne!(results["mknod"], "ok");
    assert_eq!(results["size_before"], json!(work_bytes));
    assert_eq!(
        results["size_after"],
        json!(work_bytes),
        "the work device was not resized"
    );
    assert_ne!(results["write_past_w"], "ok");
    assert_ne!(results["grow"], "ok");
    // Discard and hole punching cannot deallocate W: loop refuses them.
    assert_ne!(results["blkdiscard"], "ok");
    assert_ne!(results["punch_hole"], "ok");
    assert!(
        storage::allocated_bytes(&backing).unwrap() >= work_bytes,
        "W stayed allocated"
    );
    // The jail bound everything: host storage under the ledger did not move.
    let ledger_after = nix_free(&real.fixture.root);
    assert!(
        ledger_before.abs_diff(ledger_after) < 8 << 20,
        "{ledger_before} -> {ledger_after}"
    );
    drop(backing);
    remove_to_absent(&real, &runtime, &context, "after attacks").await;
}

/// Free bytes on the filesystem holding `path`.
fn nix_free(path: &Path) -> u64 {
    let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: stat is writable.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::statvfs(c.as_ptr(), &mut stat) }, 0);
    stat.f_bavail * stat.f_frsize
}

/// Exit 5: each real blocking class stalled in turn — artifact hashing, the work
/// directory, fallocate, mkfs, private-file fsync, cgroup creation, mount, ledger,
/// inventory and recovery — and then both P slots full. Capabilities, Inspect and Stop
/// keep answering within their budgets; an allocation-local stall leaves a healthy
/// allocation's Stop durable, and a shared stall gives a bounded honest Unknown.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_stalled_classes_and_full_pools_keep_capabilities_inspect_and_stop() {
    let real = Real::new(NodeOptions {
        heartbeat_timeout_ms: 1_000,
        ..NodeOptions::default()
    })
    .await;
    for step in [
        "artifacts",
        "work_dir",
        "fallocate",
        "mkfs",
        "private_files",
        "cgroup",
        "jail_mount",
        "binds",
    ] {
        let fault = format!("S.step.{step}.stall");
        let (healthy_runtime, healthy, _) = create(&real).await;
        real.wait_phase(healthy.allocation_id, "booting").await;
        real.fixture.fault(&fault);
        let (runtime, stalled, _) = create(&real).await;
        real.fixture.wait_reached(&format!("S.step.{step}")).await;
        // H stays responsive: cached Capabilities, a fresh Inspect of the healthy boot.
        timed_capabilities(&healthy_runtime, &real.fixture).await;
        let began = std::time::Instant::now();
        let healthy_view = inspect(&real, &healthy_runtime, &healthy, 5).await;
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{step}: Inspect {:?}",
            began.elapsed()
        );
        assert!(
            matches!(healthy_view, InspectReply::PresentBusy { .. }),
            "{step}: {healthy_view:?}"
        );
        // The stalled allocation's own Stop is bounded and honest: its S cannot exit.
        let began = std::time::Instant::now();
        let reply = stop_within(&real, &runtime, &stalled, 4).await;
        assert!(
            began.elapsed() < Duration::from_secs(6),
            "{step}: bounded stop"
        );
        assert!(
            matches!(reply, StopReply::Unknown { .. }),
            "{step}: {reply:?}"
        );
        // The healthy allocation's Stop completes durably at the same time.
        let reply = stop_within(&real, &healthy_runtime, &healthy, 30).await;
        assert!(
            matches!(reply, StopReply::Stopped { .. }),
            "{step}: {reply:?}"
        );
        // Unstalled, the original S exits on its revoke; nothing was replaced meanwhile.
        real.fixture.clear(&fault);
        remove_to_absent(&real, &runtime, &stalled, &format!("stalled at {step}")).await;
        remove_to_absent(
            &real,
            &healthy_runtime,
            &healthy,
            &format!("healthy beside {step}"),
        )
        .await;
    }
    // Both P slots occupied: a third preflight is refused at once, and the others answer.
    let (healthy_runtime, healthy, _) = create(&real).await;
    real.wait_phase(healthy.allocation_id, "booting").await;
    real.fixture.fault("P.preflight.stall");
    let mut stuck = Vec::new();
    for _ in 0..2 {
        let instance = Id128::random();
        let runtime = real.fixture.runtime(instance, Id128::random());
        epoch_of(&runtime).await;
        let context = token(instance);
        let task_runtime = runtime.clone();
        stuck.push(tokio::spawn(async move {
            task_runtime
                .prepare(&context, &spec(), deadline(20), &no_cancel())
                .await
        }));
    }
    wait_until("both P slots busy", || real.fixture.reached("P.preflight")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let instance = Id128::random();
    let third = real.fixture.runtime(instance, Id128::random());
    let began = std::time::Instant::now();
    let refused = third
        .prepare(&token(instance), &spec(), deadline(10), &no_cancel())
        .await;
    assert!(refused.is_err(), "a third preparation needs a P slot");
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "{:?}",
        began.elapsed()
    );
    timed_capabilities(&healthy_runtime, &real.fixture).await;
    assert!(matches!(
        inspect(&real, &healthy_runtime, &healthy, 5).await,
        InspectReply::PresentBusy { .. }
    ));
    assert!(matches!(
        stop_within(&real, &healthy_runtime, &healthy, 30).await,
        StopReply::Stopped { .. }
    ));
    real.fixture.clear("P.preflight.stall");
    for task in stuck {
        let _ = task.await;
    }
    remove_to_absent(&real, &healthy_runtime, &healthy, "beside full P").await;
    // The ledger itself stalled: Capabilities still answers from memory, Inspect is a
    // bounded Unknown, and Stop is an honest Unknown while K stops the VM anyway.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let vmm = real.vmm(context.allocation_id).unwrap();
    real.fixture.fault("L.loop.stall");
    real.fixture.wait_reached("L.loop").await;
    timed_capabilities(&runtime, &real.fixture).await;
    let began = std::time::Instant::now();
    let view = raw_call(
        &real.fixture,
        context.instance_id,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Inspect {
            allocation_id: context.allocation_id,
        },
        wire_deadline(3),
        3_000,
    )
    .await
    .unwrap();
    assert!(
        began.elapsed() < Duration::from_secs(4),
        "{:?}",
        began.elapsed()
    );
    // Honest and bounded: Unknown, or Unavailable at the original deadline.
    assert!(
        matches!(
            view,
            FirecrackerResponse::Inspect(InspectReply::Unknown { .. })
                | FirecrackerResponse::Error(GroupError {
                    kind: GroupErrorKind::Unavailable,
                    ..
                })
        ),
        "{view:?}"
    );
    let reply = stop_within(&real, &runtime, &context, 4).await;
    assert!(matches!(reply, StopReply::Unknown { .. }), "{reply:?}");
    wait_until("independent containment with L blocked", || !running(vmm)).await;
    real.fixture.clear("L.loop.stall");
    remove_to_absent(&real, &runtime, &context, "after the ledger stall").await;
    // Inventory stalled in P: List is bounded, Stop is not affected.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    real.fixture.fault("P.observe.stall");
    let began = std::time::Instant::now();
    let listed = runtime.list(deadline(3), &no_cancel()).await;
    assert!(began.elapsed() < Duration::from_secs(5));
    assert!(listed.map(|l| !l.complete).unwrap_or(true));
    assert!(matches!(
        stop_within(&real, &runtime, &context, 30).await,
        StopReply::Stopped { .. }
    ));
    real.fixture.clear("P.observe.stall");
    remove_to_absent(&real, &runtime, &context, "after the inventory stall").await;
    // Both recovery slots stuck inside cgroup.kill: Stop is a bounded Unknown, then the
    // same slots finish once released; no third K exists.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    let before = real.fixture.census().await;
    real.fixture.fault("K.cgroup_kill.stall");
    let reply = stop_within(&real, &runtime, &context, 4).await;
    assert!(matches!(reply, StopReply::Unknown { .. }), "{reply:?}");
    timed_capabilities(&runtime, &real.fixture).await;
    let after = real.fixture.census().await;
    assert_eq!(before["recovery"], after["recovery"], "no K was replaced");
    real.fixture.clear("K.cgroup_kill.stall");
    remove_to_absent(&real, &runtime, &context, "after the recovery stall").await;
}

/// Exit 6: stale PIDs and replaced inodes protect unrelated resources. A live process
/// whose start time differs is never signaled; a replaced cgroup is never killed; a
/// replaced work file is refused, not deleted; a loop slot rebound to another file is
/// left bound; the slot rebound to the allocation's own file with another offset or
/// size limit is refused and left bound; a replacement jail tmpfs is refused and left
/// mounted.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_stale_pids_and_inodes_protect_unrelated_resources() {
    // A reused PID: the recorded start time names a process that no longer exists.
    let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
    let pid = unrelated.id() as i32;
    let ProcessState::Running { start_time } = super::super::workers::process_state(pid) else {
        panic!("sleep is not running");
    };
    let stale = super::super::monitor::StopTarget::process(ProcessId {
        pid,
        start_time: start_time + 1,
    });
    assert!(
        super::super::monitor::execute(&stale),
        "a different process is not ours"
    );
    assert!(
        running(ProcessId { pid, start_time }),
        "the unrelated process survived"
    );
    // A replaced cgroup: same path, another inode, a live task inside.
    let scratch = format!("kilnd-firecracker/{}/fc-stale", Id128::random());
    let base = Path::new("/sys/fs/cgroup").join(&scratch);
    std::fs::create_dir_all(base.join("vm")).unwrap();
    std::fs::write(base.join("vm/cgroup.procs"), pid.to_string()).unwrap();
    let state = super::super::cgroup::kill_node(
        &super::super::cgroup::CgroupTarget {
            path: format!("{scratch}/vm"),
            st_ino: 1,
        },
        Duration::from_millis(200),
    )
    .unwrap();
    assert_eq!(state, super::super::cgroup::NodeState::Replaced);
    assert!(
        running(ProcessId { pid, start_time }),
        "a replaced cgroup is not signaled"
    );
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    std::fs::remove_dir(base.join("vm")).unwrap();
    std::fs::remove_dir(&base).unwrap();
    let _ = std::fs::remove_dir(base.parent().unwrap());

    let real = Real::new(NodeOptions::default()).await;
    // A replaced work file is refused and survives; the operator's removal unblocks.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    assert!(matches!(
        stop_within(&real, &runtime, &context, 30).await,
        StopReply::Stopped { .. }
    ));
    let (paths, _) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    let replacement = paths.work_dir.join("replacement");
    std::fs::write(&replacement, b"not the allocation's disk").unwrap();
    std::fs::rename(&replacement, &paths.work_file).unwrap();
    let reply = remove(&real, &runtime, &context).await;
    assert!(!is_absent(&reply), "{reply:?}");
    assert_eq!(
        std::fs::read(&paths.work_file).unwrap(),
        b"not the allocation's disk"
    );
    assert!(
        claim_held(&real, context.allocation_id),
        "refusal keeps the charge"
    );
    std::fs::remove_file(&paths.work_file).unwrap();
    remove_to_absent(&real, &runtime, &context, "after the replaced work file").await;
    // A loop slot rebound to an unrelated file stays bound to it.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    assert!(matches!(
        stop_within(&real, &runtime, &context, 30).await,
        StopReply::Stopped { .. }
    ));
    let binding = real
        .resources(context.allocation_id)
        .into_iter()
        .find_map(|record| match record {
            super::super::supervisor::ResourceRecord::Loop { binding, .. } => Some(binding),
            _ => None,
        })
        .unwrap();
    let device = format!("/dev/loop{}", binding.minor);
    assert!(
        Command::new("losetup")
            .args(["-d", &device])
            .status()
            .unwrap()
            .success()
    );
    wait_until("slot free", || {
        !Path::new(&format!(
            "/sys/block/loop{}/loop/backing_file",
            binding.minor
        ))
        .exists()
    })
    .await;
    let other = real.fixture.root.join("unrelated.img");
    std::fs::write(&other, vec![0u8; 1 << 20]).unwrap();
    assert!(
        Command::new("losetup")
            .args([&device, other.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    remove_to_absent(&real, &runtime, &context, "after the rebound loop slot").await;
    let backing = std::fs::read_to_string(format!(
        "/sys/block/loop{}/loop/backing_file",
        binding.minor
    ))
    .unwrap();
    assert_eq!(
        backing.trim(),
        other.to_str().unwrap(),
        "the unrelated binding was left alone"
    );
    assert!(
        Command::new("losetup")
            .args(["-d", &device])
            .status()
            .unwrap()
            .success()
    );
    // B4 break-it finding 2: the recorded slot rebound to the allocation's own backing
    // file with another offset or size limit is not the journaled binding. Remove
    // leaves it bound and the allocation charged until the operator unbinds it.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    assert!(matches!(
        stop_within(&real, &runtime, &context, 30).await,
        StopReply::Stopped { .. }
    ));
    let (paths, _) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    let binding = real
        .resources(context.allocation_id)
        .into_iter()
        .find_map(|record| match record {
            super::super::supervisor::ResourceRecord::Loop { binding, .. } => Some(binding),
            _ => None,
        })
        .unwrap();
    let device = format!("/dev/loop{}", binding.minor);
    let backing_file = format!("/sys/block/loop{}/loop/backing_file", binding.minor);
    let unbind = || async {
        assert!(
            Command::new("losetup")
                .args(["-d", &device])
                .status()
                .unwrap()
                .success()
        );
        wait_until("slot free", || !Path::new(&backing_file).exists()).await;
    };
    unbind().await;
    let half = (binding.size_limit / 2).to_string();
    let shorter = (binding.size_limit - 4096).to_string();
    for (label, args) in [
        ("offset", vec!["--offset", "4096", "--sizelimit", shorter.as_str()]),
        ("size limit", vec!["--sizelimit", half.as_str()]),
    ] {
        let mut all = args.clone();
        all.extend([device.as_str(), paths.work_file.to_str().unwrap()]);
        assert!(Command::new("losetup").args(&all).status().unwrap().success());
        let reply = remove(&real, &runtime, &context).await;
        assert!(!is_absent(&reply), "{label}: {reply:?}");
        assert_eq!(
            std::fs::read_to_string(&backing_file).unwrap().trim(),
            paths.work_file.to_str().unwrap(),
            "{label}: the other binding was detached"
        );
        assert!(claim_held(&real, context.allocation_id), "{label}: charged");
        eprintln!("B4 evidence: same work inode, different {label}: refused, left bound");
        unbind().await;
    }
    // B4 recheck finding 2: the exact journaled tuple, rebound to the same slot and work
    // inode, is another attachment generation. Only its disk sequence number differs.
    let generation = real
        .resources(context.allocation_id)
        .into_iter()
        .find_map(|record| match record {
            super::super::supervisor::ResourceRecord::Loop { generation, .. } => Some(generation),
            _ => None,
        })
        .unwrap();
    let exact = binding.size_limit.to_string();
    assert!(
        Command::new("losetup")
            .args(["--sizelimit", exact.as_str(), device.as_str(), paths.work_file.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    storage::verify_loop(&binding).unwrap();
    let rebound = storage::current_generation(binding.minor).unwrap();
    assert_ne!(rebound.diskseq, generation.diskseq);
    let reply = remove(&real, &runtime, &context).await;
    assert!(!is_absent(&reply), "same tuple, new generation: {reply:?}");
    assert_eq!(
        std::fs::read_to_string(&backing_file).unwrap().trim(),
        paths.work_file.to_str().unwrap(),
        "the rebinding was detached"
    );
    assert!(claim_held(&real, context.allocation_id), "a new generation: charged");
    eprintln!(
        "B4 evidence: same tuple rebound, diskseq {} != journaled {}: refused, left bound",
        rebound.diskseq, generation.diskseq
    );
    unbind().await;
    remove_to_absent(&real, &runtime, &context, "after the retuned loop slot").await;
    // B4 break-it finding 1: a fresh tmpfs mounted in place of the allocation's own,
    // carrying the allocation's own source string, is refused and left mounted.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    assert!(matches!(
        stop_within(&real, &runtime, &context, 30).await,
        StopReply::Stopped { .. }
    ));
    let (paths, _) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    let identity = real
        .resources(context.allocation_id)
        .into_iter()
        .find_map(|record| match record {
            super::super::supervisor::ResourceRecord::JailIntent(identity) => Some(identity),
            _ => None,
        })
        .unwrap();
    let run = |program: &str, args: &[&str]| {
        assert!(
            Command::new(program).args(args).status().unwrap().success(),
            "{program} {args:?}"
        );
    };
    for name in storage::BINDS {
        run("umount", &[paths.jail_root.join(name).to_str().unwrap()]);
    }
    run("umount", &[paths.jail_dir.to_str().unwrap()]);
    run(
        "mount",
        &[
            "-t",
            "tmpfs",
            "-o",
            storage::JAIL_TMPFS_DATA,
            &identity.source(),
            paths.jail_dir.to_str().unwrap(),
        ],
    );
    std::fs::create_dir(&paths.jail_root).unwrap();
    let reply = remove(&real, &runtime, &context).await;
    assert!(!is_absent(&reply), "{reply:?}");
    let mounts =
        storage::parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo").unwrap())
            .unwrap();
    assert!(
        storage::mounts_under(&mounts, &paths.jail_dir)
            .iter()
            .any(|m| m.mount_point == paths.jail_dir && m.source == identity.source()),
        "the replacement survived"
    );
    assert!(claim_held(&real, context.allocation_id), "refusal keeps the charge");
    eprintln!("B4 evidence: replacement jail tmpfs with the allocation's source: refused");
    run("umount", &[paths.jail_dir.to_str().unwrap()]);
    remove_to_absent(&real, &runtime, &context, "after the replaced jail mount").await;
}

/// Exit 7: the prelaunch charge. The node claim exists before any host effect, J sits
/// in the charged `vm/vmm` leaf before it executes, the VMM's memory is charged there
/// from launch under the contract's limits, and the claim survives STOPPED until ABSENT.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_prelaunch_charge_is_held_from_c2_through_absent() {
    let real = Real::new(NodeOptions::default()).await;
    real.fixture.fault("S.step.cgroup.stall");
    let (runtime, context, plan) = create(&real).await;
    real.fixture.wait_reached("S.step.cgroup").await;
    assert!(
        claim_held(&real, context.allocation_id),
        "C2 claim before any effect"
    );
    assert_eq!(
        host_leftovers(&context, None),
        Vec::<String>::new(),
        "no effect yet"
    );
    let totals = node_totals(&runtime).await;
    assert!(
        serde_json::to_value(&totals)
            .unwrap()
            .to_string()
            .contains(&(896u64 << 20).to_string())
    );
    real.fixture.clear("S.step.cgroup.stall");
    real.fixture.fault("S.step.continue_jailer.stall");
    real.fixture.wait_reached("S.step.continue_jailer").await;
    let jailer = worker_pid(&real, context.allocation_id, "jailer").unwrap();
    let (_, cgroup) =
        super::super::inventory::real_paths(context.instance_id, context.allocation_id);
    let placed = std::fs::read_to_string(format!("/proc/{}/cgroup", jailer.pid)).unwrap();
    assert_eq!(
        placed.trim(),
        format!("0::/{cgroup}/vm/vmm"),
        "J is charged before it executes"
    );
    real.fixture.clear("S.step.continue_jailer.stall");
    real.wait_phase(context.allocation_id, "booting").await;
    let root = Path::new("/sys/fs/cgroup").join(&cgroup);
    let read = |name: &str| {
        std::fs::read_to_string(root.join(name))
            .unwrap()
            .trim()
            .to_string()
    };
    assert_eq!(read("memory.max"), "939524096");
    assert_eq!(read("memory.swap.max"), "0");
    assert_eq!(read("memory.oom.group"), "1");
    assert_eq!(read("pids.max"), "32");
    assert_eq!(read("cpu.max"), "100000 100000");
    let vmm = real.vmm(context.allocation_id).unwrap();
    let vmm_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", vmm.pid)).unwrap();
    assert_eq!(vmm_cgroup.trim(), format!("0::/{cgroup}/vm/vmm"));
    let charged: u64 = read("vm/vmm/memory.current").parse().unwrap();
    assert!(
        charged > 0,
        "the VMM's memory is charged to the allocation from launch"
    );
    eprintln!(
        "B4 evidence: allocation memory.current {} vm/vmm {} control {} (max 939524096), plan {}",
        read("memory.current"),
        charged,
        read("control/memory.current"),
        plan.plan_digest()
    );
    assert!(matches!(
        stop_within(&real, &runtime, &context, 30).await,
        StopReply::Stopped { .. }
    ));
    assert!(
        claim_held(&real, context.allocation_id),
        "STOPPED is not a release"
    );
    assert_eq!(real.phase(context.allocation_id), "stopped");
    remove_to_absent(&real, &runtime, &context, "charge").await;
}

/// Replaces one installed name with other bytes, as root, after the retained descriptor
/// was verified. Returns the path to restore afterwards.
fn swap_installed(role: Role) -> PathBuf {
    let pin = install(role, &sources()[&role]);
    let path = installed_path(&pin);
    let swap = path.with_file_name(format!(".{}.swap", role.as_str()));
    std::fs::copy("/bin/true", &swap).unwrap();
    std::fs::rename(&swap, &path).unwrap();
    path
}

fn restore_installed(role: Role) {
    let pin = install_unchecked_path(role);
    let _ = std::fs::remove_file(&pin);
    install(role, &sources()[&role]);
}

fn install_unchecked_path(role: Role) -> PathBuf {
    let (_, sha256) = digest_file(&sources()[&role]);
    Path::new(STORE)
        .join(sha256.to_string())
        .join(role.as_str())
}

/// Exit 8: KR-05. As an unrelated unprivileged UID, renaming the source tree after
/// verification succeeds and renaming any protected ancestor fails; as root, swapping
/// the installed jailer name just before S executes J, and the Firecracker name between
/// J's verification and V's exec, and the formatter's name before it runs, changes
/// nothing: the actual /proc exe device, inode and FD-computed digest of J, V and the
/// formatter equal the journal. Every fork-only worker runs the approved helper image.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_kr05_replacement_races_run_only_the_retained_inodes() {
    let real = Real::new(NodeOptions::default()).await;
    // The formatter is short-lived: a test-only exec stop lets S read its real /proc exe.
    real.fixture.fault("S.exec_stop");
    // The unprivileged attacker: a source tree it owns, and the protected store.
    let attacker = (64_200u32, 64_200u32);
    let tree = real.fixture.root.join("kr05");
    std::fs::create_dir(&tree).unwrap();
    std::fs::set_permissions(&real.fixture.root, std::fs::Permissions::from_mode(0o711)).unwrap();
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::chown(&tree, Some(attacker.0), Some(attacker.1)).unwrap();
    let source = tree.join("src");
    std::fs::create_dir(&source).unwrap();
    for role in [Role::Jailer, Role::Firecracker, Role::MkfsXfs] {
        let target = source.join(role.as_str());
        std::fs::copy(&sources()[&role], &target).unwrap();
        std::os::unix::fs::chown(&target, Some(attacker.0), Some(attacker.1)).unwrap();
        install(role, &target);
    }
    std::os::unix::fs::chown(&source, Some(attacker.0), Some(attacker.1)).unwrap();
    let jailer_dir = installed_path(&install(Role::Jailer, &sources()[&Role::Jailer]))
        .parent()
        .unwrap()
        .to_path_buf();
    let script = format!(
        "import os, sys\n\
         results = []\n\
         os.rename({src:?}, {src:?} + '.old'); os.mkdir({src:?})\n\
         open({src:?} + '/jailer', 'wb').write(b'planted')\n\
         results.append('source-rename-ok')\n\
         for path in [{dir:?}, '/opt/kilnd/exec/sha256', '/opt/kilnd/exec', '/opt/kilnd']:\n\
         \x20   try:\n\
         \x20       os.rename(path, path + '.x'); results.append('renamed ' + path)\n\
         \x20   except OSError as e:\n\
         \x20       results.append('denied ' + path)\n\
         print(' '.join(results))\n",
        src = source.to_str().unwrap(),
        dir = jailer_dir.to_str().unwrap(),
    );
    let output = {
        use std::os::unix::process::CommandExt;
        Command::new("python3")
            .args(["-I", "-c", &script])
            .uid(attacker.0)
            .gid(attacker.1)
            .output()
            .unwrap()
    };
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    eprintln!(
        "B4 evidence: KR-05 unprivileged attacker: {text} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("source-rename-ok"), "{text}");
    assert!(
        !text.contains("renamed"),
        "a protected ancestor was renamed: {text}"
    );
    // The race outcome: only the approved inodes run.
    let (runtime, context, _) = create(&real).await;
    real.wait_phase(context.allocation_id, "booting").await;
    for role in [Role::Jailer, Role::Firecracker, Role::MkfsXfs] {
        let (expected, observed) = real.lease(context.allocation_id, role);
        assert_eq!(expected, observed, "{}", role.as_str());
        // Under the test exec stop even the formatter's image is read from /proc.
        assert_eq!(
            real.evidence(context.allocation_id, role).as_deref(),
            Some("proc_exe"),
            "{}",
            role.as_str()
        );
    }
    remove_to_absent(&real, &runtime, &context, "unprivileged race").await;

    // Root name swaps at the two launch boundaries and before the formatter runs.
    for (role, boundary) in [
        (Role::Jailer, "S.step.release_jailer"),
        (Role::Firecracker, "S.step.continue_jailer"),
        (Role::MkfsXfs, "S.step.mkfs"),
    ] {
        real.fixture.fault(&format!("{boundary}.stall"));
        let (runtime, context, _) = create(&real).await;
        real.fixture.wait_reached(boundary).await;
        let swapped = swap_installed(role);
        real.fixture.clear(&format!("{boundary}.stall"));
        real.wait_phase(context.allocation_id, "booting").await;
        let (expected, observed) = real.lease(context.allocation_id, role);
        assert_eq!(expected, observed, "{} after the name swap", role.as_str());
        let now = std::fs::metadata(&swapped).unwrap();
        assert_ne!(
            json!(now.ino()),
            expected[1],
            "the installed name really changed"
        );
        if role == Role::Firecracker {
            let vmm = real.vmm(context.allocation_id).unwrap();
            let actual = vmm_image(&real, context.allocation_id, vmm.pid);
            assert_eq!(
                json!([
                    actual.st_dev,
                    actual.st_ino,
                    actual.bytes,
                    actual.sha256.to_string()
                ]),
                expected
            );
        }
        eprintln!(
            "B4 evidence: KR-05 {} swapped at {boundary}: journal {expected} observed {observed}",
            role.as_str()
        );
        remove_to_absent(&real, &runtime, &context, boundary).await;
        // The running helper now refuses new plans: its retained descriptor names an
        // unlinked inode. Republishing and reopening is a new installation, not repair.
        let instance = Id128::random();
        let fresh = real.fixture.runtime(instance, Id128::random());
        let error = fresh
            .prepare(&token(instance), &spec(), deadline(10), &no_cancel())
            .await;
        assert!(
            error.is_err(),
            "a swapped store object refuses new plans until reopened"
        );
        restore_installed(role);
        restart_helper(&real).await;
    }
    real.fixture.clear("S.exec_stop");
    // Fork-only workers run the verified helper image.
    let helper =
        std::fs::metadata(std::fs::read_to_string(real.fixture.root.join("helper-image")).unwrap())
            .unwrap();
    let census = real.fixture.census().await;
    for pid in all_census_pids(&census) {
        let image = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
        assert_eq!(
            (image.dev(), image.ino()),
            (helper.dev(), helper.ino()),
            "worker {pid}"
        );
    }
    // The jailer's capabilities are scoped to S: L, P, M and K gave them up at start.
    let launch_caps: u64 = (1 << 8) | (1 << 18) | (1 << 27);
    // L is left out only because this fixture's attaching peer is the root test process,
    // whose capabilities L must cover; production L drops them like the others.
    let mut workers = vec![census["monitor"].as_i64().unwrap()];
    for key in ["prep", "recovery"] {
        workers.extend(
            census[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_i64().unwrap()),
        );
    }
    for pid in workers {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let bounding = status
            .lines()
            .find_map(|l| l.strip_prefix("CapBnd:\t"))
            .map(|v| u64::from_str_radix(v, 16).unwrap())
            .unwrap();
        assert_eq!(
            bounding & launch_caps,
            0,
            "worker {pid} kept a launch capability"
        );
    }
}

/// Section 8.2's scoped collection: Gc removes only this instance's named, proven-dead
/// or stopped allocations through the absence barrier; a live boot, an unknown token
/// and another instance's allocation are left exactly as they were.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs root, KVM and the B4 artifacts: run scripts/b4-vm-tests.sh"]
async fn b4_linux_root_scoped_gc_removes_only_proven_dead_allocations() {
    let real = Real::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = real.fixture.runtime(instance, instance);
    let live = token(instance);
    let live_plan = prepared(&runtime, &live).await;
    create_accepted(&real.fixture, &runtime, &live, &live_plan).await;
    let dead = token(instance);
    let dead_plan = prepared(&runtime, &dead).await;
    create_accepted(&real.fixture, &runtime, &dead, &dead_plan).await;
    real.wait_phase(live.allocation_id, "booting").await;
    real.wait_phase(dead.allocation_id, "booting").await;
    // The inventory sees both, complete, through the real namespace observation.
    let listed = runtime.list(deadline(10), &no_cancel()).await.unwrap();
    assert!(listed.complete, "{listed:?}");
    assert_eq!(listed.records.len(), 2);
    let dead_vmm = real.vmm(dead.allocation_id).unwrap();
    signal(dead_vmm.pid as i64, libc::SIGKILL);
    wait_until("dead contained", || vm_subtree_empty(&dead)).await;
    // Another instance's allocation, named by ID in this instance's request.
    let (other_runtime, other, _) = create(&real).await;
    real.wait_phase(other.allocation_id, "booting").await;
    let unknown = Id128::random();
    let reply = raw_call(
        &real.fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Gc {
            allocation_ids: vec![
                live.allocation_id,
                dead.allocation_id,
                unknown,
                other.allocation_id,
            ],
        },
        wire_deadline(30),
        30_000,
    )
    .await
    .unwrap();
    let FirecrackerResponse::Gc(results) = reply else {
        panic!("{reply:?}");
    };
    eprintln!("B4 evidence: scoped Gc {results:?}");
    let outcome = |id: Id128| {
        results
            .iter()
            .find(|r| r.allocation_id == id)
            .unwrap()
            .outcome
            .clone()
    };
    assert!(matches!(
        outcome(live.allocation_id),
        GcOutcome::Skipped { .. }
    ));
    assert!(matches!(
        outcome(dead.allocation_id),
        GcOutcome::Removed { .. }
    ));
    assert!(matches!(outcome(unknown), GcOutcome::Skipped { .. }));
    assert!(matches!(
        outcome(other.allocation_id),
        GcOutcome::Skipped { .. }
    ));
    assert_eq!(host_leftovers(&dead, Some(dead_vmm)), Vec::<String>::new());
    assert!(
        running(real.vmm(live.allocation_id).unwrap()),
        "the live boot is untouched"
    );
    assert!(
        running(real.vmm(other.allocation_id).unwrap()),
        "another instance's boot is untouched"
    );
    // An empty Gc is a no-op.
    let reply = raw_call(
        &real.fixture,
        instance,
        Some(epoch_of(&runtime).await),
        FirecrackerOperation::Gc {
            allocation_ids: vec![],
        },
        wire_deadline(5),
        5_000,
    )
    .await
    .unwrap();
    assert!(
        matches!(reply, FirecrackerResponse::Gc(ref r) if r.is_empty()),
        "{reply:?}"
    );
    remove_to_absent(&real, &runtime, &live, "gc live").await;
    remove_to_absent(&real, &other_runtime, &other, "gc other").await;
}
