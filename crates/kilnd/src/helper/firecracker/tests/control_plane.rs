//! The break-it review's four control-plane failures, as regressions against the real
//! stack. Peers that must differ from one another are separate processes running this
//! same binary or a copy of it, so the helper examines their real UID, start time and
//! image. Only the cgroup is a stand-in where a test can't place a process in one: the
//! root Linux run of the same scenario uses the kernel's.
use super::super::MAX_ATTACH_WAITERS;
use super::*;
use crate::helper::firecracker::journal::EnrollOutcome;
use crate::helper::firecracker::peer::{EnrolledExecutable, Enrollment};
use std::os::unix::fs::MetadataExt;
use std::process::Stdio;

const PEER_ENV: &str = "KILND_B3_PEER";
#[cfg(target_os = "linux")]
const ROOT_PTRACE_ENV: &str = "KILND_B3_NO_PTRACE_TARGET";
const VICTIM_UNIT: &str = "victim.service";
/// Numeric accounts need no passwd entry to run a process, so nothing is left behind.
const VICTIM_ACCOUNT: (u32, u32) = (64_100, 64_100);
const ATTACKER_ACCOUNT: (u32, u32) = (64_101, 64_101);
const STRANGER_ACCOUNT: (u32, u32) = (64_102, 64_102);

/// This test binary's real identity, which the image its peer processes run must match.
/// Its digest is the fixture's: hashing it is slow, and peer.rs hashes real images.
fn own_image() -> EnrolledExecutable {
    let meta = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
    EnrolledExecutable {
        st_dev: meta.dev(),
        st_ino: meta.ino(),
        bytes: meta.len(),
        sha256: fixture_digest(),
    }
}

/// What one peer process does, in order.
#[derive(Debug, Serialize, Deserialize)]
struct PeerPlan {
    root: PathBuf,
    instance: Id128,
    database: Id128,
    /// Used when its own attachment was refused, as a thief that copied it would.
    stolen_epoch: Option<Id128>,
    /// Prepare and create one allocation, reporting the requests that replay it.
    create: bool,
    operations: Vec<FirecrackerOperation>,
    /// Retry this fence until it reports absence, or give up.
    fence: Option<FirecrackerOperation>,
    hold: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerReport {
    /// The helper-issued epoch, or the refusal.
    attach: Result<Id128, String>,
    create: Option<FirecrackerOperation>,
    fence_request: Option<FirecrackerOperation>,
    responses: Vec<FirecrackerResponse>,
    fence: Option<FirecrackerResponse>,
}

async fn raw_call_at(
    root: &Path,
    instance: Id128,
    epoch: Id128,
    operation: FirecrackerOperation,
) -> FirecrackerResponse {
    // Each operation has its own budget in the protocol's table.
    let timeout_ms = operation.timeout_ms();
    let request = Request {
        version: VERSION,
        timeout_ms,
        deadline_ns: wire_deadline(u64::from(timeout_ms) / 1000),
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
        Response::Firecracker(reply) => reply,
        other => panic!("{other:?}"),
    }
}

/// The separate peer process. It waits to be placed, runs its plan, and reports.
#[test]
#[ignore = "re-exec target for control-plane peers"]
fn peer_fixture_child() {
    let Ok(path) = std::env::var(PEER_ENV) else {
        return;
    };
    let out = PathBuf::from(path);
    let plan: PeerPlan = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let go = out.with_extension("go");
        wait_until("the test placed this peer", || go.exists()).await;
        // The socket belongs to the helper, whichever account this peer runs under.
        let helper_uid = std::fs::metadata(plan.root.join("helper.sock"))
            .unwrap()
            .uid();
        let peer = Arc::new(FirecrackerRuntime::with_helper_uid(
            plan.root.join("helper.sock"),
            helper_uid,
            plan.instance,
            plan.database,
        ));
        let attach = peer
            .test_epoch(deadline(10))
            .await
            .map_err(|error| error.to_string());
        let mut report = PeerReport {
            attach: attach.clone(),
            create: None,
            fence_request: None,
            responses: Vec::new(),
            fence: None,
        };
        if plan.create {
            let (context, prepared) = issued(&peer, plan.instance).await;
            let create = create_operation(&context, &prepared);
            let epoch = attach.clone().unwrap();
            let reply = raw_call_at(&plan.root, plan.instance, epoch, create.clone()).await;
            assert!(
                matches!(
                    reply,
                    FirecrackerResponse::Create(CreateReply::Accepted { replay: false, .. })
                ),
                "{reply:?}"
            );
            report.create = Some(create);
            report.fence_request = Some(FirecrackerOperation::FenceAbsent {
                allocation_id: context.allocation_id,
                sandbox_id: context.sandbox_id.clone(),
                plan_digest: prepared.plan_digest(),
            });
        }
        let epoch = attach.clone().ok().or(plan.stolen_epoch);
        if let Some(epoch) = epoch {
            for operation in plan.operations {
                report
                    .responses
                    .push(raw_call_at(&plan.root, plan.instance, epoch, operation).await);
            }
            if let Some(fence) = plan.fence {
                for _ in 0..250 {
                    let reply = raw_call_at(&plan.root, plan.instance, epoch, fence.clone()).await;
                    let done =
                        matches!(reply, FirecrackerResponse::Fence(FenceReply::Absent { .. }));
                    report.fence = Some(reply);
                    if done {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        let ready = out.with_extension("report");
        let staged = out.with_extension("staged");
        std::fs::write(&staged, serde_json::to_vec(&report).unwrap()).unwrap();
        std::fs::rename(&staged, &ready).unwrap();
        if plan.hold {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                // SAFETY: getppid has no preconditions; _exit runs no destructors.
                if unsafe { libc::getppid() } == 1 {
                    unsafe { libc::_exit(0) };
                }
            }
        }
    });
}

struct Peer {
    child: Child,
    out: PathBuf,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Peer {
    async fn report(&self) -> PeerReport {
        let ready = self.out.with_extension("report");
        wait_until("the peer's report", || ready.exists()).await;
        serde_json::from_slice(&std::fs::read(&ready).unwrap()).unwrap()
    }

    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

/// Puts a real process where the node will look for it.
struct Placement {
    evidence: PeerEvidence,
    root: PathBuf,
    /// Real cgroup directories to remove once their processes are gone.
    created: Mutex<Vec<PathBuf>>,
}

impl Placement {
    /// The cgroup a unit gets. Under a real hierarchy, a unique slice for this test.
    fn cgroup_of(&self, unit: &str) -> String {
        match self.evidence {
            PeerEvidence::Real => format!("/kilnd-b3-{}.slice/{unit}", std::process::id()),
            _ => format!("/test.slice/{unit}"),
        }
    }

    /// Only a marker needs writing: a real account is the one the process really runs as.
    fn mark_account(&self, pid: i32, (uid, gid): (u32, u32)) {
        if !matches!(self.evidence, PeerEvidence::Real) {
            std::fs::write(
                self.root.join("peers").join(format!("{pid}.account")),
                format!("{uid}:{gid}"),
            )
            .unwrap();
        }
    }

    fn place(&self, pid: i32, cgroup: &str) {
        match self.evidence {
            PeerEvidence::Real => {
                let path = PathBuf::from(format!("/sys/fs/cgroup{cgroup}"));
                std::fs::create_dir_all(&path).unwrap();
                std::fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                self.created.lock().unwrap().push(path);
            }
            _ => std::fs::write(self.root.join("peers").join(pid.to_string()), cgroup).unwrap(),
        }
    }
}

impl Drop for Placement {
    fn drop(&mut self) {
        let mut created = self.created.lock().unwrap().clone();
        created.sort();
        created.dedup();
        // Children first, then the slices above them.
        for path in created.iter().rev() {
            let _ = std::fs::remove_dir(path);
            if let Some(parent) = path.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }
}

impl Fixture {
    /// Root's enrollment of this binary's image, with the helper stopped, under an account
    /// of the instance's own.
    fn enroll(&self, instance: Id128, unit: &str, cgroup: &str, limit: u32) -> EnrollOutcome {
        let account = super::super::peer::fixture_account(instance);
        self.enroll_as(instance, unit, cgroup, limit, account)
    }

    fn enroll_as(
        &self,
        instance: Id128,
        unit: &str,
        cgroup: &str,
        limit: u32,
        (uid, gid): (u32, u32),
    ) -> EnrollOutcome {
        let config: ChildConfig =
            serde_json::from_slice(&std::fs::read(self.root.join("config.json")).unwrap()).unwrap();
        let mut ledger = Ledger::open(ledger_config(&config)).unwrap();
        ledger
            .enroll_instance(
                &Enrollment {
                    instance_id: instance,
                    unit: unit.into(),
                    cgroup: cgroup.into(),
                    uid,
                    gid,
                    executable: own_image(),
                },
                limit,
            )
            .unwrap()
    }

    /// Starts one peer from `image`, placed in `cgroup`, and lets it run its plan.
    fn spawn_peer(
        &self,
        plan: &PeerPlan,
        placement: &Placement,
        cgroup: &str,
        image: &Path,
        name: &str,
    ) -> Peer {
        self.spawn_peer_as(plan, placement, cgroup, image, name, VICTIM_ACCOUNT)
    }

    /// The same, under `account`: for real under real evidence, otherwise by its marker.
    fn spawn_peer_as(
        &self,
        plan: &PeerPlan,
        placement: &Placement,
        cgroup: &str,
        image: &Path,
        name: &str,
        account: (u32, u32),
    ) -> Peer {
        // Its own directory, since a peer under another account writes its report here.
        let directory = self.root.join("peer-io").join(name);
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let real_account = matches!(placement.evidence, PeerEvidence::Real);
        if real_account {
            std::os::unix::fs::chown(&directory, Some(account.0), Some(account.1)).unwrap();
        }
        let out = directory.join("plan.json");
        std::fs::write(&out, serde_json::to_vec(plan).unwrap()).unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("peer.log"))
            .unwrap();
        let child = {
            let _guard = crate::process::spawn_guard();
            let mut command = Command::new(image);
            command
                .args([
                    "--ignored",
                    "--exact",
                    "helper::firecracker::tests::control_plane::peer_fixture_child",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(PEER_ENV, &out)
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log);
            if real_account {
                use std::os::unix::process::CommandExt;
                command.uid(account.0).gid(account.1);
            }
            command.spawn().unwrap()
        };
        placement.mark_account(child.id() as i32, account);
        placement.place(child.id() as i32, cgroup);
        std::fs::write(out.with_extension("go"), b"").unwrap();
        Peer { child, out }
    }

    /// This instance's attachment has ended, whatever others hold.
    #[cfg(target_os = "linux")]
    async fn wait_detached_of(&self, _instance: Id128) {
        for _ in 0..3000 {
            if self.census().await["attached"].as_u64() <= Some(1) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the holder's attachment did not end");
    }

    async fn wait_detached(&self) {
        for _ in 0..3000 {
            if self.census().await["attached"].as_u64() == Some(0) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the holder's attachment did not end");
    }
}

fn group_kind(response: &FirecrackerResponse) -> Option<GroupErrorKind> {
    match response {
        FirecrackerResponse::Error(error) => Some(error.kind),
        _ => None,
    }
}

/// None of the instance-scoped surface answered: no Inspect, List, Create or Fence, with
/// the copied epoch, and no token fact either.
fn assert_no_authority(who: &str, report: &PeerReport, refusals: &[&str]) {
    let refused = report.attach.as_ref().err().unwrap_or_else(|| {
        panic!("{who} attached: {:?}", report.attach);
    });
    assert!(
        refusals.iter().any(|expected| refused.contains(expected)),
        "{who}: {refused}"
    );
    assert_eq!(report.responses.len(), 4, "{who}");
    assert_eq!(
        group_kind(&report.responses[0]),
        Some(GroupErrorKind::StaleEpoch),
        "{who}: {:?}",
        report.responses[0]
    );
    assert_eq!(
        group_kind(&report.responses[1]),
        Some(GroupErrorKind::StaleEpoch),
        "{who}: {:?}",
        report.responses[1]
    );
    match &report.responses[2] {
        FirecrackerResponse::Create(reply) => {
            assert_eq!(class_of(reply), AmbiguousClass::OldEpoch, "{who}");
        }
        other => panic!("{who}: {other:?}"),
    }
    match &report.responses[3] {
        FirecrackerResponse::Fence(FenceReply::Ambiguous { class, .. }) => {
            assert_eq!(*class, AmbiguousClass::OldEpoch, "{who}");
        }
        other => panic!("{who}: {other:?}"),
    }
}

/// The scenario the review demonstrated, and the legitimate restart next to it.
async fn takeover_scenario(evidence: PeerEvidence) {
    let fixture = Fixture::unstarted(NodeOptions {
        auto_enroll: false,
        peers: evidence,
        ..NodeOptions::default()
    });
    let placement = Placement {
        evidence,
        root: fixture.root.clone(),
        created: Mutex::default(),
    };
    let instance = Id128::random();
    let database = Id128::random();
    let unit_cgroup = placement.cgroup_of(VICTIM_UNIT);
    let elsewhere = placement.cgroup_of("thief.service");
    assert!(matches!(
        fixture.enroll_as(instance, VICTIM_UNIT, &unit_cgroup, 8, VICTIM_ACCOUNT),
        EnrollOutcome::Enrolled { .. }
    ));
    #[cfg(target_os = "linux")]
    if matches!(evidence, PeerEvidence::Real) {
        fixture.allow_other_accounts();
    }
    fixture.start().await;
    let own = std::env::current_exe().unwrap();
    let copied = fixture.root.join("copied-kilnd");
    std::fs::copy(&own, &copied).unwrap();
    assert_ne!(
        std::fs::metadata(&copied).unwrap().ino(),
        std::fs::metadata(&own).unwrap().ino()
    );

    // The enrolled unit attaches and owns real work.
    let mut holder = fixture.spawn_peer(
        &PeerPlan {
            root: fixture.root.clone(),
            instance,
            database,
            stolen_epoch: None,
            create: true,
            operations: vec![],
            fence: None,
            hold: true,
        },
        &placement,
        &unit_cgroup,
        &own,
        "holder",
    );
    let held = holder.report().await;
    let stolen = *held.attach.as_ref().expect("the enrolled unit attaches");
    let create = held.create.clone().unwrap();
    let fence = held.fence_request.clone().unwrap();
    let FirecrackerOperation::Create {
        allocation_id,
        plan_digest,
        ..
    } = &create
    else {
        unreachable!();
    };
    let (allocation_id, plan_digest) = (*allocation_id, *plan_digest);
    let attempts = vec![
        FirecrackerOperation::Inspect {
            allocation_id,
            plan_digest,
        },
        FirecrackerOperation::List,
        create.clone(),
        fence.clone(),
    ];
    // Every copied value: instance, database, and even the live epoch itself.
    let thief_plan = || PeerPlan {
        root: fixture.root.clone(),
        instance,
        database,
        stolen_epoch: Some(stolen),
        create: false,
        operations: attempts.clone(),
        fence: None,
        hold: false,
    };
    let try_thieves = |stage: &'static str, refusals: &'static [&'static str]| {
        let wrong_cgroup = fixture.spawn_peer(
            &thief_plan(),
            &placement,
            &elsewhere,
            &own,
            &format!("{stage}-cgroup"),
        );
        let copied_image = fixture.spawn_peer(
            &thief_plan(),
            &placement,
            &unit_cgroup,
            &copied,
            &format!("{stage}-image"),
        );
        async move {
            assert_no_authority(
                &format!("{stage}: wrong cgroup"),
                &wrong_cgroup.report().await,
                refusals,
            );
            assert_no_authority(
                &format!("{stage}: copied image"),
                &copied_image.report().await,
                refusals,
            );
        }
    };

    // While the holder lives, and once it is gone, and across a helper restart.
    try_thieves("live", &["live holder"]).await;
    holder.kill();
    fixture.wait_detached().await;
    let refused = &["enrolled service"];
    try_thieves("after-death", refused).await;
    // A thief's attempt created nothing to answer for later, and no state.
    let census = fixture.census().await;
    assert_eq!(census["attached"], 0, "{census}");
    assert_eq!(census["closed_gates"], 0, "{census}");
    assert_eq!(census["open_gates"], 0, "{census}");
    assert_eq!(fixture.active_allocations(), 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    fixture.kill_helper().await;
    fixture.start().await;
    try_thieves("after-restart", refused).await;
    let census = fixture.census().await;
    assert_eq!(census["attached"], 0, "{census}");
    assert_eq!(fixture.active_allocations(), 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM instances"), 1);

    // Nothing enrolled, nothing attaches, whatever IDs it brings.
    let stranger = fixture.spawn_peer(
        &PeerPlan {
            instance: Id128::random(),
            database: Id128::random(),
            stolen_epoch: None,
            operations: vec![],
            ..thief_plan()
        },
        &placement,
        &unit_cgroup,
        &own,
        "stranger",
    );
    let refused = stranger.report().await.attach.unwrap_err();
    assert!(refused.contains("not enrolled"), "{refused}");

    // The enrolled unit's next process is the owner again, with full authority.
    let successor = fixture.spawn_peer(
        &PeerPlan {
            root: fixture.root.clone(),
            instance,
            database,
            stolen_epoch: None,
            create: false,
            operations: attempts.clone(),
            fence: Some(fence),
            hold: false,
        },
        &placement,
        &unit_cgroup,
        &own,
        "successor",
    );
    let report = successor.report().await;
    assert!(report.attach.is_ok(), "{:?}", report.attach);
    assert!(
        matches!(report.responses[0], FirecrackerResponse::Inspect(_)),
        "{:?}",
        report.responses[0]
    );
    assert!(
        matches!(report.responses[1], FirecrackerResponse::List(_)),
        "{:?}",
        report.responses[1]
    );
    assert!(
        matches!(
            report.responses[2],
            FirecrackerResponse::Create(CreateReply::Accepted { replay: true, .. })
        ),
        "{:?}",
        report.responses[2]
    );
    assert!(
        matches!(
            report.fence,
            Some(FirecrackerResponse::Fence(FenceReply::Absent { .. }))
        ),
        "{:?}",
        report.fence
    );
    assert_eq!(fixture.active_allocations(), 0);

    // The database UUID is reconciliation state, even for the real service: a new one
    // gets a read-only attachment, not a rebinding.
    let restored = fixture.spawn_peer(
        &PeerPlan {
            root: fixture.root.clone(),
            instance,
            database: Id128::random(),
            stolen_epoch: None,
            create: false,
            operations: vec![FirecrackerOperation::List],
            fence: None,
            hold: false,
        },
        &placement,
        &unit_cgroup,
        &own,
        "restored",
    );
    let report = restored.report().await;
    assert!(report.attach.is_ok(), "{:?}", report.attach);
    assert!(matches!(report.responses[0], FirecrackerResponse::List(_)));
    let bound: String = fixture
        .read(|view| view.query_row("SELECT database_uuid FROM instances", [], |r| r.get(0)));
    assert_eq!(bound, database.to_string());
}

#[tokio::test]
async fn b3_01_takeover_fails_after_death_restart_and_with_copied_files() {
    takeover_scenario(PeerEvidence::Markers).await;
}

/// The same scenario against the kernel's cgroups and the real pidfd pin.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root on Linux: run in the VM"]
async fn b3_linux_root_takeover_fails_against_real_cgroups() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    takeover_scenario(PeerEvidence::Real).await;
}

/// `/proc/<pid>/exe` under the service's real bounding set, which has no CAP_SYS_PTRACE.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root on Linux: run in the VM"]
fn b3_linux_root_attestation_needs_no_cap_sys_ptrace() {
    use super::super::peer::{PeerAttestor, TestPeers};
    const CAP_SYS_PTRACE: u32 = 19;
    const NOBODY: u32 = 65534;
    if let Ok(target) = std::env::var(ROOT_PTRACE_ENV) {
        // SAFETY: only this process's own capability sets change.
        unsafe {
            assert_eq!(
                libc::prctl(
                    libc::PR_CAPBSET_DROP,
                    CAP_SYS_PTRACE as libc::c_ulong,
                    0,
                    0,
                    0
                ),
                0
            );
            let mut header = [0x2008_0522u32, 0]; // _LINUX_CAPABILITY_VERSION_3
            let mut sets = [0u32; 6];
            assert_eq!(
                libc::syscall(libc::SYS_capget, header.as_mut_ptr(), sets.as_mut_ptr()),
                0
            );
            sets[0] &= !(1 << CAP_SYS_PTRACE); // effective
            sets[1] &= !(1 << CAP_SYS_PTRACE); // permitted
            assert_eq!(
                libc::syscall(libc::SYS_capset, header.as_mut_ptr(), sets.as_ptr()),
                0
            );
        }
        let pid: i32 = target.parse().unwrap();
        // The control: plain root can no longer open this other account's image.
        assert_eq!(
            std::fs::File::open(format!("/proc/{pid}/exe"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied,
        );
        let image = std::fs::File::open("/bin/sleep").unwrap();
        let meta = image.metadata().unwrap();
        let enrollment = Enrollment {
            instance_id: Id128::random(),
            unit: "nobody.service".into(),
            cgroup: "/any".into(),
            uid: NOBODY,
            gid: NOBODY,
            executable: EnrolledExecutable {
                st_dev: meta.dev(),
                st_ino: meta.ino(),
                bytes: meta.len(),
                sha256: executable::hash_descriptor(&image, meta.len()).unwrap(),
            },
        };
        let mut attestor = PeerAttestor::with_test_peers(TestPeers {
            directory: None,
            any_cgroup: true,
            any_account: false,
            assumed_digest: None,
        });
        attestor.attest(pid, &enrollment).unwrap();
        // Root's own filesystem IDs came back afterward.
        let own = std::fs::File::open(std::env::current_exe().unwrap());
        assert!(own.is_ok());
        assert_eq!(
            std::fs::read_to_string("/proc/self/status")
                .unwrap()
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .unwrap()
                .split_whitespace()
                .nth(4),
            Some("0"),
        );
        return;
    }
    use std::os::unix::process::CommandExt;
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    let mut target = Command::new("/bin/sleep")
        .arg("30")
        .uid(NOBODY)
        .gid(NOBODY)
        .spawn()
        .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "helper::firecracker::tests::control_plane::b3_linux_root_attestation_needs_no_cap_sys_ptrace",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(ROOT_PTRACE_ENV, target.id().to_string())
        .status()
        .unwrap();
    let _ = target.kill();
    let _ = target.wait();
    assert!(status.success());
}

/// PoC 01 in reverse. Two real accounts at the laxest Yama setting: the kernel's own
/// ptrace, signal and file checks separate them, so nothing depends on that sysctl.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root on Linux: run in the VM"]
fn b3r_02_linux_root_another_account_cannot_reach_memory_signals_or_state_at_yama_zero() {
    use std::os::unix::process::CommandExt;
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    struct Restore(Option<String>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(original) = self.0.take() {
                let _ = std::fs::write("/proc/sys/kernel/yama/ptrace_scope", original);
            }
        }
    }
    let original = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok();
    let _restore = Restore(original.clone());
    if original.is_some() {
        std::fs::write("/proc/sys/kernel/yama/ptrace_scope", "0").unwrap();
    }
    let mut daemon = Command::new("/bin/sleep")
        .arg("60")
        .uid(VICTIM_ACCOUNT.0)
        .gid(VICTIM_ACCOUNT.1)
        .spawn()
        .unwrap();
    let pid = daemon.id();
    // A state directory and database as the unit and store leave them.
    let state = tempfile::Builder::new()
        .prefix("b3r02")
        .tempdir_in("/tmp")
        .unwrap();
    let database = state.path().join("kilnd.db");
    std::fs::write(&database, b"token").unwrap();
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::chown(&database, Some(VICTIM_ACCOUNT.0), Some(VICTIM_ACCOUNT.1)).unwrap();
    std::os::unix::fs::chown(state.path(), Some(VICTIM_ACCOUNT.0), Some(VICTIM_ACCOUNT.1)).unwrap();
    let as_account = |(uid, gid): (u32, u32), script: &str| {
        Command::new("/bin/sh")
            .args(["-c", script])
            .uid(uid)
            .gid(gid)
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    let probes = [
        ("memory", format!("exec 3<>/proc/{pid}/mem")),
        ("signal", format!("kill -0 {pid}")),
        ("database", format!("cat {} >/dev/null", database.display())),
    ];
    for (what, script) in &probes {
        // The control: these probes do work, for the instance's own account.
        assert!(as_account(VICTIM_ACCOUNT, script), "own account: {what}");
        assert!(
            !as_account(ATTACKER_ACCOUNT, script),
            "other account: {what}"
        );
    }
    let _ = daemon.kill();
    let _ = daemon.wait();
    if let Some(value) = &original {
        drop(_restore);
        assert_eq!(
            &std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").unwrap(),
            value,
            "the original setting came back"
        );
    }
}

/// The connector's pidfd outlives its number's first owner and reports it gone.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn b3_01_linux_connection_pin_follows_the_connecting_process() {
    use super::super::peer::PeerPin;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pin.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let python = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-c",
            "import socket,sys,time;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);time.sleep(30)",
            path.to_str().unwrap(),
        ])
        .spawn();
    let Ok(mut connector) = python else {
        eprintln!("python3 is unavailable here; the root scenario covers the pin");
        return;
    };
    let (stream, _) = listener.accept().await.unwrap();
    let pin = PeerPin::of_connection(stream.as_raw_fd()).unwrap();
    assert!(pin.alive());
    connector.kill().unwrap();
    connector.wait().unwrap();
    assert!(
        !pin.alive(),
        "a reaped connector is gone, whatever its PID does"
    );
}

/// Another test's fork can hold a copy of the last enrollment's lock descriptor until its
/// exec closes it. The installed command runs alone, with the helper stopped.
fn enroll_past_forks<T>(mut enroll: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    let mut outcome = enroll();
    for _ in 0..200 {
        if !matches!(&outcome, Err(error) if error.contains("stop kilnd-helper")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
        outcome = enroll();
    }
    outcome
}

#[tokio::test]
async fn b3_01_enroll_checks_its_unit_image_limit_and_the_helper_lock() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    let config: ChildConfig =
        serde_json::from_slice(&std::fs::read(fixture.root.join("config.json")).unwrap()).unwrap();
    let ledger = ledger_config(&config);
    private_dir(&fixture.root.join("bin"));
    let kilnd = fixture.root.join("bin/kilnd");
    std::fs::write(&kilnd, b"kilnd image").unwrap();
    std::fs::set_permissions(&kilnd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let enroll = |instance: Id128, unit: &str, limit: u32, image: &Path| {
        let account = super::super::peer::fixture_account(instance);
        enroll_past_forks(|| {
            super::super::enroll_with(&ledger, limit, instance, unit, None, account, image)
        })
    };
    let first = Id128::random();
    let done = enroll(first, "kilnd.service", 2, &kilnd).unwrap();
    assert!(done.contains("enrolled"), "{done}");
    // The real image's identity went into the ledger, not anything a caller supplied.
    let row = fixture.read(|view| {
        view.query_row(
            "SELECT cgroup, exe_st_ino, exe_sha256, database_uuid FROM instances",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            },
        )
    });
    assert_eq!(row.0, "/system.slice/kilnd.service");
    assert_eq!(row.1 as u64, std::fs::metadata(&kilnd).unwrap().ino());
    assert_eq!(row.2, Digest::of(b"kilnd image").to_string());
    assert_eq!(row.3, None, "enrollment names no database");
    // One unit per instance, and only a plain unit name.
    let taken = enroll(Id128::random(), "kilnd.service", 2, &kilnd).unwrap_err();
    assert!(taken.contains("another instance"), "{taken}");
    assert!(enroll(Id128::random(), "../x.service", 2, &kilnd).is_err());
    enroll(Id128::random(), "second.service", 2, &kilnd).unwrap();
    let full = enroll(Id128::random(), "third.service", 2, &kilnd).unwrap_err();
    assert!(full.contains("allows 2"), "{full}");
    // An image another account could write, or a symlink to one, is not an identity.
    std::fs::set_permissions(&kilnd, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(enroll(first, "kilnd.service", 2, &kilnd).is_err());
    std::fs::set_permissions(&kilnd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let link = fixture.root.join("bin/link");
    std::os::unix::fs::symlink(&kilnd, &link).unwrap();
    assert!(enroll(first, "kilnd.service", 2, &link).is_err());
    assert!(enroll(first, "kilnd.service", 2, &fixture.root.join("bin/none")).is_err());
    // Re-enrolling after an upgrade names the new inode.
    let upgraded = fixture.root.join("bin/kilnd.new");
    std::fs::write(&upgraded, b"kilnd image 2").unwrap();
    std::fs::set_permissions(&upgraded, std::fs::Permissions::from_mode(0o755)).unwrap();
    let done = enroll(first, "kilnd.service", 2, &upgraded).unwrap();
    assert!(done.contains("updated"), "{done}");
    // With a helper running this takes no action at all.
    fixture.start().await;
    let account = super::super::peer::fixture_account(first);
    let busy = super::super::enroll_with(&ledger, 2, first, "kilnd.service", None, account, &kilnd)
        .unwrap_err();
    assert!(busy.contains("stop kilnd-helper"), "{busy}");
}

#[tokio::test]
async fn b3r_02_enroll_refuses_a_shared_or_privileged_account() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    let config: ChildConfig =
        serde_json::from_slice(&std::fs::read(fixture.root.join("config.json")).unwrap()).unwrap();
    let ledger = ledger_config(&config);
    private_dir(&fixture.root.join("bin"));
    let kilnd = fixture.root.join("bin/kilnd");
    std::fs::write(&kilnd, b"kilnd image").unwrap();
    std::fs::set_permissions(&kilnd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let enroll = |instance: Id128, unit: &str, account: (u32, u32)| {
        enroll_past_forks(|| {
            super::super::enroll_with(&ledger, 8, instance, unit, None, account, &kilnd)
        })
    };
    enroll(Id128::random(), "first.service", VICTIM_ACCOUNT).unwrap();
    let shared = enroll(Id128::random(), "second.service", VICTIM_ACCOUNT).unwrap_err();
    assert!(shared.contains("UID or GID"), "{shared}");
    let row: (i64, i64) = fixture.read(|view| {
        view.query_row("SELECT uid, gid FROM instances", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
    });
    assert_eq!(row, (64_100, 64_100), "the row records the account");
    // Root's command also rules out root, itself and the VM identity ranges.
    let policy = |uid, gid, helper| {
        super::super::peer::validate_account(uid, gid, helper, &IdentityRanges::default())
    };
    assert!(policy(0, 990, 0).is_err());
    assert!(policy(990, 0, 0).is_err());
    assert!(policy(990, 990, 990).is_err());
    assert!(policy(300_001, 990, 0).is_err());
    assert!(policy(990, 990, 0).is_ok());
}

/// B3F-03: root's upgrade commands, against a real ledger and image. They need the same
/// node lock enrollment does, and they rebind nothing.
#[tokio::test]
async fn b3f_03_refresh_binds_every_instance_to_the_new_image_and_restore_undoes_it() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    let config: ChildConfig =
        serde_json::from_slice(&std::fs::read(fixture.root.join("config.json")).unwrap()).unwrap();
    let ledger = ledger_config(&config);
    private_dir(&fixture.root.join("bin"));
    let (old_image, new_image) = (
        fixture.root.join("bin/kilnd"),
        fixture.root.join("bin/kilnd-next"),
    );
    for (path, bytes) in [(&old_image, &b"old"[..]), (&new_image, &b"newer"[..])] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (first, second) = (Id128::random(), Id128::random());
    for (instance, unit, account) in [
        (first, "first.service", VICTIM_ACCOUNT),
        (second, "second.service", ATTACKER_ACCOUNT),
    ] {
        enroll_past_forks(|| {
            super::super::enroll_with(&ledger, 8, instance, unit, None, account, &old_image)
        })
        .unwrap();
    }
    let before = enroll_past_forks(|| super::super::list_enrollments_with(&ledger)).unwrap();
    assert_eq!(before.len(), 2);

    let checked =
        enroll_past_forks(|| super::super::refresh_enrollments_with(&ledger, &new_image, true))
            .unwrap();
    assert!(checked.contains('2'), "{checked}");
    assert_eq!(
        enroll_past_forks(|| super::super::list_enrollments_with(&ledger)).unwrap(),
        before,
        "a check writes nothing"
    );
    let missing = fixture.root.join("bin/missing");
    enroll_past_forks(|| super::super::refresh_enrollments_with(&ledger, &missing, false))
        .unwrap_err();

    enroll_past_forks(|| super::super::refresh_enrollments_with(&ledger, &new_image, false))
        .unwrap();
    let after = enroll_past_forks(|| super::super::list_enrollments_with(&ledger)).unwrap();
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(
            (&old.instance_id, &old.unit, &old.cgroup, old.uid, old.gid),
            (&new.instance_id, &new.unit, &new.cgroup, new.uid, new.gid),
        );
        assert_ne!(old.executable, new.executable);
        assert_eq!(new.executable.bytes, 5);
    }

    enroll_past_forks(|| super::super::restore_enrollments_with(&ledger, &before)).unwrap();
    assert_eq!(
        enroll_past_forks(|| super::super::list_enrollments_with(&ledger)).unwrap(),
        before
    );
    let stale = enroll_past_forks(|| super::super::restore_enrollments_with(&ledger, &before[..1]))
        .unwrap_err();
    assert!(stale.contains("nothing was changed"), "{stale}");

    // With a helper running none of them takes any action.
    fixture.start().await;
    for busy in [
        super::super::list_enrollments_with(&ledger).unwrap_err(),
        super::super::refresh_enrollments_with(&ledger, &new_image, false).unwrap_err(),
        super::super::restore_enrollments_with(&ledger, &before).unwrap_err(),
    ] {
        assert!(busy.contains("stop kilnd-helper"), "{busy}");
    }
}

/// A ledger that binds an instance to root or to the VM identity ranges would break
/// every separation built on accounts, so that node serves no instance at all.
#[tokio::test]
async fn b3r_02_a_ledger_binding_a_forbidden_account_serves_no_instance() {
    for account in [
        (301_000, 990),
        // SAFETY: geteuid has no preconditions. The fixture helper's own account.
        (unsafe { libc::geteuid() }, 990),
    ] {
        let fixture = Fixture::unstarted(NodeOptions {
            auto_enroll: false,
            ..NodeOptions::default()
        });
        let instance = Id128::random();
        assert!(matches!(
            fixture.enroll_as(
                instance,
                VICTIM_UNIT,
                "/test.slice/victim.service",
                8,
                account
            ),
            EnrollOutcome::Enrolled { .. }
        ));
        fixture.start().await;
        let refused = fixture
            .runtime(instance, Id128::random())
            .test_epoch(deadline(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("account") || refused.contains("VM identity"),
            "{refused}"
        );
    }
}

#[test]
fn b3_02_policy_bounds_enrollment_and_defaults_to_eight() {
    use super::super::config::{MAX_ENROLLED_HARD, POLICY_SCHEMA, parse_policy};
    let policy = |extra: Option<u32>| {
        let mut document = json!({
            "schema": POLICY_SCHEMA,
            "node_id": Id128::random().to_string(),
            "ledger_dir": "/var/lib/kilnd-helper/firecracker",
            "ceilings": NodeCeilings::default(),
            "uid_range": {"first": 300000, "last": 365535},
            "gid_range": {"first": 300000, "last": 365535},
            "cid_range": {"first": 3, "last": 65535},
            "profiles": [],
        });
        if let Some(limit) = extra {
            document["max_enrolled_instances"] = json!(limit);
        }
        serde_json::to_vec(&document).unwrap()
    };
    assert_eq!(
        parse_policy(&policy(None), 999)
            .unwrap()
            .max_enrolled_instances,
        8
    );
    assert_eq!(
        parse_policy(&policy(Some(2)), 999)
            .unwrap()
            .max_enrolled_instances,
        2
    );
    assert!(parse_policy(&policy(Some(0)), 999).is_err());
    assert!(parse_policy(&policy(Some(MAX_ENROLLED_HARD + 1)), 999).is_err());
}

#[tokio::test]
async fn b3_02_no_flood_of_attachments_can_starve_an_enrolled_instance() {
    let fixture = Fixture::unstarted(NodeOptions {
        auto_enroll: false,
        ..NodeOptions::default()
    });
    let instances: Vec<Id128> = (0..8).map(|_| Id128::random()).collect();
    for (index, instance) in instances.iter().enumerate() {
        let unit = format!("kilnd-{index}.service");
        let cgroup = format!("/test.slice/{unit}");
        assert!(matches!(
            fixture.enroll(*instance, &unit, &cgroup, 8),
            EnrollOutcome::Enrolled { .. }
        ));
    }
    // The ninth is root's own limit, and nothing else can enroll at all.
    assert_eq!(
        fixture.enroll(
            Id128::random(),
            "ninth.service",
            "/test.slice/ninth.service",
            8
        ),
        EnrollOutcome::LimitReached { limit: 8 }
    );
    fixture.start().await;
    // Seven hold all they can. The old pool of sixteen would need nine more of them.
    let mut holders = Vec::new();
    for instance in &instances[..7] {
        let runtime = fixture.runtime(*instance, Id128::random());
        epoch_of(&runtime).await;
        holders.push(runtime);
    }
    // Hundreds of attempts, in parallel, with every identity the attacker can choose.
    let mut floods = Vec::new();
    // Under the 128 framing slots, whose fairness the design doesn't promise.
    for _ in 0..100 {
        let runtime = fixture.runtime(Id128::random(), Id128::random());
        floods.push(tokio::spawn(async move {
            runtime
                .test_epoch(deadline(10))
                .await
                .map_err(|e| e.to_string())
        }));
    }
    for _ in 0..20 {
        let runtime = fixture.runtime(instances[0], Id128::random());
        floods.push(tokio::spawn(async move {
            runtime
                .test_epoch(deadline(10))
                .await
                .map_err(|e| e.to_string())
        }));
    }
    // The last instance attaches, first try, in the middle of all that.
    let victim = fixture.runtime(instances[7], Id128::random());
    epoch_of(&victim).await;
    assert!(victim.version(deadline(5), &no_cancel()).await.is_ok());
    for flood in floods {
        let refused = flood.await.unwrap().unwrap_err();
        assert!(
            refused.contains("not enrolled")
                || refused.contains("live holder")
                || refused.contains("too many attach attempts"),
            "{refused}"
        );
    }
    // Holders keep their own slots, and one leaving helps only itself return.
    holders[0].test_reattach().await;
    wait_until_attached(&holders[0]).await;
    for holder in &holders {
        assert!(holder.version(deadline(5), &no_cancel()).await.is_ok());
    }
    assert_eq!(fixture.census().await["attached"], 8);
}

/// The report's PoC turned around: the victim has no live attachment, L is stalled, and
/// every queue an attacker can reach is full. The real service still gets its proof.
async fn targeted_attach_scenario(evidence: PeerEvidence) {
    let fixture = Fixture::unstarted(NodeOptions {
        auto_enroll: false,
        peers: evidence,
        ..NodeOptions::default()
    });
    let placement = Placement {
        evidence,
        root: fixture.root.clone(),
        created: Mutex::default(),
    };
    let victim = Id128::random();
    let attacker = Id128::random();
    let victim_cgroup = placement.cgroup_of(VICTIM_UNIT);
    let attacker_cgroup = placement.cgroup_of("attacker.service");
    let elsewhere = placement.cgroup_of("elsewhere.service");
    assert!(matches!(
        fixture.enroll_as(victim, VICTIM_UNIT, &victim_cgroup, 8, VICTIM_ACCOUNT),
        EnrollOutcome::Enrolled { .. }
    ));
    assert!(matches!(
        fixture.enroll_as(
            attacker,
            "attacker.service",
            &attacker_cgroup,
            8,
            ATTACKER_ACCOUNT
        ),
        EnrollOutcome::Enrolled { .. }
    ));
    #[cfg(target_os = "linux")]
    if matches!(evidence, PeerEvidence::Real) {
        fixture.allow_other_accounts();
    }
    fixture.start().await;
    let image = std::env::current_exe().unwrap();
    let plan = |instance| PeerPlan {
        root: fixture.root.clone(),
        instance,
        database: Id128::random(),
        stolen_epoch: None,
        create: false,
        operations: Vec::new(),
        fence: None,
        hold: false,
    };

    // Make L stop between requests. A sacrificial wrong-cgroup request gets L to the
    // next loop, where the deterministic fault holds it before another proof.
    fixture.fault("L.loop.stall");
    let sacrificial = fixture.spawn_peer_as(
        &plan(attacker),
        &placement,
        &elsewhere,
        &image,
        "sacrificial",
        ATTACKER_ACCOUNT,
    );
    assert!(sacrificial.report().await.attach.is_err());
    fixture.wait_reached("L.loop").await;

    // Naming the victim gets the attacker, and an account root never enrolled, nothing:
    // these are refused with L stalled, so they can't have queued for it.
    let mut aimed = Vec::new();
    for index in 0..=MAX_ATTACH_WAITERS {
        aimed.push(fixture.spawn_peer_as(
            &plan(victim),
            &placement,
            &elsewhere,
            &image,
            &format!("aimed-{index}"),
            ATTACKER_ACCOUNT,
        ));
    }
    let stranger = fixture.spawn_peer_as(
        &plan(victim),
        &placement,
        &elsewhere,
        &image,
        "stranger",
        STRANGER_ACCOUNT,
    );
    for peer in &aimed {
        let refused = peer.report().await.attach.unwrap_err();
        assert!(
            refused.contains("not enrolled under this account"),
            "{refused}"
        );
    }
    assert!(stranger.report().await.attach.is_err());

    // The attacker's own queue fills: one proof and eight waiting, all doomed.
    let mut own = Vec::new();
    for index in 0..=MAX_ATTACH_WAITERS {
        own.push(fixture.spawn_peer_as(
            &plan(attacker),
            &placement,
            &elsewhere,
            &image,
            &format!("own-{index}"),
            ATTACKER_ACCOUNT,
        ));
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let overflow = fixture.spawn_peer_as(
        &plan(attacker),
        &placement,
        &elsewhere,
        &image,
        "overflow",
        ATTACKER_ACCOUNT,
    );
    let refused = overflow.report().await.attach.unwrap_err();
    assert!(refused.contains("too many attach attempts"), "{refused}");

    // None of that touched the victim's queue: its real service waits for L, unrefused.
    let service = fixture.spawn_peer(
        &plan(victim),
        &placement,
        &victim_cgroup,
        &image,
        "victim-while-flooded",
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !service.out.with_extension("report").exists(),
        "the service was answered while L was stalled"
    );
    fixture.clear("L.loop.stall");
    let report = service.report().await;
    assert!(report.attach.is_ok(), "{:?}", report.attach);
    for peer in own {
        let refused = peer.report().await.attach.unwrap_err();
        assert!(refused.contains("not the enrolled service"), "{refused}");
    }
}

#[tokio::test]
async fn b3r_03_wrong_account_and_wrong_cgroup_peers_cannot_touch_a_victims_attach() {
    targeted_attach_scenario(PeerEvidence::Markers).await;
}

/// The same with two real accounts, SO_PEERCRED and the kernel's cgroups.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root on Linux: run in the VM"]
async fn b3r_03_linux_root_real_accounts_cannot_touch_a_victims_attach() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    targeted_attach_scenario(PeerEvidence::Real).await;
}

/// What one probe process, run under a real account, tries against the helper socket.
#[cfg(target_os = "linux")]
const PROBE_ENV: &str = "KILND_B3_PROBE";

/// Exits 0 only if the helper said nothing at all to a kiln request, or keeps silent
/// connections open until killed. Run as a separate process under another real account.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "re-exec target for real-account probes"]
fn account_probe_child() {
    let Ok(probe) = std::env::var(PROBE_ENV) else {
        return;
    };
    let (mode, socket) = probe.split_once(':').unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        if mode == "silent" {
            // Every framing slot this account can reach, for as long as it is allowed.
            let mut held = Vec::new();
            loop {
                if let Ok(stream) = UnixStream::connect(socket).await {
                    held.push(stream);
                }
                if held.len() >= 800 {
                    held.drain(..400);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        assert!(kiln_probe(Path::new(socket)).await.is_err());
    });
}

/// One kiln request, as far as the helper lets it go.
#[cfg(target_os = "linux")]
async fn kiln_probe(socket: &Path) -> std::io::Result<Response> {
    let request = Request {
        version: VERSION,
        timeout_ms: 2000,
        deadline_ns: wire_deadline(2),
        operation: Operation::Kiln(KilnRequest::Capabilities { id: None }),
    };
    let mut stream = UnixStream::connect(socket).await?;
    fds::send(&stream, &[]).await?;
    write_frame(&mut stream, &request).await?;
    fds::receive(&stream).await?;
    read_frame::<Response>(&mut stream).await
}

#[cfg(target_os = "linux")]
fn probe_as(account: (u32, u32), mode: &str, socket: &Path) -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "helper::firecracker::tests::control_plane::account_probe_child",
            "--test-threads=1",
        ])
        .env(PROBE_ENV, format!("{mode}:{}", socket.display()))
        .uid(account.0)
        .gid(account.1)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// The listener's half, with real accounts: an account root never enrolled gets no frame
/// read, an enrolled one gets no kiln, and one holding every framing slot it can reach
/// doesn't keep another from attaching.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root on Linux: run in the VM"]
async fn b3r_linux_root_the_listener_tells_real_accounts_apart() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    let evidence = PeerEvidence::Real;
    let fixture = Fixture::unstarted(NodeOptions {
        auto_enroll: false,
        peers: evidence,
        ..NodeOptions::default()
    });
    let placement = Placement {
        evidence,
        root: fixture.root.clone(),
        created: Mutex::default(),
    };
    let (victim, attacker) = (Id128::random(), Id128::random());
    let victim_cgroup = placement.cgroup_of(VICTIM_UNIT);
    let attacker_cgroup = placement.cgroup_of("attacker.service");
    fixture.enroll_as(victim, VICTIM_UNIT, &victim_cgroup, 8, VICTIM_ACCOUNT);
    fixture.enroll_as(
        attacker,
        "attacker.service",
        &attacker_cgroup,
        8,
        ATTACKER_ACCOUNT,
    );
    fixture.allow_other_accounts();
    fixture.start().await;
    let socket = fixture.root.join("helper.sock");

    // The control: the service account does get an answer from kiln's side.
    assert!(kiln_probe(&socket).await.is_ok());
    // An enrolled account gets nothing about kiln, and neither does a stranger.
    for account in [ATTACKER_ACCOUNT, STRANGER_ACCOUNT] {
        let status = probe_as(account, "kiln", &socket).status().unwrap();
        assert!(status.success(), "{account:?} heard from kiln");
    }

    // The attacker holds every framing slot it can. The victim attaches anyway.
    let mut silent = probe_as(ATTACKER_ACCOUNT, "silent", &socket)
        .spawn()
        .unwrap();
    // The control: the shared slots really are gone, even for the service account.
    let mut crowded_out = false;
    for _ in 0..100 {
        if kiln_probe(&socket).await.is_err() {
            crowded_out = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(crowded_out, "the flood never filled the framing slots");
    let image = std::env::current_exe().unwrap();
    let plan = PeerPlan {
        root: fixture.root.clone(),
        instance: victim,
        database: Id128::random(),
        stolen_epoch: None,
        create: true,
        operations: vec![],
        fence: None,
        hold: false,
    };
    let service = fixture.spawn_peer(&plan, &placement, &victim_cgroup, &image, "under-flood");
    let report = service.report().await;
    let _ = silent.kill();
    let _ = silent.wait();
    assert!(report.attach.is_ok(), "{:?}", report.attach);
    // That Create really committed, under this instance's account alone.
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM allocations WHERE instance_id = '{victim}'"
        )),
        1
    );
}

/// B3R-01 with a real second account: the attacker's copy of the victim's fence touches
/// nothing of the victim's, and the victim's token is still its own afterward. Since B7
/// milestone 1 the token carries the issuing instance's tag (RTC-3), so H refuses the
/// copy at its tag check, before any gate or ledger row (B7 integration: this root test
/// still expected the pre-B7 fence in the attacker's own namespace).
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root on Linux: run in the VM"]
async fn b3r_01_linux_root_a_prefence_from_a_real_second_account_stays_its_own() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    let evidence = PeerEvidence::Real;
    let fixture = Fixture::unstarted(NodeOptions {
        auto_enroll: false,
        peers: evidence,
        ..NodeOptions::default()
    });
    let placement = Placement {
        evidence,
        root: fixture.root.clone(),
        created: Mutex::default(),
    };
    let (victim, attacker) = (Id128::random(), Id128::random());
    let victim_cgroup = placement.cgroup_of(VICTIM_UNIT);
    let attacker_cgroup = placement.cgroup_of("attacker.service");
    fixture.enroll_as(victim, VICTIM_UNIT, &victim_cgroup, 8, VICTIM_ACCOUNT);
    fixture.enroll_as(
        attacker,
        "attacker.service",
        &attacker_cgroup,
        8,
        ATTACKER_ACCOUNT,
    );
    fixture.allow_other_accounts();
    fixture.start().await;
    let image = std::env::current_exe().unwrap();
    // The victim creates, holding its attachment, so the token and its fence are real.
    let database = Id128::random();
    let holder = fixture.spawn_peer(
        &PeerPlan {
            root: fixture.root.clone(),
            instance: victim,
            database,
            stolen_epoch: None,
            create: true,
            operations: vec![],
            fence: None,
            hold: true,
        },
        &placement,
        &victim_cgroup,
        &image,
        "victim",
    );
    let held = holder.report().await;
    let fence = held.fence_request.clone().unwrap();
    let FirecrackerOperation::FenceAbsent { allocation_id, .. } = &fence else {
        unreachable!();
    };
    let allocation_id = *allocation_id;
    // The attacker sends the victim's exact fence under its own attachment.
    let aimed = fixture.spawn_peer_as(
        &PeerPlan {
            root: fixture.root.clone(),
            instance: attacker,
            database: Id128::random(),
            stolen_epoch: None,
            create: false,
            operations: vec![],
            fence: Some(fence.clone()),
            hold: false,
        },
        &placement,
        &attacker_cgroup,
        &image,
        "attacker",
        ATTACKER_ACCOUNT,
    );
    let aimed = aimed.report().await;
    assert!(aimed.attach.is_ok(), "{:?}", aimed.attach);
    assert!(
        matches!(
            &aimed.fence,
            Some(FirecrackerResponse::Error(GroupError { kind: GroupErrorKind::Incompatible, message }))
                if message.contains("not issued to this instance")
        ),
        "{:?}",
        aimed.fence
    );
    // Nothing reached the ledger for either account, and the victim's claim did not move.
    let count = |sql: String| fixture.count(&sql);
    assert_eq!(
        count(format!(
            "SELECT COUNT(*) FROM retired_tokens WHERE allocation_id = '{allocation_id}'
             AND instance_id = '{attacker}'"
        )),
        0
    );
    assert_eq!(
        count(format!(
            "SELECT COUNT(*) FROM retired_tokens WHERE instance_id = '{victim}'"
        )),
        0
    );
    assert_eq!(fixture.active_allocations(), 1);
    // The victim's own account, next process, fences exactly.
    drop(holder);
    fixture.wait_detached_of(victim).await;
    let successor = fixture.spawn_peer(
        &PeerPlan {
            root: fixture.root.clone(),
            instance: victim,
            database,
            stolen_epoch: None,
            create: false,
            operations: vec![],
            fence: Some(fence),
            hold: false,
        },
        &placement,
        &victim_cgroup,
        &image,
        "successor",
    );
    let report = successor.report().await;
    assert!(
        matches!(
            report.fence,
            Some(FirecrackerResponse::Fence(FenceReply::Absent { .. }))
        ),
        "{:?}",
        report.fence
    );
    assert_eq!(fixture.active_allocations(), 0);
}

#[tokio::test]
async fn b3_02_attach_churn_cannot_grow_the_root_ledger() {
    let fixture = Fixture::unstarted(NodeOptions {
        auto_enroll: false,
        ..NodeOptions::default()
    });
    let instance = Id128::random();
    let cgroup = format!("/test.slice/{VICTIM_UNIT}");
    fixture.enroll(instance, VICTIM_UNIT, &cgroup, 8);
    fixture.start().await;
    let database = Id128::random();
    let owner = fixture.runtime(instance, database);
    epoch_of(&owner).await;
    let generation = || fixture.count("SELECT value FROM generation_counter");
    let before = generation();
    // The review's loop: a fresh identity each cycle, detached each time.
    for _ in 0..100 {
        let attempt = fixture.runtime(Id128::random(), Id128::random());
        assert!(attempt.test_epoch(deadline(5)).await.is_err());
        owner.test_reattach().await;
        wait_until_attached(&owner).await;
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM instances"), 1);
    assert_eq!(generation(), before, "no attach path advanced the ledger");
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM worker_intents WHERE allocation_id IS NOT NULL"),
        0
    );
}

/// A malformed Create: well-framed, and the plan is bound to a different token.
/// B7: the token is a real issued one, so the Create passes H's tag check and is
/// rejected only by the plan's binding, closing that token's gate.
async fn poison(
    fixture: &Fixture,
    runtime: &FirecrackerRuntime,
    instance: Id128,
    epoch: Id128,
    plan: &PreparedCreate,
) {
    let (target, _) = issued(runtime, instance).await;
    let reply = raw_create(fixture, &target, epoch, plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch);
}

/// B7 (RTC-3, RTC-15): what a tag refusal must leave alone, read before it.
struct TagCensus {
    ledger_calls: Value,
    refusals: u64,
    closed: Value,
    open: Value,
    rows: i64,
}

fn ledger_rows(fixture: &Fixture) -> i64 {
    fixture.count("SELECT COUNT(*) FROM allocations")
        + fixture.count("SELECT COUNT(*) FROM retired_tokens")
}

async fn tag_census(fixture: &Fixture) -> TagCensus {
    let census = fixture.census().await;
    TagCensus {
        ledger_calls: census["ledger_calls"].clone(),
        refusals: census["tag_refusals"].as_u64().unwrap(),
        closed: census["closed_gates"].clone(),
        open: census["open_gates"].clone(),
        rows: ledger_rows(fixture),
    }
}

impl TagCensus {
    /// `refused` more tokens failed H's tag check, and nothing else moved: no L call,
    /// no gate, no ledger row.
    async fn assert_only_refused(&self, fixture: &Fixture, refused: u64) {
        let census = fixture.census().await;
        assert_eq!(census["ledger_calls"], self.ledger_calls, "no L call: {census}");
        assert_eq!(census["tag_refusals"].as_u64().unwrap(), self.refusals + refused);
        assert_eq!(census["closed_gates"], self.closed, "no gate retained: {census}");
        assert_eq!(census["open_gates"], self.open, "no gate open: {census}");
        assert_eq!(ledger_rows(fixture), self.rows, "no ledger row");
    }
}

fn tag_refused(response: &FirecrackerResponse) -> bool {
    matches!(
        response,
        FirecrackerResponse::Error(GroupError {
            kind: GroupErrorKind::Incompatible,
            ..
        })
    )
}

/// One raw request that H must refuse by its tag check alone.
async fn refused_by_tag(
    fixture: &Fixture,
    instance: Id128,
    epoch: Id128,
    operation: FirecrackerOperation,
) {
    let before = tag_census(fixture).await;
    let reply = raw_call(fixture, instance, Some(epoch), operation, wire_deadline(5), 5_000)
        .await
        .unwrap();
    assert!(tag_refused(&reply), "{reply:?}");
    before.assert_only_refused(fixture, 1).await;
}

#[tokio::test]
async fn b3_03_rejected_creates_cannot_block_another_instances_create_or_fence() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let attacker_id = Id128::random();
    let attacker = fixture.runtime(attacker_id, Id128::random());
    let (seed, plan) = issued(&attacker, attacker_id).await;
    let epoch = epoch_of(&attacker).await;
    // B7: random IDs (checked while no allocation is live) no longer reach a gate at all: H refuses them by their tag.
    let before = tag_census(&fixture).await;
    for _ in 0..super::super::MAX_TOKEN_GATES {
        let reply = raw_call(
            &fixture,
            attacker_id,
            Some(epoch),
            create_operation(&token(attacker_id), &plan),
            wire_deadline(5),
            5_000,
        )
        .await
        .unwrap();
        assert!(tag_refused(&reply), "{reply:?}");
    }
    before
        .assert_only_refused(&fixture, super::super::MAX_TOKEN_GATES as u64)
        .await;
    let victim_id = Id128::random();
    let victim = fixture.runtime(victim_id, Id128::random());
    // A token that really reached the ledger before the attack began.
    let (owned, owned_plan) = issued(&victim, victim_id).await;
    create_accepted(&fixture, &victim, &owned, &owned_plan).await;

    // B7: so the flood that can fill gates is of issued tokens, past the share.
    let quota = super::super::MAX_TOKEN_GATES / DEFAULT_MAX_ENROLLED as usize;
    for _ in 0..quota + 16 {
        poison(&fixture, &attacker, attacker_id, epoch, &plan).await;
    }
    // Memory stayed within one instance's share, and none of it stayed open.
    let census = fixture.census().await;
    assert_eq!(census["closed_gates"], quota, "{census}");
    assert!(
        census["closed_gates"].as_u64().unwrap() as usize <= quota,
        "{census}"
    );
    assert_eq!(census["open_gates"], 0, "{census}");

    // The victim admits a new Create, and fences a token only its own C1 knows about.
    let (fresh, fresh_plan) = issued(&victim, victim_id).await;
    assert!(
        matches!(
            raw_create(&fixture, &fresh, epoch_of(&victim).await, &fresh_plan).await,
            CreateReply::Accepted { replay: false, .. }
        ),
        "the victim's Create is refused"
    );
    let (reconciled, reconciled_plan) = issued(&victim, victim_id).await;
    fenced(
        victim
            .fence_absent(
                &reconciled,
                &reconciled_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    // And it fences what the ledger already owns.
    fenced(
        victim
            .fence_absent(
                &owned,
                &owned_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    // The attacker hurt itself no more than the rest: malformed gates gave way.
    assert!(matches!(
        raw_create(&fixture, &seed, epoch, &plan).await,
        CreateReply::Accepted { replay: false, .. }
    ));
}

#[tokio::test]
async fn b3_03_a_token_id_from_another_instance_touches_only_its_senders_gates() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let attacker_id = Id128::random();
    let attacker = fixture.runtime(attacker_id, Id128::random());
    let (seed, plan) = issued(&attacker, attacker_id).await;
    let epoch = epoch_of(&attacker).await;
    let victim_id = Id128::random();
    let victim = fixture.runtime(victim_id, Id128::random());
    let (context, victim_plan) = issued(&victim, victim_id).await;
    // Copied from the victim's database, then rejected in the attacker's name.
    // B7: rejected by H's tag check, before any gate (the sender's or the victim's) or
    // L call; the attacker's own token still works too.
    let aimed = CreateContext {
        instance_id: attacker_id,
        allocation_id: context.allocation_id,
        sandbox_id: context.sandbox_id.clone(),
    };
    refused_by_tag(&fixture, attacker_id, epoch, create_operation(&aimed, &plan)).await;
    assert!(matches!(
        raw_create(&fixture, &seed, epoch, &plan).await,
        CreateReply::Accepted { replay: false, .. }
    ));
    assert!(matches!(
        raw_create(&fixture, &context, epoch_of(&victim).await, &victim_plan).await,
        CreateReply::Accepted { replay: false, .. }
    ));
}

#[tokio::test]
async fn b3r_01_a_copied_token_prefenced_by_another_instance_stays_the_victims() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let attacker_id = Id128::random();
    let attacker = fixture.runtime(attacker_id, Id128::random());
    epoch_of(&attacker).await;
    let victim_id = Id128::random();
    let victim = fixture.runtime(victim_id, Id128::random());
    // The victim has finished C0, and C1 holds this exact binding.
    let (victim_context, victim_plan) = issued(&victim, victim_id).await;
    // The attacker tries to retire the copied ID in its own namespace.
    // B7: the copy does not verify there, so H refuses it before any gate or L call,
    // and not even the attacker's own namespace gets a row.
    let aimed = CreateContext {
        instance_id: attacker_id,
        allocation_id: victim_context.allocation_id,
        sandbox_id: victim_context.sandbox_id.clone(),
    };
    let before = tag_census(&fixture).await;
    let refused = attacker
        .fence_absent(
            &aimed,
            &victim_plan.plan_digest(),
            deadline(20),
            &no_cancel(),
        )
        .await;
    assert!(matches!(refused, Err(RuntimeError::Incompatible(_))), "{refused:?}");
    // The adapter's Remove, then its FenceAbsent: both refused by the tag.
    before.assert_only_refused(&fixture, 2).await;
    assert_eq!(fixture.count("SELECT COUNT(*) FROM retired_tokens"), 0);
    // A helper restart changes nothing about whose token this is.
    fixture.kill_helper().await;
    fixture.start().await;
    let renewed = fixture.runtime(victim_id, runtime_database(&fixture, victim_id));
    assert!(matches!(
        renewed
            .inspect_allocation(
                &victim_context,
                &victim_plan.plan_digest(),
                deadline(5),
                &no_cancel()
            )
            .await
            .unwrap(),
        AllocationObservation::Unknown { .. }
    ));
    assert!(matches!(
        raw_create(
            &fixture,
            &victim_context,
            epoch_of(&renewed).await,
            &victim_plan
        )
        .await,
        CreateReply::Accepted { replay: false, .. }
    ));
    let receipt = fenced(
        renewed
            .fence_absent(
                &victim_context,
                &victim_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(receipt.instance_id(), victim_id);
    assert_eq!(receipt.allocation_id(), victim_context.allocation_id);
}

#[tokio::test]
async fn b3r_01_a_fence_with_no_create_also_stays_with_the_victim() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let attacker_id = Id128::random();
    let attacker = fixture.runtime(attacker_id, Id128::random());
    let victim_id = Id128::random();
    let victim = fixture.runtime(victim_id, Id128::random());
    let (victim_context, victim_plan) = issued(&victim, victim_id).await;
    let aimed = CreateContext {
        instance_id: attacker_id,
        allocation_id: victim_context.allocation_id,
        sandbox_id: victim_context.sandbox_id.clone(),
    };
    // B7: the copied token is refused by H's tag check: no gate, L call or row.
    epoch_of(&attacker).await;
    let before = tag_census(&fixture).await;
    let refused = attacker
        .fence_absent(
            &aimed,
            &victim_plan.plan_digest(),
            deadline(20),
            &no_cancel(),
        )
        .await;
    assert!(matches!(refused, Err(RuntimeError::Incompatible(_))), "{refused:?}");
    // The adapter's Remove, then its FenceAbsent: both refused by the tag.
    before.assert_only_refused(&fixture, 2).await;
    // The victim's recovery path: its own exact fence, with no Create at all.
    let receipt = fenced(
        victim
            .fence_absent(
                &victim_context,
                &victim_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(receipt.instance_id(), victim_id);
    // B7: only the victim's namespace holds a row for its token.
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM retired_tokens"),
        1,
        "only the victim's, and it does not conflict"
    );
}

#[tokio::test]
async fn b3r_01_a_claim_on_a_copied_token_shares_no_name_with_the_victim() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let attacker_id = Id128::random();
    let attacker = fixture.runtime(attacker_id, Id128::random());
    let victim_id = Id128::random();
    let victim = fixture.runtime(victim_id, Id128::random());
    let (victim_context, victim_plan) = issued(&victim, victim_id).await;
    // The attacker claims first, with the victim's allocation and sandbox IDs.
    // B7: the copied allocation ID is refused by H's tag check, so the most it can claim
    // is its own issued token under the victim's sandbox ID.
    let copied = CreateContext {
        instance_id: attacker_id,
        allocation_id: victim_context.allocation_id,
        sandbox_id: victim_context.sandbox_id.clone(),
    };
    let aimed_plan = prepared(&attacker, &copied).await;
    let epoch = epoch_of(&attacker).await;
    refused_by_tag(&fixture, attacker_id, epoch, create_operation(&copied, &aimed_plan)).await;
    let aimed = CreateContext {
        allocation_id: aimed_plan.allocation_id().unwrap(),
        ..copied
    };
    assert_ne!(aimed.allocation_id, victim_context.allocation_id);
    assert!(matches!(
        raw_create(&fixture, &aimed, epoch, &aimed_plan).await,
        CreateReply::Accepted { replay: false, .. }
    ));
    assert!(matches!(
        raw_create(
            &fixture,
            &victim_context,
            epoch_of(&victim).await,
            &victim_plan
        )
        .await,
        CreateReply::Accepted { replay: false, .. }
    ));
    // Node-global host names differ, though each plan binds the same sandbox ID.
    let launch = |plan: &PreparedCreate| -> Value {
        crate::firecracker::strict_json(plan.backend_plan()).unwrap()["launch"].clone()
    };
    let (theirs, mine) = (launch(&aimed_plan), launch(&victim_plan));
    assert_ne!(theirs["jail_root"], mine["jail_root"]);
    assert_ne!(theirs["jailer_argv"], mine["jailer_argv"]);
    // B7: the victim's token has a row only in the victim's namespace.
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM allocations WHERE allocation_id = '{}'",
            victim_context.allocation_id
        )),
        1
    );
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM allocations WHERE sandbox_id = '{}'",
            victim_context.sandbox_id
        )),
        2
    );
    // Each one fences alone, and the other's claim doesn't move.
    fenced(
        attacker
            .fence_absent(
                &aimed,
                &aimed_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(node_totals(&victim).await.claimed.slots, 1);
    assert_eq!(fixture.active_allocations(), 1);
    fenced(
        victim
            .fence_absent(
                &victim_context,
                &victim_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(node_totals(&victim).await.claimed.slots, 0);
}

/// The report's real manager test: paused after its C1, with the row committed, while a
/// second attached instance pre-fences what it copied from that row.
#[tokio::test]
async fn b3r_01_real_manager_paused_after_c1_keeps_an_exact_path_past_a_prefence() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let attacker_id = Id128::random();
    let attacker = fixture.runtime(attacker_id, Id128::random());
    epoch_of(&attacker).await;

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
    let window = format!("H.create.enter.{}", identity.instance_id);
    fixture.fault(&format!("{window}.hold"));
    let creating = {
        let manager = manager.clone();
        tokio::spawn(async move {
            manager
                .create(CreateRequest {
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
    fixture.wait_reached(&window).await;
    // C1 committed: this is the row a daemon's database holds before C2.
    let rows = manager.list(true).unwrap();
    assert_eq!(rows.len(), 1);
    let row = rows[0].clone();
    let binding = row.accounting.allocation.clone().unwrap();
    assert!(row.is_charged());
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM allocations WHERE allocation_id = '{}'",
            binding.allocation_id
        )),
        0,
        "C2 has not happened"
    );
    let aimed = CreateContext {
        instance_id: attacker_id,
        allocation_id: binding.allocation_id,
        sandbox_id: row.id.clone(),
    };
    // B7: the pre-fence on the copied token is refused by H's tag check: no L call,
    // no gate and no row, in either namespace.
    let before = tag_census(&fixture).await;
    let refused = attacker
        .fence_absent(&aimed, &binding.plan_digest, deadline(20), &no_cancel())
        .await;
    assert!(matches!(refused, Err(RuntimeError::Incompatible(_))), "{refused:?}");
    // The adapter's Remove, then its FenceAbsent: both refused by the tag.
    before.assert_only_refused(&fixture, 2).await;
    fixture.clear(&format!("{window}.hold"));
    // The victim's Create reaches its own C2: the attacker's row is no obstacle.
    let _ = creating.await.unwrap();
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM allocations WHERE allocation_id = '{}' AND instance_id = '{}'",
            binding.allocation_id, identity.instance_id
        )),
        1,
        "the victim's Create was admitted"
    );
    // And it fences exactly, through the manager's own Delete.
    let deleted = manager.delete(&row.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert!(!deleted.is_charged());
    let ReservationRelease::Fenced(released) = &deleted.accounting.release else {
        panic!("{:?}", deleted.accounting.release);
    };
    assert_eq!(
        fixture.count(&format!(
            "SELECT COUNT(*) FROM retired_tokens WHERE receipt_id = '{released}'
             AND instance_id = '{}'",
            identity.instance_id
        )),
        1
    );
}

/// An expired Create that passes the durable lookup and closes its gate. A daemon could
/// hold a C1 charge for this one, so unlike a malformed token its gate is never evicted.
async fn expire(fixture: &Fixture, context: &CreateContext, epoch: Id128, plan: &PreparedCreate) {
    let reply = raw_call(
        fixture,
        context.instance_id,
        Some(epoch),
        create_operation(context, plan),
        crate::helper::monotonic_ns().unwrap(),
        1,
    )
    .await
    .unwrap();
    match reply {
        FirecrackerResponse::Create(reply) => {
            assert_eq!(class_of(&reply), AmbiguousClass::Expired)
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn b3_03_ledger_owned_tokens_answer_with_a_full_table_and_charged_gates_stay_closed() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (active, active_plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &active, &active_plan).await;
    let (retired, retired_plan) = issued(&runtime, instance).await;
    let receipt = fenced(
        runtime
            .fence_absent(
                &retired,
                &retired_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    let epoch = epoch_of(&runtime).await;
    let quota = super::super::MAX_TOKEN_GATES / DEFAULT_MAX_ENROLLED as usize;
    // Every one of these could be a real charged token.
    let (first, first_plan) = issued(&runtime, instance).await;
    expire(&fixture, &first, epoch, &first_plan).await;
    // B7: each an issued token, since a random one never reaches a gate.
    for _ in 1..quota {
        let (charged, _) = issued(&runtime, instance).await;
        expire(&fixture, &charged, epoch, &first_plan).await;
    }
    assert_eq!(fixture.census().await["closed_gates"], quota);

    // A new token gets no work: it could not be closed if it were rejected.
    let (refused, refused_plan) = issued(&runtime, instance).await;
    let reply = raw_create(&fixture, &refused, epoch, &refused_plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::WorkerExhausted);
    assert_eq!(fixture.census().await["closed_gates"], quota);
    // Malformed requests can't push out a charged token's gate either.
    // B7: they are refused by H's tag check and never reach the table at all.
    refused_by_tag(
        &fixture,
        instance,
        epoch,
        create_operation(&token(instance), &first_plan),
    )
    .await;
    assert_eq!(fixture.census().await["closed_gates"], quota);
    let reply = raw_create(&fixture, &first, epoch, &first_plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::GateClosed);

    // Ledger-owned tokens need none of this memory, however full it is.
    assert!(matches!(
        raw_create(&fixture, &active, epoch, &active_plan).await,
        CreateReply::Accepted { replay: true, .. }
    ));
    match raw_create(&fixture, &retired, epoch, &retired_plan).await {
        CreateReply::Absent { receipt: bytes } => {
            assert_eq!(FencedAbsence::decode(&bytes.0).unwrap(), receipt);
        }
        other => panic!("{other:?}"),
    }
    let again = fenced(
        runtime
            .fence_absent(
                &retired,
                &retired_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(again, receipt);
    fenced(
        runtime
            .fence_absent(
                &active,
                &active_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    // So does a token only the daemon's C1 knows: its fence needs no retained entry.
    fenced(
        runtime
            .fence_absent(
                &refused,
                &refused_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    let second = fenced(
        runtime
            .fence_absent(
                &first,
                &first_plan.plan_digest(),
                deadline(20),
                &no_cancel(),
            )
            .await
            .unwrap(),
    );
    // Fencing one charged token freed its entry, so new work is admitted again.
    let (next, next_plan) = issued(&runtime, instance).await;
    assert!(matches!(
        raw_create(&fixture, &next, epoch, &next_plan).await,
        CreateReply::Accepted { replay: false, .. }
    ));
    // A helper restart forgets everything non-durable, and L answers just the same.
    fixture.kill_helper().await;
    fixture.start().await;
    let renewed = fixture.runtime(instance, runtime_database(&fixture, instance));
    let epoch = epoch_of(&renewed).await;
    match raw_create(&fixture, &first, epoch, &first_plan).await {
        CreateReply::Absent { receipt: bytes } => {
            assert_eq!(FencedAbsence::decode(&bytes.0).unwrap(), second);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        raw_create(&fixture, &next, epoch, &next_plan).await,
        CreateReply::Accepted { replay: true, .. }
    ));
}

fn runtime_database(fixture: &Fixture, instance: Id128) -> Id128 {
    let text: String = fixture.read(|view| {
        view.query_row(
            "SELECT database_uuid FROM instances WHERE instance_id = ?1",
            [instance.to_string()],
            |r| r.get(0),
        )
    });
    Id128::parse(&text).unwrap()
}

/// One never-admitted fence. B7: of an issued token that never reached C2 (a random
/// ID is refused by H's tag check and spends no quota), under some digest of its own.
async fn random_fence(
    runtime: Arc<FirecrackerRuntime>,
    context: CreateContext,
) -> Result<(), String> {
    runtime
        .fence_absent(
            &context,
            &Digest::of(Id128::random().to_string().as_bytes()),
            deadline(20),
            &no_cancel(),
        )
        .await
        .map(|receipt| {
            fenced(receipt);
        })
        .map_err(|error| error.to_string())
}

/// `count` tokens issued to `instance` and never created.
async fn issue_many(runtime: &FirecrackerRuntime, instance: Id128, count: usize) -> Vec<CreateContext> {
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        tokens.push(issued(runtime, instance).await.0);
    }
    tokens
}

#[tokio::test]
async fn b3_02_a_random_id_fence_flood_stops_at_its_quota_and_spares_other_instances() {
    // A share small enough to reach quickly: the pool across 32 possible instances.
    // B7: a quarter of the default allowance's entries, with no floor.
    let pool = SharedReserve::default().fence_allowance_bytes / super::super::journal::FENCE_ENTRY_BOUND / 4;
    let quota = (pool / 32) as i64;
    let fixture = Fixture::new(NodeOptions {
        max_enrolled: 32,
        ..NodeOptions::default()
    })
    .await;
    let hostile_id = Id128::random();
    let hostile = fixture.runtime(hostile_id, Id128::random());
    // B7: random IDs are refused by H's tag check and spend nothing (checked while no
    // allocation is live, so no other L call can interleave); each is the adapter's
    // Remove and then its FenceAbsent.
    epoch_of(&hostile).await;
    let before = tag_census(&fixture).await;
    for _ in 0..20 {
        let error = random_fence(hostile.clone(), token(hostile_id)).await.unwrap_err();
        assert!(error.contains("not issued to this instance"), "{error}");
    }
    before.assert_only_refused(&fixture, 40).await;
    let victim_id = Id128::random();
    let victim = fixture.runtime(victim_id, Id128::random());
    // Real work on each side, plus a token prepared now and admitted only at the quota.
    let (admitted, admitted_plan) = issued(&hostile, hostile_id).await;
    create_accepted(&fixture, &hostile, &admitted, &admitted_plan).await;
    let (late, late_plan) = issued(&hostile, hostile_id).await;
    let (owned, owned_plan) = issued(&victim, victim_id).await;
    create_accepted(&fixture, &victim, &owned, &owned_plan).await;

    // B7: so the flood is of issued tokens that never reach C2. Preflight stops issuing
    // at a quarter below the quota, so the hostile daemon draws them all first.
    let mut flood: std::collections::VecDeque<_> =
        issue_many(&hostile, hostile_id, quota as usize + 24).await.into();

    let hostile_rows =
        format!("SELECT COUNT(*) FROM retired_tokens WHERE instance_id = '{hostile_id}'");
    // The flood, in parallel, until the helper starts refusing it by quota. Some attempts
    // can find no fresh observation while the others hold the workers; those don't
    // count, and their token goes back for another try.
    let mut exhausted = false;
    while !exhausted {
        let mut batch = Vec::new();
        for _ in 0..4 {
            let context = flood.pop_front().expect("the flood was never refused");
            let hostile = hostile.clone();
            batch.push(tokio::spawn(async move {
                let result = random_fence(hostile, context.clone()).await;
                (context, result)
            }));
        }
        for attempt in batch {
            match attempt.await.unwrap() {
                (_, Ok(())) => {}
                (_, Err(error)) if error.contains("ResourceExhausted") => exhausted = true,
                (context, Err(_)) => flood.push_back(context),
            }
        }
    }
    assert!(exhausted, "the flood was never refused");
    assert_eq!(fixture.count(&hostile_rows), quota, "exactly the quota");
    // More of it writes no row at all.
    let generation = fixture.count("SELECT value FROM generation_counter");
    let spare = flood.pop_front().unwrap();
    for context in flood {
        let error = random_fence(hostile.clone(), context).await.unwrap_err();
        assert!(error.contains("ResourceExhausted"), "{error}");
        assert!(error.contains("stays charged"), "{error}");
    }
    assert_eq!(fixture.count(&hostile_rows), quota);
    assert_eq!(
        fixture.count("SELECT value FROM generation_counter"),
        generation
    );
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM allocations"),
        2,
        "the flood admitted nothing"
    );

    // The victim is untouched: its never-admitted fences under its own quota, a new
    // Preflight and Create, and the token the ledger already owns.
    for context in issue_many(&victim, victim_id, 8).await {
        random_fence(victim.clone(), context).await.unwrap();
    }
    let (fresh, fresh_plan) = issued(&victim, victim_id).await;
    create_accepted(&fixture, &victim, &fresh, &fresh_plan).await;
    for (context, plan) in [(&owned, &owned_plan), (&fresh, &fresh_plan)] {
        fenced(
            victim
                .fence_absent(context, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }

    // At its quota the hostile instance gets no new token, and the tokens the ledger
    // admitted still fence, including one admitted after the quota ran out.
    // B7: the refusal is RTC-12's issuance floor.
    let refused = hostile
        .prepare(&prep(hostile_id), &spec(), deadline(5), &no_cancel())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("window quota"), "{refused}");
    create_accepted(&fixture, &hostile, &late, &late_plan).await;
    for (context, plan) in [(&admitted, &admitted_plan), (&late, &late_plan)] {
        fenced(
            hostile
                .fence_absent(context, &plan.plan_digest(), deadline(20), &no_cancel())
                .await
                .unwrap(),
        );
    }
    assert_eq!(fixture.active_allocations(), 0);
    // The refusal is durable across a helper restart, where nothing in memory helps.
    fixture.kill_helper().await;
    fixture.start().await;
    let renewed = fixture.runtime(hostile_id, runtime_database(&fixture, hostile_id));
    let error = random_fence(renewed, spare).await.unwrap_err();
    assert!(error.contains("ResourceExhausted"), "{error}");
    assert_eq!(fixture.count(&hostile_rows), quota + 2);
}

const INFRASTRUCTURE_ROWS: i64 = 6;

#[tokio::test]
async fn b3_04_startup_serves_nothing_until_every_slot_has_its_row() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    fixture.fault("L.record_infrastructure.fail");
    fixture.spawn_helper();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        std::os::unix::net::UnixStream::connect(fixture.root.join("helper.sock")).is_err(),
        "the helper served with no journal row"
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM worker_intents"), 0);
    fixture.clear("L.record_infrastructure.fail");
    wait_until("the helper listens", || {
        std::os::unix::net::UnixStream::connect(fixture.root.join("helper.sock")).is_ok()
    })
    .await;
    // Every process now in a slot has its own unsettled row with its identity.
    let census = fixture.census().await;
    let mut pids = vec![
        census["ledger"].as_i64().unwrap(),
        census["monitor"].as_i64().unwrap(),
    ];
    for key in ["prep", "recovery"] {
        for pid in census[key].as_array().unwrap() {
            pids.push(pid.as_i64().unwrap());
        }
    }
    assert_eq!(pids.len() as i64, INFRASTRUCTURE_ROWS);
    for pid in pids {
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM worker_intents WHERE pid = {pid}
                 AND start_time IS NOT NULL AND settled_generation IS NULL"
            )),
            1,
            "{pid}"
        );
    }
}

#[tokio::test]
async fn b3_04_startup_that_cannot_journal_never_serves_and_leaves_no_workers() {
    let fixture = Fixture::unstarted(NodeOptions {
        startup_journal_ms: 300,
        ..NodeOptions::default()
    });
    fixture.fault("L.record_infrastructure.fail");
    fixture.spawn_helper();
    let error = fixture.root.join("start-error");
    wait_until("startup gives up", || error.exists()).await;
    let reason = std::fs::read_to_string(&error).unwrap();
    assert!(reason.contains("no journal row"), "{reason}");
    wait_until("the helper listens", || {
        std::os::unix::net::UnixStream::connect(fixture.root.join("helper.sock")).is_ok()
    })
    .await;
    // Kiln keeps its listener, and the group answers Disabled, not half a node.
    assert!(!fixture.root.join("control.sock").exists());
    let runtime = fixture.runtime(Id128::random(), Id128::random());
    let refused = runtime
        .test_epoch(deadline(5))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.to_lowercase().contains("disabled"), "{refused}");
    assert_eq!(fixture.count("SELECT COUNT(*) FROM worker_intents"), 0);
    // Its workers left and were reaped: the node lock is free for the next attempt.
    let config: ChildConfig =
        serde_json::from_slice(&std::fs::read(fixture.root.join("config.json")).unwrap()).unwrap();
    let ledger = ledger_config(&config);
    let directory = executable::walk_directory(&ledger.policy, &ledger.directory).unwrap();
    wait_until("the node lock is released", || {
        crate::lock::ExclusiveFileLock::acquire_at(
            directory.file(),
            std::ffi::OsStr::new(super::super::journal::LEDGER_LOCK),
            &super::super::journal::ledger_lock_path(&ledger.directory),
            "test",
        )
        .is_ok()
    })
    .await;
}

/// The replacement test the review asked for: each way a new L can fail its own journal.
#[tokio::test]
async fn b3_04_a_replacement_ledger_stays_private_until_it_journals_exactly() {
    for fault in ["L.settle.fail", "L.record_infrastructure.fail"] {
        let fixture = Fixture::new(NodeOptions::default()).await;
        let runtime = fixture.runtime(Id128::random(), Id128::random());
        epoch_of(&runtime).await;
        let dead = fixture.census().await["ledger"].as_i64().unwrap();
        fixture.fault(fault);
        signal(dead, libc::SIGKILL);
        // Long enough for several discarded attempts.
        tokio::time::sleep(Duration::from_millis(900)).await;
        let during = fixture.census().await;
        assert_eq!(
            during["ledger"].as_i64(),
            Some(dead),
            "{fault}: a replacement L was published"
        );
        // Requests see a missing ledger, and the fault says why.
        assert!(
            runtime
                .node_accounting(deadline(2), &no_cancel())
                .await
                .is_err(),
            "{fault}"
        );
        let health = timed_capabilities(&runtime, &fixture).await.health.unwrap();
        assert_eq!(health.ledger, WorkerHealth::Dead, "{fault}");
        let reported = health.ledger_fault.unwrap_or_default();
        assert!(reported.contains("was not replaced"), "{fault}: {reported}");
        // No discarded process journaled itself, and each one gets reaped.
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM worker_intents WHERE mode = 'ledger' AND pid != {dead}"
            )),
            0,
            "{fault}"
        );
        let settled = |pid: i64| {
            fixture.count(&format!(
                "SELECT COUNT(*) FROM worker_intents WHERE mode = 'ledger' AND pid = {pid}
                 AND settled_generation IS NOT NULL"
            ))
        };
        let expected = i64::from(fault != "L.settle.fail");
        assert_eq!(settled(dead), expected, "{fault}");
        fixture.clear(fault);
        let mut replaced = None;
        for _ in 0..3000 {
            let current = fixture.census().await["ledger"].as_i64().unwrap();
            if current != dead {
                replaced = Some(current);
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let replaced = replaced.unwrap_or_else(|| panic!("{fault}: never replaced"));
        assert_eq!(
            settled(dead),
            1,
            "{fault}: the predecessor settles exactly once"
        );
        assert_eq!(
            fixture.count(&format!(
                "SELECT COUNT(*) FROM worker_intents WHERE mode = 'ledger' AND pid = {replaced}
                 AND start_time IS NOT NULL AND settled_generation IS NULL"
            )),
            1,
            "{fault}"
        );
        let mut discarded = Value::Null;
        for _ in 0..1000 {
            discarded = fixture.census().await["discarded"].clone();
            if discarded.as_array().is_some_and(Vec::is_empty) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(discarded, json!([]), "{fault}: every discard is reaped");
        let health = timed_capabilities(&runtime, &fixture).await.health.unwrap();
        assert_eq!(health.ledger_fault, None, "{fault}");
        assert!(
            runtime
                .node_accounting(deadline(5), &no_cancel())
                .await
                .is_ok(),
            "{fault}"
        );
    }
}
