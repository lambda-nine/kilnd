//! Fixture teardown: every process a helper fixture started, directly or through its
//! workers, is killed and reaped before the fixture is gone.
//!
//! Each helper H runs as the leader of a session of its own (`Fixture::spawn_helper`), so
//! one ID names its whole tree, whenever a member was forked: H's fork-only workers keep
//! its process group, and a member that moves to a group of its own (the fake VM, the late
//! worker below) stays in the session. Only a process that calls `setsid` itself leaves:
//! the real chain's VMM (supervisor.rs's launch child), which lives in its allocation's
//! cgroup instead and is reached through the census as before.
//!
//! The fixture keeps every H it started unreaped until teardown (`Fixture::kill_helper`
//! waits for H's exit without reaping it), so no other process can take a session's ID,
//! or its leader's group ID, while teardown scans and signals by them.
//!
//! Proof C5 (2026-11-24) found two K workers of the real helper alive for about 4 s after
//! the test: K outlives H by design (workers.rs, `RECOVERY_IDLE_AFTER_HELPER_LOSS`), and
//! the old teardown killed only H and the pids an earlier census named.
use super::*;
use std::collections::BTreeSet;
use std::io;

/// How long teardown waits for a killed tree to be gone, reaped, before it fails.
pub(super) const REAP_LIMIT: Duration = Duration::from_secs(10);
/// The real chain's M and K contain any VM still running once H is gone, as they do in
/// production; teardown lets them finish before it kills what is left.
pub(super) const REAL_GRACE: Duration = Duration::from_secs(10);
const PAUSE: Duration = Duration::from_millis(5);

/// What teardown asks of the OS, so its kill-and-wait logic can be checked with a fake.
pub(super) trait Processes {
    /// `kill(-group, signal)`.
    fn signal_group(&mut self, group: i32, signal: i32) -> io::Result<()>;
    /// Every process the OS lists in `session`, with its process group. Linux lists a
    /// zombie; macOS doesn't, but a zombie still keeps its group until it is reaped.
    fn members(&mut self, session: i32) -> Vec<(i32, i32)>;
    fn now(&mut self) -> std::time::Instant;
    fn pause(&mut self);
}

/// What outlived the limit.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Leftovers {
    /// `(pid, group)` of every listed member but the leaders.
    pub members: Vec<(i32, i32)>,
    /// Groups the tree used that still exist.
    pub groups: Vec<i32>,
}

impl Leftovers {
    fn is_empty(&self) -> bool {
        self.members.is_empty() && self.groups.is_empty()
    }
}

fn group_exists(os: &mut impl Processes, group: i32) -> bool {
    // EPERM: the group exists, only zombies are left in it (macOS).
    !matches!(os.signal_group(group, 0), Err(e) if e.raw_os_error() == Some(libc::ESRCH))
}

/// One look: every member but the leaders, and every group seen in use that still exists.
/// A group seen gone leaves `groups` and is never probed again.
fn look(os: &mut impl Processes, leaders: &[i32], groups: &mut BTreeSet<i32>) -> Leftovers {
    let mut members = Vec::new();
    for &session in leaders {
        for (pid, group) in os.members(session) {
            if leaders.contains(&pid) {
                continue;
            }
            if !leaders.contains(&group) {
                groups.insert(group);
            }
            members.push((pid, group));
        }
    }
    groups.retain(|&group| group_exists(os, group));
    Leftovers {
        members,
        groups: groups.iter().copied().collect(),
    }
}

/// Kills every process of the sessions `leaders` lead and returns once none is left and
/// every group they used is gone, which on Linux and macOS alike means reaped. The
/// leaders are the caller's own children, already sent SIGKILL and not yet reaped, so
/// their IDs stay theirs while this runs; `reap_leaders` reaps them once nothing else of
/// their sessions is listed. On an error they are left to the caller. During `grace`
/// nothing is signalled: the tree may leave by itself. Then each pass signals the group of
/// every member its look found: a fork in progress dies with its group, and a member that
/// moved to a group of its own dies with that one (a group is always within its session).
/// Signals go only to groups a member listed in a leader's session holds in that same
/// pass, never to a group only remembered from before, and never by pid.
pub(super) fn reap<P: Processes>(
    os: &mut P,
    leaders: &[i32],
    grace: Duration,
    limit: Duration,
    reap_leaders: impl FnOnce(&mut P),
) -> Result<(), Leftovers> {
    let mut groups = BTreeSet::new();
    let grace_end = os.now() + grace;
    let mut end = None;
    loop {
        let left = look(os, leaders, &mut groups);
        if left.is_empty() {
            break;
        }
        let now = os.now();
        if now >= grace_end {
            let end = *end.get_or_insert(now + limit);
            if now >= end {
                return Err(left);
            }
            let mut signalled = BTreeSet::new();
            for &(_, group) in &left.members {
                if signalled.insert(group) {
                    let _ = os.signal_group(group, libc::SIGCONT);
                    let _ = os.signal_group(group, libc::SIGKILL);
                }
            }
        }
        os.pause();
    }
    reap_leaders(os);
    // A worker's zombie the OS doesn't list still keeps its leader's group: probe only.
    let end = end.unwrap_or_else(|| os.now() + limit);
    loop {
        let groups: Vec<i32> = leaders
            .iter()
            .copied()
            .filter(|&group| group_exists(os, group))
            .collect();
        if groups.is_empty() {
            return Ok(());
        }
        if os.now() >= end {
            return Err(Leftovers {
                members: Vec::new(),
                groups,
            });
        }
        os.pause();
    }
}

/// A teardown that left something fails the test; inside a test that is already
/// panicking it is reported instead, since a second panic would abort the whole run.
pub(super) fn fail_loudly(result: Result<(), Leftovers>, panicking: bool) {
    if let Err(left) = result {
        let message = format!(
            "fixture teardown: processes of its helpers are still there after {REAP_LIMIT:?}: {left:?}"
        );
        if panicking {
            eprintln!("{message}");
        } else {
            panic!("{message}");
        }
    }
}

/// This host's processes.
pub(super) struct Host;

impl Processes for Host {
    fn signal_group(&mut self, group: i32, signal: i32) -> io::Result<()> {
        // SAFETY: plain signal syscall; the group is one this teardown just listed, or a
        // probe with signal 0.
        if unsafe { libc::kill(-group, signal) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn members(&mut self, session: i32) -> Vec<(i32, i32)> {
        let mut members = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return members;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            // `pid (comm) state ppid pgrp session ...`; comm may hold spaces and ')'.
            let Some((_, rest)) = stat.rsplit_once(')') else {
                continue;
            };
            let fields: Vec<&str> = rest.split_whitespace().collect();
            let (Some(group), Some(sid)) = (
                fields.get(2).and_then(|f| f.parse::<i32>().ok()),
                fields.get(3).and_then(|f| f.parse::<i32>().ok()),
            ) else {
                continue;
            };
            if sid == session {
                members.push((pid, group));
            }
        }
        members
    }

    #[cfg(target_os = "macos")]
    fn members(&mut self, session: i32) -> Vec<(i32, i32)> {
        let mut pids = vec![0i32; 1 << 16];
        // SAFETY: the buffer is writable and exactly the size given, in bytes.
        let count = unsafe {
            libc::proc_listallpids(
                pids.as_mut_ptr().cast(),
                (pids.len() * std::mem::size_of::<i32>()) as libc::c_int,
            )
        };
        pids.truncate(count.max(0) as usize);
        let mut members = Vec::new();
        for pid in pids.into_iter().filter(|pid| *pid > 0) {
            // SAFETY: getsid and getpgid have no preconditions.
            let (sid, group) = unsafe { (libc::getsid(pid), libc::getpgid(pid)) };
            if sid == session && group > 0 {
                members.push((pid, group));
            }
        }
        members
    }

    fn now(&mut self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn pause(&mut self) {
        std::thread::sleep(PAUSE);
    }
}

/// A test's own child, killed and reaped when it goes out of scope, a failed assertion
/// included, so it can't outlive the test. For a child with no descendants of its own.
#[cfg(target_os = "linux")]
pub(super) struct Reaped(pub(super) Child);

#[cfg(target_os = "linux")]
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for Reaped {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

#[cfg(target_os = "linux")]
impl std::ops::DerefMut for Reaped {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

/// `waitid(WEXITED | WNOWAIT)`: blocks until the child has exited and leaves it a zombie,
/// so its pid, and the session and group it leads, stay its own until it is reaped.
pub(super) fn wait_exited_unreaped(child: &Child) {
    loop {
        // SAFETY: zeroed siginfo is a valid output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: the pid is this process's own unreaped child; info is writable.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return;
        }
        let error = io::Error::last_os_error();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "waitid: {error}");
    }
}

/// The late worker of the teardown tests, started by `node_fixture_child` when the
/// fixture asks for it: after `late-worker-go` appears, H forks a worker, which forks a
/// grandchild that moves to a process group of its own. Neither leaves by itself
/// within a test's time (a 60 s cap, so a broken teardown can't leave them for good);
/// only teardown ends them.
pub(super) fn spawn_late_worker(root: PathBuf) {
    tokio::spawn(async move {
        while !root.join("late-worker-go").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let worker_root = root.clone();
        let _ = super::super::workers::spawn_process(&[], move || {
            let root = worker_root;
            let grandchild_root = root.clone();
            let _ = super::super::workers::spawn_process(&[], move || {
                // SAFETY: making this process its own group's leader, as the fake VM does.
                unsafe { libc::setpgid(0, 0) };
                linger(&grandchild_root, "late-grandchild.pid");
            });
            linger(&root, "late-worker.pid");
        });
    });
}

fn linger(root: &Path, name: &str) {
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let temporary = root.join(format!("{name}.tmp"));
    if std::fs::write(&temporary, pid.to_string()).is_ok() {
        let _ = std::fs::rename(&temporary, root.join(name));
    }
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn late_pid(fixture: &Fixture, name: &str) -> Option<i32> {
    std::fs::read_to_string(fixture.root.join(name))
        .ok()
        .and_then(|text| text.parse().ok())
}

/// Starts `fixture`'s helper with the late worker and returns (worker, grandchild) once
/// both run.
pub(super) async fn start_with_late_worker(
    fixture: &Fixture,
    start: impl AsyncFnOnce(),
) -> (i32, i32) {
    std::fs::write(fixture.root.join("late-worker"), b"").unwrap();
    start().await;
    std::fs::write(fixture.root.join("late-worker-go"), b"").unwrap();
    wait_until("the late worker and its grandchild", || {
        late_pid(fixture, "late-worker.pid").is_some()
            && late_pid(fixture, "late-grandchild.pid").is_some()
    })
    .await;
    (
        late_pid(fixture, "late-worker.pid").unwrap(),
        late_pid(fixture, "late-grandchild.pid").unwrap(),
    )
}

/// What a helper's session holds before teardown: H, its L, P×2, K×2 and M, and the late
/// worker in H's group, with the grandchild in a group of its own.
pub(super) fn assert_whole_tree(helper: i32, late: (i32, i32)) -> Vec<(i32, i32)> {
    let members = Host.members(helper);
    assert!(
        members.contains(&(helper, helper)),
        "H leads its own session and group: {members:?}"
    );
    assert!(members.contains(&(late.0, helper)), "{members:?}");
    assert!(members.contains(&(late.1, late.1)), "{members:?}");
    // H, L, P, P, K, K, M, the worker and its grandchild.
    assert!(members.len() >= 9, "{members:?}");
    members
}

/// After teardown: nothing of the session, no group it used, and no pid it held.
pub(super) fn assert_nothing_left(helper: i32, before: &[(i32, i32)]) {
    let listed = Host.members(helper);
    assert!(
        listed.is_empty(),
        "left in the helper's session: {listed:?}"
    );
    let groups: BTreeSet<i32> = before.iter().map(|(_, group)| *group).collect();
    for group in groups {
        assert!(
            !group_exists(&mut Host, group),
            "group {group} outlived teardown"
        );
    }
    for (pid, _) in before {
        // SAFETY: signal 0 only checks for existence.
        let rc = unsafe { libc::kill(*pid, 0) };
        let error = io::Error::last_os_error();
        assert!(
            rc == -1 && error.raw_os_error() == Some(libc::ESRCH),
            "pid {pid} outlived teardown (unreaped or alive)"
        );
    }
}

/// C5's case on the fake chain: H's K workers outlive H by design and a late worker and
/// its grandchild never leave by themselves; once the fixture is dropped, none is left,
/// not even a zombie.
#[tokio::test]
async fn a_fixture_teardown_leaves_no_process_its_helper_started() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    let late = start_with_late_worker(&fixture, async || fixture.start().await).await;
    let helper = fixture.helper_pid();
    let before = assert_whole_tree(helper, late);
    drop(fixture);
    assert_nothing_left(helper, &before);
}

/// A helper replaced in the fixture's bookkeeping (a second spawn, or one killed and
/// started again) is torn down with the current one, whole trees included.
#[tokio::test]
async fn a_replaced_helpers_tree_is_torn_down_too() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    let late = start_with_late_worker(&fixture, async || fixture.start().await).await;
    let first = fixture.helper_pid();
    let first_tree = assert_whole_tree(first, late);
    // H killed alone: its workers and the late worker stay, as a crashed helper's would.
    fixture.kill_helper().await;
    // The killed helper stays unreaped, so its pid, and its session's ID, stay its own.
    // SAFETY: signal 0 only checks for existence.
    let rc = unsafe { libc::kill(first, 0) };
    let error = io::Error::last_os_error();
    assert!(
        rc == 0 || error.raw_os_error() != Some(libc::ESRCH),
        "the killed helper was reaped before teardown"
    );
    // A second helper on the same ledger waits for the first's L to let go of it.
    fixture.start().await;
    let second = fixture.helper_pid();
    assert_ne!(first, second);
    let second_tree = Host.members(second);
    assert!(second_tree.len() >= 7, "{second_tree:?}");
    let still: Vec<_> = Host.members(first);
    assert!(
        still.iter().any(|(pid, _)| *pid == late.0),
        "the first helper's late worker is still running: {still:?}"
    );
    // A third helper spawned over the second, as exit3_second_helper_is_refused_by_the_
    // persistent_node_lock does: refused the ledger, it keeps running with no node.
    let _ = std::fs::remove_file(fixture.root.join("start-error"));
    fixture.spawn_helper();
    wait_until("the third helper's lock failure", || {
        std::fs::read_to_string(fixture.root.join("start-error")).is_ok_and(|r| !r.is_empty())
    })
    .await;
    let third = fixture.helper_pid();
    let third_tree = Host.members(third);
    assert!(third_tree.contains(&(third, third)), "{third_tree:?}");
    drop(fixture);
    assert_nothing_left(first, &first_tree);
    assert_nothing_left(second, &second_tree);
    assert_nothing_left(third, &third_tree);
}

/// The real chain (a fixture with a helper image) lets its M and K leave by themselves
/// before teardown kills anything, as they would contain a VM in production: K leaves
/// about three seconds after M stops sending, well inside the grace, and nothing is left.
#[tokio::test]
async fn a_real_chain_teardown_lets_its_workers_leave_by_themselves() {
    let fixture = Fixture::unstarted(NodeOptions::default());
    // A helper image marks the real chain; here it is this test binary, on the fake chain.
    let image = std::env::current_exe().unwrap();
    std::fs::write(fixture.root.join("helper-image"), image.to_str().unwrap()).unwrap();
    fixture.start().await;
    let helper = fixture.helper_pid();
    let before = Host.members(helper);
    assert!(before.len() >= 7, "{before:?}");
    let started = std::time::Instant::now();
    drop(fixture);
    let took = started.elapsed();
    assert_nothing_left(helper, &before);
    assert!(took >= Duration::from_secs(2), "killed at once: {took:?}");
    assert!(took < REAL_GRACE, "{took:?}");
}

#[test]
fn a_teardown_that_leaves_something_fails_unless_already_panicking() {
    fail_loudly(Ok(()), false);
    let left = Leftovers {
        members: vec![(7, 7)],
        groups: vec![7],
    };
    fail_loudly(Err(left), true);
    let caught = std::panic::catch_unwind(|| {
        fail_loudly(
            Err(Leftovers {
                members: vec![(7, 7)],
                groups: vec![7],
            }),
            false,
        )
    });
    let message = caught.expect_err("a leftover fails the test");
    let text = message
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(text.contains("(7, 7)"), "{text}");
}

/// A fake process table: exact signals, deaths a few passes after SIGKILL, zombies that
/// keep their group until an init reaps them, forks after a look, and a clock that moves
/// only when teardown pauses.
mod fake {
    use super::*;

    /// A table past this many processes fails the test: forks are outrunning teardown,
    /// and a table that doubles on every look would otherwise exhaust the host's memory.
    const MAX_PROCS: usize = 10_000;

    #[derive(Clone, Debug)]
    pub struct Proc {
        pub pid: i32,
        pub group: i32,
        pub session: i32,
        /// Pauses from SIGKILL to exit; `None`: SIGKILL never takes (stuck in the kernel).
        pub dies_after: Option<u32>,
        /// Pauses from exit to being reaped by init.
        pub reaped_after: u32,
        /// Leaves by itself after this many pauses, unsignalled.
        pub leaves_after: Option<u32>,
        /// Forks a child into its group (another forker) right after every look.
        pub forks: bool,
        pub killed: Option<u32>,
        pub exited: Option<u32>,
        pub reaped: bool,
    }

    impl Proc {
        pub fn new(pid: i32, group: i32, session: i32) -> Self {
            Self {
                pid,
                group,
                session,
                dies_after: Some(1),
                reaped_after: 1,
                leaves_after: None,
                forks: false,
                killed: None,
                exited: None,
                reaped: false,
            }
        }
    }

    pub struct Os {
        pub procs: Vec<Proc>,
        /// Linux lists zombies in a session; macOS doesn't.
        pub lists_zombies: bool,
        pub group_signals: Vec<(i32, i32)>,
        pub pauses: u32,
        pub start: std::time::Instant,
        pub next_pid: i32,
        /// A pause past this many fails the test: teardown never gave up.
        pub max_pauses: u32,
        /// Once this pid is reaped, its ID is taken by this process of another session.
        pub reuse: Option<(i32, Proc)>,
    }

    impl Os {
        pub fn new(procs: Vec<Proc>) -> Self {
            Self {
                procs,
                lists_zombies: false,
                group_signals: Vec::new(),
                pauses: 0,
                start: std::time::Instant::now(),
                next_pid: 1000,
                max_pauses: 100_000,
                reuse: None,
            }
        }

        fn kill(&mut self, index: usize, signal: i32) {
            let pauses = self.pauses;
            let proc = &mut self.procs[index];
            if signal == libc::SIGKILL && proc.exited.is_none() && proc.killed.is_none() {
                proc.killed = Some(pauses);
            }
        }

        pub fn alive(&self) -> Vec<i32> {
            self.procs
                .iter()
                .filter(|p| p.exited.is_none())
                .map(|p| p.pid)
                .collect()
        }

        pub fn unreaped(&self) -> Vec<i32> {
            self.procs
                .iter()
                .filter(|p| !p.reaped)
                .map(|p| p.pid)
                .collect()
        }
    }

    impl Processes for Os {
        fn signal_group(&mut self, group: i32, signal: i32) -> io::Result<()> {
            let members: Vec<usize> = (0..self.procs.len())
                .filter(|&i| self.procs[i].group == group && !self.procs[i].reaped)
                .collect();
            if members.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if signal != 0 {
                self.group_signals.push((group, signal));
            }
            let mut delivered = false;
            for index in members {
                if self.procs[index].exited.is_none() {
                    delivered = true;
                    self.kill(index, signal);
                }
            }
            if delivered {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            }
        }

        fn members(&mut self, session: i32) -> Vec<(i32, i32)> {
            let listed = self
                .procs
                .iter()
                .filter(|p| p.session == session && !p.reaped)
                .filter(|p| p.exited.is_none() || self.lists_zombies)
                .map(|p| (p.pid, p.group))
                .collect();
            // A fork in progress lands after the look, in its parent's group.
            let forkers: Vec<(i32, i32)> = self
                .procs
                .iter()
                .filter(|p| p.forks && p.exited.is_none())
                .map(|p| (p.group, p.session))
                .collect();
            assert!(
                self.procs.len() + forkers.len() <= MAX_PROCS,
                "forks outran teardown: {} processes",
                self.procs.len() + forkers.len()
            );
            for (group, session) in forkers {
                let mut child = Proc::new(self.next_pid, group, session);
                child.forks = true;
                self.next_pid += 1;
                self.procs.push(child);
            }
            listed
        }

        fn now(&mut self) -> std::time::Instant {
            self.start + PAUSE * self.pauses
        }

        fn pause(&mut self) {
            self.pauses += 1;
            assert!(
                self.pauses <= self.max_pauses,
                "teardown never gave up: {} pauses",
                self.pauses
            );
            let now = self.pauses;
            for proc in &mut self.procs {
                if proc.exited.is_none() {
                    let killed = proc
                        .killed
                        .zip(proc.dies_after)
                        .is_some_and(|(at, after)| now >= at + after);
                    let left = proc.leaves_after.is_some_and(|after| now >= after);
                    if killed || left {
                        proc.exited = Some(now);
                    }
                }
                if let Some(at) = proc.exited
                    && !proc.reaped
                    && proc.pid != proc.session
                    && now >= at + proc.reaped_after
                {
                    proc.reaped = true;
                }
            }
            if let Some((pid, _)) = &self.reuse
                && self.procs.iter().any(|p| p.pid == *pid && p.reaped)
            {
                let (_, newcomer) = self.reuse.take().unwrap();
                self.procs.push(newcomer);
            }
        }
    }
}

use fake::{Os, Proc};

/// A leader already killed and waiting to be reaped by the fixture; `reap_leaders`
/// reaps it.
fn leader(pid: i32) -> Proc {
    let mut proc = Proc::new(pid, pid, pid);
    proc.exited = Some(0);
    proc
}

fn reap_fake(
    os: &mut Os,
    leaders: &[i32],
    grace: Duration,
) -> (Result<(), Leftovers>, Option<u32>) {
    let mut reaped_at = None;
    let result = reap(os, leaders, grace, Duration::from_millis(500), |os| {
        assert!(reaped_at.is_none(), "the leaders are reaped once");
        reaped_at = Some(os.pauses);
        for proc in &mut os.procs {
            if leaders.contains(&proc.pid) {
                assert!(proc.exited.is_some(), "a leader is reaped only once dead");
                proc.reaped = true;
            }
        }
    });
    (result, reaped_at)
}

/// The whole tree: workers in the leader's group, one that moved to a group of its own,
/// zombies that keep their groups for a while, and a process of another session.
#[test]
fn teardown_kills_every_member_and_returns_only_once_all_are_reaped() {
    for lists_zombies in [false, true] {
        let mut slow = Proc::new(101, 100, 100);
        slow.dies_after = Some(4);
        slow.reaped_after = 30;
        let mut moved = Proc::new(103, 103, 100);
        moved.reaped_after = 20;
        let foreign = Proc::new(200, 200, 200);
        let mut os = Os::new(vec![
            leader(100),
            slow,
            Proc::new(102, 100, 100),
            moved,
            foreign,
        ]);
        os.lists_zombies = lists_zombies;
        let (result, reaped_at) = reap_fake(&mut os, &[100], Duration::ZERO);
        assert_eq!(result, Ok(()));
        let reaped_at = reaped_at.unwrap();
        assert_eq!(
            os.unreaped(),
            vec![200],
            "only the other session's process is left"
        );
        assert_eq!(os.alive(), vec![200]);
        // It waited for the last reap: 101 died 4 pauses after its kill, then 30 more.
        assert!(os.pauses >= 34, "returned after {} pauses", os.pauses);
        // The leaders are reaped only once nothing else of their session is listed.
        assert!(reaped_at >= 5, "leaders reaped at pause {reaped_at}");
        for (group, _) in &os.group_signals {
            assert_ne!(*group, 200, "never a group of another session");
        }
    }
}

/// SIGKILL that never takes: teardown gives up at its limit and says what is left.
#[test]
fn teardown_fails_at_its_limit_with_what_is_left() {
    let mut stuck = Proc::new(101, 100, 100);
    stuck.dies_after = None;
    let mut os = Os::new(vec![leader(100), stuck, Proc::new(102, 100, 100)]);
    os.max_pauses = 1_000;
    let (result, _) = reap_fake(&mut os, &[100], Duration::ZERO);
    assert_eq!(
        result,
        Err(Leftovers {
            members: vec![(101, 100)],
            groups: vec![],
        })
    );
    // The limit is 500 ms of 5 ms pauses.
    assert!((100..=102).contains(&os.pauses), "{}", os.pauses);
}

/// A zombie nobody reaps keeps its group: teardown fails rather than call it gone.
#[test]
fn an_unreaped_zombie_fails_teardown() {
    for lists_zombies in [false, true] {
        let mut zombie = Proc::new(103, 103, 100);
        zombie.reaped_after = u32::MAX / 2;
        let mut os = Os::new(vec![leader(100), zombie]);
        os.lists_zombies = lists_zombies;
        os.max_pauses = 1_000;
        let (result, _) = reap_fake(&mut os, &[100], Duration::ZERO);
        let left = result.expect_err("a zombie is not gone");
        assert_eq!(left.groups, vec![103]);
        assert!(os.alive().is_empty(), "{:?}", os.alive());
    }
}

/// A worker's zombie the OS doesn't list keeps the leader's group: teardown waits.
#[test]
fn a_hidden_zombie_in_the_leaders_group_is_waited_for() {
    let mut zombie = Proc::new(101, 100, 100);
    zombie.exited = Some(0);
    zombie.reaped_after = 40;
    let mut os = Os::new(vec![leader(100), zombie]);
    let (result, _) = reap_fake(&mut os, &[100], Duration::ZERO);
    assert_eq!(result, Ok(()));
    assert!(os.pauses >= 40, "returned after {} pauses", os.pauses);
    assert!(os.unreaped().is_empty());
}

/// Every child forks again right after each look: only the group kill, which reaches a
/// fork that lands after the look, empties the tree.
#[test]
fn a_tree_that_forks_after_every_look_is_still_emptied() {
    let mut forker = Proc::new(101, 100, 100);
    forker.forks = true;
    let mut os = Os::new(vec![leader(100), forker]);
    os.max_pauses = 1_000;
    let (result, _) = reap_fake(&mut os, &[100], Duration::ZERO);
    assert_eq!(result, Ok(()));
    assert!(os.unreaped().is_empty(), "{:?}", os.unreaped());
}

/// During the grace nothing is signalled, and a tree that leaves by itself is never
/// signalled at all; what is left at its end is killed.
#[test]
fn grace_signals_nothing_and_what_outlives_it_is_killed() {
    let mut leaves = Proc::new(101, 100, 100);
    leaves.leaves_after = Some(20);
    let mut os = Os::new(vec![leader(100), leaves]);
    let (result, _) = reap_fake(&mut os, &[100], Duration::from_millis(500));
    assert_eq!(result, Ok(()));
    assert!(os.group_signals.is_empty());
    assert!((21..=30).contains(&os.pauses), "{}", os.pauses);

    let mut stays = Proc::new(101, 100, 100);
    stays.leaves_after = Some(10_000);
    let mut os = Os::new(vec![leader(100), stays]);
    let (result, _) = reap_fake(&mut os, &[100], Duration::from_millis(100));
    assert_eq!(result, Ok(()));
    let first = os.group_signals.first().copied();
    assert_eq!(first, Some((100, libc::SIGCONT)));
    assert!(
        os.pauses >= 20,
        "killed only after the grace: {}",
        os.pauses
    );
    assert!(os.unreaped().is_empty());
}

/// Each leader's session is torn down, not only the current helper's.
#[test]
fn every_leaders_session_is_torn_down() {
    let mut os = Os::new(vec![
        leader(100),
        Proc::new(101, 100, 100),
        leader(300),
        Proc::new(301, 300, 300),
        Proc::new(302, 302, 300),
    ]);
    let (result, _) = reap_fake(&mut os, &[100, 300], Duration::ZERO);
    assert_eq!(result, Ok(()));
    assert!(os.unreaped().is_empty(), "{:?}", os.unreaped());
}

/// A group is signalled only while a member of the session is in it: once its last
/// member is reaped and its ID is taken by another session's group, teardown never
/// signals that group, and reports it rather than call the tree gone.
#[test]
fn a_group_is_signalled_only_while_the_session_has_a_member_in_it() {
    let moved = Proc::new(103, 103, 100);
    let mut slow = Proc::new(101, 100, 100);
    slow.dies_after = Some(10);
    let mut os = Os::new(vec![leader(100), moved, slow]);
    os.reuse = Some((103, Proc::new(500, 103, 500)));
    os.max_pauses = 1_000;
    let (result, _) = reap_fake(&mut os, &[100], Duration::ZERO);
    assert_eq!(
        result,
        Err(Leftovers {
            members: vec![],
            groups: vec![103],
        })
    );
    assert!(os.procs.iter().any(|p| p.pid == 500), "the ID was taken");
    let to_103: Vec<_> = os
        .group_signals
        .iter()
        .filter(|(group, _)| *group == 103)
        .collect();
    assert_eq!(
        to_103,
        vec![&(103, libc::SIGCONT), &(103, libc::SIGKILL)],
        "only in the pass that listed 103"
    );
    assert_eq!(os.alive(), vec![500]);
}
