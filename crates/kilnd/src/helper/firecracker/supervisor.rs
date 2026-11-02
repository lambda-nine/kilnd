//! S's real effects (sections 3.4, 4.3, 4.4, 6.2 and 7.1). S runs gated, in its
//! allocation's `control` leaf, one step at a time: every step heartbeats, reads every
//! queued command first, honors the original deadline and journals what it is about
//! to own before it owns it. Nothing here takes a path, flag or identity from a
//! request: names come from the verified plan and identities from retained
//! descriptors or the kernel. Readiness is not reported: B4 has no broker, so the
//! furthest a boot gets is BOOTING.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::cgroup::{self, CgroupIdentity, CgroupTarget};
use super::executable::ExecutableIdentity;
#[cfg(target_os = "linux")]
use super::executable::{self, Role};
#[cfg(target_os = "linux")]
use super::storage;
use super::storage::{AllocationPaths, Credentials, FileIdentity, JailMount, LoopBinding};
use super::workers::{
    ProcessId, Received, SupervisorCommand, SupervisorContext, SupervisorEvent, fault_point,
    monotonic_ns,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant};

/// What S asks H to make durable before it proceeds. H answers each in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorRecord {
    /// An owned resource, recorded as soon as its identity exists. `loop_intent`
    /// precedes LOOP_CONFIGURE; the cgroup record also gives M its stop target.
    Resource(ResourceRecord),
    /// SPAWN_INTENT before J exists; BOOTING after V is validated and hardened.
    Phase { from: Vec<String>, to: String },
    /// A gated child's identity (J or V), recorded before it is released or adopted.
    Child { role: ChildRole, process: ProcessId },
    /// The tuple that actually ran, compared with the journal by L as well.
    Observed(ExecutableIdentity),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildRole {
    Jailer,
    Vm,
}

/// One owned resource and its typed identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceRecord {
    Cgroup(CgroupIdentity),
    WorkFile(FileIdentity),
    PrivateFiles {
        identity: FileIdentity,
        config: FileIdentity,
    },
    LoopIntent(LoopBinding),
    Loop(LoopBinding),
    JailMount(JailMount),
    Vmm {
        process: ProcessId,
        credentials: Credentials,
    },
}

impl ResourceRecord {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Cgroup(_) => "cgroup",
            Self::WorkFile(_) => "work_file",
            Self::PrivateFiles { .. } => "private_files",
            Self::LoopIntent(_) => "loop_intent",
            Self::Loop(_) => "loop",
            Self::JailMount(_) => "jail_mount",
            Self::Vmm { .. } => "vmm",
        }
    }
}

/// Every resource record of one allocation, as cleanup needs them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedResources {
    pub cgroup: Option<CgroupIdentity>,
    pub work_file: Option<FileIdentity>,
    pub identity_file: Option<FileIdentity>,
    pub config_file: Option<FileIdentity>,
    /// Every loop slot ever intended for this allocation, attached or not.
    pub loops: Vec<LoopBinding>,
    pub jail_mount: Option<JailMount>,
    pub vmm: Option<ProcessId>,
}

impl RecordedResources {
    pub fn absorb(&mut self, record: &ResourceRecord) {
        match record {
            ResourceRecord::Cgroup(identity) => self.cgroup = Some(*identity),
            ResourceRecord::WorkFile(identity) => self.work_file = Some(*identity),
            ResourceRecord::PrivateFiles { identity, config } => {
                self.identity_file = Some(*identity);
                self.config_file = Some(*config);
            }
            ResourceRecord::LoopIntent(binding) | ResourceRecord::Loop(binding) => {
                if !self.loops.contains(binding) {
                    self.loops.push(*binding);
                }
            }
            ResourceRecord::JailMount(mount) => self.jail_mount = Some(*mount),
            ResourceRecord::Vmm { process, .. } => self.vmm = Some(*process),
        }
    }
}

/// The parts of a verified plan S acts on, parsed once.
#[derive(Clone, Debug)]
pub struct LaunchPlan {
    pub plan: Value,
    pub launch: Value,
    pub paths: AllocationPaths,
    /// `kilnd-firecracker/<I>/fc-<H>`
    pub cgroup: String,
    pub uid: u32,
    pub gid: u32,
    pub work_bytes: u64,
    pub work_uuid: String,
}

impl LaunchPlan {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let plan = crate::firecracker::strict_json(bytes).map_err(io::Error::other)?;
        let launch = plan["launch"].clone();
        let paths = AllocationPaths::from_launch(&launch)?;
        let cgroup = launch["cgroup"]
            .as_str()
            .filter(|path| cgroup::valid_relative(path))
            .ok_or_else(|| io::Error::other("plan cgroup"))?
            .to_string();
        let credentials = &launch["resource_recipe"]["vmm_credentials"];
        let uid = credentials["uid"]
            .as_u64()
            .ok_or_else(|| io::Error::other("uid"))? as u32;
        let gid = credentials["gid"]
            .as_u64()
            .ok_or_else(|| io::Error::other("gid"))? as u32;
        Ok(Self {
            work_bytes: launch["work_bytes"]
                .as_u64()
                .ok_or_else(|| io::Error::other("work bytes"))?,
            work_uuid: plan["substitutions"]["work_uuid"]
                .as_str()
                .ok_or_else(|| io::Error::other("work uuid"))?
                .to_string(),
            plan,
            launch,
            paths,
            cgroup,
            uid,
            gid,
        })
    }

    pub fn vm_target(&self, identity: &CgroupIdentity) -> CgroupTarget {
        CgroupTarget {
            path: format!("{}/vm", self.cgroup),
            st_ino: identity.vm_ino,
        }
    }

    fn argv(&self, key: &str) -> io::Result<Vec<String>> {
        self.launch[key]
            .as_array()
            .ok_or_else(|| io::Error::other(format!("plan {key}")))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| io::Error::other(format!("plan {key} entry")))
            })
            .collect()
    }
}

/// Why forward work stopped. Every case leaves what exists for Remove to observe.
#[derive(Debug)]
pub enum Abort {
    Revoked,
    HelperGone,
    Expired,
    Refused(String),
}

impl From<io::Error> for Abort {
    fn from(error: io::Error) -> Self {
        Abort::Refused(error.to_string())
    }
}

/// S's link to H: heartbeats, the command queue and journaled records.
pub struct Link<'a> {
    context: &'a mut SupervisorContext,
    deadline_ns: u64,
    last_beat: Instant,
    pub last_helper: Instant,
    seq: u64,
    console: Option<Console>,
}

const CONSOLE_PREFIX: usize = 64 * 1024;

/// The console pipe, drained continuously; a bounded prefix is kept for diagnostics.
pub struct Console {
    fd: std::os::fd::OwnedFd,
    pub prefix: Vec<u8>,
    pub total: u64,
}

impl Console {
    pub fn drain(&mut self) {
        use std::os::fd::AsRawFd;
        let mut chunk = [0u8; 64 * 1024];
        for _ in 0..16 {
            // SAFETY: chunk is writable; the descriptor is owned and nonblocking.
            let n =
                unsafe { libc::read(self.fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            if n <= 0 {
                return;
            }
            let n = n as usize;
            self.total = self.total.saturating_add(n as u64);
            let room = CONSOLE_PREFIX.saturating_sub(self.prefix.len());
            self.prefix.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
}

impl<'a> Link<'a> {
    /// Test-only: the retained console prefix, for evidence that the guest booted.
    #[cfg(test)]
    pub fn dump_console(&self) {
        if let Some(console) = &self.console {
            let name = format!("console-{}.log", self.context.allocation);
            super::workers::faults::write(&name, &console.prefix);
        }
    }

    pub fn new(context: &'a mut SupervisorContext, deadline_ns: u64) -> Self {
        Self {
            context,
            deadline_ns,
            last_beat: Instant::now() - Duration::from_secs(1),
            last_helper: Instant::now(),
            seq: 0,
            console: None,
        }
    }

    pub fn context(&self) -> &SupervisorContext {
        self.context
    }

    pub fn beat(&mut self) {
        if self.last_beat.elapsed() >= self.context.config.timings.heartbeat {
            super::workers::send_watch_byte(&self.context.watch, b'h');
            self.last_beat = Instant::now();
        }
        if let Some(console) = self.console.as_mut() {
            console.drain();
        }
    }

    /// Reads every queued command. Revoke ends forward work at once.
    pub fn poll(&mut self, wait: Duration) -> Result<Option<SupervisorCommand>, Abort> {
        let mut wait = wait;
        loop {
            match self.context.control.receive::<SupervisorCommand>(wait) {
                Ok(Received::Message { body, .. }) => match body {
                    SupervisorCommand::Tick => self.last_helper = Instant::now(),
                    SupervisorCommand::Revoke => return Err(Abort::Revoked),
                    other => return Ok(Some(other)),
                },
                Ok(Received::Idle) => break,
                Ok(Received::Closed) | Err(_) => return Err(Abort::HelperGone),
            }
            wait = Duration::ZERO;
        }
        if self.last_helper.elapsed() >= self.context.config.timings.heartbeat_timeout {
            return Err(Abort::HelperGone);
        }
        Ok(None)
    }

    /// The point before each forward effect: heartbeat, commands, deadline, and the
    /// test fault points that stall or kill S exactly here.
    pub fn step(&mut self, name: &str) -> Result<(), Abort> {
        self.beat();
        fault_point(&format!("S.step.{name}"));
        self.beat();
        if let Some(command) = self.poll(Duration::ZERO)? {
            return Err(Abort::Refused(format!("unexpected command {command:?}")));
        }
        if monotonic_ns() >= self.deadline_ns {
            return Err(Abort::Expired);
        }
        Ok(())
    }

    /// The crash boundary between an effect and its journal record: tests panic, stall
    /// or kill S exactly here. Production compiles it to nothing.
    pub fn after(&mut self, name: &str) {
        self.beat();
        fault_point(&format!("S.after.{name}"));
    }

    pub fn event(&mut self, event: &SupervisorEvent) {
        let _ = self.context.control.send(0, event, Duration::from_secs(1));
    }

    /// Sends one record and waits for H's durable answer, heartbeating meanwhile.
    pub fn record(&mut self, record: SupervisorRecord) -> Result<(), Abort> {
        self.seq += 1;
        let seq = self.seq;
        self.event(&SupervisorEvent::Record { seq, record });
        loop {
            self.beat();
            match self.poll(Duration::from_millis(10))? {
                Some(SupervisorCommand::Recorded { seq: answered, ok }) if answered == seq => {
                    return if ok {
                        Ok(())
                    } else {
                        Err(Abort::Refused("H refused the record".into()))
                    };
                }
                Some(other) => return Err(Abort::Refused(format!("unexpected {other:?}"))),
                None => {}
            }
            if monotonic_ns() >= self.deadline_ns {
                return Err(Abort::Expired);
            }
        }
    }

    /// Waits for a condition while staying responsive. `check` returns Some to finish.
    pub fn wait_for<T>(
        &mut self,
        limit: Duration,
        mut check: impl FnMut() -> io::Result<Option<T>>,
    ) -> Result<T, Abort> {
        let end = Instant::now() + limit;
        loop {
            if let Some(value) = check()? {
                return Ok(value);
            }
            self.beat();
            if let Some(command) = self.poll(Duration::from_millis(5))? {
                return Err(Abort::Refused(format!("unexpected command {command:?}")));
            }
            if monotonic_ns() >= self.deadline_ns || Instant::now() >= end {
                return Err(Abort::Expired);
            }
        }
    }
}

/// The state a booted S keeps for its steady loop and teardown.
pub struct Booted {
    pub plan: LaunchPlan,
    pub cgroup: CgroupIdentity,
    pub vmm: ProcessId,
    pub vmm_pidfd: std::os::fd::OwnedFd,
    pub console: Option<Console>,
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::MetadataExt;

    fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    pub fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes a PID and flags.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    pub fn pidfd_signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
        // SAFETY: the pidfd pins one process; no siginfo.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Whether the pinned process has exited (its pidfd is readable).
    pub fn pidfd_exited(pidfd: &OwnedFd) -> bool {
        let mut entry = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live entry; zero timeout.
        unsafe { libc::poll(&mut entry, 1, 0) };
        entry.revents != 0
    }

    /// A pidfd that provably names `target`: opened first, then the start time read.
    pub fn pin(target: ProcessId) -> io::Result<OwnedFd> {
        let pidfd = pidfd_open(target.pid)?;
        match super::super::workers::process_state(target.pid) {
            super::super::workers::ProcessState::Running { start_time }
                if start_time == target.start_time => {}
            _ => return Err(io::Error::other("process identity changed")),
        }
        if pidfd_exited(&pidfd) {
            return Err(io::Error::other("process has exited"));
        }
        Ok(pidfd)
    }

    fn identify(pid: i32) -> io::Result<ProcessId> {
        match super::super::workers::process_state(pid) {
            super::super::workers::ProcessState::Running { start_time } => {
                Ok(ProcessId { pid, start_time })
            }
            _ => Err(io::Error::other("process is gone")),
        }
    }

    fn proc_status(pid: i32) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
    }

    fn ppid(pid: i32) -> io::Result<i32> {
        let status = proc_status(pid)?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| io::Error::other("no PPid"))
    }

    /// Runs `body` with this process's filesystem IDs set to the VMM's. `/proc/<V>/exe`
    /// and `/proc/<V>/fd` are ptrace-read checks, and the helper's bounding set has no
    /// CAP_SYS_PTRACE: as B3's L does for peers, S takes the target's filesystem IDs for
    /// those opens and restores them at once. S is single-threaded.
    pub fn as_fs_ids<T>(uid: u32, gid: u32, body: impl FnOnce() -> T) -> T {
        // SAFETY: setfsgid/setfsuid affect only this single-threaded process and are
        // restored before returning. Changing them also resets the dumpable flag, which
        // is put back exactly as it was.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        unsafe {
            libc::setfsgid(gid);
            libc::setfsuid(uid);
        }
        let result = body();
        unsafe {
            libc::setfsuid(0);
            libc::setfsgid(0);
            if dumpable >= 0 {
                libc::prctl(libc::PR_SET_DUMPABLE, dumpable, 0, 0, 0);
            }
        }
        result
    }

    /// The descriptors a process holds, as link text: kept bounded and exact.
    pub fn open_descriptors(pid: i32) -> io::Result<BTreeMap<i32, String>> {
        let mut out = BTreeMap::new();
        for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
            let entry = entry?;
            let fd: i32 = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| io::Error::other("fd name"))?;
            let target = std::fs::read_link(entry.path())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.insert(fd, target);
            if out.len() > 4096 {
                return Err(io::Error::other("too many descriptors"));
            }
        }
        Ok(out)
    }

    fn socket_inode(fd: RawFd) -> io::Result<u64> {
        // SAFETY: stat is writable.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        cvt(unsafe { libc::fstat(fd, &mut stat) })?;
        #[allow(clippy::unnecessary_cast)]
        Ok(stat.st_ino as u64)
    }

    fn write_all(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
        let mut done = 0;
        while done < bytes.len() {
            // SAFETY: the slice is live; MSG_NOSIGNAL turns a dead peer into EPIPE.
            let n = unsafe {
                libc::send(
                    fd,
                    bytes[done..].as_ptr().cast(),
                    bytes.len() - done,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            done += n as usize;
        }
        Ok(())
    }

    /// Reads exactly `out.len()` bytes without blocking past what is there. Returns
    /// Ok(None) while incomplete, Err on EOF.
    fn read_some(fd: RawFd, out: &mut Vec<u8>, want: usize) -> io::Result<Option<()>> {
        let mut chunk = [0u8; 16];
        while out.len() < want {
            // SAFETY: chunk is writable.
            let n = unsafe {
                libc::recv(
                    fd,
                    chunk.as_mut_ptr().cast(),
                    (want - out.len()).min(chunk.len()),
                    libc::MSG_DONTWAIT,
                )
            };
            if n == 0 {
                return Err(io::Error::other("bootstrap peer closed"));
            }
            if n < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(error),
                };
            }
            out.extend_from_slice(&chunk[..n as usize]);
        }
        Ok(Some(()))
    }

    fn waitpid_nohang(pid: i32) -> io::Result<Option<i32>> {
        let mut status = 0;
        // SAFETY: status is writable.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Ok(None);
        }
        Ok(Some(status))
    }

    /// Reaps any exited child that is not one we are tracking (V's own reparented
    /// descendants never exist, but a subreaper must not accumulate zombies).
    fn reap_strays(keep: &[i32]) {
        loop {
            let mut status = 0;
            // SAFETY: status is writable; WNOHANG returns at once.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG | libc::__WALL) };
            if pid <= 0 {
                return;
            }
            if keep.contains(&pid) {
                // Not ours to consume: this is the only exit evidence for that child.
                // Waiting by PID again would fail, so we stop here without losing it.
                return;
            }
        }
    }

    fn expected_identity(
        expected: &[ExecutableIdentity],
        role: Role,
    ) -> io::Result<ExecutableIdentity> {
        expected
            .iter()
            .find(|identity| identity.role == role)
            .copied()
            .ok_or_else(|| io::Error::other(format!("no expected {}", role.as_str())))
    }

    /// The verified artifacts S binds: opened through the protected bundle walk and
    /// hashed again on this create, with heartbeats between chunks.
    fn open_artifacts(link: &mut Link<'_>, profile: &str) -> Result<(File, File), Abort> {
        let config = link.context().config.clone();
        let profile = config
            .profile(profile)
            .ok_or_else(|| Abort::Refused("profile is not configured".into()))?;
        let bundle = executable::walk_directory(&config.walk, &profile.catalog.bundle_directory)
            .map_err(|e| Abort::Refused(e.to_string()))?;
        let mut files = Vec::new();
        for name in ["Image", "rootfs.squashfs"] {
            let pin = profile
                .artifacts
                .get(name)
                .ok_or_else(|| Abort::Refused(format!("{name} is not pinned")))?;
            let (file, meta) =
                super::super::manifest::open_regular(&bundle, name, config.walk.owner_uid)
                    .map_err(Abort::Refused)?;
            if meta.len() != pin.bytes {
                return Err(Abort::Refused(format!("{name} size differs")));
            }
            let digest = storage::hash_with(&file, meta.len(), &mut || link.beat())?;
            if digest != pin.sha256 {
                return Err(Abort::Refused(format!("{name} digest differs")));
            }
            files.push(file);
        }
        let rootfs = files.pop().unwrap();
        let kernel = files.pop().unwrap();
        Ok((kernel, rootfs))
    }

    /// The formatter, run by its retained descriptor in this leaf, waited on with
    /// heartbeats. The new inode is checked before and after, then synced.
    fn format_work(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        dir: &File,
        work: &File,
        identity: FileIdentity,
        expected: &[ExecutableIdentity],
    ) -> Result<(), Abort> {
        let config = link.context().config.clone();
        let profile = config
            .profile(&link.context().profile)
            .ok_or_else(|| Abort::Refused("profile".into()))?;
        let mkfs = expected_identity(expected, Role::MkfsXfs)?;
        let fd = profile
            .table
            .raw_fd(Role::MkfsXfs)
            .ok_or_else(|| Abort::Refused("formatter is not retained".into()))?;
        let argv: Vec<CString> = plan
            .argv("formatter_argv")?
            .into_iter()
            .map(|a| CString::new(a).map_err(|_| io::Error::other("argv NUL")))
            .collect::<io::Result<_>>()?;
        if argv.len() != 7
            || argv[6].as_bytes() != plan.paths.work_file.as_os_str().as_encoded_bytes()
        {
            return Err(Abort::Refused(
                "formatter argv differs from the contract".into(),
            ));
        }
        let observe = super::super::workers::fault_enabled("S.exec_stop");
        // SAFETY: S is single-threaded; the child only arranges descriptors and execs.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if pid == 0 {
            // SAFETY: the child execs or exits without unwinding.
            unsafe {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                libc::dup2(null, 0);
                libc::dup2(null, 1);
                libc::dup2(null, 2);
                if observe {
                    // Test-only exec stop: the parent reads /proc/<pid>/exe at the
                    // post-exec trap and detaches. Production has no ptrace path.
                    libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                }
                let keep = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10);
                executable::close_all_except(&[keep]);
                let error = executable::exec_retained(keep, &argv, &[]);
                let _ = error;
                libc::_exit(127);
            }
        }
        if observe {
            // The first stop is the exec trap.
            let mut status = 0;
            // SAFETY: waiting on our own child.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let actual =
                executable::observe_process_image(pid, Role::MkfsXfs, mkfs.installation_generation);
            // SAFETY: release the traced child.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
            let actual = actual?;
            link.record(SupervisorRecord::Observed(actual))?;
            if actual != mkfs {
                // SAFETY: our own child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                return Err(Abort::Refused("formatter actual image differs".into()));
            }
        } else {
            link.record(SupervisorRecord::Observed(mkfs))?;
        }
        let status = link.wait_for(Duration::from_secs(60), || waitpid_nohang(pid))?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(Abort::Refused(format!("formatter failed: status {status}")));
        }
        let after = storage::identity_at(dir, storage::WORK_FILE)?;
        if after != Some(identity) {
            return Err(Abort::Refused(
                "work inode changed during formatting".into(),
            ));
        }
        work.sync_all().map_err(Abort::from)?;
        dir.sync_all().map_err(Abort::from)?;
        Ok(())
    }

    /// The forward pipeline, C3 through BOOTING. Returns the booted state; on any
    /// abort, what exists stays for Remove and the caller contains the VM subtree.
    pub fn launch(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        expected: &[ExecutableIdentity],
        plan_generation: u64,
        created: &mut Option<CgroupIdentity>,
    ) -> Result<Booted, Abort> {
        let recipe = &plan.launch["resource_recipe"];
        // Orphans reparent here, so V becomes S's child when J exits.
        // SAFETY: a process-wide flag on S itself.
        cvt(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) })?;
        link.step("cgroup")?;
        let identity = cgroup::create_tree(&plan.cgroup, &recipe["cgroups"])?;
        *created = Some(identity);
        link.after("cgroup");
        link.record(SupervisorRecord::Resource(ResourceRecord::Cgroup(identity)))?;
        link.step("join")?;
        cgroup::join(&format!("{}/control", plan.cgroup), identity.control_ino)?;
        link.step("artifacts")?;
        let profile_name = link.context().profile.clone();
        let (kernel, rootfs) = open_artifacts(link, &profile_name)?;
        link.step("work_dir")?;
        let dir = storage::create_work_dir(&plan.paths)?;
        link.step("work_file")?;
        let (work, first) = storage::create_work_file(&dir)?;
        link.after("work_file");
        link.record(SupervisorRecord::Resource(ResourceRecord::WorkFile(first)))?;
        link.step("fallocate")?;
        let work_identity = storage::preallocate(&work, plan.work_bytes)?;
        if (work_identity.st_dev, work_identity.st_ino) != (first.st_dev, first.st_ino) {
            return Err(Abort::Refused("work inode changed".into()));
        }
        link.step("mkfs")?;
        format_work(link, plan, &dir, &work, work_identity, expected)?;
        link.step("private_files")?;
        let block = storage::identity_block(&plan.plan)?;
        let identity_file = storage::write_private(&dir, storage::IDENTITY_FILE, &block)?;
        let config_file = storage::write_private(
            &dir,
            storage::CONFIG_FILE,
            &storage::config_bytes(&plan.launch)?,
        )?;
        link.record(SupervisorRecord::Resource(ResourceRecord::PrivateFiles {
            identity: identity_file,
            config: config_file,
        }))?;
        link.event(&SupervisorEvent::PreparationDone);
        link.step("loop")?;
        let mut attempts = 0;
        let binding = loop {
            attempts += 1;
            let minor = storage::free_loop_slot()?;
            let binding = LoopBinding {
                major: storage::LOOP_MAJOR,
                minor,
                backing_dev: work_identity.st_dev,
                backing_ino: work_identity.st_ino,
                offset: 0,
                size_limit: plan.work_bytes,
            };
            link.record(SupervisorRecord::Resource(ResourceRecord::LoopIntent(
                binding,
            )))?;
            link.step("loop_configure")?;
            match storage::attach_loop(&binding, &work) {
                Ok(()) => {
                    link.after("loop_configure");
                    break binding;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempts < 4 => {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        };
        link.record(SupervisorRecord::Resource(ResourceRecord::Loop(binding)))?;
        drop(work);
        link.step("jail")?;
        let (root, mount) = storage::create_jail(&plan.paths)?;
        link.after("jail");
        link.record(SupervisorRecord::Resource(ResourceRecord::JailMount(mount)))?;
        link.step("binds")?;
        let config = link.context().config.clone();
        let profile = config
            .profile(&profile_name)
            .ok_or_else(|| Abort::Refused("profile".into()))?;
        let vmm_fd = profile
            .table
            .raw_fd(Role::Firecracker)
            .ok_or_else(|| Abort::Refused("VMM is not retained".into()))?;
        let jailer_fd = profile
            .table
            .raw_fd(Role::Jailer)
            .ok_or_else(|| Abort::Refused("jailer is not retained".into()))?;
        // SAFETY: a duplicate of a retained descriptor, closed with this File.
        let vmm_file =
            unsafe { File::from_raw_fd(cvt(libc::fcntl(vmm_fd, libc::F_DUPFD_CLOEXEC, 3))?) };
        let config_open = storage::open_private(&dir, storage::CONFIG_FILE)?;
        let identity_open = storage::open_private(&dir, storage::IDENTITY_FILE)?;
        for (name, source) in [
            ("kernel", &kernel),
            ("rootfs", &rootfs),
            ("config.json", &config_open),
            ("identity", &identity_open),
            ("firecracker", &vmm_file),
        ] {
            storage::bind_read_only(&root, &plan.paths, name, source)?;
        }
        storage::work_node(&root, binding.minor, plan.uid, plan.gid)?;
        drop((kernel, rootfs, config_open, identity_open));
        let jailer = expected_identity(expected, Role::Jailer)?;
        let vmm = expected_identity(expected, Role::Firecracker)?;
        if (vmm_file.metadata()?.dev(), vmm_file.metadata()?.ino()) != (vmm.st_dev, vmm.st_ino) {
            return Err(Abort::Refused("retained VMM differs from the plan".into()));
        }
        link.step("spawn_intent")?;
        link.record(SupervisorRecord::Phase {
            from: vec!["preparing".into()],
            to: "spawn_intent".into(),
        })?;
        let booted = spawn(
            link,
            plan,
            identity,
            &mount,
            jailer_fd,
            &vmm_file,
            jailer,
            vmm,
            plan_generation,
            binding,
        )?;
        Ok(booted)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        identity: CgroupIdentity,
        mount: &JailMount,
        jailer_fd: RawFd,
        vmm_file: &File,
        jailer: ExecutableIdentity,
        vmm: ExecutableIdentity,
        plan_generation: u64,
        binding: LoopBinding,
    ) -> Result<Booted, Abort> {
        let (control_s, control_j) = std::os::unix::net::UnixStream::pair()?;
        let mut gate = [0 as RawFd; 2];
        cvt(unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) })?;
        let mut console = [0 as RawFd; 2];
        cvt(unsafe { libc::pipe2(console.as_mut_ptr(), libc::O_CLOEXEC) })?;
        // SAFETY: new owned descriptors.
        let (gate_read, gate_write) =
            unsafe { (OwnedFd::from_raw_fd(gate[0]), OwnedFd::from_raw_fd(gate[1])) };
        let (console_read, console_write) = unsafe {
            (
                OwnedFd::from_raw_fd(console[0]),
                OwnedFd::from_raw_fd(console[1]),
            )
        };
        let argv: Vec<CString> = plan
            .argv("jailer_argv")?
            .into_iter()
            .map(|a| CString::new(a).map_err(|_| io::Error::other("argv NUL")))
            .collect::<io::Result<_>>()?;
        let vmm_leaf = format!("{}/vm/vmm", plan.cgroup);
        let control_raw = control_j.as_raw_fd();
        let vmm_raw = vmm_file.as_raw_fd();
        // SAFETY: S is single-threaded; the child only does async-signal-safe work
        // plus small allocations before exec, and never returns.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if pid == 0 {
            launch_child(
                &vmm_leaf,
                identity.vmm_ino,
                gate_read.as_raw_fd(),
                console_write.as_raw_fd(),
                jailer_fd,
                vmm_raw,
                control_raw,
                &argv,
            );
        }
        drop(gate_read);
        drop(console_write);
        drop(control_j);
        // SAFETY: the console read end is ours; nonblocking for the drain.
        unsafe {
            let flags = libc::fcntl(console_read.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(
                console_read.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            );
        }
        link.console = Some(Console {
            fd: console_read,
            prefix: Vec::new(),
            total: 0,
        });
        let j = identify(pid)?;
        let j_pidfd = pin(j)?;
        link.after("fork_jailer");
        link.record(SupervisorRecord::Child {
            role: ChildRole::Jailer,
            process: j,
        })?;
        link.step("release_jailer")?;
        // The gate byte releases J's exec. Its own exec descriptor is close-on-exec.
        write_all_pipe(gate_write.as_raw_fd(), b"G")?;
        drop(gate_write);
        // Bootstrap: the record, then J's post-exec gate.
        let record = executable::BootstrapRecord::for_vmm(
            plan_generation,
            &vmm,
            executable::JailRootIdentity {
                mount_id: mount.mount_id,
                st_dev: mount.st_dev,
                st_ino: mount.st_ino,
            },
        );
        let label = plan.launch["executable_paths"]["firecracker"]
            .as_str()
            .unwrap_or("");
        if record.exec_file_label != label {
            return Err(Abort::Refused(
                "bootstrap label differs from the plan".into(),
            ));
        }
        let bytes = record.encode().map_err(Abort::Refused)?;
        let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        write_all(control_s.as_raw_fd(), &framed)?;
        let mut ready = Vec::new();
        let control_fd = control_s.as_raw_fd();
        link.wait_for(Duration::from_secs(10), || {
            if pidfd_exited(&j_pidfd) {
                return Err(io::Error::other("the jailer exited at its bootstrap gate"));
            }
            read_some(control_fd, &mut ready, 4)
        })?;
        if ready != b"RDY1" {
            return Err(Abort::Refused(
                "the jailer's gate reply is malformed".into(),
            ));
        }
        // J is waiting: observe what actually runs, through the pinned process.
        let actual =
            executable::observe_process_image(j.pid, Role::Jailer, jailer.installation_generation)?;
        if pidfd_exited(&j_pidfd) {
            return Err(Abort::Refused(
                "the jailer exited during observation".into(),
            ));
        }
        let fds = open_descriptors(j.pid)?;
        link.record(SupervisorRecord::Observed(actual))?;
        if actual != jailer {
            return Err(Abort::Refused(
                "the jailer's actual image differs from the journal".into(),
            ));
        }
        if fds.keys().copied().collect::<Vec<_>>() != vec![0, 1, 2, 3, 4] {
            return Err(Abort::Refused(format!(
                "the jailer holds unexpected descriptors: {fds:?}"
            )));
        }
        link.step("continue_jailer")?;
        write_all(control_fd, b"CONT")?;
        link.after("continue_jailer");
        let socket_ino = socket_inode(control_fd)?;
        // J clones V, writes its PID file and exits. Its zero exit is not V's.
        let status = link.wait_for(Duration::from_secs(20), || waitpid_nohang(j.pid))?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(Abort::Refused(format!(
                "the jailer exited abnormally: {status}"
            )));
        }
        drop(control_s);
        link.step("adopt")?;
        let v = adopt(link, plan, &identity)?;
        let v_pidfd = pin(v)?;
        link.after("adopt");
        let actual = as_fs_ids(plan.uid, plan.gid, || {
            executable::observe_process_image(v.pid, Role::Firecracker, vmm.installation_generation)
        })?;
        let status_text = proc_status(v.pid)?;
        if pidfd_exited(&v_pidfd) {
            return Err(Abort::Refused("the VMM exited during observation".into()));
        }
        let credentials = storage::parse_status(&status_text)?;
        let credentials = test_credentials(credentials);
        link.record(SupervisorRecord::Child {
            role: ChildRole::Vm,
            process: v,
        })?;
        link.record(SupervisorRecord::Observed(actual))?;
        link.record(SupervisorRecord::Resource(ResourceRecord::Vmm {
            process: v,
            credentials: credentials.clone(),
        }))?;
        link.event(&SupervisorEvent::VmStarted(v));
        if actual != vmm {
            return Err(Abort::Refused(
                "the VMM's actual image differs from the journal".into(),
            ));
        }
        storage::check_vmm_credentials(
            &credentials,
            &plan.launch["resource_recipe"]["vmm_credentials"],
        )
        .map_err(Abort::Refused)?;
        // No bootstrap or executable descriptor survived V's exec.
        for (fd, target) in as_fs_ids(plan.uid, plan.gid, || open_descriptors(v.pid))? {
            if target == format!("socket:[{socket_ino}]") || target.ends_with("/firecracker") {
                return Err(Abort::Refused(format!(
                    "the VMM kept bootstrap FD {fd} ({target})"
                )));
            }
        }
        link.step("harden")?;
        pidfd_signal(&v_pidfd, libc::SIGSTOP)?;
        link.wait_for(Duration::from_secs(5), || {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", v.pid))?;
            let state = stat
                .rfind(')')
                .and_then(|at| stat[at + 1..].split_whitespace().next().map(str::to_owned));
            Ok((state.as_deref() == Some("T")).then_some(()))
        })?;
        storage::harden_jail(
            &plan.paths,
            mount,
            (vmm.st_dev, vmm.st_ino),
            binding.minor,
            plan.uid,
            plan.gid,
        )?;
        pidfd_signal(&v_pidfd, libc::SIGCONT)?;
        link.after("harden");
        link.record(SupervisorRecord::Phase {
            from: vec!["spawn_intent".into()],
            to: "booting".into(),
        })?;
        Ok(Booted {
            plan: plan.clone(),
            cgroup: identity,
            vmm: v,
            vmm_pidfd: v_pidfd,
            console: link.console.take(),
        })
    }

    /// Test-only credential perturbation proving a mismatch stops the launch.
    fn test_credentials(credentials: Credentials) -> Credentials {
        #[cfg(test)]
        {
            let mut credentials = credentials;
            if super::super::workers::fault_enabled("S.credentials.capbnd") {
                credentials.cap_bnd |= 1 << 10;
            }
            credentials
        }
        #[cfg(not(test))]
        credentials
    }

    fn write_all_pipe(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
        // SAFETY: the slice is live.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n as usize != bytes.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The gated launch child: it enters the verified VMM leaf, unshares a network
    /// namespace with no links, sets the contract's process recipe, waits for S's gate
    /// byte and only then executes the retained jailer descriptor. Never returns.
    #[allow(clippy::too_many_arguments)]
    fn launch_child(
        vmm_leaf: &str,
        vmm_ino: u64,
        gate: RawFd,
        console: RawFd,
        jailer_fd: RawFd,
        vmm_fd: RawFd,
        control: RawFd,
        argv: &[CString],
    ) -> ! {
        let fail = |code: i32| -> ! {
            // SAFETY: leave without unwinding into S's stack.
            unsafe { libc::_exit(code) }
        };
        // SAFETY: restoring default dispositions in the new process.
        unsafe {
            for signal in [
                libc::SIGTERM,
                libc::SIGINT,
                libc::SIGCHLD,
                libc::SIGHUP,
                libc::SIGPIPE,
            ] {
                libc::signal(signal, libc::SIG_DFL);
            }
        }
        if cgroup::join(vmm_leaf, vmm_ino).is_err() {
            fail(120);
        }
        // SAFETY: plain syscalls in the child.
        unsafe {
            if libc::unshare(libc::CLONE_NEWNET) != 0 {
                fail(121);
            }
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &core);
            libc::umask(0o077);
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if null < 0
                || libc::dup2(null, 0) < 0
                || libc::dup2(console, 1) < 0
                || libc::dup2(console, 2) < 0
            {
                fail(122);
            }
            libc::setsid();
            let mut byte = 0u8;
            if libc::read(gate, (&mut byte as *mut u8).cast(), 1) != 1 {
                fail(123);
            }
        }
        let jailer = match executable::arrange_bootstrap_fds(jailer_fd, vmm_fd, control) {
            Ok(fd) => fd,
            Err(_) => fail(124),
        };
        let _ = executable::exec_retained(jailer, argv, &[]);
        fail(125)
    }

    /// Adopts V: the PID file is only a candidate; the only task in `vm/vmm` must be
    /// it, it must be S's child, and its pidfd is opened before any trust in it.
    fn adopt(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        identity: &CgroupIdentity,
    ) -> Result<ProcessId, Abort> {
        let leaf = cgroup::open_node(&format!("{}/vm/vmm", plan.cgroup))?;
        if cgroup::inode(&leaf)? != identity.vmm_ino {
            return Err(Abort::Refused("vm/vmm was replaced".into()));
        }
        let root = storage::open_trusted(&plan.paths.jail_dir)
            .and_then(|dir| storage::open_dir_at(&dir, "root"))?;
        let candidate = link.wait_for(Duration::from_secs(5), || {
            match storage::open_private(&root, "firecracker.pid") {
                Ok(file) => {
                    use std::io::Read;
                    let mut text = String::new();
                    file.take(32).read_to_string(&mut text)?;
                    Ok(text.trim().parse::<i32>().ok())
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        })?;
        let procs = cgroup::procs(&leaf)?;
        if procs != vec![candidate] {
            return Err(Abort::Refused(format!(
                "vm/vmm holds {procs:?}, not only {candidate}"
            )));
        }
        // SAFETY: getpid has no preconditions.
        if ppid(candidate)? != unsafe { libc::getpid() } {
            return Err(Abort::Refused(
                "the VMM candidate is not this supervisor's child".into(),
            ));
        }
        Ok(identify(candidate)?)
    }

    /// The steady loop of a booted S: heartbeats, the console drain, V's pidfd and
    /// H's commands. V's exit or H's loss ends it; Revoke stops V and ends it.
    pub fn steady(link: &mut Link<'_>, booted: &mut Booted) -> SteadyEnd {
        link.console = booted.console.take();
        #[cfg(test)]
        let mut dumped = Instant::now();
        loop {
            link.beat();
            #[cfg(test)]
            if dumped.elapsed() >= Duration::from_millis(500) {
                dumped = Instant::now();
                link.dump_console();
            }
            if pidfd_exited(&booted.vmm_pidfd) {
                reap_strays(&[]);
                return SteadyEnd::VmExited;
            }
            match link.poll(Duration::from_millis(20)) {
                Ok(None) => {}
                Ok(Some(_)) => {}
                Err(Abort::Revoked) => return SteadyEnd::Revoked,
                Err(_) => return SteadyEnd::HelperGone,
            }
        }
    }

    pub enum SteadyEnd {
        VmExited,
        Revoked,
        HelperGone,
    }

    /// Kills the allocation's `vm` subtree through its pinned inode and waits for it to
    /// empty. Used by S on any abort, Revoke or V exit, and by cleanup.
    pub fn contain(
        plan: &LaunchPlan,
        identity: Option<&CgroupIdentity>,
    ) -> io::Result<cgroup::NodeState> {
        let path = format!("{}/vm", plan.cgroup);
        let st_ino = match identity {
            Some(identity) => identity.vm_ino,
            // Unrecorded: the deterministic name under C2 is ours, so use what is there.
            None => match cgroup::open_node(&path) {
                Ok(node) => cgroup::inode(&node)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(cgroup::NodeState::Absent);
                }
                Err(error) => return Err(error),
            },
        };
        cgroup::kill_node(&CgroupTarget { path, st_ino }, Duration::from_secs(2))
    }

    /// Cleanup: stop everything still in the VM subtree, then remove exactly the owned
    /// mounts, loop bindings, files and directories. The cgroup tree itself is K's to
    /// remove after S exits. Any unknown or replaced entry fails without deleting it.
    pub fn cleanup(
        link: &mut Link<'_>,
        plan: &LaunchPlan,
        recorded: &RecordedResources,
    ) -> Result<(), Abort> {
        link.step("cleanup_stop")?;
        match contain(plan, recorded.cgroup.as_ref())? {
            cgroup::NodeState::Absent | cgroup::NodeState::Empty => {}
            state => return Err(Abort::Refused(format!("the VM subtree is {state:?}"))),
        }
        if let Some(vmm) = recorded.vmm
            && let super::super::workers::ProcessState::Running { start_time } =
                super::super::workers::process_state(vmm.pid)
            && start_time == vmm.start_time
        {
            return Err(Abort::Refused("the recorded VMM is still running".into()));
        }
        link.step("cleanup_unmount")?;
        storage::unmount_jail(&plan.paths)?;
        link.step("cleanup_loop")?;
        for binding in &recorded.loops {
            match storage::detach_loop(binding)? {
                storage::LoopOutcome::Detached
                | storage::LoopOutcome::Free
                | storage::LoopOutcome::NotOurs => {}
            }
        }
        // A slot backed in our directory that no record names: refused, never guessed.
        let leftover = storage::loops_backed_in(&plan.paths.work_dir)?;
        if !leftover.is_empty() {
            return Err(Abort::Refused(format!(
                "unrecorded loop slots remain: {leftover:?}"
            )));
        }
        link.step("cleanup_files")?;
        storage::remove_jail_dirs(&plan.paths)?;
        let mut files = BTreeMap::new();
        if let Some(identity) = recorded.work_file {
            files.insert(storage::WORK_FILE.to_string(), identity);
        }
        if let Some(identity) = recorded.identity_file {
            files.insert(storage::IDENTITY_FILE.to_string(), identity);
        }
        if let Some(identity) = recorded.config_file {
            files.insert(storage::CONFIG_FILE.to_string(), identity);
        }
        storage::remove_work(&plan.paths, &files)?;
        Ok(())
    }
}
