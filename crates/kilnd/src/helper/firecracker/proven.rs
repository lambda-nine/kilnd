//! Section 7.1's destructive-action gate (B4 recheck 3). No destructive action runs on
//! a resource unless the caller holds proof that the resource's current generation is
//! a durable journaled generation from the current boot. The proofs are the types
//! below: none is `Clone`, none can be built outside this module, and only the
//! verification functions here produce them. Every destructive system call the helper
//! makes on a tenant-reachable or replaceable resource lives in this module and takes
//! its proof by value or reference:
//!
//! | Action | Proof | Bound to |
//! |---|---|---|
//! | `pidfd_send_signal` | [`ProvenProcess`] | the pidfd opened before the start time and boot ID were compared |
//! | `cgroup.kill` | [`ProvenCgroupVm`] | the `vm` node's descriptor, its children re-listed from that descriptor (`getdents64`) immediately before |
//! | cgroup `rmdir` | [`ProvenCgroupTree`] | each parent's descriptor, the child's inode re-read immediately before |
//! | `unlinkat` | [`ProvenFile`] | the verified directory's descriptor, the birth time re-read immediately before |
//! | directory `rmdir` | [`ProvenDir`] | the parent's descriptor, the birth time re-read immediately before |
//! | `umount2` | [`ProvenMount`] | `<name>` from a thread whose working directory is the parent's descriptor, the unique mount ID re-read immediately before |
//! | `LOOP_CLR_FD` | [`ProvenLoop`] | the slot descriptor the generation was compared on |
//! | `kill` of S's own unreaped child | [`UnreapedChild`] | the PID the kernel cannot reuse before this process reaps it |
//!
//! A resource without such proof is Unknown: it stays charged, nothing is done to it,
//! and it never counts toward ABSENT. A missing, invalid, unreadable or mismatching boot
//! ID never produces a proof: a mismatch only shows that the journaled generation is
//! gone. The residual windows are the decided ones of section 7.1: the kernel has no
//! compare-and-act for a cgroup child swapped between its last check and `cgroup.kill`
//! or `rmdir`, for a name swapped between `statx` and `unlinkat`, or for a mount moved
//! between its last check (whose descriptor must be closed first, or the unmount is
//! busy) and `umount2`. Enforcement: the unit test
//! `no_destructive_call_outside_the_gate` fails if any other helper source makes one of
//! these calls outside its allow-list.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
// Approved (design 7.1): the destructive-action gate itself. Every raw signal,
// cgroup.kill, unlink, rmdir, unmount and LOOP_CLR_FD sits behind a proof type here.
#![allow(clippy::disallowed_methods)]
use super::workers::ProcessId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io;
use std::time::Duration;

/// Why a destructive action cannot be proven against a resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unprovable {
    /// The journaled generation is provably gone: nothing at the name, a free slot, an
    /// exited process, or a record from another boot with nothing there now.
    Gone,
    /// Something else holds the journaled name: another inode, birth time, unique
    /// mount ID, disk sequence number, an unexpected child, or anything at the name of
    /// a record from another boot. It is never touched.
    Replaced(String),
    /// Ownership cannot be decided: no journaled generation (an intent alone, or no
    /// record at all), a missing or invalid boot ID, or unreadable evidence. Nothing is
    /// touched and the allocation stays charged.
    Unknown(String),
}

impl fmt::Display for Unprovable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone => write!(f, "gone"),
            Self::Replaced(why) => write!(f, "replaced: {why}"),
            Self::Unknown(why) => write!(f, "unknown: {why}"),
        }
    }
}

impl Unprovable {
    /// A refusal as an I/O error, for callers that only proceed on proof.
    pub fn refusal(&self, what: &str) -> io::Error {
        io::Error::other(format!("{what} is not proven ours: {self}"))
    }
}

fn unknown(why: impl fmt::Display) -> Unprovable {
    Unprovable::Unknown(why.to_string())
}

/// The kernel's boot ID, procfs `sys/kernel/random/boot_id` (on macOS, where only the
/// fake fixtures run, `kern.bootsessionuuid`). Process start times and every
/// kernel-generation ID the gate compares are meaningful only within one boot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId([u8; 16]);

impl BootId {
    /// A boot ID exactly as the kernel prints it; anything else is no boot ID.
    pub fn parse(text: &str) -> Option<Self> {
        if !super::storage::valid_boot_id(text) {
            return None;
        }
        let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
        let mut bytes = [0u8; 16];
        for (index, pair) in hex.chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).ok()?;
            bytes[index] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// This boot's ID, read beneath the helper's private procfs instance
    /// (`crate::sys::procfs`), never a `/proc` pathname. Unreadable or malformed is an
    /// error, never a placeholder.
    #[cfg(target_os = "linux")]
    pub fn current() -> io::Result<Self> {
        let text = crate::sys::procfs::boot_id()?;
        Self::parse(text.trim_end_matches('\n'))
            .ok_or_else(|| io::Error::other("malformed boot ID"))
    }

    #[cfg(target_os = "macos")]
    pub fn current() -> io::Result<Self> {
        let mut buffer = [0u8; 64];
        let mut size = buffer.len();
        // SAFETY: the name is NUL-terminated and the buffer is writable for `size`.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                buffer.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let text = std::str::from_utf8(&buffer[..size])
            .map_err(io::Error::other)?
            .trim_end_matches('\0')
            .to_ascii_lowercase();
        Self::parse(&text).ok_or_else(|| io::Error::other("malformed boot session UUID"))
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if [4, 6, 8, 10].contains(&index) {
                write!(f, "-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BootId({self})")
    }
}

impl Serialize for BootId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BootId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("not a boot ID"))
    }
}

/// Whether a journaled boot ID string names this boot. A malformed record or an
/// unreadable host boot ID is Unknown; another boot is `Ok(false)`.
pub fn recorded_boot_is_current(recorded: &str) -> Result<bool, Unprovable> {
    let recorded =
        BootId::parse(recorded).ok_or_else(|| unknown("the journaled boot ID is malformed"))?;
    let current =
        BootId::current().map_err(|e| unknown(format!("the host boot ID is unreadable: {e}")))?;
    Ok(recorded == current)
}

// Processes.

/// A live process proven to be the journaled one: this boot, its PID and its start
/// time, compared after its pidfd was opened, so a signal can reach only it.
pub struct ProvenProcess {
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
    target: ProcessId,
}

impl ProvenProcess {
    pub fn target(&self) -> ProcessId {
        self.target
    }
}

/// The journaled process identity checked against the live process. A PID or start
/// time that does not match means the journaled process is not running, so it is gone
/// whatever the boot. A match with a journaled boot ID from another boot is another
/// process: gone. A match with no journaled boot ID, or with the host's unreadable, is
/// Unknown and is never signaled.
pub fn prove_process(target: &ProcessId) -> Result<ProvenProcess, Unprovable> {
    use super::workers::{ProcessState, process_state};
    #[cfg(target_os = "linux")]
    let pidfd = match super::supervisor::pidfd_open(target.pid) {
        Ok(pidfd) => pidfd,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Err(Unprovable::Gone),
        Err(error) => return Err(unknown(format!("pidfd_open: {error}"))),
    };
    match process_state(target.pid) {
        ProcessState::Running { start_time } if start_time == target.start_time => {}
        _ => return Err(Unprovable::Gone),
    }
    #[cfg(target_os = "linux")]
    if super::supervisor::pidfd_exited(&pidfd) {
        return Err(Unprovable::Gone);
    }
    let Some(recorded) = target.boot_id else {
        return Err(unknown(
            "the journaled process has no boot ID: PID and start time alone prove nothing",
        ));
    };
    let current =
        BootId::current().map_err(|e| unknown(format!("the host boot ID is unreadable: {e}")))?;
    if recorded != current {
        return Err(Unprovable::Gone);
    }
    Ok(ProvenProcess {
        #[cfg(target_os = "linux")]
        pidfd,
        target: *target,
    })
}

/// Whether the journaled process is provably not running. Unknown is not gone.
pub fn process_gone(target: &ProcessId) -> bool {
    matches!(prove_process(target), Err(Unprovable::Gone))
}

/// One signal to exactly the proven process.
pub fn signal(proof: &ProvenProcess, signal: i32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the pidfd pins one process; no siginfo.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                proof.pidfd.as_raw_fd(),
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
    #[cfg(not(target_os = "linux"))]
    {
        // macOS runs only the fake fixtures: no pidfd, so the start time was compared
        // just before. Production is Linux.
        // SAFETY: a plain signal to the PID whose identity was just compared.
        if unsafe { libc::kill(proof.target.pid, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn exited(proof: &ProvenProcess) -> bool {
    #[cfg(target_os = "linux")]
    {
        super::supervisor::pidfd_exited(&proof.pidfd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use super::workers::{ProcessState, process_state};
        !matches!(process_state(proof.target.pid),
            ProcessState::Running { start_time } if start_time == proof.target.start_time)
    }
}

/// SIGKILL to the proven process and a bounded wait for its exit.
pub fn kill_and_wait(proof: ProvenProcess, wait: Duration) -> bool {
    let _ = signal(&proof, libc::SIGKILL);
    let end = std::time::Instant::now() + wait;
    loop {
        if exited(&proof) {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Stops one journaled process: true only when it is provably gone. An Unknown
/// identity is never signaled and is not gone.
pub fn stop_process(target: &ProcessId) -> bool {
    match prove_process(target) {
        Ok(proof) => kill_and_wait(proof, Duration::from_secs(2)),
        Err(Unprovable::Gone) => true,
        Err(_) => false,
    }
}

/// A child this process forked and has not reaped. Until `waitpid` reaps it, the
/// kernel keeps its PID, so a signal by PID can reach only it. Only [`fork_child`]
/// makes one, and a reaped child is never signaled. Not journaled (S's formatter runs
/// and is waited in the allocation's charged `control` leaf) and never replaceable.
pub struct UnreapedChild {
    pid: i32,
    reaped: bool,
}

/// Which side of a [`fork_child`] this is.
pub enum Forked {
    Child,
    Parent(UnreapedChild),
}

/// `fork(2)`.
///
/// # Safety
///
/// As for `fork`: the caller is single-threaded, and the child only does
/// async-signal-safe work before it execs or `_exit`s.
pub unsafe fn fork_child() -> io::Result<Forked> {
    // SAFETY: the caller's contract above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        return Ok(Forked::Child);
    }
    Ok(Forked::Parent(UnreapedChild { pid, reaped: false }))
}

impl UnreapedChild {
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// A blocking wait for the next state change, as for a ptrace stop. An exit or a
    /// kill reaps the child.
    pub fn wait(&mut self) -> io::Result<i32> {
        let mut status = 0;
        // SAFETY: status is writable; the PID is our own unreaped child.
        let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.reaped = true;
        }
        Ok(status)
    }

    /// `waitpid(WNOHANG)`: the exit status once the child has exited, which reaps it.
    pub fn try_reap(&mut self) -> io::Result<Option<i32>> {
        let mut status = 0;
        // SAFETY: status is writable; the PID is our own unreaped child.
        let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Ok(None);
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.reaped = true;
            return Ok(Some(status));
        }
        Ok(None)
    }

    /// `PTRACE_DETACH` of this traced, unreaped child (the formatter's test-only
    /// exec-stop observation): its PID cannot name another process.
    #[cfg(target_os = "linux")]
    pub fn detach_trace(&self) {
        if !self.reaped {
            // SAFETY: an unreaped child's PID cannot name another process.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, self.pid, 0, 0) };
        }
    }

    /// SIGKILL, only while the PID is still provably this child's.
    pub fn kill_unreaped(&self) {
        if !self.reaped {
            // SAFETY: an unreaped child's PID cannot name another process.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::super::cgroup::{self, CgroupIdentity, NodeState};
    use super::super::storage::{self, FileIdentity, LoopBinding, LoopGeneration};
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    fn cstr(name: &str) -> io::Result<CString> {
        CString::new(name).map_err(|_| io::Error::other("name contains NUL"))
    }

    fn not_found(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound
    }

    fn rmdir_at(parent: &File, name: &CString) -> io::Result<()> {
        // SAFETY: a NUL-terminated name below a live directory descriptor;
        // AT_REMOVEDIR removes only an empty directory or cgroup.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // Cgroups.

    /// Subdirectory names of a cgroup node, its child cgroups, enumerated from the
    /// retained node descriptor itself (`getdents64` on a rewound duplicate, B4 recheck
    /// 5): never by reopening a `/proc/self/fd/N` pathname, which a mount in the
    /// helper's namespace could replace with another view. An entry whose type the
    /// filesystem does not report counts as a child.
    fn child_cgroups(node: &File) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in crate::sys::read_dir_fd(node, 4096)? {
            if matches!(entry.kind, libc::DT_DIR | libc::DT_UNKNOWN) {
                names.push(String::from_utf8_lossy(&entry.name).into_owned());
            }
            if names.len() > 64 {
                return Err(io::Error::other("too many child cgroups"));
            }
        }
        names.sort();
        Ok(names)
    }

    fn io_unknown(what: &str) -> impl Fn(io::Error) -> Unprovable + '_ {
        move |error| unknown(format!("{what}: {error}"))
    }

    /// Every child cgroup of a recorded node is a recorded child with its journaled
    /// inode, and the recorded leaves have no children at all. A missing recorded child
    /// is fine (gone); anything else present is a replacement.
    fn check_children(
        node: &File,
        prefix: &str,
        allowed: &[&str],
        identity: &CgroupIdentity,
    ) -> Result<Vec<(String, File)>, Unprovable> {
        let mut found = Vec::new();
        for name in child_cgroups(node).map_err(io_unknown("list cgroup children"))? {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if !allowed.contains(&name.as_str()) {
                return Err(Unprovable::Replaced(format!(
                    "unexpected cgroup {path} in the recorded tree"
                )));
            }
            let child = match cgroup::open_dir(node, &name) {
                Ok(child) => child,
                Err(error) if not_found(&error) => continue,
                Err(error) => return Err(unknown(format!("open cgroup {path}: {error}"))),
            };
            let ino = child.metadata().map_err(io_unknown("cgroup inode"))?.ino();
            if Some(ino) != identity.node_ino(&path) {
                return Err(Unprovable::Replaced(format!(
                    "cgroup {path} is inode {ino}, not the journaled {:?}",
                    identity.node_ino(&path)
                )));
            }
            found.push((name, child));
        }
        Ok(found)
    }

    /// The `vm` subtree below a verified `vm` node: only `vmm` and `console`, each the
    /// journaled inode and childless.
    fn check_vm_subtree(vm: &File, identity: &CgroupIdentity) -> Result<(), Unprovable> {
        for (name, child) in check_children(vm, "vm", &["vmm", "console"], identity)? {
            if let Some(extra) = child_cgroups(&child)
                .map_err(io_unknown("list cgroup children"))?
                .first()
            {
                return Err(Unprovable::Replaced(format!(
                    "unexpected cgroup vm/{name}/{extra} in the recorded tree"
                )));
            }
        }
        Ok(())
    }

    /// The allocation parent at `relative`, opened below its instance node, and the
    /// recorded identity it must carry. Nothing at the path is Gone; something there
    /// with no journaled generation is Unknown; a record from another boot with anything
    /// at its path, or another inode, is Replaced.
    fn open_recorded_parent<'a>(
        relative: &str,
        identity: Option<&'a CgroupIdentity>,
    ) -> Result<(File, CString, File, &'a CgroupIdentity), Unprovable> {
        let (base, leaf) = relative
            .rsplit_once('/')
            .ok_or_else(|| unknown("cgroup path has no parent"))?;
        let instance = match cgroup::open_node(base) {
            Ok(node) => node,
            Err(error) if not_found(&error) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("open cgroup {base}: {error}"))),
        };
        let parent = match cgroup::open_dir(&instance, leaf) {
            Ok(node) => node,
            Err(error) if not_found(&error) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("open cgroup {relative}: {error}"))),
        };
        let identity = identity.ok_or_else(|| {
            unknown("a cgroup is at the allocation's path but no generation was journaled")
        })?;
        if !recorded_boot_is_current(&identity.boot_id)? {
            return Err(Unprovable::Replaced(
                "the journaled tree belongs to another boot; this one is a replacement".into(),
            ));
        }
        let ino = parent.metadata().map_err(io_unknown("cgroup inode"))?.ino();
        if ino != identity.parent_ino {
            return Err(Unprovable::Replaced(format!(
                "allocation cgroup is inode {ino}, not the journaled {}",
                identity.parent_ino
            )));
        }
        Ok((
            instance,
            cstr(leaf).map_err(io_unknown("name"))?,
            parent,
            identity,
        ))
    }

    /// The journaled `vm` subtree, proven: this boot, the allocation parent and `vm`
    /// with their journaled inodes, and below `vm` only `vmm` and `console` with theirs.
    /// Holds the `vm` node's descriptor, which is what `cgroup.kill` is written through.
    pub struct ProvenCgroupVm {
        vm: File,
        identity: CgroupIdentity,
    }

    pub fn prove_cgroup_vm(
        relative: &str,
        identity: Option<&CgroupIdentity>,
    ) -> Result<ProvenCgroupVm, Unprovable> {
        let (_, _, parent, identity) = open_recorded_parent(relative, identity)?;
        let vm = match cgroup::open_dir(&parent, "vm") {
            Ok(vm) => vm,
            Err(error) if not_found(&error) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("open cgroup vm: {error}"))),
        };
        let ino = vm.metadata().map_err(io_unknown("cgroup inode"))?.ino();
        if ino != identity.vm_ino {
            return Err(Unprovable::Replaced(format!(
                "cgroup vm is inode {ino}, not the journaled {}",
                identity.vm_ino
            )));
        }
        check_vm_subtree(&vm, identity)?;
        Ok(ProvenCgroupVm {
            vm,
            identity: identity.clone(),
        })
    }

    /// Whether anything runs in the proven subtree.
    pub fn vm_populated(proof: &ProvenCgroupVm) -> io::Result<bool> {
        cgroup::populated(&proof.vm)
    }

    /// The one `cgroup.kill` write in the helper, on the `vm` descriptor a
    /// [`ProvenCgroupVm`] holds. Private: only [`kill_cgroup_vm`] reaches it.
    fn write_cgroup_kill(vm: &File) -> io::Result<()> {
        use std::io::Write;
        use std::os::fd::FromRawFd;
        // SAFETY: a NUL-terminated name relative to the live `vm` directory descriptor.
        let fd = unsafe {
            libc::openat(
                vm.as_raw_fd(),
                c"cgroup.kill".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(b"1")
    }

    /// `cgroup.kill` through the proven `vm` descriptor, after re-listing its children
    /// immediately before, then a bounded wait for populated=0. A replacement child
    /// found by that last check is Replaced and nothing is signaled.
    pub fn kill_cgroup_vm(proof: &ProvenCgroupVm, wait: Duration) -> io::Result<NodeState> {
        if !cgroup::populated(&proof.vm)? {
            return Ok(NodeState::Empty);
        }
        match check_vm_subtree(&proof.vm, &proof.identity) {
            Ok(()) => {}
            Err(Unprovable::Replaced(_)) => return Ok(NodeState::Replaced),
            Err(other) => return Err(other.refusal("the vm subtree")),
        }
        write_cgroup_kill(&proof.vm)?;
        let end = std::time::Instant::now() + wait;
        loop {
            if !cgroup::populated(&proof.vm)? {
                return Ok(NodeState::Empty);
            }
            if std::time::Instant::now() >= end {
                return Ok(NodeState::Populated);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The whole journaled tree, proven: this boot, the parent and every present node
    /// with its journaled inode, and no other cgroup anywhere below the parent.
    pub struct ProvenCgroupTree {
        instance: File,
        leaf: CString,
        parent: File,
        vm: Option<File>,
        identity: CgroupIdentity,
    }

    pub fn prove_cgroup_tree(
        relative: &str,
        identity: Option<&CgroupIdentity>,
    ) -> Result<ProvenCgroupTree, Unprovable> {
        let (instance, leaf, parent, identity) = open_recorded_parent(relative, identity)?;
        let mut vm = None;
        for (name, child) in check_children(&parent, "", &["control", "relay", "vm"], identity)? {
            if name == "vm" {
                check_vm_subtree(&child, identity)?;
                vm = Some(child);
            } else if let Some(extra) = child_cgroups(&child)
                .map_err(io_unknown("list cgroup children"))?
                .first()
            {
                return Err(Unprovable::Replaced(format!(
                    "unexpected cgroup {name}/{extra} in the recorded tree"
                )));
            }
        }
        Ok(ProvenCgroupTree {
            instance,
            leaf,
            parent,
            vm,
            identity: identity.clone(),
        })
    }

    /// Removes the proven tree bottom-up once it is unpopulated. Each node's inode is
    /// read again through its parent's descriptor immediately before its `rmdir`; a
    /// change there stops the removal as Replaced.
    pub fn remove_cgroup_tree(proof: ProvenCgroupTree) -> io::Result<NodeState> {
        if cgroup::populated(&proof.parent)? {
            return Ok(NodeState::Populated);
        }
        let check_and_remove = |base: &File, name: &str, path: &str| -> io::Result<bool> {
            let node = match cgroup::open_dir(base, name) {
                Ok(node) => node,
                Err(error) if not_found(&error) => return Ok(true),
                Err(error) => return Err(error),
            };
            if Some(node.metadata()?.ino()) != proof.identity.node_ino(path) {
                return Ok(false);
            }
            drop(node);
            match rmdir_at(base, &cstr(name)?) {
                Ok(()) => Ok(true),
                Err(error) if not_found(&error) => Ok(true),
                Err(error) => Err(error),
            }
        };
        if let Some(vm) = &proof.vm {
            for (name, path) in [("console", "vm/console"), ("vmm", "vm/vmm")] {
                if !check_and_remove(vm, name, path)? {
                    return Ok(NodeState::Replaced);
                }
            }
        }
        for name in ["vm", "relay", "control"] {
            if !check_and_remove(&proof.parent, name, name)? {
                return Ok(NodeState::Replaced);
            }
        }
        let ProvenCgroupTree {
            instance,
            leaf,
            parent,
            vm,
            identity,
        } = proof;
        drop((parent, vm));
        let leaf_name = leaf.to_str().map_err(io::Error::other)?;
        match cgroup::open_dir(&instance, leaf_name) {
            Ok(node) => {
                if node.metadata()?.ino() != identity.parent_ino {
                    return Ok(NodeState::Replaced);
                }
            }
            Err(error) if not_found(&error) => return Ok(NodeState::Absent),
            Err(error) => return Err(error),
        }
        match rmdir_at(&instance, &leaf) {
            Ok(()) => Ok(NodeState::Absent),
            Err(error) if not_found(&error) => Ok(NodeState::Absent),
            Err(error) => Err(error),
        }
    }

    // Files and directories.

    /// A regular file proven to be the journaled generation (device, inode and birth
    /// time), single-link and root-owned, in a directory held by descriptor.
    pub struct ProvenFile {
        dir: File,
        name: CString,
        identity: FileIdentity,
    }

    pub fn prove_file(
        dir: &File,
        name: &str,
        recorded: Option<&FileIdentity>,
    ) -> Result<ProvenFile, Unprovable> {
        let seen = match storage::identity_at(dir, name) {
            Ok(Some(seen)) => seen,
            Ok(None) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("{name}: {error}"))),
        };
        let recorded = recorded.ok_or_else(|| {
            unknown(format!(
                "{name} is present but no generation was journaled: never ours by its name"
            ))
        })?;
        let stat = storage::stat_at(dir, name).map_err(io_unknown(name))?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 || stat.st_uid != 0 {
            return Err(Unprovable::Replaced(format!("{name} is not an owned file")));
        }
        if seen.generation() != recorded.generation() {
            return Err(Unprovable::Replaced(format!(
                "{name} is generation {:?}, not the journaled {:?}",
                seen.generation(),
                recorded.generation()
            )));
        }
        Ok(ProvenFile {
            dir: dir.try_clone().map_err(io_unknown("dup"))?,
            name: cstr(name).map_err(io_unknown("name"))?,
            identity: *recorded,
        })
    }

    /// Unlinks the proven file after reading its generation again immediately before.
    pub fn unlink_file(proof: ProvenFile) -> io::Result<()> {
        let name = proof.name.to_str().map_err(io::Error::other)?;
        match storage::identity_at(&proof.dir, name)? {
            Some(seen) if seen.generation() == proof.identity.generation() => {}
            Some(_) => return Err(io::Error::other(format!("{name} was replaced"))),
            None => return Ok(()),
        }
        // SAFETY: a NUL-terminated name below a live directory descriptor.
        if unsafe { libc::unlinkat(proof.dir.as_raw_fd(), proof.name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A directory proven to be the journaled generation, root-owned and private, held
    /// open (`dir`) so its entries are read and removed through this very inode.
    pub struct ProvenDir {
        parent: File,
        name: CString,
        identity: FileIdentity,
        dir: File,
    }

    impl ProvenDir {
        pub fn dir(&self) -> &File {
            &self.dir
        }
    }

    pub fn prove_dir(
        parent: &File,
        name: &str,
        recorded: Option<&FileIdentity>,
    ) -> Result<ProvenDir, Unprovable> {
        match storage::identity_at(parent, name) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("{name}: {error}"))),
        }
        let recorded = recorded.ok_or_else(|| {
            unknown(format!(
                "{name} is present but no generation was journaled: never ours by its name"
            ))
        })?;
        let dir = match storage::open_dir_at(parent, name) {
            Ok(dir) => dir,
            Err(error) if not_found(&error) => return Err(Unprovable::Gone),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTDIR) | Some(libc::ELOOP)
                ) =>
            {
                return Err(Unprovable::Replaced(format!("{name} is not a directory")));
            }
            Err(error) => return Err(unknown(format!("{name}: {error}"))),
        };
        let seen = storage::file_identity(&dir).map_err(io_unknown(name))?;
        if seen.generation() != recorded.generation() {
            return Err(Unprovable::Replaced(format!(
                "{name} is generation {:?}, not the journaled {:?}",
                seen.generation(),
                recorded.generation()
            )));
        }
        storage::check_private_dir(&dir)
            .map_err(|e| Unprovable::Replaced(format!("{name}: {e}")))?;
        Ok(ProvenDir {
            parent: parent.try_clone().map_err(io_unknown("dup"))?,
            name: cstr(name).map_err(io_unknown("name"))?,
            identity: *recorded,
            dir,
        })
    }

    /// Removes the proven (empty) directory after reading its generation again through
    /// its parent's descriptor immediately before.
    pub fn remove_directory(proof: ProvenDir) -> io::Result<()> {
        let ProvenDir {
            parent,
            name,
            identity,
            dir,
        } = proof;
        drop(dir);
        let text = name.to_str().map_err(io::Error::other)?;
        match storage::identity_at(&parent, text)? {
            Some(seen) if seen.generation() == identity.generation() => {}
            Some(_) => return Err(io::Error::other(format!("{text} was replaced"))),
            None => return Ok(()),
        }
        rmdir_at(&parent, &name)?;
        parent.sync_all()
    }

    // Mounts.

    /// A mount proven to be the journaled one by its unique mount ID (never reused
    /// within a boot) at one name below a directory held by descriptor.
    pub struct ProvenMount {
        parent: File,
        name: CString,
        unique_id: u64,
    }

    pub fn prove_mount(
        parent: &File,
        name: &str,
        recorded_unique: u64,
        recorded_boot: &str,
    ) -> Result<ProvenMount, Unprovable> {
        if !recorded_boot_is_current(recorded_boot)? {
            return Err(Unprovable::Replaced(format!(
                "{name}'s journaled mount belongs to another boot"
            )));
        }
        let seen = match storage::mount_identity_at(parent, name) {
            Ok(seen) => seen,
            Err(error) if not_found(&error) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("{name}: {error}"))),
        };
        if seen.unique_id != recorded_unique {
            return Err(Unprovable::Replaced(format!(
                "{name} mount {} is not the journaled mount {recorded_unique}",
                seen.unique_id
            )));
        }
        Ok(ProvenMount {
            parent: parent.try_clone().map_err(io_unknown("dup"))?,
            name: cstr(name).map_err(io_unknown("name"))?,
            unique_id: recorded_unique,
        })
    }

    /// Unmounts the proven mount, never lazily, resolving the target from the held
    /// parent descriptor and nothing else (B4 recheck 5).
    ///
    /// Linux 6.8 has no unmount-by-descriptor: `umount2` takes a pathname, `open_tree`
    /// without `OPEN_TREE_CLONE` only returns another descriptor of the attached mount,
    /// and `move_mount` cannot detach. So the unmount runs on a short-lived thread that
    /// gives itself a private filesystem context (`unshare(CLONE_FS)`, which changes no
    /// other thread), makes the parent descriptor its working directory (`fchdir`),
    /// reads the unique mount ID at the single-component `name` again, and calls
    /// `umount2(name, UMOUNT_NOFOLLOW)`. Both resolve one component from exactly the
    /// parent's dentry and mount; no `/proc/self/fd` pathname, which a mount in the
    /// helper's namespace could redirect, is involved. The descriptor of that last read
    /// is closed first, because a held one makes a non-lazy unmount busy.
    pub fn unmount(proof: ProvenMount) -> io::Result<()> {
        let name = proof.name.to_str().map_err(io::Error::other)?;
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(io::Error::other("a mount name is one path component"));
        }
        std::thread::scope(|scope| {
            scope
                .spawn(|| -> io::Result<()> {
                    // SAFETY: unshare(CLONE_FS) copies this thread's filesystem context
                    // (root, working directory, umask) for it alone.
                    if unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // SAFETY: a live directory descriptor; only this thread's working
                    // directory changes, and the thread ends with this closure.
                    if unsafe { libc::fchdir(proof.parent.as_raw_fd()) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let seen = storage::mount_identity_at(&proof.parent, name)?;
                    if seen.unique_id != proof.unique_id {
                        return Err(io::Error::other(format!(
                            "{name} changed before its unmount"
                        )));
                    }
                    // SAFETY: a NUL-terminated single component, resolved from this
                    // thread's working directory, the parent; UMOUNT_NOFOLLOW refuses a
                    // link there.
                    if unsafe { libc::umount2(proof.name.as_ptr(), libc::UMOUNT_NOFOLLOW) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                })
                .join()
                .map_err(|_| io::Error::other("the unmount thread panicked"))?
        })
    }

    // Loops.

    /// A loop slot proven to hold exactly the journaled generation (this boot, the full
    /// tuple and the disk sequence number) on the descriptor `LOOP_CLR_FD` is issued on.
    pub struct ProvenLoop {
        device: File,
        generation: LoopGeneration,
    }

    pub fn prove_loop(
        binding: &LoopBinding,
        generation: &LoopGeneration,
    ) -> Result<ProvenLoop, Unprovable> {
        if !recorded_boot_is_current(&generation.boot_id)? {
            return Err(Unprovable::Gone);
        }
        let device = match storage::open_loop(binding.minor, false) {
            Ok(device) => device,
            Err(error) if not_found(&error) => return Err(Unprovable::Gone),
            Err(error) => return Err(unknown(format!("loop{}: {error}", binding.minor))),
        };
        let before = storage::diskseq(&device).map_err(io_unknown("BLKGETDISKSEQ"))?;
        match storage::match_slot(&device, binding).map_err(io_unknown("loop status"))? {
            storage::SlotMatch::Free => return Err(Unprovable::Gone),
            storage::SlotMatch::OtherBacking | storage::SlotMatch::Differs => {
                return Err(Unprovable::Replaced(format!(
                    "loop{} holds another binding",
                    binding.minor
                )));
            }
            storage::SlotMatch::Exact => {}
        }
        if before != generation.diskseq
            || storage::diskseq(&device).map_err(io_unknown("BLKGETDISKSEQ"))? != generation.diskseq
        {
            return Err(Unprovable::Replaced(format!(
                "loop{} is another attachment of the same tuple",
                binding.minor
            )));
        }
        Ok(ProvenLoop {
            device,
            generation: generation.clone(),
        })
    }

    /// Test-only gate between the proof and the final generation check before
    /// `LOOP_CLR_FD`, so a privileged test can replace the binding in that window.
    #[cfg(test)]
    pub(crate) static TEST_DETACH_GATE: std::sync::atomic::AtomicU8 =
        std::sync::atomic::AtomicU8::new(0);

    /// `LOOP_CLR_FD` on the proven descriptor after reading the disk sequence number
    /// once more, immediately before. False (nothing done) if it changed.
    pub fn clear_loop(proof: ProvenLoop) -> io::Result<bool> {
        const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            if TEST_DETACH_GATE
                .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                while TEST_DETACH_GATE.load(Ordering::SeqCst) == 2 {
                    std::thread::yield_now();
                }
            }
        }
        if storage::diskseq(&proof.device)? != proof.generation.diskseq {
            return Ok(false);
        }
        // SAFETY: LOOP_CLR_FD takes no argument.
        if unsafe { libc::ioctl(proof.device.as_raw_fd(), LOOP_CLR_FD, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_ids_round_trip_and_reject_anything_else() {
        let text = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let id = BootId::parse(text).unwrap();
        assert_eq!(id.to_string(), text);
        assert_eq!(serde_json::to_value(id).unwrap(), serde_json::json!(text));
        let back: BootId = serde_json::from_value(serde_json::json!(text)).unwrap();
        assert_eq!(back, id);
        for bad in ["unknown", "", "boot-123", &text.to_uppercase(), &text[1..]] {
            assert!(BootId::parse(bad).is_none(), "{bad}");
        }
        assert!(serde_json::from_value::<BootId>(serde_json::json!("unknown")).is_err());
        assert!(BootId::current().is_ok(), "this host's boot ID is readable");
    }

    /// B4 recheck 3 finding 3, the PoC as a regression: a process stop target with a
    /// missing or mismatching boot ID never signals the process at its PID and start
    /// time. Missing is Unknown (not gone, so the allocation stays charged); another
    /// boot only shows the journaled process is gone.
    #[test]
    fn a_process_target_without_this_boot_is_never_signaled() {
        use super::super::monitor::{StopTarget, execute};
        use super::super::workers::{ProcessState, process_state};
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let ProcessState::Running { start_time } = process_state(pid) else {
            panic!("the child did not start");
        };
        let current = BootId::current().unwrap();
        let mut other = current;
        other.0[0] ^= 0xff;
        let missing = StopTarget::process(ProcessId {
            pid,
            start_time,
            boot_id: None,
        });
        let encoded = serde_json::to_value(&missing).unwrap();
        assert!(encoded["process"].get("boot_id").is_none());
        assert!(!execute(&missing), "no boot ID proves nothing: not gone");
        assert!(matches!(
            prove_process(&missing.process.unwrap()),
            Err(Unprovable::Unknown(_))
        ));
        let mismatched = StopTarget::process(ProcessId {
            pid,
            start_time,
            boot_id: Some(other),
        });
        assert!(execute(&mismatched), "another boot's process is gone");
        // Both left the live process at that PID and start time alone.
        assert_eq!(process_state(pid), ProcessState::Running { start_time });
        assert!(child.try_wait().unwrap().is_none(), "nothing was signaled");
        // This boot's identity is proven and stopped.
        let ours = StopTarget::process(ProcessId {
            pid,
            start_time,
            boot_id: Some(current),
        });
        let encoded = serde_json::to_value(&ours).unwrap();
        assert_eq!(encoded["process"]["boot_id"], current.to_string());
        assert!(execute(&ours));
        assert!(!child.wait().unwrap().success());
        // An exited process is gone whatever its boot ID.
        assert!(process_gone(&ProcessId {
            pid,
            start_time,
            boot_id: None,
        }));
    }

    /// Removes `//` comments and every whitespace character, so an expression matches
    /// however rustfmt wraps it. Needles and allowed expressions go through it too.
    fn squash(text: &str) -> String {
        text.lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .flat_map(|line| line.chars())
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    /// A file's production text: everything before its `#[cfg(test)]` test module.
    fn production_part(text: &str) -> &str {
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let mut offset = 0;
        for (index, line) in lines.iter().enumerate() {
            if line.trim() == "#[cfg(test)]" {
                let next = lines[index + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("//") && !l.starts_with("#["));
                if next.is_some_and(|l| {
                    l.starts_with("mod tests") || l.starts_with("pub(super) mod tests")
                }) {
                    return &text[..offset];
                }
            }
            offset += line.len();
        }
        text
    }

    fn rust_files(root: &std::path::Path, skip_test_files: bool) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if path.is_dir() {
                    if !(skip_test_files && name == "tests") && name != "fixtures" {
                        stack.push(path);
                    }
                } else if name.ends_with(".rs") && !(skip_test_files && name == "tests.rs") {
                    files.push(path);
                }
            }
        }
        files.sort();
        files
    }

    /// Section 7.1's inventory, as defense in depth behind the clippy gate: no helper
    /// source other than this module and `crate::sys` names a destructive capability,
    /// and `crate::sys` names only its two signal-0 probes and its one generation-checked
    /// socket unlink (raw `syscall`, `ioctl`, `prctl`, `ptrace` and mode-0 `fallocate`
    /// are its typed wrappers' business, policed by clippy). Matching is over whole
    /// expressions with comments and whitespace removed, so an allowed expression never
    /// hides another one next to it, and a function taken as a value (an alias) matches
    /// as well as a call. Test fixtures (the `tests` modules and files) are excluded.
    #[test]
    fn no_destructive_call_outside_the_gate() {
        const DESTRUCTIVE: [&str; 36] = [
            "libc::kill",
            "libc::killpg",
            "libc::tgkill",
            "SYS_pidfd_send_signal",
            "SYS_kill",
            "SYS_tgkill",
            "cgroup.kill",
            "AT_REMOVEDIR",
            "libc::rmdir",
            "libc::unlink",
            "unlinkat",
            "fs::remove_dir",
            "fs::remove_file",
            "fs::rename",
            "libc::rename",
            "renameat",
            "umount",
            "libc::unmount",
            "LOOP_CLR_FD",
            "MNT_DETACH",
            ".kill(",
            "start_kill",
            "Command::new",
            "libc::exec",
            "posix_spawn",
            "libc::system",
            "extern\"",
            "asm!",
            "dlsym",
            "set_len",
            ".truncate(true)",
            "File::create(",
            "libc::truncate",
            "libc::ftruncate",
            "process_vm_writev",
            "pidfd_getfd",
        ];
        const RAW: [&str; 5] = [
            "libc::syscall",
            "libc::ioctl",
            "libc::prctl",
            "libc::ptrace",
            "libc::fallocate",
        ];
        // (file, whole expression, justification). Each must occur exactly once.
        const ALLOWED: [(&str, &str, &str); 3] = [
            (
                "sys.rs",
                "libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    0,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )",
                "signal 0 through a pidfd: a liveness probe, not a signal",
            ),
            (
                "sys.rs",
                "libc::kill(pid, 0)",
                "signal 0 on macOS: an existence probe, not a signal",
            ),
            (
                "sys.rs",
                "libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0)",
                "kilnd's own API socket, only while its device, inode and birth time are \
                 the generation it was bound or found as (sys::socket)",
            ),
        ];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files: Vec<_> = rust_files(&src.join("helper"), true);
        files.push(src.join("sys.rs"));
        // Phase 1b B5 moved the child setup's capability and prctl wrappers to the
        // direct-kiln core crate's own typed `sys` module; it is held to the same rule.
        let core_sys =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kilnd-exec-core/src/sys.rs");
        assert!(
            core_sys.is_file(),
            "the core crate's sys module was not found"
        );
        files.push(core_sys);
        assert!(files.len() > 15, "the helper sources were not found");
        let mut offenders = Vec::new();
        let mut allowed_hits = [0; ALLOWED.len()];
        for path in files {
            let relative = path.strip_prefix(&src).map_or_else(
                |_| "kilnd-exec-core/src/sys.rs".to_string(),
                |relative| relative.to_string_lossy().into_owned(),
            );
            if relative == "helper/firecracker/proven.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let mut code = squash(production_part(&text));
            for (index, (file, expression, _)) in ALLOWED.iter().enumerate() {
                if relative == *file {
                    let expression = squash(expression);
                    allowed_hits[index] += code.matches(&expression).count();
                    code = code.replace(&expression, " ");
                }
            }
            let raw_allowed = relative == "sys.rs" || relative == "kilnd-exec-core/src/sys.rs";
            for needle in DESTRUCTIVE
                .iter()
                .chain(RAW.iter().filter(|_| !raw_allowed))
            {
                let needle = squash(needle);
                for (at, _) in code.match_indices(&needle) {
                    let start = code[..at]
                        .char_indices()
                        .rev()
                        .nth(40)
                        .map_or(0, |(i, _)| i);
                    let end = code[at..]
                        .char_indices()
                        .nth(60)
                        .map_or(code.len(), |(i, _)| at + i);
                    offenders.push(format!("{relative}: `{needle}` in …{}…", &code[start..end]));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "destructive or raw calls outside proven.rs:\n{}",
            offenders.join("\n")
        );
        for (index, (file, expression, _)) in ALLOWED.iter().enumerate() {
            assert_eq!(
                allowed_hits[index], 1,
                "the allow-listed {file} `{expression}` must occur exactly once"
            );
        }
    }

    /// B4 recheck 4 finding 2: `clippy::disallowed_methods` is the semantic gate (CI runs
    /// clippy with `-D warnings`). This polices its exceptions: an `allow` or `expect` of
    /// that lint, of `disallowed_types`, or of a group or level that would silence it
    /// (`clippy::style`, `clippy::all`, `warnings`) may appear only on the approved items
    /// below or on a `#[cfg(test)]` test module or test-only file, and each one needs an
    /// `// Approved (design 7.1):` justification immediately above it. No manifest or
    /// cargo config may lower the lint, and `clippy.toml` must still list every capability.
    #[test]
    fn disallowed_allows_only_in_approved_modules() {
        const INNER: &str = "<the whole module>";
        // (crate, file under that crate, item the allow is on, why). Phase 1b B5 moved
        // the subprocess runner, the kiln probe/exec owner and the child setup's
        // capability and prctl wrappers to kilnd-exec-core unchanged, so their allows
        // moved with them; the wrapper subset is that crate's own typed `sys` module.
        const APPROVED: [(&str, &str, &str, &str); 9] = [
            (
                "kilnd",
                "src/helper/firecracker/proven.rs",
                INNER,
                "the destructive-action gate",
            ),
            (
                "kilnd",
                "src/sys.rs",
                INNER,
                "the typed syscall and ioctl wrappers",
            ),
            (
                "kilnd-exec-core",
                "src/sys.rs",
                INNER,
                "the child setup's typed capget/capset and fixed prctl wrappers",
            ),
            (
                "kilnd-exec-core",
                "src/process.rs",
                "pub async fn run(",
                "the fixed-tool subprocess runner",
            ),
            (
                "kilnd-exec-core",
                "src/runtime/kiln_process.rs",
                "pub async fn probe(",
                "the kiln probe",
            ),
            (
                "kilnd-exec-core",
                "src/runtime/kiln_process.rs",
                "pub fn spawn(",
                "kiln exec",
            ),
            (
                "kilnd-exec-core",
                "src/runtime/kiln_process.rs",
                "pub async fn kill_reap(",
                "its own child",
            ),
            (
                "kilnd",
                "src/lock.rs",
                "fn finish_acquire(",
                "truncating this process's own verified lock file",
            ),
            (
                "kilnd-api",
                "build.rs",
                "fn main(",
                "tonic-prost-build writes the gRPC stubs on the build host (B7 milestone 2)",
            ),
        ];
        const SILENCERS: [&str; 5] = [
            "clippy::disallowed_methods",
            "clippy::disallowed_types",
            "clippy::style",
            "clippy::all",
            "warnings",
        ];
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let workspace = crates.join("..");
        let mut hits = [0; APPROVED.len()];
        let mut offenders = Vec::new();
        let mut checked = 0;
        for krate in std::fs::read_dir(&crates).unwrap() {
            let krate = krate.unwrap().path();
            for path in rust_files(&krate, false) {
                let relative = path
                    .strip_prefix(&krate)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let crate_name = krate.file_name().unwrap().to_string_lossy().into_owned();
                let text = std::fs::read_to_string(&path).unwrap();
                let lines: Vec<&str> = text.lines().collect();
                checked += 1;
                let mut index = 0;
                while index < lines.len() {
                    let line = lines[index].trim_start();
                    if !(line.starts_with("#[") || line.starts_with("#![")) {
                        index += 1;
                        continue;
                    }
                    // The whole attribute, across lines, to its matching bracket.
                    let first = index;
                    let mut attribute = String::new();
                    let mut depth = 0i32;
                    loop {
                        for c in lines[index].chars() {
                            attribute.push(c);
                            match c {
                                '[' | '(' => depth += 1,
                                ']' | ')' => depth -= 1,
                                _ => {}
                            }
                        }
                        index += 1;
                        if depth <= 0 || index >= lines.len() {
                            break;
                        }
                    }
                    let squashed = squash(&attribute);
                    let lowers = squashed.contains("allow(") || squashed.contains("expect(");
                    if !lowers || !SILENCERS.iter().any(|s| squashed.contains(s)) {
                        continue;
                    }
                    let place = format!("{crate_name}/{relative}:{}", first + 1);
                    let justified = lines[..first]
                        .iter()
                        .rev()
                        .take_while(|l| l.trim_start().starts_with("//"))
                        .any(|l| l.trim_start().starts_with("// Approved (design 7.1):"));
                    if !justified {
                        offenders.push(format!("{place}: no `// Approved (design 7.1):` comment"));
                    }
                    let inner = line.starts_with("#![");
                    let item = lines[index..]
                        .iter()
                        .map(|l| l.trim())
                        .find(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with("#["))
                        .unwrap_or("");
                    let before: Vec<&str> = lines[..first]
                        .iter()
                        .rev()
                        .map(|l| l.trim())
                        .take_while(|l| l.starts_with("//") || l.starts_with("#["))
                        .collect();
                    // Any item compiled only under cfg(test): a test module, a test-only
                    // fixture module or function.
                    let test_module = !inner && before.contains(&"#[cfg(test)]");
                    let test_file = inner
                        && (relative.starts_with("tests/")
                            || (relative.ends_with("/tests.rs")
                                && declared_for_tests(&krate, &relative)));
                    if let Some(at) = APPROVED.iter().position(|(krate, file, approved, _)| {
                        *krate == crate_name
                            && *file == relative
                            && if inner {
                                *approved == INNER
                            } else {
                                item.starts_with(approved)
                            }
                    }) {
                        hits[at] += 1;
                    } else if !(test_module || test_file) {
                        offenders.push(format!(
                            "{place}: `{}` on `{item}` is not approved",
                            attribute.trim()
                        ));
                    }
                }
            }
        }
        assert!(checked > 40, "the workspace sources were not found");
        assert!(
            offenders.is_empty(),
            "unapproved lint exceptions:\n{}",
            offenders.join("\n")
        );
        for (index, (krate, file, item, _)) in APPROVED.iter().enumerate() {
            assert_eq!(
                hits[index], 1,
                "the approved allow on {krate}/{file} `{item}` must occur exactly once"
            );
        }
        // Nothing outside the sources may lower the lint.
        let mut manifests = vec![workspace.join("Cargo.toml")];
        for krate in std::fs::read_dir(&crates).unwrap() {
            manifests.push(krate.unwrap().path().join("Cargo.toml"));
        }
        for manifest in manifests {
            let text = std::fs::read_to_string(&manifest).unwrap_or_default();
            assert!(
                !text.contains("[lints"),
                "{} has a [lints] table",
                manifest.display()
            );
        }
        for config in [".cargo/config", ".cargo/config.toml"] {
            assert!(
                !workspace.join(config).exists(),
                "{config} could pass lint flags"
            );
        }
        let clippy = std::fs::read_to_string(workspace.join("clippy.toml")).unwrap();
        for path in [
            "libc::kill",
            "libc::killpg",
            "libc::tgkill",
            "libc::pidfd_send_signal",
            "libc::syscall",
            "libc::unlink",
            "libc::unlinkat",
            "libc::rmdir",
            "libc::umount2",
            "libc::rename",
            "libc::renameat",
            "libc::renameat2",
            "libc::ioctl",
            "std::fs::remove_file",
            "std::fs::remove_dir",
            "std::fs::remove_dir_all",
            "std::fs::rename",
            "std::process::Command::new",
            "tokio::process::Command::new",
            "std::process::Child::kill",
            "tokio::process::Child::start_kill",
            "std::fs::File::set_len",
            "std::fs::File::create",
            "std::fs::OpenOptions::truncate",
            "std::fs::write",
            "tokio::fs::File::set_len",
            "tokio::fs::write",
            "libc::truncate",
            "libc::ftruncate",
            "libc::fallocate",
            "libc::prctl",
            "libc::ptrace",
            "libc::process_vm_writev",
            // B7 milestone 2 (MEDIUM-1); the completeness tests hold the rest.
            "std::fs::copy",
            "tokio::fs::copy",
            "libc::creat",
            "libc::popen",
            "libc::execl",
            "libc::sigqueue",
            "libc::mount",
        ] {
            assert!(
                clippy.contains(&format!("path = \"{path}\"")),
                "clippy.toml no longer disallows {path}"
            );
        }
    }

    /// Clippy's gate sees only paths it can resolve. A local `extern` block, inline
    /// assembly or a dynamic symbol lookup would reach a destructive call under another
    /// name, so none may appear anywhere in the workspace, tests included.
    #[test]
    fn no_foreign_declarations_or_inline_assembly() {
        // Squashed forms; the `|` keeps this list from matching itself and is removed.
        const FORBIDDEN: [&str; 9] = [
            "extern|\"C\"{",
            "extern|\"system\"{",
            "extern|{",
            "asm|!(",
            "global_asm|!(",
            "naked_asm|!(",
            "#[link|(",
            "link|_name",
            "dlsym|(",
        ];
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut offenders = Vec::new();
        for krate in std::fs::read_dir(&crates).unwrap() {
            for path in rust_files(&krate.unwrap().path(), false) {
                let code = squash(&std::fs::read_to_string(&path).unwrap());
                for needle in FORBIDDEN {
                    let needle = needle.replace('|', "");
                    if code.contains(&needle) {
                        offenders.push(format!("{}: {needle}", path.display()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "foreign declarations:\n{}",
            offenders.join("\n")
        );
    }

    /// B4 recheck 5 finding 3: generated code is invisible to the source gates, so no
    /// crate may grow a build script beyond the approved list, and no source may
    /// `include!` anything (generated `OUT_DIR` code in particular) other than
    /// `kilnd-api`'s protobuf stubs. A deliberately obfuscated bypass is out of scope
    /// (code review covers malicious source changes); this catches an honest one.
    #[test]
    fn no_unapproved_build_scripts_or_generated_includes() {
        // (crate-relative path, why).
        const BUILD_SCRIPTS: [(&str, &str); 1] = [(
            "kilnd-api/build.rs",
            "tonic-prost-build compiles proto/kilnd/v1 into its out directory",
        )];
        // (crate-relative file, squashed expression, why). Each exactly once.
        const INCLUDES: [(&str, &str, &str); 1] = [(
            "kilnd-api/src/lib.rs",
            "tonic::include_proto|!(\"kilnd.v1\")",
            "the generated gRPC stubs, an API crate with no system calls",
        )];
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut offenders = Vec::new();
        let mut hits = [0; INCLUDES.len()];
        let mut scripts = 0;
        for krate in std::fs::read_dir(&crates).unwrap() {
            let krate = krate.unwrap().path();
            let name = krate.file_name().unwrap().to_string_lossy().into_owned();
            let manifest = std::fs::read_to_string(krate.join("Cargo.toml")).unwrap_or_default();
            if manifest
                .lines()
                .any(|l| l.trim_start().starts_with("build"))
            {
                offenders.push(format!("{name}/Cargo.toml names a build script"));
            }
            for path in rust_files(&krate, false) {
                let relative = format!(
                    "{name}/{}",
                    path.strip_prefix(&krate).unwrap().to_string_lossy()
                );
                if path.file_name().is_some_and(|f| f == "build.rs") {
                    scripts += 1;
                    if !BUILD_SCRIPTS
                        .iter()
                        .any(|(approved, _)| *approved == relative)
                    {
                        offenders.push(format!("{relative}: build script not approved"));
                    }
                    continue;
                }
                let mut code = squash(&std::fs::read_to_string(&path).unwrap());
                for (index, (file, expression, _)) in INCLUDES.iter().enumerate() {
                    let expression = expression.replace('|', "");
                    if *file == relative {
                        hits[index] += code.matches(&expression).count();
                        code = code.replace(&expression, " ");
                    }
                }
                // The `|` keeps these needles from matching this test itself.
                for needle in ["include|!(", "include_proto|!(", "OUT|_DIR"] {
                    let needle = needle.replace('|', "");
                    if code.contains(&needle) {
                        offenders.push(format!("{relative}: `{needle}`"));
                    }
                }
            }
        }
        assert!(scripts >= 1, "the approved build script was not found");
        assert!(
            offenders.is_empty(),
            "unapproved build scripts or generated includes:\n{}",
            offenders.join("\n")
        );
        for (index, (file, expression, _)) in INCLUDES.iter().enumerate() {
            assert_eq!(
                hits[index], 1,
                "{file} `{expression}` must occur exactly once"
            );
        }
    }

    /// The string literals of Rust source, comments excluded: plain, byte, C and raw
    /// strings, with escapes left as written.
    fn string_literals(text: &str) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '/' if chars.get(i + 1) == Some(&'/') => {
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                }
                '/' if chars.get(i + 1) == Some(&'*') => {
                    i += 2;
                    while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                        i += 1;
                    }
                    i += 2;
                }
                '\'' => {
                    if chars.get(i + 1) == Some(&'\\') {
                        i += 2;
                        while i < chars.len() && chars[i] != '\'' {
                            i += 1;
                        }
                        i += 1;
                    } else if chars.get(i + 2) == Some(&'\'') {
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                'r' if !chars
                    .get(i.wrapping_sub(1))
                    .is_some_and(|c| c.is_alphanumeric() || *c == '_')
                    && matches!(chars.get(i + 1), Some('"') | Some('#')) =>
                {
                    let mut j = i + 1;
                    let mut hashes = 0;
                    while chars.get(j) == Some(&'#') {
                        hashes += 1;
                        j += 1;
                    }
                    if chars.get(j) != Some(&'"') {
                        i += 1;
                        continue;
                    }
                    let start = j + 1;
                    let mut k = start;
                    loop {
                        if k >= chars.len() {
                            break;
                        }
                        if chars[k] == '"'
                            && (0..hashes).all(|h| chars.get(k + 1 + h) == Some(&'#'))
                        {
                            break;
                        }
                        k += 1;
                    }
                    out.push(chars[start..k.min(chars.len())].iter().collect());
                    i = k + 1 + hashes;
                }
                '"' => {
                    let start = i + 1;
                    let mut k = start;
                    while k < chars.len() && chars[k] != '"' {
                        if chars[k] == '\\' {
                            k += 1;
                        }
                        k += 1;
                    }
                    out.push(chars[start..k.min(chars.len())].iter().collect());
                    i = k + 1;
                }
                _ => i += 1,
            }
        }
        out
    }

    /// B4 recheck 5: proc and control files are reached only through the approved
    /// modules: `/proc` through `crate::sys::procfs` (a private procfs instance), and
    /// cgroup control files through `cgroup::write_control`'s enum (with
    /// `cgroup.kill` only in this module). Defense in depth: no production string
    /// literal elsewhere in the workspace contains `/proc/` or `cgroup.`, except the
    /// exact justified ones below. Test modules and test files are excluded.
    #[test]
    fn proc_and_control_paths_only_in_approved_modules() {
        const MODULES: [(&str, &str); 3] = [
            (
                "kilnd/src/sys.rs",
                "the private procfs instance and fixed sysfs writes",
            ),
            (
                "kilnd/src/helper/firecracker/cgroup.rs",
                "the ControlFile enum's names and read-only cgroup files",
            ),
            (
                "kilnd/src/helper/firecracker/proven.rs",
                "cgroup.kill behind ProvenCgroupVm",
            ),
        ];
        // (file, literal, why). Each must still occur.
        const LITERALS: [(&str, &str, &str); 6] = [
            (
                "kilnd-guest-broker/src/main.rs",
                "/proc/sys/kernel/random/boot_id",
                "the guest broker reads its own kernel's boot ID for HelloReply; guest-only, \
                 read-only",
            ),
            (
                "kilnd-guest-broker/src/main.rs",
                "/proc/self/mountinfo",
                "the guest broker reads the work disk's mount flags for HelloReply; \
                 guest-only, read-only",
            ),
            (
                "kilnd/src/helper/firecracker/storage.rs",
                "/proc/self/fd/{}",
                "linkat of an unnamed O_TMPFILE inode; the post-link generation recheck \
                 rejects a redirected link (design 7.1)",
            ),
            (
                "kilnd/src/helper/firecracker/executable.rs",
                "/proc/self/fd/{}",
                "linkat of the unnamed executable inode; the post-link device/inode/birth \
                 time recheck rejects a redirected link (design 7.1)",
            ),
            (
                "kilnd-exec-core/src/runtime/kiln_direct.rs",
                "exec/cgroup.events",
                "reads kiln's own exec scope events; never written",
            ),
            (
                "kilnd/src/helper/firecracker/workers.rs",
                "/proc/{pid}/exe",
                "a cfg(test) fixture's image path",
            ),
        ];
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut offenders = Vec::new();
        let mut hits = [0; LITERALS.len()];
        let mut checked = 0;
        for krate in std::fs::read_dir(&crates).unwrap() {
            let krate = krate.unwrap().path();
            let name = krate.file_name().unwrap().to_string_lossy().into_owned();
            let src = krate.join("src");
            if !src.is_dir() {
                continue;
            }
            for path in rust_files(&src, true) {
                let relative = format!(
                    "{name}/src/{}",
                    path.strip_prefix(&src).unwrap().to_string_lossy()
                );
                checked += 1;
                if MODULES.iter().any(|(module, _)| *module == relative) {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for literal in string_literals(production_part(&text)) {
                    if !(literal.contains("/proc/") || literal.contains("cgroup.")) {
                        continue;
                    }
                    match LITERALS
                        .iter()
                        .position(|(file, allowed, _)| *file == relative && *allowed == literal)
                    {
                        Some(at) => hits[at] += 1,
                        None => offenders.push(format!("{relative}: {literal:?}")),
                    }
                }
            }
        }
        assert!(checked > 40, "the workspace sources were not found");
        assert!(
            offenders.is_empty(),
            "proc or control-file paths outside the approved modules:\n{}",
            offenders.join("\n")
        );
        for (index, (file, literal, _)) in LITERALS.iter().enumerate() {
            assert!(
                hits[index] >= 1,
                "{file} no longer has {literal:?}: drop it here"
            );
        }
    }

    #[test]
    fn the_literal_scanner_sees_strings_not_comments() {
        let text = "// \"/proc/a\"\nlet a = \"/proc/b\"; let c = '\"'; let d = r#\"x\"y\"#;\n/* \"cgroup.z\" */ let e = c\"cgroup.w\"; fn f<'a>(_: &'a str) {}";
        assert_eq!(string_literals(text), ["/proc/b", "x\"y", "cgroup.w"]);
    }

    /// Whether `relative` (a `.../tests.rs`) is declared `#[cfg(test)] mod tests;` by its
    /// parent module, so it compiles only for tests.
    fn declared_for_tests(krate: &std::path::Path, relative: &str) -> bool {
        let directory = std::path::Path::new(relative).parent().unwrap();
        let candidates = [
            krate.join(directory).join("mod.rs"),
            krate.join(directory.with_extension("rs")),
        ];
        candidates.iter().any(|parent| {
            std::fs::read_to_string(parent).is_ok_and(|text| {
                let lines: Vec<&str> = text.lines().map(str::trim).collect();
                lines.windows(2).any(|pair| {
                    pair[0] == "#[cfg(test)]"
                        && (pair[1] == "mod tests;" || pair[1].ends_with(" mod tests;"))
                })
            })
        })
    }

    /// Design section 7.1's dependency gate and the destructive-list completeness tests
    /// (B7 milestone 2: HIGH-1, MEDIUM-1, LOW-1).
    mod dependency_gate;
}
