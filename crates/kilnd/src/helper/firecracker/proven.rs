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
//! | `cgroup.kill` | [`ProvenCgroupVm`] | the `vm` node's descriptor, its children re-listed immediately before |
//! | cgroup `rmdir` | [`ProvenCgroupTree`] | each parent's descriptor, the child's inode re-read immediately before |
//! | `unlinkat` | [`ProvenFile`] | the verified directory's descriptor, the birth time re-read immediately before |
//! | directory `rmdir` | [`ProvenDir`] | the parent's descriptor, the birth time re-read immediately before |
//! | `umount2` | [`ProvenMount`] | `/proc/self/fd/<parent>/<name>`, the unique mount ID re-read immediately before |
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

/// The kernel's boot ID, `/proc/sys/kernel/random/boot_id` (on macOS, where only the
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

    /// This boot's ID. Unreadable or malformed is an error, never a placeholder.
    #[cfg(target_os = "linux")]
    pub fn current() -> io::Result<Self> {
        let text = std::fs::read_to_string(super::storage::BOOT_ID_PATH)?;
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
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // Cgroups.

    /// Subdirectory names of a cgroup node: its child cgroups.
    fn child_cgroups(node: &File) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", node.as_raw_fd()))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                names.push(entry.file_name().to_string_lossy().into_owned());
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
            let child = match cgroup::open_at(node, &name, true) {
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
        let parent = match cgroup::open_at(&instance, leaf, true) {
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
        Ok((instance, cstr(leaf).map_err(io_unknown("name"))?, parent, identity))
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
        let vm = match cgroup::open_at(&parent, "vm", true) {
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
        cgroup::write_control(&proof.vm, "cgroup.kill", "1")?;
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
            let node = match cgroup::open_at(base, name, true) {
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
        match cgroup::open_at(&instance, leaf_name, true) {
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
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 || stat.st_uid != 0
        {
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
                if matches!(error.raw_os_error(), Some(libc::ENOTDIR) | Some(libc::ELOOP)) =>
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

    /// Unmounts the proven mount, never lazily. Its unique ID is read again on a fresh
    /// descriptor immediately before; that descriptor is closed first, because a held
    /// one makes a non-lazy unmount busy. The target is resolved through the held
    /// parent descriptor, not a path from the root.
    pub fn unmount(proof: ProvenMount) -> io::Result<()> {
        let name = proof.name.to_str().map_err(io::Error::other)?;
        let seen = storage::mount_identity_at(&proof.parent, name)?;
        if seen.unique_id != proof.unique_id {
            return Err(io::Error::other(format!(
                "{name} changed before its unmount"
            )));
        }
        let target = cstr(&format!(
            "/proc/self/fd/{}/{name}",
            proof.parent.as_raw_fd()
        ))?;
        // SAFETY: NUL-terminated; UMOUNT_NOFOLLOW refuses a link at the last component.
        if unsafe { libc::umount2(target.as_ptr(), libc::UMOUNT_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
            || storage::diskseq(&device).map_err(io_unknown("BLKGETDISKSEQ"))?
                != generation.diskseq
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

    /// Section 7.1's inventory, enforced: no helper source other than this module makes
    /// a destructive system call, apart from the justified allow-list below. Test
    /// fixtures (the `tests` modules and files) are excluded.
    #[test]
    fn no_destructive_call_outside_the_gate() {
        const NEEDLES: [&str; 18] = [
            "libc::kill(",
            "libc::killpg(",
            "libc::tgkill(",
            "SYS_pidfd_send_signal",
            "SYS_kill",
            "SYS_tgkill",
            "cgroup.kill",
            "AT_REMOVEDIR",
            "libc::rmdir(",
            "libc::unlink(",
            "unlinkat(",
            "remove_dir(",
            "remove_dir_all(",
            "remove_file(",
            "umount",
            "LOOP_CLR_FD",
            ".kill()",
            "MNT_DETACH",
        ];
        // (file, line fragment, justification). Each must match exactly one line.
        const ALLOWED: [(&str, &str, &str); 3] = [
            (
                "firecracker/executable.rs",
                "libc::unlinkat(directory.file().as_raw_fd(), temporary.as_ptr(), 0)",
                "the helper's own temporary copy name in the root-only executable store, \
                 created O_EXCL by the same function: never tenant-reachable or replaced",
            ),
            (
                "firecracker/peer.rs",
                "libc::SYS_pidfd_send_signal,",
                "signal 0 through a pidfd: a liveness probe, not a signal",
            ),
            (
                "firecracker/workers.rs",
                "libc::kill(pid, 0)",
                "signal 0 on macOS: an existence probe, not a signal",
            ),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/helper");
        let mut files = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|n| n != "tests") {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|e| e == "rs")
                    && path.file_name().is_some_and(|n| n != "tests.rs")
                {
                    files.push(path);
                }
            }
        }
        assert!(files.len() > 15, "the helper sources were not found");
        let mut offenders = Vec::new();
        let mut allowed_hits = vec![0; ALLOWED.len()];
        for path in files {
            let relative = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if relative == "firecracker/proven.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // A file's unit tests are fixtures: everything from its test module on.
            let production = match text.find("#[cfg(test)]\nmod tests") {
                Some(at) => &text[..at],
                None => &text[..],
            };
            for (number, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if !NEEDLES.iter().any(|needle| code.contains(needle)) {
                    continue;
                }
                match ALLOWED
                    .iter()
                    .position(|(file, fragment, _)| relative == *file && code.contains(fragment))
                {
                    Some(index) => allowed_hits[index] += 1,
                    None => offenders.push(format!("{relative}:{}: {}", number + 1, line.trim())),
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "destructive calls outside proven.rs:\n{}",
            offenders.join("\n")
        );
        for (index, (file, fragment, _)) in ALLOWED.iter().enumerate() {
            assert_eq!(
                allowed_hits[index], 1,
                "the allow-listed {file} `{fragment}` must match exactly one line"
            );
        }
    }
}
