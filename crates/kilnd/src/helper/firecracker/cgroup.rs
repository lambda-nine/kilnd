//! Section 6.2's allocation cgroup tree. Every path is derived from the plan's typed
//! names below one opened cgroup2 root and walked by descriptor without following
//! links. Limits come from the plan's expanded contract recipe and only from a fixed
//! set of control files: no request supplies a cgroup key or value.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

/// The cgroup2 mount the contract's relative paths start from.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The node-wide subtree, the first component of every allocation path.
pub const FIRECRACKER_TREE: &str = "kilnd-firecracker";
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
/// Leaves and internal nodes below an allocation parent, parents before children.
pub const NODES: [&str; 5] = ["control", "relay", "vm", "vm/vmm", "vm/console"];
/// Control files a recipe may set, in the order they are written.
const LIMIT_FILES: [&str; 5] = [
    "memory.max",
    "memory.swap.max",
    "memory.oom.group",
    "pids.max",
    "cpu.max",
];

/// The inode numbers of a created tree and the boot it was created in. Kill and
/// removal compare against these before acting, so a replaced directory is refused
/// rather than signaled or removed. cgroupfs (kernfs) inode numbers are never reused
/// within a boot but start again at each boot, so a tree recorded in another boot is
/// gone by definition and anything at its path now is a replacement (section 7.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupIdentity {
    pub boot_id: String,
    pub parent_ino: u64,
    pub control_ino: u64,
    pub relay_ino: u64,
    pub vm_ino: u64,
    pub vmm_ino: u64,
    pub console_ino: u64,
}

impl CgroupIdentity {
    /// The recorded inode of one of [`NODES`].
    pub fn node_ino(&self, node: &str) -> Option<u64> {
        match node {
            "control" => Some(self.control_ino),
            "relay" => Some(self.relay_ino),
            "vm" => Some(self.vm_ino),
            "vm/vmm" => Some(self.vmm_ino),
            "vm/console" => Some(self.console_ino),
            _ => None,
        }
    }
}

/// A stop target's cgroup: the allocation's tree and whatever generation the journal
/// holds for it. The kill is proven against the whole `vm` subtree, never one inode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupStopTarget {
    /// The allocation parent, relative to the cgroup2 root:
    /// `kilnd-firecracker/<I>/fc-<H>`.
    pub relative: String,
    /// The journaled generation, absent while only an intent is journaled: a tree at the
    /// path is then Unknown, never signaled.
    pub identity: Option<CgroupIdentity>,
}

/// Checks a relative path names a node in this subtree: plain components only.
pub fn valid_relative(path: &str) -> bool {
    path.starts_with(FIRECRACKER_TREE)
        && path.len() < 256
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.into())
}

/// Opens the cgroup2 root and checks its filesystem type.
#[cfg(target_os = "linux")]
fn open_root() -> io::Result<File> {
    let root = File::open(CGROUP_ROOT)?;
    // SAFETY: statfs writes into the zeroed structure.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)]
    if stat.f_type as i64 != CGROUP2_SUPER_MAGIC {
        return Err(io::Error::other("the cgroup root is not cgroup2"));
    }
    Ok(root)
}

#[cfg(target_os = "linux")]
pub(super) fn open_at(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    let name = std::ffi::CString::new(name).map_err(|_| invalid("cgroup name"))?;
    let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW;
    flags |= if directory {
        libc::O_DIRECTORY | libc::O_RDONLY
    } else {
        libc::O_RDWR
    };
    // SAFETY: name is NUL-terminated and the parent is a live directory.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Walks a relative path from the root without following links.
#[cfg(target_os = "linux")]
pub fn open_node(relative: &str) -> io::Result<File> {
    if !valid_relative(relative) {
        return Err(invalid("cgroup path outside the Firecracker subtree"));
    }
    let mut current = open_root()?;
    for component in relative.split('/') {
        current = open_at(&current, component, true)?;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn mkdir_at(parent: &File, name: &str) -> io::Result<bool> {
    let c = std::ffi::CString::new(name).map_err(|_| invalid("cgroup name"))?;
    // SAFETY: c is NUL-terminated; the parent is a live directory.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o755) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        return Ok(false);
    }
    Err(error)
}

#[cfg(target_os = "linux")]
pub(super) fn write_control(node: &File, name: &str, value: &str) -> io::Result<()> {
    use std::io::Write;
    let mut file = open_at(node, name, false)?;
    file.write_all(value.as_bytes())
}

#[cfg(target_os = "linux")]
fn read_control(node: &File, name: &str) -> io::Result<String> {
    use std::io::Read;
    let c = std::ffi::CString::new(name).map_err(|_| invalid("cgroup name"))?;
    // SAFETY: c is NUL-terminated; the parent is a live directory.
    let fd = unsafe {
        libc::openat(
            node.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut text = String::new();
    file.by_ref().take(64 * 1024).read_to_string(&mut text)?;
    Ok(text)
}

/// Enables the three controllers for a node's children, and requires them present.
#[cfg(target_os = "linux")]
fn delegate_controllers(node: &File, controllers: &[String]) -> io::Result<()> {
    let enabled = read_control(node, "cgroup.subtree_control")?;
    let missing: Vec<_> = controllers
        .iter()
        .filter(|c| !enabled.split_whitespace().any(|e| e == c.as_str()))
        .collect();
    if !missing.is_empty() {
        let value = missing
            .iter()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        write_control(node, "cgroup.subtree_control", &value)?;
    }
    let enabled = read_control(node, "cgroup.subtree_control")?;
    for controller in controllers {
        if !enabled.split_whitespace().any(|e| e == controller) {
            return Err(io::Error::other(format!(
                "controller {controller} could not be delegated"
            )));
        }
    }
    Ok(())
}

fn controllers(recipe: &Value) -> io::Result<Vec<String>> {
    let list = recipe["controllers"]
        .as_array()
        .ok_or_else(|| invalid("recipe controllers"))?;
    let mut names = Vec::new();
    for value in list {
        let name = value.as_str().ok_or_else(|| invalid("controller name"))?;
        if !["memory", "pids", "cpu"].contains(&name) {
            return Err(invalid(format!(
                "controller {name} is outside the contract"
            )));
        }
        names.push(name.to_string());
    }
    if names.len() != 3 {
        return Err(invalid("recipe must name memory, pids and cpu"));
    }
    Ok(names)
}

/// The fixed (file, value) pairs one recipe node sets, refusing any other key.
fn limits(node: &Value) -> io::Result<Vec<(&'static str, String)>> {
    let object = node.as_object().ok_or_else(|| invalid("recipe node"))?;
    for key in object.keys() {
        if !LIMIT_FILES.contains(&key.as_str())
            && !["inherit", "direct_tasks"].contains(&key.as_str())
        {
            return Err(invalid(format!("cgroup key {key} is outside the contract")));
        }
    }
    let mut out = Vec::new();
    for file in LIMIT_FILES {
        if let Some(value) = object.get(file) {
            let text = match value {
                Value::Number(n) => n.to_string(),
                Value::String(s)
                    if s.len() < 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || b == b' ' || b == b'x') =>
                {
                    s.clone()
                }
                _ => return Err(invalid(format!("cgroup value for {file}"))),
            };
            out.push((file, text));
        }
    }
    Ok(out)
}

/// Creates `<relative>` and its fixed children with the recipe's limits. The parent is
/// new: an existing directory is a conflict, never adopted. Returns the inodes.
#[cfg(target_os = "linux")]
pub fn create_tree(relative: &str, recipe: &Value) -> io::Result<CgroupIdentity> {
    if !valid_relative(relative) {
        return Err(invalid("cgroup path outside the Firecracker subtree"));
    }
    let wanted = controllers(recipe)?;
    let components: Vec<&str> = relative.split('/').collect();
    let mut node = open_root()?;
    delegate_controllers(&node, &wanted)?;
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let created = mkdir_at(&node, component)?;
        if last && !created {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "allocation cgroup already exists",
            ));
        }
        node = open_at(&node, component, true)?;
        delegate_controllers(&node, &wanted)?;
    }
    let parent = node;
    for (file, value) in limits(&recipe["allocation"])? {
        write_control(&parent, file, &value)?;
    }
    let mut inodes = std::collections::HashMap::new();
    for name in NODES {
        let (base, leaf) = match name.rsplit_once('/') {
            Some((base, leaf)) => (open_at(&parent, base, true)?, leaf),
            None => (parent.try_clone()?, name),
        };
        if !mkdir_at(&base, leaf)? {
            return Err(io::Error::other(format!("cgroup {name} already exists")));
        }
        let child = open_at(&base, leaf, true)?;
        if name == "vm" {
            delegate_controllers(&child, &wanted)?;
        }
        if let Some(node) = recipe.get(name) {
            for (file, value) in limits(node)? {
                write_control(&child, file, &value)?;
            }
        }
        inodes.insert(name, child.metadata()?.ino());
    }
    Ok(CgroupIdentity {
        boot_id: super::storage::boot_id()?,
        parent_ino: parent.metadata()?.ino(),
        control_ino: inodes["control"],
        relay_ino: inodes["relay"],
        vm_ino: inodes["vm"],
        vmm_ino: inodes["vm/vmm"],
        console_ino: inodes["vm/console"],
    })
}

/// Moves the calling process into a leaf and proves the kernel agrees.
#[cfg(target_os = "linux")]
pub fn join(relative_leaf: &str, expected_ino: u64) -> io::Result<()> {
    let node = open_node(relative_leaf)?;
    if node.metadata()?.ino() != expected_ino {
        return Err(io::Error::other("cgroup leaf was replaced"));
    }
    // "0" names the writer itself.
    write_control(&node, "cgroup.procs", "0")?;
    let own = std::fs::read_to_string("/proc/self/cgroup")?;
    let expected = format!("0::/{relative_leaf}");
    if own.lines().next() != Some(expected.as_str()) {
        return Err(io::Error::other("the kernel placed this process elsewhere"));
    }
    Ok(())
}

/// Whether a node or any descendant holds a live task.
#[cfg(target_os = "linux")]
pub fn populated(node: &File) -> io::Result<bool> {
    let events = read_control(node, "cgroup.events")?;
    for line in events.lines() {
        if let Some(value) = line.strip_prefix("populated ") {
            return Ok(value.trim() != "0");
        }
    }
    Err(io::Error::other("cgroup.events has no populated line"))
}

/// The process IDs directly in one node.
#[cfg(target_os = "linux")]
pub fn procs(node: &File) -> io::Result<Vec<i32>> {
    read_control(node, "cgroup.procs")?
        .lines()
        .map(|line| line.trim().parse::<i32>().map_err(io::Error::other))
        .collect()
}

/// What a kill or removal found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// The node does not exist: nothing in it can run.
    Absent,
    /// The node exists and is unpopulated.
    Empty,
    /// The node still holds a task after the bounded wait.
    Populated,
    /// The tree at that path, or a node or child in it, is not the journaled one (another
    /// inode, an unexpected child, or a record from another boot with something at its
    /// path): nothing was signaled or removed.
    Replaced,
    /// Something is at the path but no generation was journaled for it (an intent alone,
    /// or no record), or its identity could not be read: nothing was signaled or
    /// removed, and it is never ours by its deterministic name.
    Unknown,
}

#[cfg(target_os = "linux")]
fn unproven_state(refusal: super::proven::Unprovable) -> NodeState {
    use super::proven::Unprovable;
    match refusal {
        Unprovable::Gone => NodeState::Absent,
        Unprovable::Replaced(_) => NodeState::Replaced,
        Unprovable::Unknown(_) => NodeState::Unknown,
    }
}

/// `cgroup.kill` on an allocation's `vm` subtree, only through a [`ProvenCgroupVm`]:
/// this boot, the parent, `vm`, `vm/vmm` and `vm/console` all the journaled inodes and
/// no other cgroup below `vm`, checked before the kill. A replaced child is Replaced
/// with no signal; a tree at the path with no journaled generation is Unknown.
///
/// [`ProvenCgroupVm`]: super::proven::ProvenCgroupVm
#[cfg(target_os = "linux")]
pub fn kill_recorded(
    relative: &str,
    identity: Option<&CgroupIdentity>,
    wait: Duration,
) -> io::Result<NodeState> {
    match super::proven::prove_cgroup_vm(relative, identity) {
        Ok(proof) => super::proven::kill_cgroup_vm(&proof, wait),
        Err(refusal) => Ok(unproven_state(refusal)),
    }
}

/// Whether the journaled `vm` subtree is provably empty: absent, or proven and
/// unpopulated. A replaced or unrecorded subtree is not.
#[cfg(target_os = "linux")]
pub fn vm_empty(relative: &str, identity: Option<&CgroupIdentity>) -> bool {
    use super::proven::Unprovable;
    match super::proven::prove_cgroup_vm(relative, identity) {
        Ok(proof) => super::proven::vm_populated(&proof).is_ok_and(|p| !p),
        Err(Unprovable::Gone) => true,
        Err(_) => false,
    }
}

/// Removes an allocation's tree bottom-up, only through a [`ProvenCgroupTree`]: this
/// boot, the parent and every present node the journaled inodes, and no other cgroup
/// anywhere below. Nothing at the path is Absent. Something there with no journaled
/// generation is Unknown and stays; a replacement is Replaced and stays.
///
/// [`ProvenCgroupTree`]: super::proven::ProvenCgroupTree
#[cfg(target_os = "linux")]
pub fn remove_tree(relative: &str, identity: Option<&CgroupIdentity>) -> io::Result<NodeState> {
    if !valid_relative(relative) {
        return Err(invalid("cgroup path outside the Firecracker subtree"));
    }
    match super::proven::prove_cgroup_tree(relative, identity) {
        Ok(proof) => super::proven::remove_cgroup_tree(proof),
        Err(refusal) => Ok(unproven_state(refusal)),
    }
}

/// Whether the allocation's parent exists.
#[cfg(target_os = "linux")]
pub fn exists(relative: &str) -> io::Result<bool> {
    match open_node(relative) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Every allocation directory below one instance's node, for inventory.
#[cfg(target_os = "linux")]
pub fn allocation_names(instance_relative: &str) -> io::Result<Vec<String>> {
    let node = match open_node(instance_relative) {
        Ok(node) => node,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(error) => return Err(error),
    };
    let path = format!("/proc/self/fd/{}", node.as_raw_fd());
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        if names.len() > 4096 {
            return Err(io::Error::other("too many cgroup entries"));
        }
    }
    Ok(names)
}

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use super::*;
    fn no() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "cgroups need Linux")
    }
    pub fn open_node(_: &str) -> io::Result<File> {
        Err(no())
    }
    pub fn create_tree(_: &str, _: &Value) -> io::Result<CgroupIdentity> {
        Err(no())
    }
    pub fn join(_: &str, _: u64) -> io::Result<()> {
        Err(no())
    }
    pub fn populated(_: &File) -> io::Result<bool> {
        Err(no())
    }
    pub fn procs(_: &File) -> io::Result<Vec<i32>> {
        Err(no())
    }
    pub fn remove_tree(_: &str, _: Option<&CgroupIdentity>) -> io::Result<NodeState> {
        Err(no())
    }
    pub fn kill_recorded(
        _: &str,
        _: Option<&CgroupIdentity>,
        _: Duration,
    ) -> io::Result<NodeState> {
        Err(no())
    }
    pub fn vm_empty(_: &str, _: Option<&CgroupIdentity>) -> bool {
        false
    }
    pub fn exists(_: &str) -> io::Result<bool> {
        Err(no())
    }
    pub fn allocation_names(_: &str) -> io::Result<Vec<String>> {
        Err(no())
    }
}
#[cfg(not(target_os = "linux"))]
pub use unsupported::*;

/// An inode from a node's metadata, for callers that only hold a `File`.
pub fn inode(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn relative_paths_stay_inside_the_subtree() {
        assert!(valid_relative("kilnd-firecracker/abc/fc-0123/vm"));
        for bad in [
            "",
            "/kilnd-firecracker",
            "kilnd-firecracker/../x",
            "kilnd-firecracker//vm",
            "kilnd-firecracker/a b",
            "system.slice/kilnd.service",
            "kilnd-firecracker/x/./y",
        ] {
            assert!(!valid_relative(bad), "{bad}");
        }
    }

    #[test]
    fn recipe_limits_accept_only_the_fixed_control_files() {
        let node =
            json!({"memory.max": 939524096, "cpu.max": "100000 100000", "direct_tasks": false});
        assert_eq!(
            limits(&node).unwrap(),
            vec![
                ("memory.max", "939524096".to_string()),
                ("cpu.max", "100000 100000".to_string())
            ]
        );
        assert!(limits(&json!({"cgroup.procs": "1"})).is_err());
        assert!(limits(&json!({"cpu.max": "1;rm"})).is_err());
        assert!(controllers(&json!({"controllers": ["memory", "pids", "cpu"]})).is_ok());
        assert!(controllers(&json!({"controllers": ["memory", "pids", "io"]})).is_err());
    }

    /// B4 recheck 2 sweep: a recorded tree is removed only while it and every recorded
    /// node are the journaled inodes of this boot. A replaced child, or a tree at the
    /// path again after a reboot (a record from another boot), is Replaced: nothing is
    /// signaled or removed, and the replacement survives.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and a cgroup2 root: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_cgroup_cleanup_refuses_replaced_nodes_and_other_boots() {
        let instance = format!("{FIRECRACKER_TREE}/b4-sweep-{}", std::process::id());
        let relative = format!("{instance}/fc-sweep");
        let base = std::path::Path::new(CGROUP_ROOT).join(&relative);
        let make = || {
            std::fs::create_dir_all(base.join("vm/vmm")).unwrap();
            for name in NODES {
                std::fs::create_dir_all(base.join(name)).unwrap();
            }
            let ino = |name: &str| std::fs::metadata(base.join(name)).unwrap().ino();
            CgroupIdentity {
                boot_id: super::super::storage::boot_id().unwrap(),
                parent_ino: std::fs::metadata(&base).unwrap().ino(),
                control_ino: ino("control"),
                relay_ino: ino("relay"),
                vm_ino: ino("vm"),
                vmm_ino: ino("vm/vmm"),
                console_ino: ino("vm/console"),
            }
        };
        let identity = make();
        // A replaced child: root removed the empty relay leaf and made another.
        std::fs::remove_dir(base.join("relay")).unwrap();
        std::fs::create_dir(base.join("relay")).unwrap();
        let replaced_child = remove_tree(&relative, Some(&identity));
        let child_survived = base.join("relay").exists();
        // The whole tree, recorded in another boot and present again at the path.
        std::fs::remove_dir(base.join("relay")).unwrap();
        let identity = make();
        let earlier = CgroupIdentity {
            boot_id: "00000000-0000-4000-8000-000000000000".into(),
            ..identity.clone()
        };
        let other_boot_kill = kill_recorded(&relative, Some(&earlier), Duration::from_millis(100));
        let other_boot_remove = remove_tree(&relative, Some(&earlier));
        let tree_survived = base.join("vm/vmm").exists();
        // The journaled tree itself is killed and removed.
        let own_kill = kill_recorded(&relative, Some(&identity), Duration::from_millis(500));
        let own_remove = remove_tree(&relative, Some(&identity));
        let gone = !base.exists();
        if !gone {
            for name in NODES.iter().rev() {
                let _ = std::fs::remove_dir(base.join(name));
            }
            let _ = std::fs::remove_dir(&base);
        }
        let _ = std::fs::remove_dir(std::path::Path::new(CGROUP_ROOT).join(&instance));

        assert_eq!(replaced_child.unwrap(), NodeState::Replaced);
        assert!(child_survived, "the replaced child was removed");
        assert_eq!(other_boot_kill.unwrap(), NodeState::Replaced);
        assert_eq!(other_boot_remove.unwrap(), NodeState::Replaced);
        assert!(tree_survived, "another boot's record removed the tree");
        assert_eq!(own_kill.unwrap(), NodeState::Empty);
        assert_eq!(own_remove.unwrap(), NodeState::Absent);
        assert!(gone, "the journaled tree remains");
        eprintln!(
            "B4 evidence: a replaced cgroup child and another boot's record were refused \
             and left in place; the journaled tree was removed"
        );
    }

    /// A scratch allocation tree like `create_tree`'s, with its journaled identity.
    #[cfg(target_os = "linux")]
    fn scratch_tree(relative: &str) -> CgroupIdentity {
        let base = std::path::Path::new(CGROUP_ROOT).join(relative);
        std::fs::create_dir_all(base.join("vm/vmm")).unwrap();
        for name in NODES {
            std::fs::create_dir_all(base.join(name)).unwrap();
        }
        let ino = |name: &str| std::fs::metadata(base.join(name)).unwrap().ino();
        CgroupIdentity {
            boot_id: super::super::storage::boot_id().unwrap(),
            parent_ino: std::fs::metadata(&base).unwrap().ino(),
            control_ino: ino("control"),
            relay_ino: ino("relay"),
            vm_ino: ino("vm"),
            vmm_ino: ino("vm/vmm"),
            console_ino: ino("vm/console"),
        }
    }

    #[cfg(target_os = "linux")]
    fn scrub_tree(relative: &str, extra: &[&str]) {
        let base = std::path::Path::new(CGROUP_ROOT).join(relative);
        for name in extra.iter().chain(NODES.iter().rev()) {
            let _ = std::fs::remove_dir(base.join(name));
        }
        let _ = std::fs::remove_dir(&base);
        let _ = std::fs::remove_dir(base.parent().unwrap());
    }

    #[cfg(target_os = "linux")]
    fn sleeper_in(node: &std::path::Path) -> std::process::Child {
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(node.join("cgroup.procs"), child.id().to_string()).unwrap();
        child
    }

    /// B4 recheck 3 finding 1, the PoC as a regression: root replaced the journaled
    /// `vm/vmm` leaf (or added a child below `vm`) and put an unrelated process in it.
    /// The `vm` parent is still the journaled inode, but `cgroup.kill` on it would kill
    /// that process, so the proof covers every child: the kill is Replaced with no
    /// signal, removal is Replaced, and the replacement and its process survive.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and a cgroup2 root: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_a_replaced_vm_child_is_never_killed() {
        let instance = format!("{FIRECRACKER_TREE}/b4-recheck3-{}", std::process::id());
        let relative = format!("{instance}/fc-child-kill");
        let base = std::path::Path::new(CGROUP_ROOT).join(&relative);
        let identity = scratch_tree(&relative);
        let journaled_vmm = identity.vmm_ino;
        std::fs::remove_dir(base.join("vm/vmm")).unwrap();
        std::fs::create_dir(base.join("vm/vmm")).unwrap();
        let replacement_ino = std::fs::metadata(base.join("vm/vmm")).unwrap().ino();
        let mut foreign = sleeper_in(&base.join("vm/vmm"));
        let replaced_kill = kill_recorded(&relative, Some(&identity), Duration::from_secs(1));
        let replaced_remove = remove_tree(&relative, Some(&identity));
        let replaced_survived = foreign.try_wait().unwrap().is_none() && base.join("vm/vmm").exists();
        let _ = foreign.kill();
        let _ = foreign.wait();
        // An extra child below the journaled vm node, with our own vmm intact.
        std::fs::remove_dir(base.join("vm/vmm")).unwrap();
        std::fs::create_dir(base.join("vm/vmm")).unwrap();
        let identity = CgroupIdentity {
            vmm_ino: std::fs::metadata(base.join("vm/vmm")).unwrap().ino(),
            ..identity
        };
        std::fs::create_dir(base.join("vm/extra")).unwrap();
        let mut stranger = sleeper_in(&base.join("vm/extra"));
        let extra_kill = kill_recorded(&relative, Some(&identity), Duration::from_secs(1));
        let extra_empty = vm_empty(&relative, Some(&identity));
        let extra_survived = stranger.try_wait().unwrap().is_none();
        let _ = stranger.kill();
        let _ = stranger.wait();
        std::fs::remove_dir(base.join("vm/extra")).unwrap();
        // The journaled tree itself, with a process of its own: killed and removed.
        let mut own = sleeper_in(&base.join("vm/vmm"));
        let own_kill = kill_recorded(&relative, Some(&identity), Duration::from_secs(2));
        let own_status = own.wait().unwrap();
        let own_remove = remove_tree(&relative, Some(&identity));
        let gone = !base.exists();
        scrub_tree(&relative, &["vm/extra"]);

        assert_eq!(replaced_kill.unwrap(), NodeState::Replaced);
        assert_eq!(replaced_remove.unwrap(), NodeState::Replaced);
        assert!(replaced_survived, "the replaced child or its process was touched");
        assert_eq!(extra_kill.unwrap(), NodeState::Replaced);
        assert!(!extra_empty, "a subtree with a foreign child is not proven empty");
        assert!(extra_survived, "a process in an unexpected child was killed");
        assert_eq!(own_kill.unwrap(), NodeState::Empty);
        assert!(!own_status.success());
        assert_eq!(own_remove.unwrap(), NodeState::Absent);
        assert!(gone);
        eprintln!(
            "B4 evidence: vm/vmm inode {replacement_ino} replaced journaled {journaled_vmm} and an \
             unexpected vm/extra were Replaced with no cgroup.kill; their processes \
             survived; the journaled tree was killed and removed",
        );
    }

    /// B4 recheck 3 finding 2, the cgroup PoC as a regression: a tree at the
    /// allocation's path with no journaled generation (the crash after `create_tree`,
    /// before its record, or a root replacement there) is Unknown. Nothing is signaled
    /// or removed by its deterministic name; a path with nothing at it is Absent.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and a cgroup2 root: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_an_unrecorded_cgroup_is_unknown_and_left() {
        let instance = format!("{FIRECRACKER_TREE}/b4-recheck3-{}", std::process::id());
        let relative = format!("{instance}/fc-unrecorded");
        let base = std::path::Path::new(CGROUP_ROOT).join(&relative);
        let absent_kill = kill_recorded(&relative, None, Duration::from_millis(100));
        let absent_remove = remove_tree(&relative, None);
        scratch_tree(&relative);
        let mut inside = sleeper_in(&base.join("vm/vmm"));
        let kill = kill_recorded(&relative, None, Duration::from_millis(500));
        let empty = vm_empty(&relative, None);
        let process_survived = inside.try_wait().unwrap().is_none();
        let _ = inside.kill();
        let _ = inside.wait();
        let remove = remove_tree(&relative, None);
        let tree_survived = base.join("vm/vmm").exists();
        scrub_tree(&relative, &[]);

        assert_eq!(absent_kill.unwrap(), NodeState::Absent);
        assert_eq!(absent_remove.unwrap(), NodeState::Absent);
        assert_eq!(kill.unwrap(), NodeState::Unknown);
        assert!(!empty, "an unrecorded tree is not proven empty");
        assert!(process_survived, "an unrecorded tree was signaled");
        assert_eq!(remove.unwrap(), NodeState::Unknown);
        assert!(tree_survived, "an unrecorded tree was removed by its name");
        eprintln!(
            "B4 evidence: an unrecorded cgroup tree was Unknown: not signaled, not removed"
        );
    }

    #[test]
    fn the_contract_recipe_is_accepted() {
        let recipe = &crate::firecracker::contract()["cgroups"];
        controllers(recipe).unwrap();
        for node in [
            "allocation",
            "relay",
            "vm/console",
            "control",
            "vm",
            "vm/vmm",
        ] {
            limits(&recipe[node]).unwrap();
        }
        assert_eq!(
            limits(&recipe["allocation"]).unwrap(),
            vec![
                ("memory.max", "939524096".to_string()),
                ("memory.swap.max", "0".to_string()),
                ("memory.oom.group", "1".to_string()),
                ("pids.max", "32".to_string()),
                ("cpu.max", "100000 100000".to_string()),
            ]
        );
    }
}
