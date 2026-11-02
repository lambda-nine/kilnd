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

/// The inode numbers of a created tree. Kill and removal compare against these before
/// acting, so a replaced directory is refused rather than signaled or removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupIdentity {
    pub parent_ino: u64,
    pub control_ino: u64,
    pub vm_ino: u64,
    pub vmm_ino: u64,
}

/// A stop target's cgroup: the internal `vm` node holding J, V and the console.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupTarget {
    /// Relative to the cgroup2 root, e.g. `kilnd-firecracker/<I>/fc-<H>/vm`.
    pub path: String,
    pub st_ino: u64,
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
fn open_at(parent: &File, name: &str, directory: bool) -> io::Result<File> {
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
fn write_control(node: &File, name: &str, value: &str) -> io::Result<()> {
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
        parent_ino: parent.metadata()?.ino(),
        control_ino: inodes["control"],
        vm_ino: inodes["vm"],
        vmm_ino: inodes["vm/vmm"],
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
    /// The directory at that path is a different inode: nothing was done to it.
    Replaced,
}

/// `cgroup.kill` against one pinned node, then a bounded wait for populated=0. The
/// inode is compared first, so a replacement directory is never signaled.
#[cfg(target_os = "linux")]
pub fn kill_node(target: &CgroupTarget, wait: Duration) -> io::Result<NodeState> {
    let node = match open_node(&target.path) {
        Ok(node) => node,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(NodeState::Absent),
        Err(error) => return Err(error),
    };
    if node.metadata()?.ino() != target.st_ino {
        return Ok(NodeState::Replaced);
    }
    if !populated(&node)? {
        return Ok(NodeState::Empty);
    }
    write_control(&node, "cgroup.kill", "1")?;
    let end = std::time::Instant::now() + wait;
    loop {
        if !populated(&node)? {
            return Ok(NodeState::Empty);
        }
        if std::time::Instant::now() >= end {
            return Ok(NodeState::Populated);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Removes an allocation's tree bottom-up after proving it empty. Missing nodes are
/// fine (a reboot or an earlier attempt removed them); a replaced parent is refused.
#[cfg(target_os = "linux")]
pub fn remove_tree(relative: &str, identity: Option<&CgroupIdentity>) -> io::Result<NodeState> {
    let parent = match open_node(relative) {
        Ok(node) => node,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(NodeState::Absent),
        Err(error) => return Err(error),
    };
    if let Some(identity) = identity
        && parent.metadata()?.ino() != identity.parent_ino
    {
        return Ok(NodeState::Replaced);
    }
    if populated(&parent)? {
        return Ok(NodeState::Populated);
    }
    for name in NODES.iter().rev() {
        let (base, leaf) = match name.rsplit_once('/') {
            Some((base, leaf)) => match open_at(&parent, base, true) {
                Ok(base) => (base, leaf),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            },
            None => (parent.try_clone()?, *name),
        };
        let c = std::ffi::CString::new(leaf).map_err(|_| invalid("cgroup name"))?;
        // SAFETY: c is NUL-terminated; AT_REMOVEDIR removes only an empty cgroup.
        if unsafe { libc::unlinkat(base.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
    }
    let (base, leaf) = relative.rsplit_once('/').ok_or_else(|| invalid("path"))?;
    let base = open_node(base)?;
    let c = std::ffi::CString::new(leaf).map_err(|_| invalid("cgroup name"))?;
    // SAFETY: as above.
    if unsafe { libc::unlinkat(base.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    Ok(NodeState::Absent)
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
    pub fn kill_node(_: &CgroupTarget, _: Duration) -> io::Result<NodeState> {
        Err(no())
    }
    pub fn remove_tree(_: &str, _: Option<&CgroupIdentity>) -> io::Result<NodeState> {
        Err(no())
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
