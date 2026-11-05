//! Section 8.2's observations. An inventory is complete only when every namespace,
//! process and resource observation in it is fresh and bounded. A missing record is
//! never absence, an empty listing is never proof, and another instance's identities
//! never appear: node totals come from `Accounting` alone.
use super::journal::{InventoryRecord, InventorySnapshot};
use super::supervisor::RecordedLoop;
use crate::helper::protocol::{ListRecord, ListStatus};
use crate::model::Id128;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The most encoded bytes one complete list may take.
pub const MAX_LIST_BYTES: usize = 1 << 20;

/// What a worker saw of one exact allocation's derived names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceObservation {
    /// The owned namespace was read and holds nothing for this allocation.
    Absent,
    Present {
        names: Vec<String>,
    },
    /// No fresh answer. Never interpreted as either of the above.
    Unknown {
        reason: String,
    },
}

/// One namespace's derived allocation directories, as actually observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeObservation {
    Observed { allocations: BTreeSet<Id128> },
    Unknown { reason: String },
}

/// Where namespace evidence comes from. B3 has no real resources: production cannot
/// observe any, so it never reports absence. B4 adds the real owned namespaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationBackend {
    Disabled,
    /// B4's real owned namespaces: cgroup tree, jail and work directories, mounts and
    /// loop slots, all derived from the instance-scoped host name.
    Real,
    /// A private directory of fake resources, injected only by internal tests.
    #[cfg(test)]
    FakeDirectory(std::path::PathBuf),
    /// The real offline walk over a fake host tree, injected only by internal tests.
    /// It answers nothing but [`ObservationBackend::observe_offline`].
    #[cfg(test)]
    FakeHost(HostRoots),
}

/// One owned resource on the host that no active allocation explains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfflineFinding {
    pub family: &'static str,
    pub detail: String,
}

/// Everything owned on the host, walked against the ledger's active allocations
/// (design 16.6, 16.7): every jail, jail mount, loop device, cgroup, work file and
/// VMM or supervisor process. Nothing is adopted because its name looks plausible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfflineObservation {
    Observed {
        /// The `(instance, allocation)` pairs at least one owned resource belongs to.
        explained: BTreeSet<(Id128, Id128)>,
        orphans: Vec<OfflineFinding>,
    },
    /// No complete walk. Never interpreted as an empty host.
    Unknown { reason: String },
}

impl ObservationBackend {
    /// `loops` are the journal's loop records for this allocation: the real backend
    /// observes each recorded slot itself, not only slots backed in the work directory.
    pub fn observe_allocation(
        &self,
        instance: Id128,
        allocation: Id128,
        loops: &[RecordedLoop],
    ) -> NamespaceObservation {
        let _ = (instance, allocation, loops);
        match self {
            Self::Disabled => NamespaceObservation::Unknown {
                reason: "resource observation is disabled before B4".into(),
            },
            Self::Real => real::observe_allocation(instance, allocation, loops),
            #[cfg(test)]
            Self::FakeDirectory(root) => fake::observe_allocation(root, instance, allocation),
            #[cfg(test)]
            Self::FakeHost(_) => NamespaceObservation::Unknown {
                reason: "the fake host answers only the offline walk".into(),
            },
        }
    }

    pub fn observe_node(&self, instance: Id128, known: &[Id128]) -> NodeObservation {
        let _ = (instance, known);
        match self {
            Self::Disabled => NodeObservation::Unknown {
                reason: "resource observation is disabled before B4".into(),
            },
            Self::Real => real::observe_node(instance, known),
            #[cfg(test)]
            Self::FakeDirectory(root) => fake::observe_node(root, instance),
            #[cfg(test)]
            Self::FakeHost(_) => NodeObservation::Unknown {
                reason: "the fake host answers only the offline walk".into(),
            },
        }
    }

    /// The offline inventory's node-wide walk, once per report. `known` maps every
    /// enrolled instance to its active allocations.
    pub fn observe_offline(&self, known: &BTreeMap<Id128, Vec<Id128>>) -> OfflineObservation {
        match self {
            Self::Disabled => OfflineObservation::Unknown {
                reason: "resource observation is disabled before B4".into(),
            },
            Self::Real => real::observe_offline(known),
            #[cfg(test)]
            Self::FakeDirectory(root) => fake::observe_offline(root, known),
            #[cfg(test)]
            Self::FakeHost(roots) => host::observe(roots, known),
        }
    }
}

/// The real owned namespaces. Host names are digests, so a node listing maps them back
/// only through the journal's own allocations; any other name makes it incomplete.
mod real {
    use super::*;
    use crate::helper::firecracker::identity::{host_allocation, host_name};
    use crate::helper::firecracker::storage::{AllocationPaths, JAIL_BASE, WORK_BASE};

    pub fn paths(instance: Id128, allocation: Id128) -> (AllocationPaths, String) {
        let host = host_name(instance, allocation);
        let _ = host_allocation(instance, allocation);
        let jail_dir = std::path::Path::new(JAIL_BASE)
            .join("firecracker")
            .join(&host);
        let work_dir = std::path::Path::new(WORK_BASE)
            .join(instance.to_string())
            .join(&host);
        (
            AllocationPaths {
                jail_root: jail_dir.join("root"),
                jail_dir,
                work_file: work_dir.join(crate::helper::firecracker::storage::WORK_FILE),
                work_dir,
            },
            format!("kilnd-firecracker/{instance}/{host}"),
        )
    }

    #[cfg(target_os = "linux")]
    pub fn observe_allocation(
        instance: Id128,
        allocation: Id128,
        loops: &[RecordedLoop],
    ) -> NamespaceObservation {
        let (paths, cgroup) = paths(instance, allocation);
        match crate::helper::firecracker::storage::observe_presence(&paths, &cgroup, loops) {
            Ok(presence) if presence.names.is_empty() => NamespaceObservation::Absent,
            Ok(presence) => NamespaceObservation::Present {
                names: presence.names,
            },
            Err(error) => NamespaceObservation::Unknown {
                reason: error.to_string(),
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn observe_allocation(_: Id128, _: Id128, _: &[RecordedLoop]) -> NamespaceObservation {
        NamespaceObservation::Unknown {
            reason: "real observation needs Linux".into(),
        }
    }

    fn names_in(path: &std::path::Path) -> Result<Vec<String>, String> {
        match std::fs::read_dir(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
            Err(error) => Err(error.to_string()),
            Ok(entries) => {
                let mut names = Vec::new();
                for entry in entries {
                    let entry = entry.map_err(|e| e.to_string())?;
                    names.push(entry.file_name().to_string_lossy().into_owned());
                    if names.len() > super::super::journal::MAX_ACTIVE_LISTED + 8 {
                        return Err("namespace exceeds the listing bound".into());
                    }
                }
                Ok(names)
            }
        }
    }

    pub fn observe_node(instance: Id128, known: &[Id128]) -> NodeObservation {
        let by_host: std::collections::HashMap<String, Id128> = known
            .iter()
            .map(|allocation| (host_name(instance, *allocation), *allocation))
            .collect();
        let mut allocations = BTreeSet::new();
        let work = std::path::Path::new(WORK_BASE).join(instance.to_string());
        let cgroup = std::path::Path::new(crate::helper::firecracker::cgroup::CGROUP_ROOT)
            .join(crate::helper::firecracker::cgroup::FIRECRACKER_TREE)
            .join(instance.to_string());
        for directory in [work, cgroup] {
            let names = match names_in(&directory) {
                Ok(names) => names,
                Err(reason) => return NodeObservation::Unknown { reason },
            };
            for name in names {
                // cgroupfs control files are not allocations.
                if !name.starts_with("fc-") {
                    if directory.starts_with(crate::helper::firecracker::cgroup::CGROUP_ROOT) {
                        continue;
                    }
                    return NodeObservation::Unknown {
                        reason: format!("unrecognized namespace entry {name}"),
                    };
                }
                match by_host.get(&name) {
                    Some(allocation) => {
                        allocations.insert(*allocation);
                    }
                    None => {
                        return NodeObservation::Unknown {
                            reason: format!("owned name {name} has no journal record"),
                        };
                    }
                }
            }
        }
        NodeObservation::Observed { allocations }
    }

    #[cfg(target_os = "linux")]
    pub fn observe_offline(known: &BTreeMap<Id128, Vec<Id128>>) -> OfflineObservation {
        match super::host::HostRoots::production() {
            Ok(roots) => super::host::observe(&roots, known),
            Err(reason) => OfflineObservation::Unknown { reason },
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn observe_offline(_: &BTreeMap<Id128, Vec<Id128>>) -> OfflineObservation {
        OfflineObservation::Unknown {
            reason: "real observation needs Linux".into(),
        }
    }
}

pub use real::paths as real_paths;
#[cfg(any(target_os = "linux", test))]
pub use host::{HostRoots, ProcSource};

/// The offline walk itself, over an injectable set of roots so tests run it on a temp
/// tree. Each family lists everything under its owned base and maps each entry to an
/// active allocation only through `identity::host_name` (and, where the path has one,
/// its instance component): anything else is an orphan.
#[cfg(any(target_os = "linux", test))]
mod host {
    use super::*;
    use crate::helper::firecracker::cgroup::FIRECRACKER_TREE;
    use crate::helper::firecracker::identity::host_name;
    use crate::helper::firecracker::journal::MAX_ACTIVE_LISTED;
    use crate::helper::firecracker::storage::{JAIL_FS_SOURCE_PREFIX, MountEntry, parse_mountinfo};
    use std::collections::HashMap;
    use std::io;
    use std::path::{Component, Path, PathBuf};

    /// Entries beyond the active allocations an owned directory may hold before the
    /// listing is refused, as `real::names_in`.
    const SLACK: usize = 8;
    /// The most process directories one walk lists.
    const MAX_PROCESSES: usize = 1 << 16;
    /// The most block devices one walk lists.
    const MAX_BLOCK_DEVICES: usize = 1 << 14;

    /// Where process state is read.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ProcSource {
        /// The helper's private procfs instance (`crate::sys::procfs`).
        #[cfg(target_os = "linux")]
        Private,
        /// A directory of `<pid>/cgroup` and `<pid>/comm` files.
        #[cfg(test)]
        Directory(PathBuf),
    }

    impl ProcSource {
        fn pids(&self) -> Result<Vec<String>, String> {
            let names: Vec<String> = match self {
                #[cfg(target_os = "linux")]
                Self::Private => crate::sys::procfs::read_root_dir(MAX_PROCESSES)
                    .map_err(|e| format!("procfs: {e}"))?
                    .into_iter()
                    .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
                    .collect(),
                #[cfg(test)]
                Self::Directory(root) => list(root, MAX_PROCESSES)?
                    .into_iter()
                    .map(|entry| entry.name)
                    .collect(),
            };
            Ok(names
                .into_iter()
                .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
                .collect())
        }

        fn read(&self, pid: &str, file: &str) -> io::Result<String> {
            match self {
                #[cfg(target_os = "linux")]
                Self::Private => crate::sys::procfs::read_to_string(&format!("{pid}/{file}")),
                #[cfg(test)]
                Self::Directory(root) => std::fs::read_to_string(root.join(pid).join(file)),
            }
        }
    }

    /// The owned bases one walk covers.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct HostRoots {
        pub jail_base: PathBuf,
        pub work_base: PathBuf,
        /// `CGROUP_ROOT/FIRECRACKER_TREE`.
        pub cgroup_tree: PathBuf,
        /// `/sys/block`.
        pub sys_block: PathBuf,
        pub proc: ProcSource,
        /// This process's mountinfo text.
        pub mountinfo: String,
    }

    impl HostRoots {
        #[cfg(target_os = "linux")]
        pub fn production() -> Result<Self, String> {
            use crate::helper::firecracker::cgroup::CGROUP_ROOT;
            use crate::helper::firecracker::storage::{JAIL_BASE, WORK_BASE};
            let mountinfo = crate::sys::procfs::read_to_string(&crate::sys::procfs::own(
                "mountinfo",
            ))
            .map_err(|e| format!("mountinfo: {e}"))?;
            Ok(Self {
                jail_base: JAIL_BASE.into(),
                work_base: WORK_BASE.into(),
                cgroup_tree: Path::new(CGROUP_ROOT).join(FIRECRACKER_TREE),
                sys_block: "/sys/block".into(),
                proc: ProcSource::Private,
                mountinfo,
            })
        }
    }

    pub(super) struct Entry {
        pub name: String,
        pub directory: bool,
    }

    /// Every entry of `path`; an absent directory has none. Any other error, or more
    /// than `bound` entries, fails the walk.
    pub(super) fn list(path: &Path, bound: usize) -> Result<Vec<Entry>, String> {
        let entries = match std::fs::read_dir(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(format!("{}: {error}", path.display())),
            Ok(entries) => entries,
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
            // file_type does not follow a link: a link is never a directory here.
            let kind = entry
                .file_type()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            out.push(Entry {
                name: entry.file_name().to_string_lossy().into_owned(),
                directory: kind.is_dir(),
            });
            if out.len() > bound {
                return Err(format!("{} exceeds the listing bound", path.display()));
            }
        }
        Ok(out)
    }

    /// The ledger's active allocations, by their node-unique host names.
    struct Ledger {
        instances: HashMap<String, Id128>,
        hosts: HashMap<String, (Id128, Id128)>,
        total: usize,
    }

    impl Ledger {
        fn new(known: &BTreeMap<Id128, Vec<Id128>>) -> Self {
            let mut hosts = HashMap::new();
            for (instance, allocations) in known {
                for allocation in allocations {
                    hosts.insert(host_name(*instance, *allocation), (*instance, *allocation));
                }
            }
            Self {
                instances: known.keys().map(|i| (i.to_string(), *i)).collect(),
                total: hosts.len(),
                hosts,
            }
        }

        fn enrolled(&self, name: &str) -> bool {
            self.instances.contains_key(name)
        }

        fn host(&self, host: &str) -> Option<(Id128, Id128)> {
            self.hosts.get(host).copied()
        }

        /// `host` is a known allocation of the instance named `instance`.
        fn of_instance(&self, instance: &str, host: &str) -> Option<(Id128, Id128)> {
            let id = self.instances.get(instance)?;
            self.host(host).filter(|(owner, _)| owner == id)
        }

        /// The first two plain components of `rest`, mapped as `<instance>/<host>`.
        fn of_path(&self, rest: &Path) -> Option<(Id128, Id128)> {
            let mut parts = rest.components();
            let (Some(Component::Normal(instance)), Some(Component::Normal(host))) =
                (parts.next(), parts.next())
            else {
                return None;
            };
            self.of_instance(instance.to_str()?, host.to_str()?)
        }

        /// Bound for a directory holding one instance's allocations.
        fn instance_bound(&self) -> usize {
            MAX_ACTIVE_LISTED + SLACK
        }

        /// Bound for a directory holding every instance's allocations.
        fn node_bound(&self) -> usize {
            MAX_ACTIVE_LISTED
                .saturating_mul(self.instances.len().max(1))
                .max(self.total)
                .saturating_add(SLACK)
        }
    }

    struct Walk {
        explained: BTreeSet<(Id128, Id128)>,
        orphans: Vec<OfflineFinding>,
    }

    impl Walk {
        fn orphan(&mut self, family: &'static str, detail: String) {
            self.orphans.push(OfflineFinding { family, detail });
        }
    }

    pub fn observe(roots: &HostRoots, known: &BTreeMap<Id128, Vec<Id128>>) -> OfflineObservation {
        let ledger = Ledger::new(known);
        let mut walk = Walk {
            explained: BTreeSet::new(),
            orphans: Vec::new(),
        };
        let walked = (|| -> Result<(), String> {
            let mounts = parse_mountinfo(&roots.mountinfo).map_err(|e| format!("mountinfo: {e}"))?;
            jail_directories(roots, &ledger, &mut walk)?;
            jail_mounts(roots, &mounts, &ledger, &mut walk);
            loop_devices(roots, &ledger, &mut walk)?;
            processes(roots, &ledger, &mut walk)?;
            cgroups(roots, &ledger, &mut walk)?;
            work_files(roots, &ledger, &mut walk)
        })();
        match walked {
            Ok(()) => OfflineObservation::Observed {
                explained: walk.explained,
                orphans: walk.orphans,
            },
            Err(reason) => OfflineObservation::Unknown { reason },
        }
    }

    /// `jail_base` holds only `firecracker/`, which holds only known allocations' jails.
    fn jail_directories(roots: &HostRoots, ledger: &Ledger, walk: &mut Walk) -> Result<(), String> {
        const FAMILY: &str = "jail directory";
        for entry in list(&roots.jail_base, ledger.node_bound())? {
            if entry.name != "firecracker" || !entry.directory {
                walk.orphan(FAMILY, roots.jail_base.join(&entry.name).display().to_string());
            }
        }
        let firecracker = roots.jail_base.join("firecracker");
        for entry in list(&firecracker, ledger.node_bound())? {
            match ledger.host(&entry.name).filter(|_| entry.directory) {
                Some(key) => {
                    walk.explained.insert(key);
                }
                None => walk.orphan(FAMILY, firecracker.join(&entry.name).display().to_string()),
            }
        }
        Ok(())
    }

    /// Every mount at or below either owned base, or with a jail tmpfs's source, inside
    /// one known allocation's jail or work directory. The jail base's own private bind
    /// (`prepare_jail_base`) is the node's, not an allocation's: exactly one, never a
    /// jail tmpfs; another mount stacked on the base would hide what is below it.
    fn jail_mounts(roots: &HostRoots, mounts: &[MountEntry], ledger: &Ledger, walk: &mut Walk) {
        let firecracker = roots.jail_base.join("firecracker");
        let mut base_bind = false;
        for mount in mounts {
            let at = &mount.mount_point;
            let jail_source = mount.source.starts_with(JAIL_FS_SOURCE_PREFIX);
            let owned =
                at.starts_with(&roots.jail_base) || at.starts_with(&roots.work_base) || jail_source;
            if !owned {
                continue;
            }
            if *at == roots.jail_base && !jail_source && !base_bind {
                base_bind = true;
                continue;
            }
            let key = if let Ok(rest) = at.strip_prefix(&firecracker) {
                match rest.components().next() {
                    Some(Component::Normal(host)) => host.to_str().and_then(|h| ledger.host(h)),
                    _ => None,
                }
            } else if let Ok(rest) = at.strip_prefix(&roots.work_base) {
                ledger.of_path(rest)
            } else {
                None
            };
            match key {
                Some(key) => {
                    walk.explained.insert(key);
                }
                None => walk.orphan(
                    "jail mount",
                    format!(
                        "mount {} at {} ({} from {})",
                        mount.mount_id,
                        at.display(),
                        mount.fs_type,
                        mount.source
                    ),
                ),
            }
        }
    }

    /// Every bound loop device backed inside either owned base, inside one known
    /// allocation's work directory. Devices backed elsewhere are not ours.
    fn loop_devices(roots: &HostRoots, ledger: &Ledger, walk: &mut Walk) -> Result<(), String> {
        for entry in list(&roots.sys_block, MAX_BLOCK_DEVICES)? {
            if !entry.name.starts_with("loop") {
                continue;
            }
            let path = roots.sys_block.join(&entry.name).join("loop").join("backing_file");
            let text = match std::fs::read_to_string(&path) {
                // No `loop/` attributes: the slot is not bound.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("{}: {error}", path.display())),
                Ok(text) => text,
            };
            let text = text.strip_suffix('\n').unwrap_or(&text);
            let backing = Path::new(text.strip_suffix(" (deleted)").unwrap_or(text));
            if !backing.starts_with(&roots.work_base) && !backing.starts_with(&roots.jail_base) {
                continue;
            }
            let key = backing
                .strip_prefix(&roots.work_base)
                .ok()
                .and_then(|rest| ledger.of_path(rest));
            match key {
                Some(key) => {
                    walk.explained.insert(key);
                }
                None => walk.orphan(
                    "loop device",
                    format!("{} backed by {}", entry.name, backing.display()),
                ),
            }
        }
        Ok(())
    }

    fn vanished(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    }

    /// Every process: one in the Firecracker cgroup tree must be in a known
    /// allocation's subtree (S in `control`, the VMM below `vm`), and a `firecracker`
    /// or `jailer` anywhere else is an orphan. A process that exits mid-walk is gone.
    fn processes(roots: &HostRoots, ledger: &Ledger, walk: &mut Walk) -> Result<(), String> {
        const FAMILY: &str = "process";
        let tree = Path::new("/").join(FIRECRACKER_TREE);
        for pid in roots.proc.pids()? {
            let cgroup = match roots.proc.read(&pid, "cgroup") {
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(format!("process {pid} cgroup: {error}")),
                Ok(text) => text,
            };
            let comm = match roots.proc.read(&pid, "comm") {
                Err(error) if vanished(&error) => continue,
                Err(error) => return Err(format!("process {pid} comm: {error}")),
                Ok(text) => text.trim_end_matches('\n').to_string(),
            };
            let path = cgroup
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .ok_or_else(|| format!("process {pid} has no cgroup2 membership"))?;
            let path = Path::new(path);
            if let Ok(rest) = path.strip_prefix(&tree) {
                match ledger.of_path(rest) {
                    Some(key) => {
                        walk.explained.insert(key);
                    }
                    None => walk.orphan(
                        FAMILY,
                        format!("{pid} ({comm}) in cgroup {}", path.display()),
                    ),
                }
            } else if comm == "firecracker" || comm == "jailer" {
                walk.orphan(
                    FAMILY,
                    format!(
                        "{pid} ({comm}) outside every allocation cgroup, in {}",
                        path.display()
                    ),
                );
            }
        }
        Ok(())
    }

    /// The tree holds only enrolled instances' directories, each only known
    /// allocations' subtrees. cgroupfs control files are not resources.
    fn cgroups(roots: &HostRoots, ledger: &Ledger, walk: &mut Walk) -> Result<(), String> {
        const FAMILY: &str = "cgroup";
        for instance in list(&roots.cgroup_tree, ledger.node_bound())? {
            if !instance.directory {
                continue;
            }
            let directory = roots.cgroup_tree.join(&instance.name);
            if !ledger.enrolled(&instance.name) {
                walk.orphan(FAMILY, directory.display().to_string());
                continue;
            }
            for entry in list(&directory, ledger.instance_bound())? {
                if !entry.directory {
                    continue;
                }
                match ledger.of_instance(&instance.name, &entry.name) {
                    Some(key) => {
                        walk.explained.insert(key);
                    }
                    None => walk.orphan(FAMILY, directory.join(&entry.name).display().to_string()),
                }
            }
        }
        Ok(())
    }

    /// `work_base` holds only enrolled instances' directories, each only known
    /// allocations' work directories.
    fn work_files(roots: &HostRoots, ledger: &Ledger, walk: &mut Walk) -> Result<(), String> {
        const FAMILY: &str = "work file";
        for instance in list(&roots.work_base, ledger.node_bound())? {
            let directory = roots.work_base.join(&instance.name);
            if !instance.directory || !ledger.enrolled(&instance.name) {
                walk.orphan(FAMILY, directory.display().to_string());
                continue;
            }
            for entry in list(&directory, ledger.instance_bound())? {
                match ledger
                    .of_instance(&instance.name, &entry.name)
                    .filter(|_| entry.directory)
                {
                    Some(key) => {
                        walk.explained.insert(key);
                    }
                    None => walk.orphan(FAMILY, directory.join(&entry.name).display().to_string()),
                }
            }
        }
        Ok(())
    }
}

/// The fake namespace: `<root>/<instance>/fc-<allocation>/<resource>` files. Real
/// directory reads run in workers, so stalling them exercises the real process model.
#[cfg(test)]
pub(super) mod fake {
    use super::*;
    use std::path::{Path, PathBuf};

    pub fn allocation_dir(root: &Path, instance: Id128, allocation: Id128) -> PathBuf {
        root.join(instance.to_string())
            .join(super::super::identity::backend_id(allocation))
    }

    pub fn observe_allocation(
        root: &Path,
        instance: Id128,
        allocation: Id128,
    ) -> NamespaceObservation {
        let directory = allocation_dir(root, instance, allocation);
        match std::fs::read_dir(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                NamespaceObservation::Absent
            }
            Err(error) => NamespaceObservation::Unknown {
                reason: error.to_string(),
            },
            Ok(entries) => {
                let mut names = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => names.push(entry.file_name().to_string_lossy().into_owned()),
                        Err(error) => {
                            return NamespaceObservation::Unknown {
                                reason: error.to_string(),
                            };
                        }
                    }
                }
                if names.is_empty() {
                    // The directory itself is an owned resource.
                    names.push(".".into());
                }
                names.sort();
                NamespaceObservation::Present { names }
            }
        }
    }

    /// Today's per-instance fake namespace, once per enrolled instance: an allocation
    /// with no active record, or an unrecognized name, is an orphan.
    pub fn observe_offline(root: &Path, known: &BTreeMap<Id128, Vec<Id128>>) -> OfflineObservation {
        let mut explained = BTreeSet::new();
        let mut orphans = Vec::new();
        for (instance, active) in known {
            match observe_node(root, *instance) {
                NodeObservation::Observed { allocations } => {
                    for allocation in allocations {
                        if active.contains(&allocation) {
                            explained.insert((*instance, allocation));
                        } else {
                            orphans.push(OfflineFinding {
                                family: "fake",
                                detail: format!(
                                    "instance {instance}: resources of allocation {allocation} have no active ledger record"
                                ),
                            });
                        }
                    }
                }
                NodeObservation::Unknown { reason } => orphans.push(OfflineFinding {
                    family: "fake",
                    detail: format!("instance {instance}: {reason}"),
                }),
            }
        }
        OfflineObservation::Observed { explained, orphans }
    }

    pub fn observe_node(root: &Path, instance: Id128) -> NodeObservation {
        let directory = root.join(instance.to_string());
        let entries = match std::fs::read_dir(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return NodeObservation::Observed {
                    allocations: BTreeSet::new(),
                };
            }
            Err(error) => {
                return NodeObservation::Unknown {
                    reason: error.to_string(),
                };
            }
            Ok(entries) => entries,
        };
        let mut allocations = BTreeSet::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return NodeObservation::Unknown {
                    reason: "unreadable namespace entry".into(),
                };
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let parsed = name
                .strip_prefix("fc-")
                .and_then(|id| Id128::parse(id).ok());
            match parsed {
                Some(id) => {
                    allocations.insert(id);
                }
                // Never adopt or ignore a name that merely looks plausible.
                None => {
                    return NodeObservation::Unknown {
                        reason: format!("unrecognized namespace entry {name}"),
                    };
                }
            }
            if allocations.len() > super::super::journal::MAX_ACTIVE_LISTED {
                return NodeObservation::Unknown {
                    reason: "namespace exceeds the listing bound".into(),
                };
            }
        }
        NodeObservation::Observed { allocations }
    }
}

/// Freshness inputs for one allocation, from H's own worker table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerFreshness {
    pub stop_fenced: bool,
    pub supervisor_stalled: bool,
    pub supervisor_missing: bool,
}

/// One complete-or-inconclusive answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssembledInventory {
    pub generation: u64,
    pub records: Vec<ListRecord>,
    pub complete: bool,
    pub incomplete_reason: Option<String>,
}

fn status_of(record: &InventoryRecord, freshness: &WorkerFreshness) -> ListStatus {
    if freshness.stop_fenced {
        return ListStatus::Quarantined;
    }
    if freshness.supervisor_stalled || freshness.supervisor_missing {
        return ListStatus::Unknown;
    }
    match record.phase.as_str() {
        // Only a READY VM with no execution in flight is reusable.
        "ready" => ListStatus::Ready,
        "intent" | "preparing" | "spawn_intent" | "booting" | "exec_intent" | "busy" => {
            ListStatus::Busy
        }
        "stop_intent" | "quarantined" => ListStatus::Quarantined,
        "stopped" | "cleaning" => ListStatus::StoppedWithResources,
        _ => ListStatus::Unknown,
    }
}

/// Combines the root journal, the owned namespace and process freshness. Any stale
/// source, an unexplained resource or an oversize result makes it incomplete; records
/// stay, marked Unknown where they cannot be established, and never read as absent.
pub fn assemble(
    journal: &InventorySnapshot,
    namespace: &NodeObservation,
    monitor_healthy: bool,
    freshness: &dyn Fn(Id128) -> WorkerFreshness,
) -> AssembledInventory {
    let mut incomplete: Option<String> = None;
    let mut note = |reason: String| {
        incomplete.get_or_insert(reason);
    };
    if journal.overflow {
        note("active allocations exceed the listing bound".into());
    }
    if !monitor_healthy {
        note("process monitor is not healthy".into());
    }
    let mut records = Vec::with_capacity(journal.records.len());
    let mut journaled = BTreeSet::new();
    for record in &journal.records {
        journaled.insert(record.allocation_id);
        let fresh = freshness(record.allocation_id);
        let status = status_of(record, &fresh);
        if status == ListStatus::Unknown {
            note(format!(
                "allocation {} has no fresh process observation",
                record.allocation_id
            ));
        }
        records.push(ListRecord {
            allocation_id: record.allocation_id,
            plan_digest: record.plan_digest,
            generation: record.generation,
            status,
        });
    }
    match namespace {
        NodeObservation::Unknown { reason } => {
            note(format!("namespace observation unavailable: {reason}"));
        }
        NodeObservation::Observed { allocations } => {
            if let Some(unexplained) = allocations.iter().find(|id| !journaled.contains(id)) {
                // A resource with no journal record is reported, never adopted or
                // deleted, and it blocks a complete answer.
                note(format!("unexplained resources for fc-{unexplained}"));
            }
        }
    }
    let encoded = serde_json::to_vec(&records)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if encoded > MAX_LIST_BYTES {
        note("inventory exceeds its encoded bound".into());
    }
    AssembledInventory {
        generation: journal.generation,
        complete: incomplete.is_none(),
        incomplete_reason: incomplete,
        records,
    }
}

#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They create,
// overwrite and remove their own scratch files directly.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::model::Digest;

    fn record(byte: u8, phase: &str) -> InventoryRecord {
        InventoryRecord {
            allocation_id: Id128::from_bytes([byte; 16]),
            plan_digest: Digest::of(&[byte]),
            phase: phase.into(),
            generation: 7,
            unsettled_workers: 0,
        }
    }

    fn healthy(_: Id128) -> WorkerFreshness {
        WorkerFreshness::default()
    }

    fn snapshot(records: Vec<InventoryRecord>) -> InventorySnapshot {
        InventorySnapshot {
            generation: 9,
            records,
            overflow: false,
        }
    }

    #[test]
    fn complete_only_when_every_source_is_fresh_and_explained() {
        let a = record(1, "preparing");
        let namespace = NodeObservation::Observed {
            allocations: [a.allocation_id].into(),
        };
        let done = assemble(&snapshot(vec![a.clone()]), &namespace, true, &healthy);
        assert!(done.complete, "{:?}", done.incomplete_reason);
        assert_eq!(done.records[0].status, ListStatus::Busy);
        assert_eq!(done.generation, 9);
    }

    #[test]
    fn a_missing_record_is_never_absence_and_an_empty_stale_list_is_not_complete() {
        // Unknown namespace with no journal records: not "nothing exists".
        let unknown = NodeObservation::Unknown {
            reason: "worker shortage".into(),
        };
        let listed = assemble(&snapshot(vec![]), &unknown, true, &healthy);
        assert!(!listed.complete);
        assert!(listed.records.is_empty());
        assert!(
            listed
                .incomplete_reason
                .unwrap()
                .contains("worker shortage")
        );
        // A real resource with no journal record blocks completeness.
        let stray = Id128::from_bytes([3; 16]);
        let observed = NodeObservation::Observed {
            allocations: [stray].into(),
        };
        let listed = assemble(&snapshot(vec![]), &observed, true, &healthy);
        assert!(!listed.complete);
        assert!(
            listed
                .incomplete_reason
                .unwrap()
                .contains(&stray.to_string())
        );
    }

    #[test]
    fn stale_processes_or_monitor_make_records_unknown_and_incomplete() {
        let a = record(1, "preparing");
        let namespace = NodeObservation::Observed {
            allocations: [a.allocation_id].into(),
        };
        let stalled = |_: Id128| WorkerFreshness {
            supervisor_stalled: true,
            ..WorkerFreshness::default()
        };
        let listed = assemble(&snapshot(vec![a.clone()]), &namespace, true, &stalled);
        assert!(!listed.complete);
        assert_eq!(listed.records[0].status, ListStatus::Unknown);
        let listed = assemble(&snapshot(vec![a.clone()]), &namespace, false, &healthy);
        assert!(!listed.complete);
        let fenced = |_: Id128| WorkerFreshness {
            stop_fenced: true,
            ..WorkerFreshness::default()
        };
        let listed = assemble(&snapshot(vec![a]), &namespace, true, &fenced);
        assert_eq!(listed.records[0].status, ListStatus::Quarantined);
    }

    #[test]
    fn overflow_is_an_error_not_a_truncated_complete_list() {
        let journal = InventorySnapshot {
            generation: 1,
            records: vec![],
            overflow: true,
        };
        let namespace = NodeObservation::Observed {
            allocations: BTreeSet::new(),
        };
        assert!(!assemble(&journal, &namespace, true, &healthy).complete);
    }

    #[test]
    fn production_observation_never_reports_absence() {
        let backend = ObservationBackend::Disabled;
        let (i, a) = (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]));
        assert!(matches!(
            backend.observe_allocation(i, a, &[]),
            NamespaceObservation::Unknown { .. }
        ));
        assert!(matches!(
            backend.observe_node(i, &[]),
            NodeObservation::Unknown { .. }
        ));
        assert!(matches!(
            backend.observe_offline(&[(i, vec![a])].into()),
            OfflineObservation::Unknown { .. }
        ));
    }

    // The offline walk over a temp host tree (design 16.6, 16.7).
    use super::super::identity::host_name;
    use std::path::{Path, PathBuf};

    struct Host {
        _temp: tempfile::TempDir,
        roots: HostRoots,
        /// Mountinfo lines: the walk reads `roots.mountinfo`, rebuilt by `observe`.
        mounts: Vec<String>,
        next_mount: u64,
    }

    fn mkdir(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
    }

    fn write(path: &Path, text: &str) {
        mkdir(path.parent().unwrap());
        std::fs::write(path, text).unwrap();
    }

    fn proc_dir(host: &Host) -> PathBuf {
        match &host.roots.proc {
            ProcSource::Directory(proc) => proc.clone(),
            #[cfg(target_os = "linux")]
            ProcSource::Private => unreachable!("the fake host reads a directory"),
        }
    }

    impl Host {
        /// A host with only the node's own and unrelated state: the jail base's bind,
        /// the root filesystem, a snap's loop device, init and a kernel thread.
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let at = |name: &str| temp.path().join(name);
            let roots = HostRoots {
                jail_base: at("jails"),
                work_base: at("work"),
                cgroup_tree: at("cgroup").join(super::super::cgroup::FIRECRACKER_TREE),
                sys_block: at("block"),
                proc: ProcSource::Directory(at("proc")),
                mountinfo: String::new(),
            };
            mkdir(&roots.jail_base.join("firecracker"));
            mkdir(&roots.work_base);
            write(&roots.cgroup_tree.join("cgroup.procs"), "");
            write(
                &roots.sys_block.join("loop0/loop/backing_file"),
                "/var/lib/snapd/snaps/core.snap\n",
            );
            mkdir(&roots.sys_block.join("loop1/queue")); // unbound
            mkdir(&roots.sys_block.join("nvme0n1"));
            let mut host = Self {
                _temp: temp,
                roots,
                mounts: vec![],
                next_mount: 20,
            };
            host.process(1, "/init.scope", "systemd");
            host.process(2, "/", "kthreadd");
            host.mount(Path::new("/"), "ext4", "/dev/vda1");
            let base = host.roots.jail_base.clone();
            host.mount(&base, "ext4", "/dev/vda1");
            host
        }

        fn mount(&mut self, at: &Path, fs_type: &str, source: &str) {
            let id = self.next_mount;
            self.next_mount += 1;
            self.mounts.push(format!(
                "{id} 1 0:{id} / {} rw,relatime shared:1 - {fs_type} {source} rw",
                at.display()
            ));
        }

        fn process(&self, pid: u32, cgroup: &str, comm: &str) {
            let proc = proc_dir(self).join(pid.to_string());
            write(&proc.join("cgroup"), &format!("0::{cgroup}\n"));
            write(&proc.join("comm"), &format!("{comm}\n"));
        }

        fn backed(&self, slot: u32, backing: &Path, deleted: bool) {
            let suffix = if deleted { " (deleted)" } else { "" };
            write(
                &self
                    .roots
                    .sys_block
                    .join(format!("loop{slot}/loop/backing_file")),
                &format!("{}{suffix}\n", backing.display()),
            );
        }

        fn work_dir(&self, instance: Id128, host: &str) -> PathBuf {
            self.roots.work_base.join(instance.to_string()).join(host)
        }

        fn jail_dir(&self, host: &str) -> PathBuf {
            self.roots.jail_base.join("firecracker").join(host)
        }

        fn cgroup_path(instance: Id128, host: &str, leaf: &str) -> String {
            format!(
                "/{}/{instance}/{host}/{leaf}",
                super::super::cgroup::FIRECRACKER_TREE
            )
        }

        /// Every family's resources for one live allocation: its jail directory with
        /// the jail tmpfs and a bind, its work directory and file, the loop device over
        /// that file, its cgroup subtree, S in `control`, and the VMM and jailer below
        /// `vm`. `n` keeps slots and pids distinct.
        fn allocation(&mut self, instance: Id128, allocation: Id128, n: u32) {
            let host = host_name(instance, allocation);
            let jail = self.jail_dir(&host);
            mkdir(&jail.join("root"));
            self.mount(&jail, "tmpfs", &format!("kilnd-jail-{n:032x}"));
            self.mount(&jail.join("root/kernel"), "ext4", "/dev/vda1");
            let work = self.work_dir(instance, &host);
            write(&work.join("work.xfs"), "");
            self.backed(10 + n, &work.join("work.xfs"), n % 2 == 1);
            let cgroup = self.roots.cgroup_tree.join(instance.to_string());
            write(&cgroup.join("cgroup.procs"), "");
            for leaf in ["control", "relay", "vm/vmm", "vm/console"] {
                mkdir(&cgroup.join(&host).join(leaf));
            }
            write(&cgroup.join(&host).join("cgroup.subtree_control"), "");
            let leaf = |leaf| Self::cgroup_path(instance, &host, leaf);
            self.process(1000 + 3 * n, &leaf("control"), "kilnd-helper");
            self.process(1001 + 3 * n, &leaf("vm/vmm"), "firecracker");
            self.process(1002 + 3 * n, &leaf("vm"), "jailer");
        }

        fn observe(&mut self, known: &BTreeMap<Id128, Vec<Id128>>) -> OfflineObservation {
            self.roots.mountinfo = self.mounts.join("\n");
            ObservationBackend::FakeHost(self.roots.clone()).observe_offline(known)
        }
    }

    type Live = (Host, BTreeMap<Id128, Vec<Id128>>, [(Id128, Id128); 2]);

    /// Two enrolled instances, one live allocation each, every family populated.
    fn live() -> Live {
        let pairs = [
            (Id128::from_bytes([1; 16]), Id128::from_bytes([11; 16])),
            (Id128::from_bytes([2; 16]), Id128::from_bytes([12; 16])),
        ];
        let mut host = Host::new();
        for (n, (instance, allocation)) in pairs.iter().enumerate() {
            host.allocation(*instance, *allocation, n as u32);
        }
        let known = pairs.iter().map(|(i, a)| (*i, vec![*a])).collect();
        (host, known, pairs)
    }

    /// The walk observed exactly one orphan, of `family`; returns its detail.
    fn sole_orphan(observation: OfflineObservation, family: &str) -> String {
        let OfflineObservation::Observed { orphans, .. } = observation else {
            panic!("not observed: {observation:?}");
        };
        assert_eq!(orphans.len(), 1, "{orphans:?}");
        assert_eq!(orphans[0].family, family, "{orphans:?}");
        orphans[0].detail.clone()
    }

    /// A name shaped exactly like an owned one, of an allocation the ledger has not.
    fn stray(instance: Id128) -> String {
        host_name(instance, Id128::from_bytes([0xee; 16]))
    }

    #[test]
    fn offline_walk_explains_every_family_of_known_allocations() {
        let (mut host, known, pairs) = live();
        assert_eq!(
            host.observe(&known),
            OfflineObservation::Observed {
                explained: pairs.into_iter().collect(),
                orphans: vec![],
            }
        );
        // An enrolled instance with nothing at all is fine; an empty host too.
        let mut idle = known.clone();
        idle.insert(Id128::from_bytes([3; 16]), vec![]);
        assert!(matches!(
            host.observe(&idle),
            OfflineObservation::Observed { ref orphans, .. } if orphans.is_empty()
        ));
        assert_eq!(
            Host::new().observe(&BTreeMap::new()),
            OfflineObservation::Observed {
                explained: BTreeSet::new(),
                orphans: vec![],
            }
        );
    }

    #[test]
    fn offline_walk_reports_an_orphan_jail_directory() {
        let (mut host, known, [(i, _), _]) = live();
        mkdir(&host.jail_dir(&stray(i)));
        let detail = sole_orphan(host.observe(&known), "jail directory");
        assert!(detail.ends_with(&stray(i)), "{detail}");
        // Anything in the jail base besides `firecracker/` is not ours either.
        let (mut host, known, _) = live();
        mkdir(&host.roots.jail_base.join("other"));
        sole_orphan(host.observe(&known), "jail directory");
    }

    #[test]
    fn offline_walk_reports_an_orphan_jail_mount() {
        let (mut host, known, [(i, a), (j, _)]) = live();
        // A jail tmpfs left on a jail directory that is gone.
        let at = host.jail_dir(&stray(i));
        host.mount(&at, "tmpfs", "kilnd-jail-00000000000000000000000000000077");
        let detail = sole_orphan(host.observe(&known), "jail mount");
        assert!(detail.contains(&stray(i)), "{detail}");
        // A jail tmpfs moved anywhere else, found by its source alone.
        let (mut host, known, _) = live();
        host.mount(
            Path::new("/mnt/x"),
            "tmpfs",
            "kilnd-jail-00000000000000000000000000000078",
        );
        sole_orphan(host.observe(&known), "jail mount");
        // A mount in one instance's work directory named for another's allocation.
        let (mut host, known, _) = live();
        let at = host.work_dir(j, &host_name(i, a));
        host.mount(&at, "xfs", "/dev/loop9");
        sole_orphan(host.observe(&known), "jail mount");
        // A second mount stacked on the jail base, which would hide what is below it.
        let (mut host, known, _) = live();
        let base = host.roots.jail_base.clone();
        host.mount(&base, "tmpfs", "tmpfs");
        sole_orphan(host.observe(&known), "jail mount");
    }

    #[test]
    fn offline_walk_reports_an_orphan_loop_device() {
        let (host, known, [(i, _), _]) = live();
        let mut host = host;
        let backing = host.work_dir(i, &stray(i)).join("work.xfs");
        host.backed(40, &backing, true);
        let detail = sole_orphan(host.observe(&known), "loop device");
        assert!(detail.starts_with("loop40 backed by"), "{detail}");
        assert!(!detail.contains("(deleted)"), "{detail}");
        // Backed in the jail base: never an allocation's work file.
        let (mut host, known, _) = live();
        let backing = host.roots.jail_base.join("firecracker/x.img");
        host.backed(41, &backing, false);
        sole_orphan(host.observe(&known), "loop device");
    }

    #[test]
    fn offline_walk_reports_an_orphan_vmm_or_supervisor_process() {
        let (mut host, known, [(i, a), (j, _)]) = live();
        host.process(4000, &Host::cgroup_path(i, &stray(i), "vm/vmm"), "firecracker");
        let detail = sole_orphan(host.observe(&known), "process");
        assert!(detail.starts_with("4000 (firecracker) in cgroup"), "{detail}");
        // A supervisor in the control leaf of an allocation the ledger has not.
        let (mut host, known, _) = live();
        host.process(4001, &Host::cgroup_path(i, &stray(i), "control"), "kilnd-helper");
        sole_orphan(host.observe(&known), "process");
        // One under another instance's directory, named for a known allocation.
        let (mut host, known, _) = live();
        host.process(4002, &Host::cgroup_path(j, &host_name(i, a), "control"), "kilnd-helper");
        sole_orphan(host.observe(&known), "process");
        // A VMM or jailer outside the Firecracker tree altogether.
        for comm in ["firecracker", "jailer"] {
            let (mut host, known, _) = live();
            host.process(4003, "/system.slice/other.service", comm);
            let detail = sole_orphan(host.observe(&known), "process");
            assert!(detail.contains("outside every allocation cgroup"), "{detail}");
        }
        // Any process in the tree but outside an allocation's subtree.
        let (mut host, known, _) = live();
        let tree = super::super::cgroup::FIRECRACKER_TREE;
        host.process(4004, &format!("/{tree}/{i}"), "sh");
        sole_orphan(host.observe(&known), "process");
    }

    #[test]
    fn offline_walk_reports_an_orphan_cgroup() {
        let (mut host, known, [(i, _), _]) = live();
        let instance = host.roots.cgroup_tree.join(i.to_string());
        mkdir(&instance.join(stray(i)).join("vm"));
        let detail = sole_orphan(host.observe(&known), "cgroup");
        assert!(detail.ends_with(&stray(i)), "{detail}");
        // An instance directory the ledger has not enrolled.
        let (mut host, known, _) = live();
        mkdir(&host.roots.cgroup_tree.join(Id128::from_bytes([9; 16]).to_string()));
        sole_orphan(host.observe(&known), "cgroup");
    }

    #[test]
    fn offline_walk_reports_an_orphan_work_file() {
        let (mut host, known, [(i, _), (j, b)]) = live();
        write(&host.work_dir(i, &stray(i)).join("work.xfs"), "");
        let detail = sole_orphan(host.observe(&known), "work file");
        assert!(detail.ends_with(&stray(i)), "{detail}");
        // An unenrolled instance's directory, and a file where a directory belongs.
        let (mut host, known, _) = live();
        mkdir(&host.roots.work_base.join(Id128::from_bytes([9; 16]).to_string()));
        sole_orphan(host.observe(&known), "work file");
        let (mut host, known, _) = live();
        std::fs::remove_dir_all(host.work_dir(j, &host_name(j, b))).unwrap();
        write(&host.work_dir(j, &host_name(j, b)), "");
        sole_orphan(host.observe(&known), "work file");
    }

    #[test]
    fn offline_walk_skips_a_process_that_exits_mid_walk() {
        let (mut host, known, pairs) = live();
        let proc = proc_dir(&host);
        // Listed, then gone before its cgroup was read; or after it, before its comm.
        mkdir(&proc.join("5000"));
        write(&proc.join("5001/cgroup"), "0::/system.slice/x.service\n");
        assert_eq!(
            host.observe(&known),
            OfflineObservation::Observed {
                explained: pairs.into_iter().collect(),
                orphans: vec![],
            }
        );
        // Non-numeric entries of /proc are not processes.
        mkdir(&proc.join("sys"));
        write(&proc.join("meminfo"), "");
        assert!(matches!(
            host.observe(&known),
            OfflineObservation::Observed { ref orphans, .. } if orphans.is_empty()
        ));
    }

    #[test]
    fn offline_walk_is_unknown_when_any_source_cannot_be_read() {
        // An owned base that cannot be listed: never an empty one.
        let (mut host, known, _) = live();
        std::fs::remove_dir_all(&host.roots.work_base).unwrap();
        write(&host.roots.work_base, "");
        let OfflineObservation::Unknown { reason } = host.observe(&known) else {
            panic!("an unreadable work base is not observed");
        };
        assert!(reason.contains("work"), "{reason}");
        // A process whose cgroup cannot be read for a reason other than its exit.
        let (mut host, known, _) = live();
        mkdir(&proc_dir(&host).join("6000/cgroup"));
        assert!(matches!(host.observe(&known), OfflineObservation::Unknown { .. }));
        // A process with no cgroup2 membership cannot be placed.
        let (mut host, known, _) = live();
        host.process(6001, "", "x");
        write(&proc_dir(&host).join("6001/cgroup"), "1:name=systemd:/\n");
        assert!(matches!(host.observe(&known), OfflineObservation::Unknown { .. }));
        // Malformed mountinfo, and a loop attribute that cannot be read.
        let (mut host, known, _) = live();
        host.mounts.push("garbage".into());
        assert!(matches!(host.observe(&known), OfflineObservation::Unknown { .. }));
        let (mut host, known, _) = live();
        mkdir(&host.roots.sys_block.join("loop50/loop/backing_file"));
        assert!(matches!(host.observe(&known), OfflineObservation::Unknown { .. }));
        // A listing over its bound.
        let (mut host, known, [(i, _), _]) = live();
        let instance = host.roots.work_base.join(i.to_string());
        for n in 0..super::super::journal::MAX_ACTIVE_LISTED + 9 {
            write(&instance.join(format!("x{n}")), "");
        }
        let OfflineObservation::Unknown { reason } = host.observe(&known) else {
            panic!("an overflowing listing is not observed");
        };
        assert!(reason.contains("listing bound"), "{reason}");
    }

    #[test]
    fn fake_directory_offline_walk_turns_unknown_names_into_orphans() {
        let temp = tempfile::tempdir().unwrap();
        let (i, a, b) = (
            Id128::from_bytes([1; 16]),
            Id128::from_bytes([2; 16]),
            Id128::from_bytes([3; 16]),
        );
        let backend = ObservationBackend::FakeDirectory(temp.path().to_path_buf());
        mkdir(&fake::allocation_dir(temp.path(), i, a));
        mkdir(&fake::allocation_dir(temp.path(), i, b));
        let OfflineObservation::Observed { explained, orphans } =
            backend.observe_offline(&[(i, vec![a])].into())
        else {
            panic!("not observed");
        };
        assert_eq!(explained, [(i, a)].into());
        assert_eq!(orphans.len(), 1);
        assert!(orphans[0].detail.contains(&b.to_string()), "{orphans:?}");
    }

    #[test]
    fn fake_directory_distinguishes_absent_present_and_unexplained_names() {
        let temp = tempfile::tempdir().unwrap();
        let (i, a) = (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]));
        let backend = ObservationBackend::FakeDirectory(temp.path().to_path_buf());
        assert_eq!(
            backend.observe_allocation(i, a, &[]),
            NamespaceObservation::Absent
        );
        let directory = fake::allocation_dir(temp.path(), i, a);
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(
            backend.observe_allocation(i, a, &[]),
            NamespaceObservation::Present {
                names: vec![".".into()]
            }
        );
        std::fs::write(directory.join("work.xfs"), b"").unwrap();
        assert_eq!(
            backend.observe_allocation(i, a, &[]),
            NamespaceObservation::Present {
                names: vec!["work.xfs".into()]
            }
        );
        assert_eq!(
            backend.observe_node(i, &[]),
            NodeObservation::Observed {
                allocations: [a].into()
            }
        );
        std::fs::create_dir(temp.path().join(i.to_string()).join("looks-like-mine")).unwrap();
        assert!(matches!(
            backend.observe_node(i, &[]),
            NodeObservation::Unknown { .. }
        ));
    }
}
