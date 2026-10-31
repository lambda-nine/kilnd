//! Who may hold an instance. Root enrolls an instance with the systemd unit and the
//! installed kilnd image allowed to serve it, and AttachInstance proves the connecting
//! process is that service: right UID, exactly that unit's cgroup, and that executable
//! by device, inode and digest. Nothing a same-UID process can read or copy takes part.
//! A database UUID is a reconciliation identifier here, never a credential.
//!
//! L collects this evidence, because H performs no `/proc` or hashing work. The pin is
//! H's half: the connector's own pidfd, which proves L looked at that exact process.
use super::executable::{self, ExecutableError, WalkPolicy};
use crate::model::{Digest, Id128};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// `kilnd-helper enroll`'s default image: the one ExecStart runs.
pub const DEFAULT_KILND_PATH: &str = "/usr/local/bin/kilnd";
const DEFAULT_SLICE: &str = "/system.slice";
const MAX_UNIT_NAME: usize = 128;
const MAX_CGROUP_PATH: usize = 512;
/// More than any `/proc/<pid>` text this reads.
#[cfg(target_os = "linux")]
const MAX_PROC_READ: usize = 64 * 1024;

/// The installed kilnd image an instance runs. Compared whole, never by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledExecutable {
    pub st_dev: u64,
    pub st_ino: u64,
    pub bytes: u64,
    pub sha256: Digest,
}

/// One root-enrolled instance, as the ledger stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub instance_id: Id128,
    pub unit: String,
    pub cgroup: String,
    pub executable: EnrolledExecutable,
}

/// A systemd service unit's plain name: one path component, nothing to traverse.
pub fn validate_unit(unit: &str) -> Result<(), String> {
    let stem = unit
        .strip_suffix(".service")
        .ok_or("the unit must be a .service")?;
    let plain = stem
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@'));
    if stem.is_empty() || unit.len() > MAX_UNIT_NAME || !plain || stem.starts_with('.') {
        return Err("invalid systemd unit name".into());
    }
    Ok(())
}

/// The exact cgroup a unit runs in: its own leaf, under the default slice unless root
/// names another. Absolute, normalized, and it must end in that unit.
pub fn unit_cgroup(unit: &str, explicit: Option<&str>) -> Result<String, String> {
    validate_unit(unit)?;
    let cgroup = match explicit {
        Some(path) => path.to_string(),
        None => format!("{DEFAULT_SLICE}/{unit}"),
    };
    let components: Vec<&str> = cgroup
        .strip_prefix('/')
        .ok_or("a cgroup path must be absolute")?
        .split('/')
        .collect();
    let printable = cgroup
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'\\' && b != b'"');
    if cgroup.len() > MAX_CGROUP_PATH
        || !printable
        || components
            .iter()
            .any(|c| c.is_empty() || *c == "." || *c == "..")
        || components.last() != Some(&unit)
    {
        return Err("the cgroup must be a normalized path ending in the unit".into());
    }
    Ok(cgroup)
}

/// The installed image to enroll, read through the protected walk: a root-owned path no
/// one else can write, a single-link regular file with no ACL, capability, setuid or
/// setgid, hashed from the descriptor that was checked.
pub fn read_installed_kilnd(
    policy: &WalkPolicy,
    path: &Path,
) -> Result<EnrolledExecutable, ExecutableError> {
    let file = executable::open_protected_program(policy, path)?;
    let meta = file
        .metadata()
        .map_err(|e| ExecutableError::Descriptor(e.to_string()))?;
    Ok(EnrolledExecutable {
        st_dev: meta.dev(),
        st_ino: meta.ino(),
        bytes: meta.len(),
        sha256: executable::hash_descriptor(&file, meta.len())?,
    })
}

/// Why a peer is not the enrolled service. Details stay in the helper's log: the peer
/// only learns it was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PeerRefusal {
    #[error("the peer process is gone or could not be read: {0}")]
    Unreadable(String),
    #[error("the peer does not run as the service account")]
    Uid,
    #[error("the peer is not in the enrolled unit's cgroup")]
    Cgroup,
    #[error("the peer is not running the enrolled kilnd image")]
    Executable,
    #[error("the peer changed while it was being checked")]
    Changed,
}

/// What can be read about a process without hashing anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerFacts {
    /// Real, effective, saved and filesystem UIDs.
    pub uids: [u32; 4],
    pub cgroup: String,
    pub start_time: u64,
}

/// The cheap half of the decision, in the order the checks run.
pub fn check_facts(
    facts: &PeerFacts,
    service_uid: u32,
    enrollment: &Enrollment,
) -> Result<(), PeerRefusal> {
    if facts.uids.iter().any(|uid| *uid != service_uid) {
        return Err(PeerRefusal::Uid);
    }
    // Exact: a child cgroup of the unit is not the unit.
    if facts.cgroup != enrollment.cgroup {
        return Err(PeerRefusal::Cgroup);
    }
    Ok(())
}

/// The running image's identity, stat fields first so only the enrolled inode is hashed.
pub fn check_image(
    actual: &ImageStat,
    enrollment: &Enrollment,
    digest: impl FnOnce() -> Result<Digest, String>,
) -> Result<(), PeerRefusal> {
    let expected = &enrollment.executable;
    if actual.st_dev != expected.st_dev
        || actual.st_ino != expected.st_ino
        || actual.bytes != expected.bytes
    {
        return Err(PeerRefusal::Executable);
    }
    if digest().map_err(PeerRefusal::Unreadable)? != expected.sha256 {
        return Err(PeerRefusal::Executable);
    }
    Ok(())
}

/// A descriptor's stat identity. The time fields key the digest memo only: a write or
/// replacement on the same inode changes them, and the next attach hashes again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImageStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub bytes: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

impl ImageStat {
    fn of(file: &File) -> io::Result<Self> {
        let meta = file.metadata()?;
        Ok(Self {
            st_dev: meta.dev(),
            st_ino: meta.ino(),
            bytes: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

/// The parser for `/proc/<pid>/cgroup`: cgroup v2's single `0::` line and nothing else.
/// A hybrid hierarchy has no one answer to "which unit", so it refuses.
pub fn parse_cgroup(content: &str) -> Option<&str> {
    let mut lines = content.lines();
    let path = lines.next()?.strip_prefix("0::")?;
    if lines.next().is_some() || !path.starts_with('/') {
        return None;
    }
    Some(path)
}

/// `Uid:` from `/proc/<pid>/status`: real, effective, saved, filesystem.
pub fn parse_ids(status: &str, field: &str) -> Option<[u32; 4]> {
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))?;
    let mut ids = values.split_whitespace().map(|id| id.parse().ok());
    let parsed = [ids.next()??, ids.next()??, ids.next()??, ids.next()??];
    ids.next().is_none().then_some(parsed)
}

/// Field 22 of `/proc/<pid>/stat`. The command name may hold spaces and parentheses.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let tail = &stat[stat.rfind(')')? + 1..];
    tail.split_whitespace().nth(19)?.parse().ok()
}

/// The peer process being examined. On Linux this holds both a pidfd and a `/proc/<pid>`
/// directory descriptor. The directory stops answering when that process dies, even if
/// the number is reused, and a pidfd still alive afterward ties it to the process opened.
struct ProcessView {
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    directory: File,
    #[cfg(not(target_os = "linux"))]
    pid: i32,
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn open_pidfd(pid: i32) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    pub(super) fn pidfd_alive(fd: RawFd) -> bool {
        // SAFETY: signal 0 only checks existence, and the null info pointer is allowed.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) == 0
        }
    }

    impl ProcessView {
        pub(super) fn open(pid: i32) -> io::Result<Self> {
            let pidfd = open_pidfd(pid)?;
            let path = CString::new(format!("/proc/{pid}")).unwrap();
            // SAFETY: the path is NUL-terminated and the flags are valid for open.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                pidfd,
                // SAFETY: open returned a new descriptor that nothing else owns.
                directory: unsafe { File::from_raw_fd(fd) },
            })
        }

        fn open_entry(&self, name: &str, flags: libc::c_int) -> io::Result<File> {
            let name = CString::new(name).unwrap();
            // SAFETY: the directory is live and name is NUL-terminated.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: openat returned a new descriptor that nothing else owns.
            Ok(unsafe { File::from_raw_fd(fd) })
        }

        fn read_entry(&self, name: &str) -> io::Result<String> {
            let mut text = String::new();
            self.open_entry(name, libc::O_RDONLY)?
                .take(MAX_PROC_READ as u64)
                .read_to_string(&mut text)?;
            Ok(text)
        }

        pub(super) fn facts(&self) -> io::Result<PeerFacts> {
            let invalid = |what: &str| io::Error::other(format!("malformed {what}"));
            let status = self.read_entry("status")?;
            let cgroup = self.read_entry("cgroup")?;
            let stat = self.read_entry("stat")?;
            Ok(PeerFacts {
                uids: parse_ids(&status, "Uid").ok_or_else(|| invalid("status"))?,
                // No unified line is a hierarchy this contract does not recognize.
                cgroup: parse_cgroup(&cgroup).unwrap_or_default().to_string(),
                start_time: parse_start_time(&stat).ok_or_else(|| invalid("stat"))?,
            })
        }

        /// `/proc/<pid>/exe` is a ptrace-read check, and the helper's bounding set has
        /// no CAP_SYS_PTRACE. Taking the peer's filesystem IDs for this one open
        /// satisfies that check without adding a capability to the service.
        pub(super) fn open_image(&self) -> io::Result<File> {
            let status = self.read_entry("status")?;
            let invalid = || io::Error::other("malformed status");
            let [_, _, _, fsuid] = parse_ids(&status, "Uid").ok_or_else(invalid)?;
            let [_, _, _, fsgid] = parse_ids(&status, "Gid").ok_or_else(invalid)?;
            // SAFETY: these change only this thread's filesystem IDs, and return the
            // previous ones, which are restored before any other file is opened.
            let (old_uid, old_gid) = unsafe { (libc::setfsuid(fsuid), libc::setfsgid(fsgid)) };
            let image = self.open_entry("exe", libc::O_RDONLY);
            // SAFETY: as above, restoring the IDs read just now.
            unsafe {
                libc::setfsgid(old_gid as libc::gid_t);
                libc::setfsuid(old_uid as libc::uid_t);
            }
            image
        }

        pub(super) fn still_alive(&self) -> bool {
            pidfd_alive(self.pidfd.as_raw_fd())
        }
    }
}

/// macOS builds and tests kilnd but never runs this service, so it reads the same facts
/// from `proc_pidinfo`. There is no cgroup: production refuses without one, and tests
/// supply it. The evidence below is real process evidence on both platforms.
#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use crate::helper::firecracker::workers::{ProcessState, process_state};
    use std::os::unix::ffi::OsStrExt;

    impl ProcessView {
        pub(super) fn open(pid: i32) -> io::Result<Self> {
            Ok(Self { pid })
        }

        pub(super) fn facts(&self) -> io::Result<PeerFacts> {
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            // SAFETY: info is writable and exactly the size given.
            let read = unsafe {
                libc::proc_pidinfo(
                    self.pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    (&mut info as *mut libc::proc_bsdinfo).cast(),
                    size,
                )
            };
            if read != size {
                return Err(io::Error::last_os_error());
            }
            Ok(PeerFacts {
                uids: [info.pbi_ruid, info.pbi_uid, info.pbi_svuid, info.pbi_uid],
                cgroup: String::new(),
                start_time: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
            })
        }

        pub(super) fn open_image(&self) -> io::Result<File> {
            let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            // SAFETY: path is writable and exactly the size given.
            let len = unsafe {
                libc::proc_pidpath(self.pid, path.as_mut_ptr().cast(), path.len() as u32)
            };
            if len <= 0 {
                return Err(io::Error::last_os_error());
            }
            path.truncate(len as usize);
            File::open(std::ffi::OsStr::from_bytes(&path))
        }

        pub(super) fn still_alive(&self) -> bool {
            matches!(process_state(self.pid), ProcessState::Running { .. })
        }
    }
}

/// The digest fixtures assume for their own unhashed test binary.
#[cfg(test)]
pub fn fixture_digest() -> Digest {
    Digest::of(b"fixture test image")
}

/// How tests stand in for a cgroup on hosts where the test can't place a process in one.
/// The rest of the evidence stays real. Compiled out of production.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct TestPeers {
    /// `<directory>/<pid>` holds that process's cgroup path. A missing file means none.
    pub directory: Option<std::path::PathBuf>,
    /// Instances the fixture auto-enrolled accept this process in their own cgroup.
    pub any_cgroup: bool,
    /// A debug test binary takes seconds to hash under an unoptimized SHA-256, once per
    /// helper per attach path. Fixtures take this digest for it, and everything else
    /// about the image stays real. The tests below hash real small images.
    pub assumed_digest: Option<Digest>,
}

/// L's half of attachment. It remembers the digest of the enrolled inode by its stat
/// identity, so a holder that keeps reattaching cannot make L hash its image each time.
#[derive(Debug)]
pub struct PeerAttestor {
    service_uid: u32,
    memo: HashMap<ImageStat, Digest>,
    #[cfg(test)]
    test: TestPeers,
}

impl PeerAttestor {
    pub fn new(service_uid: u32) -> Self {
        Self {
            service_uid,
            memo: HashMap::new(),
            #[cfg(test)]
            test: TestPeers::default(),
        }
    }

    #[cfg(test)]
    pub fn with_test_peers(service_uid: u32, test: TestPeers) -> Self {
        Self {
            test,
            ..Self::new(service_uid)
        }
    }

    #[cfg(test)]
    fn observed_cgroup(&self, pid: i32, real: String, enrollment: &Enrollment) -> String {
        if self.test.any_cgroup {
            return enrollment.cgroup.clone();
        }
        match &self.test.directory {
            Some(directory) => {
                std::fs::read_to_string(directory.join(pid.to_string())).unwrap_or_default()
            }
            None => real,
        }
    }

    #[cfg(not(test))]
    fn observed_cgroup(&self, _pid: i32, real: String, _enrollment: &Enrollment) -> String {
        real
    }

    /// Proves that `pid`, right now, is the enrolled service, and returns its start
    /// time. Every read goes through one process view, which must still be the same
    /// live process afterward, so a reused number cannot lend its identity.
    pub fn attest(&mut self, pid: i32, enrollment: &Enrollment) -> Result<u64, PeerRefusal> {
        let unreadable = |error: io::Error| PeerRefusal::Unreadable(error.to_string());
        let view = ProcessView::open(pid).map_err(unreadable)?;
        let mut facts = view.facts().map_err(unreadable)?;
        facts.cgroup = self.observed_cgroup(pid, facts.cgroup, enrollment);
        check_facts(&facts, self.service_uid, enrollment)?;
        let image = view.open_image().map_err(unreadable)?;
        let stat = ImageStat::of(&image).map_err(unreadable)?;
        #[cfg(test)]
        let assumed = self.test.assumed_digest;
        #[cfg(not(test))]
        let assumed: Option<Digest> = None;
        let memo = &mut self.memo;
        check_image(&stat, enrollment, || {
            if let Some(digest) = assumed.or_else(|| memo.get(&stat).copied()) {
                return Ok(digest);
            }
            let digest =
                executable::hash_descriptor(&image, stat.bytes).map_err(|e| e.to_string())?;
            // Only an inode that already matched gets here, so this stays small.
            memo.insert(stat, digest);
            Ok(digest)
        })?;
        let after = view.facts().map_err(unreadable)?;
        if after.start_time != facts.start_time || after.uids != facts.uids || !view.still_alive() {
            return Err(PeerRefusal::Changed);
        }
        Ok(facts.start_time)
    }
}

/// The socket option's value on every architecture this runs on (asm-generic).
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: libc::c_int = 77;

/// H's hold on the process that made this connection. SO_PEERCRED's number alone could
/// belong to a later process by the time L reads `/proc`. A connector whose pidfd is
/// still alive after L answers has held that number throughout, so L read that process.
#[derive(Debug)]
pub struct PeerPin {
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl PeerPin {
    /// Refuses on a kernel older than 6.5: no pidfd for the connector, no attachment.
    pub fn of_connection(stream: RawFd) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        let mut fd: libc::c_int = -1;
        let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: fd and size are live, writable and correctly sized.
        let rc = unsafe {
            libc::getsockopt(
                stream,
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&mut fd as *mut libc::c_int).cast(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if fd < 0 {
            return Err(io::Error::other("the connecting process has no pidfd"));
        }
        Ok(Self {
            // SAFETY: the kernel returned a new descriptor that nothing else owns.
            pidfd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
        })
    }

    pub fn alive(&self) -> bool {
        use std::os::fd::AsRawFd;
        platform::pidfd_alive(self.pidfd.as_raw_fd())
    }
}

/// macOS is a development host only. Its stand-in pins nothing, so production refuses it
/// outright, and a test build carries the process-liveness half through L's checks.
#[cfg(not(target_os = "linux"))]
impl PeerPin {
    #[cfg(test)]
    pub fn of_connection(_stream: RawFd) -> io::Result<Self> {
        Ok(Self {})
    }

    #[cfg(not(test))]
    pub fn of_connection(_stream: RawFd) -> io::Result<Self> {
        Err(io::Error::other("instance attachment needs Linux"))
    }

    pub fn alive(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment() -> Enrollment {
        Enrollment {
            instance_id: Id128::from_bytes([7; 16]),
            unit: "kilnd.service".into(),
            cgroup: "/system.slice/kilnd.service".into(),
            executable: EnrolledExecutable {
                st_dev: 1,
                st_ino: 2,
                bytes: 3,
                sha256: Digest::of(b"kilnd"),
            },
        }
    }

    fn facts() -> PeerFacts {
        PeerFacts {
            uids: [990; 4],
            cgroup: "/system.slice/kilnd.service".into(),
            start_time: 100,
        }
    }

    fn stat() -> ImageStat {
        ImageStat {
            st_dev: 1,
            st_ino: 2,
            bytes: 3,
            mtime: (0, 0),
            ctime: (0, 0),
        }
    }

    #[test]
    fn b3_01_every_uid_and_the_exact_cgroup_must_match() {
        assert_eq!(check_facts(&facts(), 990, &enrollment()), Ok(()));
        for slot in 0..4 {
            let mut other = facts();
            other.uids[slot] = 991;
            assert_eq!(
                check_facts(&other, 990, &enrollment()),
                Err(PeerRefusal::Uid),
                "{slot}"
            );
        }
        for cgroup in [
            "/system.slice/kilnd.service/child",
            "/system.slice",
            "/system.slice/other.service",
            "/system.slice/kilnd.service (deleted)",
            "",
        ] {
            let mut other = facts();
            other.cgroup = cgroup.into();
            assert_eq!(
                check_facts(&other, 990, &enrollment()),
                Err(PeerRefusal::Cgroup),
                "{cgroup}"
            );
        }
    }

    #[test]
    fn b3_01_image_compares_device_inode_size_and_digest_and_hashes_last() {
        let right = || Ok(Digest::of(b"kilnd"));
        assert_eq!(check_image(&stat(), &enrollment(), right), Ok(()));
        for wrong in [
            ImageStat {
                st_dev: 9,
                ..stat()
            },
            ImageStat {
                st_ino: 9,
                ..stat()
            },
            ImageStat { bytes: 9, ..stat() },
        ] {
            // A stat mismatch refuses without hashing whatever the peer is running.
            let result = check_image(&wrong, &enrollment(), || panic!("hashed a stranger"));
            assert_eq!(result, Err(PeerRefusal::Executable));
        }
        assert_eq!(
            check_image(&stat(), &enrollment(), || Ok(Digest::of(b"other"))),
            Err(PeerRefusal::Executable)
        );
    }

    #[test]
    fn b3_01_proc_parsers_accept_only_the_expected_shapes() {
        assert_eq!(parse_cgroup("0::/a/b.service\n"), Some("/a/b.service"));
        assert_eq!(parse_cgroup("1:name=systemd:/a\n0::/b\n"), None);
        assert_eq!(parse_cgroup("0::/a\n1:cpu:/b\n"), None);
        assert_eq!(parse_cgroup("0::relative\n"), None);
        assert_eq!(parse_cgroup(""), None);
        assert_eq!(
            parse_ids("Name:\tx\nUid:\t1\t2\t3\t4\nGid:\t5\t6\t7\t8\n", "Uid"),
            Some([1, 2, 3, 4])
        );
        assert_eq!(parse_ids("Uid:\t1\t2\t3\n", "Uid"), None);
        assert_eq!(parse_ids("Uid:\t1\t2\t3\t4\t5\n", "Uid"), None);
        // A hostile command name cannot move the fields.
        let fields = (3..=21)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            parse_start_time(&format!("1 (a) b) c) {fields} 777 23")),
            Some(777)
        );
        assert_eq!(parse_start_time("1 (a)"), None);
    }

    #[test]
    fn b3_01_unit_names_and_cgroup_paths_cannot_traverse() {
        assert_eq!(
            unit_cgroup("kilnd.service", None).unwrap(),
            "/system.slice/kilnd.service"
        );
        assert_eq!(
            unit_cgroup("kilnd@a.service", Some("/app.slice/kilnd@a.service")).unwrap(),
            "/app.slice/kilnd@a.service"
        );
        for unit in [
            "kilnd",
            ".service",
            "../x.service",
            "a/b.service",
            "a b.service",
            "..service",
        ] {
            assert!(unit_cgroup(unit, None).is_err(), "{unit}");
        }
        for path in [
            "relative/kilnd.service",
            "/a/../kilnd.service",
            "/a//kilnd.service",
            "/a/other.service",
            "/a/kilnd.service/",
            "/a b/kilnd.service",
        ] {
            assert!(unit_cgroup("kilnd.service", Some(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn b3_01_attestor_hashes_a_real_process_image_and_refuses_what_differs() {
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let image = wait_for_image(pid);
        let meta = image.metadata().unwrap();
        let mut right = enrollment();
        right.executable = EnrolledExecutable {
            st_dev: meta.dev(),
            st_ino: meta.ino(),
            bytes: meta.len(),
            sha256: executable::hash_descriptor(&image, meta.len()).unwrap(),
        };
        let test = TestPeers {
            directory: None,
            any_cgroup: true,
            assumed_digest: None,
        };
        let mut attestor = PeerAttestor::with_test_peers(uid, test.clone());
        assert!(attestor.attest(pid, &right).is_ok());
        assert!(attestor.attest(pid, &right).is_ok(), "the memo answers");
        assert_eq!(attestor.memo.len(), 1);

        // The real digest is compared, even for the inode the memo knows.
        let mut other_digest = right.clone();
        other_digest.executable.sha256 = Digest::of(b"other");
        assert_eq!(
            attestor.attest(pid, &other_digest),
            Err(PeerRefusal::Executable)
        );
        let mut other_inode = right.clone();
        other_inode.executable.st_ino += 1;
        assert_eq!(
            attestor.attest(pid, &other_inode),
            Err(PeerRefusal::Executable)
        );
        let mut other_uid = PeerAttestor::with_test_peers(uid + 1, test);
        assert_eq!(other_uid.attest(pid, &right), Err(PeerRefusal::Uid));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(matches!(
            attestor.attest(pid, &right),
            Err(PeerRefusal::Unreadable(_))
        ));
    }

    /// A fork that hasn't reached its exec yet still shows the parent's image.
    fn wait_for_image(pid: i32) -> File {
        let sleep = std::fs::metadata("/bin/sleep").unwrap();
        for _ in 0..1000 {
            if let Ok(view) = ProcessView::open(pid)
                && let Ok(image) = view.open_image()
                && image.metadata().is_ok_and(|meta| meta.ino() == sleep.ino())
            {
                return image;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("the child never ran /bin/sleep");
    }

    /// Real `/proc` evidence for a real child, and what is left once it is gone.
    #[cfg(target_os = "linux")]
    #[test]
    fn b3_01_linux_evidence_is_real_and_a_dead_process_refuses() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let view = ProcessView::open(pid).unwrap();
        let facts = view.facts().unwrap();
        // SAFETY: geteuid has no preconditions.
        assert_eq!(facts.uids, [unsafe { libc::geteuid() }; 4]);
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        assert_eq!(facts.cgroup, parse_cgroup(&own).unwrap_or_default());
        let sleep = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let on_disk = std::fs::metadata(&sleep).unwrap();
        let image = ImageStat::of(&view.open_image().unwrap()).unwrap();
        assert_eq!(
            (image.st_dev, image.st_ino),
            (on_disk.dev(), on_disk.ino()),
            "the exe descriptor is the running inode"
        );
        assert!(view.still_alive());
        child.kill().unwrap();
        child.wait().unwrap();
        // The same view, and the same number, no longer answer for a reaped process.
        assert!(!view.still_alive());
        assert!(view.facts().is_err());
        assert!(view.open_image().is_err());
        assert!(ProcessView::open(pid).is_err());
    }
}
