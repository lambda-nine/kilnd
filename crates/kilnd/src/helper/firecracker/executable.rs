//! Section 3.4: one protected store and descriptor handoff for every executable in
//! the Firecracker chain. A pathname is never execution authority. Installed objects
//! are found by a no-symlink walk from an opened root, hashed through the same
//! descriptor and retained; replacing a source or installed name cannot redirect
//! them. B3 launches nothing: `exec_retained` is exercised only by privileged tests.
use crate::model::Digest;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Far more than any real store path needs; the table retains one handle per component.
const MAX_COMPONENTS: usize = 32;
/// The contract's executable bound.
pub const MAX_EXECUTABLE_BYTES: u64 = 1 << 30;
/// A retained bootstrap record is a fixed 4 KiB message.
pub const MAX_BOOTSTRAP_BYTES: usize = 4096;
/// `J` bootstrap descriptors, frozen by the contract's handoff section.
pub const VMM_FD: RawFd = 3;
pub const CONTROL_FD: RawFd = 4;
pub const JAILER_EXEC_FD_MIN: RawFd = 5;

/// Every host executable the chain may run. The B1 contract declares no separate
/// worker image: L/P/S/R/D/M/K are fork-only modes of `KilndHelper`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "jailer")]
    Jailer,
    #[serde(rename = "firecracker")]
    Firecracker,
    #[serde(rename = "mkfs.xfs")]
    MkfsXfs,
    #[serde(rename = "kilnd-helper")]
    KilndHelper,
}

impl Role {
    pub const ALL: [Self; 4] = [
        Self::Jailer,
        Self::Firecracker,
        Self::MkfsXfs,
        Self::KilndHelper,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jailer => "jailer",
            Self::Firecracker => "firecracker",
            Self::MkfsXfs => "mkfs.xfs",
            Self::KilndHelper => "kilnd-helper",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }
}

/// The fork-only worker modes. Each runs the inherited verified helper image, and
/// the journal records that image as its executable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkerMode {
    Ledger,
    Prep,
    Supervisor,
    Relay,
    Drainer,
    Monitor,
    Recovery,
}

impl WorkerMode {
    pub const ALL: [Self; 7] = [
        Self::Ledger,
        Self::Prep,
        Self::Supervisor,
        Self::Relay,
        Self::Drainer,
        Self::Monitor,
        Self::Recovery,
    ];
}

/// The node-local tuple that identifies one installed object. Device and inode come
/// only from verified installed descriptors, never from a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub role: Role,
    pub st_dev: u64,
    pub st_ino: u64,
    pub bytes: u64,
    pub sha256: Digest,
    pub installation_generation: u64,
}

impl ExecutableIdentity {
    pub fn substitution(&self) -> serde_json::Value {
        serde_json::json!({
            "role": self.role.as_str(),
            "st_dev": self.st_dev,
            "st_ino": self.st_ino,
            "bytes": self.bytes,
            "sha256": self.sha256.to_string(),
            "installation_generation": self.installation_generation,
        })
    }
}

/// What actually ran: expected and observed tuples are compared field by field, so
/// matching argv or an earlier digest is never sufficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecObservation {
    pub expected: ExecutableIdentity,
    pub actual: ExecutableIdentity,
}

/// The catalog's pin for one role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutablePin {
    pub role: Role,
    pub bytes: u64,
    pub sha256: Digest,
    pub installation_generation: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutableError {
    #[error("unsafe executable ancestry: {0}")]
    Ancestry(String),
    #[error("executable refused: {0}")]
    Object(String),
    #[error("executable identity mismatch: {0}")]
    Mismatch(String),
    #[error("descriptor generation is unusable: {0}")]
    Descriptor(String),
    #[error("{0}")]
    Io(String),
}

fn io_error(what: &str, error: io::Error) -> ExecutableError {
    ExecutableError::Io(format!("{what}: {error}"))
}

/// How ancestry is judged. Production always starts at `/`, requires root ownership
/// and enforces ACL checks; the two weaker settings exist only under `cfg(test)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkPolicy {
    pub(super) owner_uid: u32,
    anchor: Anchor,
    acls: Acls,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Anchor {
    Slash,
    #[cfg(test)]
    TestRoot(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Acls {
    Enforce,
    /// Unprivileged tests: a private test directory may be on a filesystem without
    /// these xattrs. The Linux root tests below enforce them for real from `/`.
    #[cfg(test)]
    TestSkip,
}

impl WalkPolicy {
    pub fn production() -> Self {
        Self {
            owner_uid: 0,
            anchor: Anchor::Slash,
            acls: Acls::Enforce,
        }
    }

    /// Unprivileged tests walk from a private directory, as the current UID. The
    /// Linux root tests use `production()`.
    #[cfg(test)]
    pub fn test_rooted(root: &Path) -> Self {
        Self {
            owner_uid: unsafe { libc::geteuid() },
            anchor: Anchor::TestRoot(root.to_path_buf()),
            acls: Acls::TestSkip,
        }
    }
}

fn open_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: parent is live, name is NUL-terminated and flags are valid.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_anchor(path: &Path) -> Result<File, ExecutableError> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ExecutableError::Ancestry("path contains NUL".into()))?;
    // SAFETY: name is NUL-terminated and flags are valid for open.
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error("open walk anchor", io::Error::last_os_error()));
    }
    // SAFETY: open returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn xattr_present(file: &File, name: &CStr) -> Result<bool, ExecutableError> {
    // SAFETY: file and name are live; a null buffer with size 0 only asks for size.
    let rc = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if rc >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA) => Ok(false),
        // An unsupported permission check is a refusal, not an empty answer.
        _ => Err(ExecutableError::Ancestry(format!(
            "cannot verify {}: {error}",
            name.to_string_lossy()
        ))),
    }
}

/// No access or default POSIX ACL may exist on any store ancestor or object. A
/// minimal mode-only ACL is not stored as an xattr, so presence means extended.
fn check_acls(file: &File, policy: &WalkPolicy, directory: bool) -> Result<(), ExecutableError> {
    match policy.acls {
        Acls::Enforce => {
            #[cfg(target_os = "linux")]
            {
                if xattr_present(file, c"system.posix_acl_access")?
                    || (directory && xattr_present(file, c"system.posix_acl_default")?)
                {
                    return Err(ExecutableError::Ancestry(
                        "extended ACL present on a protected object".into(),
                    ));
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (file, directory);
                Err(ExecutableError::Ancestry(
                    "ACL checks are unsupported on this platform".into(),
                ))
            }
        }
        #[cfg(test)]
        Acls::TestSkip => Ok(()),
    }
}

/// File capabilities would give a verified image authority beyond its bytes.
fn check_capabilities(file: &File, policy: &WalkPolicy) -> Result<(), ExecutableError> {
    match policy.acls {
        Acls::Enforce => {
            #[cfg(target_os = "linux")]
            {
                if xattr_present(file, c"security.capability")? {
                    return Err(ExecutableError::Object("file capabilities present".into()));
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = file;
                Err(ExecutableError::Object(
                    "capability checks are unsupported on this platform".into(),
                ))
            }
        }
        #[cfg(test)]
        Acls::TestSkip => Ok(()),
    }
}

fn check_directory(file: &File, policy: &WalkPolicy, label: &str) -> Result<(), ExecutableError> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("inspect ancestor", e))?;
    if !meta.is_dir() {
        return Err(ExecutableError::Ancestry(format!(
            "{label} is not a directory"
        )));
    }
    if meta.uid() != policy.owner_uid {
        return Err(ExecutableError::Ancestry(format!(
            "{label} is owned by uid {}",
            meta.uid()
        )));
    }
    // A group- or world-writable parent grants rename authority over its children,
    // whoever owns them. The sticky bit does not make that safe enough here.
    if meta.mode() & 0o022 != 0 {
        return Err(ExecutableError::Ancestry(format!(
            "{label} is writable by a non-owner: mode {:o}",
            meta.mode() & 0o7777
        )));
    }
    check_acls(file, policy, true)
}

/// A pinned directory: every handle from the anchor down stays open so the tree the
/// walk validated is the tree later relative opens use.
#[derive(Debug)]
pub struct ProtectedDir {
    chain: Vec<File>,
    path: PathBuf,
}

impl ProtectedDir {
    pub fn file(&self) -> &File {
        self.chain.last().expect("a walk always has its anchor")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn raw_fds(&self) -> Vec<RawFd> {
        self.chain.iter().map(AsRawFd::as_raw_fd).collect()
    }
}

/// Walks `path` one no-follow component at a time from the policy's anchor.
pub fn walk_directory(policy: &WalkPolicy, path: &Path) -> Result<ProtectedDir, ExecutableError> {
    if !path.is_absolute() {
        return Err(ExecutableError::Ancestry("path must be absolute".into()));
    }
    let (anchor, relative): (File, &Path) = match &policy.anchor {
        Anchor::Slash => (
            open_anchor(Path::new("/"))?,
            path.strip_prefix("/").unwrap(),
        ),
        #[cfg(test)]
        Anchor::TestRoot(root) => (
            open_anchor(root)?,
            path.strip_prefix(root)
                .map_err(|_| ExecutableError::Ancestry("path outside walk anchor".into()))?,
        ),
    };
    check_directory(&anchor, policy, "walk anchor")?;
    let mut chain = vec![anchor];
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(ExecutableError::Ancestry(
                "path has a special component".into(),
            ));
        };
        if chain.len() >= MAX_COMPONENTS {
            return Err(ExecutableError::Ancestry("path is too deep".into()));
        }
        let name_c = component_name(name)?;
        let next = open_at(
            chain.last().unwrap().as_raw_fd(),
            &name_c,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
        .map_err(|e| ExecutableError::Ancestry(format!("{}: {e}", name.to_string_lossy())))?;
        check_directory(&next, policy, &name.to_string_lossy())?;
        chain.push(next);
    }
    Ok(ProtectedDir {
        chain,
        path: path.to_path_buf(),
    })
}

fn component_name(name: &OsStr) -> Result<CString, ExecutableError> {
    CString::new(name.as_bytes()).map_err(|_| ExecutableError::Ancestry("name contains NUL".into()))
}

/// Exactly one sha256 of `bytes` read by offset: retained descriptors are shared open
/// file descriptions, so the file offset is never used or changed.
pub fn hash_descriptor(file: &File, bytes: u64) -> Result<Digest, ExecutableError> {
    use std::os::unix::fs::FileExt;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|e| io_error("hash descriptor", e))?;
        if read == 0 {
            break;
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| ExecutableError::Object("offset overflow".into()))?;
        if offset > bytes {
            return Err(ExecutableError::Object(
                "object grew past its verified size".into(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if offset != bytes {
        return Err(ExecutableError::Object(
            "object is shorter than its verified size".into(),
        ));
    }
    Digest::parse(&format!("{:x}", hasher.finalize())).map_err(ExecutableError::Object)
}

/// Refuses scripts, other architectures and any dynamic closure: PT_INTERP or a
/// DT_NEEDED entry. This revision approves static images only.
pub fn check_static_elf(file: &File, bytes: u64) -> Result<(), ExecutableError> {
    use std::os::unix::fs::FileExt;
    let invalid = |why: &str| ExecutableError::Object(format!("not an approved static ELF: {why}"));
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, 0)
        .map_err(|_| invalid("short header"))?;
    if &header[..7] != b"\x7fELF\x02\x01\x01" {
        return Err(invalid("bad ident"));
    }
    if u16::from_le_bytes([header[18], header[19]]) != 183 {
        return Err(invalid("not EM_AARCH64"));
    }
    let phoff = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let phentsize = u64::from(u16::from_le_bytes([header[54], header[55]]));
    let phnum = u64::from(u16::from_le_bytes([header[56], header[57]]));
    if phentsize != 56 || phnum > 256 {
        return Err(invalid("program header shape"));
    }
    for index in 0..phnum {
        let start = index
            .checked_mul(56)
            .and_then(|at| at.checked_add(phoff))
            .filter(|at| at.checked_add(56).is_some_and(|end| end <= bytes))
            .ok_or_else(|| invalid("program header outside the file"))?;
        let mut entry = [0u8; 56];
        file.read_exact_at(&mut entry, start)
            .map_err(|_| invalid("short program header"))?;
        match u32::from_le_bytes(entry[..4].try_into().unwrap()) {
            3 => {
                return Err(ExecutableError::Object(
                    "dynamic closure unsupported: PT_INTERP present".into(),
                ));
            }
            2 => {
                // A static-PIE has PT_DYNAMIC without needed libraries.
                let offset = u64::from_le_bytes(entry[8..16].try_into().unwrap());
                let size = u64::from_le_bytes(entry[32..40].try_into().unwrap());
                if size > 64 * 1024
                    || offset.checked_add(size).is_none_or(|end| end > bytes)
                    || size % 16 != 0
                {
                    return Err(invalid("dynamic section shape"));
                }
                let mut dynamic = vec![0u8; size as usize];
                file.read_exact_at(&mut dynamic, offset)
                    .map_err(|_| invalid("short dynamic section"))?;
                for tag in dynamic.as_chunks::<16>().0 {
                    if u64::from_le_bytes(tag[..8].try_into().unwrap()) == 1 {
                        return Err(ExecutableError::Object(
                            "dynamic closure unsupported: DT_NEEDED present".into(),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn open_object(
    policy: &WalkPolicy,
    directory: &ProtectedDir,
    role: Role,
) -> Result<File, ExecutableError> {
    let name = component_name(OsStr::new(role.as_str()))?;
    // The contract's exact open flags: O_NONBLOCK makes a planted FIFO harmless.
    let file = open_at(
        directory.file().as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(|e| ExecutableError::Object(format!("{}: {e}", role.as_str())))?;
    check_object_meta(policy, &file, role)?;
    Ok(file)
}

fn check_object_meta(
    policy: &WalkPolicy,
    file: &File,
    role: Role,
) -> Result<std::fs::Metadata, ExecutableError> {
    let meta = file
        .metadata()
        .map_err(|e| ExecutableError::Descriptor(format!("{}: {e}", role.as_str())))?;
    let name = role.as_str();
    if !meta.is_file() {
        return Err(ExecutableError::Object(format!("{name} is not regular")));
    }
    if meta.uid() != policy.owner_uid {
        return Err(ExecutableError::Object(format!(
            "{name} is owned by uid {}",
            meta.uid()
        )));
    }
    // Exact mode: no writable alias and no setuid, setgid or sticky bits.
    if meta.permissions().mode() & 0o7777 != 0o555 {
        return Err(ExecutableError::Object(format!(
            "{name} mode is {:o}, not 0555",
            meta.permissions().mode() & 0o7777
        )));
    }
    if meta.nlink() != 1 {
        return Err(ExecutableError::Object(format!(
            "{name} has {} links",
            meta.nlink()
        )));
    }
    check_acls(file, policy, false)?;
    check_capabilities(file, policy)?;
    Ok(meta)
}

/// A program outside the digest store, such as the installed kilnd, under the same
/// protected traversal: root-owned, not writable by anyone else, single-link and regular,
/// with no setuid, setgid, sticky bit, ACL or file capability. The mode may keep root's
/// write bit, since installers use 0755 and root is the one writer it admits.
pub fn open_protected_program(policy: &WalkPolicy, path: &Path) -> Result<File, ExecutableError> {
    let parent = path
        .parent()
        .ok_or_else(|| ExecutableError::Object("the program path has no parent".into()))?;
    let name = path
        .file_name()
        .ok_or_else(|| ExecutableError::Object("the program path has no file name".into()))?;
    let directory = walk_directory(policy, parent)?;
    let name = component_name(name)?;
    let file = open_at(
        directory.file().as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(|e| ExecutableError::Object(format!("{}: {e}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| ExecutableError::Descriptor(format!("{}: {e}", path.display())))?;
    let mode = meta.permissions().mode() & 0o7777;
    if !meta.is_file()
        || meta.uid() != policy.owner_uid
        || mode & 0o7022 != 0
        || mode & 0o111 == 0
        || meta.nlink() != 1
    {
        return Err(ExecutableError::Object(format!(
            "{} is not a protected program: uid {}, mode {mode:o}, {} links",
            path.display(),
            meta.uid(),
            meta.nlink(),
        )));
    }
    check_acls(&file, policy, false)?;
    check_capabilities(&file, policy)?;
    Ok(file)
}

fn verify_object(
    policy: &WalkPolicy,
    directory: &ProtectedDir,
    pin: &ExecutablePin,
) -> Result<(File, ExecutableIdentity), ExecutableError> {
    let file = open_object(policy, directory, pin.role)?;
    let meta = check_object_meta(policy, &file, pin.role)?;
    if meta.len() != pin.bytes || meta.len() > MAX_EXECUTABLE_BYTES {
        return Err(ExecutableError::Mismatch(format!(
            "{} is {} bytes, pinned {}",
            pin.role.as_str(),
            meta.len(),
            pin.bytes
        )));
    }
    let digest = hash_descriptor(&file, meta.len())?;
    if digest != pin.sha256 {
        return Err(ExecutableError::Mismatch(format!(
            "{} digest differs from its pin",
            pin.role.as_str()
        )));
    }
    check_static_elf(&file, meta.len())?;
    let after = check_object_meta(policy, &file, pin.role)?;
    if after.len() != meta.len() || after.modified().ok() != meta.modified().ok() {
        return Err(ExecutableError::Mismatch(format!(
            "{} changed while hashing",
            pin.role.as_str()
        )));
    }
    Ok((
        file,
        ExecutableIdentity {
            role: pin.role,
            st_dev: meta.dev(),
            st_ino: meta.ino(),
            bytes: meta.len(),
            sha256: digest,
            installation_generation: pin.installation_generation,
        },
    ))
}

struct Retained {
    identity: ExecutableIdentity,
    file: File,
    directory: ProtectedDir,
}

impl std::fmt::Debug for ExecutableTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutableTable")
            .field("vector", &self.vector())
            .finish()
    }
}

/// The bounded retained table: four read-only descriptors and their directory chains.
/// These survive source renames and installed-name swaps by construction.
pub struct ExecutableTable {
    policy: WalkPolicy,
    store_root: PathBuf,
    entries: BTreeMap<Role, Retained>,
}

fn digest_directory(
    policy: &WalkPolicy,
    store_root: &Path,
    digest: &Digest,
) -> Result<ProtectedDir, ExecutableError> {
    walk_directory(policy, &store_root.join(digest.to_string()))
}

impl ExecutableTable {
    /// Verified opening, with no session side effects. A missing or unsafe object is
    /// a C0 refusal; Create can never install or download one.
    pub fn open(
        policy: WalkPolicy,
        store_root: &Path,
        pins: &[ExecutablePin],
    ) -> Result<Self, ExecutableError> {
        let mut entries = BTreeMap::new();
        for pin in pins {
            let directory = digest_directory(&policy, store_root, &pin.sha256)?;
            let (file, identity) = verify_object(&policy, &directory, pin)?;
            if entries
                .insert(
                    pin.role,
                    Retained {
                        identity,
                        file,
                        directory,
                    },
                )
                .is_some()
            {
                return Err(ExecutableError::Object("duplicate role pin".into()));
            }
        }
        let table = Self {
            policy,
            store_root: store_root.to_path_buf(),
            entries,
        };
        table.check_unique_inodes()?;
        Ok(table)
    }

    fn check_unique_inodes(&self) -> Result<(), ExecutableError> {
        let mut seen = std::collections::BTreeSet::new();
        for retained in self.entries.values() {
            if !seen.insert((retained.identity.st_dev, retained.identity.st_ino)) {
                return Err(ExecutableError::Object(
                    "executable roles alias one inode".into(),
                ));
            }
        }
        Ok(())
    }

    /// Restart: protected traversal, then exact device, inode, size, digest and
    /// generation comparison with the journal. A replacement inode with the same
    /// bytes cannot satisfy an old plan, and nothing falls back to the pathname.
    pub fn reopen_exact(
        policy: WalkPolicy,
        store_root: &Path,
        expected: &[ExecutableIdentity],
    ) -> Result<Self, ExecutableError> {
        let pins: Vec<_> = expected
            .iter()
            .map(|identity| ExecutablePin {
                role: identity.role,
                bytes: identity.bytes,
                sha256: identity.sha256,
                installation_generation: identity.installation_generation,
            })
            .collect();
        let table = Self::open(policy, store_root, &pins)?;
        table.require_vector(expected)?;
        Ok(table)
    }

    pub fn identity(&self, role: Role) -> Option<ExecutableIdentity> {
        self.entries.get(&role).map(|retained| retained.identity)
    }

    /// Ordered, so its substitution form is stable.
    pub fn vector(&self) -> Vec<ExecutableIdentity> {
        self.entries
            .values()
            .map(|retained| retained.identity)
            .collect()
    }

    fn require_vector(&self, expected: &[ExecutableIdentity]) -> Result<(), ExecutableError> {
        if expected.len() != self.entries.len() {
            return Err(ExecutableError::Mismatch(
                "plan names a different executable set".into(),
            ));
        }
        for identity in expected {
            let retained = self.entries.get(&identity.role).ok_or_else(|| {
                ExecutableError::Mismatch(format!(
                    "no retained descriptor for {}",
                    identity.role.as_str()
                ))
            })?;
            if retained.identity != *identity {
                return Err(ExecutableError::Mismatch(format!(
                    "{} tuple differs from the retained identity",
                    identity.role.as_str()
                )));
            }
        }
        Ok(())
    }

    /// The tuple a descriptor actually names right now, by descriptor only.
    fn actual(&self, retained: &Retained) -> Result<ExecutableIdentity, ExecutableError> {
        let meta = check_object_meta(&self.policy, &retained.file, retained.identity.role)
            .map_err(|e| ExecutableError::Descriptor(e.to_string()))?;
        let digest = hash_descriptor(&retained.file, meta.len())
            .map_err(|e| ExecutableError::Descriptor(e.to_string()))?;
        Ok(ExecutableIdentity {
            role: retained.identity.role,
            st_dev: meta.dev(),
            st_ino: meta.ino(),
            bytes: meta.len(),
            sha256: digest,
            installation_generation: retained.identity.installation_generation,
        })
    }

    /// Create's recheck before C2: the plan's vector equals the retained table, every
    /// retained descriptor still names that tuple, and a fresh protected walk reaches
    /// the same inode. Any disagreement refuses; no alternate object is tried.
    pub fn revalidate(&self, plan: &[ExecutableIdentity]) -> Result<(), ExecutableError> {
        self.require_vector(plan)?;
        for retained in self.entries.values() {
            let actual = self.actual(retained)?;
            if actual != retained.identity {
                return Err(ExecutableError::Mismatch(format!(
                    "retained {} descriptor no longer names its verified tuple",
                    retained.identity.role.as_str()
                )));
            }
            let directory =
                digest_directory(&self.policy, &self.store_root, &retained.identity.sha256)?;
            let pin = ExecutablePin {
                role: retained.identity.role,
                bytes: retained.identity.bytes,
                sha256: retained.identity.sha256,
                installation_generation: retained.identity.installation_generation,
            };
            let (_, reopened) = verify_object(&self.policy, &directory, &pin)?;
            if reopened != retained.identity {
                return Err(ExecutableError::Mismatch(format!(
                    "installed {} is a different inode",
                    retained.identity.role.as_str()
                )));
            }
        }
        Ok(())
    }

    /// The modeled dispatch point: what would execute is the retained descriptor,
    /// never a pathname. The tuple it names must equal the journal's, or nothing runs.
    pub fn model_execute(
        &self,
        expected: &ExecutableIdentity,
    ) -> Result<ExecObservation, ExecutableError> {
        let retained = self.entries.get(&expected.role).ok_or_else(|| {
            ExecutableError::Descriptor(format!("{} is not retained", expected.role.as_str()))
        })?;
        let actual = self.actual(retained)?;
        if actual != *expected {
            return Err(ExecutableError::Mismatch(format!(
                "{} actual tuple differs from the plan",
                expected.role.as_str()
            )));
        }
        Ok(ExecObservation {
            expected: *expected,
            actual,
        })
    }

    /// The retained descriptor for the gated launch child.
    pub fn raw_fd(&self, role: Role) -> Option<RawFd> {
        self.entries
            .get(&role)
            .map(|retained| retained.file.as_raw_fd())
    }

    /// Every descriptor a forked worker must keep to use this table.
    pub fn raw_fds(&self) -> Vec<RawFd> {
        self.entries
            .values()
            .flat_map(|retained| {
                let mut fds = retained.directory.raw_fds();
                fds.push(retained.file.as_raw_fd());
                fds
            })
            .collect()
    }
}

/// Publishes an object from an already authenticated source descriptor. Never
/// replaces or repairs: an existing object must match, and a mismatch is an error.
/// The installer alone calls this, outside Create. Parent and file are fsynced.
pub fn publish_object(
    policy: &WalkPolicy,
    store_root: &Path,
    source: &File,
    pin: &ExecutablePin,
) -> Result<(), ExecutableError> {
    let digest = pin.sha256.to_string();
    let root = walk_directory(policy, store_root)?;
    let digest_name = component_name(OsStr::new(&digest))?;
    // SAFETY: root and name are live and mkdirat takes a mode.
    if unsafe { libc::mkdirat(root.file().as_raw_fd(), digest_name.as_ptr(), 0o700) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(io_error("create digest directory", error));
        }
    }
    let directory = walk_directory(policy, &store_root.join(&digest))?;
    let name = component_name(OsStr::new(pin.role.as_str()))?;
    if open_at(
        directory.file().as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW,
    )
    .is_ok()
    {
        verify_object(policy, &directory, pin)?;
        return Ok(());
    }
    let temporary = component_name(OsStr::new(&format!(".{}.tmp", pin.role.as_str())))?;
    let mut file = open_at(
        directory.file().as_raw_fd(),
        &temporary,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
    )
    .map_err(|e| io_error("create private copy", e))?;
    let mut input = source.try_clone().map_err(|e| io_error("source", e))?;
    let copied = std::io::copy(
        &mut std::io::Read::take(&mut input, MAX_EXECUTABLE_BYTES + 1),
        &mut file,
    )
    .map_err(|e| io_error("copy", e))?;
    let digest_of_copy = hash_descriptor(&file, copied)?;
    let result = (|| {
        if copied != pin.bytes || digest_of_copy != pin.sha256 {
            return Err(ExecutableError::Mismatch(
                "source does not match its pin".into(),
            ));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o555))
            .map_err(|e| io_error("chmod", e))?;
        file.sync_all().map_err(|e| io_error("fsync", e))?;
        // SAFETY: both directory handles and names are live; linkat never replaces.
        if unsafe {
            libc::linkat(
                directory.file().as_raw_fd(),
                temporary.as_ptr(),
                directory.file().as_raw_fd(),
                name.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io_error("publish", io::Error::last_os_error()));
        }
        Ok(())
    })();
    // SAFETY: directory and temporary name are live.
    unsafe { libc::unlinkat(directory.file().as_raw_fd(), temporary.as_ptr(), 0) };
    result?;
    directory
        .file()
        .sync_all()
        .map_err(|e| io_error("fsync parent", e))?;
    root.file()
        .sync_all()
        .map_err(|e| io_error("fsync store", e))?;
    Ok(())
}

/// The record S sends J on control FD 4. Bound by version, plan generation, exact VMM
/// tuple, `--exec-file` label and pinned jail root, and at most 4 KiB when encoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRecord {
    pub version: u32,
    pub plan_generation: u64,
    pub vmm_identity: BootstrapVmm,
    pub exec_file_label: String,
    pub jail_root_identity: JailRootIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapVmm {
    pub st_dev: u64,
    pub st_ino: u64,
    pub bytes: u64,
    pub sha256: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailRootIdentity {
    pub mount_id: u64,
    pub st_dev: u64,
    pub st_ino: u64,
}

impl BootstrapRecord {
    pub fn for_vmm(
        plan_generation: u64,
        vmm: &ExecutableIdentity,
        jail_root_identity: JailRootIdentity,
    ) -> Self {
        Self {
            version: 1,
            plan_generation,
            vmm_identity: BootstrapVmm {
                st_dev: vmm.st_dev,
                st_ino: vmm.st_ino,
                bytes: vmm.bytes,
                sha256: vmm.sha256,
            },
            exec_file_label: format!("/opt/kilnd/exec/sha256/{}/firecracker", vmm.sha256),
            jail_root_identity,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let bytes = crate::firecracker::canonical(&value)?;
        if bytes.len() > MAX_BOOTSTRAP_BYTES {
            return Err("bootstrap record exceeds 4 KiB".into());
        }
        Ok(bytes)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() > MAX_BOOTSTRAP_BYTES {
            return Err("bootstrap record exceeds 4 KiB".into());
        }
        let value = crate::firecracker::strict_json(raw)?;
        let record: Self = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if record.version != 1 || record.encode()? != raw {
            return Err("bootstrap record is not canonical version 1".into());
        }
        Ok(record)
    }
}

fn check_fd(rc: libc::c_int, what: &str) -> io::Result<libc::c_int> {
    if rc < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("{what}: {}", io::Error::last_os_error()),
        ));
    }
    Ok(rc)
}

/// Closes every descriptor above stderr that is not in `keep`. A forked worker starts
/// with this, so nothing the parent holds crosses into it by accident.
pub fn close_all_except(keep: &[RawFd]) {
    let mut sorted: Vec<RawFd> = keep.iter().copied().filter(|fd| *fd > 2).collect();
    sorted.sort_unstable();
    sorted.dedup();
    #[cfg(target_os = "linux")]
    {
        let mut next: libc::c_uint = 3;
        for fd in &sorted {
            let fd = *fd as libc::c_uint;
            if fd > next {
                // SAFETY: closing a descriptor range this process owns.
                unsafe { libc::syscall(libc::SYS_close_range, next, fd - 1, 0) };
            }
            next = fd + 1;
        }
        // SAFETY: closing a descriptor range this process owns.
        unsafe { libc::syscall(libc::SYS_close_range, next, libc::c_uint::MAX, 0) };
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: limit is writable.
        let open_max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            limit.rlim_cur.min(1 << 16) as RawFd
        } else {
            1 << 16
        };
        for fd in 3..open_max {
            if sorted.binary_search(&fd).is_err() {
                // SAFETY: closing a descriptor this process owns or EBADF.
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// The gated launch child's descriptor arrangement, before J exec. V and control end
/// at exactly 3 and 4 without close-on-exec; J's own exec descriptor ends at >= 5 with
/// close-on-exec; everything else above stderr closes. Returns the J descriptor.
pub fn arrange_bootstrap_fds(jailer_exec: RawFd, vmm: RawFd, control: RawFd) -> io::Result<RawFd> {
    // Move every input out of the way first; any of them might already be 3 or 4.
    // SAFETY: the inputs are live descriptors in this child.
    let jailer = check_fd(
        unsafe { libc::fcntl(jailer_exec, libc::F_DUPFD_CLOEXEC, JAILER_EXEC_FD_MIN) },
        "duplicate jailer descriptor",
    )?;
    let vmm_high = check_fd(
        unsafe { libc::fcntl(vmm, libc::F_DUPFD_CLOEXEC, JAILER_EXEC_FD_MIN) },
        "duplicate VMM descriptor",
    )?;
    let control_high = check_fd(
        unsafe { libc::fcntl(control, libc::F_DUPFD_CLOEXEC, JAILER_EXEC_FD_MIN) },
        "duplicate control descriptor",
    )?;
    // dup2 clears close-on-exec on the new descriptor.
    check_fd(unsafe { libc::dup2(vmm_high, VMM_FD) }, "install FD 3")?;
    check_fd(
        unsafe { libc::dup2(control_high, CONTROL_FD) },
        "install FD 4",
    )?;
    close_all_except(&[VMM_FD, CONTROL_FD, jailer]);
    for fd in [VMM_FD, CONTROL_FD] {
        if check_fd(unsafe { libc::fcntl(fd, libc::F_GETFD) }, "read FD flags")? & libc::FD_CLOEXEC
            != 0
        {
            return Err(io::Error::other("bootstrap descriptor is close-on-exec"));
        }
    }
    let flags = check_fd(
        unsafe { libc::fcntl(VMM_FD, libc::F_GETFL) },
        "read FD 3 mode",
    )?;
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(io::Error::other("FD 3 is not read-only"));
    }
    if !is_stream_socket(CONTROL_FD) {
        return Err(io::Error::other("FD 4 is not a stream socket"));
    }
    if check_fd(
        unsafe { libc::fcntl(jailer, libc::F_GETFD) },
        "read J flags",
    )? & libc::FD_CLOEXEC
        == 0
    {
        return Err(io::Error::other("J exec descriptor must be close-on-exec"));
    }
    Ok(jailer)
}

fn is_stream_socket(fd: RawFd) -> bool {
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: output pointers are live and exactly sized for SO_TYPE.
    (unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    }) == 0
        && kind == libc::SOCK_STREAM
}

/// J's entry after exec: FD 3 must name the exact bootstrap VMM tuple and read-only
/// mode, FD 4 must be the stream control socket, both then become close-on-exec, and
/// every unexpected descriptor closes. Nothing bootstrap-related survives V's exec.
pub fn jailer_entry(record: &BootstrapRecord) -> Result<(), ExecutableError> {
    // SAFETY: fstat writes into live storage; a bad FD reports EBADF.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(VMM_FD, &mut stat) } != 0 {
        return Err(ExecutableError::Descriptor(format!(
            "FD 3: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: querying a live descriptor.
    let flags = unsafe { libc::fcntl(VMM_FD, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(ExecutableError::Descriptor("FD 3 is not read-only".into()));
    }
    #[allow(clippy::unnecessary_cast)]
    let (dev, ino, size) = (stat.st_dev as u64, stat.st_ino as u64, stat.st_size as u64);
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || dev != record.vmm_identity.st_dev
        || ino != record.vmm_identity.st_ino
        || size != record.vmm_identity.bytes
    {
        return Err(ExecutableError::Mismatch(
            "FD 3 tuple differs from the bootstrap record".into(),
        ));
    }
    // SAFETY: duplicate keeps FD 3 itself untouched by File's drop.
    let duplicate = unsafe { libc::fcntl(VMM_FD, libc::F_DUPFD_CLOEXEC, JAILER_EXEC_FD_MIN) };
    if duplicate < 0 {
        return Err(ExecutableError::Descriptor("duplicate FD 3".into()));
    }
    // SAFETY: fcntl returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(duplicate) };
    if hash_descriptor(&file, size)? != record.vmm_identity.sha256 {
        return Err(ExecutableError::Mismatch(
            "FD 3 digest differs from the bootstrap record".into(),
        ));
    }
    drop(file);
    if !is_stream_socket(CONTROL_FD) {
        return Err(ExecutableError::Descriptor(
            "FD 4 is not the control socket".into(),
        ));
    }
    for fd in [VMM_FD, CONTROL_FD] {
        // SAFETY: setting flags on a live descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(ExecutableError::Descriptor(format!(
                "FD {fd} close-on-exec"
            )));
        }
    }
    close_all_except(&[VMM_FD, CONTROL_FD]);
    Ok(())
}

/// Linux's descriptor exec. There is no `execve(path)` fallback anywhere in this
/// module. It returns only on failure.
#[cfg(target_os = "linux")]
pub fn exec_retained(fd: RawFd, argv: &[CString], env: &[CString]) -> io::Error {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|arg| arg.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    // SAFETY: fd is live, the empty path and both NULL-terminated vectors outlive the
    // call, and AT_EMPTY_PATH selects the descriptor itself.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            c"".as_ptr(),
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    io::Error::last_os_error()
}

/// A process's actual executable through its `/proc` magic link: device and inode
/// from the opened file, digest computed through that same descriptor.
#[cfg(target_os = "linux")]
pub fn observe_process_image(
    pid: i32,
    role: Role,
    generation: u64,
) -> io::Result<ExecutableIdentity> {
    let path = CString::new(format!("/proc/{pid}/exe")).unwrap();
    // SAFETY: path is NUL-terminated. This is the one permitted magic-link open: the
    // resulting descriptor is the running image, not a name lookup of its path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    let sha256 = hash_descriptor(&file, meta.len()).map_err(io::Error::other)?;
    Ok(ExecutableIdentity {
        role,
        st_dev: meta.dev(),
        st_ino: meta.ino(),
        bytes: meta.len(),
        sha256,
        installation_generation: generation,
    })
}

/// H's startup self-check: the running image is the protected installed helper. A
/// fork-only worker inherits that verified image and records it as its identity.
#[cfg(target_os = "linux")]
pub fn verify_self_image(table: &ExecutableTable) -> Result<ExecutableIdentity, ExecutableError> {
    let expected = table
        .identity(Role::KilndHelper)
        .ok_or_else(|| ExecutableError::Mismatch("no retained helper identity".into()))?;
    let actual = observe_process_image(
        unsafe { libc::getpid() },
        Role::KilndHelper,
        expected.installation_generation,
    )
    .map_err(|e| io_error("observe /proc/self/exe", e))?;
    if actual != expected {
        return Err(ExecutableError::Mismatch(
            "running helper is not the protected installed image".into(),
        ));
    }
    Ok(expected)
}

#[cfg(not(target_os = "linux"))]
pub fn verify_self_image(_: &ExecutableTable) -> Result<ExecutableIdentity, ExecutableError> {
    Err(ExecutableError::Object(
        "the helper image self-check needs /proc".into(),
    ))
}

#[cfg(test)]
pub(super) mod tests;
