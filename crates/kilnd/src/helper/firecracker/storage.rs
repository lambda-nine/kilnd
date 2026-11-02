//! Section 7.1: the private work disk, its loop exposure and the mandatory jail bounds.
//! Every function takes names derived from a verified plan and typed journal
//! identities, never a request path. Directories are walked by descriptor without
//! following links; every removal compares the recorded inode or device first, so a
//! replacement entry is refused instead of deleted, detached or unmounted.
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// The helper's state root. Its jail and work subtrees are root-owned and 0700.
pub const HELPER_STATE: &str = "/var/lib/kilnd-helper";
/// The jailer's `--chroot-base-dir`, a private bind mount of itself so nothing mounted
/// below propagates into another mount namespace.
pub const JAIL_BASE: &str = "/var/lib/kilnd-helper/jails";
pub const WORK_BASE: &str = "/var/lib/kilnd-helper/work";
/// The prefix of each jail tmpfs's allocation-specific source, `kilnd-jail-<nonce>`.
pub const JAIL_FS_SOURCE_PREFIX: &str = "kilnd-jail-";
/// The root-only marker beside the jail root, inside the tmpfs but outside the chroot.
pub const JAIL_MARKER: &str = ".kilnd-jail";
pub const JAIL_TMPFS_DATA: &str = "size=16M,nr_inodes=1024,mode=0700";
pub const WORK_FILE: &str = "work.xfs";
pub const IDENTITY_FILE: &str = "identity.bin";
pub const CONFIG_FILE: &str = "config.json";
/// The read-only artifact binds inside the jail, in mount order.
pub const BINDS: [&str; 5] = ["kernel", "rootfs", "config.json", "identity", "firecracker"];
pub const LOOP_MAJOR: u32 = 7;
/// The identity block's fixed size and magic (section 3.3).
pub const IDENTITY_BYTES: usize = 4096;

/// A file's node-local identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub st_dev: u64,
    pub st_ino: u64,
    pub bytes: u64,
}

/// A loop slot chosen for one work file, journaled before LOOP_CONFIGURE. Every field is
/// compared on the opened slot before it is trusted or detached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopBinding {
    pub major: u32,
    pub minor: u32,
    pub backing_dev: u64,
    pub backing_ino: u64,
    pub offset: u64,
    pub size_limit: u64,
    /// The slot's logical block size, set by LOOP_CONFIGURE.
    pub block_size: u32,
}

/// The work device's logical block size: the formatter's 512-byte sectors.
pub const LOOP_BLOCK_SIZE: u32 = 512;

/// This boot's identity. Mount unique IDs and disk sequence numbers are never reused
/// within one boot, so every journaled generation carries the boot it belongs to: a
/// record from another boot names a mount or loop attachment that is gone by definition.
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// A boot ID as the kernel prints it: a lowercase 8-4-4-4-12 UUID.
pub fn valid_boot_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}

/// The generation of one loop attachment: the device's disk sequence number
/// (`BLKGETDISKSEQ`), read on the configuring descriptor right after LOOP_CONFIGURE.
/// The kernel takes it from one global counter at every attach and detach and never
/// reuses it within a boot, so a slot detached and rebound to the same backing inode
/// with the same tuple has another one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopGeneration {
    pub boot_id: String,
    pub diskseq: u64,
}

/// The jail tmpfs's allocation-specific source and marker, journaled before the mount
/// exists. The mount's source is `kilnd-jail-<nonce>` and its root-only marker holds the
/// nonce. Root can copy both into a replacement, so they are secondary checks only: the
/// authority is the journaled unique mount ID in [`JailMount`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailIdentity {
    /// 128 random bits, lowercase hexadecimal.
    pub nonce: String,
}

impl JailIdentity {
    pub fn source(&self) -> String {
        format!("{JAIL_FS_SOURCE_PREFIX}{}", self.nonce)
    }

    /// The marker's exact bytes.
    pub fn marker(&self) -> Vec<u8> {
        format!("kilnd-jail-marker {}\n", self.nonce).into_bytes()
    }

    pub fn valid(&self) -> bool {
        self.nonce.len() == 32
            && self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }
}

/// The jail tmpfs, as created detached and journaled before it is attached at the
/// allocation's jail directory, and the jail root directory inside it (the jailer's
/// chroot, the bootstrap's `jail_root_identity`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailMount {
    pub boot_id: String,
    /// `STATX_MNT_ID_UNIQUE`: never reused within a boot. Teardown's authority.
    pub unique_id: u64,
    /// The reusable 32-bit mount ID, `st_dev` and `st_ino`: secondary checks only.
    pub mount_id: u64,
    pub st_dev: u64,
    /// The tmpfs root, which is the jail directory while mounted.
    pub st_ino: u64,
    /// The jail root directory on the tmpfs.
    pub root_ino: u64,
}

/// One read-only artifact bind inside the jail root, as cloned detached and journaled
/// before it is attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindMount {
    pub name: String,
    pub boot_id: String,
    /// `STATX_MNT_ID_UNIQUE`: never reused within a boot. Teardown's authority.
    pub unique_id: u64,
    pub mount_id: u64,
    /// The bound file's identity, seen through the bind.
    pub st_dev: u64,
    pub st_ino: u64,
}

/// A mounted directory's or file's unique and reusable mount IDs, device and inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountedIdentity {
    pub unique_id: u64,
    pub mount_id: u64,
    pub st_dev: u64,
    pub st_ino: u64,
}

/// What detaching a recorded loop slot found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopOutcome {
    /// The journaled generation, with its full tuple, detached with no pending attachment.
    Detached,
    /// The slot is free, or the journaled generation belongs to an earlier boot: nothing
    /// of ours is attached there.
    Free,
    /// The slot is bound to another backing file: left exactly as it was.
    NotOurs,
    /// The slot is bound to our backing inode, but not as the journaled generation: another
    /// offset, size limit or block size, another disk sequence number (detached and
    /// rebound), or no journaled generation at all. Left bound; cleanup stays charged.
    Unknown,
}

/// Test-only gate between the full tuple comparison and the final generation check
/// before `LOOP_CLR_FD`, so a privileged test can replace the binding in that window.
#[cfg(all(test, target_os = "linux"))]
pub(crate) static TEST_DETACH_GATE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// Derived paths for one allocation, from the plan's launch object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationPaths {
    /// `<JAIL_BASE>/firecracker/fc-<H>`
    pub jail_dir: PathBuf,
    /// `<jail_dir>/root`
    pub jail_root: PathBuf,
    /// `<WORK_BASE>/<I>/fc-<H>`
    pub work_dir: PathBuf,
    pub work_file: PathBuf,
}

impl AllocationPaths {
    /// Checks the plan's paths are exactly the contract's shapes before any use.
    pub fn from_launch(launch: &serde_json::Value) -> io::Result<Self> {
        let jail_root = launch["jail_root"]
            .as_str()
            .ok_or_else(|| invalid("plan jail root"))?;
        let backing = launch["work_backing_path"]
            .as_str()
            .ok_or_else(|| invalid("plan work path"))?;
        let jail_root = PathBuf::from(jail_root);
        let work_file = PathBuf::from(backing);
        let jail_dir = jail_root
            .parent()
            .ok_or_else(|| invalid("jail root"))?
            .to_path_buf();
        let work_dir = work_file
            .parent()
            .ok_or_else(|| invalid("work path"))?
            .to_path_buf();
        let backend = jail_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("jail name"))?;
        let ok_name = |n: &str| {
            n.len() == 35
                && n.starts_with("fc-")
                && n[3..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        if !ok_name(backend)
            || jail_dir != Path::new(JAIL_BASE).join("firecracker").join(backend)
            || jail_root.file_name().and_then(|n| n.to_str()) != Some("root")
            || work_file.file_name().and_then(|n| n.to_str()) != Some(WORK_FILE)
            || work_dir.file_name().and_then(|n| n.to_str()) != Some(backend)
            || work_dir.parent().and_then(|p| p.parent()) != Some(Path::new(WORK_BASE))
        {
            return Err(invalid("plan paths are outside the contract's shapes"));
        }
        Ok(Self {
            jail_dir,
            jail_root,
            work_dir,
            work_file,
        })
    }
}

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.into())
}

/// The canonical identity block: `KID1`, a big-endian length, canonical JSON and zero
/// padding to 4096 bytes. It binds the plan's session; it is not a credential.
pub fn identity_block(plan: &serde_json::Value) -> io::Result<Vec<u8>> {
    let subs = &plan["substitutions"];
    let text = |v: &serde_json::Value| v.as_str().map(str::to_owned);
    let launch = crate::firecracker::canonical(&plan["launch"]).map_err(invalid)?;
    let inner = crate::firecracker::canonical(&subs["inner_spec"]).map_err(invalid)?;
    let mut record = serde_json::Map::new();
    for name in [
        "instance_id",
        "allocation_id",
        "sandbox_id",
        "boot_nonce",
        "work_uuid",
    ] {
        record.insert(
            name.into(),
            serde_json::Value::String(text(&subs[name]).ok_or_else(|| invalid(name))?),
        );
    }
    record.insert(
        "manifest_sha256".into(),
        serde_json::Value::String(
            text(&plan["manifest_sha256"]).ok_or_else(|| invalid("manifest digest"))?,
        ),
    );
    record.insert(
        "launch_sha256".into(),
        serde_json::Value::String(crate::firecracker::sha256(&launch)),
    );
    record.insert(
        "guest_exec_spec_sha256".into(),
        serde_json::Value::String(crate::firecracker::sha256(&inner)),
    );
    let payload =
        crate::firecracker::canonical(&serde_json::Value::Object(record)).map_err(invalid)?;
    if payload.is_empty() || payload.len() > IDENTITY_BYTES - 8 {
        return Err(invalid("identity record length"));
    }
    let mut block = Vec::with_capacity(IDENTITY_BYTES);
    block.extend_from_slice(b"KID1");
    block.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    block.extend_from_slice(&payload);
    block.resize(IDENTITY_BYTES, 0);
    Ok(block)
}

/// The exact `/config.json` bytes: the plan's Firecracker object, canonical.
pub fn config_bytes(launch: &serde_json::Value) -> io::Result<Vec<u8>> {
    crate::firecracker::canonical(&launch["firecracker"]).map_err(invalid)
}

/// One entry of `/proc/self/mountinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_id: u64,
    pub parent_id: u64,
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub source: String,
    pub read_only: bool,
}

fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value =
                (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses mountinfo text. Malformed lines fail the whole read rather than hide a mount.
pub fn parse_mountinfo(text: &str) -> io::Result<Vec<MountEntry>> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let separator = fields
            .iter()
            .position(|f| *f == "-")
            .ok_or_else(|| io::Error::other("mountinfo line without separator"))?;
        if separator < 6 || fields.len() < separator + 3 {
            return Err(io::Error::other("short mountinfo line"));
        }
        entries.push(MountEntry {
            mount_id: fields[0]
                .parse()
                .map_err(|_| io::Error::other("mount ID"))?,
            parent_id: fields[1]
                .parse()
                .map_err(|_| io::Error::other("parent mount ID"))?,
            mount_point: PathBuf::from(unescape(fields[4])),
            read_only: fields[5].split(',').any(|o| o == "ro"),
            fs_type: fields[separator + 1].to_string(),
            source: unescape(fields[separator + 2]),
        });
    }
    Ok(entries)
}

/// Mounts at or below `path`, deepest first.
pub fn mounts_under(entries: &[MountEntry], path: &Path) -> Vec<MountEntry> {
    let mut found: Vec<MountEntry> = entries
        .iter()
        .filter(|e| e.mount_point == path || e.mount_point.starts_with(path))
        .cloned()
        .collect();
    found.sort_by_key(|e| std::cmp::Reverse(e.mount_point.components().count()));
    found
}

/// Parsed `/proc/<pid>/status` credential lines (section 6.2's checked fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub uid: [u32; 4],
    pub gid: [u32; 4],
    pub groups: Vec<u32>,
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_bnd: u64,
    pub cap_amb: u64,
    pub no_new_privs: u32,
    pub seccomp: u32,
}

/// Strict status parsing: a duplicate or missing field fails, never defaults.
pub fn parse_status(text: &str) -> io::Result<Credentials> {
    let mut fields = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':')
            && fields
                .insert(name.to_string(), value.trim().to_string())
                .is_some()
        {
            return Err(io::Error::other(format!("duplicate status field {name}")));
        }
    }
    let get = |name: &str| {
        fields
            .get(name)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("status has no {name}")))
    };
    let four = |name: &str| -> io::Result<[u32; 4]> {
        let values: Vec<u32> = get(name)?
            .split_whitespace()
            .map(|v| v.parse().map_err(|_| io::Error::other(name.to_string())))
            .collect::<io::Result<_>>()?;
        values
            .try_into()
            .map_err(|_| io::Error::other(format!("{name} needs four values")))
    };
    let hex = |name: &str| -> io::Result<u64> {
        let text = get(name)?;
        if text.len() != 16 {
            return Err(io::Error::other(format!("{name} is not 16 hex digits")));
        }
        u64::from_str_radix(&text, 16).map_err(|_| io::Error::other(name.to_string()))
    };
    let number = |name: &str| -> io::Result<u32> {
        get(name)?
            .parse()
            .map_err(|_| io::Error::other(name.to_string()))
    };
    Ok(Credentials {
        uid: four("Uid")?,
        gid: four("Gid")?,
        groups: get("Groups")?
            .split_whitespace()
            .map(|v| v.parse().map_err(|_| io::Error::other("Groups")))
            .collect::<io::Result<_>>()?,
        cap_inh: hex("CapInh")?,
        cap_prm: hex("CapPrm")?,
        cap_eff: hex("CapEff")?,
        cap_bnd: hex("CapBnd")?,
        cap_amb: hex("CapAmb")?,
        no_new_privs: number("NoNewPrivs")?,
        seccomp: number("Seccomp")?,
    })
}

/// The contract's VMM credentials for one plan: typed U and G, empty groups, every
/// capability mask zero, no_new_privs and seccomp filter mode. Any difference stops
/// the launch; there is no partial acceptance.
pub fn check_vmm_credentials(
    observed: &Credentials,
    recipe: &serde_json::Value,
) -> Result<(), String> {
    let uid = recipe["uid"].as_u64().ok_or("recipe uid")? as u32;
    let gid = recipe["gid"].as_u64().ok_or("recipe gid")? as u32;
    let expect = |name: &str, ok: bool| {
        if ok {
            Ok(())
        } else {
            Err(format!("VMM credentials differ from contract: {name}"))
        }
    };
    expect("Uid", observed.uid == [uid; 4])?;
    expect("Gid", observed.gid == [gid; 4])?;
    expect(
        "Groups",
        observed.groups.is_empty() && recipe["groups"] == serde_json::json!([]),
    )?;
    for (name, value) in [
        ("CapInh", observed.cap_inh),
        ("CapPrm", observed.cap_prm),
        ("CapEff", observed.cap_eff),
        ("CapBnd", observed.cap_bnd),
        ("CapAmb", observed.cap_amb),
    ] {
        expect(name, Some(value) == recipe[name].as_u64())?;
    }
    expect(
        "NoNewPrivs",
        Some(observed.no_new_privs as u64) == recipe["NoNewPrivs"].as_u64(),
    )?;
    expect(
        "Seccomp",
        Some(observed.seccomp as u64) == recipe["status_seccomp"].as_u64(),
    )?;
    Ok(())
}

/// What an absence observation found for one allocation's owned names.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    pub names: Vec<String>,
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;

    const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
    const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
    const LOOP_GET_STATUS64: libc::c_ulong = 0x4C05;
    const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
    const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
    const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
    const BLKSSZGET: libc::c_ulong = 0x1268;
    /// `_IOR(0x12, 128, __u64)`.
    const BLKGETDISKSEQ: libc::c_ulong = 0x8008_1280;
    const LO_FLAGS_AUTOCLEAR: u32 = 4;
    const STATX_MNT_ID: u32 = 0x1000;
    /// Linux 6.8: the 64-bit mount ID that is never reused within a boot.
    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

    /// This boot's ID. Unreadable or malformed is an error, never a default.
    pub fn boot_id() -> io::Result<String> {
        let text = std::fs::read_to_string(BOOT_ID_PATH)?;
        let text = text.trim_end_matches('\n');
        if !valid_boot_id(text) {
            return Err(io::Error::other("malformed boot ID"));
        }
        Ok(text.to_string())
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LoopInfo64 {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        lo_file_name: [u8; 64],
        lo_crypt_name: [u8; 64],
        lo_encrypt_key: [u8; 32],
        lo_init: [u64; 2],
    }

    #[repr(C)]
    struct LoopConfig {
        fd: u32,
        block_size: u32,
        info: LoopInfo64,
        reserved: [u64; 8],
    }

    fn cstr(name: &str) -> io::Result<CString> {
        CString::new(name).map_err(|_| invalid("name contains NUL"))
    }

    fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn openat_raw(parent: RawFd, name: &str, flags: libc::c_int, mode: u32) -> io::Result<File> {
        let c = cstr(name)?;
        // SAFETY: c is NUL-terminated; the descriptor is live or AT_FDCWD.
        let fd = cvt(unsafe { libc::openat(parent, c.as_ptr(), flags | libc::O_CLOEXEC, mode) })?;
        // SAFETY: a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub fn open_dir_at(parent: &File, name: &str) -> io::Result<File> {
        openat_raw(
            parent.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )
    }

    fn fstatat(parent: &File, name: &str) -> io::Result<libc::stat> {
        let c = cstr(name)?;
        // SAFETY: stat is writable; c is NUL-terminated.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        cvt(unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                c.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        Ok(stat)
    }

    fn fstat(file: &File) -> io::Result<libc::stat> {
        // SAFETY: stat is writable.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        cvt(unsafe { libc::fstat(file.as_raw_fd(), &mut stat) })?;
        Ok(stat)
    }

    /// A trusted directory: root-owned, not group/world-writable, not a link.
    fn check_trusted_dir(file: &File, private: bool) -> io::Result<()> {
        let stat = fstat(file)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || stat.st_uid != 0 {
            return Err(io::Error::other("untrusted directory: owner or type"));
        }
        let mode = stat.st_mode & 0o7777;
        if mode & 0o022 != 0 || (private && mode & 0o077 != 0) {
            return Err(io::Error::other(format!(
                "untrusted directory mode {mode:o}"
            )));
        }
        Ok(())
    }

    /// Opens an absolute path by descriptor from `/`, refusing links and any ancestor
    /// writable by a non-root principal.
    pub fn open_trusted(path: &Path) -> io::Result<File> {
        let mut current = File::open("/")?;
        check_trusted_dir(&current, false)?;
        for component in path.components().skip(1) {
            let name = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| invalid("path"))?;
            current = open_dir_at(&current, name)?;
            check_trusted_dir(&current, false)?;
        }
        Ok(current)
    }

    /// Creates (or reuses, when `reuse`) one private root-owned 0700 directory.
    pub fn private_dir(parent: &File, name: &str, reuse: bool) -> io::Result<File> {
        let c = cstr(name)?;
        // SAFETY: c is NUL-terminated.
        let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists || !reuse {
                return Err(error);
            }
        }
        let dir = open_dir_at(parent, name)?;
        check_trusted_dir(&dir, true)?;
        parent.sync_all()?;
        Ok(dir)
    }

    /// The node-level jail base: created once, private, and a private bind mount of
    /// itself so later jail mounts never propagate elsewhere.
    pub fn prepare_jail_base() -> io::Result<()> {
        let var_lib = open_trusted(Path::new("/var/lib"))?;
        let state = private_dir(&var_lib, "kilnd-helper", true)?;
        let jails = private_dir(&state, "jails", true)?;
        private_dir(&jails, "firecracker", true)?;
        private_dir(&state, "work", true)?;
        let base = Path::new(JAIL_BASE);
        let mounts = parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo")?)?;
        if !mounts.iter().any(|m| m.mount_point == base) {
            let path = CString::new(base.as_os_str().as_bytes()).unwrap();
            // SAFETY: both paths are NUL-terminated; a bind of the directory onto itself.
            cvt(unsafe {
                libc::mount(
                    path.as_ptr(),
                    path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            })?;
        }
        let path = CString::new(base.as_os_str().as_bytes()).unwrap();
        // SAFETY: changes only propagation of the base and below.
        cvt(unsafe {
            libc::mount(
                std::ptr::null(),
                path.as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        })?;
        Ok(())
    }

    /// The allocation's private work directory, created new.
    pub fn create_work_dir(paths: &AllocationPaths) -> io::Result<File> {
        let base = open_trusted(Path::new(WORK_BASE))?;
        let instance = paths
            .work_dir
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("work instance"))?;
        let instance_dir = private_dir(&base, instance, true)?;
        let name = paths
            .work_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("work name"))?;
        private_dir(&instance_dir, name, false)
    }

    pub fn open_work_dir(paths: &AllocationPaths) -> io::Result<Option<File>> {
        match open_trusted(&paths.work_dir) {
            Ok(dir) => {
                check_trusted_dir(&dir, true)?;
                Ok(Some(dir))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` of the backing file, root 0600.
    pub fn create_work_file(dir: &File) -> io::Result<(File, FileIdentity)> {
        let file = openat_raw(
            dir.as_raw_fd(),
            WORK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        let meta = file.metadata()?;
        Ok((
            file,
            FileIdentity {
                st_dev: meta.dev(),
                st_ino: meta.ino(),
                bytes: meta.len(),
            },
        ))
    }

    /// Full preallocation: mode-0 fallocate, then a block count check. Unsupported
    /// preallocation fails; there is no sparse fallback.
    pub fn preallocate(file: &File, bytes: u64) -> io::Result<FileIdentity> {
        let length = libc::off_t::try_from(bytes).map_err(|_| invalid("work size"))?;
        // SAFETY: a live descriptor; mode 0 allocates and extends.
        let rc = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, length) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()?;
        let stat = fstat(file)?;
        #[allow(clippy::unnecessary_cast)]
        let allocated = stat.st_blocks as u64 * 512;
        if stat.st_size as u64 != bytes || allocated < bytes {
            return Err(io::Error::other("work file is not fully allocated"));
        }
        let meta = file.metadata()?;
        Ok(FileIdentity {
            st_dev: meta.dev(),
            st_ino: meta.ino(),
            bytes: meta.len(),
        })
    }

    /// The allocated bytes of a backing file, for the work-resize/discard evidence.
    pub fn allocated_bytes(file: &File) -> io::Result<u64> {
        #[allow(clippy::unnecessary_cast)]
        Ok(fstat(file)?.st_blocks as u64 * 512)
    }

    /// The identity of a name in a directory, without following it.
    pub fn identity_at(dir: &File, name: &str) -> io::Result<Option<FileIdentity>> {
        match fstatat(dir, name) {
            Ok(stat) =>
            {
                #[allow(clippy::unnecessary_cast)]
                Ok(Some(FileIdentity {
                    st_dev: stat.st_dev as u64,
                    st_ino: stat.st_ino as u64,
                    bytes: stat.st_size as u64,
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Writes one new private read-only file (identity block, config).
    pub fn write_private(dir: &File, name: &str, bytes: &[u8]) -> io::Result<FileIdentity> {
        use std::io::Write;
        let mut file = openat_raw(
            dir.as_raw_fd(),
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o444,
        )?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let meta = file.metadata()?;
        dir.sync_all()?;
        Ok(FileIdentity {
            st_dev: meta.dev(),
            st_ino: meta.ino(),
            bytes: meta.len(),
        })
    }

    pub fn open_private(dir: &File, name: &str) -> io::Result<File> {
        openat_raw(dir.as_raw_fd(), name, libc::O_RDONLY | libc::O_NOFOLLOW, 0)
    }

    fn loop_status(device: &File) -> io::Result<Option<LoopInfo64>> {
        // SAFETY: info is writable and sized for LOOP_GET_STATUS64.
        let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(device.as_raw_fd(), LOOP_GET_STATUS64, &mut info) };
        if rc == 0 {
            return Ok(Some(info));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        Err(error)
    }

    fn decode_dev(encoded: u64) -> (u32, u32) {
        // The kernel reports lo_device as huge_encode_dev: the "new" encoding.
        let major = ((encoded & 0xfff00) >> 8) as u32;
        let minor = ((encoded & 0xff) | ((encoded >> 12) & 0xfff00)) as u32;
        (major, minor)
    }

    fn same_device(encoded: u64, st_dev: u64) -> bool {
        decode_dev(encoded) == (libc::major(st_dev), libc::minor(st_dev))
    }

    fn open_loop(minor: u32, write: bool) -> io::Result<File> {
        let path = format!("/dev/loop{minor}");
        let flags = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let file = openat_raw(libc::AT_FDCWD, &path, flags | libc::O_NOFOLLOW, 0)?;
        let stat = fstat(&file)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFBLK
            || libc::major(stat.st_rdev) != LOOP_MAJOR
            || libc::minor(stat.st_rdev) != minor
        {
            return Err(io::Error::other(format!("{path} is not loop {minor}")));
        }
        Ok(file)
    }

    /// A free loop slot from the kernel. It is only a candidate until LOOP_CONFIGURE.
    pub fn free_loop_slot() -> io::Result<u32> {
        let control = openat_raw(
            libc::AT_FDCWD,
            "/dev/loop-control",
            libc::O_RDWR | libc::O_NOFOLLOW,
            0,
        )?;
        // SAFETY: LOOP_CTL_GET_FREE takes no argument.
        let minor = cvt(unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) })?;
        Ok(minor as u32)
    }

    /// The device's disk sequence number, on this one opened descriptor.
    fn diskseq(device: &File) -> io::Result<u64> {
        let mut seq: u64 = 0;
        // SAFETY: seq is writable for BLKGETDISKSEQ.
        cvt(unsafe { libc::ioctl(device.as_raw_fd(), BLKGETDISKSEQ, &mut seq) })?;
        Ok(seq)
    }

    /// A loop attachment made by [`attach_loop`]: the configuring descriptor, still open,
    /// and the attachment's generation. Until [`persist_loop`] it is an autoclear binding,
    /// so if its owner dies before the generation is journaled, the kernel detaches it
    /// when this descriptor closes and no unrecorded attachment outlives the crash.
    pub struct AttachedLoop {
        device: File,
        pub generation: LoopGeneration,
    }

    /// LOOP_CONFIGURE of the recorded slot onto the recorded backing file with its
    /// exact size limit and `LO_FLAGS_AUTOCLEAR`, then the attachment's disk sequence
    /// number on the same descriptor, verification and disabled discard. A busy slot is
    /// a conflict, never a replacement.
    pub fn attach_loop(binding: &LoopBinding, backing: &File) -> io::Result<AttachedLoop> {
        let meta = backing.metadata()?;
        if meta.dev() != binding.backing_dev
            || meta.ino() != binding.backing_ino
            || meta.len() != binding.size_limit
            || binding.offset != 0
            || binding.major != LOOP_MAJOR
            || binding.block_size != LOOP_BLOCK_SIZE
        {
            return Err(io::Error::other(
                "backing file differs from the loop intent",
            ));
        }
        let boot_id = boot_id()?;
        let device = open_loop(binding.minor, true)?;
        // SAFETY: zero is valid for every field; the kernel copies the structure.
        let mut config: LoopConfig = unsafe { std::mem::zeroed() };
        config.fd = backing.as_raw_fd() as u32;
        config.info.lo_offset = 0;
        config.info.lo_sizelimit = binding.size_limit;
        config.info.lo_flags = LO_FLAGS_AUTOCLEAR;
        config.block_size = binding.block_size;
        let rc = unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CONFIGURE, &config) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBUSY) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "loop slot is busy",
                ));
            }
            return Err(error);
        }
        let generation = LoopGeneration {
            boot_id,
            diskseq: diskseq(&device)?,
        };
        if match_slot(&device, binding)? != SlotMatch::Exact
            || diskseq(&device)? != generation.diskseq
        {
            return Err(io::Error::other("loop binding differs from the intent"));
        }
        disable_discard(binding.minor)?;
        Ok(AttachedLoop { device, generation })
    }

    /// After the generation is journaled: clears autoclear on the configuring
    /// descriptor, so the binding outlives it, and proves that changed nothing else.
    /// `LOOP_SET_STATUS64` writes back exactly what `LOOP_GET_STATUS64` returned, less
    /// the one flag; it does not change the disk sequence number.
    pub fn persist_loop(binding: &LoopBinding, attached: AttachedLoop) -> io::Result<()> {
        let AttachedLoop { device, generation } = attached;
        let mut info = loop_status(&device)?
            .ok_or_else(|| io::Error::other("loop detached before it was persisted"))?;
        if match_slot(&device, binding)? != SlotMatch::Exact
            || diskseq(&device)? != generation.diskseq
            || info.lo_flags & LO_FLAGS_AUTOCLEAR == 0
        {
            return Err(io::Error::other("loop binding is not the journaled generation"));
        }
        info.lo_flags &= !LO_FLAGS_AUTOCLEAR;
        // SAFETY: info is the kernel's own status structure for this slot.
        cvt(unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_STATUS64, &info) })?;
        let after = loop_status(&device)?
            .ok_or_else(|| io::Error::other("loop detached while it was persisted"))?;
        if after.lo_flags & LO_FLAGS_AUTOCLEAR != 0
            || match_slot(&device, binding)? != SlotMatch::Exact
            || diskseq(&device)? != generation.diskseq
        {
            return Err(io::Error::other("loop binding changed while it was persisted"));
        }
        Ok(())
    }

    /// What one opened slot holds, compared with every recorded field.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SlotMatch {
        Free,
        /// Exactly the recorded binding.
        Exact,
        /// Another backing file.
        OtherBacking,
        /// Our backing inode with a different offset, size limit or block size.
        Differs,
    }

    /// The full recorded tuple on this one opened descriptor: the device's major/minor
    /// (checked when it was opened), backing device/inode, offset, size limit, the
    /// device's real size and its logical block size.
    fn match_slot(device: &File, binding: &LoopBinding) -> io::Result<SlotMatch> {
        let stat = fstat(device)?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFBLK
            || binding.major != LOOP_MAJOR
            || (libc::major(stat.st_rdev), libc::minor(stat.st_rdev))
                != (binding.major, binding.minor)
        {
            return Err(io::Error::other("loop descriptor is not the recorded slot"));
        }
        let Some(info) = loop_status(device)? else {
            return Ok(SlotMatch::Free);
        };
        if !same_device(info.lo_device, binding.backing_dev) || info.lo_inode != binding.backing_ino
        {
            return Ok(SlotMatch::OtherBacking);
        }
        if info.lo_offset != binding.offset || info.lo_sizelimit != binding.size_limit {
            return Ok(SlotMatch::Differs);
        }
        let mut size: u64 = 0;
        // SAFETY: size is writable for BLKGETSIZE64.
        cvt(unsafe { libc::ioctl(device.as_raw_fd(), BLKGETSIZE64, &mut size) })?;
        let mut block: libc::c_int = 0;
        // SAFETY: block is writable for BLKSSZGET.
        cvt(unsafe { libc::ioctl(device.as_raw_fd(), BLKSSZGET, &mut block) })?;
        if size != binding.size_limit || u32::try_from(block).ok() != Some(binding.block_size) {
            return Ok(SlotMatch::Differs);
        }
        Ok(SlotMatch::Exact)
    }

    /// The bound slot is exactly the recorded binding.
    pub fn verify_loop(binding: &LoopBinding) -> io::Result<()> {
        let device = open_loop(binding.minor, false)?;
        match match_slot(&device, binding)? {
            SlotMatch::Exact => Ok(()),
            SlotMatch::Free => Err(io::Error::other("loop is unbound")),
            SlotMatch::OtherBacking | SlotMatch::Differs => {
                Err(io::Error::other("loop binding differs from the record"))
            }
        }
    }

    /// Section 7.1: discard and write-zeroes unmapping could punch holes in W. Loop
    /// refuses both while its discard limit is zero.
    fn disable_discard(minor: u32) -> io::Result<()> {
        let path = format!("/sys/block/loop{minor}/queue/discard_max_bytes");
        std::fs::write(&path, b"0")?;
        let value = std::fs::read_to_string(&path)?;
        if value.trim() != "0" {
            return Err(io::Error::other("loop discard could not be disabled"));
        }
        Ok(())
    }

    /// The discard limit as the kernel reports it, for evidence.
    pub fn discard_max_bytes(minor: u32) -> io::Result<u64> {
        std::fs::read_to_string(format!("/sys/block/loop{minor}/queue/discard_max_bytes"))?
            .trim()
            .parse()
            .map_err(io::Error::other)
    }

    /// Detaches the recorded slot only if, on the same opened descriptor that then
    /// issues LOOP_CLR_FD, it is exactly the journaled generation: this boot, the full
    /// tuple, and the journaled disk sequence number, read again immediately before the
    /// ioctl. Then it waits until that generation and every holder is gone.
    ///
    /// A generation from another boot is gone by definition and nothing is touched. A
    /// slot with no journaled generation is never detached: the attachment was made with
    /// autoclear and its owner is dead, so it is waited out briefly and otherwise
    /// Unknown. Fault model (design section 7.1): root replacing the binding before
    /// cleanup is refused; root mutating our own generation in place during teardown
    /// (`LOOP_SET_STATUS64` leaves the sequence number unchanged) is outside it, because
    /// the kernel has no compare-and-clear and host root is trusted.
    pub fn detach_loop(
        binding: &LoopBinding,
        generation: Option<&LoopGeneration>,
    ) -> io::Result<LoopOutcome> {
        if let Some(generation) = generation
            && generation.boot_id != boot_id()?
        {
            return Ok(LoopOutcome::Free);
        }
        let device = match open_loop(binding.minor, false) {
            Ok(device) => device,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(LoopOutcome::Free),
            Err(error) => return Err(error),
        };
        let Some(generation) = generation else {
            return settle_unrecorded(device, binding);
        };
        let before = diskseq(&device)?;
        match match_slot(&device, binding)? {
            SlotMatch::Free => return Ok(LoopOutcome::Free),
            SlotMatch::OtherBacking => return Ok(LoopOutcome::NotOurs),
            SlotMatch::Differs => return Ok(LoopOutcome::Unknown),
            SlotMatch::Exact => {}
        }
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
        // Immediately before the clear: still the journaled generation.
        if before != generation.diskseq || diskseq(&device)? != generation.diskseq {
            return Ok(LoopOutcome::Unknown);
        }
        // SAFETY: LOOP_CLR_FD takes no argument.
        cvt(unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CLR_FD, 0) })?;
        drop(device);
        let end = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let device = match open_loop(binding.minor, false) {
                Ok(device) => Some(device),
                // Running down after our clear: still pending.
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => None,
                Err(error) => return Err(error),
            };
            let Some(device) = device else {
                if std::time::Instant::now() >= end {
                    return Err(io::Error::other("loop detach is still pending"));
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            let bound = loop_status(&device)?.is_some();
            let seq = diskseq(&device)?;
            drop(device);
            let holders = std::fs::read_dir(format!("/sys/block/loop{}/holders", binding.minor))
                .map(|d| d.count())
                .unwrap_or(0);
            if !bound && holders == 0 {
                return Ok(LoopOutcome::Detached);
            }
            // Already bound again by someone else: ours is gone.
            if bound && seq != generation.diskseq {
                return Ok(LoopOutcome::Detached);
            }
            if std::time::Instant::now() >= end {
                return Err(io::Error::other("loop detach is still pending"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A loop intent with no journaled generation: its owner died between
    /// LOOP_CONFIGURE and the journal, so the autoclear attachment goes when the last
    /// descriptor on it closes. Waits up to five seconds for that and never detaches:
    /// a binding to our backing inode that is still there is Unknown.
    fn settle_unrecorded(device: File, binding: &LoopBinding) -> io::Result<LoopOutcome> {
        let end = std::time::Instant::now() + Duration::from_secs(5);
        let mut device = device;
        loop {
            match match_slot(&device, binding)? {
                SlotMatch::Free => return Ok(LoopOutcome::Free),
                SlotMatch::OtherBacking => return Ok(LoopOutcome::NotOurs),
                SlotMatch::Exact | SlotMatch::Differs => {}
            }
            let autoclear = loop_status(&device)?
                .is_some_and(|info| info.lo_flags & LO_FLAGS_AUTOCLEAR != 0);
            if !autoclear || std::time::Instant::now() >= end {
                return Ok(LoopOutcome::Unknown);
            }
            // Our own descriptor must not be the one keeping it alive.
            drop(device);
            std::thread::sleep(Duration::from_millis(20));
            device = loop {
                match open_loop(binding.minor, false) {
                    Ok(device) => break device,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(LoopOutcome::Free);
                    }
                    // Running down as its last descriptor closed.
                    Err(error)
                        if error.raw_os_error() == Some(libc::ENXIO)
                            && std::time::Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => return Err(error),
                }
            };
        }
    }

    /// A slot's current generation as the kernel reports it, for evidence and tests.
    pub fn current_generation(minor: u32) -> io::Result<LoopGeneration> {
        let device = open_loop(minor, false)?;
        Ok(LoopGeneration {
            boot_id: boot_id()?,
            diskseq: diskseq(&device)?,
        })
    }

    /// Every loop slot whose backing file lives in this work directory.
    pub fn loops_backed_in(work_dir: &Path) -> io::Result<Vec<u32>> {
        let prefix = work_dir.as_os_str().as_bytes();
        let mut found = Vec::new();
        for entry in std::fs::read_dir("/sys/block")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(minor) = name
                .to_str()
                .and_then(|n| n.strip_prefix("loop"))
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            match std::fs::read(entry.path().join("loop/backing_file")) {
                Ok(text) => {
                    if text.starts_with(prefix) && text.get(prefix.len()) == Some(&b'/') {
                        found.push(minor);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    fn statx_fd(fd: RawFd, mask: u32) -> io::Result<libc::statx> {
        // SAFETY: statx writes into the zeroed buffer; the empty name is NUL-terminated.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        cvt(unsafe {
            libc::statx(
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_INO | mask,
                &mut stx,
            )
        })?;
        Ok(stx)
    }

    /// Both mount IDs, device and inode of one descriptor. The descriptor pins its
    /// mount, so the two statx calls see the same one. A kernel that does not report
    /// `STATX_MNT_ID_UNIQUE` is an error: there is no fallback to the reusable ID.
    fn fd_identity(fd: RawFd) -> io::Result<MountedIdentity> {
        let unique = statx_fd(fd, STATX_MNT_ID_UNIQUE)?;
        if unique.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
            return Err(io::Error::other(
                "kernel reports no unique mount ID (STATX_MNT_ID_UNIQUE needs Linux 6.8)",
            ));
        }
        let old = statx_fd(fd, STATX_MNT_ID)?;
        if old.stx_mask & STATX_MNT_ID == 0 {
            return Err(io::Error::other("kernel reports no mount ID"));
        }
        if (old.stx_dev_major, old.stx_dev_minor, old.stx_ino)
            != (unique.stx_dev_major, unique.stx_dev_minor, unique.stx_ino)
        {
            return Err(io::Error::other("descriptor changed between statx calls"));
        }
        Ok(MountedIdentity {
            unique_id: unique.stx_mnt_id,
            mount_id: old.stx_mnt_id,
            st_dev: libc::makedev(old.stx_dev_major, old.stx_dev_minor),
            st_ino: old.stx_ino,
        })
    }

    /// The identity of an open directory, file or mount descriptor.
    pub fn mount_identity(file: &File) -> io::Result<MountedIdentity> {
        fd_identity(file.as_raw_fd())
    }

    /// The identity of what is mounted at one name in a directory: an `O_PATH`
    /// descriptor opened without following, then statx on that descriptor.
    pub fn mount_identity_at(dir: &File, name: &str) -> io::Result<MountedIdentity> {
        let at = openat_raw(
            dir.as_raw_fd(),
            name,
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
        )?;
        mount_identity(&at)
    }

    /// A new allocation-specific jail identity.
    pub fn new_jail_identity() -> io::Result<JailIdentity> {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(JailIdentity {
            nonce: bytes.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    /// The marker beside the jail root holds exactly this identity's bytes, root-only.
    fn check_marker(jail: &File, identity: &JailIdentity) -> io::Result<()> {
        use std::io::Read;
        let mut marker = openat_raw(
            jail.as_raw_fd(),
            JAIL_MARKER,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("jail marker is not ours: {e}")))?;
        let stat = fstat(&marker)?;
        let expected = identity.marker();
        #[allow(clippy::unnecessary_cast)]
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != 0
            || stat.st_mode & 0o7777 != 0o400
            || stat.st_nlink != 1
            || stat.st_size as u64 != expected.len() as u64
        {
            return Err(io::Error::other("jail marker is not the owned root-only file"));
        }
        let mut bytes = Vec::with_capacity(expected.len() + 1);
        (&mut marker)
            .take(expected.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes != expected {
            return Err(io::Error::other("jail marker names another allocation"));
        }
        Ok(())
    }

    fn sys_ret(rc: libc::c_long) -> io::Result<libc::c_long> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    /// A detached tmpfs from the new mount API: configured, created and mounted with no
    /// path, so its marker and jail root exist before it is attached anywhere.
    fn detached_jail_tmpfs(identity: &JailIdentity) -> io::Result<File> {
        const FSOPEN_CLOEXEC: libc::c_uint = 1;
        const FSCONFIG_SET_STRING: libc::c_uint = 1;
        const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
        const FSMOUNT_CLOEXEC: libc::c_uint = 1;
        const MOUNT_ATTR_NOSUID: libc::c_uint = 0x2;
        // SAFETY: a NUL-terminated name and constant flags.
        let fs = sys_ret(unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), FSOPEN_CLOEXEC) })?;
        // SAFETY: a new owned descriptor.
        let fs = unsafe { File::from_raw_fd(fs as RawFd) };
        let source = cstr(&identity.source())?;
        let mut options = vec![(c"source".to_owned(), source)];
        for option in JAIL_TMPFS_DATA.split(',') {
            let (key, value) = option.split_once('=').ok_or_else(|| invalid("tmpfs option"))?;
            options.push((cstr(key)?, cstr(value)?));
        }
        for (key, value) in &options {
            // SAFETY: both strings are NUL-terminated; the context descriptor is live.
            sys_ret(unsafe {
                libc::syscall(
                    libc::SYS_fsconfig,
                    fs.as_raw_fd(),
                    FSCONFIG_SET_STRING,
                    key.as_ptr(),
                    value.as_ptr(),
                    0,
                )
            })?;
        }
        // SAFETY: as above, with no key or value.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                fs.as_raw_fd(),
                FSCONFIG_CMD_CREATE,
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<libc::c_void>(),
                0,
            )
        })?;
        // SAFETY: a live context descriptor and constant flags.
        let mount = sys_ret(unsafe {
            libc::syscall(
                libc::SYS_fsmount,
                fs.as_raw_fd(),
                FSMOUNT_CLOEXEC,
                MOUNT_ATTR_NOSUID,
            )
        })?;
        // SAFETY: a new owned descriptor on the detached mount's root.
        Ok(unsafe { File::from_raw_fd(mount as RawFd) })
    }

    fn mount_raw(
        source: Option<&str>,
        target: &Path,
        fstype: Option<&str>,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) -> io::Result<()> {
        let source = source.map(cstr).transpose()?;
        let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| invalid("path"))?;
        let fstype = fstype.map(cstr).transpose()?;
        let data = data.map(cstr).transpose()?;
        // SAFETY: every pointer is NUL-terminated or null.
        cvt(unsafe {
            libc::mount(
                source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                target.as_ptr(),
                fstype.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                flags,
                data.as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
            )
        })?;
        Ok(())
    }

    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
    const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;

    /// The jail tmpfs, created detached with its marker and jail root, and identified
    /// before it is attached anywhere. Its owner journals [`DetachedJail::record`], then
    /// calls [`attach_jail`]. If the owner dies first, the detached mount dies with its
    /// descriptor, so a jail tmpfs at the path whose unique ID was never journaled can
    /// only be a replacement.
    pub struct DetachedJail {
        mount: File,
        jail_dir: File,
        pub record: JailMount,
    }

    /// Creates the allocation's private jail directory and its mandatory bounded tmpfs,
    /// detached: the marker and jail root exist before the jailer could write anything,
    /// and the record carries the tmpfs's unique mount ID and this boot's ID.
    pub fn prepare_jail(paths: &AllocationPaths, identity: &JailIdentity) -> io::Result<DetachedJail> {
        if !identity.valid() {
            return Err(invalid("jail identity"));
        }
        let boot_id = boot_id()?;
        let firecracker = open_trusted(&Path::new(JAIL_BASE).join("firecracker"))?;
        let name = paths
            .jail_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("jail name"))?;
        let jail_dir = private_dir(&firecracker, name, false)?;
        let mount = detached_jail_tmpfs(identity)?;
        {
            use std::io::Write;
            let mut marker = openat_raw(
                mount.as_raw_fd(),
                JAIL_MARKER,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                0o400,
            )?;
            marker.write_all(&identity.marker())?;
        }
        let root_name = cstr("root")?;
        // SAFETY: a NUL-terminated name under a live mount descriptor.
        cvt(unsafe { libc::mkdirat(mount.as_raw_fd(), root_name.as_ptr(), 0o700) })?;
        let ids = mount_identity(&mount)?;
        let root = mount_identity_at(&mount, "root")?;
        if (root.unique_id, root.st_dev) != (ids.unique_id, ids.st_dev) {
            return Err(io::Error::other("jail root is not on the jail tmpfs"));
        }
        Ok(DetachedJail {
            mount,
            jail_dir,
            record: JailMount {
                boot_id,
                unique_id: ids.unique_id,
                mount_id: ids.mount_id,
                st_dev: ids.st_dev,
                st_ino: ids.st_ino,
                root_ino: root.st_ino,
            },
        })
    }

    /// Attaches the journaled detached tmpfs onto the jail directory's descriptor,
    /// makes exactly that mount private, and proves the path now shows the journaled
    /// mount. Returns the mounted jail directory and the jail root.
    pub fn attach_jail(
        paths: &AllocationPaths,
        identity: &JailIdentity,
        detached: DetachedJail,
    ) -> io::Result<(File, File)> {
        let DetachedJail {
            mount,
            jail_dir,
            record,
        } = detached;
        // SAFETY: both descriptors are live; empty paths name them exactly.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                mount.as_raw_fd(),
                c"".as_ptr(),
                jail_dir.as_raw_fd(),
                c"".as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
            )
        })?;
        // Private propagation of exactly this mount, through its own descriptor.
        let own = PathBuf::from(format!("/proc/self/fd/{}", mount.as_raw_fd()));
        mount_raw(None, &own, None, libc::MS_PRIVATE, None)?;
        drop((mount, jail_dir));
        let jail = open_trusted(&paths.jail_dir)?;
        let seen = mount_identity(&jail)?;
        if (seen.unique_id, seen.mount_id, seen.st_dev, seen.st_ino)
            != (record.unique_id, record.mount_id, record.st_dev, record.st_ino)
        {
            return Err(io::Error::other("the attached jail mount is not the journaled one"));
        }
        check_marker(&jail, identity)?;
        let root = open_dir_at(&jail, "root")?;
        let root_identity = mount_identity(&root)?;
        if (root_identity.unique_id, root_identity.st_ino) != (record.unique_id, record.root_ino) {
            return Err(io::Error::other("jail root is not on the jail tmpfs"));
        }
        Ok((jail, root))
    }

    /// One read-only artifact bind, cloned detached from an already verified
    /// descriptor and identified before it is attached. Its owner journals every
    /// record, then calls [`attach_bind`]; if the owner dies first, the clone dies with
    /// its descriptor.
    pub struct DetachedBind {
        tree: File,
        pub record: BindMount,
    }

    /// `open_tree(OPEN_TREE_CLONE)` of the descriptor itself (never a pathname lookup of
    /// the original), made read-only, nosuid, nodev and private with `mount_setattr`
    /// while detached, plus the empty file it will be attached over.
    pub fn prepare_bind(root: &File, name: &str, source: &File) -> io::Result<DetachedBind> {
        const OPEN_TREE_CLONE: libc::c_uint = 1;
        const MOUNT_ATTR_RDONLY: u64 = 0x1;
        const MOUNT_ATTR_NOSUID: u64 = 0x2;
        const MOUNT_ATTR_NODEV: u64 = 0x4;
        #[repr(C)]
        struct MountAttr {
            attr_set: u64,
            attr_clr: u64,
            propagation: u64,
            userns_fd: u64,
        }
        let name = BINDS
            .iter()
            .copied()
            .find(|b| *b == name)
            .ok_or_else(|| invalid("not a contract bind"))?;
        let boot_id = boot_id()?;
        // An empty target file to mount over.
        drop(openat_raw(
            root.as_raw_fd(),
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o400,
        )?);
        // SAFETY: a live descriptor and an empty NUL-terminated path.
        let tree = sys_ret(unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                source.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint | OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
            )
        })?;
        // SAFETY: a new owned descriptor on the detached clone.
        let tree = unsafe { File::from_raw_fd(tree as RawFd) };
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
            attr_clr: 0,
            propagation: libc::MS_PRIVATE,
            userns_fd: 0,
        };
        // SAFETY: attr is a complete version-0 mount_attr; the path is empty.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                tree.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                &attr,
                std::mem::size_of::<MountAttr>(),
            )
        })?;
        let ids = mount_identity(&tree)?;
        let original = source.metadata()?;
        if (ids.st_dev, ids.st_ino) != (original.dev(), original.ino()) {
            return Err(io::Error::other(format!(
                "{name} clone is not the verified inode"
            )));
        }
        Ok(DetachedBind {
            tree,
            record: BindMount {
                name: name.to_string(),
                boot_id,
                unique_id: ids.unique_id,
                mount_id: ids.mount_id,
                st_dev: ids.st_dev,
                st_ino: ids.st_ino,
            },
        })
    }

    /// Attaches one journaled clone at its fixed jail name and proves the name now
    /// shows exactly the journaled mount.
    pub fn attach_bind(root: &File, detached: DetachedBind) -> io::Result<()> {
        let DetachedBind { tree, record } = detached;
        let name = cstr(&record.name)?;
        // SAFETY: both descriptors are live; the target name is NUL-terminated and is
        // resolved under the jail root without following a final link.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                tree.as_raw_fd(),
                c"".as_ptr(),
                root.as_raw_fd(),
                name.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            )
        })?;
        drop(tree);
        let seen = mount_identity_at(root, &record.name)?;
        if (seen.unique_id, seen.mount_id, seen.st_dev, seen.st_ino)
            != (record.unique_id, record.mount_id, record.st_dev, record.st_ino)
            || seen.unique_id == mount_identity(root)?.unique_id
        {
            return Err(io::Error::other(format!(
                "{} is not the journaled bind",
                record.name
            )));
        }
        Ok(())
    }

    /// The `/work` block node, owned U:G 0600. No loop-control or host `/dev` enters.
    pub fn work_node(root: &File, minor: u32, uid: u32, gid: u32) -> io::Result<()> {
        let c = cstr("work")?;
        // SAFETY: c is NUL-terminated.
        cvt(unsafe {
            libc::mknodat(
                root.as_raw_fd(),
                c.as_ptr(),
                libc::S_IFBLK | 0o600,
                libc::makedev(LOOP_MAJOR, minor),
            )
        })?;
        cvt(unsafe {
            libc::fchownat(
                root.as_raw_fd(),
                c.as_ptr(),
                uid,
                gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        Ok(())
    }

    fn open_trusted_jail_root(paths: &AllocationPaths) -> io::Result<File> {
        let dir = open_trusted(&paths.jail_dir)?;
        open_dir_at(&dir, "root")
    }

    fn chown_mode(parent: &File, name: &str, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: c is NUL-terminated; no link is followed.
        cvt(unsafe {
            libc::fchownat(
                parent.as_raw_fd(),
                c.as_ptr(),
                uid,
                gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        cvt(unsafe { libc::fchmodat(parent.as_raw_fd(), c.as_ptr(), mode, 0) })?;
        Ok(())
    }

    fn list(dir: &File) -> io::Result<Vec<String>> {
        let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let mut names = Vec::new();
        for entry in std::fs::read_dir(path)? {
            names.push(
                entry?
                    .file_name()
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 jail entry"))?
                    .to_string(),
            );
            if names.len() > 1024 {
                return Err(io::Error::other("jail directory exceeds its inode bound"));
            }
        }
        names.sort();
        Ok(names)
    }

    /// The post-jailer hardening of section 7.1, with V stopped: root, `/dev` and
    /// `/dev/net` root-owned 0755, cache files root-owned 0444, only `/run` writable
    /// by U:G, only `/dev/kvm`, `/dev/urandom` and `/work` reachable as U:G devices,
    /// and `/firecracker` the read-only bind of the expected inode. Any unexpected
    /// entry, link or type retires the VM: nothing is followed or repaired.
    pub fn harden_jail(
        paths: &AllocationPaths,
        mount: &JailMount,
        vmm: (u64, u64),
        work_minor: u32,
        uid: u32,
        gid: u32,
    ) -> io::Result<()> {
        let root = open_trusted_jail_root(paths)?;
        if mount_identity(&root)?
            != (MountedIdentity {
                unique_id: mount.unique_id,
                mount_id: mount.mount_id,
                st_dev: mount.st_dev,
                st_ino: mount.root_ino,
            })
        {
            return Err(io::Error::other("jail root mount was replaced"));
        }
        let mut seen = 0usize;
        harden_dir(&root, "", &mut seen, (vmm, work_minor, uid, gid))?;
        chown_dir(&root, 0, 0, 0o755)?;
        // The VMM executable: the read-only bind of the retained inode, mode 0555.
        let firecracker = fstatat(&root, "firecracker")?;
        #[allow(clippy::unnecessary_cast)]
        if (firecracker.st_dev as u64, firecracker.st_ino as u64) != vmm
            || firecracker.st_uid != 0
            || firecracker.st_mode & 0o7777 != 0o555
        {
            return Err(io::Error::other(
                "/firecracker is not the root-owned 0555 bind",
            ));
        }
        // Exactly the contract's mounts remain: the tmpfs at the jail directory and the
        // five read-only binds directly on it.
        let mounts = parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo")?)?;
        let under = mounts_under(&mounts, &paths.jail_dir);
        let tmpfs: Vec<&MountEntry> = under
            .iter()
            .filter(|m| m.mount_point == paths.jail_dir)
            .collect();
        let mut names: Vec<String> = under
            .iter()
            .filter(|m| m.mount_point != paths.jail_dir)
            .filter_map(|m| bind_name(paths, m).map(str::to_owned))
            .collect();
        names.sort();
        let mut expected: Vec<String> = BINDS.iter().map(|s| s.to_string()).collect();
        expected.sort();
        if tmpfs.len() != 1
            || tmpfs[0].mount_id != mount.mount_id
            || names != expected
            || under.len() != BINDS.len() + 1
            || under.iter().any(|m| {
                m.mount_point != paths.jail_dir
                    && (!m.read_only || m.parent_id != mount.mount_id)
            })
        {
            return Err(io::Error::other(
                "jail mount tree differs from the contract",
            ));
        }
        Ok(())
    }

    fn chown_dir(dir: &File, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
        // SAFETY: a live directory descriptor.
        cvt(unsafe { libc::fchown(dir.as_raw_fd(), uid, gid) })?;
        cvt(unsafe { libc::fchmod(dir.as_raw_fd(), mode) })?;
        Ok(())
    }

    type HardenContext = ((u64, u64), u32, u32, u32);

    fn harden_dir(
        dir: &File,
        prefix: &str,
        seen: &mut usize,
        context: HardenContext,
    ) -> io::Result<()> {
        let (_, work_minor, uid, gid) = context;
        for name in list(dir)? {
            *seen += 1;
            if *seen > 1024 {
                return Err(io::Error::other("jail exceeds its inode bound"));
            }
            let path = format!("{prefix}/{name}");
            let stat = fstatat(dir, &name)?;
            let kind = stat.st_mode & libc::S_IFMT;
            let device = (libc::major(stat.st_rdev), libc::minor(stat.st_rdev));
            match (path.as_str(), kind) {
                // Read-only binds: verified separately; chmod would fail on them.
                (
                    "/kernel" | "/rootfs" | "/config.json" | "/identity" | "/firecracker",
                    libc::S_IFREG,
                ) => {}
                ("/work", libc::S_IFBLK) => {
                    if device != (LOOP_MAJOR, work_minor)
                        || stat.st_uid != uid
                        || stat.st_gid != gid
                        || stat.st_mode & 0o7777 != 0o600
                    {
                        return Err(io::Error::other("/work node differs from its record"));
                    }
                }
                ("/firecracker.pid", libc::S_IFREG) => chown_mode(dir, &name, 0, 0, 0o444)?,
                ("/dev" | "/dev/net", libc::S_IFDIR) => {
                    let child = open_dir_at(dir, &name)?;
                    harden_dir(&child, &path, seen, context)?;
                    chown_dir(&child, 0, 0, 0o755)?;
                }
                ("/dev/kvm", libc::S_IFCHR) if device == (10, 232) => {
                    chown_mode(dir, &name, uid, gid, 0o600)?
                }
                ("/dev/urandom", libc::S_IFCHR) if device == (1, 9) => {
                    chown_mode(dir, &name, uid, gid, 0o600)?
                }
                // Present only for networking and snapshot restore: neither applies.
                ("/dev/net/tun", libc::S_IFCHR) if device == (10, 200) => {
                    chown_mode(dir, &name, 0, 0, 0o600)?
                }
                ("/dev/userfaultfd", libc::S_IFCHR) if device.0 == 10 => {
                    chown_mode(dir, &name, 0, 0, 0o600)?
                }
                ("/run", libc::S_IFDIR) => {
                    let child = open_dir_at(dir, &name)?;
                    for entry in list(&child)? {
                        let inner = fstatat(&child, &entry)?;
                        if entry != "vsock.sock"
                            || inner.st_mode & libc::S_IFMT != libc::S_IFSOCK
                            || inner.st_uid != uid
                        {
                            return Err(io::Error::other(format!("unexpected /run/{entry}")));
                        }
                    }
                    if stat.st_uid != uid || stat.st_gid != gid {
                        return Err(io::Error::other("/run owner differs"));
                    }
                }
                (p, libc::S_IFDIR) if p == "/sys" || p.starts_with("/sys/") => {
                    let child = open_dir_at(dir, &name)?;
                    harden_dir(&child, &path, seen, context)?;
                    chown_dir(&child, 0, 0, 0o755)?;
                }
                (p, libc::S_IFREG) if p.starts_with("/sys/devices/system/cpu/cpu0/") => {
                    chown_mode(dir, &name, 0, 0, 0o444)?
                }
                _ => {
                    return Err(io::Error::other(format!(
                        "unexpected jail entry {path} ({kind:o})"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The contract bind a mount entry names, if it is exactly `<jail root>/<bind>`.
    fn bind_name(paths: &AllocationPaths, entry: &MountEntry) -> Option<&'static str> {
        BINDS
            .iter()
            .copied()
            .find(|b| entry.mount_point == paths.jail_root.join(b))
    }

    /// What the journal knows of one allocation's jail mounts.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct JailRecords<'a> {
        /// The source and marker nonce, journaled before the mount was created.
        pub identity: Option<&'a JailIdentity>,
        /// The tmpfs's unique ID, journaled before it was attached.
        pub mount: Option<&'a JailMount>,
        /// Every bind's unique ID, journaled before any was attached.
        pub binds: Option<&'a [BindMount]>,
    }

    /// The tmpfs at the jail directory is the journaled one: this boot, the only mount
    /// there, and the journaled unique mount ID on a fresh no-follow descriptor. The
    /// reusable tuple, source and marker are secondary checks. Returns that descriptor
    /// and the reusable mount ID nested mounts name as their parent.
    fn verify_jail_tmpfs(
        paths: &AllocationPaths,
        identity: &JailIdentity,
        recorded: &JailMount,
        entries: &[MountEntry],
    ) -> io::Result<(File, u64)> {
        let at: Vec<&MountEntry> = entries
            .iter()
            .filter(|m| m.mount_point == paths.jail_dir)
            .collect();
        let [entry] = at.as_slice() else {
            return Err(io::Error::other(format!(
                "{} mounts at the jail directory, not one",
                at.len()
            )));
        };
        let jail = open_trusted(&paths.jail_dir)?;
        let seen = mount_identity(&jail)?;
        if seen.unique_id != recorded.unique_id {
            return Err(io::Error::other(format!(
                "jail mount {} is not the journaled mount {}",
                seen.unique_id, recorded.unique_id
            )));
        }
        if seen.mount_id != entry.mount_id
            || (recorded.mount_id, recorded.st_dev, recorded.st_ino)
                != (seen.mount_id, seen.st_dev, seen.st_ino)
            || entry.fs_type != "tmpfs"
            || entry.source != identity.source()
        {
            return Err(io::Error::other("jail mount differs from its record"));
        }
        check_marker(&jail, identity)?;
        Ok((jail, entry.mount_id))
    }

    /// One nested mount is a journaled bind: exactly a contract bind name, directly on
    /// our tmpfs, read-only, and showing its journaled unique mount ID and inode now. A
    /// bind is journaled before it is attached, so one with no record is never ours by
    /// its name: the allocation is Unknown.
    fn verify_bind<'b>(
        paths: &AllocationPaths,
        root: &File,
        entry: &MountEntry,
        tmpfs_id: u64,
        binds: Option<&'b [BindMount]>,
    ) -> io::Result<&'b BindMount> {
        let name = bind_name(paths, entry).ok_or_else(|| {
            io::Error::other(format!("unknown mount {}", entry.mount_point.display()))
        })?;
        if entry.parent_id != tmpfs_id || !entry.read_only {
            return Err(io::Error::other(format!(
                "{name} is not a read-only bind on the jail tmpfs"
            )));
        }
        let record = binds
            .ok_or_else(|| io::Error::other(format!("{name} is mounted but no bind was journaled")))?
            .iter()
            .find(|b| b.name == name)
            .ok_or_else(|| io::Error::other(format!("{name} has no bind record")))?;
        let seen = mount_identity_at(root, name)?;
        if seen.unique_id != record.unique_id {
            return Err(io::Error::other(format!(
                "{name} mount {} is not the journaled mount {}",
                seen.unique_id, record.unique_id
            )));
        }
        if seen.mount_id != entry.mount_id
            || (record.mount_id, record.st_dev, record.st_ino)
                != (seen.mount_id, seen.st_dev, seen.st_ino)
        {
            return Err(io::Error::other(format!("{name} differs from its record")));
        }
        Ok(record)
    }

    fn read_mounts() -> io::Result<Vec<MountEntry>> {
        parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo")?)
    }

    fn umount_exact(path: &Path) -> io::Result<()> {
        let target = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path"))?;
        // SAFETY: NUL-terminated; UMOUNT_NOFOLLOW refuses a link at the target.
        cvt(unsafe { libc::umount2(target.as_ptr(), libc::UMOUNT_NOFOLLOW) })?;
        Ok(())
    }

    /// Unmounts the allocation's jail mounts, deepest first, never lazily. Every mount
    /// is unmounted only if the unique mount ID at its path, read immediately before its
    /// own unmount, is the journaled one from this boot; the reusable tuple, source and
    /// marker must also match. Nothing mounted is nothing to do. A mount whose unique ID
    /// was never journaled, a record from another boot, a changed ID, or any other mount
    /// under the jail directory is refused and left exactly as it is, before anything is
    /// unmounted: ownership is never inferred from the deterministic path or a copyable
    /// marker, so the allocation stays charged (Unknown) for the operator.
    pub fn unmount_jail(paths: &AllocationPaths, recorded: JailRecords<'_>) -> io::Result<()> {
        let entries = read_mounts()?;
        let found = mounts_under(&entries, &paths.jail_dir);
        if found.is_empty() {
            return Ok(());
        }
        let identity = recorded.identity.ok_or_else(|| {
            io::Error::other("a jail mount exists but no identity was journaled")
        })?;
        let mount = recorded.mount.ok_or_else(|| {
            io::Error::other("a jail mount exists but no unique mount ID was journaled")
        })?;
        let boot = boot_id()?;
        if mount.boot_id != boot
            || recorded.binds.is_some_and(|binds| binds.iter().any(|b| b.boot_id != boot))
        {
            return Err(io::Error::other(
                "the journaled jail mounts belong to another boot: this mount is not ours",
            ));
        }
        let (jail, tmpfs_id) = verify_jail_tmpfs(paths, identity, mount, &found)?;
        let root = open_dir_at(&jail, "root")?;
        drop(jail);
        // Check the whole tree before changing anything.
        for entry in found.iter().filter(|m| m.mount_point != paths.jail_dir) {
            verify_bind(paths, &root, entry, tmpfs_id, recorded.binds)?;
        }
        for entry in found.iter().filter(|m| m.mount_point != paths.jail_dir) {
            // Again, at the last moment: still the only mount there, still journaled.
            let now = read_mounts()?;
            let current: Vec<&MountEntry> = now
                .iter()
                .filter(|m| m.mount_point == entry.mount_point)
                .collect();
            if current.len() != 1 || current[0] != entry {
                return Err(io::Error::other(format!(
                    "{} changed before its unmount",
                    entry.mount_point.display()
                )));
            }
            verify_bind(paths, &root, entry, tmpfs_id, recorded.binds)?;
            umount_exact(&entry.mount_point)?;
        }
        drop(root);
        // The tmpfs last: re-verified by its unique ID, its descriptor closed, unmounted.
        let now = read_mounts()?;
        let left = mounts_under(&now, &paths.jail_dir);
        let (jail, again) = verify_jail_tmpfs(paths, identity, mount, &left)?;
        if again != tmpfs_id || left.len() != 1 {
            return Err(io::Error::other("jail mounts changed during unmount"));
        }
        drop(jail);
        umount_exact(&paths.jail_dir)?;
        if !mounts_under(&read_mounts()?, &paths.jail_dir).is_empty() {
            return Err(io::Error::other("a jail mount remains"));
        }
        Ok(())
    }

    /// Removes the unmounted, empty jail directory. Its marker and root lived on the
    /// tmpfs, so anything left in it is unknown and refused: nothing is deleted
    /// recursively.
    pub fn remove_jail_dirs(paths: &AllocationPaths) -> io::Result<()> {
        let firecracker = match open_trusted(&Path::new(JAIL_BASE).join("firecracker")) {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let name = paths
            .jail_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("jail name"))?;
        let jail = match open_dir_at(&firecracker, name) {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !mounts_under(&read_mounts()?, &paths.jail_dir).is_empty() {
            return Err(io::Error::other("the jail directory is still mounted"));
        }
        if let Some(entry) = list(&jail)?.first() {
            return Err(io::Error::other(format!("unknown jail entry {entry}")));
        }
        drop(jail);
        unlink_dir(&firecracker, name)?;
        firecracker.sync_all()?;
        Ok(())
    }

    fn unlink_dir(parent: &File, name: &str) -> io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: c is NUL-terminated; AT_REMOVEDIR removes only an empty directory.
        cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) })?;
        Ok(())
    }

    fn unlink_file(parent: &File, name: &str) -> io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: c is NUL-terminated.
        cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), 0) })?;
        Ok(())
    }

    /// Removes the private work directory's three owned files and then the directory.
    /// A recorded identity must match; an unrecorded file is ours only by its fixed
    /// name inside this root-only directory. Anything else is refused.
    pub fn remove_work(
        paths: &AllocationPaths,
        recorded: &std::collections::BTreeMap<String, FileIdentity>,
    ) -> io::Result<()> {
        let Some(dir) = open_work_dir(paths)? else {
            return Ok(());
        };
        for name in list(&dir)? {
            if ![WORK_FILE, IDENTITY_FILE, CONFIG_FILE].contains(&name.as_str()) {
                return Err(io::Error::other(format!("unknown work entry {name}")));
            }
            let stat = fstatat(&dir, &name)?;
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || stat.st_nlink != 1
                || stat.st_uid != 0
            {
                return Err(io::Error::other(format!("{name} is not an owned file")));
            }
            if let Some(identity) = recorded.get(&name) {
                #[allow(clippy::unnecessary_cast)]
                if (stat.st_dev as u64, stat.st_ino as u64) != (identity.st_dev, identity.st_ino) {
                    return Err(io::Error::other(format!("{name} was replaced")));
                }
            }
        }
        for name in list(&dir)? {
            unlink_file(&dir, &name)?;
        }
        dir.sync_all()?;
        let instance = open_trusted(paths.work_dir.parent().ok_or_else(|| invalid("work"))?)?;
        let name = paths
            .work_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("work name"))?;
        unlink_dir(&instance, name)?;
        instance.sync_all()?;
        Ok(())
    }

    /// Every owned name still present for one allocation: cgroup, mounts, jail and
    /// work directories, and loop slots backed inside the work directory. Read
    /// failures are errors, never absence.
    pub fn observe_presence(paths: &AllocationPaths, cgroup: &str) -> io::Result<Presence> {
        let mut names = Vec::new();
        if super::super::cgroup::exists(cgroup)? {
            names.push("cgroup".into());
        }
        let entries = parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo")?)?;
        for entry in mounts_under(&entries, &paths.jail_dir) {
            names.push(format!("mount:{}", entry.mount_point.display()));
        }
        match std::fs::symlink_metadata(&paths.jail_dir) {
            Ok(_) => names.push("jail".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match std::fs::symlink_metadata(&paths.work_dir) {
            Ok(_) => names.push("work".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        for minor in loops_backed_in(&paths.work_dir)? {
            names.push(format!("loop{minor}"));
        }
        names.sort();
        Ok(Presence { names })
    }

    /// Hashes a descriptor in bounded chunks, calling `tick` between them so a long
    /// read never silences the caller's heartbeat.
    pub fn hash_with(
        file: &File,
        bytes: u64,
        tick: &mut dyn FnMut(),
    ) -> io::Result<crate::model::Digest> {
        use sha2::Digest as _;
        use std::os::unix::fs::FileExt;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; 1 << 20];
        let mut offset = 0u64;
        while offset < bytes {
            let want = ((bytes - offset) as usize).min(buffer.len());
            let n = file.read_at(&mut buffer[..want], offset)?;
            if n == 0 {
                return Err(io::Error::other("descriptor shorter than its size"));
            }
            hasher.update(&buffer[..n]);
            offset += n as u64;
            tick();
        }
        let mut probe = [0u8; 1];
        if file.read_at(&mut probe, offset)? != 0 {
            return Err(io::Error::other("descriptor longer than its size"));
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(crate::model::Digest::from_bytes(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A fresh allocation's paths under the real base, for the root storage tests.
    #[cfg(target_os = "linux")]
    fn scratch_paths() -> AllocationPaths {
        let mut bytes = [0u8; 16];
        use std::io::Read;
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let jail_dir = Path::new(JAIL_BASE).join("firecracker").join(format!("fc-{h}"));
        let work_dir = Path::new(WORK_BASE).join(&h).join(format!("fc-{h}"));
        AllocationPaths {
            jail_root: jail_dir.join("root"),
            work_file: work_dir.join(WORK_FILE),
            jail_dir,
            work_dir,
        }
    }

    #[cfg(target_os = "linux")]
    fn mounted_at(path: &Path) -> Vec<MountEntry> {
        let entries = parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo").unwrap())
            .unwrap();
        entries
            .into_iter()
            .filter(|e| e.mount_point == path)
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn raw_mount(source: &str, target: &Path, fstype: &str, data: &str) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source = CString::new(source).unwrap();
        let target_c = CString::new(target.as_os_str().as_bytes()).unwrap();
        let fstype = CString::new(fstype).unwrap();
        let data = CString::new(data).unwrap();
        // SAFETY: every pointer is NUL-terminated.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                fstype.as_ptr(),
                libc::MS_NOSUID,
                data.as_ptr().cast(),
            )
        };
        assert_eq!(rc, 0, "mount {}: {}", target.display(), io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    fn raw_umount(target: &Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let target_c = CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated.
        let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::UMOUNT_NOFOLLOW) };
        assert_eq!(rc, 0, "umount {}: {}", target.display(), io::Error::last_os_error());
    }

    /// The product's jail creation: detached, identified (the caller journals the
    /// record here), then attached.
    #[cfg(target_os = "linux")]
    fn create_jail(paths: &AllocationPaths, identity: &JailIdentity) -> (File, File, JailMount) {
        let detached = prepare_jail(paths, identity).unwrap();
        let record = detached.record.clone();
        let (jail, root) = attach_jail(paths, identity, detached).unwrap();
        (jail, root, record)
    }

    /// The product's bind: cloned detached, identified, then attached.
    #[cfg(target_os = "linux")]
    fn bind_read_only(root: &File, name: &str, source: &File) -> BindMount {
        let detached = prepare_bind(root, name, source).unwrap();
        let record = detached.record.clone();
        attach_bind(root, detached).unwrap();
        record
    }

    /// A root actor's plain read-only bind of a path at a jail name.
    #[cfg(target_os = "linux")]
    fn raw_bind_read_only(source: &Path, target: &Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source = CString::new(source.as_os_str().as_bytes()).unwrap();
        let target = CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated paths.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "bind: {}", io::Error::last_os_error());
        // SAFETY: as above.
        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "remount: {}", io::Error::last_os_error());
    }

    /// B4 break-it finding 1, as a regression: a fresh tmpfs mounted in place of the
    /// allocation's own, a foreign marker and a mount with no journaled identity are all
    /// refused and left mounted; a mount nested anywhere but a journaled bind is refused
    /// before anything is unmounted; the genuine, fully journaled tree is removed.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_cleanup_refuses_a_replacement_jail_mount() {
        prepare_jail_base().unwrap();
        let paths = scratch_paths();
        let identity = new_jail_identity().unwrap();
        let (jail, root, recorded) = create_jail(&paths, &identity);
        drop((jail, root));
        let records = JailRecords {
            identity: Some(&identity),
            mount: Some(&recorded),
            binds: Some(&[]),
        };

        // The root fault: ours unmounted, a fresh tmpfs with the same source and a jail
        // root put in its place.
        raw_umount(&paths.jail_dir);
        raw_mount(&identity.source(), &paths.jail_dir, "tmpfs", JAIL_TMPFS_DATA);
        std::fs::create_dir(&paths.jail_root).unwrap();
        let replacement = mount_identity(&File::open(&paths.jail_dir).unwrap()).unwrap();
        let refused = unmount_jail(&paths, records);
        assert!(refused.is_err(), "cleanup accepted a replacement");
        assert_eq!(mounted_at(&paths.jail_dir).len(), 1, "the replacement survived");
        eprintln!(
            "B4 evidence: recorded {recorded:?}, replacement {replacement:?}; refused: {}",
            refused.unwrap_err()
        );

        // A marker naming another allocation.
        let other = new_jail_identity().unwrap();
        let marker = paths.jail_dir.join(JAIL_MARKER);
        std::fs::write(&marker, other.marker()).unwrap();
        std::fs::set_permissions(&marker, std::os::unix::fs::PermissionsExt::from_mode(0o400))
            .unwrap();
        assert!(unmount_jail(&paths, records).is_err(), "a foreign marker");
        // No journaled identity or unique ID at all: never inferred from the path.
        assert!(unmount_jail(&paths, JailRecords::default()).is_err());
        assert!(
            unmount_jail(
                &paths,
                JailRecords {
                    mount: None,
                    ..records
                }
            )
            .is_err()
        );
        // A record from another boot names nothing that exists now.
        let other_boot = JailMount {
            boot_id: "00000000-0000-4000-8000-000000000000".into(),
            ..recorded.clone()
        };
        assert!(
            unmount_jail(
                &paths,
                JailRecords {
                    mount: Some(&other_boot),
                    ..records
                }
            )
            .is_err()
        );
        assert_eq!(mounted_at(&paths.jail_dir).len(), 1);
        raw_umount(&paths.jail_dir);
        remove_jail_dirs(&paths).unwrap();

        // The genuine tree: a foreign nested mount and a journaled bind whose unique ID
        // differs are refused; nothing is unmounted until the whole tree checks out.
        let identity = new_jail_identity().unwrap();
        let (jail, root, recorded) = create_jail(&paths, &identity);
        let scratch = std::env::temp_dir().join(format!("b4-bind-{}", std::process::id()));
        std::fs::write(&scratch, b"kernel").unwrap();
        let source = File::open(&scratch).unwrap();
        let bind = bind_read_only(&root, "kernel", &source);
        drop(source);
        std::fs::create_dir(paths.jail_root.join("x")).unwrap();
        raw_mount("foreign", &paths.jail_root.join("x"), "tmpfs", "size=1M");
        drop((jail, root));
        let journaled = [bind.clone()];
        let records = JailRecords {
            identity: Some(&identity),
            mount: Some(&recorded),
            binds: Some(&journaled),
        };
        assert!(unmount_jail(&paths, records).is_err(), "a foreign nested mount");
        assert_eq!(mounted_at(&paths.jail_root.join("kernel")).len(), 1);
        assert_eq!(mounted_at(&paths.jail_dir).len(), 1);
        raw_umount(&paths.jail_root.join("x"));
        std::fs::remove_dir(paths.jail_root.join("x")).unwrap();
        let wrong = [BindMount {
            unique_id: bind.unique_id + 1,
            ..bind.clone()
        }];
        assert!(
            unmount_jail(
                &paths,
                JailRecords {
                    binds: Some(&wrong),
                    ..records
                }
            )
            .is_err()
        );
        assert_eq!(mounted_at(&paths.jail_root.join("kernel")).len(), 1);
        unmount_jail(&paths, records).unwrap();
        assert!(mounted_at(&paths.jail_root.join("kernel")).is_empty());
        assert!(mounted_at(&paths.jail_dir).is_empty());
        remove_jail_dirs(&paths).unwrap();
        assert!(!paths.jail_dir.exists());
        std::fs::remove_file(&scratch).unwrap();
    }

    /// B4 recheck finding 1 (was `poc_b4_recheck_spoofed_marker_unmounts_replacement`):
    /// root copies the journaled source, the marker and the jail root into a fresh
    /// tmpfs, and the kernel reuses the reusable `{mount_id, st_dev, st_ino}` exactly.
    /// Only the unique mount ID differs, and cleanup refuses on it and leaves the
    /// replacement mounted.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_cleanup_refuses_a_copied_marker_replacement() {
        use std::os::unix::fs::PermissionsExt;
        prepare_jail_base().unwrap();
        let paths = scratch_paths();
        let identity = new_jail_identity().unwrap();
        let (jail, root, recorded) = create_jail(&paths, &identity);
        drop((jail, root));
        raw_umount(&paths.jail_dir);
        raw_mount(&identity.source(), &paths.jail_dir, "tmpfs", JAIL_TMPFS_DATA);
        std::fs::write(paths.jail_dir.join(JAIL_MARKER), identity.marker()).unwrap();
        std::fs::set_permissions(
            paths.jail_dir.join(JAIL_MARKER),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        std::fs::create_dir(&paths.jail_root).unwrap();
        let replacement = mount_identity(&File::open(&paths.jail_dir).unwrap()).unwrap();
        let reused = (replacement.mount_id, replacement.st_dev, replacement.st_ino)
            == (recorded.mount_id, recorded.st_dev, recorded.st_ino);
        let result = unmount_jail(
            &paths,
            JailRecords {
                identity: Some(&identity),
                mount: Some(&recorded),
                binds: Some(&[]),
            },
        );
        let survived = mounted_at(&paths.jail_dir).len() == 1;
        if survived {
            raw_umount(&paths.jail_dir);
        }
        remove_jail_dirs(&paths).unwrap();
        assert_ne!(replacement.unique_id, recorded.unique_id);
        let error = result.expect_err("cleanup accepted the copied marker");
        assert!(survived, "the replacement was unmounted");
        eprintln!(
            "B4 evidence: copied source+marker, reusable tuple reused: {reused}; unique \
             {} != journaled {}; refused: {error}",
            replacement.unique_id, recorded.unique_id
        );
    }

    /// B4 recheck finding 1 (was `poc_b4_recheck_unrecorded_bind_replacement_is_unmounted`):
    /// a bind whose unique ID was never journaled is never ours by its contract name,
    /// and a journaled bind replaced by another inode, or by a fresh bind of the very
    /// same inode, is refused on its unique ID. Every one stays mounted.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_cleanup_refuses_an_unrecorded_or_replaced_bind() {
        prepare_jail_base().unwrap();
        let paths = scratch_paths();
        let identity = new_jail_identity().unwrap();
        let (jail, root, recorded) = create_jail(&paths, &identity);
        let first = std::env::temp_dir().join(format!("b4-bind-first-{}", std::process::id()));
        let other = std::env::temp_dir().join(format!("b4-bind-other-{}", std::process::id()));
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&other, b"other").unwrap();
        let original = bind_read_only(&root, "kernel", &File::open(&first).unwrap());
        drop(jail);
        let kernel = paths.jail_root.join("kernel");
        let still_mounted = || mounted_at(&kernel).len() == 1;

        // Mounted but never journaled.
        let error = unmount_jail(
            &paths,
            JailRecords {
                identity: Some(&identity),
                mount: Some(&recorded),
                binds: None,
            },
        )
        .expect_err("an unrecorded bind was accepted by its name");
        assert!(still_mounted(), "the unrecorded bind was unmounted");
        eprintln!("B4 evidence: unrecorded bind refused: {error}");

        let journaled = [original.clone()];
        let records = JailRecords {
            identity: Some(&identity),
            mount: Some(&recorded),
            binds: Some(&journaled),
        };
        for (label, source) in [("another inode", &other), ("the same inode", &first)] {
            raw_umount(&kernel);
            raw_bind_read_only(source, &kernel);
            let now = mount_identity_at(&root, "kernel").unwrap();
            let error = unmount_jail(&paths, records).expect_err(label);
            assert!(still_mounted(), "{label}: the replacement was unmounted");
            assert_ne!(now.unique_id, original.unique_id, "{label}");
            eprintln!(
                "B4 evidence: bind replaced by {label} (inode {} vs {}): refused: {error}",
                now.st_ino, original.st_ino
            );
        }
        drop(root);
        raw_umount(&kernel);
        raw_umount(&paths.jail_dir);
        remove_jail_dirs(&paths).unwrap();
        std::fs::remove_file(first).unwrap();
        std::fs::remove_file(other).unwrap();
    }

    /// A scratch backing file and the product's attached, persisted loop on it.
    #[cfg(target_os = "linux")]
    fn scratch_loop(label: &str, bytes: u64) -> (PathBuf, File, LoopBinding, LoopGeneration) {
        use std::os::unix::fs::MetadataExt;
        let backing = std::env::temp_dir().join(format!("b4-{label}-{}.img", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&backing)
            .unwrap();
        file.set_len(bytes).unwrap();
        let meta = file.metadata().unwrap();
        let binding = LoopBinding {
            major: LOOP_MAJOR,
            minor: free_loop_slot().unwrap(),
            backing_dev: meta.dev(),
            backing_ino: meta.ino(),
            offset: 0,
            size_limit: bytes,
            block_size: LOOP_BLOCK_SIZE,
        };
        let attached = attach_loop(&binding, &file).unwrap();
        let generation = attached.generation.clone();
        persist_loop(&binding, attached).unwrap();
        (backing, file, binding, generation)
    }

    #[cfg(target_os = "linux")]
    fn loop_bound(minor: u32) -> bool {
        Path::new(&format!("/sys/block/loop{minor}/loop/backing_file")).exists()
    }

    #[cfg(target_os = "linux")]
    fn losetup(args: &[&str]) -> bool {
        std::process::Command::new("/usr/sbin/losetup")
            .args(args)
            .status()
            .unwrap()
            .success()
    }

    #[cfg(target_os = "linux")]
    fn unbind_loop(minor: u32) {
        let _ = losetup(&["-d", &format!("/dev/loop{minor}")]);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while loop_bound(minor) {
            assert!(std::time::Instant::now() < end, "loop{minor} stayed bound");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// The kernel's `struct loop_info64`, for the tests' root actor.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct TestLoopInfo {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        lo_file_name: [u8; 64],
        lo_crypt_name: [u8; 64],
        lo_encrypt_key: [u8; 32],
        lo_init: [u64; 2],
    }

    /// A root actor's `LOOP_SET_STATUS64` on a bound slot: the same attachment, retuned
    /// in place.
    #[cfg(target_os = "linux")]
    fn retune_loop(minor: u32, offset: u64, size_limit: u64) {
        use std::os::fd::AsRawFd;
        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/loop{minor}"))
            .unwrap();
        // SAFETY: zeroed is a valid loop_info64; the ioctls fill and read it.
        let mut info: TestLoopInfo = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::ioctl(device.as_raw_fd(), 0x4C05, &mut info) }, 0);
        info.lo_offset = offset;
        info.lo_sizelimit = size_limit;
        let rc = unsafe { libc::ioctl(device.as_raw_fd(), 0x4C04, &info) };
        assert_eq!(rc, 0, "LOOP_SET_STATUS64: {}", io::Error::last_os_error());
    }

    /// The kernel behaviour B4's fault model rests on (design section 7.1), on this
    /// kernel: a fresh replacement tmpfs gets a new unique mount ID even when the
    /// reusable tuple is handed out again; a detached clone keeps its unique ID when it
    /// is attached; detaching and reattaching the same slot to the same inode with the
    /// same tuple changes the disk sequence number; `LOOP_SET_STATUS64` does not.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_kernel_generation_ids_are_never_reused() {
        prepare_jail_base().unwrap();
        assert!(valid_boot_id(&boot_id().unwrap()));
        // Mounts: attach_jail and attach_bind already require the attached unique ID to
        // equal the detached one.
        let paths = scratch_paths();
        let identity = new_jail_identity().unwrap();
        let (jail, root, recorded) = create_jail(&paths, &identity);
        let scratch = std::env::temp_dir().join(format!("b4-kernel-bind-{}", std::process::id()));
        std::fs::write(&scratch, b"kernel").unwrap();
        let bind = bind_read_only(&root, "kernel", &File::open(&scratch).unwrap());
        assert_ne!(bind.unique_id, recorded.unique_id);
        drop((jail, root));
        unmount_jail(
            &paths,
            JailRecords {
                identity: Some(&identity),
                mount: Some(&recorded),
                binds: Some(&[bind]),
            },
        )
        .unwrap();
        let mut seen = std::collections::BTreeSet::from([recorded.unique_id]);
        let mut reused_tuple = 0;
        for _ in 0..100 {
            raw_mount(&identity.source(), &paths.jail_dir, "tmpfs", JAIL_TMPFS_DATA);
            let fresh = mount_identity(&File::open(&paths.jail_dir).unwrap()).unwrap();
            raw_umount(&paths.jail_dir);
            assert!(seen.insert(fresh.unique_id), "unique mount ID {} reused", fresh.unique_id);
            if (fresh.mount_id, fresh.st_dev, fresh.st_ino)
                == (recorded.mount_id, recorded.st_dev, recorded.st_ino)
            {
                reused_tuple += 1;
            }
        }
        remove_jail_dirs(&paths).unwrap();
        std::fs::remove_file(&scratch).unwrap();
        eprintln!(
            "B4 kernel: 100 replacement tmpfs mounts: reusable tuple reused {reused_tuple} \
             times, unique mount ID reused 0 times"
        );

        // Loops.
        const W: u64 = 16 * 1024 * 1024;
        let (backing, file, binding, first) = scratch_loop("kernel-loop", W);
        assert_eq!(current_generation(binding.minor).unwrap(), first);
        assert_eq!(
            detach_loop(&binding, Some(&first)).unwrap(),
            LoopOutcome::Detached
        );
        let attached = attach_loop(&binding, &file).unwrap();
        let second = attached.generation.clone();
        persist_loop(&binding, attached).unwrap();
        assert_ne!(second.diskseq, first.diskseq, "reattach kept the disk sequence");
        retune_loop(binding.minor, 4096, W - 4096);
        let retuned = current_generation(binding.minor).unwrap();
        assert_eq!(retuned, second, "LOOP_SET_STATUS64 changed the disk sequence");
        unbind_loop(binding.minor);
        drop(file);
        std::fs::remove_file(&backing).unwrap();
        eprintln!(
            "B4 kernel: loop{} diskseq attach {} -> reattach {} -> after LOOP_SET_STATUS64 {}",
            binding.minor, first.diskseq, second.diskseq, retuned.diskseq
        );
    }

    /// B4 break-it finding 2, as a regression: a slot bound to the recorded backing
    /// inode with another offset, size limit or block size is not the journaled
    /// binding, even with the slot's current disk sequence number. Verification and
    /// detach both refuse it, on the same opened slot, and it stays bound; a slot with no
    /// journaled generation is never detached; only the exact generation is.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root, CAP_SYS_ADMIN and losetup: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_detach_refuses_the_same_inode_with_another_loop_tuple() {
        use std::os::unix::fs::MetadataExt;
        const W: u64 = 16 * 1024 * 1024;
        let backing = std::env::temp_dir().join(format!("b4-loop-tuple-{}.img", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&backing)
            .unwrap();
        file.set_len(W).unwrap();
        let meta = file.metadata().unwrap();
        let minor = free_loop_slot().unwrap();
        let device = format!("/dev/loop{minor}");
        let recorded = LoopBinding {
            major: LOOP_MAJOR,
            minor,
            backing_dev: meta.dev(),
            backing_ino: meta.ino(),
            offset: 0,
            size_limit: W,
            block_size: LOOP_BLOCK_SIZE,
        };
        let bind = |args: &[&str]| {
            let mut all: Vec<&str> = args.to_vec();
            all.extend([device.as_str(), backing.to_str().unwrap()]);
            assert!(losetup(&all), "losetup {all:?}");
        };
        for (label, args) in [
            ("offset", vec!["--offset", "4096", "--sizelimit", "16773120"]),
            ("size limit", vec!["--sizelimit", "8388608"]),
            ("offset and size limit", vec!["--offset", "4096", "--sizelimit", "8388608"]),
            ("block size", vec!["--sizelimit", "16777216", "--sector-size", "4096"]),
        ] {
            bind(&args);
            let generation = current_generation(minor).unwrap();
            assert!(verify_loop(&recorded).is_err(), "{label}: verified");
            let outcome = detach_loop(&recorded, Some(&generation)).unwrap();
            let still = loop_bound(minor);
            unbind_loop(minor);
            assert_eq!(outcome, LoopOutcome::Unknown, "{label}");
            assert!(still, "{label}: the other binding was detached");
            eprintln!("B4 evidence: same inode, different {label}: Unknown, left bound");
        }
        bind(&["--sizelimit", "16777216"]);
        verify_loop(&recorded).unwrap();
        // The exact tuple with no journaled generation: never detached.
        assert_eq!(detach_loop(&recorded, None).unwrap(), LoopOutcome::Unknown);
        assert!(loop_bound(minor), "an unjournaled binding was detached");
        let generation = current_generation(minor).unwrap();
        assert_eq!(
            detach_loop(&recorded, Some(&generation)).unwrap(),
            LoopOutcome::Detached
        );
        assert!(!loop_bound(minor), "the exact generation was detached");
        drop(file);
        std::fs::remove_file(&backing).unwrap();
    }

    /// B4 recheck finding 2 (was `poc_b4_recheck_loop_mutation_between_compare_and_clear`),
    /// the in-scope half: root detaches the journaled attachment and rebinds the same
    /// slot to the same inode with the same tuple before cleanup. Only the disk sequence
    /// number differs; cleanup returns Unknown and the rebinding stays bound. Inside
    /// cleanup's compare-to-clear window the same replacement cannot happen at all:
    /// while cleanup's descriptor is open, another opener's LOOP_CLR_FD only marks the
    /// attachment autoclear and its rebinding LOOP_CONFIGURE fails EBUSY, so the
    /// generation cleanup clears is still the journaled one.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_detach_refuses_a_rebound_generation() {
        use std::os::fd::AsRawFd;
        use std::sync::atomic::Ordering;
        const W: u64 = 16 * 1024 * 1024;
        let (backing, file, binding, journaled) = scratch_loop("loop-rebind", W);
        // Before cleanup: the same slot, inode and tuple, a new generation.
        unbind_loop(binding.minor);
        let attached = attach_loop(&binding, &file).unwrap();
        let rebound = attached.generation.clone();
        persist_loop(&binding, attached).unwrap();
        verify_loop(&binding).unwrap();
        assert_ne!(rebound.diskseq, journaled.diskseq);
        assert_eq!(
            detach_loop(&binding, Some(&journaled)).unwrap(),
            LoopOutcome::Unknown
        );
        assert!(loop_bound(binding.minor), "the rebinding was detached");
        assert_eq!(current_generation(binding.minor).unwrap(), rebound);
        eprintln!(
            "B4 evidence: loop{} rebound with the same tuple: diskseq {} != journaled {}; \
             Unknown, left bound",
            binding.minor, rebound.diskseq, journaled.diskseq
        );

        // Inside the window: cleanup holds the slot between its tuple comparison and the
        // final generation check while a root actor tries to detach and rebind it.
        TEST_DETACH_GATE.store(1, Ordering::SeqCst);
        let worker = {
            let rebound = rebound.clone();
            std::thread::spawn(move || detach_loop(&binding, Some(&rebound)))
        };
        while TEST_DETACH_GATE.load(Ordering::SeqCst) != 2 {
            std::thread::yield_now();
        }
        let actor = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/loop{}", binding.minor))
            .unwrap();
        // SAFETY: LOOP_CLR_FD takes no argument.
        let cleared = unsafe { libc::ioctl(actor.as_raw_fd(), 0x4C01, 0) };
        drop(actor);
        let still = current_generation(binding.minor).unwrap();
        let reattach = attach_loop(&binding, &file).map(|_| ());
        TEST_DETACH_GATE.store(3, Ordering::SeqCst);
        let outcome = worker.join().unwrap().unwrap();
        TEST_DETACH_GATE.store(0, Ordering::SeqCst);
        let left = loop_bound(binding.minor);
        if left {
            unbind_loop(binding.minor);
        }
        drop(file);
        std::fs::remove_file(&backing).unwrap();
        assert_eq!(cleared, 0, "LOOP_CLR_FD");
        assert_eq!(still, rebound, "the generation changed inside the window");
        let error = reattach.expect_err("rebound while cleanup held the slot");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert_eq!(outcome, LoopOutcome::Detached);
        assert!(!left, "the journaled generation was not detached");
        eprintln!(
            "B4 evidence: inside the window LOOP_CLR_FD only marked autoclear and the \
             rebinding failed ({error}); cleanup detached the journaled generation {}",
            rebound.diskseq
        );
    }

    /// B4 recheck finding 2, the out-of-scope half, recorded: host root retuning our own
    /// attachment in place with `LOOP_SET_STATUS64` inside cleanup's compare-to-clear
    /// window keeps its disk sequence number and backing inode, so it is still our
    /// generation and cleanup detaches it. The kernel has no compare-and-clear and host
    /// root is trusted (design section 7.1).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_detach_of_a_retuned_own_generation_is_out_of_scope() {
        use std::sync::atomic::Ordering;
        const W: u64 = 16 * 1024 * 1024;
        let (backing, file, binding, journaled) = scratch_loop("loop-retune", W);
        TEST_DETACH_GATE.store(1, Ordering::SeqCst);
        let worker = {
            let journaled = journaled.clone();
            std::thread::spawn(move || detach_loop(&binding, Some(&journaled)))
        };
        while TEST_DETACH_GATE.load(Ordering::SeqCst) != 2 {
            std::thread::yield_now();
        }
        retune_loop(binding.minor, 4096, W - 4096);
        let retuned = current_generation(binding.minor).unwrap();
        TEST_DETACH_GATE.store(3, Ordering::SeqCst);
        let outcome = worker.join().unwrap().unwrap();
        TEST_DETACH_GATE.store(0, Ordering::SeqCst);
        let left = loop_bound(binding.minor);
        if left {
            unbind_loop(binding.minor);
        }
        drop(file);
        std::fs::remove_file(&backing).unwrap();
        assert_eq!(retuned, journaled, "LOOP_SET_STATUS64 changed the generation");
        assert_eq!(outcome, LoopOutcome::Detached);
        assert!(!left);
        eprintln!(
            "B4 evidence (out of scope): our attachment retuned in place kept diskseq {}; \
             cleanup detached it",
            journaled.diskseq
        );
    }

    /// A crash between LOOP_CONFIGURE and the journal: the attachment is autoclear, so
    /// it goes with the configuring descriptor, and cleanup with only the intent finds
    /// the slot free without detaching anything.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and CAP_SYS_ADMIN: run scripts/b4-vm-tests.sh"]
    fn b4_linux_root_an_unjournaled_attachment_clears_itself() {
        use std::os::unix::fs::MetadataExt;
        const W: u64 = 16 * 1024 * 1024;
        let backing = std::env::temp_dir().join(format!("b4-loop-auto-{}.img", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&backing)
            .unwrap();
        file.set_len(W).unwrap();
        let meta = file.metadata().unwrap();
        let binding = LoopBinding {
            major: LOOP_MAJOR,
            minor: free_loop_slot().unwrap(),
            backing_dev: meta.dev(),
            backing_ino: meta.ino(),
            offset: 0,
            size_limit: W,
            block_size: LOOP_BLOCK_SIZE,
        };
        let attached = attach_loop(&binding, &file).unwrap();
        assert!(loop_bound(binding.minor));
        drop(attached);
        let outcome = detach_loop(&binding, None).unwrap();
        let left = loop_bound(binding.minor);
        if left {
            unbind_loop(binding.minor);
        }
        drop(file);
        std::fs::remove_file(&backing).unwrap();
        assert_eq!(outcome, LoopOutcome::Free);
        assert!(!left);
    }

    #[test]
    fn mountinfo_parsing_is_strict_and_unescapes() {
        let text = "36 25 0:32 / /var/lib/kilnd-helper/jails/firecracker/fc-0/root rw,nosuid shared:1 - tmpfs kilnd-jail rw,size=16384k\n\
                    37 36 8:1 /x /var/lib/kilnd-helper/jails/firecracker/fc-0/root/kernel ro,nosuid,nodev - ext4 /dev/sda1 rw\n\
                    38 25 0:33 / /mnt/a\\040b rw - tmpfs none rw\n";
        let entries = parse_mountinfo(text).unwrap();
        assert_eq!(entries[0].source, "kilnd-jail");
        assert_eq!((entries[1].mount_id, entries[1].parent_id), (37, 36));
        assert!(entries[1].read_only && !entries[0].read_only);
        assert_eq!(entries[2].mount_point, PathBuf::from("/mnt/a b"));
        let under = mounts_under(
            &entries,
            Path::new("/var/lib/kilnd-helper/jails/firecracker/fc-0"),
        );
        assert_eq!(under.len(), 2);
        assert!(under[0].mount_point.ends_with("kernel"), "deepest first");
        assert!(parse_mountinfo("1 2 3\n").is_err());
    }

    fn status(caps: &str, groups: &str) -> String {
        format!(
            "Name:\tfirecracker\nUid:\t300123\t300123\t300123\t300123\nGid:\t300456\t300456\t300456\t300456\nGroups:\t{groups}\n\
             CapInh:\t{caps}\nCapPrm:\t{caps}\nCapEff:\t{caps}\nCapBnd:\t{caps}\nCapAmb:\t{caps}\nNoNewPrivs:\t1\nSeccomp:\t2\n"
        )
    }

    fn recipe() -> serde_json::Value {
        json!({"uid": 300123, "gid": 300456, "groups": [], "CapInh": 0, "CapPrm": 0,
               "CapEff": 0, "CapBnd": 0, "CapAmb": 0, "NoNewPrivs": 1, "status_seccomp": 2})
    }

    #[test]
    fn vmm_credentials_must_match_every_mask() {
        let good = parse_status(&status("0000000000000000", "")).unwrap();
        check_vmm_credentials(&good, &recipe()).unwrap();
        // One bounding bit left set refuses the launch.
        let bounding = status("0000000000000000", "")
            .replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000400");
        let error =
            check_vmm_credentials(&parse_status(&bounding).unwrap(), &recipe()).unwrap_err();
        assert!(error.contains("CapBnd"), "{error}");
        let groups = parse_status(&status("0000000000000000", "27")).unwrap();
        assert!(check_vmm_credentials(&groups, &recipe()).is_err());
        let swapped = status("0000000000000000", "").replace(
            "Uid:\t300123\t300123\t300123\t300123",
            "Uid:\t300456\t300456\t300456\t300456",
        );
        assert!(check_vmm_credentials(&parse_status(&swapped).unwrap(), &recipe()).is_err());
        assert!(
            parse_status(&format!(
                "{}Uid:\t1\t1\t1\t1\n",
                status("0000000000000000", "")
            ))
            .is_err()
        );
        assert!(parse_status("Uid:\t1\n").is_err());
    }

    #[test]
    fn identity_block_is_framed_canonical_and_padded() {
        let plan = json!({
            "manifest_sha256": "a".repeat(64),
            "launch": {"jail_root": "/x"},
            "substitutions": {
                "instance_id": "0".repeat(32), "allocation_id": "1".repeat(32),
                "sandbox_id": "sb-0123456789abcdef", "boot_nonce": "2".repeat(64),
                "work_uuid": "00000000-0000-4000-8000-000000000000",
                "inner_spec": {"image": "alpine"}
            }
        });
        let block = identity_block(&plan).unwrap();
        assert_eq!(block.len(), IDENTITY_BYTES);
        assert_eq!(&block[..4], b"KID1");
        let length = u32::from_be_bytes(block[4..8].try_into().unwrap()) as usize;
        let record: serde_json::Value = serde_json::from_slice(&block[8..8 + length]).unwrap();
        assert!(block[8 + length..].iter().all(|b| *b == 0));
        assert_eq!(record.as_object().unwrap().len(), 8);
        assert_eq!(
            record["launch_sha256"],
            crate::firecracker::sha256(&crate::firecracker::canonical(&plan["launch"]).unwrap())
        );
    }

    #[test]
    fn plan_paths_must_have_the_contract_shapes() {
        let h = "0123456789abcdef0123456789abcdef";
        let good = json!({
            "jail_root": format!("/var/lib/kilnd-helper/jails/firecracker/fc-{h}/root"),
            "work_backing_path": format!("/var/lib/kilnd-helper/work/{h}/fc-{h}/work.xfs"),
        });
        AllocationPaths::from_launch(&good).unwrap();
        for (key, value) in [
            ("jail_root", "/tmp/fc-x/root".to_string()),
            (
                "jail_root",
                format!("/var/lib/kilnd-helper/jails/firecracker/fc-{h}/../root"),
            ),
            (
                "work_backing_path",
                format!("/var/lib/kilnd-helper/work/{h}/fc-{h}/other"),
            ),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(AllocationPaths::from_launch(&bad).is_err(), "{value}");
        }
    }
}
