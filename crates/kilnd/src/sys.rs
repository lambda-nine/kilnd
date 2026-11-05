//! Typed system-call and ioctl wrappers (design section 7.1, B4 recheck 4 and 5).
//!
//! `libc::syscall` and `libc::ioctl` take any request, so clippy's
//! `disallowed-methods` (see `clippy.toml`) rejects them everywhere except here and
//! `helper::firecracker::proven`. Each function below issues exactly one fixed request,
//! and none of them signals, unmounts, renames or detaches anything:
//!
//! - descriptors and processes: `close_range` of this process's own descriptors,
//!   `pidfd_open`, a pidfd liveness probe whose signal is the constant 0, `capget` and
//!   `capset` on the calling thread, the calling process's dumpable flag (`prctl`), and
//!   `execveat` of a retained descriptor (the only way the helper starts the jailer,
//!   Firecracker or mkfs.xfs);
//! - fd-native reads: [`read_dir_fd`] lists a held directory descriptor with
//!   `getdents64` on a duplicate (never a `/proc/self/fd` pathname), and [`procfs`]
//!   reads process and kernel state beneath a private, never-attached procfs instance
//!   that no mount in any namespace can shadow;
//! - the new mount API, creation only: [`DetachedMount`] can be built only by
//!   [`fsmount`] or [`open_tree_clone`], and `move_mount` and `mount_setattr` take one,
//!   so they can only act on a mount this process created;
//! - the [`ioctl`] module: read requests, `LOOP_CONFIGURE` on a free slot (the kernel
//!   refuses a bound one), and clearing `LO_FLAGS_AUTOCLEAR` on a [`ioctl::ConfiguredLoop`]
//!   only, a slot this process configured itself, after re-reading its status and
//!   generation on that descriptor. `LoopInfo64` is opaque: no caller can build or
//!   change one. `LOOP_CLR_FD` is not here: it exists only in `proven::clear_loop`,
//!   which takes a `ProvenLoop`;
//! - fixed storage writes: [`preallocate`] (mode-0 `fallocate`, never a punch-hole) and
//!   [`write_sysfs`], which writes only the [`SysfsControl`] enum's files;
//! - [`socket`]: the one unlink here, of kilnd's own API socket, only while its
//!   device, inode and birth time, read through the socket directory's descriptor
//!   immediately before, are the generation it was bound or found as.
//!
//! Signals, `cgroup.kill`, every other unlink, `rmdir`, unmounts and `LOOP_CLR_FD` live
//! only in `helper::firecracker::proven`, behind its proof types.
// Approved (design 7.1): the typed wrapper module for libc::syscall and libc::ioctl.
// Every request is a fixed one; see the module documentation.
#![allow(clippy::disallowed_methods)]

#[cfg(target_os = "linux")]
pub use linux::*;

/// Whether a process exists, by signal 0, which checks and delivers nothing. macOS
/// only, where a zombie has no BSD info; Linux reads `/proc` instead.
#[cfg(target_os = "macos")]
pub fn process_exists(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// A process-wide descriptor cache keyed by an identity (B7, B4 recheck 6 item 3): the
/// private procfs root and its unique mount ID. One mutex orders the check and the
/// creation, so concurrent first callers make exactly one root and none leaks; a cached
/// descriptor whose identity no longer matches (a forked worker closed it, or its number
/// was reused) is replaced, never closed, since the number may now be another file.
///
/// The mutex is held only across the identity read and, once, the creation. A worker
/// forks only from a single-threaded process (`workers::spawn_process`), so no fork
/// inherits it locked; a multithreaded fork would already risk the allocator's own locks.
#[cfg(any(target_os = "linux", test))]
pub(crate) struct RootCache(std::sync::Mutex<Option<(std::os::fd::RawFd, u64)>>);

#[cfg(any(target_os = "linux", test))]
impl RootCache {
    pub(crate) const fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }

    /// The cached descriptor and identity if `identity` still reads that identity from
    /// it; otherwise one `make`, recorded and kept open for the process's life.
    pub(crate) fn get(
        &self,
        identity: impl Fn(std::os::fd::RawFd) -> std::io::Result<u64>,
        make: impl FnOnce() -> std::io::Result<std::fs::File>,
    ) -> std::io::Result<(std::os::fd::RawFd, u64)> {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let mut cached = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((fd, id)) = *cached
            && identity(fd).ok() == Some(id)
        {
            return Ok((fd, id));
        }
        let file = make()?;
        let id = identity(file.as_raw_fd())?;
        let fd = file.into_raw_fd();
        *cached = Some((fd, id));
        Ok((fd, id))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CStr;
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    fn sys_ret(rc: libc::c_long) -> io::Result<libc::c_long> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    /// Closes this process's descriptors `first..=last`. Async-signal-safe.
    pub fn close_range(first: libc::c_uint, last: libc::c_uint) -> io::Result<()> {
        // SAFETY: closing a descriptor range this process owns.
        sys_ret(unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) }).map(drop)
    }

    // Phase 1b B5 moved the thread capability calls to the direct-kiln core crate.
    pub use kilnd_exec_core::sys::{CapData, CapHeader, capget, capset};

    /// A pidfd for `pid`, which pins that process object from now on.
    pub fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes a PID and flags and returns a new descriptor.
        let fd = sys_ret(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) })?;
        // SAFETY: the kernel returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    /// Whether the pidfd's process still exists: `pidfd_send_signal` with the constant
    /// signal 0, which checks and delivers nothing.
    pub fn pidfd_alive(pidfd: RawFd) -> bool {
        // SAFETY: signal 0 only checks existence, and the null info pointer is allowed.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) == 0
        }
    }

    /// `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`: runs the image the descriptor
    /// names, never a pathname. Returns only on failure, with its error.
    ///
    /// # Safety
    /// `argv` and `envp` are NULL-terminated arrays of NUL-terminated strings that
    /// outlive the call.
    pub unsafe fn execveat_empty(
        fd: RawFd,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> io::Error {
        // SAFETY: the caller's contract; the empty path with AT_EMPTY_PATH selects the
        // descriptor itself.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                c"".as_ptr(),
                argv,
                envp,
                libc::AT_EMPTY_PATH,
            );
        }
        io::Error::last_os_error()
    }

    /// Fixed `prctl` requests on the calling thread or process. Each returns the raw
    /// `prctl` result; all are async-signal-safe and allocation-free, for use between
    /// fork and exec. Phase 1b B5 moved the capability, no-new-privs and parent-death
    /// requests to the direct-kiln core crate with the child setup that issues them.
    pub mod prctl {
        pub use kilnd_exec_core::sys::prctl::{
            cap_ambient_is_set, cap_ambient_lower, capbset_drop, capbset_read, get_no_new_privs,
            set_no_new_privs, set_parent_death_kill,
        };

        /// `PR_SET_CHILD_SUBREAPER` to 1 on the calling process.
        pub fn set_child_subreaper() -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }
        }
    }

    /// `ptrace(PTRACE_TRACEME)` in a freshly forked child, so its exec stops for the
    /// parent's image observation (a test-only path of the formatter launch).
    /// Async-signal-safe.
    pub fn ptrace_traceme() -> libc::c_long {
        // SAFETY: PTRACE_TRACEME takes no other arguments.
        unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) }
    }

    /// The calling process's dumpable flag (`PR_GET_DUMPABLE`).
    pub fn dumpable() -> io::Result<libc::c_int> {
        // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
        let rc = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(rc)
    }

    /// Restores the calling process's dumpable flag (`PR_SET_DUMPABLE`), which a
    /// filesystem-ID change resets. Only 0 and 1 are accepted.
    pub fn set_dumpable(value: libc::c_int) -> io::Result<()> {
        if !matches!(value, 0 | 1) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // SAFETY: PR_SET_DUMPABLE takes one integer argument.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, value, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// One entry of a directory descriptor: its name and `d_type` (`DT_UNKNOWN` when
    /// the filesystem does not say).
    pub struct DirEntry {
        pub name: Vec<u8>,
        pub kind: u8,
    }

    /// Every entry of the directory `dir` holds, except `.` and `..`: `getdents64` on a
    /// fresh open file description of that same directory, `openat(dir, ".",
    /// O_RDONLY|O_DIRECTORY|O_CLOEXEC)`, so the listing is of exactly that inode, never
    /// of a `/proc/self/fd/N` pathname a mount could shadow. `.` resolves to the held
    /// descriptor's own mount and dentry, crossing nothing. The description is
    /// independent: unlike an `F_DUPFD` duplicate, reading it from the start leaves the
    /// caller's directory offset where it was (B7, B4 recheck 6 item 4). More than
    /// `limit` entries is an error.
    pub fn read_dir_fd(dir: &File, limit: usize) -> io::Result<Vec<DirEntry>> {
        // SAFETY: a live directory descriptor and a NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor nothing else owns.
        let dup = unsafe { OwnedFd::from_raw_fd(fd) };
        // u64 storage keeps the records 8-byte aligned, as the kernel writes them.
        let mut buffer = vec![0u64; 4096];
        let bytes = buffer.len() * 8;
        let mut entries = Vec::new();
        loop {
            // SAFETY: the buffer is writable for `bytes`; the descriptor is live.
            let n = sys_ret(unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dup.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<u8>(),
                    bytes,
                )
            })? as usize;
            if n == 0 {
                return Ok(entries);
            }
            // SAFETY: the kernel wrote `n <= bytes` bytes of the u64 buffer.
            let raw = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n) };
            let mut at = 0;
            while at < n {
                // struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type;
                // char d_name[]; }
                if at + 19 > n {
                    return Err(io::Error::other("truncated directory record"));
                }
                let reclen = u16::from_ne_bytes([raw[at + 16], raw[at + 17]]) as usize;
                if reclen < 20 || at + reclen > n {
                    return Err(io::Error::other("malformed directory record"));
                }
                let kind = raw[at + 18];
                let name = &raw[at + 19..at + reclen];
                let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())];
                if name != b"." && name != b".." {
                    entries.push(DirEntry {
                        name: name.to_vec(),
                        kind,
                    });
                    if entries.len() > limit {
                        return Err(io::Error::other("directory exceeds its entry bound"));
                    }
                }
                at += reclen;
            }
        }
    }

    /// The `readlinkat` text of one entry below a directory descriptor (a `/proc`
    /// descriptor link, say), never followed.
    pub fn read_link_at(dir: &File, name: &CStr) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 4096];
        // SAFETY: the buffer is writable for its length; the name is NUL-terminated.
        let n = unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(n as usize);
        Ok(buffer)
    }

    /// Process and kernel state read beneath a private procfs instance (B4 recheck 5).
    ///
    /// The helper's own `/proc` pathnames are in its mount namespace, where root can
    /// mount over them; a proof must not read such a view. The helper therefore makes
    /// its own procfs superblock (`fsopen("proc")`, `fsmount`) and never attaches it:
    /// no other process can reach a mount there, so nothing can shadow a path below
    /// it. Every lookup is `openat2` beneath that root with `RESOLVE_BENEATH`,
    /// `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_XDEV`, except
    /// [`open_image`]'s one magic link. Without `CAP_SYS_ADMIN` (an unprivileged
    /// process: a test, or the daemon reading its own cgroup, never the root helper) it
    /// falls back to `/proc`; as root, failure to make the instance is an error. Where
    /// `openat2` itself is refused with `ENOSYS` (systemd's `RestrictSUIDSGID=`, which
    /// `kilnd@.service` sets, cannot filter its mode argument), an unprivileged process
    /// walks one component at a time instead, each `O_NOFOLLOW` and proved on procfs.
    ///
    /// The descriptor is cached with the instance's unique mount ID (never reused
    /// within a boot) and re-verified on every use, so a forked worker that closed
    /// every descriptor, or a reused descriptor number, makes a fresh instance rather
    /// than reading another file.
    pub mod procfs {
        use super::{DetachedMount, fsconfig_create, fsmount, fsopen, sys_ret};
        use std::fs::File;
        use std::io::{self, Read};
        use std::os::fd::{AsRawFd, FromRawFd, RawFd};

        const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
        const RESOLVE_NO_XDEV: u64 = 0x01;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_BENEATH: u64 = 0x08;
        const PROC_SUPER_MAGIC: libc::__fsword_t = 0x9fa0;

        /// The private root and its unique mount ID (B7, B4 recheck 6 item 3).
        static ROOT: super::super::RootCache = super::super::RootCache::new();

        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }

        fn unique_mount_id(fd: RawFd) -> io::Result<u64> {
            // SAFETY: statx writes into the zeroed buffer; the empty name is
            // NUL-terminated.
            let mut stx: libc::statx = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::statx(
                    fd,
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH,
                    STATX_MNT_ID_UNIQUE,
                    &mut stx,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if stx.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
                return Err(io::Error::other(
                    "kernel reports no unique mount ID (STATX_MNT_ID_UNIQUE needs Linux 6.8)",
                ));
            }
            Ok(stx.stx_mnt_id)
        }

        fn new_root() -> io::Result<File> {
            let made = (|| -> io::Result<DetachedMount> {
                let context = fsopen(c"proc")?;
                fsconfig_create(&context)?;
                fsmount(&context, 0)
            })();
            match made {
                Ok(mount) => Ok(mount.into_file()),
                // SAFETY: geteuid has no preconditions.
                Err(error)
                    if error.raw_os_error() == Some(libc::EPERM)
                        && unsafe { libc::geteuid() } != 0 =>
                {
                    let fd = unsafe {
                        libc::open(
                            c"/proc".as_ptr(),
                            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // SAFETY: open returned a new owned descriptor.
                    Ok(unsafe { File::from_raw_fd(fd) })
                }
                Err(error) => Err(io::Error::new(
                    error.kind(),
                    format!("private procfs instance: {error}"),
                )),
            }
        }

        /// The cached root and its unique mount ID, re-verified on every use; a fresh
        /// one otherwise. Concurrent first callers make exactly one (`RootCache`).
        pub(in crate::sys) fn root() -> io::Result<(RawFd, u64)> {
            ROOT.get(unique_mount_id, new_root)
        }

        fn check(relative: &str) -> io::Result<()> {
            let valid = !relative.is_empty()
                && relative.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
                });
            if valid {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("not a procfs-relative path: {relative:?}"),
                ))
            }
        }

        /// Opens `relative` (for example `"123/stat"`) beneath the private instance,
        /// following no link of any kind and crossing no mount.
        pub fn open(relative: &str, flags: libc::c_int) -> io::Result<File> {
            check(relative)?;
            let path = std::ffi::CString::new(relative)?;
            let (root, root_id) = root()?;
            let how = OpenHow {
                flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH
                    | RESOLVE_NO_SYMLINKS
                    | RESOLVE_NO_MAGICLINKS
                    | RESOLVE_NO_XDEV,
            };
            // SAFETY: a live root descriptor, a NUL-terminated path and a complete
            // version-0 open_how.
            let opened = sys_ret(unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    root,
                    path.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                )
            });
            match opened {
                // SAFETY: a new owned descriptor.
                Ok(fd) => Ok(unsafe { File::from_raw_fd(fd as RawFd) }),
                // SAFETY: geteuid has no preconditions.
                Err(error)
                    if error.raw_os_error() == Some(libc::ENOSYS)
                        && unsafe { libc::geteuid() } != 0 =>
                {
                    open_by_components(root, root_id, relative, flags)
                }
                Err(error) => Err(error),
            }
        }

        /// `openat2`'s resolution by hand, for an unprivileged process whose seccomp
        /// filter refuses `openat2`: `check` already allowed only plain names, each is
        /// opened `O_NOFOLLOW` beneath the previous one (no link of any kind is followed),
        /// and each must still be procfs on the root's own mount: `RESOLVE_NO_XDEV`'s
        /// substitute. The superblock check alone cannot see a bind mount of another
        /// `/proc` path on the same procfs (B6-RC-01); the unique mount ID can, since a
        /// bind mount is a new mount with a new ID. That attack needs root control of
        /// the daemon's own mount namespace, which is in its TCB; the check is the cheap
        /// defense in depth B7 adds.
        pub(in crate::sys) fn open_by_components(
            root: RawFd,
            root_id: u64,
            relative: &str,
            flags: libc::c_int,
        ) -> io::Result<File> {
            let parts: Vec<&str> = relative.split('/').collect();
            let mut at: Option<File> = None;
            for (index, part) in parts.iter().enumerate() {
                let name = std::ffi::CString::new(*part)?;
                let last = index + 1 == parts.len();
                let step = if last {
                    flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
                } else {
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
                };
                let dir = at.as_ref().map_or(root, |file| file.as_raw_fd());
                // SAFETY: a live directory descriptor and a NUL-terminated single name.
                let fd = unsafe { libc::openat(dir, name.as_ptr(), step) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: openat returned a new owned descriptor.
                let file = unsafe { File::from_raw_fd(fd) };
                // SAFETY: fstatfs writes into the zeroed buffer.
                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                if stat.f_type != PROC_SUPER_MAGIC {
                    return Err(io::Error::other(format!(
                        "{relative:?} leaves procfs at {part:?}"
                    )));
                }
                if unique_mount_id(file.as_raw_fd())? != root_id {
                    return Err(io::Error::other(format!(
                        "{relative:?} crosses a mount at {part:?}"
                    )));
                }
                if last {
                    return Ok(file);
                }
                at = Some(file);
            }
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        }

        /// A directory beneath the private instance, as [`open`].
        pub fn open_dir(relative: &str) -> io::Result<File> {
            open(relative, libc::O_RDONLY | libc::O_DIRECTORY)
        }

        /// A whole file beneath the private instance, as [`open`].
        pub fn read_to_string(relative: &str) -> io::Result<String> {
            let mut text = String::new();
            open(relative, libc::O_RDONLY)?.read_to_string(&mut text)?;
            Ok(text)
        }

        /// The private instance's own top-level entries (every process directory among
        /// them), listed through a read descriptor of its root itself, as
        /// [`super::read_dir_fd`]. More than `limit` entries is an error.
        pub fn read_root_dir(limit: usize) -> io::Result<Vec<super::DirEntry>> {
            let (root, _) = root()?;
            // SAFETY: a live root descriptor; "." is that directory itself, so no link
            // is followed and no mount is crossed.
            let fd = unsafe {
                libc::openat(
                    root,
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: openat returned a new owned descriptor.
            let dir = unsafe { File::from_raw_fd(fd) };
            super::read_dir_fd(&dir, limit)
        }

        /// `relative` below this process's own directory (`<pid>/relative`), since
        /// `self` is a link and links are not followed.
        pub fn own(relative: &str) -> String {
            // SAFETY: getpid has no preconditions.
            format!("{}/{relative}", unsafe { libc::getpid() })
        }

        /// This boot's ID text, `sys/kernel/random/boot_id`.
        pub fn boot_id() -> io::Result<String> {
            read_to_string("sys/kernel/random/boot_id")
        }

        /// A process's running image through its `exe` magic link, the one magic link
        /// followed here: `<pid>` is a directory of the private instance, so only the
        /// final link is resolved, and the descriptor is the image itself.
        pub fn open_image(pid: i32) -> io::Result<File> {
            if pid <= 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let path = std::ffi::CString::new(format!("{pid}/exe"))?;
            let (root, _) = root()?;
            // SAFETY: a live root descriptor and a NUL-terminated relative path.
            let fd = unsafe { libc::openat(root, path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a new owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    /// Full preallocation of a work file: mode-0 `fallocate` (allocate and extend; never
    /// `FALLOC_FL_PUNCH_HOLE` or any other mode), then `fsync`.
    pub fn preallocate(file: &File, bytes: u64) -> io::Result<()> {
        let length = libc::off_t::try_from(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: a live descriptor; mode 0 allocates and extends.
        if unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, length) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()
    }

    /// The only sysfs files the helper writes.
    #[derive(Clone, Copy, Debug)]
    pub enum SysfsControl {
        /// `/sys/block/loop<minor>/queue/discard_max_bytes`, written `0` only.
        LoopDiscardOff { minor: u32 },
    }

    /// Writes one fixed value to one [`SysfsControl`] file, opened without following a
    /// link, never created or truncated.
    pub fn write_sysfs(control: SysfsControl) -> io::Result<()> {
        use std::io::Write;
        let (path, value) = match control {
            SysfsControl::LoopDiscardOff { minor } => (
                format!("/sys/block/loop{minor}/queue/discard_max_bytes"),
                b"0" as &[u8],
            ),
        };
        let path = std::ffi::CString::new(path)?;
        // SAFETY: a NUL-terminated path; no O_CREAT or O_TRUNC.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a new owned descriptor.
        unsafe { File::from_raw_fd(fd) }.write_all(value)
    }

    // The new mount API, creation only.

    /// A filesystem context from `fsopen`.
    pub struct FsContext(File);

    /// A mount this process created that has not been attached anywhere, or that this
    /// process attached itself. Only [`fsmount`] and [`open_tree_clone`] make one, so
    /// `move_mount` and `mount_setattr` here never act on another mount.
    pub struct DetachedMount(File);

    impl DetachedMount {
        /// The mount's root, for relative creation and identity reads.
        pub fn file(&self) -> &File {
            &self.0
        }

        fn into_file(self) -> File {
            self.0
        }
    }

    /// `fsopen(fstype, FSOPEN_CLOEXEC)`.
    pub fn fsopen(fstype: &CStr) -> io::Result<FsContext> {
        const FSOPEN_CLOEXEC: libc::c_uint = 1;
        // SAFETY: a NUL-terminated name and constant flags.
        let fd =
            sys_ret(unsafe { libc::syscall(libc::SYS_fsopen, fstype.as_ptr(), FSOPEN_CLOEXEC) })?;
        // SAFETY: a new owned descriptor.
        Ok(FsContext(unsafe { File::from_raw_fd(fd as RawFd) }))
    }

    /// `fsconfig(FSCONFIG_SET_STRING, key, value)` on a new context.
    pub fn fsconfig_set_string(context: &FsContext, key: &CStr, value: &CStr) -> io::Result<()> {
        const FSCONFIG_SET_STRING: libc::c_uint = 1;
        // SAFETY: both strings are NUL-terminated; the context descriptor is live.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.0.as_raw_fd(),
                FSCONFIG_SET_STRING,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        })
        .map(drop)
    }

    /// `fsconfig(FSCONFIG_CMD_CREATE)`: creates the configured superblock.
    pub fn fsconfig_create(context: &FsContext) -> io::Result<()> {
        const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
        // SAFETY: a live context descriptor, with no key or value.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.0.as_raw_fd(),
                FSCONFIG_CMD_CREATE,
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<libc::c_void>(),
                0,
            )
        })
        .map(drop)
    }

    /// `fsmount(context, FSMOUNT_CLOEXEC, attributes)`: a new detached mount.
    pub fn fsmount(context: &FsContext, attributes: libc::c_uint) -> io::Result<DetachedMount> {
        const FSMOUNT_CLOEXEC: libc::c_uint = 1;
        // SAFETY: a live context descriptor and constant flags.
        let fd = sys_ret(unsafe {
            libc::syscall(
                libc::SYS_fsmount,
                context.0.as_raw_fd(),
                FSMOUNT_CLOEXEC,
                attributes,
            )
        })?;
        // SAFETY: a new owned descriptor on the detached mount's root.
        Ok(DetachedMount(unsafe { File::from_raw_fd(fd as RawFd) }))
    }

    /// `open_tree(source, "", AT_EMPTY_PATH | OPEN_TREE_CLONE)`: a detached clone of
    /// the descriptor itself, never a pathname lookup of the original.
    pub fn open_tree_clone(source: &File) -> io::Result<DetachedMount> {
        const OPEN_TREE_CLONE: libc::c_uint = 1;
        // SAFETY: a live descriptor and an empty NUL-terminated path.
        let fd = sys_ret(unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                source.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint
                    | OPEN_TREE_CLONE
                    | libc::O_CLOEXEC as libc::c_uint,
            )
        })?;
        // SAFETY: a new owned descriptor on the detached clone.
        Ok(DetachedMount(unsafe { File::from_raw_fd(fd as RawFd) }))
    }

    /// A version-0 `struct mount_attr`.
    #[repr(C)]
    pub struct MountAttr {
        pub attr_set: u64,
        pub attr_clr: u64,
        pub propagation: u64,
        pub userns_fd: u64,
    }

    /// `mount_setattr` of exactly this process's mount, through its descriptor.
    pub fn mount_setattr(mount: &DetachedMount, attr: &MountAttr) -> io::Result<()> {
        // SAFETY: attr is a complete version-0 mount_attr; the path is empty.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                mount.0.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                attr,
                std::mem::size_of::<MountAttr>(),
            )
        })
        .map(drop)
    }

    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
    const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;

    /// Attaches this process's mount onto a directory descriptor.
    pub fn move_mount_onto(mount: &DetachedMount, target: &File) -> io::Result<()> {
        // SAFETY: both descriptors are live; empty paths name them exactly.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                mount.0.as_raw_fd(),
                c"".as_ptr(),
                target.as_raw_fd(),
                c"".as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
            )
        })
        .map(drop)
    }

    /// Attaches this process's mount at `name` under a directory descriptor. The
    /// target is resolved under that directory without following a final link.
    pub fn move_mount_at(mount: &DetachedMount, dir: &File, name: &CStr) -> io::Result<()> {
        // SAFETY: both descriptors are live; the target name is NUL-terminated.
        sys_ret(unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                mount.0.as_raw_fd(),
                c"".as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            )
        })
        .map(drop)
    }

    /// Binds a directory onto itself, making it a mount point (the jail base, so its
    /// propagation can be made private). `libc::mount` is disallowed elsewhere since
    /// B7 milestone 2 (MEDIUM-1); these two fixed forms are all the helper needs.
    pub fn bind_onto_itself(path: &CStr) -> io::Result<()> {
        // SAFETY: a NUL-terminated path, as both source and target of a plain bind.
        let rc = unsafe {
            libc::mount(
                path.as_ptr(),
                path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        sys_ret(libc::c_long::from(rc)).map(drop)
    }

    /// Makes a mount and every mount below it private, so later mounts there never
    /// propagate elsewhere. It changes propagation only.
    pub fn make_private_recursive(path: &CStr) -> io::Result<()> {
        // SAFETY: a NUL-terminated target; no source, type or data.
        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                path.as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        };
        sys_ret(libc::c_long::from(rc)).map(drop)
    }

    /// Loop and block-device ioctls: read requests, attaching a free slot, and clearing
    /// autoclear on a slot this process configured. Nothing here detaches a slot or
    /// changes any other binding field (B4 recheck 5 finding 3).
    pub mod ioctl {
        use std::fs::File;
        use std::io;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
        const LOOP_GET_STATUS64: libc::c_ulong = 0x4C05;
        const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
        const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
        const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
        const BLKSSZGET: libc::c_ulong = 0x1268;
        /// `_IOR(0x12, 128, __u64)`.
        const BLKGETDISKSEQ: libc::c_ulong = 0x8008_1280;
        const LO_FLAGS_AUTOCLEAR: u32 = 4;
        const LOOP_MAJOR: u32 = 7;

        /// A slot's `LOOP_GET_STATUS64` answer. Opaque: only [`loop_status`] makes one,
        /// from the kernel, and nothing outside this module can change or submit one.
        ///
        /// ```compile_fail
        /// // B4 recheck 5 PoC (typed-ioctl-occupied-loop): a forged status cannot be
        /// // built or edited, so it cannot retune an occupied slot.
        /// fn forge(device: &std::fs::File) {
        ///     let mut forged = kilnd::sys::ioctl::loop_status(device).unwrap().unwrap();
        ///     forged.lo_sizelimit = 1 << 20;
        /// }
        /// ```
        #[repr(C)]
        pub struct LoopInfo64 {
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

        impl LoopInfo64 {
            /// The backing file's device, as the kernel encodes it (`huge_encode_dev`).
            pub fn backing_device(&self) -> u64 {
                self.lo_device
            }

            pub fn backing_inode(&self) -> u64 {
                self.lo_inode
            }

            pub fn offset(&self) -> u64 {
                self.lo_offset
            }

            pub fn size_limit(&self) -> u64 {
                self.lo_sizelimit
            }

            pub fn autoclear(&self) -> bool {
                self.lo_flags & LO_FLAGS_AUTOCLEAR != 0
            }
        }

        /// Whether a `lo_device` (`huge_encode_dev`) names the device `st_dev`.
        pub fn same_device(encoded: u64, st_dev: u64) -> bool {
            let major = ((encoded & 0xfff00) >> 8) as u32;
            let minor = ((encoded & 0xff) | ((encoded >> 12) & 0xfff00)) as u32;
            (major, minor) == (libc::major(st_dev), libc::minor(st_dev))
        }

        #[repr(C)]
        struct LoopConfig {
            fd: u32,
            block_size: u32,
            info: LoopInfo64,
            reserved: [u64; 8],
        }

        fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
            if rc < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(rc)
            }
        }

        /// `LOOP_GET_STATUS64`; `None` for a free slot (`ENXIO`).
        pub fn loop_status(device: &File) -> io::Result<Option<LoopInfo64>> {
            // SAFETY: zero is valid for every field.
            let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
            // SAFETY: info is writable and sized for LOOP_GET_STATUS64.
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

        /// `LOOP_CTL_GET_FREE` on `/dev/loop-control`: a candidate slot, nothing bound.
        pub fn loop_free_slot(control: &File) -> io::Result<u32> {
            // SAFETY: LOOP_CTL_GET_FREE takes no argument.
            let minor = cvt(unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) })?;
            Ok(minor as u32)
        }

        /// `BLKGETDISKSEQ`.
        pub fn disk_sequence(device: &File) -> io::Result<u64> {
            let mut seq: u64 = 0;
            // SAFETY: seq is writable for BLKGETDISKSEQ.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), BLKGETDISKSEQ, &mut seq) })?;
            Ok(seq)
        }

        /// `BLKGETSIZE64`.
        pub fn block_device_bytes(device: &File) -> io::Result<u64> {
            let mut size: u64 = 0;
            // SAFETY: size is writable for BLKGETSIZE64.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), BLKGETSIZE64, &mut size) })?;
            Ok(size)
        }

        /// `BLKSSZGET`.
        pub fn logical_block_size(device: &File) -> io::Result<libc::c_int> {
            let mut block: libc::c_int = 0;
            // SAFETY: block is writable for BLKSSZGET.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), BLKSSZGET, &mut block) })?;
            Ok(block)
        }

        /// A slot this process bound with [`loop_configure_autoclear`]: the configuring
        /// descriptor, what it was bound to, and the attachment's disk sequence number
        /// read on that descriptor right after. Only that function makes one, so the
        /// autoclear clear can only reach this process's own attachment.
        pub struct ConfiguredLoop {
            device: File,
            backing_dev: u64,
            backing_ino: u64,
            size_limit: u64,
            diskseq: u64,
        }

        impl ConfiguredLoop {
            /// The configuring descriptor, for read-only checks.
            pub fn device(&self) -> &File {
                &self.device
            }

            /// The attachment's disk sequence number, read right after `LOOP_CONFIGURE`.
            pub fn diskseq(&self) -> u64 {
                self.diskseq
            }
        }

        /// `LOOP_CONFIGURE` of a slot onto `backing`, offset 0, with `LO_FLAGS_AUTOCLEAR`.
        /// The kernel refuses a bound slot with `EBUSY`, so this never replaces a binding.
        pub fn loop_configure_autoclear(
            device: File,
            backing: &File,
            size_limit: u64,
            block_size: u32,
        ) -> io::Result<ConfiguredLoop> {
            let meta = backing.metadata()?;
            // SAFETY: zero is valid for every field; the kernel copies the structure.
            let mut config: LoopConfig = unsafe { std::mem::zeroed() };
            config.fd = backing.as_raw_fd() as u32;
            config.info.lo_offset = 0;
            config.info.lo_sizelimit = size_limit;
            config.info.lo_flags = LO_FLAGS_AUTOCLEAR;
            config.block_size = block_size;
            // SAFETY: config is a complete loop_config for this live descriptor.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CONFIGURE, &config) })?;
            let diskseq = disk_sequence(&device)?;
            Ok(ConfiguredLoop {
                device,
                backing_dev: meta.dev(),
                backing_ino: meta.ino(),
                size_limit,
                diskseq,
            })
        }

        /// Clears `LO_FLAGS_AUTOCLEAR` on this process's own attachment, so it outlives
        /// the configuring descriptor. On that descriptor it reads the status itself
        /// (`LOOP_GET_STATUS64`), requires the configured backing device and inode,
        /// offset 0, size limit, autoclear still set, and the configured disk sequence
        /// number before and after that read, then writes back exactly that status less
        /// the one flag. It cannot end or retune a binding.
        ///
        /// ```compile_fail
        /// // B4 recheck 5 PoC (unchecked-wrappers): a status read from any slot is not a
        /// // ConfiguredLoop, so it cannot be submitted for that slot.
        /// fn retune(device: &std::fs::File) {
        ///     let forged = kilnd::sys::ioctl::loop_status(device).unwrap().unwrap();
        ///     kilnd::sys::ioctl::loop_clear_autoclear(device, &forged).unwrap();
        /// }
        /// ```
        ///
        /// The read-only accessors do compile, so the two refusals above are the
        /// privacy and the signature, not a wrong path:
        ///
        /// ```no_run
        /// fn limit(device: &std::fs::File) -> u64 {
        ///     let status = kilnd::sys::ioctl::loop_status(device).unwrap();
        ///     status.map_or(0, |s| s.size_limit())
        /// }
        /// ```
        pub fn loop_clear_autoclear(configured: &ConfiguredLoop) -> io::Result<()> {
            let device = &configured.device;
            let stat = device.metadata()?;
            use std::os::unix::fs::FileTypeExt;
            if !stat.file_type().is_block_device() || libc::major(stat.rdev()) != LOOP_MAJOR {
                return Err(io::Error::other("not a loop device"));
            }
            let generation = |what: &str| -> io::Result<()> {
                if disk_sequence(device)? != configured.diskseq {
                    return Err(io::Error::other(format!(
                        "loop attachment changed {what} clearing autoclear"
                    )));
                }
                Ok(())
            };
            generation("before")?;
            let mut info = loop_status(device)?
                .ok_or_else(|| io::Error::other("loop detached before clearing autoclear"))?;
            generation("while")?;
            if !same_device(info.lo_device, configured.backing_dev)
                || info.lo_inode != configured.backing_ino
                || info.lo_offset != 0
                || info.lo_sizelimit != configured.size_limit
                || !info.autoclear()
            {
                return Err(io::Error::other(
                    "loop status is not this process's attachment",
                ));
            }
            info.lo_flags &= !LO_FLAGS_AUTOCLEAR;
            // SAFETY: info is the kernel's own status for this slot, less one flag.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_STATUS64, &info) }).map(drop)
        }
    }
}

/// kilnd's API socket generation and its one removal (B4 recheck 5 finding 2).
///
/// `(device, inode)` is not a generation: once a socket is unlinked, the filesystem can
/// hand its inode number straight to a replacement. A [`SocketGeneration`] adds the
/// birth time, which no system call sets, and on Linux the inode's file handle
/// (`name_to_handle_at`), which carries the inode generation number that ext4, XFS and
/// tmpfs draw afresh for every allocation. The birth time alone is not enough: inode
/// timestamps come from the coarse clock, so a replacement created within one clock tick
/// of the original has the same one (measured on ext4, B4 fixes 6). Everything is read
/// without following a link through the retained socket directory's descriptor. [`remove_socket_generation`] reads it
/// again that way immediately before `unlinkat(dir, name)`; the remaining interval
/// between that read and the unlink is the decided narrow window (design 7.1).
pub mod socket {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    /// A socket's device, inode, birth time and (Linux) file handle. Only
    /// [`socket_generation_at`] makes one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SocketGeneration {
        device: u64,
        inode: u64,
        birth_sec: i64,
        birth_nsec: u32,
        handle: Handle,
    }

    /// `name_to_handle_at`'s answer: type, length and bytes. On Linux it is never empty:
    /// a socket filesystem that cannot export a handle is refused (B7, B4 recheck 6
    /// item 1), so the birth time is never the only generation field there. macOS has no
    /// file handles; its sockets carry the empty one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Handle {
        kind: i32,
        len: u32,
        bytes: [u8; 128],
    }

    #[cfg(target_os = "macos")]
    const NO_HANDLE: Handle = Handle {
        kind: 0,
        len: 0,
        bytes: [0; 128],
    };

    /// What a failed `name_to_handle_at` means. `ENOENT` is a vanished name; every other
    /// error is an error, `EOPNOTSUPP` included: a filesystem that exports no handle
    /// (ramfs, say, which accepts Unix sockets) has no inode generation to compare, and
    /// device, inode and birth time alone are not a generation (B4 recheck 6 item 1).
    /// There is no all-zero fallback.
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn handle_error(error: io::Error) -> io::Result<Option<()>> {
        match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::EOPNOTSUPP) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the socket directory's filesystem cannot export file handles \
                 (name_to_handle_at: EOPNOTSUPP), so a socket's generation cannot be \
                 proved; put the socket on tmpfs, ext4 or XFS",
            )),
            _ => Err(error),
        }
    }

    #[cfg(target_os = "linux")]
    fn handle_at(dir: &File, name: &CString) -> io::Result<Option<Handle>> {
        #[repr(C)]
        struct FileHandle {
            handle_bytes: libc::c_uint,
            handle_type: libc::c_int,
            f_handle: [u8; 128],
        }
        let mut raw = FileHandle {
            handle_bytes: 128,
            handle_type: 0,
            f_handle: [0; 128],
        };
        let mut mount_id: libc::c_int = 0;
        // SAFETY: the handle buffer holds `handle_bytes` bytes after its header; the name
        // is NUL-terminated; flags 0 do not follow a final link.
        let rc = unsafe {
            libc::name_to_handle_at(
                dir.as_raw_fd(),
                name.as_ptr(),
                (&mut raw as *mut FileHandle).cast::<libc::file_handle>(),
                &mut mount_id,
                0,
            )
        };
        if rc != 0 {
            return handle_error(io::Error::last_os_error()).map(|_| None);
        }
        if raw.handle_bytes == 0 || raw.handle_bytes > 128 {
            return Err(io::Error::other(format!(
                "name_to_handle_at returned a {}-byte handle",
                raw.handle_bytes
            )));
        }
        let len = raw.handle_bytes;
        let mut bytes = [0u8; 128];
        bytes[..len as usize].copy_from_slice(&raw.f_handle[..len as usize]);
        Ok(Some(Handle {
            kind: raw.handle_type,
            len,
            bytes,
        }))
    }

    /// What is at a name below a directory descriptor, never followed.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Seen {
        Nothing,
        NotASocket,
        Socket(SocketGeneration),
    }

    fn name_c(name: &OsStr) -> io::Result<CString> {
        if name.is_empty() || name.as_bytes().contains(&b'/') || name == "." || name == ".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a socket name is one path component",
            ));
        }
        CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    #[cfg(target_os = "linux")]
    fn read(dir: &File, name: &CString) -> io::Result<Option<(bool, SocketGeneration)>> {
        // SAFETY: statx writes into the zeroed buffer; the name is NUL-terminated.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::statx(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_TYPE | libc::STATX_INO | libc::STATX_BTIME,
                &mut stx,
            )
        };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error);
        }
        // The file handle first: a filesystem without one is refused by name, whatever
        // else it lacks (ramfs has neither handles nor birth times).
        let Some(handle) = handle_at(dir, name)? else {
            return Ok(None);
        };
        if stx.stx_mask & libc::STATX_BTIME == 0 {
            return Err(io::Error::other(
                "the socket directory's filesystem reports no birth time (STATX_BTIME)",
            ));
        }
        let socket = u32::from(stx.stx_mode) & libc::S_IFMT == libc::S_IFSOCK;
        Ok(Some((
            socket,
            SocketGeneration {
                device: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
                inode: stx.stx_ino,
                birth_sec: stx.stx_btime.tv_sec,
                birth_nsec: stx.stx_btime.tv_nsec,
                handle,
            },
        )))
    }

    #[cfg(target_os = "macos")]
    fn read(dir: &File, name: &CString) -> io::Result<Option<(bool, SocketGeneration)>> {
        // SAFETY: stat is writable; the name is NUL-terminated.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(Some((
            stat.st_mode & libc::S_IFMT == libc::S_IFSOCK,
            SocketGeneration {
                device: stat.st_dev as u64,
                inode: stat.st_ino,
                birth_sec: stat.st_birthtime,
                birth_nsec: stat.st_birthtime_nsec as u32,
                handle: NO_HANDLE,
            },
        )))
    }

    /// What is at `name` below `dir` now, without following it.
    pub fn socket_generation_at(dir: &File, name: &OsStr) -> io::Result<Seen> {
        Ok(match read(dir, &name_c(name)?)? {
            None => Seen::Nothing,
            Some((false, _)) => Seen::NotASocket,
            Some((true, generation)) => Seen::Socket(generation),
        })
    }

    /// The outcome of [`remove_socket_generation`].
    #[derive(Debug, PartialEq, Eq)]
    pub enum Removal {
        Removed,
        /// Something else is at the name now; it was left exactly as it is.
        Replaced,
        /// Nothing is at the name.
        Gone,
    }

    /// Unlinks `name` below `dir` only if it is still exactly `expected`, read again
    /// through `dir` immediately before `unlinkat(dir, name, 0)`.
    pub fn remove_socket_generation(
        dir: &File,
        name: &OsStr,
        expected: &SocketGeneration,
    ) -> io::Result<Removal> {
        let c = name_c(name)?;
        match read(dir, &c)? {
            None => return Ok(Removal::Gone),
            Some((true, seen)) if seen == *expected => {}
            Some(_) => return Ok(Removal::Replaced),
        }
        // SAFETY: a NUL-terminated single component below a live directory descriptor.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(Removal::Gone);
            }
            return Err(error);
        }
        Ok(Removal::Removed)
    }
}

// After every production item: the destructive-call gate stops scanning this file at its
// test module.
#[cfg(test)]
mod tests {
    /// The unprivileged fallback reads what `openat2` reads, and follows no link.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_component_walk_reads_what_openat2_reads() {
        use super::linux::procfs;
        use std::io::Read;
        let relative = procfs::own("cgroup");
        let (root, root_id) = procfs::root().unwrap();
        let mut walked = String::new();
        procfs::open_by_components(root, root_id, &relative, libc::O_RDONLY)
            .unwrap()
            .read_to_string(&mut walked)
            .unwrap();
        assert_eq!(walked, procfs::read_to_string(&relative).unwrap());
        assert!(walked.starts_with("0::/"), "{walked}");
        // `self` is a link: never followed.
        assert!(procfs::open_by_components(root, root_id, "self/cgroup", libc::O_RDONLY).is_err());
        // A root ID that is not the walk's mount refuses the first component.
        let error =
            procfs::open_by_components(root, root_id ^ 1, &relative, libc::O_RDONLY).unwrap_err();
        assert!(error.to_string().contains("crosses a mount"), "{error}");
    }

    /// B4 recheck 6 item 1: `EOPNOTSUPP` from `name_to_handle_at` is an error, never the
    /// all-zero handle; a vanished name is still "nothing there".
    #[test]
    fn b7_a_socket_filesystem_without_file_handles_is_refused() {
        use super::socket::handle_error;
        use std::io;
        let error = handle_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error.to_string().contains("cannot export file handles"),
            "{error}"
        );
        assert!(matches!(
            handle_error(io::Error::from_raw_os_error(libc::ENOENT)),
            Ok(None)
        ));
        assert_eq!(
            handle_error(io::Error::from_raw_os_error(libc::EIO))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
    }

    /// B4 recheck 6 item 3: concurrent first callers make exactly one root and all get
    /// it; a cached descriptor whose identity changed is replaced once, and the old one
    /// is not closed.
    #[test]
    fn b7_concurrent_first_callers_make_exactly_one_procfs_root() {
        use super::RootCache;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        static CACHE: RootCache = RootCache::new();
        static MADE: AtomicUsize = AtomicUsize::new(0);
        static STALE: AtomicBool = AtomicBool::new(false);
        let directory = tempfile::tempdir().unwrap();
        let path = Arc::new(directory.path().to_path_buf());
        // The identity of a descriptor: its inode, or another value once marked stale.
        fn identity(fd: std::os::fd::RawFd) -> std::io::Result<u64> {
            // SAFETY: fstat writes into the zeroed buffer.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut stat) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(stat.st_ino + u64::from(STALE.load(Ordering::SeqCst)))
        }
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (barrier, path) = (barrier.clone(), path.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    CACHE
                        .get(identity, || {
                            MADE.fetch_add(1, Ordering::SeqCst);
                            // Widen the race: every other caller arrives meanwhile.
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            std::fs::File::open(&*path)
                        })
                        .unwrap()
                })
            })
            .collect();
        let roots: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            MADE.load(Ordering::SeqCst),
            1,
            "more than one root was made"
        );
        assert!(roots.iter().all(|r| *r == roots[0]), "{roots:?}");
        // Still cached: no second make.
        let again = CACHE.get(identity, || unreachable!()).unwrap();
        assert_eq!(again, roots[0]);
        // The cached descriptor no longer reads its identity: replaced once, the old
        // descriptor left open (its number may be another file's by now).
        STALE.store(true, Ordering::SeqCst);
        let made = CACHE
            .get(identity, || {
                MADE.fetch_add(1, Ordering::SeqCst);
                std::fs::File::open(&*path)
            })
            .unwrap();
        assert_eq!(MADE.load(Ordering::SeqCst), 2);
        assert_ne!(made.0, roots[0].0);
        assert!(
            identity(roots[0].0).is_ok(),
            "the replaced descriptor was closed"
        );
        // A make that fails caches nothing.
        STALE.store(false, Ordering::SeqCst);
        let fresh = RootCache::new();
        assert!(
            fresh
                .get(identity, || Err(std::io::Error::other("no root")))
                .is_err()
        );
        assert_eq!(
            fresh
                .get(identity, || std::fs::File::open(&*path))
                .unwrap()
                .1,
            { identity(made.0).unwrap() }
        );
    }

    /// B4 recheck 6 item 4: listing a directory reads its own open file description, so
    /// the caller's directory offset is exactly where it was, and the listing is whole.
    #[cfg(target_os = "linux")]
    #[test]
    fn b7_read_dir_fd_leaves_the_callers_offset_alone() {
        use std::os::fd::AsRawFd;
        let directory = tempfile::tempdir().unwrap();
        for n in 0..200 {
            std::fs::File::create(directory.path().join(format!("entry-{n:03}"))).unwrap();
        }
        let dir = std::fs::File::open(directory.path()).unwrap();
        // Advance the caller's own offset partway with a small getdents64.
        let mut buffer = vec![0u64; 64];
        // SAFETY: the buffer is writable for its length; the descriptor is live.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dir.as_raw_fd(),
                buffer.as_mut_ptr().cast::<u8>(),
                buffer.len() * 8,
            )
        };
        assert!(n > 0);
        // SAFETY: reading the descriptor's offset.
        let before = unsafe { libc::lseek(dir.as_raw_fd(), 0, libc::SEEK_CUR) };
        assert!(before > 0, "the caller's offset did not advance");
        let entries = super::read_dir_fd(&dir, 1000).unwrap();
        assert_eq!(entries.len(), 200);
        // SAFETY: as above.
        let after = unsafe { libc::lseek(dir.as_raw_fd(), 0, libc::SEEK_CUR) };
        assert_eq!(
            after, before,
            "read_dir_fd moved the caller's directory offset"
        );
        // An O_PATH descriptor, as the helper holds, lists the same.
        let path = std::ffi::CString::new(directory.path().to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        // SAFETY: open returned a new descriptor.
        let held = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        assert_eq!(super::read_dir_fd(&held, 1000).unwrap().len(), 200);
    }

    /// Runs `body` on a thread of its own with a private copy of the mount namespace, so
    /// mounts it makes vanish with the thread.
    #[cfg(target_os = "linux")]
    fn in_private_mount_namespace<T: Send + 'static>(
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        std::thread::spawn(move || {
            // SAFETY: unsharing this thread's filesystem attributes and mount namespace.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNS) },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            // SAFETY: NUL-terminated strings; MS_REC|MS_PRIVATE stops propagation out.
            let rc = unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            };
            assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
            body()
        })
        .join()
        .unwrap()
    }

    /// B6-RC-01: a bind mount of another process's procfs directory over this one's, on
    /// the same procfs superblock, passes the superblock check but not the mount check.
    /// Root, in a private mount namespace on one thread (the PoC's `procfs-fallback-
    /// redirect.sh` without the seccomp filter: the walk is called directly).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root: sudo the kilnd lib test binary --ignored b7_linux_root_sys"]
    fn b7_linux_root_sys_the_component_walk_refuses_a_bind_mounted_procfs_directory() {
        use super::linux::procfs;
        use std::io::Read;
        let refused = in_private_mount_namespace(|| {
            // SAFETY: getpid has no preconditions.
            let me = unsafe { libc::getpid() };
            let target = std::ffi::CString::new(format!("/proc/{me}")).unwrap();
            // SAFETY: NUL-terminated paths; a plain bind of PID 1's directory.
            let rc = unsafe {
                libc::mount(
                    c"/proc/1".as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
            let root = std::fs::File::open("/proc").unwrap();
            use std::os::fd::AsRawFd;
            let mut stx: libc::statx = unsafe { std::mem::zeroed() };
            // SAFETY: statx writes into the zeroed buffer.
            assert_eq!(
                unsafe {
                    libc::statx(
                        root.as_raw_fd(),
                        c"".as_ptr(),
                        libc::AT_EMPTY_PATH,
                        0x4000,
                        &mut stx,
                    )
                },
                0
            );
            let root_id = stx.stx_mnt_id;
            // Through the bind: the walk is refused at the redirected component.
            let redirected = procfs::open_by_components(
                root.as_raw_fd(),
                root_id,
                &format!("{me}/cgroup"),
                libc::O_RDONLY,
            )
            .unwrap_err()
            .to_string();
            // Without it (another process's own directory): the walk reads.
            let mut text = String::new();
            procfs::open_by_components(root.as_raw_fd(), root_id, "1/cgroup", libc::O_RDONLY)
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            assert!(text.starts_with("0::/"), "{text}");
            redirected
        });
        assert!(refused.contains("crosses a mount"), "{refused}");
    }

    /// B4 recheck 6 item 1 on a real kernel: ramfs accepts a Unix socket but exports no
    /// file handle, so kilnd refuses to bind its API socket there (the socket's
    /// generation could not be proved before a later unlink).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root: sudo the kilnd lib test binary --ignored b7_linux_root_sys"]
    fn b7_linux_root_sys_a_ramfs_socket_has_no_generation_and_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let mountpoint = scratch.path().join("ramfs");
        std::fs::create_dir(&mountpoint).unwrap();
        let errors = in_private_mount_namespace(move || {
            let target = std::ffi::CString::new(mountpoint.to_str().unwrap()).unwrap();
            // SAFETY: NUL-terminated strings; a fresh ramfs instance.
            let rc = unsafe {
                libc::mount(
                    c"kilnd-b7-ramfs".as_ptr(),
                    target.as_ptr(),
                    c"ramfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
            assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
            std::fs::set_permissions(
                &mountpoint,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            // The raw socket: ramfs takes it, and its generation is refused.
            let dir = std::fs::File::open(&mountpoint).unwrap();
            let _listener =
                std::os::unix::net::UnixListener::bind(mountpoint.join("raw.sock")).unwrap();
            let raw = super::socket::socket_generation_at(&dir, std::ffi::OsStr::new("raw.sock"))
                .unwrap_err();
            // kilnd's own bind refuses the directory.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let bound = runtime
                .block_on(crate::server::bind(
                    &mountpoint.join("run/kilnd.sock"),
                    None,
                ))
                .err()
                .expect("kilnd bound its socket on ramfs");
            (raw, format!("{bound:#}"))
        });
        assert_eq!(
            errors.0.kind(),
            std::io::ErrorKind::Unsupported,
            "{}",
            errors.0
        );
        assert!(
            errors.1.contains("cannot export file handles"),
            "{}",
            errors.1
        );
    }

    /// The root listing holds this process's own directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_private_root_lists_this_process() {
        let own = std::process::id().to_string().into_bytes();
        let entries = super::linux::procfs::read_root_dir(1 << 16).unwrap();
        assert!(entries.iter().any(|entry| entry.name == own));
        assert!(super::linux::procfs::read_root_dir(0).is_err(), "bounded");
    }
}
