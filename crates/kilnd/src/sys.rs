//! Typed system-call and ioctl wrappers (design section 7.1, B4 recheck 4).
//!
//! `libc::syscall` and `libc::ioctl` take any request, so clippy's
//! `disallowed-methods` (see `clippy.toml`) rejects them everywhere except here and
//! `helper::firecracker::proven`. Each function below issues exactly one fixed request,
//! and none of them signals, removes, unmounts, renames or detaches anything:
//!
//! - descriptors and processes: `close_range` of this process's own descriptors,
//!   `pidfd_open`, a pidfd liveness probe whose signal is the constant 0, `capget` and
//!   `capset` on the calling thread, and `execveat` of a retained descriptor (the only
//!   way the helper starts the jailer, Firecracker or mkfs.xfs);
//! - the new mount API, creation only: [`DetachedMount`] can be built only by
//!   [`fsmount`] or [`open_tree_clone`], and `move_mount` and `mount_setattr` take one,
//!   so they can only act on a mount this process created;
//! - the [`ioctl`] module: read requests, plus `LOOP_CONFIGURE` on a free slot (the
//!   kernel refuses a bound one) and clearing `LO_FLAGS_AUTOCLEAR`. `LOOP_CLR_FD`
//!   is not here: it exists only in `proven::clear_loop`, which takes a `ProvenLoop`.
//!
//! Signals, `cgroup.kill`, unlinks, `rmdir`, unmounts and `LOOP_CLR_FD` live only in
//! `helper::firecracker::proven`, behind its proof types.
// Approved (design 7.1): the typed wrapper module for libc::syscall and libc::ioctl.
// Every request is a fixed, non-destructive one; see the module documentation.
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

    /// `_LINUX_CAPABILITY_VERSION_3`'s header.
    #[repr(C)]
    pub struct CapHeader {
        pub version: u32,
        pub pid: i32,
    }

    /// One of the two `_LINUX_CAPABILITY_VERSION_3` data words.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct CapData {
        pub effective: u32,
        pub permitted: u32,
        pub inheritable: u32,
    }

    /// The calling thread's capability sets. Async-signal-safe.
    pub fn capget(header: &mut CapHeader, data: &mut [CapData; 2]) -> io::Result<()> {
        // SAFETY: header and two data words are live, correctly sized storage.
        sys_ret(unsafe { libc::syscall(libc::SYS_capget, header, data.as_mut_ptr()) }).map(drop)
    }

    /// Sets the calling thread's capability sets. Async-signal-safe.
    pub fn capset(header: &mut CapHeader, data: &[CapData; 2]) -> io::Result<()> {
        // SAFETY: header and data are live, correctly sized storage.
        sys_ret(unsafe { libc::syscall(libc::SYS_capset, header, data.as_ptr()) }).map(drop)
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

    /// Loop and block-device ioctls: read requests, plus attaching a free slot and
    /// clearing autoclear. Nothing here detaches or reconfigures a bound slot.
    pub mod ioctl {
        use std::fs::File;
        use std::io;
        use std::os::fd::AsRawFd;

        const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
        const LOOP_GET_STATUS64: libc::c_ulong = 0x4C05;
        const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
        const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
        const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
        const BLKSSZGET: libc::c_ulong = 0x1268;
        /// `_IOR(0x12, 128, __u64)`.
        const BLKGETDISKSEQ: libc::c_ulong = 0x8008_1280;
        pub const LO_FLAGS_AUTOCLEAR: u32 = 4;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct LoopInfo64 {
            pub lo_device: u64,
            pub lo_inode: u64,
            pub lo_rdevice: u64,
            pub lo_offset: u64,
            pub lo_sizelimit: u64,
            pub lo_number: u32,
            pub lo_encrypt_type: u32,
            pub lo_encrypt_key_size: u32,
            pub lo_flags: u32,
            pub lo_file_name: [u8; 64],
            pub lo_crypt_name: [u8; 64],
            pub lo_encrypt_key: [u8; 32],
            pub lo_init: [u64; 2],
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

        /// `LOOP_CONFIGURE` of a slot onto `backing`, offset 0, with `LO_FLAGS_AUTOCLEAR`.
        /// The kernel refuses a bound slot with `EBUSY`, so this never replaces a binding.
        pub fn loop_configure_autoclear(
            device: &File,
            backing: &File,
            size_limit: u64,
            block_size: u32,
        ) -> io::Result<()> {
            // SAFETY: zero is valid for every field; the kernel copies the structure.
            let mut config: LoopConfig = unsafe { std::mem::zeroed() };
            config.fd = backing.as_raw_fd() as u32;
            config.info.lo_offset = 0;
            config.info.lo_sizelimit = size_limit;
            config.info.lo_flags = LO_FLAGS_AUTOCLEAR;
            config.block_size = block_size;
            // SAFETY: config is a complete loop_config for this live descriptor.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CONFIGURE, &config) }).map(drop)
        }

        /// `LOOP_SET_STATUS64` of exactly `current` (what `LOOP_GET_STATUS64` returned)
        /// less `LO_FLAGS_AUTOCLEAR`. It can only make a binding outlive its descriptor,
        /// never end or alter one.
        pub fn loop_clear_autoclear(device: &File, current: &LoopInfo64) -> io::Result<()> {
            let mut info = *current;
            info.lo_flags &= !LO_FLAGS_AUTOCLEAR;
            // SAFETY: info is the kernel's own status structure for this slot.
            cvt(unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_STATUS64, &info) }).map(drop)
        }
    }
}
