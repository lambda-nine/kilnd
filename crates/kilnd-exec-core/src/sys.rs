//! Typed system-call wrappers the direct-kiln child setup needs (design section 7.1).
//! Moved from `kilnd::sys` (Phase 1b B5) with `process::prepare_child`, which issues
//! them between fork and exec; kilnd re-exports them. Each function issues exactly one
//! fixed request on the calling thread or process, and none of them signals, unmounts,
//! renames, removes or detaches anything: `capget` and `capset` of the calling thread,
//! and fixed `prctl` capability, no-new-privs and parent-death requests.
// Approved (design 7.1): the typed wrapper module for libc::syscall and libc::prctl.
// Every request is a fixed one; see the module documentation.
#![allow(clippy::disallowed_methods)]

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::io;

    fn sys_ret(rc: libc::c_long) -> io::Result<libc::c_long> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
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

    /// Fixed `prctl` requests on the calling thread or process. Each returns the raw
    /// `prctl` result; all are async-signal-safe and allocation-free, for use between
    /// fork and exec.
    pub mod prctl {
        /// `PR_CAP_AMBIENT_IS_SET` of one capability.
        pub fn cap_ambient_is_set(cap: u32) -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
                    cap as libc::c_ulong,
                    0,
                    0,
                )
            }
        }

        /// `PR_CAP_AMBIENT_LOWER` of one capability.
        pub fn cap_ambient_lower(cap: u32) -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_LOWER as libc::c_ulong,
                    cap as libc::c_ulong,
                    0,
                    0,
                )
            }
        }

        /// `PR_CAPBSET_READ` of one capability.
        pub fn capbset_read(cap: u32) -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) }
        }

        /// `PR_CAPBSET_DROP` of one capability from the calling thread's bounding set.
        pub fn capbset_drop(cap: u32) -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) }
        }

        /// `PR_SET_NO_NEW_PRIVS` to 1 (it cannot be cleared).
        pub fn set_no_new_privs() -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }
        }

        /// `PR_GET_NO_NEW_PRIVS`.
        pub fn get_no_new_privs() -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }
        }

        /// `PR_SET_PDEATHSIG` to `SIGKILL`: the calling child dies with its parent.
        pub fn set_parent_death_kill() -> libc::c_int {
            // SAFETY: integer arguments only.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }
        }
    }
}
