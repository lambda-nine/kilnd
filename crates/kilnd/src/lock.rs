//! Small advisory file locks used to coordinate daemon ownership.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A nonblocking exclusive lock held for as long as its file stays open.
///
/// The pathname is deliberately persistent. Removing a lock file while it is
/// held would let another process lock a different inode at the same path.
pub(crate) struct ExclusiveFileLock {
    _file: File,
    #[allow(dead_code)]
    path: PathBuf,
    #[cfg(test)]
    drop_probe: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl ExclusiveFileLock {
    pub(crate) fn acquire(path: &Path, resource: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open {resource} lock {}", path.display()))?;
        let meta = file
            .metadata()
            .with_context(|| format!("inspect {resource} lock {}", path.display()))?;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if !meta.is_file()
            || meta.uid() != euid
            || meta.permissions().mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            bail!(
                "{} is not a private regular lock file owned by uid {euid}",
                path.display()
            );
        }

        // SAFETY: the descriptor is live and flock accepts any open file
        // descriptor. LOCK_NB makes contention fail instead of blocking.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!("{resource} already owned; lock is {}", path.display());
            }
            return Err(error).with_context(|| format!("lock {resource} at {}", path.display()));
        }

        // Refuse a pathname swap around open/lock. The lock protects this
        // inode; ownership is useful only while the stable pathname names it.
        let path_meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("recheck {resource} lock {}", path.display()))?;
        if !path_meta.is_file() || path_meta.dev() != meta.dev() || path_meta.ino() != meta.ino() {
            bail!("{resource} lock changed while acquiring {}", path.display());
        }

        // PID text is diagnostic only. Kernel lock ownership is authoritative.
        file.set_len(0)
            .with_context(|| format!("truncate {resource} lock {}", path.display()))?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", std::process::id())
            .with_context(|| format!("write {resource} lock {}", path.display()))?;

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
            #[cfg(test)]
            drop_probe: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_drop_probe(mut self, probe: impl FnOnce() + Send + Sync + 'static) -> Self {
        self.drop_probe = Some(Box::new(probe));
        self
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(probe) = self.drop_probe.take() {
            probe();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_descriptor_is_closed_across_exec() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("owner.lock");
        let owner = ExclusiveFileLock::acquire(&path, "test resource").unwrap();
        let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();

        drop(owner);
        let next = ExclusiveFileLock::acquire(&path, "test resource")
            .expect("exec child inherited the ownership descriptor");
        drop(next);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
