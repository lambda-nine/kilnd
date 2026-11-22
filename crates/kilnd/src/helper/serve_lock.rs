//! The helper's serving lock: every serving `kilnd-helper` holds it, from before it
//! accepts its first request until every request it accepted has settled, and `kilnd
//! release-ambiguous` holds it for its whole proof. While the release holds it no helper
//! serves, so nothing can start a kiln create; a helper that starts meanwhile exits
//! instead of waiting (docs/setup.md, "Releasing an ambiguous reservation").
//!
//! It is its own lock, not the Firecracker node ledger's: a helper with no Firecracker
//! policy never takes that one. The file sits in the helper's root-only state directory,
//! which `deploy/kilnd-helper.conf` creates on every node and the unit can write.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};

use crate::lock::{AlreadyOwned, ExclusiveFileLock};

/// Where both take it unless told otherwise (`kilnd-helper --serve-lock`, `kilnd
/// release-ambiguous --helper-lock`).
pub const DEFAULT_SERVE_LOCK: &str = "/var/lib/kilnd-helper/helper.lock";

/// The held lock. Its descriptor is close-on-exec, so no kiln child or shim inherits it;
/// a fork does, and holds it too until it closes it.
pub struct ServeLock {
    _lock: ExclusiveFileLock,
    path: PathBuf,
}

impl std::fmt::Debug for ServeLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeLock").field("path", &self.path).finish()
    }
}

/// Why the lock wasn't taken.
#[derive(Debug)]
pub enum ServeLockError {
    /// Another process holds it: a serving helper or a release.
    Held(PathBuf),
    /// Anything else: a bad path, a directory that isn't root's alone, an I/O error.
    Other(anyhow::Error),
}

impl std::fmt::Display for ServeLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(path) => write!(f, "{} is held", path.display()),
            Self::Other(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for ServeLockError {}

impl ServeLock {
    /// Takes the lock without waiting. The path must be absolute, without `..`, and its
    /// directory, opened without following a link, this process's own and writable by
    /// no one else.
    pub fn acquire(path: &Path) -> Result<Self, ServeLockError> {
        Self::open(path).map_err(|error| {
            if error.downcast_ref::<AlreadyOwned>().is_some() {
                ServeLockError::Held(path.to_path_buf())
            } else {
                ServeLockError::Other(error)
            }
        })
    }

    fn open(path: &Path) -> anyhow::Result<Self> {
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            bail!("the serving lock {} must be absolute, without '..'", path.display());
        }
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            bail!("the serving lock {} names no file", path.display());
        };
        let parent_c = CString::new(parent.as_os_str().as_bytes()).context("path contains NUL")?;
        // SAFETY: a NUL-terminated path and valid flags.
        let fd = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("open {} without following links", parent.display()));
        }
        // SAFETY: open returned a new owned descriptor.
        let directory = unsafe { File::from_raw_fd(fd) };
        let meta = directory.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid || meta.mode() & 0o022 != 0 {
            bail!(
                "{} is not uid {euid}'s alone (owner {}, mode {:o})",
                parent.display(),
                meta.uid(),
                meta.mode() & 0o7777
            );
        }
        let lock = ExclusiveFileLock::acquire_at(&directory, name, path, "kilnd-helper serving")?;
        Ok(Self {
            _lock: lock,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `serve` holding the lock at `path`: taken before `serve` is first polled, and
    /// released only once it has returned. kilnd-helper passes its whole serve, the
    /// groups' shutdown included, so no release can run beside anything it started.
    pub async fn hold_while<T>(
        path: &Path,
        serve: impl std::future::Future<Output = T>,
    ) -> Result<T, ServeLockError> {
        let lock = Self::acquire(path)?;
        let served = serve.await;
        drop(lock);
        Ok(served)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn one_holder_at_a_time_and_the_next_is_told_it_is_held() {
        let dir = private_dir();
        let path = dir.path().join("helper.lock");
        let first = ServeLock::acquire(&path).unwrap();
        assert_eq!(first.path(), path);
        match ServeLock::acquire(&path) {
            Err(ServeLockError::Held(held)) => assert_eq!(held, path),
            other => panic!("expected Held, got {other:?}"),
        }
        drop(first);
        ServeLock::acquire(&path).expect("free again once the holder is gone");
    }

    /// Review 2026-11-22 (spare kilnd security, T1): the helper's side of the fence.
    /// The lock is held while the serve runs, through a request still in flight and the
    /// groups' shutdown after it, and released only once the serve has returned; taken
    /// elsewhere, the serve never starts.
    #[tokio::test]
    async fn the_lock_is_held_for_the_whole_serve_and_released_after_it() {
        let dir = private_dir();
        let path = dir.path().join("helper.lock");
        let (in_flight, settle) = tokio::sync::oneshot::channel::<()>();
        let (started, serving) = tokio::sync::oneshot::channel::<()>();
        let held = path.clone();
        let serve = tokio::spawn(async move {
            ServeLock::hold_while(&held, async {
                // As a release would see it from the start of the serve...
                assert!(matches!(ServeLock::acquire(&held), Err(ServeLockError::Held(_))));
                started.send(()).unwrap();
                // ...through a request that has not settled...
                settle.await.unwrap();
                tokio::task::yield_now().await;
                // ...and the groups' shutdown after the listener stops.
                assert!(matches!(ServeLock::acquire(&held), Err(ServeLockError::Held(_))));
                "served"
            })
            .await
        });
        serving.await.unwrap();
        for _ in 0..3 {
            tokio::task::yield_now().await;
            assert!(matches!(ServeLock::acquire(&path), Err(ServeLockError::Held(_))));
        }
        in_flight.send(()).unwrap();
        assert_eq!(serve.await.unwrap().unwrap(), "served");
        ServeLock::acquire(&path).expect("free once the serve returned");

        // Held by a release: refused, and the serve is never polled.
        let fence = ServeLock::acquire(&path).unwrap();
        let refused = ServeLock::hold_while(&path, async { panic!("served beside a release") }).await;
        assert!(matches!(refused, Err(ServeLockError::Held(_))), "{refused:?}");
        drop(fence);
    }

    #[test]
    fn a_shared_directory_or_relative_path_is_refused() {
        let dir = private_dir();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        for bad in [
            shared.join("helper.lock"),
            PathBuf::from("relative/helper.lock"),
            dir.path().join("x/../helper.lock"),
        ] {
            assert!(
                matches!(ServeLock::acquire(&bad), Err(ServeLockError::Other(_))),
                "{}",
                bad.display()
            );
        }
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(matches!(
            ServeLock::acquire(&link.join("helper.lock")),
            Err(ServeLockError::Other(_))
        ));
    }
}
