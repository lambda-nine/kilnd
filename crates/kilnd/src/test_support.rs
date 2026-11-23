//! Helpers shared by the unit tests.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Bytes the tests add below a [`short_tempdir`]: `/.tmpXXXXXX/` and a socket name
/// (`alias/state/kilnd.sock` is the longest), with room to spare.
const SOCKET_ROOM: usize = 48;

/// The longest socket path `sun_path` holds everywhere the tests run: 104 bytes on macOS
/// and 108 on Linux, each with the terminating NUL.
const SUN_PATH_MAX: usize = 103;

/// A private (0700) temporary directory short enough for the Unix sockets the tests bind
/// in it. Under a `TMPDIR` that leaves less than [`SOCKET_ROOM`] bytes within `sun_path`,
/// spelled or resolved (a consumer may canonicalize before binding, and a short alias can
/// resolve to a long path), the directory is made in `/tmp` instead, whose sticky bit
/// passes the same ancestor rules. Either way it is created atomically at 0700, so
/// neither the process umask nor `/tmp`'s sticky bit decides who can reach it.
pub(crate) fn short_tempdir() -> std::io::Result<tempfile::TempDir> {
    short_tempdir_under(&std::env::temp_dir())
}

/// [`short_tempdir`] with `root` in place of `TMPDIR`.
pub(crate) fn short_tempdir_under(root: &Path) -> std::io::Result<tempfile::TempDir> {
    let resolved = root.canonicalize()?;
    let longest = root.as_os_str().len().max(resolved.as_os_str().len());
    let parent = if longest + SOCKET_ROOM > SUN_PATH_MAX {
        Path::new("/tmp")
    } else {
        root
    };
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let mode = std::fs::metadata(dir.path())?.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return Err(std::io::Error::other(format!(
            "{} was created with mode {mode:o}, not 0700",
            dir.path().display()
        )));
    }
    Ok(dir)
}

#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). The umask test
// reruns this test binary in a child shell with another umask.
#[allow(clippy::disallowed_methods)]
mod tests {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::Path;

    use super::{SOCKET_ROOM, SUN_PATH_MAX, short_tempdir, short_tempdir_under};

    const CHILD_UMASK: &str = "KILND_TEST_SUPPORT_CHILD_UMASK";

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// A directory under a private `/tmp` base whose path is at least `len` bytes.
    fn long_dir(base: &Path, len: usize) -> std::path::PathBuf {
        let mut dir = base.to_path_buf();
        while dir.as_os_str().len() < len {
            dir.push("d".repeat(20));
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        dir
    }

    // Every directory the helper makes is exactly 0700 under umask 0002 and 0000, on the
    // ordinary path and the `/tmp` fallback. The umask is process-wide, so each case runs
    // in a child copy of this test binary that runs only this test.
    #[test]
    fn short_tempdirs_are_private_under_any_umask() {
        if let Ok(umask) = std::env::var(CHILD_UMASK) {
            let umask = u32::from_str_radix(&umask, 8).unwrap();
            let base = short_tempdir_under(Path::new("/tmp")).unwrap();
            // The child really runs under the umask: a plain directory follows it.
            let probe = base.path().join("probe");
            std::fs::create_dir(&probe).unwrap();
            assert_eq!(
                mode(&probe),
                0o777 & !umask,
                "umask {umask:o} not in effect"
            );

            let ordinary = short_tempdir_under(Path::new("/tmp")).unwrap();
            assert_eq!(ordinary.path().parent(), Some(Path::new("/tmp")));
            assert_eq!(mode(ordinary.path()), 0o700, "ordinary path");
            let long = long_dir(base.path(), 132);
            let fallback = short_tempdir_under(&long).unwrap();
            assert_eq!(fallback.path().parent(), Some(Path::new("/tmp")));
            assert_eq!(mode(fallback.path()), 0o700, "fallback path");
            let default = short_tempdir().unwrap();
            assert_eq!(mode(default.path()), 0o700, "TMPDIR path");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        for umask in ["0002", "0000"] {
            let out = std::process::Command::new("/bin/sh")
                .args(["-c", r#"umask "$0" && exec "$@""#, umask])
                .arg(&exe)
                .args([
                    "--exact",
                    "test_support::tests::short_tempdirs_are_private_under_any_umask",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD_UMASK, umask)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("1 passed"),
                "umask {umask}: {}\n{stdout}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // A consumer that canonicalizes before binding (checkpoint/tests/socket.rs) binds the
    // resolved path, so a short alias to a long TMPDIR must still fall back.
    #[test]
    fn a_short_alias_to_a_long_root_falls_back() {
        let base = short_tempdir_under(Path::new("/tmp")).unwrap();
        let long = long_dir(base.path(), 132);
        let alias = base.path().join("a");
        std::os::unix::fs::symlink(&long, &alias).unwrap();
        // The case the spelled length alone would let through.
        assert!(alias.as_os_str().len() + SOCKET_ROOM <= SUN_PATH_MAX);
        assert!(alias.canonicalize().unwrap().as_os_str().len() + SOCKET_ROOM > SUN_PATH_MAX);

        let dir = short_tempdir_under(&alias).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        let resolved = dir.path().canonicalize().unwrap();
        let state = resolved.join("alias/state");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state)
            .unwrap();
        drop(std::os::unix::net::UnixListener::bind(state.join("kilnd.sock")).unwrap());

        // A long spelled root falls back as before.
        let spelled = short_tempdir_under(&long).unwrap();
        assert_eq!(spelled.path().parent(), Some(Path::new("/tmp")));
    }
}

/// A live process whose command name isn't UTF-8, for the tests of the procfs readers
/// that read every process (or a given one) beneath the private instance.
#[cfg(target_os = "linux")]
#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They start a
// process through a link whose name isn't UTF-8, and kill and reap it when done.
#[allow(clippy::disallowed_methods)]
pub(crate) mod non_utf8 {
    use std::os::unix::ffi::OsStrExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// `/bin/sleep` run through a link named `\xff`: the kernel names a process for the
    /// basename it was executed by, so its `comm` (and `stat`'s and `status`'s copies)
    /// is that one byte. Killed and reaped when dropped.
    pub(crate) struct Process {
        child: Child,
        _dir: tempfile::TempDir,
    }

    impl Process {
        pub(crate) fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let link = dir.path().join(std::ffi::OsStr::from_bytes(b"\xff"));
            std::os::unix::fs::symlink("/bin/sleep", &link).unwrap();
            let child = Command::new(&link)
                .arg("600")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let process = Self { child, _dir: dir };
            // Named once it has executed: then a text read of its stat fails, as the
            // readers under test did.
            let pid = process.pid();
            let deadline = Instant::now() + Duration::from_secs(10);
            while std::fs::read(format!("/proc/{pid}/comm")).ok().as_deref() != Some(b"\xff\n") {
                assert!(
                    Instant::now() < deadline,
                    "process {pid} was never named \\xff"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            for file in ["stat", "status"] {
                let text = std::fs::read_to_string(format!("/proc/{pid}/{file}"));
                assert!(text.is_err(), "{file} read as text: {text:?}");
            }
            process
        }

        pub(crate) fn pid(&self) -> i32 {
            self.child.id() as i32
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
