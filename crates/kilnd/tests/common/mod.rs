//! Helpers shared by the integration tests.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Bytes the tests add below a [`short_tempdir`]: `/.tmpXXXXXX/` and a socket name
/// (`run/alternate.sock` is the longest), with room to spare.
pub const SOCKET_ROOM: usize = 48;

/// The longest socket path `sun_path` holds everywhere the tests run: 104 bytes on macOS
/// and 108 on Linux, each with the terminating NUL.
pub const SUN_PATH_MAX: usize = 103;

/// A private (0700) temporary directory short enough for the Unix sockets the tests bind
/// in it. Under a `TMPDIR` that leaves less than [`SOCKET_ROOM`] bytes within `sun_path`,
/// spelled or resolved (a short alias can resolve to a long path), the directory is made
/// in `/tmp` instead, whose sticky bit passes the same ancestor rules. Either way it is
/// created atomically at 0700, so neither the process umask nor `/tmp`'s sticky bit
/// decides who can reach it.
pub fn short_tempdir() -> std::io::Result<tempfile::TempDir> {
    short_tempdir_under(&std::env::temp_dir())
}

/// [`short_tempdir`] with `root` in place of `TMPDIR`.
pub fn short_tempdir_under(root: &Path) -> std::io::Result<tempfile::TempDir> {
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
