//! Helpers shared by the integration tests.

/// [`tempfile::tempdir`], short enough for the Unix sockets the tests bind in it. A
/// socket path must fit in `sun_path` (104 bytes on macOS, 108 on Linux, with the
/// terminating NUL), so under a `TMPDIR` that leaves less than 48 bytes for
/// `/.tmpXXXXXX/` and a socket name (`run/alternate.sock` is the longest) the directory
/// is made in `/tmp` instead, whose sticky bit passes the same ancestor rules. Otherwise
/// it is exactly `tempdir()`.
pub fn short_tempdir() -> std::io::Result<tempfile::TempDir> {
    let root = std::env::temp_dir();
    if root.as_os_str().len() + 48 > 103 {
        return tempfile::tempdir_in("/tmp");
    }
    tempfile::tempdir_in(root)
}
