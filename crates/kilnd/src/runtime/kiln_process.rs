//! The persistent-exec process owner moved to the direct-kiln core crate
//! (`kilnd_exec_core::runtime::kiln_process`) in Phase 1b B5. Only the adapter tests'
//! CLI fixture remains here.

/// The CLI fixture the kiln adapter's tests drive. A copy of the core crate's
/// `cfg(test)` fixture, which another crate's tests cannot reach.
#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#[allow(clippy::disallowed_methods)]
pub(super) mod tests {
    use std::os::unix::fs::PermissionsExt;

    pub fn fixture(path: &std::path::Path, body: &str) {
        std::fs::write(path, format!(r#"#!/usr/bin/python3
import os,sys,time,signal,socket
CAPS=bytes.fromhex('4b494c4e45584f00010002001d0000001f000000010001000500080000000000302e312e306769742074657374')
EXIT125=bytes.fromhex('4b494c4e45584f000100010018000000010102007d00000000000000000000000000000000000000')
if sys.argv[1]=='capabilities':
    os.write(1,CAPS)
    sys.exit(0)
if sys.argv[1:]==['gc','--help']:
    print('Usage: kiln gc [ID]...')
    sys.exit(0)
fds={{a.split('=')[0]:int(a.split('=')[1]) for a in sys.argv[2:7]}}
STATUS=fds['--status-fd']; IN=fds['--stdin-fd']; OUT=fds['--stdout-fd']; ERR=fds['--stderr-fd']
{body}
"#)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
