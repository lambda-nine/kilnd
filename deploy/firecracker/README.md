# Pinned Firecracker jailer patch (`kilnd-handoff1`)

`jailer-v1.17.0-kilnd-handoff1.patch` is the reviewed patch to the Firecracker **v1.17.0**
jailer that [phase1b-firecracker.md](../../docs/design/phase1b-firecracker.md) sections 3.4
and 6.2 ("Pinned jailer patch prerequisite") require. The stock jailer copies `--exec-file`
into the jail by path and drops privileges with `Command::uid/gid` only. That leaves the
bounding set full and exec goes through a pathname. The patch replaces both with a
descriptor handoff from kilnd's supervisor S, a bootstrap gate, and an explicit, verified
capability drop. Only the jailer changes: the official release `firecracker` binary runs
unmodified. `--version` prints `Jailer v1.17.0-kilnd-handoff1`.

## Protocol

S runs J with `execveat(jailer_fd, "", argv, [], AT_EMPTY_PATH)` and the contract argv
(`--id fc-<32hex> --exec-file /opt/kilnd/exec/sha256/<64hex>/firecracker --uid U --gid G
--chroot-base-dir /var/lib/kilnd-helper/jails --cgroup-version 2 --parent-cgroup … --new-pid-ns
--resource-limit no-file=256 -- --no-api --config-file /config.json`). Only stdio, FD 3 (the
verified VMM, `O_RDONLY`) and FD 4 (an AF_UNIX `SOCK_STREAM` socket to S) are inherited.

1. **Descriptors.** `close_range(5, UINT_MAX, 0)`. FD 3 must be a regular file opened
   `O_RDONLY` (not `O_PATH`). FD 4 must be an AF_UNIX `SOCK_STREAM` socket. Both are then set
   `FD_CLOEXEC`, and the environment is cleared. `--help` and `--version` are answered before
   the FD 3/4 checks.
2. **Contract argv.** `--daemonize`, `--netns`, any `--cgroup`, and a missing `--new-pid-ns`
   are refused. `--exec-file` is only a label: it must be an absolute UTF-8 path with no
   empty, `.` or `..` components. It is never canonicalized, stat'ed or opened. The chroot
   dir is the lexical `<chroot-base-dir>/<basename>/<id>/root`, and `Env` uses the same path.
3. **Record.** S sends a 4-byte big-endian length L (1 to 4096), then L bytes of canonical
   JSON (sorted keys, no whitespace):
   `{"exec_file_label":…,"jail_root_identity":{"mount_id":…,"st_dev":…,"st_ino":…},"plan_generation":…,"version":1,"vmm_identity":{"bytes":…,"sha256":"<64 lowercase hex>","st_dev":…,"st_ino":…}}`.
   J parses with `deny_unknown_fields` and requires `serde_json::to_vec(parsed) == raw`.
4. **Validation.**
   - `fstat(3)` must match `vmm_identity`: S_IFREG, dev, ino and size.
   - The SHA-256 of FD 3 (read with `pread` from offset 0) must equal `vmm_identity.sha256`.
   - `exec_file_label` must equal `--exec-file` byte for byte.
   - `statx(AT_SYMLINK_NOFOLLOW, STATX_INO|STATX_MNT_ID)` on the jail root must match
     `jail_root_identity`: dev, ino and `stx_mnt_id`. That mount ID is the one in the first
     column of `/proc/self/mountinfo`, not `STATX_MNT_ID_UNIQUE`.
   - `<root>/<basename>` must be FD 3's inode on a read-only mount (`statvfs` `ST_RDONLY`).
5. **Gate.** J writes `RDY1` and reads exactly 4 bytes. Only `CONT` continues; EOF or anything
   else refuses. No setup happens before this point: no cgroup join, rlimits, mknod or chroot.
6. **Setup** is upstream `Env::run` minus `copy_exec_to_chroot`. J writes the PID file
   `/<basename>.pid` inside the jail.
7. **V** (the `CLONE_NEWPID` child) keeps upstream's `setsid()`, resets SIGPIPE and the
   signal mask (as `Command::exec` did), then:
   1. `setgroups(0)`.
   2. Clears the ambient set and the inheritable set.
   3. Runs `PR_CAPBSET_DROP` for caps 0 to 63, stopping at EINVAL.
   4. `setresgid(G,G,G)`, then `setresuid(U,U,U)`.
   5. `capset` with all sets zero.
   6. Sets `PR_SET_NO_NEW_PRIVS`.
   7. Verifies all of the above: groups, res[ug]id, `capget`, the bounding set and the ambient
      set over the same range, and no_new_privs.
   8. Runs `execveat(3, "", argv, [], AT_EMPTY_PATH)`. The argv is upstream's, in the same
      order. There is no pathname exec and no fallback.

| Exit | Meaning |
|------|---------|
| 70 | J refused the bootstrap (steps 1–5); one line on stderr; no setup, no V |
| 71 | V failed to drop or verify a privilege; nothing was exec'd |
| 72 | V's `execveat(3)` returned |

## Build

Inside the kiln VM, as the normal user:

```sh
scripts/build-phase1b-tools.sh --out "$HOME/b4-build/out"
```

The script does the following:

- Verifies the source tarball and, before applying it, that the patch is the approved one
  (`PATCH_SHA256`). `--patch` can only name another copy of the same bytes; any other patch
  fails the build.
- Builds `cargo build --locked --release -p jailer --target aarch64-unknown-linux-musl` with
  toolchain 1.97.0, using fixed paths and `--remap-path-prefix`, so the digest doesn't depend
  on OUT or `$HOME`.
- Builds a static, stripped `mkfs.xfs` 6.6.0 against a private sysroot unpacked from the six
  exact debs in [`mkfs-sysroot.lock`](mkfs-sysroot.lock). Each is fetched by its pool file
  name from Launchpad's primary-archive file store
  (`https://launchpad.net/ubuntu/+archive/primary/+files/<file>`), which keeps every
  published version, and must match its SHA-256. Nothing comes from `apt-get` or the host's
  package indexes. (snapshot.ubuntu.com answers 401 for `ubuntu-ports`, so it can't serve
  arm64.)
- Downloads, verifies, builds and stages everything in a private `mktemp -d` directory, mode
  0700, removed on exit. Nothing but the two outputs is written under OUT.
- Checks that both outputs are static (no `PT_INTERP`, no `DT_NEEDED`) and that each staged
  copy equals its approved digest (`JAILER_SHA256`, `MKFS_SHA256`). It then publishes each
  with a rename inside OUT and hashes the *published* name: that comparison, after
  publishing, is the gate. A mismatch removes the published output and exits non-zero, and a
  final comparison of both published names must pass before the build reports success.
- Trusts the build UID and every process running as it (shell, cargo, rustup, compilers,
  PATH): mode 0700 keeps other users out of the private directory, not that UID. An output
  replaced before its post-publish comparison fails the build; one replaced in OUT after the
  script exits is outside its promise, so installers compare digests again.
  `scripts/build-phase1b-tools-swap-check.sh` replaces the staged jailer after its first hash
  and passes only if the build fails at the post-publish gate and no jailer is left in OUT.

The script never uses sudo. Changing any approved digest is a reviewed edit of the script
and this table.

Approved digests, first from 2026-11-02 (built twice from different `--out` directories
with identical results) and reproduced on 2026-11-02 from the pinned sysroot, so pinning
did not change them:

| Artifact | SHA-256 |
|----------|---------|
| `jailer-v1.17.0-kilnd-handoff1.patch` | `e54547ff520a91a25f4b292f450163f972505a383374f23b099a4f4414b0ff5d` |
| source `firecracker v1.17.0.tar.gz` | `1f61367c07266dc9caa5135d655ba532a3d6a994b9320eec85de5efcbd8a759f` |
| `jailer` | `42e9dea3ed1b94292464c9af0286ea0eaf09934ac0b92b439fc3e76b55e8ad11` |
| source `xfsprogs-6.6.0.tar.xz` | `50ca2f4676df8fab4cb4c3ef3dd512d5551e6844d40a65a31d5b8e03593d22df` |
| `mkfs.xfs` | `9571cecc3e015742c19d1e762fb4389b15f7ff0746f52af55fd2879c96e160ab` |

The sysroot is util-linux 2.39.3-9ubuntu6.6 (`uuid-dev`, `libblkid-dev`), liburcu
0.14.0-3.1build1 (`liburcu-dev`, `liburcu8t64`) and libinih 55-1ubuntu2 (`libinih-dev`,
`libinih1`), each hashed in the lock. The compilers stay the host's: Rust 1.97.0 from the
tree's `rust-toolchain.toml` and the Ubuntu noble gcc. A different gcc that changes the
output is caught by the `mkfs.xfs` digest check rather than producing another binary.

`mkfs.xfs` is built with `--disable-blkid`, which has two consequences:

- It always refuses to run without `-f`, because upstream's no-blkid `check_overwrite`
  returns 1 unconditionally.
- It doesn't probe device topology; sector sizes default to 512.

## Verification (2026-11-02)

- `cargo test -p jailer`, run as the normal user, passes 37/42. The 5 failures need root:
  mknod, chown, `/dev/kvm`, setrlimit, and writing under `/`.
- The same tests run as root pass 41/42. The remaining failure, `test_copy_cache_info`,
  happens because this Lima vCPU exposes only 3 of the 6 cache sysfs files.
- New unit tests cover:
  - SHA-256 known answers, including the 1,000,000 × `a` vector;
  - canonical-record rejection;
  - length framing and the gate;
  - label and chroot path rules;
  - `pread` hashing;
  - the `statx` layout.
- A root harness plays S, using a tmpfs jail root and read-only binds from `/proc/self/fd`,
  and boots the bundle-a guest as UID 300123 / GID 300456. V's `/proc/<pid>/status` showed:
  - `Uid` and `Gid` set to U/G and G in all four fields;
  - an empty `Groups:`;
  - `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` all `0000000000000000`;
  - `NoNewPrivs: 1` and `Seccomp: 2`.

  `/proc/<V>/exe` was FD 3's inode, and V held no VMM or bootstrap-socket descriptor.
- The harness negative cases each exited 70 with no V: wrong digest, wrong label, a writable
  `/firecracker` bind, EOF at the gate, and a wrong gate answer. An extra inherited FD 5 was
  closed, and the launch succeeded. A non-executable FD 3 exited 72.
