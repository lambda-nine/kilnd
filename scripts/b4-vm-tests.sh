#!/bin/sh
# Phase 1b B4's privileged regressions against the real jailer/Firecracker chain. Run in
# the kiln Lima VM as your user (it uses sudo for the test binary), under the shared VM
# lock, after scripts/build-phase1b-tools.sh:
#   scripts/b4-vm-tests.sh [TEST-NAME-FILTER]
# Inputs (override by environment):
#   B4_TOOLS   jailer + mkfs.xfs from build-phase1b-tools.sh   ($HOME/b4-build/out)
#   B4_VMM     the release Firecracker v1.17.0 aarch64 binary
#   KILND_B5_KILL_INNER_GUEST, KILND_B5_CONSOLE_FLOOD_GUEST  B5's test guests from
#              scripts/b5-test-guest.sh, for the two b5_linux_root tests that need them
#   B4_GUEST   a kiln-guest bundle directory with Image, rootfs.squashfs and
#              kilnd-guest-broker (the B5 production bundle; earlier: the schema-1
#              guest, which listens for no command, so a boot ends at BOOTING
#   KILND_B7_CYCLES  sessions b7_linux_root_compaction_cycles runs (default 300)
#   B6_EVIDENCE  where b6_linux_root writes its transcript and SQLite/journal evidence
#              (default: none). B6's session test also runs the kilnd and kilndctl
#              binaries, built here as ordinary dynamic executables in their own
#              target directory ($HOME/.cache/kilnd-target-b6). kilnd is built with the
#              non-default firecracker-test-deployment feature, without which it has no
#              Firecracker flags (B6-BI-01); release and installed builds never enable it
# The test binary is built static (crt-static) because it is installed as the helper
# image and the contract approves static ELFs only. Everything the tests create under
# /opt/kilnd, /var/lib/kilnd-helper/{jails,work} and /sys/fs/cgroup/kilnd-firecracker is
# removed afterwards, and the script fails if anything owned is left behind.
set -eu
cd "$(dirname "$0")/.."
filter=${1:-b4_linux_root}
tools=${B4_TOOLS:-$HOME/b4-build/out}
vmm=${B4_VMM:-$HOME/fc-spike/release-v1.17.0-aarch64/firecracker-v1.17.0-aarch64}
guest=${B4_GUEST:-$HOME/kiln-guest-build/bundle-a}
target=aarch64-unknown-linux-gnu

# B6: the daemon and client the session test runs as an ordinary installed kilnd would
# be, before the static flags below apply to anything.
bins=${B6_TARGET_DIR:-$HOME/.cache/kilnd-target-b6}
CARGO_TARGET_DIR=$bins scripts/build.sh firecracker-test-deployment build --release \
    -p kilnd -p kilndctl --bin kilnd --bin kilndctl

export CARGO_TARGET_DIR=${B4_TARGET_DIR:-$HOME/.cache/kilnd-target-static}
export RUSTFLAGS="-C target-feature=+crt-static"

# kilnd's library tests, and since Phase 1b B5 the direct-kiln core's, which hold the
# moved capability-drop regression (process::tests).
# Dependencies are optimized (kilnd itself stays a debug build with its overflow checks):
# a real helper hashes its own image and parses the bundle's 33 MB manifest at start and
# in every Preflight, which unoptimized sha2 and serde_json made slower than the wire
# deadlines on a loaded host. The workspace Cargo.toml's `vm-test` profile is `dev` with
# every dependency at opt-level 2.
built=$(scripts/build.sh default test -p kilnd -p kilnd-exec-core --lib --no-run --target "$target" \
    --profile vm-test \
    --message-format=json \
    | python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] in ("kilnd", "kilnd_exec_core") and m["profile"]["test"]:
        print(m["target"]["name"], m["executable"])
')
lib=$(printf '%s\n' "$built" | awk '$1 == "kilnd" { print $2 }')
core=$(printf '%s\n' "$built" | awk '$1 == "kilnd_exec_core" { print $2 }')
[ -n "$lib" ] && [ -n "$core" ] || { echo "library test binaries not found" >&2; exit 1; }

work=$(mktemp -d /tmp/b4-tests.XXXXXX)
cleanup() {
    status=$?
    sudo python3 -I scripts/b4-vm-cleanup.py || status=1
    sudo rm -rf "$work"
    exit $status
}
trap cleanup EXIT INT TERM

# Root-owned inputs: the tests install from these, never from a user-writable path.
sudo install -d -m 0755 -o root -g root "$work/artifacts"
sudo install -m 0555 -o root -g root "$tools/jailer" "$work/artifacts/jailer"
sudo install -m 0555 -o root -g root "$tools/mkfs.xfs" "$work/artifacts/mkfs.xfs"
sudo install -m 0555 -o root -g root "$vmm" "$work/artifacts/firecracker"
sudo install -m 0444 -o root -g root "$guest/Image" "$work/artifacts/Image"
sudo install -m 0444 -o root -g root "$guest/rootfs.squashfs" "$work/artifacts/rootfs.squashfs"
# Since B5-10 the host checks the broker's digest against the manifest's pin: the
# bundle's own broker artifact, which its root runs.
sudo install -m 0444 -o root -g root "$guest/kilnd-guest-broker" "$work/artifacts/kilnd-guest-broker"
# B6's daemon and client: root-owned copies the test installs and enrolls from.
sudo install -d -m 0755 -o root -g root "$work/bin"
sudo install -m 0755 -o root -g root "$bins/release/kilnd" "$work/bin/kilnd"
sudo install -m 0755 -o root -g root "$bins/release/kilndctl" "$work/bin/kilndctl"
# A stripped static copy is the helper image: it is hashed at every helper start.
sudo install -m 0755 -o root -g root "$lib" "$work/kilnd-lib-tests"
sudo strip --strip-debug "$work/kilnd-lib-tests"
sudo install -m 0755 -o root -g root "$core" "$work/kilnd-exec-core-tests"
sudo chmod 0711 "$work"

# Exactly deploy/kilnd-helper.service's bounding set, from exec, for every thread: the
# helper fixture and S inherit it, so the chain is proven without CAP_SYS_PTRACE.
caps=-all,+chown,+dac_override,+fowner,+kill,+setgid,+setuid,+setpcap,+net_admin,+sys_chroot,+sys_admin,+mknod
sudo setpriv --bounding-set="$caps" --inh-caps=-all \
    env KILND_B4_ARTIFACTS="$work/artifacts" RUST_BACKTRACE=${RUST_BACKTRACE:-1} \
    KILND_B5_KILL_INNER_GUEST="${KILND_B5_KILL_INNER_GUEST:-}" \
    KILND_B5_CONSOLE_FLOOD_GUEST="${KILND_B5_CONSOLE_FLOOD_GUEST:-}" \
    KILND_B6_BIN="$work/bin" KILND_B6_EVIDENCE="${B6_EVIDENCE:-}" \
    KILND_B7_CYCLES="${KILND_B7_CYCLES:-}" \
    "$work/kilnd-lib-tests" --include-ignored --test-threads=1 --nocapture "$filter"
sudo setpriv --bounding-set="$caps" --inh-caps=-all \
    env RUST_BACKTRACE=${RUST_BACKTRACE:-1} \
    "$work/kilnd-exec-core-tests" --include-ignored --test-threads=1 --nocapture "$filter"
