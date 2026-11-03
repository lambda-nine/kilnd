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
export CARGO_TARGET_DIR=${B4_TARGET_DIR:-$HOME/.cache/kilnd-target-static}
export RUSTFLAGS="-C target-feature=+crt-static"
target=aarch64-unknown-linux-gnu

# kilnd's library tests, and since Phase 1b B5 the direct-kiln core's, which hold the
# moved capability-drop regression (process::tests).
built=$(cargo test --locked -p kilnd -p kilnd-exec-core --lib --no-run --target "$target" \
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
    "$work/kilnd-lib-tests" --ignored --test-threads=1 --nocapture "$filter"
sudo setpriv --bounding-set="$caps" --inh-caps=-all \
    env RUST_BACKTRACE=${RUST_BACKTRACE:-1} \
    "$work/kilnd-exec-core-tests" --ignored --test-threads=1 --nocapture "$filter"
