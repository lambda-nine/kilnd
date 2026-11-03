#!/bin/sh
# Builds one of B5's test guests from a production kiln-guest bundle. Run in the kiln
# Lima VM as your user (sudo keeps the root filesystem's ownership):
#   scripts/b5-test-guest.sh kill-inner|console-flood BUNDLE OUT
# kill-inner is for b5_linux_root_a_killed_inner_sandbox_is_never_ready (B5-04),
# console-flood for b5_linux_root_a_real_guest_console_flood_keeps_the_drainer_flat.
# OUT receives Image (unchanged), rootfs.squashfs (the broker renamed to
# kilnd-guest-broker.real behind the static wrapper in scripts/b5-test-guest/wrapper.c)
# and kilnd-guest-broker (the wrapper, which the test's manifest pins: the broker hashes
# the binary at its own path, so the pin and HelloReply agree). Then:
#   KILND_B5_KILL_INNER_GUEST=OUT1 KILND_B5_CONSOLE_FLOOD_GUEST=OUT2 \
#       scripts/b4-vm-tests.sh b5_linux_root
# Test guests only: never a product image.
set -eu
case $1 in
    kill-inner) attack=B5_KILL_INNER ;;
    console-flood) attack=B5_CONSOLE_FLOOD ;;
    *) echo "unknown test guest $1" >&2; exit 2 ;;
esac
bundle=$2
out=$3
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/b5-guest.XXXXXX)
trap 'sudo rm -rf "$work"' EXIT INT TERM
gcc -static -O2 -Wall -Werror -D"$attack" -o "$work/kilnd-guest-broker" "$here/b5-test-guest/wrapper.c"
sudo unsquashfs -no-progress -d "$work/root" "$bundle/rootfs.squashfs" >/dev/null
bin="$work/root/usr/local/bin"
owner=$(sudo stat -c %u:%g "$bin/kilnd-guest-broker")
sudo mv "$bin/kilnd-guest-broker" "$bin/kilnd-guest-broker.real"
sudo install -m 0755 -o "${owner%:*}" -g "${owner#*:}" "$work/kilnd-guest-broker" "$bin/kilnd-guest-broker"
mkdir -p "$out"
sudo mksquashfs "$work/root" "$work/rootfs.squashfs" -noappend -comp gzip -no-xattrs \
    -no-exports -no-fragments -no-progress >/dev/null
sudo install -m 0444 "$work/rootfs.squashfs" "$out/rootfs.squashfs"
install -m 0444 "$bundle/Image" "$out/Image"
install -m 0555 "$work/kilnd-guest-broker" "$out/kilnd-guest-broker"
sha256sum "$out"/*
