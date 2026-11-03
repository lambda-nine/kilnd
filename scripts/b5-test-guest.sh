#!/bin/sh
# Builds B5-04's kill-inner test guest from a production kiln-guest bundle, for
# `b5_linux_root_a_killed_inner_sandbox_is_never_ready`. Run in the kiln Lima VM as your
# user (sudo keeps the root filesystem's ownership):
#   scripts/b5-test-guest.sh BUNDLE OUT
# OUT receives Image (unchanged), rootfs.squashfs (the broker renamed to
# kilnd-guest-broker.real behind the static wrapper in scripts/b5-test-guest/kill-inner.c)
# and kilnd-guest-broker (the wrapper, which the test's manifest pins: the broker hashes
# the binary at its own path, so the pin and HelloReply agree). Then:
#   KILND_B5_KILL_INNER_GUEST=OUT scripts/b4-vm-tests.sh b5_linux_root
# Test guests only: never a product image.
set -eu
bundle=$1
out=$2
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/b5-guest.XXXXXX)
trap 'sudo rm -rf "$work"' EXIT INT TERM
gcc -static -O2 -Wall -Werror -o "$work/kilnd-guest-broker" "$here/b5-test-guest/kill-inner.c"
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
