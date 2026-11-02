#!/bin/sh
# Builds the two Phase 1b host tools inside the kiln Lima VM (aarch64 Ubuntu), as the normal
# user, never with sudo:
#   OUT/jailer    Firecracker v1.17.0 jailer + deploy/firecracker/jailer-v1.17.0-kilnd-handoff1.patch
#                 (static musl ELF)
#   OUT/mkfs.xfs  xfsprogs 6.6.0 mkfs.xfs, static glibc ELF, stripped
# Every download is SHA-256 pinned. Builds happen only under OUT (default $HOME/b4-build/out);
# cargo's crate cache stays in CARGO_HOME. See deploy/firecracker/README.md.
#
# Usage: scripts/build-phase1b-tools.sh [--out DIR] [--patch FILE]
set -eu

FC_VERSION=1.17.0
FC_URL="https://github.com/firecracker-microvm/firecracker/archive/refs/tags/v${FC_VERSION}.tar.gz"
FC_SHA256=1f61367c07266dc9caa5135d655ba532a3d6a994b9320eec85de5efcbd8a759f
FC_TARGET=aarch64-unknown-linux-musl
JAILER_VERSION_LINE="Jailer v${FC_VERSION}-kilnd-handoff1"

XFS_VERSION=6.6.0
XFS_URL="https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/xfsprogs/xfsprogs-${XFS_VERSION}.tar.xz"
XFS_SHA256=50ca2f4676df8fab4cb4c3ef3dd512d5551e6844d40a65a31d5b8e03593d22df
XFS_DEBS="uuid-dev liburcu-dev libinih-dev libblkid-dev libinih1 liburcu8t64"

script_dir=$(cd "$(dirname "$0")" && pwd)
OUT="$HOME/b4-build/out"
PATCH="$script_dir/../deploy/firecracker/jailer-v${FC_VERSION}-kilnd-handoff1.patch"

usage() {
    echo "usage: $0 [--out DIR] [--patch FILE]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) [ $# -ge 2 ] || usage; OUT=$2; shift 2 ;;
        --patch) [ $# -ge 2 ] || usage; PATCH=$2; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

die() {
    echo "build-phase1b-tools: $*" >&2
    exit 1
}

[ "$(id -u)" -ne 0 ] || die "run as the normal user, not root"
[ "$(uname -m)" = aarch64 ] || die "aarch64 Linux only (run inside the kiln VM)"
for tool in curl sha256sum tar xz patch cargo rustup file readelf strip make gcc apt-get dpkg-deb; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool"
done
[ -f "$PATCH" ] || die "patch not found: $PATCH"

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PATCH=$(cd "$(dirname "$PATCH")" && pwd)/$(basename "$PATCH")

# fetch URL FILE SHA256: download once, always verify.
fetch() {
    if [ ! -f "$2" ]; then
        curl -fsSL --retry 3 -o "$2.part" "$1"
        mv "$2.part" "$2"
    fi
    echo "$3  $2" | sha256sum -c --quiet - || die "SHA-256 mismatch for $2"
}

# require_static FILE: an ELF with no program interpreter and no dynamic section.
require_static() {
    file -b "$1" | grep -q 'statically linked' || die "$1 is not statically linked: $(file -b "$1")"
    if readelf -lW "$1" | grep -q 'INTERP'; then
        die "$1 has a PT_INTERP segment"
    fi
    if readelf -dW "$1" 2>/dev/null | grep -q 'NEEDED'; then
        die "$1 has DT_NEEDED entries"
    fi
}

downloads="$OUT/downloads"
mkdir -p "$downloads"

# --- jailer ------------------------------------------------------------------------------
echo "==> jailer v${FC_VERSION} + kilnd-handoff1"
fetch "$FC_URL" "$downloads/firecracker-v${FC_VERSION}.tar.gz" "$FC_SHA256"

# Fixed paths, remapped below, so the binary's digest does not depend on OUT or $HOME.
fc_src="$OUT/src/firecracker-${FC_VERSION}"
rm -rf "$OUT/src"
mkdir -p "$OUT/src"
tar -xzf "$downloads/firecracker-v${FC_VERSION}.tar.gz" -C "$OUT/src"
[ -d "$fc_src" ] || die "unexpected tarball layout"
(cd "$fc_src" && patch -p1 --forward --batch --quiet <"$PATCH") || die "patch does not apply"

# Inside the tree, rust-toolchain.toml selects the pinned toolchain (1.97.0).
(cd "$fc_src" && rustup target add "$FC_TARGET" >/dev/null)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
# RUSTFLAGS replaces the tree's build.rustflags, so repeat its -Ccodegen-units=1.
(
    cd "$fc_src"
    CARGO_TARGET_DIR="$OUT/cargo-target" \
    RUSTFLAGS="-Ccodegen-units=1 --remap-path-prefix=$fc_src=/firecracker --remap-path-prefix=$cargo_home=/cargo" \
        cargo build --locked --release -p jailer --target "$FC_TARGET"
)
jailer_bin="$OUT/cargo-target/$FC_TARGET/release/jailer"
require_static "$jailer_bin"
[ "$("$jailer_bin" --version | head -n 1)" = "$JAILER_VERSION_LINE" ] \
    || die "jailer --version is not '$JAILER_VERSION_LINE'"
cp "$jailer_bin" "$OUT/jailer.tmp"
mv "$OUT/jailer.tmp" "$OUT/jailer"

# --- mkfs.xfs ----------------------------------------------------------------------------
echo "==> mkfs.xfs ${XFS_VERSION} (static)"
fetch "$XFS_URL" "$downloads/xfsprogs-${XFS_VERSION}.tar.xz" "$XFS_SHA256"

xfs_dir="$OUT/xfs"
rm -rf "$xfs_dir"
mkdir -p "$xfs_dir/debs" "$xfs_dir/sysroot"
# Headers and static libraries come from the distribution's packages, unpacked into a private
# sysroot; nothing is installed on the host.
# shellcheck disable=SC2086 # XFS_DEBS is a word list
(cd "$xfs_dir/debs" && apt-get download $XFS_DEBS)
for deb in "$xfs_dir"/debs/*.deb; do
    dpkg-deb -x "$deb" "$xfs_dir/sysroot"
done
sysroot="$xfs_dir/sysroot"
tar -xJf "$downloads/xfsprogs-${XFS_VERSION}.tar.xz" -C "$xfs_dir"
(
    cd "$xfs_dir/xfsprogs-${XFS_VERSION}"
    inc="-I$sysroot/usr/include -I$sysroot/usr/include/aarch64-linux-gnu"
    # The prefix map keeps OUT out of the debug info the GNU build-id is hashed over, so the
    # stripped binary's digest does not depend on OUT.
    CPPFLAGS="$inc" CFLAGS="-O2 -ffile-prefix-map=$xfs_dir=/xfs $inc" LDFLAGS="-L$sysroot/usr/lib/aarch64-linux-gnu" \
        ./configure --enable-static=yes --enable-shared=no --disable-gettext --disable-blkid \
        --disable-editline --disable-libicu --disable-scrub --disable-lto >"$xfs_dir/configure.log" 2>&1 \
        || die "configure failed; see $xfs_dir/configure.log"
    make -j4 LLDFLAGS=-all-static >"$xfs_dir/make.log" 2>&1 || die "make failed; see $xfs_dir/make.log"
)
mkfs_bin="$xfs_dir/xfsprogs-${XFS_VERSION}/mkfs/mkfs.xfs"
strip "$mkfs_bin"
require_static "$mkfs_bin"
"$mkfs_bin" -V | grep -qx "mkfs.xfs version ${XFS_VERSION}" || die "mkfs.xfs -V is not ${XFS_VERSION}"
cp "$mkfs_bin" "$OUT/mkfs.xfs.tmp"
mv "$OUT/mkfs.xfs.tmp" "$OUT/mkfs.xfs"

echo "==> done"
(cd "$OUT" && sha256sum jailer mkfs.xfs)
