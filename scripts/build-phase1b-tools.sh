#!/bin/sh
# Builds the two Phase 1b host tools inside the kiln Lima VM (aarch64 Ubuntu), as the normal
# user, never with sudo:
#   OUT/jailer    Firecracker v1.17.0 jailer + deploy/firecracker/jailer-v1.17.0-kilnd-handoff1.patch
#                 (static musl ELF)
#   OUT/mkfs.xfs  xfsprogs 6.6.0 mkfs.xfs, static glibc ELF, stripped
# Every input is SHA-256 pinned: both source archives, the jailer patch (also when --patch
# names another copy of it) and every deb of the mkfs sysroot (deploy/firecracker/
# mkfs-sysroot.lock). Everything is downloaded, verified, built and staged in a private
# mktemp directory (mode 0700) that is removed on exit. Each output is published into OUT
# (default $HOME/b4-build/out) with a rename inside OUT, and then the published name is
# hashed and compared with its approved digest below: that comparison, after publishing,
# is the gate. A mismatch removes the published output and fails the build, and a final
# comparison of both published names must pass before the build succeeds. cargo's crate
# cache stays in CARGO_HOME. See deploy/firecracker/README.md.
#
# Trust: the build UID and every process running as it (its shell, cargo, rustup, the
# compilers, PATH) are trusted; mode 0700 keeps other non-root users out of the private
# directory, not that UID. The gate catches an output replaced at any point before its
# post-publish comparison; one replaced in OUT after the build has exited is outside what
# this script can promise, so installers compare the digest again (scripts/b4-vm-tests.sh
# and the production catalog both do).
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
# The approved patch and outputs. A change to any of them is a reviewed edit here and in
# deploy/firecracker/README.md, never a silently different root executable.
PATCH_SHA256=e54547ff520a91a25f4b292f450163f972505a383374f23b099a4f4414b0ff5d
JAILER_SHA256=42e9dea3ed1b94292464c9af0286ea0eaf09934ac0b92b439fc3e76b55e8ad11
MKFS_SHA256=9571cecc3e015742c19d1e762fb4389b15f7ff0746f52af55fd2879c96e160ab
DEB_BASE_URL="https://launchpad.net/ubuntu/+archive/primary/+files"

script_dir=$(cd "$(dirname "$0")" && pwd)
OUT="$HOME/b4-build/out"
PATCH="$script_dir/../deploy/firecracker/jailer-v${FC_VERSION}-kilnd-handoff1.patch"
SYSROOT_LOCK="$script_dir/../deploy/firecracker/mkfs-sysroot.lock"

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
for tool in curl sha256sum tar xz patch cargo rustup file readelf strip make gcc dpkg-deb; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool"
done
[ -f "$PATCH" ] || die "patch not found: $PATCH"
[ -f "$SYSROOT_LOCK" ] || die "sysroot lock not found: $SYSROOT_LOCK"

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PATCH=$(cd "$(dirname "$PATCH")" && pwd)/$(basename "$PATCH")

# The private build directory: mode 0700, owned by this user, removed on any exit.
work=$(mktemp -d "${TMPDIR:-/tmp}/b4-tools.XXXXXX")
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
chmod 0700 "$work"
[ "$(stat -c '%u %a' "$work")" = "$(id -u) 700" ] || die "private build directory is not 0700 and ours"

# fetch URL FILE SHA256: download once, always verify.
fetch() {
    if [ ! -f "$2" ]; then
        curl -fsSL --retry 3 -o "$2.part" "$1"
        mv "$2.part" "$2"
    fi
    echo "$3  $2" | sha256sum -c --quiet - || die "SHA-256 mismatch for $2"
}

# require_sha FILE SHA256 WHAT: the file is exactly the approved one.
require_sha() {
    actual=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$actual" = "$2" ] || die "$3 SHA-256 is $actual, not the approved $2"
}

# publish STAGED NAME SHA256: checks the private staged file, renames a copy into OUT
# under its final name, then hashes the published name. A mismatch there removes it and
# fails the build: the post-publish comparison is the gate.
publish() {
    require_sha "$1" "$3" "staged $2"
    rm -f "$OUT/$2"
    incoming=$(mktemp "$OUT/.$2.XXXXXX")
    cp "$1" "$incoming"
    chmod 0755 "$incoming"
    mv -f "$incoming" "$OUT/$2"
    published=$(sha256sum "$OUT/$2" | cut -d' ' -f1)
    if [ "$published" != "$3" ]; then
        rm -f "$OUT/$2"
        die "published $2 SHA-256 is $published, not the approved $3; removed it"
    fi
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

downloads="$work/downloads"
mkdir -p "$downloads" "$work/stage"

# --- jailer ------------------------------------------------------------------------------
echo "==> jailer v${FC_VERSION} + kilnd-handoff1"
fetch "$FC_URL" "$downloads/firecracker-v${FC_VERSION}.tar.gz" "$FC_SHA256"

# Paths remapped below, so the binary's digest does not depend on where it was built.
fc_src="$work/src/firecracker-${FC_VERSION}"
mkdir -p "$work/src"
tar -xzf "$downloads/firecracker-v${FC_VERSION}.tar.gz" -C "$work/src"
[ -d "$fc_src" ] || die "unexpected tarball layout"
# The approved patch only, whichever path names it.
require_sha "$PATCH" "$PATCH_SHA256" "patch $PATCH"
(cd "$fc_src" && patch -p1 --forward --batch --quiet <"$PATCH") || die "patch does not apply"

# Inside the tree, rust-toolchain.toml selects the pinned toolchain (1.97.0).
(cd "$fc_src" && rustup target add "$FC_TARGET" >/dev/null)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
# RUSTFLAGS replaces the tree's build.rustflags, so repeat its -Ccodegen-units=1.
(
    cd "$fc_src"
    CARGO_TARGET_DIR="$work/cargo-target" \
    RUSTFLAGS="-Ccodegen-units=1 --remap-path-prefix=$fc_src=/firecracker --remap-path-prefix=$cargo_home=/cargo" \
        cargo build --locked --release -p jailer --target "$FC_TARGET"
)
jailer_bin="$work/cargo-target/$FC_TARGET/release/jailer"
require_static "$jailer_bin"
[ "$("$jailer_bin" --version | head -n 1)" = "$JAILER_VERSION_LINE" ] \
    || die "jailer --version is not '$JAILER_VERSION_LINE'"
cp "$jailer_bin" "$work/stage/jailer"
publish "$work/stage/jailer" jailer "$JAILER_SHA256"

# --- mkfs.xfs ----------------------------------------------------------------------------
echo "==> mkfs.xfs ${XFS_VERSION} (static)"
fetch "$XFS_URL" "$downloads/xfsprogs-${XFS_VERSION}.tar.xz" "$XFS_SHA256"

xfs_dir="$work/xfs"
mkdir -p "$xfs_dir/sysroot"
# Headers and static libraries come from the exact distribution debs in the lock, each
# verified, unpacked into a private sysroot; nothing is installed on the host.
deb_count=0
while read -r deb_sha deb_file rest; do
    case "$deb_sha" in ''|'#'*) continue ;; esac
    [ -z "$rest" ] || die "malformed sysroot lock line: $deb_sha $deb_file $rest"
    case "$deb_file" in
        *_arm64.deb) ;;
        *) die "sysroot lock names a non-arm64 deb: $deb_file" ;;
    esac
    case "$deb_file" in */*|.*) die "sysroot lock file name is not a plain name: $deb_file" ;; esac
    fetch "$DEB_BASE_URL/$deb_file" "$downloads/$deb_file" "$deb_sha"
    dpkg-deb -x "$downloads/$deb_file" "$xfs_dir/sysroot"
    deb_count=$((deb_count + 1))
done <"$SYSROOT_LOCK"
[ "$deb_count" -eq 6 ] || die "sysroot lock names $deb_count debs, not 6"
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
        || { tail -n 40 "$xfs_dir/configure.log" >&2; die "configure failed"; }
    make -j4 LLDFLAGS=-all-static >"$xfs_dir/make.log" 2>&1 \
        || { tail -n 40 "$xfs_dir/make.log" >&2; die "make failed"; }
)
mkfs_bin="$xfs_dir/xfsprogs-${XFS_VERSION}/mkfs/mkfs.xfs"
strip "$mkfs_bin"
require_static "$mkfs_bin"
"$mkfs_bin" -V | grep -qx "mkfs.xfs version ${XFS_VERSION}" || die "mkfs.xfs -V is not ${XFS_VERSION}"
cp "$mkfs_bin" "$work/stage/mkfs.xfs"
publish "$work/stage/mkfs.xfs" mkfs.xfs "$MKFS_SHA256"

# The final gate: both published names, again, compared rather than printed.
status=0
for pair in "jailer $JAILER_SHA256" "mkfs.xfs $MKFS_SHA256"; do
    set -- $pair
    actual=$(sha256sum "$OUT/$1" | cut -d' ' -f1)
    if [ "$actual" != "$2" ]; then
        rm -f "$OUT/$1"
        echo "build-phase1b-tools: published $1 SHA-256 is $actual, not the approved $2; removed it" >&2
        status=1
    fi
done
[ "$status" -eq 0 ] || exit 1
echo "==> done: both published outputs equal their approved digests"
echo "$JAILER_SHA256  jailer"
echo "$MKFS_SHA256  mkfs.xfs"
