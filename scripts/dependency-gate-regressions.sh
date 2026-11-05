#!/bin/sh
# B7 milestone 2 break-it regressions for design section 7.1's dependency gate, on the
# real crates and the real clippy (the gate's own synthetic tests run under cargo test).
#
#   scripts/dependency-gate-regressions.sh [TOOLCHAIN...]
#
# In a disposable copy of HEAD (this checkout is never touched):
#
# 1. HIGH-1, Daybreak's fs-err PoC: kilnd gains the ordinary `fs-err` dependency and a
#    production call to fs_err::remove_dir_all.
#    a. Reviewed as `none` (Daybreak's declaration): the gate test fails, naming the
#       production call and fs-err's own source.
#    b. Reviewed honestly as `filesystem`, its destructive paths listed and disallowed:
#       the gate test passes, and clippy rejects the call on every toolchain.
# 2. MEDIUM-1, Daybreak's missing-methods PoC: std::fs::copy and libc::creat (exact
#    libc 0.2.190) against this clippy.toml: clippy rejects both.
#
# Default toolchains: 1.88.0 and 1.99.0. It resolves fs-err from the registry (the
# network, or cargo's cache), so it is not part of the offline checks.
set -eu

toolchains=${*:-1.88.0 1.99.0}
repo=$(git -C "$(dirname -- "$0")" rev-parse --show-toplevel)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/kilnd-gate-regressions.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
work=$scratch/kilnd
mkdir "$work"
git -C "$repo" archive HEAD | tar -x -C "$work"
export CARGO_TARGET_DIR="$scratch/target"
first=$(echo "$toolchains" | awk '{print $1}')
failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=1
}

# --- 1. fs-err -----------------------------------------------------------------------
cd "$work"
python3 -I - <<'EOF'
import re
root = open("Cargo.toml").read()
root = root.replace('clap = {', 'fs-err = "=3.3.2"\nclap = {', 1)
open("Cargo.toml", "w").write(root)
kilnd = open("crates/kilnd/Cargo.toml").read()
kilnd = kilnd.replace("clap.workspace = true\n", "clap.workspace = true\nfs-err.workspace = true\n", 1)
open("crates/kilnd/Cargo.toml", "w").write(kilnd)
lib = open("crates/kilnd/src/lib.rs").read()
lib = lib.replace("pub mod admission;\n", "pub mod admission;\npub mod gate_bypass_poc;\n", 1)
open("crates/kilnd/src/lib.rs", "w").write(lib)
open("crates/kilnd/src/gate_bypass_poc.rs", "w").write(
    "//! Daybreak's honest-looking wrapper call (B7 milestone 2 HIGH-1).\n\n"
    "use std::path::Path;\n\n"
    "/// Removes a caller-selected tree.\n"
    "pub fn remove_tree(path: &Path) -> std::io::Result<()> {\n"
    "    fs_err::remove_dir_all(path)\n"
    "}\n")
EOF
# Resolve fs-err into the disposable lockfile, then freeze it.
cargo "+$first" update -q -p fs-err --precise 3.3.2 2>/dev/null || cargo "+$first" check -q -p kilnd

set_entry() {
    python3 -I - "$1" <<'EOF'
import json, sys
gate = json.load(open("dependency-gate.json"))
entries = {
    "none": {"kind": "runtime", "capability": "none",
             "why": "std::fs wrappers with path-rich errors"},
    "filesystem": {"kind": "runtime", "capability": "filesystem",
                   "destructive": ["fs_err::remove_dir_all", "fs_err::remove_dir",
                                   "fs_err::remove_file", "fs_err::rename",
                                   "fs_err::copy", "fs_err::write",
                                   "fs_err::File::create", "fs_err::File::set_len"],
                   "why": "std::fs wrappers with path-rich errors"},
}
gate["dependencies"]["fs-err"] = entries[sys.argv[1]]
json.dump(gate, open("dependency-gate.json", "w"), indent=2)
clippy = open("clippy.toml").read()
if sys.argv[1] == "filesystem" and "fs_err::" not in clippy:
    lines = "".join(
        '  { path = "%s", reason = "fs-err wraps std::fs (design 7.1)" },\n' % p
        for p in entries["filesystem"]["destructive"])
    clippy = clippy.rstrip()[:-1] + lines + "]\n"
    open("clippy.toml", "w").write(clippy)
EOF
}

gate_test() {
    cargo "+$1" test --locked -q -p kilnd --lib \
        helper::firecracker::proven::tests::dependency_gate -- --test-threads=1 >"$scratch/gate.log" 2>&1
}

set_entry none
for toolchain in $toolchains; do
    echo "== Rust $toolchain: fs-err reviewed as none =="
    if gate_test "$toolchain"; then
        fail "the gate accepted fs-err as none"
    elif grep -q "production names fs_err::remove_dir_all" "$scratch/gate.log" &&
        grep "fs-err is declared \`none\`, but its locked source reaches" "$scratch/gate.log" |
        grep -q "std::fs::remove_dir_all (fs-err"; then
        echo "refused: the production call and fs-err's own source"
    else
        cat "$scratch/gate.log" >&2
        fail "the gate failed for another reason"
    fi
done

set_entry filesystem
for toolchain in $toolchains; do
    echo "== Rust $toolchain: fs-err reviewed as filesystem =="
    if gate_test "$toolchain"; then
        echo "the gate holds"
    else
        cat "$scratch/gate.log" >&2
        fail "the gate refused the honest declaration"
    fi
    if cargo "+$toolchain" clippy --locked -q -p kilnd --all-targets -- \
        -D warnings -D clippy::disallowed_methods >"$scratch/clippy.log" 2>&1; then
        fail "clippy accepted fs_err::remove_dir_all"
    elif grep -q "disallowed method \`fs_err::remove_dir_all\`" "$scratch/clippy.log"; then
        echo "clippy rejects fs_err::remove_dir_all"
    else
        cat "$scratch/clippy.log" >&2
        fail "clippy failed for another reason"
    fi
done

# --- 2. std::fs::copy and libc::creat ------------------------------------------------
fixture=$scratch/missing-methods
mkdir -p "$fixture/src"
cat >"$fixture/Cargo.toml" <<'EOF'
[package]
name = "b7m2-missing-methods"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
libc = "=0.2.190"

[workspace]
EOF
cat >"$fixture/src/main.rs" <<'EOF'
use std::ffi::CStr;
use std::path::Path;

fn overwrite_with_copy(source: &Path, target: &Path) -> std::io::Result<u64> {
    std::fs::copy(source, target)
}

fn truncate_with_creat(path: &CStr) -> i32 {
    // SAFETY: a NUL-terminated path; the fixture is never run.
    unsafe { libc::creat(path.as_ptr(), 0o600) }
}

fn main() {
    let _ = overwrite_with_copy as fn(&Path, &Path) -> std::io::Result<u64>;
    let _ = truncate_with_creat as fn(&CStr) -> i32;
}
EOF
for toolchain in $toolchains; do
    echo "== Rust $toolchain: std::fs::copy and libc::creat =="
    if CLIPPY_CONF_DIR="$repo" cargo "+$toolchain" clippy -q \
        --manifest-path "$fixture/Cargo.toml" -- \
        -D warnings -D clippy::disallowed_methods >"$scratch/missing.log" 2>&1; then
        fail "clippy accepted std::fs::copy and libc::creat"
    elif grep -q "disallowed method \`std::fs::copy\`" "$scratch/missing.log" &&
        grep -q "disallowed method \`libc::creat\`" "$scratch/missing.log"; then
        echo "clippy rejects both"
    else
        cat "$scratch/missing.log" >&2
        fail "clippy failed for another reason"
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "dependency gate regressions: FAILED" >&2
    exit 1
fi
echo "dependency gate regressions: all passed"
