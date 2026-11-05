#!/bin/sh
# B7 milestone 2 break-it and recheck regressions for design section 7.1's dependency
# gate, through the actual source loader (cargo metadata, Cargo.lock and each package's
# extracted source), cargo and clippy. The gate's synthetic tests run under cargo test.
#
#   scripts/dependency-gate-regressions.sh [TOOLCHAIN...]
#
# Every case runs in a disposable copy of HEAD (this checkout is never touched). The
# gate test binary is built once per toolchain from a pristine copy and pointed at each
# case's workspace with KILND_DEPENDENCY_GATE_ROOT, so the same loader reads it.
#
# 1. HIGH-1, Daybreak's fs-err PoC: kilnd gains the ordinary `fs-err` dependency and a
#    production call to fs_err::remove_dir_all.
#    a. Reviewed as `none`: the gate refuses, naming the production call and fs-err's
#       own source.
#    b. Reviewed honestly as `filesystem`, its destructive paths listed and disallowed:
#       the gate holds, and clippy rejects the call on every toolchain.
# 2. The HIGH-1 recheck, Daybreak's method and transitive wrappers
#    (reviews/poc-b7m2-recheck), as vendored registry packages with Cargo.lock checksums:
#    a. method-wrapper (an extension trait on std::fs::File whose method calls
#       set_len), reviewed `filesystem` with `no_destructive_api`: the gate refuses on
#       its `.set_len(`; clippy accepts the workspace (dependency bodies are not linted).
#    b. The same reviewed `none`: refused.
#    c. outer-wrapper (`none`) re-exporting the trait from inner-wrapper: refused, for
#       the unreviewed inner package and for the outer package's subtree `.set_len(`;
#       clippy accepts the workspace.
#    d. Case a with a reviewed exception for method-wrapper 1.0.0, no features: holds,
#       and clippy accepts.
#    e. Case d after a lock change bumping method-wrapper to 1.0.1: refused until 1.0.1
#       is reviewed (entry and exception), then holds.
#    f. Case d with method-wrapper's `extra` feature enabled: refused (the review and the
#       exception are scoped to no features).
# 3. MEDIUM-1, Daybreak's missing-methods PoC: std::fs::copy and libc::creat (exact
#    libc 0.2.190) against this clippy.toml: clippy rejects both.
#
# Default toolchains: 1.88.0 and 1.99.0. It resolves fs-err from the registry and
# vendors the locked crates (the network, or cargo's cache), so it is not part of the
# offline checks.
set -eu

toolchains=${*:-1.88.0 1.99.0}
repo=$(git -C "$(dirname -- "$0")" rev-parse --show-toplevel)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/kilnd-gate-regressions.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
# A caller may keep the build between runs with its own CARGO_TARGET_DIR.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch/target}"
first=$(echo "$toolchains" | awk '{print $1}')
failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=1
}
copy_head() {
    mkdir "$1"
    git -C "$repo" archive HEAD | tar -x -C "$1"
}

# The gate, from a pristine copy, against the workspace at $1. Output in $scratch/gate.log.
copy_head "$scratch/gate"
gate() {
    (cd "$scratch/gate" && KILND_DEPENDENCY_GATE_ROOT=$2 cargo "+$1" test --locked -q -p kilnd --lib \
        helper::firecracker::proven::tests::dependency_gate::the_dependency_gate_holds \
        -- --exact) >"$scratch/gate.log" 2>&1
}
expect_refused() { # toolchain root message...
    toolchain=$1 root=$2
    shift 2
    if gate "$toolchain" "$root"; then
        fail "the gate accepted it"
        return
    fi
    for message in "$@"; do
        if ! grep -qF -- "$message" "$scratch/gate.log"; then
            cat "$scratch/gate.log" >&2
            fail "the gate refused, but without: $message"
            return
        fi
    done
    echo "refused: $*"
}
expect_holds() { # toolchain root
    if gate "$1" "$2"; then
        echo "the gate holds"
    else
        cat "$scratch/gate.log" >&2
        fail "the gate refused it"
    fi
}
clippy_accepts() { # toolchain root
    if (cd "$2" && cargo "+$1" clippy --locked -q -p kilnd --all-targets -- \
        -D warnings -D clippy::disallowed_methods) >"$scratch/clippy.log" 2>&1; then
        echo "clippy accepts the workspace (it does not lint dependency bodies)"
    else
        cat "$scratch/clippy.log" >&2
        fail "clippy refused the fixture workspace"
    fi
}

# Draft entries for new packages, then give each named package its review.
review() { # root package=capability-json ...
    root=$1
    shift
    python3 -I "$root/scripts/dependency-gate-review.py" --write >/dev/null || true
    python3 -I - "$root/dependency-gate.json" "$@" <<'EOF'
import json, sys
path = sys.argv[1]
gate = json.load(open(path))
for spec in sys.argv[2:]:
    name, review = spec.split("=", 1)
    review = json.loads(review)
    for key, entry in gate["packages"].items():
        if key.split("@")[0] == name and not entry.get("why"):
            entry.update(review)
            entry.pop("group", None)
open(path, "w").write(json.dumps(gate, indent=2) + "\n")
EOF
}

# --- 1. fs-err -----------------------------------------------------------------------
work=$scratch/kilnd
copy_head "$work"
cd "$work"
python3 -I - <<'EOF'
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
cp dependency-gate.json "$scratch/gate-before-fs-err.json"
fs_err_none() {
    cp "$scratch/gate-before-fs-err.json" dependency-gate.json
    review "$work" \
        'fs-err={"capability": "none", "why": "std::fs wrappers with path-rich errors"}' \
        'autocfg={"capability": "none", "why": "fs-err build script: probes rustc"}'
}
fs_err_filesystem() {
    cp "$scratch/gate-before-fs-err.json" dependency-gate.json
    review "$work" \
        'fs-err={"capability": "filesystem", "destructive": ["fs_err::remove_dir_all", "fs_err::remove_dir", "fs_err::remove_file", "fs_err::rename", "fs_err::copy", "fs_err::write", "fs_err::File::create", "fs_err::File::set_len"], "why": "std::fs wrappers with path-rich errors"}' \
        'autocfg={"capability": "none", "why": "fs-err build script: probes rustc"}'
    python3 -I - <<'EOF'
clippy = open("clippy.toml").read()
if "fs_err::" not in clippy:
    lines = "".join(
        '  { path = "%s", reason = "fs-err wraps std::fs (design 7.1)" },\n' % p
        for p in ["fs_err::remove_dir_all", "fs_err::remove_dir", "fs_err::remove_file",
                  "fs_err::rename", "fs_err::copy", "fs_err::write", "fs_err::File::create",
                  "fs_err::File::set_len"])
    clippy = clippy.rstrip()[:-1] + lines + "]\n"
    open("clippy.toml", "w").write(clippy)
EOF
}

fs_err_none
for toolchain in $toolchains; do
    echo "== Rust $toolchain: fs-err reviewed as none =="
    expect_refused "$toolchain" "$work" \
        "production names fs_err::remove_dir_all" \
        "fs-err@3.3.2 is declared \`none\`, but its runtime subtree reaches" \
        "\`std::fs::remove_dir_all\` in fs-err@3.3.2 (fs-err-3.3.2/src/lib.rs)"
done

fs_err_filesystem
for toolchain in $toolchains; do
    echo "== Rust $toolchain: fs-err reviewed as filesystem =="
    expect_holds "$toolchain" "$work"
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

# --- 2. method and transitive wrappers, as vendored registry packages ----------------
fixture=$scratch/fixture
copy_head "$fixture"
cd "$fixture"
echo "== vendoring the locked crates =="
cargo "+$first" vendor -q --locked "$fixture/vendor" >/dev/null
mkdir -p .cargo
cat >.cargo/config.toml <<EOF
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "$fixture/vendor"
EOF
# A vendored package: its manifest, library source and a .cargo-checksum.json whose
# package checksum Cargo.lock records.
vendored() { # name version library-source [dependency-line]
    dir=$fixture/vendor/$1-$2
    mkdir -p "$dir/src"
    printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n\n[features]\nextra = []\n\n[dependencies]\n%s\n' \
        "$1" "$2" "${4:-}" >"$dir/Cargo.toml"
    printf '%s' "$3" >"$dir/src/lib.rs"
    python3 -I -c 'import hashlib, json, sys
print(json.dumps({"files": {}, "package": hashlib.sha256(" ".join(sys.argv[1:3]).encode()).hexdigest()}))' \
        "$1" "$2" >"$dir/.cargo-checksum.json"
}
wrapper='//! An extension trait on std::fs::File (reviews/poc-b7m2-recheck).
use std::fs::File;
/// Resets a file.
pub trait Reset {
    /// Resets it.
    fn reset(&self) -> std::io::Result<()>;
}
impl Reset for File {
    fn reset(&self) -> std::io::Result<()> {
        self.set_len(0)
    }
}
'
vendored method-wrapper 1.0.0 "$wrapper"
vendored method-wrapper 1.0.1 "$wrapper"
vendored inner-wrapper 1.0.0 "$wrapper"
vendored outer-wrapper 1.0.0 '//! Re-exports a convenience trait.
pub use inner_wrapper::Reset;
' 'inner-wrapper = "1"'
cp Cargo.lock "$scratch/lock-before"
cp dependency-gate.json "$scratch/gate-before"
cp crates/kilnd/Cargo.toml "$scratch/kilnd-manifest-before"
cp crates/kilnd/src/lib.rs "$scratch/kilnd-lib-before"
# kilnd depends on $1 (a dependency line) and calls file.reset() through crate $2.
uses() {
    cp "$scratch/lock-before" Cargo.lock
    cp "$scratch/gate-before" dependency-gate.json
    cp "$scratch/kilnd-manifest-before" crates/kilnd/Cargo.toml
    cp "$scratch/kilnd-lib-before" crates/kilnd/src/lib.rs
    python3 -I - "$1" "$2" <<'EOF'
import sys
dependency, crate = sys.argv[1], sys.argv[2]
manifest = open("crates/kilnd/Cargo.toml").read()
manifest = manifest.replace("clap.workspace = true\n", "clap.workspace = true\n%s\n" % dependency, 1)
open("crates/kilnd/Cargo.toml", "w").write(manifest)
lib = open("crates/kilnd/src/lib.rs").read()
lib = lib.replace("pub mod admission;\n", "pub mod admission;\npub mod gate_method_poc;\n", 1)
open("crates/kilnd/src/lib.rs", "w").write(lib)
open("crates/kilnd/src/gate_method_poc.rs", "w").write(
    "//! Daybreak's method wrapper call (B7 milestone 2 recheck HIGH-1).\n\n"
    "use %s::Reset as _;\n\n"
    "/// Empties a file through the dependency's extension trait.\n"
    "pub fn reset(file: &std::fs::File) -> std::io::Result<()> {\n"
    "    file.reset()\n"
    "}\n" % crate)
EOF
    # Lock the new package (only the vendored versions exist), then the gate runs --locked.
    cargo "+$first" metadata -q --format-version 1 --offline >/dev/null
}
no_destructive_api='{"capability": "filesystem", "no_destructive_api": "only extends File with a reset helper", "why": "file convenience traits"}'
exception() { # version features-json
    python3 -I - "$1" "$2" <<'EOF'
import json, sys
gate = json.load(open("dependency-gate.json"))
gate["sink_exceptions"].append({
    "package": "method-wrapper", "version": sys.argv[1], "features": json.loads(sys.argv[2]),
    "sinks": [".set_len(", "impl for std::fs::File"],
    "why": "fixture: Reset::reset truncates a file the caller opened; reviewed for this regression",
})
gate["sink_exceptions"].sort(key=lambda e: (e["package"], e["version"]))
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
EOF
}

for toolchain in $toolchains; do
    echo "== Rust $toolchain: method-wrapper reviewed filesystem with no destructive API =="
    uses 'method-wrapper = "=1.0.0"' method_wrapper
    review "$fixture" "method-wrapper=$no_destructive_api"
    expect_refused "$toolchain" "$fixture" \
        "method-wrapper@1.0.0 is declared \`filesystem\` with no destructive API, but its runtime subtree reaches \`.set_len(\` in method-wrapper@1.0.0 (method-wrapper-1.0.0/src/lib.rs)" \
        "\`impl for std::fs::File\` in method-wrapper@1.0.0"
    clippy_accepts "$toolchain" "$fixture"

    echo "== Rust $toolchain: method-wrapper reviewed none =="
    uses 'method-wrapper = "=1.0.0"' method_wrapper
    review "$fixture" 'method-wrapper={"capability": "none", "why": "file convenience traits"}'
    expect_refused "$toolchain" "$fixture" \
        "method-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches \`.set_len(\` in method-wrapper@1.0.0"

    echo "== Rust $toolchain: outer-wrapper (none) re-exporting an unreviewed inner-wrapper =="
    uses 'outer-wrapper = "=1.0.0"' outer_wrapper
    review "$fixture" 'outer-wrapper={"capability": "none", "why": "re-exports a convenience trait"}'
    # The drafter's skeleton for inner-wrapper is not a review either.
    expect_refused "$toolchain" "$fixture" \
        "inner-wrapper@1.0.0 needs a reviewed \`capability\`" \
        "outer-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches \`.set_len(\` in inner-wrapper@1.0.0 (inner-wrapper-1.0.0/src/lib.rs)"
    python3 -I - <<'EOF'
import json
gate = json.load(open("dependency-gate.json"))
del gate["packages"]["inner-wrapper@1.0.0"]
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
EOF
    echo "-- with no entry for inner-wrapper at all:"
    expect_refused "$toolchain" "$fixture" \
        "inner-wrapper@1.0.0 is in Cargo.lock with no reviewed entry" \
        "outer-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches \`.set_len(\` in inner-wrapper@1.0.0 (inner-wrapper-1.0.0/src/lib.rs)"
    clippy_accepts "$toolchain" "$fixture"

    echo "== Rust $toolchain: method-wrapper with a reviewed exception =="
    uses 'method-wrapper = "=1.0.0"' method_wrapper
    review "$fixture" "method-wrapper=$no_destructive_api"
    exception 1.0.0 '[]'
    expect_holds "$toolchain" "$fixture"
    clippy_accepts "$toolchain" "$fixture"
    cp dependency-gate.json "$scratch/gate-excepted"

    echo "== Rust $toolchain: a lock change bumps method-wrapper to 1.0.1 =="
    sed -i.bak 's/method-wrapper = "=1.0.0"/method-wrapper = "=1.0.1"/' crates/kilnd/Cargo.toml
    rm crates/kilnd/Cargo.toml.bak
    cargo "+$first" metadata -q --format-version 1 --offline >/dev/null
    grep -A1 'name = "method-wrapper"' Cargo.lock | grep -q 'version = "1.0.1"' ||
        fail "the lock did not move to method-wrapper 1.0.1"
    expect_refused "$toolchain" "$fixture" \
        "method-wrapper@1.0.1 is in Cargo.lock with no reviewed entry" \
        "\`packages\` entry method-wrapper@1.0.0 is not in Cargo.lock" \
        "the sink exception for method-wrapper@1.0.0 is stale"
    python3 -I - <<'EOF'
import json
gate = json.load(open("dependency-gate.json"))
del gate["packages"]["method-wrapper@1.0.0"]
gate["sink_exceptions"] = [e for e in gate["sink_exceptions"] if e["package"] != "method-wrapper"]
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
EOF
    review "$fixture" "method-wrapper=$no_destructive_api"
    exception 1.0.1 '[]'
    echo "-- after 1.0.1 is reviewed:"
    expect_holds "$toolchain" "$fixture"

    echo "== Rust $toolchain: method-wrapper's extra feature enabled =="
    uses 'method-wrapper = { version = "=1.0.0", features = ["extra"] }' method_wrapper
    cp "$scratch/gate-excepted" dependency-gate.json
    expect_refused "$toolchain" "$fixture" \
        "method-wrapper@1.0.0's reviewed features [] are not the resolved features [\"extra\"]" \
        "the sink exception for method-wrapper@1.0.0 is scoped to features [], but cargo resolves [\"extra\"]" \
        "but its runtime subtree reaches \`.set_len(\` in method-wrapper@1.0.0"
done

# --- 3. std::fs::copy and libc::creat ------------------------------------------------
missing=$scratch/missing-methods
mkdir -p "$missing/src"
cat >"$missing/Cargo.toml" <<'EOF'
[package]
name = "b7m2-missing-methods"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
libc = "=0.2.190"

[workspace]
EOF
cat >"$missing/src/main.rs" <<'EOF'
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
cd "$scratch"
for toolchain in $toolchains; do
    echo "== Rust $toolchain: std::fs::copy and libc::creat =="
    if CLIPPY_CONF_DIR="$repo" cargo "+$toolchain" clippy -q \
        --manifest-path "$missing/Cargo.toml" -- \
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
