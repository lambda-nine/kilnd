#!/bin/sh
# B7 milestone 2 break-it and recheck regressions for design section 7.1's dependency
# gate, through the actual source loader (cargo metadata per build profile, Cargo.lock
# and each package's extracted source), cargo, clippy and scripts/build.sh. The gate's
# synthetic tests run under cargo test.
#
#   scripts/dependency-gate-regressions.sh [TOOLCHAIN...]
#
# Every case runs in a disposable copy of HEAD (this checkout is never touched). The
# gate test binary is built once per toolchain from a pristine copy, and its ignored
# regression_fixture_gate test (the same loader and gate) is pointed at each case's
# workspace with KILND_DEPENDENCY_GATE_FIXTURE. The authoritative the_dependency_gate_holds
# reads no variable at all (case 7).
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
#       its `set_len`; clippy accepts the workspace (dependency bodies are not linted).
#    b. The same reviewed `none`: refused.
#    c. outer-wrapper (`none`) re-exporting the trait from inner-wrapper: refused, for
#       the unreviewed inner package and for the outer package's subtree `set_len`;
#       clippy accepts the workspace.
#    d. Case a with a reviewed exception for method-wrapper 1.0.0, no features: holds,
#       and clippy accepts.
#    e. Case d after a lock change bumping method-wrapper to 1.0.1: refused until 1.0.1
#       is reviewed (entry and exception), then holds.
#    f. Case d with method-wrapper's `extra` feature enabled: refused (the review and the
#       exception are scoped to no features).
#    g. Recheck 2 HIGH-2, Daybreak's type-alias UFCS PoC (reviews/poc-b7m2-recheck2/
#       type-alias-ufcs.sh): its exact wrapper source (`pub type LocalFile = File;` and
#       `LocalFile::set_len(self, 0)` in an extension trait) as the vendored
#       alias-wrapper, reviewed `none`: refused on the `set_len` identifier, the alias and
#       the impl; clippy accepts the workspace.
# 3. MEDIUM-1, Daybreak's missing-methods PoC: std::fs::copy and libc::creat (exact
#    libc 0.2.190) against this clippy.toml: clippy rejects both.
# 4. Recheck 2 HIGH-1, Daybreak's feature-injection PoC (feature-injection.sh) through
#    scripts/build.sh: `--features tokio/full`, and every other spelling of a feature,
#    manifest, config or unstable selection, is refused before cargo runs.
# 5. Recheck 2 HIGH-1, a profile's own graph:
#    a. A profile selecting tokio/full directly: build.sh refuses it, and the gate refuses
#       it as no workspace feature and for the four packages its graph resolves that
#       Cargo.lock does not lock (parking_lot and the rest).
#    b. A checked-in workspace feature forwarding tokio/full, in a profile: the gate
#       refuses the unreviewed packages it locks and Tokio's unreviewed features.
# 6. Recheck 2 MEDIUM-1, Daybreak's two-registry PoC (source-collision.sh): two
#    dupe@1.0.0 packages from two local registries. The gate and the review drafter
#    refuse the duplicate identity.
# 7. Recheck 2 MEDIUM-2, Daybreak's root-override PoC (root-override.sh): in a workspace
#    with an unreviewed path dependency, the authoritative test refuses even with
#    KILND_DEPENDENCY_GATE_ROOT and KILND_DEPENDENCY_GATE_FIXTURE naming a clean copy, and
#    the pristine copy's authoritative test holds with both naming the dirty one.
# 8. Recheck 3 HIGH-1, Daybreak's compiler-cfg PoC (reviews/poc-b7m2-recheck3/
#    rustflags-feature.sh): a declared `ambient-poc` feature no profile selects, and a
#    test compiled only under it.
#    a. RUSTFLAGS and CARGO_BUILD_RUSTFLAGS='--cfg feature="ambient-poc"' through
#       scripts/build.sh: refused before cargo runs.
#    b. The Clippy tail `-- --cfg 'feature="ambient-poc"'`: refused.
#    c. The same cfg from a Cargo config file (`build.rustflags` and a
#       `target.'cfg(all())'` table) and a config `rustc-wrapper`: build.sh's closed
#       environment overrides them, and the feature's test is not compiled.
#    d. A raw cargo build with that RUSTFLAGS: the workspace build scripts' backstop
#       refuses the `--cfg`.
# 9. Recheck 3 HIGH-2, Daybreak's path-module PoC (path-module-sink.sh): its exact
#    vendored path-module-wrapper (src/lib.rs delegates through `#[path = "../hidden.rs"]`
#    to a package-root file whose `File` alias impl calls `LocalFile::set_len(self, 0)`),
#    reviewed `none`.
#    a. Refused on hidden.rs's `set_len`, alias and impl; clippy accepts the workspace.
#    b. The module under tests/, reached only by its `#[path]`: refused the same way.
#    c. A `#[path]` outside the package root: refused as unscannable.
#
# Default toolchains: 1.88.0 and 1.99.0. It resolves fs-err and parking_lot from the
# registry and vendors the locked crates (the network, or cargo's cache), so it is not
# part of the offline checks.
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

# The gate, from a pristine copy, against the workspace at $2. Output in $scratch/gate.log.
copy_head "$scratch/gate"
gate() { # toolchain root
    (cd "$scratch/gate" && KILND_DEPENDENCY_GATE_FIXTURE=$2 cargo "+$1" test --locked -q -p kilnd --lib \
        helper::firecracker::proven::tests::dependency_gate::regression_fixture_gate \
        -- --exact --ignored) >"$scratch/gate.log" 2>&1
}
# The authoritative test, built in the workspace $2, with both variables naming $3.
authoritative() { # toolchain workspace other-root
    (cd "$2" && KILND_DEPENDENCY_GATE_ROOT=$3 KILND_DEPENDENCY_GATE_FIXTURE=$3 \
        cargo "+$1" test --locked -q -p kilnd --lib \
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
# Recheck 2 HIGH-2: type-alias-ufcs.sh's wrapper source, exactly.
vendored alias-wrapper 1.0.0 'use std::fs::File;

/// A conventional local alias used throughout this wrapper.
pub type LocalFile = File;

pub trait Reset {
    fn reset(&self) -> std::io::Result<()>;
}

impl Reset for LocalFile {
    fn reset(&self) -> std::io::Result<()> {
        LocalFile::set_len(self, 0)
    }
}
'
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
    "sinks": ["impl for std::fs::File", "set_len"],
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
        "method-wrapper@1.0.0 is declared \`filesystem\` with no destructive API, but its runtime subtree reaches" \
        "\`set_len\` in method-wrapper@1.0.0 (method-wrapper-1.0.0/src/lib.rs)" \
        "\`impl for std::fs::File\` in method-wrapper@1.0.0"
    clippy_accepts "$toolchain" "$fixture"

    echo "== Rust $toolchain: method-wrapper reviewed none =="
    uses 'method-wrapper = "=1.0.0"' method_wrapper
    review "$fixture" 'method-wrapper={"capability": "none", "why": "file convenience traits"}'
    expect_refused "$toolchain" "$fixture" \
        "method-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches" \
        "\`set_len\` in method-wrapper@1.0.0"

    echo "== Rust $toolchain: outer-wrapper (none) re-exporting an unreviewed inner-wrapper =="
    uses 'outer-wrapper = "=1.0.0"' outer_wrapper
    review "$fixture" 'outer-wrapper={"capability": "none", "why": "re-exports a convenience trait"}'
    # The drafter's skeleton for inner-wrapper is not a review either.
    expect_refused "$toolchain" "$fixture" \
        "inner-wrapper@1.0.0 needs a reviewed \`capability\`" \
        "outer-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches" \
        "\`set_len\` in inner-wrapper@1.0.0 (inner-wrapper-1.0.0/src/lib.rs)"
    python3 -I - <<'EOF'
import json
gate = json.load(open("dependency-gate.json"))
del gate["packages"]["inner-wrapper@1.0.0"]
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
EOF
    echo "-- with no entry for inner-wrapper at all:"
    expect_refused "$toolchain" "$fixture" \
        "inner-wrapper@1.0.0 is in Cargo.lock with no reviewed entry" \
        "outer-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches" \
        "\`set_len\` in inner-wrapper@1.0.0 (inner-wrapper-1.0.0/src/lib.rs)"
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
        "\`set_len\` in method-wrapper@1.0.0"

    echo "== Rust $toolchain: alias-wrapper (none), a type alias plus UFCS =="
    uses 'alias-wrapper = "=1.0.0"' alias_wrapper
    review "$fixture" 'alias-wrapper={"capability": "none", "why": "a file convenience trait using a local File alias"}'
    expect_refused "$toolchain" "$fixture" \
        "alias-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches" \
        "\`set_len\` in alias-wrapper@1.0.0 (alias-wrapper-1.0.0/src/lib.rs)" \
        "\`type alias for std::fs::File\` in alias-wrapper@1.0.0" \
        "\`impl for std::fs::File\` in alias-wrapper@1.0.0"
    clippy_accepts "$toolchain" "$fixture"
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

# --- 4. feature injection through scripts/build.sh ------------------------------------
injection=$scratch/injection
copy_head "$injection"
cd "$injection"
for toolchain in $toolchains; do
    echo "== Rust $toolchain: Daybreak's feature injection through scripts/build.sh =="
    for arguments in "--all-features --features tokio/full" "--features tokio/full" \
        "--features=tokio/full" "-F tokio/full" "-Ftokio/full" "-rF tokio/full" \
        "--all-features" "--no-default-features" "--manifest-path ../other/Cargo.toml" \
        "--config patch.crates-io.tokio.path=x" "-Zunstable-options"; do
        # Word splitting is the point: each string is several arguments.
        # shellcheck disable=SC2086
        if sh scripts/build.sh "+$toolchain" default test -q -p kilnd --lib $arguments \
            helper::firecracker::proven::tests::dependency_gate::the_dependency_gate_holds \
            -- --exact >"$scratch/build.log" 2>&1; then
            fail "build.sh ran cargo with $arguments"
        elif grep -q '^scripts/build.sh: refused: ' "$scratch/build.log"; then
            echo "build.sh refuses: $arguments"
        else
            cat "$scratch/build.log" >&2
            fail "build.sh failed for another reason with $arguments"
        fi
    done
done

# --- 5. a profile's own graph -------------------------------------------------------
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi |
        awk '{print $1}'
}
profiles=$scratch/profiles
copy_head "$profiles"
cd "$profiles"
python3 -I - <<'EOF'
import json
gate = json.load(open("dependency-gate.json"))
gate["profiles"]["tokio-full"] = {"features": ["tokio/full"], "why": "fixture: feature injection as a profile"}
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
EOF
lock_before=$(sha256 Cargo.lock)
for toolchain in $toolchains; do
    echo "== Rust $toolchain: a profile selecting tokio/full directly =="
    if sh scripts/build.sh "+$toolchain" tokio-full check -q >"$scratch/build.log" 2>&1; then
        fail "build.sh built the tokio-full profile"
    elif grep -qF "scripts/build.sh: refused: profile tokio-full selects tokio/full, which is not a feature a workspace member declares" "$scratch/build.log"; then
        echo "build.sh refuses the profile"
    else
        cat "$scratch/build.log" >&2
        fail "build.sh failed for another reason"
    fi
    expect_refused "$toolchain" "$profiles" \
        "profile tokio-full selects tokio/full, which is not a feature a workspace member declares" \
        "profile tokio-full resolves lock_api@" \
        "profile tokio-full resolves parking_lot@" \
        "profile tokio-full resolves parking_lot_core@" \
        "profile tokio-full resolves scopeguard@"
    [ "$(sha256 Cargo.lock)" = "$lock_before" ] || fail "the gate changed Cargo.lock"
done
python3 -I - <<'EOF'
import json
gate = json.load(open("dependency-gate.json"))
gate["profiles"]["tokio-full"]["features"] = ["kilnd/tokio-full"]
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
manifest = open("crates/kilnd/Cargo.toml").read()
manifest = manifest.replace(
    "firecracker-test-deployment = []\n",
    'firecracker-test-deployment = []\ntokio-full = ["tokio/full"]\n', 1)
open("crates/kilnd/Cargo.toml", "w").write(manifest)
EOF
# The workspace feature puts Tokio's optional dependencies in the lock.
cargo "+$first" metadata -q --format-version 1 >/dev/null
for toolchain in $toolchains; do
    echo "== Rust $toolchain: a workspace feature forwarding tokio/full, in a profile =="
    expect_refused "$toolchain" "$profiles" \
        "is in Cargo.lock with no reviewed entry" \
        "tokio@1.53.3's reviewed features"
    if grep -Eq 'parking_lot@[0-9.]+ is in Cargo.lock with no reviewed entry' "$scratch/gate.log"; then
        echo "refused: parking_lot is unreviewed"
    else
        cat "$scratch/gate.log" >&2
        fail "the gate did not name parking_lot"
    fi
done

# --- 6. one name@version from two registries -----------------------------------------
collision=$scratch/collision
copy_head "$collision"
make_registry() { # name library-source
    index=$scratch/index-$1
    crates=$scratch/crates-$1
    package=$scratch/package-$1/dupe-1.0.0
    mkdir -p "$index/du/pe" "$crates" "$package/src"
    printf '[package]\nname = "dupe"\nversion = "1.0.0"\nedition = "2021"\n' >"$package/Cargo.toml"
    printf '%s\n' "$2" >"$package/src/lib.rs"
    (cd "$(dirname "$package")" && COPYFILE_DISABLE=1 tar -czf "$crates/dupe-1.0.0.crate" dupe-1.0.0)
    printf '{"dl":"file://%s/{crate}-{version}.crate"}\n' "$crates" >"$index/config.json"
    printf '{"name":"dupe","vers":"1.0.0","deps":[],"cksum":"%s","features":{},"yanked":false,"links":null}\n' \
        "$(sha256 "$crates/dupe-1.0.0.crate")" >"$index/du/pe/dupe"
    git -C "$index" init -q
    git -C "$index" add config.json du/pe/dupe
    git -C "$index" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m index
}
make_registry a 'pub fn tidy(path: &std::path::Path) -> std::io::Result<()> { std::fs::remove_file(path) }'
make_registry z 'pub fn tidy(_path: &std::path::Path) -> std::io::Result<()> { Ok(()) }'
mkdir -p "$collision/.cargo"
printf '[registries.a]\nindex = "file://%s/index-a"\n\n[registries.z]\nindex = "file://%s/index-z"\n' \
    "$scratch" "$scratch" >"$collision/.cargo/config.toml"
for name in a z; do
    mkdir -p "$collision/crates/collision-$name/src"
    printf '[package]\nname = "collision-%s"\nversion.workspace = true\nedition.workspace = true\npublish = false\n\n[dependencies]\ndupe = { version = "=1.0.0", registry = "%s" }\n' \
        "$name" "$name" >"$collision/crates/collision-$name/Cargo.toml"
    printf 'pub fn tidy(path: &std::path::Path) -> std::io::Result<()> { dupe::tidy(path) }\n' \
        >"$collision/crates/collision-$name/src/lib.rs"
done
cd "$collision"
python3 -I - <<'EOF'
text = open("Cargo.toml").read()
text = text.replace("members = [\n", 'members = [\n    "crates/collision-a",\n    "crates/collision-z",\n', 1)
open("Cargo.toml", "w").write(text)
EOF
cargo "+$first" metadata -q --format-version 1 >/dev/null
[ "$(grep -c '^name = "dupe"$' Cargo.lock)" -eq 2 ] || fail "the fixture did not lock two dupe@1.0.0 packages"
python3 -I - <<'EOF'
import json, re
lock = open("Cargo.lock").read()
checksum = [b for b in lock.split("[[package]]") if 'name = "dupe"' in b][-1]
checksum = re.search(r'(?m)^checksum = "([^"]+)"$', checksum).group(1)
gate = json.load(open("dependency-gate.json"))
gate["packages"]["dupe@1.0.0"] = {"checksum": checksum, "features": [], "kind": "runtime",
                                  "capability": "none", "why": "the z-registry package only returns Ok"}
open("dependency-gate.json", "w").write(json.dumps(gate, indent=2) + "\n")
EOF
echo "== the review drafter: two dupe@1.0.0 registry sources =="
if python3 -I scripts/dependency-gate-review.py >"$scratch/review.log" 2>&1; then
    fail "the drafter accepted the duplicate identity"
elif grep -qF "Cargo.lock locks two packages with the same identity dupe@1.0.0" "$scratch/review.log"; then
    echo "the drafter refuses the duplicate identity"
else
    cat "$scratch/review.log" >&2
    fail "the drafter failed for another reason"
fi
for toolchain in $toolchains; do
    echo "== Rust $toolchain: two dupe@1.0.0 registry sources =="
    expect_refused "$toolchain" "$collision" \
        "resolves two packages with the same identity dupe@1.0.0"
done

# --- 7. the authoritative test's root ------------------------------------------------
dirty=$scratch/dirty
copy_head "$dirty"
mkdir -p "$scratch/unreviewed/src"
printf '[package]\nname = "unreviewed"\nversion = "1.0.0"\nedition = "2021"\n' >"$scratch/unreviewed/Cargo.toml"
printf 'pub fn value() -> u8 { 7 }\n' >"$scratch/unreviewed/src/lib.rs"
cd "$dirty"
python3 -I - <<'EOF'
path = "crates/kilnd/Cargo.toml"
text = open(path).read().replace(
    "clap.workspace = true\n", 'clap.workspace = true\nunreviewed = { path = "../../../unreviewed" }\n', 1)
open(path, "w").write(text)
EOF
cargo "+$first" metadata -q --format-version 1 >/dev/null
for toolchain in $toolchains; do
    echo "== Rust $toolchain: the authoritative test ignores the root variables =="
    if authoritative "$toolchain" "$dirty" "$scratch/gate"; then
        fail "the dirty workspace's authoritative test passed with the variables naming a clean copy"
    elif grep -qF "unreviewed@1.0.0 is not a registry package" "$scratch/gate.log" &&
        grep -qF "unreviewed@1.0.0 is in Cargo.lock with no reviewed entry" "$scratch/gate.log"; then
        echo "refused: the dirty workspace, whatever the variables name"
    else
        cat "$scratch/gate.log" >&2
        fail "the dirty workspace's authoritative test failed for another reason"
    fi
    if authoritative "$toolchain" "$scratch/gate" "$dirty"; then
        echo "the pristine copy's authoritative test holds, whatever the variables name"
    else
        cat "$scratch/gate.log" >&2
        fail "the pristine copy's authoritative test followed a variable"
    fi
    echo "-- the ignored fixture test does follow its variable:"
    expect_refused "$toolchain" "$dirty" "unreviewed@1.0.0 is not a registry package"
done

# --- 8. compiler cfg inputs (recheck 3 HIGH-1) ------------------------------------
ambient=$scratch/ambient
copy_head "$ambient"
cd "$ambient"
python3 -I - <<'EOF'
from pathlib import Path

manifest = Path("crates/kilnd/Cargo.toml")
text = manifest.read_text()
assert "firecracker-test-deployment = []\n" in text
manifest.write_text(text.replace(
    "firecracker-test-deployment = []\n",
    "firecracker-test-deployment = []\nambient-poc = []\n", 1))
lib = Path("crates/kilnd/src/lib.rs")
lib.write_text(lib.read_text() + r"""

#[cfg(feature = "ambient-poc")]
#[deprecated(note = "ambient-poc cfg reached clippy")]
pub fn ambient_profile_marker() {}

#[cfg(feature = "ambient-poc")]
pub fn use_ambient_profile_marker() {
    ambient_profile_marker();
}

#[cfg(all(test, feature = "ambient-poc"))]
mod ambient_profile_poc {
    #[test]
    fn unreviewed_feature_entered_default_profile() {}
}
""")
EOF
ambient_test=ambient_profile_poc::unreviewed_feature_entered_default_profile
expect_build_refused() { # what message command...
    what=$1 message=$2
    shift 2
    if "$@" >"$scratch/build.log" 2>&1; then
        cat "$scratch/build.log" >&2
        fail "build.sh ran cargo with $what"
    elif grep -qF -- "scripts/build.sh: refused: $message" "$scratch/build.log"; then
        echo "build.sh refuses: $what"
    else
        cat "$scratch/build.log" >&2
        fail "build.sh failed for another reason with $what"
    fi
}
for toolchain in $toolchains; do
    echo "== Rust $toolchain: Daybreak's compiler cfg inputs through scripts/build.sh =="
    for route in RUSTFLAGS CARGO_BUILD_RUSTFLAGS; do
        expect_build_refused "$route" "$route is set; build.sh runs cargo in a closed compiler environment" \
            env "$route=--cfg feature=\"ambient-poc\"" sh scripts/build.sh "+$toolchain" default test \
            -p kilnd --lib "$ambient_test" -- --exact
    done
    expect_build_refused "the clippy tail" "clippy takes no arguments after --" \
        sh scripts/build.sh "+$toolchain" default clippy -p kilnd --lib -- --cfg 'feature="ambient-poc"'

    echo "-- the same cfg from a Cargo config file, and a config rustc-wrapper:"
    mkdir -p .cargo
    cat >.cargo/config.toml <<'EOF'
[build]
rustflags = ["--cfg", "feature=\"ambient-poc\""]
rustc-wrapper = "/nonexistent/rustc-wrapper"

[target.'cfg(all())']
rustflags = ["--cfg", "feature=\"ambient-poc\""]
EOF
    if sh scripts/build.sh "+$toolchain" default test -p kilnd --lib "$ambient_test" -- --exact \
        >"$scratch/build.log" 2>&1 && grep -q '^running 0 tests' "$scratch/build.log" &&
        ! grep -q 'unreviewed_feature_entered_default_profile' "$scratch/build.log"; then
        echo "build.sh's closed environment overrides the config: the feature's test is not compiled"
    else
        cat "$scratch/build.log" >&2
        fail "a Cargo config file reached build.sh's build"
    fi
    rm -r .cargo

    echo "-- a raw cargo build with that RUSTFLAGS:"
    if RUSTFLAGS='--cfg feature="ambient-poc"' cargo "+$toolchain" test --locked -q -p kilnd --lib \
        --no-run >"$scratch/build.log" 2>&1; then
        fail "the raw build compiled the ambient feature"
    elif grep -qF 'refused compiler flag "--cfg"' "$scratch/build.log"; then
        echo "the build scripts' backstop refuses the --cfg"
    else
        cat "$scratch/build.log" >&2
        fail "the raw build failed for another reason"
    fi
done

# --- 9. a #[path] module outside the library directory (recheck 3 HIGH-2) -----------
cd "$fixture"
# path-module-sink.sh's vendored wrapper, exactly, with its module at $2 reached by
# `#[path = "$1"]` from src/lib.rs.
path_wrapper() { # module-path module-file
    dir=$fixture/vendor/path-module-wrapper-1.0.0
    rm -rf "$dir"
    mkdir -p "$dir/src" "$(dirname "$dir/$2")"
    printf '[package]\nname = "path-module-wrapper"\nversion = "1.0.0"\nedition = "2021"\n' \
        >"$dir/Cargo.toml"
    printf '#[path = "%s"]\nmod hidden;\npub use hidden::Reset;\n' "$1" >"$dir/src/lib.rs"
    cat >"$dir/$2" <<'EOF'
use std::fs::File;

pub type LocalFile = File;

pub trait Reset {
    fn reset(&self) -> std::io::Result<()>;
}

impl Reset for LocalFile {
    fn reset(&self) -> std::io::Result<()> {
        LocalFile::set_len(self, 0)
    }
}
EOF
    python3 -I -c 'import hashlib, json
print(json.dumps({"files": {}, "package": hashlib.sha256(b"path-module-wrapper 1.0.0").hexdigest()}))' \
        >"$dir/.cargo-checksum.json"
    uses 'path-module-wrapper = "=1.0.0"' path_module_wrapper
    review "$fixture" 'path-module-wrapper={"capability": "none", "why": "a file convenience trait whose library root delegates to a checked-in path module"}'
}
for toolchain in $toolchains; do
    echo "== Rust $toolchain: path-module-wrapper (none), a #[path] module at the package root =="
    path_wrapper ../hidden.rs hidden.rs
    expect_refused "$toolchain" "$fixture" \
        "path-module-wrapper@1.0.0 is declared \`none\`, but its runtime subtree reaches" \
        "\`set_len\` in path-module-wrapper@1.0.0 (path-module-wrapper-1.0.0/hidden.rs)" \
        "\`type alias for std::fs::File\` in path-module-wrapper@1.0.0 (path-module-wrapper-1.0.0/hidden.rs)" \
        "\`impl for std::fs::File\` in path-module-wrapper@1.0.0 (path-module-wrapper-1.0.0/hidden.rs)"
    clippy_accepts "$toolchain" "$fixture"

    echo "== Rust $toolchain: the module under tests/, reached only by its #[path] =="
    path_wrapper ../tests/hidden.rs tests/hidden.rs
    expect_refused "$toolchain" "$fixture" \
        "\`set_len\` in path-module-wrapper@1.0.0 (path-module-wrapper-1.0.0/tests/hidden.rs)"

    echo "== Rust $toolchain: a #[path] outside the package root =="
    path_wrapper ../../../outside.rs hidden.rs
    expect_refused "$toolchain" "$fixture" \
        "path-module-wrapper@1.0.0's source cannot be scanned completely, so the gate refuses it: path-module-wrapper-1.0.0/src/lib.rs: \`#[path = \"../../../outside.rs\"]\` resolves outside the package root"
done

if [ "$failed" -ne 0 ]; then
    echo "dependency gate regressions: FAILED" >&2
    exit 1
fi
echo "dependency gate regressions: all passed"
