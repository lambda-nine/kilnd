#!/bin/sh
# kilnd's one supported build entry point (design section 7.1's dependency gate; B7
# milestone 2 recheck 2 HIGH-1). CI, scripts/install.sh, the binaries scripts/upgrade.sh
# installs and the VM scripts all run cargo through it:
#
#   scripts/build.sh [+TOOLCHAIN] [--crt-static] PROFILE COMMAND [CARGO-ARGUMENT...] [-- TEST-ARGUMENT...]
#
# PROFILE is one of the `profiles` in dependency-gate.json, the same list the gate
# resolves and reviews (`default`, `firecracker-test-deployment`). COMMAND is build,
# test, clippy or check. It runs, from the workspace root,
#
#   cargo [+TOOLCHAIN] COMMAND --locked [--features PROFILE'S] CARGO-ARGUMENT... [-- TEST-ARGUMENT...]
#
# in a closed compiler environment (B7 milestone 2 recheck 3 HIGH-1): rustc's flags can
# turn on code no profile reviews (`--cfg feature="x"`) without cargo's resolver, and so
# the gate, ever seeing it. build.sh refuses a nonempty RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS,
# CARGO_BUILD_RUSTFLAGS, RUSTDOCFLAGS (and their encoded and build forms),
# CARGO_TARGET_*_RUSTFLAGS, CARGO_TARGET_*_RUSTDOCFLAGS, CARGO_PROFILE_*_RUSTFLAGS,
# CARGO_HOST_RUSTFLAGS, RUSTC, RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER, CARGO_BUILD_RUSTC*,
# RUSTC_BOOTSTRAP, CARGO_UNSTABLE_* and CLIPPY_ARGS. It then sets the compiler flags
# itself, so no Cargo config file can supply any: CARGO_ENCODED_RUSTFLAGS and
# CARGO_ENCODED_RUSTDOCFLAGS (empty, which overrides every config table including
# `target.'cfg(...)'`), RUSTC=rustc and empty wrappers, plus `--config build.rustflags=[]`,
# `build.rustdocflags=[]` and `target.TRIPLE.rustflags=[]` for the host triple and every
# --target. The one compiler flag it ever passes is --crt-static's
# `-C target-feature=+crt-static` (scripts/b4-vm-tests.sh's static test helper), which
# requires --target so build scripts and procedural macros stay dynamic.
#
# clippy's arguments are build.sh's own, a fixed list: `-- -D warnings -D
# clippy::disallowed_methods`. A caller's `--` tail is refused for clippy (it reaches
# clippy-driver and rustc: `--cfg`, response files) and for build and check; for test it
# goes to the test harness, which compiles nothing.
#
# A closed Cargo configuration too (C6a recheck 1 HIGH 5 and 6): a Cargo runner can list
# a test without running it, and a config `[env]` reaches every test process. build.sh
# refuses, before cargo runs, any `.cargo/config` or `.cargo/config.toml` in the
# repository or a parent directory other than $CARGO_HOME's own; a $CARGO_HOME config
# with an `[env]` table, a `target` key other than rustflags/rustdocflags, or a `build`
# key other than those this file overrides (rustflags, rustdocflags, rustc and the two
# wrappers); any CARGO_TARGET_*_RUNNER, CARGO_TARGET_*_LINKER, CARGO_BUILD_* or
# CARGO_ENV_* variable, set at all; and KILND_BLESS_CHECKPOINT_CONTRACT, which only the
# ignored bless_checkpoint_contract test, run locally by name, may use. It also
# passes `--config target.TRIPLE.runner=["/bin/sh", "-c", 'exec "$0" "$@"']`, a
# pass-through, for the host and every --target (Cargo refuses an empty runner).
#
# Full-suite test (no cargo arguments and no -- tail) runs the suite once with its
# libtest output kept, then checks the checkpoint ledger against it and the compiled
# test registries: every compiled test ran (`ok`, or `ignored` as the registry lists
# it), none was filtered out, and every ledger test passed. Filtered test invocations
# retain their ordinary cargo behavior.
#
# A profile enables only workspace features (member/feature) its member declares; a
# dependency's feature is forwarded through one, checked in. Before `--`, it refuses
# every argument that would select features or another graph: --features and -F (and so
# `dep/feature` selectors), --all-features, --no-default-features, --manifest-path,
# --config and -Z, however cargo accepts them spelled (`--features=x`, `-Fx`, `-rF x`).
#
# The gate's guarantee covers builds made this way. A raw `cargo build` with other
# feature flags or compiler flags builds what the gate has not reviewed; every workspace
# crate's build script refuses a `--cfg` or `-Z` compiler flag as a backstop.
set -eu
# No pathname expansion: environment names and target triples are split, never globbed.
set -f
repo=$(cd "$(dirname -- "$0")/.." && pwd)
usage() {
    echo "usage: $0 [+TOOLCHAIN] [--crt-static] PROFILE build|test|clippy|check [CARGO-ARGUMENT...] [-- TEST-ARGUMENT...]" >&2
    exit 2
}
refuse() {
    echo "scripts/build.sh: refused: $*" >&2
    exit 2
}

toolchain=
case ${1:-} in
    +*) toolchain=$1; shift ;;
esac
static=
if [ "${1:-}" = --crt-static ]; then
    static=1
    shift
fi
[ "$#" -ge 2 ] || usage
profile=$1 command=$2
shift 2
full_suite=
if [ "$command" = test ] && [ "$#" -eq 0 ]; then
    full_suite=1
fi
case $command in
    build | test | clippy | check) ;;
    *) refuse "$command is not a supported command (build, test, clippy or check)" ;;
esac

# The closed compiler environment: nothing ambient reaches rustc.
for name in $(awk 'BEGIN { for (name in ENVIRON) print name }'); do
    case $name in
        RUSTFLAGS | CARGO_ENCODED_RUSTFLAGS | CARGO_BUILD_RUSTFLAGS | \
            RUSTDOCFLAGS | CARGO_ENCODED_RUSTDOCFLAGS | CARGO_BUILD_RUSTDOCFLAGS | \
            CARGO_TARGET_*_RUSTFLAGS | CARGO_TARGET_*_RUSTDOCFLAGS | \
            CARGO_PROFILE_*_RUSTFLAGS | CARGO_HOST_RUSTFLAGS | \
            RUSTC | RUSTC_WRAPPER | RUSTC_WORKSPACE_WRAPPER | CARGO_BUILD_RUSTC* | \
            RUSTC_BOOTSTRAP | CARGO_UNSTABLE_* | CLIPPY_ARGS)
            if [ -n "$(printenv "$name" || true)" ]; then
                refuse "$name is set; build.sh runs cargo in a closed compiler environment, because compiler flags, wrappers and unstable switches can compile code (a feature cfg) no reviewed profile selects (dependency-gate.json, design section 7.1). Unset it"
            fi ;;
        CARGO_TARGET_*_RUNNER | CARGO_TARGET_*_LINKER | CARGO_BUILD_* | CARGO_ENV_*)
            refuse "$name is set; build.sh runs cargo in a closed configuration, because a runner or linker can report tests that never ran (C6a recheck 1 HIGH 5). Unset it" ;;
        KILND_BLESS_CHECKPOINT_CONTRACT)
            refuse "$name is set; build.sh never blesses goldens. Bless them locally with the ignored bless_checkpoint_contract test (docs/checkpoint-rollout-gate.md) and review the diff" ;;
    esac
done

# The closed Cargo configuration: no config file but $CARGO_HOME's own, which is checked.
cargo_home=${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}
cargo_home=$(cd "$cargo_home" 2>/dev/null && pwd -P || echo "$cargo_home")
dir=$(cd "$repo" && pwd -P)
while :; do
    if [ "$dir/.cargo" != "$cargo_home" ] && [ "${dir%/}/.cargo" != "$cargo_home" ]; then
        for name in config config.toml; do
            file=${dir%/}/.cargo/$name
            if [ -e "$file" ] || [ -L "$file" ]; then
                refuse "$file is a Cargo configuration file; build.sh runs cargo with none but \$CARGO_HOME's, because a config runner, [env] or build table can skip tests or bless goldens unseen (C6a recheck 1 HIGH 5). Remove it"
            fi
        done
    fi
    [ "$dir" = / ] && break
    dir=$(dirname -- "$dir")
done
for name in config config.toml; do
    [ -e "$cargo_home/$name" ] || continue
    python3 -I -c '
import sys
path = sys.argv[1]
def refuse(message):
    sys.exit("scripts/build.sh: refused: %s %s; build.sh runs cargo in a closed configuration (C6a recheck 1 HIGH 5)" % (path, message))
try:
    import tomllib
except ImportError:
    refuse("cannot be checked without Python 3.11 (tomllib)")
try:
    config = tomllib.loads(open(path, encoding="utf-8").read())
except (OSError, ValueError) as error:
    refuse("is unreadable: %s" % error)
overridden = {"rustflags", "rustdocflags", "rustc", "rustc-wrapper", "rustc-workspace-wrapper"}
found = ["[env]"] if "env" in config else []
found += ["build." + k for k in config.get("build", {}) if k not in overridden]
found += ["target.%s.%s" % (t, k) for t, table in config.get("target", {}).items()
          for k in (table if isinstance(table, dict) else {"": None}) if k not in ("rustflags", "rustdocflags")]
if found:
    refuse("sets " + ", ".join(found))
' "$cargo_home/$name" || exit 2
done

targets=
tail=
previous=
for arg do
    if [ "$previous" = --target ]; then
        targets="$targets $arg"
    fi
    previous=$arg
    case $arg in
        --)
            tail=1
            break ;;
        --target=*) targets="$targets ${arg#--target=}" ;;
        --features | --features=* | --all-features | --all-features=* | \
            --no-default-features | --no-default-features=*)
            refuse "$arg selects features; the profile's are the only ones (dependency-gate.json)" ;;
        --manifest-path | --manifest-path=* | --config | --config=*)
            refuse "$arg selects another manifest or configuration" ;;
        --*) ;;
        -*F* | -*Z*)
            refuse "$arg selects features or unstable flags (-F, -Z)" ;;
    esac
done

if [ -n "$tail" ] && [ "$command" != test ]; then
    case $command in
        clippy) refuse "clippy takes no arguments after --; build.sh passes its fixed list (-D warnings -D clippy::disallowed_methods)" ;;
        *) refuse "$command takes no arguments after --" ;;
    esac
fi
if [ -n "$static" ] && [ -z "$targets" ]; then
    refuse "--crt-static needs --target, so build scripts and procedural macros stay dynamic"
fi

# The profile's features, checked against the workspace members' own feature tables.
gate=$repo/dependency-gate.json
members=$(cd "$repo" && cargo ${toolchain:+"$toolchain"} metadata --no-deps --format-version 1 --locked)
features=$(printf '%s' "$members" | python3 -I -c '
import json, re, sys
gate, profile = sys.argv[1], sys.argv[2]
def refuse(message):
    sys.exit("scripts/build.sh: refused: " + message)
profiles = json.load(open(gate)).get("profiles")
if not isinstance(profiles, dict) or profile not in profiles:
    refuse("%s is not a profile in dependency-gate.json (%s)"
           % (profile, ", ".join(sorted(profiles or {}))))
features = profiles[profile].get("features") if isinstance(profiles[profile], dict) else None
if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
    refuse("profile %s has no list of features" % profile)
declared = {p["name"]: set(p["features"]) for p in json.load(sys.stdin)["packages"]}
for feature in features:
    match = re.fullmatch(r"([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)", feature)
    if not match or feature.split("/")[1] not in declared.get(match.group(1), ()):
        refuse("profile %s selects %s, which is not a feature a workspace member declares"
               % (profile, feature))
print(",".join(features))
' "$gate" "$profile")

# Compiler flags come from here alone. The empty encoded variables take precedence over
# every Cargo config table; the --config resets say the same to the config layer.
host=$(rustc ${toolchain:+"$toolchain"} -vV | sed -n 's/^host: //p')
[ -n "$host" ] || refuse "rustc reported no host triple"
set -- --locked --config 'build.rustflags=[]' --config 'build.rustdocflags=[]' "$@"
for triple in $host $targets; do
    case $triple in
        *[!A-Za-z0-9_-]*) refuse "--target $triple is not a target triple" ;;
    esac
    set -- --config "target.$triple.rustflags=[]" \
        --config "target.$triple.runner=[\"/bin/sh\", \"-c\", \"exec \\\"\$0\\\" \\\"\$@\\\"\"]" "$@"
done
if [ -n "$static" ]; then
    CARGO_ENCODED_RUSTFLAGS=-Ctarget-feature=+crt-static
else
    CARGO_ENCODED_RUSTFLAGS=
fi
CARGO_ENCODED_RUSTDOCFLAGS=
RUSTC=rustc
RUSTC_WRAPPER=
RUSTC_WORKSPACE_WRAPPER=
export CARGO_ENCODED_RUSTFLAGS CARGO_ENCODED_RUSTDOCFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
if [ -n "$features" ]; then
    set -- --features "$features" "$@"
fi
if [ "$command" = clippy ]; then
    set -- "$@" -- -D warnings -D clippy::disallowed_methods
fi

cd "$repo"
if [ -n "$full_suite" ]; then
    cargo ${toolchain:+"$toolchain"} "$command" --no-run "$@"
    registry_dir=$(mktemp -d)
    trap 'rm -rf "$registry_dir"' EXIT
    trap 'exit 1' HUP INT TERM
    # The one run, built above, its libtest lines kept for the ledger check.
    {
        status=0
        cargo ${toolchain:+"$toolchain"} "$command" "$@" 2>&1 || status=$?
        echo "$status" >"$registry_dir/status"
    } | tee "$registry_dir/run"
    status=$(cat "$registry_dir/status")
    [ "$status" = 0 ] || exit "$status"
    # Merge streams at the producer so each Running header precedes its entries.
    cargo ${toolchain:+"$toolchain"} "$command" "$@" -- --list >"$registry_dir/all" 2>&1 || { cat "$registry_dir/all" >&2; exit 1; }
    cargo ${toolchain:+"$toolchain"} "$command" "$@" -- --list --ignored >"$registry_dir/ignored" 2>&1 || { cat "$registry_dir/ignored" >&2; exit 1; }
    python3 -I scripts/checkpoint-ledger.py --self-test
    python3 -I scripts/checkpoint-ledger.py crates/kilnd/tests/data/checkpoint-acceptance-matrix.json \
        "$registry_dir/run" "$registry_dir/all" "$registry_dir/ignored" "$(uname -s)"
else
    exec cargo ${toolchain:+"$toolchain"} "$command" "$@"
fi
