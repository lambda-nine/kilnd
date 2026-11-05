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
    esac
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
    set -- --config "target.$triple.rustflags=[]" "$@"
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
exec cargo ${toolchain:+"$toolchain"} "$command" "$@"
