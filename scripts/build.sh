#!/bin/sh
# kilnd's one supported build entry point (design section 7.1's dependency gate; B7
# milestone 2 recheck 2 HIGH-1). CI, scripts/install.sh, the binaries scripts/upgrade.sh
# installs and the VM scripts all run cargo through it:
#
#   scripts/build.sh [+TOOLCHAIN] PROFILE COMMAND [CARGO-ARGUMENT...] [-- ARGUMENT...]
#
# PROFILE is one of the `profiles` in dependency-gate.json, the same list the gate
# resolves and reviews (`default`, `firecracker-test-deployment`). COMMAND is build,
# test, clippy or check. It runs, from the workspace root,
#
#   cargo [+TOOLCHAIN] COMMAND --locked [--features PROFILE'S] CARGO-ARGUMENT... [-- ARGUMENT...]
#
# A profile enables only workspace features (member/feature) its member declares; a
# dependency's feature is forwarded through one, checked in. Before `--`, it refuses
# every argument that would select features or another graph: --features and -F (and so
# `dep/feature` selectors), --all-features, --no-default-features, --manifest-path,
# --config and -Z, however cargo accepts them spelled (`--features=x`, `-Fx`, `-rF x`).
# Arguments after `--` go to the test harness or clippy-driver, not to cargo's resolver.
#
# The gate's guarantee covers builds made this way. A raw `cargo build` with other
# feature flags builds a graph the gate has not reviewed.
set -eu
repo=$(cd "$(dirname -- "$0")/.." && pwd)
usage() {
    echo "usage: $0 [+TOOLCHAIN] PROFILE build|test|clippy|check [CARGO-ARGUMENT...] [-- ARGUMENT...]" >&2
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
[ "$#" -ge 2 ] || usage
profile=$1 command=$2
shift 2
case $command in
    build | test | clippy | check) ;;
    *) refuse "$command is not a supported command (build, test, clippy or check)" ;;
esac

for arg do
    case $arg in
        --) break ;;
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

cd "$repo"
if [ -n "$features" ]; then
    exec cargo ${toolchain:+"$toolchain"} "$command" --locked --features "$features" "$@"
fi
exec cargo ${toolchain:+"$toolchain"} "$command" --locked "$@"
