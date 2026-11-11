#!/bin/sh
# Opt-in Linux integration tests: first a dedicated-child admission resource
# soak and its ExecStream phase, then kilnd's manager against the installed kiln CLI with a temporary
# database, then the Firecracker executable-handoff property tests. Run inside the VM as your user after kiln's setup and install:
#   scripts/integration-test.sh
set -eu
cd "$(dirname "$0")/.."
scripts/build.sh default test -p kilnd --test admission_stress -- --ignored --test-threads=1 --nocapture
# Processes under other real accounts (the ExecStream stress phase's client uids and the
# per-instance account tests below) need to reach these test images, wherever the build
# directory is. Numeric accounts leave no users behind.
copy=$(mktemp -d)
trap 'rm -rf "$copy"' EXIT
chmod 755 "$copy"
stress=$(scripts/build.sh default test -p kilnd --test admission_stress --no-run --message-format=json \
    | python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "admission_stress":
        print(m["executable"])
')
[ -n "$stress" ] || { echo "admission stress binary not found" >&2; exit 1; }
install -m 755 "$stress" "$copy/admission-stress"
# ExecStream's stream phase (API additions design 8): 16 non-reading streams from two
# client uids, another uid's Health and Exec, as root.
sudo "$copy/admission-stress" --ignored --exact exec_stream_resources_bound_and_recover --test-threads=1 --nocapture
bin=$(scripts/build.sh default test -p kilnd --test kiln_integration --no-run --message-format=json \
    | python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "kiln_integration":
        print(m["executable"])
')
[ -n "$bin" ] || { echo "integration test binary not found" >&2; exit 1; }
sudo env KILND_INTEGRATION=1 KILN_BIN="${KILN_BIN:-/usr/local/bin/kiln}" "$bin" --ignored --test-threads=1 --nocapture
# Firecracker B3's retained-descriptor evidence: real traversal from /, real ACLs and
# file capabilities, real execveat and /proc/<pid>/exe tuples. It launches no VM.
lib=$(scripts/build.sh default test -p kilnd --lib --no-run --message-format=json \
    | python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "kilnd" and m["profile"]["test"]:
        print(m["executable"])
')
[ -n "$lib" ] || { echo "library test binary not found" >&2; exit 1; }
sudo "$lib" --ignored --test-threads=1 --nocapture exit5_linux_root
install -m 755 "$lib" "$copy/kilnd-lib-tests"
sudo "$copy/kilnd-lib-tests" --ignored --test-threads=1 --nocapture b3_linux_root
sudo "$copy/kilnd-lib-tests" --ignored --test-threads=1 --nocapture b3r_
