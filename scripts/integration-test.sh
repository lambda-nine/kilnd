#!/bin/sh
# Opt-in Linux integration tests: first a dedicated-child admission resource
# soak, then kilnd's manager against the installed kiln CLI with a temporary
# database, then the Firecracker executable-handoff property tests. Run inside the VM as your user after kiln's setup and install:
#   scripts/integration-test.sh
set -eu
cd "$(dirname "$0")/.."
cargo test --locked -p kilnd --test admission_stress -- --ignored --test-threads=1 --nocapture
bin=$(cargo test --locked -p kilnd --test kiln_integration --no-run --message-format=json \
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
lib=$(cargo test --locked -p kilnd --lib --no-run --message-format=json \
    | python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "kilnd" and m["profile"]["test"]:
        print(m["executable"])
')
[ -n "$lib" ] || { echo "library test binary not found" >&2; exit 1; }
sudo "$lib" --ignored --test-threads=1 --nocapture exit5_linux_root
# The per-instance account tests run processes under other real accounts, which need to
# reach this image, wherever the build directory is. Numeric accounts leave no users behind.
copy=$(mktemp -d)
trap 'rm -rf "$copy"' EXIT
install -m 755 "$lib" "$copy/kilnd-lib-tests"
chmod 755 "$copy"
sudo "$copy/kilnd-lib-tests" --ignored --test-threads=1 --nocapture b3_linux_root
sudo "$copy/kilnd-lib-tests" --ignored --test-threads=1 --nocapture b3r_
