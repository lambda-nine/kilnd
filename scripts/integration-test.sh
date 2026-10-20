#!/bin/sh
# Opt-in Linux integration tests: first a dedicated-child admission resource
# soak, then kilnd's manager against the installed kiln CLI with a temporary
# database. Run inside the VM as your user after kiln's setup and install:
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
