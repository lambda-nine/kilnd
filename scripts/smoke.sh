#!/bin/bash
# End-to-end smoke test through the installed service: kilndctl → the socket
# → kilnd → kiln create/exec/rm, with results checked through the API and in
# `kiln ls`. Also restarts and kills kilnd to check that sandboxes survive
# and reconciliation repairs state. Run inside the VM as your user after
# scripts/install.sh:
#   scripts/smoke.sh
set -euo pipefail

ctl() { sudo kilndctl "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_ready() {
    for _ in $(seq 100); do
        ctl health >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    fail "kilnd did not come back"
}
restart_kilnd() {
    sudo systemctl reset-failed kilnd
    sudo systemctl restart kilnd
}
backend_of() { ctl get "$1" | awk '/^backend:/ {print $3}'; }
created=()
backend_created=()
api_tmp=
cleanup() {
    for s in "${created[@]}"; do sudo kilndctl rm "$s" >/dev/null 2>&1 || true; done
    for b in "${backend_created[@]}"; do
        sudo kiln rm "$b" >/dev/null 2>&1 || sudo kiln gc "$b" >/dev/null 2>&1 || true
    done
    if [[ -n "$api_tmp" && -d "$api_tmp" ]]; then
        rm -f "$api_tmp/exit125.out" "$api_tmp/exit125.err" \
            "$api_tmp/signal15.out" "$api_tmp/signal15.err" \
            "$api_tmp/launch.out" "$api_tmp/launch.err"
        rmdir "$api_tmp"
    fi
}
wait_backend_status() {
    local id=$1 status=$2
    for _ in $(seq 100); do
        sudo kiln ls | grep -q "^$id[[:space:]]$status[[:space:]]" && return 0
        sleep 0.1
    done
    fail "kiln did not report $id as $status"
}
trap cleanup EXIT

echo "1. Health"
wait_ready
ctl health

echo "2. Socket ownership and permissions"
[ "$(stat -c '%U:%G %a' /run/kilnd)" = "root:kilnd 750" ] || fail "/run/kilnd is $(stat -c '%U:%G %a' /run/kilnd)"
[ "$(sudo stat -c '%U:%G %a' /run/kilnd/kilnd.sock)" = "root:kilnd 660" ] || fail "socket permissions"
[ "$(sudo stat -c '%U %a' /var/lib/kilnd)" = "root 700" ] || fail "/var/lib/kilnd permissions"
db=/var/lib/kilnd/kilnd.db
[ "$(sudo stat -c '%U:%G %a %F %h' "$db")" = "root:root 600 regular file 1" ] || fail "kilnd.db metadata"
[ ! -L "$db" ] || fail "kilnd.db is a symlink"
for sidecar in "$db-wal" "$db-shm" "$db-journal"; do
    [ ! -e "$sidecar" ] ||
        [ "$(sudo stat -c '%U:%G %a %F %h' "$sidecar")" = "root:root 600 regular file 1" ] ||
        fail "unsafe SQLite sidecar: $sidecar"
done
if ! id -nG | grep -qw kilnd; then
    if kilndctl health >/dev/null 2>&1; then fail "a user outside the kilnd group reached the socket"; fi
fi
nobody_out=$(sudo -u nobody kilndctl health 2>&1 || true)
echo "$nobody_out" | grep -qi "permission denied" || fail "nobody was not refused: $nobody_out"

echo "3. kilndctl create → kilnd → kiln create → kiln exec → API → kiln rm"
id=$(ctl create --memory 128M --cpus 0.5 --pids 64 --disk 64M --label purpose=smoke)
created+=("$id")
backend=$(backend_of "$id")
echo "sandbox $id is kiln $backend"
sudo kiln ls | grep -q "^$backend[[:space:]]running" || fail "kiln ls does not show $backend"
ctl get "$id" | grep -q '^state: *ready' || fail "sandbox not recorded as ready"
[ "$(sudo cat "/sys/fs/cgroup/kiln/$backend/pids.max")" = 64 ] || fail "limits were not passed to kiln"

out=$(ctl exec "$id" -- sh -c 'echo "hello from $(hostname)"; echo note >/workspace/note')
[ "$out" = "hello from kiln" ] || fail "exec printed: $out"
[ "$(ctl exec "$id" -- cat /workspace/note)" = note ] || fail "state did not persist"
set +e
ctl exec "$id" -- sh -c 'echo bad >&2; exit 7' 2>/dev/null
code=$?
ctl exec --timeout 1s "$id" -- sh -c 'sleep 30 & sleep 30' 2>/dev/null
timeout_code=$?
set -e
[ "$code" -eq 7 ] || fail "exit code $code, expected 7"
[ "$timeout_code" -eq 124 ] || fail "timeout exit $timeout_code, expected 124"
[ "$(ctl exec "$id" -- sh -c 'pgrep sleep || echo none')" = none ] || fail "timed-out command still running"
printf 'piped' | ctl exec --stdin "$id" -- cat | grep -qx piped || fail "stdin was not passed"
ctl exec "$id" -- head -c 2000000 /dev/zero 2>&1 >/dev/null | grep -q 'stdout truncated: kept 1048576 of 2000000 bytes' \
    || fail "output was not bounded"
details=$(ctl get "$id")
echo "   executions recorded through the API:"
echo "$details"
[ "$(awk '$1 ~ /^ex-/ { count++ } END { print count + 0 }' <<<"$details")" -eq 7 ] || fail "expected 7 executions"
echo "$details" | awk '$1 ~ /^ex-/ && $2 == "exited" && $3 == "7" { found=1 } END { exit !found }' \
    || fail "exit status was not persisted"
echo "$details" | awk '$1 ~ /^ex-/ && $2 == "timed_out" { found=1 } END { exit !found }' \
    || fail "timeout not persisted"
bounded_id=$(echo "$details" | awk '$1 ~ /^ex-/ && /head -c 2000000/ { print $1; exit }')
[ -n "$bounded_id" ] || fail "bounded execution was not listed"
bounded_summary=$(ctl execution "$bounded_id" 2>&1 >/dev/null)
echo "$bounded_summary" | grep -q 'stdout truncated: kept 1048576 of 2000000 bytes' \
    || fail "bounded output accounting was not exact and truncated"

echo "   typed outcomes and binary evidence"
set +e
ctl exec "$id" -- sh -c 'printf "\000\377out"; printf "\000\376err" >&2; exit 125' >/dev/null 2>/dev/null
exit125=$?
ctl exec "$id" -- sh -c 'exit 143' >/dev/null 2>/dev/null
exit143=$?
ctl exec "$id" -- sh -c 'kill -TERM $$' >/dev/null 2>/dev/null
signal15=$?
ctl exec "$id" -- /no/such/program >/dev/null 2>/dev/null
launch_failure=$?
set -e
[ "$exit125:$exit143:$signal15" = '125:143:143' ] || fail "typed shell projections"
[ "$launch_failure" -eq 125 ] || fail "missing executable must fail as runtime error"
details=$(ctl get "$id")
exit125_id=$(echo "$details" | awk '$1 ~ /^ex-/ && $2 == "exited" && $3 == "125" { print $1; exit }')
signal15_id=$(echo "$details" | awk '$1 ~ /^ex-/ && /kill -TERM/ { print $1; exit }')
launch_id=$(echo "$details" | awk '$1 ~ /^ex-/ && $2 == "failed" && /\/no\/such\/program/ { print $1; exit }')
[ -n "$exit125_id" ] && [ -n "$signal15_id" ] && [ -n "$launch_id" ] || fail "typed execution IDs"

echo "4. Restarting kilnd keeps the sandbox"
restart_kilnd
wait_ready
ctl get "$id" | grep -q '^state: *ready' || fail "sandbox not ready after restart"
[ "$(ctl exec "$id" -- cat /workspace/note)" = note ] || fail "sandbox state lost across restart"
api_tmp=$(mktemp -d)
ctl execution "$exit125_id" >"$api_tmp/exit125.out" 2>"$api_tmp/exit125.err"
ctl execution "$signal15_id" >"$api_tmp/signal15.out" 2>"$api_tmp/signal15.err"
ctl execution "$launch_id" >"$api_tmp/launch.out" 2>"$api_tmp/launch.err"
python3 -I - "$api_tmp" <<'PY' || fail "typed API evidence after restart"
from pathlib import Path
import sys

root = Path(sys.argv[1])
assert (root / "exit125.out").read_bytes() == b"\0\xffout"
exit125 = (root / "exit125.err").read_bytes()
assert exit125.startswith(b"\0\xfeerr")
exit125_summary = exit125[5:].decode()
assert "state:    exited" in exit125_summary
assert "exit:     125" in exit125_summary
assert "kilndctl: runtime" not in exit125_summary

assert (root / "signal15.out").read_bytes() == b""
signal15 = (root / "signal15.err").read_text()
assert "kilndctl: terminated by signal 15" in signal15
assert "state:    exited" in signal15
assert "exit:     143" in signal15

assert (root / "launch.out").read_bytes() == b""
launch = (root / "launch.err").read_text()
assert "kilndctl: runtime LaunchFailed/Exec:" in launch
assert "state:    failed" in launch
assert "exit:" not in launch
PY

echo "5. Killing kilnd mid-exec interrupts the execution, not the sandbox"
ctl exec --timeout 60s "$id" -- sleep 30 >/dev/null 2>&1 &
for _ in $(seq 50); do
    ctl get "$id" | awk '$1 ~ /^ex-/ && $2 == "running" { found=1 } END { exit !found }' && break
    sleep 0.1
done
sudo kill -9 "$(systemctl show -p MainPID --value kilnd)"
wait || true
wait_ready
ctl get "$id" | awk '$1 ~ /^ex-/ && $2 == "interrupted" { found=1 } END { exit !found }' \
    || fail "killed execution not marked interrupted"
[ "$(ctl exec --timeout 10s "$id" -- sh -c 'pgrep sleep || echo none')" = none ] \
    || fail "orphaned command still running after kilnd was killed"

echo "6. Delete"
ctl rm "$id"
if sudo kiln ls | grep -q "^$backend[[:space:]]"; then fail "kiln still has $backend"; fi
ctl get "$id" | grep -q '^state: *deleted' || fail "sandbox not recorded as deleted"
ctl rm "$id" >/dev/null || fail "second delete was not idempotent"

echo "7. A sandbox removed behind kilnd's back is lost after restart"
lost=$(ctl create --memory 64M --disk 16M)
created+=("$lost")
sudo kiln rm "$(backend_of "$lost")"
restart_kilnd
wait_ready
ctl get "$lost" | grep -q '^state: *lost' || fail "sandbox not marked lost"
ctl rm "$lost" >/dev/null

echo "8. Reconciliation and shutdown preserve unmanaged live and stale sandboxes"
unmanaged_live=$(sudo kiln create --memory=64M --disk=16M)
backend_created+=("$unmanaged_live")
unmanaged_stale=$(sudo kiln create --memory=64M --disk=16M)
backend_created+=("$unmanaged_stale")
managed_stale=$(ctl create --memory 64M --disk 16M)
created+=("$managed_stale")
managed_backend=$(backend_of "$managed_stale")
sudo kill -9 "$(sudo cat "/var/lib/kiln/runs/$unmanaged_stale/shim.pid")"
sudo kill -9 "$(sudo cat "/var/lib/kiln/runs/$managed_backend/shim.pid")"
wait_backend_status "$unmanaged_stale" stale
wait_backend_status "$managed_backend" stale

restart_kilnd
wait_ready
ctl get "$managed_stale" | grep -q '^state: *lost' || fail "managed stale sandbox not marked lost"
if sudo kiln ls | grep -q "^$managed_backend[[:space:]]"; then
    fail "managed stale backend survived scoped GC"
fi
wait_backend_status "$unmanaged_live" running
wait_backend_status "$unmanaged_stale" stale

restart_kilnd
wait_ready
wait_backend_status "$unmanaged_live" running
wait_backend_status "$unmanaged_stale" stale
sudo systemctl stop kilnd
wait_backend_status "$unmanaged_live" running
wait_backend_status "$unmanaged_stale" stale
sudo systemctl reset-failed kilnd
sudo systemctl start kilnd
wait_ready

sudo kiln rm "$unmanaged_live"
sudo kiln gc "$unmanaged_stale"
ctl rm "$managed_stale"

echo "9. One-shot run"
[ "$(ctl run --memory 64M --disk 16M -- echo one-shot)" = one-shot ] || fail "run"

echo "10. Structured logs"
logs=$(sudo journalctl -u kilnd --since "-5min" --no-pager -o cat)
line=$(grep '"message":"exec finished"' <<<"$logs" | tail -1)
[ -n "$line" ] || fail "no JSON exec log lines"
python3 -I -c 'import json, sys; e = json.loads(sys.argv[1]); assert e["execution"] and e["state"]' "$line" \
    || fail "log line is not structured JSON: $line"
echo "$line"

ctl health | grep -q '^active sandboxes: *0' || fail "smoke test left active sandboxes"
echo "PASS"
