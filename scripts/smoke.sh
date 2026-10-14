#!/bin/bash
# End-to-end smoke test through the installed service: kilndctl → the socket
# → kilnd → kiln create/exec/rm, with results checked in SQLite and in
# `kiln ls`. Also restarts and kills kilnd to check that sandboxes survive
# and reconciliation repairs state. Run inside the VM as your user after
# scripts/install.sh:
#   scripts/smoke.sh
set -euo pipefail

db=/var/lib/kilnd/kilnd.db
ctl() { sudo kilndctl "$@"; }
sql() { sudo sqlite3 -batch -noheader "$db" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_ready() {
    for _ in $(seq 100); do
        ctl health >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    fail "kilnd did not come back"
}
backend_of() { ctl get "$1" | awk '/^backend:/ {print $3}'; }
created=()
cleanup() {
    for s in "${created[@]}"; do sudo kilndctl rm "$s" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

echo "1. Health"
wait_ready
ctl health

echo "2. Socket ownership and permissions"
[ "$(stat -c '%U:%G %a' /run/kilnd)" = "root:kilnd 750" ] || fail "/run/kilnd is $(stat -c '%U:%G %a' /run/kilnd)"
[ "$(sudo stat -c '%U:%G %a' /run/kilnd/kilnd.sock)" = "root:kilnd 660" ] || fail "socket permissions"
[ "$(sudo stat -c '%U %a' /var/lib/kilnd)" = "root 700" ] || fail "/var/lib/kilnd permissions"
if ! id -nG | grep -qw kilnd; then
    if kilndctl health >/dev/null 2>&1; then fail "a user outside the kilnd group reached the socket"; fi
fi
nobody_out=$(sudo -u nobody kilndctl health 2>&1 || true)
echo "$nobody_out" | grep -qi "permission denied" || fail "nobody was not refused: $nobody_out"

echo "3. kilndctl create → kilnd → kiln create → kiln exec → SQLite → kiln rm"
id=$(ctl create --memory 128M --cpus 0.5 --pids 64 --disk 64M --label purpose=smoke)
created+=("$id")
backend=$(backend_of "$id")
echo "sandbox $id is kiln $backend"
sudo kiln ls | grep -q "^$backend[[:space:]]running" || fail "kiln ls does not show $backend"
[ "$(sql "SELECT state FROM sandboxes WHERE id = '$id'")" = ready ] || fail "sandbox not recorded as ready"
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

echo "   executions recorded in SQLite:"
sql "SELECT state, IFNULL(exit_code, '-'), stdout_bytes, stdout_truncated, stderr_bytes, IFNULL(failure_reason, '')
     FROM executions WHERE sandbox_id = '$id' ORDER BY started_at_ms" | sed 's/^/   /'
[ "$(sql "SELECT COUNT(*) FROM executions WHERE sandbox_id = '$id'")" -eq 7 ] || fail "expected 7 executions"
[ "$(sql "SELECT exit_code || ':' || CAST(stderr AS TEXT) FROM executions WHERE sandbox_id = '$id' AND exit_code = 7")" = "7:bad" ] || fail "exit status and stderr not persisted"
[ "$(sql "SELECT COUNT(*) FROM executions WHERE sandbox_id = '$id' AND state = 'timed_out'")" -eq 1 ] || fail "timeout not persisted"
ctl get "$id"

echo "4. Restarting kilnd keeps the sandbox"
sudo systemctl restart kilnd
wait_ready
ctl get "$id" | grep -q '^state: *ready' || fail "sandbox not ready after restart"
[ "$(ctl exec "$id" -- cat /workspace/note)" = note ] || fail "sandbox state lost across restart"

echo "5. Killing kilnd mid-exec interrupts the execution, not the sandbox"
ctl exec --timeout 60s "$id" -- sleep 30 >/dev/null 2>&1 &
for _ in $(seq 50); do
    [ "$(sql "SELECT COUNT(*) FROM executions WHERE state = 'running'")" -eq 1 ] && break
    sleep 0.1
done
sudo kill -9 "$(systemctl show -p MainPID --value kilnd)"
wait || true
wait_ready
[ "$(sql "SELECT COUNT(*) FROM executions WHERE sandbox_id = '$id' AND state = 'interrupted'")" -eq 1 ] \
    || fail "killed execution not marked interrupted"
[ "$(ctl exec --timeout 10s "$id" -- sh -c 'pgrep sleep || echo none')" = none ] \
    || fail "orphaned command still running after kilnd was killed"

echo "6. Delete"
ctl rm "$id"
if sudo kiln ls | grep -q "^$backend[[:space:]]"; then fail "kiln still has $backend"; fi
[ "$(sql "SELECT state FROM sandboxes WHERE id = '$id'")" = deleted ] || fail "sandbox not recorded as deleted"
ctl rm "$id" >/dev/null || fail "second delete was not idempotent"

echo "7. A sandbox removed behind kilnd's back is lost after restart"
lost=$(ctl create --memory 64M --disk 16M)
created+=("$lost")
sudo kiln rm "$(backend_of "$lost")"
sudo systemctl restart kilnd
wait_ready
ctl get "$lost" | grep -q '^state: *lost' || fail "sandbox not marked lost"
ctl rm "$lost" >/dev/null

echo "8. One-shot run"
[ "$(ctl run --memory 64M --disk 16M -- echo one-shot)" = one-shot ] || fail "run"

echo "9. Structured logs"
logs=$(sudo journalctl -u kilnd --since "-5min" --no-pager -o cat)
line=$(grep '"message":"exec finished"' <<<"$logs" | tail -1)
[ -n "$line" ] || fail "no JSON exec log lines"
python3 -I -c 'import json, sys; e = json.loads(sys.argv[1]); assert e["execution"] and e["state"]' "$line" \
    || fail "log line is not structured JSON: $line"
echo "$line"

[ "$(sql "SELECT COUNT(*) FROM sandboxes WHERE state IN ('creating', 'ready', 'deleting')")" -eq 0 ] \
    || fail "smoke test left active sandboxes"
echo "PASS"
