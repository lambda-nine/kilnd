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
exec_client=
eof_probe_dir=
service_needs_start=false
cleanup() {
    if [ -n "$exec_client" ]; then
        sudo kill -TERM "$exec_client" 2>/dev/null || true
        for _ in $(seq 20); do
            sudo kill -0 "$exec_client" 2>/dev/null || break
            sleep 0.1
        done
        sudo kill -KILL "$exec_client" 2>/dev/null || true
        wait "$exec_client" 2>/dev/null || true
    fi
    if [ -n "$eof_probe_dir" ]; then rm -rf "$eof_probe_dir"; fi
    if $service_needs_start; then
        sudo timeout --kill-after=5s 60s systemctl restart kilnd >/dev/null 2>&1 || true
    fi
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

running_execution() {
    ctl get "$id" | awk '$1 ~ /^ex-/ && $2 == "running" { print $1; exit }'
}
# Inspect the persistent init's root through /proc: another exec would queue
# behind the running command, and its output is not stored until it finishes.
marker_exists() {
    local pid
    while read -r pid; do
        if sudo test -s "/proc/$pid/root/workspace/$1"; then return 0; fi
    done < <(sudo cat "/sys/fs/cgroup/kiln/$backend/cgroup.procs")
    return 1
}
wait_running() {
    for _ in $(seq 100); do
        if [ -n "$(running_execution)" ] \
            && marker_exists "$1"; then return 0; fi
        sleep 0.1
    done
    fail "exec did not reach its detached-descendant marker: $1"
}
start_detached_exec() {
    local script
    script=$(cat <<'SH'
setsid sh -c 'sleep 120 & child=$!; kill -0 "$child" || exit 91; echo "$child" >"$1"; wait' sh "$1" &
sleep 120
SH
)
    sudo -n timeout --kill-after=5s 90s kilndctl exec --timeout 120s "$id" -- sh -c "$script" sh "/workspace/$1" \
        </dev/null >/dev/null 2>&1 &
    exec_client=$!
}
wait_exec_client() {
    for _ in $(seq 100); do
        sudo kill -0 "$exec_client" 2>/dev/null || break
        sleep 0.1
    done
    if sudo kill -0 "$exec_client" 2>/dev/null; then fail "exec client did not exit"; fi
    client_status=0
    wait "$exec_client" || client_status=$?
    exec_client=
}

echo "1. Health"
wait_ready
ctl health

echo "2. Socket ownership and permissions"
[ "$(stat -c '%U:%G %a' /run/kilnd)" = "kilnd:kilnd 750" ] || fail "/run/kilnd is $(stat -c '%U:%G %a' /run/kilnd)"
[ "$(sudo stat -c '%U:%G %a' /run/kilnd/kilnd.sock)" = "kilnd:kilnd 660" ] || fail "socket permissions"
[ "$(sudo stat -c '%U %a' /var/lib/kilnd)" = "kilnd 700" ] || fail "/var/lib/kilnd permissions"
db=/var/lib/kilnd/kilnd.db
[ "$(sudo stat -c '%U:%G %a %F %h' "$db")" = "kilnd:kilnd 600 regular file 1" ] || fail "kilnd.db metadata"
[ ! -L "$db" ] || fail "kilnd.db is a symlink"
for sidecar in "$db-wal" "$db-shm" "$db-journal"; do
    [ ! -e "$sidecar" ] ||
        [ "$(sudo stat -c '%U:%G %a %F %h' "$sidecar")" = "kilnd:kilnd 600 regular file 1" ] ||
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
timeout_out=$(ctl exec --timeout 1s "$id" -- sh -c '
    rm -f /workspace/timeout-ready
    setsid sh -c '\''sleep 30 & child=$!; kill -0 "$child" || exit 91; echo "$child" >/workspace/timeout-ready; wait'\'' &
    for attempt in $(seq 100); do
        [ -s /workspace/timeout-ready ] && break
        sleep 0.01
    done
    [ -s /workspace/timeout-ready ] || exit 90
    echo detached-ready
    sleep 30
' 2>/dev/null)
timeout_code=$?
set -e
[ "$code" -eq 7 ] || fail "exit code $code, expected 7"
[ "$timeout_code" -eq 124 ] || fail "timeout exit $timeout_code, expected 124"
[ "$timeout_out" = detached-ready ] || fail "timeout did not start its setsid descendant"
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

echo "4. Leader exit stops nohup/setsid descendants and closes inherited output"
# Drive kiln directly so kilnd's bounded drain cannot hide a missing EOF.
eof_probe_dir=$(mktemp -d)
mkfifo "$eof_probe_dir/output.fifo"
sudo -n kiln exec "$backend" -- sh -c '
    rm -f /workspace/leader-exit-ready
    nohup setsid sh -c '\''
        sleep 30 & child=$!
        kill -0 "$child" || exit 91
        echo detached-stdout
        echo detached-stderr >&2
        echo "$child" >/workspace/leader-exit-ready
        wait
    '\'' &
    for attempt in $(seq 100); do
        [ -s /workspace/leader-exit-ready ] && break
        sleep 0.01
    done
    [ -s /workspace/leader-exit-ready ] || exit 90
    echo leader-exit
    exit 23
' </dev/null >"$eof_probe_dir/output.fifo" 2>&1 &
exec_client=$!
# Keep the deadline armed until the reader sees EOF, even if the CLI has
# already exited while a leaked descendant still holds the FIFO open.
reader_status=0
timeout --kill-after=2s 5s cat "$eof_probe_dir/output.fifo" >"$eof_probe_dir/output" || reader_status=$?
[ "$reader_status" -eq 0 ] || fail "inherited-output reader status $reader_status, expected 0"
wait_exec_client
[ "$client_status" -eq 23 ] || fail "normal-exit status $client_status, expected 23"
marker_exists leader-exit-ready || fail "normal exit did not start its setsid descendant"
for line in detached-stdout detached-stderr leader-exit; do
    grep -qx "$line" "$eof_probe_dir/output" || fail "missing normal-exit output $line"
done
[ "$(ctl exec --timeout 10s "$id" -- sh -c 'pgrep sleep || echo none')" = none ] \
    || fail "normal leader exit left a detached descendant"
rm -rf "$eof_probe_dir"
eof_probe_dir=

echo "5. Restarting kilnd keeps the sandbox"
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

echo "6. Graceful kilnd shutdown cancels descendants after the configured grace"
start_detached_exec shutdown-ready
wait_running shutdown-ready
shutdown_exec=$(running_execution)
main_pid=$(systemctl show -p MainPID --value kilnd)
[ "$main_pid" -gt 0 ] || fail "kilnd has no MainPID"
service_needs_start=true
sudo kill -TERM "$main_pid"
# The installed unit's grace is 30 seconds, with a final 10-second wait.
for _ in $(seq 250); do
    [ "$(systemctl show -p MainPID --value kilnd)" != "$main_pid" ] && break
    sleep 0.2
done
[ "$(systemctl show -p MainPID --value kilnd)" = 0 ] || fail "kilnd did not exit after graceful shutdown"
[ "$(systemctl show -p ExecMainStatus --value kilnd)" = 0 ] || fail "kilnd did not exit cleanly"
wait_exec_client
[ "$client_status" -eq 125 ] || fail "canceled exec client status $client_status, expected 125"
sudo systemctl start kilnd
wait_ready
service_needs_start=false
summary=$(ctl execution "$shutdown_exec" 2>&1 >/dev/null)
grep -q '^state: *canceled$' <<<"$summary" && grep -q '^reason: *kilnd shut down$' <<<"$summary" \
    || fail "graceful shutdown was not recorded as canceled"
[ "$(ctl exec --timeout 10s "$id" -- sh -c 'pgrep sleep || echo none')" = none ] \
    || fail "graceful shutdown left a detached descendant"
[ "$(ctl exec --timeout 10s "$id" -- cat /workspace/note)" = note ] || fail "sandbox unusable after graceful shutdown"

echo "7. Abrupt kilnd death interrupts the execution, not the sandbox"
start_detached_exec abrupt-ready
wait_running abrupt-ready
interrupted_exec=$(running_execution)
main_pid=$(systemctl show -p MainPID --value kilnd)
[ "$main_pid" -gt 0 ] || fail "kilnd has no MainPID"
service_needs_start=true
sudo kill -KILL "$main_pid"
wait_exec_client
wait_ready
service_needs_start=false
summary=$(ctl execution "$interrupted_exec" 2>&1 >/dev/null)
grep -q '^state: *interrupted$' <<<"$summary" || fail "killed execution not marked interrupted"
[ "$(ctl exec --timeout 10s "$id" -- sh -c 'pgrep sleep || echo none')" = none ] \
    || fail "orphaned command still running after kilnd was killed"

echo "8. Delete"
ctl rm "$id"
if sudo kiln ls | grep -q "^$backend[[:space:]]"; then fail "kiln still has $backend"; fi
ctl get "$id" | grep -q '^state: *deleted' || fail "sandbox not recorded as deleted"
ctl rm "$id" >/dev/null || fail "second delete was not idempotent"

echo "9. A sandbox removed behind kilnd's back is lost after restart"
lost=$(ctl create --memory 64M --disk 16M)
created+=("$lost")
sudo kiln rm "$(backend_of "$lost")"
restart_kilnd
wait_ready
ctl get "$lost" | grep -q '^state: *lost' || fail "sandbox not marked lost"
ctl rm "$lost" >/dev/null

echo "10. Reconciliation and shutdown preserve unmanaged live and stale sandboxes"
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

echo "11. One-shot run"
[ "$(ctl run --memory 64M --disk 16M -- echo one-shot)" = one-shot ] || fail "run"

echo "12. A preflight create failure releases its reservation, including across restart"
node_reservations() { ctl health | awk '/^node reservations:/ { print $3, $4 }'; }
reserved_before=$(node_reservations)
backends_before=$(sudo kiln ls)
if missing_out=$(ctl create --image kilnd-smoke-definitely-missing --memory 64M --disk 16M 2>&1); then
    created+=("$missing_out")
    fail "missing-image create succeeded"
fi
missing_id=$(grep -oE 'sb-[0-9a-f]+' <<<"$missing_out" | sed -n 1p)
[ -n "$missing_id" ] || fail "missing-image create did not name its row: $missing_out"
created+=("$missing_id")
check_released_failure() {
    ctl get "$missing_id" | grep -q '^state: *failed' || fail "missing-image row is not failed"
    [ "$(node_reservations)" = "$reserved_before" ] || fail "missing-image create stayed charged"
    [ "$(sudo kiln ls)" = "$backends_before" ] || fail "missing-image create changed the backend"
}
check_released_failure
restart_kilnd
wait_ready
check_released_failure
ctl rm "$missing_id" >/dev/null || fail "missing-image row could not be deleted"
ctl get "$missing_id" | grep -q '^state: *deleted' || fail "missing-image row is not deleted"

echo "13. Structured logs"
logs=$(sudo journalctl -u kilnd --since "-5min" --no-pager -o cat)
line=$(grep '"message":"exec finished"' <<<"$logs" | tail -1)
[ -n "$line" ] || fail "no JSON exec log lines"
python3 -I -c 'import json, sys; e = json.loads(sys.argv[1]); assert e["execution"] and e["state"]' "$line" \
    || fail "log line is not structured JSON: $line"
echo "$line"

echo "14. Expiry policy and renew (scripts/expiry-regressions.sh waits out real deadlines)"
ctl health | grep -q '^features: .*sandbox_expiry' || fail "no sandbox_expiry feature"
expiring=$(ctl create --memory 64M --disk 16M --idle-timeout 1h --max-lifetime 2h)
created+=("$expiring")
ctl get "$expiring" | grep -q '^expiry: *lifetime 7200 s, idle 3600 s' || fail "effective policy not shown"
[ "$(ctl renew "$expiring")" = "$expiring ready" ] || fail "renew"
ctl rm "$expiring" >/dev/null
ctl get "$expiring" | grep -q '^deleted by: *requested' || fail "user delete reason not shown"

echo "15. Idempotent create (scripts/idempotent-create-regressions.sh covers crashes)"
ctl health | grep -q '^features: .*idempotent_create' || fail "no idempotent_create feature"
key="smoke-$$-$(date +%s)"
keyed=$(ctl create --memory 64M --disk 16M --request-id "$key" --idle-timeout 1h)
created+=("$keyed")
[ "$(ctl create --memory 64M --disk 16M --request-id "$key" --idle-timeout 1h)" = "$keyed" ] \
    || fail "a keyed retry created another sandbox"
ctl get "$keyed" | grep -q "^request id: *$key\$" || fail "request id not shown"
ctl rm --release-request-id "$keyed" >/dev/null
ctl get "$keyed" | grep -q "^request id: *$key (released)" || fail "release not shown"

echo "16. Exec cwd and env (needs kiln with exec options, bit 0x20)"
if ctl health | grep -q '^features: .*exec_env'; then
    opts=$(ctl create --memory 64M --disk 16M --default-env "SMOKE_DEFAULT=from-create")
    created+=("$opts")
    ctl get "$opts" | grep -q '^env: *SMOKE_DEFAULT (sha256 [0-9a-f]\{64\})' || fail "default env names not shown"
    # A relative script resolves in the cwd (the harness's fib.sh case).
    ctl exec "$opts" -- sh -c 'printf "%s\n" "#!/bin/sh" "a=0 b=1 i=0" "while [ \$i -lt \$1 ]; do t=\$((a + b)); a=\$b; b=\$t; i=\$((i + 1)); done" "echo \$a" >/workspace/fib.sh && chmod +x /workspace/fib.sh'
    [ "$(ctl exec --cwd /workspace "$opts" -- ./fib.sh 10)" = 55 ] || fail "./fib.sh in /workspace"
    out=$(ctl exec --cwd /workspace --env SMOKE_EXEC=from-exec \
        --env SMOKE_DEFAULT=overridden "$opts" -- sh -c 'pwd; echo "$SMOKE_DEFAULT $SMOKE_EXEC"')
    [ "$out" = "$(printf '/workspace\noverridden from-exec')" ] || fail "cwd and env: $out"
    [ "$(ctl exec "$opts" -- sh -c 'echo "$SMOKE_DEFAULT"; pwd')" = "$(printf 'from-create\n/')" ] \
        || fail "default env without options"
    if ctl exec --cwd /var/lib/kilnd-helper "$opts" -- true 2>"$api_tmp/launch.err"; then
        fail "a host-only cwd was entered"
    fi
    grep -q 'cwd_not_found' "$api_tmp/launch.err" || fail "missing cwd not typed: $(cat "$api_tmp/launch.err")"
    ctl rm "$opts" >/dev/null
else
    echo "   (kiln lacks exec options; checking that kilndctl refuses them)"
    plain=$(ctl create --memory 64M --disk 16M)
    created+=("$plain")
    if ctl exec --cwd /workspace "$plain" -- true 2>/dev/null; then fail "cwd sent without exec_cwd"; fi
    ctl rm "$plain" >/dev/null
fi

ctl health | grep -q '^active sandboxes: *0' || fail "smoke test left active sandboxes"
echo "PASS"
