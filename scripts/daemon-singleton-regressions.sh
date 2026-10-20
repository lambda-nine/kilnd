#!/bin/sh
# Privileged regression for daemon instance ownership. Run inside kiln's VM
# after installing this checkout. It leaves the installed service running.
set -eu

db=/var/lib/kilnd/kilnd.db
socket=/run/kilnd/kilnd.sock
tmp=$(mktemp -d /tmp/kilnd-singleton.XXXXXX)
sandbox=
exec_pid=

ctl() { sudo kilndctl "$@"; }
sql() { sudo sqlite3 -batch -noheader "$db" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
release_execution() {
    backend=$(sql "SELECT backend_id FROM sandboxes WHERE id = '$sandbox'") || return 1
    [ -n "$backend" ] || return 1
    cgroup="/sys/fs/cgroup/kiln/$backend/exec/cgroup.procs"
    pid=$(sudo sed -n '1p' "$cgroup") || return 1
    [ -n "$pid" ] || return 1
    sudo touch "/proc/$pid/root/tmp/kilnd-singleton-release"
}
cleanup() {
    if [ -n "$exec_pid" ]; then
        release_execution >/dev/null 2>&1 || true
        kill "$exec_pid" >/dev/null 2>&1 || true
        wait "$exec_pid" >/dev/null 2>&1 || true
    fi
    if [ -n "$sandbox" ]; then ctl rm "$sandbox" >/dev/null 2>&1 || true; fi
    sudo find "$tmp" -depth -delete >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "1. Start a real execution under the incumbent daemon"
ctl health >/dev/null
sandbox=$(ctl create --memory 64M --disk 16M)
ctl exec "$sandbox" -- sh -c \
    'while [ ! -e /tmp/kilnd-singleton-release ]; do sleep 0.1; done; printf singleton-ok' \
    >"$tmp/exec.out" 2>"$tmp/exec.err" &
exec_pid=$!
running=
for _ in $(seq 100); do
    running=$(sql "SELECT id FROM executions WHERE sandbox_id = '$sandbox' AND state = 'running' LIMIT 1")
    [ -n "$running" ] && break
    sleep 0.05
done
[ -n "$running" ] || fail "execution never became RUNNING"

service_pid=$(systemctl show -p MainPID --value kilnd)
socket_identity=$(sudo stat -Lc '%d:%i' "$socket")
state_lock_identity=$(sudo stat -Lc '%d:%i' /var/lib/kilnd/kilnd.lock)

echo "2. Same state directory with a different socket is rejected before bind"
set +e
sudo timeout 5s /usr/local/bin/kilnd \
    --kiln /usr/local/bin/kiln \
    --state-dir /var/lib/kilnd \
    --socket "$tmp/alternate.sock" \
    --socket-group '' >"$tmp/same-state.log" 2>&1
same_state_rc=$?
set -e
[ "$same_state_rc" -ne 0 ] && [ "$same_state_rc" -ne 124 ] || fail "same-state contender did not fail promptly"
grep -q 'state directory already owned' "$tmp/same-state.log" || fail "same-state rejection did not name the state lock"
[ ! -e "$tmp/alternate.sock" ] || fail "same-state contender created its alternate socket"

echo "3. Different state directory with the same socket is rejected before reconciliation"
set +e
sudo timeout 5s /usr/local/bin/kilnd \
    --kiln /usr/local/bin/kiln \
    --state-dir "$tmp/other-state" \
    --socket "$socket" \
    --socket-group kilnd >"$tmp/same-socket.log" 2>&1
same_socket_rc=$?
set -e
[ "$same_socket_rc" -ne 0 ] && [ "$same_socket_rc" -ne 124 ] || fail "same-socket contender did not fail promptly"
grep -q 'socket directory already owned' "$tmp/same-socket.log" || fail "same-socket rejection did not name the socket lock"
if grep -q 'reconciled with kiln' "$tmp/same-socket.log"; then fail "same-socket contender reconciled"; fi

echo "4. The incumbent and its active execution were untouched"
[ "$(systemctl show -p MainPID --value kilnd)" = "$service_pid" ] || fail "incumbent service restarted"
[ "$(sudo stat -Lc '%d:%i' "$socket")" = "$socket_identity" ] || fail "incumbent socket was replaced"
[ "$(sudo stat -Lc '%d:%i' /var/lib/kilnd/kilnd.lock)" = "$state_lock_identity" ] || fail "state lock inode changed"
[ "$(sql "SELECT state FROM executions WHERE id = '$running'")" = running ] || fail "active execution was changed"
ctl health >/dev/null

release_execution || fail "could not release the synchronized execution"
wait "$exec_pid"
exec_pid=
[ "$(cat "$tmp/exec.out")" = singleton-ok ] || fail "incumbent execution did not complete normally"
[ "$(sql "SELECT state FROM executions WHERE id = '$running'")" = exited ] || fail "execution did not finish EXITED"
ctl rm "$sandbox" >/dev/null
sandbox=

echo "PASS"
