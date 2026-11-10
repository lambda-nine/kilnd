#!/bin/bash
# Sandbox expiry under the installed daemon (API additions M1): real kiln sandboxes
# expire by lifetime (canceling a running command) and by idle, the restart grace
# holds idle but not lifetime, Renew moves only idle, a restart keeps deadlines, a
# sandbox without a policy never expires, and refusals name their reason. It restarts
# kilnd once and takes about three minutes. Run inside the VM as your user after
# scripts/install.sh:
#   scripts/expiry-regressions.sh
set -euo pipefail

ctl() { sudo kilndctl "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
small=(--memory 64M --disk 16M)
created=()
exec_client=
out=$(mktemp -d)
cleanup() {
    if [ -n "$exec_client" ]; then
        kill "$exec_client" 2>/dev/null || true
        wait "$exec_client" 2>/dev/null || true
    fi
    for s in "${created[@]}"; do ctl rm "$s" >/dev/null 2>&1 || true; done
    rm -f "$out"/*
    rmdir "$out"
}
trap cleanup EXIT

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
    wait_ready
}
create() {
    local id
    id=$(ctl create "${small[@]}" "$@")
    created+=("$id")
    echo "$id"
}
state_of() { ctl get "$1" | awk '/^state:/ { print $2 }'; }
reason_of() { ctl get "$1" | awk '/^deleted by:/ { print $3 }'; }
backend_of() { ctl get "$1" | awk '/^backend:/ { print $3 }'; }
now() { date +%s; }
# Waits until $1 is deleted, no later than $2 (epoch seconds).
wait_deleted() {
    local id=$1 by=$2
    while [ "$(state_of "$id")" != deleted ]; do
        [ "$(now)" -le "$by" ] || fail "$id is still $(state_of "$id") at the deadline"
        sleep 1
    done
}
backend_gone() {
    if sudo kiln ls | grep -q "^$1[[:space:]]"; then fail "kiln still has $1"; fi
}

echo "1. Health lists the expiry features"
wait_ready
health=$(ctl health)
grep -q '^features: .*sandbox_expiry' <<<"$health" || fail "no sandbox_expiry feature: $health"
grep -q '^features: .*typed_reasons' <<<"$health" || fail "no typed_reasons feature"
grep -q '^expiry: ' <<<"$health" || fail "no expiry stats"

echo "2. Out-of-range policies are refused before anything is created"
before=$(sudo kiln ls | wc -l)
for flags in "--max-lifetime 9s" "--idle-timeout 9s" "--max-lifetime 8d" "--idle-timeout 25h"; do
    # shellcheck disable=SC2086
    if ctl create "${small[@]}" $flags >"$out/refused" 2>&1; then
        created+=("$(cat "$out/refused")")
        fail "create $flags succeeded"
    fi
    grep -q 'invalidargument: ' "$out/refused" || fail "create $flags: $(cat "$out/refused")"
done
[ "$(sudo kiln ls | wc -l)" = "$before" ] || fail "a refused create reached the backend"

echo "3. A restart starts the idle grace; lifetime has none"
restart_kilnd
started=$(now)
never=$(create)
grace_idle=$(create --idle-timeout 10s)
lifetime=$(create --max-lifetime 15s)
lifetime_backend=$(backend_of "$lifetime")
ctl get "$lifetime" | grep -q '^expiry: *lifetime 15 s, idle never' || fail "effective policy not shown"
ctl get "$lifetime" | grep -q '(lifetime)' || fail "lifetime deadline not shown"
sudo -n kilndctl exec --timeout 120s "$lifetime" -- sleep 100 \
    </dev/null >"$out/exec.out" 2>"$out/exec.err" &
exec_client=$!
for _ in $(seq 100); do
    ctl get "$lifetime" | awk '$1 ~ /^ex-/ && $2 == "running"' | grep -q . && break
    sleep 0.1
done
running=$(ctl get "$lifetime" | awk '$1 ~ /^ex-/ { print $1; exit }')
[ -n "$running" ] || fail "the long command never started"
wait_deleted "$lifetime" $((started + 60))
[ "$(reason_of "$lifetime")" = expired_lifetime ] || fail "lifetime reason $(reason_of "$lifetime")"
backend_gone "$lifetime_backend"
wait "$exec_client" || true
exec_client=
summary=$(ctl execution "$running" 2>&1 >/dev/null)
grep -q '^state: *canceled$' <<<"$summary" || fail "running command not canceled: $summary"
grep -q '^canceled: *sandbox_expired_lifetime$' <<<"$summary" || fail "no cancel reason: $summary"
if ctl exec "$lifetime" -- true >"$out/refused" 2>&1; then fail "exec on an expired sandbox ran"; fi
grep -q 'failedprecondition: expired_lifetime: ' "$out/refused" || fail "untyped refusal: $(cat "$out/refused")"
# The restart grace (60 s) still holds the 10 s idle timeout.
[ "$(state_of "$grace_idle")" = ready ] || fail "idle expired inside the restart grace"
grace_backend=$(backend_of "$grace_idle")
wait_deleted "$grace_idle" $((started + 120))
[ "$(now)" -ge $((started + 59)) ] || fail "idle expired before the grace ended"
[ "$(reason_of "$grace_idle")" = expired_idle ] || fail "idle reason $(reason_of "$grace_idle")"
backend_gone "$grace_backend"
if ctl renew "$grace_idle" >"$out/refused" 2>&1; then fail "renew of an expired sandbox succeeded"; fi
grep -q 'failedprecondition: expired_idle: ' "$out/refused" || fail "untyped renew refusal: $(cat "$out/refused")"

echo "4. Renew and executions are activity; observers are not"
renewed=$(create --idle-timeout 15s)
for _ in 1 2 3 4 5 6; do
    sleep 5
    ctl renew "$renewed" >/dev/null
done
ctl exec "$renewed" -- true
[ "$(state_of "$renewed")" = ready ] || fail "a renewed sandbox expired"
quiet=$(now)
for _ in $(seq 10); do ctl get "$renewed" >/dev/null; ctl ls >/dev/null; sleep 1; done
wait_deleted "$renewed" $((quiet + 50))
[ "$(now)" -ge $((quiet + 14)) ] || fail "idle expired before its timeout"
[ "$(reason_of "$renewed")" = expired_idle ] || fail "renewed reason $(reason_of "$renewed")"

echo "5. A daemon restart keeps a lifetime deadline"
kept=$(create --max-lifetime 30s)
kept_at=$(now)
sleep 5
restart_kilnd
[ "$(state_of "$kept")" = ready ] || fail "sandbox lost across restart"
wait_deleted "$kept" $((kept_at + 70))
[ "$(now)" -ge $((kept_at + 29)) ] || fail "lifetime expired early after restart"
[ "$(reason_of "$kept")" = expired_lifetime ] || fail "kept reason $(reason_of "$kept")"

echo "6. A sandbox without a policy never expired; stats add up"
[ "$(state_of "$never")" = ready ] || fail "a sandbox without a policy is $(state_of "$never")"
ctl get "$never" | grep -q '^expiry:' && fail "a sandbox without a policy shows an expiry"
ctl rm "$never" >/dev/null
[ "$(reason_of "$never")" = requested ] || fail "user delete reason $(reason_of "$never")"
expiry=$(ctl health | awk '/^expiry:/')
grep -q '0 pending deletes' <<<"$expiry" || fail "pending expiry deletes: $expiry"
grep -q '0 failed attempts' <<<"$expiry" || fail "failed expiry deletes: $expiry"
ctl health | grep -q '^active sandboxes: *0' || fail "expiry regressions left active sandboxes"
echo "PASS"
