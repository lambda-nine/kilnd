# pid-limit test, run inside one guest session only (busybox sh; the stress script sends it
# as `sh -s -- SECONDS`). Starts sleeping processes until the session refuses another fork,
# 4096 have started, or SECONDS pass, then stops them. A refused fork may end the shell
# itself, so it reports its count as it goes; the session's exec ends whatever is left.
limit=${1:-20}
end=$(( $(date +%s) + limit ))
started=0
previous=
while [ "$started" -lt 4096 ] && [ "$(date +%s)" -lt "$end" ]; do
    sleep "$limit" 2>/dev/null &
    [ "$!" != "$previous" ] || break
    previous=$!
    started=$((started + 1))
    [ $((started % 64)) -ne 0 ] || echo "pid-limit test: started $started"
done
echo "pid-limit test: started $started processes"
pkill -P $$ sleep 2>/dev/null
wait 2>/dev/null
echo "pid-limit test: done"
