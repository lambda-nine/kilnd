# memory-limit test, run inside one guest session only (busybox sh; sent as
# `sh -s -- SECONDS`). Doubles a string in awk until the guest's memory runs out and its own
# OOM killer ends awk, or SECONDS pass. The host side must see no OOM of its own.
limit=${1:-60}
timeout "$limit" awk 'BEGIN {
    s = "xxxxxxxxxxxxxxxx"
    for (i = 0; i < 40; i++) {
        s = s s
        printf "memory-limit test: %d MiB\n", length(s) / 1048576
        fflush()
    }
}'
echo "memory-limit test: awk exit $?"
free 2>/dev/null | head -2
