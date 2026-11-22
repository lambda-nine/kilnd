# output-flood test, run inside one guest session only (busybox sh; sent as
# `sh -s -- SECONDS`). Writes zeros to stdout and stderr as fast as it can for SECONDS. kilnd
# must keep a bounded capture and report the rest as truncated, never lose it silently. The
# guest console stays quiet: an exec's output goes over vsock, not the serial console.
limit=${1:-20}
timeout "$limit" cat /dev/zero >&2 &
timeout "$limit" cat /dev/zero
wait
