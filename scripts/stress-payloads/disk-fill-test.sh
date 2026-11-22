# disk-fill test, run inside one guest session only (busybox sh; sent as
# `sh -s -- SECONDS`). Writes zeros into /workspace until its disk is full or SECONDS pass,
# then reports the disk's use. The host side must see its own free space unchanged: the
# session's disk is preallocated.
limit=${1:-90}
df -k /workspace | tail -1
timeout "$limit" dd if=/dev/zero of=/workspace/disk-fill bs=1048576 2>/workspace/dd.err
echo "disk-fill test: dd exit $?"
tail -2 /workspace/dd.err
df -k /workspace | tail -1
rm -f /workspace/disk-fill /workspace/dd.err
echo "disk-fill test: done"
