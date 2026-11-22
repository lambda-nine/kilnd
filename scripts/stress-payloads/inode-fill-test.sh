# inode-fill test, run inside one guest session only (busybox sh; sent as
# `sh -s -- SECONDS`). Creates empty files under /workspace until no inode is left or
# SECONDS pass, and reports how many it made.
limit=${1:-60}
df -i /workspace 2>/dev/null | tail -1
mkdir -p /workspace/inode-fill
timeout "$limit" sh -c 'cd /workspace/inode-fill && i=0; while : > "f$i" 2>/dev/null; do i=$((i + 1)); done; echo "inode-fill test: stopped after $i files"'
echo "inode-fill test: exit $?"
df -i /workspace 2>/dev/null | tail -1
