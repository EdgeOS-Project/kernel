#!/bin/sh
set -eu

group=/sys/fs/cgroup/edgeos-oom-group-test
probe=${1:-/root/memory_oom_group_abi_probe}
peer=

cleanup() {
    if [ -n "$peer" ]; then
        kill "$peer" 2>/dev/null || true
        wait "$peer" 2>/dev/null || true
    fi
    rmdir "$group" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

rmdir "$group" 2>/dev/null || true
mkdir "$group"
echo 1 > "$group/memory.oom.group"
echo 65536 > "$group/memory.max"
echo 0 > "$group/memory.swap.max"

sleep 120 &
peer=$!
echo "$peer" > "$group/cgroup.procs"

set +e
"$probe"
probe_status=$?
set -e

for attempt in 1 2 3 4 5; do
    if ! kill -0 "$peer" 2>/dev/null; then
        break
    fi
    sleep 1
done

if kill -0 "$peer" 2>/dev/null; then
    echo "MEMORY_OOM_GROUP_ABI_FAIL peer-survived"
    exit 1
fi
if [ "$probe_status" -ne 137 ]; then
    echo "MEMORY_OOM_GROUP_ABI_FAIL probe-status=$probe_status"
    exit 1
fi

oom_kill=$(awk '$1 == "oom_kill" { print $2 }' "$group/memory.events.local")
group_kill=$(awk '$1 == "oom_group_kill" { print $2 }' "$group/memory.events.local")
if [ "${oom_kill:-0}" -lt 2 ] || [ "${group_kill:-0}" -lt 1 ]; then
    echo "MEMORY_OOM_GROUP_ABI_FAIL events"
    cat "$group/memory.events.local"
    exit 1
fi

echo "MEMORY_OOM_GROUP_ABI_PASS oom_kill=$oom_kill oom_group_kill=$group_kill"
