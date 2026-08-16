#!/bin/sh
set -eu

output=/tmp/edgeos-pss-share-ready
probe=${PSS_SHARE_PROBE:-/root/pss_share_probe}
rm -f "$output"
"$probe" >"$output" &
probe_pid=$!
cleanup() {
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    rm -f "$output"
}
trap cleanup EXIT INT TERM

ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q '^READY$' "$output" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
test "$ready" -eq 1

rollup="/proc/$probe_pid/smaps_rollup"
rss=$(awk '$1 == "Rss:" { print $2; exit }' "$rollup")
pss=$(awk '$1 == "Pss:" { print $2; exit }' "$rollup")
shared_clean=$(awk '$1 == "Shared_Clean:" { print $2; exit }' "$rollup")
shared_dirty=$(awk '$1 == "Shared_Dirty:" { print $2; exit }' "$rollup")
locked=$(awk '$1 == "Locked:" { print $2; exit }' "$rollup")
test -n "$rss"
test -n "$pss"
test -n "$shared_clean"
test -n "$shared_dirty"
test -n "$locked"
test "$rss" -gt 16384
test "$pss" -gt 0
test "$pss" -lt "$rss"
test $((shared_clean + shared_dirty)) -gt 16384
test "$locked" -ge 4
echo "PSS_SHARE_RUNTIME_PASS rss_kb=$rss pss_kb=$pss shared_kb=$((shared_clean + shared_dirty)) locked_kb=$locked"

buddy_bytes=$(wc -c </proc/buddyinfo)
pagetype_bytes=$(wc -c </proc/pagetypeinfo)
test "$buddy_bytes" -gt 0
test "$pagetype_bytes" -gt 0
grep -q 'Node 0, zone' /proc/buddyinfo
grep -q 'Node 0, zone' /proc/pagetypeinfo
echo "MM_TOPOLOGY_RUNTIME_PASS buddy_bytes=$buddy_bytes pagetype_bytes=$pagetype_bytes"

meminfo=$(cat /proc/meminfo)
mem_total=$(printf '%s\n' "$meminfo" | awk '$1 == "MemTotal:" { print $2; exit }')
mem_free=$(printf '%s\n' "$meminfo" | awk '$1 == "MemFree:" { print $2; exit }')
mem_available=$(printf '%s\n' "$meminfo" | awk '$1 == "MemAvailable:" { print $2; exit }')
echo "MM_MEMORY_RUNTIME_VALUES total_kb=${mem_total:-missing} free_kb=${mem_free:-missing} available_kb=${mem_available:-missing}"
test -n "$mem_total"
test -n "$mem_free"
test -n "$mem_available"
test "$mem_total" -gt 0
test "$mem_free" -gt 0
test "$mem_free" -le "$mem_total"
test "$mem_available" -ge "$mem_free"
test "$mem_available" -le "$mem_total"
echo "MM_MEMORY_RUNTIME_PASS total_kb=$mem_total free_kb=$mem_free available_kb=$mem_available"
