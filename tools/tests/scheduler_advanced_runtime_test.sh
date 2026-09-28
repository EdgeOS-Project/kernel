#!/bin/sh
# Validate advanced Linux scheduler behavior in a booted EdgeOS guest.
set -eu

EXPECTED_CPUS=${EDGEOS_EXPECT_CPUS:-2}
SCHEDULER_PROBE=${EDGEOS_SCHEDULER_PROBE:-/opt/edgeos-tests/scheduler_runtime_probe}
FUTEX_PROBE=${EDGEOS_FUTEX_PROBE:-/opt/edgeos-tests/futex_runtime_probe}
CGROUP_TEST=${EDGEOS_CGROUP_TEST:-/opt/edgeos-tests/cgroup_cpu_hierarchy_runtime_test.sh}
AFFINITY_BUSY=${EDGEOS_AFFINITY_BUSY:-/opt/edgeos-tests/scheduler_affinity_busy}

fail() {
    echo "SCHEDULER_ADVANCED_FAIL $*"
    exit 1
}

run_policy() {
    name=$1
    shift
    output=$(chrt "$@" sh -c 'chrt -p $$') || fail "$name"
    echo "$output"
    echo "SCHEDULER_POLICY_PASS $name"
}

echo "SCHEDULER_ADVANCED_BEGIN"
online_count=$(getconf _NPROCESSORS_ONLN)
online_mask=$(cat /sys/devices/system/cpu/online)
echo "SCHEDULER_CPUS count=$online_count online=$online_mask"
[ "$online_count" -ge "$EXPECTED_CPUS" ] ||
    fail "online-cpus expected=$EXPECTED_CPUS actual=$online_count"

chrt -m
run_policy rr -r 10
run_policy fifo -f 20
run_policy batch -b 0
run_policy idle -i 0
run_policy deadline -d -R -T 1000000 -D 5000000 -P 10000000 0

[ -x "$SCHEDULER_PROBE" ] || fail "missing-scheduler-probe"
"$SCHEDULER_PROBE"

workers=""
cleanup_workers() {
    for pid in $workers; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in $workers; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup_workers EXIT INT TERM

before=/tmp/edgeos-scheduler-before.$$
after=/tmp/edgeos-scheduler-after.$$
awk '/^cpu[0-9]+ / { total=0; for (i=2; i<=NF; ++i) total += $i; print $1, total }' \
    /proc/stat > "$before"
cpu=0
while [ "$cpu" -lt "$online_count" ]; do
    if [ -x "$AFFINITY_BUSY" ]; then
        "$AFFINITY_BUSY" "$cpu" &
    else
        taskset -c "$cpu" sh -c 'while :; do :; done' &
    fi
    workers="$workers $!"
    cpu=$((cpu + 1))
done
for pid in $workers; do
    kill -0 "$pid" 2>/dev/null || fail "worker-start-$pid"
done
sleep 2
awk '/^cpu[0-9]+ / { total=0; for (i=2; i<=NF; ++i) total += $i; print $1, total }' \
    /proc/stat > "$after"
cleanup_workers
workers=""

while read -r name start; do
    end=$(awk -v cpu="$name" '$1 == cpu { print $2 }' "$after")
    [ -n "$end" ] || fail "missing-stat-$name"
    delta=$((end - start))
    echo "SCHEDULER_CPU_PROGRESS cpu=$name delta=$delta"
    [ "$delta" -gt 0 ] || fail "no-progress-$name"
done < "$before"
rm -f "$before" "$after"
echo "SCHEDULER_MULTICPU_PASS"

if [ "$online_count" -ge 2 ]; then
    sh -c 'while :; do :; done' &
    migrate_pid=$!
    workers="$migrate_pid"
    taskset -pc 0 "$migrate_pid"
    sleep 1
    taskset -pc 1 "$migrate_pid"
    sleep 1
    affinity=$(taskset -pc "$migrate_pid")
    processor=$(awk '{ print $39 }' "/proc/$migrate_pid/stat")
    echo "$affinity"
    echo "SCHEDULER_AFFINITY_PROCESSOR cpu=$processor"
    echo "$affinity" | grep -q ': 1$' || fail "live-affinity-migration"
    [ "$processor" = 1 ] || fail "live-affinity-processor-$processor"
    cleanup_workers
    workers=""
    echo "SCHEDULER_AFFINITY_MIGRATION_PASS"
fi

[ -x "$FUTEX_PROBE" ] || fail "missing-futex-probe"
"$FUTEX_PROBE"

[ -x "$CGROUP_TEST" ] || fail "missing-cgroup-test"
EDGEOS_AFFINITY_BUSY="$AFFINITY_BUSY" "$CGROUP_TEST"

trap - EXIT INT TERM
echo "SCHEDULER_ADVANCED_PASS"
