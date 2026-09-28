#!/bin/sh
# Validate cgroup v2 hierarchical CPU shares independently of task count.
set -eu

ROOT=/sys/fs/cgroup
PREFIX="$ROOT/edgeos-cpu-hierarchy-$$"
GROUP_A="$PREFIX/a"
GROUP_B="$PREFIX/b"
PIDS=""

cleanup() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in $PIDS; do
        wait "$pid" 2>/dev/null || true
    done
    rmdir "$GROUP_A" "$GROUP_B" "$PREFIX" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cpu_usage() {
    awk '$1 == "usage_usec" { print $2 }' "$1/cpu.stat"
}

start_worker() {
    group=$1
    if [ -n "${EDGEOS_AFFINITY_BUSY:-}" ] &&
       [ -x "$EDGEOS_AFFINITY_BUSY" ]; then
        "$EDGEOS_AFFINITY_BUSY" &
    elif command -v taskset >/dev/null 2>&1; then
        taskset -c 0 sh -c 'while :; do :; done' &
    else
        sh -c 'while :; do :; done' &
    fi
    pid=$!
    PIDS="$PIDS $pid"
    echo "$pid" > "$group/cgroup.procs"
}

require_single_cpu_workers() {
    if [ -n "${EDGEOS_AFFINITY_BUSY:-}" ] &&
       [ -x "$EDGEOS_AFFINITY_BUSY" ]; then
        return
    fi
    if command -v taskset >/dev/null 2>&1; then
        return
    fi
    if [ "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" -gt 1 ]; then
        echo "CGROUP_CPU_HIERARCHY_SKIP no-affinity-worker"
        exit 77
    fi
}

stop_workers() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in $PIDS; do
        wait "$pid" 2>/dev/null || true
    done
    PIDS=""
}

run_case() {
    weight_a=$1
    weight_b=$2
    expected_min=$3
    expected_max=$4

    echo "$weight_a" > "$GROUP_A/cpu.weight"
    echo "$weight_b" > "$GROUP_B/cpu.weight"
    start_a=$(cpu_usage "$GROUP_A")
    start_b=$(cpu_usage "$GROUP_B")
    start_worker "$GROUP_A"
    start_worker "$GROUP_B"
    start_worker "$GROUP_B"
    start_worker "$GROUP_B"
    start_worker "$GROUP_B"
    sleep 10
    stop_workers
    end_a=$(cpu_usage "$GROUP_A")
    end_b=$(cpu_usage "$GROUP_B")
    used_a=$((end_a - start_a))
    used_b=$((end_b - start_b))
    if [ "$used_a" -le 0 ]; then
        echo "CGROUP_CPU_HIERARCHY_FAIL no-runtime-a"
        exit 1
    fi
    ratio=$((used_b * 100 / used_a))
    echo "CGROUP_CPU_HIERARCHY_CASE weights=$weight_a:$weight_b usage=$used_a:$used_b ratio=$ratio"
    if [ "$ratio" -lt "$expected_min" ] ||
       [ "$ratio" -gt "$expected_max" ]; then
        echo "CGROUP_CPU_HIERARCHY_FAIL ratio=$ratio expected=$expected_min..$expected_max"
        exit 1
    fi
}

echo +cpu > "$ROOT/cgroup.subtree_control" 2>/dev/null || true
require_single_cpu_workers
mkdir "$PREFIX" "$GROUP_A" "$GROUP_B"
echo +cpu > "$PREFIX/cgroup.subtree_control"

run_case 100 100 70 145
run_case 100 400 260 560
echo "CGROUP_CPU_HIERARCHY_PASS"
