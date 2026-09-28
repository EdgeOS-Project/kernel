#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS Docker resource-controller runtime acceptance test.

set -eu

IMAGE=${EDGEOS_DOCKER_TEST_IMAGE:-busybox:latest}
NAME=edgeos-resource-runtime
GROUP=/sys/fs/cgroup/edgeos-resource-runtime

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [ -d "$GROUP" ]; then
        echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
        rmdir "$GROUP" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM
cleanup

grep -qw io /sys/fs/cgroup/cgroup.controllers
test -r /sys/fs/cgroup/memory.swap.current
test -w /sys/fs/cgroup/memory.swap.max
test "$(cat /sys/fs/cgroup/memory.swap.current)" = 0

docker_info=$(docker info 2>&1)
if printf '%s\n' "$docker_info" | grep -Eq \
    'No swap limit support|No io\.(weight|max) support'; then
    printf '%s\n' "$docker_info" >&2
    exit 1
fi

echo '+io +memory' > /sys/fs/cgroup/cgroup.subtree_control
mkdir "$GROUP"
test "$(cat "$GROUP/io.weight")" = 'default 100'
echo 200 > "$GROUP/io.weight"
test "$(cat "$GROUP/io.weight")" = 'default 200'
echo 0 > "$GROUP/memory.swap.max"
test "$(cat "$GROUP/memory.swap.max")" = 0

root_device=$(findmnt -n -o SOURCE /)
device_number=
if [ -d /sys/dev/block ]; then
    device_number=$(lsblk -n -o MAJ:MIN "$root_device" 2>/dev/null |
        head -n 1 || true)
fi
if [ -z "$device_number" ]; then
    device_number=$(stat -c '%Hr:%Lr' "$root_device" 2>/dev/null || true)
fi
test -n "$device_number"
echo "$device_number rbps=1048576 wbps=2097152 riops=100 wiops=200" \
    > "$GROUP/io.max"
grep -q "$device_number rbps=1048576 wbps=2097152 riops=100 wiops=200" \
    "$GROUP/io.max"
echo "$device_number 300" > "$GROUP/io.weight"
grep -q "$device_number 300" "$GROUP/io.weight"

docker run -d --name "$NAME" --memory=64m --memory-swap=64m \
    --blkio-weight=200 "$IMAGE" sleep 30 >/dev/null
container_pid=$(docker inspect -f '{{.State.Pid}}' "$NAME")
test "$container_pid" -gt 0
container_group=$(sed -n 's/^0:://p' "/proc/$container_pid/cgroup")
test -n "$container_group"
test -r "/sys/fs/cgroup$container_group/io.weight"
test -r "/sys/fs/cgroup$container_group/io.stat"
test "$(cat "/sys/fs/cgroup$container_group/memory.swap.max")" = 0

docker exec "$NAME" sh -c \
    'dd if=/dev/zero of=/tmp/edgeos-io-test bs=4096 count=32 conv=fsync >/dev/null 2>&1'
grep -Eq '^[0-9]+:[0-9]+ .*wbytes=[1-9][0-9]*' \
    "/sys/fs/cgroup$container_group/io.stat"

echo 'docker_resource_runtime_test: PASS'
