#!/bin/sh
# Exercise the Linux loop ABI and mount a writable ext4 image in a real guest.

set -eux

IMAGE=/root/loop-runtime.ext4
MOUNTPOINT=/mnt/loop-runtime
LOOP_DEVICE=

cleanup() {
    if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
        umount "$MOUNTPOINT" || true
    fi
    if [ -n "$LOOP_DEVICE" ]; then
        losetup -d "$LOOP_DEVICE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "LOOP_RUNTIME_START"
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
ls -l /dev/loop-control /dev/loop0
test -c /dev/loop-control
test -b /dev/loop0
test -f "$IMAGE"
echo "LOOP_RUNTIME_NODES_OK"

LOOP_DEVICE=$(losetup -f)
echo "LOOP_RUNTIME_FREE=$LOOP_DEVICE"
test "$LOOP_DEVICE" = /dev/loop0
losetup "$LOOP_DEVICE" "$IMAGE"
echo "LOOP_RUNTIME_CONFIGURED"
ls -la /sys/block/loop0 /sys/block/loop0/loop
cat /sys/block/loop0/loop/backing_file
test "$(cat /sys/block/loop0/ro)" = 0
losetup "$LOOP_DEVICE"
losetup --list
test "$(losetup -j "$IMAGE" | cut -d: -f1)" = "$LOOP_DEVICE"

mkdir -p "$MOUNTPOINT"
mount -t ext4 "$LOOP_DEVICE" "$MOUNTPOINT"
echo "LOOP_RUNTIME_MOUNTED"
test "$(cat "$MOUNTPOINT/host-marker")" = edgeos-loop-runtime
printf '%s\n' guest-write-ok > "$MOUNTPOINT/guest-marker"
sync
umount "$MOUNTPOINT"
losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=

test -z "$(losetup -j "$IMAGE")"
echo "LOOP_RUNTIME_PASS"
trap - EXIT INT TERM
sync
poweroff -f
