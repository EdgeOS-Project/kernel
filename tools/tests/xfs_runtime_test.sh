#!/bin/sh
# Validate Linux-compatible XFS mounting through a loop device.

set -eux

IMAGE=/root/xfs-runtime.xfs
MOUNTPOINT=/mnt/xfs-runtime
LOOP_DEVICE=

cleanup() {
    umount "$MOUNTPOINT" 2>/dev/null || true
    if [ -n "$LOOP_DEVICE" ]; then
        losetup -d "$LOOP_DEVICE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "XFS_RUNTIME_START"
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
if [ ! -f "$IMAGE" ] && [ -f "$IMAGE.zst" ]; then
    zstd -q -d --sparse "$IMAGE.zst" -o "$IMAGE"
fi
test -f "$IMAGE"

LOOP_DEVICE=$(losetup -f)
losetup --read-only "$LOOP_DEVICE" "$IMAGE"
test "$(blockdev --getro "$LOOP_DEVICE")" = 1
cmp "$IMAGE" "$LOOP_DEVICE"
echo "XFS_RUNTIME_LOOP_IO_OK"

mkdir -p "$MOUNTPOINT"
mount -t xfs -o ro "$LOOP_DEVICE" "$MOUNTPOINT"
grep -q " $MOUNTPOINT xfs ro" /proc/mounts
echo "XFS_RUNTIME_MOUNT_OK"

test "$(cat "$MOUNTPOINT/marker.txt")" = edgeos-xfs-runtime
test "$(readlink "$MOUNTPOINT/marker-link")" = marker.txt
test "$(cat "$MOUNTPOINT/marker-link")" = edgeos-xfs-runtime
test "$(cat "$MOUNTPOINT/nested/data.txt")" = nested-data
test "$(cat "$MOUNTPOINT/large-dir/entry-119.txt")" = entry-119-data
test "$(wc -c < "$MOUNTPOINT/sparse.bin")" -eq 1048576
dd if="$MOUNTPOINT/sparse.bin" bs=1 skip=524288 count=4096 status=none |
    cmp -n 4096 - /dev/zero
test "$(dd if="$MOUNTPOINT/sparse.bin" bs=1 skip=1048567 count=9 status=none)" = tail-data
dd if="$MOUNTPOINT/btree.bin" bs=1 skip=327680 count=4096 status=none |
    tr '\132' '\000' | cmp -n 4096 - /dev/zero
dd if="$MOUNTPOINT/btree.bin" bs=1 skip=331776 count=4096 status=none |
    cmp -n 4096 - /dev/zero
echo "XFS_RUNTIME_CONTENT_OK"

if printf '%s\n' write-must-fail > "$MOUNTPOINT/marker.txt"; then
    echo "XFS_RUNTIME_READONLY_FAILED"
    exit 1
fi
echo "XFS_RUNTIME_READONLY_OK"

umount "$MOUNTPOINT"
losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=
echo "XFS_RUNTIME_PASS"
trap - EXIT INT TERM
sync
poweroff -f
