#!/bin/sh
# Validate Linux-compatible SquashFS mounting through a loop device.

set -eux

IMAGE=/root/squashfs-runtime.sqfs
MOUNTPOINT=/mnt/squashfs-runtime
LOOP_DEVICE=

cleanup() {
    umount "$MOUNTPOINT" 2>/dev/null || true
    if [ -n "$LOOP_DEVICE" ]; then
        losetup -d "$LOOP_DEVICE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "SQUASHFS_RUNTIME_START"
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
test -f "$IMAGE"

LOOP_DEVICE=$(losetup -f)
losetup --read-only "$LOOP_DEVICE" "$IMAGE"
test "$(blockdev --getro "$LOOP_DEVICE")" = 1
cmp "$IMAGE" "$LOOP_DEVICE"
echo "SQUASHFS_RUNTIME_LOOP_IO_OK"
mkdir -p "$MOUNTPOINT"
mount -t squashfs -o ro "$LOOP_DEVICE" "$MOUNTPOINT"
grep -q " $MOUNTPOINT squashfs ro" /proc/mounts
echo "SQUASHFS_RUNTIME_MOUNT_OK"

test "$(cat "$MOUNTPOINT/marker.txt")" = edgeos-squashfs-runtime
test "$(readlink "$MOUNTPOINT/marker-link")" = marker.txt
test "$(cat "$MOUNTPOINT/marker-link")" = edgeos-squashfs-runtime
test "$(wc -c < "$MOUNTPOINT/payload/large-zero.bin")" -eq 2097152
cmp -n 2097152 "$MOUNTPOINT/payload/large-zero.bin" /dev/zero
test "$(cat "$MOUNTPOINT/payload/nested/value.txt")" = nested-value
echo "SQUASHFS_RUNTIME_CONTENT_OK"

python3 - "$MOUNTPOINT/marker.txt" <<'PY'
import os
import sys

value = os.getxattr(sys.argv[1], "user.edgeos")
if value != b"verified":
    raise SystemExit(f"unexpected xattr value: {value!r}")
PY
echo "SQUASHFS_RUNTIME_XATTR_OK"

if printf '%s\n' write-must-fail > "$MOUNTPOINT/marker.txt"; then
    echo "SQUASHFS_RUNTIME_READONLY_FAILED"
    exit 1
fi
echo "SQUASHFS_RUNTIME_READONLY_OK"

umount "$MOUNTPOINT"
losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=
echo "SQUASHFS_RUNTIME_PASS"
trap - EXIT INT TERM
sync
poweroff -f
