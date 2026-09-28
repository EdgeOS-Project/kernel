#!/bin/sh
# Validate Linux-compatible EROFS mounting through a loop device.

set -eux

IMAGE=/root/erofs-runtime.erofs
MOUNTPOINT=/mnt/erofs-runtime
LOOP_DEVICE=

cleanup() {
    umount "$MOUNTPOINT" 2>/dev/null || true
    if [ -n "$LOOP_DEVICE" ]; then
        losetup -d "$LOOP_DEVICE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "EROFS_RUNTIME_START"
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
test -f "$IMAGE"

LOOP_DEVICE=$(losetup -f)
losetup --read-only "$LOOP_DEVICE" "$IMAGE"
test "$(blockdev --getro "$LOOP_DEVICE")" = 1
cmp "$IMAGE" "$LOOP_DEVICE"
echo "EROFS_RUNTIME_LOOP_IO_OK"

mkdir -p "$MOUNTPOINT"
mount -t erofs -o ro "$LOOP_DEVICE" "$MOUNTPOINT"
grep -q " $MOUNTPOINT erofs ro" /proc/mounts
echo "EROFS_RUNTIME_MOUNT_OK"

test "$(cat "$MOUNTPOINT/marker.txt")" = edgeos-erofs-runtime
test "$(readlink "$MOUNTPOINT/marker-link")" = marker.txt
test "$(cat "$MOUNTPOINT/marker-link")" = edgeos-erofs-runtime
test "$(wc -c < "$MOUNTPOINT/payload/large-zero.bin")" -eq 32768
cmp -n 32768 "$MOUNTPOINT/payload/large-zero.bin" /dev/zero
test "$(cat "$MOUNTPOINT/payload/nested/value.txt")" = nested-value
echo "EROFS_RUNTIME_CONTENT_OK"

if [ -f "$MOUNTPOINT/payload/mixed.bin" ]; then
    python3 - "$MOUNTPOINT/payload/mixed.bin" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
prefix = (b"EdgeOS compressed extent validation. " * 4096)[:98304]
middle = bytes(
    ((index * 73 + (index >> 3) * 19) ^ ((index * 13) >> 7)) & 0xff
    for index in range(65536)
)
suffix = (b"Shared x86_64 arm64 EROFS reader. " * 8192)[:131072]
if path.read_bytes() != prefix + middle + suffix:
    raise SystemExit("compressed EROFS payload mismatch")
PY
    echo "EROFS_RUNTIME_LZ4_OK"
fi

python3 - "$MOUNTPOINT/marker.txt" <<'PY'
import os
import sys

value = os.getxattr(sys.argv[1], "user.edgeos")
if value != b"verified":
    raise SystemExit(f"unexpected xattr value: {value!r}")
PY
echo "EROFS_RUNTIME_XATTR_OK"

if printf '%s\n' write-must-fail > "$MOUNTPOINT/marker.txt"; then
    echo "EROFS_RUNTIME_READONLY_FAILED"
    exit 1
fi
echo "EROFS_RUNTIME_READONLY_OK"

umount "$MOUNTPOINT"
losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=
echo "EROFS_RUNTIME_PASS"
trap - EXIT INT TERM
sync
poweroff -f
