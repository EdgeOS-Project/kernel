#!/bin/sh
# Build the deterministic EROFS image used by host and guest acceptance tests.

set -eu

OUTPUT=${1:-work/erofs-runtime.erofs}
MKFS_EROFS=${MKFS_EROFS:-mkfs.erofs}
PYTHON=${PYTHON:-python3}
EROFS_COMPRESSION=${EROFS_COMPRESSION:-none}
TEMPORARY=$(mktemp -d "${TMPDIR:-/tmp}/edgeos-erofs.XXXXXX")

cleanup() {
    rm -rf "$TEMPORARY"
}
trap cleanup EXIT INT TERM

command -v "$MKFS_EROFS" >/dev/null 2>&1 || {
    echo "mkfs.erofs is required to build $OUTPUT" >&2
    exit 1
}

mkdir -p "$TEMPORARY/root/payload/nested" "$(dirname "$OUTPUT")"
printf '%s\n' edgeos-erofs-runtime > "$TEMPORARY/root/marker.txt"
printf '%s\n' nested-value > "$TEMPORARY/root/payload/nested/value.txt"
ln -s marker.txt "$TEMPORARY/root/marker-link"
dd if=/dev/zero of="$TEMPORARY/root/payload/large-zero.bin" \
    bs=4096 count=8 2>/dev/null
if [ "$EROFS_COMPRESSION" != none ]; then
    "$PYTHON" - "$TEMPORARY/root/payload/mixed.bin" <<'PY'
from pathlib import Path
import sys

prefix = (b"EdgeOS compressed extent validation. " * 4096)[:98304]
middle = bytes(
    ((index * 73 + (index >> 3) * 19) ^ ((index * 13) >> 7)) & 0xff
    for index in range(65536)
)
suffix = (b"Shared x86_64 arm64 EROFS reader. " * 8192)[:131072]
Path(sys.argv[1]).write_bytes(prefix + middle + suffix)
PY
fi

if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$TEMPORARY/root"
fi
if "$PYTHON" - "$TEMPORARY/root/marker.txt" <<'PY'
import os
import sys

if not hasattr(os, "setxattr"):
    raise SystemExit(1)
os.setxattr(sys.argv[1], "user.edgeos", b"verified")
PY
then
    :
elif command -v xattr >/dev/null 2>&1; then
    xattr -w user.edgeos verified "$TEMPORARY/root/marker.txt"
elif command -v setfattr >/dev/null 2>&1; then
    setfattr -n user.edgeos -v verified "$TEMPORARY/root/marker.txt"
else
    echo "an extended-attribute writer is required to build $OUTPUT" >&2
    exit 1
fi

rm -f "$OUTPUT"
case "$EROFS_COMPRESSION" in
    none)
        "$MKFS_EROFS" -d0 -T0 --all-root -b4096 \
            -U 00000000-0000-0000-0000-000000000001 \
            -L EDGEOS_EROFS "$OUTPUT" "$TEMPORARY/root"
        ;;
    lz4)
        "$MKFS_EROFS" -d0 -T0 --all-root -b4096 -zlz4 \
            -U 00000000-0000-0000-0000-000000000002 \
            -L EDGEOS_LZ4 "$OUTPUT" "$TEMPORARY/root"
        ;;
    lz4-legacy)
        "$MKFS_EROFS" -d0 -T0 --all-root -b4096 -zlz4 \
            -Elegacy-compress \
            -U 00000000-0000-0000-0000-000000000003 \
            -L EDGEOS_LZ4_OLD "$OUTPUT" "$TEMPORARY/root"
        ;;
    lz4-big)
        "$MKFS_EROFS" -d0 -T0 --all-root -b4096 -zlz4 -C65536 \
            -U 00000000-0000-0000-0000-000000000004 \
            -L EDGEOS_LZ4_BIG "$OUTPUT" "$TEMPORARY/root"
        ;;
    *)
        echo "unsupported EROFS compression mode: $EROFS_COMPRESSION" >&2
        exit 1
        ;;
esac
echo "created $OUTPUT"
