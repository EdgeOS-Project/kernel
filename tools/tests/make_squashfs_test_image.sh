#!/bin/sh
# Build the deterministic SquashFS image used by host and guest acceptance tests.

set -eu

OUTPUT=${1:-work/squashfs-runtime.sqfs}
MKSQUASHFS=${MKSQUASHFS:-mksquashfs}
PYTHON=${PYTHON:-python3}
TEMPORARY=$(mktemp -d "${TMPDIR:-/tmp}/edgeos-squashfs.XXXXXX")

cleanup() {
    rm -rf "$TEMPORARY"
}
trap cleanup EXIT INT TERM

command -v "$MKSQUASHFS" >/dev/null 2>&1 || {
    echo "mksquashfs is required to build $OUTPUT" >&2
    exit 1
}

mkdir -p "$TEMPORARY/root/payload/nested" "$(dirname "$OUTPUT")"
printf '%s\n' edgeos-squashfs-runtime > "$TEMPORARY/root/marker.txt"
printf '%s\n' nested-value > "$TEMPORARY/root/payload/nested/value.txt"
ln -s marker.txt "$TEMPORARY/root/marker-link"
dd if=/dev/zero of="$TEMPORARY/root/payload/large-zero.bin" \
    bs=1048576 count=2 2>/dev/null
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
"$MKSQUASHFS" "$TEMPORARY/root" "$OUTPUT" \
    -noappend -comp gzip -b 131072 -all-root -mkfs-time 0 -all-time 0 \
    -xattrs-include '^user\.edgeos$' \
    >/dev/null
echo "created $OUTPUT"
