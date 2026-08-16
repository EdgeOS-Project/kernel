#!/bin/sh
# Build the XFS image used by host and guest acceptance tests.

set -eu

OUTPUT=${1:-work/xfs-runtime.xfs}
MKFS_XFS=${MKFS_XFS:-mkfs.xfs}
XFS_IO=${XFS_IO:-xfs_io}
TEMPORARY=$(mktemp -d "${TMPDIR:-/tmp}/edgeos-xfs.XXXXXX")
MOUNTED=0

if [ "$(id -u)" -eq 0 ]; then
    SUDO=
else
    SUDO=${SUDO:-sudo}
fi

cleanup() {
    if [ "$MOUNTED" -eq 1 ]; then
        $SUDO umount "$TEMPORARY/mnt" >/dev/null 2>&1 || true
    fi
    rm -rf "$TEMPORARY"
}
trap cleanup EXIT INT TERM

command -v "$MKFS_XFS" >/dev/null 2>&1 || {
    echo "mkfs.xfs is required to build $OUTPUT" >&2
    exit 1
}
command -v "$XFS_IO" >/dev/null 2>&1 || {
    echo "xfs_io is required to build $OUTPUT" >&2
    exit 1
}

mkdir -p "$TEMPORARY/mnt" "$(dirname "$OUTPUT")"
truncate -s 512M "$TEMPORARY/image.xfs"
"$MKFS_XFS" -f \
    -m crc=1,reflink=0,bigtime=0,inobtcount=0,uuid=00000000-0000-0000-0000-000000000005 \
    -i size=512,sparse=0 -n ftype=1 "$TEMPORARY/image.xfs" >/dev/null
$SUDO mount -o loop "$TEMPORARY/image.xfs" "$TEMPORARY/mnt"
MOUNTED=1

printf '%s\n' edgeos-xfs-runtime |
    $SUDO tee "$TEMPORARY/mnt/marker.txt" >/dev/null
$SUDO mkdir "$TEMPORARY/mnt/nested" "$TEMPORARY/mnt/large-dir"
printf '%s\n' nested-data |
    $SUDO tee "$TEMPORARY/mnt/nested/data.txt" >/dev/null
$SUDO ln -s marker.txt "$TEMPORARY/mnt/marker-link"
$SUDO truncate -s 1048576 "$TEMPORARY/mnt/sparse.bin"
printf '%s' tail-data | $SUDO dd of="$TEMPORARY/mnt/sparse.bin" \
    bs=1 seek=1048567 conv=notrunc status=none

index=0
while [ "$index" -lt 120 ]; do
    printf 'entry-%03d-data\n' "$index" |
        $SUDO tee "$TEMPORARY/mnt/large-dir/entry-$index.txt" >/dev/null
    index=$((index + 1))
done

$SUDO touch "$TEMPORARY/mnt/btree.bin"
index=0
while [ "$index" -lt 48 ]; do
    offset=$((index * 8192))
    $SUDO "$XFS_IO" -c "pwrite -S 0x5a $offset 4096" \
        "$TEMPORARY/mnt/btree.bin" >/dev/null
    index=$((index + 1))
done

sync
$SUDO umount "$TEMPORARY/mnt"
MOUNTED=0
mv "$TEMPORARY/image.xfs" "$OUTPUT"
echo "created $OUTPUT"
