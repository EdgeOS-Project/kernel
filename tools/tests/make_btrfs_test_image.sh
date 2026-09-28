#!/bin/sh
# Build the Btrfs image used by host and guest acceptance tests.

set -eu

OUTPUT=${1:-work/btrfs-runtime.btrfs}
MKFS_BTRFS=${MKFS_BTRFS:-mkfs.btrfs}
TEMPORARY=$(mktemp -d "${TMPDIR:-/tmp}/edgeos-btrfs.XXXXXX")
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

command -v "$MKFS_BTRFS" >/dev/null 2>&1 || {
    echo "mkfs.btrfs is required to build $OUTPUT" >&2
    exit 1
}

mkdir -p "$TEMPORARY/mnt" "$(dirname "$OUTPUT")"
truncate -s 256M "$TEMPORARY/image.btrfs"
"$MKFS_BTRFS" -f -m single -d single -L EDGEOS_BTRFS \
    "$TEMPORARY/image.btrfs" >/dev/null
$SUDO mount -o loop "$TEMPORARY/image.btrfs" "$TEMPORARY/mnt"
MOUNTED=1

printf '%s\n' edgeos-btrfs-runtime |
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

sync
$SUDO umount "$TEMPORARY/mnt"
MOUNTED=0
mv "$TEMPORARY/image.btrfs" "$OUTPUT"
echo "created $OUTPUT"
