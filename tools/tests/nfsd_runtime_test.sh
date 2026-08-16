#!/bin/sh
# Validate the EdgeOS NFSv3 server with an unmodified Linux NFS client.

set -eu

SERVER=${EDGEOS_NFSD_SERVER:-127.0.0.1}
EXPORT=${EDGEOS_NFSD_EXPORT:-/srv/nfs-test}
NFS_PORT=${EDGEOS_NFSD_PORT:-32049}
MOUNT_PORT=${EDGEOS_MOUNTD_PORT:-32048}
MOUNTPOINT=${EDGEOS_NFSD_MOUNTPOINT:-/mnt/edgeos-nfsd-runtime}
TEST_UDP=${EDGEOS_NFSD_TEST_UDP:-1}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
    umount "$MOUNTPOINT" 2>/dev/null || true
    rmdir "$MOUNTPOINT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mount_export() {
    transport=$1
    mount -t nfs \
        -o "vers=3,nolock,soft,timeo=20,retrans=2,proto=$transport,port=$NFS_PORT,mountproto=$transport,mountport=$MOUNT_PORT" \
        "$SERVER:$EXPORT" "$MOUNTPOINT"
}

mkdir -p "$MOUNTPOINT"
echo "NFSD_RUNTIME_START"

mount_export tcp
rm -rf "$MOUNTPOINT/client-directory" \
       "$MOUNTPOINT/client-hardlink" \
       "$MOUNTPOINT/client-symlink" \
       "$MOUNTPOINT/client-write" \
       "$MOUNTPOINT/large-write"
test "$(cat "$MOUNTPOINT/server-seed")" = "edgeos-nfsd-seed"
printf '%s\n' "edgeos-nfsd-write" > "$MOUNTPOINT/client-write"
test "$(cat "$MOUNTPOINT/client-write")" = "edgeos-nfsd-write"
test "$(stat -c %u "$MOUNTPOINT/client-write")" = "65534"
test "$(stat -c %g "$MOUNTPOINT/client-write")" = "65534"
chmod 0640 "$MOUNTPOINT/client-write"
test "$(stat -c %a "$MOUNTPOINT/client-write")" = "640"
mkdir "$MOUNTPOINT/client-directory"
mv "$MOUNTPOINT/client-write" "$MOUNTPOINT/client-directory/renamed"
ln "$MOUNTPOINT/client-directory/renamed" "$MOUNTPOINT/client-hardlink"
ln -s client-directory/renamed "$MOUNTPOINT/client-symlink"
test "$(cat "$MOUNTPOINT/client-hardlink")" = "edgeos-nfsd-write"
test "$(readlink "$MOUNTPOINT/client-symlink")" = "client-directory/renamed"
dd if=/dev/zero of="$MOUNTPOINT/large-write" bs=32768 count=4 status=none
test "$(stat -c %s "$MOUNTPOINT/large-write")" = "131072"
truncate -s 98304 "$MOUNTPOINT/large-write"
test "$(stat -c %s "$MOUNTPOINT/large-write")" = "98304"
touch -t 202608050700 "$MOUNTPOINT/large-write"
ls -la "$MOUNTPOINT" >/dev/null
stat -f "$MOUNTPOINT" >/dev/null
sync
rm "$MOUNTPOINT/client-symlink" "$MOUNTPOINT/client-hardlink"
rm "$MOUNTPOINT/client-directory/renamed"
rmdir "$MOUNTPOINT/client-directory"
rm "$MOUNTPOINT/large-write"
umount "$MOUNTPOINT"
echo "NFSD_RUNTIME_TCP_OK"

if [ "$TEST_UDP" != "1" ]; then
    echo "NFSD_RUNTIME_PASS"
    trap - EXIT INT TERM
    rmdir "$MOUNTPOINT"
    exit 0
fi

if mount_export udp 2>/dev/null; then
    test "$(cat "$MOUNTPOINT/server-seed")" = "edgeos-nfsd-seed"
    printf '%s\n' "udp-write" > "$MOUNTPOINT/udp-write"
    test "$(cat "$MOUNTPOINT/udp-write")" = "udp-write"
    rm "$MOUNTPOINT/udp-write"
    umount "$MOUNTPOINT"
    echo "NFSD_RUNTIME_UDP_OK"
else
    python3 "$SCRIPT_DIR/nfsd_udp_runtime_test.py" \
        --host "$SERVER" --rpcbind-port "${EDGEOS_NFSD_RPCBIND_PORT:-32111}" \
        --mount-port "$MOUNT_PORT" --nfs-port "$NFS_PORT"
fi
echo "NFSD_RUNTIME_PASS"

trap - EXIT INT TERM
rmdir "$MOUNTPOINT"
