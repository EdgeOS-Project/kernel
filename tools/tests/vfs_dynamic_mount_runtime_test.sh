#!/bin/sh

set -eu

# Keep util-linux on the legacy mount syscall so this test isolates the VFS
# mount table instead of depending on the separate fd-based mount API.
export LIBMOUNT_FORCE_MOUNT2=always

base=${EDGEOS_VFS_MOUNT_TEST_ROOT:-/run/edgeos-vfs-mount-table-test}
requested=${1:-80}
mounted=0
namespace_mounted=0

mount_bind() {
    if command -v busybox >/dev/null 2>&1; then
        busybox mount --bind "$1" "$2"
    else
        mount --bind "$1" "$2"
    fi
}

unmount_target() {
    if command -v busybox >/dev/null 2>&1; then
        busybox umount "$1"
    else
        umount "$1"
    fi
}

cleanup() {
    while [ "$namespace_mounted" -gt 0 ]; do
        namespace_mounted=$((namespace_mounted - 1))
        unmount_target "$base/namespace-$namespace_mounted" \
            2>/dev/null || true
    done
    while [ "$mounted" -gt 0 ]; do
        mounted=$((mounted - 1))
        unmount_target "$base/target-$mounted" 2>/dev/null || true
    done
    rm -rf "$base"
}

trap cleanup EXIT HUP INT TERM

case "$requested" in
    ''|*[!0-9]*)
        echo "invalid mount count: $requested" >&2
        exit 2
        ;;
esac

if [ "$requested" -lt 65 ]; then
    echo "mount count must cross the former 64-entry boundary" >&2
    exit 2
fi

rm -rf "$base"
mkdir -p "$base/source"
printf 'dynamic-mount-table\n' > "$base/source/marker"

while [ "$mounted" -lt "$requested" ]; do
    target="$base/target-$mounted"
    mkdir -p "$target"
    mount_bind "$base/source" "$target"
    test "$(cat "$target/marker")" = "dynamic-mount-table"
    mounted=$((mounted + 1))
done

visible=$(grep -c " $base/target-" /proc/self/mountinfo || true)
if [ "$visible" -lt "$requested" ]; then
    echo "mountinfo exposed only $visible of $requested test mounts" >&2
    exit 1
fi

echo "DYNAMIC_MOUNT_TABLE_RUNTIME_PASS mounted=$mounted visible=$visible"
echo "DYNAMIC_MOUNT_TABLE_CLEANUP_BEGIN mounted=$mounted"

while [ "$mounted" -gt 0 ]; do
    mounted=$((mounted - 1))
    unmount_target "$base/target-$mounted"
done
echo "DYNAMIC_MOUNT_TABLE_CLEANUP_PASS"

while [ "$namespace_mounted" -lt "$requested" ]; do
    target="$base/namespace-$namespace_mounted"
    : > "$target"
    mount_bind /proc/self/ns/mnt "$target"
    namespace_mounted=$((namespace_mounted + 1))
    if [ $((namespace_mounted % 10)) -eq 0 ]; then
        echo "DYNAMIC_NSFS_MOUNT_PROGRESS mounted=$namespace_mounted"
    fi
done

visible=$(grep -c " $base/namespace-" /proc/self/mountinfo || true)
if [ "$visible" -lt "$requested" ]; then
    echo "mountinfo exposed only $visible of $requested namespace mounts" >&2
    exit 1
fi

echo "DYNAMIC_NSFS_MOUNT_RUNTIME_PASS mounted=$namespace_mounted visible=$visible"
cleanup
trap - EXIT HUP INT TERM
echo "DYNAMIC_MOUNT_RUNTIME_COMPLETE"
