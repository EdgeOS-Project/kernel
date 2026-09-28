#!/bin/sh
# Build an ARM64 EdgeOS image that runs an unmodified Debian QEMU with KVM.

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <task-slug> [base-rootfs]" >&2
    exit 2
fi

task_slug=$1
case "$task_slug" in
    *[!A-Za-z0-9._-]*|'')
        echo "invalid task slug: $task_slug" >&2
        exit 2
        ;;
esac

repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
artifact_root=/Volumes/EdwardData/EdgeOS
base_rootfs=${2:-$artifact_root/rootfs/legacy-edgeos/debian/arm64}
task_root=$artifact_root/tmp/$task_slug
rootfs=$task_root/rootfs
log_root=$artifact_root/logs/arm64/$task_slug
image=$task_root/edgeos-arm64-kvm-acceptance.img
docker_image=edgeos-debian-rootfs:trixie-arm64-base

if ! mount | grep -q '^/dev/.* on /Volumes/EdwardData '; then
    echo "/Volumes/EdwardData is not a mounted filesystem" >&2
    exit 1
fi
case "$task_root" in
    "$artifact_root"/tmp/*) ;;
    *) echo "task output escaped the artifact root" >&2; exit 1 ;;
esac
if [ ! -d "$base_rootfs" ]; then
    echo "base rootfs not found: $base_rootfs" >&2
    exit 1
fi
if ! docker image inspect "$docker_image" >/dev/null 2>&1; then
    echo "required local ARM64 container image not found: $docker_image" >&2
    exit 1
fi

mkdir -p "$task_root" "$log_root"
if [ ! -d "$rootfs" ]; then
    mkdir -p "$rootfs"
    ditto "$base_rootfs" "$rootfs"
fi

docker run --rm --platform linux/arm64 \
    -v "$rootfs:/target" "$docker_image" sh -eu -c '
        cp /target/etc/resolv.conf /target/etc/resolv.conf.edge-kvm-backup
        trap '\''mv /target/etc/resolv.conf.edge-kvm-backup /target/etc/resolv.conf'\'' EXIT
        cp /etc/resolv.conf /target/etc/resolv.conf
        chroot /target apt-get update
        chroot /target env DEBIAN_FRONTEND=noninteractive \
            apt-get install -y --no-install-recommends qemu-system-arm
        mv /target/etc/resolv.conf.edge-kvm-backup /target/etc/resolv.conf
        trap - EXIT
        chroot /target /usr/bin/qemu-system-aarch64 --version
    ' 2>&1 | tee "$log_root/qemu-install.log"

make -C "$repository" edge-kvm-arm64-acceptance-payload \
    2>&1 | tee "$log_root/payload-build.log"
install -m 0755 "$repository/out/tests/edge-kvm-arm64-qemu-init" \
    "$rootfs/edge-kvm-init"
install -m 0644 "$repository/out/tests/edge-kvm-arm64-guest.elf" \
    "$rootfs/edge-kvm-arm64-guest.elf"

TMPDIR=$task_root make -C "$repository" \
    INITRAMFS_SOURCE_DIR="$rootfs" \
    ARM64_INITRAMFS_ESP_SIZE_MB=768 \
    ARM64_INITRAMFS_CMDLINE=config/cmdline-arm64-kvm-acceptance \
    arm64-initramfs-uefi 2>&1 | tee "$log_root/image-build.log"
cp "$repository/out/edgeos-arm64-initramfs.img" "$image"
shasum -a 256 \
    "$repository/out/tests/edge-kvm-arm64-qemu-init" \
    "$repository/out/tests/edge-kvm-arm64-guest.elf" \
    "$repository/out/arm64/BOOTAA64.EFI" \
    "$repository/out/arm64/initramfs.img" \
    "$image" | tee "$log_root/hashes.log"

echo "ARM64 QEMU/KVM acceptance image: $image"
