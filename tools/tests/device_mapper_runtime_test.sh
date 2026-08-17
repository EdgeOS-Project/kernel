#!/bin/sh
# Exercise the Linux device-mapper ABI with the real dmsetup utility.

set -eux

IMAGE=/root/loop-runtime.ext4
MOUNTPOINT=/mnt/device-mapper-runtime
LOOP_DEVICE=
CRYPT_LOOP_DEVICE=
CRYPT_IMAGE=/root/device-mapper-crypt.img

cleanup() {
    umount "$MOUNTPOINT" 2>/dev/null || true
    dmsetup --noudevsync remove edgeos-linear-renamed 2>/dev/null || true
    dmsetup --noudevsync remove edgeos-linear 2>/dev/null || true
    dmsetup --noudevsync remove edgeos-zero 2>/dev/null || true
    dmsetup --noudevsync remove edgeos-error 2>/dev/null || true
    dmsetup --noudevsync remove edgeos-crypt 2>/dev/null || true
    if [ -n "$CRYPT_LOOP_DEVICE" ]; then
        losetup -d "$CRYPT_LOOP_DEVICE" 2>/dev/null || true
    fi
    if [ -n "$LOOP_DEVICE" ]; then
        losetup -d "$LOOP_DEVICE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "DEVICE_MAPPER_RUNTIME_START"
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
test -c /dev/mapper/control
test -f "$IMAGE"
dmsetup version
dmsetup targets
echo "DEVICE_MAPPER_RUNTIME_CONTROL_OK"

LOOP_DEVICE=$(losetup -f)
losetup "$LOOP_DEVICE" "$IMAGE"
SECTORS=$(blockdev --getsz "$LOOP_DEVICE")
test "$SECTORS" -gt 0
printf '0 %s linear %s 0\n' "$SECTORS" "$LOOP_DEVICE" |
    dmsetup --noudevsync create edgeos-linear
test -b /dev/dm-0
test -b /dev/mapper/edgeos-linear
dmsetup info edgeos-linear
dmsetup table edgeos-linear
dmsetup deps edgeos-linear
dmsetup ls --tree
echo "DEVICE_MAPPER_RUNTIME_LINEAR_OK"

mkdir -p "$MOUNTPOINT"
mount -t ext4 /dev/mapper/edgeos-linear "$MOUNTPOINT"
test "$(cat "$MOUNTPOINT/host-marker")" = edgeos-loop-runtime
printf '%s\n' device-mapper-write-ok > "$MOUNTPOINT/dm-guest-marker"
sync
umount "$MOUNTPOINT"
dmsetup suspend edgeos-linear
dmsetup resume edgeos-linear
dmsetup rename edgeos-linear edgeos-linear-renamed
test -b /dev/mapper/edgeos-linear-renamed
echo "DEVICE_MAPPER_RUNTIME_SWITCH_OK"

dmsetup --noudevsync create edgeos-zero --table '0 2048 zero'
dd if=/dev/mapper/edgeos-zero of=/root/dm-zero-output bs=512 count=8
dd if=/dev/zero of=/root/dm-zero-expected bs=512 count=8
cmp /root/dm-zero-expected /root/dm-zero-output
dmsetup --noudevsync create edgeos-error --table '0 2048 error'
if dd if=/dev/mapper/edgeos-error of=/dev/null bs=512 count=1; then
    echo "DEVICE_MAPPER_RUNTIME_ERROR_TARGET_ACCEPTED_IO"
    exit 1
fi
echo "DEVICE_MAPPER_RUNTIME_TARGETS_OK"

dd if=/dev/zero of="$CRYPT_IMAGE" bs=512 count=32
CRYPT_LOOP_DEVICE=$(losetup -f)
losetup "$CRYPT_LOOP_DEVICE" "$CRYPT_IMAGE"
CRYPT_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
printf '0 32 crypt aes-xts-plain64 %s 7 %s 0 1 sector_size:512\n' \
    "$CRYPT_KEY" "$CRYPT_LOOP_DEVICE" |
    dmsetup --noudevsync create edgeos-crypt
dd if=/dev/zero of=/dev/mapper/edgeos-crypt bs=512 count=2
dd if=/dev/mapper/edgeos-crypt of=/root/dm-crypt-plain bs=512 count=2
dd if=/dev/zero of=/root/dm-crypt-zero bs=512 count=2
dd if=/dev/zero of=/root/dm-crypt-zero-sector bs=512 count=1
cmp /root/dm-crypt-zero /root/dm-crypt-plain
dd if="$CRYPT_LOOP_DEVICE" of=/root/dm-crypt-raw-0 bs=512 count=1
dd if="$CRYPT_LOOP_DEVICE" of=/root/dm-crypt-raw-1 bs=512 skip=1 count=1
if cmp /root/dm-crypt-zero-sector /root/dm-crypt-raw-0 2>/dev/null; then
    echo "DEVICE_MAPPER_RUNTIME_CRYPT_PLAINTEXT_BACKING"
    exit 1
fi
if cmp /root/dm-crypt-raw-0 /root/dm-crypt-raw-1 2>/dev/null; then
    echo "DEVICE_MAPPER_RUNTIME_CRYPT_IDENTICAL_SECTORS"
    exit 1
fi
dmsetup table edgeos-crypt
dmsetup --noudevsync remove edgeos-crypt
losetup -d "$CRYPT_LOOP_DEVICE"
CRYPT_LOOP_DEVICE=
echo "DEVICE_MAPPER_RUNTIME_CRYPT_OK"

dmsetup --noudevsync remove edgeos-error
dmsetup --noudevsync remove edgeos-zero
dmsetup --noudevsync remove edgeos-linear-renamed
losetup -d "$LOOP_DEVICE"
LOOP_DEVICE=
if dmsetup ls 2>/dev/null | grep -q ' ('; then
    echo "DEVICE_MAPPER_RUNTIME_REMOVE_FAILED"
    exit 1
fi
echo "DEVICE_MAPPER_RUNTIME_PASS"
trap - EXIT INT TERM
sync
poweroff -f
