#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu
architecture=${1:?Expected x86_64 or aarch64}
case "$architecture" in x86_64|aarch64) ;; *) exit 2 ;; esac
cd /work
archive=buildroot-2026.08.tar.xz
expected=87aaca4164ea9d5c8085854953018263f7963f07c22e73a2a2185cc98c581c34
if [ ! -f "$archive" ]; then
    wget -O "$archive" "https://buildroot.org/downloads/$archive"
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum -c -
if [ ! -d buildroot-2026.08 ]; then
    tar -xf "$archive"
fi
output="/work/rootfs-$architecture"
make -C buildroot-2026.08 O="$output" \
    BR2_DEFCONFIG="/recipe/${architecture}_defconfig" defconfig
if grep -q '^BR2_LINUX_KERNEL=y' "$output/.config"; then
    echo "Linux kernel generation must remain disabled" >&2
    exit 1
fi
make -C buildroot-2026.08 O="$output" BR2_DL_DIR=/work/downloads -j"${BUILD_JOBS:-4}"
sha256sum "$output/.config" "$output/images/rootfs.ext4" \
    "$output/images/rootfs.cpio.gz"
