#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu
image=${1:?Expected an ISO filename}
prefix=${2:?Expected a unique result prefix}
count=${3:-10}
scratch=${4:-}
case "$image$prefix" in *[!a-zA-Z0-9._-]*) exit 2 ;; esac
case "$count" in 1|2|3|4|5|6|7|8|9|10) ;; *) exit 2 ;; esac
case "$scratch" in *[!a-zA-Z0-9._-]*) exit 2 ;; esac
if test -n "$scratch"; then
    test "$(stat -c %s "$scratch")" = 16777216
fi
test "$(uname -m)" = x86_64
test -r /dev/kvm
test -f "$image"
vm_pid=
cleanup() {
    if test -n "$vm_pid"; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM
i=1
while test "$i" -le "$count"; do
    run="$prefix-$i"
    test ! -e "$run.serial.log"
    set --
    if test -n "$scratch"; then set -- -drive "file=$scratch,format=raw,if=virtio"; fi
    timeout 120s qemu-system-x86_64 -machine q35,accel=kvm -cpu host \
        -smp 1 -m 128M -cdrom "$image" -nic user,model=virtio-net-pci \
        "$@" \
        -display none -chardev "socket,id=serial0,path=$run.sock,server=on,wait=off,logfile=$run.serial.log" \
        -serial chardev:serial0 -no-reboot > "$run.qemu.log" 2>&1 &
    vm_pid=$!
    set --
    if test -n "$scratch"; then
        set -- --scratch-device /dev/sda
        if test "$i" -gt 1; then set -- "$@" --expect-scratch-data; fi
    fi
    python3 serial_memory_boot_probe.py "$run.sock" --timeout 100 "$@" > "$run.probe.log" 2>&1
    wait "$vm_pid"
    vm_pid=
    printf '{"architecture":"x86_64","ram_mib":128,"cold_boot":%s,"status":"pass"}\n' "$i"
    i=$((i + 1))
done
