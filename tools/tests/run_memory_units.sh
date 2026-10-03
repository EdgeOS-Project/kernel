#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu
output=${1:?Expected an absolute build-output directory}
case "$output" in /*) ;; *) echo "Output must be absolute" >&2; exit 2 ;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
case "$(uname -s)" in
    Darwin)
        case "$output" in /Volumes/EdwardData/EdgeOS/*) ;; *) exit 2 ;; esac
        test "$(df /Volumes/EdwardData | awk 'END {print $NF}')" = /Volumes/EdwardData
        dead_strip=-Wl,-dead_strip
        ;;
    *) dead_strip=-Wl,--gc-sections ;;
esac
mkdir -p "$output"
cd "$root"
compiler=${CC:-clang}
awk '
    /^void \*process_user_mmap_alloc_contiguous_backing_pages\(/ { emit = 1 }
    emit { print }
    emit && /^}/ { emit = 0 }
' src/sys/process.c > "$output/contiguous_backing.inc"
"$compiler" -std=c11 -Wall -Wextra -Werror -I"$output" \
    tools/tests/contiguous_backing_unit.c -o "$output/contiguous-backing"
"$output/contiguous-backing"
awk '
    /^static int mmap_backing_carve_contiguous_tail_pages\(/ { emit = 1 }
    /^int process_kernel_runtime_reserve_pages\(/ { emit = 1 }
    emit { print }
    emit && /^}/ { emit = 0 }
' src/sys/process.c > "$output/runtime_reservation.inc"
"$compiler" -std=c11 -Wall -Wextra -Werror -I"$output" \
    tools/tests/runtime_reservation_unit.c -o "$output/runtime-reservation"
"$output/runtime-reservation"
"$compiler" -std=c11 -fno-builtin -ffunction-sections -fdata-sections \
    -Iinclude tools/tests/ramdisk_backing_unit.c "$dead_strip" \
    -o "$output/ramdisk-unit"
"$output/ramdisk-unit"
for name in exec_payload_lifetime tmpfs_mount_backing task_scratch_lifetime task_stack_lifetime initramfs_destination; do
    "$compiler" -std=c11 -DEDGEOS_HOST_TEST -iquote include \
        -ffunction-sections -fdata-sections "tools/tests/${name}_unit.c" \
        "$dead_strip" -o "$output/$name"
    "$output/$name"
done
"$compiler" -std=c11 -fno-builtin -Iinclude \
    tools/tests/fb_console_init_unit.c -o "$output/fb-console-unit"
"$output/fb-console-unit"
python3 -B tools/tests/test_kernel_memory_inventory.py
"$compiler" -std=c11 -Wall -Wextra -Werror \
    tools/tests/memory_scale_abi_probe.c -o "$output/memory-scale-host"
"$output/memory-scale-host" 8 3
echo "Host regression checks passed; guest runtime acceptance is separate."
