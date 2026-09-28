#!/bin/sh
# Run the EdgeOS ARM64 KVM acceptance payload with Apple HVF nested virtualization.

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <task-slug> [qemu-system-aarch64]" >&2
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
log_root=$artifact_root/logs/arm64/$task_slug
qemu=${2:-/Volumes/EdwardData/Build/qemu/build-qemu-mainline/qemu-system-aarch64}
firmware=${EDGEOS_AARCH64_EFI:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}
kernel=$repository/out/arm64/BOOTAA64.EFI
initramfs=$repository/out/arm64/initramfs.img
serial_log=$log_root/serial.log
qemu_log=$log_root/qemu.log
pid_file=$log_root/qemu.pid
hash_log=$log_root/hashes.log
version_log=$log_root/qemu-version.log
timeout_seconds=${EDGE_KVM_ACCEPTANCE_TIMEOUT:-120}
acceptance_profile=${EDGE_KVM_ACCEPTANCE_PROFILE:-bare}
append_extra=${EDGE_KVM_ACCEPTANCE_APPEND_EXTRA:-}
owned_pid=

case "$timeout_seconds" in
    ''|*[!0-9]*)
        echo "EDGE_KVM_ACCEPTANCE_TIMEOUT must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "$timeout_seconds" -eq 0 ]; then
    echo "EDGE_KVM_ACCEPTANCE_TIMEOUT must be greater than zero" >&2
    exit 2
fi
case "$acceptance_profile" in
    bare|linux|migration) ;;
    *)
        echo "EDGE_KVM_ACCEPTANCE_PROFILE must be bare, linux, or migration" >&2
        exit 2
        ;;
esac

if ! mount | grep -q '^/dev/.* on /Volumes/EdwardData '; then
    echo "/Volumes/EdwardData is not a mounted filesystem" >&2
    exit 1
fi
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo "Apple Silicon macOS is required for nested HVF acceptance" >&2
    exit 1
fi
if [ ! -x "$qemu" ]; then
    echo "QEMU binary not found or not executable: $qemu" >&2
    exit 1
fi
if [ ! -f "$firmware" ]; then
    echo "AArch64 EDK2 firmware not found: $firmware" >&2
    exit 1
fi
if [ ! -f "$kernel" ] || [ ! -f "$initramfs" ]; then
    echo "build arm64-initramfs-uefi before running acceptance" >&2
    exit 1
fi

mkdir -p "$log_root"
if [ -f "$pid_file" ]; then
    previous_pid=$(sed -n '1p' "$pid_file")
    case "$previous_pid" in
        ''|*[!0-9]*) ;;
        *)
            if kill -0 "$previous_pid" 2>/dev/null; then
                echo "task-owned QEMU is already running: $previous_pid" >&2
                exit 1
            fi
            ;;
    esac
fi

cleanup()
{
    if [ -n "$owned_pid" ] && kill -0 "$owned_pid" 2>/dev/null; then
        kill "$owned_pid" 2>/dev/null || true
        attempts=0
        while kill -0 "$owned_pid" 2>/dev/null && [ "$attempts" -lt 20 ]; do
            sleep 1
            attempts=$((attempts + 1))
        done
        if kill -0 "$owned_pid" 2>/dev/null; then
            echo "task-owned QEMU did not stop: $owned_pid" >&2
            return 1
        fi
    fi
    return 0
}
trap cleanup EXIT HUP INT TERM

: > "$serial_log"
: > "$qemu_log"
"$qemu" --version > "$version_log"
shasum -a 256 "$qemu" "$firmware" "$kernel" "$initramfs" > "$hash_log"

"$qemu" \
    -machine virt,virtualization=on,gic-version=3,acpi=off \
    -accel hvf \
    -cpu host \
    -smp 4 \
    -m 4096M \
    -bios "$firmware" \
    -kernel "$kernel" \
    -initrd "$initramfs" \
    -append "rdinit=/edge-kvm-init console=ttyAMA0 loglevel=8 logfile=/edgeos-boot.log $append_extra" \
    -display none \
    -serial "file:$serial_log" \
    -pidfile "$pid_file" \
    -daemonize \
    -no-reboot \
    2> "$qemu_log"

owned_pid=$(sed -n '1p' "$pid_file")
case "$owned_pid" in
    ''|*[!0-9]*)
        echo "QEMU did not write a valid PID" >&2
        exit 1
        ;;
esac

elapsed=0
if [ "$acceptance_profile" = linux ]; then
    completion_marker=EDGE_ARM64_LINUX_QEMU_EXECUTION_PASS
    failure_marker=EDGE_ARM64_LINUX_QEMU_EXECUTION_FAIL
elif [ "$acceptance_profile" = migration ]; then
    completion_marker=EDGE_ARM64_QEMU_KVM_MIGRATION_PASS
    failure_marker='EDGE_ARM64_MIGRATION_.*_FAIL'
else
    completion_marker=EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_PASS
    failure_marker=EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_FAIL
fi
while [ "$elapsed" -lt "$timeout_seconds" ]; do
    if grep -q "$completion_marker" "$serial_log"; then
        break
    fi
    if grep -q "$failure_marker" "$serial_log"; then
        break
    fi
    if ! kill -0 "$owned_pid" 2>/dev/null; then
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [ "$acceptance_profile" = linux ]; then
    required_markers='uefi: preparing EL1 page tables from EL2
arm64: bhyve-backed KVM hardware backend ready
EDGE_ARM64_LINUX_QEMU_STARTUP_BEGIN
EDGE_LINUX_BOOT_PASS
EDGE_LINUX_BENCHMARK_PASS
EDGE_ARM64_LINUX_QEMU_EXECUTION_PASS'
elif [ "$acceptance_profile" = migration ]; then
    required_markers='uefi: preparing EL1 page tables from EL2
arm64: bhyve-backed KVM hardware backend ready
EDGE_ARM64_MIGRATION_STARTUP_BEGIN
EDGE_ARM64_MIGRATION_SOURCE_COMPLETE
EDGE_ARM64_MIGRATION_DESTINATION_COMPLETE
EDGE_ARM64_QEMU_KVM_MIGRATION_PASS'
else
    required_markers='uefi: preparing EL1 page tables from EL2
arm64: bhyve-backed KVM hardware backend ready
EDGE_ARM64_QEMU_KVM_STARTUP_BEGIN
EDGE_ARM64_QEMU_KVM_TIMER_START
EDGE_ARM64_QEMU_KVM_TIMER_ARMED
EDGE_ARM64_QEMU_KVM_TIMER_STATUS_PASS
EDGE_ARM64_QEMU_KVM_TIMER_IRQ_PASS
EDGE_ARM64_QEMU_KVM_GUEST_IO_PASS
EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_PASS'
fi
printf '%s\n' "$required_markers" | while IFS= read -r marker; do
    if ! grep -Fq "$marker" "$serial_log"; then
        echo "missing ARM64 acceptance marker: $marker" >&2
        exit 1
    fi
done

if [ "$acceptance_profile" = migration ] &&
    grep -q "$completion_marker" "$serial_log"; then
    sleep 5
fi

if [ "$acceptance_profile" = migration ] && ! awk '
    /EDGE_ARM64_MIGRATION_DESTINATION_COMPLETE/ { destination = 1; next }
    destination && /EDGE_ARM64_MIGRATION_RESUME_HEARTBEAT/ { resumed = 1 }
    END { exit resumed ? 0 : 1 }
' "$serial_log"; then
    echo "missing destination heartbeat after ARM64 migration" >&2
    exit 1
fi

if grep -Eq 'EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_FAIL|EDGE_ARM64_LINUX_QEMU_EXECUTION_FAIL|EDGE_ARM64_QEMU_KVM_INVALID_EL|EDGE_ARM64_QEMU_KVM_GIC_ENABLE_FAIL|EDGE_ARM64_QEMU_KVM_EXCEPTION_FAIL|EDGE_ARM64_QEMU_KVM_UNEXPECTED_IRQ|Kernel panic|\[bsd-bridge\] panic:|failed to initialize kvm' \
    "$serial_log"; then
    echo "ARM64 acceptance log contains a failure marker" >&2
    exit 1
fi

if [ "$acceptance_profile" = linux ]; then
    echo "EDGE_ARM64_LINUX_NESTED_HVF_ACCEPTANCE_PASS"
else
    echo "EDGE_ARM64_NESTED_HVF_ACCEPTANCE_PASS"
fi
echo "serial log: $serial_log"
echo "hashes: $hash_log"
