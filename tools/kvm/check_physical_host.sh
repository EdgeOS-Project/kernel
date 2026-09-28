#!/bin/sh

set -eu

usage()
{
    cat <<'EOF'
Usage: check_physical_host.sh [--require inventory|core|vfio|vdpa]

Inspect a Linux hardware-validation host without changing its configuration.
The optional requirement selects which readiness gate controls the exit status.
EOF
}

requirement=inventory
while [ "$#" -gt 0 ]; do
    case "$1" in
    --require)
        [ "$#" -ge 2 ] || {
            usage >&2
            exit 2
        }
        requirement=$2
        shift 2
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
    esac
done

case "$requirement" in
inventory|core|vfio|vdpa)
    ;;
*)
    usage >&2
    exit 2
    ;;
esac

proc_root=${PROC_ROOT:-/proc}
sysfs_root=${SYSFS_ROOT:-/sys}
dev_root=${DEV_ROOT:-/dev}

arch=$(uname -m)
cpu_vendor=unknown
virtualization_flags=none
if [ -r "$proc_root/cpuinfo" ]; then
    cpu_vendor=$(awk -F: '/^(vendor_id|CPU implementer)[[:space:]]*:/ {
        value=$2
        sub(/^[[:space:]]+/, "", value)
        print value
        exit
    }' "$proc_root/cpuinfo")
    [ -n "$cpu_vendor" ] || cpu_vendor=unknown
    virtualization_flags=$(awk -F: '/^(flags|Features)[[:space:]]*:/ {
        value=$2
        sub(/^[[:space:]]+/, "", value)
        print value
        exit
    }' "$proc_root/cpuinfo")
    [ -n "$virtualization_flags" ] || virtualization_flags=none
fi

kvm_status=BLOCKED
if [ -c "$dev_root/kvm" ] && [ -r "$dev_root/kvm" ] && [ -w "$dev_root/kvm" ]; then
    kvm_status=READY
fi

iommu_group_count=0
if [ -d "$sysfs_root/kernel/iommu_groups" ]; then
    iommu_group_count=$(find "$sysfs_root/kernel/iommu_groups" -mindepth 1 \
        -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
fi

vfio_group_node_count=0
if [ -d "$dev_root/vfio" ]; then
    vfio_group_node_count=$(find "$dev_root/vfio" -mindepth 1 -maxdepth 1 \
        \( -type c -o -type f \) ! -name vfio 2>/dev/null | wc -l | tr -d ' ')
fi

vdpa_device_count=$(find "$dev_root" -maxdepth 1 \
    \( -type c -o -type f \) -name 'vhost-vdpa*' 2>/dev/null | wc -l | tr -d ' ')

vfio_status=BLOCKED
if [ "$kvm_status" = READY ] && [ "$iommu_group_count" -gt 0 ]; then
    vfio_status=READY
fi

vdpa_status=BLOCKED
if [ "$kvm_status" = READY ] && [ "$vdpa_device_count" -gt 0 ]; then
    vdpa_status=READY
fi

printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_ARCH=%s\n' "$arch"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_CPU_VENDOR=%s\n' "$cpu_vendor"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_VIRTUALIZATION_FLAGS=%s\n' "$virtualization_flags"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_CORE_KVM=%s\n' "$kvm_status"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_IOMMU_GROUPS=%s\n' "$iommu_group_count"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_VFIO_GROUP_NODES=%s\n' "$vfio_group_node_count"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_VFIO=%s\n' "$vfio_status"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_VDPA_DEVICES=%s\n' "$vdpa_device_count"
printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_VDPA=%s\n' "$vdpa_status"

if [ -d "$sysfs_root/kernel/iommu_groups" ]; then
    for group_path in "$sysfs_root"/kernel/iommu_groups/*; do
        [ -d "$group_path" ] || continue
        group_name=${group_path##*/}
        for device_path in "$group_path"/devices/*; do
            [ -e "$device_path" ] || continue
            device_name=${device_path##*/}
            driver=none
            if [ -L "$device_path/driver" ]; then
                driver=$(basename "$(readlink "$device_path/driver")")
            fi
            printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_IOMMU_DEVICE=group:%s,bdf:%s,driver:%s\n' \
                "$group_name" "$device_name" "$driver"
        done
    done
fi

if command -v lspci >/dev/null 2>&1; then
    printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_PCI_BEGIN\n'
    lspci -Dnnk || true
    printf 'EDGE_KVM_PHYSICAL_PREFLIGHT_PCI_END\n'
fi

case "$requirement" in
inventory)
    exit 0
    ;;
core)
    [ "$kvm_status" = READY ]
    ;;
vfio)
    [ "$vfio_status" = READY ]
    ;;
vdpa)
    [ "$vdpa_status" = READY ]
    ;;
esac
