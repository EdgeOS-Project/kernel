/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_KVM_ABI_H
#define EDGEOS_KERNEL_EDGE_KVM_ABI_H

#include <stdint.h>

/* Linux-compatible ioctl encoding, independently implemented for EdgeOS. */
#define EDGE_LINUX_IOC_NR_BITS 8u
#define EDGE_LINUX_IOC_TYPE_BITS 8u
#define EDGE_LINUX_IOC_SIZE_BITS 14u
#define EDGE_LINUX_IOC_NR_SHIFT 0u
#define EDGE_LINUX_IOC_TYPE_SHIFT \
    (EDGE_LINUX_IOC_NR_SHIFT + EDGE_LINUX_IOC_NR_BITS)
#define EDGE_LINUX_IOC_SIZE_SHIFT \
    (EDGE_LINUX_IOC_TYPE_SHIFT + EDGE_LINUX_IOC_TYPE_BITS)
#define EDGE_LINUX_IOC_DIR_SHIFT \
    (EDGE_LINUX_IOC_SIZE_SHIFT + EDGE_LINUX_IOC_SIZE_BITS)
#define EDGE_LINUX_IOC_NONE 0u
#define EDGE_LINUX_IOC_WRITE 1u
#define EDGE_LINUX_IOC_READ 2u
#define EDGE_LINUX_IOC(direction, type, number, size) \
    (((uint32_t)(direction) << EDGE_LINUX_IOC_DIR_SHIFT) | \
     ((uint32_t)(size) << EDGE_LINUX_IOC_SIZE_SHIFT) | \
     ((uint32_t)(type) << EDGE_LINUX_IOC_TYPE_SHIFT) | \
     ((uint32_t)(number) << EDGE_LINUX_IOC_NR_SHIFT))
#define EDGE_LINUX_IO(type, number) \
    EDGE_LINUX_IOC(EDGE_LINUX_IOC_NONE, type, number, 0u)
#define EDGE_LINUX_IOW(type, number, data_type) \
    EDGE_LINUX_IOC(EDGE_LINUX_IOC_WRITE, type, number, sizeof(data_type))

#define EDGE_KVM_IOCTL_TYPE 0xaeu
#define EDGE_KVM_IOCTL_GET_API_VERSION \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x00u)
#define EDGE_KVM_IOCTL_CREATE_VM \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x01u)
#define EDGE_KVM_IOCTL_CHECK_EXTENSION \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x03u)
#define EDGE_KVM_IOCTL_GET_VCPU_MMAP_SIZE \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x04u)
#define EDGE_KVM_IOCTL_CREATE_VCPU \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x41u)
#define EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION \
    EDGE_LINUX_IOW(EDGE_KVM_IOCTL_TYPE, 0x46u, \
                   edge_kvm_userspace_memory_region_t)
#define EDGE_KVM_IOCTL_RUN \
    EDGE_LINUX_IO(EDGE_KVM_IOCTL_TYPE, 0x80u)

#define EDGE_KVM_VCPU_MMAP_PAGES 3u

typedef struct edge_kvm_userspace_memory_region {
    uint32_t slot;
    uint32_t flags;
    uint64_t guest_physical_address;
    uint64_t memory_size;
    uint64_t userspace_address;
} edge_kvm_userspace_memory_region_t;

/* Capability numbers observed from unmodified QEMU and Linux KVM behavior. */
enum edge_kvm_public_capability {
    EDGE_KVM_CAP_IRQCHIP = 0x00,
    EDGE_KVM_CAP_USER_MEMORY = 0x03,
    EDGE_KVM_CAP_SET_TSS_ADDR = 0x04,
    EDGE_KVM_CAP_EXT_CPUID = 0x07,
    EDGE_KVM_CAP_NR_VCPUS = 0x09,
    EDGE_KVM_CAP_NR_MEMSLOTS = 0x0a,
    EDGE_KVM_CAP_MP_STATE = 0x0e,
    EDGE_KVM_CAP_COALESCED_MMIO = 0x0f,
    EDGE_KVM_CAP_SYNC_MMU = 0x10,
    EDGE_KVM_CAP_DESTROY_MEMORY_REGION_WORKS = 0x15,
    EDGE_KVM_CAP_IRQ_ROUTING = 0x19,
    EDGE_KVM_CAP_INTERNAL_ERROR_DATA = 0x28,
    EDGE_KVM_CAP_VCPU_EVENTS = 0x29,
    EDGE_KVM_CAP_IRQFD = 0x20,
    EDGE_KVM_CAP_IOEVENTFD = 0x24,
    EDGE_KVM_CAP_MAX_VCPUS = 0x42,
    EDGE_KVM_CAP_READONLY_MEMORY = 0x51,
    EDGE_KVM_CAP_IMMEDIATE_EXIT = 0x88,
    EDGE_KVM_CAP_NESTED_STATE = 0x9d,
    EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 = 0xa8,
};

#endif
