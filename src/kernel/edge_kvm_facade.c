/* SPDX-License-Identifier: MPL-2.0 */
/* Clean-room KVM ioctl translation above the EdgeOS vmm object model. */

#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_facade.h"
#include "kernel/linux_errno.h"
#include "string.h"

int edge_kvm_facade_init(edge_kvm_facade_t *facade,
                         const edge_kvm_backend_ops_t *backend,
                         const edge_kvm_descriptor_ops_t *descriptors,
                         const edge_kvm_capability_table_t *capabilities) {
    int status;

    if (!facade || !descriptors || !descriptors->install || !capabilities)
        return -EDGE_LINUX_EINVAL;
    memset(facade, 0, sizeof(*facade));
    status = edge_kvm_object_table_init(&facade->objects, backend);
    if (status < 0) return status;
    facade->descriptors = *descriptors;
    facade->capabilities = *capabilities;
    edge_kvm_capability_freeze(&facade->capabilities);
    facade->initialized = 1u;
    return 0;
}

void edge_kvm_facade_reset(edge_kvm_facade_t *facade) {
    if (!facade || !facade->initialized) return;
    edge_kvm_object_table_reset(&facade->objects);
    memset(facade, 0, sizeof(*facade));
}

static int64_t edge_kvm_facade_create_vm(edge_kvm_facade_t *facade,
                                         uint32_t machine_type) {
    edge_kvm_handle_t handle;
    int descriptor;
    int status = edge_kvm_vm_create(&facade->objects, machine_type, &handle);

    if (status < 0) return status;
    descriptor = facade->descriptors.install(
        facade->descriptors.context, EDGE_KVM_DESCRIPTOR_VM, handle);
    if (descriptor < 0) {
        (void)edge_kvm_vm_release(&facade->objects, handle);
        return descriptor;
    }
    return descriptor;
}

int64_t edge_kvm_facade_system_ioctl(edge_kvm_facade_t *facade,
                                     uint32_t request, uint64_t argument) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    switch (request) {
    case EDGE_KVM_IOCTL_GET_API_VERSION:
        return EDGE_KVM_API_VERSION;
    case EDGE_KVM_IOCTL_CREATE_VM:
        return edge_kvm_facade_create_vm(facade, (uint32_t)argument);
    case EDGE_KVM_IOCTL_CHECK_EXTENSION:
        return edge_kvm_capability_query(&facade->capabilities,
                                         (uint32_t)argument);
    case EDGE_KVM_IOCTL_GET_VCPU_MMAP_SIZE:
        return EDGE_KVM_VCPU_MMAP_PAGES * EDGE_KVM_PAGE_SIZE;
    default:
        return -EDGE_LINUX_ENOTTY;
    }
}

static int64_t edge_kvm_facade_create_vcpu(edge_kvm_facade_t *facade,
                                           edge_kvm_handle_t vm,
                                           uint32_t vcpu_id) {
    edge_kvm_handle_t handle;
    int descriptor;
    int status = edge_kvm_vcpu_create(&facade->objects, vm, vcpu_id,
                                      &handle);

    if (status < 0) return status;
    descriptor = facade->descriptors.install(
        facade->descriptors.context, EDGE_KVM_DESCRIPTOR_VCPU, handle);
    if (descriptor < 0) {
        (void)edge_kvm_vcpu_release(&facade->objects, handle);
        return descriptor;
    }
    return descriptor;
}

int64_t edge_kvm_facade_vm_ioctl(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vm, uint32_t request,
                                 uint64_t argument) {
    const edge_kvm_userspace_memory_region_t *userspace_region;
    edge_kvm_memory_region_t region;

    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    switch (request) {
    case EDGE_KVM_IOCTL_CREATE_VCPU:
        return edge_kvm_facade_create_vcpu(facade, vm,
                                           (uint32_t)argument);
    case EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION:
        if (!argument) return -EDGE_LINUX_EFAULT;
        userspace_region =
            (const edge_kvm_userspace_memory_region_t *)(uintptr_t)argument;
        region.slot = userspace_region->slot;
        region.flags = userspace_region->flags;
        region.guest_physical_address =
            userspace_region->guest_physical_address;
        region.memory_size = userspace_region->memory_size;
        region.userspace_address = userspace_region->userspace_address;
        return edge_kvm_vm_set_memory_region(&facade->objects, vm, &region);
    default:
        return -EDGE_LINUX_ENOTTY;
    }
}

int edge_kvm_facade_descriptor_retain(edge_kvm_facade_t *facade,
                                      edge_kvm_descriptor_kind_t kind,
                                      edge_kvm_handle_t handle) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    if (kind == EDGE_KVM_DESCRIPTOR_VM)
        return edge_kvm_vm_retain(&facade->objects, handle);
    if (kind == EDGE_KVM_DESCRIPTOR_VCPU)
        return edge_kvm_vcpu_retain(&facade->objects, handle);
    return -EDGE_LINUX_EINVAL;
}

int edge_kvm_facade_descriptor_release(edge_kvm_facade_t *facade,
                                       edge_kvm_descriptor_kind_t kind,
                                       edge_kvm_handle_t handle) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    if (kind == EDGE_KVM_DESCRIPTOR_VM)
        return edge_kvm_vm_release(&facade->objects, handle);
    if (kind == EDGE_KVM_DESCRIPTOR_VCPU)
        return edge_kvm_vcpu_release(&facade->objects, handle);
    return -EDGE_LINUX_EINVAL;
}
