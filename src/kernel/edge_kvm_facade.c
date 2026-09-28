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
    const edge_kvm_pit_config_t *pit_config;
    const edge_kvm_userspace_memory_region_t *userspace_region;

    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    switch (request) {
    case EDGE_KVM_IOCTL_CREATE_VCPU:
        return edge_kvm_facade_create_vcpu(facade, vm,
                                           (uint32_t)argument);
    case EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION:
        if (!argument) return -EDGE_LINUX_EFAULT;
        userspace_region =
            (const edge_kvm_userspace_memory_region_t *)(uintptr_t)argument;
        return edge_kvm_facade_vm_set_memory_region(facade, vm,
                                                     userspace_region);
    case EDGE_KVM_IOCTL_SET_TSS_ADDR:
        return edge_kvm_vm_set_tss_address(
            &facade->objects, vm, argument);
    case EDGE_KVM_IOCTL_SET_IDENTITY_MAP_ADDR:
        if (!argument) return -EDGE_LINUX_EFAULT;
        return edge_kvm_vm_set_identity_map_address(
            &facade->objects, vm, *(const uint64_t *)(uintptr_t)argument);
    case EDGE_KVM_IOCTL_CREATE_IRQCHIP:
        return edge_kvm_vm_create_irqchip(&facade->objects, vm);
    case EDGE_KVM_IOCTL_CREATE_PIT2:
        if (!argument) return -EDGE_LINUX_EFAULT;
        pit_config = (const edge_kvm_pit_config_t *)(uintptr_t)argument;
        return edge_kvm_vm_create_pit(&facade->objects, vm, pit_config);
    default:
        return -EDGE_LINUX_ENOTTY;
    }
}

int edge_kvm_facade_vm_set_gsi_routing(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        const edge_kvm_irq_routing_entry_t *entries, uint32_t count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_set_gsi_routing(
        &facade->objects, vm, entries, count);
}

int edge_kvm_facade_vm_set_irq_line(edge_kvm_facade_t *facade,
                                    edge_kvm_handle_t vm,
                                    edge_kvm_irq_level_t *level) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_set_irq_line(&facade->objects, vm, level);
}

int edge_kvm_facade_vm_signal_msi(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vm,
                                  const edge_kvm_msi_t *message) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_signal_msi(&facade->objects, vm, message);
}

int edge_kvm_facade_vm_get_irqchip(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vm,
                                   edge_kvm_irqchip_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_get_irqchip(&facade->objects, vm, state);
}

int edge_kvm_facade_vm_set_irqchip(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vm,
                                   const edge_kvm_irqchip_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_set_irqchip(&facade->objects, vm, state);
}

int edge_kvm_facade_vm_get_pit(edge_kvm_facade_t *facade,
                               edge_kvm_handle_t vm,
                               edge_kvm_pit_state2_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_get_pit(&facade->objects, vm, state);
}

int edge_kvm_facade_vm_set_pit(edge_kvm_facade_t *facade,
                               edge_kvm_handle_t vm,
                               const edge_kvm_pit_state2_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_set_pit(&facade->objects, vm, state);
}

int edge_kvm_facade_vm_get_clock(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vm,
                                 edge_kvm_clock_data_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_get_clock(&facade->objects, vm, state);
}

int edge_kvm_facade_vm_set_clock(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vm,
                                 const edge_kvm_clock_data_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_set_clock(&facade->objects, vm, state);
}

int edge_kvm_facade_vm_ioeventfd(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        const edge_kvm_ioeventfd_registration_t *event) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_ioeventfd(&facade->objects, vm, event);
}

int edge_kvm_facade_vm_irqfd(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        const edge_kvm_irqfd_registration_t *irq) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_irqfd(&facade->objects, vm, irq);
}

int edge_kvm_facade_vm_get_preferred_target(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        edge_kvm_vcpu_init_t *init) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_get_preferred_target(&facade->objects, vm, init);
}

int edge_kvm_facade_device_create(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vm, uint32_t type,
                                  uint32_t flags) {
    edge_kvm_handle_t handle;
    int descriptor;
    int status;

    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    status = edge_kvm_device_create(
        &facade->objects, vm, type, flags, &handle);
    if (status < 0) return status;
    descriptor = facade->descriptors.install(
        facade->descriptors.context, EDGE_KVM_DESCRIPTOR_DEVICE, handle);
    if (descriptor < 0) {
        (void)edge_kvm_device_release(&facade->objects, handle);
        return descriptor;
    }
    return descriptor;
}

int edge_kvm_facade_device_test(edge_kvm_facade_t *facade,
                                edge_kvm_handle_t vm, uint32_t type) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_device_test(&facade->objects, vm, type);
}

int edge_kvm_facade_device_set_attr(
        edge_kvm_facade_t *facade, edge_kvm_handle_t device,
        const edge_kvm_device_attr_t *attribute, const void *value,
        uint32_t value_size) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_device_set_attr(
        &facade->objects, device, attribute, value, value_size);
}

int edge_kvm_facade_device_get_attr(
        edge_kvm_facade_t *facade, edge_kvm_handle_t device,
        const edge_kvm_device_attr_t *attribute, void *value,
        uint32_t value_size) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_device_get_attr(
        &facade->objects, device, attribute, value, value_size);
}

int edge_kvm_facade_device_has_attr(
        edge_kvm_facade_t *facade, edge_kvm_handle_t device,
        const edge_kvm_device_attr_t *attribute) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_device_has_attr(
        &facade->objects, device, attribute);
}

int64_t edge_kvm_facade_vcpu_ioctl(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   uint32_t request, uint64_t argument) {
    (void)argument;
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    if (request == EDGE_KVM_IOCTL_RUN)
        return edge_kvm_vcpu_run(&facade->objects, vcpu);
    return -EDGE_LINUX_ENOTTY;
}

int edge_kvm_facade_vcpu_init(edge_kvm_facade_t *facade,
                              edge_kvm_handle_t vcpu,
                              const edge_kvm_vcpu_init_t *init) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_init(&facade->objects, vcpu, init);
}

int edge_kvm_facade_vcpu_get_one_reg(edge_kvm_facade_t *facade,
                                     edge_kvm_handle_t vcpu, uint64_t id,
                                     void *value, uint32_t size) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_one_reg(
        &facade->objects, vcpu, id, value, size);
}

int edge_kvm_facade_vcpu_set_one_reg(edge_kvm_facade_t *facade,
                                     edge_kvm_handle_t vcpu, uint64_t id,
                                     const void *value, uint32_t size) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_one_reg(
        &facade->objects, vcpu, id, value, size);
}

int edge_kvm_facade_vcpu_get_reg_list(edge_kvm_facade_t *facade,
                                      edge_kvm_handle_t vcpu,
                                      uint64_t *ids, uint32_t capacity,
                                      uint32_t *count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_reg_list(
        &facade->objects, vcpu, ids, capacity, count);
}

int edge_kvm_facade_vcpu_mmap_page(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   uint32_t page_index,
                                   uint64_t *physical_address) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_mmap_page(&facade->objects, vcpu, page_index,
                                   physical_address);
}

int edge_kvm_facade_vcpu_pre_fault_memory(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        edge_kvm_pre_fault_memory_t *request) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_pre_fault_memory(
        &facade->objects, vcpu, request);
}

int edge_kvm_facade_vcpu_translate(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_translation_t *translation) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_translate(&facade->objects, vcpu, translation);
}

int edge_kvm_facade_vcpu_get_regs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  edge_kvm_regs_t *registers) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_regs(&facade->objects, vcpu, registers);
}

int edge_kvm_facade_vcpu_set_regs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  const edge_kvm_regs_t *registers) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_regs(&facade->objects, vcpu, registers);
}

int edge_kvm_facade_vcpu_get_sregs(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_sregs_t *registers) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_sregs(&facade->objects, vcpu, registers);
}

int edge_kvm_facade_vcpu_set_sregs(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   const edge_kvm_sregs_t *registers) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_sregs(&facade->objects, vcpu, registers);
}

int edge_kvm_facade_vcpu_get_sregs2(edge_kvm_facade_t *facade,
                                    edge_kvm_handle_t vcpu,
                                    edge_kvm_sregs2_t *registers) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_sregs2(&facade->objects, vcpu, registers);
}

int edge_kvm_facade_vcpu_set_sregs2(edge_kvm_facade_t *facade,
                                    edge_kvm_handle_t vcpu,
                                    const edge_kvm_sregs2_t *registers) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_sregs2(&facade->objects, vcpu, registers);
}

int edge_kvm_facade_vcpu_get_fpu(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vcpu,
                                 edge_kvm_fpu_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_fpu(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_fpu(edge_kvm_facade_t *facade,
                                 edge_kvm_handle_t vcpu,
                                 const edge_kvm_fpu_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_fpu(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_get_lapic(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_lapic_state_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_lapic(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_lapic(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   const edge_kvm_lapic_state_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_lapic(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_get_debugregs(edge_kvm_facade_t *facade,
                                       edge_kvm_handle_t vcpu,
                                       edge_kvm_debugregs_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_debugregs(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_debugregs(edge_kvm_facade_t *facade,
                                       edge_kvm_handle_t vcpu,
                                       const edge_kvm_debugregs_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_debugregs(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_guest_debug(
    edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
    const edge_kvm_guest_debug_x86_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_guest_debug(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_get_xcrs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  edge_kvm_xcrs_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_xcrs(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_xcrs(edge_kvm_facade_t *facade,
                                  edge_kvm_handle_t vcpu,
                                  const edge_kvm_xcrs_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_xcrs(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_get_xsave(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   edge_kvm_xsave_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_xsave(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_xsave(edge_kvm_facade_t *facade,
                                   edge_kvm_handle_t vcpu,
                                   const edge_kvm_xsave_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_xsave(&facade->objects, vcpu, state);
}

int edge_kvm_facade_get_msr_index_list(
        edge_kvm_facade_t *facade, uint32_t *indices,
        uint32_t capacity, uint32_t *count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_get_msr_index_list(
        &facade->objects, indices, capacity, count);
}

int edge_kvm_facade_get_msr_feature_index_list(
        edge_kvm_facade_t *facade, uint32_t *indices,
        uint32_t capacity, uint32_t *count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_get_msr_feature_index_list(
        &facade->objects, indices, capacity, count);
}

int edge_kvm_facade_get_msr_features(
        edge_kvm_facade_t *facade, edge_kvm_msr_entry_t *entries,
        uint32_t count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_get_msr_features(&facade->objects, entries, count);
}

int edge_kvm_facade_get_mce_cap_supported(edge_kvm_facade_t *facade,
                                          uint64_t *capability) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_get_mce_cap_supported(&facade->objects, capability);
}

int edge_kvm_facade_vcpu_get_msrs(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        edge_kvm_msr_entry_t *entries, uint32_t count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_msrs(
        &facade->objects, vcpu, entries, count);
}

int edge_kvm_facade_vcpu_set_msrs(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        const edge_kvm_msr_entry_t *entries, uint32_t count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_msrs(
        &facade->objects, vcpu, entries, count);
}

int edge_kvm_facade_vcpu_get_mp_state(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        edge_kvm_mp_state_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_mp_state(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_set_mp_state(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        const edge_kvm_mp_state_t *state) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_mp_state(&facade->objects, vcpu, state);
}

int edge_kvm_facade_vcpu_get_events(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        edge_kvm_vcpu_events_t *events) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_events(&facade->objects, vcpu, events);
}

int edge_kvm_facade_vcpu_set_events(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        const edge_kvm_vcpu_events_t *events) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_events(&facade->objects, vcpu, events);
}

int edge_kvm_facade_vcpu_set_vapic_address(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        uint64_t address) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_vapic_address(
        &facade->objects, vcpu, address);
}

int64_t edge_kvm_facade_vcpu_get_tsc_khz(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_tsc_khz(&facade->objects, vcpu);
}

int edge_kvm_facade_vcpu_set_tsc_khz(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        uint32_t frequency_khz) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_tsc_khz(
        &facade->objects, vcpu, frequency_khz);
}

int edge_kvm_facade_vcpu_setup_mce(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        uint64_t capability) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_setup_mce(
        &facade->objects, vcpu, capability);
}

int edge_kvm_facade_vcpu_set_mce(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        const edge_kvm_x86_mce_t *machine_check) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_mce(
        &facade->objects, vcpu, machine_check);
}

int edge_kvm_facade_vcpu_set_signal_mask(edge_kvm_facade_t *facade,
                                         edge_kvm_handle_t vcpu,
                                         uint64_t mask) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_signal_mask(&facade->objects, vcpu, mask);
}

int edge_kvm_facade_get_supported_cpuid(
        edge_kvm_facade_t *facade, edge_kvm_cpuid_entry2_t *entries,
        uint32_t capacity, uint32_t *count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_get_supported_cpuid(
        &facade->objects, entries, capacity, count);
}

int edge_kvm_facade_vcpu_set_cpuid(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        const edge_kvm_cpuid_entry2_t *entries, uint32_t count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_set_cpuid(
        &facade->objects, vcpu, entries, count);
}

int edge_kvm_facade_vcpu_get_cpuid(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vcpu,
        edge_kvm_cpuid_entry2_t *entries, uint32_t capacity,
        uint32_t *count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vcpu_get_cpuid(
        &facade->objects, vcpu, entries, capacity, count);
}

int edge_kvm_facade_vm_set_memory_region(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        const edge_kvm_userspace_memory_region_t *userspace_region) {
    edge_kvm_memory_region_t region;

    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    if (!userspace_region) return -EDGE_LINUX_EFAULT;
    region.slot = userspace_region->slot;
    region.flags = userspace_region->flags;
    region.guest_physical_address =
        userspace_region->guest_physical_address;
    region.memory_size = userspace_region->memory_size;
    region.userspace_address = userspace_region->userspace_address;
    return edge_kvm_vm_set_memory_region(&facade->objects, vm, &region);
}

int edge_kvm_facade_vm_coalesced_mmio(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_coalesced_mmio(
        &facade->objects, vm, zone, unregister);
}

int edge_kvm_facade_vm_dirty_log_page_count(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm, uint32_t slot,
        uint32_t *page_count) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_dirty_log_page_count(
        &facade->objects, vm, slot, page_count);
}

int edge_kvm_facade_vm_get_dirty_log(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm, uint32_t slot,
        uint32_t first_page, uint32_t page_count, uint64_t *bitmap,
        uint32_t bitmap_words) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_get_dirty_log(
        &facade->objects, vm, slot, first_page, page_count,
        bitmap, bitmap_words);
}

int edge_kvm_facade_vm_enable_cap(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm,
        const edge_kvm_enable_cap_t *capability) {
    int32_t supported;

    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    if (!capability) return -EDGE_LINUX_EINVAL;
    supported = edge_kvm_capability_query(
        &facade->capabilities, capability->capability);
    if (supported <= 0) return -EDGE_LINUX_EOPNOTSUPP;
    if ((capability->arguments[0] & ~(uint64_t)(uint32_t)supported) != 0)
        return -EDGE_LINUX_EINVAL;
    return edge_kvm_vm_enable_cap(&facade->objects, vm, capability);
}

int edge_kvm_facade_vm_clear_dirty_log(
        edge_kvm_facade_t *facade, edge_kvm_handle_t vm, uint32_t slot,
        uint32_t first_page, uint32_t page_count,
        const uint64_t *bitmap, uint32_t bitmap_words) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    return edge_kvm_vm_clear_dirty_log(
        &facade->objects, vm, slot, first_page, page_count,
        bitmap, bitmap_words);
}

int edge_kvm_facade_descriptor_retain(edge_kvm_facade_t *facade,
                                      edge_kvm_descriptor_kind_t kind,
                                      edge_kvm_handle_t handle) {
    if (!facade || !facade->initialized) return -EDGE_LINUX_ENODEV;
    if (kind == EDGE_KVM_DESCRIPTOR_VM)
        return edge_kvm_vm_retain(&facade->objects, handle);
    if (kind == EDGE_KVM_DESCRIPTOR_VCPU)
        return edge_kvm_vcpu_retain(&facade->objects, handle);
    if (kind == EDGE_KVM_DESCRIPTOR_DEVICE)
        return edge_kvm_device_retain(&facade->objects, handle);
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
    if (kind == EDGE_KVM_DESCRIPTOR_DEVICE)
        return edge_kvm_device_release(&facade->objects, handle);
    return -EDGE_LINUX_EINVAL;
}
