/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"

int kernel_anonymous_fd_descriptor_object_id(
        int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    return kind == KERNEL_ANONYMOUS_FD_EVENT && descriptor >= 0 ?
        descriptor : -EDGE_LINUX_EBADF;
}

int kernel_eventfd_retain(int event_id) {
    return event_id >= 0 ? 0 : -EDGE_LINUX_EBADF;
}

void kernel_eventfd_release(int event_id) {
    (void)event_id;
}

typedef struct runtime_mock {
    kernel_edge_kvm_file_t files[32];
    uint8_t live[32];
    uint8_t stats[32];
    int next_descriptor;
    uint64_t guest_memfd_size;
    uint32_t vm_destroys;
    uint32_t vcpu_destroys;
    uint32_t device_destroys;
    uint32_t memory_updates;
    uint32_t coalesced_updates;
    uint8_t coalesced_unregister;
    edge_kvm_coalesced_mmio_zone_t coalesced_zone;
    uint32_t vcpu_runs;
    uint32_t pre_fault_pages;
    edge_kvm_regs_t registers;
    edge_kvm_sregs_t special_registers;
    edge_kvm_sregs2_t special_registers2;
    edge_kvm_fpu_t fpu_state;
    edge_kvm_lapic_state_t lapic_state;
    edge_kvm_debugregs_t debug_registers;
    edge_kvm_guest_debug_x86_t guest_debug;
    edge_kvm_xcrs_t xcrs;
    edge_kvm_xsave_t xsave;
    edge_kvm_irqchip_t irqchip;
    edge_kvm_pit_state2_t pit_state;
    edge_kvm_msr_entry_t msrs[4];
    uint32_t msr_count;
    edge_kvm_mp_state_t mp_state;
    edge_kvm_vcpu_events_t events;
    uint32_t tsc_frequency_khz;
    uint64_t mce_capability;
    edge_kvm_x86_mce_t machine_check;
    edge_kvm_cpuid_entry2_t cpuid_entries[4];
    uint32_t cpuid_count;
    edge_kvm_vcpu_init_t vcpu_init;
    uint64_t arm_x0;
    uint64_t vgic_dist_address;
    uint64_t vgic_redist_address;
    uint32_t vgic_interrupt_count;
    uint8_t vgic_initialized;
    uint8_t run_pages[EDGE_KVM_VCPU_MMAP_PAGES][EDGE_KVM_PAGE_SIZE]
        __attribute__((aligned(EDGE_KVM_PAGE_SIZE)));
} runtime_mock_t;

static int g_copy_to_user_fail_once;

static int get_supported_cpuid(void *context,
                               edge_kvm_cpuid_entry2_t *entries,
                               uint32_t capacity, uint32_t *count) {
    (void)context;
    *count = 2;
    if (capacity > 0)
        entries[0] = (edge_kvm_cpuid_entry2_t) {.function = 0,
                                                .eax = 1};
    if (capacity > 1)
        entries[1] = (edge_kvm_cpuid_entry2_t) {.function = 1,
                                                .eax = 0x1234};
    return 0;
}

static int descriptor_install(void *context, kernel_edge_kvm_file_kind_t kind,
                              edge_kvm_handle_t handle) {
    runtime_mock_t *mock = context;
    int descriptor = mock->next_descriptor++;
    assert(descriptor >= 0 && descriptor < 32);
    mock->files[descriptor].kind = kind;
    mock->files[descriptor].handle = handle;
    mock->live[descriptor] = 1u;
    return descriptor;
}

static int descriptor_resolve(void *context, int32_t descriptor,
                              kernel_edge_kvm_file_t *file) {
    runtime_mock_t *mock = context;
    if (descriptor == 3) {
        memset(file, 0, sizeof(*file));
        file->kind = KERNEL_EDGE_KVM_FILE_SYSTEM;
        return 0;
    }
    if (descriptor < 0 || descriptor >= 32 || !mock->live[descriptor] ||
        mock->stats[descriptor])
        return -EDGE_LINUX_EBADF;
    *file = mock->files[descriptor];
    return 0;
}

static int descriptor_install_stats(
        void *context, kernel_edge_kvm_file_kind_t source_kind,
        edge_kvm_handle_t handle) {
    runtime_mock_t *mock = context;
    int descriptor = mock->next_descriptor++;

    assert(source_kind == KERNEL_EDGE_KVM_FILE_VM ||
           source_kind == KERNEL_EDGE_KVM_FILE_VCPU);
    assert(descriptor >= 0 && descriptor < 32);
    mock->files[descriptor].kind = source_kind;
    mock->files[descriptor].handle = handle;
    mock->live[descriptor] = 1u;
    mock->stats[descriptor] = 1u;
    return descriptor;
}

static int descriptor_install_guest_memfd(void *context, uint64_t size) {
    runtime_mock_t *mock = context;
    int descriptor = 31;

    assert(size != 0);
    assert(descriptor >= 0 && descriptor < 32);
    mock->guest_memfd_size = size;
    return descriptor;
}

static int descriptor_close(void *context, int32_t descriptor) {
    runtime_mock_t *mock = context;
    kernel_edge_kvm_file_t file;
    int status;

    if (descriptor >= 0 && descriptor < 32 && mock->live[descriptor] &&
        mock->stats[descriptor]) {
        file = mock->files[descriptor];
        mock->live[descriptor] = 0;
        mock->stats[descriptor] = 0;
        return kernel_edge_kvm_descriptor_release(file.kind, file.handle);
    }
    status = descriptor_resolve(context, descriptor, &file);
    if (status < 0) return status;
    mock->live[descriptor] = 0;
    return kernel_edge_kvm_descriptor_release(file.kind, file.handle);
}

static int vm_create(void *context, uint32_t machine_type, uint64_t *cookie) {
    (void)context;
    *cookie = 0x1000u + machine_type;
    return 0;
}

static void vm_destroy(void *context, uint64_t cookie) {
    runtime_mock_t *mock = context;
    (void)cookie;
    ++mock->vm_destroys;
}

static int vm_get_preferred_target(void *context, uint64_t cookie,
                                   edge_kvm_vcpu_init_t *init) {
    (void)context;
    assert(cookie != 0 && init != 0);
    memset(init, 0, sizeof(*init));
    init->target = 7;
    return 0;
}

static int vm_set_address(void *context, uint64_t cookie,
                          uint64_t address) {
    (void)context;
    assert(cookie != 0 && (address & (EDGE_KVM_PAGE_SIZE - 1)) == 0);
    return 0;
}

static int vm_coalesced_mmio(
        void *context, uint64_t cookie,
        const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister) {
    runtime_mock_t *mock = context;

    assert(cookie != 0 && zone != 0);
    mock->coalesced_zone = *zone;
    mock->coalesced_unregister = unregister;
    ++mock->coalesced_updates;
    return 0;
}

static int vm_create_irqchip(void *context, uint64_t cookie) {
    (void)context;
    assert(cookie != 0);
    return 0;
}

static int vm_set_gsi_routing(
        void *context, uint64_t cookie,
        const edge_kvm_irq_routing_entry_t *entries, uint32_t count) {
    (void)context;
    assert(cookie != 0 && (count == 0 || entries != 0));
    return 0;
}

static int vm_set_irq_line(void *context, uint64_t cookie,
                           edge_kvm_irq_level_t *level) {
    (void)context;
    assert(cookie != 0 && level != 0 && level->level <= 1);
    return 0;
}

static int vm_get_irqchip(void *context, uint64_t cookie,
                          edge_kvm_irqchip_t *state) {
    runtime_mock_t *mock = context;
    assert(cookie != 0);
    *state = mock->irqchip;
    return 0;
}

static int vm_set_irqchip(void *context, uint64_t cookie,
                          const edge_kvm_irqchip_t *state) {
    runtime_mock_t *mock = context;
    assert(cookie != 0);
    mock->irqchip = *state;
    return 0;
}

static int vm_get_pit(void *context, uint64_t cookie,
                      edge_kvm_pit_state2_t *state) {
    runtime_mock_t *mock = context;
    assert(cookie != 0);
    *state = mock->pit_state;
    return 0;
}

static int vm_set_pit(void *context, uint64_t cookie,
                      const edge_kvm_pit_state2_t *state) {
    runtime_mock_t *mock = context;
    assert(cookie != 0);
    mock->pit_state = *state;
    return 0;
}

static int vm_create_pit(void *context, uint64_t cookie,
                         const edge_kvm_pit_config_t *config) {
    (void)context;
    assert(cookie != 0 && config != 0 && config->flags == 0);
    return 0;
}

static int vcpu_create(void *context, uint64_t vm_cookie, uint32_t vcpu_id,
                       uint64_t *cookie) {
    (void)context;
    *cookie = vm_cookie + vcpu_id + 1u;
    return 0;
}

static void vcpu_destroy(void *context, uint64_t cookie) {
    runtime_mock_t *mock = context;
    (void)cookie;
    ++mock->vcpu_destroys;
}

static int device_create(void *context, uint64_t vm_cookie, uint32_t type,
                         uint32_t flags, uint64_t *cookie) {
    (void)context;
    assert(vm_cookie != 0 && type == EDGE_KVM_DEVICE_ARM_VGIC_V3 &&
           (flags == 0 || flags == EDGE_KVM_CREATE_DEVICE_TEST) &&
           cookie != 0);
    if (flags == EDGE_KVM_CREATE_DEVICE_TEST) {
        *cookie = 0;
        return 0;
    }
    *cookie = vm_cookie + UINT64_C(0x2000);
    return 0;
}

static void device_destroy(void *context, uint64_t cookie) {
    runtime_mock_t *mock = context;
    assert(cookie != 0);
    ++mock->device_destroys;
}

static int device_has_attr(void *context, uint64_t cookie,
                           const edge_kvm_device_attr_t *attribute) {
    (void)context;
    assert(cookie != 0 && attribute != 0);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS &&
        (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST ||
         attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST))
        return 0;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0)
        return 0;
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL &&
        attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT)
        return 0;
    return -EDGE_LINUX_ENXIO;
}

static int device_set_attr(void *context, uint64_t cookie,
                           const edge_kvm_device_attr_t *attribute,
                           const void *value, uint32_t value_size) {
    runtime_mock_t *mock = context;
    assert(cookie != 0 && attribute != 0);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS &&
        value_size == sizeof(uint64_t)) {
        if (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST)
            memcpy(&mock->vgic_dist_address, value, value_size);
        else if (attribute->attribute ==
                 EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST)
            memcpy(&mock->vgic_redist_address, value, value_size);
        else
            return -EDGE_LINUX_ENXIO;
        return 0;
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0 && value_size == sizeof(uint32_t)) {
        memcpy(&mock->vgic_interrupt_count, value, value_size);
        return 0;
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL &&
        attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT &&
        value_size == 0) {
        mock->vgic_initialized = 1;
        return 0;
    }
    return -EDGE_LINUX_ENXIO;
}

static int device_get_attr(void *context, uint64_t cookie,
                           const edge_kvm_device_attr_t *attribute,
                           void *value, uint32_t value_size) {
    runtime_mock_t *mock = context;
    assert(cookie != 0 && attribute != 0 && value != 0);
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS &&
        value_size == sizeof(uint64_t)) {
        if (attribute->attribute == EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST)
            memcpy(value, &mock->vgic_dist_address, value_size);
        else if (attribute->attribute ==
                 EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST)
            memcpy(value, &mock->vgic_redist_address, value_size);
        else
            return -EDGE_LINUX_ENXIO;
        return 0;
    }
    if (attribute->group == EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS &&
        attribute->attribute == 0 && value_size == sizeof(uint32_t)) {
        memcpy(value, &mock->vgic_interrupt_count, value_size);
        return 0;
    }
    return -EDGE_LINUX_ENXIO;
}

static int vcpu_init(void *context, uint64_t cookie,
                     const edge_kvm_vcpu_init_t *init) {
    runtime_mock_t *mock = context;
    assert(cookie != 0 && init != 0);
    mock->vcpu_init = *init;
    return 0;
}

static int vcpu_get_one_reg(void *context, uint64_t cookie, uint64_t id,
                            void *value, uint32_t size) {
    runtime_mock_t *mock = context;
    assert(cookie != 0 && id == EDGE_KVM_REG_ARM64_X(0) &&
           size == sizeof(mock->arm_x0));
    memcpy(value, &mock->arm_x0, size);
    return 0;
}

static int vcpu_set_one_reg(void *context, uint64_t cookie, uint64_t id,
                            const void *value, uint32_t size) {
    runtime_mock_t *mock = context;
    assert(cookie != 0 && id == EDGE_KVM_REG_ARM64_X(0) &&
           size == sizeof(mock->arm_x0));
    memcpy(&mock->arm_x0, value, size);
    return 0;
}

static int vcpu_get_reg_list(void *context, uint64_t cookie, uint64_t *ids,
                             uint32_t capacity, uint32_t *count) {
    (void)context;
    assert(cookie != 0 && count != 0);
    *count = 2;
    if (capacity > 0) ids[0] = EDGE_KVM_REG_ARM64_X(0);
    if (capacity > 1) ids[1] = EDGE_KVM_REG_ARM64_PC;
    return 0;
}

static int vcpu_run(void *context, uint64_t cookie, edge_kvm_run_t *run) {
    runtime_mock_t *mock = context;
    (void)cookie;
    ++mock->vcpu_runs;
    run->exit_reason = EDGE_KVM_EXIT_HLT;
    return 0;
}

static int vcpu_get_regs(void *context, uint64_t cookie,
                         edge_kvm_regs_t *registers) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *registers = mock->registers;
    return 0;
}

static int vcpu_set_regs(void *context, uint64_t cookie,
                         const edge_kvm_regs_t *registers) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->registers = *registers;
    return 0;
}

static int vcpu_get_sregs(void *context, uint64_t cookie,
                          edge_kvm_sregs_t *registers) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *registers = mock->special_registers;
    return 0;
}

static int vcpu_set_sregs(void *context, uint64_t cookie,
                          const edge_kvm_sregs_t *registers) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->special_registers = *registers;
    return 0;
}

static int vcpu_get_sregs2(void *context, uint64_t cookie,
                           edge_kvm_sregs2_t *registers) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *registers = mock->special_registers2;
    return 0;
}

static int vcpu_set_sregs2(void *context, uint64_t cookie,
                           const edge_kvm_sregs2_t *registers) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->special_registers2 = *registers;
    return 0;
}

static int vcpu_get_fpu(void *context, uint64_t cookie,
                        edge_kvm_fpu_t *fpu_state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *fpu_state = mock->fpu_state;
    return 0;
}

static int vcpu_set_fpu(void *context, uint64_t cookie,
                        const edge_kvm_fpu_t *fpu_state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->fpu_state = *fpu_state;
    return 0;
}

static int get_msr_index_list(void *context, uint32_t *indices,
                              uint32_t capacity, uint32_t *count) {
    (void)context;
    *count = 1;
    if (capacity != 0) indices[0] = 0x10;
    return 0;
}

static int get_msr_feature_index_list(void *context, uint32_t *indices,
                                      uint32_t capacity, uint32_t *count) {
    (void)context;
    *count = 1;
    if (capacity != 0) indices[0] = UINT32_C(0xc0011029);
    return 0;
}

static int get_msr_features(void *context, edge_kvm_msr_entry_t *entries,
                            uint32_t count) {
    (void)context;
    for (uint32_t index = 0; index < count; ++index) {
        if (entries[index].index != UINT32_C(0xc0011029))
            return (int)index;
        entries[index].data = 0;
    }
    return (int)count;
}

static int vcpu_get_msrs(void *context, uint64_t cookie,
                         edge_kvm_msr_entry_t *entries, uint32_t count) {
    runtime_mock_t *mock = context;
    (void)cookie;
    assert(count <= mock->msr_count);
    for (uint32_t index = 0; index < count; ++index)
        entries[index].data = mock->msrs[index].data;
    return (int)count;
}

static int vcpu_set_msrs(void *context, uint64_t cookie,
                         const edge_kvm_msr_entry_t *entries,
                         uint32_t count) {
    runtime_mock_t *mock = context;
    (void)cookie;
    assert(count <= 4);
    if (count != 0) memcpy(mock->msrs, entries,
                           count * sizeof(entries[0]));
    mock->msr_count = count;
    return (int)count;
}

static int vcpu_get_mp_state(void *context, uint64_t cookie,
                             edge_kvm_mp_state_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *state = mock->mp_state;
    return 0;
}

static int vcpu_set_mp_state(void *context, uint64_t cookie,
                             const edge_kvm_mp_state_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->mp_state = *state;
    return 0;
}

static int vcpu_get_lapic(void *context, uint64_t cookie,
                          edge_kvm_lapic_state_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *state = mock->lapic_state;
    return 0;
}

static int vcpu_set_lapic(void *context, uint64_t cookie,
                          const edge_kvm_lapic_state_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->lapic_state = *state;
    return 0;
}

static int vcpu_get_debugregs(void *context, uint64_t cookie,
                              edge_kvm_debugregs_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *state = mock->debug_registers;
    return 0;
}

static int vcpu_set_debugregs(void *context, uint64_t cookie,
                              const edge_kvm_debugregs_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->debug_registers = *state;
    return 0;
}

static int vcpu_set_guest_debug(
    void *context, uint64_t cookie,
    const edge_kvm_guest_debug_x86_t *state) {
    runtime_mock_t *mock = context;
    assert(cookie != 0);
    mock->guest_debug = *state;
    return 0;
}

static int vcpu_get_xcrs(void *context, uint64_t cookie,
                         edge_kvm_xcrs_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *state = mock->xcrs;
    return 0;
}

static int vcpu_set_xcrs(void *context, uint64_t cookie,
                         const edge_kvm_xcrs_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->xcrs = *state;
    return 0;
}

static int vcpu_get_xsave(void *context, uint64_t cookie,
                          edge_kvm_xsave_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *state = mock->xsave;
    return 0;
}

static int vcpu_set_xsave(void *context, uint64_t cookie,
                          const edge_kvm_xsave_t *state) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->xsave = *state;
    return 0;
}

static int vcpu_get_events(void *context, uint64_t cookie,
                           edge_kvm_vcpu_events_t *events) {
    runtime_mock_t *mock = context;
    (void)cookie;
    *events = mock->events;
    return 0;
}

static int vcpu_set_events(void *context, uint64_t cookie,
                           const edge_kvm_vcpu_events_t *events) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->events = *events;
    return 0;
}

static int64_t vcpu_get_tsc_khz(void *context, uint64_t cookie) {
    runtime_mock_t *mock = context;
    (void)cookie;
    return mock->tsc_frequency_khz;
}

static int vcpu_set_tsc_khz(void *context, uint64_t cookie,
                            uint32_t frequency_khz) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->tsc_frequency_khz = frequency_khz;
    return 0;
}

static int vcpu_setup_mce(void *context, uint64_t cookie,
                          uint64_t capability) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->mce_capability = capability;
    return 0;
}

static int vcpu_set_mce(void *context, uint64_t cookie,
                        const edge_kvm_x86_mce_t *machine_check) {
    runtime_mock_t *mock = context;
    (void)cookie;
    mock->machine_check = *machine_check;
    return 0;
}

static int vcpu_set_cpuid(void *context, uint64_t cookie,
                          const edge_kvm_cpuid_entry2_t *entries,
                          uint32_t count) {
    runtime_mock_t *mock = context;
    (void)cookie;
    assert(count <= 4);
    if (count != 0)
        memcpy(mock->cpuid_entries, entries, count * sizeof(entries[0]));
    mock->cpuid_count = count;
    return 0;
}

static int vcpu_get_cpuid(void *context, uint64_t cookie,
                          edge_kvm_cpuid_entry2_t *entries,
                          uint32_t capacity, uint32_t *count) {
    runtime_mock_t *mock = context;
    uint32_t copied;

    (void)cookie;
    assert(count != 0);
    *count = mock->cpuid_count;
    copied = capacity < mock->cpuid_count ? capacity : mock->cpuid_count;
    if (copied != 0)
        memcpy(entries, mock->cpuid_entries,
               copied * sizeof(entries[0]));
    return 0;
}

static int vcpu_mmap_page(void *context, uint64_t cookie,
                          uint32_t page_index, uint64_t *physical) {
    runtime_mock_t *mock = context;
    (void)cookie;
    if (page_index >= EDGE_KVM_VCPU_MMAP_PAGES || !physical)
        return -EDGE_LINUX_EINVAL;
    *physical = (uint64_t)(uintptr_t)mock->run_pages[page_index];
    return 0;
}

static int vcpu_pre_fault_memory(void *context, uint64_t cookie,
                                 edge_kvm_pre_fault_memory_t *request) {
    runtime_mock_t *mock = context;
    uint32_t processed = 0;

    assert(cookie != 0 && request != 0);
    while (request->size != 0 &&
           request->guest_physical_address < UINT64_C(0x4000)) {
        request->guest_physical_address += EDGE_KVM_PAGE_SIZE;
        request->size -= EDGE_KVM_PAGE_SIZE;
        ++processed;
    }
    mock->pre_fault_pages += processed;
    return processed != 0 ? 0 : -EDGE_LINUX_ENOENT;
}

static int vcpu_translate(void *context, uint64_t cookie,
                          edge_kvm_translation_t *translation) {
    (void)context;
    assert(cookie != 0 && translation != 0);
    translation->physical_address = translation->linear_address + 0x1000;
    translation->valid = 1;
    translation->writeable = 1;
    translation->usermode = 0;
    return 0;
}

static int memory_region_set(void *context, uint64_t vm_cookie,
                             const edge_kvm_memory_region_t *region) {
    runtime_mock_t *mock = context;
    (void)vm_cookie;
    (void)region;
    ++mock->memory_updates;
    return 0;
}

static int memory_dirty_log_get(
        void *context, uint64_t vm_cookie, uint32_t slot,
        uint32_t first_page, uint32_t page_count, uint64_t *bitmap,
        uint32_t bitmap_words, uint8_t clear) {
    (void)context;
    (void)vm_cookie;
    (void)slot;
    (void)first_page;
    (void)page_count;
    (void)clear;
    memset(bitmap, 0, (size_t)bitmap_words * sizeof(bitmap[0]));
    bitmap[0] = UINT64_C(0x21);
    return 0;
}

static int memory_dirty_log_clear(
        void *context, uint64_t vm_cookie, uint32_t slot,
        uint32_t first_page, uint32_t page_count,
        const uint64_t *bitmap, uint32_t bitmap_words) {
    (void)context;
    (void)vm_cookie;
    (void)slot;
    (void)first_page;
    (void)page_count;
    (void)bitmap;
    (void)bitmap_words;
    return 0;
}

static int copy_from_user(void *context, void *destination, uint64_t source,
                          uint64_t size) {
    (void)context;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)size);
    return 0;
}

static int copy_to_user(void *context, uint64_t destination,
                        const void *source, uint64_t size) {
    (void)context;
    if (g_copy_to_user_fail_once) {
        g_copy_to_user_fail_once = 0;
        return -1;
    }
    memcpy((void *)(uintptr_t)destination, source, (size_t)size);
    return 0;
}

int main(void) {
    runtime_mock_t mock = {
        .next_descriptor = 10,
        .tsc_frequency_khz = UINT32_C(2900000),
    };
    kernel_edge_kvm_descriptor_backend_ops_t descriptor_ops = {
        .install = descriptor_install,
        .resolve = descriptor_resolve,
        .install_stats = descriptor_install_stats,
        .install_guest_memfd = descriptor_install_guest_memfd,
        .close = descriptor_close,
    };
    edge_kvm_backend_ops_t backend = {
        .context = &mock,
        .get_supported_cpuid = get_supported_cpuid,
        .get_msr_index_list = get_msr_index_list,
        .get_msr_feature_index_list = get_msr_feature_index_list,
        .get_msr_features = get_msr_features,
        .vm_create = vm_create,
        .vm_destroy = vm_destroy,
        .vm_get_preferred_target = vm_get_preferred_target,
        .vm_set_tss_address = vm_set_address,
        .vm_set_identity_map_address = vm_set_address,
        .vm_coalesced_mmio = vm_coalesced_mmio,
        .vm_create_irqchip = vm_create_irqchip,
        .vm_set_gsi_routing = vm_set_gsi_routing,
        .vm_set_irq_line = vm_set_irq_line,
        .vm_get_irqchip = vm_get_irqchip,
        .vm_set_irqchip = vm_set_irqchip,
        .vm_create_pit = vm_create_pit,
        .vm_get_pit = vm_get_pit,
        .vm_set_pit = vm_set_pit,
        .vcpu_create = vcpu_create,
        .vcpu_destroy = vcpu_destroy,
        .vcpu_init = vcpu_init,
        .vcpu_get_one_reg = vcpu_get_one_reg,
        .vcpu_set_one_reg = vcpu_set_one_reg,
        .vcpu_get_reg_list = vcpu_get_reg_list,
        .vcpu_run = vcpu_run,
        .vcpu_get_regs = vcpu_get_regs,
        .vcpu_set_regs = vcpu_set_regs,
        .vcpu_get_sregs = vcpu_get_sregs,
        .vcpu_set_sregs = vcpu_set_sregs,
        .vcpu_get_sregs2 = vcpu_get_sregs2,
        .vcpu_set_sregs2 = vcpu_set_sregs2,
        .vcpu_get_fpu = vcpu_get_fpu,
        .vcpu_set_fpu = vcpu_set_fpu,
        .vcpu_get_lapic = vcpu_get_lapic,
        .vcpu_set_lapic = vcpu_set_lapic,
        .vcpu_get_debugregs = vcpu_get_debugregs,
        .vcpu_set_debugregs = vcpu_set_debugregs,
        .vcpu_set_guest_debug = vcpu_set_guest_debug,
        .vcpu_get_xcrs = vcpu_get_xcrs,
        .vcpu_set_xcrs = vcpu_set_xcrs,
        .vcpu_get_xsave = vcpu_get_xsave,
        .vcpu_set_xsave = vcpu_set_xsave,
        .vcpu_get_msrs = vcpu_get_msrs,
        .vcpu_set_msrs = vcpu_set_msrs,
        .vcpu_get_mp_state = vcpu_get_mp_state,
        .vcpu_set_mp_state = vcpu_set_mp_state,
        .vcpu_get_events = vcpu_get_events,
        .vcpu_set_events = vcpu_set_events,
        .vcpu_get_tsc_khz = vcpu_get_tsc_khz,
        .vcpu_set_tsc_khz = vcpu_set_tsc_khz,
        .vcpu_setup_mce = vcpu_setup_mce,
        .vcpu_set_mce = vcpu_set_mce,
        .vcpu_set_cpuid = vcpu_set_cpuid,
        .vcpu_get_cpuid = vcpu_get_cpuid,
        .vcpu_mmap_page = vcpu_mmap_page,
        .vcpu_pre_fault_memory = vcpu_pre_fault_memory,
        .vcpu_translate = vcpu_translate,
        .memory_region_set = memory_region_set,
        .memory_dirty_log_get = memory_dirty_log_get,
        .memory_dirty_log_clear = memory_dirty_log_clear,
        .device_create = device_create,
        .device_destroy = device_destroy,
        .device_set_attr = device_set_attr,
        .device_get_attr = device_get_attr,
        .device_has_attr = device_has_attr,
    };
    edge_kvm_capability_table_t capabilities;
    kernel_ioctl_request_t request = {.descriptor = 3};
    edge_kvm_userspace_memory_region_t memory = {
        .slot = 0,
        .flags = EDGE_KVM_MEMORY_LOG_DIRTY_PAGES,
        .guest_physical_address = 0,
        .memory_size = 0x4000,
        .userspace_address = 0x100000,
    };
    int vm_descriptor;
    int vcpu_descriptor;
    int device_descriptor;

    edge_kvm_capability_table_init(&capabilities);
    assert(edge_kvm_capability_set(
               &capabilities, EDGE_KVM_CAP_USER_MEMORY, 1) == 0);
    assert(edge_kvm_capability_set(
               &capabilities, EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
               EDGE_KVM_DIRTY_LOG_MANUAL_SUPPORTED_FLAGS) == 0);
    assert(edge_kvm_capability_set(
               &capabilities, EDGE_KVM_CAP_PRE_FAULT_MEMORY, 1) == 0);
    assert(edge_kvm_capability_set(
               &capabilities, EDGE_KVM_CAP_GET_MSR_FEATURES, 1) == 0);
    assert(kernel_edge_kvm_descriptor_backend_register(
               &descriptor_ops, &mock) == 0);
    assert(kernel_edge_kvm_backend_register(&backend, &capabilities) == 0);

    request.copy_from_user = copy_from_user;
    request.copy_to_user = copy_to_user;
    request.command = EDGE_KVM_IOCTL_GET_API_VERSION;
    assert(kernel_edge_kvm_ioctl(&request) == EDGE_KVM_API_VERSION);
    request.command = EDGE_KVM_IOCTL_CHECK_EXTENSION;
    request.argument = EDGE_KVM_CAP_PRE_FAULT_MEMORY;
    assert(kernel_edge_kvm_ioctl(&request) == 1);
    request.command = EDGE_KVM_IOCTL_GET_STATS_FD;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
    request.command = EDGE_KVM_IOCTL_GET_MSR_FEATURE_INDEX_LIST;
    request.argument = 0;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EFAULT);
    request.command = EDGE_KVM_IOCTL_GET_NR_MMU_PAGES;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
    {
        struct {
            uint32_t nent;
            uint32_t padding;
            edge_kvm_cpuid_entry2_t entries[1];
        } cpuid = {.nent = 1};

        request.command = EDGE_KVM_IOCTL_GET_EMULATED_CPUID;
        request.argument = (uint64_t)(uintptr_t)&cpuid;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(cpuid.nent == 0 && cpuid.padding == 0);
    }
    {
        struct {
            uint32_t nmsrs;
            uint32_t indices[1];
        } list = {0};

        request.command = EDGE_KVM_IOCTL_GET_MSR_INDEX_LIST;
        request.argument = (uint64_t)(uintptr_t)&list;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_E2BIG);
        assert(list.nmsrs == 1);
        list.nmsrs = 1;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(list.nmsrs == 1 && list.indices[0] == 0x10u);

        list.nmsrs = 0;
        request.command = EDGE_KVM_IOCTL_GET_MSR_FEATURE_INDEX_LIST;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_E2BIG);
        assert(list.nmsrs == 1);
        list.nmsrs = 1;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(list.indices[0] == UINT32_C(0xc0011029));
    }
    {
        struct {
            struct {
                uint32_t nmsrs;
                uint32_t padding;
            } header;
            edge_kvm_msr_entry_t entry;
        } features = {
            .header = {.nmsrs = 1},
            .entry = {
                .index = UINT32_C(0xc0011029),
                .data = UINT64_MAX,
            },
        };

        request.command = EDGE_KVM_IOCTL_GET_MSRS;
        request.argument = (uint64_t)(uintptr_t)&features;
        assert(kernel_edge_kvm_ioctl(&request) == 1);
        assert(features.entry.data == 0);
        features.entry.index = UINT32_C(0xdeadbeef);
        assert(kernel_edge_kvm_ioctl(&request) == 0);
    }
    {
        struct {
            struct { uint32_t nent; uint32_t padding; } header;
            edge_kvm_cpuid_entry2_t entries[2];
        } cpuid = {.header = {.nent = 1}};
        request.command = EDGE_KVM_IOCTL_GET_SUPPORTED_CPUID;
        request.argument = (uint64_t)(uintptr_t)&cpuid;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_E2BIG);
        assert(cpuid.header.nent == 2);
        cpuid.header.nent = 2;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(cpuid.header.nent == 2 && cpuid.entries[1].eax == 0x1234);
    }
    request.command = EDGE_KVM_IOCTL_CREATE_VM;
    request.argument = 2;
    vm_descriptor = (int)kernel_edge_kvm_ioctl(&request);
    assert(vm_descriptor == 10);

    request.descriptor = vm_descriptor;
    {
        edge_kvm_coalesced_mmio_zone_t zone = {
            .address = UINT64_C(0x10000000),
            .size = UINT32_C(0x1000),
        };

        request.command = EDGE_KVM_IOCTL_REGISTER_COALESCED_MMIO;
        request.argument = (uint64_t)(uintptr_t)&zone;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.coalesced_updates == 1);
        assert(mock.coalesced_unregister == 0);
        assert(mock.coalesced_zone.address == zone.address);
        zone.pio = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        zone.pio = 0;
        zone.size = 0;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        zone.size = UINT32_C(0x1000);
        request.command = EDGE_KVM_IOCTL_UNREGISTER_COALESCED_MMIO;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.coalesced_updates == 2);
        assert(mock.coalesced_unregister == 1);
    }
    {
        edge_kvm_create_guest_memfd_t guest_memfd = {
            .size = EDGE_KVM_PAGE_SIZE,
        };

        request.command = EDGE_KVM_IOCTL_CREATE_GUEST_MEMFD;
        request.argument = (uint64_t)(uintptr_t)&guest_memfd;
        assert(kernel_edge_kvm_ioctl(&request) == 31);
        assert(mock.guest_memfd_size == EDGE_KVM_PAGE_SIZE);
        guest_memfd.size = 0;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        guest_memfd.size = EDGE_KVM_PAGE_SIZE;
        guest_memfd.flags = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        guest_memfd.flags = 0;
    }
    {
        edge_kvm_memory_attributes_t attributes = {
            .size = EDGE_KVM_PAGE_SIZE,
        };

        request.command = EDGE_KVM_IOCTL_SET_MEMORY_ATTRIBUTES;
        request.argument = (uint64_t)(uintptr_t)&attributes;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        attributes.attributes = UINT64_C(1) << 3;
        assert(kernel_edge_kvm_ioctl(&request) ==
               -EDGE_LINUX_EOPNOTSUPP);
        attributes.attributes = 0;
        attributes.size = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
    }
    {
        static const uint32_t unsupported_vm_commands[] = {
            EDGE_KVM_IOCTL_SET_BOOT_CPU_ID,
            EDGE_KVM_IOCTL_ARM_SET_DEVICE_ADDR,
            EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_X86,
            EDGE_KVM_IOCTL_SET_PMU_EVENT_FILTER_ARM64,
            EDGE_KVM_IOCTL_ARM_MTE_COPY_TAGS,
            EDGE_KVM_IOCTL_ARM_SET_COUNTER_OFFSET,
            EDGE_KVM_IOCTL_ARM_GET_REG_WRITABLE_MASKS,
            EDGE_KVM_IOCTL_HYPERV_EVENTFD,
            EDGE_KVM_IOCTL_XEN_HVM_CONFIG,
            EDGE_KVM_IOCTL_XEN_HVM_GET_ATTR,
            EDGE_KVM_IOCTL_XEN_HVM_SET_ATTR,
            EDGE_KVM_IOCTL_XEN_HVM_EVTCHN_SEND,
        };

        for (uint32_t index = 0;
             index < sizeof(unsupported_vm_commands) /
                 sizeof(unsupported_vm_commands[0]); ++index) {
            request.command = unsupported_vm_commands[index];
            request.argument = 0;
            assert(kernel_edge_kvm_ioctl(&request) ==
                   -EDGE_LINUX_EOPNOTSUPP);
        }
    }
    {
        edge_kvm_create_device_t create = {
            .type = EDGE_KVM_DEVICE_ARM_VGIC_V3,
            .descriptor = UINT32_C(0xdeadbeef),
            .flags = EDGE_KVM_CREATE_DEVICE_TEST,
        };

        request.command = EDGE_KVM_IOCTL_CREATE_DEVICE;
        request.argument = (uint64_t)(uintptr_t)&create;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(create.descriptor == UINT32_C(0xdeadbeef));
        assert(mock.next_descriptor == 11);
        assert(mock.device_destroys == 0);
    }
    {
        edge_kvm_create_device_t create = {
            .type = EDGE_KVM_DEVICE_ARM_VGIC_V3,
        };

        request.command = EDGE_KVM_IOCTL_CREATE_DEVICE;
        request.argument = (uint64_t)(uintptr_t)&create;
        g_copy_to_user_fail_once = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EFAULT);
        assert(mock.device_destroys == 1);
        assert(mock.live[11] == 0);
    }
    {
        edge_kvm_vcpu_init_t preferred = {0};

        request.command = EDGE_KVM_IOCTL_ARM_PREFERRED_TARGET;
        request.argument = (uint64_t)(uintptr_t)&preferred;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(preferred.target == 7);
    }
    {
        edge_kvm_create_device_t create = {
            .type = EDGE_KVM_DEVICE_ARM_VGIC_V3,
        };
        uint64_t dist = UINT64_C(0x08000000);
        uint64_t redist = UINT64_C(0x080a0000);
        uint64_t output = 0;
        uint32_t interrupts = 256;
        edge_kvm_device_attr_t attribute = {
            .group = EDGE_KVM_DEVICE_ARM_VGIC_GROUP_ADDRESS,
            .attribute = EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_DIST,
            .address = (uint64_t)(uintptr_t)&dist,
        };

        request.command = EDGE_KVM_IOCTL_CREATE_DEVICE;
        request.argument = (uint64_t)(uintptr_t)&create;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        device_descriptor = (int)create.descriptor;
        assert(device_descriptor == 12);
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EEXIST);

        request.descriptor = device_descriptor;
        request.command = EDGE_KVM_IOCTL_HAS_DEVICE_ATTR;
        request.argument = (uint64_t)(uintptr_t)&attribute;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_SET_DEVICE_ATTR;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.vgic_dist_address == dist);

        attribute.attribute = EDGE_KVM_DEVICE_ARM_VGIC_ADDRESS_REDIST;
        attribute.address = (uint64_t)(uintptr_t)&redist;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.vgic_redist_address == redist);

        attribute.group = EDGE_KVM_DEVICE_ARM_VGIC_GROUP_NR_IRQS;
        attribute.attribute = 0;
        attribute.address = (uint64_t)(uintptr_t)&interrupts;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.vgic_interrupt_count == interrupts);
        output = 0;
        attribute.address = (uint64_t)(uintptr_t)&output;
        request.command = EDGE_KVM_IOCTL_GET_DEVICE_ATTR;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert((uint32_t)output == interrupts);

        attribute.group = EDGE_KVM_DEVICE_ARM_VGIC_GROUP_CONTROL;
        attribute.attribute = EDGE_KVM_DEVICE_ARM_VGIC_CONTROL_INIT;
        attribute.address = 0;
        request.command = EDGE_KVM_IOCTL_SET_DEVICE_ATTR;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.vgic_initialized == 1);
    }
    request.descriptor = vm_descriptor;
    {
        uint64_t identity_map_address = 0xfeffc000u;
        edge_kvm_pit_config_t pit = {0};

        request.command = EDGE_KVM_IOCTL_SET_TSS_ADDR;
        request.argument = 0xfeffd000u;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_SET_IDENTITY_MAP_ADDR;
        request.argument = (uint64_t)(uintptr_t)&identity_map_address;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_CREATE_IRQCHIP;
        request.argument = 0;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_CREATE_PIT2;
        request.argument = (uint64_t)(uintptr_t)&pit;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_CREATE_PIT;
        request.argument = 0;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        {
            edge_kvm_pit_state_t legacy_input = {0};
            edge_kvm_pit_state_t legacy_output = {0};

            legacy_input.channels[1].count = 0x1234u;
            request.command = EDGE_KVM_IOCTL_SET_PIT;
            request.argument = (uint64_t)(uintptr_t)&legacy_input;
            assert(kernel_edge_kvm_ioctl(&request) == 0);
            request.command = EDGE_KVM_IOCTL_GET_PIT;
            request.argument = (uint64_t)(uintptr_t)&legacy_output;
            assert(kernel_edge_kvm_ioctl(&request) == 0);
            assert(legacy_output.channels[1].count == 0x1234u);
        }
    }
    {
        edge_kvm_userspace_memory_region2_t memory2 = {
            .slot = memory.slot,
            .flags = memory.flags,
            .guest_phys_addr = memory.guest_physical_address,
            .memory_size = memory.memory_size,
            .userspace_addr = memory.userspace_address,
        };

        request.command = EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION2;
        request.argument = (uint64_t)(uintptr_t)&memory2;
        request.copy_from_user = copy_from_user;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.memory_updates == 1);
        memory2.pad1 = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        memory2.pad1 = 0;
        memory2.flags |= EDGE_KVM_MEMORY_GUEST_MEMFD;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
        assert(mock.memory_updates == 1);
    }
    {
        uint64_t dirty_bitmap = 0;
        uint64_t clear_bitmap = UINT64_C(0x5);
        edge_kvm_dirty_log_t dirty_log = {
            .slot = 0,
            .dirty_bitmap = (uint64_t)(uintptr_t)&dirty_bitmap,
        };

        request.command = EDGE_KVM_IOCTL_GET_DIRTY_LOG;
        request.argument = (uint64_t)(uintptr_t)&dirty_log;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(dirty_bitmap == UINT64_C(0x21));
        dirty_log.padding = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        {
            edge_kvm_enable_cap_t enable = {
                .capability = EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
                .arguments = {
                    EDGE_KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE,
                },
            };
            edge_kvm_clear_dirty_log_t clear = {
                .slot = 0,
                .num_pages = 4,
                .first_page = 0,
                .dirty_bitmap = (uint64_t)(uintptr_t)&clear_bitmap,
            };

            request.command = EDGE_KVM_IOCTL_ENABLE_CAP;
            request.argument = (uint64_t)(uintptr_t)&enable;
            assert(kernel_edge_kvm_ioctl(&request) == 0);
            enable.arguments[0] = EDGE_KVM_DIRTY_LOG_INITIALLY_SET;
            assert(kernel_edge_kvm_ioctl(&request) ==
                   -EDGE_LINUX_EINVAL);
            request.command = EDGE_KVM_IOCTL_CLEAR_DIRTY_LOG;
            request.argument = (uint64_t)(uintptr_t)&clear;
            assert(kernel_edge_kvm_ioctl(&request) == 0);
            clear.first_page = 1;
            assert(kernel_edge_kvm_ioctl(&request) ==
                   -EDGE_LINUX_EINVAL);
        }
    }
    request.command = EDGE_KVM_IOCTL_CREATE_VCPU;
    request.argument = 4;
    {
        edge_kvm_pre_fault_memory_t pre_fault = {
            .size = EDGE_KVM_PAGE_SIZE,
        };

        request.command = EDGE_KVM_IOCTL_PRE_FAULT_MEMORY;
        request.argument = (uint64_t)(uintptr_t)&pre_fault;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_ENOTTY);
    }
    {
        edge_kvm_translation_t translation = {0};

        request.command = EDGE_KVM_IOCTL_TRANSLATE;
        request.argument = (uint64_t)(uintptr_t)&translation;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_ENOTTY);
    }
    request.command = EDGE_KVM_IOCTL_CREATE_VCPU;
    request.argument = 4;
    vcpu_descriptor = (int)kernel_edge_kvm_ioctl(&request);
    assert(vcpu_descriptor == 13);
    request.descriptor = vcpu_descriptor;
    {
        edge_kvm_pre_fault_memory_t pre_fault = {
            .size = EDGE_KVM_PAGE_SIZE * 2u,
            .padding = {1},
        };

        request.command = EDGE_KVM_IOCTL_PRE_FAULT_MEMORY;
        request.argument = (uint64_t)(uintptr_t)&pre_fault;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(pre_fault.guest_physical_address ==
               EDGE_KVM_PAGE_SIZE * 2u);
        assert(pre_fault.size == 0 && pre_fault.padding[0] == 1);
        assert(mock.pre_fault_pages == 2);
        pre_fault.guest_physical_address = 0;
        pre_fault.size = 0;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        pre_fault.size = EDGE_KVM_PAGE_SIZE;
        pre_fault.flags = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
        pre_fault.flags = 0;
        pre_fault.guest_physical_address = UINT64_C(0x4000);
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_ENOENT);
        assert(pre_fault.guest_physical_address == UINT64_C(0x4000));
        assert(pre_fault.size == EDGE_KVM_PAGE_SIZE);
    }
    {
        edge_kvm_translation_t translation = {
            .linear_address = UINT64_C(0x1234),
            .padding = {0xa5},
        };

        request.command = EDGE_KVM_IOCTL_TRANSLATE;
        request.argument = (uint64_t)(uintptr_t)&translation;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(translation.physical_address == UINT64_C(0x2234));
        assert(translation.valid == 1 && translation.writeable == 1);
        assert(translation.usermode == 0 && translation.padding[0] == 0xa5);
        request.argument = 0;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EFAULT);
    }
    request.command = EDGE_KVM_IOCTL_RUN;
    request.argument = 0;
    assert(kernel_edge_kvm_ioctl(&request) == 0);
    assert(mock.vcpu_runs == 1);
    assert(((edge_kvm_run_t *)mock.run_pages[0])->exit_reason ==
           EDGE_KVM_EXIT_HLT);
    {
        edge_kvm_guest_debug_x86_t debug = {
            .control = EDGE_KVM_GUESTDBG_ENABLE |
                       EDGE_KVM_GUESTDBG_SINGLESTEP,
        };

        request.command = EDGE_KVM_IOCTL_SET_GUEST_DEBUG_X86;
        request.argument = (uint64_t)(uintptr_t)&debug;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.guest_debug.control == debug.control);
        debug.padding = 1;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
    }
    {
        edge_kvm_vcpu_init_t init = {.target = 7};
        uint64_t input = UINT64_C(0x123456789abcdef0);
        uint64_t output = 0;
        edge_kvm_one_reg_t one = {
            .id = EDGE_KVM_REG_ARM64_X(0),
            .address = (uint64_t)(uintptr_t)&input,
        };
        struct {
            edge_kvm_reg_list_t header;
            uint64_t ids[2];
        } list = {0};

        request.command = EDGE_KVM_IOCTL_ARM_VCPU_INIT;
        request.argument = (uint64_t)(uintptr_t)&init;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.vcpu_init.target == 7);
        request.command = EDGE_KVM_IOCTL_SET_ONE_REG;
        request.argument = (uint64_t)(uintptr_t)&one;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.arm_x0 == input);
        one.address = (uint64_t)(uintptr_t)&output;
        request.command = EDGE_KVM_IOCTL_GET_ONE_REG;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(output == input);
        request.command = EDGE_KVM_IOCTL_GET_REG_LIST;
        request.argument = (uint64_t)(uintptr_t)&list;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_E2BIG);
        assert(list.header.count == 2);
        list.header.count = 2;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(list.ids[0] == EDGE_KVM_REG_ARM64_X(0));
        assert(list.ids[1] == EDGE_KVM_REG_ARM64_PC);
    }
    {
        edge_kvm_regs_t input = {.rax = 0x1234, .rip = 0x8000};
        edge_kvm_regs_t output = {0};
        request.command = EDGE_KVM_IOCTL_SET_REGS;
        request.argument = (uint64_t)(uintptr_t)&input;
        request.copy_from_user = copy_from_user;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_REGS;
        request.argument = (uint64_t)(uintptr_t)&output;
        request.copy_to_user = copy_to_user;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(output.rax == input.rax && output.rip == input.rip);
    }
    {
        edge_kvm_sregs_t input = {.cr0 = 0x31, .cr3 = 0x2000};
        edge_kvm_sregs_t output = {0};
        request.command = EDGE_KVM_IOCTL_SET_SREGS;
        request.argument = (uint64_t)(uintptr_t)&input;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_SREGS;
        request.argument = (uint64_t)(uintptr_t)&output;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(output.cr0 == input.cr0 && output.cr3 == input.cr3);
    }
    {
        edge_kvm_fpu_t input = {
            .fcw = 0x027f,
            .ftwx = 0xff,
            .last_opcode = 0x0321,
            .last_ip = 0x1020304050607080ull,
            .last_dp = 0x8070605040302010ull,
            .mxcsr = 0x1f80,
        };
        edge_kvm_fpu_t output = {0};
        input.fpr[7][15] = 0xd4;
        input.xmm[15][0] = 0x4d;
        request.command = EDGE_KVM_IOCTL_SET_FPU;
        request.argument = (uint64_t)(uintptr_t)&input;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_FPU;
        request.argument = (uint64_t)(uintptr_t)&output;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_xsave_t input = {0};
        edge_kvm_xsave_t output = {0};
        input.region[0] = 0x7f;
        input.region[1] = 0x02;
        input.region[24] = 0x40;
        input.region[25] = 0x1f;
        input.region[512] = 3;
        request.command = EDGE_KVM_IOCTL_SET_XSAVE;
        request.argument = (uint64_t)(uintptr_t)&input;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_XSAVE2;
        request.argument = (uint64_t)(uintptr_t)&output;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_sregs2_t input = {
            .cr0 = UINT64_C(0x80000001),
            .cr4 = UINT64_C(0x20),
            .flags = EDGE_KVM_SREGS2_PDPTRS_VALID,
            .pdptrs = {0x67, 0x1067, 0x2067, 0x3067},
        };
        edge_kvm_sregs2_t output = {0};
        request.command = EDGE_KVM_IOCTL_SET_SREGS2;
        request.argument = (uint64_t)(uintptr_t)&input;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_SREGS2;
        request.argument = (uint64_t)(uintptr_t)&output;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_lapic_state_t input = {0};
        edge_kvm_lapic_state_t output = {0};
        input.registers[0x80] = 0x50;
        request.command = EDGE_KVM_IOCTL_SET_LAPIC;
        request.argument = (uint64_t)(uintptr_t)&input;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_LAPIC;
        request.argument = (uint64_t)(uintptr_t)&output;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        struct {
            struct { uint32_t nmsrs; uint32_t padding; } header;
            edge_kvm_msr_entry_t entries[2];
        } input = {
            .header = {.nmsrs = 2},
            .entries = {
                {.index = 0xc0000081u,
                 .data = 0x0013000800000000ull},
                {.index = 0x00000277u,
                 .data = 0x0007040600070406ull},
            },
        }, output = {
            .header = {.nmsrs = 2},
            .entries = {
                {.index = 0xc0000081u},
                {.index = 0x00000277u},
            },
        };

        request.command = EDGE_KVM_IOCTL_SET_MSRS;
        request.argument = (uint64_t)(uintptr_t)&input;
        assert(kernel_edge_kvm_ioctl(&request) == 2);
        request.command = EDGE_KVM_IOCTL_GET_MSRS;
        request.argument = (uint64_t)(uintptr_t)&output;
        assert(kernel_edge_kvm_ioctl(&request) == 2);
        assert(output.entries[0].data == input.entries[0].data);
        assert(output.entries[1].data == input.entries[1].data);
    }
    {
        edge_kvm_mp_state_t input_state = {
            .mp_state = EDGE_KVM_MP_STATE_HALTED,
        };
        edge_kvm_mp_state_t output_state = {0};
        edge_kvm_vcpu_events_t input_events = {
            .interrupt = {.injected = 1, .number = 32},
            .sipi_vector = 0x30,
            .flags = EDGE_KVM_VCPUEVENT_VALID_SIPI_VECTOR,
        };
        edge_kvm_vcpu_events_t output_events = {0};

        request.command = EDGE_KVM_IOCTL_SET_MP_STATE;
        request.argument = (uint64_t)(uintptr_t)&input_state;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_MP_STATE;
        request.argument = (uint64_t)(uintptr_t)&output_state;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(output_state.mp_state == input_state.mp_state);
        request.command = EDGE_KVM_IOCTL_SET_VCPU_EVENTS;
        request.argument = (uint64_t)(uintptr_t)&input_events;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_VCPU_EVENTS;
        request.argument = (uint64_t)(uintptr_t)&output_events;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(memcmp(&output_events, &input_events,
                      sizeof(input_events)) == 0);
    }
    request.command = EDGE_KVM_IOCTL_NMI;
    request.argument = 0;
    assert(kernel_edge_kvm_ioctl(&request) == 0);
    assert(mock.events.nmi.pending == 1);
    assert((mock.events.flags & EDGE_KVM_VCPUEVENT_VALID_NMI_PENDING) != 0);
    {
        edge_kvm_interrupt_t interrupt = {.irq = 48};
        request.command = EDGE_KVM_IOCTL_INTERRUPT;
        request.argument = (uint64_t)(uintptr_t)&interrupt;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.events.interrupt.injected == 1);
        assert(mock.events.interrupt.number == 48);
        interrupt.irq = 8;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EINVAL);
    }
    request.command = EDGE_KVM_IOCTL_SMI;
    request.argument = 0;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
    request.command = EDGE_KVM_IOCTL_SET_GUEST_DEBUG_ARM64;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
    request.command = EDGE_KVM_IOCTL_ENABLE_CAP;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
        request.command = EDGE_KVM_IOCTL_DIRTY_TLB;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
        request.command = EDGE_KVM_IOCTL_XEN_VCPU_GET_ATTR;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
        request.command = EDGE_KVM_IOCTL_XEN_VCPU_SET_ATTR;
        assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_EOPNOTSUPP);
    request.command = EDGE_KVM_IOCTL_GET_TSC_KHZ;
    request.argument = 0;
    assert(kernel_edge_kvm_ioctl(&request) == 2900000);
    request.command = EDGE_KVM_IOCTL_SET_TSC_KHZ;
    request.argument = 3000000;
    assert(kernel_edge_kvm_ioctl(&request) == 0);
    assert(mock.tsc_frequency_khz == 3000000);
    {
        uint64_t capability = UINT64_C(0x0100010a);
        request.command = EDGE_KVM_IOCTL_X86_SETUP_MCE;
        request.argument = (uint64_t)(uintptr_t)&capability;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.mce_capability == capability);
        {
            edge_kvm_x86_mce_t machine_check = {
                .status = EDGE_KVM_X86_MCE_STATUS_VALID,
                .address = UINT64_C(0xfeed0000),
                .bank = 3,
            };
            request.command = EDGE_KVM_IOCTL_X86_SET_MCE;
            request.argument = (uint64_t)(uintptr_t)&machine_check;
            assert(kernel_edge_kvm_ioctl(&request) == 0);
            assert(mock.machine_check.address == machine_check.address);
            machine_check.status = 0;
            assert(kernel_edge_kvm_ioctl(&request) ==
                   -EDGE_LINUX_EINVAL);
        }
    }
    {
        struct {
            struct { uint32_t nent; uint32_t padding; } header;
            edge_kvm_cpuid_entry2_t entries[1];
        } cpuid = {
            .header = {.nent = 1},
            .entries = {{.function = 1, .eax = 0x5678}},
        };
        request.command = EDGE_KVM_IOCTL_SET_CPUID2;
        request.argument = (uint64_t)(uintptr_t)&cpuid;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(mock.cpuid_count == 1 && mock.cpuid_entries[0].eax == 0x5678);
        cpuid.header.nent = 1;
        cpuid.entries[0].eax = 0;
        request.command = EDGE_KVM_IOCTL_GET_CPUID2;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(cpuid.header.nent == 1 && cpuid.entries[0].eax == 0x5678);
    }
    {
        struct {
            uint32_t nent;
            uint32_t padding;
            edge_kvm_cpuid_entry_t entries[1];
        } cpuid = {
            .nent = 1,
            .entries = {{.function = 1, .eax = 0x9abc}},
        };
        struct {
            uint32_t nent;
            uint32_t padding;
            edge_kvm_cpuid_entry2_t entries[1];
        } cpuid2 = {.nent = 1};

        request.command = EDGE_KVM_IOCTL_SET_CPUID;
        request.argument = (uint64_t)(uintptr_t)&cpuid;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        request.command = EDGE_KVM_IOCTL_GET_CPUID2;
        request.argument = (uint64_t)(uintptr_t)&cpuid2;
        assert(kernel_edge_kvm_ioctl(&request) == 0);
        assert(cpuid2.entries[0].index == 0);
        assert(cpuid2.entries[0].eax == 0x9abc);
    }

    {
        uint8_t blob[EDGE_KVM_STATS_NAME_SIZE + 256u]
            __attribute__((aligned(8)));
        edge_kvm_stats_header_t *header =
            (edge_kvm_stats_header_t *)(void *)blob;
        uint64_t *values;
        int vm_stats_descriptor;
        int vcpu_stats_descriptor;
        int64_t received;

        request.descriptor = vm_descriptor;
        request.command = EDGE_KVM_IOCTL_GET_STATS_FD;
        request.argument = 0;
        vm_stats_descriptor = (int)kernel_edge_kvm_ioctl(&request);
        assert(vm_stats_descriptor == 14);
        received = kernel_edge_kvm_stats_read(
            KERNEL_EDGE_KVM_FILE_VM,
            mock.files[vm_descriptor].handle, 0, blob, sizeof(blob));
        assert(received > (int64_t)sizeof(*header));
        assert(header->name_size == EDGE_KVM_STATS_NAME_SIZE);
        assert(header->descriptor_count == 3);
        assert(header->id_offset == sizeof(*header));
        assert(memcmp(blob + header->id_offset, "edgeos-kvm-vm-", 14) == 0);
        values = (uint64_t *)(void *)(blob + header->data_offset);
        assert(values[0] == 1);
        assert(values[1] == 1);
        assert(values[2] == 1);

        request.descriptor = vcpu_descriptor;
        vcpu_stats_descriptor = (int)kernel_edge_kvm_ioctl(&request);
        assert(vcpu_stats_descriptor == 15);
        received = kernel_edge_kvm_stats_read(
            KERNEL_EDGE_KVM_FILE_VCPU,
            mock.files[vcpu_descriptor].handle, 0, blob, sizeof(blob));
        assert(received > (int64_t)sizeof(*header));
        assert(header->descriptor_count == 2);
        assert(memcmp(blob + header->id_offset, "edgeos-kvm-vcpu-", 16) == 0);
        values = (uint64_t *)(void *)(blob + header->data_offset);
        assert(values[0] == 4);
        assert(values[1] == 1);

        assert(descriptor_close(&mock, vm_stats_descriptor) == 0);
        assert(descriptor_close(&mock, vcpu_stats_descriptor) == 0);
    }

    assert(kernel_edge_kvm_descriptor_release(
               KERNEL_EDGE_KVM_FILE_VM,
               mock.files[vm_descriptor].handle) == 0);
    assert(mock.vm_destroys == 0);
    assert(kernel_edge_kvm_descriptor_release(
               KERNEL_EDGE_KVM_FILE_DEVICE,
               mock.files[device_descriptor].handle) == 0);
    assert(mock.device_destroys == 2);
    assert(mock.vm_destroys == 0);
    assert(kernel_edge_kvm_descriptor_release(
               KERNEL_EDGE_KVM_FILE_VCPU,
               mock.files[vcpu_descriptor].handle) == 0);
    assert(mock.vcpu_destroys == 1);
    assert(mock.vm_destroys == 1);

    request.descriptor = 31;
    assert(kernel_edge_kvm_ioctl(&request) == -EDGE_LINUX_ENOTTY);
    puts("edge_kvm_runtime_unit: PASS");
    return 0;
}
