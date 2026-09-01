/* SPDX-License-Identifier: MPL-2.0 */
/* Object lifetime translation shared by the KVM facade and vmm backend. */

#include <stdint.h>

#include "kernel/edge_kvm_object.h"
#include "kernel/linux_errno.h"
#include "string.h"

static uint32_t edge_kvm_next_generation(edge_kvm_object_table_t *table) {
    ++table->next_generation;
    if (!table->next_generation) ++table->next_generation;
    return table->next_generation;
}

static edge_kvm_vm_object_t *edge_kvm_find_vm(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle) {
    edge_kvm_vm_object_t *vm;

    if (!table || handle.slot >= EDGE_KVM_OBJECT_MAX_VMS ||
        !handle.generation)
        return 0;
    vm = &table->vms[handle.slot];
    if (!vm->active || vm->generation != handle.generation) return 0;
    return vm;
}

static const edge_kvm_vm_object_t *edge_kvm_find_vm_const(
        const edge_kvm_object_table_t *table, edge_kvm_handle_t handle) {
    if (!table || handle.slot >= EDGE_KVM_OBJECT_MAX_VMS ||
        !handle.generation)
        return 0;
    if (!table->vms[handle.slot].active ||
        table->vms[handle.slot].generation != handle.generation)
        return 0;
    return &table->vms[handle.slot];
}

static edge_kvm_vcpu_object_t *edge_kvm_find_vcpu(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle) {
    edge_kvm_vcpu_object_t *vcpu;

    if (!table || handle.slot >= EDGE_KVM_OBJECT_MAX_VCPUS ||
        !handle.generation)
        return 0;
    vcpu = &table->vcpus[handle.slot];
    if (!vcpu->active || vcpu->generation != handle.generation) return 0;
    return vcpu;
}

static const edge_kvm_vcpu_object_t *edge_kvm_find_vcpu_const(
        const edge_kvm_object_table_t *table, edge_kvm_handle_t handle) {
    if (!table || handle.slot >= EDGE_KVM_OBJECT_MAX_VCPUS ||
        !handle.generation)
        return 0;
    if (!table->vcpus[handle.slot].active ||
        table->vcpus[handle.slot].generation != handle.generation)
        return 0;
    return &table->vcpus[handle.slot];
}

static edge_kvm_device_object_t *edge_kvm_find_device(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle) {
    edge_kvm_device_object_t *device;

    if (!table || handle.slot >= EDGE_KVM_OBJECT_MAX_DEVICES ||
        !handle.generation)
        return 0;
    device = &table->devices[handle.slot];
    if (!device->active || device->generation != handle.generation)
        return 0;
    return device;
}

static void edge_kvm_destroy_vm(edge_kvm_object_table_t *table,
                                edge_kvm_vm_object_t *vm) {
    uint64_t backend_cookie = vm->backend_cookie;

    memset(vm, 0, sizeof(*vm));
    --table->active_vm_count;
    table->backend.vm_destroy(table->backend.context, backend_cookie);
}

int edge_kvm_object_table_init(edge_kvm_object_table_t *table,
                               const edge_kvm_backend_ops_t *backend) {
    if (!table || !backend || !backend->vm_create || !backend->vm_destroy ||
        !backend->vm_set_tss_address ||
        !backend->vm_set_identity_map_address ||
        !backend->vm_create_irqchip || !backend->vm_set_gsi_routing ||
        !backend->vm_set_irq_line || !backend->vm_get_irqchip ||
        !backend->vm_set_irqchip || !backend->vm_create_pit ||
        !backend->vm_get_pit || !backend->vm_set_pit ||
        !backend->get_supported_cpuid ||
        !backend->get_msr_index_list ||
        !backend->vcpu_create || !backend->vcpu_destroy ||
        !backend->vcpu_run || !backend->vcpu_mmap_page ||
        !backend->vcpu_get_regs || !backend->vcpu_set_regs ||
        !backend->vcpu_get_sregs || !backend->vcpu_set_sregs ||
        !backend->vcpu_get_sregs2 || !backend->vcpu_set_sregs2 ||
        !backend->vcpu_get_fpu || !backend->vcpu_set_fpu ||
        !backend->vcpu_get_lapic || !backend->vcpu_set_lapic ||
        !backend->vcpu_get_debugregs || !backend->vcpu_set_debugregs ||
        !backend->vcpu_set_guest_debug ||
        !backend->vcpu_get_xcrs || !backend->vcpu_set_xcrs ||
        !backend->vcpu_get_xsave || !backend->vcpu_set_xsave ||
        !backend->vcpu_get_msrs || !backend->vcpu_set_msrs ||
        !backend->vcpu_get_mp_state || !backend->vcpu_set_mp_state ||
        !backend->vcpu_get_events || !backend->vcpu_set_events ||
        !backend->vcpu_get_tsc_khz || !backend->vcpu_set_tsc_khz ||
        !backend->vcpu_setup_mce || !backend->vcpu_set_mce ||
        !backend->vcpu_set_cpuid || !backend->vcpu_get_cpuid ||
        !backend->memory_region_set || !backend->memory_dirty_log_get ||
        !backend->memory_dirty_log_clear)
        return -EDGE_LINUX_EINVAL;
    memset(table, 0, sizeof(*table));
    table->backend = *backend;
    return 0;
}

void edge_kvm_object_table_reset(edge_kvm_object_table_t *table) {
    if (!table) return;
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_DEVICES; ++index) {
        edge_kvm_device_object_t *device = &table->devices[index];
        if (!device->active) continue;
        if (table->backend.device_destroy)
            table->backend.device_destroy(table->backend.context,
                                           device->backend_cookie);
        memset(device, 0, sizeof(*device));
    }
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_VCPUS; ++index) {
        edge_kvm_vcpu_object_t *vcpu = &table->vcpus[index];
        if (!vcpu->active) continue;
        table->backend.vcpu_destroy(table->backend.context,
                                    vcpu->backend_cookie);
        memset(vcpu, 0, sizeof(*vcpu));
    }
    for (uint32_t index = 0; index < EDGE_KVM_OBJECT_MAX_VMS; ++index) {
        edge_kvm_vm_object_t *vm = &table->vms[index];
        if (!vm->active) continue;
        table->backend.vm_destroy(table->backend.context,
                                  vm->backend_cookie);
        memset(vm, 0, sizeof(*vm));
    }
    table->active_vm_count = 0;
    table->active_vcpu_count = 0;
    table->active_device_count = 0;
}

int edge_kvm_get_mce_cap_supported(edge_kvm_object_table_t *table,
                                   uint64_t *capability) {
    if (!table || !capability || !table->backend.get_mce_cap_supported)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.get_mce_cap_supported(
        table->backend.context, capability);
}

int edge_kvm_vm_create(edge_kvm_object_table_t *table, uint32_t machine_type,
                       edge_kvm_handle_t *handle) {
    edge_kvm_vm_object_t *vm = 0;
    uint32_t slot = 0;
    uint64_t backend_cookie = 0;
    int status;

    if (!table || !handle) return -EDGE_LINUX_EINVAL;
    for (slot = 0; slot < EDGE_KVM_OBJECT_MAX_VMS; ++slot) {
        if (!table->vms[slot].active) {
            vm = &table->vms[slot];
            break;
        }
    }
    if (!vm) return -EDGE_LINUX_EMFILE;
    status = table->backend.vm_create(table->backend.context, machine_type,
                                      &backend_cookie);
    if (status < 0) return status;

    memset(vm, 0, sizeof(*vm));
    vm->active = 1u;
    vm->generation = edge_kvm_next_generation(table);
    vm->machine_type = machine_type;
    vm->descriptor_references = 1u;
    vm->backend_cookie = backend_cookie;
    ++table->active_vm_count;
    handle->slot = slot;
    handle->generation = vm->generation;
    return 0;
}

int edge_kvm_vm_retain(edge_kvm_object_table_t *table,
                       edge_kvm_handle_t handle) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (vm->descriptor_references == UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    ++vm->descriptor_references;
    return 0;
}

int edge_kvm_vm_release(edge_kvm_object_table_t *table,
                        edge_kvm_handle_t handle) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    --vm->descriptor_references;
    if (!vm->descriptor_references && !vm->vcpu_count && !vm->device_count)
        edge_kvm_destroy_vm(table, vm);
    return 0;
}

int edge_kvm_vm_snapshot(const edge_kvm_object_table_t *table,
                         edge_kvm_handle_t handle,
                         edge_kvm_vm_snapshot_t *snapshot) {
    const edge_kvm_vm_object_t *vm = edge_kvm_find_vm_const(table, handle);
    uint32_t memory_slot_count = 0;

    if (!vm || !snapshot) return -EDGE_LINUX_EBADF;
    for (uint32_t slot = 0; slot < EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS; ++slot)
        memory_slot_count += vm->memory_slots[slot].active != 0;
    snapshot->machine_type = vm->machine_type;
    snapshot->descriptor_references = vm->descriptor_references;
    snapshot->vcpu_count = vm->vcpu_count;
    snapshot->device_count = vm->device_count;
    snapshot->memory_slot_count = memory_slot_count;
    snapshot->backend_cookie = vm->backend_cookie;
    return 0;
}

static int edge_kvm_validate_memory_region(
        const edge_kvm_vm_object_t *vm,
        const edge_kvm_memory_region_t *region) {
    uint64_t end;
    uint64_t userspace_end;

    if (!region || region->slot >= EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS ||
        (region->flags & ~EDGE_KVM_MEMORY_VALID_FLAGS))
        return -EDGE_LINUX_EINVAL;
    if (!region->memory_size) return 0;
    if ((region->guest_physical_address & (EDGE_KVM_PAGE_SIZE - 1u)) ||
        (region->memory_size & (EDGE_KVM_PAGE_SIZE - 1u)) ||
        (region->userspace_address & (EDGE_KVM_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    end = region->guest_physical_address + region->memory_size;
    userspace_end = region->userspace_address + region->memory_size;
    if (end < region->guest_physical_address ||
        userspace_end < region->userspace_address)
        return -EDGE_LINUX_EOVERFLOW;

    for (uint32_t slot = 0; slot < EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS; ++slot) {
        const edge_kvm_memory_slot_t *existing = &vm->memory_slots[slot];
        uint64_t existing_end;

        if (slot == region->slot || !existing->active) continue;
        existing_end = existing->region.guest_physical_address +
                       existing->region.memory_size;
        if (end > existing->region.guest_physical_address &&
            region->guest_physical_address < existing_end)
            return -EDGE_LINUX_EEXIST;
    }
    return 0;
}

int edge_kvm_vm_set_memory_region(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle,
                                  const edge_kvm_memory_region_t *region) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);
    edge_kvm_memory_slot_t *slot;
    int status;

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    status = edge_kvm_validate_memory_region(vm, region);
    if (status < 0) return status;
    status = table->backend.memory_region_set(table->backend.context,
                                              vm->backend_cookie, region);
    if (status < 0) return status;

    slot = &vm->memory_slots[region->slot];
    if (!region->memory_size) {
        memset(slot, 0, sizeof(*slot));
        return 0;
    }
    slot->active = 1u;
    slot->region = *region;
    return 0;
}

int edge_kvm_vm_coalesced_mmio(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
        const edge_kvm_coalesced_mmio_zone_t *zone, uint8_t unregister) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!zone || !zone->size || zone->pio ||
        zone->address > UINT64_MAX - zone->size)
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.vm_coalesced_mmio)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.vm_coalesced_mmio(
        table->backend.context, vm->backend_cookie, zone,
        unregister ? 1u : 0u);
}

int edge_kvm_vm_dirty_log_page_count(edge_kvm_object_table_t *table,
                                     edge_kvm_handle_t handle,
                                     uint32_t slot_index,
                                     uint32_t *page_count) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);
    const edge_kvm_memory_slot_t *slot;
    uint64_t pages;

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!page_count || slot_index >= EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS)
        return -EDGE_LINUX_EINVAL;
    slot = &vm->memory_slots[slot_index];
    if (!slot->active ||
        (slot->region.flags & EDGE_KVM_MEMORY_LOG_DIRTY_PAGES) == 0)
        return -EDGE_LINUX_ENOENT;
    pages = slot->region.memory_size / EDGE_KVM_PAGE_SIZE;
    if (pages > UINT32_MAX) return -EDGE_LINUX_E2BIG;
    *page_count = (uint32_t)pages;
    return 0;
}

int edge_kvm_vm_get_dirty_log(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle, uint32_t slot_index,
                              uint32_t first_page, uint32_t page_count,
                              uint64_t *bitmap, uint32_t bitmap_words) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);
    uint32_t total_pages;
    uint32_t required_words;
    int status;

    status = edge_kvm_vm_dirty_log_page_count(
        table, handle, slot_index, &total_pages);
    if (status < 0) return status;
    required_words = (page_count + 63u) / 64u;
    if (!bitmap || page_count == 0 || bitmap_words < required_words ||
        first_page > total_pages || page_count > total_pages - first_page)
        return -EDGE_LINUX_EINVAL;
    return table->backend.memory_dirty_log_get(
        table->backend.context, vm->backend_cookie, slot_index,
        first_page, page_count, bitmap, bitmap_words,
        vm->manual_dirty_log ? 0u : 1u);
}

int edge_kvm_vm_enable_cap(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_enable_cap_t *capability) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!capability || capability->flags != 0 ||
        capability->capability != EDGE_KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 1; index < 4u; ++index) {
        if (capability->arguments[index] != 0)
            return -EDGE_LINUX_EINVAL;
    }
    for (uint32_t index = 0; index < sizeof(capability->padding); ++index) {
        if (capability->padding[index] != 0)
            return -EDGE_LINUX_EINVAL;
    }
    if ((capability->arguments[0] &
         ~EDGE_KVM_DIRTY_LOG_MANUAL_SUPPORTED_FLAGS) != 0)
        return -EDGE_LINUX_EINVAL;
    vm->manual_dirty_log =
        (capability->arguments[0] &
         EDGE_KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE) != 0;
    return 0;
}

int edge_kvm_vm_clear_dirty_log(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                uint32_t slot_index,
                                uint32_t first_page,
                                uint32_t page_count,
                                const uint64_t *bitmap,
                                uint32_t bitmap_words) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);
    uint32_t total_pages;
    uint32_t required_words;
    int status;

    status = edge_kvm_vm_dirty_log_page_count(
        table, handle, slot_index, &total_pages);
    if (status < 0) return status;
    required_words = (page_count + 63u) / 64u;
    if (!bitmap || page_count == 0 || bitmap_words < required_words ||
        (first_page & 63u) != 0 || first_page > total_pages ||
        page_count > total_pages - first_page ||
        ((page_count & 63u) != 0 &&
         first_page + page_count != total_pages))
        return -EDGE_LINUX_EINVAL;
    return table->backend.memory_dirty_log_clear(
        table->backend.context, vm->backend_cookie, slot_index,
        first_page, page_count, bitmap, bitmap_words);
}

int edge_kvm_vm_get_preferred_target(edge_kvm_object_table_t *table,
                                     edge_kvm_handle_t handle,
                                     edge_kvm_vcpu_init_t *init) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!init) return -EDGE_LINUX_EINVAL;
    if (!table->backend.vm_get_preferred_target)
        return -EDGE_LINUX_ENOTTY;
    return table->backend.vm_get_preferred_target(
        table->backend.context, vm->backend_cookie, init);
}

int edge_kvm_vm_set_tss_address(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                uint64_t address) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    return table->backend.vm_set_tss_address(
        table->backend.context, vm->backend_cookie, address);
}

int edge_kvm_vm_set_identity_map_address(edge_kvm_object_table_t *table,
                                         edge_kvm_handle_t handle,
                                         uint64_t address) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    return table->backend.vm_set_identity_map_address(
        table->backend.context, vm->backend_cookie, address);
}

int edge_kvm_vm_create_irqchip(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    return table->backend.vm_create_irqchip(
        table->backend.context, vm->backend_cookie);
}

int edge_kvm_vm_set_gsi_routing(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
        const edge_kvm_irq_routing_entry_t *entries, uint32_t count) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (count > EDGE_KVM_MAX_IRQ_ROUTES || (count != 0 && !entries))
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        const edge_kvm_irq_routing_entry_t *entry = &entries[index];

        if (entry->gsi >= EDGE_KVM_MAX_IRQ_ROUTES || entry->padding != 0)
            return -EDGE_LINUX_EINVAL;
        if (entry->type == EDGE_KVM_IRQ_ROUTING_IRQCHIP) {
            if (entry->flags != 0 ||
                entry->u.irqchip.irqchip > EDGE_KVM_IRQCHIP_IOAPIC ||
                (entry->u.irqchip.irqchip != EDGE_KVM_IRQCHIP_IOAPIC &&
                 entry->u.irqchip.pin >= 8) ||
                (entry->u.irqchip.irqchip == EDGE_KVM_IRQCHIP_IOAPIC &&
                 entry->u.irqchip.pin >= 24))
                return -EDGE_LINUX_EINVAL;
        } else if (entry->type == EDGE_KVM_IRQ_ROUTING_MSI) {
            if ((entry->flags & ~EDGE_KVM_MSI_VALID_DEVID) != 0)
                return -EDGE_LINUX_EINVAL;
        } else {
            return -EDGE_LINUX_EINVAL;
        }
    }
    return table->backend.vm_set_gsi_routing(
        table->backend.context, vm->backend_cookie, entries, count);
}

int edge_kvm_vm_set_irq_line(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             edge_kvm_irq_level_t *level) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!level || level->level > 1)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_set_irq_line(
        table->backend.context, vm->backend_cookie, level);
}

int edge_kvm_vm_signal_msi(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_msi_t *message) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!message || !table->backend.vm_signal_msi ||
        (message->flags & ~EDGE_KVM_MSI_VALID_DEVID) != 0 ||
        message->padding[0] != 0 || message->padding[1] != 0 ||
        message->padding[2] != 0)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_signal_msi(
        table->backend.context, vm->backend_cookie, message);
}

int edge_kvm_vm_get_irqchip(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_irqchip_t *state) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || state->chip_id > EDGE_KVM_IRQCHIP_IOAPIC)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_get_irqchip(
        table->backend.context, vm->backend_cookie, state);
}

int edge_kvm_vm_set_irqchip(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_irqchip_t *state) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || state->chip_id > EDGE_KVM_IRQCHIP_IOAPIC)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_set_irqchip(
        table->backend.context, vm->backend_cookie, state);
}

int edge_kvm_vm_get_pit(edge_kvm_object_table_t *table,
                        edge_kvm_handle_t handle,
                        edge_kvm_pit_state2_t *state) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vm_get_pit(
        table->backend.context, vm->backend_cookie, state);
}

int edge_kvm_vm_set_pit(edge_kvm_object_table_t *table,
                        edge_kvm_handle_t handle,
                        const edge_kvm_pit_state2_t *state) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vm_set_pit(
        table->backend.context, vm->backend_cookie, state);
}

int edge_kvm_vm_get_clock(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          edge_kvm_clock_data_t *state) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || !table->backend.vm_get_clock)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_get_clock(table->backend.context,
                                       vm->backend_cookie, state);
}

int edge_kvm_vm_set_clock(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_clock_data_t *state) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || !table->backend.vm_set_clock)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_set_clock(table->backend.context,
                                       vm->backend_cookie, state);
}

int edge_kvm_vm_ioeventfd(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
        const edge_kvm_ioeventfd_registration_t *event) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!event || !table->backend.vm_ioeventfd)
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((event->flags & ~EDGE_KVM_IOEVENTFD_VALID_FLAGS) != 0 ||
        (event->length != 0 && event->length != 1 && event->length != 2 &&
         event->length != 4 && event->length != 8) ||
        ((event->flags & EDGE_KVM_IOEVENTFD_FLAG_PIO) != 0 &&
         (event->address > UINT16_MAX || event->length == 8)) ||
        event->address + event->length < event->address)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_ioeventfd(
        table->backend.context, vm->backend_cookie, event);
}

int edge_kvm_vm_irqfd(edge_kvm_object_table_t *table,
        edge_kvm_handle_t handle,
        const edge_kvm_irqfd_registration_t *irq) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!irq || !table->backend.vm_irqfd)
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((irq->flags & ~EDGE_KVM_IRQFD_VALID_FLAGS) != 0 ||
        irq->gsi >= EDGE_KVM_MAX_IRQ_ROUTES || irq->event_id < 0 ||
        ((irq->flags & EDGE_KVM_IRQFD_FLAG_RESAMPLE) != 0 &&
         irq->resample_event_id < 0))
        return -EDGE_LINUX_EINVAL;
    return table->backend.vm_irqfd(
        table->backend.context, vm->backend_cookie, irq);
}

int edge_kvm_vm_create_pit(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_pit_config_t *config) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, handle);

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!config) return -EDGE_LINUX_EINVAL;
    return table->backend.vm_create_pit(
        table->backend.context, vm->backend_cookie, config);
}

int edge_kvm_vcpu_create(edge_kvm_object_table_t *table,
                         edge_kvm_handle_t vm_handle, uint32_t vcpu_id,
                         edge_kvm_handle_t *vcpu_handle) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, vm_handle);
    edge_kvm_vcpu_object_t *vcpu = 0;
    uint32_t slot = 0;
    uint64_t backend_cookie = 0;
    int status;

    if (!vcpu_handle) return -EDGE_LINUX_EINVAL;
    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    for (slot = 0; slot < EDGE_KVM_OBJECT_MAX_VCPUS; ++slot) {
        edge_kvm_vcpu_object_t *candidate = &table->vcpus[slot];
        if (candidate->active && candidate->vm.slot == vm_handle.slot &&
            candidate->vm.generation == vm_handle.generation &&
            candidate->vcpu_id == vcpu_id)
            return -EDGE_LINUX_EEXIST;
        if (!candidate->active && !vcpu) vcpu = candidate;
    }
    if (!vcpu) return -EDGE_LINUX_EMFILE;
    status = table->backend.vcpu_create(table->backend.context,
                                        vm->backend_cookie, vcpu_id,
                                        &backend_cookie);
    if (status < 0) return status;

    memset(vcpu, 0, sizeof(*vcpu));
    vcpu->active = 1u;
    vcpu->generation = edge_kvm_next_generation(table);
    vcpu->vcpu_id = vcpu_id;
    vcpu->descriptor_references = 1u;
    vcpu->vm = vm_handle;
    vcpu->backend_cookie = backend_cookie;
    ++vm->vcpu_count;
    ++table->active_vcpu_count;
    vcpu_handle->slot = (uint32_t)(vcpu - table->vcpus);
    vcpu_handle->generation = vcpu->generation;
    return 0;
}

int edge_kvm_vcpu_retain(edge_kvm_object_table_t *table,
                         edge_kvm_handle_t handle) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (vcpu->descriptor_references == UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    ++vcpu->descriptor_references;
    return 0;
}

int edge_kvm_vcpu_release(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);
    edge_kvm_vm_object_t *vm;
    uint64_t backend_cookie;

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    --vcpu->descriptor_references;
    if (vcpu->descriptor_references) return 0;

    vm = edge_kvm_find_vm(table, vcpu->vm);
    backend_cookie = vcpu->backend_cookie;
    memset(vcpu, 0, sizeof(*vcpu));
    --table->active_vcpu_count;
    table->backend.vcpu_destroy(table->backend.context, backend_cookie);
    if (!vm || !vm->vcpu_count) return -EDGE_LINUX_EIO;
    --vm->vcpu_count;
    if (!vm->descriptor_references && !vm->vcpu_count && !vm->device_count)
        edge_kvm_destroy_vm(table, vm);
    return 0;
}

int edge_kvm_vcpu_snapshot(const edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_vcpu_snapshot_t *snapshot) {
    const edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu_const(table,
                                                                  handle);

    if (!vcpu || !snapshot) return -EDGE_LINUX_EBADF;
    snapshot->vcpu_id = vcpu->vcpu_id;
    snapshot->descriptor_references = vcpu->descriptor_references;
    snapshot->vm = vcpu->vm;
    snapshot->backend_cookie = vcpu->backend_cookie;
    snapshot->run_calls = vcpu->run_calls;
    return 0;
}

int edge_kvm_vcpu_run(edge_kvm_object_table_t *table,
                      edge_kvm_handle_t handle) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);
    uint64_t physical_address;
    edge_kvm_run_t *run;
    int status;

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    status = table->backend.vcpu_mmap_page(
        table->backend.context, vcpu->backend_cookie, 0,
        &physical_address);
    if (status < 0) return status;
    run = (edge_kvm_run_t *)(uintptr_t)physical_address;
    ++vcpu->run_calls;
    return table->backend.vcpu_run(table->backend.context,
                                   vcpu->backend_cookie, run);
}

int edge_kvm_vcpu_init(edge_kvm_object_table_t *table,
                       edge_kvm_handle_t handle,
                       const edge_kvm_vcpu_init_t *init) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!init) return -EDGE_LINUX_EINVAL;
    if (!table->backend.vcpu_init) return -EDGE_LINUX_ENOTTY;
    return table->backend.vcpu_init(
        table->backend.context, vcpu->backend_cookie, init);
}

int edge_kvm_vcpu_get_one_reg(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle, uint64_t id,
                              void *value, uint32_t size) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!value || size == 0 || size > 16 ||
        size != edge_kvm_register_size(id))
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.vcpu_get_one_reg) return -EDGE_LINUX_ENOTTY;
    return table->backend.vcpu_get_one_reg(
        table->backend.context, vcpu->backend_cookie, id, value, size);
}

int edge_kvm_vcpu_set_one_reg(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle, uint64_t id,
                              const void *value, uint32_t size) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!value || size == 0 || size > 16 ||
        size != edge_kvm_register_size(id))
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.vcpu_set_one_reg) return -EDGE_LINUX_ENOTTY;
    return table->backend.vcpu_set_one_reg(
        table->backend.context, vcpu->backend_cookie, id, value, size);
}

int edge_kvm_vcpu_get_reg_list(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle, uint64_t *ids,
                               uint32_t capacity, uint32_t *count) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!count || (capacity != 0 && !ids)) return -EDGE_LINUX_EINVAL;
    if (!table->backend.vcpu_get_reg_list) return -EDGE_LINUX_ENOTTY;
    return table->backend.vcpu_get_reg_list(
        table->backend.context, vcpu->backend_cookie, ids, capacity,
        count);
}

int edge_kvm_vcpu_get_regs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_regs_t *registers) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!registers) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_regs(
        table->backend.context, vcpu->backend_cookie, registers);
}

int edge_kvm_vcpu_set_regs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_regs_t *registers) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!registers) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_regs(
        table->backend.context, vcpu->backend_cookie, registers);
}

int edge_kvm_vcpu_get_sregs(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_sregs_t *registers) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!registers) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_sregs(
        table->backend.context, vcpu->backend_cookie, registers);
}

int edge_kvm_vcpu_set_sregs(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_sregs_t *registers) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!registers) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_sregs(
        table->backend.context, vcpu->backend_cookie, registers);
}

int edge_kvm_vcpu_get_sregs2(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             edge_kvm_sregs2_t *registers) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!registers) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_sregs2(
        table->backend.context, vcpu->backend_cookie, registers);
}

int edge_kvm_vcpu_set_sregs2(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_sregs2_t *registers) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!registers ||
        (registers->flags & ~EDGE_KVM_SREGS2_VALID_FLAGS) != 0)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_sregs2(
        table->backend.context, vcpu->backend_cookie, registers);
}

int edge_kvm_vcpu_get_fpu(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          edge_kvm_fpu_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_fpu(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_fpu(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_fpu_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_fpu(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_get_lapic(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_lapic_state_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_lapic(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_lapic(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_lapic_state_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_lapic(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_get_debugregs(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                edge_kvm_debugregs_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_debugregs(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_debugregs(edge_kvm_object_table_t *table,
                                edge_kvm_handle_t handle,
                                const edge_kvm_debugregs_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);
    uint64_t reserved = 0;

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || state->flags != 0) return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < 9; ++index)
        reserved |= state->reserved[index];
    if (reserved != 0) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_debugregs(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_guest_debug(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle,
                                  const edge_kvm_guest_debug_x86_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || state->padding != 0) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_guest_debug(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_get_xcrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_xcrs_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_xcrs(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_xcrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_xcrs_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);
    uint64_t padding = 0;

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || state->nr_xcrs > EDGE_KVM_MAX_XCRS || state->flags != 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < 16; ++index)
        padding |= state->padding[index];
    if (padding != 0) return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < state->nr_xcrs; ++index) {
        if (state->xcrs[index].reserved != 0 ||
            state->xcrs[index].xcr != 0)
            return -EDGE_LINUX_EINVAL;
    }
    return table->backend.vcpu_set_xcrs(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_get_xsave(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_xsave_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_xsave(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_xsave(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_xsave_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_xsave(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_get_msr_index_list(edge_kvm_object_table_t *table,
                                uint32_t *indices, uint32_t capacity,
                                uint32_t *count) {
    if (!table || !count || (capacity != 0 && !indices) ||
        capacity > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.get_msr_index_list(
        table->backend.context, indices, capacity, count);
}

int edge_kvm_get_msr_feature_index_list(edge_kvm_object_table_t *table,
                                        uint32_t *indices,
                                        uint32_t capacity,
                                        uint32_t *count) {
    if (!table || !count || (capacity != 0 && !indices) ||
        capacity > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.get_msr_feature_index_list)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.get_msr_feature_index_list(
        table->backend.context, indices, capacity, count);
}

int edge_kvm_get_msr_features(edge_kvm_object_table_t *table,
                              edge_kvm_msr_entry_t *entries,
                              uint32_t count) {
    if (!table || (count != 0 && !entries) ||
        count > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.get_msr_features)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.get_msr_features(
        table->backend.context, entries, count);
}

int edge_kvm_vcpu_get_msrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           edge_kvm_msr_entry_t *entries, uint32_t count) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if ((count != 0 && !entries) || count > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_msrs(
        table->backend.context, vcpu->backend_cookie, entries, count);
}

int edge_kvm_vcpu_set_msrs(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle,
                           const edge_kvm_msr_entry_t *entries,
                           uint32_t count) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if ((count != 0 && !entries) || count > EDGE_KVM_MAX_MSR_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_msrs(
        table->backend.context, vcpu->backend_cookie, entries, count);
}

int edge_kvm_vcpu_get_mp_state(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle,
                               edge_kvm_mp_state_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_mp_state(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_set_mp_state(edge_kvm_object_table_t *table,
                               edge_kvm_handle_t handle,
                               const edge_kvm_mp_state_t *state) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!state || state->mp_state > EDGE_KVM_MP_STATE_LOAD)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_mp_state(
        table->backend.context, vcpu->backend_cookie, state);
}

int edge_kvm_vcpu_get_events(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             edge_kvm_vcpu_events_t *events) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!events) return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_events(
        table->backend.context, vcpu->backend_cookie, events);
}

int edge_kvm_vcpu_set_events(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_vcpu_events_t *events) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!events || (events->flags & ~EDGE_KVM_VCPUEVENT_VALID_MASK) != 0)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_events(
        table->backend.context, vcpu->backend_cookie, events);
}

int edge_kvm_vcpu_set_vapic_address(edge_kvm_object_table_t *table,
                                    edge_kvm_handle_t handle,
                                    uint64_t address) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    /*
     * bhyve keeps the virtual LAPIC inside the vCPU instead of consulting a
     * userspace VAPIC cache page.  Preserve the Linux ABI address for object
     * state while the bhyve vlapic remains the authoritative implementation.
     */
    vcpu->vapic_address = address;
    return 0;
}

int64_t edge_kvm_vcpu_get_tsc_khz(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    return table->backend.vcpu_get_tsc_khz(
        table->backend.context, vcpu->backend_cookie);
}

int edge_kvm_vcpu_set_tsc_khz(edge_kvm_object_table_t *table,
                              edge_kvm_handle_t handle,
                              uint32_t frequency_khz) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    return table->backend.vcpu_set_tsc_khz(
        table->backend.context, vcpu->backend_cookie, frequency_khz);
}

int edge_kvm_vcpu_setup_mce(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            uint64_t capability) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);
    uint32_t bank_count =
        (uint32_t)(capability & EDGE_KVM_X86_MCE_BANK_COUNT_MASK);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (bank_count == 0 || bank_count > EDGE_KVM_X86_MCE_MAX_BANKS ||
        (capability & ~EDGE_KVM_X86_MCE_VALID_MASK) != 0)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_setup_mce(
        table->backend.context, vcpu->backend_cookie, capability);
}

int edge_kvm_vcpu_set_mce(edge_kvm_object_table_t *table,
                          edge_kvm_handle_t handle,
                          const edge_kvm_x86_mce_t *machine_check) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!machine_check ||
        (machine_check->status & EDGE_KVM_X86_MCE_STATUS_VALID) == 0)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_mce(
        table->backend.context, vcpu->backend_cookie, machine_check);
}

int edge_kvm_vcpu_set_signal_mask(edge_kvm_object_table_t *table,
                                  edge_kvm_handle_t handle,
                                  uint64_t mask) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!table->backend.vcpu_set_signal_mask)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.vcpu_set_signal_mask(
        table->backend.context, vcpu->backend_cookie, mask);
}

int edge_kvm_get_supported_cpuid(edge_kvm_object_table_t *table,
                                 edge_kvm_cpuid_entry2_t *entries,
                                 uint32_t capacity, uint32_t *count) {
    if (!table || !count || (capacity != 0 && !entries) ||
        capacity > EDGE_KVM_MAX_CPUID_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.get_supported_cpuid(
        table->backend.context, entries, capacity, count);
}

int edge_kvm_vcpu_set_cpuid(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            const edge_kvm_cpuid_entry2_t *entries,
                            uint32_t count) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if ((count != 0 && !entries) || count > EDGE_KVM_MAX_CPUID_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_set_cpuid(
        table->backend.context, vcpu->backend_cookie, entries, count);
}

int edge_kvm_vcpu_get_cpuid(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_cpuid_entry2_t *entries,
                            uint32_t capacity, uint32_t *count) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!count || (capacity != 0 && !entries) ||
        capacity > EDGE_KVM_MAX_CPUID_ENTRIES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_get_cpuid(
        table->backend.context, vcpu->backend_cookie, entries, capacity,
        count);
}

int edge_kvm_vcpu_mmap_page(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            uint32_t page_index,
                            uint64_t *physical_address) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!physical_address || page_index >= EDGE_KVM_VCPU_MMAP_PAGES)
        return -EDGE_LINUX_EINVAL;
    return table->backend.vcpu_mmap_page(
        table->backend.context, vcpu->backend_cookie, page_index,
        physical_address);
}

int edge_kvm_vcpu_pre_fault_memory(
        edge_kvm_object_table_t *table, edge_kvm_handle_t handle,
        edge_kvm_pre_fault_memory_t *request) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!request || !request->size || request->flags != 0 ||
        (request->guest_physical_address & (EDGE_KVM_PAGE_SIZE - 1u)) != 0 ||
        (request->size & (EDGE_KVM_PAGE_SIZE - 1u)) != 0 ||
        request->guest_physical_address > UINT64_MAX - request->size)
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.vcpu_pre_fault_memory)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.vcpu_pre_fault_memory(
        table->backend.context, vcpu->backend_cookie, request);
}

int edge_kvm_vcpu_translate(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle,
                            edge_kvm_translation_t *translation) {
    edge_kvm_vcpu_object_t *vcpu = edge_kvm_find_vcpu(table, handle);

    if (!vcpu || !vcpu->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!translation) return -EDGE_LINUX_EINVAL;
    if (!table->backend.vcpu_translate) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.vcpu_translate(
        table->backend.context, vcpu->backend_cookie, translation);
}

int edge_kvm_device_create(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t vm_handle, uint32_t type,
                           uint32_t flags, edge_kvm_handle_t *handle) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, vm_handle);
    edge_kvm_device_object_t *device = 0;
    uint64_t backend_cookie = 0;
    int status;

    if (!handle) return -EDGE_LINUX_EINVAL;
    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!table->backend.device_create || !table->backend.device_destroy)
        return -EDGE_LINUX_EOPNOTSUPP;
    for (uint32_t slot = 0; slot < EDGE_KVM_OBJECT_MAX_DEVICES; ++slot) {
        edge_kvm_device_object_t *candidate = &table->devices[slot];
        if (candidate->active && candidate->vm.slot == vm_handle.slot &&
            candidate->vm.generation == vm_handle.generation &&
            candidate->type == type)
            return -EDGE_LINUX_EEXIST;
        if (!candidate->active && !device) device = candidate;
    }
    if (!device) return -EDGE_LINUX_EMFILE;
    status = table->backend.device_create(
        table->backend.context, vm->backend_cookie, type, flags,
        &backend_cookie);
    if (status < 0) return status;
    memset(device, 0, sizeof(*device));
    device->active = 1;
    device->generation = edge_kvm_next_generation(table);
    device->type = type;
    device->descriptor_references = 1;
    device->vm = vm_handle;
    device->backend_cookie = backend_cookie;
    ++vm->device_count;
    ++table->active_device_count;
    handle->slot = (uint32_t)(device - table->devices);
    handle->generation = device->generation;
    return 0;
}

int edge_kvm_device_test(edge_kvm_object_table_t *table,
                         edge_kvm_handle_t vm_handle, uint32_t type) {
    edge_kvm_vm_object_t *vm = edge_kvm_find_vm(table, vm_handle);
    uint64_t backend_cookie = 0;
    int status;

    if (!vm || !vm->descriptor_references) return -EDGE_LINUX_EBADF;
    if (!table->backend.device_create || !table->backend.device_destroy)
        return -EDGE_LINUX_EOPNOTSUPP;
    status = table->backend.device_create(
        table->backend.context, vm->backend_cookie, type,
        EDGE_KVM_CREATE_DEVICE_TEST, &backend_cookie);
    if (status == 0 && backend_cookie != 0)
        table->backend.device_destroy(
            table->backend.context, backend_cookie);
    return status;
}

int edge_kvm_device_retain(edge_kvm_object_table_t *table,
                           edge_kvm_handle_t handle) {
    edge_kvm_device_object_t *device = edge_kvm_find_device(table, handle);

    if (!device || !device->descriptor_references)
        return -EDGE_LINUX_EBADF;
    if (device->descriptor_references == UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    ++device->descriptor_references;
    return 0;
}

int edge_kvm_device_release(edge_kvm_object_table_t *table,
                            edge_kvm_handle_t handle) {
    edge_kvm_device_object_t *device = edge_kvm_find_device(table, handle);
    edge_kvm_vm_object_t *vm;
    uint64_t backend_cookie;

    if (!device || !device->descriptor_references)
        return -EDGE_LINUX_EBADF;
    --device->descriptor_references;
    if (device->descriptor_references) return 0;
    vm = edge_kvm_find_vm(table, device->vm);
    backend_cookie = device->backend_cookie;
    memset(device, 0, sizeof(*device));
    --table->active_device_count;
    table->backend.device_destroy(table->backend.context, backend_cookie);
    if (!vm || !vm->device_count) return -EDGE_LINUX_EIO;
    --vm->device_count;
    if (!vm->descriptor_references && !vm->vcpu_count && !vm->device_count)
        edge_kvm_destroy_vm(table, vm);
    return 0;
}

int edge_kvm_device_set_attr(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_device_attr_t *attribute,
                             const void *value, uint32_t value_size) {
    edge_kvm_device_object_t *device = edge_kvm_find_device(table, handle);

    if (!device || !device->descriptor_references)
        return -EDGE_LINUX_EBADF;
    if (!attribute || (value_size != 0 && !value) ||
        !table->backend.device_set_attr)
        return -EDGE_LINUX_EINVAL;
    return table->backend.device_set_attr(
        table->backend.context, device->backend_cookie, attribute,
        value, value_size);
}

int edge_kvm_device_get_attr(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_device_attr_t *attribute,
                             void *value, uint32_t value_size) {
    edge_kvm_device_object_t *device = edge_kvm_find_device(table, handle);

    if (!device || !device->descriptor_references)
        return -EDGE_LINUX_EBADF;
    if (!attribute || (value_size != 0 && !value) ||
        !table->backend.device_get_attr)
        return -EDGE_LINUX_EINVAL;
    return table->backend.device_get_attr(
        table->backend.context, device->backend_cookie, attribute,
        value, value_size);
}

int edge_kvm_device_has_attr(edge_kvm_object_table_t *table,
                             edge_kvm_handle_t handle,
                             const edge_kvm_device_attr_t *attribute) {
    edge_kvm_device_object_t *device = edge_kvm_find_device(table, handle);

    if (!device || !device->descriptor_references)
        return -EDGE_LINUX_EBADF;
    if (!attribute || !table->backend.device_has_attr)
        return -EDGE_LINUX_EINVAL;
    return table->backend.device_has_attr(
        table->backend.context, device->backend_cookie, attribute);
}
