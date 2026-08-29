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
        !backend->vcpu_create || !backend->vcpu_destroy ||
        !backend->memory_region_set)
        return -EDGE_LINUX_EINVAL;
    memset(table, 0, sizeof(*table));
    table->backend = *backend;
    return 0;
}

void edge_kvm_object_table_reset(edge_kvm_object_table_t *table) {
    if (!table) return;
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
    if (!vm->descriptor_references && !vm->vcpu_count)
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
    if (!vm->descriptor_references && !vm->vcpu_count)
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
    return 0;
}
