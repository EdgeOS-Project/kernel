/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for KVM facade object lifetime translation. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/edge_kvm_object.h"
#include "kernel/linux_errno.h"

typedef struct test_backend {
    uint64_t next_cookie;
    uint32_t created_vms;
    uint32_t destroyed_vms;
    uint32_t created_vcpus;
    uint32_t destroyed_vcpus;
    uint32_t memory_updates;
    uint32_t fail_memory_update;
} test_backend_t;

static int test_vm_create(void *opaque, uint32_t machine_type,
                          uint64_t *cookie) {
    test_backend_t *backend = opaque;
    (void)machine_type;
    *cookie = ++backend->next_cookie;
    ++backend->created_vms;
    return 0;
}

static void test_vm_destroy(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    ++backend->destroyed_vms;
}

static int test_vcpu_create(void *opaque, uint64_t vm_cookie,
                            uint32_t vcpu_id, uint64_t *cookie) {
    test_backend_t *backend = opaque;
    assert(vm_cookie != 0);
    (void)vcpu_id;
    *cookie = ++backend->next_cookie;
    ++backend->created_vcpus;
    return 0;
}

static void test_vcpu_destroy(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    ++backend->destroyed_vcpus;
}

static int test_memory_region_set(
        void *opaque, uint64_t vm_cookie,
        const edge_kvm_memory_region_t *region) {
    test_backend_t *backend = opaque;
    assert(vm_cookie != 0 && region != 0);
    ++backend->memory_updates;
    return backend->fail_memory_update ? -EDGE_LINUX_EIO : 0;
}

int main(void) {
    edge_kvm_object_table_t table;
    test_backend_t backend_state;
    edge_kvm_backend_ops_t backend;
    edge_kvm_handle_t vm;
    edge_kvm_handle_t stale_vm;
    edge_kvm_handle_t vcpu;
    edge_kvm_handle_t second_vcpu;
    edge_kvm_vm_snapshot_t vm_snapshot;
    edge_kvm_vcpu_snapshot_t vcpu_snapshot;
    edge_kvm_memory_region_t region;

    memset(&backend_state, 0, sizeof(backend_state));
    backend = (edge_kvm_backend_ops_t) {
        .context = &backend_state,
        .vm_create = test_vm_create,
        .vm_destroy = test_vm_destroy,
        .vcpu_create = test_vcpu_create,
        .vcpu_destroy = test_vcpu_destroy,
        .memory_region_set = test_memory_region_set,
    };
    assert(edge_kvm_object_table_init(&table, &backend) == 0);
    assert(edge_kvm_vm_create(&table, 0, &vm) == 0);
    stale_vm = vm;
    assert(table.active_vm_count == 1 && backend_state.created_vms == 1);
    assert(edge_kvm_vm_retain(&table, vm) == 0);
    assert(edge_kvm_vm_snapshot(&table, vm, &vm_snapshot) == 0);
    assert(vm_snapshot.descriptor_references == 2);

    region = (edge_kvm_memory_region_t) {
        .slot = 0,
        .flags = EDGE_KVM_MEMORY_LOG_DIRTY_PAGES,
        .guest_physical_address = 0x100000,
        .memory_size = 0x200000,
        .userspace_address = 0x40000000,
    };
    assert(edge_kvm_vm_set_memory_region(&table, vm, &region) == 0);
    assert(edge_kvm_vm_snapshot(&table, vm, &vm_snapshot) == 0);
    assert(vm_snapshot.memory_slot_count == 1);

    region.slot = 1;
    region.guest_physical_address = 0x200000;
    assert(edge_kvm_vm_set_memory_region(&table, vm, &region) ==
           -EDGE_LINUX_EEXIST);
    region.guest_physical_address = 0x400000;
    region.userspace_address = 0x50000000;
    backend_state.fail_memory_update = 1;
    assert(edge_kvm_vm_set_memory_region(&table, vm, &region) ==
           -EDGE_LINUX_EIO);
    backend_state.fail_memory_update = 0;
    assert(edge_kvm_vm_snapshot(&table, vm, &vm_snapshot) == 0);
    assert(vm_snapshot.memory_slot_count == 1);

    assert(edge_kvm_vcpu_create(&table, vm, 0, &vcpu) == 0);
    assert(edge_kvm_vcpu_create(&table, vm, 0, &second_vcpu) ==
           -EDGE_LINUX_EEXIST);
    assert(edge_kvm_vcpu_create(&table, vm, 7, &second_vcpu) == 0);
    assert(edge_kvm_vcpu_retain(&table, vcpu) == 0);
    assert(edge_kvm_vcpu_snapshot(&table, vcpu, &vcpu_snapshot) == 0);
    assert(vcpu_snapshot.vcpu_id == 0 &&
           vcpu_snapshot.descriptor_references == 2);

    assert(edge_kvm_vm_release(&table, vm) == 0);
    assert(edge_kvm_vm_release(&table, vm) == 0);
    assert(backend_state.destroyed_vms == 0);
    assert(edge_kvm_vm_retain(&table, vm) == -EDGE_LINUX_EBADF);
    assert(edge_kvm_vcpu_release(&table, vcpu) == 0);
    assert(edge_kvm_vcpu_release(&table, vcpu) == 0);
    assert(edge_kvm_vcpu_release(&table, second_vcpu) == 0);
    assert(backend_state.destroyed_vcpus == 2);
    assert(backend_state.destroyed_vms == 1);
    assert(table.active_vm_count == 0 && table.active_vcpu_count == 0);

    assert(edge_kvm_vm_create(&table, 0, &vm) == 0);
    assert(vm.slot == stale_vm.slot && vm.generation != stale_vm.generation);
    assert(edge_kvm_vm_snapshot(&table, stale_vm, &vm_snapshot) ==
           -EDGE_LINUX_EBADF);
    assert(edge_kvm_vm_release(&table, vm) == 0);

    assert(edge_kvm_vm_create(&table, 0, &vm) == 0);
    assert(edge_kvm_vcpu_create(&table, vm, 3, &vcpu) == 0);
    edge_kvm_object_table_reset(&table);
    assert(table.active_vm_count == 0 && table.active_vcpu_count == 0);
    assert(backend_state.created_vms == backend_state.destroyed_vms);
    assert(backend_state.created_vcpus == backend_state.destroyed_vcpus);
    assert(backend_state.memory_updates == 2);

    puts("edge_kvm_object_unit: PASS");
    return 0;
}
