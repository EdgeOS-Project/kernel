/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/edge_kvm_abi.h"
#include "kernel/edge_kvm_facade.h"
#include "kernel/linux_errno.h"

typedef struct mock_state {
    uint32_t vm_creates;
    uint32_t vm_destroys;
    uint32_t vcpu_creates;
    uint32_t vcpu_destroys;
    uint32_t memory_updates;
    int next_descriptor;
    int install_error;
    edge_kvm_descriptor_kind_t installed_kind;
    edge_kvm_handle_t installed_handle;
} mock_state_t;

static int mock_vm_create(void *context, uint32_t machine_type,
                          uint64_t *cookie) {
    mock_state_t *state = context;
    ++state->vm_creates;
    *cookie = 0x1000u + machine_type;
    return 0;
}

static void mock_vm_destroy(void *context, uint64_t cookie) {
    mock_state_t *state = context;
    (void)cookie;
    ++state->vm_destroys;
}

static int mock_vcpu_create(void *context, uint64_t vm_cookie,
                            uint32_t vcpu_id, uint64_t *cookie) {
    mock_state_t *state = context;
    ++state->vcpu_creates;
    *cookie = vm_cookie + vcpu_id + 1u;
    return 0;
}

static void mock_vcpu_destroy(void *context, uint64_t cookie) {
    mock_state_t *state = context;
    (void)cookie;
    ++state->vcpu_destroys;
}

static int mock_memory_region_set(void *context, uint64_t vm_cookie,
                                  const edge_kvm_memory_region_t *region) {
    mock_state_t *state = context;
    (void)vm_cookie;
    (void)region;
    ++state->memory_updates;
    return 0;
}

static int mock_descriptor_install(void *context,
                                   edge_kvm_descriptor_kind_t kind,
                                   edge_kvm_handle_t handle) {
    mock_state_t *state = context;
    state->installed_kind = kind;
    state->installed_handle = handle;
    if (state->install_error) return state->install_error;
    return state->next_descriptor++;
}

static void init_facade(edge_kvm_facade_t *facade, mock_state_t *state) {
    edge_kvm_backend_ops_t backend = {
        .context = state,
        .vm_create = mock_vm_create,
        .vm_destroy = mock_vm_destroy,
        .vcpu_create = mock_vcpu_create,
        .vcpu_destroy = mock_vcpu_destroy,
        .memory_region_set = mock_memory_region_set,
    };
    edge_kvm_descriptor_ops_t descriptors = {
        .context = state,
        .install = mock_descriptor_install,
    };
    edge_kvm_capability_table_t capabilities;

    edge_kvm_capability_table_init(&capabilities);
    assert(edge_kvm_capability_set(
               &capabilities, EDGE_KVM_CAP_USER_MEMORY, 1) == 0);
    assert(edge_kvm_capability_set(
               &capabilities, EDGE_KVM_CAP_NR_MEMSLOTS,
               EDGE_KVM_OBJECT_MAX_MEMORY_SLOTS) == 0);
    assert(edge_kvm_facade_init(facade, &backend, &descriptors,
                                &capabilities) == 0);
}

static void test_system_contract_and_vm_lifetime(void) {
    edge_kvm_facade_t facade;
    mock_state_t state = {.next_descriptor = 40};
    edge_kvm_handle_t vm;
    edge_kvm_handle_t vcpu;
    edge_kvm_userspace_memory_region_t memory = {
        .slot = 2,
        .guest_physical_address = 0x4000,
        .memory_size = 0x8000,
        .userspace_address = 0x100000,
    };

    init_facade(&facade, &state);
    assert(edge_kvm_facade_system_ioctl(
               &facade, EDGE_KVM_IOCTL_GET_API_VERSION, 0) == 12);
    assert(edge_kvm_facade_system_ioctl(
               &facade, EDGE_KVM_IOCTL_GET_VCPU_MMAP_SIZE, 0) == 12288);
    assert(edge_kvm_facade_system_ioctl(
               &facade, EDGE_KVM_IOCTL_CHECK_EXTENSION,
               EDGE_KVM_CAP_USER_MEMORY) == 1);
    assert(edge_kvm_facade_system_ioctl(
               &facade, EDGE_KVM_IOCTL_CHECK_EXTENSION, 0xffffffffu) == 0);
    assert(edge_kvm_facade_system_ioctl(&facade, 0xdeadbeefu, 0) ==
           -EDGE_LINUX_ENOTTY);

    assert(edge_kvm_facade_system_ioctl(
               &facade, EDGE_KVM_IOCTL_CREATE_VM, 7) == 40);
    assert(state.installed_kind == EDGE_KVM_DESCRIPTOR_VM);
    vm = state.installed_handle;
    assert(edge_kvm_facade_vm_ioctl(
               &facade, vm, EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION,
               (uint64_t)(uintptr_t)&memory) == 0);
    assert(state.memory_updates == 1);

    assert(edge_kvm_facade_vm_ioctl(
               &facade, vm, EDGE_KVM_IOCTL_CREATE_VCPU, 3) == 41);
    assert(state.installed_kind == EDGE_KVM_DESCRIPTOR_VCPU);
    vcpu = state.installed_handle;
    assert(edge_kvm_facade_descriptor_release(
               &facade, EDGE_KVM_DESCRIPTOR_VM, vm) == 0);
    assert(state.vm_destroys == 0);
    assert(edge_kvm_facade_descriptor_retain(
               &facade, EDGE_KVM_DESCRIPTOR_VCPU, vcpu) == 0);
    assert(edge_kvm_facade_descriptor_release(
               &facade, EDGE_KVM_DESCRIPTOR_VCPU, vcpu) == 0);
    assert(edge_kvm_facade_descriptor_release(
               &facade, EDGE_KVM_DESCRIPTOR_VCPU, vcpu) == 0);
    assert(state.vcpu_destroys == 1);
    assert(state.vm_destroys == 1);
    edge_kvm_facade_reset(&facade);
}

static void test_descriptor_install_rollback(void) {
    edge_kvm_facade_t facade;
    mock_state_t state = {
        .next_descriptor = 80,
        .install_error = -EDGE_LINUX_EMFILE,
    };

    init_facade(&facade, &state);
    assert(edge_kvm_facade_system_ioctl(
               &facade, EDGE_KVM_IOCTL_CREATE_VM, 0) ==
           -EDGE_LINUX_EMFILE);
    assert(state.vm_creates == 1);
    assert(state.vm_destroys == 1);
    assert(facade.objects.active_vm_count == 0);
    edge_kvm_facade_reset(&facade);
}

int main(void) {
    test_system_contract_and_vm_lifetime();
    test_descriptor_install_rollback();
    puts("edge_kvm_facade_unit: PASS");
    return 0;
}
