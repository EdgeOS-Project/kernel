/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
    uint32_t vcpu_runs;
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
    uint8_t run_pages[EDGE_KVM_VCPU_MMAP_PAGES][EDGE_KVM_PAGE_SIZE]
        __attribute__((aligned(EDGE_KVM_PAGE_SIZE)));
} mock_state_t;

static int mock_get_supported_cpuid(void *context,
                                    edge_kvm_cpuid_entry2_t *entries,
                                    uint32_t capacity, uint32_t *count) {
    (void)context;
    *count = 1;
    if (capacity != 0)
        entries[0] = (edge_kvm_cpuid_entry2_t) {.function = 1,
                                                .eax = 0x1234};
    return 0;
}

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

static int mock_vm_set_address(void *context, uint64_t cookie,
                               uint64_t address) {
    (void)context;
    assert(cookie != 0 && (address & (EDGE_KVM_PAGE_SIZE - 1)) == 0);
    return 0;
}

static int mock_vm_create_irqchip(void *context, uint64_t cookie) {
    (void)context;
    assert(cookie != 0);
    return 0;
}

static int mock_vm_set_gsi_routing(
        void *context, uint64_t cookie,
        const edge_kvm_irq_routing_entry_t *entries, uint32_t count) {
    (void)context;
    assert(cookie != 0 && (count == 0 || entries != 0));
    return 0;
}

static int mock_vm_set_irq_line(void *context, uint64_t cookie,
                                edge_kvm_irq_level_t *level) {
    (void)context;
    assert(cookie != 0 && level != 0 && level->level <= 1);
    return 0;
}

static int mock_vm_get_irqchip(void *context, uint64_t cookie,
                               edge_kvm_irqchip_t *state) {
    mock_state_t *mock = context;
    assert(cookie != 0);
    *state = mock->irqchip;
    return 0;
}

static int mock_vm_set_irqchip(void *context, uint64_t cookie,
                               const edge_kvm_irqchip_t *state) {
    mock_state_t *mock = context;
    assert(cookie != 0);
    mock->irqchip = *state;
    return 0;
}

static int mock_vm_get_pit(void *context, uint64_t cookie,
                           edge_kvm_pit_state2_t *state) {
    mock_state_t *mock = context;
    assert(cookie != 0);
    *state = mock->pit_state;
    return 0;
}

static int mock_vm_set_pit(void *context, uint64_t cookie,
                           const edge_kvm_pit_state2_t *state) {
    mock_state_t *mock = context;
    assert(cookie != 0);
    mock->pit_state = *state;
    return 0;
}

static int mock_vm_create_pit(void *context, uint64_t cookie,
                              const edge_kvm_pit_config_t *config) {
    (void)context;
    assert(cookie != 0 && config != 0 && config->flags == 0);
    return 0;
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

static int mock_vcpu_run(void *context, uint64_t cookie,
                         edge_kvm_run_t *run) {
    mock_state_t *state = context;
    (void)cookie;
    ++state->vcpu_runs;
    run->exit_reason = EDGE_KVM_EXIT_HLT;
    return 0;
}

static int mock_vcpu_get_regs(void *context, uint64_t cookie,
                              edge_kvm_regs_t *registers) {
    mock_state_t *state = context;
    (void)cookie;
    *registers = state->registers;
    return 0;
}

static int mock_vcpu_set_regs(void *context, uint64_t cookie,
                              const edge_kvm_regs_t *registers) {
    mock_state_t *state = context;
    (void)cookie;
    state->registers = *registers;
    return 0;
}

static int mock_vcpu_get_sregs(void *context, uint64_t cookie,
                               edge_kvm_sregs_t *registers) {
    mock_state_t *state = context;
    (void)cookie;
    *registers = state->special_registers;
    return 0;
}

static int mock_vcpu_set_sregs(void *context, uint64_t cookie,
                               const edge_kvm_sregs_t *registers) {
    mock_state_t *state = context;
    (void)cookie;
    state->special_registers = *registers;
    return 0;
}

static int mock_vcpu_get_sregs2(void *context, uint64_t cookie,
                                edge_kvm_sregs2_t *registers) {
    mock_state_t *state = context;
    (void)cookie;
    *registers = state->special_registers2;
    return 0;
}

static int mock_vcpu_set_sregs2(void *context, uint64_t cookie,
                                const edge_kvm_sregs2_t *registers) {
    mock_state_t *state = context;
    (void)cookie;
    state->special_registers2 = *registers;
    return 0;
}

static int mock_vcpu_get_fpu(void *context, uint64_t cookie,
                             edge_kvm_fpu_t *fpu_state) {
    mock_state_t *state = context;
    (void)cookie;
    *fpu_state = state->fpu_state;
    return 0;
}

static int mock_vcpu_set_fpu(void *context, uint64_t cookie,
                             const edge_kvm_fpu_t *fpu_state) {
    mock_state_t *state = context;
    (void)cookie;
    state->fpu_state = *fpu_state;
    return 0;
}

static int mock_get_msr_index_list(void *context, uint32_t *indices,
                                   uint32_t capacity, uint32_t *count) {
    (void)context;
    *count = 1;
    if (capacity != 0) indices[0] = 0x10;
    return 0;
}

static int mock_vcpu_get_msrs(void *context, uint64_t cookie,
                              edge_kvm_msr_entry_t *entries,
                              uint32_t count) {
    mock_state_t *state = context;
    (void)cookie;
    assert(count <= state->msr_count);
    for (uint32_t index = 0; index < count; ++index)
        entries[index].data = state->msrs[index].data;
    return (int)count;
}

static int mock_vcpu_set_msrs(void *context, uint64_t cookie,
                              const edge_kvm_msr_entry_t *entries,
                              uint32_t count) {
    mock_state_t *state = context;
    (void)cookie;
    assert(count <= 4);
    if (count != 0) memcpy(state->msrs, entries,
                           count * sizeof(entries[0]));
    state->msr_count = count;
    return (int)count;
}

static int mock_vcpu_get_mp_state(void *context, uint64_t cookie,
                                  edge_kvm_mp_state_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    *state = mock->mp_state;
    return 0;
}

static int mock_vcpu_set_mp_state(void *context, uint64_t cookie,
                                  const edge_kvm_mp_state_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    mock->mp_state = *state;
    return 0;
}

static int mock_vcpu_get_lapic(void *context, uint64_t cookie,
                               edge_kvm_lapic_state_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    *state = mock->lapic_state;
    return 0;
}

static int mock_vcpu_set_lapic(void *context, uint64_t cookie,
                               const edge_kvm_lapic_state_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    mock->lapic_state = *state;
    return 0;
}

static int mock_vcpu_get_debugregs(void *context, uint64_t cookie,
                                   edge_kvm_debugregs_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    *state = mock->debug_registers;
    return 0;
}

static int mock_vcpu_set_debugregs(void *context, uint64_t cookie,
                                   const edge_kvm_debugregs_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    mock->debug_registers = *state;
    return 0;
}

static int mock_vcpu_set_guest_debug(
    void *context, uint64_t cookie,
    const edge_kvm_guest_debug_x86_t *state) {
    mock_state_t *mock = context;
    assert(cookie != 0);
    mock->guest_debug = *state;
    return 0;
}

static int mock_vcpu_get_xcrs(void *context, uint64_t cookie,
                              edge_kvm_xcrs_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    *state = mock->xcrs;
    return 0;
}

static int mock_vcpu_set_xcrs(void *context, uint64_t cookie,
                              const edge_kvm_xcrs_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    mock->xcrs = *state;
    return 0;
}

static int mock_vcpu_get_xsave(void *context, uint64_t cookie,
                               edge_kvm_xsave_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    *state = mock->xsave;
    return 0;
}

static int mock_vcpu_set_xsave(void *context, uint64_t cookie,
                               const edge_kvm_xsave_t *state) {
    mock_state_t *mock = context;
    (void)cookie;
    mock->xsave = *state;
    return 0;
}

static int mock_vcpu_get_events(void *context, uint64_t cookie,
                                edge_kvm_vcpu_events_t *events) {
    mock_state_t *mock = context;
    (void)cookie;
    *events = mock->events;
    return 0;
}

static int mock_vcpu_set_events(void *context, uint64_t cookie,
                                const edge_kvm_vcpu_events_t *events) {
    mock_state_t *mock = context;
    (void)cookie;
    mock->events = *events;
    return 0;
}

static int64_t mock_vcpu_get_tsc_khz(void *context, uint64_t cookie) {
    mock_state_t *state = context;
    (void)cookie;
    return state->tsc_frequency_khz;
}

static int mock_vcpu_set_tsc_khz(void *context, uint64_t cookie,
                                 uint32_t frequency_khz) {
    mock_state_t *state = context;
    (void)cookie;
    state->tsc_frequency_khz = frequency_khz;
    return 0;
}

static int mock_vcpu_setup_mce(void *context, uint64_t cookie,
                               uint64_t capability) {
    mock_state_t *state = context;
    (void)cookie;
    state->mce_capability = capability;
    return 0;
}

static int mock_vcpu_set_mce(void *context, uint64_t cookie,
                             const edge_kvm_x86_mce_t *machine_check) {
    mock_state_t *state = context;
    (void)cookie;
    state->machine_check = *machine_check;
    return 0;
}

static int mock_vcpu_set_cpuid(void *context, uint64_t cookie,
                               const edge_kvm_cpuid_entry2_t *entries,
                               uint32_t count) {
    mock_state_t *state = context;
    (void)cookie;
    assert(count <= 4);
    if (count != 0)
        memcpy(state->cpuid_entries, entries, count * sizeof(entries[0]));
    state->cpuid_count = count;
    return 0;
}

static int mock_vcpu_get_cpuid(void *context, uint64_t cookie,
                               edge_kvm_cpuid_entry2_t *entries,
                               uint32_t capacity, uint32_t *count) {
    mock_state_t *state = context;
    uint32_t copied;

    (void)cookie;
    assert(count != 0);
    *count = state->cpuid_count;
    copied = capacity < state->cpuid_count ? capacity : state->cpuid_count;
    if (copied != 0)
        memcpy(entries, state->cpuid_entries,
               copied * sizeof(entries[0]));
    return 0;
}

static int mock_vcpu_mmap_page(void *context, uint64_t cookie,
                               uint32_t page_index, uint64_t *physical) {
    mock_state_t *state = context;
    (void)cookie;
    if (page_index >= EDGE_KVM_VCPU_MMAP_PAGES || !physical)
        return -EDGE_LINUX_EINVAL;
    *physical = (uint64_t)(uintptr_t)state->run_pages[page_index];
    return 0;
}

static int mock_memory_region_set(void *context, uint64_t vm_cookie,
                                  const edge_kvm_memory_region_t *region) {
    mock_state_t *state = context;
    (void)vm_cookie;
    (void)region;
    ++state->memory_updates;
    return 0;
}

static int mock_memory_dirty_log_get(
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
    bitmap[0] = UINT64_C(0x9);
    return 0;
}

static int mock_memory_dirty_log_clear(
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
        .get_supported_cpuid = mock_get_supported_cpuid,
        .get_msr_index_list = mock_get_msr_index_list,
        .vm_create = mock_vm_create,
        .vm_destroy = mock_vm_destroy,
        .vm_set_tss_address = mock_vm_set_address,
        .vm_set_identity_map_address = mock_vm_set_address,
        .vm_create_irqchip = mock_vm_create_irqchip,
        .vm_set_gsi_routing = mock_vm_set_gsi_routing,
        .vm_set_irq_line = mock_vm_set_irq_line,
        .vm_get_irqchip = mock_vm_get_irqchip,
        .vm_set_irqchip = mock_vm_set_irqchip,
        .vm_create_pit = mock_vm_create_pit,
        .vm_get_pit = mock_vm_get_pit,
        .vm_set_pit = mock_vm_set_pit,
        .vcpu_create = mock_vcpu_create,
        .vcpu_destroy = mock_vcpu_destroy,
        .vcpu_run = mock_vcpu_run,
        .vcpu_get_regs = mock_vcpu_get_regs,
        .vcpu_set_regs = mock_vcpu_set_regs,
        .vcpu_get_sregs = mock_vcpu_get_sregs,
        .vcpu_set_sregs = mock_vcpu_set_sregs,
        .vcpu_get_sregs2 = mock_vcpu_get_sregs2,
        .vcpu_set_sregs2 = mock_vcpu_set_sregs2,
        .vcpu_get_fpu = mock_vcpu_get_fpu,
        .vcpu_set_fpu = mock_vcpu_set_fpu,
        .vcpu_get_lapic = mock_vcpu_get_lapic,
        .vcpu_set_lapic = mock_vcpu_set_lapic,
        .vcpu_get_debugregs = mock_vcpu_get_debugregs,
        .vcpu_set_debugregs = mock_vcpu_set_debugregs,
        .vcpu_set_guest_debug = mock_vcpu_set_guest_debug,
        .vcpu_get_xcrs = mock_vcpu_get_xcrs,
        .vcpu_set_xcrs = mock_vcpu_set_xcrs,
        .vcpu_get_xsave = mock_vcpu_get_xsave,
        .vcpu_set_xsave = mock_vcpu_set_xsave,
        .vcpu_get_msrs = mock_vcpu_get_msrs,
        .vcpu_set_msrs = mock_vcpu_set_msrs,
        .vcpu_get_mp_state = mock_vcpu_get_mp_state,
        .vcpu_set_mp_state = mock_vcpu_set_mp_state,
        .vcpu_get_events = mock_vcpu_get_events,
        .vcpu_set_events = mock_vcpu_set_events,
        .vcpu_get_tsc_khz = mock_vcpu_get_tsc_khz,
        .vcpu_set_tsc_khz = mock_vcpu_set_tsc_khz,
        .vcpu_setup_mce = mock_vcpu_setup_mce,
        .vcpu_set_mce = mock_vcpu_set_mce,
        .vcpu_set_cpuid = mock_vcpu_set_cpuid,
        .vcpu_get_cpuid = mock_vcpu_get_cpuid,
        .vcpu_mmap_page = mock_vcpu_mmap_page,
        .memory_region_set = mock_memory_region_set,
        .memory_dirty_log_get = mock_memory_dirty_log_get,
        .memory_dirty_log_clear = mock_memory_dirty_log_clear,
    };
    edge_kvm_descriptor_ops_t descriptors = {
        .context = state,
        .install = mock_descriptor_install,
    };
    edge_kvm_capability_table_t capabilities;

    state->tsc_frequency_khz = UINT32_C(2900000);

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
    {
        uint64_t identity_map_address = 0xfeffc000u;
        edge_kvm_pit_config_t pit = {0};

        assert(edge_kvm_facade_vm_ioctl(
                   &facade, vm, EDGE_KVM_IOCTL_SET_TSS_ADDR,
                   0xfeffd000u) == 0);
        assert(edge_kvm_facade_vm_ioctl(
                   &facade, vm, EDGE_KVM_IOCTL_SET_IDENTITY_MAP_ADDR,
                   (uint64_t)(uintptr_t)&identity_map_address) == 0);
        assert(edge_kvm_facade_vm_ioctl(
                   &facade, vm, EDGE_KVM_IOCTL_CREATE_IRQCHIP, 0) == 0);
        assert(edge_kvm_facade_vm_ioctl(
                   &facade, vm, EDGE_KVM_IOCTL_CREATE_PIT2,
                   (uint64_t)(uintptr_t)&pit) == 0);
    }
    assert(edge_kvm_facade_vm_ioctl(
               &facade, vm, EDGE_KVM_IOCTL_SET_USER_MEMORY_REGION,
               (uint64_t)(uintptr_t)&memory) == 0);
    assert(state.memory_updates == 1);

    assert(edge_kvm_facade_vm_ioctl(
               &facade, vm, EDGE_KVM_IOCTL_CREATE_VCPU, 3) == 41);
    assert(state.installed_kind == EDGE_KVM_DESCRIPTOR_VCPU);
    vcpu = state.installed_handle;
    assert(edge_kvm_facade_vcpu_ioctl(
               &facade, vcpu, EDGE_KVM_IOCTL_RUN, 0) == 0);
    assert(state.vcpu_runs == 1);
    assert(((edge_kvm_run_t *)state.run_pages[0])->exit_reason ==
           EDGE_KVM_EXIT_HLT);
    {
        edge_kvm_guest_debug_x86_t debug = {
            .control = EDGE_KVM_GUESTDBG_ENABLE |
                       EDGE_KVM_GUESTDBG_SINGLESTEP,
        };

        assert(edge_kvm_facade_vcpu_set_guest_debug(
                   &facade, vcpu, &debug) == 0);
        assert(state.guest_debug.control == debug.control);
        debug.padding = 1;
        assert(edge_kvm_facade_vcpu_set_guest_debug(
                   &facade, vcpu, &debug) == -EDGE_LINUX_EINVAL);
    }
    {
        edge_kvm_fpu_t input = {
            .fcw = 0x037f,
            .last_ip = 0x1122334455667788ull,
            .mxcsr = 0x1f80,
        };
        edge_kvm_fpu_t output = {0};
        input.fpr[2][4] = 0xc3;
        input.xmm[9][12] = 0x7e;
        assert(edge_kvm_facade_vcpu_set_fpu(
                   &facade, vcpu, &input) == 0);
        assert(edge_kvm_facade_vcpu_get_fpu(
                   &facade, vcpu, &output) == 0);
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
        assert(edge_kvm_facade_vcpu_set_sregs2(
                   &facade, vcpu, &input) == 0);
        assert(edge_kvm_facade_vcpu_get_sregs2(
                   &facade, vcpu, &output) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_lapic_state_t input = {0};
        edge_kvm_lapic_state_t output = {0};
        input.registers[0x80] = 0x50;
        assert(edge_kvm_facade_vcpu_set_lapic(
                   &facade, vcpu, &input) == 0);
        assert(edge_kvm_facade_vcpu_get_lapic(
                   &facade, vcpu, &output) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_msr_entry_t input[2] = {
            {.index = 0xc0000081u, .data = 0x0013000800000000ull},
            {.index = 0x00000277u, .data = 0x0007040600070406ull},
        };
        edge_kvm_msr_entry_t output[2] = {
            {.index = 0xc0000081u},
            {.index = 0x00000277u},
        };
        uint32_t indices[1] = {0};
        uint32_t count = 0;

        assert(edge_kvm_facade_get_msr_index_list(
                   &facade, indices, 1, &count) == 0);
        assert(count == 1 && indices[0] == 0x10u);
        assert(edge_kvm_facade_vcpu_set_msrs(
                   &facade, vcpu, input, 2) == 2);
        assert(edge_kvm_facade_vcpu_get_msrs(
                   &facade, vcpu, output, 2) == 2);
        assert(output[0].data == input[0].data);
        assert(output[1].data == input[1].data);
    }
    {
        edge_kvm_mp_state_t input_state = {
            .mp_state = EDGE_KVM_MP_STATE_HALTED,
        };
        edge_kvm_mp_state_t output_state = {0};
        edge_kvm_vcpu_events_t input_events = {
            .nmi = {.pending = 1},
            .sipi_vector = 0x20,
            .flags = EDGE_KVM_VCPUEVENT_VALID_NMI_PENDING |
                     EDGE_KVM_VCPUEVENT_VALID_SIPI_VECTOR,
        };
        edge_kvm_vcpu_events_t output_events = {0};

        assert(edge_kvm_facade_vcpu_set_mp_state(
                   &facade, vcpu, &input_state) == 0);
        assert(edge_kvm_facade_vcpu_get_mp_state(
                   &facade, vcpu, &output_state) == 0);
        assert(output_state.mp_state == input_state.mp_state);
        assert(edge_kvm_facade_vcpu_set_events(
                   &facade, vcpu, &input_events) == 0);
        assert(edge_kvm_facade_vcpu_get_events(
                   &facade, vcpu, &output_events) == 0);
        assert(memcmp(&output_events, &input_events,
                      sizeof(input_events)) == 0);
    }
    assert(edge_kvm_facade_vcpu_get_tsc_khz(
               &facade, vcpu) == 2900000);
    assert(edge_kvm_facade_vcpu_set_tsc_khz(
               &facade, vcpu, 3000000) == 0);
    assert(state.tsc_frequency_khz == 3000000);
    assert(edge_kvm_facade_vcpu_setup_mce(
               &facade, vcpu, UINT64_C(0x0100010a)) == 0);
    assert(state.mce_capability == UINT64_C(0x0100010a));
    {
        edge_kvm_x86_mce_t machine_check = {
            .status = EDGE_KVM_X86_MCE_STATUS_VALID,
            .miscellaneous = UINT64_C(0xabcdef),
            .bank = 1,
        };
        assert(edge_kvm_facade_vcpu_set_mce(
                   &facade, vcpu, &machine_check) == 0);
        assert(state.machine_check.miscellaneous ==
               machine_check.miscellaneous);
    }
    {
        edge_kvm_cpuid_entry2_t supported = {0};
        edge_kvm_cpuid_entry2_t selected = {
            .function = 1, .eax = 0x5678,
        };
        uint32_t count = 0;
        assert(edge_kvm_facade_get_supported_cpuid(
                   &facade, &supported, 1, &count) == 0);
        assert(count == 1 && supported.eax == 0x1234);
        assert(edge_kvm_facade_vcpu_set_cpuid(
                   &facade, vcpu, &selected, 1) == 0);
        assert(state.cpuid_count == 1 &&
               state.cpuid_entries[0].eax == 0x5678);
        selected.eax = 0;
        assert(edge_kvm_facade_vcpu_get_cpuid(
                   &facade, vcpu, &selected, 1, &count) == 0);
        assert(count == 1 && selected.eax == 0x5678);
    }
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
