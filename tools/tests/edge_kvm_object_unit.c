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
} test_backend_t;

static int test_get_supported_cpuid(void *opaque,
                                    edge_kvm_cpuid_entry2_t *entries,
                                    uint32_t capacity, uint32_t *count) {
    (void)opaque;
    *count = 1;
    if (capacity != 0)
        entries[0] = (edge_kvm_cpuid_entry2_t) {.function = 1,
                                                .eax = 0x1234};
    return 0;
}

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

static int test_vm_set_address(void *opaque, uint64_t cookie,
                               uint64_t address) {
    (void)opaque;
    assert(cookie != 0 && (address & (EDGE_KVM_PAGE_SIZE - 1)) == 0);
    return 0;
}

static int test_vm_create_irqchip(void *opaque, uint64_t cookie) {
    (void)opaque;
    assert(cookie != 0);
    return 0;
}

static int test_vm_set_gsi_routing(
        void *opaque, uint64_t cookie,
        const edge_kvm_irq_routing_entry_t *entries, uint32_t count) {
    (void)opaque;
    assert(cookie != 0 && (count == 0 || entries != 0));
    return 0;
}

static int test_vm_set_irq_line(void *opaque, uint64_t cookie,
                                edge_kvm_irq_level_t *level) {
    (void)opaque;
    assert(cookie != 0 && level != 0 && level->level <= 1);
    return 0;
}

static int test_vm_get_irqchip(void *opaque, uint64_t cookie,
                               edge_kvm_irqchip_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->irqchip;
    return 0;
}

static int test_vm_set_irqchip(void *opaque, uint64_t cookie,
                               const edge_kvm_irqchip_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->irqchip = *state;
    return 0;
}

static int test_vm_get_pit(void *opaque, uint64_t cookie,
                           edge_kvm_pit_state2_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->pit_state;
    return 0;
}

static int test_vm_set_pit(void *opaque, uint64_t cookie,
                           const edge_kvm_pit_state2_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->pit_state = *state;
    return 0;
}

static int test_vm_create_pit(void *opaque, uint64_t cookie,
                              const edge_kvm_pit_config_t *config) {
    (void)opaque;
    assert(cookie != 0 && config != 0 && config->flags == 0);
    return 0;
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

static int test_vcpu_run(void *opaque, uint64_t cookie,
                         edge_kvm_run_t *run) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && run != 0);
    ++backend->vcpu_runs;
    run->exit_reason = EDGE_KVM_EXIT_HLT;
    return 0;
}

static int test_vcpu_get_regs(void *opaque, uint64_t cookie,
                              edge_kvm_regs_t *registers) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *registers = backend->registers;
    return 0;
}

static int test_vcpu_set_regs(void *opaque, uint64_t cookie,
                              const edge_kvm_regs_t *registers) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->registers = *registers;
    return 0;
}

static int test_vcpu_get_sregs(void *opaque, uint64_t cookie,
                               edge_kvm_sregs_t *registers) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *registers = backend->special_registers;
    return 0;
}

static int test_vcpu_set_sregs(void *opaque, uint64_t cookie,
                               const edge_kvm_sregs_t *registers) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->special_registers = *registers;
    return 0;
}

static int test_vcpu_get_sregs2(void *opaque, uint64_t cookie,
                                edge_kvm_sregs2_t *registers) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *registers = backend->special_registers2;
    return 0;
}

static int test_vcpu_set_sregs2(void *opaque, uint64_t cookie,
                                const edge_kvm_sregs2_t *registers) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->special_registers2 = *registers;
    return 0;
}

static int test_vcpu_get_fpu(void *opaque, uint64_t cookie,
                             edge_kvm_fpu_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->fpu_state;
    return 0;
}

static int test_vcpu_set_fpu(void *opaque, uint64_t cookie,
                             const edge_kvm_fpu_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->fpu_state = *state;
    return 0;
}

static int test_get_msr_index_list(void *opaque, uint32_t *indices,
                                   uint32_t capacity, uint32_t *count) {
    (void)opaque;
    *count = 1;
    if (capacity != 0) indices[0] = 0x10;
    return 0;
}

static int test_vcpu_get_msrs(void *opaque, uint64_t cookie,
                              edge_kvm_msr_entry_t *entries,
                              uint32_t count) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && count <= backend->msr_count);
    for (uint32_t index = 0; index < count; ++index)
        entries[index].data = backend->msrs[index].data;
    return (int)count;
}

static int test_vcpu_set_msrs(void *opaque, uint64_t cookie,
                              const edge_kvm_msr_entry_t *entries,
                              uint32_t count) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && count <= 4);
    if (count != 0) memcpy(backend->msrs, entries,
                           count * sizeof(entries[0]));
    backend->msr_count = count;
    return (int)count;
}

static int test_vcpu_get_mp_state(void *opaque, uint64_t cookie,
                                  edge_kvm_mp_state_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->mp_state;
    return 0;
}

static int test_vcpu_set_mp_state(void *opaque, uint64_t cookie,
                                  const edge_kvm_mp_state_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->mp_state = *state;
    return 0;
}

static int test_vcpu_get_lapic(void *opaque, uint64_t cookie,
                               edge_kvm_lapic_state_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->lapic_state;
    return 0;
}

static int test_vcpu_set_lapic(void *opaque, uint64_t cookie,
                               const edge_kvm_lapic_state_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->lapic_state = *state;
    return 0;
}

static int test_vcpu_get_debugregs(void *opaque, uint64_t cookie,
                                   edge_kvm_debugregs_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->debug_registers;
    return 0;
}

static int test_vcpu_set_debugregs(void *opaque, uint64_t cookie,
                                   const edge_kvm_debugregs_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->debug_registers = *state;
    return 0;
}

static int test_vcpu_set_guest_debug(
    void *opaque, uint64_t cookie,
    const edge_kvm_guest_debug_x86_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->guest_debug = *state;
    return 0;
}

static int test_vcpu_get_xcrs(void *opaque, uint64_t cookie,
                              edge_kvm_xcrs_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->xcrs;
    return 0;
}

static int test_vcpu_set_xcrs(void *opaque, uint64_t cookie,
                              const edge_kvm_xcrs_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->xcrs = *state;
    return 0;
}

static int test_vcpu_get_xsave(void *opaque, uint64_t cookie,
                               edge_kvm_xsave_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *state = backend->xsave;
    return 0;
}

static int test_vcpu_set_xsave(void *opaque, uint64_t cookie,
                               const edge_kvm_xsave_t *state) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->xsave = *state;
    return 0;
}

static int test_vcpu_get_events(void *opaque, uint64_t cookie,
                                edge_kvm_vcpu_events_t *events) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    *events = backend->events;
    return 0;
}

static int test_vcpu_set_events(void *opaque, uint64_t cookie,
                                const edge_kvm_vcpu_events_t *events) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->events = *events;
    return 0;
}

static int64_t test_vcpu_get_tsc_khz(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    return backend->tsc_frequency_khz;
}

static int test_vcpu_set_tsc_khz(void *opaque, uint64_t cookie,
                                 uint32_t frequency_khz) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->tsc_frequency_khz = frequency_khz;
    return 0;
}

static int test_vcpu_setup_mce(void *opaque, uint64_t cookie,
                               uint64_t capability) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->mce_capability = capability;
    return 0;
}

static int test_vcpu_set_mce(void *opaque, uint64_t cookie,
                             const edge_kvm_x86_mce_t *machine_check) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    backend->machine_check = *machine_check;
    return 0;
}

static int test_vcpu_set_cpuid(void *opaque, uint64_t cookie,
                               const edge_kvm_cpuid_entry2_t *entries,
                               uint32_t count) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && count <= 4);
    if (count != 0) memcpy(backend->cpuid_entries, entries,
                           count * sizeof(entries[0]));
    backend->cpuid_count = count;
    return 0;
}

static int test_vcpu_get_cpuid(void *opaque, uint64_t cookie,
                               edge_kvm_cpuid_entry2_t *entries,
                               uint32_t capacity, uint32_t *count) {
    test_backend_t *backend = opaque;
    uint32_t copied;

    assert(cookie != 0 && count != 0);
    *count = backend->cpuid_count;
    copied = capacity < backend->cpuid_count ? capacity : backend->cpuid_count;
    if (copied != 0)
        memcpy(entries, backend->cpuid_entries,
               copied * sizeof(entries[0]));
    return 0;
}

static int test_vcpu_mmap_page(void *opaque, uint64_t cookie,
                               uint32_t page_index, uint64_t *physical) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    if (page_index >= EDGE_KVM_VCPU_MMAP_PAGES || !physical)
        return -EDGE_LINUX_EINVAL;
    *physical = (uint64_t)(uintptr_t)backend->run_pages[page_index];
    return 0;
}

static int test_memory_region_set(
        void *opaque, uint64_t vm_cookie,
        const edge_kvm_memory_region_t *region) {
    test_backend_t *backend = opaque;
    assert(vm_cookie != 0 && region != 0);
    ++backend->memory_updates;
    return backend->fail_memory_update ? -EDGE_LINUX_EIO : 0;
}

static int test_memory_dirty_log_get(
        void *opaque, uint64_t vm_cookie, uint32_t slot,
        uint32_t first_page, uint32_t page_count, uint64_t *bitmap,
        uint32_t bitmap_words, uint8_t clear) {
    (void)opaque;
    assert(vm_cookie != 0 && slot == 0 && first_page == 0);
    assert(page_count == 512 && bitmap_words == 8);
    assert(clear <= 1u);
    memset(bitmap, 0, (size_t)bitmap_words * sizeof(bitmap[0]));
    bitmap[0] = UINT64_C(0x5);
    return 0;
}

static int test_memory_dirty_log_clear(
        void *opaque, uint64_t vm_cookie, uint32_t slot,
        uint32_t first_page, uint32_t page_count,
        const uint64_t *bitmap, uint32_t bitmap_words) {
    (void)opaque;
    assert(vm_cookie != 0 && slot == 0 && first_page == 0);
    assert(page_count == 512 && bitmap_words == 8 && bitmap != 0);
    return 0;
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
    backend_state.tsc_frequency_khz = UINT32_C(2900000);
    backend = (edge_kvm_backend_ops_t) {
        .context = &backend_state,
        .get_supported_cpuid = test_get_supported_cpuid,
        .get_msr_index_list = test_get_msr_index_list,
        .vm_create = test_vm_create,
        .vm_destroy = test_vm_destroy,
        .vm_set_tss_address = test_vm_set_address,
        .vm_set_identity_map_address = test_vm_set_address,
        .vm_create_irqchip = test_vm_create_irqchip,
        .vm_set_gsi_routing = test_vm_set_gsi_routing,
        .vm_set_irq_line = test_vm_set_irq_line,
        .vm_get_irqchip = test_vm_get_irqchip,
        .vm_set_irqchip = test_vm_set_irqchip,
        .vm_create_pit = test_vm_create_pit,
        .vm_get_pit = test_vm_get_pit,
        .vm_set_pit = test_vm_set_pit,
        .vcpu_create = test_vcpu_create,
        .vcpu_destroy = test_vcpu_destroy,
        .vcpu_run = test_vcpu_run,
        .vcpu_get_regs = test_vcpu_get_regs,
        .vcpu_set_regs = test_vcpu_set_regs,
        .vcpu_get_sregs = test_vcpu_get_sregs,
        .vcpu_set_sregs = test_vcpu_set_sregs,
        .vcpu_get_sregs2 = test_vcpu_get_sregs2,
        .vcpu_set_sregs2 = test_vcpu_set_sregs2,
        .vcpu_get_fpu = test_vcpu_get_fpu,
        .vcpu_set_fpu = test_vcpu_set_fpu,
        .vcpu_get_lapic = test_vcpu_get_lapic,
        .vcpu_set_lapic = test_vcpu_set_lapic,
        .vcpu_get_debugregs = test_vcpu_get_debugregs,
        .vcpu_set_debugregs = test_vcpu_set_debugregs,
        .vcpu_set_guest_debug = test_vcpu_set_guest_debug,
        .vcpu_get_xcrs = test_vcpu_get_xcrs,
        .vcpu_set_xcrs = test_vcpu_set_xcrs,
        .vcpu_get_xsave = test_vcpu_get_xsave,
        .vcpu_set_xsave = test_vcpu_set_xsave,
        .vcpu_get_msrs = test_vcpu_get_msrs,
        .vcpu_set_msrs = test_vcpu_set_msrs,
        .vcpu_get_mp_state = test_vcpu_get_mp_state,
        .vcpu_set_mp_state = test_vcpu_set_mp_state,
        .vcpu_get_events = test_vcpu_get_events,
        .vcpu_set_events = test_vcpu_set_events,
        .vcpu_get_tsc_khz = test_vcpu_get_tsc_khz,
        .vcpu_set_tsc_khz = test_vcpu_set_tsc_khz,
        .vcpu_setup_mce = test_vcpu_setup_mce,
        .vcpu_set_mce = test_vcpu_set_mce,
        .vcpu_set_cpuid = test_vcpu_set_cpuid,
        .vcpu_get_cpuid = test_vcpu_get_cpuid,
        .vcpu_mmap_page = test_vcpu_mmap_page,
        .memory_region_set = test_memory_region_set,
        .memory_dirty_log_get = test_memory_dirty_log_get,
        .memory_dirty_log_clear = test_memory_dirty_log_clear,
    };
    assert(edge_kvm_object_table_init(&table, &backend) == 0);
    assert(edge_kvm_vm_create(&table, 0, &vm) == 0);
    stale_vm = vm;
    assert(table.active_vm_count == 1 && backend_state.created_vms == 1);
    assert(edge_kvm_vm_retain(&table, vm) == 0);
    assert(edge_kvm_vm_snapshot(&table, vm, &vm_snapshot) == 0);
    assert(vm_snapshot.descriptor_references == 2);
    {
        edge_kvm_pit_config_t pit = {0};

        assert(edge_kvm_vm_set_tss_address(
                   &table, vm, 0xfeffd000u) == 0);
        assert(edge_kvm_vm_set_identity_map_address(
                   &table, vm, 0xfeffc000u) == 0);
        assert(edge_kvm_vm_create_irqchip(&table, vm) == 0);
        assert(edge_kvm_vm_create_pit(&table, vm, &pit) == 0);
    }

    region = (edge_kvm_memory_region_t) {
        .slot = 0,
        .flags = EDGE_KVM_MEMORY_LOG_DIRTY_PAGES,
        .guest_physical_address = 0x100000,
        .memory_size = 0x200000,
        .userspace_address = 0x40000000,
    };
    assert(edge_kvm_vm_set_memory_region(&table, vm, &region) == 0);
    {
        uint64_t bitmap[8];
        uint32_t pages = 0;

        assert(edge_kvm_vm_dirty_log_page_count(
                   &table, vm, 0, &pages) == 0);
        assert(pages == 512);
        assert(edge_kvm_vm_get_dirty_log(
                   &table, vm, 0, 0, pages, bitmap, 8) == 0);
        assert(bitmap[0] == UINT64_C(0x5));
    }
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
    assert(edge_kvm_vcpu_run(&table, vcpu) == 0);
    assert(backend_state.vcpu_runs == 1);
    assert(((edge_kvm_run_t *)backend_state.run_pages[0])->exit_reason ==
           EDGE_KVM_EXIT_HLT);
    {
        edge_kvm_guest_debug_x86_t debug = {
            .control = EDGE_KVM_GUESTDBG_ENABLE |
                       EDGE_KVM_GUESTDBG_SINGLESTEP,
        };

        assert(edge_kvm_vcpu_set_guest_debug(&table, vcpu, &debug) == 0);
        assert(backend_state.guest_debug.control == debug.control);
        debug.padding = 1;
        assert(edge_kvm_vcpu_set_guest_debug(&table, vcpu, &debug) ==
               -EDGE_LINUX_EINVAL);
    }
    {
        edge_kvm_fpu_t input = {
            .fcw = 0x027f,
            .ftwx = 0xff,
            .last_opcode = 0x0321,
            .last_ip = 0x123456789abcdef0ull,
            .last_dp = 0x0fedcba987654321ull,
            .mxcsr = 0x1f80,
        };
        edge_kvm_fpu_t output = {0};
        input.fpr[0][0] = 0xa5;
        input.xmm[3][7] = 0x5a;
        assert(edge_kvm_vcpu_set_fpu(&table, vcpu, &input) == 0);
        assert(edge_kvm_vcpu_get_fpu(&table, vcpu, &output) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_sregs2_t input = {
            .cr0 = UINT64_C(0x80000001),
            .cr3 = UINT64_C(0x2000),
            .cr4 = UINT64_C(0x20),
            .flags = EDGE_KVM_SREGS2_PDPTRS_VALID,
            .pdptrs = {0x67, 0x1067, 0x2067, 0x3067},
        };
        edge_kvm_sregs2_t output = {0};
        assert(edge_kvm_vcpu_set_sregs2(&table, vcpu, &input) == 0);
        assert(edge_kvm_vcpu_get_sregs2(&table, vcpu, &output) == 0);
        assert(memcmp(&output, &input, sizeof(input)) == 0);
    }
    {
        edge_kvm_lapic_state_t input = {0};
        edge_kvm_lapic_state_t output = {0};
        input.registers[0x80] = 0x50;
        input.registers[0xf0] = 0xff;
        assert(edge_kvm_vcpu_set_lapic(&table, vcpu, &input) == 0);
        assert(edge_kvm_vcpu_get_lapic(&table, vcpu, &output) == 0);
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

        assert(edge_kvm_get_msr_index_list(
                   &table, indices, 1, &count) == 0);
        assert(count == 1 && indices[0] == 0x10u);
        assert(edge_kvm_vcpu_set_msrs(&table, vcpu, input, 2) == 2);
        assert(edge_kvm_vcpu_get_msrs(&table, vcpu, output, 2) == 2);
        assert(output[0].data == input[0].data);
        assert(output[1].data == input[1].data);
    }
    {
        edge_kvm_mp_state_t input_state = {
            .mp_state = EDGE_KVM_MP_STATE_HALTED,
        };
        edge_kvm_mp_state_t output_state = {0};
        edge_kvm_vcpu_events_t input_events = {
            .exception = {
                .injected = 1, .number = 14,
                .has_error_code = 1, .error_code = 5,
            },
            .sipi_vector = 0x10,
            .flags = EDGE_KVM_VCPUEVENT_VALID_SIPI_VECTOR |
                     EDGE_KVM_VCPUEVENT_VALID_PAYLOAD,
            .exception_has_payload = 1,
            .exception_payload = 0x12345000,
        };
        edge_kvm_vcpu_events_t output_events = {0};

        assert(edge_kvm_vcpu_set_mp_state(
                   &table, vcpu, &input_state) == 0);
        assert(edge_kvm_vcpu_get_mp_state(
                   &table, vcpu, &output_state) == 0);
        assert(output_state.mp_state == input_state.mp_state);
        assert(edge_kvm_vcpu_set_events(
                   &table, vcpu, &input_events) == 0);
        assert(edge_kvm_vcpu_get_events(
                   &table, vcpu, &output_events) == 0);
        assert(memcmp(&output_events, &input_events,
                      sizeof(input_events)) == 0);
    }
    assert(edge_kvm_vcpu_get_tsc_khz(&table, vcpu) == 2900000);
    assert(edge_kvm_vcpu_set_tsc_khz(&table, vcpu, 3000000) == 0);
    assert(backend_state.tsc_frequency_khz == 3000000);
    assert(edge_kvm_vcpu_setup_mce(
               &table, vcpu, UINT64_C(0x0100010a)) == 0);
    assert(backend_state.mce_capability == UINT64_C(0x0100010a));
    assert(edge_kvm_vcpu_setup_mce(&table, vcpu, 0) ==
           -EDGE_LINUX_EINVAL);
    {
        edge_kvm_x86_mce_t machine_check = {
            .status = EDGE_KVM_X86_MCE_STATUS_VALID,
            .address = UINT64_C(0x12345000),
            .bank = 2,
        };
        assert(edge_kvm_vcpu_set_mce(
                   &table, vcpu, &machine_check) == 0);
        assert(backend_state.machine_check.address == machine_check.address);
        machine_check.status = 0;
        assert(edge_kvm_vcpu_set_mce(
                   &table, vcpu, &machine_check) == -EDGE_LINUX_EINVAL);
    }
    {
        edge_kvm_cpuid_entry2_t supported = {0};
        edge_kvm_cpuid_entry2_t selected = {
            .function = 1, .eax = 0x5678,
        };
        uint32_t count = 0;
        assert(edge_kvm_get_supported_cpuid(
                   &table, &supported, 1, &count) == 0);
        assert(count == 1 && supported.eax == 0x1234);
        assert(edge_kvm_vcpu_set_cpuid(
                   &table, vcpu, &selected, 1) == 0);
        assert(backend_state.cpuid_count == 1 &&
               backend_state.cpuid_entries[0].eax == 0x5678);
        selected.eax = 0;
        assert(edge_kvm_vcpu_get_cpuid(
                   &table, vcpu, &selected, 1, &count) == 0);
        assert(count == 1 && selected.eax == 0x5678);
    }

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
