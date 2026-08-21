/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS x86 CPU discovery and topology decoding.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#include "arch/x86_64/smp.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/syscall.h"
#include "drivers/acpi.h"
#include "drivers/apic.h"
#include "kernel/arch_cpu.h"
#include "kernel/smp.h"
#include "kernel/timer_policy.h"
#include "sys/boottime.h"
#include "sys/mmio.h"
#include "sys/process.h"
#include "stdio.h"
#include "sys/scheduler.h"

#include <stdint.h>

typedef struct x86_topology_shift {
    uint8_t smt;
    uint8_t core;
} x86_topology_shift_t;

#define X86_AP_MAILBOX_PHYS 0x7000u
#define X86_AP_TRAMPOLINE_PHYS 0x8000u
#define X86_AP_TRAMPOLINE_VECTOR (X86_AP_TRAMPOLINE_PHYS >> 12)

typedef struct x86_ap_mailbox {
    volatile uint64_t cr3;
    volatile uint64_t stack;
    volatile uint64_t entry;
    volatile uint32_t logical_id;
    volatile uint32_t acknowledged;
    volatile uint32_t entered;
} x86_ap_mailbox_t;

extern uint8_t x86_ap_trampoline_start[];
extern uint8_t x86_ap_trampoline_end[];

static volatile x86_ap_mailbox_t *x86_smp_mailbox(void) {
    return (volatile x86_ap_mailbox_t *)
        edge_mmio_low_alias(X86_AP_MAILBOX_PHYS);
}

static void cpuid_count(uint32_t leaf, uint32_t subleaf, uint32_t *a,
                        uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ __volatile__("cpuid"
                         : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                         : "a"(leaf), "c"(subleaf));
}

static x86_topology_shift_t topology_shifts(void) {
    x86_topology_shift_t shifts = {0, 0};
    uint32_t maximum;
    uint32_t unused;
    uint32_t leaf;

    cpuid_count(0, 0, &maximum, &unused, &unused, &unused);
    leaf = maximum >= 0x1fu ? 0x1fu : maximum >= 0xbu ? 0xbu : 0u;
    if (!leaf) return shifts;
    for (uint32_t level = 0; level < 8u; ++level) {
        uint32_t a, b, c, d;
        uint32_t type;

        cpuid_count(leaf, level, &a, &b, &c, &d);
        if ((b & 0xffffu) == 0) break;
        type = (c >> 8) & 0xffu;
        if (type == 1u) shifts.smt = (uint8_t)(a & 0x1fu);
        if (type == 2u) shifts.core = (uint8_t)(a & 0x1fu);
    }
    if (shifts.core < shifts.smt) shifts.core = shifts.smt;
    return shifts;
}

static uint32_t low_mask(uint8_t bits) {
    if (bits == 0) return 0;
    if (bits >= 32u) return UINT32_MAX;
    return (UINT32_C(1) << bits) - 1u;
}

static void decode_topology(uint32_t apic_id, x86_topology_shift_t shifts,
                            uint32_t *package_id, uint32_t *core_id,
                            uint32_t *thread_id) {
    uint8_t core_bits = shifts.core - shifts.smt;

    *thread_id = apic_id & low_mask(shifts.smt);
    *core_id = (apic_id >> shifts.smt) & low_mask(core_bits);
    *package_id = shifts.core >= 32u ? 0u : apic_id >> shifts.core;
}

void x86_smp_discover(void) {
    struct acpi_processor_info boot_information = {0, 0, 0, 0};
    x86_topology_shift_t shifts = topology_shifts();
    uint32_t boot_apic_id = apic_local_id();
    uint32_t package_id;
    uint32_t core_id;
    uint32_t thread_id;
    uint32_t present = acpi_processor_count();

    for (uint32_t index = 0; index < present; ++index) {
        struct acpi_processor_info information;

        if (acpi_get_processor(index, &information) == 0 &&
            information.apic_id == boot_apic_id) {
            boot_information = information;
            break;
        }
    }
    decode_topology(boot_apic_id, shifts, &package_id, &core_id, &thread_id);
    edge_smp_reset(boot_apic_id, boot_information.processor_uid,
                   EDGE_SMP_CAPACITY_SCALE);
    for (uint32_t index = 0; index < present; ++index) {
        struct acpi_processor_info information;

        if (acpi_get_processor(index, &information) != 0 ||
            (information.flags & (EDGE_ACPI_CPU_ENABLED |
                                  EDGE_ACPI_CPU_ONLINE_CAPABLE)) == 0)
            continue;
        decode_topology(information.apic_id, shifts, &package_id, &core_id,
                        &thread_id);
        (void)edge_smp_register_cpu(information.apic_id,
            information.processor_uid, package_id, core_id, thread_id, 0u,
            EDGE_SMP_CAPACITY_SCALE);
    }
    printf("[smp] discovered=%u usable=%u online=%u bsp_apic=%u topology=%u/%u\n",
           present, edge_smp_present_count(), edge_smp_online_count(),
           boot_apic_id, (uint32_t)shifts.smt, (uint32_t)shifts.core);
}

uint32_t x86_smp_current_cpu_id(void) {
    if (edgeos_x86_64_syscall_identity_ready())
        return edgeos_x86_64_syscall_cpu_id();
    int logical_id = edge_smp_find_cpu(apic_local_id());

    return logical_id >= 0 ? (uint32_t)logical_id : 0u;
}

static void x86_smp_ap_entry(uint32_t logical_id) {
    volatile x86_ap_mailbox_t *mailbox = x86_smp_mailbox();

    __atomic_store_n(&mailbox->entered, logical_id + 1u,
                     __ATOMIC_RELEASE);
    /*
     * Install the logical CPU identity before initializing any facility that
     * selects per-CPU storage through scheduler_cpu_id().  In particular,
     * SYSCALL entry programs GS to point at the current CPU's entry record.
     * Initializing it while every AP still reported CPU 0 made user syscalls
     * on secondary CPUs reuse the boot CPU's kernel stack.
     */
    scheduler_set_cpu_id(logical_id);
    gdt_init_cpu(logical_id);
    idt_load();
    (void)apic_init_local();
    edgeos_x86_64_syscall_init_cpu(logical_id);
    gdt_set_tss_rsp0(scheduler_idle_stack_top(logical_id));
    if (apic_timer_init(EDGE_KERNEL_TIMER_HZ) != 0)
        printf("[smp] cpu=%u local timer unavailable\n", logical_id);
    __atomic_store_n(&mailbox->acknowledged, logical_id + 1u,
                     __ATOMIC_RELEASE);
    scheduler_secondary_enter(logical_id);
}

static uint64_t x86_smp_read_tsc(void) {
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
}

static int copy_ap_trampoline(void) {
    uint64_t size = (uint64_t)(x86_ap_trampoline_end -
                               x86_ap_trampoline_start);
    volatile uint8_t *destination =
        (volatile uint8_t *)edge_mmio_low_alias(X86_AP_TRAMPOLINE_PHYS);

    if (size == 0 || size > 4096u) return -1;
    for (uint64_t index = 0; index < size; ++index)
        destination[index] = x86_ap_trampoline_start[index];
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return 0;
}

uint32_t x86_smp_start_secondaries(void) {
    uint32_t started = 0;
    uint32_t nr_cpu_ids = edge_smp_nr_cpu_ids();
    volatile x86_ap_mailbox_t *mailbox = x86_smp_mailbox();

    if (!apic_available() || copy_ap_trampoline() != 0) return 0;
    for (uint32_t logical_id = 1;
         logical_id < nr_cpu_ids && logical_id < SCHED_MAX_CPUS;
         ++logical_id) {
        edge_cpu_topology_t topology;
        uint64_t start;
        uint64_t timeout;

        if (edge_smp_get_cpu(logical_id, &topology) != 0 ||
            edge_smp_set_state(logical_id, EDGE_CPU_STARTING) != 0)
            continue;
        mailbox->cr3 = scheduler_kernel_cr3();
        mailbox->stack = scheduler_idle_stack_top(logical_id);
        mailbox->entry = (uint64_t)(uintptr_t)x86_smp_ap_entry;
        mailbox->logical_id = logical_id;
        __atomic_store_n(&mailbox->acknowledged, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&mailbox->entered, 0u, __ATOMIC_RELEASE);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        __asm__ __volatile__("wbinvd" ::: "memory");
        if (!mailbox->stack ||
            apic_start_processor((uint32_t)topology.hardware_id,
                                 X86_AP_TRAMPOLINE_VECTOR) != 0) {
            (void)edge_smp_set_state(logical_id, EDGE_CPU_FAILED);
            continue;
        }
        timeout = boottime_clocksource_hz() / 2u;
        if (!timeout) timeout = UINT64_MAX;
        start = x86_smp_read_tsc();
        while (__atomic_load_n(&mailbox->acknowledged,
                               __ATOMIC_ACQUIRE) != logical_id + 1u &&
               x86_smp_read_tsc() - start < timeout)
            __asm__ __volatile__("pause");
        if (__atomic_load_n(&mailbox->acknowledged,
                            __ATOMIC_ACQUIRE) == logical_id + 1u) {
            ++started;
            printf("[smp] cpu=%u apic=%u online\n", logical_id,
                   (uint32_t)topology.hardware_id);
        } else {
            (void)edge_smp_set_state(logical_id, EDGE_CPU_FAILED);
            printf("[smp] cpu=%u apic=%u startup timeout entered=%u\n",
                   logical_id, (uint32_t)topology.hardware_id,
                   __atomic_load_n(&mailbox->entered,
                                   __ATOMIC_ACQUIRE));
        }
    }
    printf("[smp] online=%u/%u secondary_started=%u\n",
           edge_smp_online_count(), edge_smp_present_count(), started);
    return started;
}

int arch_smp_send_reschedule(uint32_t logical_id) {
    edge_cpu_topology_t topology;

    if (edge_smp_get_cpu(logical_id, &topology) != 0 ||
        topology.state != EDGE_CPU_ONLINE)
        return -1;
    return apic_send_fixed_ipi((uint32_t)topology.hardware_id,
                               APIC_RESCHEDULE_VECTOR);
}

uint32_t arch_smp_current_cpu(void) {
    return x86_smp_current_cpu_id();
}

int arch_smp_calls_available(void) {
    return apic_available() || edge_smp_online_count() <= 1u;
}

int arch_smp_send_call(uint32_t logical_id) {
    edge_cpu_topology_t topology;

    if (edge_smp_get_cpu(logical_id, &topology) != 0 ||
        topology.state != EDGE_CPU_ONLINE)
        return -1;
    return apic_send_fixed_ipi((uint32_t)topology.hardware_id,
                               APIC_TLB_VECTOR);
}

void arch_smp_execute_call(uint32_t flags) {
    if (flags & EDGE_SMP_CALL_MEMORY_BARRIER)
        arch_cpu_memory_barrier();
    if (flags & EDGE_SMP_CALL_SYNC_CORE)
        arch_cpu_sync_instruction_stream();
    if (flags & EDGE_SMP_CALL_TLB_FLUSH) {
        uint64_t address_space;

        __asm__ __volatile__("mov %%cr3, %0" : "=r"(address_space));
        __asm__ __volatile__("mov %0, %%cr3" :: "r"(address_space) :
                             "memory");
    }
    if (flags & EDGE_SMP_CALL_ARCH_MM_REFRESH)
        process_x86_ldt_activate(process_current_task());
}

void arch_smp_call_relax(void) {
    arch_cpu_relax();
}
