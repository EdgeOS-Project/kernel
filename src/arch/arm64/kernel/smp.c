/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 PSCI secondary CPU bring-up.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "arch/arm64/interrupt.h"
#include "arch/arm64/platform.h"
#include "arch/arm64/smp.h"
#include "arch/arm64/vm.h"
#include "kernel/smp.h"

#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
#include "compat/freebsd/edgeos/ofw.h"
#define EDGEOS_ARM64_SMP_FDT 1
#endif

/*
 * Secondary CPUs execute the same VFS, process, and device paths as the boot
 * CPU. Keep their EL1 stacks at the boot CPU's 64 KiB size so a nested IRQ on
 * a deep filesystem operation cannot exhaust a smaller secondary stack.
 */
#define ARM64_SECONDARY_STACK_PAGES 16u
#define PSCI_0_2_FN64_CPU_ON 0xc4000003u
#define PSCI_SUCCESS 0
#define ARM64_RESCHEDULE_SGI 1u
#define ARM64_CALL_SGI 2u

enum arm64_cpu_boot_method {
    ARM64_CPU_BOOT_NONE = 0,
    ARM64_CPU_BOOT_PSCI,
    ARM64_CPU_BOOT_SPIN_TABLE,
};

extern void edgeos_arm64_secondary_entry(void);
extern void edgeos_arm64_spin_table_entry(void);

uint64_t edgeos_arm64_secondary_mair;
uint64_t edgeos_arm64_secondary_tcr;
uint64_t edgeos_arm64_secondary_ttbr0;
uint64_t edgeos_arm64_secondary_sctlr;
uint64_t edgeos_arm64_secondary_cpacr;
uint64_t edgeos_arm64_secondary_stack_top[EDGE_SMP_MAX_CPUS];

static int g_psci_use_hvc = 1;
static int g_psci_available;
static uint8_t g_cpu_boot_method[EDGE_SMP_MAX_CPUS];
static uint64_t g_cpu_release_address[EDGE_SMP_MAX_CPUS];
static volatile uint32_t g_reschedule_pending[EDGE_SMP_MAX_CPUS];

static void smp_serial_puts(const char *text) {
    while (text && *text) edgeos_arm64_platform_serial_write(*text++);
}

static void smp_serial_hex64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";

    smp_serial_puts("0x");
    for (int shift = 60; shift >= 0; shift -= 4)
        edgeos_arm64_platform_serial_write(
            digits[(value >> (uint32_t)shift) & 0xfu]);
}

static int text_equal(const char *left, const char *right) {
    if (!left || !right) return 0;
    while (*left && *right) {
        if (*left++ != *right++) return 0;
    }
    return *left == 0 && *right == 0;
}

static uint64_t current_mpidr(void) {
    uint64_t mpidr;

    __asm__ __volatile__("mrs %0, mpidr_el1" : "=r"(mpidr));
    return mpidr & 0xff00ffffffULL;
}

#ifdef EDGEOS_ARM64_SMP_FDT
static int discover_psci_conduit(void) {
    phandle_t node;
    char method[8] = {0};

    node = bsd_ofw_fdt_find_compatible("arm,psci-1.0", 0);
    if (!node)
        node = bsd_ofw_fdt_find_compatible("arm,psci-0.2", 0);
    if (!node)
        node = bsd_ofw_fdt_find_compatible("arm,psci", 0);
    if (!node || OF_getprop(node, "method", method, sizeof(method) - 1u) <= 0)
        return -1;
    if (text_equal(method, "hvc")) {
        g_psci_use_hvc = 1;
        return 0;
    }
    if (text_equal(method, "smc")) {
        g_psci_use_hvc = 0;
        return 0;
    }
    return -1;
}

static int discover_fdt_cpus(void) {
    phandle_t cpus = OF_finddevice("/cpus");
    pcell_t address_cells = 1;
    uint32_t firmware_id = 0;

    if (!cpus) return -1;
    (void)OF_getencprop(cpus, "#address-cells", &address_cells,
                        sizeof(address_cells));
    if (address_cells == 0 || address_cells > 2) return -1;

    for (phandle_t node = OF_child(cpus); node; node = OF_peer(node)) {
        char device_type[8] = {0};
        char status[16] = {0};
        pcell_t reg[2] = {0, 0};
        uint64_t mpidr = 0;
        uint64_t release_address = 0;
        uint32_t package_id;
        uint32_t core_id;
        char enable_method[24] = {0};
        pcell_t release_cells[2] = {0, 0};
        int logical_id;

        if (OF_getprop(node, "device_type", device_type,
                       sizeof(device_type) - 1u) <= 0 ||
            !text_equal(device_type, "cpu"))
            continue;
        if (OF_getprop(node, "status", status, sizeof(status) - 1u) > 0 &&
            text_equal(status, "disabled"))
            continue;
        if (OF_getencprop(node, "reg", reg,
                          address_cells * sizeof(reg[0])) !=
            (long)(address_cells * sizeof(reg[0])))
            continue;
        for (uint32_t cell = 0; cell < address_cells; ++cell)
            mpidr = (mpidr << 32) | reg[cell];
        mpidr &= 0xff00ffffffULL;
        package_id = (uint32_t)((mpidr >> 32) & 0xffu);
        core_id = ((uint32_t)((mpidr >> 16) & 0xffu) << 16) |
                  ((uint32_t)((mpidr >> 8) & 0xffu) << 8) |
                  (uint32_t)(mpidr & 0xffu);
        logical_id = edge_smp_register_cpu(
            mpidr, firmware_id++, package_id, core_id, 0, 0,
            EDGE_SMP_CAPACITY_SCALE);
        if (logical_id < 0)
            return -1;
        if (OF_getprop(node, "enable-method", enable_method,
                       sizeof(enable_method) - 1u) > 0 &&
            text_equal(enable_method, "spin-table") &&
            OF_getencprop(node, "cpu-release-addr", release_cells,
                          sizeof(release_cells)) ==
                (long)sizeof(release_cells)) {
            release_address = ((uint64_t)release_cells[0] << 32) |
                              release_cells[1];
            if (release_address != 0) {
                g_cpu_boot_method[logical_id] = ARM64_CPU_BOOT_SPIN_TABLE;
                g_cpu_release_address[logical_id] = release_address;
            }
        } else if (g_psci_available) {
            g_cpu_boot_method[logical_id] = ARM64_CPU_BOOT_PSCI;
        }
    }
    return edge_smp_present_count() ? 0 : -1;
}
#endif

int edgeos_arm64_smp_discover(const edgeos_arm64_bootinfo_t *bootinfo) {
    (void)bootinfo;
    for (uint32_t cpu = 0; cpu < EDGE_SMP_MAX_CPUS; ++cpu)
        __atomic_store_n(&g_reschedule_pending[cpu], 0u,
                         __ATOMIC_RELAXED);
    for (uint32_t cpu = 0; cpu < EDGE_SMP_MAX_CPUS; ++cpu) {
        g_cpu_boot_method[cpu] = ARM64_CPU_BOOT_NONE;
        g_cpu_release_address[cpu] = 0;
    }
    edge_smp_reset(current_mpidr(), 0, EDGE_SMP_CAPACITY_SCALE);
#ifdef EDGEOS_ARM64_SMP_FDT
    g_psci_available = discover_psci_conduit() == 0;
    if (g_psci_available)
        g_cpu_boot_method[0] = ARM64_CPU_BOOT_PSCI;
    return discover_fdt_cpus();
#else
    return -1;
#endif
}

static int64_t psci_cpu_on(uint64_t mpidr, uint64_t entry,
                           uint64_t logical_id) {
    register uint64_t x0 __asm("x0") = PSCI_0_2_FN64_CPU_ON;
    register uint64_t x1 __asm("x1") = mpidr;
    register uint64_t x2 __asm("x2") = entry;
    register uint64_t x3 __asm("x3") = logical_id;

    if (g_psci_use_hvc) {
        __asm__ __volatile__("hvc #0"
            : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3) :: "memory");
    } else {
        __asm__ __volatile__("smc #0"
            : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3) :: "memory");
    }
    return (int64_t)x0;
}

static int spin_table_cpu_on(uint64_t release_address) {
    volatile uint64_t *release;
    uint64_t entry;

    if (!release_address || (release_address & 7u)) return -1;
    release = (volatile uint64_t *)(uintptr_t)release_address;
    entry = (uint64_t)(uintptr_t)edgeos_arm64_spin_table_entry;
    smp_serial_puts("arm64: releasing spin-table CPU mailbox=");
    smp_serial_hex64(release_address);
    smp_serial_puts(" entry=");
    smp_serial_hex64(entry);
    smp_serial_puts("\n");
    *release = entry;
    __asm__ __volatile__("dc cvac, %0\n\tdsb sy\n\tsev"
                         :: "r"(release) : "memory");
    return 0;
}

int edgeos_arm64_smp_start_secondary_cpus(void) {
    uint32_t failures = 0;

    __asm__ __volatile__("mrs %0, mair_el1" : "=r"(edgeos_arm64_secondary_mair));
    __asm__ __volatile__("mrs %0, tcr_el1" : "=r"(edgeos_arm64_secondary_tcr));
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(edgeos_arm64_secondary_ttbr0));
    __asm__ __volatile__("mrs %0, sctlr_el1" : "=r"(edgeos_arm64_secondary_sctlr));
    __asm__ __volatile__("mrs %0, cpacr_el1" : "=r"(edgeos_arm64_secondary_cpacr));

    for (uint32_t cpu = 1; cpu < edge_smp_nr_cpu_ids(); ++cpu) {
        edge_cpu_topology_t topology;
        void *stack;
        uint32_t spins;

        if (edge_smp_get_cpu(cpu, &topology) != 0) {
            ++failures;
            continue;
        }
        stack = edgeos_arm64_early_alloc_pages(ARM64_SECONDARY_STACK_PAGES);
        if (!stack) {
            ++failures;
            continue;
        }
        edgeos_arm64_secondary_stack_top[cpu] =
            (uint64_t)(uintptr_t)stack + ARM64_SECONDARY_STACK_PAGES * 4096u;
        __asm__ __volatile__("dsb ishst" ::: "memory");
        if (edge_smp_set_state(cpu, EDGE_CPU_STARTING) != 0 ||
            (g_cpu_boot_method[cpu] == ARM64_CPU_BOOT_PSCI &&
             psci_cpu_on(topology.hardware_id,
                 (uint64_t)(uintptr_t)edgeos_arm64_secondary_entry, cpu) !=
                 PSCI_SUCCESS) ||
            (g_cpu_boot_method[cpu] == ARM64_CPU_BOOT_SPIN_TABLE &&
             spin_table_cpu_on(g_cpu_release_address[cpu]) != 0) ||
            g_cpu_boot_method[cpu] == ARM64_CPU_BOOT_NONE) {
            (void)edge_smp_set_state(cpu, EDGE_CPU_FAILED);
            ++failures;
            continue;
        }
        __asm__ __volatile__("dsb ishst\n\tsev" ::: "memory");
        for (spins = 0; spins < 10000000u; ++spins) {
            if (edge_smp_cpu_state(cpu) == EDGE_CPU_ONLINE) break;
            __asm__ __volatile__("yield");
        }
        if (edge_smp_cpu_state(cpu) != EDGE_CPU_ONLINE) {
            (void)edge_smp_set_state(cpu, EDGE_CPU_FAILED);
            ++failures;
        }
    }
    return failures ? -1 : 0;
}

uint32_t edgeos_arm64_smp_current_cpu(void) {
    int cpu = edge_smp_find_cpu(current_mpidr());

    return cpu < 0 ? 0u : (uint32_t)cpu;
}

uint64_t edgeos_arm64_smp_current_hardware_id(void) {
    return current_mpidr();
}

void edgeos_arm64_secondary_main(uint64_t logical_id) {
    smp_serial_puts("arm64: secondary CPU entered logical-id=");
    smp_serial_hex64(logical_id);
    smp_serial_puts("\n");
    edgeos_arm64_exceptions_init();
    if (logical_id >= edge_smp_nr_cpu_ids() ||
        edgeos_arm64_irq_init_secondary() < 0) {
        for (;;) __asm__ __volatile__("wfe");
    }
    edgeos_arm64_scheduler_secondary_prepare(
        (uint32_t)logical_id,
        edgeos_arm64_secondary_stack_top[logical_id]);
    if (edge_smp_set_state((uint32_t)logical_id, EDGE_CPU_ONLINE) != 0) {
        for (;;) __asm__ __volatile__("wfe");
    }
    __asm__ __volatile__("dsb ishst\n\tsev\n\tmsr daifclr, #2" ::: "memory");
    edgeos_arm64_scheduler_secondary_enter((uint32_t)logical_id);
}

static int arm64_send_sgi(uint32_t logical_id, uint32_t interrupt_id) {
    edge_cpu_topology_t topology;

    if (edge_smp_get_cpu(logical_id, &topology) != 0 ||
        topology.state != EDGE_CPU_ONLINE)
        return -1;
    return edgeos_arm64_gic_send_sgi(
        topology.hardware_id, interrupt_id);
}

int arch_smp_send_reschedule(uint32_t logical_id) {
    int result;

    if (logical_id >= EDGE_SMP_MAX_CPUS) return -1;
    __atomic_store_n(&g_reschedule_pending[logical_id], 1u,
                     __ATOMIC_RELEASE);
    result = arm64_send_sgi(logical_id, ARM64_RESCHEDULE_SGI);
    if (result < 0)
        __atomic_store_n(&g_reschedule_pending[logical_id], 0u,
                         __ATOMIC_RELEASE);
    return result;
}

void edgeos_arm64_smp_idle_prepare(void) {
    uint32_t cpu = edgeos_arm64_smp_current_cpu();

    if (cpu < EDGE_SMP_MAX_CPUS) {
        __atomic_store_n(&g_reschedule_pending[cpu], 0u,
                         __ATOMIC_RELEASE);
        edgeos_arm64_timer_enter_idle();
    }
}

void edgeos_arm64_smp_idle_irq_window(void) {
    uint32_t cpu = edgeos_arm64_smp_current_cpu();

    __asm__ __volatile__("msr daifclr, #2\n\tdmb ish" ::: "memory");
    if (cpu >= EDGE_SMP_MAX_CPUS ||
        !__atomic_load_n(&g_reschedule_pending[cpu], __ATOMIC_ACQUIRE))
        __asm__ __volatile__("wfi" ::: "memory");
    __asm__ __volatile__("msr daifset, #2" ::: "memory");
}

uint32_t arch_smp_current_cpu(void) {
    return edgeos_arm64_smp_current_cpu();
}

int arch_smp_calls_available(void) {
    return 1;
}

int arch_smp_send_call(uint32_t logical_id) {
    return arm64_send_sgi(logical_id, ARM64_CALL_SGI);
}

void arch_smp_execute_call(uint32_t flags) {
    if (flags & EDGE_SMP_CALL_MEMORY_BARRIER)
        __asm__ __volatile__("dmb ish" ::: "memory");
    if (flags & EDGE_SMP_CALL_SYNC_CORE)
        __asm__ __volatile__("dsb ish\n\tisb" ::: "memory");
    if (flags & EDGE_SMP_CALL_TLB_FLUSH)
        __asm__ __volatile__("dsb ishst\n\ttlbi vmalle1is\n\tdsb ish\n\tisb"
                             ::: "memory");
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

void arch_smp_call_relax(void) {
    __asm__ __volatile__("yield" ::: "memory");
}
