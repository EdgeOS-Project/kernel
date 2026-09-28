#include "kernel/wait_runtime.h"
/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS x86 APIC/MSI support.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This is original EdgeOS code informed by Intel xAPIC/MSI architectural
 * documentation and ACPI MADT data.  FreeBSD's APIC implementation was used as
 * a high-level design reference for table-driven discovery, but this file is
 * not a port of that code.
 */

#include "drivers/apic.h"
#include "drivers/acpi.h"
#include "drivers/pci.h"
#include "arch/x86_64/smp.h"
#include "kernel/smp.h"
#include "kernel/timer_policy.h"
#include "kernel/timer_alarm.h"
#include "kernel/deferred_work.h"
#include "sys/boottime.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define IA32_APIC_BASE_MSR   0x1Bu
#define APIC_BASE_ENABLE     (1ULL << 11)
#define APIC_BASE_X2APIC     (1ULL << 10)
#define X2APIC_MSR_BASE      0x800u
#define APIC_REG_ID          0x020u
#define APIC_REG_VERSION     0x030u
#define APIC_REG_EOI         0x0B0u
#define APIC_REG_SVR         0x0F0u
#define APIC_REG_ICR_LOW     0x300u
#define APIC_REG_ICR_HIGH    0x310u
#define APIC_REG_LVT_TIMER   0x320u
#define APIC_REG_LVT_PCINT   0x340u
#define APIC_REG_TIMER_INITIAL 0x380u
#define APIC_REG_TIMER_CURRENT 0x390u
#define APIC_REG_TIMER_DIVIDE  0x3E0u
#define APIC_SVR_ENABLE      0x00000100u
#define APIC_SPURIOUS_VECTOR 0xFFu
#define APIC_LVT_DELIVERY_MASK 0x00000700u
#define APIC_LVT_DELIVERY_NMI  0x00000400u
#define APIC_LVT_MASKED        0x00010000u
#define APIC_LVT_TIMER_PERIODIC 0x00020000u
#define APIC_ICR_DELIVERY_STATUS 0x00001000u
#define APIC_ICR_LEVEL_ASSERT    0x00004000u
#define APIC_ICR_TRIGGER_LEVEL   0x00008000u
#define APIC_ICR_DELIVERY_INIT   0x00000500u
#define APIC_ICR_DELIVERY_STARTUP 0x00000600u

#define MSI_VECTOR_FIRST 48u
#define MSI_VECTOR_LAST  63u
#define MSI_ADDR_BASE    0xFEE00000u

#define PCI_COMMAND_INTX_DISABLE 0x0400u
#define PCI_CAP_MSI_CTRL        0x02u
#define PCI_CAP_MSI_ADDR_LO     0x04u
#define PCI_CAP_MSI_ADDR_HI     0x08u
#define PCI_CAP_MSI_DATA_32     0x08u
#define PCI_CAP_MSI_DATA_64     0x0Cu
#define PCI_MSI_CTRL_ENABLE     0x0001u
#define PCI_MSI_CTRL_64BIT      0x0080u

#define PCI_MSIX_CTRL           0x02u
#define PCI_MSIX_TABLE          0x04u
#define PCI_MSIX_PBA            0x08u
#define PCI_MSIX_CTRL_ENABLE    0x8000u
#define PCI_MSIX_CTRL_MASKALL   0x4000u
#define PCI_MSIX_BIR_MASK       0x7u
#define PCI_MSIX_OFFSET_MASK    0xFFFFFFF8u
#define PCI_MSIX_ENTRY_SIZE     16u

static volatile uint32_t *g_lapic;
static uint32_t g_lapic_id;
static uint8_t g_x2apic_enabled;
static uint16_t g_allocated_vectors;
static volatile uint32_t g_performance_interrupt_users;
static kernel_timer_alarm_t g_apic_alarms[EDGE_SMP_MAX_CPUS];
static uint64_t g_apic_timer_frequency[EDGE_SMP_MAX_CPUS];
static uint32_t g_apic_timer_initial[EDGE_SMP_MAX_CPUS];
static uint32_t g_apic_timer_lvt[EDGE_SMP_MAX_CPUS];
static uint8_t g_apic_timer_ready[EDGE_SMP_MAX_CPUS];
static uint8_t g_apic_timer_highres[EDGE_SMP_MAX_CPUS];
static uint8_t g_apic_timer_lvt_valid[EDGE_SMP_MAX_CPUS];

static uint64_t apic_read_tsc(void) {
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
}

static void apic_delay_us(uint64_t delay) {
    uint64_t frequency = boottime_clocksource_hz();
    uint64_t start;
    uint64_t ticks;

    if (!frequency) {
        for (volatile uint64_t spin = 0; spin < delay * 100u; ++spin)
            __asm__ __volatile__("pause");
        return;
    }
    ticks = (frequency / 1000000u) * delay;
    if (!ticks) ticks = 1u;
    start = apic_read_tsc();
    while (apic_read_tsc() - start < ticks)
        __asm__ __volatile__("pause");
}

static uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static int apic_x2apic_supported(void) {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    eax = 1u;
    ecx = 0u;
    __asm__ __volatile__("cpuid"
                         : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    return (ecx & (1u << 21)) != 0u;
}

static uint32_t x2apic_msr(uint32_t reg) {
    return X2APIC_MSR_BASE + (reg >> 4);
}

static uint32_t lapic_read(uint32_t reg) {
    if (!g_lapic) return 0;
    if (g_x2apic_enabled) return (uint32_t)rdmsr(x2apic_msr(reg));
    return g_lapic[reg >> 2];
}

static void lapic_write(uint32_t reg, uint32_t value) {
    if (!g_lapic) return;
    if (g_x2apic_enabled) {
        wrmsr(x2apic_msr(reg), value);
        return;
    }
    g_lapic[reg >> 2] = value;
}

static uint64_t pci_bar_base(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_index) {
    uint8_t off;
    uint32_t lo;

    if (bar_index >= 6u) return 0;
    off = (uint8_t)(0x10u + bar_index * 4u);
    lo = pci_cfg_read32(bus, slot, func, off);
    if (lo & 1u) return 0;
    if (((lo >> 1) & 0x3u) == 0x2u && bar_index < 5u) {
        uint32_t hi = pci_cfg_read32(bus, slot, func, (uint8_t)(off + 4u));
        return ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xFu);
    }
    return (uint64_t)(lo & ~0xFu);
}

void apic_init(void) {
#ifdef CONFIG_APIC
    uint64_t base_msr;
    uint64_t base_phys;
    uint32_t acpi_base;
    uint32_t version;

    acpi_base = acpi_lapic_address();
    base_msr = rdmsr(IA32_APIC_BASE_MSR);
    base_phys = base_msr & 0xFFFFF000ULL;
    if (acpi_base) base_phys = acpi_base;
    if (!base_phys) {
        printf("[apic] local APIC base unavailable\n");
        return;
    }

    wrmsr(IA32_APIC_BASE_MSR, (base_msr & ~0xFFFFF000ULL) | base_phys | APIC_BASE_ENABLE);
    g_lapic = (volatile uint32_t *)edge_mmio_low_alias(base_phys);
    if ((base_msr & APIC_BASE_X2APIC) != 0u ||
        apic_x2apic_supported()) {
        if ((base_msr & APIC_BASE_X2APIC) == 0u)
            wrmsr(IA32_APIC_BASE_MSR,
                  rdmsr(IA32_APIC_BASE_MSR) | APIC_BASE_ENABLE |
                  APIC_BASE_X2APIC);
        g_x2apic_enabled = 1u;
    }
    version = lapic_read(APIC_REG_VERSION);
    g_lapic_id = g_x2apic_enabled ? lapic_read(APIC_REG_ID) :
                                    lapic_read(APIC_REG_ID) >> 24;
    lapic_write(APIC_REG_SVR, (lapic_read(APIC_REG_SVR) & 0xFFFFFF00u) |
                              APIC_SVR_ENABLE | APIC_SPURIOUS_VECTOR);
    printf("[apic] local APIC enabled base=0x%llx id=%u version=0x%x mode=%s local_cpus=%u\n",
           (unsigned long long)base_phys, g_lapic_id, version,
           g_x2apic_enabled ? "x2apic" : "xapic",
           acpi_local_apic_count());

#ifdef CONFIG_IOAPIC
    for (uint32_t i = 0; i < acpi_ioapic_count(); ++i) {
        struct acpi_ioapic_info ioa;
        if (acpi_get_ioapic(i, &ioa) == 0) {
            printf("[ioapic] id=%u addr=0x%x gsi_base=%u\n",
                   (uint32_t)ioa.id, ioa.address, ioa.global_irq_base);
        }
    }
    for (uint32_t i = 0; i < acpi_interrupt_override_count(); ++i) {
        struct acpi_irq_override_info iso;
        if (acpi_get_interrupt_override(i, &iso) == 0) {
            printf("[ioapic] irq override bus=%u source=%u gsi=%u flags=0x%x\n",
                   (uint32_t)iso.bus, (uint32_t)iso.source_irq,
                   iso.global_irq, (uint32_t)iso.flags);
        }
    }
#endif
#else
    printf("[apic] disabled by configuration\n");
#endif
}

int apic_init_local(void) {
#ifdef CONFIG_APIC
    uint64_t base_msr = rdmsr(IA32_APIC_BASE_MSR);
    uint64_t base_phys = base_msr & 0xFFFFF000ULL;

    if (!base_phys && g_lapic)
        base_phys = acpi_lapic_address();
    if (!base_phys) return -1;
    wrmsr(IA32_APIC_BASE_MSR,
          (base_msr & ~0xFFFFF000ULL) | base_phys | APIC_BASE_ENABLE);
    if (!g_lapic)
        g_lapic = (volatile uint32_t *)edge_mmio_low_alias(base_phys);
    if (g_x2apic_enabled) {
        if (!apic_x2apic_supported()) return -1;
        wrmsr(IA32_APIC_BASE_MSR,
              rdmsr(IA32_APIC_BASE_MSR) | APIC_BASE_ENABLE |
              APIC_BASE_X2APIC);
    }
    lapic_write(APIC_REG_SVR, (lapic_read(APIC_REG_SVR) & 0xFFFFFF00u) |
                              APIC_SVR_ENABLE | APIC_SPURIOUS_VECTOR);
    return 0;
#else
    return -1;
#endif
}

static int apic_wait_icr_idle(void) {
    uint64_t frequency = boottime_clocksource_hz();
    uint64_t start = apic_read_tsc();
    uint64_t timeout = frequency ? frequency / 10u : UINT64_MAX;

    if (g_x2apic_enabled) return 0;
    while (lapic_read(APIC_REG_ICR_LOW) & APIC_ICR_DELIVERY_STATUS) {
        if (apic_read_tsc() - start > timeout) return -1;
        __asm__ __volatile__("pause");
    }
    return 0;
}

static int apic_send_ipi_command(uint32_t apic_id, uint32_t command) {
    if (!g_lapic || apic_wait_icr_idle() != 0) return -1;
    if (g_x2apic_enabled) {
        wrmsr(x2apic_msr(APIC_REG_ICR_LOW),
              ((uint64_t)apic_id << 32) | command);
        return 0;
    }
    if (apic_id > 255u) return -1;
    lapic_write(APIC_REG_ICR_HIGH, apic_id << 24);
    lapic_write(APIC_REG_ICR_LOW, command);
    return apic_wait_icr_idle();
}

int apic_send_fixed_ipi(uint32_t apic_id, uint8_t vector) {
    if (vector < 0x20u) return -1;
    if (!g_lapic || apic_wait_icr_idle() != 0)
        return -1;
    if (g_x2apic_enabled) {
        wrmsr(x2apic_msr(APIC_REG_ICR_LOW),
              ((uint64_t)apic_id << 32) | vector);
        return 0;
    }
    if (apic_id > 255u) return -1;
    lapic_write(APIC_REG_ICR_HIGH, apic_id << 24);
    lapic_write(APIC_REG_ICR_LOW, vector);
    /* The next sender waits before reusing ICR; delivery itself is async. */
    return 0;
}

int apic_start_processor(uint32_t apic_id, uint8_t startup_vector) {
    if (!startup_vector) return -1;
    if (apic_send_ipi_command(apic_id,
            APIC_ICR_DELIVERY_INIT | APIC_ICR_LEVEL_ASSERT |
            APIC_ICR_TRIGGER_LEVEL) != 0)
        return -1;
    apic_delay_us(10000u);
    if (apic_send_ipi_command(apic_id,
            APIC_ICR_DELIVERY_INIT | APIC_ICR_TRIGGER_LEVEL) != 0)
        return -1;
    apic_delay_us(200u);
    if (apic_send_ipi_command(apic_id,
            APIC_ICR_DELIVERY_STARTUP | startup_vector) != 0)
        return -1;
    apic_delay_us(200u);
    return apic_send_ipi_command(apic_id,
        APIC_ICR_DELIVERY_STARTUP | startup_vector);
}

static uint64_t apic_timer_irq_save(void) {
    uint64_t flags;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

static void apic_timer_irq_restore(uint64_t flags) {
    if (flags & (1ULL << 9)) __asm__ __volatile__("sti" ::: "memory");
}

static void apic_timer_write_lvt(uint32_t cpu, uint32_t value) {
    if (!g_apic_timer_lvt_valid[cpu] || g_apic_timer_lvt[cpu] != value) {
        lapic_write(APIC_REG_LVT_TIMER, value);
        g_apic_timer_lvt[cpu] = value;
        g_apic_timer_lvt_valid[cpu] = 1u;
    }
}

static void apic_timer_rearm(uint32_t cpu) {
    kernel_timer_alarm_t *alarm = &g_apic_alarms[cpu];
    uint64_t deadline;
    uint64_t now;
    uint32_t count;

    if (!g_apic_timer_ready[cpu]) return;
    if (!g_apic_timer_highres[cpu]) {
        apic_timer_write_lvt(cpu, APIC_TIMER_VECTOR |
                            (alarm->periodic_enabled ?
                             APIC_LVT_TIMER_PERIODIC : APIC_LVT_MASKED));
        lapic_write(APIC_REG_TIMER_INITIAL,
                    alarm->periodic_enabled ? g_apic_timer_initial[cpu] : 0u);
        return;
    }
    deadline = kernel_timer_alarm_next(alarm);
    if (!deadline) {
        apic_timer_write_lvt(cpu, APIC_LVT_MASKED | APIC_TIMER_VECTOR);
        lapic_write(APIC_REG_TIMER_INITIAL, 0u);
        return;
    }
    now = boottime_monotonic_us();
    count = (uint32_t)kernel_timer_alarm_counts(
        deadline > now ? deadline - now : 1u,
        g_apic_timer_frequency[cpu], UINT32_MAX);
    /* Program the vector/mode first and start the countdown with the last write. */
    apic_timer_write_lvt(cpu, APIC_TIMER_VECTOR);
    lapic_write(APIC_REG_TIMER_INITIAL, count);
}

static int apic_timer_initialize(uint32_t ticks_per_second, int periodic) {
    uint32_t elapsed;
    uint32_t initial;
    uint32_t cpu;
    uint64_t flags;
    uint64_t now;

    if (!g_lapic || ticks_per_second == 0) return -1;
    flags = apic_timer_irq_save();
    cpu = x86_smp_current_cpu_id();
    if (cpu >= EDGE_SMP_MAX_CPUS) {
        apic_timer_irq_restore(flags);
        return -1;
    }
    g_apic_timer_lvt_valid[cpu] = 0u;
    apic_timer_write_lvt(cpu, APIC_LVT_MASKED | APIC_TIMER_VECTOR);
    lapic_write(APIC_REG_TIMER_DIVIDE, 0x3u);
    lapic_write(APIC_REG_TIMER_INITIAL, UINT32_MAX);
    apic_delay_us(10000u);
    elapsed = UINT32_MAX - lapic_read(APIC_REG_TIMER_CURRENT);
    lapic_write(APIC_REG_TIMER_INITIAL, 0u);
    if (elapsed < 100u) {
        apic_timer_irq_restore(flags);
        return -1;
    }
    initial = (uint32_t)(((uint64_t)elapsed * 100u) / ticks_per_second);
    if (!initial) initial = 1u;
    g_apic_timer_initial[cpu] = initial;
    g_apic_timer_frequency[cpu] = (uint64_t)elapsed * 100u;
    g_apic_timer_highres[cpu] = boottime_clocksource_hz() != 0u;
    now = boottime_monotonic_us();
    kernel_timer_alarm_init(&g_apic_alarms[cpu], now,
        periodic ? 1000000u / ticks_per_second : 0u, 0u);
    kernel_timer_alarm_display(&g_apic_alarms[cpu], kernel_display_deadline());
    g_apic_timer_ready[cpu] = 1u;
    apic_timer_rearm(cpu);
    apic_timer_irq_restore(flags);
    return 0;
}

int apic_timer_init(uint32_t ticks_per_second) {
    return apic_timer_initialize(ticks_per_second, 1);
}

int apic_timer_init_alarms(void) {
    return apic_timer_initialize(EDGE_KERNEL_TIMER_HZ, 0);
}

void apic_timer_pause_periodic(void) {
    uint64_t flags = apic_timer_irq_save();
    uint32_t cpu = x86_smp_current_cpu_id();
    if (g_lapic && cpu < EDGE_SMP_MAX_CPUS && g_apic_timer_ready[cpu]) {
        kernel_timer_alarm_pause(&g_apic_alarms[cpu]);
        apic_timer_rearm(cpu);
    }
    apic_timer_irq_restore(flags);
}

void apic_timer_resume_periodic(void) {
    uint64_t flags = apic_timer_irq_save();
    uint32_t cpu = x86_smp_current_cpu_id();
    if (g_lapic && cpu < EDGE_SMP_MAX_CPUS && g_apic_timer_ready[cpu]) {
        kernel_timer_alarm_resume(&g_apic_alarms[cpu], boottime_monotonic_us());
        apic_timer_rearm(cpu);
    }
    apic_timer_irq_restore(flags);
}

int apic_timer_arm_oneshot_us(uint32_t microseconds) {
    uint64_t flags = apic_timer_irq_save();
    uint32_t cpu = x86_smp_current_cpu_id();

    if (!g_lapic || !microseconds || cpu >= EDGE_SMP_MAX_CPUS ||
        !g_apic_timer_ready[cpu] || !g_apic_timer_highres[cpu]) {
        apic_timer_irq_restore(flags);
        return -1;
    }
    kernel_timer_alarm_rseq(&g_apic_alarms[cpu], kernel_timer_alarm_add(
        boottime_monotonic_us(), microseconds));
    apic_timer_rearm(cpu);
    apic_timer_irq_restore(flags);
    return 0;
}

void apic_timer_cancel_oneshot(void) {
    uint64_t flags = apic_timer_irq_save();
    uint32_t cpu = x86_smp_current_cpu_id();
    if (g_lapic && cpu < EDGE_SMP_MAX_CPUS && g_apic_timer_ready[cpu] &&
        g_apic_alarms[cpu].rseq_deadline_us) {
        kernel_timer_alarm_rseq(&g_apic_alarms[cpu], 0u);
        apic_timer_rearm(cpu);
    }
    apic_timer_irq_restore(flags);
}

uint32_t apic_timer_interrupt(void) {
    uint32_t cpu = x86_smp_current_cpu_id();
    uint32_t events;

    if (cpu >= EDGE_SMP_MAX_CPUS || !g_apic_timer_ready[cpu]) return 0u;
    if (!g_apic_timer_highres[cpu])
        return g_apic_alarms[cpu].periodic_enabled ?
               KERNEL_TIMER_ALARM_PERIODIC : 0u;
    events = kernel_timer_alarm_expire(&g_apic_alarms[cpu], boottime_monotonic_us());
    apic_timer_rearm(cpu);
    return events;
}

void kernel_arch_display_deadline_request(uint64_t deadline_us) {
    uint64_t flags = apic_timer_irq_save();
    uint32_t cpu = x86_smp_current_cpu_id();
    uint64_t previous;

    /* The publishing CPU owns this alarm, including while its runqueue is idle. */
    if (deadline_us && g_lapic && cpu < EDGE_SMP_MAX_CPUS &&
        g_apic_timer_ready[cpu] && g_apic_timer_highres[cpu]) {
        previous = kernel_timer_alarm_next(&g_apic_alarms[cpu]);
        kernel_timer_alarm_display(&g_apic_alarms[cpu], deadline_us);
        if (kernel_timer_alarm_next(&g_apic_alarms[cpu]) != previous)
            apic_timer_rearm(cpu);
    }
    apic_timer_irq_restore(flags);
}

void kernel_arch_wait_deadline_request(uint64_t deadline_us) {
    uint64_t flags = apic_timer_irq_save();
    uint32_t cpu = x86_smp_current_cpu_id();
    uint64_t previous;

    /* The publishing CPU owns this alarm, including while its runqueue is idle. */
    if (deadline_us && g_lapic && cpu < EDGE_SMP_MAX_CPUS &&
        g_apic_timer_ready[cpu] && g_apic_timer_highres[cpu]) {
        previous = kernel_timer_alarm_next(&g_apic_alarms[cpu]);
        kernel_timer_alarm_wait(&g_apic_alarms[cpu], deadline_us);
        if (kernel_timer_alarm_next(&g_apic_alarms[cpu]) != previous)
            apic_timer_rearm(cpu);
    }
    apic_timer_irq_restore(flags);
}

int apic_available(void) {
    return g_lapic != 0;
}

uint32_t apic_local_id(void) {
    if (!g_lapic) return g_lapic_id;
    return g_x2apic_enabled ? lapic_read(APIC_REG_ID) :
                             lapic_read(APIC_REG_ID) >> 24;
}

void apic_eoi(void) {
    if (g_lapic) lapic_write(APIC_REG_EOI, 0);
}

int apic_enable_performance_interrupt(void) {
#ifdef CONFIG_APIC
    uint32_t users;
    uint32_t version;
    uint32_t value;

    if (!g_lapic) return 0;
    version = lapic_read(APIC_REG_VERSION);
    if (((version >> 16) & 0xFFu) < 4u) return 0;
    users = __atomic_fetch_add(&g_performance_interrupt_users, 1u,
                               __ATOMIC_ACQ_REL);
    if (users != 0) return 1;
    value = lapic_read(APIC_REG_LVT_PCINT);
    value &= ~(APIC_LVT_DELIVERY_MASK | APIC_LVT_MASKED | 0xFFu);
    value |= APIC_LVT_DELIVERY_NMI;
    lapic_write(APIC_REG_LVT_PCINT, value);
    return 1;
#else
    return 0;
#endif
}

void apic_disable_performance_interrupt(void) {
#ifdef CONFIG_APIC
    uint32_t users;

    users = __atomic_load_n(&g_performance_interrupt_users,
                            __ATOMIC_ACQUIRE);
    while (users != 0) {
        if (!__atomic_compare_exchange_n(&g_performance_interrupt_users,
            &users, users - 1u, 0, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE))
            continue;
        if (users == 1u && g_lapic) {
            uint32_t value = lapic_read(APIC_REG_LVT_PCINT);

            lapic_write(APIC_REG_LVT_PCINT,
                        value | APIC_LVT_MASKED);
        }
        return;
    }
#endif
}

void apic_reenable_performance_interrupt(void) {
#ifdef CONFIG_APIC
    uint32_t value;

    if (!g_lapic ||
        __atomic_load_n(&g_performance_interrupt_users,
                        __ATOMIC_ACQUIRE) == 0)
        return;
    value = lapic_read(APIC_REG_LVT_PCINT);
    lapic_write(APIC_REG_LVT_PCINT, value & ~APIC_LVT_MASKED);
#endif
}

int apic_allocate_msi_vector(void) {
    uint32_t vector;

    return apic_allocate_msi_vectors(1, 1, &vector) == 0 ?
        (int)vector : -1;
}

int apic_allocate_msi_vectors(unsigned int count, int contiguous,
                              uint32_t *vectors) {
#if defined(CONFIG_APIC) && (defined(CONFIG_PCI_MSI) || defined(CONFIG_PCI_MSIX))
    uint16_t selected;
    uint16_t observed;

    if (!g_lapic || !vectors || count == 0 ||
        count > MSI_VECTOR_LAST - MSI_VECTOR_FIRST + 1u)
        return -1;
    if (contiguous) {
        if ((count & (count - 1u)) != 0)
            return -1;
        selected = (uint16_t)((UINT32_C(1) << count) - 1u);
        for (unsigned int first = 0;
             first + count <= MSI_VECTOR_LAST - MSI_VECTOR_FIRST + 1u;
             first += count) {
            uint16_t mask = (uint16_t)(selected << first);

            observed = __atomic_load_n(&g_allocated_vectors,
                                       __ATOMIC_ACQUIRE);
            while ((observed & mask) == 0) {
                uint16_t desired = observed | mask;

                if (__atomic_compare_exchange_n(&g_allocated_vectors,
                    &observed, desired, 0, __ATOMIC_ACQ_REL,
                    __ATOMIC_ACQUIRE)) {
                    for (unsigned int index = 0; index < count; ++index)
                        vectors[index] = MSI_VECTOR_FIRST + first + index;
                    return 0;
                }
            }
        }
        return -1;
    }
    for (;;) {
        unsigned int found = 0;

        selected = 0;
        observed = __atomic_load_n(&g_allocated_vectors, __ATOMIC_ACQUIRE);
        for (unsigned int bit = 0;
             bit <= MSI_VECTOR_LAST - MSI_VECTOR_FIRST && found < count;
             ++bit) {
            if ((observed & (UINT16_C(1) << bit)) == 0) {
                selected |= (uint16_t)(UINT16_C(1) << bit);
                vectors[found++] = MSI_VECTOR_FIRST + bit;
            }
        }
        if (found != count)
            return -1;
        {
            uint16_t desired = observed | selected;

            if (__atomic_compare_exchange_n(&g_allocated_vectors,
                &observed, desired, 0, __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE))
                return 0;
        }
    }
#else
    (void)count;
    (void)contiguous;
    (void)vectors;
#endif
    return -1;
}

void apic_release_msi_vectors(const uint32_t *vectors, unsigned int count) {
#if defined(CONFIG_APIC) && (defined(CONFIG_PCI_MSI) || defined(CONFIG_PCI_MSIX))
    uint16_t mask = 0;

    if (!vectors) return;
    for (unsigned int index = 0; index < count; ++index) {
        if (vectors[index] < MSI_VECTOR_FIRST ||
            vectors[index] > MSI_VECTOR_LAST)
            return;
        mask |= (uint16_t)(UINT16_C(1) <<
            (vectors[index] - MSI_VECTOR_FIRST));
    }
    __atomic_fetch_and(&g_allocated_vectors, (uint16_t)~mask,
                       __ATOMIC_ACQ_REL);
#else
    (void)vectors;
    (void)count;
#endif
}

int pci_enable_msi_vectors(uint8_t bus, uint8_t slot, uint8_t func,
                           const uint32_t *vectors, unsigned int count) {
#ifdef CONFIG_PCI_MSI
    uint8_t cap = (uint8_t)pci_find_capability(bus, slot, func, PCI_CAP_ID_MSI);
    uint16_t ctrl;
    uint16_t cmd;
    unsigned int encoded = 0;
    uint16_t data;
    uint32_t addr = MSI_ADDR_BASE | (g_lapic_id << 12);

    if (!g_lapic || !cap || !vectors || count == 0 ||
        count > 32 || (count & (count - 1u)) != 0 ||
        vectors[0] < MSI_VECTOR_FIRST ||
        (vectors[0] & (count - 1u)) != 0)
        return -1;
    for (unsigned int index = 0; index < count; ++index) {
        if (vectors[index] != vectors[0] + index ||
            vectors[index] > MSI_VECTOR_LAST)
            return -1;
    }
    while ((1u << encoded) < count) encoded++;
    data = (uint16_t)vectors[0];
    ctrl = pci_cfg_read16(bus, slot, func, (uint8_t)(cap + PCI_CAP_MSI_CTRL));
    pci_cfg_write32(bus, slot, func, (uint8_t)(cap + PCI_CAP_MSI_ADDR_LO), addr);
    if (ctrl & PCI_MSI_CTRL_64BIT) {
        pci_cfg_write32(bus, slot, func, (uint8_t)(cap + PCI_CAP_MSI_ADDR_HI), 0);
        pci_cfg_write16(bus, slot, func, (uint8_t)(cap + PCI_CAP_MSI_DATA_64), data);
    } else {
        pci_cfg_write16(bus, slot, func, (uint8_t)(cap + PCI_CAP_MSI_DATA_32), data);
    }
    ctrl = (uint16_t)((ctrl & ~0x0070u) | (encoded << 4) |
                      PCI_MSI_CTRL_ENABLE);
    pci_cfg_write16(bus, slot, func,
                    (uint8_t)(cap + PCI_CAP_MSI_CTRL), ctrl);
    cmd = pci_cfg_read16(bus, slot, func, 0x04);
    pci_cfg_write16(bus, slot, func, 0x04, (uint16_t)(cmd | PCI_COMMAND_INTX_DISABLE));
    printf("[msi] enabled %u:%u.%u vector=%u addr=0x%x\n",
           bus, slot, func, vectors[0], addr);
    return 0;
#else
    (void)bus; (void)slot; (void)func; (void)vectors; (void)count;
    return -1;
#endif
}

int pci_enable_msi_vector(uint8_t bus, uint8_t slot, uint8_t func,
                          uint8_t vector) {
    uint32_t expanded = vector;

    return pci_enable_msi_vectors(bus, slot, func, &expanded, 1);
}

int pci_disable_msi_vectors(uint8_t bus, uint8_t slot, uint8_t func) {
#ifdef CONFIG_PCI_MSI
    uint8_t cap = (uint8_t)pci_find_capability(
        bus, slot, func, PCI_CAP_ID_MSI);
    uint16_t ctrl;
    uint16_t cmd;

    if (!cap) return -1;
    ctrl = pci_cfg_read16(bus, slot, func,
                          (uint8_t)(cap + PCI_CAP_MSI_CTRL));
    ctrl &= (uint16_t)~PCI_MSI_CTRL_ENABLE;
    pci_cfg_write16(bus, slot, func,
                    (uint8_t)(cap + PCI_CAP_MSI_CTRL), ctrl);
    cmd = pci_cfg_read16(bus, slot, func, 0x04);
    pci_cfg_write16(bus, slot, func, 0x04,
                    (uint16_t)(cmd & ~PCI_COMMAND_INTX_DISABLE));
    return 0;
#else
    (void)bus; (void)slot; (void)func;
    return -1;
#endif
}

int pci_enable_msix_vector(uint8_t bus, uint8_t slot, uint8_t func,
                           uint16_t table_index, uint8_t vector) {
#ifdef CONFIG_PCI_MSIX
    uint8_t cap = (uint8_t)pci_find_capability(bus, slot, func, PCI_CAP_ID_MSIX);
    uint16_t ctrl;
    uint32_t table;
    uint8_t bir;
    uint64_t bar;
    volatile uint32_t *entry;
    uint32_t addr = MSI_ADDR_BASE | (g_lapic_id << 12);

    if (!g_lapic || !cap || vector < MSI_VECTOR_FIRST) return -1;
    ctrl = pci_cfg_read16(bus, slot, func, (uint8_t)(cap + PCI_MSIX_CTRL));
    if (table_index > (uint16_t)(ctrl & 0x07FFu)) return -1;
    table = pci_cfg_read32(bus, slot, func, (uint8_t)(cap + PCI_MSIX_TABLE));
    bir = (uint8_t)(table & PCI_MSIX_BIR_MASK);
    bar = pci_bar_base(bus, slot, func, bir);
    if (!bar) return -1;
    entry = (volatile uint32_t *)edge_mmio_low_alias(bar + (table & PCI_MSIX_OFFSET_MASK) +
                                                     (uint32_t)table_index * PCI_MSIX_ENTRY_SIZE);
    entry[3] = 1u;
    entry[0] = addr;
    entry[1] = 0;
    entry[2] = vector;
    entry[3] = 0;
    pci_cfg_write16(bus, slot, func, (uint8_t)(cap + PCI_MSIX_CTRL),
                    (uint16_t)((ctrl | PCI_MSIX_CTRL_ENABLE) & ~PCI_MSIX_CTRL_MASKALL));
    printf("[msix] enabled %u:%u.%u table=%u vector=%u addr=0x%x\n",
           bus, slot, func, (uint32_t)table_index, (uint32_t)vector, addr);
    return 0;
#else
    (void)bus; (void)slot; (void)func; (void)table_index; (void)vector;
    return -1;
#endif
}

int pci_disable_msix_vector(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t table_index) {
#ifdef CONFIG_PCI_MSIX
    uint8_t cap = (uint8_t)pci_find_capability(
        bus, slot, func, PCI_CAP_ID_MSIX);
    uint16_t ctrl;
    uint32_t table;
    uint8_t bir;
    uint64_t bar;
    volatile uint32_t *entry;

    if (!cap) return -1;
    ctrl = pci_cfg_read16(bus, slot, func,
                          (uint8_t)(cap + PCI_MSIX_CTRL));
    if (table_index > (uint16_t)(ctrl & 0x07ffu)) return -1;
    table = pci_cfg_read32(bus, slot, func,
                           (uint8_t)(cap + PCI_MSIX_TABLE));
    bir = (uint8_t)(table & PCI_MSIX_BIR_MASK);
    bar = pci_bar_base(bus, slot, func, bir);
    if (!bar) return -1;
    entry = (volatile uint32_t *)edge_mmio_low_alias(
        bar + (table & PCI_MSIX_OFFSET_MASK) +
        (uint32_t)table_index * PCI_MSIX_ENTRY_SIZE);
    entry[3] = 1u;
    return 0;
#else
    (void)bus; (void)slot; (void)func; (void)table_index;
    return -1;
#endif
}

int pci_disable_msix_vectors(uint8_t bus, uint8_t slot, uint8_t func) {
#ifdef CONFIG_PCI_MSIX
    uint8_t cap = (uint8_t)pci_find_capability(
        bus, slot, func, PCI_CAP_ID_MSIX);
    uint16_t ctrl;
    uint16_t cmd;

    if (!cap) return -1;
    ctrl = pci_cfg_read16(bus, slot, func,
                          (uint8_t)(cap + PCI_MSIX_CTRL));
    ctrl |= PCI_MSIX_CTRL_MASKALL;
    ctrl &= (uint16_t)~PCI_MSIX_CTRL_ENABLE;
    pci_cfg_write16(bus, slot, func,
                    (uint8_t)(cap + PCI_MSIX_CTRL), ctrl);
    cmd = pci_cfg_read16(bus, slot, func, 0x04);
    pci_cfg_write16(bus, slot, func, 0x04,
                    (uint16_t)(cmd & ~PCI_COMMAND_INTX_DISABLE));
    return 0;
#else
    (void)bus; (void)slot; (void)func;
    return -1;
#endif
}
