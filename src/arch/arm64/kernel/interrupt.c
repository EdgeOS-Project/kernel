/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 GICv3 and architectural timer bring-up.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include "arch/arm64/interrupt.h"
#include "arch/arm64/smp.h"
#include "arch/arm64/platform.h"
#include "kernel/runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/deferred_work.h"
#include "kernel/linux_ptrace.h"
#include "kernel/smp.h"
#include "kernel/timer_policy.h"
#include "arch/arm64/syscall.h"
#include "arch/arm64/vm.h"
#include "fb_console.h"
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
#define EDGEOS_ARM64_SHARED_OFW 1
#include "compat/freebsd/edgeos/ofw.h"
#endif

#ifndef EDGEOS_ARM64_SHARED_OFW
#define FDT_MAGIC 0xd00dfeedu
#define FDT_BEGIN_NODE 1u
#define FDT_END_NODE 2u
#define FDT_PROP 3u
#define FDT_NOP 4u
#define FDT_END 9u
#endif

#define GICD_CTLR 0x0000u
#define GICD_CTLR_ENABLE_GRP1NS (1u << 1)
#define GICD_CTLR_ENABLE_GRP0 (1u << 0)
#define GICD_CTLR_ARE (1u << 4)
#define GICD_CTLR_ARE_NS (1u << 5)
#define GICD_CTLR_DS (1u << 6)
#define GICD_CTLR_RWP (1u << 31)
#define GICD_IGROUPR 0x0080u
#define GICD_ISENABLER 0x0100u
#define GICD_ICENABLER 0x0180u
#define GICD_ISPENDR 0x0200u
#define GICD_ICPENDR 0x0280u
#define GICD_IPRIORITYR 0x0400u
#define GICD_ITARGETSR 0x0800u
#define GICD_ICFGR 0x0c00u
#define GICD_SGIR 0x0f00u
#define GICD_IROUTER 0x6000u
#define GICC_CTLR 0x0000u
#define GICC_PMR 0x0004u
#define GICC_BPR 0x0008u
#define GICC_IAR 0x000cu
#define GICC_EOIR 0x0010u
#define GICC_CTLR_ACK_CTL (1u << 2)
#define GICR_WAKER 0x0014u
#define GICR_WAKER_PROCESSOR_SLEEP (1u << 1)
#define GICR_WAKER_CHILDREN_ASLEEP (1u << 2)
#define GICR_TYPER 0x0008u
#define GICR_TYPER_LAST (1ULL << 4)
#define GICR_FRAME_STRIDE 0x20000u
#define GICR_SGI_BASE 0x10000u
#define GICR_IGROUPR0 (GICR_SGI_BASE + 0x0080u)
#define GICR_ISENABLER0 (GICR_SGI_BASE + 0x0100u)
#define GICR_IPRIORITYR (GICR_SGI_BASE + 0x0400u)
#define ARM64_VIRTUAL_TIMER_PPI 27u
#define ARM64_RESCHEDULE_SGI 1u
#define ARM64_CALL_SGI 2u
#define ARM64_GIC_INTERRUPT_MAX 1020u
#define ARM64_ESR_SYS64_DIR_READ 1u
#define ARM64_MPIDR_USER_SAFE (1ULL << 31)

extern char edgeos_arm64_vectors[];
static volatile uint8_t g_rseq_slice_timer_armed[EDGE_SMP_MAX_CPUS];
static volatile uint64_t g_rseq_slice_timer_ticks[EDGE_SMP_MAX_CPUS];
static volatile uint64_t g_rseq_period_saved_ticks[EDGE_SMP_MAX_CPUS];
static volatile uint64_t g_rseq_period_resume_ticks[EDGE_SMP_MAX_CPUS];

#ifndef EDGEOS_ARM64_SHARED_OFW
typedef struct {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
} fdt_header_t;
#endif

static volatile uint32_t *g_gicd;
static volatile uint32_t *g_gicr_base;
static volatile uint32_t *g_gicc;
static uint32_t g_gic_version;
static volatile uint64_t g_timer_ticks;
static uint32_t g_user_debug_fault_log_budget = 32u;
static uint32_t g_user_illegal_fault_log_budget = 16u;
static edgeos_arm64_irq_callback_t
    g_irq_callbacks[ARM64_GIC_INTERRUPT_MAX];
static void *g_irq_contexts[ARM64_GIC_INTERRUPT_MAX];
static volatile uint32_t g_irq_active[ARM64_GIC_INTERRUPT_MAX];

static void arm64_serial_puts(const char *s);
static void arm64_serial_hex64(uint64_t value);

static int arm64_emulate_user_id_register(
        edgeos_arm64_exception_frame_t *frame) {
    uint32_t iss;
    uint32_t op0;
    uint32_t op1;
    uint32_t op2;
    uint32_t crn;
    uint32_t crm;
    uint32_t rt;
    uint64_t value;

    if (!frame) return -1;
    iss = (uint32_t)frame->esr;
    op0 = (iss >> 20) & 0x3u;
    op1 = (iss >> 14) & 0x7u;
    op2 = (iss >> 17) & 0x7u;
    crn = (iss >> 10) & 0xfu;
    crm = (iss >> 1) & 0xfu;
    rt = (iss >> 5) & 0x1fu;
    if ((iss & 1u) != ARM64_ESR_SYS64_DIR_READ || op0 != 3u || op1 != 0u ||
        crn != 0u)
        return -1;

    if (crm == 0u) {
        switch (op2) {
        case 0u:
            __asm__ __volatile__("mrs %0, midr_el1" : "=r"(value));
            break;
        case 5u:
            value = ARM64_MPIDR_USER_SAFE;
            break;
        case 6u:
            value = 0;
            break;
        default:
            return -1;
        }
    } else if (crm >= 2u && crm <= 7u) {
        value = 0;
    } else {
        return -1;
    }

    if (rt < 31u) frame->x[rt] = value;
    frame->elr += 4u;
    return 0;
}

static int arm64_user_u64(uint64_t ttbr0, uint64_t address,
                          uint64_t *value) {
    uint64_t physical;

    if (!value || (address & 7u) || address >= (1ULL << 48) ||
        edgeos_arm64_address_space_translate(
            ttbr0, address, &physical, 0) < 0)
        return -1;
    *value = *(const uint64_t *)(uintptr_t)physical;
    return 0;
}

static void arm64_log_user_backtrace(uint64_t ttbr0, uint64_t frame_pointer) {
    uint64_t previous = 0;
    uint64_t return_address = 0;

    arm64_serial_puts(" backtrace=");
    for (uint32_t depth = 0; depth < 16u; ++depth) {
        uint64_t mapping_offset = 0;
        const char *mapping_name;

        if ((frame_pointer & 15u) || frame_pointer >= (1ULL << 48) ||
            arm64_user_u64(ttbr0, frame_pointer, &previous) < 0 ||
            arm64_user_u64(ttbr0, frame_pointer + 8u, &return_address) < 0)
            break;
        arm64_serial_puts(depth ? ";" : "");
        arm64_serial_hex64(return_address);
        mapping_name = kernel_current_mapping_name(return_address,
                                                   &mapping_offset);
        if (mapping_name) {
            arm64_serial_puts("[");
            arm64_serial_puts(mapping_name);
            arm64_serial_puts("+");
            arm64_serial_hex64(mapping_offset);
            arm64_serial_puts("]");
        }
        if (previous <= frame_pointer || previous - frame_pointer > (1u << 20))
            break;
        frame_pointer = previous;
    }
}

#ifdef EDGEOS_ARM64_SHARED_OFW
static int edgeos_arm64_find_gic(const edgeos_arm64_bootinfo_t *bootinfo,
                                 uint64_t *dist_out, uint64_t *redist_out) {
    phandle_t node;
    uint64_t dist_size;
    uint64_t redist_size;

    (void)bootinfo;
    node = bsd_ofw_fdt_find_compatible("arm,gic-v3", 0);
    if (node != 0)
        g_gic_version = 3u;
    else {
        node = bsd_ofw_fdt_find_compatible("arm,gic-400", 0);
        if (node == 0)
            node = bsd_ofw_fdt_find_compatible("arm,cortex-a15-gic", 0);
        if (node != 0)
            g_gic_version = 2u;
    }
    if (node == 0 ||
        bsd_ofw_fdt_get_reg(node, 0, dist_out, &dist_size) != 0 ||
        bsd_ofw_fdt_get_reg(node, 1, redist_out, &redist_size) != 0 ||
        *dist_out == 0 || *redist_out == 0 ||
        dist_size == 0 || redist_size == 0)
        return -1;
    return 0;
}
#else
static uint32_t fdt_be32(const void *ptr) {
    const uint8_t *p = (const uint8_t *)ptr;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t fdt_cells(const uint8_t *data, uint32_t cells) {
    uint64_t value = 0;
    uint32_t i;
    if (cells > 2u) return 0;
    for (i = 0; i < cells; ++i) value = (value << 32) | fdt_be32(data + i * 4u);
    return value;
}

static int str_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a++ != *b++) return 0;
    }
    return *a == 0 && *b == 0;
}

static int compatible_has_gicv3(const uint8_t *data, uint32_t len) {
    uint32_t off = 0;
    while (off < len) {
        const char *s = (const char *)(data + off);
        uint32_t n = 0;
        while (off + n < len && s[n]) ++n;
        if (off + n >= len) return 0;
        if (str_eq(s, "arm,gic-v3")) return 1;
        off += n + 1u;
    }
    return 0;
}

static int edgeos_arm64_find_gic(const edgeos_arm64_bootinfo_t *bootinfo,
                                 uint64_t *dist_out, uint64_t *redist_out) {
    const fdt_header_t *hdr;
    const uint8_t *base;
    const uint8_t *p;
    const uint8_t *end;
    const char *strings;
    uint32_t address_cells = 2;
    uint32_t size_cells = 2;
    int depth = -1;
    int candidate_depth = -1;
    int candidate = 0;
    int register_depth = -1;
    uint64_t register_dist = 0;
    uint64_t register_redist = 0;

    if (!bootinfo || !(bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_FDT) ||
        bootinfo->fdt_size < sizeof(*hdr)) return -1;
    base = (const uint8_t *)(uintptr_t)bootinfo->fdt_base;
    hdr = (const fdt_header_t *)base;
    if (fdt_be32(&hdr->magic) != FDT_MAGIC || fdt_be32(&hdr->totalsize) > bootinfo->fdt_size) return -1;
    p = base + fdt_be32(&hdr->off_dt_struct);
    end = p + fdt_be32(&hdr->size_dt_struct);
    strings = (const char *)(base + fdt_be32(&hdr->off_dt_strings));
    if (p < base || end > base + bootinfo->fdt_size || (const uint8_t *)strings >= base + bootinfo->fdt_size) return -1;

    while (p + 4u <= end) {
        uint32_t token = fdt_be32(p);
        p += 4u;
        if (token == FDT_BEGIN_NODE) {
            while (p < end && *p) ++p;
            if (p >= end) return -1;
            ++p;
            p = (const uint8_t *)(((uintptr_t)p + 3u) & ~(uintptr_t)3u);
            ++depth;
            register_depth = -1;
            register_dist = 0;
            register_redist = 0;
            continue;
        }
        if (token == FDT_END_NODE) {
            if (candidate_depth == depth) {
                candidate = 0;
                candidate_depth = -1;
            }
            if (register_depth == depth) register_depth = -1;
            --depth;
            continue;
        }
        if (token == FDT_NOP) continue;
        if (token == FDT_END) break;
        if (token != FDT_PROP || p + 8u > end) return -1;
        {
            uint32_t len = fdt_be32(p);
            uint32_t nameoff = fdt_be32(p + 4u);
            const char *name = strings + nameoff;
            const uint8_t *data;
            p += 8u;
            if (p + len > end || (const uint8_t *)name >= base + bootinfo->fdt_size) return -1;
            data = p;
            p = (const uint8_t *)(((uintptr_t)(p + len) + 3u) & ~(uintptr_t)3u);

            if (depth == 0 && str_eq(name, "#address-cells") && len == 4u) address_cells = fdt_be32(data);
            else if (depth == 0 && str_eq(name, "#size-cells") && len == 4u) size_cells = fdt_be32(data);
            else if (str_eq(name, "compatible") && compatible_has_gicv3(data, len)) {
                candidate = 1;
                candidate_depth = depth;
                if (register_depth == depth && register_dist && register_redist) {
                    *dist_out = register_dist;
                    *redist_out = register_redist;
                    return 0;
                }
            } else if (str_eq(name, "reg") &&
                       len >= 2u * (address_cells + size_cells) * 4u) {
                uint32_t stride = (address_cells + size_cells) * 4u;
                uint64_t dist = fdt_cells(data, address_cells);
                uint64_t redist = fdt_cells(data + stride, address_cells);
                if (!dist || !redist) return -1;
                register_depth = depth;
                register_dist = dist;
                register_redist = redist;
                if (candidate && candidate_depth == depth) {
                    *dist_out = dist;
                    *redist_out = redist;
                    return 0;
                }
            }
        }
    }
    return -1;
}
#endif

static uint32_t acpi_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t acpi_le64(const uint8_t *p) {
    return (uint64_t)acpi_le32(p) | ((uint64_t)acpi_le32(p + 4u) << 32);
}

static int acpi_sig_eq(const uint8_t *p, const char sig[4]) {
    return p[0] == (uint8_t)sig[0] && p[1] == (uint8_t)sig[1] &&
           p[2] == (uint8_t)sig[2] && p[3] == (uint8_t)sig[3];
}

static int edgeos_arm64_find_gic_acpi(const edgeos_arm64_bootinfo_t *bootinfo,
                                      uint64_t *dist_out, uint64_t *redist_out) {
    const uint8_t *rsdp;
    const uint8_t *xsdt;
    uint64_t xsdt_addr;
    uint32_t xsdt_len;
    uint32_t off;

    if (!bootinfo || !(bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_ACPI) || !bootinfo->acpi_rsdp) return -1;
    rsdp = (const uint8_t *)(uintptr_t)bootinfo->acpi_rsdp;
    if (!acpi_sig_eq(rsdp, "RSD ") || rsdp[4] != 'P' || rsdp[5] != 'T' || rsdp[6] != 'R' || rsdp[7] != ' ') return -1;
    if (rsdp[15] < 2u) return -1;
    xsdt_addr = acpi_le64(rsdp + 24u);
    if (!xsdt_addr) return -1;
    xsdt = (const uint8_t *)(uintptr_t)xsdt_addr;
    if (!acpi_sig_eq(xsdt, "XSDT")) return -1;
    xsdt_len = acpi_le32(xsdt + 4u);
    if (xsdt_len < 36u) return -1;

    for (off = 36u; off + 8u <= xsdt_len; off += 8u) {
        const uint8_t *madt = (const uint8_t *)(uintptr_t)acpi_le64(xsdt + off);
        uint32_t madt_len;
        uint32_t entry;
        uint64_t dist = 0;
        uint64_t redist = 0;

        if (!madt || !acpi_sig_eq(madt, "APIC")) continue;
        madt_len = acpi_le32(madt + 4u);
        if (madt_len < 44u) return -1;
        entry = 44u;
        while (entry + 2u <= madt_len) {
            uint8_t type = madt[entry];
            uint8_t len = madt[entry + 1u];
            if (len < 2u || entry + len > madt_len) return -1;
            /* ACPI MADT Generic Interrupt Distributor structure, type 12. */
            if (type == 12u && len >= 24u) dist = acpi_le64(madt + entry + 8u);
            /* ACPI MADT Generic Redistributor structure, type 14. */
            if (type == 14u && len >= 16u) redist = acpi_le64(madt + entry + 4u);
            entry += len;
        }
        if (dist && redist) {
            *dist_out = dist;
            *redist_out = redist;
            return 0;
        }
    }
    return -1;
}

int edgeos_arm64_gic_discover(const edgeos_arm64_bootinfo_t *bootinfo,
                              uint64_t *dist_out, uint64_t *redist_out) {
    if (!dist_out || !redist_out) return -1;
    if (edgeos_arm64_find_gic(bootinfo, dist_out, redist_out) == 0) return 0;
    if (edgeos_arm64_find_gic_acpi(bootinfo, dist_out, redist_out) == 0) {
        g_gic_version = 3u;
        return 0;
    }
    return -1;
}

uint32_t edgeos_arm64_gic_version(void) {
    return g_gic_version;
}

int edgeos_arm64_gic_send_sgi(uint64_t mpidr, uint32_t interrupt_id) {
    uint32_t aff0 = (uint32_t)(mpidr & 0xffu);

    if (interrupt_id >= 16u || aff0 >= 16u) return -1;
    if (g_gic_version == 2u) {
        if (!g_gicd || aff0 >= 8u) return -1;
        __asm__ __volatile__("dsb ishst" ::: "memory");
        g_gicd[GICD_SGIR / 4u] =
            (UINT32_C(1) << (16u + aff0)) | interrupt_id;
        __asm__ __volatile__("isb" ::: "memory");
        return 0;
    }
    if (g_gic_version == 3u) {
        uint64_t sgi = ((mpidr >> 32) & 0xffu) << 48;

        sgi |= ((mpidr >> 16) & 0xffu) << 32;
        sgi |= ((uint64_t)interrupt_id & 0xfu) << 24;
        sgi |= ((mpidr >> 8) & 0xffu) << 16;
        sgi |= UINT64_C(1) << aff0;
        __asm__ __volatile__(
            "dsb ishst\n\tmsr icc_sgi1r_el1, %0\n\tisb"
            :: "r"(sgi) : "memory");
        return 0;
    }
    return -1;
}

static void gic_wait_rwp(void) {
    uint32_t spins = 0;
    while ((g_gicd[GICD_CTLR / 4u] & GICD_CTLR_RWP) && spins++ < 1000000u) {
        __asm__ __volatile__("yield");
    }
}

static void gic_enable_cpu_interface(void) {
    uint64_t value;
    value = 1;
    __asm__ __volatile__("msr icc_sre_el1, %0\n\tisb" :: "r"(value));
    value = 0xff;
    __asm__ __volatile__("msr icc_pmr_el1, %0" :: "r"(value));
    value = 1;
    __asm__ __volatile__("msr icc_igrpen1_el1, %0\n\tisb" :: "r"(value));
}

static uint32_t mpidr_affinity(uint64_t mpidr) {
    return ((uint32_t)((mpidr >> 32) & 0xffu) << 24) |
           ((uint32_t)((mpidr >> 16) & 0xffu) << 16) |
           ((uint32_t)((mpidr >> 8) & 0xffu) << 8) |
           (uint32_t)(mpidr & 0xffu);
}

static volatile uint32_t *gic_find_redistributor(void) {
    uint64_t mpidr;
    uint32_t affinity;
    volatile uint8_t *frame = (volatile uint8_t *)g_gicr_base;

    if (!frame) return 0;
    __asm__ __volatile__("mrs %0, mpidr_el1" : "=r"(mpidr));
    affinity = mpidr_affinity(mpidr);
    for (uint32_t index = 0; index < 16u; ++index) {
        uint64_t typer = *(volatile uint64_t *)(frame + GICR_TYPER);

        if ((uint32_t)(typer >> 32) == affinity)
            return (volatile uint32_t *)frame;
        if (typer & GICR_TYPER_LAST) break;
        frame += GICR_FRAME_STRIDE;
    }
    return 0;
}

static int gic_init_cpu_redistributor(int enable_timer) {
    volatile uint32_t *redistributor = gic_find_redistributor();
    uint32_t spins = 0;

    if (!redistributor) return -1;
    redistributor[GICR_WAKER / 4u] &= ~GICR_WAKER_PROCESSOR_SLEEP;
    while ((redistributor[GICR_WAKER / 4u] &
            GICR_WAKER_CHILDREN_ASLEEP) && spins++ < 1000000u)
        __asm__ __volatile__("yield");
    if (spins >= 1000000u) return -1;
    redistributor[GICR_IGROUPR0 / 4u] |=
        (1u << ARM64_RESCHEDULE_SGI) |
        (1u << ARM64_CALL_SGI) |
        (enable_timer ? (1u << ARM64_VIRTUAL_TIMER_PPI) : 0u);
    ((volatile uint8_t *)redistributor)[GICR_IPRIORITYR +
        ARM64_RESCHEDULE_SGI] = 0x80u;
    ((volatile uint8_t *)redistributor)[GICR_IPRIORITYR +
        ARM64_CALL_SGI] = 0x80u;
    redistributor[GICR_ISENABLER0 / 4u] =
        (1u << ARM64_RESCHEDULE_SGI) | (1u << ARM64_CALL_SGI);
    if (enable_timer) {
        ((volatile uint8_t *)redistributor)[GICR_IPRIORITYR +
            ARM64_VIRTUAL_TIMER_PPI] = 0x80u;
        redistributor[GICR_ISENABLER0 / 4u] =
            1u << ARM64_VIRTUAL_TIMER_PPI;
    }
    __asm__ __volatile__("dsb sy" ::: "memory");
    gic_enable_cpu_interface();
    return 0;
}

static int gicv2_init_cpu_interface(int enable_timer) {
    uint32_t enabled =
        (1u << ARM64_RESCHEDULE_SGI) |
        (1u << ARM64_CALL_SGI) |
        (enable_timer ? (1u << ARM64_VIRTUAL_TIMER_PPI) : 0u);

    if (!g_gicd || !g_gicc) return -1;
    g_gicd[GICD_IGROUPR / 4u] |= enabled;
    ((volatile uint8_t *)g_gicd)[GICD_IPRIORITYR +
        ARM64_RESCHEDULE_SGI] = 0x80u;
    ((volatile uint8_t *)g_gicd)[GICD_IPRIORITYR +
        ARM64_CALL_SGI] = 0x80u;
    if (enable_timer)
        ((volatile uint8_t *)g_gicd)[GICD_IPRIORITYR +
            ARM64_VIRTUAL_TIMER_PPI] = 0x80u;
    g_gicd[GICD_ICPENDR / 4u] = enabled;
    g_gicd[GICD_ISENABLER / 4u] = enabled;
    g_gicc[GICC_PMR / 4u] = 0xffu;
    g_gicc[GICC_BPR / 4u] = 0u;
    /*
     * Enable both interrupt groups. GICv2 implementations without security
     * extensions expose Group 0 and Group 1 directly and require AckCtl for
     * Group 1 to be returned through IAR. A non-secure access on a
     * security-aware GIC aliases bit 0 to Group 1 and ignores AckCtl.
     */
    g_gicc[GICC_CTLR / 4u] = 3u | GICC_CTLR_ACK_CTL;
    __asm__ __volatile__("dsb sy\n\tisb" ::: "memory");
    return 0;
}

static void arm64_timer_enable(void) {
    uint64_t freq;
    uint64_t period;
    uint64_t tval;
    uint64_t ctl = 1;
    uint64_t cntkctl;
    uint32_t cpu;
    uint32_t cpu_count;

    __asm__ __volatile__("mrs %0, cntkctl_el1" : "=r"(cntkctl));
    cntkctl |= 3u; /* EL0PCTEN | EL0VCTEN; compare/control registers stay EL1-only. */
    __asm__ __volatile__("msr cntkctl_el1, %0\n\tisb" :: "r"(cntkctl));
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(freq));
    period = freq / EDGE_KERNEL_TIMER_HZ;
    if (!period) period = 1;
    tval = period;
    cpu = edgeos_arm64_smp_current_cpu();
    cpu_count = edge_smp_present_count();
    /*
     * Spread per-CPU timer phases across one period.  Simultaneous timer
     * interrupts otherwise make every CPU contend for the serialized process
     * runtime at the same instant, allowing one CPU to win every tick while
     * compute-bound tasks on the others miss repeated preemption points.
     */
    if (cpu_count > 1u && cpu < cpu_count)
        tval += (period * cpu) / cpu_count;
    __asm__ __volatile__("msr cntv_tval_el0, %0" :: "r"(tval));
    __asm__ __volatile__("msr cntv_ctl_el0, %0\n\tisb" :: "r"(ctl));
}

void edgeos_arm64_timer_enter_idle(void) {
    uint64_t control = 3u; /* ENABLE | IMASK */

    /*
     * CPU 0 owns the global timer and deferred-work clocks. Secondary CPUs
     * have no local timeout queue, so their periodic scheduler tick has no
     * work to perform after the run queue becomes empty. Masking the local
     * timer here provides real tickless idle without reducing timeout
     * precision. A reschedule or device interrupt calls timer_leave_idle()
     * before returning to a newly runnable task.
     */
    if (edgeos_arm64_smp_current_cpu() == 0u) return;
    __asm__ __volatile__("msr cntv_ctl_el0, %0\n\tisb" :: "r"(control));
}

void edgeos_arm64_timer_leave_idle(void) {
    uint64_t frequency;
    uint64_t interval;
    uint64_t first_interval;
    uint64_t control = 1u;
    uint32_t cpu;
    uint32_t cpu_count;

    if (edgeos_arm64_smp_current_cpu() == 0u) return;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(frequency));
    interval = frequency / EDGE_KERNEL_TIMER_HZ;
    if (!interval) interval = 1u;
    first_interval = interval;
    cpu = edgeos_arm64_smp_current_cpu();
    cpu_count = edge_smp_present_count();
    /*
     * Preserve the phase separation established during CPU bring-up. If
     * several idle CPUs receive one workload burst, arming all of them at
     * the same deadline makes their scheduler interrupts contend with CPU 0
     * and can indefinitely postpone global timeout processing.
     */
    if (cpu_count > 1u && cpu < cpu_count)
        first_interval += (interval * cpu) / cpu_count;
    __asm__ __volatile__(
        "msr cntv_tval_el0, %0\n\t"
        "msr cntv_ctl_el0, %1\n\t"
        "isb"
        :: "r"(first_interval), "r"(control));
}

int edgeos_arm64_timer_arm_rseq_slice(uint32_t microseconds) {
    uint64_t frequency;
    uint64_t ticks;
    int64_t periodic_remaining;
    uint64_t control = 1u;
    uint32_t cpu = edgeos_arm64_smp_current_cpu();

    if (!microseconds || cpu >= EDGE_SMP_MAX_CPUS) return -1;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(frequency));
    ticks = (frequency * microseconds + 999999u) / 1000000u;
    if (!ticks) ticks = 1u;
    __asm__ __volatile__("mrs %0, cntv_tval_el0" : "=r"(periodic_remaining));
    if (periodic_remaining <= 0)
        periodic_remaining = (int64_t)(frequency / EDGE_KERNEL_TIMER_HZ);
    g_rseq_slice_timer_ticks[cpu] = ticks;
    g_rseq_period_saved_ticks[cpu] = (uint64_t)periodic_remaining;
    __atomic_store_n(&g_rseq_slice_timer_armed[cpu], 1u,
                     __ATOMIC_RELEASE);
    __asm__ __volatile__(
        "msr cntv_tval_el0, %0\n\t"
        "msr cntv_ctl_el0, %1\n\t"
        "isb"
        :: "r"(ticks), "r"(control));
    return 0;
}

void edgeos_arm64_timer_cancel_rseq_slice(void) {
    int64_t slice_remaining;
    uint64_t slice_ticks;
    uint64_t elapsed;
    uint64_t periodic_remaining;
    uint32_t cpu = edgeos_arm64_smp_current_cpu();

    if (cpu >= EDGE_SMP_MAX_CPUS ||
        !__atomic_exchange_n(&g_rseq_slice_timer_armed[cpu], 0u,
                             __ATOMIC_ACQ_REL))
        return;
    __asm__ __volatile__("mrs %0, cntv_tval_el0" : "=r"(slice_remaining));
    slice_ticks = g_rseq_slice_timer_ticks[cpu];
    elapsed = slice_remaining > 0 && (uint64_t)slice_remaining < slice_ticks ?
              slice_ticks - (uint64_t)slice_remaining : slice_ticks;
    periodic_remaining = g_rseq_period_saved_ticks[cpu];
    periodic_remaining = periodic_remaining > elapsed ?
                         periodic_remaining - elapsed : 1u;
    __asm__ __volatile__("msr cntv_tval_el0, %0\n\tisb" ::
                         "r"(periodic_remaining));
}

int edgeos_arm64_timer_consume_rseq_slice(void) {
    uint32_t cpu = edgeos_arm64_smp_current_cpu();
    uint64_t elapsed;
    uint64_t periodic_remaining;

    if (cpu >= EDGE_SMP_MAX_CPUS) return 0;
    if (!__atomic_exchange_n(&g_rseq_slice_timer_armed[cpu], 0u,
                             __ATOMIC_ACQ_REL))
        return 0;
    elapsed = g_rseq_slice_timer_ticks[cpu];
    periodic_remaining = g_rseq_period_saved_ticks[cpu];
    g_rseq_period_resume_ticks[cpu] = periodic_remaining > elapsed ?
                                      periodic_remaining - elapsed : 1u;
    return 1;
}

void edgeos_arm64_exceptions_init(void) {
    uint64_t vectors = (uint64_t)(uintptr_t)edgeos_arm64_vectors;
    __asm__ __volatile__("msr vbar_el1, %0\n\tisb" :: "r"(vectors) : "memory");
}

int edgeos_arm64_irq_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t dist;
    uint64_t redist;
    uint32_t distributor_control;
    uint32_t affinity_routing;

    if (edgeos_arm64_gic_discover(bootinfo, &dist, &redist) < 0) return -1;
    g_gicd = (volatile uint32_t *)(uintptr_t)dist;
    g_gicr_base = (volatile uint32_t *)(uintptr_t)redist;

    if (g_gic_version == 2u) {
        arm64_serial_puts("arm64: GICv2 distributor=");
        arm64_serial_hex64(dist);
        arm64_serial_puts(" cpu-interface=");
        arm64_serial_hex64(redist);
        arm64_serial_puts("\n");
        g_gicc = (volatile uint32_t *)(uintptr_t)redist;
        g_gicd[GICD_CTLR / 4u] = 0u;
        __asm__ __volatile__("dsb sy" ::: "memory");
        g_gicd[GICD_CTLR / 4u] =
            GICD_CTLR_ENABLE_GRP0 | GICD_CTLR_ENABLE_GRP1NS;
        if (gicv2_init_cpu_interface(1) < 0) return -1;
        arm64_timer_enable();
        return 0;
    }
    if (g_gic_version != 3u) return -1;

    arm64_serial_puts("arm64: GICv3 distributor=");
    arm64_serial_hex64(dist);
    arm64_serial_puts(" redistributor=");
    arm64_serial_hex64(redist);
    arm64_serial_puts("\n");

    arm64_serial_puts("arm64: GICv3 disabling distributor\n");
    distributor_control = g_gicd[GICD_CTLR / 4u];
    affinity_routing = (distributor_control & GICD_CTLR_DS) ?
        GICD_CTLR_ARE : GICD_CTLR_ARE_NS;
    g_gicd[GICD_CTLR / 4u] = 0;
    gic_wait_rwp();
    g_gicd[GICD_CTLR / 4u] = affinity_routing;
    gic_wait_rwp();
    arm64_serial_puts("arm64: GICv3 waking redistributor\n");
    arm64_serial_puts("arm64: GICv3 enabling virtual timer PPI\n");
    g_gicd[GICD_CTLR / 4u] =
        affinity_routing | GICD_CTLR_ENABLE_GRP1NS;
    gic_wait_rwp();
    if (gic_init_cpu_redistributor(1) < 0) return -1;
    arm64_serial_puts("arm64: enabling architectural virtual timer\n");
    arm64_timer_enable();
    return 0;
}

int edgeos_arm64_irq_init_secondary(void) {
    if (!g_gicd || !g_gicr_base) return -1;
    if (g_gic_version == 2u) {
        if (gicv2_init_cpu_interface(1) < 0) return -1;
    } else if (g_gic_version == 3u) {
        if (gic_init_cpu_redistributor(1) < 0) return -1;
    } else {
        return -1;
    }
    arm64_timer_enable();
    return 0;
}

int edgeos_arm64_irq_register(uint32_t interrupt, uint32_t flags,
                              edgeos_arm64_irq_callback_t callback,
                              void *context) {
    uint32_t configuration;
    uint32_t shift;
    uint64_t affinity;

    if (!g_gicd || !callback || interrupt < 32u ||
        interrupt >= ARM64_GIC_INTERRUPT_MAX ||
        g_irq_callbacks[interrupt])
        return -1;
    g_irq_contexts[interrupt] = context;
    __atomic_store_n(&g_irq_callbacks[interrupt], callback,
                     __ATOMIC_RELEASE);

    g_gicd[(GICD_ICENABLER + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    gic_wait_rwp();
    g_gicd[(GICD_IGROUPR + (interrupt / 32u) * 4u) / 4u] |=
        1u << (interrupt % 32u);
    ((volatile uint8_t *)g_gicd)[GICD_IPRIORITYR + interrupt] = 0x80u;
    configuration = g_gicd[(GICD_ICFGR + (interrupt / 16u) * 4u) / 4u];
    shift = (interrupt % 16u) * 2u;
    configuration &= ~(3u << shift);
    if (flags & 3u) configuration |= 2u << shift;
    g_gicd[(GICD_ICFGR + (interrupt / 16u) * 4u) / 4u] = configuration;

    if (g_gic_version == 2u) {
        ((volatile uint8_t *)g_gicd)[GICD_ITARGETSR + interrupt] = 1u;
    } else {
        __asm__ __volatile__("mrs %0, mpidr_el1" : "=r"(affinity));
        affinity &= 0xff00ffffffULL;
        *(volatile uint64_t *)((volatile uint8_t *)g_gicd + GICD_IROUTER +
                               (uint64_t)interrupt * 8u) = affinity;
    }
    g_gicd[(GICD_ICPENDR + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    __asm__ __volatile__("dsb sy" ::: "memory");
    g_gicd[(GICD_ISENABLER + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    gic_wait_rwp();
    return 0;
}

int edgeos_arm64_irq_mask(uint32_t interrupt) {
    if (!g_gicd || interrupt < 32u ||
        interrupt >= ARM64_GIC_INTERRUPT_MAX ||
        !__atomic_load_n(&g_irq_callbacks[interrupt], __ATOMIC_ACQUIRE))
        return -1;
    g_gicd[(GICD_ICENABLER + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    gic_wait_rwp();
    return 0;
}

int edgeos_arm64_irq_unmask(uint32_t interrupt) {
    if (!g_gicd || interrupt < 32u ||
        interrupt >= ARM64_GIC_INTERRUPT_MAX ||
        !__atomic_load_n(&g_irq_callbacks[interrupt], __ATOMIC_ACQUIRE))
        return -1;
    g_gicd[(GICD_ISENABLER + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    gic_wait_rwp();
    return 0;
}

int edgeos_arm64_irq_unregister(uint32_t interrupt,
                                edgeos_arm64_irq_callback_t callback,
                                void *context) {
    if (!g_gicd || !callback || interrupt < 32u ||
        interrupt >= ARM64_GIC_INTERRUPT_MAX ||
        __atomic_load_n(&g_irq_callbacks[interrupt], __ATOMIC_ACQUIRE) !=
            callback ||
        g_irq_contexts[interrupt] != context)
        return -1;
    g_gicd[(GICD_ICENABLER + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    gic_wait_rwp();
    __atomic_store_n(&g_irq_callbacks[interrupt], 0, __ATOMIC_RELEASE);
    while (__atomic_load_n(&g_irq_active[interrupt],
                           __ATOMIC_ACQUIRE) != 0)
        __asm__ __volatile__("yield");
    g_irq_contexts[interrupt] = 0;
    g_gicd[(GICD_ICPENDR + (interrupt / 32u) * 4u) / 4u] =
        1u << (interrupt % 32u);
    __asm__ __volatile__("dsb sy" ::: "memory");
    return 0;
}

static void arm64_serial_puts(const char *s) {
    while (*s) edgeos_arm64_platform_serial_write(*s++);
}

static void arm64_serial_hex64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    int i;
    arm64_serial_puts("0x");
    for (i = 15; i >= 0; --i) {
        char ch = digits[(value >> ((uint64_t)i * 4u)) & 0xfu];
        edgeos_arm64_platform_serial_write(ch);
    }
}

static void arm64_finish_user_fp_return(int execution_locked) {
    if (!execution_locked) return;
    /*
     * Select and restore the current task's SIMD state while the scheduler
     * ownership protected by the execution lock is still stable.  The kernel
     * is built with general-register-only code, and a nested IRQ saves and
     * restores this same task state if the saved IRQ flags permit one after
     * the lock is released.
     */
    kernel_restore_current_fp();
    edgeos_arm64_kernel_execution_exit();
}

void edgeos_arm64_sync_handler(edgeos_arm64_exception_frame_t *frame) {
    uint32_t ec;
    int execution_locked = 0;
    if (frame) {
        if ((frame->spsr & 0xfu) == 0u) {
            edgeos_arm64_kernel_execution_enter_from_user();
            execution_locked = 1;
            kernel_save_current_fp();
            kernel_finish_deferred_group_exit();
        }
        ec = (uint32_t)(frame->esr >> 26);
        if (ec == 0x15u) {
            edgeos_arm64_syscall_dispatch(frame);
            kernel_reschedule(frame);
            /*
             * An input IRQ can publish deferred work on a CPU that cannot
             * acquire the serialized runtime while this CPU owns it for a
             * syscall.  Treat a successful syscall return as a mandatory
             * process-context boundary for that work.  Otherwise a dense
             * browser syscall stream can reacquire the runtime repeatedly
             * and leave evdev readers or display completion waiting for a
             * later timer tick.
             */
            if (kernel_deferred_work_service_pending(
                    edgeos_arm64_smp_current_cpu()))
                kernel_preempt(frame);
            kernel_deliver_signal(frame);
            arm64_finish_user_fp_return(execution_locked);
            return;
        }
        if ((frame->spsr & 0xfu) == 0u) {
            if (ec == 0x18u && arm64_emulate_user_id_register(frame) == 0) {
                arm64_finish_user_fp_return(execution_locked);
                return;
            }
            /* Linux reports EL0 debug exceptions to the faulting task. */
            if (ec == 0x30u || ec == 0x32u || ec == 0x34u || ec == 0x3cu) {
                if (edge_linux_ptrace_debug_stop(frame)) {
                    arm64_finish_user_fp_return(execution_locked);
                    return;
                }
                if (g_user_debug_fault_log_budget) {
                    uint64_t offset = 0;
                    const char *image = kernel_current_mapping_name(frame->elr,
                                                                     &offset);
                    --g_user_debug_fault_log_budget;
                    arm64_serial_puts("[arm64-debug-fault] ec=");
                    arm64_serial_hex64(ec);
                    arm64_serial_puts(" esr=");
                    arm64_serial_hex64(frame->esr);
                    arm64_serial_puts(" elr=");
                    arm64_serial_hex64(frame->elr);
                    arm64_serial_puts(" far=");
                    arm64_serial_hex64(frame->far);
                    arm64_serial_puts(" lr=");
                    arm64_serial_hex64(frame->x[30]);
                    arm64_serial_puts(" fp=");
                    arm64_serial_hex64(frame->x[29]);
                    arm64_serial_puts(" sp=");
                    arm64_serial_hex64(frame->sp_el0);
                    arm64_serial_puts(" pid=");
                    arm64_serial_hex64((uint64_t)(uint32_t)kernel_current_pid());
                    arm64_serial_puts(" comm=");
                    arm64_serial_puts(kernel_current_comm());
                    if (image) {
                        arm64_serial_puts(" image=");
                        arm64_serial_puts(image);
                        arm64_serial_puts("+");
                        arm64_serial_hex64(offset);
                    }
                    arm64_serial_puts("\n");
                }
                kernel_fault_current(5u); /* SIGTRAP */
            }
            if (ec == 0x00u || ec == 0x0eu || ec == 0x1cu) {
                if (g_user_illegal_fault_log_budget) {
                    uint64_t mapping_offset = 0;
                    uint64_t instruction_pair = 0;
                    uint64_t ttbr0;
                    const char *mapping_name =
                        kernel_current_mapping_name(frame->elr,
                                                    &mapping_offset);

                    --g_user_illegal_fault_log_budget;
                    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(ttbr0));
                    ttbr0 &= EDGEOS_ARM64_TTBR0_BASE_MASK;
                    (void)arm64_user_u64(ttbr0, frame->elr & ~7ull,
                                         &instruction_pair);
                    arm64_serial_puts("[arm64-user-sigill] ec=");
                    arm64_serial_hex64(ec);
                    arm64_serial_puts(" esr=");
                    arm64_serial_hex64(frame->esr);
                    arm64_serial_puts(" elr=");
                    arm64_serial_hex64(frame->elr);
                    arm64_serial_puts(" insn=");
                    arm64_serial_hex64(
                        (instruction_pair >> ((frame->elr & 4u) * 8u)) &
                        0xffffffffu);
                    arm64_serial_puts(" pid=");
                    arm64_serial_hex64(
                        (uint64_t)(uint32_t)kernel_current_pid());
                    arm64_serial_puts(" comm=");
                    arm64_serial_puts(kernel_current_comm());
                    if (mapping_name) {
                        arm64_serial_puts(" image=");
                        arm64_serial_puts(mapping_name);
                        arm64_serial_puts("+");
                        arm64_serial_hex64(mapping_offset);
                    }
                    arm64_serial_puts("\n");
                }
                kernel_fault_current(4u); /* SIGILL */
            }
        }
        if ((frame->spsr & 0xfu) == 0u &&
            kernel_deferred_work_service_pending(
                edgeos_arm64_smp_current_cpu())) {
            /*
             * Do not begin a potentially major file fault while an input or
             * display wakeup is already pending.  Saving this EL0 frame is
             * safe: the task retries the same instruction after it is chosen
             * again, exactly as it would after normal fault completion.
             */
            kernel_preempt(frame);
        }
        if (kernel_handle_page_fault(frame)) {
            /*
             * A sequential fault stream must not bypass deferred input and
             * display work.  Syscall and timer returns already pass through
             * the scheduler; apply the same boundary after a resolved EL0
             * fault so another runnable task can make progress before the
             * faulting thread immediately enters on the next page.
             */
            if ((frame->spsr & 0xfu) == 0u)
                kernel_preempt(frame);
            arm64_finish_user_fp_return(execution_locked);
            return;
        }
    }
    arm64_serial_puts("arm64: unhandled synchronous exception\n");
    if (frame) {
        arm64_serial_puts("  esr=");
        arm64_serial_hex64(frame->esr);
        arm64_serial_puts(" far=");
        arm64_serial_hex64(frame->far);
        arm64_serial_puts(" elr=");
        arm64_serial_hex64(frame->elr);
        arm64_serial_puts(" pid=");
        arm64_serial_hex64((uint64_t)(uint32_t)kernel_current_pid());
        arm64_serial_puts(" comm=");
        arm64_serial_puts(kernel_current_comm());
        arm64_serial_puts(" lr=");
        arm64_serial_hex64(frame->x[30]);
        arm64_serial_puts(" x0=");
        arm64_serial_hex64(frame->x[0]);
        arm64_serial_puts(" x1=");
        arm64_serial_hex64(frame->x[1]);
        arm64_serial_puts(" x2=");
        arm64_serial_hex64(frame->x[2]);
        arm64_serial_puts(" x3=");
        arm64_serial_hex64(frame->x[3]);
        arm64_serial_puts(" x29=");
        arm64_serial_hex64(frame->x[29]);
        arm64_serial_puts(" x19=");
        arm64_serial_hex64(frame->x[19]);
        arm64_serial_puts(" x20=");
        arm64_serial_hex64(frame->x[20]);
        arm64_serial_puts(" x21=");
        arm64_serial_hex64(frame->x[21]);
        arm64_serial_puts(" x22=");
        arm64_serial_hex64(frame->x[22]);
        arm64_serial_puts(" x23=");
        arm64_serial_hex64(frame->x[23]);
        arm64_serial_puts(" x24=");
        arm64_serial_hex64(frame->x[24]);
        arm64_serial_puts(" x25=");
        arm64_serial_hex64(frame->x[25]);
        arm64_serial_puts(" x26=");
        arm64_serial_hex64(frame->x[26]);
        arm64_serial_puts(" x27=");
        arm64_serial_hex64(frame->x[27]);
        arm64_serial_puts(" x28=");
        arm64_serial_hex64(frame->x[28]);
        arm64_serial_puts(" sp0=");
        arm64_serial_hex64(frame->sp_el0);
        arm64_serial_puts(" x8=");
        arm64_serial_hex64(frame->x[8]);
        {
            uint64_t mapping_offset = 0;
            const char *mapping_name = kernel_current_mapping_name(
                frame->elr, &mapping_offset);
            if (mapping_name) {
                arm64_serial_puts(" image=");
                arm64_serial_puts(mapping_name);
                arm64_serial_puts("+0x");
                arm64_serial_hex64(mapping_offset);
            }
        }
        {
            uint64_t mapping_start;
            uint64_t mapping_end;
            uint64_t file_offset;
            uint32_t inode;
            if (kernel_current_file_mapping_info(
                    frame->elr, &mapping_start, &mapping_end,
                    &file_offset, &inode) == 0) {
                arm64_serial_puts(" file-map=");
                arm64_serial_hex64(mapping_start);
                arm64_serial_puts("-");
                arm64_serial_hex64(mapping_end);
                arm64_serial_puts(" off=");
                arm64_serial_hex64(file_offset);
                arm64_serial_puts(" ino=");
                arm64_serial_hex64(inode);
            }
        }
        {
            uint64_t ttbr0;
            uint64_t pa;
            __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(ttbr0));
            ttbr0 &= EDGEOS_ARM64_TTBR0_BASE_MASK;
            if (frame->elr && edgeos_arm64_address_space_translate(
                    ttbr0, frame->elr, &pa, 0) == 0) {
                uint64_t free_caller;
                uint64_t alloc_caller;
                uint32_t references = edgeos_arm64_page_lifecycle(
                    pa, &free_caller, &alloc_caller);
                arm64_serial_puts(" insn-pa=");
                arm64_serial_hex64(pa);
                arm64_serial_puts(" insn=");
                arm64_serial_hex64(
                    *(const uint32_t *)(uintptr_t)(pa & ~3ULL));
                arm64_serial_puts(" insn-refs=");
                arm64_serial_hex64(references);
                arm64_serial_puts(" insn-aliases=");
                arm64_serial_hex64(
                    edgeos_arm64_address_space_count_physical_aliases(
                        pa & ~0xfffULL, 4096u));
                arm64_serial_puts(" insn-last-free=");
                arm64_serial_hex64(free_caller);
                arm64_serial_puts(" insn-last-alloc=");
                arm64_serial_hex64(alloc_caller);
            }
            if (frame->x[1] && edgeos_arm64_address_space_translate(
                    ttbr0, frame->x[1], &pa, 0) == 0) {
                arm64_serial_puts(" mem[x1]=");
                arm64_serial_hex64(*(uint64_t *)(uintptr_t)pa);
            }
            if (frame->x[29] >= 8u &&
                edgeos_arm64_address_space_translate(ttbr0,
                    frame->x[29] - 8u, &pa, 0) == 0) {
                uint64_t free_caller;
                uint64_t alloc_caller;
                uint32_t references = edgeos_arm64_page_lifecycle(
                    pa, &free_caller, &alloc_caller);
                arm64_serial_puts(" mem[x29-8]=");
                arm64_serial_hex64(*(uint64_t *)(uintptr_t)pa);
                arm64_serial_puts(" stack-pa=");
                arm64_serial_hex64(pa & ~0xfffULL);
                arm64_serial_puts(" refs=");
                arm64_serial_hex64(references);
                arm64_serial_puts(" last-free=");
                arm64_serial_hex64(free_caller);
                arm64_serial_puts(" last-alloc=");
                arm64_serial_hex64(alloc_caller);
            }
            if (frame->x[26] && edgeos_arm64_address_space_translate(
                    ttbr0, frame->x[26], &pa, 0) == 0) {
                arm64_serial_puts(" mem[x26]=");
                for (uint32_t index = 0; index < 5u; ++index) {
                    uint64_t item_pa;
                    if (edgeos_arm64_address_space_translate(ttbr0,
                            frame->x[26] + index * 8u, &item_pa, 0) < 0) break;
                    arm64_serial_hex64(*(uint64_t *)(uintptr_t)item_pa);
                    arm64_serial_puts(index == 4u ? "" : ",");
                }
            }
            if (frame->x[29])
                arm64_log_user_backtrace(ttbr0, frame->x[29]);
        }
        if (frame->far && frame->far < (1ULL << 48)) {
            uint64_t pa;
            uint64_t desc;
            uint64_t ttbr0;
            uint32_t prot;
            kernel_memory_mapping_info_t mapping;
            __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(ttbr0));
            arm64_serial_puts(" far-map=");
            if (edgeos_arm64_address_space_translate(
                    ttbr0 & EDGEOS_ARM64_TTBR0_BASE_MASK,
                    frame->far, &pa, &desc) == 0) {
                arm64_serial_puts("pa:");
                arm64_serial_hex64(pa);
                arm64_serial_puts(" desc:");
                arm64_serial_hex64(desc);
                arm64_serial_puts(" ttbr:");
                arm64_serial_hex64(ttbr0);
                if (edgeos_arm64_address_space_user_protection(
                        ttbr0 & EDGEOS_ARM64_TTBR0_BASE_MASK,
                        frame->far, &prot) == 0) {
                    arm64_serial_puts(" prot:");
                    arm64_serial_hex64(prot);
                }
                arm64_serial_puts(" bytes:");
                arm64_serial_hex64(*(uint64_t *)(uintptr_t)(pa & ~7ULL));
            } else {
                arm64_serial_puts("none");
            }
            arm64_serial_puts(" vma=");
            if (kernel_current_memory_mapping_info(frame->far, &mapping) == 0) {
                switch (mapping.kind) {
                case KERNEL_MEMORY_MAPPING_ANONYMOUS:
                    arm64_serial_puts("anon:");
                    break;
                case KERNEL_MEMORY_MAPPING_TMPFS:
                    arm64_serial_puts("tmpfs:");
                    break;
                case KERNEL_MEMORY_MAPPING_FILE:
                    arm64_serial_puts("file:");
                    break;
                default:
                    arm64_serial_puts("unknown:");
                    break;
                }
                arm64_serial_hex64(mapping.start);
                arm64_serial_puts("-");
                arm64_serial_hex64(mapping.end);
                arm64_serial_puts(" prot:");
                arm64_serial_hex64(mapping.protection);
                arm64_serial_puts(" shared:");
                arm64_serial_hex64(mapping.shared);
            } else {
                arm64_serial_puts("none");
            }
        }
        {
            uint64_t arguments[6];
            uint32_t syscall = kernel_current_last_syscall(arguments);
            arm64_serial_puts(" last-syscall=");
            arm64_serial_hex64(syscall);
            arm64_serial_puts(" args=");
            for (uint32_t index = 0; index < 6u; ++index) {
                arm64_serial_hex64(arguments[index]);
                if (index + 1u < 6u) arm64_serial_puts(",");
            }
        }
        arm64_serial_puts("\n");
        if ((frame->spsr & 0xfu) == 0u &&
            (ec == 0x20u || ec == 0x21u || ec == 0x24u || ec == 0x25u))
            kernel_fault_current(11u);
    }
    for (;;) __asm__ __volatile__("wfe");
}

void edgeos_arm64_irq_handler(edgeos_arm64_exception_frame_t *frame) {
    uint64_t iar;
    uint32_t intid;
    uint64_t freq;
    uint64_t tval;
    int execution_locked = 0;
    int rseq_slice_expired = 0;

    if (frame && (frame->spsr & 0xfu) == 0u) kernel_save_current_fp();
    if (g_gic_version == 2u)
        iar = g_gicc[GICC_IAR / 4u];
    else
        __asm__ __volatile__("mrs %0, icc_iar1_el1" : "=r"(iar));
    intid = (uint32_t)(iar & 0x00ffffffu);
    if (intid != ARM64_VIRTUAL_TIMER_PPI)
        edgeos_arm64_timer_leave_idle();
    if (intid == ARM64_VIRTUAL_TIMER_PPI) {
        rseq_slice_expired = edgeos_arm64_timer_consume_rseq_slice();
        execution_locked = edgeos_arm64_kernel_execution_try_enter();
        /*
         * CPU 0 advances the global timeout queues, but every CPU owns its
         * local fair-scheduler time slice. A timer interrupt taken from EL0
         * may wait for the serialized runtime safely and must eventually run.
         * Keeping secondary ticks try-only unless a remote wake marker exists
         * lets a syscall-heavy task miss every local preemption point after
         * the marker is consumed, starving sibling browser and compositor
         * threads for seconds. An EL1 tick inside an active kernel section
         * remains try-only and non-reentrant.
         */
        if (!execution_locked &&
            !edgeos_arm64_kernel_execution_waiting() &&
            ((frame && (frame->spsr & 0xfu) == 0u) ||
             (edgeos_arm64_smp_current_cpu() == 0u &&
              kernel_scheduler_cpu_is_idle()))) {
            if (frame && (frame->spsr & 0xfu) == 0u)
                edgeos_arm64_kernel_execution_enter_from_user();
            else
                edgeos_arm64_kernel_execution_enter();
            execution_locked = 1;
        }
        if (execution_locked && !rseq_slice_expired) {
            if (edgeos_arm64_smp_current_cpu() == 0u) {
                ++g_timer_ticks;
                fb_console_request_tick_from_irq((uint32_t)g_timer_ticks);
            }
            kernel_timer_tick(
                edgeos_arm64_smp_current_cpu() == 0u,
                frame && (frame->spsr & 0xfu) == 0u);
        }
        __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(freq));
        if (rseq_slice_expired)
            tval = __atomic_exchange_n(
                &g_rseq_period_resume_ticks[
                    edgeos_arm64_smp_current_cpu()], 0u,
                __ATOMIC_ACQ_REL);
        else
            tval = freq / EDGE_KERNEL_TIMER_HZ;
        if (!tval) tval = 1;
        __asm__ __volatile__(
            "msr cntv_tval_el0, %0\n\t"
            "msr cntv_ctl_el0, %1\n\t"
            "isb"
            :: "r"(tval), "r"(1u));
    } else if (intid == ARM64_RESCHEDULE_SGI) {
        __asm__ __volatile__("dmb ish" ::: "memory");
        execution_locked = edgeos_arm64_kernel_execution_try_enter();
    } else if (intid == ARM64_CALL_SGI) {
        edge_smp_handle_call(edgeos_arm64_smp_current_cpu());
    } else if (intid < ARM64_GIC_INTERRUPT_MAX) {
        __atomic_add_fetch(&g_irq_active[intid], 1, __ATOMIC_ACQ_REL);
        edgeos_arm64_irq_callback_t callback =
            __atomic_load_n(&g_irq_callbacks[intid], __ATOMIC_ACQUIRE);
        if (callback) callback(intid, g_irq_contexts[intid]);
        __atomic_sub_fetch(&g_irq_active[intid], 1, __ATOMIC_ACQ_REL);
        /*
         * A latency-sensitive device callback only publishes process-context
         * work. If this IRQ interrupted userspace and the runtime owner is
         * immediately available, enter the scheduler before returning so an
         * evdev reader does not wait for a later timer tick. Contended entry
         * remains non-blocking; the regular timer path will consume the latch.
         */
        if (frame && (frame->spsr & 0xfu) == 0u &&
            kernel_deferred_work_service_pending(
                edgeos_arm64_smp_current_cpu()))
            execution_locked = edgeos_arm64_kernel_execution_try_enter();
    }
    if (g_gic_version == 2u)
        g_gicc[GICC_EOIR / 4u] = (uint32_t)iar;
    else
        __asm__ __volatile__("msr icc_eoir1_el1, %0" :: "r"(iar));
    if (execution_locked && frame && (frame->spsr & 0xfu) == 0u)
        kernel_finish_deferred_group_exit();
    if (execution_locked)
        kernel_preempt(frame);
    if (frame && (frame->spsr & 0xfu) == 0u) {
        kernel_restore_current_fp();
    }
    if (execution_locked) edgeos_arm64_kernel_execution_exit();
}

uint64_t edgeos_arm64_timer_ticks(void) {
    return g_timer_ticks;
}

void edgeos_arm64_fiq_handler(edgeos_arm64_exception_frame_t *frame) {
    (void)frame;
    arm64_serial_puts("arm64: unhandled FIQ\n");
    for (;;) __asm__ __volatile__("wfe");
}

void edgeos_arm64_serror_handler(edgeos_arm64_exception_frame_t *frame) {
    (void)frame;
    arm64_serial_puts("arm64: asynchronous system error\n");
    for (;;) __asm__ __volatile__("wfe");
}
