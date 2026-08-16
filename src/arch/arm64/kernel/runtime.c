/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 CPU-local mechanisms used by architecture-neutral kernel policy. */

#include <stdint.h>
#include "arch/arm64/smp.h"
#include "arch/arm64/user_layout.h"
#include "dev/alsa.h"
#include "kernel/arch_cpu.h"
#include "kernel/proc_platform.h"
#include "kernel/smp.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
extern _Bool psci_conduit_is_smc(void);
#endif

uint64_t arch_cpu_current_task(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, tpidr_el1" : "=r"(value));
    return value;
}

void arch_cpu_set_current_task(uint64_t task) {
    __asm__ __volatile__("msr tpidr_el1, %0" :: "r"(task) : "memory");
}

uint64_t arch_cpu_user_tls(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, tpidr_el0" : "=r"(value));
    return value;
}

void arch_cpu_set_user_tls(uint64_t tls) {
    __asm__ __volatile__("msr tpidr_el0, %0\n\tisb" :: "r"(tls) : "memory");
}

__attribute__((naked, target("fp"))) void arch_cpu_save_user_fp(void *state) {
    __asm__ __volatile__(
        "stp q0, q1, [x0, #0]\n\tstp q2, q3, [x0, #32]\n\t"
        "stp q4, q5, [x0, #64]\n\tstp q6, q7, [x0, #96]\n\t"
        "stp q8, q9, [x0, #128]\n\tstp q10, q11, [x0, #160]\n\t"
        "stp q12, q13, [x0, #192]\n\tstp q14, q15, [x0, #224]\n\t"
        "stp q16, q17, [x0, #256]\n\tstp q18, q19, [x0, #288]\n\t"
        "stp q20, q21, [x0, #320]\n\tstp q22, q23, [x0, #352]\n\t"
        "stp q24, q25, [x0, #384]\n\tstp q26, q27, [x0, #416]\n\t"
        "stp q28, q29, [x0, #448]\n\tstp q30, q31, [x0, #480]\n\t"
        "mrs x1, fpsr\n\tmrs x2, fpcr\n\tadd x3, x0, #512\n\t"
        "stp x1, x2, [x3]\n\tret");
}

__attribute__((naked, target("fp"))) void arch_cpu_restore_user_fp(const void *state) {
    __asm__ __volatile__(
        "ldp q0, q1, [x0, #0]\n\tldp q2, q3, [x0, #32]\n\t"
        "ldp q4, q5, [x0, #64]\n\tldp q6, q7, [x0, #96]\n\t"
        "ldp q8, q9, [x0, #128]\n\tldp q10, q11, [x0, #160]\n\t"
        "ldp q12, q13, [x0, #192]\n\tldp q14, q15, [x0, #224]\n\t"
        "ldp q16, q17, [x0, #256]\n\tldp q18, q19, [x0, #288]\n\t"
        "ldp q20, q21, [x0, #320]\n\tldp q22, q23, [x0, #352]\n\t"
        "ldp q24, q25, [x0, #384]\n\tldp q26, q27, [x0, #416]\n\t"
        "ldp q28, q29, [x0, #448]\n\tldp q30, q31, [x0, #480]\n\t"
        "add x3, x0, #512\n\tldp x1, x2, [x3]\n\t"
        "msr fpsr, x1\n\tmsr fpcr, x2\n\tret");
}

void arch_cpu_set_user_single_step(int enabled) {
    uint64_t mdscr;
    __asm__ __volatile__("mrs %0, mdscr_el1" : "=r"(mdscr));
    if (enabled) {
        /* SS, KDE, and MDE route an EL0 software-step event to EL1. */
        mdscr |= (1ULL << 0) | (1ULL << 13) | (1ULL << 15);
    } else {
        mdscr &= ~((1ULL << 0) | (1ULL << 13) | (1ULL << 15));
    }
    __asm__ __volatile__("msr mdscr_el1, %0\n\tisb" :: "r"(mdscr) :
                         "memory");
}

uint64_t arch_cpu_stack_pointer(void) {
    uint64_t value;
    __asm__ __volatile__("mov %0, sp" : "=r"(value));
    return value;
}

__attribute__((naked, noreturn)) void arch_cpu_call_on_stack(
        uint64_t stack_pointer, arch_cpu_stack_entry_t entry,
        uint32_t argument) {
    __asm__ __volatile__(
        "msr daifset, #0xf\n\t"
        "mov sp, x0\n\t"
        "mov x0, x2\n\t"
        "br x1");
}

uint64_t arch_cpu_cycle_counter(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

uint64_t arch_cpu_user_stack_top(void) {
    return EDGEOS_ARM64_USER_STACK_TOP;
}

uint64_t arch_cpu_user_vdso_base(void) {
    return (EDGEOS_ARM64_USER_STACK_TOP -
            16ULL * 1024ULL * 1024ULL) & ~0xffffULL;
}

#define ARM64_HWCAP_FP          (1ULL << 0)
#define ARM64_HWCAP_ASIMD       (1ULL << 1)
#define ARM64_HWCAP_AES         (1ULL << 3)
#define ARM64_HWCAP_PMULL       (1ULL << 4)
#define ARM64_HWCAP_SHA1        (1ULL << 5)
#define ARM64_HWCAP_SHA2        (1ULL << 6)
#define ARM64_HWCAP_CRC32       (1ULL << 7)
#define ARM64_HWCAP_ATOMICS     (1ULL << 8)
#define ARM64_HWCAP_FPHP        (1ULL << 9)
#define ARM64_HWCAP_ASIMDHP     (1ULL << 10)
#define ARM64_HWCAP_CPUID       (1ULL << 11)
#define ARM64_HWCAP_ASIMDRDM    (1ULL << 12)
#define ARM64_HWCAP_JSCVT       (1ULL << 13)
#define ARM64_HWCAP_FCMA        (1ULL << 14)
#define ARM64_HWCAP_LRCPC       (1ULL << 15)
#define ARM64_HWCAP_SHA3        (1ULL << 17)
#define ARM64_HWCAP_SM3         (1ULL << 18)
#define ARM64_HWCAP_SM4         (1ULL << 19)
#define ARM64_HWCAP_ASIMDDP     (1ULL << 20)
#define ARM64_HWCAP_SHA512      (1ULL << 21)
#define ARM64_HWCAP_ASIMDFHM    (1ULL << 23)
#define ARM64_HWCAP_DIT         (1ULL << 24)
#define ARM64_HWCAP_ILRCPC      (1ULL << 26)
#define ARM64_HWCAP_FLAGM       (1ULL << 27)
#define ARM64_HWCAP_SB          (1ULL << 29)

static uint32_t arm64_feature_field(uint64_t value, uint32_t shift) {
    return (uint32_t)((value >> shift) & 0xfu);
}

uint64_t arch_cpu_user_hwcap(void) {
    uint64_t isar0;
    uint64_t isar1;
    uint64_t pfr0;
    uint64_t capabilities = ARM64_HWCAP_CPUID;

    __asm__ __volatile__("mrs %0, id_aa64isar0_el1" : "=r"(isar0));
    __asm__ __volatile__("mrs %0, id_aa64isar1_el1" : "=r"(isar1));
    __asm__ __volatile__("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));

    if (arm64_feature_field(pfr0, 16u) != 0xfu)
        capabilities |= ARM64_HWCAP_FP;
    if (arm64_feature_field(pfr0, 20u) != 0xfu)
        capabilities |= ARM64_HWCAP_ASIMD;
    if (arm64_feature_field(pfr0, 16u) >= 1u &&
        arm64_feature_field(pfr0, 16u) != 0xfu)
        capabilities |= ARM64_HWCAP_FPHP;
    if (arm64_feature_field(pfr0, 20u) >= 1u &&
        arm64_feature_field(pfr0, 20u) != 0xfu)
        capabilities |= ARM64_HWCAP_ASIMDHP;
    if (arm64_feature_field(pfr0, 48u) >= 1u)
        capabilities |= ARM64_HWCAP_DIT;

    if (arm64_feature_field(isar0, 4u) >= 1u)
        capabilities |= ARM64_HWCAP_AES;
    if (arm64_feature_field(isar0, 4u) >= 2u)
        capabilities |= ARM64_HWCAP_PMULL;
    if (arm64_feature_field(isar0, 8u) >= 1u)
        capabilities |= ARM64_HWCAP_SHA1;
    if (arm64_feature_field(isar0, 12u) >= 1u)
        capabilities |= ARM64_HWCAP_SHA2;
    if (arm64_feature_field(isar0, 12u) >= 2u)
        capabilities |= ARM64_HWCAP_SHA512;
    if (arm64_feature_field(isar0, 16u) >= 1u)
        capabilities |= ARM64_HWCAP_CRC32;
    if (arm64_feature_field(isar0, 20u) >= 2u)
        capabilities |= ARM64_HWCAP_ATOMICS;
    if (arm64_feature_field(isar0, 28u) >= 1u)
        capabilities |= ARM64_HWCAP_ASIMDRDM;
    if (arm64_feature_field(isar0, 32u) >= 1u)
        capabilities |= ARM64_HWCAP_SHA3;
    if (arm64_feature_field(isar0, 36u) >= 1u)
        capabilities |= ARM64_HWCAP_SM3;
    if (arm64_feature_field(isar0, 40u) >= 1u)
        capabilities |= ARM64_HWCAP_SM4;
    if (arm64_feature_field(isar0, 44u) >= 1u)
        capabilities |= ARM64_HWCAP_ASIMDDP;
    if (arm64_feature_field(isar0, 48u) >= 1u)
        capabilities |= ARM64_HWCAP_ASIMDFHM;
    if (arm64_feature_field(isar0, 52u) >= 1u)
        capabilities |= ARM64_HWCAP_FLAGM;

    if (arm64_feature_field(isar1, 12u) >= 1u)
        capabilities |= ARM64_HWCAP_JSCVT;
    if (arm64_feature_field(isar1, 16u) >= 1u)
        capabilities |= ARM64_HWCAP_FCMA;
    if (arm64_feature_field(isar1, 20u) >= 1u)
        capabilities |= ARM64_HWCAP_LRCPC;
    if (arm64_feature_field(isar1, 20u) >= 2u)
        capabilities |= ARM64_HWCAP_ILRCPC;
    if (arm64_feature_field(isar1, 36u) >= 1u)
        capabilities |= ARM64_HWCAP_SB;
    return capabilities;
}
uint64_t arch_cpu_user_hwcap2(void) { return 0u; }

static int cpuinfo_append(char *buffer, uint32_t capacity, uint32_t *length,
                          const char *text) {
    if (!buffer || !length || !text) return -1;
    while (*text) {
        if (*length + 1u >= capacity) return -1;
        buffer[(*length)++] = *text++;
    }
    buffer[*length] = 0;
    return 0;
}

static int cpuinfo_append_u64(char *buffer, uint32_t capacity,
                              uint32_t *length, uint64_t value,
                              uint32_t radix) {
    static const char digits[] = "0123456789abcdef";
    char reversed[24];
    uint32_t count = 0;
    if (radix != 10u && radix != 16u) return -1;
    if (!value) reversed[count++] = '0';
    while (value && count < sizeof(reversed)) {
        reversed[count++] = digits[value % radix];
        value /= radix;
    }
    while (count) {
        char byte[2] = { reversed[--count], 0 };
        if (cpuinfo_append(buffer, capacity, length, byte) < 0) return -1;
    }
    return 0;
}

static int cpuinfo_append_features(char *buffer, uint32_t capacity,
                                   uint32_t *length) {
    static const struct {
        uint64_t bit;
        const char *name;
    } features[] = {
        { ARM64_HWCAP_FP, "fp" },
        { ARM64_HWCAP_ASIMD, "asimd" },
        { ARM64_HWCAP_AES, "aes" },
        { ARM64_HWCAP_PMULL, "pmull" },
        { ARM64_HWCAP_SHA1, "sha1" },
        { ARM64_HWCAP_SHA2, "sha2" },
        { ARM64_HWCAP_CRC32, "crc32" },
        { ARM64_HWCAP_ATOMICS, "atomics" },
        { ARM64_HWCAP_FPHP, "fphp" },
        { ARM64_HWCAP_ASIMDHP, "asimdhp" },
        { ARM64_HWCAP_CPUID, "cpuid" },
        { ARM64_HWCAP_ASIMDRDM, "asimdrdm" },
        { ARM64_HWCAP_JSCVT, "jscvt" },
        { ARM64_HWCAP_FCMA, "fcma" },
        { ARM64_HWCAP_LRCPC, "lrcpc" },
        { ARM64_HWCAP_SHA3, "sha3" },
        { ARM64_HWCAP_SM3, "sm3" },
        { ARM64_HWCAP_SM4, "sm4" },
        { ARM64_HWCAP_ASIMDDP, "asimddp" },
        { ARM64_HWCAP_SHA512, "sha512" },
        { ARM64_HWCAP_ASIMDFHM, "asimdfhm" },
        { ARM64_HWCAP_DIT, "dit" },
        { ARM64_HWCAP_ILRCPC, "ilrcpc" },
        { ARM64_HWCAP_FLAGM, "flagm" },
        { ARM64_HWCAP_SB, "sb" },
    };
    uint64_t capabilities = arch_cpu_user_hwcap();

    if (cpuinfo_append(buffer, capacity, length, "Features\t:") < 0)
        return -1;
    for (uint32_t index = 0;
         index < sizeof(features) / sizeof(features[0]); ++index) {
        if (!(capabilities & features[index].bit)) continue;
        if (cpuinfo_append(buffer, capacity, length, " ") < 0 ||
            cpuinfo_append(buffer, capacity, length,
                           features[index].name) < 0)
            return -1;
    }
    return cpuinfo_append(buffer, capacity, length, "\n");
}

static const char *cpuinfo_implementer_name(uint32_t implementer) {
    switch (implementer) {
    case 0x41u: return "ARM";
    case 0x42u: return "Broadcom";
    case 0x43u: return "Cavium";
    case 0x46u: return "Fujitsu";
    case 0x48u: return "HiSilicon";
    case 0x4eu: return "NVIDIA";
    case 0x50u: return "APM";
    case 0x51u: return "Qualcomm";
    case 0x61u: return "Apple";
    case 0xc0u: return "Ampere";
    default: return "ARM64";
    }
}

int arch_cpu_proc_info(char *buffer, uint32_t capacity) {
    uint64_t midr;
    uint32_t length = 0;
    uint32_t implementer;
    uint32_t variant;
    uint32_t part;
    uint32_t revision;

    if (!buffer || capacity < 2u) return -1;
    __asm__ __volatile__("mrs %0, midr_el1" : "=r"(midr));
    implementer = (uint32_t)((midr >> 24) & 0xffu);
    variant = (uint32_t)((midr >> 20) & 0xfu);
    part = (uint32_t)((midr >> 4) & 0xfffu);
    revision = (uint32_t)(midr & 0xfu);

    for (uint32_t cpu = 0; cpu < edge_smp_nr_cpu_ids(); ++cpu) {
        if (edge_smp_cpu_state(cpu) != EDGE_CPU_ONLINE) continue;
        if (cpuinfo_append(buffer, capacity, &length,
                "processor\t: ") < 0 ||
            cpuinfo_append_u64(buffer, capacity, &length, cpu, 10u) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                "\nmodel name\t: ") < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                           cpuinfo_implementer_name(implementer)) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                " ARM64 CPU part 0x") < 0 ||
            cpuinfo_append_u64(buffer, capacity, &length, part, 16u) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                "\nBogoMIPS\t: 100.00\n") < 0 ||
            cpuinfo_append_features(buffer, capacity, &length) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                "CPU implementer\t: 0x") < 0 ||
            cpuinfo_append_u64(buffer, capacity, &length,
                               implementer, 16u) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                "\nCPU architecture: 8\nCPU variant\t: 0x") < 0 ||
            cpuinfo_append_u64(buffer, capacity, &length, variant, 16u) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                "\nCPU part\t: 0x") < 0 ||
            cpuinfo_append_u64(buffer, capacity, &length, part, 16u) < 0 ||
            cpuinfo_append(buffer, capacity, &length,
                "\nCPU revision\t: ") < 0 ||
            cpuinfo_append_u64(buffer, capacity, &length, revision, 10u) < 0 ||
            cpuinfo_append(buffer, capacity, &length, "\n\n") < 0)
            return -1;
    }
    return (int)length;
}

int arch_cpu_proc_ioports(char *buffer, uint32_t capacity) {
    if (!buffer || !capacity) return -1;
    buffer[0] = 0;
    return 0;
}

void arch_cpu_relax(void) { __asm__ __volatile__("yield"); }

int arch_proc_filesystem_available(kernel_proc_filesystem_kind_t kind) {
    return kind == KERNEL_PROC_FS_EXT4;
}

int arch_proc_sound_available(void) { return alsa_available(); }

int arch_proc_sound_read(const char *name, char *buffer,
                         uint32_t capacity) {
    return alsa_proc_read(name, buffer, capacity);
}
void arch_cpu_wait_event(void) { __asm__ __volatile__("wfe"); }
void arch_cpu_idle(void) { __asm__ __volatile__("wfi"); }

void arch_cpu_idle_irq_window(void) {
    edgeos_arm64_smp_idle_irq_window();
}

void arch_cpu_memory_barrier(void) { __asm__ __volatile__("dmb ish" ::: "memory"); }
void arch_cpu_sync_barrier(void) { __asm__ __volatile__("dsb ish" ::: "memory"); }

void arch_cpu_sync_instruction_stream(void) {
    __asm__ __volatile__("dsb ish\n\tic iallu\n\tdsb ish\n\tisb" ::: "memory");
}

void arch_cpu_clean_data_range(const void *address, uint64_t length) {
    uint64_t ctr;
    uint64_t line_size;
    uint64_t start;
    uint64_t end;
    if (!address || !length) return;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    line_size = 4ULL << ((ctr >> 16) & 0xfu);
    start = (uint64_t)(uintptr_t)address & ~(line_size - 1u);
    end = ((uint64_t)(uintptr_t)address + length + line_size - 1u) &
          ~(line_size - 1u);
    for (; start < end; start += line_size)
        __asm__ __volatile__("dc cvac, %0" :: "r"(start) : "memory");
    __asm__ __volatile__("dsb osh" ::: "memory");
}

void arch_cpu_invalidate_data_range(const void *address, uint64_t length) {
    uint64_t ctr;
    uint64_t line_size;
    uint64_t start;
    uint64_t end;
    if (!address || !length) return;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    line_size = 4ULL << ((ctr >> 16) & 0xfu);
    start = (uint64_t)(uintptr_t)address & ~(line_size - 1u);
    end = ((uint64_t)(uintptr_t)address + length + line_size - 1u) &
          ~(line_size - 1u);
    for (; start < end; start += line_size)
        __asm__ __volatile__("dc ivac, %0" :: "r"(start) : "memory");
    __asm__ __volatile__("dsb osh" ::: "memory");
}

__attribute__((noreturn)) void arch_cpu_power_control(int reboot) {
    register uint64_t function __asm__("x0") = reboot ? 0x84000009u : 0x84000008u;
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    if (psci_conduit_is_smc())
        __asm__ __volatile__("smc #0" : "+r"(function) :: "memory");
    else
        __asm__ __volatile__("hvc #0" : "+r"(function) :: "memory");
#else
    __asm__ __volatile__("hvc #0" : "+r"(function) :: "memory");
#endif
    for (;;) arch_cpu_wait_event();
}
