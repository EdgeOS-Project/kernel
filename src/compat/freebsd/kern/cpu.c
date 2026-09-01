/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-neutral CPU services for imported FreeBSD drivers.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdbool.h>

#include "compat/freebsd/edgeos/cpu.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/machine/cputypes.h"
#if defined(__x86_64__)
#include "compat/freebsd/machine/fpu.h"
#endif
#include "compat/freebsd/machine/md_var.h"
#if defined(__x86_64__)
#include "compat/freebsd/machine/frame.h"
#include "compat/freebsd/x86/ucode.h"
#endif
#include "compat/freebsd/machine/specialreg.h"
#include "compat/freebsd/sys/_callout.h"
#include "compat/freebsd/sys/pcpu.h"
#include "compat/freebsd/sys/smp.h"
#include "sys/boottime.h"

#ifndef BSD_BRIDGE_HOST_TEST
#include "kernel/smp.h"
#include "mm/arch_vm.h"
#if defined(__x86_64__)
#include "arch/x86_64/task.h"
#endif
#endif

#define BSD_CPU_EINVAL 22
#define BSD_CPU_EFAULT 14
#define BSD_CPU_EOPNOTSUPP 45

unsigned int cpu_power_eax;
int cpu_clflush_line_size = 64;
unsigned int cpu_power_ecx;
unsigned int cpu_id;
unsigned int cpu_high;
unsigned int cpu_exthigh;
unsigned int cpu_feature;
unsigned int cpu_feature2;
unsigned int cpu_stdext_feature;
unsigned int cpu_stdext_feature2;
unsigned int cpu_stdext_feature3;
unsigned int cpu_stdext_feature4;
uint64_t cpu_ia32_arch_caps;
unsigned int cpu_vendor_id;
unsigned int cpu_mon_mwait_edx;
unsigned int amd_pminfo;
unsigned int amd_feature;
unsigned int amd_feature2;
unsigned int amd_extended_feature_extensions;
unsigned int cpu_procinfo2;
char cpu_vendor[13];
uint64_t tsc_freq;
int tsc_is_invariant;
int smp_tsc;
int cpu_disable_c2_sleep;
int cpu_disable_c3_sleep;
int nmi_flush_l1d_sw;
vm_paddr_t intel_graphics_stolen_base;
vm_paddr_t intel_graphics_stolen_size;
int use_xsave;
uint64_t xsave_mask;
extern unsigned long physmem;
void (*cpu_idle_hook)(sbintime_t);
#if defined(__x86_64__)
void (*vmm_suspend_p)(void);
void (*vmm_resume_p)(void);

/*
 * Keep the FreeBSD VMM's L1TF software-flush contract.  The routine is
 * intentionally ABI-special: vmx_support.S permits it to clobber RBX and the
 * ordinary caller wrapper preserves RBX.
 */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global flush_l1d_sw\n"
    ".type flush_l1d_sw,@function\n"
    "flush_l1d_sw:\n"
    "movq $0x08000000, %r9\n"
    "movq $-65536, %rcx\n"
    "1: movb 65536(%r9,%rcx), %al\n"
    "addq $4096, %rcx\n"
    "jne 1b\n"
    "xorl %eax, %eax\n"
    "cpuid\n"
    "movq $-65536, %rcx\n"
    "2: movb 65536(%r9,%rcx), %al\n"
    "addq $64, %rcx\n"
    "jne 2b\n"
    "lfence\n"
    "ret\n"
    ".size flush_l1d_sw, .-flush_l1d_sw\n"
    ".global flush_l1d_sw_abi\n"
    ".type flush_l1d_sw_abi,@function\n"
    "flush_l1d_sw_abi:\n"
    "pushq %rbx\n"
    "call flush_l1d_sw\n"
    "popq %rbx\n"
    "ret\n"
    ".size flush_l1d_sw_abi, .-flush_l1d_sw_abi\n");
#endif

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
static void *g_bsd_cpu_microcode;

int
ucode_intel_load(const void *data, ucode_load_how how,
    uint64_t *new_revision, uint64_t *old_revision)
{
    uint32_t registers[4];
    uint64_t old_value;
    uint64_t new_value;
    int error;

    if (!data)
        return BSD_CPU_EINVAL;
    old_value = rdmsr(MSR_BIOS_SIGN) >> 32;
    __asm__ __volatile__("wbinvd" : : : "memory");
    if (how == SAFE) {
        error = wrmsr_safe(MSR_BIOS_UPDT_TRIG,
            (uint64_t)(uintptr_t)data);
        if (error)
            return error;
    } else {
        wrmsr(MSR_BIOS_UPDT_TRIG, (uint64_t)(uintptr_t)data);
    }
    error = wrmsr_safe(MSR_BIOS_SIGN, 0);
    if (error)
        return error;
    do_cpuid(0, registers);
    new_value = rdmsr(MSR_BIOS_SIGN) >> 32;
    if (new_revision)
        *new_revision = new_value;
    if (old_revision)
        *old_revision = old_value;
    return new_value > old_value ? 0 : 17;
}

void *
ucode_update(void *data)
{
    return (void *)__atomic_exchange_n((uintptr_t *)&g_bsd_cpu_microcode,
        (uintptr_t)data, __ATOMIC_ACQ_REL);
}
#endif

#define BSD_BRIDGE_MAX_CPUS 256u
static struct pcpu g_bsd_pcpus[BSD_BRIDGE_MAX_CPUS];
static volatile int g_bsd_cpu_initialized;

#ifndef BSD_BRIDGE_HOST_TEST
static void
bsd_smp_build_edge_mask(const cpuset_t *source, edge_cpumask_t *destination)
{
    unsigned int cpu;

    edge_cpumask_init(destination, edge_smp_nr_cpu_ids());
    for (cpu = 0; cpu < destination->nbits; ++cpu) {
        if (CPU_ISSET(cpu, source))
            (void)edge_cpumask_set_cpu(destination, cpu);
    }
}

void
bsd_smp_rendezvous_cpus(cpuset_t cpus, smp_rendezvous_func_t setup,
    smp_rendezvous_func_t action, smp_rendezvous_func_t teardown,
    void *argument)
{
    edge_cpumask_t targets;

    bsd_smp_build_edge_mask(&cpus, &targets);
    if (setup && edge_smp_rendezvous(&targets, setup, argument) != 0)
        bsd_panic("SMP rendezvous setup failed");
    if (action && edge_smp_rendezvous(&targets, action, argument) != 0)
        bsd_panic("SMP rendezvous action failed");
    if (teardown && edge_smp_rendezvous(&targets, teardown, argument) != 0)
        bsd_panic("SMP rendezvous teardown failed");
}

static void
bsd_cpu_import_topology(void)
{
    edge_cpumask_t online;
    edge_cpu_topology_t topology;
    uint32_t cpu = UINT32_MAX;
    unsigned int cores = 0;

    edge_smp_online_mask(&online);
    CPU_ZERO(&all_cpus);
    CPU_ZERO(&cpuset_domain[0]);
    while ((cpu = edge_cpumask_next(&online, cpu)) < online.nbits) {
        if (cpu >= BSD_BRIDGE_MAX_CPUS ||
            edge_smp_get_cpu(cpu, &topology) != 0)
            continue;
        CPU_SET(cpu, &all_cpus);
        CPU_SET(cpu, &cpuset_domain[0]);
        g_bsd_pcpus[cpu].pc_cpuid = cpu;
        g_bsd_pcpus[cpu].pc_acpi_id = topology.firmware_id;
        g_bsd_pcpus[cpu].pc_domain = topology.numa_node;
        if (topology.thread_id == 0u)
            ++cores;
    }
    mp_ncpus = (int)edge_cpumask_weight(&online);
    if (mp_ncpus < 1)
        mp_ncpus = 1;
    mp_maxid = (int)edge_smp_nr_cpu_ids() - 1;
    mp_ncores = cores ? (int)cores : mp_ncpus;
    smp_threads_per_core = mp_ncores > 0 ? mp_ncpus / mp_ncores : 1;
    if (smp_threads_per_core < 1)
        smp_threads_per_core = 1;
    smp_started = mp_ncpus > 1;
}
#endif

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)

#define BSD_MSR_MPERF UINT32_C(0x000000e7)
#define BSD_MSR_APERF UINT32_C(0x000000e8)
#define BSD_CPUID_APERF_MPERF (UINT32_C(1) << 0)
#define BSD_CPUID_INVARIANT_TSC (UINT32_C(1) << 8)
#define BSD_X86_FLAGS_INTERRUPT (UINT64_C(1) << 9)

static volatile uintptr_t g_bsd_msr_fault_fixup;
static volatile int g_bsd_msr_faulted;
static uint64_t g_bsd_xsave_supervisor_mask;
static uint32_t g_bsd_xsave_extensions;

#define BSD_X86_NMI_HANDLER_COUNT 16u
typedef int (*bsd_x86_nmi_handler_t)(struct trapframe *);
typedef struct {
    bsd_x86_nmi_handler_t handler;
    volatile uint32_t active;
} bsd_x86_nmi_slot_t;

static bsd_x86_nmi_slot_t g_bsd_x86_nmi_handlers[
    BSD_X86_NMI_HANDLER_COUNT];

static void
bsd_cpu_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
    uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    __asm__ __volatile__("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
}

static uint64_t
bsd_cpu_rdtsc(void)
{
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("lfence; rdtsc"
        : "=a"(low), "=d"(high) :: "memory");
    return ((uint64_t)high << 32) | low;
}

static uint64_t
bsd_cpu_rdmsr(uint32_t register_id)
{
    uint32_t low;
    uint32_t high;

    __asm__ __volatile__("rdmsr"
        : "=a"(low), "=d"(high) : "c"(register_id) : "memory");
    return ((uint64_t)high << 32) | low;
}

void
bsd_x86_ltr(uint16_t selector)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;
    uint64_t *descriptor;
    uint32_t offset = selector & ~UINT16_C(7);

    __asm__ __volatile__("sgdt %0" : "=m"(gdtr));
    if ((selector & UINT16_C(7)) != 0 ||
        offset + 2u * sizeof(uint64_t) - 1u > gdtr.limit)
        bsd_panic("invalid TSS selector %#x for GDT limit %#x",
            selector, gdtr.limit);
    descriptor = (uint64_t *)(uintptr_t)(gdtr.base + offset);
    descriptor[0] = (descriptor[0] & ~(UINT64_C(0x1f) << 40)) |
        ((uint64_t)SDT_SYSTSS << 40);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __asm__ __volatile__("ltr %0" : : "r"(selector) : "memory");
}

static int
bsd_cpu_has_invariant_tsc(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t maximum;

    bsd_cpu_cpuid(UINT32_C(0x80000000), 0, &maximum, &ebx, &ecx, &edx);
    if (maximum < UINT32_C(0x80000007))
        return 0;
    bsd_cpu_cpuid(UINT32_C(0x80000007), 0, &eax, &ebx, &ecx, &edx);
    return (edx & BSD_CPUID_INVARIANT_TSC) != 0;
}

static int
bsd_cpu_has_aperf_mperf(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t maximum;

    bsd_cpu_cpuid(0, 0, &maximum, &ebx, &ecx, &edx);
    cpu_vendor[0] = (char)ebx;
    cpu_vendor[1] = (char)(ebx >> 8);
    cpu_vendor[2] = (char)(ebx >> 16);
    cpu_vendor[3] = (char)(ebx >> 24);
    cpu_vendor[4] = (char)edx;
    cpu_vendor[5] = (char)(edx >> 8);
    cpu_vendor[6] = (char)(edx >> 16);
    cpu_vendor[7] = (char)(edx >> 24);
    cpu_vendor[8] = (char)ecx;
    cpu_vendor[9] = (char)(ecx >> 8);
    cpu_vendor[10] = (char)(ecx >> 16);
    cpu_vendor[11] = (char)(ecx >> 24);
    cpu_vendor[12] = '\0';
    cpu_high = maximum;
    if (maximum < 6)
        return 0;
    bsd_cpu_cpuid(6, 0, &eax, &ebx, &ecx, &edx);
    return (ecx & BSD_CPUID_APERF_MPERF) != 0;
}

static uint64_t
bsd_cpu_tsc_frequency(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t maximum;
    uint64_t start;
    uint64_t end;
    uint64_t deadline;

    bsd_cpu_cpuid(0, 0, &maximum, &ebx, &ecx, &edx);
    if (maximum >= UINT32_C(0x15)) {
        bsd_cpu_cpuid(UINT32_C(0x15), 0, &eax, &ebx, &ecx, &edx);
        if (eax != 0 && ebx != 0 && ecx != 0)
            return ((uint64_t)ecx * ebx) / eax;
    }
    if (maximum >= UINT32_C(0x16)) {
        bsd_cpu_cpuid(UINT32_C(0x16), 0, &eax, &ebx, &ecx, &edx);
        if ((eax & UINT32_C(0xffff)) != 0)
            return (uint64_t)(eax & UINT32_C(0xffff)) * UINT64_C(1000000);
    }
    start = bsd_cpu_rdtsc();
    deadline = boottime_monotonic_us() + UINT64_C(1000);
    while (boottime_monotonic_us() < deadline)
        __asm__ __volatile__("pause");
    end = bsd_cpu_rdtsc();
    return (end - start) * UINT64_C(1000);
}

static void
bsd_cpu_identify_x86(void)
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t maximum;
    uint32_t extended_maximum;

    bsd_cpu_cpuid(0, 0, &maximum, &ebx, &ecx, &edx);
    cpu_high = maximum;
    cpu_vendor[0] = (char)ebx;
    cpu_vendor[1] = (char)(ebx >> 8);
    cpu_vendor[2] = (char)(ebx >> 16);
    cpu_vendor[3] = (char)(ebx >> 24);
    cpu_vendor[4] = (char)edx;
    cpu_vendor[5] = (char)(edx >> 8);
    cpu_vendor[6] = (char)(edx >> 16);
    cpu_vendor[7] = (char)(edx >> 24);
    cpu_vendor[8] = (char)ecx;
    cpu_vendor[9] = (char)(ecx >> 8);
    cpu_vendor[10] = (char)(ecx >> 16);
    cpu_vendor[11] = (char)(ecx >> 24);
    cpu_vendor[12] = '\0';
    if (ebx == UINT32_C(0x68747541) &&
        edx == UINT32_C(0x69746e65) &&
        ecx == UINT32_C(0x444d4163))
        cpu_vendor_id = CPU_VENDOR_AMD;
    else if (ebx == UINT32_C(0x6f677948) &&
        edx == UINT32_C(0x6e65476e) &&
        ecx == UINT32_C(0x656e6975))
        cpu_vendor_id = CPU_VENDOR_HYGON;
    else if (ebx == UINT32_C(0x756e6547) &&
        edx == UINT32_C(0x49656e69) &&
        ecx == UINT32_C(0x6c65746e))
        cpu_vendor_id = CPU_VENDOR_INTEL;
    if (maximum >= 1) {
        bsd_cpu_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
        cpu_id = eax;
        cpu_feature = edx;
        cpu_feature2 = ecx;
    }
    if (maximum >= 5) {
        bsd_cpu_cpuid(5, 0, &eax, &ebx, &ecx, &edx);
        cpu_mon_mwait_edx = edx;
    }
    if (maximum >= 6) {
        bsd_cpu_cpuid(6, 0, &eax, &ebx, &ecx, &edx);
        cpu_power_eax = eax;
        cpu_power_ecx = ecx;
    }
    if (maximum >= 7) {
        bsd_cpu_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        cpu_stdext_feature = ebx;
        cpu_stdext_feature2 = ecx;
        cpu_stdext_feature3 = edx;
        cpu_stdext_feature4 = eax;
        cpu_ia32_arch_caps = 0;
        if ((cpu_stdext_feature3 & CPUID_STDEXT3_ARCH_CAP) != 0)
            (void)rdmsr_safe(MSR_IA32_ARCH_CAP, &cpu_ia32_arch_caps);
    }
    use_xsave = (cpu_feature2 & CPUID2_XSAVE) != 0;
    if (use_xsave && maximum >= UINT32_C(0x0d)) {
        bsd_cpu_cpuid(UINT32_C(0x0d), 0, &eax, &ebx, &ecx, &edx);
        xsave_mask = ((uint64_t)edx << 32) | eax;
        bsd_cpu_cpuid(UINT32_C(0x0d), 1, &eax, &ebx, &ecx, &edx);
        g_bsd_xsave_extensions = eax;
        g_bsd_xsave_supervisor_mask = ((uint64_t)edx << 32) | ecx;
    }
    bsd_cpu_cpuid(UINT32_C(0x80000000), 0, &extended_maximum,
        &ebx, &ecx, &edx);
    cpu_exthigh = extended_maximum;
    if (extended_maximum >= UINT32_C(0x80000007)) {
        bsd_cpu_cpuid(UINT32_C(0x80000007), 0,
            &eax, &ebx, &ecx, &edx);
        amd_pminfo = edx;
        tsc_is_invariant =
            (edx & BSD_CPUID_INVARIANT_TSC) != 0;
    }
    if (extended_maximum >= UINT32_C(0x80000001)) {
        bsd_cpu_cpuid(UINT32_C(0x80000001), 0,
            &eax, &ebx, &ecx, &edx);
        amd_feature = edx & ~(cpu_feature & UINT32_C(0x0183f3ff));
        amd_feature2 = ecx;
    }
    if (extended_maximum >= UINT32_C(0x80000008)) {
        bsd_cpu_cpuid(UINT32_C(0x80000008), 0,
            &eax, &ebx, &ecx, &edx);
        amd_extended_feature_extensions = ebx;
        cpu_procinfo2 = ecx;
    }
    tsc_freq = bsd_cpu_tsc_frequency();
}

static int
bsd_cpu_highest_xfeature(uint64_t bitmap)
{
    if (bitmap == 0)
        return -1;
    return 63 - __builtin_clzll(bitmap);
}

bool
xsave_extfeature_supported(uint64_t feature, bool supervisor)
{
    uint64_t mask = supervisor ? g_bsd_xsave_supervisor_mask : xsave_mask;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    int index;

    if (!use_xsave || feature == 0 || (feature & (feature - 1)) != 0 ||
        (mask & feature) == 0)
        return false;
    index = bsd_cpu_highest_xfeature(feature);
    if (index < 2 || index > 63)
        return !supervisor;
    bsd_cpu_cpuid(UINT32_C(0x0d), (uint32_t)index,
        &eax, &ebx, &ecx, &edx);
    (void)eax;
    (void)ebx;
    (void)edx;
    return ((ecx & CPUID_EXTSTATE_SUPERVISOR) != 0) == supervisor;
}

bool
xsave_extension_supported(uint64_t extension)
{
    return use_xsave && extension != 0 &&
        ((uint64_t)g_bsd_xsave_extensions & extension) == extension;
}

size_t
xsave_area_offset(uint64_t xstate_bv, uint64_t feature, bool compact,
    bool supervisor)
{
    uint64_t supported = supervisor ?
        (xsave_mask | g_bsd_xsave_supervisor_mask) : xsave_mask;
    size_t offset;
    int feature_index;

    if (!use_xsave || xstate_bv == 0 || feature == 0 ||
        (feature & (feature - 1)) != 0 ||
        (xstate_bv & feature) == 0 || (supported & feature) == 0)
        return 0;
    feature_index = bsd_cpu_highest_xfeature(feature);
    if (feature_index < 2)
        return 0;
    if (!compact) {
        uint32_t registers[4];

        cpuid_count(UINT32_C(0x0d), (uint32_t)feature_index, registers);
        return registers[1];
    }

    offset = sizeof(struct savefpu) + sizeof(struct xstate_hdr);
    xstate_bv &= ~(uint64_t)(XFEATURE_ENABLED_X87 |
        XFEATURE_ENABLED_SSE);
    for (int index = 2; index < feature_index; ++index) {
        uint64_t bit = UINT64_C(1) << index;
        uint32_t registers[4];

        if ((xstate_bv & bit) == 0)
            continue;
        cpuid_count(UINT32_C(0x0d), (uint32_t)index, registers);
        if ((registers[2] & CPUID_EXTSTATE_ALIGNED) != 0)
            offset = (offset + 63u) & ~(size_t)63u;
        offset += registers[0];
    }
    {
        uint32_t registers[4];

        cpuid_count(UINT32_C(0x0d), (uint32_t)feature_index, registers);
        if ((registers[2] & CPUID_EXTSTATE_ALIGNED) != 0)
            offset = (offset + 63u) & ~(size_t)63u;
    }
    return offset;
}

size_t
xsave_area_size(uint64_t xstate_bv, bool compact, bool supervisor)
{
    uint32_t registers[4];
    size_t offset;
    int last_index = bsd_cpu_highest_xfeature(xstate_bv);

    if (last_index < 0)
        return 0;
    if (last_index < 2)
        return sizeof(struct savefpu);
    offset = xsave_area_offset(xstate_bv, UINT64_C(1) << last_index,
        compact, supervisor);
    cpuid_count(UINT32_C(0x0d), (uint32_t)last_index, registers);
    return offset + registers[0];
}

size_t
xsave_area_hdr_offset(void)
{
    return sizeof(struct savefpu);
}

void
nmi_register_handler(int (*handler)(struct trapframe *))
{
    if (!handler)
        return;
    for (unsigned int index = 0; index < BSD_X86_NMI_HANDLER_COUNT;
         ++index) {
        bsd_x86_nmi_handler_t expected = 0;

        if (__atomic_load_n(&g_bsd_x86_nmi_handlers[index].handler,
            __ATOMIC_ACQUIRE) == handler)
            return;
        if (__atomic_compare_exchange_n(
            &g_bsd_x86_nmi_handlers[index].handler, &expected, handler,
            0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
    }
}

void
nmi_remove_handler(int (*handler)(struct trapframe *))
{
    if (!handler)
        return;
    for (unsigned int index = 0; index < BSD_X86_NMI_HANDLER_COUNT;
         ++index) {
        bsd_x86_nmi_handler_t expected = handler;

        if (!__atomic_compare_exchange_n(
            &g_bsd_x86_nmi_handlers[index].handler, &expected, 0,
            0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        while (__atomic_load_n(&g_bsd_x86_nmi_handlers[index].active,
            __ATOMIC_ACQUIRE) != 0)
            __asm__ __volatile__("pause");
        return;
    }
}

static int
bsd_x86_nmi_dispatch_frame(struct trapframe *frame)
{
    int handled = 0;

    for (unsigned int index = 0; index < BSD_X86_NMI_HANDLER_COUNT;
         ++index) {
        bsd_x86_nmi_handler_t handler = __atomic_load_n(
            &g_bsd_x86_nmi_handlers[index].handler, __ATOMIC_ACQUIRE);

        if (!handler)
            continue;
        __atomic_add_fetch(&g_bsd_x86_nmi_handlers[index].active, 1,
            __ATOMIC_ACQ_REL);
        if (__atomic_load_n(&g_bsd_x86_nmi_handlers[index].handler,
            __ATOMIC_ACQUIRE) == handler)
            handled |= handler(frame) != 0;
        __atomic_sub_fetch(&g_bsd_x86_nmi_handlers[index].active, 1,
            __ATOMIC_ACQ_REL);
    }
    return handled;
}

void
nmi_handle_intr(struct trapframe *frame)
{
    if (frame)
        (void)bsd_x86_nmi_dispatch_frame(frame);
}

int
bsd_x86_nmi_dispatch(const void *native_frame)
{
    const edgeos_x86_64_trap_frame_t *native = native_frame;
    struct trapframe frame = { 0 };

    if (!native)
        return 0;
    frame.tf_rdi = native->rdi;
    frame.tf_rsi = native->rsi;
    frame.tf_rdx = native->rdx;
    frame.tf_rcx = native->rcx;
    frame.tf_r8 = native->r8;
    frame.tf_r9 = native->r9;
    frame.tf_rax = native->rax;
    frame.tf_rbx = native->rbx;
    frame.tf_rbp = native->rbp;
    frame.tf_r10 = native->r10;
    frame.tf_r11 = native->r11;
    frame.tf_r12 = native->r12;
    frame.tf_r13 = native->r13;
    frame.tf_r14 = native->r14;
    frame.tf_r15 = native->r15;
    frame.tf_trapno = (uint32_t)native->int_no;
    frame.tf_err = native->err_code;
    frame.tf_rip = native->rip;
    frame.tf_cs = (uint16_t)native->cs;
    frame.tf_rflags = native->rflags;
    frame.tf_rsp = native->rsp;
    frame.tf_ss = (uint16_t)native->ss;
    return bsd_x86_nmi_dispatch_frame(&frame);
}

void
identify_cpu1(void)
{
    bsd_cpu_identify_x86();
}

void
identify_cpu2(void)
{
    bsd_cpu_identify_x86();
}

void
hw_ibrs_recalculate(bool all_cpus)
{
    (void)all_cpus;
    bsd_cpu_identify_x86();
}

void
hw_ssb_recalculate(bool all_cpus)
{
    (void)all_cpus;
    bsd_cpu_identify_x86();
}

void
amd64_syscall_ret_flush_l1d_recalc(void)
{
    bsd_cpu_identify_x86();
}

void
hw_mds_recalculate(void)
{
    bsd_cpu_identify_x86();
}

void
x86_taa_recalculate(void)
{
    bsd_cpu_identify_x86();
}

void
x86_rngds_mitg_recalculate(bool all_cpus)
{
    (void)all_cpus;
    bsd_cpu_identify_x86();
}

void
zenbleed_check_and_apply(bool all_cpus)
{
    (void)all_cpus;
    bsd_cpu_identify_x86();
}

void
printcpuinfo(void)
{
    bsd_printf("[bsd-cpu] vendor=%s id=0x%x features=0x%x/0x%x "
        "extended=0x%x\n", cpu_vendor, cpu_id, cpu_feature,
        cpu_feature2, cpu_stdext_feature);
}

static uint64_t
bsd_cpu_muldiv_u64(uint64_t value, uint64_t multiplier, uint64_t divisor)
{
    uint64_t quotient;
    uint64_t remainder;

    if (divisor == 0)
        return 0;
    quotient = value / divisor;
    remainder = value % divisor;
    if (multiplier != 0 && quotient > UINT64_MAX / multiplier)
        return UINT64_MAX;
    while (remainder != 0 && multiplier > UINT64_MAX / remainder) {
        remainder >>= 1;
        divisor >>= 1;
        if (divisor == 0)
            return UINT64_MAX;
    }
    return quotient * multiplier +
        (remainder * multiplier) / divisor;
}

#endif

struct pcpu *
pcpu_find(unsigned int cpu)
{
    if (cpu >= (unsigned int)mp_ncpus ||
        cpu >= sizeof(g_bsd_pcpus) / sizeof(g_bsd_pcpus[0]))
        return 0;
    g_bsd_pcpus[cpu].pc_cpuid = cpu;
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    if (cpu == bsd_pcpu_current_cpuid()) {
        g_bsd_pcpus[cpu].pc_tssp = gdt_current_tss();
        g_bsd_pcpus[cpu].pc_gdt = gdt_current_base();
    }
#endif
    return &g_bsd_pcpus[cpu];
}

int
pmc_cpu_is_present(int cpu)
{
    return cpu >= 0 && cpu < mp_ncpus && pcpu_find((unsigned int)cpu) != 0;
}

int
pmc_cpu_is_disabled(int cpu)
{
    return !pmc_cpu_is_present(cpu);
}

int
pmc_cpu_is_active(int cpu)
{
    return pmc_cpu_is_present(cpu);
}

int
pmc_cpu_is_primary(int cpu)
{
    return cpu == 0 && pmc_cpu_is_present(cpu);
}

unsigned int
pmc_cpu_max(void)
{
    return mp_ncpus > 0 ? (unsigned int)mp_ncpus : 0;
}

unsigned int
bsd_pcpu_current_small_core(void)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    if (cpu_high < UINT32_C(0x1a))
        return 0;
    bsd_cpu_cpuid(UINT32_C(0x1a), 0, &eax, &ebx, &ecx, &edx);
    return (eax & CPUID_HYBRID_CORE_MASK) == CPUID_HYBRID_SMALL_CORE;
#else
    return 0;
#endif
}

int
bsd_cpu_runtime_initialize(void)
{
    int expected = 0;

    if (!__atomic_compare_exchange_n(&g_bsd_cpu_initialized, &expected,
        1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;
    g_bsd_pcpus[0].pc_cpuid = 0;
    g_bsd_pcpus[0].pc_acpi_id = 0;
    g_bsd_pcpus[0].pc_small_core = 0;
    g_bsd_pcpus[0].pc_domain = 0;
    g_bsd_pcpus[0].pc_clock = 0;
    g_bsd_pcpus[0].pc_device = 0;
#ifndef BSD_BRIDGE_HOST_TEST
    bsd_cpu_import_topology();
    physmem = (unsigned long)(arch_vm_memory_total_bytes() / 4096u);
    if (physmem == 0)
        physmem = 1;
    Maxmem = (long)physmem;
    realmem = (long)physmem;
#endif
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    bsd_cpu_identify_x86();
    g_bsd_pcpus[0].pc_small_core = bsd_pcpu_current_small_core();
#endif
    return 0;
}

int
bsd_cpu_runtime_refresh_topology(void)
{
#ifndef BSD_BRIDGE_HOST_TEST
    bsd_cpu_import_topology();
#endif
    return 0;
}

int
bsd_cpu_idle(int64_t predicted_idle_time)
{
    if (!cpu_idle_hook)
        return 0;
    cpu_idle_hook((sbintime_t)predicted_idle_time);
    return 1;
}

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)

bool
cpu_mwait_usable(void)
{
    /*
     * EdgeOS uses the ACPI I/O and C1 paths until its idle scheduler can
     * provide the monitored-state wake protocol required for race-free MWAIT.
     */
    return false;
}

void
acpi_cpu_c1(void)
{
    __asm__ __volatile__("sti; hlt" ::: "memory");
}

void
acpi_cpu_idle_mwait(uint32_t hint)
{
    (void)hint;
    acpi_cpu_c1();
}

uint64_t
cpu_ticks(void)
{
    return bsd_cpu_rdtsc();
}

uint64_t
cpu_tickrate(void)
{
    return tsc_freq ? tsc_freq : UINT64_C(1000000);
}

unsigned int
cpu_auxmsr(void)
{
    return bsd_kthread_current_cpu_id();
}

int
bsd_x86_msr_fault_recover(uint64_t *instruction_pointer)
{
    uintptr_t fixup;

    if (!instruction_pointer)
        return 0;
    fixup = __atomic_load_n(&g_bsd_msr_fault_fixup, __ATOMIC_ACQUIRE);
    if (!fixup)
        return 0;
    __atomic_store_n(&g_bsd_msr_faulted, 1, __ATOMIC_RELEASE);
    *instruction_pointer = (uint64_t)fixup;
    return 1;
}

int
rdmsr_safe(unsigned int register_id, uint64_t *value)
{
    uint64_t flags;
    uint32_t low = 0;
    uint32_t high = 0;

    if (!value)
        return BSD_CPU_EINVAL;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    __atomic_store_n(&g_bsd_msr_faulted, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_bsd_msr_fault_fixup,
        (uintptr_t)&&msr_fault, __ATOMIC_RELEASE);
    __asm__ goto volatile("rdmsr" : "=a"(low), "=d"(high)
        : "c"(register_id) : "memory" : msr_fault);
    goto msr_complete;
msr_fault:
    low = 0;
    high = 0;
msr_complete:
    __atomic_store_n(&g_bsd_msr_fault_fixup, 0, __ATOMIC_RELEASE);
    if ((flags & BSD_X86_FLAGS_INTERRUPT) != 0)
        __asm__ __volatile__("sti" ::: "memory");
    if (__atomic_load_n(&g_bsd_msr_faulted, __ATOMIC_ACQUIRE))
        return BSD_CPU_EFAULT;
    *value = ((uint64_t)high << 32) | low;
    return 0;
}

int
wrmsr_safe(unsigned int register_id, uint64_t value)
{
    uint64_t flags;
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);

    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    __atomic_store_n(&g_bsd_msr_faulted, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_bsd_msr_fault_fixup,
        (uintptr_t)&&msr_fault, __ATOMIC_RELEASE);
    __asm__ goto volatile("wrmsr" :: "a"(low), "d"(high),
        "c"(register_id) : "memory" : msr_fault);
    goto msr_complete;
msr_fault:
    low = 0;
    high = 0;
msr_complete:
    (void)low;
    (void)high;
    __atomic_store_n(&g_bsd_msr_fault_fixup, 0, __ATOMIC_RELEASE);
    if ((flags & BSD_X86_FLAGS_INTERRUPT) != 0)
        __asm__ __volatile__("sti" ::: "memory");
    return __atomic_load_n(&g_bsd_msr_faulted, __ATOMIC_ACQUIRE) ?
        BSD_CPU_EFAULT : 0;
}

int
x86_msr_op(unsigned int register_id, unsigned int operation,
    uint64_t argument, uint64_t *result)
{
    const unsigned int execution_mask = UINT32_C(0xf0000000);
    const unsigned int operation_mask = UINT32_C(0x000000ff);
    const unsigned int safe_flag = UINT32_C(0x08000000);
    unsigned int execution_mode = operation & execution_mask;
    unsigned int requested_operation = operation & operation_mask;
    unsigned int target_cpu =
        (operation & ~(execution_mask | safe_flag)) >> 8;
    uint64_t value;
    int error;

    /*
     * The current x86 scheduler exposes one logical CPU. All FreeBSD
     * execution modes therefore name the same processor, while invalid
     * explicit processor identifiers are rejected rather than misdirected.
     */
    switch (execution_mode) {
    case MSR_OP_LOCAL:
    case MSR_OP_SCHED_ALL:
    case MSR_OP_RENDEZVOUS_ALL:
        break;
    case MSR_OP_SCHED_ONE:
    case MSR_OP_RENDEZVOUS_ONE:
        if (target_cpu != 0)
            return BSD_CPU_EINVAL;
        break;
    default:
        return BSD_CPU_EINVAL;
    }
    switch (requested_operation) {
    case MSR_OP_READ:
        error = rdmsr_safe(register_id, &value);
        if (error == 0 && result)
            *result = value;
        return error;
    case MSR_OP_WRITE:
        return wrmsr_safe(register_id, argument);
    case MSR_OP_ANDNOT:
    case MSR_OP_OR:
        error = rdmsr_safe(register_id, &value);
        if (error != 0)
            return error;
        if (result)
            *result = value;
        if (requested_operation == MSR_OP_ANDNOT)
            value &= ~argument;
        else
            value |= argument;
        return wrmsr_safe(register_id, value);
    default:
        return BSD_CPU_EINVAL;
    }
}

#else

bool
cpu_mwait_usable(void)
{
    return false;
}

#endif

int
cpu_est_clockrate(int cpu_id, uint64_t *rate)
{
    if (!rate || cpu_id < 0 || cpu_id >= mp_ncpus)
        return BSD_CPU_EINVAL;

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    {
        uint64_t aperf_start;
        uint64_t aperf_end;
        uint64_t mperf_start;
        uint64_t mperf_end;
        uint64_t tsc_start;
        uint64_t tsc_end;
        uint64_t deadline;
        uint64_t tsc_rate;

        if ((uint32_t)cpu_id != bsd_kthread_current_cpu_id())
            return BSD_CPU_EOPNOTSUPP;
        if (!bsd_cpu_has_invariant_tsc()) {
            tsc_start = bsd_cpu_rdtsc();
            deadline = boottime_monotonic_us() + UINT64_C(1000);
            while (boottime_monotonic_us() < deadline)
                __asm__ __volatile__("pause");
            tsc_end = bsd_cpu_rdtsc();
            *rate = (tsc_end - tsc_start) * UINT64_C(1000);
            return *rate != 0 ? 0 : BSD_CPU_EOPNOTSUPP;
        }
        if (!bsd_cpu_has_aperf_mperf())
            return BSD_CPU_EOPNOTSUPP;

        mperf_start = bsd_cpu_rdmsr(BSD_MSR_MPERF);
        aperf_start = bsd_cpu_rdmsr(BSD_MSR_APERF);
        tsc_start = bsd_cpu_rdtsc();
        deadline = boottime_monotonic_us() + UINT64_C(1000);
        while (boottime_monotonic_us() < deadline)
            __asm__ __volatile__("pause");
        tsc_end = bsd_cpu_rdtsc();
        aperf_end = bsd_cpu_rdmsr(BSD_MSR_APERF);
        mperf_end = bsd_cpu_rdmsr(BSD_MSR_MPERF);
        if (mperf_end == mperf_start || tsc_end == tsc_start)
            return BSD_CPU_EOPNOTSUPP;
        tsc_rate = (tsc_end - tsc_start) * UINT64_C(1000);
        *rate = bsd_cpu_muldiv_u64(tsc_rate,
            aperf_end - aperf_start, mperf_end - mperf_start);
        return *rate != 0 ? 0 : BSD_CPU_EOPNOTSUPP;
    }
#else
    /*
     * ARM64 has no architecture-defined register for the current core
     * frequency. Platform CPU-frequency drivers provide authoritative
     * settings, so the generic bridge reports the absence of an estimate.
     */
    return BSD_CPU_EOPNOTSUPP;
#endif
}
