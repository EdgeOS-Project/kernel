#include "arch/x86_64/gdt.h"
#include "arch/x86_64/syscall.h"
#include "sys/scheduler.h"

#include "types.h"

extern void load_gdt(uint64 gdt_ptr);
extern void load_tss(uint16 tss_sel);

typedef struct {
    uint16 limit;
    uint64 base;
} __attribute__((packed)) gdt_ptr_t;

typedef struct {
    uint32 reserved0;
    uint64 rsp0;
    uint64 rsp1;
    uint64 rsp2;
    uint64 reserved1;
    uint64 ist1;
    uint64 ist2;
    uint64 ist3;
    uint64 ist4;
    uint64 ist5;
    uint64 ist6;
    uint64 ist7;
    uint64 reserved2;
    uint16 reserved3;
    uint16 iomap_base;
} __attribute__((packed)) tss64_t;

#define GDT_ENTRY_LDT 7u
#define GDT_LDT_SELECTOR ((uint16_t)(GDT_ENTRY_LDT << 3))
#define GDT_ENTRY_TLS_MIN 12u
#define GDT_ENTRY_TLS_COUNT 3u
#define GDT_ENTRY_COUNT 15u

static uint64 g_gdt[SCHED_MAX_CPUS][GDT_ENTRY_COUNT]
    __attribute__((aligned(64)));
static tss64_t g_tss[SCHED_MAX_CPUS] __attribute__((aligned(64)));
static gdt_ptr_t g_gdt_ptr[SCHED_MAX_CPUS];

static void gdt_set_tss_desc(uint32 cpu, int idx, uint64 base, uint32 limit) {
    uint64 lo = 0;
    uint64 hi = 0;

    lo |= (limit & 0xFFFFULL);
    lo |= (base & 0xFFFFFFULL) << 16;
    lo |= 0x89ULL << 40;
    lo |= ((limit >> 16) & 0xFULL) << 48;
    lo |= ((base >> 24) & 0xFFULL) << 56;

    hi |= (base >> 32) & 0xFFFFFFFFULL;

    g_gdt[cpu][idx] = lo;
    g_gdt[cpu][idx + 1] = hi;
}

__attribute__((used)) void gdt_set_tss_rsp0(uint64_t rsp0) {
    uint32_t cpu = scheduler_cpu_id();

    if (cpu >= SCHED_MAX_CPUS) cpu = 0;
    g_tss[cpu].rsp0 = rsp0;
    edgeos_x86_64_syscall_set_kernel_rsp(rsp0);
}

uint64_t gdt_get_tss_rsp0(void) {
    uint32_t cpu = scheduler_cpu_id();

    if (cpu >= SCHED_MAX_CPUS) cpu = 0;
    return g_tss[cpu].rsp0;
}

static void gdt_load_ldt_cpu(uint32_t cpu, const uint64_t *entries,
                             uint32_t entry_count) {
    uint16_t selector = 0;

    if (cpu >= SCHED_MAX_CPUS) cpu = 0;
    g_gdt[cpu][GDT_ENTRY_LDT] = 0;
    g_gdt[cpu][GDT_ENTRY_LDT + 1u] = 0;
    if (entries && entry_count) {
        uint64_t base = (uint64_t)(uintptr_t)entries;
        uint32_t limit = entry_count >= 8192u ?
            8192u * 8u - 1u : entry_count * 8u - 1u;
        uint64_t low = 0;

        low |= limit & 0xffffu;
        low |= (base & 0xffffffu) << 16;
        low |= UINT64_C(0x82) << 40;
        low |= ((uint64_t)(limit >> 16) & 0x0fu) << 48;
        low |= ((base >> 24) & 0xffu) << 56;
        g_gdt[cpu][GDT_ENTRY_LDT] = low;
        g_gdt[cpu][GDT_ENTRY_LDT + 1u] = base >> 32;
        selector = GDT_LDT_SELECTOR;
    }
    __asm__ __volatile__("lldt %0" :: "m"(selector) : "memory");
}

void gdt_load_ldt(const uint64_t *entries, uint32_t entry_count) {
    gdt_load_ldt_cpu(scheduler_cpu_id(), entries, entry_count);
}

void gdt_load_tls(const uint64_t entries[GDT_ENTRY_TLS_COUNT]) {
    uint32_t cpu = scheduler_cpu_id();

    if (cpu >= SCHED_MAX_CPUS) cpu = 0;
    for (uint32_t index = 0; index < GDT_ENTRY_TLS_COUNT; ++index)
        g_gdt[cpu][GDT_ENTRY_TLS_MIN + index] = entries ? entries[index] : 0;
}

void gdt_init_cpu(uint32_t cpu) {
    if (cpu >= SCHED_MAX_CPUS) cpu = 0;
    g_gdt[cpu][0] = 0;
    g_gdt[cpu][1] = 0x00AF9A000000FFFFULL;
    g_gdt[cpu][2] = 0x00AF92000000FFFFULL;
    g_gdt[cpu][3] = 0x00AFFA000000FFFFULL;
    g_gdt[cpu][4] = 0x00AFF2000000FFFFULL;
    for (uint32_t index = 5u; index < GDT_ENTRY_COUNT; ++index)
        g_gdt[cpu][index] = 0;
#ifdef CONFIG_COMPAT_IA32
    g_gdt[cpu][9] = 0x00CFFA000000FFFFULL;
    g_gdt[cpu][10] = 0x00CFF2000000FFFFULL;
#endif

    for (uint32 i = 0; i < sizeof(g_tss[cpu]); ++i)
        ((uint8 *)&g_tss[cpu])[i] = 0;
    g_tss[cpu].iomap_base = sizeof(g_tss[cpu]);

    gdt_set_tss_desc(cpu, 5, (uint64)&g_tss[cpu],
                     sizeof(g_tss[cpu]) - 1);

    g_gdt_ptr[cpu].base = (uint64)&g_gdt[cpu][0];
    g_gdt_ptr[cpu].limit = sizeof(g_gdt[cpu]) - 1;

    load_gdt((uint64)&g_gdt_ptr[cpu]);
    load_tss(0x28);
    gdt_load_ldt_cpu(cpu, 0, 0);
}

void gdt_init(void) {
    gdt_init_cpu(0);
}
