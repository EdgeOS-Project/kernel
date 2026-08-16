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

static uint64 g_gdt[SCHED_MAX_CPUS][7] __attribute__((aligned(64)));
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

void gdt_init_cpu(uint32_t cpu) {
    if (cpu >= SCHED_MAX_CPUS) cpu = 0;
    g_gdt[cpu][0] = 0;
    g_gdt[cpu][1] = 0x00AF9A000000FFFFULL;
    g_gdt[cpu][2] = 0x00AF92000000FFFFULL;
    g_gdt[cpu][3] = 0x00AFFA000000FFFFULL;
    g_gdt[cpu][4] = 0x00AFF2000000FFFFULL;

    for (uint32 i = 0; i < sizeof(g_tss[cpu]); ++i)
        ((uint8 *)&g_tss[cpu])[i] = 0;
    g_tss[cpu].iomap_base = sizeof(g_tss[cpu]);

    gdt_set_tss_desc(cpu, 5, (uint64)&g_tss[cpu],
                     sizeof(g_tss[cpu]) - 1);

    g_gdt_ptr[cpu].base = (uint64)&g_gdt[cpu][0];
    g_gdt_ptr[cpu].limit = sizeof(g_gdt[cpu]) - 1;

    load_gdt((uint64)&g_gdt_ptr[cpu]);
    load_tss(0x28);
}

void gdt_init(void) {
    gdt_init_cpu(0);
}
