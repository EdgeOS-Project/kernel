/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 context-switch verification. */

#include <stdint.h>
#include "arch/arm64/task.h"

static edgeos_arm64_cpu_context_t g_boot_context;
static edgeos_arm64_cpu_context_t g_worker_context;
static uint8_t g_worker_stack[8192] __attribute__((aligned(16)));
static volatile uint32_t g_worker_reached;

static __attribute__((noreturn)) void edgeos_arm64_context_worker(void) {
    g_worker_reached = 1;
    edgeos_arm64_context_switch(&g_worker_context, &g_boot_context);
    for (;;) __asm__ __volatile__("wfe");
}

int edgeos_arm64_context_selftest(void) {
    uint32_t i;
    uint8_t *p;

    for (i = 0; i < sizeof(g_boot_context); ++i) ((uint8_t *)&g_boot_context)[i] = 0;
    for (i = 0; i < sizeof(g_worker_context); ++i) ((uint8_t *)&g_worker_context)[i] = 0;
    g_worker_reached = 0;
    p = &g_worker_stack[sizeof(g_worker_stack)];
    g_worker_context.sp = (uint64_t)(uintptr_t)p;
    g_worker_context.pc = (uint64_t)(uintptr_t)edgeos_arm64_context_worker;
    edgeos_arm64_context_switch(&g_boot_context, &g_worker_context);
    return g_worker_reached == 1u ? 0 : -1;
}
