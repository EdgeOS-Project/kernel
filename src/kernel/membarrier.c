/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux membarrier runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/arch_cpu.h"
#include "kernel/linux_abi.h"
#include "kernel/membarrier.h"
#include "kernel/process_runtime.h"
#include "kernel/smp.h"

uint32_t kernel_membarrier_supported_commands(void) {
    uint64_t online = kernel_scheduler_online_cpu_mask();

    if ((online & (online - 1u)) && !edge_smp_calls_available()) return 0;
    return EDGE_LINUX_MEMBARRIER_CMD_GLOBAL |
           EDGE_LINUX_MEMBARRIER_CMD_GLOBAL_EXPEDITED |
           EDGE_LINUX_MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED |
           EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED |
           EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED |
           EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE |
           EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE |
           EDGE_LINUX_MEMBARRIER_CMD_GET_REGISTRATIONS;
}

int kernel_current_membarrier_registrations(uint32_t *registrations) {
    uint32_t *state;

    if (!registrations ||
        kernel_arch_current_membarrier_state(&state) < 0 || !state)
        return -1;
    *registrations = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    return 0;
}

int kernel_current_membarrier_register(uint32_t command) {
    uint32_t *registrations;

    if (kernel_arch_current_membarrier_state(&registrations) < 0 ||
        !registrations)
        return -1;
    (void)__atomic_fetch_or(registrations, command, __ATOMIC_RELEASE);
    return 0;
}

int kernel_membarrier_execute(uint32_t command) {
    edge_cpumask_t online;
    uint32_t flags = EDGE_SMP_CALL_MEMORY_BARRIER;

    if (command == EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)
        flags |= EDGE_SMP_CALL_SYNC_CORE;
    edge_smp_online_mask(&online);
    return edge_smp_call(&online, flags);
}
