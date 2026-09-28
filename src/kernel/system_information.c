/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent system information runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/system_runtime.h"
#include "sys/boottime.h"
#include "vfs/vfs.h"

static void system_information_clear(void *pointer, uint32_t size) {
    uint8_t *bytes = (uint8_t *)pointer;
    uint32_t index;
    for (index = 0; index < size; ++index) bytes[index] = 0;
}

int kernel_arch_memory_information_sample(
    kernel_memory_information_sample_t *sample) {
    if (!sample) return -EDGE_LINUX_EINVAL;
    system_information_clear(sample, sizeof(*sample));
    return edge_system_runtime_memory_information_sample(sample);
}

int64_t kernel_system_power_action(kernel_power_action_t action) {
    if (action != KERNEL_POWER_RESTART &&
        action != KERNEL_POWER_HALT &&
        action != KERNEL_POWER_OFF)
        return -EDGE_LINUX_EINVAL;
    (void)vfs_shutdown_sync_all();
    return edge_system_runtime_power_action(action);
}

int kernel_system_information_snapshot(
    kernel_system_information_t *information) {
    kernel_memory_information_sample_t memory;
    kernel_proc_task_view_t task;
    uint64_t load;
    uint32_t process_count = 0;
    uint32_t running_process_count = 0;
    uint32_t index;
    if (!information) return -1;
    if (kernel_arch_memory_information_sample(&memory) < 0) return -1;
    for (index = 0;; ++index) {
        int status = kernel_arch_proc_task_sample(index, &task);
        if (status < 0) break;
        if (status > 0 || task.state == KERNEL_PROC_TASK_ZOMBIE) continue;
        ++process_count;
        if (task.state == KERNEL_PROC_TASK_RUNNING)
            ++running_process_count;
    }
    system_information_clear(information, sizeof(*information));
    information->uptime_seconds = boottime_monotonic_us() / 1000000u;
    information->total_ram_bytes = memory.total_ram_bytes;
    information->free_ram_bytes = memory.free_ram_bytes;
    information->shared_ram_bytes = memory.shared_ram_bytes;
    information->buffer_ram_bytes = memory.buffer_ram_bytes;
    information->total_swap_bytes = memory.total_swap_bytes;
    information->free_swap_bytes = memory.free_swap_bytes;
    information->process_count = process_count;
    load = (uint64_t)running_process_count << 16;
    for (index = 0; index < 3u; ++index) information->loads[index] = load;
    return 0;
}
