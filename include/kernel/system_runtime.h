/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS system-control runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SYSTEM_RUNTIME_H
#define EDGEOS_KERNEL_SYSTEM_RUNTIME_H

#include <stdint.h>

#define KERNEL_REBOOT_MAGIC1       0xfee1deadu
#define KERNEL_REBOOT_MAGIC2       0x28121969u
#define KERNEL_REBOOT_MAGIC2A      0x05121996u
#define KERNEL_REBOOT_MAGIC2B      0x16041998u
#define KERNEL_REBOOT_MAGIC2C      0x20112000u

#define KERNEL_REBOOT_CMD_RESTART  0x01234567u
#define KERNEL_REBOOT_CMD_HALT     0xcdef0123u
#define KERNEL_REBOOT_CMD_CAD_ON   0x89abcdefu
#define KERNEL_REBOOT_CMD_CAD_OFF  0x00000000u
#define KERNEL_REBOOT_CMD_POWER_OFF 0x4321fedcu

typedef enum kernel_power_action {
    KERNEL_POWER_RESTART = 1,
    KERNEL_POWER_HALT,
    KERNEL_POWER_OFF,
} kernel_power_action_t;

typedef struct kernel_system_information {
    uint64_t uptime_seconds;
    uint64_t loads[3];
    uint64_t total_ram_bytes;
    uint64_t free_ram_bytes;
    uint64_t shared_ram_bytes;
    uint64_t buffer_ram_bytes;
    uint64_t total_swap_bytes;
    uint64_t free_swap_bytes;
    uint32_t process_count;
} kernel_system_information_t;

typedef struct kernel_memory_information_sample {
    uint64_t total_ram_bytes;
    uint64_t free_ram_bytes;
    uint64_t shared_ram_bytes;
    uint64_t buffer_ram_bytes;
    uint64_t total_swap_bytes;
    uint64_t free_swap_bytes;
} kernel_memory_information_sample_t;

int64_t kernel_system_power_action(kernel_power_action_t action);
int kernel_arch_memory_information_sample(
    kernel_memory_information_sample_t *sample);
int64_t edge_system_runtime_power_action(kernel_power_action_t action);
int edge_system_runtime_memory_information_sample(
    kernel_memory_information_sample_t *sample);
int kernel_system_information_snapshot(
    kernel_system_information_t *information);

#endif
