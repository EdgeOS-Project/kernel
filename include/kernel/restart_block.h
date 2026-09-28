/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux restart block state. */

#ifndef EDGEOS_KERNEL_RESTART_BLOCK_H
#define EDGEOS_KERNEL_RESTART_BLOCK_H

#include <stdint.h>

typedef enum kernel_restart_block_operation {
    KERNEL_RESTART_BLOCK_NONE = 0,
    KERNEL_RESTART_BLOCK_NANOSLEEP = 1,
} kernel_restart_block_operation_t;

typedef struct kernel_restart_block {
    kernel_restart_block_operation_t operation;
    uint32_t write_remaining;
    uint32_t remaining_time32;
    uint64_t deadline_microseconds;
    uint64_t remaining_user;
} kernel_restart_block_t;

typedef int64_t (*kernel_restart_sleep_fn)(
    uint64_t deadline_microseconds, uint64_t remaining_user,
    int write_remaining, int remaining_time32, void *user_registers);

void kernel_restart_block_reset(kernel_restart_block_t *block);
void kernel_restart_block_prepare_nanosleep(
    kernel_restart_block_t *block, uint64_t deadline_microseconds,
    uint64_t remaining_user, int write_remaining, int remaining_time32);
int64_t kernel_restart_block_execute(
    kernel_restart_block_t *block, uint64_t monotonic_now,
    kernel_restart_sleep_fn sleep_until, void *user_registers);

#endif
