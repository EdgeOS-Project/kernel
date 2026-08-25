/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux restart block state. */

#include "kernel/linux_errno.h"
#include "kernel/restart_block.h"

void kernel_restart_block_reset(kernel_restart_block_t *block) {
    if (!block) return;
    block->operation = KERNEL_RESTART_BLOCK_NONE;
    block->write_remaining = 0;
    block->remaining_time32 = 0;
    block->deadline_microseconds = 0;
    block->remaining_user = 0;
}

void kernel_restart_block_prepare_nanosleep(
    kernel_restart_block_t *block, uint64_t deadline_microseconds,
    uint64_t remaining_user, int write_remaining, int remaining_time32) {
    if (!block) return;
    block->operation = KERNEL_RESTART_BLOCK_NANOSLEEP;
    block->write_remaining = write_remaining != 0;
    block->remaining_time32 = write_remaining && remaining_time32;
    block->deadline_microseconds = deadline_microseconds;
    block->remaining_user = write_remaining ? remaining_user : 0;
}

int64_t kernel_restart_block_execute(
    kernel_restart_block_t *block, uint64_t monotonic_now,
    kernel_restart_sleep_fn sleep_until, void *user_registers) {
    int64_t result;

    if (!block || !sleep_until ||
        block->operation == KERNEL_RESTART_BLOCK_NONE)
        return -EDGE_LINUX_EINTR;
    if (block->operation != KERNEL_RESTART_BLOCK_NANOSLEEP) {
        kernel_restart_block_reset(block);
        return -EDGE_LINUX_EINTR;
    }
    if (monotonic_now >= block->deadline_microseconds) {
        kernel_restart_block_reset(block);
        return 0;
    }
    result = sleep_until(
        block->deadline_microseconds, block->remaining_user,
        block->write_remaining != 0, block->remaining_time32 != 0,
        user_registers);
    if (result != -EDGE_LINUX_EINTR)
        kernel_restart_block_reset(block);
    return result;
}
