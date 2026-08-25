/* SPDX-License-Identifier: MPL-2.0 */
/* Linux restart block policy regression test. */

#include <assert.h>
#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/restart_block.h"

static int64_t g_result;
static uint64_t g_deadline;
static uint64_t g_remaining_user;
static int g_write_remaining;
static int g_remaining_time32;
static void *g_registers;

static int64_t sleep_until(uint64_t deadline, uint64_t remaining_user,
                           int write_remaining, int remaining_time32,
                           void *registers) {
    g_deadline = deadline;
    g_remaining_user = remaining_user;
    g_write_remaining = write_remaining;
    g_remaining_time32 = remaining_time32;
    g_registers = registers;
    return g_result;
}

int main(void) {
    kernel_restart_block_t block;
    void *registers = (void *)(uintptr_t)0x1234u;

    kernel_restart_block_reset(&block);
    assert(kernel_restart_block_execute(
               &block, 10u, sleep_until, registers) ==
           -EDGE_LINUX_EINTR);

    kernel_restart_block_prepare_nanosleep(&block, 100u, 77u, 1, 1);
    g_result = -EDGE_LINUX_EINTR;
    assert(kernel_restart_block_execute(
               &block, 20u, sleep_until, registers) ==
           -EDGE_LINUX_EINTR);
    assert(block.operation == KERNEL_RESTART_BLOCK_NANOSLEEP);
    assert(g_deadline == 100u && g_remaining_user == 77u &&
           g_write_remaining == 1 && g_remaining_time32 == 1 &&
           g_registers == registers);

    g_result = 0;
    assert(kernel_restart_block_execute(
               &block, 30u, sleep_until, registers) == 0);
    assert(block.operation == KERNEL_RESTART_BLOCK_NONE);

    kernel_restart_block_prepare_nanosleep(&block, 100u, 0u, 0, 0);
    assert(kernel_restart_block_execute(
               &block, 100u, sleep_until, registers) == 0);
    assert(block.operation == KERNEL_RESTART_BLOCK_NONE);
    return 0;
}
