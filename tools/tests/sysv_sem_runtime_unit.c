/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent SysV semaphore core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/sysv_sem_runtime.h"
#include "kernel/sysv_shm_runtime.h"

static kernel_linux_identity_t g_identity = {
    .global_tgid = 41,
    .global_tid = 41,
    .pid = 41,
    .tgid = 41,
    .tid = 41,
    .uid = 1000,
    .euid = 1000,
    .suid = 1000,
    .fsuid = 1000,
    .gid = 1000,
    .egid = 1000,
    .sgid = 1000,
    .fsgid = 1000,
};
static uint64_t g_time = 1000000u;

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    *identity = g_identity;
    return 0;
}

int kernel_current_in_group(uint32_t gid) {
    return gid == g_identity.egid;
}

uint64_t boottime_realtime_us(void) {
    return g_time++;
}

static void test_create_and_atomic_operations(void) {
    const uint32_t namespace_id = 7u;
    struct edge_linux_sembuf operations[2] = {
        {.sem_num = 0, .sem_op = -1, .sem_flg = 0},
        {.sem_num = 1, .sem_op = 1, .sem_flg = 0},
    };
    kernel_sysv_sem_status_t status;
    kernel_sysv_sem_wait_t wait;
    uint16_t values[2] = {2, 0};
    int64_t identifier;

    identifier = kernel_sysv_sem_get(
        namespace_id, 0x1234, 2, KERNEL_SYSV_IPC_CREAT | 0600);
    assert(identifier > 0);
    assert(kernel_sysv_sem_get(namespace_id, 0x1234, 3, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_sysv_sem_get(namespace_id + 1u, 0x1234, 2, 0) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 0,
               KERNEL_SYSV_SEM_SETALL, 0, values, 2, &status, 0) == 0);
    assert(kernel_sysv_sem_operate(
               namespace_id, (int32_t)identifier, operations, 2, &wait) == 0);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 0,
               KERNEL_SYSV_SEM_GETVAL, 0, 0, 0, &status, 0) == 1);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 1,
               KERNEL_SYSV_SEM_GETVAL, 0, 0, 0, &status, 0) == 1);

    operations[0].sem_op = -2;
    operations[1].sem_op = 1;
    assert(kernel_sysv_sem_operate(
               namespace_id, (int32_t)identifier, operations, 2, &wait) ==
           -EDGE_LINUX_EAGAIN);
    assert(wait.valid && wait.semaphore_number == 0 && !wait.wait_for_zero);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 1,
               KERNEL_SYSV_SEM_GETVAL, 0, 0, 0, &status, 0) == 1);
}

static void test_sem_undo_and_removal(void) {
    const uint32_t namespace_id = 9u;
    struct edge_linux_sembuf operation = {
        .sem_num = 0,
        .sem_op = 2,
        .sem_flg = KERNEL_SYSV_SEM_UNDO,
    };
    kernel_sysv_sem_status_t status;
    kernel_sysv_sem_wait_t wait;
    int64_t identifier = kernel_sysv_sem_get(
        namespace_id, KERNEL_SYSV_IPC_PRIVATE, 1,
        KERNEL_SYSV_IPC_CREAT | 0600);

    assert(identifier > 0);
    assert(kernel_sysv_sem_operate(
               namespace_id, (int32_t)identifier, &operation, 1, &wait) == 0);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 0,
               KERNEL_SYSV_SEM_GETVAL, 0, 0, 0, &status, 0) == 2);
    kernel_sysv_sem_task_exit(g_identity.tid);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 0,
               KERNEL_SYSV_SEM_GETVAL, 0, 0, 0, &status, 0) == 0);
    assert(kernel_sysv_sem_control(
               namespace_id, (int32_t)identifier, 0,
               KERNEL_SYSV_IPC_RMID, 0, 0, 0, &status, 0) == 0);
    assert(kernel_sysv_sem_operate(
               namespace_id, (int32_t)identifier, &operation, 1, &wait) ==
           -EDGE_LINUX_EINVAL);
}

int main(void) {
    test_create_and_atomic_operations();
    test_sem_undo_and_removal();
    puts("sysv_sem_runtime_unit: PASS");
    return 0;
}
