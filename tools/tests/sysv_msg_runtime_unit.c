/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent SysV message core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/sysv_msg_runtime.h"
#include "kernel/sysv_shm_runtime.h"

static kernel_linux_identity_t g_identity = {
    .global_tgid = 73,
    .global_tid = 73,
    .pid = 73,
    .tgid = 73,
    .tid = 73,
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

int main(void) {
    const uint32_t namespace_id = 17u;
    struct edge_linux_msqid_ds64 status;
    struct edge_linux_msginfo information;
    char output[16];
    int64_t type;
    int64_t identifier;

    assert(kernel_sysv_msg_get(namespace_id, 0x3344, 0) ==
           -EDGE_LINUX_ENOENT);
    identifier = kernel_sysv_msg_get(
        namespace_id, 0x3344, KERNEL_SYSV_IPC_CREAT | 0600);
    assert(identifier > 0);
    assert(kernel_sysv_msg_get(
               namespace_id, 0x3344,
               KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL | 0600) ==
           -EDGE_LINUX_EEXIST);
    assert(kernel_sysv_msg_get(namespace_id + 1u, 0x3344, 0) ==
           -EDGE_LINUX_ENOENT);

    assert(kernel_sysv_msg_send(
               namespace_id, (int32_t)identifier, 5, "five", 4, 0) == 0);
    assert(kernel_sysv_msg_send(
               namespace_id, (int32_t)identifier, 2, "two", 3, 0) == 0);
    assert(kernel_sysv_msg_send(
               namespace_id, (int32_t)identifier, 7, "seven", 5, 0) == 0);

    memset(output, 0, sizeof(output));
    assert(kernel_sysv_msg_receive(
               namespace_id, (int32_t)identifier, -6, output,
               sizeof(output), 0, &type) == 3);
    assert(type == 2 && memcmp(output, "two", 3) == 0);

    memset(output, 0, sizeof(output));
    assert(kernel_sysv_msg_receive(
               namespace_id, (int32_t)identifier, 1, output,
               sizeof(output), KERNEL_SYSV_MSG_COPY |
               KERNEL_SYSV_IPC_NOWAIT, &type) == 5);
    assert(type == 7 && memcmp(output, "seven", 5) == 0);

    assert(kernel_sysv_msg_receive(
               namespace_id, (int32_t)identifier, 5, output, 2, 0,
               &type) == -EDGE_LINUX_E2BIG);
    assert(kernel_sysv_msg_receive(
               namespace_id, (int32_t)identifier, 5, output, 2,
               KERNEL_SYSV_MSG_NOERROR, &type) == 2);
    assert(type == 5 && memcmp(output, "fi", 2) == 0);

    memset(&status, 0, sizeof(status));
    assert(kernel_sysv_msg_control(
               namespace_id, (int32_t)identifier,
               KERNEL_SYSV_IPC_STAT, &status, 0) == 0);
    assert(status.msg_perm.key == 0x3344 && status.msg_qnum == 1 &&
           status.msg_cbytes == 5 && status.msg_lspid == 73 &&
           status.msg_lrpid == 73);
    memset(&information, 0, sizeof(information));
    assert(kernel_sysv_msg_control(
               namespace_id, 0, KERNEL_SYSV_MSG_INFO, 0,
               &information) >= 0);
    assert(information.msgpool == 1 && information.msgmap == 1 &&
           information.msgtql == 5);

    assert(kernel_sysv_msg_receive(
               namespace_id, (int32_t)identifier, 0, output,
               sizeof(output), KERNEL_SYSV_IPC_NOWAIT, &type) == 5);
    assert(type == 7);
    assert(kernel_sysv_msg_receive(
               namespace_id, (int32_t)identifier, 0, output,
               sizeof(output), KERNEL_SYSV_IPC_NOWAIT, &type) ==
           -EDGE_LINUX_ENOMSG);
    assert(kernel_sysv_msg_control(
               namespace_id, (int32_t)identifier,
               KERNEL_SYSV_IPC_RMID, &status, 0) == 0);
    assert(kernel_sysv_msg_send(
               namespace_id, (int32_t)identifier, 1, 0, 0, 0) ==
           -EDGE_LINUX_EINVAL);

    puts("sysv_msg_runtime_unit: PASS");
    return 0;
}
