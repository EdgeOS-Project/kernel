/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent POSIX mq core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/posix_mq_runtime.h"
#include "kernel/process_runtime.h"

static kernel_linux_identity_t g_identity = {
    .pid = 91,
    .tid = 91,
    .tgid = 91,
    .uid = 1000,
    .euid = 1000,
    .gid = 1000,
    .egid = 1000,
};
static int g_changed;
static int g_notified;

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    *identity = g_identity;
    return 0;
}

int kernel_current_in_group(uint32_t gid) {
    return gid == g_identity.egid;
}

void kernel_posix_mq_state_changed(int32_t queue_id) {
    assert(queue_id > 0);
    ++g_changed;
}

int kernel_posix_mq_deliver_notification(int32_t target_tgid,
                                         uint32_t signal,
                                         uint64_t value,
                                         int32_t sender_pid,
                                         uint32_t sender_uid) {
    assert(target_tgid == 91 && signal == 10 && value == 0x1234 &&
           sender_pid == 91 && sender_uid == 1000);
    ++g_notified;
    return 0;
}

int main(void) {
    struct edge_linux_mq_attr attributes = {
        .mq_maxmsg = 3,
        .mq_msgsize = 16,
    };
    kernel_posix_mq_notification_t notification = {
        .notify = 0,
        .signal = 10,
        .value = 0x1234,
    };
    kernel_posix_mq_state_t state;
    char buffer[16];
    uint32_t priority;
    int64_t queue;

    assert(kernel_posix_mq_open(3, "missing", 0, 0600, 0) ==
           -EDGE_LINUX_ENOENT);
    queue = kernel_posix_mq_open(
        3, "edge-test", KERNEL_POSIX_MQ_O_CREAT |
        KERNEL_POSIX_MQ_O_RDWR, 0600, &attributes);
    assert(queue > 0);
    assert(kernel_posix_mq_open(
               3, "edge-test", KERNEL_POSIX_MQ_O_CREAT |
               KERNEL_POSIX_MQ_O_EXCL | KERNEL_POSIX_MQ_O_RDWR,
               0600, &attributes) == -EDGE_LINUX_EEXIST);
    assert(kernel_posix_mq_notify((int32_t)queue, &notification) == 0);
    assert(kernel_posix_mq_send((int32_t)queue, "low", 3, 1) == 0);
    assert(g_notified == 1);
    assert(kernel_posix_mq_send((int32_t)queue, "high", 4, 7) == 0);
    assert(kernel_posix_mq_send((int32_t)queue, "mid", 3, 4) == 0);
    assert(kernel_posix_mq_send((int32_t)queue, "full", 4, 2) ==
           -EDGE_LINUX_EAGAIN);
    assert(kernel_posix_mq_query((int32_t)queue, &state) == 0);
    assert(state.current_messages == 3 && state.readable && !state.writable &&
           state.maximum_messages == 3 && state.maximum_message_size == 16);

    memset(buffer, 0, sizeof(buffer));
    assert(kernel_posix_mq_receive(
               (int32_t)queue, buffer, sizeof(buffer), &priority) == 4);
    assert(priority == 7 && memcmp(buffer, "high", 4) == 0);
    assert(kernel_posix_mq_receive(
               (int32_t)queue, buffer, sizeof(buffer), &priority) == 3);
    assert(priority == 4 && memcmp(buffer, "mid", 3) == 0);
    assert(kernel_posix_mq_receive(
               (int32_t)queue, buffer, sizeof(buffer), &priority) == 3);
    assert(priority == 1 && memcmp(buffer, "low", 3) == 0);
    assert(kernel_posix_mq_receive(
               (int32_t)queue, buffer, sizeof(buffer), &priority) ==
           -EDGE_LINUX_EAGAIN);

    assert(kernel_posix_mq_retain((int32_t)queue) == 0);
    assert(kernel_posix_mq_unlink(3, "edge-test") == 0);
    assert(kernel_posix_mq_open(3, "edge-test", 0, 0600, 0) ==
           -EDGE_LINUX_ENOENT);
    assert(kernel_posix_mq_query((int32_t)queue, &state) == 0);
    kernel_posix_mq_release((int32_t)queue);
    kernel_posix_mq_release((int32_t)queue);
    assert(kernel_posix_mq_query((int32_t)queue, &state) ==
           -EDGE_LINUX_EBADF);
    assert(g_changed >= 6);

    puts("posix_mq_runtime_unit: PASS");
    return 0;
}
