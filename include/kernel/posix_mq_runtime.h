/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent POSIX message queue interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_POSIX_MQ_RUNTIME_H
#define EDGEOS_KERNEL_POSIX_MQ_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_POSIX_MQ_NAME_MAX 255u
#define KERNEL_POSIX_MQ_MAX_QUEUES 128u
#define KERNEL_POSIX_MQ_MAX_MESSAGES 512u
#define KERNEL_POSIX_MQ_DEFAULT_MAX_MESSAGES 10u
#define KERNEL_POSIX_MQ_HARD_MAX_MESSAGES 64u
#define KERNEL_POSIX_MQ_DEFAULT_MESSAGE_SIZE 8192u
#define KERNEL_POSIX_MQ_HARD_MESSAGE_SIZE 8192u
#define KERNEL_POSIX_MQ_PRIORITY_MAX 32768u

#define KERNEL_POSIX_MQ_O_RDONLY 0u
#define KERNEL_POSIX_MQ_O_WRONLY 1u
#define KERNEL_POSIX_MQ_O_RDWR 2u
#define KERNEL_POSIX_MQ_O_ACCMODE 3u
#define KERNEL_POSIX_MQ_O_CREAT 00000100u
#define KERNEL_POSIX_MQ_O_EXCL 00000200u
#define KERNEL_POSIX_MQ_O_NONBLOCK 00004000u
#define KERNEL_POSIX_MQ_O_CLOEXEC 02000000u

typedef struct kernel_posix_mq_state {
    uint32_t current_messages;
    uint32_t maximum_messages;
    uint32_t maximum_message_size;
    uint8_t readable;
    uint8_t writable;
} kernel_posix_mq_state_t;

typedef struct kernel_posix_mq_notification {
    int32_t notify;
    int32_t signal;
    uint64_t value;
} kernel_posix_mq_notification_t;

int64_t kernel_posix_mq_open(uint32_t ipc_namespace_id, const char *name,
                             uint32_t flags, uint32_t mode,
                             const struct edge_linux_mq_attr *attributes);
int kernel_posix_mq_retain(int32_t queue_id);
void kernel_posix_mq_release(int32_t queue_id);
int kernel_posix_mq_unlink(uint32_t ipc_namespace_id, const char *name);
int64_t kernel_posix_mq_send(int32_t queue_id, const void *data,
                             uint32_t length, uint32_t priority);
int64_t kernel_posix_mq_receive(int32_t queue_id, void *data,
                                uint32_t capacity, uint32_t *priority);
int kernel_posix_mq_query(int32_t queue_id,
                          kernel_posix_mq_state_t *state);
int kernel_posix_mq_notify(int32_t queue_id,
                           const kernel_posix_mq_notification_t *event);

void kernel_posix_mq_state_changed(int32_t queue_id);
int kernel_posix_mq_deliver_notification(int32_t target_tgid,
                                         uint32_t signal,
                                         uint64_t value,
                                         int32_t sender_pid,
                                         uint32_t sender_uid);

#endif
