/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux SysV message queue core.
 * Copyright (c) EdgeOS Contributors.
 */

#include <limits.h>
#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/sysv_msg_runtime.h"
#include "kernel/sysv_shm_runtime.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

typedef struct kernel_sysv_message {
    uint8_t used;
    uint8_t reserved[3];
    int32_t next;
    int64_t type;
    uint32_t length;
    uint8_t data[KERNEL_SYSV_MSG_MAX_BYTES];
} kernel_sysv_message_t;

typedef struct kernel_sysv_msg_queue {
    uint8_t used;
    uint8_t reserved[3];
    int32_t identifier;
    int32_t key;
    uint32_t ipc_namespace_id;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint32_t mode;
    uint32_t sequence;
    uint64_t send_time_us;
    uint64_t receive_time_us;
    uint64_t change_time_us;
    uint64_t current_bytes;
    uint64_t message_count;
    uint64_t maximum_bytes;
    int32_t last_sender_pid;
    int32_t last_receiver_pid;
    int32_t first_message;
    int32_t last_message;
} kernel_sysv_msg_queue_t;

static kernel_sysv_msg_queue_t
    g_sysv_msg_queues[KERNEL_SYSV_MSG_MAX_QUEUES];
static kernel_sysv_message_t
    g_sysv_messages[KERNEL_SYSV_MSG_MAX_MESSAGES];
static spinlock_t g_sysv_msg_lock;
static uint32_t g_sysv_msg_next_identifier = 1u;
static uint32_t g_sysv_msg_next_sequence = 1u;

static int kernel_sysv_msg_capable(const kernel_linux_identity_t *identity,
                                   uint32_t capability) {
    return identity && capability < 64u &&
           (identity->effective_capabilities & (1ull << capability));
}

static uint32_t kernel_sysv_msg_granted_bits(
        const kernel_sysv_msg_queue_t *queue,
        const kernel_linux_identity_t *identity) {
    if (identity->euid == queue->uid || identity->euid == queue->cuid)
        return (queue->mode >> 6) & 7u;
    if (kernel_current_in_group(queue->gid) ||
        kernel_current_in_group(queue->cgid))
        return (queue->mode >> 3) & 7u;
    return queue->mode & 7u;
}

static int kernel_sysv_msg_has_access(
        const kernel_sysv_msg_queue_t *queue,
        const kernel_linux_identity_t *identity, uint32_t requested) {
    if ((kernel_sysv_msg_granted_bits(queue, identity) & requested) ==
        requested)
        return 1;
    return kernel_sysv_msg_capable(identity, EDGE_LINUX_CAP_IPC_OWNER);
}

static int kernel_sysv_msg_is_owner(
        const kernel_sysv_msg_queue_t *queue,
        const kernel_linux_identity_t *identity) {
    return identity &&
           (identity->euid == queue->uid || identity->euid == queue->cuid ||
            kernel_sysv_msg_capable(identity, EDGE_LINUX_CAP_SYS_ADMIN));
}

static int kernel_sysv_msg_by_identifier_locked(
        int32_t identifier, uint32_t ipc_namespace_id) {
    for (uint32_t index = 0; index < KERNEL_SYSV_MSG_MAX_QUEUES; ++index) {
        const kernel_sysv_msg_queue_t *queue = &g_sysv_msg_queues[index];
        if (queue->used && queue->identifier == identifier &&
            queue->ipc_namespace_id == ipc_namespace_id)
            return (int)index;
    }
    return -1;
}

static int kernel_sysv_msg_by_key_locked(int32_t key,
                                         uint32_t ipc_namespace_id) {
    for (uint32_t index = 0; index < KERNEL_SYSV_MSG_MAX_QUEUES; ++index) {
        const kernel_sysv_msg_queue_t *queue = &g_sysv_msg_queues[index];
        if (queue->used && queue->key == key &&
            queue->ipc_namespace_id == ipc_namespace_id)
            return (int)index;
    }
    return -1;
}

static int kernel_sysv_msg_free_queue_locked(void) {
    for (uint32_t index = 0; index < KERNEL_SYSV_MSG_MAX_QUEUES; ++index)
        if (!g_sysv_msg_queues[index].used) return (int)index;
    return -1;
}

static int kernel_sysv_msg_free_message_locked(void) {
    for (uint32_t index = 0; index < KERNEL_SYSV_MSG_MAX_MESSAGES; ++index)
        if (!g_sysv_messages[index].used) return (int)index;
    return -1;
}

static void kernel_sysv_msg_status_fill(
        const kernel_sysv_msg_queue_t *queue,
        struct edge_linux_msqid_ds64 *status) {
    memset(status, 0, sizeof(*status));
    status->msg_perm.key = queue->key;
    status->msg_perm.uid = queue->uid;
    status->msg_perm.gid = queue->gid;
    status->msg_perm.cuid = queue->cuid;
    status->msg_perm.cgid = queue->cgid;
    status->msg_perm.mode = queue->mode;
    status->msg_perm.sequence = (int32_t)queue->sequence;
    status->msg_stime = (int64_t)(queue->send_time_us / 1000000u);
    status->msg_rtime = (int64_t)(queue->receive_time_us / 1000000u);
    status->msg_ctime = (int64_t)(queue->change_time_us / 1000000u);
    status->msg_cbytes = queue->current_bytes;
    status->msg_qnum = queue->message_count;
    status->msg_qbytes = queue->maximum_bytes;
    status->msg_lspid = queue->last_sender_pid;
    status->msg_lrpid = queue->last_receiver_pid;
}

int64_t kernel_sysv_msg_get(uint32_t ipc_namespace_id, int32_t key,
                            uint32_t flags) {
    kernel_linux_identity_t identity;
    kernel_sysv_msg_queue_t *queue;
    uint64_t lock_flags;
    int queue_index;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_sysv_msg_lock);
    if (key != KERNEL_SYSV_IPC_PRIVATE) {
        queue_index = kernel_sysv_msg_by_key_locked(key, ipc_namespace_id);
        if (queue_index >= 0) {
            uint32_t requested = ((flags & 0444u) ? 4u : 0u) |
                                 ((flags & 0222u) ? 2u : 0u);
            queue = &g_sysv_msg_queues[queue_index];
            if ((flags & (KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL)) ==
                (KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL)) {
                spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
                return -EDGE_LINUX_EEXIST;
            }
            if (!kernel_sysv_msg_has_access(queue, &identity, requested)) {
                spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
                return -EDGE_LINUX_EACCES;
            }
            queue_index = queue->identifier;
            spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
            return queue_index;
        }
        if (!(flags & KERNEL_SYSV_IPC_CREAT)) {
            spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
            return -EDGE_LINUX_ENOENT;
        }
    }
    queue_index = kernel_sysv_msg_free_queue_locked();
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_ENOSPC;
    }
    queue = &g_sysv_msg_queues[queue_index];
    memset(queue, 0, sizeof(*queue));
    queue->used = 1u;
    queue->identifier = (int32_t)g_sysv_msg_next_identifier++;
    if (!g_sysv_msg_next_identifier) g_sysv_msg_next_identifier = 1u;
    queue->key = key;
    queue->ipc_namespace_id = ipc_namespace_id;
    queue->uid = identity.euid;
    queue->gid = identity.egid;
    queue->cuid = identity.euid;
    queue->cgid = identity.egid;
    queue->mode = flags & 0777u;
    queue->sequence = g_sysv_msg_next_sequence++;
    if (!g_sysv_msg_next_sequence) g_sysv_msg_next_sequence = 1u;
    queue->change_time_us = boottime_realtime_us();
    queue->maximum_bytes = KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES;
    queue->first_message = -1;
    queue->last_message = -1;
    queue_index = queue->identifier;
    spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
    return queue_index;
}

int64_t kernel_sysv_msg_send(uint32_t ipc_namespace_id, int32_t identifier,
                             int64_t type, const void *data, uint32_t length,
                             uint32_t flags) {
    kernel_linux_identity_t identity;
    kernel_sysv_msg_queue_t *queue;
    kernel_sysv_message_t *message;
    uint64_t lock_flags;
    int message_index;
    int queue_index;

    (void)flags;
    if (identifier < 0 || type < 1 || length > KERNEL_SYSV_MSG_MAX_BYTES)
        return -EDGE_LINUX_EINVAL;
    if (length && !data) return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_sysv_msg_lock);
    queue_index = kernel_sysv_msg_by_identifier_locked(
        identifier, ipc_namespace_id);
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    queue = &g_sysv_msg_queues[queue_index];
    if (!kernel_sysv_msg_has_access(queue, &identity, 2u)) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EACCES;
    }
    if (queue->current_bytes + length > queue->maximum_bytes ||
        queue->message_count + 1u > queue->maximum_bytes) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    message_index = kernel_sysv_msg_free_message_locked();
    if (message_index < 0) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_ENOMEM;
    }
    message = &g_sysv_messages[message_index];
    message->used = 1u;
    memset(message->reserved, 0, sizeof(message->reserved));
    message->next = -1;
    message->type = type;
    message->length = length;
    if (length) memcpy(message->data, data, length);
    if (queue->last_message >= 0)
        g_sysv_messages[queue->last_message].next = message_index;
    else
        queue->first_message = message_index;
    queue->last_message = message_index;
    queue->current_bytes += length;
    ++queue->message_count;
    queue->last_sender_pid = identity.tgid;
    queue->send_time_us = boottime_realtime_us();
    spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
    return 0;
}

static int kernel_sysv_msg_select_locked(
        const kernel_sysv_msg_queue_t *queue, int64_t requested_type,
        uint32_t flags, int32_t *previous_out) {
    int32_t previous = -1;
    int32_t current = queue->first_message;
    int32_t selected = -1;
    int32_t selected_previous = -1;
    uint64_t limit;
    uint64_t ordinal = 0;

    if (requested_type < 0) {
        limit = requested_type == INT64_MIN ?
            (uint64_t)INT64_MAX : (uint64_t)(-requested_type);
    } else {
        limit = (uint64_t)requested_type;
    }
    while (current >= 0) {
        const kernel_sysv_message_t *message = &g_sysv_messages[current];
        int match = 0;
        if (flags & KERNEL_SYSV_MSG_COPY)
            match = requested_type >= 0 && ordinal == limit;
        else if (!requested_type)
            match = 1;
        else if (requested_type > 0)
            match = (flags & KERNEL_SYSV_MSG_EXCEPT) ?
                message->type != requested_type :
                message->type == requested_type;
        else if ((uint64_t)message->type <= limit &&
                 (selected < 0 || message->type <
                  g_sysv_messages[selected].type)) {
            selected = current;
            selected_previous = previous;
        }
        if (match) {
            *previous_out = previous;
            return current;
        }
        previous = current;
        current = message->next;
        ++ordinal;
    }
    *previous_out = selected_previous;
    return selected;
}

int64_t kernel_sysv_msg_receive(uint32_t ipc_namespace_id,
                                int32_t identifier, int64_t requested_type,
                                void *data, uint32_t capacity,
                                uint32_t flags, int64_t *type) {
    kernel_linux_identity_t identity;
    kernel_sysv_msg_queue_t *queue;
    kernel_sysv_message_t *message;
    uint64_t lock_flags;
    uint32_t copy_length;
    int32_t previous;
    int message_index;
    int queue_index;

    if (identifier < 0 || !type || (capacity && !data))
        return -EDGE_LINUX_EINVAL;
    if ((flags & KERNEL_SYSV_MSG_COPY) &&
        ((flags & KERNEL_SYSV_MSG_EXCEPT) ||
         !(flags & KERNEL_SYSV_IPC_NOWAIT)))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_sysv_msg_lock);
    queue_index = kernel_sysv_msg_by_identifier_locked(
        identifier, ipc_namespace_id);
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    queue = &g_sysv_msg_queues[queue_index];
    if (!kernel_sysv_msg_has_access(queue, &identity, 4u)) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EACCES;
    }
    message_index = kernel_sysv_msg_select_locked(
        queue, requested_type, flags, &previous);
    if (message_index < 0) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_ENOMSG;
    }
    message = &g_sysv_messages[message_index];
    if (capacity < message->length && !(flags & KERNEL_SYSV_MSG_NOERROR)) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_E2BIG;
    }
    copy_length = capacity < message->length ? capacity : message->length;
    *type = message->type;
    if (copy_length) memcpy(data, message->data, copy_length);
    if (!(flags & KERNEL_SYSV_MSG_COPY)) {
        if (previous >= 0)
            g_sysv_messages[previous].next = message->next;
        else
            queue->first_message = message->next;
        if (queue->last_message == message_index)
            queue->last_message = previous;
        queue->current_bytes -= message->length;
        --queue->message_count;
        queue->last_receiver_pid = identity.tgid;
        queue->receive_time_us = boottime_realtime_us();
        message->used = 0u;
        message->next = 0;
        message->type = 0;
        message->length = 0u;
    }
    spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
    return copy_length;
}

static void kernel_sysv_msg_information_fill(
        uint32_t ipc_namespace_id, uint32_t command,
        struct edge_linux_msginfo *information, int *maximum_index) {
    uint32_t queue_count = 0;
    uint32_t message_count = 0;
    uint64_t byte_count = 0;

    memset(information, 0, sizeof(*information));
    *maximum_index = 0;
    for (uint32_t index = 0; index < KERNEL_SYSV_MSG_MAX_QUEUES; ++index) {
        const kernel_sysv_msg_queue_t *queue = &g_sysv_msg_queues[index];
        if (!queue->used || queue->ipc_namespace_id != ipc_namespace_id)
            continue;
        ++queue_count;
        message_count += (uint32_t)queue->message_count;
        byte_count += queue->current_bytes;
        *maximum_index = (int)index;
    }
    information->msgmax = KERNEL_SYSV_MSG_MAX_BYTES;
    information->msgmnb = KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES;
    information->msgmni = KERNEL_SYSV_MSG_MAX_QUEUES;
    information->msgssz = 16;
    information->msgseg = UINT16_MAX;
    if (command == KERNEL_SYSV_MSG_INFO) {
        information->msgpool = (int32_t)queue_count;
        information->msgmap = (int32_t)message_count;
        information->msgtql = byte_count > INT32_MAX ?
            INT32_MAX : (int32_t)byte_count;
    } else {
        information->msgpool = (KERNEL_SYSV_MSG_MAX_QUEUES *
                                KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES) / 1024u;
        information->msgmap = KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES;
        information->msgtql = KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES;
    }
}

int64_t kernel_sysv_msg_control(uint32_t ipc_namespace_id,
                                int32_t identifier, uint32_t command,
                                struct edge_linux_msqid_ds64 *status,
                                struct edge_linux_msginfo *information) {
    kernel_linux_identity_t identity;
    kernel_sysv_msg_queue_t *queue;
    uint32_t operation = command & 0xffu;
    uint64_t lock_flags;
    int queue_index;
    int result = 0;

    if (identifier < 0 || (command & ~(KERNEL_SYSV_IPC_64 | 0xffu)))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_sysv_msg_lock);
    if (operation == KERNEL_SYSV_IPC_INFO ||
        operation == KERNEL_SYSV_MSG_INFO) {
        if (!information) result = -EDGE_LINUX_EFAULT;
        else kernel_sysv_msg_information_fill(
            ipc_namespace_id, operation, information, &result);
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return result;
    }
    if (operation == KERNEL_SYSV_MSG_STAT ||
        operation == KERNEL_SYSV_MSG_STAT_ANY) {
        if ((uint32_t)identifier >= KERNEL_SYSV_MSG_MAX_QUEUES ||
            !g_sysv_msg_queues[identifier].used ||
            g_sysv_msg_queues[identifier].ipc_namespace_id !=
                ipc_namespace_id) {
            spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
            return -EDGE_LINUX_EINVAL;
        }
        queue_index = identifier;
    } else {
        queue_index = kernel_sysv_msg_by_identifier_locked(
            identifier, ipc_namespace_id);
    }
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    queue = &g_sysv_msg_queues[queue_index];
    if (operation != KERNEL_SYSV_MSG_STAT_ANY &&
        operation != KERNEL_SYSV_IPC_RMID &&
        operation != KERNEL_SYSV_IPC_SET &&
        !kernel_sysv_msg_has_access(queue, &identity, 4u)) {
        spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
        return -EDGE_LINUX_EACCES;
    }
    switch (operation) {
    case KERNEL_SYSV_IPC_RMID:
        if (!kernel_sysv_msg_is_owner(queue, &identity)) {
            result = -EDGE_LINUX_EPERM;
        } else {
            int32_t current = queue->first_message;
            while (current >= 0) {
                int32_t next = g_sysv_messages[current].next;
                g_sysv_messages[current].used = 0u;
                g_sysv_messages[current].next = 0;
                g_sysv_messages[current].type = 0;
                g_sysv_messages[current].length = 0u;
                current = next;
            }
            memset(queue, 0, sizeof(*queue));
        }
        break;
    case KERNEL_SYSV_IPC_SET:
        if (!status) {
            result = -EDGE_LINUX_EFAULT;
        } else if (!kernel_sysv_msg_is_owner(queue, &identity)) {
            result = -EDGE_LINUX_EPERM;
        } else if (status->msg_qbytes >
                       KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES &&
                   !kernel_sysv_msg_capable(
                       &identity, EDGE_LINUX_CAP_SYS_RESOURCE)) {
            result = -EDGE_LINUX_EPERM;
        } else {
            queue->uid = status->msg_perm.uid;
            queue->gid = status->msg_perm.gid;
            queue->mode = status->msg_perm.mode & 0777u;
            queue->maximum_bytes = status->msg_qbytes;
            queue->change_time_us = boottime_realtime_us();
        }
        break;
    case KERNEL_SYSV_IPC_STAT:
    case KERNEL_SYSV_MSG_STAT:
    case KERNEL_SYSV_MSG_STAT_ANY:
        if (!status) result = -EDGE_LINUX_EFAULT;
        else kernel_sysv_msg_status_fill(queue, status);
        if (!result && operation != KERNEL_SYSV_IPC_STAT)
            result = queue->identifier;
        break;
    default:
        result = -EDGE_LINUX_EINVAL;
        break;
    }
    spin_unlock_irqrestore(&g_sysv_msg_lock, lock_flags);
    return result;
}
