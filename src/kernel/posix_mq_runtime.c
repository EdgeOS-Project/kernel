/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux POSIX message queue core.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/linux_errno.h"
#include "kernel/posix_mq_runtime.h"
#include "kernel/process_runtime.h"
#include "string.h"
#include "sys/spinlock.h"

typedef struct kernel_posix_mq_message {
    uint8_t used;
    uint8_t reserved[3];
    int32_t next;
    uint32_t priority;
    uint32_t length;
    uint8_t data[KERNEL_POSIX_MQ_HARD_MESSAGE_SIZE];
} kernel_posix_mq_message_t;

typedef struct kernel_posix_mq_queue {
    uint8_t used;
    uint8_t linked;
    uint8_t notify_armed;
    uint8_t notify_kind;
    int32_t identifier;
    uint32_t ipc_namespace_id;
    uint32_t references;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
    uint32_t maximum_messages;
    uint32_t maximum_message_size;
    uint32_t current_messages;
    int32_t first_message;
    int32_t notify_tgid;
    int32_t notify_signal;
    uint64_t notify_value;
    char name[KERNEL_POSIX_MQ_NAME_MAX + 1u];
} kernel_posix_mq_queue_t;

typedef struct kernel_posix_mq_delivery {
    uint8_t armed;
    int32_t queue_id;
    int32_t target_tgid;
    uint32_t signal;
    uint64_t value;
    int32_t sender_pid;
    uint32_t sender_uid;
} kernel_posix_mq_delivery_t;

static kernel_posix_mq_queue_t
    g_posix_mq_queues[KERNEL_POSIX_MQ_MAX_QUEUES];
static kernel_posix_mq_message_t
    g_posix_mq_messages[KERNEL_POSIX_MQ_MAX_MESSAGES];
static spinlock_t g_posix_mq_lock;
static uint32_t g_posix_mq_next_identifier = 1u;

static int posix_mq_capable(const kernel_linux_identity_t *identity,
                            uint32_t capability) {
    return identity && capability < 64u &&
           (identity->effective_capabilities & (1ull << capability));
}

static uint32_t posix_mq_access_bits(
        const kernel_posix_mq_queue_t *queue,
        const kernel_linux_identity_t *identity) {
    if (identity->euid == queue->uid) return (queue->mode >> 6) & 7u;
    if (kernel_current_in_group(queue->gid)) return (queue->mode >> 3) & 7u;
    return queue->mode & 7u;
}

static int posix_mq_has_access(const kernel_posix_mq_queue_t *queue,
                               const kernel_linux_identity_t *identity,
                               uint32_t requested) {
    return (posix_mq_access_bits(queue, identity) & requested) == requested ||
           posix_mq_capable(identity, EDGE_LINUX_CAP_IPC_OWNER);
}

static int posix_mq_valid_name(const char *name) {
    uint32_t length = 0;
    if (!name || !name[0]) return 0;
    while (name[length]) {
        if (length > KERNEL_POSIX_MQ_NAME_MAX) return 0;
        if (name[length] == '/') return 0;
        ++length;
    }
    return length <= KERNEL_POSIX_MQ_NAME_MAX;
}

static int posix_mq_find_id_locked(int32_t identifier) {
    for (uint32_t index = 0; index < KERNEL_POSIX_MQ_MAX_QUEUES; ++index)
        if (g_posix_mq_queues[index].used &&
            g_posix_mq_queues[index].identifier == identifier)
            return (int)index;
    return -1;
}

static int posix_mq_find_name_locked(uint32_t ipc_namespace_id,
                                     const char *name) {
    for (uint32_t index = 0; index < KERNEL_POSIX_MQ_MAX_QUEUES; ++index) {
        const kernel_posix_mq_queue_t *queue = &g_posix_mq_queues[index];
        if (queue->used && queue->linked &&
            queue->ipc_namespace_id == ipc_namespace_id &&
            strcmp(queue->name, name) == 0)
            return (int)index;
    }
    return -1;
}

static int posix_mq_free_queue_locked(void) {
    for (uint32_t index = 0; index < KERNEL_POSIX_MQ_MAX_QUEUES; ++index)
        if (!g_posix_mq_queues[index].used) return (int)index;
    return -1;
}

static int posix_mq_free_message_locked(void) {
    for (uint32_t index = 0; index < KERNEL_POSIX_MQ_MAX_MESSAGES; ++index)
        if (!g_posix_mq_messages[index].used) return (int)index;
    return -1;
}

static void posix_mq_destroy_locked(kernel_posix_mq_queue_t *queue) {
    int32_t current = queue->first_message;
    while (current >= 0) {
        int32_t next = g_posix_mq_messages[current].next;
        g_posix_mq_messages[current].used = 0u;
        g_posix_mq_messages[current].next = 0;
        g_posix_mq_messages[current].priority = 0u;
        g_posix_mq_messages[current].length = 0u;
        current = next;
    }
    memset(queue, 0, sizeof(*queue));
}

static uint32_t posix_mq_requested_access(uint32_t flags) {
    switch (flags & KERNEL_POSIX_MQ_O_ACCMODE) {
    case KERNEL_POSIX_MQ_O_RDONLY:
        return 4u;
    case KERNEL_POSIX_MQ_O_WRONLY:
        return 2u;
    case KERNEL_POSIX_MQ_O_RDWR:
        return 6u;
    default:
        return 0u;
    }
}

int64_t kernel_posix_mq_open(uint32_t ipc_namespace_id, const char *name,
                             uint32_t flags, uint32_t mode,
                             const struct edge_linux_mq_attr *attributes) {
    const uint32_t allowed = KERNEL_POSIX_MQ_O_ACCMODE |
        KERNEL_POSIX_MQ_O_CREAT | KERNEL_POSIX_MQ_O_EXCL |
        KERNEL_POSIX_MQ_O_NONBLOCK | KERNEL_POSIX_MQ_O_CLOEXEC;
    kernel_linux_identity_t identity;
    kernel_posix_mq_queue_t *queue;
    uint32_t requested;
    uint32_t maximum_messages = KERNEL_POSIX_MQ_DEFAULT_MAX_MESSAGES;
    uint32_t maximum_message_size =
        KERNEL_POSIX_MQ_DEFAULT_MESSAGE_SIZE;
    uint64_t lock_flags;
    int queue_index;

    if (!posix_mq_valid_name(name)) return -EDGE_LINUX_EINVAL;
    if ((flags & ~allowed) ||
        (flags & KERNEL_POSIX_MQ_O_ACCMODE) ==
            KERNEL_POSIX_MQ_O_ACCMODE)
        return -EDGE_LINUX_EINVAL;
    requested = posix_mq_requested_access(flags);
    if (!requested) return -EDGE_LINUX_EINVAL;
    if (attributes && (flags & KERNEL_POSIX_MQ_O_CREAT)) {
        if (attributes->mq_maxmsg <= 0 ||
            attributes->mq_maxmsg > KERNEL_POSIX_MQ_HARD_MAX_MESSAGES ||
            attributes->mq_msgsize <= 0 ||
            attributes->mq_msgsize > KERNEL_POSIX_MQ_HARD_MESSAGE_SIZE)
            return -EDGE_LINUX_EINVAL;
        maximum_messages = (uint32_t)attributes->mq_maxmsg;
        maximum_message_size = (uint32_t)attributes->mq_msgsize;
    }
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (maximum_messages > KERNEL_POSIX_MQ_DEFAULT_MAX_MESSAGES &&
        !posix_mq_capable(&identity, EDGE_LINUX_CAP_SYS_RESOURCE))
        return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    queue_index = posix_mq_find_name_locked(ipc_namespace_id, name);
    if (queue_index >= 0) {
        queue = &g_posix_mq_queues[queue_index];
        if ((flags & (KERNEL_POSIX_MQ_O_CREAT | KERNEL_POSIX_MQ_O_EXCL)) ==
            (KERNEL_POSIX_MQ_O_CREAT | KERNEL_POSIX_MQ_O_EXCL)) {
            spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
            return -EDGE_LINUX_EEXIST;
        }
        if (!posix_mq_has_access(queue, &identity, requested)) {
            spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
            return -EDGE_LINUX_EACCES;
        }
        if (queue->references == UINT32_MAX) {
            spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
            return -EDGE_LINUX_EOVERFLOW;
        }
        ++queue->references;
        queue_index = queue->identifier;
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return queue_index;
    }
    if (!(flags & KERNEL_POSIX_MQ_O_CREAT)) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_ENOENT;
    }
    queue_index = posix_mq_free_queue_locked();
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_ENOSPC;
    }
    queue = &g_posix_mq_queues[queue_index];
    memset(queue, 0, sizeof(*queue));
    queue->used = 1u;
    queue->linked = 1u;
    queue->identifier = (int32_t)g_posix_mq_next_identifier++;
    if (!g_posix_mq_next_identifier) g_posix_mq_next_identifier = 1u;
    queue->ipc_namespace_id = ipc_namespace_id;
    queue->references = 1u;
    queue->uid = identity.euid;
    queue->gid = identity.egid;
    queue->mode = mode & 0777u;
    queue->maximum_messages = maximum_messages;
    queue->maximum_message_size = maximum_message_size;
    queue->first_message = -1;
    memcpy(queue->name, name, strlen(name) + 1u);
    queue_index = queue->identifier;
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    return queue_index;
}

int kernel_posix_mq_retain(int32_t queue_id) {
    uint64_t lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    int index = posix_mq_find_id_locked(queue_id);
    if (index < 0 || g_posix_mq_queues[index].references == UINT32_MAX) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return index < 0 ? -EDGE_LINUX_EBADF : -EDGE_LINUX_EOVERFLOW;
    }
    ++g_posix_mq_queues[index].references;
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    return 0;
}

void kernel_posix_mq_release(int32_t queue_id) {
    kernel_linux_identity_t identity;
    int have_identity =
        kernel_current_linux_identity(&identity) == 0;
    uint64_t lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    int index = posix_mq_find_id_locked(queue_id);
    if (index >= 0 && g_posix_mq_queues[index].references) {
        kernel_posix_mq_queue_t *queue = &g_posix_mq_queues[index];
        if (have_identity && queue->notify_armed &&
            queue->notify_tgid == identity.tgid)
            queue->notify_armed = 0u;
        --queue->references;
        if (!queue->references && !queue->linked)
            posix_mq_destroy_locked(queue);
    }
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
}

int kernel_posix_mq_unlink(uint32_t ipc_namespace_id, const char *name) {
    kernel_linux_identity_t identity;
    uint64_t lock_flags;
    int index;
    if (!posix_mq_valid_name(name)) return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    index = posix_mq_find_name_locked(ipc_namespace_id, name);
    if (index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_ENOENT;
    }
    if (identity.euid != g_posix_mq_queues[index].uid &&
        !posix_mq_capable(&identity, EDGE_LINUX_CAP_SYS_ADMIN)) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EPERM;
    }
    g_posix_mq_queues[index].linked = 0u;
    g_posix_mq_queues[index].name[0] = 0;
    if (!g_posix_mq_queues[index].references)
        posix_mq_destroy_locked(&g_posix_mq_queues[index]);
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    return 0;
}

static void posix_mq_delivery_take_locked(
        kernel_posix_mq_queue_t *queue,
        const kernel_linux_identity_t *sender,
        kernel_posix_mq_delivery_t *delivery) {
    memset(delivery, 0, sizeof(*delivery));
    if (!queue->notify_armed) return;
    delivery->armed = queue->notify_kind == 0u &&
                      queue->notify_signal != 0;
    delivery->queue_id = queue->identifier;
    delivery->target_tgid = queue->notify_tgid;
    delivery->signal = (uint32_t)queue->notify_signal;
    delivery->value = queue->notify_value;
    delivery->sender_pid = sender->tgid;
    delivery->sender_uid = sender->uid;
    queue->notify_armed = 0u;
}

static void posix_mq_delivery_finish(
        const kernel_posix_mq_delivery_t *delivery) {
    kernel_posix_mq_state_changed(delivery->queue_id);
    if (delivery->armed)
        (void)kernel_posix_mq_deliver_notification(
            delivery->target_tgid, delivery->signal, delivery->value,
            delivery->sender_pid, delivery->sender_uid);
}

int64_t kernel_posix_mq_send(int32_t queue_id, const void *data,
                             uint32_t length, uint32_t priority) {
    kernel_linux_identity_t identity;
    kernel_posix_mq_delivery_t delivery;
    kernel_posix_mq_message_t *message;
    kernel_posix_mq_queue_t *queue;
    int32_t current;
    int32_t previous;
    uint64_t lock_flags;
    int message_index;
    int queue_index;

    if (priority >= KERNEL_POSIX_MQ_PRIORITY_MAX)
        return -EDGE_LINUX_EINVAL;
    if (length && !data) return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    queue_index = posix_mq_find_id_locked(queue_id);
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EBADF;
    }
    queue = &g_posix_mq_queues[queue_index];
    if (length > queue->maximum_message_size) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EMSGSIZE;
    }
    if (queue->current_messages >= queue->maximum_messages) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    message_index = posix_mq_free_message_locked();
    if (message_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_ENOMEM;
    }
    message = &g_posix_mq_messages[message_index];
    message->used = 1u;
    message->next = -1;
    message->priority = priority;
    message->length = length;
    if (length) memcpy(message->data, data, length);
    previous = -1;
    current = queue->first_message;
    while (current >= 0 &&
           g_posix_mq_messages[current].priority >= priority) {
        previous = current;
        current = g_posix_mq_messages[current].next;
    }
    message->next = current;
    if (previous >= 0)
        g_posix_mq_messages[previous].next = message_index;
    else
        queue->first_message = message_index;
    if (!queue->current_messages)
        posix_mq_delivery_take_locked(queue, &identity, &delivery);
    else
        memset(&delivery, 0, sizeof(delivery));
    ++queue->current_messages;
    delivery.queue_id = queue->identifier;
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    posix_mq_delivery_finish(&delivery);
    return 0;
}

int64_t kernel_posix_mq_receive(int32_t queue_id, void *data,
                                uint32_t capacity, uint32_t *priority) {
    kernel_posix_mq_queue_t *queue;
    kernel_posix_mq_message_t *message;
    uint64_t lock_flags;
    uint32_t length;
    int message_index;
    int queue_index;

    if (!priority || (capacity && !data)) return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    queue_index = posix_mq_find_id_locked(queue_id);
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EBADF;
    }
    queue = &g_posix_mq_queues[queue_index];
    if (capacity < queue->maximum_message_size) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EMSGSIZE;
    }
    message_index = queue->first_message;
    if (message_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    message = &g_posix_mq_messages[message_index];
    length = message->length;
    *priority = message->priority;
    if (length) memcpy(data, message->data, length);
    queue->first_message = message->next;
    --queue->current_messages;
    message->used = 0u;
    message->next = 0;
    message->priority = 0u;
    message->length = 0u;
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    kernel_posix_mq_state_changed(queue_id);
    return length;
}

int kernel_posix_mq_query(int32_t queue_id,
                          kernel_posix_mq_state_t *state) {
    uint64_t lock_flags;
    int queue_index;
    if (!state) return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    queue_index = posix_mq_find_id_locked(queue_id);
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EBADF;
    }
    state->current_messages =
        g_posix_mq_queues[queue_index].current_messages;
    state->maximum_messages =
        g_posix_mq_queues[queue_index].maximum_messages;
    state->maximum_message_size =
        g_posix_mq_queues[queue_index].maximum_message_size;
    state->readable = state->current_messages != 0;
    state->writable =
        state->current_messages < state->maximum_messages;
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    return 0;
}

int kernel_posix_mq_notify(int32_t queue_id,
                           const kernel_posix_mq_notification_t *event) {
    kernel_linux_identity_t identity;
    kernel_posix_mq_queue_t *queue;
    uint64_t lock_flags;
    int queue_index;
    int result = 0;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_posix_mq_lock);
    queue_index = posix_mq_find_id_locked(queue_id);
    if (queue_index < 0) {
        spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
        return -EDGE_LINUX_EBADF;
    }
    queue = &g_posix_mq_queues[queue_index];
    if (!event) {
        if (queue->notify_armed && queue->notify_tgid == identity.tgid)
            queue->notify_armed = 0u;
    } else if (queue->notify_armed) {
        result = -EDGE_LINUX_EBUSY;
    } else if (event->notify != 0 && event->notify != 1) {
        result = -EDGE_LINUX_EINVAL;
    } else if (event->notify == 0 &&
               (event->signal < 0 || event->signal > 64)) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        queue->notify_armed = 1u;
        queue->notify_kind = (uint8_t)event->notify;
        queue->notify_tgid = identity.tgid;
        queue->notify_signal = event->signal;
        queue->notify_value = event->value;
    }
    spin_unlock_irqrestore(&g_posix_mq_lock, lock_flags);
    return result;
}
