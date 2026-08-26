/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux fanotify service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/fanotify.h"
#include "kernel/fanotify_runtime.h"
#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "kernel/vfs_runtime.h"
#include "string.h"
#include "vfs/vfs.h"

#define KERNEL_FANOTIFY_EVENT_NONE UINT16_MAX
#define KERNEL_FANOTIFY_EVENT_MASK \
    (KERNEL_FAN_ACCESS | KERNEL_FAN_MODIFY | KERNEL_FAN_ATTRIB | \
     KERNEL_FAN_CLOSE_WRITE | KERNEL_FAN_CLOSE_NOWRITE | KERNEL_FAN_OPEN | \
     KERNEL_FAN_MOVED_FROM | KERNEL_FAN_MOVED_TO | KERNEL_FAN_CREATE | \
     KERNEL_FAN_DELETE | KERNEL_FAN_DELETE_SELF | KERNEL_FAN_MOVE_SELF | \
     KERNEL_FAN_OPEN_EXEC | KERNEL_FAN_OPEN_PERM | \
     KERNEL_FAN_ACCESS_PERM | KERNEL_FAN_OPEN_EXEC_PERM | \
     KERNEL_FAN_PRE_ACCESS | KERNEL_FAN_EVENT_ON_CHILD | \
     KERNEL_FAN_RENAME | KERNEL_FAN_ONDIR)
#define KERNEL_FANOTIFY_PERMISSION_MASK \
    (KERNEL_FAN_OPEN_PERM | KERNEL_FAN_ACCESS_PERM | \
     KERNEL_FAN_OPEN_EXEC_PERM | KERNEL_FAN_PRE_ACCESS)
#define KERNEL_FANOTIFY_PATH_EVENT_MASK \
    (KERNEL_FAN_ACCESS | KERNEL_FAN_MODIFY | KERNEL_FAN_CLOSE_WRITE | \
     KERNEL_FAN_CLOSE_NOWRITE | KERNEL_FAN_OPEN | KERNEL_FAN_OPEN_EXEC | \
     KERNEL_FANOTIFY_PERMISSION_MASK)
#define KERNEL_FANOTIFY_EVENT_FLAG_MASK \
    (KERNEL_FAN_EVENT_ON_CHILD | KERNEL_FAN_ONDIR)
#define KERNEL_FANOTIFY_FID_MODE_MASK \
    (KERNEL_FAN_REPORT_FID | KERNEL_FAN_REPORT_DIR_FID | \
     KERNEL_FAN_REPORT_NAME | KERNEL_FAN_REPORT_TARGET_FID)

typedef struct kernel_fanotify_group {
    uint8_t used;
    uint8_t overflow_queued;
    uint8_t read_busy;
    uint8_t padding8;
    uint16_t head;
    uint16_t tail;
    uint16_t count;
    uint32_t owner_uid;
    uint32_t references;
    uint32_t flags;
    uint32_t event_flags;
    uint64_t readiness_sequence;
} kernel_fanotify_group_t;

typedef struct kernel_fanotify_mark {
    uint8_t used;
    uint8_t ignored_survives_modify;
    uint16_t padding;
    int32_t group_id;
    uint64_t mask;
    uint64_t ignored_mask;
    char path[VFS_PATH_MAX];
} kernel_fanotify_mark_t;

typedef struct kernel_fanotify_event {
    uint8_t used;
    uint8_t directory_entry;
    uint8_t permission;
    uint8_t delivered;
    uint8_t range_valid;
    uint8_t padding8[3];
    uint16_t next;
    uint16_t transaction_index;
    int32_t group_id;
    int32_t pid;
    int32_t response_descriptor;
    uint64_t mask;
    uint64_t range_offset;
    uint64_t range_count;
    char path[VFS_PATH_MAX];
} kernel_fanotify_event_t;

typedef struct kernel_fanotify_permission_transaction {
    uint8_t used;
    uint8_t padding8[3];
    uint32_t pending;
    int32_t result;
    uint32_t padding32;
    uint64_t ticket;
} kernel_fanotify_permission_transaction_t;

static kernel_fanotify_group_t
    g_fanotify_groups[EDGE_RUNTIME_MAX_FANOTIFY_GROUPS];
static kernel_fanotify_mark_t
    g_fanotify_marks[EDGE_RUNTIME_MAX_FANOTIFY_MARKS];
static kernel_fanotify_event_t
    g_fanotify_events[EDGE_RUNTIME_FANOTIFY_EVENT_POOL];
static kernel_fanotify_permission_transaction_t
    g_fanotify_permission_transactions[EDGE_RUNTIME_FANOTIFY_EVENT_POOL];
static char g_fanotify_path_scratch[3][VFS_PATH_MAX];
static char g_fanotify_read_path[VFS_PATH_MAX];
static volatile uint32_t g_fanotify_lock;
static volatile uint32_t g_fanotify_read_path_lock;
static uint64_t g_fanotify_next_permission_ticket = 1u;

static void fanotify_lock(void) {
    while (__sync_lock_test_and_set(&g_fanotify_lock, 1u)) { }
}

static void fanotify_unlock(void) {
    __sync_lock_release(&g_fanotify_lock);
}

static kernel_fanotify_group_t *fanotify_group_locked(int group_id) {
    if (group_id < 0 || group_id >= EDGE_RUNTIME_MAX_FANOTIFY_GROUPS ||
        !g_fanotify_groups[group_id].used)
        return 0;
    return &g_fanotify_groups[group_id];
}

static void fanotify_sequence_advance(kernel_fanotify_group_t *group) {
    ++group->readiness_sequence;
    if (!group->readiness_sequence) group->readiness_sequence = 1u;
}

static int fanotify_path_equal(const char *left, const char *right) {
    return left && right && strcmp(left, right) == 0;
}

static int fanotify_path_has_prefix(const char *path, const char *prefix,
                                    uint32_t prefix_length) {
    return memcmp(path, prefix, prefix_length) == 0 &&
           (path[prefix_length] == 0 || path[prefix_length] == '/');
}

static int fanotify_parent_path(const char *path, char *parent) {
    uint32_t length;
    uint32_t split;

    if (!path || path[0] != '/' || !parent) return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(path);
    while (length > 1u && path[length - 1u] == '/') --length;
    split = length;
    while (split && path[split - 1u] != '/') --split;
    if (!split || split == length) return -EDGE_LINUX_EINVAL;
    if (split == 1u) {
        parent[0] = '/';
        parent[1] = 0;
    } else {
        memcpy(parent, path, split - 1u);
        parent[split - 1u] = 0;
    }
    return 0;
}

static void fanotify_event_free_locked(uint16_t index) {
    if (index >= EDGE_RUNTIME_FANOTIFY_EVENT_POOL) return;
    memset(&g_fanotify_events[index], 0, sizeof(g_fanotify_events[index]));
    g_fanotify_events[index].next = KERNEL_FANOTIFY_EVENT_NONE;
}

static uint16_t fanotify_event_allocate_locked(void) {
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_FANOTIFY_EVENT_POOL; ++index) {
        if (g_fanotify_events[index].used) continue;
        memset(&g_fanotify_events[index], 0,
               sizeof(g_fanotify_events[index]));
        g_fanotify_events[index].used = 1u;
        g_fanotify_events[index].next = KERNEL_FANOTIFY_EVENT_NONE;
        return index;
    }
    return KERNEL_FANOTIFY_EVENT_NONE;
}

static uint16_t fanotify_permission_transaction_allocate_locked(
        uint64_t *ticket) {
    uint64_t candidate;

    if (!ticket) return KERNEL_FANOTIFY_EVENT_NONE;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_FANOTIFY_EVENT_POOL; ++index) {
        kernel_fanotify_permission_transaction_t *transaction =
            &g_fanotify_permission_transactions[index];
        if (transaction->used) continue;
        candidate = g_fanotify_next_permission_ticket++;
        if (!candidate) candidate = g_fanotify_next_permission_ticket++;
        memset(transaction, 0, sizeof(*transaction));
        transaction->used = 1u;
        transaction->ticket = candidate;
        *ticket = candidate;
        return index;
    }
    return KERNEL_FANOTIFY_EVENT_NONE;
}

static kernel_fanotify_permission_transaction_t *
fanotify_permission_transaction_locked(uint64_t ticket) {
    if (!ticket) return 0;
    for (uint16_t index = 0;
         index < EDGE_RUNTIME_FANOTIFY_EVENT_POOL; ++index) {
        kernel_fanotify_permission_transaction_t *transaction =
            &g_fanotify_permission_transactions[index];
        if (transaction->used && transaction->ticket == ticket)
            return transaction;
    }
    return 0;
}

static uint64_t fanotify_permission_resolve_event_locked(
        uint16_t event_index, int result) {
    kernel_fanotify_event_t *event;
    kernel_fanotify_permission_transaction_t *transaction;
    uint64_t ticket = 0;

    if (event_index >= EDGE_RUNTIME_FANOTIFY_EVENT_POOL) return 0;
    event = &g_fanotify_events[event_index];
    if (!event->used || !event->permission ||
        event->transaction_index >= EDGE_RUNTIME_FANOTIFY_EVENT_POOL)
        return 0;
    transaction = &g_fanotify_permission_transactions[
        event->transaction_index];
    if (transaction->used && transaction->pending) {
        if (result < 0 && transaction->result == 0)
            transaction->result = result;
        --transaction->pending;
        if (!transaction->pending) ticket = transaction->ticket;
    }
    fanotify_event_free_locked(event_index);
    return ticket;
}

static int fanotify_permission_complete(uint64_t ticket) {
    kernel_fanotify_permission_transaction_t *transaction;
    int result;

    fanotify_lock();
    transaction = fanotify_permission_transaction_locked(ticket);
    if (!transaction || transaction->pending) {
        fanotify_unlock();
        return -EDGE_LINUX_EAGAIN;
    }
    result = transaction->result;
    memset(transaction, 0, sizeof(*transaction));
    fanotify_unlock();
    return result;
}

static uint64_t fanotify_queue_locked(int group_id, uint64_t mask,
                                      const char *path, int32_t pid,
                                      int directory_entry) {
    kernel_fanotify_group_t *group = fanotify_group_locked(group_id);
    kernel_fanotify_event_t *event;
    uint16_t index;

    if (!group) return 0;
    if (group->tail != KERNEL_FANOTIFY_EVENT_NONE) {
        event = &g_fanotify_events[group->tail];
        if (event->used && event->mask == mask && event->pid == pid &&
            event->directory_entry == (directory_entry != 0) &&
            fanotify_path_equal(event->path, path ? path : ""))
            return 0;
    }
    if (group->count >= EDGE_RUNTIME_FANOTIFY_GROUP_QUEUE) {
        if (group->overflow_queued ||
            group->tail == KERNEL_FANOTIFY_EVENT_NONE)
            return 0;
        event = &g_fanotify_events[group->tail];
        event->mask = KERNEL_FAN_Q_OVERFLOW;
        event->pid = 0;
        event->path[0] = 0;
        group->overflow_queued = 1u;
        fanotify_sequence_advance(group);
        return 1ULL << (uint32_t)group_id;
    }
    index = fanotify_event_allocate_locked();
    if (index == KERNEL_FANOTIFY_EVENT_NONE) {
        if (!group->overflow_queued &&
            group->tail != KERNEL_FANOTIFY_EVENT_NONE) {
            event = &g_fanotify_events[group->tail];
            event->mask = KERNEL_FAN_Q_OVERFLOW;
            event->pid = 0;
            event->path[0] = 0;
            group->overflow_queued = 1u;
            fanotify_sequence_advance(group);
            return 1ULL << (uint32_t)group_id;
        }
        return 0;
    }
    event = &g_fanotify_events[index];
    event->group_id = group_id;
    event->pid = pid;
    event->mask = mask;
    event->directory_entry = directory_entry != 0;
    if (path) {
        uint32_t length = (uint32_t)strlen(path);
        if (length >= VFS_PATH_MAX) length = VFS_PATH_MAX - 1u;
        memcpy(event->path, path, length);
        event->path[length] = 0;
    }
    if (group->tail == KERNEL_FANOTIFY_EVENT_NONE)
        group->head = index;
    else
        g_fanotify_events[group->tail].next = index;
    group->tail = index;
    ++group->count;
    fanotify_sequence_advance(group);
    return 1ULL << (uint32_t)group_id;
}

static int fanotify_queue_permission_locked(
        int group_id, uint64_t mask, const char *path, int32_t pid,
        int directory_entry, uint16_t transaction_index,
        int range_valid, uint64_t range_offset, uint64_t range_count) {
    kernel_fanotify_group_t *group = fanotify_group_locked(group_id);
    kernel_fanotify_permission_transaction_t *transaction;
    kernel_fanotify_event_t *event;
    uint16_t index;

    if (!group || transaction_index >= EDGE_RUNTIME_FANOTIFY_EVENT_POOL)
        return -EDGE_LINUX_EINVAL;
    transaction = &g_fanotify_permission_transactions[transaction_index];
    if (!transaction->used) return -EDGE_LINUX_EINVAL;
    if (group->count >= EDGE_RUNTIME_FANOTIFY_GROUP_QUEUE)
        return -EDGE_LINUX_ENOSPC;
    index = fanotify_event_allocate_locked();
    if (index == KERNEL_FANOTIFY_EVENT_NONE)
        return -EDGE_LINUX_ENOSPC;
    event = &g_fanotify_events[index];
    event->permission = 1u;
    event->transaction_index = transaction_index;
    event->response_descriptor = KERNEL_FANOTIFY_NOFD;
    event->group_id = group_id;
    event->pid = pid;
    event->mask = mask;
    event->directory_entry = directory_entry != 0;
    event->range_valid = range_valid != 0;
    event->range_offset = range_offset;
    event->range_count = range_count;
    if (path) {
        uint32_t length = (uint32_t)strlen(path);
        if (length >= VFS_PATH_MAX) length = VFS_PATH_MAX - 1u;
        memcpy(event->path, path, length);
        event->path[length] = 0;
    }
    if (group->tail == KERNEL_FANOTIFY_EVENT_NONE)
        group->head = index;
    else
        g_fanotify_events[group->tail].next = index;
    group->tail = index;
    ++group->count;
    ++transaction->pending;
    fanotify_sequence_advance(group);
    return 0;
}

static void fanotify_wake_groups(uint64_t groups) {
    for (int group_id = 0;
         group_id < EDGE_RUNTIME_MAX_FANOTIFY_GROUPS; ++group_id)
        if (groups & (1ULL << (uint32_t)group_id))
            kernel_fanotify_state_changed(group_id);
}

void kernel_fanotify_permission_state_changed(uint64_t ticket) {
    if (ticket) arch_fanotify_permission_state_changed(ticket);
}

static void fanotify_read_finish(int group_id) {
    kernel_fanotify_group_t *group;

    fanotify_lock();
    group = fanotify_group_locked(group_id);
    if (group) group->read_busy = 0u;
    fanotify_unlock();
}

static int fanotify_prepare_fid_record(
    const kernel_fanotify_event_t *event, uint32_t group_flags,
    uint8_t *buffer, uint32_t capacity, uint32_t *length_out) {
    kernel_fanotify_event_info_fid_prefix_t *fid;
    kernel_vfs_target_t target;
    const char *name = 0;
    uint64_t filesystem_id = 0u;
    uint32_t handle_bytes = VFS_FILE_HANDLE_MAX;
    uint32_t handle_type = 0u;
    uint32_t name_length = 0u;
    uint32_t raw_length;
    uint32_t path_length;
    uint32_t split;
    int status;

    if (!event || !buffer || !length_out ||
        capacity < KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
                       VFS_FILE_HANDLE_MAX)
        return -EDGE_LINUX_EINVAL;
    while (__sync_lock_test_and_set(&g_fanotify_read_path_lock, 1u)) { }
    if (event->directory_entry &&
        (group_flags & KERNEL_FAN_REPORT_DIR_FID)) {
        path_length = (uint32_t)strlen(event->path);
        split = path_length;
        while (split && event->path[split - 1u] != '/') --split;
        if (!split || split == path_length) {
            status = -EDGE_LINUX_EIO;
            goto out;
        }
        if (split == 1u) {
            g_fanotify_read_path[0] = '/';
            g_fanotify_read_path[1] = 0;
        } else {
            memcpy(g_fanotify_read_path, event->path, split - 1u);
            g_fanotify_read_path[split - 1u] = 0;
        }
        name = event->path + split;
    } else if (group_flags & KERNEL_FAN_REPORT_FID) {
        memcpy(g_fanotify_read_path, event->path,
               strlen(event->path) + 1u);
    } else {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    status = kernel_vfs_resolve_path(g_fanotify_read_path, 0, &target);
    if (status < 0 || !target.inode || !target.superblock) {
        status = status < 0 ? status : -EDGE_LINUX_EIO;
        goto out;
    }
    status = vfs_mount_id_for_superblock(
        target.superblock, &filesystem_id);
    if (status < 0) goto out;
    fid = (kernel_fanotify_event_info_fid_prefix_t *)(void *)buffer;
    status = vfs_encode_file_handle(
        target.superblock, target.inode, &handle_type,
        buffer + KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH,
        &handle_bytes);
    if (status < 0) goto out;
    if (name && (group_flags & KERNEL_FAN_REPORT_NAME))
        name_length = (uint32_t)strlen(name) + 1u;
    raw_length = KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
        handle_bytes + name_length;
    if (raw_length > capacity) {
        status = -EDGE_LINUX_EOVERFLOW;
        goto out;
    }
    if (name_length)
        memcpy(buffer + KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
                   handle_bytes,
               name, name_length);
    raw_length = (raw_length + 3u) & ~3u;
    memset(buffer + KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
               handle_bytes + name_length,
           0, raw_length - (KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
                            handle_bytes + name_length));
    fid->information_type = name_length ?
        KERNEL_FANOTIFY_INFO_TYPE_DFID_NAME :
        (event->directory_entry &&
         (group_flags & KERNEL_FAN_REPORT_DIR_FID)) ?
            KERNEL_FANOTIFY_INFO_TYPE_DFID :
            KERNEL_FANOTIFY_INFO_TYPE_FID;
    fid->length = (uint16_t)raw_length;
    fid->filesystem_id[0] = (int32_t)filesystem_id;
    fid->filesystem_id[1] = (int32_t)(filesystem_id >> 32u);
    fid->handle_bytes = handle_bytes;
    fid->handle_type = (int32_t)handle_type;
    *length_out = raw_length;
    status = 0;
out:
    __sync_lock_release(&g_fanotify_read_path_lock);
    return status;
}

int kernel_fanotify_create(uint32_t flags, uint32_t event_flags) {
    kernel_linux_identity_t identity;
    uint32_t groups = 0;
    int result = -EDGE_LINUX_ENFILE;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    fanotify_lock();
    for (int index = 0; index < EDGE_RUNTIME_MAX_FANOTIFY_GROUPS; ++index)
        if (g_fanotify_groups[index].used &&
            g_fanotify_groups[index].owner_uid == identity.uid)
            ++groups;
    if (groups >= EDGE_RUNTIME_MAX_FANOTIFY_GROUPS) {
        fanotify_unlock();
        return -EDGE_LINUX_EMFILE;
    }
    for (int index = 0; index < EDGE_RUNTIME_MAX_FANOTIFY_GROUPS; ++index) {
        kernel_fanotify_group_t *group = &g_fanotify_groups[index];
        if (group->used) continue;
        memset(group, 0, sizeof(*group));
        group->used = 1u;
        group->owner_uid = identity.uid;
        group->references = 1u;
        group->flags = flags;
        group->event_flags = event_flags;
        group->head = KERNEL_FANOTIFY_EVENT_NONE;
        group->tail = KERNEL_FANOTIFY_EVENT_NONE;
        group->readiness_sequence = 1u;
        result = index;
        break;
    }
    fanotify_unlock();
    return result;
}

int kernel_fanotify_retain(int group_id) {
    kernel_fanotify_group_t *group;
    int result = 0;
    fanotify_lock();
    group = fanotify_group_locked(group_id);
    if (!group) result = -EDGE_LINUX_EBADF;
    else if (group->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else
        ++group->references;
    fanotify_unlock();
    return result;
}

void kernel_fanotify_release(int group_id) {
    kernel_fanotify_group_t *group;
    uint64_t completed[EDGE_RUNTIME_FANOTIFY_EVENT_POOL];
    uint32_t completed_count = 0;

    fanotify_lock();
    group = fanotify_group_locked(group_id);
    if (group && group->references && --group->references == 0u) {
        for (uint16_t event_index = 0;
             event_index < EDGE_RUNTIME_FANOTIFY_EVENT_POOL;
             ++event_index) {
            kernel_fanotify_event_t *event =
                &g_fanotify_events[event_index];
            uint64_t ticket;
            if (!event->used || event->group_id != group_id) continue;
            if (!event->permission) {
                fanotify_event_free_locked(event_index);
                continue;
            }
            ticket = fanotify_permission_resolve_event_locked(
                event_index, 0);
            if (ticket && completed_count <
                              EDGE_RUNTIME_FANOTIFY_EVENT_POOL)
                completed[completed_count++] = ticket;
        }
        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index)
            if (g_fanotify_marks[index].used &&
                g_fanotify_marks[index].group_id == group_id)
                memset(&g_fanotify_marks[index], 0,
                       sizeof(g_fanotify_marks[index]));
        memset(group, 0, sizeof(*group));
    }
    fanotify_unlock();
    for (uint32_t index = 0; index < completed_count; ++index)
        kernel_fanotify_permission_state_changed(completed[index]);
}

int kernel_fanotify_query(int group_id, kernel_fanotify_state_t *state) {
    kernel_fanotify_group_t *group;
    int result = 0;
    if (!state) return -EDGE_LINUX_EINVAL;
    memset(state, 0, sizeof(*state));
    fanotify_lock();
    group = fanotify_group_locked(group_id);
    if (!group) {
        result = -EDGE_LINUX_EBADF;
    } else {
        state->references = group->references;
        state->queued_events = group->count;
        state->queued_bytes = (uint32_t)group->count *
            (KERNEL_FANOTIFY_METADATA_LENGTH +
             ((group->flags & KERNEL_FAN_REPORT_PIDFD) ?
                KERNEL_FANOTIFY_PIDFD_INFO_LENGTH : 0u) +
             ((group->flags & KERNEL_FANOTIFY_FID_MODE_MASK) ?
                KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
                    VFS_FILE_HANDLE_MAX +
                    ((group->flags & KERNEL_FAN_REPORT_NAME) ?
                        VFS_NAME_MAX : 0u) : 0u));
        state->readiness_sequence = group->readiness_sequence;
        state->flags = group->flags;
        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index)
            if (g_fanotify_marks[index].used &&
                g_fanotify_marks[index].group_id == group_id)
                ++state->marks;
    }
    fanotify_unlock();
    return result;
}

int kernel_fanotify_modify_mark(int group_id, uint32_t flags,
                                uint64_t mask, const char *canonical_path,
                                int target_is_directory) {
    const uint32_t operation = flags &
        (KERNEL_FAN_MARK_ADD | KERNEL_FAN_MARK_REMOVE |
         KERNEL_FAN_MARK_FLUSH);
    const uint32_t type = flags & KERNEL_FAN_MARK_MNTNS;
    const uint32_t allowed_flags =
        KERNEL_FAN_MARK_ADD | KERNEL_FAN_MARK_REMOVE |
        KERNEL_FAN_MARK_DONT_FOLLOW | KERNEL_FAN_MARK_ONLYDIR |
        KERNEL_FAN_MARK_MOUNT | KERNEL_FAN_MARK_IGNORED_MASK |
        KERNEL_FAN_MARK_IGNORED_SURV_MODIFY | KERNEL_FAN_MARK_FLUSH |
        KERNEL_FAN_MARK_FILESYSTEM | KERNEL_FAN_MARK_EVICTABLE |
        KERNEL_FAN_MARK_IGNORE;
    kernel_fanotify_group_t *group;
    kernel_fanotify_mark_t *mark = 0;
    kernel_fanotify_mark_t *free_mark = 0;
    uint64_t *selected_mask;
    int result = 0;

    if (flags & ~allowed_flags) return -EDGE_LINUX_EINVAL;
    if ((flags & KERNEL_FAN_MARK_IGNORED_MASK) &&
        (flags & KERNEL_FAN_MARK_IGNORE))
        return -EDGE_LINUX_EINVAL;
    if (operation != KERNEL_FAN_MARK_ADD &&
        operation != KERNEL_FAN_MARK_REMOVE &&
        operation != KERNEL_FAN_MARK_FLUSH)
        return -EDGE_LINUX_EINVAL;
    if (type != 0u) return -EDGE_LINUX_EOPNOTSUPP;
    if (mask & ~(uint64_t)KERNEL_FANOTIFY_EVENT_MASK)
        return -EDGE_LINUX_EINVAL;
    if (operation == KERNEL_FAN_MARK_FLUSH) {
        if (mask || canonical_path) return -EDGE_LINUX_EINVAL;
        fanotify_lock();
        group = fanotify_group_locked(group_id);
        if (!group) result = -EDGE_LINUX_EBADF;
        else
            for (uint32_t index = 0;
                 index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index)
                if (g_fanotify_marks[index].used &&
                    g_fanotify_marks[index].group_id == group_id)
                    memset(&g_fanotify_marks[index], 0,
                           sizeof(g_fanotify_marks[index]));
        fanotify_unlock();
        return result;
    }
    if (!canonical_path || canonical_path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if (!mask) return -EDGE_LINUX_EINVAL;
    if ((flags & KERNEL_FAN_MARK_ONLYDIR) && !target_is_directory)
        return -EDGE_LINUX_ENOTDIR;
    if ((flags & KERNEL_FAN_MARK_IGNORE) && target_is_directory &&
        !(flags & KERNEL_FAN_MARK_IGNORED_SURV_MODIFY))
        return -EDGE_LINUX_EISDIR;
    if (flags & KERNEL_FAN_MARK_IGNORED_MASK)
        mask &= ~(uint64_t)KERNEL_FANOTIFY_EVENT_FLAG_MASK;

    fanotify_lock();
    group = fanotify_group_locked(group_id);
    if (!group) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    if ((mask & KERNEL_FANOTIFY_PERMISSION_MASK) &&
        !(group->flags & (KERNEL_FAN_CLASS_CONTENT |
                          KERNEL_FAN_CLASS_PRE_CONTENT))) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if ((mask & KERNEL_FAN_PRE_ACCESS) &&
        !(group->flags & KERNEL_FAN_CLASS_PRE_CONTENT)) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if ((mask & KERNEL_FAN_PRE_ACCESS) &&
        (mask & KERNEL_FAN_ONDIR)) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if ((mask & ~(uint64_t)(KERNEL_FANOTIFY_PATH_EVENT_MASK |
                            KERNEL_FANOTIFY_EVENT_FLAG_MASK)) &&
        !(group->flags & KERNEL_FANOTIFY_FID_MODE_MASK)) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if ((group->flags & KERNEL_FAN_REPORT_FID) &&
        (mask & (KERNEL_FAN_MOVED_FROM | KERNEL_FAN_MOVED_TO |
                 KERNEL_FAN_DELETE | KERNEL_FAN_DELETE_SELF |
                 KERNEL_FAN_MOVE_SELF | KERNEL_FAN_RENAME))) {
        result = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index) {
        kernel_fanotify_mark_t *candidate = &g_fanotify_marks[index];
        if (!candidate->used) {
            if (!free_mark) free_mark = candidate;
            continue;
        }
        if (candidate->group_id == group_id &&
            fanotify_path_equal(candidate->path, canonical_path)) {
            mark = candidate;
            break;
        }
    }
    if (!mark && operation == KERNEL_FAN_MARK_REMOVE) {
        result = -EDGE_LINUX_ENOENT;
        goto out;
    }
    if (!mark) {
        if (!free_mark) {
            result = -EDGE_LINUX_ENOSPC;
            goto out;
        }
        mark = free_mark;
        memset(mark, 0, sizeof(*mark));
        mark->used = 1u;
        mark->group_id = group_id;
        memcpy(mark->path, canonical_path, strlen(canonical_path) + 1u);
    }
    selected_mask = (flags & (KERNEL_FAN_MARK_IGNORED_MASK |
                              KERNEL_FAN_MARK_IGNORE)) ?
                    &mark->ignored_mask : &mark->mask;
    if (operation == KERNEL_FAN_MARK_ADD)
        *selected_mask |= mask;
    else if ((*selected_mask & mask) != mask)
        result = -EDGE_LINUX_ENOENT;
    else
        *selected_mask &= ~mask;
    if (result == 0 && selected_mask == &mark->ignored_mask)
        mark->ignored_survives_modify =
            (flags & KERNEL_FAN_MARK_IGNORED_SURV_MODIFY) != 0;
    if (result == 0 && !mark->mask && !mark->ignored_mask)
        memset(mark, 0, sizeof(*mark));
out:
    fanotify_unlock();
    return result;
}

int64_t kernel_fanotify_read(int group_id,
                            kernel_fanotify_copy_record_fn copy_record,
                            void *copy_context, uint64_t length) {
    struct fanotify_record {
        kernel_fanotify_event_metadata_t metadata;
        uint8_t information[416];
    } record;
    uint64_t done = 0;

    fanotify_lock();
    {
        kernel_fanotify_group_t *group = fanotify_group_locked(group_id);
        if (!group) {
            fanotify_unlock();
            return -EDGE_LINUX_EBADF;
        }
        if (group->read_busy) {
            fanotify_unlock();
            return -EDGE_LINUX_EAGAIN;
        }
        group->read_busy = 1u;
    }
    fanotify_unlock();

    while (length - done >= KERNEL_FANOTIFY_METADATA_LENGTH) {
        kernel_fanotify_group_t *group;
        kernel_fanotify_event_t *event;
        uint32_t group_flags;
        uint32_t event_flags;
        uint32_t record_length;
        uint32_t information_offset = 0u;
        uint32_t pidfd_offset = UINT32_MAX;
        uint16_t event_index;
        int permission;
        int descriptor = KERNEL_FANOTIFY_NOFD;
        int pidfd = KERNEL_FANOTIFY_NOFD;
        int prepare_status = 0;
        int copy_status;

        fanotify_lock();
        group = fanotify_group_locked(group_id);
        if (!group) {
            fanotify_unlock();
            fanotify_read_finish(group_id);
            return done ? (int64_t)done : -EDGE_LINUX_EBADF;
        }
        if (!group->count || group->head == KERNEL_FANOTIFY_EVENT_NONE) {
            fanotify_unlock();
            fanotify_read_finish(group_id);
            return done ? (int64_t)done : -EDGE_LINUX_EAGAIN;
        }
        event_index = group->head;
        event = &g_fanotify_events[event_index];
        permission = event->permission != 0;
        group_flags = group->flags;
        event_flags = group->event_flags;
        fanotify_unlock();

        memset(&record, 0, sizeof(record));
        if (event->mask != KERNEL_FAN_Q_OVERFLOW &&
            (group_flags & KERNEL_FANOTIFY_FID_MODE_MASK))
            prepare_status = fanotify_prepare_fid_record(
                event, group_flags, record.information,
                sizeof(record.information), &information_offset);
        if (prepare_status < 0) {
            fanotify_read_finish(group_id);
            return done ? (int64_t)done : -EDGE_LINUX_EIO;
        }
        if (event->mask != KERNEL_FAN_Q_OVERFLOW &&
            (group_flags & KERNEL_FAN_REPORT_PIDFD)) {
            kernel_fanotify_event_info_pidfd_t *pidfd_information =
                (kernel_fanotify_event_info_pidfd_t *)(void *)
                    (record.information + information_offset);
            pidfd_information->information_type =
                KERNEL_FANOTIFY_INFO_TYPE_PIDFD;
            pidfd_information->length =
                KERNEL_FANOTIFY_PIDFD_INFO_LENGTH;
            pidfd_offset = information_offset;
            information_offset += KERNEL_FANOTIFY_PIDFD_INFO_LENGTH;
        }
        if (event->range_valid) {
            kernel_fanotify_event_info_range_t *range_information =
                (kernel_fanotify_event_info_range_t *)(void *)
                    (record.information + information_offset);
            range_information->information_type =
                KERNEL_FANOTIFY_INFO_TYPE_RANGE;
            range_information->length = sizeof(*range_information);
            range_information->offset = event->range_offset;
            range_information->count = event->range_count;
            information_offset += sizeof(*range_information);
        }
        record_length = KERNEL_FANOTIFY_METADATA_LENGTH +
            information_offset;

        fanotify_lock();
        group = fanotify_group_locked(group_id);
        if (!group || group->head != event_index) {
            fanotify_unlock();
            fanotify_read_finish(group_id);
            return done ? (int64_t)done : -EDGE_LINUX_EAGAIN;
        }
        if (length - done < record_length) {
            fanotify_unlock();
            fanotify_read_finish(group_id);
            return done ? (int64_t)done : -EDGE_LINUX_EINVAL;
        }
        group->head = event->next;
        --group->count;
        if (!group->count) group->tail = KERNEL_FANOTIFY_EVENT_NONE;
        if (event->mask == KERNEL_FAN_Q_OVERFLOW)
            group->overflow_queued = 0u;
        fanotify_unlock();

        if (event->path[0] &&
            !(group_flags & KERNEL_FANOTIFY_FID_MODE_MASK)) {
            kernel_vfs_target_t target;
            int status = kernel_vfs_resolve_path(event->path, 0, &target);
            if (status == 0 && target.inode && target.superblock)
                descriptor = kernel_vfs_install_inode_descriptor(
                    target.superblock, target.inode,
                    event_flags & ~0x00080000u,
                    (event_flags & 0x00080000u) ?
                        KERNEL_FD_CLOEXEC : 0u,
                    target.linkable_zero_link_inode);
            else if (group_flags & KERNEL_FAN_REPORT_FD_ERROR)
                descriptor = status < 0 ? status : -EDGE_LINUX_EIO;
        }
        record.metadata.event_length = record_length;
        record.metadata.version = KERNEL_FANOTIFY_METADATA_VERSION;
        record.metadata.metadata_length = KERNEL_FANOTIFY_METADATA_LENGTH;
        record.metadata.mask = event->mask;
        record.metadata.descriptor = descriptor;
        record.metadata.pid = event->pid;
        if (event->mask != KERNEL_FAN_Q_OVERFLOW &&
            (group_flags & KERNEL_FAN_REPORT_PIDFD)) {
            kernel_fanotify_event_info_pidfd_t *pidfd_information =
                (kernel_fanotify_event_info_pidfd_t *)(void *)
                    (record.information + pidfd_offset);
            pidfd = kernel_pidfd_open(event->pid, 0u);
            if (pidfd < 0)
                pidfd = pidfd == -EDGE_LINUX_ESRCH ?
                    KERNEL_FANOTIFY_NOFD : KERNEL_FANOTIFY_EPIDFD;
            pidfd_information->descriptor = pidfd;
        }
        copy_status = copy_record ? copy_record(
            copy_context, done, &record, record_length) : -1;
        if (copy_status < 0) {
            if (descriptor >= 0) (void)kernel_fd_close(descriptor);
            if (pidfd >= 0) (void)kernel_fd_close(pidfd);
            fanotify_lock();
            group = fanotify_group_locked(group_id);
            event = &g_fanotify_events[event_index];
            if (permission && group && event->used) {
                event->next = group->head;
                group->head = event_index;
                if (group->tail == KERNEL_FANOTIFY_EVENT_NONE)
                    group->tail = event_index;
                ++group->count;
                fanotify_sequence_advance(group);
            } else if (event->used) {
                fanotify_event_free_locked(event_index);
            }
            fanotify_unlock();
            fanotify_read_finish(group_id);
            return done ? (int64_t)done : -EDGE_LINUX_EFAULT;
        }
        fanotify_lock();
        event = &g_fanotify_events[event_index];
        if (permission && event->used) {
            event->delivered = 1u;
            event->response_descriptor = descriptor;
            event->next = KERNEL_FANOTIFY_EVENT_NONE;
        } else if (event->used) {
            fanotify_event_free_locked(event_index);
        }
        fanotify_unlock();
        done += record_length;
    }
    fanotify_read_finish(group_id);
    return done ? (int64_t)done : -EDGE_LINUX_EINVAL;
}

static int fanotify_response_errno_allowed(uint32_t error) {
    return error == 0u || error == EDGE_LINUX_EIO ||
           error == EDGE_LINUX_EPERM || error == EDGE_LINUX_EBUSY ||
           error == EDGE_LINUX_ETXTBSY || error == EDGE_LINUX_EAGAIN ||
           error == EDGE_LINUX_ENOSPC || error == EDGE_LINUX_EDQUOT;
}

int64_t kernel_fanotify_write(
        int group_id, const kernel_fanotify_response_t *response,
        const kernel_fanotify_response_info_audit_rule_t *information,
        uint64_t length) {
    const uint32_t error_mask = 0xff000000u;
    const uint32_t valid_mask = error_mask | KERNEL_FAN_ALLOW |
        KERNEL_FAN_DENY | KERNEL_FAN_AUDIT | KERNEL_FAN_INFO;
    kernel_fanotify_group_t *group;
    uint64_t completed_ticket = 0;
    uint32_t decision;
    uint32_t error;
    int result;

    if (!response || length < sizeof(*response))
        return -EDGE_LINUX_EINVAL;
    if (response->response & ~valid_mask)
        return -EDGE_LINUX_EINVAL;
    decision = response->response &
        (KERNEL_FAN_ALLOW | KERNEL_FAN_DENY);
    error = (response->response >> 24u) & 0xffu;
    if (decision != KERNEL_FAN_ALLOW && decision != KERNEL_FAN_DENY)
        return -EDGE_LINUX_EINVAL;
    if (decision == KERNEL_FAN_ALLOW && error)
        return -EDGE_LINUX_EINVAL;
    if (!fanotify_response_errno_allowed(error))
        return -EDGE_LINUX_EINVAL;
    if (response->response & KERNEL_FAN_INFO) {
        if (!information ||
            length - sizeof(*response) != sizeof(*information) ||
            information->information_type !=
                KERNEL_FAN_RESPONSE_INFO_AUDIT_RULE ||
            information->padding != 0u ||
            information->length != sizeof(*information))
            return -EDGE_LINUX_EINVAL;
        if (response->descriptor == KERNEL_FANOTIFY_NOFD)
            return (int64_t)length;
    }
    if (response->descriptor < 0) return -EDGE_LINUX_EINVAL;

    fanotify_lock();
    group = fanotify_group_locked(group_id);
    if (!group) {
        fanotify_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if ((response->response & KERNEL_FAN_AUDIT) &&
        !(group->flags & KERNEL_FAN_ENABLE_AUDIT)) {
        fanotify_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    if (error && !(group->flags & KERNEL_FAN_CLASS_PRE_CONTENT)) {
        fanotify_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    result = -EDGE_LINUX_ENOENT;
    for (uint16_t event_index = 0;
         event_index < EDGE_RUNTIME_FANOTIFY_EVENT_POOL; ++event_index) {
        kernel_fanotify_event_t *event =
            &g_fanotify_events[event_index];
        if (!event->used || !event->permission || !event->delivered ||
            event->group_id != group_id ||
            event->response_descriptor != response->descriptor)
            continue;
        result = decision == KERNEL_FAN_ALLOW ? 0 :
            -(int)(error ? error : EDGE_LINUX_EPERM);
        completed_ticket = fanotify_permission_resolve_event_locked(
            event_index, result);
        result = 0;
        break;
    }
    fanotify_unlock();
    if (completed_ticket)
        kernel_fanotify_permission_state_changed(completed_ticket);
    if (result < 0) return result;
    return (response->response & KERNEL_FAN_INFO) ?
        (int64_t)length : (int64_t)sizeof(*response);
}

int kernel_fanotify_permission_pending(uint64_t ticket) {
    kernel_fanotify_permission_transaction_t *transaction;
    int pending;

    fanotify_lock();
    transaction = fanotify_permission_transaction_locked(ticket);
    pending = transaction && transaction->pending;
    fanotify_unlock();
    return pending;
}

static int fanotify_permission_check_internal(
        const char *canonical_path, uint64_t mask, int range_valid,
        uint64_t range_offset, uint64_t range_count) {
    kernel_linux_identity_t identity;
    kernel_fanotify_permission_transaction_t *transaction;
    uint64_t replay_ticket = 0;
    uint64_t ticket = 0;
    uint64_t wake_groups = 0;
    uint16_t transaction_index;
    int32_t tid;
    int32_t tgid;
    int has_parent;
    char *parent;

    if (arch_fanotify_consume_completed_permission(&replay_ticket))
        return fanotify_permission_complete(replay_ticket);
    if (!canonical_path ||
        !(mask & KERNEL_FANOTIFY_PERMISSION_MASK) ||
        (mask & ~((uint64_t)KERNEL_FANOTIFY_PERMISSION_MASK |
                  KERNEL_FAN_ONDIR)))
        return -EDGE_LINUX_EINVAL;
    /*
     * Descriptors opened from a persistent file handle have an inode and
     * superblock but no canonical pathname.  Path marks cannot match such an
     * access, so it proceeds until inode-based fanotify marks are available.
     */
    if (!canonical_path[0]) return 0;
    if (canonical_path[0] != '/') return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) == 0) {
        tid = identity.tid;
        tgid = identity.tgid;
    } else {
        tid = kernel_current_pid();
        tgid = tid;
    }
    if (tid <= 0) tid = 0;
    if (tgid <= 0) tgid = tid;

    fanotify_lock();
    transaction_index = fanotify_permission_transaction_allocate_locked(
        &ticket);
    if (transaction_index == KERNEL_FANOTIFY_EVENT_NONE) {
        fanotify_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    transaction = &g_fanotify_permission_transactions[transaction_index];
    parent = g_fanotify_path_scratch[1];
    has_parent = fanotify_parent_path(canonical_path, parent) == 0;
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index) {
        kernel_fanotify_mark_t *mark = &g_fanotify_marks[index];
        kernel_fanotify_group_t *group;
        uint64_t event_mask;
        int direct;
        int child;
        int status;

        if (!mark->used) continue;
        group = fanotify_group_locked(mark->group_id);
        if (!group ||
            !(group->flags & (KERNEL_FAN_CLASS_CONTENT |
                              KERNEL_FAN_CLASS_PRE_CONTENT)))
            continue;
        direct = fanotify_path_equal(mark->path, canonical_path);
        child = has_parent && fanotify_path_equal(mark->path, parent) &&
                (mark->mask & KERNEL_FAN_EVENT_ON_CHILD);
        if (!direct && !child) continue;
        event_mask = mask & mark->mask;
        if (!(event_mask & KERNEL_FANOTIFY_PERMISSION_MASK) ||
            (event_mask & mark->ignored_mask))
            continue;
        status = fanotify_queue_permission_locked(
            mark->group_id, event_mask, canonical_path,
            (group->flags & KERNEL_FAN_REPORT_TID) ? tid : tgid,
            child, transaction_index, range_valid,
            range_offset, range_count);
        if (status < 0) {
            if (!transaction->result) transaction->result = status;
            continue;
        }
        wake_groups |= 1ULL << (uint32_t)mark->group_id;
    }
    if (!transaction->pending) {
        int result = transaction->result;
        memset(transaction, 0, sizeof(*transaction));
        fanotify_unlock();
        return result;
    }
    fanotify_unlock();
    fanotify_wake_groups(wake_groups);
    arch_fanotify_permission_wait(ticket);
    return fanotify_permission_complete(ticket);
}

int kernel_fanotify_permission_check(const char *canonical_path,
                                     uint64_t mask) {
    return fanotify_permission_check_internal(
        canonical_path, mask, 0, 0u, 0u);
}

int kernel_fanotify_pre_access_permission_check(const char *canonical_path,
                                                uint64_t offset,
                                                uint64_t count) {
    const uint64_t page_mask = 4095u;
    uint64_t range_start = offset & ~page_mask;
    uint64_t range_end;

    if (count > UINT64_MAX - offset ||
        offset + count > UINT64_MAX - page_mask)
        range_end = UINT64_MAX & ~page_mask;
    else
        range_end = (offset + count + page_mask) & ~page_mask;
    if (range_end < range_start) range_end = UINT64_MAX;
    return fanotify_permission_check_internal(
        canonical_path, KERNEL_FAN_PRE_ACCESS, 1,
        range_start, range_end - range_start);
}

int kernel_fanotify_access_permission_check(const char *canonical_path,
                                            uint64_t offset,
                                            uint64_t count) {
    int status = kernel_fanotify_pre_access_permission_check(
        canonical_path, offset, count);

    if (status < 0) return status;
    return fanotify_permission_check_internal(
        canonical_path, KERNEL_FAN_ACCESS_PERM, 0, 0u, 0u);
}

int kernel_fanotify_directory_access_permission_check(
        const char *canonical_path) {
    return fanotify_permission_check_internal(
        canonical_path, KERNEL_FAN_ACCESS_PERM | KERNEL_FAN_ONDIR,
        0, 0u, 0u);
}

static uint64_t fanotify_notify_path_locked(const char *canonical_path,
                                            uint64_t mask, int32_t tid,
                                            int32_t tgid) {
    char *parent = g_fanotify_path_scratch[0];
    uint64_t wake_groups = 0;
    int has_parent = fanotify_parent_path(canonical_path, parent) == 0;

    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index) {
        kernel_fanotify_mark_t *mark = &g_fanotify_marks[index];
        kernel_fanotify_group_t *group;
        uint64_t event_mask = mask;
        int direct;
        int child;

        if (!mark->used) continue;
        group = fanotify_group_locked(mark->group_id);
        if (!group) continue;
        direct = fanotify_path_equal(mark->path, canonical_path);
        child = has_parent && fanotify_path_equal(mark->path, parent) &&
                (mark->mask & KERNEL_FAN_EVENT_ON_CHILD);
        if (!direct && !child) continue;
        if (event_mask & mark->ignored_mask) {
            if ((event_mask & KERNEL_FAN_MODIFY) &&
                !mark->ignored_survives_modify)
                mark->ignored_mask = 0;
            continue;
        }
        event_mask &= mark->mask;
        event_mask &= ~(uint64_t)KERNEL_FAN_EVENT_ON_CHILD;
        if (!(event_mask &
              ~(uint64_t)KERNEL_FANOTIFY_EVENT_FLAG_MASK))
            continue;
        if ((group->flags & KERNEL_FAN_REPORT_DIR_FID) && !child &&
            !(group->flags & KERNEL_FAN_REPORT_FID))
            continue;
        wake_groups |= fanotify_queue_locked(
            mark->group_id, event_mask, canonical_path,
            (group->flags & KERNEL_FAN_REPORT_TID) ? tid : tgid,
            child);
    }
    return wake_groups;
}

void kernel_fanotify_notify_path(const char *canonical_path, uint32_t mask) {
    kernel_linux_identity_t identity;
    uint64_t wake_groups;
    int32_t tid;
    int32_t tgid;
    if (!canonical_path || canonical_path[0] != '/') return;
    if (kernel_current_linux_identity(&identity) == 0) {
        tid = identity.tid;
        tgid = identity.tgid;
    } else {
        tid = kernel_current_pid();
        tgid = tid;
    }
    if (tid <= 0) tid = 0;
    if (tgid <= 0) tgid = tid;
    fanotify_lock();
    wake_groups = fanotify_notify_path_locked(
        canonical_path, (uint64_t)mask, tid, tgid);
    fanotify_unlock();
    fanotify_wake_groups(wake_groups);
}

void kernel_fanotify_notify_move(const char *old_canonical_path,
                                 const char *new_canonical_path) {
    kernel_linux_identity_t identity;
    char *updated = g_fanotify_path_scratch[2];
    uint64_t wake_groups;
    int32_t tid;
    int32_t tgid;

    if (!old_canonical_path || old_canonical_path[0] != '/' ||
        !new_canonical_path || new_canonical_path[0] != '/')
        return;
    if (kernel_current_linux_identity(&identity) == 0) {
        tid = identity.tid;
        tgid = identity.tgid;
    } else {
        tid = kernel_current_pid();
        tgid = tid;
    }
    if (tid <= 0) tid = 0;
    if (tgid <= 0) tgid = tid;
    fanotify_lock();
    wake_groups = fanotify_notify_path_locked(
        old_canonical_path,
        KERNEL_FAN_MOVED_FROM | KERNEL_FAN_MOVE_SELF,
        tid, tgid);
    wake_groups |= fanotify_notify_path_locked(
        new_canonical_path, KERNEL_FAN_MOVED_TO,
        tid, tgid);
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_FANOTIFY_MARKS; ++index) {
        kernel_fanotify_mark_t *mark = &g_fanotify_marks[index];
        uint32_t old_length;
        uint32_t new_length;
        uint32_t suffix_length;
        if (!mark->used) continue;
        old_length = (uint32_t)strlen(old_canonical_path);
        if (!fanotify_path_has_prefix(
                mark->path, old_canonical_path, old_length))
            continue;
        new_length = (uint32_t)strlen(new_canonical_path);
        suffix_length = (uint32_t)strlen(mark->path + old_length);
        if (new_length + suffix_length >= VFS_PATH_MAX) continue;
        memcpy(updated, new_canonical_path, new_length);
        memcpy(updated + new_length, mark->path + old_length,
               suffix_length + 1u);
        memcpy(mark->path, updated,
               new_length + suffix_length + 1u);
    }
    fanotify_unlock();
    fanotify_wake_groups(wake_groups);
}
