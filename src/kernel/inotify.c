/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-independent Linux inotify state, queue, and watch semantics.
 * Descriptor tables, user-copy mechanisms, and task wake queues are supplied
 * by the architecture runtime through the small inotify runtime interface.
 */

#include <stdint.h>

#include "kernel/inotify.h"
#include "kernel/inotify_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "string.h"
#include "vfs/vfs.h"

#define KERNEL_INOTIFY_QUEUE_CAPACITY \
    (EDGE_RUNTIME_INOTIFY_QUEUE_SIZE + 1u)

typedef struct kernel_inotify_object {
    uint8_t used;
    uint8_t overflow_queued;
    uint16_t padding;
    uint32_t owner_uid;
    uint32_t references;
    uint32_t read_position;
    uint32_t write_position;
    uint32_t count;
    int32_t next_watch_descriptor;
    uint64_t readiness_sequence;
} kernel_inotify_object_t;

typedef struct kernel_inotify_watch {
    uint8_t used;
    uint8_t padding[3];
    int32_t inotify_id;
    int32_t descriptor;
    uint32_t mask;
    char path[VFS_PATH_MAX];
} kernel_inotify_watch_t;

typedef struct kernel_inotify_event {
    int32_t descriptor;
    uint32_t mask;
    uint32_t cookie;
    uint32_t name_length;
    char name[EDGE_RUNTIME_INOTIFY_NAME_MAX];
} kernel_inotify_event_t;

typedef struct kernel_inotify_event_record {
    int32_t descriptor;
    uint32_t mask;
    uint32_t cookie;
    uint32_t name_length;
    char name[EDGE_RUNTIME_INOTIFY_NAME_MAX];
} kernel_inotify_event_record_t;

static kernel_inotify_object_t
    g_inotify_objects[EDGE_RUNTIME_MAX_INOTIFY_INSTANCES];
static kernel_inotify_watch_t
    g_inotify_watches[EDGE_RUNTIME_MAX_INOTIFY_WATCHES];
static kernel_inotify_event_t
    g_inotify_events[EDGE_RUNTIME_MAX_INOTIFY_INSTANCES]
                     [KERNEL_INOTIFY_QUEUE_CAPACITY];
/* Notification paths execute under g_inotify_lock, so one shared scratch set
 * avoids consuming architecture exception stacks with VFS_PATH_MAX arrays. */
static char g_inotify_path_scratch[3][VFS_PATH_MAX];
static char g_inotify_name_scratch[2][EDGE_RUNTIME_INOTIFY_NAME_MAX];
static volatile uint32_t g_inotify_lock;
static uint32_t g_inotify_cookie = 1u;
static uint32_t g_max_queued_events = EDGE_RUNTIME_INOTIFY_QUEUE_SIZE;
static uint32_t g_max_user_instances = EDGE_RUNTIME_MAX_INOTIFY_INSTANCES;
static uint32_t g_max_user_watches = EDGE_RUNTIME_MAX_INOTIFY_WATCHES;

static void kernel_inotify_lock(void) {
    while (__sync_lock_test_and_set(&g_inotify_lock, 1u)) { }
}

static void kernel_inotify_unlock(void) {
    __sync_lock_release(&g_inotify_lock);
}

static void kernel_inotify_sequence_advance(
    kernel_inotify_object_t *object) {
    if (!object) return;
    ++object->readiness_sequence;
    if (!object->readiness_sequence) object->readiness_sequence = 1u;
}

static kernel_inotify_object_t *kernel_inotify_lookup_locked(int inotify_id) {
    if (inotify_id < 0 ||
        inotify_id >= EDGE_RUNTIME_MAX_INOTIFY_INSTANCES ||
        !g_inotify_objects[inotify_id].used)
        return 0;
    return &g_inotify_objects[inotify_id];
}

static uint32_t kernel_inotify_limit_capacity(kernel_inotify_limit_t limit) {
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS)
        return EDGE_RUNTIME_INOTIFY_QUEUE_SIZE;
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES)
        return EDGE_RUNTIME_MAX_INOTIFY_INSTANCES;
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_USER_WATCHES)
        return EDGE_RUNTIME_MAX_INOTIFY_WATCHES;
    return 0;
}

uint32_t kernel_inotify_limit_get(kernel_inotify_limit_t limit) {
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS)
        return __atomic_load_n(&g_max_queued_events, __ATOMIC_RELAXED);
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES)
        return __atomic_load_n(&g_max_user_instances, __ATOMIC_RELAXED);
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_USER_WATCHES)
        return __atomic_load_n(&g_max_user_watches, __ATOMIC_RELAXED);
    return 0;
}

int kernel_inotify_limit_set(kernel_inotify_limit_t limit, uint32_t value) {
    uint32_t capacity = kernel_inotify_limit_capacity(limit);

    if (!capacity || !value || value > capacity)
        return -EDGE_LINUX_EINVAL;
    if (limit == KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS)
        __atomic_store_n(&g_max_queued_events, value, __ATOMIC_RELAXED);
    else if (limit == KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES)
        __atomic_store_n(&g_max_user_instances, value, __ATOMIC_RELAXED);
    else
        __atomic_store_n(&g_max_user_watches, value, __ATOMIC_RELAXED);
    return 0;
}

static uint32_t kernel_inotify_padded_name_length(uint32_t length) {
    return length ? (length + 15u) & ~15u : 0u;
}

static int kernel_inotify_path_equal(const char *left, const char *right) {
    return left && right && strcmp(left, right) == 0;
}

static int kernel_inotify_split_path(const char *path,
                                     char parent[VFS_PATH_MAX],
                                     char leaf[EDGE_RUNTIME_INOTIFY_NAME_MAX]) {
    uint32_t length;
    uint32_t leaf_index;
    uint32_t leaf_length;
    if (!path || path[0] != '/' || !parent || !leaf)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(path);
    while (length > 1u && path[length - 1u] == '/') --length;
    leaf_index = length;
    while (leaf_index && path[leaf_index - 1u] != '/') --leaf_index;
    if (!leaf_index || leaf_index == length)
        return -EDGE_LINUX_EINVAL;
    leaf_length = length - leaf_index;
    if (leaf_length >= EDGE_RUNTIME_INOTIFY_NAME_MAX)
        return -EDGE_LINUX_ENAMETOOLONG;
    if (leaf_index == 1u) {
        parent[0] = '/';
        parent[1] = 0;
    } else {
        memcpy(parent, path, leaf_index - 1u);
        parent[leaf_index - 1u] = 0;
    }
    memcpy(leaf, path + leaf_index, leaf_length);
    leaf[leaf_length] = 0;
    return 0;
}

static void kernel_inotify_wake_mask(uint64_t wake_mask) {
    for (int inotify_id = 0;
         inotify_id < EDGE_RUNTIME_MAX_INOTIFY_INSTANCES; ++inotify_id)
        if (wake_mask & (1ULL << (uint32_t)inotify_id))
            kernel_inotify_state_changed(inotify_id);
}

static int kernel_inotify_event_equal(const kernel_inotify_event_t *left,
                                      int32_t descriptor, uint32_t mask,
                                      uint32_t cookie, const char *name,
                                      uint32_t name_length) {
    if (!left || left->descriptor != descriptor || left->mask != mask ||
        left->cookie != cookie || left->name_length != name_length)
        return 0;
    if (!name_length) return 1;
    return name && memcmp(left->name, name, name_length) == 0;
}

static uint64_t kernel_inotify_queue_locked(int inotify_id,
                                            int32_t descriptor,
                                            uint32_t mask,
                                            uint32_t cookie,
                                            const char *name) {
    kernel_inotify_object_t *object =
        kernel_inotify_lookup_locked(inotify_id);
    kernel_inotify_event_t *event;
    uint32_t name_length = 0;
    uint32_t previous;
    if (!object) return 0;
    if (name && name[0]) {
        name_length = (uint32_t)strlen(name) + 1u;
        if (name_length > EDGE_RUNTIME_INOTIFY_NAME_MAX)
            name_length = EDGE_RUNTIME_INOTIFY_NAME_MAX;
    }

    if (object->count) {
        previous = (object->write_position +
                    KERNEL_INOTIFY_QUEUE_CAPACITY - 1u) %
                   KERNEL_INOTIFY_QUEUE_CAPACITY;
        if (kernel_inotify_event_equal(
                &g_inotify_events[inotify_id][previous], descriptor, mask,
                cookie, name, name_length))
            return 0;
    }

    if (object->count >= kernel_inotify_limit_get(
                            KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS)) {
        if (object->overflow_queued ||
            object->count >= KERNEL_INOTIFY_QUEUE_CAPACITY)
            return 0;
        descriptor = -1;
        mask = KERNEL_INOTIFY_Q_OVERFLOW;
        cookie = 0;
        name = 0;
        name_length = 0;
        object->overflow_queued = 1u;
    }

    event = &g_inotify_events[inotify_id][object->write_position];
    memset(event, 0, sizeof(*event));
    event->descriptor = descriptor;
    event->mask = mask;
    event->cookie = cookie;
    event->name_length = name_length;
    if (name_length) {
        memcpy(event->name, name, name_length);
        event->name[name_length - 1u] = 0;
    }
    object->write_position = (object->write_position + 1u) %
                             KERNEL_INOTIFY_QUEUE_CAPACITY;
    ++object->count;
    kernel_inotify_sequence_advance(object);
    return 1ULL << (uint32_t)inotify_id;
}

static uint64_t kernel_inotify_remove_watch_locked(uint32_t watch_index,
                                                   int emit_ignored) {
    kernel_inotify_watch_t old;
    if (watch_index >= EDGE_RUNTIME_MAX_INOTIFY_WATCHES ||
        !g_inotify_watches[watch_index].used)
        return 0;
    old = g_inotify_watches[watch_index];
    memset(&g_inotify_watches[watch_index], 0,
           sizeof(g_inotify_watches[watch_index]));
    return emit_ignored ? kernel_inotify_queue_locked(
        old.inotify_id, old.descriptor, KERNEL_INOTIFY_IGNORED, 0, 0) : 0;
}

static int32_t kernel_inotify_allocate_watch_descriptor_locked(
    int inotify_id, kernel_inotify_object_t *object) {
    for (uint32_t attempt = 0;
         attempt <= EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++attempt) {
        int32_t candidate = object->next_watch_descriptor;
        int collision = 0;
        if (candidate <= 0) candidate = 1;
        object->next_watch_descriptor =
            candidate == INT32_MAX ? 1 : candidate + 1;
        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
            kernel_inotify_watch_t *watch = &g_inotify_watches[index];
            if (watch->used && watch->inotify_id == inotify_id &&
                watch->descriptor == candidate) {
                collision = 1;
                break;
            }
        }
        if (!collision) return candidate;
    }
    return -EDGE_LINUX_ENOSPC;
}

int kernel_inotify_validate_watch_mask(uint32_t mask) {
    const uint32_t allowed = KERNEL_INOTIFY_ALL_EVENTS |
        KERNEL_INOTIFY_UNMOUNT | KERNEL_INOTIFY_Q_OVERFLOW |
        KERNEL_INOTIFY_IGNORED | KERNEL_INOTIFY_ONLYDIR |
        KERNEL_INOTIFY_DONT_FOLLOW | KERNEL_INOTIFY_EXCL_UNLINK |
        KERNEL_INOTIFY_MASK_CREATE | KERNEL_INOTIFY_MASK_ADD |
        KERNEL_INOTIFY_ISDIR | KERNEL_INOTIFY_ONESHOT;
    if (!mask || (mask & ~allowed) ||
        (mask & (KERNEL_INOTIFY_MASK_CREATE |
                 KERNEL_INOTIFY_MASK_ADD)) ==
            (KERNEL_INOTIFY_MASK_CREATE | KERNEL_INOTIFY_MASK_ADD))
        return -EDGE_LINUX_EINVAL;
    return 0;
}

int kernel_inotify_create(void) {
    kernel_linux_identity_t identity;
    uint32_t instances = 0;
    int result = -EDGE_LINUX_ENFILE;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    kernel_inotify_lock();
    for (int inotify_id = 0;
         inotify_id < EDGE_RUNTIME_MAX_INOTIFY_INSTANCES; ++inotify_id)
        if (g_inotify_objects[inotify_id].used &&
            g_inotify_objects[inotify_id].owner_uid == identity.uid)
            ++instances;
    if (instances >= kernel_inotify_limit_get(
                         KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES)) {
        result = -EDGE_LINUX_EMFILE;
        goto out;
    }
    for (int inotify_id = 0;
         inotify_id < EDGE_RUNTIME_MAX_INOTIFY_INSTANCES; ++inotify_id) {
        kernel_inotify_object_t *object = &g_inotify_objects[inotify_id];
        if (object->used) continue;
        memset(object, 0, sizeof(*object));
        memset(g_inotify_events[inotify_id], 0,
               sizeof(g_inotify_events[inotify_id]));
        object->used = 1u;
        object->owner_uid = identity.uid;
        object->references = 1u;
        object->next_watch_descriptor = 1;
        object->readiness_sequence = 1u;
        result = inotify_id;
        break;
    }
out:
    kernel_inotify_unlock();
    return result;
}

int kernel_inotify_retain(int inotify_id) {
    kernel_inotify_object_t *object;
    int result = 0;
    kernel_inotify_lock();
    object = kernel_inotify_lookup_locked(inotify_id);
    if (!object) result = -EDGE_LINUX_EBADF;
    else if (object->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else
        ++object->references;
    kernel_inotify_unlock();
    return result;
}

void kernel_inotify_release(int inotify_id) {
    kernel_inotify_object_t *object;
    kernel_inotify_lock();
    object = kernel_inotify_lookup_locked(inotify_id);
    if (object && object->references && --object->references == 0u) {
        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index)
            if (g_inotify_watches[index].used &&
                g_inotify_watches[index].inotify_id == inotify_id)
                memset(&g_inotify_watches[index], 0,
                       sizeof(g_inotify_watches[index]));
        memset(g_inotify_events[inotify_id], 0,
               sizeof(g_inotify_events[inotify_id]));
        memset(object, 0, sizeof(*object));
    }
    kernel_inotify_unlock();
}

int kernel_inotify_query(int inotify_id, kernel_inotify_state_t *state) {
    kernel_inotify_object_t *object;
    int result = 0;
    if (!state) return -EDGE_LINUX_EINVAL;
    memset(state, 0, sizeof(*state));
    kernel_inotify_lock();
    object = kernel_inotify_lookup_locked(inotify_id);
    if (!object) {
        result = -EDGE_LINUX_EBADF;
    } else {
        state->references = object->references;
        state->queued_events = object->count;
        for (uint32_t offset = 0; offset < object->count; ++offset) {
            uint32_t index =
                (object->read_position + offset) %
                KERNEL_INOTIFY_QUEUE_CAPACITY;
            state->queued_bytes += 16u + kernel_inotify_padded_name_length(
                g_inotify_events[inotify_id][index].name_length);
        }
        state->readiness_sequence = object->readiness_sequence;
    }
    kernel_inotify_unlock();
    return result;
}

int kernel_inotify_add_watch(int inotify_id, const char *canonical_path,
                             uint32_t mask, int target_is_directory) {
    kernel_inotify_object_t *object;
    uint32_t stored_mask;
    int free_index = -1;
    uint32_t owner_watch_count = 0;
    int result;
    if (!canonical_path || canonical_path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if (strlen(canonical_path) >= VFS_PATH_MAX)
        return -EDGE_LINUX_ENAMETOOLONG;
    result = kernel_inotify_validate_watch_mask(mask);
    if (result < 0) return result;
    if ((mask & KERNEL_INOTIFY_ONLYDIR) && !target_is_directory)
        return -EDGE_LINUX_ENOTDIR;
    stored_mask = mask & ~(KERNEL_INOTIFY_ONLYDIR |
                           KERNEL_INOTIFY_DONT_FOLLOW |
                           KERNEL_INOTIFY_MASK_CREATE |
                           KERNEL_INOTIFY_MASK_ADD);

    kernel_inotify_lock();
    object = kernel_inotify_lookup_locked(inotify_id);
    if (!object) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
        kernel_inotify_watch_t *watch = &g_inotify_watches[index];
        kernel_inotify_object_t *watch_object;
        if (!watch->used) {
            if (free_index < 0) free_index = (int)index;
            continue;
        }
        watch_object = kernel_inotify_lookup_locked(watch->inotify_id);
        if (watch_object && watch_object->owner_uid == object->owner_uid)
            ++owner_watch_count;
        if (watch->inotify_id == inotify_id &&
            kernel_inotify_path_equal(watch->path, canonical_path)) {
            if (mask & KERNEL_INOTIFY_MASK_CREATE) {
                result = -EDGE_LINUX_EEXIST;
                goto out;
            }
            if (mask & KERNEL_INOTIFY_MASK_ADD)
                watch->mask |= stored_mask;
            else
                watch->mask = stored_mask;
            result = watch->descriptor;
            goto out;
        }
    }
    if (free_index < 0) {
        result = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    if (owner_watch_count >= kernel_inotify_limit_get(
                                KERNEL_INOTIFY_LIMIT_MAX_USER_WATCHES)) {
        result = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    result = kernel_inotify_allocate_watch_descriptor_locked(
        inotify_id, object);
    if (result < 0) goto out;
    g_inotify_watches[free_index].used = 1u;
    g_inotify_watches[free_index].inotify_id = inotify_id;
    g_inotify_watches[free_index].descriptor = result;
    g_inotify_watches[free_index].mask = stored_mask;
    memcpy(g_inotify_watches[free_index].path, canonical_path,
           strlen(canonical_path) + 1u);
out:
    kernel_inotify_unlock();
    return result;
}

int kernel_inotify_remove_watch(int inotify_id,
                                int32_t watch_descriptor) {
    kernel_inotify_object_t *object;
    uint64_t wake_mask = 0;
    int result = -EDGE_LINUX_EINVAL;
    kernel_inotify_lock();
    object = kernel_inotify_lookup_locked(inotify_id);
    if (!object) {
        result = -EDGE_LINUX_EBADF;
    } else if (watch_descriptor > 0) {
        for (uint32_t index = 0;
             index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
            kernel_inotify_watch_t *watch = &g_inotify_watches[index];
            if (!watch->used || watch->inotify_id != inotify_id ||
                watch->descriptor != watch_descriptor)
                continue;
            wake_mask |= kernel_inotify_remove_watch_locked(index, 1);
            result = 0;
            break;
        }
    }
    kernel_inotify_unlock();
    kernel_inotify_wake_mask(wake_mask);
    return result;
}

int64_t kernel_inotify_read(int inotify_id,
                            kernel_inotify_copy_record_fn copy_record,
                            void *copy_context, uint64_t length) {
    uint64_t done = 0;
    for (;;) {
        kernel_inotify_object_t *object;
        kernel_inotify_event_t event;
        kernel_inotify_event_record_t record;
        uint32_t padded_name_length;
        uint32_t required;
        int copy_status;

        kernel_inotify_lock();
        object = kernel_inotify_lookup_locked(inotify_id);
        if (!object) {
            kernel_inotify_unlock();
            return done ? (int64_t)done : -EDGE_LINUX_EBADF;
        }
        if (!object->count) {
            kernel_inotify_unlock();
            return done ? (int64_t)done : -EDGE_LINUX_EAGAIN;
        }
        event = g_inotify_events[inotify_id][object->read_position];
        padded_name_length =
            kernel_inotify_padded_name_length(event.name_length);
        required = 16u + padded_name_length;
        if (required > length - done) {
            kernel_inotify_unlock();
            return done ? (int64_t)done : -EDGE_LINUX_EINVAL;
        }
        memset(&record, 0, sizeof(record));
        record.descriptor = event.descriptor;
        record.mask = event.mask;
        record.cookie = event.cookie;
        record.name_length = padded_name_length;
        if (event.name_length)
            memcpy(record.name, event.name, event.name_length);
        memset(&g_inotify_events[inotify_id][object->read_position], 0,
               sizeof(g_inotify_events[inotify_id][object->read_position]));
        object->read_position = (object->read_position + 1u) %
                                KERNEL_INOTIFY_QUEUE_CAPACITY;
        --object->count;
        if (event.mask == KERNEL_INOTIFY_Q_OVERFLOW)
            object->overflow_queued = 0u;
        kernel_inotify_unlock();

        copy_status = copy_record ? copy_record(
            copy_context, done, &record, required) : -1;
        if (copy_status < 0)
            return done ? (int64_t)done : -EDGE_LINUX_EFAULT;
        done += required;
    }
}

void kernel_inotify_notify_path(const char *canonical_path, uint32_t mask,
                                const char *name_override) {
    char *parent = g_inotify_path_scratch[0];
    char *leaf = g_inotify_name_scratch[0];
    uint64_t wake_mask = 0;
    uint32_t direct_bits;
    uint32_t parent_bits;
    int split;
    if (!canonical_path || canonical_path[0] != '/') return;
    kernel_inotify_lock();
    split = kernel_inotify_split_path(canonical_path, parent, leaf);
    if (name_override && name_override[0]) {
        uint32_t length = (uint32_t)strlen(name_override);
        if (length >= EDGE_RUNTIME_INOTIFY_NAME_MAX)
            length = EDGE_RUNTIME_INOTIFY_NAME_MAX - 1u;
        memcpy(leaf, name_override, length);
        leaf[length] = 0;
    }
    direct_bits = mask & ~(KERNEL_INOTIFY_CREATE |
                           KERNEL_INOTIFY_DELETE |
                           KERNEL_INOTIFY_MOVED_FROM |
                           KERNEL_INOTIFY_MOVED_TO);
    parent_bits = mask & ~(KERNEL_INOTIFY_DELETE_SELF |
                           KERNEL_INOTIFY_MOVE_SELF);

    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
        kernel_inotify_watch_t *watch = &g_inotify_watches[index];
        int matched = 0;
        int delete_self;
        if (!watch->used) continue;
        delete_self = kernel_inotify_path_equal(
                          watch->path, canonical_path) &&
                      (mask & KERNEL_INOTIFY_DELETE_SELF);
        if (kernel_inotify_path_equal(watch->path, canonical_path)) {
            uint32_t event_bits = direct_bits & KERNEL_INOTIFY_ALL_EVENTS;
            if (event_bits && (watch->mask & event_bits)) {
                wake_mask |= kernel_inotify_queue_locked(
                    watch->inotify_id, watch->descriptor, direct_bits, 0, 0);
                matched = 1;
            }
        } else if (!split &&
                   kernel_inotify_path_equal(watch->path, parent)) {
            uint32_t event_bits = parent_bits & KERNEL_INOTIFY_ALL_EVENTS;
            if (event_bits && (watch->mask & event_bits)) {
                wake_mask |= kernel_inotify_queue_locked(
                    watch->inotify_id, watch->descriptor, parent_bits, 0,
                    leaf[0] ? leaf : 0);
                matched = 1;
            }
        }
        if (watch->used &&
            (delete_self ||
             (matched && (watch->mask & KERNEL_INOTIFY_ONESHOT))))
            wake_mask |= kernel_inotify_remove_watch_locked(index, 1);
    }
    kernel_inotify_unlock();
    kernel_inotify_wake_mask(wake_mask);
}

static int kernel_inotify_path_has_prefix(const char *path,
                                          const char *prefix,
                                          uint32_t prefix_length) {
    return memcmp(path, prefix, prefix_length) == 0 &&
           (path[prefix_length] == 0 || path[prefix_length] == '/');
}

static void kernel_inotify_rebase_watch_path(kernel_inotify_watch_t *watch,
                                             const char *old_path,
                                             const char *new_path,
                                             char updated[VFS_PATH_MAX]) {
    uint32_t old_length = (uint32_t)strlen(old_path);
    uint32_t new_length = (uint32_t)strlen(new_path);
    uint32_t suffix_length;
    if (!watch || !watch->used ||
        !kernel_inotify_path_has_prefix(watch->path, old_path, old_length))
        return;
    suffix_length = (uint32_t)strlen(watch->path + old_length);
    if (new_length + suffix_length >= VFS_PATH_MAX) return;
    memcpy(updated, new_path, new_length);
    memcpy(updated + new_length, watch->path + old_length,
           suffix_length + 1u);
    memcpy(watch->path, updated, new_length + suffix_length + 1u);
}

void kernel_inotify_notify_move(const char *old_canonical_path,
                                const char *new_canonical_path) {
    char *old_parent = g_inotify_path_scratch[0];
    char *new_parent = g_inotify_path_scratch[1];
    char *updated = g_inotify_path_scratch[2];
    char *old_leaf = g_inotify_name_scratch[0];
    char *new_leaf = g_inotify_name_scratch[1];
    uint64_t wake_mask = 0;
    uint32_t cookie;
    int old_split;
    int new_split;
    if (!old_canonical_path || old_canonical_path[0] != '/' ||
        !new_canonical_path || new_canonical_path[0] != '/')
        return;
    kernel_inotify_lock();
    old_split = kernel_inotify_split_path(
        old_canonical_path, old_parent, old_leaf);
    new_split = kernel_inotify_split_path(
        new_canonical_path, new_parent, new_leaf);

    cookie = g_inotify_cookie++;
    if (!cookie) cookie = g_inotify_cookie++;
    if (!g_inotify_cookie) g_inotify_cookie = 1u;

    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
        kernel_inotify_watch_t *watch = &g_inotify_watches[index];
        if (!watch->used || old_split ||
            !kernel_inotify_path_equal(watch->path, old_parent) ||
            !(watch->mask & KERNEL_INOTIFY_MOVED_FROM))
            continue;
        wake_mask |= kernel_inotify_queue_locked(
            watch->inotify_id, watch->descriptor,
            KERNEL_INOTIFY_MOVED_FROM, cookie, old_leaf);
        if (watch->used && (watch->mask & KERNEL_INOTIFY_ONESHOT))
            wake_mask |= kernel_inotify_remove_watch_locked(index, 1);
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
        kernel_inotify_watch_t *watch = &g_inotify_watches[index];
        if (!watch->used || new_split ||
            !kernel_inotify_path_equal(watch->path, new_parent) ||
            !(watch->mask & KERNEL_INOTIFY_MOVED_TO))
            continue;
        wake_mask |= kernel_inotify_queue_locked(
            watch->inotify_id, watch->descriptor,
            KERNEL_INOTIFY_MOVED_TO, cookie, new_leaf);
        if (watch->used && (watch->mask & KERNEL_INOTIFY_ONESHOT))
            wake_mask |= kernel_inotify_remove_watch_locked(index, 1);
    }
    for (uint32_t index = 0;
         index < EDGE_RUNTIME_MAX_INOTIFY_WATCHES; ++index) {
        kernel_inotify_watch_t *watch = &g_inotify_watches[index];
        int direct;
        if (!watch->used) continue;
        direct = kernel_inotify_path_equal(watch->path, old_canonical_path);
        if (direct && (watch->mask & KERNEL_INOTIFY_MOVE_SELF)) {
            wake_mask |= kernel_inotify_queue_locked(
                watch->inotify_id, watch->descriptor,
                KERNEL_INOTIFY_MOVE_SELF, 0, 0);
            if (watch->used && (watch->mask & KERNEL_INOTIFY_ONESHOT)) {
                wake_mask |= kernel_inotify_remove_watch_locked(index, 1);
                continue;
            }
        }
        kernel_inotify_rebase_watch_path(
            watch, old_canonical_path, new_canonical_path, updated);
    }
    kernel_inotify_unlock();
    kernel_inotify_wake_mask(wake_mask);
}
