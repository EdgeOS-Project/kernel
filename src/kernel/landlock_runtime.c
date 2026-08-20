/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux Landlock filesystem policy runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/landlock_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "string.h"

#define KERNEL_LANDLOCK_RULESET_MAX 32u
#define KERNEL_LANDLOCK_LAYER_MAX 64u
#define KERNEL_LANDLOCK_RULE_MAX 32u
#define KERNEL_LANDLOCK_TASK_LAYER_MAX 16u
#define KERNEL_LANDLOCK_PATH_MAX 1024u

typedef struct kernel_landlock_path_rule {
    uint64_t allowed_access;
    char path[KERNEL_LANDLOCK_PATH_MAX];
} kernel_landlock_path_rule_t;

typedef struct kernel_landlock_ruleset {
    uint8_t used;
    uint8_t padding[3];
    uint32_t generation;
    uint32_t references;
    uint32_t rule_count;
    uint64_t handled_access_fs;
    kernel_landlock_path_rule_t rules[KERNEL_LANDLOCK_RULE_MAX];
} kernel_landlock_ruleset_t;

typedef struct kernel_landlock_layer {
    uint8_t used;
    uint8_t padding[3];
    uint32_t references;
    uint32_t rule_count;
    uint64_t handled_access_fs;
    kernel_landlock_path_rule_t rules[KERNEL_LANDLOCK_RULE_MAX];
} kernel_landlock_layer_t;

typedef struct kernel_landlock_task {
    uint8_t used;
    uint8_t layer_count;
    uint8_t padding[2];
    int32_t tid;
    int32_t tgid;
    uint16_t layers[KERNEL_LANDLOCK_TASK_LAYER_MAX];
} kernel_landlock_task_t;

static kernel_landlock_ruleset_t
    g_landlock_rulesets[KERNEL_LANDLOCK_RULESET_MAX];
static kernel_landlock_layer_t g_landlock_layers[KERNEL_LANDLOCK_LAYER_MAX];
static kernel_landlock_task_t g_landlock_tasks[EDGE_RUNTIME_MAX_TASKS];
static volatile uint32_t g_landlock_lock;
static uint32_t g_landlock_generation = 1u;

static void landlock_lock(void) {
    while (__sync_lock_test_and_set(&g_landlock_lock, 1u)) { }
}

static void landlock_unlock(void) {
    __sync_lock_release(&g_landlock_lock);
}

static uint32_t landlock_path_length(const char *path) {
    uint32_t length = 0;
    if (!path) return KERNEL_LANDLOCK_PATH_MAX;
    while (length < KERNEL_LANDLOCK_PATH_MAX && path[length]) ++length;
    return length;
}

static int landlock_path_is_beneath(const char *parent,
                                    const char *path) {
    uint32_t length;
    if (!parent || !path || parent[0] != '/' || path[0] != '/') return 0;
    if (parent[1] == 0) return 1;
    length = landlock_path_length(parent);
    if (length >= KERNEL_LANDLOCK_PATH_MAX) return 0;
    return strncmp(parent, path, length) == 0 &&
           (path[length] == 0 || path[length] == '/');
}

static kernel_landlock_ruleset_t *landlock_ruleset_find_locked(
    int32_t ruleset_id) {
    uint32_t slot;
    uint32_t generation;
    kernel_landlock_ruleset_t *ruleset;

    if (ruleset_id <= 0) return 0;
    slot = ((uint32_t)ruleset_id & 0xffu);
    generation = (uint32_t)ruleset_id >> 8;
    if (!slot || slot > KERNEL_LANDLOCK_RULESET_MAX || !generation)
        return 0;
    ruleset = &g_landlock_rulesets[slot - 1u];
    return ruleset->used && ruleset->generation == generation ?
        ruleset : 0;
}

static kernel_landlock_task_t *landlock_task_find_locked(int32_t tid) {
    uint32_t index;
    for (index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index)
        if (g_landlock_tasks[index].used &&
            g_landlock_tasks[index].tid == tid)
            return &g_landlock_tasks[index];
    return 0;
}

static kernel_landlock_task_t *landlock_task_allocate_locked(
    int32_t tid, int32_t tgid) {
    uint32_t index;
    kernel_landlock_task_t *task;
    task = landlock_task_find_locked(tid);
    if (task) return task;
    for (index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index)
        if (!g_landlock_tasks[index].used) break;
    if (index == EDGE_RUNTIME_MAX_TASKS) return 0;
    task = &g_landlock_tasks[index];
    memset(task, 0, sizeof(*task));
    task->used = 1u;
    task->tid = tid;
    task->tgid = tgid;
    return task;
}

static void landlock_layer_release_locked(uint16_t layer_id) {
    kernel_landlock_layer_t *layer;
    if (!layer_id || layer_id > KERNEL_LANDLOCK_LAYER_MAX) return;
    layer = &g_landlock_layers[layer_id - 1u];
    if (!layer->used || !layer->references) return;
    if (--layer->references == 0) memset(layer, 0, sizeof(*layer));
}

static void landlock_task_clear_locked(kernel_landlock_task_t *task) {
    uint32_t index;
    if (!task || !task->used) return;
    for (index = 0; index < task->layer_count; ++index)
        landlock_layer_release_locked(task->layers[index]);
    memset(task, 0, sizeof(*task));
}

static uint32_t landlock_next_generation_locked(void) {
    uint32_t generation;
    do {
        generation = g_landlock_generation++ & 0x7fffffu;
    } while (!generation);
    return generation;
}

int kernel_landlock_ruleset_create(uint64_t handled_access_fs) {
    kernel_landlock_ruleset_t *ruleset;
    uint32_t generation;
    uint32_t index;
    int32_t id;

    if (!handled_access_fs) return -EDGE_LINUX_ENOMSG;
    if (handled_access_fs & ~EDGE_LINUX_LANDLOCK_ACCESS_FS_MASK)
        return -EDGE_LINUX_EINVAL;
    landlock_lock();
    for (index = 0; index < KERNEL_LANDLOCK_RULESET_MAX; ++index)
        if (!g_landlock_rulesets[index].used) break;
    if (index == KERNEL_LANDLOCK_RULESET_MAX) {
        landlock_unlock();
        return -EDGE_LINUX_ENFILE;
    }
    generation = landlock_next_generation_locked();
    ruleset = &g_landlock_rulesets[index];
    memset(ruleset, 0, sizeof(*ruleset));
    ruleset->used = 1u;
    ruleset->generation = generation;
    ruleset->references = 1u;
    ruleset->handled_access_fs = handled_access_fs;
    id = (int32_t)((generation << 8) | (index + 1u));
    landlock_unlock();
    return id;
}

int kernel_landlock_ruleset_retain(int32_t ruleset_id) {
    kernel_landlock_ruleset_t *ruleset;
    int result = -EDGE_LINUX_EBADF;
    landlock_lock();
    ruleset = landlock_ruleset_find_locked(ruleset_id);
    if (ruleset && ruleset->references != UINT32_MAX) {
        ++ruleset->references;
        result = 0;
    }
    landlock_unlock();
    return result;
}

void kernel_landlock_ruleset_release(int32_t ruleset_id) {
    kernel_landlock_ruleset_t *ruleset;
    landlock_lock();
    ruleset = landlock_ruleset_find_locked(ruleset_id);
    if (ruleset && ruleset->references && --ruleset->references == 0)
        memset(ruleset, 0, sizeof(*ruleset));
    landlock_unlock();
}

int kernel_landlock_ruleset_add_path(int32_t ruleset_id,
                                     const char *path,
                                     uint64_t allowed_access) {
    kernel_landlock_ruleset_t *ruleset;
    uint32_t length;
    uint32_t index;
    int result = 0;

    if (!allowed_access) return -EDGE_LINUX_ENOMSG;
    if (!path || path[0] != '/') return -EDGE_LINUX_EBADFD;
    length = landlock_path_length(path);
    if (!length || length >= KERNEL_LANDLOCK_PATH_MAX)
        return -EDGE_LINUX_ENAMETOOLONG;
    landlock_lock();
    ruleset = landlock_ruleset_find_locked(ruleset_id);
    if (!ruleset) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (allowed_access & ~ruleset->handled_access_fs) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    for (index = 0; index < ruleset->rule_count; ++index) {
        if (!strcmp(ruleset->rules[index].path, path)) {
            ruleset->rules[index].allowed_access |= allowed_access;
            goto out;
        }
    }
    if (ruleset->rule_count == KERNEL_LANDLOCK_RULE_MAX) {
        result = -EDGE_LINUX_ENOSPC;
        goto out;
    }
    ruleset->rules[ruleset->rule_count].allowed_access = allowed_access;
    memcpy(ruleset->rules[ruleset->rule_count].path, path, length + 1u);
    ++ruleset->rule_count;
out:
    landlock_unlock();
    return result;
}

int kernel_landlock_restrict_task(int32_t tid, int32_t tgid,
                                  int32_t ruleset_id) {
    kernel_landlock_ruleset_t *ruleset;
    kernel_landlock_layer_t *layer = 0;
    kernel_landlock_task_t *task;
    uint32_t index;
    int result = 0;

    if (tid <= 0 || tgid <= 0) return -EDGE_LINUX_ESRCH;
    landlock_lock();
    ruleset = landlock_ruleset_find_locked(ruleset_id);
    if (!ruleset) {
        result = -EDGE_LINUX_EBADF;
        goto out;
    }
    task = landlock_task_allocate_locked(tid, tgid);
    if (!task) {
        result = -EDGE_LINUX_ENOMEM;
        goto out;
    }
    if (task->layer_count == KERNEL_LANDLOCK_TASK_LAYER_MAX) {
        result = -EDGE_LINUX_E2BIG;
        goto out;
    }
    for (index = 0; index < KERNEL_LANDLOCK_LAYER_MAX; ++index)
        if (!g_landlock_layers[index].used) {
            layer = &g_landlock_layers[index];
            break;
        }
    if (!layer) {
        result = -EDGE_LINUX_ENOMEM;
        goto out;
    }
    memset(layer, 0, sizeof(*layer));
    layer->used = 1u;
    layer->references = 1u;
    layer->rule_count = ruleset->rule_count;
    layer->handled_access_fs = ruleset->handled_access_fs;
    memcpy(layer->rules, ruleset->rules,
           ruleset->rule_count * sizeof(ruleset->rules[0]));
    task->layers[task->layer_count++] = (uint16_t)(index + 1u);
out:
    landlock_unlock();
    return result;
}

int kernel_landlock_check_path_for_task(int32_t tid, const char *path,
                                        uint64_t requested_access) {
    kernel_landlock_task_t *task;
    uint32_t layer_index;
    int result = 0;

    if (!requested_access) return 0;
    if (!path || path[0] != '/') return -EDGE_LINUX_EACCES;
    landlock_lock();
    task = landlock_task_find_locked(tid);
    if (!task) goto out;
    for (layer_index = 0; layer_index < task->layer_count; ++layer_index) {
        kernel_landlock_layer_t *layer;
        uint64_t allowed = 0;
        uint64_t required;
        uint32_t rule_index;
        uint16_t layer_id = task->layers[layer_index];

        if (!layer_id || layer_id > KERNEL_LANDLOCK_LAYER_MAX) continue;
        layer = &g_landlock_layers[layer_id - 1u];
        if (!layer->used) continue;
        required = requested_access &
            (layer->handled_access_fs |
             EDGE_LINUX_LANDLOCK_ACCESS_FS_REFER);
        if (!required) continue;
        for (rule_index = 0; rule_index < layer->rule_count; ++rule_index)
            if (landlock_path_is_beneath(
                    layer->rules[rule_index].path, path))
                allowed |= layer->rules[rule_index].allowed_access;
        if (required & ~allowed) {
            result = -EDGE_LINUX_EACCES;
            break;
        }
    }
out:
    landlock_unlock();
    return result;
}

int kernel_landlock_check_path(const char *path,
                               uint64_t requested_access) {
    kernel_linux_identity_t identity;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    return kernel_landlock_check_path_for_task(
        identity.global_tid, path, requested_access);
}

int kernel_landlock_check_refer_for_task(int32_t tid,
                                         const char *source_path,
                                         const char *destination_path) {
    kernel_landlock_task_t *task;
    uint32_t layer_index;
    int result = 0;

    if (!source_path || !destination_path || source_path[0] != '/' ||
        destination_path[0] != '/')
        return -EDGE_LINUX_EXDEV;
    landlock_lock();
    task = landlock_task_find_locked(tid);
    if (!task) goto out;
    for (layer_index = 0; layer_index < task->layer_count; ++layer_index) {
        kernel_landlock_layer_t *layer;
        uint64_t source_allowed = 0;
        uint64_t destination_allowed = 0;
        uint64_t compared_access;
        uint32_t rule_index;
        uint16_t layer_id = task->layers[layer_index];

        if (!layer_id || layer_id > KERNEL_LANDLOCK_LAYER_MAX) continue;
        layer = &g_landlock_layers[layer_id - 1u];
        if (!layer->used) continue;
        for (rule_index = 0; rule_index < layer->rule_count; ++rule_index) {
            const kernel_landlock_path_rule_t *rule =
                &layer->rules[rule_index];
            if (landlock_path_is_beneath(rule->path, source_path))
                source_allowed |= rule->allowed_access;
            if (landlock_path_is_beneath(rule->path, destination_path))
                destination_allowed |= rule->allowed_access;
        }
        if (!(source_allowed & EDGE_LINUX_LANDLOCK_ACCESS_FS_REFER) ||
            !(destination_allowed & EDGE_LINUX_LANDLOCK_ACCESS_FS_REFER)) {
            result = -EDGE_LINUX_EXDEV;
            break;
        }
        compared_access = layer->handled_access_fs |
            EDGE_LINUX_LANDLOCK_ACCESS_FS_REFER;
        if ((destination_allowed & compared_access) &
            ~(source_allowed & compared_access)) {
            result = -EDGE_LINUX_EXDEV;
            break;
        }
    }
out:
    landlock_unlock();
    return result;
}

int kernel_landlock_check_refer(const char *source_path,
                                const char *destination_path) {
    kernel_linux_identity_t identity;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    return kernel_landlock_check_refer_for_task(
        identity.global_tid, source_path, destination_path);
}

int kernel_landlock_task_clone(int32_t parent_tid, int32_t child_tid,
                               int32_t child_tgid) {
    kernel_landlock_task_t *parent;
    kernel_landlock_task_t *child;
    uint32_t index;
    int result = 0;

    if (parent_tid <= 0 || child_tid <= 0 || child_tgid <= 0)
        return -EDGE_LINUX_EINVAL;
    landlock_lock();
    parent = landlock_task_find_locked(parent_tid);
    if (!parent) goto out;
    child = landlock_task_allocate_locked(child_tid, child_tgid);
    if (!child) {
        result = -EDGE_LINUX_ENOMEM;
        goto out;
    }
    if (child->layer_count) {
        result = -EDGE_LINUX_EEXIST;
        goto out;
    }
    child->layer_count = parent->layer_count;
    for (index = 0; index < parent->layer_count; ++index) {
        uint16_t layer_id = parent->layers[index];
        kernel_landlock_layer_t *layer =
            &g_landlock_layers[layer_id - 1u];
        if (!layer->used || layer->references == UINT32_MAX) {
            while (index) landlock_layer_release_locked(
                child->layers[--index]);
            memset(child, 0, sizeof(*child));
            result = -EDGE_LINUX_ENOMEM;
            goto out;
        }
        ++layer->references;
        child->layers[index] = layer_id;
    }
out:
    landlock_unlock();
    return result;
}

void kernel_landlock_task_exit(int32_t tid, int32_t tgid,
                               int whole_thread_group) {
    uint32_t index;
    landlock_lock();
    for (index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index) {
        kernel_landlock_task_t *task = &g_landlock_tasks[index];
        if (!task->used) continue;
        if (whole_thread_group ? task->tgid == tgid : task->tid == tid)
            landlock_task_clear_locked(task);
    }
    landlock_unlock();
}
