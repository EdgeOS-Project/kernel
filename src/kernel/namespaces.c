/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux namespace implementation.
 * Copyright (c) EdgeOS Contributors.
 *
 * Namespace identity and lifetime are architecture-independent Linux ABI.
 * Hardware ports only select the namespace of the task being scheduled.
 */

#include "kernel/namespace_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_netlink.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "net/network_core.h"
#include "vfs/vfs.h"
#include "string.h"

#define EDGE_NAMESPACE_MAX 64u
#define EDGE_USERNS_MAP_MAX 5u

/* Linux reserves these inode numbers for the initial namespaces. */
#define EDGE_NAMESPACE_INIT_TIME_INODE   UINT32_C(0xEFFFFFFA)
#define EDGE_NAMESPACE_INIT_CGROUP_INODE UINT32_C(0xEFFFFFFB)
#define EDGE_NAMESPACE_INIT_PID_INODE    UINT32_C(0xEFFFFFFC)
#define EDGE_NAMESPACE_INIT_USER_INODE   UINT32_C(0xEFFFFFFD)
#define EDGE_NAMESPACE_INIT_UTS_INODE    UINT32_C(0xEFFFFFFE)
#define EDGE_NAMESPACE_INIT_IPC_INODE    UINT32_C(0xEFFFFFFF)
#define EDGE_NAMESPACE_INIT_NET_INODE    UINT32_C(0xF0000000)
#define EDGE_NAMESPACE_INIT_MNT_INODE    UINT64_C(0xF0000001)
#define EDGE_NAMESPACE_MNT_INODE_BASE    UINT64_C(0x100000000)
#define EDGE_NAMESPACE_DYNAMIC_INODE     UINT32_C(0xF0001000)

enum edge_namespace_pool_kind {
    EDGE_NS_POOL_CGROUP = 0,
    EDGE_NS_POOL_IPC,
    EDGE_NS_POOL_NET,
    EDGE_NS_POOL_PID,
    EDGE_NS_POOL_TIME,
    EDGE_NS_POOL_USER,
    EDGE_NS_POOL_UTS,
    EDGE_NS_POOL_COUNT
};

typedef struct edge_userns_extent {
    uint32_t inside;
    uint32_t outside;
    uint32_t count;
} edge_userns_extent_t;

typedef struct edge_namespace_object {
    uint32_t references;
    uint32_t serial;
    uint64_t list_id;
    uint32_t parent;
    uint32_t owner_user_namespace;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint32_t next_pid;
    uint8_t uid_map_written;
    uint8_t gid_map_written;
    uint8_t setgroups_allowed;
    uint8_t uid_map_count;
    uint8_t gid_map_count;
    edge_userns_extent_t uid_map[EDGE_USERNS_MAP_MAX];
    edge_userns_extent_t gid_map[EDGE_USERNS_MAP_MAX];
    char hostname[65];
    char domainname[65];
} edge_namespace_object_t;

typedef struct edge_pid_namespace_mapping {
    uint32_t namespace_id;
    int32_t visible_tid;
} edge_pid_namespace_mapping_t;

typedef struct edge_pid_task_mapping {
    int32_t global_tid;
    uint8_t state;
    uint8_t count;
    uint16_t reserved;
    edge_pid_namespace_mapping_t mappings[EDGE_NAMESPACE_MAX];
} edge_pid_task_mapping_t;

static edge_namespace_object_t
    g_namespace_objects[EDGE_NS_POOL_COUNT][EDGE_NAMESPACE_MAX];
static uint32_t g_namespace_next_serial;
static uint64_t g_namespace_next_list_id;
static volatile uint32_t g_namespace_lock;
static edge_pid_task_mapping_t g_pid_task_mappings[EDGE_RUNTIME_MAX_TASKS];

enum {
    EDGE_PID_MAPPING_EMPTY = 0,
    EDGE_PID_MAPPING_LIVE = 1,
    EDGE_PID_MAPPING_TOMBSTONE = 2,
};

static int namespace_pool_for_kind(edge_namespace_kind_t kind) {
    switch (kind) {
        case EDGE_NAMESPACE_CGROUP: return EDGE_NS_POOL_CGROUP;
        case EDGE_NAMESPACE_IPC: return EDGE_NS_POOL_IPC;
        case EDGE_NAMESPACE_NET: return EDGE_NS_POOL_NET;
        case EDGE_NAMESPACE_PID:
        case EDGE_NAMESPACE_PID_FOR_CHILDREN: return EDGE_NS_POOL_PID;
        case EDGE_NAMESPACE_TIME:
        case EDGE_NAMESPACE_TIME_FOR_CHILDREN: return EDGE_NS_POOL_TIME;
        case EDGE_NAMESPACE_USER: return EDGE_NS_POOL_USER;
        case EDGE_NAMESPACE_UTS: return EDGE_NS_POOL_UTS;
        default: return -1;
    }
}

static void namespace_set_prepare(edge_namespace_set_t *set) {
    if (!set) return;
    memset(set, 0, sizeof(*set));
    set->mount = UINT32_MAX;
    set->cgroup = UINT32_MAX;
    set->ipc = UINT32_MAX;
    set->net = UINT32_MAX;
    set->pid = UINT32_MAX;
    set->pid_children = UINT32_MAX;
    set->time = UINT32_MAX;
    set->time_children = UINT32_MAX;
    set->user = UINT32_MAX;
    set->uts = UINT32_MAX;
}

static void namespace_lock(void) {
    while (__atomic_exchange_n(&g_namespace_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_namespace_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void namespace_unlock(void) {
    __atomic_store_n(&g_namespace_lock, 0u, __ATOMIC_RELEASE);
}

static void namespace_text_set(char out[65], const char *text,
                               uint32_t length) {
    uint32_t index = 0;
    if (length > 64u) length = 64u;
    while (index < length && text && text[index]) {
        out[index] = text[index];
        ++index;
    }
    while (index < 65u) out[index++] = 0;
}

static edge_namespace_object_t *namespace_object(int pool, uint32_t id) {
    if (pool < 0 || pool >= EDGE_NS_POOL_COUNT || id >= EDGE_NAMESPACE_MAX)
        return 0;
    if (!g_namespace_objects[pool][id].references) return 0;
    return &g_namespace_objects[pool][id];
}

static uint32_t namespace_initial_inode(int pool) {
    switch (pool) {
        case EDGE_NS_POOL_CGROUP: return EDGE_NAMESPACE_INIT_CGROUP_INODE;
        case EDGE_NS_POOL_IPC: return EDGE_NAMESPACE_INIT_IPC_INODE;
        case EDGE_NS_POOL_NET: return EDGE_NAMESPACE_INIT_NET_INODE;
        case EDGE_NS_POOL_PID: return EDGE_NAMESPACE_INIT_PID_INODE;
        case EDGE_NS_POOL_TIME: return EDGE_NAMESPACE_INIT_TIME_INODE;
        case EDGE_NS_POOL_USER: return EDGE_NAMESPACE_INIT_USER_INODE;
        case EDGE_NS_POOL_UTS: return EDGE_NAMESPACE_INIT_UTS_INODE;
        default: return 0;
    }
}

static uint64_t namespace_initial_list_id(int pool) {
    switch (pool) {
        case EDGE_NS_POOL_IPC: return 1u;
        case EDGE_NS_POOL_UTS: return 2u;
        case EDGE_NS_POOL_USER: return 3u;
        case EDGE_NS_POOL_PID: return 4u;
        case EDGE_NS_POOL_CGROUP: return 5u;
        case EDGE_NS_POOL_TIME: return 6u;
        case EDGE_NS_POOL_NET: return 7u;
        default: return 0;
    }
}

static uint32_t pid_mapping_hash(int32_t global_tid) {
    return ((uint32_t)global_tid * 2654435761u) % EDGE_RUNTIME_MAX_TASKS;
}

static edge_pid_task_mapping_t *pid_mapping_find_locked(int32_t global_tid) {
    uint32_t start;
    if (global_tid <= 0) return 0;
    start = pid_mapping_hash(global_tid);
    for (uint32_t probe = 0; probe < EDGE_RUNTIME_MAX_TASKS; ++probe) {
        edge_pid_task_mapping_t *mapping =
            &g_pid_task_mappings[(start + probe) % EDGE_RUNTIME_MAX_TASKS];
        if (mapping->state == EDGE_PID_MAPPING_EMPTY) return 0;
        if (mapping->state == EDGE_PID_MAPPING_LIVE &&
            mapping->global_tid == global_tid)
            return mapping;
    }
    return 0;
}

static edge_pid_task_mapping_t *pid_mapping_allocate_locked(
    int32_t global_tid) {
    edge_pid_task_mapping_t *tombstone = 0;
    uint32_t start;
    if (global_tid <= 0) return 0;
    start = pid_mapping_hash(global_tid);
    for (uint32_t probe = 0; probe < EDGE_RUNTIME_MAX_TASKS; ++probe) {
        edge_pid_task_mapping_t *mapping =
            &g_pid_task_mappings[(start + probe) % EDGE_RUNTIME_MAX_TASKS];
        if (mapping->state == EDGE_PID_MAPPING_LIVE) {
            if (mapping->global_tid == global_tid) return mapping;
            continue;
        }
        if (mapping->state == EDGE_PID_MAPPING_TOMBSTONE) {
            if (!tombstone) tombstone = mapping;
            continue;
        }
        mapping = tombstone ? tombstone : mapping;
        memset(mapping, 0, sizeof(*mapping));
        mapping->global_tid = global_tid;
        mapping->state = EDGE_PID_MAPPING_LIVE;
        return mapping;
    }
    if (!tombstone) return 0;
    memset(tombstone, 0, sizeof(*tombstone));
    tombstone->global_tid = global_tid;
    tombstone->state = EDGE_PID_MAPPING_LIVE;
    return tombstone;
}

static int pid_mapping_visible_locked(
    const edge_pid_task_mapping_t *mapping, uint32_t namespace_id,
    int32_t *visible_tid_out) {
    if (!mapping || mapping->state != EDGE_PID_MAPPING_LIVE ||
        !visible_tid_out)
        return -1;
    if (!namespace_id) {
        *visible_tid_out = mapping->global_tid;
        return 0;
    }
    for (uint32_t index = 0; index < mapping->count; ++index) {
        if (mapping->mappings[index].namespace_id != namespace_id) continue;
        *visible_tid_out = mapping->mappings[index].visible_tid;
        return 0;
    }
    return -1;
}

static int namespace_retain(int pool, uint32_t id) {
    edge_namespace_object_t *object;
    namespace_lock();
    object = namespace_object(pool, id);
    if (!object || object->references == UINT32_MAX) {
        namespace_unlock();
        return -1;
    }
    ++object->references;
    namespace_unlock();
    return 0;
}

static void namespace_release(int pool, uint32_t id) {
    edge_namespace_object_t *object;
    int destroyed = 0;

    namespace_lock();
    object = namespace_object(pool, id);
    if (object && --object->references == 0) {
        memset(object, 0, sizeof(*object));
        destroyed = 1;
    }
    namespace_unlock();
    if (destroyed && pool == EDGE_NS_POOL_NET && id)
        edge_linux_network_namespace_destroy(id);
}

static int namespace_clone_object(int pool, uint32_t parent,
                                  uint32_t owner_uid, uint32_t owner_gid,
                                  uint32_t owner_user_namespace,
                                  int fresh_user_map, uint32_t *id_out) {
    edge_namespace_object_t *parent_object;
    uint32_t id;
    if (!id_out) return -1;
    namespace_lock();
    parent_object = namespace_object(pool, parent);
    if (!parent_object) {
        namespace_unlock();
        return -1;
    }
    for (id = 1; id < EDGE_NAMESPACE_MAX; ++id) {
        edge_namespace_object_t *object = &g_namespace_objects[pool][id];
        if (object->references) continue;
        *object = *parent_object;
        object->references = 1u;
        object->serial = g_namespace_next_serial++;
        if (!object->serial) object->serial = g_namespace_next_serial++;
        object->list_id = g_namespace_next_list_id++;
        if (!object->list_id) object->list_id = g_namespace_next_list_id++;
        object->parent = parent;
        object->owner_user_namespace = owner_user_namespace;
        object->owner_uid = owner_uid;
        object->owner_gid = owner_gid;
        if (pool == EDGE_NS_POOL_PID) object->next_pid = 1u;
        if (fresh_user_map) {
            object->uid_map_written = 0;
            object->gid_map_written = 0;
            object->setgroups_allowed = 1;
            object->uid_map_count = 0;
            object->gid_map_count = 0;
            memset(object->uid_map, 0, sizeof(object->uid_map));
            memset(object->gid_map, 0, sizeof(object->gid_map));
        }
        *id_out = id;
        namespace_unlock();
        if (pool == EDGE_NS_POOL_NET &&
            edge_net_namespace_ensure(id) != EDGE_NET_OK) {
            namespace_release(pool, id);
            return -1;
        }
        return 0;
    }
    namespace_unlock();
    return -1;
}

void edge_namespaces_bootstrap(edge_namespace_set_t *initial,
                               const char *hostname) {
    memset(g_namespace_objects, 0, sizeof(g_namespace_objects));
    memset(g_pid_task_mappings, 0, sizeof(g_pid_task_mappings));
    g_namespace_next_serial = EDGE_NAMESPACE_DYNAMIC_INODE;
    g_namespace_next_list_id = 9u;
    __atomic_store_n(&g_namespace_lock, 0u, __ATOMIC_RELEASE);
    for (int pool = 0; pool < EDGE_NS_POOL_COUNT; ++pool) {
        edge_namespace_object_t *object = &g_namespace_objects[pool][0];
        object->references = 1u;
        object->serial = namespace_initial_inode(pool);
        object->list_id = namespace_initial_list_id(pool);
        object->owner_user_namespace = 0u;
        object->setgroups_allowed = 1;
        object->uid_map_written = 1;
        object->gid_map_written = 1;
        object->uid_map_count = 1;
        object->gid_map_count = 1;
        object->uid_map[0].count = UINT32_MAX;
        object->gid_map[0].count = UINT32_MAX;
    }
    g_namespace_objects[EDGE_NS_POOL_USER][0].owner_user_namespace =
        UINT32_MAX;
    g_namespace_objects[EDGE_NS_POOL_PID][0].next_pid = 2u;
    namespace_text_set(g_namespace_objects[EDGE_NS_POOL_UTS][0].hostname,
                       hostname && hostname[0] ? hostname : "edgeos", 64u);
    namespace_text_set(g_namespace_objects[EDGE_NS_POOL_UTS][0].domainname,
                       "localdomain", 11u);
    if (!initial) return;
    memset(initial, 0, sizeof(*initial));
    initial->owned = 1;
    /* pid_for_children and time_for_children own independent references. */
    (void)namespace_retain(EDGE_NS_POOL_PID, 0);
    (void)namespace_retain(EDGE_NS_POOL_TIME, 0);
}

int edge_pid_namespace_task_attach(const edge_namespace_set_t *set,
                                   int32_t global_tid) {
    edge_pid_task_mapping_t *mapping;
    uint32_t chain[EDGE_NAMESPACE_MAX];
    uint32_t depth = 0;
    uint32_t namespace_id;
    int result = -1;

    if (!set || !set->owned || set->pid == UINT32_MAX || global_tid <= 0)
        return -1;
    namespace_lock();
    mapping = pid_mapping_allocate_locked(global_tid);
    if (!mapping) goto out;
    if (mapping->count) {
        result = 0;
        goto out;
    }
    namespace_id = set->pid;
    while (namespace_id && depth < EDGE_NAMESPACE_MAX) {
        edge_namespace_object_t *object =
            namespace_object(EDGE_NS_POOL_PID, namespace_id);
        if (!object) goto rollback;
        chain[depth++] = namespace_id;
        if (object->parent == namespace_id) goto rollback;
        namespace_id = object->parent;
    }
    if (namespace_id || depth >= EDGE_NAMESPACE_MAX) goto rollback;
    while (depth) {
        edge_namespace_object_t *object;
        edge_pid_namespace_mapping_t *entry;
        namespace_id = chain[--depth];
        object = namespace_object(EDGE_NS_POOL_PID, namespace_id);
        if (!object || !object->next_pid || object->next_pid > INT32_MAX ||
            mapping->count >= EDGE_NAMESPACE_MAX)
            goto rollback;
        entry = &mapping->mappings[mapping->count++];
        entry->namespace_id = namespace_id;
        entry->visible_tid = (int32_t)object->next_pid++;
    }
    result = 0;
    goto out;
rollback:
    memset(mapping, 0, sizeof(*mapping));
    mapping->state = EDGE_PID_MAPPING_TOMBSTONE;
out:
    namespace_unlock();
    return result;
}

void edge_pid_namespace_task_detach(int32_t global_tid) {
    edge_pid_task_mapping_t *mapping;
    if (global_tid <= 0) return;
    namespace_lock();
    mapping = pid_mapping_find_locked(global_tid);
    if (mapping) {
        memset(mapping, 0, sizeof(*mapping));
        mapping->state = EDGE_PID_MAPPING_TOMBSTONE;
    }
    namespace_unlock();
}

int edge_pid_namespace_global_to_visible(uint32_t namespace_id,
                                         int32_t global_tid,
                                         int32_t *visible_tid_out) {
    edge_pid_task_mapping_t *mapping;
    int result;
    if (!visible_tid_out || global_tid <= 0) return -1;
    if (!namespace_id) {
        *visible_tid_out = global_tid;
        return 0;
    }
    namespace_lock();
    mapping = pid_mapping_find_locked(global_tid);
    result = pid_mapping_visible_locked(mapping, namespace_id,
                                        visible_tid_out);
    namespace_unlock();
    return result;
}

int edge_pid_namespace_visible_to_global(uint32_t namespace_id,
                                         int32_t visible_tid,
                                         int32_t *global_tid_out) {
    int result = -1;
    if (!global_tid_out || visible_tid <= 0) return -1;
    if (!namespace_id) {
        *global_tid_out = visible_tid;
        return 0;
    }
    namespace_lock();
    for (uint32_t slot = 0; slot < EDGE_RUNTIME_MAX_TASKS; ++slot) {
        edge_pid_task_mapping_t *mapping = &g_pid_task_mappings[slot];
        int32_t candidate;
        if (pid_mapping_visible_locked(mapping, namespace_id,
                                       &candidate) < 0 ||
            candidate != visible_tid)
            continue;
        *global_tid_out = mapping->global_tid;
        result = 0;
        break;
    }
    namespace_unlock();
    return result;
}

static int namespace_assign(uint32_t *out, int pool, uint32_t parent,
                            int create, uint32_t owner_uid,
                            uint32_t owner_gid,
                            uint32_t owner_user_namespace) {
    if (create)
        return namespace_clone_object(pool, parent, owner_uid, owner_gid,
                                      owner_user_namespace,
                                      pool == EDGE_NS_POOL_USER, out);
    if (namespace_retain(pool, parent) < 0) return -1;
    *out = parent;
    return 0;
}

void edge_namespaces_release(edge_namespace_set_t *set) {
    if (!set || !set->owned) return;
    if (set->mount != UINT32_MAX) vfs_mount_namespace_release(set->mount);
    if (set->cgroup != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_CGROUP, set->cgroup);
    if (set->ipc != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_IPC, set->ipc);
    if (set->net != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_NET, set->net);
    if (set->pid != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_PID, set->pid);
    if (set->pid_children != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_PID, set->pid_children);
    if (set->time != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_TIME, set->time);
    if (set->time_children != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_TIME, set->time_children);
    if (set->user != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_USER, set->user);
    if (set->uts != UINT32_MAX)
        namespace_release(EDGE_NS_POOL_UTS, set->uts);
    memset(set, 0, sizeof(*set));
}

int edge_namespaces_clone(edge_namespace_set_t *child,
                          const edge_namespace_set_t *parent,
                          uint64_t clone_flags,
                          uint32_t owner_uid, uint32_t owner_gid) {
    if (!child || !parent || !parent->owned ||
        (clone_flags & ~EDGE_NAMESPACE_CLONE_FLAGS)) return -1;
    namespace_set_prepare(child);
    child->owned = 1;
    if ((clone_flags & EDGE_CLONE_NEWNS) ?
        vfs_mount_namespace_clone(parent->mount, &child->mount) < 0 :
        (child->mount = parent->mount,
         vfs_mount_namespace_retain(child->mount) < 0)) goto fail;
    if (namespace_assign(&child->user, EDGE_NS_POOL_USER, parent->user,
                         (clone_flags & EDGE_CLONE_NEWUSER) != 0,
                         owner_uid, owner_gid, parent->user) < 0) goto fail;
    if ((clone_flags & EDGE_CLONE_NEWNS) != 0) {
        uint64_t list_id;
        namespace_lock();
        list_id = g_namespace_next_list_id++;
        if (!list_id) list_id = g_namespace_next_list_id++;
        namespace_unlock();
        if (vfs_mount_namespace_metadata_set(
                child->mount, list_id, child->user) < 0)
            goto fail;
    }
    if (namespace_assign(&child->cgroup, EDGE_NS_POOL_CGROUP,
                         parent->cgroup,
                         (clone_flags & EDGE_CLONE_NEWCGROUP) != 0,
                         owner_uid, owner_gid, child->user) < 0) goto fail;
    if (namespace_assign(&child->ipc, EDGE_NS_POOL_IPC, parent->ipc,
                         (clone_flags & EDGE_CLONE_NEWIPC) != 0,
                         owner_uid, owner_gid, child->user) < 0) goto fail;
    if (namespace_assign(&child->net, EDGE_NS_POOL_NET, parent->net,
                         (clone_flags & EDGE_CLONE_NEWNET) != 0,
                         owner_uid, owner_gid, child->user) < 0) goto fail;
    if (namespace_assign(&child->pid, EDGE_NS_POOL_PID,
                         (clone_flags & EDGE_CLONE_NEWPID) ? parent->pid :
                                                            parent->pid_children,
                         (clone_flags & EDGE_CLONE_NEWPID) != 0,
                         owner_uid, owner_gid, child->user) < 0) goto fail;
    child->pid_children = child->pid;
    if (namespace_retain(EDGE_NS_POOL_PID, child->pid_children) < 0)
        goto fail;
    if (namespace_assign(&child->time, EDGE_NS_POOL_TIME,
                         parent->time_children,
                         (clone_flags & EDGE_CLONE_NEWTIME) != 0,
                         owner_uid, owner_gid, child->user) < 0) goto fail;
    child->time_children = child->time;
    if (namespace_retain(EDGE_NS_POOL_TIME, child->time_children) < 0)
        goto fail;
    if (namespace_assign(&child->uts, EDGE_NS_POOL_UTS, parent->uts,
                         (clone_flags & EDGE_CLONE_NEWUTS) != 0,
                         owner_uid, owner_gid, child->user) < 0) goto fail;
    return 0;
fail:
    edge_namespaces_release(child);
    return -1;
}

int edge_namespaces_inherit(edge_namespace_set_t *child,
                            const edge_namespace_set_t *parent) {
    return edge_namespaces_clone(child, parent, 0, 0, 0);
}

int edge_namespaces_unshare(edge_namespace_set_t *set, uint64_t flags,
                            uint32_t owner_uid, uint32_t owner_gid) {
    edge_namespace_set_t replacement;
    uint32_t old_pid;
    uint32_t old_time;
    uint32_t new_pid_children;
    uint32_t new_time_children;
    if (!set || !set->owned || (flags & ~EDGE_NAMESPACE_CLONE_FLAGS))
        return -1;
    if (!flags) return 0;
    old_pid = set->pid;
    old_time = set->time;
    if (edge_namespaces_clone(&replacement, set, flags,
                              owner_uid, owner_gid) < 0) return -1;
    if (flags & EDGE_CLONE_NEWPID) {
        /* unshare(CLONE_NEWPID) affects only subsequently created children. */
        new_pid_children = replacement.pid;
        namespace_release(EDGE_NS_POOL_PID, replacement.pid_children);
        replacement.pid_children = new_pid_children;
        if (namespace_retain(EDGE_NS_POOL_PID,
                             replacement.pid_children) < 0) {
            edge_namespaces_release(&replacement);
            return -1;
        }
        namespace_release(EDGE_NS_POOL_PID, replacement.pid);
        replacement.pid = old_pid;
        if (namespace_retain(EDGE_NS_POOL_PID, replacement.pid) < 0) {
            edge_namespaces_release(&replacement);
            return -1;
        }
    }
    if (flags & EDGE_CLONE_NEWTIME) {
        /* unshare(CLONE_NEWTIME) changes the namespace used by new children. */
        new_time_children = replacement.time;
        namespace_release(EDGE_NS_POOL_TIME, replacement.time_children);
        replacement.time_children = new_time_children;
        if (namespace_retain(EDGE_NS_POOL_TIME,
                             replacement.time_children) < 0) {
            edge_namespaces_release(&replacement);
            return -1;
        }
        namespace_release(EDGE_NS_POOL_TIME, replacement.time);
        replacement.time = old_time;
        if (namespace_retain(EDGE_NS_POOL_TIME, replacement.time) < 0) {
            edge_namespaces_release(&replacement);
            return -1;
        }
    }
    edge_namespaces_release(set);
    *set = replacement;
    if ((flags & EDGE_CLONE_NEWNS) &&
        vfs_mount_namespace_activate(set->mount) < 0) return -1;
    return 0;
}

const char *edge_namespace_name(edge_namespace_kind_t kind) {
    static const char *const names[EDGE_NAMESPACE_KIND_COUNT] = {
        "cgroup", "ipc", "mnt", "net", "pid", "pid_for_children",
        "time", "time_for_children", "user", "uts"
    };
    return (uint32_t)kind < EDGE_NAMESPACE_KIND_COUNT ? names[kind] : 0;
}

uint64_t edge_namespace_clone_flag(edge_namespace_kind_t kind) {
    switch (kind) {
        case EDGE_NAMESPACE_CGROUP: return EDGE_CLONE_NEWCGROUP;
        case EDGE_NAMESPACE_IPC: return EDGE_CLONE_NEWIPC;
        case EDGE_NAMESPACE_MNT: return EDGE_CLONE_NEWNS;
        case EDGE_NAMESPACE_NET: return EDGE_CLONE_NEWNET;
        case EDGE_NAMESPACE_PID:
        case EDGE_NAMESPACE_PID_FOR_CHILDREN: return EDGE_CLONE_NEWPID;
        case EDGE_NAMESPACE_TIME:
        case EDGE_NAMESPACE_TIME_FOR_CHILDREN: return EDGE_CLONE_NEWTIME;
        case EDGE_NAMESPACE_USER: return EDGE_CLONE_NEWUSER;
        case EDGE_NAMESPACE_UTS: return EDGE_CLONE_NEWUTS;
        default: return 0;
    }
}

uint32_t edge_namespace_id(const edge_namespace_set_t *set,
                           edge_namespace_kind_t kind) {
    if (!set || !set->owned) return UINT32_MAX;
    switch (kind) {
        case EDGE_NAMESPACE_CGROUP: return set->cgroup;
        case EDGE_NAMESPACE_IPC: return set->ipc;
        case EDGE_NAMESPACE_MNT: return set->mount;
        case EDGE_NAMESPACE_NET: return set->net;
        case EDGE_NAMESPACE_PID: return set->pid;
        case EDGE_NAMESPACE_PID_FOR_CHILDREN: return set->pid_children;
        case EDGE_NAMESPACE_TIME: return set->time;
        case EDGE_NAMESPACE_TIME_FOR_CHILDREN: return set->time_children;
        case EDGE_NAMESPACE_USER: return set->user;
        case EDGE_NAMESPACE_UTS: return set->uts;
        default: return UINT32_MAX;
    }
}

uint64_t edge_namespace_inode(const edge_namespace_set_t *set,
                              edge_namespace_kind_t kind) {
    uint32_t id = edge_namespace_id(set, kind);
    return id == UINT32_MAX ? 0 : edge_namespace_handle_inode(kind, id);
}

uint64_t edge_namespace_handle_inode(edge_namespace_kind_t kind, uint32_t id) {
    int pool;
    if (kind == EDGE_NAMESPACE_MNT) {
        if (!vfs_mount_namespace_exists(id)) return 0;
        return id == 0 ? EDGE_NAMESPACE_INIT_MNT_INODE :
            EDGE_NAMESPACE_MNT_INODE_BASE + id;
    }
    pool = namespace_pool_for_kind(kind);
    if (pool < 0) return 0;
    {
        edge_namespace_object_t *object = namespace_object(pool, id);
        return object ? object->serial : 0;
    }
}

uint64_t edge_namespace_list_id(edge_namespace_kind_t kind, uint32_t id) {
    edge_namespace_object_t *object;
    uint64_t list_id = 0;
    int pool;

    if (kind == EDGE_NAMESPACE_PID_FOR_CHILDREN)
        kind = EDGE_NAMESPACE_PID;
    else if (kind == EDGE_NAMESPACE_TIME_FOR_CHILDREN)
        kind = EDGE_NAMESPACE_TIME;
    if (kind == EDGE_NAMESPACE_MNT) {
        if (vfs_mount_namespace_metadata_get(id, &list_id, 0) < 0)
            return 0;
        return list_id;
    }
    pool = namespace_pool_for_kind(kind);
    if (pool < 0) return 0;
    namespace_lock();
    object = namespace_object(pool, id);
    if (object) list_id = object->list_id;
    namespace_unlock();
    return list_id;
}

static edge_namespace_kind_t namespace_kind_for_pool(int pool) {
    switch (pool) {
        case EDGE_NS_POOL_CGROUP: return EDGE_NAMESPACE_CGROUP;
        case EDGE_NS_POOL_IPC: return EDGE_NAMESPACE_IPC;
        case EDGE_NS_POOL_NET: return EDGE_NAMESPACE_NET;
        case EDGE_NS_POOL_PID: return EDGE_NAMESPACE_PID;
        case EDGE_NS_POOL_TIME: return EDGE_NAMESPACE_TIME;
        case EDGE_NS_POOL_USER: return EDGE_NAMESPACE_USER;
        case EDGE_NS_POOL_UTS: return EDGE_NAMESPACE_UTS;
        default: return EDGE_NAMESPACE_KIND_COUNT;
    }
}

static int namespace_current_matches(const edge_namespace_set_t *current,
                                     edge_namespace_kind_t kind,
                                     uint32_t id) {
    return current && current->owned &&
           edge_namespace_id(current, kind) == id;
}

int edge_namespace_list_next(const edge_namespace_set_t *current,
                             uint64_t after_list_id,
                             uint64_t owner_user_list_id,
                             uint32_t type_mask,
                             int may_see_all,
                             uint64_t *next_list_id_out,
                             int *any_matching_after_out) {
    uint64_t best = UINT64_MAX;
    uint32_t owner_user_namespace = UINT32_MAX;
    int filter_owner = owner_user_list_id != 0;
    int any_matching = 0;
    int single_type = type_mask && !(type_mask & (type_mask - 1u));

    if (!current || !current->owned || !next_list_id_out ||
        !any_matching_after_out)
        return -EDGE_LINUX_EINVAL;

    namespace_lock();
    if (filter_owner) {
        if (owner_user_list_id == UINT64_MAX) {
            owner_user_namespace = current->user;
        } else {
            for (uint32_t id = 0; id < EDGE_NAMESPACE_MAX; ++id) {
                edge_namespace_object_t *object =
                    namespace_object(EDGE_NS_POOL_USER, id);
                if (object && object->list_id == owner_user_list_id) {
                    owner_user_namespace = id;
                    break;
                }
            }
            if (owner_user_namespace == UINT32_MAX) {
                namespace_unlock();
                return -EDGE_LINUX_EINVAL;
            }
        }
    }

    for (int pool = 0; pool < EDGE_NS_POOL_COUNT; ++pool) {
        edge_namespace_kind_t kind = namespace_kind_for_pool(pool);
        uint32_t clone_flag = (uint32_t)edge_namespace_clone_flag(kind);
        for (uint32_t id = 0; id < EDGE_NAMESPACE_MAX; ++id) {
            edge_namespace_object_t *object = namespace_object(pool, id);
            if (!object || object->list_id <= after_list_id) continue;
            if (filter_owner &&
                object->owner_user_namespace != owner_user_namespace)
                continue;
            if (filter_owner || !single_type || (type_mask & clone_flag))
                any_matching = 1;
            if (type_mask && !(type_mask & clone_flag)) continue;
            if (!may_see_all &&
                !namespace_current_matches(current, kind, id))
                continue;
            if (object->list_id < best) best = object->list_id;
        }
    }
    namespace_unlock();

    {
        uint64_t cursor = after_list_id;
        for (;;) {
            uint64_t list_id;
            uint32_t namespace_id;
            uint32_t owner;
            int result = vfs_mount_namespace_list_next(
                cursor, &list_id, &namespace_id, &owner);
            if (result <= 0) break;
            cursor = list_id;
            if (filter_owner && owner != owner_user_namespace) continue;
            if (filter_owner || !single_type ||
                (type_mask & EDGE_CLONE_NEWNS))
                any_matching = 1;
            if (type_mask && !(type_mask & EDGE_CLONE_NEWNS)) continue;
            if (!may_see_all && current->mount != namespace_id) continue;
            if (list_id < best) best = list_id;
        }
    }

    *any_matching_after_out = any_matching;
    if (best == UINT64_MAX) return 0;
    *next_list_id_out = best;
    return 1;
}

int edge_namespace_handle_retain(edge_namespace_kind_t kind, uint32_t id) {
    int pool;
    if (kind == EDGE_NAMESPACE_MNT)
        return vfs_mount_namespace_retain(id);
    pool = namespace_pool_for_kind(kind);
    return pool < 0 ? -1 : namespace_retain(pool, id);
}

void edge_namespace_handle_release(edge_namespace_kind_t kind, uint32_t id) {
    int pool;
    if (kind == EDGE_NAMESPACE_MNT) {
        vfs_mount_namespace_release(id);
        return;
    }
    pool = namespace_pool_for_kind(kind);
    if (pool >= 0) namespace_release(pool, id);
}

int edge_namespace_handle_acquire_inode(edge_namespace_kind_t kind,
                                        uint64_t inode,
                                        uint32_t *id_out) {
    int pool;

    if (!inode || !id_out || (uint32_t)kind >= EDGE_NAMESPACE_KIND_COUNT)
        return -1;
    if (kind == EDGE_NAMESPACE_MNT) {
        uint64_t offset;
        uint32_t id;

        if (inode == EDGE_NAMESPACE_INIT_MNT_INODE) {
            id = 0;
        } else {
            if (inode <= EDGE_NAMESPACE_MNT_INODE_BASE) return -1;
            offset = inode - EDGE_NAMESPACE_MNT_INODE_BASE;
            if (offset > UINT32_MAX) return -1;
            id = (uint32_t)offset;
        }
        if (edge_namespace_handle_retain(kind, id) < 0) return -1;
        *id_out = id;
        return 0;
    }

    pool = namespace_pool_for_kind(kind);
    if (pool < 0) return -1;
    namespace_lock();
    for (uint32_t id = 0; id < EDGE_NAMESPACE_MAX; ++id) {
        edge_namespace_object_t *object = namespace_object(pool, id);
        if (!object || object->serial != inode ||
            object->references == UINT32_MAX)
            continue;
        ++object->references;
        *id_out = id;
        namespace_unlock();
        return 0;
    }
    namespace_unlock();
    return -1;
}

int edge_namespace_owner_uid(edge_namespace_kind_t kind, uint32_t id,
                             uint32_t *uid_out) {
    edge_namespace_object_t *object;
    int pool = namespace_pool_for_kind(kind);
    if (!uid_out || pool < 0) return -1;
    namespace_lock();
    object = namespace_object(pool, id);
    if (!object) {
        namespace_unlock();
        return -1;
    }
    *uid_out = object->owner_uid;
    namespace_unlock();
    return 0;
}

int edge_namespace_handle_acquire(const edge_namespace_set_t *set,
                                  edge_namespace_kind_t kind,
                                  uint32_t *id_out) {
    uint32_t id;
    if (!set || !set->owned || !id_out) return -1;
    id = edge_namespace_id(set, kind);
    if (id == UINT32_MAX || edge_namespace_handle_retain(kind, id) < 0)
        return -1;
    *id_out = id;
    return 0;
}

int edge_namespaces_join(edge_namespace_set_t *set,
                         edge_namespace_kind_t kind, uint32_t id) {
    uint32_t *slot = 0;
    int pool;
    if (!set || !set->owned || !edge_namespace_clone_flag(kind)) return -1;
    if (kind == EDGE_NAMESPACE_MNT) {
        if (vfs_mount_namespace_retain(id) < 0) return -1;
        if (vfs_mount_namespace_activate(id) < 0) {
            vfs_mount_namespace_release(id);
            return -1;
        }
        vfs_mount_namespace_release(set->mount);
        set->mount = id;
        return 0;
    }
    pool = namespace_pool_for_kind(kind);
    if (pool < 0 || namespace_retain(pool, id) < 0) return -1;
    switch (kind) {
        case EDGE_NAMESPACE_CGROUP: slot = &set->cgroup; break;
        case EDGE_NAMESPACE_IPC: slot = &set->ipc; break;
        case EDGE_NAMESPACE_NET: slot = &set->net; break;
        case EDGE_NAMESPACE_PID:
        case EDGE_NAMESPACE_PID_FOR_CHILDREN:
            slot = &set->pid_children;
            break;
        case EDGE_NAMESPACE_USER: slot = &set->user; break;
        case EDGE_NAMESPACE_UTS: slot = &set->uts; break;
        case EDGE_NAMESPACE_TIME:
        case EDGE_NAMESPACE_TIME_FOR_CHILDREN:
            if (namespace_retain(pool, id) < 0) {
                namespace_release(pool, id);
                return -1;
            }
            namespace_release(pool, set->time);
            namespace_release(pool, set->time_children);
            set->time = id;
            set->time_children = id;
            return 0;
        default:
            namespace_release(pool, id);
            return -1;
    }
    namespace_release(pool, *slot);
    *slot = id;
    return 0;
}

const char *edge_uts_hostname(const edge_namespace_set_t *set) {
    edge_namespace_object_t *object = set ?
        namespace_object(EDGE_NS_POOL_UTS, set->uts) : 0;
    return object ? object->hostname : "edgeos";
}

const char *edge_uts_domainname(const edge_namespace_set_t *set) {
    edge_namespace_object_t *object = set ?
        namespace_object(EDGE_NS_POOL_UTS, set->uts) : 0;
    return object ? object->domainname : "localdomain";
}

static int edge_uts_set_field(const edge_namespace_set_t *set,
                              const char *name, uint32_t length,
                              int domain) {
    edge_namespace_object_t *object;
    if (!set || !set->owned || !name || length > 64u) return -1;
    namespace_lock();
    object = namespace_object(EDGE_NS_POOL_UTS, set->uts);
    if (!object) {
        namespace_unlock();
        return -1;
    }
    namespace_text_set(domain ? object->domainname : object->hostname,
                       name, length);
    namespace_unlock();
    return 0;
}

int edge_uts_set_hostname(const edge_namespace_set_t *set,
                          const char *name, uint32_t length) {
    return edge_uts_set_field(set, name, length, 0);
}

int edge_uts_set_domainname(const edge_namespace_set_t *set,
                            const char *name, uint32_t length) {
    return edge_uts_set_field(set, name, length, 1);
}

static int namespace_append_u32(char *out, uint32_t max, uint32_t *offset,
                                uint32_t value) {
    char digits[10];
    uint32_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    if (*offset + count >= max) return -1;
    while (count) out[(*offset)++] = digits[--count];
    return 0;
}

int edge_userns_read_map(const edge_namespace_set_t *set, int gid_map,
                         char *out, uint32_t max) {
    edge_namespace_object_t *object;
    edge_userns_extent_t *map;
    uint32_t offset = 0;
    uint32_t count;
    if (!set || !out || !max) return -1;
    object = namespace_object(EDGE_NS_POOL_USER, set->user);
    if (!object) return -1;
    map = gid_map ? object->gid_map : object->uid_map;
    count = gid_map ? object->gid_map_count : object->uid_map_count;
    for (uint32_t index = 0; index < count; ++index) {
        if (namespace_append_u32(out, max, &offset, map[index].inside) < 0 ||
            offset + 1u >= max) return -1;
        out[offset++] = ' ';
        if (namespace_append_u32(out, max, &offset, map[index].outside) < 0 ||
            offset + 1u >= max) return -1;
        out[offset++] = ' ';
        if (namespace_append_u32(out, max, &offset, map[index].count) < 0 ||
            offset + 1u >= max) return -1;
        out[offset++] = '\n';
    }
    out[offset] = 0;
    return (int)offset;
}

int edge_userns_map_from_parent(const edge_namespace_set_t *set, int gid_map,
                                uint32_t outside_id,
                                uint32_t *inside_id_out) {
    edge_namespace_object_t *object;
    edge_userns_extent_t *map;
    uint32_t count;
    int result = -1;
    if (!set || !inside_id_out) return -1;
    namespace_lock();
    object = namespace_object(EDGE_NS_POOL_USER, set->user);
    if (!object) {
        namespace_unlock();
        return -1;
    }
    map = gid_map ? object->gid_map : object->uid_map;
    count = gid_map ? object->gid_map_count : object->uid_map_count;
    for (uint32_t index = 0; index < count; ++index) {
        uint64_t outside_end = (uint64_t)map[index].outside +
                               map[index].count;
        if (outside_id < map[index].outside || outside_id >= outside_end)
            continue;
        *inside_id_out = map[index].inside +
                         (outside_id - map[index].outside);
        result = 0;
        break;
    }
    namespace_unlock();
    return result;
}

static int namespace_parse_u32(const char **text, const char *end,
                               uint32_t *value_out) {
    uint64_t value = 0;
    const char *p = *text;
    int digits = 0;
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    while (p < end && *p >= '0' && *p <= '9') {
        value = value * 10u + (uint32_t)(*p - '0');
        if (value > UINT32_MAX) return -1;
        ++p;
        digits = 1;
    }
    if (!digits) return -1;
    *text = p;
    *value_out = (uint32_t)value;
    return 0;
}

int edge_userns_write_map(const edge_namespace_set_t *set, int gid_map,
                          const char *text, uint32_t length,
                          uint32_t writer_uid, uint32_t writer_gid) {
    edge_userns_extent_t parsed[EDGE_USERNS_MAP_MAX];
    edge_namespace_object_t *object;
    const char *p = text;
    const char *end = text + length;
    uint32_t count = 0;
    (void)writer_gid;
    if (!set || !text || !length || length > 4096u) return -1;
    while (p < end) {
        edge_userns_extent_t extent;
        while (p < end && (*p == '\n' || *p == ' ' || *p == '\t')) ++p;
        if (p == end) break;
        if (count >= EDGE_USERNS_MAP_MAX ||
            namespace_parse_u32(&p, end, &extent.inside) < 0 ||
            namespace_parse_u32(&p, end, &extent.outside) < 0 ||
            namespace_parse_u32(&p, end, &extent.count) < 0 ||
            !extent.count || extent.inside + extent.count < extent.inside ||
            extent.outside + extent.count < extent.outside) return -1;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        if (p < end && *p != '\n') return -1;
        if (p < end) ++p;
        for (uint32_t old = 0; old < count; ++old) {
            uint64_t old_in_end = (uint64_t)parsed[old].inside + parsed[old].count;
            uint64_t old_out_end = (uint64_t)parsed[old].outside + parsed[old].count;
            uint64_t in_end = (uint64_t)extent.inside + extent.count;
            uint64_t out_end = (uint64_t)extent.outside + extent.count;
            if ((extent.inside < old_in_end && parsed[old].inside < in_end) ||
                (extent.outside < old_out_end && parsed[old].outside < out_end))
                return -1;
        }
        parsed[count++] = extent;
    }
    if (!count) return -1;
    namespace_lock();
    object = namespace_object(EDGE_NS_POOL_USER, set->user);
    if (!object || (gid_map ? object->gid_map_written :
                              object->uid_map_written) ||
        (writer_uid != 0 && writer_uid != object->owner_uid) ||
        (gid_map && writer_uid != 0 && object->setgroups_allowed)) {
        namespace_unlock();
        return -1;
    }
    if (gid_map) {
        memcpy(object->gid_map, parsed, count * sizeof(parsed[0]));
        object->gid_map_count = (uint8_t)count;
        object->gid_map_written = 1;
    } else {
        memcpy(object->uid_map, parsed, count * sizeof(parsed[0]));
        object->uid_map_count = (uint8_t)count;
        object->uid_map_written = 1;
    }
    namespace_unlock();
    return (int)length;
}

int edge_userns_read_setgroups(const edge_namespace_set_t *set,
                               char *out, uint32_t max) {
    edge_namespace_object_t *object;
    const char *text;
    uint32_t length;
    if (!set || !out) return -1;
    object = namespace_object(EDGE_NS_POOL_USER, set->user);
    if (!object) return -1;
    text = object->setgroups_allowed ? "allow\n" : "deny\n";
    length = object->setgroups_allowed ? 6u : 5u;
    if (max <= length) return -1;
    memcpy(out, text, length + 1u);
    return (int)length;
}

int edge_userns_write_setgroups(const edge_namespace_set_t *set,
                                const char *text, uint32_t length,
                                uint32_t writer_uid) {
    edge_namespace_object_t *object;
    if (!set || !text ||
        !((length == 4u && memcmp(text, "deny", 4u) == 0) ||
          (length == 5u && memcmp(text, "deny\n", 5u) == 0)))
        return -1;
    namespace_lock();
    object = namespace_object(EDGE_NS_POOL_USER, set->user);
    if (!object || object->gid_map_written || !object->setgroups_allowed ||
        (writer_uid != 0 && writer_uid != object->owner_uid)) {
        namespace_unlock();
        return -1;
    }
    object->setgroups_allowed = 0;
    namespace_unlock();
    return (int)length;
}

int kernel_current_namespace_state(
    kernel_namespace_runtime_state_t *state) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    kernel_linux_identity_t identity;
    kernel_proc_task_view_t task;
    uint64_t current_fs_context_id;
    if (!namespaces || !state) return -EDGE_LINUX_ESRCH;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(state, 0, sizeof(*state));
    state->user_namespace_id = edge_namespace_id(
        namespaces, EDGE_NAMESPACE_USER);
    if (kernel_proc_task_view_get(identity.global_tid, &task) < 0 ||
        task.state == KERNEL_PROC_TASK_ZOMBIE)
        return -EDGE_LINUX_ESRCH;
    current_fs_context_id = task.fs_context_id;
    for (uint32_t slot = 0;; ++slot) {
        int status = kernel_arch_proc_task_sample(slot, &task);
        int32_t tgid;
        if (status < 0) break;
        if (status > 0 || task.state == KERNEL_PROC_TASK_ZOMBIE) continue;
        tgid = task.tgid > 0 ? task.tgid : task.tid;
        if (tgid == identity.global_tgid) ++state->thread_count;
        if (task.tid != identity.global_tid &&
            task.fs_context_id == current_fs_context_id)
            state->filesystem_context_shared = 1u;
    }
    return 0;
}

int kernel_current_namespace_join(edge_namespace_kind_t kind, uint32_t id) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    if (!namespaces) return -EDGE_LINUX_ESRCH;
    if (edge_namespaces_join(namespaces, kind, id) < 0)
        return -EDGE_LINUX_EINVAL;
    kernel_arch_current_namespace_committed(namespaces);
    return 0;
}

int kernel_current_namespaces_unshare(uint64_t flags,
                                      uint32_t owner_uid,
                                      uint32_t owner_gid) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    kernel_linux_identity_t identity;
    if (!namespaces) return -EDGE_LINUX_ESRCH;
    if (edge_namespaces_unshare(namespaces, flags,
                                owner_uid, owner_gid) < 0)
        return -EDGE_LINUX_ENOMEM;
    kernel_arch_current_namespace_committed(namespaces);
    if ((flags & EDGE_CLONE_NEWUSER) &&
        (kernel_current_linux_identity(&identity) < 0 ||
         kernel_user_namespace_capabilities_grant(identity.global_tid) < 0))
        return -EDGE_LINUX_EIO;
    return 0;
}

int kernel_user_namespace_capabilities_grant(int32_t tid) {
    linux_credential_state_t credentials;

    if (kernel_process_credentials_get(tid, &credentials) < 0)
        return -1;
    linux_capabilities_init_root(&credentials.capabilities);
    return kernel_arch_process_credentials_commit(tid, &credentials, 0);
}
