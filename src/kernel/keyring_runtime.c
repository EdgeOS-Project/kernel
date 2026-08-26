/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux key retention service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>
#include <stdint.h>

#include "kernel/keyring_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/pipe_runtime.h"
#include "kernel/sha1_runtime.h"
#include "kernel/sha256_runtime.h"
#include "kernel/sha512_runtime.h"
#include "kernel/vfs_runtime.h"
#include "string.h"
#include "sys/boottime.h"

#define KERNEL_KEY_MAX 256u
#define KERNEL_KEY_TASK_MAX 2048u
#define KERNEL_KEY_LINK_MAX 64u
#define KERNEL_KEY_TYPE_MAX 32u
#define KERNEL_KEY_DESCRIPTION_MAX 4096u
#define KERNEL_KEY_PAYLOAD_MAX 65536u
#define KERNEL_KEY_SEARCH_DEPTH_MAX 8u
#define KERNEL_KEY_WATCH_MAX 16u
#define KERNEL_KEY_IOV_MAX 1024u
#define KERNEL_KEY_DH_MAX_BYTES 2048u
#define KERNEL_KEY_DH_MAX_LIMBS (KERNEL_KEY_DH_MAX_BYTES / 4u)
#define KERNEL_KEY_KDF_MAX_OUTPUT 1024u
#define KERNEL_KEY_KDF_MAX_OTHERINFO 64u
#define KERNEL_KEY_KDF_HASH_NAME_MAX 64u

enum kernel_key_notification_subtype {
    KERNEL_KEY_NOTIFY_INSTANTIATED = 0,
    KERNEL_KEY_NOTIFY_UPDATED = 1,
    KERNEL_KEY_NOTIFY_LINKED = 2,
    KERNEL_KEY_NOTIFY_UNLINKED = 3,
    KERNEL_KEY_NOTIFY_CLEARED = 4,
    KERNEL_KEY_NOTIFY_REVOKED = 5,
    KERNEL_KEY_NOTIFY_INVALIDATED = 6,
    KERNEL_KEY_NOTIFY_SETATTR = 7,
};

typedef struct kernel_key_watch {
    uint8_t used;
    uint8_t watch_id;
    uint16_t reserved;
    kernel_pipe_runtime_t *pipe;
    uint64_t pipe_generation;
} kernel_key_watch_t;

typedef struct kernel_key_notification {
    uint32_t type_subtype;
    uint32_t info;
    uint32_t key_id;
    uint32_t auxiliary;
} kernel_key_notification_t;

typedef struct kernel_key_removal_notification {
    uint32_t type_subtype;
    uint32_t info;
    uint64_t key_id;
} kernel_key_removal_notification_t;

typedef struct kernel_key_user_iovec {
    uint64_t base;
    uint64_t length;
} kernel_key_user_iovec_t;

typedef struct kernel_key_user_iovec32 {
    uint32_t base;
    uint32_t length;
} kernel_key_user_iovec32_t;

enum kernel_key_kind {
    KERNEL_KEY_KIND_KEYRING = 1,
    KERNEL_KEY_KIND_USER,
    KERNEL_KEY_KIND_LOGON,
    KERNEL_KEY_KIND_BIG_KEY,
};

typedef struct kernel_key_object {
    uint8_t used;
    uint8_t constructing;
    uint8_t revoked;
    uint8_t invalidated;
    uint8_t restriction_set;
    uint8_t reject_links;
    uint8_t kind;
    uint8_t padding;
    int32_t serial;
    uint32_t uid;
    uint32_t gid;
    uint32_t user_namespace_id;
    uint32_t permissions;
    uint32_t payload_length;
    uint32_t link_count;
    uint64_t expires_us;
    int32_t links[KERNEL_KEY_LINK_MAX];
    char type[KERNEL_KEY_TYPE_MAX];
    char restriction_type[KERNEL_KEY_TYPE_MAX];
    char description[KERNEL_KEY_DESCRIPTION_MAX];
    uint8_t payload[KERNEL_KEY_PAYLOAD_MAX];
    kernel_key_watch_t watches[KERNEL_KEY_WATCH_MAX];
} kernel_key_object_t;

typedef struct kernel_key_task_state {
    uint8_t used;
    uint8_t padding[3];
    int32_t tid;
    int32_t tgid;
    int32_t ppid;
    int32_t thread_keyring;
    int32_t session_keyring;
    int32_t request_key_default;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
} kernel_key_task_state_t;

static kernel_key_object_t g_keys[KERNEL_KEY_MAX];
static kernel_key_task_state_t g_key_tasks[KERNEL_KEY_TASK_MAX];
static char g_key_type_scratch[KERNEL_KEY_TYPE_MAX];
static char g_key_description_scratch[KERNEL_KEY_DESCRIPTION_MAX];
static char g_key_callout_scratch[4096u];
static uint8_t g_key_payload_scratch[KERNEL_KEY_PAYLOAD_MAX];
static uint8_t g_key_dh_private[KERNEL_KEY_DH_MAX_BYTES];
static uint8_t g_key_dh_prime[KERNEL_KEY_DH_MAX_BYTES];
static uint8_t g_key_dh_base[KERNEL_KEY_DH_MAX_BYTES];
static uint8_t g_key_dh_secret[KERNEL_KEY_DH_MAX_BYTES];
static uint8_t g_key_kdf_otherinfo[KERNEL_KEY_KDF_MAX_OTHERINFO];
static uint8_t g_key_kdf_output[KERNEL_KEY_KDF_MAX_OUTPUT];
static uint32_t g_key_dh_left[KERNEL_KEY_DH_MAX_LIMBS];
static uint32_t g_key_dh_right[KERNEL_KEY_DH_MAX_LIMBS];
static uint32_t g_key_dh_modulus[KERNEL_KEY_DH_MAX_LIMBS];
static uint32_t g_key_dh_result[KERNEL_KEY_DH_MAX_LIMBS];
static uint32_t g_key_dh_product[KERNEL_KEY_DH_MAX_LIMBS * 2u];
static uint32_t g_key_dh_remainder[KERNEL_KEY_DH_MAX_LIMBS + 1u];
static volatile uint32_t g_key_lock;
static volatile uint32_t g_key_copy_lock;
static int32_t g_next_key_serial = 1;

static int key_permission_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, const kernel_key_object_t *key,
    uint32_t need);

static void key_notify_locked(kernel_key_object_t *key,
                              uint32_t subtype, uint32_t auxiliary) {
#ifdef CONFIG_KEY_NOTIFICATIONS
    uint32_t index;

    if (!key) return;
    for (index = 0; index < KERNEL_KEY_WATCH_MAX; ++index) {
        kernel_key_watch_t *watch = &key->watches[index];
        kernel_key_notification_t notification;

        if (!watch->used) continue;
        if (!watch->pipe ||
            kernel_pipe_generation(watch->pipe) !=
                watch->pipe_generation ||
            !kernel_pipe_notification_mode(watch->pipe)) {
            memset(watch, 0, sizeof(*watch));
            continue;
        }
        notification.type_subtype = 1u | (subtype << 24u);
        notification.info = sizeof(notification) |
            ((uint32_t)watch->watch_id << 8u);
        notification.key_id = (uint32_t)key->serial;
        notification.auxiliary = auxiliary;
        (void)kernel_pipe_watch_notification_post(
            watch->pipe, watch->pipe_generation, &notification,
            sizeof(notification));
    }
#else
    (void)key;
    (void)subtype;
    (void)auxiliary;
#endif
}

#ifdef CONFIG_KEY_NOTIFICATIONS
static void key_notify_removal_locked(kernel_key_object_t *key,
                                      kernel_key_watch_t *watch) {
    kernel_key_removal_notification_t notification;

    if (!key || !watch || !watch->used || !watch->pipe ||
        kernel_pipe_generation(watch->pipe) != watch->pipe_generation ||
        !kernel_pipe_notification_mode(watch->pipe))
        return;
    notification.type_subtype = 0u;
    notification.info = sizeof(notification) |
        ((uint32_t)watch->watch_id << 8u);
    notification.key_id = (uint64_t)(uint32_t)key->serial;
    (void)kernel_pipe_watch_notification_post(
        watch->pipe, watch->pipe_generation, &notification,
        sizeof(notification));
}
#endif

static void key_lock(volatile uint32_t *lock) {
    while (__sync_lock_test_and_set(lock, 1u)) { }
}

static void key_unlock(volatile uint32_t *lock) {
    __sync_lock_release(lock);
}

static int key_copy_user_string(
    const kernel_keyring_user_access_t *access, uint64_t source,
    char *destination, uint32_t capacity, int null_allowed) {
    uint32_t index;
    char value;

    if (!destination || !capacity || !access || !access->copy_from_user)
        return -EDGE_LINUX_EFAULT;
    if (!source) {
        destination[0] = 0;
        return null_allowed ? 0 : -EDGE_LINUX_EFAULT;
    }
    for (index = 0; index < capacity; ++index) {
        if (access->copy_from_user(
                access->context, &value, source + index, 1u) < 0)
            return -EDGE_LINUX_EFAULT;
        destination[index] = value;
        if (!value) return 0;
    }
    destination[capacity - 1u] = 0;
    return -EDGE_LINUX_EINVAL;
}

static enum kernel_key_kind key_kind_from_type(const char *type) {
    if (!type) return 0;
    if (!strcmp(type, "keyring")) return KERNEL_KEY_KIND_KEYRING;
    if (!strcmp(type, "user")) return KERNEL_KEY_KIND_USER;
    if (!strcmp(type, "logon")) return KERNEL_KEY_KIND_LOGON;
    if (!strcmp(type, "big_key")) return KERNEL_KEY_KIND_BIG_KEY;
    return 0;
}

static kernel_key_object_t *key_find_locked(int32_t serial) {
    uint32_t index;
    if (serial <= 0) return 0;
    for (index = 0; index < KERNEL_KEY_MAX; ++index)
        if (g_keys[index].used && !g_keys[index].constructing &&
            g_keys[index].serial == serial)
            return &g_keys[index];
    return 0;
}

static int key_serial_has_task_reference_locked(int32_t serial) {
    uint32_t index;

    if (serial <= 0) return 0;
    for (index = 0; index < KERNEL_KEY_TASK_MAX; ++index) {
        const kernel_key_task_state_t *state = &g_key_tasks[index];
        if (state->used &&
            (state->thread_keyring == serial ||
             state->session_keyring == serial))
            return 1;
    }
    return 0;
}

static int key_serial_has_link_reference_locked(int32_t serial) {
    uint32_t key_index;

    if (serial <= 0) return 0;
    for (key_index = 0; key_index < KERNEL_KEY_MAX; ++key_index) {
        const kernel_key_object_t *ring = &g_keys[key_index];
        uint32_t link_index;

        if (!ring->used || ring->kind != KERNEL_KEY_KIND_KEYRING)
            continue;
        for (link_index = 0; link_index < ring->link_count; ++link_index)
            if (ring->links[link_index] == serial) return 1;
    }
    return 0;
}

static void key_release_unreferenced_locked(int32_t serial,
                                            uint32_t depth) {
    int32_t children[KERNEL_KEY_LINK_MAX];
    kernel_key_object_t *key;
    uint32_t child_count;
    uint32_t index;

    if (depth > KERNEL_KEY_SEARCH_DEPTH_MAX ||
        key_serial_has_task_reference_locked(serial) ||
        key_serial_has_link_reference_locked(serial))
        return;
    key = key_find_locked(serial);
    if (!key) return;
    child_count = key->kind == KERNEL_KEY_KIND_KEYRING ?
        key->link_count : 0u;
    if (child_count)
        memcpy(children, key->links,
               child_count * sizeof(children[0]));
#ifdef CONFIG_KEY_NOTIFICATIONS
    for (index = 0; index < KERNEL_KEY_WATCH_MAX; ++index)
        if (key->watches[index].used)
            key_notify_removal_locked(key, &key->watches[index]);
#endif
    memset(key, 0, sizeof(*key));
    for (index = 0; index < child_count; ++index)
        key_release_unreferenced_locked(children[index], depth + 1u);
}

static int key_is_expired(const kernel_key_object_t *key) {
    return key && key->expires_us &&
           boottime_monotonic_us() >= key->expires_us;
}

static int key_validate(const kernel_key_object_t *key) {
    if (!key || key->invalidated) return -EDGE_LINUX_ENOKEY;
    if (key->revoked) return -EDGE_LINUX_EKEYREVOKED;
    if (key_is_expired(key)) return -EDGE_LINUX_EKEYEXPIRED;
    return 0;
}

static kernel_key_object_t *key_allocate_locked(
    enum kernel_key_kind kind, const char *type, const char *description,
    uint32_t uid, uint32_t gid, uint32_t user_namespace_id,
    uint32_t permissions) {
    uint32_t index;
    kernel_key_object_t *key;

    for (index = 0; index < KERNEL_KEY_MAX; ++index)
        if (!g_keys[index].used) break;
    if (index == KERNEL_KEY_MAX) return 0;
    key = &g_keys[index];
    memset(key, 0, sizeof(*key));
    key->used = 1u;
    key->kind = (uint8_t)kind;
    key->serial = g_next_key_serial++;
    if (g_next_key_serial <= 0) g_next_key_serial = 1;
    key->uid = uid;
    key->gid = gid;
    key->user_namespace_id = user_namespace_id;
    key->permissions = permissions & EDGE_LINUX_KEY_PERM_ALL;
    memcpy(key->type, type, strlen(type) + 1u);
    memcpy(key->description, description, strlen(description) + 1u);
    return key;
}

static kernel_key_task_state_t *key_task_find_locked(int32_t tid) {
    uint32_t index;
    for (index = 0; index < KERNEL_KEY_TASK_MAX; ++index)
        if (g_key_tasks[index].used && g_key_tasks[index].tid == tid)
            return &g_key_tasks[index];
    return 0;
}

static kernel_key_object_t *key_named_keyring_locked(
    uint32_t uid, uint32_t user_namespace_id, const char *description) {
    uint32_t index;
    for (index = 0; index < KERNEL_KEY_MAX; ++index) {
        kernel_key_object_t *key = &g_keys[index];
        if (key->used && !key->constructing && !key->invalidated &&
            key->kind == KERNEL_KEY_KIND_KEYRING && key->uid == uid &&
            key->user_namespace_id == user_namespace_id &&
            !strcmp(key->description, description))
            return key;
    }
    return 0;
}

static kernel_key_object_t *key_create_keyring_locked(
    uint32_t uid, uint32_t gid, uint32_t user_namespace_id,
    const char *description,
    uint32_t permissions) {
    return key_allocate_locked(
        KERNEL_KEY_KIND_KEYRING, "keyring", description, uid, gid,
        user_namespace_id,
        permissions);
}

static kernel_key_object_t *key_user_ring_locked(
    const kernel_linux_identity_t *identity, int session) {
    char name[32];
    uint32_t value;
    uint32_t length = 0;
    kernel_key_object_t *ring;
    const char *prefix = session ? "_uid_ses." : "_uid.";

    memcpy(name, prefix, strlen(prefix));
    length = (uint32_t)strlen(prefix);
    value = identity->uid;
    {
        char digits[10];
        uint32_t count = 0;
        do {
            digits[count++] = (char)('0' + value % 10u);
            value /= 10u;
        } while (value && count < sizeof(digits));
        while (count) name[length++] = digits[--count];
    }
    name[length] = 0;
    ring = key_named_keyring_locked(
        identity->uid, identity->user_namespace_id, name);
    if (ring) return ring;
    return key_create_keyring_locked(
        identity->uid, identity->gid, identity->user_namespace_id, name,
        EDGE_LINUX_KEY_POS_ALL | EDGE_LINUX_KEY_USR_VIEW |
            EDGE_LINUX_KEY_USR_READ | EDGE_LINUX_KEY_USR_LINK);
}

static kernel_key_task_state_t *key_task_get_locked(
    const kernel_linux_identity_t *identity) {
    kernel_key_task_state_t *state;
    kernel_key_object_t *user_session;
    uint32_t index;

    state = key_task_find_locked(identity->global_tid);
    if (state) {
        state->tgid = identity->global_tgid;
        state->ppid = identity->global_ppid;
        state->uid = identity->uid;
        state->euid = identity->euid;
        state->suid = identity->suid;
        state->gid = identity->gid;
        state->egid = identity->egid;
        state->sgid = identity->sgid;
        return state;
    }
    for (index = 0; index < KERNEL_KEY_TASK_MAX; ++index)
        if (!g_key_tasks[index].used) break;
    if (index == KERNEL_KEY_TASK_MAX) return 0;
    state = &g_key_tasks[index];
    memset(state, 0, sizeof(*state));
    state->used = 1u;
    state->tid = identity->global_tid;
    state->tgid = identity->global_tgid;
    state->ppid = identity->global_ppid;
    state->request_key_default = EDGE_LINUX_KEY_REQKEY_DEFL_DEFAULT;
    state->uid = identity->uid;
    state->euid = identity->euid;
    state->suid = identity->suid;
    state->gid = identity->gid;
    state->egid = identity->egid;
    state->sgid = identity->sgid;

    for (index = 0; index < KERNEL_KEY_TASK_MAX; ++index) {
        kernel_key_task_state_t *parent = &g_key_tasks[index];
        if (!parent->used || parent->tgid != identity->global_ppid ||
            !parent->session_keyring)
            continue;
        state->session_keyring = parent->session_keyring;
        return state;
    }
    user_session = key_user_ring_locked(identity, 1);
    if (!user_session) {
        memset(state, 0, sizeof(*state));
        return 0;
    }
    state->session_keyring = user_session->serial;
    return state;
}

static int64_t keyctl_session_to_parent(
    const kernel_linux_identity_t *identity) {
    kernel_linux_identity_t parent_identity;
    kernel_key_task_state_t *state;
    kernel_key_task_state_t *parent_state;
    kernel_key_object_t *session;
    kernel_key_object_t *parent_session;
    int32_t previous_session;
    int64_t result = -EDGE_LINUX_EPERM;

    if (!identity || identity->global_ppid <= 0 ||
        kernel_process_linux_identity(
            identity->global_ppid, &parent_identity) < 0)
        return -EDGE_LINUX_EPERM;
    if (kernel_arch_proc_thread_group_count(parent_identity.global_tgid) !=
            1u ||
        parent_identity.uid != identity->euid ||
        parent_identity.euid != identity->euid ||
        parent_identity.suid != identity->euid ||
        parent_identity.gid != identity->egid ||
        parent_identity.egid != identity->egid ||
        parent_identity.sgid != identity->egid ||
        parent_identity.user_namespace_id != identity->user_namespace_id)
        return -EDGE_LINUX_EPERM;

    key_lock(&g_key_lock);
    state = key_task_get_locked(identity);
    parent_state = key_task_get_locked(&parent_identity);
    if (!state || !parent_state) {
        result = -EDGE_LINUX_ENFILE;
        goto out;
    }
    session = key_find_locked(state->session_keyring);
    parent_session = key_find_locked(parent_state->session_keyring);
    if (!session || session->kind != KERNEL_KEY_KIND_KEYRING ||
        session->uid != identity->euid ||
        (parent_session && parent_session->uid != identity->euid) ||
        key_permission_locked(identity, state, session, 16u) < 0)
        goto out;
    previous_session = parent_state->session_keyring;
    parent_state->session_keyring = session->serial;
    key_release_unreferenced_locked(previous_session, 0u);
    result = 0;
out:
    key_unlock(&g_key_lock);
    return result;
}

static kernel_key_object_t *key_process_ring_locked(
    const kernel_linux_identity_t *identity, int create) {
    char name[32];
    uint32_t length = 6u;
    uint32_t value = (uint32_t)identity->global_tgid;
    kernel_key_object_t *ring;
    char digits[10];
    uint32_t count = 0;

    memcpy(name, "_pid.", 6u);
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count) name[length++] = digits[--count];
    name[length] = 0;
    ring = key_named_keyring_locked(
        identity->uid, identity->user_namespace_id, name);
    if (ring || !create) return ring;
    return key_create_keyring_locked(
        identity->uid, identity->gid, identity->user_namespace_id, name,
        EDGE_LINUX_KEY_POS_ALL | EDGE_LINUX_KEY_USR_VIEW);
}

static kernel_key_object_t *key_thread_ring_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, int create) {
    kernel_key_object_t *ring;
    char name[32];
    uint32_t length = 9u;
    uint32_t value = (uint32_t)identity->global_tid;
    char digits[10];
    uint32_t count = 0;

    if (state->thread_keyring) {
        ring = key_find_locked(state->thread_keyring);
        if (ring) return ring;
        state->thread_keyring = 0;
    }
    if (!create) return 0;
    memcpy(name, "_tid_key.", 9u);
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count) name[length++] = digits[--count];
    name[length] = 0;
    ring = key_create_keyring_locked(
        identity->uid, identity->gid, identity->user_namespace_id, name,
        EDGE_LINUX_KEY_POS_ALL | EDGE_LINUX_KEY_USR_VIEW);
    if (ring) state->thread_keyring = ring->serial;
    return ring;
}

static kernel_key_object_t *key_resolve_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, int32_t serial, int create) {
    kernel_key_object_t *ring;

    if (serial > 0) return key_find_locked(serial);
    switch (serial) {
    case EDGE_LINUX_KEY_SPEC_THREAD_KEYRING:
        return key_thread_ring_locked(identity, state, create);
    case EDGE_LINUX_KEY_SPEC_PROCESS_KEYRING:
        return key_process_ring_locked(identity, create);
    case EDGE_LINUX_KEY_SPEC_SESSION_KEYRING:
        ring = key_find_locked(state->session_keyring);
        if (ring || !create) return ring;
        ring = key_user_ring_locked(identity, 1);
        if (ring) state->session_keyring = ring->serial;
        return ring;
    case EDGE_LINUX_KEY_SPEC_USER_KEYRING:
        return key_user_ring_locked(identity, 0);
    case EDGE_LINUX_KEY_SPEC_USER_SESSION_KEYRING:
        return key_user_ring_locked(identity, 1);
    case EDGE_LINUX_KEY_SPEC_GROUP_KEYRING:
        return 0;
    default:
        return 0;
    }
}

static int key_ring_contains_locked(
    const kernel_key_object_t *ring, int32_t serial, uint32_t depth) {
    uint32_t index;
    if (!ring || ring->kind != KERNEL_KEY_KIND_KEYRING ||
        depth > KERNEL_KEY_SEARCH_DEPTH_MAX)
        return 0;
    for (index = 0; index < ring->link_count; ++index) {
        kernel_key_object_t *child;
        if (ring->links[index] == serial) return 1;
        child = key_find_locked(ring->links[index]);
        if (child && child->kind == KERNEL_KEY_KIND_KEYRING &&
            key_ring_contains_locked(child, serial, depth + 1u))
            return 1;
    }
    return 0;
}

static int key_possessed_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, int32_t serial) {
    kernel_key_object_t *roots[5];
    uint32_t index;

    roots[0] = key_thread_ring_locked(identity, state, 0);
    roots[1] = key_process_ring_locked(identity, 0);
    roots[2] = key_find_locked(state->session_keyring);
    roots[3] = key_user_ring_locked(identity, 0);
    roots[4] = key_user_ring_locked(identity, 1);
    for (index = 0; index < 5u; ++index) {
        if (!roots[index]) continue;
        if (roots[index]->serial == serial ||
            key_ring_contains_locked(roots[index], serial, 0u))
            return 1;
    }
    return 0;
}

static int key_permission_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, const kernel_key_object_t *key,
    uint32_t need) {
    uint32_t granted = key->permissions & EDGE_LINUX_KEY_OTH_ALL;
    if (key->uid == identity->fsuid)
        granted |= (key->permissions >> 16u) & EDGE_LINUX_KEY_OTH_ALL;
    else if (key->gid == identity->fsgid)
        granted |= (key->permissions >> 8u) & EDGE_LINUX_KEY_OTH_ALL;
    if (key_possessed_locked(identity, state, key->serial))
        granted |= (key->permissions >> 24u) & EDGE_LINUX_KEY_OTH_ALL;
    return (granted & need) == need ? 0 : -EDGE_LINUX_EACCES;
}

typedef struct kernel_keyctl_dh_params {
    int32_t private_key;
    int32_t prime;
    int32_t base;
} kernel_keyctl_dh_params_t;

typedef struct kernel_keyctl_kdf_params {
    uint64_t hash_name;
    uint64_t other_info;
    uint32_t other_info_length;
    uint32_t spare[8];
    uint32_t padding;
} kernel_keyctl_kdf_params_t;

typedef struct kernel_keyctl_kdf_params32 {
    uint32_t hash_name;
    uint32_t other_info;
    uint32_t other_info_length;
    uint32_t spare[8];
} kernel_keyctl_kdf_params32_t;

_Static_assert(sizeof(kernel_keyctl_kdf_params_t) == 56u,
               "native keyctl KDF parameters must match Linux UAPI");
_Static_assert(sizeof(kernel_keyctl_kdf_params32_t) == 44u,
               "compat keyctl KDF parameters must match Linux UAPI");

static int key_dh_compare(const uint32_t *left, const uint32_t *right,
                          uint32_t limbs) {
    while (limbs) {
        --limbs;
        if (left[limbs] < right[limbs]) return -1;
        if (left[limbs] > right[limbs]) return 1;
    }
    return 0;
}

static void key_dh_subtract(uint32_t *left, const uint32_t *right,
                            uint32_t limbs) {
    uint64_t borrow = 0u;

    for (uint32_t index = 0; index < limbs; ++index) {
        uint64_t value = (uint64_t)right[index] + borrow;
        uint64_t original = left[index];

        left[index] = (uint32_t)(original - value);
        borrow = original < value;
    }
}

static void key_dh_load(const uint8_t *bytes, uint32_t length,
                        uint32_t *limbs, uint32_t count) {
    memset(limbs, 0, count * sizeof(limbs[0]));
    for (uint32_t offset = 0; offset < length; ++offset) {
        uint32_t reverse = length - 1u - offset;
        limbs[offset / 4u] |=
            (uint32_t)bytes[reverse] << ((offset % 4u) * 8u);
    }
}

static void key_dh_reduce_product(const uint32_t *product,
                                  uint32_t product_limbs,
                                  const uint32_t *modulus,
                                  uint32_t modulus_limbs,
                                  uint32_t *result) {
    uint32_t bits = product_limbs * 32u;

    memset(g_key_dh_remainder, 0, sizeof(g_key_dh_remainder));
    while (bits) {
        uint32_t carry = 0u;

        --bits;
        for (uint32_t index = 0; index <= modulus_limbs; ++index) {
            uint32_t next = g_key_dh_remainder[index] >> 31u;
            g_key_dh_remainder[index] =
                (g_key_dh_remainder[index] << 1u) | carry;
            carry = next;
        }
        g_key_dh_remainder[0] |=
            (product[bits / 32u] >> (bits % 32u)) & 1u;
        if (g_key_dh_remainder[modulus_limbs] ||
            key_dh_compare(g_key_dh_remainder, modulus,
                           modulus_limbs) >= 0) {
            key_dh_subtract(g_key_dh_remainder, modulus,
                            modulus_limbs);
            g_key_dh_remainder[modulus_limbs] = 0u;
        }
    }
    memcpy(result, g_key_dh_remainder,
           modulus_limbs * sizeof(result[0]));
}

static void key_dh_multiply_mod(const uint32_t *left,
                                const uint32_t *right,
                                const uint32_t *modulus,
                                uint32_t limbs, uint32_t *result) {
    memset(g_key_dh_product, 0, sizeof(g_key_dh_product));
    for (uint32_t left_index = 0; left_index < limbs; ++left_index) {
        uint64_t carry = 0u;

        for (uint32_t right_index = 0; right_index < limbs;
             ++right_index) {
            uint32_t target = left_index + right_index;
            uint64_t value = (uint64_t)left[left_index] *
                                 right[right_index] +
                             g_key_dh_product[target] + carry;

            g_key_dh_product[target] = (uint32_t)value;
            carry = value >> 32u;
        }
        for (uint32_t target = left_index + limbs;
             carry && target < limbs * 2u; ++target) {
            uint64_t value = (uint64_t)g_key_dh_product[target] + carry;
            g_key_dh_product[target] = (uint32_t)value;
            carry = value >> 32u;
        }
    }
    key_dh_reduce_product(g_key_dh_product, limbs * 2u, modulus,
                          limbs, result);
}

static int key_dh_payload_locked(
        const kernel_linux_identity_t *identity,
        kernel_key_task_state_t *state, int32_t serial,
        uint8_t *destination, uint32_t *length) {
    kernel_key_object_t *key = key_find_locked(serial);

    if (!key || key_permission_locked(identity, state, key, 2u) < 0)
        return -EDGE_LINUX_ENOKEY;
    if (key_validate(key) < 0) return -EDGE_LINUX_ENOKEY;
    if (key->kind != KERNEL_KEY_KIND_USER)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (!key->payload_length) return -EDGE_LINUX_EINVAL;
    if (key->payload_length > KERNEL_KEY_DH_MAX_BYTES)
        return -EDGE_LINUX_EMSGSIZE;
    memcpy(destination, key->payload, key->payload_length);
    *length = key->payload_length;
    return 0;
}

static int64_t keyctl_dh_compute(
        const kernel_linux_identity_t *identity,
        const kernel_keyring_user_access_t *access,
        const uint64_t arguments[4]) {
    kernel_keyctl_dh_params_t parameters;
    kernel_keyctl_kdf_params_t kdf;
    char hash_name[KERNEL_KEY_KDF_HASH_NAME_MAX];
    kernel_key_task_state_t *state;
    uint32_t private_length = 0u;
    uint32_t prime_length = 0u;
    uint32_t base_length = 0u;
    uint32_t output_length;
    uint32_t limbs;
    uint32_t base_limbs;
    uint32_t exponent_bits;
    uint32_t digest_length = 32u;
    uint32_t digest_algorithm = 256u;
    int use_kdf = arguments[3] != 0u;
    int result;

    if (use_kdf) {
        if (access->keyctl_kdf_pointer_size == sizeof(uint32_t)) {
            kernel_keyctl_kdf_params32_t compat_kdf;

            if (!access->copy_from_user ||
                access->copy_from_user(
                    access->context, &compat_kdf,
                    arguments[3], sizeof(compat_kdf)) < 0)
                return -EDGE_LINUX_EFAULT;
            memset(&kdf, 0, sizeof(kdf));
            kdf.hash_name = compat_kdf.hash_name;
            kdf.other_info = compat_kdf.other_info;
            kdf.other_info_length = compat_kdf.other_info_length;
            memcpy(kdf.spare, compat_kdf.spare, sizeof(kdf.spare));
        } else if (!access->copy_from_user ||
                   access->copy_from_user(
                       access->context, &kdf, arguments[3],
                       sizeof(kdf)) < 0) {
            return -EDGE_LINUX_EFAULT;
        }
    } else {
        memset(&kdf, 0, sizeof(kdf));
    }
    if (!arguments[0] || (!arguments[1] && arguments[2]))
        return -EDGE_LINUX_EINVAL;
    if (!access->copy_from_user ||
        access->copy_from_user(access->context, &parameters,
                               arguments[0], sizeof(parameters)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (use_kdf) {
        for (uint32_t index = 0; index < 8u; ++index)
            if (kdf.spare[index]) return -EDGE_LINUX_EINVAL;
        if (arguments[2] > KERNEL_KEY_KDF_MAX_OUTPUT ||
            kdf.other_info_length > KERNEL_KEY_KDF_MAX_OTHERINFO)
            return -EDGE_LINUX_EMSGSIZE;
        result = key_copy_user_string(
            access, kdf.hash_name, hash_name, sizeof(hash_name), 0);
        if (result < 0) return result;
        if (!strcmp(hash_name, "sha1")) {
            digest_algorithm = 1u;
            digest_length = 20u;
        } else if (!strcmp(hash_name, "sha224")) {
            digest_algorithm = 224u;
            digest_length = 28u;
        } else if (!strcmp(hash_name, "sha256")) {
            digest_algorithm = 256u;
        } else if (!strcmp(hash_name, "sha384")) {
            digest_algorithm = 384u;
            digest_length = 48u;
        } else if (!strcmp(hash_name, "sha512")) {
            digest_algorithm = 512u;
            digest_length = 64u;
        } else {
            return -EDGE_LINUX_ENOENT;
        }
    }

    key_lock(&g_key_copy_lock);
    key_lock(&g_key_lock);
    state = key_task_get_locked(identity);
    if (!state) {
        result = -EDGE_LINUX_ENFILE;
        goto out_unlock_keys;
    }
    result = key_dh_payload_locked(
        identity, state, parameters.private_key, g_key_dh_private,
        &private_length);
    if (result < 0) goto out_unlock_keys;
    result = key_dh_payload_locked(
        identity, state, parameters.prime, g_key_dh_prime,
        &prime_length);
    if (result < 0) goto out_unlock_keys;
    result = key_dh_payload_locked(
        identity, state, parameters.base, g_key_dh_base,
        &base_length);
    if (result < 0) goto out_unlock_keys;
    key_unlock(&g_key_lock);

    if (private_length > prime_length || base_length > prime_length) {
        result = -EDGE_LINUX_EINVAL;
        goto out_unlock_copy;
    }

    limbs = (prime_length + 3u) / 4u;
    output_length = (prime_length + 7u) & ~7u;
    key_dh_load(g_key_dh_prime, prime_length, g_key_dh_modulus, limbs);
    if (!limbs ||
        (limbs == 1u && g_key_dh_modulus[0] <= 1u)) {
        result = -EDGE_LINUX_EINVAL;
        goto out_unlock_copy;
    }
    if (!use_kdf && !arguments[2]) {
        result = (int)output_length;
        goto out_unlock_copy;
    }
    if (!use_kdf && arguments[2] < output_length) {
        result = -EDGE_LINUX_EOVERFLOW;
        goto out_unlock_copy;
    }

    base_limbs = (base_length + 3u) / 4u;
    key_dh_load(g_key_dh_base, base_length, g_key_dh_product,
                KERNEL_KEY_DH_MAX_LIMBS * 2u);
    key_dh_reduce_product(g_key_dh_product, base_limbs,
                          g_key_dh_modulus, limbs, g_key_dh_right);
    memset(g_key_dh_left, 0, limbs * sizeof(g_key_dh_left[0]));
    g_key_dh_left[0] = 1u;
    if (key_dh_compare(g_key_dh_left, g_key_dh_modulus, limbs) >= 0)
        key_dh_subtract(g_key_dh_left, g_key_dh_modulus, limbs);

    exponent_bits = private_length * 8u;
    for (uint32_t bit = 0; bit < exponent_bits; ++bit) {
        key_dh_multiply_mod(g_key_dh_left, g_key_dh_left,
                            g_key_dh_modulus, limbs, g_key_dh_result);
        memcpy(g_key_dh_left, g_key_dh_result,
               limbs * sizeof(g_key_dh_left[0]));
        if ((g_key_dh_private[bit / 8u] >>
             (7u - bit % 8u)) & 1u) {
            key_dh_multiply_mod(g_key_dh_left, g_key_dh_right,
                                g_key_dh_modulus, limbs,
                                g_key_dh_result);
            memcpy(g_key_dh_left, g_key_dh_result,
                   limbs * sizeof(g_key_dh_left[0]));
        }
    }

    memset(g_key_dh_secret, 0, output_length);
    for (uint32_t offset = 0; offset < prime_length; ++offset) {
        uint32_t reverse = output_length - 1u - offset;
        g_key_dh_secret[reverse] =
            (uint8_t)(g_key_dh_left[offset / 4u] >>
                      ((offset % 4u) * 8u));
    }
    if (use_kdf) {
        uint32_t produced = 0u;
        uint32_t counter = 1u;

        if (kdf.other_info_length &&
            (!kdf.other_info || !access->copy_from_user ||
             access->copy_from_user(
                 access->context, g_key_kdf_otherinfo,
                 kdf.other_info, kdf.other_info_length) < 0)) {
            result = -EDGE_LINUX_EFAULT;
            goto out_unlock_copy;
        }
        while (produced < arguments[2]) {
            uint8_t digest[64];
            uint8_t encoded_counter[4] = {
                (uint8_t)(counter >> 24u),
                (uint8_t)(counter >> 16u),
                (uint8_t)(counter >> 8u),
                (uint8_t)counter,
            };
            uint32_t copy = (uint32_t)arguments[2] - produced;

            if (copy > digest_length) copy = digest_length;
            if (digest_algorithm == 1u) {
                kernel_sha1_context_t hash;

                kernel_sha1_init(&hash);
                kernel_sha1_update(
                    &hash, encoded_counter, sizeof(encoded_counter));
                kernel_sha1_update(
                    &hash, g_key_dh_secret, output_length);
                kernel_sha1_update(
                    &hash, g_key_kdf_otherinfo,
                    kdf.other_info_length);
                kernel_sha1_final(&hash, digest);
            } else if (digest_algorithm == 224u ||
                       digest_algorithm == 256u) {
                kernel_sha256_context_t hash;

                if (digest_algorithm == 224u)
                    kernel_sha224_init(&hash);
                else
                    kernel_sha256_init(&hash);
                kernel_sha256_update(
                    &hash, encoded_counter, sizeof(encoded_counter));
                kernel_sha256_update(
                    &hash, g_key_dh_secret, output_length);
                kernel_sha256_update(
                    &hash, g_key_kdf_otherinfo,
                    kdf.other_info_length);
                if (digest_algorithm == 224u)
                    kernel_sha224_final(&hash, digest);
                else
                    kernel_sha256_final(&hash, digest);
            } else {
                kernel_sha512_context_t hash;

                if (digest_algorithm == 384u)
                    kernel_sha384_init(&hash);
                else
                    kernel_sha512_init(&hash);
                kernel_sha512_update(
                    &hash, encoded_counter, sizeof(encoded_counter));
                kernel_sha512_update(
                    &hash, g_key_dh_secret, output_length);
                kernel_sha512_update(
                    &hash, g_key_kdf_otherinfo,
                    kdf.other_info_length);
                if (digest_algorithm == 384u)
                    kernel_sha384_final(&hash, digest);
                else
                    kernel_sha512_final(&hash, digest);
            }
            memcpy(g_key_kdf_output + produced, digest, copy);
            memset(digest, 0, sizeof(digest));
            produced += copy;
            ++counter;
        }
        if (arguments[2] &&
            (!access->copy_to_user ||
             access->copy_to_user(
                 access->context, arguments[1], g_key_kdf_output,
                 (uint32_t)arguments[2]) < 0))
            result = -EDGE_LINUX_EFAULT;
        else
            result = (int)arguments[2];
        goto out_unlock_copy;
    }
    if (!access->copy_to_user ||
        access->copy_to_user(access->context, arguments[1],
                             g_key_dh_secret, output_length) < 0)
        result = -EDGE_LINUX_EFAULT;
    else
        result = (int)output_length;
    goto out_unlock_copy;

out_unlock_keys:
    key_unlock(&g_key_lock);
out_unlock_copy:
    memset(g_key_dh_private, 0, private_length);
    memset(g_key_dh_secret, 0, sizeof(g_key_dh_secret));
    memset(g_key_kdf_otherinfo, 0, sizeof(g_key_kdf_otherinfo));
    memset(g_key_kdf_output, 0, sizeof(g_key_kdf_output));
    memset(g_key_dh_left, 0, sizeof(g_key_dh_left));
    memset(g_key_dh_right, 0, sizeof(g_key_dh_right));
    memset(g_key_dh_result, 0, sizeof(g_key_dh_result));
    memset(g_key_dh_product, 0, sizeof(g_key_dh_product));
    memset(g_key_dh_remainder, 0, sizeof(g_key_dh_remainder));
    key_unlock(&g_key_copy_lock);
    return result;
}

static int key_link_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, kernel_key_object_t *key,
    kernel_key_object_t *ring, int exclusive) {
    uint32_t index;
    int result;

    if (!key || !ring || ring->kind != KERNEL_KEY_KIND_KEYRING)
        return -EDGE_LINUX_ENOTDIR;
    result = key_validate(key);
    if (result < 0) return result;
    result = key_validate(ring);
    if (result < 0) return result;
    if (key_permission_locked(identity, state, ring, 4u) < 0 ||
        key_permission_locked(identity, state, key, 16u) < 0)
        return -EDGE_LINUX_EACCES;
    if (ring->reject_links ||
        (ring->restriction_set &&
         strcmp(ring->restriction_type, key->type)))
        return -EDGE_LINUX_EPERM;
    if (key->kind == KERNEL_KEY_KIND_KEYRING &&
        (key->serial == ring->serial ||
         key_ring_contains_locked(key, ring->serial, 0u)))
        return -EDGE_LINUX_EDEADLK;
    for (index = 0; index < ring->link_count; ++index) {
        if (ring->links[index] != key->serial) continue;
        return exclusive ? -EDGE_LINUX_EEXIST : 0;
    }
    if (ring->link_count >= KERNEL_KEY_LINK_MAX)
        return -EDGE_LINUX_ENFILE;
    ring->links[ring->link_count++] = key->serial;
    key_notify_locked(
        ring, KERNEL_KEY_NOTIFY_LINKED, (uint32_t)key->serial);
    return 0;
}

static int key_link_created_locked(kernel_key_object_t *key,
                                   kernel_key_object_t *ring) {
    if (!key || !ring || ring->kind != KERNEL_KEY_KIND_KEYRING)
        return -EDGE_LINUX_ENOTDIR;
    if (ring->reject_links ||
        (ring->restriction_set &&
         strcmp(ring->restriction_type, key->type)))
        return -EDGE_LINUX_EPERM;
    if (ring->link_count >= KERNEL_KEY_LINK_MAX)
        return -EDGE_LINUX_ENFILE;
    ring->links[ring->link_count++] = key->serial;
    key_notify_locked(
        ring, KERNEL_KEY_NOTIFY_LINKED, (uint32_t)key->serial);
    return 0;
}

static int key_unlink_locked(kernel_key_object_t *key,
                             kernel_key_object_t *ring) {
    uint32_t index;
    if (!key || !ring || ring->kind != KERNEL_KEY_KIND_KEYRING)
        return -EDGE_LINUX_ENOTDIR;
    for (index = 0; index < ring->link_count; ++index) {
        if (ring->links[index] != key->serial) continue;
        --ring->link_count;
        memmove(&ring->links[index], &ring->links[index + 1u],
                (ring->link_count - index) * sizeof(ring->links[0]));
        key_notify_locked(
            ring, KERNEL_KEY_NOTIFY_UNLINKED, (uint32_t)key->serial);
        return 0;
    }
    return -EDGE_LINUX_ENOENT;
}

static kernel_key_object_t *key_search_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, kernel_key_object_t *ring,
    const char *type, const char *description, uint32_t depth) {
    uint32_t index;
    if (!ring || ring->kind != KERNEL_KEY_KIND_KEYRING ||
        depth > KERNEL_KEY_SEARCH_DEPTH_MAX ||
        key_permission_locked(identity, state, ring, 8u) < 0)
        return 0;
    for (index = 0; index < ring->link_count; ++index) {
        kernel_key_object_t *key = key_find_locked(ring->links[index]);
        if (!key || key_validate(key) < 0) continue;
        if (!strcmp(key->type, type) &&
            !strcmp(key->description, description) &&
            key_permission_locked(identity, state, key, 8u) == 0)
            return key;
    }
    for (index = 0; index < ring->link_count; ++index) {
        kernel_key_object_t *key = key_find_locked(ring->links[index]);
        kernel_key_object_t *found;
        if (!key || key->kind != KERNEL_KEY_KIND_KEYRING) continue;
        found = key_search_locked(
            identity, state, key, type, description, depth + 1u);
        if (found) return found;
    }
    return 0;
}

static uint32_t key_append_decimal(char *buffer, uint32_t offset,
                                   uint32_t value) {
    char digits[10];
    uint32_t count = 0;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count) buffer[offset++] = digits[--count];
    return offset;
}

static uint32_t key_append_hex8(char *buffer, uint32_t offset,
                                uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    for (int shift = 28; shift >= 0; shift -= 4)
        buffer[offset++] = digits[(value >> (uint32_t)shift) & 0xfu];
    return offset;
}

static uint32_t key_describe(const kernel_key_object_t *key, char *buffer) {
    uint32_t offset = 0;
    uint32_t length;
    length = (uint32_t)strlen(key->type);
    memcpy(buffer + offset, key->type, length);
    offset += length;
    buffer[offset++] = ';';
    offset = key_append_decimal(buffer, offset, key->uid);
    buffer[offset++] = ';';
    offset = key_append_decimal(buffer, offset, key->gid);
    buffer[offset++] = ';';
    offset = key_append_hex8(buffer, offset, key->permissions);
    buffer[offset++] = ';';
    length = (uint32_t)strlen(key->description);
    memcpy(buffer + offset, key->description, length);
    offset += length;
    buffer[offset++] = 0;
    return offset;
}

static int key_copy_result(
    const kernel_keyring_user_access_t *access, uint64_t destination,
    uint64_t capacity, const void *source, uint32_t required) {
    uint32_t copy = capacity < required ? (uint32_t)capacity : required;
    if (copy && (!destination || !access || !access->copy_to_user ||
                 access->copy_to_user(
                     access->context, destination, source, copy) < 0))
        return -EDGE_LINUX_EFAULT;
    return (int)required;
}

static int key_prepare_strings(
    const kernel_keyring_user_access_t *access,
    uint64_t type_user, uint64_t description_user,
    int description_null_allowed) {
    int result;
    key_lock(&g_key_copy_lock);
    result = key_copy_user_string(
        access, type_user, g_key_type_scratch,
        sizeof(g_key_type_scratch), 0);
    if (result < 0) goto out;
    if (!g_key_type_scratch[0]) {
        result = -EDGE_LINUX_EINVAL;
        goto out;
    }
    if (g_key_type_scratch[0] == '.') {
        result = -EDGE_LINUX_EPERM;
        goto out;
    }
    result = key_copy_user_string(
        access, description_user, g_key_description_scratch,
        sizeof(g_key_description_scratch), description_null_allowed);
out:
    if (result < 0) key_unlock(&g_key_copy_lock);
    return result;
}

int64_t kernel_keyring_add_key(
    const kernel_linux_identity_t *identity,
    const kernel_keyring_user_access_t *access,
    uint64_t type, uint64_t description, uint64_t payload,
    uint64_t payload_length, int32_t keyring_serial) {
    enum kernel_key_kind kind;
    kernel_key_task_state_t *state;
    kernel_key_object_t *ring;
    kernel_key_object_t *key = 0;
    uint32_t index;
    int result;

    if (!identity || !access) return -EDGE_LINUX_ESRCH;
    if (payload_length > 1024u * 1024u - 1u)
        return -EDGE_LINUX_EINVAL;
    if (payload_length > KERNEL_KEY_PAYLOAD_MAX)
        return -EDGE_LINUX_ENOMEM;
    result = key_prepare_strings(access, type, description, 1);
    if (result < 0) return result;
    kind = key_kind_from_type(g_key_type_scratch);
    if (!kind) {
        key_unlock(&g_key_copy_lock);
        return -EDGE_LINUX_ENODEV;
    }
    if (!g_key_description_scratch[0] ||
        (kind == KERNEL_KEY_KIND_KEYRING &&
         g_key_description_scratch[0] == '.')) {
        key_unlock(&g_key_copy_lock);
        return kind == KERNEL_KEY_KIND_KEYRING ?
            -EDGE_LINUX_EPERM : -EDGE_LINUX_EINVAL;
    }
    if (payload_length && (!payload || !access->copy_from_user ||
        access->copy_from_user(access->context, g_key_payload_scratch,
                               payload, payload_length) < 0)) {
        key_unlock(&g_key_copy_lock);
        return -EDGE_LINUX_EFAULT;
    }

    key_lock(&g_key_lock);
    state = key_task_get_locked(identity);
    ring = state ? key_resolve_locked(
        identity, state, keyring_serial, 1) : 0;
    if (!state) result = -EDGE_LINUX_ENFILE;
    else if (!ring) result = keyring_serial == EDGE_LINUX_KEY_SPEC_GROUP_KEYRING ?
        -EDGE_LINUX_EINVAL : -EDGE_LINUX_ENOKEY;
    else if (ring->kind != KERNEL_KEY_KIND_KEYRING)
        result = -EDGE_LINUX_ENOTDIR;
    else if (key_permission_locked(identity, state, ring, 4u) < 0)
        result = -EDGE_LINUX_EACCES;
    else {
        result = 0;
        for (index = 0; index < ring->link_count; ++index) {
            kernel_key_object_t *candidate =
                key_find_locked(ring->links[index]);
            if (candidate && !strcmp(candidate->type, g_key_type_scratch) &&
                !strcmp(candidate->description,
                        g_key_description_scratch)) {
                key = candidate;
                break;
            }
        }
        if (key) {
            if (key_permission_locked(identity, state, key, 4u) < 0)
                result = -EDGE_LINUX_EACCES;
        } else {
            {
                uint32_t permissions =
                    EDGE_LINUX_KEY_POS_VIEW | EDGE_LINUX_KEY_POS_SEARCH |
                    EDGE_LINUX_KEY_POS_LINK | EDGE_LINUX_KEY_POS_SETATTR |
                    EDGE_LINUX_KEY_POS_WRITE | EDGE_LINUX_KEY_USR_VIEW;
                if (kind != KERNEL_KEY_KIND_LOGON)
                    permissions |= EDGE_LINUX_KEY_POS_READ;
                key = key_allocate_locked(
                kind, g_key_type_scratch, g_key_description_scratch,
                identity->fsuid, identity->fsgid,
                identity->user_namespace_id, permissions);
            }
            if (!key) result = -EDGE_LINUX_EDQUOT;
            else {
                result = key_link_created_locked(key, ring);
                if (result < 0) memset(key, 0, sizeof(*key));
            }
        }
        if (result == 0 && key) {
            key->payload_length = (uint32_t)payload_length;
            if (payload_length)
                memcpy(key->payload, g_key_payload_scratch,
                       (uint32_t)payload_length);
            key_notify_locked(key, KERNEL_KEY_NOTIFY_UPDATED, 0u);
            result = key->serial;
        }
    }
    key_unlock(&g_key_lock);
    key_unlock(&g_key_copy_lock);
    return result;
}

int64_t kernel_keyring_request_key(
    const kernel_linux_identity_t *identity,
    const kernel_keyring_user_access_t *access,
    uint64_t type, uint64_t description, uint64_t callout,
    int32_t destination_keyring) {
    kernel_key_task_state_t *state;
    kernel_key_object_t *roots[5];
    kernel_key_object_t *found = 0;
    kernel_key_object_t *destination = 0;
    int result;

    if (!identity || !access) return -EDGE_LINUX_ESRCH;
    result = key_prepare_strings(access, type, description, 0);
    if (result < 0) return result;
    if (!key_kind_from_type(g_key_type_scratch)) {
        key_unlock(&g_key_copy_lock);
        return -EDGE_LINUX_ENODEV;
    }
    if (callout) {
        result = key_copy_user_string(
            access, callout, g_key_callout_scratch,
            sizeof(g_key_callout_scratch), 1);
        if (result < 0) {
            key_unlock(&g_key_copy_lock);
            return result;
        }
    }

    key_lock(&g_key_lock);
    state = key_task_get_locked(identity);
    if (!state) {
        result = -EDGE_LINUX_ENFILE;
        goto out;
    }
    roots[0] = key_thread_ring_locked(identity, state, 0);
    roots[1] = key_process_ring_locked(identity, 0);
    roots[2] = key_find_locked(state->session_keyring);
    roots[3] = key_user_ring_locked(identity, 1);
    roots[4] = key_user_ring_locked(identity, 0);
    for (uint32_t index = 0; index < 5u && !found; ++index)
        found = key_search_locked(
            identity, state, roots[index], g_key_type_scratch,
            g_key_description_scratch, 0u);
    if (!found) {
        result = -EDGE_LINUX_ENOKEY;
        goto out;
    }
    if (destination_keyring) {
        destination = key_resolve_locked(
            identity, state, destination_keyring, 1);
        if (!destination) {
            result = -EDGE_LINUX_ENOKEY;
            goto out;
        }
        result = key_link_locked(identity, state, found, destination, 0);
        if (result < 0) goto out;
    }
    result = found->serial;
out:
    key_unlock(&g_key_lock);
    key_unlock(&g_key_copy_lock);
    return result;
}

static int64_t keyctl_get_keyring_id_locked(
    const kernel_linux_identity_t *identity,
    kernel_key_task_state_t *state, int32_t serial, int create) {
    kernel_key_object_t *ring = key_resolve_locked(
        identity, state, serial, create != 0);
    if (!ring) {
        if (serial == EDGE_LINUX_KEY_SPEC_GROUP_KEYRING)
            return -EDGE_LINUX_EINVAL;
        return serial < 0 && !create ? 0 : -EDGE_LINUX_ENOKEY;
    }
    if (ring->kind != KERNEL_KEY_KIND_KEYRING)
        return -EDGE_LINUX_ENOTDIR;
    if (key_permission_locked(identity, state, ring, 8u) < 0)
        return -EDGE_LINUX_EACCES;
    return ring->serial;
}

static int64_t keyctl_watch_key_locked(
        const kernel_linux_identity_t *identity,
        kernel_key_task_state_t *state, kernel_key_object_t *key,
        int32_t descriptor, int32_t watch_id) {
#ifndef CONFIG_KEY_NOTIFICATIONS
    (void)identity;
    (void)state;
    (void)key;
    (void)descriptor;
    (void)watch_id;
    return -EDGE_LINUX_EOPNOTSUPP;
#else
    kernel_vfs_descriptor_t description;
    uint64_t generation;
    uint32_t index;
    int result;

    if (watch_id < -1 || watch_id > 255)
        return -EDGE_LINUX_EINVAL;
    if (!key) return -EDGE_LINUX_ENOKEY;
    result = key_permission_locked(identity, state, key, 1u);
    if (result < 0) return result;
    result = kernel_vfs_describe_descriptor(descriptor, &description);
    if (result < 0 || description.kind != KERNEL_VFS_DESCRIPTOR_PIPE ||
        !description.pipe ||
        !kernel_pipe_notification_mode(description.pipe))
        return -EDGE_LINUX_EINVAL;
    generation = kernel_pipe_generation(description.pipe);
    if (!generation) return -EDGE_LINUX_EINVAL;

    for (index = 0; index < KERNEL_KEY_WATCH_MAX; ++index) {
        kernel_key_watch_t *watch = &key->watches[index];

        if (!watch->used) continue;
        if (!watch->pipe ||
            kernel_pipe_generation(watch->pipe) !=
                watch->pipe_generation ||
            !kernel_pipe_notification_mode(watch->pipe)) {
            memset(watch, 0, sizeof(*watch));
            continue;
        }
        if (watch->pipe != description.pipe ||
            watch->pipe_generation != generation)
            continue;
        if (watch_id >= 0) return -EDGE_LINUX_EBUSY;
        key_notify_removal_locked(key, watch);
        memset(watch, 0, sizeof(*watch));
        return 0;
    }
    if (watch_id < 0) return -EDGE_LINUX_EBADSLT;
    for (index = 0; index < KERNEL_KEY_WATCH_MAX; ++index) {
        kernel_key_watch_t *watch = &key->watches[index];

        if (watch->used) continue;
        watch->used = 1u;
        watch->watch_id = (uint8_t)watch_id;
        watch->pipe = description.pipe;
        watch->pipe_generation = generation;
        return 0;
    }
    return -EDGE_LINUX_ENOMEM;
#endif
}

int64_t kernel_keyring_keyctl(
    const kernel_linux_identity_t *identity,
    const kernel_keyring_user_access_t *access,
    uint32_t command, const uint64_t arguments[4]) {
    kernel_key_task_state_t *state;
    kernel_key_object_t *key;
    kernel_key_object_t *ring;
    kernel_key_object_t *other;
    char output[KERNEL_KEY_DESCRIPTION_MAX + 96u];
    int32_t serials[KERNEL_KEY_LINK_MAX];
    uint32_t length;
    int64_t result = -EDGE_LINUX_EOPNOTSUPP;

    if (!identity || !access || !arguments) return -EDGE_LINUX_EINVAL;
    if (command == EDGE_LINUX_KEYCTL_SESSION_TO_PARENT)
        return keyctl_session_to_parent(identity);
    if (command == EDGE_LINUX_KEYCTL_ASSUME_AUTHORITY) {
        int32_t serial = (int32_t)arguments[0];

        if (serial < 0) return -EDGE_LINUX_EINVAL;
        return serial ? -EDGE_LINUX_ENOKEY : 0;
    }
    if (command == EDGE_LINUX_KEYCTL_INSTANTIATE) {
        if (arguments[2] > 1024u * 1024u - 1u)
            return -EDGE_LINUX_EINVAL;
        return -EDGE_LINUX_EPERM;
    }
    if (command == EDGE_LINUX_KEYCTL_INSTANTIATE_IOV) {
        uint64_t total = 0u;
        uint32_t count = (uint32_t)arguments[2];

        if (arguments[2] != count || count > KERNEL_KEY_IOV_MAX)
            return -EDGE_LINUX_EINVAL;
        if (!arguments[1]) count = 0u;
        for (uint32_t index = 0; index < count; ++index) {
            kernel_key_user_iovec_t vector;

            if (access->iovec_pointer_size == sizeof(uint32_t)) {
                kernel_key_user_iovec32_t compat_vector;

                if (!access->copy_from_user ||
                    access->copy_from_user(
                        access->context, &compat_vector,
                        arguments[1] +
                            (uint64_t)index * sizeof(compat_vector),
                        sizeof(compat_vector)) < 0)
                    return -EDGE_LINUX_EFAULT;
                vector.base = compat_vector.base;
                vector.length = compat_vector.length;
            } else if (!access->copy_from_user ||
                       access->copy_from_user(
                           access->context, &vector,
                           arguments[1] +
                               (uint64_t)index * sizeof(vector),
                           sizeof(vector)) < 0) {
                return -EDGE_LINUX_EFAULT;
            }
            if (vector.length > UINT64_MAX - total)
                return -EDGE_LINUX_EINVAL;
            total += vector.length;
        }
        if (total > 1024u * 1024u - 1u)
            return -EDGE_LINUX_EINVAL;
        return -EDGE_LINUX_EPERM;
    }
    if (command == EDGE_LINUX_KEYCTL_NEGATE)
        return -EDGE_LINUX_EPERM;
    if (command == EDGE_LINUX_KEYCTL_REJECT) {
        uint32_t error = (uint32_t)arguments[2];

        if (!error || error >= 4095u || error == 512u ||
            error == 513u || error == 514u || error == 516u)
            return -EDGE_LINUX_EINVAL;
        return -EDGE_LINUX_EPERM;
    }
    if (command == EDGE_LINUX_KEYCTL_DH_COMPUTE)
        return keyctl_dh_compute(identity, access, arguments);
    if (command == EDGE_LINUX_KEYCTL_PKEY_QUERY ||
        command == EDGE_LINUX_KEYCTL_PKEY_ENCRYPT ||
        command == EDGE_LINUX_KEYCTL_PKEY_DECRYPT ||
        command == EDGE_LINUX_KEYCTL_PKEY_SIGN ||
        command == EDGE_LINUX_KEYCTL_PKEY_VERIFY)
        return -EDGE_LINUX_EOPNOTSUPP;
    key_lock(&g_key_lock);
    state = key_task_get_locked(identity);
    if (!state) {
        key_unlock(&g_key_lock);
        return -EDGE_LINUX_ENFILE;
    }

    if (command == EDGE_LINUX_KEYCTL_GET_KEYRING_ID) {
        result = keyctl_get_keyring_id_locked(
            identity, state, (int32_t)arguments[0],
            (int)arguments[1]);
        goto out;
    }
    if (command == EDGE_LINUX_KEYCTL_JOIN_SESSION_KEYRING) {
        int32_t previous_session;

        key_unlock(&g_key_lock);
        key_lock(&g_key_copy_lock);
        result = key_copy_user_string(
            access, arguments[0], g_key_description_scratch,
            sizeof(g_key_description_scratch), 1);
        key_lock(&g_key_lock);
        state = key_task_get_locked(identity);
        if (result < 0 || !state) {
            key_unlock(&g_key_copy_lock);
            goto out;
        }
        if (g_key_description_scratch[0])
            ring = key_named_keyring_locked(
                identity->fsuid, identity->user_namespace_id,
                g_key_description_scratch);
        else
            ring = 0;
        if (!ring)
            ring = key_create_keyring_locked(
                identity->fsuid, identity->fsgid,
                identity->user_namespace_id,
                g_key_description_scratch[0] ?
                    g_key_description_scratch : "_ses.anonymous",
                EDGE_LINUX_KEY_POS_ALL | EDGE_LINUX_KEY_USR_VIEW |
                    EDGE_LINUX_KEY_USR_READ | EDGE_LINUX_KEY_USR_LINK);
        if (!ring) result = -EDGE_LINUX_EDQUOT;
        else {
            previous_session = state->session_keyring;
            state->session_keyring = ring->serial;
            result = ring->serial;
            if (previous_session != ring->serial)
                key_release_unreferenced_locked(previous_session, 0u);
        }
        key_unlock(&g_key_copy_lock);
        goto out;
    }
    if (command == EDGE_LINUX_KEYCTL_CAPABILITIES) {
        const uint8_t capabilities[2] = {
            0x01u | 0x02u | 0x04u | 0x10u | 0x20u | 0x40u | 0x80u,
#ifdef CONFIG_KEY_NOTIFICATIONS
            0x01u | 0x04u,
#else
            0x01u,
#endif
        };
        static const uint8_t zeros[64] = {0};
        uint64_t remaining = arguments[1] > sizeof(capabilities) ?
            arguments[1] - sizeof(capabilities) : 0u;
        uint64_t destination = arguments[0] + sizeof(capabilities);
        int copied;
        key_unlock(&g_key_lock);
        copied = key_copy_result(
            access, arguments[0], arguments[1], capabilities,
            sizeof(capabilities));
        if (copied < 0) return copied;
        while (remaining) {
            uint32_t chunk = remaining > sizeof(zeros) ?
                sizeof(zeros) : (uint32_t)remaining;
            if (!access->copy_to_user ||
                access->copy_to_user(
                    access->context, destination, zeros, chunk) < 0)
                return -EDGE_LINUX_EFAULT;
            destination += chunk;
            remaining -= chunk;
        }
        return sizeof(capabilities);
    }
    if (command == EDGE_LINUX_KEYCTL_SET_REQKEY_KEYRING) {
        int32_t replacement = (int32_t)arguments[0];
        int32_t previous = state->request_key_default;
        if (replacement != EDGE_LINUX_KEY_REQKEY_DEFL_NO_CHANGE &&
            (replacement < EDGE_LINUX_KEY_REQKEY_DEFL_DEFAULT ||
             replacement >
                EDGE_LINUX_KEY_REQKEY_DEFL_REQUESTOR_KEYRING ||
             replacement == EDGE_LINUX_KEY_REQKEY_DEFL_GROUP_KEYRING)) {
            result = -EDGE_LINUX_EINVAL;
        } else {
            if (replacement != EDGE_LINUX_KEY_REQKEY_DEFL_NO_CHANGE)
                state->request_key_default = replacement;
            result = previous;
        }
        goto out;
    }
    if (command == EDGE_LINUX_KEYCTL_GET_PERSISTENT) {
        uint32_t uid = (uint32_t)arguments[0];
        char name[32];
        uint32_t offset = 12u;
        if (uid == UINT32_MAX) uid = identity->fsuid;
        if (uid != identity->fsuid && identity->euid != 0u) {
            result = -EDGE_LINUX_EPERM;
            goto out;
        }
        memcpy(name, "_persistent.", 12u);
        offset = key_append_decimal(name, offset, uid);
        name[offset] = 0;
        key = key_named_keyring_locked(
            uid, identity->user_namespace_id, name);
        if (!key)
            key = key_create_keyring_locked(
                uid, identity->fsgid, identity->user_namespace_id, name,
                EDGE_LINUX_KEY_POS_ALL | EDGE_LINUX_KEY_USR_VIEW |
                    EDGE_LINUX_KEY_USR_READ);
        ring = key_resolve_locked(
            identity, state, (int32_t)arguments[1], 1);
        if (!key) result = -EDGE_LINUX_EDQUOT;
        else if (!ring) result = -EDGE_LINUX_ENOKEY;
        else {
            result = key_link_locked(identity, state, key, ring, 0);
            if (result == 0) result = key->serial;
        }
        goto out;
    }

    if (command == EDGE_LINUX_KEYCTL_WATCH_KEY) {
        int32_t watch_id = (int32_t)arguments[2];

        if (watch_id < -1 || watch_id > 255) {
            result = -EDGE_LINUX_EINVAL;
            goto out;
        }
        key = key_resolve_locked(
            identity, state, (int32_t)arguments[0], 1);
        result = keyctl_watch_key_locked(
            identity, state, key, (int32_t)arguments[1], watch_id);
        goto out;
    }

    key = key_resolve_locked(
        identity, state, (int32_t)arguments[0], 0);
    if (!key) {
        result = -EDGE_LINUX_ENOKEY;
        goto out;
    }
    result = key_validate(key);
    if (result < 0 && command != EDGE_LINUX_KEYCTL_INVALIDATE)
        goto out;

    switch (command) {
    case EDGE_LINUX_KEYCTL_UPDATE:
        if (arguments[2] > KERNEL_KEY_PAYLOAD_MAX) {
            result = arguments[2] > 1024u * 1024u - 1u ?
                -EDGE_LINUX_EINVAL : -EDGE_LINUX_ENOMEM;
            break;
        }
        if (key->kind == KERNEL_KEY_KIND_KEYRING) {
            result = -EDGE_LINUX_EOPNOTSUPP;
            break;
        }
        if (key_permission_locked(identity, state, key, 4u) < 0) {
            result = -EDGE_LINUX_EACCES;
            break;
        }
        key_unlock(&g_key_lock);
        key_lock(&g_key_copy_lock);
        result = arguments[2] &&
                 (!arguments[1] || !access->copy_from_user ||
                  access->copy_from_user(
                      access->context, g_key_payload_scratch,
                      arguments[1], arguments[2]) < 0) ?
            -EDGE_LINUX_EFAULT : 0;
        key_lock(&g_key_lock);
        state = key_task_get_locked(identity);
        key = state ? key_resolve_locked(
            identity, state, (int32_t)arguments[0], 0) : 0;
        if (result == 0 && (!key || key_validate(key) < 0))
            result = -EDGE_LINUX_ENOKEY;
        if (result == 0) {
            key->payload_length = (uint32_t)arguments[2];
            if (arguments[2])
                memcpy(key->payload, g_key_payload_scratch,
                       (uint32_t)arguments[2]);
            key_notify_locked(key, KERNEL_KEY_NOTIFY_UPDATED, 0u);
        }
        key_unlock(&g_key_copy_lock);
        break;
    case EDGE_LINUX_KEYCTL_REVOKE:
        if (key_permission_locked(identity, state, key, 32u) < 0)
            result = -EDGE_LINUX_EACCES;
        else {
            key->revoked = 1u;
            memset(key->payload, 0, key->payload_length);
            key->payload_length = 0u;
            key_notify_locked(key, KERNEL_KEY_NOTIFY_REVOKED, 0u);
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_INVALIDATE:
        if (key_permission_locked(identity, state, key, 32u) < 0)
            result = -EDGE_LINUX_EACCES;
        else {
            key->invalidated = 1u;
            key_notify_locked(key, KERNEL_KEY_NOTIFY_INVALIDATED, 0u);
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_CHOWN:
        if (key->uid != identity->fsuid && identity->euid != 0u)
            result = -EDGE_LINUX_EPERM;
        else if ((uint32_t)arguments[1] != UINT32_MAX &&
                 (uint32_t)arguments[1] != identity->fsuid &&
                 identity->euid != 0u)
            result = -EDGE_LINUX_EPERM;
        else {
            if ((uint32_t)arguments[1] != UINT32_MAX)
                key->uid = (uint32_t)arguments[1];
            if ((uint32_t)arguments[2] != UINT32_MAX)
                key->gid = (uint32_t)arguments[2];
            key_notify_locked(key, KERNEL_KEY_NOTIFY_SETATTR, 0u);
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_SETPERM:
        if (arguments[1] & ~EDGE_LINUX_KEY_PERM_ALL)
            result = -EDGE_LINUX_EINVAL;
        else if (key_permission_locked(identity, state, key, 32u) < 0)
            result = -EDGE_LINUX_EACCES;
        else {
            key->permissions = (uint32_t)arguments[1];
            key_notify_locked(key, KERNEL_KEY_NOTIFY_SETATTR, 0u);
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_DESCRIBE:
        if (key_permission_locked(identity, state, key, 1u) < 0) {
            result = -EDGE_LINUX_EACCES;
            break;
        }
        length = key_describe(key, output);
        key_unlock(&g_key_lock);
        return key_copy_result(
            access, arguments[1], arguments[2], output, length);
    case EDGE_LINUX_KEYCTL_GET_SECURITY:
        if (key_permission_locked(identity, state, key, 1u) < 0) {
            result = -EDGE_LINUX_EACCES;
            break;
        }
        output[0] = 0;
        key_unlock(&g_key_lock);
        if (!arguments[1] || !arguments[2]) return 1;
        return key_copy_result(
            access, arguments[1], arguments[2], output, 1u);
    case EDGE_LINUX_KEYCTL_CLEAR:
        if (key->kind != KERNEL_KEY_KIND_KEYRING)
            result = -EDGE_LINUX_ENOTDIR;
        else if (key_permission_locked(identity, state, key, 4u) < 0)
            result = -EDGE_LINUX_EACCES;
        else {
            memset(key->links, 0, sizeof(key->links));
            key->link_count = 0;
            key_notify_locked(key, KERNEL_KEY_NOTIFY_CLEARED, 0u);
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_LINK:
        ring = key_resolve_locked(
            identity, state, (int32_t)arguments[1], 0);
        result = ring ? key_link_locked(
            identity, state, key, ring, 0) : -EDGE_LINUX_ENOKEY;
        break;
    case EDGE_LINUX_KEYCTL_UNLINK:
        ring = key_resolve_locked(
            identity, state, (int32_t)arguments[1], 0);
        if (!ring) result = -EDGE_LINUX_ENOKEY;
        else if (key_permission_locked(identity, state, ring, 4u) < 0)
            result = -EDGE_LINUX_EACCES;
        else result = key_unlink_locked(key, ring);
        break;
    case EDGE_LINUX_KEYCTL_READ:
        if (key_permission_locked(identity, state, key, 2u) < 0) {
            result = -EDGE_LINUX_EACCES;
            break;
        }
        if (key->kind == KERNEL_KEY_KIND_LOGON) {
            result = -EDGE_LINUX_EOPNOTSUPP;
            break;
        }
        if (key->kind == KERNEL_KEY_KIND_KEYRING) {
            length = key->link_count * sizeof(serials[0]);
            memcpy(serials, key->links, length);
            key_unlock(&g_key_lock);
            return key_copy_result(
                access, arguments[1], arguments[2], serials, length);
        }
        length = key->payload_length;
        if (length > sizeof(output)) {
            uint32_t copy = arguments[2] < length ?
                (uint32_t)arguments[2] : length;
            if (copy && (!arguments[1] || !access->copy_to_user ||
                access->copy_to_user(access->context, arguments[1],
                                     key->payload, copy) < 0))
                result = -EDGE_LINUX_EFAULT;
            else
                result = length;
            break;
        }
        memcpy(output, key->payload, length);
        key_unlock(&g_key_lock);
        return key_copy_result(
            access, arguments[1], arguments[2], output, length);
    case EDGE_LINUX_KEYCTL_SET_TIMEOUT:
        if (key_permission_locked(identity, state, key, 32u) < 0)
            result = -EDGE_LINUX_EACCES;
        else {
            key->expires_us = arguments[1] ?
                boottime_monotonic_us() + arguments[1] * 1000000u : 0u;
            key_notify_locked(key, KERNEL_KEY_NOTIFY_SETATTR, 0u);
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_RESTRICT_KEYRING:
        if (key->kind != KERNEL_KEY_KIND_KEYRING) {
            result = -EDGE_LINUX_ENOTDIR;
            break;
        }
        if (key_permission_locked(identity, state, key, 32u) < 0) {
            result = -EDGE_LINUX_EACCES;
            break;
        }
        key_unlock(&g_key_lock);
        key_lock(&g_key_copy_lock);
        if (!arguments[1] && arguments[2]) {
            result = -EDGE_LINUX_EINVAL;
        } else if (!arguments[1]) {
            result = 0;
            g_key_type_scratch[0] = 0;
        } else if (!arguments[2]) {
            result = -EDGE_LINUX_EINVAL;
        } else {
            result = key_copy_user_string(
                access, arguments[1], g_key_type_scratch,
                sizeof(g_key_type_scratch), 0);
            if (result == 0)
                result = key_copy_user_string(
                    access, arguments[2], g_key_callout_scratch,
                    sizeof(g_key_callout_scratch), 0);
        }
        key_lock(&g_key_lock);
        state = key_task_get_locked(identity);
        key = state ? key_resolve_locked(
            identity, state, (int32_t)arguments[0], 0) : 0;
        if (result == 0 && !key) result = -EDGE_LINUX_ENOKEY;
        if (result == 0) {
            key->restriction_set = 1u;
            key->reject_links = arguments[1] ? 0u : 1u;
            if (arguments[1])
                memcpy(key->restriction_type, g_key_type_scratch,
                       strlen(g_key_type_scratch) + 1u);
            key_notify_locked(key, KERNEL_KEY_NOTIFY_SETATTR, 0u);
        }
        key_unlock(&g_key_copy_lock);
        break;
    case EDGE_LINUX_KEYCTL_MOVE:
        if (arguments[3] & ~EDGE_LINUX_KEYCTL_MOVE_EXCL) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
        ring = key_resolve_locked(
            identity, state, (int32_t)arguments[1], 0);
        other = key_resolve_locked(
            identity, state, (int32_t)arguments[2], 0);
        if (!ring || !other) result = -EDGE_LINUX_ENOKEY;
        else if (key_permission_locked(identity, state, ring, 4u) < 0)
            result = -EDGE_LINUX_EACCES;
        else if (ring == other)
            result = 0;
        else {
            uint32_t link_index;
            int linked = 0;

            for (link_index = 0; link_index < ring->link_count;
                 ++link_index) {
                if (ring->links[link_index] == key->serial) {
                    linked = 1;
                    break;
                }
            }
            if (!linked) {
                result = -EDGE_LINUX_ENOENT;
                break;
            }
            result = key_link_locked(
                identity, state, key, other,
                (arguments[3] & EDGE_LINUX_KEYCTL_MOVE_EXCL) != 0u);
            if (result == 0) {
                result = key_unlink_locked(key, ring);
                if (result < 0)
                    (void)key_unlink_locked(key, other);
            }
        }
        break;
    case EDGE_LINUX_KEYCTL_SEARCH:
        if (key->kind != KERNEL_KEY_KIND_KEYRING) {
            result = -EDGE_LINUX_ENOTDIR;
            break;
        }
        key_unlock(&g_key_lock);
        result = key_prepare_strings(
            access, arguments[1], arguments[2], 0);
        key_lock(&g_key_lock);
        state = key_task_get_locked(identity);
        key = state ? key_resolve_locked(
            identity, state, (int32_t)arguments[0], 0) : 0;
        if (result < 0 || !state || !key) {
            if (result == 0) {
                result = -EDGE_LINUX_ENOKEY;
                key_unlock(&g_key_copy_lock);
            }
            break;
        }
        other = key_search_locked(
            identity, state, key, g_key_type_scratch,
            g_key_description_scratch, 0u);
        if (!other) result = -EDGE_LINUX_ENOKEY;
        else if (arguments[3]) {
            ring = key_resolve_locked(
                identity, state, (int32_t)arguments[3], 1);
            result = ring ? key_link_locked(
                identity, state, other, ring, 0) : -EDGE_LINUX_ENOKEY;
            if (result == 0) result = other->serial;
        } else result = other->serial;
        key_unlock(&g_key_copy_lock);
        break;
    default:
        result = -EDGE_LINUX_EOPNOTSUPP;
        break;
    }
out:
    key_unlock(&g_key_lock);
    return result;
}

void kernel_keyring_task_exit(int32_t global_tid, int32_t global_tgid,
                              int whole_thread_group) {
    uint32_t index;
    key_lock(&g_key_lock);
    for (index = 0; index < KERNEL_KEY_TASK_MAX; ++index) {
        kernel_key_task_state_t *state = &g_key_tasks[index];
        int32_t session_keyring;
        int32_t thread_keyring;
        if (!state->used ||
            (whole_thread_group ? state->tgid != global_tgid :
                                  state->tid != global_tid))
            continue;
        thread_keyring = state->thread_keyring;
        session_keyring = state->session_keyring;
        if (state->thread_keyring) {
            kernel_key_object_t *ring = key_find_locked(
                state->thread_keyring);
            if (ring) ring->invalidated = 1u;
        }
        memset(state, 0, sizeof(*state));
        key_release_unreferenced_locked(thread_keyring, 0u);
        key_release_unreferenced_locked(session_keyring, 0u);
    }
    if (whole_thread_group) {
        for (index = 0; index < KERNEL_KEY_MAX; ++index) {
            kernel_key_object_t *ring = &g_keys[index];
            if (!ring->used || ring->kind != KERNEL_KEY_KIND_KEYRING ||
                strncmp(ring->description, "_pid.", 5u))
                continue;
            {
                uint32_t value = 0;
                const char *cursor = ring->description + 5u;
                while (*cursor >= '0' && *cursor <= '9') {
                    value = value * 10u + (uint32_t)(*cursor - '0');
                    ++cursor;
                }
                if (!*cursor && value == (uint32_t)global_tgid)
                    ring->invalidated = 1u;
            }
        }
    }
    if (whole_thread_group) {
        for (index = 0; index < KERNEL_KEY_MAX; ++index) {
            kernel_key_object_t *ring = &g_keys[index];
            if (ring->used && ring->invalidated)
                key_release_unreferenced_locked(ring->serial, 0u);
        }
    }
    key_unlock(&g_key_lock);
}
