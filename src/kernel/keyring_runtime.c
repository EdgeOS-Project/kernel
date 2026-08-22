/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux key retention service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>
#include <stdint.h>

#include "kernel/keyring_runtime.h"
#include "kernel/linux_errno.h"
#include "string.h"
#include "sys/boottime.h"

#define KERNEL_KEY_MAX 256u
#define KERNEL_KEY_TASK_MAX 2048u
#define KERNEL_KEY_LINK_MAX 64u
#define KERNEL_KEY_TYPE_MAX 32u
#define KERNEL_KEY_DESCRIPTION_MAX 4096u
#define KERNEL_KEY_PAYLOAD_MAX 65536u
#define KERNEL_KEY_SEARCH_DEPTH_MAX 8u

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
    uint32_t permissions;
    uint32_t payload_length;
    uint32_t link_count;
    uint64_t expires_us;
    int32_t links[KERNEL_KEY_LINK_MAX];
    char type[KERNEL_KEY_TYPE_MAX];
    char restriction_type[KERNEL_KEY_TYPE_MAX];
    char description[KERNEL_KEY_DESCRIPTION_MAX];
    uint8_t payload[KERNEL_KEY_PAYLOAD_MAX];
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
} kernel_key_task_state_t;

static kernel_key_object_t g_keys[KERNEL_KEY_MAX];
static kernel_key_task_state_t g_key_tasks[KERNEL_KEY_TASK_MAX];
static char g_key_type_scratch[KERNEL_KEY_TYPE_MAX];
static char g_key_description_scratch[KERNEL_KEY_DESCRIPTION_MAX];
static char g_key_callout_scratch[4096u];
static uint8_t g_key_payload_scratch[KERNEL_KEY_PAYLOAD_MAX];
static volatile uint32_t g_key_lock;
static volatile uint32_t g_key_copy_lock;
static int32_t g_next_key_serial = 1;

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
    uint32_t uid, uint32_t gid, uint32_t permissions) {
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
    uint32_t uid, const char *description) {
    uint32_t index;
    for (index = 0; index < KERNEL_KEY_MAX; ++index) {
        kernel_key_object_t *key = &g_keys[index];
        if (key->used && !key->constructing && !key->invalidated &&
            key->kind == KERNEL_KEY_KIND_KEYRING && key->uid == uid &&
            !strcmp(key->description, description))
            return key;
    }
    return 0;
}

static kernel_key_object_t *key_create_keyring_locked(
    uint32_t uid, uint32_t gid, const char *description,
    uint32_t permissions) {
    return key_allocate_locked(
        KERNEL_KEY_KIND_KEYRING, "keyring", description, uid, gid,
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
    ring = key_named_keyring_locked(identity->uid, name);
    if (ring) return ring;
    return key_create_keyring_locked(
        identity->uid, identity->gid, name,
        EDGE_LINUX_KEY_POS_ALL | EDGE_LINUX_KEY_USR_VIEW |
            EDGE_LINUX_KEY_USR_READ | EDGE_LINUX_KEY_USR_LINK);
}

static kernel_key_task_state_t *key_task_get_locked(
    const kernel_linux_identity_t *identity) {
    kernel_key_task_state_t *state;
    kernel_key_object_t *user_session;
    uint32_t index;

    state = key_task_find_locked(identity->global_tid);
    if (state) return state;
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
    ring = key_named_keyring_locked(identity->uid, name);
    if (ring || !create) return ring;
    return key_create_keyring_locked(
        identity->uid, identity->gid, name,
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
        identity->uid, identity->gid, name,
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
                identity->fsuid, identity->fsgid, permissions);
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
                identity->fsuid, g_key_description_scratch);
        else
            ring = 0;
        if (!ring)
            ring = key_create_keyring_locked(
                identity->fsuid, identity->fsgid,
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
            0x01u | 0x10u | 0x20u | 0x40u | 0x80u,
            0x01u,
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
        key = key_named_keyring_locked(uid, name);
        if (!key)
            key = key_create_keyring_locked(
                uid, identity->fsgid, name,
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
            result = 0;
        }
        break;
    case EDGE_LINUX_KEYCTL_INVALIDATE:
        if (key_permission_locked(identity, state, key, 32u) < 0)
            result = -EDGE_LINUX_EACCES;
        else {
            key->invalidated = 1u;
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
        else {
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
