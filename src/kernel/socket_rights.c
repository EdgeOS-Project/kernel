/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral SCM_RIGHTS storage.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/socket_message.h"
#include "kernel/socket_rights.h"

#define SOCKET_RIGHTS_POOL_MAGIC UINT32_C(0x53434d52)
#define SOCKET_RIGHTS_INDEX_NONE UINT32_MAX
#define SOCKET_RIGHTS_SCM_CREDENTIALS 2

typedef enum socket_rights_token_state {
    SOCKET_RIGHTS_TOKEN_FREE = 0,
    SOCKET_RIGHTS_TOKEN_ACQUIRING,
    SOCKET_RIGHTS_TOKEN_SOURCE,
    SOCKET_RIGHTS_TOKEN_RELEASING,
} socket_rights_token_state_t;

typedef enum socket_rights_record_internal_state {
    SOCKET_RIGHTS_RECORD_RELEASING =
        KERNEL_SOCKET_RIGHTS_RECORD_QUEUED + 1,
} socket_rights_record_internal_state_t;

typedef struct socket_rights_token_slot {
    kernel_fd_operation_lease_t lease;
    uint32_t next;
    uint32_t generation;
    uint32_t owner_record;
    uint8_t state;
    uint8_t reserved[3];
} socket_rights_token_slot_t;

typedef struct socket_rights_record_slot {
    uint64_t association_sequence;
    kernel_socket_rights_record_handle_t next_record;
    uint32_t first_token;
    uint32_t last_token;
    uint32_t generation;
    uint16_t descriptor_count;
    uint8_t state;
    uint8_t association_kind;
} socket_rights_record_slot_t;

typedef union socket_rights_default_arena {
    uint8_t bytes[KERNEL_SOCKET_RIGHTS_DEFAULT_ARENA_BYTES];
    uint64_t align_u64;
    void *align_pointer;
} __attribute__((aligned(KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT)))
socket_rights_default_arena_t;

static kernel_socket_rights_pool_t g_socket_rights_default_pool;
static socket_rights_default_arena_t g_socket_rights_default_arena;
static uint32_t g_socket_rights_default_state;

_Static_assert(
    sizeof(socket_rights_token_slot_t) == 592u,
    "SCM_RIGHTS token slot size changed");
_Static_assert(
    _Alignof(socket_rights_token_slot_t) >=
        KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT,
    "SCM_RIGHTS token slot does not preserve lease alignment");
_Static_assert(
    sizeof(socket_rights_record_slot_t) == 32u,
    "SCM_RIGHTS record slot size changed");
_Static_assert(
    sizeof(kernel_socket_rights_queue_t) == 24u,
    "SCM_RIGHTS per-socket queue must remain compact");
_Static_assert(
    KERNEL_SOCKET_RIGHTS_DEFAULT_ARENA_BYTES >=
        KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY *
            sizeof(socket_rights_token_slot_t) +
        KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY *
            sizeof(socket_rights_record_slot_t) +
        KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u,
    "default SCM_RIGHTS arena is too small");
_Static_assert(
    KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS ==
        KERNEL_SOCKET_SCM_RIGHTS_MAX,
    "SCM_RIGHTS limits disagree");

static socket_rights_token_slot_t *socket_rights_tokens(
        const kernel_socket_rights_pool_t *pool) {
    return pool ?
        (socket_rights_token_slot_t *)pool->token_storage : 0;
}

static socket_rights_record_slot_t *socket_rights_records(
        const kernel_socket_rights_pool_t *pool) {
    return pool ?
        (socket_rights_record_slot_t *)pool->record_storage : 0;
}

static int socket_rights_pool_valid(
        const kernel_socket_rights_pool_t *pool) {
    return pool && pool->magic == SOCKET_RIGHTS_POOL_MAGIC &&
        pool->record_storage && pool->record_capacity;
}

static uint32_t socket_rights_next_generation(uint32_t generation) {
    ++generation;
    return generation ? generation : 1u;
}

static kernel_socket_rights_record_handle_t
socket_rights_record_handle(uint32_t index, uint32_t generation) {
    return ((uint64_t)generation << 32) | ((uint64_t)index + 1u);
}

static kernel_socket_rights_token_handle_t
socket_rights_token_handle(uint32_t index, uint32_t generation) {
    return ((uint64_t)generation << 32) | ((uint64_t)index + 1u);
}

static int socket_rights_handle_parts(
        uint64_t handle, uint32_t capacity,
        uint32_t *index, uint32_t *generation) {
    uint32_t encoded_index;
    uint32_t encoded_generation;

    if (!handle || !index || !generation)
        return -EDGE_LINUX_EINVAL;
    encoded_index = (uint32_t)handle;
    encoded_generation = (uint32_t)(handle >> 32);
    if (!encoded_index || !encoded_generation ||
        encoded_index > capacity)
        return -EDGE_LINUX_ESTALE;
    *index = encoded_index - 1u;
    *generation = encoded_generation;
    return 0;
}

static socket_rights_record_slot_t *
socket_rights_record_locked(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t handle,
        uint32_t *index) {
    socket_rights_record_slot_t *records;
    uint32_t decoded_index;
    uint32_t generation;

    if (!socket_rights_pool_valid(pool) ||
        socket_rights_handle_parts(
            handle, pool->record_capacity,
            &decoded_index, &generation) < 0)
        return 0;
    records = socket_rights_records(pool);
    if (records[decoded_index].generation != generation ||
        records[decoded_index].state ==
            KERNEL_SOCKET_RIGHTS_RECORD_FREE)
        return 0;
    if (index) *index = decoded_index;
    return &records[decoded_index];
}

static socket_rights_token_slot_t *
socket_rights_token_locked(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_token_handle_t handle,
        uint32_t *index) {
    socket_rights_token_slot_t *tokens;
    uint32_t decoded_index;
    uint32_t generation;

    if (!socket_rights_pool_valid(pool) ||
        socket_rights_handle_parts(
            handle, pool->token_capacity,
            &decoded_index, &generation) < 0)
        return 0;
    tokens = socket_rights_tokens(pool);
    if (tokens[decoded_index].generation != generation ||
        tokens[decoded_index].state == SOCKET_RIGHTS_TOKEN_FREE)
        return 0;
    if (index) *index = decoded_index;
    return &tokens[decoded_index];
}

static int socket_rights_record_allocate_locked(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t *handle) {
    socket_rights_record_slot_t *record;
    uint32_t index;

    if (!pool->free_record_count ||
        pool->free_record_head == SOCKET_RIGHTS_INDEX_NONE)
        return -EDGE_LINUX_ENOBUFS;
    index = pool->free_record_head;
    if (index >= pool->record_capacity)
        return -EDGE_LINUX_EIO;
    record = &socket_rights_records(pool)[index];
    pool->free_record_head = record->first_token;
    --pool->free_record_count;
    record->association_sequence = 0;
    record->next_record = 0;
    record->first_token = SOCKET_RIGHTS_INDEX_NONE;
    record->last_token = SOCKET_RIGHTS_INDEX_NONE;
    record->descriptor_count = 0;
    record->state = KERNEL_SOCKET_RIGHTS_RECORD_BUILDING;
    record->association_kind =
        KERNEL_SOCKET_RIGHTS_ASSOCIATION_NONE;
    *handle = socket_rights_record_handle(
        index, record->generation);
    return 0;
}

static void socket_rights_record_free_locked(
        kernel_socket_rights_pool_t *pool, uint32_t index) {
    socket_rights_record_slot_t *record =
        &socket_rights_records(pool)[index];

    record->association_sequence = 0;
    record->next_record = 0;
    record->last_token = SOCKET_RIGHTS_INDEX_NONE;
    record->descriptor_count = 0;
    record->state = KERNEL_SOCKET_RIGHTS_RECORD_FREE;
    record->association_kind =
        KERNEL_SOCKET_RIGHTS_ASSOCIATION_NONE;
    record->generation =
        socket_rights_next_generation(record->generation);
    record->first_token = pool->free_record_head;
    pool->free_record_head = index;
    ++pool->free_record_count;
}

static int socket_rights_token_allocate_locked(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_token_handle_t *handle,
        uint32_t *index) {
    socket_rights_token_slot_t *token;
    uint32_t allocated;

    if (!pool->free_token_count ||
        pool->free_token_head == SOCKET_RIGHTS_INDEX_NONE)
        return -EDGE_LINUX_ENOBUFS;
    allocated = pool->free_token_head;
    if (allocated >= pool->token_capacity)
        return -EDGE_LINUX_EIO;
    token = &socket_rights_tokens(pool)[allocated];
    pool->free_token_head = token->next;
    --pool->free_token_count;
    token->next = SOCKET_RIGHTS_INDEX_NONE;
    token->owner_record = SOCKET_RIGHTS_INDEX_NONE;
    token->state = SOCKET_RIGHTS_TOKEN_ACQUIRING;
    *handle = socket_rights_token_handle(
        allocated, token->generation);
    *index = allocated;
    return 0;
}

static void socket_rights_token_free_locked(
        kernel_socket_rights_pool_t *pool, uint32_t index) {
    socket_rights_token_slot_t *token =
        &socket_rights_tokens(pool)[index];

    memset(&token->lease, 0, sizeof(token->lease));
    token->owner_record = SOCKET_RIGHTS_INDEX_NONE;
    token->state = SOCKET_RIGHTS_TOKEN_FREE;
    token->generation =
        socket_rights_next_generation(token->generation);
    token->next = pool->free_token_head;
    pool->free_token_head = index;
    ++pool->free_token_count;
}

static int socket_rights_record_start(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t *record) {
    uint64_t irq_flags;
    int result;

    irq_flags = spin_lock_irqsave(&pool->lock);
    result = socket_rights_record_allocate_locked(pool, record);
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return result;
}

static int socket_rights_record_release_state(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t *handle,
        uint8_t expected_state) {
    socket_rights_record_slot_t *record;
    socket_rights_token_slot_t *token;
    uint64_t irq_flags;
    uint32_t record_index;
    uint32_t token_index;
    int first_error = 0;

    if (!socket_rights_pool_valid(pool) || !handle || !*handle)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(
        pool, *handle, &record_index);
    if (!record) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    if (record->state != expected_state) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EBUSY;
    }
    if (record->descriptor_count >
        KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EIO;
    }
    record->state = SOCKET_RIGHTS_RECORD_RELEASING;
    spin_unlock_irqrestore(&pool->lock, irq_flags);

    /*
     * Backend release may drop the final reference to another socket and
     * recursively clear its queue.  It must never run under the pool lock.
     * Pop and generation-pin one token at a time to keep this path safe for
     * small architecture kernel stacks.
     */
    for (;;) {
        kernel_socket_rights_token_handle_t token_handle;
        uint32_t remaining;
        int release_result;

        irq_flags = spin_lock_irqsave(&pool->lock);
        record = socket_rights_record_locked(
            pool, *handle, &record_index);
        if (!record ||
            record->state != SOCKET_RIGHTS_RECORD_RELEASING) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return first_error ?
                first_error : -EDGE_LINUX_EIO;
        }
        remaining = record->descriptor_count;
        if (!remaining) {
            if (record->first_token !=
                    SOCKET_RIGHTS_INDEX_NONE ||
                record->last_token !=
                    SOCKET_RIGHTS_INDEX_NONE) {
                spin_unlock_irqrestore(
                    &pool->lock, irq_flags);
                return first_error ?
                    first_error : -EDGE_LINUX_EIO;
            }
            socket_rights_record_free_locked(
                pool, record_index);
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            *handle = 0;
            return first_error;
        }
        token_index = record->first_token;
        if (token_index == SOCKET_RIGHTS_INDEX_NONE ||
            token_index >= pool->token_capacity) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return first_error ?
                first_error : -EDGE_LINUX_EIO;
        }
        token = &socket_rights_tokens(pool)[token_index];
        if (token->state != SOCKET_RIGHTS_TOKEN_SOURCE ||
            token->owner_record != record_index ||
            (remaining == 1u &&
             (record->last_token != token_index ||
              token->next != SOCKET_RIGHTS_INDEX_NONE)) ||
            (remaining > 1u &&
             (record->last_token == token_index ||
              token->next == SOCKET_RIGHTS_INDEX_NONE))) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return first_error ?
                first_error : -EDGE_LINUX_EIO;
        }
        token_handle = socket_rights_token_handle(
            token_index, token->generation);
        record->first_token = token->next;
        --record->descriptor_count;
        if (!record->descriptor_count)
            record->last_token = SOCKET_RIGHTS_INDEX_NONE;
        token->next = SOCKET_RIGHTS_INDEX_NONE;
        token->state = SOCKET_RIGHTS_TOKEN_RELEASING;
        spin_unlock_irqrestore(&pool->lock, irq_flags);

        release_result =
            kernel_fd_operation_release(&token->lease);
        if (release_result < 0 && !first_error)
            first_error = release_result;

        irq_flags = spin_lock_irqsave(&pool->lock);
        token = socket_rights_token_locked(
            pool, token_handle, &token_index);
        if (token &&
            token->state == SOCKET_RIGHTS_TOKEN_RELEASING &&
            token->owner_record == record_index)
            socket_rights_token_free_locked(pool, token_index);
        else if (!first_error)
            first_error = -EDGE_LINUX_EIO;
        spin_unlock_irqrestore(&pool->lock, irq_flags);
    }
}

static int socket_rights_record_append_descriptor(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t record_handle,
        const void *fd_owner,
        int32_t descriptor) {
    kernel_socket_rights_token_handle_t token_handle = 0;
    socket_rights_record_slot_t *record;
    socket_rights_token_slot_t *token;
    uint64_t irq_flags;
    uint32_t record_index;
    uint32_t token_index;
    int result;

    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(
        pool, record_handle, &record_index);
    if (!record ||
        record->state != KERNEL_SOCKET_RIGHTS_RECORD_BUILDING) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return record ? -EDGE_LINUX_EBUSY : -EDGE_LINUX_ESTALE;
    }
    result = socket_rights_token_allocate_locked(
        pool, &token_handle, &token_index);
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    if (result < 0) return result;

    token = &socket_rights_tokens(pool)[token_index];
    result = kernel_fd_operation_acquire_for_owner(
        fd_owner, descriptor, &token->lease);
    if (result < 0) {
        irq_flags = spin_lock_irqsave(&pool->lock);
        token = socket_rights_token_locked(
            pool, token_handle, &token_index);
        if (token &&
            token->state == SOCKET_RIGHTS_TOKEN_ACQUIRING)
            socket_rights_token_free_locked(pool, token_index);
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return result;
    }

    irq_flags = spin_lock_irqsave(&pool->lock);
    token = socket_rights_token_locked(
        pool, token_handle, &token_index);
    record = socket_rights_record_locked(
        pool, record_handle, &record_index);
    if (!token ||
        token->state != SOCKET_RIGHTS_TOKEN_ACQUIRING ||
        !record ||
        record->state != KERNEL_SOCKET_RIGHTS_RECORD_BUILDING) {
        if (token)
            token->state = SOCKET_RIGHTS_TOKEN_RELEASING;
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        (void)kernel_fd_operation_release(
            &socket_rights_tokens(pool)[token_index].lease);
        irq_flags = spin_lock_irqsave(&pool->lock);
        token = socket_rights_token_locked(
            pool, token_handle, &token_index);
        if (token &&
            token->state == SOCKET_RIGHTS_TOKEN_RELEASING)
            socket_rights_token_free_locked(pool, token_index);
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    token->owner_record = record_index;
    token->state = SOCKET_RIGHTS_TOKEN_SOURCE;
    if (record->last_token != SOCKET_RIGHTS_INDEX_NONE)
        socket_rights_tokens(pool)[record->last_token].next =
            token_index;
    else
        record->first_token = token_index;
    record->last_token = token_index;
    ++record->descriptor_count;
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return 0;
}

static int socket_rights_record_finish(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t record_handle) {
    socket_rights_record_slot_t *record;
    uint64_t irq_flags;
    int result = 0;

    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(
        pool, record_handle, 0);
    if (!record)
        result = -EDGE_LINUX_ESTALE;
    else if (record->state !=
             KERNEL_SOCKET_RIGHTS_RECORD_BUILDING)
        result = -EDGE_LINUX_EBUSY;
    else
        record->state =
            KERNEL_SOCKET_RIGHTS_RECORD_DETACHED;
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return result;
}

uint64_t kernel_socket_rights_pool_required_bytes(
        uint32_t token_capacity, uint32_t record_capacity) {
    uint64_t token_bytes;
    uint64_t record_bytes;
    uint64_t total;

    if (!record_capacity ||
        token_capacity == UINT32_MAX ||
        record_capacity == UINT32_MAX)
        return 0;
    token_bytes =
        (uint64_t)token_capacity *
        sizeof(socket_rights_token_slot_t);
    record_bytes =
        (uint64_t)record_capacity *
        sizeof(socket_rights_record_slot_t);
    if (token_bytes > UINT64_MAX - record_bytes)
        return 0;
    total = token_bytes + record_bytes;
    if (total > UINT64_MAX -
            (KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u))
        return 0;
    return total +
        (KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u);
}

int kernel_socket_rights_pool_initialize(
        kernel_socket_rights_pool_t *pool,
        void *arena, uint64_t arena_bytes,
        uint32_t token_capacity, uint32_t record_capacity) {
    socket_rights_record_slot_t *records;
    socket_rights_token_slot_t *tokens;
    uint64_t required;
    uint64_t padding;
    uint64_t token_bytes;
    uint64_t record_bytes;
    uint64_t storage_bytes;
    uintptr_t address;
    uintptr_t aligned;

    if (!pool || !arena)
        return -EDGE_LINUX_EINVAL;
    if (pool->magic == SOCKET_RIGHTS_POOL_MAGIC)
        return -EDGE_LINUX_EBUSY;
    required = kernel_socket_rights_pool_required_bytes(
        token_capacity, record_capacity);
    if (!required)
        return -EDGE_LINUX_EINVAL;
    if (arena_bytes < required)
        return -EDGE_LINUX_ENOMEM;
    address = (uintptr_t)arena;
    if (address > UINTPTR_MAX -
            (KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u))
        return -EDGE_LINUX_EOVERFLOW;
    aligned = (address +
        (KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u)) &
        ~((uintptr_t)
            KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u);
    padding = (uint64_t)(aligned - address);
    token_bytes =
        (uint64_t)token_capacity *
        sizeof(socket_rights_token_slot_t);
    record_bytes =
        (uint64_t)record_capacity *
        sizeof(socket_rights_record_slot_t);
    storage_bytes = token_bytes + record_bytes;
    if (arena_bytes - padding < storage_bytes)
        return -EDGE_LINUX_ENOMEM;
    if (storage_bytes > UINTPTR_MAX ||
        aligned > UINTPTR_MAX - (uintptr_t)storage_bytes)
        return -EDGE_LINUX_EOVERFLOW;

    memset(pool, 0, sizeof(*pool));
    spinlock_init(&pool->lock);
    tokens = (socket_rights_token_slot_t *)(void *)aligned;
    records = (socket_rights_record_slot_t *)(void *)(
        aligned + (uintptr_t)token_bytes);
    memset(tokens, 0, (size_t)token_bytes);
    memset(records, 0, (size_t)record_bytes);
    pool->token_storage = tokens;
    pool->record_storage = records;
    pool->arena_bytes = arena_bytes;
    pool->token_capacity = token_capacity;
    pool->record_capacity = record_capacity;
    pool->free_token_head =
        token_capacity ? 0u : SOCKET_RIGHTS_INDEX_NONE;
    pool->free_record_head = 0;
    pool->free_token_count = token_capacity;
    pool->free_record_count = record_capacity;
    for (uint32_t index = 0; index < token_capacity; ++index) {
        tokens[index].next =
            index + 1u < token_capacity ?
                index + 1u : SOCKET_RIGHTS_INDEX_NONE;
        tokens[index].generation = 1u;
        tokens[index].owner_record =
            SOCKET_RIGHTS_INDEX_NONE;
        tokens[index].state = SOCKET_RIGHTS_TOKEN_FREE;
    }
    for (uint32_t index = 0; index < record_capacity; ++index) {
        records[index].first_token =
            index + 1u < record_capacity ?
                index + 1u : SOCKET_RIGHTS_INDEX_NONE;
        records[index].last_token =
            SOCKET_RIGHTS_INDEX_NONE;
        records[index].generation = 1u;
        records[index].state =
            KERNEL_SOCKET_RIGHTS_RECORD_FREE;
    }
    pool->magic = SOCKET_RIGHTS_POOL_MAGIC;
    return 0;
}

int kernel_socket_rights_default_pool_initialize(void) {
    uint32_t expected = 0;
    int result;

    if (__atomic_load_n(
            &g_socket_rights_default_state,
            __ATOMIC_ACQUIRE) == 2u)
        return 0;
    if (!__atomic_compare_exchange_n(
            &g_socket_rights_default_state, &expected, 1u, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -EDGE_LINUX_EBUSY;
    result = kernel_socket_rights_pool_initialize(
        &g_socket_rights_default_pool,
        g_socket_rights_default_arena.bytes,
        sizeof(g_socket_rights_default_arena.bytes),
        KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY,
        KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY);
    __atomic_store_n(
        &g_socket_rights_default_state,
        result < 0 ? 0u : 2u,
        __ATOMIC_RELEASE);
    return result;
}

kernel_socket_rights_pool_t *kernel_socket_rights_default_pool(void) {
    return __atomic_load_n(
               &g_socket_rights_default_state,
               __ATOMIC_ACQUIRE) == 2u ?
        &g_socket_rights_default_pool : 0;
}

int kernel_socket_rights_pool_statistics(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_pool_statistics_t *statistics) {
    uint64_t irq_flags;

    if (!socket_rights_pool_valid(pool) || !statistics)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&pool->lock);
    statistics->token_capacity = pool->token_capacity;
    statistics->record_capacity = pool->record_capacity;
    statistics->free_tokens = pool->free_token_count;
    statistics->free_records = pool->free_record_count;
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return 0;
}

int kernel_socket_rights_record_create_empty(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t *record) {
    kernel_socket_rights_record_handle_t created = 0;
    int result;

    if (!socket_rights_pool_valid(pool) || !record)
        return -EDGE_LINUX_EINVAL;
    if (*record) return -EDGE_LINUX_EBUSY;
    result = socket_rights_record_start(pool, &created);
    if (result < 0) return result;
    result = socket_rights_record_finish(pool, created);
    if (result < 0) {
        (void)socket_rights_record_release_state(
            pool, &created,
            KERNEL_SOCKET_RIGHTS_RECORD_BUILDING);
        return result;
    }
    *record = created;
    return 0;
}

int kernel_socket_rights_record_import_abi(
        kernel_socket_rights_pool_t *pool,
        const void *fd_owner, void *copy_context,
        edge_linux_copy_from_user_fn copy_from_user,
        uint64_t user_control, uint64_t control_length,
        kernel_socket_rights_record_handle_t *record,
        uint32_t message_abi) {
    kernel_socket_control_cursor_t cursor;
    kernel_socket_rights_record_handle_t building = 0;
    uint32_t descriptor_count = 0;
    int result = 0;

    if (!socket_rights_pool_valid(pool) ||
        !copy_from_user || !record)
        return -EDGE_LINUX_EINVAL;
    if (*record) return -EDGE_LINUX_EBUSY;
    if (!control_length) return 0;
    kernel_socket_control_cursor_initialize_abi(
        &cursor, copy_context, copy_from_user,
        user_control, control_length,
        (kernel_socket_message_abi_t)message_abi);
    for (;;) {
        kernel_socket_control_item_t item;
        uint64_t item_count;
        int next = kernel_socket_control_next(&cursor, &item);

        if (next < 0) {
            result = next;
            break;
        }
        if (!next) break;
        if (item.header.cmsg_level !=
            (int32_t)EDGE_LINUX_SOL_SOCKET)
            continue;
        if (item.header.cmsg_type ==
            (int32_t)KERNEL_SOCKET_SCM_RIGHTS) {
            item_count =
                item.data_length / sizeof(int32_t);
            if (item_count >
                KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS -
                    descriptor_count) {
                result = -EDGE_LINUX_EINVAL;
                break;
            }
            if (!item_count) continue;
            if (!building) {
                result =
                    socket_rights_record_start(pool, &building);
                if (result < 0) break;
            }
            for (uint64_t index = 0;
                 index < item_count; ++index) {
                int32_t descriptor = -1;
                uint64_t offset =
                    index * sizeof(descriptor);

                if (item.user_data > UINT64_MAX - offset ||
                    copy_from_user(
                        copy_context, &descriptor,
                        item.user_data + offset,
                        sizeof(descriptor)) < 0) {
                    result = -EDGE_LINUX_EFAULT;
                    break;
                }
                result =
                    socket_rights_record_append_descriptor(
                        pool, building, fd_owner, descriptor);
                if (result < 0) break;
                ++descriptor_count;
            }
            if (result < 0) break;
        } else if (item.header.cmsg_type !=
                   SOCKET_RIGHTS_SCM_CREDENTIALS) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
    }
    if (result < 0) {
        if (building)
            (void)socket_rights_record_release_state(
                pool, &building,
                KERNEL_SOCKET_RIGHTS_RECORD_BUILDING);
        return result;
    }
    if (!building) return 0;
    result = socket_rights_record_finish(pool, building);
    if (result < 0) {
        (void)socket_rights_record_release_state(
            pool, &building,
            KERNEL_SOCKET_RIGHTS_RECORD_BUILDING);
        return result;
    }
    *record = building;
    return 0;
}

int kernel_socket_rights_record_import(
        kernel_socket_rights_pool_t *pool,
        const void *fd_owner, void *copy_context,
        edge_linux_copy_from_user_fn copy_from_user,
        uint64_t user_control, uint64_t control_length,
        kernel_socket_rights_record_handle_t *record) {
    return kernel_socket_rights_record_import_abi(
        pool, fd_owner, copy_context, copy_from_user, user_control,
        control_length, record, KERNEL_SOCKET_MESSAGE_ABI_NATIVE);
}

int kernel_socket_rights_record_drop(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t *record) {
    return socket_rights_record_release_state(
        pool, record,
        KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
}

static void socket_rights_record_fill_info(
        kernel_socket_rights_record_handle_t handle,
        const socket_rights_record_slot_t *record,
        kernel_socket_rights_record_info_t *information) {
    memset(information, 0, sizeof(*information));
    information->handle = handle;
    information->association_sequence =
        record->association_sequence;
    information->descriptor_count =
        record->descriptor_count;
    information->state = record->state;
    information->association_kind =
        record->association_kind;
}

int kernel_socket_rights_record_info(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t handle,
        kernel_socket_rights_record_info_t *information) {
    socket_rights_record_slot_t *record;
    uint64_t irq_flags;

    if (!socket_rights_pool_valid(pool) ||
        !handle || !information)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(pool, handle, 0);
    if (!record) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    socket_rights_record_fill_info(
        handle, record, information);
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return 0;
}

int kernel_socket_rights_token_cursor_initialize(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_record_handle_t handle,
        kernel_socket_rights_token_cursor_t *cursor) {
    socket_rights_record_slot_t *record;
    socket_rights_token_slot_t *token;
    uint64_t irq_flags;

    if (!socket_rights_pool_valid(pool) ||
        !handle || !cursor)
        return -EDGE_LINUX_EINVAL;
    memset(cursor, 0, sizeof(*cursor));
    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(pool, handle, 0);
    if (!record) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    if (record->state !=
            KERNEL_SOCKET_RIGHTS_RECORD_DETACHED &&
        record->state !=
            KERNEL_SOCKET_RIGHTS_RECORD_QUEUED) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EBUSY;
    }
    cursor->record = handle;
    cursor->descriptor_count =
        record->descriptor_count;
    if (record->first_token !=
        SOCKET_RIGHTS_INDEX_NONE) {
        if (record->first_token >= pool->token_capacity) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            memset(cursor, 0, sizeof(*cursor));
            return -EDGE_LINUX_EIO;
        }
        token = &socket_rights_tokens(
            pool)[record->first_token];
        cursor->next_token = socket_rights_token_handle(
            record->first_token, token->generation);
    }
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return 0;
}

int kernel_socket_rights_token_cursor_next(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_token_cursor_t *cursor,
        uint32_t *source_index,
        const kernel_fd_operation_lease_t **lease) {
    socket_rights_record_slot_t *record;
    socket_rights_token_slot_t *token;
    uint64_t irq_flags;
    uint32_t record_index;

    if (!socket_rights_pool_valid(pool) ||
        !cursor || !source_index || !lease ||
        !cursor->record)
        return -EDGE_LINUX_EINVAL;
    *lease = 0;
    *source_index = cursor->next_index;
    if (!cursor->next_token) {
        return cursor->next_index ==
                cursor->descriptor_count ?
            0 : -EDGE_LINUX_EIO;
    }
    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(
        pool, cursor->record, &record_index);
    if (!record) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    if ((record->state !=
             KERNEL_SOCKET_RIGHTS_RECORD_DETACHED &&
         record->state !=
             KERNEL_SOCKET_RIGHTS_RECORD_QUEUED) ||
        record->descriptor_count !=
            cursor->descriptor_count) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EBUSY;
    }
    token = socket_rights_token_locked(
        pool, cursor->next_token, 0);
    if (!token ||
        token->state != SOCKET_RIGHTS_TOKEN_SOURCE ||
        token->owner_record != record_index) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    *lease = &token->lease;
    ++cursor->next_index;
    if (token->next == SOCKET_RIGHTS_INDEX_NONE)
        cursor->next_token = 0;
    else if (token->next >= pool->token_capacity) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        *lease = 0;
        return -EDGE_LINUX_EIO;
    } else {
        socket_rights_token_slot_t *next =
            &socket_rights_tokens(pool)[token->next];
        cursor->next_token = socket_rights_token_handle(
            token->next, next->generation);
    }
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return 1;
}

void kernel_socket_rights_queue_initialize(
        kernel_socket_rights_queue_t *queue,
        uint32_t limit) {
    if (!queue) return;
    memset(queue, 0, sizeof(*queue));
    queue->limit = limit;
}

uint32_t kernel_socket_rights_queue_count(
        const kernel_socket_rights_queue_t *queue) {
    return queue ?
        __atomic_load_n(&queue->count, __ATOMIC_ACQUIRE) : 0u;
}

int kernel_socket_rights_queue_enqueue(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue,
        kernel_socket_rights_record_handle_t *handle,
        kernel_socket_rights_association_kind_t association_kind,
        uint64_t association_sequence) {
    socket_rights_record_slot_t *record;
    socket_rights_record_slot_t *tail;
    uint64_t irq_flags;
    uint32_t count;

    if (!socket_rights_pool_valid(pool) ||
        !queue || !handle || !*handle ||
        (association_kind !=
             KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE &&
         association_kind !=
             KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET))
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&pool->lock);
    record = socket_rights_record_locked(pool, *handle, 0);
    if (!record) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_ESTALE;
    }
    if (record->state !=
        KERNEL_SOCKET_RIGHTS_RECORD_DETACHED) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EBUSY;
    }
    count = __atomic_load_n(
        &queue->count, __ATOMIC_RELAXED);
    if (count >= queue->limit) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    if (count) {
        tail = socket_rights_record_locked(
            pool, queue->tail, 0);
        if (!tail ||
            tail->state !=
                KERNEL_SOCKET_RIGHTS_RECORD_QUEUED) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return -EDGE_LINUX_EIO;
        }
        if (tail->association_kind !=
                (uint8_t)association_kind ||
            association_sequence <
                tail->association_sequence) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return -EDGE_LINUX_EINVAL;
        }
        tail->next_record = *handle;
    } else {
        queue->head = *handle;
    }
    queue->tail = *handle;
    record->association_sequence = association_sequence;
    record->next_record = 0;
    record->association_kind =
        (uint8_t)association_kind;
    record->state =
        KERNEL_SOCKET_RIGHTS_RECORD_QUEUED;
    __atomic_store_n(
        &queue->count, count + 1u, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    *handle = 0;
    return 0;
}

int kernel_socket_rights_queue_peek_at(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue,
        uint32_t ordinal,
        kernel_socket_rights_record_info_t *information) {
    socket_rights_record_slot_t *record;
    kernel_socket_rights_record_handle_t handle;
    uint64_t irq_flags;
    uint32_t count;

    if (!socket_rights_pool_valid(pool) ||
        !queue || !information)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&pool->lock);
    count = __atomic_load_n(
        &queue->count, __ATOMIC_RELAXED);
    if (ordinal >= count) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    handle = queue->head;
    for (uint32_t index = 0; index < ordinal; ++index) {
        record = socket_rights_record_locked(
            pool, handle, 0);
        if (!record ||
            record->state !=
                KERNEL_SOCKET_RIGHTS_RECORD_QUEUED ||
            !record->next_record) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return -EDGE_LINUX_EIO;
        }
        handle = record->next_record;
    }
    record = socket_rights_record_locked(
        pool, handle, 0);
    if (!record ||
        record->state !=
            KERNEL_SOCKET_RIGHTS_RECORD_QUEUED) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EIO;
    }
    socket_rights_record_fill_info(
        handle, record, information);
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return 0;
}

int kernel_socket_rights_queue_peek(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue,
        kernel_socket_rights_record_info_t *information) {
    return kernel_socket_rights_queue_peek_at(
        pool, queue, 0, information);
}

int kernel_socket_rights_queue_take(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue,
        kernel_socket_rights_record_handle_t *handle) {
    socket_rights_record_slot_t *record;
    kernel_socket_rights_record_handle_t taken;
    uint64_t irq_flags;
    uint32_t count;

    if (!socket_rights_pool_valid(pool) ||
        !queue || !handle)
        return -EDGE_LINUX_EINVAL;
    if (*handle) return -EDGE_LINUX_EBUSY;
    irq_flags = spin_lock_irqsave(&pool->lock);
    count = __atomic_load_n(
        &queue->count, __ATOMIC_RELAXED);
    if (!count) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EAGAIN;
    }
    taken = queue->head;
    record = socket_rights_record_locked(
        pool, taken, 0);
    if (!record ||
        record->state !=
            KERNEL_SOCKET_RIGHTS_RECORD_QUEUED) {
        spin_unlock_irqrestore(&pool->lock, irq_flags);
        return -EDGE_LINUX_EIO;
    }
    queue->head = record->next_record;
    --count;
    if (!count)
        queue->head = queue->tail = 0;
    record->next_record = 0;
    record->state =
        KERNEL_SOCKET_RIGHTS_RECORD_DETACHED;
    __atomic_store_n(
        &queue->count, count, __ATOMIC_RELEASE);
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    *handle = taken;
    return 0;
}

int kernel_socket_rights_queue_remove(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue,
        kernel_socket_rights_record_handle_t handle) {
    socket_rights_record_slot_t *record;
    socket_rights_record_slot_t *previous = 0;
    kernel_socket_rights_record_handle_t current;
    kernel_socket_rights_record_handle_t previous_handle = 0;
    uint64_t irq_flags;
    uint32_t count;

    if (!socket_rights_pool_valid(pool) ||
        !queue || !handle)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&pool->lock);
    count = __atomic_load_n(
        &queue->count, __ATOMIC_RELAXED);
    current = queue->head;
    for (uint32_t index = 0; index < count; ++index) {
        record = socket_rights_record_locked(
            pool, current, 0);
        if (!record ||
            record->state !=
                KERNEL_SOCKET_RIGHTS_RECORD_QUEUED) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return -EDGE_LINUX_EIO;
        }
        if (current == handle) {
            if (previous)
                previous->next_record =
                    record->next_record;
            else
                queue->head = record->next_record;
            if (queue->tail == handle)
                queue->tail = previous_handle;
            --count;
            if (!count)
                queue->head = queue->tail = 0;
            record->next_record = 0;
            record->state =
                KERNEL_SOCKET_RIGHTS_RECORD_DETACHED;
            __atomic_store_n(
                &queue->count, count, __ATOMIC_RELEASE);
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return 0;
        }
        previous = record;
        previous_handle = current;
        current = record->next_record;
        if (!current && index + 1u < count) {
            spin_unlock_irqrestore(&pool->lock, irq_flags);
            return -EDGE_LINUX_EIO;
        }
    }
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return -EDGE_LINUX_ESTALE;
}

int kernel_socket_rights_queue_drop(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue) {
    kernel_socket_rights_record_handle_t record = 0;
    int result;

    result = kernel_socket_rights_queue_take(
        pool, queue, &record);
    if (result < 0) return result;
    return kernel_socket_rights_record_drop(
        pool, &record);
}

int kernel_socket_rights_queue_clear(
        kernel_socket_rights_pool_t *pool,
        kernel_socket_rights_queue_t *queue) {
    int first_error = 0;

    if (!socket_rights_pool_valid(pool) || !queue)
        return -EDGE_LINUX_EINVAL;
    for (;;) {
        kernel_socket_rights_record_handle_t record = 0;
        int result = kernel_socket_rights_queue_take(
            pool, queue, &record);

        if (result == -EDGE_LINUX_EAGAIN)
            return first_error;
        if (result < 0)
            return first_error ? first_error : result;
        result = kernel_socket_rights_record_drop(
            pool, &record);
        if (result < 0 && !first_error)
            first_error = result;
    }
}
