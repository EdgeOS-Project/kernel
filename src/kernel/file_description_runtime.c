/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include "kernel/file_description_runtime.h"
#include "kernel/linux_errno.h"
#include "sys/spinlock.h"

#define FILE_DESCRIPTION_STATE_CLOSING        0x0001u
#define FILE_DESCRIPTION_STATE_DETACH_ACTIVE  0x0002u
#define FILE_DESCRIPTION_STATE_DETACH_AGAIN   0x0004u
#define FILE_DESCRIPTION_STATE_INPUT_REVOKED  0x0008u

#define FILE_DESCRIPTION_SLOT_MASK \
    (KERNEL_FILE_DESCRIPTION_CAPACITY - 1u)

_Static_assert(
    KERNEL_FILE_DESCRIPTION_CAPACITY != 0u &&
        (KERNEL_FILE_DESCRIPTION_CAPACITY &
         (KERNEL_FILE_DESCRIPTION_CAPACITY - 1u)) == 0u,
    "file-description capacity must be a power of two");
_Static_assert(
    KERNEL_FILE_DESCRIPTION_CAPACITY ==
        (1u << KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS),
    "file-description handle slot width must match capacity");
_Static_assert(
    KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS + 16u <= 31u,
    "file-description handles must remain positive signed integers");

typedef struct kernel_file_description_entry {
    uint64_t identity;
    uint64_t offset;
    uint64_t input_cursor;
    uint64_t position_sequence;
    uint64_t position_owner;
    kernel_file_description_position_t *position_wait_head;
    kernel_file_description_position_t *position_wait_tail;
    void *owned_payload;
    uint32_t references;
    uint32_t epoll_pins;
    uint32_t close_holds;
    uint32_t mount_namespace;
    uint32_t mount_generation;
    uint32_t status_flags;
    int32_t input_clock;
    int32_t async_owner;
    int32_t async_signal;
    uint16_t handle_generation;
    uint16_t lifecycle_flags;
} kernel_file_description_entry_t;

_Static_assert(sizeof(kernel_file_description_entry_t) == 104u,
               "file-description entry size");

static kernel_file_description_entry_t
    g_file_descriptions[KERNEL_FILE_DESCRIPTION_CAPACITY];
static spinlock_t g_file_description_lock;
static kernel_file_description_ops_t g_file_description_ops;
static uint64_t g_file_description_identity_sequence;
static volatile uint32_t g_file_description_initialization_state;

static void file_description_bytes_zero(void *destination, uint64_t length) {
    uint8_t *bytes = (uint8_t *)destination;
    while (length--) *bytes++ = 0;
}

static int file_description_runtime_ready(void) {
    return __atomic_load_n(&g_file_description_initialization_state,
                           __ATOMIC_ACQUIRE) == 2u;
}

static uint32_t file_description_hash(uint64_t identity) {
    identity ^= identity >> 33;
    identity *= UINT64_C(0xff51afd7ed558ccd);
    identity ^= identity >> 33;
    return (uint32_t)identity & FILE_DESCRIPTION_SLOT_MASK;
}

static uint32_t file_description_handle(uint32_t slot,
                                        uint16_t generation) {
    return ((uint32_t)generation <<
            KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS) | slot;
}

static int32_t file_description_identity_slot_locked(uint64_t identity) {
    uint32_t first;

    if (identity == KERNEL_FILE_DESCRIPTION_INVALID_ID ||
        identity == KERNEL_FILE_DESCRIPTION_TOMBSTONE_ID)
        return -1;
    first = file_description_hash(identity);
    for (uint32_t probe = 0;
         probe < KERNEL_FILE_DESCRIPTION_CAPACITY; ++probe) {
        uint32_t slot = (first + probe) & FILE_DESCRIPTION_SLOT_MASK;
        uint64_t candidate = g_file_descriptions[slot].identity;
        if (candidate == identity) return (int32_t)slot;
        if (candidate == KERNEL_FILE_DESCRIPTION_INVALID_ID) return -1;
    }
    return -1;
}

static int32_t file_description_insert_slot_locked(uint64_t identity) {
    int32_t first_tombstone = -1;
    uint32_t first = file_description_hash(identity);

    for (uint32_t probe = 0;
         probe < KERNEL_FILE_DESCRIPTION_CAPACITY; ++probe) {
        uint32_t slot = (first + probe) & FILE_DESCRIPTION_SLOT_MASK;
        uint64_t candidate = g_file_descriptions[slot].identity;
        if (candidate == KERNEL_FILE_DESCRIPTION_TOMBSTONE_ID) {
            if (first_tombstone < 0) first_tombstone = (int32_t)slot;
            continue;
        }
        if (candidate == KERNEL_FILE_DESCRIPTION_INVALID_ID)
            return first_tombstone >= 0 ?
                first_tombstone : (int32_t)slot;
    }
    return first_tombstone;
}

static uint64_t file_description_next_identity_locked(void) {
    /*
     * At most one identity per live slot can collide after counter wrap.
     * Capacity plus the two reserved values is therefore a sufficient search.
     */
    for (uint32_t attempt = 0;
         attempt < KERNEL_FILE_DESCRIPTION_CAPACITY + 2u; ++attempt) {
        uint64_t identity = ++g_file_description_identity_sequence;
        if (identity == KERNEL_FILE_DESCRIPTION_INVALID_ID ||
            identity == KERNEL_FILE_DESCRIPTION_TOMBSTONE_ID)
            continue;
        if (file_description_identity_slot_locked(identity) < 0)
            return identity;
    }
    return KERNEL_FILE_DESCRIPTION_INVALID_ID;
}

static kernel_file_description_entry_t *
file_description_entry_from_locator_locked(
    kernel_file_description_locator_t locator,
    uint32_t *slot_out,
    int require_live) {
    uint32_t slot;
    kernel_file_description_entry_t *entry;

    if (locator.kind == KERNEL_FILE_DESCRIPTION_BY_HANDLE) {
        uint32_t handle;
        uint16_t generation;
        if (!locator.value || locator.value > INT32_MAX) return 0;
        handle = (uint32_t)locator.value;
        generation = (uint16_t)(
            handle >> KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS);
        if (!generation) return 0;
        slot = handle & FILE_DESCRIPTION_SLOT_MASK;
        entry = &g_file_descriptions[slot];
        if (entry->handle_generation != generation)
            return 0;
    } else if (locator.kind == KERNEL_FILE_DESCRIPTION_BY_IDENTITY) {
        int32_t identity_slot =
            file_description_identity_slot_locked(locator.value);
        if (identity_slot < 0) return 0;
        slot = (uint32_t)identity_slot;
        entry = &g_file_descriptions[slot];
    } else {
        return 0;
    }

    if (entry->identity == KERNEL_FILE_DESCRIPTION_INVALID_ID ||
        entry->identity == KERNEL_FILE_DESCRIPTION_TOMBSTONE_ID ||
        (require_live &&
         (!entry->references ||
          (entry->lifecycle_flags & FILE_DESCRIPTION_STATE_CLOSING))))
        return 0;
    if (slot_out) *slot_out = slot;
    return entry;
}

static kernel_file_description_entry_t *
file_description_ticket_entry_locked(
    const kernel_file_description_release_t *release,
    uint32_t *slot_out) {
    uint32_t slot;
    uint32_t handle;
    uint16_t generation;
    kernel_file_description_entry_t *entry;

    if (!release || !release->active || !release->handle ||
        !release->identity)
        return 0;
    handle = release->handle;
    generation = (uint16_t)(
        handle >> KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS);
    if (!generation) return 0;
    slot = handle & FILE_DESCRIPTION_SLOT_MASK;
    entry = &g_file_descriptions[slot];
    if (entry->identity != release->identity ||
        entry->handle_generation != generation)
        return 0;
    if (slot_out) *slot_out = slot;
    return entry;
}

static kernel_file_description_entry_t *
file_description_position_token_entry_locked(
    const kernel_file_description_position_t *position) {
    uint32_t slot;
    uint16_t generation;
    kernel_file_description_entry_t *entry;

    if (!position || !position->active || !position->handle ||
        !position->identity || !position->owner)
        return 0;
    generation = (uint16_t)(
        position->handle >>
        KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS);
    if (!generation) return 0;
    slot = position->handle & FILE_DESCRIPTION_SLOT_MASK;
    entry = &g_file_descriptions[slot];
    if (entry->identity != position->identity ||
        entry->handle_generation != generation)
        return 0;
    return entry;
}

static kernel_file_description_entry_t *
file_description_position_entry_locked(
    const kernel_file_description_position_t *position) {
    kernel_file_description_entry_t *entry =
        file_description_position_token_entry_locked(position);
    if (!entry || !position->acquired ||
        entry->position_owner != position->owner)
        return 0;
    return entry;
}

static int file_description_request_detach_locked(
    kernel_file_description_entry_t *entry) {
    if (!entry ||
        !(entry->lifecycle_flags & FILE_DESCRIPTION_STATE_CLOSING))
        return 0;
    if (entry->lifecycle_flags & FILE_DESCRIPTION_STATE_DETACH_ACTIVE) {
        entry->lifecycle_flags |= FILE_DESCRIPTION_STATE_DETACH_AGAIN;
        return 0;
    }
    entry->lifecycle_flags |= FILE_DESCRIPTION_STATE_DETACH_ACTIVE;
    return 1;
}

static void *file_description_reclaim_locked(
    kernel_file_description_entry_t *entry) {
    void *payload;
    uint16_t generation;

    if (!entry || entry->references || entry->epoll_pins ||
        entry->position_owner ||
        entry->close_holds ||
        !(entry->lifecycle_flags & FILE_DESCRIPTION_STATE_CLOSING) ||
        (entry->lifecycle_flags &
         (FILE_DESCRIPTION_STATE_DETACH_ACTIVE |
          FILE_DESCRIPTION_STATE_DETACH_AGAIN)))
        return 0;
    payload = entry->owned_payload;
    generation = entry->handle_generation;
    file_description_bytes_zero(entry, sizeof(*entry));
    entry->handle_generation = generation;
    entry->identity = KERNEL_FILE_DESCRIPTION_TOMBSTONE_ID;
    return payload;
}

static void file_description_release_payload(void *payload) {
    if (payload && g_file_description_ops.release_payload)
        g_file_description_ops.release_payload(
            g_file_description_ops.context, payload);
}

static void file_description_drain_detach(uint32_t slot,
                                          uint16_t generation,
                                          uint64_t identity) {
    for (;;) {
        kernel_file_description_entry_t *entry;
        void *payload = 0;
        uint64_t irq_flags;

        g_file_description_ops.detach_description(
            g_file_description_ops.context, identity);

        irq_flags = spin_lock_irqsave(&g_file_description_lock);
        entry = &g_file_descriptions[slot];
        if (entry->identity != identity ||
            entry->handle_generation != generation) {
            spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
            return;
        }
        if (entry->lifecycle_flags &
            FILE_DESCRIPTION_STATE_DETACH_AGAIN) {
            entry->lifecycle_flags &=
                (uint16_t)~FILE_DESCRIPTION_STATE_DETACH_AGAIN;
            spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
            continue;
        }
        entry->lifecycle_flags &=
            (uint16_t)~FILE_DESCRIPTION_STATE_DETACH_ACTIVE;
        payload = file_description_reclaim_locked(entry);
        spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
        file_description_release_payload(payload);
        return;
    }
}

int kernel_file_description_runtime_initialize(
    const kernel_file_description_ops_t *ops) {
    if (!ops || !ops->detach_description)
        return -EDGE_LINUX_EINVAL;
    if (!__sync_bool_compare_and_swap(
            &g_file_description_initialization_state, 0u, 1u))
        return -EDGE_LINUX_EBUSY;

    file_description_bytes_zero(
        g_file_descriptions, sizeof(g_file_descriptions));
    file_description_bytes_zero(
        &g_file_description_ops, sizeof(g_file_description_ops));
    spinlock_init(&g_file_description_lock);
    g_file_description_identity_sequence = 0;
    g_file_description_ops = *ops;
    __atomic_store_n(&g_file_description_initialization_state, 2u,
                     __ATOMIC_RELEASE);
    return 0;
}

int kernel_file_description_create(
    uint64_t initial_offset,
    uint32_t initial_status_flags,
    void *owned_payload,
    uint32_t *handle,
    uint64_t *identity) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    uint64_t new_identity;
    int32_t slot;
    uint16_t generation;

    if (!handle || !identity) return -EDGE_LINUX_EINVAL;
    *handle = 0;
    *identity = 0;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    if (owned_payload && !g_file_description_ops.release_payload)
        return -EDGE_LINUX_EINVAL;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    new_identity = file_description_next_identity_locked();
    if (!new_identity) {
        spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
        return -EDGE_LINUX_ENFILE;
    }
    slot = file_description_insert_slot_locked(new_identity);
    if (slot < 0) {
        spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
        return -EDGE_LINUX_ENFILE;
    }

    entry = &g_file_descriptions[(uint32_t)slot];
    generation = (uint16_t)(entry->handle_generation + 1u);
    if (!generation) generation = 1u;
    file_description_bytes_zero(entry, sizeof(*entry));
    entry->offset = initial_offset;
    entry->owned_payload = owned_payload;
    entry->references = 1u;
    entry->mount_namespace =
        KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE;
    entry->status_flags = initial_status_flags;
    entry->input_clock = 0;
    entry->handle_generation = generation;
    entry->identity = new_identity;
    *handle = file_description_handle((uint32_t)slot, generation);
    *identity = new_identity;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return 0;
}

int kernel_file_description_retain(
    kernel_file_description_locator_t locator) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = locator.kind == KERNEL_FILE_DESCRIPTION_BY_HANDLE ||
                 locator.kind == KERNEL_FILE_DESCRIPTION_BY_IDENTITY ?
            -EDGE_LINUX_EBADF : -EDGE_LINUX_EINVAL;
    else if (entry->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else
        ++entry->references;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_release_begin(
    kernel_file_description_locator_t locator,
    kernel_file_description_release_t *release) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    uint64_t identity = 0;
    uint32_t handle = 0;
    uint32_t slot = 0;
    uint16_t generation = 0;
    int run_detach = 0;
    int result = 0;

    if (!release) return -EDGE_LINUX_EINVAL;
    file_description_bytes_zero(release, sizeof(*release));
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, &slot, 1);
    if (!entry) {
        result = locator.kind == KERNEL_FILE_DESCRIPTION_BY_HANDLE ||
                 locator.kind == KERNEL_FILE_DESCRIPTION_BY_IDENTITY ?
            -EDGE_LINUX_EBADF : -EDGE_LINUX_EINVAL;
    } else {
        --entry->references;
        release->remaining_references = entry->references;
        if (!entry->references) {
            entry->lifecycle_flags |= FILE_DESCRIPTION_STATE_CLOSING;
            entry->close_holds = 1u;
            identity = entry->identity;
            generation = entry->handle_generation;
            handle = file_description_handle(slot, generation);
            release->identity = identity;
            release->handle = handle;
            release->last_reference = 1u;
            release->active = 1u;
            run_detach =
                file_description_request_detach_locked(entry);
        }
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);

    if (run_detach)
        file_description_drain_detach(
            slot, generation, identity);
    return result;
}

int kernel_file_description_release_finish(
    kernel_file_description_release_t *release) {
    kernel_file_description_entry_t *entry;
    void *payload = 0;
    uint64_t irq_flags;

    if (!release || !release->active)
        return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_ticket_entry_locked(release, 0);
    if (!entry || !entry->close_holds) {
        spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
        return -EDGE_LINUX_EBADF;
    }
    --entry->close_holds;
    release->active = 0u;
    payload = file_description_reclaim_locked(entry);
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    file_description_release_payload(payload);
    return 0;
}

int kernel_file_description_pin_identity(uint64_t identity) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int32_t slot;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    slot = file_description_identity_slot_locked(identity);
    entry = slot >= 0 ? &g_file_descriptions[(uint32_t)slot] : 0;
    if (!entry || !entry->references ||
        (entry->lifecycle_flags & FILE_DESCRIPTION_STATE_CLOSING))
        result = -EDGE_LINUX_EBADF;
    else if (entry->epoll_pins == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else
        ++entry->epoll_pins;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_unpin_identity(uint64_t identity) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    uint32_t slot = 0;
    uint16_t generation = 0;
    int32_t identity_slot;
    int run_detach = 0;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    identity_slot = file_description_identity_slot_locked(identity);
    entry = identity_slot >= 0 ?
        &g_file_descriptions[(uint32_t)identity_slot] : 0;
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (!entry->epoll_pins)
        result = -EDGE_LINUX_EINVAL;
    else {
        --entry->epoll_pins;
        if (!entry->references) {
            slot = (uint32_t)identity_slot;
            generation = entry->handle_generation;
            run_detach =
                file_description_request_detach_locked(entry);
        }
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);

    if (run_detach)
        file_description_drain_detach(
            slot, generation, identity);
    return result;
}

int kernel_file_description_snapshot(
    kernel_file_description_locator_t locator,
    kernel_file_description_snapshot_t *snapshot) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    uint32_t slot = 0;
    int result = 0;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    file_description_bytes_zero(snapshot, sizeof(*snapshot));
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, &slot, 1);
    if (!entry) {
        result = locator.kind == KERNEL_FILE_DESCRIPTION_BY_HANDLE ||
                 locator.kind == KERNEL_FILE_DESCRIPTION_BY_IDENTITY ?
            -EDGE_LINUX_EBADF : -EDGE_LINUX_EINVAL;
    } else {
        snapshot->identity = entry->identity;
        snapshot->offset = entry->offset;
        snapshot->input_cursor = entry->input_cursor;
        snapshot->handle =
            file_description_handle(slot, entry->handle_generation);
        snapshot->references = entry->references;
        snapshot->epoll_pins = entry->epoll_pins;
        snapshot->mount_namespace = entry->mount_namespace;
        snapshot->mount_generation = entry->mount_generation;
        snapshot->status_flags = entry->status_flags;
        snapshot->input_clock = entry->input_clock;
        snapshot->input_revoked =
            (entry->lifecycle_flags &
             FILE_DESCRIPTION_STATE_INPUT_REVOKED) != 0;
        snapshot->async_owner = entry->async_owner;
        snapshot->async_signal = entry->async_signal;
        snapshot->position_busy = entry->position_owner != 0;
        snapshot->mount_monitor_configured =
            entry->mount_namespace !=
                KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_identity(
    kernel_file_description_locator_t locator,
    uint64_t *identity) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!identity) return -EDGE_LINUX_EINVAL;
    *identity = 0;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = locator.kind == KERNEL_FILE_DESCRIPTION_BY_HANDLE ||
                 locator.kind == KERNEL_FILE_DESCRIPTION_BY_IDENTITY ?
            -EDGE_LINUX_EBADF : -EDGE_LINUX_EINVAL;
    else
        *identity = entry->identity;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_offset_load(
    kernel_file_description_locator_t locator,
    uint64_t *offset) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!offset) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        *offset = entry->offset;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_offset_store(
    kernel_file_description_locator_t locator,
    uint64_t offset) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (entry->position_owner)
        result = -EDGE_LINUX_EAGAIN;
    else
        entry->offset = offset;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_offset_compare_exchange(
    kernel_file_description_locator_t locator,
    uint64_t *expected,
    uint64_t desired) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result;

    if (!expected) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (entry->position_owner)
        result = -EDGE_LINUX_EAGAIN;
    else if (entry->offset != *expected) {
        *expected = entry->offset;
        result = 0;
    } else {
        entry->offset = desired;
        result = 1;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_offset_add(
    kernel_file_description_locator_t locator,
    uint64_t amount,
    uint64_t *new_offset) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!new_offset) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (entry->position_owner)
        result = -EDGE_LINUX_EAGAIN;
    else if (UINT64_MAX - entry->offset < amount)
        result = -EDGE_LINUX_EOVERFLOW;
    else {
        entry->offset += amount;
        *new_offset = entry->offset;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_position_reserve(
    kernel_file_description_locator_t locator,
    kernel_file_description_position_t *position) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    uint32_t slot = 0;
    int result;

    if (!position) return -EDGE_LINUX_EINVAL;
    file_description_bytes_zero(position, sizeof(*position));
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, &slot, 1);
    if (!entry) {
        result = locator.kind == KERNEL_FILE_DESCRIPTION_BY_HANDLE ||
                 locator.kind == KERNEL_FILE_DESCRIPTION_BY_IDENTITY ?
            -EDGE_LINUX_EBADF : -EDGE_LINUX_EINVAL;
    } else {
        ++entry->position_sequence;
        if (!entry->position_sequence)
            ++entry->position_sequence;
        position->identity = entry->identity;
        position->owner = entry->position_sequence;
        position->handle =
            file_description_handle(slot, entry->handle_generation);
        position->active = 1u;
        if (!entry->position_owner) {
            entry->position_owner = position->owner;
            position->offset = entry->offset;
            position->acquired = 1u;
            result = 1;
        } else {
            if (entry->position_wait_tail)
                entry->position_wait_tail->next = position;
            else
                entry->position_wait_head = position;
            entry->position_wait_tail = position;
            result = 0;
        }
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_position_poll(
    kernel_file_description_position_t *position) {
    kernel_file_description_entry_t *entry;
    kernel_file_description_position_t *waiter;
    uint64_t irq_flags;
    int result;

    if (!position || !position->active)
        return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_position_token_entry_locked(position);
    if (!entry) {
        result = -EDGE_LINUX_EBADF;
    } else if (position->acquired) {
        result = entry->position_owner == position->owner ?
            1 : -EDGE_LINUX_EBADF;
    } else {
        waiter = entry->position_wait_head;
        while (waiter && waiter != position)
            waiter = waiter->next;
        result = waiter ? 0 : -EDGE_LINUX_EBADF;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

static void file_description_position_grant_next_locked(
    kernel_file_description_entry_t *entry) {
    kernel_file_description_position_t *next;

    if (!entry) return;
    entry->position_owner = 0;
    next = entry->position_wait_head;
    if (!next) {
        entry->position_wait_tail = 0;
        return;
    }
    entry->position_wait_head = next->next;
    if (!entry->position_wait_head)
        entry->position_wait_tail = 0;
    next->next = 0;
    next->offset = entry->offset;
    next->acquired = 1u;
    entry->position_owner = next->owner;
}

static int file_description_position_finish(
    kernel_file_description_position_t *position,
    uint64_t new_offset, int commit) {
    kernel_file_description_entry_t *entry;
    void *payload = 0;
    uint64_t irq_flags;

    if (!position || !position->active)
        return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_position_entry_locked(position);
    if (!entry) {
        spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
        return -EDGE_LINUX_EBADF;
    }
    if (commit) entry->offset = new_offset;
    file_description_position_grant_next_locked(entry);
    position->active = 0u;
    position->acquired = 0u;
    position->next = 0;
    payload = file_description_reclaim_locked(entry);
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    file_description_release_payload(payload);
    return 0;
}

int kernel_file_description_position_try_begin(
    kernel_file_description_locator_t locator,
    kernel_file_description_position_t *position) {
    int result = kernel_file_description_position_reserve(
        locator, position);

    if (result < 0) return result;
    if (result == 1) return 0;
    if (kernel_file_description_position_abort(position) < 0)
        return -EDGE_LINUX_EBADF;
    return -EDGE_LINUX_EAGAIN;
}

int kernel_file_description_position_commit(
    kernel_file_description_position_t *position,
    uint64_t new_offset) {
    return file_description_position_finish(
        position, new_offset, 1);
}

int kernel_file_description_position_abort(
    kernel_file_description_position_t *position) {
    kernel_file_description_entry_t *entry;
    kernel_file_description_position_t *previous;
    kernel_file_description_position_t *waiter;
    void *payload = 0;
    uint64_t irq_flags;

    if (!position || !position->active)
        return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_position_token_entry_locked(position);
    if (entry && position->acquired &&
        entry->position_owner == position->owner) {
        file_description_position_grant_next_locked(entry);
        position->active = 0u;
        position->acquired = 0u;
        position->next = 0;
        payload = file_description_reclaim_locked(entry);
        spin_unlock_irqrestore(
            &g_file_description_lock, irq_flags);
        file_description_release_payload(payload);
        return 0;
    }
    previous = 0;
    waiter = entry ? entry->position_wait_head : 0;
    while (waiter && waiter != position) {
        previous = waiter;
        waiter = waiter->next;
    }
    if (!waiter) {
        spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
        return -EDGE_LINUX_EBADF;
    }
    if (previous)
        previous->next = waiter->next;
    else
        entry->position_wait_head = waiter->next;
    if (entry->position_wait_tail == waiter)
        entry->position_wait_tail = previous;
    position->active = 0u;
    position->next = 0;
    payload = file_description_reclaim_locked(entry);
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    file_description_release_payload(payload);
    return 0;
}

int kernel_file_description_input_state_load(
    kernel_file_description_locator_t locator,
    uint64_t *cursor,
    int32_t *clock_id) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!cursor || !clock_id) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else {
        *cursor = entry->input_cursor;
        *clock_id = entry->input_clock;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_input_cursor_store(
    kernel_file_description_locator_t locator,
    uint64_t cursor) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        entry->input_cursor = cursor;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_input_cursor_compare_exchange(
    kernel_file_description_locator_t locator,
    uint64_t *expected,
    uint64_t desired) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result;

    if (!expected) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (entry->input_cursor != *expected) {
        *expected = entry->input_cursor;
        result = 0;
    } else {
        entry->input_cursor = desired;
        result = 1;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_input_clock_store(
    kernel_file_description_locator_t locator,
    int32_t clock_id) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        entry->input_clock = clock_id;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_input_revoked(
    kernel_file_description_locator_t locator) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(locator, 0, 1);
    result = entry ?
        (entry->lifecycle_flags &
         FILE_DESCRIPTION_STATE_INPUT_REVOKED) != 0 :
        -EDGE_LINUX_EBADF;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_input_revoke(
    kernel_file_description_locator_t locator) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        entry->lifecycle_flags |= FILE_DESCRIPTION_STATE_INPUT_REVOKED;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_mount_bind(
    kernel_file_description_locator_t locator,
    uint32_t namespace_id,
    uint32_t observed_generation) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else {
        entry->mount_namespace = namespace_id;
        entry->mount_generation =
            namespace_id == KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE ?
                0u : observed_generation;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_mount_snapshot(
    kernel_file_description_locator_t locator,
    uint32_t *namespace_id,
    uint32_t *observed_generation) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!namespace_id || !observed_generation)
        return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (entry->mount_namespace ==
             KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE)
        result = -EDGE_LINUX_ENODATA;
    else {
        *namespace_id = entry->mount_namespace;
        *observed_generation = entry->mount_generation;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_mount_acknowledge(
    kernel_file_description_locator_t locator,
    uint32_t expected_namespace,
    uint32_t new_generation) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else if (entry->mount_namespace ==
             KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE)
        result = -EDGE_LINUX_ENODATA;
    else if (entry->mount_namespace != expected_namespace)
        result = -EDGE_LINUX_EAGAIN;
    else
        entry->mount_generation = new_generation;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_status_load(
    kernel_file_description_locator_t locator,
    uint32_t *status_flags) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!status_flags) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        *status_flags = entry->status_flags;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_status_update(
    kernel_file_description_locator_t locator,
    uint32_t mask,
    uint32_t value) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        entry->status_flags =
            (entry->status_flags & ~mask) | (value & mask);
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_async_state_load(
    kernel_file_description_locator_t locator,
    int32_t *owner,
    int32_t *signal) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!owner || !signal) return -EDGE_LINUX_EINVAL;
    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else {
        *owner = entry->async_owner;
        *signal = entry->async_signal;
    }
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_async_owner_store(
    kernel_file_description_locator_t locator,
    int32_t owner) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        entry->async_owner = owner;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}

int kernel_file_description_async_signal_store(
    kernel_file_description_locator_t locator,
    int32_t signal) {
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    int result = 0;

    if (!file_description_runtime_ready())
        return -EDGE_LINUX_ENODEV;
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = file_description_entry_from_locator_locked(
        locator, 0, 1);
    if (!entry)
        result = -EDGE_LINUX_EBADF;
    else
        entry->async_signal = signal;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    return result;
}
