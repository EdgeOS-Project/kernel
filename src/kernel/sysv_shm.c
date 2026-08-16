/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux SysV shared-memory core.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/sysv_shm_runtime.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

#define KERNEL_SYSV_SHM_SEGMENT_MAX 32u
#define KERNEL_SYSV_SHM_ATTACHMENT_MAX 256u
#define KERNEL_SYSV_SHM_SEGMENT_MAX_PAGES 8192u
#define KERNEL_SYSV_SHM_PAGE_SIZE 4096u

enum kernel_sysv_shm_segment_state {
    KERNEL_SYSV_SHM_FREE = 0,
    KERNEL_SYSV_SHM_INITIALIZING,
    KERNEL_SYSV_SHM_ACTIVE,
    KERNEL_SYSV_SHM_DESTROYING,
};

typedef struct kernel_sysv_shm_segment {
    uint8_t state;
    uint8_t removed;
    uint16_t reserved;
    int32_t identifier;
    int32_t key;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint32_t sequence;
    uint32_t page_count;
    uint64_t size;
    uint64_t atime_us;
    uint64_t dtime_us;
    uint64_t ctime_us;
    int32_t creator_pid;
    int32_t last_pid;
    uint32_t attachment_count;
    kernel_sysv_shm_page_t pages[KERNEL_SYSV_SHM_SEGMENT_MAX_PAGES];
} kernel_sysv_shm_segment_t;

typedef struct kernel_sysv_shm_attachment {
    uint8_t used;
    uint8_t segment_index;
    uint16_t reserved;
    int32_t pid;
    uint32_t attachment_id;
    uintptr_t address_space;
    uint64_t address;
    uint64_t length;
    uint64_t detach_address;
} kernel_sysv_shm_attachment_t;

static kernel_sysv_shm_segment_t
    g_sysv_shm_segments[KERNEL_SYSV_SHM_SEGMENT_MAX];
static kernel_sysv_shm_attachment_t
    g_sysv_shm_attachments[KERNEL_SYSV_SHM_ATTACHMENT_MAX];
static spinlock_t g_sysv_shm_lock;
static uint32_t g_sysv_shm_next_identifier = 1u;
static uint32_t g_sysv_shm_next_sequence = 1u;
static uint32_t g_sysv_shm_next_attachment_id = 1u;

static uint64_t kernel_sysv_shm_page_align(uint64_t value) {
    if (value > UINT64_MAX - (KERNEL_SYSV_SHM_PAGE_SIZE - 1u)) return 0;
    return (value + KERNEL_SYSV_SHM_PAGE_SIZE - 1u) &
           ~(uint64_t)(KERNEL_SYSV_SHM_PAGE_SIZE - 1u);
}

static int kernel_sysv_shm_segment_by_identifier_locked(int32_t identifier) {
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index) {
        const kernel_sysv_shm_segment_t *segment = &g_sysv_shm_segments[index];
        if (segment->state == KERNEL_SYSV_SHM_ACTIVE &&
            segment->identifier == identifier)
            return (int)index;
    }
    return -1;
}

static int kernel_sysv_shm_segment_by_key_locked(int32_t key) {
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index) {
        const kernel_sysv_shm_segment_t *segment = &g_sysv_shm_segments[index];
        if (segment->state == KERNEL_SYSV_SHM_ACTIVE && !segment->removed &&
            segment->key == key)
            return (int)index;
    }
    return -1;
}

static int kernel_sysv_shm_free_segment_locked(void) {
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index)
        if (g_sysv_shm_segments[index].state == KERNEL_SYSV_SHM_FREE)
            return (int)index;
    return -1;
}

static int kernel_sysv_shm_capable(const kernel_linux_identity_t *identity,
                                   uint32_t capability) {
    return identity && capability < 64u &&
           (identity->effective_capabilities & (1ull << capability));
}

static uint32_t kernel_sysv_shm_granted_bits(
    const kernel_sysv_shm_segment_t *segment,
    const kernel_linux_identity_t *identity) {
    if (identity->euid == segment->uid || identity->euid == segment->cuid)
        return (segment->mode >> 6) & 7u;
    if (kernel_current_in_group(segment->gid) ||
        kernel_current_in_group(segment->cgid))
        return (segment->mode >> 3) & 7u;
    return segment->mode & 7u;
}

static int kernel_sysv_shm_has_access(
    const kernel_sysv_shm_segment_t *segment,
    const kernel_linux_identity_t *identity, uint32_t requested) {
    if ((kernel_sysv_shm_granted_bits(segment, identity) & requested) ==
        requested)
        return 1;
    return kernel_sysv_shm_capable(identity, EDGE_LINUX_CAP_IPC_OWNER);
}

static int kernel_sysv_shm_is_owner(
    const kernel_sysv_shm_segment_t *segment,
    const kernel_linux_identity_t *identity) {
    return identity &&
           (identity->euid == segment->uid ||
            identity->euid == segment->cuid ||
            kernel_sysv_shm_capable(identity, EDGE_LINUX_CAP_SYS_ADMIN));
}

static void kernel_sysv_shm_destroy_if_unused(uint32_t index) {
    kernel_sysv_shm_segment_t *segment;
    uint32_t page_count;
    uint64_t lock_flags;

    if (index >= KERNEL_SYSV_SHM_SEGMENT_MAX) return;
    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    segment = &g_sysv_shm_segments[index];
    if (segment->state != KERNEL_SYSV_SHM_ACTIVE || !segment->removed ||
        segment->attachment_count) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return;
    }
    segment->state = KERNEL_SYSV_SHM_DESTROYING;
    page_count = segment->page_count;
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);

    for (uint32_t page = 0; page < page_count; ++page)
        kernel_sysv_shm_arch_page_release(segment->pages[page]);

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    memset(segment, 0, sizeof(*segment));
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
}

int64_t kernel_sysv_shm_get(int32_t key, uint64_t size, uint32_t flags) {
    kernel_linux_identity_t identity;
    kernel_sysv_shm_segment_t *segment;
    uint64_t rounded_size;
    uint64_t lock_flags;
    uint32_t page_count;
    int segment_index;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (flags & ~(0777u | KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL |
                  KERNEL_SYSV_SHM_NORESERVE))
        return -EDGE_LINUX_EINVAL;

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    if (key != KERNEL_SYSV_IPC_PRIVATE) {
        segment_index = kernel_sysv_shm_segment_by_key_locked(key);
        if (segment_index >= 0) {
            uint32_t requested = ((flags & 0444u) ? 4u : 0u) |
                                 ((flags & 0222u) ? 2u : 0u);
            segment = &g_sysv_shm_segments[segment_index];
            if ((flags & (KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL)) ==
                (KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL)) {
                spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
                return -EDGE_LINUX_EEXIST;
            }
            if (size && size > segment->size) {
                spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
                return -EDGE_LINUX_EINVAL;
            }
            if (!kernel_sysv_shm_has_access(segment, &identity, requested)) {
                spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
                return -EDGE_LINUX_EACCES;
            }
            segment_index = segment->identifier;
            spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
            return segment_index;
        }
        if (!(flags & KERNEL_SYSV_IPC_CREAT)) {
            spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
            return -EDGE_LINUX_ENOENT;
        }
    }
    rounded_size = kernel_sysv_shm_page_align(size);
    if (!size || !rounded_size) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    page_count = (uint32_t)(rounded_size / KERNEL_SYSV_SHM_PAGE_SIZE);
    if (!page_count || page_count > KERNEL_SYSV_SHM_SEGMENT_MAX_PAGES) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    segment_index = kernel_sysv_shm_free_segment_locked();
    if (segment_index < 0) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_ENOSPC;
    }
    segment = &g_sysv_shm_segments[segment_index];
    memset(segment, 0, sizeof(*segment));
    segment->state = KERNEL_SYSV_SHM_INITIALIZING;
    segment->identifier = (int32_t)g_sysv_shm_next_identifier++;
    if (!g_sysv_shm_next_identifier) g_sysv_shm_next_identifier = 1u;
    segment->sequence = g_sysv_shm_next_sequence++;
    if (!g_sysv_shm_next_sequence) g_sysv_shm_next_sequence = 1u;
    segment->key = key;
    segment->mode = flags & 0777u;
    segment->uid = identity.euid;
    segment->gid = identity.egid;
    segment->cuid = identity.euid;
    segment->cgid = identity.egid;
    segment->size = size;
    segment->page_count = page_count;
    segment->creator_pid = identity.tgid;
    segment->last_pid = identity.tgid;
    segment->ctime_us = boottime_realtime_us();
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);

    for (uint32_t page = 0; page < page_count; ++page) {
        if (kernel_sysv_shm_arch_page_allocate(&segment->pages[page]) < 0) {
            for (uint32_t allocated = 0; allocated < page; ++allocated)
                kernel_sysv_shm_arch_page_release(segment->pages[allocated]);
            lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
            memset(segment, 0, sizeof(*segment));
            spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
            return -EDGE_LINUX_ENOMEM;
        }
    }

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    segment->state = KERNEL_SYSV_SHM_ACTIVE;
    segment_index = segment->identifier;
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    return segment_index;
}

int64_t kernel_sysv_shm_attach(int32_t identifier, uint64_t address,
                               uint32_t flags) {
    kernel_linux_identity_t identity;
    kernel_sysv_shm_segment_t *segment;
    kernel_sysv_shm_attachment_t *attachment;
    uintptr_t address_space;
    uint64_t mapped_address = 0;
    uint64_t rounded_size;
    uint64_t lock_flags;
    uint64_t replacement_end = 0;
    uint32_t requested_access;
    uint16_t replacement_attachments[KERNEL_SYSV_SHM_ATTACHMENT_MAX];
    uint16_t reserved_attachments[KERNEL_SYSV_SHM_ATTACHMENT_MAX];
    uint8_t destroy_segments[KERNEL_SYSV_SHM_SEGMENT_MAX];
    uint32_t replacement_count = 0;
    uint32_t replacement_split_count = 0;
    uint32_t reserved_count = 0;
    uint32_t map_flags = flags;
    int attachment_index;
    int segment_index;
    int status;

    if (flags & ~(KERNEL_SYSV_SHM_RDONLY | KERNEL_SYSV_SHM_RND |
                  KERNEL_SYSV_SHM_REMAP | KERNEL_SYSV_SHM_EXEC))
        return -EDGE_LINUX_EINVAL;
    if ((flags & KERNEL_SYSV_SHM_REMAP) && !address)
        return -EDGE_LINUX_EINVAL;
    if (address && (flags & KERNEL_SYSV_SHM_RND))
        address &= ~(uint64_t)(KERNEL_SYSV_SHMLBA - 1u);
    if (address && (address & (KERNEL_SYSV_SHM_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    address_space = kernel_sysv_shm_arch_current_address_space();
    if (!address_space) return -EDGE_LINUX_ESRCH;
    memset(destroy_segments, 0, sizeof(destroy_segments));

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    segment_index = kernel_sysv_shm_segment_by_identifier_locked(identifier);
    if (segment_index < 0) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    segment = &g_sysv_shm_segments[segment_index];
    requested_access = (flags & KERNEL_SYSV_SHM_RDONLY) ? 4u : 6u;
    if (!kernel_sysv_shm_has_access(segment, &identity, requested_access)) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EACCES;
    }
    rounded_size = kernel_sysv_shm_page_align(segment->size);
    if ((flags & KERNEL_SYSV_SHM_REMAP) &&
        address > UINT64_MAX - rounded_size) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    if (flags & KERNEL_SYSV_SHM_REMAP) {
        replacement_end = address + rounded_size;
        for (uint32_t index = 0;
             index < KERNEL_SYSV_SHM_ATTACHMENT_MAX; ++index) {
            kernel_sysv_shm_attachment_t *candidate =
                &g_sysv_shm_attachments[index];
            uint64_t candidate_end;

            if (candidate->used != 1u ||
                candidate->address_space != address_space)
                continue;
            candidate_end = candidate->address + candidate->length;
            if (address >= candidate_end ||
                candidate->address >= replacement_end)
                continue;
            /*
             * Keep surviving fragments associated with their originating
             * shmat operation.  Linux counts each surviving VMA fragment in
             * shm_nattch, while shmdt still finds the group by its original
             * address and leaves a SHM_REMAP mapping between them untouched.
             */
            if (candidate->address < address ||
                candidate_end > replacement_end) {
                if (candidate->address < address &&
                    candidate_end > replacement_end)
                    replacement_split_count++;
            }
            replacement_attachments[replacement_count++] = (uint16_t)index;
        }
    }
    for (uint32_t index = 0;
         index < KERNEL_SYSV_SHM_ATTACHMENT_MAX &&
         reserved_count < 1u + replacement_split_count; ++index) {
        if (g_sysv_shm_attachments[index].used) continue;
        g_sysv_shm_attachments[index].used = 2u;
        reserved_attachments[reserved_count++] = (uint16_t)index;
    }
    if (reserved_count < 1u + replacement_split_count) {
        for (uint32_t index = 0; index < reserved_count; ++index)
            memset(&g_sysv_shm_attachments[reserved_attachments[index]], 0,
                   sizeof(g_sysv_shm_attachments[0]));
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_ENOMEM;
    }
    attachment_index = reserved_attachments[0];
    attachment = &g_sysv_shm_attachments[attachment_index];
    memset(attachment, 0, sizeof(*attachment));
    attachment->used = 2u;
    attachment->segment_index = (uint8_t)segment_index;
    attachment->pid = identity.tgid;
    attachment->attachment_id = g_sysv_shm_next_attachment_id++;
    if (!g_sysv_shm_next_attachment_id)
        g_sysv_shm_next_attachment_id = 1u;
    attachment->address_space = address_space;
    attachment->length = rounded_size;
    for (uint32_t index = 0; index < replacement_count; ++index)
        g_sysv_shm_attachments[replacement_attachments[index]].used = 2u;
    segment->attachment_count++;
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);

    if (flags & KERNEL_SYSV_SHM_REMAP) {
        status = kernel_sysv_shm_arch_unmap(
            address_space, address, rounded_size);
        if (status < 0) {
            lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
            for (uint32_t index = 0; index < replacement_count; ++index)
                g_sysv_shm_attachments[replacement_attachments[index]].used =
                    1u;
            for (uint32_t index = 0; index < reserved_count; ++index)
                memset(&g_sysv_shm_attachments[reserved_attachments[index]],
                       0, sizeof(g_sysv_shm_attachments[0]));
            if (segment->attachment_count) segment->attachment_count--;
            spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
            kernel_sysv_shm_destroy_if_unused((uint32_t)segment_index);
            return status;
        }

        lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
        uint32_t split_slot = 1u;
        for (uint32_t index = 0; index < replacement_count; ++index) {
            kernel_sysv_shm_attachment_t *replaced =
                &g_sysv_shm_attachments[replacement_attachments[index]];
            kernel_sysv_shm_segment_t *replaced_segment =
                &g_sysv_shm_segments[replaced->segment_index];
            uint32_t replaced_segment_index = replaced->segment_index;
            uint64_t old_end = replaced->address + replaced->length;

            if (address <= replaced->address &&
                replacement_end >= old_end) {
                if (replaced_segment->state == KERNEL_SYSV_SHM_ACTIVE &&
                    replaced_segment->attachment_count)
                    replaced_segment->attachment_count--;
                memset(replaced, 0, sizeof(*replaced));
            } else if (address <= replaced->address) {
                replaced->address = replacement_end;
                replaced->length = old_end - replacement_end;
                replaced->used = 1u;
            } else if (replacement_end >= old_end) {
                replaced->length = address - replaced->address;
                replaced->used = 1u;
            } else {
                kernel_sysv_shm_attachment_t original = *replaced;
                kernel_sysv_shm_attachment_t *upper =
                    &g_sysv_shm_attachments[
                        reserved_attachments[split_slot++]];
                replaced->length = address - replaced->address;
                replaced->used = 1u;
                *upper = original;
                upper->used = 1u;
                upper->address = replacement_end;
                upper->length = old_end - replacement_end;
                if (replaced_segment->state == KERNEL_SYSV_SHM_ACTIVE)
                    replaced_segment->attachment_count++;
            }
            if (replaced_segment->state == KERNEL_SYSV_SHM_ACTIVE) {
                replaced_segment->last_pid = identity.tgid;
                replaced_segment->dtime_us = boottime_realtime_us();
                if (replaced_segment->removed &&
                    !replaced_segment->attachment_count)
                    destroy_segments[replaced_segment_index] = 1u;
            }
        }
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        map_flags &= ~KERNEL_SYSV_SHM_REMAP;
    }

    status = kernel_sysv_shm_arch_map(
        address_space, address, rounded_size, segment->pages,
        segment->page_count, map_flags, &mapped_address);

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    if (status < 0) {
        memset(attachment, 0, sizeof(*attachment));
        if (segment->attachment_count) segment->attachment_count--;
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        kernel_sysv_shm_destroy_if_unused((uint32_t)segment_index);
        for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index)
            if (destroy_segments[index])
                kernel_sysv_shm_destroy_if_unused(index);
        return status;
    }
    attachment->used = 1u;
    attachment->address = mapped_address;
    attachment->detach_address = mapped_address;
    segment->last_pid = identity.tgid;
    segment->atime_us = boottime_realtime_us();
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index)
        if (destroy_segments[index])
            kernel_sysv_shm_destroy_if_unused(index);
    return (int64_t)mapped_address;
}

int kernel_sysv_shm_detach(uint64_t address) {
    kernel_linux_identity_t identity;
    kernel_sysv_shm_segment_t *segment;
    uintptr_t address_space;
    uint64_t lock_flags;
    uint32_t attachment_id = 0;
    uint32_t segment_index = 0;
    int status = 0;

    if (!address || (address & (KERNEL_SYSV_SHM_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    address_space = kernel_sysv_shm_arch_current_address_space();
    if (!address_space) return -EDGE_LINUX_ESRCH;

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_ATTACHMENT_MAX; ++index) {
        const kernel_sysv_shm_attachment_t *candidate =
            &g_sysv_shm_attachments[index];
        if (candidate->used != 1u ||
            candidate->address_space != address_space ||
            candidate->detach_address != address)
            continue;
        attachment_id = candidate->attachment_id;
        segment_index = candidate->segment_index;
        break;
    }
    if (!attachment_id) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_ATTACHMENT_MAX; ++index) {
        kernel_sysv_shm_attachment_t *candidate =
            &g_sysv_shm_attachments[index];
        if (candidate->used != 1u ||
            candidate->address_space != address_space ||
            candidate->attachment_id != attachment_id)
            continue;
        candidate->used = 2u;
    }
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);

    for (;;) {
        kernel_sysv_shm_attachment_t *fragment = 0;
        uint64_t fragment_address = 0;
        uint64_t fragment_length = 0;
        int unmap_status;

        lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
        for (uint32_t index = 0;
             index < KERNEL_SYSV_SHM_ATTACHMENT_MAX; ++index) {
            kernel_sysv_shm_attachment_t *candidate =
                &g_sysv_shm_attachments[index];
            if (candidate->used != 2u ||
                candidate->address_space != address_space ||
                candidate->attachment_id != attachment_id)
                continue;
            fragment = candidate;
            fragment_address = candidate->address;
            fragment_length = candidate->length;
            candidate->used = 3u;
            break;
        }
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        if (!fragment) break;

        unmap_status = kernel_sysv_shm_arch_unmap(
            address_space, fragment_address, fragment_length);
        lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
        if (unmap_status < 0) {
            if (!status) status = unmap_status;
            fragment->used = 1u;
        } else {
            segment = &g_sysv_shm_segments[segment_index];
            if (segment->state == KERNEL_SYSV_SHM_ACTIVE) {
                if (segment->attachment_count)
                    segment->attachment_count--;
                segment->last_pid = identity.tgid;
                segment->dtime_us = boottime_realtime_us();
            }
            memset(fragment, 0, sizeof(*fragment));
        }
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    }
    kernel_sysv_shm_destroy_if_unused(segment_index);
    return status;
}

int kernel_sysv_shm_control(int32_t identifier, uint32_t command,
                            struct edge_linux_shmid_ds64 *information) {
    kernel_linux_identity_t identity;
    kernel_sysv_shm_segment_t *segment;
    uint64_t lock_flags;
    uint32_t operation = command & 0xffu;
    int segment_index;
    int result = 0;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (command & ~(KERNEL_SYSV_IPC_64 | 0xffu))
        return -EDGE_LINUX_EINVAL;

    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    segment_index = kernel_sysv_shm_segment_by_identifier_locked(identifier);
    if (segment_index < 0) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    segment = &g_sysv_shm_segments[segment_index];
    switch (operation) {
        case KERNEL_SYSV_IPC_RMID:
            if (!kernel_sysv_shm_is_owner(segment, &identity)) {
                result = -EDGE_LINUX_EPERM;
                break;
            }
            segment->removed = 1u;
            segment->last_pid = identity.tgid;
            break;
        case KERNEL_SYSV_IPC_STAT:
            if (!information) {
                result = -EDGE_LINUX_EFAULT;
                break;
            }
            if (!kernel_sysv_shm_has_access(segment, &identity, 4u)) {
                result = -EDGE_LINUX_EACCES;
                break;
            }
            memset(information, 0, sizeof(*information));
            information->shm_perm.key = segment->key;
            information->shm_perm.uid = segment->uid;
            information->shm_perm.gid = segment->gid;
            information->shm_perm.cuid = segment->cuid;
            information->shm_perm.cgid = segment->cgid;
            information->shm_perm.mode = segment->mode |
                (segment->removed ? KERNEL_SYSV_SHM_DEST : 0u);
            information->shm_perm.sequence = (int32_t)segment->sequence;
            information->shm_segsz = segment->size;
            information->shm_atime = (int64_t)(segment->atime_us / 1000000u);
            information->shm_dtime = (int64_t)(segment->dtime_us / 1000000u);
            information->shm_ctime = (int64_t)(segment->ctime_us / 1000000u);
            information->shm_cpid = segment->creator_pid;
            information->shm_lpid = segment->last_pid;
            information->shm_nattch = segment->attachment_count;
            break;
        case KERNEL_SYSV_IPC_SET:
            if (!information) {
                result = -EDGE_LINUX_EFAULT;
                break;
            }
            if (!kernel_sysv_shm_is_owner(segment, &identity)) {
                result = -EDGE_LINUX_EPERM;
                break;
            }
            segment->uid = information->shm_perm.uid;
            segment->gid = information->shm_perm.gid;
            segment->mode = information->shm_perm.mode & 0777u;
            segment->last_pid = identity.tgid;
            segment->ctime_us = boottime_realtime_us();
            break;
        default:
            result = -EDGE_LINUX_EINVAL;
            break;
    }
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    if (!result && operation == KERNEL_SYSV_IPC_RMID)
        kernel_sysv_shm_destroy_if_unused((uint32_t)segment_index);
    return result;
}

int kernel_sysv_shm_address_space_clone(uintptr_t parent_address_space,
                                        uintptr_t child_address_space,
                                        int32_t child_pid) {
    uint64_t lock_flags;
    uint32_t required = 0;
    uint32_t available = 0;

    if (!parent_address_space || !child_address_space)
        return -EDGE_LINUX_EINVAL;
    if (parent_address_space == child_address_space) return 0;
    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_ATTACHMENT_MAX; ++index) {
        const kernel_sysv_shm_attachment_t *attachment =
            &g_sysv_shm_attachments[index];
        if (attachment->used == 1u &&
            attachment->address_space == parent_address_space)
            required++;
        if (!attachment->used) available++;
    }
    if (required > available) {
        spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
        return -EDGE_LINUX_ENOMEM;
    }
    for (uint32_t parent = 0; parent < KERNEL_SYSV_SHM_ATTACHMENT_MAX;
         ++parent) {
        const kernel_sysv_shm_attachment_t *source =
            &g_sysv_shm_attachments[parent];
        if (source->used != 1u ||
            source->address_space != parent_address_space)
            continue;
        for (uint32_t child = 0; child < KERNEL_SYSV_SHM_ATTACHMENT_MAX;
             ++child) {
            kernel_sysv_shm_attachment_t *destination =
                &g_sysv_shm_attachments[child];
            kernel_sysv_shm_segment_t *segment;
            if (destination->used) continue;
            *destination = *source;
            destination->address_space = child_address_space;
            destination->pid = child_pid;
            segment = &g_sysv_shm_segments[destination->segment_index];
            if (segment->state == KERNEL_SYSV_SHM_ACTIVE)
                segment->attachment_count++;
            break;
        }
    }
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    return 0;
}

void kernel_sysv_shm_address_space_release(uintptr_t address_space,
                                           int32_t last_pid) {
    uint8_t destroy[KERNEL_SYSV_SHM_SEGMENT_MAX];
    uint64_t lock_flags;

    if (!address_space) return;
    memset(destroy, 0, sizeof(destroy));
    lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_ATTACHMENT_MAX; ++index) {
        kernel_sysv_shm_attachment_t *attachment =
            &g_sysv_shm_attachments[index];
        kernel_sysv_shm_segment_t *segment;
        if (attachment->used != 1u ||
            attachment->address_space != address_space)
            continue;
        segment = &g_sysv_shm_segments[attachment->segment_index];
        if (segment->state == KERNEL_SYSV_SHM_ACTIVE) {
            if (segment->attachment_count) segment->attachment_count--;
            segment->last_pid = last_pid;
            segment->dtime_us = boottime_realtime_us();
            if (segment->removed && !segment->attachment_count)
                destroy[attachment->segment_index] = 1u;
        }
        memset(attachment, 0, sizeof(*attachment));
    }
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index)
        if (destroy[index]) kernel_sysv_shm_destroy_if_unused(index);
}

uint64_t kernel_runtime_sysv_shmem_bytes(void) {
    uint64_t total = 0;
    uint64_t lock_flags = spin_lock_irqsave(&g_sysv_shm_lock);
    for (uint32_t index = 0; index < KERNEL_SYSV_SHM_SEGMENT_MAX; ++index) {
        const kernel_sysv_shm_segment_t *segment = &g_sysv_shm_segments[index];
        if (segment->state == KERNEL_SYSV_SHM_ACTIVE)
            total += (uint64_t)segment->page_count *
                     KERNEL_SYSV_SHM_PAGE_SIZE;
    }
    spin_unlock_irqrestore(&g_sysv_shm_lock, lock_flags);
    return total;
}
