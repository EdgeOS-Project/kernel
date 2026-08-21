/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux io_uring ring storage and lifetime. */

#include <stdint.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/eventfd.h"
#include "kernel/fd_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_time.h"
#include "kernel/runtime_limits.h"
#include "string.h"
#include "sys/spinlock.h"

#define IORING_SETUP_CQSIZE          (1u << 3)
#define IORING_SETUP_CLAMP           (1u << 4)
#define IORING_SETUP_R_DISABLED      (1u << 6)
#define IORING_SETUP_SUBMIT_ALL      (1u << 7)
#define IORING_SETUP_COOP_TASKRUN    (1u << 8)
#define IORING_SETUP_TASKRUN_FLAG    (1u << 9)
#define IORING_SETUP_SINGLE_ISSUER   (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN   (1u << 13)

#define IORING_FEAT_SUBMIT_STABLE    (1u << 2)
#define IORING_FEAT_RW_CUR_POS       (1u << 3)
#define IORING_FEAT_POLL_32BITS      (1u << 6)
#define IORING_FEAT_CQE_SKIP         (1u << 11)

#define IORING_SETUP_SUPPORTED \
    (IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | \
     IORING_SETUP_R_DISABLED | IORING_SETUP_SUBMIT_ALL | \
     IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | \
     IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN)

#define IORING_SQ_HEAD_OFFSET        0u
#define IORING_SQ_TAIL_OFFSET        4u
#define IORING_SQ_RING_MASK_OFFSET   8u
#define IORING_SQ_RING_ENTRIES_OFFSET 12u
#define IORING_SQ_FLAGS_OFFSET       16u
#define IORING_SQ_DROPPED_OFFSET     20u
#define IORING_SQ_ARRAY_OFFSET       64u

#define IORING_CQ_HEAD_OFFSET        0u
#define IORING_CQ_TAIL_OFFSET        4u
#define IORING_CQ_RING_MASK_OFFSET   8u
#define IORING_CQ_RING_ENTRIES_OFFSET 12u
#define IORING_CQ_OVERFLOW_OFFSET    16u
#define IORING_CQ_FLAGS_OFFSET       20u
#define IORING_CQ_CQES_OFFSET        64u

#define IO_URING_FIXED_FILES_PER_PAGE \
    (KERNEL_IO_URING_PAGE_SIZE / sizeof(kernel_fd_operation_lease_t))
#define IO_URING_FIXED_FILE_PAGES \
    ((KERNEL_IO_URING_MAX_FIXED_FILES + \
      IO_URING_FIXED_FILES_PER_PAGE - 1u) / \
     IO_URING_FIXED_FILES_PER_PAGE)

typedef struct kernel_io_uring_pending {
    uint8_t used;
    uint8_t kind;
    uint8_t realtime_clock;
    uint8_t multishot;
    uint8_t ready_latched;
    uint8_t reserved[3];
    int32_t descriptor;
    uint32_t events;
    uint32_t completion_target;
    int32_t expiration_result;
    uint64_t user_data;
    uint64_t deadline_us;
    uint64_t interval_us;
    uint32_t repeat_count;
    uint32_t reserved2;
    uint64_t sequence;
} kernel_io_uring_pending_t;

typedef struct kernel_io_uring {
    uint8_t used;
    uint8_t disabled;
    uint16_t reserved;
    uint32_t references;
    uint32_t setup_flags;
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t sq_ring_pages;
    uint32_t cq_ring_pages;
    uint32_t sqe_pages;
    int32_t event_id;
    uint8_t event_async_only;
    uint64_t next_pending_sequence;
    kernel_io_uring_page_t
        sq_ring[KERNEL_IO_URING_MAX_SQ_RING_PAGES];
    kernel_io_uring_page_t
        cq_ring[KERNEL_IO_URING_MAX_CQ_RING_PAGES];
    kernel_io_uring_page_t sqes[KERNEL_IO_URING_MAX_SQE_PAGES];
    kernel_io_uring_page_t
        wait_region[KERNEL_IO_URING_MAX_WAIT_REGION_PAGES];
    uint32_t wait_region_pages;
    uint8_t region_registered;
    uint8_t region_wait_argument;
    kernel_io_uring_page_t fixed_file_pages[IO_URING_FIXED_FILE_PAGES];
    uint8_t fixed_file_used[KERNEL_IO_URING_MAX_FIXED_FILES];
    uint64_t fixed_file_tags[KERNEL_IO_URING_MAX_FIXED_FILES];
    uint32_t fixed_file_count;
    uint32_t fixed_file_page_count;
    uint32_t file_alloc_start;
    uint32_t file_alloc_end;
    uint32_t file_alloc_hint;
    uint32_t clock_id;
    kernel_io_uring_pending_t pending[KERNEL_IO_URING_MAX_PENDING];
} kernel_io_uring_t;

typedef struct kernel_io_uring_task_registry {
    uint8_t used;
    int32_t task_id;
    int32_t ring_ids[KERNEL_IO_URING_REGISTERED_RINGS];
} kernel_io_uring_task_registry_t;

static int io_uring_completion_add_locked(
    kernel_io_uring_t *ring, uint64_t user_data,
    int32_t result, uint32_t cqe_flags);

static int32_t io_uring_event_retain_locked(
        kernel_io_uring_t *ring, int asynchronous) {
    if (ring->event_id >= 0 &&
        (!ring->event_async_only || asynchronous) &&
        kernel_eventfd_retain(ring->event_id) == 0)
        return ring->event_id;
    return -1;
}

#define IO_URING_PENDING_TIMEOUT 1u
#define IO_URING_PENDING_POLL    2u

static kernel_io_uring_t g_io_urings[KERNEL_IO_URING_MAX_RINGS];
static kernel_io_uring_task_registry_t
    g_io_uring_task_registries[EDGE_RUNTIME_MAX_TASKS];
static kernel_io_uring_page_allocator_t g_io_uring_allocator;
static spinlock_t g_io_uring_lock;

static kernel_io_uring_task_registry_t *io_uring_task_registry_locked(
        int32_t task_id, int create) {
    kernel_io_uring_task_registry_t *free_registry = 0;

    for (uint32_t index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index) {
        kernel_io_uring_task_registry_t *registry =
            &g_io_uring_task_registries[index];
        if (registry->used && registry->task_id == task_id)
            return registry;
        if (!registry->used && !free_registry) free_registry = registry;
    }
    if (!create || !free_registry) return 0;
    memset(free_registry, 0, sizeof(*free_registry));
    free_registry->used = 1u;
    free_registry->task_id = task_id;
    for (uint32_t index = 0;
         index < KERNEL_IO_URING_REGISTERED_RINGS; ++index)
        free_registry->ring_ids[index] = -1;
    return free_registry;
}

static int io_uring_task_registry_empty(
        const kernel_io_uring_task_registry_t *registry) {
    for (uint32_t index = 0;
         index < KERNEL_IO_URING_REGISTERED_RINGS; ++index)
        if (registry->ring_ids[index] >= 0) return 0;
    return 1;
}

static uint32_t io_uring_page_count(uint64_t bytes) {
    return (uint32_t)((bytes + KERNEL_IO_URING_PAGE_SIZE - 1u) /
                      KERNEL_IO_URING_PAGE_SIZE);
}

static uint32_t io_uring_round_entries(uint32_t entries) {
    uint32_t rounded = 1u;
    while (rounded < entries && rounded < KERNEL_IO_URING_MAX_CQ_ENTRIES)
        rounded <<= 1;
    return rounded;
}

static volatile uint32_t *io_uring_u32(kernel_io_uring_page_t *pages,
                                       uint32_t offset) {
    uint32_t page = offset / KERNEL_IO_URING_PAGE_SIZE;
    uint32_t within = offset % KERNEL_IO_URING_PAGE_SIZE;
    if (!pages[page].address) return 0;
    return (volatile uint32_t *)((uint8_t *)pages[page].address + within);
}

static void *io_uring_region_pointer(kernel_io_uring_page_t *pages,
                                     uint32_t offset) {
    uint32_t page = offset / KERNEL_IO_URING_PAGE_SIZE;
    uint32_t within = offset % KERNEL_IO_URING_PAGE_SIZE;
    if (!pages[page].address) return 0;
    return (uint8_t *)pages[page].address + within;
}

static int io_uring_allocate_pages(kernel_io_uring_page_t *pages,
                                   uint32_t count) {
    uint32_t page;
    for (page = 0; page < count; ++page) {
        if (g_io_uring_allocator.allocate(
                g_io_uring_allocator.context, &pages[page]) < 0)
            break;
        if (!pages[page].address) break;
        memset(pages[page].address, 0, KERNEL_IO_URING_PAGE_SIZE);
    }
    if (page == count) return 0;
    while (page) {
        --page;
        g_io_uring_allocator.release(
            g_io_uring_allocator.context, &pages[page]);
        memset(&pages[page], 0, sizeof(pages[page]));
    }
    return -EDGE_LINUX_ENOMEM;
}

static void io_uring_release_pages(kernel_io_uring_page_t *pages,
                                   uint32_t count) {
    for (uint32_t page = 0; page < count; ++page) {
        if (pages[page].address)
            g_io_uring_allocator.release(
                g_io_uring_allocator.context, &pages[page]);
        memset(&pages[page], 0, sizeof(pages[page]));
    }
}

static kernel_fd_operation_lease_t *io_uring_fixed_file_lease(
        kernel_io_uring_page_t *pages, uint32_t index) {
    uint32_t page = index / IO_URING_FIXED_FILES_PER_PAGE;
    uint32_t within = index % IO_URING_FIXED_FILES_PER_PAGE;

    if (page >= IO_URING_FIXED_FILE_PAGES || !pages[page].address)
        return 0;
    return &((kernel_fd_operation_lease_t *)pages[page].address)[within];
}

static void io_uring_release_fixed_files(
        kernel_io_uring_page_t *pages, const uint8_t *used,
        uint32_t count, uint32_t page_count) {
    for (uint32_t index = 0; index < count; ++index) {
        kernel_fd_operation_lease_t *lease;
        if (!used[index]) continue;
        lease = io_uring_fixed_file_lease(pages, index);
        if (lease) (void)kernel_fd_operation_release(lease);
    }
    io_uring_release_pages(pages, page_count);
}

static void io_uring_release_storage(kernel_io_uring_t *ring) {
    if (ring->event_id >= 0)
        kernel_eventfd_release(ring->event_id);
    io_uring_release_pages(ring->sq_ring, ring->sq_ring_pages);
    io_uring_release_pages(ring->cq_ring, ring->cq_ring_pages);
    io_uring_release_pages(ring->sqes, ring->sqe_pages);
    io_uring_release_pages(ring->wait_region, ring->wait_region_pages);
    io_uring_release_fixed_files(
        ring->fixed_file_pages, ring->fixed_file_used,
        ring->fixed_file_count, ring->fixed_file_page_count);
}

static kernel_io_uring_t *io_uring_lookup_locked(int32_t ring_id) {
    if (ring_id < 0 || ring_id >= (int32_t)KERNEL_IO_URING_MAX_RINGS ||
        !g_io_urings[ring_id].used)
        return 0;
    return &g_io_urings[ring_id];
}

int kernel_io_uring_page_allocator_register(
        const kernel_io_uring_page_allocator_t *allocator) {
    uint64_t flags;
    if (!allocator || !allocator->allocate || !allocator->retain ||
        !allocator->release)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    g_io_uring_allocator = *allocator;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return 0;
}

int kernel_io_uring_create(uint32_t entries,
                           struct edge_linux_io_uring_params *parameters,
                           int32_t *ring_id) {
    kernel_io_uring_t *ring;
    uint32_t cq_entries;
    uint32_t slot;
    uint64_t flags;
    int result;

    if (!parameters || !ring_id || !entries)
        return -EDGE_LINUX_EINVAL;
    if (parameters->flags & ~IORING_SETUP_SUPPORTED)
        return -EDGE_LINUX_EINVAL;
    if ((parameters->flags & IORING_SETUP_TASKRUN_FLAG) &&
        !(parameters->flags & (IORING_SETUP_COOP_TASKRUN |
                               IORING_SETUP_DEFER_TASKRUN)))
        return -EDGE_LINUX_EINVAL;
    if (entries > KERNEL_IO_URING_MAX_SQ_ENTRIES) {
        if (!(parameters->flags & IORING_SETUP_CLAMP))
            return -EDGE_LINUX_EINVAL;
        entries = KERNEL_IO_URING_MAX_SQ_ENTRIES;
    }
    entries = io_uring_round_entries(entries);
    if (parameters->flags & IORING_SETUP_CQSIZE) {
        if (parameters->cq_entries < entries)
            return -EDGE_LINUX_EINVAL;
        cq_entries = io_uring_round_entries(parameters->cq_entries);
        if (cq_entries > KERNEL_IO_URING_MAX_CQ_ENTRIES) {
            if (!(parameters->flags & IORING_SETUP_CLAMP))
                return -EDGE_LINUX_EINVAL;
            cq_entries = KERNEL_IO_URING_MAX_CQ_ENTRIES;
        }
    } else {
        cq_entries = entries < KERNEL_IO_URING_MAX_CQ_ENTRIES ?
                     entries * 2u : entries;
    }

    flags = spin_lock_irqsave(&g_io_uring_lock);
    if (!g_io_uring_allocator.allocate) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_ENODEV;
    }
    for (slot = 0; slot < KERNEL_IO_URING_MAX_RINGS; ++slot)
        if (!g_io_urings[slot].used) break;
    if (slot == KERNEL_IO_URING_MAX_RINGS) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_ENFILE;
    }
    ring = &g_io_urings[slot];
    memset(ring, 0, sizeof(*ring));
    ring->used = 1u;
    ring->event_id = -1;
    ring->clock_id = LINUX_CLOCK_MONOTONIC;
    ring->references = 1u;
    ring->disabled =
        (parameters->flags & IORING_SETUP_R_DISABLED) != 0;
    ring->setup_flags = parameters->flags;
    ring->sq_entries = entries;
    ring->cq_entries = cq_entries;
    ring->sq_ring_pages = io_uring_page_count(
        IORING_SQ_ARRAY_OFFSET + (uint64_t)entries * sizeof(uint32_t));
    ring->cq_ring_pages = io_uring_page_count(
        IORING_CQ_CQES_OFFSET +
        (uint64_t)cq_entries * sizeof(struct edge_linux_io_uring_cqe));
    ring->sqe_pages = io_uring_page_count(
        (uint64_t)entries * sizeof(struct edge_linux_io_uring_sqe));
    result = io_uring_allocate_pages(ring->sq_ring, ring->sq_ring_pages);
    if (result == 0)
        result = io_uring_allocate_pages(
            ring->cq_ring, ring->cq_ring_pages);
    if (result == 0)
        result = io_uring_allocate_pages(ring->sqes, ring->sqe_pages);
    if (result < 0) {
        io_uring_release_storage(ring);
        memset(ring, 0, sizeof(*ring));
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return result;
    }

    *io_uring_u32(ring->sq_ring, IORING_SQ_RING_MASK_OFFSET) =
        entries - 1u;
    *io_uring_u32(ring->sq_ring, IORING_SQ_RING_ENTRIES_OFFSET) = entries;
    *io_uring_u32(ring->cq_ring, IORING_CQ_RING_MASK_OFFSET) =
        cq_entries - 1u;
    *io_uring_u32(ring->cq_ring, IORING_CQ_RING_ENTRIES_OFFSET) = cq_entries;

    parameters->sq_entries = entries;
    parameters->cq_entries = cq_entries;
    parameters->features = IORING_FEAT_SUBMIT_STABLE |
                           IORING_FEAT_RW_CUR_POS |
                           IORING_FEAT_POLL_32BITS |
                           IORING_FEAT_CQE_SKIP;
    parameters->sq_off.head = IORING_SQ_HEAD_OFFSET;
    parameters->sq_off.tail = IORING_SQ_TAIL_OFFSET;
    parameters->sq_off.ring_mask = IORING_SQ_RING_MASK_OFFSET;
    parameters->sq_off.ring_entries = IORING_SQ_RING_ENTRIES_OFFSET;
    parameters->sq_off.flags = IORING_SQ_FLAGS_OFFSET;
    parameters->sq_off.dropped = IORING_SQ_DROPPED_OFFSET;
    parameters->sq_off.array = IORING_SQ_ARRAY_OFFSET;
    parameters->cq_off.head = IORING_CQ_HEAD_OFFSET;
    parameters->cq_off.tail = IORING_CQ_TAIL_OFFSET;
    parameters->cq_off.ring_mask = IORING_CQ_RING_MASK_OFFSET;
    parameters->cq_off.ring_entries = IORING_CQ_RING_ENTRIES_OFFSET;
    parameters->cq_off.overflow = IORING_CQ_OVERFLOW_OFFSET;
    parameters->cq_off.cqes = IORING_CQ_CQES_OFFSET;
    parameters->cq_off.flags = IORING_CQ_FLAGS_OFFSET;
    *ring_id = (int32_t)slot;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return 0;
}

int kernel_io_uring_retain(int32_t ring_id) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result = 0;
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (ring->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else ++ring->references;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

void kernel_io_uring_release(int32_t ring_id) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (ring && ring->references && --ring->references == 0u) {
        io_uring_release_storage(ring);
        memset(ring, 0, sizeof(*ring));
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
}

int kernel_io_uring_task_ring_register(int32_t task_id, int32_t ring_id,
                                       uint32_t requested,
                                       uint32_t *assigned) {
    kernel_io_uring_task_registry_t *registry;
    uint32_t slot;
    uint64_t flags;
    int result;

    if (task_id <= 0 || !assigned)
        return -EDGE_LINUX_EINVAL;
    if (requested != KERNEL_IO_URING_REGISTERED_RING_ALLOC &&
        requested >= KERNEL_IO_URING_REGISTERED_RINGS)
        return -EDGE_LINUX_EINVAL;
    result = kernel_io_uring_retain(ring_id);
    if (result < 0) return result;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    registry = io_uring_task_registry_locked(task_id, 1);
    if (!registry) {
        result = -EDGE_LINUX_ENOMEM;
        goto unlock;
    }
    if (requested == KERNEL_IO_URING_REGISTERED_RING_ALLOC) {
        for (slot = 0; slot < KERNEL_IO_URING_REGISTERED_RINGS; ++slot)
            if (registry->ring_ids[slot] < 0) break;
        if (slot == KERNEL_IO_URING_REGISTERED_RINGS) {
            result = -EDGE_LINUX_EBUSY;
            goto unlock;
        }
    } else {
        slot = requested;
        if (registry->ring_ids[slot] >= 0) {
            result = -EDGE_LINUX_EBUSY;
            goto unlock;
        }
    }
    registry->ring_ids[slot] = ring_id;
    *assigned = slot;
    result = 0;
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result < 0) kernel_io_uring_release(ring_id);
    return result;
}

int kernel_io_uring_task_ring_unregister(int32_t task_id, uint32_t index) {
    kernel_io_uring_task_registry_t *registry;
    int32_t ring_id = -1;
    uint64_t flags;

    if (task_id <= 0 || index >= KERNEL_IO_URING_REGISTERED_RINGS)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    registry = io_uring_task_registry_locked(task_id, 0);
    if (registry) {
        ring_id = registry->ring_ids[index];
        registry->ring_ids[index] = -1;
        if (io_uring_task_registry_empty(registry))
            memset(registry, 0, sizeof(*registry));
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (ring_id >= 0) kernel_io_uring_release(ring_id);
    return 0;
}

int kernel_io_uring_task_ring_lookup(int32_t task_id, uint32_t index,
                                     int32_t *ring_id) {
    kernel_io_uring_task_registry_t *registry;
    uint64_t flags;
    int result;

    if (task_id <= 0 || !ring_id ||
        index >= KERNEL_IO_URING_REGISTERED_RINGS)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    registry = io_uring_task_registry_locked(task_id, 0);
    if (!registry || registry->ring_ids[index] < 0) {
        result = -EDGE_LINUX_EBADF;
    } else {
        *ring_id = registry->ring_ids[index];
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

void kernel_io_uring_task_release(int32_t task_id) {
    kernel_io_uring_task_registry_t *registry;
    int32_t ring_ids[KERNEL_IO_URING_REGISTERED_RINGS];
    uint64_t flags;

    if (task_id <= 0) return;
    for (uint32_t index = 0;
         index < KERNEL_IO_URING_REGISTERED_RINGS; ++index)
        ring_ids[index] = -1;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    registry = io_uring_task_registry_locked(task_id, 0);
    if (registry) {
        for (uint32_t index = 0;
             index < KERNEL_IO_URING_REGISTERED_RINGS; ++index)
            ring_ids[index] = registry->ring_ids[index];
        memset(registry, 0, sizeof(*registry));
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    for (uint32_t index = 0;
         index < KERNEL_IO_URING_REGISTERED_RINGS; ++index)
        if (ring_ids[index] >= 0)
            kernel_io_uring_release(ring_ids[index]);
}

int kernel_io_uring_enable(int32_t ring_id) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    if (!ring->disabled) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADFD;
    }
    ring->disabled = 0u;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return 0;
}

int kernel_io_uring_disabled(int32_t ring_id) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;
    ring = io_uring_lookup_locked(ring_id);
    result = ring ? ring->disabled != 0 : -EDGE_LINUX_EBADF;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_eventfd_register(int32_t ring_id, int32_t event_id,
                                     int asynchronous_only) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (event_id < 0) return -EDGE_LINUX_EBADF;
    result = kernel_eventfd_retain(event_id);
    if (result < 0) return result;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (ring->event_id >= 0) result = -EDGE_LINUX_EBUSY;
    else {
        ring->event_id = event_id;
        ring->event_async_only = asynchronous_only != 0;
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result < 0) kernel_eventfd_release(event_id);
    return result;
}

int kernel_io_uring_eventfd_unregister(int32_t ring_id) {
    kernel_io_uring_t *ring;
    int32_t event_id = -1;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result = 0;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (ring->event_id < 0) result = -EDGE_LINUX_ENXIO;
    else {
        event_id = ring->event_id;
        ring->event_id = -1;
        ring->event_async_only = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) kernel_eventfd_release(event_id);
    return result;
}

int kernel_io_uring_region_registered(int32_t ring_id) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;

    ring = io_uring_lookup_locked(ring_id);
    result = ring ? ring->region_registered != 0 : -EDGE_LINUX_EBADF;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_region_register(int32_t ring_id, uint32_t page_count,
                                    int wait_argument) {
    kernel_io_uring_page_t
        pages[KERNEL_IO_URING_MAX_WAIT_REGION_PAGES] = {{0}};
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (!page_count) return -EDGE_LINUX_EINVAL;
    if (page_count > KERNEL_IO_URING_MAX_WAIT_REGION_PAGES)
        return -EDGE_LINUX_E2BIG;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (ring->region_registered) result = -EDGE_LINUX_EBUSY;
    else if (wait_argument && !ring->disabled)
        result = -EDGE_LINUX_EINVAL;
    else result = 0;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result < 0) return result;

    result = io_uring_allocate_pages(pages, page_count);
    if (result < 0) return result;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (ring->region_registered) result = -EDGE_LINUX_EBUSY;
    else if (wait_argument && !ring->disabled)
        result = -EDGE_LINUX_EINVAL;
    else {
        memcpy(ring->wait_region, pages,
               page_count * sizeof(pages[0]));
        memset(pages, 0, page_count * sizeof(pages[0]));
        ring->wait_region_pages = page_count;
        ring->region_registered = 1u;
        ring->region_wait_argument = wait_argument != 0;
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    io_uring_release_pages(pages, page_count);
    return result;
}

int kernel_io_uring_region_unregister(int32_t ring_id) {
    kernel_io_uring_page_t
        pages[KERNEL_IO_URING_MAX_WAIT_REGION_PAGES] = {{0}};
    kernel_io_uring_t *ring;
    uint32_t page_count = 0;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result = 0;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (!ring->region_registered) result = -EDGE_LINUX_ENOENT;
    else {
        page_count = ring->wait_region_pages;
        memcpy(pages, ring->wait_region,
               page_count * sizeof(pages[0]));
        memset(ring->wait_region, 0, sizeof(ring->wait_region));
        ring->wait_region_pages = 0;
        ring->region_registered = 0;
        ring->region_wait_argument = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    io_uring_release_pages(pages, page_count);
    return result;
}

int kernel_io_uring_registered_wait_read(
        int32_t ring_id, uint64_t offset,
        struct edge_linux_io_uring_reg_wait *wait) {
    kernel_io_uring_t *ring;
    uint64_t end;
    uint64_t flags;
    uint32_t copied = 0;
    int result = 0;

    if (!wait || (offset & (sizeof(uint64_t) - 1u)))
        return -EDGE_LINUX_EFAULT;
    if (offset > UINT64_MAX - sizeof(*wait))
        return -EDGE_LINUX_EFAULT;
    end = offset + sizeof(*wait);
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (!ring->region_registered || !ring->region_wait_argument ||
             end > (uint64_t)ring->wait_region_pages *
                       KERNEL_IO_URING_PAGE_SIZE)
        result = -EDGE_LINUX_EFAULT;
    while (result == 0 && copied < sizeof(*wait)) {
        uint64_t position = offset + copied;
        uint32_t page = (uint32_t)(position / KERNEL_IO_URING_PAGE_SIZE);
        uint32_t within = (uint32_t)(position % KERNEL_IO_URING_PAGE_SIZE);
        uint32_t chunk = KERNEL_IO_URING_PAGE_SIZE - within;
        if (chunk > sizeof(*wait) - copied)
            chunk = (uint32_t)sizeof(*wait) - copied;
        if (!ring->wait_region[page].address) {
            result = -EDGE_LINUX_EFAULT;
            break;
        }
        memcpy((uint8_t *)wait + copied,
               (uint8_t *)ring->wait_region[page].address + within,
               chunk);
        copied += chunk;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_files_register_tagged(
        int32_t ring_id, const int32_t *descriptors,
        const uint64_t *tags, uint32_t count) {
    kernel_io_uring_page_t pages[IO_URING_FIXED_FILE_PAGES] = {{0}};
    uint8_t used[KERNEL_IO_URING_MAX_FIXED_FILES] = {0};
    kernel_io_uring_t *ring;
    uint32_t page_count;
    uint64_t flags;
    int result;

    if (!descriptors || !count) return -EDGE_LINUX_EINVAL;
    if (count > KERNEL_IO_URING_MAX_FIXED_FILES)
        return -EDGE_LINUX_EMFILE;
    page_count = (count + IO_URING_FIXED_FILES_PER_PAGE - 1u) /
                 IO_URING_FIXED_FILES_PER_PAGE;
    result = io_uring_allocate_pages(pages, page_count);
    if (result < 0) return result;
    for (uint32_t index = 0; index < count; ++index) {
        kernel_fd_operation_lease_t *lease;
        if (descriptors[index] == -1) {
            if (tags && tags[index]) {
                result = -EDGE_LINUX_EINVAL;
                goto release_new;
            }
            continue;
        }
        if (descriptors[index] < 0) {
            result = -EDGE_LINUX_EBADF;
            goto release_new;
        }
        lease = io_uring_fixed_file_lease(pages, index);
        if (!lease) {
            result = -EDGE_LINUX_ENOMEM;
            goto release_new;
        }
        result = kernel_fd_operation_acquire(descriptors[index], lease);
        if (result < 0) goto release_new;
        used[index] = 1u;
    }

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (ring->fixed_file_count) {
        result = -EDGE_LINUX_EBUSY;
    } else {
        memcpy(ring->fixed_file_pages, pages, sizeof(pages));
        memcpy(ring->fixed_file_used, used, sizeof(used));
        if (tags)
            memcpy(ring->fixed_file_tags, tags,
                   (size_t)count * sizeof(tags[0]));
        else
            memset(ring->fixed_file_tags, 0,
                   sizeof(ring->fixed_file_tags));
        ring->fixed_file_count = count;
        ring->fixed_file_page_count = page_count;
        ring->file_alloc_start = 0u;
        ring->file_alloc_end = count;
        ring->file_alloc_hint = 0u;
        memset(pages, 0, sizeof(pages));
        memset(used, 0, sizeof(used));
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);

release_new:
    if (result < 0)
        io_uring_release_fixed_files(pages, used, count, page_count);
    return result;
}

int kernel_io_uring_files_register(int32_t ring_id,
                                   const int32_t *descriptors,
                                   uint32_t count) {
    return kernel_io_uring_files_register_tagged(
        ring_id, descriptors, 0, count);
}

int kernel_io_uring_files_unregister(int32_t ring_id) {
    kernel_io_uring_page_t pages[IO_URING_FIXED_FILE_PAGES] = {{0}};
    uint8_t used[KERNEL_IO_URING_MAX_FIXED_FILES] = {0};
    kernel_io_uring_t *ring;
    uint32_t count = 0u;
    uint32_t page_count = 0u;
    int32_t event_id = -1;
    int notify = 0;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result = 0;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (!ring->fixed_file_count) {
        result = -EDGE_LINUX_ENXIO;
    } else {
        for (uint32_t index = 0;
             index < ring->fixed_file_count; ++index) {
            if (!ring->fixed_file_used[index] ||
                !ring->fixed_file_tags[index])
                continue;
            if (io_uring_completion_add_locked(
                    ring, ring->fixed_file_tags[index], 0, 0) == 0)
                notify = 1;
        }
        if (notify) event_id = io_uring_event_retain_locked(ring, 0);
        memcpy(pages, ring->fixed_file_pages, sizeof(pages));
        memcpy(used, ring->fixed_file_used, sizeof(used));
        count = ring->fixed_file_count;
        page_count = ring->fixed_file_page_count;
        memset(ring->fixed_file_pages, 0,
               sizeof(ring->fixed_file_pages));
        memset(ring->fixed_file_used, 0,
               sizeof(ring->fixed_file_used));
        memset(ring->fixed_file_tags, 0,
               sizeof(ring->fixed_file_tags));
        ring->fixed_file_count = 0u;
        ring->fixed_file_page_count = 0u;
        ring->file_alloc_start = 0u;
        ring->file_alloc_end = 0u;
        ring->file_alloc_hint = 0u;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result == 0)
        io_uring_release_fixed_files(pages, used, count, page_count);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    return result;
}

int kernel_io_uring_files_update_validate(int32_t ring_id,
                                          uint32_t offset,
                                          uint32_t count) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring)
        result = -EDGE_LINUX_EBADF;
    else if (!ring->fixed_file_count)
        result = -EDGE_LINUX_ENXIO;
    else if (!count)
        result = -EDGE_LINUX_EINVAL;
    else if (offset > UINT32_MAX - count)
        result = -EDGE_LINUX_EOVERFLOW;
    else if (offset + count > ring->fixed_file_count)
        result = -EDGE_LINUX_EINVAL;
    else
        result = 0;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_files_update_tagged(
        int32_t ring_id, uint32_t offset,
        const int32_t *descriptors, const uint64_t *tags,
        uint32_t count) {
    kernel_io_uring_t *ring;
    uint32_t done;
    uint64_t flags;
    int32_t event_id = -1;
    int notify = 0;
    int result = 0;

    if (!descriptors || !count) return -EDGE_LINUX_EINVAL;
    result = kernel_io_uring_files_update_validate(
        ring_id, offset, count);
    if (result < 0) return result;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    if (!ring->fixed_file_count) {
        result = -EDGE_LINUX_ENXIO;
        goto unlock;
    }
    if (offset > UINT32_MAX - count ||
        offset + count > ring->fixed_file_count) {
        result = -EDGE_LINUX_EINVAL;
        goto unlock;
    }

    for (done = 0; done < count; ++done) {
        kernel_fd_operation_lease_t *lease;
        int32_t descriptor = descriptors[done];
        uint64_t tag = tags ? tags[done] : 0u;
        uint32_t index = offset + done;

        if ((descriptor == KERNEL_IO_URING_REGISTER_FILES_SKIP ||
             descriptor == -1) && tag) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
        if (descriptor == KERNEL_IO_URING_REGISTER_FILES_SKIP)
            continue;
        lease = io_uring_fixed_file_lease(
            ring->fixed_file_pages, index);
        if (!lease) {
            result = -EDGE_LINUX_EBADF;
            break;
        }
        if (ring->fixed_file_used[index]) {
            if (ring->fixed_file_tags[index] &&
                io_uring_completion_add_locked(
                    ring, ring->fixed_file_tags[index], 0, 0) == 0)
                notify = 1;
            (void)kernel_fd_operation_release(lease);
            ring->fixed_file_used[index] = 0u;
            ring->fixed_file_tags[index] = 0u;
        }
        if (descriptor == -1) continue;
        if (descriptor < 0 ||
            kernel_anonymous_fd_descriptor_object_id(
                descriptor, KERNEL_ANONYMOUS_FD_IO_URING) >= 0) {
            result = -EDGE_LINUX_EBADF;
            break;
        }
        result = kernel_fd_operation_acquire(descriptor, lease);
        if (result < 0) break;
        ring->fixed_file_used[index] = 1u;
        ring->fixed_file_tags[index] = tag;
    }
    if (done) result = (int)done;
    else if (result >= 0) result = (int)count;
    if (notify) event_id = io_uring_event_retain_locked(ring, 0);

unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    return result;
}

int kernel_io_uring_files_update(int32_t ring_id, uint32_t offset,
                                 const int32_t *descriptors,
                                 uint32_t count) {
    return kernel_io_uring_files_update_tagged(
        ring_id, offset, descriptors, 0, count);
}

int kernel_io_uring_file_alloc_range_set(int32_t ring_id,
                                         uint32_t offset,
                                         uint32_t length) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (offset > UINT32_MAX - length) {
        result = -EDGE_LINUX_EOVERFLOW;
    } else if (offset + length > ring->fixed_file_count) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        ring->file_alloc_start = offset;
        ring->file_alloc_end = offset + length;
        ring->file_alloc_hint = offset;
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_file_alloc_range_get(int32_t ring_id,
                                         uint32_t *offset,
                                         uint32_t *length) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (!offset || !length) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        *offset = ring->file_alloc_start;
        *length = ring->file_alloc_end - ring->file_alloc_start;
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_clock_set(int32_t ring_id, uint32_t clock_id) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (clock_id != LINUX_CLOCK_MONOTONIC &&
        clock_id != LINUX_CLOCK_BOOTTIME)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        ring->clock_id = clock_id;
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_clock_now(int32_t ring_id,
                              uint64_t monotonic_now_us,
                              uint64_t boottime_now_us,
                              uint64_t *now_us) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (!now_us) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        *now_us = ring->clock_id == LINUX_CLOCK_BOOTTIME ?
                  boottime_now_us : monotonic_now_us;
        result = 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_fixed_file_install(int32_t ring_id,
                                       uint32_t index,
                                       uint32_t descriptor_flags,
                                       int32_t *descriptor) {
    kernel_io_uring_t *ring;
    kernel_fd_operation_lease_t *lease;
    uint64_t flags;
    int result;

    if (!descriptor || (descriptor_flags & ~KERNEL_FD_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    *descriptor = -1;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (index >= ring->fixed_file_count ||
               !ring->fixed_file_used[index]) {
        result = -EDGE_LINUX_EBADF;
    } else {
        lease = io_uring_fixed_file_lease(
            ring->fixed_file_pages, index);
        result = lease ? kernel_fd_operation_materialize(
                             lease, descriptor_flags, descriptor) :
                         -EDGE_LINUX_EBADF;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_fixed_file_materialize(int32_t ring_id,
                                           uint32_t index,
                                           int32_t *descriptor) {
    return kernel_io_uring_fixed_file_install(
        ring_id, index, KERNEL_FD_CLOEXEC, descriptor);
}

static int io_uring_pending_add(int32_t ring_id, uint8_t kind,
                                uint64_t user_data, int32_t descriptor,
                                uint32_t events, uint64_t deadline_us,
                                uint32_t completion_target,
                                int32_t expiration_result,
                                int realtime_clock, uint64_t interval_us,
                                uint32_t repeat_count, int multishot) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    uint32_t slot;
    int result = 0;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else {
        for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot)
            if (!ring->pending[slot].used) break;
        if (slot == KERNEL_IO_URING_MAX_PENDING) {
            result = -EDGE_LINUX_EAGAIN;
        } else {
            memset(&ring->pending[slot], 0, sizeof(ring->pending[slot]));
            ring->pending[slot].used = 1u;
            ring->pending[slot].kind = kind;
            ring->pending[slot].descriptor = descriptor;
            ring->pending[slot].events = events;
            ring->pending[slot].realtime_clock = realtime_clock ? 1u : 0u;
            ring->pending[slot].multishot = multishot ? 1u : 0u;
            ring->pending[slot].deadline_us = deadline_us;
            ring->pending[slot].interval_us = interval_us;
            ring->pending[slot].repeat_count = repeat_count;
            ring->pending[slot].completion_target = completion_target;
            ring->pending[slot].expiration_result = expiration_result;
            ring->pending[slot].user_data = user_data;
            ++ring->next_pending_sequence;
            if (!ring->next_pending_sequence)
                ++ring->next_pending_sequence;
            ring->pending[slot].sequence = ring->next_pending_sequence;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_timeout_add(int32_t ring_id, uint64_t user_data,
                                uint64_t deadline_us,
                                uint32_t completion_target,
                                int32_t expiration_result,
                                int realtime_clock,
                                uint64_t interval_us,
                                uint32_t repeat_count,
                                int multishot) {
    return io_uring_pending_add(
        ring_id, IO_URING_PENDING_TIMEOUT, user_data, -1, 0,
        deadline_us, completion_target, expiration_result,
        realtime_clock, interval_us, repeat_count, multishot);
}

int kernel_io_uring_timeout_update(int32_t ring_id, uint64_t user_data,
                                   uint64_t value_us, int absolute,
                                   uint64_t monotonic_now_us,
                                   uint64_t realtime_now_us) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result = -EDGE_LINUX_ENOENT;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        for (uint32_t slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
            kernel_io_uring_pending_t *pending = &ring->pending[slot];
            uint64_t deadline;

            if (!pending->used ||
                pending->kind != IO_URING_PENDING_TIMEOUT ||
                pending->user_data != user_data)
                continue;
            if (pending->ready_latched) {
                result = -EDGE_LINUX_EALREADY;
                break;
            }
            if (!absolute) {
                deadline = value_us > UINT64_MAX - monotonic_now_us ?
                           UINT64_MAX : monotonic_now_us + value_us;
            } else if (pending->realtime_clock) {
                deadline = value_us <= realtime_now_us ? monotonic_now_us :
                    (value_us - realtime_now_us >
                         UINT64_MAX - monotonic_now_us ?
                     UINT64_MAX :
                     monotonic_now_us + value_us - realtime_now_us);
            } else {
                deadline = value_us;
            }
            pending->deadline_us = deadline;
            if (pending->multishot) {
                pending->interval_us = value_us;
                pending->repeat_count = 0u;
            }
            pending->completion_target = 0u;
            pending->ready_latched = 0u;
            ++ring->next_pending_sequence;
            if (!ring->next_pending_sequence)
                ++ring->next_pending_sequence;
            pending->sequence = ring->next_pending_sequence;
            result = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_poll_add(int32_t ring_id, uint64_t user_data,
                             int32_t descriptor, uint32_t events,
                             int multishot) {
    if (descriptor < 0 || !events) return -EDGE_LINUX_EINVAL;
    return io_uring_pending_add(
        ring_id, IO_URING_PENDING_POLL, user_data, descriptor,
        events, UINT64_MAX, 0, 0, 0, 0, 0, multishot);
}

int kernel_io_uring_poll_update(int32_t ring_id, uint64_t old_user_data,
                                int update_events, uint32_t events,
                                int update_user_data,
                                uint64_t new_user_data,
                                int multishot) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result = -EDGE_LINUX_ENOENT;

    if ((!update_events && !update_user_data) ||
        (update_events && !events)) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EINVAL;
    }
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        for (uint32_t slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
            kernel_io_uring_pending_t *pending = &ring->pending[slot];

            if (!pending->used || pending->kind != IO_URING_PENDING_POLL ||
                pending->user_data != old_user_data)
                continue;
            if (update_events) {
                pending->events = events;
                pending->multishot = multishot ? 1u : 0u;
            }
            if (update_user_data)
                pending->user_data = new_user_data;
            pending->ready_latched = 0u;
            ++ring->next_pending_sequence;
            if (!ring->next_pending_sequence)
                ++ring->next_pending_sequence;
            pending->sequence = ring->next_pending_sequence;
            result = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_pending_cancel(int32_t ring_id, uint64_t user_data) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    uint32_t slot;
    int result = -EDGE_LINUX_ENOENT;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else {
        for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
            if (!ring->pending[slot].used ||
                ring->pending[slot].user_data != user_data)
                continue;
            memset(&ring->pending[slot], 0, sizeof(ring->pending[slot]));
            result = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

uint32_t kernel_io_uring_collect(int32_t ring_id, uint64_t now_us) {
    uint32_t count = 0;
    for (uint32_t slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
        kernel_io_uring_pending_t pending;
        kernel_io_uring_t *ring;
        uint32_t completion_count;
        uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
        int32_t result = 0;
        int remove = 0;
        int ready = 0;
        int timeout_completion = 0;
        int timeout_final = 0;
        uint64_t completion_user_data;
        uint32_t completion_flags = 0u;
        ring = io_uring_lookup_locked(ring_id);
        if (!ring) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            break;
        }
        pending = ring->pending[slot];
        if (!pending.used) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            continue;
        }
        completion_count = *io_uring_u32(
            ring->cq_ring, IORING_CQ_TAIL_OFFSET) -
            *io_uring_u32(ring->cq_ring, IORING_CQ_HEAD_OFFSET);
        completion_user_data = pending.user_data;
        if (pending.kind == IO_URING_PENDING_TIMEOUT) {
            if (pending.completion_target &&
                completion_count >=
                    pending.completion_target) {
                ready = 1;
            } else if (now_us >= pending.deadline_us) {
                ready = 1;
                result = pending.expiration_result;
            }
            if (ready) {
                if (pending.ready_latched) {
                    spin_unlock_irqrestore(&g_io_uring_lock, flags);
                    continue;
                }
                ring->pending[slot].ready_latched = 1u;
                timeout_completion = 1;
                timeout_final = !pending.multishot ||
                                pending.repeat_count == 1u;
                if (pending.multishot && !timeout_final)
                    completion_flags = 1u << 1;
                remove = 1;
            }
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
        } else if (pending.kind == IO_URING_PENDING_POLL) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            if ((pending.events & 0x2003u) &&
                kernel_io_descriptor_ready(
                    pending.descriptor, KERNEL_IO_READ_CURRENT))
                result |= (int32_t)(pending.events & 0x2003u);
            if ((pending.events & 0x0004u) &&
                kernel_io_descriptor_ready(
                    pending.descriptor, KERNEL_IO_WRITE_CURRENT))
                result |= 0x0004;
            if (!result) {
                flags = spin_lock_irqsave(&g_io_uring_lock);
                ring = io_uring_lookup_locked(ring_id);
                if (ring && ring->pending[slot].used &&
                    ring->pending[slot].kind == IO_URING_PENDING_POLL &&
                    ring->pending[slot].sequence == pending.sequence)
                    ring->pending[slot].ready_latched = 0u;
                spin_unlock_irqrestore(&g_io_uring_lock, flags);
                continue;
            }
            flags = spin_lock_irqsave(&g_io_uring_lock);
            ring = io_uring_lookup_locked(ring_id);
            if (ring && ring->pending[slot].used &&
                ring->pending[slot].kind == IO_URING_PENDING_POLL &&
                ring->pending[slot].sequence == pending.sequence) {
                completion_user_data = ring->pending[slot].user_data;
                if (ring->pending[slot].multishot)
                    completion_flags = 1u << 1;
                if (!ring->pending[slot].multishot) {
                    memset(&ring->pending[slot], 0,
                           sizeof(ring->pending[slot]));
                    remove = 1;
                } else if (!ring->pending[slot].ready_latched) {
                    ring->pending[slot].ready_latched = 1u;
                    remove = 1;
                }
            }
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
        } else {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            continue;
        }
        if (remove) {
            int completion_result = kernel_io_uring_completion_add_async(
                ring_id, completion_user_data, result,
                completion_flags);
            if (timeout_completion) {
                flags = spin_lock_irqsave(&g_io_uring_lock);
                ring = io_uring_lookup_locked(ring_id);
                if (ring && ring->pending[slot].used &&
                    ring->pending[slot].kind == IO_URING_PENDING_TIMEOUT &&
                    ring->pending[slot].sequence == pending.sequence) {
                    kernel_io_uring_pending_t *current =
                        &ring->pending[slot];
                    if (completion_result == 0 && timeout_final) {
                        memset(current, 0, sizeof(*current));
                    } else if (completion_result == 0) {
                        if (current->repeat_count > 1u)
                            --current->repeat_count;
                        current->deadline_us =
                            current->interval_us > UINT64_MAX - now_us ?
                            UINT64_MAX : now_us + current->interval_us;
                        current->ready_latched = 0u;
                    } else {
                        current->ready_latched = 0u;
                    }
                }
                spin_unlock_irqrestore(&g_io_uring_lock, flags);
            } else if (completion_result < 0 &&
                       (completion_flags & (1u << 1))) {
                flags = spin_lock_irqsave(&g_io_uring_lock);
                ring = io_uring_lookup_locked(ring_id);
                if (ring && ring->pending[slot].used &&
                    ring->pending[slot].kind == IO_URING_PENDING_POLL &&
                    ring->pending[slot].sequence == pending.sequence)
                    ring->pending[slot].ready_latched = 0u;
                spin_unlock_irqrestore(&g_io_uring_lock, flags);
            }
            if (completion_result == 0) ++count;
        }
    }
    return count;
}

static int io_uring_region(kernel_io_uring_t *ring, uint64_t offset,
                           kernel_io_uring_page_t **pages,
                           uint32_t *page_count) {
    if (offset == KERNEL_IO_URING_OFF_SQ_RING) {
        *pages = ring->sq_ring;
        *page_count = ring->sq_ring_pages;
    } else if (offset == KERNEL_IO_URING_OFF_CQ_RING) {
        *pages = ring->cq_ring;
        *page_count = ring->cq_ring_pages;
    } else if (offset == KERNEL_IO_URING_OFF_SQES) {
        *pages = ring->sqes;
        *page_count = ring->sqe_pages;
    } else if (offset == KERNEL_IO_URING_OFF_PARAM_REGION &&
               ring->region_registered) {
        *pages = ring->wait_region;
        *page_count = ring->wait_region_pages;
    } else {
        return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

int kernel_io_uring_mmap_info(int32_t ring_id, uint64_t offset,
                              uint64_t length, uint32_t *page_count) {
    kernel_io_uring_page_t *pages;
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t count;
    int result;
    if (!length || !page_count) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    result = io_uring_region(ring, offset, &pages, &count);
    (void)pages;
    if (result == 0 &&
        (length > (uint64_t)count * KERNEL_IO_URING_PAGE_SIZE ||
         ((length + KERNEL_IO_URING_PAGE_SIZE - 1u) /
          KERNEL_IO_URING_PAGE_SIZE) > count))
        result = -EDGE_LINUX_EINVAL;
    if (result == 0) *page_count = io_uring_page_count(length);
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_mmap_page(int32_t ring_id, uint64_t offset,
                              uint32_t page_index,
                              kernel_io_uring_page_t *page) {
    kernel_io_uring_page_t *pages;
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t count;
    int result;
    if (!page) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    result = io_uring_region(ring, offset, &pages, &count);
    if (result == 0 && page_index >= count)
        result = -EDGE_LINUX_EINVAL;
    if (result == 0) {
        result = g_io_uring_allocator.retain(
            g_io_uring_allocator.context, &pages[page_index]);
        if (result == 0) *page = pages[page_index];
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_take_submission(
        int32_t ring_id, struct edge_linux_io_uring_sqe *submission) {
    kernel_io_uring_t *ring;
    volatile uint32_t *head_pointer;
    volatile uint32_t *tail_pointer;
    volatile uint32_t *dropped_pointer;
    uint32_t head;
    uint32_t tail;
    uint32_t sqe_index;
    uint64_t flags;
    void *source;
    if (!submission) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    if (ring->disabled) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADFD;
    }
    head_pointer = io_uring_u32(ring->sq_ring, IORING_SQ_HEAD_OFFSET);
    tail_pointer = io_uring_u32(ring->sq_ring, IORING_SQ_TAIL_OFFSET);
    head = __atomic_load_n(head_pointer, __ATOMIC_RELAXED);
    tail = __atomic_load_n(tail_pointer, __ATOMIC_ACQUIRE);
    if (head == tail) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EAGAIN;
    }
    if (tail - head > ring->sq_entries) {
        dropped_pointer = io_uring_u32(
            ring->sq_ring, IORING_SQ_DROPPED_OFFSET);
        __atomic_add_fetch(dropped_pointer, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(head_pointer, tail, __ATOMIC_RELEASE);
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADMSG;
    }
    sqe_index = __atomic_load_n(
        io_uring_u32(ring->sq_ring,
            IORING_SQ_ARRAY_OFFSET +
            (head & (ring->sq_entries - 1u)) * sizeof(uint32_t)),
        __ATOMIC_RELAXED);
    __atomic_store_n(head_pointer, head + 1u, __ATOMIC_RELEASE);
    if (sqe_index >= ring->sq_entries) {
        dropped_pointer = io_uring_u32(
            ring->sq_ring, IORING_SQ_DROPPED_OFFSET);
        __atomic_add_fetch(dropped_pointer, 1u, __ATOMIC_RELAXED);
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADMSG;
    }
    source = io_uring_region_pointer(
        ring->sqes,
        sqe_index * (uint32_t)sizeof(struct edge_linux_io_uring_sqe));
    memcpy(submission, source, sizeof(*submission));
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return 0;
}

static int io_uring_completion_add_locked(
        kernel_io_uring_t *ring, uint64_t user_data,
        int32_t result, uint32_t cqe_flags) {
    struct edge_linux_io_uring_cqe *completion;
    volatile uint32_t *head_pointer;
    volatile uint32_t *tail_pointer;
    volatile uint32_t *overflow_pointer;
    uint32_t head;
    uint32_t tail;
    uint32_t offset;
    if (!ring) return -EDGE_LINUX_EBADF;
    head_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_HEAD_OFFSET);
    tail_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_TAIL_OFFSET);
    head = __atomic_load_n(head_pointer, __ATOMIC_ACQUIRE);
    tail = __atomic_load_n(tail_pointer, __ATOMIC_RELAXED);
    if (tail - head >= ring->cq_entries) {
        overflow_pointer = io_uring_u32(
            ring->cq_ring, IORING_CQ_OVERFLOW_OFFSET);
        __atomic_add_fetch(overflow_pointer, 1u, __ATOMIC_RELAXED);
        return -EDGE_LINUX_EBUSY;
    }
    offset = IORING_CQ_CQES_OFFSET +
             (tail & (ring->cq_entries - 1u)) *
             (uint32_t)sizeof(*completion);
    completion = io_uring_region_pointer(ring->cq_ring, offset);
    completion->user_data = user_data;
    completion->result = result;
    completion->flags = cqe_flags;
    __atomic_store_n(tail_pointer, tail + 1u, __ATOMIC_RELEASE);
    return 0;
}

static int io_uring_completion_add(int32_t ring_id, uint64_t user_data,
                                   int32_t result, uint32_t cqe_flags,
                                   int asynchronous) {
    kernel_io_uring_t *ring;
    int32_t event_id = -1;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int status;

    ring = io_uring_lookup_locked(ring_id);
    status = io_uring_completion_add_locked(
        ring, user_data, result, cqe_flags);
    if (status == 0)
        event_id = io_uring_event_retain_locked(ring, asynchronous);
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    return status;
}

int kernel_io_uring_completion_add(int32_t ring_id, uint64_t user_data,
                                   int32_t result, uint32_t cqe_flags) {
    return io_uring_completion_add(
        ring_id, user_data, result, cqe_flags, 0);
}

int kernel_io_uring_completion_add_async(int32_t ring_id,
                                         uint64_t user_data,
                                         int32_t result,
                                         uint32_t cqe_flags) {
    return io_uring_completion_add(
        ring_id, user_data, result, cqe_flags, 1);
}

uint32_t kernel_io_uring_completion_count(int32_t ring_id) {
    kernel_io_uring_t *ring;
    volatile uint32_t *head_pointer;
    volatile uint32_t *tail_pointer;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    uint32_t result = 0;
    ring = io_uring_lookup_locked(ring_id);
    if (ring) {
        head_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_HEAD_OFFSET);
        tail_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_TAIL_OFFSET);
        result = __atomic_load_n(tail_pointer, __ATOMIC_ACQUIRE) -
                 __atomic_load_n(head_pointer, __ATOMIC_RELAXED);
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

uint32_t kernel_io_uring_completion_capacity(int32_t ring_id) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    uint32_t result = 0;

    ring = io_uring_lookup_locked(ring_id);
    if (ring) result = ring->cq_entries;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

static uint64_t io_uring_saturating_add(uint64_t first, uint64_t second) {
    return second > UINT64_MAX - first ? UINT64_MAX : first + second;
}

int kernel_io_uring_wait_deadlines(uint64_t start_us,
                                   uint64_t timeout_us,
                                   int timeout_present,
                                   int absolute_timeout,
                                   uint32_t minimum_wait_us,
                                   uint64_t *minimum_deadline_us,
                                   uint64_t *wait_deadline_us) {
    uint64_t minimum_deadline = 0;
    uint64_t wait_deadline = UINT64_MAX;

    if (!minimum_deadline_us || !wait_deadline_us)
        return -EDGE_LINUX_EINVAL;
    if (minimum_wait_us)
        minimum_deadline = io_uring_saturating_add(
            start_us, minimum_wait_us);
    if (timeout_present)
        wait_deadline = absolute_timeout ? timeout_us :
            io_uring_saturating_add(start_us, timeout_us);
    if (minimum_deadline &&
        (wait_deadline == UINT64_MAX || wait_deadline < minimum_deadline))
        wait_deadline = minimum_deadline;
    *minimum_deadline_us = minimum_deadline;
    *wait_deadline_us = wait_deadline;
    return 0;
}
