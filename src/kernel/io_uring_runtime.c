/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux io_uring ring storage and lifetime. */

#include <stdint.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/event_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/fd_runtime.h"
#include "kernel/futex_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_time.h"
#include "kernel/mm_runtime.h"
#include "kernel/runtime_limits.h"
#include "string.h"
#include "sys/spinlock.h"

#define IORING_SETUP_CQSIZE          (1u << 3)
#define IORING_SETUP_CLAMP           (1u << 4)
#define IORING_SETUP_R_DISABLED      (1u << 6)
#define IORING_SETUP_SUBMIT_ALL      (1u << 7)
#define IORING_SETUP_COOP_TASKRUN    (1u << 8)
#define IORING_SETUP_TASKRUN_FLAG    (1u << 9)
#define IORING_SETUP_SQE128          (1u << 10)
#define IORING_SETUP_CQE32           (1u << 11)
#define IORING_SETUP_SINGLE_ISSUER   (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN   (1u << 13)
#define IORING_SETUP_NO_SQARRAY      (1u << 16)
#define IORING_SETUP_CQE_MIXED       (1u << 18)
#define IORING_SETUP_SQE_MIXED       (1u << 19)
#define IORING_SETUP_SQ_REWIND       (1u << 20)

#define IORING_CQE_F_SKIP            (1u << 5)
#define IORING_CQE_F_32              (1u << 15)

#define IORING_OP_NOP128             63u
#define IORING_OP_URING_CMD128       64u

#define IORING_FEAT_SUBMIT_STABLE    (1u << 2)
#define IORING_FEAT_RW_CUR_POS       (1u << 3)
#define IORING_FEAT_POLL_32BITS      (1u << 6)
#define IORING_FEAT_CQE_SKIP         (1u << 11)
#define IORING_SQ_CQ_OVERFLOW        (1u << 1)

#define IORING_SETUP_SUPPORTED \
    (IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | \
     IORING_SETUP_R_DISABLED | IORING_SETUP_SUBMIT_ALL | \
     IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | \
     IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | \
     IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | \
     IORING_SETUP_NO_SQARRAY | IORING_SETUP_CQE_MIXED | \
     IORING_SETUP_SQE_MIXED | IORING_SETUP_SQ_REWIND)

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
#define IO_URING_MAX_COMPLETION_OVERFLOW 128u

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
    uint64_t link_target_sequence;
    uint64_t futex_wait_id;
    uint64_t user_address;
    uint64_t address_space;
    uint32_t maximum_events;
    uint8_t event_size;
    uint8_t event_data_offset;
    uint16_t reserved3;
    kernel_fd_operation_lease_t descriptor_lease;
} kernel_io_uring_pending_t;

typedef struct kernel_io_uring_fixed_buffer {
    uint64_t address;
    uint64_t length;
    uint64_t tag;
} kernel_io_uring_fixed_buffer_t;

typedef struct kernel_io_uring_provided_buffer {
    uint64_t address;
    uint64_t sequence;
    uint32_t length;
    uint16_t group_id;
    uint16_t buffer_id;
    uint8_t used;
    uint8_t reserved[7];
} kernel_io_uring_provided_buffer_t;

typedef struct kernel_io_uring_buffer_group {
    uint64_t ring_address;
    uint64_t ring_address_space;
    uint32_t ring_entries;
    uint32_t minimum_left;
    uint16_t ring_head;
    uint16_t ring_page_count;
    uint16_t id;
    uint8_t used;
    uint8_t provided_ring;
    uint8_t kernel_allocated;
    uint8_t incremental;
} kernel_io_uring_buffer_group_t;

typedef struct kernel_io_uring_overflow_completion {
    struct edge_linux_io_uring_cqe completion;
    uint64_t extra1;
    uint64_t extra2;
} kernel_io_uring_overflow_completion_t;

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
    uint32_t fixed_file_reservations[KERNEL_IO_URING_MAX_FIXED_FILES];
    uint64_t fixed_file_tags[KERNEL_IO_URING_MAX_FIXED_FILES];
    uint32_t fixed_file_count;
    uint32_t fixed_file_page_count;
    uint32_t file_alloc_start;
    uint32_t file_alloc_end;
    uint32_t file_alloc_hint;
    uint32_t next_fixed_file_reservation;
    uint32_t fixed_file_reservation_count;
    kernel_io_uring_fixed_buffer_t
        fixed_buffers[KERNEL_IO_URING_MAX_FIXED_BUFFERS];
    uint32_t fixed_buffer_count;
    kernel_io_uring_provided_buffer_t
        provided_buffers[KERNEL_IO_URING_MAX_PROVIDED_BUFFERS];
    kernel_io_uring_buffer_group_t
        buffer_groups[KERNEL_IO_URING_MAX_BUFFER_GROUPS];
    kernel_io_uring_page_t pbuf_pages[KERNEL_IO_URING_MAX_PBUF_PAGES];
    uint16_t pbuf_page_groups[KERNEL_IO_URING_MAX_PBUF_PAGES];
    uint8_t pbuf_page_used[KERNEL_IO_URING_MAX_PBUF_PAGES];
    uint64_t next_provided_buffer_sequence;
    uint32_t clock_id;
    kernel_io_uring_pending_t pending[KERNEL_IO_URING_MAX_PENDING];
    kernel_io_uring_overflow_completion_t
        completion_overflow[IO_URING_MAX_COMPLETION_OVERFLOW];
    uint32_t completion_overflow_head;
    uint32_t completion_overflow_count;
} kernel_io_uring_t;

typedef struct kernel_io_uring_task_registry {
    uint8_t used;
    int32_t task_id;
    int32_t ring_ids[KERNEL_IO_URING_REGISTERED_RINGS];
} kernel_io_uring_task_registry_t;

static int io_uring_completion_add_locked(
    kernel_io_uring_t *ring, uint64_t user_data,
    int32_t result, uint32_t cqe_flags);

static int io_uring_completion_add_extended_locked(
    kernel_io_uring_t *ring, uint64_t user_data,
    int32_t result, uint32_t cqe_flags,
    uint64_t extra1, uint64_t extra2);

static int io_uring_completion_publish_locked(
    kernel_io_uring_t *ring, uint64_t user_data,
    int32_t result, uint32_t cqe_flags,
    uint64_t extra1, uint64_t extra2);

static uint32_t io_uring_completion_overflow_flush_locked(
    kernel_io_uring_t *ring);

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
#define IO_URING_PENDING_EPOLL   3u
#define IO_URING_PENDING_LINK_TIMEOUT 4u
#define IO_URING_PENDING_FUTEX 5u

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
    for (uint32_t slot = 0;
         slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
        kernel_io_uring_pending_t *pending = &ring->pending[slot];
        if (pending->used &&
            pending->kind == IO_URING_PENDING_POLL &&
            kernel_fd_operation_view(&pending->descriptor_lease))
            (void)kernel_fd_operation_release(
                &pending->descriptor_lease);
        if (pending->used &&
            pending->kind == IO_URING_PENDING_EPOLL)
            kernel_epoll_object_release(pending->descriptor);
        if (pending->used &&
            pending->kind == IO_URING_PENDING_FUTEX)
            (void)kernel_futex_async_wait_cancel(
                pending->futex_wait_id);
    }
    for (uint32_t page = 0;
         page < KERNEL_IO_URING_MAX_PBUF_PAGES; ++page) {
        if (ring->pbuf_page_used[page])
            g_io_uring_allocator.release(
                g_io_uring_allocator.context,
                &ring->pbuf_pages[page]);
        memset(&ring->pbuf_pages[page], 0,
               sizeof(ring->pbuf_pages[page]));
        ring->pbuf_page_used[page] = 0u;
        ring->pbuf_page_groups[page] = 0u;
    }
}

static void io_uring_fixed_file_reservation_clear(
        kernel_io_uring_fixed_file_reservation_t *reservation) {
    if (!reservation) return;
    reservation->ring_id = -1;
    reservation->indices[0] = UINT32_MAX;
    reservation->indices[1] = UINT32_MAX;
    reservation->cookie = 0u;
    reservation->active = 0u;
    memset(reservation->reserved, 0, sizeof(reservation->reserved));
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
    if ((parameters->flags & IORING_SETUP_DEFER_TASKRUN) &&
        !(parameters->flags & IORING_SETUP_SINGLE_ISSUER))
        return -EDGE_LINUX_EINVAL;
    if ((parameters->flags & IORING_SETUP_SQ_REWIND) &&
        !(parameters->flags & IORING_SETUP_NO_SQARRAY))
        return -EDGE_LINUX_EINVAL;
    if ((parameters->flags & (IORING_SETUP_CQE32 |
                              IORING_SETUP_CQE_MIXED)) ==
        (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED))
        return -EDGE_LINUX_EINVAL;
    if ((parameters->flags & (IORING_SETUP_SQE128 |
                              IORING_SETUP_SQE_MIXED)) ==
        (IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED))
        return -EDGE_LINUX_EINVAL;
    if (entries > KERNEL_IO_URING_MAX_SQ_ENTRIES) {
        if (!(parameters->flags & IORING_SETUP_CLAMP))
            return -EDGE_LINUX_EINVAL;
        entries = KERNEL_IO_URING_MAX_SQ_ENTRIES;
    }
    entries = io_uring_round_entries(entries);
    if ((parameters->flags & IORING_SETUP_SQE_MIXED) && entries < 2u)
        return -EDGE_LINUX_EOVERFLOW;
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
    if ((parameters->flags & IORING_SETUP_CQE_MIXED) && cq_entries < 2u)
        return -EDGE_LINUX_EOVERFLOW;

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
        (parameters->flags & IORING_SETUP_NO_SQARRAY) ?
            IORING_SQ_ARRAY_OFFSET :
            IORING_SQ_ARRAY_OFFSET +
                (uint64_t)entries * sizeof(uint32_t));
    ring->cq_ring_pages = io_uring_page_count(
        IORING_CQ_CQES_OFFSET +
        (uint64_t)cq_entries *
            ((parameters->flags & IORING_SETUP_CQE32) ? 32u : 16u));
    ring->sqe_pages = io_uring_page_count(
        (uint64_t)entries *
            ((parameters->flags & IORING_SETUP_SQE128) ? 128u : 64u));
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
    memset(&parameters->sq_off, 0, sizeof(parameters->sq_off));
    memset(&parameters->cq_off, 0, sizeof(parameters->cq_off));
    parameters->sq_off.head = IORING_SQ_HEAD_OFFSET;
    parameters->sq_off.tail = IORING_SQ_TAIL_OFFSET;
    parameters->sq_off.ring_mask = IORING_SQ_RING_MASK_OFFSET;
    parameters->sq_off.ring_entries = IORING_SQ_RING_ENTRIES_OFFSET;
    parameters->sq_off.flags = IORING_SQ_FLAGS_OFFSET;
    parameters->sq_off.dropped = IORING_SQ_DROPPED_OFFSET;
    if (!(parameters->flags & IORING_SETUP_NO_SQARRAY))
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

int kernel_io_uring_setup_flags(int32_t ring_id, uint32_t *setup_flags) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result = 0;

    if (!setup_flags) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else *setup_flags = ring->setup_flags;
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
    } else if (ring->fixed_file_reservation_count) {
        result = -EDGE_LINUX_EBUSY;
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
    for (uint32_t index = offset; index < offset + count; ++index) {
        if (ring->fixed_file_reservations[index]) {
            result = -EDGE_LINUX_EBUSY;
            goto unlock;
        }
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

static int io_uring_fixed_buffer_validate_registration(
        const struct edge_linux_iovec *buffer) {
    uint64_t accounted_length;

    if (!buffer) return -EDGE_LINUX_EINVAL;
    if (!buffer->iov_base)
        return buffer->iov_len ? -EDGE_LINUX_EFAULT : 0;
    if (!buffer->iov_len) return -EDGE_LINUX_EFAULT;
    if (buffer->iov_len > (UINT64_C(1) << 40))
        return -EDGE_LINUX_EINVAL;
    if (buffer->iov_len >
        UINT64_MAX - (KERNEL_IO_URING_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EOVERFLOW;
    accounted_length =
        (buffer->iov_len + KERNEL_IO_URING_PAGE_SIZE - 1u) &
        ~(uint64_t)(KERNEL_IO_URING_PAGE_SIZE - 1u);
    if (buffer->iov_base > UINT64_MAX - accounted_length)
        return -EDGE_LINUX_EOVERFLOW;
    return 0;
}

int kernel_io_uring_buffers_register(
        int32_t ring_id, const struct edge_linux_iovec *buffers,
        const uint64_t *tags, uint32_t count) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result = 0;

    if (!buffers || !count ||
        count > KERNEL_IO_URING_MAX_FIXED_BUFFERS)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        result = io_uring_fixed_buffer_validate_registration(
            &buffers[index]);
        if (result < 0) return result;
        if (!buffers[index].iov_base && tags && tags[index])
            return -EDGE_LINUX_EINVAL;
    }

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring)
        result = -EDGE_LINUX_EBADF;
    else if (ring->fixed_buffer_count)
        result = -EDGE_LINUX_EBUSY;
    else {
        for (uint32_t index = 0; index < count; ++index) {
            ring->fixed_buffers[index].address =
                buffers[index].iov_base;
            ring->fixed_buffers[index].length =
                buffers[index].iov_len;
            ring->fixed_buffers[index].tag =
                tags ? tags[index] : 0u;
        }
        ring->fixed_buffer_count = count;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_buffers_unregister(int32_t ring_id) {
    kernel_io_uring_t *ring;
    int32_t event_id = -1;
    uint64_t flags;
    int notify = 0;
    int result = 0;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (!ring->fixed_buffer_count) {
        result = -EDGE_LINUX_ENXIO;
    } else {
        for (uint32_t index = 0;
             index < ring->fixed_buffer_count; ++index) {
            if (ring->fixed_buffers[index].tag &&
                io_uring_completion_add_locked(
                    ring, ring->fixed_buffers[index].tag, 0, 0) == 0)
                notify = 1;
        }
        memset(ring->fixed_buffers, 0,
               sizeof(ring->fixed_buffers));
        ring->fixed_buffer_count = 0u;
        if (notify)
            event_id = io_uring_event_retain_locked(ring, 0);
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    return result;
}

int kernel_io_uring_buffers_update(
        int32_t ring_id, uint32_t offset,
        const struct edge_linux_iovec *buffers,
        const uint64_t *tags, uint32_t count) {
    kernel_io_uring_t *ring;
    int32_t event_id = -1;
    uint32_t done;
    uint64_t flags;
    int notify = 0;
    int result = 0;

    if (!buffers || !count) return -EDGE_LINUX_EINVAL;
    if (offset > UINT32_MAX - count)
        return -EDGE_LINUX_EOVERFLOW;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    if (!ring->fixed_buffer_count) {
        result = -EDGE_LINUX_ENXIO;
        goto unlock;
    }
    if (offset + count > ring->fixed_buffer_count) {
        result = -EDGE_LINUX_EINVAL;
        goto unlock;
    }
    for (done = 0; done < count; ++done) {
        const struct edge_linux_iovec *buffer = &buffers[done];
        uint64_t tag = tags ? tags[done] : 0u;
        uint32_t index = offset + done;

        result = io_uring_fixed_buffer_validate_registration(buffer);
        if (result < 0) break;
        if (!buffer->iov_base && tag) {
            result = -EDGE_LINUX_EINVAL;
            break;
        }
        if (ring->fixed_buffers[index].tag &&
            io_uring_completion_add_locked(
                ring, ring->fixed_buffers[index].tag, 0, 0) == 0)
            notify = 1;
        ring->fixed_buffers[index].address = buffer->iov_base;
        ring->fixed_buffers[index].length = buffer->iov_len;
        ring->fixed_buffers[index].tag = tag;
    }
    if (done) result = (int)done;
    else if (result >= 0) result = (int)count;
    if (notify)
        event_id = io_uring_event_retain_locked(ring, 0);

unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    return result;
}

int kernel_io_uring_fixed_buffer_validate(
        int32_t ring_id, uint32_t index,
        uint64_t address, uint64_t length) {
    kernel_io_uring_t *ring;
    kernel_io_uring_fixed_buffer_t *buffer;
    uint64_t end;
    uint64_t limit;
    uint64_t flags;
    int result;

    if (address > UINT64_MAX - length)
        return -EDGE_LINUX_EFAULT;
    end = address + length;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (index >= ring->fixed_buffer_count) {
        result = -EDGE_LINUX_EFAULT;
    } else {
        buffer = &ring->fixed_buffers[index];
        limit = buffer->address + buffer->length;
        result = !buffer->address || address < buffer->address ||
                 end > limit ? -EDGE_LINUX_EFAULT : 0;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_fixed_buffer_registered(
        int32_t ring_id, uint32_t index) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (index >= ring->fixed_buffer_count ||
             !ring->fixed_buffers[index].address)
        result = -EDGE_LINUX_EFAULT;
    else result = 0;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

static kernel_io_uring_buffer_group_t *io_uring_buffer_group_locked(
        kernel_io_uring_t *ring, uint16_t group_id, int create) {
    kernel_io_uring_buffer_group_t *available = 0;

    for (uint32_t index = 0;
         index < KERNEL_IO_URING_MAX_BUFFER_GROUPS; ++index) {
        kernel_io_uring_buffer_group_t *group =
            &ring->buffer_groups[index];

        if (group->used && group->id == group_id) return group;
        if (!group->used && !available) available = group;
    }
    if (!create || !available) return 0;
    memset(available, 0, sizeof(*available));
    available->id = group_id;
    available->used = 1u;
    return available;
}

static kernel_io_uring_provided_buffer_t *
io_uring_oldest_provided_buffer_locked(
        kernel_io_uring_t *ring, uint16_t group_id) {
    kernel_io_uring_provided_buffer_t *oldest = 0;

    for (uint32_t index = 0;
         index < KERNEL_IO_URING_MAX_PROVIDED_BUFFERS; ++index) {
        kernel_io_uring_provided_buffer_t *buffer =
            &ring->provided_buffers[index];

        if (!buffer->used || buffer->group_id != group_id)
            continue;
        if (!oldest || buffer->sequence < oldest->sequence)
            oldest = buffer;
    }
    return oldest;
}

int kernel_io_uring_provided_buffers_add(
        int32_t ring_id, uint16_t group_id, uint16_t first_buffer_id,
        uint64_t address, uint32_t length, uint32_t count) {
    kernel_io_uring_t *ring;
    uint64_t total_length;
    uint64_t flags;
    uint32_t added = 0u;
    int result = 0;

    if (!length || !count || count > UINT16_MAX + 1u)
        return -EDGE_LINUX_EINVAL;
    if (count > UINT16_MAX + 1u - (uint32_t)first_buffer_id)
        return -EDGE_LINUX_EINVAL;
    if ((uint64_t)count > UINT64_MAX / length)
        return -EDGE_LINUX_EOVERFLOW;
    total_length = (uint64_t)count * length;
    if (address > UINT64_MAX - total_length)
        return -EDGE_LINUX_EOVERFLOW;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    if (!io_uring_buffer_group_locked(ring, group_id, 1)) {
        result = -EDGE_LINUX_ENOMEM;
        goto unlock;
    }
    if (io_uring_buffer_group_locked(ring, group_id, 0)->provided_ring) {
        result = -EDGE_LINUX_EEXIST;
        goto unlock;
    }
    for (uint32_t index = 0;
         index < KERNEL_IO_URING_MAX_PROVIDED_BUFFERS && added < count;
         ++index) {
        kernel_io_uring_provided_buffer_t *buffer =
            &ring->provided_buffers[index];

        if (buffer->used) continue;
        buffer->address = address + (uint64_t)added * length;
        buffer->length = length;
        buffer->group_id = group_id;
        buffer->buffer_id = (uint16_t)(first_buffer_id + added);
        buffer->sequence = ++ring->next_provided_buffer_sequence;
        buffer->used = 1u;
        ++added;
    }
    if (!added) result = -EDGE_LINUX_ENOMEM;

unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_provided_buffers_remove(
        int32_t ring_id, uint16_t group_id, uint32_t count) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t removed = 0u;
    int result;

    if (!count || count > UINT16_MAX + 1u)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (!io_uring_buffer_group_locked(ring, group_id, 0)) {
        result = -EDGE_LINUX_ENOENT;
    } else if (io_uring_buffer_group_locked(
                   ring, group_id, 0)->provided_ring) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        while (removed < count) {
            kernel_io_uring_provided_buffer_t *buffer =
                io_uring_oldest_provided_buffer_locked(ring, group_id);

            if (!buffer) break;
            memset(buffer, 0, sizeof(*buffer));
            ++removed;
        }
        result = (int)removed;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_provided_buffer_select(
        int32_t ring_id, uint16_t group_id, uint32_t requested_length,
        kernel_io_uring_selected_buffer_t *selected) {
    kernel_io_uring_provided_buffer_t *buffer;
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (!selected) return -EDGE_LINUX_EINVAL;
    memset(selected, 0, sizeof(*selected));
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (!io_uring_buffer_group_locked(ring, group_id, 0)) {
        result = -EDGE_LINUX_ENOBUFS;
    } else if (io_uring_buffer_group_locked(
                   ring, group_id, 0)->provided_ring) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        buffer = io_uring_oldest_provided_buffer_locked(ring, group_id);
        if (!buffer) {
            result = -EDGE_LINUX_ENOBUFS;
        } else {
            selected->address = buffer->address;
            selected->capacity = buffer->length;
            selected->length = !requested_length ||
                               requested_length > buffer->length ?
                               buffer->length : requested_length;
            selected->id = buffer->buffer_id;
            selected->group_id = buffer->group_id;
            memset(buffer, 0, sizeof(*buffer));
            result = 0;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_pbuf_ring_register(
        int32_t ring_id, uint16_t group_id, uint64_t address,
        uint64_t address_space,
        uint32_t entries, int kernel_allocated,
        int incremental, uint32_t minimum_left) {
    kernel_io_uring_buffer_group_t *group;
    kernel_io_uring_t *ring;
    uint32_t page_count;
    uint64_t flags;
    int result = 0;

    if ((!address && !kernel_allocated) ||
        (address && kernel_allocated) ||
        (!address_space && !kernel_allocated) ||
        (address_space && kernel_allocated) ||
        !entries || entries > UINT16_MAX)
        return -EDGE_LINUX_EINVAL;
    page_count = io_uring_page_count(
        (uint64_t)entries *
        sizeof(struct edge_linux_io_uring_buf));
    if (page_count > KERNEL_IO_URING_MAX_PBUF_PAGES)
        return -EDGE_LINUX_ENOMEM;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    group = io_uring_buffer_group_locked(ring, group_id, 0);
    if (group) {
        if (group->provided_ring ||
            io_uring_oldest_provided_buffer_locked(ring, group_id)) {
            result = -EDGE_LINUX_EEXIST;
            goto unlock;
        }
        memset(group, 0, sizeof(*group));
        group->id = group_id;
        group->used = 1u;
    } else {
        group = io_uring_buffer_group_locked(ring, group_id, 1);
        if (!group) {
            result = -EDGE_LINUX_ENOMEM;
            goto unlock;
        }
    }
    if (kernel_allocated) {
        uint32_t allocated = 0u;

        for (uint32_t page = 0;
             page < KERNEL_IO_URING_MAX_PBUF_PAGES &&
             allocated < page_count; ++page) {
            kernel_io_uring_page_t *storage;

            if (ring->pbuf_page_used[page]) continue;
            storage = &ring->pbuf_pages[page];
            if (g_io_uring_allocator.allocate(
                    g_io_uring_allocator.context, storage) < 0 ||
                !storage->address)
                break;
            memset(storage->address, 0, KERNEL_IO_URING_PAGE_SIZE);
            ring->pbuf_page_groups[page] = group_id;
            ring->pbuf_page_used[page] = 1u;
            ++allocated;
        }
        if (allocated != page_count) {
            for (uint32_t page = 0;
                 page < KERNEL_IO_URING_MAX_PBUF_PAGES; ++page) {
                if (!ring->pbuf_page_used[page] ||
                    ring->pbuf_page_groups[page] != group_id)
                    continue;
                g_io_uring_allocator.release(
                    g_io_uring_allocator.context,
                    &ring->pbuf_pages[page]);
                memset(&ring->pbuf_pages[page], 0,
                       sizeof(ring->pbuf_pages[page]));
                ring->pbuf_page_used[page] = 0u;
                ring->pbuf_page_groups[page] = 0u;
            }
            memset(group, 0, sizeof(*group));
            result = -EDGE_LINUX_ENOMEM;
            goto unlock;
        }
    }
    group->ring_address = address;
    group->ring_address_space = address_space;
    group->ring_entries = entries;
    group->minimum_left = minimum_left;
    group->ring_page_count = kernel_allocated ?
        (uint16_t)page_count : 0u;
    group->provided_ring = 1u;
    group->kernel_allocated = kernel_allocated ? 1u : 0u;
    group->incremental = incremental ? 1u : 0u;
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_pbuf_ring_unregister(
        int32_t ring_id, uint16_t group_id) {
    kernel_io_uring_buffer_group_t *group;
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result = 0;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    group = io_uring_buffer_group_locked(ring, group_id, 0);
    if (!group) {
        result = -EDGE_LINUX_ENOENT;
    } else if (!group->provided_ring) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        if (group->kernel_allocated) {
            for (uint32_t page = 0;
                 page < KERNEL_IO_URING_MAX_PBUF_PAGES; ++page) {
                if (!ring->pbuf_page_used[page] ||
                    ring->pbuf_page_groups[page] != group_id)
                    continue;
                g_io_uring_allocator.release(
                    g_io_uring_allocator.context,
                    &ring->pbuf_pages[page]);
                memset(&ring->pbuf_pages[page], 0,
                       sizeof(ring->pbuf_pages[page]));
                ring->pbuf_page_used[page] = 0u;
                ring->pbuf_page_groups[page] = 0u;
            }
        }
        memset(group, 0, sizeof(*group));
    }
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_pbuf_ring_snapshot(
        int32_t ring_id, uint16_t group_id,
        kernel_io_uring_pbuf_ring_t *snapshot) {
    kernel_io_uring_buffer_group_t *group;
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result = 0;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    memset(snapshot, 0, sizeof(*snapshot));
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    group = io_uring_buffer_group_locked(ring, group_id, 0);
    if (!group) {
        result = -EDGE_LINUX_ENOENT;
    } else if (!group->provided_ring) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        snapshot->address = group->ring_address;
        snapshot->address_space = group->ring_address_space;
        snapshot->entries = group->ring_entries;
        snapshot->head = group->ring_head;
        snapshot->minimum_left = group->minimum_left;
        snapshot->kernel_allocated = group->kernel_allocated;
        snapshot->incremental = group->incremental;
    }
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

static kernel_io_uring_page_t *io_uring_pbuf_page_locked(
        kernel_io_uring_t *ring, uint16_t group_id,
        uint32_t page_index) {
    for (uint32_t page = 0;
         page < KERNEL_IO_URING_MAX_PBUF_PAGES; ++page) {
        if (!ring->pbuf_page_used[page] ||
            ring->pbuf_page_groups[page] != group_id)
            continue;
        if (!page_index) return &ring->pbuf_pages[page];
        --page_index;
    }
    return 0;
}

int kernel_io_uring_pbuf_ring_read(
        int32_t ring_id, uint16_t group_id, uint32_t head,
        struct edge_linux_io_uring_buf *buffer, uint16_t *tail) {
    kernel_io_uring_buffer_group_t *group;
    kernel_io_uring_page_t *page;
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t offset;
    int result = 0;

    if (!buffer || !tail) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    group = io_uring_buffer_group_locked(ring, group_id, 0);
    if (!group || !group->provided_ring || !group->kernel_allocated) {
        result = -EDGE_LINUX_EINVAL;
        goto unlock;
    }
    page = io_uring_pbuf_page_locked(ring, group_id, 0u);
    if (!page || !page->address) {
        result = -EDGE_LINUX_EIO;
        goto unlock;
    }
    memcpy(tail,
           &((struct edge_linux_io_uring_buf *)page->address)->reserved,
           sizeof(*tail));
    offset = (head & (group->ring_entries - 1u)) *
        sizeof(*buffer);
    page = io_uring_pbuf_page_locked(
        ring, group_id, offset / KERNEL_IO_URING_PAGE_SIZE);
    if (!page || !page->address) {
        result = -EDGE_LINUX_EIO;
        goto unlock;
    }
    memcpy(buffer, (uint8_t *)page->address +
           offset % KERNEL_IO_URING_PAGE_SIZE, sizeof(*buffer));
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_pbuf_ring_commit(
        int32_t ring_id, uint16_t group_id, uint32_t expected_head) {
    kernel_io_uring_buffer_group_t *group;
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result = 0;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    group = io_uring_buffer_group_locked(ring, group_id, 0);
    if (!group || !group->provided_ring) {
        result = -EDGE_LINUX_EINVAL;
    } else if (group->ring_head != (uint16_t)expected_head) {
        result = -EDGE_LINUX_EAGAIN;
    } else {
        ++group->ring_head;
    }
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_pbuf_ring_complete(
        int32_t ring_id, uint16_t group_id, uint32_t expected_head,
        uint32_t consumed, int *buffer_more) {
    kernel_io_uring_buffer_group_t *group;
    struct edge_linux_io_uring_buf *buffer;
    kernel_io_uring_page_t *page;
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t remaining;
    uint32_t offset;
    int result = 0;

    if (!buffer_more) return -EDGE_LINUX_EINVAL;
    *buffer_more = 0;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    group = io_uring_buffer_group_locked(ring, group_id, 0);
    if (!group || !group->provided_ring ||
        !group->kernel_allocated || !group->incremental) {
        result = -EDGE_LINUX_EINVAL;
        goto unlock;
    }
    if (group->ring_head != (uint16_t)expected_head) {
        result = -EDGE_LINUX_EAGAIN;
        goto unlock;
    }
    offset = (group->ring_head & (group->ring_entries - 1u)) *
        sizeof(*buffer);
    page = io_uring_pbuf_page_locked(
        ring, group_id, offset / KERNEL_IO_URING_PAGE_SIZE);
    if (!page || !page->address) {
        result = -EDGE_LINUX_EIO;
        goto unlock;
    }
    buffer = (struct edge_linux_io_uring_buf *)(
        (uint8_t *)page->address +
        offset % KERNEL_IO_URING_PAGE_SIZE);
    if (consumed > buffer->length) {
        result = -EDGE_LINUX_EIO;
        goto unlock;
    }
    if (!consumed) {
        *buffer_more = 1;
        goto unlock;
    }
    remaining = buffer->length - consumed;
    if (remaining &&
        (!group->minimum_left ||
         remaining >= group->minimum_left)) {
        buffer->address += consumed;
        buffer->length = remaining;
        *buffer_more = 1;
    } else {
        buffer->length = 0u;
        ++group->ring_head;
    }
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
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

static int io_uring_fixed_file_find_free_locked(
        kernel_io_uring_t *ring, uint32_t excluded,
        uint32_t *index) {
    uint32_t start;
    uint32_t length;

    if (!ring || !index ||
        ring->file_alloc_start >= ring->file_alloc_end)
        return -EDGE_LINUX_ENFILE;
    start = ring->file_alloc_hint;
    if (start < ring->file_alloc_start ||
        start >= ring->file_alloc_end)
        start = ring->file_alloc_start;
    length = ring->file_alloc_end - ring->file_alloc_start;
    for (uint32_t offset = 0; offset < length; ++offset) {
        uint32_t candidate = start + offset;
        if (candidate >= ring->file_alloc_end)
            candidate = ring->file_alloc_start +
                candidate - ring->file_alloc_end;
        if (candidate == excluded ||
            ring->fixed_file_used[candidate] ||
            ring->fixed_file_reservations[candidate])
            continue;
        *index = candidate;
        ring->file_alloc_hint = candidate + 1u;
        if (ring->file_alloc_hint >= ring->file_alloc_end)
            ring->file_alloc_hint = ring->file_alloc_start;
        return 0;
    }
    return -EDGE_LINUX_ENFILE;
}

int kernel_io_uring_fixed_file_pair_reserve(
        int32_t ring_id, uint32_t file_slot,
        kernel_io_uring_fixed_file_reservation_t *reservation) {
    kernel_io_uring_t *ring;
    uint32_t indices[2] = {UINT32_MAX, UINT32_MAX};
    uint32_t cookie;
    uint64_t flags;
    int result = 0;

    if (!reservation) return -EDGE_LINUX_EINVAL;
    if (reservation->active) return -EDGE_LINUX_EBUSY;
    io_uring_fixed_file_reservation_clear(reservation);
    if (!file_slot) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else if (!ring->fixed_file_count) {
        result = -EDGE_LINUX_ENXIO;
    } else if (ring->references == UINT32_MAX) {
        result = -EDGE_LINUX_EOVERFLOW;
    } else if (file_slot == UINT32_MAX) {
        result = io_uring_fixed_file_find_free_locked(
            ring, UINT32_MAX, &indices[0]);
        if (result == 0)
            result = io_uring_fixed_file_find_free_locked(
                ring, indices[0], &indices[1]);
    } else {
        indices[0] = file_slot - 1u;
        if (ring->fixed_file_count < 2u ||
            indices[0] > ring->fixed_file_count - 2u) {
            result = -EDGE_LINUX_EINVAL;
        } else if (ring->fixed_file_reservations[indices[0]] ||
                   ring->fixed_file_reservations[indices[0] + 1u]) {
            result = -EDGE_LINUX_EBUSY;
        } else {
            indices[1] = indices[0] + 1u;
        }
    }
    if (result == 0) {
        cookie = ++ring->next_fixed_file_reservation;
        if (!cookie) cookie = ++ring->next_fixed_file_reservation;
        ring->fixed_file_reservations[indices[0]] = cookie;
        ring->fixed_file_reservations[indices[1]] = cookie;
        ++ring->fixed_file_reservation_count;
        ++ring->references;
        reservation->ring_id = ring_id;
        reservation->indices[0] = indices[0];
        reservation->indices[1] = indices[1];
        reservation->cookie = cookie;
        reservation->active = 1u;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

static int io_uring_fixed_file_pair_finish_locked(
        kernel_io_uring_t *ring,
        const kernel_io_uring_fixed_file_reservation_t *reservation) {
    if (!ring || !reservation || !reservation->active ||
        reservation->indices[0] >= ring->fixed_file_count ||
        reservation->indices[1] >= ring->fixed_file_count ||
        ring->fixed_file_reservations[reservation->indices[0]] !=
            reservation->cookie ||
        ring->fixed_file_reservations[reservation->indices[1]] !=
            reservation->cookie)
        return -EDGE_LINUX_EINVAL;
    ring->fixed_file_reservations[reservation->indices[0]] = 0u;
    ring->fixed_file_reservations[reservation->indices[1]] = 0u;
    if (ring->fixed_file_reservation_count)
        --ring->fixed_file_reservation_count;
    return 0;
}

int kernel_io_uring_fixed_file_pair_cancel(
        kernel_io_uring_fixed_file_reservation_t *reservation) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result;

    if (!reservation || !reservation->active)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(reservation->ring_id);
    result = io_uring_fixed_file_pair_finish_locked(
        ring, reservation);
    if (result == 0 && ring->references && --ring->references == 0u) {
        io_uring_release_storage(ring);
        memset(ring, 0, sizeof(*ring));
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result == 0)
        io_uring_fixed_file_reservation_clear(reservation);
    return result;
}

int kernel_io_uring_fixed_file_pair_commit(
        kernel_io_uring_fixed_file_reservation_t *reservation,
        const kernel_fd_publication_t *publication) {
    kernel_fd_operation_lease_t sources[2] = {0};
    kernel_io_uring_t *ring;
    uint32_t indices[2];
    int32_t event_id = -1;
    uint32_t installed = 0u;
    uint32_t reservation_finished = 0u;
    uint64_t flags;
    int notify = 0;
    int result;

    if (!reservation || !reservation->active ||
        reservation->indices[0] >= KERNEL_IO_URING_MAX_FIXED_FILES ||
        reservation->indices[1] >= KERNEL_IO_URING_MAX_FIXED_FILES ||
        !publication ||
        !publication->active || publication->count != 2u)
        return -EDGE_LINUX_EINVAL;
    indices[0] = reservation->indices[0];
    indices[1] = reservation->indices[1];
    result = kernel_fd_operation_acquire_from_publication(
        publication, 0u, &sources[0]);
    if (result < 0) goto cancel;
    result = kernel_fd_operation_acquire_from_publication(
        publication, 1u, &sources[1]);
    if (result < 0) goto release_sources;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(reservation->ring_id);
    result = io_uring_fixed_file_pair_finish_locked(
        ring, reservation);
    if (result < 0) goto unlock;
    reservation_finished = 1u;
    for (uint32_t item = 0; item < 2u; ++item) {
        uint32_t index = indices[item];
        kernel_fd_operation_lease_t *destination =
            io_uring_fixed_file_lease(
                ring->fixed_file_pages, index);

        if (!destination) {
            result = -EDGE_LINUX_EBADF;
            break;
        }
        if (ring->fixed_file_used[index]) {
            if (ring->fixed_file_tags[index] &&
                io_uring_completion_add_locked(
                    ring, ring->fixed_file_tags[index], 0, 0) == 0)
                notify = 1;
            (void)kernel_fd_operation_release(destination);
            ring->fixed_file_used[index] = 0u;
            ring->fixed_file_tags[index] = 0u;
        }
        result = kernel_fd_operation_move(destination, &sources[item]);
        if (result < 0) break;
        ring->fixed_file_used[index] = 1u;
        ring->fixed_file_tags[index] = 0u;
        ++installed;
    }
    if (result < 0) {
        for (uint32_t item = 0;
             item < installed && item < 2u; ++item) {
            uint32_t index = indices[item];
            kernel_fd_operation_lease_t *destination =
                index < KERNEL_IO_URING_MAX_FIXED_FILES ?
                    io_uring_fixed_file_lease(
                        ring->fixed_file_pages, index) : 0;
            if (index >= KERNEL_IO_URING_MAX_FIXED_FILES)
                continue;
            if (ring->fixed_file_used[index] && destination)
                (void)kernel_fd_operation_release(destination);
            ring->fixed_file_used[index] = 0u;
            ring->fixed_file_tags[index] = 0u;
        }
    }
    if (notify) event_id = io_uring_event_retain_locked(ring, 0);
    if (ring->references && --ring->references == 0u) {
        io_uring_release_storage(ring);
        memset(ring, 0, sizeof(*ring));
    }

unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    if (reservation_finished)
        io_uring_fixed_file_reservation_clear(reservation);

release_sources:
    for (uint32_t item = 0; item < 2u; ++item)
        if (kernel_fd_operation_view(&sources[item]))
            (void)kernel_fd_operation_release(&sources[item]);
    if (result < 0 && reservation->active)
        (void)kernel_io_uring_fixed_file_pair_cancel(reservation);
    return result;

cancel:
    (void)kernel_io_uring_fixed_file_pair_cancel(reservation);
    return result;
}

int kernel_io_uring_fixed_file_transfer(
        int32_t source_ring_id, uint32_t source_index,
        int32_t target_ring_id, uint32_t target_file_slot) {
    kernel_fd_operation_lease_t clone = {0};
    kernel_fd_operation_lease_t *source_lease;
    kernel_fd_operation_lease_t *destination;
    kernel_io_uring_t *source;
    kernel_io_uring_t *target;
    uint32_t target_index = UINT32_MAX;
    int32_t event_id = -1;
    uint64_t flags;
    int allocated;
    int notify = 0;
    int result;

    if (source_ring_id == target_ring_id)
        return -EDGE_LINUX_EINVAL;
    allocated = target_file_slot == UINT32_MAX;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    source = io_uring_lookup_locked(source_ring_id);
    target = io_uring_lookup_locked(target_ring_id);
    if (!source || !target) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    if (source_index >= source->fixed_file_count ||
        !source->fixed_file_used[source_index]) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    if (!target->fixed_file_count) {
        result = -EDGE_LINUX_ENXIO;
        goto unlock;
    }
    if (!allocated && !target_file_slot) {
        result = -EDGE_LINUX_EINVAL;
        goto unlock;
    }
    if (allocated) {
        result = io_uring_fixed_file_find_free_locked(
            target, UINT32_MAX, &target_index);
        if (result < 0) goto unlock;
    } else {
        target_index = target_file_slot - 1u;
        if (target_index >= target->fixed_file_count) {
            result = -EDGE_LINUX_EINVAL;
            goto unlock;
        }
        if (target->fixed_file_reservations[target_index]) {
            result = -EDGE_LINUX_EBUSY;
            goto unlock;
        }
    }

    source_lease = io_uring_fixed_file_lease(
        source->fixed_file_pages, source_index);
    destination = io_uring_fixed_file_lease(
        target->fixed_file_pages, target_index);
    if (!source_lease || !destination) {
        result = -EDGE_LINUX_EBADF;
        goto unlock;
    }
    result = kernel_fd_operation_clone(&clone, source_lease);
    if (result < 0) goto unlock;
    if (target->fixed_file_used[target_index]) {
        if (target->fixed_file_tags[target_index] &&
            io_uring_completion_add_locked(
                target, target->fixed_file_tags[target_index],
                0, 0) == 0)
            notify = 1;
        (void)kernel_fd_operation_release(destination);
        target->fixed_file_used[target_index] = 0u;
        target->fixed_file_tags[target_index] = 0u;
    }
    result = kernel_fd_operation_move(destination, &clone);
    if (result < 0) goto unlock;
    target->fixed_file_used[target_index] = 1u;
    target->fixed_file_tags[target_index] = 0u;
    result = allocated ? (int)target_index : 0;
    if (notify)
        event_id = io_uring_event_retain_locked(target, 0);

unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    if (kernel_fd_operation_view(&clone))
        (void)kernel_fd_operation_release(&clone);
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

int kernel_io_uring_fixed_file_registered(
        int32_t ring_id, uint32_t index) {
    kernel_io_uring_t *ring;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else if (index >= ring->fixed_file_count ||
             !ring->fixed_file_used[index])
        result = -EDGE_LINUX_EBADF;
    else result = 0;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

static int io_uring_pending_add(int32_t ring_id, uint8_t kind,
                                uint64_t user_data, int32_t descriptor,
                                uint32_t events, uint64_t deadline_us,
                                uint32_t completion_target,
                                int32_t expiration_result,
                                int realtime_clock, uint64_t interval_us,
                                uint32_t repeat_count, int multishot) {
    kernel_fd_operation_lease_t descriptor_lease = {0};
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t slot;
    int result = 0;
    int lease_transferred = 0;

    if (kind == IO_URING_PENDING_POLL) {
        result = kernel_fd_operation_acquire(
            descriptor, &descriptor_lease);
        if (result < 0) return result;
    }

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) result = -EDGE_LINUX_EBADF;
    else {
        for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot)
            if (!ring->pending[slot].used) break;
        if (slot == KERNEL_IO_URING_MAX_PENDING) {
            result = -EDGE_LINUX_EAGAIN;
        } else {
            memset(&ring->pending[slot], 0, sizeof(ring->pending[slot]));
            if (kind == IO_URING_PENDING_POLL) {
                result = kernel_fd_operation_move(
                    &ring->pending[slot].descriptor_lease,
                    &descriptor_lease);
                if (result < 0) goto pending_add_done;
                lease_transferred = 1;
            }
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
pending_add_done:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (kind == IO_URING_PENDING_POLL && !lease_transferred)
        (void)kernel_fd_operation_release(&descriptor_lease);
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

int kernel_io_uring_pending_sequence(int32_t ring_id,
                                     uint64_t user_data,
                                     uint64_t *sequence) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint64_t newest = 0;

    if (!sequence) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (ring) {
        for (uint32_t slot = 0;
             slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
            const kernel_io_uring_pending_t *pending =
                &ring->pending[slot];
            if (pending->used && pending->user_data == user_data &&
                pending->sequence > newest)
                newest = pending->sequence;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (!ring) return -EDGE_LINUX_EBADF;
    if (!newest) return -EDGE_LINUX_ENOENT;
    *sequence = newest;
    return 0;
}

int kernel_io_uring_link_timeout_add(int32_t ring_id,
                                     uint64_t user_data,
                                     uint64_t target_sequence,
                                     uint64_t deadline_us,
                                     int realtime_clock) {
    kernel_io_uring_t *ring;
    kernel_io_uring_pending_t *target = 0;
    uint64_t flags;
    uint32_t slot;
    int result = 0;

    if (!target_sequence) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
        goto link_timeout_done;
    }
    for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
        if (ring->pending[slot].used &&
            ring->pending[slot].sequence == target_sequence) {
            target = &ring->pending[slot];
            break;
        }
    }
    if (!target || target->kind == IO_URING_PENDING_LINK_TIMEOUT) {
        result = -EDGE_LINUX_EINVAL;
        goto link_timeout_done;
    }
    for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot)
        if (!ring->pending[slot].used) break;
    if (slot == KERNEL_IO_URING_MAX_PENDING) {
        result = -EDGE_LINUX_EAGAIN;
        goto link_timeout_done;
    }
    memset(&ring->pending[slot], 0, sizeof(ring->pending[slot]));
    ring->pending[slot].used = 1u;
    ring->pending[slot].kind = IO_URING_PENDING_LINK_TIMEOUT;
    ring->pending[slot].realtime_clock = realtime_clock ? 1u : 0u;
    ring->pending[slot].user_data = user_data;
    ring->pending[slot].deadline_us = deadline_us;
    ring->pending[slot].expiration_result = -EDGE_LINUX_ETIME;
    ring->pending[slot].link_target_sequence = target_sequence;
    ++ring->next_pending_sequence;
    if (!ring->next_pending_sequence)
        ++ring->next_pending_sequence;
    ring->pending[slot].sequence = ring->next_pending_sequence;
link_timeout_done:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
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

int kernel_io_uring_epoll_wait_add(int32_t ring_id, uint64_t user_data,
                                   int32_t descriptor,
                                   uint64_t user_events,
                                   uint64_t address_space,
                                   uint32_t maximum_events,
                                   uint8_t event_size,
                                   uint8_t event_data_offset) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t slot;
    int32_t epoll_index;
    int result;

    if (!user_events || !address_space || !maximum_events ||
        event_size < sizeof(uint32_t) + sizeof(uint64_t) ||
        event_size > 16u || event_data_offset < sizeof(uint32_t) ||
        event_data_offset > event_size - sizeof(uint64_t))
        return -EDGE_LINUX_EINVAL;
    result = kernel_epoll_descriptor_retain(
        descriptor, &epoll_index);
    if (result < 0) return result;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot)
            if (!ring->pending[slot].used) break;
        if (slot == KERNEL_IO_URING_MAX_PENDING) {
            result = -EDGE_LINUX_EAGAIN;
        } else {
            kernel_io_uring_pending_t *pending = &ring->pending[slot];

            memset(pending, 0, sizeof(*pending));
            pending->used = 1u;
            pending->kind = IO_URING_PENDING_EPOLL;
            pending->descriptor = epoll_index;
            pending->user_data = user_data;
            pending->user_address = user_events;
            pending->address_space = address_space;
            pending->maximum_events = maximum_events;
            pending->event_size = event_size;
            pending->event_data_offset = event_data_offset;
            ++ring->next_pending_sequence;
            if (!ring->next_pending_sequence)
                ++ring->next_pending_sequence;
            pending->sequence = ring->next_pending_sequence;
            result = 0;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result < 0) kernel_epoll_object_release(epoll_index);
    return result;
}

int kernel_io_uring_futex_wait_add(
        int32_t ring_id, uint64_t user_data,
        const kernel_futex_request_t *request) {
    kernel_io_uring_t *ring;
    uint64_t futex_wait_id;
    uint64_t flags;
    uint32_t slot;
    int result;

    result = kernel_futex_async_wait_add(request, &futex_wait_id);
    if (result < 0) return result;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        for (slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot)
            if (!ring->pending[slot].used) break;
        if (slot == KERNEL_IO_URING_MAX_PENDING) {
            result = -EDGE_LINUX_EAGAIN;
        } else {
            memset(&ring->pending[slot], 0,
                   sizeof(ring->pending[slot]));
            ring->pending[slot].used = 1u;
            ring->pending[slot].kind = IO_URING_PENDING_FUTEX;
            ring->pending[slot].user_data = user_data;
            ring->pending[slot].futex_wait_id = futex_wait_id;
            ++ring->next_pending_sequence;
            if (!ring->next_pending_sequence)
                ++ring->next_pending_sequence;
            ring->pending[slot].sequence =
                ring->next_pending_sequence;
            result = 0;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (result < 0)
        (void)kernel_futex_async_wait_cancel(futex_wait_id);
    return result;
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
    kernel_fd_operation_lease_t descriptor_lease = {0};
    int32_t epoll_index = -1;
    uint64_t canceled_sequence = 0;
    uint64_t link_timeout_user_data = 0;
    int link_timeout_canceled = 0;
    uint64_t futex_wait_id = 0u;
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
            if (ring->pending[slot].kind == IO_URING_PENDING_POLL) {
                result = kernel_fd_operation_move(
                    &descriptor_lease,
                    &ring->pending[slot].descriptor_lease);
                if (result < 0) break;
            } else if (ring->pending[slot].kind ==
                       IO_URING_PENDING_EPOLL) {
                epoll_index = ring->pending[slot].descriptor;
            } else if (ring->pending[slot].kind ==
                       IO_URING_PENDING_FUTEX) {
                futex_wait_id = ring->pending[slot].futex_wait_id;
            }
            canceled_sequence = ring->pending[slot].sequence;
            memset(&ring->pending[slot], 0, sizeof(ring->pending[slot]));
            result = 0;
            break;
        }
        if (canceled_sequence) {
            for (uint32_t linked = 0;
                 linked < KERNEL_IO_URING_MAX_PENDING; ++linked) {
                kernel_io_uring_pending_t *timeout =
                    &ring->pending[linked];
                if (!timeout->used ||
                    timeout->kind != IO_URING_PENDING_LINK_TIMEOUT ||
                    timeout->link_target_sequence != canceled_sequence)
                    continue;
                link_timeout_user_data = timeout->user_data;
                link_timeout_canceled = 1;
                memset(timeout, 0, sizeof(*timeout));
                break;
            }
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (kernel_fd_operation_view(&descriptor_lease))
        (void)kernel_fd_operation_release(&descriptor_lease);
    if (epoll_index >= 0)
        kernel_epoll_object_release(epoll_index);
    if (futex_wait_id)
        (void)kernel_futex_async_wait_cancel(futex_wait_id);
    if (link_timeout_canceled)
        (void)kernel_io_uring_completion_add_async(
            ring_id, link_timeout_user_data,
            -EDGE_LINUX_ECANCELED, 0u);
    return result;
}

typedef struct io_uring_pending_snapshot {
    uint8_t used;
    uint8_t kind;
    uint8_t realtime_clock;
    uint8_t multishot;
    uint8_t ready_latched;
    int32_t descriptor;
    uint32_t events;
    uint32_t completion_target;
    int32_t expiration_result;
    uint64_t user_data;
    uint64_t deadline_us;
    uint64_t interval_us;
    uint32_t repeat_count;
    uint64_t sequence;
    uint64_t link_target_sequence;
    uint64_t futex_wait_id;
    uint64_t user_address;
    uint64_t address_space;
    uint32_t maximum_events;
    uint8_t event_size;
    uint8_t event_data_offset;
} io_uring_pending_snapshot_t;

static void io_uring_pending_snapshot(
        io_uring_pending_snapshot_t *destination,
        const kernel_io_uring_pending_t *source) {
    memset(destination, 0, sizeof(*destination));
    destination->used = source->used;
    destination->kind = source->kind;
    destination->realtime_clock = source->realtime_clock;
    destination->multishot = source->multishot;
    destination->ready_latched = source->ready_latched;
    destination->descriptor = source->descriptor;
    destination->events = source->events;
    destination->completion_target = source->completion_target;
    destination->expiration_result = source->expiration_result;
    destination->user_data = source->user_data;
    destination->deadline_us = source->deadline_us;
    destination->interval_us = source->interval_us;
    destination->repeat_count = source->repeat_count;
    destination->sequence = source->sequence;
    destination->link_target_sequence = source->link_target_sequence;
    destination->futex_wait_id = source->futex_wait_id;
    destination->user_address = source->user_address;
    destination->address_space = source->address_space;
    destination->maximum_events = source->maximum_events;
    destination->event_size = source->event_size;
    destination->event_data_offset = source->event_data_offset;
}

typedef struct io_uring_epoll_copy_context {
    uint64_t address;
    uint64_t address_space;
    uint8_t event_size;
    uint8_t event_data_offset;
} io_uring_epoll_copy_context_t;

static int io_uring_epoll_copy_event(
        void *opaque, uint32_t event_index,
        const kernel_epoll_event_t *event) {
    io_uring_epoll_copy_context_t *context =
        (io_uring_epoll_copy_context_t *)opaque;
    uint8_t result[16];
    uint64_t destination;

    if (!context || !event || context->event_size > sizeof(result) ||
        context->event_data_offset >
            context->event_size - sizeof(event->data))
        return -EDGE_LINUX_EFAULT;
    destination = context->address +
        (uint64_t)event_index * context->event_size;
    if (destination < context->address)
        return -EDGE_LINUX_EFAULT;
    memset(result, 0, sizeof(result));
    memcpy(result, &event->events, sizeof(event->events));
    memcpy(result + context->event_data_offset,
           &event->data, sizeof(event->data));
    return kernel_mm_address_space_copy(
        context->address_space, destination, result,
        context->event_size,
        KERNEL_MM_PROCESS_VM_WRITE) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

typedef struct io_uring_pending_release {
    kernel_fd_operation_lease_t descriptor_lease;
    int32_t epoll_index;
    uint64_t futex_wait_id;
} io_uring_pending_release_t;

static int io_uring_pending_remove_locked(
        kernel_io_uring_pending_t *pending,
        io_uring_pending_release_t *release) {
    if (!pending || !pending->used || !release)
        return -EDGE_LINUX_EINVAL;
    memset(release, 0, sizeof(*release));
    release->epoll_index = -1;
    if (pending->kind == IO_URING_PENDING_POLL &&
        kernel_fd_operation_view(&pending->descriptor_lease) &&
        kernel_fd_operation_move(
            &release->descriptor_lease,
            &pending->descriptor_lease) < 0)
        return -EDGE_LINUX_EBUSY;
    if (pending->kind == IO_URING_PENDING_EPOLL)
        release->epoll_index = pending->descriptor;
    if (pending->kind == IO_URING_PENDING_FUTEX)
        release->futex_wait_id = pending->futex_wait_id;
    memset(pending, 0, sizeof(*pending));
    return 0;
}

static void io_uring_pending_release_finish(
        io_uring_pending_release_t *release) {
    if (!release) return;
    if (kernel_fd_operation_view(&release->descriptor_lease))
        (void)kernel_fd_operation_release(
            &release->descriptor_lease);
    if (release->epoll_index >= 0)
        kernel_epoll_object_release(release->epoll_index);
    if (release->futex_wait_id)
        (void)kernel_futex_async_wait_cancel(
            release->futex_wait_id);
    release->epoll_index = -1;
}

static int io_uring_link_timeout_disarm(
        int32_t ring_id, uint64_t target_sequence,
        uint64_t *timeout_user_data) {
    kernel_io_uring_t *ring;
    uint64_t flags;
    int result = -EDGE_LINUX_ENOENT;

    if (!target_sequence || !timeout_user_data)
        return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        for (uint32_t slot = 0;
             slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
            kernel_io_uring_pending_t *pending =
                &ring->pending[slot];
            if (!pending->used ||
                pending->kind != IO_URING_PENDING_LINK_TIMEOUT ||
                pending->link_target_sequence != target_sequence)
                continue;
            *timeout_user_data = pending->user_data;
            memset(pending, 0, sizeof(*pending));
            result = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

static uint32_t io_uring_link_timeout_expire(
        int32_t ring_id, uint64_t timeout_sequence,
        uint64_t target_sequence, uint64_t now_us) {
    io_uring_pending_release_t target_release;
    kernel_io_uring_pending_t *timeout = 0;
    kernel_io_uring_pending_t *target = 0;
    kernel_io_uring_t *ring;
    uint64_t target_user_data = 0;
    uint64_t timeout_user_data = 0;
    uint64_t flags;
    uint32_t count = 0;
    int target_found = 0;

    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return 0;
    }
    for (uint32_t slot = 0;
         slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
        kernel_io_uring_pending_t *pending = &ring->pending[slot];
        if (!pending->used) continue;
        if (pending->kind == IO_URING_PENDING_LINK_TIMEOUT &&
            pending->sequence == timeout_sequence)
            timeout = pending;
        if (pending->sequence == target_sequence)
            target = pending;
    }
    if (!timeout || now_us < timeout->deadline_us) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return 0;
    }
    timeout_user_data = timeout->user_data;
    if (target) {
        target_user_data = target->user_data;
        if (io_uring_pending_remove_locked(
                target, &target_release) < 0) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            return 0;
        }
        target_found = 1;
    }
    memset(timeout, 0, sizeof(*timeout));
    spin_unlock_irqrestore(&g_io_uring_lock, flags);

    if (target_found) {
        io_uring_pending_release_finish(&target_release);
        if (kernel_io_uring_completion_add_async(
                ring_id, target_user_data,
                -EDGE_LINUX_ECANCELED, 0u) == 0)
            ++count;
    }
    if (kernel_io_uring_completion_add_async(
            ring_id, timeout_user_data,
            target_found ? -EDGE_LINUX_ETIME :
                           -EDGE_LINUX_ECANCELED,
            0u) == 0)
        ++count;
    return count;
}

uint32_t kernel_io_uring_collect(int32_t ring_id, uint64_t now_us) {
    uint32_t count = 0;
    for (uint32_t slot = 0; slot < KERNEL_IO_URING_MAX_PENDING; ++slot) {
        io_uring_pending_snapshot_t pending;
        kernel_fd_operation_lease_t poll_lease = {0};
        kernel_fd_operation_lease_t release_lease = {0};
        kernel_io_uring_t *ring;
        uint32_t completion_count;
        uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
        int32_t result = 0;
        int remove = 0;
        int ready = 0;
        int timeout_completion = 0;
        int timeout_final = 0;
        int request_final = 0;
        uint64_t completion_user_data;
        uint32_t completion_flags = 0u;
        ring = io_uring_lookup_locked(ring_id);
        if (!ring) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            break;
        }
        io_uring_pending_snapshot(&pending, &ring->pending[slot]);
        if (!pending.used) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            continue;
        }
        completion_count = *io_uring_u32(
            ring->cq_ring, IORING_CQ_TAIL_OFFSET) -
            *io_uring_u32(ring->cq_ring, IORING_CQ_HEAD_OFFSET);
        completion_user_data = pending.user_data;
        if (pending.kind == IO_URING_PENDING_LINK_TIMEOUT) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            count += io_uring_link_timeout_expire(
                ring_id, pending.sequence,
                pending.link_target_sequence, now_us);
            continue;
        } else if (pending.kind == IO_URING_PENDING_TIMEOUT) {
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
                request_final = timeout_final;
                if (pending.multishot && !timeout_final)
                    completion_flags = 1u << 1;
                remove = 1;
            }
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
        } else if (pending.kind == IO_URING_PENDING_POLL) {
            if (kernel_fd_operation_clone(
                    &poll_lease,
                    &ring->pending[slot].descriptor_lease) < 0) {
                spin_unlock_irqrestore(&g_io_uring_lock, flags);
                continue;
            }
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            if ((pending.events & 0x2003u) &&
                kernel_fd_operation_ready(
                    &poll_lease, KERNEL_IO_READ_CURRENT) > 0)
                result |= (int32_t)(pending.events & 0x2003u);
            if ((pending.events & 0x0004u) &&
                kernel_fd_operation_ready(
                    &poll_lease, KERNEL_IO_WRITE_CURRENT) > 0)
                result |= 0x0004;
            (void)kernel_fd_operation_release(&poll_lease);
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
                    if (kernel_fd_operation_move(
                            &release_lease,
                            &ring->pending[slot].descriptor_lease) < 0) {
                        spin_unlock_irqrestore(
                            &g_io_uring_lock, flags);
                        continue;
                    }
                    memset(&ring->pending[slot], 0,
                           sizeof(ring->pending[slot]));
                    remove = 1;
                    request_final = 1;
                } else if (!ring->pending[slot].ready_latched) {
                    ring->pending[slot].ready_latched = 1u;
                    remove = 1;
                }
            }
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            if (kernel_fd_operation_view(&release_lease))
                (void)kernel_fd_operation_release(&release_lease);
        } else if (pending.kind == IO_URING_PENDING_EPOLL) {
            io_uring_epoll_copy_context_t copy_context = {
                .address = pending.user_address,
                .address_space = pending.address_space,
                .event_size = pending.event_size,
                .event_data_offset = pending.event_data_offset,
            };
            int32_t release_epoll = -1;

            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            result = kernel_epoll_deliver_events(
                pending.descriptor, pending.maximum_events,
                io_uring_epoll_copy_event, &copy_context);
            if (result == 0) continue;
            flags = spin_lock_irqsave(&g_io_uring_lock);
            ring = io_uring_lookup_locked(ring_id);
            if (ring && ring->pending[slot].used &&
                ring->pending[slot].kind == IO_URING_PENDING_EPOLL &&
                ring->pending[slot].sequence == pending.sequence) {
                completion_user_data = ring->pending[slot].user_data;
                release_epoll = ring->pending[slot].descriptor;
                memset(&ring->pending[slot], 0,
                       sizeof(ring->pending[slot]));
                remove = 1;
                request_final = 1;
            }
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            if (release_epoll >= 0)
                kernel_epoll_object_release(release_epoll);
        } else if (pending.kind == IO_URING_PENDING_FUTEX) {
            int poll_result;

            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            poll_result = kernel_futex_async_wait_poll(
                pending.futex_wait_id, &result);
            if (poll_result <= 0) continue;
            flags = spin_lock_irqsave(&g_io_uring_lock);
            ring = io_uring_lookup_locked(ring_id);
            if (ring && ring->pending[slot].used &&
                ring->pending[slot].kind == IO_URING_PENDING_FUTEX &&
                ring->pending[slot].sequence == pending.sequence) {
                completion_user_data = ring->pending[slot].user_data;
                memset(&ring->pending[slot], 0,
                       sizeof(ring->pending[slot]));
                remove = 1;
                request_final = 1;
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
            if (completion_result == 0 && request_final) {
                uint64_t timeout_user_data;

                if (io_uring_link_timeout_disarm(
                        ring_id, pending.sequence,
                        &timeout_user_data) == 0 &&
                    kernel_io_uring_completion_add_async(
                        ring_id, timeout_user_data,
                        -EDGE_LINUX_ECANCELED, 0u) == 0)
                    ++count;
            }
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

static int io_uring_pbuf_mmap_group(
        uint64_t offset, uint16_t *group_id) {
    uint64_t encoded;

    if ((offset & KERNEL_IO_URING_OFF_MMAP_MASK) !=
        KERNEL_IO_URING_OFF_PBUF_RING)
        return 0;
    if (offset & ((1ull << KERNEL_IO_URING_OFF_PBUF_SHIFT) - 1u))
        return -EDGE_LINUX_EINVAL;
    encoded = (offset & ~KERNEL_IO_URING_OFF_MMAP_MASK) >>
        KERNEL_IO_URING_OFF_PBUF_SHIFT;
    if (encoded > UINT16_MAX) return -EDGE_LINUX_EINVAL;
    *group_id = (uint16_t)encoded;
    return 1;
}

int kernel_io_uring_mmap_info(int32_t ring_id, uint64_t offset,
                              uint64_t length, uint32_t *page_count) {
    kernel_io_uring_page_t *pages;
    kernel_io_uring_t *ring;
    uint64_t flags;
    uint32_t count;
    uint16_t group_id = 0u;
    int pbuf;
    int result;
    if (!length || !page_count) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    pbuf = io_uring_pbuf_mmap_group(offset, &group_id);
    if (pbuf < 0) {
        result = pbuf;
    } else if (pbuf) {
        kernel_io_uring_buffer_group_t *group =
            io_uring_buffer_group_locked(ring, group_id, 0);

        pages = 0;
        if (!group || !group->provided_ring ||
            !group->kernel_allocated)
            result = -EDGE_LINUX_EINVAL;
        else {
            count = group->ring_page_count;
            result = 0;
        }
    } else {
        result = io_uring_region(ring, offset, &pages, &count);
    }
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
    uint16_t group_id = 0u;
    int pbuf;
    int result;
    if (!page) return -EDGE_LINUX_EINVAL;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    pbuf = io_uring_pbuf_mmap_group(offset, &group_id);
    if (pbuf < 0) {
        result = pbuf;
    } else if (pbuf) {
        kernel_io_uring_buffer_group_t *group =
            io_uring_buffer_group_locked(ring, group_id, 0);

        if (!group || !group->provided_ring ||
            !group->kernel_allocated) {
            pages = 0;
            count = 0u;
            result = -EDGE_LINUX_EINVAL;
        } else {
            pages = 0;
            count = group->ring_page_count;
            result = 0;
        }
    } else {
        result = io_uring_region(ring, offset, &pages, &count);
    }
    if (result == 0 && page_index >= count)
        result = -EDGE_LINUX_EINVAL;
    if (result == 0) {
        kernel_io_uring_page_t *source = pbuf ?
            io_uring_pbuf_page_locked(ring, group_id, page_index) :
            &pages[page_index];

        if (!source) {
            result = -EDGE_LINUX_EINVAL;
            goto unlock;
        }
        result = g_io_uring_allocator.retain(
            g_io_uring_allocator.context, source);
        if (result == 0) *page = *source;
    }
unlock:
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return result;
}

int kernel_io_uring_take_submission(
        int32_t ring_id, uint32_t submission_offset,
        uint32_t submission_limit,
        struct edge_linux_io_uring_sqe *submission,
        uint32_t *entries_consumed, int32_t *layout_result) {
    kernel_io_uring_t *ring;
    volatile uint32_t *head_pointer;
    volatile uint32_t *tail_pointer;
    volatile uint32_t *dropped_pointer;
    uint32_t head;
    uint32_t tail;
    uint32_t sqe_index;
    uint64_t flags;
    void *source;
    uint32_t consumed = 1u;
    int32_t entry_layout_result = 0;
    if (!submission || !entries_consumed || !layout_result ||
        !submission_limit)
        return -EDGE_LINUX_EINVAL;
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
    if (ring->setup_flags & IORING_SETUP_SQ_REWIND) {
        if (submission_offset >= ring->sq_entries) {
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            return -EDGE_LINUX_EAGAIN;
        }
        head = submission_offset;
        tail = ring->sq_entries;
    } else {
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
    }
    if (ring->setup_flags & IORING_SETUP_NO_SQARRAY) {
        sqe_index = head & (ring->sq_entries - 1u);
    } else {
        sqe_index = __atomic_load_n(
            io_uring_u32(ring->sq_ring,
                IORING_SQ_ARRAY_OFFSET +
                (head & (ring->sq_entries - 1u)) * sizeof(uint32_t)),
            __ATOMIC_RELAXED);
        if (sqe_index >= ring->sq_entries) {
            dropped_pointer = io_uring_u32(
                ring->sq_ring, IORING_SQ_DROPPED_OFFSET);
            __atomic_add_fetch(dropped_pointer, 1u, __ATOMIC_RELAXED);
            __atomic_store_n(head_pointer, head + 1u, __ATOMIC_RELEASE);
            spin_unlock_irqrestore(&g_io_uring_lock, flags);
            return -EDGE_LINUX_EBADMSG;
        }
    }
    source = io_uring_region_pointer(
        ring->sqes,
        sqe_index * ((ring->setup_flags & IORING_SETUP_SQE128) ?
                     128u : 64u));
    memcpy(submission, source, sizeof(*submission));
    if ((submission->opcode == IORING_OP_NOP128 ||
         submission->opcode == IORING_OP_URING_CMD128) &&
        !(ring->setup_flags & IORING_SETUP_SQE128)) {
        if (!(ring->setup_flags & IORING_SETUP_SQE_MIXED) ||
            submission_limit < 2u || tail - head < 2u ||
            sqe_index >= ring->sq_entries - 1u)
            entry_layout_result = -EDGE_LINUX_EINVAL;
        else
            consumed = 2u;
    }
    if (!(ring->setup_flags & IORING_SETUP_SQ_REWIND))
        __atomic_store_n(head_pointer, head + consumed, __ATOMIC_RELEASE);
    *entries_consumed = consumed;
    *layout_result = entry_layout_result;
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return 0;
}

static int io_uring_completion_publish_locked(
        kernel_io_uring_t *ring, uint64_t user_data,
        int32_t result, uint32_t cqe_flags,
        uint64_t extra1, uint64_t extra2) {
    struct edge_linux_io_uring_cqe *completion;
    volatile uint32_t *head_pointer;
    volatile uint32_t *tail_pointer;
    uint32_t head;
    uint32_t tail;
    uint32_t offset;
    uint32_t required;
    uint32_t stride;
    int mixed_extended;
    if (!ring) return -EDGE_LINUX_EBADF;
    head_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_HEAD_OFFSET);
    tail_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_TAIL_OFFSET);
    head = __atomic_load_n(head_pointer, __ATOMIC_ACQUIRE);
    tail = __atomic_load_n(tail_pointer, __ATOMIC_RELAXED);
    mixed_extended =
        (ring->setup_flags & IORING_SETUP_CQE_MIXED) &&
        (cqe_flags & IORING_CQE_F_32);
    required = mixed_extended ? 2u : 1u;
    if (tail - head >= ring->cq_entries)
        return -EDGE_LINUX_EBUSY;
    if (mixed_extended &&
        (tail & (ring->cq_entries - 1u)) == ring->cq_entries - 1u) {
        completion = io_uring_region_pointer(
            ring->cq_ring,
            IORING_CQ_CQES_OFFSET +
                (ring->cq_entries - 1u) * 16u);
        memset(completion, 0, sizeof(*completion));
        completion->flags = IORING_CQE_F_SKIP;
        ++tail;
        __atomic_store_n(tail_pointer, tail, __ATOMIC_RELEASE);
    }
    if (tail - head + required > ring->cq_entries)
        return -EDGE_LINUX_EBUSY;
    stride = (ring->setup_flags & IORING_SETUP_CQE32) ? 32u : 16u;
    offset = IORING_CQ_CQES_OFFSET +
             (tail & (ring->cq_entries - 1u)) * stride;
    completion = io_uring_region_pointer(ring->cq_ring, offset);
    memset(completion, 0, stride);
    completion->user_data = user_data;
    completion->result = result;
    completion->flags = cqe_flags;
    if (stride == 32u || mixed_extended) {
        uint64_t *extra = (uint64_t *)(void *)(completion + 1);
        extra[0] = extra1;
        extra[1] = extra2;
    }
    __atomic_store_n(tail_pointer, tail + required, __ATOMIC_RELEASE);
    return 0;
}

static int io_uring_completion_add_extended_locked(
        kernel_io_uring_t *ring, uint64_t user_data,
        int32_t result, uint32_t cqe_flags,
        uint64_t extra1, uint64_t extra2) {
    volatile uint32_t *overflow_pointer;
    uint32_t slot;
    int status;

    if (!ring) return -EDGE_LINUX_EBADF;
    (void)io_uring_completion_overflow_flush_locked(ring);
    status = ring->completion_overflow_count ? -EDGE_LINUX_EBUSY :
        io_uring_completion_publish_locked(
            ring, user_data, result, cqe_flags, extra1, extra2);
    if (status != -EDGE_LINUX_EBUSY) return status;
    if (ring->completion_overflow_count <
        IO_URING_MAX_COMPLETION_OVERFLOW) {
        slot = (ring->completion_overflow_head +
                ring->completion_overflow_count) %
               IO_URING_MAX_COMPLETION_OVERFLOW;
        ring->completion_overflow[slot].completion.user_data = user_data;
        ring->completion_overflow[slot].completion.result = result;
        ring->completion_overflow[slot].completion.flags = cqe_flags;
        ring->completion_overflow[slot].extra1 = extra1;
        ring->completion_overflow[slot].extra2 = extra2;
        ++ring->completion_overflow_count;
        __atomic_or_fetch(
            io_uring_u32(ring->sq_ring, IORING_SQ_FLAGS_OFFSET),
            IORING_SQ_CQ_OVERFLOW, __ATOMIC_RELEASE);
        return 0;
    }
    overflow_pointer = io_uring_u32(
        ring->cq_ring, IORING_CQ_OVERFLOW_OFFSET);
    __atomic_add_fetch(overflow_pointer, 1u, __ATOMIC_RELAXED);
    return -EDGE_LINUX_EBUSY;
}

static int io_uring_completion_add_locked(
        kernel_io_uring_t *ring, uint64_t user_data,
        int32_t result, uint32_t cqe_flags) {
    return io_uring_completion_add_extended_locked(
        ring, user_data, result, cqe_flags, 0u, 0u);
}

static uint32_t io_uring_completion_overflow_flush_locked(
        kernel_io_uring_t *ring) {
    uint32_t flushed = 0u;

    while (ring && ring->completion_overflow_count) {
        kernel_io_uring_overflow_completion_t *overflow =
            &ring->completion_overflow[ring->completion_overflow_head];
        if (io_uring_completion_publish_locked(
                ring, overflow->completion.user_data,
                overflow->completion.result,
                overflow->completion.flags,
                overflow->extra1, overflow->extra2) < 0)
            break;
        ring->completion_overflow_head =
            (ring->completion_overflow_head + 1u) %
            IO_URING_MAX_COMPLETION_OVERFLOW;
        --ring->completion_overflow_count;
        ++flushed;
    }
    if (ring && !ring->completion_overflow_count)
        __atomic_and_fetch(
            io_uring_u32(ring->sq_ring, IORING_SQ_FLAGS_OFFSET),
            ~IORING_SQ_CQ_OVERFLOW, __ATOMIC_RELEASE);
    return flushed;
}

static int io_uring_completion_add(
        int32_t ring_id, uint64_t user_data,
        int32_t result, uint32_t cqe_flags,
        uint64_t extra1, uint64_t extra2,
        int require_cqe32, int asynchronous) {
    kernel_io_uring_t *ring;
    int32_t event_id = -1;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int status;

    ring = io_uring_lookup_locked(ring_id);
    if (require_cqe32 && ring) {
        if (!(ring->setup_flags & (IORING_SETUP_CQE32 |
                                   IORING_SETUP_CQE_MIXED))) {
            status = -EDGE_LINUX_EINVAL;
        } else {
            if (ring->setup_flags & IORING_SETUP_CQE_MIXED)
                cqe_flags |= IORING_CQE_F_32;
            status = io_uring_completion_add_extended_locked(
                ring, user_data, result, cqe_flags, extra1, extra2);
        }
    } else {
        status = io_uring_completion_add_extended_locked(
            ring, user_data, result, cqe_flags, extra1, extra2);
    }
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
        ring_id, user_data, result, cqe_flags,
        0u, 0u, 0, 0);
}

int kernel_io_uring_completion_add32(
        int32_t ring_id, uint64_t user_data, int32_t result,
        uint32_t cqe_flags, uint64_t extra1, uint64_t extra2) {
    return io_uring_completion_add(
        ring_id, user_data, result, cqe_flags,
        extra1, extra2, 1, 0);
}

int kernel_io_uring_completion_flush(int32_t ring_id) {
    kernel_io_uring_t *ring;
    int32_t event_id = -1;
    uint64_t flags = spin_lock_irqsave(&g_io_uring_lock);
    int result;

    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        result = -EDGE_LINUX_EBADF;
    } else {
        uint32_t flushed =
            io_uring_completion_overflow_flush_locked(ring);
        if (flushed)
            event_id = io_uring_event_retain_locked(ring, 0);
        result = (int)flushed;
    }
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    if (event_id >= 0) {
        (void)kernel_eventfd_write_value(event_id, 1, 1u);
        kernel_eventfd_release(event_id);
    }
    return result;
}

int kernel_io_uring_completion_add_async(int32_t ring_id,
                                         uint64_t user_data,
                                         int32_t result,
                                         uint32_t cqe_flags) {
    return io_uring_completion_add(
        ring_id, user_data, result, cqe_flags,
        0u, 0u, 0, 1);
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
