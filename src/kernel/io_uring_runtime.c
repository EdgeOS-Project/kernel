/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux io_uring ring storage and lifetime. */

#include <stdint.h>

#include "kernel/io_uring_runtime.h"
#include "kernel/linux_errno.h"
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
    kernel_io_uring_page_t
        sq_ring[KERNEL_IO_URING_MAX_SQ_RING_PAGES];
    kernel_io_uring_page_t
        cq_ring[KERNEL_IO_URING_MAX_CQ_RING_PAGES];
    kernel_io_uring_page_t sqes[KERNEL_IO_URING_MAX_SQE_PAGES];
} kernel_io_uring_t;

static kernel_io_uring_t g_io_urings[KERNEL_IO_URING_MAX_RINGS];
static kernel_io_uring_page_allocator_t g_io_uring_allocator;
static spinlock_t g_io_uring_lock;

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

static void io_uring_release_storage(kernel_io_uring_t *ring) {
    io_uring_release_pages(ring->sq_ring, ring->sq_ring_pages);
    io_uring_release_pages(ring->cq_ring, ring->cq_ring_pages);
    io_uring_release_pages(ring->sqes, ring->sqe_pages);
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

int kernel_io_uring_completion_add(int32_t ring_id, uint64_t user_data,
                                   int32_t result, uint32_t cqe_flags) {
    struct edge_linux_io_uring_cqe *completion;
    kernel_io_uring_t *ring;
    volatile uint32_t *head_pointer;
    volatile uint32_t *tail_pointer;
    volatile uint32_t *overflow_pointer;
    uint32_t head;
    uint32_t tail;
    uint32_t offset;
    uint64_t flags;
    flags = spin_lock_irqsave(&g_io_uring_lock);
    ring = io_uring_lookup_locked(ring_id);
    if (!ring) {
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
        return -EDGE_LINUX_EBADF;
    }
    head_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_HEAD_OFFSET);
    tail_pointer = io_uring_u32(ring->cq_ring, IORING_CQ_TAIL_OFFSET);
    head = __atomic_load_n(head_pointer, __ATOMIC_ACQUIRE);
    tail = __atomic_load_n(tail_pointer, __ATOMIC_RELAXED);
    if (tail - head >= ring->cq_entries) {
        overflow_pointer = io_uring_u32(
            ring->cq_ring, IORING_CQ_OVERFLOW_OFFSET);
        __atomic_add_fetch(overflow_pointer, 1u, __ATOMIC_RELAXED);
        spin_unlock_irqrestore(&g_io_uring_lock, flags);
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
    spin_unlock_irqrestore(&g_io_uring_lock, flags);
    return 0;
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
