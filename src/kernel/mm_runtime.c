/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux memory policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/vfs_runtime.h"
#include "fs/cgroupfs.h"
#include "mm/arch_vm.h"
#include "mm/statistics.h"
#include "string.h"
#include "sys/boottime.h"

static kernel_vm_area_t *g_kernel_vma_pool;
static uint32_t g_kernel_vma_address_spaces;
static uint32_t g_kernel_vma_areas_per_space;
static kernel_mm_lock_space_t *g_kernel_mm_lock_spaces;
static kernel_mm_seal_space_t *g_kernel_mm_seal_spaces;
static uint32_t g_kernel_mm_lock_space_capacity;
static volatile uint32_t g_kernel_mm_lock_registry_guard;

#define KERNEL_MM_FILE_SHADOW_BUCKETS 4096u
#define KERNEL_MM_FILE_SHADOW_WAYS 4u
#define KERNEL_MM_FILE_SHADOW_RECENT_DISTANCE 4096u

typedef struct kernel_mm_file_shadow {
    uint64_t mapping_identity;
    uint64_t inode_number;
    uint64_t page_offset;
    uint64_t eviction_sequence;
    uint32_t inode_generation;
    uint8_t used;
    uint8_t reserved[3];
} kernel_mm_file_shadow_t;

static kernel_mm_file_shadow_t g_kernel_mm_file_shadows[
    KERNEL_MM_FILE_SHADOW_BUCKETS][KERNEL_MM_FILE_SHADOW_WAYS];
static uint64_t g_kernel_mm_file_shadow_sequence;
static volatile uint32_t g_kernel_mm_file_shadow_guard;

static void kernel_mm_registry_lock(void) {
    while (__sync_lock_test_and_set(&g_kernel_mm_lock_registry_guard, 1u)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void kernel_mm_registry_unlock(void) {
    __sync_lock_release(&g_kernel_mm_lock_registry_guard);
}

static void kernel_mm_file_shadow_lock(void) {
    while (__sync_lock_test_and_set(&g_kernel_mm_file_shadow_guard, 1u)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void kernel_mm_file_shadow_unlock(void) {
    __sync_lock_release(&g_kernel_mm_file_shadow_guard);
}

static uint32_t kernel_mm_file_shadow_bucket(
        uint64_t mapping_identity, uint64_t inode_number,
        uint32_t inode_generation, uint64_t page_offset) {
    uint64_t value = mapping_identity ^
                     (inode_number * UINT64_C(0x9e3779b185ebca87)) ^
                     ((uint64_t)inode_generation << 32u) ^
                     (page_offset / KERNEL_MM_USER_PAGE_SIZE);

    value ^= value >> 33u;
    value *= UINT64_C(0xff51afd7ed558ccd);
    value ^= value >> 33u;
    return (uint32_t)value & (KERNEL_MM_FILE_SHADOW_BUCKETS - 1u);
}

static int kernel_mm_file_shadow_matches(
        const kernel_mm_file_shadow_t *shadow,
        uint64_t mapping_identity, uint64_t inode_number,
        uint32_t inode_generation, uint64_t page_offset) {
    return shadow && shadow->used &&
           shadow->mapping_identity == mapping_identity &&
           shadow->inode_number == inode_number &&
           shadow->inode_generation == inode_generation &&
           shadow->page_offset == page_offset;
}

static kernel_mm_lock_space_t *kernel_mm_lock_space_find_locked(
        uint64_t address_space, int create) {
    kernel_mm_lock_space_t *free_space = 0;

    if (!address_space || !g_kernel_mm_lock_spaces) return 0;
    for (uint32_t index = 0;
         index < g_kernel_mm_lock_space_capacity; ++index) {
        kernel_mm_lock_space_t *space = &g_kernel_mm_lock_spaces[index];
        if (space->address_space == address_space) return space;
        if (!space->address_space && !free_space) free_space = space;
    }
    if (!create || !free_space) return 0;
    free_space->address_space = address_space;
    return free_space;
}

static kernel_mm_seal_space_t *kernel_mm_seal_space_find_locked(
        uint64_t address_space, int create) {
    kernel_mm_seal_space_t *free_space = 0;

    if (!address_space || !g_kernel_mm_seal_spaces) return 0;
    for (uint32_t index = 0;
         index < g_kernel_mm_lock_space_capacity; ++index) {
        kernel_mm_seal_space_t *space = &g_kernel_mm_seal_spaces[index];
        if (space->address_space == address_space) return space;
        if (!space->address_space && !free_space) free_space = space;
    }
    if (!create || !free_space) return 0;
    free_space->address_space = address_space;
    return free_space;
}

static void kernel_mm_release_pages(void *memory, uint32_t pages) {
    uint8_t *base = (uint8_t *)memory;

    if (!base) return;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(base +
                          (uint64_t)page * KERNEL_MM_USER_PAGE_SIZE);
}

static int kernel_mm_range_overflows(uint64_t address, uint64_t length) {
    return length > UINT64_MAX - address;
}

int kernel_mm_resolve_user_page(uint64_t address_space, uint64_t address,
                                uint32_t access) {
    return arch_mm_resolve_user_page(address_space, address, access);
}

uint32_t kernel_mm_reclaim_pages(uint32_t cgroup_id, uint32_t target_pages) {
    uint64_t scanned_pages = 0;
    uint64_t started_us;
    uint64_t finished_us;
    uint64_t stalled_us;
    uint32_t reclaimed;

    if (!target_pages) return 0;
    if (target_pages > 64u) target_pages = 64u;
    started_us = boottime_monotonic_us();
    reclaimed = arch_mm_reclaim_pages(cgroup_id, target_pages,
                                      &scanned_pages);
    finished_us = boottime_monotonic_us();
    stalled_us = finished_us > started_us ?
                 finished_us - started_us : 1u;
    if (reclaimed > target_pages) reclaimed = target_pages;
    cgroupfs_memory_note_reclaim(cgroup_id, scanned_pages,
                                 reclaimed);
    edge_mm_statistics_note_pressure(
        finished_us, stalled_us, reclaimed ? 0u : stalled_us);
    cgroupfs_memory_note_pressure(
        cgroup_id, finished_us, stalled_us,
        reclaimed ? 0u : stalled_us);
    return reclaimed;
}

uint32_t kernel_mm_reclaim_cgroup_pressure(uint32_t cgroup_id) {
    uint32_t total_reclaimed = 0;

    for (uint32_t pass = 0; pass < 4u; ++pass) {
        uint64_t excess_bytes = 0;
        uint64_t target_pages;
        uint32_t reclaimed;

        if (!cgroupfs_memory_pressure(cgroup_id, &excess_bytes) ||
            !excess_bytes)
            break;
        target_pages = (excess_bytes + KERNEL_MM_USER_PAGE_SIZE - 1u) /
                       KERNEL_MM_USER_PAGE_SIZE;
        reclaimed = kernel_mm_reclaim_pages(
            cgroup_id,
            target_pages > UINT32_MAX ? UINT32_MAX :
                                        (uint32_t)target_pages);
        if (!reclaimed) break;
        if (total_reclaimed > UINT32_MAX - reclaimed)
            total_reclaimed = UINT32_MAX;
        else
            total_reclaimed += reclaimed;
    }
    return total_reclaimed;
}

uint32_t kernel_mm_prepare_cgroup_charge(uint32_t cgroup_id,
                                         uint64_t bytes) {
    uint64_t excess_bytes = 0;
    uint64_t target_pages;

    if (!cgroupfs_memory_prepare_charge(
            cgroup_id, bytes, &excess_bytes) || !excess_bytes)
        return 0;
    target_pages = (excess_bytes + KERNEL_MM_USER_PAGE_SIZE - 1u) /
                   KERNEL_MM_USER_PAGE_SIZE;
    return kernel_mm_reclaim_pages(
        cgroup_id,
        target_pages > UINT32_MAX ? UINT32_MAX :
                                    (uint32_t)target_pages);
}

int kernel_mm_madvise_known(uint32_t advice) {
    switch (advice) {
    case 0u:  /* MADV_NORMAL */
    case 1u:  /* MADV_RANDOM */
    case 2u:  /* MADV_SEQUENTIAL */
    case 3u:  /* MADV_WILLNEED */
    case 4u:  /* MADV_DONTNEED */
    case 8u:  /* MADV_FREE */
    case 12u: /* MADV_MERGEABLE */
    case 13u: /* MADV_UNMERGEABLE */
    case 14u: /* MADV_HUGEPAGE */
    case 15u: /* MADV_NOHUGEPAGE */
    case 16u: /* MADV_DONTDUMP */
    case 17u: /* MADV_DODUMP */
    case 18u: /* MADV_WIPEONFORK */
    case 19u: /* MADV_KEEPONFORK */
    case 20u: /* MADV_COLD */
    case 21u: /* MADV_PAGEOUT */
    case 22u: /* MADV_POPULATE_READ */
    case 23u: /* MADV_POPULATE_WRITE */
    case 25u: /* MADV_COLLAPSE */
        return 1;
    default:
        return 0;
    }
}

int kernel_mm_madvise_cross_process_allowed(uint32_t advice) {
    return advice == 3u || advice == 20u ||
           advice == 21u || advice == 25u;
}

int kernel_process_madvise(int32_t pid, uint64_t address, uint64_t length,
                           uint32_t advice, uint32_t flags) {
    kernel_madvise_operation_t operation;

    if (flags & ~KERNEL_PROCESS_MADVISE_VALIDATE_ONLY)
        return -EDGE_LINUX_EINVAL;
    if (address & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (length > UINT64_MAX - address -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_ENOMEM;

    switch (advice) {
    case 4u:
        operation = KERNEL_MADVISE_DISCARD;
        break;
    case 8u:
        operation = KERNEL_MADVISE_LAZY_FREE;
        break;
    case 20u:
        operation = KERNEL_MADVISE_DEACTIVATE;
        break;
    case 21u:
        operation = KERNEL_MADVISE_PAGEOUT;
        break;
    case 22u:
        operation = KERNEL_MADVISE_POPULATE_READ;
        break;
    case 23u:
        operation = KERNEL_MADVISE_POPULATE_WRITE;
        break;
    case 18u:
        operation = KERNEL_MADVISE_SET_WIPE_ON_FORK;
        break;
    case 19u:
        operation = KERNEL_MADVISE_CLEAR_WIPE_ON_FORK;
        break;
    case 25u:
        return -EDGE_LINUX_EINVAL;
    default:
        if (!kernel_mm_madvise_known(advice))
            return -EDGE_LINUX_EINVAL;
        operation = KERNEL_MADVISE_NOOP;
        break;
    }
    if (operation == KERNEL_MADVISE_DISCARD ||
        operation == KERNEL_MADVISE_LAZY_FREE ||
        operation == KERNEL_MADVISE_SET_WIPE_ON_FORK) {
        int allowed = arch_mm_sealed_discard_allowed(
            pid, address, length);
        if (allowed < 0) return allowed;
        if (!allowed) return -EDGE_LINUX_EPERM;
    }
    return arch_mm_process_madvise(
        pid, address, length, operation,
        (flags & KERNEL_PROCESS_MADVISE_VALIDATE_ONLY) != 0);
}

int kernel_process_mrelease(int32_t pid) {
    if (pid <= 0) return -EDGE_LINUX_ESRCH;
    return arch_mm_process_mrelease(pid);
}

int kernel_process_vm_read_memory(int32_t pid, uint64_t address,
                                  void *buffer, uint64_t size) {
    return arch_mm_process_vm_copy(
        pid, address, buffer, size, KERNEL_MM_PROCESS_VM_READ);
}

int kernel_process_vm_write_memory(int32_t pid, uint64_t address,
                                   const void *buffer, uint64_t size) {
    return arch_mm_process_vm_copy(
        pid, address, (void *)buffer, size, KERNEL_MM_PROCESS_VM_WRITE);
}

uint64_t kernel_mm_vma_pool_bytes(uint32_t address_spaces,
                                  uint32_t areas_per_space) {
    if (!address_spaces || !areas_per_space ||
        areas_per_space > KERNEL_MM_VMA_MAX)
        return 0;
    if ((uint64_t)address_spaces >
        UINT64_MAX / (uint64_t)areas_per_space /
            sizeof(kernel_vm_area_t))
        return 0;
    return (uint64_t)address_spaces * (uint64_t)areas_per_space *
           sizeof(kernel_vm_area_t);
}

int kernel_mm_vma_pool_initialize(void *memory, uint64_t size,
                                  uint32_t address_spaces,
                                  uint32_t areas_per_space) {
    uint64_t required =
        kernel_mm_vma_pool_bytes(address_spaces, areas_per_space);
    if (!memory || !required || size < required)
        return -EDGE_LINUX_ENOMEM;
    g_kernel_vma_pool = (kernel_vm_area_t *)memory;
    g_kernel_vma_address_spaces = address_spaces;
    g_kernel_vma_areas_per_space = areas_per_space;
    memset(g_kernel_vma_pool, 0, (uint32_t)required);
    return 0;
}

kernel_vm_area_t *kernel_mm_vma_space(uint32_t index) {
    if (!g_kernel_vma_pool || index >= g_kernel_vma_address_spaces)
        return 0;
    return g_kernel_vma_pool +
        (uint64_t)index * g_kernel_vma_areas_per_space;
}

int kernel_mm_vma_storage_grow(kernel_vm_area_t **areas,
                               uint32_t *capacity,
                               uint32_t live_count,
                               uint32_t required_count,
                               uint32_t *dynamic_pages) {
    kernel_vm_area_t *replacement;
    kernel_vm_area_t *previous;
    uint32_t previous_pages;
    uint32_t new_capacity;
    uint32_t new_pages;
    uint64_t bytes;

    if (!areas || !capacity || !dynamic_pages || live_count > *capacity ||
        required_count > KERNEL_MM_VMA_MAX)
        return -EDGE_LINUX_ENOMEM;
    if (required_count <= *capacity) return 0;

    new_capacity = *capacity ? *capacity : KERNEL_MM_VMA_INITIAL_AREAS;
    while (new_capacity < required_count) {
        uint32_t doubled = new_capacity > KERNEL_MM_VMA_MAX / 2u ?
                           KERNEL_MM_VMA_MAX : new_capacity * 2u;
        if (doubled <= new_capacity) return -EDGE_LINUX_ENOMEM;
        new_capacity = doubled;
    }
    bytes = (uint64_t)new_capacity * sizeof(kernel_vm_area_t);
    new_pages = (uint32_t)((bytes + KERNEL_MM_USER_PAGE_SIZE - 1u) /
                           KERNEL_MM_USER_PAGE_SIZE);
    replacement = (kernel_vm_area_t *)arch_vm_alloc_pages(new_pages);
    if (!replacement) return -EDGE_LINUX_ENOMEM;
    memset(replacement, 0, new_pages * KERNEL_MM_USER_PAGE_SIZE);
    if (*areas && live_count)
        memcpy(replacement, *areas,
               live_count * (uint32_t)sizeof(kernel_vm_area_t));

    previous = *areas;
    previous_pages = *dynamic_pages;
    *areas = replacement;
    *capacity = new_capacity;
    *dynamic_pages = new_pages;
    if (previous_pages)
        kernel_mm_vma_storage_release(previous, previous_pages);
    return 0;
}

void kernel_mm_vma_storage_release(kernel_vm_area_t *areas,
                                   uint32_t dynamic_pages) {
    kernel_mm_release_pages(areas, dynamic_pages);
}

uint64_t kernel_mm_lock_space_pool_bytes(uint32_t address_spaces) {
    if (!address_spaces) return 0;
    return (uint64_t)address_spaces *
           (sizeof(kernel_mm_lock_space_t) +
            sizeof(kernel_mm_seal_space_t));
}

int kernel_mm_lock_space_pool_initialize(void *memory, uint64_t size,
                                         uint32_t address_spaces) {
    uint64_t required = kernel_mm_lock_space_pool_bytes(address_spaces);

    if (!memory || !required || size < required)
        return -EDGE_LINUX_ENOMEM;
    g_kernel_mm_lock_spaces = (kernel_mm_lock_space_t *)memory;
    g_kernel_mm_seal_spaces = (kernel_mm_seal_space_t *)(
        (uint8_t *)memory +
        (uint64_t)address_spaces * sizeof(kernel_mm_lock_space_t));
    g_kernel_mm_lock_space_capacity = address_spaces;
    g_kernel_mm_lock_registry_guard = 0u;
    memset(memory, 0, (uint32_t)required);
    return 0;
}

static int kernel_mm_seal_space_reserve(uint64_t address_space,
                                        uint32_t additional_ranges) {
    kernel_mm_locked_range_t *replacement;
    kernel_mm_locked_range_t *previous;
    uint32_t previous_pages;
    uint32_t required;
    uint32_t new_capacity;
    uint32_t new_pages;
    uint64_t bytes;

    if (!address_space) return -EDGE_LINUX_EINVAL;
    if (!additional_ranges) return 0;

    for (;;) {
        kernel_mm_seal_space_t *space;

        kernel_mm_registry_lock();
        space = kernel_mm_seal_space_find_locked(address_space, 1);
        if (!space ||
            additional_ranges > KERNEL_MM_VMA_MAX - space->range_count) {
            kernel_mm_registry_unlock();
            return -EDGE_LINUX_ENOMEM;
        }
        required = space->range_count + additional_ranges;
        if (required <= space->range_capacity) {
            kernel_mm_registry_unlock();
            return 0;
        }
        new_capacity = space->range_capacity ?
            space->range_capacity : KERNEL_MM_VMA_INITIAL_AREAS;
        while (new_capacity < required) {
            uint32_t doubled = new_capacity > KERNEL_MM_VMA_MAX / 2u ?
                               KERNEL_MM_VMA_MAX : new_capacity * 2u;
            if (doubled <= new_capacity) {
                kernel_mm_registry_unlock();
                return -EDGE_LINUX_ENOMEM;
            }
            new_capacity = doubled;
        }
        kernel_mm_registry_unlock();

        bytes = (uint64_t)new_capacity * sizeof(kernel_mm_locked_range_t);
        new_pages = (uint32_t)((bytes + KERNEL_MM_USER_PAGE_SIZE - 1u) /
                               KERNEL_MM_USER_PAGE_SIZE);
        replacement = (kernel_mm_locked_range_t *)
            arch_vm_alloc_pages(new_pages);
        if (!replacement) return -EDGE_LINUX_ENOMEM;
        memset(replacement, 0, new_pages * KERNEL_MM_USER_PAGE_SIZE);

        kernel_mm_registry_lock();
        space = kernel_mm_seal_space_find_locked(address_space, 1);
        if (!space) {
            kernel_mm_registry_unlock();
            kernel_mm_release_pages(replacement, new_pages);
            return -EDGE_LINUX_ENOMEM;
        }
        if (space->range_capacity >= required) {
            kernel_mm_registry_unlock();
            kernel_mm_release_pages(replacement, new_pages);
            return 0;
        }
        if (space->range_count)
            memcpy(replacement, space->ranges,
                   space->range_count *
                       (uint32_t)sizeof(kernel_mm_locked_range_t));
        previous = space->ranges;
        previous_pages = space->range_pages;
        space->ranges = replacement;
        space->range_capacity = new_capacity;
        space->range_pages = new_pages;
        kernel_mm_registry_unlock();
        kernel_mm_release_pages(previous, previous_pages);
        return 0;
    }
}

static int kernel_mm_seal_space_add(uint64_t address_space,
                                    uint64_t address, uint64_t length) {
    kernel_mm_seal_space_t *space;
    uint64_t end;
    uint32_t first;
    uint32_t last;

    if (!address_space || !length || length > UINT64_MAX - address)
        return -EDGE_LINUX_EINVAL;
    end = address + length;
    if (kernel_mm_seal_space_reserve(address_space, 1u) < 0)
        return -EDGE_LINUX_ENOMEM;

    kernel_mm_registry_lock();
    space = kernel_mm_seal_space_find_locked(address_space, 0);
    if (!space || !space->ranges ||
        space->range_count >= space->range_capacity) {
        kernel_mm_registry_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    first = 0;
    while (first < space->range_count &&
           space->ranges[first].end < address)
        ++first;
    last = first;
    while (last < space->range_count &&
           space->ranges[last].start <= end) {
        if (space->ranges[last].start < address)
            address = space->ranges[last].start;
        if (space->ranges[last].end > end)
            end = space->ranges[last].end;
        ++last;
    }
    if (last > first) {
        space->ranges[first].start = address;
        space->ranges[first].end = end;
        if (last < space->range_count)
            memmove(&space->ranges[first + 1u], &space->ranges[last],
                    (space->range_count - last) *
                        (uint32_t)sizeof(kernel_mm_locked_range_t));
        space->range_count -= last - first - 1u;
    } else {
        if (first < space->range_count)
            memmove(&space->ranges[first + 1u], &space->ranges[first],
                    (space->range_count - first) *
                        (uint32_t)sizeof(kernel_mm_locked_range_t));
        space->ranges[first].start = address;
        space->ranges[first].end = end;
        ++space->range_count;
    }
    kernel_mm_registry_unlock();
    return 0;
}

int kernel_mm_seal_space_overlaps(uint64_t address_space,
                                  uint64_t address, uint64_t length) {
    kernel_mm_seal_space_t *space;
    uint64_t end;
    int result = 0;

    if (!address_space || !length || length > UINT64_MAX - address)
        return 0;
    end = address + length;
    kernel_mm_registry_lock();
    space = kernel_mm_seal_space_find_locked(address_space, 0);
    if (space) {
        for (uint32_t index = 0; index < space->range_count; ++index) {
            kernel_mm_locked_range_t *range = &space->ranges[index];
            if (range->start >= end) break;
            if (range->end > address) {
                result = 1;
                break;
            }
        }
    }
    kernel_mm_registry_unlock();
    return result;
}

int kernel_mm_seal_space_clone(uint64_t parent_address_space,
                               uint64_t child_address_space) {
    kernel_mm_seal_space_t *parent;
    kernel_mm_seal_space_t *child;
    uint32_t count;

    if (!parent_address_space || !child_address_space)
        return -EDGE_LINUX_EINVAL;
    kernel_mm_registry_lock();
    parent = kernel_mm_seal_space_find_locked(parent_address_space, 0);
    count = parent ? parent->range_count : 0u;
    kernel_mm_registry_unlock();
    if (!count) return 0;
    if (kernel_mm_seal_space_reserve(child_address_space, count) < 0)
        return -EDGE_LINUX_ENOMEM;

    kernel_mm_registry_lock();
    parent = kernel_mm_seal_space_find_locked(parent_address_space, 0);
    child = kernel_mm_seal_space_find_locked(child_address_space, 0);
    if (!parent || !child || child->range_capacity < parent->range_count) {
        kernel_mm_registry_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    if (parent->range_count)
        memcpy(child->ranges, parent->ranges,
               parent->range_count *
                   (uint32_t)sizeof(kernel_mm_locked_range_t));
    child->range_count = parent->range_count;
    kernel_mm_registry_unlock();
    return 0;
}

int kernel_mm_lock_space_reserve(uint64_t address_space,
                                 uint32_t additional_ranges) {
    kernel_mm_locked_range_t *replacement;
    kernel_mm_locked_range_t *previous;
    uint32_t previous_pages;
    uint32_t required;
    uint32_t new_capacity;
    uint32_t new_pages;
    uint64_t bytes;

    if (!address_space) return -EDGE_LINUX_EINVAL;
    if (!additional_ranges) return 0;

    for (;;) {
        kernel_mm_lock_space_t *space;

        kernel_mm_registry_lock();
        space = kernel_mm_lock_space_find_locked(address_space, 1);
        if (!space) {
            kernel_mm_registry_unlock();
            return -EDGE_LINUX_ENOMEM;
        }
        if (additional_ranges > KERNEL_MM_VMA_MAX - space->range_count) {
            kernel_mm_registry_unlock();
            return -EDGE_LINUX_ENOMEM;
        }
        required = space->range_count + additional_ranges;
        if (required <= space->range_capacity) {
            kernel_mm_registry_unlock();
            return 0;
        }
        new_capacity = space->range_capacity ?
            space->range_capacity : KERNEL_MM_VMA_INITIAL_AREAS;
        while (new_capacity < required) {
            uint32_t doubled = new_capacity > KERNEL_MM_VMA_MAX / 2u ?
                               KERNEL_MM_VMA_MAX : new_capacity * 2u;
            if (doubled <= new_capacity) {
                kernel_mm_registry_unlock();
                return -EDGE_LINUX_ENOMEM;
            }
            new_capacity = doubled;
        }
        kernel_mm_registry_unlock();

        bytes = (uint64_t)new_capacity *
                sizeof(kernel_mm_locked_range_t);
        new_pages = (uint32_t)((bytes + KERNEL_MM_USER_PAGE_SIZE - 1u) /
                               KERNEL_MM_USER_PAGE_SIZE);
        replacement = (kernel_mm_locked_range_t *)
            arch_vm_alloc_pages(new_pages);
        if (!replacement) return -EDGE_LINUX_ENOMEM;
        memset(replacement, 0,
               new_pages * KERNEL_MM_USER_PAGE_SIZE);

        kernel_mm_registry_lock();
        space = kernel_mm_lock_space_find_locked(address_space, 1);
        if (!space) {
            kernel_mm_registry_unlock();
            kernel_mm_release_pages(replacement, new_pages);
            return -EDGE_LINUX_ENOMEM;
        }
        if (space->range_capacity >= required) {
            kernel_mm_registry_unlock();
            kernel_mm_release_pages(replacement, new_pages);
            return 0;
        }
        if (space->range_count)
            memcpy(replacement, space->ranges,
                   space->range_count *
                       (uint32_t)sizeof(kernel_mm_locked_range_t));
        previous = space->ranges;
        previous_pages = space->range_pages;
        space->ranges = replacement;
        space->range_capacity = new_capacity;
        space->range_pages = new_pages;
        kernel_mm_registry_unlock();
        kernel_mm_release_pages(previous, previous_pages);
        return 0;
    }
}

int kernel_mm_lock_space_add_limited(uint64_t address_space,
                                     uint64_t address, uint64_t length,
                                     uint64_t byte_limit) {
    kernel_mm_lock_space_t *space;
    uint64_t end;
    uint64_t requested_start;
    uint64_t requested_end;
    uint64_t locked_bytes = 0;
    uint64_t overlap_bytes = 0;
    uint32_t first;
    uint32_t last;

    if (!address_space || !length || length > UINT64_MAX - address)
        return -EDGE_LINUX_EINVAL;
    end = address + length;
    requested_start = address;
    requested_end = end;
    if (kernel_mm_lock_space_reserve(address_space, 1u) < 0)
        return -EDGE_LINUX_ENOMEM;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (!space || !space->ranges ||
        space->range_count >= space->range_capacity) {
        kernel_mm_registry_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    for (uint32_t index = 0; index < space->range_count; ++index) {
        kernel_mm_locked_range_t *range = &space->ranges[index];
        uint64_t overlap_start;
        uint64_t overlap_end;

        locked_bytes += range->end - range->start;
        overlap_start = range->start > requested_start ?
                        range->start : requested_start;
        overlap_end = range->end < requested_end ?
                      range->end : requested_end;
        if (overlap_end > overlap_start)
            overlap_bytes += overlap_end - overlap_start;
    }
    if (length - overlap_bytes > byte_limit ||
        locked_bytes > byte_limit - (length - overlap_bytes)) {
        kernel_mm_registry_unlock();
        return -EDGE_LINUX_ENOMEM;
    }
    first = 0;
    while (first < space->range_count &&
           space->ranges[first].end < address)
        ++first;
    last = first;
    while (last < space->range_count &&
           space->ranges[last].start <= end) {
        if (space->ranges[last].start < address)
            address = space->ranges[last].start;
        if (space->ranges[last].end > end)
            end = space->ranges[last].end;
        ++last;
    }
    if (last > first) {
        space->ranges[first].start = address;
        space->ranges[first].end = end;
        if (last < space->range_count)
            memmove(&space->ranges[first + 1u],
                    &space->ranges[last],
                    (space->range_count - last) *
                        (uint32_t)sizeof(kernel_mm_locked_range_t));
        space->range_count -= last - first - 1u;
    } else {
        if (first < space->range_count)
            memmove(&space->ranges[first + 1u],
                    &space->ranges[first],
                    (space->range_count - first) *
                        (uint32_t)sizeof(kernel_mm_locked_range_t));
        space->ranges[first].start = address;
        space->ranges[first].end = end;
        ++space->range_count;
    }
    kernel_mm_registry_unlock();
    return 0;
}

int kernel_mm_lock_space_add(uint64_t address_space, uint64_t address,
                             uint64_t length) {
    return kernel_mm_lock_space_add_limited(
        address_space, address, length, UINT64_MAX);
}

int kernel_mm_lock_space_remove(uint64_t address_space, uint64_t address,
                                uint64_t length) {
    kernel_mm_lock_space_t *space;
    uint64_t end;
    int need_reserve = 0;

    if (!address_space || !length || length > UINT64_MAX - address)
        return -EDGE_LINUX_EINVAL;
    end = address + length;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (!space || !space->range_count) {
        kernel_mm_registry_unlock();
        return 0;
    }
    for (uint32_t index = 0; index < space->range_count; ++index) {
        kernel_mm_locked_range_t *range = &space->ranges[index];
        if (range->start < address && range->end > end) {
            need_reserve = space->range_count >= space->range_capacity;
            break;
        }
        if (range->start >= end) break;
    }
    kernel_mm_registry_unlock();
    /* One source interval can become two after a middle-range unlock. */
    if (need_reserve &&
        kernel_mm_lock_space_reserve(address_space, 1u) < 0)
        return -EDGE_LINUX_ENOMEM;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (!space) {
        kernel_mm_registry_unlock();
        return 0;
    }
    for (uint32_t index = 0; index < space->range_count;) {
        kernel_mm_locked_range_t *range = &space->ranges[index];
        if (range->end <= address) {
            ++index;
            continue;
        }
        if (range->start >= end) break;
        if (address <= range->start && end >= range->end) {
            if (index + 1u < space->range_count)
                memmove(range, range + 1u,
                        (space->range_count - index - 1u) *
                            (uint32_t)sizeof(*range));
            --space->range_count;
            continue;
        }
        if (address <= range->start) {
            range->start = end;
            break;
        }
        if (end >= range->end) {
            range->end = address;
            ++index;
            continue;
        }
        memmove(range + 2u, range + 1u,
                (space->range_count - index - 1u) *
                    (uint32_t)sizeof(*range));
        range[1].start = end;
        range[1].end = range[0].end;
        range[0].end = address;
        ++space->range_count;
        break;
    }
    kernel_mm_registry_unlock();
    return 0;
}

static void kernel_mm_lock_space_sort_and_merge_locked(
        kernel_mm_lock_space_t *space) {
    uint32_t output;

    if (!space || space->range_count < 2u) return;
    for (uint32_t index = 1u; index < space->range_count; ++index) {
        kernel_mm_locked_range_t value = space->ranges[index];
        uint32_t position = index;

        while (position &&
               space->ranges[position - 1u].start > value.start) {
            space->ranges[position] = space->ranges[position - 1u];
            --position;
        }
        space->ranges[position] = value;
    }
    output = 0u;
    for (uint32_t index = 0u; index < space->range_count; ++index) {
        kernel_mm_locked_range_t *current = &space->ranges[index];

        if (current->end <= current->start) continue;
        if (output && current->start <= space->ranges[output - 1u].end) {
            if (current->end > space->ranges[output - 1u].end)
                space->ranges[output - 1u].end = current->end;
            continue;
        }
        space->ranges[output++] = *current;
    }
    space->range_count = output;
}

int kernel_mm_lock_space_remap(uint64_t address_space,
                               uint64_t old_address,
                               uint64_t old_length,
                               uint64_t new_address,
                               uint64_t new_length) {
    kernel_mm_lock_space_t *space;
    uint64_t old_end;
    uint64_t retained_length;
    uint64_t retained_end;
    uint64_t new_end;
    int extend_locked;

    if (!address_space || !old_length || !new_length ||
        old_length > UINT64_MAX - old_address ||
        new_length > UINT64_MAX - new_address)
        return -EDGE_LINUX_EINVAL;
    old_end = old_address + old_length;
    new_end = new_address + new_length;
    retained_length = old_length < new_length ? old_length : new_length;
    retained_end = old_address + retained_length;

    /* Two boundary splits plus one locked expansion are the worst case. */
    if (kernel_mm_lock_space_reserve(address_space, 3u) < 0)
        return -EDGE_LINUX_ENOMEM;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (!space || !space->range_count) {
        kernel_mm_registry_unlock();
        return 0;
    }
    extend_locked = 0;
    for (uint32_t index = 0u; index < space->range_count; ++index) {
        if (space->ranges[index].start < old_end &&
            space->ranges[index].end >= old_end) {
            extend_locked = 1;
            break;
        }
    }

    if (new_address == old_address) {
        uint64_t removed_start = new_end;
        uint64_t removed_end = old_end;

        for (uint32_t index = 0u; index < space->range_count;) {
            kernel_mm_locked_range_t *range = &space->ranges[index];

            if (new_length >= old_length ||
                range->end <= removed_start ||
                range->start >= removed_end) {
                ++index;
                continue;
            }
            if (range->start < removed_start &&
                range->end > removed_end) {
                memmove(range + 2u, range + 1u,
                        (space->range_count - index - 1u) *
                            (uint32_t)sizeof(*range));
                range[1].start = removed_end;
                range[1].end = range[0].end;
                range[0].end = removed_start;
                ++space->range_count;
                index += 2u;
            } else if (range->start < removed_start) {
                range->end = removed_start;
                ++index;
            } else if (range->end > removed_end) {
                range->start = removed_end;
                ++index;
            } else {
                if (index + 1u < space->range_count)
                    memmove(range, range + 1u,
                            (space->range_count - index - 1u) *
                                (uint32_t)sizeof(*range));
                --space->range_count;
            }
        }
        if (new_length > old_length && extend_locked) {
            space->ranges[space->range_count].start = old_end;
            space->ranges[space->range_count].end = new_end;
            ++space->range_count;
        }
        kernel_mm_lock_space_sort_and_merge_locked(space);
        kernel_mm_registry_unlock();
        return 0;
    }

    /* A moved mapping replaces any resident locks at its destination. */
    for (uint32_t index = 0u; index < space->range_count;) {
        kernel_mm_locked_range_t *range = &space->ranges[index];

        if (range->end <= new_address || range->start >= new_end) {
            ++index;
            continue;
        }
        if (range->start < new_address && range->end > new_end) {
            memmove(range + 2u, range + 1u,
                    (space->range_count - index - 1u) *
                        (uint32_t)sizeof(*range));
            range[1].start = new_end;
            range[1].end = range[0].end;
            range[0].end = new_address;
            ++space->range_count;
            index += 2u;
            continue;
        }
        if (range->start < new_address) {
            range->end = new_address;
            ++index;
            continue;
        }
        if (range->end > new_end) {
            range->start = new_end;
            ++index;
            continue;
        }
        if (index + 1u < space->range_count)
            memmove(range, range + 1u,
                    (space->range_count - index - 1u) *
                        (uint32_t)sizeof(*range));
        --space->range_count;
    }

    for (uint32_t index = 0u; index < space->range_count;) {
        kernel_mm_locked_range_t original = space->ranges[index];
        kernel_mm_locked_range_t pieces[3];
        uint32_t piece_count = 0u;
        uint64_t middle_start;
        uint64_t middle_end;

        if (original.end <= old_address || original.start >= old_end) {
            ++index;
            continue;
        }
        if (original.start < old_address) {
            pieces[piece_count].start = original.start;
            pieces[piece_count++].end = old_address;
        }
        middle_start = original.start > old_address ?
                       original.start : old_address;
        middle_end = original.end < retained_end ?
                     original.end : retained_end;
        if (middle_end > middle_start) {
            pieces[piece_count].start =
                new_address + (middle_start - old_address);
            pieces[piece_count++].end =
                new_address + (middle_end - old_address);
        }
        if (original.end > old_end) {
            pieces[piece_count].start = old_end;
            pieces[piece_count++].end = original.end;
        }
        if (piece_count > 1u && index + 1u < space->range_count)
            memmove(&space->ranges[index + piece_count],
                    &space->ranges[index + 1u],
                    (space->range_count - index - 1u) *
                        (uint32_t)sizeof(space->ranges[0]));
        if (!piece_count) {
            if (index + 1u < space->range_count)
                memmove(&space->ranges[index],
                        &space->ranges[index + 1u],
                        (space->range_count - index - 1u) *
                            (uint32_t)sizeof(space->ranges[0]));
            --space->range_count;
            continue;
        }
        for (uint32_t piece = 0u; piece < piece_count; ++piece)
            space->ranges[index + piece] = pieces[piece];
        space->range_count += piece_count - 1u;
        index += piece_count;
    }
    if (new_length > old_length && extend_locked) {
        space->ranges[space->range_count].start =
            new_address + old_length;
        space->ranges[space->range_count].end = new_end;
        ++space->range_count;
    }
    kernel_mm_lock_space_sort_and_merge_locked(space);
    kernel_mm_registry_unlock();
    return 0;
}

int kernel_mm_lock_space_contains(uint64_t address_space, uint64_t address) {
    kernel_mm_lock_space_t *space;
    uint32_t low;
    uint32_t high;
    int result = 0;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    low = 0;
    high = space ? space->range_count : 0;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2u;
        kernel_mm_locked_range_t *range = &space->ranges[middle];
        if (address < range->start)
            high = middle;
        else if (address >= range->end)
            low = middle + 1u;
        else {
            result = 1;
            break;
        }
    }
    kernel_mm_registry_unlock();
    return result;
}

uint64_t kernel_mm_lock_space_bytes(uint64_t address_space) {
    kernel_mm_lock_space_t *space;
    uint64_t bytes = 0;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (space) {
        for (uint32_t index = 0; index < space->range_count; ++index)
            bytes += space->ranges[index].end -
                     space->ranges[index].start;
    }
    kernel_mm_registry_unlock();
    return bytes;
}

uint64_t kernel_mm_resident_peak_observe(uint64_t address_space,
                                         uint64_t resident_bytes) {
    kernel_mm_lock_space_t *space;
    uint64_t peak = resident_bytes;

    if (!address_space) return resident_bytes;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 1);
    if (space) {
        if (resident_bytes > space->peak_resident_bytes)
            space->peak_resident_bytes = resident_bytes;
        peak = space->peak_resident_bytes;
    }
    kernel_mm_registry_unlock();
    return peak;
}

uint64_t kernel_mm_resident_peak_bytes(uint64_t address_space) {
    kernel_mm_lock_space_t *space;
    uint64_t peak = 0;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (space) peak = space->peak_resident_bytes;
    kernel_mm_registry_unlock();
    return peak;
}

int kernel_mm_mempolicy_set(uint64_t address_space, int32_t mode,
                            uint32_t flags, uint64_t nodes) {
    kernel_mm_lock_space_t *space;

    if (!address_space) return -EDGE_LINUX_EINVAL;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(
        address_space, mode != 0 || flags != 0u);
    if (!space) {
        kernel_mm_registry_unlock();
        return mode == 0 && flags == 0u ? 0 : -EDGE_LINUX_ENOMEM;
    }
    space->mempolicy_mode = mode;
    space->mempolicy_flags = flags;
    space->mempolicy_nodes = nodes;
    kernel_mm_registry_unlock();
    return 0;
}

int kernel_mm_mempolicy_get(uint64_t address_space, int32_t *mode,
                            uint32_t *flags, uint64_t *nodes) {
    kernel_mm_lock_space_t *space;

    if (!address_space || !mode || !flags || !nodes)
        return -EDGE_LINUX_EINVAL;
    *mode = 0;
    *flags = 0u;
    *nodes = 0u;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (space) {
        *mode = space->mempolicy_mode;
        *flags = space->mempolicy_flags;
        *nodes = space->mempolicy_nodes;
    }
    kernel_mm_registry_unlock();
    return 0;
}

uint32_t kernel_mm_lock_space_future_flags(uint64_t address_space) {
    kernel_mm_lock_space_t *space;
    uint32_t flags = 0;

    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (space) flags = space->future_flags;
    kernel_mm_registry_unlock();
    return flags;
}

int kernel_mm_lock_space_set_future(uint64_t address_space, uint32_t flags) {
    kernel_mm_lock_space_t *space;

    if (!address_space ||
        (flags & ~(KERNEL_MM_LOCK_ALL_FUTURE |
                   KERNEL_MM_LOCK_ALL_ONFAULT)))
        return -EDGE_LINUX_EINVAL;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, flags != 0u);
    if (!space) {
        kernel_mm_registry_unlock();
        return flags ? -EDGE_LINUX_ENOMEM : 0;
    }
    space->future_flags = flags;
    kernel_mm_registry_unlock();
    return 0;
}

void kernel_mm_lock_space_release(uint64_t address_space) {
    kernel_mm_lock_space_t *space;
    kernel_mm_seal_space_t *seal_space;
    kernel_mm_locked_range_t *ranges = 0;
    kernel_mm_locked_range_t *seal_ranges = 0;
    uint32_t pages = 0;
    uint32_t seal_pages = 0;

    if (!address_space) return;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (space) {
        ranges = space->ranges;
        pages = space->range_pages;
        memset(space, 0, sizeof(*space));
    }
    seal_space = kernel_mm_seal_space_find_locked(address_space, 0);
    if (seal_space) {
        seal_ranges = seal_space->ranges;
        seal_pages = seal_space->range_pages;
        memset(seal_space, 0, sizeof(*seal_space));
    }
    kernel_mm_registry_unlock();
    kernel_mm_release_pages(ranges, pages);
    kernel_mm_release_pages(seal_ranges, seal_pages);
}

void kernel_mm_lock_space_clear(uint64_t address_space) {
    kernel_mm_lock_space_t *space;

    if (!address_space) return;
    kernel_mm_registry_lock();
    space = kernel_mm_lock_space_find_locked(address_space, 0);
    if (space) {
        space->range_count = 0u;
        space->future_flags = 0u;
    }
    kernel_mm_registry_unlock();
}

uint32_t kernel_mm_reclaim_candidate_offer(
    kernel_mm_reclaim_candidate_t *selection, uint32_t selected,
    uint32_t capacity, const kernel_mm_reclaim_candidate_t *candidate) {
    uint32_t position;
    uint32_t limit;

    if (!selection || !candidate || !capacity ||
        !candidate->used || candidate->busy || candidate->pinned ||
        candidate->references)
        return selected;
    if (selected > capacity) selected = capacity;
    position = 0;
    while (position < selected) {
        const kernel_mm_reclaim_candidate_t *current =
            &selection[position];
        if (candidate->active < current->active ||
            (candidate->active == current->active &&
             (candidate->last_used_sequence <
                  current->last_used_sequence ||
              (candidate->last_used_sequence ==
                   current->last_used_sequence &&
               candidate->slot < current->slot))))
            break;
        ++position;
    }
    if (position >= capacity) return selected;
    limit = selected < capacity ? selected : capacity - 1u;
    while (limit > position) {
        selection[limit] = selection[limit - 1u];
        --limit;
    }
    selection[position] = *candidate;
    return selected < capacity ? selected + 1u : selected;
}

void kernel_mm_cache_state_insert(kernel_mm_cache_state_t *state,
                                  uint64_t sequence) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->last_used_sequence = sequence;
    state->access_count = 1u;
    state->referenced = 1u;
}

void kernel_mm_cache_state_access(kernel_mm_cache_state_t *state,
                                  uint64_t sequence) {
    if (!state) return;
    if (state->referenced || state->access_count > 1u)
        state->active = 1u;
    state->referenced = 1u;
    state->last_used_sequence = sequence;
    if (state->access_count != UINT32_MAX) ++state->access_count;
}

void kernel_mm_cache_state_age(kernel_mm_cache_state_t *state) {
    if (!state) return;
    if (state->referenced) {
        state->referenced = 0u;
        return;
    }
    state->active = 0u;
}

void kernel_mm_cache_state_deactivate(kernel_mm_cache_state_t *state) {
    if (!state) return;
    state->referenced = 0u;
    state->active = 0u;
}

void kernel_mm_file_cache_note_eviction(
        uint64_t mapping_identity, uint64_t inode_number,
        uint32_t inode_generation, uint64_t page_offset) {
    kernel_mm_file_shadow_t *bucket;
    kernel_mm_file_shadow_t *selected = 0;
    uint64_t sequence;
    uint32_t bucket_index;

    if (!mapping_identity) return;
    page_offset &= ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    bucket_index = kernel_mm_file_shadow_bucket(
        mapping_identity, inode_number, inode_generation, page_offset);
    kernel_mm_file_shadow_lock();
    sequence = ++g_kernel_mm_file_shadow_sequence;
    if (!sequence) sequence = ++g_kernel_mm_file_shadow_sequence;
    bucket = g_kernel_mm_file_shadows[bucket_index];
    for (uint32_t way = 0; way < KERNEL_MM_FILE_SHADOW_WAYS; ++way) {
        kernel_mm_file_shadow_t *candidate = &bucket[way];

        if (kernel_mm_file_shadow_matches(
                candidate, mapping_identity, inode_number,
                inode_generation, page_offset)) {
            selected = candidate;
            break;
        }
        if (!candidate->used || !selected ||
            candidate->eviction_sequence < selected->eviction_sequence)
            selected = candidate;
        if (!candidate->used) break;
    }
    if (selected) {
        selected->mapping_identity = mapping_identity;
        selected->inode_number = inode_number;
        selected->inode_generation = inode_generation;
        selected->page_offset = page_offset;
        selected->eviction_sequence = sequence;
        selected->used = 1u;
    }
    kernel_mm_file_shadow_unlock();
}

void kernel_mm_file_cache_note_refault(
        uint64_t mapping_identity, uint64_t inode_number,
        uint32_t inode_generation, uint64_t page_offset) {
    kernel_mm_file_shadow_t *bucket;
    uint32_t bucket_index;

    if (!mapping_identity) return;
    page_offset &= ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    bucket_index = kernel_mm_file_shadow_bucket(
        mapping_identity, inode_number, inode_generation, page_offset);
    kernel_mm_file_shadow_lock();
    bucket = g_kernel_mm_file_shadows[bucket_index];
    for (uint32_t way = 0; way < KERNEL_MM_FILE_SHADOW_WAYS; ++way) {
        if (!kernel_mm_file_shadow_matches(
                &bucket[way], mapping_identity, inode_number,
                inode_generation, page_offset))
            continue;
        memset(&bucket[way], 0, sizeof(bucket[way]));
        break;
    }
    kernel_mm_file_shadow_unlock();
}

void kernel_mm_file_cache_shadow_stat_range(
    uint64_t mapping_identity, uint64_t inode_number,
    uint32_t inode_generation, uint64_t offset, uint64_t length,
    uint64_t *evicted_pages, uint64_t *recently_evicted_pages) {
    uint64_t end;
    uint64_t evicted = 0;
    uint64_t recent = 0;
    uint64_t current_sequence;

    if (evicted_pages) *evicted_pages = 0;
    if (recently_evicted_pages) *recently_evicted_pages = 0;
    if (!mapping_identity) return;
    end = !length || length > UINT64_MAX - offset ?
          UINT64_MAX : offset + length;
    kernel_mm_file_shadow_lock();
    current_sequence = g_kernel_mm_file_shadow_sequence;
    for (uint32_t bucket_index = 0;
         bucket_index < KERNEL_MM_FILE_SHADOW_BUCKETS; ++bucket_index) {
        for (uint32_t way = 0;
             way < KERNEL_MM_FILE_SHADOW_WAYS; ++way) {
            const kernel_mm_file_shadow_t *shadow =
                &g_kernel_mm_file_shadows[bucket_index][way];

            if (!shadow->used ||
                shadow->mapping_identity != mapping_identity ||
                shadow->inode_number != inode_number ||
                shadow->inode_generation != inode_generation ||
                shadow->page_offset < offset ||
                shadow->page_offset >= end)
                continue;
            ++evicted;
            if (current_sequence - shadow->eviction_sequence <=
                KERNEL_MM_FILE_SHADOW_RECENT_DISTANCE)
                ++recent;
        }
    }
    kernel_mm_file_shadow_unlock();
    if (evicted_pages) *evicted_pages = evicted;
    if (recently_evicted_pages) *recently_evicted_pages = recent;
}

int kernel_mm_file_install_race_satisfied(
    uint64_t resident_identity, uint64_t requested_identity,
    int resident_present, int resident_user, int resident_file_cache,
    int resident_writable, int requested_writable, int private_cow) {
    if (!resident_present || !resident_user || !resident_file_cache)
        return 0;
    if (resident_identity != requested_identity)
        return 0;
    if (private_cow)
        return !requested_writable || resident_writable;
    /*
     * Shared writable file pages use a read-only PTE to detect the next write
     * after writeback.  That PTE is still the requested page, so a concurrent
     * read fault must retry it instead of replacing or rejecting it.
     */
    return !requested_writable || resident_writable || resident_file_cache;
}

int kernel_mm_query_residency(uint64_t address, uint32_t page_count,
                              uint8_t *vector) {
    uint64_t length;

    if (!vector && page_count) return -EDGE_LINUX_EFAULT;
    if (!page_count) return 0;
    length = (uint64_t)page_count * KERNEL_MM_USER_PAGE_SIZE;
    if (kernel_mm_range_overflows(address, length))
        return -EDGE_LINUX_ENOMEM;
    return arch_mm_query_residency(address, page_count, vector);
}

int kernel_mm_lock_range(uint64_t address, uint64_t length, uint32_t flags) {
    if (flags & ~KERNEL_MM_LOCK_RANGE_ONFAULT)
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (kernel_mm_range_overflows(address, length))
        return -EDGE_LINUX_EINVAL;
    return arch_mm_lock_range(address, length, flags);
}

int kernel_mm_unlock_range(uint64_t address, uint64_t length) {
    if (!length) return 0;
    if (kernel_mm_range_overflows(address, length))
        return -EDGE_LINUX_EINVAL;
    return arch_mm_unlock_range(address, length);
}

int kernel_mm_lock_all(uint32_t flags) {
    if (flags & ~(KERNEL_MM_LOCK_ALL_CURRENT | KERNEL_MM_LOCK_ALL_FUTURE |
                  KERNEL_MM_LOCK_ALL_ONFAULT))
        return -EDGE_LINUX_EINVAL;
    return arch_mm_lock_all(flags);
}

int kernel_mm_unlock_all(void) {
    return arch_mm_unlock_all();
}

int kernel_mm_sync_range(uint64_t address, uint64_t length, uint32_t flags) {
    if (flags & ~(KERNEL_MM_SYNC_ASYNC | KERNEL_MM_SYNC_INVALIDATE |
                  KERNEL_MM_SYNC_SYNC))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (kernel_mm_range_overflows(address, length))
        return -EDGE_LINUX_ENOMEM;
    return arch_mm_sync_range(address, length, flags);
}

int64_t kernel_mm_protect_range(uint64_t address, uint64_t length,
                                uint64_t protection) {
    uint64_t allowed = KERNEL_MM_PROT_READ | KERNEL_MM_PROT_WRITE |
                       KERNEL_MM_PROT_EXEC | KERNEL_MM_PROT_SEM |
                       KERNEL_MM_PROT_GROWSDOWN | KERNEL_MM_PROT_GROWSUP;

    if (address & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if ((protection & ~allowed) ||
        (protection & (KERNEL_MM_PROT_GROWSDOWN |
                       KERNEL_MM_PROT_GROWSUP)))
        return -EDGE_LINUX_EINVAL;
    if (length > UINT64_MAX - address -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_ENOMEM;
    length = (length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
             ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    if (kernel_mm_seal_space_overlaps(
            arch_mm_current_address_space(), address, length))
        return -EDGE_LINUX_EPERM;
    return arch_mm_protect_range(address, length, protection);
}

int64_t kernel_mm_map(const kernel_mm_map_request_t *request) {
    kernel_mm_map_request_t effective_request;
    kernel_vfs_descriptor_t description;
    uint64_t mapping_type;
    uint64_t address_space;
    uint64_t rounded_length;
    uint32_t lock_flags;
    uint32_t future_flags;
    int64_t result;
    int lock_status;
    int secret_mapping = 0;

    if (!request) return -EDGE_LINUX_EIO;
    if (!request->length)
        return -EDGE_LINUX_EINVAL;
    if (request->length >
        UINT64_MAX - (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    mapping_type = request->flags & KERNEL_MM_MAP_TYPE_MASK;
    if (mapping_type != KERNEL_MM_MAP_SHARED &&
        mapping_type != KERNEL_MM_MAP_PRIVATE &&
        mapping_type != KERNEL_MM_MAP_SHARED_VALIDATE)
        return -EDGE_LINUX_EINVAL;
    if (request->offset & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if ((request->flags &
         (KERNEL_MM_MAP_FIXED | KERNEL_MM_MAP_FIXED_NOREPLACE)) &&
        (request->address & (KERNEL_MM_USER_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    if (!(request->flags & KERNEL_MM_MAP_ANONYMOUS) &&
        request->descriptor < 0)
        return -EDGE_LINUX_EBADF;
    effective_request = *request;
    if (!(request->flags & KERNEL_MM_MAP_ANONYMOUS)) {
        int status = kernel_vfs_describe_descriptor(
            request->descriptor, &description);
        if (status < 0) return status;
        if (description.attributes &
            KERNEL_VFS_DESCRIPTOR_SECRET_MEMORY) {
            if (mapping_type != KERNEL_MM_MAP_SHARED &&
                mapping_type != KERNEL_MM_MAP_SHARED_VALIDATE)
                return -EDGE_LINUX_EINVAL;
            effective_request.flags |=
                KERNEL_MM_MAP_LOCKED | KERNEL_MM_MAP_SECRET;
            secret_mapping = 1;
        }
    }
    rounded_length =
        (request->length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
        ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    address_space = arch_mm_current_address_space();
    if ((request->flags & KERNEL_MM_MAP_FIXED) &&
        !(request->flags & KERNEL_MM_MAP_FIXED_NOREPLACE) &&
        kernel_mm_seal_space_overlaps(
            address_space, request->address, rounded_length))
        return -EDGE_LINUX_EPERM;
    result = arch_mm_map(&effective_request);
    if (result < 0) return result;

    future_flags = kernel_mm_lock_space_future_flags(address_space);
    if (!(effective_request.flags & KERNEL_MM_MAP_LOCKED) &&
        !(future_flags & KERNEL_MM_LOCK_ALL_FUTURE))
        return result;
    lock_flags = (!(effective_request.flags & KERNEL_MM_MAP_LOCKED) &&
                  (future_flags & KERNEL_MM_LOCK_ALL_ONFAULT)) ?
                 KERNEL_MM_LOCK_RANGE_ONFAULT : 0u;
    lock_status = arch_mm_lock_range(
        (uint64_t)result, rounded_length, lock_flags);
    if (lock_status < 0) {
        (void)arch_mm_unmap_range((uint64_t)result, rounded_length);
        return secret_mapping && lock_status == -EDGE_LINUX_ENOMEM ?
            -EDGE_LINUX_EAGAIN : lock_status;
    }
    return result;
}

int64_t kernel_mm_unmap_range(uint64_t address, uint64_t length) {
    uint64_t address_space;
    int64_t result;

    if ((address & (KERNEL_MM_USER_PAGE_SIZE - 1u)) || !length)
        return -EDGE_LINUX_EINVAL;
    if (length > UINT64_MAX - (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    length = (length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
             ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    if (length > UINT64_MAX - address)
        return 0;
    address_space = arch_mm_current_address_space();
    if (kernel_mm_seal_space_overlaps(address_space, address, length))
        return -EDGE_LINUX_EPERM;
    result = arch_mm_unmap_range(address, length);
    if (result >= 0)
        (void)kernel_mm_lock_space_remove(
            address_space, address, length);
    return result;
}

int64_t kernel_mm_remap_range(uint64_t old_address, uint64_t old_length,
                              uint64_t new_length, uint64_t flags,
                              uint64_t new_address) {
    uint64_t valid_flags =
        KERNEL_MM_REMAP_MAYMOVE |
        KERNEL_MM_REMAP_FIXED |
        KERNEL_MM_REMAP_DONTUNMAP;

    if (flags & ~valid_flags)
        return -EDGE_LINUX_EINVAL;
    /*
     * DONTUNMAP needs two aliases to one backing object. Neither current
     * address-space backend can preserve that ownership model yet.
     */
    if ((flags & KERNEL_MM_REMAP_DONTUNMAP) ||
        ((flags & KERNEL_MM_REMAP_FIXED) &&
         !(flags & KERNEL_MM_REMAP_MAYMOVE)))
        return -EDGE_LINUX_EINVAL;
    if ((old_address & (KERNEL_MM_USER_PAGE_SIZE - 1u)) ||
        !old_length || !new_length)
        return -EDGE_LINUX_EINVAL;
    if (old_length >
            UINT64_MAX - (KERNEL_MM_USER_PAGE_SIZE - 1u) ||
        new_length >
            UINT64_MAX - (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    old_length = (old_length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
                 ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    new_length = (new_length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
                 ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    if ((flags & KERNEL_MM_REMAP_FIXED) &&
        (new_address & (KERNEL_MM_USER_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    {
        uint64_t address_space = arch_mm_current_address_space();
        if (kernel_mm_seal_space_overlaps(
                address_space, old_address, old_length) ||
            ((flags & KERNEL_MM_REMAP_FIXED) &&
             kernel_mm_seal_space_overlaps(
                 address_space, new_address, new_length)))
            return -EDGE_LINUX_EPERM;
        int had_locked_ranges =
            kernel_mm_lock_space_bytes(address_space) != 0u;
        if (had_locked_ranges &&
            kernel_mm_lock_space_reserve(address_space, 3u) < 0)
            return -EDGE_LINUX_ENOMEM;
        int64_t result = arch_mm_remap_range(
            old_address, old_length, new_length, (uint32_t)flags,
            new_address);
        if (result >= 0 && had_locked_ranges) {
            int lock_status = kernel_mm_lock_space_remap(
                address_space, old_address, old_length,
                (uint64_t)result, new_length);
            if (lock_status < 0) return lock_status;
        }
        return result;
    }
}

int64_t kernel_mm_remap_file_pages(uint64_t address, uint64_t length,
                                   uint64_t protection,
                                   uint64_t page_offset, uint64_t flags) {
    kernel_mm_file_mapping_info_t first;
    uint64_t page_count;
    uint64_t end;
    uint64_t cursor;

    if (protection) return -EDGE_LINUX_EINVAL;
    address &= ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    length &= ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    if (!length || address > UINT64_MAX - length)
        return -EDGE_LINUX_EINVAL;
    page_count = length / KERNEL_MM_USER_PAGE_SIZE;
    if (page_offset > UINT64_MAX - page_count ||
        page_offset > UINT64_MAX / KERNEL_MM_USER_PAGE_SIZE)
        return -EDGE_LINUX_EINVAL;
    if (arch_mm_file_mapping_info(address, &first) < 0 || !first.shared)
        return -EDGE_LINUX_EINVAL;

    end = address + length;
    cursor = address;
    while (cursor < end) {
        kernel_mm_file_mapping_info_t current;
        uint64_t next;

        if (arch_mm_file_mapping_info(cursor, &current) < 0 ||
            !current.shared ||
            current.backing_identity != first.backing_identity ||
            current.object_identity != first.object_identity ||
            current.protection != first.protection ||
            current.attributes != first.attributes)
            return -EDGE_LINUX_EINVAL;
        next = current.end < end ? current.end : end;
        if (next <= cursor) return -EDGE_LINUX_EINVAL;
        cursor = next;
    }
    return arch_mm_remap_file_pages(
        address, length, page_offset * KERNEL_MM_USER_PAGE_SIZE,
        (uint32_t)(flags & KERNEL_MM_MAP_NONBLOCK));
}

int64_t kernel_mm_program_break(uint64_t address) {
    kernel_mm_program_break_state_t state;
    uint64_t old_page;
    uint64_t requested_page;
    uint64_t address_space;
    uint32_t future_flags;
    int status = arch_mm_program_break_snapshot(&state);

    if (status < 0) return status;
    if (!address) return (int64_t)state.current;
    if (address < state.base || address > state.maximum)
        return (int64_t)state.current;

    old_page =
        (state.current + KERNEL_MM_USER_PAGE_SIZE - 1u) &
        ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    requested_page =
        (address + KERNEL_MM_USER_PAGE_SIZE - 1u) &
        ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    address_space = arch_mm_current_address_space();
    if (requested_page != old_page &&
        kernel_mm_seal_space_overlaps(
            address_space,
            requested_page < old_page ? requested_page : old_page,
            requested_page < old_page ? old_page - requested_page :
                                        requested_page - old_page))
        return (int64_t)state.current;
    if (arch_mm_program_break_resize(old_page, requested_page) < 0)
        return (int64_t)state.current;
    future_flags = kernel_mm_lock_space_future_flags(address_space);
    if (requested_page > old_page &&
        (future_flags & KERNEL_MM_LOCK_ALL_FUTURE)) {
        status = arch_mm_lock_range(
            old_page, requested_page - old_page,
            (future_flags & KERNEL_MM_LOCK_ALL_ONFAULT) ?
                KERNEL_MM_LOCK_RANGE_ONFAULT : 0u);
        if (status < 0) {
            (void)arch_mm_program_break_resize(requested_page, old_page);
            return (int64_t)state.current;
        }
    } else if (requested_page < old_page) {
        (void)kernel_mm_lock_space_remove(
            address_space, requested_page, old_page - requested_page);
    }
    arch_mm_program_break_commit(address);
    return (int64_t)address;
}

int64_t kernel_mm_seal_range(uint64_t address, uint64_t length,
                             uint64_t flags) {
    uint64_t address_space;
    int status;

    if (flags || (address & (KERNEL_MM_USER_PAGE_SIZE - 1u)))
        return -EDGE_LINUX_EINVAL;
    if (length > UINT64_MAX - (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    length = (length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
             ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    if (!length) return 0;
    if (length > UINT64_MAX - address)
        return -EDGE_LINUX_EINVAL;
    status = arch_mm_range_mapped(address, length);
    if (status < 0) return status;
    address_space = arch_mm_current_address_space();
    if (!address_space) return -EDGE_LINUX_ESRCH;
    return kernel_mm_seal_space_add(address_space, address, length);
}

int64_t kernel_mm_pkey_allocate(uint32_t access_rights) {
    (void)access_rights;
    /* Neither current architecture backend advertises hardware pkeys. */
    return -EDGE_LINUX_ENOSPC;
}

int kernel_mm_pkey_free(int32_t protection_key) {
    (void)protection_key;
    return -EDGE_LINUX_EINVAL;
}

int64_t kernel_mm_pkey_mprotect(uint64_t address, uint64_t length,
                                uint64_t protection,
                                int32_t protection_key) {
    /* Linux reserves pkey -1 for ordinary mprotect semantics. */
    if (protection_key != -1) return -EDGE_LINUX_EINVAL;
    return kernel_mm_protect_range(address, length, protection);
}
