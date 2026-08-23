/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 early per-address-space mapper.
 * Copyright (c) EdgeOS Contributors.
 *
 * UEFI supplies the initial physical inventory.  Before the full allocator is
 * online, this module reserves pages only from EFI_CONVENTIONAL_MEMORY and
 * creates private TTBR0 roots for userspace.  Each user mapping first clones
 * the affected kernel L1/L2 path and splits its inherited 2 MiB identity block
 * into 4 KiB descriptors, so user AP/execute permissions never mutate the
 * kernel's shared translation tables.
 */

#include <stdint.h>
#include "arch/arm64/mmu.h"
#include "arch/arm64/smp.h"
#include "arch/arm64/user_layout.h"
#include "arch/arm64/vm.h"
#include "console.h"
#include "fs/cgroupfs.h"
#include "kernel/runtime_limits.h"
#include "mm/page_allocator.h"
#include "string.h"
#include "sys/spinlock.h"

#define PAGE_SIZE 4096ULL
#define ARM64_PA_MASK 0x0000FFFFFFFFF000ULL
#define L2_BLOCK_SIZE (2ULL * 1024ULL * 1024ULL)
#define TABLE_ENTRIES 512u
#define EFI_CONVENTIONAL_MEMORY 7u
#define EARLY_USER_ALIAS_FLOOR 0x50000000ULL
/*
 * Every live user page has one ownership record per address space.  A real
 * Xorg process commonly carries more than 10,000 pages, so the old 32K table
 * could not represent a single fork while OpenRC and D-Bus were alive.  Keep
 * enough metadata for a complete desktop process set plus the transient child
 * address space needed by fork.  Debian desktop processes can each carry over
 * 40,000 resident mappings, and a one-million-entry global table exhausted
 * before dconf, panel, and file-manager helpers could fork.  Private writable
 * mappings are shared read-only across fork and copied on the first write.
 */
#define ARM64_USER_MAPPING_MAX 4194304u
#define ARM64_USER_MAPPING_HASH_BUCKETS 4194304u
#define ARM64_USER_MAPPING_HASH_MASK (ARM64_USER_MAPPING_HASH_BUCKETS - 1u)
#define ARM64_PHYSICAL_MAPPING_HASH_BUCKETS 262144u
#define ARM64_PHYSICAL_MAPPING_HASH_MASK \
    (ARM64_PHYSICAL_MAPPING_HASH_BUCKETS - 1u)

#define DESC_VALID (1ULL << 0)
#define DESC_TABLE (1ULL << 1)
#define DESC_AF (1ULL << 10)
#define DESC_NG (1ULL << 11)
#define DESC_SH_INNER (3ULL << 8)
#define DESC_SH_OUTER (2ULL << 8)
#define DESC_ATTRIDX(v) ((uint64_t)(v) << 2)
#define DESC_AP_EL0_RW (1ULL << 6)
#define DESC_AP_EL0_RO (3ULL << 6)
#define DESC_AP_MASK (3ULL << 6)
#define DESC_UXN (1ULL << 54)
#define DESC_PXN (1ULL << 53)
#define DESC_EDGEOS_COW (1ULL << 55)
#define DESC_EDGEOS_POISON (1ULL << 56)

typedef struct {
    uint32_t type;
    uint32_t pad;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} efi_memory_descriptor_t;

static uint64_t g_early_next;
static uint64_t g_early_start;
static uint64_t g_early_end;
static uint64_t g_managed_memory_bytes;
static uint64_t g_identity_map_end;
static uint64_t g_kernel_ttbr0;
static uint64_t g_kernel_image_start;
static uint64_t g_kernel_image_end;
static uint64_t g_shared_zero_page;
static edge_page_allocator_t g_physical_pages;
typedef struct {
    uint64_t page;
    uint64_t caller;
    uint8_t allocation;
} arm64_page_lifecycle_t;
#define ARM64_PAGE_LIFECYCLE_MAX 8192u
static arm64_page_lifecycle_t g_page_lifecycle[ARM64_PAGE_LIFECYCLE_MAX];
static uint32_t g_page_lifecycle_cursor;

typedef struct {
    uint64_t ttbr0;
    uint64_t va;
    uint64_t pa;
    uint32_t prot;
    uint8_t used;
    uint8_t reserved[3];
    int32_t prev_for_ttbr;
    int32_t next_for_ttbr;
    int32_t next_hash;
    int32_t next_physical_hash;
} arm64_user_mapping_t;

static arm64_user_mapping_t *g_user_mappings;
static int32_t *g_user_mapping_hash;
static int32_t *g_physical_mapping_hash;
static uint32_t g_user_mapping_count;
static uint32_t g_user_mapping_free_hint;
static uint32_t g_writeprotect_generation;

#define ARM64_ADDRESS_SPACE_MAX EDGE_RUNTIME_MAX_TASKS
#define ARM64_ADDRESS_SPACE_HASH_BUCKETS 2048u
#define ARM64_ADDRESS_SPACE_HASH_MASK (ARM64_ADDRESS_SPACE_HASH_BUCKETS - 1u)
#define ARM64_CLONE_TABLE_HASH_CAPACITY 8192u
#define ARM64_CLONE_TABLE_HASH_MASK (ARM64_CLONE_TABLE_HASH_CAPACITY - 1u)
/*
 * AArch64 loaders place DSOs in a sparse address range.  Forking a desktop
 * process can therefore require substantially more L2/L3 tables than its
 * resident page count suggests.  This is ownership metadata, not a limit on
 * the architectural table depth; size it for the supported mapping inventory.
 */
#define ARM64_OWNED_TABLE_MAX 4096u
typedef struct {
    uint64_t ttbr0;
    uint32_t cgroup_id;
    uint16_t asid;
    int32_t mapping_head;
    uint32_t mapping_count;
    uint64_t cached_prefix[3];
    uint64_t *cached_table[3];
    uint8_t cached_valid[3];
    uint32_t writeprotect_generation;
    uint16_t owned_table_count;
    int32_t next_hash;
    uint64_t owned_tables[ARM64_OWNED_TABLE_MAX];
    uint8_t used;
} arm64_address_space_record_t;

static arm64_address_space_record_t *g_address_spaces;
static int32_t g_address_space_hash[ARM64_ADDRESS_SPACE_HASH_BUCKETS];
static uint64_t g_asid_bitmap[65536u / 64u];
static uint32_t g_asid_limit = 255u;
static uint32_t g_asid_shift = 56u;
static uint32_t g_asid_free_hint = 1u;
static uint32_t g_asid_epoch;
static spinlock_t g_asid_lock;
static int32_t g_clone_table_hash[ARM64_CLONE_TABLE_HASH_CAPACITY];
static volatile uint32_t g_clone_table_hash_busy;
static uint32_t g_table_exhaustion_log_budget = 4u;
static uint32_t g_mapping_failure_log_budget = 8u;

static void asid_invalidate(uint16_t asid) {
    uint64_t operand;
    if (!asid) return;
    operand = (uint64_t)asid << g_asid_shift;
    __asm__ __volatile__("dsb ishst\n\ttlbi aside1is, %0\n\ttlbi aside1, %0\n\t"
                         "dsb ish\n\tisb" :: "r"(operand) : "memory");
}

static void asid_invalidate_all(void) {
    __asm__ __volatile__("dsb ishst\n\ttlbi vmalle1is\n\ttlbi vmalle1\n\t"
                         "dsb ish\n\tisb" ::: "memory");
}

static void asid_reset_epoch(void) {
    uint32_t i;
    uint32_t words = (g_asid_limit + 64u) / 64u;

    /*
     * An ASID may be reused only after every stale translation carrying that
     * value has been removed from every CPU.  Retired ASIDs remain set in the
     * bitmap until this epoch boundary.  This matters most for executable
     * mappings: handing a retired ASID directly to a new process can execute
     * instructions from a recycled physical page even though its new PTE is
     * already correct.
     */
    asid_invalidate_all();
    for (i = 0; i < words; ++i) g_asid_bitmap[i] = 0;
    for (i = 0; i < ARM64_ADDRESS_SPACE_MAX; ++i) {
        uint16_t asid;
        if (!g_address_spaces[i].used) continue;
        asid = g_address_spaces[i].asid;
        if (asid)
            g_asid_bitmap[asid >> 6] |= 1ULL << (asid & 63u);
    }
    ++g_asid_epoch;
    if (!g_asid_epoch) g_asid_epoch = 1u;
    g_asid_free_hint = 1u;
}

static uint16_t asid_find_free(void) {
    uint32_t asid;

    if (!g_asid_free_hint || g_asid_free_hint > g_asid_limit) return 0;
    for (asid = g_asid_free_hint; asid <= g_asid_limit; ++asid) {
        uint64_t bit = 1ULL << (asid & 63u);
        uint64_t *word = &g_asid_bitmap[asid >> 6];
        if (*word & bit) continue;
        *word |= bit;
        g_asid_free_hint = asid + 1u;
        return (uint16_t)asid;
    }
    g_asid_free_hint = g_asid_limit + 1u;
    return 0;
}

static uint16_t asid_allocate(void) {
    uint64_t irq_flags;
    uint16_t asid;

    irq_flags = spin_lock_irqsave(&g_asid_lock);
    asid = asid_find_free();
    if (!asid) {
        asid_reset_epoch();
        asid = asid_find_free();
    }
    spin_unlock_irqrestore(&g_asid_lock, irq_flags);
    /* ASID 0 is a correct, globally-flushed fallback on 8-bit hardware. */
    return asid;
}

static void asid_release(uint16_t asid) {
    uint64_t irq_flags;

    if (!asid) return;
    irq_flags = spin_lock_irqsave(&g_asid_lock);
    asid_invalidate(asid);
    /* Keep this ASID quarantined until asid_reset_epoch() invalidates all CPUs. */
    spin_unlock_irqrestore(&g_asid_lock, irq_flags);
}

static uint64_t cache_line_size(void) {
    uint64_t ctr;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    return 4ULL << ((ctr >> 16) & 0xfu);
}

static void cache_clean_range_deferred(uint64_t address, uint64_t length) {
    uint64_t line = cache_line_size();
    uint64_t end = (address + length + line - 1u) & ~(line - 1u);
    address &= ~(line - 1u);
    while (address < end) {
        __asm__ __volatile__("dc cvac, %0" :: "r"(address) : "memory");
        address += line;
    }
}

static void cache_clean_range(uint64_t address, uint64_t length) {
    cache_clean_range_deferred(address, length);
    __asm__ __volatile__("dsb ish" ::: "memory");
}

static uint32_t address_space_hash_bucket(uint64_t ttbr0) {
    uint64_t key = ttbr0 >> 12;
    key ^= key >> 21;
    key *= 0x9e3779b97f4a7c15ULL;
    key ^= key >> 29;
    return (uint32_t)key & ARM64_ADDRESS_SPACE_HASH_MASK;
}

static void address_space_hash_remove(
    const arm64_address_space_record_t *record) {
    uint32_t bucket;
    int32_t *link;

    if (!record || !record->used) return;
    bucket = address_space_hash_bucket(record->ttbr0);
    link = &g_address_space_hash[bucket];
    while (*link >= 0) {
        arm64_address_space_record_t *candidate =
            &g_address_spaces[(uint32_t)*link];
        if (candidate == record) {
            *link = candidate->next_hash;
            candidate->next_hash = -1;
            return;
        }
        link = &candidate->next_hash;
    }
}

static arm64_address_space_record_t *address_space_record(uint64_t ttbr0,
                                                           int create) {
    uint32_t i;
    uint32_t bucket;
    int32_t current;
    arm64_address_space_record_t *free_record = 0;

    if (!g_address_spaces) return 0;
    bucket = address_space_hash_bucket(ttbr0);
    current = g_address_space_hash[bucket];
    while (current >= 0) {
        arm64_address_space_record_t *record =
            &g_address_spaces[(uint32_t)current];
        if (record->used && record->ttbr0 == ttbr0) return record;
        current = record->next_hash;
    }
    if (!create) return 0;
    for (i = 0; i < ARM64_ADDRESS_SPACE_MAX; ++i) {
        if (!g_address_spaces[i].used && !free_record) free_record = &g_address_spaces[i];
    }
    if (!free_record) {
        printf("[arm64-vm] address-space records exhausted limit=%u ttbr0=0x%llx\n",
               ARM64_ADDRESS_SPACE_MAX, (unsigned long long)ttbr0);
        return 0;
    }
    free_record->used = 1;
    free_record->ttbr0 = ttbr0;
    free_record->cgroup_id = 0;
    free_record->asid = asid_allocate();
    free_record->mapping_head = -1;
    free_record->mapping_count = 0;
    free_record->next_hash = g_address_space_hash[bucket];
    g_address_space_hash[bucket] =
        (int32_t)(free_record - g_address_spaces);
    free_record->owned_table_count = 0;
    for (i = 0; i < 3u; ++i) {
        free_record->cached_prefix[i] = 0;
        free_record->cached_table[i] = 0;
        free_record->cached_valid[i] = 0;
    }
    return free_record;
}

static int address_space_own_table(arm64_address_space_record_t *space,
                                   uint64_t *table) {
    if (!space || !table || space->owned_table_count >= ARM64_OWNED_TABLE_MAX)
        return -1;
    space->owned_tables[space->owned_table_count++] =
        (uint64_t)(uintptr_t)table;
    return 0;
}

#define ARM64_OWNED_TABLE_RECLAIM 1ULL

static int address_space_table_empty(const uint64_t *table) {
    if (!table) return 0;
    for (uint32_t index = 0; index < TABLE_ENTRIES; ++index)
        if (table[index] != 0) return 0;
    return 1;
}

static int address_space_mark_table_reclaim(
    arm64_address_space_record_t *space, const uint64_t *table) {
    uint64_t address = (uint64_t)(uintptr_t)table;

    if (!space || !table || address == space->ttbr0) return 0;
    for (uint32_t index = 0; index < space->owned_table_count; ++index) {
        uint64_t owned = space->owned_tables[index];
        if ((owned & ~ARM64_OWNED_TABLE_RECLAIM) != address) continue;
        space->owned_tables[index] =
            address | ARM64_OWNED_TABLE_RECLAIM;
        return 1;
    }
    return 0;
}

static void address_space_reap_marked_tables(
    arm64_address_space_record_t *space) {
    uint32_t destination = 0;
    uint32_t old_count;

    if (!space) return;
    old_count = space->owned_table_count;
    for (uint32_t index = 0; index < old_count; ++index) {
        uint64_t owned = space->owned_tables[index];
        if (owned & ARM64_OWNED_TABLE_RECLAIM) {
            edgeos_arm64_early_free_page(
                (void *)(uintptr_t)(owned & ~ARM64_OWNED_TABLE_RECLAIM));
            continue;
        }
        space->owned_tables[destination++] = owned;
    }
    for (uint32_t index = destination; index < old_count; ++index)
        space->owned_tables[index] = 0;
    space->owned_table_count = (uint16_t)destination;
}

static uint64_t *address_space_alloc_table(arm64_address_space_record_t *space) {
    uint64_t *table = (uint64_t *)edgeos_arm64_early_alloc_page();
    if (!table) {
        if (g_mapping_failure_log_budget) {
            --g_mapping_failure_log_budget;
            printf("[arm64-vm] page-table allocation failed ttbr0=0x%llx "
                   "tables=%u free=%llu\n",
                   (unsigned long long)(space ? space->ttbr0 : 0),
                   space ? space->owned_table_count : 0u,
                   (unsigned long long)edgeos_arm64_memory_free_bytes());
        }
        return 0;
    }
    if (address_space_own_table(space, table) < 0) {
        if (g_table_exhaustion_log_budget) {
            --g_table_exhaustion_log_budget;
            printf("[arm64-vm] page-table ownership exhausted ttbr0=0x%llx tables=%u limit=%u\n",
                   (unsigned long long)(space ? space->ttbr0 : 0),
                   space ? space->owned_table_count : 0u,
                   ARM64_OWNED_TABLE_MAX);
        }
        edgeos_arm64_early_free_page(table);
        return 0;
    }
    return table;
}

static void page_zero(void *page) {
    uint64_t *p = (uint64_t *)page;
    uint32_t i;
    for (i = 0; i < TABLE_ENTRIES; ++i) p[i] = 0;
    cache_clean_range((uint64_t)(uintptr_t)page, PAGE_SIZE);
}

static void page_copy(void *dst, const void *src) {
    uint64_t *d = (uint64_t *)dst;
    const uint64_t *s = (const uint64_t *)src;
    uint32_t i;
    for (i = 0; i < TABLE_ENTRIES; ++i) d[i] = s[i];
    cache_clean_range((uint64_t)(uintptr_t)dst, PAGE_SIZE);
}

static void page_copy_unpublished(void *dst, const void *src) {
    uint64_t *d = (uint64_t *)dst;
    const uint64_t *s = (const uint64_t *)src;
    uint32_t i;
    for (i = 0; i < TABLE_ENTRIES; ++i) d[i] = s[i];
}

static uint16_t address_space_asid(uint64_t ttbr0);

static void descriptor_replace_global(uint64_t ttbr0, uint64_t *entry,
                                      uint64_t value) {
    uint64_t active_ttbr0;
    int switched = 0;

    if (*entry == value) return;
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(active_ttbr0));
    active_ttbr0 &= ARM64_PA_MASK;
    ttbr0 &= ARM64_PA_MASK;
    if (active_ttbr0 == ttbr0 && ttbr0 != g_kernel_ttbr0) {
        /*
         * TTBR0 also provides the kernel's identity aliases.  Clearing an
         * active process's intermediate descriptor can therefore unmap the
         * page-table page being edited, the exception vectors, or the kernel
         * stack before break-before-make completes.  Edit through the
         * permanent kernel root and restore the process ASID afterward.
         */
        edgeos_arm64_address_space_activate(g_kernel_ttbr0);
        switched = 1;
    }
    if (*entry & DESC_VALID) {
        uint16_t asid = address_space_asid(ttbr0);
        *entry = 0;
        /*
         * All TTBR0 identity and user mappings are non-global.  Replacing an
         * intermediate descriptor therefore invalidates only this root's ASID.
         */
        if (asid) asid_invalidate(asid);
        else asid_invalidate_all();
    }
    *entry = value;
    __asm__ __volatile__("dsb ishst" ::: "memory");
    if (switched) edgeos_arm64_address_space_activate(ttbr0);
}

static uint16_t address_space_asid(uint64_t ttbr0) {
    arm64_address_space_record_t *space;
    ttbr0 &= ARM64_PA_MASK;
    if (!ttbr0 || ttbr0 == g_kernel_ttbr0) return 0;
    space = address_space_record(ttbr0, 0);
    return space ? space->asid : 0;
}

static void address_space_flush_active_all(uint64_t ttbr0) {
    uint16_t asid = address_space_asid(ttbr0);

    /* Deferred non-global edits need one broadcast for this address space. */
    if (asid) asid_invalidate(asid);
    else asid_invalidate_all();
}

static void descriptor_replace_page(uint64_t ttbr0, uint64_t *entry,
                                    uint64_t value, uint64_t va) {
    if (*entry == value) return;
    if (*entry & DESC_VALID) {
        uint64_t old = *entry;
        uint64_t operand =
                           ((uint64_t)address_space_asid(ttbr0) <<
                            g_asid_shift) |
                           (va >> 12);
        /*
         * A live valid-to-valid replacement needs break-before-make.  The ASID
         * in the TLBI operand makes this valid even when a different
         * address space is active; stale translations must never survive a
         * later switch back to this process.
         */
        *entry = 0;
        if (old & DESC_NG) {
            __asm__ __volatile__("dsb ishst\n\ttlbi vae1is, %0\n\t"
                                 "tlbi vae1, %0\n\tdsb ish\n\tisb" ::
                                 "r"(operand) : "memory");
        } else {
            /* A legacy global entry cannot be invalidated by VA and ASID. */
            asid_invalidate_all();
        }
        *entry = value;
        __asm__ __volatile__("dsb ishst\n\tisb" ::: "memory");
        return;
    }
    *entry = value;
    __asm__ __volatile__("dsb ishst" ::: "memory");
}

static void mapping_table_reset(void) {
    uint8_t *p = (uint8_t *)g_user_mappings;
    uint64_t i;
    uint64_t mmfr0;
    for (i = 0; i < (uint64_t)ARM64_USER_MAPPING_MAX *
                    sizeof(g_user_mappings[0]); ++i) p[i] = 0;
    for (i = 0; i < ARM64_USER_MAPPING_HASH_BUCKETS; ++i)
        g_user_mapping_hash[i] = -1;
    for (i = 0; i < ARM64_PHYSICAL_MAPPING_HASH_BUCKETS; ++i)
        g_physical_mapping_hash[i] = -1;
    p = (uint8_t *)g_address_spaces;
    for (i = 0; i < (uint64_t)ARM64_ADDRESS_SPACE_MAX *
                    sizeof(g_address_spaces[0]); ++i)
        p[i] = 0;
    for (i = 0; i < ARM64_ADDRESS_SPACE_HASH_BUCKETS; ++i)
        g_address_space_hash[i] = -1;
    p = (uint8_t *)g_asid_bitmap;
    for (i = 0; i < sizeof(g_asid_bitmap); ++i) p[i] = 0;
    __asm__ __volatile__("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    if (((mmfr0 >> 4) & 0xfu) >= 2u) {
        g_asid_limit = 65535u;
        g_asid_shift = 48u;
    } else {
        /* TCR_EL1.AS=0 selects TTBR[63:56], not TTBR[55:48]. */
        g_asid_limit = 255u;
        g_asid_shift = 56u;
    }
    g_asid_free_hint = 1u;
    g_asid_epoch = 1u;
    spinlock_init(&g_asid_lock);
    g_clone_table_hash_busy = 0;
    g_user_mapping_count = 0;
    g_user_mapping_free_hint = 0;
    g_writeprotect_generation = 0;
}

static uint32_t user_mapping_hash_bucket(uint64_t ttbr0, uint64_t va) {
    uint64_t key = (ttbr0 >> 12) ^
                   ((va >> 12) * 0x9e3779b97f4a7c15ULL);
    key ^= key >> 33;
    return (uint32_t)key & ARM64_USER_MAPPING_HASH_MASK;
}

static uint32_t physical_mapping_hash_bucket(uint64_t pa) {
    uint64_t key = pa >> 12;

    key ^= key >> 17;
    key *= 0x9e3779b97f4a7c15ULL;
    key ^= key >> 31;
    return (uint32_t)key & ARM64_PHYSICAL_MAPPING_HASH_MASK;
}

static int physical_mapping_hash_required(uint32_t prot) {
    return (prot & EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY) != 0u;
}

static int mapping_alias_index(uint64_t page, uint32_t *index_out) {
    return edge_page_allocator_contains(
        &g_physical_pages, page, index_out) ? 0 : -1;
}

static int mapping_alias_acquire(const arm64_address_space_record_t *space,
                                 uint64_t page) {
    uint32_t cgroup_id;
    uint32_t oom_cgroup_id = 0;
    uint32_t previous_mappings;
    uint16_t released_owner;
    uint32_t remaining;

    if (!edge_page_allocator_contains(&g_physical_pages, page, 0)) return 0;
    if (!space || space->cgroup_id >= EDGE_PAGE_CGROUP_NONE) return -1;
    cgroup_id = space->cgroup_id;
    if (edge_page_allocator_mapping_acquire(
            &g_physical_pages, page, (uint16_t)cgroup_id,
            &previous_mappings) < 0)
        return -1;
    if (!previous_mappings)
        (void)kernel_mm_prepare_cgroup_charge(cgroup_id, PAGE_SIZE);
    if (!previous_mappings &&
        cgroupfs_memory_charge(cgroup_id, PAGE_SIZE,
                               &oom_cgroup_id) < 0) {
        (void)edge_page_allocator_mapping_release(
            &g_physical_pages, page, &released_owner, &remaining);
        edgeos_arm64_address_space_note_memory_oom(
            space->ttbr0, oom_cgroup_id);
        return -1;
    }
    if (!previous_mappings)
        (void)kernel_mm_reclaim_cgroup_pressure(cgroup_id);
    return 0;
}

static void mapping_alias_release(uint64_t page) {
    uint16_t owner = EDGE_PAGE_CGROUP_NONE;
    uint32_t remaining = 0;

    if (edge_page_allocator_mapping_release(
            &g_physical_pages, page, &owner, &remaining) < 0 || remaining)
        return;
    if (owner != EDGE_PAGE_CGROUP_NONE)
        cgroupfs_memory_uncharge(owner, PAGE_SIZE);
}

int edgeos_arm64_page_cgroup_owner(uint64_t physical,
                                   uint32_t *cgroup_id_out) {
    uint16_t owner;

    if (!cgroup_id_out || edge_page_allocator_mapping_owner(
            &g_physical_pages, physical, &owner) < 0 ||
        owner == EDGE_PAGE_CGROUP_NONE)
        return -1;
    *cgroup_id_out = owner;
    return 0;
}

static arm64_user_mapping_t *user_mapping_find(uint64_t ttbr0, uint64_t va) {
    uint32_t bucket;
    int32_t current;

    if (!g_user_mapping_hash) return 0;
    va &= ~(PAGE_SIZE - 1u);
    bucket = user_mapping_hash_bucket(ttbr0, va);
    current = g_user_mapping_hash[bucket];
    while (current >= 0) {
        arm64_user_mapping_t *mapping = &g_user_mappings[(uint32_t)current];
        if (mapping->used && mapping->ttbr0 == ttbr0 && mapping->va == va)
            return mapping;
        current = mapping->next_hash;
    }
    return 0;
}

static void user_mapping_hash_insert(uint32_t index) {
    arm64_user_mapping_t *mapping = &g_user_mappings[index];
    uint32_t bucket = user_mapping_hash_bucket(mapping->ttbr0, mapping->va);
    mapping->next_hash = g_user_mapping_hash[bucket];
    g_user_mapping_hash[bucket] = (int32_t)index;
}

static void physical_mapping_hash_insert(uint32_t index) {
    arm64_user_mapping_t *mapping = &g_user_mappings[index];
    uint32_t bucket = physical_mapping_hash_bucket(mapping->pa);

    mapping->next_physical_hash = g_physical_mapping_hash[bucket];
    g_physical_mapping_hash[bucket] = (int32_t)index;
}

static void user_mapping_hash_remove(uint32_t index) {
    arm64_user_mapping_t *mapping = &g_user_mappings[index];
    uint32_t bucket = user_mapping_hash_bucket(mapping->ttbr0, mapping->va);
    int32_t *link = &g_user_mapping_hash[bucket];

    while (*link >= 0) {
        arm64_user_mapping_t *candidate =
            &g_user_mappings[(uint32_t)*link];
        if ((uint32_t)*link == index) {
            *link = candidate->next_hash;
            candidate->next_hash = -1;
            return;
        }
        link = &candidate->next_hash;
    }
}

static void physical_mapping_hash_remove(uint32_t index) {
    arm64_user_mapping_t *mapping = &g_user_mappings[index];
    uint32_t bucket = physical_mapping_hash_bucket(mapping->pa);
    int32_t *link = &g_physical_mapping_hash[bucket];

    while (*link >= 0) {
        arm64_user_mapping_t *candidate =
            &g_user_mappings[(uint32_t)*link];
        if ((uint32_t)*link == index) {
            *link = candidate->next_physical_hash;
            candidate->next_physical_hash = -1;
            return;
        }
        link = &candidate->next_physical_hash;
    }
}

static int user_mapping_record_in_space(arm64_address_space_record_t *space,
                                        uint64_t ttbr0, uint64_t va,
                                        uint64_t pa, uint32_t prot,
                                        int replace) {
    arm64_user_mapping_t *existing;
    uint32_t i;
    if (!space) return -1;
    if (replace) {
        existing = user_mapping_find(ttbr0, va);
        if (existing) {
            int same_physical = existing->pa == pa;
            int old_external =
                (existing->prot & EDGEOS_ARM64_VM_PROT_EXTERNAL) != 0u;
            int new_external =
                (prot & EDGEOS_ARM64_VM_PROT_EXTERNAL) != 0u;
            int old_physical_hashed =
                physical_mapping_hash_required(existing->prot);
            int new_physical_hashed =
                physical_mapping_hash_required(prot);

            if (existing->pa != pa) {
                if (!new_external && mapping_alias_acquire(space, pa) < 0)
                    return -1;
                if (old_physical_hashed)
                    physical_mapping_hash_remove(
                        (uint32_t)(existing - g_user_mappings));
                if (!old_external) mapping_alias_release(existing->pa);
                existing->pa = pa;
                if (new_physical_hashed)
                    physical_mapping_hash_insert(
                        (uint32_t)(existing - g_user_mappings));
            } else if (old_physical_hashed != new_physical_hashed) {
                if (old_physical_hashed)
                    physical_mapping_hash_remove(
                        (uint32_t)(existing - g_user_mappings));
                else
                    physical_mapping_hash_insert(
                        (uint32_t)(existing - g_user_mappings));
            }
            if (same_physical && old_external != new_external) {
                if (old_external) {
                    if (mapping_alias_acquire(space, pa) < 0) return -1;
                } else {
                    mapping_alias_release(pa);
                }
            }
            existing->prot = prot;
            return 0;
        }
    }
    for (i = g_user_mapping_free_hint;
         i < g_user_mapping_count && g_user_mappings[i].used; ++i) {}
    if (i == g_user_mapping_count) {
        if (g_user_mapping_count >= ARM64_USER_MAPPING_MAX) {
            if (g_mapping_failure_log_budget) {
                --g_mapping_failure_log_budget;
                printf("[arm64-vm] user-mapping records exhausted limit=%u\n",
                       ARM64_USER_MAPPING_MAX);
            }
            return -1;
        }
        ++g_user_mapping_count;
    }
    g_user_mapping_free_hint = i + 1u;
    g_user_mappings[i].ttbr0 = ttbr0;
    g_user_mappings[i].va = va;
    g_user_mappings[i].pa = pa;
    g_user_mappings[i].prot = prot;
    g_user_mappings[i].used = 1;
    g_user_mappings[i].prev_for_ttbr = -1;
    g_user_mappings[i].next_for_ttbr = space->mapping_head;
    g_user_mappings[i].next_hash = -1;
    g_user_mappings[i].next_physical_hash = -1;
    if (space->mapping_head >= 0)
        g_user_mappings[(uint32_t)space->mapping_head].prev_for_ttbr =
            (int32_t)i;
    space->mapping_head = (int32_t)i;
    ++space->mapping_count;
    user_mapping_hash_insert(i);
    if (physical_mapping_hash_required(prot))
        physical_mapping_hash_insert(i);
    if (!(prot & EDGEOS_ARM64_VM_PROT_EXTERNAL) &&
        mapping_alias_acquire(space, pa) < 0) {
        if (g_mapping_failure_log_budget) {
            --g_mapping_failure_log_budget;
            printf("[arm64-vm] mapping ownership failed ttbr0=0x%llx "
                   "va=0x%llx pa=0x%llx prot=0x%x cgroup=%u\n",
                   (unsigned long long)ttbr0,
                   (unsigned long long)va,
                   (unsigned long long)pa, prot, space->cgroup_id);
        }
        if (physical_mapping_hash_required(prot))
            physical_mapping_hash_remove(i);
        user_mapping_hash_remove(i);
        space->mapping_head = g_user_mappings[i].next_for_ttbr;
        if (space->mapping_head >= 0)
            g_user_mappings[(uint32_t)space->mapping_head].prev_for_ttbr = -1;
        --space->mapping_count;
        g_user_mappings[i].used = 0;
        g_user_mappings[i].prev_for_ttbr = -1;
        g_user_mappings[i].next_for_ttbr = -1;
        g_user_mappings[i].next_hash = -1;
        g_user_mappings[i].next_physical_hash = -1;
        if (i < g_user_mapping_free_hint) g_user_mapping_free_hint = i;
        return -1;
    }
    return 0;
}

static int user_mapping_record(uint64_t ttbr0, uint64_t va, uint64_t pa,
                               uint32_t prot, int replace) {
    return user_mapping_record_in_space(address_space_record(ttbr0, 1),
                                        ttbr0, va, pa, prot, replace);
}

static uint64_t align_up_page(uint64_t v) {
    return (v + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
}

static int physical_page_index(uint64_t page, uint32_t *index_out) {
    return edge_page_allocator_contains(
        &g_physical_pages, page, index_out) ? 0 : -1;
}

static void physical_page_acquire(uint64_t page) {
    (void)edge_page_allocator_retain(&g_physical_pages, page);
}

static void physical_page_recover(uint64_t page) {
    (void)edge_page_allocator_recover(&g_physical_pages, page);
}

static uint32_t physical_page_reference_count(uint64_t page);

static void page_lifecycle_record(uint64_t page, int allocation,
                                  uint64_t caller) {
    arm64_page_lifecycle_t *record =
        &g_page_lifecycle[g_page_lifecycle_cursor++ % ARM64_PAGE_LIFECYCLE_MAX];
    record->page = page;
    record->caller = caller;
    record->allocation = allocation != 0;
}

uint32_t edgeos_arm64_page_lifecycle(uint64_t physical,
                                     uint64_t *last_free_caller,
                                     uint64_t *last_alloc_caller) {
    uint32_t available = g_page_lifecycle_cursor < ARM64_PAGE_LIFECYCLE_MAX ?
                         g_page_lifecycle_cursor : ARM64_PAGE_LIFECYCLE_MAX;
    uint64_t page = physical & ~(PAGE_SIZE - 1u);
    if (last_free_caller) *last_free_caller = 0;
    if (last_alloc_caller) *last_alloc_caller = 0;
    for (uint32_t age = 0; age < available; ++age) {
        arm64_page_lifecycle_t *record = &g_page_lifecycle[
            (g_page_lifecycle_cursor - 1u - age) % ARM64_PAGE_LIFECYCLE_MAX];
        if (record->page != page) continue;
        if (record->allocation) {
            if (last_alloc_caller && !*last_alloc_caller)
                *last_alloc_caller = record->caller;
        } else if (last_free_caller && !*last_free_caller) {
            *last_free_caller = record->caller;
        }
        if ((!last_free_caller || *last_free_caller) &&
            (!last_alloc_caller || *last_alloc_caller)) break;
    }
    return physical_page_reference_count(page);
}

static uint32_t physical_page_reference_count(uint64_t page) {
    return physical_page_index(page, 0) == 0 ?
        edge_page_allocator_references(&g_physical_pages, page) : 1u;
}

int edgeos_arm64_vm_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t off;
    uint64_t selected_start = 0;
    uint64_t selected_end = 0;
    uint64_t managed_start = 0;
    uint64_t managed_end = 0;

    if (!bootinfo || !bootinfo->efi_mmap.map ||
        !bootinfo->efi_mmap.descriptor_size)
        return -1;
    g_identity_map_end = 0;
    g_kernel_image_start = bootinfo->kernel_image.base;
    g_kernel_image_end = bootinfo->kernel_image.size <=
            UINT64_MAX - bootinfo->kernel_image.base ?
        bootinfo->kernel_image.base + bootinfo->kernel_image.size : 0u;
    for (off = 0; off + bootinfo->efi_mmap.descriptor_size <= bootinfo->efi_mmap.size;
         off += bootinfo->efi_mmap.descriptor_size) {
        const efi_memory_descriptor_t *d =
            (const efi_memory_descriptor_t *)(uintptr_t)(bootinfo->efi_mmap.map + off);
        uint64_t start;
        uint64_t end;
        if (d->number_of_pages &&
            d->number_of_pages <=
                (UINT64_MAX - d->physical_start) / PAGE_SIZE) {
            end = d->physical_start + d->number_of_pages * PAGE_SIZE;
            if (end > g_identity_map_end) g_identity_map_end = align_up_page(end);
        }
        if (d->type != EFI_CONVENTIONAL_MEMORY || !d->number_of_pages) continue;
        start = align_up_page(d->physical_start);
        end = d->physical_start + d->number_of_pages * PAGE_SIZE;
        if (end <= start) continue;
        /*
         * TTBR0 still carries the kernel's low identity mapping during early
         * bring-up.  Keep page tables and anonymous user backing pages above
         * the conventional user-image region so a MAP_FIXED request cannot
         * replace the translation metadata's active virtual alias.
         */
        if (end > EARLY_USER_ALIAS_FLOOR && start < EARLY_USER_ALIAS_FLOOR)
            start = EARLY_USER_ALIAS_FLOOR;
        if (end <= start) continue;
        if (!managed_start || start < managed_start) managed_start = start;
        if (end > managed_end) managed_end = end;
        if (!selected_start || end - start > selected_end - selected_start) {
            selected_start = start;
            selected_end = end;
        }
    }
    g_early_start = managed_start;
    g_early_next = selected_start;
    g_early_end = managed_end;
    g_managed_memory_bytes = 0;
    {
        uint64_t physical_page_count =
            (g_early_end - g_early_start) / PAGE_SIZE;
        uint64_t mapping_bytes = align_up_page(
            (uint64_t)ARM64_USER_MAPPING_MAX * sizeof(g_user_mappings[0]));
        uint64_t hash_bytes = align_up_page(
            (uint64_t)ARM64_USER_MAPPING_HASH_BUCKETS *
            sizeof(g_user_mapping_hash[0]));
        uint64_t physical_hash_bytes = align_up_page(
            (uint64_t)ARM64_PHYSICAL_MAPPING_HASH_BUCKETS *
            sizeof(g_physical_mapping_hash[0]));
        uint64_t address_space_bytes = align_up_page(
            (uint64_t)ARM64_ADDRESS_SPACE_MAX *
            sizeof(g_address_spaces[0]));
        uint64_t page_metadata_bytes;
        void *page_metadata;
        uint64_t metadata_region_end;

        if (!selected_start || !physical_page_count ||
            physical_page_count > UINT32_MAX)
            return -1;
        page_metadata_bytes = align_up_page(
            edge_page_allocator_metadata_bytes(physical_page_count));
        if (!g_early_next || mapping_bytes > selected_end - g_early_next ||
            hash_bytes > selected_end - g_early_next - mapping_bytes ||
            physical_hash_bytes >
                selected_end - g_early_next - mapping_bytes - hash_bytes ||
            address_space_bytes >
                selected_end - g_early_next - mapping_bytes - hash_bytes -
                    physical_hash_bytes ||
            page_metadata_bytes >
                selected_end - g_early_next - mapping_bytes - hash_bytes -
                    physical_hash_bytes - address_space_bytes)
            return -1;
        g_user_mappings = (arm64_user_mapping_t *)(uintptr_t)g_early_next;
        g_early_next += mapping_bytes;
        g_user_mapping_hash = (int32_t *)(uintptr_t)g_early_next;
        g_early_next += hash_bytes;
        g_physical_mapping_hash = (int32_t *)(uintptr_t)g_early_next;
        g_early_next += physical_hash_bytes;
        g_address_spaces =
            (arm64_address_space_record_t *)(uintptr_t)g_early_next;
        g_early_next += address_space_bytes;
        page_metadata = (void *)(uintptr_t)g_early_next;
        g_early_next += page_metadata_bytes;
        metadata_region_end = g_early_next;
        if (edge_page_allocator_initialize(
                &g_physical_pages, page_metadata, page_metadata_bytes,
                g_early_start, (uint32_t)physical_page_count,
                (uint32_t)physical_page_count) < 0)
            return -1;

        /*
         * EFI commonly splits RAM around the loaded kernel, initramfs, and
         * firmware allocations. Keep those holes reserved while adding every
         * conventional range to one sparse physical allocator. Selecting only
         * the largest descriptor made a 2 GiB RPi4 appear to have too little
         * memory for the shared desktop runtime pools.
         */
        for (off = 0;
             off + bootinfo->efi_mmap.descriptor_size <=
                 bootinfo->efi_mmap.size;
             off += bootinfo->efi_mmap.descriptor_size) {
            const efi_memory_descriptor_t *d =
                (const efi_memory_descriptor_t *)(uintptr_t)(
                    bootinfo->efi_mmap.map + off);
            uint64_t start;
            uint64_t end;

            if (d->type != EFI_CONVENTIONAL_MEMORY || !d->number_of_pages ||
                d->number_of_pages >
                    (UINT64_MAX - d->physical_start) / PAGE_SIZE)
                continue;
            start = align_up_page(d->physical_start);
            end = d->physical_start + d->number_of_pages * PAGE_SIZE;
            if (end > EARLY_USER_ALIAS_FLOOR &&
                start < EARLY_USER_ALIAS_FLOOR)
                start = EARLY_USER_ALIAS_FLOOR;
            if (end <= start) continue;

            if (start < selected_start && end > selected_start) {
                uint64_t before_end = end < selected_start ? end :
                                      selected_start;
                if (before_end > start &&
                    edge_page_allocator_add_range(
                        &g_physical_pages, start,
                        (uint32_t)((before_end - start) / PAGE_SIZE), 0u) < 0)
                    return -1;
                if (before_end > start)
                    g_managed_memory_bytes += before_end - start;
                start = metadata_region_end > start ? metadata_region_end :
                                                     start;
            } else if (start < metadata_region_end &&
                       end > selected_start) {
                start = metadata_region_end;
            }
            if (end > start &&
                edge_page_allocator_add_range(
                    &g_physical_pages, start,
                    (uint32_t)((end - start) / PAGE_SIZE), 0u) < 0)
                return -1;
            if (end > start) g_managed_memory_bytes += end - start;
        }
    }
    mapping_table_reset();
    g_shared_zero_page =
        (uint64_t)(uintptr_t)edgeos_arm64_early_alloc_page();
    if (!g_shared_zero_page) return -1;
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(g_kernel_ttbr0));
    g_kernel_ttbr0 &= ARM64_PA_MASK;
    return g_early_next && g_kernel_ttbr0 ? 0 : -1;
}

uint64_t edgeos_arm64_memory_total_bytes(void) {
    return g_managed_memory_bytes;
}

uint64_t edgeos_arm64_memory_free_bytes(void) {
    return edge_page_allocator_free_bytes(&g_physical_pages);
}

int edgeos_arm64_page_allocator_snapshot(
    edge_page_allocator_snapshot_t *snapshot) {
    return edge_page_allocator_snapshot(&g_physical_pages, snapshot);
}

void edgeos_arm64_page_allocator_set_reclaim(
    edge_page_reclaim_callback_t reclaim, void *context) {
    edge_page_allocator_set_reclaim(
        &g_physical_pages, reclaim, context);
}

static void *early_alloc_page_internal(int clear) {
    uint64_t page = edge_page_allocator_allocate_local(
        &g_physical_pages, edgeos_arm64_smp_current_cpu(),
        EDGE_PAGE_ZONE_NORMAL);
    if (!page) {
        uint64_t references = 0;
        uint32_t live_pages = edge_page_allocator_referenced_pages(
            &g_physical_pages, &references);
        uint32_t live_spaces = 0;

        for (uint32_t index = 0; index < ARM64_ADDRESS_SPACE_MAX; ++index)
            if (g_address_spaces[index].used) ++live_spaces;
        printf("[arm64-vm] physical OOM start=0x%llx next=0x%llx end=0x%llx live=%u refs=%llu free=%u mappings=%u spaces=%u\n",
               (unsigned long long)g_early_start,
               (unsigned long long)g_early_next,
               (unsigned long long)g_early_end,
               live_pages, (unsigned long long)references,
               g_physical_pages.free_pages, g_user_mapping_count,
               live_spaces);
        return 0;
    }
    if (clear) page_zero((void *)(uintptr_t)page);
    page_lifecycle_record(page, 1,
        (uint64_t)(uintptr_t)__builtin_return_address(0));
    return (void *)(uintptr_t)page;
}

void *edgeos_arm64_early_alloc_page(void) {
    return early_alloc_page_internal(1);
}

static void *early_alloc_pages_internal(uint64_t page_count, int clear) {
    uint64_t base;
    uint64_t bytes;
    uint64_t offset;
    uint64_t *words;

    if (!page_count || page_count > UINT32_MAX ||
        page_count > UINT64_MAX / PAGE_SIZE)
        return 0;
    bytes = page_count * PAGE_SIZE;
    base = edge_page_allocator_allocate(
        &g_physical_pages, (uint32_t)page_count, EDGE_PAGE_ZONE_NORMAL);
    if (!base) {
        printf("[arm64-vm] contiguous allocation failed pages=%llu free=%u\n",
               (unsigned long long)page_count,
               g_physical_pages.free_pages);
        return 0;
    }
    if (clear) {
        words = (uint64_t *)(uintptr_t)base;
        for (offset = 0; offset < bytes / sizeof(words[0]); ++offset)
            words[offset] = 0;
    }
    cache_clean_range(base, bytes);
    return (void *)(uintptr_t)base;
}

void *edgeos_arm64_early_alloc_pages(uint64_t page_count) {
    return early_alloc_pages_internal(page_count, 1);
}

void *edgeos_arm64_early_reserve_pages(uint64_t page_count) {
    return early_alloc_pages_internal(page_count, 0);
}

int edgeos_arm64_early_retain_page(void *page) {
    uint64_t physical = (uint64_t)(uintptr_t)page;
    return edge_page_allocator_retain(&g_physical_pages, physical);
}

int edgeos_arm64_shared_zero_page_acquire(uint64_t *physical_out) {
    if (!physical_out || !g_shared_zero_page ||
        edgeos_arm64_early_retain_page(
            (void *)(uintptr_t)g_shared_zero_page) < 0)
        return -1;
    *physical_out = g_shared_zero_page;
    return 0;
}

static void early_free_page(uint64_t page) {
    if (!page || (page & (PAGE_SIZE - 1u)) ||
        physical_page_index(page, 0) < 0)
        return;
    if (edge_page_allocator_release_local(
            &g_physical_pages, page, edgeos_arm64_smp_current_cpu()) == 1)
        page_lifecycle_record(page, 0,
            (uint64_t)(uintptr_t)__builtin_return_address(0));
}

void edgeos_arm64_early_free_page(void *page) {
    early_free_page((uint64_t)(uintptr_t)page);
}

void edgeos_arm64_address_space_destroy(uint64_t ttbr0) {
    arm64_address_space_record_t *space;
    uint64_t active_ttbr0;
    int32_t current;
    ttbr0 &= ARM64_PA_MASK;
    if (!ttbr0 || ttbr0 == g_kernel_ttbr0) return;

    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(active_ttbr0));
    if ((active_ttbr0 & ARM64_PA_MASK) == ttbr0) {
        /*
         * Linux may reap an exiting task immediately when SIGCHLD is ignored
         * or SA_NOCLDWAIT is set.  That release runs on the exiting task's
         * kernel stack, before the scheduler selects another task.  Reclaiming
         * an active TTBR0 here leaves kernel text, exception vectors, and the
         * stack reachable only through freed translation tables.  A timer IRQ
         * can then take a recursive instruction abort while fetching VBAR_EL1.
         * Switch to the permanent identity-mapped kernel root before any page
         * owned by the dying address space enters the allocator's free pool.
         */
        edgeos_arm64_address_space_activate(g_kernel_ttbr0);
    }
    space = address_space_record(ttbr0, 0);
    if (!space) return;
    /* Invalidate before any backing or table page can enter the free pool. */
    asid_release(space->asid);
    current = space->mapping_head;
    while (current >= 0) {
        arm64_user_mapping_t *mapping = &g_user_mappings[(uint32_t)current];
        int32_t next = mapping->next_for_ttbr;
        if (mapping->used) {
            if (physical_mapping_hash_required(mapping->prot))
                physical_mapping_hash_remove((uint32_t)current);
            user_mapping_hash_remove((uint32_t)current);
            mapping_alias_release(mapping->pa);
            if (!(mapping->prot & EDGEOS_ARM64_VM_PROT_EXTERNAL))
                early_free_page(mapping->pa);
            mapping->used = 0;
            if ((uint32_t)current < g_user_mapping_free_hint)
                g_user_mapping_free_hint = (uint32_t)current;
            mapping->prev_for_ttbr = -1;
            mapping->next_for_ttbr = -1;
            mapping->next_hash = -1;
            mapping->next_physical_hash = -1;
        }
        current = next;
    }
    for (uint32_t table = 0; table < space->owned_table_count; ++table)
        early_free_page(space->owned_tables[table] &
                        ~ARM64_OWNED_TABLE_RECLAIM);
    /*
     * Forked address spaces own their user backing pages, but their table
     * hierarchy can still contain inherited kernel table descriptors.  Table
     * pages need explicit ownership metadata before they can be reclaimed;
     * treating every traversed descriptor as private can recycle a live table.
     */
    address_space_hash_remove(space);
    space->used = 0;
    space->ttbr0 = 0;
    space->cgroup_id = 0;
    space->asid = 0;
    space->mapping_head = -1;
    space->mapping_count = 0;
    space->next_hash = -1;
    space->owned_table_count = 0;
    for (uint32_t level = 0; level < 3u; ++level) {
        space->cached_prefix[level] = 0;
        space->cached_table[level] = 0;
        space->cached_valid[level] = 0;
    }
}

uint64_t edgeos_arm64_kernel_ttbr0(void) {
    return g_kernel_ttbr0;
}

uint32_t edgeos_arm64_address_space_cgroup(uint64_t ttbr0) {
    arm64_address_space_record_t *space =
        address_space_record(ttbr0 & ARM64_PA_MASK, 0);
    return space ? space->cgroup_id : 0;
}

uint64_t edgeos_arm64_address_space_resident_pages(uint64_t ttbr0) {
    arm64_address_space_record_t *space =
        address_space_record(ttbr0 & ARM64_PA_MASK, 0);

    return space ? space->mapping_count : 0u;
}

void edgeos_arm64_address_space_set_cgroup(uint64_t ttbr0,
                                           uint32_t cgroup_id) {
    arm64_address_space_record_t *space =
        address_space_record(ttbr0 & ARM64_PA_MASK, 0);
    if (space) space->cgroup_id = cgroup_id;
}

uint64_t edgeos_arm64_address_space_ttbr_value(uint64_t ttbr0) {
    uint64_t base = ttbr0 & ARM64_PA_MASK;
    return base | ((uint64_t)address_space_asid(base) << g_asid_shift);
}

int edgeos_arm64_address_space_create(uint64_t *ttbr0_out) {
    uint64_t *root;
    uint64_t *private_kernel_l1;
    arm64_address_space_record_t *space;
    uint32_t kernel_l0_index;
    if (!ttbr0_out || !g_kernel_ttbr0) return -1;
    root = (uint64_t *)edgeos_arm64_early_alloc_page();
    if (!root) return -1;
    page_copy(root, (const void *)(uintptr_t)g_kernel_ttbr0);
    *ttbr0_out = (uint64_t)(uintptr_t)root;
    space = address_space_record(*ttbr0_out, 1);
    if (!space || address_space_own_table(space, root) < 0) {
        edgeos_arm64_early_free_page(root);
        if (space) {
            address_space_hash_remove(space);
            asid_release(space->asid);
            space->asid = 0;
            space->ttbr0 = 0;
            space->next_hash = -1;
            space->used = 0;
        }
        return -1;
    }

    /*
     * Keep the L0 entry containing the kernel image private from the moment
     * this root is published.  User executables and the low kernel identity
     * mapping occupy the same 512 GiB L0 region.  Lazily cloning that L1 on a
     * running multithreaded process requires a break-before-make interval in
     * which another CPU can take an exception while the vector mapping is
     * temporarily unreachable.  Pre-cloning the L1 avoids any live L0
     * replacement; lower user-only levels can still be allocated lazily.
     */
    kernel_l0_index =
        (uint32_t)((g_kernel_image_start >> 39) & 0x1ffu);
    if ((root[kernel_l0_index] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) {
        edgeos_arm64_address_space_destroy(*ttbr0_out);
        return -1;
    }
    private_kernel_l1 = address_space_alloc_table(space);
    if (!private_kernel_l1) {
        edgeos_arm64_address_space_destroy(*ttbr0_out);
        return -1;
    }
    page_copy(private_kernel_l1, (const void *)(uintptr_t)
              (root[kernel_l0_index] & ARM64_PA_MASK));
    root[kernel_l0_index] =
        (uint64_t)(uintptr_t)private_kernel_l1 |
        DESC_VALID | DESC_TABLE;
    cache_clean_range((uint64_t)(uintptr_t)&root[kernel_l0_index],
                      sizeof(root[kernel_l0_index]));
    return 0;
}

int edgeos_arm64_address_space_ensure_kernel_image(uint64_t ttbr0) {
    static uint32_t repair_log_budget = 8u;
    uint64_t *kernel_root;
    uint64_t *root;
    uint64_t *kernel_l1;
    uint64_t *l1;
    uint32_t l0_index;
    uint32_t first_l1;
    uint32_t last_l1;
    uint32_t repaired = 0u;

    ttbr0 &= ARM64_PA_MASK;
    if (!ttbr0 || !g_kernel_ttbr0 || ttbr0 == g_kernel_ttbr0 ||
        !g_kernel_image_start || g_kernel_image_end <= g_kernel_image_start)
        return 0;
    if ((g_kernel_image_start >> 39) !=
        ((g_kernel_image_end - 1u) >> 39))
        return -1;
    kernel_root = (uint64_t *)(uintptr_t)g_kernel_ttbr0;
    root = (uint64_t *)(uintptr_t)ttbr0;
    l0_index = (uint32_t)((g_kernel_image_start >> 39) & 0x1ffu);
    if ((kernel_root[l0_index] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE))
        return -1;
    if ((root[l0_index] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) {
        descriptor_replace_global(
            ttbr0, &root[l0_index], kernel_root[l0_index]);
        ++repaired;
    }
    kernel_l1 = (uint64_t *)(uintptr_t)(
        kernel_root[l0_index] & ARM64_PA_MASK);
    for (uint64_t address =
             g_kernel_image_start & ~(L2_BLOCK_SIZE - 1u);
         address < g_kernel_image_end; address += L2_BLOCK_SIZE) {
        uint32_t image_l1 =
            (uint32_t)((address >> 30) & 0x1ffu);
        uint32_t image_l2 =
            (uint32_t)((address >> 21) & 0x1ffu);
        uint64_t *kernel_l2;
        uint64_t expected;

        if ((kernel_l1[image_l1] & (DESC_VALID | DESC_TABLE)) !=
            (DESC_VALID | DESC_TABLE))
            return -1;
        kernel_l2 = (uint64_t *)(uintptr_t)(
            kernel_l1[image_l1] & ARM64_PA_MASK);
        expected = address | DESC_VALID | DESC_AF | DESC_NG |
                   DESC_SH_INNER | DESC_ATTRIDX(0);
        if (kernel_l2[image_l2] == expected) continue;
        descriptor_replace_global(
            g_kernel_ttbr0, &kernel_l2[image_l2], expected);
        ++repaired;
    }
    l1 = (uint64_t *)(uintptr_t)(root[l0_index] & ARM64_PA_MASK);
    first_l1 = (uint32_t)((g_kernel_image_start >> 30) & 0x1ffu);
    last_l1 = (uint32_t)(((g_kernel_image_end - 1u) >> 30) & 0x1ffu);
    for (uint32_t index = first_l1; index <= last_l1; ++index) {
        if (l1[index] == kernel_l1[index]) continue;
        descriptor_replace_global(ttbr0, &l1[index], kernel_l1[index]);
        ++repaired;
    }
    if (repaired && repair_log_budget) {
        --repair_log_budget;
        printf("[arm64-vm] repaired kernel image mapping ttbr0=0x%llx entries=%u\n",
               (unsigned long long)ttbr0, repaired);
    }
    return 0;
}

static int address_space_set_page_prot(uint64_t ttbr0, uint64_t va,
                                       uint32_t prot);
static int address_space_set_page_prot_internal(uint64_t ttbr0, uint64_t va,
                                                uint32_t prot,
                                                int defer_tlb_flush);
static int address_space_map_user_page_internal(uint64_t ttbr0, uint64_t va,
                                                uint64_t pa, uint32_t prot,
                                                int defer_publish,
                                                arm64_address_space_record_t *space);

static int32_t address_space_owned_table_index(
    const arm64_address_space_record_t *space, uint64_t table) {
    uint64_t address = table & ARM64_PA_MASK;

    if (!space || !address) return -1;
    for (uint32_t index = 0; index < space->owned_table_count; ++index) {
        if ((space->owned_tables[index] &
             ~(PAGE_SIZE - 1u)) == address)
            return (int32_t)index;
    }
    return -1;
}

static uint32_t clone_table_hash_bucket(uint64_t table) {
    uint64_t key = (table & ARM64_PA_MASK) >> 12;
    key ^= key >> 17;
    key *= 0x9e3779b97f4a7c15ULL;
    key ^= key >> 31;
    return (uint32_t)key & ARM64_CLONE_TABLE_HASH_MASK;
}

static void clone_table_hash_acquire(void) {
    while (__sync_lock_test_and_set(&g_clone_table_hash_busy, 1u))
        __asm__ __volatile__("yield" ::: "memory");
}

static void clone_table_hash_release(void) {
    __sync_lock_release(&g_clone_table_hash_busy);
}

static int clone_table_hash_build(
    const arm64_address_space_record_t *parent) {
    if (!parent || parent->owned_table_count * 2u >
                       ARM64_CLONE_TABLE_HASH_CAPACITY)
        return -1;
    for (uint32_t slot = 0; slot < ARM64_CLONE_TABLE_HASH_CAPACITY; ++slot)
        g_clone_table_hash[slot] = -1;
    for (uint32_t index = 0; index < parent->owned_table_count; ++index) {
        uint64_t table = parent->owned_tables[index] & ARM64_PA_MASK;
        uint32_t start = clone_table_hash_bucket(table);
        int inserted = 0;
        for (uint32_t probe = 0; probe < ARM64_CLONE_TABLE_HASH_CAPACITY;
             ++probe) {
            uint32_t slot = (start + probe) & ARM64_CLONE_TABLE_HASH_MASK;
            if (g_clone_table_hash[slot] >= 0) continue;
            g_clone_table_hash[slot] = (int32_t)index;
            inserted = 1;
            break;
        }
        if (!inserted) return -1;
    }
    return 0;
}

static int32_t clone_table_hash_lookup(
    const arm64_address_space_record_t *parent, uint64_t table) {
    uint32_t start;
    if (!parent) return -1;
    table &= ARM64_PA_MASK;
    start = clone_table_hash_bucket(table);
    for (uint32_t probe = 0; probe < ARM64_CLONE_TABLE_HASH_CAPACITY;
         ++probe) {
        uint32_t slot = (start + probe) & ARM64_CLONE_TABLE_HASH_MASK;
        int32_t index = g_clone_table_hash[slot];
        if (index < 0) return -1;
        if ((parent->owned_tables[(uint32_t)index] & ARM64_PA_MASK) == table)
            return index;
    }
    return -1;
}

static int address_space_clone_owned_tables(
    const arm64_address_space_record_t *parent,
    arm64_address_space_record_t *child) {
    uint32_t parent_count;

    if (!parent || !child || !parent->owned_table_count ||
        !child->owned_table_count ||
        (parent->owned_tables[0] & ARM64_PA_MASK) != parent->ttbr0 ||
        (child->owned_tables[0] & ARM64_PA_MASK) != child->ttbr0)
        return -1;

    /*
     * address_space_create() gives every new root a private kernel-image L1.
     * A fork replaces the entire unpublished child hierarchy with private
     * copies of the parent's owned tables, so its provisional L1 must leave
     * the ownership list before the one-for-one clone below.
     */
    if (child->owned_table_count != 2u) return -1;
    early_free_page(child->owned_tables[1] & ARM64_PA_MASK);
    child->owned_tables[1] = 0;
    child->owned_table_count = 1u;
    parent_count = parent->owned_table_count;
    page_copy_unpublished((void *)(uintptr_t)child->owned_tables[0],
                          (const void *)(uintptr_t)parent->owned_tables[0]);
    for (uint32_t index = 1; index < parent_count; ++index) {
        uint64_t *copy = (uint64_t *)early_alloc_page_internal(0);
        if (!copy) return -1;
        if (address_space_own_table(child, copy) < 0) {
            edgeos_arm64_early_free_page(copy);
            return -1;
        }
        page_copy_unpublished(copy, (const void *)(uintptr_t)
                              (parent->owned_tables[index] &
                               ~ARM64_OWNED_TABLE_RECLAIM));
    }
    if (child->owned_table_count != parent_count) return -1;

    /*
     * The copied hierarchy still names the parent's private intermediate
     * tables.  Rebase only descriptors that resolve to a parent-owned table;
     * inherited kernel tables and user leaf pages remain shared deliberately.
     * A live data page can never also be an owned page-table page, so the same
     * ownership test is valid at every copied level.  The ownership hash keeps
     * fork proportional to the number of page-table descriptors; a linear
     * search here made browser address-space cloning quadratic in table count.
     */
    clone_table_hash_acquire();
    if (clone_table_hash_build(parent) < 0) {
        clone_table_hash_release();
        return -1;
    }
    for (uint32_t table_index = 0; table_index < parent_count; ++table_index) {
        uint64_t *table = (uint64_t *)(uintptr_t)
            (child->owned_tables[table_index] &
             ~ARM64_OWNED_TABLE_RECLAIM);
        for (uint32_t entry_index = 0; entry_index < TABLE_ENTRIES;
             ++entry_index) {
            uint64_t entry = table[entry_index];
            int32_t owned_index;
            if ((entry & (DESC_VALID | DESC_TABLE)) !=
                (DESC_VALID | DESC_TABLE))
                continue;
            owned_index = clone_table_hash_lookup(
                parent, entry & ARM64_PA_MASK);
            if (owned_index < 0) continue;
            table[entry_index] =
                (entry & ~ARM64_PA_MASK) |
                (child->owned_tables[(uint32_t)owned_index] &
                 ARM64_PA_MASK);
        }
        cache_clean_range_deferred((uint64_t)(uintptr_t)table, PAGE_SIZE);
    }
    clone_table_hash_release();
    __asm__ __volatile__("dsb ish" ::: "memory");
    return 0;
}

int edgeos_arm64_address_space_clone(uint64_t parent_ttbr0, uint64_t *child_ttbr0_out) {
    arm64_address_space_record_t *parent_space;
    arm64_address_space_record_t *child_space;
    uint64_t child_ttbr0;
    int32_t current;
    uint32_t copied = 0;
    int parent_protection_changed = 0;

    if (!parent_ttbr0 || !child_ttbr0_out) return -1;
    parent_space = address_space_record(parent_ttbr0, 0);
    if (!parent_space) {
        printf("[arm64-vm] clone missing parent record ttbr0=0x%llx\n",
               (unsigned long long)parent_ttbr0);
        return -1;
    }
    if (edgeos_arm64_address_space_create(&child_ttbr0) < 0) {
        printf("[arm64-vm] clone could not create child free=%llu\n",
               (unsigned long long)edgeos_arm64_memory_free_bytes());
        return -1;
    }

    /*
     * Protect private writable pages before copying descriptors.  The child
     * then receives the exact same read-only COW leaves while MAP_SHARED and
     * write-notify mappings retain their existing Linux-visible semantics.
     */
    current = parent_space->mapping_head;
    while (current >= 0) {
        arm64_user_mapping_t *mapping = &g_user_mappings[(uint32_t)current];
        int32_t next = mapping->next_for_ttbr;
        uint32_t child_prot;
        if (!mapping->used || mapping->ttbr0 != parent_ttbr0) {
            if (parent_protection_changed)
                address_space_flush_active_all(parent_ttbr0);
            edgeos_arm64_address_space_destroy(child_ttbr0);
            return -1;
        }
        child_prot = mapping->prot;
        /*
         * A private mapping remains private even when its current protection
         * is read-only.  Linux retains VMA ownership separately from the
         * active PTE permissions, so a later mprotect(PROT_WRITE) must still
         * split a page inherited across fork.  This is observable for RELRO:
         * the AArch64 dynamic linker stack guard is read-only at fork and
         * Chromium temporarily makes it writable in each zygote child.
         *
         * Record COW provenance on every ordinary private page now.  The PTE
         * stays read-only until WRITE is requested, while a later permission
         * expansion preserves COW and faults through the normal copy path.
         */
        if (!(child_prot & (EDGEOS_ARM64_VM_PROT_SHARED |
                            EDGEOS_ARM64_VM_PROT_COW |
                            EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY |
                            EDGEOS_ARM64_VM_PROT_DEVICE |
                            EDGEOS_ARM64_VM_PROT_EXTERNAL))) {
            child_prot |= EDGEOS_ARM64_VM_PROT_COW;
            mapping->prot = child_prot;
            if (address_space_set_page_prot_internal(parent_ttbr0,
                    mapping->va, child_prot, 1) < 0) {
                address_space_flush_active_all(parent_ttbr0);
                edgeos_arm64_address_space_destroy(child_ttbr0);
                return -1;
            }
            parent_protection_changed = 1;
        }
        current = next;
    }
    if (parent_protection_changed)
        address_space_flush_active_all(parent_ttbr0);

    child_space = address_space_record(child_ttbr0, 0);
    if (child_space) child_space->cgroup_id = parent_space->cgroup_id;
    if (!child_space ||
        address_space_clone_owned_tables(parent_space, child_space) < 0) {
        printf("[arm64-vm] clone table copy failed parent-tables=%u child-tables=%u free=%llu\n",
               parent_space->owned_table_count,
               child_space ? child_space->owned_table_count : 0u,
               (unsigned long long)edgeos_arm64_memory_free_bytes());
        edgeos_arm64_address_space_destroy(child_ttbr0);
        return -1;
    }

    current = parent_space->mapping_head;
    while (current >= 0) {
        arm64_user_mapping_t *mapping = &g_user_mappings[(uint32_t)current];
        int32_t next = mapping->next_for_ttbr;
        if (!mapping->used || mapping->ttbr0 != parent_ttbr0) {
            edgeos_arm64_address_space_destroy(child_ttbr0);
            return -1;
        }
        if (!(mapping->prot & EDGEOS_ARM64_VM_PROT_EXTERNAL))
            physical_page_acquire(mapping->pa);
        if (user_mapping_record_in_space(child_space, child_ttbr0,
                mapping->va, mapping->pa, mapping->prot, 0) < 0) {
            if (!(mapping->prot & EDGEOS_ARM64_VM_PROT_EXTERNAL))
                early_free_page(mapping->pa);
            printf("[arm64-vm] clone ownership failed after %u pages va=0x%llx tables=%u free=%llu\n",
                   copied, (unsigned long long)mapping->va,
                   child_space->owned_table_count,
                   (unsigned long long)edgeos_arm64_memory_free_bytes());
            edgeos_arm64_address_space_destroy(child_ttbr0);
            return -1;
        }
        ++copied;
        current = next;
    }
    /* The child ASID has never run, so publish the completed hierarchy once. */
    __asm__ __volatile__("dsb ishst" ::: "memory");
    *child_ttbr0_out = child_ttbr0;
    return 0;
}

static uint64_t *clone_table(arm64_address_space_record_t *space,
                             uint64_t entry) {
    uint64_t *copy;
    if ((entry & (DESC_VALID | DESC_TABLE)) != (DESC_VALID | DESC_TABLE)) return 0;
    copy = address_space_alloc_table(space);
    if (!copy) return 0;
    page_copy(copy, (const void *)(uintptr_t)(entry & ~(PAGE_SIZE - 1u)));
    return copy;
}

static uint64_t *split_l2_block(arm64_address_space_record_t *space,
                                uint64_t block) {
    uint64_t *l3;
    uint64_t base;
    uint64_t attrs;
    uint32_t i;
    if ((block & DESC_VALID) == 0 || (block & DESC_TABLE) != 0) return 0;
    l3 = address_space_alloc_table(space);
    if (!l3) return 0;
    base = block & ~(L2_BLOCK_SIZE - 1u);
    attrs = block & ~((1ULL << 48) - 1ULL);
    attrs |= block & 0xfffULL;
    for (i = 0; i < TABLE_ENTRIES; ++i) {
        l3[i] = base + (uint64_t)i * PAGE_SIZE | attrs | DESC_TABLE;
    }
    return l3;
}

static int address_space_map_user_page_internal(uint64_t ttbr0, uint64_t va,
                                                uint64_t pa, uint32_t prot,
                                                int defer_publish,
                                                arm64_address_space_record_t *space) {
    uint64_t *root;
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint32_t l0i;
    uint32_t l1i;
    uint32_t l2i;
    uint32_t l3i;
    uint64_t desc;
    int replacing;

    if ((ttbr0 & (PAGE_SIZE - 1u)) || (va & (PAGE_SIZE - 1u)) ||
        (pa & (PAGE_SIZE - 1u)) || va >= (1ULL << 48)) {
        if (g_mapping_failure_log_budget) {
            --g_mapping_failure_log_budget;
            printf("[arm64-vm] invalid mapping ttbr0=0x%llx va=0x%llx "
                   "pa=0x%llx prot=0x%x\n",
                   (unsigned long long)ttbr0,
                   (unsigned long long)va,
                   (unsigned long long)pa, prot);
        }
        return -1;
    }
    /*
     * External mappings may intentionally replace a userspace slice of the
     * inherited identity map, for example a firmware framebuffer aperture.
     * They are never allocator-owned, regardless of their cache attribute.
     */
    if (!(prot & (EDGEOS_ARM64_VM_PROT_DEVICE |
                  EDGEOS_ARM64_VM_PROT_EXTERNAL)) &&
        va >= EDGEOS_ARM64_USER_LOW_RESERVED_END &&
        va < g_identity_map_end)
        return -1;
    root = (uint64_t *)(uintptr_t)ttbr0;
    if (!space) space = address_space_record(ttbr0, 1);
    else if (space->ttbr0 != ttbr0) return -1;
    if (!space) return -1;
    l0i = (uint32_t)((va >> 39) & 0x1ffu);
    l1i = (uint32_t)((va >> 30) & 0x1ffu);
    l2i = (uint32_t)((va >> 21) & 0x1ffu);
    l3i = (uint32_t)((va >> 12) & 0x1ffu);

    if (space->cached_valid[0] && space->cached_prefix[0] == (va >> 39)) {
        l1 = space->cached_table[0];
    } else if ((root[l0i] & (DESC_VALID | DESC_TABLE)) ==
                   (DESC_VALID | DESC_TABLE) &&
               address_space_owned_table_index(
                   space, root[l0i] & ARM64_PA_MASK) >= 0) {
        l1 = (uint64_t *)(uintptr_t)(root[l0i] & ARM64_PA_MASK);
    } else if ((root[l0i] & (DESC_VALID | DESC_TABLE)) ==
               (DESC_VALID | DESC_TABLE)) {
        l1 = clone_table(space, root[l0i]);
    } else if ((root[l0i] & DESC_VALID) == 0) {
        l1 = address_space_alloc_table(space);
    } else {
        l1 = 0;
    }
    if (!l1) {
        if (g_mapping_failure_log_budget) {
            --g_mapping_failure_log_budget;
            printf("[arm64-vm] L1 mapping table unavailable va=0x%llx\n",
                   (unsigned long long)va);
        }
        return -1;
    }
    space->cached_prefix[0] = va >> 39;
    space->cached_table[0] = l1;
    space->cached_valid[0] = 1;
    if (defer_publish)
        root[l0i] = (uint64_t)(uintptr_t)l1 | DESC_VALID | DESC_TABLE;
    else
        descriptor_replace_global(ttbr0, &root[l0i],
            (uint64_t)(uintptr_t)l1 | DESC_VALID | DESC_TABLE);
    if (space->cached_valid[1] && space->cached_prefix[1] == (va >> 30)) {
        l2 = space->cached_table[1];
    } else if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) ==
                   (DESC_VALID | DESC_TABLE) &&
               address_space_owned_table_index(
                   space, l1[l1i] & ARM64_PA_MASK) >= 0) {
        l2 = (uint64_t *)(uintptr_t)(l1[l1i] & ARM64_PA_MASK);
    } else if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) == (DESC_VALID | DESC_TABLE)) {
        l2 = clone_table(space, l1[l1i]);
    } else if ((l1[l1i] & DESC_VALID) == 0) {
        l2 = address_space_alloc_table(space);
    } else {
        l2 = 0;
    }
    if (!l2) {
        if (g_mapping_failure_log_budget) {
            --g_mapping_failure_log_budget;
            printf("[arm64-vm] L2 mapping table unavailable va=0x%llx\n",
                   (unsigned long long)va);
        }
        return -1;
    }
    space->cached_prefix[1] = va >> 30;
    space->cached_table[1] = l2;
    space->cached_valid[1] = 1;
    if (defer_publish)
        l1[l1i] = (uint64_t)(uintptr_t)l2 | DESC_VALID | DESC_TABLE;
    else
        descriptor_replace_global(ttbr0, &l1[l1i],
            (uint64_t)(uintptr_t)l2 | DESC_VALID | DESC_TABLE);
    if (space->cached_valid[2] && space->cached_prefix[2] == (va >> 21)) {
        l3 = space->cached_table[2];
    } else if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) ==
                   (DESC_VALID | DESC_TABLE) &&
               address_space_owned_table_index(
                   space, l2[l2i] & ARM64_PA_MASK) >= 0) {
        l3 = (uint64_t *)(uintptr_t)(l2[l2i] & ARM64_PA_MASK);
    } else if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) == (DESC_VALID | DESC_TABLE)) {
        l3 = clone_table(space, l2[l2i]);
    } else if (l2[l2i] & DESC_VALID) {
        l3 = split_l2_block(space, l2[l2i]);
    } else {
        l3 = address_space_alloc_table(space);
    }
    if (!l3) {
        if (g_mapping_failure_log_budget) {
            --g_mapping_failure_log_budget;
            printf("[arm64-vm] L3 mapping table unavailable va=0x%llx\n",
                   (unsigned long long)va);
        }
        return -1;
    }
    space->cached_prefix[2] = va >> 21;
    space->cached_table[2] = l3;
    space->cached_valid[2] = 1;
    if (defer_publish)
        l2[l2i] = (uint64_t)(uintptr_t)l3 | DESC_VALID | DESC_TABLE;
    else
        descriptor_replace_global(ttbr0, &l2[l2i],
            (uint64_t)(uintptr_t)l3 | DESC_VALID | DESC_TABLE);

    if (prot & EDGEOS_ARM64_VM_PROT_POISON) {
        if (l3[l3i] != 0) return -2;
        l3[l3i] = DESC_EDGEOS_POISON;
        if (!defer_publish)
            __asm__ __volatile__("dsb ishst" ::: "memory");
        return 0;
    }

    replacing = (l3[l3i] & (DESC_VALID | DESC_TABLE)) ==
                (DESC_VALID | DESC_TABLE);
    desc = pa | DESC_VALID | DESC_TABLE | DESC_AF | DESC_NG | DESC_PXN;
    if (prot & EDGEOS_ARM64_VM_PROT_DEVICE)
        desc |= DESC_SH_OUTER | DESC_ATTRIDX(1);
    else if (prot & EDGEOS_ARM64_VM_PROT_NOCACHE)
        desc |= DESC_SH_INNER | DESC_ATTRIDX(2);
    else
        desc |= DESC_SH_INNER | DESC_ATTRIDX(0);
    if ((prot & EDGEOS_ARM64_VM_PROT_WRITE) &&
        !(prot & (EDGEOS_ARM64_VM_PROT_COW |
                  EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY))) {
        desc |= DESC_AP_EL0_RW;
    } else if (prot & (EDGEOS_ARM64_VM_PROT_READ |
                       EDGEOS_ARM64_VM_PROT_WRITE)) {
        desc |= DESC_AP_EL0_RO;
    }
    if (prot & EDGEOS_ARM64_VM_PROT_COW) desc |= DESC_EDGEOS_COW;
    if ((prot & EDGEOS_ARM64_VM_PROT_EXEC) == 0) desc |= DESC_UXN;
    {
        uint64_t old_desc = l3[l3i];
        int record_result;
        /*
         * Adding a translation to an invalid PTE cannot leave a stale TLB
         * entry.  A break-before-make TLBI is required only when replacing an
         * existing valid translation.  Firefox and other large dynamically
         * linked programs fault in thousands of executable pages; globally
         * invalidating for every new PTE turns ordinary demand paging into a
         * dominant launch cost.
         */
        if (defer_publish || !replacing) l3[l3i] = desc;
        else descriptor_replace_page(ttbr0, &l3[l3i], desc, va);
        record_result = user_mapping_record_in_space(
            space, ttbr0, va, pa, prot, replacing);
        if (record_result < 0) {
            if (g_mapping_failure_log_budget) {
                --g_mapping_failure_log_budget;
                printf("[arm64-vm] mapping record failed ttbr0=0x%llx "
                       "va=0x%llx pa=0x%llx prot=0x%x replacing=%d\n",
                       (unsigned long long)ttbr0,
                       (unsigned long long)va,
                       (unsigned long long)pa, prot, replacing);
            }
            if (defer_publish || !replacing) l3[l3i] = old_desc;
            else descriptor_replace_page(ttbr0, &l3[l3i], old_desc, va);
            return -1;
        }
        if (!defer_publish && !replacing)
            __asm__ __volatile__("dsb ishst" ::: "memory");
    }
    return 0;
}

int edgeos_arm64_address_space_map_user_page(uint64_t ttbr0, uint64_t va,
                                             uint64_t pa, uint32_t prot) {
    return address_space_map_user_page_internal(ttbr0, va, pa, prot, 0, 0);
}

int edgeos_arm64_address_space_poison_user_page(uint64_t ttbr0, uint64_t va) {
    return address_space_map_user_page_internal(
        ttbr0, va, 0, EDGEOS_ARM64_VM_PROT_POISON, 0, 0);
}

int edgeos_arm64_address_space_user_page_poisoned(uint64_t ttbr0,
                                                   uint64_t va) {
    uint64_t *root;
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint32_t l0i;
    uint32_t l1i;
    uint32_t l2i;
    uint32_t l3i;

    if (!edgeos_arm64_address_space_is_live(ttbr0) ||
        va >= (1ULL << 48))
        return -1;
    root = (uint64_t *)(uintptr_t)ttbr0;
    l0i = (uint32_t)((va >> 39) & 0x1ffu);
    l1i = (uint32_t)((va >> 30) & 0x1ffu);
    l2i = (uint32_t)((va >> 21) & 0x1ffu);
    l3i = (uint32_t)((va >> 12) & 0x1ffu);
    if ((root[l0i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE))
        return 0;
    l1 = (uint64_t *)(uintptr_t)(root[l0i] & ARM64_PA_MASK);
    if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE))
        return 0;
    l2 = (uint64_t *)(uintptr_t)(l1[l1i] & ARM64_PA_MASK);
    if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE))
        return 0;
    l3 = (uint64_t *)(uintptr_t)(l2[l2i] & ARM64_PA_MASK);
    return l3[l3i] == DESC_EDGEOS_POISON ? 1 : 0;
}

int edgeos_arm64_address_space_map_user_pages(uint64_t ttbr0, uint64_t va,
                                              const uint64_t *physical_pages,
                                              uint32_t page_count,
                                              uint32_t prot,
                                              uint32_t *mapped_count) {
    arm64_address_space_record_t *space;
    uint32_t mapped = 0;

    if (mapped_count) *mapped_count = 0;
    if (!physical_pages || !page_count ||
        va > UINT64_MAX - (uint64_t)page_count * PAGE_SIZE)
        return -1;
    space = address_space_record(ttbr0, 1);
    if (!space) return -1;
    while (mapped < page_count) {
        if (address_space_map_user_page_internal(
                ttbr0, va + (uint64_t)mapped * PAGE_SIZE,
                physical_pages[mapped], prot, 1, space) < 0) {
            if (mapped) __asm__ __volatile__("dsb ishst" ::: "memory");
            if (mapped_count) *mapped_count = mapped;
            return -1;
        }
        ++mapped;
    }
    /* All translations were invalid before this batch, so one publish suffices. */
    __asm__ __volatile__("dsb ishst" ::: "memory");
    if (mapped_count) *mapped_count = mapped;
    return 0;
}

static int address_space_set_page_prot_internal(uint64_t ttbr0, uint64_t va,
                                                uint32_t prot,
                                                int defer_tlb_flush) {
    arm64_user_mapping_t *mapping = user_mapping_find(ttbr0, va);
    uint64_t *root = (uint64_t *)(uintptr_t)ttbr0;
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint64_t desc;
    uint32_t l0i = (uint32_t)((va >> 39) & 0x1ffu);
    uint32_t l1i = (uint32_t)((va >> 30) & 0x1ffu);
    uint32_t l2i = (uint32_t)((va >> 21) & 0x1ffu);
    uint32_t l3i = (uint32_t)((va >> 12) & 0x1ffu);

    if ((root[l0i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    l1 = (uint64_t *)(uintptr_t)(root[l0i] & ARM64_PA_MASK);
    if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    l2 = (uint64_t *)(uintptr_t)(l1[l1i] & ARM64_PA_MASK);
    if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    l3 = (uint64_t *)(uintptr_t)(l2[l2i] & ARM64_PA_MASK);
    desc = l3[l3i];
    if ((desc & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    if (mapping) {
        /*
         * mprotect changes access permissions, not VMA ownership or memory
         * type.  Dropping SHARED here makes the next fork install COW on a
         * Linux MAP_SHARED page; dropping cache/device attributes creates
         * incompatible aliases to the same physical memory on AArch64.
         */
        prot |= mapping->prot &
            (EDGEOS_ARM64_VM_PROT_SHARED |
             EDGEOS_ARM64_VM_PROT_DEVICE |
             EDGEOS_ARM64_VM_PROT_NOCACHE |
             EDGEOS_ARM64_VM_PROT_EXTERNAL |
             EDGEOS_ARM64_VM_PROT_COW);
        if ((mapping->prot & EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY) &&
            (prot & EDGEOS_ARM64_VM_PROT_WRITE))
            prot |= EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY;
    }
    desc &= ~(DESC_AP_MASK | DESC_UXN | DESC_PXN | DESC_EDGEOS_COW);
    desc |= DESC_PXN;
    if ((prot & EDGEOS_ARM64_VM_PROT_WRITE) &&
        !(prot & (EDGEOS_ARM64_VM_PROT_COW |
                  EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY))) {
        desc |= DESC_AP_EL0_RW;
    } else if (prot & (EDGEOS_ARM64_VM_PROT_READ |
                       EDGEOS_ARM64_VM_PROT_WRITE)) {
        desc |= DESC_AP_EL0_RO;
    }
    if (prot & EDGEOS_ARM64_VM_PROT_COW) desc |= DESC_EDGEOS_COW;
    if ((prot & EDGEOS_ARM64_VM_PROT_EXEC) == 0) desc |= DESC_UXN;
    if (defer_tlb_flush) l3[l3i] = desc;
    else descriptor_replace_page(ttbr0, &l3[l3i], desc, va);
    return 0;
}

static int address_space_set_page_prot(uint64_t ttbr0, uint64_t va,
                                       uint32_t prot) {
    return address_space_set_page_prot_internal(ttbr0, va, prot, 0);
}

int edgeos_arm64_address_space_protect_user_range(uint64_t ttbr0, uint64_t va,
                                                   uint64_t length, uint32_t prot) {
    uint64_t end;
    uint64_t page;
    int changed = 0;

    if (!ttbr0 || (ttbr0 & (PAGE_SIZE - 1u)) || (va & (PAGE_SIZE - 1u)) || !length) return -1;
    end = align_up_page(va + length);
    if (end < va || end > (1ULL << 48)) return -1;
    for (page = va; page < end; page += PAGE_SIZE) {
        uint64_t desc;
        arm64_user_mapping_t *mapping = user_mapping_find(ttbr0, page);
        uint32_t page_prot = prot;
        if (mapping)
            page_prot |= mapping->prot &
                (EDGEOS_ARM64_VM_PROT_SHARED |
                 EDGEOS_ARM64_VM_PROT_DEVICE |
                 EDGEOS_ARM64_VM_PROT_NOCACHE |
                 EDGEOS_ARM64_VM_PROT_EXTERNAL |
                 EDGEOS_ARM64_VM_PROT_COW |
                 EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY);
        if (address_space_set_page_prot_internal(
                ttbr0, page, page_prot, 1) < 0 ||
            edgeos_arm64_address_space_translate(ttbr0, page, 0, &desc) < 0) {
            if (changed) address_space_flush_active_all(ttbr0);
            return -1;
        }
        changed = 1;
        {
            if (((desc >> 2) & 7u) == 1u) page_prot |= EDGEOS_ARM64_VM_PROT_DEVICE;
            if (((desc >> 2) & 7u) == 2u) page_prot |= EDGEOS_ARM64_VM_PROT_NOCACHE;
            if (user_mapping_record(ttbr0, page, desc & ARM64_PA_MASK,
                                    page_prot, 1) < 0) {
                address_space_flush_active_all(ttbr0);
                return -1;
            }
        }
    }
    if (changed) address_space_flush_active_all(ttbr0);
    return 0;
}

int edgeos_arm64_address_space_protect_user_resident_range(
    uint64_t ttbr0, uint64_t va, uint64_t length, uint32_t prot) {
    arm64_address_space_record_t *space;
    uint64_t end;
    int32_t current;
    int changed = 0;

    if (!ttbr0 || (ttbr0 & (PAGE_SIZE - 1u)) ||
        (va & (PAGE_SIZE - 1u)) || !length)
        return -1;
    end = align_up_page(va + length);
    if (end <= va || end > (1ULL << 48)) return -1;
    space = address_space_record(ttbr0, 0);
    if (!space) return 0;
    if ((end - va) / PAGE_SIZE <= (uint64_t)space->mapping_count) {
        for (uint64_t page = va; page < end; page += PAGE_SIZE) {
            arm64_user_mapping_t *mapping = user_mapping_find(ttbr0, page);
            uint32_t page_prot;
            if (!mapping) continue;
            page_prot = prot | (mapping->prot &
                (EDGEOS_ARM64_VM_PROT_SHARED |
                 EDGEOS_ARM64_VM_PROT_DEVICE |
                 EDGEOS_ARM64_VM_PROT_NOCACHE |
                 EDGEOS_ARM64_VM_PROT_EXTERNAL |
                 EDGEOS_ARM64_VM_PROT_COW |
                 EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY));
            if (address_space_set_page_prot_internal(
                    ttbr0, mapping->va, page_prot, 1) < 0) {
                if (changed) address_space_flush_active_all(ttbr0);
                return -1;
            }
            mapping->prot = page_prot;
            changed = 1;
        }
    } else {
        current = space->mapping_head;
        while (current >= 0) {
            arm64_user_mapping_t *mapping =
                &g_user_mappings[(uint32_t)current];
            int32_t next = mapping->next_for_ttbr;
            if (mapping->used && mapping->va >= va && mapping->va < end) {
                uint32_t page_prot = prot | (mapping->prot &
                    (EDGEOS_ARM64_VM_PROT_SHARED |
                     EDGEOS_ARM64_VM_PROT_DEVICE |
                     EDGEOS_ARM64_VM_PROT_NOCACHE |
                     EDGEOS_ARM64_VM_PROT_EXTERNAL |
                     EDGEOS_ARM64_VM_PROT_COW |
                     EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY));
                if (address_space_set_page_prot_internal(
                        ttbr0, mapping->va, page_prot, 1) < 0) {
                    if (changed) address_space_flush_active_all(ttbr0);
                    return -1;
                }
                mapping->prot = page_prot;
                changed = 1;
            }
            current = next;
        }
    }
    if (changed) address_space_flush_active_all(ttbr0);
    return 0;
}

int edgeos_arm64_address_space_user_range_mapped(uint64_t ttbr0, uint64_t va,
                                                  uint64_t length) {
    return edgeos_arm64_address_space_user_overlap_end(ttbr0, va, length) != 0;
}

uint64_t edgeos_arm64_address_space_user_overlap_end(uint64_t ttbr0,
                                                      uint64_t va,
                                                      uint64_t length) {
    static const uint8_t level_shifts[] = {39u, 30u, 21u, 12u};
    typedef struct {
        const uint64_t *table;
        uint64_t base;
        uint64_t start;
        uint64_t end;
        uint16_t index;
        uint16_t last;
        uint8_t level;
    } page_table_cursor_t;
    page_table_cursor_t cursors[4];
    uint64_t end;
    uint64_t overlap_end = 0;
    uint32_t depth = 0;

    if (!ttbr0 || (ttbr0 & (PAGE_SIZE - 1u)) || !length ||
        va + length < va || va >= (1ULL << 48) ||
        va + length > (1ULL << 48))
        return 0;
    end = va + length;

    /*
     * mmap placement queries are much more frequent than resident-map
     * mutations.  Walking the ownership list here made every query O(RSS),
     * and a dynamic linker with thousands of pages became quadratic.  The
     * translation hierarchy is the authoritative resident-map index: absent
     * L0/L1/L2 entries skip 512 GiB, 1 GiB, or 2 MiB respectively, while
     * block and page descriptors report their complete occupied interval.
     * Architecture-independent demand mappings are checked separately before
     * this hook, including ranges which have not faulted in a PTE yet.
     */
    cursors[0].table = (const uint64_t *)(uintptr_t)ttbr0;
    cursors[0].base = 0;
    cursors[0].start = va;
    cursors[0].end = end;
    cursors[0].level = 0;
    cursors[0].index = (uint16_t)(va >> level_shifts[0]);
    cursors[0].last = (uint16_t)((end - 1u) >> level_shifts[0]);

    for (;;) {
        page_table_cursor_t *cursor = &cursors[depth];
        uint64_t entry;
        uint64_t entry_base;
        uint64_t entry_end;
        uint64_t span;

        if (cursor->index > cursor->last) {
            if (!depth) break;
            --depth;
            ++cursors[depth].index;
            continue;
        }
        span = 1ULL << level_shifts[cursor->level];
        entry_base = cursor->base + (uint64_t)cursor->index * span;
        entry_end = entry_base + span;
        entry = cursor->table[cursor->index];
        if (!(entry & DESC_VALID)) {
            ++cursor->index;
            continue;
        }
        if (cursor->level == 3u || !(entry & DESC_TABLE)) {
            if (entry_end > overlap_end) overlap_end = entry_end;
            ++cursor->index;
            continue;
        }

        ++depth;
        cursor = &cursors[depth];
        cursor->table = (const uint64_t *)(uintptr_t)(entry & ARM64_PA_MASK);
        cursor->base = entry_base;
        cursor->start = cursors[depth - 1u].start > entry_base ?
                        cursors[depth - 1u].start : entry_base;
        cursor->end = cursors[depth - 1u].end < entry_end ?
                      cursors[depth - 1u].end : entry_end;
        cursor->level = (uint8_t)depth;
        cursor->index = (uint16_t)((cursor->start - cursor->base) >>
                                  level_shifts[cursor->level]);
        cursor->last = (uint16_t)((cursor->end - 1u - cursor->base) >>
                                 level_shifts[cursor->level]);
    }
    return overlap_end;
}

static int address_space_detach_mapping(
    arm64_address_space_record_t *space, arm64_user_mapping_t *mapping,
    int32_t *release_head) {
    uint64_t *root;
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint32_t l0i;
    uint32_t l1i;
    uint32_t l2i;
    uint32_t l3i;
    int32_t index;
    int32_t next;

    if (!space || !mapping || !mapping->used || !release_head) return -1;
    root = (uint64_t *)(uintptr_t)space->ttbr0;
    l0i = (uint32_t)((mapping->va >> 39) & 0x1ffu);
    l1i = (uint32_t)((mapping->va >> 30) & 0x1ffu);
    l2i = (uint32_t)((mapping->va >> 21) & 0x1ffu);
    l3i = (uint32_t)((mapping->va >> 12) & 0x1ffu);
    if ((root[l0i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    l1 = (uint64_t *)(uintptr_t)(root[l0i] & ARM64_PA_MASK);
    if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    l2 = (uint64_t *)(uintptr_t)(l1[l1i] & ARM64_PA_MASK);
    if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    l3 = (uint64_t *)(uintptr_t)(l2[l2i] & ARM64_PA_MASK);
    if ((l3[l3i] & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;

    index = (int32_t)(mapping - g_user_mappings);
    next = mapping->next_for_ttbr;
    l3[l3i] = 0;
    if (physical_mapping_hash_required(mapping->prot))
        physical_mapping_hash_remove((uint32_t)index);
    user_mapping_hash_remove((uint32_t)index);
    if (mapping->prev_for_ttbr >= 0)
        g_user_mappings[(uint32_t)mapping->prev_for_ttbr].next_for_ttbr = next;
    else
        space->mapping_head = next;
    if (next >= 0)
        g_user_mappings[(uint32_t)next].prev_for_ttbr =
            mapping->prev_for_ttbr;
    if (space->mapping_count) --space->mapping_count;
    mapping->used = 2;
    mapping->prev_for_ttbr = -1;
    mapping->next_for_ttbr = *release_head;
    mapping->next_hash = -1;
    mapping->next_physical_hash = -1;
    *release_head = index;
    return 0;
}

static int address_space_clear_poison_level(
    arm64_address_space_record_t *space, uint64_t *table,
    uint32_t level, uint64_t table_base, uint64_t start, uint64_t end) {
    static const uint32_t level_shift[4] = { 39u, 30u, 21u, 12u };
    uint32_t shift;
    uint32_t first;
    uint32_t last;
    int changed = 0;

    if (!space || !table || level >= 4u || end <= start ||
        start < table_base)
        return 0;
    shift = level_shift[level];
    first = (uint32_t)((start - table_base) >> shift);
    last = (uint32_t)(((end - 1u) - table_base) >> shift);
    if (first >= TABLE_ENTRIES) return 0;
    if (last >= TABLE_ENTRIES) last = TABLE_ENTRIES - 1u;

    for (uint32_t index = first; index <= last; ++index) {
        uint64_t entry_base = table_base + ((uint64_t)index << shift);
        uint64_t entry_end = entry_base + (1ULL << shift);
        uint64_t overlap_start = start > entry_base ? start : entry_base;
        uint64_t overlap_end = end < entry_end ? end : entry_end;

        if (level == 3u) {
            if (table[index] == DESC_EDGEOS_POISON) {
                table[index] = 0;
                changed = 1;
            }
            continue;
        }
        if ((table[index] & (DESC_VALID | DESC_TABLE)) !=
            (DESC_VALID | DESC_TABLE))
            continue;
        {
            uint64_t *child = (uint64_t *)(uintptr_t)
                (table[index] & ARM64_PA_MASK);
            int child_changed = address_space_clear_poison_level(
                space, child, level + 1u, entry_base,
                overlap_start, overlap_end);
            if (!child_changed) continue;
            changed = 1;
            if (address_space_table_empty(child) &&
                address_space_mark_table_reclaim(space, child))
                table[index] = 0;
        }
    }
    return changed;
}

int edgeos_arm64_address_space_unmap_user_range(uint64_t ttbr0, uint64_t va,
                                                 uint64_t length) {
    arm64_address_space_record_t *space;
    uint64_t end;
    int32_t release_head = -1;
    if (!ttbr0 || (va & (PAGE_SIZE - 1u)) || !length) return -1;
    end = align_up_page(va + length);
    if (end <= va || end > (1ULL << 48)) return -1;
    space = address_space_record(ttbr0, 0);
    if (!space) return 0;
    (void)address_space_clear_poison_level(
        space, (uint64_t *)(uintptr_t)ttbr0, 0, 0, va, end);

    /*
     * Dynamic loaders reserve large sparse ranges but normally unmap only a
     * few populated pages when unloading one DSO.  Walking every resident
     * mapping for each small munmap makes plug-in discovery quadratic.  Use
     * the (TTBR0, VA) hash for small ranges and retain one list walk for a
     * range wider than the live mapping set.
     */
    if ((end - va) / PAGE_SIZE <= (uint64_t)space->mapping_count) {
        for (uint64_t page = va; page < end; page += PAGE_SIZE) {
            arm64_user_mapping_t *mapping = user_mapping_find(ttbr0, page);
            if (mapping &&
                address_space_detach_mapping(
                    space, mapping, &release_head) < 0)
                return -1;
        }
    } else {
        int32_t current = space->mapping_head;
        while (current >= 0) {
            arm64_user_mapping_t *mapping =
                &g_user_mappings[(uint32_t)current];
            int32_t next = mapping->next_for_ttbr;
            if (mapping->used && mapping->va >= va && mapping->va < end &&
                address_space_detach_mapping(
                    space, mapping, &release_head) < 0)
                return -1;
            current = next;
        }
    }

    /*
     * Sparse desktop workloads repeatedly reserve and discard large virtual
     * ranges.  Reclaim empty translation levels along with their PTEs so an
     * address space is bounded by its live mappings instead of its lifetime
     * mmap history.  A table inherited from the kernel hierarchy is never
     * reclaimed unless this address space owns a private clone of it.
     */
    for (int32_t current = release_head; current >= 0;) {
        arm64_user_mapping_t *mapping =
            &g_user_mappings[(uint32_t)current];
        uint64_t *root = (uint64_t *)(uintptr_t)ttbr0;
        uint32_t l0i = (uint32_t)((mapping->va >> 39) & 0x1ffu);
        uint32_t l1i = (uint32_t)((mapping->va >> 30) & 0x1ffu);
        uint32_t l2i = (uint32_t)((mapping->va >> 21) & 0x1ffu);
        uint64_t *l1;
        uint64_t *l2;
        uint64_t *l3;

        current = mapping->next_for_ttbr;
        if ((root[l0i] & (DESC_VALID | DESC_TABLE)) !=
            (DESC_VALID | DESC_TABLE))
            continue;
        l1 = (uint64_t *)(uintptr_t)(root[l0i] & ARM64_PA_MASK);
        if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) !=
            (DESC_VALID | DESC_TABLE))
            continue;
        l2 = (uint64_t *)(uintptr_t)(l1[l1i] & ARM64_PA_MASK);
        if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) !=
            (DESC_VALID | DESC_TABLE))
            continue;
        l3 = (uint64_t *)(uintptr_t)(l2[l2i] & ARM64_PA_MASK);

        if (!address_space_table_empty(l3) ||
            !address_space_mark_table_reclaim(space, l3))
            continue;
        l2[l2i] = 0;
        if (!address_space_table_empty(l2) ||
            !address_space_mark_table_reclaim(space, l2))
            continue;
        l1[l1i] = 0;
        if (!address_space_table_empty(l1) ||
            !address_space_mark_table_reclaim(space, l1))
            continue;
        root[l0i] = 0;
    }

    for (uint32_t level = 0; level < 3u; ++level) {
        space->cached_prefix[level] = 0;
        space->cached_table[level] = 0;
        space->cached_valid[level] = 0;
    }
    /* Invalidate stale translations before any backing or table page reuse. */
    address_space_flush_active_all(ttbr0);
    while (release_head >= 0) {
        arm64_user_mapping_t *mapping =
            &g_user_mappings[(uint32_t)release_head];
        int32_t next = mapping->next_for_ttbr;
        uint32_t index = (uint32_t)release_head;

        mapping_alias_release(mapping->pa);
        if (!(mapping->prot & EDGEOS_ARM64_VM_PROT_EXTERNAL))
            early_free_page(mapping->pa);
        mapping->used = 0;
        mapping->prev_for_ttbr = -1;
        mapping->next_for_ttbr = -1;
        mapping->next_hash = -1;
        mapping->next_physical_hash = -1;
        if (index < g_user_mapping_free_hint)
            g_user_mapping_free_hint = index;
        release_head = next;
    }
    address_space_reap_marked_tables(space);
    return 0;
}

int edgeos_arm64_address_space_unmap_user_page_if_physical(
    uint64_t ttbr0, uint64_t va, uint64_t physical) {
    arm64_user_mapping_t *mapping;

    if (!ttbr0 || (va & (PAGE_SIZE - 1u)) ||
        (physical & (PAGE_SIZE - 1u)))
        return -1;
    mapping = user_mapping_find(ttbr0, va);
    if (!mapping || mapping->pa != physical) return 0;
    return edgeos_arm64_address_space_unmap_user_range(
               ttbr0, va, PAGE_SIZE) < 0 ? -1 : 1;
}

int edgeos_arm64_address_space_translate(uint64_t ttbr0, uint64_t va,
                                         uint64_t *pa_out, uint64_t *desc_out) {
    uint64_t *root;
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint64_t desc;
    uint32_t l0i;
    uint32_t l1i;
    uint32_t l2i;
    uint32_t l3i;

    if (!edgeos_arm64_address_space_is_live(ttbr0) ||
        va >= (1ULL << 48))
        return -1;
    root = (uint64_t *)(uintptr_t)ttbr0;
    l0i = (uint32_t)((va >> 39) & 0x1ffu);
    l1i = (uint32_t)((va >> 30) & 0x1ffu);
    l2i = (uint32_t)((va >> 21) & 0x1ffu);
    l3i = (uint32_t)((va >> 12) & 0x1ffu);
    if ((root[l0i] & (DESC_VALID | DESC_TABLE)) != (DESC_VALID | DESC_TABLE)) return -1;
    l1 = (uint64_t *)(uintptr_t)(root[l0i] & ~(PAGE_SIZE - 1u));
    if ((l1[l1i] & (DESC_VALID | DESC_TABLE)) != (DESC_VALID | DESC_TABLE)) return -1;
    l2 = (uint64_t *)(uintptr_t)(l1[l1i] & ~(PAGE_SIZE - 1u));
    if ((l2[l2i] & (DESC_VALID | DESC_TABLE)) != (DESC_VALID | DESC_TABLE)) return -1;
    l3 = (uint64_t *)(uintptr_t)(l2[l2i] & ~(PAGE_SIZE - 1u));
    desc = l3[l3i];
    if ((desc & (DESC_VALID | DESC_TABLE)) != (DESC_VALID | DESC_TABLE)) return -1;
    /* Upper descriptor bits carry UXN/PXN and other attributes, not PA bits. */
    if (pa_out) *pa_out = (desc & ARM64_PA_MASK) | (va & (PAGE_SIZE - 1u));
    if (desc_out) *desc_out = desc;
    return 0;
}

int edgeos_arm64_address_space_is_live(uint64_t ttbr0) {
    if (!ttbr0 || ttbr0 != (ttbr0 & ARM64_PA_MASK) ||
        (ttbr0 & (PAGE_SIZE - 1u)))
        return 0;
    return address_space_record(ttbr0, 0) != 0;
}

int edgeos_arm64_address_space_handle_cow(uint64_t ttbr0, uint64_t va) {
    arm64_address_space_record_t *space;
    arm64_user_mapping_t *mapping;
    uint64_t page = va & ~(PAGE_SIZE - 1u);
    uint32_t prot;

    space = address_space_record(ttbr0, 0);
    if (!space) return 0;
    mapping = user_mapping_find(ttbr0, page);
    if (!mapping) {
        uint64_t physical;
        uint64_t descriptor;
        uint32_t recovered_prot;
        if (edgeos_arm64_address_space_translate(ttbr0, page, &physical,
                                                  &descriptor) == 0 &&
            (descriptor & DESC_EDGEOS_COW)) {
            recovered_prot = EDGEOS_ARM64_VM_PROT_READ |
                             EDGEOS_ARM64_VM_PROT_WRITE |
                             EDGEOS_ARM64_VM_PROT_COW;
            if (!(descriptor & DESC_UXN))
                recovered_prot |= EDGEOS_ARM64_VM_PROT_EXEC;
            if (((descriptor >> 2) & 7u) == 1u)
                recovered_prot |= EDGEOS_ARM64_VM_PROT_DEVICE;
            if (((descriptor >> 2) & 7u) == 2u)
                recovered_prot |= EDGEOS_ARM64_VM_PROT_NOCACHE;
            /*
             * Missing ownership metadata also means the software reference
             * count cannot prove exclusivity.  Take a conservative reference
             * so resolution always copies instead of making a potentially
             * shared page writable in place.
             */
            physical_page_recover(physical & ARM64_PA_MASK);
            if (user_mapping_record(ttbr0, page,
                    physical & ARM64_PA_MASK, recovered_prot, 0) < 0)
                return -1;
            mapping = user_mapping_find(ttbr0, page);
        }
    }
    if (!mapping || !(mapping->prot & EDGEOS_ARM64_VM_PROT_COW) ||
        !(mapping->prot & EDGEOS_ARM64_VM_PROT_WRITE))
        return 0;

    prot = mapping->prot & ~EDGEOS_ARM64_VM_PROT_COW;
    {
        uint64_t old_page = mapping->pa;
        uint32_t old_references = physical_page_reference_count(old_page);
        if (old_references == 1u) {
            /*
             * The final owner can drop COW in place.  Taking a synthetic
             * reference and copying here leaks the original page: replacing
             * the mapping transfers no ownership, and the later release only
             * cancels the synthetic reference.  Fork/exec-heavy desktop
             * workloads then exhaust physical memory despite having very few
             * live address spaces.
             */
            mapping->prot = prot;
            if (address_space_set_page_prot(ttbr0, page, prot) < 0) {
                mapping->prot |= EDGEOS_ARM64_VM_PROT_COW;
                return -1;
            }
            return 1;
        }
        /* page_copy initializes every byte; clearing first doubles COW traffic. */
        void *new_page = early_alloc_page_internal(0);
        if (!new_page) {
            printf("[arm64-vm] COW allocation failed va=0x%llx refs=%u\n",
                   (unsigned long long)page,
                   physical_page_reference_count(mapping->pa));
            return -1;
        }
        /* Publish dirty EL0 cache lines before reading through the identity alias. */
        cache_clean_range(page, PAGE_SIZE);
        page_copy(new_page, (const void *)(uintptr_t)old_page);
        if (edgeos_arm64_address_space_map_user_page(ttbr0, page,
                (uint64_t)(uintptr_t)new_page, prot) < 0) {
            printf("[arm64-vm] COW remap failed ttbr=0x%llx va=0x%llx prot=0x%x\n",
                   (unsigned long long)ttbr0,
                   (unsigned long long)page, prot);
            early_free_page((uint64_t)(uintptr_t)new_page);
            return -1;
        }
        early_free_page(old_page);
    }
    return 1;
}

int edgeos_arm64_address_space_handle_write_notify(uint64_t ttbr0,
                                                    uint64_t va,
                                                    uint64_t *pa_out) {
    arm64_user_mapping_t *mapping = user_mapping_find(ttbr0, va);
    uint64_t page = va & ~(PAGE_SIZE - 1u);
    uint64_t *root;
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint64_t desc;

    if (!mapping || !(mapping->prot & EDGEOS_ARM64_VM_PROT_WRITE) ||
        !(mapping->prot & EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY))
        return 0;
    root = (uint64_t *)(uintptr_t)ttbr0;
    l1 = (uint64_t *)(uintptr_t)(root[(page >> 39) & 0x1ffu] & ARM64_PA_MASK);
    if (!l1) return -1;
    l2 = (uint64_t *)(uintptr_t)(l1[(page >> 30) & 0x1ffu] & ARM64_PA_MASK);
    if (!l2) return -1;
    l3 = (uint64_t *)(uintptr_t)(l2[(page >> 21) & 0x1ffu] & ARM64_PA_MASK);
    if (!l3) return -1;
    desc = l3[(page >> 12) & 0x1ffu];
    if ((desc & (DESC_VALID | DESC_TABLE)) !=
        (DESC_VALID | DESC_TABLE)) return -1;
    if ((desc & DESC_AP_MASK) != DESC_AP_EL0_RW) {
        desc = (desc & ~DESC_AP_MASK) | DESC_AP_EL0_RW;
        descriptor_replace_page(ttbr0, &l3[(page >> 12) & 0x1ffu],
                                desc, page);
    }
    if (pa_out) *pa_out = mapping->pa;
    return 1;
}

int edgeos_arm64_address_space_user_protection(uint64_t ttbr0, uint64_t va,
                                               uint32_t *prot_out) {
    arm64_user_mapping_t *mapping;

    if (!prot_out) return -1;
    mapping = user_mapping_find(ttbr0, va);
    if (!mapping) return -1;
    *prot_out = mapping->prot;
    return 0;
}

int edgeos_arm64_address_space_retry_user_page(uint64_t ttbr0, uint64_t va) {
    uint64_t operand;
    uint16_t asid;

    va &= ~(PAGE_SIZE - 1u);
    if (edgeos_arm64_address_space_translate(ttbr0, va, 0, 0) < 0)
        return 0;
    asid = address_space_asid(ttbr0);
    if (!asid) {
        asid_invalidate_all();
        return 1;
    }
    operand = ((uint64_t)asid << g_asid_shift) | (va >> 12);
    /*
     * Fault-around can publish an adjacent page after the processor has
     * already remembered an earlier failed walk for that page.  Retry only
     * the software-present page instead of flushing the complete address
     * space on every successful demand-page batch.
     */
    __asm__ __volatile__("dsb ishst\n\ttlbi vae1is, %0\n\t"
                         "tlbi vae1, %0\n\tdsb ish\n\tisb" ::
                         "r"(operand) : "memory");
    return 1;
}

int edgeos_arm64_address_space_retry_user_access(uint64_t ttbr0, uint64_t va,
                                                 uint32_t access) {
    uint64_t descriptor;

    if (edgeos_arm64_address_space_translate(
            ttbr0, va, 0, &descriptor) < 0)
        return 0;
    if ((access & EDGEOS_ARM64_VM_PROT_WRITE) &&
        (descriptor & DESC_AP_MASK) != DESC_AP_EL0_RW)
        return 0;
    if ((access & EDGEOS_ARM64_VM_PROT_READ) &&
        (descriptor & DESC_AP_MASK) != DESC_AP_EL0_RW &&
        (descriptor & DESC_AP_MASK) != DESC_AP_EL0_RO)
        return 0;
    if ((access & EDGEOS_ARM64_VM_PROT_EXEC) &&
        (descriptor & DESC_UXN))
        return 0;
    return edgeos_arm64_address_space_retry_user_page(ttbr0, va);
}

uint32_t edgeos_arm64_address_space_writeprotect_physical_aliases(
    uint64_t physical_start, uint64_t length) {
    uint64_t physical_end;
    uint64_t page;
    uint32_t protected_pages = 0;
    uint32_t generation;

    if (!g_physical_mapping_hash || !length ||
        physical_start > UINT64_MAX - length)
        return 0;
    physical_end = physical_start + length;
    generation = ++g_writeprotect_generation;
    if (!generation) {
        for (uint32_t index = 0; index < ARM64_ADDRESS_SPACE_MAX; ++index)
            g_address_spaces[index].writeprotect_generation = 0;
        generation = ++g_writeprotect_generation;
    }

    /*
     * Framebuffer presentation re-arms only mappings which alias the submitted
     * physical pages.  Walking every resident page in every process made this
     * operation grow with the complete desktop and browser working set.  The
     * physical-page index keeps deferred display work proportional to actual
     * scanout damage while retaining write notification for every alias.
     */
    page = physical_start & ~(PAGE_SIZE - 1u);
    while (page < physical_end) {
        uint32_t bucket = physical_mapping_hash_bucket(page);
        int32_t current = g_physical_mapping_hash[bucket];

        while (current >= 0) {
            arm64_user_mapping_t *mapping =
                &g_user_mappings[(uint32_t)current];
            int32_t next = mapping->next_physical_hash;
            arm64_address_space_record_t *space = 0;

            if (mapping->used)
                space = address_space_record(mapping->ttbr0, 0);
            if (space &&
                (mapping->prot & EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY) &&
                mapping->pa + PAGE_SIZE > physical_start &&
                mapping->pa < physical_end &&
                address_space_set_page_prot_internal(
                    space->ttbr0, mapping->va,
                    mapping->prot | EDGEOS_ARM64_VM_PROT_WRITE_NOTIFY, 1) == 0) {
                space->writeprotect_generation = generation;
                ++protected_pages;
            }
            current = next;
        }
        if (page > UINT64_MAX - PAGE_SIZE) break;
        page += PAGE_SIZE;
    }
    for (uint32_t index = 0; index < ARM64_ADDRESS_SPACE_MAX; ++index) {
        arm64_address_space_record_t *space = &g_address_spaces[index];

        if (space->used && space->writeprotect_generation == generation)
            address_space_flush_active_all(space->ttbr0);
    }
    return protected_pages;
}

int edgeos_arm64_address_space_discard_private_page(uint64_t ttbr0,
                                                     uint64_t va) {
    arm64_address_space_record_t *space;
    arm64_user_mapping_t *mapping = 0;
    uint64_t page = va & ~(PAGE_SIZE - 1u);
    uint64_t old_page;
    uint32_t prot;
    int32_t current;
    void *zero_page;

    space = address_space_record(ttbr0, 0);
    if (!space) return -1;
    current = space->mapping_head;
    while (current >= 0) {
        arm64_user_mapping_t *candidate = &g_user_mappings[(uint32_t)current];
        if (candidate->used && candidate->va == page) {
            mapping = candidate;
            break;
        }
        current = candidate->next_for_ttbr;
    }
    if (!mapping) return -1;
    if (mapping->prot & (EDGEOS_ARM64_VM_PROT_SHARED |
                         EDGEOS_ARM64_VM_PROT_DEVICE |
                         EDGEOS_ARM64_VM_PROT_EXTERNAL)) return 0;

    old_page = mapping->pa;
    prot = mapping->prot & ~EDGEOS_ARM64_VM_PROT_COW;
    zero_page = edgeos_arm64_early_alloc_page();
    if (!zero_page) return -1;
    if (edgeos_arm64_address_space_map_user_page(ttbr0, page,
            (uint64_t)(uintptr_t)zero_page, prot) < 0) {
        early_free_page((uint64_t)(uintptr_t)zero_page);
        return -1;
    }
    early_free_page(old_page);
    return 0;
}

int edgeos_arm64_copy_from_user(uint64_t ttbr0, void *dst, uint64_t src,
                                uint64_t length) {
    uint8_t *out = (uint8_t *)dst;
    uint64_t saved_ttbr0;
    int result = 0;
    if ((!dst && length) || !src) return -1;
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(saved_ttbr0));
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0)
        edgeos_arm64_address_space_activate(ttbr0);
    while (length) {
        uint64_t available;
        uint64_t count;
        uint8_t *in;
        uint64_t desc;
        if (edgeos_arm64_address_space_translate(ttbr0, src, 0, &desc) < 0 ||
            (desc & DESC_AP_MASK) == 0) {
            result = -1;
            break;
        }
        available = PAGE_SIZE - (src & (PAGE_SIZE - 1u));
        count = length < available ? length : available;
        in = (uint8_t *)(uintptr_t)src;
        while (count--) *out++ = *in++;
        src += available < length ? available : length;
        length -= available < length ? available : length;
    }
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0)
        edgeos_arm64_address_space_activate(saved_ttbr0 & ARM64_PA_MASK);
    return result;
}

int edgeos_arm64_copy_to_user(uint64_t ttbr0, uint64_t dst, const void *src,
                              uint64_t length) {
    const uint8_t *in = (const uint8_t *)src;
    uint64_t saved_ttbr0;
    int result = 0;
    if ((!src && length) || !dst) return -1;
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(saved_ttbr0));
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0)
        edgeos_arm64_address_space_activate(ttbr0);
    while (length) {
        uint64_t desc;
        uint64_t available;
        uint64_t count;
        uint64_t copied;
        uint8_t *out;
        if (edgeos_arm64_address_space_translate(ttbr0, dst, 0, &desc) < 0) {
            result = -1;
            break;
        }
        if ((desc & DESC_AP_MASK) != DESC_AP_EL0_RW) {
            if (!(desc & DESC_EDGEOS_COW) ||
                edgeos_arm64_address_space_handle_cow(ttbr0, dst) <= 0 ||
                edgeos_arm64_address_space_translate(ttbr0, dst,
                                                      0, &desc) < 0 ||
                (desc & DESC_AP_MASK) != DESC_AP_EL0_RW) {
                result = -1;
                break;
            }
        }
        available = PAGE_SIZE - (dst & (PAGE_SIZE - 1u));
        count = length < available ? length : available;
        copied = count;
        out = (uint8_t *)(uintptr_t)dst;
        while (count--) *out++ = *in++;
        dst += copied;
        length -= copied;
    }
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0)
        edgeos_arm64_address_space_activate(saved_ttbr0 & ARM64_PA_MASK);
    return result;
}

int edgeos_arm64_compare_exchange_user_u32(uint64_t ttbr0, uint64_t address,
                                           uint32_t *expected,
                                           uint32_t desired) {
    volatile uint32_t *word;
    uint64_t saved_ttbr0;
    uint64_t desc;
    uint32_t observed;
    int exchanged;

    if (!ttbr0 || !address || !expected || (address & 3u) != 0u ||
        !edgeos_arm64_address_space_is_live(ttbr0))
        return -1;
    if (edgeos_arm64_address_space_translate(ttbr0, address, 0, &desc) < 0)
        return -1;
    if ((desc & DESC_AP_MASK) != DESC_AP_EL0_RW) {
        if (!(desc & DESC_EDGEOS_COW) ||
            edgeos_arm64_address_space_handle_cow(ttbr0, address) <= 0 ||
            edgeos_arm64_address_space_translate(
                ttbr0, address, 0, &desc) < 0 ||
            (desc & DESC_AP_MASK) != DESC_AP_EL0_RW)
            return -1;
    }

    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(saved_ttbr0));
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0)
        edgeos_arm64_address_space_activate(ttbr0);
    word = (volatile uint32_t *)(uintptr_t)address;
    observed = *expected;
    exchanged = __atomic_compare_exchange_n(
        word, &observed, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0)
        edgeos_arm64_address_space_activate(saved_ttbr0 & ARM64_PA_MASK);
    *expected = observed;
    return exchanged ? 0 : 1;
}

void edgeos_arm64_address_space_activate(uint64_t ttbr0) {
    uint64_t current;
    uint64_t encoded;
    uint16_t asid;

    ttbr0 &= ARM64_PA_MASK;
    if (!ttbr0) return;
    encoded = edgeos_arm64_address_space_ttbr_value(ttbr0);
    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(current));
    if (current == encoded) return;
    asid = address_space_asid(ttbr0);
    if (!asid) {
        /* ASID 0 is shared by the kernel root and the exhaustion fallback. */
        __asm__ __volatile__("dsb ish\n\tmsr ttbr0_el1, %0\n\tisb\n\ttlbi vmalle1is\n\tdsb ish\n\tisb" ::
                             "r"(encoded) : "memory");
        return;
    }
    /* Page-table publication already performs the required store barrier. */
    __asm__ __volatile__("msr ttbr0_el1, %0\n\tisb" ::
                         "r"(encoded) : "memory");
}

int edgeos_arm64_address_space_sync_user_exec_range(uint64_t ttbr0,
                                                     uint64_t virtual_address,
                                                     uint64_t length) {
    uint64_t end;
    uint64_t line;
    uint64_t saved_ttbr0;
    int switched = 0;

    ttbr0 &= ARM64_PA_MASK;
    if (!ttbr0 || !length || virtual_address > UINT64_MAX - length)
        return -1;
    end = virtual_address + length;
    for (uint64_t page = virtual_address & ~(PAGE_SIZE - 1u);
         page < end; page += PAGE_SIZE) {
        if (edgeos_arm64_address_space_translate(ttbr0, page, 0, 0) < 0)
            return -1;
    }

    __asm__ __volatile__("mrs %0, ttbr0_el1" : "=r"(saved_ttbr0));
    if ((saved_ttbr0 & ARM64_PA_MASK) != ttbr0) {
        edgeos_arm64_address_space_activate(ttbr0);
        switched = 1;
    }
    line = cache_line_size();
    for (uint64_t cursor = virtual_address & ~(line - 1u);
         cursor < end; cursor += line)
        __asm__ __volatile__("dc cvau, %0" :: "r"(cursor) : "memory");
    __asm__ __volatile__("dsb ish\n\tic ialluis\n\tic iallu\n\tdsb ish\n\tisb" :::
                         "memory");
    if (switched)
        edgeos_arm64_address_space_activate(saved_ttbr0 & ARM64_PA_MASK);
    return 0;
}

uint32_t edgeos_arm64_address_space_clean_physical_aliases(
    uint64_t physical_start, uint64_t length) {
    if (!length || physical_start > UINT64_MAX - length) return 0;

    /*
     * User pages and the kernel direct map are normal cacheable aliases of the
     * same physical memory.  AArch64 cache maintenance by VA translates the
     * operand and selects the physical cache line, so one valid direct-map VA
     * cleans data written through every userspace alias.  Walking all user
     * mappings and switching TTBR0 for every 4 KiB page was both unnecessary
     * and quadratic in the resident desktop working set.
     */
    cache_clean_range(physical_start, length);
    return edgeos_arm64_address_space_count_physical_aliases(physical_start,
                                                              length);
}

uint32_t edgeos_arm64_address_space_count_physical_aliases(
    uint64_t physical_start, uint64_t length) {
    uint64_t physical_end;
    uint32_t aliases = 0;

    if (!length || physical_start > UINT64_MAX - length) return 0;
    physical_end = physical_start + length;
    if (!(physical_start & (PAGE_SIZE - 1u)) &&
        physical_start >= g_early_start && physical_end <= g_early_end) {
        uint64_t total = 0;
        for (uint64_t page = physical_start; page < physical_end;
             page += PAGE_SIZE) {
            uint32_t index;
            if (mapping_alias_index(page, &index) < 0) break;
            (void)index;
            total += edge_page_allocator_mappings(
                &g_physical_pages, page);
            if (total >= UINT32_MAX) return UINT32_MAX;
        }
        return (uint32_t)total;
    }
    for (uint32_t index = 0; index < g_user_mapping_count; ++index) {
        const arm64_user_mapping_t *mapping = &g_user_mappings[index];
        if (!mapping->used || mapping->pa + PAGE_SIZE <= physical_start ||
            mapping->pa >= physical_end)
            continue;
        ++aliases;
    }
    return aliases;
}
