/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral memory-management runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_MM_RUNTIME_H
#define EDGEOS_KERNEL_MM_RUNTIME_H

#include <stdint.h>

#define KERNEL_PROCESS_MADVISE_VALIDATE_ONLY 0x0001u
#define KERNEL_MM_USER_PAGE_SIZE             4096u
#define KERNEL_MM_LOCK_RANGE_ONFAULT         0x0001u
#define KERNEL_MM_LOCK_ALL_CURRENT           0x0001u
#define KERNEL_MM_LOCK_ALL_FUTURE            0x0002u
#define KERNEL_MM_LOCK_ALL_ONFAULT           0x0004u
#define KERNEL_MM_SYNC_ASYNC                 0x0001u
#define KERNEL_MM_SYNC_INVALIDATE            0x0002u
#define KERNEL_MM_SYNC_SYNC                  0x0004u
#define KERNEL_MM_PROT_READ                  0x00000001u
#define KERNEL_MM_PROT_WRITE                 0x00000002u
#define KERNEL_MM_PROT_EXEC                  0x00000004u
#define KERNEL_MM_PROT_SEM                   0x00000008u
#define KERNEL_MM_PROT_GROWSDOWN             0x01000000u
#define KERNEL_MM_PROT_GROWSUP               0x02000000u
#define KERNEL_MM_REMAP_MAYMOVE              0x00000001u
#define KERNEL_MM_REMAP_FIXED                0x00000002u
#define KERNEL_MM_REMAP_DONTUNMAP            0x00000004u
#define KERNEL_MM_MAP_SHARED                 0x00000001u
#define KERNEL_MM_MAP_PRIVATE                0x00000002u
#define KERNEL_MM_MAP_SHARED_VALIDATE        0x00000003u
#define KERNEL_MM_MAP_TYPE_MASK              0x0000000fu
#define KERNEL_MM_MAP_FIXED                  0x00000010u
#define KERNEL_MM_MAP_ANONYMOUS              0x00000020u
#define KERNEL_MM_MAP_LOCKED                 0x00002000u
#define KERNEL_MM_MAP_NONBLOCK               0x00010000u
#define KERNEL_MM_MAP_FIXED_NOREPLACE        0x00100000u
#define KERNEL_MM_MAP_SECRET                 0x80000000u
#define KERNEL_MM_VMA_INITIAL_AREAS           128u
#define KERNEL_MM_VMA_MAX                     65530u
#define KERNEL_MM_VMA_FORK_WIPE               0x01u

/*
 * Linux-visible mapping policy is shared even though page-table formats are
 * architecture-specific.  Keep the durable VMA description independent from
 * x86_64 and AArch64 task frames so CLONE_VM threads can reference one mm
 * object instead of carrying private copies of the complete mapping table.
 */
typedef struct kernel_vm_area {
    uint64_t start;
    uint64_t end;
    uint64_t file_off;
    uint64_t file_len;
    uint32_t prot;
    uint32_t flags;
    uint32_t file_ino;
    uint32_t file_generation;
    uint32_t file_size;
    uint32_t file_fs_private[4];
    void *file_sb;
    uint16_t file_slot;
    uint16_t file_mode;
    uint16_t file_uid;
    uint16_t file_gid;
    uint8_t file_backed;
    uint8_t file_have_inode;
    uint8_t fork_policy;
    uint8_t padding[5];
} kernel_vm_area_t;

typedef struct kernel_mm_map_request {
    uint64_t address;
    uint64_t length;
    uint64_t protection;
    uint64_t flags;
    int32_t descriptor;
    uint32_t reserved;
    uint64_t offset;
} kernel_mm_map_request_t;

typedef struct kernel_mm_file_mapping_info {
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    uint64_t backing_identity;
    uint64_t object_identity;
    uint32_t protection;
    uint32_t attributes;
    uint8_t shared;
    uint8_t reserved[7];
} kernel_mm_file_mapping_info_t;

typedef struct kernel_process_vm_scratch {
    void *buffer;
    uint32_t capacity;
} kernel_process_vm_scratch_t;

typedef struct kernel_mm_program_break_state {
    uint64_t base;
    uint64_t current;
    uint64_t maximum;
} kernel_mm_program_break_state_t;

typedef struct kernel_mm_reclaim_candidate {
    uint64_t last_used_sequence;
    uint32_t references;
    uint32_t slot;
    uint8_t used;
    uint8_t busy;
    uint8_t pinned;
    uint8_t active;
    uint8_t reserved[4];
} kernel_mm_reclaim_candidate_t;

typedef struct kernel_mm_cache_state {
    uint64_t last_used_sequence;
    uint32_t access_count;
    uint8_t referenced;
    uint8_t active;
    uint8_t reserved[2];
} kernel_mm_cache_state_t;

typedef struct kernel_mm_locked_range {
    uint64_t start;
    uint64_t end;
} kernel_mm_locked_range_t;

typedef struct kernel_mm_mempolicy_range {
    uint64_t start;
    uint64_t end;
    uint64_t nodes;
    int32_t mode;
    uint32_t flags;
    uint32_t home_node;
    uint32_t reserved;
} kernel_mm_mempolicy_range_t;

typedef struct kernel_mm_lock_space {
    uint64_t address_space;
    uint64_t peak_resident_bytes;
    uint64_t mempolicy_nodes;
    int32_t mempolicy_mode;
    uint32_t mempolicy_flags;
    kernel_mm_locked_range_t *ranges;
    uint32_t range_count;
    uint32_t range_capacity;
    uint32_t range_pages;
    uint32_t future_flags;
    kernel_mm_mempolicy_range_t *policy_ranges;
    uint32_t policy_range_count;
    uint32_t policy_range_capacity;
    uint32_t policy_range_pages;
    uint32_t policy_reserved;
} kernel_mm_lock_space_t;

typedef struct kernel_mm_seal_space {
    uint64_t address_space;
    kernel_mm_locked_range_t *ranges;
    uint32_t range_count;
    uint32_t range_capacity;
    uint32_t range_pages;
    uint32_t reserved;
} kernel_mm_seal_space_t;

typedef enum kernel_madvise_operation {
    KERNEL_MADVISE_NOOP = 0,
    KERNEL_MADVISE_DISCARD,
    KERNEL_MADVISE_POPULATE_READ,
    KERNEL_MADVISE_POPULATE_WRITE,
    KERNEL_MADVISE_SET_WIPE_ON_FORK,
    KERNEL_MADVISE_CLEAR_WIPE_ON_FORK,
    KERNEL_MADVISE_LAZY_FREE,
    KERNEL_MADVISE_DEACTIVATE,
    KERNEL_MADVISE_PAGEOUT,
} kernel_madvise_operation_t;

typedef enum kernel_mm_process_vm_operation {
    KERNEL_MM_PROCESS_VM_READ = 0,
    KERNEL_MM_PROCESS_VM_WRITE,
} kernel_mm_process_vm_operation_t;

int kernel_mm_madvise_known(uint32_t advice);
int kernel_mm_madvise_cross_process_allowed(uint32_t advice);
int kernel_process_madvise(int32_t pid, uint64_t address, uint64_t length,
                           uint32_t advice, uint32_t flags);
int kernel_process_mrelease(int32_t pid);
int kernel_process_vm_current_scratch(kernel_process_vm_scratch_t *scratch);
int kernel_process_vm_read_memory(int32_t pid, uint64_t address,
                                  void *buffer, uint64_t size);
int kernel_process_vm_write_memory(int32_t pid, uint64_t address,
                                   const void *buffer, uint64_t size);
int kernel_mm_query_residency(uint64_t address, uint32_t page_count,
                              uint8_t *vector);
int kernel_mm_lock_range(uint64_t address, uint64_t length, uint32_t flags);
int kernel_mm_unlock_range(uint64_t address, uint64_t length);
int kernel_mm_lock_all(uint32_t flags);
int kernel_mm_unlock_all(void);
int kernel_mm_sync_range(uint64_t address, uint64_t length, uint32_t flags);
int64_t kernel_mm_protect_range(uint64_t address, uint64_t length,
                                uint64_t protection);
int64_t kernel_mm_map(const kernel_mm_map_request_t *request);
int64_t kernel_mm_unmap_range(uint64_t address, uint64_t length);
int64_t kernel_mm_remap_range(uint64_t old_address, uint64_t old_length,
                              uint64_t new_length, uint64_t flags,
                              uint64_t new_address);
int64_t kernel_mm_remap_file_pages(uint64_t address, uint64_t length,
                                   uint64_t protection,
                                   uint64_t page_offset, uint64_t flags);
int64_t kernel_mm_program_break(uint64_t address);
int64_t kernel_mm_seal_range(uint64_t address, uint64_t length,
                             uint64_t flags);
int64_t kernel_mm_pkey_allocate(uint32_t access_rights);
int kernel_mm_pkey_free(int32_t protection_key);
int64_t kernel_mm_pkey_mprotect(uint64_t address, uint64_t length,
                                uint64_t protection,
                                int32_t protection_key);

uint64_t kernel_mm_vma_pool_bytes(uint32_t address_spaces,
                                  uint32_t areas_per_space);
int kernel_mm_vma_pool_initialize(void *memory, uint64_t size,
                                  uint32_t address_spaces,
                                  uint32_t areas_per_space);
kernel_vm_area_t *kernel_mm_vma_space(uint32_t index);
int kernel_mm_vma_storage_grow(kernel_vm_area_t **areas,
                               uint32_t *capacity,
                               uint32_t live_count,
                               uint32_t required_count,
                               uint32_t *dynamic_pages);
void kernel_mm_vma_storage_release(kernel_vm_area_t *areas,
                                   uint32_t dynamic_pages);

/*
 * Resident-lock policy is keyed by the hardware address-space identity so
 * CLONE_VM threads share one state on every architecture.  The range vector
 * grows on demand and remains sorted and coalesced for bounded fault/reclaim
 * lookup cost.
 */
uint64_t kernel_mm_lock_space_pool_bytes(uint32_t address_spaces);
int kernel_mm_lock_space_pool_initialize(void *memory, uint64_t size,
                                         uint32_t address_spaces);
int kernel_mm_lock_space_reserve(uint64_t address_space,
                                 uint32_t additional_ranges);
int kernel_mm_lock_space_add(uint64_t address_space, uint64_t address,
                             uint64_t length);
int kernel_mm_lock_space_add_limited(uint64_t address_space,
                                     uint64_t address, uint64_t length,
                                     uint64_t byte_limit);
int kernel_mm_lock_space_remove(uint64_t address_space, uint64_t address,
                                uint64_t length);
int kernel_mm_lock_space_remap(uint64_t address_space,
                               uint64_t old_address,
                               uint64_t old_length,
                               uint64_t new_address,
                               uint64_t new_length);
int kernel_mm_lock_space_contains(uint64_t address_space, uint64_t address);
uint64_t kernel_mm_lock_space_bytes(uint64_t address_space);
uint64_t kernel_mm_resident_peak_observe(uint64_t address_space,
                                         uint64_t resident_bytes);
uint64_t kernel_mm_resident_peak_bytes(uint64_t address_space);
int kernel_mm_mempolicy_set(uint64_t address_space, int32_t mode,
                            uint32_t flags, uint64_t nodes);
int kernel_mm_mempolicy_get(uint64_t address_space, int32_t *mode,
                            uint32_t *flags, uint64_t *nodes);
int kernel_mm_mempolicy_range_set(uint64_t address_space,
                                  uint64_t address, uint64_t length,
                                  int32_t mode, uint32_t flags,
                                  uint64_t nodes);
int kernel_mm_mempolicy_range_get(uint64_t address_space,
                                  uint64_t address, int32_t *mode,
                                  uint32_t *flags, uint64_t *nodes);
int kernel_mm_mempolicy_home_node(uint64_t address_space,
                                  uint64_t address, uint64_t length,
                                  uint32_t home_node);
int kernel_mm_mempolicy_clone(uint64_t parent_address_space,
                              uint64_t child_address_space);
uint32_t kernel_mm_lock_space_future_flags(uint64_t address_space);
int kernel_mm_lock_space_set_future(uint64_t address_space, uint32_t flags);
void kernel_mm_lock_space_release(uint64_t address_space);
void kernel_mm_lock_space_clear(uint64_t address_space);
int kernel_mm_seal_space_clone(uint64_t parent_address_space,
                               uint64_t child_address_space);
int kernel_mm_seal_space_overlaps(uint64_t address_space,
                                  uint64_t address, uint64_t length);

/*
 * Keep bounded architecture caches on one pressure policy: inactive,
 * unpinned entries are reclaimed in least-recently-used order.
 */
uint32_t kernel_mm_reclaim_candidate_offer(
    kernel_mm_reclaim_candidate_t *selection, uint32_t selected,
    uint32_t capacity, const kernel_mm_reclaim_candidate_t *candidate);
void kernel_mm_cache_state_insert(kernel_mm_cache_state_t *state,
                                  uint64_t sequence);
void kernel_mm_cache_state_access(kernel_mm_cache_state_t *state,
                                  uint64_t sequence);
void kernel_mm_cache_state_age(kernel_mm_cache_state_t *state);
void kernel_mm_cache_state_deactivate(kernel_mm_cache_state_t *state);

/*
 * Retain bounded nonresident file-page shadows in shared policy so cachestat
 * reports the same eviction history on every architecture backend.
 */
void kernel_mm_file_cache_note_eviction(
    uint64_t mapping_identity, uint64_t inode_number,
    uint32_t inode_generation, uint64_t page_offset);
void kernel_mm_file_cache_note_refault(
    uint64_t mapping_identity, uint64_t inode_number,
    uint32_t inode_generation, uint64_t page_offset);
void kernel_mm_file_cache_shadow_stat_range(
    uint64_t mapping_identity, uint64_t inode_number,
    uint32_t inode_generation, uint64_t offset, uint64_t length,
    uint64_t *evicted_pages, uint64_t *recently_evicted_pages);

/*
 * Decide whether a concurrent file-fault install already satisfies the
 * requested mapping.  A shared writable page may be temporarily read-only
 * while writeback rearms first-write notification.
 */
int kernel_mm_file_install_race_satisfied(
    uint64_t resident_identity, uint64_t requested_identity,
    int resident_present, int resident_user, int resident_file_cache,
    int resident_writable, int requested_writable, int private_cow);

/* Resolve a demand-paged shared mapping for architecture user-copy helpers. */
int kernel_mm_resolve_user_page(uint64_t address_space, uint64_t address,
                                uint32_t access);
int kernel_mm_address_space_copy(
    uint64_t address_space, uint64_t address, void *buffer,
    uint64_t size, kernel_mm_process_vm_operation_t operation);
uint32_t kernel_mm_reclaim_pages(uint32_t cgroup_id, uint32_t target_pages);
uint32_t kernel_mm_reclaim_cgroup_pressure(uint32_t cgroup_id);
uint32_t kernel_mm_prepare_cgroup_charge(uint32_t cgroup_id,
                                         uint64_t bytes);

/*
 * Architecture backends implement only address-space inspection and page
 * table/cache mechanisms. Linux validation and errno policy stay in the
 * architecture-independent runtime.
 */
int arch_mm_resolve_user_page(uint64_t address_space, uint64_t address,
                              uint32_t access);
uint32_t arch_mm_reclaim_pages(uint32_t cgroup_id, uint32_t target_pages,
                               uint64_t *scanned_pages_out);
int arch_mm_query_residency(uint64_t address, uint32_t page_count,
                            uint8_t *vector);
int arch_mm_process_madvise(
    int32_t pid, uint64_t address, uint64_t length,
    kernel_madvise_operation_t operation, int validate_only);
int arch_mm_sealed_discard_allowed(
    int32_t pid, uint64_t address, uint64_t length);
int arch_mm_process_mrelease(int32_t pid);
int arch_mm_process_vm_copy(
    int32_t pid, uint64_t address, void *buffer, uint64_t size,
    kernel_mm_process_vm_operation_t operation);
int arch_mm_lock_range(uint64_t address, uint64_t length, uint32_t flags);
int arch_mm_unlock_range(uint64_t address, uint64_t length);
int arch_mm_lock_all(uint32_t flags);
int arch_mm_unlock_all(void);
uint64_t arch_mm_current_address_space(void);
int arch_mm_range_mapped(uint64_t address, uint64_t length);
int arch_mm_address_space_range_mapped(
    uint64_t address_space, uint64_t address, uint64_t length);
int arch_mm_address_space_page_resident(
    uint64_t address_space, uint64_t address);
int arch_mm_address_space_shmem_range_supported(
    uint64_t address_space, uint64_t address, uint64_t length);
int arch_mm_address_space_shmem_page_size(
    uint64_t address_space, uint64_t address, uint64_t length,
    uint64_t *page_size);
int arch_mm_address_space_shmem_page_state(
    uint64_t address_space, uint64_t address);
int arch_mm_address_space_copy(
    uint64_t address_space, uint64_t address, void *buffer, uint64_t size,
    kernel_mm_process_vm_operation_t operation);
int arch_mm_address_space_write_protect(
    uint64_t address_space, uint64_t address, uint64_t length, int enable);
int arch_mm_address_space_move_validate(
    uint64_t address_space, uint64_t source, uint64_t destination,
    uint64_t length);
int arch_mm_address_space_move_page(
    uint64_t address_space, uint64_t source, uint64_t destination,
    int allow_source_hole);
int arch_mm_address_space_poison_page(
    uint64_t address_space, uint64_t address);
int arch_mm_address_space_page_poisoned(
    uint64_t address_space, uint64_t address);
int arch_mm_sync_range(uint64_t address, uint64_t length, uint32_t flags);
int64_t arch_mm_protect_range(uint64_t address, uint64_t length,
                              uint64_t protection);
int64_t arch_mm_map(const kernel_mm_map_request_t *request);
int64_t arch_mm_unmap_range(uint64_t address, uint64_t length);
int64_t arch_mm_remap_range(uint64_t old_address, uint64_t old_length,
                            uint64_t new_length, uint32_t flags,
                            uint64_t new_address);
int arch_mm_file_mapping_info(uint64_t address,
                              kernel_mm_file_mapping_info_t *info);
int64_t arch_mm_remap_file_pages(uint64_t address, uint64_t length,
                                 uint64_t file_offset, uint32_t flags);
int arch_mm_program_break_snapshot(
    kernel_mm_program_break_state_t *state);
int arch_mm_program_break_resize(uint64_t old_page, uint64_t new_page);
void arch_mm_program_break_commit(uint64_t address);

#endif
