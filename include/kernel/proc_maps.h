/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux procfs memory-map interface. */
#ifndef EDGEOS_KERNEL_PROC_MAPS_H
#define EDGEOS_KERNEL_PROC_MAPS_H

#include <stdint.h>

#define KERNEL_PROC_MAP_READ    (1u << 0)
#define KERNEL_PROC_MAP_WRITE   (1u << 1)
#define KERNEL_PROC_MAP_EXEC    (1u << 2)
#define KERNEL_PROC_MAP_SHARED  (1u << 3)
#define KERNEL_PROC_MAP_SEALED  (1u << 4)
#define KERNEL_PROC_MAP_PATH_MAX 512u

#define KERNEL_PROC_MAPS_VIEW_MAPS         1u
#define KERNEL_PROC_MAPS_VIEW_SMAPS        2u
#define KERNEL_PROC_MAPS_VIEW_SMAPS_ROLLUP 3u

typedef struct kernel_proc_vma_cursor {
    uint64_t start;
    uint32_t order;
    uint8_t valid;
} kernel_proc_vma_cursor_t;

typedef struct kernel_proc_vma_snapshot {
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    uint64_t inode;
    uint32_t device_major;
    uint32_t device_minor;
    uint32_t flags;
    uint32_t order;
    char path[KERNEL_PROC_MAP_PATH_MAX];
} kernel_proc_vma_snapshot_t;

typedef struct kernel_proc_vma_accounting {
    uint64_t virtual_size_bytes;
    uint64_t text_size_bytes;
    uint64_t data_size_bytes;
    uint64_t stack_size_bytes;
} kernel_proc_vma_accounting_t;

typedef struct kernel_proc_vma_residency {
    uint64_t resident_pages;
    uint64_t swapped_pages;
    uint64_t shared_resident_pages;
    uint64_t locked_resident_pages;
    uint64_t proportional_resident_bytes;
    uint64_t proportional_swapped_bytes;
} kernel_proc_vma_residency_t;

int kernel_proc_vma_next(int32_t pid,
                         const kernel_proc_vma_cursor_t *after,
                         kernel_proc_vma_snapshot_t *snapshot);
int kernel_proc_maps_render(int32_t pid, char *buffer, uint32_t capacity);
int kernel_proc_maps_read(int32_t pid, uint64_t offset, void *buffer,
                          uint32_t length);
int kernel_proc_smaps_read(int32_t pid, uint64_t offset, void *buffer,
                           uint32_t length);
int kernel_proc_smaps_rollup_read(int32_t pid, uint64_t offset, void *buffer,
                                  uint32_t length);
int kernel_proc_maps_read_description(uint64_t description_identity,
                                      int32_t pid, uint32_t view,
                                      uint64_t offset, void *buffer,
                                      uint32_t length);
void kernel_proc_maps_description_release(uint64_t description_identity);
int kernel_proc_vma_account(int32_t pid,
                            kernel_proc_vma_accounting_t *accounting);
void kernel_proc_vma_account_mapping(
    kernel_proc_vma_accounting_t *accounting,
    uint64_t start, uint64_t end, uint32_t flags, int is_stack);

/*
 * Architecture runtimes enumerate native address-space records. The shared
 * iterator validates ordering and record shape before procfs can expose them.
 */
int arch_proc_vma_next(int32_t pid,
                       const kernel_proc_vma_cursor_t *after,
                       kernel_proc_vma_snapshot_t *snapshot);
int arch_proc_vma_account(int32_t pid,
                          kernel_proc_vma_accounting_t *accounting);
int arch_proc_vma_residency(int32_t pid, uint64_t start, uint64_t end,
                            kernel_proc_vma_residency_t *residency);

#endif
