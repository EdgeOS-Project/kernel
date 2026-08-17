/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-compatible swap metadata validation.
 */

#ifndef EDGEOS_FS_SWAP_H
#define EDGEOS_FS_SWAP_H

#include <stdint.h>

typedef int (*edge_swap_restore_mapping_fn)(uint64_t address_space,
                                            uint64_t address,
                                            uint64_t swap_entry);

#ifdef CONFIG_FS_SWAP
int swap_enable_path(const char *path, uint32_t flags);
int swap_disable_path(const char *path);
void swap_register_pager(edge_swap_restore_mapping_fn restore_mapping);
int swap_store_page(uint32_t cgroup_id, const void *page,
                    uint64_t *entry_out);
int swap_load_page(uint64_t entry, void *page, uint32_t *cgroup_id_out);
int swap_retain_entry(uint64_t entry);
uint32_t swap_entry_references(uint64_t entry);
void swap_release_entry(uint64_t entry);
uint64_t swap_total_bytes(void);
uint64_t swap_free_bytes(void);
int swap_proc_snapshot(char *buf, uint32_t max);
#else
static inline int swap_enable_path(const char *path, uint32_t flags) {
    (void)path;
    (void)flags;
    return -38;
}

static inline int swap_disable_path(const char *path) {
    (void)path;
    return -38;
}

static inline void swap_register_pager(
        edge_swap_restore_mapping_fn restore_mapping) {
    (void)restore_mapping;
}

static inline int swap_store_page(uint32_t cgroup_id, const void *page,
                                  uint64_t *entry_out) {
    (void)cgroup_id;
    (void)page;
    (void)entry_out;
    return -38;
}

static inline int swap_load_page(uint64_t entry, void *page,
                                 uint32_t *cgroup_id_out) {
    (void)entry;
    (void)page;
    (void)cgroup_id_out;
    return -38;
}

static inline int swap_retain_entry(uint64_t entry) {
    (void)entry;
    return -38;
}

static inline uint32_t swap_entry_references(uint64_t entry) {
    (void)entry;
    return 0;
}

static inline void swap_release_entry(uint64_t entry) { (void)entry; }

static inline uint64_t swap_total_bytes(void) {
    return 0;
}

static inline uint64_t swap_free_bytes(void) {
    return 0;
}

static inline int swap_proc_snapshot(char *buf, uint32_t max) {
    static const char header[] = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
    uint32_t n = (uint32_t)(sizeof(header) - 1u);
    if (!buf || max <= n) return -1;
    for (uint32_t i = 0; i < n; ++i) buf[i] = header[i];
    buf[n] = 0;
    return (int)n;
}
#endif

#endif
