/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_FD_PATH_STORAGE_H
#define EDGEOS_KERNEL_FD_PATH_STORAGE_H

#include <stdint.h>
#include "mm/arch_vm.h"
#include "string.h"

/* Descriptor copies share storage; namespace changes allocate a replacement. */
typedef struct kernel_fd_path_storage {
    uint32_t references;
    uint32_t pages;
    char text[];
} kernel_fd_path_storage_t;

static inline kernel_fd_path_storage_t *kernel_fd_path_storage_create(
        const char *text, uint32_t capacity) {
    size_t length = strlen(text);
    kernel_fd_path_storage_t *storage;
    uint32_t pages;
    if (length >= capacity) return 0;
    pages = (sizeof(*storage) + capacity + EDGE_PAGE_SIZE - 1u) / EDGE_PAGE_SIZE;
    storage = arch_vm_alloc_pages(pages);
    if (!storage) return 0;
    storage->references = 1;
    storage->pages = pages;
    memcpy(storage->text, text, length + 1u);
    return storage;
}

static inline void kernel_fd_path_storage_retain(kernel_fd_path_storage_t *storage) {
    if (storage)
        __atomic_add_fetch(&storage->references, 1u, __ATOMIC_RELAXED);
}

static inline void kernel_fd_path_storage_release(kernel_fd_path_storage_t *storage) {
    if (storage &&
        __atomic_sub_fetch(&storage->references, 1u, __ATOMIC_ACQ_REL) == 0) {
        uint32_t pages = storage->pages;
        for (uint32_t page = 0; page < pages; ++page)
            arch_vm_free_page((uint8_t *)storage + page * EDGE_PAGE_SIZE);
    }
}

#endif
