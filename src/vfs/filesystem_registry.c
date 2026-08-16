/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS filesystem type registry.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/filesystem_registry.h"
#include "mm/arch_vm.h"
#include "string.h"

#define VFS_FILESYSTEM_NAME_CAPACITY 16u
#define VFS_FILESYSTEM_INLINE_CAPACITY 8u
#define VFS_FILESYSTEM_CHUNK_CAPACITY 8u
#define VFS_FILESYSTEM_ALLOCATION_PAGE_SIZE 4096u

typedef struct vfs_filesystem_registration {
    char name[VFS_FILESYSTEM_NAME_CAPACITY];
    vfs_filesystem_mount_fn_t mount_fn;
} vfs_filesystem_registration_t;

typedef struct vfs_filesystem_registry_chunk {
    struct vfs_filesystem_registry_chunk *next;
    uint32_t page_count;
    uint32_t capacity;
    vfs_filesystem_registration_t registrations[];
} vfs_filesystem_registry_chunk_t;

static vfs_filesystem_registration_t
    g_inline_registrations[VFS_FILESYSTEM_INLINE_CAPACITY];
static vfs_filesystem_registry_chunk_t *g_registry_chunks;
static uint32_t g_registration_count;
static volatile uint32_t g_registry_lock;

static void registry_lock(void) {
    while (__atomic_test_and_set(&g_registry_lock, __ATOMIC_ACQUIRE)) {
    }
}

static void registry_unlock(void) {
    __atomic_clear(&g_registry_lock, __ATOMIC_RELEASE);
}

static vfs_filesystem_registration_t *registry_at(uint32_t index) {
    vfs_filesystem_registry_chunk_t *chunk;

    if (index < VFS_FILESYSTEM_INLINE_CAPACITY)
        return &g_inline_registrations[index];
    index -= VFS_FILESYSTEM_INLINE_CAPACITY;
    for (chunk = __atomic_load_n(&g_registry_chunks, __ATOMIC_ACQUIRE);
         chunk;
         chunk = __atomic_load_n(&chunk->next, __ATOMIC_ACQUIRE)) {
        if (index < chunk->capacity) return &chunk->registrations[index];
        index -= chunk->capacity;
    }
    return 0;
}

uint32_t vfs_filesystem_registry_capacity(void) {
    vfs_filesystem_registry_chunk_t *chunk;
    uint32_t capacity = VFS_FILESYSTEM_INLINE_CAPACITY;

    for (chunk = __atomic_load_n(&g_registry_chunks, __ATOMIC_ACQUIRE);
         chunk;
         chunk = __atomic_load_n(&chunk->next, __ATOMIC_ACQUIRE)) {
        if (capacity > UINT32_MAX - chunk->capacity) return UINT32_MAX;
        capacity += chunk->capacity;
    }
    return capacity;
}

static int registry_reserve(uint32_t required_capacity) {
    vfs_filesystem_registry_chunk_t **link = &g_registry_chunks;
    uint32_t capacity = VFS_FILESYSTEM_INLINE_CAPACITY;

    while (*link) {
        if (capacity > UINT32_MAX - (*link)->capacity) return -1;
        capacity += (*link)->capacity;
        link = &(*link)->next;
    }
    while (capacity < required_capacity) {
        uint64_t bytes = sizeof(vfs_filesystem_registry_chunk_t) +
            (uint64_t)VFS_FILESYSTEM_CHUNK_CAPACITY *
                sizeof(vfs_filesystem_registration_t);
        uint32_t pages = (uint32_t)((bytes +
            VFS_FILESYSTEM_ALLOCATION_PAGE_SIZE - 1u) /
            VFS_FILESYSTEM_ALLOCATION_PAGE_SIZE);
        vfs_filesystem_registry_chunk_t *chunk;

        if (!pages || capacity >
                UINT32_MAX - VFS_FILESYSTEM_CHUNK_CAPACITY)
            return -1;
        chunk = (vfs_filesystem_registry_chunk_t *)
            arch_vm_alloc_pages(pages);
        if (!chunk) return -1;
        memset(chunk, 0,
               (uint64_t)pages * VFS_FILESYSTEM_ALLOCATION_PAGE_SIZE);
        chunk->page_count = pages;
        chunk->capacity = VFS_FILESYSTEM_CHUNK_CAPACITY;
        __atomic_store_n(link, chunk, __ATOMIC_RELEASE);
        link = &chunk->next;
        capacity += chunk->capacity;
    }
    return 0;
}

void vfs_filesystem_registry_reset(void) {
    vfs_filesystem_registry_chunk_t *chunk;

    registry_lock();
    chunk = g_registry_chunks;
    g_registry_chunks = 0;
    g_registration_count = 0;
    memset(g_inline_registrations, 0, sizeof(g_inline_registrations));
    registry_unlock();

    while (chunk) {
        vfs_filesystem_registry_chunk_t *next = chunk->next;
        uint32_t page_count = chunk->page_count;
        uint8_t *page = (uint8_t *)chunk;
        for (uint32_t index = 0; index < page_count; ++index) {
            arch_vm_free_page(page +
                (uint64_t)index * VFS_FILESYSTEM_ALLOCATION_PAGE_SIZE);
        }
        chunk = next;
    }
}

int vfs_filesystem_registry_register(const char *name,
                                     vfs_filesystem_mount_fn_t mount_fn) {
    vfs_filesystem_registration_t *registration;
    uint32_t length;

    if (!name || !mount_fn) return -1;
    length = (uint32_t)strlen(name);
    if (!length || length >= VFS_FILESYSTEM_NAME_CAPACITY) return -1;

    registry_lock();
    if (g_registration_count == UINT32_MAX ||
        registry_reserve(g_registration_count + 1u) != 0) {
        registry_unlock();
        return -1;
    }
    registration = registry_at(g_registration_count);
    if (!registration) {
        registry_unlock();
        return -1;
    }
    memcpy(registration->name, name, length + 1u);
    registration->mount_fn = mount_fn;
    __atomic_store_n(&g_registration_count, g_registration_count + 1u,
                     __ATOMIC_RELEASE);
    registry_unlock();
    return 0;
}

int vfs_filesystem_registry_mount(const char *name, const char *device,
                                  const char *target) {
    uint32_t count;

    if (!name) return -1;
    count = __atomic_load_n(&g_registration_count, __ATOMIC_ACQUIRE);
    for (uint32_t index = 0; index < count; ++index) {
        vfs_filesystem_registration_t *registration = registry_at(index);
        if (registration && strcmp(registration->name, name) == 0)
            return registration->mount_fn(device, target);
    }
    return -1;
}

uint32_t vfs_filesystem_registry_count(void) {
    return __atomic_load_n(&g_registration_count, __ATOMIC_ACQUIRE);
}
