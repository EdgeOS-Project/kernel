/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent staging for Linux kexec_load images. */

#include <stdint.h>

#include "kernel/kexec_runtime.h"
#include "kernel/linux_errno.h"
#include "string.h"
#include "sys/spinlock.h"

#define KERNEL_KEXEC_PAGE_SIZE 4096u
#define KERNEL_KEXEC_IMAGE_SLOTS 2u

typedef struct kernel_kexec_staged_segment {
    void *storage;
    uint32_t page_count;
    uint32_t reserved;
    kernel_kexec_segment_t descriptor;
} kernel_kexec_staged_segment_t;

typedef struct kernel_kexec_staged_blob {
    void *storage;
    uint32_t page_count;
    uint32_t reserved;
    uint64_t size;
} kernel_kexec_staged_blob_t;

typedef struct kernel_kexec_image {
    uint8_t loaded;
    uint8_t crash_image;
    uint8_t file_mode;
    uint8_t reserved;
    uint16_t segment_count;
    uint32_t generation;
    uint64_t entry;
    uint64_t flags;
    uint64_t source_bytes;
    uint64_t destination_bytes;
    kernel_kexec_staged_segment_t segments[KERNEL_KEXEC_SEGMENT_MAX];
    kernel_kexec_staged_blob_t kernel;
    kernel_kexec_staged_blob_t initrd;
    kernel_kexec_staged_blob_t command_line;
} kernel_kexec_image_t;

static kernel_kexec_image_t g_kexec_images[KERNEL_KEXEC_IMAGE_SLOTS];
static spinlock_t g_kexec_lock;
static uint32_t g_kexec_generation;

static void kexec_release_image(kernel_kexec_image_t *image,
                                const kernel_kexec_access_t *access) {
    if (!image || !access || !access->free_page) return;
    for (uint32_t segment = 0; segment < image->segment_count; ++segment) {
        uint8_t *storage = image->segments[segment].storage;
        uint32_t pages = image->segments[segment].page_count;

        for (uint32_t page = 0; storage && page < pages; ++page)
            access->free_page(access->context,
                              storage + (uint64_t)page *
                                  KERNEL_KEXEC_PAGE_SIZE);
    }
    kernel_kexec_staged_blob_t *blobs[] = {
        &image->kernel, &image->initrd, &image->command_line,
    };
    for (uint32_t index = 0; index < 3u; ++index) {
        uint8_t *storage = blobs[index]->storage;
        for (uint32_t page = 0; storage && page < blobs[index]->page_count;
             ++page)
            access->free_page(access->context,
                              storage + (uint64_t)page *
                                  KERNEL_KEXEC_PAGE_SIZE);
    }
    memset(image, 0, sizeof(*image));
}

static int kexec_stage_blob(kernel_kexec_staged_blob_t *blob,
                            const void *source, uint64_t size,
                            const kernel_kexec_access_t *access) {
    uint64_t page_count;

    if (!blob || (!source && size)) return -EDGE_LINUX_EINVAL;
    blob->size = size;
    if (!size) return 0;
    page_count = (size + KERNEL_KEXEC_PAGE_SIZE - 1u) /
                 KERNEL_KEXEC_PAGE_SIZE;
    if (page_count > UINT32_MAX) return -EDGE_LINUX_EFBIG;
    blob->page_count = (uint32_t)page_count;
    blob->storage = access->allocate_pages(access->context,
                                           blob->page_count);
    if (!blob->storage) return -EDGE_LINUX_ENOMEM;
    if (access->copy_from_user(access->context, blob->storage,
                               (uint64_t)(uintptr_t)source, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int kexec_validate_segments(
        const kernel_kexec_segment_t *segments, uint32_t segment_count,
        uint64_t total_memory, uint64_t *source_bytes,
        uint64_t *destination_bytes) {
    uint64_t source_total = 0;
    uint64_t destination_total = 0;

    for (uint32_t index = 0; index < segment_count; ++index) {
        uint64_t start = segments[index].memory;
        uint64_t size = segments[index].memory_size;
        uint64_t end = start + size;

        if (end < start || (start & (KERNEL_KEXEC_PAGE_SIZE - 1u)) != 0 ||
            (end & (KERNEL_KEXEC_PAGE_SIZE - 1u)) != 0)
            return -EDGE_LINUX_EADDRNOTAVAIL;
        if (segments[index].buffer_size > size)
            return -EDGE_LINUX_EINVAL;
        if (UINT64_MAX - source_total < segments[index].buffer_size ||
            UINT64_MAX - destination_total < size)
            return -EDGE_LINUX_EINVAL;
        source_total += segments[index].buffer_size;
        destination_total += size;

        for (uint32_t previous = 0; previous < index; ++previous) {
            uint64_t previous_start = segments[previous].memory;
            uint64_t previous_end = previous_start +
                                    segments[previous].memory_size;
            if (end > previous_start && start < previous_end)
                return -EDGE_LINUX_EINVAL;
        }
    }

    if (total_memory && destination_total > total_memory / 2u)
        return -EDGE_LINUX_EINVAL;
    *source_bytes = source_total;
    *destination_bytes = destination_total;
    return 0;
}

int kernel_kexec_stage(uint64_t entry, uint32_t segment_count,
                       const kernel_kexec_segment_t *segments,
                       uint64_t flags,
                       const kernel_kexec_access_t *access) {
    kernel_kexec_image_t candidate;
    kernel_kexec_image_t replaced;
    uint64_t lock_flags;
    uint32_t slot = (flags & KERNEL_KEXEC_ON_CRASH) ? 1u : 0u;
    int status;

    if (!access || !access->copy_from_user || !access->allocate_pages ||
        !access->free_page || !access->memory_total_bytes)
        return -EDGE_LINUX_EINVAL;
    if (segment_count > KERNEL_KEXEC_SEGMENT_MAX ||
        (segment_count && !segments))
        return -EDGE_LINUX_EINVAL;

    memset(&candidate, 0, sizeof(candidate));
    memset(&replaced, 0, sizeof(replaced));
    candidate.crash_image = slot != 0;
    candidate.entry = entry;
    candidate.flags = flags;
    candidate.segment_count = (uint16_t)segment_count;

    if (segment_count) {
        status = kexec_validate_segments(
            segments, segment_count,
            access->memory_total_bytes(access->context),
            &candidate.source_bytes, &candidate.destination_bytes);
        if (status < 0) return status;

        for (uint32_t index = 0; index < segment_count; ++index) {
            uint64_t size = segments[index].buffer_size;
            uint64_t page_count =
                (size + KERNEL_KEXEC_PAGE_SIZE - 1u) /
                KERNEL_KEXEC_PAGE_SIZE;
            uint32_t pages;
            void *storage = 0;

            if (page_count > UINT32_MAX) {
                kexec_release_image(&candidate, access);
                return -EDGE_LINUX_EINVAL;
            }
            pages = (uint32_t)page_count;
            candidate.segments[index].descriptor = segments[index];
            candidate.segments[index].page_count = pages;
            if (!pages) continue;
            storage = access->allocate_pages(access->context, pages);
            if (!storage) {
                kexec_release_image(&candidate, access);
                return -EDGE_LINUX_ENOMEM;
            }
            candidate.segments[index].storage = storage;
            if (access->copy_from_user(access->context, storage,
                                       segments[index].buffer, size) < 0) {
                kexec_release_image(&candidate, access);
                return -EDGE_LINUX_EFAULT;
            }
        }
        candidate.loaded = 1u;
    }

    lock_flags = spin_lock_irqsave(&g_kexec_lock);
    candidate.generation = ++g_kexec_generation;
    if (!candidate.generation)
        candidate.generation = ++g_kexec_generation;
    replaced = g_kexec_images[slot];
    g_kexec_images[slot] = candidate;
    spin_unlock_irqrestore(&g_kexec_lock, lock_flags);
    kexec_release_image(&replaced, access);
    return 0;
}

int kernel_kexec_stage_file(const void *kernel, uint64_t kernel_size,
                            const void *initrd, uint64_t initrd_size,
                            const void *command_line,
                            uint64_t command_line_size, uint64_t flags,
                            const kernel_kexec_access_t *access) {
    kernel_kexec_image_t candidate;
    kernel_kexec_image_t replaced;
    uint64_t lock_flags;
    uint32_t slot = (flags & KERNEL_KEXEC_ON_CRASH) ? 1u : 0u;
    int status;

    if (!access || !access->copy_from_user || !access->allocate_pages ||
        !access->free_page)
        return -EDGE_LINUX_EINVAL;
    if (!kernel_size)
        return -EDGE_LINUX_ENOEXEC;
    memset(&candidate, 0, sizeof(candidate));
    memset(&replaced, 0, sizeof(replaced));
    candidate.loaded = 1u;
    candidate.file_mode = 1u;
    candidate.crash_image = slot != 0;
    candidate.flags = flags;
    status = kexec_stage_blob(&candidate.kernel, kernel, kernel_size, access);
    if (status < 0) goto fail;
    status = kexec_stage_blob(&candidate.initrd, initrd, initrd_size, access);
    if (status < 0) goto fail;
    status = kexec_stage_blob(&candidate.command_line, command_line,
                              command_line_size, access);
    if (status < 0) goto fail;
    candidate.source_bytes = kernel_size + initrd_size + command_line_size;

    lock_flags = spin_lock_irqsave(&g_kexec_lock);
    candidate.generation = ++g_kexec_generation;
    if (!candidate.generation)
        candidate.generation = ++g_kexec_generation;
    replaced = g_kexec_images[slot];
    g_kexec_images[slot] = candidate;
    spin_unlock_irqrestore(&g_kexec_lock, lock_flags);
    kexec_release_image(&replaced, access);
    return 0;

fail:
    kexec_release_image(&candidate, access);
    return status;
}

int kernel_kexec_snapshot(int crash_image,
                          kernel_kexec_snapshot_t *snapshot) {
    kernel_kexec_image_t *image;
    uint64_t lock_flags;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    lock_flags = spin_lock_irqsave(&g_kexec_lock);
    image = &g_kexec_images[crash_image ? 1u : 0u];
    snapshot->loaded = image->loaded;
    snapshot->crash_image = image->crash_image;
    snapshot->file_mode = image->file_mode;
    snapshot->reserved = 0;
    snapshot->reserved2 = 0;
    snapshot->segment_count = image->segment_count;
    snapshot->generation = image->generation;
    snapshot->entry = image->entry;
    snapshot->flags = image->flags;
    snapshot->source_bytes = image->source_bytes;
    snapshot->destination_bytes = image->destination_bytes;
    snapshot->kernel_bytes = image->kernel.size;
    snapshot->initrd_bytes = image->initrd.size;
    snapshot->command_line_bytes = image->command_line.size;
    spin_unlock_irqrestore(&g_kexec_lock, lock_flags);
    return 0;
}
