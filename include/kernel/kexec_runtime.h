/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_KEXEC_RUNTIME_H
#define EDGEOS_KERNEL_KEXEC_RUNTIME_H

#include <stdint.h>

#define KERNEL_KEXEC_SEGMENT_MAX 16u
#define KERNEL_KEXEC_ON_CRASH 0x00000001u

typedef struct kernel_kexec_segment {
    uint64_t buffer;
    uint64_t buffer_size;
    uint64_t memory;
    uint64_t memory_size;
} kernel_kexec_segment_t;

typedef struct kernel_kexec_access {
    void *context;
    int (*copy_from_user)(void *context, void *destination,
                          uint64_t source, uint64_t length);
    void *(*allocate_pages)(void *context, uint32_t page_count);
    void (*free_page)(void *context, void *page);
    uint64_t (*memory_total_bytes)(void *context);
} kernel_kexec_access_t;

typedef struct kernel_kexec_snapshot {
    uint8_t loaded;
    uint8_t crash_image;
    uint8_t file_mode;
    uint8_t reserved;
    uint16_t segment_count;
    uint16_t reserved2;
    uint32_t generation;
    uint64_t entry;
    uint64_t flags;
    uint64_t source_bytes;
    uint64_t destination_bytes;
    uint64_t kernel_bytes;
    uint64_t initrd_bytes;
    uint64_t command_line_bytes;
} kernel_kexec_snapshot_t;

int kernel_kexec_stage(uint64_t entry, uint32_t segment_count,
                       const kernel_kexec_segment_t *segments,
                       uint64_t flags,
                       const kernel_kexec_access_t *access);
int kernel_kexec_stage_file(const void *kernel, uint64_t kernel_size,
                            const void *initrd, uint64_t initrd_size,
                            const void *command_line,
                            uint64_t command_line_size, uint64_t flags,
                            const kernel_kexec_access_t *access);
int kernel_kexec_snapshot(int crash_image,
                          kernel_kexec_snapshot_t *snapshot);

#endif
