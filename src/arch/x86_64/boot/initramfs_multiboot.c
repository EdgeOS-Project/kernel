// SPDX-License-Identifier: MPL-2.0
/*
 * x86 Multiboot initramfs discovery.
 *
 * Archive parsing and filesystem population remain architecture-independent in
 * fs/initramfs.c.  This file only translates Multiboot module descriptors into
 * the shared memory-payload interface.
 */

#include "arch/x86_64/boot/multiboot.h"
#include "fs/initramfs.h"

#include <stdint.h>

#ifndef MULTIBOOT2_BOOTLOADER_MAGIC
#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36d76289u
#endif

#define MB2_TAG_TYPE_END 0u
#define MB2_TAG_TYPE_MODULE 3u

struct mb2_tag {
    uint32_t type;
    uint32_t size;
};

struct mb2_tag_module {
    struct mb2_tag tag;
    uint32_t mod_start;
    uint32_t mod_end;
    char cmdline[];
};

typedef struct {
    const void *data;
    uint64_t size;
} initramfs_multiboot_blob_t;

static int initramfs_scan_mb1(uint32_t magic, void *mb_info,
                              initramfs_multiboot_blob_t *out) {
    multiboot_info_t *mb;
    multiboot_module_t *modules;

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC || !mb_info || !out) return 0;
    mb = (multiboot_info_t *)mb_info;
    if (!(mb->flags & MULTIBOOT_INFO_MODS) || mb->mods_count == 0) return 0;
    modules = (multiboot_module_t *)(uintptr_t)mb->mods_addr;
    for (uint32_t index = 0; index < mb->mods_count; ++index) {
        uint32_t start = modules[index].mod_start;
        uint32_t end = modules[index].mod_end;

        if (end <= start) continue;
        if (initramfs_buffer_has_archive(
                (const void *)(uintptr_t)start, end - start)) {
            out->data = (const void *)(uintptr_t)start;
            out->size = end - start;
            return 1;
        }
    }
    return 0;
}

static int initramfs_scan_mb2(void *mb_info,
                              initramfs_multiboot_blob_t *out) {
    uint8_t *base;
    uint8_t *cursor;
    uint8_t *end;
    uint32_t total;

    if (!mb_info || !out) return 0;
    base = (uint8_t *)mb_info;
    total = *(uint32_t *)base;
    if (total < 16 || total > 16u * 1024u * 1024u) return 0;
    cursor = base + 8;
    end = base + total;
    while (cursor + sizeof(struct mb2_tag) <= end) {
        struct mb2_tag *tag = (struct mb2_tag *)cursor;
        uint32_t aligned;

        if (tag->type == MB2_TAG_TYPE_END) break;
        if (tag->size < sizeof(*tag) || cursor + tag->size > end) break;
        if (tag->type == MB2_TAG_TYPE_MODULE &&
            tag->size >= sizeof(struct mb2_tag_module)) {
            struct mb2_tag_module *module =
                (struct mb2_tag_module *)tag;

            if (module->mod_end > module->mod_start &&
                initramfs_buffer_has_archive(
                    (const void *)(uintptr_t)module->mod_start,
                    module->mod_end - module->mod_start)) {
                out->data = (const void *)(uintptr_t)module->mod_start;
                out->size = module->mod_end - module->mod_start;
                return 1;
            }
        }
        aligned = (tag->size + 7u) & ~7u;
        if (aligned == 0) break;
        cursor += aligned;
    }
    return 0;
}

static int initramfs_multiboot_find(uint32_t magic, void *mb_info,
                                    initramfs_multiboot_blob_t *out) {
    if (!out) return 0;
    out->data = 0;
    out->size = 0;
    if (initramfs_scan_mb1(magic, mb_info, out)) return 1;
    return magic == MULTIBOOT2_BOOTLOADER_MAGIC &&
           initramfs_scan_mb2(mb_info, out);
}

int initramfs_multiboot_has_archive(uint32_t magic, void *mb_info) {
    initramfs_multiboot_blob_t blob;

    return initramfs_multiboot_find(magic, mb_info, &blob);
}

int initramfs_unpack_multiboot(uint32_t magic, void *mb_info) {
    initramfs_multiboot_blob_t blob;

    if (!initramfs_multiboot_find(magic, mb_info, &blob)) return 0;
    return initramfs_unpack_memory(blob.data, blob.size);
}
