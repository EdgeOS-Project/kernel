/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ELF_IMAGE_H
#define EDGEOS_ELF_IMAGE_H

#include <stdint.h>
#include "vfs/vfs.h"

typedef struct elf_image_info {
    uint64_t entry;
    uint64_t phoff;
    uint64_t phdr_vaddr;
    uint16_t phnum;
    uint16_t type;
    char interpreter[256];
} elf_image_info_t;

typedef struct elf_image_demand_mapper {
    int (*validate_range)(void *context, uint64_t address, uint64_t length);
    int (*map_file)(void *context, uint64_t address, uint64_t length,
                    uint64_t file_offset, uint32_t protection);
    int (*map_anonymous)(void *context, uint64_t address, uint64_t length,
                         uint32_t protection);
} elf_image_demand_mapper_t;

int elf_image_probe(const char *path, uint16_t machine, elf_image_info_t *info);
int elf_image_probe_inode(vfs_superblock_t *superblock,
                          const vfs_inode_t *inode, uint16_t machine,
                          elf_image_info_t *info);
int elf_image_load(uint64_t address_space, const char *path, uint16_t machine,
                   uint64_t load_bias, elf_image_info_t *info,
                   uint64_t *entry_out);
int elf_image_load_demand(uint64_t address_space, const char *path,
                          uint16_t machine, uint64_t load_bias,
                          elf_image_info_t *info, uint64_t *entry_out,
                          const elf_image_demand_mapper_t *mapper,
                          void *mapper_context);
int elf_image_load_demand_inode(
    uint64_t address_space, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, uint16_t machine, uint64_t load_bias,
    elf_image_info_t *info, uint64_t *entry_out,
    const elf_image_demand_mapper_t *mapper, void *mapper_context);

#endif
