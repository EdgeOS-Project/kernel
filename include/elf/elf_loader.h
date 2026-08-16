#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdint.h>
#include "vfs/vfs.h"

int elf_loader_probe(const char *path);
int elf_loader_probe_inode(vfs_superblock_t *superblock,
                           const vfs_inode_t *inode);

typedef struct edge_elf_image {
    uint64_t entry_rip;
    uint64_t at_phdr;
    uint64_t at_phnum;
    uint64_t at_entry;
    uint64_t at_base;
    uint64_t main_load_hi;
} edge_elf_image_t;

int elf_loader_exec(const char *path, edge_elf_image_t *out);
int elf_loader_exec_into(int pid, const char *path, edge_elf_image_t *out);
int elf_loader_exec_inode(vfs_superblock_t *superblock,
                          const vfs_inode_t *inode, const char *display_path,
                          edge_elf_image_t *out);

#endif
