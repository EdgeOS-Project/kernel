/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 ELF metadata reader.
 * Copyright (c) EdgeOS Contributors.
 *
 * This validates the Linux AArch64 ELF ABI before user mapping begins.  The
 * interpreter path comes from PT_INTERP in the mounted VFS object, never from
 * a distro-specific hardcoded location.
 */

#include <stdint.h>
#include "elf/elf_abi.h"
#include "elf/elf_image.h"
#include "mm/arch_vm.h"
#include "vfs/vfs.h"
#include "stdio.h"

#define ELF_ET_EXEC 2u
#define ELF_ET_DYN 3u
#define ELF_EM_AARCH64 183u
#define ELF_PT_INTERP 3u
#define ELF_PT_LOAD 1u
#define ELF_PT_PHDR 6u
#define ELF_MAX_PHNUM 128u
#define ELF_SYNC_PAGE_BATCH 128u

typedef struct {
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} elf64_phdr_t;

static int elf_image_source_read(const char *path,
                                 vfs_superblock_t *superblock,
                                 const vfs_inode_t *inode, uint32_t offset,
                                 void *buffer, uint32_t length) {
    vfs_inode_t source;

    if (!inode) return vfs_pread(path, offset, buffer, length);
    if (!superblock || (uint64_t)offset + length > inode->size)
        return -1;
    source = *inode;
    return vfs_read_inode_exact(
        superblock, &source, offset, buffer, length) == 0 ?
        (int)length : -1;
}

static int elf_image_probe_source(
    const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *supplied_inode, uint16_t machine,
    elf_image_info_t *info) {
    elf64_ehdr_t eh;
    vfs_inode_t inode;
    uint64_t phdr_bytes;
    int header_read;
    uint16_t i;
    if (!path || !info) return -1;
    if (supplied_inode) {
        if (!superblock) return -1;
        inode = *supplied_inode;
    } else if (vfs_resolve(path, &inode, &superblock, 0, 0) < 0) {
        return -1;
    }
    header_read = elf_image_source_read(
        path, superblock, &inode, 0, &eh, sizeof(eh));
    if (header_read != (int)sizeof(eh)) {
        printf("[arm64-elf] probe read failed path=%s result=%d\n", path, header_read);
        return -1;
    }
    if (eh.ident[0] != 0x7f || eh.ident[1] != 'E' || eh.ident[2] != 'L' || eh.ident[3] != 'F' ||
        eh.ident[4] != 2u || eh.ident[5] != 1u || eh.ident[6] != 1u ||
        eh.machine != machine || (eh.type != ELF_ET_EXEC && eh.type != ELF_ET_DYN) ||
        eh.ehsize != sizeof(eh) || eh.phentsize != sizeof(elf64_phdr_t) ||
        !eh.phnum || eh.phnum > ELF_MAX_PHNUM) return -1;
    info->entry = eh.entry;
    info->phoff = eh.phoff;
    info->phdr_vaddr = 0;
    info->phnum = eh.phnum;
    info->type = eh.type;
    info->interpreter[0] = 0;
    phdr_bytes = (uint64_t)eh.phnum * sizeof(elf64_phdr_t);
    if (!edge_elf_file_range_valid(
            inode.size, eh.phoff, phdr_bytes)) return -1;
    for (i = 0; i < eh.phnum; ++i) {
        elf64_phdr_t ph;
        if (eh.phoff > UINT32_MAX || eh.phoff + (uint64_t)i * sizeof(ph) > UINT32_MAX ||
            elf_image_source_read(
                path, superblock, &inode,
                (uint32_t)(eh.phoff + (uint64_t)i * sizeof(ph)),
                &ph, sizeof(ph)) != (int)sizeof(ph)) return -1;
        if (ph.type == ELF_PT_LOAD) {
            if (ph.memsz < ph.filesz || !edge_elf_file_range_valid(
                    inode.size, ph.offset, ph.filesz))
                return -1;
        }
        if (ph.type == ELF_PT_PHDR) {
            if (ph.filesz < phdr_bytes || ph.memsz < phdr_bytes) return -1;
            info->phdr_vaddr = ph.vaddr;
        } else if (ph.type == ELF_PT_LOAD && !info->phdr_vaddr &&
                   eh.phoff >= ph.offset &&
                   eh.phoff + phdr_bytes <= ph.offset + ph.filesz) {
            info->phdr_vaddr = ph.vaddr + (eh.phoff - ph.offset);
        }
        if (ph.type == ELF_PT_INTERP) {
            uint64_t n = ph.filesz;
            if (!n || n >= sizeof(info->interpreter) ||
                !edge_elf_file_range_valid(inode.size, ph.offset, n) ||
                ph.offset > UINT32_MAX ||
                elf_image_source_read(
                    path, superblock, &inode, (uint32_t)ph.offset,
                    info->interpreter, (uint32_t)n) != (int)n) return -1;
            info->interpreter[n - 1u] = 0;
        }
    }
    return info->phdr_vaddr ? 0 : -1;
}

int elf_image_probe(const char *path, uint16_t machine,
                    elf_image_info_t *info) {
    return elf_image_probe_source(path, 0, 0, machine, info);
}

int elf_image_probe_inode(vfs_superblock_t *superblock,
                          const vfs_inode_t *inode, uint16_t machine,
                          elf_image_info_t *info) {
    return elf_image_probe_source(
        "[open executable]", superblock, inode, machine, info);
}

static uint64_t page_down(uint64_t value) {
    return value & ~0xfffULL;
}

static uint64_t page_up(uint64_t value) {
    return (value + 0xfffULL) & ~0xfffULL;
}

static int elf_get_boundary_page(uint64_t ttbr0, uint64_t va, uint32_t prot,
                                 uint8_t **page_out) {
    uint64_t physical = 0;
    uint32_t existing_prot = 0;
    uint8_t *page;

    if (!page_out || (va & 0xfffu)) return -1;
    if (arch_vm_translate(ttbr0, va, &physical, 0) == 0 &&
        arch_vm_user_page_protection(ttbr0, va, &existing_prot) == 0) {
        page = (uint8_t *)(uintptr_t)(physical & ~0xfffULL);
        if ((existing_prot | prot) != existing_prot &&
            arch_vm_protect_user_range(
                ttbr0, va, 4096u, existing_prot | prot) < 0)
            return -1;
    } else {
        page = (uint8_t *)arch_vm_alloc_page();
        if (!page) return -1;
        for (uint32_t index = 0; index < 4096u; ++index) page[index] = 0;
        if (arch_vm_map_user_page(
                ttbr0, va, (uint64_t)(uintptr_t)page, prot) < 0) {
            arch_vm_free_page(page);
            return -1;
        }
    }
    *page_out = page;
    return 0;
}

static int elf_load_boundary(uint64_t ttbr0, const char *path,
                             vfs_superblock_t *superblock,
                             const vfs_inode_t *inode,
                             uint64_t page_va, uint64_t copy_start,
                             uint64_t copy_end, uint64_t segment_start,
                             uint64_t file_offset, uint32_t prot) {
    uint8_t *page;
    uint64_t source;
    uint64_t count;

    if (elf_get_boundary_page(ttbr0, page_va, prot, &page) < 0) return -1;
    if (copy_start < copy_end) {
        source = file_offset + copy_start - segment_start;
        count = copy_end - copy_start;
        if (source > UINT32_MAX || count > UINT32_MAX ||
            elf_image_source_read(
                path, superblock, inode, (uint32_t)source,
                page + copy_start - page_va,
                (uint32_t)count) != (int)count)
            return -1;
    }
    arch_vm_sync_loaded_page(page, (prot & ARCH_VM_PROT_EXEC) != 0);
    return 0;
}

static int elf_image_load_demand_source(
    uint64_t ttbr0, const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, uint16_t machine, uint64_t load_bias,
    elf_image_info_t *info, uint64_t *entry_out,
    const elf_image_demand_mapper_t *mapper, void *mapper_context) {
    elf64_ehdr_t eh;
    elf_image_info_t local_info;

    if (!ttbr0 || !entry_out || !mapper || !mapper->validate_range ||
        !mapper->map_file || !mapper->map_anonymous ||
        elf_image_probe_source(
            path, superblock, inode, machine,
            info ? info : &local_info) < 0 ||
        elf_image_source_read(
            path, superblock, inode, 0, &eh, sizeof(eh)) !=
            (int)sizeof(eh))
        return -1;
    for (uint16_t index = 0; index < eh.phnum; ++index) {
        elf64_phdr_t ph;
        uint64_t segment_start;
        uint64_t segment_end;
        uint64_t file_end;
        uint64_t full_file_start;
        uint64_t full_file_end;
        uint64_t anonymous_start;
        uint32_t prot = 0;

        if (elf_image_source_read(
                path, superblock, inode,
                (uint32_t)(eh.phoff + (uint64_t)index * sizeof(ph)),
                &ph, sizeof(ph)) != (int)sizeof(ph))
            return -1;
        if (ph.type != ELF_PT_LOAD) continue;
        if (ph.memsz < ph.filesz || ph.vaddr + load_bias < ph.vaddr ||
            ph.vaddr + load_bias + ph.memsz < ph.vaddr + load_bias)
            return -1;
        if (!ph.memsz) continue;
        if (((ph.vaddr + load_bias) & 0xfffu) !=
            (ph.offset & 0xfffu))
            return -1;
        segment_start = ph.vaddr + load_bias;
        segment_end = segment_start + ph.memsz;
        file_end = segment_start + ph.filesz;
        if (ph.flags & 4u) prot |= ARCH_VM_PROT_READ;
        if (ph.flags & 2u) prot |= ARCH_VM_PROT_WRITE;
        if (ph.flags & 1u) prot |= ARCH_VM_PROT_EXEC;
        if (mapper->validate_range(
                mapper_context, page_down(segment_start),
                page_up(segment_end) - page_down(segment_start)) < 0)
            return -1;

        /* Partial pages need private zero-fill and therefore cannot use the
         * inode page cache.  Complete file pages remain demand-backed. */
        if (segment_start & 0xfffu) {
            uint64_t boundary_end = file_end < page_up(segment_start) ?
                                    file_end : page_up(segment_start);
            if (elf_load_boundary(
                    ttbr0, path, superblock, inode,
                    page_down(segment_start), segment_start,
                    boundary_end, segment_start, ph.offset, prot) < 0)
                return -1;
        }
        full_file_start = page_up(segment_start);
        if (!(segment_start & 0xfffu)) full_file_start = segment_start;
        full_file_end = page_down(file_end);
        if (full_file_end > full_file_start && mapper->map_file(
                mapper_context, full_file_start,
                full_file_end - full_file_start,
                ph.offset + full_file_start - segment_start, prot) < 0)
            return -1;
        if ((file_end & 0xfffu) &&
            page_down(file_end) != page_down(segment_start)) {
            if (elf_load_boundary(
                    ttbr0, path, superblock, inode,
                    page_down(file_end), page_down(file_end),
                    file_end, segment_start, ph.offset, prot) < 0)
                return -1;
        } else if ((file_end & 0xfffu) &&
                   !(segment_start & 0xfffu)) {
            if (elf_load_boundary(
                    ttbr0, path, superblock, inode,
                    page_down(file_end), segment_start,
                    file_end, segment_start, ph.offset, prot) < 0)
                return -1;
        }
        anonymous_start = page_up(file_end > segment_start ?
                                  file_end : segment_start);
        if (!ph.filesz && !(segment_start & 0xfffu))
            anonymous_start = segment_start;
        if (page_up(segment_end) > anonymous_start &&
            mapper->map_anonymous(
                mapper_context, anonymous_start,
                page_up(segment_end) - anonymous_start, prot) < 0)
            return -1;
    }
    *entry_out = eh.entry + load_bias;
    return 0;
}

int elf_image_load_demand(uint64_t ttbr0, const char *path,
                          uint16_t machine, uint64_t load_bias,
                          elf_image_info_t *info, uint64_t *entry_out,
                          const elf_image_demand_mapper_t *mapper,
                          void *mapper_context) {
    return elf_image_load_demand_source(
        ttbr0, path, 0, 0, machine, load_bias, info, entry_out,
        mapper, mapper_context);
}

int elf_image_load_demand_inode(
    uint64_t ttbr0, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, uint16_t machine, uint64_t load_bias,
    elf_image_info_t *info, uint64_t *entry_out,
    const elf_image_demand_mapper_t *mapper, void *mapper_context) {
    return elf_image_load_demand_source(
        ttbr0, "[open executable]", superblock, inode, machine, load_bias,
        info, entry_out, mapper, mapper_context);
}

static int elf_sync_page_batch(void **pages, uint32_t *count, int executable) {
    if (!pages || !count) return -1;
    if (*count) {
        arch_vm_sync_loaded_pages(pages, *count, executable);
        *count = 0;
    }
    return 0;
}

static int elf_load_image_pages(uint64_t ttbr0, const char *path,
                                uint64_t load_bias, uint16_t machine,
                                elf_image_info_t *info, uint64_t *entry_out) {
    elf64_ehdr_t eh;
    uint16_t i;
    elf_image_info_t local_info;

    if (!entry_out || elf_image_probe(path, machine, info ? info : &local_info) < 0 ||
        vfs_pread(path, 0, &eh, sizeof(eh)) != (int)sizeof(eh)) {
        printf("[arm64-elf] metadata failed\n");
        return -1;
    }
    for (i = 0; i < eh.phnum; ++i) {
        elf64_phdr_t ph;
        uint64_t seg_start;
        uint64_t seg_end;
        uint64_t va;
        uint32_t prot = 0;
        void *sync_pages[ELF_SYNC_PAGE_BATCH];
        uint32_t sync_count = 0;
        if (vfs_pread(path, (uint32_t)(eh.phoff + (uint64_t)i * sizeof(ph)), &ph, sizeof(ph)) != (int)sizeof(ph)) {
            printf("[arm64-elf] phdr failed i=%u\n", i);
            return -1;
        }
        if (ph.type != ELF_PT_LOAD) continue;
        if (ph.memsz < ph.filesz || ph.vaddr + load_bias < ph.vaddr ||
            ph.vaddr + load_bias + ph.memsz < ph.vaddr + load_bias) {
            printf("[arm64-elf] range failed i=%u\n", i);
            return -1;
        }
        if (ph.flags & 4u) prot |= ARCH_VM_PROT_READ;
        if (ph.flags & 2u) prot |= ARCH_VM_PROT_WRITE;
        if (ph.flags & 1u) prot |= ARCH_VM_PROT_EXEC;
        seg_start = ph.vaddr + load_bias;
        seg_end = seg_start + ph.memsz;
        for (va = page_down(seg_start); va < page_up(seg_end); va += 4096u) {
            uint8_t *page = 0;
            uint64_t physical = 0;
            uint64_t copy_start;
            uint64_t copy_end;
            uint32_t existing_prot = 0;

            /*
             * Adjacent PT_LOAD segments may share a boundary page.  Resolve
             * it from the new address space instead of retaining a
             * fixed-size side table.  This keeps executable size limited by
             * the VM and available memory, and it permits concurrent execs.
             */
            if (arch_vm_translate(ttbr0, va, &physical, 0) == 0 &&
                arch_vm_user_page_protection(
                    ttbr0, va, &existing_prot) == 0) {
                page = (uint8_t *)(uintptr_t)(physical & ~0xfffULL);
                if ((existing_prot | prot) != existing_prot &&
                    arch_vm_protect_user_range(
                        ttbr0, va, 4096u, existing_prot | prot) < 0)
                    return -1;
            } else {
                /*
                 * A new ARM64 address space inherits privileged low identity
                 * mappings.  Splitting one such block leaves adjacent
                 * kernel-only PTEs visible to translation, but they have no
                 * user ownership record.  Replace those leaves exactly as an
                 * absent user mapping; only a successful protection lookup
                 * identifies a previously loaded PT_LOAD boundary page.
                 */
                page = (uint8_t *)arch_vm_alloc_page();
                if (!page || arch_vm_map_user_page(
                        ttbr0, va, (uint64_t)(uintptr_t)page, prot) < 0)
                    page = 0;
            }
            if (!page) {
                printf("[arm64-elf] map failed i=%u va=0x%x page=0x%x\n", i,
                       (uint32_t)va, (uint32_t)(uintptr_t)page);
                return -1;
            }
            copy_start = va > seg_start ? va : seg_start;
            copy_end = va + 4096u < seg_start + ph.filesz ? va + 4096u : seg_start + ph.filesz;
            if (copy_start < copy_end) {
                uint64_t file_off = ph.offset + copy_start - seg_start;
                uint64_t bytes = copy_end - copy_start;
                if (file_off > UINT32_MAX || bytes > UINT32_MAX ||
                    vfs_pread(path, (uint32_t)file_off, page + copy_start - va,
                              (uint32_t)bytes) != (int)bytes) {
                    printf("[arm64-elf] read failed i=%u off=0x%x\n", i, (uint32_t)file_off);
                    return -1;
                }
            }
            sync_pages[sync_count++] = page;
            if (sync_count == ELF_SYNC_PAGE_BATCH)
                elf_sync_page_batch(sync_pages, &sync_count,
                                    (prot & ARCH_VM_PROT_EXEC) != 0);
        }
        elf_sync_page_batch(sync_pages, &sync_count,
                            (prot & ARCH_VM_PROT_EXEC) != 0);
    }
    *entry_out = eh.entry + load_bias;
    return 0;
}

int elf_image_load(uint64_t ttbr0, const char *path, uint16_t machine,
                   uint64_t load_bias, elf_image_info_t *info, uint64_t *entry_out) {
    return elf_load_image_pages(ttbr0, path, load_bias, machine, info,
                                entry_out);
}
