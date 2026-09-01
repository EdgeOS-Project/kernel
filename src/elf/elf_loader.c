#include "elf/elf_loader.h"
#include "elf/elf_abi.h"
#include "arch/x86_64/user_layout.h"

#include "sys/boottime.h"
#include "sys/process.h"
#include "sys/scheduler.h"
#include "stdio.h"
#include "string.h"

static inline void elf_cpu_relax(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield" ::: "memory");
#else
#error "elf_cpu_relax needs an architecture implementation"
#endif
}
#include "vfs/vfs.h"

#include <stdint.h>

#define ELF64_EHDR_SIZE 64
#define ELF64_PHDR_SIZE 56
#define ELF32_EHDR_SIZE 52
#define ELF32_PHDR_SIZE 32
#define ELF_IO_CHUNK   (64u * 1024u)
#define ELF_MAX_PHNUM  128

#define PT_LOAD   1u
#define PT_DYNAMIC 2u
#define PT_INTERP 3u
#define PT_PHDR 6u

#define ET_EXEC 2u
#define ET_DYN  3u

#define PF_W 2u
#define PF_R 4u
#define PF_X 1u

#define USER_ADDR_MIN EDGE_USER_MIN_ADDR
#define USER_ADDR_MAX EDGE_USER_MAX_ADDR

#define EDGE_MAIN_ET_DYN_BASE   0x0000000000400000ULL
#define EDGE_INTERP_ET_DYN_BASE X86_USER_INTERP_BASE
#define USER_LOW_BASE_ADDR      0x0000000000400000ULL
#define USER_LOW_LIMIT_ADDR     (USER_LOW_BASE_ADDR + (4ULL * 1024ULL * 1024ULL))
#define USER_TEXT_BASE_ADDR     X86_USER_INTERP_BASE
#define USER_TEXT_LIMIT_ADDR    (USER_TEXT_BASE_ADDR + X86_USER_FIXED_WINDOW_SIZE)
#define USER_BIGPIE_BASE_ADDR   X86_USER_BIGPIE_BASE
#define USER_BIGPIE_LIMIT_ADDR  (USER_BIGPIE_BASE_ADDR + X86_USER_BIGPIE_SIZE)

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

typedef union {
    elf64_ehdr_t elf64;
    elf32_ehdr_t elf32;
    uint8_t bytes[ELF64_EHDR_SIZE];
} edge_elf_ehdr_storage_t;

typedef struct {
    uint16_t type;
    uint16_t machine;
    uint64_t entry;
    uint64_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    edge_linux_task_abi_t linux_abi;
} edge_elf_header_t;

typedef struct {
    uint64_t load_bias;
    uint64_t entry;
    uint64_t phdr;
    uint64_t phnum;
    uint64_t load_hi;
    uint64_t interp_off;
    uint64_t interp_sz;
    uint8_t has_interp;
    uint16_t phent;
    edge_linux_task_abi_t linux_abi;
    char interp_path[256];
} edge_elf_loaded_t;

typedef struct {
    volatile int busy;
    elf64_phdr_t phdr[ELF_MAX_PHNUM];
    uint8_t io_chunk[ELF_IO_CHUNK];
} elf_load_workspace_t;

#define ELF_LOAD_WORKSPACES 16
static elf_load_workspace_t g_elf_load_workspaces[ELF_LOAD_WORKSPACES];

static elf_load_workspace_t *elf_workspace_acquire(void) {
    uint64_t wait_start_us = 0;
    uint64_t next_log_us = 0;
    int log_budget = 8;
    for (;;) {
        for (int i = 0; i < ELF_LOAD_WORKSPACES; ++i) {
            if (!__sync_lock_test_and_set(&g_elf_load_workspaces[i].busy, 1)) {
                if (wait_start_us && log_budget > 0) {
                    task_t *cur = process_current_task();
                    uint64_t waited = boottime_monotonic_us() - wait_start_us;
                    printf("[elf-ws] acquired pid=%d cmd=%s slot=%d wait_us=%u\n",
                           cur ? cur->pid : -1,
                           cur ? cur->name : "-",
                           i,
                           (unsigned)waited);
                }
                return &g_elf_load_workspaces[i];
            }
        }
        if (!wait_start_us) {
            wait_start_us = boottime_monotonic_us();
            next_log_us = wait_start_us + 500000ull;
        } else {
            uint64_t now = boottime_monotonic_us();
            if (log_budget > 0 && now >= next_log_us) {
                task_t *cur = process_current_task();
                log_budget--;
                printf("[elf-ws] wait pid=%d cmd=%s wait_us=%u busy=%d\n",
                       cur ? cur->pid : -1,
                       cur ? cur->name : "-",
                       (unsigned)(now - wait_start_us),
                       ELF_LOAD_WORKSPACES);
                next_log_us = now + 500000ull;
            }
        }
        if (process_current_task()) scheduler_yield();
        else elf_cpu_relax();
    }
}

static void elf_workspace_release(elf_load_workspace_t *ws) {
    if (ws) __sync_lock_release(&ws->busy);
}

#ifndef EDGE_ELF_XORG_TRACE
#define EDGE_ELF_XORG_TRACE 0
#endif

static int elf_debug_is_xorg_path(const char *path) {
    if (!path) return 0;
    return strcmp(path, "/usr/libexec/Xorg") == 0 || strcmp(path, "/usr/bin/Xorg") == 0;
}

static void elf_debug_dump_xorg_hash(const char *tag) {
    const volatile uint32_t *h = (const volatile uint32_t *)(uintptr_t)0x0000000000400388ULL;
    printf("[elf-xorg] %s hash=%x %x %x %x %x %x %x %x\n",
           tag ? tag : "?",
           h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
}

static int elf_magic_valid(const unsigned char *ident) {
    return ident && ident[0] == 0x7f && ident[1] == 'E' &&
        ident[2] == 'L' && ident[3] == 'F';
}

static int elf_header_read(vfs_superblock_t *superblock, vfs_inode_t *inode,
                           edge_elf_header_t *header) {
    edge_elf_ehdr_storage_t storage;
    uint32_t header_size;

    if (!superblock || !inode || !header || inode->size < ELF32_EHDR_SIZE)
        return -1;
    memset(&storage, 0, sizeof(storage));
    if (vfs_read_inode_exact(
            superblock, inode, 0, storage.bytes, 16u) < 0 ||
        !elf_magic_valid(storage.bytes))
        return -1;
#if defined(__x86_64__)
    if (storage.bytes[4] == 1u) {
#if defined(CONFIG_X86_X32_ABI) || defined(CONFIG_COMPAT_IA32)
        header_size = ELF32_EHDR_SIZE;
#else
        return -1;
#endif
    } else
#endif
    if (storage.bytes[4] == 2u) {
        header_size = ELF64_EHDR_SIZE;
    } else {
        return -1;
    }
    if (inode->size < header_size ||
        vfs_read_inode_exact(
            superblock, inode, 0, storage.bytes, header_size) < 0)
        return -1;
    memset(header, 0, sizeof(*header));
    if (storage.bytes[4] == 1u) {
        header->type = storage.elf32.e_type;
        header->machine = storage.elf32.e_machine;
        header->entry = storage.elf32.e_entry;
        header->phoff = storage.elf32.e_phoff;
        header->phentsize = storage.elf32.e_phentsize;
        header->phnum = storage.elf32.e_phnum;
        if (header->machine == 62u) {
#ifdef CONFIG_X86_X32_ABI
            header->linux_abi = EDGE_LINUX_TASK_ABI_X32;
#else
            return -1;
#endif
        } else if (header->machine == 3u) {
#ifdef CONFIG_COMPAT_IA32
            header->linux_abi = EDGE_LINUX_TASK_ABI_IA32;
#else
            return -1;
#endif
        } else {
            return -1;
        }
    } else {
        header->type = storage.elf64.e_type;
        header->machine = storage.elf64.e_machine;
        header->entry = storage.elf64.e_entry;
        header->phoff = storage.elf64.e_phoff;
        header->phentsize = storage.elf64.e_phentsize;
        header->phnum = storage.elf64.e_phnum;
        header->linux_abi = EDGE_LINUX_TASK_ABI_NATIVE64;
    }
    if ((header->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64 &&
         header->machine != 62u) ||
        (header->type != ET_EXEC && header->type != ET_DYN) ||
        (header->linux_abi != EDGE_LINUX_TASK_ABI_NATIVE64 &&
         header->phentsize != ELF32_PHDR_SIZE) ||
        (header->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64 &&
         header->phentsize != ELF64_PHDR_SIZE) ||
        !header->phnum || header->phnum > ELF_MAX_PHNUM)
        return -1;
    return 0;
}

static int elf_program_headers_read(vfs_superblock_t *superblock,
                                    vfs_inode_t *inode,
                                    const edge_elf_header_t *header,
                                    elf64_phdr_t *program_headers) {
    uint64_t bytes;

    if (!superblock || !inode || !header || !program_headers) return -1;
    bytes = (uint64_t)header->phnum * header->phentsize;
    if (header->phoff > inode->size || bytes > inode->size - header->phoff)
        return -1;
    if (header->linux_abi == EDGE_LINUX_TASK_ABI_NATIVE64)
        return vfs_read_inode_exact(
            superblock, inode, (uint32_t)header->phoff,
            program_headers, (uint32_t)bytes);
    for (uint16_t index = 0; index < header->phnum; ++index) {
        elf32_phdr_t compat;
        uint64_t offset = header->phoff +
            (uint64_t)index * ELF32_PHDR_SIZE;
        if (vfs_read_inode_exact(
                superblock, inode, (uint32_t)offset,
                &compat, sizeof(compat)) < 0)
            return -1;
        program_headers[index].p_type = compat.p_type;
        program_headers[index].p_flags = compat.p_flags;
        program_headers[index].p_offset = compat.p_offset;
        program_headers[index].p_vaddr = compat.p_vaddr;
        program_headers[index].p_paddr = compat.p_paddr;
        program_headers[index].p_filesz = compat.p_filesz;
        program_headers[index].p_memsz = compat.p_memsz;
        program_headers[index].p_align = compat.p_align;
    }
    return 0;
}

static int user_addr_range_ok(uint64_t addr, uint64_t len) {
    if (addr < USER_ADDR_MIN) return 0;
    if (addr >= USER_ADDR_MAX) return 0;
    if (len == 0) return 1;
    if (addr + len < addr) return 0;
    if (addr + len > USER_ADDR_MAX) return 0;
    return 1;
}

static int elf_write_user(int pid, uint64_t addr, const void *in, uint64_t len) {
    if (!user_addr_range_ok(addr, len)) return -1;
    return process_write_user_memory(pid, addr, in, len);
}

static uint64_t page_align_down_u64(uint64_t v) {
    return v & ~0xFFFULL;
}

static uint64_t page_align_up_u64(uint64_t v) {
    return (v + 0xFFFULL) & ~0xFFFULL;
}

static int elf_et_dyn_layout(const elf64_phdr_t *ph, uint16_t phnum,
                             uint64_t *min_vaddr_out, uint64_t *max_vaddr_out) {
    uint64_t min_vaddr = ~0ULL;
    uint64_t max_vaddr = 0;
    int saw_load = 0;

    if (!ph || !min_vaddr_out || !max_vaddr_out) return -1;
    for (uint16_t i = 0; i < phnum; ++i) {
        uint64_t seg_lo;
        uint64_t seg_hi;
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_memsz == 0) continue;
        seg_lo = page_align_down_u64(ph[i].p_vaddr);
        if (ph[i].p_vaddr + ph[i].p_memsz < ph[i].p_vaddr) return -1;
        seg_hi = page_align_up_u64(ph[i].p_vaddr + ph[i].p_memsz);
        if (!saw_load || seg_lo < min_vaddr) min_vaddr = seg_lo;
        if (!saw_load || seg_hi > max_vaddr) max_vaddr = seg_hi;
        saw_load = 1;
    }
    if (!saw_load || max_vaddr < min_vaddr) return -1;
    *min_vaddr_out = min_vaddr;
    *max_vaddr_out = max_vaddr;
    return 0;
}

static int elf_pick_et_dyn_bias(const elf64_phdr_t *ph, uint16_t phnum,
                                uint64_t window_base, uint64_t window_limit,
                                uint64_t *load_bias_out) {
    uint64_t min_vaddr;
    uint64_t max_vaddr;
    uint64_t span;

    if (!load_bias_out) return -1;
    if (elf_et_dyn_layout(ph, phnum, &min_vaddr, &max_vaddr) < 0) return -1;
    span = max_vaddr - min_vaddr;
    if (window_limit <= window_base) return -1;
    if (span > (window_limit - window_base)) return -1;

    *load_bias_out = window_base - min_vaddr;
    return 0;
}

static int vfs_pread_exact(vfs_superblock_t *sb, vfs_inode_t *ino, uint32_t off, void *buf, uint32_t len) {
    return vfs_read_inode_exact(sb, ino, off, buf, len);
}

static int edge_load_elf_from_vfs(
    int target_pid, const char *path, vfs_superblock_t *supplied_superblock,
    const vfs_inode_t *supplied_inode, uint64_t et_dyn_base,
    edge_elf_loaded_t *out) {
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    edge_elf_header_t eh;
    elf_load_workspace_t *ws;
    elf64_phdr_t *ph;
    uint8_t *io_chunk;
    uint64_t load_bias;
    uint64_t ph_bytes;
    uint64_t load_hi = 0;
    int ret = -1;

    if (!path || !out) return -1;
    ws = elf_workspace_acquire();
    ph = ws->phdr;
    io_chunk = ws->io_chunk;
    if (supplied_inode) {
        if (!supplied_superblock) goto out_release;
        ino = *supplied_inode;
        sb = supplied_superblock;
    } else if (vfs_resolve(path, &ino, &sb, 0, 0) < 0) {
        printf("[elf][err] resolve %s\n", path);
        goto out_release;
    }
    if ((ino.mode & 0xF000u) == VFS_INODE_DIR) { printf("[elf][err] dir %s\n", path); goto out_release; }
    if (elf_header_read(sb, &ino, &eh) < 0) {
        printf("[elf][err] invalid ehdr %s\n", path);
        goto out_release;
    }
    ph_bytes = (uint64_t)eh.phnum * eh.phentsize;
    if (elf_program_headers_read(sb, &ino, &eh, ph) < 0) {
        printf("[elf][err] read phdr %s\n", path);
        goto out_release;
    }

    load_bias = 0;
    if (eh.type == ET_DYN) {
        if (et_dyn_base == EDGE_MAIN_ET_DYN_BASE) {
            if (elf_pick_et_dyn_bias(ph, eh.phnum,
                                     USER_LOW_BASE_ADDR, USER_LOW_LIMIT_ADDR,
                                     &load_bias) < 0) {
                if (elf_pick_et_dyn_bias(ph, eh.phnum,
                                         USER_BIGPIE_BASE_ADDR, USER_BIGPIE_LIMIT_ADDR,
                                         &load_bias) < 0) {
                    printf("[elf][err] dyn layout %s main span too large\n", path);
                    goto out_release;
                }
            }
        } else if (et_dyn_base == EDGE_INTERP_ET_DYN_BASE) {
            if (elf_pick_et_dyn_bias(ph, eh.phnum,
                                     USER_TEXT_BASE_ADDR, USER_TEXT_LIMIT_ADDR,
                                     &load_bias) < 0) {
                printf("[elf][err] dyn layout %s interp span too large\n", path);
                goto out_release;
            }
        } else {
            uint64_t min_vaddr;
            uint64_t max_vaddr;
            if (elf_et_dyn_layout(ph, eh.phnum, &min_vaddr, &max_vaddr) < 0) {
                printf("[elf][err] dyn layout %s invalid\n", path);
                goto out_release;
            }
            load_bias = et_dyn_base - min_vaddr;
        }
    }

    for (uint16_t i = 0; i < eh.phnum; ++i) {
        uint64_t dst;
        uint64_t end;
        uint64_t file_end;
        uint64_t full_file_start;
        uint64_t full_file_end;
        uint64_t anonymous_start;
        uint32_t protection = 0;
        if (ph[i].p_type != PT_LOAD) continue;
        if (!edge_elf_file_range_valid(
                (uint64_t)ino.size, ph[i].p_offset, ph[i].p_filesz)) {
            printf("[elf][err] seg file range %s i=%u\n", path, i);
            goto out_release;
        }
        if (ph[i].p_memsz < ph[i].p_filesz) { printf("[elf][err] seg mem<file %s i=%u\n", path, i); goto out_release; }
        /*
         * A zero-length PT_LOAD contributes no mapping.  Linux accepts and
         * ignores these records, which linkers may emit for an empty data
         * segment.  Validate its file range first, then skip address checks:
         * virtual address zero is harmless when no byte is mapped.
         */
        if (ph[i].p_memsz == 0) continue;
        dst = load_bias + ph[i].p_vaddr;
        if (!user_addr_range_ok(dst, ph[i].p_memsz)) { printf("[elf][err] seg addr %s i=%u dst=0x%x mem=0x%x bias=0x%x\n", path, i, (uint32_t)dst, (uint32_t)ph[i].p_memsz, (uint32_t)load_bias); goto out_release; }
        end = dst + ph[i].p_memsz;
        if (end < dst) { printf("[elf][err] seg end ovf %s i=%u\n", path, i); goto out_release; }
        if (eh.linux_abi != EDGE_LINUX_TASK_ABI_NATIVE64 &&
            end > UINT64_C(0x100000000)) {
            printf("[elf][err] compat seg above 4G %s i=%u\n", path, i);
            goto out_release;
        }
        if (end > load_hi) load_hi = end;
        file_end = dst + ph[i].p_filesz;
        if (file_end < dst) { printf("[elf][err] seg file end ovf %s i=%u\n", path, i); goto out_release; }
        if (ph[i].p_flags & PF_R) protection |= 0x1u;
        if (ph[i].p_flags & PF_W) protection |= 0x2u;
        if (ph[i].p_flags & PF_X) protection |= 0x4u;

        /*
         * Linux installs complete PT_LOAD file pages as private file VMAs and
         * reads them on the first fault.  Eagerly copying a browser's complete
         * executable consumes hundreds of MiB and blocks exec for seconds even
         * though most code is never touched.  Keep partial boundary pages
         * private and eager because bytes outside p_filesz must be zero rather
         * than exposing adjacent file contents.
         */
        full_file_start = page_align_up_u64(dst);
        if ((dst & 0xFFFULL) == 0) full_file_start = dst;
        full_file_end = page_align_down_u64(file_end);
        if (full_file_end > full_file_start) {
            uint64_t file_offset = ph[i].p_offset + full_file_start - dst;
            uint64_t length = full_file_end - full_file_start;
            if (process_user_fixed_reserve_pid(
                    target_pid, full_file_start, length) < 0 ||
                process_user_elf_map_inode_pid(
                    target_pid, path, &ino, sb, full_file_start,
                    length, file_offset, protection) < 0) {
                printf("[elf][err] demand map %s i=%u dst=0x%x len=0x%x off=0x%x\n",
                       path, i, (uint32_t)full_file_start,
                       (uint32_t)length, (uint32_t)file_offset);
                goto out_release;
            }
        }

        if (ph[i].p_filesz != 0) {
            uint64_t first_page = page_align_down_u64(dst);
            uint64_t last_page = page_align_down_u64(file_end - 1ULL);
            uint64_t boundary[2];
            uint32_t boundary_count = 0;

            if ((dst & 0xFFFULL) != 0 || first_page == last_page)
                boundary[boundary_count++] = first_page;
            if ((file_end & 0xFFFULL) != 0 &&
                (boundary_count == 0 || boundary[boundary_count - 1] != last_page))
                boundary[boundary_count++] = last_page;
            for (uint32_t boundary_index = 0;
                 boundary_index < boundary_count; ++boundary_index) {
                uint64_t page = boundary[boundary_index];
                uint64_t copy_start = page > dst ? page : dst;
                uint64_t copy_end = page + 0x1000ULL < file_end ?
                                    page + 0x1000ULL : file_end;
                uint64_t file_offset =
                    ph[i].p_offset + copy_start - dst;
                uint32_t bytes = (uint32_t)(copy_end - copy_start);

                if (process_user_fixed_map_pid(target_pid, page, 0x1000ULL) < 0 ||
                    process_user_elf_map_anon_pid(
                        target_pid, page, 0x1000ULL, protection) < 0 ||
                    vfs_pread_exact(sb, &ino, (uint32_t)file_offset,
                                    io_chunk, bytes) < 0 ||
                    elf_write_user(target_pid, copy_start, io_chunk, bytes) < 0) {
                    printf("[elf][err] boundary load %s i=%u page=0x%x off=0x%x n=0x%x\n",
                           path, i, (uint32_t)page,
                           (uint32_t)file_offset, bytes);
                    goto out_release;
                }
            }
        } else if ((dst & 0xFFFULL) != 0) {
            if (process_user_fixed_map_pid(
                    target_pid, page_align_down_u64(dst), 0x1000ULL) < 0 ||
                process_user_elf_map_anon_pid(
                    target_pid, page_align_down_u64(dst), 0x1000ULL,
                    protection) < 0) {
                printf("[elf][err] zero boundary map %s i=%u dst=0x%x\n",
                       path, i, (uint32_t)dst);
                goto out_release;
            }
        }

        anonymous_start = page_align_up_u64(file_end > dst ? file_end : dst);
        if (ph[i].p_filesz == 0 && (dst & 0xFFFULL) == 0)
            anonymous_start = dst;
        if (page_align_up_u64(end) > anonymous_start &&
            (process_user_fixed_map_pid(
                 target_pid, anonymous_start,
                 page_align_up_u64(end) - anonymous_start) < 0 ||
             process_user_elf_map_anon_pid(
                 target_pid, anonymous_start,
                 page_align_up_u64(end) - anonymous_start,
                 protection) < 0)) {
            printf("[elf][err] zero map %s i=%u dst=0x%x len=0x%x\n",
                   path, i, (uint32_t)anonymous_start,
                   (uint32_t)(page_align_up_u64(end) - anonymous_start));
            goto out_release;
        }
    }

    /*
     * EdgeOS fixed executable windows historically started writable and relied
     * on later mprotect(2) calls to approximate Linux segment permissions.
     * That is too late for dynamic loaders: read-only PT_LOAD metadata such as
     * .gnu.hash must not remain writable while dependency relocation runs.
     *
     * Apply the final fixed-window permissions at page granularity.  ELF
     * PT_LOAD segments can share a boundary page after page rounding; if any
     * load segment covering that page is writable, Linux userspace must see a
     * writable page until a later mprotect/RELRO operation changes it.  A
     * segment-by-segment pass can otherwise make the boundary page read-only
     * just because an adjacent RX segment rounded into the same page.
     */
    for (uint16_t i = 0; i < eh.phnum; ++i) {
        uint64_t start;
        uint64_t end;
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0) continue;
        if (ph[i].p_vaddr + ph[i].p_memsz < ph[i].p_vaddr) continue;
        start = page_align_down_u64(load_bias + ph[i].p_vaddr);
        end = page_align_up_u64(load_bias + ph[i].p_vaddr + ph[i].p_memsz);
        if (end <= start) continue;
        for (uint64_t va = start; va < end; va += 0x1000ULL) {
            uint32_t prot = 0;
            for (uint16_t j = 0; j < eh.phnum; ++j) {
                uint64_t j_start;
                uint64_t j_end;
                if (ph[j].p_type != PT_LOAD || ph[j].p_memsz == 0) continue;
                if (ph[j].p_vaddr + ph[j].p_memsz < ph[j].p_vaddr) continue;
                j_start = page_align_down_u64(load_bias + ph[j].p_vaddr);
                j_end = page_align_up_u64(load_bias + ph[j].p_vaddr + ph[j].p_memsz);
                if (j_end <= j_start) continue;
                if (va >= j_start && va < j_end && (ph[j].p_flags & PF_W)) {
                    prot = 0x2u;
                    break;
                }
            }
            (void)process_user_fixed_mprotect_pid(target_pid, va, 0x1000ULL,
                                                  prot);
        }
    }

    memset(out, 0, sizeof(*out));
    out->load_bias = load_bias;
    out->entry = load_bias + eh.entry;
    out->phdr = 0;
    out->phnum = eh.phnum;
    out->load_hi = load_hi;
    out->phent = eh.phentsize;
    out->linux_abi = eh.linux_abi;
    if (out->linux_abi != EDGE_LINUX_TASK_ABI_NATIVE64 &&
        (out->entry > UINT32_MAX || load_hi > UINT64_C(0x100000000))) {
        printf("[elf][err] compat entry above 4G %s\n", path);
        goto out_release;
    }

    for (uint16_t i = 0; i < eh.phnum; ++i) {
        if (ph[i].p_type == PT_PHDR) out->phdr = load_bias + ph[i].p_vaddr;
        if (ph[i].p_type != PT_INTERP) continue;
        out->has_interp = 1;
        out->interp_off = ph[i].p_offset;
        out->interp_sz = ph[i].p_filesz;
        if (ph[i].p_filesz < 2 || ph[i].p_filesz >= sizeof(out->interp_path)) { printf("[elf][err] interp size %s\n", path); goto out_release; }
        if (!edge_elf_file_range_valid(
                (uint64_t)ino.size, ph[i].p_offset, ph[i].p_filesz)) {
            printf("[elf][err] interp range %s\n", path);
            goto out_release;
        }
        if (vfs_pread_exact(sb, &ino, (uint32_t)ph[i].p_offset, out->interp_path, (uint32_t)ph[i].p_filesz) < 0) { printf("[elf][err] interp read %s\n", path); goto out_release; }
        out->interp_path[ph[i].p_filesz - 1] = 0;
    }
    if (!out->phdr) {
        for (uint16_t i = 0; i < eh.phnum; ++i) {
            if (ph[i].p_type != PT_LOAD) continue;
            if (eh.phoff < ph[i].p_offset) continue;
            if (eh.phoff + ph_bytes > ph[i].p_offset + ph[i].p_filesz) continue;
            out->phdr = load_bias + ph[i].p_vaddr + (eh.phoff - ph[i].p_offset);
            break;
        }
    }
    if (!out->phdr) { printf("[elf][err] no phdr %s\n", path); goto out_release; }
    ret = 0;

out_release:
    elf_workspace_release(ws);
    return ret;
}

int elf_loader_probe(const char *path) {
    edge_elf_header_t header;
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    if (!path || vfs_resolve(path, &inode, &superblock, 0, 0) < 0)
        return -1;
    return elf_header_read(superblock, &inode, &header);
}

int elf_loader_probe_inode(vfs_superblock_t *superblock,
                           const vfs_inode_t *inode) {
    edge_elf_header_t header;
    vfs_inode_t source;
    if (!superblock || !inode) return -1;
    source = *inode;
    return elf_header_read(superblock, &source, &header);
}

static int elf_loader_exec_source(
    int target_pid, const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, edge_elf_image_t *out) {
    edge_elf_loaded_t main_img;
    edge_elf_loaded_t interp_img;

    if (!path || !out) return -1;
    if (edge_load_elf_from_vfs(
            target_pid, path, superblock, inode,
            EDGE_MAIN_ET_DYN_BASE, &main_img) < 0) {
        printf("[elf][err] main load failed %s\n", path);
        return -1;
    }
    if (EDGE_ELF_XORG_TRACE && elf_debug_is_xorg_path(path)) {
        printf("[elf-xorg] main entry=0x%x phdr=0x%x phnum=%u hi=0x%x bias=0x%x interp=%s\n",
               (uint32_t)main_img.entry, (uint32_t)main_img.phdr, (uint32_t)main_img.phnum,
               (uint32_t)main_img.load_hi, (uint32_t)main_img.load_bias,
               main_img.has_interp ? main_img.interp_path : "-");
        elf_debug_dump_xorg_hash("after-main");
    }

    memset(out, 0, sizeof(*out));
    out->entry_rip = main_img.entry;
    out->at_phdr = main_img.phdr;
    out->at_phnum = main_img.phnum;
    out->at_entry = main_img.entry;
    out->at_base = 0;
    out->main_load_hi = main_img.load_hi;
    out->at_phent = main_img.phent;
    out->linux_abi = main_img.linux_abi;

    if (!main_img.has_interp) {
        /*
         * Linux exec never applies userspace dynamic relocations in the
         * kernel.  A static PIE has no PT_INTERP because its CRT relocates the
         * image before entering libc; pre-relocating it here makes RELA/RELR
         * slots receive the load bias twice.  Dynamically linked executables
         * are relocated by their PT_INTERP loader for the same reason.
         */
        return 0;
    }
    if (main_img.interp_path[0] != '/') { printf("[elf][err] bad interp path %s\n", path); return -1; }
    if (edge_load_elf_from_vfs(
            target_pid, main_img.interp_path, 0, 0,
            EDGE_INTERP_ET_DYN_BASE, &interp_img) < 0) {
        printf("[elf][err] interp load failed %s -> %s\n", path, main_img.interp_path);
        return -1;
    }
    if (interp_img.linux_abi != main_img.linux_abi) {
        printf("[elf][err] interp ABI mismatch %s -> %s\n",
               path, main_img.interp_path);
        return -1;
    }
    if (EDGE_ELF_XORG_TRACE && elf_debug_is_xorg_path(path)) {
        printf("[elf-xorg] interp entry=0x%x base=0x%x phdr=0x%x hi=0x%x\n",
               (uint32_t)interp_img.entry, (uint32_t)interp_img.load_bias,
               (uint32_t)interp_img.phdr, (uint32_t)interp_img.load_hi);
        elf_debug_dump_xorg_hash("after-interp");
    }

    out->entry_rip = interp_img.entry;
    out->at_base = interp_img.load_bias;
    return 0;
}

int elf_loader_exec_into(int target_pid, const char *path,
                         edge_elf_image_t *out) {
    return elf_loader_exec_source(target_pid, path, 0, 0, out);
}

int elf_loader_exec(const char *path, edge_elf_image_t *out) {
    return elf_loader_exec_into(process_getpid(), path, out);
}

int elf_loader_exec_inode(vfs_superblock_t *superblock,
                          const vfs_inode_t *inode, const char *display_path,
                          edge_elf_image_t *out) {
    return elf_loader_exec_source(
        process_getpid(), display_path, superblock, inode, out);
}
