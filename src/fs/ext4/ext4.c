#include "ext4/ext4.h"

#include "block/block.h"
#include "kernel/boot_command_line.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "vfs/vfs.h"

static inline void ext4_cpu_relax(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield" ::: "memory");
#else
#error "ext4_cpu_relax needs an architecture implementation"
#endif
}

static void ext4_current_fs_identity(uint32_t *uid, uint32_t *gid) {
    uint32_t current_uid = 0;
    uint32_t current_gid = 0;
    (void)kernel_current_identity(0, &current_uid, &current_gid);
    if (uid) *uid = current_uid;
    if (gid) *gid = current_gid;
}
#define EXT4_LOOKUP_CACHE_BUCKETS 256u
#define EXT4_DIRECTORY_INDEX_SLOTS 256u
#define EXT4_BLOCK_CACHE_SLOTS 128u
#define EXT4_INODE_CACHE_BUCKETS 256u
#define EXT4_READDIR_CACHE_SLOTS 128u
#define EXT4_READ_RUN_BLOCKS 128u
#define EXT4_RO_WORKSPACES 32u
#define EXT4_PARALLEL_READ_MIN (64u * 1024u)
#define EXT4_CACHE_PAGE_SIZE 4096u
#define EXT4_MAX_EXTENT_DEPTH 5u

#pragma pack(push,1)
typedef struct {
    uint32_t inodes_count, blocks_count_lo, r_blocks_count_lo, free_blocks_count_lo;
    uint32_t free_inodes_count, first_data_block, log_block_size, log_frag_size;
    uint32_t blocks_per_group, frags_per_group, inodes_per_group;
    uint32_t mtime, wtime;
    uint16_t mnt_count, max_mnt_count, magic, state, errors, minor_rev_level;
    uint32_t lastcheck, checkinterval, creator_os, rev_level;
    uint16_t def_resuid, def_resgid;
    uint32_t first_ino;
    uint16_t inode_size;
    uint16_t block_group_nr;
    uint32_t feature_compat;
    uint32_t feature_incompat;
    uint32_t feature_ro_compat;
} ext4_super_t;

typedef struct {
    uint32_t block_bitmap_lo, inode_bitmap_lo, inode_table_lo;
    uint16_t free_blocks_count_lo, free_inodes_count_lo, used_dirs_count_lo;
    uint16_t flags;
    uint32_t exclude_bitmap_lo;
    uint16_t block_bitmap_csum_lo;
    uint16_t inode_bitmap_csum_lo;
    uint16_t itable_unused_lo;
    uint16_t checksum;
} ext4_bgdesc_t;

typedef struct {
    uint16_t mode, uid;
    uint32_t size_lo, atime, ctime, mtime, dtime;
    uint16_t gid, links_count;
    uint32_t blocks_lo, flags, osd1;
    uint32_t block[15];
    uint32_t generation, file_acl_lo, size_high, obso_faddr;
    uint8_t osd2[12];
} ext4_inode_t;

typedef struct {
    uint16_t eh_magic;
    uint16_t eh_entries;
    uint16_t eh_max;
    uint16_t eh_depth;
    uint32_t eh_generation;
} ext4_extent_header_t;

typedef struct {
    uint32_t ee_block;
    uint16_t ee_len;
    uint16_t ee_start_hi;
    uint32_t ee_start_lo;
} ext4_extent_t;

typedef struct {
    uint32_t ei_block;
    uint32_t ei_leaf_lo;
    uint16_t ei_leaf_hi;
    uint16_t ei_unused;
} ext4_extent_idx_t;

typedef struct {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    uint8_t name[];
} ext4_dirent_t;

typedef struct {
    uint32_t magic;
    uint32_t refcount;
    uint32_t blocks;
    uint32_t hash;
    uint32_t checksum;
    uint32_t reserved[3];
} ext4_xattr_header_t;

typedef struct {
    uint8_t name_len;
    uint8_t name_index;
    uint16_t value_offs;
    uint32_t value_block;
    uint32_t value_size;
    uint32_t hash;
    char name[];
} ext4_xattr_entry_t;
#pragma pack(pop)

/* Linux ext2/ext4 stores the upper UID/GID halves in the Linux osd2 area. */
static uint16_t ext4_inode_osd2_u16(const ext4_inode_t *inode,
                                    uint32_t offset) {
    return (uint16_t)((uint16_t)inode->osd2[offset] |
                      ((uint16_t)inode->osd2[offset + 1u] << 8));
}

static void ext4_inode_osd2_set_u16(ext4_inode_t *inode, uint32_t offset,
                                    uint16_t value) {
    inode->osd2[offset] = (uint8_t)value;
    inode->osd2[offset + 1u] = (uint8_t)(value >> 8);
}

static uint32_t ext4_inode_uid(const ext4_inode_t *inode) {
    return (uint32_t)inode->uid |
           ((uint32_t)ext4_inode_osd2_u16(inode, 4u) << 16);
}

static uint32_t ext4_inode_gid(const ext4_inode_t *inode) {
    return (uint32_t)inode->gid |
           ((uint32_t)ext4_inode_osd2_u16(inode, 6u) << 16);
}

static void ext4_inode_set_uid(ext4_inode_t *inode, uint32_t uid) {
    inode->uid = (uint16_t)uid;
    ext4_inode_osd2_set_u16(inode, 4u, (uint16_t)(uid >> 16));
}

static void ext4_inode_set_gid(ext4_inode_t *inode, uint32_t gid) {
    inode->gid = (uint16_t)gid;
    ext4_inode_osd2_set_u16(inode, 6u, (uint16_t)(gid >> 16));
}

typedef struct {
    uint8_t valid;
    uint8_t pad[3];
    uint32_t dir_ino;
    uint32_t dir_size;
    uint32_t next_idx;
    uint32_t next_block_index;
    uint32_t next_block_offset;
    uint32_t age;
} ext4_readdir_cache_entry_t;

typedef struct {
    uint8_t valid;
    uint8_t pad[3];
    uint32_t dir_ino;
    uint32_t dir_size;
    uint32_t age;
} ext4_directory_index_entry_t;

typedef struct ext4_inode_cache_page ext4_inode_cache_page_t;
typedef struct ext4_inode_cache_entry {
    struct ext4_inode_cache_entry *next;
    ext4_inode_cache_page_t *owner;
    uint8_t valid;
    uint8_t pad[3];
    uint32_t ino;
    uint32_t age;
    ext4_inode_t inode;
} ext4_inode_cache_entry_t;

struct ext4_inode_cache_page {
    ext4_inode_cache_page_t *next;
    uint16_t capacity;
    uint16_t live;
    ext4_inode_cache_entry_t entries[];
};

typedef struct ext4_lookup_cache_page ext4_lookup_cache_page_t;
typedef struct ext4_lookup_cache_entry {
    struct ext4_lookup_cache_entry *next;
    ext4_lookup_cache_page_t *owner;
    uint8_t valid;
    uint8_t miss;
    uint16_t pad;
    uint32_t dir_ino;
    uint32_t child_ino;
    uint32_t dir_block;
    uint32_t dir_offset;
    uint32_t age;
    char name[VFS_NAME_MAX];
} ext4_lookup_cache_entry_t;

struct ext4_lookup_cache_page {
    ext4_lookup_cache_page_t *next;
    uint16_t capacity;
    uint16_t live;
    ext4_lookup_cache_entry_t entries[];
};

typedef struct {
    uint32_t ino;
    uint32_t references;
    uint8_t delete_pending;
} ext4_open_inode_entry_t;

typedef struct ext4_open_inode_page ext4_open_inode_page_t;
struct ext4_open_inode_page {
    ext4_open_inode_page_t *next;
    uint16_t capacity;
    uint16_t live;
    ext4_open_inode_entry_t entries[];
};

typedef struct ext4_fs {
    struct ext4_fs *registry_next;
    uint32_t allocation_pages;
    uint32_t references;
    vfs_superblock_t lifecycle_superblock;
    block_device_t *bdev;
    /*
     * Metadata caches grow in page-sized slabs and can be reclaimed through
     * the shared VFS pressure hook.  The operation lock is still required for
     * mutable on-disk allocation state.  Each mount owns its workspaces so a
     * filesystem hosted in a loop-backed file can safely recurse through a
     * different ext4 mount without overwriting the caller's in-flight data.
     */
    volatile uint32_t op_lock;
    volatile uint32_t read_count;
    volatile uint64_t op_wait_sequence;
    uintptr_t op_lock_owner;
    int32_t op_lock_owner_pid;
    uint32_t op_lock_depth;
    ext4_super_t sb;
    ext4_bgdesc_t bg;
    uint32_t block_size;
    uint32_t desc_size;
    uint16_t inode_extra_isize;
    uint8_t meta_dirty;
    uint8_t write_session_started;
    uint8_t mount_state_was_clean;
    uint8_t shutdown_complete;
    uint32_t next_free_block_hint;
    uint32_t next_free_inode_hint;
    uint32_t bitmap_cache_block;
    uint8_t bitmap_cache_valid;
    uint8_t bitmap_cache_dirty;
    volatile uint32_t inode_cache_lock;
    uint32_t inode_cache_clock;
    ext4_inode_cache_entry_t
        *inode_cache[EXT4_INODE_CACHE_BUCKETS];
    ext4_inode_cache_page_t *inode_cache_pages;
    uint32_t inode_cache_count;
    uint32_t lookup_cache_clock;
    ext4_lookup_cache_entry_t
        *lookup_cache[EXT4_LOOKUP_CACHE_BUCKETS];
    ext4_lookup_cache_page_t *lookup_cache_pages;
    uint32_t lookup_cache_count;
    ext4_directory_index_entry_t
        directory_index[EXT4_DIRECTORY_INDEX_SLOTS];
    uint32_t directory_index_clock;
    uint32_t block_cache_clock;
    struct {
        uint8_t valid;
        uint8_t dirty;
        uint8_t pad[2];
        uint32_t block;
        uint32_t age;
        uint8_t data[4096];
    } block_cache[EXT4_BLOCK_CACHE_SLOTS];
    ext4_readdir_cache_entry_t readdir_cache[EXT4_READDIR_CACHE_SLOTS];
    uint32_t readdir_cache_clock;
    ext4_open_inode_page_t *open_inode_pages;
    uint32_t open_inode_capacity;
    /* Mutating extents is serialized by op_lock, so one path per mount is sufficient. */
    uint8_t extent_work[EXT4_MAX_EXTENT_DEPTH][4096];
    uint8_t extent_scratch[4096];
    uint8_t legacy_work[3][4096];
    uint8_t bitmap_cache[4096];
    uint8_t io[4096];
    uint8_t block_work[4096];
    uint8_t read_run[EXT4_READ_RUN_BLOCKS * 4096u];
    uint8_t writeback_run[EXT4_BLOCK_CACHE_SLOTS * 4096u];
    uint8_t xattr_inode[4096];
    uint8_t xattr_old[4096];
    uint8_t xattr_new[4096];
} ext4_fs_t;

static ext4_fs_t *g_ext4_mounts;
static volatile uint32_t g_ext4_mount_registry_lock;
typedef struct {
    volatile uint32_t busy;
    uint8_t io[4096];
    uint8_t blk[4096];
} ext4_ro_workspace_t;
static ext4_ro_workspace_t g_ro_ws[EXT4_RO_WORKSPACES];
static volatile uint32_t g_ro_ws_sequence;
static uint32_t g_ext4_slow_log_budget = 0;
static uint32_t g_ext4_badfs_log_budget = 64;

#define EXT4_EXTENTS_FL 0x00080000u
#define EXT4_EXT_MAGIC  0xF30Au
#define EXT4_VALID_FS   0x0001u
#define EXT4_ERROR_FS   0x0002u
#define EXT4_XATTR_MAGIC 0xEA020000u
#define EXT4_XATTR_INDEX_USER 1u
#define EXT4_XATTR_INDEX_POSIX_ACL_ACCESS 2u
#define EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT 3u
#define EXT4_XATTR_INDEX_TRUSTED 4u
#define EXT4_XATTR_INDEX_SECURITY 6u
#define EXT4_XATTR_INDEX_SYSTEM 7u
#define EXT4_XATTR_INDEX_RICHACL 8u

#define EXT4_INCOMPAT_FILETYPE      0x0002u
#define EXT4_INCOMPAT_EXTENTS       0x0040u
#define EXT4_INCOMPAT_64BIT         0x0080u
#define EXT4_INCOMPAT_MMP           0x0100u
#define EXT4_INCOMPAT_FLEX_BG       0x0200u
#define EXT4_INCOMPAT_EA_INODE      0x0400u
#define EXT4_INCOMPAT_DIRDATA       0x1000u
#define EXT4_INCOMPAT_CSUM_SEED     0x2000u
#define EXT4_INCOMPAT_LARGEDIR      0x4000u
#define EXT4_INCOMPAT_INLINE_DATA   0x8000u
#define EXT4_INCOMPAT_ENCRYPT       0x10000u
#define EXT4_INCOMPAT_CASEFOLD      0x20000u

#define EXT4_RO_COMPAT_SPARSE_SUPER 0x0001u
#define EXT4_RO_COMPAT_LARGE_FILE   0x0002u
#define EXT4_RO_COMPAT_BTREE_DIR    0x0004u
#define EXT4_RO_COMPAT_HUGE_FILE    0x0008u
#define EXT4_RO_COMPAT_GDT_CSUM     0x0010u
#define EXT4_RO_COMPAT_DIR_NLINK    0x0020u
#define EXT4_RO_COMPAT_EXTRA_ISIZE  0x0040u
#define EXT4_RO_COMPAT_QUOTA        0x0100u
#define EXT4_RO_COMPAT_BIGALLOC     0x0200u
#define EXT4_RO_COMPAT_METADATA_CSUM 0x0400u
#define EXT4_RO_COMPAT_REPLICA      0x0800u
#define EXT4_RO_COMPAT_READONLY     0x1000u
#define EXT4_RO_COMPAT_PROJECT      0x2000u
#define EXT4_RO_COMPAT_VERITY       0x8000u
#define EXT4_RO_COMPAT_ORPHAN_PRESENT 0x10000u
#define EXT4_SUPER_MIN_EXTRA_ISIZE_OFFSET 0x15cu
#define EXT4_SUPER_WANT_EXTRA_ISIZE_OFFSET 0x15eu
#ifndef EXT4_DEBUG
#define EXT4_DEBUG 0
#endif
#define EXT4_DBG(...) do { if (EXT4_DEBUG) printf(__VA_ARGS__); } while (0)

static uint16_t rec_len_min(uint8_t name_len) { return (uint16_t)((8 + name_len + 3) & ~3); }

static void ext4_mount_registry_lock(void) {
    while (__atomic_exchange_n(&g_ext4_mount_registry_lock, 1u,
                               __ATOMIC_ACQUIRE))
        ext4_cpu_relax();
}

static void ext4_mount_registry_unlock(void) {
    __atomic_store_n(&g_ext4_mount_registry_lock, 0u, __ATOMIC_RELEASE);
}

static void ext4_mount_registry_add(ext4_fs_t *fs) {
    if (!fs) return;
    ext4_mount_registry_lock();
    fs->registry_next = g_ext4_mounts;
    g_ext4_mounts = fs;
    ext4_mount_registry_unlock();
}

static void ext4_mount_registry_remove(ext4_fs_t *fs) {
    ext4_fs_t **link;

    if (!fs) return;
    ext4_mount_registry_lock();
    link = &g_ext4_mounts;
    while (*link && *link != fs) link = &(*link)->registry_next;
    if (*link == fs) *link = fs->registry_next;
    fs->registry_next = 0;
    ext4_mount_registry_unlock();
}

static ext4_fs_t *ext4_state_allocate(void) {
    uint64_t pages =
        (sizeof(ext4_fs_t) + EXT4_CACHE_PAGE_SIZE - 1u) /
        EXT4_CACHE_PAGE_SIZE;
    ext4_fs_t *fs;

    if (!pages || pages > UINT32_MAX) return 0;
    fs = (ext4_fs_t *)arch_vm_alloc_pages(pages);
    if (!fs) return 0;
    memset(fs, 0, pages * EXT4_CACHE_PAGE_SIZE);
    fs->allocation_pages = (uint32_t)pages;
    fs->lifecycle_superblock.fs_private = fs;
    return fs;
}

static void ext4_state_release(ext4_fs_t *fs) {
    uint32_t pages;

    if (!fs) return;
    pages = fs->allocation_pages;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page((uint8_t *)fs +
                          (uint64_t)page * EXT4_CACHE_PAGE_SIZE);
}

static int ext4_fs_slot(const ext4_fs_t *fs) {
    const ext4_fs_t *current;
    int slot = 0;

    if (!fs) return -1;
    for (current = __atomic_load_n(&g_ext4_mounts, __ATOMIC_ACQUIRE);
         current;
         current = __atomic_load_n(&current->registry_next,
                                   __ATOMIC_ACQUIRE), ++slot) {
        if (current == fs) return slot;
    }
    return -1;
}

static int ext4_fs_looks_live(const ext4_fs_t *fs) {
    if (ext4_fs_slot(fs) < 0) return 0;
    if (!fs->bdev) return 0;
    if (fs->sb.magic != 0xEF53u) return 0;
    if (fs->block_size != 1024u && fs->block_size != 2048u && fs->block_size != 4096u) return 0;
    if (fs->desc_size == 0 || fs->desc_size > fs->block_size) return 0;
    if (fs->sb.inodes_per_group == 0 || fs->sb.blocks_per_group == 0) return 0;
    if (fs->sb.inode_size < sizeof(ext4_inode_t) || fs->sb.inode_size > fs->block_size) return 0;
    return 1;
}

static void ext4_trace_bad_fs(const char *op, vfs_superblock_t *sb, const ext4_fs_t *fs) {
    if (g_ext4_badfs_log_budget == 0) return;
    g_ext4_badfs_log_budget--;
    printf("[ext4-badfs] op=%s fs=%p slot=%d sb=%p sbfs=%p sbname=%s mnt=%s pid=%d task=%s block=%u desc=%u magic=0x%x budget=%u\n",
           op ? op : "?",
           fs,
           ext4_fs_slot(fs),
           sb,
           sb ? sb->fs_private : 0,
           sb ? sb->fs_name : "-",
           sb ? sb->mountpoint : "-",
           kernel_current_pid(),
           kernel_current_comm(),
           fs ? (unsigned)fs->block_size : 0u,
           fs ? (unsigned)fs->desc_size : 0u,
           fs ? (unsigned)fs->sb.magic : 0u,
           (unsigned)g_ext4_badfs_log_budget);
}

static int ext4_validate_fs(const char *op, vfs_superblock_t *sb, ext4_fs_t *fs) {
    if (ext4_fs_looks_live(fs)) return 1;
    ext4_trace_bad_fs(op, sb, fs);
    return 0;
}

static void ext4_op_lock(ext4_fs_t *fs) {
    uintptr_t current;
    int32_t current_pid;
    const char *current_comm;
    uint64_t wait_start_us = 0;
    uint64_t next_log_us = 0;
    uint64_t reader_wait_start_us = 0;
    uint64_t reader_next_log_us = 0;
    int log_budget = 0;
    if (!fs) return;
    current = kernel_current_context_token();
    current_pid = kernel_current_pid();
    current_comm = kernel_current_comm();
    if (current && fs->op_lock_owner == current) {
        fs->op_lock_depth++;
        return;
    }
    while (__sync_lock_test_and_set(&fs->op_lock, 1)) {
        uint64_t observed = __atomic_load_n(
            &fs->op_wait_sequence, __ATOMIC_ACQUIRE);

        if (!wait_start_us) {
            wait_start_us = boottime_monotonic_us();
            next_log_us = wait_start_us + 500000ull;
        } else {
            uint64_t now = boottime_monotonic_us();
            if (log_budget > 0 && now >= next_log_us) {
                log_budget--;
                printf("[ext4-lock] wait pid=%d cmd=%s owner=%d depth=%u wait_us=%u\n",
                       current_pid, current_comm,
                       fs->op_lock_owner_pid,
                       (unsigned)fs->op_lock_depth,
                       (unsigned)(now - wait_start_us));
                next_log_us = now + 500000ull;
            }
        }
        if (__atomic_load_n(&fs->op_lock, __ATOMIC_ACQUIRE)) {
            int waited = kernel_runtime_wait_sequence(
                &fs->op_wait_sequence, observed, UINT64_MAX);

            if (waited >= 0) continue;
        }
        if (!kernel_runtime_yield()) {
            int released = kernel_runtime_contention_begin();

            while (__sync_lock_test_and_set(&fs->op_lock, 1))
                ext4_cpu_relax();
            kernel_runtime_contention_end(released);
            break;
        }
    }
    fs->op_lock_owner = current;
    fs->op_lock_owner_pid = current_pid;
    fs->op_lock_depth = 1;
    while (fs->read_count != 0) {
        uint64_t observed = __atomic_load_n(
            &fs->op_wait_sequence, __ATOMIC_ACQUIRE);

        if (!reader_wait_start_us) {
            reader_wait_start_us = boottime_monotonic_us();
            reader_next_log_us = reader_wait_start_us + 500000ull;
        } else {
            uint64_t now = boottime_monotonic_us();
            if (log_budget > 0 && now >= reader_next_log_us) {
                log_budget--;
                printf("[ext4-rwlock] writer pid=%d cmd=%s readers=%u wait_us=%u\n",
                       current_pid, current_comm,
                       (unsigned)fs->read_count,
                       (unsigned)(now - reader_wait_start_us));
                reader_next_log_us = now + 500000ull;
            }
        }
        if (__atomic_load_n(&fs->read_count, __ATOMIC_ACQUIRE) != 0u) {
            int waited = kernel_runtime_wait_sequence(
                &fs->op_wait_sequence, observed, UINT64_MAX);

            if (waited >= 0) continue;
        }
        if (!kernel_runtime_yield()) {
            int released = kernel_runtime_contention_begin();

            while (__atomic_load_n(&fs->read_count, __ATOMIC_ACQUIRE) != 0u)
                ext4_cpu_relax();
            kernel_runtime_contention_end(released);
            break;
        }
    }
    if (wait_start_us && log_budget > 0) {
        uint64_t waited = boottime_monotonic_us() - wait_start_us;
        if (waited >= 500000ull) {
            printf("[ext4-lock] acquired pid=%d cmd=%s wait_us=%u\n",
                   current_pid, current_comm,
                   (unsigned)waited);
        }
    }
}

static void ext4_op_unlock(ext4_fs_t *fs) {
    if (!fs) return;
    if (fs->op_lock_depth > 1) {
        fs->op_lock_depth--;
        return;
    }
    fs->op_lock_owner = 0;
    fs->op_lock_owner_pid = -1;
    fs->op_lock_depth = 0;
    __sync_lock_release(&fs->op_lock);
    __atomic_add_fetch(&fs->op_wait_sequence, 1u, __ATOMIC_RELEASE);
    kernel_runtime_notify_sequence(&fs->op_wait_sequence);
}

static void ext4_read_begin(ext4_fs_t *fs) {
    if (!fs) return;
    for (;;) {
        while (fs->op_lock) {
            uint64_t observed = __atomic_load_n(
                &fs->op_wait_sequence, __ATOMIC_ACQUIRE);

            if (__atomic_load_n(&fs->op_lock, __ATOMIC_ACQUIRE)) {
                int waited = kernel_runtime_wait_sequence(
                    &fs->op_wait_sequence, observed, UINT64_MAX);

                if (waited >= 0) continue;
            }
            if (!kernel_runtime_yield()) {
                int released = kernel_runtime_contention_begin();

                while (__atomic_load_n(&fs->op_lock, __ATOMIC_ACQUIRE))
                    ext4_cpu_relax();
                kernel_runtime_contention_end(released);
            }
        }
        __sync_fetch_and_add(&fs->read_count, 1);
        if (!fs->op_lock) return;
        if (__sync_sub_and_fetch(&fs->read_count, 1) == 0u) {
            __atomic_add_fetch(
                &fs->op_wait_sequence, 1u, __ATOMIC_RELEASE);
            kernel_runtime_notify_sequence(&fs->op_wait_sequence);
        }
    }
}

static void ext4_read_end(ext4_fs_t *fs) {
    if (!fs) return;
    if (__sync_sub_and_fetch(&fs->read_count, 1) == 0u) {
        __atomic_add_fetch(&fs->op_wait_sequence, 1u, __ATOMIC_RELEASE);
        kernel_runtime_notify_sequence(&fs->op_wait_sequence);
    }
}

static ext4_fs_t *ext4_lock_from_sb(vfs_superblock_t *sb) {
    ext4_fs_t *fs;
    if (!sb) return 0;
    fs = (ext4_fs_t *)sb->fs_private;
    if (!ext4_validate_fs("lock", sb, fs)) return 0;
    ext4_op_lock(fs);
    return fs;
}

static void ext4_trace_slow_lookup(vfs_inode_t *dir, const char *name, int rc, uint64_t dt_us) {
    if (dt_us < 500000ull || g_ext4_slow_log_budget == 0) return;
    g_ext4_slow_log_budget--;
    printf("[ext4-slow] lookup dir_ino=%u name=%s rc=%d dt_us=%u\n",
           dir ? (unsigned)dir->ino : 0u,
           name ? name : "-",
           rc,
           (unsigned)dt_us);
}

static uint32_t inode_size_get(const ext4_inode_t *in) {
    return in ? in->size_lo : 0;
}

static void ext4_release_cache_page(void *page) {
    if (page) arch_vm_free_page(page);
}

static void directory_index_invalidate_all(ext4_fs_t *fs) {
    if (!fs) return;
    memset(fs->directory_index, 0, sizeof(fs->directory_index));
    fs->directory_index_clock = 0;
}

static void directory_index_invalidate(ext4_fs_t *fs, uint32_t dir_ino) {
    if (!fs || !dir_ino) return;
    for (uint32_t slot = 0; slot < EXT4_DIRECTORY_INDEX_SLOTS; ++slot) {
        ext4_directory_index_entry_t *entry = &fs->directory_index[slot];
        if (entry->valid && entry->dir_ino == dir_ino) {
            memset(entry, 0, sizeof(*entry));
            return;
        }
    }
}

static int directory_index_is_complete(ext4_fs_t *fs, uint32_t dir_ino,
                                       uint32_t dir_size) {
    if (!fs || !dir_ino) return 0;
    for (uint32_t slot = 0; slot < EXT4_DIRECTORY_INDEX_SLOTS; ++slot) {
        ext4_directory_index_entry_t *entry = &fs->directory_index[slot];
        if (!entry->valid || entry->dir_ino != dir_ino) continue;
        if (entry->dir_size != dir_size) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        entry->age = ++fs->directory_index_clock;
        return 1;
    }
    return 0;
}

static void directory_index_mark_complete(ext4_fs_t *fs, uint32_t dir_ino,
                                          uint32_t dir_size) {
    ext4_directory_index_entry_t *selected = 0;

    if (!fs || !dir_ino) return;
    for (uint32_t slot = 0; slot < EXT4_DIRECTORY_INDEX_SLOTS; ++slot) {
        ext4_directory_index_entry_t *entry = &fs->directory_index[slot];
        if (entry->valid && entry->dir_ino == dir_ino) {
            selected = entry;
            break;
        }
        if (!entry->valid || !selected || entry->age < selected->age)
            selected = entry;
    }
    if (!selected) return;
    selected->valid = 1;
    selected->dir_ino = dir_ino;
    selected->dir_size = dir_size;
    selected->age = ++fs->directory_index_clock;
}

static void directory_index_note_insert(ext4_fs_t *fs, uint32_t dir_ino,
                                        uint32_t old_size,
                                        uint32_t new_size, int cached) {
    if (!directory_index_is_complete(fs, dir_ino, old_size)) return;
    if (!cached) {
        directory_index_invalidate(fs, dir_ino);
        return;
    }
    directory_index_mark_complete(fs, dir_ino, new_size);
}

static void lookup_cache_invalidate_all(ext4_fs_t *fs) {
    ext4_lookup_cache_page_t *page;

    if (!fs) return;
    page = fs->lookup_cache_pages;
    while (page) {
        ext4_lookup_cache_page_t *next = page->next;
        ext4_release_cache_page(page);
        page = next;
    }
    memset(fs->lookup_cache, 0, sizeof(fs->lookup_cache));
    fs->lookup_cache_pages = 0;
    fs->lookup_cache_count = 0;
    fs->lookup_cache_clock = 0;
    directory_index_invalidate_all(fs);
}

static uint32_t lookup_cache_bucket(uint32_t dir_ino, const char *name) {
    uint32_t hash = 2166136261u ^ dir_ino;

    while (*name) {
        hash ^= (uint8_t)*name++;
        hash *= 16777619u;
    }
    return hash % EXT4_LOOKUP_CACHE_BUCKETS;
}

static void lookup_cache_remove_page(ext4_fs_t *fs,
                                     ext4_lookup_cache_page_t *page) {
    ext4_lookup_cache_page_t **link;

    if (!fs || !page || page->live) return;
    link = &fs->lookup_cache_pages;
    while (*link && *link != page) link = &(*link)->next;
    if (*link == page) {
        *link = page->next;
        ext4_release_cache_page(page);
    }
}

static void lookup_cache_release_unlinked(
    ext4_fs_t *fs, ext4_lookup_cache_entry_t *entry) {
    ext4_lookup_cache_page_t *page;

    if (!fs || !entry || !entry->valid) return;
    page = entry->owner;
    entry->valid = 0;
    entry->next = 0;
    if (fs->lookup_cache_count) --fs->lookup_cache_count;
    if (page && page->live) --page->live;
    lookup_cache_remove_page(fs, page);
}

static int lookup_cache_reclaim_page(ext4_fs_t *fs) {
    ext4_lookup_cache_page_t *page;
    ext4_lookup_cache_page_t *oldest_page = 0;
    uint32_t oldest_age = UINT32_MAX;

    if (!fs) return 0;
    for (page = fs->lookup_cache_pages; page; page = page->next) {
        uint32_t page_age = UINT32_MAX;
        for (uint32_t index = 0; index < page->capacity; ++index) {
            if (page->entries[index].valid &&
                page->entries[index].age < page_age)
                page_age = page->entries[index].age;
        }
        if (page_age < oldest_age) {
            oldest_age = page_age;
            oldest_page = page;
        }
    }
    if (!oldest_page) return 0;
    /*
     * A completed directory index is exact only while every name discovered
     * by its full scan remains resident.  Dropping any cache page therefore
     * makes the compact completeness markers conservative again.
     */
    directory_index_invalidate_all(fs);
    for (uint32_t bucket = 0; bucket < EXT4_LOOKUP_CACHE_BUCKETS;
         ++bucket) {
        ext4_lookup_cache_entry_t **link = &fs->lookup_cache[bucket];
        while (*link) {
            ext4_lookup_cache_entry_t *entry = *link;
            if (entry->owner != oldest_page) {
                link = &entry->next;
                continue;
            }
            *link = entry->next;
            entry->valid = 0;
            entry->next = 0;
            if (fs->lookup_cache_count) --fs->lookup_cache_count;
            if (oldest_page->live) --oldest_page->live;
        }
    }
    lookup_cache_remove_page(fs, oldest_page);
    return 1;
}

static ext4_lookup_cache_entry_t *lookup_cache_allocate(ext4_fs_t *fs) {
    ext4_lookup_cache_page_t *page;

    if (!fs) return 0;
retry:
    for (page = fs->lookup_cache_pages; page; page = page->next) {
        if (page->live >= page->capacity) continue;
        for (uint32_t index = 0; index < page->capacity; ++index) {
            ext4_lookup_cache_entry_t *entry = &page->entries[index];
            if (entry->valid) continue;
            memset(entry, 0, sizeof(*entry));
            entry->owner = page;
            entry->valid = 1;
            ++page->live;
            ++fs->lookup_cache_count;
            return entry;
        }
    }
    page = (ext4_lookup_cache_page_t *)arch_vm_alloc_page();
    if (!page) {
        if (!fs->lookup_cache_pages) return 0;
        lookup_cache_reclaim_page(fs);
        goto retry;
    }
    memset(page, 0, EXT4_CACHE_PAGE_SIZE);
    page->capacity = (uint16_t)(
        (EXT4_CACHE_PAGE_SIZE - sizeof(*page)) /
        sizeof(page->entries[0]));
    if (!page->capacity) {
        ext4_release_cache_page(page);
        return 0;
    }
    page->next = fs->lookup_cache_pages;
    fs->lookup_cache_pages = page;
    goto retry;
}

static void lookup_cache_invalidate(ext4_fs_t *fs, uint32_t dir_ino, const char *name) {
    uint32_t bucket;
    ext4_lookup_cache_entry_t **link;

    if (!fs || !name) return;
    bucket = lookup_cache_bucket(dir_ino, name);
    link = &fs->lookup_cache[bucket];
    while (*link) {
        ext4_lookup_cache_entry_t *entry = *link;
        if (entry->dir_ino == dir_ino && strcmp(entry->name, name) == 0) {
            *link = entry->next;
            lookup_cache_release_unlinked(fs, entry);
            return;
        }
        link = &entry->next;
    }
}

static int lookup_cache_find(ext4_fs_t *fs, uint32_t dir_ino,
                             const char *name, uint32_t *child_ino_out,
                             int *miss_out, uint32_t *dir_block_out,
                             uint32_t *dir_offset_out) {
    uint32_t bucket;
    ext4_lookup_cache_entry_t *entry;

    if (!fs || !name) return 0;
    bucket = lookup_cache_bucket(dir_ino, name);
    for (entry = fs->lookup_cache[bucket]; entry; entry = entry->next) {
        if (entry->dir_ino != dir_ino ||
            strcmp(entry->name, name) != 0)
            continue;
        entry->age = ++fs->lookup_cache_clock;
        if (miss_out) *miss_out = entry->miss ? 1 : 0;
        if (child_ino_out) *child_ino_out = entry->child_ino;
        if (dir_block_out) *dir_block_out = entry->dir_block;
        if (dir_offset_out) *dir_offset_out = entry->dir_offset;
        return 1;
    }
    return 0;
}

static int lookup_cache_store(ext4_fs_t *fs, uint32_t dir_ino,
                              const char *name, uint32_t child_ino,
                              int miss, uint32_t dir_block,
                              uint32_t dir_offset) {
    uint32_t bucket;
    ext4_lookup_cache_entry_t *entry;

    if (!fs || !name || !name[0]) return 0;
    bucket = lookup_cache_bucket(dir_ino, name);
    for (entry = fs->lookup_cache[bucket]; entry; entry = entry->next) {
        if (entry->dir_ino == dir_ino && strcmp(entry->name, name) == 0)
            break;
    }
    if (!entry) {
        entry = lookup_cache_allocate(fs);
        if (!entry) return 0;
        entry->next = fs->lookup_cache[bucket];
        fs->lookup_cache[bucket] = entry;
    }
    entry->miss = miss ? 1 : 0;
    entry->dir_ino = dir_ino;
    entry->child_ino = child_ino;
    entry->dir_block = dir_block;
    entry->dir_offset = dir_offset;
    entry->age = ++fs->lookup_cache_clock;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = 0;
    return 1;
}

static void readdir_cache_invalidate(ext4_fs_t *fs, uint32_t dir_ino) {
    if (!fs) return;
    for (uint32_t slot = 0; slot < EXT4_READDIR_CACHE_SLOTS; ++slot) {
        if (dir_ino == 0 || (fs->readdir_cache[slot].valid &&
                            fs->readdir_cache[slot].dir_ino == dir_ino))
            fs->readdir_cache[slot].valid = 0;
    }
}

static ext4_readdir_cache_entry_t *readdir_cache_select(
    ext4_fs_t *fs, uint32_t dir_ino, int create) {
    ext4_readdir_cache_entry_t *oldest = 0;

    if (!fs || !dir_ino) return 0;
    for (uint32_t slot = 0; slot < EXT4_READDIR_CACHE_SLOTS; ++slot) {
        ext4_readdir_cache_entry_t *entry = &fs->readdir_cache[slot];

        if (entry->valid && entry->dir_ino == dir_ino) {
            entry->age = ++fs->readdir_cache_clock;
            return entry;
        }
        if (!create) continue;
        if (!entry->valid) oldest = entry;
        else if (!oldest || entry->age < oldest->age) oldest = entry;
    }
    if (!oldest) return 0;
    memset(oldest, 0, sizeof(*oldest));
    oldest->valid = 1;
    oldest->dir_ino = dir_ino;
    oldest->age = ++fs->readdir_cache_clock;
    return oldest;
}

static int block_cache_newest_slot(ext4_fs_t *fs, uint32_t block) {
    int newest = -1;
    if (!fs) return -1;
    for (int i = 0;
         i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0]));
         ++i) {
        if (!fs->block_cache[i].valid ||
            fs->block_cache[i].block != block)
            continue;
        if (newest < 0 ||
            (int32_t)(fs->block_cache[i].age -
                      fs->block_cache[newest].age) > 0)
            newest = i;
    }
    return newest;
}

static void block_cache_discard_duplicates(ext4_fs_t *fs, uint32_t block,
                                           int keep) {
    if (!fs) return;
    for (int i = 0;
         i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0]));
         ++i) {
        if (i == keep || !fs->block_cache[i].valid ||
            fs->block_cache[i].block != block)
            continue;
        /*
         * A disk block has exactly one cache identity.  An older duplicate is
         * stale even when it is marked dirty; flushing it after the newest
         * line would roll metadata back and can free live ext4 allocations.
         */
        fs->block_cache[i].valid = 0;
        fs->block_cache[i].dirty = 0;
    }
}

static int block_cache_lookup(ext4_fs_t *fs, uint32_t block, void *out) {
    int slot;
    if (!fs || !out || fs->block_size > 4096) return 0;
    slot = block_cache_newest_slot(fs, block);
    if (slot < 0) return 0;
    block_cache_discard_duplicates(fs, block, slot);
    fs->block_cache[slot].age = ++fs->block_cache_clock;
    memcpy(out, fs->block_cache[slot].data, fs->block_size);
    return 1;
}

static int block_cache_has_dirty(ext4_fs_t *fs) {
    if (!fs) return 0;
    if (fs->meta_dirty || fs->bitmap_cache_dirty) return 1;
    for (int i = 0; i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0])); ++i) {
        if (fs->block_cache[i].valid && fs->block_cache[i].dirty) return 1;
    }
    return 0;
}

static int block_cache_flush_run(ext4_fs_t *fs, int first_slot) {
    int slots[EXT4_BLOCK_CACHE_SLOTS];
    uint32_t first_block;
    uint32_t sectors_per_block;
    uint32_t max_blocks;
    uint32_t blocks = 0;
    int result;

    if (!fs || first_slot < 0 ||
        first_slot >= (int)EXT4_BLOCK_CACHE_SLOTS ||
        !fs->block_cache[first_slot].valid ||
        !fs->block_cache[first_slot].dirty || !fs->bdev ||
        fs->bdev->sector_size == 0 ||
        fs->block_size == 0 || fs->block_size > 4096u)
        return -1;

    sectors_per_block = fs->block_size / fs->bdev->sector_size;
    if (sectors_per_block == 0 ||
        sectors_per_block * fs->bdev->sector_size != fs->block_size)
        return -1;
    max_blocks = BLOCK_BATCH_MAX_SECTORS / sectors_per_block;
    if (max_blocks == 0) return -1;
    if (max_blocks > EXT4_BLOCK_CACHE_SLOTS)
        max_blocks = EXT4_BLOCK_CACHE_SLOTS;
    first_block = fs->block_cache[first_slot].block;

    /*
     * The writeback staging area is owned by this mount and callers hold its
     * operation lock.  A global staging lock is both unnecessary and unsafe:
     * a filesystem inside a loop-backed file may write through its parent
     * filesystem while another parent-cache eviction writes in the opposite
     * direction.  Keeping writeback mount-local prevents that lock inversion.
     */
    while (blocks < max_blocks && first_block <= UINT32_MAX - blocks) {
        uint32_t wanted = first_block + blocks;
        int slot = -1;
        for (int i = 0; i < (int)EXT4_BLOCK_CACHE_SLOTS; ++i) {
            if (fs->block_cache[i].valid && fs->block_cache[i].dirty &&
                fs->block_cache[i].block == wanted) {
                slot = i;
                break;
            }
        }
        if (slot < 0) break;
        slots[blocks] = slot;
        memcpy(fs->writeback_run + blocks * fs->block_size,
               fs->block_cache[slot].data, fs->block_size);
        blocks++;
    }

    if (blocks == 0) {
        return -1;
    }
    if (first_block > UINT32_MAX / sectors_per_block ||
        blocks > UINT32_MAX / sectors_per_block ||
        first_block * sectors_per_block >
            UINT32_MAX - blocks * sectors_per_block) {
        return -1;
    }
    result = block_write_sectors(fs->bdev,
                                 first_block * sectors_per_block,
                                 blocks * sectors_per_block,
                                 fs->writeback_run);
    if (result == 0) {
        for (uint32_t i = 0; i < blocks; ++i)
            fs->block_cache[slots[i]].dirty = 0;
    }
    return result;
}

static int block_cache_flush_slot(ext4_fs_t *fs, int slot) {
    if (!fs || slot < 0 || slot >= (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0]))) return -1;
    if (!fs->block_cache[slot].valid || !fs->block_cache[slot].dirty) return 0;
    return block_cache_flush_run(fs, slot);
}

static int block_cache_flush_block(ext4_fs_t *fs, uint32_t block) {
    if (!fs) return -1;
    for (int i = 0; i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0])); ++i) {
        if (!fs->block_cache[i].valid || fs->block_cache[i].block != block) continue;
        if (block_cache_flush_slot(fs, i) < 0) return -1;
    }
    return 0;
}

static int block_cache_flush_range(ext4_fs_t *fs, uint32_t first,
                                   uint32_t count) {
    uint64_t end;
    if (!fs || !count) return count ? -1 : 0;
    end = (uint64_t)first + count;
    for (int slot = 0; slot < (int)EXT4_BLOCK_CACHE_SLOTS; ++slot) {
        uint32_t block;
        if (!fs->block_cache[slot].valid ||
            !fs->block_cache[slot].dirty)
            continue;
        block = fs->block_cache[slot].block;
        if (block < first || (uint64_t)block >= end) continue;
        if (block_cache_flush_slot(fs, slot) < 0) return -1;
    }
    return 0;
}

static int block_cache_flush_all(ext4_fs_t *fs) {
    if (!fs) return -1;
    for (int i = 0; i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0])); ++i) {
        if (block_cache_flush_slot(fs, i) < 0) return -1;
    }
    return 0;
}

static int block_cache_store(ext4_fs_t *fs, uint32_t block, const void *in, int dirty) {
    int slot = -1;
    int existing;
    uint32_t oldest_age = 0xFFFFFFFFu;
    if (!fs || !in || fs->block_size > 4096) return -1;

    /*
     * Search for an existing identity before considering empty space.  The old
     * one-pass search stopped at the first empty slot, so a matching line later
     * in the cache was missed.  Package-manager rename/unlink churn then left
     * multiple dirty copies of inode-table and bitmap blocks, and writeback of
     * a stale copy produced allocated files whose inode and block bits were
     * clear on disk.
     */
    existing = block_cache_newest_slot(fs, block);
    if (existing >= 0) {
        slot = existing;
        block_cache_discard_duplicates(fs, block, slot);
        if (!dirty && fs->block_cache[slot].dirty) {
            fs->block_cache[slot].age = ++fs->block_cache_clock;
            return 0;
        }
    }

    if (slot < 0) {
        for (int i = 0;
             i < (int)(sizeof(fs->block_cache) /
                       sizeof(fs->block_cache[0]));
             ++i) {
            if (!fs->block_cache[i].valid) {
                slot = i;
                break;
            }
            if (fs->block_cache[i].age < oldest_age) {
                oldest_age = fs->block_cache[i].age;
                slot = i;
            }
        }
    }
    if (slot < 0) return -1;
    if (fs->block_cache[slot].valid &&
        fs->block_cache[slot].block != block &&
        fs->block_cache[slot].dirty &&
        block_cache_flush_slot(fs, slot) < 0) return -1;
    fs->block_cache[slot].valid = 1;
    fs->block_cache[slot].dirty = dirty ? 1 : 0;
    fs->block_cache[slot].block = block;
    fs->block_cache[slot].age = ++fs->block_cache_clock;
    memcpy(fs->block_cache[slot].data, in, fs->block_size);
    return 0;
}

static void block_cache_invalidate(ext4_fs_t *fs, uint32_t block) {
    if (!fs) return;
    for (int i = 0; i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0])); ++i) {
        if (!fs->block_cache[i].valid || fs->block_cache[i].block != block) continue;
        (void)block_cache_flush_slot(fs, i);
        fs->block_cache[i].valid = 0;
    }
}

static void block_cache_discard(ext4_fs_t *fs, uint32_t block) {
    if (!fs) return;
    for (int i = 0; i < (int)(sizeof(fs->block_cache) / sizeof(fs->block_cache[0])); ++i) {
        if (!fs->block_cache[i].valid || fs->block_cache[i].block != block) continue;
        fs->block_cache[i].valid = 0;
        fs->block_cache[i].dirty = 0;
    }
}

static uint16_t vfs_mode_from_ext(uint16_t mode) {
    uint16_t kind = mode & 0xF000u;
    uint16_t perms = mode & 07777u;
    if (kind == 0x4000u) return (uint16_t)(VFS_INODE_DIR | perms);
    if (kind == 0x8000u) return (uint16_t)(VFS_INODE_FILE | perms);
    if (kind == 0xA000u) return (uint16_t)(VFS_INODE_LNK | perms);
    if (kind == 0x1000u) return (uint16_t)(VFS_INODE_FIFO | perms);
    if (kind == 0x2000u) return (uint16_t)(VFS_INODE_CHR | perms);
    if (kind == 0x6000u) return (uint16_t)(VFS_INODE_BLK | perms);
    if (kind == 0xC000u) return (uint16_t)(VFS_INODE_SOCK | perms);
    return 0;
}

static uint64_t ext4_decode_rdev(const ext4_inode_t *inode) {
    uint32_t encoded;
    if (!inode) return 0;

    /*
     * ext filesystems keep an old 8:8 encoding in i_block[0], or the modern
     * Linux 12:20 encoding in i_block[1] when i_block[0] is zero.  EdgeOS VFS
     * exposes Linux dev_t in that same modern encoding, so no host-specific
     * dev_t conversion belongs here.
     */
    encoded = inode->block[0] ? inode->block[0] : inode->block[1];
    return encoded;
}

static int ext4_encode_rdev(ext4_inode_t *inode, uint64_t rdev) {
    if (!inode || (rdev & ~0xffffffffull)) return -1;
    inode->block[0] = 0;
    inode->block[1] = (uint32_t)rdev;
    inode->block[2] = 0;
    return 0;
}

static uint32_t ext4_now_sec(void) {
    return (uint32_t)(boottime_realtime_us() / 1000000ull);
}

static void ext4_fill_vfs_inode(uint32_t ino, const ext4_inode_t *in, vfs_inode_t *out) {
    if (!in || !out) return;
    memset(out, 0, sizeof(*out));
    out->ino = ino;
    out->generation = in->generation;
    out->mode = vfs_mode_from_ext(in->mode);
    out->size = inode_size_get(in);
    out->uid = ext4_inode_uid(in);
    out->gid = ext4_inode_gid(in);
    out->nlink = in->links_count;
    out->nlink_valid = 1;
    out->atime = in->atime;
    out->mtime = in->mtime;
    out->ctime = in->ctime;
    if ((out->mode & 0xF000u) == VFS_INODE_CHR ||
        (out->mode & 0xF000u) == VFS_INODE_BLK)
        out->rdev = ext4_decode_rdev(in);
}

static int read_block(ext4_fs_t *fs, uint32_t block, void *out) {
    uint32_t cnt;
    if (!fs || !fs->bdev || fs->bdev->sector_size == 0) return -1;
    cnt = fs->block_size / fs->bdev->sector_size;
    if (cnt == 0) return -1;
    if (block_cache_lookup(fs, block, out)) return 0;
    if (block_read_sectors(fs->bdev, block * cnt, cnt, out) < 0) return -1;
    if (block_cache_store(fs, block, out, 0) < 0) return -1;
    return 0;
}

static int read_block_uncached(ext4_fs_t *fs, uint32_t block, void *out) {
    uint32_t cnt;
    if (!fs || !fs->bdev || !out || fs->bdev->sector_size == 0) return -1;
    if (fs->block_size == 0 || fs->block_size > 4096) return -1;
    cnt = fs->block_size / fs->bdev->sector_size;
    if (cnt == 0) return -1;
    return block_read_sectors(fs->bdev, block * cnt, cnt, out);
}

static int read_block_run_uncached(ext4_fs_t *fs, uint32_t first_block, uint32_t blocks, void *out) {
    uint32_t cnt;
    if (!fs || !fs->bdev || !out || blocks == 0 || fs->bdev->sector_size == 0) return -1;
    if (fs->block_size == 0 || fs->block_size > 4096) return -1;
    cnt = fs->block_size / fs->bdev->sector_size;
    if (cnt == 0) return -1;
    return block_read_sectors(fs->bdev, first_block * cnt, blocks * cnt, out);
}

static int read_block_run(ext4_fs_t *fs, uint32_t first_block, uint32_t blocks, void *out) {
    uint32_t cnt;
    uint8_t *dst = (uint8_t *)out;
    int all_cached = 1;
    if (!fs || !fs->bdev || !out || blocks == 0 || fs->bdev->sector_size == 0) return -1;
    if (blocks == 1) return read_block(fs, first_block, out);
    if (blocks > EXT4_READ_RUN_BLOCKS) return -1;
    if (fs->block_size == 0 || fs->block_size > 4096) return -1;
    cnt = fs->block_size / fs->bdev->sector_size;
    if (cnt == 0) return -1;

    /*
     * Linux normally amortizes dynamic-loader and package-manager reads with a
     * real page cache and readahead.  EdgeOS still has a small fixed ext4 block
     * cache, so full-file mmap loads of Python/Tk shared libraries were issuing
     * one NVMe command per 4K block and could push IDLE's subprocess startup
     * past its 10 second RPC timeout while X11 was active.  Batch only
     * contiguous full-block reads here; partial, sparse, and indirect cases keep
     * the conservative single-block path.
     *
     * Red flag: do not bypass dirty cache entries.  A read after write must see
     * the cache contents just like Linux observes the completed write, so flush
     * any dirty cached blocks in the run before the multi-block disk read.
     */
    for (uint32_t i = 0; i < blocks; ++i) {
        if (!block_cache_lookup(fs, first_block + i, dst + i * fs->block_size)) {
            all_cached = 0;
        }
    }
    if (all_cached) return 0;

    for (uint32_t i = 0; i < blocks; ++i) {
        if (block_cache_flush_block(fs, first_block + i) < 0) return -1;
    }
    if (block_read_sectors(fs->bdev, first_block * cnt, blocks * cnt, dst) < 0) return -1;
    for (uint32_t i = 0; i < blocks; ++i) {
        if (block_cache_store(fs, first_block + i, dst + i * fs->block_size, 0) < 0) return -1;
    }
    return 0;
}

static int write_block(ext4_fs_t *fs, uint32_t block, const void *in) {
    uint32_t cnt;
    if (!fs || !fs->bdev || fs->bdev->sector_size == 0) return -1;
    cnt = fs->block_size / fs->bdev->sector_size;
    if (cnt == 0) return -1;
    return block_cache_store(fs, block, in, 1);
}

static int sync_super_bg(ext4_fs_t *fs) {
    uint32_t descriptor_block;

    if (!fs || !fs->bdev) return -1;
    descriptor_block = fs->sb.first_data_block + 1u;
    if (read_block(fs, descriptor_block, fs->io) < 0) return -1;
    memcpy(fs->io, &fs->bg, sizeof(fs->bg));
    if (write_block(fs, descriptor_block, fs->io) < 0 ||
        block_cache_flush_block(fs, descriptor_block) < 0)
        return -1;

    /* Free-space and group metadata must reach the device before the summary. */
    if (block_read_sectors(fs->bdev, 2, 2, fs->io) < 0) return -1;
    memcpy(fs->io, &fs->sb, sizeof(fs->sb));
    return block_write_sectors(fs->bdev, 2, 2, fs->io);
}

static int bitmap_cache_flush(ext4_fs_t *fs) {
    if (!fs) return -1;
    if (!fs->bitmap_cache_valid || !fs->bitmap_cache_dirty) return 0;
    if (write_block(fs, fs->bitmap_cache_block, fs->bitmap_cache) < 0) return -1;
    fs->bitmap_cache_dirty = 0;
    return 0;
}

static int bitmap_cache_load(ext4_fs_t *fs, uint32_t bitmap_block) {
    if (!fs) return -1;
    if (fs->block_size > sizeof(fs->bitmap_cache)) return -1;
    if (fs->bitmap_cache_valid && fs->bitmap_cache_block == bitmap_block) return 0;
    if (bitmap_cache_flush(fs) < 0) return -1;
    if (read_block(fs, bitmap_block, fs->bitmap_cache) < 0) return -1;
    fs->bitmap_cache_valid = 1;
    fs->bitmap_cache_dirty = 0;
    fs->bitmap_cache_block = bitmap_block;
    return 0;
}

static int sync_super_bg_if_dirty(ext4_fs_t *fs) {
    if (!fs) return -1;
    if (bitmap_cache_flush(fs) < 0) return -1;
    if (!fs->meta_dirty) return 0;
    if (sync_super_bg(fs) < 0) return -1;
    fs->meta_dirty = 0;
    return 0;
}

static int ext4_flush_all_durable(ext4_fs_t *fs) {
    if (!fs) return -1;

    /*
     * Commit dirty data and allocation maps first, then publish the superblock
     * counters, and finally issue the device cache flush used by Linux fsync,
     * syncfs, sync, and clean unmount semantics.
     */
    if (bitmap_cache_flush(fs) < 0 || block_cache_flush_all(fs) < 0)
        return -1;
    if (fs->meta_dirty) {
        if (sync_super_bg(fs) < 0) return -1;
        fs->meta_dirty = 0;
    }
    if (block_cache_flush_all(fs) < 0) return -1;
    return block_flush(fs->bdev);
}

static int read_bgdesc(ext4_fs_t *fs, uint32_t group, ext4_bgdesc_t *out) {
    uint32_t per_block;
    uint32_t gd_block;
    uint32_t gd_index;
    uint32_t off;
    if (!out || !ext4_validate_fs("read_bgdesc", 0, fs)) return -1;
    per_block = fs->block_size / fs->desc_size;
    if (per_block == 0) return -1;
    gd_block = fs->sb.first_data_block + 1 + (group / per_block);
    gd_index = group % per_block;
    if (read_block(fs, gd_block, fs->io) < 0) return -1;
    off = gd_index * fs->desc_size;
    if (off + sizeof(ext4_bgdesc_t) > fs->block_size) return -1;
    memcpy(out, fs->io + off, sizeof(ext4_bgdesc_t));
    return 0;
}

static int write_bgdesc(ext4_fs_t *fs, uint32_t group, const ext4_bgdesc_t *in) {
    uint32_t per_block;
    uint32_t gd_block;
    uint32_t gd_index;
    uint32_t off;
    if (!in || !ext4_validate_fs("write_bgdesc", 0, fs)) return -1;
    per_block = fs->block_size / fs->desc_size;
    if (per_block == 0) return -1;
    gd_block = fs->sb.first_data_block + 1 + (group / per_block);
    gd_index = group % per_block;
    if (read_block(fs, gd_block, fs->io) < 0) return -1;
    off = gd_index * fs->desc_size;
    if (off + sizeof(ext4_bgdesc_t) > fs->block_size) return -1;
    memcpy(fs->io + off, in, sizeof(ext4_bgdesc_t));
    return write_block(fs, gd_block, fs->io);
}

static void inode_cache_lock(ext4_fs_t *fs) {
    while (__atomic_exchange_n(&fs->inode_cache_lock, 1u,
                               __ATOMIC_ACQUIRE))
        ext4_cpu_relax();
}

static void inode_cache_unlock(ext4_fs_t *fs) {
    __atomic_store_n(&fs->inode_cache_lock, 0u, __ATOMIC_RELEASE);
}

static uint32_t inode_cache_bucket(uint32_t ino) {
    uint32_t hash = ino * 2654435761u;

    hash ^= hash >> 16;
    return hash % EXT4_INODE_CACHE_BUCKETS;
}

static void inode_cache_remove_page(ext4_fs_t *fs,
                                    ext4_inode_cache_page_t *page) {
    ext4_inode_cache_page_t **link;

    if (!fs || !page || page->live) return;
    link = &fs->inode_cache_pages;
    while (*link && *link != page) link = &(*link)->next;
    if (*link == page) {
        *link = page->next;
        ext4_release_cache_page(page);
    }
}

static void inode_cache_release_unlinked(
    ext4_fs_t *fs, ext4_inode_cache_entry_t *entry) {
    ext4_inode_cache_page_t *page;

    if (!fs || !entry || !entry->valid) return;
    page = entry->owner;
    entry->valid = 0;
    entry->next = 0;
    if (fs->inode_cache_count) --fs->inode_cache_count;
    if (page && page->live) --page->live;
    inode_cache_remove_page(fs, page);
}

static int inode_cache_reclaim_page(ext4_fs_t *fs) {
    ext4_inode_cache_page_t *page;
    ext4_inode_cache_page_t *oldest_page = 0;
    uint32_t oldest_age = UINT32_MAX;

    if (!fs) return 0;
    for (page = fs->inode_cache_pages; page; page = page->next) {
        uint32_t page_age = UINT32_MAX;
        for (uint32_t index = 0; index < page->capacity; ++index) {
            if (page->entries[index].valid &&
                page->entries[index].age < page_age)
                page_age = page->entries[index].age;
        }
        if (page_age < oldest_age) {
            oldest_age = page_age;
            oldest_page = page;
        }
    }
    if (!oldest_page) return 0;
    for (uint32_t bucket = 0; bucket < EXT4_INODE_CACHE_BUCKETS; ++bucket) {
        ext4_inode_cache_entry_t **link = &fs->inode_cache[bucket];
        while (*link) {
            ext4_inode_cache_entry_t *entry = *link;
            if (entry->owner != oldest_page) {
                link = &entry->next;
                continue;
            }
            *link = entry->next;
            entry->valid = 0;
            entry->next = 0;
            if (fs->inode_cache_count) --fs->inode_cache_count;
            if (oldest_page->live) --oldest_page->live;
        }
    }
    inode_cache_remove_page(fs, oldest_page);
    return 1;
}

static ext4_inode_cache_entry_t *inode_cache_allocate(ext4_fs_t *fs) {
    ext4_inode_cache_page_t *page;

    if (!fs) return 0;
retry:
    for (page = fs->inode_cache_pages; page; page = page->next) {
        if (page->live >= page->capacity) continue;
        for (uint32_t index = 0; index < page->capacity; ++index) {
            ext4_inode_cache_entry_t *entry = &page->entries[index];
            if (entry->valid) continue;
            memset(entry, 0, sizeof(*entry));
            entry->owner = page;
            entry->valid = 1;
            ++page->live;
            ++fs->inode_cache_count;
            return entry;
        }
    }
    page = (ext4_inode_cache_page_t *)arch_vm_alloc_page();
    if (!page) {
        if (!fs->inode_cache_pages) return 0;
        inode_cache_reclaim_page(fs);
        goto retry;
    }
    memset(page, 0, EXT4_CACHE_PAGE_SIZE);
    page->capacity = (uint16_t)(
        (EXT4_CACHE_PAGE_SIZE - sizeof(*page)) /
        sizeof(page->entries[0]));
    if (!page->capacity) {
        ext4_release_cache_page(page);
        return 0;
    }
    page->next = fs->inode_cache_pages;
    fs->inode_cache_pages = page;
    goto retry;
}

static int inode_cache_lookup(ext4_fs_t *fs, uint32_t ino,
                              ext4_inode_t *out) {
    int found = 0;
    uint32_t bucket;
    ext4_inode_cache_entry_t *entry;

    if (!fs || !out) return 0;
    bucket = inode_cache_bucket(ino);
    inode_cache_lock(fs);
    for (entry = fs->inode_cache[bucket]; entry; entry = entry->next) {
        if (entry->ino != ino) continue;
        entry->age = ++fs->inode_cache_clock;
        memcpy(out, &entry->inode, sizeof(*out));
        found = 1;
        break;
    }
    inode_cache_unlock(fs);
    return found;
}

static void inode_cache_store(ext4_fs_t *fs, uint32_t ino,
                              const ext4_inode_t *inode) {
    uint32_t bucket;
    ext4_inode_cache_entry_t *entry;

    if (!fs || !inode) return;
    bucket = inode_cache_bucket(ino);
    inode_cache_lock(fs);
    for (entry = fs->inode_cache[bucket]; entry; entry = entry->next) {
        if (entry->ino == ino) break;
    }
    if (!entry) {
        entry = inode_cache_allocate(fs);
        if (entry) {
            entry->next = fs->inode_cache[bucket];
            fs->inode_cache[bucket] = entry;
        }
    }
    if (entry) {
        entry->ino = ino;
        entry->age = ++fs->inode_cache_clock;
        memcpy(&entry->inode, inode, sizeof(*inode));
    }
    inode_cache_unlock(fs);
}

static int read_inode(ext4_fs_t *fs, uint32_t ino, ext4_inode_t *out) {
    ext4_bgdesc_t bg;
    uint32_t idx, group, idx_in_group, off, blk, boff;
    if (!out || !ext4_validate_fs("read_inode", 0, fs)) return -1;
    if (ino == 0 || ino > fs->sb.inodes_count) return -1;
    if (inode_cache_lookup(fs, ino, out)) return 0;

    idx = ino - 1;
    group = idx / fs->sb.inodes_per_group;
    idx_in_group = idx % fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return -1;
    off = idx_in_group * fs->sb.inode_size;
    blk = bg.inode_table_lo + off / fs->block_size;
    boff = off % fs->block_size;
    if (boff + sizeof(ext4_inode_t) > fs->block_size) return -1;
    if (read_block(fs, blk, fs->io) < 0) return -1;
    memcpy(out, fs->io + boff, sizeof(ext4_inode_t));
    inode_cache_store(fs, ino, out);
    return 0;
}

static int read_bgdesc_ro(ext4_fs_t *fs, uint32_t group, ext4_bgdesc_t *out, ext4_ro_workspace_t *ws) {
    uint32_t per_block;
    uint32_t gd_block;
    uint32_t gd_index;
    uint32_t off;
    if (!out || !ws || !ext4_validate_fs("read_bgdesc_ro", 0, fs)) return -1;
    per_block = fs->block_size / fs->desc_size;
    if (per_block == 0) return -1;
    gd_block = fs->sb.first_data_block + 1 + (group / per_block);
    gd_index = group % per_block;
    if (read_block_uncached(fs, gd_block, ws->io) < 0) return -1;
    off = gd_index * fs->desc_size;
    if (off + sizeof(ext4_bgdesc_t) > fs->block_size) return -1;
    memcpy(out, ws->io + off, sizeof(ext4_bgdesc_t));
    return 0;
}

static int read_inode_ro(ext4_fs_t *fs, uint32_t ino, ext4_inode_t *out, ext4_ro_workspace_t *ws) {
    ext4_bgdesc_t bg;
    uint32_t idx, group, idx_in_group, off, blk, boff;
    if (!out || !ws || !ext4_validate_fs("read_inode_ro", 0, fs)) return -1;
    if (ino == 0 || ino > fs->sb.inodes_count) return -1;
    if (inode_cache_lookup(fs, ino, out)) return 0;
    idx = ino - 1;
    group = idx / fs->sb.inodes_per_group;
    idx_in_group = idx % fs->sb.inodes_per_group;
    if (read_bgdesc_ro(fs, group, &bg, ws) < 0) return -1;
    off = idx_in_group * fs->sb.inode_size;
    blk = bg.inode_table_lo + off / fs->block_size;
    boff = off % fs->block_size;
    if (boff + sizeof(ext4_inode_t) > fs->block_size) return -1;
    if (read_block_uncached(fs, blk, ws->io) < 0) return -1;
    memcpy(out, ws->io + boff, sizeof(ext4_inode_t));
    inode_cache_store(fs, ino, out);
    return 0;
}

static int write_inode(ext4_fs_t *fs, uint32_t ino, const ext4_inode_t *in) {
    ext4_bgdesc_t bg;
    uint32_t idx, group, idx_in_group, off, blk, boff;
    int rc;
    if (!in || !ext4_validate_fs("write_inode", 0, fs)) return -1;
    if (ino == 0 || ino > fs->sb.inodes_count) return -1;
    idx = ino - 1;
    group = idx / fs->sb.inodes_per_group;
    idx_in_group = idx % fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return -1;
    off = idx_in_group * fs->sb.inode_size;
    blk = bg.inode_table_lo + off / fs->block_size;
    boff = off % fs->block_size;
    if (boff + sizeof(ext4_inode_t) > fs->block_size) return -1;
    if (read_block(fs, blk, fs->io) < 0) return -1;
    memcpy(fs->io + boff, in, sizeof(ext4_inode_t));
    rc = write_block(fs, blk, fs->io);
    if (rc == 0) inode_cache_store(fs, ino, in);
    return rc;
}

static int write_new_inode(ext4_fs_t *fs, uint32_t ino,
                           const ext4_inode_t *inode) {
    ext4_bgdesc_t bg;
    uint64_t table_offset;
    uint32_t group;
    uint32_t index;
    uint32_t remaining;
    uint32_t copied = 0;

    if (!fs || !inode || !ino || ino > fs->sb.inodes_count ||
        fs->sb.inode_size < sizeof(*inode) ||
        fs->sb.inode_size > sizeof(fs->xattr_inode))
        return -1;

    /*
     * A newly allocated ext4 inode owns the complete on-disk inode record,
     * not only the original 128-byte ext2 prefix. Reusing a free inode while
     * leaving the extended tail untouched can expose stale i_extra_isize,
     * timestamp, project-ID, and inline-xattr bytes. Linux e2fsck then rejects
     * the inode even though the base inode fields look valid.
     */
    memset(fs->xattr_inode, 0, fs->sb.inode_size);
    memcpy(fs->xattr_inode, inode, sizeof(*inode));
    if (fs->inode_extra_isize) {
        memcpy(fs->xattr_inode + sizeof(*inode),
               &fs->inode_extra_isize,
               sizeof(fs->inode_extra_isize));
    }

    index = ino - 1u;
    group = index / fs->sb.inodes_per_group;
    index %= fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return -1;
    table_offset = (uint64_t)index * fs->sb.inode_size;
    remaining = fs->sb.inode_size;
    while (remaining) {
        uint32_t block =
            bg.inode_table_lo +
            (uint32_t)(table_offset / fs->block_size);
        uint32_t offset = (uint32_t)(table_offset % fs->block_size);
        uint32_t amount = fs->block_size - offset;
        if (amount > remaining) amount = remaining;
        if (read_block(fs, block, fs->io) < 0) return -1;
        memcpy(fs->io + offset, fs->xattr_inode + copied, amount);
        if (write_block(fs, block, fs->io) < 0) return -1;
        copied += amount;
        remaining -= amount;
        table_offset += amount;
    }
    inode_cache_store(fs, ino, inode);
    return 0;
}

static int alloc_from_bitmap(ext4_fs_t *fs, uint32_t bitmap_block, uint32_t max, int is_inode) {
    uint32_t total;
    uint32_t per_group;
    uint32_t groups;
    uint32_t start_group;
    uint32_t start_bit;
    uint32_t *hint;
    (void)bitmap_block;
    (void)max;
    if (!fs) return -1;
    total = is_inode ? fs->sb.inodes_count :
                       fs->sb.blocks_count_lo - fs->sb.first_data_block;
    per_group = is_inode ? fs->sb.inodes_per_group : fs->sb.blocks_per_group;
    if (per_group == 0 || total == 0) return -1;
    groups = (total + per_group - 1) / per_group;
    hint = is_inode ? &fs->next_free_inode_hint : &fs->next_free_block_hint;
    if (*hint >= total) *hint = 0;
    start_group = *hint / per_group;
    start_bit = *hint % per_group;

    for (uint32_t group_off = 0; group_off < groups; ++group_off) {
        ext4_bgdesc_t bg;
        uint32_t group = start_group + group_off;
        uint32_t group_limit;
        uint32_t first_bit;
        uint32_t bitmap;
        if (group >= groups) group -= groups;
        if (read_bgdesc(fs, group, &bg) < 0) return -1;
        bitmap = is_inode ? bg.inode_bitmap_lo : bg.block_bitmap_lo;
        if (bitmap_cache_load(fs, bitmap) < 0) return -1;
        group_limit = total - group * per_group;
        if (group_limit > per_group) group_limit = per_group;
        first_bit = (group == start_group) ? start_bit : 0;

        for (uint32_t pass = 0; pass < 2; ++pass) {
            uint32_t begin = pass == 0 ? first_bit : 0;
            uint32_t end = pass == 0 ? group_limit : first_bit;
            if (begin >= end) continue;
            for (uint32_t i = begin; i < end; ++i) {
                uint32_t byte = i / 8;
                uint32_t bit = i % 8;
                if (fs->bitmap_cache[byte] & (1u << bit)) continue;
                fs->bitmap_cache[byte] |= (1u << bit);
                fs->bitmap_cache_dirty = 1;
                *hint = group * per_group + i + 1;
                if (*hint >= total) *hint = 0;
                if (is_inode) {
                    if (fs->sb.free_inodes_count) fs->sb.free_inodes_count--;
                    if (bg.free_inodes_count_lo) bg.free_inodes_count_lo--;
                } else {
                    if (fs->sb.free_blocks_count_lo) fs->sb.free_blocks_count_lo--;
                    if (bg.free_blocks_count_lo) bg.free_blocks_count_lo--;
                }
                /*
                 * The rootfs can span many block groups.  Keep the descriptor
                 * for the group we actually allocated from coherent with the
                 * bitmap and superblock counters; otherwise large package
                 * installs eventually see stale per-group metadata after
                 * allocations move past group 0.
                 */
                if (write_bgdesc(fs, group, &bg) < 0) return -1;
                if (group == 0) fs->bg = bg;
                fs->meta_dirty = 1;
                if (is_inode) return (int)(group * per_group + i + 1);
                return (int)(fs->sb.first_data_block + group * per_group + i);
            }
        }
    }
    return -1;
}

static void inode_cache_invalidate(ext4_fs_t *fs, uint32_t ino) {
    uint32_t bucket;
    ext4_inode_cache_entry_t **link;

    if (!fs || !ino) return;
    bucket = inode_cache_bucket(ino);
    inode_cache_lock(fs);
    link = &fs->inode_cache[bucket];
    while (*link) {
        ext4_inode_cache_entry_t *entry = *link;
        if (entry->ino == ino) {
            *link = entry->next;
            inode_cache_release_unlinked(fs, entry);
            break;
        }
        link = &entry->next;
    }
    inode_cache_unlock(fs);
}

static void ext4_dynamic_state_release(ext4_fs_t *fs) {
    ext4_inode_cache_page_t *inode_page;
    ext4_open_inode_page_t *open_inode_page;

    if (!fs) return;
    lookup_cache_invalidate_all(fs);
    inode_cache_lock(fs);
    inode_page = fs->inode_cache_pages;
    memset(fs->inode_cache, 0, sizeof(fs->inode_cache));
    fs->inode_cache_pages = 0;
    fs->inode_cache_count = 0;
    fs->inode_cache_clock = 0;
    inode_cache_unlock(fs);
    while (inode_page) {
        ext4_inode_cache_page_t *next = inode_page->next;
        ext4_release_cache_page(inode_page);
        inode_page = next;
    }
    open_inode_page = fs->open_inode_pages;
    while (open_inode_page) {
        ext4_open_inode_page_t *next = open_inode_page->next;

        arch_vm_free_page(open_inode_page);
        open_inode_page = next;
    }
    fs->open_inode_pages = 0;
    fs->open_inode_capacity = 0;
}

static int free_bitmap_item(ext4_fs_t *fs, uint32_t value,
                            int is_inode, int was_directory) {
    uint32_t total;
    uint32_t per_group;
    uint32_t logical;
    uint32_t group;
    uint32_t bit;
    uint32_t bitmap;
    ext4_bgdesc_t bg;
    uint32_t *hint;
    if (!fs || !value) return -1;
    total = is_inode ? fs->sb.inodes_count :
                       fs->sb.blocks_count_lo - fs->sb.first_data_block;
    per_group = is_inode ? fs->sb.inodes_per_group : fs->sb.blocks_per_group;
    logical = is_inode ? value - 1u : value - fs->sb.first_data_block;
    if (!per_group || logical >= total) return -1;
    group = logical / per_group;
    bit = logical % per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return -1;
    bitmap = is_inode ? bg.inode_bitmap_lo : bg.block_bitmap_lo;
    if (bitmap_cache_load(fs, bitmap) < 0) return -1;
    if ((fs->bitmap_cache[bit / 8u] & (uint8_t)(1u << (bit % 8u))) == 0)
        return -1;
    fs->bitmap_cache[bit / 8u] &= (uint8_t)~(1u << (bit % 8u));
    fs->bitmap_cache_dirty = 1;
    hint = is_inode ? &fs->next_free_inode_hint : &fs->next_free_block_hint;
    if (*hint == 0 || logical < *hint) *hint = logical;
    if (is_inode) {
        ++fs->sb.free_inodes_count;
        ++bg.free_inodes_count_lo;
        if (was_directory && bg.used_dirs_count_lo) --bg.used_dirs_count_lo;
        inode_cache_invalidate(fs, value);
    } else {
        ++fs->sb.free_blocks_count_lo;
        ++bg.free_blocks_count_lo;
        block_cache_discard(fs, value);
    }
    if (write_bgdesc(fs, group, &bg) < 0) return -1;
    if (group == 0) fs->bg = bg;
    fs->meta_dirty = 1;
    return 0;
}

static int ext4_adjust_used_dirs(ext4_fs_t *fs, uint32_t ino, int delta) {
    ext4_bgdesc_t bg;
    uint32_t group;
    if (!fs || !ino || ino > fs->sb.inodes_count ||
        (delta != 1 && delta != -1) || !fs->sb.inodes_per_group)
        return -1;
    group = (ino - 1u) / fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return -1;
    if (delta > 0) {
        if (bg.used_dirs_count_lo == UINT16_MAX) return -1;
        ++bg.used_dirs_count_lo;
    } else {
        if (!bg.used_dirs_count_lo) return -1;
        --bg.used_dirs_count_lo;
    }
    if (write_bgdesc(fs, group, &bg) < 0) return -1;
    if (group == 0) fs->bg = bg;
    return 0;
}

static int ext4_free_block(ext4_fs_t *fs, uint32_t block,
                           uint32_t *freed_blocks) {
    if (free_bitmap_item(fs, block, 0, 0) < 0) return -1;
    if (freed_blocks) ++*freed_blocks;
    return 0;
}

static int ext4_free_block_run(ext4_fs_t *fs, uint32_t first,
                               uint32_t count, uint32_t *freed_blocks) {
    for (uint32_t i = 0; i < count; ++i) {
        block_cache_invalidate(fs, first + i);
        if (ext4_free_block(fs, first + i, freed_blocks) < 0) return -1;
    }
    return 0;
}

static int ext4_inode_charge_blocks(ext4_fs_t *fs, ext4_inode_t *inode,
                                    uint32_t filesystem_blocks) {
    uint64_t sectors;
    uint64_t total;
    if (!fs || !inode) return -1;
    if (!filesystem_blocks) return 0;
    if (fs->block_size < 512u || (fs->block_size % 512u) != 0) return -1;

    /*
     * ext4 i_blocks is measured in 512-byte sectors, independent of the block
     * device's logical sector size.  Charge both data and mapping-tree blocks;
     * deriving this field from i_size corrupts sparse-file accounting and makes
     * every short file on a 4K filesystem fail e2fsck.
     */
    sectors = (uint64_t)filesystem_blocks * (fs->block_size / 512u);
    total = (uint64_t)inode->blocks_lo + sectors;
    if (total > UINT32_MAX) return -1;
    inode->blocks_lo = (uint32_t)total;
    return 0;
}

static uint32_t ext4_next_inode_generation(ext4_fs_t *fs, uint32_t ino) {
    ext4_inode_t previous;
    uint32_t generation = 1u;
    if (fs && ino && read_inode(fs, ino, &previous) == 0) {
        generation = previous.generation + 1u;
        if (!generation) generation = 1u;
    }
    return generation;
}

static int extent_header_valid(const ext4_extent_header_t *h) {
    return h && h->eh_magic == EXT4_EXT_MAGIC && h->eh_entries <= h->eh_max;
}

static uint32_t extent_start_phys(const ext4_extent_t *e) {
    uint64_t v = ((uint64_t)e->ee_start_hi << 32) | (uint64_t)e->ee_start_lo;
    return (uint32_t)v;
}

static uint32_t extent_actual_length(const ext4_extent_t *e) {
    if (!e || !e->ee_len) return 0;
    return e->ee_len <= 0x8000u ? (uint32_t)e->ee_len :
                                  (uint32_t)e->ee_len - 0x8000u;
}

static int extent_is_unwritten(const ext4_extent_t *e) {
    return e && e->ee_len > 0x8000u;
}

static void extent_set_length(ext4_extent_t *e, uint32_t length) {
    int unwritten;
    if (!e || !length || length > 0x8000u) return;
    unwritten = extent_is_unwritten(e);
    e->ee_len = (uint16_t)(length + (unwritten ? 0x8000u : 0u));
}

static uint32_t idx_leaf_phys(const ext4_extent_idx_t *e) {
    uint64_t v = ((uint64_t)e->ei_leaf_hi << 32) | (uint64_t)e->ei_leaf_lo;
    return (uint32_t)v;
}

static int extent_find_phys(ext4_fs_t *fs, const ext4_inode_t *in, uint32_t lblock, uint32_t *phys_out) {
    const uint8_t *node;
    uint16_t expected_depth;

    if (!fs || !in || !phys_out) return -1;
    node = (const uint8_t *)in->block;
    if (!extent_header_valid((const ext4_extent_header_t *)node)) return -1;
    expected_depth = ((const ext4_extent_header_t *)node)->eh_depth;
    if (expected_depth > EXT4_MAX_EXTENT_DEPTH) return -1;

    for (uint32_t level = 0; level <= EXT4_MAX_EXTENT_DEPTH; ++level) {
        const ext4_extent_header_t *header =
            (const ext4_extent_header_t *)node;
        uint16_t i;

        if (!extent_header_valid(header) ||
            header->eh_depth != expected_depth)
            return -1;
        if (header->eh_depth == 0) {
            const ext4_extent_t *extent =
                (const ext4_extent_t *)(node + sizeof(*header));
            for (i = 0; i < header->eh_entries; ++i) {
                uint32_t first = extent[i].ee_block;
                uint32_t count = extent_actual_length(&extent[i]);
                uint32_t physical = extent_start_phys(&extent[i]);
                if (!count) continue;
                if (lblock >= first && lblock - first < count) {
                    *phys_out = physical + (lblock - first);
                    return 0;
                }
            }
            return -1;
        }

        {
            const ext4_extent_idx_t *index =
                (const ext4_extent_idx_t *)(node + sizeof(*header));
            int selected = -1;
            uint32_t child_block;
            if (!header->eh_entries || level >= EXT4_MAX_EXTENT_DEPTH)
                return -1;
            for (i = 0; i < header->eh_entries; ++i) {
                if (index[i].ei_block <= lblock) selected = (int)i;
                else break;
            }
            if (selected < 0) selected = 0;
            child_block = idx_leaf_phys(&index[selected]);
            if (!child_block ||
                read_block(fs, child_block, fs->extent_work[level]) < 0)
                return -1;
            node = fs->extent_work[level];
            expected_depth--;
        }
    }
    return -1;
}

static int legacy_find_phys(ext4_fs_t *fs, const ext4_inode_t *in, uint32_t lblock, uint32_t *phys_out) {
    if (!fs || !in || !phys_out) return -1;
    if (lblock < 12) {
        if (!in->block[lblock]) return -1;
        *phys_out = in->block[lblock];
        return 0;
    }
    lblock -= 12;
    if (!in->block[12]) return -1;
    if (read_block(fs, in->block[12], fs->io) < 0) return -1;
    {
        uint32_t ents = fs->block_size / 4;
        if (lblock >= ents) return -1;
        if (!((uint32_t *)fs->io)[lblock]) return -1;
        *phys_out = ((uint32_t *)fs->io)[lblock];
        return 0;
    }
}

static int map_find_phys(ext4_fs_t *fs, const ext4_inode_t *in, uint32_t lblock, uint32_t *phys_out) {
    if (in && (in->flags & EXT4_EXTENTS_FL)) {
        return extent_find_phys(fs, in, lblock, phys_out);
    }
    return legacy_find_phys(fs, in, lblock, phys_out);
}

static int extent_find_phys_from_node_ro(ext4_fs_t *fs, const uint8_t *node, uint32_t lblock,
                                         uint32_t *phys_out, ext4_ro_workspace_t *ws) {
    const ext4_extent_header_t *h = (const ext4_extent_header_t *)node;
    uint16_t i;
    if (!fs || !node || !phys_out || !ws || !extent_header_valid(h)) return -1;

    if (h->eh_depth == 0) {
        const ext4_extent_t *ex = (const ext4_extent_t *)(node + sizeof(ext4_extent_header_t));
        for (i = 0; i < h->eh_entries; ++i) {
            uint32_t lb = ex[i].ee_block;
            uint32_t len = extent_actual_length(&ex[i]);
            uint32_t st = extent_start_phys(&ex[i]);
            if (len == 0) continue;
            if (lblock >= lb && lblock < lb + len) {
                *phys_out = st + (lblock - lb);
                return 0;
            }
        }
        return -1;
    }

    {
        const ext4_extent_idx_t *ix = (const ext4_extent_idx_t *)(node + sizeof(ext4_extent_header_t));
        int pick = -1;
        for (i = 0; i < h->eh_entries; ++i) {
            if (ix[i].ei_block <= lblock) pick = (int)i;
            else break;
        }
        if (pick < 0) pick = 0;
        if (pick >= (int)h->eh_entries) return -1;
        if (read_block_uncached(fs, idx_leaf_phys(&ix[pick]), ws->blk) < 0) return -1;
        return extent_find_phys_from_node_ro(fs, ws->blk, lblock, phys_out, ws);
    }
}

static int legacy_find_phys_ro(ext4_fs_t *fs, const ext4_inode_t *in, uint32_t lblock,
                               uint32_t *phys_out, ext4_ro_workspace_t *ws) {
    if (!fs || !in || !phys_out || !ws) return -1;
    if (lblock < 12) {
        if (!in->block[lblock]) return -1;
        *phys_out = in->block[lblock];
        return 0;
    }
    lblock -= 12;
    if (!in->block[12]) return -1;
    if (read_block_uncached(fs, in->block[12], ws->blk) < 0) return -1;
    {
        uint32_t ents = fs->block_size / 4;
        if (lblock >= ents) return -1;
        if (!((uint32_t *)ws->blk)[lblock]) return -1;
        *phys_out = ((uint32_t *)ws->blk)[lblock];
        return 0;
    }
}

static int map_find_phys_ro(ext4_fs_t *fs, const ext4_inode_t *in, uint32_t lblock,
                            uint32_t *phys_out, ext4_ro_workspace_t *ws) {
    if (in && (in->flags & EXT4_EXTENTS_FL)) {
        return extent_find_phys_from_node_ro(fs, (const uint8_t *)in->block, lblock, phys_out, ws);
    }
    return legacy_find_phys_ro(fs, in, lblock, phys_out, ws);
}

static int extent_init_inode(ext4_inode_t *in) {
    ext4_extent_header_t *h;
    if (!in) return -1;
    memset(in->block, 0, sizeof(in->block));
    h = (ext4_extent_header_t *)in->block;
    h->eh_magic = EXT4_EXT_MAGIC;
    h->eh_entries = 0;
    h->eh_max = (uint16_t)((sizeof(in->block) - sizeof(*h)) / sizeof(ext4_extent_t));
    h->eh_depth = 0;
    h->eh_generation = 0;
    in->flags |= EXT4_EXTENTS_FL;
    return 0;
}

static int extent_leaf_insert(ext4_extent_header_t *h, uint32_t lblock,
                              uint32_t pblock) {
    ext4_extent_t *ex;
    uint16_t position = 0;
    if (!extent_header_valid(h) || h->eh_depth != 0) return -1;
    ex = (ext4_extent_t *)((uint8_t *)h + sizeof(*h));

    for (uint16_t i = 0; i < h->eh_entries; ++i) {
        uint32_t lb = ex[i].ee_block;
        uint32_t len = extent_actual_length(&ex[i]);
        uint32_t st = extent_start_phys(&ex[i]);
        if (!len) return -1;
        if (lblock >= lb && lblock < lb + len)
            return st + (lblock - lb) == pblock ? 0 : -1;
        if (lb < lblock) position = (uint16_t)(i + 1u);
    }

    if (position > 0) {
        ext4_extent_t *previous = &ex[position - 1u];
        uint32_t length = extent_actual_length(previous);
        uint32_t physical = extent_start_phys(previous);
        if (!extent_is_unwritten(previous) &&
            lblock == previous->ee_block + length &&
            pblock == physical + length && length < 0x7fffu) {
            extent_set_length(previous, length + 1u);
            if (position < h->eh_entries) {
                ext4_extent_t *next = &ex[position];
                uint32_t next_length = extent_actual_length(next);
                uint32_t combined = length + 1u + next_length;
                if (!extent_is_unwritten(next) && combined <= 0x7fffu &&
                    next->ee_block == lblock + 1u &&
                    extent_start_phys(next) == pblock + 1u) {
                    extent_set_length(previous, combined);
                    for (uint16_t i = position; i + 1u < h->eh_entries; ++i)
                        ex[i] = ex[i + 1u];
                    --h->eh_entries;
                    memset(&ex[h->eh_entries], 0, sizeof(*ex));
                }
            }
            return 0;
        }
    }

    if (position < h->eh_entries) {
        ext4_extent_t *next = &ex[position];
        uint32_t next_length = extent_actual_length(next);
        uint32_t next_physical = extent_start_phys(next);
        if (!extent_is_unwritten(next) && next_length < 0x7fffu &&
            next->ee_block == lblock + 1u && next_physical == pblock + 1u) {
            next->ee_block = lblock;
            next->ee_start_hi = 0;
            next->ee_start_lo = pblock;
            extent_set_length(next, next_length + 1u);
            return 0;
        }
    }

    if (h->eh_entries >= h->eh_max) return -1;
    for (uint16_t i = h->eh_entries; i > position; --i)
        ex[i] = ex[i - 1u];
    ++h->eh_entries;
    ex[position].ee_block = lblock;
    ex[position].ee_len = 1;
    ex[position].ee_start_hi = 0;
    ex[position].ee_start_lo = pblock;
    return 0;
}

static int extent_map_insert_local(ext4_inode_t *in, uint32_t lblock,
                                   uint32_t pblock) {
    if (!in) return -1;
    return extent_leaf_insert((ext4_extent_header_t *)in->block,
                              lblock, pblock);
}

static int extent_node_insert(ext4_extent_header_t *h, uint32_t lblock,
                              uint32_t pblock) {
    return extent_leaf_insert(h, lblock, pblock);
}

static int extent_convert_inline_to_depth1(ext4_fs_t *fs, ext4_inode_t *in) {
    ext4_extent_header_t *root;
    ext4_extent_header_t *leaf;
    ext4_extent_t *old_ex;
    ext4_extent_t *leaf_ex;
    ext4_extent_idx_t *idx;
    uint16_t old_entries;
    int leaf_block;

    if (!fs || !in) return -1;
    root = (ext4_extent_header_t *)in->block;
    if (!extent_header_valid(root) || root->eh_depth != 0) return -1;
    old_entries = root->eh_entries;
    if (old_entries == 0) return -1;

    leaf_block = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo, fs->sb.blocks_per_group, 0);
    if (leaf_block < 0) return -1;

    memset(fs->block_work, 0, fs->block_size);
    leaf = (ext4_extent_header_t *)fs->block_work;
    leaf->eh_magic = EXT4_EXT_MAGIC;
    leaf->eh_entries = old_entries;
    leaf->eh_max = (uint16_t)((fs->block_size - sizeof(*leaf)) / sizeof(ext4_extent_t));
    leaf->eh_depth = 0;
    leaf->eh_generation = 0;
    old_ex = (ext4_extent_t *)((uint8_t *)in->block + sizeof(*root));
    leaf_ex = (ext4_extent_t *)(fs->block_work + sizeof(*leaf));
    memcpy(leaf_ex, old_ex, (uint32_t)old_entries * sizeof(ext4_extent_t));
    if (write_block(fs, (uint32_t)leaf_block, fs->block_work) < 0) {
        (void)ext4_free_block(fs, (uint32_t)leaf_block, 0);
        return -1;
    }

    memset(in->block, 0, sizeof(in->block));
    root = (ext4_extent_header_t *)in->block;
    root->eh_magic = EXT4_EXT_MAGIC;
    root->eh_entries = 1;
    root->eh_max = (uint16_t)((sizeof(in->block) - sizeof(*root)) / sizeof(ext4_extent_idx_t));
    root->eh_depth = 1;
    root->eh_generation = 0;
    idx = (ext4_extent_idx_t *)((uint8_t *)in->block + sizeof(*root));
    idx[0].ei_block = leaf_ex[0].ee_block;
    idx[0].ei_leaf_lo = (uint32_t)leaf_block;
    idx[0].ei_leaf_hi = 0;
    idx[0].ei_unused = 0;
    return 0;
}

static int extent_split_leaf_and_insert(ext4_fs_t *fs,
                                        ext4_extent_header_t *root,
                                        ext4_extent_idx_t *indexes,
                                        uint16_t selected,
                                        uint32_t lblock,
                                        uint32_t pblock) {
    ext4_extent_header_t *old_leaf;
    ext4_extent_t *old_extents;
    ext4_extent_t *ordered;
    uint16_t old_entries;
    uint16_t insert_at = 0;
    uint16_t total;
    uint16_t left_entries;
    uint16_t right_entries;
    uint16_t leaf_max;
    uint16_t new_index;
    uint32_t old_leaf_block;
    int new_leaf_block;

    if (!fs || !root || !indexes || selected >= root->eh_entries ||
        root->eh_depth != 1 || root->eh_entries >= root->eh_max)
        return -1;
    old_leaf = (ext4_extent_header_t *)fs->block_work;
    if (!extent_header_valid(old_leaf) || old_leaf->eh_depth != 0 ||
        old_leaf->eh_entries != old_leaf->eh_max)
        return -1;
    old_entries = old_leaf->eh_entries;
    total = (uint16_t)(old_entries + 1u);
    if ((uint32_t)total * sizeof(ext4_extent_t) >
        sizeof(fs->extent_scratch))
        return -1;

    old_extents = (ext4_extent_t *)(fs->block_work + sizeof(*old_leaf));
    while (insert_at < old_entries &&
           old_extents[insert_at].ee_block < lblock)
        ++insert_at;
    if ((insert_at > 0u &&
         lblock - old_extents[insert_at - 1u].ee_block <
             extent_actual_length(&old_extents[insert_at - 1u])) ||
        (insert_at < old_entries &&
         lblock >= old_extents[insert_at].ee_block &&
         lblock - old_extents[insert_at].ee_block <
             extent_actual_length(&old_extents[insert_at])))
        return -1;
    ordered = (ext4_extent_t *)(void *)fs->extent_scratch;
    if (insert_at)
        memcpy(ordered, old_extents,
               (uint32_t)insert_at * sizeof(*ordered));
    ordered[insert_at].ee_block = lblock;
    ordered[insert_at].ee_len = 1u;
    ordered[insert_at].ee_start_hi = 0u;
    ordered[insert_at].ee_start_lo = pblock;
    if (insert_at < old_entries)
        memcpy(&ordered[insert_at + 1u], &old_extents[insert_at],
               (uint32_t)(old_entries - insert_at) * sizeof(*ordered));

    left_entries = (uint16_t)((total + 1u) / 2u);
    right_entries = (uint16_t)(total - left_entries);
    leaf_max = (uint16_t)((fs->block_size - sizeof(*old_leaf)) /
                          sizeof(ext4_extent_t));
    old_leaf_block = idx_leaf_phys(&indexes[selected]);
    if (!old_leaf_block) return -1;
    new_leaf_block = alloc_from_bitmap(
        fs, fs->bg.block_bitmap_lo, fs->sb.blocks_per_group, 0);
    if (new_leaf_block < 0) return -1;

    /* Publish the new right leaf before shortening the existing left leaf. */
    memset(fs->block_work, 0, fs->block_size);
    old_leaf = (ext4_extent_header_t *)fs->block_work;
    old_leaf->eh_magic = EXT4_EXT_MAGIC;
    old_leaf->eh_entries = right_entries;
    old_leaf->eh_max = leaf_max;
    old_leaf->eh_depth = 0u;
    memcpy(fs->block_work + sizeof(*old_leaf), &ordered[left_entries],
           (uint32_t)right_entries * sizeof(*ordered));
    if (write_block(fs, (uint32_t)new_leaf_block, fs->block_work) < 0) {
        (void)ext4_free_block(fs, (uint32_t)new_leaf_block, 0);
        return -1;
    }

    memset(fs->block_work, 0, fs->block_size);
    old_leaf = (ext4_extent_header_t *)fs->block_work;
    old_leaf->eh_magic = EXT4_EXT_MAGIC;
    old_leaf->eh_entries = left_entries;
    old_leaf->eh_max = leaf_max;
    old_leaf->eh_depth = 0u;
    memcpy(fs->block_work + sizeof(*old_leaf), ordered,
           (uint32_t)left_entries * sizeof(*ordered));
    if (write_block(fs, old_leaf_block, fs->block_work) < 0) {
        (void)ext4_free_block(fs, (uint32_t)new_leaf_block, 0);
        return -1;
    }

    indexes[selected].ei_block = ordered[0].ee_block;
    new_index = (uint16_t)(selected + 1u);
    for (uint16_t index = root->eh_entries; index > new_index; --index)
        indexes[index] = indexes[index - 1u];
    indexes[new_index].ei_block = ordered[left_entries].ee_block;
    indexes[new_index].ei_leaf_lo = (uint32_t)new_leaf_block;
    indexes[new_index].ei_leaf_hi = 0u;
    indexes[new_index].ei_unused = 0u;
    ++root->eh_entries;
    return 0;
}

static int extent_map_insert_tree(ext4_fs_t *fs, ext4_inode_t *in, uint32_t lblock, uint32_t pblock) {
    ext4_extent_header_t *root;
    if (!fs || !in) return -1;
    root = (ext4_extent_header_t *)in->block;
    if (!extent_header_valid(root)) return -1;

    if (root->eh_depth == 0) {
        if (extent_map_insert_local(in, lblock, pblock) == 0) return 0;
        if (extent_convert_inline_to_depth1(fs, in) < 0) return -1;
        root = (ext4_extent_header_t *)in->block;
    }

    if (root->eh_depth == 1) {
        ext4_extent_idx_t *idx = (ext4_extent_idx_t *)((uint8_t *)in->block + sizeof(*root));
        int pick = -1;
        uint16_t i;
        for (i = 0; i < root->eh_entries; ++i) {
            if (idx[i].ei_block <= lblock) pick = (int)i;
            else break;
        }
        if (pick < 0) pick = 0;
        if (pick >= (int)root->eh_entries) return -1;
        if (read_block(fs, idx_leaf_phys(&idx[pick]), fs->block_work) < 0) return -1;
        if (extent_node_insert((ext4_extent_header_t *)fs->block_work, lblock, pblock) < 0) {
            return extent_split_leaf_and_insert(
                fs, root, idx, (uint16_t)pick, lblock, pblock);
        }
        {
            ext4_extent_header_t *leaf = (ext4_extent_header_t *)fs->block_work;
            ext4_extent_t *ex = (ext4_extent_t *)(fs->block_work + sizeof(*leaf));
            if (leaf->eh_entries > 0) idx[pick].ei_block = ex[0].ee_block;
        }
        return write_block(fs, idx_leaf_phys(&idx[pick]), fs->block_work);
    }

    return -1;
}

static int extent_map_create(ext4_fs_t *fs, ext4_inode_t *in, uint32_t lblock, uint32_t *phys_out) {
    uint32_t phys = 0;
    int nb;
    if (!fs || !in || !phys_out) return -1;
    if (extent_find_phys(fs, in, lblock, &phys) == 0) {
        *phys_out = phys;
        return 0;
    }
    nb = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo, fs->sb.blocks_per_group, 0);
    if (nb < 0) return -1;
    if (extent_map_insert_tree(fs, in, lblock, (uint32_t)nb) < 0) {
        (void)ext4_free_block(fs, (uint32_t)nb, 0);
        return -1;
    }
    *phys_out = (uint32_t)nb;
    return 0;
}

static int legacy_map_create(ext4_fs_t *fs, ext4_inode_t *in, uint32_t lblock, uint32_t *phys_out) {
    int nb;
    if (!fs || !in || !phys_out) return -1;
    if (legacy_find_phys(fs, in, lblock, phys_out) == 0) return 0;
    nb = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo, fs->sb.blocks_per_group, 0);
    if (nb < 0) return -1;
    if (lblock < 12) {
        in->block[lblock] = (uint32_t)nb;
        *phys_out = (uint32_t)nb;
        return 0;
    }
    lblock -= 12;
    {
        uint32_t ents = fs->block_size / 4;
        if (lblock >= ents) return -1;
        if (!in->block[12]) {
            int ib = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo, fs->sb.blocks_per_group, 0);
            if (ib < 0) return -1;
            in->block[12] = (uint32_t)ib;
            memset(fs->io, 0, fs->block_size);
            if (write_block(fs, in->block[12], fs->io) < 0) return -1;
        }
        if (read_block(fs, in->block[12], fs->io) < 0) return -1;
        ((uint32_t *)fs->io)[lblock] = (uint32_t)nb;
        if (write_block(fs, in->block[12], fs->io) < 0) return -1;
        *phys_out = (uint32_t)nb;
        return 0;
    }
}

static int map_create_phys(ext4_fs_t *fs, ext4_inode_t *in, uint32_t lblock,
                           uint32_t *phys_out, int *created_out) {
    uint32_t free_before;
    uint32_t allocated;
    int rc;
    if (!fs || !in || !phys_out) return -1;
    if (created_out) *created_out = 0;
    free_before = fs->sb.free_blocks_count_lo;
    if (in->flags & EXT4_EXTENTS_FL)
        rc = extent_map_create(fs, in, lblock, phys_out);
    else
        rc = legacy_map_create(fs, in, lblock, phys_out);
    if (fs->sb.free_blocks_count_lo > free_before) return -1;
    allocated = free_before - fs->sb.free_blocks_count_lo;
    if (ext4_inode_charge_blocks(fs, in, allocated) < 0) return -1;
    if (created_out) *created_out = allocated != 0u;
    return rc;
}

static uint32_t extent_node_first_logical(const ext4_extent_header_t *header) {
    if (!header || !header->eh_entries) return UINT32_MAX;
    if (header->eh_depth == 0) {
        const ext4_extent_t *extent =
            (const ext4_extent_t *)((const uint8_t *)header + sizeof(*header));
        return extent[0].ee_block;
    }
    {
        const ext4_extent_idx_t *index =
            (const ext4_extent_idx_t *)((const uint8_t *)header + sizeof(*header));
        return index[0].ei_block;
    }
}

static int extent_truncate_node(ext4_fs_t *fs, ext4_extent_header_t *header,
                                uint32_t keep_blocks, uint32_t work_depth,
                                uint32_t *first_logical,
                                uint32_t *freed_blocks) {
    if (!fs || !header || !extent_header_valid(header) ||
        header->eh_depth > EXT4_MAX_EXTENT_DEPTH)
        return -1;
    if (header->eh_depth == 0) {
        ext4_extent_t *extent =
            (ext4_extent_t *)((uint8_t *)header + sizeof(*header));
        uint16_t output = 0;
        uint16_t old_entries = header->eh_entries;
        for (uint16_t i = 0; i < old_entries; ++i) {
            uint32_t logical = extent[i].ee_block;
            uint32_t length = extent_actual_length(&extent[i]);
            uint32_t physical = extent_start_phys(&extent[i]);
            uint32_t retained = 0;
            if (!length) return -1;
            if (logical < keep_blocks) {
                retained = keep_blocks - logical;
                if (retained > length) retained = length;
            }
            if (retained < length &&
                ext4_free_block_run(fs, physical + retained,
                                    length - retained, freed_blocks) < 0)
                return -1;
            if (retained) {
                if (output != i) extent[output] = extent[i];
                extent_set_length(&extent[output], retained);
                ++output;
            }
        }
        if (output < old_entries)
            memset(&extent[output], 0,
                   (uint32_t)(old_entries - output) * sizeof(*extent));
        header->eh_entries = output;
        if (first_logical)
            *first_logical = output ? extent[0].ee_block : UINT32_MAX;
        return 0;
    }

    if (work_depth >= EXT4_MAX_EXTENT_DEPTH) return -1;
    {
        ext4_extent_idx_t *index =
            (ext4_extent_idx_t *)((uint8_t *)header + sizeof(*header));
        uint16_t old_entries = header->eh_entries;
        uint16_t output = 0;
        for (uint16_t i = 0; i < old_entries; ++i) {
            uint32_t child_block = idx_leaf_phys(&index[i]);
            ext4_extent_header_t *child =
                (ext4_extent_header_t *)fs->extent_work[work_depth];
            uint32_t child_first = UINT32_MAX;
            if (!child_block || read_block(fs, child_block, child) < 0 ||
                !extent_header_valid(child) ||
                child->eh_depth + 1u != header->eh_depth)
                return -1;
            if (extent_truncate_node(fs, child, keep_blocks, work_depth + 1u,
                                     &child_first, freed_blocks) < 0)
                return -1;
            if (!child->eh_entries) {
                if (ext4_free_block(fs, child_block, freed_blocks) < 0)
                    return -1;
                continue;
            }
            if (write_block(fs, child_block, child) < 0) return -1;
            if (output != i) index[output] = index[i];
            index[output].ei_block = child_first;
            ++output;
        }
        if (output < old_entries)
            memset(&index[output], 0,
                   (uint32_t)(old_entries - output) * sizeof(*index));
        header->eh_entries = output;
        if (first_logical)
            *first_logical = extent_node_first_logical(header);
    }
    return 0;
}

static int extent_remove_range_node(ext4_fs_t *fs,
                                    ext4_extent_header_t *header,
                                    uint32_t first_block,
                                    uint32_t end_block,
                                    uint32_t work_depth,
                                    uint32_t *first_logical,
                                    uint32_t *freed_blocks) {
    if (!fs || !header || !extent_header_valid(header) ||
        first_block >= end_block ||
        header->eh_depth > EXT4_MAX_EXTENT_DEPTH)
        return -1;
    if (header->eh_depth == 0) {
        ext4_extent_header_t *source_header;
        ext4_extent_t *source;
        ext4_extent_t *destination;
        uint16_t old_entries = header->eh_entries;
        uint16_t output = 0;
        uint32_t bytes = sizeof(*header) +
                         (uint32_t)old_entries * sizeof(*source);

        if (bytes > sizeof(fs->extent_scratch)) return -1;
        memcpy(fs->extent_scratch, header, bytes);
        source_header = (ext4_extent_header_t *)fs->extent_scratch;
        source = (ext4_extent_t *)(fs->extent_scratch +
                                   sizeof(*source_header));
        destination = (ext4_extent_t *)((uint8_t *)header +
                                        sizeof(*header));
        header->eh_entries = 0;

        for (uint16_t i = 0; i < old_entries; ++i) {
            uint32_t logical = source[i].ee_block;
            uint32_t length = extent_actual_length(&source[i]);
            uint32_t physical = extent_start_phys(&source[i]);
            uint32_t extent_end;
            uint32_t remove_start;
            uint32_t remove_end;
            if (!length || logical > UINT32_MAX - length) return -1;
            extent_end = logical + length;
            remove_start = logical > first_block ? logical : first_block;
            remove_end = extent_end < end_block ? extent_end : end_block;
            if (remove_start >= remove_end) {
                if (output >= header->eh_max) return -1;
                destination[output++] = source[i];
                continue;
            }

            if (ext4_free_block_run(
                    fs, physical + (remove_start - logical),
                    remove_end - remove_start, freed_blocks) < 0)
                return -1;
            if (remove_start > logical) {
                if (output >= header->eh_max) return -1;
                destination[output] = source[i];
                extent_set_length(&destination[output],
                                  remove_start - logical);
                ++output;
            }
            if (remove_end < extent_end) {
                if (output >= header->eh_max) return -1;
                destination[output] = source[i];
                destination[output].ee_block = remove_end;
                destination[output].ee_start_hi = 0;
                destination[output].ee_start_lo =
                    physical + (remove_end - logical);
                extent_set_length(&destination[output],
                                  extent_end - remove_end);
                ++output;
            }
        }
        if (output < old_entries)
            memset(&destination[output], 0,
                   (uint32_t)(old_entries - output) * sizeof(*destination));
        header->eh_entries = output;
        if (first_logical)
            *first_logical = output ? destination[0].ee_block : UINT32_MAX;
        return 0;
    }

    if (work_depth >= EXT4_MAX_EXTENT_DEPTH) return -1;
    {
        ext4_extent_idx_t *index =
            (ext4_extent_idx_t *)((uint8_t *)header + sizeof(*header));
        uint16_t old_entries = header->eh_entries;
        uint16_t output = 0;
        for (uint16_t i = 0; i < old_entries; ++i) {
            uint32_t child_block = idx_leaf_phys(&index[i]);
            ext4_extent_header_t *child =
                (ext4_extent_header_t *)fs->extent_work[work_depth];
            uint32_t child_first = UINT32_MAX;
            if (!child_block || read_block(fs, child_block, child) < 0 ||
                !extent_header_valid(child) ||
                child->eh_depth + 1u != header->eh_depth)
                return -1;
            if (extent_remove_range_node(
                    fs, child, first_block, end_block, work_depth + 1u,
                    &child_first, freed_blocks) < 0)
                return -1;
            if (!child->eh_entries) {
                block_cache_invalidate(fs, child_block);
                if (ext4_free_block(fs, child_block, freed_blocks) < 0)
                    return -1;
                continue;
            }
            if (write_block(fs, child_block, child) < 0) return -1;
            if (output != i) index[output] = index[i];
            index[output].ei_block = child_first;
            ++output;
        }
        if (output < old_entries)
            memset(&index[output], 0,
                   (uint32_t)(old_entries - output) * sizeof(*index));
        header->eh_entries = output;
        if (first_logical)
            *first_logical = extent_node_first_logical(header);
    }
    return 0;
}

static uint64_t legacy_indirect_span(uint32_t entries, uint32_t depth) {
    uint64_t span = 1;
    while (depth--) {
        if (span > UINT64_MAX / entries) return UINT64_MAX;
        span *= entries;
    }
    return span;
}

static int legacy_truncate_indirect(ext4_fs_t *fs, uint32_t *pointer,
                                    uint32_t depth, uint64_t logical_base,
                                    uint64_t keep_blocks, uint32_t work_depth,
                                    uint32_t *freed_blocks) {
    uint32_t entries;
    uint32_t *table;
    uint64_t child_span;
    int changed = 0;
    int any = 0;
    if (!fs || !pointer || !*pointer || !depth || depth > 3u ||
        work_depth >= 3u)
        return pointer && !*pointer ? 0 : -1;
    entries = fs->block_size / sizeof(uint32_t);
    if (!entries) return -1;
    child_span = legacy_indirect_span(entries, depth - 1u);
    table = (uint32_t *)fs->legacy_work[work_depth];
    if (read_block(fs, *pointer, table) < 0) return -1;
    for (uint32_t i = 0; i < entries; ++i) {
        uint64_t child_base;
        if (!table[i]) continue;
        child_base = logical_base + (uint64_t)i * child_span;
        if (child_base + child_span <= keep_blocks) {
            any = 1;
            continue;
        }
        if (depth == 1u) {
            if (ext4_free_block(fs, table[i], freed_blocks) < 0) return -1;
            table[i] = 0;
            changed = 1;
        } else {
            uint32_t old = table[i];
            if (legacy_truncate_indirect(fs, &table[i], depth - 1u,
                                         child_base, keep_blocks,
                                         work_depth + 1u,
                                         freed_blocks) < 0)
                return -1;
            if (table[i] != old) changed = 1;
            if (table[i]) any = 1;
        }
    }
    if (!any) {
        uint32_t metadata = *pointer;
        *pointer = 0;
        return ext4_free_block(fs, metadata, freed_blocks);
    }
    return changed ? write_block(fs, *pointer, table) : 0;
}

static int legacy_remove_range_indirect(
    ext4_fs_t *fs, uint32_t *pointer, uint32_t depth,
    uint64_t logical_base, uint64_t first_block, uint64_t end_block,
    uint32_t work_depth, uint32_t *freed_blocks) {
    uint32_t entries;
    uint32_t *table;
    uint64_t child_span;
    int changed = 0;
    int any = 0;

    if (!fs || !pointer || !*pointer || !depth || depth > 3u ||
        work_depth >= 3u)
        return pointer && !*pointer ? 0 : -1;
    entries = fs->block_size / sizeof(uint32_t);
    if (!entries) return -1;
    child_span = legacy_indirect_span(entries, depth - 1u);
    table = (uint32_t *)fs->legacy_work[work_depth];
    if (read_block(fs, *pointer, table) < 0) return -1;

    for (uint32_t i = 0; i < entries; ++i) {
        uint64_t child_base;
        uint64_t child_end;
        if (!table[i]) continue;
        child_base = logical_base + (uint64_t)i * child_span;
        child_end = child_base + child_span;
        if (child_end <= first_block || child_base >= end_block) {
            any = 1;
            continue;
        }
        if (depth == 1u) {
            block_cache_invalidate(fs, table[i]);
            if (ext4_free_block(fs, table[i], freed_blocks) < 0) return -1;
            table[i] = 0;
            changed = 1;
        } else {
            uint32_t old = table[i];
            if (legacy_remove_range_indirect(
                    fs, &table[i], depth - 1u, child_base,
                    first_block, end_block, work_depth + 1u,
                    freed_blocks) < 0)
                return -1;
            if (table[i] != old) changed = 1;
            if (table[i]) any = 1;
        }
    }
    if (!any) {
        uint32_t metadata = *pointer;
        *pointer = 0;
        block_cache_invalidate(fs, metadata);
        return ext4_free_block(fs, metadata, freed_blocks);
    }
    return changed ? write_block(fs, *pointer, table) : 0;
}

static int ext4_remove_mapping_range(ext4_fs_t *fs, ext4_inode_t *inode,
                                     uint32_t first_block,
                                     uint32_t end_block) {
    uint32_t freed = 0;
    uint32_t sectors_per_block;
    if (!fs || !inode || first_block >= end_block) return 0;

    if (inode->flags & EXT4_EXTENTS_FL) {
        ext4_extent_header_t *root = (ext4_extent_header_t *)inode->block;
        uint32_t first = UINT32_MAX;
        if (root->eh_depth == 0 && root->eh_entries >= root->eh_max &&
            extent_convert_inline_to_depth1(fs, inode) < 0)
            return -1;
        root = (ext4_extent_header_t *)inode->block;
        if (extent_remove_range_node(fs, root, first_block, end_block,
                                     0, &first, &freed) < 0)
            return -1;
    } else {
        uint32_t entries = fs->block_size / sizeof(uint32_t);
        uint64_t logical = 12u;
        for (uint32_t i = 0; i < 12u; ++i) {
            if (!inode->block[i] || i < first_block || i >= end_block)
                continue;
            block_cache_invalidate(fs, inode->block[i]);
            if (ext4_free_block(fs, inode->block[i], &freed) < 0)
                return -1;
            inode->block[i] = 0;
        }
        for (uint32_t depth = 1; depth <= 3u; ++depth) {
            uint64_t span = legacy_indirect_span(entries, depth);
            if (inode->block[11u + depth] &&
                legacy_remove_range_indirect(
                    fs, &inode->block[11u + depth], depth, logical,
                    first_block, end_block, 0, &freed) < 0)
                return -1;
            logical += span;
        }
    }

    sectors_per_block = fs->block_size / 512u;
    if (sectors_per_block && freed) {
        uint64_t released = (uint64_t)freed * sectors_per_block;
        inode->blocks_lo = released >= inode->blocks_lo ? 0u :
                           inode->blocks_lo - (uint32_t)released;
    }
    return 0;
}

static int ext4_truncate_mappings(ext4_fs_t *fs, ext4_inode_t *inode,
                                  uint32_t new_size, int release_all,
                                  uint32_t *freed_blocks) {
    uint32_t old_size;
    uint32_t keep_blocks;
    uint32_t sectors_per_block;
    uint32_t freed = 0;
    if (!fs || !inode) return -1;
    old_size = inode_size_get(inode);
    if (!release_all && new_size >= old_size) return 0;
    /* Special inodes store device metadata, not block mappings, in i_block. */
    if ((inode->mode & 0xf000u) != VFS_INODE_FILE &&
        (inode->mode & 0xf000u) != VFS_INODE_DIR &&
        (inode->mode & 0xf000u) != VFS_INODE_LNK)
        return 0;
    if ((inode->mode & 0xf000u) == VFS_INODE_LNK && inode->blocks_lo == 0)
        return 0;
    keep_blocks = (new_size + fs->block_size - 1u) / fs->block_size;
    if (!release_all && new_size % fs->block_size) {
        uint32_t physical;
        uint32_t offset = new_size % fs->block_size;
        if (map_find_phys(fs, inode, keep_blocks - 1u, &physical) == 0 && physical) {
            if (read_block(fs, physical, fs->io) < 0) return -1;
            memset(fs->io + offset, 0, fs->block_size - offset);
            if (write_block(fs, physical, fs->io) < 0) return -1;
        }
    }
    if (inode->flags & EXT4_EXTENTS_FL) {
        ext4_extent_header_t *root = (ext4_extent_header_t *)inode->block;
        uint32_t first = UINT32_MAX;
        if (extent_truncate_node(fs, root, keep_blocks, 0,
                                 &first, &freed) < 0)
            return -1;
    } else {
        uint32_t entries = fs->block_size / sizeof(uint32_t);
        uint64_t logical = 12u;
        for (uint32_t i = 0; i < 12u; ++i) {
            if (!inode->block[i] || i < keep_blocks) continue;
            if (ext4_free_block(fs, inode->block[i], &freed) < 0) return -1;
            inode->block[i] = 0;
        }
        for (uint32_t depth = 1; depth <= 3u; ++depth) {
            uint64_t span = legacy_indirect_span(entries, depth);
            if (inode->block[11u + depth] &&
                legacy_truncate_indirect(fs, &inode->block[11u + depth],
                                         depth, logical, keep_blocks, 0,
                                         &freed) < 0)
                return -1;
            logical += span;
        }
    }
    sectors_per_block = fs->block_size / 512u;
    if (sectors_per_block && freed) {
        uint64_t released = (uint64_t)freed * sectors_per_block;
        inode->blocks_lo = released >= inode->blocks_lo ? 0u :
                           inode->blocks_lo - (uint32_t)released;
    }
    if (freed_blocks) *freed_blocks += freed;
    return 0;
}

static int ext4_zero_mapped_range(ext4_fs_t *fs, const ext4_inode_t *in, uint32_t start, uint32_t end) {
    if (!fs || !in) return -1;
    if (end <= start) return 0;

    while (start < end) {
        uint32_t lbi = start / fs->block_size;
        uint32_t bo = start % fs->block_size;
        uint32_t n = fs->block_size - bo;
        uint32_t pblk = 0;
        if (n > end - start) n = end - start;

        /* Linux-visible holes and bytes exposed by growth must read as zero. */
        if (map_find_phys(fs, in, lbi, &pblk) == 0 && pblk != 0) {
            if (read_block(fs, pblk, fs->io) < 0) return -1;
            memset(fs->io + bo, 0, n);
            if (write_block(fs, pblk, fs->io) < 0) return -1;
        }
        start += n;
    }
    return 0;
}

static void ext4_debug_dump_dir(ext4_fs_t *fs, uint32_t ino, const char *label) {
    ext4_inode_t in;
    uint32_t size, pblk = 0;
    int map_rc;
    uint32_t off;
    if (!fs || !label) return;
    if (read_inode(fs, ino, &in) < 0) {
        EXT4_DBG("[ext4] dbg %s ino=%u read_inode failed\n", label, (unsigned)ino);
        return;
    }
    size = inode_size_get(&in);
    map_rc = map_find_phys(fs, &in, 0, &pblk);
    EXT4_DBG("[ext4] dbg %s ino=%u mode=0x%x flags=0x%x size=%u map0_rc=%d map0=%u\n",
             label, (unsigned)ino, (unsigned)in.mode, (unsigned)in.flags, (unsigned)size, map_rc, (unsigned)pblk);
    if (map_rc < 0) return;
    if (read_block(fs, pblk, fs->io) < 0) {
        EXT4_DBG("[ext4] dbg %s ino=%u read_block(%u) failed\n", label, (unsigned)ino, (unsigned)pblk);
        return;
    }
    off = 0;
    while (off + 8 <= fs->block_size && off < 256) {
        ext4_dirent_t *de = (ext4_dirent_t *)(fs->io + off);
        char nm[33];
        uint32_t nlen = de->name_len;
        if (de->rec_len < 8 || off + de->rec_len > fs->block_size) {
            EXT4_DBG("[ext4] dbg %s off=%u invalid rec_len=%u\n",
                     label, (unsigned)off, (unsigned)de->rec_len);
            break;
        }
        if (nlen > 32) nlen = 32;
        memcpy(nm, de->name, nlen);
        nm[nlen] = 0;
        EXT4_DBG("[ext4] dbg %s off=%u ino=%u rec=%u nlen=%u type=%u name='%s'\n",
                 label, (unsigned)off, (unsigned)de->inode, (unsigned)de->rec_len,
                 (unsigned)de->name_len, (unsigned)de->file_type, nm);
        off += de->rec_len;
    }
}

static int ext4_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t dino;
    uint32_t dsz, blk_n, bi;
    uint32_t matched_ino = 0;
    int complete_scan = 1;
    if (!fs || !dir || !name || !out) return -1;
    {
        uint32_t cached_ino = 0;
        int miss = 0;
        if (lookup_cache_find(fs, dir->ino, name, &cached_ino, &miss,
                              0, 0)) {
            ext4_inode_t in;
            if (miss) return -1;
            if (cached_ino == 0 || read_inode(fs, cached_ino, &in) < 0) return -1;
            ext4_fill_vfs_inode(cached_ino, &in, out);
            if (!out->mode) return -1;
            return 0;
        }
    }
    if (read_inode(fs, dir->ino, &dino) < 0) return -1;
    if (strcmp(name, "init") == 0) {
        uint32_t p0 = 0;
        int mr = map_find_phys(fs, &dino, 0, &p0);
        EXT4_DBG("[ext4] dbg lookup-init dir_ino=%u flags=0x%x size=%u map0_rc=%d map0=%u\n",
                 (unsigned)dir->ino, (unsigned)dino.flags, (unsigned)inode_size_get(&dino), mr, (unsigned)p0);
    }
    dsz = inode_size_get(&dino);
    if (directory_index_is_complete(fs, dir->ino, dsz)) return -1;
    blk_n = (dsz + fs->block_size - 1) / fs->block_size;
    for (bi = 0; bi < blk_n; ++bi) {
        uint32_t pblk;
        uint32_t off = 0;
        if (map_find_phys(fs, &dino, bi, &pblk) < 0) {
            complete_scan = 0;
            continue;
        }
        if (read_block(fs, pblk, fs->io) < 0) {
            complete_scan = 0;
            continue;
        }
        while (off + 8 <= fs->block_size) {
            ext4_dirent_t *de = (ext4_dirent_t *)(fs->io + off);
            if (de->rec_len < 8 || off + de->rec_len > fs->block_size) {
                complete_scan = 0;
                break;
            }
            if (de->inode && de->name_len > 0 && de->name_len < VFS_NAME_MAX) {
                char dn[VFS_NAME_MAX];
                uint32_t found_ino = de->inode;
                memcpy(dn, de->name, de->name_len);
                dn[de->name_len] = 0;
                if (!lookup_cache_store(fs, dir->ino, dn, found_ino, 0,
                                        pblk, off))
                    complete_scan = 0;
                if (!matched_ino && strcmp(dn, (char *)name) == 0)
                    matched_ino = found_ino;
            }
            off += de->rec_len;
        }
    }
    if (complete_scan)
        directory_index_mark_complete(fs, dir->ino, dsz);
    if (matched_ino) {
        ext4_inode_t in;
        if (read_inode(fs, matched_ino, &in) < 0) return -1;
        ext4_fill_vfs_inode(matched_ino, &in, out);
        return out->mode ? 0 : -1;
    }
    (void)lookup_cache_store(fs, dir->ino, name, 0, 1, 0, 0);
    return -1;
}

static uint16_t ext4_dirent_mode(uint8_t type) {
    switch (type) {
        case 1u: return VFS_INODE_FILE;
        case 2u: return VFS_INODE_DIR;
        case 3u: return VFS_INODE_CHR;
        case 4u: return VFS_INODE_BLK;
        case 5u: return VFS_INODE_FIFO;
        case 6u: return VFS_INODE_SOCK;
        case 7u: return VFS_INODE_LNK;
        default: return 0u;
    }
}

static int ext4_readdir_entry(vfs_superblock_t *sb, vfs_inode_t *dir,
                              uint32_t idx, char *name_out,
                              vfs_inode_t *inode_out, int dirent_only) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_readdir_cache_entry_t *cursor;
    ext4_inode_t dino;
    uint32_t dsz, blk_n, bi, seen = 0;
    uint32_t start_bi = 0;
    uint32_t start_off = 0;
    if (!fs || !dir || !name_out || !inode_out) return -1;
    if (read_inode(fs, dir->ino, &dino) < 0) return -1;
    dsz = inode_size_get(&dino);
    blk_n = (dsz + fs->block_size - 1) / fs->block_size;
    cursor = readdir_cache_select(fs, dir->ino, idx == 0);

    /*
     * VFS currently exposes Linux getdents as repeated index lookups instead
     * of passing a persistent directory file offset into the filesystem.  A
     * directory scan therefore calls ext4_readdir(..., 0), then 1, then 2...
     * Without remembering the previous physical record, every call rescans the
     * directory from byte zero.  Large /usr trees make XFCE startup and Thunar
     * plugin discovery look broken because a simple recursive walk turns into
     * O(n^2) directory parsing.  This cache preserves Linux-visible behavior
     * while amortizing the common sequential getdents pattern.
     */
    if (cursor && cursor->valid &&
        cursor->dir_size == dsz &&
        cursor->next_idx == idx &&
        cursor->next_block_index < blk_n &&
        cursor->next_block_offset < fs->block_size) {
        seen = idx;
        start_bi = cursor->next_block_index;
        start_off = cursor->next_block_offset;
    } else if (cursor && idx == 0) {
        cursor->dir_size = dsz;
        cursor->next_idx = 0;
        cursor->next_block_index = 0;
        cursor->next_block_offset = 0;
    }

    for (bi = start_bi; bi < blk_n; ++bi) {
        uint32_t pblk;
        uint32_t off = (bi == start_bi) ? start_off : 0;
        if (map_find_phys(fs, &dino, bi, &pblk) < 0) continue;
        if (read_block(fs, pblk, fs->io) < 0) continue;
        while (off + 8 <= fs->block_size) {
            ext4_dirent_t *de = (ext4_dirent_t *)(fs->io + off);
            if (de->rec_len < 8 || off + de->rec_len > fs->block_size) break;
            if (de->inode && de->name_len > 0 && de->name_len < VFS_NAME_MAX) {
                if (seen == idx) {
                    uint32_t found_ino = de->inode;
                    uint32_t next_off = off + de->rec_len;
                    memcpy(name_out, de->name, de->name_len);
                    name_out[de->name_len] = 0;
                    if (dirent_only) {
                        uint16_t mode = ext4_dirent_mode(de->file_type);

                        if (!mode) {
                            ext4_inode_t in;

                            if (read_inode(fs, found_ino, &in) < 0)
                                return -1;
                            ext4_fill_vfs_inode(found_ino, &in, inode_out);
                        } else {
                            memset(inode_out, 0, sizeof(*inode_out));
                            inode_out->ino = found_ino;
                            inode_out->mode = mode;
                        }
                    } else {
                        ext4_inode_t in;

                        if (read_inode(fs, found_ino, &in) < 0) return -1;
                        ext4_fill_vfs_inode(found_ino, &in, inode_out);
                    }
                    /*
                     * Linux populates its dentry cache while getdents walks a
                     * directory.  Desktop applications commonly enumerate a
                     * resource directory and then stat/open every returned
                     * name.  Seeding the existing coherent lookup cache here
                     * prevents that second phase from rescanning the ext4
                     * directory from byte zero for each unique resource.
                     */
                    lookup_cache_store(
                        fs, dir->ino, name_out, found_ino, 0, pblk, off);
                    if (!inode_out->mode) return -1;
                    if (!cursor)
                        cursor = readdir_cache_select(fs, dir->ino, 1);
                    if (cursor) {
                        cursor->valid = 1;
                        cursor->dir_ino = dir->ino;
                        cursor->dir_size = dsz;
                        cursor->next_idx = idx + 1;
                        cursor->next_block_index = bi;
                        cursor->next_block_offset = next_off;
                        cursor->age = ++fs->readdir_cache_clock;
                    }
                    if (cursor && next_off >= fs->block_size) {
                        cursor->next_block_index = bi + 1;
                        cursor->next_block_offset = 0;
                    }
                    return 0;
                }
                seen++;
            }
            off += de->rec_len;
        }
    }
    if (cursor) cursor->valid = 0;
    return -1;
}

static int ext4_readdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                        uint32_t idx, char *name_out,
                        vfs_inode_t *inode_out) {
    return ext4_readdir_entry(
        sb, dir, idx, name_out, inode_out, 0);
}

static int ext4_readdir_dirent(vfs_superblock_t *sb, vfs_inode_t *dir,
                               uint32_t idx, char *name_out,
                               uint32_t *inode_number, uint16_t *mode) {
    vfs_inode_t inode;
    int result;

    if (!inode_number || !mode) return -1;
    result = ext4_readdir_entry(
        sb, dir, idx, name_out, &inode, 1);
    if (result < 0) return result;
    *inode_number = inode.ino;
    *mode = inode.mode;
    return 0;
}

static int ext4_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t in;
    uint32_t size;
    uint8_t *out = (uint8_t *)buf;
    uint32_t done = 0;
    if (!fs || !inode || !buf) return -1;
    if (read_inode(fs, inode->ino, &in) < 0) return -1;
    size = inode_size_get(&in);
    if (off >= size) return 0;
    if (off + len > size) len = size - off;
    while (done < len) {
        uint32_t pos = off + done;
        uint32_t lbi = pos / fs->block_size;
        uint32_t bo = pos % fs->block_size;
        uint32_t pblk;
        uint32_t n;
        n = fs->block_size - bo;
        if (n > len - done) n = len - done;
        if (bo == 0 && n == fs->block_size && fs->block_size <= 4096) {
            uint32_t run_blocks = 0;
            uint32_t run_first_pblk = 0;
            uint32_t run_prev_pblk = 0;
            uint32_t max_blocks = (len - done) / fs->block_size;
            if (max_blocks > EXT4_READ_RUN_BLOCKS) max_blocks = EXT4_READ_RUN_BLOCKS;

            while (run_blocks < max_blocks) {
                uint32_t rpblk;
                if (map_find_phys(fs, &in, lbi + run_blocks, &rpblk) < 0 || rpblk == 0) break;
                if (run_blocks == 0) {
                    run_first_pblk = rpblk;
                } else if (rpblk != run_prev_pblk + 1u) {
                    break;
                }
                run_prev_pblk = rpblk;
                run_blocks++;
            }

            if (run_blocks > 1) {
                uint32_t bytes = run_blocks * fs->block_size;
                if (read_block_run(fs, run_first_pblk, run_blocks, fs->read_run) < 0) break;
                memcpy(out + done, fs->read_run, bytes);
                done += bytes;
                continue;
            }
        }
        if (map_find_phys(fs, &in, lbi, &pblk) < 0 || pblk == 0) {
            /* Sparse hole / unmapped logical block reads as zeroes. */
            memset(out + done, 0, n);
            done += n;
            continue;
        }
        if (read_block(fs, pblk, fs->io) < 0) break;
        memcpy(out + done, fs->io + bo, n);
        done += n;
    }
    return (int)done;
}

static ext4_ro_workspace_t *ext4_ro_workspace_acquire(void) {
    for (;;) {
        uint32_t sequence = __atomic_load_n(&g_ro_ws_sequence,
                                             __ATOMIC_ACQUIRE);
        for (uint32_t i = 0; i < EXT4_RO_WORKSPACES; ++i) {
            if (!__sync_lock_test_and_set(&g_ro_ws[i].busy, 1)) return &g_ro_ws[i];
        }
        if (__atomic_load_n(&g_ro_ws_sequence, __ATOMIC_ACQUIRE) == sequence &&
            !kernel_runtime_yield())
            ext4_cpu_relax();
    }
}

static void ext4_ro_workspace_release(ext4_ro_workspace_t *ws) {
    if (!ws) return;
    __sync_lock_release(&ws->busy);
    __atomic_add_fetch(&g_ro_ws_sequence, 1u, __ATOMIC_RELEASE);
}

static int ext4_read_ro(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf,
                        uint32_t len, ext4_ro_workspace_t *ws) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t in;
    uint32_t size;
    uint8_t *out = (uint8_t *)buf;
    uint32_t done = 0;
    if (!fs || !inode || !buf || !ws) return -1;
    if (read_inode_ro(fs, inode->ino, &in, ws) < 0) return -1;
    size = inode_size_get(&in);
    if (off >= size) return 0;
    if (off + len > size) len = size - off;
    while (done < len) {
        uint32_t pos = off + done;
        uint32_t lbi = pos / fs->block_size;
        uint32_t bo = pos % fs->block_size;
        uint32_t pblk;
        uint32_t n = fs->block_size - bo;
        if (n > len - done) n = len - done;
        if (bo == 0 && n == fs->block_size && fs->block_size <= 4096) {
            uint32_t run_blocks = 0;
            uint32_t run_first_pblk = 0;
            uint32_t run_prev_pblk = 0;
            uint32_t max_blocks = (len - done) / fs->block_size;
            if (max_blocks > EXT4_READ_RUN_BLOCKS) max_blocks = EXT4_READ_RUN_BLOCKS;
            while (run_blocks < max_blocks) {
                uint32_t rpblk;
                if (map_find_phys_ro(fs, &in, lbi + run_blocks, &rpblk, ws) < 0 || rpblk == 0) break;
                if (run_blocks == 0) run_first_pblk = rpblk;
                else if (rpblk != run_prev_pblk + 1u) break;
                run_prev_pblk = rpblk;
                run_blocks++;
            }
            if (run_blocks > 1) {
                uint32_t bytes = run_blocks * fs->block_size;
                /*
                 * The read-only workspace path permits concurrent readers and
                 * therefore cannot use the mount's mutable block cache.  It can
                 * still submit one contiguous block request directly into the
                 * caller's private buffer.  Issuing one request per 4 KiB block
                 * made every exec and shared-library fault pay hundreds of
                 * virtio/NVMe queue round trips despite extent contiguity.
                 */
                if (read_block_run_uncached(fs, run_first_pblk, run_blocks,
                                            out + done) < 0) break;
                done += bytes;
                continue;
            }
        }
        if (map_find_phys_ro(fs, &in, lbi, &pblk, ws) < 0 || pblk == 0) {
            memset(out + done, 0, n);
            done += n;
            continue;
        }
        if (read_block_uncached(fs, pblk, ws->io) < 0) break;
        memcpy(out + done, ws->io + bo, n);
        done += n;
    }
    return (int)done;
}

static int ext4_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t in;
    const uint8_t *src = (const uint8_t *)buf;
    uint32_t done = 0;
    uint32_t size;
    if (!fs || !inode || !buf) return -1;
    if (len > UINT32_MAX - off) return -1;
    if (read_inode(fs, inode->ino, &in) < 0) return -1;
    if (fs->block_size < 512u || (fs->block_size % 512u) != 0) return -1;
    size = inode_size_get(&in);
    if (off > size && ext4_zero_mapped_range(fs, &in, size, off) < 0) return -1;
    while (done < len) {
        uint32_t pos = off + done;
        uint32_t lbi = pos / fs->block_size;
        uint32_t bo = pos % fs->block_size;
        uint32_t pblk;
        uint32_t existing_pblk = 0;
        int had_mapping;
        uint32_t n = fs->block_size - bo;
        if (n > len - done) n = len - done;

        /* Fast path for sequential full-block writes: map a contiguous run
         * and submit a single large block-layer write. */
        if (bo == 0 && n == fs->block_size) {
            uint32_t run_blocks = 0;
            uint32_t run_first_pblk = 0;
            uint32_t run_prev_pblk = 0;
            uint32_t max_blocks = (len - done) / fs->block_size;
            if (max_blocks > 256u) max_blocks = 256u;

            while (run_blocks < max_blocks) {
                uint32_t rpblk;
                if (map_create_phys(
                        fs, &in, lbi + run_blocks, &rpblk, 0) < 0)
                    break;
                if (run_blocks == 0) {
                    run_first_pblk = rpblk;
                } else if (rpblk != run_prev_pblk + 1u) {
                    break;
                }
                run_prev_pblk = rpblk;
                run_blocks++;
            }

            if (run_blocks > 0) {
                int cached = 1;
                for (uint32_t ci = 0; ci < run_blocks; ++ci) {
                    if (block_cache_store(fs, run_first_pblk + ci, src + done + ci * fs->block_size, 1) < 0) {
                        cached = 0;
                        break;
                    }
                }
                if (cached) {
                    done += run_blocks * fs->block_size;
                    continue;
                }
                break;
            }
        }

        had_mapping = (map_find_phys(fs, &in, lbi, &existing_pblk) == 0 && existing_pblk != 0);
        if (map_create_phys(fs, &in, lbi, &pblk, 0) < 0) break;
        if (!(bo == 0 && n == fs->block_size)) {
            if (had_mapping) {
                if (read_block(fs, pblk, fs->io) < 0) break;
            } else {
                /*
                 * Never merge a partial write with old media contents from a
                 * freshly allocated block.  User-visible unwritten bytes in
                 * sparse or newly extended files must be zero-filled.
                 */
                memset(fs->io, 0, fs->block_size);
            }
            memcpy(fs->io + bo, src + done, n);
            if (write_block(fs, pblk, fs->io) < 0) break;
        } else {
            if (write_block(fs, pblk, src + done) < 0) break;
        }
        done += n;
    }
    size = inode_size_get(&in);
    if (off + done > size) {
        in.size_lo = off + done;
        in.size_high = 0;
        size = off + done;
    }
    in.mtime = ext4_now_sec();
    in.ctime = in.mtime;
    if (write_inode(fs, inode->ino, &in) < 0) return -1;
    inode->size = size;
    inode->mtime = in.mtime;
    inode->ctime = in.ctime;
    return (int)done;
}

static int ext4_truncate(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t len) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t in;
    uint32_t old_size;
    if (!fs || !inode) return -1;
    if (read_inode(fs, inode->ino, &in) < 0) return -1;
    old_size = inode_size_get(&in);
    if (len < old_size && ext4_truncate_mappings(fs, &in, len, 0, 0) < 0)
        return -1;
    if (len > old_size && ext4_zero_mapped_range(fs, &in, old_size, len) < 0) return -1;
    in.size_lo = len;
    in.size_high = 0;
    in.mtime = ext4_now_sec();
    in.ctime = in.mtime;
    if (write_inode(fs, inode->ino, &in) < 0) return -1;
    inode->size = len;
    inode->mtime = in.mtime;
    inode->ctime = in.ctime;
    return 0;
}

static int ext4_fallocate(vfs_superblock_t *sb, vfs_inode_t *inode,
                          uint32_t mode, uint64_t offset64,
                          uint64_t length64) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t in;
    uint32_t offset;
    uint32_t length;
    uint32_t end;
    uint32_t old_size;
    uint32_t first_block;
    uint32_t last_block;
    int zero_range;
    if (!fs || !inode || !length64 || offset64 > UINT32_MAX ||
        length64 > UINT32_MAX || offset64 + length64 > UINT32_MAX ||
        offset64 + length64 < offset64)
        return VFS_FALLOCATE_ERR_INVALID;
    if (mode & VFS_FALLOC_FL_PUNCH_HOLE) {
        if (mode != (VFS_FALLOC_FL_PUNCH_HOLE |
                     VFS_FALLOC_FL_KEEP_SIZE))
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        zero_range = 0;
    } else if (mode & VFS_FALLOC_FL_COLLAPSE_RANGE) {
        if (mode != VFS_FALLOC_FL_COLLAPSE_RANGE)
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        zero_range = 0;
    } else if (mode & VFS_FALLOC_FL_INSERT_RANGE) {
        if (mode != VFS_FALLOC_FL_INSERT_RANGE)
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        zero_range = 0;
    } else if (mode & VFS_FALLOC_FL_ZERO_RANGE) {
        if (mode & ~(VFS_FALLOC_FL_ZERO_RANGE | VFS_FALLOC_FL_KEEP_SIZE))
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        zero_range = 1;
    } else {
        if (mode & ~(VFS_FALLOC_FL_KEEP_SIZE | VFS_FALLOC_FL_UNSHARE_RANGE))
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        zero_range = 0;
    }

    offset = (uint32_t)offset64;
    length = (uint32_t)length64;
    end = offset + length;
    if (read_inode(fs, inode->ino, &in) < 0)
        return VFS_FALLOCATE_ERR_IO;
    old_size = inode_size_get(&in);

    if (mode & VFS_FALLOC_FL_PUNCH_HOLE) {
        uint32_t clipped_end;
        uint32_t first_full;
        uint32_t end_full;
        if (offset >= old_size) return 0;
        clipped_end = end > old_size ? old_size : end;
        first_full = (offset + fs->block_size - 1u) / fs->block_size;
        end_full = clipped_end / fs->block_size;
        if (first_full >= end_full) {
            if (ext4_zero_mapped_range(
                    fs, &in, offset, clipped_end) < 0)
                return VFS_FALLOCATE_ERR_IO;
        } else {
            uint32_t leading_end = first_full * fs->block_size;
            uint32_t trailing_start = end_full * fs->block_size;
            if (offset < leading_end &&
                ext4_zero_mapped_range(
                    fs, &in, offset, leading_end) < 0)
                return VFS_FALLOCATE_ERR_IO;
            if (trailing_start < clipped_end &&
                ext4_zero_mapped_range(
                    fs, &in, trailing_start, clipped_end) < 0)
                return VFS_FALLOCATE_ERR_IO;
            if (ext4_remove_mapping_range(
                    fs, &in, first_full, end_full) < 0)
                return VFS_FALLOCATE_ERR_IO;
        }
        in.mtime = ext4_now_sec();
        in.ctime = in.mtime;
        if (write_inode(fs, inode->ino, &in) < 0)
            return VFS_FALLOCATE_ERR_IO;
        inode->mtime = in.mtime;
        inode->ctime = in.ctime;
        return 0;
    }

    if (mode & VFS_FALLOC_FL_COLLAPSE_RANGE) {
        uint32_t source;
        if ((offset % fs->block_size) || (length % fs->block_size) ||
            end >= old_size)
            return VFS_FALLOCATE_ERR_INVALID;
        source = end;
        while (source < old_size) {
            uint32_t count = old_size - source;
            int got;
            if (count > sizeof(fs->extent_scratch))
                count = sizeof(fs->extent_scratch);
            if (count > length) count = length;
            got = ext4_read(sb, inode, source,
                            fs->extent_scratch, count);
            if (got != (int)count ||
                ext4_write(sb, inode, source - length,
                           fs->extent_scratch, count) != (int)count)
                return VFS_FALLOCATE_ERR_IO;
            source += count;
        }
        return ext4_truncate(sb, inode, old_size - length) == 0 ?
               0 : VFS_FALLOCATE_ERR_IO;
    }

    if (mode & VFS_FALLOC_FL_INSERT_RANGE) {
        uint32_t remaining;
        if ((offset % fs->block_size) || (length % fs->block_size) ||
            offset >= old_size || old_size > UINT32_MAX - length)
            return VFS_FALLOCATE_ERR_INVALID;
        if (ext4_truncate(sb, inode, old_size + length) < 0)
            return VFS_FALLOCATE_ERR_IO;
        remaining = old_size - offset;
        while (remaining) {
            uint32_t count = remaining;
            uint32_t source;
            int got;
            if (count > sizeof(fs->extent_scratch))
                count = sizeof(fs->extent_scratch);
            source = offset + remaining - count;
            got = ext4_read(sb, inode, source,
                            fs->extent_scratch, count);
            if (got != (int)count ||
                ext4_write(sb, inode, source + length,
                           fs->extent_scratch, count) != (int)count)
                return VFS_FALLOCATE_ERR_IO;
            remaining -= count;
        }
        if (read_inode(fs, inode->ino, &in) < 0 ||
            ext4_remove_mapping_range(
                fs, &in, offset / fs->block_size,
                end / fs->block_size) < 0)
            return VFS_FALLOCATE_ERR_IO;
        in.mtime = ext4_now_sec();
        in.ctime = in.mtime;
        if (write_inode(fs, inode->ino, &in) < 0)
            return VFS_FALLOCATE_ERR_IO;
        inode->size = inode_size_get(&in);
        inode->mtime = in.mtime;
        inode->ctime = in.ctime;
        return 0;
    }

    first_block = offset / fs->block_size;
    last_block = (end - 1u) / fs->block_size;

    for (uint32_t logical = first_block; logical <= last_block; ++logical) {
        uint32_t physical = 0;
        uint32_t block_start = logical * fs->block_size;
        uint32_t from = offset > block_start ? offset - block_start : 0u;
        uint32_t to = end < block_start + fs->block_size ?
                      end - block_start : fs->block_size;
        int created = 0;
        if (map_create_phys(
                fs, &in, logical, &physical, &created) < 0)
            return VFS_FALLOCATE_ERR_NOSPC;
        if (created) {
            memset(fs->io, 0, fs->block_size);
            if (write_block(fs, physical, fs->io) < 0)
                return VFS_FALLOCATE_ERR_IO;
        } else if (zero_range && to > from) {
            if (from == 0u && to == fs->block_size) {
                memset(fs->io, 0, fs->block_size);
            } else if (read_block(fs, physical, fs->io) < 0) {
                return VFS_FALLOCATE_ERR_IO;
            } else {
                memset(fs->io + from, 0, to - from);
            }
            if (write_block(fs, physical, fs->io) < 0)
                return VFS_FALLOCATE_ERR_IO;
        }
    }

    if (!(mode & VFS_FALLOC_FL_KEEP_SIZE) && end > old_size) {
        in.size_lo = end;
        in.size_high = 0;
        old_size = end;
    }
    in.mtime = ext4_now_sec();
    in.ctime = in.mtime;
    if (write_inode(fs, inode->ino, &in) < 0)
        return VFS_FALLOCATE_ERR_IO;
    inode->size = old_size;
    inode->mtime = in.mtime;
    inode->ctime = in.ctime;
    return 0;
}

static int ext4_seek_data_hole(vfs_superblock_t *sb,
                               const vfs_inode_t *inode,
                               uint64_t offset, int seek_hole,
                               uint64_t *result) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t disk_inode;
    uint64_t size;
    uint64_t logical;
    uint64_t last;

    if (!fs || !inode || !result || !inode->ino ||
        read_inode(fs, inode->ino, &disk_inode) < 0)
        return VFS_SEEK_DATA_HOLE_ERR_IO;
    size = inode_size_get(&disk_inode);
    if (offset >= size) return VFS_SEEK_DATA_HOLE_ERR_NO_DATA;
    logical = offset / fs->block_size;
    last = (size - 1u) / fs->block_size;
    while (logical <= last) {
        uint32_t physical = 0;
        int mapped = logical <= UINT32_MAX &&
            map_find_phys(fs, &disk_inode, (uint32_t)logical,
                          &physical) == 0 && physical != 0;
        if ((seek_hole && !mapped) || (!seek_hole && mapped)) {
            uint64_t block_offset = logical * fs->block_size;
            *result = block_offset < offset ? offset : block_offset;
            return 0;
        }
        ++logical;
    }
    if (seek_hole) {
        *result = size;
        return 0;
    }
    return VFS_SEEK_DATA_HOLE_ERR_NO_DATA;
}

static int ext4_map_extent(vfs_superblock_t *sb,
                           const vfs_inode_t *inode,
                           uint64_t offset, uint64_t length,
                           vfs_extent_t *extent) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t disk_inode;
    uint64_t size;
    uint64_t end;
    uint64_t logical;
    uint64_t last;
    uint32_t physical = 0;
    uint32_t first_physical;
    uint64_t logical_start;
    uint64_t logical_end;
    int final_extent = 1;

    if (!fs || !inode || !extent || !length || !inode->ino ||
        read_inode(fs, inode->ino, &disk_inode) < 0)
        return VFS_EXTENT_ERR_IO;
    size = inode_size_get(&disk_inode);
    if (offset >= size) return VFS_EXTENT_ERR_NO_DATA;
    end = offset + length;
    if (end < offset || end > size) end = size;
    logical = offset / fs->block_size;
    last = (end - 1u) / fs->block_size;

    while (logical <= last) {
        if (logical <= UINT32_MAX &&
            map_find_phys(fs, &disk_inode, (uint32_t)logical,
                          &physical) == 0 && physical != 0)
            break;
        ++logical;
    }
    if (logical > last) return VFS_EXTENT_ERR_NO_DATA;

    first_physical = physical;
    logical_start = logical * fs->block_size;
    if (logical_start < offset) {
        uint64_t delta = offset - logical_start;
        logical_start = offset;
        first_physical += (uint32_t)(delta / fs->block_size);
    }
    logical_end = (logical + 1u) * fs->block_size;
    if (logical_end > end) logical_end = end;

    while (logical < last) {
        uint32_t next_physical = 0;
        if (map_find_phys(fs, &disk_inode, (uint32_t)(logical + 1u),
                          &next_physical) < 0 ||
            next_physical != physical + 1u)
            break;
        ++logical;
        physical = next_physical;
        logical_end = (logical + 1u) * fs->block_size;
        if (logical_end > end) logical_end = end;
    }

    for (uint64_t scan = logical + 1u; scan <= last; ++scan) {
        uint32_t scan_physical = 0;
        if (map_find_phys(fs, &disk_inode, (uint32_t)scan,
                          &scan_physical) == 0 && scan_physical != 0) {
            final_extent = 0;
            break;
        }
    }

    memset(extent, 0, sizeof(*extent));
    extent->logical = logical_start;
    extent->physical = (uint64_t)first_physical * fs->block_size +
                       (logical_start % fs->block_size);
    extent->length = logical_end - logical_start;
    if (final_extent) extent->flags |= VFS_EXTENT_FLAG_LAST;
    return 0;
}

static int dir_insert(ext4_fs_t *fs, ext4_inode_t *dino, uint32_t dir_ino, uint32_t child_ino, const char *name, uint8_t file_type) {
    uint16_t nlen = (uint16_t)strlen(name);
    uint16_t need = rec_len_min((uint8_t)nlen);
    uint32_t dsz = inode_size_get(dino);
    uint32_t blk_n = (dsz + fs->block_size - 1) / fs->block_size;
    for (uint32_t scan = 0; scan < blk_n; ++scan) {
        uint32_t bi = blk_n - 1u - scan;
        uint32_t pblk;
        uint32_t off = 0;
        if (map_find_phys(fs, dino, bi, &pblk) < 0) continue;
        if (read_block(fs, pblk, fs->io) < 0) continue;
        while (off + 8 <= fs->block_size) {
            ext4_dirent_t *de = (ext4_dirent_t *)(fs->io + off);
            if (de->rec_len < 8 || off + de->rec_len > fs->block_size) break;
            if (de->inode == 0 && de->rec_len >= need) {
                uint16_t slot = de->rec_len;
                int cached;
                memset(de, 0, slot);
                de->inode = child_ino;
                de->rec_len = slot;
                de->name_len = (uint8_t)nlen;
                de->file_type = file_type;
                memcpy(de->name, name, nlen);
                if (write_block(fs, pblk, fs->io) < 0 ||
                    write_inode(fs, dir_ino, dino) < 0)
                    return -1;
                cached = lookup_cache_store(fs, dir_ino, name, child_ino, 0,
                                            pblk, off);
                directory_index_note_insert(fs, dir_ino, dsz, dsz, cached);
                return 0;
            }
            if (de->inode != 0 && de->name_len > 0) {
                uint16_t used = rec_len_min(de->name_len);
                if (de->rec_len >= used + need) {
                    uint16_t slot = (uint16_t)(de->rec_len - used);
                    ext4_dirent_t *new_de = (ext4_dirent_t *)(fs->io + off + used);
                    int cached;
                    de->rec_len = used;
                    memset(new_de, 0, slot);
                    new_de->inode = child_ino;
                    new_de->rec_len = slot;
                    new_de->name_len = (uint8_t)nlen;
                    new_de->file_type = file_type;
                    memcpy(new_de->name, name, nlen);
                    if (write_block(fs, pblk, fs->io) < 0 ||
                        write_inode(fs, dir_ino, dino) < 0)
                        return -1;
                    cached = lookup_cache_store(
                        fs, dir_ino, name, child_ino, 0, pblk, off + used);
                    directory_index_note_insert(fs, dir_ino, dsz, dsz,
                                                cached);
                    return 0;
                }
            }
            off += de->rec_len;
        }
    }
    {
        uint32_t pblk;
        uint32_t lbi = blk_n;
        if (map_create_phys(fs, dino, lbi, &pblk, 0) < 0) return -1;
        memset(fs->io, 0, fs->block_size);
        {
            ext4_dirent_t *de = (ext4_dirent_t *)fs->io;
            de->inode = child_ino;
            de->rec_len = (uint16_t)fs->block_size;
            de->name_len = (uint8_t)nlen;
            de->file_type = file_type;
            memcpy(de->name, name, nlen);
        }
        if (write_block(fs, pblk, fs->io) < 0) return -1;
        dino->size_lo = dsz + fs->block_size;
        dino->size_high = 0;
        if (write_inode(fs, dir_ino, dino) < 0) return -1;
        {
            int cached = lookup_cache_store(
                fs, dir_ino, name, child_ino, 0, pblk, 0);
            directory_index_note_insert(fs, dir_ino, dsz, dino->size_lo,
                                        cached);
        }
        return 0;
    }
}

static int ext4_reclaim_inode(ext4_fs_t *fs, uint32_t ino,
                              ext4_inode_t *inode);
static int ext4_dir_remove_entry(ext4_fs_t *fs, vfs_inode_t *dir,
                                 const char *name, uint32_t *ino_out);
static uint8_t ext4_dirent_type(uint16_t mode);

static int ext4_create_like(vfs_superblock_t *sb, vfs_inode_t *dir,
                            const char *name, uint16_t mode, uint64_t rdev,
                            vfs_inode_t *out, int is_dir) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t dino, ni;
    vfs_inode_t exists;
    uint16_t ext_kind;
    int nino;
    if (!fs || !dir || !name || !out || !name[0] || strlen(name) >= VFS_NAME_MAX) return -1;
    if (read_inode(fs, dir->ino, &dino) < 0) return -1;
    if (ext4_lookup(sb, dir, name, &exists) == 0) return -1;

    nino = alloc_from_bitmap(fs, fs->bg.inode_bitmap_lo, fs->sb.inodes_per_group, 1);
    if (nino < 0) return -1;
    {
        uint32_t generation = ext4_next_inode_generation(fs, (uint32_t)nino);
        memset(&ni, 0, sizeof(ni));
        ni.generation = generation;
    }
    {
        ext_kind = is_dir ? VFS_INODE_DIR : (uint16_t)(mode & 0xF000u);
        if (ext_kind == 0) ext_kind = VFS_INODE_FILE;
        if (ext_kind != VFS_INODE_FILE && ext_kind != VFS_INODE_DIR &&
            ext_kind != VFS_INODE_FIFO && ext_kind != VFS_INODE_SOCK &&
            ext_kind != VFS_INODE_CHR && ext_kind != VFS_INODE_BLK) {
            (void)free_bitmap_item(fs, (uint32_t)nino, 1, 0);
            return -1;
        }
        /*
         * Linux preserves special permission bits supplied at create time.
         * Package managers may install helpers directly with setuid/setgid
         * modes instead of relying on a later chmod(2).  Dropping those bits
         * here makes execve(2) observe a different inode mode than Linux and
         * breaks unmodified userspace such as dbus-daemon-launch-helper.
         */
        ni.mode = (uint16_t)(ext_kind | (mode & 07777u));
    }
    {
        uint32_t uid;
        uint32_t gid;
        ext4_current_fs_identity(&uid, &gid);
        ext4_inode_set_uid(&ni, uid);
        ext4_inode_set_gid(&ni, gid);
    }
    ni.atime = ni.ctime = ni.mtime = ext4_now_sec();
    ni.links_count = is_dir ? 2 : 1;
    if (ext_kind == VFS_INODE_FILE || ext_kind == VFS_INODE_DIR) {
        ni.flags = EXT4_EXTENTS_FL;
        if (extent_init_inode(&ni) < 0) {
            (void)free_bitmap_item(fs, (uint32_t)nino, 1, 0);
            return -1;
        }
    } else if ((ext_kind == VFS_INODE_CHR || ext_kind == VFS_INODE_BLK) &&
               ext4_encode_rdev(&ni, rdev) < 0) {
        (void)free_bitmap_item(fs, (uint32_t)nino, 1, 0);
        return -1;
    }
    if (is_dir) {
        if (ext4_adjust_used_dirs(fs, (uint32_t)nino, 1) < 0) {
            (void)free_bitmap_item(fs, (uint32_t)nino, 1, 0);
            return -1;
        }
    }

    if (is_dir) {
        int nb = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo, fs->sb.blocks_per_group, 0);
        if (nb < 0) goto fail;
        if (extent_map_insert_local(&ni, 0, (uint32_t)nb) < 0) {
            (void)ext4_free_block(fs, (uint32_t)nb, 0);
            goto fail;
        }
        memset(fs->io, 0, fs->block_size);
        {
            uint16_t dot = rec_len_min(1);
            ext4_dirent_t *de1 = (ext4_dirent_t *)fs->io;
            ext4_dirent_t *de2 = (ext4_dirent_t *)(fs->io + dot);
            de1->inode = (uint32_t)nino;
            de1->rec_len = dot;
            de1->name_len = 1;
            de1->file_type = 2;
            de1->name[0] = '.';
            de2->inode = dir->ino;
            de2->rec_len = (uint16_t)(fs->block_size - dot);
            de2->name_len = 2;
            de2->file_type = 2;
            de2->name[0] = '.';
            de2->name[1] = '.';
        }
        if (write_block(fs, (uint32_t)nb, fs->io) < 0) goto fail;
        ni.size_lo = fs->block_size;
        ni.size_high = 0;
        if (ext4_inode_charge_blocks(fs, &ni, 1u) < 0) goto fail;
        dino.links_count++;
    }

    if (write_new_inode(fs, (uint32_t)nino, &ni) < 0) goto fail;
    if (dir_insert(fs, &dino, dir->ino, (uint32_t)nino, name,
                   ext4_dirent_type(ni.mode)) < 0) {
        uint32_t removed = 0;
        if (ext4_dir_remove_entry(fs, dir, name, &removed) == 0 &&
            removed == (uint32_t)nino && is_dir &&
            read_inode(fs, dir->ino, &dino) == 0 && dino.links_count) {
            --dino.links_count;
            (void)write_inode(fs, dir->ino, &dino);
        }
        goto fail;
    }
    readdir_cache_invalidate(fs, dir->ino);

    ext4_fill_vfs_inode((uint32_t)nino, &ni, out);
    return 0;

fail:
    (void)ext4_reclaim_inode(fs, (uint32_t)nino, &ni);
    return -1;
}

static int ext4_create(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    return ext4_create_like(sb, dir, name, mode, 0, out, 0);
}

static int ext4_mkdir(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    return ext4_create_like(sb, dir, name, mode, 0, out, 1);
}

static int ext4_mknod(vfs_superblock_t *sb, vfs_inode_t *dir,
                      const char *name, uint16_t mode, uint64_t rdev,
                      vfs_inode_t *out) {
    uint16_t kind = (uint16_t)(mode & 0xF000u);
    if (kind != VFS_INODE_FIFO && kind != VFS_INODE_SOCK &&
        kind != VFS_INODE_CHR && kind != VFS_INODE_BLK)
        return -1;
    return ext4_create_like(sb, dir, name, mode, rdev, out, 0);
}

static int ext4_symlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name,
                        const char *target, uint16_t mode, vfs_inode_t *out) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t dino;
    ext4_inode_t ni;
    vfs_inode_t exists;
    uint32_t target_len;
    int nino;
    if (!fs || !dir || !name || !target || !out || !name[0] || !target[0] ||
        strlen(name) >= VFS_NAME_MAX) return -1;
    target_len = (uint32_t)strlen(target);
    if (target_len >= VFS_PATH_MAX) return -1;
    if (read_inode(fs, dir->ino, &dino) < 0) return -1;
    if (ext4_lookup(sb, dir, name, &exists) == 0) return -1;
    nino = alloc_from_bitmap(fs, fs->bg.inode_bitmap_lo, fs->sb.inodes_per_group, 1);
    if (nino < 0) return -1;
    {
        uint32_t generation = ext4_next_inode_generation(fs, (uint32_t)nino);
        memset(&ni, 0, sizeof(ni));
        ni.generation = generation;
    }
    ni.mode = (uint16_t)(0xA000u | (mode & 0777u));
    {
        uint32_t uid;
        uint32_t gid;
        ext4_current_fs_identity(&uid, &gid);
        ext4_inode_set_uid(&ni, uid);
        ext4_inode_set_gid(&ni, gid);
    }
    ni.atime = ni.ctime = ni.mtime = ext4_now_sec();
    ni.links_count = 1;
    ni.size_lo = target_len;
    ni.size_high = 0;
    if (target_len < sizeof(ni.block)) {
        memcpy(ni.block, target, target_len);
    } else {
        vfs_inode_t tmp;
        ni.flags = EXT4_EXTENTS_FL;
        if (extent_init_inode(&ni) < 0) goto fail;
        if (write_new_inode(fs, (uint32_t)nino, &ni) < 0) goto fail;
        memset(&tmp, 0, sizeof(tmp));
        tmp.ino = (uint32_t)nino;
        tmp.mode = (uint16_t)(VFS_INODE_LNK | (mode & 0777u));
        tmp.size = 0;
        if (ext4_write(sb, &tmp, 0, target, target_len) != (int)target_len)
            goto fail;
        if (read_inode(fs, (uint32_t)nino, &ni) < 0) goto fail;
    }
    if (target_len < sizeof(ni.block) &&
        write_new_inode(fs, (uint32_t)nino, &ni) < 0)
        goto fail;
    if (dir_insert(fs, &dino, dir->ino, (uint32_t)nino, name, 7) < 0) {
        uint32_t removed = 0;
        (void)ext4_dir_remove_entry(fs, dir, name, &removed);
        goto fail;
    }
    readdir_cache_invalidate(fs, dir->ino);
    ext4_fill_vfs_inode((uint32_t)nino, &ni, out);
    return 0;

fail:
    (void)ext4_reclaim_inode(fs, (uint32_t)nino, &ni);
    return -1;
}

static int ext4_readlink(vfs_superblock_t *sb, vfs_inode_t *inode, char *out, uint32_t max) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t in;
    uint32_t n;
    if (!fs || !inode || !out || max == 0) return -1;
    if (read_inode(fs, inode->ino, &in) < 0) return -1;
    if ((in.mode & 0xF000u) != 0xA000u) return -1;
    n = inode_size_get(&in);
    if (n > max) n = max;
    if (inode_size_get(&in) < sizeof(in.block) && !(in.flags & EXT4_EXTENTS_FL)) {
        memcpy(out, in.block, n);
        return (int)n;
    }
    return ext4_read(sb, inode, 0, out, n);
}

static int ext4_dir_remove_entry(ext4_fs_t *fs, vfs_inode_t *dir, const char *name, uint32_t *ino_out) {
    ext4_inode_t dino;
    uint32_t dsz, blk_n, bi;
    if (!fs || !dir || !name) return -1;
    if (read_inode(fs, dir->ino, &dino) < 0) return -1;
    {
        uint32_t cached_ino = 0;
        uint32_t cached_block = 0;
        uint32_t cached_offset = 0;
        int cached_miss = 0;

        if (lookup_cache_find(fs, dir->ino, name, &cached_ino,
                              &cached_miss, &cached_block,
                              &cached_offset) &&
            !cached_miss && cached_ino && cached_block &&
            cached_offset + 8u <= fs->block_size &&
            read_block(fs, cached_block, fs->io) == 0) {
            uint32_t offset = 0;
            ext4_dirent_t *previous = 0;

            while (offset + 8u <= fs->block_size &&
                   offset <= cached_offset) {
                ext4_dirent_t *entry = (ext4_dirent_t *)(fs->io + offset);
                if (entry->rec_len < 8u ||
                    offset + entry->rec_len > fs->block_size)
                    break;
                if (offset == cached_offset && entry->inode == cached_ino &&
                    entry->name_len == strlen(name) &&
                    memcmp(entry->name, name, entry->name_len) == 0) {
                    if (previous) {
                        previous->rec_len = (uint16_t)(
                            previous->rec_len + entry->rec_len);
                    } else {
                        entry->inode = 0;
                    }
                    if (write_block(fs, cached_block, fs->io) < 0) return -1;
                    lookup_cache_invalidate(fs, dir->ino, name);
                    readdir_cache_invalidate(fs, dir->ino);
                    if (ino_out) *ino_out = cached_ino;
                    return 0;
                }
                if (offset >= cached_offset) break;
                previous = entry;
                offset += entry->rec_len;
            }
        }
    }
    dsz = inode_size_get(&dino);
    blk_n = (dsz + fs->block_size - 1) / fs->block_size;
    for (bi = 0; bi < blk_n; ++bi) {
        uint32_t pblk;
        uint32_t off = 0;
        if (map_find_phys(fs, &dino, bi, &pblk) < 0) continue;
        if (read_block(fs, pblk, fs->io) < 0) continue;
        ext4_dirent_t *prev = 0;
        while (off + 8 <= fs->block_size) {
            ext4_dirent_t *de = (ext4_dirent_t *)(fs->io + off);
            if (de->rec_len < 8 || off + de->rec_len > fs->block_size) break;
            if (de->inode && de->name_len > 0 && de->name_len < VFS_NAME_MAX) {
                char dn[VFS_NAME_MAX];
                memcpy(dn, de->name, de->name_len);
                dn[de->name_len] = 0;
                if (strcmp(dn, (char *)name) == 0) {
                    uint32_t removed_ino = de->inode;
                    /*
                     * Merge only with the physically adjacent record.  The
                     * previous record may itself be free; skipping free
                     * records and extending an earlier live entry would make
                     * its rec_len cover unrelated entries in between.
                     */
                    if (prev) {
                        prev->rec_len = (uint16_t)(prev->rec_len + de->rec_len);
                    } else {
                        de->inode = 0;
                    }
                    if (write_block(fs, pblk, fs->io) < 0) return -1;
                    lookup_cache_invalidate(fs, dir->ino, name);
                    readdir_cache_invalidate(fs, dir->ino);
                    if (ino_out) *ino_out = removed_ino;
                    return 0;
                }
            }
            prev = de;
            off += de->rec_len;
        }
    }
    return -1;
}

static int ext4_open_inode_grow(ext4_fs_t *fs) {
    ext4_open_inode_page_t *page;
    uint32_t capacity;

    if (!fs) return -1;
    capacity = (EXT4_CACHE_PAGE_SIZE - sizeof(*page)) /
        sizeof(page->entries[0]);
    if (!capacity || fs->open_inode_capacity > UINT32_MAX - capacity)
        return -1;
    page = (ext4_open_inode_page_t *)arch_vm_alloc_pages(1u);
    if (!page) return -1;
    memset(page, 0, EXT4_CACHE_PAGE_SIZE);
    page->capacity = (uint16_t)capacity;
    page->next = fs->open_inode_pages;
    fs->open_inode_pages = page;
    fs->open_inode_capacity += capacity;
    return 0;
}

static ext4_open_inode_entry_t *ext4_open_inode_entry(
    ext4_fs_t *fs, uint32_t ino, int create) {
    ext4_open_inode_entry_t *free_entry = 0;
    ext4_open_inode_page_t *page;

    if (!fs || !ino) return 0;
retry:
    for (page = fs->open_inode_pages; page; page = page->next) {
        for (uint32_t i = 0; i < page->capacity; ++i) {
            ext4_open_inode_entry_t *entry = &page->entries[i];

            if (entry->ino == ino) return entry;
            if (create && !free_entry && !entry->ino) free_entry = entry;
        }
    }
    if (free_entry) {
        free_entry->ino = ino;
        return free_entry;
    }
    if (create && ext4_open_inode_grow(fs) == 0) {
        free_entry = 0;
        goto retry;
    }
    return 0;
}

static int ext4_release_xattr_block(ext4_fs_t *fs, ext4_inode_t *inode,
                                    uint32_t *freed_blocks) {
    ext4_xattr_header_t *header;
    uint32_t block;
    if (!fs || !inode || !inode->file_acl_lo) return 0;
    block = inode->file_acl_lo;
    if (read_block(fs, block, fs->io) < 0) return -1;
    header = (ext4_xattr_header_t *)fs->io;
    if (header->magic != 0xEA020000u || header->blocks != 1u ||
        !header->refcount)
        return -1;
    if (header->refcount > 1u) {
        --header->refcount;
        if (write_block(fs, block, fs->io) < 0) return -1;
    } else if (ext4_free_block(fs, block, freed_blocks) < 0) {
        return -1;
    }
    inode->file_acl_lo = 0;
    return 0;
}

typedef struct {
    const uint8_t *data;
    uint32_t size;
    uint32_t entry_offset;
    uint32_t value_base;
    uint8_t external;
} ext4_xattr_view_t;

typedef struct {
    uint8_t index;
    uint8_t length;
    const char *name;
} ext4_xattr_key_t;

typedef struct {
    uint8_t *data;
    uint32_t size;
    uint32_t entry_offset;
    uint32_t value_base;
    uint32_t entry_position;
    uint32_t value_position;
    uint32_t count;
    uint8_t external;
} ext4_xattr_builder_t;

static uint32_t ext4_xattr_align4(uint32_t value) {
    return (value + 3u) & ~3u;
}

static int ext4_read_inode_raw(ext4_fs_t *fs, uint32_t ino, uint8_t *out) {
    ext4_bgdesc_t bg;
    uint64_t table_offset;
    uint32_t group;
    uint32_t index;
    uint32_t remaining;
    uint32_t copied = 0;
    if (!fs || !out || !ino || ino > fs->sb.inodes_count ||
        fs->sb.inode_size < sizeof(ext4_inode_t) ||
        fs->sb.inode_size > sizeof(fs->xattr_inode))
        return VFS_XATTR_ERR_IO;
    index = ino - 1u;
    group = index / fs->sb.inodes_per_group;
    index %= fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return VFS_XATTR_ERR_IO;
    table_offset = (uint64_t)index * fs->sb.inode_size;
    remaining = fs->sb.inode_size;
    while (remaining) {
        uint32_t block = bg.inode_table_lo + (uint32_t)(table_offset / fs->block_size);
        uint32_t offset = (uint32_t)(table_offset % fs->block_size);
        uint32_t amount = fs->block_size - offset;
        if (amount > remaining) amount = remaining;
        if (read_block(fs, block, fs->io) < 0) return VFS_XATTR_ERR_IO;
        memcpy(out + copied, fs->io + offset, amount);
        copied += amount;
        remaining -= amount;
        table_offset += amount;
    }
    return 0;
}

static int ext4_write_inode_raw(ext4_fs_t *fs, uint32_t ino,
                                const uint8_t *raw) {
    ext4_bgdesc_t bg;
    uint64_t table_offset;
    uint32_t group;
    uint32_t index;
    uint32_t remaining;
    uint32_t copied = 0;
    if (!fs || !raw || !ino || ino > fs->sb.inodes_count ||
        fs->sb.inode_size < sizeof(ext4_inode_t) ||
        fs->sb.inode_size > sizeof(fs->xattr_inode))
        return VFS_XATTR_ERR_IO;
    index = ino - 1u;
    group = index / fs->sb.inodes_per_group;
    index %= fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &bg) < 0) return VFS_XATTR_ERR_IO;
    table_offset = (uint64_t)index * fs->sb.inode_size;
    remaining = fs->sb.inode_size;
    while (remaining) {
        uint32_t block = bg.inode_table_lo + (uint32_t)(table_offset / fs->block_size);
        uint32_t offset = (uint32_t)(table_offset % fs->block_size);
        uint32_t amount = fs->block_size - offset;
        if (amount > remaining) amount = remaining;
        if (read_block(fs, block, fs->io) < 0) return VFS_XATTR_ERR_IO;
        memcpy(fs->io + offset, raw + copied, amount);
        if (write_block(fs, block, fs->io) < 0) return VFS_XATTR_ERR_IO;
        copied += amount;
        remaining -= amount;
        table_offset += amount;
    }
    inode_cache_invalidate(fs, ino);
    return 0;
}

static int ext4_xattr_split_name(const char *name, ext4_xattr_key_t *key) {
    uint32_t length;
    const char *suffix = 0;
    uint32_t suffix_length = 0;
    uint8_t index = 0;
    if (!name || !key) return VFS_XATTR_ERR_INVALID;
    length = (uint32_t)strlen(name);
    if (!length || length > VFS_XATTR_NAME_MAX)
        return VFS_XATTR_ERR_INVALID;
    if (strcmp(name, "system.posix_acl_access") == 0) {
        index = EXT4_XATTR_INDEX_POSIX_ACL_ACCESS;
        suffix = name + length;
    } else if (strcmp(name, "system.posix_acl_default") == 0) {
        index = EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT;
        suffix = name + length;
    } else if (strcmp(name, "system.richacl") == 0) {
        index = EXT4_XATTR_INDEX_RICHACL;
        suffix = name + length;
    } else if (strncmp(name, "user.", 5) == 0) {
        index = EXT4_XATTR_INDEX_USER;
        suffix = name + 5;
    } else if (strncmp(name, "trusted.", 8) == 0) {
        index = EXT4_XATTR_INDEX_TRUSTED;
        suffix = name + 8;
    } else if (strncmp(name, "security.", 9) == 0) {
        index = EXT4_XATTR_INDEX_SECURITY;
        suffix = name + 9;
    } else if (strncmp(name, "system.", 7) == 0) {
        index = EXT4_XATTR_INDEX_SYSTEM;
        suffix = name + 7;
    } else {
        return VFS_XATTR_ERR_UNSUPPORTED;
    }
    suffix_length = (uint32_t)strlen(suffix);
    if ((index != EXT4_XATTR_INDEX_POSIX_ACL_ACCESS &&
         index != EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT &&
         index != EXT4_XATTR_INDEX_RICHACL && !suffix_length) ||
        suffix_length > UINT8_MAX)
        return VFS_XATTR_ERR_INVALID;
    key->index = index;
    key->length = (uint8_t)suffix_length;
    key->name = suffix;
    return 0;
}

static int ext4_xattr_validate_area(const ext4_xattr_view_t *view) {
    uint32_t position;
    uint32_t lowest_value;
    uint32_t count = 0;
    if (!view || !view->data || view->entry_offset + sizeof(uint32_t) > view->size ||
        view->value_base > view->size)
        return VFS_XATTR_ERR_IO;
    position = view->entry_offset;
    lowest_value = view->size;
    for (;;) {
        const ext4_xattr_entry_t *entry;
        uint32_t marker;
        uint32_t entry_length;
        uint32_t value_length;
        uint32_t value_offset;
        uint32_t value_position;
        if (position + sizeof(marker) > view->size || ++count > 256u)
            return VFS_XATTR_ERR_IO;
        memcpy(&marker, view->data + position, sizeof(marker));
        if (!marker)
            return position + sizeof(marker) <= lowest_value ? 0 :
                   VFS_XATTR_ERR_IO;
        if (position + sizeof(*entry) > view->size)
            return VFS_XATTR_ERR_IO;
        entry = (const ext4_xattr_entry_t *)(view->data + position);
        entry_length = ext4_xattr_align4((uint32_t)sizeof(*entry) +
                                         entry->name_len);
        if ((!entry->name_len &&
             entry->name_index != EXT4_XATTR_INDEX_POSIX_ACL_ACCESS &&
             entry->name_index != EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT &&
             entry->name_index != EXT4_XATTR_INDEX_RICHACL) ||
            position + entry_length > view->size || entry->value_block)
            return VFS_XATTR_ERR_IO;
        value_length = entry->value_size;
        value_offset = entry->value_offs;
        if (value_length) {
            if ((value_offset & 3u) || value_offset > view->size - view->value_base)
                return VFS_XATTR_ERR_IO;
            value_position = view->value_base + value_offset;
            if (value_position > view->size ||
                ext4_xattr_align4(value_length) > view->size - value_position)
                return VFS_XATTR_ERR_IO;
            if (value_position < lowest_value) lowest_value = value_position;
        } else if (value_offset) {
            return VFS_XATTR_ERR_IO;
        }
        position += entry_length;
    }
}

static int ext4_xattr_key_compare(const ext4_xattr_key_t *key,
                                  const ext4_xattr_entry_t *entry) {
    int compared;
    if (key->index != entry->name_index)
        return key->index < entry->name_index ? -1 : 1;
    if (key->length != entry->name_len)
        return key->length < entry->name_len ? -1 : 1;
    compared = memcmp(key->name, entry->name, key->length);
    return compared < 0 ? -1 : compared > 0 ? 1 : 0;
}

static const ext4_xattr_entry_t *ext4_xattr_lookup(
    const ext4_xattr_view_t *view, const ext4_xattr_key_t *key) {
    uint32_t position;
    if (!view || !view->data || !key) return 0;
    position = view->entry_offset;
    for (;;) {
        const ext4_xattr_entry_t *entry;
        uint32_t marker;
        memcpy(&marker, view->data + position, sizeof(marker));
        if (!marker) return 0;
        entry = (const ext4_xattr_entry_t *)(view->data + position);
        if (ext4_xattr_key_compare(key, entry) == 0) return entry;
        position += ext4_xattr_align4((uint32_t)sizeof(*entry) +
                                      entry->name_len);
    }
}

static uint32_t ext4_xattr_entry_hash(const ext4_xattr_builder_t *builder,
                                      const ext4_xattr_entry_t *entry) {
    uint32_t hash = 0;
    const uint8_t *name = (const uint8_t *)entry->name;
    const uint8_t *value;
    uint32_t words;
    for (uint32_t i = 0; i < entry->name_len; ++i)
        hash = (hash << 5) ^ (hash >> 27) ^ name[i];
    if (!entry->value_size) return hash;
    value = builder->data + builder->value_base + entry->value_offs;
    words = ext4_xattr_align4(entry->value_size) / sizeof(uint32_t);
    for (uint32_t i = 0; i < words; ++i) {
        uint32_t word;
        memcpy(&word, value + i * sizeof(word), sizeof(word));
        hash = (hash << 16) ^ (hash >> 16) ^ word;
    }
    return hash;
}

static int ext4_xattr_builder_add(ext4_xattr_builder_t *builder,
                                  uint8_t index, const char *name,
                                  uint8_t name_length, const void *value,
                                  uint32_t value_length) {
    ext4_xattr_entry_t *entry;
    uint32_t entry_length;
    uint32_t value_space;
    uint32_t value_position;
    if (!builder || !name || (value_length && !value))
        return VFS_XATTR_ERR_INVALID;
    entry_length = ext4_xattr_align4((uint32_t)sizeof(*entry) + name_length);
    value_space = ext4_xattr_align4(value_length);
    if (value_space > builder->value_position)
        return VFS_XATTR_ERR_NOSPC;
    value_position = builder->value_position - value_space;
    value_position &= ~3u;
    if (builder->entry_position + entry_length + sizeof(uint32_t) >
        value_position)
        return VFS_XATTR_ERR_NOSPC;
    entry = (ext4_xattr_entry_t *)(builder->data + builder->entry_position);
    entry->name_len = name_length;
    entry->name_index = index;
    entry->value_offs = value_length ?
        (uint16_t)(value_position - builder->value_base) : 0;
    entry->value_block = 0;
    entry->value_size = value_length;
    entry->hash = 0;
    if (name_length) memcpy(entry->name, name, name_length);
    if (value_length) memcpy(builder->data + value_position, value, value_length);
    if (builder->external) entry->hash = ext4_xattr_entry_hash(builder, entry);
    builder->entry_position += entry_length;
    builder->value_position = value_position;
    builder->count++;
    return 0;
}

static int ext4_xattr_build(uint8_t *destination, uint32_t size,
                            int external, const ext4_xattr_view_t *old,
                            const ext4_xattr_key_t *key, const void *value,
                            uint32_t value_length, int include_key,
                            uint32_t *count_out) {
    ext4_xattr_builder_t builder;
    uint32_t old_position = 0;
    int inserted = 0;
    if (!destination || !key || size < 8u) return VFS_XATTR_ERR_NOSPC;
    memset(destination, 0, size);
    memset(&builder, 0, sizeof(builder));
    builder.data = destination;
    builder.size = size;
    builder.external = external ? 1u : 0u;
    builder.entry_offset = external ? sizeof(ext4_xattr_header_t) :
                                      sizeof(uint32_t);
    builder.value_base = external ? 0u : sizeof(uint32_t);
    builder.entry_position = builder.entry_offset;
    builder.value_position = size;
    if (external) {
        ext4_xattr_header_t *header = (ext4_xattr_header_t *)destination;
        header->magic = EXT4_XATTR_MAGIC;
        header->refcount = 1u;
        header->blocks = 1u;
    } else {
        uint32_t magic = EXT4_XATTR_MAGIC;
        memcpy(destination, &magic, sizeof(magic));
    }
    if (old && old->data) old_position = old->entry_offset;
    while (old && old->data) {
        const ext4_xattr_entry_t *entry;
        const void *old_value = 0;
        uint32_t marker;
        int comparison;
        int rc;
        memcpy(&marker, old->data + old_position, sizeof(marker));
        if (!marker) break;
        entry = (const ext4_xattr_entry_t *)(old->data + old_position);
        comparison = ext4_xattr_key_compare(key, entry);
        if (include_key && !inserted && comparison <= 0) {
            rc = ext4_xattr_builder_add(&builder, key->index, key->name,
                                        key->length, value, value_length);
            if (rc < 0) return rc;
            inserted = 1;
        }
        if (comparison != 0) {
            if (entry->value_size)
                old_value = old->data + old->value_base + entry->value_offs;
            rc = ext4_xattr_builder_add(&builder, entry->name_index,
                                        entry->name, entry->name_len, old_value,
                                        entry->value_size);
            if (rc < 0) return rc;
        }
        old_position += ext4_xattr_align4((uint32_t)sizeof(*entry) +
                                          entry->name_len);
    }
    if (include_key && !inserted) {
        int rc = ext4_xattr_builder_add(&builder, key->index, key->name,
                                        key->length, value, value_length);
        if (rc < 0) return rc;
    }
    if (external) {
        ext4_xattr_header_t *header = (ext4_xattr_header_t *)destination;
        uint32_t position = builder.entry_offset;
        uint32_t hash = 0;
        for (;;) {
            ext4_xattr_entry_t *entry;
            uint32_t marker;
            memcpy(&marker, destination + position, sizeof(marker));
            if (!marker) break;
            entry = (ext4_xattr_entry_t *)(destination + position);
            if (!entry->hash) {
                hash = 0;
                break;
            }
            hash = (hash << 16) ^ (hash >> 16) ^ entry->hash;
            position += ext4_xattr_align4((uint32_t)sizeof(*entry) +
                                          entry->name_len);
        }
        header->hash = hash;
    }
    if (count_out) *count_out = builder.count;
    return 0;
}

static int ext4_xattr_inline_layout(ext4_fs_t *fs, const uint8_t *raw,
                                    uint32_t *offset_out, uint32_t *size_out,
                                    ext4_xattr_view_t *view_out) {
    uint16_t extra_size = 0;
    uint32_t offset;
    uint32_t magic = 0;
    if (view_out) memset(view_out, 0, sizeof(*view_out));
    if (!fs || !raw || fs->sb.inode_size <= sizeof(ext4_inode_t) + 4u)
        return 0;
    memcpy(&extra_size, raw + sizeof(ext4_inode_t), sizeof(extra_size));
    if ((extra_size & 3u) ||
        extra_size > fs->sb.inode_size - sizeof(ext4_inode_t) - 4u)
        return VFS_XATTR_ERR_IO;
    offset = (uint32_t)sizeof(ext4_inode_t) + extra_size;
    if (offset + 8u > fs->sb.inode_size) return 0;
    if (offset_out) *offset_out = offset;
    if (size_out) *size_out = fs->sb.inode_size - offset;
    memcpy(&magic, raw + offset, sizeof(magic));
    if (!magic) return 1;
    if (magic != EXT4_XATTR_MAGIC) return VFS_XATTR_ERR_IO;
    if (view_out) {
        view_out->data = raw + offset;
        view_out->size = fs->sb.inode_size - offset;
        view_out->entry_offset = sizeof(uint32_t);
        view_out->value_base = sizeof(uint32_t);
        view_out->external = 0;
        return ext4_xattr_validate_area(view_out) < 0 ?
               VFS_XATTR_ERR_IO : 1;
    }
    return 1;
}

static int ext4_xattr_load(ext4_fs_t *fs, uint32_t ino,
                           ext4_inode_t **disk_inode_out,
                           ext4_xattr_view_t *inline_view,
                           uint32_t *inline_offset,
                           uint32_t *inline_size,
                           ext4_xattr_view_t *external_view) {
    ext4_inode_t *disk_inode;
    int inline_result;
    if (inline_view) memset(inline_view, 0, sizeof(*inline_view));
    if (external_view) memset(external_view, 0, sizeof(*external_view));
    if (ext4_read_inode_raw(fs, ino, fs->xattr_inode) < 0)
        return VFS_XATTR_ERR_IO;
    disk_inode = (ext4_inode_t *)fs->xattr_inode;
    if (!disk_inode->mode) return VFS_XATTR_ERR_IO;
    inline_result = ext4_xattr_inline_layout(fs, fs->xattr_inode,
                                             inline_offset, inline_size,
                                             inline_view);
    if (inline_result < 0) return inline_result;
    if (disk_inode->file_acl_lo) {
        ext4_xattr_header_t *header;
        if (disk_inode->file_acl_lo >= fs->sb.blocks_count_lo ||
            read_block(fs, disk_inode->file_acl_lo, fs->xattr_old) < 0)
            return VFS_XATTR_ERR_IO;
        header = (ext4_xattr_header_t *)fs->xattr_old;
        if (header->magic != EXT4_XATTR_MAGIC || header->blocks != 1u ||
            !header->refcount)
            return VFS_XATTR_ERR_IO;
        if (external_view) {
            external_view->data = fs->xattr_old;
            external_view->size = fs->block_size;
            external_view->entry_offset = sizeof(ext4_xattr_header_t);
            external_view->value_base = 0;
            external_view->external = 1;
            if (ext4_xattr_validate_area(external_view) < 0)
                return VFS_XATTR_ERR_IO;
        }
    }
    if (disk_inode_out) *disk_inode_out = disk_inode;
    return inline_result;
}

static int ext4_xattr_commit_inline(ext4_fs_t *fs, vfs_inode_t *inode,
                                    ext4_inode_t *disk_inode,
                                    uint32_t inline_offset,
                                    uint32_t inline_size,
                                    const ext4_xattr_view_t *old,
                                    const ext4_xattr_key_t *key,
                                    const void *value, uint32_t value_size,
                                    int include_key, int write_now) {
    uint32_t count = 0;
    int rc = ext4_xattr_build(fs->xattr_new, inline_size, 0, old, key, value,
                              value_size, include_key, &count);
    if (rc < 0) return rc;
    if (count) memcpy(fs->xattr_inode + inline_offset, fs->xattr_new, inline_size);
    else memset(fs->xattr_inode + inline_offset, 0, inline_size);
    disk_inode->ctime = ext4_now_sec();
    if (inode) inode->ctime = disk_inode->ctime;
    if (!write_now) return 0;
    return ext4_write_inode_raw(fs, inode->ino, fs->xattr_inode);
}

static int ext4_xattr_commit_external(ext4_fs_t *fs, vfs_inode_t *inode,
                                      ext4_inode_t *disk_inode,
                                      const ext4_xattr_view_t *old,
                                      const ext4_xattr_key_t *key,
                                      const void *value, uint32_t value_size,
                                      int include_key) {
    ext4_xattr_header_t *old_header = old && old->data ?
        (ext4_xattr_header_t *)fs->xattr_old : 0;
    uint32_t old_block = disk_inode->file_acl_lo;
    uint32_t count = 0;
    uint32_t sectors_per_block = fs->block_size / 512u;
    int new_block;
    int rc;
    rc = ext4_xattr_build(fs->xattr_new, fs->block_size, 1, old, key, value,
                          value_size, include_key, &count);
    if (rc < 0) return rc;
    disk_inode->ctime = ext4_now_sec();
    if (inode) inode->ctime = disk_inode->ctime;

    if (!count) {
        if (!old_block || !old_header) return VFS_XATTR_ERR_NO_DATA;
        disk_inode->file_acl_lo = 0;
        disk_inode->blocks_lo = sectors_per_block >= disk_inode->blocks_lo ? 0u :
                                disk_inode->blocks_lo - sectors_per_block;
        if (ext4_write_inode_raw(fs, inode->ino, fs->xattr_inode) < 0)
            return VFS_XATTR_ERR_IO;
        if (old_header->refcount > 1u) {
            --old_header->refcount;
            if (write_block(fs, old_block, fs->xattr_old) < 0)
                return VFS_XATTR_ERR_IO;
        } else if (ext4_free_block(fs, old_block, 0) < 0) {
            return VFS_XATTR_ERR_IO;
        }
        return 0;
    }

    if (!old_block) {
        uint32_t old_blocks = disk_inode->blocks_lo;
        new_block = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo,
                                     fs->sb.blocks_per_group, 0);
        if (new_block < 0) return VFS_XATTR_ERR_NOSPC;
        if (ext4_inode_charge_blocks(fs, disk_inode, 1u) < 0 ||
            write_block(fs, (uint32_t)new_block, fs->xattr_new) < 0) {
            disk_inode->blocks_lo = old_blocks;
            (void)ext4_free_block(fs, (uint32_t)new_block, 0);
            return VFS_XATTR_ERR_IO;
        }
        disk_inode->file_acl_lo = (uint32_t)new_block;
        if (ext4_write_inode_raw(fs, inode->ino, fs->xattr_inode) < 0) {
            disk_inode->file_acl_lo = 0;
            disk_inode->blocks_lo = old_blocks;
            (void)ext4_free_block(fs, (uint32_t)new_block, 0);
            return VFS_XATTR_ERR_IO;
        }
        return 0;
    }

    if (old_header->refcount == 1u) {
        if (write_block(fs, old_block, fs->xattr_new) < 0)
            return VFS_XATTR_ERR_IO;
        if (ext4_write_inode_raw(fs, inode->ino, fs->xattr_inode) < 0) {
            (void)write_block(fs, old_block, fs->xattr_old);
            return VFS_XATTR_ERR_IO;
        }
        return 0;
    }

    new_block = alloc_from_bitmap(fs, fs->bg.block_bitmap_lo,
                                 fs->sb.blocks_per_group, 0);
    if (new_block < 0) return VFS_XATTR_ERR_NOSPC;
    if (write_block(fs, (uint32_t)new_block, fs->xattr_new) < 0) {
        (void)ext4_free_block(fs, (uint32_t)new_block, 0);
        return VFS_XATTR_ERR_IO;
    }
    disk_inode->file_acl_lo = (uint32_t)new_block;
    if (ext4_write_inode_raw(fs, inode->ino, fs->xattr_inode) < 0) {
        disk_inode->file_acl_lo = old_block;
        (void)ext4_free_block(fs, (uint32_t)new_block, 0);
        return VFS_XATTR_ERR_IO;
    }
    --old_header->refcount;
    if (write_block(fs, old_block, fs->xattr_old) < 0)
        return VFS_XATTR_ERR_IO;
    return 0;
}

static int ext4_xattr_full_name(const ext4_xattr_entry_t *entry,
                                char out[VFS_XATTR_NAME_MAX + 1u]) {
    const char *prefix = 0;
    uint32_t prefix_length = 0;
    uint32_t total;
    if (!entry || !out) return -1;
    switch (entry->name_index) {
        case EXT4_XATTR_INDEX_USER:
            prefix = "user.";
            break;
        case EXT4_XATTR_INDEX_POSIX_ACL_ACCESS:
            if (entry->name_len) return -1;
            prefix = "system.posix_acl_access";
            break;
        case EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT:
            if (entry->name_len) return -1;
            prefix = "system.posix_acl_default";
            break;
        case EXT4_XATTR_INDEX_TRUSTED:
            prefix = "trusted.";
            break;
        case EXT4_XATTR_INDEX_SECURITY:
            prefix = "security.";
            break;
        case EXT4_XATTR_INDEX_SYSTEM:
            prefix = "system.";
            break;
        case EXT4_XATTR_INDEX_RICHACL:
            if (entry->name_len) return -1;
            prefix = "system.richacl";
            break;
        default:
            return 0;
    }
    prefix_length = (uint32_t)strlen(prefix);
    total = prefix_length + entry->name_len;
    if (!total || total > VFS_XATTR_NAME_MAX) return -1;
    memcpy(out, prefix, prefix_length);
    if (entry->name_len) memcpy(out + prefix_length, entry->name,
                                entry->name_len);
    out[total] = 0;
    return (int)total;
}

static int ext4_xattr_list_view(const ext4_xattr_view_t *view,
                                const ext4_xattr_view_t *skip,
                                char *list, uint32_t *offset) {
    uint32_t position;
    if (!view || !view->data || !offset) return 0;
    position = view->entry_offset;
    for (;;) {
        const ext4_xattr_entry_t *entry;
        ext4_xattr_key_t key;
        char full_name[VFS_XATTR_NAME_MAX + 1u];
        uint32_t marker;
        int length;
        memcpy(&marker, view->data + position, sizeof(marker));
        if (!marker) return 0;
        entry = (const ext4_xattr_entry_t *)(view->data + position);
        length = ext4_xattr_full_name(entry, full_name);
        if (length < 0) return VFS_XATTR_ERR_IO;
        if (length > 0) {
            key.index = entry->name_index;
            key.length = entry->name_len;
            key.name = entry->name;
            if (!skip || !ext4_xattr_lookup(skip, &key)) {
                if (list) memcpy(list + *offset, full_name, (uint32_t)length + 1u);
                *offset += (uint32_t)length + 1u;
            }
        }
        position += ext4_xattr_align4((uint32_t)sizeof(*entry) +
                                      entry->name_len);
    }
}

static int ext4_setxattr_locked(vfs_superblock_t *sb, vfs_inode_t *inode,
                                const char *name, const void *value,
                                uint32_t size, uint32_t flags) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t *disk_inode = 0;
    ext4_xattr_view_t inline_view;
    ext4_xattr_view_t external_view;
    ext4_xattr_key_t key;
    const ext4_xattr_entry_t *inline_entry;
    const ext4_xattr_entry_t *external_entry;
    uint32_t inline_offset = 0;
    uint32_t inline_size = 0;
    int inline_layout;
    int rc;
    if (!fs) return VFS_XATTR_ERR_IO;
    rc = ext4_xattr_split_name(name, &key);
    if (rc < 0) goto out;
    inline_layout = ext4_xattr_load(fs, inode->ino, &disk_inode, &inline_view,
                                    &inline_offset, &inline_size,
                                    &external_view);
    if (inline_layout < 0) {
        rc = inline_layout;
        goto out;
    }
    inline_entry = ext4_xattr_lookup(&inline_view, &key);
    external_entry = ext4_xattr_lookup(&external_view, &key);
    if ((flags & VFS_XATTR_CREATE) && (inline_entry || external_entry)) {
        rc = VFS_XATTR_ERR_EXISTS;
        goto out;
    }
    if ((flags & VFS_XATTR_REPLACE) && !inline_entry && !external_entry) {
        rc = VFS_XATTR_ERR_NO_DATA;
        goto out;
    }

    if (inline_entry || (!external_entry && inline_layout > 0)) {
        rc = ext4_xattr_commit_inline(fs, inode, disk_inode, inline_offset,
                                      inline_size, inline_view.data ?
                                      &inline_view : 0, &key, value, size, 1,
                                      external_entry ? 0 : 1);
        if (rc == 0) {
            if (external_entry)
                rc = ext4_xattr_commit_external(fs, inode, disk_inode,
                                                 &external_view, &key, value,
                                                 size, 1);
            goto out;
        }
        if (rc != VFS_XATTR_ERR_NOSPC || !inline_entry) {
            if (rc != VFS_XATTR_ERR_NOSPC) goto out;
        } else {
            rc = ext4_xattr_commit_inline(fs, inode, disk_inode, inline_offset,
                                          inline_size, &inline_view, &key, 0,
                                          0, 0, 0);
            if (rc < 0) goto out;
        }
    }
    rc = ext4_xattr_commit_external(fs, inode, disk_inode,
                                    external_view.data ? &external_view : 0,
                                    &key, value, size, 1);
out:
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_getxattr_locked(vfs_superblock_t *sb,
                                const vfs_inode_t *inode, const char *name,
                                void *value, uint32_t size) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t *disk_inode = 0;
    ext4_xattr_view_t inline_view;
    ext4_xattr_view_t external_view;
    ext4_xattr_key_t key;
    const ext4_xattr_entry_t *entry;
    const ext4_xattr_view_t *view;
    int rc;
    if (!fs) return VFS_XATTR_ERR_IO;
    rc = ext4_xattr_split_name(name, &key);
    if (rc < 0) goto out;
    rc = ext4_xattr_load(fs, inode->ino, &disk_inode, &inline_view, 0, 0,
                         &external_view);
    if (rc < 0) goto out;
    entry = ext4_xattr_lookup(&inline_view, &key);
    view = &inline_view;
    if (!entry) {
        entry = ext4_xattr_lookup(&external_view, &key);
        view = &external_view;
    }
    if (!entry) {
        rc = VFS_XATTR_ERR_NO_DATA;
        goto out;
    }
    if (!value && !size) {
        rc = (int)entry->value_size;
        goto out;
    }
    if (size < entry->value_size) {
        rc = VFS_XATTR_ERR_RANGE;
        goto out;
    }
    if (entry->value_size)
        memcpy(value, view->data + view->value_base + entry->value_offs,
               entry->value_size);
    rc = (int)entry->value_size;
out:
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_listxattr_locked(vfs_superblock_t *sb,
                                 const vfs_inode_t *inode, char *list,
                                 uint32_t size) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t *disk_inode = 0;
    ext4_xattr_view_t inline_view;
    ext4_xattr_view_t external_view;
    uint32_t required = 0;
    uint32_t written = 0;
    int rc;
    if (!fs) return VFS_XATTR_ERR_IO;
    rc = ext4_xattr_load(fs, inode->ino, &disk_inode, &inline_view, 0, 0,
                         &external_view);
    if (rc < 0) goto out;
    rc = ext4_xattr_list_view(&inline_view, 0, 0, &required);
    if (rc < 0) goto out;
    rc = ext4_xattr_list_view(&external_view, &inline_view, 0, &required);
    if (rc < 0) goto out;
    if (!list && !size) {
        rc = (int)required;
        goto out;
    }
    if (size < required) {
        rc = VFS_XATTR_ERR_RANGE;
        goto out;
    }
    rc = ext4_xattr_list_view(&inline_view, 0, list, &written);
    if (rc < 0) goto out;
    rc = ext4_xattr_list_view(&external_view, &inline_view, list, &written);
    if (rc < 0) goto out;
    rc = (int)written;
out:
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_removexattr_locked(vfs_superblock_t *sb, vfs_inode_t *inode,
                                   const char *name) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t *disk_inode = 0;
    ext4_xattr_view_t inline_view;
    ext4_xattr_view_t external_view;
    ext4_xattr_key_t key;
    const ext4_xattr_entry_t *inline_entry;
    const ext4_xattr_entry_t *external_entry;
    uint32_t inline_offset = 0;
    uint32_t inline_size = 0;
    int rc;
    if (!fs) return VFS_XATTR_ERR_IO;
    rc = ext4_xattr_split_name(name, &key);
    if (rc < 0) goto out;
    rc = ext4_xattr_load(fs, inode->ino, &disk_inode, &inline_view,
                         &inline_offset, &inline_size, &external_view);
    if (rc < 0) goto out;
    inline_entry = ext4_xattr_lookup(&inline_view, &key);
    external_entry = ext4_xattr_lookup(&external_view, &key);
    if (!inline_entry && !external_entry) {
        rc = VFS_XATTR_ERR_NO_DATA;
        goto out;
    }
    if (inline_entry) {
        rc = ext4_xattr_commit_inline(fs, inode, disk_inode, inline_offset,
                                      inline_size, &inline_view, &key, 0, 0, 0,
                                      external_entry ? 0 : 1);
        if (rc < 0) goto out;
    }
    if (external_entry)
        rc = ext4_xattr_commit_external(fs, inode, disk_inode,
                                        &external_view, &key, 0, 0, 0);
out:
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_reclaim_inode(ext4_fs_t *fs, uint32_t ino,
                              ext4_inode_t *inode) {
    uint32_t generation;
    uint32_t freed_blocks = 0;
    int was_directory;
    if (!fs || !inode || !ino || ino > fs->sb.inodes_count) return -1;
    generation = inode->generation;
    was_directory = (inode->mode & 0xf000u) == VFS_INODE_DIR;
    if (ext4_truncate_mappings(fs, inode, 0, 1, &freed_blocks) < 0 ||
        ext4_release_xattr_block(fs, inode, &freed_blocks) < 0)
        return -1;
    memset(inode, 0, sizeof(*inode));
    inode->generation = generation;
    inode->dtime = ext4_now_sec();
    if (write_inode(fs, ino, inode) < 0) return -1;
    if (free_bitmap_item(fs, ino, 1, was_directory) < 0) return -1;
    readdir_cache_invalidate(fs, ino);
    return 0;
}

static int ext4_drop_inode_link(ext4_fs_t *fs, uint32_t ino) {
    ext4_inode_t inode;
    ext4_open_inode_entry_t *open_entry;
    if (!fs || !ino || read_inode(fs, ino, &inode) < 0 ||
        !inode.mode || !inode.links_count)
        return -1;
    --inode.links_count;
    inode.ctime = ext4_now_sec();
    if (inode.links_count) return write_inode(fs, ino, &inode);
    inode.dtime = inode.ctime;
    open_entry = ext4_open_inode_entry(fs, ino, 0);
    if (open_entry && open_entry->references) {
        open_entry->delete_pending = 1;
        return write_inode(fs, ino, &inode);
    }
    return ext4_reclaim_inode(fs, ino, &inode);
}

static int ext4_unlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    uint32_t ino = 0;
    if (ext4_dir_remove_entry(fs, dir, name, &ino) < 0 || !ino) return -1;
    return ext4_drop_inode_link(fs, ino);
}

static int ext4_directory_is_empty(ext4_fs_t *fs, uint32_t ino,
                                   ext4_inode_t *inode_out) {
    ext4_inode_t inode;
    uint32_t blocks;
    if (!fs || !ino || read_inode(fs, ino, &inode) < 0 ||
        (inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -1;
    blocks = (inode_size_get(&inode) + fs->block_size - 1u) /
             fs->block_size;
    for (uint32_t logical = 0; logical < blocks; ++logical) {
        uint32_t physical;
        uint32_t offset = 0;
        if (map_find_phys(fs, &inode, logical, &physical) < 0 ||
            read_block(fs, physical, fs->io) < 0)
            return -1;
        while (offset + 8u <= fs->block_size) {
            ext4_dirent_t *entry = (ext4_dirent_t *)(fs->io + offset);
            int dot;
            int dotdot;
            if (entry->rec_len < 8u ||
                offset + entry->rec_len > fs->block_size)
                return -1;
            dot = entry->name_len == 1u && entry->name[0] == '.';
            dotdot = entry->name_len == 2u && entry->name[0] == '.' &&
                     entry->name[1] == '.';
            if (entry->inode && !dot && !dotdot) return 0;
            offset += entry->rec_len;
        }
    }
    if (inode_out) *inode_out = inode;
    return 1;
}

static int ext4_directory_parent_inode(ext4_fs_t *fs, uint32_t ino,
                                       uint32_t *parent_out) {
    ext4_inode_t inode;
    uint32_t blocks;
    if (!fs || !ino || !parent_out || read_inode(fs, ino, &inode) < 0 ||
        (inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -1;
    blocks = (inode_size_get(&inode) + fs->block_size - 1u) /
             fs->block_size;
    for (uint32_t logical = 0; logical < blocks; ++logical) {
        uint32_t physical;
        uint32_t offset = 0;
        if (map_find_phys(fs, &inode, logical, &physical) < 0 ||
            read_block(fs, physical, fs->io) < 0)
            return -1;
        while (offset + 8u <= fs->block_size) {
            ext4_dirent_t *entry = (ext4_dirent_t *)(fs->io + offset);
            if (entry->rec_len < 8u ||
                offset + entry->rec_len > fs->block_size)
                return -1;
            if (entry->inode && entry->name_len == 2u &&
                entry->name[0] == '.' && entry->name[1] == '.') {
                *parent_out = entry->inode;
                return 0;
            }
            offset += entry->rec_len;
        }
    }
    return -1;
}

static int ext4_directory_is_ancestor(ext4_fs_t *fs, uint32_t ancestor,
                                      uint32_t directory) {
    const uint32_t maximum_depth = VFS_PATH_MAX / 2u;
    if (!fs || !ancestor || !directory) return -1;
    /*
     * Every traversed component consumes at least two bytes in an absolute
     * Linux path (slash plus name).  Bound malformed '..' chains by PATH_MAX
     * instead of the filesystem inode count, which may be millions.
     */
    for (uint32_t depth = 0; depth < maximum_depth; ++depth) {
        uint32_t parent;
        if (directory == ancestor) return 1;
        if (directory == 2u) return 0;
        if (ext4_directory_parent_inode(fs, directory, &parent) < 0 ||
            !parent || parent == directory)
            return -1;
        directory = parent;
    }
    return -1;
}

static int ext4_directory_set_parent(ext4_fs_t *fs, uint32_t ino,
                                     uint32_t parent_ino) {
    ext4_inode_t inode;
    uint32_t blocks;
    if (!fs || !ino || !parent_ino || read_inode(fs, ino, &inode) < 0 ||
        (inode.mode & 0xf000u) != VFS_INODE_DIR)
        return -1;
    blocks = (inode_size_get(&inode) + fs->block_size - 1u) /
             fs->block_size;
    for (uint32_t logical = 0; logical < blocks; ++logical) {
        uint32_t physical;
        uint32_t offset = 0;
        if (map_find_phys(fs, &inode, logical, &physical) < 0 ||
            read_block(fs, physical, fs->io) < 0)
            return -1;
        while (offset + 8u <= fs->block_size) {
            ext4_dirent_t *entry = (ext4_dirent_t *)(fs->io + offset);
            if (entry->rec_len < 8u ||
                offset + entry->rec_len > fs->block_size)
                return -1;
            if (entry->inode && entry->name_len == 2u &&
                entry->name[0] == '.' && entry->name[1] == '.') {
                entry->inode = parent_ino;
                if (write_block(fs, physical, fs->io) < 0) return -1;
                inode.ctime = ext4_now_sec();
                return write_inode(fs, ino, &inode);
            }
            offset += entry->rec_len;
        }
    }
    return -1;
}

static int ext4_dir_replace_entry(ext4_fs_t *fs, vfs_inode_t *dir,
                                  const char *name, uint32_t replacement_ino,
                                  uint8_t replacement_type,
                                  uint32_t *replaced_ino) {
    ext4_inode_t directory;
    uint32_t blocks;
    uint32_t name_length;
    if (!fs || !dir || !name || !replacement_ino ||
        read_inode(fs, dir->ino, &directory) < 0)
        return -1;
    name_length = (uint32_t)strlen(name);
    {
        uint32_t cached_ino = 0;
        uint32_t cached_block = 0;
        uint32_t cached_offset = 0;
        int cached_miss = 0;

        if (lookup_cache_find(fs, dir->ino, name, &cached_ino,
                              &cached_miss, &cached_block,
                              &cached_offset) &&
            !cached_miss && cached_ino && cached_block &&
            cached_offset + 8u <= fs->block_size &&
            read_block(fs, cached_block, fs->io) == 0) {
            ext4_dirent_t *entry =
                (ext4_dirent_t *)(fs->io + cached_offset);

            if (entry->rec_len >= 8u &&
                cached_offset + entry->rec_len <= fs->block_size &&
                entry->inode == cached_ino &&
                entry->name_len == name_length &&
                memcmp(entry->name, name, name_length) == 0) {
                int cached;
                if (replaced_ino) *replaced_ino = cached_ino;
                entry->inode = replacement_ino;
                entry->file_type = replacement_type;
                if (write_block(fs, cached_block, fs->io) < 0) return -1;
                cached = lookup_cache_store(
                    fs, dir->ino, name, replacement_ino, 0,
                    cached_block, cached_offset);
                if (!cached) directory_index_invalidate(fs, dir->ino);
                readdir_cache_invalidate(fs, dir->ino);
                return 0;
            }
            lookup_cache_invalidate(fs, dir->ino, name);
        }
    }
    blocks = (inode_size_get(&directory) + fs->block_size - 1u) /
             fs->block_size;
    for (uint32_t logical = 0; logical < blocks; ++logical) {
        uint32_t physical;
        uint32_t offset = 0;
        if (map_find_phys(fs, &directory, logical, &physical) < 0 ||
            read_block(fs, physical, fs->io) < 0)
            return -1;
        while (offset + 8u <= fs->block_size) {
            ext4_dirent_t *entry = (ext4_dirent_t *)(fs->io + offset);
            if (entry->rec_len < 8u ||
                offset + entry->rec_len > fs->block_size)
                return -1;
            if (entry->inode && entry->name_len == name_length &&
                memcmp(entry->name, name, entry->name_len) == 0) {
                int cached;
                if (replaced_ino) *replaced_ino = entry->inode;
                entry->inode = replacement_ino;
                entry->file_type = replacement_type;
                if (write_block(fs, physical, fs->io) < 0) return -1;
                cached = lookup_cache_store(
                    fs, dir->ino, name, replacement_ino, 0,
                    physical, offset);
                if (!cached) directory_index_invalidate(fs, dir->ino);
                readdir_cache_invalidate(fs, dir->ino);
                return 0;
            }
            offset += entry->rec_len;
        }
    }
    return -1;
}

static int ext4_retire_directory_inode(ext4_fs_t *fs, uint32_t ino,
                                       ext4_inode_t *inode) {
    ext4_open_inode_entry_t *open_entry;
    if (!fs || !ino || !inode ||
        (inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -1;
    inode->links_count = 0;
    inode->ctime = inode->dtime = ext4_now_sec();
    open_entry = ext4_open_inode_entry(fs, ino, 0);
    if (open_entry && open_entry->references) {
        open_entry->delete_pending = 1;
        return write_inode(fs, ino, inode);
    }
    return ext4_reclaim_inode(fs, ino, inode);
}

static int ext4_update_rename_parent_metadata(ext4_fs_t *fs,
                                              uint32_t old_parent,
                                              uint32_t new_parent,
                                              int source_directory,
                                              int target_directory) {
    ext4_inode_t old_inode;
    ext4_inode_t new_inode;
    uint32_t now = ext4_now_sec();
    if (!fs || read_inode(fs, old_parent, &old_inode) < 0)
        return -1;
    if (old_parent == new_parent) {
        if (target_directory) {
            if (!old_inode.links_count) return -1;
            --old_inode.links_count;
        }
        old_inode.mtime = old_inode.ctime = now;
        return write_inode(fs, old_parent, &old_inode);
    }
    if (read_inode(fs, new_parent, &new_inode) < 0) return -1;
    if (source_directory) {
        if (!old_inode.links_count || new_inode.links_count == 0xffffu)
            return -1;
        --old_inode.links_count;
        ++new_inode.links_count;
    }
    if (target_directory) {
        if (!new_inode.links_count) return -1;
        --new_inode.links_count;
    }
    old_inode.mtime = old_inode.ctime = now;
    new_inode.mtime = new_inode.ctime = now;
    if (write_inode(fs, old_parent, &old_inode) < 0 ||
        write_inode(fs, new_parent, &new_inode) < 0)
        return -1;
    return 0;
}

static int ext4_rmdir(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    vfs_inode_t target;
    uint32_t ino = 0;
    ext4_inode_t inode;
    ext4_inode_t parent;
    ext4_open_inode_entry_t *open_entry;
    int empty;
    if (!fs || !dir || !name) return VFS_PATH_ERR_INVALID;
    if (ext4_lookup(sb, dir, name, &target) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if ((target.mode & 0xf000u) != VFS_INODE_DIR)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    empty = ext4_directory_is_empty(fs, target.ino, &inode);
    if (empty < 0) return VFS_PATH_ERR_IO;
    if (!empty) return VFS_PATH_ERR_NOT_EMPTY;
    if (ext4_dir_remove_entry(fs, dir, name, &ino) < 0 || ino != target.ino ||
        read_inode(fs, dir->ino, &parent) < 0)
        return VFS_PATH_ERR_IO;
    inode.links_count = 0;
    inode.ctime = inode.dtime = ext4_now_sec();
    if (parent.links_count) --parent.links_count;
    if (write_inode(fs, dir->ino, &parent) < 0) return VFS_PATH_ERR_IO;
    open_entry = ext4_open_inode_entry(fs, ino, 0);
    if (open_entry && open_entry->references) {
        open_entry->delete_pending = 1;
        return write_inode(fs, ino, &inode) < 0 ? VFS_PATH_ERR_IO : 0;
    }
    return ext4_reclaim_inode(fs, ino, &inode) < 0 ? VFS_PATH_ERR_IO : 0;
}

static uint8_t ext4_dirent_type(uint16_t mode) {
    switch (mode & 0xf000u) {
        case 0x8000u: return 1;
        case 0x4000u: return 2;
        case 0x2000u: return 3;
        case 0x6000u: return 4;
        case 0x1000u: return 5;
        case 0xc000u: return 6;
        case 0xa000u: return 7;
        default: return 0;
    }
}

static int ext4_link(vfs_superblock_t *sb, vfs_inode_t *inode,
                     vfs_inode_t *dir, const char *name) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    ext4_inode_t disk_inode;
    ext4_inode_t original_inode;
    ext4_inode_t disk_dir;
    ext4_open_inode_entry_t *open_entry;
    if (!fs || !inode || !dir || !name || !name[0] ||
        (inode->mode & 0xf000u) == VFS_INODE_DIR ||
        ext4_lookup(sb, dir, name, &(vfs_inode_t){0}) == 0 ||
        read_inode(fs, inode->ino, &disk_inode) < 0 ||
        !disk_inode.mode || read_inode(fs, dir->ino, &disk_dir) < 0 ||
        (disk_dir.mode & 0xf000u) != VFS_INODE_DIR ||
        disk_inode.links_count == 0xffffu)
        return -1;
    original_inode = disk_inode;
    ++disk_inode.links_count;
    disk_inode.dtime = 0;
    disk_inode.ctime = ext4_now_sec();
    if (write_inode(fs, inode->ino, &disk_inode) < 0) return -1;
    if (dir_insert(fs, &disk_dir, dir->ino, inode->ino, name,
                   ext4_dirent_type(inode->mode)) < 0) {
        (void)write_inode(fs, inode->ino, &original_inode);
        return -1;
    }
    open_entry = ext4_open_inode_entry(fs, inode->ino, 0);
    if (open_entry) open_entry->delete_pending = 0;
    readdir_cache_invalidate(fs, dir->ino);
    return 0;
}

static int ext4_rename(vfs_superblock_t *sb, vfs_inode_t *old_dir, const char *old_name, vfs_inode_t *new_dir, const char *new_name) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    vfs_inode_t source;
    vfs_inode_t target;
    ext4_inode_t source_inode;
    ext4_inode_t target_inode;
    ext4_inode_t new_parent_inode;
    uint8_t source_type;
    int source_directory;
    int target_directory = 0;
    int target_exists;
    int moved_parent;
    int ancestry;

    if (!fs || !old_dir || !new_dir || !old_name || !new_name ||
        !old_name[0] || !new_name[0] ||
        strlen(old_name) >= VFS_NAME_MAX || strlen(new_name) >= VFS_NAME_MAX ||
        strcmp(old_name, ".") == 0 || strcmp(old_name, "..") == 0 ||
        strcmp(new_name, ".") == 0 || strcmp(new_name, "..") == 0)
        return VFS_PATH_ERR_INVALID;
    if (old_dir->ino == new_dir->ino && strcmp(old_name, new_name) == 0)
        return 0;
    if (ext4_lookup(sb, old_dir, old_name, &source) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if (read_inode(fs, source.ino, &source_inode) < 0)
        return VFS_PATH_ERR_IO;

    source_directory = (source.mode & 0xf000u) == VFS_INODE_DIR;
    source_type = ext4_dirent_type(source.mode);
    if (!source_type) return VFS_PATH_ERR_INVALID;
    target_exists = ext4_lookup(sb, new_dir, new_name, &target) == 0;
    if (target_exists && target.ino == source.ino) return 0;
    if (target_exists) {
        target_directory = (target.mode & 0xf000u) == VFS_INODE_DIR;
        if (source_directory && !target_directory)
            return VFS_PATH_ERR_NOT_DIRECTORY;
        if (!source_directory && target_directory)
            return VFS_PATH_ERR_IS_DIRECTORY;
        if (read_inode(fs, target.ino, &target_inode) < 0)
            return VFS_PATH_ERR_IO;
        if (target_directory) {
            int empty = ext4_directory_is_empty(fs, target.ino,
                                                &target_inode);
            if (empty < 0) return VFS_PATH_ERR_IO;
            if (!empty) return VFS_PATH_ERR_NOT_EMPTY;
        }
    }

    if (source_directory) {
        ancestry = ext4_directory_is_ancestor(fs, source.ino,
                                              new_dir->ino);
        if (ancestry < 0) return VFS_PATH_ERR_IO;
        if (ancestry) return VFS_PATH_ERR_INVALID;
    }

    /*
     * Publish the new name before removing the old one.  When replacing an
     * existing entry, update that directory record in place so readers never
     * observe a missing destination name while the filesystem lock is held.
     */
    if (target_exists) {
        uint32_t replaced = 0;
        if (ext4_dir_replace_entry(fs, new_dir, new_name, source.ino,
                                   source_type, &replaced) < 0 ||
            replaced != target.ino)
            return VFS_PATH_ERR_IO;
    } else {
        if (read_inode(fs, new_dir->ino, &new_parent_inode) < 0 ||
            dir_insert(fs, &new_parent_inode, new_dir->ino, source.ino,
                       new_name, source_type) < 0)
            return VFS_PATH_ERR_IO;
    }

    moved_parent = source_directory && old_dir->ino != new_dir->ino;
    if (moved_parent &&
        ext4_directory_set_parent(fs, source.ino, new_dir->ino) < 0) {
        if (target_exists)
            (void)ext4_dir_replace_entry(fs, new_dir, new_name, target.ino,
                                         ext4_dirent_type(target.mode), 0);
        else
            (void)ext4_dir_remove_entry(fs, new_dir, new_name, 0);
        return VFS_PATH_ERR_IO;
    }

    if (ext4_dir_remove_entry(fs, old_dir, old_name, 0) < 0) {
        if (moved_parent)
            (void)ext4_directory_set_parent(fs, source.ino, old_dir->ino);
        if (target_exists)
            (void)ext4_dir_replace_entry(fs, new_dir, new_name, target.ino,
                                         ext4_dirent_type(target.mode), 0);
        else
            (void)ext4_dir_remove_entry(fs, new_dir, new_name, 0);
        return VFS_PATH_ERR_IO;
    }

    if (ext4_update_rename_parent_metadata(fs, old_dir->ino, new_dir->ino,
                                           source_directory,
                                           target_directory) < 0)
        return VFS_PATH_ERR_IO;
    if (target_exists) {
        int retire_result = target_directory ?
            ext4_retire_directory_inode(fs, target.ino, &target_inode) :
            ext4_drop_inode_link(fs, target.ino);
        if (retire_result < 0) return VFS_PATH_ERR_IO;
    }
    source_inode.ctime = ext4_now_sec();
    if (write_inode(fs, source.ino, &source_inode) < 0)
        return VFS_PATH_ERR_IO;
    lookup_cache_invalidate(fs, old_dir->ino, old_name);
    readdir_cache_invalidate(fs, old_dir->ino);
    readdir_cache_invalidate(fs, new_dir->ino);
    return 0;
}

static int ext4_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    uint64_t total_bytes, free_bytes, used_bytes;
    if (!total_kb || !used_kb || !ext4_validate_fs("statfs", sb, fs)) return -1;
    total_bytes = (uint64_t)fs->sb.blocks_count_lo * (uint64_t)fs->block_size;
    free_bytes = (uint64_t)fs->sb.free_blocks_count_lo * (uint64_t)fs->block_size;
    used_bytes = total_bytes > free_bytes ? total_bytes - free_bytes : 0;
    *total_kb = (uint32_t)(total_bytes / 1024ull);
    *used_kb = (uint32_t)(used_bytes / 1024ull);
    return 0;
}

static int ext4_sync_allocation_group(ext4_fs_t *fs, uint32_t group,
                                      int include_inode_bitmap) {
    ext4_bgdesc_t descriptor;
    uint32_t groups;
    uint32_t descriptors_per_block;
    uint32_t descriptor_block;

    if (!fs || !fs->sb.blocks_per_group || !fs->desc_size) return -1;
    groups = (fs->sb.blocks_count_lo - fs->sb.first_data_block +
              fs->sb.blocks_per_group - 1u) / fs->sb.blocks_per_group;
    if (group >= groups || read_bgdesc(fs, group, &descriptor) < 0)
        return -1;
    descriptors_per_block = fs->block_size / fs->desc_size;
    if (!descriptors_per_block) return -1;
    descriptor_block = fs->sb.first_data_block + 1u +
                       group / descriptors_per_block;
    if (block_cache_flush_block(fs, descriptor.block_bitmap_lo) < 0 ||
        (include_inode_bitmap &&
         block_cache_flush_block(fs, descriptor.inode_bitmap_lo) < 0) ||
        block_cache_flush_block(fs, descriptor_block) < 0)
        return -1;
    return 0;
}

static int ext4_sync_data_allocation_groups(ext4_fs_t *fs,
                                            uint32_t first_block,
                                            uint32_t block_count) {
    uint64_t last_block;
    uint32_t first_group;
    uint32_t last_group;

    if (!fs || !block_count || !fs->sb.blocks_per_group ||
        first_block < fs->sb.first_data_block)
        return block_count ? -1 : 0;
    last_block = (uint64_t)first_block + block_count - 1u;
    if (last_block >= fs->sb.blocks_count_lo) return -1;
    first_group = (first_block - fs->sb.first_data_block) /
                  fs->sb.blocks_per_group;
    last_group = ((uint32_t)last_block - fs->sb.first_data_block) /
                 fs->sb.blocks_per_group;
    for (uint32_t group = first_group; group <= last_group; ++group)
        if (ext4_sync_allocation_group(fs, group, 0) < 0) return -1;
    return 0;
}

static int ext4_sync_extent_node(ext4_fs_t *fs, const uint8_t *node,
                                 uint32_t workspace_depth) {
    const ext4_extent_header_t *header =
        (const ext4_extent_header_t *)node;

    if (!fs || !node || !extent_header_valid(header) ||
        header->eh_depth > EXT4_MAX_EXTENT_DEPTH)
        return -1;
    if (header->eh_depth == 0) {
        const ext4_extent_t *extents = (const ext4_extent_t *)(
            node + sizeof(*header));
        for (uint16_t index = 0; index < header->eh_entries; ++index) {
            uint32_t count = extent_actual_length(&extents[index]);
            uint32_t first = extent_start_phys(&extents[index]);
            if (!count) continue;
            if (block_cache_flush_range(fs, first, count) < 0 ||
                ext4_sync_data_allocation_groups(fs, first, count) < 0)
                return -1;
        }
        return 0;
    }
    if (workspace_depth >= EXT4_MAX_EXTENT_DEPTH) return -1;
    {
        const ext4_extent_idx_t *indexes = (const ext4_extent_idx_t *)(
            node + sizeof(*header));
        for (uint16_t index = 0; index < header->eh_entries; ++index) {
            uint32_t block = idx_leaf_phys(&indexes[index]);
            uint8_t *child = fs->extent_work[workspace_depth];
            if (!block || read_block(fs, block, child) < 0 ||
                ext4_sync_extent_node(fs, child, workspace_depth + 1u) < 0 ||
                block_cache_flush_block(fs, block) < 0 ||
                ext4_sync_data_allocation_groups(fs, block, 1u) < 0)
                return -1;
        }
    }
    return 0;
}

static int ext4_sync_legacy_indirect(ext4_fs_t *fs, uint32_t block,
                                     uint32_t depth, uint32_t workspace_depth) {
    uint32_t *entries;
    uint32_t count;

    if (!fs || !block || !depth || workspace_depth >= 3u) return -1;
    entries = (uint32_t *)fs->legacy_work[workspace_depth];
    if (read_block(fs, block, entries) < 0) return -1;
    count = fs->block_size / sizeof(entries[0]);
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t child = entries[index];
        if (!child) continue;
        if (depth == 1u) {
            if (block_cache_flush_block(fs, child) < 0 ||
                ext4_sync_data_allocation_groups(fs, child, 1u) < 0)
                return -1;
        } else if (ext4_sync_legacy_indirect(
                       fs, child, depth - 1u, workspace_depth + 1u) < 0) {
            return -1;
        }
    }
    if (block_cache_flush_block(fs, block) < 0 ||
        ext4_sync_data_allocation_groups(fs, block, 1u) < 0)
        return -1;
    return 0;
}

static int ext4_sync_inode_locked(vfs_superblock_t *sb,
                                  const vfs_inode_t *inode, int data_only) {
    ext4_fs_t *fs;
    ext4_inode_t disk_inode;
    ext4_bgdesc_t inode_group;
    uint32_t inode_index;
    uint32_t group;
    uint32_t table_offset;
    uint32_t inode_table_block;
    int result = -1;

    (void)data_only;
    if (!sb || !inode || !inode->ino) return -1;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    if (read_inode(fs, inode->ino, &disk_inode) < 0 ||
        bitmap_cache_flush(fs) < 0)
        goto done;

    if (disk_inode.flags & EXT4_EXTENTS_FL) {
        if (ext4_sync_extent_node(
                fs, (const uint8_t *)disk_inode.block, 0) < 0)
            goto done;
    } else {
        for (uint32_t index = 0; index < 12u; ++index) {
            if (!disk_inode.block[index]) continue;
            if (block_cache_flush_block(fs, disk_inode.block[index]) < 0 ||
                ext4_sync_data_allocation_groups(
                    fs, disk_inode.block[index], 1u) < 0)
                goto done;
        }
        for (uint32_t depth = 1; depth <= 3u; ++depth) {
            uint32_t block = disk_inode.block[11u + depth];
            if (block && ext4_sync_legacy_indirect(
                    fs, block, depth, 0) < 0)
                goto done;
        }
    }
    if (disk_inode.file_acl_lo &&
        (block_cache_flush_block(fs, disk_inode.file_acl_lo) < 0 ||
         ext4_sync_data_allocation_groups(
             fs, disk_inode.file_acl_lo, 1u) < 0))
        goto done;

    inode_index = inode->ino - 1u;
    group = inode_index / fs->sb.inodes_per_group;
    if (read_bgdesc(fs, group, &inode_group) < 0) goto done;
    table_offset = (inode_index % fs->sb.inodes_per_group) *
                   fs->sb.inode_size;
    inode_table_block = inode_group.inode_table_lo +
                        table_offset / fs->block_size;
    if (block_cache_flush_block(fs, inode_table_block) < 0 ||
        ext4_sync_allocation_group(fs, group, 1) < 0 ||
        sync_super_bg_if_dirty(fs) < 0 ||
        block_cache_flush_block(fs, fs->sb.first_data_block + 1u) < 0 ||
        block_flush(fs->bdev) < 0)
        goto done;
    result = 0;
done:
    ext4_op_unlock(fs);
    return result;
}

int ext4_sync(vfs_superblock_t *sb) {
    ext4_fs_t *fs;
    ext4_open_inode_page_t *page;
    int rc;
    if (!sb) return -1;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    if (fs->shutdown_complete) {
        ext4_op_unlock(fs);
        return 0;
    }
    rc = 0;
    for (page = fs->open_inode_pages; page; page = page->next) {
        for (uint32_t i = 0; i < page->capacity; ++i) {
            ext4_open_inode_entry_t *entry = &page->entries[i];
            ext4_inode_t inode;

            if (!entry->ino || entry->references || !entry->delete_pending)
                continue;
            if (read_inode(fs, entry->ino, &inode) < 0 ||
                ext4_reclaim_inode(fs, entry->ino, &inode) < 0) {
                rc = -1;
                continue;
            }
            memset(entry, 0, sizeof(*entry));
        }
    }
    if (ext4_flush_all_durable(fs) < 0) rc = -1;
    ext4_op_unlock(fs);
    return rc;
}

static uint32_t ext4_reclaim_metadata(vfs_superblock_t *sb,
                                     uint32_t page_count) {
    ext4_fs_t *fs;
    uint32_t reclaimed = 0;

    if (!sb || !page_count) return 0;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return 0;
    while (reclaimed < page_count) {
        int released = 0;

        if (fs->lookup_cache_pages)
            released = lookup_cache_reclaim_page(fs);
        if (!released && fs->inode_cache_pages) {
            inode_cache_lock(fs);
            released = inode_cache_reclaim_page(fs);
            inode_cache_unlock(fs);
        }
        if (!released) break;
        ++reclaimed;
    }
    ext4_op_unlock(fs);
    return reclaimed;
}

static int ext4_shutdown(vfs_superblock_t *sb) {
    ext4_fs_t *fs;
    ext4_open_inode_page_t *page;
    int result = 0;

    if (!sb) return -1;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    if (fs->shutdown_complete) goto out;

    /*
     * vfs_shutdown_sync_all() calls this only after the architecture page cache
     * and the ordinary filesystem sync have both completed successfully.
     * Validate the complete retirement set before changing any allocation
     * metadata.  A stale delete_pending flag must never free a linked inode.
     */
    if (fs->bitmap_cache_dirty) {
        result = -1;
        goto out;
    }
    for (uint32_t cache = 0; cache < EXT4_BLOCK_CACHE_SLOTS; ++cache) {
        if (fs->block_cache[cache].valid &&
            fs->block_cache[cache].dirty) {
            result = -1;
            goto out;
        }
    }
    for (page = fs->open_inode_pages; page; page = page->next) {
        for (uint32_t slot = 0; slot < page->capacity; ++slot) {
            ext4_open_inode_entry_t *entry = &page->entries[slot];
            ext4_inode_t inode;

            if (!entry->ino || !entry->delete_pending) continue;
            if (read_inode(fs, entry->ino, &inode) < 0 ||
                (inode.mode && inode.links_count)) {
                result = -1;
                goto out;
            }
        }
    }

    /*
     * Live descriptor and VMA reference counters are deliberately ignored in
     * this terminal-only phase.  The normal sync and inode_close paths retain
     * their existing behavior and never reclaim storage while a reference is
     * live.
     */
    for (page = fs->open_inode_pages; page; page = page->next) {
        for (uint32_t slot = 0; slot < page->capacity; ++slot) {
            ext4_open_inode_entry_t *entry = &page->entries[slot];
            ext4_inode_t inode;
            uint32_t ino = entry->ino;

            if (!ino || !entry->delete_pending) continue;
            if (read_inode(fs, ino, &inode) < 0) {
                result = -1;
                break;
            }
            if (inode.mode && ext4_reclaim_inode(fs, ino, &inode) < 0) {
                result = -1;
                break;
            }
            memset(entry, 0, sizeof(*entry));
        }
        if (result < 0) break;
    }
    if (result == 0 && ext4_flush_all_durable(fs) < 0)
        result = -1;

    if (result == 0 && fs->write_session_started &&
        fs->mount_state_was_clean &&
        !(fs->sb.state & EXT4_ERROR_FS)) {
        uint16_t unclean_state = fs->sb.state;

        /*
         * Only a filesystem that entered this mount clean may be declared
         * clean again.  A pre-existing recovery requirement is preserved
         * until a recovery-capable implementation has actually handled it.
         */
        fs->sb.state |= EXT4_VALID_FS;
        fs->sb.wtime = ext4_now_sec();
        fs->meta_dirty = 1;
        if (ext4_flush_all_durable(fs) < 0) {
            fs->sb.state = unclean_state & (uint16_t)~EXT4_VALID_FS;
            fs->meta_dirty = 1;
            (void)sync_super_bg_if_dirty(fs);
            (void)block_cache_flush_all(fs);
            (void)block_flush(fs->bdev);
            result = -1;
        }
    }
    if (result == 0) fs->shutdown_complete = 1u;
out:
    ext4_op_unlock(fs);
    return result;
}

static void ext4_retain_backend(void *private_data) {
    ext4_fs_t *fs = (ext4_fs_t *)private_data;

    if (fs)
        __atomic_add_fetch(&fs->references, 1u, __ATOMIC_RELAXED);
}

static void ext4_release_backend(void *private_data) {
    ext4_fs_t *fs = (ext4_fs_t *)private_data;

    if (!fs || !__atomic_load_n(&fs->references, __ATOMIC_RELAXED))
        return;
    if (__atomic_sub_fetch(&fs->references, 1u, __ATOMIC_ACQ_REL) != 0)
        return;

    if ((!fs->shutdown_complete &&
         ext4_sync(&fs->lifecycle_superblock) < 0) ||
        ext4_shutdown(&fs->lifecycle_superblock) < 0) {
        printf("[ext4] final release could not complete durable shutdown\n");
        return;
    }
    ext4_dynamic_state_release(fs);
    ext4_mount_registry_remove(fs);
    ext4_state_release(fs);
}

static int ext4_writeback(vfs_superblock_t *sb) {
    ext4_fs_t *fs;
    int rc = 0;
    if (!sb) return -1;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    if (sync_super_bg_if_dirty(fs) < 0) {
        rc = -1;
    } else {
        for (uint32_t slot = 0; slot < EXT4_BLOCK_CACHE_SLOTS; ++slot) {
            if (!fs->block_cache[slot].valid ||
                !fs->block_cache[slot].dirty)
                continue;
            rc = block_cache_flush_slot(fs, (int)slot);
            break;
        }
    }
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_feature_set_supported(const ext4_super_t *sb) {
    uint32_t unsupported_incompat, unsupported_ro;
    if (!sb) return 0;
    unsupported_incompat = sb->feature_incompat &
        ~(EXT4_INCOMPAT_FILETYPE | EXT4_INCOMPAT_EXTENTS | EXT4_INCOMPAT_FLEX_BG);
    if (unsupported_incompat) {
        printf("[ext4] unsupported incompat=0x%x\n", unsupported_incompat);
        return 0;
    }
    unsupported_ro = sb->feature_ro_compat &
        ~(EXT4_RO_COMPAT_SPARSE_SUPER | EXT4_RO_COMPAT_LARGE_FILE | EXT4_RO_COMPAT_BTREE_DIR | EXT4_RO_COMPAT_DIR_NLINK);
    if (unsupported_ro) {
        printf("[ext4] unsupported ro_compat=0x%x\n", unsupported_ro);
        return 0;
    }
    return 1;
}

static int ext4_lookup_locked(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    uint64_t t0;
    int rc;
    if (!fs) return -1;
    t0 = boottime_monotonic_us();
    rc = ext4_lookup(sb, dir, name, out);
    ext4_trace_slow_lookup(dir, name, rc, boottime_monotonic_us() - t0);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_read_locked(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    ext4_fs_t *fs;
    ext4_ro_workspace_t *ws;
    int rc;
    if (!sb) return -1;
    fs = (ext4_fs_t *)sb->fs_private;
    if (!fs) return -1;

    if (inode && len >= EXT4_PARALLEL_READ_MIN && fs->block_size != 0 &&
        (off % fs->block_size) == 0) {
        ws = ext4_ro_workspace_acquire();
        ext4_read_begin(fs);
        if (ext4_validate_fs("read-ro", sb, fs) && !block_cache_has_dirty(fs)) {
            rc = ext4_read_ro(sb, inode, off, buf, len, ws);
            if (rc >= 0) {
                ext4_read_end(fs);
                ext4_ro_workspace_release(ws);
                return rc;
            }
        }
        ext4_read_end(fs);
        ext4_ro_workspace_release(ws);
    }

    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    rc = ext4_read(sb, inode, off, buf, len);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_write_locked(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_write(sb, inode, off, buf, len);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_append_locked(vfs_superblock_t *sb, vfs_inode_t *inode,
                              const void *buf, uint32_t len,
                              uint32_t *offset_out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t disk_inode;
    uint32_t offset;
    int rc = -1;
    if (!fs || !inode || !offset_out) {
        if (fs) ext4_op_unlock(fs);
        return -1;
    }
    if (read_inode(fs, inode->ino, &disk_inode) < 0) goto out;
    offset = inode_size_get(&disk_inode);
    if (len > UINT32_MAX - offset) goto out;
    rc = ext4_write(sb, inode, offset, buf, len);
    if (rc >= 0) *offset_out = offset;
out:
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_create_locked(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_create(sb, dir, name, mode, out);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_mkdir_locked(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_mkdir(sb, dir, name, mode, out);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_mknod_locked(vfs_superblock_t *sb, vfs_inode_t *dir,
                             const char *name, uint16_t mode, uint64_t rdev,
                             vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_mknod(sb, dir, name, mode, rdev, out);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_symlink_locked(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name,
                               const char *target, uint16_t mode, vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_symlink(sb, dir, name, target, mode, out);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_readlink_locked(vfs_superblock_t *sb, vfs_inode_t *inode, char *out, uint32_t max) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_readlink(sb, inode, out, max);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_unlink_locked(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_unlink(sb, dir, name);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_rmdir_locked(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_rmdir(sb, dir, name);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_rename_locked(vfs_superblock_t *sb, vfs_inode_t *old_dir, const char *old_name, vfs_inode_t *new_dir, const char *new_name) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_rename(sb, old_dir, old_name, new_dir, new_name);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_truncate_locked(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t len) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_truncate(sb, inode, len);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_fallocate_locked(vfs_superblock_t *sb, vfs_inode_t *inode,
                                 uint32_t mode, uint64_t offset,
                                 uint64_t length) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return VFS_FALLOCATE_ERR_IO;
    rc = ext4_fallocate(sb, inode, mode, offset, length);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_seek_data_hole_locked(vfs_superblock_t *sb,
                                      const vfs_inode_t *inode,
                                      uint64_t offset, int seek_hole,
                                      uint64_t *result) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return VFS_SEEK_DATA_HOLE_ERR_IO;
    rc = ext4_seek_data_hole(
        sb, inode, offset, seek_hole, result);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_map_extent_locked(vfs_superblock_t *sb,
                                  const vfs_inode_t *inode,
                                  uint64_t offset, uint64_t length,
                                  vfs_extent_t *extent) {
    ext4_fs_t *fs = (ext4_fs_t *)sb->fs_private;
    int rc;
    ext4_op_lock(fs);
    rc = ext4_map_extent(sb, inode, offset, length, extent);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_readdir_locked(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_readdir(sb, dir, idx, name_out, inode_out);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_readdir_dirent_locked(vfs_superblock_t *sb,
                                      vfs_inode_t *dir, uint32_t idx,
                                      char *name_out,
                                      uint32_t *inode_number,
                                      uint16_t *mode) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int result;

    if (!fs) return -1;
    result = ext4_readdir_dirent(
        sb, dir, idx, name_out, inode_number, mode);
    ext4_op_unlock(fs);
    return result;
}

static int ext4_statfs_locked(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_statfs(sb, total_kb, used_kb);
    ext4_op_unlock(fs);
    return rc;
}

static int ext4_link_locked(vfs_superblock_t *sb, vfs_inode_t *inode,
                            vfs_inode_t *dir, const char *name) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    int rc;
    if (!fs) return -1;
    rc = ext4_link(sb, inode, dir, name);
    ext4_op_unlock(fs);
    return rc;
}

typedef struct {
    uint32_t inode;
    uint32_t generation;
} ext4_export_handle_t;

static int ext4_encode_handle_locked(vfs_superblock_t *sb,
                                     const vfs_inode_t *inode,
                                     uint32_t *handle_type, void *handle,
                                     uint32_t *handle_bytes) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t disk_inode;
    ext4_export_handle_t value;
    int result = VFS_FILE_HANDLE_ERR_STALE;
    if (!fs) return VFS_FILE_HANDLE_ERR_IO;
    if (!inode || !handle_type || !handle_bytes || !inode->ino ||
        inode->ino > fs->sb.inodes_count ||
        read_inode(fs, inode->ino, &disk_inode) < 0 || !disk_inode.mode ||
        !disk_inode.links_count)
        goto out;
    *handle_type = 1u;
    if (*handle_bytes < sizeof(value)) {
        *handle_bytes = sizeof(value);
        result = VFS_FILE_HANDLE_ERR_OVERFLOW;
        goto out;
    }
    if (!handle) {
        result = VFS_FILE_HANDLE_ERR_INVALID;
        goto out;
    }
    value.inode = inode->ino;
    value.generation = disk_inode.generation;
    memcpy(handle, &value, sizeof(value));
    *handle_bytes = sizeof(value);
    result = 0;
out:
    ext4_op_unlock(fs);
    return result;
}

static int ext4_decode_handle_locked(vfs_superblock_t *sb,
                                     uint32_t handle_type,
                                     const void *handle,
                                     uint32_t handle_bytes,
                                     vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t disk_inode;
    ext4_export_handle_t value;
    int result = VFS_FILE_HANDLE_ERR_STALE;
    if (!fs) return VFS_FILE_HANDLE_ERR_IO;
    if (!handle || !out || handle_type != 1u ||
        handle_bytes != sizeof(value)) {
        result = VFS_FILE_HANDLE_ERR_INVALID;
        goto out;
    }
    memcpy(&value, handle, sizeof(value));
    if (!value.inode || value.inode > fs->sb.inodes_count ||
        read_inode(fs, value.inode, &disk_inode) < 0 || !disk_inode.mode ||
        !disk_inode.links_count || disk_inode.generation != value.generation)
        goto out;
    ext4_fill_vfs_inode(value.inode, &disk_inode, out);
    result = 0;
out:
    ext4_op_unlock(fs);
    return result;
}

static int ext4_inode_open_locked(vfs_superblock_t *sb,
                                  const vfs_inode_t *inode) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_open_inode_entry_t *open_entry;
    ext4_inode_t disk_inode;
    int result = -1;
    if (!fs) return -1;
    if (!inode || !inode->ino || inode->ino > fs->sb.inodes_count ||
        read_inode(fs, inode->ino, &disk_inode) < 0 || !disk_inode.mode)
        goto out;
    open_entry = ext4_open_inode_entry(fs, inode->ino, 0);
    /*
     * mmap may acquire its independent file-object reference after unlink but
     * before the descriptor is closed.  Linux keeps that inode alive for the
     * VMA.  Permit a new reference to an unlinked inode only while an existing
     * open reference already proves the object has not been reclaimed.
     */
    if (!disk_inode.links_count &&
        (!open_entry || !open_entry->references))
        goto out;
    if (!open_entry)
        open_entry = ext4_open_inode_entry(fs, inode->ino, 1);
    if (!open_entry || open_entry->references == UINT32_MAX)
        goto out;
    ++open_entry->references;
    result = 0;
out:
    ext4_op_unlock(fs);
    return result;
}

static void ext4_inode_close_locked(vfs_superblock_t *sb,
                                    const vfs_inode_t *inode) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_open_inode_entry_t *open_entry;
    ext4_inode_t disk_inode;
    if (!fs) return;
    if (!inode) goto out;
    open_entry = ext4_open_inode_entry(fs, inode->ino, 0);
    if (!open_entry || !open_entry->references) goto out;
    --open_entry->references;
    if (open_entry->references) goto out;
    if (read_inode(fs, inode->ino, &disk_inode) < 0) {
        open_entry->delete_pending = 1;
        goto out;
    }
    if (!disk_inode.links_count || open_entry->delete_pending) {
        if (ext4_reclaim_inode(fs, inode->ino, &disk_inode) < 0) {
            open_entry->delete_pending = 1;
            goto out;
        }
    }
    memset(open_entry, 0, sizeof(*open_entry));
out:
    ext4_op_unlock(fs);
}

static int ext4_getattr_locked(vfs_superblock_t *sb,
                               const vfs_inode_t *inode,
                               vfs_inode_t *out) {
    ext4_fs_t *fs = ext4_lock_from_sb(sb);
    ext4_inode_t disk_inode;
    int result = -1;
    if (!fs) return -1;
    if (!inode || !out || !inode->ino ||
        inode->ino > fs->sb.inodes_count ||
        read_inode(fs, inode->ino, &disk_inode) < 0 || !disk_inode.mode)
        goto done;
    ext4_fill_vfs_inode(inode->ino, &disk_inode, out);
    result = 0;
done:
    ext4_op_unlock(fs);
    return result;
}

static filesystem_ops_t g_ext4_ops = {
    .lookup = ext4_lookup_locked,
    .read = ext4_read_locked,
    .write = ext4_write_locked,
    .create = ext4_create_locked,
    .mkdir = ext4_mkdir_locked,
    .symlink = ext4_symlink_locked,
    .readlink = ext4_readlink_locked,
    .unlink = ext4_unlink_locked,
    .rename = ext4_rename_locked,
    .truncate = ext4_truncate_locked,
    .readdir = ext4_readdir_locked,
    .readdir_dirent = ext4_readdir_dirent_locked,
    .statfs = ext4_statfs_locked,
    .sync = ext4_sync,
    .link = ext4_link_locked,
    .rmdir = ext4_rmdir_locked,
    .mknod = ext4_mknod_locked,
    .fallocate = ext4_fallocate_locked,
    .seek_data_hole = ext4_seek_data_hole_locked,
    .map_extent = ext4_map_extent_locked,
    .encode_handle = ext4_encode_handle_locked,
    .decode_handle = ext4_decode_handle_locked,
    .inode_open = ext4_inode_open_locked,
    .inode_close = ext4_inode_close_locked,
    .append = ext4_append_locked,
    .setxattr = ext4_setxattr_locked,
    .getxattr = ext4_getxattr_locked,
    .listxattr = ext4_listxattr_locked,
    .removexattr = ext4_removexattr_locked,
    .getattr = ext4_getattr_locked,
    .settimes = ext4_settimes,
    .setattr = ext4_setattr,
    .writeback = ext4_writeback,
    .sync_inode = ext4_sync_inode_locked,
    .reclaim_metadata = ext4_reclaim_metadata,
    .shutdown = ext4_shutdown,
};

static int ext4_mount_common(block_device_t *b, const char *dev, const char *target) {
    ext4_fs_t *fs;
    ext4_inode_t root;
    vfs_superblock_t sb;
    uint16_t minimum_extra_isize;
    uint16_t wanted_extra_isize;
    uint16_t root_mode;
    int registered = 0;
    if (!b || !target) return -1;
    fs = ext4_state_allocate();
    if (!fs) return -1;
    fs->bdev = b;

    if (block_read_sectors(b, 2, 2, fs->io) < 0) {
        printf("[ext4] failed reading superblock from %s\n", dev);
        goto fail;
    }
    memcpy(&fs->sb, fs->io, sizeof(ext4_super_t));
    if (fs->sb.magic != 0xEF53) {
        printf("[ext4] invalid superblock magic on %s\n", dev);
        goto fail;
    }
    fs->mount_state_was_clean =
        (fs->sb.state & EXT4_VALID_FS) != 0 &&
        (fs->sb.state & EXT4_ERROR_FS) == 0;
    if (!fs->mount_state_was_clean)
        printf("[ext4] %s requires filesystem recovery; preserving state\n",
               dev);
    if (!ext4_feature_set_supported(&fs->sb)) goto fail;
    fs->block_size = 1024u << fs->sb.log_block_size;
    fs->desc_size = 32;
    minimum_extra_isize =
        (uint16_t)((uint16_t)fs->io[EXT4_SUPER_MIN_EXTRA_ISIZE_OFFSET] |
        ((uint16_t)fs->io[EXT4_SUPER_MIN_EXTRA_ISIZE_OFFSET + 1u] << 8));
    wanted_extra_isize =
        (uint16_t)((uint16_t)fs->io[EXT4_SUPER_WANT_EXTRA_ISIZE_OFFSET] |
        ((uint16_t)fs->io[EXT4_SUPER_WANT_EXTRA_ISIZE_OFFSET + 1u] << 8));
    fs->inode_extra_isize = wanted_extra_isize > minimum_extra_isize ?
        wanted_extra_isize : minimum_extra_isize;
    if (fs->inode_extra_isize &&
        ((fs->inode_extra_isize & 3u) ||
         fs->sb.inode_size <= sizeof(ext4_inode_t) + 4u ||
         fs->inode_extra_isize >
            fs->sb.inode_size - sizeof(ext4_inode_t) - 4u)) {
        printf("[ext4] invalid inode extra isize on %s: %u\n",
               dev, (unsigned)fs->inode_extra_isize);
        goto fail;
    }
    fs->bitmap_cache_valid = 0;
    fs->bitmap_cache_dirty = 0;
    fs->bitmap_cache_block = 0;
    lookup_cache_invalidate_all(fs);
    if (fs->block_size == 0 || fs->block_size > sizeof(fs->io)) {
        printf("[ext4] unsupported block size on %s\n", dev);
        goto fail;
    }
    ext4_mount_registry_add(fs);
    registered = 1;

    /*
     * A writable ext4 mount is an active write session even before the first
     * inode change.  Publish the unclean state while the boot block path is
     * still polling, then restore the clean bit only after ordered shutdown.
     */
    fs->sb.state &= (uint16_t)~EXT4_VALID_FS;
    if (fs->sb.mnt_count != UINT16_MAX) ++fs->sb.mnt_count;
    fs->sb.mtime = ext4_now_sec();
    memcpy(fs->io, &fs->sb, sizeof(fs->sb));
    if (block_write_sectors(b, 2, 2, fs->io) < 0) {
        printf("[ext4] failed writing mount state on %s\n", dev);
        goto fail;
    }
    if (block_flush(b) < 0) {
        printf("[ext4] failed flushing mount state on %s\n", dev);
        goto fail;
    }
    fs->write_session_started = 1;

    if (read_block(fs, fs->sb.first_data_block + 1, fs->io) < 0) {
        printf("[ext4] failed reading group descriptor on %s\n", dev);
        goto fail;
    }
    memcpy(&fs->bg, fs->io, sizeof(ext4_bgdesc_t));
    if (read_inode(fs, 2, &root) < 0) {
        printf("[ext4] failed to read root inode on %s\n", dev);
        goto fail;
    }

    root_mode = vfs_mode_from_ext(root.mode);
    if (!root_mode || (root_mode & 0xF000u) != VFS_INODE_DIR) {
        printf("[ext4] invalid root inode mode on %s\n", dev);
        goto fail;
    }

    memset(&sb, 0, sizeof(sb));
    strcpy(sb.fs_name, "ext4");
    if (dev[0] == '/') strcpy(sb.dev_name, dev); else { strcpy(sb.dev_name, "/dev/"); strcat(sb.dev_name, dev); }
    strcpy(sb.mountpoint, target);
    ext4_fill_vfs_inode(2, &root, &sb.root);
    sb.root.mode = root_mode;
    sb.ops = &g_ext4_ops;
    sb.fs_private = fs;
    sb.retain = ext4_retain_backend;
    sb.release = ext4_release_backend;

    if (strcmp(target, "/") == 0) {
        char init_path[VFS_PATH_MAX];
        vfs_inode_t init;

        memset(&init, 0, sizeof(init));
        if (kernel_boot_init_path(
                0, init_path, sizeof(init_path)) < 0 ||
            vfs_resolve_superblock_path(&sb, init_path, &init) < 0 ||
            (init.mode & 0xF000u) != VFS_INODE_FILE) {
            printf("[ext4] rejecting %s as root: configured init missing\n",
                   sb.dev_name);
            {
                char n[VFS_NAME_MAX];
                vfs_inode_t e;
                printf("[ext4] root entries:");
                for (int i = 0; i < 24; ++i) {
                    if (ext4_readdir(&sb, &sb.root, (uint32_t)i, n, &e) < 0) break;
                    printf(" %s", n);
                }
                printf("\n");
            }
            goto fail;
        }
    }

    if (vfs_add_superblock(&sb) < 0) goto fail;
    printf("[ext4] mounted %s on %s\n", sb.dev_name, target);
    return 0;
fail:
    if (registered && fs->write_session_started) {
        (void)ext4_shutdown(&fs->lifecycle_superblock);
    }
    ext4_dynamic_state_release(fs);
    if (registered) ext4_mount_registry_remove(fs);
    ext4_state_release(fs);
    return -1;
}

int ext4_mount(const char *dev, const char *target) {
    block_device_t *b;
    if (!dev || !target) return -1;
    b = block_find(dev[0] == '/' ? dev + 5 : dev);
    if (!b) return -1;
    return ext4_mount_common(b, dev, target);
}

int ext4_mount_block(block_device_t *bdev, const char *target) {
    if (!bdev || !target) return -1;
    return ext4_mount_common(bdev, bdev->name, target);
}

int ext4_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                 uint16_t mode, uint32_t uid, uint32_t gid, uint32_t mask) {
    ext4_fs_t *fs;
    ext4_inode_t in;
    int rc = -1;
    if (!sb || !inode) return -1;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    if (read_inode(fs, inode->ino, &in) < 0) goto out;
    if (mask & 1u) {
        uint16_t kind = in.mode & 0xF000u;
        in.mode = (uint16_t)(kind | (mode & 07777u));
    }
    if (mask & VFS_SETATTR_UID) ext4_inode_set_uid(&in, uid);
    if (mask & VFS_SETATTR_GID) ext4_inode_set_gid(&in, gid);
    in.ctime = ext4_now_sec();
    if (write_inode(fs, inode->ino, &in) < 0) goto out;
    /*
     * Linux metadata updates become dirty cache state.  Durability is
     * established by fsync/sync, periodic writeback, cache eviction, or the
     * unmount path; chmod/chown must not serialize every caller behind a full
     * filesystem flush.  Package extraction performs several attribute
     * changes per inode, so flushing here turns ordinary metadata traffic into
     * synchronous device I/O and stalls the entire desktop.
     */
    rc = 0;
out:
    ext4_op_unlock(fs);
    return rc;
}

int ext4_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode, uint32_t atime, uint32_t mtime, int set_atime, int set_mtime) {
    ext4_fs_t *fs;
    ext4_inode_t in;
    int rc = -1;
    if (!sb || !inode) return -1;
    fs = ext4_lock_from_sb(sb);
    if (!fs) return -1;
    if (read_inode(fs, inode->ino, &in) < 0) goto out;
    if (set_atime) in.atime = atime;
    if (set_mtime) in.mtime = mtime;
    in.ctime = ext4_now_sec();
    if (write_inode(fs, inode->ino, &in) < 0) goto out;
    /* Timestamp changes follow the same deferred-writeback contract. */
    rc = 0;
out:
    ext4_op_unlock(fs);
    return rc;
}
