#ifndef VFS_VFS_H
#define VFS_VFS_H

#include <stdint.h>
#include "block/block.h"
#include "sys/process.h"

/*
 * Linux filesystems such as ext4 expose NAME_MAX=255 bytes for a single path
 * component.  Keep the internal buffer one byte larger for the terminating
 * NUL.  A smaller value silently breaks real Linux userspace paths such as
 * shared-mime-info's long MIME XML filenames and makes package post-install
 * cache generation fail in otherwise valid directories.
 */
#define VFS_NAME_MAX 256
/*
 * Linux exposes PATH_MAX as 4096 bytes.  Desktop stacks routinely build paths
 * under XDG cache/config, icon themes, MIME databases, and plugin directories
 * that exceed 255 bytes.  Keep all absolute path storage at Linux ABI size so
 * normal path resolution fails cleanly at the boundary instead of corrupting
 * adjacent kernel state.
 */
#define VFS_PATH_MAX 4096
#define VFS_MAX_SYMLINK_FOLLOWS 40

#define VFS_MOUNT_SHARED     1u
#define VFS_MOUNT_PRIVATE    2u
#define VFS_MOUNT_SLAVE      3u
#define VFS_MOUNT_UNBINDABLE 4u
#define VFS_MOUNT_READONLY   0x1u
#define VFS_MOUNT_NOSUID     0x2u
#define VFS_MOUNT_NODEV      0x4u
#define VFS_MOUNT_NOEXEC     0x8u
#define VFS_MOUNT_SYNCHRONOUS 0x10u
#define VFS_MOUNT_DIRSYNC    0x80u
#define VFS_MOUNT_NOSYMFOLLOW 0x100u
#define VFS_MOUNT_NOATIME    0x400u
#define VFS_MOUNT_NODIRATIME 0x800u
#define VFS_MOUNT_POSIXACL   0x10000u
#define VFS_MOUNT_RELATIME   0x200000u
#define VFS_MOUNT_I_VERSION  0x800000u
#define VFS_MOUNT_STRICTATIME 0x1000000u
#define VFS_MOUNT_LAZYTIME   0x2000000u

#define VFS_INODE_DIR  0x4000
#define VFS_INODE_FILE 0x8000
#define VFS_INODE_FIFO 0x1000
#define VFS_INODE_CHR  0x2000
#define VFS_INODE_BLK  0x6000
#define VFS_INODE_LNK  0xA000
#define VFS_INODE_SOCK 0xC000

/*
 * Namespace mutation hooks return these architecture-neutral error classes.
 * Syscall entry code translates them to the architecture's Linux errno ABI.
 * Keeping the distinction below the syscall layer is required for operations
 * such as rmdir and rename where EBUSY, ENOTEMPTY, and EXDEV drive userspace
 * recovery behavior.
 */
#define VFS_PATH_ERR_IO               (-1)
#define VFS_PATH_ERR_BUSY             (-2)
#define VFS_PATH_ERR_NOT_EMPTY        (-3)
#define VFS_PATH_ERR_CROSS_DEVICE     (-4)
#define VFS_PATH_ERR_IS_DIRECTORY     (-5)
#define VFS_PATH_ERR_NOT_DIRECTORY    (-6)
#define VFS_PATH_ERR_NOT_FOUND        (-7)
#define VFS_PATH_ERR_EXISTS           (-8)
#define VFS_PATH_ERR_INVALID          (-9)
#define VFS_PATH_ERR_ACCESS           (-10)
#define VFS_PATH_ERR_NO_SPACE         (-11)
#define VFS_PATH_ERR_READ_ONLY        (-12)
#define VFS_PATH_ERR_PERMISSION       (-13)

/* Linux fallocate(2) mode bits used by filesystem allocation hooks. */
#define VFS_FALLOC_FL_KEEP_SIZE      0x01u
#define VFS_FALLOC_FL_PUNCH_HOLE     0x02u
#define VFS_FALLOC_FL_COLLAPSE_RANGE 0x08u
#define VFS_FALLOC_FL_ZERO_RANGE     0x10u
#define VFS_FALLOC_FL_INSERT_RANGE   0x20u
#define VFS_FALLOC_FL_UNSHARE_RANGE  0x40u

/* Filesystem fallocate hooks use these stable VFS error classes. */
#define VFS_FALLOCATE_ERR_IO          (-1)
#define VFS_FALLOCATE_ERR_UNSUPPORTED (-2)
#define VFS_FALLOCATE_ERR_NOSPC       (-3)
#define VFS_FALLOCATE_ERR_INVALID     (-4)

/* Filesystem truncate hooks use these stable VFS error classes. */
#define VFS_TRUNCATE_ERR_IO          (-1)
#define VFS_TRUNCATE_ERR_UNSUPPORTED (-2)
#define VFS_TRUNCATE_ERR_INVALID     (-3)
#define VFS_TRUNCATE_ERR_PERMISSION  (-4)

/* Sparse extent queries use these stable VFS result classes. */
#define VFS_SEEK_DATA_HOLE_ERR_IO       (-1)
#define VFS_SEEK_DATA_HOLE_ERR_NO_DATA  (-2)
#define VFS_SEEK_DATA_HOLE_ERR_INVALID  (-3)

/* Filesystem extent queries use byte ranges and stable VFS result classes. */
#define VFS_EXTENT_FLAG_LAST      0x0001u
#define VFS_EXTENT_FLAG_UNWRITTEN 0x0002u
#define VFS_EXTENT_FLAG_UNKNOWN   0x0004u
#define VFS_EXTENT_ERR_IO          (-1)
#define VFS_EXTENT_ERR_NO_DATA     (-2)
#define VFS_EXTENT_ERR_UNSUPPORTED (-3)
#define VFS_EXTENT_ERR_INVALID     (-4)

typedef struct vfs_extent {
    uint64_t logical;
    uint64_t physical;
    uint64_t length;
    uint32_t flags;
} vfs_extent_t;

#define VFS_FILE_HANDLE_MAX 128u
#define VFS_FILE_HANDLE_ERR_IO          (-1)
#define VFS_FILE_HANDLE_ERR_UNSUPPORTED (-2)
#define VFS_FILE_HANDLE_ERR_OVERFLOW    (-3)
#define VFS_FILE_HANDLE_ERR_STALE       (-4)
#define VFS_FILE_HANDLE_ERR_INVALID     (-5)

/* Linux-compatible extended attribute limits, flags, and VFS error classes. */
#define VFS_XATTR_NAME_MAX 255u
#define VFS_XATTR_VALUE_MAX 65536u
#define VFS_XATTR_CREATE 0x1u
#define VFS_XATTR_REPLACE 0x2u
#define VFS_XATTR_ERR_IO          (-1)
#define VFS_XATTR_ERR_NO_DATA     (-2)
#define VFS_XATTR_ERR_EXISTS      (-3)
#define VFS_XATTR_ERR_RANGE       (-4)
#define VFS_XATTR_ERR_NOSPC       (-5)
#define VFS_XATTR_ERR_UNSUPPORTED (-6)
#define VFS_XATTR_ERR_INVALID     (-7)
#define VFS_XATTR_ERR_ACCESS      (-8)
#define VFS_XATTR_ERR_PERMISSION  (-9)

/* Linux file attribute flags and architecture-neutral dispatch results. */
#define VFS_FILE_XFLAG_REALTIME            0x00000001u
#define VFS_FILE_XFLAG_PREALLOC            0x00000002u
#define VFS_FILE_XFLAG_IMMUTABLE           0x00000008u
#define VFS_FILE_XFLAG_APPEND              0x00000010u
#define VFS_FILE_XFLAG_SYNC                0x00000020u
#define VFS_FILE_XFLAG_NOATIME             0x00000040u
#define VFS_FILE_XFLAG_NODUMP              0x00000080u
#define VFS_FILE_XFLAG_RTINHERIT           0x00000100u
#define VFS_FILE_XFLAG_PROJINHERIT         0x00000200u
#define VFS_FILE_XFLAG_NOSYMLINKS          0x00000400u
#define VFS_FILE_XFLAG_EXTSIZE             0x00000800u
#define VFS_FILE_XFLAG_EXTSZINHERIT        0x00001000u
#define VFS_FILE_XFLAG_NODEFRAG            0x00002000u
#define VFS_FILE_XFLAG_FILESTREAM          0x00004000u
#define VFS_FILE_XFLAG_DAX                 0x00008000u
#define VFS_FILE_XFLAG_COWEXTSIZE          0x00010000u
#define VFS_FILE_XFLAG_VERITY              0x00020000u
#define VFS_FILE_XFLAG_CASEFOLD            0x00040000u
#define VFS_FILE_XFLAG_CASENONPRESERVING   0x00080000u
#define VFS_FILE_XFLAG_HASATTR             0x80000000u

#define VFS_FILE_XFLAG_COMMON \
    (VFS_FILE_XFLAG_SYNC | VFS_FILE_XFLAG_IMMUTABLE | \
     VFS_FILE_XFLAG_APPEND | VFS_FILE_XFLAG_NODUMP | \
     VFS_FILE_XFLAG_NOATIME | VFS_FILE_XFLAG_DAX | \
     VFS_FILE_XFLAG_PROJINHERIT | VFS_FILE_XFLAG_VERITY)
#define VFS_FILE_XFLAG_READ_ONLY \
    (VFS_FILE_XFLAG_PREALLOC | VFS_FILE_XFLAG_HASATTR | \
     VFS_FILE_XFLAG_VERITY | VFS_FILE_XFLAG_CASEFOLD | \
     VFS_FILE_XFLAG_CASENONPRESERVING)
#define VFS_FILE_XFLAG_ALL \
    (VFS_FILE_XFLAG_COMMON | VFS_FILE_XFLAG_READ_ONLY | \
     VFS_FILE_XFLAG_EXTSIZE | VFS_FILE_XFLAG_COWEXTSIZE | \
     VFS_FILE_XFLAG_RTINHERIT | VFS_FILE_XFLAG_NOSYMLINKS | \
     VFS_FILE_XFLAG_EXTSZINHERIT | VFS_FILE_XFLAG_REALTIME | \
     VFS_FILE_XFLAG_NODEFRAG | VFS_FILE_XFLAG_FILESTREAM)

#define VFS_FILEATTR_ERR_IO          (-1)
#define VFS_FILEATTR_ERR_UNSUPPORTED (-2)
#define VFS_FILEATTR_ERR_INVALID     (-3)
#define VFS_FILEATTR_ERR_READ_ONLY   (-4)
#define VFS_FILEATTR_ERR_PERMISSION  (-5)

typedef struct vfs_fileattr {
    uint64_t xflags;
    uint32_t extsize;
    uint32_t nextents;
    uint32_t projid;
    uint32_t cowextsize;
} vfs_fileattr_t;

typedef struct vfs_inode vfs_inode_t;
typedef struct vfs_superblock vfs_superblock_t;
typedef struct vfs_filesystem_instance vfs_filesystem_instance_t;
struct linux_group_list;

typedef struct {
    int (*lookup)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out);
    int (*read)(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len);
    int (*write)(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len);
    int (*create)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out);
    int (*mkdir)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out);
    int (*symlink)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, const char *target, uint16_t mode, vfs_inode_t *out);
    int (*readlink)(vfs_superblock_t *sb, vfs_inode_t *inode, char *out, uint32_t max);
    int (*unlink)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name);
    int (*rename)(vfs_superblock_t *sb, vfs_inode_t *old_dir, const char *old_name, vfs_inode_t *new_dir, const char *new_name);
    int (*truncate)(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t len);
    int (*readdir)(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out);
    int (*readdir_dirent)(vfs_superblock_t *sb, vfs_inode_t *dir,
                          uint32_t idx, char *name_out,
                          uint32_t *inode_number, uint16_t *mode);
    int (*statfs)(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb);
    int (*sync)(vfs_superblock_t *sb);
    int (*link)(vfs_superblock_t *sb, vfs_inode_t *inode,
                vfs_inode_t *dir, const char *name);
    int (*rmdir)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name);
    int (*mknod)(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name,
                 uint16_t mode, uint64_t rdev, vfs_inode_t *out);
    int (*fallocate)(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t mode,
                     uint64_t offset, uint64_t length);
    int (*seek_data_hole)(vfs_superblock_t *sb,
                          const vfs_inode_t *inode, uint64_t offset,
                          int seek_hole, uint64_t *result);
    int (*map_extent)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                      uint64_t offset, uint64_t length,
                      vfs_extent_t *extent);
    int (*encode_handle)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                         uint32_t *handle_type, void *handle,
                         uint32_t *handle_bytes);
    int (*decode_handle)(vfs_superblock_t *sb, uint32_t handle_type,
                         const void *handle, uint32_t handle_bytes,
                         vfs_inode_t *out);
    /*
     * Preserve Linux open-unlinked lifetime across architecture-specific file
     * descriptor tables. The final open file description releases storage.
     */
    int (*inode_open)(vfs_superblock_t *sb, const vfs_inode_t *inode);
    void (*inode_close)(vfs_superblock_t *sb, const vfs_inode_t *inode);
    /* Select the end offset and write under one filesystem mutation lock. */
    int (*append)(vfs_superblock_t *sb, vfs_inode_t *inode, const void *buf,
                  uint32_t len, uint32_t *offset_out);
    int (*setxattr)(vfs_superblock_t *sb, vfs_inode_t *inode,
                    const char *name, const void *value, uint32_t size,
                    uint32_t flags);
    int (*getxattr)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                    const char *name, void *value, uint32_t size);
    int (*listxattr)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                     char *list, uint32_t size);
    int (*removexattr)(vfs_superblock_t *sb, vfs_inode_t *inode,
                       const char *name);
    int (*fileattr_get)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        vfs_fileattr_t *attributes);
    int (*fileattr_set)(vfs_superblock_t *sb, vfs_inode_t *inode,
                        const vfs_fileattr_t *attributes);
    /* Refresh mutable inode metadata by identity, including link count. */
    int (*getattr)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   vfs_inode_t *out);
    int (*settimes)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                    uint32_t atime, uint32_t mtime,
                    int set_atime, int set_mtime);
    int (*setattr)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   uint16_t mode, uint32_t uid, uint32_t gid,
                   uint32_t valid);
    /* Drain a bounded amount of dirty state without stalling a caller. */
    int (*writeback)(vfs_superblock_t *sb);
    /* Persist one inode for fsync/fdatasync without draining unrelated files. */
    int (*sync_inode)(vfs_superblock_t *sb, const vfs_inode_t *inode,
                      int data_only);
    /* Release up to page_count clean metadata-cache pages under pressure. */
    uint32_t (*reclaim_metadata)(vfs_superblock_t *sb,
                                 uint32_t page_count);
    /*
     * Complete terminal-only filesystem teardown after every dirty page and
     * ordinary filesystem cache has been flushed successfully.  Unlike sync(),
     * this callback may retire zero-link objects that still have live kernel
     * references because the machine will not return to userspace.
     */
    int (*shutdown)(vfs_superblock_t *sb);
} filesystem_ops_t;

#define VFS_SETATTR_MODE 0x00000001u
#define VFS_SETATTR_UID  0x00000002u
#define VFS_SETATTR_GID  0x00000004u
#define VFS_SETATTR_CTIME 0x00000008u

struct vfs_inode {
    uint32_t ino;
    /* Stable filesystem incarnation. Zero is valid for filesystems without one. */
    uint32_t generation;
    uint16_t mode;
    uint16_t metadata_flags;
    uint32_t uid;
    uint32_t gid;
    uint32_t nlink;
    uint8_t nlink_valid;
    uint8_t metadata_padding[3];
    uint32_t size;
    uint32_t atime;
    uint32_t mtime;
    uint32_t ctime;
    uint32_t fs_private[4];
    uint64_t rdev;
};

static inline uint32_t vfs_inode_link_count(const vfs_inode_t *inode) {
    return inode && inode->nlink_valid ? inode->nlink : 1u;
}

struct vfs_superblock {
    char fs_name[16];
    char dev_name[16];
    char mountpoint[VFS_PATH_MAX];
    vfs_inode_t root;
    filesystem_ops_t *ops;
    void *fs_private;
    uint32_t propagation;
    uint32_t peer_group;
    uint32_t master_group;
    void (*retain)(void *fs_private);
    void (*release)(void *fs_private);
    uint32_t mount_flags;
    uint64_t mount_id;
    uint64_t parent_mount_id;
    /*
     * Mount entries are namespace-local wrappers and may move when a mount
     * table is compacted.  instance identifies the stable underlying
     * filesystem object shared by namespace clones and bind mounts.
     */
    vfs_filesystem_instance_t *instance;
    uint32_t instance_generation;
    /* Path results can change without a local VFS namespace mutation. */
    uint32_t runtime_flags;
};

#define VFS_SUPERBLOCK_DYNAMIC_LOOKUP 0x00000001u

vfs_superblock_t *vfs_superblock_acquire(vfs_superblock_t *sb);
void vfs_superblock_release(vfs_superblock_t *sb);
vfs_superblock_t *vfs_superblock_stable(vfs_superblock_t *sb);
const vfs_superblock_t *vfs_superblock_stable_const(
    const vfs_superblock_t *sb);
const void *vfs_superblock_identity(const vfs_superblock_t *sb);
int vfs_filesystem_sync_all(void);
uint32_t vfs_filesystem_reclaim_metadata(uint32_t page_count);
int vfs_filesystem_shutdown_all(void);

static inline int vfs_superblock_same_filesystem(
    const vfs_superblock_t *left, const vfs_superblock_t *right) {
    return left && right &&
           vfs_superblock_identity(left) == vfs_superblock_identity(right);
}

static inline int vfs_inode_same_object(const vfs_superblock_t *left_sb,
                                        const vfs_inode_t *left,
                                        const vfs_superblock_t *right_sb,
                                        const vfs_inode_t *right) {
    return left && right &&
           vfs_superblock_same_filesystem(left_sb, right_sb) &&
           left->ino == right->ino &&
           left->generation == right->generation;
}

/*
 * Architecture VM implementations may retain filesystem inode references in
 * a file-page cache after the last pathname is removed.  Namespace policy
 * stays in the VFS; the backend is responsible only for locating and releasing
 * its cached aliases.  prepare_alias_release() must not perform I/O because it
 * runs before page-table teardown.  finish_alias_release() and shutdown() may
 * write back dirty pages after the architecture has released aliases.
 * reclaim_cached_inode() is optional and may retire one inactive cache
 * identity when a filesystem cannot create another live-inode reference.
 */
typedef struct vfs_inode_lifetime_backend_ops {
    void (*orphan_inode)(void *context, vfs_superblock_t *sb,
                         const vfs_inode_t *inode);
    void (*prepare_alias_release)(void *context, vfs_superblock_t *sb,
                                  const vfs_inode_t *inode);
    void (*finish_alias_release)(void *context);
    int (*reclaim_cached_inode)(void *context, vfs_superblock_t *sb);
    int (*shutdown)(void *context);
} vfs_inode_lifetime_backend_ops_t;

int vfs_inode_lifetime_backend_register(
    const vfs_inode_lifetime_backend_ops_t *ops, void *context);
void vfs_inode_lifetime_orphan_inode(vfs_superblock_t *sb,
                                     const vfs_inode_t *inode);
void vfs_inode_lifetime_prepare_alias_release(
    vfs_superblock_t *sb, const vfs_inode_t *inode);
void vfs_inode_lifetime_finish_alias_release(void);
int vfs_inode_lifetime_shutdown(void);

void vfs_init(void);
/* Initialize the mount/path-cache core without registering optional filesystems. */
void vfs_bootstrap_init(void);
int vfs_register(const char *name, int (*mount_fn)(const char *dev, const char *target));
int vfs_mount(const char *dev, const char *target, const char *fsname);
int vfs_mount_blockdev(block_device_t *dev, const char *target, const char *fsname);
int vfs_add_superblock(vfs_superblock_t *sb);
int vfs_mount_exists(const char *target, const char *fsname, const char *dev);
int vfs_set_mount_propagation(const char *target, uint32_t propagation,
                              int recursive);
int vfs_set_mount_attributes(const char *target, uint32_t set_flags,
                             uint32_t clear_flags, int recursive);
int vfs_bind_mount(const char *source, const char *target, int recursive);
int vfs_move_mount(const char *source, const char *target);
int vfs_remount(const char *target, uint32_t mount_flags);
int vfs_umount(const char *target, int detach);
int vfs_mount_namespace_clone(uint32_t parent_namespace,
                              uint32_t *namespace_out);
int vfs_mount_namespace_retain(uint32_t namespace_id);
/* Internal helper for filesystem retain callbacks invoked under the lock. */
int vfs_mount_namespace_retain_locked(uint32_t namespace_id);
void vfs_mount_namespace_release(uint32_t namespace_id);
int vfs_mount_namespace_activate(uint32_t namespace_id);
uint32_t vfs_mount_namespace_current(void);
int vfs_mount_namespace_exists(uint32_t namespace_id);
uint32_t vfs_mount_namespace_event_generation(uint32_t namespace_id);
int vfs_mount_namespace_metadata_set(uint32_t namespace_id,
                                     uint64_t list_id,
                                     uint32_t owner_user_namespace);
int vfs_mount_namespace_metadata_get(uint32_t namespace_id,
                                     uint64_t *list_id_out,
                                     uint32_t *owner_user_namespace_out);
int vfs_mount_namespace_list_next(uint64_t after_list_id,
                                  uint64_t *list_id_out,
                                  uint32_t *namespace_id_out,
                                  uint32_t *owner_user_namespace_out);
void vfs_mount_namespace_note_change(void);
typedef void (*vfs_mount_namespace_change_notifier_t)(uint32_t namespace_id);
void vfs_mount_namespace_set_change_notifier(
    vfs_mount_namespace_change_notifier_t notifier);
int vfs_pivot_root(const char *new_root, const char *put_old);
void vfs_path_cache_invalidate_all(void);
void vfs_path_cache_invalidate(const char *path);
void vfs_path_cache_seed(const char *path, const vfs_inode_t *inode, const vfs_superblock_t *sb);
int vfs_resolve(const char *path, vfs_inode_t *out_inode, vfs_superblock_t **out_sb, vfs_inode_t *out_parent, char *leaf);
int vfs_resolve_nofollow(const char *path, vfs_inode_t *out_inode, vfs_superblock_t **out_sb);
int vfs_resolve_canonical(const char *path, char *resolved,
                          uint32_t resolved_capacity,
                          vfs_inode_t *out_inode,
                          vfs_superblock_t **out_sb);
int vfs_resolve_canonical_rooted(const char *path, const char *root,
                                 char *resolved,
                                 uint32_t resolved_capacity,
                                 vfs_inode_t *out_inode,
                                 vfs_superblock_t **out_sb);
int vfs_resolve_cached(const char *path, vfs_inode_t *out_inode,
                       vfs_superblock_t **out_sb, int *negative);
/* Resolve an absolute path against a superblock before it is mounted. */
int vfs_resolve_superblock_path(vfs_superblock_t *sb, const char *path,
                                vfs_inode_t *out_inode);
int vfs_pread(const char *path, uint32_t off, void *out, uint32_t len);
int vfs_append_write(const char *path, vfs_superblock_t *sb,
                     vfs_inode_t *inode, const void *buf, uint32_t len,
                     uint32_t *offset_out);
int vfs_read_file(const char *path, char *out, uint32_t max);
int vfs_readlink(const char *path, char *out, uint32_t max);
int vfs_write_file(const char *path, const char *buf, uint32_t len);
int vfs_truncate(const char *path, uint32_t len);
int vfs_fallocate_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint32_t mode, uint64_t offset, uint64_t length);
int vfs_truncate_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                       uint32_t length);
int vfs_seek_data_hole(vfs_superblock_t *sb, const vfs_inode_t *inode,
                       uint64_t offset, int seek_hole,
                       uint64_t *result);
int vfs_map_extent(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   uint64_t offset, uint64_t length,
                   vfs_extent_t *extent);
#define VFS_READAHEAD_ERR_INVALID (-1)
#define VFS_READAHEAD_ERR_IO      (-2)
int vfs_read_inode_exact(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint64_t offset, void *buffer, uint32_t length);
int vfs_readahead_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint64_t offset, uint64_t length,
                        void *scratch, uint32_t scratch_capacity);
int vfs_encode_file_handle(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           uint32_t *handle_type, void *handle,
                           uint32_t *handle_bytes);
int vfs_decode_file_handle(vfs_superblock_t *sb, uint32_t handle_type,
                           const void *handle, uint32_t handle_bytes,
                           vfs_inode_t *out);
int vfs_inode_open(vfs_superblock_t *sb, const vfs_inode_t *inode);
void vfs_inode_close(vfs_superblock_t *sb, const vfs_inode_t *inode);
int vfs_inode_refresh(vfs_superblock_t *sb, vfs_inode_t *inode);
int vfs_inode_setxattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                       const char *name, const void *value, uint32_t size,
                       uint32_t flags);
int vfs_inode_getxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                       const char *name, void *value, uint32_t size);
int vfs_inode_listxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        char *list, uint32_t size);
int vfs_inode_removexattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                          const char *name);
int vfs_inode_fileattr_get(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           vfs_fileattr_t *attributes);
int vfs_inode_fileattr_set(vfs_superblock_t *sb, vfs_inode_t *inode,
                           const vfs_fileattr_t *attributes);
int vfs_mount_id_for_superblock(const vfs_superblock_t *sb,
                                uint64_t *mount_id_out);
vfs_superblock_t *vfs_superblock_for_mount_id(uint64_t mount_id);
uint32_t vfs_mount_flags_for_path(const char *path);
int vfs_mkdir(const char *path);
int vfs_mkdir_mode(const char *path, uint16_t mode);
int vfs_create_file(const char *path, uint16_t mode, vfs_inode_t *out_inode,
                    vfs_superblock_t **out_sb);
int vfs_touch(const char *path);
int vfs_symlink(const char *target, const char *path);
int vfs_link(const char *old_path, const char *new_path, int follow_source);
int vfs_link_inode(vfs_superblock_t *source_sb, const vfs_inode_t *source,
                   const char *new_path);
int vfs_create_special_node(const char *path, uint16_t mode);
int vfs_mknod(const char *path, uint16_t mode, uint64_t rdev);
int vfs_create_socket_node(const char *path, uint16_t mode);
int vfs_unlink(const char *path);
int vfs_rmdir(const char *path);
int vfs_rename(const char *old_path, const char *new_path);
void vfs_list(const char *path, int longf);
int vfs_readdir(const char *path, uint32_t idx, char *name_out, vfs_inode_t *inode_out);
int vfs_readdir_dirent(vfs_superblock_t *sb, vfs_inode_t *dir,
                       uint32_t idx, char *name_out,
                       vfs_inode_t *inode_out);
int vfs_getcwd(char *buffer, uint32_t capacity);
int vfs_chdir(const char *path);
int vfs_chroot(const char *path);
void vfs_list_mounts(void);
int vfs_statfs_path(const char *path, uint32_t *total_kb, uint32_t *used_kb);
int vfs_has_mounts(void);
int vfs_inode_get_block_device(const vfs_inode_t *inode, block_device_t **out);
int vfs_dev_ioctl(const char *path, uint32_t cmd, void *arg);
int vfs_dev_mmap(const char *path, uint64_t req_len, uint64_t off,
                 uint64_t selected_addr, uint64_t *addr_out, uint64_t *len_out);
int vfs_dev_pwrite(const char *path, const char *buf, uint32_t len, uint64_t off);
int vfs_mounts_snapshot(char *buf, uint32_t max);
int vfs_mountinfo_snapshot(char *buf, uint32_t max);
int vfs_mount_snapshot_read(int mountinfo, uint64_t offset,
                            void *buffer, uint32_t length);
int vfs_permission_check(const vfs_inode_t *inode, int access_mask);
int vfs_permission_check_as(const vfs_inode_t *inode, int access_mask,
                            uint32_t uid, uint32_t gid,
                            const struct linux_group_list *groups,
                            uint64_t capabilities);
int vfs_path_search_check(const char *path, char *scratch,
                          uint32_t scratch_capacity, int include_final);
int vfs_path_search_check_as(const char *path, char *scratch,
                             uint32_t scratch_capacity, int include_final,
                             uint32_t uid, uint32_t gid,
                             const struct linux_group_list *groups,
                             uint64_t capabilities);
int vfs_inode_chmod(vfs_superblock_t *sb, vfs_inode_t *inode, uint16_t mode);
int vfs_inode_setattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint16_t mode, uint32_t uid, uint32_t gid,
                      uint32_t valid);
int vfs_inode_chown(vfs_superblock_t *sb, vfs_inode_t *inode,
                    uint32_t uid, uint32_t gid, uint32_t valid);
int vfs_inode_utimens(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint32_t atime, uint32_t mtime,
                      int set_atime, int set_mtime);
int vfs_chmod(const char *path, uint16_t mode);
int vfs_chown(const char *path, uint32_t uid, uint32_t gid);
int vfs_lchown(const char *path, uint32_t uid, uint32_t gid);
int vfs_utimens(const char *path, uint32_t atime, uint32_t mtime, int set_atime, int set_mtime);
int vfs_sync_mutation_if_required(vfs_superblock_t *sb,
                                  int directory_mutation);
int vfs_sync_all(void);
int vfs_shutdown_sync_all(void);
int vfs_sync_inode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   int data_only);
void vfs_writeback_poll(void);

/*
 * Internal kernel helpers for stackable filesystems.  They use normal Linux
 * permission and path-resolution semantics through the public VFS entrypoints;
 * callers must not use them to bypass ABI-visible checks.
 */
int vfs_inode_is_dir(const vfs_inode_t *inode);

#endif
