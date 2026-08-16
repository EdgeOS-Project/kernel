#ifndef SYS_SYSCALL_H
#define SYS_SYSCALL_H

#include <stdint.h>

#include "vfs/vfs.h"

#define EDGE_SYS_read    0
#define EDGE_SYS_write   1
#define EDGE_SYS_open    2
#define EDGE_SYS_close   3
#define EDGE_SYS_getpid  39
#define EDGE_SYS_fork    57
#define EDGE_SYS_execve  59
#define EDGE_SYS_exit    60
#define EDGE_SYS_wait    61
#define EDGE_SYS_brk     12
#define EDGE_SYS_spawn   400
#define EDGE_SYS_getcwd  401
#define EDGE_SYS_chdir   402
#define EDGE_SYS_ls      403
#define EDGE_SYS_mkdir   404
#define EDGE_SYS_touch   405
#define EDGE_SYS_unlink  406
#define EDGE_SYS_cat     407
#define EDGE_SYS_statfs  408
#define EDGE_SYS_meminfo 409
#define EDGE_SYS_mounts  410
#define EDGE_SYS_shutdown 411
#define EDGE_SYS_ps      412
#define EDGE_SYS_kill    413
#define EDGE_SYS_sleep   414
#define EDGE_SYS_dmesg   415
#define EDGE_SYS_stat    416
#define EDGE_SYS_mv      417
#define EDGE_SYS_writefile 418
#define EDGE_SYS_mount   419
#define EDGE_SYS_readfile 420

void syscall_init(void);
int syscall_runtime_init(void);
void syscall_release_process_fds(int pid);
void syscall_ensure_process_stdio(int pid);
void syscall_tty_irq_poll(void);
void syscall_network_poll(void);
void syscall_console_activate_vt(int vt);
void syscall_console_set_preferred_line(int line_id);
int syscall_console_default_line(void);
int syscall_console_active_vt_in_graphics(void);
int syscall_console_any_vt_in_graphics(void);
void syscall_console_keyboard_input_ready(void);
void syscall_rseq_prepare_user_return(uint64_t *instruction_pointer);

/*
 * Linux inotify event masks used by VFS mutation hooks.  Keep these values
 * ABI-identical to Linux UAPI because records are copied directly to Linux
 * userspace as struct inotify_event.
 */
#define EDGE_IN_ACCESS        0x00000001u
#define EDGE_IN_MODIFY        0x00000002u
#define EDGE_IN_ATTRIB        0x00000004u
#define EDGE_IN_CLOSE_WRITE   0x00000008u
#define EDGE_IN_CLOSE_NOWRITE 0x00000010u
#define EDGE_IN_OPEN          0x00000020u
#define EDGE_IN_MOVED_FROM    0x00000040u
#define EDGE_IN_MOVED_TO      0x00000080u
#define EDGE_IN_CREATE        0x00000100u
#define EDGE_IN_DELETE        0x00000200u
#define EDGE_IN_DELETE_SELF   0x00000400u
#define EDGE_IN_MOVE_SELF     0x00000800u
#define EDGE_IN_ALL_EVENTS    0x00000fffu
#define EDGE_IN_UNMOUNT       0x00002000u
#define EDGE_IN_Q_OVERFLOW    0x00004000u
#define EDGE_IN_IGNORED       0x00008000u
#define EDGE_IN_ONLYDIR       0x01000000u
#define EDGE_IN_DONT_FOLLOW   0x02000000u
#define EDGE_IN_EXCL_UNLINK   0x04000000u
#define EDGE_IN_MASK_CREATE   0x10000000u
#define EDGE_IN_MASK_ADD      0x20000000u
#define EDGE_IN_ISDIR         0x40000000u
#define EDGE_IN_ONESHOT       0x80000000u

void edge_inotify_notify_path(const char *path, uint32_t mask, const char *name);
void edge_inotify_notify_move(const char *old_path, const char *new_path);
void edge_mmap_file_cache_invalidate_path(const char *path);
void edge_mmap_file_cache_rename_path(const char *old_path, const char *new_path);
void edge_mmap_file_cache_overlay_read(vfs_superblock_t *superblock,
                                       const vfs_inode_t *inode,
                                       uint64_t offset, void *buffer,
                                       uint32_t length);
void edge_mmap_file_cache_apply_write(vfs_superblock_t *superblock,
                                      const vfs_inode_t *inode,
                                      uint64_t offset, const void *buffer,
                                      uint32_t length);
void edge_mmap_file_cache_resize(vfs_superblock_t *superblock,
                                 const vfs_inode_t *inode,
                                 uint64_t length);
void edge_mmap_file_cache_zero_range(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     uint64_t offset, uint64_t length);
void edge_mmap_file_cache_invalidate_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length);
int edge_mmap_file_cache_sync_inode(vfs_superblock_t *superblock,
                                    const vfs_inode_t *inode,
                                    int sync_filesystem);
int edge_mmap_file_cache_sync_superblock(vfs_superblock_t *superblock);

#endif
