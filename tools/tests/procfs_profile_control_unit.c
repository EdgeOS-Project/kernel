/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise procfs control-file O_TRUNC through the shared VFS truncate hook. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define STDIO_H
#define STRING_H
#define EDGEOS_HOST_TEST 1
#define EDGE_VFS_PROFILE_IMPLEMENTATION
#ifndef PROCFS_TEST_SOURCE
#define PROCFS_TEST_SOURCE "../../src/fs/procfs.c"
#endif
#include PROCFS_TEST_SOURCE
#include "../../src/vfs/profile.c"
#include "../../src/vfs/truncate.c"

uint64_t arch_cpu_current_task(void) { return 7; }
int kernel_current_pid(void) { return 42; }
uint64_t boottime_monotonic_us(void) { return 1000; }
static kernel_proc_task_view_t proc_task_view;
int kernel_proc_task_view_get(int32_t pid, kernel_proc_task_view_t *view) {
    if (pid != proc_task_view.tid || !view) return -1;
    *view = proc_task_view;
    return 0;
}
static unsigned invalidations;
void vfs_path_cache_invalidate_all(void) { ++invalidations; }
void vfs_readahead_forget_inode(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    (void)sb; (void)inode;
}
void vfs_page_writeback_forget_range(vfs_superblock_t *sb,
    const vfs_inode_t *inode, uint64_t offset, uint64_t length) {
    (void)sb; (void)inode; (void)offset; (void)length;
}
int main(void) {
    filesystem_ops_t ops = {.truncate = proc_truncate};
    vfs_superblock_t sb = {.ops = &ops};
    vfs_inode_t inode;
    proc_task_view.tid = 123;
    proc_task_view.euid = 1000;
    proc_task_view.egid = 1001;
    proc_task_view.dumpable = 1;
    inode_set_pid(&inode, PROC_PID_DIR, 123, VFS_INODE_DIR | 0555);
    assert(inode.uid == 1000 && inode.gid == 1001);
    proc_task_view.dumpable = 0;
    inode_set_pid(&inode, PROC_THREAD_DIR, 123, VFS_INODE_DIR | 0555);
    assert(inode.uid == 0 && inode.gid == 0);
    inode_set(&inode, PROC_VFS_PROFILE, VFS_INODE_FILE | 0600);
    assert(vfs_profile_control("counts", 6) == 0);
    vfs_profile_scope_t scope = vfs_profile_begin(VFS_PROFILE_MOUNT);
    scope.work = 99;
    vfs_profile_end(&scope);
    uint64_t generation = profile.generation;
    assert(vfs_truncate_inode(&sb, &inode, 0) == 0);
    assert(invalidations == 1);
    assert(vfs_profile_selected_task == 7 && profile.generation == generation);
    assert(profile.rows[VFS_PROFILE_MOUNT].work == 99);
    assert(proc_truncate(&sb, &inode, 0) == 0);
    assert(vfs_truncate_inode(&sb, &inode, 1) == VFS_TRUNCATE_ERR_IO);
    assert(vfs_profile_selected_task == 7 && profile.generation == generation);
    assert(vfs_profile_control("stop", 4) == 0);
    assert(!vfs_profile_selected_task && profile.rows[VFS_PROFILE_MOUNT].work == 99);
    inode_set(&inode, PROC_VERSION, VFS_INODE_FILE | 0444);
    assert(vfs_truncate_inode(&sb, &inode, 0) == VFS_TRUNCATE_ERR_IO);
    inode_set(&inode, PROC_HOSTNAME, VFS_INODE_FILE | 0644);
    assert(vfs_truncate_inode(&sb, &inode, 0) == 0);
    assert(proc_truncate(&sb, 0, 0) < 0);
    puts("procfs_profile_control_unit: PASS");
    return 0;
}
