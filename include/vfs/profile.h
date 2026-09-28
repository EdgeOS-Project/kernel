/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_VFS_PROFILE_H
#define EDGEOS_VFS_PROFILE_H
#include <stdint.h>

enum vfs_profile_metric {
    VFS_PROFILE_USER_STRING,
    VFS_PROFILE_METADATA,
    VFS_PROFILE_SEARCH,
    VFS_PROFILE_SEARCH_DIRECTORY,
    VFS_PROFILE_RESOLVE,
    VFS_PROFILE_MOUNT,
    VFS_PROFILE_PATH_CACHE,
    VFS_PROFILE_EXT4_LOOKUP,
    VFS_PROFILE_EXT4_INODE_CACHE,
    VFS_PROFILE_EXT4_READDIR,
    VFS_PROFILE_EXT4_BLOCK,
    VFS_PROFILE_EXT4_LOCK_WAIT,
    VFS_PROFILE_GETDENTS,
    VFS_PROFILE_DIRECTORY_SEED,
    VFS_PROFILE_SQUASHFS_LOOKUP,
    VFS_PROFILE_SQUASHFS_GETXATTR,
    VFS_PROFILE_PATH_CACHE_STORE,
    VFS_PROFILE_METRIC_COUNT
};
typedef struct {
    uint64_t generation, started_us, work, hits;
    uint32_t metric, sampled;
} vfs_profile_scope_t;

extern uint64_t vfs_profile_selected_task;
vfs_profile_scope_t vfs_profile_begin(uint32_t metric);
void vfs_profile_end(vfs_profile_scope_t *scope);
int vfs_profile_control(const void *command, uint32_t length);
int vfs_profile_render(char *buffer, uint32_t capacity);

/* Standalone hosted units omit instrumentation; dedicated integration units
 * define EDGE_VFS_PROFILE_IMPLEMENTATION and exercise the real hooks/runtime.
 * The freestanding kernel always links the profiling implementation. */
#if !defined(__STDC_HOSTED__) || __STDC_HOSTED__ == 0 || \
    defined(EDGE_VFS_PROFILE_IMPLEMENTATION)
#define EDGE_VFS_PROFILE_HOOKS 1
#else
#define EDGE_VFS_PROFILE_HOOKS 0
#endif
static inline vfs_profile_scope_t vfs_profile_scope_begin(uint32_t metric) {
    vfs_profile_scope_t empty = {0};
#if EDGE_VFS_PROFILE_HOOKS
    if (__atomic_load_n(&vfs_profile_selected_task, __ATOMIC_RELAXED))
        return vfs_profile_begin(metric);
#else
    (void)metric;
#endif
    return empty;
}
static inline void vfs_profile_scope_end(vfs_profile_scope_t *scope) {
#if EDGE_VFS_PROFILE_HOOKS
    if (scope->generation) vfs_profile_end(scope);
#else
    (void)scope;
#endif
}
/* Cleanup records early error returns as well as successful calls. */
#define VFS_PROFILE_SCOPE(metric) \
    vfs_profile_scope_t vfs_profile_scope \
    __attribute__((cleanup(vfs_profile_scope_end))) = \
        vfs_profile_scope_begin(metric)
#endif
