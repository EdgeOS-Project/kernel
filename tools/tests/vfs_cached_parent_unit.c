/* SPDX-License-Identifier: MPL-2.0 */
/* Real path-cache invalidation and permission checks around parent reuse. */
#define main path_cache_test_main
#include "vfs_path_cache_unit.c"
#undef main
#define STDIO_H
#include "vfs/cached_parent.h"
#include "../../src/fs/permission.c"

static vfs_superblock_t mounts[2];
static uint32_t current_namespace = 1, cache_lookups, backend_lookups;
static uint32_t resolve_calls;
static uint16_t ancestor_mode = VFS_INODE_DIR | 0755;
int linux_group_list_contains(const linux_group_list_t *groups, uint32_t gid) {
    (void)groups; (void)gid;
    assert(!"No supplementary group lookup expected in this fixture");
    return 0;
}
int vfs_resolve(const char *path, vfs_inode_t *inode, vfs_superblock_t **sb,
                vfs_inode_t *parent, char *leaf) {
    (void)sb; (void)parent; (void)leaf;
    ++resolve_calls;
    *inode = (vfs_inode_t){.ino = 1, .mode = VFS_INODE_DIR | 0755};
    if (strcmp(path, "/usr") == 0) inode->mode = ancestor_mode;
    return 0;
}
int vfs_resolve_cached(const char *path, vfs_inode_t *inode,
                       vfs_superblock_t **sb, int *negative) {
    vfs_path_cache_result_t result;
    if (!vfs_path_cache_runtime_lookup(path, current_namespace, &result))
        return 0;
    if (negative) *negative = result.miss;
    if (inode) *inode = result.inode;
    if (sb) *sb = &mounts[result.superblock_index];
    return 1;
}
static int parent_lookup(const char *path, vfs_inode_t *inode,
                         vfs_superblock_t **sb, int *negative) {
    vfs_path_cache_result_t result;
    ++cache_lookups;
    if (!vfs_path_cache_runtime_lookup(path, current_namespace, &result)) return 0;
    *negative = result.miss;
    *inode = result.inode;
    *sb = result.superblock_index < 2 ? &mounts[result.superblock_index] : 0;
    return 1;
}
static int backend_lookup(vfs_superblock_t *sb, vfs_inode_t *dir,
                          const char *name, vfs_inode_t *out) {
    (void)sb;
    ++backend_lookups;
    if (dir->ino == 1 && strcmp(name, "usr") == 0)
        *out = (vfs_inode_t){.ino = 2, .mode = VFS_INODE_DIR | 0755};
    else if (dir->ino == 2 && strcmp(name, "bin") == 0)
        *out = (vfs_inode_t){.ino = 3, .mode = VFS_INODE_DIR | 0755};
    else if (dir->ino == 3 && strncmp(name, "tool", 4) == 0)
        *out = (vfs_inode_t){.ino = 4, .mode = VFS_INODE_FILE | 0755};
    else return -1;
    return 0;
}
static void walk(char *path, int require_full_walk) {
    const char *cursor = path + 1;
    vfs_inode_t current = mounts[0].root;
    (void)vfs_cached_parent_start(path, &mounts[0], require_full_walk,
                                  parent_lookup, &current, &cursor);
    while (*cursor) {
        char component[VFS_NAME_MAX];
        unsigned length = 0;
        while (*cursor && *cursor != '/') component[length++] = *cursor++;
        component[length] = 0;
        if (*cursor) ++cursor;
        assert(backend_lookup(&mounts[0], &current, component, &current) == 0);
    }
    assert(current.ino == 4);
}
int main(void) {
    vfs_path_cache_allocator_t allocator = {
        .allocate_pages = test_allocate_pages, .release_pages = test_release_pages
    };
    assert(vfs_path_cache_runtime_set_allocator(&allocator) == 0);
    strcpy(mounts[0].mountpoint, "/");
    strcpy(mounts[1].mountpoint, "/usr/bin");
    mounts[0].root = (vfs_inode_t){.ino = 1, .mode = VFS_INODE_DIR | 0755};
    vfs_inode_t cached = {.ino = 3, .mode = VFS_INODE_DIR | 0755};
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0);
    for (unsigned i = 0; i < 1000; ++i) {
        char path[64];
        snprintf(path, sizeof(path), "/usr/bin/tool%u", i);
        walk(path, 0);
    }
    assert(backend_lookups == 1000 && cache_lookups == 1000);
    backend_lookups = 0;
    for (unsigned i = 0; i < 1000; ++i) {
        char path[64];
        snprintf(path, sizeof(path), "/usr/bin/tool%u", i);
        walk(path, 1);
    }
    assert(backend_lookups == 3000);
    char path[] = "/usr/bin/tool";
    const char *remaining = path + 1;
    vfs_inode_t result = {.ino = 123};
#define MISS() do { \
    assert(!vfs_cached_parent_start(path, &mounts[0], 0, parent_lookup, &result, &remaining)); \
    assert(strcmp(path, "/usr/bin/tool") == 0 && result.ino == 123 && remaining == path + 1); \
} while (0)
    current_namespace = 2; MISS(); current_namespace = 1;
    mounts[0].runtime_flags = VFS_SUPERBLOCK_DYNAMIC_LOOKUP; MISS();
    mounts[0].runtime_flags = 0;
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 1); MISS();
    vfs_path_cache_runtime_store("/usr/bin", 1, 1, 0, 0); MISS();
    cached.mode = VFS_INODE_LNK | 0777;
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0); MISS();
    cached.mode = VFS_INODE_FILE | 0755;
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0); MISS();
    cached.mode = VFS_INODE_DIR | 0755;
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0);
    vfs_path_cache_runtime_invalidate_subtree("/usr"); MISS();
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0);
    vfs_path_cache_runtime_invalidate_namespace(1); MISS();
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0);
    assert(vfs_path_cache_runtime_reclaim(1) == 1); MISS();
    vfs_path_cache_runtime_store("/usr/bin", 1, 0, &cached, 0);
    char scratch[VFS_PATH_MAX];
    assert(vfs_path_search_check_as(path, scratch, sizeof(scratch), 0,
                                    1000, 1000, 0, 0) == 0);
    ancestor_mode = VFS_INODE_DIR | 0600;
    assert(vfs_path_search_check_as(path, scratch, sizeof(scratch), 0,
                                    1000, 1000, 0, 0) == -EDGE_LINUX_EACCES);
    ancestor_mode = VFS_INODE_DIR | 0755;
    cached = (vfs_inode_t){.ino = 2, .mode = ancestor_mode};
    vfs_path_cache_runtime_store("/usr", 1, 0, &cached, 0);
    resolve_calls = 0;
    assert(vfs_path_search_check_as(path, scratch, sizeof(scratch), 0,
                                    1000, 1000, 0, 0) == 0);
    assert(resolve_calls == 1);
    vfs_path_cache_runtime_store("/usr", 1, 1, 0, 0);
    assert(vfs_path_search_check_as(path, scratch, sizeof(scratch), 0,
                                    1000, 1000, 0, 0) == -EDGE_LINUX_ENOENT);
    vfs_path_cache_runtime_invalidate_subtree("/usr");
    strcpy(mounts[0].mountpoint, "/usr/bin"); MISS();
    vfs_path_cache_runtime_reset();
    puts("vfs_cached_parent_unit: PASS (3000 -> 1000 backend calls; no authorization cached)");
    return 0;
}
