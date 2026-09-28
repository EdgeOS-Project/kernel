/* SPDX-License-Identifier: MPL-2.0 */
/* Full production resolver, path cache, and rooted path joining regression. */
#include <assert.h>
#include <stdlib.h>
extern int puts(const char *text);
#include <string.h>
#define EDGEOS_HOST_TEST 1
#define STRING_H
#define STDIO_H
#ifndef VFS_TEST_SOURCE
#define VFS_TEST_SOURCE "../../src/vfs/vfs.c"
#endif
#include VFS_TEST_SOURCE
#include "../../src/vfs/path_cache.c"
#include "../../src/kernel/fs_context.c"

static vfs_mount_table_t table;
static vfs_superblock_t mounts[96];
static unsigned lookups;
static unsigned mount_iterations;
static unsigned mount_id_lookups;
static const char *link_target = "libcrypt.so.1.1.0";
void *arch_vm_alloc_pages(uint64_t count) { return calloc(count, 4096); }
void arch_vm_free_page(void *p) { free(p); }
uint32_t vfs_mount_namespace_current(void) { return 1; }
int vfs_mount_namespace_uses_initial_root(void) { return 0; }
vfs_mount_table_t *vfs_mount_namespace_active_table(void) { return &table; }
vfs_superblock_t *vfs_mount_table_at(vfs_mount_table_t *t, uint32_t i) {
    return i < (unsigned)t->mount_count ? &mounts[i] : NULL;
}
void vfs_mount_table_iterator_begin(vfs_mount_table_t *t, vfs_mount_table_iterator_t *i) {
    memset(i, 0, sizeof(*i)); i->table = t;
}
vfs_superblock_t *vfs_mount_table_iterator_next(vfs_mount_table_iterator_t *i, uint32_t *index) {
    if (i->index >= (unsigned)i->table->mount_count) return NULL;
    if (index) *index = i->index;
    ++mount_iterations;
    return vfs_mount_table_at(i->table, i->index++);
}
vfs_superblock_t *vfs_mount_table_find_id(vfs_mount_table_t *t,
                                          uint64_t mount_id) {
    ++mount_id_lookups;
    for (uint32_t index = 0; index < (uint32_t)t->mount_count; ++index)
        if (mounts[index].mount_id == mount_id) return &mounts[index];
    return NULL;
}
int vfs_mount_table_lookup_cache_get(vfs_mount_table_t *t, const char *path, uint32_t *index) {
    (void)t; (void)path; (void)index; return 0;
}
void vfs_mount_table_lookup_cache_store(vfs_mount_table_t *t, const char *path, uint32_t index) {
    (void)t; (void)path; (void)index;
}
static int lookup(vfs_superblock_t *sb, vfs_inode_t *parent,
                  const char *name, vfs_inode_t *out) {
    (void)sb; ++lookups;
    uint32_t ino = 0; uint16_t mode = VFS_INODE_DIR | 0755;
    if (parent->ino == 1 && !strcmp(name, "lib")) ino = 2;
    if (parent->ino == 2 && !strcmp(name, "x86_64-linux-gnu")) ino = 3;
    if (parent->ino == 2 && !strcmp(name, "alias")) { ino = 6; mode = VFS_INODE_LNK | 0777; }
    if (parent->ino == 3 && !strcmp(name, "libcrypt.so.1")) { ino = 4; mode = VFS_INODE_LNK | 0777; }
    if (parent->ino == 3 && !strcmp(name, "libcrypt.so.1.1.0")) { ino = 5; mode = VFS_INODE_FILE | 0644; }
    if (!ino) return -1;
    *out = (vfs_inode_t){.ino = ino, .mode = mode}; return 0;
}
static int readlink_fixture(vfs_superblock_t *sb, vfs_inode_t *in, char *out, uint32_t cap) {
    (void)sb; assert(in->ino == 4 || in->ino == 6);
    const char *target = in->ino == 6 ? "x86_64-linux-gnu" : link_target;
    assert(strlen(target) < cap);
    strcpy(out, target); return strlen(target);
}
static filesystem_ops_t ops = {.lookup = lookup, .readlink = readlink_fixture};
static void resolve_case(vfs_superblock_t *sb, int warm, int full,
                         const char *target) {
    vfs_path_cache_runtime_invalidate_namespace(1);
    link_target = target;
    vfs_inode_t inode, parent;
    vfs_superblock_t *found;
    if (warm) {
        assert(vfs_resolve("/lib/x86_64-linux-gnu", &inode, &found, NULL, NULL) == 0);
        assert(inode.ino == 3 && found == sb);
    }
    lookups = 0;
    assert(vfs_resolve("/lib/x86_64-linux-gnu/libcrypt.so.1", &inode, &found,
                       full ? &parent : NULL, NULL) == 0);
    assert(inode.ino == 5 && found == sb);
    if (warm && !full) assert(lookups == 2);
    if (!warm || full) assert(lookups > 2);
    if (full) assert(parent.ino == 3);
}
int main(void) {
    table.mount_count = 1;
    vfs_superblock_t *root = &mounts[0];
    strcpy(root->mountpoint, "/"); root->root = (vfs_inode_t){.ino = 1, .mode = VFS_INODE_DIR | 0755};
    root->ops = &ops; root->mount_id = 1; table.root_mount_id = 1;
    for (int nested = 0; nested < 2; ++nested) {
        vfs_superblock_t *sb = root;
        if (nested) {
            table.mount_count = 2; sb = &mounts[1];
            *sb = *root; strcpy(sb->mountpoint, "/lib"); sb->root.ino = 2;
            sb->mount_id = 2; sb->parent_mount_id = 1;
            root->latest_child_mount_id = 2;
        }
        resolve_case(sb, 1, 0, "libcrypt.so.1.1.0");
        resolve_case(sb, 0, 0, "libcrypt.so.1.1.0");
        resolve_case(sb, 1, 1, "libcrypt.so.1.1.0");
        resolve_case(sb, 1, 0, "/lib/x86_64-linux-gnu/libcrypt.so.1.1.0");
        resolve_case(sb, 1, 0, "../x86_64-linux-gnu/libcrypt.so.1.1.0");
        vfs_inode_t inode; vfs_superblock_t *found; char canonical[VFS_PATH_MAX];
        link_target = "libcrypt.so.1.1.0";
        assert(vfs_resolve_nofollow("/lib/x86_64-linux-gnu/libcrypt.so.1", &inode, &found) == 0);
        assert(inode.ino == 4 && found == sb);
        assert(vfs_resolve_canonical("/lib/alias/libcrypt.so.1", canonical,
                                     sizeof(canonical), &inode, &found) == 0);
        assert(inode.ino == 5 && found == sb);
        assert(!strcmp(canonical, "/lib/x86_64-linux-gnu/libcrypt.so.1.1.0"));
    }
    vfs_path_cache_runtime_invalidate_namespace(1);
    vfs_inode_t cached_inode;
    vfs_superblock_t *cached_mount;
    int negative = 0;
    assert(vfs_resolve("/lib/x86_64-linux-gnu", &cached_inode,
                       &cached_mount, NULL, NULL) == 0);
    mount_iterations = 0;
    assert(vfs_resolve_cached("/lib/x86_64-linux-gnu", &cached_inode,
                              &cached_mount, &negative) == 1);
    assert(!negative && cached_inode.ino == 3 && cached_mount == &mounts[1]);
    assert(mount_iterations == 0);
    mounts[1].runtime_flags = VFS_SUPERBLOCK_DYNAMIC_LOOKUP;
    assert(vfs_resolve_cached("/lib/x86_64-linux-gnu", &cached_inode,
                              &cached_mount, &negative) == 0);
    mounts[1].runtime_flags = 0;
    vfs_path_cache_runtime_store("/lib/missing", 1, 1, NULL, 0);
    mounts[1].runtime_flags = VFS_SUPERBLOCK_DYNAMIC_LOOKUP;
    assert(vfs_resolve_cached("/lib/missing", &cached_inode,
                              &cached_mount, &negative) == 0);
    mounts[1].runtime_flags = 0;
    memset(mounts, 0, sizeof(mounts));
    table.mount_count = 65;
    table.root_mount_id = 1;
    root = &mounts[0];
    strcpy(root->mountpoint, "/");
    root->mount_id = 1;
    for (uint32_t index = 1; index < 65u; ++index) {
        vfs_superblock_t *mount = &mounts[index];
        mount->mount_id = index + 1u;
        mount->parent_mount_id = index;
        mounts[index - 1u].latest_child_mount_id = mount->mount_id;
        if (index == 1u)
            strcpy(mount->mountpoint, "/m");
        else {
            strcpy(mount->mountpoint, mounts[index - 1u].mountpoint);
            strcat(mount->mountpoint, "/m");
        }
    }
    mount_iterations = 0;
    mount_id_lookups = 0;
    assert(vfs_find_mount(mounts[64].mountpoint) == &mounts[64]);
    assert(mount_id_lookups == 65u);
    assert(mount_iterations == 65u);

    /* A stale link must fall back to the authoritative parent relation. */
    mounts[32].latest_child_mount_id = UINT64_MAX;
    mount_iterations = 0;
    assert(vfs_find_mount(mounts[64].mountpoint) == &mounts[64]);
    assert(mount_iterations > 65u);
    vfs_path_cache_runtime_reset();
    puts("vfs_resolver_symlink_unit: PASS (full resolver, warm/cold parent, relative/absolute targets, nested mount, nofollow, canonical)");
    return 0;
}
/* Peripheral models are absent; the tested paths never enter their namespaces. */
int alsa_available(void) { return 0; }
int alsa_capture_available(void) { return 0; }
int alsa_path_kind(const char *path) { (void)path; return 0; }
uint32_t alsa_dev_minor_from_kind(int kind) { (void)kind; return 0; }
uint32_t alsa_inode_from_kind(int kind) { (void)kind; return 0; }
int block_sysfs_path_kind(const char *path) { (void)path; return 0; }
int edge_drm_path_is_render(const char *path) { (void)path; return 0; }
int input_device_present(uint32_t device) { (void)device; return 0; }
int kernel_arch_serial_console_device(kernel_console_device_t *device) { (void)device; return 0; }
int kernel_arch_current_fs_snapshot(char *cwd, uint32_t cc, char *root, uint32_t rc) {
    assert(cc > 1 && rc > 1); strcpy(cwd, "/"); strcpy(root, "/"); return 0;
}
