/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent dynamic mount-table growth test. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs/mount_namespace.h"

void *arch_vm_alloc_pages(uint32_t page_count) {
    return calloc(page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    (void)page;
}

uint32_t scheduler_cpu_id(void) {
    return 0;
}

int main(void) {
    vfs_mount_table_t table;
    vfs_superblock_t *stable_inline;
    vfs_superblock_t *stable_overflow;
    vfs_superblock_t *instance_sources;
    vfs_superblock_t **instance_handles;
    uint32_t namespace_ids[130];
    uint32_t workspace_pages = 0;
    char *workspace;

    memset(&table, 0, sizeof(table));
    assert(vfs_mount_table_reserve(&table, 130u) == 0);
    for (uint32_t index = 0; index < 130u; ++index) {
        vfs_superblock_t *mount = vfs_mount_table_at(&table, index);
        assert(mount != 0);
        mount->mount_id = (uint64_t)index + 1u;
    }
    table.mount_count = 130;
    stable_inline = vfs_mount_table_at(&table, 2u);
    stable_overflow = vfs_mount_table_at(&table, 67u);
    assert(stable_inline != 0 && stable_overflow != 0);
    assert(vfs_mount_table_reserve(&table, 300u) == 0);
    assert(vfs_mount_table_at(&table, 2u) == stable_inline);
    assert(vfs_mount_table_at(&table, 67u) == stable_overflow);
    assert(vfs_mount_table_at(&table, 129u)->mount_id == 130u);
    assert(vfs_mount_table_at_const(&table, 300u) == 0);

    workspace = vfs_mount_path_workspace_allocate(
        130u, &workspace_pages);
    assert(workspace != 0 && workspace_pages >= 130u);
    memcpy(workspace + 129u * VFS_PATH_MAX, "/last", 6u);
    assert(strcmp(workspace + 129u * VFS_PATH_MAX, "/last") == 0);
    vfs_mount_path_workspace_release(workspace, workspace_pages);

    vfs_mount_namespace_bootstrap();
    for (uint32_t index = 0; index < 130u; ++index) {
        assert(vfs_mount_namespace_clone(0u, &namespace_ids[index]) == 0);
        assert(namespace_ids[index] == index + 1u);
        assert(vfs_mount_namespace_exists(namespace_ids[index]));
    }
    assert(vfs_mount_namespace_activate(namespace_ids[129]) == 0);
    assert(vfs_mount_namespace_current() == namespace_ids[129]);
    assert(vfs_mount_namespace_active_table() != 0);
    for (uint32_t index = 0; index < 130u; ++index) {
        vfs_mount_namespace_release(namespace_ids[index]);
        assert(!vfs_mount_namespace_exists(namespace_ids[index]));
    }
    assert(vfs_mount_namespace_active_table() != 0);

    instance_sources = calloc(300u, sizeof(*instance_sources));
    instance_handles = calloc(300u, sizeof(*instance_handles));
    assert(instance_sources != 0 && instance_handles != 0);
    for (uint32_t index = 0; index < 300u; ++index) {
        instance_sources[index].fs_private =
            (void *)(uintptr_t)(index + 1u);
        instance_handles[index] =
            vfs_superblock_acquire(&instance_sources[index]);
        assert(instance_handles[index] != 0);
        assert(instance_handles[index]->fs_private ==
               instance_sources[index].fs_private);
    }
    for (uint32_t index = 0; index < 300u; ++index)
        vfs_superblock_release(instance_handles[index]);
    free(instance_handles);
    free(instance_sources);

    puts("vfs_mount_table_unit: PASS");
    return 0;
}
