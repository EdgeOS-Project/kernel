/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STRING_H
#include "../../src/fs/tmpfs.c"

static int fail_allocation;
static uint64_t allocated_pages;
static uint64_t allocation_limit_pages = UINT64_MAX;
static uint64_t largest_allocation_pages;

void *arch_vm_alloc_pages(uint64_t count) {
    if (count > largest_allocation_pages) largest_allocation_pages = count;
    if (fail_allocation || count > allocation_limit_pages) return 0;
    void *memory = calloc(count, TMPFS_BLOCK_SIZE);
    assert(memory);
    allocated_pages += count;
    return memory;
}

void *arch_vm_alloc_page(void) {
    return arch_vm_alloc_pages(1u);
}

void arch_vm_free_page(void *page) {
    /* This test retains slab addresses until its final cleanup. */
    (void)page;
    assert(allocated_pages > 0);
    --allocated_pages;
}

int main(void) {
    tmpfs_node_t standalone;
    char *standalone_name;
    assert(sizeof(g_tmpfs_states) < 1024u * 1024u);
    assert(TMPFS_INLINE_NODES == 512);
    assert(sizeof(tmpfs_node_t) <= 96u);
    assert(allocated_pages == 0);
    fail_allocation = 1;
    assert(tmpfs_dynamic_mount_allocate() == 0);
    assert(g_tmpfs_dynamic_mounts == 0 && allocated_pages == 0);
    fail_allocation = 0;
    tmpfs_dynamic_mount_t *first = tmpfs_dynamic_mount_allocate();
    tmpfs_dynamic_mount_t *second = tmpfs_dynamic_mount_allocate();
    assert(first && second && first != second);
    assert(second->next == first);
    assert(tmpfs_superblock_for_state(&first->state) == &first->superblock);
    assert(tmpfs_superblock_for_state(&second->state) == &second->superblock);
    assert(tmpfs_allocate_node_storage(&first->state, 512) == 0);
    assert(first->state.max_nodes == 512);
    assert(first->state.nodes == first->state.inline_nodes);
    assert(tmpfs_allocate_node_storage(&second->state, 1024) == 0);
    assert(second->state.max_nodes == 1024);
    assert(second->state.node_storage_pages > 0);
    assert(second->state.node_storage_pages < 32u);
    void *nodes = second->state.nodes;
    uint64_t before_release = allocated_pages;
    uint32_t node_pages = second->state.node_storage_pages;
    tmpfs_release_node_storage(&second->state);
    assert(allocated_pages == before_release - node_pages);
    assert(!second->state.used && !second->state.nodes);
    free(nodes);
    allocation_limit_pages = 128u;
    assert(tmpfs_allocate_node_storage(&second->state, TMPFS_MAX_NODES) == 0);
    assert(second->state.max_nodes == TMPFS_EAGER_NODES);
    assert(second->state.node_storage_pages <= allocation_limit_pages);
    assert(largest_allocation_pages <= 128u);
    assert(tmpfs_superblock_for_state(&second->state) == &second->superblock);

    memset(&standalone, 0, sizeof(standalone));
    assert(tmpfs_set_node_name(&standalone, "firefox-writable-mimic") == 0);
    assert(strcmp(standalone.name, "firefox-writable-mimic") == 0);
    standalone_name = standalone.name;
    tmpfs_release_node_name(&standalone);
    assert(standalone.name == 0);
    free(standalone_name);

    free(second->state.nodes);
    free(second);
    free(first);
    puts("tmpfs_mount_backing_unit: PASS");
    return 0;
}
