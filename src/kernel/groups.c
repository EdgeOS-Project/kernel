/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux supplementary-group storage.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/groups.h"
#include "kernel/process_runtime.h"
#include "string.h"

int kernel_linux_group_page_allocate(linux_group_page_t *page) {
    int status;

    if (!page) return -1;
    page->values = 0;
    page->token = 0;
    status = edge_process_runtime_group_page_allocate(page);
    if (status < 0 || !page->values) {
        if (page->values)
            edge_process_runtime_group_page_release(page);
        if (status >= 0) status = -1;
        page->values = 0;
        page->token = 0;
    }
    return status;
}

int kernel_linux_group_page_retain(const linux_group_page_t *page) {
    if (!page || !page->values) return -1;
    return edge_process_runtime_group_page_retain(page);
}

void kernel_linux_group_page_release(const linux_group_page_t *page) {
    if (!page || !page->values) return;
    edge_process_runtime_group_page_release(page);
}

void linux_group_list_init(linux_group_list_t *groups) {
    if (!groups) return;
    memset(groups, 0, sizeof(*groups));
}

void linux_group_list_release(linux_group_list_t *groups) {
    uint32_t index;
    if (!groups) return;
    if (groups->page_count > EDGE_LINUX_GROUP_PAGE_MAX)
        groups->page_count = EDGE_LINUX_GROUP_PAGE_MAX;
    for (index = 0; index < groups->page_count; ++index) {
        if (groups->pages[index].values)
            kernel_linux_group_page_release(&groups->pages[index]);
    }
    linux_group_list_init(groups);
}

int linux_group_list_allocate(linux_group_list_t *groups, uint32_t count) {
    uint32_t index;
    uint32_t page_count;
    if (!groups || count > EDGE_LINUX_NGROUPS_MAX) return -1;
    linux_group_list_init(groups);
    page_count = count ?
        (count + EDGE_LINUX_GROUPS_PER_PAGE - 1u) /
            EDGE_LINUX_GROUPS_PER_PAGE : 0;
    groups->count = count;
    for (index = 0; index < page_count; ++index) {
        if (kernel_linux_group_page_allocate(&groups->pages[index]) < 0 ||
            !groups->pages[index].values) {
            groups->page_count = index;
            linux_group_list_release(groups);
            return -1;
        }
        memset(groups->pages[index].values, 0,
               EDGE_LINUX_GROUP_PAGE_SIZE);
        groups->page_count = index + 1u;
    }
    return 0;
}

int linux_group_list_retain(linux_group_list_t *destination,
                            const linux_group_list_t *source) {
    uint32_t index;
    uint32_t expected_pages;
    if (!source) return -1;
    expected_pages = source->count ?
        (source->count + EDGE_LINUX_GROUPS_PER_PAGE - 1u) /
            EDGE_LINUX_GROUPS_PER_PAGE : 0;
    if (!destination ||
        source->count > EDGE_LINUX_NGROUPS_MAX ||
        source->page_count != expected_pages ||
        source->page_count > EDGE_LINUX_GROUP_PAGE_MAX)
        return -1;
    linux_group_list_init(destination);
    destination->count = source->count;
    for (index = 0; index < source->page_count; ++index) {
        if (!source->pages[index].values ||
            kernel_linux_group_page_retain(&source->pages[index]) < 0) {
            linux_group_list_release(destination);
            return -1;
        }
        destination->pages[index] = source->pages[index];
        destination->page_count = index + 1u;
    }
    return 0;
}

uint32_t *linux_group_list_page_values(linux_group_list_t *groups,
                                       uint32_t page_index) {
    if (!groups || page_index >= groups->page_count ||
        page_index >= EDGE_LINUX_GROUP_PAGE_MAX)
        return 0;
    return groups->pages[page_index].values;
}

const uint32_t *linux_group_list_const_page_values(
    const linux_group_list_t *groups, uint32_t page_index) {
    if (!groups || page_index >= groups->page_count ||
        page_index >= EDGE_LINUX_GROUP_PAGE_MAX)
        return 0;
    return groups->pages[page_index].values;
}

uint32_t linux_group_list_get(const linux_group_list_t *groups,
                              uint32_t index) {
    const uint32_t *values;
    if (!groups || index >= groups->count) return UINT32_MAX;
    values = linux_group_list_const_page_values(
        groups, index / EDGE_LINUX_GROUPS_PER_PAGE);
    return values ? values[index % EDGE_LINUX_GROUPS_PER_PAGE] : UINT32_MAX;
}

int linux_group_list_set(linux_group_list_t *groups, uint32_t index,
                         uint32_t gid) {
    uint32_t *values;
    if (!groups || index >= groups->count) return -1;
    values = linux_group_list_page_values(
        groups, index / EDGE_LINUX_GROUPS_PER_PAGE);
    if (!values) return -1;
    values[index % EDGE_LINUX_GROUPS_PER_PAGE] = gid;
    return 0;
}

int linux_group_list_contains(const linux_group_list_t *groups,
                              uint32_t gid) {
    uint32_t first;
    uint32_t count;
    if (!groups) return 0;
    first = 0;
    count = groups->count;
    while (count) {
        uint32_t step = count / 2u;
        uint32_t index = first + step;
        uint32_t value = linux_group_list_get(groups, index);
        if (value < gid) {
            first = index + 1u;
            count -= step + 1u;
        } else {
            count = step;
        }
    }
    return first < groups->count &&
        linux_group_list_get(groups, first) == gid;
}

static void linux_group_list_swap(linux_group_list_t *groups,
                                  uint32_t left, uint32_t right) {
    uint32_t left_value;
    uint32_t right_value;
    if (left == right) return;
    left_value = linux_group_list_get(groups, left);
    right_value = linux_group_list_get(groups, right);
    (void)linux_group_list_set(groups, left, right_value);
    (void)linux_group_list_set(groups, right, left_value);
}

static void linux_group_list_sift_down(linux_group_list_t *groups,
                                       uint32_t root, uint32_t end) {
    if (!end) return;
    while (root <= (end - 1u) / 2u) {
        uint32_t child = root * 2u + 1u;
        uint32_t swap_index = root;
        if (linux_group_list_get(groups, swap_index) <
            linux_group_list_get(groups, child))
            swap_index = child;
        if (child < end &&
            linux_group_list_get(groups, swap_index) <
            linux_group_list_get(groups, child + 1u))
            swap_index = child + 1u;
        if (swap_index == root) return;
        linux_group_list_swap(groups, root, swap_index);
        root = swap_index;
    }
}

void linux_group_list_sort(linux_group_list_t *groups) {
    uint32_t start;
    uint32_t end;
    if (!groups || groups->count < 2u) return;
    start = (groups->count - 2u) / 2u + 1u;
    while (start) {
        --start;
        linux_group_list_sift_down(groups, start, groups->count - 1u);
    }
    end = groups->count - 1u;
    while (end) {
        linux_group_list_swap(groups, 0, end);
        --end;
        linux_group_list_sift_down(groups, 0, end);
    }
}

int kernel_process_groups_snapshot(int32_t tid, linux_group_list_t *groups) {
    if (!groups) return -1;
    linux_group_list_init(groups);
    if (tid <= 0) return -1;
    return kernel_arch_process_groups_snapshot(tid, groups);
}

int kernel_current_groups_snapshot(linux_group_list_t *groups) {
    kernel_linux_identity_t identity;
    if (!groups || kernel_current_linux_identity(&identity) < 0) return -1;
    return kernel_process_groups_snapshot(identity.global_tid, groups);
}

int kernel_current_groups_replace(linux_group_list_t *groups) {
    if (!groups) return -1;
    return kernel_arch_current_groups_commit(groups);
}

int kernel_current_in_group(uint32_t gid) {
    kernel_linux_identity_t identity;
    linux_group_list_t groups;
    int found;

    if (kernel_current_linux_identity(&identity) < 0) return 0;
    if (identity.fsgid == gid) return 1;
    linux_group_list_init(&groups);
    if (kernel_process_groups_snapshot(identity.global_tid, &groups) < 0)
        return 0;
    found = linux_group_list_contains(&groups, gid);
    linux_group_list_release(&groups);
    return found;
}
