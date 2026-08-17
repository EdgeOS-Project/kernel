/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux supplementary-group storage.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_GROUPS_H
#define EDGEOS_KERNEL_GROUPS_H

#include <stdint.h>

#define EDGE_LINUX_NGROUPS_MAX 65536u
#define EDGE_LINUX_GROUP_PAGE_SIZE 4096u
#define EDGE_LINUX_GROUPS_PER_PAGE \
    (EDGE_LINUX_GROUP_PAGE_SIZE / sizeof(uint32_t))
#define EDGE_LINUX_GROUP_PAGE_MAX \
    (EDGE_LINUX_NGROUPS_MAX / EDGE_LINUX_GROUPS_PER_PAGE)

typedef struct linux_group_page {
    uint32_t *values;
    uint64_t token;
} linux_group_page_t;

typedef struct linux_group_list {
    uint32_t count;
    uint32_t page_count;
    linux_group_page_t pages[EDGE_LINUX_GROUP_PAGE_MAX];
} linux_group_list_t;

void linux_group_list_init(linux_group_list_t *groups);
int linux_group_list_allocate(linux_group_list_t *groups, uint32_t count);
int linux_group_list_retain(linux_group_list_t *destination,
                            const linux_group_list_t *source);
void linux_group_list_release(linux_group_list_t *groups);
uint32_t *linux_group_list_page_values(linux_group_list_t *groups,
                                       uint32_t page_index);
const uint32_t *linux_group_list_const_page_values(
    const linux_group_list_t *groups, uint32_t page_index);
uint32_t linux_group_list_get(const linux_group_list_t *groups,
                              uint32_t index);
int linux_group_list_set(linux_group_list_t *groups, uint32_t index,
                         uint32_t gid);
int linux_group_list_contains(const linux_group_list_t *groups,
                              uint32_t gid);
void linux_group_list_sort(linux_group_list_t *groups);

int kernel_linux_group_page_allocate(linux_group_page_t *page);
int kernel_linux_group_page_retain(const linux_group_page_t *page);
void kernel_linux_group_page_release(const linux_group_page_t *page);
int edge_process_runtime_group_page_allocate(linux_group_page_t *page);
int edge_process_runtime_group_page_retain(
    const linux_group_page_t *page);
void edge_process_runtime_group_page_release(
    const linux_group_page_t *page);

#endif
