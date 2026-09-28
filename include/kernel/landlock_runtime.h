/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux Landlock runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LANDLOCK_RUNTIME_H
#define EDGEOS_KERNEL_LANDLOCK_RUNTIME_H

#include <stdint.h>

#define EDGE_LINUX_LANDLOCK_ABI_VERSION 3u

#define EDGE_LINUX_LANDLOCK_CREATE_RULESET_VERSION (1u << 0)

#define EDGE_LINUX_LANDLOCK_RULE_PATH_BENEATH 1u

#define EDGE_LINUX_LANDLOCK_ACCESS_FS_EXECUTE     (1ULL << 0)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_WRITE_FILE  (1ULL << 1)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_READ_FILE   (1ULL << 2)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_READ_DIR    (1ULL << 3)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_REMOVE_DIR  (1ULL << 4)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_CHAR   (1ULL << 6)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_DIR    (1ULL << 7)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_REG    (1ULL << 8)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_SOCK   (1ULL << 9)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_FIFO   (1ULL << 10)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_SYM    (1ULL << 12)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_REFER       (1ULL << 13)
#define EDGE_LINUX_LANDLOCK_ACCESS_FS_TRUNCATE    (1ULL << 14)

#define EDGE_LINUX_LANDLOCK_ACCESS_FS_MASK \
    ((EDGE_LINUX_LANDLOCK_ACCESS_FS_TRUNCATE << 1) - 1u)

typedef struct edge_linux_landlock_ruleset_attr {
    uint64_t handled_access_fs;
} edge_linux_landlock_ruleset_attr_t;

typedef struct edge_linux_landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed)) edge_linux_landlock_path_beneath_attr_t;

int kernel_landlock_ruleset_create(uint64_t handled_access_fs);
int kernel_landlock_ruleset_retain(int32_t ruleset_id);
void kernel_landlock_ruleset_release(int32_t ruleset_id);
int kernel_landlock_ruleset_add_path(int32_t ruleset_id,
                                     const char *path,
                                     uint64_t allowed_access);
int kernel_landlock_restrict_task(int32_t tid, int32_t tgid,
                                  int32_t ruleset_id);
int kernel_landlock_check_path_for_task(int32_t tid, const char *path,
                                        uint64_t requested_access);
int kernel_landlock_check_path(const char *path,
                               uint64_t requested_access);
int kernel_landlock_check_refer_for_task(int32_t tid,
                                         const char *source_path,
                                         const char *destination_path);
int kernel_landlock_check_refer(const char *source_path,
                                const char *destination_path);
int kernel_landlock_task_clone(int32_t parent_tid, int32_t child_tid,
                               int32_t child_tgid);
void kernel_landlock_task_exit(int32_t tid, int32_t tgid,
                               int whole_thread_group);

#endif
