/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_INOTIFY_H
#define EDGEOS_KERNEL_INOTIFY_H

#include <stdint.h>

/* Linux UAPI inotify masks. */
#define KERNEL_INOTIFY_ACCESS        0x00000001u
#define KERNEL_INOTIFY_MODIFY        0x00000002u
#define KERNEL_INOTIFY_ATTRIB        0x00000004u
#define KERNEL_INOTIFY_CLOSE_WRITE   0x00000008u
#define KERNEL_INOTIFY_CLOSE_NOWRITE 0x00000010u
#define KERNEL_INOTIFY_OPEN          0x00000020u
#define KERNEL_INOTIFY_MOVED_FROM    0x00000040u
#define KERNEL_INOTIFY_MOVED_TO      0x00000080u
#define KERNEL_INOTIFY_CREATE        0x00000100u
#define KERNEL_INOTIFY_DELETE        0x00000200u
#define KERNEL_INOTIFY_DELETE_SELF   0x00000400u
#define KERNEL_INOTIFY_MOVE_SELF     0x00000800u
#define KERNEL_INOTIFY_ALL_EVENTS    0x00000fffu
#define KERNEL_INOTIFY_UNMOUNT       0x00002000u
#define KERNEL_INOTIFY_Q_OVERFLOW    0x00004000u
#define KERNEL_INOTIFY_IGNORED       0x00008000u
#define KERNEL_INOTIFY_ONLYDIR       0x01000000u
#define KERNEL_INOTIFY_DONT_FOLLOW   0x02000000u
#define KERNEL_INOTIFY_EXCL_UNLINK   0x04000000u
#define KERNEL_INOTIFY_MASK_CREATE   0x10000000u
#define KERNEL_INOTIFY_MASK_ADD      0x20000000u
#define KERNEL_INOTIFY_ISDIR         0x40000000u
#define KERNEL_INOTIFY_ONESHOT       0x80000000u

typedef struct kernel_inotify_state {
    uint32_t references;
    uint32_t queued_events;
    uint32_t queued_bytes;
    uint32_t padding;
    uint64_t readiness_sequence;
} kernel_inotify_state_t;

typedef int (*kernel_inotify_copy_record_fn)(
    void *context, uint64_t offset, const void *record, uint32_t length);

typedef enum kernel_inotify_limit {
    KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS = 0,
    KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES = 1,
    KERNEL_INOTIFY_LIMIT_MAX_USER_WATCHES = 2
} kernel_inotify_limit_t;

int kernel_inotify_validate_watch_mask(uint32_t mask);
uint32_t kernel_inotify_limit_get(kernel_inotify_limit_t limit);
int kernel_inotify_limit_set(kernel_inotify_limit_t limit, uint32_t value);
int kernel_inotify_create(void);
int kernel_inotify_retain(int inotify_id);
void kernel_inotify_release(int inotify_id);
int kernel_inotify_query(int inotify_id, kernel_inotify_state_t *state);
int kernel_inotify_add_watch(int inotify_id, const char *canonical_path,
                             uint32_t mask, int target_is_directory);
int kernel_inotify_remove_watch(int inotify_id, int32_t watch_descriptor);
int64_t kernel_inotify_read(int inotify_id,
                            kernel_inotify_copy_record_fn copy_record,
                            void *copy_context, uint64_t length);
void kernel_inotify_notify_path(const char *canonical_path, uint32_t mask,
                                const char *name_override);
void kernel_inotify_notify_move(const char *old_canonical_path,
                                const char *new_canonical_path);

#endif
