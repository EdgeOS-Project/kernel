/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux fanotify service.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_FANOTIFY_H
#define EDGEOS_KERNEL_FANOTIFY_H

#include <stdint.h>

#define KERNEL_FAN_ACCESS          0x00000001u
#define KERNEL_FAN_MODIFY          0x00000002u
#define KERNEL_FAN_ATTRIB          0x00000004u
#define KERNEL_FAN_CLOSE_WRITE     0x00000008u
#define KERNEL_FAN_CLOSE_NOWRITE   0x00000010u
#define KERNEL_FAN_OPEN            0x00000020u
#define KERNEL_FAN_MOVED_FROM      0x00000040u
#define KERNEL_FAN_MOVED_TO        0x00000080u
#define KERNEL_FAN_CREATE          0x00000100u
#define KERNEL_FAN_DELETE          0x00000200u
#define KERNEL_FAN_DELETE_SELF     0x00000400u
#define KERNEL_FAN_MOVE_SELF       0x00000800u
#define KERNEL_FAN_OPEN_EXEC       0x00001000u
#define KERNEL_FAN_Q_OVERFLOW      0x00004000u
#define KERNEL_FAN_OPEN_PERM       0x00010000u
#define KERNEL_FAN_ACCESS_PERM     0x00020000u
#define KERNEL_FAN_OPEN_EXEC_PERM  0x00040000u
#define KERNEL_FAN_PRE_ACCESS      0x00100000u
#define KERNEL_FAN_EVENT_ON_CHILD  0x08000000u
#define KERNEL_FAN_RENAME          0x10000000u
#define KERNEL_FAN_ONDIR           0x40000000u

#define KERNEL_FAN_CLOEXEC          0x00000001u
#define KERNEL_FAN_NONBLOCK         0x00000002u
#define KERNEL_FAN_CLASS_NOTIF      0x00000000u
#define KERNEL_FAN_CLASS_CONTENT    0x00000004u
#define KERNEL_FAN_CLASS_PRE_CONTENT 0x00000008u
#define KERNEL_FAN_UNLIMITED_QUEUE  0x00000010u
#define KERNEL_FAN_UNLIMITED_MARKS  0x00000020u
#define KERNEL_FAN_ENABLE_AUDIT     0x00000040u
#define KERNEL_FAN_REPORT_PIDFD     0x00000080u
#define KERNEL_FAN_REPORT_TID       0x00000100u
#define KERNEL_FAN_REPORT_FID       0x00000200u
#define KERNEL_FAN_REPORT_DIR_FID   0x00000400u
#define KERNEL_FAN_REPORT_NAME      0x00000800u
#define KERNEL_FAN_REPORT_TARGET_FID 0x00001000u
#define KERNEL_FAN_REPORT_FD_ERROR  0x00002000u
#define KERNEL_FAN_REPORT_MNT       0x00004000u

#define KERNEL_FAN_MARK_ADD          0x00000001u
#define KERNEL_FAN_MARK_REMOVE       0x00000002u
#define KERNEL_FAN_MARK_DONT_FOLLOW  0x00000004u
#define KERNEL_FAN_MARK_ONLYDIR      0x00000008u
#define KERNEL_FAN_MARK_MOUNT        0x00000010u
#define KERNEL_FAN_MARK_IGNORED_MASK 0x00000020u
#define KERNEL_FAN_MARK_IGNORED_SURV_MODIFY 0x00000040u
#define KERNEL_FAN_MARK_FLUSH        0x00000080u
#define KERNEL_FAN_MARK_FILESYSTEM   0x00000100u
#define KERNEL_FAN_MARK_EVICTABLE    0x00000200u
#define KERNEL_FAN_MARK_IGNORE       0x00000400u
#define KERNEL_FAN_MARK_MNTNS        0x00000110u

#define KERNEL_FANOTIFY_METADATA_VERSION 3u
#define KERNEL_FANOTIFY_METADATA_LENGTH 24u
#define KERNEL_FANOTIFY_PIDFD_INFO_LENGTH 8u
#define KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH 20u
#define KERNEL_FANOTIFY_INFO_TYPE_FID 1u
#define KERNEL_FANOTIFY_INFO_TYPE_PIDFD 4u
#define KERNEL_FANOTIFY_NOFD (-1)
#define KERNEL_FANOTIFY_EPIDFD (-2)

typedef struct kernel_fanotify_state {
    uint32_t references;
    uint32_t queued_events;
    uint32_t queued_bytes;
    uint32_t marks;
    uint32_t flags;
    uint64_t readiness_sequence;
} kernel_fanotify_state_t;

typedef struct kernel_fanotify_event_metadata {
    uint32_t event_length;
    uint8_t version;
    uint8_t reserved;
    uint16_t metadata_length;
    uint64_t mask;
    int32_t descriptor;
    int32_t pid;
} kernel_fanotify_event_metadata_t;

typedef struct kernel_fanotify_event_info_pidfd {
    uint8_t information_type;
    uint8_t padding;
    uint16_t length;
    int32_t descriptor;
} kernel_fanotify_event_info_pidfd_t;

typedef struct kernel_fanotify_event_info_fid_prefix {
    uint8_t information_type;
    uint8_t padding;
    uint16_t length;
    int32_t filesystem_id[2];
    uint32_t handle_bytes;
    int32_t handle_type;
} kernel_fanotify_event_info_fid_prefix_t;

_Static_assert(sizeof(kernel_fanotify_event_info_pidfd_t) ==
               KERNEL_FANOTIFY_PIDFD_INFO_LENGTH,
               "fanotify pidfd information layout must match Linux UAPI");
_Static_assert(sizeof(kernel_fanotify_event_info_fid_prefix_t) ==
               KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH,
               "fanotify FID prefix layout must match Linux UAPI");

typedef int (*kernel_fanotify_copy_record_fn)(
    void *context, uint64_t offset, const void *record, uint32_t length);

int kernel_fanotify_create(uint32_t flags, uint32_t event_flags);
int kernel_fanotify_retain(int group_id);
void kernel_fanotify_release(int group_id);
int kernel_fanotify_query(int group_id, kernel_fanotify_state_t *state);
int kernel_fanotify_modify_mark(int group_id, uint32_t flags,
                                uint64_t mask, const char *canonical_path,
                                int target_is_directory);
int64_t kernel_fanotify_read(int group_id,
                            kernel_fanotify_copy_record_fn copy_record,
                            void *copy_context, uint64_t length);
void kernel_fanotify_notify_path(const char *canonical_path, uint32_t mask);
void kernel_fanotify_notify_move(const char *old_canonical_path,
                                 const char *new_canonical_path);

#endif
