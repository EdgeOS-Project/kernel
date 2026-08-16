/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent readlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"

typedef enum kernel_proc_link_kind {
    KERNEL_PROC_LINK_NONE = 0,
    KERNEL_PROC_LINK_SELF,
    KERNEL_PROC_LINK_THREAD_SELF,
    KERNEL_PROC_LINK_CWD,
    KERNEL_PROC_LINK_ROOT,
    KERNEL_PROC_LINK_EXE,
    KERNEL_PROC_LINK_DESCRIPTOR,
} kernel_proc_link_kind_t;

typedef struct kernel_proc_link {
    kernel_proc_link_kind_t kind;
    int32_t pid;
    int32_t descriptor;
} kernel_proc_link_t;

static uint32_t readlink_text_length(const char *text) {
    uint32_t length = 0;
    if (!text) return 0;
    while (text[length]) ++length;
    return length;
}

static int readlink_text_equal(const char *left, const char *right) {
    uint32_t index = 0;
    if (!left || !right) return 0;
    while (left[index] && right[index] &&
           left[index] == right[index])
        ++index;
    return left[index] == right[index];
}

static const char *readlink_after_prefix(const char *text,
                                         const char *prefix) {
    uint32_t index = 0;
    if (!text || !prefix) return 0;
    while (prefix[index] && text[index] == prefix[index]) ++index;
    return prefix[index] ? 0 : text + index;
}

static int readlink_parse_decimal(const char **cursor, int32_t *value) {
    const char *text;
    uint64_t parsed = 0;
    if (!cursor || !*cursor || !value) return -EDGE_LINUX_EINVAL;
    text = *cursor;
    if (*text < '0' || *text > '9') return 0;
    while (*text >= '0' && *text <= '9') {
        parsed = parsed * 10u + (uint32_t)(*text - '0');
        if (parsed > INT32_MAX) return -EDGE_LINUX_ENOENT;
        ++text;
    }
    *cursor = text;
    *value = (int32_t)parsed;
    return 1;
}

static int readlink_copy(char *target, uint32_t capacity,
                         const char *source) {
    uint32_t length;
    if (!target || !capacity || !source) return -EDGE_LINUX_EFAULT;
    length = readlink_text_length(source);
    if (length > capacity) length = capacity;
    for (uint32_t index = 0; index < length; ++index)
        target[index] = source[index];
    return (int)length;
}

static int readlink_append_decimal(char *target, uint32_t capacity,
                                   uint32_t *position, uint32_t value) {
    char reversed[16];
    uint32_t digits = 0;
    if (!target || !position) return -EDGE_LINUX_EFAULT;
    do {
        reversed[digits++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && digits < sizeof(reversed));
    while (digits) {
        if (*position >= capacity) return 0;
        target[(*position)++] = reversed[--digits];
    }
    return 1;
}

static int readlink_append_text(char *target, uint32_t capacity,
                                uint32_t *position, const char *text) {
    uint32_t index = 0;
    if (!target || !position || !text) return -EDGE_LINUX_EFAULT;
    while (text[index]) {
        if (*position >= capacity) return 0;
        target[(*position)++] = text[index++];
    }
    return 1;
}

static int readlink_format_identity(char *target, uint32_t capacity,
                                    const char *prefix, uint64_t identity,
                                    const char *suffix) {
    char reversed[24];
    uint32_t digits = 0;
    uint32_t position = 0;

    if (!target || !capacity || !prefix || !suffix)
        return -EDGE_LINUX_EFAULT;
    if (readlink_append_text(
            target, capacity, &position, prefix) <= 0)
        return (int)position;
    do {
        reversed[digits++] = (char)('0' + identity % 10u);
        identity /= 10u;
    } while (identity && digits < sizeof(reversed));
    while (digits) {
        if (position >= capacity) return (int)position;
        target[position++] = reversed[--digits];
    }
    (void)readlink_append_text(
        target, capacity, &position, suffix);
    return (int)position;
}

static int readlink_current_alias(
    kernel_proc_link_kind_t kind, const kernel_linux_identity_t *identity,
    char *target, uint32_t capacity) {
    static const char task_component[] = "/task/";
    uint32_t position = 0;

    if (!identity) return -EDGE_LINUX_EFAULT;
    if (readlink_append_decimal(
            target, capacity, &position, (uint32_t)identity->tgid) <= 0)
        return (int)position;
    if (kind == KERNEL_PROC_LINK_THREAD_SELF) {
        for (uint32_t index = 0; task_component[index]; ++index) {
            if (position >= capacity) return (int)position;
            target[position++] = task_component[index];
        }
        (void)readlink_append_decimal(
            target, capacity, &position, (uint32_t)identity->tid);
    }
    return (int)position;
}

static int readlink_parse_proc_link(
    const char *path, const kernel_linux_identity_t *identity,
    kernel_proc_link_t *link) {
    const char *cursor;
    int32_t owner;
    int32_t thread;
    int status;

    if (!path || !identity || !link) return -EDGE_LINUX_EINVAL;
    link->kind = KERNEL_PROC_LINK_NONE;
    link->pid = -1;
    link->descriptor = -1;

    if (readlink_text_equal(path, "/proc/self")) {
        link->kind = KERNEL_PROC_LINK_SELF;
        return 1;
    }
    if (readlink_text_equal(path, "/proc/thread-self")) {
        link->kind = KERNEL_PROC_LINK_THREAD_SELF;
        return 1;
    }
    if (readlink_text_equal(path, "/dev/stdin") ||
        readlink_text_equal(path, "/dev/stdout") ||
        readlink_text_equal(path, "/dev/stderr")) {
        link->kind = KERNEL_PROC_LINK_DESCRIPTOR;
        link->pid = identity->global_tgid;
        link->descriptor = readlink_text_equal(path, "/dev/stdin") ? 0 :
            readlink_text_equal(path, "/dev/stdout") ? 1 : 2;
        return 1;
    }

    cursor = readlink_after_prefix(path, "/dev/fd/");
    if (cursor) {
        link->pid = identity->global_tgid;
        status = readlink_parse_decimal(&cursor, &link->descriptor);
        if (status <= 0 || *cursor) return -EDGE_LINUX_ENOENT;
        link->kind = KERNEL_PROC_LINK_DESCRIPTOR;
        return 1;
    }

    cursor = readlink_after_prefix(path, "/proc/self/");
    if (cursor) {
        owner = identity->global_tgid;
    } else {
        cursor = readlink_after_prefix(path, "/proc/thread-self/");
        if (cursor) {
            owner = identity->global_tid;
        } else {
            cursor = readlink_after_prefix(path, "/proc/");
            if (!cursor) return 0;
            status = readlink_parse_decimal(&cursor, &owner);
            if (status <= 0) return status;
            if (*cursor++ != '/') return 0;
        }
    }

    link->pid = owner;
    if (readlink_text_equal(cursor, "cwd"))
        link->kind = KERNEL_PROC_LINK_CWD;
    else if (readlink_text_equal(cursor, "root"))
        link->kind = KERNEL_PROC_LINK_ROOT;
    else if (readlink_text_equal(cursor, "exe"))
        link->kind = KERNEL_PROC_LINK_EXE;
    else {
        const char *descriptor = readlink_after_prefix(cursor, "fd/");
        if (!descriptor) {
            const char *task = readlink_after_prefix(cursor, "task/");
            if (!task) return 0;
            status = readlink_parse_decimal(&task, &thread);
            if (status <= 0 || *task++ != '/') return -EDGE_LINUX_ENOENT;
            descriptor = readlink_after_prefix(task, "fd/");
            if (!descriptor) return 0;
            link->pid = thread;
        }
        status = readlink_parse_decimal(
            &descriptor, &link->descriptor);
        if (status <= 0 || *descriptor) return -EDGE_LINUX_ENOENT;
        link->kind = KERNEL_PROC_LINK_DESCRIPTOR;
    }
    return 1;
}

int kernel_procfd_readlink_target(int32_t pid, int32_t descriptor,
                                  char *target, uint32_t capacity) {
    kernel_procfd_link_view_t view;
    int status;

    if (pid <= 0 || descriptor < 0 || !target || !capacity)
        return -EDGE_LINUX_ENOENT;
    view.kind = 0;
    view.identity = 0;
    view.path = target;
    view.path_capacity = capacity;
    view.path_length = 0;
    status = arch_procfd_link_view(pid, descriptor, &view);
    if (status < 0) return status;
    if (view.kind == KERNEL_PROCFD_LINK_PATH)
        return (int)(view.path_length < capacity ?
            view.path_length : capacity);
    if (view.kind == KERNEL_PROCFD_LINK_PIPE)
        return readlink_format_identity(
            target, capacity, "pipe:[", view.identity, "]");
    if (view.kind == KERNEL_PROCFD_LINK_SOCKET)
        return readlink_format_identity(
            target, capacity, "socket:[", view.identity, "]");
    if (view.kind == KERNEL_PROCFD_LINK_PIDFD)
        return readlink_copy(
            target, capacity, "anon_inode:[pidfd]");
    if (view.kind == KERNEL_PROCFD_LINK_ANONYMOUS)
        return readlink_format_identity(
            target, capacity, "anon_inode:[edge-fd-",
            (uint32_t)descriptor, "]");
    return -EDGE_LINUX_ENOENT;
}

static int readlink_proc_task_target(
    const kernel_proc_link_t *link, char *target, uint32_t capacity) {
    kernel_proc_task_snapshot_t task;
    uint32_t length;

    if (!link) return -EDGE_LINUX_EFAULT;
    if (link->kind == KERNEL_PROC_LINK_DESCRIPTOR)
        return kernel_procfd_readlink_target(
            link->pid, link->descriptor, target, capacity);
    if (link->kind == KERNEL_PROC_LINK_EXE) {
        if (kernel_proc_task_snapshot(link->pid, &task) < 0 ||
            !task.exec_path[0])
            return -EDGE_LINUX_ENOENT;
        return readlink_copy(target, capacity, task.exec_path);
    }
    if (link->kind == KERNEL_PROC_LINK_CWD ||
        link->kind == KERNEL_PROC_LINK_ROOT) {
        target[0] = 0;
        if (kernel_proc_task_fs_snapshot(
                link->pid,
                link->kind == KERNEL_PROC_LINK_CWD ? target : 0,
                link->kind == KERNEL_PROC_LINK_CWD ? capacity : 0,
                link->kind == KERNEL_PROC_LINK_ROOT ? target : 0,
                link->kind == KERNEL_PROC_LINK_ROOT ? capacity : 0) < 0)
            return -EDGE_LINUX_ENOENT;
        for (length = 0; length < capacity && target[length]; ++length) {}
        return (int)length;
    }
    return -EDGE_LINUX_ENOENT;
}

int kernel_vfs_readlink_target(const char *path, char *target,
                               uint32_t capacity) {
    kernel_linux_identity_t identity;
    kernel_proc_link_t link;
    int status;

    if (!path || !target || !capacity) return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_EFAULT;
    status = readlink_parse_proc_link(path, &identity, &link);
    if (status < 0) return status;
    if (status > 0) {
        if (link.kind == KERNEL_PROC_LINK_SELF ||
            link.kind == KERNEL_PROC_LINK_THREAD_SELF)
            return readlink_current_alias(
                link.kind, &identity, target, capacity);
        return readlink_proc_task_target(
            &link, target, capacity);
    }
    return arch_vfs_readlink_path(path, target, capacity);
}
