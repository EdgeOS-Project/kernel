/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side tests for the shared fanotify notification service. */

#include "kernel/fanotify.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct fanotify_test_copy {
    kernel_fanotify_event_metadata_t events[8];
    uint32_t count;
} fanotify_test_copy_t;

static int g_wake_count;
static int g_installed_descriptor = 40;

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    if (!identity) return -1;
    memset(identity, 0, sizeof(*identity));
    identity->uid = 1000u;
    identity->euid = 1000u;
    return 0;
}

int kernel_current_pid(void) {
    return 123;
}

void kernel_fanotify_state_changed(int group_id) {
    assert(group_id >= 0);
    ++g_wake_count;
}

int kernel_vfs_resolve_path(const char *path, int nofollow,
                            kernel_vfs_target_t *target) {
    static uintptr_t superblock_storage;
    static uintptr_t inode_storage;
    (void)nofollow;
    if (!path || !target || path[0] != '/') return -EDGE_LINUX_ENOENT;
    memset(target, 0, sizeof(*target));
    target->superblock = (vfs_superblock_t *)&superblock_storage;
    target->inode = (vfs_inode_t *)&inode_storage;
    target->resolved_path = path;
    return 0;
}

int kernel_vfs_install_inode_descriptor(vfs_superblock_t *superblock,
                                        const vfs_inode_t *inode,
                                        uint32_t status_flags,
                                        uint32_t descriptor_flags,
                                        int linkable_zero_link_inode) {
    (void)status_flags;
    (void)descriptor_flags;
    (void)linkable_zero_link_inode;
    assert(superblock != 0);
    assert(inode != 0);
    return ++g_installed_descriptor;
}

int kernel_fd_close(int32_t descriptor) {
    (void)descriptor;
    return 0;
}

static int copy_record(void *context, uint64_t offset, const void *record,
                       uint32_t length) {
    fanotify_test_copy_t *copy = context;
    assert(copy != 0);
    assert(record != 0);
    assert(length == sizeof(kernel_fanotify_event_metadata_t));
    assert(offset % length == 0u);
    assert(copy->count < 8u);
    copy->events[copy->count++] =
        *(const kernel_fanotify_event_metadata_t *)record;
    return 0;
}

static void assert_event(const kernel_fanotify_event_metadata_t *event,
                         uint64_t mask, int descriptor) {
    assert(event->event_length == KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(event->version == KERNEL_FANOTIFY_METADATA_VERSION);
    assert(event->metadata_length == KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(event->mask == mask);
    assert(event->descriptor == descriptor);
    assert(event->pid == 123);
}

int main(void) {
    fanotify_test_copy_t copy;
    kernel_fanotify_state_t state;
    uint64_t sequence;
    int group;

    memset(&copy, 0, sizeof(copy));
    group = kernel_fanotify_create(KERNEL_FAN_NONBLOCK, 0u);
    assert(group >= 0);
    assert(kernel_fanotify_query(group, &state) == 0);
    assert(state.references == 1u);
    assert(state.queued_events == 0u);
    sequence = state.readiness_sequence;

    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_OPEN,
               "/watched/file", 0) == 0);
    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_CREATE,
               "/watched", 1) == -EDGE_LINUX_EINVAL);

    kernel_fanotify_notify_path("/watched/file", KERNEL_FAN_OPEN);
    kernel_fanotify_notify_path("/watched/file", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_query(group, &state) == 0);
    assert(state.queued_events == 1u);
    assert(state.queued_bytes == KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(state.readiness_sequence == sequence + 1u);
    assert(g_wake_count == 1);

    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.events)) ==
           KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(copy.count == 1u);
    assert_event(&copy.events[0], KERNEL_FAN_OPEN, 41);
    assert(kernel_fanotify_query(group, &state) == 0);
    assert(state.queued_events == 0u);

    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_OPEN | KERNEL_FAN_EVENT_ON_CHILD,
               "/watched", 1) == 0);
    kernel_fanotify_notify_path("/watched/child", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.events)) ==
           KERNEL_FANOTIFY_METADATA_LENGTH);
    assert_event(&copy.events[1], KERNEL_FAN_OPEN, 42);
    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_REMOVE,
               KERNEL_FAN_OPEN | KERNEL_FAN_EVENT_ON_CHILD,
               "/watched", 1) == 0);

    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD | KERNEL_FAN_MARK_IGNORE,
               KERNEL_FAN_OPEN, "/watched/file", 0) == 0);
    kernel_fanotify_notify_path("/watched/file", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.events)) ==
           -EDGE_LINUX_EAGAIN);

    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_FLUSH, 0u, 0, 0) == 0);
    assert(kernel_fanotify_query(group, &state) == 0);
    assert(state.marks == 0u);
    assert(kernel_fanotify_retain(group) == 0);
    kernel_fanotify_release(group);
    assert(kernel_fanotify_query(group, &state) == 0);
    kernel_fanotify_release(group);
    assert(kernel_fanotify_query(group, &state) == -EDGE_LINUX_EBADF);

    puts("fanotify_runtime_unit: PASS");
    return 0;
}
