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
    uint8_t records[8][64];
    uint32_t lengths[8];
    uint32_t count;
} fanotify_test_copy_t;

static int g_wake_count;
static int g_permission_wake_count;
static int g_permission_wait_count;
static int g_permission_group = -1;
static int g_permission_mode;
static uint64_t g_permission_expected_mask = KERNEL_FAN_OPEN_PERM;
static int g_permission_expected_range;
static uint64_t g_permission_expected_range_offset = 4096u;
static uint64_t g_permission_expected_range_count = 8192u;
static int g_installed_descriptor = 40;
static char g_last_resolved_path[64];

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    if (!identity) return -1;
    memset(identity, 0, sizeof(*identity));
    identity->uid = 1000u;
    identity->euid = 1000u;
    identity->tid = 123;
    identity->tgid = 100;
    identity->global_tid = 123;
    identity->global_tgid = 100;
    return 0;
}

int kernel_current_pid(void) {
    return 123;
}

void kernel_fanotify_state_changed(int group_id) {
    assert(group_id >= 0);
    ++g_wake_count;
}

void arch_fanotify_permission_state_changed(uint64_t ticket) {
    assert(ticket != 0u);
    ++g_permission_wake_count;
}

int arch_fanotify_consume_completed_permission(uint64_t *ticket) {
    (void)ticket;
    return 0;
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
    assert(strlen(path) < sizeof(g_last_resolved_path));
    memcpy(g_last_resolved_path, path, strlen(path) + 1u);
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

int vfs_mount_id_for_superblock(const vfs_superblock_t *superblock,
                                uint64_t *mount_id_out) {
    assert(superblock != 0);
    assert(mount_id_out != 0);
    *mount_id_out = 0x1122334455667788ULL;
    return 0;
}

int vfs_encode_file_handle(vfs_superblock_t *superblock,
                           const vfs_inode_t *inode,
                           uint32_t *handle_type, void *handle,
                           uint32_t *handle_bytes) {
    static const uint8_t encoded[12] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    assert(superblock != 0);
    assert(inode != 0);
    assert(handle_type != 0);
    assert(handle_bytes != 0 && *handle_bytes >= sizeof(encoded));
    assert(handle != 0);
    *handle_type = 7u;
    *handle_bytes = sizeof(encoded);
    memcpy(handle, encoded, sizeof(encoded));
    return 0;
}

int kernel_fd_close(int32_t descriptor) {
    (void)descriptor;
    return 0;
}

int kernel_pidfd_open(int32_t pid, uint32_t flags) {
    assert(pid == 100);
    assert(flags == 0u);
    return 80 + pid;
}

static int copy_record(void *context, uint64_t offset, const void *record,
                       uint32_t length) {
    fanotify_test_copy_t *copy = context;
    assert(copy != 0);
    assert(record != 0);
    assert(length >= sizeof(kernel_fanotify_event_metadata_t));
    assert(length <= sizeof(copy->records[0]));
    assert(offset < sizeof(copy->records));
    assert(copy->count < 8u);
    memcpy(copy->records[copy->count], record, length);
    copy->lengths[copy->count] = length;
    ++copy->count;
    return 0;
}

static const kernel_fanotify_event_metadata_t *copied_event(
        const fanotify_test_copy_t *copy, uint32_t index) {
    assert(copy != 0 && index < copy->count);
    return (const kernel_fanotify_event_metadata_t *)(const void *)
        copy->records[index];
}

static void assert_event(const kernel_fanotify_event_metadata_t *event,
                         uint64_t mask, int descriptor) {
    assert(event->event_length == KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(event->version == KERNEL_FANOTIFY_METADATA_VERSION);
    assert(event->metadata_length == KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(event->mask == mask);
    assert(event->descriptor == descriptor);
    assert(event->pid == 100);
}

void arch_fanotify_permission_wait(uint64_t ticket) {
    fanotify_test_copy_t copy;
    kernel_fanotify_response_t response;
    const kernel_fanotify_event_metadata_t *event;
    uint32_t expected_length = KERNEL_FANOTIFY_METADATA_LENGTH;

    assert(ticket != 0u);
    assert(g_permission_group >= 0);
    assert(kernel_fanotify_permission_pending(ticket));
    ++g_permission_wait_count;
    if (g_permission_mode == 3) {
        kernel_fanotify_release(g_permission_group);
        assert(!kernel_fanotify_permission_pending(ticket));
        return;
    }
    memset(&copy, 0, sizeof(copy));
    if (g_permission_expected_range)
        expected_length += sizeof(kernel_fanotify_event_info_range_t);
    assert(kernel_fanotify_read(
               g_permission_group, copy_record, &copy,
               sizeof(copy.records)) == expected_length);
    assert(copy.count == 1u);
    event = copied_event(&copy, 0u);
    assert(event->event_length == expected_length);
    assert(event->mask == g_permission_expected_mask);
    assert(event->descriptor >= 0);
    if (g_permission_expected_range) {
        const kernel_fanotify_event_info_range_t *range =
            (const kernel_fanotify_event_info_range_t *)(const void *)
                (copy.records[0] + KERNEL_FANOTIFY_METADATA_LENGTH);
        assert(range->information_type ==
               KERNEL_FANOTIFY_INFO_TYPE_RANGE);
        assert(range->length == sizeof(*range));
        assert(range->offset == g_permission_expected_range_offset);
        assert(range->count == g_permission_expected_range_count);
    }
    response.descriptor = event->descriptor;
    response.response = g_permission_mode == 1 ? KERNEL_FAN_DENY :
        g_permission_mode == 2 ?
            KERNEL_FAN_DENY | ((uint32_t)EDGE_LINUX_EIO << 24u) :
            KERNEL_FAN_ALLOW;
    if (g_permission_mode == 4) {
        response.response = KERNEL_FAN_ALLOW | KERNEL_FAN_AUDIT;
        assert(kernel_fanotify_write(
                   g_permission_group, &response, 0,
                   sizeof(response)) == -EDGE_LINUX_EINVAL);
        response.response = KERNEL_FAN_ALLOW;
    }
    assert(kernel_fanotify_write(
               g_permission_group, &response, 0,
               sizeof(response)) == sizeof(response));
    assert(!kernel_fanotify_permission_pending(ticket));
}

int main(void) {
    fanotify_test_copy_t copy;
    kernel_fanotify_state_t state;
    uint64_t sequence;
    int group;
    int pidfd_group;
    int tid_group;
    int fid_group;
    int combined_group;
    int dfid_group;
    int permission_group;
    int access_group;
    int exec_group;
    int precontent_group;
    int directory_group;
    int release_group;

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
    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_OPEN_PERM,
               "/watched/file", 0) == -EDGE_LINUX_EINVAL);

    kernel_fanotify_notify_path("/watched/file", KERNEL_FAN_OPEN);
    kernel_fanotify_notify_path("/watched/file", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_query(group, &state) == 0);
    assert(state.queued_events == 1u);
    assert(state.queued_bytes == KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(state.readiness_sequence == sequence + 1u);
    assert(g_wake_count == 1);

    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.records)) ==
           KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(copy.count == 1u);
    assert_event(copied_event(&copy, 0u), KERNEL_FAN_OPEN, 41);
    assert(kernel_fanotify_query(group, &state) == 0);
    assert(state.queued_events == 0u);

    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_OPEN | KERNEL_FAN_EVENT_ON_CHILD,
               "/watched", 1) == 0);
    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_ONDIR,
               "/isolated/directory", 1) == 0);
    kernel_fanotify_notify_path(
        "/isolated/directory", KERNEL_FAN_OPEN | KERNEL_FAN_ONDIR);
    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.records)) ==
           -EDGE_LINUX_EAGAIN);
    kernel_fanotify_notify_path("/watched/child", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.records)) ==
           KERNEL_FANOTIFY_METADATA_LENGTH);
    assert_event(copied_event(&copy, 1u), KERNEL_FAN_OPEN, 42);
    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_REMOVE,
               KERNEL_FAN_OPEN | KERNEL_FAN_EVENT_ON_CHILD,
               "/watched", 1) == 0);

    assert(kernel_fanotify_modify_mark(
               group, KERNEL_FAN_MARK_ADD | KERNEL_FAN_MARK_IGNORE,
               KERNEL_FAN_OPEN, "/watched/file", 0) == 0);
    kernel_fanotify_notify_path("/watched/file", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               group, copy_record, &copy, sizeof(copy.records)) ==
           -EDGE_LINUX_EAGAIN);

    pidfd_group = kernel_fanotify_create(
        KERNEL_FAN_NONBLOCK | KERNEL_FAN_REPORT_PIDFD,
        0u);
    assert(pidfd_group >= 0);
    assert(kernel_fanotify_modify_mark(
               pidfd_group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_OPEN,
               "/watched/pidfd", 0) == 0);
    kernel_fanotify_notify_path("/watched/pidfd", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_query(pidfd_group, &state) == 0);
    assert(state.queued_bytes ==
           KERNEL_FANOTIFY_METADATA_LENGTH +
               KERNEL_FANOTIFY_PIDFD_INFO_LENGTH);
    assert(kernel_fanotify_read(
               pidfd_group, copy_record, &copy,
               KERNEL_FANOTIFY_METADATA_LENGTH) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fanotify_query(pidfd_group, &state) == 0);
    assert(state.queued_events == 1u);
    assert(kernel_fanotify_read(
               pidfd_group, copy_record, &copy,
               sizeof(copy.records)) ==
           KERNEL_FANOTIFY_METADATA_LENGTH +
               KERNEL_FANOTIFY_PIDFD_INFO_LENGTH);
    {
        const kernel_fanotify_event_metadata_t *event =
            copied_event(&copy, 2u);
        const kernel_fanotify_event_info_pidfd_t *pidfd =
            (const kernel_fanotify_event_info_pidfd_t *)(const void *)
                (copy.records[2] + KERNEL_FANOTIFY_METADATA_LENGTH);

        assert(event->event_length ==
               KERNEL_FANOTIFY_METADATA_LENGTH +
                   KERNEL_FANOTIFY_PIDFD_INFO_LENGTH);
        assert(event->pid == 100);
        assert(pidfd->information_type ==
               KERNEL_FANOTIFY_INFO_TYPE_PIDFD);
        assert(pidfd->length == KERNEL_FANOTIFY_PIDFD_INFO_LENGTH);
        assert(pidfd->descriptor == 180);
    }
    kernel_fanotify_release(pidfd_group);

    tid_group = kernel_fanotify_create(
        KERNEL_FAN_NONBLOCK | KERNEL_FAN_REPORT_TID, 0u);
    assert(tid_group >= 0);
    assert(kernel_fanotify_modify_mark(
               tid_group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_OPEN,
               "/watched/tid", 0) == 0);
    kernel_fanotify_notify_path("/watched/tid", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               tid_group, copy_record, &copy, sizeof(copy.records)) ==
           KERNEL_FANOTIFY_METADATA_LENGTH);
    assert(copied_event(&copy, 3u)->pid == 123);
    kernel_fanotify_release(tid_group);

    fid_group = kernel_fanotify_create(
        KERNEL_FAN_NONBLOCK | KERNEL_FAN_REPORT_FID, 0u);
    assert(fid_group >= 0);
    assert(kernel_fanotify_modify_mark(
               fid_group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_OPEN,
               "/watched/fid", 0) == 0);
    kernel_fanotify_notify_path("/watched/fid", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               fid_group, copy_record, &copy,
               KERNEL_FANOTIFY_METADATA_LENGTH) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fanotify_read(
               fid_group, copy_record, &copy,
               sizeof(copy.records[0])) == 56);
    {
        const kernel_fanotify_event_metadata_t *event =
            copied_event(&copy, 4u);
        const kernel_fanotify_event_info_fid_prefix_t *fid =
            (const kernel_fanotify_event_info_fid_prefix_t *)(const void *)
                (copy.records[4] + KERNEL_FANOTIFY_METADATA_LENGTH);
        const uint8_t *handle = copy.records[4] +
            KERNEL_FANOTIFY_METADATA_LENGTH +
            KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH;

        assert(event->event_length == 56u);
        assert(event->descriptor == KERNEL_FANOTIFY_NOFD);
        assert(fid->information_type == KERNEL_FANOTIFY_INFO_TYPE_FID);
        assert(fid->length == 32u);
        assert((uint32_t)fid->filesystem_id[0] == 0x55667788u);
        assert((uint32_t)fid->filesystem_id[1] == 0x11223344u);
        assert(fid->handle_bytes == 12u);
        assert(fid->handle_type == 7);
        for (uint32_t index = 0; index < fid->handle_bytes; ++index)
            assert(handle[index] == (uint8_t)(0x10u + index));
    }
    kernel_fanotify_release(fid_group);

    combined_group = kernel_fanotify_create(
        KERNEL_FAN_NONBLOCK | KERNEL_FAN_REPORT_FID |
            KERNEL_FAN_REPORT_PIDFD,
        0u);
    assert(combined_group >= 0);
    assert(kernel_fanotify_modify_mark(
               combined_group, KERNEL_FAN_MARK_ADD, KERNEL_FAN_OPEN,
               "/watched/combined", 0) == 0);
    kernel_fanotify_notify_path("/watched/combined", KERNEL_FAN_OPEN);
    assert(kernel_fanotify_read(
               combined_group, copy_record, &copy,
               sizeof(copy.records[0])) == 64);
    {
        const kernel_fanotify_event_metadata_t *event =
            copied_event(&copy, 5u);
        const kernel_fanotify_event_info_fid_prefix_t *fid =
            (const kernel_fanotify_event_info_fid_prefix_t *)(const void *)
                (copy.records[5] + KERNEL_FANOTIFY_METADATA_LENGTH);
        const kernel_fanotify_event_info_pidfd_t *pidfd =
            (const kernel_fanotify_event_info_pidfd_t *)(const void *)
                (copy.records[5] + KERNEL_FANOTIFY_METADATA_LENGTH +
                 fid->length);

        assert(event->event_length == 64u);
        assert(event->descriptor == KERNEL_FANOTIFY_NOFD);
        assert(fid->information_type == KERNEL_FANOTIFY_INFO_TYPE_FID);
        assert(pidfd->information_type ==
               KERNEL_FANOTIFY_INFO_TYPE_PIDFD);
        assert(pidfd->length == KERNEL_FANOTIFY_PIDFD_INFO_LENGTH);
        assert(pidfd->descriptor == 180);
    }
    kernel_fanotify_release(combined_group);

    dfid_group = kernel_fanotify_create(
        KERNEL_FAN_NONBLOCK | KERNEL_FAN_REPORT_DIR_FID |
            KERNEL_FAN_REPORT_NAME,
        0u);
    assert(dfid_group >= 0);
    assert(kernel_fanotify_modify_mark(
               dfid_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_CREATE | KERNEL_FAN_EVENT_ON_CHILD,
               "/watched", 1) == 0);
    kernel_fanotify_notify_path("/watched/child", KERNEL_FAN_CREATE);
    assert(kernel_fanotify_read(
               dfid_group, copy_record, &copy,
               sizeof(copy.records[0])) == 64);
    {
        const kernel_fanotify_event_metadata_t *event =
            copied_event(&copy, 6u);
        const kernel_fanotify_event_info_fid_prefix_t *dfid =
            (const kernel_fanotify_event_info_fid_prefix_t *)(const void *)
                (copy.records[6] + KERNEL_FANOTIFY_METADATA_LENGTH);
        const char *name = (const char *)(const void *)(
            copy.records[6] + KERNEL_FANOTIFY_METADATA_LENGTH +
            KERNEL_FANOTIFY_FID_INFO_PREFIX_LENGTH +
            dfid->handle_bytes);

        assert(event->event_length == 64u);
        assert(event->descriptor == KERNEL_FANOTIFY_NOFD);
        assert(dfid->information_type ==
               KERNEL_FANOTIFY_INFO_TYPE_DFID_NAME);
        assert(dfid->length == 40u);
        assert(strcmp(name, "child") == 0);
        assert(strcmp(g_last_resolved_path, "/watched") == 0);
    }
    kernel_fanotify_release(dfid_group);

    permission_group = kernel_fanotify_create(
        KERNEL_FAN_CLASS_CONTENT, 0u);
    assert(permission_group >= 0);
    assert(kernel_fanotify_modify_mark(
               permission_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_OPEN_PERM, "/watched/permission", 0) == 0);
    g_permission_group = permission_group;
    g_permission_mode = 0;
    assert(kernel_fanotify_permission_check(
               "/watched/permission", KERNEL_FAN_OPEN_PERM) == 0);
    g_permission_mode = 1;
    assert(kernel_fanotify_permission_check(
               "/watched/permission", KERNEL_FAN_OPEN_PERM) ==
           -EDGE_LINUX_EPERM);
    g_permission_mode = 4;
    assert(kernel_fanotify_permission_check(
               "/watched/permission", KERNEL_FAN_OPEN_PERM) == 0);
    assert(g_permission_wait_count == 3);
    assert(g_permission_wake_count == 3);
    kernel_fanotify_release(permission_group);

    access_group = kernel_fanotify_create(
        KERNEL_FAN_CLASS_PRE_CONTENT, 0u);
    assert(access_group >= 0);
    assert(kernel_fanotify_modify_mark(
               access_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_PRE_ACCESS, "/watched/access", 0) == 0);
    assert(kernel_fanotify_modify_mark(
               access_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_PRE_ACCESS | KERNEL_FAN_ONDIR,
               "/watched", 1) == -EDGE_LINUX_EINVAL);
    g_permission_group = access_group;
    g_permission_mode = 0;
    g_permission_expected_mask = KERNEL_FAN_PRE_ACCESS;
    g_permission_expected_range = 1;
    g_permission_expected_range_offset = 4096u;
    g_permission_expected_range_count = 8192u;
    assert(kernel_fanotify_access_permission_check(
               "/watched/access", 4097u, 4096u) == 0);
    g_permission_expected_range_offset = 8192u;
    g_permission_expected_range_count = 4096u;
    assert(kernel_fanotify_pre_access_permission_check(
               "/watched/access", 8193u, 0u) == 0);
    assert(kernel_fanotify_access_permission_check("", 0u, 1u) == 0);
    assert(kernel_fanotify_access_permission_check(0, 0u, 1u) ==
           -EDGE_LINUX_EINVAL);
    kernel_fanotify_release(access_group);

    directory_group = kernel_fanotify_create(
        KERNEL_FAN_CLASS_CONTENT, 0u);
    assert(directory_group >= 0);
    assert(kernel_fanotify_modify_mark(
               directory_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_ACCESS_PERM | KERNEL_FAN_ONDIR,
               "/watched", 1) == 0);
    g_permission_group = directory_group;
    g_permission_expected_mask =
        KERNEL_FAN_ACCESS_PERM | KERNEL_FAN_ONDIR;
    g_permission_expected_range = 0;
    assert(kernel_fanotify_directory_access_permission_check(
               "/watched") == 0);
    kernel_fanotify_release(directory_group);

    exec_group = kernel_fanotify_create(
        KERNEL_FAN_CLASS_CONTENT, 0u);
    assert(exec_group >= 0);
    assert(kernel_fanotify_modify_mark(
               exec_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_OPEN_EXEC_PERM, "/watched/exec", 0) == 0);
    g_permission_group = exec_group;
    g_permission_expected_mask = KERNEL_FAN_OPEN_EXEC_PERM;
    g_permission_expected_range = 0;
    assert(kernel_fanotify_permission_check(
               "/watched/exec", KERNEL_FAN_OPEN_EXEC_PERM) == 0);
    kernel_fanotify_release(exec_group);

    precontent_group = kernel_fanotify_create(
        KERNEL_FAN_CLASS_PRE_CONTENT, 0u);
    assert(precontent_group >= 0);
    assert(kernel_fanotify_modify_mark(
               precontent_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_OPEN_PERM, "/watched/precontent", 0) == 0);
    g_permission_group = precontent_group;
    g_permission_mode = 2;
    g_permission_expected_mask = KERNEL_FAN_OPEN_PERM;
    assert(kernel_fanotify_permission_check(
               "/watched/precontent", KERNEL_FAN_OPEN_PERM) ==
           -EDGE_LINUX_EIO);
    kernel_fanotify_release(precontent_group);

    release_group = kernel_fanotify_create(
        KERNEL_FAN_CLASS_CONTENT, 0u);
    assert(release_group >= 0);
    assert(kernel_fanotify_modify_mark(
               release_group, KERNEL_FAN_MARK_ADD,
               KERNEL_FAN_OPEN_PERM, "/watched/release", 0) == 0);
    g_permission_group = release_group;
    g_permission_mode = 3;
    assert(kernel_fanotify_permission_check(
               "/watched/release", KERNEL_FAN_OPEN_PERM) == 0);
    assert(kernel_fanotify_query(release_group, &state) ==
           -EDGE_LINUX_EBADF);

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
