/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux mount snapshot formatting. */

#include <stdint.h>

#include "string.h"
#include "vfs/mount_namespace.h"
#include "vfs/vfs.h"

typedef struct vfs_mount_snapshot_writer {
    char *buffer;
    uint32_t capacity;
    uint32_t copied;
    uint64_t offset;
    uint64_t length;
} vfs_mount_snapshot_writer_t;

static void mount_snapshot_append_byte(vfs_mount_snapshot_writer_t *writer,
                                       char byte) {
    if (writer->length >= writer->offset &&
        writer->copied < writer->capacity)
        writer->buffer[writer->copied++] = byte;
    ++writer->length;
}

static void mount_snapshot_append(vfs_mount_snapshot_writer_t *writer,
                                  const char *text) {
    if (!text) return;
    while (*text) mount_snapshot_append_byte(writer, *text++);
}

static void mount_snapshot_append_u64(vfs_mount_snapshot_writer_t *writer,
                                      uint64_t value) {
    char digits[20];
    uint32_t count = 0;
    if (!value) {
        mount_snapshot_append_byte(writer, '0');
        return;
    }
    while (value && count < sizeof(digits)) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) mount_snapshot_append_byte(writer, digits[--count]);
}

static void mount_snapshot_append_escaped(
    vfs_mount_snapshot_writer_t *writer, const char *text) {
    while (text && *text) {
        switch (*text) {
        case ' ':
            mount_snapshot_append(writer, "\\040");
            break;
        case '\t':
            mount_snapshot_append(writer, "\\011");
            break;
        case '\n':
            mount_snapshot_append(writer, "\\012");
            break;
        case '\\':
            mount_snapshot_append(writer, "\\134");
            break;
        default:
            mount_snapshot_append_byte(writer, *text);
            break;
        }
        ++text;
    }
}

static void mount_snapshot_append_options(
    vfs_mount_snapshot_writer_t *writer, const vfs_superblock_t *mount) {
    mount_snapshot_append(writer,
                          mount->mount_flags & VFS_MOUNT_READONLY ?
                          "ro" : "rw");
    if (mount->mount_flags & VFS_MOUNT_NOSUID)
        mount_snapshot_append(writer, ",nosuid");
    if (mount->mount_flags & VFS_MOUNT_NODEV)
        mount_snapshot_append(writer, ",nodev");
    if (mount->mount_flags & VFS_MOUNT_NOEXEC)
        mount_snapshot_append(writer, ",noexec");
    if (mount->mount_flags & VFS_MOUNT_NOATIME)
        mount_snapshot_append(writer, ",noatime");
    if (mount->mount_flags & VFS_MOUNT_NODIRATIME)
        mount_snapshot_append(writer, ",nodiratime");
    if (mount->mount_flags & VFS_MOUNT_RELATIME)
        mount_snapshot_append(writer, ",relatime");
}

static int mount_snapshot_render(vfs_mount_snapshot_writer_t *writer,
                                 int mountinfo) {
    const vfs_mount_table_t *table = vfs_mount_namespace_active_table();
    if (!writer || !table || table->mount_count < 0) return -1;
    for (int index = 0; index < table->mount_count; ++index) {
        const vfs_superblock_t *mount =
            vfs_mount_table_at_const(table, (uint32_t)index);
        const char *device;
        const char *mountpoint;
        const char *filesystem;
        if (!mount) return -1;
        device = mount->dev_name[0] ? mount->dev_name : "none";
        mountpoint = mount->mountpoint[0] ? mount->mountpoint : "/";
        filesystem = mount->fs_name[0] ? mount->fs_name : "unknown";
        if (!mountinfo) {
            mount_snapshot_append_escaped(writer, device);
            mount_snapshot_append_byte(writer, ' ');
            mount_snapshot_append_escaped(writer, mountpoint);
            mount_snapshot_append_byte(writer, ' ');
            mount_snapshot_append_escaped(writer, filesystem);
            mount_snapshot_append_byte(writer, ' ');
            mount_snapshot_append_options(writer, mount);
            mount_snapshot_append(writer, " 0 0\n");
            continue;
        }
        mount_snapshot_append_u64(writer, mount->mount_id);
        mount_snapshot_append_byte(writer, ' ');
        mount_snapshot_append_u64(writer, mount->parent_mount_id);
        mount_snapshot_append(writer, " 0:0 / ");
        mount_snapshot_append_escaped(writer, mountpoint);
        mount_snapshot_append_byte(writer, ' ');
        mount_snapshot_append_options(writer, mount);
        mount_snapshot_append_byte(writer, ' ');
        if (mount->peer_group) {
            mount_snapshot_append(writer, "shared:");
            mount_snapshot_append_u64(writer, mount->peer_group);
            mount_snapshot_append_byte(writer, ' ');
        }
        if (mount->master_group) {
            mount_snapshot_append(writer, "master:");
            mount_snapshot_append_u64(writer, mount->master_group);
            mount_snapshot_append_byte(writer, ' ');
        }
        if (mount->propagation == VFS_MOUNT_UNBINDABLE)
            mount_snapshot_append(writer, "unbindable ");
        mount_snapshot_append(writer, "- ");
        mount_snapshot_append_escaped(writer, filesystem);
        mount_snapshot_append_byte(writer, ' ');
        mount_snapshot_append_escaped(writer, device);
        mount_snapshot_append_byte(writer, ' ');
        mount_snapshot_append_options(writer, mount);
        mount_snapshot_append_byte(writer, '\n');
    }
    return 0;
}

int vfs_mount_snapshot_read(int mountinfo, uint64_t offset,
                            void *buffer, uint32_t length) {
    vfs_mount_snapshot_writer_t writer;
    if ((!buffer && length) || (mountinfo != 0 && mountinfo != 1)) return -1;
    memset(&writer, 0, sizeof(writer));
    writer.buffer = (char *)buffer;
    writer.capacity = length;
    writer.offset = offset;
    if (mount_snapshot_render(&writer, mountinfo) < 0) return -1;
    return (int)writer.copied;
}

static int mount_snapshot_full(char *buffer, uint32_t capacity,
                               int mountinfo) {
    vfs_mount_snapshot_writer_t writer;
    if (!buffer || !capacity) return -1;
    memset(&writer, 0, sizeof(writer));
    writer.buffer = buffer;
    writer.capacity = capacity - 1u;
    if (mount_snapshot_render(&writer, mountinfo) < 0 ||
        writer.length > writer.copied) {
        buffer[writer.copied] = 0;
        return -1;
    }
    buffer[writer.copied] = 0;
    return (int)writer.copied;
}

int vfs_mounts_snapshot(char *buffer, uint32_t capacity) {
    return mount_snapshot_full(buffer, capacity, 0);
}

int vfs_mountinfo_snapshot(char *buffer, uint32_t capacity) {
    return mount_snapshot_full(buffer, capacity, 1);
}
