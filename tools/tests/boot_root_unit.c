/* SPDX-License-Identifier: MPL-2.0 */
/* Shared root filesystem boot policy tests. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "kernel/boot_command_line.h"
#include "kernel/boot_root.h"
#include "vfs/vfs.h"

static block_device_t devices[3];
static uint8_t ext_superblock[136];
static uint8_t mbr_signature[4];
static block_device_t *mounted_device;
static char mounted_filesystem[32];
static uint32_t remount_flags;
static uint64_t fake_time;

static void reset_devices(void) {
    memset(devices, 0, sizeof(devices));
    strcpy(devices[0].name, "sda");
    strcpy(devices[1].name, "sda1");
    strcpy(devices[2].name, "vda");
    for (uint32_t index = 0; index < 3u; ++index) {
        devices[index].present = 1;
        devices[index].sector_size = 512u;
        devices[index].sector_count = 8192u;
    }
    devices[1].start_lba = 2048u;
    memset(ext_superblock, 0, sizeof(ext_superblock));
    ext_superblock[56] = 0x53u;
    ext_superblock[57] = 0xefu;
    for (uint32_t index = 0; index < 16u; ++index)
        ext_superblock[104u + index] = (uint8_t)index;
    memcpy(ext_superblock + 120u, "EDGE_ROOT", 9u);
    mbr_signature[0] = 0x78u;
    mbr_signature[1] = 0x56u;
    mbr_signature[2] = 0x34u;
    mbr_signature[3] = 0x12u;
    mounted_device = 0;
    mounted_filesystem[0] = 0;
    remount_flags = 0;
    fake_time = 0;
}

int block_count(void) {
    return 3;
}

block_device_t *block_get(int index) {
    return index >= 0 && index < block_count() ? &devices[index] : 0;
}

block_device_t *block_find(const char *name) {
    for (int index = 0; index < block_count(); ++index)
        if (strcmp(devices[index].name, name) == 0)
            return &devices[index];
    return 0;
}

block_device_t *block_find_linux_device(uint64_t device_number) {
    return device_number == 0x801u ? &devices[1] : 0;
}

int64_t block_read_bytes(block_device_t *device, uint64_t offset, void *output,
                         uint32_t length) {
    if (!device || !output) return -1;
    if (offset >= 1024u &&
        offset + length <= 1024u + sizeof(ext_superblock)) {
        memcpy(output, ext_superblock + offset - 1024u, length);
        return length;
    }
    if (device == &devices[0] && offset == 440u &&
        length == sizeof(mbr_signature)) {
        memcpy(output, mbr_signature, length);
        return length;
    }
    return -1;
}

int block_partition_parent_name(const block_device_t *device, char *output,
                                uint32_t capacity) {
    if (device != &devices[1] || !output || capacity < 4u) return -1;
    strcpy(output, "sda");
    return 0;
}

int block_partition_number(const block_device_t *device) {
    return device == &devices[1] ? 1 : 0;
}

int vfs_mount_blockdev(block_device_t *device, const char *target,
                       const char *filesystem) {
    if (!device || strcmp(target, "/") != 0 ||
        strcmp(filesystem, "ext4") != 0)
        return -1;
    mounted_device = device;
    strcpy(mounted_filesystem, filesystem);
    return 0;
}

int vfs_remount(const char *target, uint32_t flags) {
    if (strcmp(target, "/") != 0 || !mounted_device) return -1;
    remount_flags = flags;
    return 0;
}

uint64_t boottime_monotonic_us(void) {
    return fake_time++;
}

static void expect_resolved(const char *specification,
                            block_device_t *expected) {
    assert(kernel_boot_root_resolve_device(specification) == expected);
}

int main(void) {
    kernel_boot_root_policy_t policy;
    kernel_boot_root_result_t result;

    reset_devices();
    kernel_boot_command_line_set(
        "root=/dev/sda1 rootfstype=ext4 rootflags=nodev,noexec,relatime "
        "ro rw rootdelay=7 rootwait=12");
    assert(kernel_boot_root_policy_load(&policy) == 0);
    assert(policy.device_explicit == 1);
    assert(strcmp(policy.device_spec, "/dev/sda1") == 0);
    assert(strcmp(policy.filesystem_types, "ext4") == 0);
    assert(policy.delay_seconds == 7u);
    assert(policy.wait_for_device == 1);
    assert(policy.wait_forever == 0);
    assert(policy.wait_seconds == 12u);
    assert((policy.mount_flags & VFS_MOUNT_READONLY) == 0);
    assert((policy.mount_flags & VFS_MOUNT_NODEV) != 0);
    assert((policy.mount_flags & VFS_MOUNT_NOEXEC) != 0);
    assert((policy.mount_flags & VFS_MOUNT_RELATIME) != 0);

    kernel_boot_command_line_set("root=/dev/sda1 rw ro");
    assert(kernel_boot_root_policy_load(&policy) == 0);
    assert((policy.mount_flags & VFS_MOUNT_READONLY) != 0);
    assert(strcmp(policy.filesystem_types, "ext4,ext2") == 0);

    kernel_boot_command_line_set("root=/dev/sda1 rootwait");
    assert(kernel_boot_root_policy_load(&policy) == 0);
    assert(policy.wait_for_device == 1);
    assert(policy.wait_forever == 1);

    kernel_boot_command_line_set("root=/dev/sda1 rootflags=unknown");
    assert(kernel_boot_root_policy_load(&policy) == -1);
    kernel_boot_command_line_set("root=/dev/sda1 rootdelay=invalid");
    assert(kernel_boot_root_policy_load(&policy) == -1);

    expect_resolved("/dev/sda1", &devices[1]);
    expect_resolved("sda1", &devices[1]);
    expect_resolved("8:1", &devices[1]);
    expect_resolved("LABEL=EDGE_ROOT", &devices[0]);
    expect_resolved(
        "UUID=00010203-0405-0607-0809-0a0b0c0d0e0f", &devices[0]);
    expect_resolved("PARTUUID=12345678-01", &devices[1]);
    expect_resolved("/unsupported/path", 0);

    reset_devices();
    kernel_boot_command_line_set(
        "root=/dev/sda1 rootfstype=ext4 rw rootflags=nodev,noexec");
    assert(kernel_boot_root_mount(&result) == 0);
    assert(result.device == &devices[1]);
    assert(strcmp(result.filesystem_type, "ext4") == 0);
    assert((remount_flags & VFS_MOUNT_READONLY) == 0);
    assert((remount_flags & VFS_MOUNT_NODEV) != 0);
    assert((remount_flags & VFS_MOUNT_NOEXEC) != 0);

    reset_devices();
    kernel_boot_command_line_set("root=/dev/missing rw");
    assert(kernel_boot_root_mount(&result) == -1);
    assert(mounted_device == 0);

    reset_devices();
    kernel_boot_command_line_set("rw");
    assert(kernel_boot_root_mount(&result) == 0);
    assert(result.device == &devices[1]);
    assert(strcmp(mounted_filesystem, "ext4") == 0);
    return 0;
}
