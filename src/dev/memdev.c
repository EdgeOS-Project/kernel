/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Linux memory character devices shared by every EdgeOS architecture.
 * Copyright (c) EdgeOS Contributors.
 */

#include "dev/memdev.h"

#include "kernel/random.h"
#include "fs/fuse.h"
#include "string.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cdev.h"
#endif

#define LINUX_EFAULT 14
#define LINUX_ENOSPC 28

static uint32_t linux_device_major(uint64_t device) {
    return (uint32_t)((device >> 8) & 0xfffu) |
           (uint32_t)((device >> 32) & ~0xfffull);
}

static uint32_t linux_device_minor(uint64_t device) {
    return (uint32_t)(device & 0xffu) |
           (uint32_t)((device >> 12) & ~0xffull);
}

int edge_memdev_read_description(uint64_t linux_rdev,
                                 uint64_t description_identity,
                                 void *buffer, uint32_t length) {
    uint32_t major = linux_device_major(linux_rdev);
    uint32_t minor = linux_device_minor(linux_rdev);
#ifdef CONFIG_FUSE_FS
    if (edge_fuse_is_device(linux_rdev)) {
        int result = edge_fuse_device_read(
            description_identity, buffer, length);
        return result == EDGE_FUSE_NOT_HANDLED ? -LINUX_ENOSPC : result;
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    int bridge_result =
        bsd_bridge_cdev_read_session(
            linux_rdev, description_identity, buffer, length);
    if (bridge_result != BSD_BRIDGE_CDEV_NOT_HANDLED)
        return bridge_result;
#endif
    if (major != 1u) return EDGE_MEMDEV_NOT_HANDLED;
    if (!buffer && length) return -LINUX_EFAULT;
    switch (minor) {
        case 3u:
            return 0;
        case 5u:
        case 7u:
            if (length) memset(buffer, 0, length);
            return (int)length;
        case 8u:
        case 9u:
            edge_random_fill(buffer, length);
            return (int)length;
        default:
            return EDGE_MEMDEV_NOT_HANDLED;
    }
}

int edge_memdev_read(uint64_t linux_rdev, void *buffer, uint32_t length) {
    return edge_memdev_read_description(linux_rdev, 0, buffer, length);
}

int edge_memdev_write_description(uint64_t linux_rdev,
                                  uint64_t description_identity,
                                  const void *buffer, uint32_t length) {
    uint32_t major = linux_device_major(linux_rdev);
    uint32_t minor = linux_device_minor(linux_rdev);
#ifdef CONFIG_FUSE_FS
    if (edge_fuse_is_device(linux_rdev)) {
        int result = edge_fuse_device_write(
            description_identity, buffer, length);
        return result == EDGE_FUSE_NOT_HANDLED ? -LINUX_ENOSPC : result;
    }
#endif
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    int bridge_result =
        bsd_bridge_cdev_write_session(
            linux_rdev, description_identity, buffer, length);
    if (bridge_result != BSD_BRIDGE_CDEV_NOT_HANDLED)
        return bridge_result;
#endif
    if (major != 1u) return EDGE_MEMDEV_NOT_HANDLED;
    if (!buffer && length) return -LINUX_EFAULT;
    switch (minor) {
        case 3u:
        case 5u:
            return (int)length;
        case 7u:
            return -LINUX_ENOSPC;
        case 8u:
        case 9u:
            edge_random_mix(buffer, length);
            return (int)length;
        default:
            return EDGE_MEMDEV_NOT_HANDLED;
    }
}

int edge_memdev_write(uint64_t linux_rdev, const void *buffer,
                      uint32_t length) {
    return edge_memdev_write_description(
        linux_rdev, 0, buffer, length);
}
