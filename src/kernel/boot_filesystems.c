/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-independent boot filesystem policy. */

#include "kernel/boot_filesystems.h"
#include "dev/devtmpfs.h"

#include "fs/procfs.h"
#include "fs/sysfs.h"
#include "vfs/vfs.h"

int kernel_boot_mount_api_filesystems(void) {
    vfs_inode_t inode;
    int result;

#ifdef CONFIG_DEVTMPFS_MOUNT
    (void)vfs_mkdir("/dev");
    result = devtmpfs_mount("devtmpfs", "/dev");
    if (result < 0) return result;
#endif

    (void)vfs_mkdir("/proc");
    (void)vfs_mkdir("/sys");
    result = procfs_mount("proc", "/proc");
    if (result < 0) return result;
    result = sysfs_mount("sysfs", "/sys");
    if (result < 0) return result;
    return vfs_resolve("/proc/cmdline", &inode, 0, 0, 0);
}
