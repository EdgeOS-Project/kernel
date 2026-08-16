/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-independent boot filesystem policy. */

#include "kernel/boot_filesystems.h"

#include "fs/sysfs.h"
#include "vfs/vfs.h"

int kernel_boot_mount_sysfs(void) {
    (void)vfs_mkdir("/sys");
    return sysfs_mount("sysfs", "/sys");
}
