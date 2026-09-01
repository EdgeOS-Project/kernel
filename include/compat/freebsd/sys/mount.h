/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD mount type declarations used by source-compatible drivers. */

#ifndef _SYS_MOUNT_H_
#define _SYS_MOUNT_H_

struct mount {
    unsigned long mnt_flag;
};
struct vnode;

#define MNT_NOEXEC 0x00000004u

#endif
