/* SPDX-License-Identifier: BSD-2-Clause */
/* Kernel file information subset required by FreeBSD LinuxKPI. */

#ifndef _SYS_USER_H_
#define _SYS_USER_H_

#define KF_TYPE_VNODE 1
#define KF_TYPE_DEV 4

struct kinfo_file {
    int kf_type;
};

#endif
