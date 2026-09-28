/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * EdgeOS compatibility definitions used by imported storage headers.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_DISK_H
#define EDGEOS_COMPAT_FREEBSD_SYS_DISK_H

#include <sys/ioccom.h>

#define DISK_IDENT_SIZE 256
#define DIOCGSECTORSIZE _IOR('d', 128, unsigned int)
#define DIOCGMEDIASIZE _IOR('d', 129, off_t)
#define DIOCGIDENT _IOR('d', 137, char[DISK_IDENT_SIZE])

#endif
