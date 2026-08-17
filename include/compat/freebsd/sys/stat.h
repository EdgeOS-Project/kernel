/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_SYS_STAT_H
#define EDGEOS_COMPAT_FREEBSD_SYS_STAT_H

#include <sys/types.h>

#define S_IRWXU 0000700
#define S_IRUSR 0000400
#define S_IWUSR 0000200
#define S_IXUSR 0000100
#define S_IRWXG 0000070
#define S_IRGRP 0000040
#define S_IWGRP 0000020
#define S_IXGRP 0000010
#define S_IRWXO 0000007
#define S_IROTH 0000004
#define S_IWOTH 0000002
#define S_IXOTH 0000001

#endif
