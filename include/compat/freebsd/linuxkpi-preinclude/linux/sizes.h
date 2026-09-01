/* SPDX-License-Identifier: BSD-2-Clause */
/* Width-correct large size constants for FreeBSD LinuxKPI. */

#ifndef EDGEOS_LINUXKPI_PREINCLUDE_SIZES_H
#define EDGEOS_LINUXKPI_PREINCLUDE_SIZES_H

#include_next <linux/sizes.h>

#undef SZ_1G
#undef SZ_2G
#undef SZ_4G
#undef SZ_8G
#undef SZ_16G
#undef SZ_32G
#undef SZ_64T
#define SZ_1G  (1024ULL * 1024 * 1024)
#define SZ_2G  (SZ_1G * 2)
#define SZ_4G  (SZ_1G * 4)
#define SZ_8G  (SZ_1G * 8)
#define SZ_16G (SZ_1G * 16)
#define SZ_32G (SZ_1G * 32)
#define SZ_64T (SZ_1G * 65536ULL)

#endif
