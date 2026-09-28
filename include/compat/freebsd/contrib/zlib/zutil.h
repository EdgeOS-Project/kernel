/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_CONTRIB_ZLIB_ZUTIL_H
#define EDGEOS_COMPAT_FREEBSD_CONTRIB_ZLIB_ZUTIL_H

/*
 * FreeBSD kernel consumers use zlib's private allocation declarations.
 * Keep them on the prefixed, freestanding zlib instance linked by EdgeOS.
 */
#ifndef Z_SOLO
#define Z_SOLO 1
#endif
#ifndef Z_PREFIX
#define Z_PREFIX 1
#endif
#include <zutil.h>

#endif
