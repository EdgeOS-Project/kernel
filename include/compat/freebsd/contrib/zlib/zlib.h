/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_CONTRIB_ZLIB_ZLIB_H
#define EDGEOS_COMPAT_FREEBSD_CONTRIB_ZLIB_ZLIB_H

/*
 * Keep FreeBSD drivers on the same prefixed, freestanding zlib interface
 * that is already linked into the EdgeOS kernel.
 */
#ifndef Z_SOLO
#define Z_SOLO 1
#endif
#ifndef Z_PREFIX
#define Z_PREFIX 1
#endif
#include <zlib.h>

#endif
