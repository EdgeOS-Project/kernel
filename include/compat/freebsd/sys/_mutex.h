/* SPDX-License-Identifier: MPL-2.0 */
/* Internal mutex representation shared by all BSD bridge consumers. */

#ifndef _SYS__MUTEX_H_
#define _SYS__MUTEX_H_

#include "../edgeos/sync.h"
#include "_lock.h"

struct mtx {
    bsd_mutex_t edgeos_mutex;
    struct lock_object lock_object;
};

/*
 * FreeBSD's pad-aligned mutex has the same callable layout as struct mtx.
 * EdgeOS mutex storage is already opaque to imported drivers, so use the
 * common representation and preserve the source-level type name.
 */
#define mtx_padalign mtx

#endif
