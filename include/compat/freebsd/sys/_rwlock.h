/* SPDX-License-Identifier: MPL-2.0 */
/* Internal reader/writer lock representation for BSD bridge consumers. */

#ifndef _SYS__RWLOCK_H_
#define _SYS__RWLOCK_H_

#include "_lock.h"
#include "../edgeos/sync.h"

struct rwlock {
    struct lock_object lock_object;
    bsd_rwlock_t edgeos_lock;
};

struct rwlock_padalign {
    struct lock_object lock_object;
    bsd_rwlock_t edgeos_lock;
};

#endif
