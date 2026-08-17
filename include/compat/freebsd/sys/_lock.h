/* SPDX-License-Identifier: MPL-2.0 */
/* Internal lock object shared by the public BSD bridge lock headers. */

#ifndef _SYS__LOCK_H_
#define _SYS__LOCK_H_

#include <stdint.h>

#define BSD_LOCK_OBJECT_SPIN 0x00000001u

typedef void (*bsd_lock_object_lock_fn)(void *data);
typedef int (*bsd_lock_object_trylock_fn)(void *data);
typedef void (*bsd_lock_object_unlock_fn)(void *data);
typedef int (*bsd_lock_object_owned_fn)(void *data);

struct lock_object {
    void *lo_data;
    const char *lo_name;
    bsd_lock_object_lock_fn lo_lock;
    bsd_lock_object_trylock_fn lo_trylock;
    bsd_lock_object_unlock_fn lo_unlock;
    bsd_lock_object_owned_fn lo_owned;
    uint32_t lo_flags;
};

#ifndef LOCK_FILE
#define LOCK_FILE __FILE__
#endif

#ifndef LOCK_LINE
#define LOCK_LINE __LINE__
#endif

#endif
