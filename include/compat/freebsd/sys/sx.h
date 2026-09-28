/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD sleepable reader/writer lock API on the shared EdgeOS runtime. */

#ifndef _SYS_SX_H_
#define _SYS_SX_H_

#include "kernel.h"
#include "lock.h"

struct bsd_sx_sysinit_args {
    struct sx *lock;
    const char *description;
    int options;
};

static inline void
bsd_sx_sysinit(const void *argument)
{
    const struct bsd_sx_sysinit_args *args = argument;

    sx_init_flags(args->lock, args->description, args->options);
}

static inline void
bsd_sx_sysuninit(const void *argument)
{
    sx_destroy((struct sx *)(uintptr_t)argument);
}

#define SX_SYSINIT_FLAGS(name, lock_value, description_value, options_value) \
    static const struct bsd_sx_sysinit_args name##_args = {                  \
        (lock_value), (description_value), (options_value),                  \
    };                                                                       \
    C_SYSINIT(name##_sx_sysinit, SI_SUB_LOCK, SI_ORDER_MIDDLE,              \
        bsd_sx_sysinit, &name##_args);                                        \
    C_SYSUNINIT(name##_sx_sysuninit, SI_SUB_LOCK, SI_ORDER_MIDDLE,          \
        bsd_sx_sysuninit, (lock_value))

#define SX_SYSINIT(name, lock_value, description_value) \
    SX_SYSINIT_FLAGS(name, lock_value, description_value, 0)

#endif
