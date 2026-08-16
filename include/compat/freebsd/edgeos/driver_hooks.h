/* SPDX-License-Identifier: MPL-2.0 */
/* Attach lifecycle hooks for unmodified BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_DRIVER_HOOKS_H
#define EDGEOS_COMPAT_FREEBSD_DRIVER_HOOKS_H

#include <stdint.h>

#include "newbus.h"

typedef int (*bsd_driver_attach_begin_t)(device_t device,
    uintptr_t *cookie, void *context);
typedef void (*bsd_driver_attach_end_t)(device_t device,
    uintptr_t cookie, int result, void *context);

int bsd_driver_attach_hook_register(const char *driver_name,
    bsd_driver_attach_begin_t begin, bsd_driver_attach_end_t end,
    void *context);

#endif
