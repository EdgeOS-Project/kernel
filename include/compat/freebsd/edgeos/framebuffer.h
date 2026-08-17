/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS frontend for imported FreeBSD framebuffer registrations. */

#ifndef EDGEOS_COMPAT_FREEBSD_FRAMEBUFFER_H
#define EDGEOS_COMPAT_FREEBSD_FRAMEBUFFER_H

#include <stdint.h>

struct fb_info;

typedef struct bsd_framebuffer_status {
    uint32_t registrations;
    uint32_t removals;
    uint32_t rejected;
    const struct fb_info *active;
} bsd_framebuffer_status_t;

int bsd_framebuffer_runtime_initialize(void);
void bsd_framebuffer_runtime_shutdown(void);
void bsd_framebuffer_get_status(bsd_framebuffer_status_t *status);

#endif
