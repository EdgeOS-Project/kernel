/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 interrupt adapter for the EdgeOS BSD Driver Bridge. */

#include <stdint.h>

#include "arch/arm64/interrupt.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"

typedef struct {
    bsd_interrupt_backend_callback_t callback;
    void *argument;
    uint32_t interrupt;
} bsd_arm64_interrupt_cookie_t;

static void
bsd_arm64_interrupt_dispatch(uint32_t interrupt, void *opaque_cookie)
{
    bsd_arm64_interrupt_cookie_t *cookie = opaque_cookie;

    (void)interrupt;
    cookie->callback(cookie->argument);
}

static int
bsd_arm64_register_interrupt(void *context, uint32_t interrupt,
    uint32_t flags, uint32_t interrupt_flags,
    bsd_interrupt_backend_callback_t callback, void *argument,
    void **backend_cookie)
{
    bsd_arm64_interrupt_cookie_t *cookie;

    (void)context;
    cookie = bsd_malloc(sizeof(*cookie), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!cookie)
        return 12;
    cookie->callback = callback;
    cookie->argument = argument;
    cookie->interrupt = interrupt;
    (void)flags;
    if (edgeos_arm64_irq_register(interrupt, interrupt_flags,
        bsd_arm64_interrupt_dispatch, cookie) != 0) {
        bsd_free(cookie, M_DEVBUF);
        return 16;
    }
    *backend_cookie = cookie;
    return 0;
}

static int
bsd_arm64_unregister_interrupt(void *context, void *opaque_cookie)
{
    bsd_arm64_interrupt_cookie_t *cookie = opaque_cookie;

    (void)context;
    if (!cookie ||
        edgeos_arm64_irq_unregister(cookie->interrupt,
            bsd_arm64_interrupt_dispatch, cookie) != 0)
        return 22;
    bsd_free(cookie, M_DEVBUF);
    return 0;
}

static int
bsd_arm64_mask_interrupt(void *context, void *opaque_cookie)
{
    bsd_arm64_interrupt_cookie_t *cookie = opaque_cookie;

    (void)context;
    return cookie && edgeos_arm64_irq_mask(cookie->interrupt) == 0 ?
        0 : 22;
}

static int
bsd_arm64_unmask_interrupt(void *context, void *opaque_cookie)
{
    bsd_arm64_interrupt_cookie_t *cookie = opaque_cookie;

    (void)context;
    return cookie && edgeos_arm64_irq_unmask(cookie->interrupt) == 0 ?
        0 : 22;
}

int
bsd_interrupt_arch_initialize(void)
{
    bsd_interrupt_backend_ops_t operations = {
        .register_interrupt = bsd_arm64_register_interrupt,
        .unregister_interrupt = bsd_arm64_unregister_interrupt,
        .mask_interrupt = bsd_arm64_mask_interrupt,
        .unmask_interrupt = bsd_arm64_unmask_interrupt,
    };

    return bsd_interrupt_initialize(&operations);
}
