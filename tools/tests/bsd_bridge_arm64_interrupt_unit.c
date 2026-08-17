/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the ARM64 BSD bridge interrupt adapter. */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "arch/arm64/interrupt.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"

static bsd_interrupt_backend_ops_t g_operations;
static edgeos_arm64_irq_callback_t g_callback;
static void *g_callback_context;
static uint32_t g_interrupt;
static uint32_t g_flags;
static int g_mask_count;
static int g_unmask_count;

struct malloc_type M_DEVBUF[1];

int bsd_interrupt_arch_initialize(void);

int
bsd_interrupt_initialize(const bsd_interrupt_backend_ops_t *operations)
{
    g_operations = *operations;
    return 0;
}

void *
bsd_malloc(size_t size, struct malloc_type *type, int flags)
{
    static uint8_t storage[64];

    (void)type;
    (void)flags;
    assert(size <= sizeof(storage));
    return storage;
}

void
bsd_free(void *address, struct malloc_type *type)
{
    (void)address;
    (void)type;
}

int
edgeos_arm64_irq_register(uint32_t interrupt, uint32_t flags,
    edgeos_arm64_irq_callback_t callback, void *context)
{
    g_interrupt = interrupt;
    g_flags = flags;
    g_callback = callback;
    g_callback_context = context;
    return 0;
}

int
edgeos_arm64_irq_unregister(uint32_t interrupt,
    edgeos_arm64_irq_callback_t callback, void *context)
{
    assert(interrupt == g_interrupt);
    assert(callback == g_callback);
    assert(context == g_callback_context);
    return 0;
}

int
edgeos_arm64_irq_mask(uint32_t interrupt)
{
    assert(interrupt == g_interrupt);
    g_mask_count++;
    return 0;
}

int
edgeos_arm64_irq_unmask(uint32_t interrupt)
{
    assert(interrupt == g_interrupt);
    g_unmask_count++;
    return 0;
}

static void
test_dispatch(void *argument)
{
    int *count = argument;

    (*count)++;
}

int
main(void)
{
    void *cookie = 0;
    int dispatch_count = 0;

    assert(bsd_interrupt_arch_initialize() == 0);
    assert(g_operations.register_interrupt != 0);
    assert(g_operations.unregister_interrupt != 0);
    assert(g_operations.mask_interrupt != 0);
    assert(g_operations.unmask_interrupt != 0);
    assert(g_operations.register_interrupt(g_operations.context, 36, 0,
        4, test_dispatch, &dispatch_count, &cookie) == 0);
    assert(g_interrupt == 36);
    assert(g_flags == 4);
    g_callback(g_interrupt, g_callback_context);
    assert(dispatch_count == 1);
    assert(g_operations.mask_interrupt(g_operations.context, cookie) == 0);
    assert(g_mask_count == 1);
    assert(g_operations.unmask_interrupt(g_operations.context, cookie) == 0);
    assert(g_unmask_count == 1);
    assert(g_operations.unregister_interrupt(
        g_operations.context, cookie) == 0);
    return 0;
}
