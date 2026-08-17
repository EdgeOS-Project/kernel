/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the x86_64 BSD bridge interrupt adapter. */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "arch/x86_64/isr.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"

static bsd_interrupt_backend_ops_t g_operations;
static ISR_CONTEXT g_callback;
static void *g_callback_context;
static int g_vector;
static int g_masked_irq = -1;
static int g_unmasked_irq = -1;
static uint8_t g_isr_cookie;
static uint8_t g_allocation[64];

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
    (void)type;
    (void)flags;
    assert(size <= sizeof(g_allocation));
    return g_allocation;
}

void
bsd_free(void *address, struct malloc_type *type)
{
    assert(address == g_allocation);
    (void)type;
}

int
isr_register_context_interrupt_handler(int vector, ISR_CONTEXT callback,
    void *context, void **cookie)
{
    g_vector = vector;
    g_callback = callback;
    g_callback_context = context;
    *cookie = &g_isr_cookie;
    return 0;
}

int
isr_unregister_context_interrupt_handler(void *cookie)
{
    assert(cookie == &g_isr_cookie);
    g_callback = 0;
    g_callback_context = 0;
    return 0;
}

int
isr_interrupt_has_handler(int vector)
{
    assert(vector == g_vector);
    return 0;
}

void
pic8259_mask_irq(uint8_t irq)
{
    g_masked_irq = irq;
}

void
pic8259_unmask_irq(uint8_t irq)
{
    g_unmasked_irq = irq;
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

    assert(g_operations.register_interrupt(g_operations.context, 1, 0,
        0, test_dispatch, &dispatch_count, &cookie) == 0);
    assert(g_vector == IRQ_BASE + 1);
    assert(g_unmasked_irq == 1);
    g_callback(g_callback_context);
    assert(dispatch_count == 1);
    assert(g_operations.mask_interrupt(g_operations.context, cookie) == 0);
    assert(g_masked_irq == 1);
    assert(g_operations.unmask_interrupt(g_operations.context, cookie) == 0);
    assert(g_unmasked_irq == 1);
    assert(g_operations.unregister_interrupt(
        g_operations.context, cookie) == 0);
    assert(g_masked_irq == 1);

    g_masked_irq = -1;
    g_unmasked_irq = -1;
    assert(g_operations.register_interrupt(g_operations.context, 64, 0,
        0, test_dispatch, &dispatch_count, &cookie) == 0);
    assert(g_vector == 64);
    assert(g_unmasked_irq == -1);
    assert(g_operations.mask_interrupt(g_operations.context, cookie) == 0);
    assert(g_masked_irq == -1);
    assert(g_operations.unregister_interrupt(
        g_operations.context, cookie) == 0);
    assert(g_masked_irq == -1);
    return 0;
}
