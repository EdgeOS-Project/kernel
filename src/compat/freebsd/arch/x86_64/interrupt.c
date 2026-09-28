/* SPDX-License-Identifier: MPL-2.0 */
/* x86-64 interrupt adapter for the EdgeOS BSD Driver Bridge. */

#include <stdint.h>

#include "arch/x86_64/idt.h"
#include "arch/x86_64/isr.h"
#include "arch/x86_64/pic.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "drivers/apic.h"
#include <machine/intr_machdep.h>
#include <machine/segments.h>

typedef struct {
    void *isr_cookie;
    uint32_t vector;
    int32_t legacy_irq;
} bsd_x86_interrupt_cookie_t;

int num_io_irqs = NO_INTERRUPT_HANDLERS;
int pti;

#define BSD_X86_DYNAMIC_VECTOR_FIRST 48u
#define BSD_X86_DYNAMIC_VECTOR_LAST 63u

extern IDT g_idt[NO_IDT_DESCRIPTORS];

/* FreeBSD's VMM reads the host IDT through these machine-level symbols. */
struct gate_descriptor *idt = (struct gate_descriptor *)(void *)g_idt;
struct region_descriptor r_idt = {
    .rd_limit = sizeof(g_idt) - 1u,
};

__asm__(
    ".global Xjustreturn\n"
    "Xjustreturn:\n"
    "iretq\n"
    ".global Xjustreturn1_pti\n"
    "Xjustreturn1_pti:\n"
    "iretq\n");

#ifndef BSD_BRIDGE_HOST_TEST
static IDT bsd_x86_saved_dynamic_idt[
    BSD_X86_DYNAMIC_VECTOR_LAST - BSD_X86_DYNAMIC_VECTOR_FIRST + 1u];
static uint16_t bsd_x86_direct_dynamic_vectors;

static uint64_t
bsd_x86_disable_interrupts(void)
{
    uint64_t flags;

    __asm__ __volatile__("pushfq\n\tpopq %0\n\tcli" : "=r"(flags) ::
        "memory");
    return flags;
}

static void
bsd_x86_restore_interrupts(uint64_t flags)
{
    if ((flags & (UINT64_C(1) << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
}
#endif

int
lapic_ipi_alloc(inthand_t *handler)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)handler;
    return -1;
#else
    uint64_t flags;
    uint32_t vector;
    uint32_t index;

    if (!handler || apic_allocate_msi_vectors(1, 1, &vector) != 0)
        return -1;
    if (vector < BSD_X86_DYNAMIC_VECTOR_FIRST ||
        vector > BSD_X86_DYNAMIC_VECTOR_LAST) {
        apic_release_msi_vectors(&vector, 1);
        return -1;
    }
    index = vector - BSD_X86_DYNAMIC_VECTOR_FIRST;
    flags = bsd_x86_disable_interrupts();
    bsd_x86_saved_dynamic_idt[index] = g_idt[vector];
    idt_set_entry((int)vector, (uint64_t)(uintptr_t)handler, 0x08, 0x8e);
    bsd_x86_direct_dynamic_vectors |= (uint16_t)(UINT16_C(1) << index);
    bsd_x86_restore_interrupts(flags);
    return (int)vector;
#endif
}

void
lapic_ipi_free(int vector)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)vector;
#else
    uint64_t flags;
    uint32_t index;
    uint32_t released_vector;

    if (vector < (int)BSD_X86_DYNAMIC_VECTOR_FIRST ||
        vector > (int)BSD_X86_DYNAMIC_VECTOR_LAST)
        return;
    index = (uint32_t)vector - BSD_X86_DYNAMIC_VECTOR_FIRST;
    flags = bsd_x86_disable_interrupts();
    if ((bsd_x86_direct_dynamic_vectors &
        (uint16_t)(UINT16_C(1) << index)) == 0) {
        bsd_x86_restore_interrupts(flags);
        return;
    }
    g_idt[vector] = bsd_x86_saved_dynamic_idt[index];
    bsd_x86_direct_dynamic_vectors &=
        (uint16_t)~(UINT16_C(1) << index);
    bsd_x86_restore_interrupts(flags);
    released_vector = (uint32_t)vector;
    apic_release_msi_vectors(&released_vector, 1);
#endif
}

static uint32_t
bsd_x86_interrupt_vector(uint32_t interrupt)
{
    return interrupt < 16u ? IRQ_BASE + interrupt : interrupt;
}

static int
bsd_x86_register_interrupt(void *context, uint32_t interrupt,
    uint32_t flags, uint32_t interrupt_flags,
    bsd_interrupt_backend_callback_t callback, void *argument,
    void **backend_cookie)
{
    bsd_x86_interrupt_cookie_t *cookie;
    uint32_t vector;

    (void)context;
    (void)flags;
    (void)interrupt_flags;
    vector = bsd_x86_interrupt_vector(interrupt);
    if (vector >= NO_INTERRUPT_HANDLERS || !callback ||
        !backend_cookie)
        return 22;
    cookie = bsd_malloc(sizeof(*cookie), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!cookie)
        return 12;
    cookie->vector = vector;
    cookie->legacy_irq = interrupt < 16u ? (int32_t)interrupt : -1;
    if (isr_register_context_interrupt_handler((int)vector,
        callback, argument, &cookie->isr_cookie) != 0) {
        bsd_free(cookie, M_DEVBUF);
        return 16;
    }
    if (cookie->legacy_irq >= 0)
        pic8259_unmask_irq((uint8_t)cookie->legacy_irq);
    *backend_cookie = cookie;
    return 0;
}

static int
bsd_x86_unregister_interrupt(void *context, void *opaque_cookie)
{
    bsd_x86_interrupt_cookie_t *cookie = opaque_cookie;
    uint32_t vector;

    (void)context;
    if (!cookie)
        return 22;
    vector = cookie->vector;
    if (isr_unregister_context_interrupt_handler(cookie->isr_cookie) != 0)
        return 22;
    if (cookie->legacy_irq >= 0 &&
        !isr_interrupt_has_handler((int)vector))
        pic8259_mask_irq((uint8_t)cookie->legacy_irq);
    bsd_free(cookie, M_DEVBUF);
    return 0;
}

static int
bsd_x86_mask_interrupt(void *context, void *opaque_cookie)
{
    bsd_x86_interrupt_cookie_t *cookie = opaque_cookie;

    (void)context;
    if (!cookie)
        return 22;
    if (cookie->legacy_irq >= 0)
        pic8259_mask_irq((uint8_t)cookie->legacy_irq);
    return 0;
}

static int
bsd_x86_unmask_interrupt(void *context, void *opaque_cookie)
{
    bsd_x86_interrupt_cookie_t *cookie = opaque_cookie;

    (void)context;
    if (!cookie)
        return 22;
    if (cookie->legacy_irq >= 0)
        pic8259_unmask_irq((uint8_t)cookie->legacy_irq);
    return 0;
}

int
bsd_interrupt_arch_initialize(void)
{
    bsd_interrupt_backend_ops_t operations = {
        .register_interrupt = bsd_x86_register_interrupt,
        .unregister_interrupt = bsd_x86_unregister_interrupt,
        .mask_interrupt = bsd_x86_mask_interrupt,
        .unmask_interrupt = bsd_x86_unmask_interrupt,
    };

    r_idt.rd_base = (uint64_t)(uintptr_t)g_idt;
    return bsd_interrupt_initialize(&operations);
}
