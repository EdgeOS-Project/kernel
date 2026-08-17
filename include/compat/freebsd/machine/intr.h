/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Machine interrupt compatibility boundary.
 *
 * Imported drivers use the architecture-neutral newbus interrupt API.
 * Architecture interrupt mechanics remain in the EdgeOS interrupt backend.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_INTR_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_INTR_H

#include "../edgeos/interrupt.h"

#ifdef DEV_ACPI
#define ACPI_INTR_XREF 1
#define ACPI_MSI_XREF 2
#define ACPI_GPIO_XREF 3
#endif

#ifdef INTRNG
#include <sys/cpuset.h>

int intr_alloc_msi(device_t pci, device_t child, intptr_t xref,
    int count, int maxcount, int *irqs);
int intr_release_msi(device_t pci, device_t child, intptr_t xref,
    int count, int *irqs);
int intr_map_msi(device_t pci, device_t child, intptr_t xref, int irq,
    uint64_t *address, uint32_t *data);
int intr_alloc_msix(device_t pci, device_t child, intptr_t xref, int *irq);
int intr_release_msix(device_t pci, device_t child, intptr_t xref, int irq);

/*
 * Imported ARM interrupt controllers use this hook to make register writes
 * visible before returning from their filter.  Keep the policy shared while
 * selecting only the hardware ordering primitive at this machine boundary.
 */
#ifndef _MACHINE_INTR_H_
static inline void
arm_irq_memory_barrier(uintptr_t irq)
{
    (void)irq;
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    __asm__ __volatile__("dmb ish" ::: "memory");
#else
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
}
#endif
#endif

#endif
