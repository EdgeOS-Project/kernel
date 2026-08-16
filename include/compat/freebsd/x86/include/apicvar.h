/* SPDX-License-Identifier: BSD-2-Clause */
/* EdgeOS APIC discovery boundary for imported FreeBSD IOMMU drivers. */

#ifndef _X86_APICVAR_H_
#define _X86_APICVAR_H_

#include <sys/bus.h>
#include <machine/intr_machdep.h>

#define IRQ_EXTINT (-1)
#define IRQ_NMI (-2)
#define IRQ_SMI (-3)

extern int x2apic_mode;
extern int apic_ext_dest_id;

int ioapic_get_rid(unsigned int apic_id, uint16_t *rid);
device_t ioapic_get_dev(unsigned int apic_id);
unsigned int apic_cpuid(unsigned int apic_id);
int lapic_ipi_alloc(inthand_t *handler);
void lapic_ipi_free(int vector);
int lapic_enable_pcint(void);
void lapic_disable_pcint(void);
void lapic_reenable_pcint(void);

#endif
