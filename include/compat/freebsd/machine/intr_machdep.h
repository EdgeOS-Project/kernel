/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_INTR_MACHDEP_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_INTR_MACHDEP_H

/*
 * x86 MSI messages target the local APIC window.  FreeBSD x86 PCI drivers
 * include this machine header for the architectural base address.
 */
#define MSI_INTEL_ADDR_BASE 0xfee00000UL

typedef void inthand_t(void);

#define IDTVEC(name) X ## name

extern int num_io_irqs;
extern int pti;
extern void IDTVEC(justreturn)(void);
extern void IDTVEC(justreturn1_pti)(void);
void intr_reprogram(void);
void intrcnt_add(const char *name, unsigned long **counter);

#endif
