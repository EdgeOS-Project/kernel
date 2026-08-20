/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS x86 APIC/MSI support.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_APIC_H
#define EDGEOS_DRIVERS_APIC_H

#include <stdint.h>

#define APIC_RESCHEDULE_VECTOR 0xF0u
#define APIC_TIMER_VECTOR 0xF1u
#define APIC_TLB_VECTOR 0xF2u

void apic_init(void);
int apic_available(void);
uint32_t apic_local_id(void);
int apic_init_local(void);
int apic_send_fixed_ipi(uint32_t apic_id, uint8_t vector);
int apic_start_processor(uint32_t apic_id, uint8_t startup_vector);
int apic_timer_init(uint32_t ticks_per_second);
void apic_timer_pause_periodic(void);
void apic_timer_resume_periodic(void);
int apic_timer_arm_oneshot_us(uint32_t microseconds);
void apic_timer_cancel_oneshot(void);
int apic_timer_consume_oneshot(void);
void apic_eoi(void);
int apic_enable_performance_interrupt(void);
void apic_disable_performance_interrupt(void);
void apic_reenable_performance_interrupt(void);
int apic_allocate_msi_vector(void);
int apic_allocate_msi_vectors(unsigned int count, int contiguous,
                              uint32_t *vectors);
void apic_release_msi_vectors(const uint32_t *vectors,
                              unsigned int count);
int pci_enable_msi_vector(uint8_t bus, uint8_t slot, uint8_t func, uint8_t vector);
int pci_enable_msi_vectors(uint8_t bus, uint8_t slot, uint8_t func,
                           const uint32_t *vectors, unsigned int count);
int pci_disable_msi_vectors(uint8_t bus, uint8_t slot, uint8_t func);
int pci_enable_msix_vector(uint8_t bus, uint8_t slot, uint8_t func,
                           uint16_t table_index, uint8_t vector);
int pci_disable_msix_vector(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t table_index);
int pci_disable_msix_vectors(uint8_t bus, uint8_t slot, uint8_t func);

#endif
