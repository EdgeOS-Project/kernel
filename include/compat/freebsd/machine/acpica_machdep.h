/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_ACPICA_MACHDEP_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_ACPICA_MACHDEP_H

#include <stdint.h>
#include <vm/vm.h>

#define ACPI_SYSTEM_XFACE
#define ACPI_EXTERNAL_XFACE
#define ACPI_INTERNAL_XFACE
#define ACPI_INTERNAL_VAR_XFACE

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#define ACPI_REDUCED_HARDWARE 1
#endif

#if defined(__x86_64__)
#define ACPI_DISABLE_IRQS() __asm__ __volatile__("cli" ::: "memory")
#define ACPI_ENABLE_IRQS() __asm__ __volatile__("sti" ::: "memory")
#define ACPI_FLUSH_CPU_CACHE() __asm__ __volatile__("wbinvd" ::: "memory")
void acpi_cpu_c1(void);
void acpi_cpu_idle_mwait(uint32_t hint);
#else
#define ACPI_FLUSH_CPU_CACHE() __asm__ volatile("" ::: "memory")
#endif

int bsd_acpi_acquire_global_lock(volatile uint32_t *lock);
int bsd_acpi_release_global_lock(volatile uint32_t *lock);
void *bsd_acpi_map_table(vm_paddr_t physical_address, const char *signature);
void bsd_acpi_unmap_table(void *table);
vm_paddr_t bsd_acpi_find_table(const char *signature);

#define acpi_map_table bsd_acpi_map_table
#define acpi_unmap_table bsd_acpi_unmap_table
#define acpi_find_table bsd_acpi_find_table

#define ACPI_ACQUIRE_GLOBAL_LOCK(global_lock, acquired)                  \
    do {                                                                 \
        (acquired) = bsd_acpi_acquire_global_lock(                       \
            &((global_lock)->GlobalLock));                               \
    } while (0)
#define ACPI_RELEASE_GLOBAL_LOCK(global_lock, pending)                   \
    do {                                                                 \
        (pending) = bsd_acpi_release_global_lock(                        \
            &((global_lock)->GlobalLock));                               \
    } while (0)

#endif
