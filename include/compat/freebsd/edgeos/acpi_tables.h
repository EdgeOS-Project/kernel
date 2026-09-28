/* SPDX-License-Identifier: MPL-2.0 */
/* Shared firmware-table services for imported BSD ACPI drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_EDGEOS_ACPI_TABLES_H
#define EDGEOS_COMPAT_FREEBSD_EDGEOS_ACPI_TABLES_H

#include <stdint.h>

void bsd_acpi_tables_install_rsdp(uint64_t physical_address);
uint64_t bsd_acpi_tables_rsdp_address(void);

#endif
