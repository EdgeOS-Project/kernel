/* SPDX-License-Identifier: BSD-2-Clause */
/* Normalize EdgeOS Kconfig values before entering the FreeBSD LinuxKPI PCI header. */

#ifndef _EDGEOS_LINUXKPI_PREINCLUDE_PCI_H_
#define _EDGEOS_LINUXKPI_PREINCLUDE_PCI_H_

#undef CONFIG_PCI_MSI
#include_next <linux/pci.h>

#ifndef LKPI_PNP_INFO
#define LKPI_PNP_INFO(bus, name, table) \
    MODULE_PNP_INFO("U32:vendor;U32:device;", bus, name, table, \
        nitems(table) - 1)
#endif

#endif
