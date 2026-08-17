/* SPDX-License-Identifier: MPL-2.0 */
/* Shared resource identifiers for BSD drivers on EdgeOS. */

#ifndef _MACHINE_RESOURCE_H_
#define _MACHINE_RESOURCE_H_

#define SYS_RES_IRQ 1
#define SYS_RES_DRQ 2
#define SYS_RES_MEMORY 3
#define SYS_RES_IOPORT 4
#define SYS_RES_GPIO 5
#define PCI_RES_BUS 6

/*
 * Some architecture drivers include machine/resource.h directly while using
 * the generic resource flags and accessors.  FreeBSD supplies those through
 * its architecture include graph; the EdgeOS bridge exposes the same public
 * surface from this shared architecture-neutral entry point.
 */
#include "../sys/rman.h"

#endif
