/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS platform attachment for the imported FreeBSD ISA stack. */

#ifndef EDGEOS_COMPAT_FREEBSD_ISA_H
#define EDGEOS_COMPAT_FREEBSD_ISA_H

#include "newbus.h"

int bsd_isa_i8042_attach(device_t root);

#endif
