/* SPDX-License-Identifier: BSD-2-Clause */
/* EdgeOS type spelling compatibility for FreeBSD LinuxKPI parameters. */

#ifndef EDGEOS_LINUXKPI_PREINCLUDE_MODULEPARAM_H
#define EDGEOS_LINUXKPI_PREINCLUDE_MODULEPARAM_H

#include_next <linux/moduleparam.h>

/* EdgeOS uses the C99 stdbool macro while FreeBSD uses a bool typedef. */
#ifndef LINUXKPI_PARAM__Bool
#define LINUXKPI_PARAM__Bool LINUXKPI_PARAM_bool
#endif

#ifndef LINUXKPI_PARAM_charp
#define LINUXKPI_PARAM_charp(name, var, perm)
#endif

#endif
