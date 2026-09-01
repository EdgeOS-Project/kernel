/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD register definitions used by imported drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_SPECIALREG_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_SPECIALREG_H

#ifndef LOCORE
#include <sys/types.h>
#endif
#if defined(__x86_64__) || defined(__i386__)
#include <x86/include/specialreg.h>
#elif !defined(PAT_WRITE_BACK)
#define PAT_WRITE_BACK 0
#endif

#endif
