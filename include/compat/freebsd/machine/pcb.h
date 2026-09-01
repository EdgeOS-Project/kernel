/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture PCB router for the pinned FreeBSD VMM interface. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_PCB_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_PCB_H

#if defined(__x86_64__)
#include "../../../../src/compat/freebsd/upstream/sys/amd64/include/pcb.h"
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#include <arm64/include/pcb.h>
#else
#error "The FreeBSD PCB interface is unsupported on this architecture"
#endif

#endif
