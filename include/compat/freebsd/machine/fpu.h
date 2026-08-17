/* SPDX-License-Identifier: MPL-2.0 */
/* Firmware-call floating-point context preservation interface. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_FPU_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_FPU_H

#include <vm/pmap.h>
#include "../../../../src/compat/freebsd/upstream/sys/x86/include/fpu.h"

struct thread;

#define FPU_KERN_NOCTX 0x01

void bsd_fpu_kern_enter(struct thread *thread, void *context, int flags);
void bsd_fpu_kern_leave(struct thread *thread, void *context);

#define fpu_kern_enter(thread, context, flags) \
    bsd_fpu_kern_enter((thread), (context), (flags))
#define fpu_kern_leave(thread, context) \
    bsd_fpu_kern_leave((thread), (context))

#endif
