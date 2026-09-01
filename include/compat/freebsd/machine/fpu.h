/* SPDX-License-Identifier: MPL-2.0 */
/* Firmware-call floating-point context preservation interface. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_FPU_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_FPU_H

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)

#include <arm64/include/vfp.h>

#elif defined(__x86_64__)

#include <vm/pmap.h>
#include "../../../../src/compat/freebsd/upstream/sys/x86/include/fpu.h"

struct thread;
struct savefpu;

#define FPU_KERN_NOCTX 0x01

void bsd_fpu_kern_enter(struct thread *thread, void *context, int flags);
void bsd_fpu_kern_leave(struct thread *thread, void *context);

#define fpu_kern_enter(thread, context, flags) \
    bsd_fpu_kern_enter((thread), (context), (flags))
#define fpu_kern_leave(thread, context) \
    bsd_fpu_kern_leave((thread), (context))

void fpuexit(struct thread *thread);
void fpurestore(void *save_area);
void fpusave(void *save_area);
struct savefpu *fpu_save_area_alloc(void);
void fpu_save_area_free(struct savefpu *save_area);
void fpu_save_area_reset(struct savefpu *save_area);

#else
#error "FreeBSD FPU definitions are unsupported on this architecture"
#endif

#endif
