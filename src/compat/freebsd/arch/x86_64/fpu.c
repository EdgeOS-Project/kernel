/* SPDX-License-Identifier: MPL-2.0 */
/* x86_64 firmware-call floating-point context preservation. */

#include <sys/kthread.h>

void
bsd_fpu_kern_enter(struct thread *thread, void *context, int flags)
{
    (void)context;
    (void)flags;
    if (!thread || thread->td_fpu_depth++ != 0)
        return;
    __asm__ __volatile__("fxsave (%0)" : : "r"(thread->td_fpu_save) :
        "memory");
}

void
bsd_fpu_kern_leave(struct thread *thread, void *context)
{
    (void)context;
    if (!thread || thread->td_fpu_depth == 0 || --thread->td_fpu_depth != 0)
        return;
    __asm__ __volatile__("fxrstor (%0)" : : "r"(thread->td_fpu_save) :
        "memory");
}
