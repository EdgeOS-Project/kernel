/* SPDX-License-Identifier: MPL-2.0 */
/* AArch64 firmware-call floating-point context preservation. */

#include <sys/kthread.h>

void
bsd_fpu_kern_enter(struct thread *thread, void *context, int flags)
{
    uint8_t *state;

    (void)context;
    (void)flags;
    if (!thread || thread->td_fpu_depth++ != 0)
        return;
    state = thread->td_fpu_save;
    __asm__ __volatile__(
        "stp q0, q1, [%0, #0]\n"
        "stp q2, q3, [%0, #32]\n"
        "stp q4, q5, [%0, #64]\n"
        "stp q6, q7, [%0, #96]\n"
        "stp q8, q9, [%0, #128]\n"
        "stp q10, q11, [%0, #160]\n"
        "stp q12, q13, [%0, #192]\n"
        "stp q14, q15, [%0, #224]\n"
        "stp q16, q17, [%0, #256]\n"
        "stp q18, q19, [%0, #288]\n"
        "stp q20, q21, [%0, #320]\n"
        "stp q22, q23, [%0, #352]\n"
        "stp q24, q25, [%0, #384]\n"
        "stp q26, q27, [%0, #416]\n"
        "stp q28, q29, [%0, #448]\n"
        "stp q30, q31, [%0, #480]\n"
        "mrs x9, fpsr\n"
        "mrs x10, fpcr\n"
        "str w9, [%0, #512]\n"
        "str w10, [%0, #516]\n"
        : : "r"(state) : "x9", "x10", "memory");
}

void
bsd_fpu_kern_leave(struct thread *thread, void *context)
{
    uint8_t *state;

    (void)context;
    if (!thread || thread->td_fpu_depth == 0 || --thread->td_fpu_depth != 0)
        return;
    state = thread->td_fpu_save;
    __asm__ __volatile__(
        "ldp q0, q1, [%0, #0]\n"
        "ldp q2, q3, [%0, #32]\n"
        "ldp q4, q5, [%0, #64]\n"
        "ldp q6, q7, [%0, #96]\n"
        "ldp q8, q9, [%0, #128]\n"
        "ldp q10, q11, [%0, #160]\n"
        "ldp q12, q13, [%0, #192]\n"
        "ldp q14, q15, [%0, #224]\n"
        "ldp q16, q17, [%0, #256]\n"
        "ldp q18, q19, [%0, #288]\n"
        "ldp q20, q21, [%0, #320]\n"
        "ldp q22, q23, [%0, #352]\n"
        "ldp q24, q25, [%0, #384]\n"
        "ldp q26, q27, [%0, #416]\n"
        "ldp q28, q29, [%0, #448]\n"
        "ldp q30, q31, [%0, #480]\n"
        "ldr w9, [%0, #512]\n"
        "ldr w10, [%0, #516]\n"
        "msr fpsr, x9\n"
        "msr fpcr, x10\n"
        : : "r"(state) : "x9", "x10", "memory");
}
