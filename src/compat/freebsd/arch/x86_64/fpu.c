/* SPDX-License-Identifier: MPL-2.0 */
/* x86_64 floating-point context preservation for the BSD bridge and VMM. */

#include <arch/x86_64/fpu.h>
#include <machine/fpu.h>
#include <sys/malloc.h>
#include <sys/kthread.h>
#include <sys/systm.h>

MALLOC_DEFINE(M_BSD_VMM_FPU, "bsd_vmm_fpu", "BSD VMM guest FPU state");

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

struct savefpu *
fpu_save_area_alloc(void)
{
    return bsd_malloc_aligned(EDGE_X86_XSAVE_MAX_SIZE, 64,
        M_BSD_VMM_FPU, M_WAITOK | M_ZERO);
}

void
fpu_save_area_free(struct savefpu *save_area)
{
    bsd_free(save_area, M_BSD_VMM_FPU);
}

void
fpu_save_area_reset(struct savefpu *save_area)
{
    if (!save_area)
        return;
    bsd_memset(save_area, 0, EDGE_X86_XSAVE_MAX_SIZE);
    save_area->sv_env.en_cw = 0x037fu;
    save_area->sv_env.en_mxcsr = 0x1f80u;
    save_area->sv_env.en_mxcsr_mask = 0xffbfu;
}

void
fpusave(void *save_area)
{
    x86_fpu_save_state(save_area, save_area);
}

void
fpurestore(void *save_area)
{
    x86_fpu_restore_state(save_area, save_area);
}

void
fpuexit(struct thread *thread)
{
    if (!thread)
        return;
    __asm__ __volatile__("fxsave64 (%0)" : : "r"(thread->td_fpu_save) :
        "memory");
}

void
set_pcb_flags(struct pcb *pcb, const u_int flags)
{
    if (pcb)
        (void)__atomic_fetch_or(&pcb->pcb_flags, flags, __ATOMIC_RELEASE);
}

void
clear_pcb_flags(struct pcb *pcb, const u_int flags)
{
    if (pcb)
        (void)__atomic_fetch_and(&pcb->pcb_flags, ~flags, __ATOMIC_RELEASE);
}

void
set_pcb_flags_raw(struct pcb *pcb, const u_int flags)
{
    set_pcb_flags(pcb, flags);
}
