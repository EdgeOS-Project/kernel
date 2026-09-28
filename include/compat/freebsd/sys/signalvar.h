/* SPDX-License-Identifier: MPL-2.0 */
/* Process notification support used by imported character devices. */

#ifndef _SYS_SIGNALVAR_H_
#define _SYS_SIGNALVAR_H_

#include "kthread.h"

struct sigio;
void pgsigio(struct sigio **owner, int signal_number, int check_ctty);

static inline void
kern_psignal(struct proc *process, int signal_number)
{
    if (process && _SIG_VALID(signal_number)) {
        SIGADDSET(process->p_siglist, signal_number);
        if (signal_number < 32)
        (void)__atomic_fetch_or(&process->p_pending_signals,
            1u << (unsigned int)(signal_number - 1), __ATOMIC_RELEASE);
    }
}

static inline void
tdsignal(struct thread *thread, int signal_number)
{
    if (!thread || !_SIG_VALID(signal_number))
        return;
    SIGADDSET(thread->td_siglist, signal_number);
    kern_psignal(thread->td_proc, signal_number);
}

#endif
