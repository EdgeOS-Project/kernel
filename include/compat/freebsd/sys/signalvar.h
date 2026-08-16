/* SPDX-License-Identifier: MPL-2.0 */
/* Process notification support used by imported character devices. */

#ifndef _SYS_SIGNALVAR_H_
#define _SYS_SIGNALVAR_H_

#include "kthread.h"

#define SIGIO 23

struct sigio;
void pgsigio(struct sigio **owner, int signal_number, int check_ctty);

static inline void
kern_psignal(struct proc *process, int signal_number)
{
    if (process && signal_number > 0 && signal_number < 32)
        (void)__atomic_fetch_or(&process->p_pending_signals,
            1u << (unsigned int)signal_number, __ATOMIC_RELEASE);
}

#endif
