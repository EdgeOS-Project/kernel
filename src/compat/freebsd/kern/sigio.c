/* SPDX-License-Identifier: MPL-2.0 */
/* Asynchronous character-device ownership for the FreeBSD driver bridge. */

#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/malloc.h"
#include "compat/freebsd/sys/proc.h"
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/sigio.h>
#include "compat/freebsd/sys/signalvar.h"

#define BSD_SIGIO_ESRCH 3
#define BSD_SIGIO_ENOMEM 12

pid_t
fgetown(struct sigio **owner)
{
    return owner != 0 && *owner != 0 ? (*owner)->sio_pgid : 0;
}

void
funsetown(struct sigio **owner)
{
    struct sigio *previous;

    if (owner == 0)
        return;
    previous = __atomic_exchange_n(owner, 0, __ATOMIC_ACQ_REL);
    if (previous != 0)
        bsd_free(previous, M_DEVBUF);
}

int
fsetown(pid_t process_group_id, struct sigio **owner)
{
    struct proc *process;
    struct sigio *replacement;
    struct sigio *previous;

    if (owner == 0)
        return BSD_SIGIO_ESRCH;
    if (process_group_id == 0) {
        funsetown(owner);
        return 0;
    }
    process = bsd_curproc();
    if (process == 0)
        return BSD_SIGIO_ESRCH;
    if (process_group_id > 0 && process_group_id != process->p_pid)
        return BSD_SIGIO_ESRCH;
    if (process_group_id < 0 && -process_group_id != process->p_pgid)
        return BSD_SIGIO_ESRCH;
    replacement = bsd_malloc(sizeof(*replacement),
        M_DEVBUF, M_WAITOK | M_ZERO);
    if (replacement == 0)
        return BSD_SIGIO_ENOMEM;
    replacement->sio_proc = process;
    replacement->sio_myref = owner;
    replacement->sio_ucred = process->p_ucred;
    replacement->sio_pgid = process_group_id;
    previous = __atomic_exchange_n(owner, replacement, __ATOMIC_ACQ_REL);
    if (previous != 0)
        bsd_free(previous, M_DEVBUF);
    return 0;
}

void
funsetownlst(struct sigiolst *owners)
{
    struct sigio *owner;

    if (owners == 0)
        return;
    while ((owner = SLIST_FIRST(owners)) != 0) {
        SLIST_REMOVE_HEAD(owners, sio_pgsigio);
        if (owner->sio_myref != 0)
            __atomic_store_n(owner->sio_myref, 0, __ATOMIC_RELEASE);
        bsd_free(owner, M_DEVBUF);
    }
}

void
pgsigio(struct sigio **owner, int signal_number, int check_ctty)
{
    struct sigio *target;

    (void)check_ctty;
    if (owner == 0)
        return;
    target = __atomic_load_n(owner, __ATOMIC_ACQUIRE);
    if (target == 0 || target->sio_proc == 0)
        return;
    kern_psignal(target->sio_proc, signal_number);
}
