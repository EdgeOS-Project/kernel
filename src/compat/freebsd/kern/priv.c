/* SPDX-License-Identifier: MPL-2.0 */
/* Shared identity-based privilege checks for imported BSD drivers. */

#include <stdint.h>

#include "compat/freebsd/sys/priv.h"
#include "compat/freebsd/sys/systm.h"
#include "kernel/process_runtime.h"

#define BSD_PRIV_EPERM 1

int
priv_check(struct thread *thread, int privilege)
{
    uint32_t effective_uid;

    (void)thread;
    switch (privilege) {
    case PRIV_KEYBOARD:
    case PRIV_DRIVER:
    case PRIV_CPUCTL_UPDATE:
    case PRIV_CPUCTL_WRMSR:
    case PRIV_SCHED_SETPRIORITY:
    case PRIV_NET80211_VAP_GETKEY:
    case PRIV_NET80211_VAP_MANAGE:
    case PRIV_NET80211_VAP_SETMAC:
    case PRIV_NET80211_CREATE_VAP:
        if (kernel_current_identity(0, &effective_uid, 0) < 0)
            return BSD_PRIV_EPERM;
        return effective_uid == 0 ? 0 : BSD_PRIV_EPERM;
    default:
        return BSD_PRIV_EPERM;
    }
}

int
securelevel_gt(struct ucred *credential, int level)
{
    int securelevel = -1;

    (void)credential;
    (void)getenv_int("kern.securelevel", &securelevel);
    return securelevel > level ? BSD_PRIV_EPERM : 0;
}
