/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD privilege checks mapped to the current EdgeOS task identity. */

#ifndef _SYS_PRIV_H_
#define _SYS_PRIV_H_

#include "../edgeos/kthread.h"
#include "kthread.h"

#define PRIV_DRIVER 14
#define PRIV_KEYBOARD 13
#define PRIV_CPUCTL_UPDATE 18
#define PRIV_CPUCTL_WRMSR 19
#define PRIV_NET80211_VAP_GETKEY 440
#define PRIV_NET80211_VAP_MANAGE 441
#define PRIV_NET80211_VAP_SETMAC 442
#define PRIV_NET80211_CREATE_VAP 443
#define PRIV_NET_SETIFPHYS 400

#ifndef curthread
#define curthread bsd_kthread_current_public()
#endif

int priv_check(struct thread *thread, int privilege);

#endif
