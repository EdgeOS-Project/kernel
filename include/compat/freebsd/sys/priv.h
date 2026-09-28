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
#define PRIV_SCHED_SETPRIORITY 201
#define PRIV_VM_MLOCK 361
#define PRIV_NET_RAW 395
#define PRIV_NET80211_VAP_GETKEY 440
#define PRIV_NET80211_VAP_MANAGE 441
#define PRIV_NET80211_VAP_SETMAC 442
#define PRIV_NET80211_CREATE_VAP 443
#define PRIV_NET_SETIFPHYS 400
#define PRIV_NETINET_BINDANY 410
#define PRIV_NETBLUETOOTH_RAW 470
#define PRIV_NETGRAPH_CONTROL 480

#ifndef curthread
#define curthread bsd_kthread_current_public()
#endif

int priv_check(struct thread *thread, int privilege);

#endif
