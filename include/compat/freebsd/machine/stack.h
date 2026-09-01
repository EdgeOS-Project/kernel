/* SPDX-License-Identifier: BSD-2-Clause */
/* Stack accounting used by imported FreeBSD network graph code. */

#ifndef _MACHINE_STACK_H_
#define _MACHINE_STACK_H_

#include <sys/kthread.h>

#define GET_STACK_USAGE(total, used) \
    bsd_kthread_stack_usage(&(total), &(used))

#endif
