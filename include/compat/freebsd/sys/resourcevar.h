/* SPDX-License-Identifier: BSD-2-Clause */
/* Process resource-limit access used by imported FreeBSD drivers. */

#ifndef _SYS_RESOURCEVAR_H_
#define _SYS_RESOURCEVAR_H_

#include <sys/resource.h>

struct proc;

rlim_t lim_cur_proc(struct proc *process, int which);

#endif
