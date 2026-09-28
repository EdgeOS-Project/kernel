/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS machine-facing per-CPU compatibility interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef _MACHINE_PCPU_H_
#define _MACHINE_PCPU_H_

#include <sys/pcpu.h>

/*
 * FreeBSD drivers use curcpu as a stable logical CPU index for queue
 * selection and interrupt affinity.  Resolve it from the shared scheduler
 * state instead of pinning all driver work to CPU zero.
 */
#ifndef curcpu
#define curcpu bsd_pcpu_current_cpuid()
#endif

#endif
