/* SPDX-License-Identifier: BSD-2-Clause */
/* EdgeOS routes architecture pmap users to the shared bridge pmap. */
#ifndef _MACHINE_PMAP_H_
#define _MACHINE_PMAP_H_

#include <vm/pmap.h>

#if defined(__x86_64__)
/* FreeBSD amd64 param.h page-table geometry used by the VMM IOMMU code. */
#ifndef NPTEPG
#define NPTEPG 512
#endif
#ifndef PML4SHIFT
#define PML4SHIFT 39
#endif
#endif

#endif
