/* SPDX-License-Identifier: BSD-2-Clause */
/* Internal UMA address query surface used by FreeBSD LinuxKPI. */

#ifndef _VM_UMA_INT_H_
#define _VM_UMA_INT_H_

#include <vm/vm.h>

#define UMA_SLAB_MASK (PAGE_SIZE - 1u)

static inline void *
vtoslab(vm_offset_t address)
{
    (void)address;
    return 0;
}

#endif
