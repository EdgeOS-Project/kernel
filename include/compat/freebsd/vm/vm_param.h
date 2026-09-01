/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD VM parameter compatibility backed by EdgeOS page definitions. */

#ifndef _VM_VM_PARAM_H_
#define _VM_VM_PARAM_H_

#include <machine/param.h>
#include <vm/vm.h>

#define KERN_SUCCESS             0
#define KERN_INVALID_ADDRESS     1
#define KERN_PROTECTION_FAILURE  2
#define KERN_NO_SPACE            3
#define KERN_INVALID_ARGUMENT    4
#define KERN_FAILURE             5
#define KERN_RESOURCE_SHORTAGE   6
#define KERN_NOT_RECEIVER        7
#define KERN_NO_ACCESS           8
#define KERN_OUT_OF_BOUNDS       9
#define KERN_RESTART             10

#define VM_MIN_KERNEL_ADDRESS ((vm_offset_t)0)
#define VM_MAX_KERNEL_ADDRESS ((vm_offset_t)UINTPTR_MAX)

#if defined(__x86_64__)
#define VM_PHYSSEG_MAX 63
#else
#define VM_PHYSSEG_MAX 64
#endif

#define num_pages(value) \
    ((vm_offset_t)((((vm_offset_t)(value)) + PAGE_MASK) >> PAGE_SHIFT))

#if defined(__x86_64__)
#define VM_MAXUSER_ADDRESS_LA48 UINT64_C(0x0000800000000000)
#endif

#endif
