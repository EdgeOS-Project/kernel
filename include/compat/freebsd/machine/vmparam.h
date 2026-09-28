/* SPDX-License-Identifier: MPL-2.0 */
/* Machine VM parameters exported through the shared EdgeOS VM bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_VMPARAM_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_VMPARAM_H

#include <vm/vm_param.h>
#include <vm/pmap.h>

#if defined(__x86_64__)
/* EdgeOS x86_64 is linked in its supervisor identity-mapped kernel window. */
#ifndef KERNBASE
#define KERNBASE 0x08000000UL
#endif
#endif
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#define ADDR_IS_KERNEL(address) \
    ((((uint64_t)(address)) & (UINT64_C(1) << 55)) != 0)
#endif
#define VM_MAXUSER_ADDRESS ((vm_offset_t)0x0000800000000000ULL)

#endif
