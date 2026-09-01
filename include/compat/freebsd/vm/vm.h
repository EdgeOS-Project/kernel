/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal FreeBSD VM types backed by the EdgeOS physical-page allocator. */

#ifndef _VM_VM_H_
#define _VM_VM_H_

#include <stdint.h>
#include "compat/freebsd/machine/vm.h"

struct vm_page;
typedef struct vm_page *vm_page_t;
typedef uint8_t vm_prot_t;

#define VM_PROT_NONE        ((vm_prot_t)0x00)
#define VM_PROT_READ        ((vm_prot_t)0x01)
#define VM_PROT_WRITE       ((vm_prot_t)0x02)
#define VM_PROT_EXECUTE     ((vm_prot_t)0x04)
#define VM_PROT_COPY        ((vm_prot_t)0x08)
#define VM_PROT_PRIV_FLAG   ((vm_prot_t)0x10)
#define VM_PROT_ALL         \
    (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_RW          (VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_DEFAULT     VM_PROT_ALL

#define VM_MAXUSER_ADDRESS ((vm_offset_t)0x0000800000000000ULL)

typedef int objtype_t;

extern int vm_ndomains;

#ifndef _SYS_TYPES_H_
typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_ooffset_t;
typedef uint64_t vm_paddr_t;
typedef uint64_t vm_pindex_t;
typedef uint64_t vm_size_t;
typedef char vm_memattr_t;
#elif defined(BSD_BRIDGE_HOST_TEST)
typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_ooffset_t;
typedef uint64_t vm_paddr_t;
typedef uint64_t vm_pindex_t;
typedef uint64_t vm_size_t;
typedef char vm_memattr_t;
#endif

#endif
