/* SPDX-License-Identifier: MPL-2.0 */
/* Physical-page allocation declarations used by imported VM consumers. */

#ifndef EDGEOS_COMPAT_FREEBSD_VM_VM_PHYS_H
#define EDGEOS_COMPAT_FREEBSD_VM_VM_PHYS_H

#include <vm/vm.h>
#include <vm/vm_page.h>

vm_page_t vm_page_alloc_noobj_contig(int flags, unsigned long pages,
    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary, vm_memattr_t memory_attribute);
int vm_page_reclaim_contig(int flags, unsigned long pages, vm_paddr_t low,
    vm_paddr_t high, unsigned long alignment, vm_paddr_t boundary);

#endif
