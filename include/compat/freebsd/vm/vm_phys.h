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
int vm_phys_fictitious_reg_range(vm_paddr_t start, vm_paddr_t end,
    vm_memattr_t memory_attribute);
void vm_phys_fictitious_unreg_range(vm_paddr_t start, vm_paddr_t end);
vm_page_t vm_phys_fictitious_to_vm_page(vm_paddr_t physical_address);

#endif
