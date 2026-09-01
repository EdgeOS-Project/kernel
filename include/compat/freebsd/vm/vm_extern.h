/* SPDX-License-Identifier: MPL-2.0 */
/* VM operations required by imported FreeBSD drivers. */

#ifndef _VM_EXTERN_H_
#define _VM_EXTERN_H_

#include <stdbool.h>
#include "vm.h"
#include "vm_map.h"

struct domainset;

#define VM_FAULT_NORMAL 0x00

int vm_fault(vm_map_t map, vm_offset_t address, vm_prot_t protection,
    int fault_flags, vm_page_t *result_page);

int vm_fault_hold_pages(vm_map_t map, vm_offset_t address, vm_size_t length,
    vm_prot_t protection, vm_page_t *pages, int maximum_pages,
    int *page_count);
void vm_page_unhold_pages(vm_page_t *pages, int page_count);
int vm_fault_quick_hold_pages(vm_map_t map, vm_offset_t address,
    vm_size_t length, vm_prot_t protection, vm_page_t *pages,
    int maximum_pages);
int vm_mmap_to_errno(int result);
void *kva_alloc(vm_size_t size);
void kva_free(void *address, vm_size_t size);
void *kmem_malloc(vm_size_t size, int flags);
void *kmem_alloc_contig(vm_size_t size, int flags, vm_paddr_t low,
    vm_paddr_t high, unsigned long alignment, vm_paddr_t boundary,
    vm_memattr_t memattr);
void *kmem_alloc_contig_domainset(struct domainset *policy,
    vm_size_t size, int flags, vm_paddr_t low, vm_paddr_t high,
    unsigned long alignment, vm_paddr_t boundary,
    vm_memattr_t memattr);
void *kmem_alloc_attr(vm_size_t size, int flags, vm_paddr_t low,
    vm_paddr_t high, vm_memattr_t memattr);
void *kmem_alloc_attr_domainset(struct domainset *policy, vm_size_t size,
    int flags, vm_paddr_t low, vm_paddr_t high, vm_memattr_t memattr);
void kmem_free(void *address, vm_size_t size);
struct vmspace *vmspace_alloc(vm_offset_t min, vm_offset_t max,
    pmap_pinit_t pinit);
void vmspace_free(struct vmspace *vmspace);
long vmspace_resident_count(struct vmspace *vmspace);

static inline bool
vm_addr_bound_ok(vm_paddr_t address, vm_size_t size, vm_paddr_t boundary)
{
    if (size == 0 || boundary == 0)
        return true;
    if (address > UINT64_MAX - (size - 1u))
        return false;
    return address / boundary == (address + size - 1u) / boundary;
}

#endif
