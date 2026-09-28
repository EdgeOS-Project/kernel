#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_BO_VM_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_LEGACY_TTM_BO_VM_COMPAT_H

#include "nouveau_legacy_ttm_compat.h"
#include <linux/pfn_t.h>

#pragma GCC diagnostic ignored "-Wcompare-distinct-pointer-types"

#undef vmf_insert_pfn_prot

static inline vm_fault_t
edgeos_legacy_ttm_insert_pfn(struct vm_area_struct *area,
    unsigned long address, unsigned long pfn, pgprot_t protection)
{
	vm_fault_t result;

	VM_OBJECT_WLOCK(area->vm_obj);
	result = lkpi_vmf_insert_pfn_prot_locked(area, address, pfn, protection);
	VM_OBJECT_WUNLOCK(area->vm_obj);
	return result;
}

static inline vm_fault_t
edgeos_legacy_ttm_insert_mixed(struct vm_area_struct *area,
    unsigned long address, pfn_t pfn, pgprot_t protection)
{
	return edgeos_legacy_ttm_insert_pfn(area, address,
	    (unsigned long)(pfn.val & ~PFN_FLAGS_MASK), protection);
}

#define vmf_insert_pfn_prot edgeos_legacy_ttm_insert_pfn
#define vmf_insert_mixed_prot edgeos_legacy_ttm_insert_mixed

#undef pr_fmt

#endif
