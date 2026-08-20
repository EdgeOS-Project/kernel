/* SPDX-License-Identifier: MPL-2.0 */
/* Physical translation interface for BSD drivers on EdgeOS. */

#ifndef _VM_PMAP_H_
#define _VM_PMAP_H_

#include <stdint.h>
#include <sys/cpuset.h>
#include "vm.h"
#include "vm_page.h"
#if defined(__x86_64__)
#include <machine/specialreg.h>
#endif

#ifndef EDGEOS_FREEBSD_PMAP_TYPE_DEFINED
#define EDGEOS_FREEBSD_PMAP_TYPE_DEFINED
struct bsd_pmap_mapping;
struct pmap {
    union {
        uint64_t edgeos_address_space;
        uint64_t pm_cr3;
    };
    volatile uint32_t lock;
    struct bsd_pmap_mapping *edgeos_mappings;
};

typedef struct pmap *pmap_t;
#endif

#if defined(__x86_64__)
enum invl_op_codes {
    INVL_OP_TLB = 1,
    INVL_OP_TLB_INVPCID = 2,
    INVL_OP_TLB_INVPCID_PTI = 3,
    INVL_OP_TLB_PCID = 4,
    INVL_OP_PGRNG = 5,
    INVL_OP_PGRNG_INVPCID = 6,
    INVL_OP_PGRNG_PCID = 7,
    INVL_OP_PG = 8,
    INVL_OP_PG_INVPCID = 9,
    INVL_OP_PG_PCID = 10,
    INVL_OP_CACHE = 11,
};

typedef void (*smp_invl_local_cb_t)(struct pmap *, vm_offset_t,
    vm_offset_t);
typedef void (*smp_targeted_tlb_shootdown_t)(pmap_t, vm_offset_t,
    vm_offset_t, smp_invl_local_cb_t, enum invl_op_codes);

void smp_targeted_tlb_shootdown_native(pmap_t pmap, vm_offset_t start,
    vm_offset_t end, smp_invl_local_cb_t local_callback,
    enum invl_op_codes operation);
extern smp_targeted_tlb_shootdown_t smp_targeted_tlb_shootdown;
#endif

extern struct pmap edgeos_kernel_pmap;
#define kernel_pmap (&edgeos_kernel_pmap)

extern cpuset_t all_cpus;

static inline const cpuset_t *
pmap_invalidate_cpu_mask(pmap_t pmap)
{
    (void)pmap;
    return &all_cpus;
}

uint64_t bsd_pmap_kextract(uintptr_t virtual_value);
void *bsd_pmap_phys_to_dmap(vm_paddr_t physical_address);
vm_paddr_t pmap_extract(pmap_t pmap, vm_offset_t virtual_address);
int pmap_enter(pmap_t pmap, vm_offset_t virtual_address, vm_page_t page,
    vm_prot_t protection, unsigned int flags, int8_t page_size_index);
int pmap_pinit(pmap_t pmap);
void pmap_release(pmap_t pmap);
void pmap_remove(pmap_t pmap, vm_offset_t start, vm_offset_t end);
void pmap_qenter(void *address, vm_page_t *pages, int count);
void pmap_qremove(void *address, int count);
void pmap_kenter_device(vm_offset_t address, vm_size_t size,
    vm_paddr_t physical_address);
void pmap_kremove_device(vm_offset_t address, vm_size_t size);
int bsd_pmap_kva_extract(vm_offset_t address,
    vm_paddr_t *physical_address);
int bsd_pmap_sync_device_mapping(void *address, vm_size_t size,
    int to_device);
void pmap_copy_pages(vm_page_t source_pages[], vm_offset_t source_offset,
    vm_page_t destination_pages[], vm_offset_t destination_offset,
    int transfer_size);
int pmap_large_map(vm_paddr_t physical_address, vm_size_t size,
    void **mapping, vm_memattr_t memory_attribute);
void pmap_large_map_wb(void *mapping, vm_size_t size);
void pmap_large_unmap(void *mapping, vm_size_t size);
void pmap_flush_cache_phys_range(vm_paddr_t start, vm_paddr_t end,
    vm_memattr_t memory_attribute);
void pmap_allow_2m_x_ept_recalculate(void);

#define PMAP_ENTER_NOSLEEP 0x00000100u
#define PMAP_ENTER_WIRED 0x00000200u
#define PMAP_ENTER_LARGEPAGE 0x00000400u
#define PMAP_ENTER_UNPROTECTED 0x00000800u
#define PMAP_ENTER_RESERVED 0xff000000u

static inline void
pmap_lock(pmap_t pmap)
{
    if (!pmap)
        return;
    while (__atomic_exchange_n(&pmap->lock, 1u, __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&pmap->lock, __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

static inline void
pmap_unlock(pmap_t pmap)
{
    if (pmap)
        __atomic_store_n(&pmap->lock, 0u, __ATOMIC_RELEASE);
}

#define PMAP_LOCK(pmap) pmap_lock((pmap))
#define PMAP_UNLOCK(pmap) pmap_unlock((pmap))

static inline void
pmap_invalidate_cache(void)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    __asm__ volatile("wbinvd" ::: "memory");
#else
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
}

static inline void
pmap_invalidate_cache_pages(vm_page_t *pages, int count)
{
    if (!pages || count <= 0)
        return;
    pmap_invalidate_cache();
}

static inline void
pmap_force_invalidate_cache_range(uintptr_t start, uintptr_t end)
{
    if (start >= end)
        return;
    pmap_invalidate_cache();
}

static inline void *
pmap_quick_enter_page(vm_page_t page)
{
    return page ? page->edgeos_page : 0;
}

static inline void
pmap_quick_remove_page(void *address)
{
    (void)address;
}

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
#include "sys/mmio.h"

#ifndef PAT_WRITE_BACK
#define PAT_WRITE_BACK 0x06
#endif

static inline void *
pmap_mapbios(uint64_t physical, uint64_t size)
{
    if (!edge_mmio_phys_range_mapped(physical, size))
        return 0;
    return (void *)edge_mmio_low_alias(physical);
}

static inline void
pmap_unmapbios(void *mapping, uint64_t size)
{
    (void)mapping;
    (void)size;
}

static inline void *
pmap_mapdev(uint64_t physical, uint64_t size)
{
    return pmap_mapbios(physical, size);
}

static inline void
pmap_unmapdev(void *mapping, uint64_t size)
{
    pmap_unmapbios(mapping, size);
}

#elif (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)

#ifndef PAT_WRITE_BACK
#define PAT_WRITE_BACK 0
#endif

static inline void *
pmap_mapbios(uint64_t physical, uint64_t size)
{
    if (size == 0 || physical > UINT64_MAX - (size - 1))
        return 0;
    return (void *)(uintptr_t)physical;
}

static inline void
pmap_unmapbios(void *mapping, uint64_t size)
{
    (void)mapping;
    (void)size;
}

static inline void *
pmap_mapdev(uint64_t physical, uint64_t size)
{
    return pmap_mapbios(physical, size);
}

static inline void
pmap_unmapdev(void *mapping, uint64_t size)
{
    pmap_unmapbios(mapping, size);
}

#endif

static inline int
pmap_change_attr(void *mapping, uint64_t size, int attribute)
{
    if (!mapping || size == 0)
        return 22;
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    if (attribute == PAT_WRITE_BACK)
        return 0;
#else
    (void)attribute;
#endif
    /*
     * EdgeOS MMIO apertures currently use large permanent mappings.  Changing
     * one small BAR would also change unrelated devices in that aperture, so
     * report the unsupported request and let drivers use their standard queue
     * placement instead of claiming an attribute transition that did not
     * occur.
     */
    return 45;
}

#if !defined(BSD_BRIDGE_HOST_TEST) && \
    (defined(__x86_64__) || defined(__aarch64__) || \
    defined(EDGEOS_BSD_ARM64))
static inline void *
pmap_mapdev_attr(vm_paddr_t physical, vm_size_t size,
    vm_memattr_t attribute)
{
    void *mapping;

    mapping = pmap_mapdev(physical, size);
    if (!mapping)
        return 0;
    (void)pmap_change_attr(mapping, size, attribute);
    return mapping;
}
#endif

#define pmap_kextract(virtual_value) \
    bsd_pmap_kextract((uintptr_t)(virtual_value))
#define vtophys(virtual_value) \
    bsd_pmap_kextract((uintptr_t)(virtual_value))
#define PHYS_TO_DMAP(physical_address) \
    bsd_pmap_phys_to_dmap((vm_paddr_t)(physical_address))
#define DMAP_TO_PHYS(virtual_address) \
    ((vm_paddr_t)bsd_pmap_kextract((uintptr_t)(virtual_address)))

#endif
