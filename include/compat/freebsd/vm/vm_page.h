/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD no-object page interface backed by EdgeOS VM pages. */

#ifndef _VM_VM_PAGE_H_
#define _VM_VM_PAGE_H_

#include <stdbool.h>
#include <sys/queue.h>
#include "vm.h"

struct vm_object;
typedef struct vm_object *vm_object_t;
struct bsd_vm_page_run;

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#define PQ_NONE 255
#define PQ_INACTIVE 0
#define PQ_ACTIVE 1

#define VM_ALLOC_NORMAL		0x0000
#define VM_ALLOC_INTERRUPT	0x0001
#define VM_ALLOC_SYSTEM		0x0002
#define VM_ALLOC_CLASS_MASK	0x0003
#define VM_ALLOC_WAITOK		0x0008
#define VM_ALLOC_WIRED		0x0020
#define VM_ALLOC_ZERO		0x0040
#define VM_ALLOC_NOBUSY		0x0080
#define VM_ALLOC_NOCREAT	0x0200
#define VM_ALLOC_WAITFAIL	0x0400
#define VM_ALLOC_NORECLAIM	0x1000
#define VM_ALLOC_NODUMP		0x2000
#define VM_ALLOC_NOWAIT		0x8000

#define VPRC_BLOCKED		0x40000000u
#define VPRC_OBJREF		0x80000000u
#define VPRC_WIRE_COUNT(count) \
	((count) & ~(VPRC_BLOCKED | VPRC_OBJREF))
#define VPRC_WIRE_COUNT_MAX	(~(VPRC_BLOCKED | VPRC_OBJREF))

#define EDGEOS_VM_PAGE_OWNS_ALLOCATION 0x10000000u
#define EDGEOS_VM_PAGE_USER_HOLD       0x20000000u
#define EDGEOS_VM_PAGE_KVA_BINDING     0x40000000u
#define EDGEOS_VM_PAGE_FAKE            0x80000000u
#define EDGEOS_VM_PAGE_FICTITIOUS      0x08000000u

typedef uint64_t vm_page_bits_t;
#define VM_PAGE_BITS_ALL UINT64_MAX

#define VPO_UNMANAGED 0x04u

#define PG_PCPU_CACHE 0x01u
#define PG_FICTITIOUS 0x02u
#define PG_ZERO 0x04u
#define PG_MARKER 0x08u
#define PG_NODUMP 0x10u
#define PG_NOFREE 0x20u

SLIST_HEAD(spglist, vm_page);
TAILQ_HEAD(pglist, vm_page);

struct edgeos_vm_page_lru {
	struct edgeos_vm_page_lru *next;
	struct edgeos_vm_page_lru *prev;
};

struct vm_page {
	union {
		TAILQ_ENTRY(vm_page) q;
		struct {
			SLIST_ENTRY(vm_page) ss;
		} s;
	} plinks;
	union {
		struct {
			uint16_t flags;
			uint8_t queue;
			uint8_t act_count;
		};
		uint32_t bits;
	} a;
	vm_paddr_t phys_addr;
	uint16_t flags;
	uint8_t oflags;
	uint8_t referenced;
	volatile uint32_t busy_lock;
	void *edgeos_page;
	struct bsd_vm_page_run *edgeos_run;
	uint32_t edgeos_flags;
	volatile unsigned int ref_count;
	vm_object_t object;
	vm_pindex_t pindex;
	vm_page_bits_t valid;
	vm_page_bits_t dirty;
	TAILQ_ENTRY(vm_page) object_link;
	SLIST_ENTRY(vm_page) physical_link;
	struct edgeos_vm_page_lru lru;
};

#define VM_PAGE_TO_PHYS(page) ((page)->phys_addr)
#define VM_PAGE_TO_DMAP(page) vm_page_direct_map((page))

extern vm_page_t bogus_page;

vm_page_t vm_page_alloc_noobj(int flags);
vm_page_t vm_page_alloc_noobj_contig(int flags, unsigned long count,
    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary, vm_memattr_t memory_attribute);
static inline vm_page_t
vm_page_alloc_noobj_contig_domain(int domain, int flags,
    unsigned long count, vm_paddr_t low, vm_paddr_t high,
    unsigned long alignment, vm_paddr_t boundary,
    vm_memattr_t memory_attribute)
{
    (void)domain;
    return vm_page_alloc_noobj_contig(flags, count, low, high, alignment,
        boundary, memory_attribute);
}
vm_page_t vm_page_alloc_contig(vm_object_t object, vm_pindex_t index,
    int flags, int count, vm_paddr_t low, vm_paddr_t high,
    unsigned long alignment, vm_paddr_t boundary,
    vm_memattr_t memory_attribute);
int vm_page_reclaim_contig(int flags, unsigned long count,
    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary);
void vm_wait(vm_object_t object);
vm_page_t PHYS_TO_VM_PAGE(vm_paddr_t physical_address);
#define DMAP_TO_VM_PAGE(address) \
    PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)(address)) & \
        ~(vm_paddr_t)(PAGE_SIZE - 1u))
void vm_page_initfake(vm_page_t page, vm_paddr_t physical_address,
    vm_memattr_t memory_attribute);
void vm_page_updatefake(vm_page_t page, vm_paddr_t physical_address,
    vm_memattr_t memory_attribute);
vm_page_t vm_page_getfake(vm_paddr_t physical_address,
    vm_memattr_t memory_attribute);
void vm_page_putfake(vm_page_t page);
void *vm_page_direct_map(vm_page_t page);
void vm_page_free(vm_page_t page);
void vm_page_free_zero(vm_page_t page);
void vm_page_wire(vm_page_t page);
bool vm_page_unwire_noq(vm_page_t page);
bool vm_page_unwire(vm_page_t page, uint8_t queue);
bool vm_page_wired(vm_page_t page);
vm_page_t vm_page_grab(vm_object_t object, vm_pindex_t index, int flags);
int vm_page_grab_valid(vm_page_t *result, vm_object_t object,
    vm_pindex_t index, int flags);
vm_page_t vm_page_lookup(vm_object_t object, vm_pindex_t index);
int vm_page_insert(vm_page_t page, vm_object_t object, vm_pindex_t index);
void vm_page_remove(vm_page_t page);
void vm_page_replace(vm_page_t page, vm_object_t object,
    vm_pindex_t index, vm_page_t old_page);
bool vm_page_busy_acquire(vm_page_t page, int allocation_flags);
void vm_page_xunbusy(vm_page_t page);
void vm_page_remove_xbusy(vm_page_t page);
int vm_page_free_pages_toq(struct spglist *pages, bool update_wire_count);
void pmap_zero_page(vm_page_t page);
static inline void
vm_page_clearref(vm_page_t page)
{
    if (page)
        page->referenced = 0;
}

static inline void
vm_page_dirty(vm_page_t page)
{
    if (page)
        page->dirty = VM_PAGE_BITS_ALL;
}

static inline void
vm_page_valid(vm_page_t page)
{
    if (page)
        page->valid = VM_PAGE_BITS_ALL;
}

static inline void
vm_page_reference(vm_page_t page)
{
    if (page && page->referenced != UINT8_MAX)
        page->referenced++;
}

static inline bool
vm_page_tryxbusy(vm_page_t page)
{
    return vm_page_busy_acquire(page, VM_ALLOC_NOWAIT);
}

#endif
