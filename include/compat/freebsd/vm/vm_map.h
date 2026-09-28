/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS address-space view exposed to imported FreeBSD drivers. */

#ifndef _VM_MAP_
#define _VM_MAP_

#include <stdbool.h>
#include <stdint.h>
#include "vm.h"
#include "vm_page.h"
#include "pmap.h"

struct bsd_vm_map_entry;
struct vm_object;

struct vm_map {
    uint64_t edgeos_address_space;
    vm_offset_t edgeos_min;
    vm_offset_t edgeos_max;
    uint64_t size;
    pmap_t pmap;
    volatile uint32_t lock;
    struct bsd_vm_map_entry *edgeos_entries;
};

#define VMFS_OPTIMAL_SPACE 0
#define MAP_INHERIT_SHARE 1

typedef struct vm_map *vm_map_t;

struct vm_object;
int vm_map_find(vm_map_t map, struct vm_object *object,
    uint64_t offset, uintptr_t *address, uint64_t size,
    uint64_t maximum_address, int find_space, uint8_t protection,
    uint8_t maximum_protection, int inheritance);

static inline bool
vm_map_range_valid(vm_map_t map, uintptr_t start, uintptr_t end)
{
    return map && map->edgeos_address_space != 0 && end >= start;
}

struct vmspace {
    struct vm_map vm_map;
    struct pmap vm_pmap;
};

typedef int (*pmap_pinit_t)(pmap_t pmap);

#define VM_MAP_WIRE_USER 0x0001
#define VM_MAP_WIRE_NOHOLES 0x0000

void vm_map_lock(vm_map_t map);
void vm_map_unlock(vm_map_t map);
int vm_map_insert(vm_map_t map, struct vm_object *object,
    vm_ooffset_t offset, vm_offset_t start, vm_offset_t end,
    vm_prot_t protection, vm_prot_t maximum_protection, int flags);
int vm_map_remove(vm_map_t map, vm_offset_t start, vm_offset_t end);
int vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags);

static inline pmap_t
vmspace_pmap(struct vmspace *vmspace)
{
    return vmspace ? &vmspace->vm_pmap : 0;
}

static inline vm_offset_t
vm_map_min(const struct vm_map *map)
{
    return map ? map->edgeos_min : 0;
}

static inline vm_offset_t
vm_map_max(const struct vm_map *map)
{
    return map ? map->edgeos_max : 0;
}

static inline pmap_t
vm_map_pmap(vm_map_t map)
{
    return map ? map->pmap : 0;
}

#endif
