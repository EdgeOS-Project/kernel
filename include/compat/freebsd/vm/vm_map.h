/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS address-space view exposed to imported FreeBSD drivers. */

#ifndef _VM_MAP_
#define _VM_MAP_

#include <stdint.h>

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

struct vm_map {
    uint64_t edgeos_address_space;
};

typedef struct vm_map *vm_map_t;

struct vmspace {
    struct vm_map vm_map;
    struct pmap vm_pmap;
};

#endif
