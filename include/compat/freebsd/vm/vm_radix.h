/* SPDX-License-Identifier: MPL-2.0 */
/* Ordered VM-object page lookup compatible with FreeBSD pctrie iterators. */

#ifndef _VM_VM_RADIX_H_
#define _VM_VM_RADIX_H_

#include "vm_object.h"
#include "vm_page.h"

struct pctrie_iter {
    vm_object_t object;
};

static inline void
vm_page_iter_init(struct pctrie_iter *iterator, vm_object_t object)
{
    iterator->object = object;
}

static inline vm_page_t
vm_radix_iter_lookup(struct pctrie_iter *iterator, vm_pindex_t index)
{
    return vm_page_lookup(iterator->object, index);
}

#define VM_RADIX_FORALL(page, iterator) \
    TAILQ_FOREACH((page), &(iterator)->object->pages, object_link)

#endif
