/* SPDX-License-Identifier: MPL-2.0 */
/* Ordered VM-object page lookup compatible with FreeBSD pctrie iterators. */

#ifndef _VM_VM_RADIX_H_
#define _VM_VM_RADIX_H_

#include "vm_object.h"
#include "vm_page.h"

struct pctrie_iter {
    vm_object_t object;
    vm_pindex_t limit;
    bool limited;
};

static inline void
pctrie_iter_reset(struct pctrie_iter *iterator)
{
    (void)iterator;
}

static inline void
vm_page_iter_init(struct pctrie_iter *iterator, vm_object_t object)
{
    iterator->object = object;
    iterator->limited = false;
}

static inline void
vm_page_iter_limit_init(struct pctrie_iter *iterator, vm_object_t object,
    vm_pindex_t limit)
{
    iterator->object = object;
    iterator->limit = limit;
    iterator->limited = true;
}

static inline vm_page_t
vm_radix_iter_lookup(struct pctrie_iter *iterator, vm_pindex_t index)
{
    return vm_page_lookup(iterator->object, index);
}

static inline vm_page_t
vm_page_grab_iter(vm_object_t object, vm_pindex_t index, int flags,
    struct pctrie_iter *iterator)
{
    iterator->object = object;
    return vm_page_grab(object, index, flags);
}

static inline int
vm_page_iter_insert(vm_page_t page, vm_object_t object, vm_pindex_t index,
    struct pctrie_iter *iterator)
{
    iterator->object = object;
    return vm_page_insert(page, object, index);
}

#define VM_RADIX_FORALL(page, iterator) \
    TAILQ_FOREACH((page), &(iterator)->object->pages, object_link)
#define VM_RADIX_FOREACH_FROM(page, iterator, start) \
    for ((page) = TAILQ_FIRST(&(iterator)->object->pages); \
        (page) != 0 && ((page)->pindex < (start) || \
        ((iterator)->limited && (page)->pindex >= (iterator)->limit)); \
        (page) = TAILQ_NEXT((page), object_link)) \
        ; \
    for (; (page) != 0 && (!(iterator)->limited || \
        (page)->pindex < (iterator)->limit); \
        (page) = TAILQ_NEXT((page), object_link))

#endif
