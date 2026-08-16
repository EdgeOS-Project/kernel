/* SPDX-License-Identifier: BSD-3-Clause */
/* Physical pager interface required by imported FreeBSD drivers. */

#ifndef _VM_PAGER_
#define _VM_PAGER_

#include "vm_object.h"

struct ucred;

struct cdev_pager_ops {
    int (*cdev_pg_fault)(vm_object_t object, vm_ooffset_t offset,
        int protection, vm_page_t *result);
    int (*cdev_pg_populate)(vm_object_t object, vm_pindex_t index,
        int fault_type, vm_prot_t maximum_protection,
        vm_pindex_t *first, vm_pindex_t *last);
    int (*cdev_pg_ctor)(void *handle, vm_ooffset_t size,
        vm_prot_t protection, vm_ooffset_t offset,
        struct ucred *credential, unsigned short *color);
    void (*cdev_pg_dtor)(void *handle);
    void (*cdev_pg_path)(void *handle, char *path, size_t length);
};

vm_object_t vm_pager_allocate(objtype_t type, void *handle,
    vm_ooffset_t size, vm_prot_t protection, vm_ooffset_t offset,
    struct ucred *credential);
void vm_pager_deallocate(vm_object_t object);
vm_object_t cdev_pager_allocate(void *handle, objtype_t type,
    const struct cdev_pager_ops *operations, vm_ooffset_t size,
    vm_prot_t protection, vm_ooffset_t offset,
    struct ucred *credential);
vm_object_t cdev_pager_lookup(void *handle);
void cdev_pager_free_page(vm_object_t object, vm_page_t page);

#endif
