/* SPDX-License-Identifier: MPL-2.0 */
/* Object-backed VM pages for unmodified FreeBSD drivers. */

#ifndef _VM_VM_OBJECT_H_
#define _VM_VM_OBJECT_H_

#include <stdint.h>
#include <sys/kassert.h>
#include <sys/queue.h>
#include "vm.h"

#define OBJT_SWAP 1
#define OBJT_PHYS 2
#define OBJT_SG 3
#define OBJT_DEVICE 4
#define OBJT_MGTDEVICE 5
#define OBJT_DEAD 6
#define OBJPR_CLEANONLY 0x01
#define OBJ_UNMANAGED 0x0001u
#define OFF_TO_IDX(offset) \
    ((vm_pindex_t)(((vm_ooffset_t)(offset)) >> PAGE_SHIFT))
#define IDX_TO_OFF(index) \
    ((vm_ooffset_t)((vm_pindex_t)(index) << PAGE_SHIFT))

TAILQ_HEAD(vm_object_page_list, vm_page);

struct cdev_pager_ops;

struct vm_object {
    struct vm_object_page_list pages;
    vm_pindex_t size;
    volatile uint32_t lock;
    union {
        volatile uint32_t references;
        volatile uint32_t ref_count;
    };
    volatile uint32_t resident_page_count;
    objtype_t type;
    unsigned int flags;
    vm_memattr_t memattr;
    void *handle;
    union {
        struct {
            const struct cdev_pager_ops *ops;
            void *handle;
        } devp;
    } un_pager;
    TAILQ_ENTRY(vm_object) pager_link;
    uint8_t pager_registered;
    uint8_t edgeos_destroy_on_unlock;
    struct {
        struct domainset *dr_policy;
    } domain;
};

typedef struct vm_object *vm_object_t;

extern vm_object_t kernel_object;

vm_object_t vm_object_allocate(int type, vm_pindex_t size);
void vm_object_deallocate(vm_object_t object);
void vm_object_reference(vm_object_t object);
void vm_object_wlock(vm_object_t object);
void vm_object_wunlock(vm_object_t object);
int vm_object_wowned(vm_object_t object);
int vm_object_pager_physical_address(vm_object_t object,
    vm_ooffset_t offset, vm_paddr_t *physical_address);
int vm_object_set_memattr(vm_object_t object, vm_memattr_t memattr);
void vm_object_page_remove(vm_object_t object, vm_pindex_t start,
    vm_pindex_t end, int flags);

#define VM_OBJECT_WLOCK(object) vm_object_wlock((object))
#define VM_OBJECT_WUNLOCK(object) vm_object_wunlock((object))
#define VM_OBJECT_RLOCK(object) vm_object_wlock((object))
#define VM_OBJECT_RUNLOCK(object) vm_object_wunlock((object))
#define VM_OBJECT_ASSERT_WLOCKED(object) \
    KASSERT(vm_object_wowned((object)), ("VM object is not write locked"))
#define VM_OBJECT_ASSERT_LOCKED(object) VM_OBJECT_ASSERT_WLOCKED((object))

#endif
