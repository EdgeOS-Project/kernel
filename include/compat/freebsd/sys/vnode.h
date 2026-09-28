/* SPDX-License-Identifier: MPL-2.0 */
/* Vnode I/O flags used by imported character-device drivers. */

#ifndef _SYS_VNODE_H_
#define _SYS_VNODE_H_

#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>

struct cdev;
struct mount;
struct vm_object;

struct vnode {
    void *v_data;
    struct cdev *v_rdev;
    struct mount *v_mount;
    struct vm_object *v_object;
    volatile uint32_t v_refcount;
    volatile uint32_t edgeos_lock;
};

#define IO_NDELAY 0x0004
#ifndef LK_SHARED
#define LK_SHARED 0x200000
#endif
#ifndef LK_RETRY
#define LK_RETRY 0x000400
#endif
#define NOCRED ((struct ucred *)(uintptr_t)-1)

static inline int
vn_lock(struct vnode *vnode, int flags)
{
    (void)flags;
    if (!vnode)
        return 22;
    while (__atomic_exchange_n(&vnode->edgeos_lock, 1u,
        __ATOMIC_ACQUIRE) != 0)
        __atomic_signal_fence(__ATOMIC_ACQUIRE);
    return 0;
}

static inline int
VOP_STAT(struct vnode *vnode, struct stat *status,
    struct ucred *active_credential, struct ucred *file_credential)
{
    (void)active_credential;
    (void)file_credential;
    if (!vnode || !status)
        return 22;
    *status = (struct stat){0};
    status->st_mode = vnode->v_rdev ? S_IFCHR : 0;
    status->st_nlink = 1;
    return 0;
}

static inline void
VOP_UNLOCK(struct vnode *vnode)
{
    if (vnode)
        __atomic_store_n(&vnode->edgeos_lock, 0u, __ATOMIC_RELEASE);
}

int vget(struct vnode *vnode, int flags);
void vref(struct vnode *vnode);
void vrefact(struct vnode *vnode);
void vrele(struct vnode *vnode);

#endif
