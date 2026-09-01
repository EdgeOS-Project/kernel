/* SPDX-License-Identifier: MPL-2.0 */
/* File descriptor operations required by FreeBSD LinuxKPI modules. */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/vnode.h>

const cap_rights_t cap_no_rights = {{ 0, 0 }};

static struct filedesc *
filedesc_get(struct thread *thread)
{
    struct filedesc *candidate;
    struct filedesc *installed;

    if (thread == NULL || thread->td_proc == NULL)
        return NULL;
    installed = __atomic_load_n(&thread->td_proc->p_fd, __ATOMIC_ACQUIRE);
    if (installed != NULL)
        return installed;

    candidate = malloc(sizeof(*candidate), M_TEMP, M_WAITOK | M_ZERO);
    if (candidate == NULL)
        return NULL;
    FILEDESC_LOCK_INIT(candidate);
    candidate->fd_refcnt = 1;
    if (!__atomic_compare_exchange_n(&thread->td_proc->p_fd, &installed,
        candidate, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
        FILEDESC_LOCK_DESTROY(candidate);
        free(candidate, M_TEMP);
        return installed;
    }
    return candidate;
}

static int
filedesc_allocate_locked(struct filedesc *filedesc)
{
    int descriptor;

    for (descriptor = filedesc->fd_freefile;
        descriptor < EDGEOS_BSD_FD_MAX; descriptor++) {
        if (filedesc->fd_ofiles[descriptor].fde_file == NULL) {
            filedesc->fd_freefile = descriptor + 1;
            return descriptor;
        }
    }
    for (descriptor = 0; descriptor < filedesc->fd_freefile; descriptor++) {
        if (filedesc->fd_ofiles[descriptor].fde_file == NULL)
            return descriptor;
    }
    return -1;
}

void
finit(struct file *file, u_int flags, short type, void *data,
    const struct fileops *operations)
{
    file->f_flag = flags;
    file->f_type = type;
    file->f_data = data;
    file->f_ops = operations;
}

bool
fhold(struct file *file)
{
    u_int count;

    if (file == NULL)
        return false;
    count = __atomic_load_n(&file->f_count, __ATOMIC_ACQUIRE);
    while (count != 0) {
        if (__atomic_compare_exchange_n(&file->f_count, &count, count + 1,
            false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
    return false;
}

int
_fdrop(struct file *file, struct thread *thread)
{
    int error = 0;

    if (file == NULL)
        return EBADF;
    if (file->f_ops != NULL && file->f_ops->fo_close != NULL)
        error = file->f_ops->fo_close(file, thread);
    free(file, M_TEMP);
    return error;
}

int
falloc_noinstall(struct thread *thread, struct file **file_out)
{
    struct file *file;

    (void)thread;
    if (file_out == NULL)
        return EINVAL;
    file = malloc(sizeof(*file), M_TEMP, M_WAITOK | M_ZERO);
    if (file == NULL)
        return ENOMEM;
    file->f_count = 1;
    *file_out = file;
    return 0;
}

int
finstall(struct thread *thread, struct file *file, int *descriptor_out,
    int flags, void *caps)
{
    struct filedesc *filedesc;
    int descriptor;

    (void)caps;
    if (file == NULL || descriptor_out == NULL)
        return EINVAL;
    filedesc = filedesc_get(thread);
    if (filedesc == NULL)
        return ENOMEM;
    FILEDESC_XLOCK(filedesc);
    descriptor = filedesc_allocate_locked(filedesc);
    if (descriptor < 0) {
        FILEDESC_XUNLOCK(filedesc);
        return EMFILE;
    }
    if (!fhold(file)) {
        FILEDESC_XUNLOCK(filedesc);
        return EBADF;
    }
    filedesc->fd_ofiles[descriptor].fde_file = file;
    filedesc->fd_ofiles[descriptor].fde_flags =
        (flags & O_CLOEXEC) != 0 ? 1 : 0;
    FILEDESC_XUNLOCK(filedesc);
    *descriptor_out = descriptor;
    return 0;
}

int
falloc(struct thread *thread, struct file **file_out, int *descriptor_out,
    int flags)
{
    struct file *file;
    int error;

    error = falloc_noinstall(thread, &file);
    if (error != 0)
        return error;
    error = finstall(thread, file, descriptor_out, flags, NULL);
    if (error != 0) {
        fdrop(file, thread);
        return error;
    }
    *file_out = file;
    return 0;
}

int
fget_unlocked(struct thread *thread, int descriptor,
    const cap_rights_t *rights, struct file **file_out)
{
    struct filedesc *filedesc;
    struct file *file;

    (void)rights;
    if (file_out == NULL || descriptor < 0 ||
        descriptor >= EDGEOS_BSD_FD_MAX)
        return EBADF;
    filedesc = filedesc_get(thread);
    if (filedesc == NULL)
        return EBADF;
    FILEDESC_SLOCK(filedesc);
    file = filedesc->fd_ofiles[descriptor].fde_file;
    if (file == NULL || !fhold(file)) {
        FILEDESC_SUNLOCK(filedesc);
        return EBADF;
    }
    FILEDESC_SUNLOCK(filedesc);
    *file_out = file;
    return 0;
}

int
fget(struct thread *thread, int descriptor, const cap_rights_t *rights,
    struct file **file_out)
{
    return fget_unlocked(thread, descriptor, rights, file_out);
}

int
fgetvp(struct thread *thread, int descriptor, const cap_rights_t *rights,
    struct vnode **vnode_out)
{
    struct file *file;
    struct vnode *vnode;
    int error;

    if (vnode_out == NULL)
        return EINVAL;
    error = fget(thread, descriptor, rights, &file);
    if (error != 0)
        return error;
    vnode = file->f_vnode;
    if (vnode == NULL && file->f_type == DTYPE_VNODE)
        vnode = file->f_data;
    if (vnode == NULL) {
        fdrop(file, thread);
        return EINVAL;
    }
    vref(vnode);
    fdrop(file, thread);
    *vnode_out = vnode;
    return 0;
}

int
fdclose(struct thread *thread, struct file *file, int descriptor)
{
    struct filedesc *filedesc;

    if (descriptor < 0 || descriptor >= EDGEOS_BSD_FD_MAX)
        return EBADF;
    filedesc = filedesc_get(thread);
    if (filedesc == NULL)
        return EBADF;
    FILEDESC_XLOCK(filedesc);
    if (filedesc->fd_ofiles[descriptor].fde_file != file) {
        FILEDESC_XUNLOCK(filedesc);
        return EBADF;
    }
    filedesc->fd_ofiles[descriptor].fde_file = NULL;
    filedesc->fd_ofiles[descriptor].fde_flags = 0;
    if (descriptor < filedesc->fd_freefile)
        filedesc->fd_freefile = descriptor;
    FILEDESC_XUNLOCK(filedesc);
    return fdrop(file, thread);
}

void *
fiodgname_buf_get_ptr(void *argument, u_long command)
{
    struct fiodgname_arg *request = argument;

    (void)command;
    return request ? request->buf : NULL;
}

int
invfo_truncate(struct file *file, off_t length, struct ucred *credential,
    struct thread *thread)
{
    (void)file;
    (void)length;
    (void)credential;
    (void)thread;
    return EOPNOTSUPP;
}

int
invfo_chmod(struct file *file, mode_t mode, struct ucred *credential,
    struct thread *thread)
{
    (void)file;
    (void)mode;
    (void)credential;
    (void)thread;
    return EOPNOTSUPP;
}

int
invfo_chown(struct file *file, uid_t user, gid_t group,
    struct ucred *credential, struct thread *thread)
{
    (void)file;
    (void)user;
    (void)group;
    (void)credential;
    (void)thread;
    return EOPNOTSUPP;
}

int
invfo_sendfile(struct file *file, int socket, struct uio *headers,
    struct uio *trailers, off_t offset, size_t count, off_t *sent,
    int flags, struct thread *thread)
{
    (void)file;
    (void)socket;
    (void)headers;
    (void)trailers;
    (void)offset;
    (void)count;
    (void)sent;
    (void)flags;
    (void)thread;
    return EOPNOTSUPP;
}

int
vn_fill_kinfo_vnode(struct vnode *vnode, struct kinfo_file *information)
{
    if (!vnode || !information)
        return EINVAL;
    information->kf_type = vnode->v_rdev ? KF_TYPE_DEV : KF_TYPE_VNODE;
    return 0;
}

void
vref(struct vnode *vnode)
{
    if (vnode)
        __atomic_add_fetch(&vnode->v_refcount, 1u, __ATOMIC_RELAXED);
}

void
vrefact(struct vnode *vnode)
{
    vref(vnode);
}

void
vrele(struct vnode *vnode)
{
    uint32_t references;

    if (!vnode)
        return;
    references = __atomic_load_n(&vnode->v_refcount, __ATOMIC_RELAXED);
    while (references != 0 &&
        !__atomic_compare_exchange_n(&vnode->v_refcount, &references,
            references - 1u, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
    }
}
