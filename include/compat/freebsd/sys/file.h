/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD file object ABI backed by the EdgeOS descriptor bridge. */

#ifndef _SYS_FILE_H_
#define _SYS_FILE_H_

#include <stdbool.h>
#include <sys/capsicum.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/selinfo.h>
#include <sys/sigio.h>
#include <sys/uio.h>
#include <vm/vm.h>
#include <vm/vm_map.h>

struct file;
struct filedesc;
struct kaiocb;
struct kinfo_file;
struct knote;
struct proc;
struct stat;
struct thread;
struct ucred;
struct uio;

typedef int fo_rdwr_t(struct file *, struct uio *, struct ucred *, int,
    struct thread *);
typedef int fo_truncate_t(struct file *, off_t, struct ucred *,
    struct thread *);
typedef int fo_ioctl_t(struct file *, u_long, void *, struct ucred *,
    struct thread *);
typedef int fo_poll_t(struct file *, int, struct ucred *, struct thread *);
typedef int fo_kqfilter_t(struct file *, struct knote *);
typedef int fo_stat_t(struct file *, struct stat *, struct ucred *);
typedef int fo_close_t(struct file *, struct thread *);
typedef void fo_fdclose_t(struct file *, int, struct thread *);
typedef int fo_chmod_t(struct file *, mode_t, struct ucred *, struct thread *);
typedef int fo_chown_t(struct file *, uid_t, gid_t, struct ucred *,
    struct thread *);
typedef int fo_sendfile_t(struct file *, int, struct uio *, struct uio *,
    off_t, size_t, off_t *, int, struct thread *);
typedef int fo_seek_t(struct file *, off_t, int, struct thread *);
typedef int fo_fill_kinfo_t(struct file *, struct kinfo_file *,
    struct filedesc *);
typedef int fo_mmap_t(struct file *, vm_map_t, vm_offset_t *, vm_size_t,
    vm_prot_t, vm_prot_t, int, vm_ooffset_t, struct thread *);
typedef int fo_aio_queue_t(struct file *, struct kaiocb *);
typedef int fo_add_seals_t(struct file *, int);
typedef int fo_get_seals_t(struct file *, int *);
typedef int fo_fallocate_t(struct file *, off_t, off_t, struct thread *);
typedef int fo_fspacectl_t(struct file *, int, off_t *, off_t *, int,
    struct ucred *, struct thread *);
typedef int fo_cmp_t(struct file *, struct file *, struct thread *);
typedef int fo_fork_t(struct filedesc *, struct file *, struct file **,
    struct proc *, struct thread *);
typedef int fo_spare_t(struct file *);

struct fileops {
    fo_rdwr_t *fo_read;
    fo_rdwr_t *fo_write;
    fo_truncate_t *fo_truncate;
    fo_ioctl_t *fo_ioctl;
    fo_poll_t *fo_poll;
    fo_kqfilter_t *fo_kqfilter;
    fo_stat_t *fo_stat;
    fo_close_t *fo_close;
    fo_fdclose_t *fo_fdclose;
    fo_chmod_t *fo_chmod;
    fo_chown_t *fo_chown;
    fo_sendfile_t *fo_sendfile;
    fo_seek_t *fo_seek;
    fo_fill_kinfo_t *fo_fill_kinfo;
    fo_mmap_t *fo_mmap;
    fo_aio_queue_t *fo_aio_queue;
    fo_add_seals_t *fo_add_seals;
    fo_get_seals_t *fo_get_seals;
    fo_fallocate_t *fo_fallocate;
    fo_fspacectl_t *fo_fspacectl;
    fo_cmp_t *fo_cmp;
    fo_fork_t *fo_fork;
    fo_spare_t *fo_spares[8];
    int fo_flags;
};

#define DFLAG_PASSABLE 0x01
#define DFLAG_SEEKABLE 0x02
#define DFLAG_FORK 0x04

#define DTYPE_VNODE 1
#define DTYPE_SOCKET 2
#define DTYPE_PIPE 3
#define DTYPE_DEV 4

struct file {
    volatile u_int f_flag;
    volatile u_int f_count;
    void *f_data;
    const struct fileops *f_ops;
    struct vnode *f_vnode;
    struct ucred *f_cred;
    short f_type;
    short f_vflags;
    off_t f_offset;
};

#ifndef FASYNC
#define FASYNC 0x0040
#endif

bool fhold(struct file *file);
int fget(struct thread *thread, int descriptor, const cap_rights_t *rights,
    struct file **file);
int fgetvp(struct thread *thread, int descriptor, const cap_rights_t *rights,
    struct vnode **vnode);
extern fo_truncate_t invfo_truncate;
extern fo_chmod_t invfo_chmod;
extern fo_chown_t invfo_chown;
extern fo_sendfile_t invfo_sendfile;
int _fdrop(struct file *file, struct thread *thread);
void finit(struct file *file, u_int flags, short type, void *data,
    const struct fileops *operations);
int vn_fill_kinfo_vnode(struct vnode *vnode, struct kinfo_file *information);

#define fdrop(file, thread) \
    (__atomic_sub_fetch(&(file)->f_count, 1u, __ATOMIC_ACQ_REL) == 0 ? \
        _fdrop((file), (thread)) : 0)

#endif
