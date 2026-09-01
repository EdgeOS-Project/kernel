/* SPDX-License-Identifier: BSD-3-Clause */
/* File descriptor table contract used by FreeBSD LinuxKPI. */

#ifndef _SYS_FILEDESC_H_
#define _SYS_FILEDESC_H_

#include <sys/file.h>
#include <sys/capsicum.h>
#include <sys/sx.h>

#define EDGEOS_BSD_FD_MAX 256

struct filedescent {
    struct file *fde_file;
    uint8_t fde_flags;
};

struct filedesc {
    struct sx fd_sx;
    int fd_freefile;
    int fd_refcnt;
    struct filedescent fd_ofiles[EDGEOS_BSD_FD_MAX];
};

#define FILEDESC_LOCK_INIT(fdp) sx_init(&(fdp)->fd_sx, "filedesc structure")
#define FILEDESC_LOCK_DESTROY(fdp) sx_destroy(&(fdp)->fd_sx)
#define FILEDESC_XLOCK(fdp) sx_xlock(&(fdp)->fd_sx)
#define FILEDESC_XUNLOCK(fdp) sx_xunlock(&(fdp)->fd_sx)
#define FILEDESC_SLOCK(fdp) sx_slock(&(fdp)->fd_sx)
#define FILEDESC_SUNLOCK(fdp) sx_sunlock(&(fdp)->fd_sx)

int falloc(struct thread *thread, struct file **file, int *descriptor,
    int flags);
int falloc_noinstall(struct thread *thread, struct file **file);
int finstall(struct thread *thread, struct file *file, int *descriptor,
    int flags, void *caps);
int fget_unlocked(struct thread *thread, int descriptor,
    const cap_rights_t *rights, struct file **file);
int fdclose(struct thread *thread, struct file *file, int descriptor);

#endif
