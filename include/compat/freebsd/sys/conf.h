/* SPDX-License-Identifier: BSD-2-Clause */
/* Character-device declarations used by unmodified FreeBSD drivers. */

#ifndef _SYS_CONF_H_
#define _SYS_CONF_H_

#include <sys/types.h>
#include <vm/vm.h>
#include <sys/queue.h>

#define D_VERSION 0x20011966
#define D_DISK 0x0002
#define D_TRACKCLOSE 0x00080000
#define D_GIANTOK 0x00200000
#define D_NEEDGIANT 0x00400000
#define D_NEEDMINOR 0x00800000

#define SI_ALIAS 0x0002u
#define SI_NAMED 0x0004u
#define SI_UNMAPPED 0x0400u

#define MAKEDEV_WAITOK 0x00000001
#define MAKEDEV_NOWAIT 0x00000002
#define MAKEDEV_CHECKNAME 0x00000004
#define MAKEDEV_REF 0x00000008

#define UID_ROOT 0
#define UID_BIN 3
#define UID_UUCP 66
#define UID_NOBODY 65534
#define GID_WHEEL 0
#define GID_KMEM 2
#define GID_TTY 4
#define GID_OPERATOR 5
#define GID_BIN 7
#define GID_GAMES 13
#define GID_AUDIO 43
#define GID_VIDEO 44
#define GID_RT_PRIO 47
#define GID_ID_PRIO 48
#define GID_DIALER 68
#define GID_U2F 116
#define GID_VMM 978
#define GID_NOGROUP 65533
#define GID_NOBODY 65534

struct tty;
struct thread;
struct uio;
struct bio;
struct knote;
struct cdev;
struct clonedevs;
struct ucred;
struct vm_object;

typedef int d_open_t(struct cdev *, int, int, struct thread *);
struct file;
typedef int d_fdopen_t(struct cdev *, int, struct thread *, struct file *);
typedef int d_close_t(struct cdev *, int, int, struct thread *);
typedef void d_strategy_t(struct bio *);
typedef int d_read_t(struct cdev *, struct uio *, int);
typedef int d_write_t(struct cdev *, struct uio *, int);
typedef int d_ioctl_t(struct cdev *, unsigned long, caddr_t, int,
    struct thread *);
typedef int d_poll_t(struct cdev *, int, struct thread *);
typedef int d_kqfilter_t(struct cdev *, struct knote *);
typedef int d_mmap_t(struct cdev *, vm_ooffset_t, vm_paddr_t *, int,
    vm_memattr_t *);
typedef int d_mmap_single_t(struct cdev *, vm_ooffset_t *, vm_size_t,
    struct vm_object **, int);
typedef void d_priv_dtor_t(void *);

struct cdevsw {
    int d_version;
    d_open_t *d_open;
    d_fdopen_t *d_fdopen;
    d_close_t *d_close;
    d_read_t *d_read;
    d_write_t *d_write;
    d_ioctl_t *d_ioctl;
    d_poll_t *d_poll;
    d_kqfilter_t *d_kqfilter;
    d_mmap_t *d_mmap;
    d_mmap_single_t *d_mmap_single;
    d_strategy_t *d_strategy;
    const char *d_name;
    int d_flags;
    LIST_HEAD(, cdev) d_devs;
};

struct cdev {
    unsigned int si_flags;
    uid_t si_uid;
    gid_t si_gid;
    mode_t si_mode;
    int si_drv0;
    void *si_drv1;
    void *si_drv2;
    struct cdev *si_parent;
    struct cdev *edgeos_alias_head;
    struct cdev *edgeos_alias_next;
    struct tty *si_tty;
    struct cdevsw *si_devsw;
    int si_unit;
    int si_iosize_max;
    uint32_t si_linux_major;
    uint32_t si_linux_minor;
    volatile uint32_t edgeos_references;
    uint32_t edgeos_open_sessions;
    uint8_t edgeos_transition_active;
    uint8_t edgeos_delisted;
    char si_name[128];
    LIST_ENTRY(cdev) si_list;
};

struct make_dev_args {
    size_t mda_size;
    int mda_flags;
    struct cdevsw *mda_devsw;
    int mda_unit;
    uid_t mda_uid;
    gid_t mda_gid;
    mode_t mda_mode;
    struct ucred *mda_cr;
    void *mda_si_drv1;
    void *mda_si_drv2;
};

static inline void
make_dev_args_init(struct make_dev_args *arguments)
{
    if (!arguments)
        return;
    arguments->mda_size = sizeof(*arguments);
    arguments->mda_flags = 0;
    arguments->mda_devsw = 0;
    arguments->mda_unit = 0;
    arguments->mda_uid = 0;
    arguments->mda_gid = 0;
    arguments->mda_mode = 0;
    arguments->mda_cr = 0;
    arguments->mda_si_drv1 = 0;
    arguments->mda_si_drv2 = 0;
}

struct cdev *make_dev(struct cdevsw *driver, int unit, uid_t uid,
    gid_t gid, int mode, const char *format, ...);
struct cdev *make_dev_credf(int flags, struct cdevsw *driver, int unit,
    struct ucred *credential, uid_t uid, gid_t gid, int mode,
    const char *format, ...);
int make_dev_s(const struct make_dev_args *arguments,
    struct cdev **result, const char *format, ...);
int make_dev_p(int flags, struct cdev **result, struct cdevsw *driver,
    struct ucred *credential, uid_t uid, gid_t gid, int mode,
    const char *format, ...);
struct cdev *make_dev_alias(struct cdev *parent, const char *format, ...);
int make_dev_alias_p(int flags, struct cdev **result,
    struct cdev *parent, const char *format, ...);
void delist_dev(struct cdev *device);
void destroy_dev(struct cdev *device);
int destroy_dev_sched(struct cdev *device);
void dev_ref(struct cdev *device);
void dev_rel(struct cdev *device);
struct cdevsw *dev_refthread(struct cdev *device, int *reference);
void dev_relthread(struct cdev *device, int reference);
void dev_lock(void);
void dev_unlock(void);
const char *devtoname(const struct cdev *device);
int physread(struct cdev *device, struct uio *uio, int io_flags);
int physwrite(struct cdev *device, struct uio *uio, int io_flags);

int devfs_set_cdevpriv(void *data, d_priv_dtor_t *destructor);
int devfs_get_cdevpriv(void **data);
void devfs_clear_cdevpriv(void);
int devfs_foreach_cdevpriv(struct cdev *device,
    int (*callback)(void *data, void *argument), void *argument);

int dev_stdclone(char *name, char **name_end, const char *stem, int *unit);
void clone_setup(struct clonedevs **clones);
void clone_cleanup(struct clonedevs **clones);
int clone_create(struct clonedevs **clones, struct cdevsw *driver,
    int *unit, struct cdev **device, int extra);

#define dev2unit(device) ((device)->si_unit)
static inline uint64_t
dev2udev(const struct cdev *device)
{
    if (!device)
        return 0;
    return ((uint64_t)device->si_linux_major << 32) |
        device->si_linux_minor;
}
#define DEVFS_IOSIZE_MAX (1 << 20)

#define DEV_MODULE_ORDERED(name, handler, argument, order)                \
    static moduledata_t name##_mod = {                                    \
        #name, (handler), (argument)                                      \
    };                                                                    \
    DECLARE_MODULE(name, name##_mod, SI_SUB_DRIVERS, order)
#define DEV_MODULE(name, handler, argument)                               \
    DEV_MODULE_ORDERED(name, handler, argument, SI_ORDER_MIDDLE)

#endif
