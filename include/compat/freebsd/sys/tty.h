/* SPDX-License-Identifier: BSD-2-Clause */
/* TTY declarations used by unmodified FreeBSD drivers. */

#ifndef _SYS_TTY_H_
#define _SYS_TTY_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/_termios.h>
#include <sys/types.h>
#include "conf.h"
#include "ioccom.h"
#include "mutex.h"

#ifndef _SYS__WINSIZE_H_
#define _SYS__WINSIZE_H_
struct winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};
#endif

struct thread;
struct tty;

typedef int tsw_open_t(struct tty *);
typedef void tsw_close_t(struct tty *);
typedef void tsw_outwakeup_t(struct tty *);
typedef void tsw_inwakeup_t(struct tty *);
typedef int tsw_ioctl_t(struct tty *, unsigned long, char *, struct thread *);
typedef int tsw_cioctl_t(struct tty *, int, unsigned long, char *,
    struct thread *);
typedef int tsw_param_t(struct tty *, struct termios *);
typedef int tsw_modem_t(struct tty *, int, int);
typedef void tsw_free_t(void *);
typedef bool tsw_busy_t(struct tty *);

struct ttydevsw {
    unsigned int tsw_flags;
    tsw_open_t *tsw_open;
    tsw_close_t *tsw_close;
    tsw_outwakeup_t *tsw_outwakeup;
    tsw_inwakeup_t *tsw_inwakeup;
    tsw_ioctl_t *tsw_ioctl;
    tsw_cioctl_t *tsw_cioctl;
    tsw_param_t *tsw_param;
    tsw_modem_t *tsw_modem;
    void *tsw_mmap;
    void *tsw_pktnotify;
    tsw_free_t *tsw_free;
    tsw_busy_t *tsw_busy;
    void *tsw_spare[3];
};

#define TF_NOPREFIX 0x00001u
#define TF_INITLOCK 0x00002u
#define TF_CALLOUT 0x00004u
#define TF_OPENED_IN 0x00008u
#define TF_OPENED_OUT 0x00010u
#define TF_OPENED_CONS 0x00020u
#define TF_OPENED (TF_OPENED_IN | TF_OPENED_OUT | TF_OPENED_CONS)
#define TF_GONE 0x00040u
#define TF_STOPPED 0x01000u
#define TF_BYPASS 0x04000u

struct tty {
    struct mtx *t_mtx;
    struct mtx t_mtxobj;
    unsigned int t_flags;
    struct termios t_termios;
    struct winsize t_winsize;
    struct termios t_termios_init_in;
    struct termios t_termios_lock_in;
    struct termios t_termios_init_out;
    struct termios t_termios_lock_out;
    struct ttydevsw *t_devsw;
    void *t_devswsoftc;
    struct cdev *t_dev;
    void *edgeos_state;
};

struct tty *tty_alloc(struct ttydevsw *driver, void *softc);
struct tty *tty_alloc_mutex(struct ttydevsw *driver, void *softc,
    struct mtx *mutex);
void tty_rel_gone(struct tty *tty);
int tty_makedevf(struct tty *tty, void *credential, int flags,
    const char *format, ...);
void tty_set_winsize(struct tty *tty, const struct winsize *size);
void tty_init_console(struct tty *tty, speed_t speed);

#define tty_makedev(tty, credential, format, ...) \
    ((void)tty_makedevf((tty), (credential), 0, (format), ##__VA_ARGS__))
#define tty_lock(tty) mtx_lock((tty)->t_mtx)
#define tty_unlock(tty) mtx_unlock((tty)->t_mtx)
#define tty_assert_locked(tty) mtx_assert((tty)->t_mtx, MA_OWNED)
#define tty_opened(tty) (((tty)->t_flags & TF_OPENED) != 0)
#define tty_gone(tty) (((tty)->t_flags & TF_GONE) != 0)
#define tty_softc(tty) ((tty)->t_devswsoftc)

int ttydisc_rint(struct tty *tty, char byte, int flags);
size_t ttydisc_rint_simple(struct tty *tty, const void *buffer,
    size_t length);
size_t ttydisc_rint_bypass(struct tty *tty, const void *buffer,
    size_t length);
void ttydisc_rint_done(struct tty *tty);
size_t ttydisc_rint_poll(struct tty *tty);
size_t ttydisc_getc(struct tty *tty, void *buffer, size_t length);
size_t ttydisc_getc_poll(struct tty *tty);
void ttydisc_modem(struct tty *tty, int open);

#define ttydisc_can_bypass(tty) ((tty)->t_flags & TF_BYPASS)

#define TRE_FRAMING 0x01
#define TRE_PARITY 0x02
#define TRE_OVERRUN 0x04
#define TRE_BREAK 0x08

#define TIOCCBRK _IO('t', 122)
#define TIOCSBRK _IO('t', 123)
#define TIOCSPGRP _IOW('t', 118, int)
#define TIOCGPGRP _IOR('t', 119, int)

#endif
