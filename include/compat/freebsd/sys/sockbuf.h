/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD socket buffer state backed by EdgeOS sleep and mutex services. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_SOCKBUF_H
#define EDGEOS_COMPAT_FREEBSD_SYS_SOCKBUF_H

#include <sys/_callout.h>
#include <sys/mutex.h>
#include <sys/types.h>

#define SB_WAIT 0x0004
#define SBS_CANTSENDMORE 0x0010
#define SBS_CANTRCVMORE 0x0020

struct socket;

struct sockbuf {
    struct mtx *sb_mtx;
    short sb_state;
    short sb_flags;
    u_int sb_acc;
    u_int sb_ccc;
    u_int sb_mbcnt;
    u_int sb_ctl;
    u_int sb_hiwat;
    u_int sb_lowat;
    u_int sb_mbmax;
    sbintime_t sb_timeo;
};

typedef enum {
    SO_RCV,
    SO_SND,
} sb_which;

#define SOCKBUF_MTX(buffer) ((buffer)->sb_mtx)
#define SOCKBUF_LOCK(buffer) mtx_lock(SOCKBUF_MTX(buffer))
#define SOCKBUF_UNLOCK(buffer) mtx_unlock(SOCKBUF_MTX(buffer))
#define SOCKBUF_OWNED(buffer) mtx_owned(SOCKBUF_MTX(buffer))

int sbwait(struct socket *socket, sb_which which);

#endif
