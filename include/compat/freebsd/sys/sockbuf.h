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
struct mbuf;
struct sockaddr;
typedef int so_upcall_t(struct socket *, void *, int);

struct sockbuf {
    struct mtx *sb_mtx;
    struct mbuf *sb_mb;
    struct mbuf *sb_mbtail;
    struct mbuf *sb_lastrecord;
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
    so_upcall_t *sb_upcall;
    void *sb_upcallarg;
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
int sbappendaddr(struct sockbuf *, const struct sockaddr *, struct mbuf *,
    struct mbuf *);
int sbappendaddr_locked(struct sockbuf *, const struct sockaddr *,
    struct mbuf *, struct mbuf *);
void sbappendrecord(struct sockbuf *, struct mbuf *);
void sbappend(struct sockbuf *, struct mbuf *, int);
void sbdrop(struct sockbuf *, int);
void sbdroprecord(struct sockbuf *);
struct mbuf *sbcreatecontrol(const void *, u_int, int, int, int);

static inline u_int
sbavail(struct sockbuf *buffer)
{
    return buffer->sb_acc;
}

static inline long
sbspace(struct sockbuf *buffer)
{
    long byte_space = (long)buffer->sb_hiwat - (long)buffer->sb_ccc;
    long mbuf_space = (long)buffer->sb_mbmax - (long)buffer->sb_mbcnt;

    return byte_space < mbuf_space ? byte_space : mbuf_space;
}

#endif
