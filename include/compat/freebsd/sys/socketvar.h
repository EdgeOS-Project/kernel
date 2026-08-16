/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD socket lifecycle mapped onto shared EdgeOS synchronization. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_SOCKETVAR_H
#define EDGEOS_COMPAT_FREEBSD_SYS_SOCKETVAR_H

#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/sockbuf.h>
#include <sys/socket.h>
#include <sys/sx.h>

TAILQ_HEAD(accept_queue, socket);

struct socket {
    struct mtx so_lock;
    volatile u_int so_count;
    int so_options;
    short so_type;
    short so_state;
    void *so_pcb;
    struct protosw *so_proto;
    short so_timeo;
    u_short so_error;
    u_short so_rerror;
    struct sx so_snd_sx;
    struct mtx so_snd_mtx;
    struct sx so_rcv_sx;
    struct mtx so_rcv_mtx;
    struct sockbuf so_rcv;
    struct sockbuf so_snd;
    TAILQ_ENTRY(socket) so_list;
    struct socket *so_listen;
    struct accept_queue sol_incomp;
    struct accept_queue sol_comp;
    u_int sol_qlen;
    u_int sol_incqlen;
    u_int sol_qlimit;
};

#define SS_ISCONNECTED 0x0002
#define SS_ISCONNECTING 0x0004
#define SS_ISDISCONNECTING 0x0008
#define SS_NBIO 0x0100
#define SS_ASYNC 0x0200
#define SS_ISDISCONNECTED 0x2000

#define SOCK_LOCK(socket) mtx_lock(&(socket)->so_lock)
#define SOCK_UNLOCK(socket) mtx_unlock(&(socket)->so_lock)
#define SOCK_OWNED(socket) mtx_owned(&(socket)->so_lock)

#define SOLISTENING(socket) (((socket)->so_options & SO_ACCEPTCONN) != 0)

#define SOCK_RECVBUF_LOCK(socket) mtx_lock(&(socket)->so_rcv_mtx)
#define SOCK_RECVBUF_UNLOCK(socket) mtx_unlock(&(socket)->so_rcv_mtx)
#define SOCK_SENDBUF_LOCK(socket) mtx_lock(&(socket)->so_snd_mtx)
#define SOCK_SENDBUF_UNLOCK(socket) mtx_unlock(&(socket)->so_snd_mtx)

#define SBL_WAIT 0x00000001
#define SBL_NOINTR 0x00000002
#define SBLOCKWAIT(flags) (((flags) & MSG_DONTWAIT) ? 0 : SBL_WAIT)

#define SOCK_IO_SEND_LOCK(socket, flags) \
    soiolock((socket), &(socket)->so_snd_sx, (flags))
#define SOCK_IO_SEND_UNLOCK(socket) soiounlock(&(socket)->so_snd_sx)
#define SOCK_IO_RECV_LOCK(socket, flags) \
    soiolock((socket), &(socket)->so_rcv_sx, (flags))
#define SOCK_IO_RECV_UNLOCK(socket) soiounlock(&(socket)->so_rcv_sx)

int soiolock(struct socket *socket, struct sx *lock, int flags);
void soiounlock(struct sx *lock);
int solisten_proto_check(struct socket *socket);
void solisten_proto(struct socket *socket, int backlog);
struct socket *sonewconn(struct socket *listener, int connection_status);
int sodisconnect(struct socket *socket);
void soisconnecting(struct socket *socket);
void soisconnected(struct socket *socket);
void soisdisconnecting(struct socket *socket);
void soisdisconnected(struct socket *socket);
void socantsendmore(struct socket *socket);
void socantrcvmore(struct socket *socket);
void sorwakeup_locked(struct socket *socket);
void sowwakeup_locked(struct socket *socket);

#endif
