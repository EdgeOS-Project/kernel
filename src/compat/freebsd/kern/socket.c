/* SPDX-License-Identifier: MPL-2.0 */
/* Shared socket services required by imported FreeBSD transports. */

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/systm.h>

int domain_init_status = 1;
struct domainhead domains = SLIST_HEAD_INITIALIZER(domains);

static void
bsd_socket_initialize(struct socket *socket, struct protosw *protocol,
    short type)
{
    bzero(socket, sizeof(*socket));
    mtx_init(&socket->so_lock, "bsd socket", NULL, MTX_DEF);
    mtx_init(&socket->so_snd_mtx, "bsd socket send", NULL, MTX_DEF);
    mtx_init(&socket->so_rcv_mtx, "bsd socket receive", NULL, MTX_DEF);
    sx_init(&socket->so_snd_sx, "bsd socket send io");
    sx_init(&socket->so_rcv_sx, "bsd socket receive io");
    socket->so_count = 1;
    socket->so_type = type;
    socket->so_proto = protocol;
    socket->so_snd.sb_mtx = &socket->so_snd_mtx;
    socket->so_rcv.sb_mtx = &socket->so_rcv_mtx;
    socket->so_snd.sb_hiwat = 256 * 1024;
    socket->so_rcv.sb_hiwat = 256 * 1024;
    socket->so_snd.sb_lowat = 1;
    socket->so_rcv.sb_lowat = 1;
    TAILQ_INIT(&socket->sol_incomp);
    TAILQ_INIT(&socket->sol_comp);
}

void
domain_add(struct domain *domain)
{
    if (!domain)
        return;
    if (domain->dom_probe && domain->dom_probe() != 0)
        return;
    for (u_int index = 0; index < domain->dom_nprotosw; ++index) {
        if (domain->dom_protosw[index])
            domain->dom_protosw[index]->pr_domain = domain;
    }
    SLIST_INSERT_HEAD(&domains, domain, dom_next);
}

void
domain_remove(struct domain *domain)
{
    if (!domain)
        return;
    SLIST_REMOVE(&domains, domain, domain, dom_next);
}

struct domain *
pffinddomain(int family)
{
    struct domain *domain;

    SLIST_FOREACH(domain, &domains, dom_next) {
        if (domain->dom_family == family)
            return domain;
    }
    return NULL;
}

struct protosw *
pffindproto(int family, int type, int protocol)
{
    struct domain *domain = pffinddomain(family);

    if (!domain)
        return NULL;
    for (u_int index = 0; index < domain->dom_nprotosw; ++index) {
        struct protosw *candidate = domain->dom_protosw[index];

        if (candidate && candidate->pr_type == type &&
            (protocol == 0 || candidate->pr_protocol == protocol))
            return candidate;
    }
    return NULL;
}

int
soiolock(struct socket *socket, struct sx *lock, int flags)
{
    (void)socket;
    if ((flags & SBL_WAIT) != 0) {
        sx_xlock(lock);
        return 0;
    }
    return sx_try_xlock(lock) ? 0 : EWOULDBLOCK;
}

void
soiounlock(struct sx *lock)
{
    sx_xunlock(lock);
}

int
solisten_proto_check(struct socket *socket)
{
    if (!socket || !socket->so_proto || !socket->so_proto->pr_listen)
        return EOPNOTSUPP;
    if ((socket->so_state & (SS_ISCONNECTED | SS_ISCONNECTING |
        SS_ISDISCONNECTING)) != 0)
        return EINVAL;
    return 0;
}

void
solisten_proto(struct socket *socket, int backlog)
{
    if (!socket)
        return;
    if (backlog < 0)
        backlog = 0;
    socket->so_options |= SO_ACCEPTCONN;
    socket->sol_qlimit = (u_int)backlog;
    TAILQ_INIT(&socket->sol_incomp);
    TAILQ_INIT(&socket->sol_comp);
    socket->sol_incqlen = 0;
    socket->sol_qlen = 0;
}

struct socket *
sonewconn(struct socket *listener, int connection_status)
{
    struct socket *socket;
    int error;

    if (!listener || !listener->so_proto || !SOLISTENING(listener))
        return NULL;
    if (listener->sol_qlimit &&
        listener->sol_incqlen + listener->sol_qlen >= listener->sol_qlimit)
        return NULL;
    socket = malloc(sizeof(*socket), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!socket)
        return NULL;
    bsd_socket_initialize(socket, listener->so_proto, listener->so_type);
    socket->so_listen = listener;
    socket->so_snd.sb_hiwat = listener->so_snd.sb_hiwat;
    socket->so_rcv.sb_hiwat = listener->so_rcv.sb_hiwat;
    error = socket->so_proto->pr_attach ?
        socket->so_proto->pr_attach(socket, socket->so_proto->pr_protocol,
            NULL) : 0;
    if (error != 0) {
        sx_destroy(&socket->so_snd_sx);
        sx_destroy(&socket->so_rcv_sx);
        mtx_destroy(&socket->so_snd_mtx);
        mtx_destroy(&socket->so_rcv_mtx);
        mtx_destroy(&socket->so_lock);
        free(socket, M_DEVBUF);
        return NULL;
    }
    TAILQ_INSERT_TAIL(&listener->sol_incomp, socket, so_list);
    listener->sol_incqlen++;
    if (connection_status != 0)
        soisconnected(socket);
    return socket;
}

int
sodisconnect(struct socket *socket)
{
    if (!socket || !socket->so_proto || !socket->so_proto->pr_disconnect)
        return EOPNOTSUPP;
    return socket->so_proto->pr_disconnect(socket);
}

void
soisconnecting(struct socket *socket)
{
    if (!socket)
        return;
    socket->so_state &= ~(SS_ISCONNECTED | SS_ISDISCONNECTING |
        SS_ISDISCONNECTED);
    socket->so_state |= SS_ISCONNECTING;
}

void
soisconnected(struct socket *socket)
{
    struct socket *listener;

    if (!socket)
        return;
    socket->so_state &= ~(SS_ISCONNECTING | SS_ISDISCONNECTING |
        SS_ISDISCONNECTED);
    socket->so_state |= SS_ISCONNECTED;
    listener = socket->so_listen;
    if (listener && listener->sol_incqlen != 0) {
        TAILQ_REMOVE(&listener->sol_incomp, socket, so_list);
        listener->sol_incqlen--;
        TAILQ_INSERT_TAIL(&listener->sol_comp, socket, so_list);
        listener->sol_qlen++;
        wakeup(listener);
    }
    wakeup(socket);
}

void
soisdisconnecting(struct socket *socket)
{
    if (!socket)
        return;
    socket->so_state &= ~(SS_ISCONNECTING | SS_ISCONNECTED);
    socket->so_state |= SS_ISDISCONNECTING;
    wakeup(socket);
}

void
soisdisconnected(struct socket *socket)
{
    if (!socket)
        return;
    socket->so_state &= ~(SS_ISCONNECTING | SS_ISCONNECTED |
        SS_ISDISCONNECTING);
    socket->so_state |= SS_ISDISCONNECTED;
    socket->so_snd.sb_state |= SBS_CANTSENDMORE;
    socket->so_rcv.sb_state |= SBS_CANTRCVMORE;
    wakeup(socket);
    wakeup(&socket->so_snd);
    wakeup(&socket->so_rcv);
}

void
socantsendmore(struct socket *socket)
{
    if (!socket)
        return;
    socket->so_snd.sb_state |= SBS_CANTSENDMORE;
    wakeup(&socket->so_snd);
}

void
socantrcvmore(struct socket *socket)
{
    if (!socket)
        return;
    socket->so_rcv.sb_state |= SBS_CANTRCVMORE;
    wakeup(&socket->so_rcv);
}

int
sbwait(struct socket *socket, sb_which which)
{
    struct sockbuf *buffer;

    if (!socket)
        return EINVAL;
    buffer = which == SO_RCV ? &socket->so_rcv : &socket->so_snd;
    buffer->sb_flags |= SB_WAIT;
    int error = bsd_msleep(buffer, buffer->sb_mtx, 0, "bsd socket buffer",
        socket->so_timeo);
    buffer->sb_flags &= ~SB_WAIT;
    return error;
}

void
sorwakeup_locked(struct socket *socket)
{
    if (!socket)
        return;
    wakeup(&socket->so_rcv);
    SOCK_RECVBUF_UNLOCK(socket);
}

void
sowwakeup_locked(struct socket *socket)
{
    if (!socket)
        return;
    wakeup(&socket->so_snd);
    SOCK_SENDBUF_UNLOCK(socket);
}
