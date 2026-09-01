/* SPDX-License-Identifier: MPL-2.0 */
/* Shared socket services required by imported FreeBSD transports. */

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/uio.h>

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
    socket->so_snd.sb_mbmax = 256 * 1024;
    socket->so_rcv.sb_mbmax = 256 * 1024;
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
socreate(int family, struct socket **result, int type, int protocol,
    struct ucred *credential, struct thread *thread)
{
    struct protosw *protocol_switch;
    struct socket *socket;
    int error;

    (void)credential;
    if (!result)
        return EINVAL;
    *result = NULL;
    protocol_switch = pffindproto(family, type, protocol);
    if (!protocol_switch)
        return EPROTONOSUPPORT;
    socket = malloc(sizeof(*socket), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!socket)
        return ENOMEM;
    bsd_socket_initialize(socket, protocol_switch, (short)type);
    error = protocol_switch->pr_attach ?
        protocol_switch->pr_attach(socket, protocol, thread) : 0;
    if (error != 0) {
        (void)soclose(socket);
        return error;
    }
    *result = socket;
    return 0;
}

int
soclose(struct socket *socket)
{
    if (!socket)
        return EINVAL;
    if (socket->so_proto) {
        if (socket->so_proto->pr_close)
            socket->so_proto->pr_close(socket);
        if (socket->so_proto->pr_detach)
            socket->so_proto->pr_detach(socket);
    }
    m_freem(socket->so_snd.sb_mb);
    m_freem(socket->so_rcv.sb_mb);
    sx_destroy(&socket->so_snd_sx);
    sx_destroy(&socket->so_rcv_sx);
    mtx_destroy(&socket->so_snd_mtx);
    mtx_destroy(&socket->so_rcv_mtx);
    mtx_destroy(&socket->so_lock);
    free(socket, M_DEVBUF);
    return 0;
}

int
soreserve(struct socket *socket, u_long send_size, u_long receive_size)
{
    if (!socket || send_size == 0 || receive_size == 0)
        return EINVAL;
    socket->so_snd.sb_hiwat = (u_int)send_size;
    socket->so_rcv.sb_hiwat = (u_int)receive_size;
    socket->so_snd.sb_mbmax = (u_int)send_size;
    socket->so_rcv.sb_mbmax = (u_int)receive_size;
    return 0;
}

int
sooptcopyin(struct sockopt *option, void *buffer, size_t length,
    size_t minimum_length)
{
    size_t copy_length;

    if (!option || !buffer || !option->sopt_val ||
        option->sopt_valsize < minimum_length)
        return EINVAL;
    copy_length = option->sopt_valsize < length ?
        option->sopt_valsize : length;
    return option->sopt_td ?
        bsd_copyin(option->sopt_val, buffer, copy_length) :
        (bcopy(option->sopt_val, buffer, copy_length), 0);
}

int
sooptcopyout(struct sockopt *option, const void *buffer, size_t length)
{
    size_t copy_length;
    int error;

    if (!option || !buffer || !option->sopt_val)
        return EINVAL;
    copy_length = option->sopt_valsize < length ?
        option->sopt_valsize : length;
    error = option->sopt_td ?
        bsd_copyout(buffer, option->sopt_val, copy_length) :
        (bcopy(buffer, option->sopt_val, copy_length), 0);
    if (error == 0)
        option->sopt_valsize = copy_length;
    return error;
}

struct mbuf *
sbcreatecontrol(const void *data, u_int size, int type, int level, int wait)
{
    size_t length = CMSG_SPACE(size);
    struct mbuf *mbuf = m_get2((int)length, wait, MT_CONTROL, 0);
    struct cmsghdr *header;

    if (!mbuf)
        return NULL;
    header = mtod(mbuf, struct cmsghdr *);
    bzero(header, length);
    header->cmsg_len = (socklen_t)CMSG_LEN(size);
    header->cmsg_level = level;
    header->cmsg_type = type;
    if (data && size != 0)
        bcopy(data, CMSG_DATA(header), size);
    mbuf->m_len = (int32_t)length;
    return mbuf;
}

int
sbappendaddr(struct sockbuf *buffer, const struct sockaddr *address,
    struct mbuf *data, struct mbuf *control)
{
    struct mbuf *address_mbuf;
    struct mbuf *tail;
    unsigned int length;

    if (!buffer || !address || !data)
        return 0;
    length = address->sa_len + m_length(data, NULL) +
        m_length(control, NULL);
    if (buffer->sb_hiwat != 0 && buffer->sb_ccc + length > buffer->sb_hiwat)
        return 0;
    address_mbuf = m_get2(address->sa_len, M_NOWAIT, MT_SONAME, 0);
    if (!address_mbuf)
        return 0;
    bcopy(address, mtod(address_mbuf, void *), address->sa_len);
    address_mbuf->m_len = address->sa_len;
    tail = address_mbuf;
    if (control) {
        tail->m_next = control;
        (void)m_length(control, &tail);
    }
    tail->m_next = data;
    (void)m_length(data, &tail);
    if (buffer->sb_lastrecord)
        buffer->sb_lastrecord->m_nextpkt = address_mbuf;
    else
        buffer->sb_mb = address_mbuf;
    buffer->sb_lastrecord = address_mbuf;
    buffer->sb_mbtail = tail;
    buffer->sb_ccc += length;
    buffer->sb_acc += length;
    buffer->sb_mbcnt += length;
    return 1;
}

int
sbappendaddr_locked(struct sockbuf *buffer, const struct sockaddr *address,
    struct mbuf *data, struct mbuf *control)
{
    return sbappendaddr(buffer, address, data, control);
}

void
sbappendrecord(struct sockbuf *buffer, struct mbuf *record)
{
    struct mbuf *tail;
    unsigned int length;

    if (!buffer || !record)
        return;
    length = m_length(record, &tail);
    record->m_nextpkt = NULL;
    if (buffer->sb_lastrecord)
        buffer->sb_lastrecord->m_nextpkt = record;
    else
        buffer->sb_mb = record;
    buffer->sb_lastrecord = record;
    buffer->sb_mbtail = tail;
    buffer->sb_ccc += length;
    buffer->sb_acc += length;
    buffer->sb_mbcnt += length;
}

void
sbappend(struct sockbuf *buffer, struct mbuf *data, int flags)
{
    struct mbuf *tail;
    unsigned int length;

    (void)flags;
    if (!buffer || !data)
        return;
    length = m_length(data, &tail);
    if (buffer->sb_mbtail)
        buffer->sb_mbtail->m_next = data;
    else
        buffer->sb_mb = data;
    buffer->sb_mbtail = tail;
    buffer->sb_ccc += length;
    buffer->sb_acc += length;
    buffer->sb_mbcnt += length;
}

void
sbdrop(struct sockbuf *buffer, int requested_length)
{
    unsigned int removed = 0;

    if (!buffer || requested_length <= 0)
        return;
    while (buffer->sb_mb && requested_length > 0) {
        struct mbuf *mbuf = buffer->sb_mb;

        if (mbuf->m_len > requested_length) {
            mbuf->m_data += requested_length;
            mbuf->m_len -= requested_length;
            removed += (unsigned int)requested_length;
            requested_length = 0;
            break;
        }
        requested_length -= mbuf->m_len;
        removed += (unsigned int)mbuf->m_len;
        buffer->sb_mb = m_free(mbuf);
    }
    if (!buffer->sb_mb) {
        buffer->sb_mbtail = NULL;
        buffer->sb_lastrecord = NULL;
    }
    buffer->sb_ccc = removed > buffer->sb_ccc ? 0 :
        buffer->sb_ccc - removed;
    buffer->sb_acc = removed > buffer->sb_acc ? 0 :
        buffer->sb_acc - removed;
    buffer->sb_mbcnt = removed > buffer->sb_mbcnt ? 0 :
        buffer->sb_mbcnt - removed;
}

void
sbdroprecord(struct sockbuf *buffer)
{
    struct mbuf *record;
    struct mbuf *next_record;
    unsigned int length;

    if (!buffer || !buffer->sb_mb)
        return;
    record = buffer->sb_mb;
    next_record = record->m_nextpkt;
    record->m_nextpkt = NULL;
    length = m_length(record, NULL);
    m_freem(record);
    buffer->sb_mb = next_record;
    if (!next_record) {
        buffer->sb_lastrecord = NULL;
        buffer->sb_mbtail = NULL;
    }
    buffer->sb_ccc = length > buffer->sb_ccc ? 0 :
        buffer->sb_ccc - length;
    buffer->sb_acc = length > buffer->sb_acc ? 0 :
        buffer->sb_acc - length;
    buffer->sb_mbcnt = length > buffer->sb_mbcnt ? 0 :
        buffer->sb_mbcnt - length;
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

void
solisten_proto_abort(struct socket *socket)
{
    (void)socket;
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

int
sobind(struct socket *socket, struct sockaddr *address, struct thread *thread)
{
    if (!socket || !socket->so_proto || !socket->so_proto->pr_bind)
        return EOPNOTSUPP;
    return socket->so_proto->pr_bind(socket, address, thread);
}

int
soconnect(struct socket *socket, struct sockaddr *address,
    struct thread *thread)
{
    if (!socket || !socket->so_proto || !socket->so_proto->pr_connect)
        return EOPNOTSUPP;
    return socket->so_proto->pr_connect(socket, address, thread);
}

int
solisten(struct socket *socket, int backlog, struct thread *thread)
{
    int error = solisten_proto_check(socket);

    if (error != 0)
        return error;
    error = socket->so_proto->pr_listen(socket, backlog, thread);
    if (error != 0) {
        solisten_proto_abort(socket);
        return error;
    }
    solisten_proto(socket, backlog);
    return 0;
}

int
solisten_dequeue(struct socket *listener, struct socket **result, int flags)
{
    struct socket *socket;

    (void)flags;
    if (!listener || !result) {
        if (listener)
            SOLISTEN_UNLOCK(listener);
        return EINVAL;
    }
    socket = TAILQ_FIRST(&listener->sol_comp);
    if (!socket) {
        SOLISTEN_UNLOCK(listener);
        return EWOULDBLOCK;
    }
    TAILQ_REMOVE(&listener->sol_comp, socket, so_list);
    if (listener->sol_qlen != 0)
        listener->sol_qlen--;
    socket->so_listen = NULL;
    SOLISTEN_UNLOCK(listener);
    *result = socket;
    return 0;
}

int
soaccept(struct socket *socket, struct sockaddr *address)
{
    if (!socket || !socket->so_proto || !socket->so_proto->pr_accept)
        return EOPNOTSUPP;
    return socket->so_proto->pr_accept(socket, address);
}

int
sosetopt(struct socket *socket, struct sockopt *option)
{
    if (!socket || !option)
        return EINVAL;
    if (option->sopt_level == SOL_SOCKET)
        return EOPNOTSUPP;
    if (!socket->so_proto || !socket->so_proto->pr_ctloutput)
        return EOPNOTSUPP;
    return socket->so_proto->pr_ctloutput(socket, option);
}

int
soreceive(struct socket *socket, struct sockaddr **address, struct uio *uio,
    struct mbuf **data, struct mbuf **control, int *flags)
{
    struct mbuf *record;
    struct mbuf *next_record;
    unsigned int length;

    if (!socket)
        return EINVAL;
    if (socket->so_proto && socket->so_proto->pr_soreceive)
        return socket->so_proto->pr_soreceive(socket, address, uio, data,
            control, flags);
    record = socket->so_rcv.sb_mb;
    if (!record)
        return EWOULDBLOCK;
    next_record = record->m_nextpkt;
    length = m_length(record, NULL);
    socket->so_rcv.sb_mb = next_record;
    if (!next_record) {
        socket->so_rcv.sb_lastrecord = NULL;
        socket->so_rcv.sb_mbtail = NULL;
    }
    socket->so_rcv.sb_ccc = length > socket->so_rcv.sb_ccc ? 0 :
        socket->so_rcv.sb_ccc - length;
    socket->so_rcv.sb_acc = length > socket->so_rcv.sb_acc ? 0 :
        socket->so_rcv.sb_acc - length;
    socket->so_rcv.sb_mbcnt = length > socket->so_rcv.sb_mbcnt ? 0 :
        socket->so_rcv.sb_mbcnt - length;
    if (uio && uio->uio_resid >= (intptr_t)length)
        uio->uio_resid -= (intptr_t)length;
    if (data)
        *data = record;
    else {
        record->m_nextpkt = NULL;
        m_freem(record);
    }
    if (address)
        *address = NULL;
    if (control)
        *control = NULL;
    return 0;
}

int
soreadable(struct socket *socket)
{
    return socket && (sbavail(&socket->so_rcv) >= socket->so_rcv.sb_lowat ||
        socket->so_error || socket->so_rerror ||
        (socket->so_rcv.sb_state & SBS_CANTRCVMORE) != 0);
}

int
sowriteable(struct socket *socket)
{
    return socket && ((sbspace(&socket->so_snd) >= socket->so_snd.sb_lowat &&
        ((socket->so_state & SS_ISCONNECTED) != 0 ||
        (socket->so_proto->pr_flags & PR_CONNREQUIRED) == 0)) ||
        (socket->so_snd.sb_state & SBS_CANTSENDMORE) != 0 ||
        socket->so_error != 0);
}

void
soupcall_set(struct socket *socket, sb_which which, so_upcall_t upcall,
    void *argument)
{
    struct sockbuf *buffer;

    if (!socket)
        return;
    buffer = which == SO_RCV ? &socket->so_rcv : &socket->so_snd;
    buffer->sb_upcall = upcall;
    buffer->sb_upcallarg = argument;
}

void
soupcall_clear(struct socket *socket, sb_which which)
{
    soupcall_set(socket, which, NULL, NULL);
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
sorwakeup(struct socket *socket)
{
    if (socket) {
        wakeup(&socket->so_rcv);
        if (socket->so_rcv.sb_upcall)
            socket->so_rcv.sb_upcall(socket,
                socket->so_rcv.sb_upcallarg, M_NOWAIT);
    }
}

void
soroverflow(struct socket *socket)
{
    if (socket)
        wakeup(&socket->so_rcv);
}

void
soroverflow_locked(struct socket *socket)
{
    if (!socket)
        return;
    wakeup(&socket->so_rcv);
    SOCK_RECVBUF_UNLOCK(socket);
}

void
sowwakeup(struct socket *socket)
{
    if (socket) {
        wakeup(&socket->so_snd);
        if (socket->so_snd.sb_upcall)
            socket->so_snd.sb_upcall(socket,
                socket->so_snd.sb_upcallarg, M_NOWAIT);
    }
}

void
sowwakeup_locked(struct socket *socket)
{
    if (!socket)
        return;
    wakeup(&socket->so_snd);
    SOCK_SENDBUF_UNLOCK(socket);
}
