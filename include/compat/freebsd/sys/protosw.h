/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD protocol switch descriptors for bridge-native transports. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_PROTOSW_H
#define EDGEOS_COMPAT_FREEBSD_SYS_PROTOSW_H

#include <sys/socket.h>

struct domain;
struct mbuf;
struct sockaddr;
struct socket;
struct thread;
struct uio;

typedef int pr_attach_t(struct socket *, int, struct thread *);
typedef void pr_detach_t(struct socket *);
typedef void pr_abort_t(struct socket *);
typedef int pr_bind_t(struct socket *, struct sockaddr *, struct thread *);
typedef int pr_listen_t(struct socket *, int, struct thread *);
typedef int pr_accept_t(struct socket *, struct sockaddr *);
typedef int pr_connect_t(struct socket *, struct sockaddr *, struct thread *);
typedef int pr_disconnect_t(struct socket *);
typedef void pr_close_t(struct socket *);
typedef int pr_peeraddr_t(struct socket *, struct sockaddr *);
typedef int pr_sockaddr_t(struct socket *, struct sockaddr *);
typedef int pr_shutdown_t(struct socket *, enum shutdown_how);
typedef int pr_soreceive_t(struct socket *, struct sockaddr **, struct uio *,
    struct mbuf **, struct mbuf **, int *);
typedef int pr_sosend_t(struct socket *, struct sockaddr *, struct uio *,
    struct mbuf *, struct mbuf *, int, struct thread *);

struct protosw {
    short pr_type;
    short pr_protocol;
    short pr_flags;
    short pr_unused;
    struct domain *pr_domain;
    pr_soreceive_t *pr_soreceive;
    pr_sosend_t *pr_sosend;
    pr_attach_t *pr_attach;
    pr_detach_t *pr_detach;
    pr_connect_t *pr_connect;
    pr_disconnect_t *pr_disconnect;
    pr_close_t *pr_close;
    pr_bind_t *pr_bind;
    pr_listen_t *pr_listen;
    pr_accept_t *pr_accept;
    pr_abort_t *pr_abort;
    pr_peeraddr_t *pr_peeraddr;
    pr_sockaddr_t *pr_sockaddr;
    pr_shutdown_t *pr_shutdown;
};

#define PR_ATOMIC 0x01
#define PR_ADDR 0x02
#define PR_CONNREQUIRED 0x04
#define PR_WANTRCVD 0x08
#define PR_IMPLOPCL 0x20
#define PR_CAPATTACH 0x80
#define PR_SOCKBUF 0x100

struct domain *pffinddomain(int family);
struct protosw *pffindproto(int family, int type, int protocol);

#endif
