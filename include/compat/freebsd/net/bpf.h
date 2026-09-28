/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD packet-tap API backed by the shared EdgeOS listener registry. */

#ifndef _NET_BPF_H_
#define _NET_BPF_H_

#include <stdbool.h>
#include <stdint.h>

#define DLT_RAW 12
#define DLT_USB 186

struct bpf_if;
struct bpf_listener;
struct ifnet;
struct mbuf;

enum bpf_direction {
    BPF_D_IN,
    BPF_D_INOUT,
    BPF_D_OUT,
};

typedef void bif_attachd_t(void *);
typedef void bif_detachd_t(void *);
typedef bool bif_chkdir_t(void *, const struct mbuf *, int);
typedef int bif_write_t(void *, struct mbuf *, struct mbuf *, int);
typedef uint32_t bif_wrsize_t(void *);
typedef int bif_promisc_t(void *, bool);

struct bif_methods {
    bif_attachd_t *bif_attachd;
    bif_detachd_t *bif_detachd;
    bif_chkdir_t *bif_chkdir;
    bif_promisc_t *bif_promisc;
    bif_write_t *bif_write;
    bif_wrsize_t *bif_wrsize;
    void *bif_mac_check_receive;
};

typedef void (*bsd_bpf_listener_fn)(void *context, const void *prefix,
    uint32_t prefix_length, const struct mbuf *mbuf, int direction);

struct bpf_if *bpf_attach(const char *name, unsigned int dlt,
    unsigned int header_length, const struct bif_methods *methods,
    void *softc);
void bpf_detach(struct bpf_if *interface);
void bpfattach(struct ifnet *interface, unsigned int dlt,
    unsigned int header_length);
void bpfdetach(struct ifnet *interface);
void bpf_mtap(struct bpf_if *interface, struct mbuf *mbuf);
void bpf_mtap_if(struct ifnet *interface, struct mbuf *mbuf);
void bpf_mtap2(struct bpf_if *interface, void *prefix,
    unsigned int prefix_length, struct mbuf *mbuf);
void bpf_mtap2_if(struct ifnet *interface, void *prefix,
    unsigned int prefix_length, struct mbuf *mbuf);
void bpf_tap(struct bpf_if *interface, const void *data,
    unsigned int length);
bool bpf_peers_present(const struct bpf_if *interface);
bool bpf_peers_present_if(struct ifnet *interface);
struct bpf_listener *bsd_bpf_listener_attach(struct bpf_if *interface,
    bsd_bpf_listener_fn callback, void *context);
void bsd_bpf_listener_detach(struct bpf_listener *listener);

uint32_t bpf_ifnet_wrsize(void *softc);
int bpf_ifnet_promisc(void *softc, bool enabled);

#define BPF_MTAP(interface, mbuf) bpf_mtap_if((interface), (mbuf))
#define BPF_MTAP2(interface, data, length, mbuf) \
    bpf_mtap2_if((interface), (data), (length), (mbuf))

#endif
