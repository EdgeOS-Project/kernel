/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_DEBUGNET_H_
#define _NET_DEBUGNET_H_

struct ifnet;
struct mbuf;

struct debugnet_methods {
    int (*dn_init)(struct ifnet *, int *);
    void (*dn_event)(struct ifnet *, int);
    int (*dn_transmit)(struct ifnet *, struct mbuf *);
    int (*dn_poll)(struct ifnet *, int);
};

#define DEBUGNET_DEFINE(driver)
#define DEBUGNET_SET(ifp, driver) do { (void)(ifp); } while (0)

#endif
