/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD interface-cloner API backed by the shared EdgeOS registry. */

#ifndef _NET_IF_CLONE_H_
#define _NET_IF_CLONE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "if.h"

#define CLONE_COMPAT_13

#define IFC_F_SPARE 0x01
#define IFC_F_AUTOUNIT 0x02
#define IFC_F_SYSSPACE 0x04
#define IFC_F_FORCE 0x08
#define IFC_F_CREATE 0x10
#define IFC_F_LIMITUNIT 0x20

struct if_clone;
struct ifnet;
struct if_clonereq;
struct vnet;

struct ifc_data {
    uint32_t flags;
    uint32_t unit;
    void *params;
    struct vnet *vnet;
};

typedef int ifc_match_f(struct if_clone *, const char *);
typedef int ifc_create_f(struct if_clone *, char *, size_t,
    struct ifc_data *, struct ifnet **);
typedef int ifc_destroy_f(struct if_clone *, struct ifnet *, uint32_t);

struct if_clone_addreq {
    uint16_t version;
    uint16_t spare;
    uint32_t flags;
    uint32_t maxunit;
    ifc_match_f *match_f;
    ifc_create_f *create_f;
    ifc_destroy_f *destroy_f;
};

struct if_clone *ifc_attach_cloner(
    const char *name, struct if_clone_addreq *request);
void ifc_detach_cloner(struct if_clone *cloner);
int ifc_create_ifp(const char *name, struct ifc_data *data,
    struct ifnet **interface);
void ifc_link_ifp(struct if_clone *cloner, struct ifnet *interface);
bool ifc_unlink_ifp(struct if_clone *cloner, struct ifnet *interface);
int ifc_copyin(const struct ifc_data *data, void *target, size_t length);
int ifc_name2unit(const char *name, int *unit);
int ifc_alloc_unit(struct if_clone *cloner, int *unit);
void ifc_free_unit(struct if_clone *cloner, int unit);
void if_clone_addif(struct if_clone *cloner, struct ifnet *interface);
int if_clone_destroyif(struct if_clone *cloner, struct ifnet *interface);

#endif
