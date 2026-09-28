/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD GEOM provider contract backed by the EdgeOS block core. */

#ifndef _GEOM_GEOM_H_
#define _GEOM_GEOM_H_

#include <sys/linker_set.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/module.h>

#define G_VERSION_00 0x19950323u
#define G_VERSION_01 0x20041207u
#define G_VERSION G_VERSION_01

#define G_GEOM_WITHER 0x01u

#define G_PF_WITHER 0x02u
#define G_PF_ORPHAN 0x04u
#define G_PF_ACCEPT_UNMAPPED 0x08u
#define G_PF_DIRECT_SEND 0x10u
#define G_PF_DIRECT_RECEIVE 0x20u

struct bio;
struct g_class;
struct g_consumer;
struct g_geom;
struct g_provider;
struct gctl_req;
struct thread;

typedef void g_start_t(struct bio *bio);
typedef int g_access_t(struct g_provider *provider, int read_delta,
    int write_delta, int exclusive_delta);
typedef int g_ctl_destroy_geom_t(struct gctl_req *request,
    struct g_class *geom_class, struct g_geom *geom);
typedef int g_ioctl_t(struct g_provider *provider, unsigned long command,
    void *data, int flags, struct thread *thread);
typedef void g_provgone_t(struct g_provider *provider);
typedef void g_event_t(void *argument, int flag);

#define EV_CANCEL 1

struct g_class {
    const char *name;
    unsigned int version;
    unsigned int spare0;
    void *taste;
    void *ctlreq;
    void *init;
    void *fini;
    g_ctl_destroy_geom_t *destroy_geom;
    g_start_t *start;
    void *spoiled;
    void *attrchanged;
    void *dumpconf;
    g_access_t *access;
    void *orphan;
    g_ioctl_t *ioctl;
    g_provgone_t *providergone;
    void *resize;
    void *spare1;
    void *spare2;
    struct g_class *bridge_next;
    unsigned int bridge_registered;
};

struct g_geom {
    char *name;
    struct g_class *class;
    g_start_t *start;
    g_access_t *access;
    g_ioctl_t *ioctl;
    void *softc;
    unsigned int flags;
    struct g_provider *bridge_providers;
    struct g_geom *bridge_next;
};

struct g_provider {
    char *name;
    struct g_geom *geom;
    int acr;
    int acw;
    int ace;
    int error;
    off_t mediasize;
    unsigned int sectorsize;
    off_t stripesize;
    off_t stripeoffset;
    void *stat;
    unsigned int spare1;
    unsigned int spare2;
    unsigned int flags;
    void *private;
    unsigned int index;
    void *bridge_publication;
    struct g_provider *bridge_geom_next;
    struct g_provider *bridge_global_next;
};

struct bio *g_new_bio(void);
struct bio *g_alloc_bio(void);
void g_destroy_bio(struct bio *bio);
void g_reset_bio(struct bio *bio);
void g_io_deliver(struct bio *bio, int error);

struct g_geom *g_new_geom(struct g_class *geom_class, const char *name);
struct g_geom *g_new_geomf(struct g_class *geom_class,
    const char *format, ...);
struct g_provider *g_new_providerf(struct g_geom *geom,
    const char *format, ...);
struct g_provider *g_provider_by_name(const char *name);
void g_error_provider(struct g_provider *provider, int error);
void g_resize_provider(struct g_provider *provider, off_t size);
void g_wither_geom(struct g_geom *geom, int error);
void g_orphan_provider(struct g_provider *provider, int error);

int g_post_event(g_event_t *function, void *argument, int flags, ...);
int g_waitfor_event(g_event_t *function, void *argument, int flags, ...);
int g_handleattr_int(struct bio *bio, const char *attribute, int value);
void g_print_bio(const char *prefix, const struct bio *bio,
    const char *suffix_format, ...);
int g_modevent(module_t module, int event, void *data);

void g_topology_lock(void);
int g_topology_try_lock(void);
void g_topology_unlock(void);
int g_topology_locked(void);
void g_topology_assert(void);

#define DECLARE_GEOM_CLASS(geom_class, name) \
    DATA_SET(geom_class_set, geom_class)

#endif
