/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CAM path and request helpers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_PERIPH_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_PERIPH_H

#include <stddef.h>

#include "cam_sim.h"
#include "../sys/kernel.h"
#include "../sys/mutex.h"

struct sbuf;
struct devstat;

typedef enum cam_periph_type {
    CAM_PERIPH_BIO
} cam_periph_type;

typedef void periph_start_t(struct cam_periph *periph,
    union ccb *start_ccb);
typedef cam_status periph_ctor_t(struct cam_periph *periph, void *argument);
typedef void periph_oninv_t(struct cam_periph *periph);
typedef void periph_dtor_t(struct cam_periph *periph);
typedef void ac_callback_t(void *softc, uint32_t code,
    struct cam_path *path, void *argument);
typedef uint32_t ac_code;
typedef void periph_init_t(void);
typedef int periph_deinit_t(void);

struct periph_driver {
    periph_init_t *init;
    char *driver_name;
    TAILQ_HEAD(, cam_periph) units;
    unsigned int generation;
    unsigned int flags;
    periph_deinit_t *deinit;
};

#define CAM_PERIPH_DRV_EARLY 0x01u

#define PERIPHDRIVER_DECLARE(name, driver)                              \
    static void name##_periph_init(void *argument)                      \
    {                                                                   \
        struct periph_driver *periph_driver = argument;                 \
        if (periph_driver && periph_driver->init)                       \
            periph_driver->init();                                     \
    }                                                                   \
    SYSINIT(name##_periph, SI_SUB_DRIVERS, SI_ORDER_ANY,                \
        name##_periph_init, &(driver))

#define CAM_PERIPH_RUNNING 0x01u
#define CAM_PERIPH_LOCKED 0x02u
#define CAM_PERIPH_LOCK_WANTED 0x04u
#define CAM_PERIPH_INVALID 0x08u

/*
 * Preserve the public prefix of FreeBSD's CAM peripheral object.  EdgeOS
 * publishes one object for every CAM disk, allowing unmodified controller
 * drivers to resolve the Linux-visible da/ada instance associated with a
 * path.  Queueing internals remain private to the shared CAM gateway.
 */
struct cam_periph {
    periph_start_t *periph_start;
    periph_oninv_t *periph_oninval;
    periph_dtor_t *periph_dtor;
    char *periph_name;
    struct cam_path *path;
    void *softc;
    struct cam_sim *sim;
    uint32_t unit_number;
    cam_periph_type type;
    uint32_t flags;
    uint32_t scheduled_priority;
    uint32_t immediate_priority;
    int periph_allocating;
    int periph_allocated;
    uint32_t refcount;
    TAILQ_ENTRY(cam_periph) unit_links;
    struct cam_periph *bridge_next;
};

extern struct cam_periph *xpt_periph;

cam_status xpt_create_path(struct cam_path **path, void *periph,
    path_id_t path_id, target_id_t target_id, lun_id_t lun_id);
void xpt_free_path(struct cam_path *path);
void xpt_setup_ccb(struct ccb_hdr *header, struct cam_path *path,
    uint32_t priority);
void xpt_action(union ccb *ccb);
void xpt_async(uint32_t code, struct cam_path *path, void *argument);
union ccb *xpt_alloc_ccb_nowait(void);
union ccb *xpt_alloc_ccb(void);
void xpt_free_ccb(union ccb *ccb);
void xpt_rescan(union ccb *ccb);
void xpt_hold_boot(void);
void xpt_release_boot(void);
cam_status xpt_register_async(int event,
    void (*callback)(void *, uint32_t, struct cam_path *, void *),
    void *callback_argument, struct cam_path *path);
lun_id_t xpt_path_lun_id(const struct cam_path *path);
path_id_t xpt_path_path_id(const struct cam_path *path);
target_id_t xpt_path_target_id(const struct cam_path *path);
void xpt_path_sbuf(struct cam_path *path, struct sbuf *buffer);
char *xpt_path_string(struct cam_path *path, char *buffer,
    size_t buffer_length);
void xpt_sim_poll(struct cam_sim *sim);
void cam_calc_geometry(struct ccb_calc_geometry *geometry, int extended);
void cam_freeze_devq(struct cam_path *path);
uint32_t cam_release_devq(struct cam_path *path, uint32_t release_flags,
    uint32_t opening_reduction, uint32_t timeout, int getcount_only);
struct cam_periph *cam_periph_find(struct cam_path *path, char *name);
cam_status cam_periph_alloc(periph_ctor_t *constructor,
    periph_oninv_t *invalidate, periph_dtor_t *destructor,
    periph_start_t *start, char *name, cam_periph_type type,
    struct cam_path *path, ac_callback_t *callback, ac_code code,
    void *argument);
int cam_periph_acquire(struct cam_periph *periph);
void cam_periph_release(struct cam_periph *periph);
int cam_periph_hold(struct cam_periph *periph, int priority);
void cam_periph_unhold(struct cam_periph *periph);
union ccb *cam_periph_getccb(struct cam_periph *periph,
    uint32_t priority);
int cam_periph_runccb(union ccb *ccb,
    int (*error_routine)(union ccb *, cam_flags, uint32_t),
    cam_flags camflags, uint32_t sense_flags, struct devstat *stats);
int cam_periph_error(union ccb *ccb, cam_flags camflags,
    uint32_t sense_flags);
void xpt_schedule(struct cam_periph *periph, uint32_t priority);
void xpt_announce_periph(struct cam_periph *periph,
    const char *additional_text);
device_t xpt_path_sim_device(const struct cam_path *path);
void cam_periph_async(struct cam_periph *periph, uint32_t code,
    struct cam_path *path, void *argument);
struct mtx *xpt_path_mtx(struct cam_path *path);

#define cam_periph_owned(periph) \
    mtx_owned(xpt_path_mtx((periph)->path))
#define cam_periph_lock(periph) \
    mtx_lock(xpt_path_mtx((periph)->path))
#define cam_periph_unlock(periph) \
    mtx_unlock(xpt_path_mtx((periph)->path))
#define cam_periph_assert(periph, what) \
    mtx_assert(xpt_path_mtx((periph)->path), (what))

#define xpt_path_lock(path) mtx_lock(xpt_path_mtx(path))
#define xpt_path_unlock(path) mtx_unlock(xpt_path_mtx(path))
#define xpt_path_assert(path, what) mtx_assert(xpt_path_mtx(path), (what))
#define xpt_path_owned(path) mtx_owned(xpt_path_mtx(path))

#endif
