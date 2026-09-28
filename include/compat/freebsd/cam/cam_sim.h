/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CAM SIM interface for imported FreeBSD storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_SIM_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_SIM_H

#include <stdint.h>

#include "cam_ccb.h"
#include "../sys/mutex.h"

struct _device;
typedef struct _device *device_t;

struct cam_devq {
    uint32_t openings;
};

typedef void (*sim_action_func)(struct cam_sim *, union ccb *);
typedef void (*sim_poll_func)(struct cam_sim *);

struct cam_sim {
    sim_action_func sim_action;
    sim_poll_func sim_poll;
    const char *sim_name;
    void *softc;
    struct mtx *mtx;
    path_id_t path_id;
    uint32_t unit_number;
    uint32_t bus_id;
    int max_tagged_dev_openings;
    int max_dev_openings;
    struct cam_devq *devq;
    int refcount;
    uint32_t frozen;
    uint8_t registered;
    uint8_t scan_pending;
    uint8_t transport_ready;
    uint32_t async_events;
    void (*async_callback)(void *, uint32_t, struct cam_path *, void *);
    void *async_callback_arg;
    device_t parent;
    struct cam_sim *bridge_next;
};

#define spriv_ptr0 sim_priv.entries[0].ptr
#define spriv_ptr1 sim_priv.entries[1].ptr
#define spriv_field0 sim_priv.entries[0].field
#define spriv_field1 sim_priv.entries[1].field

struct cam_devq *cam_simq_alloc(uint32_t max_sim_transactions);
void cam_simq_free(struct cam_devq *devq);
struct cam_sim *cam_sim_alloc(sim_action_func action, sim_poll_func poll,
    const char *name, void *softc, uint32_t unit, struct mtx *mutex,
    int max_dev_transactions, int max_tagged_dev_transactions,
    struct cam_devq *queue);
void cam_sim_free(struct cam_sim *sim, int free_devq);
void cam_sim_hold(struct cam_sim *sim);
void cam_sim_release(struct cam_sim *sim);

static inline path_id_t
cam_sim_path(const struct cam_sim *sim)
{
    return sim->path_id;
}

static inline const char *
cam_sim_name(const struct cam_sim *sim)
{
    return sim->sim_name;
}

static inline void *
cam_sim_softc(const struct cam_sim *sim)
{
    return sim->softc;
}

static inline uint32_t
cam_sim_unit(const struct cam_sim *sim)
{
    return sim->unit_number;
}

static inline uint32_t
cam_sim_bus(const struct cam_sim *sim)
{
    return sim->bus_id;
}

#endif
