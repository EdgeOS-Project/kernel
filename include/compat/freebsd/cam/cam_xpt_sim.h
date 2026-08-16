/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CAM transport entry points used by FreeBSD SIM drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_XPT_SIM_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_XPT_SIM_H

#include "cam_xpt.h"

struct _device;
typedef struct _device *device_t;

int xpt_bus_register(struct cam_sim *sim, device_t parent, uint32_t bus);
int xpt_bus_deregister(path_id_t path_id);
uint32_t xpt_freeze_simq(struct cam_sim *sim, unsigned int count);
void xpt_release_simq(struct cam_sim *sim, int run_queue);
uint32_t xpt_freeze_devq(struct cam_path *path, unsigned int count);
void xpt_release_devq(struct cam_path *path, unsigned int count,
    int run_queue);
void xpt_done(union ccb *ccb);
void xpt_done_direct(union ccb *ccb);

#endif
