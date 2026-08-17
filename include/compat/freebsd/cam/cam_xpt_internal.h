/* SPDX-License-Identifier: MPL-2.0 */
/* Public CAM path prefix required by unmodified transport consumers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_XPT_INTERNAL_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_XPT_INTERNAL_H

#include "cam.h"
#include "cam_sim.h"
#include <cam/mmc/mmc.h>
#include "../sys/mutex.h"
#include "../sys/taskqueue.h"

struct cam_ed {
    cam_proto protocol;
    struct mmc_params mmc_ident_data;
};

struct cam_path {
    struct cam_sim *sim;
    path_id_t path_id;
    target_id_t target_id;
    lun_id_t lun_id;
    uint32_t frozen;
    struct mtx fallback_mtx;
    struct cam_ed *device;
    struct cam_ed device_storage;
};

#endif
