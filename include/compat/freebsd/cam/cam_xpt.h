/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CAM transport interface for imported SIM and peripheral drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_XPT_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_XPT_H

#include "cam_periph.h"

struct cam_sim *xpt_path_sim(struct cam_path *path);
void xpt_path_inq(struct ccb_pathinq *inquiry, struct cam_path *path);
void xpt_print(struct cam_path *path, const char *format, ...)
    __attribute__((format(__printf__, 2, 3)));
void xpt_print_path(struct cam_path *path);

#endif
