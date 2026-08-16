/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CAM lifecycle for imported BSD storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_EDGEOS_CAM_H
#define EDGEOS_COMPAT_FREEBSD_EDGEOS_CAM_H

#include <stddef.h>

int bsd_cam_scan_pending(void);
size_t bsd_cam_sim_count(void);
size_t bsd_cam_disk_count(void);

#endif
