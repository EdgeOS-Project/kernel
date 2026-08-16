/* SPDX-License-Identifier: MPL-2.0 */
/* CAM debug compatibility with tracing disabled by default. */

#ifndef EDGEOS_COMPAT_FREEBSD_CAM_CAM_DEBUG_H
#define EDGEOS_COMPAT_FREEBSD_CAM_CAM_DEBUG_H

#define CAM_DEBUG(path, flags, arguments) do { (void)(path); } while (0)

#endif
