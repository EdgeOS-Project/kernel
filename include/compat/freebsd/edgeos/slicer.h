/* SPDX-License-Identifier: MPL-2.0 */
/* Shared flash-slicer registry used by BSD storage drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_SLICER_H
#define EDGEOS_COMPAT_FREEBSD_SLICER_H

#include "compat/freebsd/sys/slicer.h"

flash_slicer_t bsd_flash_slicer_lookup(unsigned int type);

#endif
