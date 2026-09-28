/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Linux fbdev ioctl policy for EdgeOS. */

#ifndef EDGEOS_KERNEL_FBDEV_RUNTIME_H
#define EDGEOS_KERNEL_FBDEV_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"

int64_t kernel_fbdev_ioctl(const kernel_ioctl_request_t *request);

#endif
