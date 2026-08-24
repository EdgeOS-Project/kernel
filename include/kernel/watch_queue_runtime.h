/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent Linux watch queue UAPI. */

#ifndef EDGEOS_KERNEL_WATCH_QUEUE_RUNTIME_H
#define EDGEOS_KERNEL_WATCH_QUEUE_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"

#define KERNEL_WATCH_QUEUE_SET_SIZE   0x00005760u
#define KERNEL_WATCH_QUEUE_SET_FILTER 0x00005761u

int64_t kernel_watch_queue_ioctl(const kernel_ioctl_request_t *request);

#endif
