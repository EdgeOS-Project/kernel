/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS VirtIO input driver interface.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This is original EdgeOS glue for Linux-compatible input delivery from real
 * VirtIO input devices.  Do not expose fake devices: /dev/input/event* data
 * must come from actual hardware or a realistic virtual device event queue.
 */

#ifndef EDGEOS_DRIVERS_VIRTIO_INPUT_H
#define EDGEOS_DRIVERS_VIRTIO_INPUT_H

#include <stdint.h>
#include "kernel/input_device.h"

int virtio_input_init(void);
int virtio_input_is_ready(void);
int virtio_input_pending(void);
void virtio_input_poll(void);

#endif
