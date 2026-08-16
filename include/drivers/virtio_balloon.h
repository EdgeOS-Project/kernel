/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * VirtIO balloon driver interface.
 */

#ifndef DRIVERS_VIRTIO_BALLOON_H
#define DRIVERS_VIRTIO_BALLOON_H

#include <stdint.h>

int virtio_balloon_init(void);
int virtio_balloon_is_ready(void);
uint32_t virtio_balloon_target_pages(void);
uint32_t virtio_balloon_actual_pages(void);

#endif
