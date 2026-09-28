/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * VirtIO RNG driver interface.
 */

#ifndef DRIVERS_VIRTIO_RNG_H
#define DRIVERS_VIRTIO_RNG_H

#include <stdint.h>

int virtio_rng_init(void);
int virtio_rng_is_ready(void);
int virtio_rng_fill(void *buf, uint32_t len);

#endif
