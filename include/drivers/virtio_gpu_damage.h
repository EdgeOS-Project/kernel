/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef DRIVERS_VIRTIO_GPU_DAMAGE_H
#define DRIVERS_VIRTIO_GPU_DAMAGE_H

#include <stdint.h>

#include "display.h"

#define VIRTIO_GPU_DAMAGE_MAX_RECTS 8u

typedef struct virtio_gpu_damage {
    display_rect_t rects[VIRTIO_GPU_DAMAGE_MAX_RECTS];
    uint32_t count;
    uint32_t merged;
    uint32_t compacted;
    uint8_t full_screen;
} virtio_gpu_damage_t;

void virtio_gpu_damage_reset(virtio_gpu_damage_t *damage);
void virtio_gpu_damage_add(virtio_gpu_damage_t *damage,
                           const display_rect_t *rects, uint32_t count,
                           uint32_t screen_width, uint32_t screen_height);
uint64_t virtio_gpu_damage_area(const virtio_gpu_damage_t *damage);

#endif
