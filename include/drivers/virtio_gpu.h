/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef DRIVERS_VIRTIO_GPU_H
#define DRIVERS_VIRTIO_GPU_H

#include <stdint.h>

#include "display.h"

struct edgeos_arm64_bootinfo;

typedef struct virtio_gpu_present_stats {
    uint64_t submitted_frames;
    uint64_t completed_frames;
    uint64_t coalesced_frames;
    uint64_t replaced_frames;
    uint64_t full_screen_frames;
    uint64_t submitted_rects;
    uint64_t transferred_bytes;
    uint64_t completion_latency_total_us;
    uint64_t completion_latency_max_us;
    uint64_t completion_latency_over_16ms;
    uint64_t completion_latency_over_33ms;
    uint64_t completion_latency_over_100ms;
    uint64_t failed_frames;
    uint64_t timed_out_frames;
    uint32_t in_flight;
    uint32_t pending;
} virtio_gpu_present_stats_t;

int virtio_gpu_init(void);
int virtio_gpu_mmio_init(const struct edgeos_arm64_bootinfo *bootinfo);
int virtio_gpu_enable_interrupts(void);
int virtio_gpu_present(void);
int virtio_gpu_has_virgl(void);
int virtio_gpu_cursor_available(void);
int virtio_gpu_cursor_update(const uint8_t *pixels, uint32_t width,
                             uint32_t height, uint32_t pitch,
                             uint32_t source_x, uint32_t source_y,
                             uint32_t cursor_width, uint32_t cursor_height,
                             int32_t x, int32_t y,
                             uint32_t hotspot_x, uint32_t hotspot_y);
int virtio_gpu_cursor_hide(void);
int virtio_gpu_pci_device_name(char *out, uint32_t capacity);
void virtio_gpu_flush_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void virtio_gpu_flush_rects(const display_rect_t *rects, uint32_t count);
void virtio_gpu_poll_presents(void);
int virtio_gpu_presents_pending(void);
void virtio_gpu_get_present_stats(virtio_gpu_present_stats_t *stats);

#endif
