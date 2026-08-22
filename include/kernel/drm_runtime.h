/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Linux DRM/KMS runtime for EdgeOS. */

#ifndef EDGEOS_KERNEL_DRM_RUNTIME_H
#define EDGEOS_KERNEL_DRM_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"

#define EDGE_DRM_CARD_PATH "/dev/dri/card0"

#define EDGE_DRM_CAP_DUMB_BUFFER             0x01u
#define EDGE_DRM_CAP_DUMB_PREFERRED_DEPTH    0x03u
#define EDGE_DRM_CAP_DUMB_PREFER_SHADOW      0x04u
#define EDGE_DRM_CAP_PRIME                   0x05u
#define EDGE_DRM_CAP_TIMESTAMP_MONOTONIC     0x06u
#define EDGE_DRM_CAP_CURSOR_WIDTH            0x08u
#define EDGE_DRM_CAP_CURSOR_HEIGHT           0x09u
#define EDGE_DRM_CAP_ADDFB2_MODIFIERS        0x10u
#define EDGE_DRM_CAP_CRTC_IN_VBLANK_EVENT    0x12u
#define EDGE_DRM_CAP_SYNCOBJ                 0x13u
#define EDGE_DRM_CAP_SYNCOBJ_TIMELINE        0x14u

#define EDGE_DRM_PRIME_CAP_IMPORT            0x01u
#define EDGE_DRM_PRIME_CAP_EXPORT            0x02u

typedef struct edge_drm_runtime_stats {
    uint64_t atomic_commits;
    uint64_t atomic_cursor_only_commits;
    uint64_t atomic_primary_commits;
    uint64_t primary_present_calls;
    uint64_t damage_present_calls;
    uint64_t present_duration_total_us;
    uint64_t present_duration_max_us;
    uint64_t present_duration_over_16ms;
    uint64_t flip_events_requested;
    uint64_t flip_events_delivered;
    uint64_t flip_events_busy;
    uint64_t flip_lateness_total_us;
    uint64_t flip_lateness_max_us;
    uint64_t flip_lateness_over_16ms;
} edge_drm_runtime_stats_t;

int edge_drm_path_is_card(const char *path);
int edge_drm_path_is_render(const char *path);
int edge_drm_path_is_device(const char *path);
int64_t edge_drm_ioctl(uint64_t client_identity,
                       const kernel_ioctl_request_t *request);
int64_t edge_drm_ioctl_path(uint64_t client_identity, const char *path,
                            const kernel_ioctl_request_t *request);
int64_t edge_drm_read(uint64_t client_identity, void *buffer,
                      uint64_t length);
int edge_drm_poll_readable(uint64_t client_identity);
uint64_t edge_drm_readiness_sequence(uint64_t client_identity);
void edge_drm_release_client(uint64_t client_identity);
void edge_drm_pump_deferred(void);
void edge_drm_scanout_activity(void);
int edge_drm_scanout_refresh_required(void);
void edge_drm_get_runtime_stats(edge_drm_runtime_stats_t *stats);

int edge_drm_mmap_prepare(uint64_t client_identity, uint64_t offset,
                          uint64_t length, uint32_t *page_count);
int edge_drm_mmap_page(uint64_t client_identity, uint64_t offset,
                       uint32_t page_index, void **kernel_address);
int edge_drm_mmap_write_tracking_required(uint64_t client_identity,
                                          uint64_t offset);
int edge_drm_mmap_enable_write_tracking(uint64_t client_identity,
                                        uint64_t offset);
int edge_drm_note_mmap_dirty_physical(uint64_t physical_address,
                                      uint64_t length);
int edge_drm_prime_retain(int32_t object_id);
void edge_drm_prime_release(int32_t object_id);

#endif
