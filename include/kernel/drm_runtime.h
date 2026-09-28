/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Linux DRM/KMS runtime for EdgeOS. */

#ifndef EDGEOS_KERNEL_DRM_RUNTIME_H
#define EDGEOS_KERNEL_DRM_RUNTIME_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"
#include "kernel/timerfd_runtime.h"

#define EDGE_DRM_CARD_PATH "/dev/dri/card0"

#define EDGE_DRM_CAP_DUMB_BUFFER             0x01u
#define EDGE_DRM_CAP_VBLANK_HIGH_CRTC        0x02u
#define EDGE_DRM_CAP_DUMB_PREFERRED_DEPTH    0x03u
#define EDGE_DRM_CAP_DUMB_PREFER_SHADOW      0x04u
#define EDGE_DRM_CAP_PRIME                   0x05u
#define EDGE_DRM_CAP_TIMESTAMP_MONOTONIC     0x06u
#define EDGE_DRM_CAP_ASYNC_PAGE_FLIP         0x07u
#define EDGE_DRM_CAP_CURSOR_WIDTH            0x08u
#define EDGE_DRM_CAP_CURSOR_HEIGHT           0x09u
#define EDGE_DRM_CAP_ADDFB2_MODIFIERS        0x10u
#define EDGE_DRM_CAP_PAGE_FLIP_TARGET        0x11u
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

/* Bounded diagnostic history. IDs prevent a wrapped slot from being reused. */
#define EDGE_DRM_FLIP_TRACE_COUNT 256u
typedef struct edge_drm_flip_trace {
    uint64_t id;
    uint64_t client_identity;
    uint64_t user_data;
    uint64_t commit_us;
    uint64_t present_begin_us;
    uint64_t present_end_us;
    uint64_t event_due_us;
    uint64_t event_enqueue_us;
    uint64_t event_read_us;
    int64_t result;
} edge_drm_flip_trace_t;

/* ID zero returns the latest record. No userspace ABI is added. */
int edge_drm_get_flip_trace(uint64_t id, edge_drm_flip_trace_t *trace);

/* Optional, task-filtered timing probe. Disabled until explicitly started by
 * a kernel diagnostic controller; this does not add a userspace DRM ioctl.
 * Times use boottime_monotonic_us(), matching the existing flip trace.
 * VBLANK_TARGET records accepted requests and their prepared timestamps,
 * before any future wait sleeps. It is not a syscall-return/wakeup record. */
#define EDGE_DRM_TIMING_PROBE_COUNT 1024u
#define EDGE_DRM_TIMING_COMMIT 1u
#define EDGE_DRM_TIMING_VBLANK_TARGET 2u
#define EDGE_DRM_TIMING_TIMER_SOURCE 6u
#define EDGE_DRM_TIMING_POLL_BEGIN 7u
#define EDGE_DRM_TIMING_WAIT_BLOCK 8u
#define EDGE_DRM_TIMING_DEADLINE_WAKE 9u
#define EDGE_DRM_TIMING_WAKE_RESULT 10u
#define EDGE_DRM_TIMING_WAIT_RESUMED 11u
#define EDGE_DRM_TIMING_POLL_READY 12u
#define EDGE_DRM_TIMING_POLL_RETURN 13u
typedef struct edge_drm_timing_record {
    uint64_t id;
    uint64_t at_us;
    uint64_t client_identity;
    uint64_t flip_id;
    uint64_t user_data;
    uint64_t query_us;
    uint64_t reply_us;
    int32_t tid;
    uint32_t kind;
    uint32_t request_type;
    uint32_t requested_sequence;
    uint32_t reply_sequence;
    uint32_t reserved;
} edge_drm_timing_record_t;

/* Reject invalid filters, windows above 45 seconds, and budgets above 8192.
 * Start clears retained slots but IDs remain unique across start/stop cycles.
 * Group activation permits up to 65536 events. The opt-in boot controller
 * is x86-only; ordinary boots leave both observers uninstalled. */
int edge_drm_timing_probe_start(int32_t tid, uint32_t duration_ms,
                                uint32_t event_limit);
void edge_drm_timing_probe_stop(void);
int edge_drm_timing_probe_read(uint64_t id, edge_drm_timing_record_t *record);

/* Group mode is configured only by the opt-in x86 adapter. It registers live
 * GNOME thread-group members rather than guessing a PID before boot.
 * The same ring records timer generation/arm_id in client_identity/flip_id,
 * timer_id in user_data, requested deadline in query_us, and event value in
 * reply_us. Timer source/ready records carry wait_id in requested_sequence.
 * Wait-only records carry wait_id in user_data. No timestamp is a substitute
 * for a scheduler entry or userspace callback timestamp. */
#define EDGE_DRM_TIMING_THREAD_COUNT 128u
typedef struct edge_drm_timing_thread {
    int32_t tid;
    int32_t tgid;
    char name[16];
    uint32_t wait_id;
    uint32_t in_poll;
} edge_drm_timing_thread_t;
int edge_drm_timing_probe_start_group(uint64_t start_us, uint32_t duration_ms,
                                      uint32_t event_limit);
int edge_drm_timing_probe_enabled(void);
void edge_drm_timing_probe_register_thread(int32_t tid, int32_t tgid,
                                           const char *name);
void edge_drm_timing_probe_poll_begin(int32_t tid, int64_t timeout_us,
                                      uint32_t syscall_number);
void edge_drm_timing_probe_wait_event(uint32_t kind, int32_t tid,
                                      uint64_t value, int64_t result);
void edge_drm_timing_probe_timer_observe(uint32_t kind, int timer_id,
    const kernel_timerfd_probe_state_t *state, int64_t value);
void edge_drm_timing_probe_timer_source(int32_t tid, int timer_id,
    const kernel_timerfd_probe_state_t *state, uint64_t planned_deadline_us);
void edge_drm_timing_probe_poll_ready(int32_t tid, int timer_id, int fd,
    const kernel_timerfd_probe_state_t *state, uint32_t revents);
uint64_t edge_drm_timing_probe_dropped(void);

/* Identity-keyed subscriptions used by both architecture wait planners. */
#define EDGE_DRM_WAITERS_PER_CLIENT 32u
int edge_drm_waiter_register(uint64_t identity, int32_t waiter_pid);
void edge_drm_waiter_remove(int32_t waiter_pid);
int edge_drm_waiter_registered(uint64_t identity, int32_t waiter_pid);
/* Backend wake hook. Called only after queue publication and DRM unlock. */
void kernel_drm_waiter_ready(int32_t waiter_pid, uint64_t identity);
/* Called once after a non-empty waiter notification batch. */
void kernel_drm_waiter_wake_batch_complete(uint64_t identity);
/* Final description release cancels interest; it never queues a DRM event. */
void kernel_drm_waiter_cancelled(int32_t waiter_pid, uint64_t identity);

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
