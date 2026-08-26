/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_EVENT_RUNTIME_H
#define EDGEOS_KERNEL_EVENT_RUNTIME_H

#include <stdint.h>
#include "kernel/runtime_limits.h"

#define KERNEL_EVENTFD_SEMAPHORE 0x00000001u
#define KERNEL_EVENTFD_NONBLOCK  0x00000800u
#define KERNEL_EVENTFD_CLOEXEC   0x00080000u

#define KERNEL_EPOLL_CLOEXEC 0x00080000u

#define KERNEL_EPOLL_CTL_ADD 1u
#define KERNEL_EPOLL_CTL_DEL 2u
#define KERNEL_EPOLL_CTL_MOD 3u

#define KERNEL_EPOLLIN        0x00000001u
#define KERNEL_EPOLLPRI       0x00000002u
#define KERNEL_EPOLLOUT       0x00000004u
#define KERNEL_EPOLLERR       0x00000008u
#define KERNEL_EPOLLHUP       0x00000010u
#define KERNEL_EPOLLRDNORM    0x00000040u
#define KERNEL_EPOLLRDBAND    0x00000080u
#define KERNEL_EPOLLWRNORM    0x00000100u
#define KERNEL_EPOLLWRBAND    0x00000200u
#define KERNEL_EPOLLRDHUP     0x00002000u
#define KERNEL_EPOLLEXCLUSIVE 0x10000000u
#define KERNEL_EPOLLWAKEUP    0x20000000u
#define KERNEL_EPOLLONESHOT   0x40000000u
#define KERNEL_EPOLLET        0x80000000u

#define KERNEL_EPOLL_NESTING_MAX 5u

#define KERNEL_WAIT_TIMEOUT_NONE     0u
#define KERNEL_WAIT_TIMEOUT_TIMESPEC 1u
#define KERNEL_WAIT_TIMEOUT_TIMEVAL  2u
#define KERNEL_WAIT_TIMEOUT_TIMESPEC32 3u
#define KERNEL_WAIT_TIMEOUT_TIMEVAL32  4u

#define KERNEL_WAIT_DESCRIPTOR_MAX 1024

typedef struct kernel_epoll_event {
    uint32_t events;
    uint64_t data;
} kernel_epoll_event_t;

typedef int (*kernel_epoll_event_copy_fn)(
    void *context, uint32_t event_index,
    const kernel_epoll_event_t *event);

/*
 * Architecture backends capture a stable, non-pointer description of the
 * object that supplies readiness. Object identifiers and the cookie are
 * backend-defined, but must remain valid until release_target_source(). The
 * source is intentionally independent of descriptor-table slots so close(2)
 * and descriptor reuse cannot silently retarget an installed watch.
 */
typedef struct kernel_epoll_target_source {
    uint32_t kind;
    uint32_t flags;
    int32_t primary_object_id;
    int32_t secondary_object_id;
    uint64_t cookie;
} kernel_epoll_target_source_t;

/*
 * Linux keys an epoll item by both the descriptor number supplied to
 * epoll_ctl() and the open file description behind that descriptor. Keeping
 * the key in common code makes dup(2), close(2), and descriptor reuse behave
 * identically on every architecture.
 */
typedef struct kernel_epoll_watch {
    uint8_t used;
    uint8_t oneshot_disabled;
    int16_t target_epoll_index;
    uint32_t slot_generation;
    int32_t fd;
    uint32_t events;
    uint32_t observed_ready;
    uint32_t ready_delivered;
    uint64_t observed_read_ready_sequence;
    uint64_t observed_write_ready_sequence;
    uint64_t read_ready_seq_delivered;
    uint64_t write_ready_seq_delivered;
    uint64_t claim_id;
    uint64_t file_ref;
    uint64_t data;
    kernel_epoll_target_source_t source;
    uint8_t source_captured;
    uint8_t source_reserved[7];
} kernel_epoll_watch_t;

typedef struct kernel_epoll_object {
    uint8_t used;
    uint8_t reserved[3];
    uint32_t refs;
    uint32_t generation;
    uint32_t mutation_sequence;
    uint16_t nwatch;
    uint16_t entry_high_water;
    uint64_t readiness_sequence;
    kernel_epoll_watch_t watch[EDGE_RUNTIME_MAX_EPOLL_WATCHES];
} kernel_epoll_object_t;

typedef struct kernel_epoll_object_snapshot {
    int32_t index;
    uint32_t generation;
    uint32_t refs;
    uint32_t mutation_sequence;
    uint16_t nwatch;
    uint16_t entry_high_water;
    uint64_t readiness_sequence;
} kernel_epoll_object_snapshot_t;

/*
 * A blocking epoll wait pins its object after descriptor lookup so close(2)
 * cannot recycle the object while the task sleeps. The pin belongs to the
 * task rather than to a transient kernel stack: fatal signal and exit_group
 * teardown can discard a blocked stack without returning through the syscall
 * epilogue. Keeping the lease in common code gives every architecture the
 * same exactly-once release rule on wake, interruption, and task exit.
 */
typedef struct kernel_epoll_wait_lease {
    uint32_t epoll_index_plus_one;
} kernel_epoll_wait_lease_t;

typedef struct kernel_epoll_watch_snapshot {
    int32_t epoll_index;
    uint16_t slot;
    uint16_t reserved;
    uint32_t object_generation;
    kernel_epoll_watch_t watch;
} kernel_epoll_watch_snapshot_t;

typedef struct kernel_epoll_watch_claim {
    int32_t epoll_index;
    uint16_t slot;
    uint16_t reserved;
    uint32_t object_generation;
    uint32_t slot_generation;
    uint32_t report;
    uint64_t claim_id;
    uint64_t read_ready_sequence;
    uint64_t write_ready_sequence;
} kernel_epoll_watch_claim_t;

typedef struct kernel_epoll_backend_ops {
    int (*install_descriptor)(void *context, int32_t epoll_index,
                              uint32_t flags);
    int (*resolve_epoll_descriptor)(void *context, int32_t descriptor,
                                    int32_t *epoll_index);
    int (*resolve_target_descriptor)(void *context, int32_t descriptor,
                                     uint64_t *description_id,
                                     int32_t *target_epoll_index);
    int (*target_description_retain)(void *context,
                                     uint64_t description_id);
    void (*target_description_release)(void *context,
                                       uint64_t description_id);
    /*
     * These callbacks are optional as a pair. A successful capture transfers
     * one stable-source reference to the common epoll watch. A failed capture
     * transfers nothing. The release callback may re-enter common epoll APIs;
     * common code always invokes it without holding the epoll lock.
     */
    int (*capture_target_source)(
        void *context, int32_t descriptor,
        uint64_t expected_description_id,
        kernel_epoll_target_source_t *source);
    void (*release_target_source)(
        void *context,
        const kernel_epoll_target_source_t *source);
    int (*observe_target_source)(
        void *context,
        const kernel_epoll_target_source_t *source,
        uint32_t requested_events,
        uint32_t *ready_events,
        uint64_t *read_ready_sequence,
        uint64_t *write_ready_sequence);
    void (*commit_target_source)(
        void *context,
        const kernel_epoll_target_source_t *source);
    void (*watch_set_changed)(void *context, int32_t epoll_index);
} kernel_epoll_backend_ops_t;

int kernel_epoll_backend_register(const kernel_epoll_backend_ops_t *ops,
                                  void *context);
int kernel_epoll_object_exists(int32_t epoll_index);
int kernel_epoll_object_snapshot(
    int32_t epoll_index, kernel_epoll_object_snapshot_t *snapshot);
int kernel_epoll_watch_snapshot(
    int32_t epoll_index, uint16_t slot,
    kernel_epoll_watch_snapshot_t *snapshot);
int kernel_epoll_object_retain(int32_t epoll_index);
void kernel_epoll_object_release(int32_t epoll_index);
int kernel_epoll_descriptor_retain(int32_t descriptor,
                                   int32_t *epoll_index);
int kernel_epoll_deliver_events(int32_t epoll_index,
                                uint32_t maximum_events,
                                kernel_epoll_event_copy_fn copy_event,
                                void *copy_context);
int kernel_epoll_wait_lease_acquire(kernel_epoll_wait_lease_t *lease,
                                    int32_t epoll_index);
void kernel_epoll_wait_lease_release(kernel_epoll_wait_lease_t *lease);
void kernel_epoll_detach_description(uint64_t description_id);
int kernel_epoll_graph_reaches(int32_t source, int32_t target);
uint32_t kernel_epoll_watch_preview(
    const kernel_epoll_watch_snapshot_t *snapshot,
    uint32_t current_ready,
    uint64_t read_ready_sequence,
    uint64_t write_ready_sequence);
uint32_t kernel_epoll_watch_claim(
    const kernel_epoll_watch_snapshot_t *snapshot,
    uint32_t current_ready,
    uint64_t read_ready_sequence,
    uint64_t write_ready_sequence,
    kernel_epoll_watch_claim_t *claim);
void kernel_epoll_watch_finish(
    const kernel_epoll_watch_claim_t *claim, int copy_succeeded);

/* Install a common eventfd object in the current task's descriptor table. */
int kernel_eventfd_create_descriptor(uint32_t initial_value, uint32_t flags);

/* Install and operate on an epoll instance in the current descriptor table. */
int kernel_epoll_create_descriptor(uint32_t flags);
int kernel_epoll_control_descriptor(int32_t epoll_descriptor,
                                    uint32_t operation,
                                    int32_t target_descriptor,
                                    const kernel_epoll_event_t *event);
int kernel_epoll_maximum_events_validate(uint32_t maximum_events,
                                         uint32_t event_size);
int64_t kernel_epoll_wait_descriptor(int32_t epoll_descriptor,
                                     uint64_t user_events,
                                     uint32_t maximum_events,
                                     int64_t timeout_microseconds,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers);

/* Wait for readiness across a Linux pollfd array. */
int64_t kernel_poll_wait_descriptors(uint64_t user_poll_fds,
                                     uint64_t descriptor_count,
                                     int64_t timeout_microseconds,
                                     uint64_t user_timeout,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers);

/* Wait for readiness across Linux select fd sets. */
int64_t kernel_select_wait_descriptors(uint64_t descriptor_count,
                                       uint64_t user_read_set,
                                       uint64_t user_write_set,
                                       uint64_t user_except_set,
                                       int64_t timeout_microseconds,
                                       uint64_t user_timeout,
                                       uint32_t timeout_format,
                                       int replace_signal_mask,
                                       uint64_t signal_mask,
                                       void *user_registers);
int64_t arch_epoll_wait_descriptor(int32_t epoll_descriptor,
                                   uint64_t user_events,
                                   uint32_t maximum_events,
                                   int64_t timeout_microseconds,
                                   int replace_signal_mask,
                                   uint64_t signal_mask,
                                   void *user_registers);
int64_t arch_poll_wait_descriptors(uint64_t user_poll_fds,
                                   uint64_t descriptor_count,
                                   int64_t timeout_microseconds,
                                   uint64_t user_timeout,
                                   int replace_signal_mask,
                                   uint64_t signal_mask,
                                   void *user_registers);
int64_t arch_select_wait_descriptors(uint64_t descriptor_count,
                                     uint64_t user_read_set,
                                     uint64_t user_write_set,
                                     uint64_t user_except_set,
                                     int64_t timeout_microseconds,
                                     uint64_t user_timeout,
                                     uint32_t timeout_format,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers);

#endif
