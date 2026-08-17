/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_WAIT_RUNTIME_H
#define EDGEOS_KERNEL_WAIT_RUNTIME_H

#include <stdint.h>

#include "kernel/event_runtime.h"
#include "kernel/runtime_limits.h"

#define KERNEL_WAIT_POLLIN     0x0001
#define KERNEL_WAIT_POLLPRI    0x0002
#define KERNEL_WAIT_POLLOUT    0x0004
#define KERNEL_WAIT_POLLERR    0x0008
#define KERNEL_WAIT_POLLHUP    0x0010
#define KERNEL_WAIT_POLLNVAL   0x0020
#define KERNEL_WAIT_POLLRDNORM 0x0040
#define KERNEL_WAIT_POLLRDBAND 0x0080
#define KERNEL_WAIT_POLLWRNORM 0x0100
#define KERNEL_WAIT_POLLWRBAND 0x0200
#define KERNEL_WAIT_POLLRDHUP  0x2000

#define KERNEL_WAIT_RESCAN_INTERVAL_US 16000ull

#define KERNEL_WAIT_SELECT_READ   0x01u
#define KERNEL_WAIT_SELECT_WRITE  0x02u
#define KERNEL_WAIT_SELECT_EXCEPT 0x04u

typedef enum kernel_wait_source_kind {
    KERNEL_WAIT_SOURCE_UNSUPPORTED = 0,
    KERNEL_WAIT_SOURCE_EPOLL,
    KERNEL_WAIT_SOURCE_SOCKET,
    KERNEL_WAIT_SOURCE_EVENTFD,
    KERNEL_WAIT_SOURCE_PIPE_READ,
    KERNEL_WAIT_SOURCE_PIPE_WRITE,
    KERNEL_WAIT_SOURCE_PIPE_READ_WRITE,
    KERNEL_WAIT_SOURCE_TIMERFD,
    KERNEL_WAIT_SOURCE_INOTIFY,
    KERNEL_WAIT_SOURCE_OWNER_WAKE,
} kernel_wait_source_kind_t;

typedef struct kernel_wait_source {
    kernel_wait_source_kind_t kind;
    int32_t object_index;
    const void *backend_token;
} kernel_wait_source_t;

typedef struct kernel_wait_observation {
    uint32_t events;
    uint64_t read_sequence;
    uint64_t write_sequence;
} kernel_wait_observation_t;

typedef struct kernel_wait_pollfd {
    int32_t fd;
    int16_t events;
    int16_t revents;
} kernel_wait_pollfd_t;

typedef enum kernel_wait_registration {
    KERNEL_WAIT_REGISTRATION_FAILED = -1,
    KERNEL_WAIT_REGISTRATION_BEST_EFFORT = 0,
    KERNEL_WAIT_REGISTRATION_EXACT = 1,
} kernel_wait_registration_t;

typedef struct kernel_wait_backend_ops {
    int (*resolve_descriptor)(void *context, int32_t descriptor,
                              kernel_wait_source_t *source);
    int (*resolve_epoll_watch)(void *context,
                               const kernel_epoll_watch_t *watch,
                               kernel_wait_source_t *source);
    int (*observe_source)(void *context,
                          const kernel_wait_source_t *source,
                          int16_t requested_events,
                          kernel_wait_observation_t *observation);
    kernel_wait_registration_t (*register_waiter)(
        void *context, const kernel_wait_source_t *source,
        int16_t events, int32_t waiter_pid);
} kernel_wait_backend_ops_t;

typedef struct kernel_wait_epoll_delivery_ops {
    int (*copy_event)(
        void *context, uint32_t event_index,
        const kernel_epoll_event_t *event,
        const kernel_epoll_watch_t *watch,
        const kernel_wait_source_t *source,
        const kernel_wait_observation_t *observation);
    void (*commit_source)(void *context,
                          const kernel_wait_source_t *source);
} kernel_wait_epoll_delivery_ops_t;

typedef struct kernel_wait_plan {
    const kernel_wait_backend_ops_t *backend_ops;
    void *backend_context;
    int32_t waiter_pid;
    int all_sources_exact;
    int needs_periodic_rescan;
    uint64_t timer_deadline_us;
    uint8_t epoll_path[EDGE_RUNTIME_MAX_EPOLLS];
} kernel_wait_plan_t;

int16_t kernel_wait_epoll_to_poll_events(uint32_t events);
int kernel_wait_events_request_epoll_read(int16_t events);
uint32_t kernel_wait_poll_project(uint32_t ready_events,
                                  int16_t requested_events);
int16_t kernel_wait_select_to_poll_events(uint8_t requested_sets);
uint8_t kernel_wait_select_project(uint32_t ready_events,
                                   uint8_t requested_sets);
uint32_t kernel_wait_epoll_project(uint32_t poll_events,
                                   uint32_t requested_events);
int kernel_wait_poll_evaluate(const kernel_wait_backend_ops_t *backend_ops,
                              void *backend_context,
                              kernel_wait_pollfd_t *poll_fds,
                              uint32_t descriptor_count);
int kernel_wait_select_evaluate(
    const kernel_wait_backend_ops_t *backend_ops, void *backend_context,
    uint32_t descriptor_count,
    const uint8_t *read_set, const uint8_t *write_set,
    const uint8_t *except_set,
    uint8_t *read_result, uint8_t *write_result,
    uint8_t *except_result);
int kernel_wait_epoll_has_ready(
    const kernel_wait_backend_ops_t *backend_ops, void *backend_context,
    int32_t epoll_index);
int kernel_wait_epoll_evaluate(
    const kernel_wait_backend_ops_t *backend_ops, void *backend_context,
    const kernel_wait_epoll_delivery_ops_t *delivery_ops,
    void *delivery_context, int32_t epoll_index,
    uint32_t maximum_events);
int kernel_wait_array_element_address(
    uint64_t base, uint64_t index, uint64_t element_size,
    uint64_t *address);
uint64_t kernel_wait_deadline_min(uint64_t first, uint64_t second);
uint64_t kernel_wait_deadline_from_timeout(uint64_t start_us,
                                           int64_t timeout_us);
uint64_t kernel_wait_bounded_rescan_deadline(uint64_t start_us,
                                             int64_t timeout_us,
                                             uint64_t now_us);

void kernel_wait_plan_init(kernel_wait_plan_t *plan,
                           const kernel_wait_backend_ops_t *backend_ops,
                           void *backend_context, int32_t waiter_pid);
void kernel_wait_plan_mark_inexact(kernel_wait_plan_t *plan);
void kernel_wait_plan_collect_descriptor(kernel_wait_plan_t *plan,
                                         int32_t descriptor,
                                         int16_t events);
void kernel_wait_plan_collect_epoll(kernel_wait_plan_t *plan,
                                    int32_t epoll_index);
uint64_t kernel_wait_plan_deadline(const kernel_wait_plan_t *plan,
                                   uint64_t start_us, int64_t timeout_us,
                                   uint64_t now_us);

#endif
