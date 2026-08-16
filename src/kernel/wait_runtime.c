/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-independent poll, select, and epoll wait-source planning.
 * Descriptor lookup and waiter linkage remain backend mechanisms; traversal,
 * exactness, timeout policy, and Linux event-mask semantics live here.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/timerfd.h"
#include "kernel/wait_runtime.h"

static void kernel_wait_bytes_zero(void *destination, uint64_t length) {
    uint8_t *bytes = (uint8_t *)destination;
    while (length--) *bytes++ = 0;
}

static int16_t kernel_wait_source_registration_events(
        kernel_wait_source_kind_t kind, int16_t events) {
    const int16_t read_events =
        KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM;
    const int16_t write_events =
        KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLWRNORM;

    switch (kind) {
        case KERNEL_WAIT_SOURCE_SOCKET:
            return events &
                (KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLPRI |
                 KERNEL_WAIT_POLLRDNORM | KERNEL_WAIT_POLLRDBAND |
                 KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLWRNORM |
                 KERNEL_WAIT_POLLWRBAND | KERNEL_WAIT_POLLRDHUP);
        case KERNEL_WAIT_SOURCE_EVENTFD:
            return events & (read_events | write_events);
        case KERNEL_WAIT_SOURCE_PIPE_READ:
            return events & read_events;
        case KERNEL_WAIT_SOURCE_PIPE_WRITE:
            return events & write_events;
        case KERNEL_WAIT_SOURCE_PIPE_READ_WRITE:
            return events & (read_events | write_events);
        default:
            return events;
    }
}

int16_t kernel_wait_epoll_to_poll_events(uint32_t events) {
    int16_t requested = 0;

    if (events & KERNEL_EPOLLIN) requested |= KERNEL_WAIT_POLLIN;
    if (events & KERNEL_EPOLLPRI) requested |= KERNEL_WAIT_POLLPRI;
    if (events & KERNEL_EPOLLRDNORM) requested |= KERNEL_WAIT_POLLRDNORM;
    if (events & KERNEL_EPOLLRDBAND) requested |= KERNEL_WAIT_POLLRDBAND;
    if (events & KERNEL_EPOLLOUT) requested |= KERNEL_WAIT_POLLOUT;
    if (events & KERNEL_EPOLLWRNORM) requested |= KERNEL_WAIT_POLLWRNORM;
    if (events & KERNEL_EPOLLWRBAND) requested |= KERNEL_WAIT_POLLWRBAND;
    if (events & KERNEL_EPOLLRDHUP) requested |= KERNEL_WAIT_POLLRDHUP;
    return requested;
}

int kernel_wait_events_request_epoll_read(int16_t events) {
    /*
     * An epoll descriptor is a readable source. POLLPRI and POLLRDHUP alone
     * cannot make a nested epoll readable and therefore must not register its
     * unrelated descendants.
     */
    return (events &
            (KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM)) != 0;
}

uint32_t kernel_wait_poll_project(uint32_t ready_events,
                                  int16_t requested_events) {
    const uint32_t requested = (uint32_t)(uint16_t)requested_events;
    uint32_t result = ready_events &
        (KERNEL_WAIT_POLLERR | KERNEL_WAIT_POLLHUP |
         KERNEL_WAIT_POLLNVAL);
    if (ready_events &
        (KERNEL_EPOLLIN | KERNEL_EPOLLRDNORM))
        result |= requested &
            (KERNEL_EPOLLIN | KERNEL_EPOLLRDNORM);
    if (ready_events & KERNEL_EPOLLPRI)
        result |= requested & KERNEL_EPOLLPRI;
    if (ready_events & KERNEL_EPOLLRDBAND)
        result |= requested & KERNEL_EPOLLRDBAND;
    if (ready_events &
        (KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM))
        result |= requested &
            (KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM);
    if (ready_events & KERNEL_EPOLLWRBAND)
        result |= requested & KERNEL_EPOLLWRBAND;
    if (ready_events & KERNEL_EPOLLRDHUP)
        result |= requested & KERNEL_EPOLLRDHUP;
    return result;
}

int16_t kernel_wait_select_to_poll_events(uint8_t requested_sets) {
    int16_t events = 0;

    if (requested_sets & KERNEL_WAIT_SELECT_READ)
        events |= KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM |
                  KERNEL_WAIT_POLLRDBAND;
    if (requested_sets & KERNEL_WAIT_SELECT_WRITE)
        events |= KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLWRNORM |
                  KERNEL_WAIT_POLLWRBAND;
    if (requested_sets & KERNEL_WAIT_SELECT_EXCEPT)
        events |= KERNEL_WAIT_POLLPRI;
    return events;
}

uint8_t kernel_wait_select_project(uint32_t ready_events,
                                   uint8_t requested_sets) {
    const uint32_t read_events =
        KERNEL_EPOLLIN | KERNEL_EPOLLRDNORM |
        KERNEL_EPOLLRDBAND | KERNEL_EPOLLHUP | KERNEL_EPOLLERR |
        KERNEL_WAIT_POLLNVAL;
    const uint32_t write_events =
        KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM |
        KERNEL_EPOLLWRBAND | KERNEL_EPOLLERR |
        KERNEL_WAIT_POLLNVAL;
    const uint32_t except_events =
        KERNEL_EPOLLPRI | KERNEL_WAIT_POLLNVAL;
    uint8_t result = 0;

    /*
     * These sets mirror Linux fs/select.c. In particular, HUP makes a
     * descriptor readable but not writable, RDHUP is not a readfds event,
     * and only priority data is reported through exceptfds.
     */
    if ((requested_sets & KERNEL_WAIT_SELECT_READ) &&
        (ready_events & read_events))
        result |= KERNEL_WAIT_SELECT_READ;
    if ((requested_sets & KERNEL_WAIT_SELECT_WRITE) &&
        (ready_events & write_events))
        result |= KERNEL_WAIT_SELECT_WRITE;
    if ((requested_sets & KERNEL_WAIT_SELECT_EXCEPT) &&
        (ready_events & except_events))
        result |= KERNEL_WAIT_SELECT_EXCEPT;
    return result;
}

uint32_t kernel_wait_epoll_project(uint32_t poll_events,
                                   uint32_t requested_events) {
    uint32_t result = poll_events &
        (KERNEL_EPOLLERR | KERNEL_EPOLLHUP);

    if (poll_events &
        (KERNEL_EPOLLIN | KERNEL_EPOLLRDNORM))
        result |= requested_events &
            (KERNEL_EPOLLIN | KERNEL_EPOLLRDNORM);
    if (poll_events & KERNEL_EPOLLPRI)
        result |= requested_events & KERNEL_EPOLLPRI;
    if (poll_events & KERNEL_EPOLLRDBAND)
        result |= requested_events & KERNEL_EPOLLRDBAND;
    if (poll_events &
        (KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM))
        result |= requested_events &
            (KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM);
    if (poll_events & KERNEL_EPOLLWRBAND)
        result |= requested_events & KERNEL_EPOLLWRBAND;
    if (poll_events & KERNEL_EPOLLRDHUP)
        result |= requested_events & KERNEL_EPOLLRDHUP;
    return result;
}

static int kernel_wait_observe_descriptor(
        const kernel_wait_backend_ops_t *backend_ops,
        void *backend_context, int32_t descriptor,
        int16_t requested_events,
        kernel_wait_observation_t *observation) {
    kernel_wait_source_t source;

    if (!backend_ops || !backend_ops->resolve_descriptor ||
        !backend_ops->observe_source || !observation)
        return -EDGE_LINUX_EINVAL;
    kernel_wait_bytes_zero(&source, sizeof(source));
    if (backend_ops->resolve_descriptor(
            backend_context, descriptor, &source) < 0)
        return -EDGE_LINUX_EBADF;
    kernel_wait_bytes_zero(observation, sizeof(*observation));
    return backend_ops->observe_source(
        backend_context, &source, requested_events, observation);
}

int kernel_wait_poll_evaluate(const kernel_wait_backend_ops_t *backend_ops,
                              void *backend_context,
                              kernel_wait_pollfd_t *poll_fds,
                              uint32_t descriptor_count) {
    int ready = 0;

    if ((!poll_fds && descriptor_count) || !backend_ops ||
        !backend_ops->resolve_descriptor ||
        !backend_ops->observe_source)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < descriptor_count; ++index) {
        kernel_wait_pollfd_t *poll_fd = &poll_fds[index];
        kernel_wait_observation_t observation;
        int status;

        poll_fd->revents = 0;
        if (poll_fd->fd < 0) continue;
        kernel_wait_bytes_zero(&observation, sizeof(observation));
        status = kernel_wait_observe_descriptor(
            backend_ops, backend_context, poll_fd->fd, poll_fd->events,
            &observation);
        if (status < 0) {
            poll_fd->revents = KERNEL_WAIT_POLLNVAL;
        } else {
            poll_fd->revents = (int16_t)kernel_wait_poll_project(
                observation.events, poll_fd->events);
        }
        if (poll_fd->revents) ++ready;
    }
    return ready;
}

static int kernel_wait_fdset_test(const uint8_t *set, uint32_t descriptor) {
    return set &&
        (set[descriptor >> 3] &
         (uint8_t)(1u << (descriptor & 7u))) != 0;
}

static void kernel_wait_fdset_set(uint8_t *set, uint32_t descriptor) {
    if (set)
        set[descriptor >> 3] |=
            (uint8_t)(1u << (descriptor & 7u));
}

int kernel_wait_select_evaluate(
    const kernel_wait_backend_ops_t *backend_ops, void *backend_context,
    uint32_t descriptor_count,
    const uint8_t *read_set, const uint8_t *write_set,
    const uint8_t *except_set,
    uint8_t *read_result, uint8_t *write_result,
    uint8_t *except_result) {
    uint64_t result_bytes =
        ((uint64_t)descriptor_count + 63u) / 64u * sizeof(uint64_t);
    int ready = 0;

    if (!backend_ops || !backend_ops->resolve_descriptor ||
        !backend_ops->observe_source)
        return -EDGE_LINUX_EINVAL;
    kernel_wait_bytes_zero(read_result, read_result ? result_bytes : 0);
    kernel_wait_bytes_zero(write_result, write_result ? result_bytes : 0);
    kernel_wait_bytes_zero(except_result, except_result ? result_bytes : 0);

    for (uint32_t descriptor = 0;
         descriptor < descriptor_count; ++descriptor) {
        kernel_wait_observation_t observation;
        uint8_t requested_sets = 0;
        uint8_t ready_sets;
        int status;

        if (kernel_wait_fdset_test(read_set, descriptor))
            requested_sets |= KERNEL_WAIT_SELECT_READ;
        if (kernel_wait_fdset_test(write_set, descriptor))
            requested_sets |= KERNEL_WAIT_SELECT_WRITE;
        if (kernel_wait_fdset_test(except_set, descriptor))
            requested_sets |= KERNEL_WAIT_SELECT_EXCEPT;
        if (!requested_sets) continue;

        kernel_wait_bytes_zero(&observation, sizeof(observation));
        status = kernel_wait_observe_descriptor(
            backend_ops, backend_context, (int32_t)descriptor,
            kernel_wait_select_to_poll_events(requested_sets),
            &observation);
        if (status < 0) return -EDGE_LINUX_EBADF;
        ready_sets = kernel_wait_select_project(
            observation.events, requested_sets);
        if (ready_sets & KERNEL_WAIT_SELECT_READ) {
            kernel_wait_fdset_set(read_result, descriptor);
            ++ready;
        }
        if (ready_sets & KERNEL_WAIT_SELECT_WRITE) {
            kernel_wait_fdset_set(write_result, descriptor);
            ++ready;
        }
        if (ready_sets & KERNEL_WAIT_SELECT_EXCEPT) {
            kernel_wait_fdset_set(except_result, descriptor);
            ++ready;
        }
    }
    return ready;
}

static int kernel_wait_epoll_ready_recursive(
        const kernel_wait_backend_ops_t *backend_ops,
        void *backend_context, int32_t epoll_index,
        uint8_t visited[EDGE_RUNTIME_MAX_EPOLLS], uint32_t depth) {
    kernel_epoll_object_snapshot_t epoll;

    if (!backend_ops || !backend_ops->resolve_epoll_watch ||
        !backend_ops->observe_source || !visited ||
        epoll_index < 0 ||
        epoll_index >= (int32_t)EDGE_RUNTIME_MAX_EPOLLS ||
        visited[epoll_index] ||
        depth > KERNEL_EPOLL_NESTING_MAX)
        return 0;
    if (kernel_epoll_object_snapshot(epoll_index, &epoll) < 0)
        return 0;

    visited[epoll_index] = 1;
    for (uint32_t index = 0;
         index < epoll.entry_high_water; ++index) {
        kernel_epoll_watch_snapshot_t snapshot;
        kernel_wait_observation_t observation;
        kernel_wait_source_t source;
        const kernel_epoll_watch_t *watch;
        uint32_t current;

        if (kernel_epoll_watch_snapshot(
                epoll_index, (uint16_t)index, &snapshot) <= 0)
            continue;
        watch = &snapshot.watch;
        if (!watch->used || watch->oneshot_disabled) continue;
        kernel_wait_bytes_zero(&observation, sizeof(observation));
        if (watch->target_epoll_index >= 0) {
            if (!kernel_wait_epoll_ready_recursive(
                    backend_ops, backend_context,
                    watch->target_epoll_index, visited,
                    depth + 1u))
                continue;
            observation.events = KERNEL_WAIT_POLLIN;
            {
                kernel_epoll_object_snapshot_t child;
                if (kernel_epoll_object_snapshot(
                        watch->target_epoll_index, &child) == 0)
                    observation.read_sequence =
                        child.readiness_sequence;
            }
        } else {
            kernel_wait_bytes_zero(&source, sizeof(source));
            if (backend_ops->resolve_epoll_watch(
                    backend_context, watch, &source) < 0 ||
                backend_ops->observe_source(
                    backend_context, &source,
                    kernel_wait_epoll_to_poll_events(watch->events),
                    &observation) < 0)
                continue;
        }
        current = kernel_wait_epoll_project(
            observation.events, watch->events);
        if (kernel_epoll_watch_preview(
                &snapshot, current,
                observation.read_sequence,
                observation.write_sequence)) {
            visited[epoll_index] = 0;
            return 1;
        }
    }
    visited[epoll_index] = 0;
    return 0;
}

int kernel_wait_epoll_has_ready(
    const kernel_wait_backend_ops_t *backend_ops, void *backend_context,
    int32_t epoll_index) {
    uint8_t visited[EDGE_RUNTIME_MAX_EPOLLS] = {0};

    return kernel_wait_epoll_ready_recursive(
        backend_ops, backend_context, epoll_index, visited, 0);
}

int kernel_wait_epoll_evaluate(
    const kernel_wait_backend_ops_t *backend_ops, void *backend_context,
    const kernel_wait_epoll_delivery_ops_t *delivery_ops,
    void *delivery_context, int32_t epoll_index,
    uint32_t maximum_events) {
    kernel_epoll_object_snapshot_t epoll;
    uint8_t visited[EDGE_RUNTIME_MAX_EPOLLS] = {0};
    uint32_t emitted = 0;

    if (!backend_ops || !backend_ops->resolve_epoll_watch ||
        !backend_ops->observe_source || !delivery_ops ||
        !delivery_ops->copy_event || !maximum_events)
        return -EDGE_LINUX_EINVAL;
    if (epoll_index < 0 ||
        epoll_index >= (int32_t)EDGE_RUNTIME_MAX_EPOLLS ||
        kernel_epoll_object_snapshot(epoll_index, &epoll) < 0)
        return -EDGE_LINUX_EBADF;

    visited[epoll_index] = 1;
    for (uint32_t index = 0;
         index < epoll.entry_high_water &&
         emitted < maximum_events; ++index) {
        kernel_epoll_watch_snapshot_t snapshot;
        kernel_epoll_watch_claim_t claim;
        kernel_wait_observation_t observation;
        kernel_wait_source_t source;
        kernel_epoll_event_t event;
        const kernel_epoll_watch_t *watch;
        uint32_t current;
        uint32_t report;
        int source_resolved = 0;
        int status;

        if (kernel_epoll_watch_snapshot(
                epoll_index, (uint16_t)index, &snapshot) <= 0)
            continue;
        watch = &snapshot.watch;
        if (!watch->used || watch->oneshot_disabled) continue;
        kernel_wait_bytes_zero(&observation, sizeof(observation));
        kernel_wait_bytes_zero(&source, sizeof(source));
        if (watch->target_epoll_index >= 0) {
            if (!kernel_wait_epoll_ready_recursive(
                    backend_ops, backend_context,
                    watch->target_epoll_index, visited, 1u))
                continue;
            observation.events = KERNEL_WAIT_POLLIN;
            {
                kernel_epoll_object_snapshot_t child;
                if (kernel_epoll_object_snapshot(
                        watch->target_epoll_index, &child) == 0)
                    observation.read_sequence =
                        child.readiness_sequence;
            }
        } else {
            if (backend_ops->resolve_epoll_watch(
                    backend_context, watch, &source) < 0 ||
                backend_ops->observe_source(
                    backend_context, &source,
                    kernel_wait_epoll_to_poll_events(watch->events),
                    &observation) < 0)
                continue;
            source_resolved = 1;
        }
        current = kernel_wait_epoll_project(
            observation.events, watch->events);
        report = kernel_epoll_watch_claim(
            &snapshot, current,
            observation.read_sequence,
            observation.write_sequence, &claim);
        if (!report) continue;

        event.events = report;
        event.data = watch->data;
        status = delivery_ops->copy_event(
            delivery_context, emitted, &event, watch,
            source_resolved ? &source : 0, &observation);
        if (status < 0) {
            kernel_epoll_watch_finish(&claim, 0);
            return emitted ? (int)emitted : status;
        }
        kernel_epoll_watch_finish(&claim, 1);
        if (source_resolved && delivery_ops->commit_source)
            delivery_ops->commit_source(
                delivery_context, &source);
        ++emitted;
    }
    return (int)emitted;
}

int kernel_wait_array_element_address(
    uint64_t base, uint64_t index, uint64_t element_size,
    uint64_t *address) {
    uint64_t offset;
    uint64_t start;

    if (!address || !element_size ||
        index > UINT64_MAX / element_size)
        return -EDGE_LINUX_EINVAL;
    offset = index * element_size;
    if (offset > UINT64_MAX - base)
        return -EDGE_LINUX_EFAULT;
    start = base + offset;
    if (element_size - 1u > UINT64_MAX - start)
        return -EDGE_LINUX_EFAULT;
    *address = start;
    return 0;
}

uint64_t kernel_wait_deadline_min(uint64_t first, uint64_t second) {
    if (!first) return second;
    if (!second) return first;
    return first < second ? first : second;
}

uint64_t kernel_wait_deadline_from_timeout(uint64_t start_us,
                                           int64_t timeout_us) {
    uint64_t duration;

    if (timeout_us <= 0) return 0;
    duration = (uint64_t)timeout_us;
    return start_us > UINT64_MAX - duration ?
           UINT64_MAX : start_us + duration;
}

uint64_t kernel_wait_bounded_rescan_deadline(uint64_t start_us,
                                             int64_t timeout_us,
                                             uint64_t now_us) {
    uint64_t short_deadline =
        now_us > UINT64_MAX - KERNEL_WAIT_RESCAN_INTERVAL_US ?
        UINT64_MAX : now_us + KERNEL_WAIT_RESCAN_INTERVAL_US;
    uint64_t caller_deadline =
        kernel_wait_deadline_from_timeout(start_us, timeout_us);

    /*
     * Best-effort object waiter lists retain prompt wakeups but also rescan at
     * approximately one display frame. This bounds a missed registration race
     * without restoring the vCPU-burning millisecond retry loop.
     */
    return kernel_wait_deadline_min(caller_deadline, short_deadline);
}

void kernel_wait_plan_init(kernel_wait_plan_t *plan,
                           const kernel_wait_backend_ops_t *backend_ops,
                           void *backend_context, int32_t waiter_pid) {
    if (!plan) return;
    kernel_wait_bytes_zero(plan, sizeof(*plan));
    plan->backend_ops = backend_ops;
    plan->backend_context = backend_context;
    plan->waiter_pid = waiter_pid;
    plan->all_sources_exact = 1;
}

void kernel_wait_plan_mark_inexact(kernel_wait_plan_t *plan) {
    if (!plan) return;
    plan->all_sources_exact = 0;
    plan->needs_periodic_rescan = 1;
}

static void kernel_wait_plan_collect_source(kernel_wait_plan_t *plan,
                                            const kernel_wait_source_t *source,
                                            int16_t events,
                                            uint32_t depth);

static void kernel_wait_plan_collect_epoll_at_depth(
        kernel_wait_plan_t *plan, int32_t epoll_index, uint32_t depth) {
    kernel_epoll_object_snapshot_t epoll;

    if (!plan || epoll_index < 0 ||
        epoll_index >= (int32_t)EDGE_RUNTIME_MAX_EPOLLS ||
        depth > KERNEL_EPOLL_NESTING_MAX ||
        plan->epoll_path[epoll_index]) {
        kernel_wait_plan_mark_inexact(plan);
        return;
    }
    if (kernel_epoll_object_snapshot(epoll_index, &epoll) < 0) {
        kernel_wait_plan_mark_inexact(plan);
        return;
    }

    plan->epoll_path[epoll_index] = 1;
    for (uint32_t index = 0; index < epoll.entry_high_water; ++index) {
        kernel_epoll_watch_snapshot_t snapshot;
        const kernel_epoll_watch_t *watch;
        kernel_wait_source_t source;
        int16_t events;

        if (kernel_epoll_watch_snapshot(
                epoll_index, (uint16_t)index, &snapshot) <= 0)
            continue;
        watch = &snapshot.watch;
        if (!watch->used || watch->oneshot_disabled) continue;
        events = kernel_wait_epoll_to_poll_events(watch->events);

        /*
         * The retained target index identifies the watched epoll object even
         * after its original descriptor is closed or reused. Never re-resolve
         * a nested epoll through the descriptor table when this identity exists.
         */
        if (watch->target_epoll_index >= 0) {
            if (kernel_wait_events_request_epoll_read(events))
                kernel_wait_plan_collect_epoll_at_depth(
                    plan, watch->target_epoll_index, depth + 1u);
            continue;
        }

        if (!plan->backend_ops ||
            !plan->backend_ops->resolve_epoll_watch ||
            plan->backend_ops->resolve_epoll_watch(
                plan->backend_context, watch, &source) < 0) {
            kernel_wait_plan_mark_inexact(plan);
            continue;
        }
        kernel_wait_plan_collect_source(
            plan, &source, events, depth + 1u);
    }
    plan->epoll_path[epoll_index] = 0;
}

static void kernel_wait_plan_collect_registered_source(
        kernel_wait_plan_t *plan, const kernel_wait_source_t *source,
        int16_t events) {
    kernel_wait_registration_t registration =
        KERNEL_WAIT_REGISTRATION_FAILED;
    int16_t registration_events =
        kernel_wait_source_registration_events(source->kind, events);

    if (plan->backend_ops && plan->backend_ops->register_waiter) {
        registration = plan->backend_ops->register_waiter(
            plan->backend_context, source, registration_events,
            plan->waiter_pid);
    }
    if (registration != KERNEL_WAIT_REGISTRATION_EXACT)
        kernel_wait_plan_mark_inexact(plan);
}

static void kernel_wait_plan_collect_source(kernel_wait_plan_t *plan,
                                            const kernel_wait_source_t *source,
                                            int16_t events,
                                            uint32_t depth) {
    if (!plan || !source) {
        kernel_wait_plan_mark_inexact(plan);
        return;
    }

    switch (source->kind) {
        case KERNEL_WAIT_SOURCE_EPOLL:
            if (kernel_wait_events_request_epoll_read(events))
                kernel_wait_plan_collect_epoll_at_depth(
                    plan, source->object_index, depth);
            return;
        case KERNEL_WAIT_SOURCE_SOCKET:
        case KERNEL_WAIT_SOURCE_EVENTFD:
        case KERNEL_WAIT_SOURCE_PIPE_READ:
        case KERNEL_WAIT_SOURCE_PIPE_WRITE:
        case KERNEL_WAIT_SOURCE_PIPE_READ_WRITE:
        case KERNEL_WAIT_SOURCE_INOTIFY:
            kernel_wait_plan_collect_registered_source(
                plan, source, events);
            return;
        case KERNEL_WAIT_SOURCE_TIMERFD: {
            kernel_timerfd_state_t state;
            uint64_t deadline;

            if (kernel_timerfd_query(source->object_index, &state) < 0 ||
                kernel_timerfd_monotonic_deadline(&state, &deadline) < 0) {
                kernel_wait_plan_mark_inexact(plan);
                return;
            }
            if (events &
                (KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM)) {
                plan->timer_deadline_us = kernel_wait_deadline_min(
                    plan->timer_deadline_us, deadline);
            }
            return;
        }
        case KERNEL_WAIT_SOURCE_OWNER_WAKE:
            return;
        case KERNEL_WAIT_SOURCE_UNSUPPORTED:
        default:
            kernel_wait_plan_mark_inexact(plan);
            return;
    }
}

void kernel_wait_plan_collect_descriptor(kernel_wait_plan_t *plan,
                                         int32_t descriptor,
                                         int16_t events) {
    kernel_wait_source_t source;

    if (!plan || !plan->backend_ops ||
        !plan->backend_ops->resolve_descriptor ||
        plan->backend_ops->resolve_descriptor(
            plan->backend_context, descriptor, &source) < 0) {
        kernel_wait_plan_mark_inexact(plan);
        return;
    }
    kernel_wait_plan_collect_source(plan, &source, events, 0);
}

void kernel_wait_plan_collect_epoll(kernel_wait_plan_t *plan,
                                    int32_t epoll_index) {
    kernel_wait_plan_collect_epoll_at_depth(plan, epoll_index, 0);
}

uint64_t kernel_wait_plan_deadline(const kernel_wait_plan_t *plan,
                                   uint64_t start_us, int64_t timeout_us,
                                   uint64_t now_us) {
    uint64_t deadline =
        kernel_wait_deadline_from_timeout(start_us, timeout_us);

    if (!plan) return deadline;
    deadline = kernel_wait_deadline_min(
        deadline, plan->timer_deadline_us);
    if (!plan->all_sources_exact || plan->needs_periodic_rescan) {
        deadline = kernel_wait_deadline_min(
            deadline,
            kernel_wait_bounded_rescan_deadline(
                start_us, timeout_us, now_us));
    }
    return deadline;
}
