/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Host-side policy tests for the architecture-independent wait planner.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/timerfd.h"
#include "kernel/wait_runtime.h"

extern int printf(const char *format, ...);

#define TEST_EPOLL_COUNT 8
#define TEST_DESCRIPTOR_COUNT 32
#define TEST_DELIVERY_CAPACITY 8
#define TEST_TIMER_COUNT 16

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            printf("wait_runtime_unit: %s:%d: %s\n",                       \
                   __func__, __LINE__, #condition);                         \
            return 1;                                                       \
        }                                                                   \
    } while (0)

typedef struct mock_entry {
    int valid;
    kernel_wait_source_t source;
    kernel_wait_registration_t registration;
    uint32_t ready_events;
    uint64_t read_sequence;
    uint64_t write_sequence;
} mock_entry_t;

typedef struct mock_backend {
    mock_entry_t descriptors[TEST_DESCRIPTOR_COUNT];
    int resolve_watch_calls;
    int register_calls;
    int16_t last_registration_events;
    int32_t last_waiter_pid;
    kernel_wait_source_kind_t last_registered_kind;
} mock_backend_t;

typedef struct mock_delivery {
    uint32_t copy_calls;
    uint32_t commit_calls;
    uint32_t fail_copy_index;
    kernel_epoll_event_t copied_events[TEST_DELIVERY_CAPACITY];
    int32_t copied_descriptors[TEST_DELIVERY_CAPACITY];
    int32_t copied_source_indices[TEST_DELIVERY_CAPACITY];
    uint8_t copied_source_present[TEST_DELIVERY_CAPACITY];
    uint64_t copied_read_sequences[TEST_DELIVERY_CAPACITY];
    uint64_t copied_write_sequences[TEST_DELIVERY_CAPACITY];
    int32_t committed_source_indices[TEST_DELIVERY_CAPACITY];
} mock_delivery_t;

static kernel_epoll_object_t g_test_epolls[TEST_EPOLL_COUNT];
static uint8_t g_test_epoll_valid[TEST_EPOLL_COUNT];
static kernel_timerfd_state_t g_test_timers[TEST_TIMER_COUNT];
static uint8_t g_test_timer_valid[TEST_TIMER_COUNT];
static uint32_t g_claim_finish_calls;
static uint32_t g_claim_finish_successes;
static uint32_t g_claim_finish_failures;

static void bytes_zero(void *destination, uint64_t length) {
    uint8_t *bytes = (uint8_t *)destination;
    while (length--) *bytes++ = 0;
}

static void reset_state(mock_backend_t *backend) {
    bytes_zero(backend, sizeof(*backend));
    bytes_zero(g_test_epolls, sizeof(g_test_epolls));
    bytes_zero(g_test_epoll_valid, sizeof(g_test_epoll_valid));
    bytes_zero(g_test_timers, sizeof(g_test_timers));
    bytes_zero(g_test_timer_valid, sizeof(g_test_timer_valid));
    g_claim_finish_calls = 0;
    g_claim_finish_successes = 0;
    g_claim_finish_failures = 0;
}

static void reset_delivery(mock_delivery_t *delivery) {
    bytes_zero(delivery, sizeof(*delivery));
    delivery->fail_copy_index = UINT32_MAX;
}

kernel_epoll_object_t *kernel_epoll_object_get(int32_t epoll_index) {
    if (epoll_index < 0 || epoll_index >= TEST_EPOLL_COUNT ||
        !g_test_epoll_valid[epoll_index])
        return 0;
    return &g_test_epolls[epoll_index];
}

int kernel_epoll_object_snapshot(
        int32_t epoll_index,
        kernel_epoll_object_snapshot_t *snapshot) {
    kernel_epoll_object_t *epoll;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    bytes_zero(snapshot, sizeof(*snapshot));
    epoll = kernel_epoll_object_get(epoll_index);
    if (!epoll) return -EDGE_LINUX_EBADF;
    snapshot->index = epoll_index;
    snapshot->generation = epoll->generation;
    snapshot->refs = epoll->refs;
    snapshot->mutation_sequence = epoll->mutation_sequence;
    snapshot->nwatch = epoll->nwatch;
    snapshot->entry_high_water = epoll->entry_high_water;
    snapshot->readiness_sequence = epoll->readiness_sequence;
    return 0;
}

int kernel_epoll_watch_snapshot(
        int32_t epoll_index, uint16_t slot,
        kernel_epoll_watch_snapshot_t *snapshot) {
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    bytes_zero(snapshot, sizeof(*snapshot));
    epoll = kernel_epoll_object_get(epoll_index);
    if (!epoll) return -EDGE_LINUX_EBADF;
    if (slot >= epoll->entry_high_water ||
        slot >= EDGE_RUNTIME_MAX_EPOLL_WATCHES)
        return 0;
    watch = &epoll->watch[slot];
    if (!watch->used) return 0;
    snapshot->epoll_index = epoll_index;
    snapshot->slot = slot;
    snapshot->object_generation = epoll->generation;
    snapshot->watch = *watch;
    return 1;
}

uint32_t kernel_epoll_watch_preview(
        const kernel_epoll_watch_snapshot_t *snapshot,
        uint32_t current_ready,
        uint64_t read_ready_sequence,
        uint64_t write_ready_sequence) {
    (void)read_ready_sequence;
    (void)write_ready_sequence;
    if (!snapshot || !snapshot->watch.used ||
        snapshot->watch.oneshot_disabled)
        return 0;
    return current_ready;
}

uint32_t kernel_epoll_watch_claim(
        const kernel_epoll_watch_snapshot_t *snapshot,
        uint32_t current_ready,
        uint64_t read_ready_sequence,
        uint64_t write_ready_sequence,
        kernel_epoll_watch_claim_t *claim) {
    uint32_t report = kernel_epoll_watch_preview(
        snapshot, current_ready, read_ready_sequence,
        write_ready_sequence);

    if (claim) {
        bytes_zero(claim, sizeof(*claim));
        if (snapshot) {
            claim->epoll_index = snapshot->epoll_index;
            claim->slot = snapshot->slot;
            claim->object_generation = snapshot->object_generation;
            claim->slot_generation =
                snapshot->watch.slot_generation;
        }
        claim->report = report;
        claim->read_ready_sequence = read_ready_sequence;
        claim->write_ready_sequence = write_ready_sequence;
    }
    return report;
}

void kernel_epoll_watch_finish(
        const kernel_epoll_watch_claim_t *claim,
        int copy_succeeded) {
    (void)claim;
    ++g_claim_finish_calls;
    if (copy_succeeded)
        ++g_claim_finish_successes;
    else
        ++g_claim_finish_failures;
}

int kernel_timerfd_query(int timer_id, kernel_timerfd_state_t *state) {
    if (!state || timer_id < 0 || timer_id >= TEST_TIMER_COUNT ||
        !g_test_timer_valid[timer_id])
        return -EDGE_LINUX_EBADF;
    *state = g_test_timers[timer_id];
    return 0;
}

int kernel_timerfd_monotonic_deadline(
        const kernel_timerfd_state_t *state, uint64_t *deadline_us) {
    if (!state || !deadline_us) return -EDGE_LINUX_EINVAL;
    *deadline_us = state->next_expiry_us;
    return 0;
}

static mock_entry_t *mock_descriptor(mock_backend_t *backend,
                                     int32_t descriptor) {
    if (!backend || descriptor < 0 ||
        descriptor >= TEST_DESCRIPTOR_COUNT ||
        !backend->descriptors[descriptor].valid)
        return 0;
    return &backend->descriptors[descriptor];
}

static int mock_resolve_descriptor(void *context, int32_t descriptor,
                                   kernel_wait_source_t *source) {
    mock_entry_t *entry =
        mock_descriptor((mock_backend_t *)context, descriptor);
    if (!entry || !source) return -1;
    *source = entry->source;
    source->backend_token = entry;
    return 0;
}

static int mock_observe_source(
        void *context, const kernel_wait_source_t *source,
        int16_t requested_events,
        kernel_wait_observation_t *observation) {
    mock_entry_t *entry =
        source ? (mock_entry_t *)source->backend_token : 0;

    (void)context;
    (void)requested_events;
    if (!entry || !observation) return -1;
    bytes_zero(observation, sizeof(*observation));
    observation->events = entry->ready_events;
    observation->read_sequence = entry->read_sequence;
    observation->write_sequence = entry->write_sequence;
    return 0;
}

static int mock_resolve_epoll_watch(
        void *context, const kernel_epoll_watch_t *watch,
        kernel_wait_source_t *source) {
    mock_backend_t *backend = (mock_backend_t *)context;
    if (!backend || !watch) return -1;
    ++backend->resolve_watch_calls;
    return mock_resolve_descriptor(context, watch->fd, source);
}

static kernel_wait_registration_t mock_register_waiter(
        void *context, const kernel_wait_source_t *source,
        int16_t events, int32_t waiter_pid) {
    mock_backend_t *backend = (mock_backend_t *)context;
    const mock_entry_t *entry;

    if (!backend || !source || !source->backend_token)
        return KERNEL_WAIT_REGISTRATION_FAILED;
    entry = (const mock_entry_t *)source->backend_token;
    ++backend->register_calls;
    backend->last_registration_events = events;
    backend->last_waiter_pid = waiter_pid;
    backend->last_registered_kind = source->kind;
    return entry->registration;
}

static const kernel_wait_backend_ops_t g_mock_ops = {
    .resolve_descriptor = mock_resolve_descriptor,
    .resolve_epoll_watch = mock_resolve_epoll_watch,
    .observe_source = mock_observe_source,
    .register_waiter = mock_register_waiter,
};

static int mock_copy_event(
        void *context, uint32_t event_index,
        const kernel_epoll_event_t *event,
        const kernel_epoll_watch_t *watch,
        const kernel_wait_source_t *source,
        const kernel_wait_observation_t *observation) {
    mock_delivery_t *delivery = (mock_delivery_t *)context;

    if (!delivery || !event || !watch || !observation)
        return -EDGE_LINUX_EINVAL;
    ++delivery->copy_calls;
    if (event_index >= TEST_DELIVERY_CAPACITY)
        return -EDGE_LINUX_EFAULT;
    delivery->copied_events[event_index] = *event;
    delivery->copied_descriptors[event_index] = watch->fd;
    delivery->copied_source_present[event_index] = source ? 1u : 0u;
    delivery->copied_source_indices[event_index] =
        source ? source->object_index : -1;
    delivery->copied_read_sequences[event_index] =
        observation->read_sequence;
    delivery->copied_write_sequences[event_index] =
        observation->write_sequence;
    if (event_index == delivery->fail_copy_index)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static void mock_commit_source(
        void *context, const kernel_wait_source_t *source) {
    mock_delivery_t *delivery = (mock_delivery_t *)context;

    if (!delivery || !source) return;
    if (delivery->commit_calls < TEST_DELIVERY_CAPACITY) {
        delivery->committed_source_indices[delivery->commit_calls] =
            source->object_index;
    }
    ++delivery->commit_calls;
}

static const kernel_wait_epoll_delivery_ops_t g_mock_delivery_ops = {
    .copy_event = mock_copy_event,
    .commit_source = mock_commit_source,
};

static void install_descriptor(mock_backend_t *backend, int descriptor,
                               kernel_wait_source_kind_t kind,
                               int object_index,
                               kernel_wait_registration_t registration) {
    mock_entry_t *entry = &backend->descriptors[descriptor];
    entry->valid = 1;
    entry->source.kind = kind;
    entry->source.object_index = object_index;
    entry->source.backend_token = entry;
    entry->registration = registration;
}

static kernel_epoll_watch_t *install_watch(
        int epoll_index, int slot, int descriptor,
        int target_epoll_index, uint32_t events, int oneshot_disabled) {
    kernel_epoll_object_t *epoll = &g_test_epolls[epoll_index];
    kernel_epoll_watch_t *watch = &epoll->watch[slot];

    if (!g_test_epoll_valid[epoll_index]) {
        epoll->refs = 1;
        epoll->generation = (uint32_t)(epoll_index + 1);
        epoll->mutation_sequence = 1;
        epoll->readiness_sequence = 1;
    }
    g_test_epoll_valid[epoll_index] = 1;
    epoll->used = 1;
    if ((uint32_t)(slot + 1) > epoll->entry_high_water)
        epoll->entry_high_water = (uint16_t)(slot + 1);
    if (!watch->used) ++epoll->nwatch;
    ++epoll->mutation_sequence;
    watch->used = 1;
    watch->oneshot_disabled = oneshot_disabled ? 1u : 0u;
    watch->target_epoll_index = (int16_t)target_epoll_index;
    watch->slot_generation = (uint32_t)(slot + 1);
    watch->fd = descriptor;
    watch->events = events;
    watch->file_ref = (uint64_t)(uint32_t)(descriptor + 1);
    return watch;
}

static int test_snapshot_mock_contract(void) {
    mock_backend_t backend;
    kernel_epoll_object_snapshot_t object_snapshot;
    kernel_epoll_watch_snapshot_t watch_snapshot;
    kernel_epoll_watch_t *watch;

    reset_state(&backend);
    watch = install_watch(
        2, 2, 7, -1, KERNEL_EPOLLIN | KERNEL_EPOLLET, 0);
    watch->data = 0x12345678u;

    CHECK(kernel_epoll_object_snapshot(2, &object_snapshot) == 0);
    CHECK(object_snapshot.index == 2);
    CHECK(object_snapshot.generation == 3);
    CHECK(object_snapshot.refs == 1);
    CHECK(object_snapshot.mutation_sequence == 2);
    CHECK(object_snapshot.nwatch == 1);
    CHECK(object_snapshot.entry_high_water == 3);
    CHECK(object_snapshot.readiness_sequence == 1);

    CHECK(kernel_epoll_watch_snapshot(2, 0, &watch_snapshot) == 0);
    CHECK(kernel_epoll_watch_snapshot(2, 2, &watch_snapshot) == 1);
    CHECK(watch_snapshot.epoll_index == 2);
    CHECK(watch_snapshot.slot == 2);
    CHECK(watch_snapshot.object_generation == object_snapshot.generation);
    CHECK(watch_snapshot.watch.slot_generation == 3);
    CHECK(watch_snapshot.watch.fd == 7);
    CHECK(watch_snapshot.watch.events ==
          (KERNEL_EPOLLIN | KERNEL_EPOLLET));
    CHECK(watch_snapshot.watch.data == 0x12345678u);

    watch->events = KERNEL_EPOLLOUT;
    watch->data = 0;
    CHECK(watch_snapshot.watch.events ==
          (KERNEL_EPOLLIN | KERNEL_EPOLLET));
    CHECK(watch_snapshot.watch.data == 0x12345678u);

    CHECK(kernel_epoll_object_snapshot(7, &object_snapshot) ==
          -EDGE_LINUX_EBADF);
    CHECK(object_snapshot.entry_high_water == 0);
    CHECK(kernel_epoll_watch_snapshot(7, 0, &watch_snapshot) ==
          -EDGE_LINUX_EBADF);
    CHECK(!watch_snapshot.watch.used);
    CHECK(kernel_epoll_object_snapshot(2, 0) == -EDGE_LINUX_EINVAL);
    CHECK(kernel_epoll_watch_snapshot(2, 2, 0) == -EDGE_LINUX_EINVAL);
    return 0;
}

static int test_event_masks(void) {
    int16_t events = kernel_wait_epoll_to_poll_events(
        KERNEL_EPOLLIN | KERNEL_EPOLLPRI | KERNEL_EPOLLOUT |
        KERNEL_EPOLLRDNORM | KERNEL_EPOLLRDBAND |
        KERNEL_EPOLLWRNORM | KERNEL_EPOLLWRBAND |
        KERNEL_EPOLLRDHUP | KERNEL_EPOLLERR | KERNEL_EPOLLHUP);
    int16_t expected =
        KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLPRI |
        KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLRDNORM |
        KERNEL_WAIT_POLLRDBAND | KERNEL_WAIT_POLLWRNORM |
        KERNEL_WAIT_POLLWRBAND | KERNEL_WAIT_POLLRDHUP;

    CHECK(events == expected);
    CHECK(kernel_wait_events_request_epoll_read(KERNEL_WAIT_POLLIN));
    CHECK(kernel_wait_events_request_epoll_read(KERNEL_WAIT_POLLRDNORM));
    CHECK(!kernel_wait_events_request_epoll_read(KERNEL_WAIT_POLLPRI));
    CHECK(!kernel_wait_events_request_epoll_read(KERNEL_WAIT_POLLRDHUP));
    CHECK(!kernel_wait_events_request_epoll_read(KERNEL_WAIT_POLLOUT));
    return 0;
}

static int test_poll_projection(void) {
    const uint32_t exceptional =
        KERNEL_WAIT_POLLERR | KERNEL_WAIT_POLLHUP |
        KERNEL_WAIT_POLLNVAL;

    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLIN, KERNEL_WAIT_POLLRDNORM) ==
          KERNEL_WAIT_POLLRDNORM);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLRDNORM, KERNEL_WAIT_POLLIN) ==
          KERNEL_WAIT_POLLIN);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLIN,
              KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM) ==
          (KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM));

    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLOUT, KERNEL_WAIT_POLLWRNORM) ==
          KERNEL_WAIT_POLLWRNORM);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLWRNORM, KERNEL_WAIT_POLLOUT) ==
          KERNEL_WAIT_POLLOUT);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLOUT,
              KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLWRNORM) ==
          (KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLWRNORM));

    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLPRI,
              KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLPRI) ==
          KERNEL_WAIT_POLLPRI);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLRDHUP,
              KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDHUP) ==
          KERNEL_WAIT_POLLRDHUP);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLIN,
              KERNEL_WAIT_POLLPRI | KERNEL_WAIT_POLLRDHUP) == 0);
    CHECK(kernel_wait_poll_project(
              KERNEL_WAIT_POLLIN, KERNEL_WAIT_POLLRDBAND) == 0);

    CHECK(kernel_wait_poll_project(exceptional, 0) == exceptional);
    CHECK(kernel_wait_poll_project(
              exceptional | KERNEL_WAIT_POLLIN,
              KERNEL_WAIT_POLLOUT) == exceptional);
    return 0;
}

static int test_select_projection(void) {
    const uint8_t all_sets =
        KERNEL_WAIT_SELECT_READ | KERNEL_WAIT_SELECT_WRITE |
        KERNEL_WAIT_SELECT_EXCEPT;
    const int16_t read_events =
        KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLRDNORM |
        KERNEL_WAIT_POLLRDBAND;
    const int16_t write_events =
        KERNEL_WAIT_POLLOUT | KERNEL_WAIT_POLLWRNORM |
        KERNEL_WAIT_POLLWRBAND;

    CHECK(kernel_wait_select_to_poll_events(0) == 0);
    CHECK(kernel_wait_select_to_poll_events(
              KERNEL_WAIT_SELECT_READ) == read_events);
    CHECK(kernel_wait_select_to_poll_events(
              KERNEL_WAIT_SELECT_WRITE) == write_events);
    CHECK(kernel_wait_select_to_poll_events(
              KERNEL_WAIT_SELECT_EXCEPT) == KERNEL_WAIT_POLLPRI);
    CHECK(kernel_wait_select_to_poll_events(all_sets) ==
          (read_events | write_events | KERNEL_WAIT_POLLPRI));

    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLHUP, all_sets) ==
          KERNEL_WAIT_SELECT_READ);
    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLHUP, KERNEL_WAIT_SELECT_WRITE) == 0);
    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLRDHUP, all_sets) == 0);
    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLERR, all_sets) ==
          (KERNEL_WAIT_SELECT_READ | KERNEL_WAIT_SELECT_WRITE));
    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLNVAL, all_sets) == all_sets);
    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLPRI, all_sets) ==
          KERNEL_WAIT_SELECT_EXCEPT);
    CHECK(kernel_wait_select_project(
              KERNEL_WAIT_POLLRDBAND, all_sets) ==
          KERNEL_WAIT_SELECT_READ);

    {
        uint8_t projected = kernel_wait_select_project(
            KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLOUT,
            KERNEL_WAIT_SELECT_READ | KERNEL_WAIT_SELECT_WRITE);
        int ready_set_count =
            ((projected & KERNEL_WAIT_SELECT_READ) != 0) +
            ((projected & KERNEL_WAIT_SELECT_WRITE) != 0) +
            ((projected & KERNEL_WAIT_SELECT_EXCEPT) != 0);

        /*
         * Linux counts ready bits across the returned sets. One descriptor
         * that is both readable and writable therefore contributes two.
         */
        CHECK(projected ==
              (KERNEL_WAIT_SELECT_READ | KERNEL_WAIT_SELECT_WRITE));
        CHECK(ready_set_count == 2);
    }
    return 0;
}

static int test_epoll_projection(void) {
    const uint32_t exceptional = KERNEL_EPOLLERR | KERNEL_EPOLLHUP;

    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLIN, KERNEL_EPOLLRDNORM) ==
          KERNEL_EPOLLRDNORM);
    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLRDNORM, KERNEL_EPOLLIN) ==
          KERNEL_EPOLLIN);
    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLOUT, KERNEL_EPOLLWRNORM) ==
          KERNEL_EPOLLWRNORM);
    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLWRNORM, KERNEL_EPOLLOUT) ==
          KERNEL_EPOLLOUT);

    CHECK(kernel_wait_epoll_project(exceptional, 0) == exceptional);
    CHECK(kernel_wait_epoll_project(
              exceptional | KERNEL_EPOLLIN, KERNEL_EPOLLOUT) ==
          exceptional);
    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLRDHUP, KERNEL_EPOLLIN) == 0);
    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLRDHUP,
              KERNEL_EPOLLIN | KERNEL_EPOLLRDHUP) ==
          KERNEL_EPOLLRDHUP);
    CHECK(kernel_wait_epoll_project(
              KERNEL_EPOLLIN,
              KERNEL_EPOLLPRI | KERNEL_EPOLLRDHUP) == 0);
    return 0;
}

static void test_fdset_set(uint8_t *set, uint32_t descriptor) {
    set[descriptor >> 3] |=
        (uint8_t)(1u << (descriptor & 7u));
}

static int test_common_evaluators(void) {
    mock_backend_t backend;
    kernel_wait_pollfd_t poll_fds[4];
    uint8_t read_set[8];
    uint8_t write_set[8];
    uint8_t except_set[8];
    uint8_t read_result[8];
    uint8_t write_result[8];
    uint8_t except_result[8];

    reset_state(&backend);
    bytes_zero(poll_fds, sizeof(poll_fds));
    install_descriptor(
        &backend, 3, KERNEL_WAIT_SOURCE_SOCKET, 1,
        KERNEL_WAIT_REGISTRATION_EXACT);
    install_descriptor(
        &backend, 4, KERNEL_WAIT_SOURCE_SOCKET, 2,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[3].ready_events =
        KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLOUT;
    backend.descriptors[4].ready_events = KERNEL_WAIT_POLLHUP;
    poll_fds[0].fd = -1;
    poll_fds[0].events = KERNEL_WAIT_POLLIN;
    poll_fds[1].fd = 3;
    poll_fds[1].events = KERNEL_WAIT_POLLRDNORM;
    poll_fds[2].fd = 4;
    poll_fds[2].events = 0;
    poll_fds[3].fd = 19;
    poll_fds[3].events = KERNEL_WAIT_POLLOUT;
    CHECK(kernel_wait_poll_evaluate(
              &g_mock_ops, &backend, poll_fds, 4) == 3);
    CHECK(poll_fds[0].revents == 0);
    CHECK(poll_fds[1].revents == KERNEL_WAIT_POLLRDNORM);
    CHECK(poll_fds[2].revents == KERNEL_WAIT_POLLHUP);
    CHECK(poll_fds[3].revents == KERNEL_WAIT_POLLNVAL);

    bytes_zero(read_set, sizeof(read_set));
    bytes_zero(write_set, sizeof(write_set));
    bytes_zero(except_set, sizeof(except_set));
    test_fdset_set(read_set, 3);
    test_fdset_set(write_set, 3);
    test_fdset_set(read_set, 4);
    CHECK(kernel_wait_select_evaluate(
              &g_mock_ops, &backend, 8,
              read_set, write_set, except_set,
              read_result, write_result, except_result) == 3);
    CHECK((read_result[0] & (1u << 3)) != 0);
    CHECK((write_result[0] & (1u << 3)) != 0);
    CHECK((read_result[0] & (1u << 4)) != 0);
    CHECK(except_result[0] == 0);

    test_fdset_set(except_set, 7);
    CHECK(kernel_wait_select_evaluate(
              &g_mock_ops, &backend, 8,
              read_set, write_set, except_set,
              read_result, write_result, except_result) ==
          -EDGE_LINUX_EBADF);
    return 0;
}

static int test_epoll_leaf_delivery(void) {
    mock_backend_t backend;
    mock_delivery_t delivery;
    kernel_epoll_watch_t *watch;

    reset_state(&backend);
    reset_delivery(&delivery);
    install_descriptor(
        &backend, 3, KERNEL_WAIT_SOURCE_SOCKET, 17,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[3].ready_events =
        KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLOUT;
    backend.descriptors[3].read_sequence = 41;
    backend.descriptors[3].write_sequence = 42;
    watch = install_watch(
        0, 0, 3, -1, KERNEL_EPOLLIN, 0);
    watch->data = 0x1122334455667788ull;

    CHECK(kernel_wait_epoll_has_ready(
              &g_mock_ops, &backend, 0) == 1);
    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == 1);
    CHECK(delivery.copy_calls == 1);
    CHECK(delivery.commit_calls == 1);
    CHECK(delivery.copied_events[0].events == KERNEL_EPOLLIN);
    CHECK(delivery.copied_events[0].data ==
          0x1122334455667788ull);
    CHECK(delivery.copied_descriptors[0] == 3);
    CHECK(delivery.copied_source_present[0] == 1);
    CHECK(delivery.copied_source_indices[0] == 17);
    CHECK(delivery.copied_read_sequences[0] == 41);
    CHECK(delivery.copied_write_sequences[0] == 42);
    CHECK(delivery.committed_source_indices[0] == 17);
    CHECK(g_claim_finish_calls == 1);
    CHECK(g_claim_finish_successes == 1);
    CHECK(g_claim_finish_failures == 0);
    return 0;
}

static int test_nested_epoll_delivery(void) {
    mock_backend_t backend;
    mock_delivery_t delivery;
    kernel_epoll_watch_t *root_watch;
    kernel_epoll_watch_t *leaf_watch;

    reset_state(&backend);
    reset_delivery(&delivery);
    install_descriptor(
        &backend, 4, KERNEL_WAIT_SOURCE_SOCKET, 18,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[4].ready_events = KERNEL_WAIT_POLLIN;
    backend.descriptors[4].read_sequence = 51;
    leaf_watch = install_watch(
        1, 0, 4, -1, KERNEL_EPOLLIN, 0);
    leaf_watch->data = 0xaau;
    root_watch = install_watch(
        0, 0, 31, 1, KERNEL_EPOLLIN, 0);
    root_watch->data = 0xbbccu;

    CHECK(kernel_wait_epoll_has_ready(
              &g_mock_ops, &backend, 0) == 1);
    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == 1);
    CHECK(delivery.copy_calls == 1);
    CHECK(delivery.commit_calls == 0);
    CHECK(delivery.copied_events[0].events == KERNEL_EPOLLIN);
    CHECK(delivery.copied_events[0].data == 0xbbccu);
    CHECK(delivery.copied_descriptors[0] == 31);
    CHECK(delivery.copied_source_present[0] == 0);
    CHECK(delivery.copied_read_sequences[0] ==
          g_test_epolls[1].readiness_sequence);
    CHECK(g_claim_finish_calls == 1);
    CHECK(g_claim_finish_successes == 1);
    return 0;
}

static int test_epoll_first_copy_fault(void) {
    mock_backend_t backend;
    mock_delivery_t delivery;

    reset_state(&backend);
    reset_delivery(&delivery);
    install_descriptor(
        &backend, 5, KERNEL_WAIT_SOURCE_SOCKET, 19,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[5].ready_events = KERNEL_WAIT_POLLIN;
    install_watch(0, 0, 5, -1, KERNEL_EPOLLIN, 0);
    delivery.fail_copy_index = 0;

    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == -EDGE_LINUX_EFAULT);
    CHECK(delivery.copy_calls == 1);
    CHECK(delivery.commit_calls == 0);
    CHECK(g_claim_finish_calls == 1);
    CHECK(g_claim_finish_successes == 0);
    CHECK(g_claim_finish_failures == 1);

    reset_delivery(&delivery);
    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == 1);
    CHECK(delivery.copy_calls == 1);
    CHECK(delivery.commit_calls == 1);
    CHECK(delivery.committed_source_indices[0] == 19);
    return 0;
}

static int test_epoll_later_copy_fault(void) {
    mock_backend_t backend;
    mock_delivery_t delivery;

    reset_state(&backend);
    reset_delivery(&delivery);
    install_descriptor(
        &backend, 6, KERNEL_WAIT_SOURCE_SOCKET, 20,
        KERNEL_WAIT_REGISTRATION_EXACT);
    install_descriptor(
        &backend, 7, KERNEL_WAIT_SOURCE_SOCKET, 21,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[6].ready_events = KERNEL_WAIT_POLLIN;
    backend.descriptors[7].ready_events = KERNEL_WAIT_POLLOUT;
    install_watch(0, 0, 6, -1, KERNEL_EPOLLIN, 0)->data = 0x61u;
    install_watch(0, 1, 7, -1, KERNEL_EPOLLOUT, 0)->data = 0x72u;
    delivery.fail_copy_index = 1;

    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == 1);
    CHECK(delivery.copy_calls == 2);
    CHECK(delivery.commit_calls == 1);
    CHECK(delivery.copied_events[0].data == 0x61u);
    CHECK(delivery.copied_events[1].data == 0x72u);
    CHECK(delivery.committed_source_indices[0] == 20);
    CHECK(g_claim_finish_calls == 2);
    CHECK(g_claim_finish_successes == 1);
    CHECK(g_claim_finish_failures == 1);
    return 0;
}

static int test_epoll_maximum_and_stale_sources(void) {
    mock_backend_t backend;
    mock_delivery_t delivery;

    reset_state(&backend);
    reset_delivery(&delivery);
    install_descriptor(
        &backend, 8, KERNEL_WAIT_SOURCE_SOCKET, 22,
        KERNEL_WAIT_REGISTRATION_EXACT);
    install_descriptor(
        &backend, 9, KERNEL_WAIT_SOURCE_SOCKET, 23,
        KERNEL_WAIT_REGISTRATION_EXACT);
    install_descriptor(
        &backend, 10, KERNEL_WAIT_SOURCE_SOCKET, 24,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[8].ready_events = KERNEL_WAIT_POLLIN;
    backend.descriptors[9].ready_events = KERNEL_WAIT_POLLIN;
    backend.descriptors[10].ready_events = KERNEL_WAIT_POLLIN;
    install_watch(0, 0, 8, -1, KERNEL_EPOLLIN, 0);
    install_watch(0, 1, 9, -1, KERNEL_EPOLLIN, 0);
    install_watch(0, 2, 10, -1, KERNEL_EPOLLIN, 0);

    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 2) == 2);
    CHECK(delivery.copy_calls == 2);
    CHECK(delivery.commit_calls == 2);
    CHECK(delivery.committed_source_indices[0] == 22);
    CHECK(delivery.committed_source_indices[1] == 23);
    CHECK(backend.resolve_watch_calls == 2);

    reset_state(&backend);
    reset_delivery(&delivery);
    install_descriptor(
        &backend, 12, KERNEL_WAIT_SOURCE_SOCKET, 25,
        KERNEL_WAIT_REGISTRATION_EXACT);
    backend.descriptors[12].ready_events = KERNEL_WAIT_POLLIN;
    install_watch(0, 0, 11, -1, KERNEL_EPOLLIN, 0);
    install_watch(0, 1, 12, -1, KERNEL_EPOLLIN, 0);
    CHECK(kernel_wait_epoll_has_ready(
              &g_mock_ops, &backend, 0) == 1);
    backend.resolve_watch_calls = 0;
    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == 1);
    CHECK(backend.resolve_watch_calls == 2);
    CHECK(delivery.copy_calls == 1);
    CHECK(delivery.commit_calls == 1);
    CHECK(delivery.copied_descriptors[0] == 12);
    CHECK(delivery.committed_source_indices[0] == 25);

    reset_state(&backend);
    reset_delivery(&delivery);
    install_watch(0, 0, 13, -1, KERNEL_EPOLLIN, 0);
    CHECK(kernel_wait_epoll_has_ready(
              &g_mock_ops, &backend, 0) == 0);
    CHECK(kernel_wait_epoll_evaluate(
              &g_mock_ops, &backend, &g_mock_delivery_ops,
              &delivery, 0, 4) == 0);
    CHECK(delivery.copy_calls == 0);
    CHECK(delivery.commit_calls == 0);
    return 0;
}

static int test_wait_array_element_address(void) {
    uint64_t address = 0;

    CHECK(kernel_wait_array_element_address(
              0x1000u, 3, 16, &address) == 0);
    CHECK(address == 0x1030u);
    CHECK(kernel_wait_array_element_address(
              0, 0, 1, &address) == 0);
    CHECK(address == 0);
    CHECK(kernel_wait_array_element_address(
              0x1000u, 0, 0, &address) == -EDGE_LINUX_EINVAL);
    CHECK(kernel_wait_array_element_address(
              0x1000u, 0, 16, 0) == -EDGE_LINUX_EINVAL);
    CHECK(kernel_wait_array_element_address(
              0, UINT64_MAX, 2, &address) == -EDGE_LINUX_EINVAL);
    CHECK(kernel_wait_array_element_address(
              UINT64_MAX - 7u, 1, 8, &address) ==
          -EDGE_LINUX_EFAULT);
    CHECK(kernel_wait_array_element_address(
              UINT64_MAX - 3u, 0, 8, &address) ==
          -EDGE_LINUX_EFAULT);
    return 0;
}

static int test_exactness_and_registration_masks(void) {
    mock_backend_t backend;
    kernel_wait_plan_t plan;

    reset_state(&backend);
    install_descriptor(
        &backend, 1, KERNEL_WAIT_SOURCE_OWNER_WAKE, 10,
        KERNEL_WAIT_REGISTRATION_FAILED);
    install_descriptor(
        &backend, 2, KERNEL_WAIT_SOURCE_SOCKET, 11,
        KERNEL_WAIT_REGISTRATION_BEST_EFFORT);
    install_descriptor(
        &backend, 3, KERNEL_WAIT_SOURCE_PIPE_READ, 12,
        KERNEL_WAIT_REGISTRATION_BEST_EFFORT);
    install_descriptor(
        &backend, 4, KERNEL_WAIT_SOURCE_INOTIFY, 13,
        KERNEL_WAIT_REGISTRATION_EXACT);
    install_descriptor(
        &backend, 5, KERNEL_WAIT_SOURCE_UNSUPPORTED, 14,
        KERNEL_WAIT_REGISTRATION_FAILED);

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 77);
    kernel_wait_plan_collect_descriptor(
        &plan, 1, KERNEL_WAIT_POLLIN);
    CHECK(plan.all_sources_exact);
    CHECK(!plan.needs_periodic_rescan);
    CHECK(backend.register_calls == 0);

    kernel_wait_plan_collect_descriptor(
        &plan, 2, KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLPRI |
                  KERNEL_WAIT_POLLWRBAND | 0x0008);
    CHECK(!plan.all_sources_exact);
    CHECK(plan.needs_periodic_rescan);
    CHECK(backend.register_calls == 1);
    CHECK(backend.last_waiter_pid == 77);
    CHECK(backend.last_registration_events ==
          (KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLPRI |
           KERNEL_WAIT_POLLWRBAND));

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 78);
    kernel_wait_plan_collect_descriptor(
        &plan, 3, KERNEL_WAIT_POLLIN | KERNEL_WAIT_POLLOUT);
    CHECK(backend.last_registration_events == KERNEL_WAIT_POLLIN);
    CHECK(!plan.all_sources_exact);

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 79);
    kernel_wait_plan_collect_descriptor(
        &plan, 4, KERNEL_WAIT_POLLIN);
    CHECK(plan.all_sources_exact);
    CHECK(!plan.needs_periodic_rescan);

    kernel_wait_plan_collect_descriptor(
        &plan, 5, KERNEL_WAIT_POLLIN);
    CHECK(!plan.all_sources_exact);
    CHECK(plan.needs_periodic_rescan);

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 80);
    kernel_wait_plan_collect_descriptor(
        &plan, 31, KERNEL_WAIT_POLLIN);
    CHECK(!plan.all_sources_exact);
    return 0;
}

static int test_timer_deadline_aggregation(void) {
    mock_backend_t backend;
    kernel_wait_plan_t plan;

    reset_state(&backend);
    install_descriptor(
        &backend, 6, KERNEL_WAIT_SOURCE_TIMERFD, 1,
        KERNEL_WAIT_REGISTRATION_FAILED);
    install_descriptor(
        &backend, 7, KERNEL_WAIT_SOURCE_TIMERFD, 2,
        KERNEL_WAIT_REGISTRATION_FAILED);
    g_test_timer_valid[1] = 1;
    g_test_timer_valid[2] = 1;
    g_test_timers[1].next_expiry_us = 90000;
    g_test_timers[2].next_expiry_us = 40000;

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 81);
    kernel_wait_plan_collect_descriptor(
        &plan, 6, KERNEL_WAIT_POLLIN);
    kernel_wait_plan_collect_descriptor(
        &plan, 7, KERNEL_WAIT_POLLRDNORM);
    CHECK(plan.all_sources_exact);
    CHECK(plan.timer_deadline_us == 40000);

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 82);
    kernel_wait_plan_collect_descriptor(
        &plan, 6, KERNEL_WAIT_POLLOUT);
    CHECK(plan.all_sources_exact);
    CHECK(plan.timer_deadline_us == 0);

    install_descriptor(
        &backend, 8, KERNEL_WAIT_SOURCE_TIMERFD, 3,
        KERNEL_WAIT_REGISTRATION_FAILED);
    kernel_wait_plan_collect_descriptor(
        &plan, 8, KERNEL_WAIT_POLLIN);
    CHECK(!plan.all_sources_exact);
    CHECK(plan.needs_periodic_rescan);
    return 0;
}

static int test_nested_epoll_policy(void) {
    mock_backend_t backend;
    kernel_wait_plan_t plan;

    reset_state(&backend);
    install_descriptor(
        &backend, 9, KERNEL_WAIT_SOURCE_TIMERFD, 4,
        KERNEL_WAIT_REGISTRATION_FAILED);
    install_descriptor(
        &backend, 10, KERNEL_WAIT_SOURCE_SOCKET, 5,
        KERNEL_WAIT_REGISTRATION_BEST_EFFORT);
    install_descriptor(
        &backend, 11, KERNEL_WAIT_SOURCE_UNSUPPORTED, 6,
        KERNEL_WAIT_REGISTRATION_FAILED);
    g_test_timer_valid[4] = 1;
    g_test_timers[4].next_expiry_us = 55000;

    /* fd 31 is deliberately unresolved: the retained target is authoritative. */
    install_watch(0, 0, 31, 1, KERNEL_EPOLLIN, 0);
    install_watch(0, 1, 30, 2, KERNEL_EPOLLOUT, 0);
    install_watch(1, 0, 9, -1, KERNEL_EPOLLIN, 0);
    install_watch(1, 1, 10, -1, KERNEL_EPOLLIN, 1);
    install_watch(2, 0, 11, -1, KERNEL_EPOLLIN, 0);

    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 83);
    kernel_wait_plan_collect_epoll(&plan, 0);
    CHECK(plan.all_sources_exact);
    CHECK(!plan.needs_periodic_rescan);
    CHECK(plan.timer_deadline_us == 55000);
    CHECK(backend.resolve_watch_calls == 1);
    CHECK(backend.register_calls == 0);

    reset_state(&backend);
    install_watch(2, 0, 30, 3, KERNEL_EPOLLIN, 0);
    install_watch(3, 0, 31, 2, KERNEL_EPOLLIN, 0);
    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 84);
    kernel_wait_plan_collect_epoll(&plan, 2);
    CHECK(!plan.all_sources_exact);
    CHECK(plan.needs_periodic_rescan);

    reset_state(&backend);
    for (int index = 0; index < 7; ++index) {
        g_test_epoll_valid[index] = 1;
        g_test_epolls[index].used = 1;
        if (index < 6)
            install_watch(
                index, 0, 20 + index, index + 1,
                KERNEL_EPOLLIN, 0);
    }
    kernel_wait_plan_init(&plan, &g_mock_ops, &backend, 85);
    kernel_wait_plan_collect_epoll(&plan, 0);
    CHECK(!plan.all_sources_exact);
    CHECK(plan.needs_periodic_rescan);
    return 0;
}

static int test_deadline_policy(void) {
    kernel_wait_plan_t plan;

    kernel_wait_plan_init(&plan, 0, 0, 0);
    CHECK(kernel_wait_deadline_from_timeout(1000, 100000) == 101000);
    CHECK(kernel_wait_deadline_from_timeout(
              UINT64_MAX - 2u, 100) == UINT64_MAX);
    CHECK(kernel_wait_plan_deadline(
              &plan, 1000, 100000, 2000) == 101000);

    plan.timer_deadline_us = 50000;
    CHECK(kernel_wait_plan_deadline(
              &plan, 1000, 100000, 2000) == 50000);

    kernel_wait_plan_mark_inexact(&plan);
    CHECK(kernel_wait_plan_deadline(
              &plan, 1000, 100000, 2000) == 18000);
    CHECK(kernel_wait_plan_deadline(
              &plan, 1000, 5000, 2000) == 6000);
    CHECK(kernel_wait_plan_deadline(
              &plan, 1000, -1, 2000) == 18000);
    CHECK(kernel_wait_bounded_rescan_deadline(
              UINT64_MAX - 2u, 100, UINT64_MAX - 5u) == UINT64_MAX);
    return 0;
}

int main(void) {
    int failures = 0;

    failures += test_snapshot_mock_contract();
    failures += test_event_masks();
    failures += test_poll_projection();
    failures += test_select_projection();
    failures += test_epoll_projection();
    failures += test_common_evaluators();
    failures += test_epoll_leaf_delivery();
    failures += test_nested_epoll_delivery();
    failures += test_epoll_first_copy_fault();
    failures += test_epoll_later_copy_fault();
    failures += test_epoll_maximum_and_stale_sources();
    failures += test_wait_array_element_address();
    failures += test_exactness_and_registration_masks();
    failures += test_timer_deadline_aggregation();
    failures += test_nested_epoll_policy();
    failures += test_deadline_policy();
    if (failures) {
        printf("wait_runtime_unit: FAIL (%d)\n", failures);
        return 1;
    }
    printf("wait_runtime_unit: PASS\n");
    return 0;
}
