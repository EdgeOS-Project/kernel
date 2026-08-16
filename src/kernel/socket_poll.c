/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux socket readiness policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/socket_runtime.h"

int32_t kernel_socket_slot_claim(volatile uint8_t *claims,
                                 uint32_t claim_count) {
    uint32_t index;

    if (!claims) return -1;
    for (index = 0; index < claim_count; ++index) {
        uint8_t expected = 0u;

        if (__atomic_compare_exchange_n(&claims[index], &expected, 1u, 0,
                                        __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
            return (int32_t)index;
    }
    return -1;
}

void kernel_socket_slot_release(volatile uint8_t *claims,
                                uint32_t claim_count, uint32_t index) {
    if (!claims || index >= claim_count) return;
    __atomic_store_n(&claims[index], 0u, __ATOMIC_RELEASE);
}

static void kernel_socket_readiness_advance_one(uint64_t *sequence) {
    uint64_t current;

    current = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    for (;;) {
        uint64_t next = current + 1u;

        if (!next) next = 1u;
        if (__atomic_compare_exchange_n(sequence, &current, next, 0,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED))
            return;
    }
}

void kernel_socket_readiness_initialize(
    kernel_socket_readiness_t *readiness) {
    if (!readiness) return;
    __atomic_store_n(&readiness->read_sequence, 1u, __ATOMIC_RELEASE);
    __atomic_store_n(&readiness->write_sequence, 1u, __ATOMIC_RELEASE);
}

void kernel_socket_readiness_advance(
    kernel_socket_readiness_t *readiness, uint32_t changed) {
    if (!readiness) return;
    if (changed & KERNEL_SOCKET_READINESS_READ_CHANGED)
        kernel_socket_readiness_advance_one(&readiness->read_sequence);
    if (changed & KERNEL_SOCKET_READINESS_WRITE_CHANGED)
        kernel_socket_readiness_advance_one(&readiness->write_sequence);
}

void kernel_socket_readiness_snapshot(
    const kernel_socket_readiness_t *readiness,
    uint64_t *read_sequence, uint64_t *write_sequence) {
    if (read_sequence)
        *read_sequence = readiness ?
            __atomic_load_n(&readiness->read_sequence, __ATOMIC_ACQUIRE) : 0u;
    if (write_sequence)
        *write_sequence = readiness ?
            __atomic_load_n(&readiness->write_sequence, __ATOMIC_ACQUIRE) : 0u;
}

static uint32_t kernel_socket_external_sequence_observe(
    uint64_t *seen, uint64_t current) {
    uint64_t previous;

    if (!seen || !current) return 0u;
    previous = __atomic_load_n(seen, __ATOMIC_ACQUIRE);
    if (previous == current) return 0u;
    /*
     * More than one CPU may pump a NO_SYS network backend. Only the observer
     * that advances the stored generation publishes the socket edge. If
     * another observer wins the race, its publication covers the same
     * currently readable producer queue.
     */
    if (!__atomic_compare_exchange_n(seen, &previous, current, 0,
                                     __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return 0u;
    return KERNEL_SOCKET_READINESS_READ_CHANGED;
}

void kernel_socket_external_readiness_initialize(
    kernel_socket_external_readiness_t *readiness,
    uint64_t packet_frame_sequence, uint64_t icmp_sequence,
    uint64_t packet_ring_sequence) {
    if (!readiness) return;
    __atomic_store_n(&readiness->packet_frame_sequence,
                     packet_frame_sequence, __ATOMIC_RELEASE);
    __atomic_store_n(&readiness->icmp_sequence,
                     icmp_sequence, __ATOMIC_RELEASE);
    __atomic_store_n(&readiness->packet_ring_sequence,
                     packet_ring_sequence, __ATOMIC_RELEASE);
}

uint32_t kernel_socket_external_readiness_observe(
    kernel_socket_external_readiness_t *readiness,
    uint64_t packet_frame_sequence, uint64_t icmp_sequence,
    uint64_t packet_ring_sequence) {
    uint32_t changed = 0u;

    if (!readiness) return 0u;
    changed |= kernel_socket_external_sequence_observe(
        &readiness->packet_frame_sequence, packet_frame_sequence);
    changed |= kernel_socket_external_sequence_observe(
        &readiness->icmp_sequence, icmp_sequence);
    changed |= kernel_socket_external_sequence_observe(
        &readiness->packet_ring_sequence, packet_ring_sequence);
    return changed;
}

int kernel_socket_is_icmp_reader(
    uint32_t domain, uint32_t type, uint32_t protocol) {
    if (type != EDGE_LINUX_SOCK_RAW &&
        type != EDGE_LINUX_SOCK_DGRAM)
        return 0;
    if (domain == EDGE_LINUX_AF_INET)
        return protocol == EDGE_LINUX_IPPROTO_ICMP;
    if (domain == EDGE_LINUX_AF_INET6)
        return protocol == EDGE_LINUX_IPPROTO_ICMPV6;
    return 0;
}

uint64_t kernel_socket_connect_timeout_us(
    uint64_t configured_receive_timeout_us) {
    return configured_receive_timeout_us ?
        configured_receive_timeout_us :
        KERNEL_SOCKET_CONNECT_TIMEOUT_DEFAULT_US;
}

uint64_t kernel_socket_connect_deadline_us(
    uint64_t started_us, uint64_t configured_receive_timeout_us) {
    uint64_t timeout_us = kernel_socket_connect_timeout_us(
        configured_receive_timeout_us);

    return started_us > UINT64_MAX - timeout_us ?
        UINT64_MAX : started_us + timeout_us;
}

int kernel_socket_connect_timeout_expired(
    uint64_t started_us, uint64_t now_us,
    uint64_t configured_receive_timeout_us) {
    uint64_t timeout_us = kernel_socket_connect_timeout_us(
        configured_receive_timeout_us);

    return now_us >= started_us &&
           now_us - started_us >= timeout_us;
}

void kernel_socket_connect_deadline_tracker_initialize(
    kernel_socket_connect_deadline_tracker_t *tracker) {
    if (!tracker) return;
    __atomic_store_n(&tracker->earliest_us, 0u, __ATOMIC_RELEASE);
}

void kernel_socket_connect_deadline_tracker_note(
    kernel_socket_connect_deadline_tracker_t *tracker,
    uint64_t deadline_us) {
    uint64_t current;

    if (!tracker || !deadline_us) return;
    current = __atomic_load_n(
        &tracker->earliest_us, __ATOMIC_ACQUIRE);
    while (!current || deadline_us < current) {
        if (__atomic_compare_exchange_n(
                &tracker->earliest_us, &current, deadline_us, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
    }
}

int kernel_socket_connect_deadline_tracker_take_due(
    kernel_socket_connect_deadline_tracker_t *tracker,
    uint64_t now_us) {
    uint64_t deadline;

    if (!tracker) return 0;
    deadline = __atomic_load_n(
        &tracker->earliest_us, __ATOMIC_ACQUIRE);
    if (!deadline || now_us < deadline) return 0;
    return __atomic_compare_exchange_n(
        &tracker->earliest_us, &deadline, 0u, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

uint32_t kernel_socket_stream_write_events(
    const kernel_socket_stream_state_t *state) {
    if (!state || state->connecting) return 0;
    /*
     * Linux reports a completed asynchronous connect as writable even when it
     * failed.  POLLERR remains set until SO_ERROR consumes the stored error.
     * Omitting POLLOUT makes connect-oriented event loops wait forever.
     */
    if (state->error)
        return KERNEL_SOCKET_POLL_OUTPUT | KERNEL_SOCKET_POLL_ERROR;
    if (state->shutdown_write)
        return KERNEL_SOCKET_POLL_OUTPUT;
    if (state->connected && state->send_space)
        return KERNEL_SOCKET_POLL_OUTPUT;
    return 0;
}

uint32_t kernel_socket_poll_events(
    const kernel_socket_poll_state_t *state) {
    uint32_t events = 0;

    if (!state || !state->valid) return KERNEL_SOCKET_POLL_NVAL;
    if (state->readable || state->read_closed)
        events |= KERNEL_SOCKET_POLL_INPUT;
    if (state->writable)
        events |= KERNEL_SOCKET_POLL_OUTPUT;
    if (state->read_closed)
        events |= KERNEL_SOCKET_POLL_RDHUP;
    if (state->hangup)
        events |= KERNEL_SOCKET_POLL_HANGUP;
    if (state->stream.error)
        events |= KERNEL_SOCKET_POLL_ERROR;
    if (state->use_stream_write_policy)
        events |= kernel_socket_stream_write_events(&state->stream);
    return events;
}
