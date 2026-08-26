/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for shared Linux socket readiness policy. */

#include "kernel/socket_runtime.h"
#include "kernel/linux_errno.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SLOT_TEST_COUNT 64u
#define SLOT_TEST_THREADS 32u

static volatile uint8_t g_slot_test_claims[SLOT_TEST_COUNT];
static int32_t g_slot_test_results[SLOT_TEST_THREADS];

static void *claim_one_slot(void *argument) {
    uintptr_t thread_index = (uintptr_t)argument;

    g_slot_test_results[thread_index] = kernel_socket_slot_claim(
        g_slot_test_claims, SLOT_TEST_COUNT);
    return 0;
}

static void test_concurrent_socket_slot_claims(void) {
    pthread_t threads[SLOT_TEST_THREADS];
    uint8_t seen[SLOT_TEST_COUNT];
    uint32_t index;

    memset((void *)g_slot_test_claims, 0, sizeof(g_slot_test_claims));
    memset(g_slot_test_results, 0xff, sizeof(g_slot_test_results));
    memset(seen, 0, sizeof(seen));
    for (index = 0; index < SLOT_TEST_THREADS; ++index)
        assert(pthread_create(&threads[index], 0, claim_one_slot,
                              (void *)(uintptr_t)index) == 0);
    for (index = 0; index < SLOT_TEST_THREADS; ++index)
        assert(pthread_join(threads[index], 0) == 0);
    for (index = 0; index < SLOT_TEST_THREADS; ++index) {
        int32_t claimed = g_slot_test_results[index];

        assert(claimed >= 0 && claimed < (int32_t)SLOT_TEST_COUNT);
        assert(!seen[claimed]);
        seen[claimed] = 1u;
    }
    for (index = SLOT_TEST_THREADS; index < SLOT_TEST_COUNT; ++index)
        assert(kernel_socket_slot_claim(g_slot_test_claims,
                                        SLOT_TEST_COUNT) >= 0);
    assert(kernel_socket_slot_claim(g_slot_test_claims,
                                    SLOT_TEST_COUNT) < 0);
    kernel_socket_slot_release(g_slot_test_claims, SLOT_TEST_COUNT, 17u);
    assert(kernel_socket_slot_claim(g_slot_test_claims,
                                    SLOT_TEST_COUNT) == 17);
    kernel_socket_slot_release(g_slot_test_claims, SLOT_TEST_COUNT,
                               SLOT_TEST_COUNT);
    kernel_socket_slot_release(0, SLOT_TEST_COUNT, 0u);
}

static void snapshot_readiness(
    const kernel_socket_readiness_t *readiness,
    uint64_t *read_sequence, uint64_t *write_sequence) {
    *read_sequence = 0;
    *write_sequence = 0;
    kernel_socket_readiness_snapshot(
        readiness, read_sequence, write_sequence);
}

static void test_readiness_initialize_and_advance(void) {
    kernel_socket_readiness_t readiness;
    uint64_t read_sequence;
    uint64_t write_sequence;

    memset(&readiness, 0, sizeof(readiness));
    kernel_socket_readiness_initialize(&readiness);
    snapshot_readiness(&readiness, &read_sequence, &write_sequence);
    assert(read_sequence == 1u);
    assert(write_sequence == 1u);

    kernel_socket_readiness_advance(
        &readiness, KERNEL_SOCKET_READINESS_READ_CHANGED);
    snapshot_readiness(&readiness, &read_sequence, &write_sequence);
    assert(read_sequence == 2u);
    assert(write_sequence == 1u);

    kernel_socket_readiness_advance(
        &readiness, KERNEL_SOCKET_READINESS_WRITE_CHANGED);
    snapshot_readiness(&readiness, &read_sequence, &write_sequence);
    assert(read_sequence == 2u);
    assert(write_sequence == 2u);

    kernel_socket_readiness_advance(
        &readiness, KERNEL_SOCKET_READINESS_READ_CHANGED |
                    KERNEL_SOCKET_READINESS_WRITE_CHANGED);
    snapshot_readiness(&readiness, &read_sequence, &write_sequence);
    assert(read_sequence == 3u);
    assert(write_sequence == 3u);
}

static void test_readiness_monotonic(void) {
    kernel_socket_readiness_t readiness;
    uint64_t previous_read;
    uint64_t previous_write;
    uint64_t read_sequence;
    uint64_t write_sequence;
    uint32_t iteration;

    kernel_socket_readiness_initialize(&readiness);
    snapshot_readiness(&readiness, &previous_read, &previous_write);
    for (iteration = 0; iteration < 10000u; ++iteration) {
        uint32_t changed =
            (iteration & 1u) ?
                KERNEL_SOCKET_READINESS_READ_CHANGED :
                KERNEL_SOCKET_READINESS_WRITE_CHANGED;

        kernel_socket_readiness_advance(&readiness, changed);
        snapshot_readiness(&readiness, &read_sequence, &write_sequence);
        assert(read_sequence >= previous_read);
        assert(write_sequence >= previous_write);
        assert(read_sequence != 0u);
        assert(write_sequence != 0u);
        previous_read = read_sequence;
        previous_write = write_sequence;
    }
}

static void test_readiness_wrap_skips_zero(void) {
    kernel_socket_readiness_t readiness;
    uint64_t read_sequence;
    uint64_t write_sequence;

    kernel_socket_readiness_initialize(&readiness);
    __atomic_store_n(&readiness.read_sequence, UINT64_MAX, __ATOMIC_RELAXED);
    __atomic_store_n(&readiness.write_sequence, UINT64_MAX, __ATOMIC_RELAXED);
    kernel_socket_readiness_advance(
        &readiness, KERNEL_SOCKET_READINESS_READ_CHANGED |
                    KERNEL_SOCKET_READINESS_WRITE_CHANGED);
    snapshot_readiness(&readiness, &read_sequence, &write_sequence);
    assert(read_sequence == 1u);
    assert(write_sequence == 1u);
}

static void test_readiness_null_and_unchanged(void) {
    kernel_socket_readiness_t readiness;
    uint64_t read_sequence = UINT64_MAX;
    uint64_t write_sequence = UINT64_MAX;

    kernel_socket_readiness_initialize(0);
    kernel_socket_readiness_advance(
        0, KERNEL_SOCKET_READINESS_READ_CHANGED |
           KERNEL_SOCKET_READINESS_WRITE_CHANGED);
    kernel_socket_readiness_snapshot(
        0, &read_sequence, &write_sequence);
    assert(read_sequence == 0u);
    assert(write_sequence == 0u);

    kernel_socket_readiness_initialize(&readiness);
    kernel_socket_readiness_advance(&readiness, 0u);
    snapshot_readiness(&readiness, &read_sequence, &write_sequence);
    assert(read_sequence == 1u);
    assert(write_sequence == 1u);
}

static void test_external_readiness_observation(void) {
    kernel_socket_external_readiness_t readiness;

    memset(&readiness, 0, sizeof(readiness));
    kernel_socket_external_readiness_initialize(&readiness, 7u, 11u, 13u);
    assert(kernel_socket_external_readiness_observe(
               &readiness, 7u, 11u, 13u) == 0u);
    assert(kernel_socket_external_readiness_observe(
               &readiness, 8u, 11u, 13u) ==
           KERNEL_SOCKET_READINESS_READ_CHANGED);
    assert(kernel_socket_external_readiness_observe(
               &readiness, 8u, 12u, 14u) ==
           KERNEL_SOCKET_READINESS_READ_CHANGED);
    assert(readiness.packet_frame_sequence == 8u);
    assert(readiness.icmp_sequence == 12u);
    assert(readiness.packet_ring_sequence == 14u);

    assert(kernel_socket_external_readiness_observe(
               &readiness, 0u, 0u, 0u) == 0u);
    assert(readiness.packet_frame_sequence == 8u);
    assert(readiness.icmp_sequence == 12u);
    assert(readiness.packet_ring_sequence == 14u);

    kernel_socket_external_readiness_initialize(0, 1u, 1u, 1u);
    assert(kernel_socket_external_readiness_observe(
               0, 2u, 2u, 2u) == 0u);
}

static void test_icmp_reader_classification(void) {
    assert(kernel_socket_is_icmp_reader(
        EDGE_LINUX_AF_INET, EDGE_LINUX_SOCK_RAW,
        EDGE_LINUX_IPPROTO_ICMP));
    assert(kernel_socket_is_icmp_reader(
        EDGE_LINUX_AF_INET, EDGE_LINUX_SOCK_DGRAM,
        EDGE_LINUX_IPPROTO_ICMP));
    assert(kernel_socket_is_icmp_reader(
        EDGE_LINUX_AF_INET6, EDGE_LINUX_SOCK_RAW,
        EDGE_LINUX_IPPROTO_ICMPV6));
    assert(!kernel_socket_is_icmp_reader(
        EDGE_LINUX_AF_INET6, EDGE_LINUX_SOCK_STREAM,
        EDGE_LINUX_IPPROTO_ICMPV6));
    assert(!kernel_socket_is_icmp_reader(
        EDGE_LINUX_AF_INET, EDGE_LINUX_SOCK_RAW,
        EDGE_LINUX_IPPROTO_TCP));
    assert(!kernel_socket_is_icmp_reader(
        EDGE_LINUX_AF_UNIX, EDGE_LINUX_SOCK_DGRAM,
        EDGE_LINUX_IPPROTO_ICMP));
}

static void test_connect_timeout_policy(void) {
    kernel_socket_connect_deadline_tracker_t tracker;

    assert(kernel_socket_connect_timeout_us(0u) ==
           KERNEL_SOCKET_CONNECT_TIMEOUT_DEFAULT_US);
    assert(kernel_socket_connect_timeout_us(250000u) == 250000u);
    assert(kernel_socket_connect_deadline_us(100u, 250u) == 350u);
    assert(kernel_socket_connect_deadline_us(
               UINT64_MAX - 10u, 20u) == UINT64_MAX);
    assert(!kernel_socket_connect_timeout_expired(
        100u, 349u, 250u));
    assert(kernel_socket_connect_timeout_expired(
        100u, 350u, 250u));
    assert(!kernel_socket_connect_timeout_expired(
        100u, 99u, 250u));

    memset(&tracker, 0xff, sizeof(tracker));
    kernel_socket_connect_deadline_tracker_initialize(&tracker);
    assert(tracker.earliest_us == 0u);
    kernel_socket_connect_deadline_tracker_note(&tracker, 900u);
    kernel_socket_connect_deadline_tracker_note(&tracker, 1200u);
    assert(tracker.earliest_us == 900u);
    kernel_socket_connect_deadline_tracker_note(&tracker, 700u);
    assert(tracker.earliest_us == 700u);
    assert(!kernel_socket_connect_deadline_tracker_take_due(
        &tracker, 699u));
    assert(kernel_socket_connect_deadline_tracker_take_due(
        &tracker, 700u));
    assert(tracker.earliest_us == 0u);
    assert(!kernel_socket_connect_deadline_tracker_take_due(
        &tracker, UINT64_MAX));
    kernel_socket_connect_deadline_tracker_initialize(0);
    kernel_socket_connect_deadline_tracker_note(0, 1u);
    assert(!kernel_socket_connect_deadline_tracker_take_due(0, 1u));
}

static void test_invalid_state(void) {
    kernel_socket_poll_state_t state;

    memset(&state, 0, sizeof(state));
    assert(kernel_socket_poll_events(0) == KERNEL_SOCKET_POLL_NVAL);
    assert(kernel_socket_poll_events(&state) == KERNEL_SOCKET_POLL_NVAL);
}

static void test_data_and_shutdown(void) {
    kernel_socket_poll_state_t state;
    uint32_t events;

    memset(&state, 0, sizeof(state));
    state.valid = 1;
    state.readable = 1;
    state.writable = 1;
    events = kernel_socket_poll_events(&state);
    assert(events == (KERNEL_SOCKET_POLL_INPUT |
                      KERNEL_SOCKET_POLL_OUTPUT));

    state.read_closed = 1;
    state.hangup = 1;
    events = kernel_socket_poll_events(&state);
    assert((events & (KERNEL_SOCKET_POLL_INPUT |
                      KERNEL_SOCKET_POLL_RDHUP |
                      KERNEL_SOCKET_POLL_HANGUP)) ==
           (KERNEL_SOCKET_POLL_INPUT |
            KERNEL_SOCKET_POLL_RDHUP |
            KERNEL_SOCKET_POLL_HANGUP));
}

static void test_stream_connect_completion(void) {
    kernel_socket_poll_state_t state;
    uint32_t events;

    memset(&state, 0, sizeof(state));
    state.valid = 1;
    state.use_stream_write_policy = 1;
    state.stream.connecting = 1;
    assert(kernel_socket_poll_events(&state) == 0);

    state.stream.connecting = 0;
    state.stream.error = 111;
    events = kernel_socket_poll_events(&state);
    assert((events & (KERNEL_SOCKET_POLL_OUTPUT |
                      KERNEL_SOCKET_POLL_ERROR)) ==
           (KERNEL_SOCKET_POLL_OUTPUT |
            KERNEL_SOCKET_POLL_ERROR));

    state.stream.error = 0;
    state.stream.connected = 1;
    state.stream.send_space = 4096;
    assert(kernel_socket_poll_events(&state) ==
           KERNEL_SOCKET_POLL_OUTPUT);
}

static int64_t option_expected_value(
    kernel_socket_option_id_t option, int64_t value) {
    switch (option) {
    case KERNEL_SOCKET_OPTION_PASS_CREDENTIALS:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_OLD:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_NEW:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW:
    case KERNEL_SOCKET_OPTION_REUSE_ADDRESS:
    case KERNEL_SOCKET_OPTION_REUSE_PORT:
    case KERNEL_SOCKET_OPTION_BROADCAST:
    case KERNEL_SOCKET_OPTION_KEEPALIVE:
    case KERNEL_SOCKET_OPTION_OOB_INLINE:
    case KERNEL_SOCKET_OPTION_NO_CHECK:
    case KERNEL_SOCKET_OPTION_LINGER_ENABLED:
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_LOOP:
    case KERNEL_SOCKET_OPTION_IP_PACKET_INFO:
    case KERNEL_SOCKET_OPTION_IP_RECEIVE_ERROR:
    case KERNEL_SOCKET_OPTION_IP_RECEIVE_TTL:
    case KERNEL_SOCKET_OPTION_IP_FREEBIND:
    case KERNEL_SOCKET_OPTION_IPV6_ONLY:
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_LOOP:
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_ERROR:
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_PACKET_INFO:
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_HOP_LIMIT:
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_TRAFFIC_CLASS:
    case KERNEL_SOCKET_OPTION_TCP_NODELAY:
    case KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED:
        return value != 0;
    case KERNEL_SOCKET_OPTION_IP_TOS:
    case KERNEL_SOCKET_OPTION_IP_TTL:
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_TTL:
        return (uint8_t)value;
    case KERNEL_SOCKET_OPTION_SEND_BUFFER:
    case KERNEL_SOCKET_OPTION_RECEIVE_BUFFER:
    case KERNEL_SOCKET_OPTION_SEND_LOW_WATER:
    case KERNEL_SOCKET_OPTION_RECEIVE_LOW_WATER:
        return (uint32_t)value;
    default:
        return value;
    }
}

static uint32_t option_expected_effects(
    kernel_socket_option_id_t option) {
    switch (option) {
    case KERNEL_SOCKET_OPTION_PASS_CREDENTIALS:
        return KERNEL_SOCKET_OPTION_EFFECT_PASS_CREDENTIALS;
    case KERNEL_SOCKET_OPTION_REUSE_ADDRESS:
    case KERNEL_SOCKET_OPTION_KEEPALIVE:
    case KERNEL_SOCKET_OPTION_IP_TOS:
    case KERNEL_SOCKET_OPTION_IP_TTL:
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_TTL:
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_LOOP:
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_HOPS:
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_LOOP:
    case KERNEL_SOCKET_OPTION_TCP_NODELAY:
    case KERNEL_SOCKET_OPTION_TCP_KEEP_IDLE:
    case KERNEL_SOCKET_OPTION_TCP_KEEP_INTERVAL:
    case KERNEL_SOCKET_OPTION_TCP_KEEP_COUNT:
    case KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED:
        return KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
    default:
        return KERNEL_SOCKET_OPTION_EFFECT_NONE;
    }
}

static void test_option_state_policy(void) {
    kernel_socket_option_state_t state;
    int64_t observed;

    kernel_socket_option_state_initialize(&state, 4096u);
    assert(state.send_buffer == 4096u);
    assert(state.receive_buffer == 4096u);
    assert(state.send_low_water == 1u);
    assert(state.receive_low_water == 1u);
    assert(state.ip_ttl == 64u);
    assert(state.ip_multicast_ttl == 1u);
    assert(state.ip_multicast_loop == 1u);
    assert(state.ipv6_multicast_hops == 1);
    assert(state.ipv6_multicast_loop == 1u);
    assert(state.tcp_keep_idle == 7200);
    assert(state.tcp_keep_interval == 75);
    assert(state.tcp_keep_count == 9);
    assert(state.ip_multicast_interface_address == 0u);
    assert(state.ip_multicast_interface_index == 0u);
    assert(state.ipv6_multicast_interface_index == 0u);
    assert(kernel_socket_icmp6_filter_allows(&state, 128u));
    assert(kernel_socket_icmp6_filter_allows(&state, 129u));
    state.icmp6_filter[4] = 1u << 1;
    assert(kernel_socket_icmp6_filter_allows(&state, 128u));
    assert(!kernel_socket_icmp6_filter_allows(&state, 129u));
    assert(!kernel_socket_icmp6_filter_allows(0, 129u));

    for (int option = KERNEL_SOCKET_OPTION_PASS_CREDENTIALS;
         option <= KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED; ++option) {
        uint32_t effects = UINT32_MAX;
        int64_t selected = (int64_t)option * 17 + 3;

        kernel_socket_option_state_initialize(&state, 4096u);
        assert(kernel_socket_option_state_set_integer(
                   &state, (kernel_socket_option_id_t)option,
                   selected, &effects) == 0);
        assert(effects == option_expected_effects(
                              (kernel_socket_option_id_t)option));
        observed = INT64_MIN;
        assert(kernel_socket_option_state_get_integer(
                   &state, (kernel_socket_option_id_t)option,
                   &observed) == 0);
        assert(observed == option_expected_value(
                               (kernel_socket_option_id_t)option,
                               selected));
    }

    state.timestamp_mode = KERNEL_SOCKET_TIMESTAMP_NS_NEW;
    assert(kernel_socket_option_state_set_integer(
               &state, KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD, 0, 0) == 0);
    assert(state.timestamp_mode == KERNEL_SOCKET_TIMESTAMP_NS_NEW);
    assert(kernel_socket_option_state_set_integer(
               &state, KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW, 0, 0) == 0);
    assert(state.timestamp_mode == KERNEL_SOCKET_TIMESTAMP_DISABLED);
    assert(kernel_socket_option_state_set_integer(
               &state, (kernel_socket_option_id_t)0, 1, 0) < 0);
    assert(kernel_socket_option_state_get_integer(
               &state, (kernel_socket_option_id_t)0, &observed) < 0);
    assert(kernel_socket_option_state_set_integer(
               0, KERNEL_SOCKET_OPTION_KEEPALIVE, 1, 0) < 0);
    assert(kernel_socket_option_state_get_integer(
               0, KERNEL_SOCKET_OPTION_KEEPALIVE, &observed) < 0);

    kernel_socket_option_state_initialize(&state, 4096u);
    assert(kernel_socket_option_state_set_integer(
               &state, KERNEL_SOCKET_OPTION_FILTER_LOCKED, 1, 0) == 0);
    assert(kernel_socket_option_state_get_integer(
               &state, KERNEL_SOCKET_OPTION_FILTER_LOCKED, &observed) == 0);
    assert(observed == 1);
    assert(kernel_socket_option_state_set_integer(
               &state, KERNEL_SOCKET_OPTION_FILTER_LOCKED, 1, 0) == 0);
    assert(kernel_socket_option_state_set_integer(
               &state, KERNEL_SOCKET_OPTION_FILTER_LOCKED, 0, 0) ==
           -EDGE_LINUX_EPERM);
}

static void test_unix_socket_poll_policy(void) {
    kernel_unix_socket_poll_state_t state;
    kernel_unix_socket_poll_result_t result;

    memset(&result, 0xff, sizeof(result));
    kernel_unix_socket_poll_policy(0, &result);
    assert(!result.read_closed);
    assert(!result.hangup);
    assert(!result.writable);
    assert(kernel_socket_type_has_peer_eof(EDGE_LINUX_SOCK_STREAM));
    assert(kernel_socket_type_has_peer_eof(EDGE_LINUX_SOCK_SEQPACKET));
    assert(!kernel_socket_type_has_peer_eof(EDGE_LINUX_SOCK_DGRAM));
    assert(kernel_unix_socket_missing_peer_error(
               EDGE_LINUX_SOCK_STREAM, 0) == -EDGE_LINUX_ENOTCONN);
    assert(kernel_unix_socket_missing_peer_error(
               EDGE_LINUX_SOCK_STREAM, 1) == -EDGE_LINUX_EPIPE);
    assert(kernel_unix_socket_missing_peer_error(
               EDGE_LINUX_SOCK_DGRAM, 1) == -EDGE_LINUX_ECONNREFUSED);

    memset(&state, 0, sizeof(state));
    state.type = EDGE_LINUX_SOCK_STREAM;
    state.connected = 1;
    state.peer_valid = 1;
    state.peer_receive_capacity = 4096u;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(!result.read_closed);
    assert(!result.hangup);
    assert(result.writable);

    state.peer_receive_used = state.peer_receive_capacity;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(!result.writable);
    state.peer_shutdown_read = 1;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(result.writable);

    state.peer_shutdown_read = 0;
    state.peer_eof = 1;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(result.read_closed);
    assert(!result.hangup);
    assert(!result.writable);
    state.peer_valid = 0;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(result.read_closed);
    assert(result.hangup);
    assert(result.writable);

    memset(&state, 0, sizeof(state));
    state.type = EDGE_LINUX_SOCK_DGRAM;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(!result.read_closed);
    assert(!result.hangup);
    assert(result.writable);

    state.connected = 1;
    state.peer_valid = 1;
    state.peer_receive_capacity = 4096u;
    state.peer_record_capacity = 16u;
    state.peer_record_count = 16u;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(!result.writable);
    state.peer_shutdown_read = 1;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(!result.writable);
    state.peer_record_count = 0;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(result.writable);
    assert(kernel_unix_socket_record_peer_shutdown_error(
               EDGE_LINUX_SOCK_DGRAM, 1, 1, 1, 0, 16, 16) == 0);
    assert(kernel_unix_socket_record_peer_shutdown_error(
               EDGE_LINUX_SOCK_DGRAM, 1, 1, 1, 4096, 0, 16) ==
           -EDGE_LINUX_EPIPE);
    assert(kernel_unix_socket_record_peer_shutdown_error(
               EDGE_LINUX_SOCK_DGRAM, 0, 1, 1, 4096, 0, 16) ==
           -EDGE_LINUX_ECONNREFUSED);

    memset(&state, 0, sizeof(state));
    state.type = EDGE_LINUX_SOCK_SEQPACKET;
    state.connected = 1;
    state.shutdown_read = 1;
    state.shutdown_write = 1;
    kernel_unix_socket_poll_policy(&state, &result);
    assert(result.read_closed);
    assert(result.hangup);
    assert(result.writable);
}

static void test_unix_socket_credential_pid(void) {
    assert(kernel_unix_socket_credential_pid(682, 678) == 678);
    assert(kernel_unix_socket_credential_pid(678, 678) == 678);
    assert(kernel_unix_socket_credential_pid(42, 0) == 42);
    assert(kernel_unix_socket_credential_pid(42, -1) == 42);
}

static void test_socket_option_utility_policy(void) {
    static const uint8_t loopback[4] = {127u, 0u, 0u, 11u};
    static const uint8_t other[4] = {127u, 0u, 0u, 12u};
    char device[8];
    int32_t interface_index;
    int32_t stored_error;
    int32_t error;
    uint32_t length;

    interface_index = -1;
    assert(kernel_socket_bound_device_parse(
               "", 0, &interface_index) == 0);
    assert(interface_index == 0);
    assert(kernel_socket_bound_device_parse(
               "lo", 2, &interface_index) == 0);
    assert(interface_index == 1);
    assert(kernel_socket_bound_device_parse(
               "eth0", 4, &interface_index) == 0);
    assert(interface_index == 2);
    assert(kernel_socket_bound_device_parse(
               "missing0", 8, &interface_index) == -EDGE_LINUX_ENODEV);

    memset(device, 0xcc, sizeof(device));
    assert(kernel_socket_bound_device_format(
               1, device, sizeof(device), &length) == 0);
    assert(length == 3u);
    assert(memcmp(device, "lo", 3u) == 0);
    assert(kernel_socket_bound_device_format(
               2, device, 4u, &length) < 0);
    assert(kernel_socket_bound_device_format(
               2, device, sizeof(device), &length) == 0);
    assert(length == 5u);
    assert(memcmp(device, "eth0", 5u) == 0);
    assert(kernel_socket_bound_device_format(
               0, device, 0, &length) == 0);
    assert(length == 0u);

    stored_error = EDGE_LINUX_ECONNREFUSED;
    error = 0;
    assert(kernel_socket_error_take(&stored_error, &error) == 0);
    assert(error == EDGE_LINUX_ECONNREFUSED);
    assert(stored_error == 0);
    assert(kernel_socket_error_take(0, &error) < 0);
    assert(kernel_socket_error_take(&stored_error, 0) < 0);
    assert(kernel_socket_mtu_normalize(0) == 1500);
    assert(kernel_socket_mtu_normalize(9000) == 9000);

    assert(!kernel_socket_udp_local_refusal_policy(0, 9000, 1, 0));
    assert(!kernel_socket_udp_local_refusal_policy(1, 0, 1, 0));
    assert(!kernel_socket_udp_local_refusal_policy(1, 9000, 0, 0));
    assert(!kernel_socket_udp_local_refusal_policy(1, 9000, 1, 1));
    assert(kernel_socket_udp_local_refusal_policy(1, 9000, 1, 0));

    assert(kernel_socket_udp_local_delivery_match(
        7u, 7u, 53u, 53u, loopback, loopback, sizeof(loopback), 0));
    assert(kernel_socket_udp_local_delivery_match(
        7u, 7u, 53u, 53u, loopback, other, sizeof(loopback), 1));
    assert(!kernel_socket_udp_local_delivery_match(
        7u, 8u, 53u, 53u, loopback, loopback, sizeof(loopback), 0));
    assert(!kernel_socket_udp_local_delivery_match(
        7u, 7u, 53u, 54u, loopback, loopback, sizeof(loopback), 0));
    assert(!kernel_socket_udp_local_delivery_match(
        7u, 7u, 53u, 53u, loopback, other, sizeof(loopback), 0));
}

int main(void) {
    test_concurrent_socket_slot_claims();
    test_readiness_initialize_and_advance();
    test_readiness_monotonic();
    test_readiness_wrap_skips_zero();
    test_readiness_null_and_unchanged();
    test_external_readiness_observation();
    test_icmp_reader_classification();
    test_connect_timeout_policy();
    test_invalid_state();
    test_data_and_shutdown();
    test_stream_connect_completion();
    test_option_state_policy();
    test_unix_socket_poll_policy();
    test_unix_socket_credential_pid();
    test_socket_option_utility_policy();
    puts("socket_poll_runtime_unit: PASS");
    return 0;
}
