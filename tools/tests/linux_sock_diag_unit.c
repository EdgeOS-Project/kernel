/* SPDX-License-Identifier: MPL-2.0 */
/* Unit coverage for the shared Linux inet_diag response policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_sock_diag.h"

#define TEST_AF_INET 2u
#define TEST_AF_INET6 10u
#define TEST_IPPROTO_TCP 6u
#define TEST_IPPROTO_UDP 17u
#define TEST_NLMSG_DONE 3u

typedef struct test_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} test_nlmsghdr_t;

typedef struct test_sockid {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source[4];
    uint32_t destination[4];
    uint32_t interface_index;
    uint32_t cookie[2];
} test_sockid_t;

typedef struct test_request {
    test_nlmsghdr_t header;
    uint8_t family;
    uint8_t protocol;
    uint8_t extensions;
    uint8_t padding;
    uint32_t states;
    test_sockid_t id;
} test_request_t;

typedef struct test_message {
    test_nlmsghdr_t header;
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    test_sockid_t id;
    uint32_t expires_ms;
    uint32_t receive_queue;
    uint32_t write_queue;
    uint32_t user_id;
    uint32_t inode;
} test_message_t;

typedef struct test_source {
    edge_linux_sock_diag_snapshot_t snapshots[5];
    uint32_t count;
} test_source_t;

static uint16_t test_be16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static int snapshot_at(void *context, uint32_t network_namespace,
                       uint32_t ordinal,
                       edge_linux_sock_diag_snapshot_t *snapshot) {
    test_source_t *source = (test_source_t *)context;

    if (ordinal >= source->count) return 0;
    *snapshot = source->snapshots[ordinal];
    return snapshot->cookie[1] == network_namespace;
}

static test_request_t request_for(uint8_t family, uint8_t protocol,
                                  uint32_t states) {
    test_request_t request;

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = EDGE_LINUX_SOCK_DIAG_BY_FAMILY;
    request.header.flags = 0x301u;
    request.header.sequence = 91u;
    request.family = family;
    request.protocol = protocol;
    request.states = states;
    request.id.cookie[0] = 0xffffffffu;
    request.id.cookie[1] = 0xffffffffu;
    return request;
}

static void initialize_source(test_source_t *source) {
    edge_linux_sock_diag_snapshot_t *snapshot;

    memset(source, 0, sizeof(*source));
    source->count = 5u;
    snapshot = &source->snapshots[0];
    snapshot->family = TEST_AF_INET;
    snapshot->protocol = TEST_IPPROTO_TCP;
    snapshot->state = EDGE_LINUX_TCP_LISTEN;
    snapshot->source_port = test_be16(8080u);
    snapshot->source_address[0] = 127u;
    snapshot->source_address[3] = 1u;
    snapshot->cookie[0] = 1u;
    snapshot->cookie[1] = 7u;
    snapshot->receive_queue = 2u;
    snapshot->user_id = 1000u;

    snapshot = &source->snapshots[1];
    snapshot->family = TEST_AF_INET;
    snapshot->protocol = TEST_IPPROTO_TCP;
    snapshot->state = EDGE_LINUX_TCP_ESTABLISHED;
    snapshot->source_port = test_be16(50000u);
    snapshot->destination_port = test_be16(443u);
    snapshot->source_address[0] = 10u;
    snapshot->source_address[3] = 2u;
    snapshot->destination_address[0] = 10u;
    snapshot->destination_address[3] = 3u;
    snapshot->cookie[0] = 2u;
    snapshot->cookie[1] = 7u;
    snapshot->receive_queue = 31u;
    snapshot->write_queue = 47u;
    snapshot->user_id = 1000u;

    snapshot = &source->snapshots[2];
    snapshot->family = TEST_AF_INET;
    snapshot->protocol = TEST_IPPROTO_UDP;
    snapshot->state = EDGE_LINUX_TCP_CLOSE;
    snapshot->source_port = test_be16(5353u);
    snapshot->cookie[0] = 3u;
    snapshot->cookie[1] = 7u;

    snapshot = &source->snapshots[3];
    snapshot->family = TEST_AF_INET6;
    snapshot->protocol = TEST_IPPROTO_UDP;
    snapshot->state = EDGE_LINUX_TCP_CLOSE;
    snapshot->source_port = test_be16(546u);
    snapshot->source_address[15] = 1u;
    snapshot->cookie[0] = 4u;
    snapshot->cookie[1] = 7u;

    snapshot = &source->snapshots[4];
    snapshot->family = TEST_AF_INET;
    snapshot->protocol = TEST_IPPROTO_TCP;
    snapshot->state = EDGE_LINUX_TCP_LISTEN;
    snapshot->source_port = test_be16(9090u);
    snapshot->cookie[0] = 5u;
    snapshot->cookie[1] = 8u;
}

static void test_tcp_dump_and_state_filter(void) {
    test_source_t source;
    test_request_t request = request_for(
        TEST_AF_INET, TEST_IPPROTO_TCP, 0xffffffffu);
    uint8_t response[512];
    uint32_t response_length = 0;
    test_message_t *first;
    test_message_t *second;
    test_nlmsghdr_t *done;

    initialize_source(&source);
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == sizeof(test_message_t) * 2u + 20u);
    first = (test_message_t *)response;
    second = (test_message_t *)(response + sizeof(*first));
    done = (test_nlmsghdr_t *)(response + sizeof(*first) + sizeof(*second));
    assert(first->header.type == EDGE_LINUX_SOCK_DIAG_BY_FAMILY);
    assert(first->header.sequence == 91u);
    assert(first->header.port_id == 77u);
    assert(first->state == EDGE_LINUX_TCP_LISTEN);
    assert(first->id.source_port == test_be16(8080u));
    assert(first->user_id == 1000u);
    assert(second->state == EDGE_LINUX_TCP_ESTABLISHED);
    assert(second->receive_queue == 31u);
    assert(second->write_queue == 47u);
    assert(done->type == TEST_NLMSG_DONE);
    assert(done->sequence == 91u);
    assert(done->port_id == 77u);

    request.states = 1u << EDGE_LINUX_TCP_LISTEN;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == sizeof(test_message_t) + 20u);
    assert(((test_message_t *)response)->state == EDGE_LINUX_TCP_LISTEN);

    request.states = 0xffffffffu;
    request.id.cookie[0] = 0u;
    request.id.cookie[1] = 0u;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == sizeof(test_message_t) * 2u + 20u);
}

static void test_tuple_cookie_and_namespace_filters(void) {
    test_source_t source;
    test_request_t request = request_for(
        TEST_AF_INET, TEST_IPPROTO_TCP, 0xffffffffu);
    uint8_t response[256];
    uint32_t response_length = 0;
    uint32_t requested_address = 0;

    initialize_source(&source);
    request.id.source_port = test_be16(50000u);
    request.id.destination_port = test_be16(443u);
    request.id.cookie[0] = 2u;
    request.id.cookie[1] = 7u;
    memcpy(&requested_address, source.snapshots[1].source_address, 4u);
    request.id.source[0] = requested_address;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == sizeof(test_message_t) + 20u);
    assert(((test_message_t *)response)->id.cookie[0] == 2u);

    request.id.cookie[0] = 99u;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == 20u);

    request = request_for(TEST_AF_INET, TEST_IPPROTO_TCP, 0xffffffffu);
    assert(edge_linux_sock_diag_respond(
        8u, 88u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == sizeof(test_message_t) + 20u);
    assert(((test_message_t *)response)->id.source_port == test_be16(9090u));
}

static void test_udp_ipv6_and_errors(void) {
    test_source_t source;
    test_request_t request = request_for(
        TEST_AF_INET6, TEST_IPPROTO_UDP,
        1u << EDGE_LINUX_TCP_CLOSE);
    uint8_t response[256];
    uint32_t response_length = 0;

    initialize_source(&source);
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) == 0);
    assert(response_length == sizeof(test_message_t) + 20u);
    assert(((test_message_t *)response)->family == TEST_AF_INET6);
    assert(((test_message_t *)response)->id.source_port == test_be16(546u));

    request.protocol = 1u;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) ==
        -EDGE_LINUX_EPROTONOSUPPORT);
    request.protocol = TEST_IPPROTO_UDP;
    request.family = 1u;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(response), &response_length) ==
        -EDGE_LINUX_EAFNOSUPPORT);
    request.family = TEST_AF_INET6;
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request) - 1u, snapshot_at, &source,
        source.count, response, sizeof(response), &response_length) ==
        -EDGE_LINUX_EINVAL);
    assert(edge_linux_sock_diag_respond(
        7u, 77u, &request, sizeof(request), snapshot_at, &source, source.count,
        response, sizeof(test_nlmsghdr_t), &response_length) ==
        -EDGE_LINUX_ENOBUFS);
}

static void test_lwip_state_mapping(void) {
    assert(edge_linux_sock_diag_state_from_lwip(0u) ==
           EDGE_LINUX_TCP_CLOSE);
    assert(edge_linux_sock_diag_state_from_lwip(1u) ==
           EDGE_LINUX_TCP_LISTEN);
    assert(edge_linux_sock_diag_state_from_lwip(4u) ==
           EDGE_LINUX_TCP_ESTABLISHED);
    assert(edge_linux_sock_diag_state_from_lwip(10u) ==
           EDGE_LINUX_TCP_TIME_WAIT);
    assert(edge_linux_sock_diag_state_from_lwip(255u) ==
           EDGE_LINUX_TCP_CLOSE);
}

int main(void) {
    test_tcp_dump_and_state_filter();
    test_tuple_cookie_and_namespace_filters();
    test_udp_ipv6_and_errors();
    test_lwip_state_mapping();
    puts("linux_sock_diag_unit: PASS");
    return 0;
}
