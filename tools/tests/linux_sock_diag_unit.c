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
#define TEST_NLA_F_NESTED 0x8000u
#define TEST_INET_DIAG_REQ_SK_BPF_STORAGES 2u
#define TEST_INET_DIAG_SK_BPF_STORAGES 20u
#define TEST_SK_DIAG_BPF_STORAGE_REQ_MAP_FD 1u
#define TEST_SK_DIAG_BPF_STORAGE 1u
#define TEST_SK_DIAG_BPF_STORAGE_MAP_ID 2u
#define TEST_SK_DIAG_BPF_STORAGE_MAP_VALUE 3u

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

typedef struct test_nlattr {
    uint16_t length;
    uint16_t type;
} test_nlattr_t;

typedef struct test_source {
    edge_linux_sock_diag_snapshot_t snapshots[5];
    uint32_t count;
} test_source_t;

typedef struct test_bpf_source {
    edge_linux_sock_diag_bpf_map_t maps[2];
    uint64_t owners[2];
    uint32_t values[2];
    uint32_t retained;
    uint32_t released;
} test_bpf_source_t;

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

static int test_bpf_map_from_descriptor(
    void *context, int32_t descriptor,
    edge_linux_sock_diag_bpf_map_t *map) {
    test_bpf_source_t *source = (test_bpf_source_t *)context;
    uint32_t index;

    if (descriptor < 10 || descriptor > 11)
        return -EDGE_LINUX_EBADF;
    index = (uint32_t)(descriptor - 10);
    *map = source->maps[index];
    ++source->retained;
    return 0;
}

static int test_bpf_next_map(
    void *context, uint32_t *cursor,
    edge_linux_sock_diag_bpf_map_t *map) {
    test_bpf_source_t *source = (test_bpf_source_t *)context;

    if (*cursor >= 2u) return -EDGE_LINUX_ENOENT;
    *map = source->maps[*cursor];
    ++*cursor;
    ++source->retained;
    return 0;
}

static int test_bpf_exists(
    void *context, const edge_linux_sock_diag_bpf_map_t *map,
    uint64_t socket_identity) {
    test_bpf_source_t *source = (test_bpf_source_t *)context;
    uint32_t index = (uint32_t)map->object_id - 1u;

    return index < 2u && source->owners[index] == socket_identity ?
        0 : -EDGE_LINUX_ENOENT;
}

static int test_bpf_lookup(
    void *context, const edge_linux_sock_diag_bpf_map_t *map,
    uint64_t socket_identity, void *value) {
    test_bpf_source_t *source = (test_bpf_source_t *)context;
    uint32_t index = (uint32_t)map->object_id - 1u;

    if (index >= 2u || source->owners[index] != socket_identity)
        return -EDGE_LINUX_ENOENT;
    memcpy(value, &source->values[index], sizeof(source->values[index]));
    return 0;
}

static void test_bpf_release(
    void *context, const edge_linux_sock_diag_bpf_map_t *map) {
    test_bpf_source_t *source = (test_bpf_source_t *)context;

    (void)map;
    ++source->released;
}

static edge_linux_sock_diag_bpf_ops_t test_bpf_ops_for(
    test_bpf_source_t *source) {
    edge_linux_sock_diag_bpf_ops_t ops = {
        .map_from_descriptor = test_bpf_map_from_descriptor,
        .next_map = test_bpf_next_map,
        .lookup = test_bpf_lookup,
        .exists = test_bpf_exists,
        .release = test_bpf_release,
        .context = source,
    };

    return ops;
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
    snapshot->socket_identity = 0x1001u;

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

static const test_nlattr_t *test_find_attribute(
    const uint8_t *data, uint32_t length, uint16_t type) {
    uint32_t offset = 0u;

    while (offset + sizeof(test_nlattr_t) <= length) {
        const test_nlattr_t *attribute =
            (const test_nlattr_t *)(data + offset);
        uint32_t padded;

        if (attribute->length < sizeof(*attribute) ||
            attribute->length > length - offset)
            return 0;
        if ((attribute->type & 0x3fffu) == type) return attribute;
        padded = (attribute->length + 3u) & ~3u;
        if (padded > length - offset) return 0;
        offset += padded;
    }
    return 0;
}

static void test_bpf_socket_storage_export(void) {
    test_source_t source;
    test_bpf_source_t bpf_source;
    edge_linux_sock_diag_bpf_ops_t ops;
    uint8_t request_data[sizeof(test_request_t) + 20u];
    uint8_t response[512];
    test_request_t *request = (test_request_t *)request_data;
    test_nlattr_t *outer;
    test_nlattr_t *map_fd;
    const test_nlattr_t *storage_reply;
    const test_nlattr_t *entry;
    const test_nlattr_t *map_id;
    const test_nlattr_t *map_value;
    uint32_t response_length = 0u;
    uint32_t value = 0u;
    uint32_t id = 0u;

    initialize_source(&source);
    memset(&bpf_source, 0, sizeof(bpf_source));
    bpf_source.maps[0].object_id = 1;
    bpf_source.maps[0].user_id = 101u;
    bpf_source.maps[0].value_size = sizeof(uint32_t);
    bpf_source.maps[1].object_id = 2;
    bpf_source.maps[1].user_id = 102u;
    bpf_source.maps[1].value_size = sizeof(uint32_t);
    bpf_source.owners[0] = source.snapshots[0].socket_identity;
    bpf_source.owners[1] = source.snapshots[1].socket_identity;
    bpf_source.values[0] = 0x11223344u;
    bpf_source.values[1] = 0x55667788u;
    ops = test_bpf_ops_for(&bpf_source);

    memset(request_data, 0, sizeof(request_data));
    *request = request_for(
        TEST_AF_INET, TEST_IPPROTO_TCP,
        1u << EDGE_LINUX_TCP_LISTEN);
    outer = (test_nlattr_t *)(request_data + sizeof(*request));
    outer->length = sizeof(*outer) + sizeof(*map_fd) + sizeof(int32_t);
    outer->type = TEST_INET_DIAG_REQ_SK_BPF_STORAGES |
                  TEST_NLA_F_NESTED;
    map_fd = (test_nlattr_t *)(request_data + sizeof(*request) +
                              sizeof(*outer));
    map_fd->length = sizeof(*map_fd) + sizeof(int32_t);
    map_fd->type = TEST_SK_DIAG_BPF_STORAGE_REQ_MAP_FD;
    *(int32_t *)(request_data + sizeof(*request) + sizeof(*outer) +
                sizeof(*map_fd)) = 10;
    request->header.length = sizeof(*request) + outer->length;

    assert(edge_linux_sock_diag_respond_with_bpf_storage(
        7u, 77u, request_data, request->header.length,
        snapshot_at, &source, source.count,
        response, sizeof(response), &response_length, 1, &ops) == 0);
    assert(bpf_source.retained == 1u);
    assert(bpf_source.released == 1u);
    assert(((test_message_t *)response)->header.length >
           sizeof(test_message_t));
    storage_reply = test_find_attribute(
        response + sizeof(test_message_t),
        ((test_message_t *)response)->header.length -
            sizeof(test_message_t),
        TEST_INET_DIAG_SK_BPF_STORAGES);
    assert(storage_reply != 0);
    assert((storage_reply->type & TEST_NLA_F_NESTED) != 0u);
    entry = test_find_attribute(
        (const uint8_t *)storage_reply + sizeof(*storage_reply),
        storage_reply->length - sizeof(*storage_reply),
        TEST_SK_DIAG_BPF_STORAGE);
    assert(entry != 0);
    map_id = test_find_attribute(
        (const uint8_t *)entry + sizeof(*entry),
        entry->length - sizeof(*entry),
        TEST_SK_DIAG_BPF_STORAGE_MAP_ID);
    map_value = test_find_attribute(
        (const uint8_t *)entry + sizeof(*entry),
        entry->length - sizeof(*entry),
        TEST_SK_DIAG_BPF_STORAGE_MAP_VALUE);
    assert(map_id != 0 && map_value != 0);
    memcpy(&id, (const uint8_t *)map_id + sizeof(*map_id), sizeof(id));
    memcpy(&value, (const uint8_t *)map_value + sizeof(*map_value),
           sizeof(value));
    assert(id == 101u);
    assert(value == 0x11223344u);

    bpf_source.retained = 0u;
    bpf_source.released = 0u;
    outer->length = sizeof(*outer);
    request->header.length = sizeof(*request) + outer->length;
    assert(edge_linux_sock_diag_respond_with_bpf_storage(
        7u, 77u, request_data, request->header.length,
        snapshot_at, &source, source.count,
        response, sizeof(response), &response_length, 1, &ops) == 0);
    assert(bpf_source.retained == 2u);
    assert(bpf_source.released == 2u);
    assert(edge_linux_sock_diag_respond_with_bpf_storage(
        7u, 77u, request_data, request->header.length,
        snapshot_at, &source, source.count,
        response, sizeof(response), &response_length, 0, &ops) ==
        -EDGE_LINUX_EPERM);
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
    test_bpf_socket_storage_export();
    test_lwip_state_mapping();
    puts("linux_sock_diag_unit: PASS");
    return 0;
}
