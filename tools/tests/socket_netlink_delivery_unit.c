/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Netlink delivery policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/socket_runtime.h"

enum { TEST_ENDPOINTS = 4, TEST_CAPACITY = 64 };

static kernel_socket_netlink_endpoint_t g_endpoints[TEST_ENDPOINTS];
static int g_failures;
static int g_inspect_result;
static int g_bind_result;
static int g_enqueue_fail_index;
static uint32_t g_enqueue_count;
static uint32_t g_last_enqueue_index;
static kernel_socket_netlink_source_t g_last_source;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static void reset_backend(void) {
    memset(g_endpoints, 0, sizeof(g_endpoints));
    memset(&g_last_source, 0, sizeof(g_last_source));
    g_inspect_result = 0;
    g_bind_result = 0;
    g_enqueue_fail_index = -1;
    g_enqueue_count = 0;
    g_last_enqueue_index = 0;
}

uint32_t arch_socket_netlink_payload_capacity(void) {
    return TEST_CAPACITY;
}

uint32_t arch_socket_netlink_endpoint_count(void) {
    return TEST_ENDPOINTS;
}

int arch_socket_netlink_endpoint_view(
    uint32_t index, kernel_socket_netlink_endpoint_t *endpoint) {
    if (!endpoint || index >= TEST_ENDPOINTS)
        return -EDGE_LINUX_EFAULT;
    *endpoint = g_endpoints[index];
    return 0;
}

int arch_socket_netlink_sender_inspect(
    int32_t descriptor, uint32_t protocol,
    kernel_socket_netlink_source_t *source) {
    if (g_inspect_result < 0) return g_inspect_result;
    if (!source || descriptor != 7 || protocol != 15)
        return -EDGE_LINUX_EBADF;
    source->process_id = 31;
    source->user_id = 32;
    source->group_id = 33;
    source->network_namespace = 6;
    source->endpoint_identity = 2;
    source->backend_cookie = 34;
    return 0;
}

int arch_socket_netlink_sender_bind(
    kernel_socket_netlink_source_t *source) {
    if (g_bind_result < 0) return g_bind_result;
    if (!source || source->backend_cookie != 34)
        return -EDGE_LINUX_EADDRINUSE;
    source->port_id = 35;
    return 0;
}

int arch_socket_netlink_enqueue(
    uint32_t index, const void *payload, uint32_t length,
    const kernel_socket_netlink_source_t *source) {
    if (!source || (!payload && length) || index >= TEST_ENDPOINTS)
        return -EDGE_LINUX_EFAULT;
    if ((int)index == g_enqueue_fail_index)
        return -EDGE_LINUX_ENOBUFS;
    ++g_enqueue_count;
    g_last_enqueue_index = index;
    g_last_source = *source;
    return 0;
}

static void activate_endpoint(
    uint32_t index, uint32_t protocol, uint32_t port_id,
    uint32_t groups, int32_t identity) {
    g_endpoints[index].active = 1;
    g_endpoints[index].protocol = protocol;
    g_endpoints[index].port_id = port_id;
    g_endpoints[index].groups = groups;
    g_endpoints[index].network_namespace = 6;
    g_endpoints[index].identity = identity;
}

static void test_common_validation(void) {
    char payload[TEST_CAPACITY + 1] = { 0 };

    reset_backend();
    expect_true("broadcast null payload",
                kernel_socket_broadcast_netlink_datagram(
                    15, 1, 0, 1) == -EDGE_LINUX_EFAULT);
    expect_true("broadcast oversized payload",
                kernel_socket_broadcast_netlink_datagram(
                    15, 1, payload, sizeof(payload)) ==
                    -EDGE_LINUX_EMSGSIZE);
    g_inspect_result = -EDGE_LINUX_EBADF;
    expect_true("sender validation precedes payload validation",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 1, 0, 0, 1) ==
                    -EDGE_LINUX_EBADF);
}

static void test_broadcast_policy(void) {
    static const char payload[] = "event";

    reset_backend();
    expect_true("broadcast without listener succeeds",
                kernel_socket_broadcast_netlink_datagram(
                    15, 2, payload, sizeof(payload)) == 0);
    activate_endpoint(0, 14, 0, 2, 0);
    activate_endpoint(1, 15, 0, 1, 1);
    activate_endpoint(2, 15, 0, 2, 2);
    expect_true("broadcast filters protocol and group",
                kernel_socket_broadcast_netlink_datagram(
                    15, 2, payload, sizeof(payload)) == 0 &&
                g_enqueue_count == 1 && g_last_enqueue_index == 2 &&
                g_last_source.port_id == 0 &&
                g_last_source.groups == 2 &&
                g_last_source.endpoint_identity == -1);
    g_enqueue_count = 0;
    g_enqueue_fail_index = 2;
    expect_true("broadcast reports total congestion",
                kernel_socket_broadcast_netlink_datagram(
                    15, 2, payload, sizeof(payload)) ==
                    -EDGE_LINUX_ENOBUFS &&
                g_enqueue_count == 0);

    reset_backend();
    activate_endpoint(0, 15, 0, 2, 0);
    activate_endpoint(1, 15, 0, 2, 1);
    g_endpoints[1].network_namespace = 7;
    expect_true("kernel event stays in its network namespace",
                kernel_socket_broadcast_netlink_event(
                    6, 15, 2, 16, payload, sizeof(payload)) == 0 &&
                g_enqueue_count == 1 && g_last_enqueue_index == 0 &&
                g_last_source.network_namespace == 6 &&
                g_last_source.message_type == 16 &&
                g_last_source.kernel_originated);
}

static void test_sender_delivery_policy(void) {
    static const char payload[] = "request";

    reset_backend();
    activate_endpoint(0, 15, 90, 0, 0);
    activate_endpoint(1, 15, 0, 4, 1);
    activate_endpoint(2, 15, 0, 4, 2);
    activate_endpoint(3, 16, 90, 4, 3);
    g_endpoints[1].network_namespace = 7;
    expect_true("group delivery skips sender",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 0, 4, payload, sizeof(payload)) ==
                    -EDGE_LINUX_ESRCH &&
                g_enqueue_count == 0);
    g_endpoints[1].network_namespace = 6;
    expect_true("group delivery reaches same namespace",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 0, 4, payload, sizeof(payload)) == 0 &&
                g_enqueue_count == 1 && g_last_enqueue_index == 1 &&
                g_last_source.port_id == 35 &&
                g_last_source.groups == 4 &&
                g_last_source.process_id == 31);

    g_enqueue_count = 0;
    expect_true("unicast can address sender",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 90, 4, payload, sizeof(payload)) == 0 &&
                g_enqueue_count == 2);
    g_enqueue_count = 0;
    expect_true("missing unicast is refused",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 91, 0, payload, sizeof(payload)) ==
                    -EDGE_LINUX_ECONNREFUSED);
    expect_true("missing multicast reports no process",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 0, 8, payload, sizeof(payload)) ==
                    -EDGE_LINUX_ESRCH);
    g_enqueue_fail_index = 0;
    expect_true("delivery reports total congestion",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 90, 0, payload, sizeof(payload)) ==
                    -EDGE_LINUX_ENOBUFS);
    g_bind_result = -EDGE_LINUX_EADDRINUSE;
    expect_true("bind failure is preserved",
                kernel_socket_netlink_deliver_datagram(
                    7, 15, 90, 0, payload, sizeof(payload)) ==
                    -EDGE_LINUX_EADDRINUSE);
}

int main(void) {
    test_common_validation();
    test_broadcast_policy();
    test_sender_delivery_policy();
    if (g_failures) return 1;
    puts("socket_netlink_delivery_unit: PASS");
    return 0;
}
