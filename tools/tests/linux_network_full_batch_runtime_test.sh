#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared EdgeOS Linux networking acceptance batch.

set -u

if [ -c /dev/ttyS0 ]; then
    exec >/dev/ttyS0 2>&1
elif [ -c /dev/ttyAMA0 ]; then
    exec >/dev/ttyAMA0 2>&1
fi

test_directory=${EDGEOS_NETWORK_TEST_DIRECTORY:-/root}

"$test_directory/linux_tuntap_runtime_test.sh"
tuntap_status=$?
echo "EDGEOS_LINUX_TUNTAP_BATCH_RC=$tuntap_status"

"$test_directory/linux_virtual_link_runtime_test.sh"
virtual_link_status=$?
echo "EDGEOS_LINUX_VIRTUAL_LINK_BATCH_RC=$virtual_link_status"

"$test_directory/linux_network_batch_runtime_test.sh"
network_status=$?
echo "EDGEOS_LINUX_NETWORK_BATCH_RC=$network_status"

"$test_directory/linux_policy_routing_runtime_test.sh"
policy_status=$?
echo "EDGEOS_LINUX_POLICY_ROUTING_BATCH_RC=$policy_status"

"$test_directory/linux_ipv6_runtime_test.sh"
ipv6_status=$?
echo "EDGEOS_LINUX_IPV6_BATCH_RC=$ipv6_status"

"$test_directory/linux_ipv6_router_runtime_test.sh"
ipv6_router_status=$?
echo "EDGEOS_LINUX_IPV6_ROUTER_BATCH_RC=$ipv6_router_status"

"$test_directory/docker_ipv6_network_runtime_test.sh"
docker_ipv6_status=$?
echo "EDGEOS_DOCKER_IPV6_BATCH_RC=$docker_ipv6_status"

if [ "$tuntap_status" -ne 0 ] || [ "$virtual_link_status" -ne 0 ] ||
   [ "$network_status" -ne 0 ] ||
   [ "$policy_status" -ne 0 ] || [ "$ipv6_status" -ne 0 ] ||
   [ "$ipv6_router_status" -ne 0 ] ||
   [ "$docker_ipv6_status" -ne 0 ]; then
    echo "EDGEOS_LINUX_NETWORK_FULL_BATCH_FAIL"
    exit 1
fi

echo "EDGEOS_LINUX_NETWORK_FULL_BATCH_PASS"
