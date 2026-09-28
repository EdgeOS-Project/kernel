#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS boot-time runner for the Linux network runtime batch.

exec >/dev/ttyS0 2>&1

/root/linux-tuntap-runtime-test.sh
tuntap_status=$?
echo "EDGEOS_LINUX_TUNTAP_BATCH_RC=$tuntap_status"

/root/linux-virtual-link-runtime-test.sh
virtual_link_status=$?
echo "EDGEOS_LINUX_VIRTUAL_LINK_BATCH_RC=$virtual_link_status"

/root/linux-network-batch-runtime-test.sh
network_status=$?
echo "EDGEOS_LINUX_NETWORK_BATCH_RC=$network_status"

/root/linux_policy_routing_runtime_test.sh
policy_status=$?
echo "EDGEOS_LINUX_POLICY_ROUTING_BATCH_RC=$policy_status"

/root/linux-ipv6-runtime-test.sh
ipv6_status=$?
echo "EDGEOS_LINUX_IPV6_BATCH_RC=$ipv6_status"

if [ "$tuntap_status" -ne 0 ] || [ "$virtual_link_status" -ne 0 ] ||
   [ "$network_status" -ne 0 ] || [ "$policy_status" -ne 0 ] ||
   [ "$ipv6_status" -ne 0 ]; then
    echo "EDGEOS_LINUX_NETWORK_FULL_BATCH_FAIL"
    exit 1
fi

echo "EDGEOS_LINUX_NETWORK_FULL_BATCH_PASS"
exit 0
