#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared boot-time acceptance runner for traffic-control changes.

set -u

if [ -c /dev/ttyS0 ]; then
    exec >/dev/ttyS0 2>&1
elif [ -c /dev/ttyAMA0 ]; then
    exec >/dev/ttyAMA0 2>&1
fi

base_runner=${EDGEOS_NETWORK_BASE_RUNNER:-/root/linux_network_multicast_boot_runner.sh}
test_directory=${EDGEOS_NETWORK_TEST_DIRECTORY:-/root}

base_status=0
if [ ! -x "$base_runner" ]; then
    echo "EDGEOS_NETWORK_TC_MISSING_BASE_RUNNER=$base_runner"
    base_status=127
else
    "$base_runner" || base_status=$?
fi
echo "EDGEOS_NETWORK_MULTICAST_BATCH_RC=$base_status"

qdisc_status=0
"$test_directory/linux_qdisc_runtime_test.sh" || qdisc_status=$?
echo "EDGEOS_QDISC_BATCH_RC=$qdisc_status"

if [ "$base_status" -ne 0 ] || [ "$qdisc_status" -ne 0 ]; then
    echo EDGEOS_NETWORK_TC_BATCH_FAIL
    exit 1
fi

echo EDGEOS_NETWORK_TC_BATCH_PASS
