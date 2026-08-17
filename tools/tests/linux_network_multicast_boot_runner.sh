#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared boot-time acceptance runner for multicast networking changes.

set -u

if [ -c /dev/ttyS0 ]; then
    exec >/dev/ttyS0 2>&1
elif [ -c /dev/ttyAMA0 ]; then
    exec >/dev/ttyAMA0 2>&1
fi

base_runner=${EDGEOS_NETWORK_BASE_RUNNER:-/root/linux_network_full_batch_runtime_test.sh}
test_directory=${EDGEOS_NETWORK_TEST_DIRECTORY:-/root}

base_status=0
if [ -x "$base_runner" ]; then
    "$base_runner" || base_status=$?
fi
echo "EDGEOS_NETWORK_BASE_BATCH_RC=$base_status"

mdb_status=0
"$test_directory/linux_bridge_mdb_runtime_test.sh" || mdb_status=$?
echo "EDGEOS_BRIDGE_MDB_BATCH_RC=$mdb_status"

if [ "$base_status" -ne 0 ] || [ "$mdb_status" -ne 0 ]; then
    echo EDGEOS_NETWORK_MULTICAST_BATCH_FAIL
    exit 1
fi

echo EDGEOS_NETWORK_MULTICAST_BATCH_PASS
