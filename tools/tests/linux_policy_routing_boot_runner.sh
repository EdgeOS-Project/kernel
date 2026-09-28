#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Boot-time wrapper for the shared Linux policy-routing runtime batch.

exec >/dev/ttyS0 2>&1

/root/linux_policy_routing_runtime_test.sh
status=$?
echo "EDGEOS_LINUX_POLICY_ROUTING_BATCH_RC=$status"
exit "$status"
