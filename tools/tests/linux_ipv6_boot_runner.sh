#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS boot-time runner for the Linux IPv6 runtime batch.

exec >/dev/ttyS0 2>&1

/root/linux-ipv6-runtime-test.sh
status=$?
echo "EDGEOS_LINUX_IPV6_BATCH_RC=$status"
exit "$status"
