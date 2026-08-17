#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for Linux bridge port controls on EdgeOS.

set -eu

bridge_name=edge-bpc0
port_one=edge-bp1
port_two=edge-bp2
peer_one=edge-bn1
peer_two=edge-bn2
namespace_one=edge-bns1
namespace_two=edge-bns2

cleanup() {
    ip netns delete "$namespace_one" 2>/dev/null || true
    ip netns delete "$namespace_two" 2>/dev/null || true
    ip link delete dev "$port_one" 2>/dev/null || true
    ip link delete dev "$port_two" 2>/dev/null || true
    ip link delete dev "$bridge_name" 2>/dev/null || true
}

fail() {
    echo "EDGE_BRIDGE_PORT_FAIL: $*" >&2
    exit 1
}

trap cleanup EXIT INT TERM
cleanup

ip netns add "$namespace_one"
ip netns add "$namespace_two"
ip link add dev "$bridge_name" type bridge
ip link add dev "$port_one" type veth peer name "$peer_one"
ip link add dev "$port_two" type veth peer name "$peer_two"
ip link set dev "$port_one" master "$bridge_name"
ip link set dev "$port_two" master "$bridge_name"
ip link set dev "$peer_one" netns "$namespace_one"
ip link set dev "$peer_two" netns "$namespace_two"
ip link set dev "$bridge_name" up
ip link set dev "$port_one" up
ip link set dev "$port_two" up
ip netns exec "$namespace_one" ip link set dev lo up
ip netns exec "$namespace_two" ip link set dev lo up
ip netns exec "$namespace_one" ip link set dev "$peer_one" up
ip netns exec "$namespace_two" ip link set dev "$peer_two" up
ip netns exec "$namespace_one" ip address add 192.0.2.1/24 dev "$peer_one"
ip netns exec "$namespace_two" ip address add 192.0.2.2/24 dev "$peer_two"

bridge link set dev "$port_one" isolated on
bridge link set dev "$port_two" isolated on
bridge -details link show dev "$port_one" | grep -q 'isolated on' || \
    fail "isolated mode was not reported"
if ip netns exec "$namespace_one" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then
    fail "isolated bridge ports exchanged traffic"
fi

bridge link set dev "$port_two" isolated off
ip netns exec "$namespace_one" ping -c 1 -W 3 192.0.2.2 >/dev/null || \
    fail "isolated port could not reach a non-isolated port"

bridge link set dev "$port_two" state 4
if ip netns exec "$namespace_one" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then
    fail "blocking bridge port forwarded traffic"
fi
bridge link set dev "$port_two" state 3
ip netns exec "$namespace_one" ping -c 1 -W 3 192.0.2.2 >/dev/null || \
    fail "forwarding bridge port did not recover"

bridge link set dev "$port_one" learning off flood off mcast_flood off bcast_flood off
port_state="$(bridge -details link show dev "$port_one")"
printf '%s\n' "$port_state" | grep -q 'learning off' || \
    fail "learning control was not reported"
printf '%s\n' "$port_state" | grep -q 'flood off' || \
    fail "unicast flood control was not reported"
printf '%s\n' "$port_state" | grep -q 'mcast_flood off' || \
    fail "multicast flood control was not reported"
printf '%s\n' "$port_state" | grep -q 'bcast_flood off' || \
    fail "broadcast flood control was not reported"

echo EDGE_BRIDGE_PORT_PASS
