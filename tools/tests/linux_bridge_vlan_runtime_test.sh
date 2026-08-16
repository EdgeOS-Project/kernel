#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for Linux bridge VLAN filtering on EdgeOS.

set -eu

bridge_name=edge-brv0
host_name=edge-bvh0
peer_name=edge-bvp0

fail() {
    echo "EDGE_BRIDGE_VLAN_FAIL: $*" >&2
    exit 1
}

cleanup() {
    ip link del dev "$host_name" 2>/dev/null || true
    ip link del dev "$bridge_name" 2>/dev/null || true
}

trap cleanup EXIT INT TERM
cleanup

ip link add dev "$bridge_name" type bridge vlan_filtering 1
ip link add dev "$host_name" type veth peer name "$peer_name"
ip link set dev "$host_name" master "$bridge_name"
ip link set dev "$bridge_name" up
ip link set dev "$host_name" up
ip link set dev "$peer_name" up

ip -details link show dev "$bridge_name" | grep -q 'vlan_filtering 1' || \
    fail "bridge VLAN filtering was not reported"
bridge vlan show dev "$host_name" | grep -Eq '(^|[[:space:]])1[[:space:]]+PVID Egress Untagged' || \
    fail "default port VLAN was not reported"

bridge vlan del dev "$host_name" vid 1
bridge vlan add dev "$host_name" vid 100 pvid untagged
bridge vlan add dev "$bridge_name" vid 100 self

port_vlans="$(bridge vlan show dev "$host_name")"
printf '%s\n' "$port_vlans" | grep -Eq '(^|[[:space:]])100[[:space:]]+PVID Egress Untagged' || \
    fail "configured port VLAN was not reported"
if printf '%s\n' "$port_vlans" | grep -Eq '(^|[[:space:]])1([[:space:]]|$)'; then
    fail "deleted port VLAN was retained"
fi

bridge fdb add 02:42:ac:11:00:64 dev "$host_name" master static vlan 100
bridge fdb show br "$bridge_name" | \
    grep -Eq '02:42:ac:11:00:64.*dev edge-bvh0.*vlan 100.*permanent' || \
    fail "VLAN-scoped bridge entry was not reported"
bridge fdb del 02:42:ac:11:00:64 dev "$host_name" master vlan 100

bridge vlan del dev "$host_name" vid 100
if bridge vlan show dev "$host_name" | \
        grep -Eq '(^|[[:space:]])100([[:space:]]|$)'; then
    fail "deleted VLAN was retained"
fi

echo "EDGE_BRIDGE_VLAN_PASS"
