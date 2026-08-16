#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared Linux dummy and 802.1Q virtual-link runtime acceptance test.

set -eux

namespace=edgeos-vlan-test
host_lower=edgevh0
peer_lower=edgevp0
host_vlan=edgevh0.123
peer_vlan=edgevp0.123
host_macvlan=edgemac0
host_ipvlan=edgeipv0
peer_ipvlan=edgeipv1
dummy=edgedummy0
subnet=172.30.123
macvlan_subnet=172.30.124
ipvlan_subnet=172.30.125

cleanup() {
    ip netns delete "$namespace" 2>/dev/null || true
    ip link delete "$host_macvlan" 2>/dev/null || true
    ip link delete "$host_ipvlan" 2>/dev/null || true
    ip link delete "$host_vlan" 2>/dev/null || true
    ip link delete "$host_lower" 2>/dev/null || true
    ip link delete "$dummy" 2>/dev/null || true
}

diagnose() {
    set +e
    echo "linux_virtual_link_runtime_test: diagnostics"
    ip -details -statistics link show
    ip address show
    ip netns exec "$namespace" ip -details -statistics link show
    ip netns exec "$namespace" ip address show
    cat /proc/net/dev
    ip netns exec "$namespace" cat /proc/net/dev
}

finish() {
    result=$?
    if [ "$result" -ne 0 ]; then
        diagnose
    fi
    cleanup
    exit "$result"
}

trap finish EXIT
trap 'exit 130' INT TERM
cleanup

ip link add "$dummy" type dummy
ip link set "$dummy" up
ip address add 192.0.2.1/32 dev "$dummy"
ip -details link show "$dummy" | grep -q 'dummy'
test "$(cat "/sys/class/net/$dummy/carrier")" = 1
ping -c 1 -W 2 192.0.2.1

ip netns add "$namespace"
ip link add "$host_lower" type veth peer name "$peer_lower"
ip link set "$peer_lower" netns "$namespace"
ip link set "$host_lower" up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip link set "$peer_lower" up

ip link add link "$host_lower" name "$host_macvlan" \
    type macvlan mode bridge
ip link set "$host_macvlan" up
ip address add "$macvlan_subnet.1/24" dev "$host_macvlan"
ip netns exec "$namespace" \
    ip address add "$macvlan_subnet.2/24" dev "$peer_lower"
ip -details link show "$host_macvlan" | grep -q 'macvlan mode bridge'
test "$(cat "/sys/class/net/$host_macvlan/carrier")" = 1
ping -I "$host_macvlan" -c 1 -W 3 "$macvlan_subnet.2"
ip netns exec "$namespace" ping -c 1 -W 3 "$macvlan_subnet.1"
ip neighbor show dev "$host_macvlan" |
    grep -q "$macvlan_subnet.2"
peer_mac=$(ip netns exec "$namespace" \
    cat "/sys/class/net/$peer_lower/address")
ip neighbor replace "$macvlan_subnet.2" lladdr "$peer_mac" \
    nud permanent dev "$host_macvlan"
ip neighbor show dev "$host_macvlan" |
    grep -qi "$macvlan_subnet.2.*permanent"
ip neighbor delete "$macvlan_subnet.2" dev "$host_macvlan"
ip link delete "$host_macvlan"
ip netns exec "$namespace" \
    ip address delete "$macvlan_subnet.2/24" dev "$peer_lower"

ip link add link "$host_lower" name "$host_ipvlan" \
    type ipvlan mode l2 bridge
ip netns exec "$namespace" \
    ip link add link "$peer_lower" name "$peer_ipvlan" \
    type ipvlan mode l2 bridge
ip link set "$host_ipvlan" up
ip address add "$ipvlan_subnet.1/24" dev "$host_ipvlan"
ip netns exec "$namespace" ip link set "$peer_ipvlan" up
ip netns exec "$namespace" \
    ip address add "$ipvlan_subnet.2/24" dev "$peer_ipvlan"
ip -details link show "$host_ipvlan" | grep -Eq 'ipvlan +mode l2 bridge'
ip netns exec "$namespace" ip -details link show "$peer_ipvlan" |
    grep -Eq 'ipvlan +mode l2 bridge'
test "$(cat "/sys/class/net/$host_ipvlan/address")" = \
    "$(cat "/sys/class/net/$host_lower/address")"
ip netns exec "$namespace" ping -c 1 -W 3 "$ipvlan_subnet.1"
ping -I "$host_ipvlan" -c 1 -W 3 "$ipvlan_subnet.2"
ip link delete "$host_ipvlan"
ip netns exec "$namespace" ip link delete "$peer_ipvlan"

ip link add link "$host_lower" name "$host_vlan" type vlan id 123
ip netns exec "$namespace" \
    ip link add link "$peer_lower" name "$peer_vlan" type vlan id 123

if ip link add link "$host_lower" name edgedup0 \
    type vlan id 123 2>/dev/null; then
    echo "linux_virtual_link_runtime_test: duplicate VLAN was accepted" >&2
    exit 1
fi

ip link set "$host_vlan" up
ip address add "$subnet.1/24" dev "$host_vlan"
ip netns exec "$namespace" ip link set "$peer_vlan" up
ip netns exec "$namespace" \
    ip address add "$subnet.2/24" dev "$peer_vlan"

ip -details link show "$host_vlan" | grep -q 'vlan protocol 802.1Q id 123'
ip netns exec "$namespace" ip -details link show "$peer_vlan" |
    grep -q 'vlan protocol 802.1Q id 123'
test "$(cat "/sys/class/net/$host_vlan/carrier")" = 1
ip netns exec "$namespace" sh -c \
    'test "$(cat "/sys/class/net/'"$peer_vlan"'/carrier")" = 1'

ip netns exec "$namespace" ping -c 1 -W 3 "$subnet.1"
ping -c 1 -W 3 "$subnet.2"

ip link set "$host_lower" down
test "$(cat "/sys/class/net/$host_vlan/carrier")" = 0
ip link set "$host_lower" up
test "$(cat "/sys/class/net/$host_vlan/carrier")" = 1

ip link delete "$host_lower"
if ip link show "$host_vlan" 2>/dev/null; then
    echo "linux_virtual_link_runtime_test: lower deletion retained VLAN" >&2
    exit 1
fi

echo "linux_virtual_link_runtime_test: PASS"
