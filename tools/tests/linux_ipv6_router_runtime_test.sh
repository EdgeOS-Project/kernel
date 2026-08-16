#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared IPv6 forwarding and network-namespace runtime acceptance test.

set -eu

left_namespace=edgeos-router6-left
right_namespace=edgeos-router6-right
left_router=edge-r6l0
left_peer=edge-6l0
right_router=edge-r6r0
right_peer=edge-6r0
tcp_server_pid=
udp_server_pid=

cleanup() {
    if [ -n "$tcp_server_pid" ]; then
        kill "$tcp_server_pid" 2>/dev/null || true
    fi
    if [ -n "$udp_server_pid" ]; then
        kill "$udp_server_pid" 2>/dev/null || true
    fi
    ip netns delete "$left_namespace" 2>/dev/null || true
    ip netns delete "$right_namespace" 2>/dev/null || true
    ip link delete "$left_router" 2>/dev/null || true
    ip link delete "$right_router" 2>/dev/null || true
    printf '0\n' > /proc/sys/net/ipv6/conf/all/forwarding \
        2>/dev/null || true
}

diagnose() {
    set +e
    echo "linux_ipv6_router_runtime_test: diagnostics"
    cat /proc/sys/net/ipv6/conf/all/forwarding
    ip -6 -details address show
    ip -6 route show table all
    ip netns exec "$left_namespace" ip -6 address show
    ip netns exec "$left_namespace" ip -6 route show table all
    ip netns exec "$right_namespace" ip -6 address show
    ip netns exec "$right_namespace" ip -6 route show table all
    cat /proc/net/if_inet6
    cat /proc/net/ipv6_route
    ip -6 neighbor show
    ip netns exec "$left_namespace" ip -6 neighbor show
    ip netns exec "$right_namespace" ip -6 neighbor show
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

test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0
ip netns add "$left_namespace"
ip netns add "$right_namespace"
test "$(ip netns exec "$left_namespace" \
    cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0

ip link add "$left_router" type veth peer name "$left_peer"
ip link add "$right_router" type veth peer name "$right_peer"
ip link set "$left_peer" netns "$left_namespace"
ip link set "$right_peer" netns "$right_namespace"

ip -6 address add fd71:1::1/64 dev "$left_router"
ip -6 address add fd71:2::1/64 dev "$right_router"
ip link set "$left_router" up
ip link set "$right_router" up

ip netns exec "$left_namespace" ip link set lo up
ip netns exec "$left_namespace" ip link set "$left_peer" up
ip netns exec "$left_namespace" \
    ip -6 address add fd71:1::2/64 dev "$left_peer"
ip netns exec "$left_namespace" \
    ip -6 route add fd71:2::/64 via fd71:1::1 dev "$left_peer"

ip netns exec "$right_namespace" ip link set lo up
ip netns exec "$right_namespace" ip link set "$right_peer" up
ip netns exec "$right_namespace" \
    ip -6 address add fd71:2::2/64 dev "$right_peer"
ip netns exec "$right_namespace" \
    ip -6 route add fd71:1::/64 via fd71:2::1 dev "$right_peer"

# Allow duplicate-address detection to publish all four addresses before the
# forwarding checks begin. Linux applications cannot use tentative sources.
sleep 3

if ip netns exec "$left_namespace" ping -6 -c 1 -W 1 fd71:2::2; then
    echo "linux_ipv6_router_runtime_test: forwarding ignored disabled state" >&2
    exit 1
fi

printf '1\n' > /proc/sys/net/ipv6/conf/all/forwarding
test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 1
test "$(ip netns exec "$left_namespace" \
    cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0
ip netns exec "$left_namespace" ping -6 -c 1 -W 3 fd71:2::2
ip netns exec "$right_namespace" ping -6 -c 1 -W 3 fd71:1::2

timeout 15 ip netns exec "$right_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET6); s.bind(("fd71:2::2",18094)); s.listen(1); c,_=s.accept(); data=c.recv(64); assert data==b"edgeos-tcp6"; c.sendall(b"tcp6-ok"); c.close(); s.close()' &
tcp_server_pid=$!
sleep 1
test "$(timeout 10 ip netns exec "$left_namespace" python3 -c \
    'import socket; s=socket.create_connection(("fd71:2::2",18094),5); s.sendall(b"edgeos-tcp6"); print(s.recv(64).decode()); s.close()')" = tcp6-ok
wait "$tcp_server_pid"
tcp_server_pid=

timeout 15 ip netns exec "$right_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("fd71:2::2",18095)); data,peer=s.recvfrom(64); assert data==b"edgeos-udp6"; s.sendto(b"udp6-ok",peer); s.close()' &
udp_server_pid=$!
sleep 1
test "$(timeout 10 ip netns exec "$left_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b"edgeos-udp6",("fd71:2::2",18095)); print(s.recv(64).decode()); s.close()')" = udp6-ok
wait "$udp_server_pid"
udp_server_pid=

printf '0\n' > /proc/sys/net/ipv6/conf/all/forwarding
if ip netns exec "$right_namespace" ping -6 -c 1 -W 1 fd71:1::2; then
    echo "linux_ipv6_router_runtime_test: forwarding stayed active" >&2
    exit 1
fi

echo "linux_ipv6_router_runtime_test: PASS"
