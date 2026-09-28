#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared IPv4 forwarding and network-namespace runtime acceptance test.

set -eu

left_namespace=edgeos-router-left
right_namespace=edgeos-router-right
left_router=edge-rl0
left_peer=edge-l0
right_router=edge-rr0
right_peer=edge-r0
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
    nft delete table ip edgeos_router_nat 2>/dev/null || true
    printf '0\n' > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
}

diagnose() {
    set +e
    echo "linux_ipv4_router_runtime_test: diagnostics"
    cat /proc/sys/net/ipv4/ip_forward
    ip -details address show
    ip route show table all
    ip netns exec "$left_namespace" ip address show
    ip netns exec "$left_namespace" ip route show table all
    ip netns exec "$right_namespace" ip address show
    ip netns exec "$right_namespace" ip route show table all
    cat /proc/net/dev
    ip netns exec "$left_namespace" cat /proc/net/dev
    ip netns exec "$right_namespace" cat /proc/net/dev
    ip neighbor show
    ip netns exec "$left_namespace" ip neighbor show
    ip netns exec "$right_namespace" ip neighbor show
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

test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0
ip netns add "$left_namespace"
ip netns add "$right_namespace"
test "$(ip netns exec "$left_namespace" \
    cat /proc/sys/net/ipv4/ip_forward)" = 0

ip link add "$left_router" type veth peer name "$left_peer"
ip link add "$right_router" type veth peer name "$right_peer"
ip link set "$left_peer" netns "$left_namespace"
ip link set "$right_peer" netns "$right_namespace"

ip address add 10.71.1.1/24 dev "$left_router"
ip address add 10.71.2.1/24 dev "$right_router"
ip link set "$left_router" up
ip link set "$right_router" up

ip netns exec "$left_namespace" ip link set lo up
ip netns exec "$left_namespace" ip link set "$left_peer" up
ip netns exec "$left_namespace" \
    ip address add 10.71.1.2/24 dev "$left_peer"
ip netns exec "$left_namespace" \
    ip route add default via 10.71.1.1 dev "$left_peer"

ip netns exec "$right_namespace" ip link set lo up
ip netns exec "$right_namespace" ip link set "$right_peer" up
ip netns exec "$right_namespace" \
    ip address add 10.71.2.2/24 dev "$right_peer"
ip netns exec "$right_namespace" \
    ip route add default via 10.71.2.1 dev "$right_peer"

if ip netns exec "$left_namespace" ping -c 1 -W 1 10.71.2.2; then
    echo "linux_ipv4_router_runtime_test: forwarding ignored disabled state" >&2
    exit 1
fi

printf '1\n' > /proc/sys/net/ipv4/ip_forward
test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
test "$(ip netns exec "$left_namespace" \
    cat /proc/sys/net/ipv4/ip_forward)" = 0
ip netns exec "$left_namespace" ping -c 1 -W 3 10.71.2.2
ip netns exec "$right_namespace" ping -c 1 -W 3 10.71.1.2

timeout 15 ip netns exec "$right_namespace" python3 -c \
    'import socket; s=socket.socket(); s.bind(("10.71.2.2",18091)); s.listen(1); c,_=s.accept(); data=c.recv(64); assert data==b"edgeos-tcp"; c.sendall(b"tcp-ok"); c.close(); s.close()' &
tcp_server_pid=$!
sleep 1
test "$(timeout 10 ip netns exec "$left_namespace" python3 -c \
    'import socket; s=socket.create_connection(("10.71.2.2",18091),5); s.sendall(b"edgeos-tcp"); print(s.recv(64).decode()); s.close()')" = tcp-ok
wait "$tcp_server_pid"
tcp_server_pid=

timeout 15 ip netns exec "$right_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.71.2.2",18092)); data,peer=s.recvfrom(64); assert data==b"edgeos-udp"; s.sendto(b"udp-ok",peer); s.close()' &
udp_server_pid=$!
sleep 1
test "$(timeout 10 ip netns exec "$left_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b"edgeos-udp",("10.71.2.2",18092)); print(s.recv(64).decode()); s.close()')" = udp-ok
wait "$udp_server_pid"
udp_server_pid=

nft add table ip edgeos_router_nat
nft "add chain ip edgeos_router_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }"
nft add rule ip edgeos_router_nat postrouting \
    oifname "$right_router" masquerade
nft list table ip edgeos_router_nat

timeout 15 ip netns exec "$right_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.71.2.2",18093)); data,peer=s.recvfrom(64); assert data==b"edgeos-nat"; assert peer[0]=="10.71.2.1",peer; s.sendto(b"nat-ok",peer); s.close()' &
udp_server_pid=$!
sleep 1
test "$(timeout 10 ip netns exec "$left_namespace" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b"edgeos-nat",("10.71.2.2",18093)); print(s.recv(64).decode()); s.close()')" = nat-ok
wait "$udp_server_pid"
udp_server_pid=
nft delete table ip edgeos_router_nat

printf '0\n' > /proc/sys/net/ipv4/ip_forward
if ip netns exec "$right_namespace" ping -c 1 -W 1 10.71.1.2; then
    echo "linux_ipv4_router_runtime_test: forwarding stayed active" >&2
    exit 1
fi

echo "linux_ipv4_router_runtime_test: PASS"
