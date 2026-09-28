#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Shared Linux network namespace, veth, bridge, and local transport runtime test.

set -eux

namespace=edgeos-net-test
bridge=edgebr0
host_veth=edgehost0
peer_veth=edgepeer0
subnet=172.29.83
temporary_directory=/tmp/edgeos-network-runtime
rule_table=edgeos_runtime_filter

cleanup() {
    if [ -f "$temporary_directory/host-listener.pid" ]; then
        kill "$(cat "$temporary_directory/host-listener.pid")" 2>/dev/null || true
    fi
    if [ -f "$temporary_directory/peer-listener.pid" ]; then
        kill "$(cat "$temporary_directory/peer-listener.pid")" 2>/dev/null || true
    fi
    if [ -f "$temporary_directory/udp-listener.pid" ]; then
        kill "$(cat "$temporary_directory/udp-listener.pid")" 2>/dev/null || true
    fi
    nft delete table inet "$rule_table" 2>/dev/null || true
    ip netns delete "$namespace" 2>/dev/null || true
    ip link delete "$bridge" 2>/dev/null || true
    rm -rf "$temporary_directory"
}

diagnose() {
    set +e
    echo "linux_network_namespace_runtime_test: diagnostics"
    ip -s link show "$bridge"
    ip -s link show "$host_veth"
    cat "/sys/class/net/$bridge/carrier"
    cat "/sys/class/net/$host_veth/carrier"
    ip neighbor show
    bridge fdb show br "$bridge"
    ip netns exec "$namespace" ip -s link show eth0
    ip netns exec "$namespace" cat /sys/class/net/eth0/carrier
    ip netns exec "$namespace" ip neighbor show
    nft list table inet "$rule_table"
    cat /proc/net/dev
    ip netns exec "$namespace" cat /proc/net/dev
}

finish() {
    status=$?
    if [ "$status" -ne 0 ]; then
        diagnose
    fi
    cleanup
    exit "$status"
}

trap finish EXIT
trap 'exit 130' INT TERM
cleanup
mkdir -p "$temporary_directory/host" "$temporary_directory/peer"

ip link add "$bridge" type bridge
ip address add "$subnet.1/24" dev "$bridge"
ip link set "$bridge" up
ip netns add "$namespace"
for setting in bridge-nf-call-iptables bridge-nf-call-ip6tables \
    bridge-nf-call-arptables; do
    test "$(cat "/proc/sys/net/bridge/$setting")" = 1
    ip netns exec "$namespace" sh -c \
        "test \"\$(cat /proc/sys/net/bridge/$setting)\" = 1"
done
ip netns exec "$namespace" sh -c \
    'echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables'
ip netns exec "$namespace" sh -c \
    'test "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 0'
test "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 1
ip netns exec "$namespace" sh -c \
    'echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables'
ip link add "$host_veth" type veth peer name "$peer_veth"
ip link set "$host_veth" master "$bridge"
ip link set "$host_veth" up
ip link set "$peer_veth" netns "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip link set "$peer_veth" name eth0
ip netns exec "$namespace" ip address add "$subnet.2/24" dev eth0
ip netns exec "$namespace" ip link set eth0 up
ip netns exec "$namespace" ip route add default via "$subnet.1" dev eth0

ip -details link show "$bridge"
ip -details link show "$host_veth"
ip netns exec "$namespace" ip -details link show eth0
ip netns exec "$namespace" ip address show
ip netns exec "$namespace" ip route show
ip netns exec "$namespace" ping -c 1 -W 2 "$subnet.1"
ping -c 1 -W 2 "$subnet.2"

test -e "/sys/class/net/$bridge"
test -e "/sys/class/net/$host_veth"
ip netns exec "$namespace" test -e /sys/class/net/eth0
ip netns exec "$namespace" test ! -e "/sys/class/net/$bridge"
grep -q "$bridge:" /proc/net/dev
ip netns exec "$namespace" grep -q 'eth0:' /proc/net/dev

tcp_server='
import socket
import sys

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(8)
server.bind(("0.0.0.0", int(sys.argv[1])))
server.listen(1)
connection, _ = server.accept()
connection.settimeout(6)
payload = connection.recv(256)
with open(sys.argv[2], "wb") as output:
    output.write(payload)
connection.sendall(sys.argv[3].encode("ascii"))
connection.close()
server.close()
'
tcp_client='
import socket
import sys

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(6)
client.connect((sys.argv[1], int(sys.argv[2])))
client.sendall(sys.argv[3].encode("ascii"))
reply = client.recv(256)
with open(sys.argv[4], "wb") as output:
    output.write(reply)
client.close()
'

python3 -c "$tcp_server" 18080 \
    "$temporary_directory/host/request" EDGEOS_HOST_STREAM_REPLY &
echo $! >"$temporary_directory/host-listener.pid"
sleep 1
timeout 15 ip netns exec "$namespace" python3 -c "$tcp_client" \
    "$subnet.1" 18080 EDGEOS_PEER_STREAM_REQUEST \
    "$temporary_directory/peer/reply"
wait "$(cat "$temporary_directory/host-listener.pid")"
grep -q EDGEOS_PEER_STREAM_REQUEST "$temporary_directory/host/request"
grep -q EDGEOS_HOST_STREAM_REPLY "$temporary_directory/peer/reply"

ip netns exec "$namespace" python3 -c "$tcp_server" 18081 \
    "$temporary_directory/peer/request" EDGEOS_PEER_STREAM_REPLY &
echo $! >"$temporary_directory/peer-listener.pid"
sleep 1
timeout 15 python3 -c "$tcp_client" "$subnet.2" 18081 \
    EDGEOS_HOST_STREAM_REQUEST "$temporary_directory/host/reply"
wait "$(cat "$temporary_directory/peer-listener.pid")"
grep -q EDGEOS_HOST_STREAM_REQUEST "$temporary_directory/peer/request"
grep -q EDGEOS_PEER_STREAM_REPLY "$temporary_directory/host/reply"

python3 -c '
import socket
import sys

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.settimeout(6)
server.bind(("0.0.0.0", 18082))
payload, _ = server.recvfrom(256)
with open(sys.argv[1], "wb") as output:
    output.write(payload)
' "$temporary_directory/host/udp" &
echo $! >"$temporary_directory/udp-listener.pid"
sleep 1
ip netns exec "$namespace" python3 -c '
import socket
import sys

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto(b"EDGEOS_UDP_OK", (sys.argv[1], 18082))
' "$subnet.1"
wait "$(cat "$temporary_directory/udp-listener.pid")"
grep -q EDGEOS_UDP_OK "$temporary_directory/host/udp"

nft add table inet "$rule_table"
nft "add chain inet $rule_table input { type filter hook input priority 0; policy accept; }"
nft add rule inet "$rule_table" input \
    ip saddr "$subnet.2" udp dport 18083 drop
nft list table inet "$rule_table"
python3 -c '
import socket
import sys

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.settimeout(4)
server.bind(("0.0.0.0", 18083))
try:
    payload, _ = server.recvfrom(256)
except TimeoutError:
    raise SystemExit(23)
with open(sys.argv[1], "wb") as output:
    output.write(payload)
' "$temporary_directory/host/blocked-udp" &
echo $! >"$temporary_directory/udp-listener.pid"
sleep 1
ip netns exec "$namespace" python3 -c '
import socket
import sys

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto(b"EDGEOS_UDP_SHOULD_NOT_ARRIVE", (sys.argv[1], 18083))
' "$subnet.1"
if wait "$(cat "$temporary_directory/udp-listener.pid")"; then
    echo "linux_network_namespace_runtime_test: nftables drop verdict failed" >&2
    exit 1
fi
test ! -s "$temporary_directory/host/blocked-udp"
nft delete table inet "$rule_table"

echo "linux_network_namespace_runtime_test: PASS"
