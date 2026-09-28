#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for the Linux bridge multicast database on EdgeOS.

set -eu

bridge_name=edge-bmd0
port_one=edge-bm1
port_two=edge-bm2
peer_one=edge-bmp1
peer_two=edge-bmp2

cleanup() {
    ip link delete dev "$port_one" 2>/dev/null || true
    ip link delete dev "$port_two" 2>/dev/null || true
    ip link delete dev "$bridge_name" 2>/dev/null || true
}

fail() {
    echo "EDGE_BRIDGE_MDB_FAIL: $*" >&2
    exit 1
}

send_membership() {
    python3 - "$1" "$2" <<'PY'
import socket
import struct
import sys


def checksum(payload):
    if len(payload) & 1:
        payload += b"\0"
    total = sum(struct.unpack("!%dH" % (len(payload) // 2), payload))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


interface, operation = sys.argv[1:3]
source_mac = bytes.fromhex("020000000001")
if operation.endswith("4"):
    group = socket.inet_aton("239.1.2.3")
    destination_mac = bytes.fromhex("01005e010203")
    message_type = 0x16 if operation == "join4" else 0x17
    igmp = struct.pack("!BBH4s", message_type, 0, 0, group)
    igmp = struct.pack(
        "!BBH4s", message_type, 0, checksum(igmp), group)
    destination = group if operation == "join4" else socket.inet_aton(
        "224.0.0.2")
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 1, 2, 0,
        socket.inet_aton("10.0.0.2"), destination)
    ipv4 = ipv4[:10] + struct.pack("!H", checksum(ipv4)) + ipv4[12:]
    frame = destination_mac + source_mac + bytes.fromhex("0800") + ipv4 + igmp
else:
    group = socket.inet_pton(socket.AF_INET6, "ff3e::5678")
    destination_mac = bytes.fromhex("333300005678")
    message_type = 131 if operation == "join6" else 132
    hop_by_hop = bytes((58, 0, 5, 2, 0, 0, 1, 0))
    mld = bytes((message_type, 0, 0, 0, 0, 0, 0, 0)) + group
    ipv6 = struct.pack(
        "!IHBB16s16s", 0x60000000, len(hop_by_hop) + len(mld),
        0, 1, socket.inet_pton(socket.AF_INET6, "fe80::1"), group)
    frame = destination_mac + source_mac + bytes.fromhex("86dd") + \
        ipv6 + hop_by_hop + mld

packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
packet_socket.bind((interface, 0))
packet_socket.send(frame)
packet_socket.close()
PY
}

trap cleanup EXIT INT TERM
cleanup

ip link add dev "$bridge_name" type bridge
ip link add dev "$port_one" type veth peer name "$peer_one"
ip link add dev "$port_two" type veth peer name "$peer_two"
ip link set dev "$port_one" master "$bridge_name"
ip link set dev "$port_two" master "$bridge_name"
ip link set dev "$bridge_name" up
ip link set dev "$port_one" up
ip link set dev "$port_two" up
ip link set dev "$peer_one" up
ip link set dev "$peer_two" up

bridge mdb add dev "$bridge_name" port "$port_one" \
    grp 239.1.1.1 permanent
bridge mdb add dev "$bridge_name" port "$port_two" \
    grp ff02::123 permanent

mdb_state="$(bridge mdb show dev "$bridge_name")"
printf '%s\n' "$mdb_state" | \
    grep -Eq "dev ${bridge_name} port ${port_one} grp 239\.1\.1\.1 permanent" || \
    fail "IPv4 multicast membership was not reported"
printf '%s\n' "$mdb_state" | \
    grep -Eq "dev ${bridge_name} port ${port_two} grp ff02::123 permanent" || \
    fail "IPv6 multicast membership was not reported"

bridge mdb del dev "$bridge_name" port "$port_one" grp 239.1.1.1
bridge mdb del dev "$bridge_name" port "$port_two" grp ff02::123
if bridge mdb show dev "$bridge_name" | grep -Eq '239\.1\.1\.1|ff02::123'; then
    fail "deleted multicast membership was retained"
fi

send_membership "$peer_one" join4
send_membership "$peer_two" join6
mdb_state="$(bridge mdb show dev "$bridge_name")"
printf '%s\n' "$mdb_state" | \
    grep -Eq "dev ${bridge_name} port ${port_one} grp 239\.1\.2\.3" || \
    fail "IPv4 report was not learned"
printf '%s\n' "$mdb_state" | \
    grep -Eq "dev ${bridge_name} port ${port_two} grp ff3e::5678" || \
    fail "IPv6 report was not learned"

send_membership "$peer_one" leave4
send_membership "$peer_two" leave6
if bridge mdb show dev "$bridge_name" | \
        grep -Eq '239\.1\.2\.3|ff3e::5678'; then
    fail "multicast leave was not applied"
fi

echo EDGE_BRIDGE_MDB_PASS
