#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for shared Linux FIFO queueing disciplines on EdgeOS.

set -eu

host_interface=edge-tc0
peer_interface=edge-tc1

cleanup() {
    ip link delete dev "$host_interface" 2>/dev/null || true
}

fail() {
    echo "EDGE_QDISC_FAIL: $*" >&2
    exit 1
}

send_frame() {
    python3 - "$host_interface" <<'PY'
import socket
import sys


interface = sys.argv[1]
destination = bytes.fromhex("020000000002")
source = bytes.fromhex("020000000001")
frame = destination + source + bytes.fromhex("88b5") + bytes(range(46))
packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
packet_socket.bind((interface, 0))
sent = packet_socket.send(frame)
packet_socket.close()
if sent != len(frame):
    raise SystemExit("short AF_PACKET transmission")
PY
}

trap cleanup EXIT INT TERM
cleanup

command -v tc >/dev/null 2>&1 || fail "tc is unavailable"
ip link add dev "$host_interface" type veth peer name "$peer_interface"
ip link set dev "$host_interface" up
ip link set dev "$peer_interface" up

tc qdisc replace dev "$host_interface" root handle 1: pfifo limit 8
qdisc_state="$(tc -s qdisc show dev "$host_interface")"
printf '%s\n' "$qdisc_state" | \
    grep -Eq 'qdisc pfifo 1: root.*limit 8p' || \
    fail "pfifo configuration was not reported"

send_frame
qdisc_state="$(tc -s qdisc show dev "$host_interface")"
printf '%s\n' "$qdisc_state" | \
    grep -Eq 'Sent [1-9][0-9]* bytes [1-9][0-9]* pkt' || \
    fail "pfifo packet and byte statistics were not updated"

tc qdisc replace dev "$host_interface" root handle 2: bfifo limit 4096
qdisc_state="$(tc -s qdisc show dev "$host_interface")"
printf '%s\n' "$qdisc_state" | \
    grep -Eq 'qdisc bfifo 2: root.*limit (4096b|4Kb)' || \
    fail "bfifo configuration was not reported"

tc qdisc del dev "$host_interface" root
qdisc_state="$(tc qdisc show dev "$host_interface")"
printf '%s\n' "$qdisc_state" | \
    grep -Eq 'qdisc noqueue 0: root' || \
    fail "deleting the root queueing discipline did not restore noqueue"

echo EDGE_QDISC_PASS
