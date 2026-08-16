#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for route Netlink change events and namespace isolation.

set -eu

namespace=edge-event-ns
host_link=edge-event-host
namespace_link=edge-event-peer
ready_file=/tmp/edgeos-rtnetlink-event-ready
result_file=/tmp/edgeos-rtnetlink-event-result
port_ready_file=/tmp/edgeos-rtnetlink-port-ready
listener_pid=
port_holder_pid=

cleanup() {
    if [ -n "$listener_pid" ]; then
        kill "$listener_pid" 2>/dev/null || true
        wait "$listener_pid" 2>/dev/null || true
    fi
    if [ -n "$port_holder_pid" ]; then
        kill "$port_holder_pid" 2>/dev/null || true
        wait "$port_holder_pid" 2>/dev/null || true
    fi
    ip link delete "$host_link" 2>/dev/null || true
    ip netns delete "$namespace" 2>/dev/null || true
    rm -f "$ready_file" "$result_file" "$port_ready_file"
}

fail() {
    echo "EDGE_RTNL_EVENT_FAIL: $*" >&2
    exit 1
}

wait_ready() {
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        [ -f "$ready_file" ] && return 0
        sleep 1
    done
    return 1
}

start_listener() {
    expected_name=$1
    shift
    rm -f "$ready_file" "$result_file"
    "$@" python3 - "$ready_file" "$result_file" "$expected_name" <<'PY' &
import pathlib
import socket
import struct
import sys


ready = pathlib.Path(sys.argv[1])
result = pathlib.Path(sys.argv[2])
expected_name = sys.argv[3]
listener = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
listener.bind((0, 1))
listener.settimeout(10)
ready.write_text("ready\n", encoding="ascii")
try:
    payload = listener.recv(65535)
finally:
    listener.close()
if len(payload) < 32:
    raise SystemExit("short route Netlink event")
length, message_type, flags, sequence, port_id = struct.unpack_from("=IHHII", payload)
if length > len(payload) or message_type != 16:
    raise SystemExit("unexpected route Netlink event type")
if flags != 0 or sequence != 0 or port_id != 0:
    raise SystemExit("route Netlink event did not use kernel header fields")
offset = 32
found_name = None
while offset + 4 <= length:
    attribute_length, attribute_type = struct.unpack_from("=HH", payload, offset)
    if attribute_length < 4 or offset + attribute_length > length:
        raise SystemExit("invalid route Netlink event attribute")
    if attribute_type == 3:
        raw_name = payload[offset + 4:offset + attribute_length]
        found_name = raw_name.split(b"\0", 1)[0].decode("ascii")
        break
    offset += (attribute_length + 3) & ~3
if found_name != expected_name:
    raise SystemExit(f"unexpected link event {found_name!r}")
result.write_text("pass\n", encoding="ascii")
PY
    listener_pid=$!
}

trap cleanup EXIT INT TERM
command -v ip >/dev/null 2>&1 || fail "ip is unavailable"
command -v python3 >/dev/null 2>&1 || fail "python3 is unavailable"

cleanup
listener_pid=

start_listener "$host_link"
wait_ready || fail "host listener did not become ready"
ip link add "$host_link" type dummy
wait "$listener_pid" || fail "host listener rejected the event"
listener_pid=
[ "$(cat "$result_file")" = pass ] || fail "host event was not delivered"
ip link delete "$host_link"

ip netns add "$namespace"
python3 - "$port_ready_file" <<'PY' &
import pathlib
import socket
import sys
import time


listener = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
listener.bind((44044, 0))
pathlib.Path(sys.argv[1]).write_text("ready\n", encoding="ascii")
try:
    time.sleep(20)
finally:
    listener.close()
PY
port_holder_pid=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$port_ready_file" ] && break
    sleep 1
done
[ -f "$port_ready_file" ] || fail "host port holder did not become ready"
ip netns exec "$namespace" python3 - <<'PY'
import socket


listener = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
listener.bind((44044, 0))
listener.close()
PY
start_listener "$namespace_link" ip netns exec "$namespace"
wait_ready || fail "namespace listener did not become ready"
ip link add "$host_link" type dummy
sleep 1
ip netns exec "$namespace" ip link add "$namespace_link" type dummy
wait "$listener_pid" || fail "namespace event delivery or isolation failed"
listener_pid=
[ "$(cat "$result_file")" = pass ] || fail "namespace event was not delivered"

echo EDGE_RTNL_EVENT_PASS
