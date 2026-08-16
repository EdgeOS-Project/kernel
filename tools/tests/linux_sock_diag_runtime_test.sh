#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Runtime acceptance for shared Linux inet_diag TCP and UDP reporting.

set -eu

ready_file=/tmp/edgeos-sock-diag-ready
holder_pid=

cleanup() {
    if [ -n "$holder_pid" ]; then
        kill "$holder_pid" 2>/dev/null || true
        wait "$holder_pid" 2>/dev/null || true
    fi
    rm -f "$ready_file"
}

fail() {
    echo "EDGE_SOCK_DIAG_FAIL: $*" >&2
    exit 1
}

trap cleanup EXIT INT TERM
rm -f "$ready_file"
command -v ss >/dev/null 2>&1 || fail "ss is unavailable"

python3 - "$ready_file" <<'PY' &
import pathlib
import socket
import sys
import time


ready = pathlib.Path(sys.argv[1])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 38080))
listener.listen(4)
datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
datagram.bind(("127.0.0.1", 38081))
ready.write_text("ready\n", encoding="ascii")
try:
    time.sleep(30)
finally:
    datagram.close()
    listener.close()
PY
holder_pid=$!

for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$ready_file" ] && break
    sleep 1
done
[ -f "$ready_file" ] || fail "socket fixture did not become ready"

tcp_listen="$(ss -ltnH)"
printf '%s\n' "$tcp_listen" | grep -Eq 'LISTEN.*127\.0\.0\.1:38080' || \
    fail "TCP listener was not reported"

udp_bound="$(ss -lunH)"
printf '%s\n' "$udp_bound" | grep -Eq '127\.0\.0\.1:38081' || \
    fail "bound UDP socket was not reported"

filtered="$(ss -ltnH 'sport = :38080')"
printf '%s\n' "$filtered" | grep -Eq '127\.0\.0\.1:38080' || \
    fail "TCP port filter did not select the listener"
printf '%s\n' "$filtered" | grep -q ':38081' && \
    fail "TCP port filter returned an unrelated UDP socket"

echo EDGE_SOCK_DIAG_PASS
