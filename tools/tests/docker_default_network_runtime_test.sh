#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS default Docker network runtime acceptance test.

set -eu

IMAGE=${EDGEOS_DOCKER_TEST_IMAGE:-edgeos-local:arm64}
SERVER=edgeos-default-net-server
CLIENT=edgeos-default-net-client
HOST_PORT=${EDGEOS_DOCKER_TEST_HOST_PORT:-18088}
CONTAINER_PORT=${EDGEOS_DOCKER_TEST_CONTAINER_PORT:-18089}
WORK=/tmp/edgeos-docker-default-network

cleanup() {
    docker rm -f "$CLIENT" "$SERVER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}

trap cleanup EXIT INT TERM
cleanup
mkdir -p "$WORK"

docker version >/dev/null
docker network inspect bridge >"$WORK/bridge.json"
grep -q '"Driver": "bridge"' "$WORK/bridge.json"

docker run --rm "$IMAGE" busybox nslookup deb.debian.org \
    >"$WORK/dns.txt"
grep -q 'Address' "$WORK/dns.txt"

docker run -d --name "$SERVER" -p "$HOST_PORT:$CONTAINER_PORT" "$IMAGE" \
    /bin/sh -c "busybox mkdir -p /tmp/edgeos-www && printf 'edgeos-docker-network\\n' > /tmp/edgeos-www/index.html && exec busybox httpd -f -p $CONTAINER_PORT -h /tmp/edgeos-www" \
    >/dev/null

SERVER_ADDRESS=
BRIDGE_GATEWAY=$(docker network inspect -f \
    '{{(index .IPAM.Config 0).Gateway}}' bridge)
[ -n "$BRIDGE_GATEWAY" ]
attempt=0
while [ "$attempt" -lt 20 ]; do
    SERVER_ADDRESS=$(docker inspect -f \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$SERVER")
    [ -n "$SERVER_ADDRESS" ] && break
    attempt=$((attempt + 1))
    sleep 1
done
[ -n "$SERVER_ADDRESS" ]

docker run --rm --name "$CLIENT" "$IMAGE" busybox wget -T 10 -qO- \
    "http://$SERVER_ADDRESS:$CONTAINER_PORT/index.html" \
    >"$WORK/container.txt"
grep -q edgeos-docker-network "$WORK/container.txt"

docker run --rm --name "$CLIENT" "$IMAGE" busybox wget -T 10 -qO- \
    "http://$BRIDGE_GATEWAY:$HOST_PORT/index.html" \
    >"$WORK/hairpin.txt"
grep -q edgeos-docker-network "$WORK/hairpin.txt"

python3 -c '
import socket
import sys

connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
connection.sendall(b"GET /index.html HTTP/1.0\r\nHost: edgeos\r\n\r\n")
reply = connection.recv(256)
connection.close()
if b"200 OK" not in reply:
    raise SystemExit("published port request failed")
print("published_port_ok")
' "$HOST_PORT" >"$WORK/published.txt"
grep -q published_port_ok "$WORK/published.txt"

docker restart "$SERVER" >/dev/null
attempt=0
until python3 -c '
import socket
import sys

connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2)
connection.sendall(b"GET /index.html HTTP/1.0\r\nHost: edgeos\r\n\r\n")
reply = connection.recv(256)
connection.close()
if b"200 OK" not in reply:
    raise SystemExit(1)
' "$HOST_PORT"; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 15 ] || exit 1
    sleep 1
done

docker rm -f "$SERVER" >/dev/null
SERVER=

if python3 -c '
import socket
import sys

try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)
except OSError:
    raise SystemExit(1)
raise SystemExit(0)
' "$HOST_PORT"; then
    echo "published port remained active after container removal" >&2
    exit 1
fi

echo "docker_default_network_runtime_test: PASS"
