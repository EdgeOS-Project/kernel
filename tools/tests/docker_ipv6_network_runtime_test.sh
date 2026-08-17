#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS Docker IPv6 bridge runtime acceptance test.

set -eu

IMAGE=${EDGEOS_DOCKER_TEST_IMAGE:-busybox:latest}
NETWORK=edgeos-ipv6-runtime
SERVER=edgeos-ipv6-server
CLIENT=edgeos-ipv6-client
IPV4_SUBNET=172.30.88.0/24
IPV6_SUBNET=fd00:172:30:88::/64

cleanup() {
    docker rm -f "$CLIENT" "$SERVER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM
cleanup

docker network create --driver bridge --ipv6 \
    --subnet "$IPV4_SUBNET" --subnet "$IPV6_SUBNET" "$NETWORK" \
    >/dev/null
echo "docker_ipv6_network_runtime_test: network created"
docker run -d --name "$SERVER" --network "$NETWORK" "$IMAGE" \
    busybox sleep 120 >/dev/null
echo "docker_ipv6_network_runtime_test: server started"

server_ipv6=$(docker inspect -f \
    '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' \
    "$SERVER")
[ -n "$server_ipv6" ]

docker run --rm --name "$CLIENT" --network "$NETWORK" "$IMAGE" \
    busybox ping -6 -c 1 -W 3 "$server_ipv6" >/dev/null
echo "docker_ipv6_network_runtime_test: direct IPv6 passed"
set +e
lookup_output=$(docker run --rm --network "$NETWORK" "$IMAGE" \
    busybox nslookup "$SERVER." 2>&1)
lookup_status=$?
set -e
if [ "$lookup_status" -ne 0 ] ||
   ! printf '%s\n' "$lookup_output" | grep -q "$server_ipv6"; then
    printf '%s\n' "$lookup_output" >&2
    exit 1
fi
echo "docker_ipv6_network_runtime_test: embedded name lookup passed"
ping -6 -c 1 -W 3 "$server_ipv6" >/dev/null
echo "docker_ipv6_network_runtime_test: host-to-container IPv6 passed"

docker network inspect "$NETWORK" | grep -q '"EnableIPv6": true'
docker rm -f "$SERVER" >/dev/null
SERVER=
docker network rm "$NETWORK" >/dev/null
NETWORK=

echo "docker_ipv6_network_runtime_test: PASS"
