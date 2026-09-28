#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS repeatable Linux network runtime batch.

set -eu

TEST_DIRECTORY=${EDGEOS_NETWORK_TEST_DIRECTORY:-/root}
DOCKER_TEST=${EDGEOS_DOCKER_NETWORK_TEST:-$TEST_DIRECTORY/docker-default-network-runtime-test.sh}
NAMESPACE_TEST=${EDGEOS_NAMESPACE_NETWORK_TEST:-$TEST_DIRECTORY/linux-network-namespace-runtime-test.sh}

if [ -z "${EDGEOS_DOCKER_TEST_IMAGE:-}" ]; then
    case $(uname -m) in
        aarch64)
            EDGEOS_DOCKER_TEST_IMAGE=edgeos-local:arm64
            ;;
        *)
            EDGEOS_DOCKER_TEST_IMAGE=busybox:latest
            ;;
    esac
    export EDGEOS_DOCKER_TEST_IMAGE
fi

chmod +x "$DOCKER_TEST" "$NAMESPACE_TEST"

if ! docker info >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
    systemctl start docker.service
fi

attempt=0
until docker info >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "linux_network_batch_runtime_test: Docker did not become ready" >&2
        exit 1
    fi
    sleep 1
done

timeout 240 "$DOCKER_TEST"
timeout 180 "$NAMESPACE_TEST"
timeout 240 "$DOCKER_TEST"

echo "linux_network_batch_runtime_test: PASS"
