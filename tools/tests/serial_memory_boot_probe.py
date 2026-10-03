#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise an isolated, passwordless Buildroot test guest over its serial socket."""

import argparse
import json
import re
import socket
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("socket")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--scratch-device", help="Destructively test a caller-verified disposable VirtIO disk")
    parser.add_argument("--expect-scratch-data", action="store_true")
    args = parser.parse_args()
    if args.scratch_device and not re.fullmatch(r"/dev/(?:vd|sd)[a-z]", args.scratch_device):
        parser.error("Expected a supported block device path")
    if args.expect_scratch_data and not args.scratch_device:
        parser.error("Expected a scratch device")
    started = time.monotonic()
    deadline = started + args.timeout
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        try:
            channel.connect(args.socket)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                raise TimeoutError("Serial socket unavailable")
            time.sleep(0.1)
    channel.settimeout(0.5)
    pending = ""

    def receive(pattern):
        nonlocal pending
        while time.monotonic() < deadline:
            match = re.search(pattern, pending)
            if match:
                pending = pending[match.end():]
                return match
            try:
                data = channel.recv(8192)
            except socket.timeout:
                continue
            if not data:
                raise RuntimeError("Guest disconnected before expected output")
            decoded = data.decode("utf-8", errors="replace").replace("\r", "")
            print(decoded, end="", flush=True)
            pending += decoded
            pending = pending[-65536:]
        raise TimeoutError(f"Guest did not reach {pattern!r}")

    receive(r"login: ")
    channel.sendall(b"root\n")
    receive(r"\n# ")
    checks = [
        "test $(wc -l < /proc/swaps) -eq 1",
        "test $(echo pipe-check | tr a-z A-Z) = PIPE-CHECK",
        "dd if=/dev/zero of=/tmp/check.bin bs=4096 count=16 && "
        "test $(sha256sum /tmp/check.bin | cut -d ' ' -f 1) = "
        "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31",
        "i=0; until ping -c 1 10.0.2.2; do i=$((i+1)); "
        "test $i -lt 30 || break; sleep 1; done; ping -c 1 10.0.2.2",
        "nslookup example.com 10.0.2.3",
        "ping -c 1 example.com",
        "i=0; while test $i -lt 25; do (echo cycle | cat >/dev/null) || "
        "break; i=$((i+1)); done; test $i -eq 25",
    ]
    if args.scratch_device:
        device = args.scratch_device
        checks.append(f"test -b {device}")
        if args.expect_scratch_data:
            checks.append(f"test $(dd if={device} bs=1 count=14) = EDGEOS-DISK-V1")
        checks.extend([
            "dd if=/dev/zero of=/tmp/disk-sector bs=512 count=1 && "
            "printf EDGEOS-DISK-V1 | dd of=/tmp/disk-sector conv=notrunc",
            f"dd if=/tmp/disk-sector of={device} bs=512 count=1 && sync",
            f"test $(dd if={device} bs=512 count=1 | sha256sum | cut -d ' ' -f 1) "
            "= $(sha256sum /tmp/disk-sector | cut -d ' ' -f 1)",
        ])
    for index, command in enumerate(checks):
        channel.sendall(f"{command}; echo MEMORY_CHECK_{index}_$?\n".encode())
        result = receive(rf"\nMEMORY_CHECK_{index}_([0-9]+)\n")
        if result.group(1) != "0":
            raise RuntimeError(f"Guest check {index} failed with status {result.group(1)}")
        receive(r"# ")
    print(json.dumps({"stage": "shell_checks", "status": "pass",
                      "elapsed_seconds": time.monotonic() - started}), flush=True)
    channel.sendall(b"sync; poweroff\n")
    while time.monotonic() < deadline:
        try:
            data = channel.recv(8192)
        except socket.timeout:
            continue
        if not data:
            print(json.dumps({"stage": "serial_disconnect",
                              "elapsed_seconds": time.monotonic() - started}), flush=True)
            return
        print(data.decode("utf-8", errors="replace"), end="", flush=True)
    raise TimeoutError("Guest did not finish poweroff; verify hypervisor exit separately")


if __name__ == "__main__":
    main()
