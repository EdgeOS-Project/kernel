#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS Linux TUN/TAP runtime acceptance test.

set -eu

python3 - <<'PY'
import fcntl
import os
import select
import socket
import struct
import subprocess
import time

TUNSETIFF = 0x400454CA
TUNGETIFF = 0x800454D2
TUNSETQUEUE = 0x400454D9
TUNSETIFINDEX = 0x400454DA
TUNSETCARRIER = 0x400454E2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_MULTI_QUEUE = 0x0100
IFF_ATTACH_QUEUE = 0x0200
IFF_DETACH_QUEUE = 0x0400
IFF_NO_PI = 0x1000


def checksum(payload):
    if len(payload) & 1:
        payload += b"\0"
    words = struct.unpack("!%dH" % (len(payload) // 2), payload)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def create_interface(pattern, flags):
    descriptor = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    request = struct.pack("16sH22x", pattern.encode(), flags)
    response = fcntl.ioctl(descriptor, TUNSETIFF, request)
    name = response[:16].split(b"\0", 1)[0].decode()
    return descriptor, name


def read_matching_packet(descriptor, predicate, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    observed = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            summary = ",".join(packet[:32].hex() for packet in observed[-4:])
            raise SystemExit("TUN matching reply timed out: " + summary)
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            continue
        packet = os.read(descriptor, 2048)
        observed.append(packet)
        if predicate(packet):
            return packet


tun, tun_name = create_interface("edge-tun%d", IFF_TUN | IFF_NO_PI)
tap, tap_name = create_interface("edge-tap%d", IFF_TAP | IFF_NO_PI)
multi_first = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
requested_ifindex = 12345
fcntl.ioctl(multi_first, TUNSETIFINDEX, struct.pack("I", requested_ifindex))
multi_request = struct.pack(
    "16sH22x", b"edge-mq0", IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE
)
multi_response = fcntl.ioctl(multi_first, TUNSETIFF, multi_request)
multi_name = multi_response[:16].split(b"\0", 1)[0].decode()
multi_second, second_name = create_interface(
    multi_name, IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE
)
try:
    if second_name != multi_name:
        raise SystemExit("TUN multi-queue descriptors selected different devices")
    if socket.if_nametoindex(multi_name) != requested_ifindex:
        raise SystemExit("TUN requested ifindex was not preserved")
    subprocess.check_call(["ip", "link", "set", "dev", multi_name, "up"])
    fcntl.ioctl(multi_first, TUNSETCARRIER, struct.pack("I", 0))
    link_output = subprocess.check_output(
        ["ip", "link", "show", "dev", multi_name], text=True
    )
    if "LOWER_UP" in link_output:
        raise SystemExit("TUN carrier-off state was not reported")
    fcntl.ioctl(multi_second, TUNSETCARRIER, struct.pack("I", 1))
    link_output = subprocess.check_output(
        ["ip", "link", "show", "dev", multi_name], text=True
    )
    if "LOWER_UP" not in link_output:
        raise SystemExit("TUN carrier-on state was not reported")
    queue_request = struct.pack("16sH22x", b"", IFF_DETACH_QUEUE)
    fcntl.ioctl(multi_first, TUNSETQUEUE, queue_request)
    detached = fcntl.ioctl(
        multi_first, TUNGETIFF, struct.pack("16sH22x", b"", 0)
    )
    if not (struct.unpack_from("H", detached, 16)[0] & IFF_DETACH_QUEUE):
        raise SystemExit("TUN detached queue state was not reported")
    queue_request = struct.pack("16sH22x", b"", IFF_ATTACH_QUEUE)
    fcntl.ioctl(multi_first, TUNSETQUEUE, queue_request)

    subprocess.check_call(["ip", "addr", "add", "198.18.0.1/24", "dev", tun_name])
    subprocess.check_call([
        "ip", "-6", "addr", "add", "fd00:198:18::1/64", "nodad",
        "dev", tun_name
    ])
    subprocess.check_call(["ip", "link", "set", "dev", tun_name, "up"])
    subprocess.check_call(["ip", "link", "set", "dev", tap_name, "up"])
    subprocess.check_call(["ip", "-details", "link", "show", "dev", tun_name])
    subprocess.check_call(["ip", "-details", "link", "show", "dev", tap_name])

    body = struct.pack("!BBHHH", 8, 0, 0, 0xED6E, 1) + b"edgeos-tun"
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    source = bytes((198, 18, 0, 2))
    destination = bytes((198, 18, 0, 1))
    total_length = 20 + len(body)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 0xED6E, 0,
        64, 1, 0, source, destination
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    os.write(tun, header + body)

    reply = read_matching_packet(
        tun,
        lambda packet: (
            len(packet) >= 28
            and packet[0] >> 4 == 4
            and packet[9] == 1
            and packet[12:16] == destination
            and packet[16:20] == source
            and packet[20] == 0
        ),
        5,
    )

    source6 = bytes.fromhex("fd000198001800000000000000000002")
    destination6 = bytes.fromhex("fd000198001800000000000000000001")
    body6 = struct.pack("!BBHHH", 128, 0, 0, 0xED6E, 2) + b"edgeos-tun6"
    pseudo_header = (
        source6 + destination6 +
        struct.pack("!I3xB", len(body6), 58)
    )
    body6 = body6[:2] + struct.pack(
        "!H", checksum(pseudo_header + body6)
    ) + body6[4:]
    header6 = struct.pack(
        "!IHBB16s16s", 6 << 28, len(body6), 58, 64,
        source6, destination6
    )
    os.write(tun, header6 + body6)

    reply6 = read_matching_packet(
        tun,
        lambda packet: (
            len(packet) >= 48
            and packet[0] >> 4 == 6
            and packet[6] == 58
            and packet[8:24] == destination6
            and packet[24:40] == source6
            and packet[40] == 129
        ),
        5,
    )
finally:
    os.close(multi_second)
    os.close(multi_first)
    os.close(tap)
    os.close(tun)

print("linux_tuntap_runtime_test: PASS")
PY
