#!/usr/bin/env python3
"""Validate the Linux route-netlink multipart dump contract."""

import socket
import struct


NLMSG_DONE = 3
NLMSG_ERROR = 2
NLM_F_MULTI = 0x2
NLM_F_REQUEST = 0x1
NLM_F_DUMP = 0x300


def aligned(length: int) -> int:
    return (length + 3) & ~3


def request_payload(message_type: int) -> bytes:
    if message_type == 18:  # RTM_GETLINK: struct ifinfomsg
        return struct.pack("BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0)
    if message_type == 22:  # RTM_GETADDR: struct ifaddrmsg
        return struct.pack("BBBBI", socket.AF_UNSPEC, 0, 0, 0, 0)
    if message_type == 26:  # RTM_GETROUTE: struct rtmsg
        route = struct.pack(
            "BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0
        )
        return route + struct.pack("HHI", 8, 15, 254)  # RTA_TABLE=RT_TABLE_MAIN
    if message_type == 30:  # RTM_GETNEIGH: struct ndmsg
        return struct.pack("BBHiHBB", socket.AF_UNSPEC, 0, 0, 0, 0, 0, 0)
    raise ValueError(message_type)


def verify_dump(message_type: int, sequence: int) -> None:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock.settimeout(1.0)
    sock.bind((0, 0))
    port_id, groups = sock.getsockname()
    assert port_id > 0 and groups == 0

    payload = request_payload(message_type)
    header = struct.pack(
        "IHHII",
        16 + len(payload),
        message_type,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        port_id,
    )
    assert sock.sendto(header + payload, (0, 0)) == 16 + len(payload)

    saw_done = False
    saw_payload = False
    for _ in range(8):
        packet, source = sock.recvfrom(65536)
        assert source == (0, 0), source
        packet_has_done = False
        packet_has_payload = False
        offset = 0
        while offset + 16 <= len(packet):
            length, kind, flags, reply_sequence, reply_pid = struct.unpack_from(
                "IHHII", packet, offset
            )
            assert length >= 16 and offset + length <= len(packet)
            assert reply_sequence == sequence
            assert reply_pid == port_id
            if kind == NLMSG_DONE:
                assert length >= 20
                assert flags & NLM_F_MULTI
                assert struct.unpack_from("i", packet, offset + 16)[0] == 0
                saw_done = True
                packet_has_done = True
            else:
                assert flags & NLM_F_MULTI
                saw_payload = True
                packet_has_payload = True
            offset += aligned(length)
        assert offset == len(packet)
        if message_type == 26:
            assert not (packet_has_done and packet_has_payload), (
                "RTM_GETROUTE completion must remain separately receivable"
            )
        if saw_done:
            break

    assert saw_done
    if message_type != 30:
        assert saw_payload
    sock.close()


def verify_targeted_getlink(sequence: int) -> None:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock.settimeout(1.0)
    sock.bind((0, 0))
    port_id, _ = sock.getsockname()
    payload = struct.pack("BBHiII", socket.AF_UNSPEC, 0, 0, 1, 0, 0)
    request = struct.pack(
        "IHHII", 16 + len(payload), 18, NLM_F_REQUEST, sequence, port_id
    ) + payload
    assert sock.sendto(request, (0, 0)) == len(request)
    packet, source = sock.recvfrom(65536)
    assert source == (0, 0), source
    length, kind, flags, reply_sequence, reply_pid = struct.unpack_from(
        "IHHII", packet
    )
    assert length == len(packet)
    assert kind == 16  # RTM_NEWLINK
    assert not flags & NLM_F_MULTI
    assert reply_sequence == sequence
    assert reply_pid == port_id
    assert struct.unpack_from("i", packet, 16 + 4)[0] == 1
    sock.close()


def verify_targeted_getroute(sequence: int) -> None:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock.settimeout(1.0)
    sock.bind((0, 0))
    port_id, _ = sock.getsockname()
    route = struct.pack(
        "BBBBBBBBI", socket.AF_INET, 32, 0, 0, 0, 0, 0, 0, 0
    )
    destination = struct.pack("HH4s", 8, 1, socket.inet_aton("127.0.0.1"))
    payload = route + destination
    request = struct.pack(
        "IHHII", 16 + len(payload), 26, NLM_F_REQUEST, sequence, port_id
    ) + payload
    assert sock.sendto(request, (0, 0)) == len(request)
    packet, source = sock.recvfrom(65536)
    assert source == (0, 0), source
    length, kind, flags, reply_sequence, reply_pid = struct.unpack_from(
        "IHHII", packet
    )
    assert length == len(packet)
    assert kind == 24  # RTM_NEWROUTE
    assert not flags & NLM_F_MULTI
    assert reply_sequence == sequence
    assert reply_pid == port_id

    sock.settimeout(0.05)
    try:
        extra, _ = sock.recvfrom(65536)
    except TimeoutError:
        extra = b""
    assert not extra, "targeted RTM_GETROUTE must not enqueue NLMSG_DONE"
    sock.close()


def main() -> None:
    for ordinal, message_type in enumerate((18, 22, 26, 30), start=1):
        verify_dump(message_type, 0xED000000 + ordinal)
    verify_targeted_getlink(0xED000010)
    verify_targeted_getroute(0xED000011)
    print("NETLINK_ROUTE_DUMP_PASS")


if __name__ == "__main__":
    main()
