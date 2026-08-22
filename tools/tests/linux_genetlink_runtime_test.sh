#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

python3 - <<'PY'
import errno
import socket
import struct

NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_DUMP = 0x300
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_VERSION = 3
CTRL_ATTR_HDRSIZE = 4
CTRL_ATTR_MAXATTR = 5
CTRL_ATTR_OPS = 6
NLA_F_NESTED = 0x8000
ETHTOOL_MSG_LINKINFO_GET = 2
ETHTOOL_MSG_LINKMODES_GET = 4
ETHTOOL_MSG_LINKSTATE_GET = 6
ETHTOOL_MSG_CHANNELS_GET = 17
ETHTOOL_MSG_STATS_GET = 32
ETHTOOL_A_HEADER = 1
ETHTOOL_A_HEADER_DEV_INDEX = 1
ETHTOOL_A_HEADER_DEV_NAME = 2
ETHTOOL_A_STATS_HEADER = 2
ETHTOOL_A_STATS_GROUPS = 3
ETHTOOL_A_STATS_GRP = 4
ETHTOOL_A_STATS_SRC = 5


def align4(value):
    return (value + 3) & ~3


def attribute(kind, payload):
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + bytes(align4(length) - length)


def ctrl_request(sequence, flags, selector=b""):
    generic = struct.pack("=BBH", CTRL_CMD_GETFAMILY, 2, 0)
    length = 16 + len(generic) + len(selector)
    return struct.pack("=IHHII", length, GENL_ID_CTRL, flags, sequence, 0) + generic + selector


def messages(packet):
    offset = 0
    while offset + 16 <= len(packet):
        length, kind, flags, sequence, port_id = struct.unpack_from("=IHHII", packet, offset)
        if length < 16 or offset + length > len(packet):
            raise AssertionError("malformed netlink reply")
        yield kind, flags, sequence, port_id, packet[offset + 16:offset + length]
        offset += align4(length)


def parse_attributes(payload, offset=0):
    values = {}
    while offset + 4 <= len(payload):
        length, kind = struct.unpack_from("=HH", payload, offset)
        assert length >= 4 and offset + length <= len(payload)
        values[kind & 0x3fff] = (kind, payload[offset + 4:offset + length])
        offset += align4(length)
    return values


def parse_family(payload, expected_name):
    command, version, reserved = struct.unpack_from("=BBH", payload, 0)
    assert command == CTRL_CMD_NEWFAMILY
    assert version == 2
    assert reserved == 0
    values = parse_attributes(payload, 4)
    family_id = struct.unpack("=H", values[CTRL_ATTR_FAMILY_ID][1])[0]
    assert values[CTRL_ATTR_FAMILY_NAME][1].rstrip(b"\0") == expected_name
    expected_version = 2 if expected_name == b"nlctrl" else 1
    expected_maxattr = 10 if expected_name == b"nlctrl" else 0
    assert struct.unpack("=I", values[CTRL_ATTR_VERSION][1])[0] == expected_version
    assert struct.unpack("=I", values[CTRL_ATTR_HDRSIZE][1])[0] == 0
    assert struct.unpack("=I", values[CTRL_ATTR_MAXATTR][1])[0] == expected_maxattr
    assert values[CTRL_ATTR_OPS][0] & NLA_F_NESTED
    return family_id


def generic_request(family_id, command, sequence, flags, attributes):
    generic = struct.pack("=BBH", command, 1, 0)
    length = 16 + len(generic) + len(attributes)
    header = struct.pack("=IHHII", length, family_id, flags, sequence, 0)
    return header + generic + attributes


def parse_ethtool(payload, expected_command, expected_name):
    command, version, reserved = struct.unpack_from("=BBH", payload, 0)
    assert command == expected_command and version == 1 and reserved == 0
    values = parse_attributes(payload, 4)
    assert values[ETHTOOL_A_HEADER][0] & NLA_F_NESTED
    header = parse_attributes(values[ETHTOOL_A_HEADER][1])
    assert struct.unpack("=I", header[ETHTOOL_A_HEADER_DEV_INDEX][1])[0] > 0
    assert header[ETHTOOL_A_HEADER_DEV_NAME][1].rstrip(b"\0") == expected_name
    return values


sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
sock.settimeout(2.0)
sock.bind((0, 0))
port_id = sock.getsockname()[0]

name = attribute(CTRL_ATTR_FAMILY_NAME, b"nlctrl\0")
sock.sendto(ctrl_request(101, NLM_F_REQUEST, name), (0, 0))
reply = list(messages(sock.recv(65535)))
assert len(reply) == 1
kind, flags, sequence, reply_port, payload = reply[0]
assert kind == GENL_ID_CTRL and flags == 0 and sequence == 101
assert reply_port == port_id
assert parse_family(payload, b"nlctrl") == GENL_ID_CTRL

ethtool_name = attribute(CTRL_ATTR_FAMILY_NAME, b"ethtool\0")
sock.sendto(ctrl_request(102, NLM_F_REQUEST, ethtool_name), (0, 0))
ethtool_reply = list(messages(sock.recv(65535)))
assert len(ethtool_reply) == 1 and ethtool_reply[0][0] == GENL_ID_CTRL
ethtool_family = parse_family(ethtool_reply[0][4], b"ethtool")
assert ethtool_family >= 19

sock.sendto(ctrl_request(103, NLM_F_REQUEST | NLM_F_DUMP), (0, 0))
dump = list(messages(sock.recv(65535)))
assert len(dump) == 3
assert dump[0][0] == GENL_ID_CTRL and dump[0][1] & NLM_F_MULTI
assert dump[0][2] == 103 and dump[0][3] == port_id
assert parse_family(dump[0][4], b"nlctrl") == GENL_ID_CTRL
assert parse_family(dump[1][4], b"ethtool") == ethtool_family
assert dump[2][0] == NLMSG_DONE and dump[2][2] == 103

device_header = attribute(
    ETHTOOL_A_HEADER | NLA_F_NESTED,
    attribute(ETHTOOL_A_HEADER_DEV_NAME, b"eth0\0"),
)
sock.sendto(generic_request(
    ethtool_family, ETHTOOL_MSG_LINKINFO_GET, 104,
    NLM_F_REQUEST, device_header), (0, 0))
linkinfo = list(messages(sock.recv(65535)))
assert len(linkinfo) == 1 and linkinfo[0][0] == ethtool_family
assert linkinfo[0][2] == 104 and linkinfo[0][3] == port_id
linkinfo_values = parse_ethtool(
    linkinfo[0][4], ETHTOOL_MSG_LINKINFO_GET, b"eth0")
assert linkinfo_values[2][1] == b"\xff"

sock.sendto(generic_request(
    ethtool_family, ETHTOOL_MSG_LINKMODES_GET, 108,
    NLM_F_REQUEST, device_header), (0, 0))
linkmodes = list(messages(sock.recv(65535)))
assert len(linkmodes) == 1 and linkmodes[0][0] == ethtool_family
linkmodes_values = parse_ethtool(
    linkmodes[0][4], ETHTOOL_MSG_LINKMODES_GET, b"eth0")
assert struct.unpack("=I", linkmodes_values[5][1])[0] == 0xffffffff
assert linkmodes_values[6][1] == b"\xff"

sock.sendto(generic_request(
    ethtool_family, ETHTOOL_MSG_LINKSTATE_GET, 105,
    NLM_F_REQUEST, device_header), (0, 0))
linkstate = list(messages(sock.recv(65535)))
assert len(linkstate) == 1 and linkstate[0][0] == ethtool_family
linkstate_values = parse_ethtool(
    linkstate[0][4], ETHTOOL_MSG_LINKSTATE_GET, b"eth0")
assert linkstate_values[2][1] in (b"\0", b"\1")

sock.sendto(generic_request(
    ethtool_family, ETHTOOL_MSG_CHANNELS_GET, 109,
    NLM_F_REQUEST, device_header), (0, 0))
channels = list(messages(sock.recv(65535)))
assert len(channels) == 1 and channels[0][0] == ethtool_family
channel_values = parse_ethtool(
    channels[0][4], ETHTOOL_MSG_CHANNELS_GET, b"eth0")
assert struct.unpack("=I", channel_values[5][1])[0] == 1
assert struct.unpack("=I", channel_values[9][1])[0] == 1

stats_header = attribute(
    ETHTOOL_A_STATS_HEADER | NLA_F_NESTED,
    attribute(ETHTOOL_A_HEADER_DEV_NAME, b"eth0\0"),
)
stats_groups = attribute(
    ETHTOOL_A_STATS_GROUPS | NLA_F_NESTED,
    attribute(1, b"") +
    attribute(2, struct.pack("=I", 5)) +
    attribute(4, struct.pack("=I", 1 << 1)),
)
sock.sendto(generic_request(
    ethtool_family, ETHTOOL_MSG_STATS_GET, 110,
    NLM_F_REQUEST, stats_header + stats_groups), (0, 0))
stats = list(messages(sock.recv(65535)))
assert len(stats) == 1 and stats[0][0] == ethtool_family
stats_values = parse_attributes(stats[0][4], 4)
assert stats_values[ETHTOOL_A_STATS_HEADER][0] & NLA_F_NESTED
stats_reply_header = parse_attributes(
    stats_values[ETHTOOL_A_STATS_HEADER][1])
assert stats_reply_header[ETHTOOL_A_HEADER_DEV_NAME][1].rstrip(b"\0") == b"eth0"
assert struct.unpack("=I", stats_values[ETHTOOL_A_STATS_SRC][1])[0] == 0
stats_group = parse_attributes(stats_values[ETHTOOL_A_STATS_GRP][1])
assert struct.unpack("=I", stats_group[2][1])[0] == 1
assert struct.unpack("=I", stats_group[3][1])[0] == 18
last_mac_stat = parse_attributes(stats_group[4][1])
assert 12 in last_mac_stat and len(last_mac_stat[12][1]) == 8

empty_header = attribute(ETHTOOL_A_HEADER | NLA_F_NESTED, b"")
sock.sendto(generic_request(
    ethtool_family, ETHTOOL_MSG_LINKSTATE_GET, 106,
    NLM_F_REQUEST | NLM_F_DUMP, empty_header), (0, 0))
link_dump = list(messages(sock.recv(65535)))
assert link_dump[-1][0] == NLMSG_DONE and link_dump[-1][2] == 106
dump_names = []
for item in link_dump[:-1]:
    assert item[0] == ethtool_family and item[1] & NLM_F_MULTI
    values = parse_attributes(item[4], 4)
    header = parse_attributes(values[ETHTOOL_A_HEADER][1])
    dump_names.append(header[ETHTOOL_A_HEADER_DEV_NAME][1].rstrip(b"\0"))
assert b"eth0" in dump_names

unknown = attribute(CTRL_ATTR_FAMILY_NAME, b"edgeos-unknown\0")
sock.sendto(ctrl_request(107, NLM_F_REQUEST, unknown), (0, 0))
error_reply = list(messages(sock.recv(65535)))
assert len(error_reply) == 1 and error_reply[0][0] == NLMSG_ERROR
error = struct.unpack_from("=i", error_reply[0][4], 0)[0]
assert error == -errno.ENOENT

print("EDGE_GENL_CTRL_PASS")
print("EDGE_ETHTOOL_GENL_PASS")
PY
