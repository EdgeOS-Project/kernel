#!/usr/bin/env python3
"""Probe the EdgeOS ONC RPC services over UDP without mounting a filesystem."""

import argparse
import random
import socket
import struct


def rpc_null(host: str, port: int, program: int, version: int) -> None:
    xid = random.getrandbits(32)
    request = struct.pack(
        "!10I", xid, 0, 2, program, version, 0, 0, 0, 0, 0
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3.0)
        client.sendto(request, (host, port))
        response, _ = client.recvfrom(4096)
    if len(response) < 24:
        raise RuntimeError(f"short RPC reply from UDP port {port}")
    reply_xid, direction, reply_status, verifier, verifier_length = struct.unpack(
        "!5I", response[:20]
    )
    offset = 20 + ((verifier_length + 3) & ~3)
    if len(response) < offset + 4:
        raise RuntimeError(f"truncated RPC verifier from UDP port {port}")
    accept_status = struct.unpack("!I", response[offset : offset + 4])[0]
    if (
        reply_xid != xid
        or direction != 1
        or reply_status != 0
        or verifier != 0
        or accept_status != 0
    ):
        raise RuntimeError(
            f"RPC NULL rejected by UDP port {port}: "
            f"direction={direction} reply={reply_status} accept={accept_status}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--rpcbind-port", type=int, default=32111)
    parser.add_argument("--mount-port", type=int, default=32048)
    parser.add_argument("--nfs-port", type=int, default=32049)
    args = parser.parse_args()

    rpc_null(args.host, args.rpcbind_port, 100000, 2)
    rpc_null(args.host, args.mount_port, 100005, 3)
    rpc_null(args.host, args.nfs_port, 100003, 3)
    print("NFSD_RUNTIME_UDP_OK")


if __name__ == "__main__":
    main()
