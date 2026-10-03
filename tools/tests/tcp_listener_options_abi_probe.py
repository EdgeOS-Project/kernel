#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise option changes after listen and their accepted-socket inheritance."""

import socket


def probe(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((address, 0))
        listener.listen(4)
        for iteration in range(32):
            nodelay = iteration % 2
            listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, nodelay)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for option, value in ((socket.TCP_KEEPIDLE, 31),
                                  (socket.TCP_KEEPINTVL, 7),
                                  (socket.TCP_KEEPCNT, 3)):
                listener.setsockopt(socket.IPPROTO_TCP, option, value)
            if family == socket.AF_INET:
                listener.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(listener.getsockname())
                with listener.accept()[0] as accepted:
                    accepted.settimeout(5)
                    assert accepted.getsockopt(socket.IPPROTO_TCP,
                                               socket.TCP_NODELAY) == nodelay
                    assert accepted.getsockopt(socket.SOL_SOCKET,
                                               socket.SO_KEEPALIVE) == 1
                    for option, value in ((socket.TCP_KEEPIDLE, 31),
                                          (socket.TCP_KEEPINTVL, 7),
                                          (socket.TCP_KEEPCNT, 3)):
                        assert accepted.getsockopt(socket.IPPROTO_TCP, option) == value
                    client.sendall(b"listener options")
                    assert accepted.recv(64) == b"listener options"
                    accepted.sendall(b"accepted")
                    assert client.recv(64) == b"accepted"
        print(f"PASS: {family.name}, 32 post-listen option updates and connections")


if __name__ == "__main__":
    probe(socket.AF_INET, "127.0.0.1")
    probe(socket.AF_INET6, "::1")
