#!/usr/bin/env python3
"""Validate Linux nonblocking TCP connect readiness and SO_ERROR semantics."""

from __future__ import annotations

import argparse
import errno
import select
import socket


CONNECT_PENDING = {
    errno.EINPROGRESS,
    errno.EALREADY,
    errno.EWOULDBLOCK,
}


def begin_connect(host: str, port: int) -> tuple[socket.socket, int]:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setblocking(False)
    result = connection.connect_ex((host, port))
    if result not in CONNECT_PENDING and result != 0:
        connection.close()
        raise RuntimeError(
            f"connect_ex({host}:{port}) returned immediate errno {result}"
        )
    return connection, result


def wait_for_completion(connection: socket.socket) -> int:
    poller = select.epoll()
    try:
        poller.register(
            connection.fileno(),
            select.EPOLLIN | select.EPOLLOUT | select.EPOLLET,
        )
        events = poller.poll(8.0)
    finally:
        poller.close()
    if not events:
        raise RuntimeError("nonblocking connect did not complete within 8 seconds")
    event_mask = events[0][1]
    if not event_mask & select.EPOLLOUT:
        raise RuntimeError(
            f"completed connect omitted EPOLLOUT: mask=0x{event_mask:x}"
        )
    return event_mask


def successful_connect(host: str, port: int) -> None:
    connection, initial = begin_connect(host, port)
    try:
        event_mask = wait_for_completion(connection)
        socket_error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if socket_error:
            raise RuntimeError(
                f"successful connect reported SO_ERROR={socket_error}"
            )
        print(
            "socket connect success:"
            f" initial={initial} events=0x{event_mask:x} so_error={socket_error}"
        )
    finally:
        connection.close()


def refused_connect(host: str, port: int) -> None:
    connection, initial = begin_connect(host, port)
    try:
        event_mask = wait_for_completion(connection)
        socket_error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if socket_error not in {
            errno.ECONNREFUSED,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
        }:
            raise RuntimeError(
                f"failed connect reported unexpected SO_ERROR={socket_error}"
            )
        consumed_error = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_ERROR
        )
        if consumed_error != 0:
            raise RuntimeError(
                f"SO_ERROR was not consumed: second value={consumed_error}"
            )
        print(
            "socket connect failure:"
            f" initial={initial} events=0x{event_mask:x}"
            f" so_error={socket_error} consumed={consumed_error}"
        )
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="10.0.2.2")
    parser.add_argument("--success-port", type=int, default=80)
    parser.add_argument("--failure-port", type=int, default=1)
    arguments = parser.parse_args()

    successful_connect(arguments.host, arguments.success_port)
    refused_connect(arguments.host, arguments.failure_port)
    print("socket_connect_readiness: PASS")


if __name__ == "__main__":
    main()
