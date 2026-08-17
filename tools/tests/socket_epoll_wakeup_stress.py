#!/usr/bin/env python3
"""Stress AF_UNIX stream wakeups through epoll in both directions."""

from __future__ import annotations

import os
import select
import signal
import socket
import time


ROUNDS = 10_000
TIMEOUT_SECONDS = 5.0


def read_exact(endpoint: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = endpoint.recv(length - len(result))
        if not chunk:
            raise RuntimeError("unexpected AF_UNIX stream EOF")
        result.extend(chunk)
    return bytes(result)


def listener_epoll_wakeup() -> None:
    path = f"/tmp/edgeos-epoll-listener-{os.getpid()}"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.setblocking(False)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    listener.bind(path)
    listener.listen(4)
    epoll = select.epoll()
    epoll.register(listener.fileno(), select.EPOLLIN | select.EPOLLET)
    pid = os.fork()
    if pid == 0:
        try:
            listener.close()
            time.sleep(0.02)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(path)
            client.sendall(b"L")
            client.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    events = epoll.poll(TIMEOUT_SECONDS)
    if (not events or events[0][0] != listener.fileno() or
            not events[0][1] & select.EPOLLIN):
        raise RuntimeError(f"listener epoll event mismatch: {events!r}")
    accepted, _ = listener.accept()
    if read_exact(accepted, 1) != b"L":
        raise RuntimeError("listener payload mismatch")
    accepted.close()
    waited, status = os.waitpid(pid, 0)
    if waited != pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise RuntimeError(f"listener child failed with status {status:#x}")
    epoll.close()
    listener.close()
    os.unlink(path)


def main() -> int:
    listener_epoll_wakeup()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            epoll = select.epoll()
            epoll.register(child.fileno(), select.EPOLLIN | select.EPOLLET)
            for expected in range(ROUNDS):
                events = epoll.poll(TIMEOUT_SECONDS)
                if (not events or events[0][0] != child.fileno() or
                        not events[0][1] & select.EPOLLIN):
                    raise RuntimeError(f"child epoll event mismatch: {events!r}")
                value = read_exact(child, 1)
                if value[0] != expected & 0xFF:
                    raise RuntimeError("child payload mismatch")
                child.sendall(value)
            epoll.close()
            child.close()
            os._exit(0)
        except BaseException:
            os._exit(1)

    child.close()
    signal.alarm(60)
    epoll = select.epoll()
    epoll.register(parent.fileno(), select.EPOLLIN | select.EPOLLET)
    started = time.monotonic_ns()
    for expected in range(ROUNDS):
        value = bytes((expected & 0xFF,))
        parent.sendall(value)
        events = epoll.poll(TIMEOUT_SECONDS)
        if (not events or events[0][0] != parent.fileno() or
                not events[0][1] & select.EPOLLIN):
            raise RuntimeError(f"parent epoll event mismatch: {events!r}")
        if read_exact(parent, 1) != value:
            raise RuntimeError("parent payload mismatch")
    elapsed = time.monotonic_ns() - started
    waited, status = os.waitpid(pid, 0)
    if waited != pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise RuntimeError(f"child failed with status {status:#x}")
    epoll.close()
    parent.close()
    signal.alarm(0)
    print(
        "socket_epoll_wakeup_stress: PASS "
        f"rounds={ROUNDS} ns_per_round={elapsed // ROUNDS}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
