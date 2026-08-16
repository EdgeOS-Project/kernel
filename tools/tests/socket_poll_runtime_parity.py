#!/usr/bin/env python3
"""Exercise Linux socket poll transitions identically on both architectures."""

from __future__ import annotations

import errno
import select
import signal
import socket


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def poll_mask(endpoint: socket.socket, events: int, timeout_ms: int = 1000) -> int:
    poller = select.poll()
    poller.register(endpoint.fileno(), events)
    ready = poller.poll(timeout_ms)
    return ready[0][1] if ready else 0


def test_stream_data_and_shutdown() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    requested = (
        select.POLLIN
        | select.POLLOUT
        | select.POLLERR
        | select.POLLHUP
        | select.POLLRDHUP
    )
    try:
        initial = poll_mask(left, requested, 0)
        require(initial & select.POLLOUT,
                f"new stream socket omitted POLLOUT: 0x{initial:x}")
        require(not initial & (select.POLLIN | select.POLLRDHUP),
                f"new stream socket reported read state: 0x{initial:x}")

        right.sendall(b"socket-poll")
        readable = poll_mask(left, requested)
        require(readable & select.POLLIN,
                f"stream payload omitted POLLIN: 0x{readable:x}")
        require(left.recv(11) == b"socket-poll", "stream payload mismatch")

        right.shutdown(socket.SHUT_WR)
        shutdown = poll_mask(left, requested)
        require(shutdown & select.POLLIN,
                f"stream EOF omitted POLLIN: 0x{shutdown:x}")
        require(shutdown & select.POLLRDHUP,
                f"stream EOF omitted POLLRDHUP: 0x{shutdown:x}")
        require(left.recv(1) == b"", "stream EOF read returned data")
    finally:
        right.close()
        left.close()


def test_broken_stream_write() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    try:
        right.close()
        events = poll_mask(left, select.POLLOUT | select.POLLERR |
                           select.POLLHUP | select.POLLRDHUP)
        require(events & (select.POLLHUP | select.POLLERR),
                f"closed peer omitted error or hangup: 0x{events:x}")
        try:
            left.send(b"x")
        except BrokenPipeError as error:
            require(error.errno == errno.EPIPE,
                    f"broken stream write errno: {error.errno}")
        else:
            raise RuntimeError("broken stream write succeeded")
    finally:
        signal.signal(signal.SIGPIPE, previous)
        left.close()


def test_datagram_readiness() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        initial = poll_mask(left, select.POLLIN | select.POLLOUT, 0)
        require(initial & select.POLLOUT,
                f"new datagram socket omitted POLLOUT: 0x{initial:x}")
        right.send(b"D")
        readable = poll_mask(left, select.POLLIN | select.POLLOUT)
        require(readable & select.POLLIN,
                f"datagram payload omitted POLLIN: 0x{readable:x}")
        require(left.recv(1) == b"D", "datagram payload mismatch")
    finally:
        right.close()
        left.close()


def main() -> int:
    test_stream_data_and_shutdown()
    test_broken_stream_write()
    test_datagram_readiness()
    print("socket_poll_runtime_parity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
