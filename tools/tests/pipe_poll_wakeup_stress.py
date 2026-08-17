#!/usr/bin/env python3
"""Exercise Linux pipe readiness transitions through poll and epoll."""

from __future__ import annotations

import errno
import fcntl
import os
import select
import signal
import time


TIMEOUT_MS = 5_000


def wait_child(pid: int) -> None:
    waited, status = os.waitpid(pid, 0)
    if waited != pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise RuntimeError(f"child {pid} failed with status {status:#x}")


def delayed_write(write_fd: int, payload: bytes = b"E") -> int:
    pid = os.fork()
    if pid == 0:
        try:
            time.sleep(0.02)
            os.write(write_fd, payload)
            os._exit(0)
        except BaseException:
            os._exit(1)
    return pid


def poll_read_wakeup() -> None:
    read_fd, write_fd = os.pipe()
    pid = delayed_write(write_fd)
    poller = select.poll()
    poller.register(read_fd, select.POLLIN | select.POLLHUP)
    events = poller.poll(TIMEOUT_MS)
    if events != [(read_fd, select.POLLIN)]:
        raise RuntimeError(f"poll read wake returned {events!r}")
    if os.read(read_fd, 1) != b"E":
        raise RuntimeError("poll read payload mismatch")
    wait_child(pid)
    os.close(read_fd)
    os.close(write_fd)


def epoll_read_and_hup_wakeup() -> None:
    read_fd, write_fd = os.pipe()
    epoll = select.epoll()
    epoll.register(read_fd, select.EPOLLIN | select.EPOLLHUP | select.EPOLLET)
    pid = delayed_write(write_fd)
    events = epoll.poll(TIMEOUT_MS / 1_000)
    if not events or events[0][0] != read_fd or not events[0][1] & select.EPOLLIN:
        raise RuntimeError(f"epoll read wake returned {events!r}")
    if os.read(read_fd, 1) != b"E":
        raise RuntimeError("epoll read payload mismatch")
    wait_child(pid)
    os.close(write_fd)
    events = epoll.poll(TIMEOUT_MS / 1_000)
    if not events or events[0][0] != read_fd or not events[0][1] & select.EPOLLHUP:
        raise RuntimeError(f"epoll HUP wake returned {events!r}")
    epoll.close()
    os.close(read_fd)


def epoll_write_wakeup() -> None:
    read_fd, write_fd = os.pipe()
    fcntl.fcntl(write_fd, fcntl.F_SETFL,
                fcntl.fcntl(write_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
    block = b"W" * 4096
    while True:
        try:
            os.write(write_fd, block)
        except BlockingIOError:
            break
    epoll = select.epoll()
    epoll.register(write_fd, select.EPOLLOUT | select.EPOLLET)
    pid = os.fork()
    if pid == 0:
        try:
            time.sleep(0.02)
            if len(os.read(read_fd, len(block))) != len(block):
                os._exit(1)
            os._exit(0)
        except BaseException:
            os._exit(1)
    events = epoll.poll(TIMEOUT_MS / 1_000)
    if not events or events[0][0] != write_fd or not events[0][1] & select.EPOLLOUT:
        raise RuntimeError(f"epoll write wake returned {events!r}")
    wait_child(pid)
    epoll.close()
    os.close(read_fd)
    os.close(write_fd)


def nested_epoll_wakeup() -> None:
    read_fd, write_fd = os.pipe()
    inner = select.epoll()
    outer = select.epoll()
    inner.register(read_fd, select.EPOLLIN | select.EPOLLET)
    outer.register(inner.fileno(), select.EPOLLIN | select.EPOLLET)
    pid = delayed_write(write_fd, b"N")
    outer_events = outer.poll(TIMEOUT_MS / 1_000)
    inner_events = inner.poll(0)
    if (not outer_events or outer_events[0][0] != inner.fileno() or
            not outer_events[0][1] & select.EPOLLIN):
        raise RuntimeError(f"outer epoll wake returned {outer_events!r}")
    if (not inner_events or inner_events[0][0] != read_fd or
            not inner_events[0][1] & select.EPOLLIN):
        raise RuntimeError(f"inner epoll wake returned {inner_events!r}")
    if os.read(read_fd, 1) != b"N":
        raise RuntimeError("nested epoll payload mismatch")
    wait_child(pid)
    outer.close()
    inner.close()
    os.close(read_fd)
    os.close(write_fd)


def broken_pipe_semantics() -> None:
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    previous = signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    try:
        try:
            os.write(write_fd, b"B")
        except BrokenPipeError as error:
            if error.errno != errno.EPIPE:
                raise
        else:
            raise RuntimeError("write with no readers unexpectedly succeeded")
    finally:
        signal.signal(signal.SIGPIPE, previous)
        os.close(write_fd)


def main() -> int:
    signal.alarm(30)
    poll_read_wakeup()
    epoll_read_and_hup_wakeup()
    epoll_write_wakeup()
    nested_epoll_wakeup()
    broken_pipe_semantics()
    signal.alarm(0)
    print("pipe_poll_wakeup_stress: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
