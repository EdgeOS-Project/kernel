#!/usr/bin/env python3
"""Exercise Linux epoll lifetime, nesting, edge, and one-shot semantics."""

import errno
import ctypes
import os
import platform
import select


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def test_raw_syscall_validation_order() -> None:
    syscall_numbers = {
        "x86_64": (291, 233, 232),
        "aarch64": (20, 21, 22),
    }
    machine = platform.machine()
    require(machine in syscall_numbers, f"unsupported machine: {machine}")
    create1_number, control_number, wait_number = syscall_numbers[machine]
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long

    ctypes.set_errno(0)
    result = syscall(create1_number, 1)
    require(result == -1 and ctypes.get_errno() == errno.EINVAL,
            f"epoll_create1 invalid flags: {result}/{ctypes.get_errno()}")

    epoll_descriptor = syscall(create1_number, os.O_CLOEXEC)
    require(epoll_descriptor >= 0,
            f"epoll_create1 failed: {ctypes.get_errno()}")
    read_fd, write_fd = os.pipe()
    event_storage = ctypes.create_string_buffer(16)

    ctypes.set_errno(0)
    result = syscall(control_number, -1, 1, read_fd,
                     ctypes.byref(event_storage))
    require(result == -1 and ctypes.get_errno() == errno.EBADF,
            f"epoll_ctl bad epoll: {result}/{ctypes.get_errno()}")
    ctypes.set_errno(0)
    result = syscall(control_number, epoll_descriptor, 1, read_fd, 0)
    require(result == -1 and ctypes.get_errno() == errno.EFAULT,
            f"epoll_ctl null event: {result}/{ctypes.get_errno()}")
    ctypes.set_errno(0)
    result = syscall(wait_number, -1, ctypes.byref(event_storage), 0, 0,
                     0, 0)
    require(result == -1 and ctypes.get_errno() == errno.EINVAL,
            f"epoll_wait validation order: {result}/{ctypes.get_errno()}")

    os.close(read_fd)
    os.close(write_fd)
    os.close(epoll_descriptor)


def test_duplicate_open_description_keys() -> None:
    read_fd, write_fd = os.pipe()
    duplicate = os.dup(read_fd)
    poller = select.epoll()
    poller.register(read_fd, select.EPOLLIN)
    poller.register(duplicate, select.EPOLLIN)
    os.write(write_fd, b"D")
    events = poller.poll(1.0, 4)
    require(len(events) == 2, f"duplicate watch count: {events!r}")
    poller.close()
    os.close(duplicate)
    os.close(read_fd)
    os.close(write_fd)


def test_close_with_live_duplicate() -> None:
    read_fd, write_fd = os.pipe()
    duplicate = os.dup(read_fd)
    poller = select.epoll()
    poller.register(read_fd, select.EPOLLIN)
    os.close(read_fd)
    os.write(write_fd, b"L")
    events = poller.poll(1.0, 1)
    require(len(events) == 1, f"watch lost after close: {events!r}")
    require(events[0][1] & select.EPOLLIN, f"missing EPOLLIN: {events!r}")
    poller.close()
    os.close(duplicate)
    os.close(write_fd)


def test_eventfd_edge_and_oneshot() -> None:
    event_fd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
    poller = select.epoll()
    poller.register(
        event_fd, select.EPOLLIN | select.EPOLLET | select.EPOLLONESHOT)
    os.eventfd_write(event_fd, 1)
    os.eventfd_write(event_fd, 2)
    require(len(poller.poll(1.0, 1)) == 1, "eventfd edge missing")
    require(poller.poll(0.0, 1) == [], "one-shot watch was not disabled")
    poller.modify(event_fd, select.EPOLLIN | select.EPOLLET)
    require(len(poller.poll(0.0, 1)) == 1, "MOD did not rearm ready fd")
    require(poller.poll(0.0, 1) == [], "unchanged edge repeated")
    require(os.eventfd_read(event_fd) == 3, "eventfd counter mismatch")
    os.eventfd_write(event_fd, 4)
    require(len(poller.poll(1.0, 1)) == 1, "new eventfd edge missing")
    poller.close()
    os.close(event_fd)


def test_nested_epoll_and_cycle_rejection() -> None:
    read_fd, write_fd = os.pipe()
    inner = select.epoll()
    outer = select.epoll()
    inner.register(read_fd, select.EPOLLIN | select.EPOLLET)
    outer.register(inner.fileno(), select.EPOLLIN | select.EPOLLET)
    os.write(write_fd, b"N")
    require(len(outer.poll(1.0, 1)) == 1, "nested outer wake missing")
    require(len(inner.poll(0.0, 1)) == 1, "nested inner wake missing")
    require(outer.poll(0.0, 1) == [], "nested stale edge repeated")
    try:
        inner.register(outer.fileno(), select.EPOLLIN)
    except OSError as error:
        require(error.errno == errno.ELOOP,
                f"nested cycle errno: {error.errno}")
    else:
        raise RuntimeError("nested epoll cycle accepted")
    outer.close()
    inner.close()
    os.close(read_fd)
    os.close(write_fd)


def test_nested_epoll_retained_by_fork() -> None:
    read_fd, write_fd = os.pipe()
    release_read, release_write = os.pipe()
    inner = select.epoll()
    outer = select.epoll()
    inner.register(read_fd, select.EPOLLIN)
    inner_descriptor = inner.fileno()
    outer.register(inner_descriptor, select.EPOLLIN)

    child = os.fork()
    if child == 0:
        try:
            outer.close()
            os.close(release_write)
            os.write(write_fd, b"F")
            if os.read(release_read, 1) != b"R":
                os._exit(1)
            os._exit(0)
        except BaseException:
            os._exit(1)

    os.close(release_read)
    inner.close()
    events = outer.poll(1.0, 1)
    require(
        len(events) == 1 and events[0][0] == inner_descriptor and
        events[0][1] & select.EPOLLIN,
        f"fork-retained nested epoll wake missing: {events!r}")
    os.write(release_write, b"R")
    waited, status = os.waitpid(child, 0)
    require(
        waited == child and os.WIFEXITED(status) and
        os.WEXITSTATUS(status) == 0,
        f"fork-retained nested child failed: {status:#x}")
    outer.close()
    os.close(release_write)
    os.close(read_fd)
    os.close(write_fd)


def main() -> int:
    test_raw_syscall_validation_order()
    test_duplicate_open_description_keys()
    test_close_with_live_duplicate()
    test_eventfd_edge_and_oneshot()
    test_nested_epoll_and_cycle_rejection()
    test_nested_epoll_retained_by_fork()
    print("epoll_runtime_parity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
