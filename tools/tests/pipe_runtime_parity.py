#!/usr/bin/env python3
"""Exercise Linux pipe and FIFO behavior identically on both architectures."""

import errno
import fcntl
import os
import select
import signal
import tempfile
import threading


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def test_flags_and_capacity() -> None:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        require(fcntl.fcntl(read_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                "read descriptor lost CLOEXEC")
        require(fcntl.fcntl(write_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                "write descriptor lost CLOEXEC")
        require(fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_NONBLOCK,
                "read description lost NONBLOCK")
        require(fcntl.fcntl(write_fd, fcntl.F_GETFL) & os.O_NONBLOCK,
                "write description lost NONBLOCK")
        require(fcntl.fcntl(read_fd, fcntl.F_GETPIPE_SZ) == 65536,
                "unexpected pipe capacity")
        require(os.fpathconf(write_fd, "PC_PIPE_BUF") == 4096,
                "unexpected PIPE_BUF")
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_endpoint_lifetime() -> None:
    read_fd, write_fd = os.pipe()
    duplicate = os.dup(write_fd)
    os.close(write_fd)
    os.write(duplicate, b"live")
    require(os.read(read_fd, 4) == b"live", "duplicate writer lost data")
    os.close(duplicate)
    require(os.read(read_fd, 1) == b"", "EOF missing after final writer")
    os.close(read_fd)

    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    previous = signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    try:
        try:
            os.write(write_fd, b"x")
        except BrokenPipeError as error:
            require(error.errno == errno.EPIPE, "wrong broken-pipe errno")
        else:
            raise RuntimeError("write without readers succeeded")
    finally:
        signal.signal(signal.SIGPIPE, previous)
        os.close(write_fd)


def test_poll_transitions() -> None:
    read_fd, write_fd = os.pipe()
    poller = select.poll()
    writer_poller = select.poll()
    poller.register(read_fd, select.POLLIN | select.POLLHUP)
    writer_poller.register(write_fd, select.POLLOUT | select.POLLERR)
    require(poller.poll(0) == [], "empty pipe reported readable")
    writer_events = writer_poller.poll(0)
    require(writer_events and writer_events[0][1] & select.POLLOUT,
            f"empty pipe not writable: {writer_events!r}")
    os.write(write_fd, b"P")
    events = poller.poll(1000)
    require(events and events[0][1] & select.POLLIN,
            f"readable transition missing: {events!r}")
    require(os.read(read_fd, 1) == b"P", "poll payload mismatch")
    os.close(write_fd)
    events = poller.poll(1000)
    require(events and events[0][1] & select.POLLHUP,
            f"hangup transition missing: {events!r}")
    os.close(read_fd)

    read_fd, write_fd = os.pipe()
    writer_poller = select.poll()
    writer_poller.register(write_fd, select.POLLOUT | select.POLLERR)
    os.close(read_fd)
    writer_events = writer_poller.poll(1000)
    require(writer_events and writer_events[0][1] & select.POLLERR,
            f"reader-close error transition missing: {writer_events!r}")
    os.close(write_fd)


def test_nonblocking_atomic_admission() -> None:
    read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
    block = b"F" * 4096
    filled = 0
    while True:
        try:
            filled += os.write(write_fd, block)
        except BlockingIOError as error:
            require(error.errno == errno.EAGAIN,
                    f"full-pipe write errno: {error.errno}")
            break
    require(filled == 65536, f"unexpected fill amount: {filled}")
    require(len(os.read(read_fd, 2048)) == 2048, "short setup drain")
    try:
        os.write(write_fd, b"A" * 4096)
    except BlockingIOError as error:
        require(error.errno == errno.EAGAIN,
                f"atomic admission errno: {error.errno}")
    else:
        raise RuntimeError("partial room admitted a PIPE_BUF record")
    remaining = 0
    while True:
        try:
            chunk = os.read(read_fd, 8192)
        except BlockingIOError:
            break
        if not chunk:
            break
        remaining += len(chunk)
    require(remaining == 65536 - 2048,
            f"failed atomic write changed pipe contents: {remaining}")
    os.close(read_fd)
    os.close(write_fd)


def test_nonblocking_atomic_vector_admission() -> None:
    read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
    block = b"F" * 4096
    filled = 0
    while True:
        try:
            filled += os.write(write_fd, block)
        except BlockingIOError as error:
            require(error.errno == errno.EAGAIN,
                    f"full-pipe vector setup errno: {error.errno}")
            break
    require(filled == 65536, f"unexpected vector fill amount: {filled}")
    require(len(os.read(read_fd, 2048)) == 2048,
            "short vector setup drain")
    try:
        os.writev(write_fd, [b"A" * 2048, b"B" * 2048])
    except BlockingIOError as error:
        require(error.errno == errno.EAGAIN,
                f"atomic vector admission errno: {error.errno}")
    else:
        raise RuntimeError("partial room admitted a PIPE_BUF vector")
    remaining = bytearray()
    while True:
        try:
            chunk = os.read(read_fd, 8192)
        except BlockingIOError:
            break
        if not chunk:
            break
        remaining.extend(chunk)
    require(len(remaining) == 65536 - 2048,
            f"failed atomic vector changed pipe length: {len(remaining)}")
    require(set(remaining) <= {ord("F")},
            "failed atomic vector changed pipe contents")
    os.close(read_fd)
    os.close(write_fd)


def test_large_wraparound_transfer() -> None:
    read_fd, write_fd = os.pipe()
    payload = bytes((index * 37 + 11) & 0xff for index in range(200000))
    failure = []

    def writer() -> None:
        try:
            position = 0
            while position < len(payload):
                position += os.write(write_fd, payload[position:])
        except BaseException as error:
            failure.append(error)
        finally:
            os.close(write_fd)

    thread = threading.Thread(target=writer)
    thread.start()
    received = bytearray()
    while True:
        chunk = os.read(read_fd, 7777)
        if not chunk:
            break
        received.extend(chunk)
    thread.join()
    os.close(read_fd)
    require(not failure, f"writer failed: {failure!r}")
    require(bytes(received) == payload, "large wrapped transfer corrupted")


def test_atomic_records() -> None:
    read_fd, write_fd = os.pipe()
    record_size = 128
    count = 200
    failure = []

    def writer(byte: bytes) -> None:
        try:
            for _ in range(count):
                require(os.write(write_fd, byte * record_size) == record_size,
                        "atomic record was short")
        except BaseException as error:
            failure.append(error)

    threads = [
        threading.Thread(target=writer, args=(b"A",)),
        threading.Thread(target=writer, args=(b"B",)),
    ]
    for thread in threads:
        thread.start()
    records = []
    pending = bytearray()
    while len(records) < count * len(threads):
        pending.extend(os.read(read_fd, 4096))
        while len(pending) >= record_size:
            records.append(bytes(pending[:record_size]))
            del pending[:record_size]
    for thread in threads:
        thread.join()
    os.close(read_fd)
    os.close(write_fd)
    require(not failure, f"atomic writer failed: {failure!r}")
    require(not pending, "partial atomic record remained")
    require(all(record in (b"A" * record_size, b"B" * record_size)
                for record in records),
            "PIPE_BUF records interleaved")


def test_atomic_vector_records() -> None:
    read_fd, write_fd = os.pipe()
    segment_size = 64
    record_size = segment_size * 2
    count = 200
    failure = []

    def writer(byte: bytes) -> None:
        try:
            vector = [byte * segment_size, byte * segment_size]
            for _ in range(count):
                require(os.writev(write_fd, vector) == record_size,
                        "atomic vector record was short")
        except BaseException as error:
            failure.append(error)

    threads = [
        threading.Thread(target=writer, args=(b"C",)),
        threading.Thread(target=writer, args=(b"D",)),
    ]
    for thread in threads:
        thread.start()
    records = []
    pending = bytearray()
    while len(records) < count * len(threads):
        pending.extend(os.read(read_fd, 4096))
        while len(pending) >= record_size:
            records.append(bytes(pending[:record_size]))
            del pending[:record_size]
    for thread in threads:
        thread.join()
    os.close(read_fd)
    os.close(write_fd)
    require(not failure, f"atomic vector writer failed: {failure!r}")
    require(not pending, "partial atomic vector record remained")
    require(all(record in (b"C" * record_size, b"D" * record_size)
                for record in records),
            "PIPE_BUF vector records interleaved")


def test_named_fifo_open_policy() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "fifo")
        os.mkfifo(path, 0o600)
        try:
            os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as error:
            require(error.errno == errno.ENXIO,
                    f"FIFO writer without reader: {error.errno}")
        else:
            raise RuntimeError("FIFO writer opened without reader")
        read_fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        write_fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        os.write(write_fd, b"fifo")
        require(os.read(read_fd, 4) == b"fifo", "FIFO payload mismatch")
        os.close(write_fd)
        os.close(read_fd)


def test_named_fifo_blocking_rendezvous() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "fifo")
        os.mkfifo(path, 0o600)
        opened = threading.Event()
        failure: list[BaseException] = []

        def reader() -> None:
            try:
                read_fd = os.open(path, os.O_RDONLY)
                opened.set()
                require(os.read(read_fd, 1) == b"R",
                        "blocking FIFO reader payload mismatch")
                os.close(read_fd)
            except BaseException as error:
                failure.append(error)
                opened.set()

        thread = threading.Thread(target=reader)
        thread.start()
        require(not opened.wait(0.05),
                "blocking FIFO reader opened without a writer")
        write_fd = os.open(path, os.O_WRONLY)
        require(opened.wait(1.0),
                "blocking FIFO reader did not rendezvous with a writer")
        os.write(write_fd, b"R")
        os.close(write_fd)
        thread.join(1.0)
        require(not thread.is_alive(), "blocking FIFO reader did not finish")
        require(not failure, f"blocking FIFO reader failed: {failure!r}")

        opened.clear()
        failure.clear()

        def writer() -> None:
            try:
                writer_fd = os.open(path, os.O_WRONLY)
                opened.set()
                os.write(writer_fd, b"W")
                os.close(writer_fd)
            except BaseException as error:
                failure.append(error)
                opened.set()

        thread = threading.Thread(target=writer)
        thread.start()
        require(not opened.wait(0.05),
                "blocking FIFO writer opened without a reader")
        read_fd = os.open(path, os.O_RDONLY)
        require(opened.wait(1.0),
                "blocking FIFO writer did not rendezvous with a reader")
        require(os.read(read_fd, 1) == b"W",
                "blocking FIFO writer payload mismatch")
        os.close(read_fd)
        thread.join(1.0)
        require(not thread.is_alive(), "blocking FIFO writer did not finish")
        require(not failure, f"blocking FIFO writer failed: {failure!r}")


def main() -> int:
    test_flags_and_capacity()
    test_endpoint_lifetime()
    test_poll_transitions()
    test_nonblocking_atomic_admission()
    test_nonblocking_atomic_vector_admission()
    test_large_wraparound_transfer()
    test_atomic_records()
    test_atomic_vector_records()
    test_named_fifo_open_policy()
    test_named_fifo_blocking_rendezvous()
    print("pipe_runtime_parity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
