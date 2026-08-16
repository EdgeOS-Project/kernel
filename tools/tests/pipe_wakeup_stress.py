#!/usr/bin/env python3
"""Stress Linux-compatible blocking pipe wakeups in both directions."""

from __future__ import annotations

import hashlib
import os
import signal
import sys


ROUNDS = 20_000
BULK_SIZE = 8 * 1024 * 1024


def read_exact(fd: int, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise RuntimeError(f"unexpected pipe EOF with {remaining} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def ping_pong() -> None:
    parent_read, child_write = os.pipe()
    child_read, parent_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(parent_read)
            os.close(parent_write)
            for expected in range(ROUNDS):
                value = read_exact(child_read, 1)
                if value[0] != expected & 0xFF:
                    raise RuntimeError("pipe ping-pong payload mismatch")
                os.write(child_write, value)
            os._exit(0)
        except BaseException as error:
            print(f"pipe_wakeup_stress child: {error}", file=sys.stderr)
            os._exit(1)

    os.close(child_read)
    os.close(child_write)
    for expected in range(ROUNDS):
        value = bytes((expected & 0xFF,))
        os.write(parent_write, value)
        if read_exact(parent_read, 1) != value:
            raise RuntimeError("pipe ping-pong response mismatch")
    os.close(parent_write)
    os.close(parent_read)
    waited, status = os.waitpid(pid, 0)
    if waited != pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise RuntimeError(f"pipe ping-pong child status {status:#x}")


def backpressure() -> None:
    read_fd, write_fd = os.pipe()
    source = (b"EdgeOS-pipe-wakeup\0" * ((BULK_SIZE // 19) + 1))[:BULK_SIZE]
    expected_digest = hashlib.sha256(source).digest()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(write_fd)
            digest = hashlib.sha256()
            remaining = BULK_SIZE
            while remaining:
                chunk = os.read(read_fd, min(4096, remaining))
                if not chunk:
                    raise RuntimeError("unexpected EOF during backpressure test")
                digest.update(chunk)
                remaining -= len(chunk)
            if digest.digest() != expected_digest:
                raise RuntimeError("pipe backpressure digest mismatch")
            os._exit(0)
        except BaseException as error:
            print(f"pipe_wakeup_stress child: {error}", file=sys.stderr)
            os._exit(1)

    os.close(read_fd)
    written = 0
    while written < len(source):
        written += os.write(write_fd, source[written:])
    os.close(write_fd)
    waited, status = os.waitpid(pid, 0)
    if waited != pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise RuntimeError(f"pipe backpressure child status {status:#x}")


def main() -> int:
    signal.alarm(60)
    ping_pong()
    backpressure()
    signal.alarm(0)
    print("pipe_wakeup_stress: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
