#!/usr/bin/env python3
"""Exercise PTY readiness and peer lifetime on both architectures."""

import os
import pty
import select


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def mask(fd: int, events: int, timeout: int = 1000) -> int:
    poller = select.poll()
    poller.register(fd, events)
    ready = poller.poll(timeout)
    return ready[0][1] if ready else 0


def main() -> int:
    master, slave = pty.openpty()
    requested = select.POLLIN | select.POLLOUT | select.POLLERR | select.POLLHUP
    try:
        require(mask(master, requested, 0) & select.POLLOUT,
                "new PTY master omitted POLLOUT")
        require(mask(slave, requested, 0) & select.POLLOUT,
                "new PTY slave omitted POLLOUT")
        os.write(slave, b"pty-ready\n")
        require(mask(master, requested) & select.POLLIN,
                "slave data did not make master readable")
        require(os.read(master, 11) == b"pty-ready\r\n",
                "PTY line discipline payload mismatch")
        os.close(slave)
        slave = -1
        require(mask(master, requested) & select.POLLHUP,
                "closing the slave omitted master POLLHUP")
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
    print("pty_runtime_parity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
