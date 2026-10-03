#!/usr/bin/env python3
"""Check inherited process-group IDs inside a fresh PID namespace. Run as root."""

import ctypes
import os


def main():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x20000000) != 0:
        raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWPID)")
    child = os.fork()
    if child == 0:
        try:
            pid = os.getpid()
            assert pid == 1, ("pid", pid)
            group = os.getpgrp()
            assert group == 0, ("pgrp", group)
            group = os.getpgid(0)
            assert group == 0, ("pgid", group)
            session = os.getsid(0)
            assert session == 0, ("sid", session)
            os.setsid()
            assert os.getpgrp() == 1
            assert os.getpgid(1) == 1
            assert os.getsid(1) == 1
            print("PID_NAMESPACE_SESSION_PASS", flush=True)
        except BaseException as error:
            print("PID_NAMESPACE_SESSION_FAIL", repr(error), flush=True)
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status


if __name__ == "__main__":
    main()
