#!/usr/bin/env python3
"""Detect replayed file writes while independent writers contend on one filesystem."""
import hashlib
import os
import pathlib
import tempfile

DATA = b"".join(hashlib.sha256(str(block).encode()).digest() * 128
                for block in range(128))
with tempfile.TemporaryDirectory(prefix="write-replay-", dir=".") as directory:
    children = []
    for worker in range(6):
        child = os.fork()
        if child:
            children.append(child)
            continue
        try:
            path = pathlib.Path(directory) / f"writer-{worker}"
            for iteration in range(80):
                fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
                done = 0
                while done < len(DATA):
                    written = os.write(fd, DATA[done:]) if worker % 2 == 0 else os.writev(fd, [DATA[done:]])
                    assert written > 0, written
                    done += written
                os.fsync(fd)
                os.close(fd)
                actual = path.read_bytes()
                if actual != DATA:
                    first = next((i for i in range(min(len(actual), len(DATA)))
                                  if actual[i] != DATA[i]), min(len(actual), len(DATA)))
                    raise AssertionError((worker, iteration, len(actual), first,
                                          actual[4096:] == DATA))
            print(f"PASS writer={worker} iterations=80", flush=True)
            os._exit(0)
        except BaseException as error:
            print(f"FAIL {error}", flush=True)
            os._exit(1)
    statuses = [os.waitpid(child, 0)[1] for child in children]
    assert all(status == 0 for status in statuses), statuses
print("PASS contended file writes", flush=True)
