#!/usr/bin/env python3
"""Observe ELF rejection, caller survival, and a subsequent successful exec."""
import errno
import json
import os
from pathlib import Path
import platform
import resource
import signal
import struct
import tempfile
import time

architecture = platform.machine()
machine = 183 if architecture == "aarch64" else 62
exit_code = (struct.pack("<III", 0xd2800540, 0xd2800ba8, 0xd4000001)
             if machine == 183 else bytes.fromhex("bf2a000000b83c0000000f05"))

def elf(base=0x400000, interpreter=None, phoff=64, bad_entry=False):
    count = 2 if interpreter is not None else 1
    size = 4096 + len(exit_code)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, machine, 1,
                         1 if bad_entry else base + 4096, phoff, 0, 0,
                         64, 56, count, 0, 0, 0)
    segments = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, size, size, 4096)
    if interpreter is not None:
        segments += struct.pack("<IIQQQQQQ", 3, 4, 256, 0, 0,
                                len(interpreter), len(interpreter), 1)
    data = bytearray(header + segments + bytes(4096 - len(header) - len(segments)) + exit_code)
    if interpreter is not None:
        data[256:256 + len(interpreter)] = interpreter
    return data

with tempfile.TemporaryDirectory(prefix="edgeos-exec-recovery-") as directory:
    root = Path(directory)
    valid = root / "valid"
    valid.write_bytes(elf())
    valid.chmod(0o700)
    cases = {
        "valid": elf(),
        "truncated-program-headers": elf(phoff=0x100000),
        "missing-interpreter": elf(interpreter=b"/no-such-edgeos-interpreter\0"),
        "unterminated-interpreter": elf(interpreter=b"/no-such-edgeos-interpreterX"),
        "low-address": elf(base=0x09000000),
        "bad-entry": elf(bad_entry=True),
    }
    results = []
    for name, data in cases.items():
        path = root / name
        path.write_bytes(data)
        path.chmod(0o700)
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            signal.alarm(12)
            try:
                os.execve(str(path), [str(path)], {})
            except OSError as error:
                os.write(writer, json.dumps(dict(errno=error.errno, survived=True)).encode())
                os.execve(str(valid), [str(valid)], {})
            os._exit(90)
        os.close(writer)
        started = time.monotonic()
        while True:
            child, status = os.waitpid(pid, os.WNOHANG)
            if child:
                break
            if time.monotonic() - started > 18:
                os.kill(pid, signal.SIGKILL)
                _, status = os.waitpid(pid, 0)
                break
            time.sleep(0.05)
        output = os.read(reader, 4096)
        os.close(reader)
        results.append(dict(case=name, returncode=os.waitstatus_to_exitcode(status),
                            recovery=json.loads(output) if output else None))
    print(json.dumps(dict(architecture=architecture, results=results)))
