#!/usr/bin/env python3
"""Test fatal-fault recovery, covering the UART identity address on ARM64."""
import json
import os
from pathlib import Path
import platform
import resource
import signal
import struct
import subprocess
import tempfile
import time

arch = platform.machine()
if arch == 'aarch64':
    machine = 183
    code = struct.pack('<IIIII', 0xd2800020, 0xf9000000, 0xd2800ba8, 0xd4000001, 0x14000000)
elif arch == 'x86_64':
    machine = 62
    code = bytes.fromhex('b801000000c60000b83c0000000f05ebfe')
else:
    raise RuntimeError('Unsupported architecture')
base = 0x09000000 if arch == 'aarch64' else 0x00400000
size = 4096 + len(code)
ident = b'\x7fELF\x02\x01\x01' + bytes(9)
header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, machine, 1, base + 4096, 64, 0, 0, 64, 56, 1, 0, 0, 0)
segment = struct.pack('<IIQQQQQQ', 1, 5, 0, base, base, size, size, 4096)
started = time.monotonic()
with tempfile.TemporaryDirectory(prefix='edgeos-fault-uart-') as directory:
    path = Path(directory) / 'fault-uart'
    path.write_bytes(header + segment + bytes(4096 - len(header) - len(segment)) + code)
    path.chmod(0o700)
    def no_core():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        result = subprocess.run([str(path)], capture_output=True, timeout=20, preexec_fn=no_core)
        report = dict(architecture=arch, low_elf_base=hex(base), returncode=result.returncode, passed=result.returncode == -signal.SIGSEGV, stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
    except subprocess.TimeoutExpired:
        report = dict(architecture=arch, passed=False, error='Child did not terminate within 20 seconds')
report['elapsed_s'] = time.monotonic() - started
print(json.dumps(report))
