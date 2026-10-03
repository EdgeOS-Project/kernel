#!/usr/bin/env python3
"""Replace a process repeatedly from non-leader threads and verify its PID."""
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import threading
import time

if len(sys.argv) > 1 and sys.argv[1] == '--child':
    step = int(sys.argv[2])
    print(json.dumps(dict(step=step, pid=os.getpid())), flush=True)
    if step == 6:
        raise SystemExit(0)
    def replace():
        try:
            os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve()), '--child', str(step + 1)])
        except OSError as error:
            print(json.dumps(dict(exec_errno=error.errno)), flush=True)
            os._exit(90)
    threading.Thread(target=replace).start()
    threading.Event().wait()
else:
    def disable_core():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    started = time.monotonic()
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child', '0'],
                                capture_output=True, text=True, timeout=45, preexec_fn=disable_core)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        passed = (result.returncode == 0 and [r.get('step') for r in rows] == list(range(7))
                  and len({r.get('pid') for r in rows}) == 1)
        print(json.dumps(dict(architecture=platform.machine(), passed=passed,
                              returncode=result.returncode, steps=rows, stderr=result.stderr,
                              elapsed_s=time.monotonic()-started)))
    except subprocess.TimeoutExpired as error:
        print(json.dumps(dict(architecture=platform.machine(), passed=False, timeout=True,
                              stdout=(error.stdout or b'').decode(errors='replace'))))
