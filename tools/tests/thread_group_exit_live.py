#!/usr/bin/env python3
"""Verify that exit_group retires a CPU-bound sibling thread."""

import subprocess
import signal
import sys
import time


CHILD = (
    "import os, threading, time; "
    "threading.Thread(target=lambda: exec('while True: pass')).start(); "
    "time.sleep(0.2); os._exit(0)"
)

SIGNAL_WAIT_CHILD = (
    "import os, signal, threading, time; "
    "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1}); "
    "threading.Thread(target=lambda: signal.sigwaitinfo({signal.SIGUSR1})).start(); "
    "time.sleep(0.2); os._exit(0)"
)


def main() -> int:
    cases = [("cpu-bound", CHILD)]
    if hasattr(signal, "sigwaitinfo"):
        cases.append(("signal-wait", SIGNAL_WAIT_CHILD))
    else:
        print("thread_group_exit_live: signal-wait SKIP (unavailable)")
    for name, child in cases:
        for attempt in range(5):
            started = time.monotonic()
            try:
                result = subprocess.run(
                    [sys.executable, "-c", child],
                    check=False,
                    timeout=8,
                )
            except subprocess.TimeoutExpired:
                print(
                    f"thread_group_exit_live: {name} timeout "
                    f"on attempt {attempt + 1}"
                )
                return 1
            elapsed = time.monotonic() - started
            if result.returncode != 0:
                print(
                    f"thread_group_exit_live: {name} exit "
                    f"{result.returncode} on attempt {attempt + 1}"
                )
                return 1
            if elapsed > 5:
                print(
                    f"thread_group_exit_live: {name} slow exit "
                    f"({elapsed:.2f}s) on attempt {attempt + 1}"
                )
                return 1
    print("thread_group_exit_live: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
