#!/usr/bin/env python3
"""Launch common Debian GUI applications and time real X11 window creation."""

from __future__ import annotations

import os
import pwd
import re
import signal
import subprocess
import sys
import time
from pathlib import Path


USER_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)


APPLICATIONS = (
    (38, "xfce4-terminal", ("xfce4-terminal", "--disable-server"), r"xfce4-terminal"),
    (39, "thunar", ("thunar", str(USER_HOME)), r"thunar"),
    (40, "mousepad", ("mousepad",), r"mousepad"),
    (41, "ristretto", ("ristretto",), r"ristretto"),
    (42, "xfce4-taskmanager", ("xfce4-taskmanager",), r"task manager|xfce4-taskmanager"),
    (43, "xfce4-screenshooter", ("xfce4-screenshooter",), r"screenshot|xfce4-screenshooter"),
    (44, "xarchiver", ("xarchiver",), r"xarchiver"),
    (45, "galculator", ("galculator",), r"galculator"),
    (46, "atril", ("atril",), r"atril|document viewer"),
    (
        47,
        "firefox-esr",
        ("firefox-esr", "--new-window", "https://example.com/"),
        r"firefox",
    ),
    (48, "idle", ("idle",), r"idle|tk"),
    (49, "wireshark", ("wireshark",), r"wireshark"),
    (50, "x11-apps", ("xclock",), r"xclock"),
)

WINDOW_PATTERN = re.compile(r"0x[0-9a-fA-F]+")


def xprop(arguments: list[str], environment: dict[str, str]) -> str:
    return subprocess.check_output(
        ["xprop", *arguments],
        env=environment,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=2.0,
    )


def client_windows(environment: dict[str, str]) -> set[str]:
    output = xprop(["-root", "_NET_CLIENT_LIST"], environment)
    return {match.lower() for match in WINDOW_PATTERN.findall(output)}


def window_identity(window: str, environment: dict[str, str]) -> str:
    try:
        output = xprop(
            ["-id", window, "_NET_WM_NAME", "WM_NAME", "WM_CLASS"],
            environment,
        )
    except (subprocess.SubprocessError, OSError):
        return "window-disappeared"
    fields: list[str] = []
    for line in output.splitlines():
        if "=" not in line:
            continue
        value = line.split("=", 1)[1].strip()
        if value and value != "not found.":
            fields.append(value)
    return " | ".join(fields) if fields else "unnamed-window"


def exercise_application(
    package: str,
    process: subprocess.Popen[bytes],
    window: str,
    environment: dict[str, str],
    timeout: float,
) -> tuple[bool, str]:
    try:
        subprocess.run(
            ["xdotool", "windowactivate", "--sync", window],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3.0,
            check=False,
        )
        if package == "xfce4-terminal":
            subprocess.run(
                ["xdotool", "type", "--delay", "10", "printf edgeos-terminal-ok"],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
                check=False,
            )
        elif package == "idle":
            subprocess.run(
                ["xdotool", "type", "--delay", "30", "6*7"],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
                check=False,
            )
            subprocess.run(
                ["xdotool", "key", "Return"],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
                check=False,
            )
    except (subprocess.SubprocessError, OSError):
        return False, "interaction-failed"

    deadline = time.monotonic() + timeout
    title_pattern = r"Example Domain" if package == "firefox-esr" else ""
    while time.monotonic() < deadline:
        identity = window_identity(window, environment)
        if identity == "window-disappeared":
            return False, f"{identity}; launcher-exit={process.poll()}"
        if not title_pattern or re.search(title_pattern, identity, re.IGNORECASE):
            time.sleep(2.0)
            if window in client_windows(environment):
                return True, window_identity(window, environment)
            return False, f"window-disappeared; launcher-exit={process.poll()}"
        time.sleep(0.1)
    return False, window_identity(window, environment)


def terminate_application(
    process: subprocess.Popen[bytes],
    window: str,
    environment: dict[str, str],
) -> None:
    if window:
        try:
            subprocess.run(
                ["xdotool", "windowactivate", "--sync", window],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                check=False,
            )
            subprocess.run(
                ["xdotool", "key", "alt+F4"],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                check=False,
            )
            subprocess.run(
                ["xdotool", "keyup", "Alt_L", "Alt_R", "F4"],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            pass
    try:
        process.wait(timeout=8.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=2.0)


def main() -> int:
    environment = os.environ.copy()
    uid = os.getuid()
    user_home = Path(pwd.getpwuid(uid).pw_dir)
    environment["HOME"] = str(user_home)
    environment.setdefault("DISPLAY", ":0")
    environment.setdefault("XAUTHORITY", str(user_home / ".Xauthority"))
    environment.setdefault(
        "DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus"
    )
    launch_limit = float(os.environ.get("EDGEOS_GUI_LAUNCH_LIMIT", "2.0"))
    detection_timeout = float(os.environ.get("EDGEOS_GUI_TIMEOUT", "15.0"))
    poll_interval = float(os.environ.get("EDGEOS_GUI_POLL_INTERVAL", "0.1"))
    if poll_interval < 0.05:
        poll_interval = 0.05
    workdir = Path(os.environ.get("EDGEOS_GUI_TEST_WORKDIR", "/tmp/edgeos-gui-test"))
    workdir.mkdir(parents=True, exist_ok=True)
    results = workdir / "results.tsv"
    failures = 0

    with results.open("w", encoding="utf-8") as result_file:
        for number, package, command, identity_pattern in APPLICATIONS:
            before = client_windows(environment)
            log = (workdir / f"{number}-{package}.log").open("wb")
            started = time.monotonic()
            process = subprocess.Popen(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=user_home,
                start_new_session=True,
            )
            matched_window = ""
            identity = ""
            while time.monotonic() - started < detection_timeout:
                try:
                    new_windows = client_windows(environment) - before
                except (subprocess.SubprocessError, OSError):
                    new_windows = set()
                for window in sorted(new_windows):
                    candidate = window_identity(window, environment)
                    if re.search(identity_pattern, candidate, re.IGNORECASE):
                        matched_window = window
                        identity = candidate
                        break
                if matched_window:
                    break
                time.sleep(poll_interval)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if not matched_window:
                status = "FAIL(no-window)"
                identity = f"exit={process.poll()}"
                failures += 1
            else:
                usable, identity = exercise_application(
                    package, process, matched_window, environment, detection_timeout
                )
                if not usable:
                    status = "FAIL(interaction)"
                    failures += 1
                elif elapsed_ms > int(launch_limit * 1000):
                    status = "FAIL(slow)"
                    failures += 1
                else:
                    status = "PASS"
            line = f"{number}\t{package}\t{status}\t{elapsed_ms}\t{identity}"
            print(line, flush=True)
            print(line, file=result_file, flush=True)
            terminate_application(process, matched_window, environment)
            log.close()
            time.sleep(0.15)

    print(f"TOTAL={len(APPLICATIONS)} FAILURES={failures} RESULTS={results}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
