#!/usr/bin/env python3
"""Generate canonical syscall IDs and architecture number tables."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/syscalls/linux_syscall_inventory.json"
UAPI_INVENTORY = ROOT / "tools/uapi/linux_uapi_inventory.json"
ID_HEADER = ROOT / "include/generated/linux_syscall_ids.h"
TABLE_INCLUDE = ROOT / "src/kernel/linux_syscall_tables.inc"
DISPATCH_INCLUDE = ROOT / "src/kernel/linux_syscall_dispatch.inc"


X32_DIRECT_SHARED_SYSCALLS = {
    "alarm",
    "close",
    "close_range",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "eventfd",
    "eventfd2",
    "exit",
    "exit_group",
    "fanotify_init",
    "fchdir",
    "fdatasync",
    "flock",
    "fsync",
    "getegid",
    "geteuid",
    "getgid",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getpriority",
    "getsockopt",
    "getsid",
    "gettid",
    "getuid",
    "inotify_init",
    "inotify_init1",
    "kill",
    "memfd_secret",
    "nice",
    "pause",
    "personality",
    "pidfd_open",
    "preadv",
    "preadv2",
    "process_vm_readv",
    "process_vm_writev",
    "pwritev",
    "pwritev2",
    "readv",
    "recvmsg",
    "recvmmsg",
    "restart_syscall",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getscheduler",
    "sched_yield",
    "sendmsg",
    "sendmmsg",
    "setpgid",
    "setpriority",
    "setsockopt",
    "setsid",
    "sync",
    "tgkill",
    "timerfd_create",
    "tkill",
    "umask",
    "userfaultfd",
    "write",
    "writev",
}


def load_inventory() -> list[dict[str, object]]:
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError("unsupported Linux syscall inventory schema")
    syscalls = document.get("syscalls")
    if not isinstance(syscalls, list):
        raise ValueError("Linux syscall inventory has no syscall list")
    return syscalls


def load_x32_syscalls() -> list[dict[str, object]]:
    document = json.loads(UAPI_INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 2:
        raise ValueError("unsupported Linux UAPI inventory schema")
    syscalls = document["domains"]["syscalls"]["architectures"]["x32"]
    if not isinstance(syscalls, list):
        raise ValueError("x32 Linux UAPI syscall inventory is not a list")
    return syscalls


def render_ids(syscalls: list[dict[str, object]]) -> str:
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from tools/syscalls/linux_syscall_inventory.json. */",
        "#ifndef EDGEOS_GENERATED_LINUX_SYSCALL_IDS_H",
        "#define EDGEOS_GENERATED_LINUX_SYSCALL_IDS_H",
        "",
        "typedef enum edge_linux_syscall_id {",
        "    EDGE_LINUX_SYS_INVALID = 0,",
    ]
    for entry in syscalls:
        lines.append(f"    EDGE_LINUX_SYS_{entry['id']},")
    lines.extend(
        [
            "    EDGE_LINUX_SYS_COUNT",
            "} edge_linux_syscall_id_t;",
            "",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def render_tables(syscalls: list[dict[str, object]]) -> str:
    by_architecture: dict[str, list[tuple[int, str, str]]] = {
        "x86_64": [],
        "aarch64": [],
        "x32": [],
    }
    canonical = {str(entry["id"]): entry for entry in syscalls}
    for entry in syscalls:
        architectures = entry["architectures"]
        assert isinstance(architectures, dict)
        for architecture in ("x86_64", "aarch64"):
            mapping = architectures.get(architecture)
            if mapping is None:
                continue
            assert isinstance(mapping, dict)
            by_architecture[architecture].append(
                (int(mapping["number"]), str(entry["id"]), str(mapping["status"]))
            )
    for mapping in load_x32_syscalls():
        name = str(mapping["name"])
        entry = canonical.get(name)
        if entry is None:
            raise ValueError(f"x32 syscall has no canonical ID: {name}")
        architectures = entry["architectures"]
        assert isinstance(architectures, dict)
        native = architectures.get("x86_64")
        native_implemented = (
            isinstance(native, dict) and native.get("status") == "implemented"
        )
        status = (
            "implemented"
            if name in X32_DIRECT_SHARED_SYSCALLS and native_implemented
            else "enosys"
        )
        by_architecture["x32"].append(
            (int(mapping["number"]), name, status)
        )
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from the syscall and Linux UAPI inventories. */",
        "",
    ]
    for architecture, mappings in by_architecture.items():
        symbol = architecture.replace("64", "64")
        lines.append(
            f"static const edge_linux_syscall_number_t edge_linux_{symbol}_numbers[] = {{"
        )
        for number, name, status in sorted(mappings):
            status_symbol = (
                "EDGE_LINUX_SYSCALL_ENOSYS"
                if status == "enosys"
                else "EDGE_LINUX_SYSCALL_IMPLEMENTED"
            )
            lines.append(
                f"    {{{number}u, EDGE_LINUX_SYS_{name}, {status_symbol}}},"
            )
        lines.extend(["};", ""])
    return "\n".join(lines)


def render_dispatch(syscalls: list[dict[str, object]]) -> str:
    by_handler: dict[str, list[str]] = {}
    for entry in syscalls:
        handler = entry.get("shared_handler")
        if handler is None:
            continue
        if not isinstance(handler, str) or not handler:
            raise ValueError(f"invalid shared handler for {entry.get('id')}")
        by_handler.setdefault(handler, []).append(str(entry["id"]))
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from tools/syscalls/linux_syscall_inventory.json. */",
    ]
    for handler, names in sorted(by_handler.items()):
        for name in sorted(names):
            lines.append(f"case EDGE_LINUX_SYS_{name}:")
        lines.append(f"    context->result = {handler}(context);")
        lines.append("    return EDGE_LINUX_SYSCALL_HANDLED;")
    lines.append("")
    return "\n".join(lines)


def check_or_write(path: Path, rendered: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == rendered:
        return True
    if check:
        print(f"stale generated syscall file: {path.relative_to(ROOT)}")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    print(f"generated {path.relative_to(ROOT)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    syscalls = load_inventory()
    outputs = {
        ID_HEADER: render_ids(syscalls),
        TABLE_INCLUDE: render_tables(syscalls),
        DISPATCH_INCLUDE: render_dispatch(syscalls),
    }
    valid = all(
        check_or_write(path, rendered, args.check)
        for path, rendered in outputs.items()
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
