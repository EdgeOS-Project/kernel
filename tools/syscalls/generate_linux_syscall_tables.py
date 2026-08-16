#!/usr/bin/env python3
"""Generate canonical syscall IDs and architecture number tables."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/syscalls/linux_syscall_inventory.json"
ID_HEADER = ROOT / "include/generated/linux_syscall_ids.h"
TABLE_INCLUDE = ROOT / "src/kernel/linux_syscall_tables.inc"
DISPATCH_INCLUDE = ROOT / "src/kernel/linux_syscall_dispatch.inc"


def load_inventory() -> list[dict[str, object]]:
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError("unsupported Linux syscall inventory schema")
    syscalls = document.get("syscalls")
    if not isinstance(syscalls, list):
        raise ValueError("Linux syscall inventory has no syscall list")
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
    }
    for entry in syscalls:
        architectures = entry["architectures"]
        assert isinstance(architectures, dict)
        for architecture in by_architecture:
            mapping = architectures.get(architecture)
            if mapping is None:
                continue
            assert isinstance(mapping, dict)
            by_architecture[architecture].append(
                (int(mapping["number"]), str(entry["id"]), str(mapping["status"]))
            )
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from tools/syscalls/linux_syscall_inventory.json. */",
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
