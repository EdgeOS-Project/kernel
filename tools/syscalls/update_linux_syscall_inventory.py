#!/usr/bin/env python3
"""Refresh the checked-in EdgeOS Linux syscall inventory from dispatch code."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TEST_TOOLS = ROOT / "tools/tests"
INVENTORY = ROOT / "tools/syscalls/linux_syscall_inventory.json"
sys.path.insert(0, str(TEST_TOOLS))

from arch_syscall_parity import normalize, parse  # noqa: E402


ARCHITECTURE_EXCEPTIONS = {
    "arch_prctl": ["x86_64 register and TLS control"],
    "get_thread_area": ["legacy x86_64 TLS descriptor ABI"],
    "ioperm": ["x86_64 I/O-port permission mechanism"],
    "iopl": ["x86_64 I/O privilege mechanism"],
    "map_shadow_stack": ["x86_64 control-flow enforcement ABI"],
    "modify_ldt": ["x86_64 descriptor-table ABI"],
    "rt_sigreturn": ["Architecture-specific signal-frame restoration"],
    "set_thread_area": ["legacy x86_64 TLS descriptor ABI"],
}


def load_existing() -> dict[str, dict[str, Any]]:
    if not INVENTORY.exists():
        return {}
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in document.get("syscalls", [])}


def architecture_entry(
    report: dict[str, Any], architecture: str, name: str
) -> dict[str, Any] | None:
    side = report[architecture]
    if name not in side["numbers"]:
        return None
    route = side["routes"].get(name)
    if route is None:
        raise ValueError(f"{architecture} syscall {name} has no dispatch route")
    return {
        "number": side["numbers"][name],
        "status": "enosys" if route == "enosys" else "implemented",
        "route": route,
    }


def build_document() -> dict[str, Any]:
    report = parse()
    existing = load_existing()
    names = sorted(
        set(report["x86_64"]["numbers"]) | set(report["arm64"]["numbers"])
    )
    syscalls: list[dict[str, Any]] = []
    for name in names:
        old = existing.get(name, {})
        syscalls.append(
            {
                "id": name,
                "semantic_id": normalize(name),
                "shared_handler": old.get("shared_handler"),
                "architecture_exceptions": ARCHITECTURE_EXCEPTIONS.get(name, []),
                "runtime_tests": old.get("runtime_tests", []),
                "architectures": {
                    "x86_64": architecture_entry(report, "x86_64", name),
                    "aarch64": architecture_entry(report, "arm64", name),
                },
            }
        )
    return {
        "schema": 1,
        "description": "Canonical EdgeOS Linux syscall ABI inventory",
        "status_semantics": {
            "implemented": (
                "Statically reaches a non-ENOSYS route. Runtime tests are required "
                "before claiming semantic Linux compatibility."
            ),
            "enosys": "The architecture route explicitly returns Linux ENOSYS.",
        },
        "dispatch_model": (
            "Architecture numbers map to canonical IDs. Shared policy handlers run "
            "before temporary legacy fallbacks during incremental migration."
        ),
        "syscalls": syscalls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stdout", action="store_true", help="print instead of updating the file"
    )
    args = parser.parse_args()
    rendered = json.dumps(build_document(), indent=2, sort_keys=False) + "\n"
    if args.stdout:
        print(rendered, end="")
    else:
        INVENTORY.write_text(rendered, encoding="utf-8")
        print(f"updated {INVENTORY.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
