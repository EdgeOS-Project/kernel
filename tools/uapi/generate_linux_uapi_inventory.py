#!/usr/bin/env python3
"""Generate or check the frozen Linux UAPI inventory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from linux_uapi_inventory import build_inventory, write_inventory


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "tools/uapi/linux_uapi_inventory.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--linux-tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    generated = build_inventory(arguments.linux_tree.resolve())
    if arguments.check:
        if not arguments.output.exists():
            print(f"missing UAPI inventory: {arguments.output}")
            return 1
        current = json.loads(arguments.output.read_text(encoding="utf-8"))
        if current != generated:
            print(f"stale UAPI inventory: {arguments.output}")
            return 1
        print(f"Linux UAPI inventory is current: {arguments.output}")
        return 0
    write_inventory(generated, arguments.output)
    print(f"generated {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
