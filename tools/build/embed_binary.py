#!/usr/bin/env python3
"""Convert a small binary image into a deterministic C initializer."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--size", required=True, type=int)
    args = parser.parse_args()

    payload = args.input.read_bytes()
    if len(payload) > args.size:
        raise SystemExit(
            f"{args.input} is {len(payload)} bytes; limit is {args.size} bytes"
        )
    payload += bytes(args.size - len(payload))
    lines = []
    for offset in range(0, len(payload), 16):
        chunk = payload[offset : offset + 16]
        lines.append("    " + ", ".join(f"0x{value:02x}" for value in chunk) + ",")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
