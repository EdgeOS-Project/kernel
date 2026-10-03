#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Emit reproducible memory-layout evidence without executing a kernel."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def parse_sections(output):
    sections = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3 or not fields[0].startswith("."):
            continue
        sections.append({"name": fields[0], "bytes": int(fields[1]),
                         "address": int(fields[2])})
    if not sections:
        raise ValueError("No object sections were reported")
    return sections


def parse_symbols(output):
    symbols = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[1] not in "bBdDsSrR":
            continue
        symbols.append({"name": fields[0], "type": fields[1],
                        "address": int(fields[2]), "bytes": int(fields[3])})
    return sorted(symbols, key=lambda symbol: (-symbol["bytes"], symbol["name"]))


def inventory(path, size_tool, nm_tool, limit):
    section_run = subprocess.run([size_tool, "--format=sysv", "--radix=10", str(path)],
                                 check=True, text=True, capture_output=True)
    symbol_run = subprocess.run([nm_tool, "--format=posix", "--radix=d",
                                "--print-size", str(path)],
                               text=True, capture_output=True)
    sections = parse_sections(section_run.stdout)
    symbols = parse_symbols(symbol_run.stdout) if symbol_run.returncode == 0 else []
    return {
        "artifact": str(path.resolve()), "sha256": digest(path),
        "file_bytes": path.stat().st_size, "sections": sections,
        "bss_bytes": sum(s["bytes"] for s in sections if "bss" in s["name"]),
        "largest_static_objects": symbols[:limit],
        "symbol_status": "available" if symbols else "unavailable",
        "runtime_status": "not_tested",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", action="append", required=True,
                        help="Architecture=artifact, repeated for each architecture")
    parser.add_argument("--size-tool", default="llvm-size")
    parser.add_argument("--nm-tool", default="llvm-nm")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    artifacts = {}
    for item in args.kernel:
        architecture, separator, filename = item.partition("=")
        if not separator or architecture not in ("x86_64", "aarch64"):
            parser.error("--kernel requires x86_64=path or aarch64=path")
        if architecture in artifacts:
            parser.error("Duplicate architecture")
        artifacts[architecture] = inventory(Path(filename), args.size_tool,
                                            args.nm_tool, args.limit)
    print(json.dumps({"schema_version": 1, "artifacts": artifacts}, indent=2))


if __name__ == "__main__":
    main()
