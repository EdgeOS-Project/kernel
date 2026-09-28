#!/usr/bin/env python3
"""Verify that loadable BSD driver imports match the stable export table."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


EXPORT_PATTERN = re.compile(
    r"^[ \t]+BSD_DRIVER_(?:FUNCTION|OBJECT)"
    r"\(([A-Za-z_][A-Za-z0-9_]*)\)",
    re.MULTILINE,
)


def load_exports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    exports = set(EXPORT_PATTERN.findall(text))
    if not exports:
        raise ValueError(f"no driver exports found in {path}")
    return exports


def undefined_symbols(nm: Path, module: Path) -> set[str]:
    completed = subprocess.run(
        [str(nm), "--undefined-only", "--format=posix", str(module)],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols: set[str] = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].upper() in {"U", "W"}:
            symbols.add(fields[0])
    return symbols


def parse_module(value: str) -> tuple[str, Path]:
    architecture, separator, raw_path = value.partition("=")
    if not separator or not architecture or not raw_path:
        raise argparse.ArgumentTypeError(
            "module must use architecture=/path/to/module format"
        )
    return architecture, Path(raw_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nm", type=Path, required=True)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument(
        "--module", action="append", type=parse_module, default=[]
    )
    arguments = parser.parse_args()

    try:
        exports = load_exports(arguments.exports)
        imports_by_architecture: dict[str, set[str]] = {}
        for architecture, module in arguments.module:
            imports = undefined_symbols(arguments.nm, module)
            missing = sorted(imports - exports)
            if missing:
                raise ValueError(
                    f"{architecture} module imports unavailable symbols: "
                    f"{', '.join(missing)}"
                )
            imports_by_architecture.setdefault(architecture, set()).update(
                imports
            )
        import_sets = list(imports_by_architecture.values())
        if import_sets and any(
            imports != import_sets[0] for imports in import_sets[1:]
        ):
            raise ValueError(
                "module imports differ between configured architectures"
            )
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"bsd-module-symbols: FAIL: {error}", file=sys.stderr)
        return 1

    print(
        "bsd-module-symbols: PASS: "
        f"{len(exports)} exports, {len(import_sets[0]) if import_sets else 0} imports"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
