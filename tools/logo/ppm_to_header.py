#!/usr/bin/env python3
"""Embed a small, uncompressed P6 boot logo in a generated C header."""

import pathlib
import sys


def main(source: pathlib.Path, target: pathlib.Path) -> None:
    parts = source.read_bytes().split(b"\n", 3)
    if len(parts) != 4 or parts[0] != b"P6" or parts[2] != b"255":
        raise ValueError("logo must be an 8-bit binary PPM without comments")
    width, height = map(int, parts[1].split())
    rgb = parts[3]
    if not 1 <= width <= 256 or not 1 <= height <= 256 or len(rgb) != width * height * 3:
        raise ValueError("invalid logo dimensions or pixel data")
    lines = [
        "/* Generated from the EdgeOS Lotor PPM asset. */",
        f"#define EDGE_LOGO_WIDTH {width}u",
        f"#define EDGE_LOGO_HEIGHT {height}u",
        "static const unsigned char edge_logo_rgb[] = {",
    ]
    for offset in range(0, len(rgb), 16):
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in rgb[offset:offset + 16]) + ",")
    lines.append("};")
    target.write_text("\n".join(lines) + "\n", encoding="ascii")


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
