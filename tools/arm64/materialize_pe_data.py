#!/usr/bin/env python3
"""Materialize the zero-filled tail of a PE data section in the image file."""

import argparse
import pathlib
import struct
import subprocess
import tempfile


def data_virtual_size(image: pathlib.Path) -> int:
    blob = image.read_bytes()
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise RuntimeError(f"{image} is not a PE image")
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe + 24 > len(blob) or blob[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError(f"{image} has an invalid PE header")
    section_count = struct.unpack_from("<H", blob, pe + 6)[0]
    optional_size = struct.unpack_from("<H", blob, pe + 20)[0]
    section_table = pe + 24 + optional_size
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(blob):
            break
        if blob[offset : offset + 8].rstrip(b"\0") == b".data":
            return struct.unpack_from("<I", blob, offset + 8)[0]
    raise RuntimeError(f"{image} has no .data section")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("image", type=pathlib.Path)
    args = parser.parse_args()

    virtual_size = data_virtual_size(args.image)
    with tempfile.TemporaryDirectory(dir=args.image.parent) as directory:
        work = pathlib.Path(directory)
        section = work / "data.bin"
        output = work / args.image.name
        subprocess.run(
            [args.objcopy, "--dump-section", f".data={section}", str(args.image)],
            check=True,
        )
        if section.stat().st_size > virtual_size:
            raise RuntimeError("PE .data raw size exceeds its virtual size")
        with section.open("r+b") as stream:
            stream.truncate(virtual_size)
        subprocess.run(
            [args.objcopy, "--update-section", f".data={section}", str(args.image), str(output)],
            check=True,
        )
        output.replace(args.image)


if __name__ == "__main__":
    main()
