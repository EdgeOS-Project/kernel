#!/usr/bin/env python3
"""Materialize the zero-filled tail of a PE data section in the image file."""

import argparse
import os
import pathlib
import struct
import tempfile


def align_up(value: int, alignment: int) -> int:
    if alignment == 0 or alignment & (alignment - 1):
        raise RuntimeError("PE file alignment is not a power of two")
    return (value + alignment - 1) & -alignment


def materialize_data(blob: bytearray, image: pathlib.Path) -> bytearray:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise RuntimeError(f"{image} is not a PE image")
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe + 24 > len(blob) or blob[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError(f"{image} has an invalid PE header")
    section_count = struct.unpack_from("<H", blob, pe + 6)[0]
    optional_size = struct.unpack_from("<H", blob, pe + 20)[0]
    optional = pe + 24
    if optional + optional_size > len(blob):
        raise RuntimeError(f"{image} has a truncated PE optional header")
    magic = struct.unpack_from("<H", blob, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise RuntimeError(f"{image} has an unsupported PE optional header")
    file_alignment = struct.unpack_from("<I", blob, optional + 36)[0]
    section_table = pe + 24 + optional_size
    sections: list[int] = []
    data_section = None
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(blob):
            raise RuntimeError(f"{image} has a truncated PE section table")
        sections.append(offset)
        if blob[offset : offset + 8].rstrip(b"\0") == b".data":
            data_section = offset
    if data_section is None:
        raise RuntimeError(f"{image} has no .data section")

    virtual_size = struct.unpack_from("<I", blob, data_section + 8)[0]
    raw_size = struct.unpack_from("<I", blob, data_section + 16)[0]
    raw_offset = struct.unpack_from("<I", blob, data_section + 20)[0]
    materialized_size = align_up(virtual_size, file_alignment)
    if raw_size > materialized_size:
        raise RuntimeError("PE .data raw size exceeds its aligned virtual size")
    raw_end = raw_offset + raw_size
    if raw_end > len(blob):
        raise RuntimeError("PE .data raw bytes extend beyond the image")
    growth = materialized_size - raw_size
    if growth == 0:
        return blob

    struct.pack_into("<I", blob, data_section + 16, materialized_size)
    initialized_size = struct.unpack_from("<I", blob, optional + 8)[0]
    struct.pack_into("<I", blob, optional + 8, initialized_size + growth)

    symbol_table = struct.unpack_from("<I", blob, pe + 12)[0]
    if symbol_table >= raw_end:
        struct.pack_into("<I", blob, pe + 12, symbol_table + growth)

    for offset in sections:
        for field in (20, 24, 28):
            pointer = struct.unpack_from("<I", blob, offset + field)[0]
            if pointer >= raw_end:
                struct.pack_into("<I", blob, offset + field, pointer + growth)

    directory_base = optional + (112 if magic == 0x20B else 96)
    certificate_pointer = struct.unpack_from("<I", blob, directory_base + 32)[0]
    if certificate_pointer >= raw_end:
        struct.pack_into(
            "<I", blob, directory_base + 32, certificate_pointer + growth
        )

    return blob[:raw_end] + bytearray(growth) + blob[raw_end:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=pathlib.Path)
    args = parser.parse_args()

    materialized = materialize_data(bytearray(args.image.read_bytes()), args.image)
    with tempfile.NamedTemporaryFile(
        dir=args.image.parent, prefix=f".{args.image.name}.", delete=False
    ) as stream:
        temporary = pathlib.Path(stream.name)
        stream.write(materialized)
    os.replace(temporary, args.image)


if __name__ == "__main__":
    main()
