#!/usr/bin/env python3
"""Convert static AArch64 ELF address fixups into PE base relocations."""

import argparse
import os
import pathlib
import struct
import tempfile


ELF_RELA = 4
R_AARCH64_ABS64 = 257
R_AARCH64_ABS32 = 258
PE_RELOC_HIGHLOW = 3
PE_RELOC_DIR64 = 10
PE_SECTION_RELOC = 0x42000040


def align_up(value: int, alignment: int) -> int:
    if alignment == 0 or alignment & (alignment - 1):
        raise RuntimeError("alignment is not a power of two")
    return (value + alignment - 1) & -alignment


def read_elf_relocations(blob: bytes, image_base: int) -> list[tuple[int, int]]:
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise RuntimeError("input is not an ELF image")
    if blob[4] != 2 or blob[5] != 1:
        raise RuntimeError("only little-endian ELF64 input is supported")
    if struct.unpack_from("<H", blob, 18)[0] != 183:
        raise RuntimeError("ELF input is not AArch64")

    section_offset = struct.unpack_from("<Q", blob, 40)[0]
    section_size = struct.unpack_from("<H", blob, 58)[0]
    section_count = struct.unpack_from("<H", blob, 60)[0]
    if section_size < 64 or section_offset + section_size * section_count > len(blob):
        raise RuntimeError("ELF section table is truncated")

    relocations: set[tuple[int, int]] = set()
    for index in range(section_count):
        header = section_offset + index * section_size
        section_type = struct.unpack_from("<I", blob, header + 4)[0]
        if section_type != ELF_RELA:
            continue
        target_index = struct.unpack_from("<I", blob, header + 44)[0]
        if target_index >= section_count:
            raise RuntimeError("ELF relocation target is invalid")
        target_header = section_offset + target_index * section_size
        target_flags = struct.unpack_from("<Q", blob, target_header + 8)[0]
        if not target_flags & 2:
            continue
        data_offset = struct.unpack_from("<Q", blob, header + 24)[0]
        data_size = struct.unpack_from("<Q", blob, header + 32)[0]
        entry_size = struct.unpack_from("<Q", blob, header + 56)[0]
        if entry_size < 24 or data_offset + data_size > len(blob):
            raise RuntimeError("ELF relocation section is truncated")
        for offset in range(data_offset, data_offset + data_size, entry_size):
            address, info = struct.unpack_from("<QQ", blob, offset)
            relocation_type = info & 0xFFFFFFFF
            if relocation_type == R_AARCH64_ABS64:
                pe_type = PE_RELOC_DIR64
            elif relocation_type == R_AARCH64_ABS32:
                pe_type = PE_RELOC_HIGHLOW
            else:
                continue
            if address < image_base or address - image_base > 0xFFFFFFFF:
                raise RuntimeError("ELF relocation lies outside the PE address space")
            relocations.add((address - image_base, pe_type))
    if not relocations:
        raise RuntimeError("ELF input has no absolute relocations")
    return sorted(relocations)


def build_relocation_table(relocations: list[tuple[int, int]]) -> bytes:
    pages: dict[int, list[int]] = {}
    for rva, relocation_type in relocations:
        page = rva & ~0xFFF
        pages.setdefault(page, []).append((relocation_type << 12) | (rva & 0xFFF))

    output = bytearray()
    for page, entries in sorted(pages.items()):
        entries = sorted(set(entries))
        block_size = 8 + len(entries) * 2
        if block_size % 4:
            entries.append(0)
            block_size += 2
        output += struct.pack("<II", page, block_size)
        output += struct.pack(f"<{len(entries)}H", *entries)
    return bytes(output)


def add_relocation_section(blob: bytearray, table: bytes, image: pathlib.Path) -> bytearray:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise RuntimeError(f"{image} is not a PE image")
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe + 24 > len(blob) or blob[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError(f"{image} has an invalid PE header")
    section_count = struct.unpack_from("<H", blob, pe + 6)[0]
    optional_size = struct.unpack_from("<H", blob, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", blob, optional)[0] != 0x20B:
        raise RuntimeError("only PE32+ images are supported")

    section_alignment = struct.unpack_from("<I", blob, optional + 32)[0]
    file_alignment = struct.unpack_from("<I", blob, optional + 36)[0]
    header_size = struct.unpack_from("<I", blob, optional + 60)[0]
    section_table = optional + optional_size
    new_header = section_table + section_count * 40
    if new_header + 40 > header_size:
        raise RuntimeError("PE header has no room for a relocation section")

    last_rva = 0
    for index in range(section_count):
        header = section_table + index * 40
        virtual_size, rva, raw_size = struct.unpack_from("<III", blob, header + 8)
        last_rva = max(last_rva, rva + max(virtual_size, raw_size))
    relocation_rva = align_up(last_rva, section_alignment)
    raw_offset = align_up(len(blob), file_alignment)
    raw_size = align_up(len(table), file_alignment)
    if raw_offset > len(blob):
        blob += bytearray(raw_offset - len(blob))
    blob += table
    blob += bytearray(raw_size - len(table))

    struct.pack_into(
        "<8sIIIIIIHHI",
        blob,
        new_header,
        b".reloc\0\0",
        len(table),
        relocation_rva,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        PE_SECTION_RELOC,
    )
    struct.pack_into("<H", blob, pe + 6, section_count + 1)
    characteristics = struct.unpack_from("<H", blob, pe + 22)[0]
    struct.pack_into("<H", blob, pe + 22, (characteristics & ~1) | 0x20)
    initialized_size = struct.unpack_from("<I", blob, optional + 8)[0]
    struct.pack_into("<I", blob, optional + 8, initialized_size + raw_size)
    struct.pack_into(
        "<I", blob, optional + 56,
        align_up(relocation_rva + len(table), section_alignment),
    )
    directory = optional + 112 + 5 * 8
    struct.pack_into("<II", blob, directory, relocation_rva, len(table))
    return blob


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    parser.add_argument("image", type=pathlib.Path)
    args = parser.parse_args()

    pe = bytearray(args.image.read_bytes())
    pe_header = struct.unpack_from("<I", pe, 0x3C)[0]
    optional = pe_header + 24
    image_base = struct.unpack_from("<Q", pe, optional + 24)[0]
    relocations = read_elf_relocations(args.elf.read_bytes(), image_base)
    table = build_relocation_table(relocations)
    result = add_relocation_section(pe, table, args.image)
    with tempfile.NamedTemporaryFile(
        dir=args.image.parent, prefix=f".{args.image.name}.", delete=False
    ) as stream:
        temporary = pathlib.Path(stream.name)
        stream.write(result)
    os.replace(temporary, args.image)
    print(f"pe-relocations: {len(relocations)} entries, {len(table)} bytes")


if __name__ == "__main__":
    main()
