#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build deterministic Linux newc or crc initramfs archives."""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import os
import shlex
import stat
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


CPIO_NEWC_MAGIC = b"070701"
CPIO_CRC_MAGIC = b"070702"
CPIO_HEADER_FIELDS = 13
UINT32_MAX = (1 << 32) - 1


@dataclass
class Entry:
    path: str
    mode: int
    uid: int
    gid: int
    mtime: int
    data: bytes = b""
    device_major: int = 0
    device_minor: int = 0
    rdev_major: int = 0
    rdev_minor: int = 0
    inode: int = 0
    nlink: int = 1
    hardlink_key: tuple[int, int] | None = None


def parse_mode(value: str) -> int:
    return int(value, 8)


def normalize_archive_path(value: str) -> str:
    path = PurePosixPath(value)
    components = [part for part in path.parts if part not in ("", "/", ".")]
    if not components or any(part == ".." for part in components):
        raise ValueError(f"invalid archive path: {value!r}")
    return "/".join(components)


def mapped_owner(
    uid: int, gid: int, owner: tuple[int, int] | None
) -> tuple[int, int]:
    return owner if owner is not None else (uid, gid)


def source_entry(
    root: Path,
    filesystem_path: Path,
    archive_path: str,
    owner: tuple[int, int] | None,
    fixed_mtime: int | None,
) -> Entry:
    metadata = filesystem_path.lstat()
    uid, gid = mapped_owner(metadata.st_uid, metadata.st_gid, owner)
    mtime = fixed_mtime if fixed_mtime is not None else int(metadata.st_mtime)
    mode = metadata.st_mode
    data = b""
    rdev_major = 0
    rdev_minor = 0
    hardlink_key = None

    if stat.S_ISREG(mode):
        data = filesystem_path.read_bytes()
        if metadata.st_nlink > 1:
            hardlink_key = (metadata.st_dev, metadata.st_ino)
    elif stat.S_ISLNK(mode):
        data = os.fsencode(os.readlink(filesystem_path))
    elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        rdev_major = os.major(metadata.st_rdev)
        rdev_minor = os.minor(metadata.st_rdev)
    elif not (
        stat.S_ISDIR(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)
    ):
        raise ValueError(
            f"unsupported file type: {filesystem_path.relative_to(root)}"
        )

    return Entry(
        path=archive_path,
        mode=mode,
        uid=uid,
        gid=gid,
        mtime=mtime,
        data=data,
        device_major=os.major(metadata.st_dev),
        device_minor=os.minor(metadata.st_dev),
        rdev_major=rdev_major,
        rdev_minor=rdev_minor,
        hardlink_key=hardlink_key,
    )


def excluded(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def collect_source(
    root: Path,
    owner: tuple[int, int] | None,
    fixed_mtime: int | None,
    excludes: list[str],
) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}

    def visit(directory: Path, prefix: str) -> None:
        children = sorted(
            os.scandir(directory), key=lambda item: os.fsencode(item.name)
        )
        for child in children:
            archive_path = f"{prefix}/{child.name}" if prefix else child.name
            archive_path = normalize_archive_path(archive_path)
            if excluded(archive_path, excludes):
                continue
            filesystem_path = Path(child.path)
            entry = source_entry(
                root, filesystem_path, archive_path, owner, fixed_mtime
            )
            entries[archive_path] = entry
            if stat.S_ISDIR(entry.mode):
                visit(filesystem_path, archive_path)

    visit(root, "")
    return entries


def parse_manifest(
    manifest: Path,
    entries: dict[str, Entry],
    fixed_mtime: int | None,
) -> None:
    default_mtime = fixed_mtime if fixed_mtime is not None else 0
    for line_number, raw_line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), 1
    ):
        fields = shlex.split(raw_line, comments=True, posix=True)
        if not fields:
            continue
        kind = fields[0]
        try:
            if kind == "dir" and len(fields) == 5:
                path, mode, uid, gid = fields[1:]
                entry = Entry(
                    normalize_archive_path(path),
                    stat.S_IFDIR | parse_mode(mode),
                    int(uid),
                    int(gid),
                    default_mtime,
                )
            elif kind == "file" and len(fields) == 6:
                path, source, mode, uid, gid = fields[1:]
                entry = Entry(
                    normalize_archive_path(path),
                    stat.S_IFREG | parse_mode(mode),
                    int(uid),
                    int(gid),
                    default_mtime,
                    Path(source).read_bytes(),
                )
            elif kind == "slink" and len(fields) == 6:
                path, target, mode, uid, gid = fields[1:]
                entry = Entry(
                    normalize_archive_path(path),
                    stat.S_IFLNK | parse_mode(mode),
                    int(uid),
                    int(gid),
                    default_mtime,
                    os.fsencode(target),
                )
            elif kind == "nod" and len(fields) == 8:
                path, mode, uid, gid, node_kind, major, minor = fields[1:]
                node_mode = {
                    "c": stat.S_IFCHR,
                    "char": stat.S_IFCHR,
                    "b": stat.S_IFBLK,
                    "block": stat.S_IFBLK,
                }.get(node_kind)
                if node_mode is None:
                    raise ValueError(f"invalid device kind: {node_kind}")
                entry = Entry(
                    normalize_archive_path(path),
                    node_mode | parse_mode(mode),
                    int(uid),
                    int(gid),
                    default_mtime,
                    rdev_major=int(major),
                    rdev_minor=int(minor),
                )
            elif kind in ("pipe", "sock") and len(fields) == 5:
                path, mode, uid, gid = fields[1:]
                node_mode = stat.S_IFIFO if kind == "pipe" else stat.S_IFSOCK
                entry = Entry(
                    normalize_archive_path(path),
                    node_mode | parse_mode(mode),
                    int(uid),
                    int(gid),
                    default_mtime,
                )
            else:
                raise ValueError(f"invalid manifest record: {raw_line}")
        except (OSError, ValueError) as error:
            raise ValueError(
                f"{manifest}:{line_number}: {error}"
            ) from error
        entries[entry.path] = entry


def assign_inodes(entries: list[Entry]) -> None:
    hardlink_groups: dict[tuple[int, int], list[Entry]] = {}
    next_inode = 1

    for entry in entries:
        if entry.hardlink_key is None:
            entry.inode = next_inode
            next_inode += 1
            continue
        hardlink_groups.setdefault(entry.hardlink_key, []).append(entry)

    for group in hardlink_groups.values():
        inode = next_inode
        next_inode += 1
        for entry in group:
            entry.inode = inode
            entry.nlink = len(group)
        for entry in group[:-1]:
            entry.data = b""


def checked_u32(value: int, label: str) -> int:
    if value < 0 or value > UINT32_MAX:
        raise ValueError(f"{label} does not fit in a newc field: {value}")
    return value


def pad4(output: bytearray) -> None:
    output.extend(b"\0" * (-len(output) % 4))


def append_entry(output: bytearray, entry: Entry, crc: bool) -> None:
    name = os.fsencode(entry.path) + b"\0"
    data = entry.data
    checksum = sum(data) & UINT32_MAX if crc else 0
    values = (
        entry.inode,
        entry.mode,
        entry.uid,
        entry.gid,
        entry.nlink,
        entry.mtime,
        len(data),
        entry.device_major,
        entry.device_minor,
        entry.rdev_major,
        entry.rdev_minor,
        len(name),
        checksum,
    )
    fields = "".join(
        f"{checked_u32(value, entry.path):08x}" for value in values
    ).encode("ascii")
    if len(fields) != CPIO_HEADER_FIELDS * 8:
        raise AssertionError("invalid newc header field count")
    output.extend(CPIO_CRC_MAGIC if crc else CPIO_NEWC_MAGIC)
    output.extend(fields)
    output.extend(name)
    pad4(output)
    output.extend(data)
    pad4(output)


def build_archive(entries: Iterable[Entry], crc: bool) -> bytes:
    output = bytearray()
    for entry in entries:
        append_entry(output, entry, crc)
    append_entry(
        output,
        Entry(
            path="TRAILER!!!",
            mode=0,
            uid=0,
            gid=0,
            mtime=0,
            inode=0,
        ),
        crc,
    )
    output.extend(b"\0" * (-len(output) % 512))
    return bytes(output)


def compress_archive(archive: bytes, compression: str) -> bytes:
    if compression == "none":
        return archive
    if compression != "gzip":
        raise ValueError(f"unsupported compression: {compression}")
    compressed = bytearray(
        gzip.compress(archive, compresslevel=9, mtime=0)
    )
    if len(compressed) < 10:
        raise AssertionError("invalid gzip output")
    compressed[9] = 255
    return bytes(compressed)


def parse_owner(value: str) -> tuple[int, int] | None:
    if value == "preserve":
        return None
    try:
        uid, gid = value.split(":", 1)
        return int(uid), int(gid)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "owner must be preserve or UID:GID"
        ) from error


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a Linux-compatible newc initramfs archive"
    )
    parser.add_argument("--source", type=Path)
    parser.add_argument(
        "--overlay", action="append", type=Path, default=[],
        help="overlay another source directory on the archive tree",
    )
    parser.add_argument("--manifest", action="append", type=Path, default=[])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--format", choices=("newc", "crc"), default="newc"
    )
    parser.add_argument(
        "--compression", choices=("none", "gzip"), default="none"
    )
    parser.add_argument(
        "--owner", type=parse_owner, default=None,
        help="preserve source ownership or assign UID:GID to all source files",
    )
    parser.add_argument(
        "--mtime", type=int,
        help="replace all source and manifest modification times",
    )
    parser.add_argument(
        "--exclude", action="append", default=[],
        help="exclude archive paths matching this shell pattern",
    )
    args = parser.parse_args()

    if args.source is None and not args.overlay and not args.manifest:
        parser.error("at least one --source or --manifest is required")
    if args.source is not None and not args.source.is_dir():
        parser.error(f"source is not a directory: {args.source}")
    for overlay in args.overlay:
        if not overlay.is_dir():
            parser.error(f"overlay is not a directory: {overlay}")

    entries = (
        collect_source(
            args.source.resolve(),
            args.owner,
            args.mtime,
            args.exclude,
        )
        if args.source is not None
        else {}
    )
    for overlay in args.overlay:
        entries.update(
            collect_source(
                overlay.resolve(),
                args.owner,
                args.mtime,
                args.exclude,
            )
        )
    for manifest in args.manifest:
        parse_manifest(manifest, entries, args.mtime)

    ordered_entries = [entries[path] for path in sorted(entries)]
    assign_inodes(ordered_entries)
    archive = build_archive(ordered_entries, args.format == "crc")
    output_data = compress_archive(archive, args.compression)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.tmp")
    temporary.write_bytes(output_data)
    temporary.replace(args.output)
    print(
        f"[initramfs] wrote {args.output} "
        f"({len(ordered_entries)} entries, {len(output_data)} bytes, "
        f"compression={args.compression})"
    )


if __name__ == "__main__":
    main()
