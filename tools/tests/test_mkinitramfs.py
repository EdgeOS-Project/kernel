#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Regression tests for the deterministic initramfs archive builder."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
import gzip
from dataclasses import dataclass
from pathlib import Path

from tools.initramfs import mkinitramfs


@dataclass(frozen=True)
class ParsedEntry:
    path: str
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    data: bytes
    device_major: int
    device_minor: int
    rdev_major: int
    rdev_minor: int
    checksum: int


def parse_archive(archive: bytes) -> list[ParsedEntry]:
    entries: list[ParsedEntry] = []
    offset = 0
    while offset + 110 <= len(archive):
        header = archive[offset : offset + 110]
        magic = header[:6]
        if magic not in (
            mkinitramfs.CPIO_NEWC_MAGIC,
            mkinitramfs.CPIO_CRC_MAGIC,
        ):
            raise AssertionError(f"invalid cpio magic at offset {offset}")
        values = [
            int(header[position : position + 8], 16)
            for position in range(6, 110, 8)
        ]
        (
            inode,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            size,
            device_major,
            device_minor,
            rdev_major,
            rdev_minor,
            name_size,
            checksum,
        ) = values
        name_offset = offset + 110
        name_end = name_offset + name_size
        if name_size == 0 or name_end > len(archive):
            raise AssertionError("invalid cpio name size")
        name_bytes = archive[name_offset:name_end]
        if name_bytes[-1] != 0:
            raise AssertionError("cpio path is not null terminated")
        path = os.fsdecode(name_bytes[:-1])
        data_offset = (name_end + 3) & ~3
        data_end = data_offset + size
        if data_end > len(archive):
            raise AssertionError("invalid cpio data size")
        data = archive[data_offset:data_end]
        if magic == mkinitramfs.CPIO_CRC_MAGIC:
            if sum(data) & mkinitramfs.UINT32_MAX != checksum:
                raise AssertionError(f"invalid checksum for {path}")
        entries.append(
            ParsedEntry(
                path,
                inode,
                mode,
                uid,
                gid,
                nlink,
                mtime,
                data,
                device_major,
                device_minor,
                rdev_major,
                rdev_minor,
                checksum,
            )
        )
        offset = (data_end + 3) & ~3
        if path == "TRAILER!!!":
            break
    return entries


class InitramfsBuilderTests(unittest.TestCase):
    def test_manifest_supports_linux_initramfs_record_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.write_bytes(b"payload-data")
            manifest = root / "initramfs.list"
            manifest.write_text(
                "\n".join(
                    (
                        "dir /dev 0755 1 2",
                        f"file /etc/value {payload} 0640 3 4",
                        "slink /init /sbin/init 0777 0 0",
                        "nod /dev/console 0600 0 0 c 5 1",
                        "nod /dev/root 0600 0 0 b 8 1",
                        "pipe /run/pipe 0620 5 6",
                        "sock /run/socket 0660 7 8",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            source_entries: dict[str, mkinitramfs.Entry] = {}
            mkinitramfs.parse_manifest(manifest, source_entries, 123)
            ordered = [source_entries[path] for path in sorted(source_entries)]
            mkinitramfs.assign_inodes(ordered)
            parsed = {
                entry.path: entry
                for entry in parse_archive(
                    mkinitramfs.build_archive(ordered, crc=True)
                )
            }

            self.assertTrue(stat.S_ISDIR(parsed["dev"].mode))
            self.assertEqual(parsed["etc/value"].data, b"payload-data")
            self.assertEqual(
                (parsed["etc/value"].uid, parsed["etc/value"].gid),
                (3, 4),
            )
            self.assertEqual(parsed["init"].data, b"/sbin/init")
            self.assertTrue(stat.S_ISLNK(parsed["init"].mode))
            self.assertEqual(
                (
                    parsed["dev/console"].rdev_major,
                    parsed["dev/console"].rdev_minor,
                ),
                (5, 1),
            )
            self.assertTrue(stat.S_ISCHR(parsed["dev/console"].mode))
            self.assertTrue(stat.S_ISBLK(parsed["dev/root"].mode))
            self.assertTrue(stat.S_ISFIFO(parsed["run/pipe"].mode))
            self.assertTrue(stat.S_ISSOCK(parsed["run/socket"].mode))
            self.assertEqual(parsed["run/socket"].mtime, 123)
            self.assertNotEqual(parsed["etc/value"].checksum, 0)
            self.assertIn("TRAILER!!!", parsed)

    def test_source_overlay_owner_exclusion_and_reproducibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            overlay = root / "overlay"
            (source / "etc").mkdir(parents=True)
            (overlay / "etc").mkdir(parents=True)
            (source / "etc/value").write_bytes(b"base")
            (source / ".DS_Store").write_bytes(b"ignored")
            (overlay / "etc/value").write_bytes(b"overlay")

            entries = mkinitramfs.collect_source(
                source, (10, 20), 77, [".DS_Store"]
            )
            entries.update(
                mkinitramfs.collect_source(
                    overlay, (10, 20), 77, [".DS_Store"]
                )
            )
            ordered = [entries[path] for path in sorted(entries)]
            mkinitramfs.assign_inodes(ordered)
            first = mkinitramfs.build_archive(ordered, crc=False)
            second = mkinitramfs.build_archive(ordered, crc=False)
            parsed = {entry.path: entry for entry in parse_archive(first)}

            self.assertEqual(first, second)
            self.assertNotIn(".DS_Store", parsed)
            self.assertEqual(parsed["etc/value"].data, b"overlay")
            self.assertEqual(
                (parsed["etc/value"].uid, parsed["etc/value"].gid),
                (10, 20),
            )
            self.assertEqual(parsed["etc/value"].mtime, 77)
            self.assertEqual(len(first) % 512, 0)

    def test_hardlinks_share_inode_and_store_one_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.write_bytes(b"shared")
            os.link(first, second)

            entries = mkinitramfs.collect_source(root, (0, 0), 0, [])
            ordered = [entries[path] for path in sorted(entries)]
            mkinitramfs.assign_inodes(ordered)
            parsed = {
                entry.path: entry
                for entry in parse_archive(
                    mkinitramfs.build_archive(ordered, crc=False)
                )
            }

            self.assertEqual(parsed["first"].inode, parsed["second"].inode)
            self.assertEqual(parsed["first"].nlink, 2)
            self.assertEqual(parsed["second"].nlink, 2)
            self.assertEqual(
                sorted((parsed["first"].data, parsed["second"].data)),
                [b"", b"shared"],
            )

    def test_rejects_parent_traversal_and_invalid_owner(self) -> None:
        with self.assertRaises(ValueError):
            mkinitramfs.normalize_archive_path("../escape")
        with self.assertRaises(ValueError):
            mkinitramfs.normalize_archive_path("/")
        self.assertEqual(mkinitramfs.parse_owner("12:34"), (12, 34))
        self.assertIsNone(mkinitramfs.parse_owner("preserve"))

    def test_gzip_output_is_deterministic_and_round_trips(self) -> None:
        archive = mkinitramfs.build_archive(
            [
                mkinitramfs.Entry(
                    path="init",
                    mode=stat.S_IFREG | 0o755,
                    uid=0,
                    gid=0,
                    mtime=0,
                    data=b"init-payload",
                    inode=1,
                )
            ],
            crc=False,
        )
        first = mkinitramfs.compress_archive(archive, "gzip")
        second = mkinitramfs.compress_archive(archive, "gzip")

        self.assertEqual(first, second)
        self.assertEqual(first[:10], bytes.fromhex("1f8b08000000000002ff"))
        self.assertEqual(gzip.decompress(first), archive)


if __name__ == "__main__":
    unittest.main()
