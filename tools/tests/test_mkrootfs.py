# Copyright (c) EdgeOS Contributors.
# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ROOTFS_TOOL = REPOSITORY_ROOT / "tools" / "rootfs" / "mkrootfs.py"


def find_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for directory in (
        "/opt/homebrew/opt/e2fsprogs/bin",
        "/opt/homebrew/opt/e2fsprogs/sbin",
        "/usr/sbin",
        "/sbin",
    ):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


@unittest.skipUnless(
    find_tool("mke2fs") and find_tool("debugfs") and find_tool("e2fsck"),
    "e2fsprogs tools are required",
)
class RootfsImageTransactionTests(unittest.TestCase):
    def test_concurrent_builds_publish_only_complete_images(self) -> None:
        with tempfile.TemporaryDirectory(prefix="edgeos-rootfs-test-") as directory:
            root = Path(directory)
            source = root / "source"
            override = root / "override"
            output = root / "rootfs.img"
            self._create_source(source)
            override.mkdir()
            command = self._command(output, source, override)

            processes = [
                subprocess.Popen(
                    command,
                    cwd=REPOSITORY_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for _ in range(2)
            ]
            results = []
            for process in processes:
                output_text, _ = process.communicate(timeout=120)
                results.append((process.returncode, output_text))

            self.assertEqual(
                [return_code for return_code, _ in results],
                [0, 0],
                "\n".join(output_text for _, output_text in results),
            )
            self._assert_directory(output, "/usr/libexec")
            self.assertFalse(list(root.glob(".rootfs.img.*.part")))

    def test_failed_override_does_not_replace_the_last_valid_image(self) -> None:
        with tempfile.TemporaryDirectory(prefix="edgeos-rootfs-test-") as directory:
            root = Path(directory)
            source = root / "source"
            override = root / "override"
            output = root / "rootfs.img"
            self._create_source(source)
            override.mkdir()
            subprocess.run(
                self._command(output, source, override),
                cwd=REPOSITORY_ROOT,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            original = hashlib.sha256(output.read_bytes()).hexdigest()

            conflict = override / "usr"
            conflict.mkdir()
            (conflict / "libexec").symlink_to("/bin/busybox")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOTFS_TOOL),
                    "--output",
                    str(output),
                    "--apply-override-only",
                    "--override-dir",
                    str(override),
                ],
                cwd=REPOSITORY_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), original)
            self._assert_directory(output, "/usr/libexec")
            self.assertFalse(list(root.glob(".rootfs.img.*.part")))

    @staticmethod
    def _create_source(source: Path) -> None:
        (source / "bin").mkdir(parents=True)
        (source / "bin" / "busybox").write_bytes(b"busybox-test\n")
        applets = source / "usr" / "bin"
        applets.mkdir(parents=True)
        for index in range(256):
            (applets / f"applet-{index:03d}").symlink_to("/bin/busybox")
        libexec = source / "usr" / "libexec" / "rc"
        libexec.mkdir(parents=True)
        (libexec / "version").write_text("test\n", encoding="ascii")

    @staticmethod
    def _command(output: Path, source: Path, override: Path) -> list[str]:
        return [
            sys.executable,
            str(ROOTFS_TOOL),
            "--output",
            str(output),
            "--size-mb",
            "16",
            "--fs",
            "ext4",
            "--populate-dir",
            str(source),
            "--override-dir",
            str(override),
        ]

    def _assert_directory(self, image: Path, path: str) -> None:
        result = subprocess.run(
            [find_tool("debugfs"), "-R", f"stat {path}", str(image)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )
        self.assertIn("Type: directory", result.stdout)


if __name__ == "__main__":
    unittest.main()
