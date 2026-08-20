#!/usr/bin/env python3
"""Tests for the frozen Linux UAPI inventory parser."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.uapi.linux_uapi_inventory import (
    define_symbols,
    enum_symbols,
    generic_syscalls,
    logical_lines,
    syscall_table,
)


class LinuxUapiInventoryTests(unittest.TestCase):
    def write(self, text: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "input.h"
        path.write_text(text, encoding="utf-8")
        return path

    def test_logical_lines_join_continuations(self) -> None:
        source = "#define A " + "\\" + "\n  B\n#define C D\n"
        self.assertEqual(
            list(logical_lines(source)),
            ["#define A    B", "#define C D"],
        )

    def test_ioctl_defines_require_io_expression(self) -> None:
        path = self.write(
            "#define EXAMPLE_IOCTL _IOW('x', 1, int)\n"
            "#define EXAMPLE_VALUE 7\n"
        )
        self.assertEqual(
            [entry["name"] for entry in define_symbols(path, require_ioctl=True)],
            ["EXAMPLE_IOCTL"],
        )

    def test_enum_prefix_filter(self) -> None:
        path = self.write(
            "enum values {\n  RTM_NEWTHING = 10,\n  OTHER_THING,\n};\n"
        )
        self.assertEqual(
            enum_symbols(path, ("RTM_",)),
            [{"name": "RTM_NEWTHING", "expression": "10"}],
        )

    def test_x86_syscall_abi_filter(self) -> None:
        path = self.write(
            "0 common read sys_read\n512 x32 rt_sigaction compat_sys_rt_sigaction\n"
        )
        self.assertEqual(
            syscall_table(path, {"x32"}),
            [{"number": 512, "name": "rt_sigaction", "abi": "x32"}],
        )

    def test_x32_includes_common_and_x32_rows(self) -> None:
        path = self.write(
            "0 common read sys_read\n"
            "1 64 write sys_write\n"
            "512 x32 rt_sigaction compat_sys_rt_sigaction\n"
        )
        self.assertEqual(
            syscall_table(path, {"common", "x32"}),
            [
                {"number": 0, "name": "read", "abi": "common"},
                {"number": 512, "name": "rt_sigaction", "abi": "x32"},
            ],
        )

    def test_generic_syscall_definitions(self) -> None:
        path = self.write(
            "#define __NR_read 63\n#define __NR3264_statfs 43\n"
        )
        self.assertEqual(
            generic_syscalls(path),
            [
                {"name": "read", "number": 63, "abi": "common"},
                {"name": "statfs", "number": 43, "abi": "common"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
