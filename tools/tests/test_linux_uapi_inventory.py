#!/usr/bin/env python3
"""Tests for the frozen Linux UAPI inventory parser."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from tools.uapi.linux_uapi_inventory import (
    COVERAGE_ASSESSMENTS,
    EDGEOS_ASSESSMENTS,
    define_symbols,
    enum_sequence,
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

    def test_enum_sequence_resolves_automatic_values(self) -> None:
        path = self.write(
            "enum io_uring_op {\n"
            "  IORING_OP_NOP,\n"
            "  IORING_OP_READ = 4,\n"
            "  IORING_OP_LAST,\n"
            "};\n"
        )
        self.assertEqual(
            enum_sequence(path, "io_uring_op", "IORING_OP_"),
            [
                {"name": "IORING_OP_NOP", "value": 0},
                {"name": "IORING_OP_READ", "value": 4},
                {"name": "IORING_OP_LAST", "value": 5},
            ],
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

    def test_io_uring_is_not_overclaimed(self) -> None:
        assessment = next(
            item for item in EDGEOS_ASSESSMENTS
            if item["domain"] == "io_uring"
        )
        self.assertEqual(assessment["status"], "partial")
        self.assertIn("asynchronous worker execution", assessment["missing"])

    def test_edgeos_io_uring_opcode_values_match_frozen_inventory(self) -> None:
        root = Path(__file__).resolve().parents[2]
        inventory = json.loads(
            (root / "tools/uapi/linux_uapi_inventory.json").read_text(
                encoding="utf-8"
            )
        )
        frozen = {
            entry["name"]: entry["value"]
            for entry in inventory["domains"]["io_uring"]["opcodes"]
        }
        source = (root / "src/kernel/linux_syscall.c").read_text(
            encoding="utf-8"
        )
        definitions = re.findall(
            r"^#define\s+EDGE_LINUX_(IORING_OP_[A-Z0-9_]+)\s+([0-9]+)u$",
            source,
            re.MULTILINE,
        )
        self.assertTrue(definitions)
        for name, value in definitions:
            self.assertIn(name, frozen)
            self.assertEqual(int(value), frozen[name], name)

    def test_edgeos_io_uring_setup_bits_match_frozen_inventory(self) -> None:
        root = Path(__file__).resolve().parents[2]
        inventory = json.loads(
            (root / "tools/uapi/linux_uapi_inventory.json").read_text(
                encoding="utf-8"
            )
        )
        frozen = {
            entry["name"]: entry["expression"]
            for entry in inventory["domains"]["io_uring"]["items"]
            if entry["name"].startswith("IORING_SETUP_")
        }
        source = (root / "src/kernel/linux_syscall.c").read_text(
            encoding="utf-8"
        )
        definitions = re.findall(
            r"^#define\s+EDGE_LINUX_(IORING_SETUP_[A-Z0-9_]+)\s+"
            r"\(1u << ([0-9]+)\)$",
            source,
            re.MULTILINE,
        )
        self.assertTrue(definitions)
        for name, bit in definitions:
            self.assertIn(name, frozen)
            frozen_bit = re.fullmatch(
                r"\(1U << ([0-9]+)\)(?:\s*/\*.*\*/)?",
                frozen[name],
            )
            self.assertIsNotNone(frozen_bit, name)
            self.assertEqual(int(bit), int(frozen_bit.group(1)), name)

    def test_coverage_groups_have_unique_identifiers(self) -> None:
        identifiers = [item["id"] for item in COVERAGE_ASSESSMENTS]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertTrue({
            "syscalls-native", "syscalls-ia32", "syscalls-x32",
            "socket-options", "io-uring", "netlink", "procfs", "sysfs",
            "cgroup-v2",
        }.issubset(identifiers))

    def test_extracted_entries_are_explicitly_classified(self) -> None:
        root = Path(__file__).resolve().parents[2]
        inventory = json.loads(
            (root / "tools/uapi/linux_uapi_inventory.json").read_text(
                encoding="utf-8"
            )
        )
        coverage_ids = {
            item["id"] for item in inventory["coverage_assessments"]
        }
        for entries in inventory["domains"]["syscalls"]["architectures"].values():
            self.assertTrue(entries)
            self.assertTrue(all(
                item["assessment"] in coverage_ids and
                item["status"] == "unreviewed"
                for item in entries
            ))
        symbol_domains = [
            *inventory["domains"]["ioctl"].values(),
            inventory["domains"]["socket_options"],
            inventory["domains"]["io_uring"],
            inventory["domains"]["netlink"],
        ]
        for domain in symbol_domains:
            assessment = domain["item_defaults"]["assessment"]
            self.assertIn(assessment, coverage_ids)
            self.assertTrue(all(
                item["assessment"] == assessment and
                item["status"] == "unreviewed"
                for item in domain["items"]
            ))


if __name__ == "__main__":
    unittest.main()
