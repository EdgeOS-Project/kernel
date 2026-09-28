#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS cross-architecture guardrail regression tests.
"""Regression tests for the cross-architecture implementation guardrail."""

from __future__ import annotations

import tempfile
import unittest
from collections import Counter
from pathlib import Path
import subprocess

from tools.tests.cross_arch_unity import (
    FunctionDefinition,
    LeakageOccurrence,
    UnityError,
    leakage_digest,
    scan_architecture_leakage,
    scan_function_definitions,
    tracked_c_sources,
    validate_duplicate_inventory,
    validate_leakage_inventory,
    validate_repository,
)


def definition(symbol: str, path: str) -> FunctionDefinition:
    return FunctionDefinition(symbol=symbol, path=path, line=1)


def duplicate_document(
    *,
    mechanisms: dict[str, object] | None = None,
    debt: list[str] | None = None,
) -> dict[str, object]:
    return {
        "true_architecture_mechanisms": mechanisms or {},
        "duplicate_policy_migration_target":
            "Move policy into one shared authoritative kernel implementation.",
        "duplicate_policy_debt": debt or [],
    }


class FunctionScannerTests(unittest.TestCase):
    def test_scanner_finds_only_external_definitions(self) -> None:
        source = """
        /* int kernel_comment(void) { return 0; } */
        const char *text = "int kernel_string(void) { return 0; }";
        int kernel_declaration(void);
        static int kernel_private(void) { return 0; }
        __attribute__((weak))
        int kernel_public(
            int argument
        ) {
            return argument;
        }
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.c"
            path.write_text(source, encoding="utf-8")
            observed = scan_function_definitions(path, "source.c")
        self.assertEqual(
            observed,
            [FunctionDefinition("kernel_public", "source.c", 7)],
        )

    def test_architecture_scanner_ignores_comments_and_literals(self) -> None:
        source = """
        /* arm64_comment ttbr0 pl011_comment */
        const char *description = "x86_64 string";
        #include "arch/arm64/frame.h"
        int common(void) {
            arm64_task_t *task = 0;
            return task ? (int)task->ttbr0 : pl011_read();
        }
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.c"
            path.write_text(source, encoding="utf-8")
            observed = scan_architecture_leakage(path, "source.c")
        self.assertEqual(
            {(item.rule, item.detail) for item in observed},
            {
                ("architecture_include", "arch/arm64/frame.h"),
                ("architecture_identifier", "arm64_task_t"),
                ("architecture_register", "ttbr0"),
                ("platform_identifier", "pl011_read"),
            },
        )

    def test_source_inventory_includes_untracked_nonignored_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(
                ["git", "init", "-q", str(root)],
                check=True,
            )
            (root / "src").mkdir()
            tracked = root / "src/tracked.c"
            untracked = root / "src/untracked.c"
            ignored = root / "src/ignored.c"
            tracked.write_text("int tracked(void) { return 1; }\n", encoding="utf-8")
            untracked.write_text(
                "int untracked(void) { return 2; }\n", encoding="utf-8"
            )
            ignored.write_text("int ignored(void) { return 3; }\n", encoding="utf-8")
            (root / ".gitignore").write_text(
                "src/ignored.c\n", encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "src/tracked.c", ".gitignore"],
                check=True,
            )
            observed = {
                path.relative_to(root).as_posix()
                for path in tracked_c_sources(root)
            }
        self.assertEqual(observed, {"src/tracked.c", "src/untracked.c"})

    def test_source_archive_without_git_metadata_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/kernel/common.c"
            source.parent.mkdir(parents=True)
            source.write_text("int common(void) { return 1; }\n", encoding="utf-8")
            observed = {
                path.relative_to(root).as_posix()
                for path in tracked_c_sources(root)
            }
        self.assertEqual(observed, {"src/kernel/common.c"})


class DuplicateInventoryTests(unittest.TestCase):
    def test_exact_policy_debt_is_accepted(self) -> None:
        actual = {
            "kernel_policy": (
                definition("kernel_policy", "src/first.c"),
                definition("kernel_policy", "src/second.c"),
            )
        }
        mechanisms, debt = validate_duplicate_inventory(
            actual, duplicate_document(debt=["kernel_policy"])
        )
        self.assertEqual((mechanisms, debt), (0, 1))

    def test_unreviewed_duplicate_is_rejected(self) -> None:
        actual = {
            "kernel_new_policy": (
                definition("kernel_new_policy", "src/first.c"),
                definition("kernel_new_policy", "src/second.c"),
            )
        }
        with self.assertRaisesRegex(UnityError, "unreviewed"):
            validate_duplicate_inventory(actual, duplicate_document())

    def test_resolved_debt_must_be_removed_from_inventory(self) -> None:
        with self.assertRaisesRegex(UnityError, "resolved_but_still_in_inventory"):
            validate_duplicate_inventory(
                {}, duplicate_document(debt=["kernel_old_policy"])
            )

    def test_documented_architecture_mechanism_is_accepted(self) -> None:
        actual = {
            "kernel_arch_timer": (
                definition("kernel_arch_timer", "src/arch/a/timer.c"),
                definition("kernel_arch_timer", "src/arch/b/timer.c"),
            )
        }
        document = duplicate_document(
            mechanisms={
                "kernel_arch_timer": {
                    "category": "clock source",
                    "reason": "Reads each architecture's hardware timer counter.",
                }
            }
        )
        self.assertEqual(validate_duplicate_inventory(actual, document), (1, 0))


class LeakageInventoryTests(unittest.TestCase):
    def test_exact_leakage_debt_is_accepted(self) -> None:
        actual = [
            LeakageOccurrence(
                "src/kernel/runtime.c",
                "architecture_identifier",
                "arm64_task_t",
                10,
            )
        ]
        details = Counter({"arm64_task_t": 1})
        document = {
            "architecture_reference_allowlist": [],
            "architecture_leakage_debt": [
                {
                    "path": "src/kernel/runtime.c",
                    "rule": "architecture_identifier",
                    "count": 1,
                    "details_sha256": leakage_digest(details),
                    "migration_target":
                        "Move the native task record behind common task operations.",
                }
            ],
        }
        self.assertEqual(validate_leakage_inventory(actual, document), (0, 1))

    def test_new_leakage_changes_the_exact_debt_fingerprint(self) -> None:
        actual = [
            LeakageOccurrence(
                "src/kernel/runtime.c",
                "architecture_identifier",
                "arm64_task_t",
                10,
            ),
            LeakageOccurrence(
                "src/kernel/runtime.c",
                "architecture_identifier",
                "arm64_new_policy",
                20,
            ),
        ]
        document = {
            "architecture_reference_allowlist": [],
            "architecture_leakage_debt": [
                {
                    "path": "src/kernel/runtime.c",
                    "rule": "architecture_identifier",
                    "count": 1,
                    "details_sha256":
                        leakage_digest(Counter({"arm64_task_t": 1})),
                    "migration_target":
                        "Move the native task record behind common task operations.",
                }
            ],
        }
        with self.assertRaisesRegex(UnityError, "leakage debt drift"):
            validate_leakage_inventory(actual, document)

    def test_allowlist_is_exact_and_documented(self) -> None:
        actual = [
            LeakageOccurrence(
                "src/kernel/seccomp.c",
                "architecture_identifier",
                "AARCH64_AUDIT_ID",
                12,
            )
        ]
        document = {
            "architecture_reference_allowlist": [
                {
                    "path": "src/kernel/seccomp.c",
                    "rule": "architecture_identifier",
                    "detail": "AARCH64_AUDIT_ID",
                    "count": 1,
                    "reason":
                        "The shared seccomp policy emits a Linux UAPI audit value.",
                }
            ],
            "architecture_leakage_debt": [],
        }
        self.assertEqual(validate_leakage_inventory(actual, document), (1, 0))


class RepositoryIntegrationTests(unittest.TestCase):
    def test_checked_in_inventory_matches_current_sources(self) -> None:
        report = validate_repository()
        self.assertEqual(report.duplicate_debt_count, 0)
        self.assertEqual(report.leakage_debt_count, 0)


if __name__ == "__main__":
    unittest.main()
