#!/usr/bin/env python3
"""Regression tests for EdgeOS syscall routing inventory parsing."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("arch_syscall_parity.py")
SPEC = importlib.util.spec_from_file_location("arch_syscall_parity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PARITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARITY)


class Arm64DispatchParserTests(unittest.TestCase):
    def test_only_dispatcher_conditions_are_routes(self) -> None:
        source = r"""
#define LINUX_SYS_alpha 1u
#define LINUX_SYS_beta 2u
#define LINUX_SYS_declaration_only 3u

static int unrelated(void) {
    return LINUX_SYS_declaration_only;
}

static long bootstrap_syscall_impl(unsigned long nr) {
    if (nr == LINUX_SYS_alpha) return 0;
    if (nr == LINUX_SYS_beta) return -LINUX_ENOSYS;
    return -LINUX_ENOSYS;
}
"""
        declared = {"alpha", "beta", "declaration_only"}
        routed, stubs, handlers = PARITY.parse_arm64_dispatch(source, declared)
        self.assertEqual(routed, {"alpha", "beta"})
        self.assertEqual(stubs, {"beta"})
        self.assertEqual(
            handlers,
            {
                "alpha": "inline:aarch64",
                "beta": "enosys",
            },
        )

    def test_switch_cases_are_routes(self) -> None:
        source = r"""
#define LINUX_SYS_gamma 4u
static long bootstrap_syscall_impl(unsigned long nr) {
    switch (nr) {
    case LINUX_SYS_gamma:
        return 7;
    default:
        return -LINUX_ENOSYS;
    }
}
"""
        routed, stubs, _ = PARITY.parse_arm64_dispatch(source, {"gamma"})
        self.assertEqual(routed, {"gamma"})
        self.assertEqual(stubs, set())

    def test_direct_runtime_handler_is_reported(self) -> None:
        source = r"""
#define LINUX_SYS_openat 56u
static long bootstrap_syscall_impl(unsigned long nr) {
    if (nr == LINUX_SYS_openat) {
        return kernel_vfs_open_at(0, 0, 0, 0);
    }
    return -LINUX_ENOSYS;
}
"""
        routed, stubs, handlers = PARITY.parse_arm64_dispatch(
            source, {"openat"}
        )
        self.assertEqual(routed, {"openat"})
        self.assertEqual(stubs, set())
        self.assertEqual(handlers, {"openat": "kernel_vfs_open_at"})

    def test_split_dispatcher_tail_is_reported(self) -> None:
        source = r"""
#define LINUX_SYS_alpha 1u
#define LINUX_SYS_omega 2u
static long bootstrap_syscall_tail(unsigned long nr) {
    if (nr == LINUX_SYS_omega) return 9;
    return -LINUX_ENOSYS;
}
static long bootstrap_syscall_impl(unsigned long nr) {
    if (nr == LINUX_SYS_alpha) return 3;
    return bootstrap_syscall_tail(nr);
}
"""
        routed, stubs, handlers = PARITY.parse_arm64_dispatch(
            source, {"alpha", "omega"}
        )
        self.assertEqual(routed, {"alpha", "omega"})
        self.assertEqual(stubs, set())
        self.assertEqual(
            handlers,
            {
                "alpha": "inline:aarch64",
                "omega": "inline:aarch64",
            },
        )


class DefinitionParserTests(unittest.TestCase):
    def test_numeric_suffixes_and_hex_values(self) -> None:
        source = """
#define SYS_alpha 12
#define SYS_beta 0x20u
#define SYS_gamma 44ULL
"""
        self.assertEqual(
            PARITY.parse_numeric_definitions(source, "SYS_"),
            {"alpha": 12, "beta": 32, "gamma": 44},
        )

    def test_conflicting_redefinition_is_rejected(self) -> None:
        source = """
#define SYS_alpha 12
#define SYS_alpha 13
"""
        with self.assertRaisesRegex(ValueError, "conflicting SYS_alpha"):
            PARITY.parse_numeric_definitions(source, "SYS_")


if __name__ == "__main__":
    unittest.main()
