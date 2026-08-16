#!/usr/bin/env python3
"""Regression tests for shared syscall inventory policy validation."""

from __future__ import annotations

import unittest

from tools.tests.validate_syscall_inventory import (
    InventoryError,
    validate_shared_policy,
)


def inventory_entry(
    *,
    shared_handler: str | None,
    x86_64: dict[str, object] | None,
    aarch64: dict[str, object] | None,
    exceptions: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": "example",
        "shared_handler": shared_handler,
        "architecture_exceptions": exceptions or [],
        "architectures": {
            "x86_64": x86_64,
            "aarch64": aarch64,
        },
    }


def implemented(route: str) -> dict[str, object]:
    return {"number": 1, "status": "implemented", "route": route}


class SharedPolicyValidationTests(unittest.TestCase):
    def test_common_shared_handler_is_accepted(self) -> None:
        route = "shared:edge_linux_sys_example"
        entry = inventory_entry(
            shared_handler="edge_linux_sys_example",
            x86_64=implemented(route),
            aarch64=implemented(route),
        )
        self.assertEqual(validate_shared_policy([entry]), 1)

    def test_aarch64_policy_requires_shared_handler(self) -> None:
        entry = inventory_entry(
            shared_handler=None,
            x86_64=None,
            aarch64=implemented("inline:aarch64"),
        )
        with self.assertRaisesRegex(
            InventoryError,
            "aarch64 implemented syscall example has no shared handler or "
            "architecture exception",
        ):
            validate_shared_policy([entry])

    def test_x86_only_policy_requires_shared_handler(self) -> None:
        entry = inventory_entry(
            shared_handler=None,
            x86_64=implemented("do_sys_example"),
            aarch64=None,
        )
        with self.assertRaisesRegex(
            InventoryError,
            "x86_64 implemented syscall example has no shared handler or "
            "architecture exception",
        ):
            validate_shared_policy([entry])

    def test_private_route_cannot_bypass_declared_shared_handler(self) -> None:
        entry = inventory_entry(
            shared_handler="edge_linux_sys_example",
            x86_64=implemented("shared:edge_linux_sys_example"),
            aarch64=implemented("inline:aarch64"),
        )
        with self.assertRaisesRegex(InventoryError, "bypasses its shared handler"):
            validate_shared_policy([entry])

    def test_explicit_architecture_exception_allows_native_mechanism(self) -> None:
        entry = inventory_entry(
            shared_handler=None,
            x86_64=implemented("do_sys_rt_sigreturn"),
            aarch64=implemented("inline:aarch64"),
            exceptions=["Architecture-specific signal-frame restoration"],
        )
        self.assertEqual(validate_shared_policy([entry]), 0)

    def test_shared_route_requires_declared_handler(self) -> None:
        entry = inventory_entry(
            shared_handler=None,
            x86_64=implemented("shared:edge_linux_sys_example"),
            aarch64=None,
            exceptions=["Invalid exception cannot hide a missing handler"],
        )
        with self.assertRaisesRegex(InventoryError, "without declaring shared_handler"):
            validate_shared_policy([entry])


if __name__ == "__main__":
    unittest.main()
