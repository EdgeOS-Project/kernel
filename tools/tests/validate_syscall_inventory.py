#!/usr/bin/env python3
"""Validate the canonical EdgeOS Linux syscall inventory against source code."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/syscalls/linux_syscall_inventory.json"
SHARED_SOURCE_DIRECTORY = ROOT / "src/kernel"
LINUX_REFERENCE_COMMIT = "a13c140cc289c0b7b3770bce5b3ad42ab35074aa"
EVIDENCE_STATUSES = {
    "explicit-enosys",
    "oracle-verified-enosys",
    "static-route-only",
    "runtime-probe-listed",
    "oracle-verified",
}
sys.path.insert(0, str(ROOT / "tools/tests"))

from arch_syscall_parity import parse  # noqa: E402


class InventoryError(ValueError):
    pass


def fail(message: str) -> None:
    raise InventoryError(message)


def validate_architecture(
    architecture: str,
    source_name: str,
    entries: list[dict[str, Any]],
    report: dict[str, Any],
) -> None:
    source_numbers = report[source_name]["numbers"]
    source_routes = report[source_name]["routes"]
    inventory_numbers: dict[str, int] = {}
    number_owners: dict[int, str] = {}

    for entry in entries:
        name = entry["id"]
        mapping = entry["architectures"].get(architecture)
        if mapping is None:
            continue
        number = mapping.get("number")
        status = mapping.get("status")
        route = mapping.get("route")
        evidence_status = mapping.get("evidence_status")
        if not isinstance(number, int) or number < 0:
            fail(f"{architecture} {name} has an invalid syscall number")
        previous = number_owners.get(number)
        if previous is not None:
            fail(
                f"{architecture} syscall number {number} is assigned to both "
                f"{previous} and {name}"
            )
        number_owners[number] = name
        inventory_numbers[name] = number
        if route is None:
            fail(f"{architecture} {name} has no route")
        if status not in {"implemented", "enosys"}:
            fail(f"{architecture} {name} has invalid status {status!r}")
        if status == "implemented" and route == "enosys":
            fail(f"{architecture} {name} silently maps implemented to ENOSYS")
        if status == "enosys" and route != "enosys":
            fail(f"{architecture} {name} ENOSYS status has route {route!r}")
        if evidence_status not in EVIDENCE_STATUSES:
            fail(f"{architecture} {name} has invalid evidence status")
        if status == "enosys" and evidence_status not in {
            "explicit-enosys", "oracle-verified-enosys"
        }:
            fail(f"{architecture} {name} ENOSYS route has invalid evidence")
        if status == "implemented" and evidence_status in {
            "explicit-enosys", "oracle-verified-enosys"
        }:
            fail(f"{architecture} {name} implemented route claims ENOSYS evidence")

    if inventory_numbers != source_numbers:
        missing = sorted(set(source_numbers) - set(inventory_numbers))
        extra = sorted(set(inventory_numbers) - set(source_numbers))
        wrong = sorted(
            name
            for name in set(source_numbers) & set(inventory_numbers)
            if source_numbers[name] != inventory_numbers[name]
        )
        fail(
            f"{architecture} syscall-number inventory drift: "
            f"missing={missing} extra={extra} wrong={wrong}"
        )

    for entry in entries:
        name = entry["id"]
        mapping = entry["architectures"].get(architecture)
        if mapping is None:
            continue
        actual_route = source_routes.get(name)
        if actual_route is None:
            fail(f"{architecture} mapped syscall {name} has no source route")
        if mapping["route"] != actual_route:
            fail(
                f"{architecture} {name} route drift: inventory="
                f"{mapping['route']!r} source={actual_route!r}"
            )


def validate_shared_handlers(entries: list[dict[str, Any]]) -> None:
    handlers = {
        entry["shared_handler"]
        for entry in entries
        if entry.get("shared_handler") is not None
    }
    if not handlers:
        return
    sources = sorted(SHARED_SOURCE_DIRECTORY.glob("linux_*.c"))
    if not sources:
        fail("inventory names shared handlers but src/kernel/linux_*.c is missing")
    definitions: set[str] = set()
    definition_pattern = re.compile(
        r"\b(edge_linux_sys_[a-z0-9_]+)\s*\([^;{}]*\)\s*\{",
        re.S,
    )
    for path in sources:
        definitions.update(definition_pattern.findall(
            path.read_text(encoding="utf-8")
        ))
    for handler in sorted(handlers):
        if not isinstance(handler, str) or not re.fullmatch(r"edge_linux_sys_[a-z0-9_]+", handler):
            fail(f"invalid shared handler name {handler!r}")
        if handler not in definitions:
            fail(f"shared handler {handler} has no definition in src/kernel/linux_*.c")


def validate_shared_policy(entries: list[dict[str, Any]]) -> int:
    aarch64_shared_count = 0

    for entry in entries:
        name = entry["id"]
        exceptions = entry.get("architecture_exceptions", [])
        if not isinstance(exceptions, list) or any(
            not isinstance(exception, str) or not exception
            for exception in exceptions
        ):
            fail(f"{name} architecture_exceptions must be a list of strings")

        mappings = entry["architectures"]
        implemented = {
            architecture: mapping
            for architecture, mapping in mappings.items()
            if mapping is not None and mapping.get("status") == "implemented"
        }
        handler = entry.get("shared_handler")
        expected_route = f"shared:{handler}" if handler is not None else None

        if handler is None:
            for architecture, mapping in implemented.items():
                if str(mapping.get("route", "")).startswith("shared:"):
                    fail(
                        f"{architecture} {name} names a shared route without "
                        "declaring shared_handler"
                    )
                if not exceptions:
                    fail(
                        f"{architecture} implemented syscall {name} has no "
                        "shared handler or architecture exception"
                    )
        else:
            for architecture, mapping in implemented.items():
                if mapping.get("route") != expected_route and not exceptions:
                    fail(
                        f"{architecture} {name} bypasses its shared handler: "
                        f"route={mapping.get('route')!r} expected={expected_route!r}"
                    )

        aarch64 = implemented.get("aarch64")
        if aarch64 is not None:
            if aarch64.get("route") == expected_route:
                aarch64_shared_count += 1

        if {"x86_64", "aarch64"}.issubset(implemented):
            if handler is not None and not exceptions:
                for architecture in ("x86_64", "aarch64"):
                    route = implemented[architecture].get("route")
                    if route != expected_route:
                        fail(
                            f"{architecture} common syscall {name} does not use "
                            f"{expected_route!r}: route={route!r}"
                        )

    return aarch64_shared_count


def validate_runtime_tests(entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        tests = entry.get("runtime_tests")
        if not isinstance(tests, list):
            fail(f"{entry['id']} runtime_tests must be a list")
        for test in tests:
            if not isinstance(test, str) or not test:
                fail(f"{entry['id']} has an invalid runtime test entry")
            if not (ROOT / test).exists():
                fail(f"{entry['id']} runtime test does not exist: {test}")
        if entry.get("linux_oracle") != "required":
            fail(f"{entry['id']} must require a frozen Linux oracle")
        if entry.get("oracle_status") not in {
            "not-run", "partial", "verified"
        }:
            fail(f"{entry['id']} has an invalid oracle status")
        for architecture, mapping in entry["architectures"].items():
            if mapping is None:
                continue
            if mapping["status"] == "enosys":
                expected = (
                    "oracle-verified-enosys"
                    if tests and entry["oracle_status"] == "verified"
                    else "explicit-enosys"
                )
                if mapping["evidence_status"] != expected:
                    fail(
                        f"{architecture} {entry['id']} ENOSYS evidence does not "
                        "match its Linux oracle status"
                    )
                continue
            expected = "runtime-probe-listed" if tests else "static-route-only"
            if mapping["evidence_status"] == "oracle-verified":
                if entry["oracle_status"] != "verified":
                    fail(f"{architecture} {entry['id']} lacks oracle verification")
            elif mapping["evidence_status"] != expected:
                fail(
                    f"{architecture} {entry['id']} evidence does not match "
                    "its declared runtime probes"
                )


def validate() -> tuple[int, int, int]:
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        fail("unsupported syscall inventory schema")
    reference = document.get("linux_reference")
    if not isinstance(reference, dict) or reference.get("commit") != LINUX_REFERENCE_COMMIT:
        fail("syscall inventory has the wrong Linux reference commit")
    evidence_semantics = document.get("evidence_semantics")
    if not isinstance(evidence_semantics, dict) or set(evidence_semantics) != EVIDENCE_STATUSES:
        fail("syscall inventory evidence semantics are incomplete")
    entries = document.get("syscalls")
    if not isinstance(entries, list):
        fail("syscall inventory has no syscall list")
    ids = [entry.get("id") for entry in entries]
    if any(not isinstance(name, str) or not name for name in ids):
        fail("syscall inventory contains an invalid canonical ID")
    if len(ids) != len(set(ids)):
        fail("syscall inventory contains duplicate canonical IDs")
    if ids != sorted(ids):
        fail("syscall inventory canonical IDs are not sorted")

    report = parse()
    validate_architecture("x86_64", "x86_64", entries, report)
    validate_architecture("aarch64", "arm64", entries, report)
    validate_shared_handlers(entries)
    aarch64_shared_count = validate_shared_policy(entries)
    validate_runtime_tests(entries)
    return (
        len(entries),
        sum(1 for entry in entries if entry.get("shared_handler")),
        aarch64_shared_count,
    )


def main() -> int:
    try:
        syscall_count, shared_count, aarch64_shared_count = validate()
    except (InventoryError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"syscall inventory validation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"syscall inventory valid: {syscall_count} canonical IDs, "
        f"{shared_count} shared handlers, "
        f"{aarch64_shared_count} AArch64 policies shared"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
