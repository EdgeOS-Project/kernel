#!/usr/bin/env python3
"""Validate the frozen Linux UAPI inventory without a Linux source checkout."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/uapi/linux_uapi_inventory.json"
REFERENCE_COMMIT = "2c7c88a412aa6d09cd04b414211b4ef8553b5309"
ARCHITECTURES = {"x86_64", "aarch64", "ia32", "x32"}
STATUSES = {
    "unreviewed",
    "unimplemented",
    "partial",
    "configured-off",
    "unsupported-subsystem",
    "verified",
}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class InventoryError(ValueError):
    """Raised when the checked-in UAPI inventory violates its schema."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def validate_sources(sources: object, domain: str) -> None:
    require(isinstance(sources, list) and sources, f"{domain}: missing sources")
    seen: set[str] = set()
    for source in sources:
        require(isinstance(source, dict), f"{domain}: invalid source record")
        path = source.get("path")
        digest = source.get("sha256")
        require(isinstance(path, str) and path, f"{domain}: invalid source path")
        require(path not in seen, f"{domain}: duplicate source {path}")
        require(isinstance(digest, str) and HEX_SHA256.fullmatch(digest) is not None,
                f"{domain}: invalid source digest for {path}")
        seen.add(path)


def validate_syscalls(domain: object) -> None:
    require(isinstance(domain, dict), "syscalls: domain must be an object")
    validate_sources(domain.get("sources"), "syscalls")
    architectures = domain.get("architectures")
    require(isinstance(architectures, dict), "syscalls: missing architectures")
    require(set(architectures) == ARCHITECTURES,
            "syscalls: architecture set does not match scope")
    rules = domain.get("architecture_rules")
    require(isinstance(rules, dict) and set(rules) == ARCHITECTURES,
            "syscalls: missing architecture extraction rules")
    require(rules["x32"].get("syscall_number_or_mask") == "0x40000000",
            "syscalls: missing x32 syscall number mask")
    for architecture, entries in architectures.items():
        require(isinstance(entries, list) and entries,
                f"syscalls/{architecture}: empty table")
        identities: set[tuple[int, str, str]] = set()
        number_names: dict[int, str] = {}
        for entry in entries:
            require(isinstance(entry, dict),
                    f"syscalls/{architecture}: invalid entry")
            number = entry.get("number")
            name = entry.get("name")
            abi = entry.get("abi")
            require(isinstance(number, int) and number >= 0,
                    f"syscalls/{architecture}: invalid number")
            require(isinstance(name, str) and name,
                    f"syscalls/{architecture}: invalid name at {number}")
            require(isinstance(abi, str) and abi,
                    f"syscalls/{architecture}: invalid ABI for {name}")
            identity = (number, name, abi)
            require(identity not in identities,
                    f"syscalls/{architecture}: duplicate {identity}")
            previous = number_names.get(number)
            require(previous is None or previous == name,
                    f"syscalls/{architecture}: number {number} names both "
                    f"{previous} and {name}")
            identities.add(identity)
            number_names[number] = name


def validate_symbol_domain(domain: object, name: str) -> None:
    require(isinstance(domain, dict), f"{name}: domain must be an object")
    validate_sources(domain.get("sources"), name)
    defaults = domain.get("item_defaults")
    require(isinstance(defaults, dict), f"{name}: missing item defaults")
    require(defaults.get("status") in STATUSES, f"{name}: invalid default status")
    require(defaults.get("linux_oracle") == "required",
            f"{name}: Linux oracle must be required")
    items = domain.get("items")
    require(isinstance(items, list), f"{name}: items must be a list")
    identities: set[tuple[str, str]] = set()
    for item in items:
        require(isinstance(item, dict), f"{name}: invalid item")
        identity = (item.get("header"), item.get("name"))
        require(all(isinstance(value, str) and value for value in identity),
                f"{name}: item lacks header or name")
        require(identity not in identities, f"{name}: duplicate item {identity}")
        require(isinstance(item.get("expression"), str),
                f"{name}: item lacks expression")
        identities.add(identity)


def validate_io_uring(domain: object) -> None:
    validate_symbol_domain(domain, "io_uring")
    require(isinstance(domain, dict), "io_uring: domain must be an object")
    opcodes = domain.get("opcodes")
    require(isinstance(opcodes, list) and opcodes,
            "io_uring: missing resolved opcode sequence")
    names: set[str] = set()
    for expected, opcode in enumerate(opcodes):
        require(isinstance(opcode, dict), "io_uring: invalid opcode")
        name = opcode.get("name")
        value = opcode.get("value")
        require(isinstance(name, str) and name.startswith("IORING_OP_"),
                "io_uring: invalid opcode name")
        require(name not in names, f"io_uring: duplicate opcode {name}")
        require(value == expected,
                f"io_uring: non-contiguous opcode {name}={value}")
        names.add(name)
    require(opcodes[-1] == {"name": "IORING_OP_LAST", "value": 65},
            "io_uring: frozen opcode extent changed")


def validate_assessments(assessments: object) -> None:
    require(isinstance(assessments, list), "assessments must be a list")
    domains: set[str] = set()
    for assessment in assessments:
        require(isinstance(assessment, dict), "invalid assessment")
        domain = assessment.get("domain")
        require(isinstance(domain, str) and domain,
                "assessment lacks a domain")
        require(domain not in domains, f"duplicate assessment {domain}")
        require(assessment.get("status") in STATUSES,
                f"{domain}: invalid assessment status")
        architectures = assessment.get("architectures")
        require(isinstance(architectures, dict) and
                set(architectures) == ARCHITECTURES,
                f"{domain}: incomplete architecture assessment")
        tests = assessment.get("runtime_tests")
        require(isinstance(tests, list),
                f"{domain}: runtime tests must be a list")
        oracle = assessment.get("linux_oracle")
        require(isinstance(oracle, dict) and
                oracle.get("reference") == REFERENCE_COMMIT,
                f"{domain}: missing frozen Linux oracle")
        if assessment.get("status") == "verified":
            require(oracle.get("status") == "verified",
                    f"{domain}: verified without a verified oracle")
            require(all(value == "runtime-verified"
                        for value in architectures.values()),
                    f"{domain}: verified without every architecture")
        domains.add(domain)


def validate(document: object) -> None:
    require(isinstance(document, dict), "inventory must be an object")
    require(document.get("schema") == 1, "unsupported inventory schema")
    reference = document.get("reference")
    require(isinstance(reference, dict), "missing Linux reference")
    require(reference.get("commit") == REFERENCE_COMMIT,
            "Linux reference commit changed")
    require(isinstance(reference.get("version"), str) and reference["version"],
            "missing Linux reference version")
    semantics = document.get("status_semantics")
    require(isinstance(semantics, dict) and set(semantics) == STATUSES,
            "status semantics are incomplete")
    scope = document.get("scope")
    require(isinstance(scope, dict), "missing scope")
    require(set(scope.get("architectures", [])) == ARCHITECTURES,
            "scope architecture set is incomplete")
    require(scope.get("default_status") == "unreviewed",
            "new UAPI entries must default to unreviewed")
    validate_assessments(document.get("edgeos_assessments"))
    domains = document.get("domains")
    require(isinstance(domains, dict), "missing domains")
    require({"syscalls", "ioctl", "socket_options", "io_uring", "netlink",
             "virtual_filesystems"}.issubset(domains), "missing required domain")
    validate_syscalls(domains["syscalls"])
    ioctl = domains["ioctl"]
    require(isinstance(ioctl, dict) and ioctl, "missing ioctl groups")
    for group, domain in ioctl.items():
        validate_symbol_domain(domain, f"ioctl/{group}")
    validate_symbol_domain(domains["socket_options"], "socket_options")
    validate_io_uring(domains["io_uring"])
    validate_symbol_domain(domains["netlink"], "netlink")
    virtual_filesystems = domains["virtual_filesystems"]
    require(isinstance(virtual_filesystems, dict),
            "virtual_filesystems: domain must be an object")
    require(virtual_filesystems.get("status") == "snapshot-required",
            "virtual_filesystems: runtime snapshots must be required")


def main() -> int:
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    validate(document)
    counts = {
        architecture: len(entries)
        for architecture, entries in
        document["domains"]["syscalls"]["architectures"].items()
    }
    print(f"Linux UAPI inventory is valid: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
