#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Original EdgeOS cross-architecture implementation guardrail.
"""Enforce one authoritative implementation for architecture-neutral policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/tests/cross_arch_unity_inventory.json"

KERNEL_SERVICE_RE = re.compile(r"kernel_[A-Za-z0-9_]+\Z")
ARCHITECTURE_IDENTIFIER_RE = re.compile(
    r"\b(?:arm64|aarch64|x86_64|x86)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
ARCHITECTURE_REGISTER_RE = re.compile(
    r"\b(?:"
    r"ttbr[01](?:_el1)?|tpidr_el[01]|elr_el1|spsr_el1|esr_el1|"
    r"far_el1|vbar_el1|mair_el1|tcr_el1|sctlr_el1|"
    r"cr[0234]|xcr0"
    r")\b",
    re.IGNORECASE,
)
PLATFORM_IDENTIFIER_RE = re.compile(
    r"\b(?:pl011|gicv?[0-9]*|ioapic|lapic|apic|hpet)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
ARCHITECTURE_INCLUDE_RE = re.compile(
    r"^[ \t]*#[ \t]*include[ \t]*[<\"](?P<path>arch/[^>\"]+)[>\"]",
    re.MULTILINE,
)
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[{}();,*=]")

LEAKAGE_RULES = {
    "architecture_identifier": ARCHITECTURE_IDENTIFIER_RE,
    "architecture_register": ARCHITECTURE_REGISTER_RE,
    "platform_identifier": PLATFORM_IDENTIFIER_RE,
}
MECHANISM_CATEGORIES = {
    "address-space mechanics",
    "clock source",
    "console hardware",
    "CPU topology",
    "register ABI conversion",
    "signal frame mechanics",
}


class UnityError(ValueError):
    """Raised when the checked-in unity contract does not match source."""


@dataclass(frozen=True, order=True)
class FunctionDefinition:
    symbol: str
    path: str
    line: int


@dataclass(frozen=True, order=True)
class LeakageOccurrence:
    path: str
    rule: str
    detail: str
    line: int


@dataclass(frozen=True)
class UnityReport:
    duplicate_definitions: Mapping[str, tuple[FunctionDefinition, ...]]
    leakage: tuple[LeakageOccurrence, ...]
    mechanism_count: int
    duplicate_debt_count: int
    allowed_reference_count: int
    leakage_debt_count: int


def fail(message: str) -> None:
    raise UnityError(message)


def _blank_character(character: str) -> str:
    return "\n" if character == "\n" else " "


def sanitize_c_source(source: str) -> str:
    """Blank comments and literals while preserving offsets and line numbers."""

    output = list(source)
    index = 0
    length = len(source)
    state = "code"

    while index < length:
        current = source[index]
        following = source[index + 1] if index + 1 < length else ""

        if state == "code":
            if current == "/" and following == "*":
                output[index] = " "
                output[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if current == "/" and following == "/":
                output[index] = " "
                output[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if current == '"':
                output[index] = " "
                index += 1
                state = "string"
                continue
            if current == "'":
                output[index] = " "
                index += 1
                state = "character"
                continue
            index += 1
            continue

        output[index] = _blank_character(current)
        if state == "block_comment":
            if current == "*" and following == "/":
                output[index + 1] = " "
                index += 2
                state = "code"
                continue
        elif state == "line_comment":
            if current == "\n":
                state = "code"
        elif state in {"string", "character"}:
            delimiter = '"' if state == "string" else "'"
            if current == "\\" and index + 1 < length:
                output[index + 1] = _blank_character(source[index + 1])
                index += 2
                continue
            if current == delimiter:
                state = "code"
        index += 1

    return "".join(output)


def blank_preprocessor_directives(source: str) -> str:
    """Blank complete preprocessor directives, including continued lines."""

    output: list[str] = []
    continuing = False
    for line in source.splitlines(keepends=True):
        directive = continuing or line.lstrip().startswith("#")
        if directive:
            output.append("".join(_blank_character(character) for character in line))
            continuing = line.rstrip("\r\n").rstrip().endswith("\\")
        else:
            output.append(line)
            continuing = False
    return "".join(output)


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def scan_function_definitions(path: Path, relative_path: str) -> list[FunctionDefinition]:
    """Return externally visible kernel service definitions in one C source."""

    source = path.read_text(encoding="utf-8")
    sanitized = blank_preprocessor_directives(sanitize_c_source(source))
    matches = list(TOKEN_RE.finditer(sanitized))
    definitions: list[FunctionDefinition] = []
    depth = 0
    boundary = 0
    index = 0

    while index < len(matches):
        token = matches[index].group(0)
        if token == "{":
            depth += 1
            index += 1
            continue
        if token == "}":
            depth = max(depth - 1, 0)
            if depth == 0:
                boundary = index + 1
            index += 1
            continue
        if depth != 0:
            index += 1
            continue
        if token in {";", "="}:
            boundary = index + 1
            index += 1
            continue
        if not KERNEL_SERVICE_RE.fullmatch(token):
            index += 1
            continue
        if index + 1 >= len(matches) or matches[index + 1].group(0) != "(":
            index += 1
            continue

        parenthesis_depth = 0
        close_index: int | None = None
        cursor = index + 1
        while cursor < len(matches):
            current = matches[cursor].group(0)
            if current == "(":
                parenthesis_depth += 1
            elif current == ")":
                parenthesis_depth -= 1
                if parenthesis_depth == 0:
                    close_index = cursor
                    break
            elif current in {";", "{", "}"} and parenthesis_depth == 0:
                break
            cursor += 1
        if close_index is None:
            index += 1
            continue

        body_index = close_index + 1
        attribute_depth = 0
        while body_index < len(matches):
            current = matches[body_index].group(0)
            if current == "(":
                attribute_depth += 1
            elif current == ")":
                attribute_depth = max(attribute_depth - 1, 0)
            elif attribute_depth == 0 and current in {";", "=", "}"}:
                break
            elif attribute_depth == 0 and current == "{":
                declaration_tokens = {
                    item.group(0) for item in matches[boundary:index]
                }
                if "static" not in declaration_tokens and "typedef" not in declaration_tokens:
                    definitions.append(
                        FunctionDefinition(
                            symbol=token,
                            path=relative_path,
                            line=_line_number(sanitized, matches[index].start()),
                        )
                    )
                break
            body_index += 1
        index += 1

    return definitions


def scan_architecture_leakage(path: Path, relative_path: str) -> list[LeakageOccurrence]:
    """Find direct architecture dependencies in a designated common C source."""

    source = path.read_text(encoding="utf-8")
    occurrences = [
        LeakageOccurrence(
            path=relative_path,
            rule="architecture_include",
            detail=match.group("path"),
            line=_line_number(source, match.start()),
        )
        for match in ARCHITECTURE_INCLUDE_RE.finditer(source)
    ]
    sanitized = blank_preprocessor_directives(sanitize_c_source(source))
    for rule, pattern in LEAKAGE_RULES.items():
        for match in pattern.finditer(sanitized):
            occurrences.append(
                LeakageOccurrence(
                    path=relative_path,
                    rule=rule,
                    detail=match.group(0),
                    line=_line_number(sanitized, match.start()),
                )
            )
    return sorted(occurrences)


def tracked_c_sources(root: Path) -> list[Path]:
    """Return tracked and not-ignored first-party C sources.

    Including untracked source files makes the build-time guardrail reject new
    architecture debt before a developer stages it. Ignored build output and
    vendored trees remain outside the scan. Source archives without Git
    metadata fall back to the same first-party source root so release builds do
    not acquire an otherwise unnecessary Git runtime dependency.
    """

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                "src",
            ],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        paths = list((root / "src").rglob("*.c"))
    else:
        paths = [
            root / item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item and item.decode("utf-8").endswith(".c")
        ]
    return sorted(path for path in paths if path.is_file())


def common_runtime_sources(
    root: Path, source_paths: Iterable[Path], common_roots: Sequence[str]
) -> list[Path]:
    normalized_roots = tuple(
        str(Path(item).as_posix()).rstrip("/") + "/" for item in common_roots
    )
    selected = []
    for path in source_paths:
        relative = path.relative_to(root).as_posix()
        if relative.startswith(normalized_roots):
            selected.append(path)
    return sorted(selected)


def duplicate_kernel_services(
    root: Path, source_paths: Iterable[Path]
) -> dict[str, tuple[FunctionDefinition, ...]]:
    definitions: dict[str, list[FunctionDefinition]] = defaultdict(list)
    for path in source_paths:
        relative = path.relative_to(root).as_posix()
        for definition in scan_function_definitions(path, relative):
            definitions[definition.symbol].append(definition)
    return {
        symbol: tuple(sorted(items))
        for symbol, items in sorted(definitions.items())
        if len({item.path for item in items}) > 1
    }


def architecture_leakage(
    root: Path, source_paths: Iterable[Path], common_roots: Sequence[str]
) -> tuple[LeakageOccurrence, ...]:
    occurrences: list[LeakageOccurrence] = []
    for path in common_runtime_sources(root, source_paths, common_roots):
        occurrences.extend(
            scan_architecture_leakage(path, path.relative_to(root).as_posix())
        )
    return tuple(sorted(occurrences))


def leakage_digest(details: Counter[str]) -> str:
    payload = json.dumps(
        sorted(details.items()),
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_sorted_mapping(name: str, value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    if list(value) != sorted(value):
        fail(f"{name} keys must be sorted")
    return value


def _require_description(name: str, value: Any) -> str:
    if not isinstance(value, str) or len(value.strip()) < 12:
        fail(f"{name} must contain a specific explanation")
    return value


def validate_duplicate_inventory(
    actual: Mapping[str, tuple[FunctionDefinition, ...]],
    document: Mapping[str, Any],
) -> tuple[int, int]:
    mechanisms = _require_sorted_mapping(
        "true_architecture_mechanisms",
        document.get("true_architecture_mechanisms"),
    )
    debt_value = document.get("duplicate_policy_debt")
    if (
        not isinstance(debt_value, list)
        or any(not isinstance(symbol, str) for symbol in debt_value)
        or debt_value != sorted(set(debt_value))
    ):
        fail("duplicate_policy_debt must be a sorted list of unique symbols")
    debt = set(debt_value)
    _require_description(
        "duplicate_policy_migration_target",
        document.get("duplicate_policy_migration_target"),
    )
    overlap = set(mechanisms) & debt
    if overlap:
        fail(f"duplicate symbols appear in both mechanism and debt inventory: {sorted(overlap)}")

    for symbol, metadata in mechanisms.items():
        if not KERNEL_SERVICE_RE.fullmatch(symbol):
            fail(f"invalid architecture-mechanism symbol {symbol!r}")
        if not isinstance(metadata, dict):
            fail(f"architecture mechanism {symbol} metadata must be an object")
        category = metadata.get("category")
        if category not in MECHANISM_CATEGORIES:
            fail(f"architecture mechanism {symbol} has invalid category {category!r}")
        _require_description(
            f"architecture mechanism {symbol} reason", metadata.get("reason")
        )

    for symbol in debt:
        if not KERNEL_SERVICE_RE.fullmatch(symbol):
            fail(f"invalid duplicate-policy symbol {symbol!r}")

    expected = set(mechanisms) | debt
    observed = set(actual)
    added = sorted(observed - expected)
    stale = sorted(expected - observed)
    if added or stale:
        details = []
        if added:
            owners = {
                symbol: [item.path for item in actual[symbol]] for symbol in added
            }
            details.append(f"unreviewed={owners}")
        if stale:
            details.append(f"resolved_but_still_in_inventory={stale}")
        fail("duplicate kernel-service inventory drift: " + " ".join(details))
    return len(mechanisms), len(debt)


def _leakage_counter(
    occurrences: Iterable[LeakageOccurrence],
) -> Counter[tuple[str, str, str]]:
    return Counter((item.path, item.rule, item.detail) for item in occurrences)


def validate_leakage_inventory(
    actual: Iterable[LeakageOccurrence],
    document: Mapping[str, Any],
) -> tuple[int, int]:
    counter = _leakage_counter(actual)
    allowed = document.get("architecture_reference_allowlist")
    debt = document.get("architecture_leakage_debt")
    if not isinstance(allowed, list):
        fail("architecture_reference_allowlist must be a list")
    if not isinstance(debt, list):
        fail("architecture_leakage_debt must be a list")

    allowed_keys: set[tuple[str, str, str]] = set()
    allowed_count = 0
    for index, entry in enumerate(allowed):
        if not isinstance(entry, dict):
            fail(f"architecture reference {index} must be an object")
        key = (entry.get("path"), entry.get("rule"), entry.get("detail"))
        if not all(isinstance(item, str) and item for item in key):
            fail(f"architecture reference {index} has an invalid key")
        if key in allowed_keys:
            fail(f"duplicate architecture reference allowlist key {key}")
        allowed_keys.add(key)
        count = entry.get("count")
        if not isinstance(count, int) or count <= 0:
            fail(f"architecture reference {key} has an invalid count")
        _require_description(
            f"architecture reference {key} reason", entry.get("reason")
        )
        observed = counter.pop(key, 0)
        if observed != count:
            fail(
                f"architecture reference allowlist drift for {key}: "
                f"inventory={count} source={observed}"
            )
        allowed_count += count

    remaining: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for (path, rule, detail), count in counter.items():
        remaining[(path, rule)][detail] += count

    debt_keys: set[tuple[str, str]] = set()
    debt_count = 0
    for index, entry in enumerate(debt):
        if not isinstance(entry, dict):
            fail(f"architecture leakage debt {index} must be an object")
        key = (entry.get("path"), entry.get("rule"))
        if not all(isinstance(item, str) and item for item in key):
            fail(f"architecture leakage debt {index} has an invalid key")
        if key in debt_keys:
            fail(f"duplicate architecture leakage debt key {key}")
        debt_keys.add(key)
        count = entry.get("count")
        digest = entry.get("details_sha256")
        if not isinstance(count, int) or count <= 0:
            fail(f"architecture leakage debt {key} has an invalid count")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"architecture leakage debt {key} has an invalid digest")
        _require_description(
            f"architecture leakage debt {key} migration_target",
            entry.get("migration_target"),
        )
        details = remaining.pop(key, Counter())
        observed_count = sum(details.values())
        observed_digest = leakage_digest(details)
        if observed_count != count or observed_digest != digest:
            fail(
                f"architecture leakage debt drift for {key}: "
                f"inventory_count={count} source_count={observed_count} "
                f"inventory_digest={digest} source_digest={observed_digest} "
                f"source_details={dict(sorted(details.items()))}"
            )
        debt_count += count

    if remaining:
        formatted = {
            f"{path}:{rule}": dict(sorted(details.items()))
            for (path, rule), details in sorted(remaining.items())
        }
        fail(f"unreviewed common-runtime architecture leakage: {formatted}")
    return allowed_count, debt_count


def load_inventory(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load cross-architecture unity inventory: {error}")
    if not isinstance(document, dict) or document.get("schema") != 1:
        fail("unsupported cross-architecture unity inventory schema")
    common_roots = document.get("common_runtime_roots")
    if (
        not isinstance(common_roots, list)
        or not common_roots
        or any(not isinstance(item, str) or not item for item in common_roots)
    ):
        fail("common_runtime_roots must be a non-empty list of paths")
    return document


def validate_repository(root: Path = ROOT, inventory: Path = INVENTORY) -> UnityReport:
    document = load_inventory(inventory)
    sources = tracked_c_sources(root)
    duplicates = duplicate_kernel_services(root, sources)
    leakage = architecture_leakage(root, sources, document["common_runtime_roots"])
    mechanism_count, duplicate_debt_count = validate_duplicate_inventory(
        duplicates, document
    )
    allowed_reference_count, leakage_debt_count = validate_leakage_inventory(
        leakage, document
    )
    return UnityReport(
        duplicate_definitions=duplicates,
        leakage=leakage,
        mechanism_count=mechanism_count,
        duplicate_debt_count=duplicate_debt_count,
        allowed_reference_count=allowed_reference_count,
        leakage_debt_count=leakage_debt_count,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--inventory", type=Path, default=INVENTORY)
    arguments = parser.parse_args(argv)
    try:
        report = validate_repository(
            arguments.root.resolve(), arguments.inventory.resolve()
        )
    except (UnityError, OSError, subprocess.CalledProcessError) as error:
        print(f"cross-architecture unity guardrail failed: {error}", file=sys.stderr)
        return 1
    print(
        "cross-architecture unity guardrail passed: "
        f"{report.mechanism_count} reviewed architecture mechanisms, "
        f"{report.duplicate_debt_count} duplicate policy services to migrate, "
        f"{report.allowed_reference_count} reviewed architecture references, "
        f"{report.leakage_debt_count} common-runtime architecture references "
        "to migrate"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
