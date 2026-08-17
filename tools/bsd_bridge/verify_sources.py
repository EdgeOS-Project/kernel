#!/usr/bin/env python3
"""Verify that imported BSD driver sources match their pinned upstream tree."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from catalog import discover_json_files
from manifest import ManifestError, iter_module_sources, load_manifest, locate_repo_root


SPDX_PATTERN = re.compile(r"SPDX-License-Identifier:\s*([^\r\n]+)")
SPDX_EXPRESSION_TOKEN_PATTERN = re.compile(
    r"\s*(\(|\)|AND\b|OR\b|[A-Za-z0-9][A-Za-z0-9.+-]*)"
)
ISC_PERMISSION = (
    "Permission to use, copy, modify, and distribute this software for any"
)
PUBLIC_DOMAIN_DECLARATION = re.compile(
    r"\b(?:this file|this code) is (?:hereby )?placed in the public domain\b",
    re.IGNORECASE,
)
VENDORED_METADATA_BASENAMES = frozenset({".DS_Store", "README.md"})


def license_expression_is_covered(
    expression: str, allowed_licenses: set[str]
) -> bool:
    """Return whether an SPDX expression offers an allowed license choice."""

    if expression in allowed_licenses:
        return True

    tokens: list[str] = []
    offset = 0
    while offset < len(expression):
        match = SPDX_EXPRESSION_TOKEN_PATTERN.match(expression, offset)
        if match is None:
            return False
        tokens.append(match.group(1))
        offset = match.end()

    position = 0

    def parse_primary() -> bool:
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        token = tokens[position]
        position += 1
        if token == "(":
            value = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError
            position += 1
            return value
        if token in {"AND", "OR", ")"}:
            raise ValueError
        return token in allowed_licenses

    def parse_and() -> bool:
        nonlocal position
        value = parse_primary()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            right = parse_primary()
            value = value and right
        return value

    def parse_or() -> bool:
        nonlocal position
        value = parse_and()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            right = parse_and()
            value = value or right
        return value

    try:
        covered = parse_or()
    except ValueError:
        return False
    return covered and position == len(tokens)


def _locked_files(upstream_root: Path, locked_paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for relative in locked_paths:
        candidate = upstream_root / relative
        if candidate.is_symlink():
            raise ManifestError(f"locked path must not be a symbolic link: {relative}")
        if candidate.is_file():
            files.append(candidate)
            continue
        if not candidate.is_dir():
            raise ManifestError(f"locked path does not exist: {relative}")
        for item in candidate.rglob("*"):
            if item.is_symlink():
                raise ManifestError(
                    f"locked source tree contains a symbolic link: "
                    f"{item.relative_to(upstream_root)}"
                )
            if item.is_file():
                files.append(item)
    return sorted(
        set(files), key=lambda item: item.relative_to(upstream_root).as_posix()
    )


def source_tree_digest(
    upstream_root: Path, locked_paths: list[str]
) -> tuple[str, int]:
    digest = hashlib.sha256()
    files = _locked_files(upstream_root, locked_paths)
    for path in files:
        relative = path.relative_to(upstream_root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest(), len(files)


def detect_source_license(path: Path) -> str | None:
    """Return the declared or recognizable BSD license for one source file."""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:65536]
    except OSError as exc:
        raise ManifestError(f"cannot read license text from {path}: {exc}") from exc

    spdx = SPDX_PATTERN.search(text)
    if spdx:
        return spdx.group(1).strip().rstrip("*/").strip()

    if PUBLIC_DOMAIN_DECLARATION.search(text):
        return "Public-Domain"
    if ISC_PERMISSION in text and "with or without fee is hereby granted" in text:
        return "ISC"
    if "Redistribution and use in source and binary forms" not in text:
        return None
    if "All advertising materials mentioning features or use" in text:
        return "BSD-4-Clause"
    if re.search(r"(?:^|\n)\s*(?:\*|#)?\s*3\.\s+Neither\b", text):
        return "BSD-3-Clause"
    return "BSD-2-Clause"


def verify_manifest_licenses(
    manifest_path: Path, repo_root: Path | None = None
) -> dict[str, int]:
    """Require every locked file to have an allowed, auditable license."""

    manifest = load_manifest(manifest_path)
    if repo_root is None:
        repo_root = locate_repo_root(manifest_path)
    upstream_root = repo_root / manifest["upstream"]["root"]
    source_policy = manifest["source_policy"]
    allowed = set(source_policy["allowed_licenses"])
    exceptions = source_policy["license_exceptions"]
    used_exceptions: set[str] = set()
    counts: Counter[str] = Counter()

    for path in _locked_files(upstream_root, manifest["source_lock"]["paths"]):
        relative = path.relative_to(upstream_root).as_posix()
        license_id = detect_source_license(path)
        exception = exceptions.get(relative)
        if license_id is None:
            if exception is None:
                raise ManifestError(
                    f"locked source has no auditable license: {relative}"
                )
            license_id = exception["license"]
            used_exceptions.add(relative)
        elif exception is not None:
            raise ManifestError(
                f"license exception is unnecessary for {relative}"
            )
        if not license_expression_is_covered(license_id, allowed):
            raise ManifestError(
                f"locked source {relative} uses disallowed license {license_id}"
            )
        counts[license_id] += 1

    unused_exceptions = sorted(set(exceptions) - used_exceptions)
    if unused_exceptions:
        raise ManifestError(
            "unused license exceptions: " + ", ".join(unused_exceptions)
        )
    return dict(sorted(counts.items()))


def _git_output(upstream_root: Path, arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(upstream_root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ManifestError("git is required to verify the pinned upstream commit") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise ManifestError(f"git verification failed: {detail}") from exc
    return result.stdout.strip()


def verify_manifest_sources(
    manifest_path: Path, repo_root: Path | None = None
) -> tuple[str, int]:
    manifest = load_manifest(manifest_path)
    if repo_root is None:
        repo_root = locate_repo_root(manifest_path)
    upstream_root = repo_root / manifest["upstream"]["root"]
    if not upstream_root.is_dir():
        raise ManifestError(f"upstream source root does not exist: {upstream_root}")

    locked_paths = manifest["source_lock"]["paths"]
    if not manifest["upstream"]["vendored"]:
        expected_commit = manifest["upstream"]["commit"]
        actual_commit = _git_output(upstream_root, ["rev-parse", "HEAD"])
        if actual_commit != expected_commit:
            raise ManifestError(
                f"upstream commit mismatch: expected {expected_commit}, "
                f"got {actual_commit}"
            )

        tracked_changes = _git_output(
            upstream_root,
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
                "--",
                *locked_paths,
            ],
        )
        if tracked_changes:
            raise ManifestError(
                "pinned upstream source contains tracked modifications:\n"
                f"{tracked_changes}"
            )

    for module_id, relative in iter_module_sources(manifest):
        source = upstream_root / relative
        if not source.is_file():
            raise ManifestError(f"module {module_id} source does not exist: {relative}")
    for relative in manifest["generated_interfaces"]:
        interface = upstream_root / relative
        if not interface.is_file():
            raise ManifestError(f"generated interface source does not exist: {relative}")

    for patch in manifest["source_policy"]["patches"]:
        patched_path = upstream_root / patch["path"]
        if not patched_path.is_file():
            raise ManifestError(
                f"declared patched source does not exist: {patch['path']}"
            )
        patched_digest = hashlib.sha256(patched_path.read_bytes()).hexdigest()
        if patched_digest == patch["upstream_sha256"]:
            raise ManifestError(
                f"declared patched source still matches upstream: {patch['path']}"
            )

    actual_digest, actual_count = source_tree_digest(upstream_root, locked_paths)
    expected_digest = manifest["source_lock"]["tree_sha256"]
    expected_count = manifest["source_lock"]["file_count"]
    if actual_count != expected_count:
        raise ManifestError(
            f"source file count mismatch: expected {expected_count}, got {actual_count}"
        )
    if actual_digest != expected_digest:
        raise ManifestError(
            f"source tree digest mismatch: expected {expected_digest}, "
            f"got {actual_digest}"
        )
    verify_manifest_licenses(manifest_path, repo_root)
    return actual_digest, actual_count


def verify_vendored_source_coverage(
    manifest_paths: list[Path], repo_root: Path
) -> dict[str, int]:
    """Require every vendored upstream file to be covered by a source lock."""

    covered_by_root: dict[Path, set[str]] = {}
    display_root: dict[Path, str] = {}
    for manifest_path in manifest_paths:
        manifest = load_manifest(manifest_path)
        if not manifest["upstream"]["vendored"]:
            continue
        relative_root = manifest["upstream"]["root"]
        upstream_root = (repo_root / relative_root).resolve()
        display_root[upstream_root] = relative_root
        covered = covered_by_root.setdefault(upstream_root, set())
        covered.update(
            path.relative_to(upstream_root).as_posix()
            for path in _locked_files(
                upstream_root, manifest["source_lock"]["paths"]
            )
        )

    results: dict[str, int] = {}
    for upstream_root, covered in covered_by_root.items():
        if not upstream_root.is_dir():
            raise ManifestError(
                f"vendored upstream root does not exist: {upstream_root}"
            )
        actual = {
            path.relative_to(upstream_root).as_posix()
            for path in upstream_root.rglob("*")
            if path.is_file()
            and path.name not in VENDORED_METADATA_BASENAMES
        }
        uncovered = sorted(actual - covered)
        if uncovered:
            raise ManifestError(
                f"vendored source files are not covered by a source lock in "
                f"{display_root[upstream_root]}: {', '.join(uncovered)}"
            )
        results[display_root[upstream_root]] = len(actual)
    return dict(sorted(results.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        action="append",
    )
    parser.add_argument(
        "--manifest-dir",
        type=Path,
        default=Path("config/bsd_drivers/manifests"),
    )
    parser.add_argument("--repo-root", type=Path)
    arguments = parser.parse_args()

    try:
        repo_root = (
            arguments.repo_root.resolve()
            if arguments.repo_root
            else locate_repo_root(Path.cwd())
        )
        manifest_paths = (
            [path.resolve() for path in arguments.manifest]
            if arguments.manifest
            else discover_json_files(
                (repo_root / arguments.manifest_dir).resolve()
                if not arguments.manifest_dir.is_absolute()
                else arguments.manifest_dir.resolve(),
                "manifest",
            )
        )
        results = [
            (path, *verify_manifest_sources(path, repo_root))
            for path in manifest_paths
        ]
        coverage = (
            {}
            if arguments.manifest
            else verify_vendored_source_coverage(manifest_paths, repo_root)
        )
    except ManifestError as exc:
        print(f"bsd-source-check: FAIL: {exc}", file=sys.stderr)
        return 1

    for path, digest, count in results:
        print(
            f"bsd-source-check: PASS: {path.stem}: {count} files, "
            f"sha256={digest}"
        )
    for root, count in coverage.items():
        print(
            f"bsd-source-check: PASS: {root}: "
            f"{count} vendored files covered"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
