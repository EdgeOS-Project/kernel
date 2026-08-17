#!/usr/bin/env python3
"""Create a validated BSD Driver Bridge package from unmodified sources."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from catalog import (
    BUILDABLE_CAPABILITY_STATUSES,
    load_capability_registry,
)
from manifest import (
    DEFINE_PATTERN,
    IDENTIFIER_PATTERN,
    ManifestError,
    load_manifest,
    locate_repo_root,
    validate_relative_path,
)
from scan_dependencies import classify_include, scan_source
from verify_sources import (
    detect_source_license,
    license_expression_is_covered as _license_expression_is_covered,
    source_tree_digest,
)


def _validate_identifier(value: str, field: str) -> str:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ManifestError(f"{field} is not a valid package identifier")
    return value


def _normalize_unique_paths(values: list[str], field: str) -> list[str]:
    normalized = [
        validate_relative_path(value, f"{field}[{index}]")
        for index, value in enumerate(values)
    ]
    if len(set(normalized)) != len(normalized):
        raise ManifestError(f"{field} contains duplicates")
    return sorted(normalized)


def _locked_files(upstream_root: Path, paths: list[str]) -> list[Path]:
    files: list[Path] = []

    for relative in paths:
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
                    "locked source tree contains a symbolic link: "
                    f"{item.relative_to(upstream_root)}"
                )
            if item.is_file():
                files.append(item)
    return sorted(
        set(files), key=lambda item: item.relative_to(upstream_root).as_posix()
    )


def _parse_license_exceptions(
    values: list[str], allowed_licenses: set[str]
) -> dict[str, dict[str, str]]:
    exceptions: dict[str, dict[str, str]] = {}

    for index, value in enumerate(values):
        fields = value.split("=", 2)
        if len(fields) != 3 or not all(fields):
            raise ManifestError(
                f"license-exception[{index}] must be PATH=LICENSE=EVIDENCE"
            )
        relative = validate_relative_path(
            fields[0], f"license-exception[{index}].path"
        )
        if fields[1] not in allowed_licenses:
            raise ManifestError(
                f"license exception for {relative} uses disallowed license "
                f"{fields[1]}"
            )
        if relative in exceptions:
            raise ManifestError(f"duplicate license exception for {relative}")
        exceptions[relative] = {
            "license": fields[1],
            "evidence": fields[2],
        }
    return exceptions


def _observed_capabilities(upstream_root: Path, sources: list[str]) -> set[str]:
    capabilities = {"base"}

    for source in sources:
        for include in scan_source(upstream_root / source):
            capabilities.add(classify_include(include))
    return capabilities


def create_package_manifest(
    *,
    repo_root: Path,
    template_path: Path,
    capability_path: Path,
    package_id: str,
    module_id: str,
    description: str,
    sources: list[str],
    lock_paths: list[str],
    capabilities: list[str],
    definitions: list[str],
    interfaces: list[str],
    mode: str,
    reason: str | None,
    license_exception_values: list[str],
) -> dict[str, Any]:
    """Return a complete manifest after validating the selected sources."""

    package_id = _validate_identifier(package_id, "id")
    module_id = _validate_identifier(module_id, "module")
    template = load_manifest(template_path)
    registry = load_capability_registry(capability_path)
    if registry["provider"] != template["provider"]:
        raise ManifestError(
            "template manifest and capability registry use different providers"
        )

    normalized_sources = _normalize_unique_paths(sources, "sources")
    if not normalized_sources:
        raise ManifestError("sources must not be empty")
    if any(not source.startswith("sys/") or not source.endswith(".c")
           for source in normalized_sources):
        raise ManifestError("every source must be a C file below sys/")
    normalized_interfaces = _normalize_unique_paths(interfaces, "interfaces")
    if any(not interface.startswith("sys/") or not interface.endswith(".m")
           for interface in normalized_interfaces):
        raise ManifestError("every interface must be an .m file below sys/")
    normalized_lock_paths = _normalize_unique_paths(
        lock_paths, "lock_paths"
    )
    if any(not path.startswith("sys/") for path in normalized_lock_paths):
        raise ManifestError("every additional lock path must be below sys/")

    for index, definition in enumerate(definitions):
        if not DEFINE_PATTERN.fullmatch(definition):
            raise ManifestError(
                f"definitions[{index}] is not a safe preprocessor definition"
            )
    if len(set(definitions)) != len(definitions):
        raise ManifestError("definitions contains duplicates")

    if mode not in {"builtin", "module", "disabled"}:
        raise ManifestError("mode must be builtin, module, or disabled")
    if mode != "disabled" and reason:
        raise ManifestError("an enabled module must not have a disabled reason")
    if mode == "disabled" and not reason:
        reason = "Runtime acceptance has not been completed."

    upstream_root = repo_root / template["upstream"]["root"]
    selected_capabilities = _observed_capabilities(
        upstream_root, normalized_sources
    )
    for capability in capabilities:
        selected_capabilities.add(
            _validate_identifier(capability, "capability")
        )

    capability_registry = registry["capabilities"]
    for capability in sorted(selected_capabilities):
        details = capability_registry.get(capability)
        if details is None:
            raise ManifestError(f"unknown capability: {capability}")
        if mode != "disabled" and (
            details["status"] not in BUILDABLE_CAPABILITY_STATUSES or
            not set(template["architectures"]).issubset(
                details["architectures"]
            )
        ):
            raise ManifestError(
                f"enabled module requires unavailable capability: {capability}"
            )

    package_lock_paths = sorted(set(
        normalized_sources + normalized_interfaces + normalized_lock_paths
    ))
    allowed_licenses = set(template["source_policy"]["allowed_licenses"])
    exceptions = {
        path: details
        for path, details in
        template["source_policy"]["license_exceptions"].items()
        if path in package_lock_paths
    }
    exceptions.update(
        _parse_license_exceptions(license_exception_values, allowed_licenses)
    )
    locked_files = _locked_files(upstream_root, package_lock_paths)
    locked_relatives = {
        path.relative_to(upstream_root).as_posix() for path in locked_files
    }
    unknown_exceptions = sorted(set(exceptions) - locked_relatives)
    if unknown_exceptions:
        raise ManifestError(
            "license exceptions are outside the source lock: "
            f"{', '.join(unknown_exceptions)}"
        )
    for path in locked_files:
        relative = path.relative_to(upstream_root).as_posix()
        detected = detect_source_license(path)
        declared = exceptions.get(relative, {}).get("license", detected)
        if declared is None or not _license_expression_is_covered(
            declared, allowed_licenses
        ):
            raise ManifestError(
                f"{relative} has unsupported or unknown license "
                f"{declared or '(none)'}"
            )

    digest, file_count = source_tree_digest(
        upstream_root, package_lock_paths
    )
    build: dict[str, str] = {"mode": mode}
    if mode == "disabled":
        build["reason"] = reason or ""

    manifest = {
        "schema_version": template["schema_version"],
        "id": package_id,
        "provider": template["provider"],
        "description": description,
        "architectures": list(template["architectures"]),
        "compile": {
            "definitions": sorted(definitions),
            "undefinitions": [],
        },
        "upstream": dict(template["upstream"]),
        "source_policy": {
            "mode": "unmodified",
            "allow_inline_patches": False,
            "allowed_licenses": sorted(allowed_licenses),
            "license_exceptions": exceptions,
        },
        "source_lock": {
            "paths": package_lock_paths,
            "file_count": file_count,
            "tree_sha256": digest,
        },
        "generated_interfaces": normalized_interfaces,
        "modules": [
            {
                "id": module_id,
                "sources": normalized_sources,
                "capabilities": sorted(selected_capabilities),
                "build": build,
            }
        ],
    }
    return manifest


def write_manifest(path: Path, manifest: dict[str, Any], force: bool) -> None:
    """Atomically write and re-read a generated package manifest."""

    if path.exists() and not force:
        raise ManifestError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        load_manifest(Path(temporary_name))
        if force:
            os.replace(temporary_name, path)
        else:
            try:
                os.link(temporary_name, path)
            except FileExistsError as exc:
                raise ManifestError(f"output already exists: {path}") from exc
            os.unlink(temporary_name)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, dest="package_id")
    parser.add_argument("--module", required=True, dest="module_id")
    parser.add_argument("--description")
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument(
        "--lock-path",
        action="append",
        default=[],
        help="lock an additional unmodified header or source directory",
    )
    parser.add_argument("--capability", action="append", default=[])
    parser.add_argument("--definition", action="append", default=[])
    parser.add_argument("--interface", action="append", default=[])
    parser.add_argument(
        "--mode", choices=("builtin", "module", "disabled"), default="disabled"
    )
    parser.add_argument("--reason")
    parser.add_argument(
        "--license-exception",
        action="append",
        default=[],
        metavar="PATH=LICENSE=EVIDENCE",
    )
    parser.add_argument(
        "--template-manifest",
        type=Path,
        default=Path("config/bsd_drivers/manifests/freebsd-virtio.json"),
    )
    parser.add_argument(
        "--capability-registry",
        type=Path,
        default=Path("config/bsd_drivers/capabilities/freebsd.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        repo_root = locate_repo_root(Path.cwd())
        template_path = (
            arguments.template_manifest
            if arguments.template_manifest.is_absolute()
            else repo_root / arguments.template_manifest
        )
        capability_path = (
            arguments.capability_registry
            if arguments.capability_registry.is_absolute()
            else repo_root / arguments.capability_registry
        )
        output = arguments.output or (
            repo_root / "config/bsd_drivers/manifests" /
            f"{arguments.package_id}.json"
        )
        if not output.is_absolute():
            output = repo_root / output
        manifest = create_package_manifest(
            repo_root=repo_root,
            template_path=template_path,
            capability_path=capability_path,
            package_id=arguments.package_id,
            module_id=arguments.module_id,
            description=arguments.description or (
                f"Unmodified FreeBSD {arguments.module_id} driver package."
            ),
            sources=arguments.source,
            lock_paths=arguments.lock_path,
            capabilities=arguments.capability,
            definitions=arguments.definition,
            interfaces=arguments.interface,
            mode=arguments.mode,
            reason=arguments.reason,
            license_exception_values=arguments.license_exception,
        )
        if arguments.dry_run:
            json.dump(manifest, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            write_manifest(output, manifest, arguments.force)
            try:
                display_path = output.relative_to(repo_root)
            except ValueError:
                display_path = output
            print(f"bsd-package-create: PASS: {display_path}")
    except (ManifestError, OSError) as exc:
        print(f"bsd-package-create: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
