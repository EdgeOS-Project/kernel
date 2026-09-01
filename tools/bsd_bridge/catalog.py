#!/usr/bin/env python3
"""Load and validate BSD Driver Bridge package catalogs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from manifest import (
    IDENTIFIER_PATTERN,
    ManifestError,
    SUPPORTED_ARCHITECTURES,
    load_manifest,
)


CAPABILITY_SCHEMA_VERSION = 1
CAPABILITY_STATUSES = frozenset(
    {"unsupported", "partial", "implemented", "runtime-verified"}
)
BUILDABLE_CAPABILITY_STATUSES = frozenset(
    {"implemented", "runtime-verified"}
)


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be an object")
    return value


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{field} must be a non-empty string")
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {path}: {exc}") from exc
    return _require_mapping(raw, str(path))


def load_capability_registry(path: Path) -> dict[str, Any]:
    """Load one provider capability registry."""

    registry = _load_json(path)
    if registry.get("schema_version") != CAPABILITY_SCHEMA_VERSION:
        raise ManifestError(
            f"{path}: schema_version must be {CAPABILITY_SCHEMA_VERSION}"
        )
    provider = _require_nonempty_string(
        registry.get("provider"), f"{path}: provider"
    )
    if not IDENTIFIER_PATTERN.fullmatch(provider):
        raise ManifestError(f"{path}: provider is not a valid identifier")
    capabilities = _require_mapping(
        registry.get("capabilities"), f"{path}: capabilities"
    )
    if not capabilities:
        raise ManifestError(f"{path}: capabilities must not be empty")

    for capability_id, raw_details in capabilities.items():
        if (
            not isinstance(capability_id, str)
            or not IDENTIFIER_PATTERN.fullmatch(capability_id)
        ):
            raise ManifestError(f"{path}: invalid capability id {capability_id!r}")
        details = _require_mapping(
            raw_details, f"{path}: capabilities.{capability_id}"
        )
        status = _require_nonempty_string(
            details.get("status"),
            f"{path}: capabilities.{capability_id}.status",
        )
        if status not in CAPABILITY_STATUSES:
            raise ManifestError(
                f"{path}: capability {capability_id} has unknown status {status}"
            )
        architectures = details.get("architectures")
        if not isinstance(architectures, list):
            raise ManifestError(
                f"{path}: capabilities.{capability_id}.architectures must be an array"
            )
        if any(not isinstance(item, str) or not item for item in architectures):
            raise ManifestError(
                f"{path}: capability {capability_id} has an invalid architecture"
            )
        if len(set(architectures)) != len(architectures):
            raise ManifestError(
                f"{path}: capability {capability_id} repeats an architecture"
            )
        unknown = sorted(set(architectures) - SUPPORTED_ARCHITECTURES)
        if unknown:
            raise ManifestError(
                f"{path}: capability {capability_id} has unsupported architectures: "
                f"{', '.join(unknown)}"
            )
        if status in BUILDABLE_CAPABILITY_STATUSES and set(architectures) != set(
            SUPPORTED_ARCHITECTURES
        ):
            raise ManifestError(
                f"{path}: implemented capability {capability_id} must support "
                "both x86_64 and arm64"
            )
        _require_nonempty_string(
            details.get("owner"), f"{path}: capabilities.{capability_id}.owner"
        )

    registry["provider"] = provider
    return registry


def discover_json_files(directory: Path, label: str) -> list[Path]:
    """Return the deterministic JSON inventory for one catalog directory."""

    if not directory.is_dir():
        raise ManifestError(f"{label} directory does not exist: {directory}")
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ManifestError(f"{label} directory contains no JSON files: {directory}")
    return paths


def load_catalog(manifest_dir: Path, capability_dir: Path) -> dict[str, Any]:
    """Load packages and reject unbuildable builtin modules."""

    manifest_paths = discover_json_files(manifest_dir, "manifest")
    registry_paths = discover_json_files(capability_dir, "capability")

    registries: dict[str, dict[str, Any]] = {}
    for path in registry_paths:
        registry = load_capability_registry(path)
        provider = registry["provider"]
        if provider in registries:
            raise ManifestError(f"duplicate capability registry for {provider}")
        registry["_path"] = path
        registries[provider] = registry

    manifests: list[dict[str, Any]] = []
    package_ids: set[str] = set()
    enabled_sources: dict[tuple[str, str], str] = {}

    for path in manifest_paths:
        manifest = load_manifest(path)
        package_id = manifest["id"]
        provider = manifest["provider"]
        if package_id in package_ids:
            raise ManifestError(f"duplicate driver package id: {package_id}")
        package_ids.add(package_id)
        if provider not in registries:
            raise ManifestError(
                f"package {package_id} has no capability registry for {provider}"
            )

        registry = registries[provider]
        capabilities = registry["capabilities"]
        package_architectures = set(manifest["architectures"])
        for module in manifest["modules"]:
            module_id = module["id"]
            for capability_id in module["capabilities"]:
                details = capabilities.get(capability_id)
                if details is None:
                    raise ManifestError(
                        f"module {package_id}/{module_id} declares unknown "
                        f"capability {capability_id}"
                    )
                if module["build"]["mode"] == "disabled":
                    continue
                if details["status"] not in BUILDABLE_CAPABILITY_STATUSES:
                    raise ManifestError(
                        f"enabled module {package_id}/{module_id} requires "
                        f"{capability_id}, which is {details['status']}"
                    )
                if not package_architectures.issubset(details["architectures"]):
                    raise ManifestError(
                        f"enabled module {package_id}/{module_id} requires "
                        f"{capability_id} on every package architecture"
                    )

            if module["build"]["mode"] == "disabled":
                continue
            upstream_root = manifest["upstream"]["root"]
            for source in module["sources"]:
                key = (upstream_root, source)
                previous_owner = enabled_sources.get(key)
                if previous_owner is not None:
                    raise ManifestError(
                        f"enabled source {source} belongs to both "
                        f"{previous_owner} and {package_id}/{module_id}"
                    )
                enabled_sources[key] = f"{package_id}/{module_id}"

        manifest["_path"] = path
        manifests.append(manifest)

    return {
        "manifests": manifests,
        "registries": registries,
        "manifest_paths": manifest_paths,
        "registry_paths": registry_paths,
    }
