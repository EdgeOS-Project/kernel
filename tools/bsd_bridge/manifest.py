#!/usr/bin/env python3
"""Manifest loading and validation for the EdgeOS BSD Driver Bridge."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


class ManifestError(ValueError):
    """Raised when a BSD driver manifest violates the bridge contract."""


MANIFEST_SCHEMA_VERSION = 2
SUPPORTED_ARCHITECTURES = frozenset({"x86_64", "arm64"})
SUPPORTED_INCLUDE_GROUPS = frozenset({
    "acpica",
    "ath",
    "ath10k",
    "ath11k",
    "ath12k",
    "bhnd-bwn",
    "brcm80211",
    "drm-amd",
    "drm-kmod",
    "drm-nouveau",
    "drm-nouveau-legacy",
    "iwlwifi",
    "irdma",
    "linuxkpi",
    "linux-typec",
    "mt76",
    "netgraph-bluetooth",
    "ofed",
    "rtw88",
    "rtw89",
})
SUPPORTED_COMPILE_OPTIONS = frozenset({
    "constant-width-shifts",
    "external-inline-definitions",
    "freebsd-platform-identity",
    "negative-value-shifts",
})
SUPPORTED_KCONFIG_REQUIREMENTS = frozenset({
    "ACPI",
    "DEVICE_TREE",
    "GRAPHICS_AMD",
    "GRAPHICS_INTEL",
    "GRAPHICS_NVIDIA",
})
MODULE_BUILD_MODES = frozenset({"builtin", "module", "disabled"})
SOURCE_POLICY_MODES = frozenset({"unmodified", "patched"})
PACKAGE_TYPES = frozenset({"driver", "headers", "subsystem"})
GENERATED_DATABASES = {
    "bhnd-nvram-map": (
        "sys/dev/bhnd/nvram/nvram_map",
        "sys/dev/bhnd/tools/nvram_map_gen.sh",
        "sys/dev/bhnd/tools/nvram_map_gen.awk",
    ),
    "miidevs": (
        "sys/dev/mii/miidevs",
    ),
    "usbdevs": (
        "sys/dev/usb/usbdevs",
    ),
}
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
DEFINE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:=[A-Za-z0-9_.+:/-]+)?$"
)
UNDEFINE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEADER_PATTERN = re.compile(r"^[A-Za-z0-9_./+-]+\.h$")


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be an object")
    return value


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{field} must be a non-empty string")
    return value


def _require_identifier(value: Any, field: str) -> str:
    text = _require_nonempty_string(value, field)
    if not IDENTIFIER_PATTERN.fullmatch(text):
        raise ManifestError(
            f"{field} must contain only lowercase letters, digits, '.', '_', or '-'"
        )
    return text


def _require_string_list(
    value: Any, field: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "an array" if allow_empty else "a non-empty array"
        raise ManifestError(f"{field} must be {qualifier}")
    result = [
        _require_nonempty_string(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(set(result)) != len(result):
        raise ManifestError(f"{field} contains duplicates")
    return result


def validate_relative_path(value: Any, field: str) -> str:
    text = _require_nonempty_string(value, field)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ManifestError(f"{field} must be a normalized relative path")
    return path.as_posix()


def iter_module_sources(manifest: dict[str, Any]) -> Iterator[tuple[str, str]]:
    for module in manifest["modules"]:
        module_id = module["id"]
        for source in module["sources"]:
            yield module_id, source


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {path}: {exc}") from exc

    manifest = _require_mapping(raw, "manifest")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ManifestError(
            f"schema_version must be {MANIFEST_SCHEMA_VERSION}"
        )
    _require_identifier(manifest.get("id"), "id")
    _require_identifier(manifest.get("provider"), "provider")
    package_type = manifest.get("package_type", "driver")
    if package_type not in PACKAGE_TYPES:
        raise ManifestError(
            "package_type must be one of: "
            f"{', '.join(sorted(PACKAGE_TYPES))}"
        )
    manifest["package_type"] = package_type

    architectures = _require_string_list(
        manifest.get("architectures"), "architectures"
    )
    unknown_architectures = sorted(set(architectures) - SUPPORTED_ARCHITECTURES)
    if unknown_architectures:
        raise ManifestError(
            "architectures contains unsupported targets: "
            f"{', '.join(unknown_architectures)}"
        )
    manifest["architectures"] = architectures

    compile_config = _require_mapping(manifest.get("compile"), "compile")
    definitions = _require_string_list(
        compile_config.get("definitions"), "compile.definitions", allow_empty=True
    )
    for index, definition in enumerate(definitions):
        if not DEFINE_PATTERN.fullmatch(definition):
            raise ManifestError(
                f"compile.definitions[{index}] is not a safe preprocessor definition"
            )
    compile_config["definitions"] = definitions
    arm64_definitions = _require_string_list(
        compile_config.get("arm64_definitions", []),
        "compile.arm64_definitions",
        allow_empty=True,
    )
    for index, definition in enumerate(arm64_definitions):
        if not DEFINE_PATTERN.fullmatch(definition):
            raise ManifestError(
                f"compile.arm64_definitions[{index}] is not a safe "
                "preprocessor definition"
            )
    compile_config["arm64_definitions"] = arm64_definitions
    undefinitions = _require_string_list(
        compile_config.get("undefinitions", []),
        "compile.undefinitions", allow_empty=True
    )
    for index, definition in enumerate(undefinitions):
        if not UNDEFINE_PATTERN.fullmatch(definition):
            raise ManifestError(
                f"compile.undefinitions[{index}] is not a safe "
                "preprocessor identifier"
            )
    compile_config["undefinitions"] = undefinitions
    arm64_undefinitions = _require_string_list(
        compile_config.get("arm64_undefinitions", []),
        "compile.arm64_undefinitions",
        allow_empty=True,
    )
    for index, definition in enumerate(arm64_undefinitions):
        if not UNDEFINE_PATTERN.fullmatch(definition):
            raise ManifestError(
                f"compile.arm64_undefinitions[{index}] is not a safe "
                "preprocessor identifier"
            )
    compile_config["arm64_undefinitions"] = arm64_undefinitions
    arm64_options = _require_string_list(
        compile_config.get("arm64_options", []),
        "compile.arm64_options",
        allow_empty=True,
    )
    unknown_arm64_options = sorted(
        set(arm64_options) - SUPPORTED_COMPILE_OPTIONS
    )
    if unknown_arm64_options:
        raise ManifestError(
            "compile.arm64_options contains unsupported options: "
            f"{', '.join(unknown_arm64_options)}"
        )
    compile_config["arm64_options"] = arm64_options
    x86_fpu_sources = _require_string_list(
        compile_config.get("x86_fpu_sources", []),
        "compile.x86_fpu_sources",
        allow_empty=True,
    )
    for index, source in enumerate(x86_fpu_sources):
        validate_relative_path(source, f"compile.x86_fpu_sources[{index}]")
        if not source.startswith("sys/") or not source.endswith(".c"):
            raise ManifestError(
                "compile.x86_fpu_sources entries must be C sources below sys/"
            )
    compile_config["x86_fpu_sources"] = x86_fpu_sources
    source_preincludes = _require_mapping(
        compile_config.get("source_preincludes", {}),
        "compile.source_preincludes",
    )
    for source, header in source_preincludes.items():
        validate_relative_path(source, "compile.source_preincludes key")
        if not source.startswith("sys/") or not source.endswith(".c"):
            raise ManifestError(
                "compile.source_preincludes keys must be C sources below sys/"
            )
        if not isinstance(header, str) or not HEADER_PATTERN.fullmatch(header):
            raise ManifestError(
                f"compile.source_preincludes[{source}] must be a safe header"
            )
    compile_config["source_preincludes"] = source_preincludes
    include_groups = _require_string_list(
        compile_config.get("include_groups", []),
        "compile.include_groups",
        allow_empty=True,
    )
    unknown_include_groups = sorted(
        set(include_groups) - SUPPORTED_INCLUDE_GROUPS
    )
    if unknown_include_groups:
        raise ManifestError(
            "compile.include_groups contains unsupported groups: "
            f"{', '.join(unknown_include_groups)}"
        )
    compile_config["include_groups"] = include_groups

    upstream = _require_mapping(manifest.get("upstream"), "upstream")
    validate_relative_path(upstream.get("root"), "upstream.root")
    if not isinstance(upstream.get("vendored"), bool):
        raise ManifestError("upstream.vendored must be a boolean")
    commit = _require_nonempty_string(upstream.get("commit"), "upstream.commit")
    if len(commit) != 40 or any(ch not in "0123456789abcdef" for ch in commit):
        raise ManifestError("upstream.commit must be a lowercase 40-character Git hash")

    source_policy = _require_mapping(manifest.get("source_policy"), "source_policy")
    source_mode = source_policy.get("mode")
    if source_mode not in SOURCE_POLICY_MODES:
        raise ManifestError(
            "source_policy.mode must be one of: "
            + ", ".join(sorted(SOURCE_POLICY_MODES))
        )
    allow_inline_patches = source_policy.get("allow_inline_patches")
    raw_patches = source_policy.get("patches", [])
    if source_mode == "unmodified":
        if allow_inline_patches is not False:
            raise ManifestError(
                "unmodified source_policy.allow_inline_patches must be false"
            )
        if raw_patches:
            raise ManifestError("unmodified source policy must not declare patches")
        source_policy["patches"] = []
    else:
        if allow_inline_patches is not True:
            raise ManifestError(
                "patched source_policy.allow_inline_patches must be true"
            )
        if not isinstance(raw_patches, list) or not raw_patches:
            raise ManifestError(
                "patched source policy must declare a non-empty patches array"
            )
        patches: list[dict[str, str]] = []
        patch_paths: set[str] = set()
        for index, raw_patch in enumerate(raw_patches):
            patch = _require_mapping(
                raw_patch, f"source_policy.patches[{index}]"
            )
            patch_path = validate_relative_path(
                patch.get("path"), f"source_policy.patches[{index}].path"
            )
            if patch_path in patch_paths:
                raise ManifestError("source_policy.patches contains duplicate paths")
            patch_paths.add(patch_path)
            upstream_sha256 = _require_nonempty_string(
                patch.get("upstream_sha256"),
                f"source_policy.patches[{index}].upstream_sha256",
            )
            if len(upstream_sha256) != 64 or any(
                ch not in "0123456789abcdef" for ch in upstream_sha256
            ):
                raise ManifestError(
                    f"source_policy.patches[{index}].upstream_sha256 must be a "
                    "lowercase SHA-256 digest"
                )
            reason = _require_nonempty_string(
                patch.get("reason"), f"source_policy.patches[{index}].reason"
            )
            patches.append(
                {
                    "path": patch_path,
                    "upstream_sha256": upstream_sha256,
                    "reason": reason,
                }
            )
        source_policy["patches"] = patches
    source_policy["allowed_licenses"] = _require_string_list(
        source_policy.get("allowed_licenses"), "source_policy.allowed_licenses"
    )
    allow_unmarked_files = source_policy.get("allow_unmarked_files", False)
    if not isinstance(allow_unmarked_files, bool):
        raise ManifestError("source_policy.allow_unmarked_files must be a boolean")
    source_policy["allow_unmarked_files"] = allow_unmarked_files
    raw_exceptions = _require_mapping(
        source_policy.get("license_exceptions", {}),
        "source_policy.license_exceptions",
    )
    exceptions: dict[str, dict[str, str]] = {}
    for relative, raw_exception in raw_exceptions.items():
        normalized = validate_relative_path(
            relative, f"source_policy.license_exceptions[{relative!r}]"
        )
        details = _require_mapping(
            raw_exception,
            f"source_policy.license_exceptions[{relative!r}]",
        )
        license_id = _require_nonempty_string(
            details.get("license"),
            f"source_policy.license_exceptions[{relative!r}].license",
        )
        if license_id not in source_policy["allowed_licenses"]:
            raise ManifestError(
                f"license exception for {relative} uses disallowed license "
                f"{license_id}"
            )
        evidence = _require_nonempty_string(
            details.get("evidence"),
            f"source_policy.license_exceptions[{relative!r}].evidence",
        )
        exceptions[normalized] = {
            "license": license_id,
            "evidence": evidence,
        }
    source_policy["license_exceptions"] = exceptions

    source_lock = _require_mapping(manifest.get("source_lock"), "source_lock")
    lock_paths = source_lock.get("paths")
    if not isinstance(lock_paths, list) or not lock_paths:
        raise ManifestError("source_lock.paths must be a non-empty array")
    normalized_lock_paths = [
        validate_relative_path(item, f"source_lock.paths[{index}]")
        for index, item in enumerate(lock_paths)
    ]
    if len(set(normalized_lock_paths)) != len(normalized_lock_paths):
        raise ManifestError("source_lock.paths contains duplicates")
    source_lock["paths"] = normalized_lock_paths
    for patch in source_policy["patches"]:
        patch_path = patch["path"]
        if not any(
            patch_path == locked or patch_path.startswith(locked + "/")
            for locked in normalized_lock_paths
        ):
            raise ManifestError(
                f"patched source is not covered by source_lock.paths: {patch_path}"
            )

    file_count = source_lock.get("file_count")
    if not isinstance(file_count, int) or file_count <= 0:
        raise ManifestError("source_lock.file_count must be a positive integer")
    digest = _require_nonempty_string(
        source_lock.get("tree_sha256"), "source_lock.tree_sha256"
    )
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ManifestError("source_lock.tree_sha256 must be a lowercase SHA-256 digest")

    interfaces = manifest.get("generated_interfaces")
    if not isinstance(interfaces, list):
        raise ManifestError("generated_interfaces must be an array")
    manifest["generated_interfaces"] = [
        validate_relative_path(item, f"generated_interfaces[{index}]")
        for index, item in enumerate(interfaces)
    ]
    if len(set(manifest["generated_interfaces"])) != len(
        manifest["generated_interfaces"]
    ):
        raise ManifestError("generated_interfaces contains duplicates")

    generated_databases = _require_string_list(
        manifest.get("generated_databases", []),
        "generated_databases",
        allow_empty=True,
    )
    unknown_databases = sorted(
        set(generated_databases) - set(GENERATED_DATABASES)
    )
    if unknown_databases:
        raise ManifestError(
            "generated_databases contains unsupported generators: "
            f"{', '.join(unknown_databases)}"
        )
    for database in generated_databases:
        required_paths = GENERATED_DATABASES[database]
        missing_paths = [
            path for path in required_paths
            if path not in normalized_lock_paths
        ]
        if missing_paths:
            raise ManifestError(
                f"generated database {database} requires locked paths: "
                f"{', '.join(missing_paths)}"
            )
    manifest["generated_databases"] = generated_databases

    modules = manifest.get("modules")
    if not isinstance(modules, list):
        raise ManifestError("modules must be an array")
    if package_type == "driver" and not modules:
        raise ManifestError("driver package modules must be a non-empty array")
    if package_type in {"headers", "subsystem"} and modules:
        raise ManifestError(f"{package_type} package modules must be empty")
    module_ids: set[str] = set()
    source_owners: dict[str, str] = {}
    for index, raw_module in enumerate(modules):
        module = _require_mapping(raw_module, f"modules[{index}]")
        module_id = _require_identifier(
            module.get("id"), f"modules[{index}].id"
        )
        if module_id in module_ids:
            raise ManifestError(f"duplicate module id: {module_id}")
        module_ids.add(module_id)

        sources = module.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ManifestError(f"modules[{index}].sources must be a non-empty array")
        normalized_sources = [
            validate_relative_path(source, f"modules[{index}].sources[{source_index}]")
            for source_index, source in enumerate(sources)
        ]
        for source in normalized_sources:
            previous_owner = source_owners.get(source)
            if previous_owner is not None:
                raise ManifestError(
                    f"source {source} belongs to both {previous_owner} and {module_id}"
                )
            source_owners[source] = module_id
        module["sources"] = normalized_sources

        capabilities = module.get("capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            raise ManifestError(
                f"modules[{index}].capabilities must be a non-empty array"
            )
        normalized_capabilities = [
            _require_identifier(
                capability, f"modules[{index}].capabilities[{capability_index}]"
            )
            for capability_index, capability in enumerate(capabilities)
        ]
        if len(set(normalized_capabilities)) != len(normalized_capabilities):
            raise ManifestError(f"module {module_id} contains duplicate capabilities")
        module["capabilities"] = normalized_capabilities

        kconfig_requires = _require_string_list(
            module.get("kconfig_requires", []),
            f"modules[{index}].kconfig_requires",
            allow_empty=True,
        )
        unknown_requirements = sorted(
            set(kconfig_requires) - SUPPORTED_KCONFIG_REQUIREMENTS
        )
        if unknown_requirements:
            raise ManifestError(
                f"module {module_id} kconfig_requires contains unsupported "
                f"symbols: {', '.join(unknown_requirements)}"
            )
        module["kconfig_requires"] = kconfig_requires

        build = _require_mapping(
            module.get("build"), f"modules[{index}].build"
        )
        mode = _require_nonempty_string(
            build.get("mode"), f"modules[{index}].build.mode"
        )
        if mode not in MODULE_BUILD_MODES:
            raise ManifestError(
                f"module {module_id} build mode must be one of: "
                f"{', '.join(sorted(MODULE_BUILD_MODES))}"
            )
        if mode == "disabled":
            _require_nonempty_string(
                build.get("reason"), f"modules[{index}].build.reason"
            )
        elif "reason" in build:
            raise ManifestError(
                f"module {module_id} must not have a disabled reason when enabled"
            )
    return manifest


def locate_repo_root(start: Path) -> Path:
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists() and (candidate / "Makefile").exists():
            return candidate
    raise ManifestError(f"cannot locate the EdgeOS repository from {start}")
