#!/usr/bin/env python3
"""Generate the deterministic Make build plan for BSD driver packages."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

from catalog import load_catalog
from manifest import ManifestError, locate_repo_root


MAKE_SYMBOL_PATTERN = re.compile(r"[^A-Za-z0-9_]")
PACKAGE_REGISTRY_SOURCE = "bsd_package_registry.c"
ARCHITECTURE_SYMBOLS = {
    "x86_64": "X86_64",
    "arm64": "ARM64",
}
INCLUDE_GROUP_FLAGS = {
    "acpica": "-I$(BSD_BRIDGE_ACPICA_INCLUDE)",
}
INCLUDE_GROUP_ARM64_FLAGS = {
    "acpica": "-U_MSC_VER",
}
INCLUDE_GROUP_PREREQUISITES = {
    "acpica": "$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP)",
}
COMPILE_OPTION_FLAGS = {
    "constant-width-shifts": "-Wno-shift-count-overflow",
    "external-inline-definitions": "-Dinline=",
    "freebsd-platform-identity": "-U_WIN32 -U_WIN64",
}


def _make_symbol(value: str) -> str:
    return MAKE_SYMBOL_PATTERN.sub("_", value).upper()


def _require_make_safe(value: str, field: str) -> None:
    if any(character.isspace() for character in value):
        raise ManifestError(f"{field} must not contain whitespace")
    if any(character in value for character in ("$", "#", ":", "\\")):
        raise ManifestError(f"{field} contains a Make-sensitive character")


def _assignment(name: str, values: list[str]) -> list[str]:
    if not values:
        return [f"{name} :="]
    if len(values) == 1:
        return [f"{name} := {values[0]}"]
    lines = [f"{name} := \\"]
    for index, value in enumerate(values):
        suffix = " \\" if index + 1 < len(values) else ""
        lines.append(f"\t{value}{suffix}")
    return lines


def _append_assignment(name: str, values: list[str]) -> list[str]:
    if not values:
        return []
    if len(values) == 1:
        return [f"{name} += {values[0]}"]
    lines = [f"{name} += \\"]
    for index, value in enumerate(values):
        suffix = " \\" if index + 1 < len(values) else ""
        lines.append(f"\t{value}{suffix}")
    return lines


def _append_conditionally(
    lines: list[str],
    *,
    name: str,
    values: list[str],
    architecture: str,
    requirements: tuple[str, ...],
) -> None:
    if not values:
        return
    prefix = "" if architecture == "x86_64" else "ARM64_"
    lines.append("")
    for requirement in requirements:
        lines.append(f"ifeq ($({prefix}CONFIG_{requirement}),y)")
    lines.extend(_append_assignment(name, values))
    for _requirement in reversed(requirements):
        lines.append("endif")


def render_build_plan(manifest_dir: Path, capability_dir: Path) -> str:
    """Return a Make fragment derived only from validated package metadata."""

    catalog = load_catalog(manifest_dir, capability_dir)
    manifests = catalog["manifests"]
    providers = {manifest["provider"] for manifest in manifests}
    if providers != {"freebsd"}:
        raise ManifestError(
            "the current BSD personality build supports only FreeBSD packages"
        )

    upstream_roots = {manifest["upstream"]["root"] for manifest in manifests}
    if len(upstream_roots) != 1:
        raise ManifestError("FreeBSD packages must share one upstream source root")
    upstream_root = next(iter(upstream_roots))
    _require_make_safe(upstream_root, "upstream.root")

    package_ids: list[str] = []
    builtin_module_ids: list[str] = []
    loadable_module_ids: list[str] = []
    disabled_module_ids: list[str] = []
    builtin_sources: list[str] = []
    loadable_sources: list[str] = []
    builtin_sources_by_architecture: dict[str, list[str]] = {
        architecture: [] for architecture in ARCHITECTURE_SYMBOLS
    }
    conditional_builtin_sources: dict[
        str, dict[tuple[str, ...], list[str]]
    ] = {
        architecture: {} for architecture in ARCHITECTURE_SYMBOLS
    }
    loadable_sources_by_architecture: dict[str, list[str]] = {
        architecture: [] for architecture in ARCHITECTURE_SYMBOLS
    }
    loadable_rules: list[
        tuple[
            str, str, str, tuple[str, ...], tuple[str, ...],
            tuple[str, ...], frozenset[str]
        ]
    ] = []
    generated_by_name: dict[str, tuple[str, set[str]]] = {}
    generated_cppflags: dict[str, dict[str, set[str]]] = {}
    generated_include_groups: dict[str, dict[str, set[str]]] = {}
    module_assignments: list[tuple[str, list[str]]] = []
    package_assignments: list[
        tuple[
            str, list[str], list[str], list[str], list[str], frozenset[str]
        ]
    ] = []
    variable_owners: dict[str, str] = {}

    for manifest in manifests:
        architectures = frozenset(manifest["architectures"])
        definitions = [
            f"-D{definition}"
            for definition in sorted(manifest["compile"]["definitions"])
        ] + [
            f"-U{definition}"
            for definition in sorted(manifest["compile"]["undefinitions"])
        ]
        arm64_definitions = definitions + [
            f"-D{definition}"
            for definition in sorted(
                manifest["compile"]["arm64_definitions"]
            )
        ] + [
            f"-U{definition}"
            for definition in sorted(
                manifest["compile"]["arm64_undefinitions"]
            )
        ] + [
            COMPILE_OPTION_FLAGS[option]
            for option in sorted(manifest["compile"]["arm64_options"])
        ]
        include_groups = sorted(manifest["compile"]["include_groups"])

        for relative in manifest["generated_interfaces"]:
            if not relative.startswith("sys/"):
                raise ManifestError(
                    f"generated interface must be below sys/: {relative}"
                )
            filename = f"{Path(relative).stem}.c"
            if filename == PACKAGE_REGISTRY_SOURCE:
                raise ManifestError(
                    f"generated interface name {filename} is reserved"
                )
            previous = generated_by_name.get(filename)
            if previous is not None and previous[0] != relative:
                raise ManifestError(
                    f"generated interface name {filename} collides between "
                    f"{previous[0]} and {relative}"
                )
            if previous is None:
                generated_by_name[filename] = (
                    relative, set(architectures)
                )
                generated_cppflags[filename] = {
                    architecture: set()
                    for architecture in ARCHITECTURE_SYMBOLS
                }
                generated_include_groups[filename] = {
                    architecture: set()
                    for architecture in ARCHITECTURE_SYMBOLS
                }
            else:
                previous[1].update(architectures)
            for architecture in architectures:
                generated_cppflags[filename][architecture].update(
                    arm64_definitions
                    if architecture == "arm64"
                    else definitions
                )
                generated_include_groups[filename][architecture].update(
                    include_groups
                )

        if manifest["package_type"] != "driver":
            continue

        package_id = manifest["id"]
        package_symbol = _make_symbol(package_id)
        package_sources: list[str] = []
        package_ids.append(package_id)

        for module in manifest["modules"]:
            qualified_id = f"{package_id}/{module['id']}"
            variable_name = (
                f"BSD_BRIDGE_MODULE_{_make_symbol(package_id)}_"
                f"{_make_symbol(module['id'])}_SRCS"
            )
            previous_owner = variable_owners.get(variable_name)
            if previous_owner is not None:
                raise ManifestError(
                    f"Make variable collision between {previous_owner} and "
                    f"{qualified_id}"
                )
            variable_owners[variable_name] = qualified_id
            mode = module["build"]["mode"]
            requirements = tuple(sorted(module["kconfig_requires"]))
            if mode == "disabled":
                disabled_module_ids.append(qualified_id)
                module_assignments.append((variable_name, []))
                continue

            module_sources: list[str] = []
            for source in module["sources"]:
                if not source.startswith("sys/"):
                    raise ManifestError(
                        f"enabled FreeBSD source must be below sys/: {source}"
                    )
                relative = source.removeprefix("sys/")
                _require_make_safe(relative, f"{qualified_id} source")
                package_sources.append(relative)
                module_sources.append(f"$(BSD_BRIDGE_UPSTREAM_SYS)/{relative}")
                if mode == "builtin":
                    builtin_sources.append(relative)
                    for architecture in architectures:
                        if requirements:
                            conditional_builtin_sources[
                                architecture
                            ].setdefault(requirements, []).append(relative)
                        else:
                            builtin_sources_by_architecture[
                                architecture
                            ].append(relative)
                else:
                    loadable_sources.append(relative)
                    for architecture in architectures:
                        loadable_sources_by_architecture[architecture].append(
                            relative
                        )
            module_assignments.append((variable_name, module_sources))
            if mode == "builtin":
                builtin_module_ids.append(qualified_id)
            else:
                loadable_module_ids.append(qualified_id)
                output_name = f"{package_id}--{module['id']}.ko"
                loadable_rules.append((
                    qualified_id, package_symbol, output_name,
                    tuple(
                        source.removeprefix("sys/")
                        for source in module["sources"]
                    ),
                    tuple(sorted(manifest["compile"]["include_groups"])),
                    requirements,
                    architectures,
                ))
        package_assignments.append((
            package_symbol,
            definitions,
            arm64_definitions[len(definitions):],
            include_groups,
            sorted(package_sources),
            architectures,
        ))

    lines = [
        "# Generated by tools/bsd_bridge/generate_build_plan.py.",
        "# Do not edit this file by hand.",
        "",
    ]
    lines.extend(_assignment("BSD_BRIDGE_PACKAGE_IDS", sorted(package_ids)))
    lines.extend(
        _assignment("BSD_BRIDGE_BUILTIN_MODULE_IDS", sorted(builtin_module_ids))
    )
    lines.extend(
        _assignment("BSD_BRIDGE_LOADABLE_MODULE_IDS",
                    sorted(loadable_module_ids))
    )
    lines.extend(
        _assignment("BSD_BRIDGE_DISABLED_MODULE_IDS", sorted(disabled_module_ids))
    )
    lines.append(f"BSD_BRIDGE_UPSTREAM_SYS := {upstream_root}/sys")
    lines.extend(
        _assignment(
            "BSD_BRIDGE_GENERATED_SRCS",
            sorted([*generated_by_name, PACKAGE_REGISTRY_SOURCE]),
        )
    )
    for architecture, symbol in ARCHITECTURE_SYMBOLS.items():
        lines.extend(
            _assignment(
                f"BSD_BRIDGE_{symbol}_GENERATED_SRCS",
                sorted([
                    filename
                    for filename, (_, architectures) in
                    generated_by_name.items()
                    if architecture in architectures
                ] + [PACKAGE_REGISTRY_SOURCE]),
            )
        )
    lines.extend(
        _assignment(
            "BSD_BRIDGE_GENERATED_INCLUDE_MAPPINGS",
            [
                f"{Path(filename).stem}="
                "-I$(BSD_BRIDGE_UPSTREAM_SYS)/"
                f"{Path(relative.removeprefix('sys/')).parent.as_posix()}"
                for filename, (relative, _) in sorted(
                    generated_by_name.items()
                )
            ],
        )
    )
    for architecture, symbol in ARCHITECTURE_SYMBOLS.items():
        compile_mappings: list[str] = []
        for filename, (relative, architectures) in sorted(
            generated_by_name.items()
        ):
            if architecture not in architectures:
                continue
            source_directory = Path(
                relative.removeprefix("sys/")
            ).parent.as_posix()
            stem = Path(filename).stem
            flags = [
                f"-I$(BSD_BRIDGE_UPSTREAM_SYS)/{source_directory}",
                *sorted(generated_cppflags[filename][architecture]),
            ]
            for group in sorted(
                generated_include_groups[filename][architecture]
            ):
                flags.append(INCLUDE_GROUP_FLAGS[group])
                if architecture == "arm64":
                    flags.append(INCLUDE_GROUP_ARM64_FLAGS[group])
            compile_mappings.extend(
                f"{stem}={flag}" for flag in dict.fromkeys(flags)
            )
        lines.extend(
            _assignment(
                f"BSD_BRIDGE_{symbol}_GENERATED_COMPILE_MAPPINGS",
                compile_mappings,
            )
        )
    for filename, (relative, architectures) in sorted(
        generated_by_name.items()
    ):
        source_directory = Path(
            relative.removeprefix("sys/")
        ).parent.as_posix()
        include_flag = (
            f"-I$(BSD_BRIDGE_UPSTREAM_SYS)/{source_directory}"
        )
        object_name = Path(filename).with_suffix(".o").name
        if "x86_64" in architectures:
            target = f"$(OBJ)/compat/freebsd/generated/{object_name}"
            lines.append(
                f"{target}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += {include_flag}"
            )
            cppflags = sorted(generated_cppflags[filename]["x86_64"])
            if cppflags:
                lines.append(
                    f"{target}: BSD_BRIDGE_SOURCE_CPPFLAGS += "
                    + " ".join(cppflags)
                )
            include_groups = sorted(
                generated_include_groups[filename]["x86_64"]
            )
            if include_groups:
                lines.append(
                    f"{target}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
                    + " ".join(
                        INCLUDE_GROUP_FLAGS[group]
                        for group in include_groups
                    )
                )
                lines.append(
                    f"{target}: "
                    + " ".join(
                        INCLUDE_GROUP_PREREQUISITES[group]
                        for group in include_groups
                    )
                )
        if "arm64" in architectures:
            object_name = Path(filename).with_suffix(".obj").name
            target = f"$(OBJ)/arm64-bsd/generated/{object_name}"
            lines.append(
                f"{target}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += {include_flag}"
            )
            cppflags = sorted(generated_cppflags[filename]["arm64"])
            if cppflags:
                lines.append(
                    f"{target}: BSD_BRIDGE_SOURCE_CPPFLAGS += "
                    + " ".join(cppflags)
                )
            include_groups = sorted(
                generated_include_groups[filename]["arm64"]
            )
            if include_groups:
                lines.append(
                    f"{target}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
                    + " ".join(
                        [
                            INCLUDE_GROUP_FLAGS[group]
                            for group in include_groups
                        ] + [
                            INCLUDE_GROUP_ARM64_FLAGS[group]
                            for group in include_groups
                        ]
                    )
                )
                lines.append(
                    f"{target}: "
                    + " ".join(
                        INCLUDE_GROUP_PREREQUISITES[group]
                        for group in include_groups
                    )
                )
    lines.extend(
        _assignment(
            "BSD_BRIDGE_UPSTREAM_REL_SRCS", sorted(builtin_sources)
        )
    )
    for architecture, symbol in ARCHITECTURE_SYMBOLS.items():
        variable_name = f"BSD_BRIDGE_{symbol}_UPSTREAM_REL_SRCS"
        lines.extend(
            _assignment(
                variable_name,
                sorted(builtin_sources_by_architecture[architecture]),
            )
        )
        for requirements, sources in sorted(
            conditional_builtin_sources[architecture].items()
        ):
            _append_conditionally(
                lines,
                name=variable_name,
                values=sorted(sources),
                architecture=architecture,
                requirements=requirements,
            )
    lines.extend(
        _assignment(
            "BSD_BRIDGE_LOADABLE_REL_SRCS", sorted(loadable_sources)
        )
    )
    lines.extend(
        _assignment(
            "BSD_BRIDGE_LOADABLE_X86_MODULES",
            sorted(
                f"$(OUT)/bsd_bridge/modules/x86_64/{rule[2]}"
                for rule in loadable_rules
                if "x86_64" in rule[6] and not rule[5]
            ),
        )
    )
    for requirements in sorted({
        rule[5] for rule in loadable_rules
        if "x86_64" in rule[6] and rule[5]
    }):
        _append_conditionally(
            lines,
            name="BSD_BRIDGE_LOADABLE_X86_MODULES",
            values=sorted(
                f"$(OUT)/bsd_bridge/modules/x86_64/{rule[2]}"
                for rule in loadable_rules
                if "x86_64" in rule[6] and rule[5] == requirements
            ),
            architecture="x86_64",
            requirements=requirements,
        )
    lines.extend(
        _assignment(
            "BSD_BRIDGE_LOADABLE_ARM64_MODULES",
            sorted(
                f"$(OUT)/bsd_bridge/modules/arm64/{rule[2]}"
                for rule in loadable_rules
                if "arm64" in rule[6] and not rule[5]
            ),
        )
    )
    for requirements in sorted({
        rule[5] for rule in loadable_rules
        if "arm64" in rule[6] and rule[5]
    }):
        _append_conditionally(
            lines,
            name="BSD_BRIDGE_LOADABLE_ARM64_MODULES",
            values=sorted(
                f"$(OUT)/bsd_bridge/modules/arm64/{rule[2]}"
                for rule in loadable_rules
                if "arm64" in rule[6] and rule[5] == requirements
            ),
            architecture="arm64",
            requirements=requirements,
        )
    lines.append(f"BSD_BRIDGE_PACKAGE_COUNT := {len(package_ids)}")
    lines.append(f"BSD_BRIDGE_BUILTIN_MODULE_COUNT := {len(builtin_module_ids)}")
    lines.append(f"BSD_BRIDGE_BUILTIN_SOURCE_COUNT := {len(builtin_sources)}")
    lines.append(
        f"BSD_BRIDGE_LOADABLE_MODULE_COUNT := {len(loadable_module_ids)}"
    )
    lines.append(
        f"BSD_BRIDGE_LOADABLE_SOURCE_COUNT := {len(loadable_sources)}"
    )

    for name, values in sorted(module_assignments):
        lines.append("")
        lines.extend(_assignment(name, values))

    for (
        package_symbol,
        definitions,
        arm64_definitions,
        include_groups,
        sources,
        architectures,
    ) in sorted(package_assignments):
        flags_name = f"BSD_BRIDGE_PACKAGE_{package_symbol}_CPPFLAGS"
        arm64_flags_name = (
            f"BSD_BRIDGE_PACKAGE_{package_symbol}_ARM64_CPPFLAGS"
        )
        include_flags_name = (
            f"BSD_BRIDGE_PACKAGE_{package_symbol}_INCLUDE_FLAGS"
        )
        arm64_include_flags_name = (
            f"BSD_BRIDGE_PACKAGE_{package_symbol}_ARM64_INCLUDE_FLAGS"
        )
        sources_name = f"BSD_BRIDGE_PACKAGE_{package_symbol}_REL_SRCS"
        lines.append("")
        lines.extend(_assignment(flags_name, definitions))
        lines.extend(_assignment(
            arm64_flags_name, definitions + arm64_definitions
        ))
        lines.extend(_assignment(
            include_flags_name,
            [INCLUDE_GROUP_FLAGS[group] for group in include_groups],
        ))
        lines.extend(_assignment(
            arm64_include_flags_name,
            [INCLUDE_GROUP_FLAGS[group] for group in include_groups] + [
                INCLUDE_GROUP_ARM64_FLAGS[group]
                for group in include_groups
            ],
        ))
        lines.extend(_assignment(sources_name, sources))
        if sources:
            if "x86_64" in architectures:
                x86_targets = (
                    "$(addprefix $(OBJ)/compat/freebsd/upstream/,$("
                    f"{sources_name}:.c=.o))"
                )
                lines.append(
                    f"{x86_targets}: BSD_BRIDGE_SOURCE_CPPFLAGS += "
                    f"$({flags_name})"
                )
                lines.append(
                    f"{x86_targets}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
                    f"$({include_flags_name})"
                )
                for group in include_groups:
                    lines.append(
                        f"{x86_targets}: "
                        f"{INCLUDE_GROUP_PREREQUISITES[group]}"
                    )
            if "arm64" in architectures:
                arm64_targets = (
                    "$(addprefix $(OBJ)/arm64-bsd/upstream/,$("
                    f"{sources_name}:.c=.obj))"
                )
                lines.append(
                    f"{arm64_targets}: BSD_BRIDGE_SOURCE_CPPFLAGS += "
                    f"$({arm64_flags_name})"
                )
                lines.append(
                    f"{arm64_targets}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
                    f"$({arm64_include_flags_name})"
                )
                for group in include_groups:
                    lines.append(
                        f"{arm64_targets}: "
                        f"{INCLUDE_GROUP_PREREQUISITES[group]}"
                    )

    for (
        qualified_id,
        package_symbol,
        output_name,
        relatives,
        include_groups,
        _requirements,
        architectures,
    ) in sorted(loadable_rules):
        flags_name = f"BSD_BRIDGE_PACKAGE_{package_symbol}_CPPFLAGS"
        arm64_flags_name = (
            f"BSD_BRIDGE_PACKAGE_{package_symbol}_ARM64_CPPFLAGS"
        )
        include_flags_name = (
            f"BSD_BRIDGE_PACKAGE_{package_symbol}_INCLUDE_FLAGS"
        )
        arm64_include_flags_name = (
            f"BSD_BRIDGE_PACKAGE_{package_symbol}_ARM64_INCLUDE_FLAGS"
        )
        module_symbol = _make_symbol(qualified_id)
        x86_output = (
            f"$(OUT)/bsd_bridge/modules/x86_64/{output_name}"
        )
        arm64_output = (
            f"$(OUT)/bsd_bridge/modules/arm64/{output_name}"
        )
        object_stem = output_name.removesuffix(".ko")
        x86_objects_name = f"BSD_BRIDGE_MODULE_{module_symbol}_X86_OBJS"
        arm64_bitcode_name = f"BSD_BRIDGE_MODULE_{module_symbol}_ARM64_BCS"
        x86_objects = [
            "$(OUT)/bsd_bridge/modules/x86_64/objects/"
            f"{object_stem}/{relative.removesuffix('.c')}.o"
            for relative in relatives
        ]
        arm64_bitcode = [
            "$(OUT)/bsd_bridge/modules/arm64/objects/"
            f"{object_stem}/{relative.removesuffix('.c')}.bc"
            for relative in relatives
        ]
        arm64_linked_bitcode = (
            "$(OUT)/bsd_bridge/modules/arm64/objects/"
            f"{object_stem}/linked.bc"
        )
        generated_stamp = "$(OUT)/bsd_bridge/generated/.stamp"
        lines.append("")
        if "x86_64" in architectures:
            lines.extend(_assignment(x86_objects_name, x86_objects))
            for relative, x86_object in zip(relatives, x86_objects):
                source = f"$(BSD_BRIDGE_UPSTREAM_SYS)/{relative}"
                lines.extend([
                    f"{x86_object}: BSD_BRIDGE_SOURCE_CPPFLAGS += "
                    f"$({flags_name})",
                    f"{x86_object}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
                    f"$({include_flags_name})",
                    f"{x86_object}: {source} {generated_stamp} "
                    "$(AUTOCONF_H) "
                    + " ".join(
                        INCLUDE_GROUP_PREREQUISITES[group]
                        for group in include_groups
                    ),
                    "\t@mkdir -p $(dir $@)",
                    "\t$(CC) $(BSD_BRIDGE_X86_MODULE_COMPILE_FLAGS) "
                    "-c $< -o $@",
                ])
            lines.extend([
                f"{x86_output}: $({x86_objects_name})",
                "\t@mkdir -p $(dir $@)",
                "\t$(LD) -r $^ -o $@",
            ])
        if "arm64" in architectures:
            lines.extend(_assignment(arm64_bitcode_name, arm64_bitcode))
            for relative, bitcode in zip(relatives, arm64_bitcode):
                source = f"$(BSD_BRIDGE_UPSTREAM_SYS)/{relative}"
                lines.extend([
                    f"{bitcode}: BSD_BRIDGE_SOURCE_CPPFLAGS += "
                    f"$({arm64_flags_name})",
                    f"{bitcode}: BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
                    f"$({arm64_include_flags_name})",
                    f"{bitcode}: {source} {generated_stamp} "
                    "$(ARM64_AUTOCONF_H) "
                    + " ".join(
                        INCLUDE_GROUP_PREREQUISITES[group]
                        for group in include_groups
                    ),
                    "\t@mkdir -p $(dir $@)",
                    "\t$(ARM64_EFI_CC) "
                    "$(BSD_BRIDGE_ARM64_MODULE_COMPILE_FLAGS) "
                    "-emit-llvm -c $< -o $@",
                ])
            lines.extend([
                f"{arm64_linked_bitcode}: $({arm64_bitcode_name})",
                "\t@mkdir -p $(dir $@)",
                "\t$(LLVM_LINK) $^ -o $@",
                f"{arm64_output}: {arm64_linked_bitcode}",
                "\t@mkdir -p $(dir $@)",
                "\t$(ARM64_EFI_CC) "
                "$(BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS) -c $< -o $@",
            ])

    lines.append("")
    return "\n".join(lines)


def write_build_plan(output: Path, content: str) -> None:
    """Atomically replace a generated build plan."""

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary_name, output)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest-dir",
        type=Path,
        default=Path("config/bsd_drivers/manifests"),
    )
    parser.add_argument(
        "--capability-dir",
        type=Path,
        default=Path("config/bsd_drivers/capabilities"),
    )
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    arguments = parser.parse_args()

    try:
        repo_root = (
            arguments.repo_root.resolve()
            if arguments.repo_root
            else locate_repo_root(Path.cwd())
        )
        content = render_build_plan(
            (repo_root / arguments.manifest_dir).resolve()
            if not arguments.manifest_dir.is_absolute()
            else arguments.manifest_dir.resolve(),
            (repo_root / arguments.capability_dir).resolve()
            if not arguments.capability_dir.is_absolute()
            else arguments.capability_dir.resolve(),
        )
        if arguments.check is not None:
            check_path = arguments.check.resolve()
            existing = check_path.read_text(encoding="utf-8")
            if existing != content:
                raise ManifestError(f"generated build plan is stale: {check_path}")
        elif arguments.output is not None:
            write_build_plan(arguments.output, content)
        else:
            sys.stdout.write(content)
    except (ManifestError, OSError) as exc:
        print(f"bsd-build-plan: FAIL: {exc}", file=sys.stderr)
        return 1

    action = "checked" if arguments.check else "generated"
    print(f"bsd-build-plan: PASS: {action}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
