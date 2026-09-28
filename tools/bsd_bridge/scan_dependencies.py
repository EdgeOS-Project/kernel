#!/usr/bin/env python3
"""Inventory FreeBSD include dependencies by BSD Bridge capability domain."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from catalog import discover_json_files
from manifest import ManifestError, iter_module_sources, load_manifest, locate_repo_root


INCLUDE_PATTERN = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')

CAPABILITY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("dev/acpica/", "acpi"),
    ("contrib/dev/acpica/", "acpi"),
    ("cam/", "cam"),
    ("geom/", "geom"),
    ("net/", "network"),
    ("netinet/", "network"),
    ("netinet6/", "network"),
    ("dev/usb/", "usb"),
    ("dev/vt/", "display"),
    ("dev/fb/", "display"),
    ("dev/pci/", "pci"),
    ("dev/ofw/", "fdt"),
    ("dev/virtio/", "virtio"),
    ("machine/", "machine"),
    ("vm/", "vm"),
)

CAPABILITY_EXACT: dict[str, str] = {
    "geom/geom.h": "geom-core",
    "geom/geom_disk.h": "geom-disk",
    "sys/bio.h": "block",
    "sys/bus.h": "newbus",
    "sys/callout.h": "callout",
    "sys/conf.h": "character-device",
    "sys/condvar.h": "synchronization",
    "sys/fbio.h": "display",
    "sys/lock.h": "synchronization",
    "sys/malloc.h": "memory",
    "sys/mbuf.h": "mbuf",
    "sys/module.h": "module",
    "sys/mutex.h": "synchronization",
    "sys/random.h": "random",
    "sys/rman.h": "resource",
    "sys/rwlock.h": "synchronization",
    "sys/sglist.h": "memory",
    "sys/sx.h": "synchronization",
    "sys/sysctl.h": "sysctl",
    "sys/taskqueue.h": "taskqueue",
    "sys/tty.h": "tty",
    "sys/ttycom.h": "tty",
}


def classify_include(include: str) -> str:
    exact = CAPABILITY_EXACT.get(include)
    if exact is not None:
        return exact
    for prefix, capability in CAPABILITY_PREFIXES:
        if include.startswith(prefix):
            return capability
    if include.startswith("opt_") or include.endswith("_if.h"):
        return "generated"
    return "base"


def scan_source(path: Path) -> set[str]:
    includes: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ManifestError(f"cannot read source {path}: {exc}") from exc
    for line in lines:
        match = INCLUDE_PATTERN.match(line)
        if match:
            includes.add(match.group(1))
    return includes


def dependency_inventory(
    manifest_path: Path, repo_root: Path | None = None
) -> dict[str, dict[str, list[str]]]:
    manifest = load_manifest(manifest_path)
    if repo_root is None:
        repo_root = locate_repo_root(manifest_path)
    upstream_root = repo_root / manifest["upstream"]["root"]

    module_includes: dict[str, set[str]] = defaultdict(set)
    for module_id, relative in iter_module_sources(manifest):
        module_includes[module_id].update(scan_source(upstream_root / relative))

    inventory: dict[str, dict[str, list[str]]] = {}
    for module in manifest["modules"]:
        module_id = module["id"]
        includes = sorted(module_includes[module_id])
        observed = sorted({classify_include(include) for include in includes})
        declared = sorted(module["capabilities"])
        inventory[module_id] = {
            "declared_capabilities": declared,
            "observed_capabilities": observed,
            "missing_declarations": sorted(set(observed) - set(declared)),
            "includes": includes,
        }
    return inventory


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
    parser.add_argument("--json", action="store_true")
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
        inventories = {
            load_manifest(path)["id"]: dependency_inventory(path, repo_root)
            for path in manifest_paths
        }
    except ManifestError as exc:
        print(f"bsd-dependency-scan: FAIL: {exc}", file=sys.stderr)
        return 1

    if arguments.json:
        print(json.dumps(inventories, indent=2, sort_keys=True))
    else:
        for package_id, inventory in inventories.items():
            print(f"{package_id}:")
            for module_id, details in inventory.items():
                declared = ", ".join(details["declared_capabilities"])
                observed = ", ".join(details["observed_capabilities"])
                print(f"  {module_id}:")
                print(f"    declared: {declared}")
                print(f"    observed: {observed}")

    missing = {}
    for package_id, inventory in inventories.items():
        for module_id, details in inventory.items():
            if details["missing_declarations"]:
                missing[f"{package_id}/{module_id}"] = details[
                    "missing_declarations"
                ]
    if missing:
        for module_id, capabilities in missing.items():
            print(
                f"bsd-dependency-scan: undeclared capabilities for {module_id}: "
                f"{', '.join(capabilities)}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
