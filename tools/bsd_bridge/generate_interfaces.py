#!/usr/bin/env python3
"""Generate FreeBSD kobj interfaces without modifying the vendored source."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from catalog import discover_json_files
from generate_miidevs import generate_miidevs_header
from generate_usbdevs import generate_usbdevs_headers
from manifest import (
    GENERATED_DATABASES,
    ManifestError,
    load_manifest,
    locate_repo_root,
)


def generate_interfaces(
    manifest_path: Path, output: Path | None, repo_root: Path | None = None
) -> list[Path]:
    manifest = load_manifest(manifest_path)
    if repo_root is None:
        repo_root = locate_repo_root(manifest_path)
    upstream_root = repo_root / manifest["upstream"]["root"]
    generator = upstream_root / "sys/tools/makeobjops.awk"
    if not generator.is_file():
        raise ManifestError(f"FreeBSD interface generator is missing: {generator}")

    destination = output.resolve() if output is not None else None
    generated_names: list[str] = []
    with tempfile.TemporaryDirectory(prefix="edgeos-bsd-interfaces-") as temporary:
        temporary_path = Path(temporary)
        for relative in manifest["generated_interfaces"]:
            interface = upstream_root / relative
            try:
                subprocess.run(
                    ["awk", "-f", str(generator), str(interface), "-c", "-h"],
                    cwd=temporary_path,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except FileNotFoundError as exc:
                raise ManifestError("awk is required to generate FreeBSD interfaces") from exc
            except subprocess.CalledProcessError as exc:
                detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
                raise ManifestError(
                    f"interface generation failed for {relative}: {detail}"
                ) from exc

            stem = interface.stem
            for suffix in (".c", ".h"):
                generated = temporary_path / f"{stem}{suffix}"
                if not generated.is_file() or generated.stat().st_size == 0:
                    raise ManifestError(
                        f"FreeBSD generator did not produce {generated.name}"
                    )
                generated_names.append(generated.name)

        for database in manifest["generated_databases"]:
            source_relative = GENERATED_DATABASES[database][0]
            source = upstream_root / source_relative
            if not source.is_file():
                raise ManifestError(
                    f"FreeBSD generated database is missing: {source}"
                )
            if database == "bhnd-nvram-map":
                awk_script = upstream_root / GENERATED_DATABASES[database][2]
                database_outputs = []
                for name, option in (
                    ("bhnd_nvram_map.h", "-h"),
                    ("bhnd_nvram_map_data.h", "-d"),
                ):
                    try:
                        result = subprocess.run(
                            [
                                "awk",
                                "-f",
                                str(awk_script),
                                "--",
                                source_relative,
                                option,
                                "-o",
                                "-",
                            ],
                            cwd=upstream_root,
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                        detail = getattr(exc, "stderr", "") or str(exc)
                        raise ManifestError(
                            f"BHND NVRAM map generation failed: {detail.strip()}"
                        ) from exc
                    generated = temporary_path / name
                    generated.write_text(result.stdout, encoding="utf-8")
                    database_outputs.append(generated)
            elif database == "miidevs":
                database_outputs = generate_miidevs_header(
                    source, temporary_path
                )
            elif database == "usbdevs":
                database_outputs = generate_usbdevs_headers(
                    source, temporary_path
                )
            else:
                raise ManifestError(
                    f"unsupported generated database: {database}"
                )
            for generated in database_outputs:
                if not generated.is_file() or generated.stat().st_size == 0:
                    raise ManifestError(
                        f"FreeBSD generator did not produce {generated.name}"
                    )
                generated_names.append(generated.name)

        unique_names = sorted(set(generated_names))
        if len(unique_names) != len(generated_names):
            raise ManifestError("generated interface names collide")
        if destination is not None:
            destination.mkdir(parents=True, exist_ok=True)
            for name in unique_names:
                shutil.copy2(temporary_path / name, destination / name)
            return [destination / name for name in unique_names]
        return [Path(name) for name in unique_names]


def generate_catalog_interfaces(
    manifest_paths: list[Path],
    output: Path | None,
    repo_root: Path,
) -> list[Path]:
    """Generate every package interface and reject cross-package collisions."""

    collected: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(
        prefix="edgeos-bsd-interface-catalog-"
    ) as temporary:
        temporary_root = Path(temporary)
        for index, manifest_path in enumerate(manifest_paths):
            package_output = temporary_root / f"package-{index}"
            generated = generate_interfaces(
                manifest_path, package_output, repo_root
            )
            for path in generated:
                content = path.read_bytes()
                previous = collected.get(path.name)
                if previous is not None and previous != content:
                    raise ManifestError(
                        f"generated interface {path.name} differs between packages"
                    )
                collected[path.name] = content

    names = sorted(collected)
    if output is None:
        return [Path(name) for name in names]
    destination = output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        (destination / name).write_bytes(collected[name])
    return [destination / name for name in names]


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
    parser.add_argument("--output", type=Path)
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
        generated = generate_catalog_interfaces(
            manifest_paths, arguments.output, repo_root
        )
    except (ManifestError, OSError) as exc:
        print(f"bsd-interface-generation: FAIL: {exc}", file=sys.stderr)
        return 1

    mode = "generated" if arguments.output else "validated"
    print(f"bsd-interface-generation: PASS: {mode} {len(generated)} files")
    for path in generated:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
