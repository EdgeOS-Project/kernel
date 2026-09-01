#!/usr/bin/env python3
"""Import the pinned FreeBSD kernel vmm source baseline into EdgeOS."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BSD_BRIDGE_TOOL_ROOT = REPO_ROOT / "tools/bsd_bridge"
sys.path.insert(0, str(BSD_BRIDGE_TOOL_ROOT))

from manifest import ManifestError, load_manifest
from verify_sources import source_tree_digest, verify_manifest_licenses


DEFAULT_MANIFEST = (
    REPO_ROOT / "config/bsd_vmm/manifests/freebsd-vmm.json"
)


def git_output(source_root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise ManifestError(f"cannot verify FreeBSD source tree: {detail}") from exc
    return result.stdout.strip()


def verify_reference(source_root: Path, manifest: dict[str, object]) -> None:
    expected_commit = manifest["upstream"]["commit"]
    actual_commit = git_output(source_root, "rev-parse", "HEAD")
    if actual_commit != expected_commit:
        raise ManifestError(
            f"FreeBSD commit mismatch: expected {expected_commit}, got {actual_commit}"
        )

    locked_paths = manifest["source_lock"]["paths"]
    changes = git_output(
        source_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
        "--",
        *locked_paths,
    )
    if changes:
        raise ManifestError(f"FreeBSD vmm reference has tracked changes:\n{changes}")

    digest, count = source_tree_digest(source_root, locked_paths)
    expected_lock = manifest["source_lock"]
    if count != expected_lock["file_count"]:
        raise ManifestError(
            f"FreeBSD vmm file count mismatch: expected "
            f"{expected_lock['file_count']}, got {count}"
        )
    if digest != expected_lock["tree_sha256"]:
        raise ManifestError(
            f"FreeBSD vmm digest mismatch: expected "
            f"{expected_lock['tree_sha256']}, got {digest}"
        )


def import_sources(
    source_root: Path,
    target_root: Path,
    manifest: dict[str, object],
) -> int:
    copied = 0
    for relative in manifest["source_lock"]["paths"]:
        source = source_root / relative
        target = target_root / relative
        sources = [source] if source.is_file() else [
            path for path in source.rglob("*") if path.is_file()
        ]
        for source_file in sources:
            suffix = Path() if source.is_file() else source_file.relative_to(source)
            target_file = target / suffix if suffix.parts else target
            if target_file.exists():
                if not target_file.is_file() or (
                    target_file.read_bytes() != source_file.read_bytes()
                ):
                    raise ManifestError(
                        "refusing to replace modified vendored source file: "
                        f"{target_file}"
                    )
                continue
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_file)
            copied += 1
    return copied


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()

    try:
        manifest = load_manifest(arguments.manifest.resolve())
        if manifest["package_type"] != "subsystem":
            raise ManifestError("FreeBSD vmm import requires a subsystem manifest")
        source_root = arguments.source_root.resolve()
        verify_reference(source_root, manifest)
        if arguments.check:
            print(
                "bsd-vmm-import: PASS: pinned reference contains "
                f"{manifest['source_lock']['file_count']} files"
            )
            return 0
        target_root = (REPO_ROOT / manifest["upstream"]["root"]).resolve()
        copied = import_sources(source_root, target_root, manifest)
        verify_manifest_licenses(arguments.manifest.resolve(), REPO_ROOT)
    except ManifestError as exc:
        print(f"bsd-vmm-import: FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"bsd-vmm-import: PASS: imported {copied} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
