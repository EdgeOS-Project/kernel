#!/usr/bin/env python3
"""Tests for the FreeBSD vmm source-lock and import policy."""

from __future__ import annotations

import sys
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_ROOT = REPO_ROOT / "tools/bsd_bridge"
sys.path.insert(0, str(TOOL_ROOT))

from manifest import ManifestError, load_manifest


MANIFEST_PATH = REPO_ROOT / "config/bsd_vmm/manifests/freebsd-vmm.json"


class BsdVmmSourceGateTest(unittest.TestCase):
    def test_manifest_locks_complete_architecture_directories(self) -> None:
        manifest = load_manifest(MANIFEST_PATH)
        self.assertEqual(manifest["package_type"], "subsystem")
        self.assertEqual(manifest["source_policy"]["mode"], "patched")
        self.assertTrue(manifest["source_policy"]["allow_inline_patches"])
        locked_paths = manifest["source_lock"]["paths"]
        required_directories = {
            "sys/dev/vmm",
            "sys/amd64/vmm",
            "sys/arm64/vmm",
        }
        self.assertTrue(required_directories.issubset(locked_paths))
        self.assertEqual(len(locked_paths), len(set(locked_paths)))
        self.assertGreaterEqual(manifest["source_lock"]["file_count"], 106)
        self.assertEqual(manifest["modules"], [])

    def test_subsystem_manifest_rejects_build_modules(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["modules"] = [
            {
                "id": "forbidden",
                "sources": ["sys/dev/vmm/vmm_vm.c"],
                "capabilities": ["base"],
                "build": {"mode": "builtin"},
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ManifestError, "subsystem package modules must be empty"
            ):
                load_manifest(path)


if __name__ == "__main__":
    unittest.main()
