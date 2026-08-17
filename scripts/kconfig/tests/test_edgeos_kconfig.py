#!/usr/bin/env python3
"""Regression tests for the EdgeOS Kconfig integration.

This file is original EdgeOS code licensed under MPL-2.0.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "kconfig" / "conf.py"
KCONFIG = REPO_ROOT / "Kconfig"
DEFCONFIG = REPO_ROOT / "arch" / "x86" / "configs" / "x86_64_defconfig"
ARM64_DEFCONFIG = (
    REPO_ROOT / "arch" / "arm64" / "configs" / "arm64_defconfig"
)
VENDOR = REPO_ROOT / "scripts" / "kconfig" / "vendor" / "kconfiglib"
sys.path.insert(0, str(VENDOR))

import kconfiglib  # noqa: E402
import menuconfig  # noqa: E402


def menu_children(parent: kconfiglib.MenuNode):
    node = parent.list
    while node is not None:
        yield node
        node = node.next


class EdgeOSKconfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kconf = kconfiglib.Kconfig(str(KCONFIG), warn_to_stderr=False)

    def test_top_level_and_nested_menus_exist(self) -> None:
        top_prompts = [
            node.prompt[0]
            for node in menu_children(self.kconf.top_node)
            if node.prompt
        ]
        self.assertEqual(
            top_prompts,
            [
                "General setup",
                "Boot options",
                "Processor type and features",
                "Power management and ACPI options",
                "Bus options (PCI etc.)",
                "Firmware Drivers",
                "Device Drivers",
                "File systems",
            ],
        )

        device_menu = next(
            node
            for node in menu_children(self.kconf.top_node)
            if node.prompt and node.prompt[0] == "Device Drivers"
        )
        child_prompts = [
            node.prompt[0] for node in menu_children(device_menu) if node.prompt
        ]
        self.assertIn("Block devices", child_prompts)
        self.assertIn("Networking stack", child_prompts)
        self.assertIn("USB support", child_prompts)
        self.assertIn("Graphics support", child_prompts)

    def test_parent_symbols_control_child_visibility_and_values(self) -> None:
        net = self.kconf.syms["NET"]
        e1000 = self.kconf.syms["E1000"]
        usb = self.kconf.syms["USB"]
        xhci = self.kconf.syms["USB_XHCI"]

        net.set_value(0)
        e1000.set_value(2)
        usb.set_value(0)
        xhci.set_value(2)

        self.assertEqual(e1000.visibility, 0)
        self.assertEqual(e1000.tri_value, 0)
        self.assertEqual(xhci.visibility, 0)
        self.assertEqual(xhci.tri_value, 0)

    def test_menu_entries_are_centered_as_a_block(self) -> None:
        self.assertIn("linux", menuconfig._STYLES)
        self.assertEqual(
            menuconfig._MAIN_BUTTONS,
            "<Select>  <Exit>  <Help>  <Save>  <Load>",
        )
        self.assertTrue(
            any("Legend: [*] built-in" in line
                for line in menuconfig._MAIN_HELP_LINES)
        )
        self.assertEqual(
            menuconfig._centered_menu_origin(
                ["General setup  --->", "Device Drivers  --->"],
                height=16,
                width=80,
                center_vertically=True,
            ),
            (7, 30),
        )
        self.assertEqual(
            menuconfig._centered_menu_origin(
                ["entry"] * 20,
                height=10,
                width=80,
                center_vertically=False,
            ),
            (0, 37),
        )

    def test_defconfig_round_trip_and_generated_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / ".config"
            autoconf = pathlib.Path(tmp) / "autoconf.h"
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--kconfig",
                    str(KCONFIG),
                    "--config",
                    str(config),
                    "--defconfig",
                    str(DEFCONFIG),
                    "--autoconf",
                    str(autoconf),
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            config_text = config.read_text()
            header_text = autoconf.read_text()
            self.assertIn("CONFIG_ARCH_X86_64=y", config_text)
            self.assertIn("# CONFIG_ARCH_ARM64 is not set", config_text)
            self.assertIn("CONFIG_NET=y", config_text)
            self.assertIn("CONFIG_USB_XHCI=y", config_text)
            self.assertIn("# CONFIG_DEVICE_TREE is not set", config_text)
            self.assertIn(
                'CONFIG_BSD_DRIVER_MODULE_DIRECTORY="/usr/lib/edgeos/modules"',
                config_text,
            )
            self.assertIn('#define EDGEOS_KERNEL_RELEASE "2.0.8+86_64"', header_text)
            self.assertIn("#define CONFIG_USB_XHCI 1", header_text)

    def test_arm64_defconfig_round_trip_and_generated_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / ".config.arm64"
            autoconf = pathlib.Path(tmp) / "autoconf-arm64.h"
            makefile = pathlib.Path(tmp) / "autoconf-arm64.mk"
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--kconfig",
                    str(KCONFIG),
                    "--config",
                    str(config),
                    "--defconfig",
                    str(ARM64_DEFCONFIG),
                    "--autoconf",
                    str(autoconf),
                    "--makefile",
                    str(makefile),
                    "--make-prefix",
                    "ARM64_",
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            config_text = config.read_text()
            header_text = autoconf.read_text()
            makefile_text = makefile.read_text()
            self.assertIn("CONFIG_ARCH_ARM64=y", config_text)
            self.assertIn("# CONFIG_ARCH_X86_64 is not set", config_text)
            self.assertIn("CONFIG_INITRAMFS=y", config_text)
            self.assertIn("CONFIG_VIRTIO_NET=y", config_text)
            self.assertIn("CONFIG_VIRTIO_GPU=y", config_text)
            self.assertIn("# CONFIG_PCI is not set", config_text)
            self.assertIn("CONFIG_DEVICE_TREE=y", config_text)
            self.assertIn("CONFIG_BSD_DRIVER_FDT_INVENTORY=y", config_text)
            self.assertIn(
                '#define EDGEOS_KERNEL_RELEASE "2.0.8+arm64"',
                header_text,
            )
            self.assertNotIn("#define CONFIG_PCI 1", header_text)
            self.assertIn("#define CONFIG_VIRTIO_GPU 1", header_text)
            self.assertIn(
                'ARM64_CONFIG_KERNEL_VERSION_APPEND := "+arm64"',
                makefile_text,
            )
            self.assertIn(
                "ARM64_CONFIG_BSD_DRIVER_BRIDGE := y",
                makefile_text,
            )
            self.assertIn(
                "ARM64_CONFIG_DEVICE_TREE := y",
                makefile_text,
            )
            self.assertIn(
                "ARM64_CONFIG_VIRTIO_GPU := y",
                makefile_text,
            )
            self.assertIn(
                "ARM64_CONFIG_BSD_DRIVER_FDT_INVENTORY := y",
                makefile_text,
            )
            self.assertNotIn("ARM64_CONFIG_PCI :=", makefile_text)

    def test_makefile_prefix_rejects_make_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--kconfig",
                    str(KCONFIG),
                    "--config",
                    str(pathlib.Path(tmp) / ".config"),
                    "--defconfig",
                    str(DEFCONFIG),
                    "--autoconf",
                    str(pathlib.Path(tmp) / "autoconf.h"),
                    "--makefile",
                    str(pathlib.Path(tmp) / "autoconf.mk"),
                    "--make-prefix",
                    "ARM64_$(shell false)",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "--make-prefix must be a valid Make variable name prefix",
                result.stderr,
            )


if __name__ == "__main__":
    unittest.main()
