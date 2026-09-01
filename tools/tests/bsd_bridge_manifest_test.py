#!/usr/bin/env python3
"""Tests for the BSD Driver Bridge manifest and source-lock tooling."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_ROOT = REPO_ROOT / "tools/bsd_bridge"
sys.path.insert(0, str(TOOL_ROOT))

from catalog import load_capability_registry, load_catalog
from check_module_symbols import load_exports
from create_package import (
    _license_expression_is_covered,
    create_package_manifest,
    write_manifest,
)
from generate_build_plan import render_build_plan
from generate_interfaces import generate_interfaces
from generate_miidevs import generate_miidevs_header, parse_miidevs
from generate_package_registry import render_package_registry
from generate_usbdevs import generate_usbdevs_headers, parse_usbdevs
from manifest import ManifestError, load_manifest
from scan_dependencies import dependency_inventory
from verify_sources import (
    detect_source_license,
    source_tree_digest,
    verify_manifest_licenses,
    verify_manifest_sources,
    verify_vendored_source_coverage,
)


MANIFEST_DIR = REPO_ROOT / "config/bsd_drivers/manifests"
VMM_MANIFEST_DIR = REPO_ROOT / "config/bsd_vmm/manifests"
CAPABILITY_DIR = REPO_ROOT / "config/bsd_drivers/capabilities"
MANIFEST_PATH = MANIFEST_DIR / "freebsd-virtio.json"
BASE_HEADERS_MANIFEST_PATH = MANIFEST_DIR / "freebsd-base-headers.json"
LIBFDT_MANIFEST_PATH = MANIFEST_DIR / "freebsd-libfdt.json"
IFLIB_MANIFEST_PATH = MANIFEST_DIR / "freebsd-iflib.json"
E1000_MANIFEST_PATH = MANIFEST_DIR / "freebsd-e1000.json"
IGC_MANIFEST_PATH = MANIFEST_DIR / "freebsd-igc.json"
IAVF_MANIFEST_PATH = MANIFEST_DIR / "freebsd-iavf.json"
ICE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-ice.json"
AQ_MANIFEST_PATH = MANIFEST_DIR / "freebsd-aq.json"
BCE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-bce.json"
BXE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-bxe.json"
ENA_MANIFEST_PATH = MANIFEST_DIR / "freebsd-ena.json"
GVE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-gve.json"
LIQUIDIO_MANIFEST_PATH = MANIFEST_DIR / "freebsd-liquidio.json"
LIBKERN_CRC_MANIFEST_PATH = MANIFEST_DIR / "freebsd-libkern-crc.json"
OCE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-oce.json"
QLXGB_MANIFEST_PATH = MANIFEST_DIR / "freebsd-qlxgb.json"
QLXGBE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-qlxgbe.json"
SFXGE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-sfxge.json"
IWM_MANIFEST_PATH = MANIFEST_DIR / "freebsd-iwm.json"
IWX_MANIFEST_PATH = MANIFEST_DIR / "freebsd-iwx.json"
IPW_MANIFEST_PATH = MANIFEST_DIR / "freebsd-ipw.json"
IWI_MANIFEST_PATH = MANIFEST_DIR / "freebsd-iwi.json"
IWN_MANIFEST_PATH = MANIFEST_DIR / "freebsd-iwn.json"
BWI_MANIFEST_PATH = MANIFEST_DIR / "freebsd-bwi.json"
WPI_MANIFEST_PATH = MANIFEST_DIR / "freebsd-wpi.json"
MALO_MANIFEST_PATH = MANIFEST_DIR / "freebsd-malo.json"
NET80211_MANIFEST_PATH = MANIFEST_DIR / "freebsd-net80211.json"
OTUS_MANIFEST_PATH = MANIFEST_DIR / "freebsd-otus.json"
VMXNET3_MANIFEST_PATH = MANIFEST_DIR / "freebsd-vmxnet3.json"
USB_CORE_MANIFEST_PATH = MANIFEST_DIR / "freebsd-usb-core.json"
USB_AUDIO_MANIFEST_PATH = MANIFEST_DIR / "freebsd-usb-audio.json"
USB_WLAN_MANIFEST_PATH = MANIFEST_DIR / "freebsd-usb-wlan.json"
MPI3MR_MANIFEST_PATH = MANIFEST_DIR / "freebsd-mpi3mr.json"
LINUXKPI_HEADERS_MANIFEST_PATH = MANIFEST_DIR / "freebsd-linuxkpi-headers.json"
DRM_KMOD_HEADERS_MANIFEST_PATH = MANIFEST_DIR / "freebsd-drm-kmod-headers.json"
DRM_I915_MANIFEST_PATH = MANIFEST_DIR / "freebsd-drm-i915.json"
DRM_AMDGPU_MANIFEST_PATH = MANIFEST_DIR / "freebsd-drm-amdgpu.json"
LINUXKPI_RUNTIME_SLICE_MANIFEST_PATH = (
    MANIFEST_DIR / "freebsd-linuxkpi-runtime-slice.json"
)
CAPABILITY_PATH = CAPABILITY_DIR / "freebsd.json"


def make_assignment_values(content: str, name: str) -> list[str]:
    lines = content.splitlines()
    prefix = f"{name} :="
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        remainder = line[len(prefix):].strip()
        if remainder != "\\":
            return [] if not remainder else [remainder]
        values = []
        for continuation in lines[index + 1:]:
            if not continuation.startswith("\t"):
                break
            values.append(continuation.strip().removesuffix("\\").strip())
        return values
    raise AssertionError(f"missing Make assignment: {name}")


class BsdBridgeManifestTest(unittest.TestCase):
    def test_bridge_linker_set_and_dependency_contract(self) -> None:
        linker_set = (
            REPO_ROOT / "include/compat/freebsd/sys/linker_set.h"
        ).read_text()
        linker_script = (REPO_ROOT / "config/linker.ld").read_text()
        makefile = (REPO_ROOT / "Makefile").read_text()

        self.assertIn('section("set_" #set "$m")', linker_set)
        self.assertIn('"$a,\\"aG\\",@progbits,__start_set_"', linker_set)
        self.assertIn('"$z,\\"aG\\",@progbits,__stop_set_"', linker_set)
        self.assertIn("SORT_BY_NAME(set_*)", linker_script)
        self.assertIn("DEPS = $(OBJS:.o=.d)", makefile)
        self.assertNotIn("DEPS := $(OBJS:.o=.d)", makefile)
        self.assertIn("$(DEPS): ;", makefile)
        self.assertIn("-include $(wildcard $(DEPS))", makefile)

    def test_repository_manifest_is_valid(self) -> None:
        manifest = load_manifest(MANIFEST_PATH)
        self.assertEqual(manifest["id"], "freebsd-virtio")
        self.assertEqual(manifest["provider"], "freebsd")
        self.assertEqual(set(manifest["architectures"]), {"x86_64", "arm64"})
        self.assertEqual(len(manifest["modules"]), 16)
        self.assertTrue(manifest["upstream"]["vendored"])
        self.assertEqual(
            manifest["upstream"]["root"],
            "src/compat/freebsd/upstream",
        )

    def test_repository_catalog_selects_only_buildable_modules(self) -> None:
        catalog = load_catalog(MANIFEST_DIR, CAPABILITY_DIR)
        manifests = {
            manifest["id"]: manifest for manifest in catalog["manifests"]
        }
        self.assertEqual(
            set(manifests),
            {
                "freebsd-aac",
                "freebsd-acpi-buttons",
                "freebsd-acpi-cpu",
                "freebsd-acpi-ec",
                "freebsd-acpi-laptops",
                "freebsd-acpi-modern-laptops",
                "freebsd-acpi-oem",
                "freebsd-acpi-pci",
                "freebsd-acpi-platform",
                "freebsd-acpi-power",
                "freebsd-acpi-thermal",
                "freebsd-acpi-video",
                "freebsd-acpi-wmi",
                "freebsd-acpica-headers",
                "freebsd-acpica-runtime",
                "freebsd-adlink",
                "freebsd-ae",
                "freebsd-agp",
                "freebsd-aacraid",
                "freebsd-ahci",
                "freebsd-alpm",
                "freebsd-amd-ecc-inject",
                "freebsd-amd-sensors",
                "freebsd-amdgpio",
                "freebsd-amdpm",
                "freebsd-amdsbwd",
                "freebsd-amdsmb",
                "freebsd-amdsmu",
                "freebsd-arm-doorbell",
                "freebsd-arm-scmi",
                "freebsd-apple-bce",
                "freebsd-aq",
                "freebsd-arcmsr",
                "freebsd-asmc",
                "freebsd-ata",
                "freebsd-atkbdc",
                "freebsd-atopcase",
                "freebsd-axgbe",
                "freebsd-backlight",
                "freebsd-bce",
                "freebsd-bfe",
                "freebsd-broadcom-genet",
                "freebsd-broadcom-iproc-mdio",
                "freebsd-bwi",
                "freebsd-bxe",
                "freebsd-cadence",
                "freebsd-cas",
                "freebsd-cavium-thunderx",
                "freebsd-cfi",
                "freebsd-chromebook-platform",
                "freebsd-ciss",
                "freebsd-clock-core",
                "freebsd-common-ethernet",
                "freebsd-cpuctl",
                "freebsd-cyapa",
                "freebsd-dialog-da9063",
                "freebsd-cpufreq-dt",
                "freebsd-cpufreq",
                "freebsd-cpufreq-x86-backends",
                "freebsd-coretemp",
                "freebsd-dpaa2",
                "freebsd-dpms",
                "freebsd-drm-amdgpu",
                "freebsd-drm-core",
                "freebsd-drm-dmabuf",
                "freebsd-drm-i915",
                "freebsd-drm-kmod-headers",
                "freebsd-drm-ttm",
                "netbsd-drm-nouveau",
                "freebsd-dwc-ethernet",
                "freebsd-dwc-hdmi",
                "freebsd-dwwdt",
                "freebsd-e1000",
                "freebsd-efi-runtime",
                "freebsd-ena",
                "freebsd-enetc",
                "freebsd-enic",
                "freebsd-eqos",
                "freebsd-et",
                "freebsd-eventtimer-core",
                "freebsd-failpoint",
                "freebsd-fdc",
                "freebsd-base-headers",
                "freebsd-fdt-common",
                "freebsd-fdt-platform",
                "freebsd-fdt-slicer",
                "freebsd-ffec",
                "freebsd-flash",
                "freebsd-framebuffer-device",
                "freebsd-ftgpio",
                "freebsd-ftwd",
                "freebsd-freescale-imx8",
                "freebsd-gem",
                "freebsd-glxiic",
                "freebsd-goldfish-rtc",
                "freebsd-gpio-backlight",
                "freebsd-gpio-core",
                "freebsd-gve",
                "freebsd-hid-core",
                "freebsd-hid-devices",
                "freebsd-hwt-intel-pt",
                "freebsd-hwreset-interface",
                "freebsd-i2c-hid",
                "freebsd-iic-sensors",
                "freebsd-iicbus-core",
                "freebsd-iavf",
                "freebsd-ice",
                "freebsd-ichwd",
                "freebsd-iflib",
                "freebsd-igc",
                "freebsd-imcsmb",
                "freebsd-intelspi",
                "freebsd-intpm",
                "freebsd-ioat",
                "freebsd-iommu-x86",
                "freebsd-intrng-core",
                "freebsd-ipmi",
                "freebsd-ips",
                "freebsd-hyperv-arm64",
                "freebsd-hyperv-common",
                "freebsd-hyperv-x86",
                "freebsd-hwpstate-amd",
                "freebsd-hptiop",
                "freebsd-ipw",
                "freebsd-isa-core",
                "freebsd-ismt",
                "freebsd-isp",
                "freebsd-ispfw",
                "freebsd-itwd",
                "freebsd-iwi",
                "freebsd-iwm",
                "freebsd-iwn",
                "freebsd-iwx",
                "freebsd-ixgbe",
                "freebsd-ixl",
                "freebsd-jedec-dimm",
                "freebsd-kbdmux",
                "freebsd-kvm-clock",
                "freebsd-libfdt",
                "freebsd-libkern-crc",
                "freebsd-libkern-crc16",
                "freebsd-libkern-scanf",
                "freebsd-libkern-sort",
                "freebsd-linuxkpi-headers",
                "freebsd-linuxkpi-runtime-slice",
                "freebsd-libnv",
                "freebsd-liquidio",
                "freebsd-mana",
                "freebsd-malo",
                "freebsd-mfi",
                "freebsd-mgb",
                "freebsd-mii-fdt",
                "freebsd-mmio-sram",
                "freebsd-mlx",
                "freebsd-mmc-core",
                "freebsd-mpi3mr",
                "freebsd-mpr",
                "freebsd-mpt",
                "freebsd-mps",
                "freebsd-mrsas",
                "freebsd-mvs",
                "freebsd-mwl",
                "freebsd-mxge",
                "freebsd-my",
                "freebsd-nctgpio",
                "freebsd-ncthwm",
                "freebsd-net80211",
                "freebsd-ntb",
                "freebsd-nvd",
                "freebsd-nvdimm",
                "freebsd-nvme",
                "freebsd-nvmem",
                "freebsd-nvram",
                "freebsd-oce",
                "freebsd-ofw-pci",
                "freebsd-onewire",
                "freebsd-otus",
                "freebsd-pcf",
                "freebsd-pchtherm",
                "freebsd-pci-audio",
                "freebsd-pci-audio-extra",
                "freebsd-pci-host-generic",
                "freebsd-pcib-core",
                "freebsd-phy-core",
                "freebsd-phy-usb",
                "freebsd-power-core",
                "freebsd-psci",
                "freebsd-pwm",
                "freebsd-qcom-clk",
                "freebsd-qcom-dwc3",
                "freebsd-qcom-ess-edma",
                "freebsd-qcom-gcc",
                "freebsd-qcom-mdio",
                "freebsd-qcom-qup",
                "freebsd-qcom-rnd",
                "freebsd-qcom-tcsr",
                "freebsd-qcom-tlmm",
                "freebsd-qlxgb",
                "freebsd-qlxgbe",
                "freebsd-qlxge",
                "freebsd-ral",
                "freebsd-raspberrypi-platform",
                "freebsd-regulator",
                "freebsd-rge",
                "freebsd-rtsx",
                "freebsd-rtwn",
                "freebsd-sdhci-core",
                "freebsd-sdio",
                "freebsd-sff",
                "freebsd-sfxge",
                "freebsd-siis",
                "freebsd-simple-framebuffer",
                "freebsd-smbios",
                "freebsd-smbus-chipsets",
                "freebsd-smartpqi",
                "freebsd-spibus-core",
                "freebsd-stge",
                "freebsd-superio",
                "freebsd-sym",
                "freebsd-syscon-interface",
                "freebsd-thunderbolt",
                "freebsd-tpm",
                "freebsd-tpm-acpi",
                "freebsd-tws",
                "freebsd-ufshci",
                "freebsd-usb-core",
                "freebsd-usb-audio",
                "freebsd-usb-cdceem",
                "freebsd-usb-cp2112",
                "freebsd-usb-displaylink",
                "freebsd-usb-dwc2",
                "freebsd-usb-dwc3",
                "freebsd-usb-gadget-audio",
                "freebsd-usb-gadget-modem",
                "freebsd-usb-host-pci",
                "freebsd-usb-hub-acpi",
                "freebsd-usb-hid",
                "freebsd-usb-input",
                "freebsd-usb-mbim",
                "freebsd-usb-musb",
                "freebsd-usb-musb-allwinner",
                "freebsd-usb-network",
                "freebsd-usb-network-extra",
                "freebsd-usb-option-wwan",
                "freebsd-usb-serial",
                "freebsd-usb-sierra-wwan",
                "freebsd-usb-storage",
                "freebsd-usb-storage-function",
                "freebsd-usb-template",
                "freebsd-usb-video",
                "freebsd-usb-wlan",
                "freebsd-usb-xhci-generic",
                "freebsd-vgapci",
                "freebsd-videomode",
                "freebsd-viapm",
                "freebsd-viawd",
                "freebsd-virtio",
                "freebsd-vkbd",
                "freebsd-vmd",
                "freebsd-vmgenc",
                "freebsd-vmxnet3",
                "freebsd-vte",
                "freebsd-watchdog-core",
                "freebsd-wbwd",
                "freebsd-wdatwd",
                "freebsd-wpi",
                "freebsd-x86bios",
                "freebsd-xdma",
                "freebsd-xilinx-platform",
                "freebsd-zlib-kernel",
                "freebsd-allwinner-arm64",
                "freebsd-apple-soc",
                "freebsd-ath",
                "freebsd-ath10k",
                "freebsd-ath11k",
                "freebsd-ath12k",
                "freebsd-bhnd-bwn",
                "freebsd-bluetooth-netgraph",
                "freebsd-brcmfmac",
                "freebsd-brcmutil",
                "freebsd-fdt-audio",
                "freebsd-iommu-arm64",
                "freebsd-iommu-core",
                "freebsd-irdma",
                "freebsd-iwlwifi",
                "freebsd-linux-typec",
                "freebsd-linuxkpi-wlan",
                "freebsd-mt76-core",
                "freebsd-mt7615",
                "freebsd-mt7915",
                "freebsd-mt7921",
                "freebsd-mt7925",
                "freebsd-mt7996",
                "freebsd-nvidia-tegra210",
                "freebsd-nxp-qoriq",
                "freebsd-pci-dw",
                "freebsd-rdma-core",
                "freebsd-rockchip-soc",
                "freebsd-rtw88",
                "freebsd-rtw89",
                "freebsd-syscon-generic",
                "freebsd-uart-core",
            },
        )
        self.assertEqual(
            manifests["freebsd-base-headers"]["package_type"],
            "headers",
        )
        self.assertEqual(manifests["freebsd-base-headers"]["modules"], [])
        self.assertNotEqual(
            manifests["freebsd-linuxkpi-headers"]["upstream"]["commit"],
            manifests["freebsd-drm-kmod-headers"]["upstream"]["commit"],
        )
        modules = manifests["freebsd-virtio"]["modules"]
        builtin = {
            module["id"]
            for module in modules
            if module["build"]["mode"] == "builtin"
        }
        disabled = {
            module["id"]
            for module in modules
            if module["build"]["mode"] == "disabled"
        }
        loadable = {
            module["id"]
            for module in modules
            if module["build"]["mode"] == "module"
        }
        self.assertEqual(len(builtin), 13)
        self.assertEqual(loadable, {"virtio-random"})
        self.assertEqual(len(disabled), 2)
        self.assertIn("virtio-core", builtin)
        self.assertIn("virtio-mmio-acpi", builtin)
        self.assertIn("virtio-mmio-fdt", builtin)
        self.assertIn("virtio-block", builtin)
        self.assertIn("virtio-network", builtin)
        self.assertIn("virtio-scsi", builtin)
        atkbdc_modules = manifests["freebsd-atkbdc"]["modules"]
        self.assertEqual(manifests["freebsd-atkbdc"]["architectures"], ["x86_64"])
        self.assertEqual(len(atkbdc_modules), 1)
        self.assertEqual(atkbdc_modules[0]["id"], "atkbdc-input")
        self.assertEqual(atkbdc_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(atkbdc_modules[0]["sources"]), 6)
        isa_modules = manifests["freebsd-isa-core"]["modules"]
        self.assertEqual(manifests["freebsd-isa-core"]["architectures"], ["x86_64"])
        self.assertEqual(len(isa_modules), 1)
        self.assertEqual(isa_modules[0]["id"], "isa-core")
        self.assertEqual(isa_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(isa_modules[0]["sources"]), 4)
        libfdt_modules = manifests["freebsd-libfdt"]["modules"]
        self.assertEqual(len(libfdt_modules), 1)
        self.assertEqual(libfdt_modules[0]["id"], "libfdt-readonly")
        self.assertEqual(libfdt_modules[0]["build"]["mode"], "builtin")
        iflib_modules = manifests["freebsd-iflib"]["modules"]
        self.assertEqual(len(iflib_modules), 1)
        self.assertEqual(iflib_modules[0]["id"], "iflib-core")
        self.assertEqual(iflib_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(iflib_modules[0]["sources"]), 2)
        e1000_modules = manifests["freebsd-e1000"]["modules"]
        self.assertEqual(len(e1000_modules), 1)
        self.assertEqual(e1000_modules[0]["id"], "e1000-family")
        self.assertEqual(e1000_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(e1000_modules[0]["sources"]), 21)
        common_ethernet_modules = manifests["freebsd-common-ethernet"]["modules"]
        self.assertEqual(
            {module["id"] for module in common_ethernet_modules},
            {"age", "alc", "ale", "fxp", "jme", "nfe"},
        )
        self.assertTrue(
            all(
                module["build"]["mode"] == "builtin"
                for module in common_ethernet_modules
            )
        )
        igc_modules = manifests["freebsd-igc"]["modules"]
        self.assertEqual(len(igc_modules), 1)
        self.assertEqual(igc_modules[0]["id"], "igc-family")
        self.assertEqual(igc_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(igc_modules[0]["sources"]), 8)
        iavf_modules = manifests["freebsd-iavf"]["modules"]
        self.assertEqual(len(iavf_modules), 1)
        self.assertEqual(iavf_modules[0]["id"], "iavf")
        self.assertEqual(iavf_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(iavf_modules[0]["sources"]), 8)
        ice_modules = manifests["freebsd-ice"]["modules"]
        self.assertEqual(len(ice_modules), 1)
        self.assertEqual(ice_modules[0]["id"], "ice")
        self.assertEqual(ice_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(ice_modules[0]["sources"]), 20)
        self.assertEqual(
            manifests["freebsd-ice"]["generated_interfaces"],
            [
                "sys/dev/ice/irdma_di_if.m",
                "sys/dev/ice/irdma_if.m",
            ],
        )
        aq_modules = manifests["freebsd-aq"]["modules"]
        self.assertEqual(len(aq_modules), 1)
        self.assertEqual(aq_modules[0]["id"], "aq")
        self.assertEqual(aq_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(aq_modules[0]["sources"]), 10)
        self.assertEqual(
            manifests["freebsd-aq"]["compile"]["arm64_definitions"],
            ["STRIP_FBSDID"],
        )
        bce_modules = manifests["freebsd-bce"]["modules"]
        self.assertEqual(len(bce_modules), 1)
        self.assertEqual(bce_modules[0]["id"], "bce")
        self.assertEqual(bce_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            bce_modules[0]["sources"],
            ["sys/dev/bce/if_bce.c"],
        )
        bxe_modules = manifests["freebsd-bxe"]["modules"]
        self.assertEqual(len(bxe_modules), 1)
        self.assertEqual(bxe_modules[0]["id"], "bxe")
        self.assertEqual(bxe_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(bxe_modules[0]["sources"]), 8)
        ena_modules = manifests["freebsd-ena"]["modules"]
        self.assertEqual(len(ena_modules), 1)
        self.assertEqual(ena_modules[0]["id"], "ena")
        self.assertEqual(ena_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(ena_modules[0]["sources"]), 7)
        self.assertEqual(
            manifests["freebsd-ena"]["compile"]["arm64_definitions"],
            ["STRIP_FBSDID"],
        )
        gve_modules = manifests["freebsd-gve"]["modules"]
        self.assertEqual(len(gve_modules), 1)
        self.assertEqual(gve_modules[0]["id"], "gve")
        self.assertEqual(gve_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(gve_modules[0]["sources"]), 9)
        liquidio_modules = manifests["freebsd-liquidio"]["modules"]
        self.assertEqual(len(liquidio_modules), 1)
        self.assertEqual(liquidio_modules[0]["id"], "liquidio")
        self.assertEqual(
            liquidio_modules[0]["build"]["mode"], "builtin"
        )
        self.assertEqual(len(liquidio_modules[0]["sources"]), 14)
        crc_modules = manifests["freebsd-libkern-crc"]["modules"]
        self.assertEqual(len(crc_modules), 1)
        self.assertEqual(crc_modules[0]["id"], "libkern-crc")
        self.assertEqual(crc_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            crc_modules[0]["sources"],
            ["sys/libkern/gsb_crc32.c"],
        )
        oce_modules = manifests["freebsd-oce"]["modules"]
        self.assertEqual(len(oce_modules), 1)
        self.assertEqual(oce_modules[0]["id"], "oce")
        self.assertEqual(oce_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(oce_modules[0]["sources"]), 6)
        qlxgb_modules = manifests["freebsd-qlxgb"]["modules"]
        self.assertEqual(len(qlxgb_modules), 1)
        self.assertEqual(qlxgb_modules[0]["id"], "qlxgb")
        self.assertEqual(qlxgb_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(qlxgb_modules[0]["sources"]), 6)
        qlxge_modules = manifests["freebsd-qlxge"]["modules"]
        self.assertEqual(len(qlxge_modules), 1)
        self.assertEqual(qlxge_modules[0]["id"], "qlxge")
        self.assertEqual(qlxge_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(qlxge_modules[0]["sources"]), 6)
        mxge_modules = manifests["freebsd-mxge"]["modules"]
        self.assertEqual(len(mxge_modules), 1)
        self.assertEqual(mxge_modules[0]["id"], "mxge")
        self.assertEqual(mxge_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(mxge_modules[0]["sources"]), 5)
        zlib_modules = manifests["freebsd-zlib-kernel"]["modules"]
        self.assertEqual(len(zlib_modules), 1)
        self.assertEqual(zlib_modules[0]["id"], "zlib-kernel")
        self.assertEqual(zlib_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(zlib_modules[0]["sources"]), 2)
        iwm_modules = manifests["freebsd-iwm"]["modules"]
        self.assertEqual(len(iwm_modules), 1)
        self.assertEqual(iwm_modules[0]["id"], "iwm-family")
        self.assertEqual(iwm_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(iwm_modules[0]["sources"]), 19)
        iwx_modules = manifests["freebsd-iwx"]["modules"]
        self.assertEqual(len(iwx_modules), 1)
        self.assertEqual(iwx_modules[0]["id"], "iwx-family")
        self.assertEqual(iwx_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(iwx_modules[0]["sources"]), 2)
        net80211_modules = manifests["freebsd-net80211"]["modules"]
        self.assertEqual(len(net80211_modules), 1)
        self.assertEqual(net80211_modules[0]["id"], "net80211-complete")
        self.assertEqual(net80211_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(net80211_modules[0]["sources"]), 43)
        rtwn_modules = manifests["freebsd-rtwn"]["modules"]
        self.assertEqual(len(rtwn_modules), 1)
        self.assertEqual(rtwn_modules[0]["id"], "rtwn-family")
        self.assertEqual(rtwn_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(rtwn_modules[0]["sources"]), 91)
        ral_modules = manifests["freebsd-ral"]["modules"]
        self.assertEqual(len(ral_modules), 1)
        self.assertEqual(ral_modules[0]["id"], "ral-family")
        self.assertEqual(ral_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(ral_modules[0]["sources"]), 4)
        mwl_modules = manifests["freebsd-mwl"]["modules"]
        self.assertEqual(len(mwl_modules), 1)
        self.assertEqual(mwl_modules[0]["id"], "mwl-family")
        self.assertEqual(mwl_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(mwl_modules[0]["sources"]), 3)
        ipw_modules = manifests["freebsd-ipw"]["modules"]
        self.assertEqual(len(ipw_modules), 1)
        self.assertEqual(ipw_modules[0]["id"], "ipw")
        self.assertEqual(ipw_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(ipw_modules[0]["sources"]), 1)
        iwi_modules = manifests["freebsd-iwi"]["modules"]
        self.assertEqual(len(iwi_modules), 1)
        self.assertEqual(iwi_modules[0]["id"], "iwi")
        self.assertEqual(iwi_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(iwi_modules[0]["sources"]), 1)
        iwn_modules = manifests["freebsd-iwn"]["modules"]
        self.assertEqual(len(iwn_modules), 1)
        self.assertEqual(iwn_modules[0]["id"], "iwn")
        self.assertEqual(iwn_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(iwn_modules[0]["sources"]), 1)
        bwi_modules = manifests["freebsd-bwi"]["modules"]
        self.assertEqual(len(bwi_modules), 1)
        self.assertEqual(bwi_modules[0]["id"], "bwi")
        self.assertEqual(bwi_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(bwi_modules[0]["sources"]), 5)
        wpi_modules = manifests["freebsd-wpi"]["modules"]
        self.assertEqual(len(wpi_modules), 1)
        self.assertEqual(wpi_modules[0]["id"], "wpi")
        self.assertEqual(wpi_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(wpi_modules[0]["sources"]), 1)
        malo_modules = manifests["freebsd-malo"]["modules"]
        self.assertEqual(len(malo_modules), 1)
        self.assertEqual(malo_modules[0]["id"], "malo")
        self.assertEqual(malo_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(malo_modules[0]["sources"]), 3)
        otus_modules = manifests["freebsd-otus"]["modules"]
        self.assertEqual(len(otus_modules), 1)
        self.assertEqual(otus_modules[0]["id"], "otus")
        self.assertEqual(otus_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(otus_modules[0]["sources"]), 1)
        usb_wlan_modules = manifests["freebsd-usb-wlan"]["modules"]
        self.assertEqual(len(usb_wlan_modules), 1)
        self.assertEqual(usb_wlan_modules[0]["id"], "usb-wlan-family")
        self.assertEqual(
            usb_wlan_modules[0]["build"]["mode"], "builtin"
        )
        self.assertEqual(len(usb_wlan_modules[0]["sources"]), 9)
        vmxnet3_modules = manifests["freebsd-vmxnet3"]["modules"]
        self.assertEqual(len(vmxnet3_modules), 1)
        self.assertEqual(vmxnet3_modules[0]["id"], "vmxnet3")
        self.assertEqual(vmxnet3_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(vmxnet3_modules[0]["sources"], [
            "sys/dev/vmware/vmxnet3/if_vmx.c"
        ])
        usb_modules = manifests["freebsd-usb-core"]["modules"]
        self.assertEqual(len(usb_modules), 1)
        self.assertEqual(usb_modules[0]["id"], "usb-core")
        self.assertEqual(usb_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(usb_modules[0]["sources"]), 22)
        usb_host_modules = manifests["freebsd-usb-host-pci"]["modules"]
        self.assertEqual(
            {module["id"] for module in usb_host_modules},
            {"xhci-pci", "ehci-pci", "ohci-pci", "uhci-pci"},
        )
        self.assertTrue(
            all(
                module["build"]["mode"] == "builtin"
                for module in usb_host_modules
            )
        )
        self.assertEqual(
            sum(len(module["sources"]) for module in usb_host_modules), 8
        )
        usb_input_modules = manifests["freebsd-usb-input"]["modules"]
        self.assertEqual(len(usb_input_modules), 1)
        self.assertEqual(usb_input_modules[0]["id"], "usb-input-complete")
        self.assertEqual(usb_input_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(len(usb_input_modules[0]["sources"]), 6)
        usb_storage_modules = manifests["freebsd-usb-storage"]["modules"]
        self.assertEqual(len(usb_storage_modules), 1)
        self.assertEqual(usb_storage_modules[0]["id"], "usb-mass-storage")
        self.assertEqual(usb_storage_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            usb_storage_modules[0]["sources"],
            ["sys/dev/usb/storage/umass.c"],
        )
        usb_video_modules = manifests["freebsd-usb-video"]["modules"]
        self.assertEqual(len(usb_video_modules), 1)
        self.assertEqual(
            usb_video_modules[0]["id"], "usb-video-complete"
        )
        self.assertEqual(
            usb_video_modules[0]["build"]["mode"], "builtin"
        )
        self.assertEqual(
            usb_video_modules[0]["sources"],
            ["sys/dev/usb/video/uvideo.c"],
        )
        usb_dwc2_modules = manifests["freebsd-usb-dwc2"]["modules"]
        self.assertEqual(len(usb_dwc2_modules), 1)
        self.assertEqual(usb_dwc2_modules[0]["id"], "usb-dwc2")
        self.assertEqual(len(usb_dwc2_modules[0]["sources"]), 4)
        usb_dwc3_modules = manifests["freebsd-usb-dwc3"]["modules"]
        self.assertEqual(len(usb_dwc3_modules), 1)
        self.assertEqual(usb_dwc3_modules[0]["id"], "usb-dwc3")
        self.assertEqual(len(usb_dwc3_modules[0]["sources"]), 4)
        usb_xhci_generic_modules = manifests[
            "freebsd-usb-xhci-generic"
        ]["modules"]
        self.assertEqual(len(usb_xhci_generic_modules), 1)
        self.assertEqual(
            usb_xhci_generic_modules[0]["id"], "usb-xhci-generic"
        )
        self.assertEqual(
            usb_xhci_generic_modules[0]["build"]["mode"], "builtin"
        )
        self.assertEqual(len(usb_xhci_generic_modules[0]["sources"]), 3)
        usb_musb_modules = manifests["freebsd-usb-musb"]["modules"]
        self.assertEqual(len(usb_musb_modules), 1)
        self.assertEqual(usb_musb_modules[0]["id"], "usb-musb-core")
        self.assertEqual(len(usb_musb_modules[0]["sources"]), 1)
        usb_musb_allwinner_modules = manifests[
            "freebsd-usb-musb-allwinner"
        ]["modules"]
        self.assertEqual(len(usb_musb_allwinner_modules), 1)
        self.assertEqual(
            usb_musb_allwinner_modules[0]["id"], "usb-musb-allwinner"
        )
        self.assertEqual(
            manifests["freebsd-usb-musb-allwinner"]["architectures"],
            ["arm64"],
        )
        usb_template_modules = manifests["freebsd-usb-template"]["modules"]
        self.assertEqual(len(usb_template_modules), 1)
        self.assertEqual(usb_template_modules[0]["id"], "usb-template")
        self.assertEqual(len(usb_template_modules[0]["sources"]), 13)
        amd_sensor_modules = manifests["freebsd-amd-sensors"]["modules"]
        self.assertEqual(len(amd_sensor_modules), 1)
        self.assertEqual(amd_sensor_modules[0]["id"], "amd-sensors")
        self.assertEqual(amd_sensor_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            amd_sensor_modules[0]["sources"],
            [
                "sys/dev/amdsmn/amdsmn.c",
                "sys/dev/amdtemp/amdtemp.c",
            ],
        )
        amdgpio_modules = manifests["freebsd-amdgpio"]["modules"]
        self.assertEqual(len(amdgpio_modules), 1)
        self.assertEqual(amdgpio_modules[0]["id"], "amdgpio")
        self.assertEqual(amdgpio_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            amdgpio_modules[0]["sources"],
            ["sys/dev/amdgpio/amdgpio.c"],
        )
        amdsmu_modules = manifests["freebsd-amdsmu"]["modules"]
        self.assertEqual(len(amdsmu_modules), 1)
        self.assertEqual(amdsmu_modules[0]["id"], "amdsmu")
        self.assertEqual(amdsmu_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            amdsmu_modules[0]["sources"],
            ["sys/dev/amdsmu/amdsmu.c"],
        )
        amdpm_modules = manifests["freebsd-amdpm"]["modules"]
        self.assertEqual(len(amdpm_modules), 1)
        self.assertEqual(amdpm_modules[0]["id"], "amdpm")
        self.assertEqual(amdpm_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            amdpm_modules[0]["sources"],
            ["sys/dev/amdpm/amdpm.c"],
        )
        amdsbwd_modules = manifests["freebsd-amdsbwd"]["modules"]
        self.assertEqual(len(amdsbwd_modules), 1)
        self.assertEqual(amdsbwd_modules[0]["id"], "amdsbwd")
        self.assertEqual(amdsbwd_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            amdsbwd_modules[0]["sources"],
            ["sys/dev/amdsbwd/amdsbwd.c"],
        )
        amdsmb_modules = manifests["freebsd-amdsmb"]["modules"]
        self.assertEqual(len(amdsmb_modules), 1)
        self.assertEqual(amdsmb_modules[0]["id"], "amdsmb")
        self.assertEqual(amdsmb_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            amdsmb_modules[0]["sources"],
            ["sys/dev/amdsmb/amdsmb.c"],
        )
        asmc_modules = manifests["freebsd-asmc"]["modules"]
        self.assertEqual(len(asmc_modules), 1)
        self.assertEqual(asmc_modules[0]["id"], "asmc")
        self.assertEqual(asmc_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            asmc_modules[0]["sources"],
            [
                "sys/dev/asmc/asmc.c",
                "sys/dev/asmc/asmcmmio.c",
            ],
        )
        imcsmb_modules = manifests["freebsd-imcsmb"]["modules"]
        self.assertEqual(len(imcsmb_modules), 1)
        self.assertEqual(imcsmb_modules[0]["id"], "imcsmb")
        self.assertEqual(imcsmb_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            imcsmb_modules[0]["sources"],
            [
                "sys/dev/imcsmb/imcsmb.c",
                "sys/dev/imcsmb/imcsmb_pci.c",
            ],
        )
        ichwd_modules = manifests["freebsd-ichwd"]["modules"]
        self.assertEqual(len(ichwd_modules), 2)
        self.assertEqual(
            [module["id"] for module in ichwd_modules],
            ["ichwd", "i6300esbwd"],
        )
        self.assertTrue(
            all(module["build"]["mode"] == "builtin"
                for module in ichwd_modules)
        )
        self.assertEqual(
            ichwd_modules[0]["sources"],
            ["sys/dev/ichwd/ichwd.c"],
        )
        self.assertEqual(
            ichwd_modules[1]["sources"],
            ["sys/dev/ichwd/i6300esbwd.c"],
        )
        intpm_modules = manifests["freebsd-intpm"]["modules"]
        self.assertEqual(len(intpm_modules), 1)
        self.assertEqual(intpm_modules[0]["id"], "intpm")
        self.assertEqual(intpm_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            intpm_modules[0]["sources"],
            ["sys/dev/intpm/intpm.c"],
        )
        ismt_modules = manifests["freebsd-ismt"]["modules"]
        self.assertEqual(len(ismt_modules), 1)
        self.assertEqual(ismt_modules[0]["id"], "ismt")
        self.assertEqual(ismt_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            ismt_modules[0]["sources"],
            ["sys/dev/ismt/ismt.c"],
        )
        jedec_dimm_modules = manifests["freebsd-jedec-dimm"]["modules"]
        self.assertEqual(len(jedec_dimm_modules), 1)
        self.assertEqual(jedec_dimm_modules[0]["id"], "jedec-dimm")
        self.assertEqual(
            jedec_dimm_modules[0]["build"]["mode"], "builtin"
        )
        self.assertEqual(
            jedec_dimm_modules[0]["sources"],
            ["sys/dev/jedec_dimm/jedec_dimm.c"],
        )
        superio_modules = manifests["freebsd-superio"]["modules"]
        self.assertEqual(len(superio_modules), 1)
        self.assertEqual(superio_modules[0]["id"], "superio")
        self.assertEqual(superio_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            superio_modules[0]["sources"],
            ["sys/dev/superio/superio.c"],
        )
        nctgpio_modules = manifests["freebsd-nctgpio"]["modules"]
        self.assertEqual(len(nctgpio_modules), 1)
        self.assertEqual(nctgpio_modules[0]["id"], "nctgpio")
        self.assertEqual(nctgpio_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            nctgpio_modules[0]["sources"],
            ["sys/dev/nctgpio/nctgpio.c"],
        )
        wbwd_modules = manifests["freebsd-wbwd"]["modules"]
        self.assertEqual(len(wbwd_modules), 1)
        self.assertEqual(wbwd_modules[0]["id"], "wbwd")
        self.assertEqual(wbwd_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            wbwd_modules[0]["sources"],
            ["sys/dev/wbwd/wbwd.c"],
        )
        coretemp_modules = manifests["freebsd-coretemp"]["modules"]
        self.assertEqual(len(coretemp_modules), 1)
        self.assertEqual(coretemp_modules[0]["id"], "coretemp")
        self.assertEqual(coretemp_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            coretemp_modules[0]["sources"],
            ["sys/dev/coretemp/coretemp.c"],
        )
        smbus_modules = manifests["freebsd-smbus-chipsets"]["modules"]
        self.assertEqual(len(smbus_modules), 1)
        self.assertEqual(smbus_modules[0]["id"], "smbus-chipsets")
        self.assertEqual(smbus_modules[0]["build"]["mode"], "builtin")
        self.assertEqual(
            smbus_modules[0]["sources"],
            [
                "sys/dev/ichsmb/ichsmb.c",
                "sys/dev/ichsmb/ichsmb_pci.c",
                "sys/dev/nfsmb/nfsmb.c",
                "sys/dev/smbus/smbconf.c",
                "sys/dev/smbus/smbus.c",
            ],
        )

    def test_capability_registry_tracks_frontend_status(self) -> None:
        registry = load_capability_registry(CAPABILITY_PATH)
        self.assertEqual(registry["capabilities"]["base"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["acpi"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["fdt"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["block"]["status"], "implemented")
        self.assertEqual(
            registry["capabilities"]["geom-disk"]["status"], "implemented"
        )
        self.assertEqual(registry["capabilities"]["geom"]["status"], "unsupported")
        self.assertEqual(
            registry["capabilities"]["network"]["status"], "implemented"
        )
        self.assertEqual(registry["capabilities"]["ifnet"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["mbuf"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["cam"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["scsi"]["status"], "implemented")
        self.assertEqual(registry["capabilities"]["usb"]["status"], "implemented")

    def test_build_plan_is_derived_from_builtin_modules(self) -> None:
        plan = render_build_plan(MANIFEST_DIR, CAPABILITY_DIR)
        self.assertIn("BSD_BRIDGE_PACKAGE_COUNT := 295", plan)
        self.assertIn("BSD_BRIDGE_BUILTIN_MODULE_COUNT := 366", plan)
        self.assertIn("BSD_BRIDGE_BUILTIN_SOURCE_COUNT := 2133", plan)
        self.assertIn("BSD_BRIDGE_LOADABLE_MODULE_COUNT := 10", plan)
        self.assertIn("BSD_BRIDGE_LOADABLE_SOURCE_COUNT := 1854", plan)
        self.assertIn("freebsd-drm-dmabuf--dmabuf.ko", plan)
        self.assertIn("freebsd-drm-amdgpu--amdgpu.ko", plan)
        self.assertIn("freebsd-drm-i915--i915kms.ko", plan)
        self.assertIn("netbsd-drm-nouveau--nouveau.ko", plan)
        self.assertIn(
            "freebsd-linuxkpi-runtime-slice/linuxkpi-core", plan
        )
        self.assertIn("freebsd-virtio--virtio-random.ko", plan)
        self.assertIn("freebsd-ispfw--ispfw.ko", plan)
        self.assertIn("dev/mpi3mr/mpi3mr.c", plan)
        self.assertIn("dev/mpi3mr/mpi3mr_pci.c", plan)
        self.assertIn("dev/mpi3mr/mpi3mr_cam.c", plan)
        self.assertIn("dev/mpi3mr/mpi3mr_app.c", plan)
        self.assertIn("dev/usb/controller/generic_xhci.c", plan)
        self.assertIn("dev/usb/controller/generic_xhci_acpi.c", plan)
        self.assertIn("dev/usb/controller/generic_xhci_fdt.c", plan)
        self.assertIn("dev/sound/pcm/ac97.c", plan)
        self.assertIn("dev/sound/pci/hda/hdac.c", plan)
        self.assertIn("dev/sound/pci/hda/hdaa.c", plan)
        self.assertIn("dev/sound/pci/maestro3.c", plan)
        self.assertIn("dev/sound/midi/midi.c", plan)
        self.assertIn("dev/sound/pci/emu10kx.c", plan)
        self.assertIn("dev/sound/pci/envy24ht.c", plan)
        self.assertIn("dev/sound/pci/hdspe-pcm.c", plan)
        self.assertIn("dev/hyperv/vmbus/amd64/vmbus_vector.S", plan)
        self.assertIn("dev/hyperv/vmbus/aarch64/hyperv_aarch64.c", plan)
        self.assertIn("dev/hyperv/netvsc/if_hn.c", plan)
        self.assertIn("dev/hyperv/storvsc/hv_storvsc_drv_freebsd.c", plan)
        self.assertIn("dev/atkbdc/atkbdc.c", plan)
        self.assertIn("dev/atkbdc/psm.c", plan)
        self.assertIn("arm64/broadcom/genet/if_genet.c", plan)
        self.assertIn("arm64/broadcom/brcmmdio/mdio_mux_iproc.c", plan)
        self.assertIn("arm64/broadcom/brcmmdio/mdio_nexus_iproc.c", plan)
        self.assertIn("arm64/broadcom/brcmmdio/mdio_ns2_pcie_phy.c", plan)
        self.assertIn("arm64/freescale/imx/imx7gpc.c", plan)
        self.assertIn("arm64/freescale/imx/imx8mp_ccm.c", plan)
        self.assertIn("arm64/freescale/imx/imx8mq_ccm.c", plan)
        self.assertIn("arm64/cavium/thunder_pcie_common.c", plan)
        self.assertIn("arm64/cavium/thunder_pcie_pem.c", plan)
        self.assertIn("dev/ofw/ofw_pci.c", plan)
        self.assertIn("dev/ofw/ofw_pcib.c", plan)
        self.assertIn("dev/pci/pci_host_generic.c", plan)
        self.assertIn("dev/pci/pci_host_generic_acpi.c", plan)
        self.assertIn("dev/pci/pci_host_generic_fdt.c", plan)
        self.assertIn("dev/iicbus/iicbus.c", plan)
        self.assertIn("dev/iicbus/iiconf.c", plan)
        self.assertIn("dev/iicbus/iic_recover_bus.c", plan)
        self.assertIn("isa/isa_common.c", plan)
        self.assertIn("x86/isa/isa.c", plan)
        self.assertIn("dev/acpica/acpi_button.c", plan)
        self.assertIn("dev/acpica/acpi_lid.c", plan)
        self.assertIn("dev/acpica/acpi_ec.c", plan)
        self.assertIn("dev/acpica/acpi_acad.c", plan)
        self.assertIn("dev/acpica/acpi_battery.c", plan)
        self.assertIn("dev/acpica/acpi_cmbat.c", plan)
        self.assertIn("dev/acpica/acpi_package.c", plan)
        self.assertIn("dev/acpica/acpi_dock.c", plan)
        self.assertIn("dev/acpica/acpi_powerres.c", plan)
        self.assertIn("dev/agp/agp.c", plan)
        self.assertIn("dev/agp/agp_amd64.c", plan)
        self.assertIn("dev/agp/agp_i810.c", plan)
        self.assertIn("dev/agp/agp_via.c", plan)
        self.assertIn("arm/broadcom/bcm2835/bcm2835_firmware.c", plan)
        self.assertIn("arm/broadcom/bcm2835/bcm2835_gpio.c", plan)
        self.assertIn("arm/broadcom/bcm2835/bcm2835_sdhci.c", plan)
        self.assertIn("dev/amdpm/amdpm.c", plan)
        self.assertIn("dev/amdsbwd/amdsbwd.c", plan)
        self.assertIn("dev/amdsmb/amdsmb.c", plan)
        self.assertIn("dev/clk/clk_div.c", plan)
        self.assertIn("dev/clk/clk_gate.c", plan)
        self.assertIn("dev/clk/clk_link.c", plan)
        self.assertIn("dev/clk/clk_mux.c", plan)
        self.assertIn("dev/qcom_clk/qcom_clk_rcg2.c", plan)
        self.assertIn("dev/qcom_gcc/qcom_gcc_main.c", plan)
        self.assertIn("dev/qcom_qup/qcom_spi.c", plan)
        self.assertIn("dev/qcom_ess_edma/qcom_ess_edma.c", plan)
        self.assertIn("contrib/libnv/nvlist.c", plan)
        self.assertIn("dev/thunderbolt/nhi.c", plan)
        self.assertIn("dev/thunderbolt/router.c", plan)
        self.assertIn("dev/thunderbolt/tb_pcib.c", plan)
        self.assertIn("dev/intel/spi.c", plan)
        self.assertIn("dev/intel/spi_acpi.c", plan)
        self.assertIn("dev/intel/spi_pci.c", plan)
        self.assertIn("dev/intel/pchtherm.c", plan)
        self.assertIn("dev/chromebook_platform/chromebook_platform.c", plan)
        self.assertIn("dev/glxiic/glxiic.c", plan)
        self.assertIn("dev/iicbus/iicbb.c", plan)
        self.assertIn("dev/viapm/viapm.c", plan)
        self.assertIn("dev/alpm/alpm.c", plan)
        self.assertIn("dev/spibus/spibus.c", plan)
        self.assertIn("dev/spibus/ofw_spibus.c", plan)
        self.assertIn("dev/apple_bce/apple_bce.c", plan)
        self.assertIn("dev/apple_bce/apple_bce_mailbox.c", plan)
        self.assertIn("dev/apple_bce/apple_bce_queue.c", plan)
        self.assertIn("dev/apple_bce/apple_bce_vhci.c", plan)
        self.assertIn("dev/asmc/asmc.c", plan)
        self.assertIn("dev/asmc/asmcmmio.c", plan)
        self.assertIn("dev/atopcase/atopcase.c", plan)
        self.assertIn("dev/atopcase/atopcase_acpi.c", plan)
        self.assertIn("dev/intpm/intpm.c", plan)
        self.assertIn("dev/ichwd/ichwd.c", plan)
        self.assertIn("dev/ichwd/i6300esbwd.c", plan)
        self.assertIn("dev/ismt/ismt.c", plan)
        self.assertIn("dev/nctgpio/nctgpio.c", plan)
        self.assertIn("libkern/crc16.c", plan)
        self.assertIn("dev/wbwd/wbwd.c", plan)
        self.assertIn("dev/mfi/mfi_tbolt.c", plan)
        self.assertIn("dev/mpt/mpt_raid.c", plan)
        self.assertIn("dev/mrsas/mrsas_fp.c", plan)
        self.assertIn("dev/aacraid/aacraid_cam.c", plan)
        self.assertIn("dev/smartpqi/smartpqi_discovery.c", plan)
        self.assertIn("dev/arcmsr/arcmsr.c", plan)
        self.assertIn("dev/tws/tws_services.c", plan)
        self.assertIn("dev/mps/mps_sas.c", plan)
        self.assertIn("dev/mpr/mpr_sas.c", plan)
        self.assertIn("dev/ciss/ciss.c", plan)
        self.assertIn("dev/hptiop/hptiop.c", plan)
        self.assertIn("dev/aac/aac_cam.c", plan)
        self.assertIn("dev/ips/ips_commands.c", plan)
        self.assertIn("dev/isp/isp_target.c", plan)
        self.assertIn("dev/mvs/mvs_pci.c", plan)
        self.assertIn("dev/mlx/mlx_disk.c", plan)
        self.assertIn("dev/ixgbe/if_ix.c", plan)
        self.assertIn("dev/ixgbe/if_ixv.c", plan)
        self.assertIn("dev/ixl/ixl_pf_main.c", plan)
        self.assertIn("dev/iavf/if_iavf_iflib.c", plan)
        self.assertIn("dev/iavf/iavf_vc_iflib.c", plan)
        self.assertIn("dev/ice/if_ice_iflib.c", plan)
        self.assertIn("dev/ice/ice_common.c", plan)
        self.assertIn("dev/ice/ice_rdma.c", plan)
        self.assertIn("dev/ipw/if_ipw.c", plan)
        self.assertIn("dev/malo/if_malo.c", plan)
        self.assertIn("dev/otus/if_otus.c", plan)
        self.assertIn("dev/usb/wlan/if_rsu.c", plan)
        self.assertIn("dev/usb/wlan/if_zyd.c", plan)
        self.assertIn("dev/aq/aq_main.c", plan)
        self.assertIn("dev/aq/aq_ring.c", plan)
        self.assertIn("dev/aq/aq_fw2x.c", plan)
        self.assertIn("dev/bce/if_bce.c", plan)
        self.assertIn("dev/bxe/bxe.c", plan)
        self.assertIn("dev/bxe/57712_init_values.c", plan)
        self.assertIn("dev/oce/oce_if.c", plan)
        self.assertIn("dev/oce/oce_mbox.c", plan)
        self.assertIn("dev/qlxgb/qla_os.c", plan)
        self.assertIn("dev/qlxgb/qla_ioctl.c", plan)
        self.assertIn("dev/qlxgbe/ql_os.c", plan)
        self.assertIn("dev/qlxgbe/ql_minidump.c", plan)
        self.assertIn("dev/sfxge/sfxge.c", plan)
        self.assertIn("dev/sfxge/common/ef10_nic.c", plan)
        self.assertIn("dev/sfxge/common/medford2_nic.c", plan)
        self.assertIn("dev/gve/gve_main.c", plan)
        self.assertIn("dev/gve/gve_rx_dqo.c", plan)
        self.assertIn("dev/liquidio/lio_main.c", plan)
        self.assertIn("dev/liquidio/base/lio_device.c", plan)
        self.assertIn("libkern/gsb_crc32.c", plan)
        self.assertEqual(
            make_assignment_values(
                plan,
                "BSD_BRIDGE_PACKAGE_FREEBSD_SFXGE_ARM64_CPPFLAGS",
            ),
            [
                "-Wno-shift-count-overflow",
                "-U_WIN32 -U_WIN64",
            ],
        )
        self.assertIn("libkern/qsort.c", plan)
        self.assertIn("dev/acpica/acpi_thermal.c", plan)
        self.assertIn("dev/acpica/acpi_video.c", plan)
        self.assertIn("dev/acpica/acpi_cpu.c", plan)
        self.assertIn("dev/amdsmn/amdsmn.c", plan)
        self.assertIn("dev/amdtemp/amdtemp.c", plan)
        self.assertIn("dev/amdgpio/amdgpio.c", plan)
        self.assertIn("dev/amdsmu/amdsmu.c", plan)
        self.assertIn("dev/imcsmb/imcsmb.c", plan)
        self.assertIn("dev/imcsmb/imcsmb_pci.c", plan)
        self.assertIn("dev/jedec_dimm/jedec_dimm.c", plan)
        self.assertIn("dev/superio/superio.c", plan)
        self.assertIn("dev/coretemp/coretemp.c", plan)
        self.assertIn("dev/age/if_age.c", plan)
        self.assertIn("dev/alc/if_alc.c", plan)
        self.assertIn("dev/ale/if_ale.c", plan)
        self.assertIn("dev/fxp/if_fxp.c", plan)
        self.assertIn("dev/fxp/inphy.c", plan)
        self.assertIn("dev/jme/if_jme.c", plan)
        self.assertIn("dev/ae/if_ae.c", plan)
        self.assertIn("dev/bfe/if_bfe.c", plan)
        self.assertIn("dev/cas/if_cas.c", plan)
        self.assertIn("dev/et/if_et.c", plan)
        self.assertIn("dev/gem/if_gem.c", plan)
        self.assertIn("dev/mgb/if_mgb.c", plan)
        self.assertIn("dev/rge/if_rge.c", plan)
        self.assertIn("dev/stge/if_stge.c", plan)
        self.assertIn("dev/vte/if_vte.c", plan)
        self.assertIn("dev/nvme/nvme_ctrlr.c", plan)
        self.assertIn("dev/nvme/nvme_pci.c", plan)
        self.assertIn("dev/nvd/nvd.c", plan)
        self.assertIn("dev/nfe/if_nfe.c", plan)
        self.assertIn("dev/ichsmb/ichsmb_pci.c", plan)
        self.assertIn("dev/nfsmb/nfsmb.c", plan)
        self.assertIn("dev/smbus/smbus.c", plan)
        self.assertIn("dev/acpi_support/acpi_wmi.c", plan)
        self.assertIn("dev/acpi_support/acpi_asus.c", plan)
        self.assertIn("dev/acpi_support/acpi_ibm.c", plan)
        self.assertIn("dev/acpi_support/acpi_asus_wmi.c", plan)
        self.assertIn("dev/acpi_support/acpi_system76.c", plan)
        self.assertIn("dev/backlight/backlight.c", plan)
        self.assertIn("dev/gpio/gpiobacklight.c", plan)
        self.assertIn("dev/iicbus/sensor/lm75.c", plan)
        self.assertIn("dev/iicbus/sensor/tmp461.c", plan)
        self.assertIn("dev/vt/hw/simplefb/simplefb.c", plan)
        self.assertIn("kern/subr_power.c", plan)
        self.assertIn("dev/acpi_support/acpi_fujitsu.c", plan)
        self.assertIn("dev/acpi_support/acpi_hp.c", plan)
        self.assertIn("dev/acpi_support/acpi_panasonic.c", plan)
        self.assertIn("dev/acpi_support/acpi_rapidstart.c", plan)
        self.assertIn("dev/acpi_support/acpi_sbl_wmi.c", plan)
        self.assertIn("dev/acpi_support/acpi_sony.c", plan)
        self.assertIn("dev/acpi_support/acpi_toshiba.c", plan)
        self.assertIn("dev/acpi_support/atk0110.c", plan)
        self.assertIn("kern/kern_cpu.c", plan)
        self.assertIn("dev/cpufreq/cpufreq_dt.c", plan)
        self.assertIn("dev/cpufreq/ichss.c", plan)
        self.assertIn("x86/cpufreq/est.c", plan)
        self.assertIn("x86/cpufreq/hwpstate_amd.c", plan)
        self.assertIn("x86/cpufreq/hwpstate_common.c", plan)
        self.assertIn("x86/cpufreq/hwpstate_intel.c", plan)
        self.assertIn("x86/cpufreq/p4tcc.c", plan)
        self.assertIn("x86/cpufreq/powernow.c", plan)
        self.assertIn("dev/cyapa/cyapa.c", plan)
        self.assertIn("dev/virtio/virtqueue.c", plan)
        self.assertIn("dev/virtio/block/virtio_blk.c", plan)
        self.assertIn("dev/virtio/network/if_vtnet.c", plan)
        self.assertIn("dev/virtio/scsi/virtio_scsi.c", plan)
        self.assertIn("contrib/libfdt/fdt_ro.c", plan)
        self.assertIn("net/iflib.c", plan)
        self.assertIn("net/mp_ring.c", plan)
        self.assertIn("dev/e1000/if_em.c", plan)
        self.assertIn("dev/e1000/igb_txrx.c", plan)
        self.assertIn("dev/igc/if_igc.c", plan)
        self.assertIn("dev/igc/igc_txrx.c", plan)
        self.assertIn("dev/iwm/if_iwm.c", plan)
        self.assertIn("dev/iwm/if_iwm_pcie_trans.c", plan)
        self.assertIn("dev/iwi/if_iwi.c", plan)
        self.assertIn("dev/iwn/if_iwn.c", plan)
        self.assertIn("dev/iwx/if_iwx.c", plan)
        self.assertIn("dev/iwx/if_iwx_debug.c", plan)
        self.assertIn("dev/bwi/if_bwi.c", plan)
        self.assertIn("dev/wpi/if_wpi.c", plan)
        self.assertIn("net80211/ieee80211.c", plan)
        self.assertIn("net80211/ieee80211_xauth.c", plan)
        self.assertIn("dev/vmware/vmxnet3/if_vmx.c", plan)
        self.assertIn("dev/usb/usb_core.c", plan)
        self.assertIn("dev/usb/usb_transfer.c", plan)
        self.assertIn("dev/usb/controller/xhci_pci.c", plan)
        self.assertIn("dev/usb/controller/ehci_pci.c", plan)
        self.assertIn("dev/usb/controller/ohci_pci.c", plan)
        self.assertIn("dev/usb/controller/uhci_pci.c", plan)
        self.assertIn("dev/usb/input/ukbd.c", plan)
        self.assertIn("dev/usb/input/ums.c", plan)
        self.assertIn("dev/hid/hkbd.c", plan)
        self.assertIn("dev/hid/hmt.c", plan)
        self.assertIn("dev/hid/hpen.c", plan)
        self.assertIn("dev/usb/input/wmt.c", plan)
        self.assertIn("dev/usb/serial/ulpt.c", plan)
        self.assertIn("dev/sound/usb/uaudio.c", plan)
        self.assertIn("dev/sound/usb/uaudio_pcm.c", plan)
        self.assertIn("dev/usb/video/uvideo.c", plan)
        self.assertIn("dev/usb/video/udl.c", plan)
        self.assertIn("dev/ncthwm/ncthwm.c", plan)
        self.assertIn("dev/usb/controller/dwc_otg.c", plan)
        self.assertIn("dev/usb/controller/dwc3/dwc3.c", plan)
        self.assertIn("dev/usb/controller/musb_otg.c", plan)
        self.assertIn("dev/usb/net/if_cdceem.c", plan)
        self.assertIn("dev/usb/storage/ustorage_fs.c", plan)
        self.assertIn("dev/usb/template/usb_template_multi.c", plan)
        self.assertIn("dev/usb/gadget/g_audio.c", plan)
        self.assertIn("dev/usb/gadget/g_modem.c", plan)
        self.assertIn("dev/pci/vga_pci.c", plan)
        self.assertIn("compat/x86bios/x86bios.c", plan)
        self.assertIn("contrib/x86emu/x86emu.c", plan)
        for package_id in (
            "ACPI_BUTTONS",
            "ACPI_POWER",
            "ACPI_THERMAL",
            "ACPI_WMI",
            "ACPI_EC",
            "I2C_HID",
        ):
            self.assertIn(
                "-I$(BSD_BRIDGE_ACPICA_INCLUDE)",
                make_assignment_values(
                    plan,
                    f"BSD_BRIDGE_PACKAGE_FREEBSD_{package_id}_INCLUDE_FLAGS",
                ),
            )
        self.assertIn(
            "BSD_BRIDGE_PACKAGE_FREEBSD_I2C_HID_REL_SRCS:.c=.o)): "
            "$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP)",
            plan,
        )
        self.assertIn(
            "BSD_BRIDGE_PACKAGE_FREEBSD_LIBFDT_CPPFLAGS := -U_KERNEL",
            plan,
        )
        self.assertIn(
            "$(OBJ)/compat/freebsd/generated/irdma_if.o: "
            "BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
            "-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/ice",
            plan,
        )
        self.assertIn(
            "irdma_if=-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/ice",
            make_assignment_values(
                plan, "BSD_BRIDGE_GENERATED_INCLUDE_MAPPINGS"
            ),
        )
        self.assertIn(
            "$(OBJ)/arm64-bsd/generated/irdma_if.obj: "
            "BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
            "-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/ice",
            plan,
        )
        self.assertIn(
            "$(OBJ)/compat/freebsd/generated/pic_if.o: "
            "BSD_BRIDGE_SOURCE_CPPFLAGS += -DINTRNG",
            plan,
        )
        self.assertIn(
            "$(OBJ)/arm64-bsd/generated/pic_if.obj: "
            "BSD_BRIDGE_SOURCE_CPPFLAGS += -DINTRNG",
            plan,
        )
        self.assertIn(
            "pic_if=-DINTRNG",
            make_assignment_values(
                plan,
                "BSD_BRIDGE_X86_64_GENERATED_COMPILE_MAPPINGS",
            ),
        )
        self.assertIn(
            "pic_if=-DINTRNG",
            make_assignment_values(
                plan,
                "BSD_BRIDGE_ARM64_GENERATED_COMPILE_MAPPINGS",
            ),
        )
        self.assertIn(
            "acpi_wmi_if=-I$(BSD_BRIDGE_ACPICA_INCLUDE)",
            make_assignment_values(
                plan,
                "BSD_BRIDGE_X86_64_GENERATED_COMPILE_MAPPINGS",
            ),
        )
        self.assertIn(
            "acpi_wmi_if=-DEDGEOS_BSD_FULL_ACPICA",
            make_assignment_values(
                plan,
                "BSD_BRIDGE_X86_64_GENERATED_COMPILE_MAPPINGS",
            ),
        )
        self.assertIn(
            "$(OBJ)/compat/freebsd/generated/acpi_wmi_if.o: "
            "BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += "
            "-I$(BSD_BRIDGE_ACPICA_INCLUDE)",
            plan,
        )
        self.assertIn(
            "$(OBJ)/compat/freebsd/generated/acpi_wmi_if.o: "
            "$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP)",
            plan,
        )
        self.assertEqual(
            make_assignment_values(
                plan,
                "BSD_BRIDGE_PACKAGE_FREEBSD_SMARTPQI_ARM64_CPPFLAGS",
            ),
            ["-D__FreeBSD__=16", "-Dinline="],
        )
        self.assertIn("bsd_package_registry.c", plan)

    def test_build_plan_honors_package_architectures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_dir = Path(temporary) / "manifests"
            shutil.copytree(MANIFEST_DIR, manifest_dir)
            manifest_path = manifest_dir / "freebsd-vmxnet3.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["architectures"] = ["x86_64"]
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            plan = render_build_plan(manifest_dir, CAPABILITY_DIR)
        x86_sources = make_assignment_values(
            plan, "BSD_BRIDGE_X86_64_UPSTREAM_REL_SRCS"
        )
        arm64_sources = make_assignment_values(
            plan, "BSD_BRIDGE_ARM64_UPSTREAM_REL_SRCS"
        )
        self.assertIn("dev/vmware/vmxnet3/if_vmx.c", x86_sources)
        self.assertNotIn("dev/vmware/vmxnet3/if_vmx.c", arm64_sources)
        self.assertIn("dev/acpica/acpi_cpu.c", x86_sources)
        self.assertNotIn("dev/acpica/acpi_cpu.c", arm64_sources)
        self.assertIn("x86/cpufreq/hwpstate_amd.c", x86_sources)
        self.assertNotIn("x86/cpufreq/hwpstate_amd.c", arm64_sources)

    def test_build_plan_honors_module_kconfig_requirements(self) -> None:
        plan = render_build_plan(MANIFEST_DIR, CAPABILITY_DIR)

        x86_acpi_section = plan.split(
            "ifeq ($(CONFIG_ACPI),y)\n", 1
        )[1].split("\nendif", 1)[0]
        self.assertIn("dev/acpica/acpi_pci_link.c", x86_acpi_section)
        self.assertIn("dev/nvdimm/nvdimm_acpi.c", x86_acpi_section)
        self.assertIn("dev/sdhci/sdhci_acpi.c", x86_acpi_section)
        self.assertIn("x86/iommu/amd_drv.c", x86_acpi_section)
        self.assertIn("x86/iommu/intel_drv.c", x86_acpi_section)
        arm64_acpi_section = plan.split(
            "ifeq ($(ARM64_CONFIG_ACPI),y)\n", 1
        )[1].split("\nendif", 1)[0]
        self.assertIn("dev/sdhci/sdhci_acpi.c", arm64_acpi_section)
        self.assertIn(
            "dev/sdhci/sdhci_xenon_acpi.c", arm64_acpi_section
        )
        self.assertIn(
            "dev/pci/pci_host_generic_acpi.c", arm64_acpi_section
        )
        self.assertIn(
            "dev/pci/pci_host_generic_den0115.c", arm64_acpi_section
        )
        device_tree_section = plan.split(
            "ifeq ($(ARM64_CONFIG_DEVICE_TREE),y)\n", 1
        )[1].split("\nendif", 1)[0]
        self.assertIn("dev/cpufreq/cpufreq_dt.c", device_tree_section)
        self.assertIn(
            "arm64/freescale/imx/imx7gpc.c", device_tree_section
        )
        self.assertIn(
            "arm64/freescale/imx/imx8mp_ccm.c", device_tree_section
        )
        self.assertIn(
            "arm64/freescale/imx/imx8mq_ccm.c", device_tree_section
        )
        self.assertIn(
            "arm64/cavium/thunder_pcie_fdt.c", device_tree_section
        )
        self.assertIn("dev/ofw/ofw_pci.c", device_tree_section)
        self.assertIn(
            "dev/pci/pci_host_generic_fdt.c", device_tree_section
        )

    def test_manifest_rejects_unknown_module_kconfig_requirement(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["modules"][0]["kconfig_requires"] = ["ARBITRARY"]
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ManifestError,
                "kconfig_requires contains unsupported symbols",
            ):
                load_manifest(manifest_path)

    def test_build_plan_uses_architecture_specific_include_group_flags(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_dir = Path(temporary) / "manifests"
            shutil.copytree(MANIFEST_DIR, manifest_dir)
            manifest_path = manifest_dir / "freebsd-i2c-hid.json"
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            manifest["architectures"] = ["x86_64", "arm64"]
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            plan = render_build_plan(manifest_dir, CAPABILITY_DIR)

        arm64_flags = make_assignment_values(
            plan,
            "BSD_BRIDGE_PACKAGE_FREEBSD_I2C_HID_ARM64_INCLUDE_FLAGS",
        )
        self.assertEqual(
            arm64_flags,
            ["-I$(BSD_BRIDGE_ACPICA_INCLUDE)", "-U_MSC_VER"],
        )

    def test_manifest_rejects_unknown_arm64_compile_option(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["compile"]["arm64_options"] = ["arbitrary-flag"]
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ManifestError,
                "compile.arm64_options contains unsupported options",
            ):
                load_manifest(manifest_path)

    def test_generated_package_registry_covers_catalog(self) -> None:
        registry = render_package_registry(MANIFEST_DIR, CAPABILITY_DIR)

        self.assertIn('.id = "freebsd-virtio"', registry)
        self.assertIn('.id = "freebsd-acpi-ec"', registry)
        self.assertIn('.id = "freebsd-acpi-platform"', registry)
        self.assertIn('.id = "freebsd-acpi-power"', registry)
        self.assertIn('.id = "freebsd-acpi-thermal"', registry)
        self.assertIn('.id = "freebsd-acpi-video"', registry)
        self.assertIn('.id = "freebsd-acpi-cpu"', registry)
        self.assertIn('.id = "freebsd-acpi-wmi"', registry)
        self.assertIn('.id = "freebsd-acpi-laptops"', registry)
        self.assertIn('.id = "freebsd-acpi-modern-laptops"', registry)
        self.assertIn('.id = "freebsd-acpi-oem"', registry)
        self.assertIn('.id = "freebsd-amd-sensors"', registry)
        self.assertIn('.id = "freebsd-amd-ecc-inject"', registry)
        self.assertIn('.id = "freebsd-adlink"', registry)
        self.assertIn('.id = "freebsd-amdgpio"', registry)
        self.assertIn('.id = "freebsd-amdpm"', registry)
        self.assertIn('.id = "freebsd-amdsbwd"', registry)
        self.assertIn('.id = "freebsd-amdsmb"', registry)
        self.assertIn('.id = "freebsd-amdsmu"', registry)
        self.assertIn('.id = "freebsd-asmc"', registry)
        self.assertIn('.id = "freebsd-coretemp"', registry)
        self.assertIn('.id = "freebsd-smbus-chipsets"', registry)
        self.assertIn('.id = "freebsd-imcsmb"', registry)
        self.assertIn('.id = "freebsd-ichwd"', registry)
        self.assertIn('.id = "freebsd-intpm"', registry)
        self.assertIn('.id = "freebsd-ismt"', registry)
        self.assertIn('.id = "freebsd-jedec-dimm"', registry)
        self.assertIn('.id = "freebsd-nctgpio"', registry)
        self.assertIn('.id = "freebsd-superio"', registry)
        self.assertIn('.id = "freebsd-wbwd"', registry)
        self.assertIn('.id = "freebsd-backlight"', registry)
        self.assertIn('.id = "freebsd-gpio-backlight"', registry)
        self.assertIn('.id = "freebsd-iic-sensors"', registry)
        self.assertIn('.id = "freebsd-simple-framebuffer"', registry)
        self.assertIn('.id = "freebsd-power-core"', registry)
        self.assertIn('.id = "freebsd-cpufreq"', registry)
        self.assertIn('.id = "freebsd-cpufreq-dt"', registry)
        self.assertIn('.id = "freebsd-cpufreq-x86-backends"', registry)
        self.assertIn('.id = "freebsd-hwpstate-amd"', registry)
        self.assertIn('.id = "freebsd-libfdt"', registry)
        self.assertIn('.id = "freebsd-iflib"', registry)
        self.assertIn('.id = "freebsd-e1000"', registry)
        self.assertIn('.id = "freebsd-igc"', registry)
        self.assertIn('.id = "freebsd-iavf"', registry)
        self.assertIn('.id = "freebsd-ice"', registry)
        self.assertIn('.id = "freebsd-aq"', registry)
        self.assertIn('.id = "freebsd-bce"', registry)
        self.assertIn('.id = "freebsd-oce"', registry)
        self.assertIn('.id = "freebsd-qlxgb"', registry)
        self.assertIn('.id = "freebsd-qlxge"', registry)
        self.assertIn('.id = "freebsd-mxge"', registry)
        self.assertIn('.id = "freebsd-zlib-kernel"', registry)
        self.assertIn('.id = "freebsd-goldfish-rtc"', registry)
        self.assertIn('.id = "freebsd-sff"', registry)
        self.assertIn('.id = "freebsd-gve"', registry)
        self.assertIn('.id = "freebsd-liquidio"', registry)
        self.assertIn('.id = "freebsd-libkern-crc"', registry)
        self.assertIn('.id = "freebsd-iwm"', registry)
        self.assertIn('.id = "freebsd-iwx"', registry)
        self.assertIn('.id = "freebsd-ipw"', registry)
        self.assertIn('.id = "freebsd-iwi"', registry)
        self.assertIn('.id = "freebsd-iwn"', registry)
        self.assertIn('.id = "freebsd-bwi"', registry)
        self.assertIn('.id = "freebsd-wpi"', registry)
        self.assertIn('.id = "freebsd-malo"', registry)
        self.assertIn('.id = "freebsd-mwl"', registry)
        self.assertIn('.id = "freebsd-net80211"', registry)
        self.assertIn('.id = "freebsd-otus"', registry)
        self.assertIn('.id = "freebsd-ral"', registry)
        self.assertIn('.id = "freebsd-rtwn"', registry)
        self.assertIn('.id = "freebsd-vmxnet3"', registry)
        self.assertIn('.id = "freebsd-usb-core"', registry)
        self.assertIn('.id = "freebsd-usb-audio"', registry)
        self.assertIn('.id = "freebsd-usb-host-pci"', registry)
        self.assertIn('.id = "freebsd-usb-input"', registry)
        self.assertIn('.id = "freebsd-usb-storage"', registry)
        self.assertIn('.id = "freebsd-usb-video"', registry)
        self.assertIn('.id = "freebsd-usb-wlan"', registry)
        self.assertIn('.id = "freebsd-vgapci"', registry)
        self.assertIn('.id = "freebsd-agp"', registry)
        self.assertIn('.id = "freebsd-libnv"', registry)
        self.assertIn('.id = "freebsd-thunderbolt"', registry)
        self.assertIn('.id = "freebsd-intelspi"', registry)
        self.assertIn('.id = "freebsd-pchtherm"', registry)
        self.assertIn('.id = "freebsd-chromebook-platform"', registry)
        self.assertIn('.id = "freebsd-glxiic"', registry)
        self.assertIn('.id = "freebsd-viapm"', registry)
        self.assertIn('.id = "freebsd-alpm"', registry)
        self.assertIn('.id = "freebsd-atkbdc"', registry)
        self.assertIn('.id = "freebsd-isa-core"', registry)
        self.assertIn('.id = "freebsd-x86bios"', registry)
        self.assertIn('.id = "freebsd-efi-runtime"', registry)
        self.assertIn('.id = "freebsd-iommu-x86"', registry)
        self.assertIn('.id = "freebsd-nvdimm"', registry)
        self.assertIn('.id = "freebsd-psci"', registry)
        self.assertIn(".source_count = 43", registry)
        self.assertIn(".source_count = 19", registry)
        self.assertIn(".source_count = 21", registry)
        self.assertIn(".source_count = 8", registry)
        self.assertIn(".source_count = 2", registry)
        self.assertIn(".source_count = 22", registry)
        self.assertIn(".builtin_module_count = 13", registry)
        self.assertIn(".loadable_module_count = 1", registry)
        self.assertIn(".disabled_module_count = 2", registry)
        self.assertIn("BSD_DRIVER_PACKAGE_REGISTERED", registry)

    def test_build_plan_reserves_package_registry_source_name(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["generated_interfaces"].append(
            "sys/dev/example/bsd_package_registry.m"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests = root / "manifests"
            capabilities = root / "capabilities"
            manifests.mkdir()
            capabilities.mkdir()
            (manifests / "freebsd-virtio.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            (capabilities / "freebsd.json").write_text(
                CAPABILITY_PATH.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with self.assertRaisesRegex(ManifestError, "is reserved"):
                render_build_plan(manifests, capabilities)

    def test_catalog_supports_multiple_driver_packages(self) -> None:
        first = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        second = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        second["id"] = "freebsd-virtio-extra"
        p9 = next(
            module for module in second["modules"]
            if module["id"] == "virtio-p9fs"
        )
        p9["build"] = {"mode": "builtin"}
        second["modules"] = [p9]
        second["compile"]["definitions"] = ["VIRTIO_P9_STANDALONE"]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests = root / "manifests"
            capabilities = root / "capabilities"
            manifests.mkdir()
            capabilities.mkdir()
            (manifests / "freebsd-virtio.json").write_text(
                json.dumps(first), encoding="utf-8"
            )
            (manifests / "freebsd-virtio-extra.json").write_text(
                json.dumps(second), encoding="utf-8"
            )
            (capabilities / "freebsd.json").write_text(
                CAPABILITY_PATH.read_text(encoding="utf-8"), encoding="utf-8"
            )

            plan = render_build_plan(manifests, capabilities)
            self.assertIn("BSD_BRIDGE_PACKAGE_COUNT := 2", plan)
            self.assertIn("BSD_BRIDGE_BUILTIN_SOURCE_COUNT := 17", plan)
            self.assertIn("dev/virtio/p9fs/virtio_p9fs.c", plan)
            self.assertIn(
                "BSD_BRIDGE_PACKAGE_FREEBSD_VIRTIO_CPPFLAGS := "
                "-DSC_NO_CUTPASTE",
                plan,
            )
            self.assertIn(
                "BSD_BRIDGE_PACKAGE_FREEBSD_VIRTIO_EXTRA_CPPFLAGS := "
                "-DVIRTIO_P9_STANDALONE",
                plan,
            )
            self.assertNotIn("BSD_BRIDGE_PACKAGE_CPPFLAGS", plan)

    def test_pinned_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(MANIFEST_PATH, REPO_ROOT)
        manifest = load_manifest(MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, manifest["source_lock"]["file_count"])

    def test_libfdt_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            LIBFDT_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(LIBFDT_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 13)

    def test_iflib_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IFLIB_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IFLIB_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 3)

    def test_vmxnet3_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            VMXNET3_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(VMXNET3_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 3)

    def test_igc_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IGC_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IGC_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 19)

    def test_iavf_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IAVF_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IAVF_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 28)

    def test_ice_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            ICE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(ICE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 63)

    def test_aq_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            AQ_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(AQ_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 18)

    def test_bce_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            BCE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(BCE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 3)

    def test_bxe_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            BXE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(BXE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 24)

    def test_ena_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            ENA_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(ENA_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 20)

    def test_gve_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            GVE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(GVE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 15)

    def test_liquidio_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            LIQUIDIO_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(LIQUIDIO_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 31)

    def test_libkern_crc_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            LIBKERN_CRC_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(LIBKERN_CRC_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 2)

    def test_oce_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            OCE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(OCE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 15)

    def test_qlxgb_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            QLXGB_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(QLXGB_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 15)

    def test_sfxge_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            SFXGE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(SFXGE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 79)

    def test_qlxgbe_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            QLXGBE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(QLXGBE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 20)

    def test_iwm_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IWM_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IWM_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 38)

    def test_net80211_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            NET80211_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(NET80211_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 43)

    def test_iwx_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IWX_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IWX_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 5)

    def test_iwi_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IWI_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IWI_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 4)

    def test_iwn_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            IWN_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(IWN_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 7)

    def test_bwi_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            BWI_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(BWI_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 11)

    def test_wpi_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            WPI_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(WPI_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 4)

    def test_usb_core_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            USB_CORE_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(USB_CORE_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 52)

    def test_usb_audio_source_tree_matches(self) -> None:
        digest, count = verify_manifest_sources(
            USB_AUDIO_MANIFEST_PATH, REPO_ROOT
        )
        manifest = load_manifest(USB_AUDIO_MANIFEST_PATH)
        self.assertEqual(digest, manifest["source_lock"]["tree_sha256"])
        self.assertEqual(count, 7)

    def test_locked_sources_have_only_allowed_licenses(self) -> None:
        licenses = verify_manifest_licenses(MANIFEST_PATH, REPO_ROOT)
        self.assertEqual(sum(licenses.values()), 48)
        self.assertEqual(set(licenses), {"BSD-2-Clause", "BSD-3-Clause"})
        iflib_licenses = verify_manifest_licenses(
            IFLIB_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(iflib_licenses, {"BSD-2-Clause": 3})
        igc_licenses = verify_manifest_licenses(
            IGC_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            igc_licenses, {"BSD-2-Clause": 3, "BSD-3-Clause": 16}
        )
        aq_licenses = verify_manifest_licenses(
            AQ_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(aq_licenses, {"BSD-2-Clause": 18})
        bce_licenses = verify_manifest_licenses(
            BCE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            bce_licenses, {"BSD-2-Clause": 2, "BSD-3-Clause": 1}
        )
        bxe_licenses = verify_manifest_licenses(
            BXE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(bxe_licenses, {"BSD-2-Clause": 24})
        ena_licenses = verify_manifest_licenses(
            ENA_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            ena_licenses,
            {"BSD-2-Clause": 10, "BSD-3-Clause": 10},
        )
        gve_licenses = verify_manifest_licenses(
            GVE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(gve_licenses, {"BSD-3-Clause": 15})
        liquidio_licenses = verify_manifest_licenses(
            LIQUIDIO_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(liquidio_licenses, {"BSD-2-Clause": 31})
        crc_licenses = verify_manifest_licenses(
            LIBKERN_CRC_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            crc_licenses,
            {"LicenseRef-Gary-S-Brown-Unrestricted": 2},
        )
        oce_licenses = verify_manifest_licenses(
            OCE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            oce_licenses,
            {"BSD-3-Clause": 14, "Public-Domain": 1},
        )
        qlxgb_licenses = verify_manifest_licenses(
            QLXGB_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(qlxgb_licenses, {"BSD-2-Clause": 15})
        qlxgbe_licenses = verify_manifest_licenses(
            QLXGBE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(qlxgbe_licenses, {"BSD-2-Clause": 20})
        sfxge_licenses = verify_manifest_licenses(
            SFXGE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(sfxge_licenses, {"BSD-2-Clause": 79})
        iwm_licenses = verify_manifest_licenses(
            IWM_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(iwm_licenses, {"BSD-2-Clause": 14, "ISC": 24})
        iwx_licenses = verify_manifest_licenses(
            IWX_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            iwx_licenses,
            {
                "(GPL-2.0-only OR BSD-3-Clause) AND ISC": 2,
                "BSD-2-Clause": 2,
                "GPL-2.0-only OR BSD-3-Clause": 1,
            },
        )
        net80211_licenses = verify_manifest_licenses(
            NET80211_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            net80211_licenses,
            {
                "BSD-2-Clause": 39,
                "BSD-3-Clause": 1,
                "ISC": 1,
                "Public-Domain": 2,
            },
        )
        ipw_licenses = verify_manifest_licenses(
            IPW_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(ipw_licenses, {"BSD-2-Clause": 3})
        malo_licenses = verify_manifest_licenses(
            MALO_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(malo_licenses, {"BSD-2-Clause": 6})
        otus_licenses = verify_manifest_licenses(
            OTUS_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(otus_licenses, {"ISC": 2})
        usb_wlan_licenses = verify_manifest_licenses(
            USB_WLAN_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            usb_wlan_licenses,
            {
                "(BSD-2-Clause AND BSD-1-Clause)": 1,
                "BSD-3-Clause": 1,
                "ISC": 24,
            },
        )
        mpi3mr_licenses = verify_manifest_licenses(
            MPI3MR_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            mpi3mr_licenses,
            {"BSD-2-Clause": 7, "BSD-2-Clause-FreeBSD": 12},
        )
        vmxnet3_licenses = verify_manifest_licenses(
            VMXNET3_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(vmxnet3_licenses, {"ISC": 3})
        usb_audio_licenses = verify_manifest_licenses(
            USB_AUDIO_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            usb_audio_licenses,
            {"BSD-2-Clause": 7},
        )
        usb_core_licenses = verify_manifest_licenses(
            USB_CORE_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(
            usb_core_licenses,
            {"BSD-2-Clause": 50, "BSD-3-Clause": 2},
        )

    def test_linuxkpi_and_drm_kmod_license_inventories_are_audited(self) -> None:
        linuxkpi_licenses = verify_manifest_licenses(
            LINUXKPI_HEADERS_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(linuxkpi_licenses["LicenseRef-Upstream-Unmarked"], 141)
        drm_kmod_licenses = verify_manifest_licenses(
            DRM_KMOD_HEADERS_MANIFEST_PATH, REPO_ROOT
        )
        self.assertEqual(drm_kmod_licenses["LicenseRef-Upstream-Unmarked"], 2239)
        self.assertEqual(
            verify_manifest_licenses(DRM_I915_MANIFEST_PATH, REPO_ROOT),
            {
                "GPL-2.0": 1,
                "GPL-2.0-only": 1,
                "LicenseRef-Upstream-Unmarked": 101,
                "MIT": 548,
            },
        )
        self.assertEqual(
            verify_manifest_licenses(DRM_AMDGPU_MANIFEST_PATH, REPO_ROOT),
            {
                "GPL-2.0 OR MIT": 4,
                "GPL-2.0+": 1,
                "LicenseRef-Upstream-Unmarked": 1958,
                "MIT": 80,
            },
        )
        self.assertEqual(
            verify_manifest_licenses(
                LINUXKPI_RUNTIME_SLICE_MANIFEST_PATH, REPO_ROOT
            ),
            {
                "(GPL-2.0-only OR BSD-3-Clause)": 1,
                "BSD-2-Clause": 40,
                "MIT": 2,
                "Public-Domain": 2,
            },
        )

    def test_unmarked_source_requires_explicit_manifest_policy(self) -> None:
        manifest = json.loads(
            LINUXKPI_HEADERS_MANIFEST_PATH.read_text(encoding="utf-8")
        )
        manifest["source_policy"]["allow_unmarked_files"] = False
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "freebsd-linuxkpi-headers.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ManifestError, "locked source has no auditable license"
            ):
                verify_manifest_licenses(path, REPO_ROOT)

    def test_vendored_source_tree_is_fully_covered(self) -> None:
        manifest_paths = [
            *sorted(MANIFEST_DIR.glob("*.json")),
            *sorted(VMM_MANIFEST_DIR.glob("*.json")),
        ]
        coverage = verify_vendored_source_coverage(
            manifest_paths, REPO_ROOT
        )
        self.assertEqual(
            coverage["src/compat/freebsd/upstream"],
            sum(
                1
                for path in (
                    REPO_ROOT / "src/compat/freebsd/upstream"
                ).rglob("*")
                if path.is_file()
                and path.name not in {".DS_Store", "README.md"}
            ),
        )

    def test_vendored_source_coverage_ignores_host_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            upstream = repo_root / "upstream"
            nested = upstream / "sys/dev/example"
            nested.mkdir(parents=True)
            (nested / "driver.c").write_text("driver\n", encoding="utf-8")
            (upstream / ".DS_Store").write_bytes(b"root metadata")
            (nested / ".DS_Store").write_bytes(b"nested metadata")

            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            manifest["id"] = "freebsd-example"
            manifest["upstream"]["root"] = "upstream"
            manifest["source_lock"]["paths"] = ["sys/dev/example/driver.c"]
            manifest["modules"][0]["sources"] = [
                "sys/dev/example/driver.c"
            ]
            manifest_path = repo_root / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            coverage = verify_vendored_source_coverage(
                [manifest_path], repo_root
            )

        self.assertEqual(coverage, {"upstream": 1})

    def test_interface_generation_runs_in_temporary_directory(self) -> None:
        generated = generate_interfaces(MANIFEST_PATH, None, REPO_ROOT)
        self.assertEqual(len(generated), 14)
        self.assertIn(Path("device_if.h"), generated)
        self.assertIn(Path("fb_if.h"), generated)
        self.assertIn(Path("pci_if.c"), generated)
        self.assertIn(Path("virtio_if.h"), generated)
        self.assertIn(Path("virtio_pci_if.c"), generated)

    def test_usb_database_generation_runs_in_temporary_directory(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["generated_databases"] = ["usbdevs"]
        manifest["source_lock"]["paths"].extend(
            [
                "sys/dev/usb/usbdevs",
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "usb-generation.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            generated = generate_interfaces(path, None, REPO_ROOT)
        self.assertIn(Path("usbdevs.h"), generated)
        self.assertIn(Path("usbdevs_data.h"), generated)

    def test_mii_database_generation_runs_in_temporary_directory(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["generated_databases"] = ["miidevs"]
        manifest["source_lock"]["paths"].append("sys/dev/mii/miidevs")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mii-generation.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            generated = generate_interfaces(path, None, REPO_ROOT)
        self.assertIn(Path("miidevs.h"), generated)

    def test_mii_database_generation_preserves_phy_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "miidevs"
            source.write_text(
                "oui EXAMPLE 0x123456 Example Vendor\n"
                "model EXAMPLE PHY 0x2a Example PHY\n",
                encoding="utf-8",
            )
            generated = generate_miidevs_header(source, root / "generated")
            header = generated[0].read_text(encoding="utf-8")
        self.assertIn("#define MII_OUI_EXAMPLE 0x123456", header)
        self.assertIn("#define MII_MODEL_EXAMPLE_PHY 0x2a", header)
        self.assertIn('#define MII_STR_EXAMPLE_PHY "Example PHY"', header)

    def test_mii_database_rejects_unknown_oui(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "miidevs"
            source.write_text(
                "oui EXAMPLE 0x123456 Example Vendor\n"
                "model MISSING PHY 0x01 Missing PHY\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ManifestError, "models reference missing OUIs"
            ):
                parse_miidevs(source)

    def test_usb_core_interface_generation_is_complete(self) -> None:
        generated = generate_interfaces(
            USB_CORE_MANIFEST_PATH, None, REPO_ROOT
        )
        self.assertEqual(len(generated), 4)
        self.assertIn(Path("usb_if.c"), generated)
        self.assertIn(Path("usb_if.h"), generated)
        self.assertIn(Path("usbdevs.h"), generated)
        self.assertIn(Path("usbdevs_data.h"), generated)

    def test_usb_database_generation_accepts_identical_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "usbdevs"
            source.write_text(
                "vendor EXAMPLE 0x1234 Example Vendor\n"
                "vendor EXAMPLE 0x1234 Alternate Description\n"
                "product EXAMPLE DEVICE 0x5678 Example Device\n"
                "product EXAMPLE DEVICE 0x5678 Alternate Description\n",
                encoding="utf-8",
            )
            generated = generate_usbdevs_headers(source, root / "generated")
            header = generated[0].read_text(encoding="utf-8")
            data_header = generated[1].read_text(encoding="utf-8")
        self.assertEqual(header.count("#define USB_VENDOR_EXAMPLE "), 1)
        self.assertEqual(
            header.count("#define USB_PRODUCT_EXAMPLE_DEVICE "), 1
        )
        self.assertIn('"Example Vendor"', data_header)
        self.assertIn('"Example Device"', data_header)
        self.assertNotIn("Alternate Description", data_header)

    def test_usb_database_generation_accepts_product_without_description(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "usbdevs"
            source.write_text(
                "vendor EXAMPLE 0x1234 Example Vendor\n"
                "product EXAMPLE DEVICE 0x5678\n",
                encoding="utf-8",
            )
            generated = generate_usbdevs_headers(source, root / "generated")
            data_header = generated[1].read_text(encoding="utf-8")
        self.assertIn('        "",', data_header)

    def test_usb_database_generation_rejects_conflicting_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "usbdevs"
            source.write_text(
                "vendor EXAMPLE 0x1234 Example Vendor\n"
                "product EXAMPLE DEVICE 0x5678 Example Device\n"
                "product EXAMPLE DEVICE 0x5679 Conflicting Device\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ManifestError, "conflicts with product EXAMPLE_DEVICE"
            ):
                parse_usbdevs(source)

    def test_usb_database_requires_locked_generator_inputs(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["generated_databases"] = ["usbdevs"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid-usb-generation.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ManifestError, "requires locked paths"
            ):
                load_manifest(path)

    def test_dependency_inventory_covers_every_module(self) -> None:
        manifest = load_manifest(MANIFEST_PATH)
        inventory = dependency_inventory(MANIFEST_PATH, REPO_ROOT)
        self.assertEqual(
            set(inventory), {module["id"] for module in manifest["modules"]}
        )
        self.assertTrue(
            all(not details["missing_declarations"] for details in inventory.values())
        )
        self.assertIn("virtio", inventory["virtio-core"]["observed_capabilities"])
        self.assertIn("network", inventory["virtio-network"]["observed_capabilities"])

    def test_manifest_rejects_parent_path(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["modules"][0]["sources"][0] = "../outside.c"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_headers_package_rejects_runtime_modules(self) -> None:
        manifest = json.loads(
            BASE_HEADERS_MANIFEST_PATH.read_text(encoding="utf-8")
        )
        manifest["modules"] = [
            {
                "id": "invalid",
                "sources": ["sys/sys/types.h"],
                "capabilities": ["base"],
                "build": {"mode": "builtin"},
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "must be empty"):
                load_manifest(path)

    def test_catalog_rejects_enabled_module_with_unavailable_capability(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        registry = json.loads(CAPABILITY_PATH.read_text(encoding="utf-8"))
        registry["capabilities"]["ifnet"]["status"] = "unsupported"
        registry["capabilities"]["ifnet"]["architectures"] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests = root / "manifests"
            capabilities = root / "capabilities"
            manifests.mkdir()
            capabilities.mkdir()
            (manifests / "freebsd-virtio.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            (capabilities / "freebsd.json").write_text(
                json.dumps(registry), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ManifestError, "virtio-network requires ifnet, which is unsupported"
            ):
                load_catalog(manifests, capabilities)

    def test_build_plan_supports_multisource_loadable_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_dir = Path(temporary) / "manifests"
            shutil.copytree(MANIFEST_DIR, manifest_dir)
            manifest_path = manifest_dir / "freebsd-iflib.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            module = next(
                module for module in manifest["modules"]
                if module["id"] == "iflib-core"
            )
            module["build"] = {"mode": "module"}
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )

            plan = render_build_plan(manifest_dir, CAPABILITY_DIR)

        self.assertIn(
            "BSD_BRIDGE_MODULE_FREEBSD_IFLIB_IFLIB_CORE_X86_OBJS := \\",
            plan,
        )
        self.assertIn(
            "freebsd-iflib--iflib-core/net/iflib.o",
            plan,
        )
        self.assertIn(
            "freebsd-iflib--iflib-core/net/mp_ring.o",
            plan,
        )
        self.assertIn(
            "$(LD) -r $^ -o $@",
            plan,
        )
        self.assertIn(
            "BSD_BRIDGE_MODULE_FREEBSD_IFLIB_IFLIB_CORE_ARM64_BCS := \\",
            plan,
        )
        self.assertIn(
            "freebsd-iflib--iflib-core/net/iflib.bc",
            plan,
        )
        self.assertIn(
            "freebsd-iflib--iflib-core/net/mp_ring.bc",
            plan,
        )
        self.assertIn(
            "$(LLVM_LINK) $^ -o $@",
            plan,
        )

    def test_module_export_parser_ignores_macro_parameters(self) -> None:
        exports = load_exports(
            REPO_ROOT / "src/compat/freebsd/kern/driver_symbols.c"
        )
        self.assertGreater(len(exports), 0)
        self.assertNotIn("symbol", exports)
        self.assertIn("module_register_init", exports)
        self.assertIn("OF_getprop", exports)
        self.assertIn("ofw_bus_is_compatible", exports)
        self.assertIn("ofw_bus_lookup_imap", exports)
        self.assertIn("ofw_bus_msimap", exports)
        self.assertIn("ofw_bus_iommu_map", exports)
        self.assertIn("memmap_bus", exports)

    def test_manifest_rejects_unsafe_definition(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["compile"]["definitions"] = ["VALUE=$(shell false)"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ManifestError):
                load_manifest(path)

    def test_manifest_rejects_unsupported_include_group(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["compile"]["include_groups"] = ["unknown"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ManifestError, "unsupported groups: unknown"
            ):
                load_manifest(path)

    def test_manifest_rejects_patched_policy_without_patch_audit(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["source_policy"]["mode"] = "patched"
        manifest["source_policy"]["allow_inline_patches"] = True
        manifest["source_policy"]["patches"] = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ManifestError, "non-empty patches array"
            ):
                load_manifest(path)

    def test_manifest_rejects_patch_outside_source_lock(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest["source_policy"]["mode"] = "patched"
        manifest["source_policy"]["allow_inline_patches"] = True
        manifest["source_policy"]["patches"] = [
            {
                "path": "sys/dev/not-locked.c",
                "upstream_sha256": "0" * 64,
                "reason": "Test-only audited source adjustment.",
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ManifestError, "not covered by source_lock.paths"
            ):
                load_manifest(path)

    def test_usb_wlan_patch_is_audited(self) -> None:
        manifest = load_manifest(USB_WLAN_MANIFEST_PATH)
        self.assertEqual(manifest["source_policy"]["mode"], "patched")
        self.assertTrue(manifest["source_policy"]["allow_inline_patches"])
        patches = manifest["source_policy"]["patches"]
        self.assertEqual(len(patches), 1)
        self.assertEqual(
            patches[0]["path"], "sys/dev/usb/wlan/if_mtwvar.h"
        )
        source = (
            REPO_ROOT
            / manifest["upstream"]["root"]
            / patches[0]["path"]
        )
        self.assertNotEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            patches[0]["upstream_sha256"],
        )
        text = source.read_text(encoding="utf-8")
        self.assertIn("sc_epq[MTW_EP_QUEUES]", text)
        self.assertNotIn("sc_epq[MTW_BULK_RX]", text)

    def test_package_creator_builds_a_locked_unmodified_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "freebsd-random-example.json"
            manifest = create_package_manifest(
                repo_root=REPO_ROOT,
                template_path=MANIFEST_PATH,
                capability_path=CAPABILITY_PATH,
                package_id="freebsd-random-example",
                module_id="random-example",
                description="Generated test package.",
                sources=["sys/dev/virtio/random/virtio_random.c"],
                lock_paths=[],
                capabilities=[],
                definitions=["RANDOM_EXAMPLE=1"],
                interfaces=[],
                mode="builtin",
                reason=None,
                license_exception_values=[],
                allow_unmarked_files=False,
                allowed_license_values=[],
            )
            write_manifest(output, manifest, False)
            loaded = load_manifest(output)
            self.assertEqual(loaded["source_policy"]["mode"], "unmodified")
            self.assertEqual(loaded["source_lock"]["file_count"], 1)
            self.assertEqual(
                loaded["modules"][0]["sources"],
                ["sys/dev/virtio/random/virtio_random.c"],
            )
            self.assertIn("random", loaded["modules"][0]["capabilities"])
            self.assertEqual(loaded["modules"][0]["build"]["mode"], "builtin")

    def test_package_creator_locks_additional_headers(self) -> None:
        manifest = create_package_manifest(
            repo_root=REPO_ROOT,
            template_path=MANIFEST_PATH,
            capability_path=CAPABILITY_PATH,
            package_id="freebsd-random-header-example",
            module_id="random-header-example",
            description="Generated header lock test package.",
            sources=["sys/dev/virtio/random/virtio_random.c"],
            lock_paths=["sys/dev/virtio/virtio.h"],
            capabilities=[],
            definitions=[],
            interfaces=[],
            mode="builtin",
            reason=None,
            license_exception_values=[],
            allow_unmarked_files=False,
            allowed_license_values=[],
        )

        self.assertEqual(
            manifest["source_lock"]["paths"],
            [
                "sys/dev/virtio/random/virtio_random.c",
                "sys/dev/virtio/virtio.h",
            ],
        )
        self.assertEqual(manifest["source_lock"]["file_count"], 2)

    def test_package_creator_accepts_permitted_spdx_conjunction(self) -> None:
        allowed = {"BSD-1-Clause", "BSD-2-Clause", "BSD-3-Clause", "ISC"}

        self.assertTrue(
            _license_expression_is_covered(
                "(BSD-2-Clause AND BSD-1-Clause)", allowed
            )
        )
        self.assertFalse(
            _license_expression_is_covered(
                "(BSD-2-Clause AND GPL-2.0-only)", allowed
            )
        )
        self.assertTrue(
            _license_expression_is_covered(
                "GPL-2.0+ OR BSD-3-Clause", allowed
            )
        )
        self.assertTrue(
            _license_expression_is_covered(
                "(GPL-2.0-only OR BSD-3-Clause)", allowed
            )
        )
        self.assertFalse(
            _license_expression_is_covered(
                "GPL-2.0-only OR MIT", allowed
            )
        )

    def test_package_creator_accepts_capability_architecture_superset(self) -> None:
        manifest = create_package_manifest(
            repo_root=REPO_ROOT,
            template_path=MANIFEST_DIR / "freebsd-cyapa.json",
            capability_path=CAPABILITY_PATH,
            package_id="freebsd-cyapa-architecture-example",
            module_id="cyapa-architecture-example",
            description="Generated architecture compatibility test package.",
            sources=["sys/dev/cyapa/cyapa.c"],
            lock_paths=["sys/dev/cyapa/cyapa.h"],
            capabilities=["base"],
            definitions=[],
            interfaces=[],
            mode="builtin",
            reason=None,
            license_exception_values=[],
            allow_unmarked_files=False,
            allowed_license_values=[],
        )

        self.assertEqual(manifest["architectures"], ["x86_64"])
        self.assertIn("base", manifest["modules"][0]["capabilities"])

    def test_package_creator_validates_before_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package.json"
            output.write_text("preserve existing file\n", encoding="utf-8")
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            manifest["schema_version"] = 999

            with self.assertRaisesRegex(ManifestError, "schema_version"):
                write_manifest(output, manifest, True)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "preserve existing file\n",
            )
            self.assertEqual(
                list(output.parent.glob(f".{output.name}.*")),
                [],
            )

    def test_license_detector_rejects_advertising_clause_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.c"
            path.write_text(
                "Redistribution and use in source and binary forms\n"
                "3. All advertising materials mentioning features or use\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_source_license(path), "BSD-4-Clause")

    def test_license_detector_accepts_isc_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "permissive.c"
            path.write_text(
                "Permission to use, copy, modify, and distribute this software for any\n"
                "purpose with or without fee is hereby granted.\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_source_license(path), "ISC")

    def test_license_detector_accepts_public_domain_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "public_domain.c"
            path.write_text(
                "This file is placed in the public domain by its author.\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_source_license(path), "Public-Domain")

    def test_source_digest_is_path_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").mkdir()
            (root / "one/file.c").write_text("same\n", encoding="utf-8")
            first, first_count = source_tree_digest(root, ["one"])
            (root / "one/file.c").rename(root / "one/renamed.c")
            second, second_count = source_tree_digest(root, ["one"])
            self.assertEqual(first_count, second_count)
            self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
