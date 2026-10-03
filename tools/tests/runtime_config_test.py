#!/usr/bin/env python3
"""Verify runtime Kconfig defaults and generated C capacity overrides."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/kconfig/vendor/kconfiglib"))
import kconfiglib

DEFAULTS = {
    "PIPE_CAPACITY": 65536,
    "IO_URING_RINGS": 64,
    "KEY_OBJECTS": 256,
    "KEY_TASKS": 2048,
    "DRM_BUFFERS": 64,
    "FRAMEBUFFER_BYTES": 16777216,
    "TMPFS_BLOCK_ORDER": 18,
    "MAX_TASKS": 4096,
    "MAX_OPEN_FILES": 1024,
    "MAX_PIPES": 1024,
    "MAX_SOCKETS": 4096,
    "MAX_EVENTFDS": 1024,
    "MAX_TIMERFDS": 128,
    "MAX_SIGNALFDS": 128,
    "MAX_INOTIFY_INSTANCES": 128,
    "MAX_INOTIFY_WATCHES": 512,
    "MAX_FANOTIFY_GROUPS": 32,
    "MAX_FANOTIFY_MARKS": 512,
    "MAX_USERFAULTFDS": 64,
    "MAX_USERFAULTFD_RANGES": 256,
    "MAX_PERF_EVENTS": 128,
    "MAX_BPF_OBJECTS": 128,
    "MAX_BPF_ATTACHMENTS": 256,
    "MAX_QUOTA_FILESYSTEMS": 32,
    "MAX_QUOTA_ENTRIES": 512,
    "MAX_FUSE_SESSIONS": 256,
    "SIGNAL_QUEUE_SIZE": 16384,
    "MAX_EPOLL_IDS": 4096,
    "MAX_EPOLL_WATCHES": 1048576,
    "SOCKET_BACKLOG": 128
}


class RuntimeConfigurationTests(unittest.TestCase):
    def config(self, arch):
        os.environ["srctree"] = str(ROOT)
        config = kconfiglib.Kconfig(str(ROOT / "Kconfig"), warn=True, warn_to_stderr=False)
        config.load_config(str(ROOT / ("arch/x86/configs/x86_64_defconfig"
            if arch == "x86" else "arch/arm64/configs/arm64_defconfig")))
        return config

    def test_defaults_preserve_full_profiles(self):
        for arch in ("x86", "arm64"):
            config = self.config(arch)
            self.assertEqual(config.syms["DEVTMPFS_MOUNT"].str_value, "n")
            for name, expected in DEFAULTS.items():
                self.assertEqual(int(config.syms["RUNTIME_" + name].str_value), expected)

    def test_overrides_reach_c_on_both_architectures(self):
        for arch in ("x86", "arm64"):
            config = self.config(arch)
            for name in DEFAULTS:
                config.syms["RUNTIME_" + name].set_value("32")
            with tempfile.TemporaryDirectory() as directory:
                header = Path(directory) / "autoconf.h"
                config.write_autoconf(str(header))
                checks = '#include "kernel/runtime_limits.h"\n'
                for name in DEFAULTS:
                    expected = config.syms["RUNTIME_" + name].str_value
                    checks += f'_Static_assert(EDGE_RUNTIME_{name} == {expected}, "{name}");\n'
                subprocess.run(["clang", "-x", "c", "-std=c11", "-fsyntax-only",
                    "-I", str(ROOT / "include"), "-include", str(header), "-"],
                    input=checks, text=True, check=True)

    def test_out_of_range_values_do_not_take_effect(self):
        config = self.config("x86")
        for name, expected in DEFAULTS.items():
            symbol = config.syms["RUNTIME_" + name]
            symbol.set_value("0")
            self.assertEqual(int(symbol.str_value), expected)
        self.assertEqual(config.syms["X86_KERNEL_LOAD_ADDRESS"].str_value, "0x08000000")
        config.syms["X86_KERNEL_LOAD_ADDRESS"].set_value("0x00100000")
        self.assertEqual(config.syms["X86_KERNEL_LOAD_ADDRESS"].str_value, "0x00100000")

    def test_minimal_profiles_resolve_without_warnings(self):
        for arch, name in (("x86", "x86_64"), ("arm64", "arm64")):
            config = self.config(arch)
            config.load_config(str(ROOT / f"arch/{arch}/configs/{name}_buildroot_defconfig"))
            self.assertFalse(config.warnings)
            self.assertEqual(config.syms["RUNTIME_MAX_TASKS"].str_value, "32")
            self.assertEqual(config.syms["RUNTIME_EXEC_ARGUMENT_BYTES"].str_value, "131072")
            self.assertEqual(config.syms["DEVTMPFS_MOUNT"].str_value, "y")
            self.assertEqual(config.syms["VIRTIO_NET"].str_value, "y")
            self.assertEqual(config.syms["FS_EXT4"].str_value, "y")
            self.assertEqual(config.syms["BSD_DRIVER_BRIDGE"].str_value, "n")

    def test_mapping_defaults_and_small_profile(self):
        expected = {"PHYSICAL_POOL_MIB": "8192", "MAPPED_FILES": "4096",
                    "FILE_CACHE_ORDER": "18", "MEMFD_OBJECTS": "128",
                    "FILE_DESCRIPTION_ORDER": "15", "OVERLAY_INITIAL_CONTEXTS": "16",
                    "RIGHTS_RECORDS": "8192", "MQ_MESSAGES": "512",
                    "ARM64_MAPPING_ORDER": "22", "CGROUP_NODES": "4096",
                    "ARM64_VMA_MIN_ORDER": "14", "ARM64_FILE_PAGE_MIN_ORDER": "16",
                    "EXEC_ARGUMENT_BYTES": "2097152"}
        for arch in ("x86", "arm64"):
            config = self.config(arch)
            for name, value in expected.items():
                self.assertEqual(config.syms["RUNTIME_" + name].str_value, value)
        config.load_config(str(ROOT / "arch/x86/configs/x86_64_buildroot_defconfig"))
        self.assertEqual(config.syms["RUNTIME_PHYSICAL_POOL_MIB"].str_value, "128")
        self.assertEqual(config.syms["RUNTIME_MAPPED_FILES"].str_value, "128")
        self.assertEqual(config.syms["RUNTIME_FILE_CACHE_ORDER"].str_value, "10")

    def test_full_firmware_layout_is_preserved(self):
        config = self.config("arm64")
        self.assertEqual(config.syms["ARM64_MATERIALIZE_DATA"].str_value, "y")
        config.load_config(str(ROOT / "arch/arm64/configs/arm64_buildroot_defconfig"))
        self.assertEqual(config.syms["ARM64_MATERIALIZE_DATA"].str_value, "n")

    def test_scheduler_cpu_storage_matches_smp_selection(self):
        for minimal, expected in ((False, 64), (True, 1)):
            config = self.config("x86")
            if minimal:
                config.load_config(str(ROOT / "arch/x86/configs/x86_64_buildroot_defconfig"))
            with tempfile.TemporaryDirectory() as directory:
                header = Path(directory) / "autoconf.h"
                config.write_autoconf(str(header))
                subprocess.run(["clang", "--target=x86_64-unknown-elf", "-x", "c",
                    "-std=c11", "-fno-builtin", "-fsyntax-only", "-I", str(ROOT / "include"),
                    "-include", str(header), "-"], check=True, text=True,
                    input='#include "sys/scheduler.h"\n'
                    f'_Static_assert(SCHED_MAX_CPUS == {expected}, "CPU capacity");\n')

    def test_linker_address_and_alignment(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = Path(directory) / "entry.o"
            binary = Path(directory) / "kernel.elf"
            subprocess.run(["clang", "--target=x86_64-unknown-elf", "-x", "c",
                "-ffreestanding", "-c", "-o", str(obj), "-"],
                input="void _start(void) {}", text=True, check=True)
            for address in ("0x08000000", "0x00100000"):
                subprocess.run(["ld.lld", "--defsym=edge_kernel_load_address=" + address,
                    "-T", str(ROOT / "config/linker.ld"), str(obj), "-o", str(binary)],
                    check=True, capture_output=True)
                symbols = subprocess.check_output(["/opt/homebrew/opt/llvm/bin/llvm-nm",
                    str(binary)], text=True)
                start = next(line.split()[0] for line in symbols.splitlines()
                    if line.endswith(" _kernel_start"))
                self.assertEqual(int(start, 16), int(address, 16))
            result = subprocess.run(["ld.lld", "--defsym=edge_kernel_load_address=0x100001",
                "-T", str(ROOT / "config/linker.ld"), str(obj), "-o", str(binary)],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("page aligned", result.stderr)


if __name__ == "__main__":
    unittest.main()
