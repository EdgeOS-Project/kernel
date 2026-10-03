#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run bounded 128 MiB HVF cold boots using an immutable EFI directory."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("boot_directory", type=Path)
    parser.add_argument("output_prefix", type=Path)
    parser.add_argument("--firmware", required=True, type=Path)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--scratch-image", type=Path, help="Disposable 16 MiB disk; its first sector will be overwritten")
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("This runner requires an ARM64 Mac with HVF")
    volume = Path("/Volumes/EdwardData")
    if not os.path.ismount(volume):
        parser.error("The artifact volume is not mounted")
    boot = args.boot_directory.resolve()
    prefix = args.output_prefix.resolve()
    artifact_root = volume / "EdgeOS"
    if not boot.is_relative_to(artifact_root) or not prefix.is_relative_to(artifact_root):
        parser.error("Boot and output paths must be on the artifact volume")
    if "," in str(boot) or not 1 <= args.count <= 10:
        parser.error("Invalid boot path or repetition count")
    if not args.firmware.is_file() or not (boot / "EFI/BOOT/BOOTAA64.EFI").is_file():
        parser.error("Missing firmware or EFI image")
    probe = Path(__file__).with_name("serial_memory_boot_probe.py")
    extra = []
    if args.scratch_image:
        scratch = args.scratch_image.resolve()
        if not scratch.is_relative_to(artifact_root) or "," in str(scratch) or scratch.stat().st_size != 16777216:
            parser.error("Expected a disposable 16 MiB artifact disk")
        extra = ["-drive", f"if=none,file={scratch},format=raw,id=scratch",
                 "-device", "virtio-blk-device,drive=scratch"]
    for index in range(1, args.count + 1):
        run = f"{prefix}-{index}"
        serial = run + ".sock"
        with open(run + ".qemu.log", "x") as qemu_log, open(run + ".probe.log", "x") as probe_log:
            vm = subprocess.Popen([
                "qemu-system-aarch64", "-machine", "virt,gic-version=3,acpi=off",
                "-accel", "hvf", "-cpu", "host", "-smp", "1", "-m", "128M",
                "-bios", str(args.firmware), "-display", "none", "-nodefaults",
                "-global", "virtio-mmio.force-legacy=false",
                "-drive", f"if=none,file=fat:ro:{boot},format=raw,readonly=on,id=bootdisk",
                "-device", "virtio-blk-device,drive=bootdisk", "-netdev", "user,id=net0",
                "-device", "virtio-net-device,netdev=net0", "-chardev",
                f"socket,id=serial0,path={serial},server=on,wait=off,logfile={run}.serial.log",
                "-serial", "chardev:serial0", "-no-reboot"] + extra,
                stdout=qemu_log, stderr=subprocess.STDOUT)
            try:
                checks = []
                if args.scratch_image:
                    checks = ["--scratch-device", "/dev/vda"]
                    if index > 1:
                        checks.append("--expect-scratch-data")
                subprocess.run([sys.executable, str(probe), serial, "--timeout", "100"] + checks,
                    stdout=probe_log, stderr=subprocess.STDOUT, timeout=110, check=True)
                if vm.wait(timeout=10) != 0:
                    raise RuntimeError("QEMU did not exit successfully")
            finally:
                if vm.poll() is None:
                    vm.terminate()
                    try:
                        vm.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait()
        print(json.dumps({"architecture": "aarch64", "ram_mib": 128,
                          "cold_boot": index, "status": "pass"}), flush=True)


if __name__ == "__main__":
    main()
