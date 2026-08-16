#!/usr/bin/env python3
import argparse
import gzip
import os
import stat
import time
from pathlib import Path


CPIO_TRAILER = "TRAILER!!!"


def align4(n: int) -> int:
    return (4 - (n & 3)) & 3


class NewcWriter:
    def __init__(self, out_path: Path):
        self.out_path = out_path
        self.entries = []
        self.ino = 1

    def add_dir(self, name: str, mode: int = 0o755):
        self.entries.append((name.strip("/"), stat.S_IFDIR | mode, b"", "", 0, 0))

    def add_file(self, name: str, data: bytes, mode: int = 0o644):
        self.entries.append((name.strip("/"), stat.S_IFREG | mode, data, "", 0, 0))

    def add_symlink(self, name: str, target: str):
        self.entries.append((name.strip("/"), stat.S_IFLNK | 0o777, target.encode(), "", 0, 0))

    def add_chrdev(self, name: str, major: int, minor: int, mode: int = 0o600):
        self.entries.append((name.strip("/"), stat.S_IFCHR | mode, b"", "", major, minor))

    def write_entry(self, gz, name: str, mode: int, data: bytes, rmajor: int, rminor: int):
        encoded_name = name.encode() + b"\0"
        fields = [
            "070701",
            f"{self.ino:08x}",
            f"{mode:08x}",
            "00000000",
            "00000000",
            "00000001",
            f"{int(time.time()):08x}",
            f"{len(data):08x}",
            "00000000",
            "00000000",
            f"{rmajor:08x}",
            f"{rminor:08x}",
            f"{len(encoded_name):08x}",
            "00000000",
        ]
        self.ino += 1
        header = "".join(fields).encode()
        gz.write(header)
        gz.write(encoded_name)
        gz.write(b"\0" * align4(len(header) + len(encoded_name)))
        gz.write(data)
        gz.write(b"\0" * align4(len(data)))

    def finish(self):
        with gzip.open(self.out_path, "wb", compresslevel=9) as gz:
            for name, mode, data, _target, rmajor, rminor in self.entries:
                self.write_entry(gz, name, mode, data, rmajor, rminor)
            self.write_entry(gz, CPIO_TRAILER, stat.S_IFREG, b"", 0, 0)


def read_modules_dep(modules_dir: Path):
    dep_file = modules_dir / "modules.dep"
    deps = {}
    if not dep_file.exists():
        return deps
    for line in dep_file.read_text().splitlines():
        if not line.strip() or ":" not in line:
            continue
        module, rest = line.split(":", 1)
        deps[module] = [part for part in rest.split() if part]
    return deps


def resolve_modules(modules_dir: Path, wanted_names):
    deps = read_modules_dep(modules_dir)
    by_name = {}
    for module in deps:
        by_name[Path(module).name] = module

    selected = []
    seen = set()

    def visit(module):
        if module in seen:
            return
        seen.add(module)
        for dep in deps.get(module, []):
            visit(dep)
        selected.append(module)

    missing = []
    for name in wanted_names:
        module = by_name.get(name)
        if module is None:
            missing.append(name)
            continue
        visit(module)
    if missing:
        raise SystemExit(f"missing required modules: {', '.join(missing)}")
    return selected


def read_maybe_gzip(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix == ".gz":
        return gzip.decompress(data)
    return data


def add_parent_dirs(writer: NewcWriter, added_dirs: set[str], path: str):
    cur = ""
    for part in Path(path).parent.parts:
        if part in ("", "/"):
            continue
        cur = f"{cur}/{part}" if cur else part
        if cur not in added_dirs:
            writer.add_dir(cur)
            added_dirs.add(cur)


def main():
    ap = argparse.ArgumentParser(description="Build an arm64 Linux initramfs for EdgeOS Alpine rootfs boot")
    ap.add_argument("--rootfs-dir", required=True)
    ap.add_argument("--modules-dir", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--root-device", default="/dev/vdb")
    args = ap.parse_args()

    rootfs = Path(args.rootfs_dir)
    modules_dir = Path(args.modules_dir)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    release = modules_dir.name
    writer = NewcWriter(out_path)
    added_dirs = set()
    for d in ("bin", "sbin", "dev", "etc", "lib", "proc", "sys", "newroot"):
        writer.add_dir(d)
        added_dirs.add(d)

    writer.add_chrdev("dev/console", 5, 1)
    writer.add_chrdev("dev/null", 1, 3, 0o666)

    busybox = rootfs / "bin/busybox"
    loader = rootfs / "lib/ld-musl-aarch64.so.1"
    writer.add_file("bin/busybox", busybox.read_bytes(), 0o755)
    writer.add_file("lib/ld-musl-aarch64.so.1", loader.read_bytes(), 0o755)

    for applet in (
        "cat", "chroot", "echo", "insmod", "mkdir", "mount", "mdev", "sh",
        "sleep", "switch_root", "umount",
    ):
        writer.add_symlink(f"bin/{applet}", "busybox")
        writer.add_symlink(f"sbin/{applet}", "../bin/busybox")

    wanted = (
        "virtio_mmio.ko.gz",
        "virtio_pci.ko.gz",
        "virtio_blk.ko.gz",
        "mbcache.ko.gz",
        "jbd2.ko.gz",
        "ext4.ko.gz",
        "simpledrm.ko.gz",
        "virtio-gpu.ko.gz",
    )
    selected = resolve_modules(modules_dir, wanted)
    module_load_paths = []
    for module in selected:
        src = modules_dir / module
        dst = f"lib/modules/{release}/{module}"
        if dst.endswith(".gz"):
            dst = dst[:-3]
        add_parent_dirs(writer, added_dirs, dst)
        writer.add_file(dst, read_maybe_gzip(src), 0o644)
        module_load_paths.append("/" + dst)

    writer.add_file("etc/modules.load", ("\n".join(module_load_paths) + "\n").encode(), 0o644)
    init = f"""#!/bin/sh
export PATH=/bin:/sbin
echo "[initramfs] EdgeOS arm64 real boot"
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t proc proc /proc
mount -t sysfs sysfs /sys
while read module; do
    [ -n "$module" ] || continue
    echo "[initramfs] insmod $module"
    insmod "$module" || echo "[initramfs] failed: $module"
done < /etc/modules.load
echo /sbin/mdev > /proc/sys/kernel/hotplug 2>/dev/null || true
mdev -s 2>/dev/null || true
i=0
while [ ! -b "{args.root_device}" ] && [ "$i" -lt 200 ]; do
    sleep 0.1
    mdev -s 2>/dev/null || true
    i=$((i + 1))
done
echo "[initramfs] mounting Alpine rootfs {args.root_device}"
mount -t ext4 -o rw "{args.root_device}" /newroot || exec sh
mkdir -p /newroot/dev /newroot/proc /newroot/sys /newroot/run
mount --move /dev /newroot/dev || mount -t devtmpfs devtmpfs /newroot/dev
mount --move /proc /newroot/proc
mount --move /sys /newroot/sys
echo "[initramfs] switch_root -> Alpine /sbin/init"
exec switch_root /newroot /sbin/init
echo "[initramfs] switch_root failed"
exec sh
"""
    writer.add_file("init", init.encode(), 0o755)
    writer.finish()
    print(f"[initramfs] wrote {out_path}")
    print("[initramfs] modules:")
    for module in module_load_paths:
        print(f"  {module}")


if __name__ == "__main__":
    main()
