#!/usr/bin/env python3
"""Build a reproducible Linux UAPI symbol inventory for EdgeOS."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Iterable


REFERENCE_COMMIT = "2c7c88a412aa6d09cd04b414211b4ef8553b5309"

EDGEOS_ASSESSMENTS = [
    {
        "domain": "io_uring",
        "status": "partial",
        "kconfig": ["IO_URING"],
        "architectures": {
            "x86_64": "runtime-verified",
            "aarch64": "runtime-verified",
            "ia32": "unimplemented",
            "x32": "unimplemented",
        },
        "implemented": [
            "setup and mapped submission/completion rings",
            "NOP, READ, WRITE, READV, WRITEV and FSYNC operations",
            "probe and disabled-ring registration",
            "completion eventfd registration and notification",
            "single-shot poll requests",
            "relative and absolute timeout requests",
            "completion-count timeouts",
            "timeout removal and user-data cancellation",
            "classic and extended temporary signal-mask enter arguments",
            "OPENAT, OPENAT2, CLOSE, STATX and FALLOCATE through shared VFS handlers",
            "SEND, RECV, SENDMSG, RECVMSG and SHUTDOWN through shared socket handlers",
            "CONNECT and ACCEPT through shared socket handlers",
            "FADVISE, MADVISE, EPOLL_CTL and TEE through shared subsystem handlers",
            "RENAMEAT, UNLINKAT, MKDIRAT, SYMLINKAT and LINKAT through shared VFS handlers",
            "SOCKET, BIND and LISTEN through shared socket handlers",
            "FSETXATTR, SETXATTR, FGETXATTR, GETXATTR and FTRUNCATE through shared VFS handlers",
        ],
        "missing": [
            "asynchronous worker execution",
            "fixed files and buffers",
            "multishot poll and timeout update operations",
            "fully interruptible enter suspension and extended wait deadlines",
            "descriptor leases across close and reuse",
            "remaining supported VFS and socket operations",
            "ia32 and x32 compatibility layouts",
        ],
        "runtime_tests": [
            "tools/tests/io_uring_abi_probe.c",
            "tools/tests/io_uring_runtime_unit.c",
        ],
        "linux_oracle": {
            "status": "partial",
            "reference": REFERENCE_COMMIT,
            "scope": (
                "setup, mmap, NOP, eventfd, poll, timeout, cancellation, "
                "openat, openat2, close, statx, fallocate, send, recv, "
                "sendmsg, recvmsg, shutdown, connect, accept, fadvise, "
                "madvise, epoll_ctl, tee, renameat, unlinkat, mkdirat, "
                "symlinkat, linkat, socket, bind, listen, fsetxattr, "
                "setxattr, fgetxattr, getxattr, ftruncate and operation probe"
            ),
        },
    },
]

IOCTL_HEADERS = {
    "tty": ("include/uapi/asm-generic/ioctls.h", "include/uapi/linux/kd.h",
            "include/uapi/linux/tty.h", "include/uapi/linux/vt.h"),
    "input": ("include/uapi/linux/input.h", "include/uapi/linux/hiddev.h",
              "include/uapi/linux/hidraw.h", "include/uapi/linux/uhid.h"),
    "graphics": ("include/uapi/drm/drm.h", "include/uapi/drm/drm_mode.h",
                 "include/uapi/linux/fb.h"),
    "media": ("include/uapi/linux/videodev2.h",),
    "audio": ("include/uapi/sound/asound.h",),
    "usb": ("include/uapi/linux/usbdevice_fs.h",),
    "storage": ("include/uapi/linux/fs.h", "include/uapi/linux/loop.h",
                "include/uapi/linux/dm-ioctl.h", "include/uapi/linux/blkpg.h",
                "include/uapi/linux/cdrom.h", "include/uapi/linux/hdreg.h",
                "include/uapi/linux/nvme_ioctl.h"),
    "network": ("include/uapi/linux/if_tun.h", "include/uapi/linux/ethtool.h",
                "include/uapi/linux/rfkill.h"),
    "platform": ("include/uapi/linux/rtc.h", "include/uapi/linux/watchdog.h",
                 "include/uapi/linux/i2c-dev.h"),
    "events": ("include/uapi/linux/perf_event.h",
               "include/uapi/linux/userfaultfd.h"),
}

SOCKET_HEADERS = (
    "include/uapi/asm-generic/socket.h",
    "include/uapi/linux/in.h",
    "include/uapi/linux/in6.h",
    "include/uapi/linux/tcp.h",
    "include/uapi/linux/udp.h",
    "include/uapi/linux/if_packet.h",
    "include/uapi/linux/netlink.h",
    "include/uapi/linux/filter.h",
)

NETLINK_HEADERS = (
    "include/uapi/linux/rtnetlink.h",
    "include/uapi/linux/if_link.h",
    "include/uapi/linux/if_addr.h",
    "include/uapi/linux/neighbour.h",
    "include/uapi/linux/fib_rules.h",
    "include/uapi/linux/pkt_sched.h",
    "include/uapi/linux/netfilter/nf_tables.h",
    "include/uapi/linux/ethtool_netlink.h",
    "include/uapi/linux/sock_diag.h",
    "include/uapi/linux/inet_diag.h",
)

SOCKET_PREFIXES = ("SO_", "SCM_", "IP_", "IPV6_", "TCP_", "UDP_",
                   "PACKET_", "NETLINK_", "BPF_")
NETLINK_PREFIXES = ("RTM_", "RTN_", "RTA_", "IFLA_", "IFA_", "NDA_",
                    "FRA_", "TCA_", "NFT_", "ETHTOOL_", "SOCK_DIAG_",
                    "INET_DIAG_", "NLMSG_", "NLM_F_")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def logical_lines(text: str) -> Iterable[str]:
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        pending = f"{pending}{line}" if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        yield pending
        pending = ""
    if pending:
        yield pending


def define_symbols(path: Path, prefixes: tuple[str, ...] | None = None,
                   require_ioctl: bool = False) -> list[dict[str, str]]:
    symbols: list[dict[str, str]] = []
    pattern = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$")
    for line in logical_lines(path.read_text(encoding="utf-8", errors="replace")):
        match = pattern.match(line)
        if not match:
            continue
        name, expression = match.groups()
        if prefixes is not None and not name.startswith(prefixes):
            continue
        if require_ioctl and not re.search(r"\b_IO(?:R|W|WR)?\s*\(", expression):
            continue
        symbols.append({"name": name, "expression": expression.strip()})
    return symbols


def enum_symbols(path: Path, prefixes: tuple[str, ...]) -> list[dict[str, str]]:
    symbols: dict[str, dict[str, str]] = {}
    token = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*(?:=\s*([^,]+))?,?\s*(?:/\*.*)?$")
    in_enum = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.search(r"\benum\b[^;]*\{", raw):
            in_enum = True
            continue
        if in_enum and "}" in raw:
            in_enum = False
            continue
        if not in_enum:
            continue
        match = token.match(raw)
        if not match or not match.group(1).startswith(prefixes):
            continue
        name = match.group(1)
        symbols[name] = {
            "name": name,
            "expression": (match.group(2) or "auto").strip(),
        }
    return sorted(symbols.values(), key=lambda item: item["name"])


def syscall_table(path: Path, accepted_abis: set[str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] not in accepted_abis:
            continue
        entries.append({"number": int(fields[0]), "name": fields[2],
                        "abi": fields[1]})
    return entries


def generic_syscalls(path: Path) -> list[dict[str, object]]:
    pattern = re.compile(
        r"^#define\s+__NR(?:3264)?_([A-Za-z0-9_]+)\s+([0-9]+)$"
    )
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            entries.append({"name": match.group(1),
                            "number": int(match.group(2)), "abi": "common"})
    return entries


def git_output(tree: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(tree), *arguments], text=True
    ).strip()


def reference_version(tree: Path) -> str:
    values: dict[str, str] = {}
    pattern = re.compile(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*)$")
    for line in (tree / "Makefile").read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return (f"{values['VERSION']}.{values['PATCHLEVEL']}."
            f"{values['SUBLEVEL']}{values.get('EXTRAVERSION', '')}")


def symbol_domain(tree: Path, headers: Iterable[str], *,
                  prefixes: tuple[str, ...] | None = None,
                  require_ioctl: bool = False,
                  include_enums: bool = False) -> dict[str, object]:
    items: list[dict[str, object]] = []
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for relative in headers:
        path = tree / relative
        if not path.exists():
            raise FileNotFoundError(relative)
        sources.append({"path": relative, "sha256": sha256(path)})
        symbols = define_symbols(path, prefixes, require_ioctl)
        if include_enums and prefixes is not None:
            symbols.extend(enum_symbols(path, prefixes))
        for symbol in symbols:
            key = (relative, symbol["name"])
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "name": symbol["name"],
                "header": relative,
                "expression": symbol["expression"],
            })
    items.sort(key=lambda item: (str(item["name"]), str(item["header"])))
    return {
        "sources": sources,
        "item_defaults": {
            "status": "unreviewed",
            "kconfig": [],
            "architectures": ["x86_64", "aarch64", "ia32", "x32"],
            "runtime_tests": [],
            "linux_oracle": "required",
            "expected_errors": "reference-kernel",
        },
        "items": items,
    }


def build_inventory(tree: Path) -> dict[str, object]:
    commit = git_output(tree, "rev-parse", "HEAD")
    if commit != REFERENCE_COMMIT:
        raise ValueError(
            f"Linux reference commit is {commit}, expected {REFERENCE_COMMIT}"
        )
    x86_table = tree / "arch/x86/entry/syscalls/syscall_64.tbl"
    ia32_table = tree / "arch/x86/entry/syscalls/syscall_32.tbl"
    generic_table = tree / "scripts/syscall.tbl"
    syscall_sources = [x86_table, ia32_table, generic_table]
    syscall_architectures = {
        "x86_64": syscall_table(x86_table, {"common", "64"}),
        "x32": syscall_table(x86_table, {"common", "x32"}),
        "ia32": syscall_table(ia32_table, {"i386"}),
        "aarch64": syscall_table(
            generic_table,
            {"common", "64", "renameat", "rlimit", "memfd_secret"},
        ),
    }
    ioctl_groups = {
        name: symbol_domain(tree, headers, require_ioctl=True)
        for name, headers in IOCTL_HEADERS.items()
    }
    return {
        "schema": 1,
        "reference": {
            "commit": commit,
            "version": reference_version(tree),
            "policy": "The commit hash, not a release nickname, is authoritative.",
        },
        "status_semantics": {
            "unreviewed": "Extracted from the frozen Linux UAPI but not audited in EdgeOS.",
            "unimplemented": "No EdgeOS implementation exists.",
            "partial": "Some operations exist, but Linux semantic parity is incomplete.",
            "configured-off": "Behavior must match Linux with the same Kconfig disabled.",
            "unsupported-subsystem": "EdgeOS has no backend and must not expose a fake device.",
            "verified": "Linux oracle and EdgeOS runtime evidence both pass.",
        },
        "scope": {
            "architectures": ["x86_64", "aarch64", "ia32", "x32"],
            "boundary": "complete UAPI for EdgeOS-supported subsystems",
            "default_status": "unreviewed",
        },
        "edgeos_assessments": EDGEOS_ASSESSMENTS,
        "domains": {
            "syscalls": {
                "sources": [
                    {"path": str(path.relative_to(tree)), "sha256": sha256(path)}
                    for path in syscall_sources
                ],
                "architecture_rules": {
                    "x86_64": {"abis": ["common", "64"]},
                    "x32": {
                        "abis": ["common", "x32"],
                        "syscall_number_or_mask": "0x40000000",
                    },
                    "ia32": {"abis": ["i386"]},
                    "aarch64": {
                        "abis": [
                            "common", "64", "renameat", "rlimit",
                            "memfd_secret",
                        ],
                    },
                },
                "architectures": syscall_architectures,
            },
            "ioctl": ioctl_groups,
            "socket_options": symbol_domain(
                tree, SOCKET_HEADERS, prefixes=SOCKET_PREFIXES,
                include_enums=True),
            "netlink": symbol_domain(
                tree, NETLINK_HEADERS, prefixes=NETLINK_PREFIXES,
                include_enums=True),
            "virtual_filesystems": {
                "sources": [
                    "Documentation/filesystems/proc.rst",
                    "Documentation/admin-guide/cgroup-v2.rst",
                    "Documentation/ABI/stable and Documentation/ABI/testing",
                ],
                "status": "snapshot-required",
                "reason": "procfs, sysfs and cgroup paths are dynamic and need runtime snapshots.",
            },
        },
    }


def write_inventory(document: dict[str, object], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
