#!/usr/bin/env python3
"""Refresh the checked-in EdgeOS Linux syscall inventory from dispatch code."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TEST_TOOLS = ROOT / "tools/tests"
INVENTORY = ROOT / "tools/syscalls/linux_syscall_inventory.json"
LINUX_REFERENCE_COMMIT = "a13c140cc289c0b7b3770bce5b3ad42ab35074aa"
LINUX_REFERENCE_VERSION = "7.2.0-rc3"
sys.path.insert(0, str(TEST_TOOLS))

from arch_syscall_parity import normalize, parse  # noqa: E402


ARCHITECTURE_EXCEPTIONS = {
    "arch_prctl": [
        "x86_64 register and TLS control",
        "ia32 CPUID and xstate control; FS and GS requests return EINVAL",
    ],
    "get_thread_area": ["legacy x86_64 TLS descriptor ABI"],
    "ioperm": ["x86_64 I/O-port permission mechanism"],
    "iopl": ["x86_64 I/O privilege mechanism"],
    "map_shadow_stack": [
        "x86_64 shadow-stack and AArch64 guarded-control-stack ABI"
    ],
    "modify_ldt": ["x86_64 descriptor-table ABI"],
    "rt_sigreturn": ["Architecture-specific signal-frame restoration"],
    "set_thread_area": ["legacy x86_64 TLS descriptor ABI"],
}

LINUX_RESERVED_ENOSYS_X86_64 = {
    "_sysctl",
    "afs_syscall",
    "create_module",
    "epoll_ctl_old",
    "epoll_wait_old",
    "get_kernel_syms",
    "getpmsg",
    "get_thread_area",
    "lookup_dcookie",
    "nfsservctl",
    "putpmsg",
    "query_module",
    "security",
    "set_thread_area",
    "tuxcall",
    "uselib",
    "vserver",
}
AARCH64_LINUX_ENOSYS_NUMBERS = {
    "lookup_dcookie": 18,
    "nfsservctl": 42,
}
LINUX_RESERVED_SYSCALL_PROBE = (
    "tools/tests/linux_reserved_syscalls_abi_probe.c"
)
VERIFIED_SYSCALL_PROBES = {
    "epoll_create": "tools/tests/epoll_abi_probe.c",
    "epoll_create1": "tools/tests/epoll_abi_probe.c",
    "epoll_ctl": "tools/tests/epoll_abi_probe.c",
    "epoll_pwait": "tools/tests/epoll_abi_probe.c",
    "epoll_pwait2": "tools/tests/epoll_abi_probe.c",
    "epoll_wait": "tools/tests/epoll_abi_probe.c",
    "get_mempolicy": "tools/tests/numa_policy_abi_probe.c",
    "mbind": "tools/tests/numa_policy_abi_probe.c",
    "memfd_secret": "tools/tests/memfd_secret_abi_probe.c",
    "migrate_pages": "tools/tests/numa_policy_abi_probe.c",
    "modify_ldt": "tools/tests/modify_ldt_abi_probe.c",
    "move_pages": "tools/tests/numa_policy_abi_probe.c",
    "msgctl": "tools/tests/sysv_msg_abi_probe.c",
    "msgget": "tools/tests/sysv_msg_abi_probe.c",
    "msgrcv": "tools/tests/sysv_msg_abi_probe.c",
    "msgsnd": "tools/tests/sysv_msg_abi_probe.c",
    "mq_getsetattr": "tools/tests/posix_mq_abi_probe.c",
    "mq_notify": "tools/tests/posix_mq_abi_probe.c",
    "mq_open": "tools/tests/posix_mq_abi_probe.c",
    "mq_timedreceive": "tools/tests/posix_mq_abi_probe.c",
    "mq_timedsend": "tools/tests/posix_mq_abi_probe.c",
    "mq_unlink": "tools/tests/posix_mq_abi_probe.c",
    "remap_file_pages": "tools/tests/remap_file_pages_abi_probe.c",
    "sched_getaffinity": "tools/tests/scheduler_runtime_probe.c",
    "sched_getattr": "tools/tests/scheduler_runtime_probe.c",
    "sched_getparam": "tools/tests/scheduler_runtime_probe.c",
    "sched_getscheduler": "tools/tests/scheduler_runtime_probe.c",
    "sched_setaffinity": "tools/tests/scheduler_runtime_probe.c",
    "sched_setattr": "tools/tests/scheduler_runtime_probe.c",
    "sched_setparam": "tools/tests/scheduler_runtime_probe.c",
    "sched_setscheduler": "tools/tests/scheduler_runtime_probe.c",
    "sched_yield": "tools/tests/scheduler_runtime_probe.c",
    "semctl": "tools/tests/sysv_sem_abi_probe.c",
    "semget": "tools/tests/sysv_sem_abi_probe.c",
    "semop": "tools/tests/sysv_sem_abi_probe.c",
    "semtimedop": "tools/tests/sysv_sem_abi_probe.c",
    "set_mempolicy": "tools/tests/numa_policy_abi_probe.c",
    "set_mempolicy_home_node": "tools/tests/numa_policy_abi_probe.c",
    "setfsgid": "tools/tests/credential_transition_abi_probe.c",
    "setfsuid": "tools/tests/credential_transition_abi_probe.c",
    "setgid": "tools/tests/credential_transition_abi_probe.c",
    "setregid": "tools/tests/credential_transition_abi_probe.c",
    "setresgid": "tools/tests/credential_transition_abi_probe.c",
    "setresuid": "tools/tests/credential_transition_abi_probe.c",
    "setreuid": "tools/tests/credential_transition_abi_probe.c",
    "setuid": "tools/tests/credential_transition_abi_probe.c",
    "sysfs": "tools/tests/sysfs_syscall_abi_probe.c",
}
PARTIAL_SYSCALL_PROBES = {
    "bpf": "tools/tests/bpf_abi_probe.c",
    "kexec_file_load": "tools/tests/native_optional_syscalls_abi_probe.c",
    "kexec_load": "tools/tests/native_optional_syscalls_abi_probe.c",
    "map_shadow_stack": "tools/tests/native_optional_syscalls_abi_probe.c",
    "uprobe": "tools/tests/native_optional_syscalls_abi_probe.c",
    "uretprobe": "tools/tests/native_optional_syscalls_abi_probe.c",
}


def load_existing() -> dict[str, dict[str, Any]]:
    if not INVENTORY.exists():
        return {}
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in document.get("syscalls", [])}


def architecture_entry(
    report: dict[str, Any], architecture: str, name: str,
    runtime_tests: list[str], oracle_status: str,
) -> dict[str, Any] | None:
    side = report[architecture]
    if name not in side["numbers"]:
        return None
    route = side["routes"].get(name)
    if route is None:
        raise ValueError(f"{architecture} syscall {name} has no dispatch route")
    is_enosys = route == "enosys"
    return {
        "number": side["numbers"][name],
        "status": "enosys" if is_enosys else "implemented",
        "route": route,
        "evidence_status": (
            "oracle-verified-enosys" if is_enosys and
            oracle_status == "verified" and runtime_tests else
            "explicit-enosys" if is_enosys else
            "oracle-verified" if oracle_status == "verified" else
            "runtime-probe-listed" if runtime_tests else
            "static-route-only"
        ),
    }


def build_document() -> dict[str, Any]:
    report = parse()
    for name, number in AARCH64_LINUX_ENOSYS_NUMBERS.items():
        existing_number = report["arm64"]["numbers"].get(name)
        if existing_number is not None and existing_number != number:
            raise ValueError(
                f"aarch64 {name} moved from {number} to {existing_number}"
            )
        report["arm64"]["numbers"][name] = number
        report["arm64"]["routes"][name] = "enosys"
    existing = load_existing()
    names = sorted(
        set(report["x86_64"]["numbers"]) | set(report["arm64"]["numbers"])
    )
    syscalls: list[dict[str, Any]] = []
    for name in names:
        old = existing.get(name, {})
        runtime_tests = old.get("runtime_tests", [])
        oracle_status = old.get("oracle_status", "not-run")
        shared_handler = old.get("shared_handler")
        if name in LINUX_RESERVED_ENOSYS_X86_64:
            if report["x86_64"]["routes"].get(name) != "enosys":
                raise ValueError(
                    f"x86_64 Linux-reserved syscall {name} no longer routes "
                    "to ENOSYS"
                )
            runtime_tests = [LINUX_RESERVED_SYSCALL_PROBE]
            oracle_status = "verified"
        if name in VERIFIED_SYSCALL_PROBES:
            runtime_tests = [VERIFIED_SYSCALL_PROBES[name]]
            oracle_status = "verified"
        if name in PARTIAL_SYSCALL_PROBES:
            runtime_tests = [PARTIAL_SYSCALL_PROBES[name]]
            if oracle_status != "verified":
                oracle_status = "partial"
        if shared_handler is None:
            shared_routes = {
                route.split(":", 1)[1]
                for architecture in ("x86_64", "arm64")
                for route in [report[architecture]["routes"].get(name)]
                if route is not None and route.startswith("shared:")
            }
            if len(shared_routes) == 1:
                shared_handler = next(iter(shared_routes))
        syscalls.append(
            {
                "id": name,
                "semantic_id": normalize(name),
                "shared_handler": shared_handler,
                "architecture_exceptions": ARCHITECTURE_EXCEPTIONS.get(name, []),
                "runtime_tests": runtime_tests,
                "linux_oracle": "required",
                "oracle_status": oracle_status,
                "architectures": {
                    "x86_64": architecture_entry(
                        report, "x86_64", name, runtime_tests,
                        oracle_status),
                    "aarch64": architecture_entry(
                        report, "arm64", name, runtime_tests,
                        oracle_status),
                },
            }
        )
    for name, entry in existing.items():
        if name not in names and entry.get("architectures") == {}:
            syscalls.append(entry)
    syscalls.sort(key=lambda entry: entry["id"])
    return {
        "schema": 1,
        "description": "Canonical EdgeOS Linux syscall ABI inventory",
        "linux_reference": {
            "commit": LINUX_REFERENCE_COMMIT,
            "version": LINUX_REFERENCE_VERSION,
            "policy": "The commit hash is authoritative.",
        },
        "status_semantics": {
            "implemented": (
                "Statically reaches a non-ENOSYS route. Runtime tests are required "
                "before claiming semantic Linux compatibility."
            ),
            "enosys": "The architecture route explicitly returns Linux ENOSYS.",
        },
        "evidence_semantics": {
            "explicit-enosys": "The dispatch route explicitly returns Linux ENOSYS.",
            "oracle-verified-enosys": (
                "The ENOSYS result was compared with the frozen Linux oracle."
            ),
            "static-route-only": (
                "A non-ENOSYS route exists, but no runtime probe is listed."
            ),
            "runtime-probe-listed": (
                "A runtime probe is listed. This does not assert that it passed."
            ),
            "oracle-verified": (
                "The EdgeOS result and frozen Linux oracle result were compared."
            ),
        },
        "dispatch_model": (
            "Architecture syscall numbers map to canonical IDs. "
            "Architecture-neutral policy is implemented by shared handlers."
        ),
        "syscalls": syscalls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stdout", action="store_true", help="print instead of updating the file"
    )
    args = parser.parse_args()
    rendered = json.dumps(build_document(), indent=2, sort_keys=False) + "\n"
    if args.stdout:
        print(rendered, end="")
    else:
        INVENTORY.write_text(rendered, encoding="utf-8")
        print(f"updated {INVENTORY.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
