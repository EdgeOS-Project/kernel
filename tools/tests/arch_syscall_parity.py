#!/usr/bin/env python3
"""Inventory EdgeOS Linux syscall routing without calling stubs support."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ARM64_RUNTIME = ROOT / "src/arch/arm64/kernel/bootstrap_runtime.c"
X86_PRELUDE = ROOT / "src/sys/syscall_parts/prelude.c"
X86_DISPATCH = ROOT / "src/sys/syscall_parts/dispatch.c"
SHARED_DISPATCH = ROOT / "src/kernel/linux_syscall_dispatch.inc"
SHARED_TABLES = ROOT / "src/kernel/linux_syscall_tables.inc"
SHARED_CORE_SOURCES = tuple(sorted((ROOT / "src/kernel").glob("linux_*.c")))
X86_PARTS = (
    ROOT / "src/sys/syscall_parts/fd_tty_ipc.c",
    ROOT / "src/sys/syscall_parts/fs_fd.c",
    ROOT / "src/sys/syscall_parts/net_socket.c",
    ROOT / "src/sys/syscall_parts/process_mm_misc.c",
)

ALIASES = {
    "newfstatat": "fstatat",
    "fstatat64": "fstatat",
    "epoll_pwait": "epoll_wait",
    "epoll_pwait2": "epoll_wait",
    "pselect6": "select",
    "ppoll": "poll",
    "signalfd4": "signalfd",
    "eventfd2": "eventfd",
    "inotify_init1": "inotify_init",
}

EDGE_CORE_SYSCALLS = {
    "read": "read",
    "write": "write",
    "open": "open",
    "close": "close",
    "fork": "fork",
    "execve": "execve",
    "exit": "exit",
    "wait": "wait4",
    "getpid": "getpid",
    "brk": "brk",
}

GROUPS = {
    "process": {
        "clone", "clone3", "execve", "execveat", "exit", "exit_group",
        "fork", "vfork", "wait4", "waitid", "prctl", "ptrace", "kill",
        "tgkill", "tkill", "set_tid_address", "getpid", "getppid", "gettid",
        "pidfd_open", "pidfd_getfd", "pidfd_send_signal", "process_madvise",
        "process_vm_readv", "process_vm_writev", "setns", "unshare",
    },
    "signals": {
        "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
        "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait",
        "rt_tgsigqueueinfo", "sigaltstack", "signalfd", "signalfd4",
    },
    "synchronization": {
        "futex", "futex_wait", "futex_wake", "futex_waitv", "futex_requeue",
        "set_robust_list", "get_robust_list", "membarrier", "rseq",
    },
    "events": {
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
        "epoll_pwait", "epoll_pwait2", "eventfd", "eventfd2", "poll",
        "pselect6", "select", "timerfd_create", "timerfd_gettime",
        "timerfd_settime", "inotify_init", "inotify_init1",
        "inotify_add_watch", "inotify_rm_watch",
    },
    "memory": {
        "brk", "mmap", "mprotect", "munmap", "mremap", "madvise", "mincore",
        "mlock", "mlock2", "munlock", "mlockall", "munlockall", "msync",
        "memfd_create", "userfaultfd", "pkey_mprotect", "pkey_alloc",
        "pkey_free",
    },
    "filesystem": {
        "open", "openat", "openat2", "close", "read", "write", "readv",
        "writev", "pread64", "pwrite64", "lseek", "fstat", "newfstatat",
        "statx", "getdents64", "linkat", "renameat2", "unlinkat", "mkdirat",
        "mount", "umount2", "faccessat", "faccessat2", "fchmodat2",
    },
    "network": {
        "socket", "socketpair", "bind", "listen", "accept", "accept4",
        "connect", "shutdown", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "sendmmsg", "recvmmsg", "setsockopt", "getsockopt", "getsockname",
        "getpeername",
    },
    "ipc": {
        "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "msgget", "msgsnd", "msgrcv",
        "msgctl", "semget", "semop", "semctl", "semtimedop", "shmget",
        "shmat", "shmdt", "shmctl",
    },
}


def normalize(name: str) -> str:
    return ALIASES.get(name, name)


def classify(name: str) -> str:
    for group, members in GROUPS.items():
        if name in members or normalize(name) in members:
            return group
    if any(token in name for token in
           ("xattr", "mount", "stat", "chmod", "chown", "link", "rename")):
        return "filesystem"
    if any(token in name for token in
           ("sched", "priority", "rlimit", "rusage", "uid", "gid")):
        return "process"
    if any(token in name for token in ("socket", "sock", "send", "recv")):
        return "network"
    return "other"


def grouped(names: set[str] | list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for name in sorted(names):
        result[classify(name)].append(name)
    return dict(sorted(result.items()))


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def named_function_bodies(text: str, name_pattern: str) -> dict[str, str]:
    """Extract named C function bodies with balanced braces."""
    result: dict[str, str] = {}
    pattern = re.compile(
        rf"\b(?:static\s+)?[\w\s\*]+\b({name_pattern})\s*\([^;]*?\)\s*\{{"
    )
    for match in pattern.finditer(text):
        depth = 1
        index = match.end()
        while index < len(text) and depth:
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
            index += 1
        if depth == 0:
            result[match.group(1)] = text[match.end():index - 1]
    return result


def function_bodies(text: str) -> dict[str, str]:
    """Extract x86 do_sys_* bodies with balanced braces."""
    return named_function_bodies(text, r"do_sys_\w+")


def unconditional_enosys_handlers(text: str) -> set[str]:
    stubs: set[str] = set()
    bodies = named_function_bodies(text, r"(?:do_sys_|edge_linux_sys_)\w+")
    for name, raw_body in bodies.items():
        body = strip_comments(raw_body)
        if not re.search(r"return\s+[^;]*ENOSYS\s*;", body):
            continue
        if len(re.findall(r"\breturn\b", body)) != 1:
            continue
        if re.search(r"\b(if|switch|for|while|goto)\b|\?", body):
            continue
        stubs.add(name)
    return stubs


def parse_x86_dispatch(
    text: str, handler_stubs: set[str], declared: set[str]
) -> tuple[set[str], set[str], dict[str, str]]:
    routed: set[str] = set()
    stubs: set[str] = set()
    handlers: dict[str, str] = {}
    pending: list[str] = []

    for line in text.splitlines():
        case = re.search(r"\bcase\s+(SYS|EDGE_SYS)_(\w+)\s*:", line)
        if case:
            name = case.group(2)
            if case.group(1) == "EDGE_SYS":
                name = EDGE_CORE_SYSCALLS.get(name, "")
            if name and name in declared:
                pending.append(name)
                routed.add(name)
            continue
        handler = re.search(
            r"\b(do_sys_\w+|kernel_vfs_open_at)\s*\(", line
        )
        if handler and pending:
            for syscall_name in pending:
                if handler.group(1) in handler_stubs:
                    stubs.add(syscall_name)
                    handlers[syscall_name] = "enosys"
                else:
                    handlers[syscall_name] = handler.group(1)
        if pending and re.search(r"(?:-|\()ENOSYS\b", line):
            stubs.update(pending)
            for syscall_name in pending:
                handlers[syscall_name] = "enosys"
        if pending and re.search(r"\bbreak\s*;", line):
            for syscall_name in pending:
                handlers.setdefault(syscall_name, "inline:x86_64")
            pending.clear()
    for syscall_name in pending:
        handlers.setdefault(syscall_name, "inline:x86_64")
    return routed, stubs, handlers


def parse_arm64_dispatch(
    text: str, declared: set[str]
) -> tuple[set[str], set[str], dict[str, str]]:
    """Read routes from the real ARM64 dispatcher, never from declarations."""
    bodies = named_function_bodies(
        text, r"bootstrap_syscall_(?:impl|tail)"
    )
    if "bootstrap_syscall_impl" not in bodies:
        raise ValueError("ARM64 bootstrap_syscall_impl dispatcher was not found")
    body = strip_comments("\n".join(bodies.values()))
    routed = {
        match.group(1)
        for match in re.finditer(r"\bnr\s*==\s*LINUX_SYS_(\w+)\b", body)
    }
    routed.update(
        match.group(1)
        for match in re.finditer(r"\bLINUX_SYS_(\w+)\s*==\s*nr\b", body)
    )
    routed.update(
        match.group(1)
        for match in re.finditer(r"\bcase\s+LINUX_SYS_(\w+)\s*:", body)
    )
    routed &= declared

    stubs: set[str] = set()
    direct_stub = re.compile(
        r"\bif\s*\((?P<condition>[^{};]*?)\)\s*"
        r"(?:\{\s*)?return\s+(?:\([^;]+\)\s*)?-\s*LINUX_ENOSYS\s*;",
        re.S,
    )
    for match in direct_stub.finditer(body):
        names = set(re.findall(r"\bLINUX_SYS_(\w+)\b", match.group("condition")))
        stubs.update(names & routed)

    handlers = {
        name: "enosys" if name in stubs else "inline:aarch64"
        for name in routed
    }
    direct_runtime_handler = re.compile(
        r"\bif\s*\(\s*nr\s*==\s*LINUX_SYS_(\w+)\s*\)\s*\{\s*"
        r"return\s+(kernel_vfs_open_at)\s*\(",
        re.S,
    )
    for match in direct_runtime_handler.finditer(body):
        if match.group(1) in routed and match.group(1) not in stubs:
            handlers[match.group(1)] = match.group(2)
    return routed, stubs, handlers


def parse_definitions(text: str, prefix: str) -> set[str]:
    return set(re.findall(rf"^#define\s+{re.escape(prefix)}(\w+)\b", text, re.M))


def parse_numeric_definitions(text: str, prefix: str) -> dict[str, int]:
    """Read literal syscall numbers and reject conflicting declarations."""
    definitions: dict[str, int] = {}
    pattern = re.compile(
        rf"^#define\s+{re.escape(prefix)}(\w+)\s+"
        rf"(?P<number>0[xX][0-9a-fA-F]+|[0-9]+)(?:[uUlL]+)?\b",
        re.M,
    )
    for match in pattern.finditer(text):
        name = match.group(1)
        number = int(match.group("number"), 0)
        previous = definitions.get(name)
        if previous is not None and previous != number:
            raise ValueError(
                f"conflicting {prefix}{name} values: {previous} and {number}"
            )
        definitions[name] = number
    return definitions


def parse_shared_dispatch(text: str) -> dict[str, str]:
    """Read canonical IDs routed to real handlers by the generated switch."""
    routes: dict[str, str] = {}
    pending: list[str] = []
    for line in text.splitlines():
        case = re.search(r"\bcase\s+EDGE_LINUX_SYS_(\w+)\s*:", line)
        if case:
            pending.append(case.group(1))
            continue
        handler = re.search(r"\b(edge_linux_sys_\w+)\s*\(context\)", line)
        if handler and pending:
            for name in pending:
                routes[name] = f"shared:{handler.group(1)}"
            pending.clear()
    if pending:
        raise ValueError(f"shared dispatch cases have no handler: {pending}")
    return routes


def parse_generated_mappings(
    text: str, architecture: str
) -> dict[str, tuple[int, str]]:
    """Read generated architecture numbers and shared-dispatch status."""
    table = re.search(
        rf"edge_linux_{re.escape(architecture)}_numbers\[\]\s*=\s*\{{"
        rf"(?P<body>.*?)\n\}};",
        text,
        re.S,
    )
    if table is None:
        raise ValueError(f"generated {architecture} syscall table was not found")
    mappings: dict[str, tuple[int, str]] = {}
    for match in re.finditer(
        r"\{\s*(\d+)u,\s*EDGE_LINUX_SYS_(\w+),\s*"
        r"(EDGE_LINUX_SYSCALL_IMPLEMENTED|EDGE_LINUX_SYSCALL_ENOSYS)\s*\}",
        table.group("body"),
    ):
        mappings[match.group(2)] = (
            int(match.group(1)),
            "enosys" if match.group(3).endswith("_ENOSYS") else "implemented",
        )
    return mappings


def merge_architecture_numbers(
    generated: dict[str, tuple[int, str]], legacy: dict[str, int],
    architecture: str,
) -> dict[str, int]:
    """Keep legacy declarations as an independent consistency cross-check."""
    numbers = {name: mapping[0] for name, mapping in generated.items()}
    for name, number in legacy.items():
        generated_number = numbers.get(name)
        if generated_number is not None and generated_number != number:
            raise ValueError(
                f"{architecture} {name} number differs between generated "
                f"mapping {generated_number} and legacy declaration {number}"
            )
        numbers[name] = number
    return numbers


def merge_shared_routes(
    declared: set[str], routed: set[str], stubs: set[str],
    handlers: dict[str, str], shared_routes: dict[str, str],
    statuses: dict[str, str], shared_stub_handlers: set[str],
) -> None:
    for name, status in statuses.items():
        if name not in declared:
            continue
        if status == "enosys":
            routed.add(name)
            stubs.add(name)
            handlers[name] = "enosys"
    for name, route in shared_routes.items():
        if name not in declared:
            continue
        handler = route.removeprefix("shared:")
        routed.add(name)
        handlers[name] = route
        if handler in shared_stub_handlers:
            stubs.add(name)


def parse() -> dict[str, Any]:
    arm_text = ARM64_RUNTIME.read_text(encoding="utf-8")
    x86_defs_text = X86_PRELUDE.read_text(encoding="utf-8")
    x86_dispatch_text = X86_DISPATCH.read_text(encoding="utf-8")
    x86_parts_text = "\n".join(path.read_text(encoding="utf-8") for path in X86_PARTS)
    shared_dispatch_text = SHARED_DISPATCH.read_text(encoding="utf-8")
    shared_tables_text = SHARED_TABLES.read_text(encoding="utf-8")
    shared_core_text = "\n".join(
        path.read_text(encoding="utf-8") for path in SHARED_CORE_SOURCES
    )
    if "edge_linux_syscall_dispatch(" not in x86_dispatch_text or \
       "edge_linux_syscall_dispatch(" not in arm_text:
        raise ValueError("both architecture entry paths must call the shared dispatcher")
    shared_routes = parse_shared_dispatch(shared_dispatch_text)
    shared_stubs = unconditional_enosys_handlers(shared_core_text)

    arm_generated = parse_generated_mappings(shared_tables_text, "aarch64")
    arm_numbers = merge_architecture_numbers(
        arm_generated,
        parse_numeric_definitions(arm_text, "LINUX_SYS_"),
        "aarch64",
    )
    arm_declared = set(arm_numbers)
    arm_routed, arm_stubs, arm_handlers = parse_arm64_dispatch(
        arm_text, arm_declared
    )
    merge_shared_routes(
        arm_declared, arm_routed, arm_stubs, arm_handlers, shared_routes,
        {name: mapping[1] for name, mapping in arm_generated.items()},
        shared_stubs,
    )
    x86_generated = parse_generated_mappings(shared_tables_text, "x86_64")
    x86_numbers = merge_architecture_numbers(
        x86_generated,
        parse_numeric_definitions(x86_defs_text, "SYS_"),
        "x86_64",
    )
    x86_declared = set(x86_numbers)
    handler_stubs = unconditional_enosys_handlers(x86_parts_text)
    x86_routed, x86_stubs, x86_handlers = parse_x86_dispatch(
        x86_dispatch_text, handler_stubs, x86_declared
    )
    merge_shared_routes(
        x86_declared, x86_routed, x86_stubs, x86_handlers, shared_routes,
        {name: mapping[1] for name, mapping in x86_generated.items()},
        shared_stubs,
    )

    arm_non_stub = arm_routed - arm_stubs
    x86_non_stub = x86_routed - x86_stubs
    arm_normalized = {normalize(name) for name in arm_non_stub}
    x86_normalized = {normalize(name) for name in x86_non_stub}
    common = arm_normalized & x86_normalized

    return {
        "method": {
            "non_stub_routed": (
                "A syscall number reaches a branch that is not an unconditional "
                "ENOSYS path. This is static routing evidence, not proof that all "
                "flags, commands, errors, or concurrency semantics match Linux."
            ),
            "runtime_validation_required": True,
        },
        "arm64": {
            "declared_count": len(arm_declared),
            "routed_count": len(arm_routed),
            "non_stub_routed_count": len(arm_non_stub),
            "explicit_stub_count": len(arm_stubs),
            "declared_but_unrouted": sorted(arm_declared - arm_routed),
            "explicit_stubs": grouped(arm_stubs),
            "non_stub_routed": grouped(arm_non_stub),
            "routes": dict(sorted(arm_handlers.items())),
            "numbers": dict(sorted(arm_numbers.items())),
        },
        "x86_64": {
            "declared_count": len(x86_declared),
            "routed_count": len(x86_routed),
            "non_stub_routed_count": len(x86_non_stub),
            "explicit_stub_count": len(x86_stubs),
            "declared_but_unrouted": sorted(x86_declared - x86_routed),
            "explicit_stubs": grouped(x86_stubs),
            "non_stub_routed": grouped(x86_non_stub),
            "stub_handlers": sorted(
                {x86_handlers[name] for name in x86_stubs if name in x86_handlers}
            ),
            "routes": dict(sorted(x86_handlers.items())),
            "numbers": dict(sorted(x86_numbers.items())),
        },
        "parity": {
            "common_normalized_count": len(common),
            "arm64_only_non_stub_normalized": grouped(arm_normalized - x86_normalized),
            "x86_64_only_non_stub_normalized": grouped(x86_normalized - arm_normalized),
        },
    }


def append_grouped(lines: list[str], title: str, groups: dict[str, list[str]]) -> None:
    lines.extend(("", f"## {title}"))
    if not groups:
        lines.extend(("", "None."))
        return
    for group, names in groups.items():
        lines.extend(("", f"### {group} ({len(names)})", "", " ".join(names)))


def markdown(report: dict[str, Any]) -> str:
    arm = report["arm64"]
    x86 = report["x86_64"]
    parity = report["parity"]
    lines = [
        "# EdgeOS Linux syscall routing inventory",
        "",
        "> Static routing is not runtime proof. `non-stub routed` means the",
        "> dispatcher does not immediately return unconditional `ENOSYS`; each",
        "> syscall still needs semantic and application-level validation.",
        "",
        "| Architecture | Declared | Routed | Non-stub routed | Explicit stubs |",
        "| --- | ---: | ---: | ---: | ---: |",
        f"| ARM64 | {arm['declared_count']} | {arm['routed_count']} | "
        f"{arm['non_stub_routed_count']} | {arm['explicit_stub_count']} |",
        f"| x86_64 | {x86['declared_count']} | {x86['routed_count']} | "
        f"{x86['non_stub_routed_count']} | {x86['explicit_stub_count']} |",
        "",
        f"Normalized non-stub surface shared by both architectures: "
        f"{parity['common_normalized_count']}.",
    ]
    append_grouped(lines, "ARM64 explicit unconditional ENOSYS routes", arm["explicit_stubs"])
    append_grouped(lines, "x86_64 explicit unconditional ENOSYS routes", x86["explicit_stubs"])
    append_grouped(lines, "ARM64 non-stub routed surface", arm["non_stub_routed"])
    append_grouped(lines, "x86_64 non-stub routed surface", x86["non_stub_routed"])
    append_grouped(lines, "ARM64-only normalized non-stub routes", parity["arm64_only_non_stub_normalized"])
    append_grouped(lines, "x86_64-only normalized non-stub routes", parity["x86_64_only_non_stub_normalized"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = parse()
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else markdown(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
