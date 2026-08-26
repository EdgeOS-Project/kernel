#!/usr/bin/env python3
"""Generate canonical syscall IDs and architecture number tables."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "tools/syscalls/linux_syscall_inventory.json"
UAPI_INVENTORY = ROOT / "tools/uapi/linux_uapi_inventory.json"
ID_HEADER = ROOT / "include/generated/linux_syscall_ids.h"
TABLE_INCLUDE = ROOT / "src/kernel/linux_syscall_tables.inc"
DISPATCH_INCLUDE = ROOT / "src/kernel/linux_syscall_dispatch.inc"


X32_COMPAT_SHARED_SYSCALLS = {
    "execve",
    "execveat",
    "get_robust_list",
    "getsockopt",
    "ioctl",
    "io_setup",
    "io_submit",
    "move_pages",
    "mq_notify",
    "preadv",
    "preadv2",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "pwritev",
    "pwritev2",
    "recvfrom",
    "readv",
    "recvmsg",
    "recvmmsg",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigqueueinfo",
    "rt_sigtimedwait",
    "rt_tgsigqueueinfo",
    "sendmsg",
    "sendmmsg",
    "sigaltstack",
    "set_robust_list",
    "setsockopt",
    "timer_create",
    "vmsplice",
    "writev",
    "waitid",
}

X32_ARCH_SYSCALLS = {
    "rt_sigreturn",
}

IA32_SHARED_SYSCALLS = {
    "access",
    "accept4",
    "acct",
    "adjtimex",
    "add_key",
    "alarm",
    "bind",
    "brk",
    "bpf",
    "capget",
    "capset",
    "cachestat",
    "chdir",
    "chmod",
    "chown",
    "chown32",
    "chroot",
    "clock_getres_time64",
    "clock_gettime64",
    "clock_nanosleep_time64",
    "clock_adjtime64",
    "clock_adjtime",
    "clone",
    "clone3",
    "close",
    "close_range",
    "connect",
    "copy_file_range",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "eventfd",
    "eventfd2",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fanotify_init",
    "fanotify_mark",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "fchown",
    "fchown32",
    "fchownat",
    "fdatasync",
    "file_getattr",
    "file_setattr",
    "finit_module",
    "fcntl",
    "fcntl64",
    "flock",
    "fork",
    "fstatfs",
    "fstatfs64",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "fstat64",
    "fstat",
    "fstatat64",
    "fsync",
    "futex_requeue",
    "futex_time64",
    "futex_wait",
    "futex_waitv",
    "futex_wake",
    "getcwd",
    "getcpu",
    "getegid",
    "getegid32",
    "getgid",
    "getgroups",
    "getgroups32",
    "getpgid",
    "getpgrp",
    "getpriority",
    "getrlimit",
    "getrusage",
    "getresgid32",
    "getresgid",
    "getresuid32",
    "getresuid",
    "getsid",
    "geteuid32",
    "geteuid",
    "getgid32",
    "getpid",
    "getppid",
    "getpeername",
    "getrandom",
    "getsockname",
    "getsockopt",
    "sysinfo",
    "gettid",
    "getuid32",
    "getuid",
    "getxattrat",
    "io_cancel",
    "io_destroy",
    "io_getevents",
    "io_setup",
    "io_submit",
    "ioctl",
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
    "ioperm",
    "iopl",
    "kill",
    "kcmp",
    "keyctl",
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
    "listmount",
    "listns",
    "listen",
    "link",
    "linkat",
    "listxattrat",
    "lsm_get_self_attr",
    "lsm_list_modules",
    "lsm_set_self_attr",
    "lstat64",
    "memfd_create",
    "madvise",
    "membarrier",
    "memfd_secret",
    "mincore",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
    "mlock",
    "mlock2",
    "mlockall",
    "mmap",
    "mmap2",
    "mbind",
    "mount_setattr",
    "mount",
    "move_pages",
    "migrate_pages",
    "move_mount",
    "mseal",
    "mprotect",
    "msync",
    "mremap",
    "munmap",
    "munlock",
    "munlockall",
    "openat",
    "openat2",
    "open_tree",
    "open_tree_attr",
    "open",
    "name_to_handle_at",
    "open_by_handle_at",
    "pipe2",
    "pipe",
    "pidfd_getfd",
    "pidfd_open",
    "pidfd_send_signal",
    "poll",
    "pkey_alloc",
    "pkey_free",
    "pkey_mprotect",
    "ppoll_time64",
    "prctl",
    "prlimit64",
    "perf_event_open",
    "personality",
    "pivot_root",
    "process_madvise",
    "process_mrelease",
    "process_vm_readv",
    "process_vm_writev",
    "quotactl_fd",
    "quotactl",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "recvfrom",
    "recvmsg",
    "remap_file_pages",
    "removexattrat",
    "rename",
    "renameat",
    "renameat2",
    "request_key",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigprocmask",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "rt_sigtimedwait_time64",
    "sigaction",
    "sigpending",
    "sigprocmask",
    "signal",
    "sigsuspend",
    "sgetmask",
    "ssetmask",
    "rseq_slice_yield",
    "rt_sigqueueinfo",
    "rt_tgsigqueueinfo",
    "sched_yield",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getaffinity",
    "sched_getattr",
    "sched_getparam",
    "sched_getscheduler",
    "sched_setaffinity",
    "sched_setattr",
    "sched_setparam",
    "sched_setscheduler",
    "seccomp",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setdomainname",
    "setfsgid",
    "setfsgid32",
    "setfsuid",
    "setfsuid32",
    "setgroups",
    "setgroups32",
    "sethostname",
    "setpgid",
    "setpriority",
    "setrlimit",
    "setregid32",
    "setregid",
    "setresgid32",
    "setresgid",
    "setresuid32",
    "setresuid",
    "setreuid32",
    "setreuid",
    "set_mempolicy_home_node",
    "set_tid_address",
    "set_robust_list",
    "setgid32",
    "setgid",
    "setsockopt",
    "setuid32",
    "setuid",
    "setxattrat",
    "setns",
    "setsid",
    "shutdown",
    "signalfd",
    "signalfd4",
    "sigaltstack",
    "socket",
    "socketpair",
    "splice",
    "stat64",
    "stat",
    "statfs",
    "statfs64",
    "statmount",
    "statx",
    "get_robust_list",
    "swapoff",
    "swapon",
    "symlink",
    "symlinkat",
    "sync",
    "syncfs",
    "sysfs",
    "syslog",
    "tee",
    "tgkill",
    "timer_delete",
    "timer_getoverrun",
    "timerfd_create",
    "tkill",
    "truncate",
    "uname",
    "umask",
    "umount2",
    "unlink",
    "unlinkat",
    "unshare",
    "userfaultfd",
    "vfork",
    "vhangup",
    "vmsplice",
    "write",
    "writev",
    "getdents64",
    "getdents",
    "inotify_add_watch",
    "inotify_init",
    "inotify_init1",
    "inotify_rm_watch",
    "io_pgetevents",
    "io_pgetevents_time64",
    "ioprio_get",
    "ioprio_set",
    "init_module",
    "lchown32",
    "lchown",
    "lstat",
    "lgetxattr",
    "listxattr",
    "llistxattr",
    "lremovexattr",
    "_llseek",
    "lseek",
    "lsetxattr",
    "fgetxattr",
    "flistxattr",
    "fremovexattr",
    "fsetxattr",
    "getxattr",
    "removexattr",
    "setxattr",
    "ftruncate",
    "reboot",
    "delete_module",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "clock_settime",
    "clock_settime64",
    "futex",
    "getitimer",
    "gettimeofday",
    "nanosleep",
    "pause",
    "ptrace",
    "ppoll",
    "pselect6",
    "pselect6_time64",
    "sched_rr_get_interval",
    "sched_rr_get_interval_time64",
    "setitimer",
    "set_mempolicy",
    "settimeofday",
    "time",
    "times",
    "get_mempolicy",
    "timer_create",
    "timer_gettime",
    "timer_gettime64",
    "timer_settime",
    "timer_settime64",
    "timerfd_gettime",
    "timerfd_gettime64",
    "timerfd_settime",
    "timerfd_settime64",
    "futimesat",
    "utime",
    "utimensat",
    "utimensat_time64",
    "utimes",
    "ustat",
    "ugetrlimit",
    "wait4",
    "waitid",
    "semget",
    "semctl",
    "shmget",
    "shmctl",
    "shmat",
    "shmdt",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "_newselect",
    "select",
    "fadvise64",
    "fadvise64_64",
    "fallocate",
    "ftruncate64",
    "nice",
    "pread64",
    "preadv",
    "preadv2",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "readahead",
    "recvmmsg",
    "recvmmsg_time64",
    "semtimedop_time64",
    "sendfile",
    "sendfile64",
    "sync_file_range",
    "truncate64",
    "umount",
    "waitpid",
}

IA32_ARCH_SYSCALLS = {
    "arch_prctl",
    "get_thread_area",
    "ipc",
    "rt_sigreturn",
    "sigreturn",
    "set_thread_area",
    "socketcall",
    "modify_ldt",
}

IA32_CANONICAL_ALIASES = {
    "_llseek": "lseek",
    "_newselect": "select",
    "clock_adjtime64": "clock_adjtime",
    "clock_getres_time64": "clock_getres",
    "clock_gettime64": "clock_gettime",
    "clock_nanosleep_time64": "clock_nanosleep",
    "clock_settime64": "clock_settime",
    "fstat64": "fstat",
    "fstatat64": "newfstatat",
    "fstatfs64": "fstatfs",
    "fcntl64": "fcntl",
    "fadvise64_64": "fadvise64",
    "ftruncate64": "ftruncate",
    "chown32": "chown",
    "fchown32": "fchown",
    "futex_time64": "futex",
    "io_pgetevents_time64": "io_pgetevents",
    "getegid32": "getegid",
    "geteuid32": "geteuid",
    "getgid32": "getgid",
    "getgroups32": "getgroups",
    "getresgid32": "getresgid",
    "getresuid32": "getresuid",
    "getuid32": "getuid",
    "lstat64": "lstat",
    "lchown32": "lchown",
    "mmap2": "mmap",
    "mq_timedreceive_time64": "mq_timedreceive",
    "mq_timedsend_time64": "mq_timedsend",
    "nice": "setpriority",
    "sigaction": "rt_sigaction",
    "sigpending": "rt_sigpending",
    "sigprocmask": "rt_sigprocmask",
    "signal": "rt_sigaction",
    "sigreturn": "rt_sigreturn",
    "sigsuspend": "rt_sigsuspend",
    "sgetmask": "rt_sigprocmask",
    "ssetmask": "rt_sigprocmask",
    "ppoll_time64": "ppoll",
    "pselect6_time64": "pselect6",
    "recvmmsg_time64": "recvmmsg",
    "rt_sigtimedwait_time64": "rt_sigtimedwait",
    "sched_rr_get_interval_time64": "sched_rr_get_interval",
    "setgid32": "setgid",
    "setfsgid32": "setfsgid",
    "setfsuid32": "setfsuid",
    "setgroups32": "setgroups",
    "setregid32": "setregid",
    "setresgid32": "setresgid",
    "setresuid32": "setresuid",
    "setreuid32": "setreuid",
    "setuid32": "setuid",
    "sendfile64": "sendfile",
    "semtimedop_time64": "semtimedop",
    "stat64": "stat",
    "statfs64": "statfs",
    "timer_gettime64": "timer_gettime",
    "timer_settime64": "timer_settime",
    "timerfd_gettime64": "timerfd_gettime",
    "timerfd_settime64": "timerfd_settime",
    "truncate64": "truncate",
    "umount": "umount2",
    "utimensat_time64": "utimensat",
    "ugetrlimit": "getrlimit",
    "waitpid": "wait4",
}


def load_inventory() -> list[dict[str, object]]:
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError("unsupported Linux syscall inventory schema")
    syscalls = document.get("syscalls")
    if not isinstance(syscalls, list):
        raise ValueError("Linux syscall inventory has no syscall list")
    return syscalls


def load_compat_syscalls(architecture: str) -> list[dict[str, object]]:
    document = json.loads(UAPI_INVENTORY.read_text(encoding="utf-8"))
    if document.get("schema") != 2:
        raise ValueError("unsupported Linux UAPI inventory schema")
    syscalls = document["domains"]["syscalls"]["architectures"][architecture]
    if not isinstance(syscalls, list):
        raise ValueError(
            f"{architecture} Linux UAPI syscall inventory is not a list"
        )
    return syscalls


def render_ids(syscalls: list[dict[str, object]]) -> str:
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from tools/syscalls/linux_syscall_inventory.json. */",
        "#ifndef EDGEOS_GENERATED_LINUX_SYSCALL_IDS_H",
        "#define EDGEOS_GENERATED_LINUX_SYSCALL_IDS_H",
        "",
        "typedef enum edge_linux_syscall_id {",
        "    EDGE_LINUX_SYS_INVALID = 0,",
    ]
    for entry in syscalls:
        lines.append(f"    EDGE_LINUX_SYS_{entry['id']},")
    lines.extend(
        [
            "    EDGE_LINUX_SYS_COUNT",
            "} edge_linux_syscall_id_t;",
            "",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def render_tables(syscalls: list[dict[str, object]]) -> str:
    by_architecture: dict[str, list[tuple[int, str, str]]] = {
        "x86_64": [],
        "aarch64": [],
        "x32": [],
        "ia32": [],
    }
    canonical = {str(entry["id"]): entry for entry in syscalls}
    x32_syscalls = load_compat_syscalls("x32")
    ia32_syscalls = load_compat_syscalls("ia32")
    x32_abis = {str(entry["name"]): entry.get("abi")
                for entry in x32_syscalls}
    invalid_compat = sorted(
        name for name in X32_COMPAT_SHARED_SYSCALLS
        if x32_abis.get(name) != "x32"
    )
    if invalid_compat:
        raise ValueError(
            "x32 compat allowlist contains non-x32 entries: " +
            ", ".join(invalid_compat)
        )
    invalid_arch = sorted(
        name for name in X32_ARCH_SYSCALLS
        if x32_abis.get(name) != "x32"
    )
    if invalid_arch:
        raise ValueError(
            "x32 architecture allowlist contains non-x32 entries: " +
            ", ".join(invalid_arch)
        )
    for entry in syscalls:
        architectures = entry["architectures"]
        assert isinstance(architectures, dict)
        for architecture in ("x86_64", "aarch64"):
            mapping = architectures.get(architecture)
            if mapping is None:
                continue
            assert isinstance(mapping, dict)
            by_architecture[architecture].append(
                (int(mapping["number"]), str(entry["id"]), str(mapping["status"]))
            )
    for mapping in x32_syscalls:
        name = str(mapping["name"])
        entry = canonical.get(name)
        if entry is None:
            raise ValueError(f"x32 syscall has no canonical ID: {name}")
        architectures = entry["architectures"]
        assert isinstance(architectures, dict)
        native = architectures.get("x86_64")
        native_implemented = (
            isinstance(native, dict) and native.get("status") == "implemented"
        )
        status = (
            "implemented"
            if native_implemented and (
                mapping.get("abi") == "common" or
                name in X32_COMPAT_SHARED_SYSCALLS or
                name in X32_ARCH_SYSCALLS
            )
            else "enosys"
        )
        by_architecture["x32"].append(
            (int(mapping["number"]), name, status)
        )
    for mapping in ia32_syscalls:
        name = str(mapping["name"])
        canonical_name = IA32_CANONICAL_ALIASES.get(name, name)
        entry = canonical.get(canonical_name)
        if entry is None:
            continue
        architectures = entry["architectures"]
        assert isinstance(architectures, dict)
        native = architectures.get("x86_64")
        native_implemented = (
            isinstance(native, dict) and native.get("status") == "implemented"
        )
        status = (
            "implemented"
            if name in IA32_ARCH_SYSCALLS or
            (native_implemented and name in IA32_SHARED_SYSCALLS)
            else "enosys"
        )
        by_architecture["ia32"].append(
            (int(mapping["number"]), canonical_name, status)
        )
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from the syscall and Linux UAPI inventories. */",
        "",
    ]
    for architecture, mappings in by_architecture.items():
        symbol = architecture.replace("64", "64")
        lines.append(
            f"static const edge_linux_syscall_number_t edge_linux_{symbol}_numbers[] = {{"
        )
        for number, name, status in sorted(mappings):
            status_symbol = (
                "EDGE_LINUX_SYSCALL_ENOSYS"
                if status == "enosys"
                else "EDGE_LINUX_SYSCALL_IMPLEMENTED"
            )
            lines.append(
                f"    {{{number}u, EDGE_LINUX_SYS_{name}, {status_symbol}}},"
            )
        lines.extend(["};", ""])
    return "\n".join(lines)


def render_dispatch(syscalls: list[dict[str, object]]) -> str:
    by_handler: dict[str, list[str]] = {}
    for entry in syscalls:
        handler = entry.get("shared_handler")
        if handler is None:
            continue
        if not isinstance(handler, str) or not handler:
            raise ValueError(f"invalid shared handler for {entry.get('id')}")
        by_handler.setdefault(handler, []).append(str(entry["id"]))
    lines = [
        "/* SPDX-License-Identifier: MPL-2.0 */",
        "/* Generated from tools/syscalls/linux_syscall_inventory.json. */",
    ]
    for handler, names in sorted(by_handler.items()):
        for name in sorted(names):
            lines.append(f"case EDGE_LINUX_SYS_{name}:")
        lines.append(f"    context->result = {handler}(context);")
        lines.append("    return EDGE_LINUX_SYSCALL_HANDLED;")
    lines.append("")
    return "\n".join(lines)


def check_or_write(path: Path, rendered: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == rendered:
        return True
    if check:
        print(f"stale generated syscall file: {path.relative_to(ROOT)}")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    print(f"generated {path.relative_to(ROOT)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    syscalls = load_inventory()
    outputs = {
        ID_HEADER: render_ids(syscalls),
        TABLE_INCLUDE: render_tables(syscalls),
        DISPATCH_INCLUDE: render_dispatch(syscalls),
    }
    valid = all(
        check_or_write(path, rendered, args.check)
        for path, rendered in outputs.items()
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
