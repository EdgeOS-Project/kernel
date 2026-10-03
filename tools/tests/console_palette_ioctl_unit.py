#!/usr/bin/env python3
"""Host-execute both production palette ioctl branches and their shared renderer."""

import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def branch(path, condition):
    source = (ROOT / path).read_text()
    start = source.index(condition)
    opening = source.index("{", start)
    end = opening + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


SUPPORT = r'''
#include <errno.h>
#define LINUX_GIO_CMAP 0x4b70u
#define LINUX_PIO_CMAP 0x4b71u
#define LINUX_KDGKBTYPE 0x4b33u
#define LINUX_EPERM EPERM
#define LINUX_EFAULT EFAULT
#define LINUX_ENOTTY ENOTTY
#define EDGE_LINUX_CAP_SYS_TTY_CONFIG 26u
#define KERNEL_FD_TTY 1
#define FD_PTY_MASTER 2
#define FD_PTY_SLAVE 3
#define ARM64_TTY_PL011_BASE 66u
typedef struct {
    struct { uint64_t effective; } capabilities;
    uint64_t ttbr0;
    int controlling;
} task_t;
typedef struct { int kind, vt; uint8_t tty_identity; } edge_fd_t;
static task_t caller;
static edge_fd_t descriptor;
static uint8_t user_buffer[EDGE_FB_PALETTE_BYTES + 2u];
static unsigned int copy_limit, copies;
static int console_line_supports_linux_vt(const edge_fd_t *fd) {
    /* Production falls back to the active VT for non-console kinds. */
    return fd->kind == KERNEL_FD_TTY ? fd->vt : 1;
}
static int tty_fd_is_controlling_terminal(task_t *task, edge_fd_t *fd) {
    (void)fd; return task->controlling;
}
static int task_tty_is_controlling(task_t *task, edge_fd_t *fd) {
    return tty_fd_is_controlling_terminal(task, fd);
}
static uint8_t task_tty_identity(task_t *task, edge_fd_t *fd) {
    (void)task; return fd->tty_identity;
}
static int copy_from_user(void *dst, uint64_t src, size_t size) {
    ++copies;
    assert(size == EDGE_FB_PALETTE_BYTES);
    if (src != (uint64_t)(uintptr_t)(user_buffer + 1u)) return -1;
    memcpy(dst, user_buffer + 1u, copy_limit < size ? copy_limit : size);
    return copy_limit < size ? -1 : 0;
}
static int copy_to_user(uint64_t dst, const void *src, size_t size) {
    ++copies;
    assert(size == EDGE_FB_PALETTE_BYTES || size == 1u);
    if (dst != (uint64_t)(uintptr_t)(user_buffer + 1u)) return -1;
    memcpy(user_buffer + 1u, src, copy_limit < size ? copy_limit : size);
    return copy_limit < size ? -1 : 0;
}
static int arch_copy_from_user(uint64_t space, void *dst, uint64_t src, size_t n) {
    (void)space; return copy_from_user(dst, src, n);
}
static int arch_copy_to_user(uint64_t space, uint64_t dst, const void *src, size_t n) {
    (void)space; return copy_to_user(dst, src, n);
}
'''

TEST = r'''
static void check_discovery(int64_t (*handler)(uint64_t, uint64_t), int serial_rejected) {
    uint64_t address = (uint64_t)(uintptr_t)(user_buffer + 1u);
    caller.capabilities.effective = 0;
    caller.controlling = 0;
    descriptor.kind = KERNEL_FD_TTY;
    descriptor.vt = 1; descriptor.tty_identity = 3;
    copy_limit = 1u;
    memset(user_buffer, 0xa5, sizeof(user_buffer));
    assert(handler(LINUX_KDGKBTYPE, address) == 0);
    assert(user_buffer[1] == 2u);
    for (unsigned int i = 0; i < sizeof(user_buffer); ++i)
        if (i != 1u) assert(user_buffer[i] == 0xa5);
    assert(handler(LINUX_KDGKBTYPE, 0) == -EFAULT);
    copy_limit = 0u;
    assert(handler(LINUX_KDGKBTYPE, address) == -EFAULT);
    copy_limit = 1u;
    for (int kind = FD_PTY_MASTER; kind <= FD_PTY_SLAVE; ++kind) {
        descriptor.kind = kind;
        assert(handler(LINUX_KDGKBTYPE, address) == -ENOTTY);
    }
    if (serial_rejected) {
        descriptor.kind = KERNEL_FD_TTY;
        descriptor.vt = 0; descriptor.tty_identity = ARM64_TTY_PL011_BASE;
        assert(handler(LINUX_KDGKBTYPE, address) == -ENOTTY);
    }
}
static void check_handler(int64_t (*handler)(uint64_t, uint64_t)) {
    uint8_t original[EDGE_FB_PALETTE_BYTES], changed[EDGE_FB_PALETTE_BYTES];
    uint8_t observed[EDGE_FB_PALETTE_BYTES];
    uint64_t address = (uint64_t)(uintptr_t)(user_buffer + 1u);
    fb_console_get_palette(original);
    caller.capabilities.effective = 1ULL << EDGE_LINUX_CAP_SYS_TTY_CONFIG;
    caller.controlling = 0;
    descriptor.kind = KERNEL_FD_TTY;
    descriptor.vt = 1; descriptor.tty_identity = 3;
    copy_limit = EDGE_FB_PALETTE_BYTES;
    memset(user_buffer, 0x5a, sizeof(user_buffer));
    assert(handler(LINUX_GIO_CMAP, address) == 0);
    assert(user_buffer[0] == 0x5a && user_buffer[sizeof(user_buffer) - 1u] == 0x5a);
    assert(memcmp(user_buffer + 1u, original, sizeof(original)) == 0);
    for (unsigned int i = 0; i < sizeof(changed); ++i)
        changed[i] = (uint8_t)(255u - i * 3u);
    memcpy(user_buffer + 1u, changed, sizeof(changed));
    assert(handler(LINUX_PIO_CMAP, address) == 0);
    fb_console_get_palette(observed);
    assert(memcmp(observed, changed, sizeof(changed)) == 0);
    assert(handler(LINUX_GIO_CMAP, 0) == -EFAULT);
    assert(handler(LINUX_PIO_CMAP, 0) == -EFAULT);
    memcpy(user_buffer + 1u, original, sizeof(original));
    copy_limit = EDGE_FB_PALETTE_BYTES - 1u;
    assert(handler(LINUX_PIO_CMAP, address) == -EFAULT);
    fb_console_get_palette(observed);
    assert(memcmp(observed, changed, sizeof(changed)) == 0);
    assert(handler(LINUX_GIO_CMAP, address) == -EFAULT);
    copy_limit = EDGE_FB_PALETTE_BYTES;
    caller.capabilities.effective = 0;
    copies = 0;
    assert(handler(LINUX_PIO_CMAP, address) == -EPERM);
    assert(copies == 0);
    assert(handler(LINUX_GIO_CMAP, address) == 0);
    caller.controlling = 1;
    memcpy(user_buffer + 1u, original, sizeof(original));
    assert(handler(LINUX_PIO_CMAP, address) == 0);
    fb_console_get_palette(observed);
    assert(memcmp(observed, original, sizeof(original)) == 0);
    descriptor.vt = 0; descriptor.tty_identity = ARM64_TTY_PL011_BASE;
    assert(handler(LINUX_GIO_CMAP, address) == -ENOTTY);
    assert(handler(LINUX_PIO_CMAP, address) == -ENOTTY);
    descriptor.tty_identity = 3;
    for (int kind = FD_PTY_MASTER; kind <= FD_PTY_SLAVE; ++kind) {
        descriptor.kind = kind;
        assert(handler(LINUX_GIO_CMAP, address) == -ENOTTY);
        assert(handler(LINUX_PIO_CMAP, address) == -ENOTTY);
    }
}
int main(void) {
    assert(palette_render_main() == 0);
    check_discovery(x86_palette_ioctl, 1);
    check_discovery(arm64_palette_ioctl, 0);
    check_handler(x86_palette_ioctl);
    check_handler(arm64_palette_ioctl);
    puts("console_palette_ioctl_unit: PASS (x86_64 and AArch64 branches)");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    volume = Path("/Volumes/EdwardData")
    if not volume.is_mount() or not output.is_relative_to(volume / "EdgeOS"):
        parser.error("output must be on mounted /Volumes/EdwardData/EdgeOS")
    for path in ["src/sys/syscall_parts/prelude.c",
                 "src/arch/arm64/kernel/bootstrap_runtime.c"]:
        text = (ROOT / path).read_text()
        for name, value in [("GIO_CMAP", 0x4b70), ("PIO_CMAP", 0x4b71),
                            ("KDGKBTYPE", 0x4b33)]:
            match = re.search(r"#define LINUX_" + name + r" (0x[0-9a-fA-F]+)u", text)
            assert match and int(match[1], 16) == value, (path, name)
    text = (ROOT / "src/sys/syscall_parts/fd_tty_ipc.c").read_text()
    classifier = text[text.index("static int tty_ioctl_cmd_requires_tty("):
                      text.index("static const char *tty_ioctl_cmd_name(")]
    assert "cmd == LINUX_GIO_CMAP" in classifier
    assert "cmd == LINUX_PIO_CMAP" in classifier
    assert "cmd == LINUX_KDGKBTYPE" in classifier
    x86 = branch("src/sys/syscall_parts/net_socket.c",
                 "if (cmd == LINUX_GIO_CMAP || cmd == LINUX_PIO_CMAP)")
    x86 += branch("src/sys/syscall_parts/net_socket.c", "if (cmd == LINUX_KDGKBTYPE)")
    arm64 = branch("src/arch/arm64/kernel/bootstrap_runtime.c",
                   "if (a1 == LINUX_GIO_CMAP || a1 == LINUX_PIO_CMAP)")
    arm64 += branch("src/arch/arm64/kernel/bootstrap_runtime.c",
                     "if (fd->kind == KERNEL_FD_TTY && a1 == LINUX_KDGKBTYPE)")
    output.mkdir(parents=True, exist_ok=True)
    source = output / "console_palette_ioctl_unit.c"
    binary = output / "console_palette_ioctl_unit"
    source.write_text(
        '#define main palette_render_main\n#include "' +
        str(ROOT / "tools/tests/console_palette_unit.c") +
        '"\n#undef main\n' + SUPPORT +
        '\nstatic int64_t x86_palette_ioctl(uint64_t cmd, uint64_t arg_u) {\n'
        'task_t *cur = &caller; edge_fd_t *e = &descriptor;\n' + x86 +
        '\nreturn -ENOTTY;\n}\n'
        'static int64_t arm64_palette_ioctl(uint64_t a1, uint64_t a2) {\n'
        'task_t *task = &caller; edge_fd_t *fd = &descriptor;\n' + arm64 +
        '\nreturn -ENOTTY;\n}\n' + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                    "-Werror", "-fno-builtin", "-iquote", str(ROOT / "include"),
                    str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
