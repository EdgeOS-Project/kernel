#!/usr/bin/env python3
"""Compile the ARM64 lease-readiness callback and exercise worker context."""

import argparse
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "src/arch/arm64/kernel/bootstrap_runtime.c"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("HOST_CC", "clang"))
    args = parser.parse_args()
    source = RUNTIME.read_text()
    start = source.index("static int arm64_fd_operation_ready(")
    end = source.index("static int arm64_fd_operation_release(", start)
    callback = source[start:end]
    harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"

#define LINUX_EBADF EDGE_LINUX_EBADF
#define LINUX_POLLIN 0x001u
#define LINUX_POLLOUT 0x004u
#define LINUX_POLLERR 0x008u
#define LINUX_POLLHUP 0x010u
#define VFS_INODE_FILE 0x8000u

enum { KERNEL_FD_FILE, KERNEL_FD_PIPE_READ, KERNEL_FD_PIPE_WRITE,
       KERNEL_FD_PIPE_RW, KERNEL_FD_SIGNALFD };
typedef struct { int marker; } kernel_task_t;
typedef struct {
    int used;
    int kind;
    struct { uint16_t mode; } inode;
} bootstrap_fd_t;

static kernel_task_t task;
static kernel_task_t *running_task;
static uint32_t events;
static uint32_t poll_calls;
static kernel_task_t *current_task(void) { return running_task; }
static uint32_t fd_ready_mask(kernel_task_t *owner, bootstrap_fd_t *entry) {
    assert(owner == running_task);
    assert(entry && entry->used);
    if (!owner) {
        assert(entry->kind == KERNEL_FD_PIPE_READ ||
               entry->kind == KERNEL_FD_PIPE_WRITE ||
               entry->kind == KERNEL_FD_PIPE_RW ||
               (entry->kind == KERNEL_FD_FILE &&
                (entry->inode.mode & 0xf000u) == VFS_INODE_FILE));
    }
    ++poll_calls;
    return events;
}
'''
    harness += callback
    callback_harness = harness
    harness += r'''
int main(void) {
    bootstrap_fd_t entry = { .used = 1, .kind = KERNEL_FD_FILE,
                             .inode.mode = VFS_INODE_FILE | 0600u };
    const uint32_t operations[] = {
        KERNEL_IO_READ_CURRENT, KERNEL_IO_READ_POSITIONAL,
        KERNEL_IO_WRITE_CURRENT, KERNEL_IO_WRITE_POSITIONAL
    };

    /* A retained regular file must remain usable after its submitter exits. */
    running_task = 0;
    events = LINUX_POLLIN | LINUX_POLLOUT;
    for (unsigned i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i)
        assert(arm64_fd_operation_ready(0, &entry, operations[i]) == 1);
    assert(poll_calls == 4u);

    /* No-task pipe readiness must preserve waiting and peer-close semantics. */
    entry.kind = KERNEL_FD_PIPE_READ;
    events = 0;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) == 0);
    events = LINUX_POLLIN;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) == 1);
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_WRITE_CURRENT) == 0);
    events = LINUX_POLLHUP;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) == 1);
    entry.kind = KERNEL_FD_PIPE_WRITE;
    events = 0;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_WRITE_CURRENT) == 0);
    events = LINUX_POLLOUT;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_WRITE_CURRENT) == 1);
    events = LINUX_POLLERR;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_WRITE_CURRENT) == 1);
    entry.kind = KERNEL_FD_PIPE_RW;
    events = LINUX_POLLIN | LINUX_POLLOUT;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) == 1);
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_WRITE_CURRENT) == 1);

    /* Task-dependent descriptors must not reach their poll backend ownerless. */
    uint32_t previous_calls = poll_calls;
    entry.kind = KERNEL_FD_SIGNALFD;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) ==
           -LINUX_EBADF);
    entry.kind = KERNEL_FD_FILE;
    entry.inode.mode = 0x2000u;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) ==
           -LINUX_EBADF);
    assert(poll_calls == previous_calls);

    running_task = &task;
    entry.kind = KERNEL_FD_SIGNALFD;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) == 1);
    events = 0;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) == 0);
    entry.used = 0;
    assert(arm64_fd_operation_ready(0, &entry, KERNEL_IO_READ_CURRENT) ==
           -LINUX_EBADF);
    assert(arm64_fd_operation_ready(0, 0, KERNEL_IO_READ_CURRENT) ==
           -LINUX_EBADF);
    puts("arm64_fd_operation_ready_test: PASS");
    return 0;
}
'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [args.cc, "-x", "c", "-", "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-iquote", str(ROOT / "include"),
         "-o", str(args.output)],
        input=harness, text=True, check=True,
    )
    subprocess.run([str(args.output.resolve())], check=True)

    # Exercise the actual worker core with this callback in place of its mock.
    unit = (ROOT / "tools/tests/io_uring_runtime_unit.c").read_text()
    start = unit.index("int kernel_fd_operation_ready(")
    end = unit.index("int64_t kernel_fd_operation_file_range(", start)
    adapter = r'''
int kernel_fd_operation_ready(
        kernel_fd_operation_lease_t *lease, uint32_t operation) {
    int32_t descriptor = *(int32_t *)(void *)lease - 1;
    bootstrap_fd_t entry = { .used = descriptor >= 0,
                            .kind = KERNEL_FD_SIGNALFD };
    running_task = &task;
    if (descriptor >= 73 && descriptor <= 75) {
        running_task = 0;
        entry.kind = descriptor == 75 ? KERNEL_FD_FILE :
            (descriptor == 73 ? KERNEL_FD_PIPE_READ : KERNEL_FD_PIPE_WRITE);
        entry.inode.mode = VFS_INODE_FILE | 0600u;
    }
    events = descriptor == g_ready_descriptor &&
        ((uint32_t *)(void *)lease)[1] == g_ready_generation ?
            LINUX_POLLIN | LINUX_POLLOUT : 0u;
    return arm64_fd_operation_ready(0, &entry, operation);
}
'''
    integrated = callback_harness + unit[:start] + adapter + unit[end:]
    integrated_output = args.output.with_name(args.output.name + "-io-uring")
    subprocess.run(
        [args.cc, "-x", "c", "-", str(ROOT / "src/kernel/io_uring_runtime.c"),
         "-std=c11", "-Wall", "-Wextra", "-Werror", "-fno-builtin",
         "-DEDGEOS_HOST_TEST", "-fsanitize=address,undefined",
         "-iquote", str(ROOT / "include"), "-o", str(integrated_output)],
        input=integrated, text=True, check=True,
    )
    subprocess.run([str(integrated_output.resolve())], check=True)


if __name__ == "__main__":
    main()
