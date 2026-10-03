#!/usr/bin/env python3
"""Exercise real fsconfig, mount-context and FD lease code with close/reuse injection."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(text, name):
    match = re.search(r"^static int " + name + r"\([^;]*?\)\s*\{", text, re.M)
    if not match:
        raise ValueError(name)
    end = match.end()
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#define main legacy_mount_api_main
#define arch_vm_alloc_page test_base_alloc
#define arch_vm_free_page test_base_free
#include "LEGACY_TEST"
#undef main
#undef arch_vm_alloc_page
#undef arch_vm_free_page
#include "kernel/linux_syscall.h"
#include "FD_RUNTIME"
static int fail_page;
static unsigned pages;
void *arch_vm_alloc_page(void) {
    if (fail_page) { fail_page = 0; return 0; }
    void *page = test_base_alloc(); if (page) ++pages; return page;
}
void arch_vm_free_page(void *page) {
    if (page) { assert(pages); --pages; test_base_free(page); }
}
#define LINUX_EINVAL EDGE_LINUX_EINVAL
#define LINUX_O_PATH 0x200000
#define FD_MOUNT 1
#define FD_VFS 2
#define KERNEL_FD_MOUNT FD_MOUNT
#define KERNEL_FD_FILE FD_VFS
struct mock_file {
    int refs, context, kind, flags, id;
    char path[4096];
    vfs_inode_t inode;
};
typedef struct {
    int kind, flags, status_flags, pipe_id, anonymous_inode;
    uint64_t mount_id;
    const char *path;
    vfs_superblock_t *sb;
    vfs_inode_t inode;
    struct mock_file *owner;
} edge_fd_t;
typedef edge_fd_t bootstrap_fd_t;
static const char *fd_path(const edge_fd_t *fd) { return fd->path; }
static void bytes_zero(void *p, uint64_t n) { memset(p, 0, (size_t)n); }
static vfs_superblock_t mock_superblock;
static struct mock_file *slots[16];
static unsigned destroyed[256];
static unsigned next_file, acquisitions, releases;
static int inject_fd = -1, use_arm;
static void drop_file(struct mock_file *f) {
    assert(f && f->refs > 0);
    if (--f->refs) return;
    ++destroyed[f->id];
    if (f->context > 0) kernel_mount_api_release(f->context);
    free(f);
}
static void close_slot(int fd) {
    assert(slots[fd]); struct mock_file *f = slots[fd]; slots[fd] = 0; drop_file(f);
}
static struct mock_file *new_file(int slot, const char *path, int context, uint16_t mode) {
    assert(!slots[slot]);
    struct mock_file *f = calloc(1, sizeof(*f)); assert(f);
    f->refs = 1; f->context = context; f->id = (int)++next_file;
    assert(next_file < 256);
    f->kind = context > 0 ? FD_MOUNT : FD_VFS;
    f->flags = context > 0 ? 0 : LINUX_O_PATH;
    f->inode.mode = mode; f->inode.ino = next_file;
    snprintf(f->path, sizeof(f->path), "%s", path ? path : "");
    slots[slot] = f; return f;
}
static uint32_t table_limit(void *context) { (void)context; return 16; }
static int acquire(void *context, int32_t fd, void *storage) {
    (void)context;
    if (fd < 0 || fd >= 16 || !slots[fd]) return -EDGE_LINUX_EBADF;
    struct mock_file *f = slots[fd]; edge_fd_t *s = storage;
    memset(s, 0, sizeof(*s));
    s->owner = f; ++f->refs; ++acquisitions;
    s->kind = f->kind; s->flags = s->status_flags = f->flags;
    s->pipe_id = f->context; s->mount_id = (uint64_t)f->context;
    s->path = f->path; s->sb = &mock_superblock; s->inode = f->inode;
    if (inject_fd == fd) {
        inject_fd = -1; close_slot(fd);
        (void)new_file(fd, "/replacement", 0, VFS_INODE_DIR | 0755);
    }
    return 0;
}
static int release(void *context, void *storage) {
    (void)context; edge_fd_t *s = storage;
    assert(s->owner); drop_file(s->owner); memset(s, 0, sizeof(*s)); ++releases; return 0;
}
static int transfer(void *context, void *destination, void *source) {
    (void)context; memcpy(destination, source, sizeof(edge_fd_t));
    memset(source, 0, sizeof(edge_fd_t)); return 0;
}
static int edge_linux_copy_user_string(edge_linux_syscall_context_t *ctx,
        uint64_t source, char *out, uint32_t capacity, int error) {
    (void)ctx;
    if (source == 1) return -EDGE_LINUX_EFAULT;
    const char *text = (const char *)(uintptr_t)source;
    size_t n = strlen(text);
    if (n >= capacity) return -error;
    memcpy(out, text, n + 1); return 0;
}
'''

TESTS = r'''
static int64_t file_range(void *context, void *storage,
                          const kernel_io_file_range_request_t *request) {
    (void)context;
    assert(request->operation == KERNEL_IO_FILE_RANGE_PATH_SNAPSHOT);
    return use_arm ? arm64_fd_operation_path_snapshot(storage, request->path_snapshot) :
                     x86_fd_operation_path_snapshot(storage, request->path_snapshot);
}
static const kernel_fd_backend_ops_t backend = {
    .table_limit = table_limit, .operation_acquire = acquire,
    .operation_release = release, .operation_transfer = transfer,
    .operation_file_range = file_range,
};
static int set_fd(int ctx, const char *key, int aux) {
    edge_linux_syscall_context_t c = {0};
    c.arguments[0] = (uint32_t)ctx; c.arguments[1] = KERNEL_MOUNT_API_SET_FD;
    c.arguments[2] = (uintptr_t)key; c.arguments[4] = (uint32_t)aux;
    return (int)edge_linux_fsconfig_set_fd(&c);
}
static void clear_slots(void) {
    for (int i = 0; i < 16; ++i) if (slots[i]) close_slot(i);
    assert(acquisitions == releases);
    assert(pages == 0);
}
static void rejection_tests(const char *filesystem) {
    int object = kernel_mount_api_context_create(filesystem); assert(object > 0);
    struct mock_file *context = new_file(0, "", object, 0);
    struct mock_file *directory = new_file(1, "/original", 0, VFS_INODE_DIR | 0755);
    assert(set_fd(0, "adefinitelynotexistingmountoption", 0) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "another_unknown_option", 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "another_unknown_option", 2) == -EDGE_LINUX_EBADF);
    assert(set_fd(0, "source", 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "ro", 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "mode", 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "key", -1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, 0, 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, (const char *)1, 1) == -EDGE_LINUX_EFAULT);
    char long_key[257];
    memset(long_key, 'x', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = 0;
    assert(set_fd(0, long_key, 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(1, "key", 0) == -EDGE_LINUX_EINVAL);
    assert(set_fd(15, "key", 0) == -EDGE_LINUX_EBADF);
    assert(context->refs == 1 && directory->refs == 1);
    assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_FLAG,
        "another_unknown_option", 0, 0, 0, 0) == -EDGE_LINUX_EINVAL);
    assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_FLAG,
        "usrquota", 0, 0, 0, 0) == -EDGE_LINUX_EINVAL);
    assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_FLAG,
        "memory_recursiveprot", 0, 0, 0, 0) == -EDGE_LINUX_EINVAL);
    if (strcmp(filesystem, "tmpfs") == 0) {
        assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_FLAG,
            "noswap", 0, 0, 0, 0) == 0);
        assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_STRING,
            "size", "16m", 0, 0, 0) == 0);
        assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_FLAG,
            "size", 0, 0, 0, 0) == -EDGE_LINUX_EINVAL);
        assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_STRING,
            "noswap", "yes", 0, 0, 0) == -EDGE_LINUX_EINVAL);
    }
    close_slot(1);
    assert(set_fd(0, "another_unknown_option", 1) == -EDGE_LINUX_EBADF);
    clear_slots();
}
static void accepted_close_reuse_test(int close_context) {
    int object = kernel_mount_api_context_create("overlay"); assert(object > 0);
    struct mock_file *context = new_file(0, "", object, 0);
    struct mock_file *directory = new_file(1, "/original", 0, VFS_INODE_DIR | 0755);
    unsigned directory_id = (unsigned)directory->id;
    unsigned context_id = (unsigned)context->id;
    inject_fd = close_context ? 0 : 1;
    assert(set_fd(0, "upperdir", 1) == 0);
    assert(inject_fd == -1);
    if (close_context) {
        /* The retained context survives close/reuse until syscall completion. */
        assert(destroyed[context_id] == 1);
        assert(directory->refs == 1);
        clear_slots(); return;
    }
    assert(!destroyed[directory_id] && directory->refs == 1);
    assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_CREATE,
        0, 0, 0, 0, 0) == 0);
    assert(set_fd(0, "workdir", 1) == -EDGE_LINUX_EBUSY);
    int mount = kernel_mount_api_context_mount(object, 0); assert(mount > 0);
    close_slot(0); /* The detached mount keeps the accepted directory alive. */
    assert(!destroyed[directory_id]);
    char target[] = "/target", workspace[4096];
    assert(kernel_mount_api_mount_attach(mount, target, workspace, sizeof(workspace)) == 0);
    assert(strcmp(captured_options, "upperdir=/original") == 0);
    kernel_mount_api_release(mount);
    assert(destroyed[directory_id] == 1);
    clear_slots();
}
static void replacement_and_failure_test(void) {
    int object = kernel_mount_api_context_create("overlay");
    new_file(0, "", object, 0);
    struct mock_file *first = new_file(1, "/first", 0, VFS_INODE_DIR | 0755);
    unsigned first_id = (unsigned)first->id;
    assert(set_fd(0, "upperdir", 1) == 0); close_slot(1);
    struct mock_file *second = new_file(1, "/second", 0, VFS_INODE_DIR | 0755);
    unsigned second_id = (unsigned)second->id;
    assert(set_fd(0, "upperdir", 1) == 0);
    assert(destroyed[first_id] == 1 && second->refs == 2);
    assert(set_fd(0, "workdir", 1) == 0 && second->refs == 3);
    assert(set_fd(0, "source", 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "lowerdir", 1) == -EDGE_LINUX_EINVAL);
    assert(set_fd(0, "workdir", 0) == -EDGE_LINUX_ENOTDIR);
    fail_page = 1;
    assert(set_fd(0, "workdir", 1) == -EDGE_LINUX_ENOMEM);
    assert(second->refs == 3);
    new_file(2, "/regular", 0, VFS_INODE_FILE | 0644);
    assert(set_fd(0, "upperdir", 2) == -EDGE_LINUX_ENOTDIR);
    new_file(3, "/injected,workdir=/bad", 0, VFS_INODE_DIR | 0755);
    assert(set_fd(0, "upperdir", 3) == -EDGE_LINUX_EINVAL);
    assert(kernel_mount_api_context_configure(object, KERNEL_MOUNT_API_SET_STRING,
        "upperdir", "/string", 0, 0, 0) == 0);
    assert(second->refs == 2); /* workdir still retains its own reference */
    close_slot(1); assert(!destroyed[second_id]);
    clear_slots(); assert(destroyed[second_id] == 1);
}
int main(void) {
    g_backend_ops = &backend;
    for (use_arm = 0; use_arm < 2; ++use_arm) {
        rejection_tests("tmpfs"); rejection_tests("cgroup2");
        accepted_close_reuse_test(0); accepted_close_reuse_test(1);
        replacement_and_failure_test();
        printf("fsconfig_fd_runtime_unit: %s PASS\n", use_arm ? "aarch64" : "x86_64");
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--review-dir", type=Path, required=True)
    args = parser.parse_args()
    output, review = args.output_dir.resolve(), args.review_dir.resolve()
    volume = Path("/Volumes/EdwardData")
    if not volume.is_mount() or not output.is_relative_to(volume / "EdgeOS"):
        parser.error("output must use mounted external EdgeOS storage")
    if not review.is_relative_to(ROOT.parent / ".repair-review"):
        parser.error("generated source must stay in internal .repair-review")
    output.mkdir(parents=True, exist_ok=True); review.mkdir(parents=True, exist_ok=True)
    linux = (ROOT / "src/kernel/linux_syscall.c").read_text()
    begin = linux.index("typedef struct edge_linux_mount_file_reference")
    end = linux.index("static int64_t edge_linux_sys_mount_context(", begin)
    source = PRELUDE.replace("LEGACY_TEST", str(ROOT / "tools/tests/mount_api_unit.c"))
    source = source.replace("FD_RUNTIME", str(ROOT / "src/kernel/fd_runtime.c"))
    source += function((ROOT / "src/sys/syscall_parts/process_mm_misc.c").read_text(),
                       "x86_fd_operation_path_snapshot")
    source += "\n" + function((ROOT / "src/arch/arm64/kernel/bootstrap_runtime.c").read_text(),
                              "arm64_fd_operation_path_snapshot")
    source += "\n" + linux[begin:end] + TESTS
    generated = review / "fsconfig_fd_runtime_unit.c"; generated.write_text(source)
    binary = output / "fsconfig_fd_runtime_unit"
    cmd = [os.environ.get("CC", "clang"), "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
           "-Werror", "-fno-builtin", "-ffunction-sections", "-fdata-sections",
           "-fsanitize=address,undefined", "-iquote", str(ROOT / "include"),
           str(generated), str(ROOT / "src/kernel/mount_api.c"), "-Wl,-dead_strip", "-o", str(binary)]
    subprocess.run(cmd, check=True)
    subprocess.run([str(binary)], check=True, env=dict(os.environ, UBSAN_OPTIONS="halt_on_error=1"))


if __name__ == "__main__":
    main()
