#!/usr/bin/env python3
"""Test real cgroup notification functions with the complete inotify core."""

import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    pattern = r"^(?:static\s+)?[\w\s*]+\b" + re.escape(name) + r"\([^;{}]*\)\s*\{"
    match = re.search(pattern, source, re.M)
    if not match:
        raise ValueError("function not found: " + name)
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


STUBS = r'''
/* Only unrelated mount installation, namespaces and task enumeration are mocked. */
static filesystem_ops_t g_cgroupfs_ops;
static cgroupfs_node_t test_nodes[CGROUPFS_MAX_NODES];
static unsigned wake_count;
static int check_callback_locks;
static int render_transition;
static int render_failure;
static uint32_t callback_node = 1;
static uint32_t callback_generation;
static vfs_superblock_t host_mount;
static vfs_inode_t events_inode;
static int cgroupfs_read(vfs_superblock_t *, vfs_inode_t *, uint32_t, void *, uint32_t);
static int cgroupfs_render(vfs_inode_t *, char *, uint32_t, uint32_t *);
static void cgroupfs_initialize(void) { assert(g_cgroupfs.initialized); }
edge_namespace_set_t *kernel_arch_current_namespace_set(void) { return 0; }
uint32_t edge_namespace_id(const edge_namespace_set_t *set, edge_namespace_kind_t kind) {
    (void)set; (void)kind; return 0;
}
int edge_cgroup_namespace_root(const edge_namespace_set_t *set, uint32_t *root) {
    (void)set; (void)root; return -1;
}
int vfs_mount_exists(const char *target, const char *fs, const char *dev) {
    (void)target; (void)fs; (void)dev; return 0;
}
int vfs_add_superblock(vfs_superblock_t *sb) { assert(sb); return 0; }
int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    memset(identity, 0, sizeof(*identity)); return 0;
}
int kernel_proc_task_at(uint32_t ordinal, int32_t *pid) {
    (void)ordinal; (void)pid; return -1;
}
int kernel_proc_thread_at(int32_t tgid, uint32_t ordinal, int32_t *tid) {
    (void)tgid; (void)ordinal; (void)tid; return -1;
}
int kernel_proc_task_snapshot(int32_t pid, kernel_proc_task_snapshot_t *out) {
    (void)pid; (void)out; return -1;
}
uint32_t kernel_bpf_cgroup_storage_owner_release(uint64_t reference) {
    (void)reference; return 0;
}
void kernel_bpf_cgroup_release(uint32_t node) { (void)node; }
void kernel_fanotify_notify_path(const char *path, uint32_t mask) {
    (void)path; (void)mask;
}
void kernel_fanotify_notify_move(const char *old_path, const char *new_path) {
    (void)old_path; (void)new_path;
}
void kernel_inotify_state_changed(int id) {
    assert(id >= 0);
    ++wake_count;
    if (check_callback_locks) {
        char buffer[32];
        assert(g_cgroupfs_lock.spin.v == 0);
        assert(g_cgroupfs_snapshot_lock.spin.v == 0);
        int result = cgroupfs_event_generation(
            KERNEL_FILE_DESCRIPTION_NOTIFY_CGROUP_EVENTS_BASE + callback_node,
            &callback_generation);
        assert(result == 0 || result == -EDGE_LINUX_EBADF);
        assert(cgroupfs_read(&host_mount, &events_inode, 0, buffer, sizeof(buffer)) >= 0);
    }
}
'''


TESTS = r'''
static const char host_path[] = "/sys/fs/cgroup/unit/cgroup.events";
static const char docker_mount[] = "/var/lib/docker/rootfs/overlayfs/test/sys/fs/cgroup";
static const char alias_path[] = "/private/alias/unit/cgroup.events";
static uint32_t record_masks[32];
static int32_t record_wds[32];
static unsigned record_count;

static int copy_record(void *context, uint64_t offset, const void *data, uint32_t length) {
    int32_t wd;
    uint32_t mask;
    (void)context; (void)offset;
    assert(length >= 16 && record_count < 32);
    memcpy(&wd, data, sizeof(wd)); memcpy(&mask, (const char *)data + 4, sizeof(mask));
    record_wds[record_count] = wd; record_masks[record_count++] = mask;
    return 0;
}
static unsigned drain(int id) {
    record_count = 0;
    for (;;) {
        int64_t result = kernel_inotify_read(id, copy_record, 0, 4096);
        if (result == -EDGE_LINUX_EAGAIN) return record_count;
        assert(result > 0);
    }
}
static unsigned queued(int id) {
    kernel_inotify_state_t state;
    assert(kernel_inotify_query(id, &state) == 0); return state.queued_events;
}
static void reset_group(uint32_t generation) {
    memset(test_nodes, 0, sizeof(test_nodes));
    for (unsigned i = 0; i < 2; ++i) {
        test_nodes[i].used = test_nodes[i].linked = 1;
        test_nodes[i].generation = i ? generation : 1;
        test_nodes[i].event_generation = 1;
    }
    strcpy(test_nodes[1].name, "unit");
    g_cgroupfs.nodes = test_nodes; g_cgroupfs.initialized = 1;
    callback_node = 1;
    assert(cgroupfs_mount("cgroup", "/sys/fs/cgroup") == 0);
    host_mount = g_cgroupfs_sb;
    cgroupfs_fill_inode(1, CGROUPFS_INODE_EVENTS, 0444, &events_inode);
}
static int bind_watch(int id, const char *path, uint32_t mask) {
#if TEST_BEFORE
    return kernel_inotify_add_watch(id, path, mask, 0);
#else
    return cgroupfs_inotify_add_watch(&host_mount, &events_inode, id, path, mask);
#endif
}
static int cgroupfs_render(vfs_inode_t *inode, char *buffer, uint32_t capacity,
                           uint32_t *size) {
    (void)inode;
    if (render_transition) {
        render_transition = 0;
        cgroupfs_adjust_task_count_locked(1, 1);
    }
    if (render_failure) { render_failure = 0; return -1; }
    assert(capacity >= 12); memcpy(buffer, "populated 0\n", 12); *size = 12;
    return 0;
}
static void mount_path_regression(void) {
    reset_group(2);
    int id = kernel_inotify_create(); assert(id >= 0);
    int wd = bind_watch(id, host_path, KERNEL_INOTIFY_MODIFY); assert(wd > 0);
    assert(cgroupfs_mount("cgroup", docker_mount) == 0);
    assert(strcmp(g_cgroupfs_sb.mountpoint, docker_mount) == 0);
    unsigned before = wake_count;
    check_callback_locks = 1;
    cgroupfs_task_join(1);
    if (queued(id) != 1) {
        fprintf(stderr, "FAIL: host-path watch lost after later Docker-path mount\n");
        exit(1);
    }
    assert(wake_count == before + 1 && drain(id) == 1);
    assert(record_wds[0] == wd && record_masks[0] == KERNEL_INOTIFY_MODIFY);
    cgroupfs_task_leave(1);
    assert(queued(id) == 1 && drain(id) == 1);
    assert(test_nodes[1].subtree_task_count == 0);
    kernel_inotify_release(id);
    puts("mount-path overwrite regression: PASS");
}

#if !TEST_BEFORE
static void alias_and_identity_tests(void) {
    reset_group(3);
    int id = kernel_inotify_create(); assert(id >= 0);
    int wd = bind_watch(id, host_path, KERNEL_INOTIFY_MODIFY); assert(wd > 0);
    assert(bind_watch(id, alias_path, KERNEL_INOTIFY_MODIFY | KERNEL_INOTIFY_MASK_CREATE)
           == -EDGE_LINUX_EEXIST);
    assert(bind_watch(id, alias_path, KERNEL_INOTIFY_MODIFY | KERNEL_INOTIFY_MASK_ADD) == wd);
    cgroupfs_task_join(1);
    assert(drain(id) == 1 && record_wds[0] == wd);
    /* Generic path publication must not duplicate an object notification. */
    kernel_inotify_notify_path(host_path, KERNEL_INOTIFY_MODIFY, 0);
    kernel_inotify_notify_path(alias_path, KERNEL_INOTIFY_MODIFY, 0);
    assert(queued(id) == 0);
    kernel_inotify_object_key_t key = cgroupfs_event_key_locked(1);
    kernel_inotify_object_key_t wrong = key;
    kernel_inotify_wake_set_t wakes = {0};
    wrong.backing = &host_mount;
    kernel_inotify_queue_object(&wrong, KERNEL_INOTIFY_MODIFY, &wakes);
    wrong = key; ++wrong.kind;
    kernel_inotify_queue_object(&wrong, KERNEL_INOTIFY_MODIFY, &wakes);
    wrong = key; ++wrong.generation;
    kernel_inotify_queue_object(&wrong, KERNEL_INOTIFY_MODIFY, &wakes);
    wrong = key; ++wrong.object_id;
    kernel_inotify_queue_object(&wrong, KERNEL_INOTIFY_MODIFY, &wakes);
    assert(queued(id) == 0);
    /* Retain an old watch while the allocation generation changes. */
    ++test_nodes[1].generation;
    kernel_inotify_queue_object(&wrong, KERNEL_INOTIFY_MODIFY, &wakes);
    cgroupfs_task_leave(1);
    assert(queued(id) == 0);
    assert(bind_watch(id, host_path, KERNEL_INOTIFY_MODIFY) == -EDGE_LINUX_ENOENT);
    cgroupfs_fill_inode(1, CGROUPFS_INODE_EVENTS, 0444, &events_inode);
    int new_wd = bind_watch(id, host_path, KERNEL_INOTIFY_MODIFY);
    assert(new_wd > 0 && new_wd != wd);
    cgroupfs_task_join(1);
    assert(drain(id) == 1 && record_wds[0] == new_wd);
    cgroupfs_task_leave(1); assert(drain(id) == 1);
    kernel_inotify_release(id);
    puts("alias, backing, kind and allocation-generation isolation: PASS");
}
static void deletion_and_snapshot_lock_tests(void) {
    reset_group(10);
    int id = kernel_inotify_create(); assert(id >= 0);
    int wd = bind_watch(id, host_path, KERNEL_INOTIFY_MODIFY | KERNEL_INOTIFY_DELETE_SELF);
    assert(wd > 0);
    char buffer[32];
    for (unsigned mode = 0; mode < 3; ++mode) {
        render_transition = 1; render_failure = mode == 2;
        int result = cgroupfs_read(&host_mount, &events_inode,
                                  mode == 1 ? 100 : 0, buffer, sizeof(buffer));
        assert(result == (mode == 2 ? -1 : mode == 1 ? 0 : 12));
        assert(drain(id) == 1);
        cgroupfs_task_leave(1); assert(drain(id) == 1);
    }
    assert(cgroupfs_rmdir(&host_mount, &host_mount.root, "unit") == 0);
    assert(drain(id) == 2);
    assert(record_wds[0] == wd && record_masks[0] == KERNEL_INOTIFY_DELETE_SELF);
    assert(record_wds[1] == wd && record_masks[1] == KERNEL_INOTIFY_IGNORED);
    assert(kernel_inotify_remove_watch(id, wd) == -EDGE_LINUX_EINVAL);
    kernel_inotify_release(id);
    puts("deletion and callbacks outside both cgroup locks: PASS");
}
static void ordinary_path_regression(void) {
    int id = kernel_inotify_create(); assert(id >= 0);
    int wd = kernel_inotify_add_watch(id, "/ordinary", KERNEL_INOTIFY_MODIFY, 0);
    assert(wd > 0);
    assert(kernel_inotify_add_watch(id, "/ordinary", KERNEL_INOTIFY_MASK_ADD |
                                   KERNEL_INOTIFY_CLOSE_WRITE, 0) == wd);
    kernel_inotify_notify_path("/ordinary", KERNEL_INOTIFY_MODIFY, 0);
    assert(drain(id) == 1 && record_wds[0] == wd);
    kernel_inotify_notify_path("/ordinary", KERNEL_INOTIFY_CLOSE_WRITE, 0);
    assert(drain(id) == 1 && record_masks[0] == KERNEL_INOTIFY_CLOSE_WRITE);
    kernel_inotify_release(id);
    puts("ordinary path watch regression: PASS");
}
#endif
int main(void) {
    mount_path_regression();
#if !TEST_BEFORE
    alias_and_identity_tests(); deletion_and_snapshot_lock_tests();
    ordinary_path_regression();
#endif
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--before-root", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    review = args.review_dir.resolve()
    if not review.is_relative_to(ROOT.parent / ".repair-review"):
        parser.error("generated source must remain in internal .repair-review")
    source_root = args.before_root.resolve() if args.before_root else ROOT
    cgroup = (source_root / "src/fs/cgroupfs.c").read_text()
    before = args.before_root is not None
    generated = "#include <assert.h>\n#include <stdio.h>\n#include <stdlib.h>\n"
    generated += "#define EDGEOS_HOST_TEST 1\n#define CONFIG_RUNTIME_CGROUP_NODES 16\n"
    generated += "#define TEST_BEFORE " + str(int(before)) + "\n"
    generated += cgroup[:cgroup.index("static const cgroupfs_interface_t g_cgroup_interfaces[]")]
    a = cgroup.index("static cgroupfs_state_t g_cgroupfs;")
    b = cgroup.index("static void cgroupfs_rebuild_task_counts_locked(void);", a)
    generated += cgroup[a:b] + STUBS
    names = ["cgroupfs_lock", "cgroupfs_node_valid", "cgroupfs_inode_node",
             "cgroupfs_fill_inode", "cgroupfs_append", "cgroupfs_append_u32"]
    if not before:
        names += ["cgroupfs_unlock_deferred"]
    names += ["cgroupfs_unlock"]
    names += (["cgroupfs_event_path_locked"] if before else
              ["cgroupfs_event_key_locked", "cgroupfs_queue_event_locked"])
    names += ["cgroupfs_note_population_locked", "cgroupfs_adjust_task_count_locked",
              "cgroupfs_task_join", "cgroupfs_task_leave", "cgroupfs_read",
              "cgroupfs_mount", "cgroupfs_event_generation"]
    if not before:
        names += ["cgroupfs_inotify_add_watch", "cgroupfs_valid_name",
                  "cgroupfs_find_child", "cgroupfs_is_descendant",
                  "cgroupfs_descendant_count", "cgroupfs_node_has_tasks",
                  "cgroupfs_reclaim_unlinked_node_locked", "cgroupfs_rmdir"]
    generated += "\n".join(function(cgroup, name) for name in names) + TESTS
    review.mkdir(parents=True, exist_ok=True)
    label = "cgroup_inotify_before" if before else "cgroup_inotify_object_unit"
    test_source = review / (label + ".c")
    test_source.write_text(generated)
    if args.prepare_only:
        print(test_source)
        return
    volume = Path("/Volumes/EdwardData")
    if not volume.is_mount() or not output.is_relative_to(volume / "EdgeOS"):
        parser.error("test outputs require mounted external EdgeOS storage")
    output.mkdir(parents=True, exist_ok=True)
    command = [os.environ.get("CC", "clang"), "-std=c11", "-O1", "-g",
               "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
               "-Wno-unused-variable", "-fno-builtin", "-fsanitize=address,undefined",
               "-iquote", str(source_root / "include"), "-iquote", str(ROOT / "include"),
               str(test_source), str(source_root / "src/kernel/inotify.c"),
               "-o", str(output / label)]
    subprocess.run(command, check=True, env=dict(os.environ, TMPDIR=str(output)))
    result = subprocess.run([str(output / label)],
                            env=dict(os.environ, UBSAN_OPTIONS="halt_on_error=1"))
    if before:
        if result.returncode != 1:
            raise SystemExit("pre-fix source must fail the mount-path assertion")
        print("pre-fix negative regression: expected failure")
    else:
        result.check_returncode()


if __name__ == "__main__":
    main()
