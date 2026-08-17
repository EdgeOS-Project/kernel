/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS procfs task runtime unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdio.h>
#include <string.h>

#include "kernel/proc_maps.h"
#include "kernel/process_runtime.h"

#define TEST_TASKS 6u

typedef struct test_task {
    kernel_proc_task_view_t view;
    int used;
} test_task_t;

static test_task_t g_tasks[TEST_TASKS];
static int g_failures;
static uint64_t g_peak_resident_bytes;

uint64_t kernel_mm_resident_peak_observe(uint64_t address_space,
                                         uint64_t resident_bytes) {
    (void)address_space;
    if (resident_bytes > g_peak_resident_bytes)
        g_peak_resident_bytes = resident_bytes;
    return g_peak_resident_bytes;
}

uint64_t kernel_mm_lock_space_bytes(uint64_t address_space) {
    return address_space == 10u ? 8192u : 0u;
}

uint64_t arch_vm_address_space_resident_pages(uint64_t address_space) {
    return address_space == 10u ? 7u : 0u;
}

int kernel_proc_vma_account(int32_t pid,
                            kernel_proc_vma_accounting_t *accounting) {
    if (pid != 10 || !accounting) return -1;
    memset(accounting, 0, sizeof(*accounting));
    accounting->virtual_size_bytes = 0x4000u;
    accounting->data_size_bytes = 0x4000u;
    return 0;
}

int kernel_exec_file_snapshot(uint64_t handle,
                              struct vfs_superblock **superblock,
                              struct vfs_inode *inode) {
    (void)handle;
    (void)superblock;
    (void)inode;
    return -1;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static void initialize_task(uint32_t slot, int32_t tid, int32_t tgid,
                            int32_t ppid, kernel_proc_task_state_t state,
                            const char *comm) {
    test_task_t *task = &g_tasks[slot];
    memset(task, 0, sizeof(*task));
    task->used = 1;
    task->view.tid = tid;
    task->view.tgid = tgid;
    task->view.ppid = ppid;
    task->view.state = state;
    task->view.start_time_ticks = 123u + slot;
    task->view.memory_context_id = (uint64_t)tid;
    strncpy(task->view.comm, comm, sizeof(task->view.comm) - 1u);
}

int kernel_arch_proc_task_sample(uint32_t slot,
                                 kernel_proc_task_view_t *view) {
    if (!view || slot >= TEST_TASKS) return -1;
    if (!g_tasks[slot].used) return 1;
    *view = g_tasks[slot].view;
    return 0;
}

int kernel_arch_proc_task_lookup(int32_t tid,
                                 kernel_proc_task_view_t *view) {
    if (!view || tid <= 0) return -1;
    for (uint32_t slot = 0; slot < TEST_TASKS; ++slot) {
        if (g_tasks[slot].used && g_tasks[slot].view.tid == tid) {
            *view = g_tasks[slot].view;
            return 0;
        }
    }
    return -1;
}

int kernel_arch_proc_task_at_ordinal(uint32_t ordinal, int32_t *pid_out) {
    if (!pid_out) return -1;
    for (uint32_t slot = 0; slot < TEST_TASKS; ++slot) {
        int32_t tgid;

        if (!g_tasks[slot].used || g_tasks[slot].view.tid <= 0) continue;
        tgid = g_tasks[slot].view.tgid > 0 ?
            g_tasks[slot].view.tgid : g_tasks[slot].view.tid;
        if (g_tasks[slot].view.tid != tgid) continue;
        if (ordinal) {
            --ordinal;
            continue;
        }
        *pid_out = g_tasks[slot].view.tid;
        return 0;
    }
    return -1;
}

int kernel_arch_proc_thread_at_ordinal(int32_t tgid, uint32_t ordinal,
                                       int32_t *tid_out) {
    if (tgid <= 0 || !tid_out) return -1;
    for (uint32_t slot = 0; slot < TEST_TASKS; ++slot) {
        int32_t task_tgid;

        if (!g_tasks[slot].used || g_tasks[slot].view.tid <= 0) continue;
        task_tgid = g_tasks[slot].view.tgid > 0 ?
            g_tasks[slot].view.tgid : g_tasks[slot].view.tid;
        if (task_tgid != tgid) continue;
        if (ordinal) {
            --ordinal;
            continue;
        }
        *tid_out = g_tasks[slot].view.tid;
        return 0;
    }
    return -1;
}

uint32_t kernel_arch_proc_thread_group_count(int32_t tgid) {
    uint32_t threads = 0;

    for (uint32_t slot = 0; slot < TEST_TASKS; ++slot) {
        int32_t task_tgid;

        if (!g_tasks[slot].used || g_tasks[slot].view.tid <= 0) continue;
        task_tgid = g_tasks[slot].view.tgid > 0 ?
            g_tasks[slot].view.tgid : g_tasks[slot].view.tid;
        if (task_tgid == tgid) ++threads;
    }
    return threads;
}

int kernel_arch_proc_task_fs_snapshot(
    int32_t pid, char *cwd, uint32_t cwd_capacity,
    char *root, uint32_t root_capacity) {
    (void)pid;
    (void)cwd;
    (void)cwd_capacity;
    (void)root;
    (void)root_capacity;
    return -1;
}

int kernel_arch_proc_cgroup_attach(
    int32_t tid, int32_t tgid, uint32_t cgroup_id,
    int entire_thread_group) {
    (void)tid;
    (void)tgid;
    (void)cgroup_id;
    (void)entire_thread_group;
    return -1;
}

static void initialize_fixture(void) {
    memset(g_tasks, 0, sizeof(g_tasks));
    initialize_task(0, 0, 0, 0, KERNEL_PROC_TASK_SLEEPING, "init");
    initialize_task(1, 1, 1, 0, KERNEL_PROC_TASK_SLEEPING, "systemd");
    initialize_task(2, 11, 10, 1, KERNEL_PROC_TASK_SLEEPING, "worker");
    initialize_task(3, 10, 10, 1, KERNEL_PROC_TASK_RUNNING, "leader");
    initialize_task(5, 20, 20, 1, KERNEL_PROC_TASK_ZOMBIE, "zombie");
    g_tasks[3].view.usage.user_time_us = 23000u;
    g_tasks[3].view.usage.sys_time_us = 11000u;
    g_tasks[3].view.usage.minor_faults = 17u;
    g_tasks[3].view.usage.major_faults = 3u;
}

static void test_process_enumeration(void) {
    int32_t pid = -1;

    expect_true("first process skips pid zero",
                kernel_proc_task_at(0, &pid) == 0 && pid == 1);
    expect_true("second process is thread-group leader",
                kernel_proc_task_at(1, &pid) == 0 && pid == 10);
    expect_true("third process includes zombie leader",
                kernel_proc_task_at(2, &pid) == 0 && pid == 20);
    expect_true("process enumeration ends",
                kernel_proc_task_at(3, &pid) < 0);
}

static void test_thread_enumeration(void) {
    int32_t tid0 = -1;
    int32_t tid1 = -1;

    expect_true("thread group first member",
                kernel_proc_thread_at(10, 0, &tid0) == 0);
    expect_true("thread group second member",
                kernel_proc_thread_at(10, 1, &tid1) == 0);
    expect_true("thread group members are complete",
                ((tid0 == 10 && tid1 == 11) ||
                 (tid0 == 11 && tid1 == 10)));
    expect_true("thread enumeration ends",
                kernel_proc_thread_at(10, 2, &tid0) < 0);
}

static void test_snapshots(void) {
    kernel_proc_task_snapshot_t snapshot;
    uint32_t running = 0;
    uint32_t total = 0;

    expect_true("load omits pid zero",
                kernel_proc_task_load_snapshot(&running, &total) == 0 &&
                total == 4 && running == 1);
    expect_true("leader snapshot counts threads",
                kernel_proc_task_snapshot(10, &snapshot) == 0 &&
                snapshot.pid == 10 && snapshot.tgid == 10 &&
                snapshot.threads == 2 && snapshot.start_time_ticks == 126u &&
                snapshot.user_time_ticks == 2u &&
                snapshot.system_time_ticks == 1u &&
                snapshot.minor_faults == 17u &&
                snapshot.major_faults == 3u &&
                snapshot.virtual_size_bytes == 0x4000u &&
                snapshot.resident_size_bytes == 7u * 4096u &&
                snapshot.peak_resident_size_bytes == 7u * 4096u &&
                snapshot.locked_size_bytes == 8192u);
    expect_true("pid zero snapshot is rejected",
                kernel_proc_task_snapshot(0, &snapshot) < 0);
}

int main(void) {
    initialize_fixture();
    test_process_enumeration();
    test_thread_enumeration();
    test_snapshots();
    if (g_failures) return 1;
    puts("proc_task_unit: PASS");
    return 0;
}
