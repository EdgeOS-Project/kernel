#!/usr/bin/env python3
"""Run production task-exit policy against blocked callback lifetimes."""

import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(text, name):
    match = re.search(r"^(?:static )?(?:int|void) " + name + r"\([^;]*?\)\s*\{", text, re.M)
    if not match:
        raise ValueError("Function definition missing: " + name)
    start = match.start()
    end = match.end()
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define PROC_MAX_TASKS 6
#define EDGE_X11_TRACE 0
#define TASK_UNUSED 0
#define TASK_RUNNING 1
#define TASK_BLOCKED 2
#define TASK_STOPPED 3
#define TASK_ZOMBIE 4

typedef struct resource { int value; int borrowed; } resource_t;
typedef struct task {
    int pid, tgid, ppid, state, assigned_cpu, group_exit_code, is_idle;
    uint8_t group_exit_pending, on_cpu, switch_pending, in_syscall;
    uint8_t kernel_continuation_active;
    const char *name;
    resource_t *resource;
    unsigned finished, notified, wakes;
    uint64_t user_us, system_us, run_start;
} task_t;
static task_t g_tasks[PROC_MAX_TASKS];
static task_t *current;
static int g_desktop_child_trace_budget;
static unsigned freed, cleanup, ipis;
static uint64_t now;
static jmp_buf exit_boundary;
static task_t *process_current_task(void) { return current; }
static unsigned scheduler_cpu_id(void) { return 0; }
static int edge_smp_reschedule(unsigned cpu) { assert(cpu == 1); ++ipis; return 0; }
static int process_desktop_trace_task(const task_t *t) { (void)t; return 0; }
static task_t *task_find_by_pid(int pid) {
    for (unsigned i = 0; i < PROC_MAX_TASKS; ++i)
        if (g_tasks[i].pid == pid && g_tasks[i].state != TASK_UNUSED) return &g_tasks[i];
    return 0;
}
static void scheduler_task_make_runnable(task_t *t, unsigned cpu) {
    (void)cpu; assert(t->group_exit_pending); ++t->wakes; t->state = TASK_RUNNING;
}
static void scheduler_account_current_mode_switch(void) {
    if (current->in_syscall) current->system_us += now - current->run_start;
    else current->user_us += now - current->run_start;
    current->run_start = now;
}
static void process_finish_task_exit(task_t *t, int code, const char *reason, int notify) {
    (void)code; (void)reason;
    if (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE) return;
    if (t->resource) {
        /* Teardown must not invalidate a resource held by a suspended callback. */
        assert(t->resource->borrowed == 0);
        assert(cleanup == 1);
        free(t->resource); t->resource = 0; ++freed;
    }
    if (t == current) scheduler_account_current_mode_switch();
    ++t->finished; t->notified += notify; t->state = TASK_ZOMBIE;
}
static void process_exit_current(int code) {
    process_finish_task_exit(current, code, "exit", current->tgid == current->pid);
}
static void scheduler_yield(void) {
    assert(current->state == TASK_ZOMBIE);
    longjmp(exit_boundary, 1);
}
'''

TESTS = r'''
static void reset(void) {
    memset(g_tasks, 0, sizeof(g_tasks)); freed = cleanup = ipis = 0; now = 0;
    for (unsigned i = 0; i < 4; ++i) {
        g_tasks[i].pid = 10 + (int)i;
        g_tasks[i].tgid = i ? 11 : 10;
        g_tasks[i].state = TASK_RUNNING;
        g_tasks[i].name = "test";
    }
    current = &g_tasks[0];
}
static void test_blocked_callback(int standalone, int return_work) {
    reset();
    task_t *worker = &g_tasks[2];
    if (standalone) {
        g_tasks[1].state = g_tasks[3].state = TASK_UNUSED;
        worker->tgid = worker->pid;
    }
    worker->resource = malloc(sizeof(*worker->resource));
    assert(worker->resource);
    *worker->resource = (resource_t){42, 1};
    resource_t *retained = worker->resource;
    current = worker; worker->on_cpu = 1; now = 3;
    syscall_begin_kernel_continuation(worker);
    assert(worker->in_syscall && worker->kernel_continuation_active);
    if (return_work) {
        /* The early dispatcher exit check already passed; a later pump blocks. */
        assert(!process_current_group_exit_requested(0));
    }
    now = 8; scheduler_account_current_mode_switch();
    worker->state = TASK_BLOCKED; worker->on_cpu = 0;
    current = &g_tasks[0]; current->on_cpu = 1;
    assert(process_kill_pid(standalone ? worker->pid : g_tasks[1].pid, 137) == 0);
    assert(worker->state == TASK_RUNNING && worker->wakes == 1);
    assert(worker->group_exit_pending && worker->group_exit_code == 137);
    assert(!worker->finished && !freed && retained->value == 42);
    if (!standalone) {
        assert(g_tasks[1].finished == 1 && g_tasks[1].notified == 1);
        assert(g_tasks[3].finished == 1 && !g_tasks[3].notified);
        /* Existing wait policy cannot reap the leader while this peer lives. */
        assert(process_thread_group_has_other_live(&g_tasks[1], g_tasks[1].tgid));
    }
    current = worker; worker->on_cpu = 1; now = 508; worker->run_start = now;
    assert(retained->value == 42);
    retained->borrowed = 0; ++cleanup; /* callback finally releases its borrow */
    now = 518;
    if (!setjmp(exit_boundary)) {
        syscall_finish_kernel_continuation(worker);
        assert(0 && "deferred exit returned to userspace");
    }
    assert(worker->finished == 1 && freed == 1 && cleanup == 1);
    assert(worker->notified == (unsigned)standalone);
    assert(worker->user_us == 3 && worker->system_us == 15);
    assert(!process_thread_group_has_other_live(&g_tasks[1], 11));
}
static void test_guards(void) {
    reset(); task_t *t = &g_tasks[2];
    assert(!process_task_exit_must_defer(t, current));
    t->on_cpu = 1; assert(process_task_exit_must_defer(t, current)); t->on_cpu = 0;
    t->switch_pending = 1; assert(process_task_exit_must_defer(t, current)); t->switch_pending = 0;
    t->kernel_continuation_active = 1; t->in_syscall = 0;
    t->state = TASK_BLOCKED;
    assert(process_task_exit_must_defer(t, current));
    t->state = TASK_STOPPED;
    assert(process_task_exit_must_defer(t, current));
    assert(!process_task_exit_must_defer(t, t));
    t->on_cpu = 1; t->assigned_cpu = 1; t->state = TASK_RUNNING;
    process_request_task_group_exit(t, 9); assert(ipis == 1);
    t->on_cpu = 0; t->state = TASK_STOPPED;
    process_request_task_group_exit(t, 9); assert(t->wakes == 1);
}
static void test_normal_return_and_self_exit(void) {
    reset(); now = 4;
    syscall_begin_kernel_continuation(current); now = 14;
    syscall_finish_kernel_continuation(current);
    assert(!current->in_syscall && !current->kernel_continuation_active);
    assert(current->user_us == 4 && current->system_us == 10);
    assert(!current->finished);
    syscall_begin_kernel_continuation(current);
    assert(process_kill_pid(current->pid, 0) == 0);
    assert(current->finished == 1); /* self exit is not deferred */
}
int main(void) {
    test_blocked_callback(0, 0);
    test_guards();
    test_blocked_callback(0, 1);
    test_blocked_callback(1, 1);
    test_normal_return_and_self_exit();
    puts("process_exit_continuation_unit: PASS");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--process-source", type=Path, default=ROOT / "src/sys/process.c")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    review = args.review_dir.resolve()
    volume = Path("/Volumes/EdwardData")
    if not volume.is_mount() or not output.is_relative_to(volume / "EdgeOS"):
        parser.error("output must be on mounted /Volumes/EdwardData/EdgeOS")
    if not review.is_relative_to(ROOT.parent / ".repair-review"):
        parser.error("generated source must be inside the internal .repair-review directory")
    output.mkdir(parents=True, exist_ok=True)
    review.mkdir(parents=True, exist_ok=True)
    process = args.process_source.read_text()
    dispatch = (ROOT / "src/sys/syscall_parts/dispatch.c").read_text()
    body = function(dispatch, "edgeos_x86_64_syscall_dispatch")
    assert body.index("syscall_begin_kernel_continuation(cur)") < body.index("edge_linux_ptrace_syscall_enter(")
    assert body.rindex("syscall_finish_kernel_continuation(cur)") > body.index("syscall_maybe_pump_fbdev_mmap()")
    assert "in_syscall = 0" not in body
    names = ["process_tgid_of_task", "process_task_live", "process_thread_group_has_other_live",
             "process_task_group_exit_requested", "process_current_group_exit_requested",
             "process_request_task_group_exit", "process_task_exit_must_defer",
             "process_kill_thread_group", "process_exit_current_group", "process_kill_pid"]
    source = PRELUDE + "\n".join(function(process, name) for name in names)
    source += "\n" + function(dispatch, "syscall_begin_kernel_continuation")
    source += "\n" + function(dispatch, "syscall_finish_kernel_continuation") + TESTS
    generated = review / "process_exit_continuation_unit.c"
    binary = output / "process_exit_continuation_unit"
    generated.write_text(source)
    subprocess.run([os.environ.get("CC", "clang"), "-std=c11", "-O1", "-g", "-Wall",
                    "-Wextra", "-Werror", "-fsanitize=address,undefined", str(generated),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True,
                   env=dict(os.environ, UBSAN_OPTIONS="halt_on_error=1"))


if __name__ == "__main__":
    main()
