#!/usr/bin/env python3
"""Compile production x86 wait functions with deterministic timer interleavings."""

import argparse
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    text = (ROOT / source).read_text()
    start = text.rfind("\n", 0, text.index(name)) + 1
    opening = text.index("{", text.index(name, start))
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define TASK_UNUSED 0
#define TASK_RUNNING 1
#define TASK_BLOCKED 2
#define TASK_ZOMBIE 3
#define PROC_MAX_TASKS 1
#define CONFIG_USB 1

typedef struct {
    int pid, is_idle, state, assigned_cpu;
    const char *name;
    uint64_t sleep_deadline_us, last_syscall_nr, last_syscall_ret;
    int sleep_wait_active, fd_wait_active;
} task_t;
typedef int (*fd_wait_post_block_fn)(void *);
static task_t task;
static uint64_t now;
static int inject, signal_ready, object_ready, yields, wakes, checks;
static int g_sleep_trace_budget, g_gui_wait_block_trace_budget;
static void sleep_waiters_irq_poll(void);
static uint64_t boottime_monotonic_us(void) { return now; }
static task_t *process_current_task(void) { return &task; }
static const task_t *process_task_by_index(int i) { return i ? 0 : &task; }
static unsigned scheduler_cpu_id(void) { return 0; }
static void task_timer_poll(void) { }
static void scheduler_task_make_runnable(task_t *t, unsigned cpu) {
    (void)cpu; t->state = TASK_RUNNING; ++wakes;
}
static void scheduler_task_wake_sleep_deadline(task_t *t, uint64_t deadline) {
    if (t->state != TASK_BLOCKED || !t->sleep_wait_active ||
        t->sleep_deadline_us != deadline) return;
    t->sleep_wait_active = 0; t->sleep_deadline_us = 0;
    scheduler_task_make_runnable(t, 0);
}
static uint64_t kernel_wait_deadline_min(uint64_t a, uint64_t b) {
    return !a ? b : !b ? a : a < b ? a : b;
}
static void kernel_wait_deadline_request(uint64_t deadline) { (void)deadline; }
#define EDGE_DRM_TIMING_DEADLINE_WAKE 9
#define EDGE_DRM_TIMING_WAKE_RESULT 10
#define edge_drm_timing_probe_wait_event(...) ((void)0)
static void expire(void) {
    assert(task.sleep_wait_active);
    now = task.sleep_deadline_us;
    sleep_waiters_irq_poll();
}
static void scheduler_task_set_blocked(task_t *t) {
    if (inject == 1) expire();
    t->state = TASK_BLOCKED;
    if (inject == 2) expire();
}
static void scheduler_yield(void) {
    ++yields;
    if (task.state == TASK_BLOCKED) {
        /* A blocked task without a timer, signal, or producer is stranded. */
        assert(task.sleep_wait_active);
        expire();
    }
    assert(task.state == TASK_RUNNING);
}
static int signal_pending_interrupt(void) { return signal_ready; }
static int signal_pending_wait_wakeup(task_t *t) { (void)t; return signal_ready; }
static int waiter_task_ready_after_block(int pid) { (void)pid; return object_ready; }
static uint64_t tty_interrupt_current_ret(void) { return (uint64_t)-EINTR; }
static void lwip_stack_poll(void) { }
static void usb_poll(void) { }
static void keyboard_poll_controller(void) { }
static void wait_blocking_step(void) { assert(0); }
static int gui_diag_task(task_t *t) { (void)t; return 0; }
static void waiter_remove_pid(int pid) { (void)pid; }
'''

TESTS = r'''
static void reset(int interleaving) {
    memset(&task, 0, sizeof(task));
    task.pid = 1; task.name = "wait-test"; task.state = TASK_RUNNING;
    now = 100; inject = interleaving;
    signal_ready = object_ready = yields = wakes = checks = 0;
}
static int ready_callback(void *context) {
    assert(task.state == TASK_BLOCKED);
    ++checks;
    return *(int *)context;
}
int main(void) {
    reset(0);
    task.sleep_wait_active = 1; task.sleep_deadline_us = 100;
    sleep_waiters_irq_poll();
    assert(task.sleep_wait_active && task.sleep_deadline_us == 100);
    task.state = TASK_BLOCKED;
    sleep_waiters_irq_poll();
    assert(task.state == TASK_RUNNING && !task.sleep_wait_active);
    for (int mode = 0; mode < 3; ++mode) {
        reset(mode);
        assert(do_sys_sleep_until_us(200) == 0);
        assert(now >= 200 && yields == 1 && wakes >= 1);
        assert(!task.sleep_wait_active && !task.sleep_deadline_us);
        reset(mode);
        socket_blocking_wait_step_checked(200, 0, 0);
        assert(now >= 200 && yields == 1 && wakes >= 1);
        assert(!task.sleep_wait_active && !task.fd_wait_active);
    }
    reset(0);
    socket_blocking_wait_step_checked(50, 0, 0);
    assert(now == 100 && wakes == 1);
    reset(0);
    assert(do_sys_sleep_until_us(50) == 0 && yields == 0);
    reset(0);
    signal_ready = 1;
    assert((int64_t)do_sys_sleep_until_us(200) == -EINTR);
    assert(yields == 0);
    socket_blocking_wait_step_checked(0, 0, 0);
    assert(wakes == 1 && !task.sleep_wait_active);
    reset(0);
    object_ready = 1;
    socket_blocking_wait_step_checked(0, 0, 0);
    assert(wakes == 1);
    reset(0);
    int ready = 1;
    socket_blocking_wait_step_checked(0, ready_callback, &ready);
    assert(wakes == 1 && checks == 1);
    reset(0);
    /* An edge-triggered callback overrides unrelated level readiness. */
    ready = 0; object_ready = 1;
    socket_blocking_wait_step_checked(200, ready_callback, &ready);
    assert(now == 200 && checks == 1);
    puts("wait_timeout_race_unit: PASS");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    volume = Path("/Volumes/EdwardData")
    if not volume.is_mount() or not output.is_relative_to(volume / "EdgeOS"):
        parser.error("output must be on mounted /Volumes/EdwardData/EdgeOS")
    output.mkdir(parents=True, exist_ok=True)
    source = PRELUDE + "\n".join([
        function("src/sys/syscall_parts/fd_tty_ipc.c", "kernel_wait_deadline_poll(void)"),
        function("src/sys/syscall_parts/fd_tty_ipc.c", "sleep_waiters_irq_poll(void)"),
        function("src/sys/syscall_parts/fd_tty_ipc.c", "socket_blocking_wait_step_checked("),
        function("src/sys/syscall_parts/fs_fd.c", "do_sys_sleep_until_us("),
    ]) + TESTS
    generated = ROOT / ".repair-review/desktop-kernel-fixes-20260910/wait_timeout_race_unit.c"
    generated.parent.mkdir(parents=True, exist_ok=True)
    binary = output / "wait_timeout_race_unit"
    generated.write_text(source)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall",
                    "-Wextra", "-Werror", str(generated), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
