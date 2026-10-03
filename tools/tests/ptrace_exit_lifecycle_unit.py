#!/usr/bin/env python3
"""Exercise production ptrace exit policy, collection, and ARM wait consumption."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r'^(?:static )?[\w *]+\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    if not match:
        raise ValueError(name)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


PRELUDE = r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/linux_ptrace.h"
#include "kernel/process_runtime.h"
#include "kernel/linux_errno.h"
#define LINUX_EINVAL EDGE_LINUX_EINVAL
#define LINUX_ECHILD EDGE_LINUX_ECHILD
#define LINUX_SIGCHLD 17
#define LINUX_CLD_KILLED 2
#define LINUX_CLD_EXITED 1
#define TASK_ZOMBIE 4
#define TASK_UNUSED 0
#define TASK_BLOCKED 6
#define LINUX_SIG_IGN 1
#define LINUX_CLD_CONTINUED 6
#define LINUX_CLD_TRAPPED 4
#define LINUX_CLD_STOPPED 5
#define LINUX_SIGCONT 18
#define PROC_MAX_TASKS 3
#define PROCESS_WAIT_NOTHREAD KERNEL_PROCESS_WAIT_NOTHREAD
#define KERNEL_TASK_ZOMBIE TASK_ZOMBIE
#define KERNEL_TASK_UNUSED 0
#define KERNEL_TASK_EMBRYO 1
#define KERNEL_TASK_STOPPED 3
#define KERNEL_TASK_WAITING 5

typedef struct { uint64_t elr; } arch_user_frame_t;
typedef struct task {
    int pid, ppid, tgid, state, on_cpu, switch_pending;
    int exit_code, termination_signal, stop_signal, stop_reported;
    int continued_pending, uid, wait_pid, wait_options, wait_idtype;
    int child_wait_active, parent_tid;
    uint32_t reap_claimed;
    uint8_t wait_reaped;
    struct { uintptr_t handler; } signal_actions[64];
    uint32_t exit_signal;
    uint64_t ttbr0;
    void *fds;
    struct task *parent;
    arch_user_frame_t frame;
    edge_linux_ptrace_state_t ptrace;
} kernel_task_t;
typedef kernel_task_t task_t;
static kernel_task_t g_tasks[3];
static int kernel_task_view_from_task(const task_t *task, kernel_proc_task_view_t *view) {
    memset(view, 0, sizeof(*view)); view->tid = task->pid; return 0;
}
static unsigned g_task_high_water = 3, freed, notified, accounted;
static unsigned queued_events, wake_count, g_detached_zombie_reap_pending, mm_live_users;
static unsigned probe_reap_reset, protected_resets;
static kernel_task_t *running;
static jmp_buf blocked;
static int task_group_id(const kernel_task_t *t) { return t->tgid ? t->tgid : t->pid; }
static int process_tgid_of_task(const task_t *t) { return task_group_id(t); }
static task_t *process_current_task(void) { return running; }
static task_t *task_find_by_pid(int pid) {
    for (unsigned i = 0; i < g_task_high_water; ++i)
        if (g_tasks[i].pid == pid && g_tasks[i].state != TASK_UNUSED) return &g_tasks[i];
    return 0;
}
static unsigned scheduler_cpu_id(void) { return 0; }
static void scheduler_task_make_runnable(task_t *t, unsigned cpu) {
    (void)cpu; assert(t->state == TASK_BLOCKED); t->state = 2; ++wake_count;
}
static int process_queue_child_event(task_t *recipient, const task_t *child, int code, int status) {
    assert(recipient->pid == 10 && child->pid == 30);
    assert(code == LINUX_CLD_EXITED && status == 7);
    ++queued_events; return 1;
}
static void task_zero(kernel_task_t *t) { ++freed; t->state = KERNEL_TASK_UNUSED; }
static int scheduler_task_reap_ready(task_t *t) { return !t->on_cpu && !t->switch_pending; }
static int process_vm_owner_pid_of_task_raw(const task_t *t) { return task_group_id(t); }
static int process_vm_live_users_raw(int pid, const task_t *t) { (void)pid; (void)t; return mm_live_users; }
static void task_child_unlink(task_t *t) { t->parent = 0; }
static void task_release_unused_claimed(task_t *t) {
    assert(scheduler_task_reap_ready(t)); task_zero(t);
}
static void process_rusage_accumulate_reaped_child(task_t *a, task_t *t) { (void)a; (void)t; ++accounted; }
static void process_release_fds_if_last_user(task_t *t, const char *reason) { (void)t; (void)reason; }
static void task_vm_release(uint64_t root, kernel_task_t *t) { (void)root; (void)t; }
static void task_account_reaped_child(kernel_task_t *w, kernel_task_t *t) {
    (void)w; (void)t; ++accounted;
}
static int task_signal_send_child_event(int pid, const kernel_task_t *t, int code, int status) {
    (void)pid; (void)t; (void)code; (void)status; ++notified; return 0;
}
static int task_signal_send(int pid, unsigned signal) { (void)pid; (void)signal; ++notified; return 0; }
static void task_wake_natural_parent_zombie(kernel_task_t *t) { (void)t; }
static void task_wait_result_usage(const kernel_task_t *t, kernel_process_usage_t *u) {
    (void)t; memset(u, 0, sizeof(*u));
}
int edge_pid_namespace_global_to_visible(unsigned ns, int pid, int *out) {
    (void)ns; *out = pid; return 0;
}
static int task_wait_matches(const kernel_task_t *w, const kernel_task_t *t,
                             unsigned type, int id, unsigned flags) {
    (void)type; (void)id; (void)flags;
    return t->ptrace.tracer_pid == w->pid ||
        (t->pid == task_group_id(t) && t->ppid == task_group_id(w));
}
static void arch_copy_frame(arch_user_frame_t *d, const arch_user_frame_t *s) { *d = *s; }
static void task_state_set(kernel_task_t *t, int state) { t->state = state; }
static __attribute__((noreturn)) void task_resume_next(void) { longjmp(blocked, 1); }
'''

TESTS = r'''
static void reset(int thread) {
    memset(g_tasks, 0, sizeof(g_tasks)); freed = notified = accounted = 0;
    mm_live_users = g_detached_zombie_reap_pending = 0;
    probe_reap_reset = protected_resets = 0;
    g_tasks[0] = (kernel_task_t){ .pid=10, .tgid=10, .state=2 };
    g_tasks[1] = (kernel_task_t){ .pid=20, .tgid=20, .state=2 };
    g_tasks[2] = (kernel_task_t){ .pid=30, .tgid=thread ? 20 : 30,
        .ppid=20, .state=KERNEL_TASK_ZOMBIE, .exit_code=7,
        .exit_signal=thread ? 0 : LINUX_SIGCHLD };
    g_tasks[2].ptrace.tracer_pid = 10;
    running = &g_tasks[0];
}
int main(void) {
    kernel_process_wait_query_t q = { .flags=KERNEL_PROCESS_WAIT_EXITED | KERNEL_PROCESS_WAIT_NOHANG };
    kernel_process_wait_result_t r;
    kernel_proc_task_view_t proc_view;
    reset(1);
    /* Traced pthread slots survive both detached-collection entry points. */
    assert(!task_is_detached_zombie_candidate_raw(&g_tasks[2]));
    process_release_detached_zombie_thread(&g_tasks[2]);
    assert(!freed);
    assert(task_process_wait(&g_tasks[1], &q, &r, 0) == -LINUX_ECHILD);
    q.flags |= KERNEL_PROCESS_WAIT_NOREAP;
    assert(task_process_wait(&g_tasks[0], &q, &r, 0) == 1);
    assert(r.pid == 30 && r.status == (7u << 8) && !freed);
    q.flags &= ~KERNEL_PROCESS_WAIT_NOREAP;
    assert(task_process_wait(&g_tasks[0], &q, &r, 0) == 1 && freed == 1);
    assert(task_process_wait(&g_tasks[0], &q, &r, 0) == -LINUX_ECHILD);
    assert(!notified);
    /* A distinct tracer releases process status to the natural parent once. */
    reset(0);
    assert(task_process_wait(&g_tasks[1], &q, &r, 0) == 0);
    assert(task_process_wait(&g_tasks[0], &q, &r, 0) == 1);
    assert(!freed && notified == 1 && !g_tasks[2].ptrace.tracer_pid);
    assert(task_process_wait(&g_tasks[0], &q, &r, 0) == -LINUX_ECHILD);
    assert(task_process_wait(&g_tasks[1], &q, &r, 0) == 1 && freed == 1);
    assert(task_process_wait(&g_tasks[1], &q, &r, 0) == -LINUX_ECHILD);
    /* TRACEME has one wait owner; tracer detach reclaims thread zombies. */
    reset(0); g_tasks[2].ppid = 10;
    assert(task_process_wait(&g_tasks[0], &q, &r, 0) == 1 && freed == 1);
    reset(1); task_ptrace_release_zombie(&g_tasks[2]);
    assert(freed == 1 && !notified);
    reset(1); g_tasks[2].ptrace.tracer_pid = 0;
    assert(task_is_detached_zombie_candidate_raw(&g_tasks[2]));
    process_release_detached_zombie_thread(&g_tasks[2]);
    assert(freed == 1);
    /* A blocking traced wait replays SVC without reporting a false exit. */
    reset(0);
    g_tasks[2].state = 2;
    g_tasks[0].ptrace.tracer_pid = 99;
    g_tasks[0].ptrace.syscall_active = 1;
    q.flags = KERNEL_PROCESS_WAIT_EXITED;
    arch_user_frame_t frame = { .elr = 0x1004 };
    if (!setjmp(blocked)) {
        (void)task_process_wait(&g_tasks[0], &q, &r, &frame);
        abort();
    }
    assert(g_tasks[0].frame.elr == 0x1000);
    assert(g_tasks[0].ptrace.restart_syscall == 1);
    assert(g_tasks[0].state == KERNEL_TASK_WAITING && !freed);
    /* A pthread inherits ppid without a linked parent; tracer equals ppid. */
    reset(1); queued_events = wake_count = 0;
    g_tasks[2].ppid = 10;
    g_tasks[0].state = TASK_BLOCKED;
    g_tasks[0].child_wait_active = 1;
    assert(!g_tasks[2].parent && !g_tasks[2].exit_signal);
    terminal_notify(&g_tasks[2], 0);
    assert(queued_events == 1 && wake_count == 1);
    assert(g_tasks[0].state == 2);
    /* Terminal wait consumes tracer ownership before the live stack can go. */
    reset(1); g_tasks[2].ppid = 10; g_tasks[2].parent_tid = 10; g_tasks[2].on_cpu = 1;
    probe_reap_reset = 1;
    assert(process_wait_owns_child(&g_tasks[0], &g_tasks[2], 0));
    assert(arch_process_task_view_locked((uintptr_t)&g_tasks[2], &proc_view) == 0);
    assert(terminal_reap(&g_tasks[0], &g_tasks[2]) == 30);
    assert(arch_process_task_view_locked((uintptr_t)&g_tasks[2], &proc_view) == 1);
    assert(!freed && g_tasks[2].state == TASK_ZOMBIE);
    assert(!process_wait_owns_child(&g_tasks[0], &g_tasks[2], 0));
    assert(protected_resets == 1); probe_reap_reset = 0;
    assert(!g_tasks[2].ptrace.tracer_pid && g_detached_zombie_reap_pending);
    assert(task_is_detached_zombie_candidate_raw(&g_tasks[2]));
    g_tasks[2].on_cpu = 0; process_release_detached_zombie_thread(&g_tasks[2]);
    assert(freed == 1);
    /* A retained CLONE_VM leader also loses its already-consumed wait owner. */
    reset(0); g_tasks[2].ppid = 10; g_tasks[2].parent_tid = 10; mm_live_users = 1;
    probe_reap_reset = 1;
    assert(terminal_reap(&g_tasks[0], &g_tasks[2]) == 30);
    assert(!freed && !g_tasks[2].reap_claimed);
    assert(protected_resets == 1); probe_reap_reset = 0;
    assert(!process_wait_owns_child(&g_tasks[0], &g_tasks[2], PROCESS_WAIT_NOTHREAD));
    assert(!process_wait_owns_child(&g_tasks[0], &g_tasks[2], 0));
    assert(!g_tasks[2].ptrace.tracer_pid);
    mm_live_users = 0; task_release_unused(&g_tasks[2]);
    assert(freed == 1);
    puts("PTRACE_EXIT_LIFECYCLE_PASS");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, default=ROOT)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--notify-source', type=Path)
    p.add_argument('--reap-source', type=Path)
    a = p.parse_args()
    common = (a.source_root/'src/kernel/linux_ptrace.c').read_text()
    arm = (a.source_root/'src/arch/arm64/kernel/bootstrap_runtime.c').read_text()
    x86 = (a.source_root/'src/sys/process.c').read_text()
    code = PRELUDE
    for name in ('edge_linux_ptrace_state_reset', 'edge_linux_ptrace_exit_wait_action', 'edge_linux_ptrace_exit_is_deferred'):
        body = function(common, name)
        if name == 'edge_linux_ptrace_exit_wait_action' and 'int tracee_is_thread' not in body:
            body = body.replace('int32_t natural_parent_tgid)', 'int32_t natural_parent_tgid, int tracee_is_thread)')
        code += body + '\n'
    code += r"""
static void checked_ptrace_state_reset(edge_linux_ptrace_state_t *state) {
    edge_linux_ptrace_state_reset(state);
    if (probe_reap_reset && state == &g_tasks[2].ptrace) {
        uint32_t expected = 0;
        /* A collector racing ownership removal must fail to claim the slot. */
        assert(!__atomic_compare_exchange_n(&g_tasks[2].reap_claimed,
            &expected, 1u, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
        assert(expected == 1u);
        ++protected_resets;
    }
}
#define edge_linux_ptrace_state_reset checked_ptrace_state_reset
"""
    policy = (ROOT/'src/kernel/process_wait.c').read_text()
    for name in ('kernel_process_wait_exit_status', 'kernel_process_wait_stop_status', 'kernel_process_wait_continue_status'):
        code += function(policy, name) + '\n'
    reap_source = a.reap_source.read_text() if a.reap_source else x86
    for name in ('task_release_unused', 'process_wait_owns_child', 'task_is_detached_zombie_candidate_raw', 'process_release_detached_zombie_thread'):
        code += function(reap_source if name == 'task_release_unused' else x86, name) + '\n'
    for name in ('task_ptrace_exit_wait_action', 'task_ptrace_release_zombie', 'task_process_wait'):
        body = function(arm, name)
        if name == 'task_ptrace_exit_wait_action' and 'child->ppid);' in body:
            body = body.replace('child->ppid);', 'child->ppid, task_group_id(child) != child->pid);')
        code += body + '\n'
    notify_source = a.notify_source.read_text() if a.notify_source else x86
    for name in ('process_notify_parent_exit', 'process_notify_waiter_for_task'):
        code += function(notify_source, name) + '\n'
    start = notify_source.index('    if (notify_parent || edge_linux_ptrace_exit_is_deferred(&t->ptrace)) {')
    end = notify_source.index('    if (auto_reap) {', start)
    code += 'static void terminal_notify(task_t *t, int notify_parent) { task_t *parent = t->parent;\n'
    code += notify_source[start:end] + '}\n'
    reap_source = a.reap_source.read_text() if a.reap_source else x86
    wait = function(reap_source, 'process_wait_pid_rusage_uid_query_for_task')
    start = wait.index('            process_rusage_accumulate_reaped_child(account, t);')
    marker = '\n            edge_linux_ptrace_state_reset(&t->ptrace);'
    if marker in wait[:start]:
        start = wait.rindex(marker, 0, start)
    end = wait.index('            return reported;', start) + len('            return reported;')
    code += 'static int terminal_reap(task_t *account, task_t *t) { int reported=t->pid;\n'
    code += wait[start:end] + '}\n'
    code += function(x86, 'arch_process_task_view_locked') + '\n'
    code += TESTS
    a.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([os.environ.get('HOST_CC', 'clang'), '-x', 'c', '-', '-iquote', str(ROOT/'include'), '-O1', '-g', '-fsanitize=address,undefined', '-o', str(a.output)], input=code, text=True, check=True)
    subprocess.run([str(a.output)], check=True)


if __name__ == '__main__':
    main()
