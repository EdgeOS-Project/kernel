#!/usr/bin/env python3
"""Run the full production deadline wake with deterministic owner-lock races."""
import argparse
from pathlib import Path
import subprocess
ROOT = Path(__file__).resolve().parents[2]
PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define SCHED_MAX_CPUS 4
#define TASK_UNUSED 0
#define TASK_RUNNING 1
#define TASK_BLOCKED 2
#define TASK_STOPPED 3
#define TASK_RUNNABLE 4
#define TASK_ZOMBIE 5
#define SCHED_CONTEXT_WAKE 1
#define EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US 1000
struct task {
    int state, assigned_cpu, switch_pending, on_cpu, on_runqueue, context_ready;
    int sleep_wait_active, scheduler_vruntime_valid, cgroup_id, need_resched;
    uint64_t sleep_deadline_us, scheduler_migrations, scheduler_vruntime_us;
    uint64_t rusage_run_start_us, syscall_interrupt_notify, scheduler_entity;
};
typedef struct task task_t;
typedef struct { task_t *current; int rq_lock; uint64_t migrations; } scheduler_cpu_t;
typedef struct { int policy; } edge_linux_scheduler_state_t;
static scheduler_cpu_t cpus[4];
static task_t task;
static int locked = -1, scenario, notifications, placements;
static uint64_t spin_lock_irqsave(int *lock) {
    assert(locked == -1); locked = *lock;
    if (scenario == 1) { task.state = TASK_RUNNING; scenario = 0; }
    if (scenario == 2) { task.sleep_deadline_us = 900u; scenario = 0; }
    if (scenario == 3) { task.assigned_cpu = 2; scenario = 0; }
    return 0;
}
static void spin_unlock_irqrestore(int *lock, uint64_t flags) {
    (void)flags; assert(locked == *lock); locked = -1;
}
static scheduler_cpu_t *cpu_by_id(unsigned id) { assert(id < 4); return &cpus[id]; }
static unsigned scheduler_cpu_id(void) { return 0; }
static int scheduler_task_ptr_valid(task_t *t) { return t == &task; }
static int scheduler_task_is_idle(task_t *t) { (void)t; return 0; }
static unsigned scheduler_select_allowed_cpu(task_t *t, unsigned cpu, int wake) {
    (void)t; placements += wake ? 100 : 1; return cpu;
}
static void rq_push_tail_locked(scheduler_cpu_t *cpu, task_t *t) {
    assert(locked == cpu->rq_lock && locked == t->assigned_cpu);
    t->on_runqueue = 1;
}
static void rq_remove_locked(scheduler_cpu_t *cpu, task_t *t) {
    assert(locked == cpu->rq_lock); t->on_runqueue = 0;
}
static int edge_smp_reschedule(unsigned cpu) {
    assert(locked == -1 && cpu != 0); ++notifications; return 0;
}
#define scheduler_log_bad_task_ptr(...) ((void)0)
#define scheduler_repair_idle_marker(...) ((void)0)
#define scheduler_place_wakeup_locked(cpu,t,wake) assert(locked == (cpu)->rq_lock)
#define scheduler_account_run_start(...) ((void)0)
#define rq_recover_stranded_locked(...) ((void)0)
#define scheduler_min_vruntime_locked(cpu) ((uint64_t)0)
#define scheduler_context_event(...) ((void)0)
#define scheduler_counter_add(counter,value) (*(counter) += (value))
#define edge_linux_scheduler_rebase_vruntime(v,a,b) (v)
#define boottime_monotonic_us() ((uint64_t)500)
#define scheduler_effective_state(t,out) ((out)->policy = 0)
#define edge_linux_scheduler_entity_slice_runtime_us(a,b,c) (c)
#define edge_linux_scheduler_state_compare(a,b) (0)
#define edge_linux_scheduler_policy_is_fair(p) (0)
#define cgroupfs_cpu_group_order(a,b) (0)
#define edge_linux_scheduler_fair_wakeup_preempts(...) (0)
#define edge_linux_scheduler_entity_precedes(...) (0)
#define sched_log_cpu(...) ((void)0)
#define sched_invariant_check(...) ((void)0)
'''
TEST = r'''
static void reset(void) {
    memset(&task, 0, sizeof(task));
    for (int i = 0; i < 4; ++i) cpus[i].rq_lock = i;
    task.state = TASK_BLOCKED; task.assigned_cpu = 1;
    task.sleep_wait_active = 1; task.sleep_deadline_us = 500;
    task.context_ready = 1;
    scenario = notifications = placements = 0;
}
int main(void) {
    reset(); scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.state == TASK_RUNNABLE && task.on_runqueue && !task.sleep_wait_active);
    assert(task.assigned_cpu == 1 && notifications == 1 && placements == 0);
    scheduler_task_wake_sleep_deadline(&task, 500);
    assert(notifications == 1);
    reset(); scenario = 1; scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.state == TASK_RUNNING && task.sleep_wait_active && !notifications);
    reset(); scenario = 2; scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.state == TASK_BLOCKED && task.sleep_deadline_us == 900 && task.sleep_wait_active);
    reset(); scenario = 3; scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.assigned_cpu == 2 && task.on_runqueue && notifications == 1);
    reset(); task.on_cpu = 1; scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.state == TASK_RUNNING && !task.on_runqueue && !task.sleep_wait_active);
    reset(); task.switch_pending = 1; scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.state == TASK_RUNNABLE && task.on_runqueue && !task.sleep_wait_active);
    reset(); task.state = TASK_ZOMBIE; scheduler_task_wake_sleep_deadline(&task, 500);
    assert(task.state == TASK_ZOMBIE && !task.on_runqueue && !notifications);
    reset(); task.sleep_wait_active = 0;
    scheduler_task_make_runnable_local(&task);
    assert(task.state == TASK_RUNNABLE && task.assigned_cpu == 0);
    assert(placements == 1 && notifications == 0);
    reset(); task.sleep_wait_active = 0;
    scheduler_task_make_runnable(&task, 0);
    assert(task.state == TASK_RUNNABLE && task.assigned_cpu == 0);
    assert(placements == 100 && notifications == 0);
    assert(locked == -1);
    puts("scheduler_sleep_deadline_unit: PASS");
}
'''
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output-dir', required=True, type=Path)
a = p.parse_args(); out = a.output_dir.resolve()
assert Path('/Volumes/EdwardData').is_mount() and str(out).startswith('/Volumes/EdwardData/EdgeOS/')
out.mkdir(parents=True, exist_ok=True)
s = (ROOT/'src/sys/scheduler.c').read_text()
s = s[s.index('static void scheduler_task_make_runnable_checked('):s.index('void scheduler_task_set_blocked(')]
generated = ROOT/'.repair-review/desktop-kernel-fixes-20260910/scheduler_sleep_deadline_unit.c'
generated.parent.mkdir(parents=True, exist_ok=True)
generated.write_text(PRELUDE+s+TEST)
binary = out/'scheduler_sleep_deadline_unit'
subprocess.run(['cc','-std=c11','-O1','-g','-fsanitize=address,undefined',str(generated),'-o',str(binary)],check=True)
subprocess.run([str(binary)],check=True)
