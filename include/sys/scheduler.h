#ifndef SYS_SCHEDULER_H
#define SYS_SCHEDULER_H

#include <stdint.h>
#include "sys/process.h"
#include "sys/spinlock.h"

#ifdef CONFIG_NR_CPUS
#define SCHED_MAX_CPUS CONFIG_NR_CPUS
#else
#define SCHED_MAX_CPUS 64
#endif

typedef struct scheduler_cpu {
    task_t *current;
    task_t *idle;
    task_t *rq_head;
    task_t *rq_tail;
    task_t *retired;
    spinlock_t rq_lock;
    uint32_t logical_id;
    volatile uint32_t nr_running;
    volatile uint64_t user_time_us;
    volatile uint64_t system_time_us;
    volatile uint64_t runqueue_wait_us;
    volatile uint64_t context_switches;
    volatile uint64_t migrations;
} __attribute__((aligned(64))) scheduler_cpu_t;

void scheduler_init(void);
void scheduler_set_cpu_id(uint32_t logical_id);
uint32_t scheduler_cpu_id(void);
uint64_t scheduler_online_cpu_mask(void);
uint32_t scheduler_pick_target_cpu(uint64_t affinity_mask);
uint64_t scheduler_kernel_cr3(void);
uint64_t scheduler_idle_stack_top(uint32_t logical_id);
void scheduler_secondary_enter(uint32_t logical_id)
    __attribute__((noreturn));
task_t *scheduler_current_task(void);
scheduler_cpu_t *scheduler_cpu_local(void);
int scheduler_task_is_idle(const task_t *t);
void scheduler_set_boot_current(task_t *t);
void scheduler_task_context_ready(task_t *t);
void scheduler_task_make_runnable(task_t *t, uint32_t cpu_id);
void scheduler_task_set_blocked(task_t *t);
void scheduler_task_set_stopped(task_t *t);
void scheduler_task_set_zombie(task_t *t);
void scheduler_task_set_unused(task_t *t);
void scheduler_task_set_running(task_t *t);
int scheduler_task_reap_ready(task_t *t);

/* Called by platform timer interrupt (PIC today, LAPIC per-CPU in SMP bring-up). */
void scheduler_tick(void);
void scheduler_account_current_mode_switch(void);
void scheduler_request_deferred_work(void);
int scheduler_take_deferred_work(void);
void scheduler_yield(void);
void scheduler_yield_from_irq(void);
void scheduler_kill_current_and_yield(int code);
void scheduler_kill_current_group_and_yield(int code);
void scheduler_abandon_current_and_yield(int code);
int scheduler_fault_in_switch_window(uint64_t rip);
int scheduler_handle_context_watch(uint64_t rip, uint64_t cs, uint64_t rsp,
                                   uint64_t rdi, uint64_t rsi, uint64_t rdx,
                                   uint64_t rcx, uint64_t rax, uint64_t rbp);
uint64_t scheduler_total_ticks(void);
uint64_t scheduler_idle_ticks(void);

#endif
