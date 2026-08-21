#include "sys/scheduler.h"
#include "vfs/vfs.h"
#include "fb.h"
#include "fb_console.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/syscall.h"
#include "arch/x86_64/smp.h"
#include "drivers/apic.h"
#include "kernel/smp.h"
#include "kernel/process_runtime.h"
#include "stdio.h"
#include "serial_console.h"
#include "kernel/boot_logfile.h"
#include "kernel/deferred_work.h"
#include "kernel/drm_runtime.h"
#include "kernel/timer_policy.h"
#include "sys/boottime.h"
#include "sys/syscall.h"
#include "sys/mmio.h"
#include "fs/cgroupfs.h"
#include "string.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/cpu.h"
#include "compat/freebsd/edgeos/kthread.h"
#endif
#ifdef CONFIG_USB
#include "drivers/usb.h"
#endif

extern void switch_to(cpu_context_t *prev, cpu_context_t *next);
extern void switch_to_cr3(cpu_context_t *prev, cpu_context_t *next, uint64_t next_cr3,
                          uint64_t next_rip, uint64_t next_rsp);
extern void ret_from_fork(void);
extern char _kernel_start;
extern char _kernel_end;
extern char _kernel_text_start;
extern char _kernel_text_end;

static scheduler_cpu_t g_sched_cpus[SCHED_MAX_CPUS] __attribute__((aligned(64)));
static task_t g_idle_tasks[SCHED_MAX_CPUS];
/*
 * The idle task runs network, USB, and framebuffer bottom halves before it
 * yields.  Those paths can reach the same socket and fd wakeup call chains as
 * ordinary tasks, so the idle stack needs the same depth as a task stack.
 * A single page overflowed into adjacent kernel state under browser network
 * traffic and corrupted the global fd-table registry.
 */
static uint8_t
    g_idle_stacks[SCHED_MAX_CPUS][EDGE_TASK_KSTACK_SIZE]
        __attribute__((aligned(16)));

static volatile uint64_t g_online_cpu_mask;
static int g_scheduler_ready;
static volatile uint64_t g_sched_total_ticks;
static volatile uint64_t g_sched_idle_ticks;
static uint64_t g_scheduler_kernel_cr3;
static int g_scheduler_bad_ptr_log_budget = 16;
static int g_scheduler_kstack_log_budget = 16;
#ifndef EDGE_SCHED_XFCE_TRACE
#define EDGE_SCHED_XFCE_TRACE 0
#endif
#ifndef EDGE_SCHED_CONTEXT_DIAGNOSTICS
#define EDGE_SCHED_CONTEXT_DIAGNOSTICS 0
#endif

static int g_scheduler_xfce_switch_log_budget = EDGE_SCHED_XFCE_TRACE ? 160 : 0;

static void scheduler_counter_add(volatile uint64_t *counter,
                                  uint64_t delta) {
    uint64_t old;

    if (!counter || !delta) return;
    old = __atomic_load_n(counter, __ATOMIC_RELAXED);
    for (;;) {
        uint64_t next = old > UINT64_MAX - delta ? UINT64_MAX : old + delta;

        if (__atomic_compare_exchange_n(counter, &old, next, 0,
                                        __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            return;
    }
}

typedef enum scheduler_context_event_op {
    SCHED_CONTEXT_WAKE = 1,
    SCHED_CONTEXT_BLOCK,
    SCHED_CONTEXT_READY,
    SCHED_CONTEXT_SCHEDULE,
    SCHED_CONTEXT_PICK,
    SCHED_CONTEXT_SAVE,
    SCHED_CONTEXT_QUEUE,
    SCHED_CONTEXT_DEQUEUE
} scheduler_context_event_op_t;

typedef struct scheduler_context_event {
    uint64_t sequence;
    uint64_t caller;
    uint64_t context_rip;
    uint64_t context_rsp;
    uint64_t generation;
    uint64_t consumed_generation;
    int32_t current_pid;
    int32_t target_pid;
    uint8_t operation;
    uint8_t state;
    uint8_t on_cpu;
    uint8_t context_ready;
    uint8_t on_runqueue;
} scheduler_context_event_t;

#define SCHED_CONTEXT_EVENT_COUNT 128u

static scheduler_context_event_t
    g_scheduler_context_events[SCHED_CONTEXT_EVENT_COUNT];
static uint64_t g_scheduler_context_sequence;
#if EDGE_SCHED_CONTEXT_DIAGNOSTICS
static uint64_t g_scheduler_context_watch_address;
static int32_t g_scheduler_context_watch_pid;
static int g_scheduler_context_watch_budget = 8;
#endif

static const char *sched_state_name(task_state_t st);
static inline uint64_t cr3_read(void);
static inline scheduler_cpu_t *cpu_by_id(uint32_t id);
static task_t *scheduler_task_for_kernel_sp(uint64_t sp);
static void rq_push_tail_locked(scheduler_cpu_t *cpu, task_t *t);
static void rq_remove_locked(scheduler_cpu_t *cpu, task_t *t);
static void scheduler_place_wakeup_locked(scheduler_cpu_t *cpu,
                                          task_t *task,
                                          int woke_from_blocked);

static void scheduler_context_event(scheduler_context_event_op_t operation,
                                    const task_t *current,
                                    const task_t *target,
                                    uint64_t caller) {
#if EDGE_SCHED_CONTEXT_DIAGNOSTICS
    scheduler_context_event_t *event;
    uint64_t sequence;

    if ((!current || current->pid > 8) && (!target || target->pid > 8)) return;
    sequence = __atomic_add_fetch(&g_scheduler_context_sequence, 1u,
                                  __ATOMIC_RELAXED);
    event = &g_scheduler_context_events[
        sequence & (SCHED_CONTEXT_EVENT_COUNT - 1u)];
    event->sequence = sequence;
    event->caller = caller;
    event->current_pid = current ? current->pid : -1;
    event->target_pid = target ? target->pid : -1;
    event->operation = (uint8_t)operation;
    event->state = target ? (uint8_t)target->state : 0xffu;
    event->on_cpu = target ? target->on_cpu : 0u;
    event->context_ready = target ? target->context_ready : 0u;
    event->on_runqueue = target ? target->on_runqueue : 0u;
    event->context_rip = target ? target->context.rip : 0u;
    event->context_rsp = target ? target->context.rsp : 0u;
    event->generation = target ? target->context_generation : 0u;
    event->consumed_generation = target ?
        target->consumed_context_generation : 0u;
    __atomic_thread_fence(__ATOMIC_RELEASE);
#else
    (void)operation;
    (void)current;
    (void)target;
    (void)caller;
#endif
}

static const char *scheduler_context_event_name(uint8_t operation) {
    switch ((scheduler_context_event_op_t)operation) {
        case SCHED_CONTEXT_WAKE: return "wake";
        case SCHED_CONTEXT_BLOCK: return "block";
        case SCHED_CONTEXT_READY: return "ready";
        case SCHED_CONTEXT_SCHEDULE: return "schedule";
        case SCHED_CONTEXT_PICK: return "pick";
        case SCHED_CONTEXT_SAVE: return "save";
        case SCHED_CONTEXT_QUEUE: return "queue";
        case SCHED_CONTEXT_DEQUEUE: return "dequeue";
        default: return "unknown";
    }
}

static void scheduler_dump_context_events(void) {
    uint64_t end = __atomic_load_n(&g_scheduler_context_sequence,
                                   __ATOMIC_ACQUIRE);
    uint64_t start = end > 48u ? end - 48u : 1u;

    printf("[sched] recent context events %u..%u\n",
           (uint32_t)start, (uint32_t)end);
    for (uint64_t sequence = start; sequence <= end; ++sequence) {
        const scheduler_context_event_t *event =
            &g_scheduler_context_events[
                sequence & (SCHED_CONTEXT_EVENT_COUNT - 1u)];
        if (event->sequence != sequence) continue;
        printf("[sched-event] seq=%u op=%s cur=%d target=%d state=%s cpu=%u ready=%u rq=%u gen=%u/%u rip=0x%x rsp=0x%x caller=0x%x\n",
               (uint32_t)event->sequence,
               scheduler_context_event_name(event->operation),
               event->current_pid,
               event->target_pid,
               event->state == 0xffu ? "nil" :
                   sched_state_name((task_state_t)event->state),
               (unsigned)event->on_cpu,
               (unsigned)event->context_ready,
               (unsigned)event->on_runqueue,
               (uint32_t)event->generation,
               (uint32_t)event->consumed_generation,
               (uint32_t)event->context_rip,
               (uint32_t)event->context_rsp,
               (uint32_t)event->caller);
    }
}

static void scheduler_arm_context_watch(const task_t *task) {
#if EDGE_SCHED_CONTEXT_DIAGNOSTICS
    uint64_t address;
    uint64_t control = 1u | (1u << 16) | (2u << 18);

    if (!task || task->pid != 3 || g_scheduler_context_watch_budget <= 0)
        return;
    address = task->context.resume_cookie_addr;
    if (!address) return;
    g_scheduler_context_watch_address = address;
    g_scheduler_context_watch_pid = task->pid;
    __asm__ __volatile__(
        "mov %0, %%dr0\n"
        "xor %%rax, %%rax\n"
        "mov %%rax, %%dr6\n"
        "mov %1, %%dr7\n"
        :
        : "r"(address), "r"(control)
        : "rax", "memory");
#else
    (void)task;
#endif
}

int scheduler_handle_context_watch(uint64_t rip, uint64_t cs, uint64_t rsp,
                                   uint64_t rdi, uint64_t rsi, uint64_t rdx,
                                   uint64_t rcx, uint64_t rax, uint64_t rbp) {
#if EDGE_SCHED_CONTEXT_DIAGNOSTICS
    uint64_t status;
    task_t *current;
    task_t *stack_owner;

    __asm__ __volatile__("mov %%dr6, %0" : "=r"(status));
    if ((status & 1u) == 0 || !g_scheduler_context_watch_address) return 0;
    __asm__ __volatile__(
        "xor %%rax, %%rax\n"
        "mov %%rax, %%dr7\n"
        "mov %%rax, %%dr6\n"
        : : : "rax", "memory");
    current = scheduler_current_task();
    if (current && current->pid == g_scheduler_context_watch_pid) {
        g_scheduler_context_watch_address = 0;
        g_scheduler_context_watch_pid = 0;
        return 1;
    }
    --g_scheduler_context_watch_budget;
    printf("[sched-watch] watched-pid=%d current=%d:%s rip=0x%x cs=0x%x rsp=0x%x return=0x%x rdi=0x%x rsi=0x%x rdx=0x%x rcx=0x%x rax=0x%x addr=0x%x value=0x%x dr6=0x%x budget=%d\n",
           g_scheduler_context_watch_pid,
           current ? current->pid : -1,
           current ? current->name : "nil",
           (uint32_t)rip,
           (uint32_t)cs,
           (uint32_t)rsp,
           rsp ? (uint32_t)*(const volatile uint64_t *)(uintptr_t)rsp : 0u,
           (uint32_t)rdi,
           (uint32_t)rsi,
           (uint32_t)rdx,
           (uint32_t)rcx,
           (uint32_t)rax,
           (uint32_t)g_scheduler_context_watch_address,
           *(const volatile uint32_t *)(uintptr_t)
               g_scheduler_context_watch_address,
           (uint32_t)status,
           g_scheduler_context_watch_budget);
    stack_owner = scheduler_task_for_kernel_sp(rsp);
    if (stack_owner) {
        uint64_t low = stack_owner->kernel_stack_top - EDGE_TASK_KSTACK_SIZE;
        uint64_t high = stack_owner->kernel_stack_top;
        uint64_t frame = rbp;
        printf("[sched-watch] stack-owner=%d:%s low=0x%x high=0x%x rbp=0x%x\n",
               stack_owner->pid, stack_owner->name, (uint32_t)low,
               (uint32_t)high, (uint32_t)frame);
        for (int depth = 0; depth < 12; ++depth) {
            const uint64_t *words;
            uint64_t next_frame;
            if ((frame & 7u) != 0 || frame < low ||
                frame + 2u * sizeof(uint64_t) > high)
                break;
            words = (const uint64_t *)(uintptr_t)frame;
            next_frame = words[0];
            printf("[sched-watch-frame] depth=%d rbp=0x%x ret=0x%x next=0x%x\n",
                   depth, (uint32_t)frame, (uint32_t)words[1],
                   (uint32_t)next_frame);
            if (next_frame <= frame) break;
            frame = next_frame;
        }
    }
    g_scheduler_context_watch_address = 0;
    g_scheduler_context_watch_pid = 0;
    return 1;
#else
    (void)rip;
    (void)cs;
    (void)rsp;
    (void)rdi;
    (void)rsi;
    (void)rdx;
    (void)rcx;
    (void)rax;
    (void)rbp;
    return 0;
#endif
}

static void sched_trace_puts(const char *s) {
    if (!s) return;
    while (*s) serial_console_write_raw(*s++);
}

static void sched_trace_dec(int v) {
    char buf[16];
    int n = 0;
    unsigned int u;
    if (v < 0) {
        serial_console_write_raw('-');
        u = (unsigned int)(-v);
    } else {
        u = (unsigned int)v;
    }
    do {
        buf[n++] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u && n < (int)sizeof(buf));
    while (n > 0) serial_console_write_raw(buf[--n]);
}

static void sched_trace_hex(uint64_t v) {
    static const char hex[] = "0123456789abcdef";
    sched_trace_puts("0x");
    for (int i = 15; i >= 0; --i) {
        serial_console_write_raw(hex[(v >> ((uint64_t)i * 4u)) & 0xfu]);
    }
}

static void scheduler_effective_state(
    const task_t *task, edge_linux_scheduler_state_t *effective) {
    if (!task || !effective) return;
    cgroupfs_cpu_effective_scheduler_state(
        task->cgroup_id, &task->scheduler, effective);
}

static uint32_t scheduler_account_run_stop(task_t *t, uint64_t now) {
    scheduler_cpu_t *cpu;
    uint64_t runtime;
    uint64_t delta;
    uint32_t result;
    edge_linux_scheduler_state_t effective;
    if (!t || t->is_idle || !t->rusage_run_start_us) return 0;
    runtime = now > t->rusage_run_start_us ?
              now - t->rusage_run_start_us : 0;
    cpu = scheduler_cpu_local();
    if (t->in_syscall) {
        t->rusage_sys_time_us += runtime;
        if (cpu) scheduler_counter_add(&cpu->system_time_us, runtime);
    } else {
        t->rusage_user_time_us += runtime;
        if (cpu) scheduler_counter_add(&cpu->user_time_us, runtime);
    }
    cgroupfs_cpu_account_runtime_mode(t->cgroup_id, runtime, now,
                                      t->in_syscall != 0);
    scheduler_effective_state(t, &effective);
    result = edge_linux_scheduler_entity_account(
        &t->scheduler_entity, &effective, runtime, now);
    if (edge_linux_scheduler_policy_is_fair(effective.policy)) {
        delta = edge_linux_scheduler_vruntime_delta(&effective, runtime);
        if (t->scheduler_vruntime_us > UINT64_MAX - delta)
            t->scheduler_vruntime_us = UINT64_MAX;
        else
            t->scheduler_vruntime_us += delta;
        t->scheduler_vruntime_valid = 1;
    }
    t->rusage_run_start_us = 0;
    return result;
}

static void scheduler_account_run_start(task_t *t, uint64_t now) {
    if (!t || t->is_idle) return;
    t->rusage_run_start_us = now ? now : boottime_monotonic_us();
}

void scheduler_account_current_mode_switch(void) {
    task_t *current = scheduler_current_task();
    uint64_t now;
    uint32_t result;

    if (!current || current->is_idle || current->state != TASK_RUNNING ||
        !current->rusage_run_start_us)
        return;
    now = boottime_monotonic_us();
    result = scheduler_account_run_stop(current, now);
    if (result & EDGE_SCHEDULER_ACCOUNT_OVERRUN)
        (void)process_send_signal_thread(current->pid,
                                         EDGE_LINUX_SIGXCPU);
    if (result & (EDGE_SCHEDULER_ACCOUNT_PREEMPT |
                  EDGE_SCHEDULER_ACCOUNT_THROTTLED))
        current->need_resched = 1;
    scheduler_account_run_start(current, now);
}

static int sched_name_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b && *a == *b) {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static int sched_name_has_prefix(const char *s, const char *p) {
    if (!s || !p) return 0;
    while (*p) {
        if (*s++ != *p++) return 0;
    }
    return 1;
}

static int sched_trace_xfce_task(const task_t *t) {
    const char *n;
    if (!t) return 0;
    n = t->name;
    return sched_name_eq(n, "Xorg") ||
           sched_name_eq(n, "ps") ||
           sched_name_eq(n, "pgrep") ||
           sched_name_eq(n, "dbus-launch") ||
           sched_name_eq(n, "xclock") ||
           sched_name_has_prefix(n, "xfce") ||
           sched_name_has_prefix(n, "xfwm") ||
           sched_name_has_prefix(n, "xfdesktop") ||
           sched_name_has_prefix(n, "xfsettings") ||
           sched_name_has_prefix(n, "xfconf") ||
           sched_name_has_prefix(n, "panel");
}

static void sched_log_switch_target(const task_t *prev, const task_t *next,
                                    uint64_t next_cr3, uint64_t next_rip,
                                    uint64_t next_rsp) {
    const uint64_t *sp;
    if (g_scheduler_xfce_switch_log_budget <= 0) return;
    if (!sched_trace_xfce_task(prev) && !sched_trace_xfce_task(next)) return;
    --g_scheduler_xfce_switch_log_budget;
    sp = (const uint64_t *)(uintptr_t)next_rsp;
    printf("[sched-xfce] switch prev=%d:%s next=%d:%s rip=0x%x rsp=0x%x cr3=0x%x q0=0x%x q1=0x%x q2=0x%x budget=%d\n",
           prev ? prev->pid : -1,
           prev ? prev->name : "(none)",
           next ? next->pid : -1,
           next ? next->name : "(none)",
           (uint32_t)next_rip,
           (uint32_t)next_rsp,
           (uint32_t)next_cr3,
           sp ? (uint32_t)sp[0] : 0,
           sp ? (uint32_t)sp[1] : 0,
           sp ? (uint32_t)sp[2] : 0,
           g_scheduler_xfce_switch_log_budget);
}

static int scheduler_task_ptr_valid(const task_t *t) {
    if (!t) return 0;
    for (uint32_t i = 0; i < SCHED_MAX_CPUS; ++i) {
        if (t == &g_idle_tasks[i]) return 1;
    }
    return process_task_pointer_valid(t);
}

static int scheduler_task_runnable_ptr(const task_t *t) {
    if (!scheduler_task_ptr_valid(t)) return 0;
    return t->is_idle || t->state == TASK_RUNNABLE || t->state == TASK_RUNNING;
}

static int scheduler_kernel_context_pc_valid(uint64_t rip) {
    uint64_t start = (uint64_t)(uintptr_t)&_kernel_text_start;
    uint64_t end = (uint64_t)(uintptr_t)&_kernel_text_end;
    return rip >= start && rip < end;
}

static int scheduler_task_stack_word_valid(const task_t *t, uint64_t address) {
    uint64_t stack_low;

    if (!t || !t->kernel_stack_top ||
        t->kernel_stack_top < EDGE_TASK_KSTACK_SIZE)
        return 0;
    stack_low = t->kernel_stack_top - EDGE_TASK_KSTACK_SIZE;
    return address >= stack_low &&
           address <= t->kernel_stack_top - sizeof(uint64_t);
}

static int scheduler_task_context_image_valid(const task_t *t) {
    int has_cookie;

    if (!scheduler_task_ptr_valid(t)) return 0;
    if (!t->is_idle &&
        (t->state == TASK_UNUSED || t->state == TASK_ZOMBIE)) return 0;
    if (!t->context.rip || !t->context.rsp) return 0;
    /*
     * Saved scheduler contexts are always kernel continuations: either a fresh
     * fork/exec trampoline or the return address after switch_to().  User RIPs
     * live inside the trap frame consumed by ret_from_fork, not here.  A low or
     * otherwise non-kernel context RIP means a stale/recycled task slot escaped
     * into the run queue; never jump to it.
     */
    if (!scheduler_kernel_context_pc_valid(t->context.rip)) return 0;
    has_cookie = t->context.resume_cookie_addr ||
                 t->context.resume_cookie_value ||
                 t->context.outer_resume_cookie_addr ||
                 t->context.outer_resume_cookie_value;
    if (!has_cookie) return 1;
    if (!t->context.resume_cookie_addr ||
        !t->context.resume_cookie_value ||
        !t->context.outer_resume_cookie_addr ||
        !t->context.outer_resume_cookie_value)
        return 0;
    if (!scheduler_task_stack_word_valid(
            t, t->context.resume_cookie_addr) ||
        !scheduler_task_stack_word_valid(
            t, t->context.outer_resume_cookie_addr))
        return 0;
    if (!scheduler_kernel_context_pc_valid(
            t->context.outer_resume_cookie_value))
        return 0;
    /*
     * Per-CPU idle stacks are kernel-only mappings.  When a user task selects
     * idle, its address space is still active during this validation, so
     * dereferencing the saved idle cookie would inspect the user's alias of
     * that virtual address.  switch_task_context installs the kernel page
     * tables before loading the idle context.  The idle task is kernel-owned,
     * and the structural checks above are sufficient until that switch.
     */
    if (t->is_idle) return 1;
    return *(const volatile uint64_t *)(uintptr_t)
               t->context.resume_cookie_addr ==
               t->context.resume_cookie_value &&
           *(const volatile uint64_t *)(uintptr_t)
               t->context.outer_resume_cookie_addr ==
               t->context.outer_resume_cookie_value;
}

static int scheduler_task_context_valid(const task_t *t) {
    if (!scheduler_task_context_image_valid(t)) return 0;
    return t->context_ready && !t->on_cpu && !t->switch_pending &&
           t->context_generation != t->consumed_context_generation;
}

static uint64_t scheduler_translate_address(uint64_t root, uint64_t address) {
    const uint64_t address_mask = 0x000ffffffffff000ULL;
    uint64_t entry;
    uint64_t *table;

    if (!root) return UINT64_MAX;
    table = (uint64_t *)edge_mmio_low_alias(root & address_mask);
    entry = table[(address >> 39) & 0x1ffu];
    if ((entry & 1u) == 0) return UINT64_MAX;
    table = (uint64_t *)edge_mmio_low_alias(entry & address_mask);
    entry = table[(address >> 30) & 0x1ffu];
    if ((entry & 1u) == 0) return UINT64_MAX;
    if (entry & (1u << 7))
        return (entry & 0x000fffffc0000000ULL) |
               (address & 0x3fffffffULL);
    table = (uint64_t *)edge_mmio_low_alias(entry & address_mask);
    entry = table[(address >> 21) & 0x1ffu];
    if ((entry & 1u) == 0) return UINT64_MAX;
    if (entry & (1u << 7))
        return (entry & 0x000fffffffe00000ULL) |
               (address & 0x1fffffULL);
    table = (uint64_t *)edge_mmio_low_alias(entry & address_mask);
    entry = table[(address >> 12) & 0x1ffu];
    if ((entry & 1u) == 0) return UINT64_MAX;
    return (entry & address_mask) | (address & 0xfffu);
}

static uint32_t scheduler_phys_word(uint64_t physical_address) {
    if (physical_address == UINT64_MAX) return 0xffffffffu;
    return *(const volatile uint32_t *)edge_mmio_low_alias(physical_address);
}

static void scheduler_log_bad_task_ptr(const char *where, const task_t *t) {
    if (g_scheduler_bad_ptr_log_budget <= 0) return;
    g_scheduler_bad_ptr_log_budget--;
    printf("[sched][ERR] %s invalid task=0x%x\n",
           where, (uint32_t)(uintptr_t)t);
}

static void scheduler_log_bad_context(const char *where, const task_t *t) {
    uint64_t active_cr3;
    uint64_t active_phys;
    uint64_t task_phys;
    uint64_t kernel_phys;
    uint32_t resume_live = 0u;
    uint32_t outer_live = 0u;

    if (g_scheduler_bad_ptr_log_budget <= 0) return;
    g_scheduler_bad_ptr_log_budget--;
    if (t && scheduler_task_stack_word_valid(
            t, t->context.resume_cookie_addr))
        resume_live = (uint32_t)*(const volatile uint64_t *)(uintptr_t)
            t->context.resume_cookie_addr;
    if (t && scheduler_task_stack_word_valid(
            t, t->context.outer_resume_cookie_addr))
        outer_live = (uint32_t)*(const volatile uint64_t *)(uintptr_t)
            t->context.outer_resume_cookie_addr;
    printf("[sched][ERR] %s bad context pid=%d rip=0x%x rsp=0x%x state=%s ready=%u oncpu=%u onrq=%u generation=%u/%u cookie=0x%x/0x%x live=0x%x outer=0x%x/0x%x live=0x%x\n",
           where,
           t ? t->pid : -1,
           t ? (uint32_t)t->context.rip : 0,
           t ? (uint32_t)t->context.rsp : 0,
           t ? sched_state_name(t->state) : "nil",
           t ? (unsigned)t->context_ready : 0u,
           t ? (unsigned)t->on_cpu : 0u,
           t ? (unsigned)t->on_runqueue : 0u,
           t ? (uint32_t)t->context_generation : 0u,
           t ? (uint32_t)t->consumed_context_generation : 0u,
           t ? (uint32_t)t->context.resume_cookie_addr : 0u,
           t ? (uint32_t)t->context.resume_cookie_value : 0u,
           resume_live,
           t ? (uint32_t)t->context.outer_resume_cookie_addr : 0u,
           t ? (uint32_t)t->context.outer_resume_cookie_value : 0u,
           outer_live);
    active_cr3 = cr3_read();
    active_phys = scheduler_translate_address(
        active_cr3, t ? t->context.resume_cookie_addr : 0u);
    task_phys = scheduler_translate_address(
        t ? t->cr3 : 0u, t ? t->context.resume_cookie_addr : 0u);
    kernel_phys = scheduler_translate_address(
        g_scheduler_kernel_cr3, t ? t->context.resume_cookie_addr : 0u);
    printf("[sched][ERR] cookie mappings active=0x%x->0x%x:%x task=0x%x->0x%x:%x kernel=0x%x->0x%x:%x\n",
           (uint32_t)active_cr3, (uint32_t)active_phys,
           scheduler_phys_word(active_phys),
           t ? (uint32_t)t->cr3 : 0u, (uint32_t)task_phys,
           scheduler_phys_word(task_phys),
           (uint32_t)g_scheduler_kernel_cr3, (uint32_t)kernel_phys,
           scheduler_phys_word(kernel_phys));
    scheduler_dump_context_events();
}

static task_t *scheduler_task_for_kernel_sp(uint64_t sp) {
    for (uint32_t cpu = 0; cpu < SCHED_MAX_CPUS; ++cpu) {
        uint64_t low = (uint64_t)(uintptr_t)&g_idle_stacks[cpu][0];
        uint64_t high = (uint64_t)(uintptr_t)&g_idle_stacks[cpu]
                                                    [sizeof(g_idle_stacks[cpu])];
        if (sp >= low && sp < high) return &g_idle_tasks[cpu];
    }
    return process_task_for_kernel_stack(sp);
}

static void sched_warn_kstack_depth(const task_t *t, const char *where) {
    uint64_t sp;
    uint64_t used;

    if (!t || t->is_idle || g_scheduler_kstack_log_budget <= 0) return;
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(sp));
    if (sp > t->kernel_stack_top) return;
    used = t->kernel_stack_top - sp;
    if (used < (uint64_t)EDGE_TASK_KSTACK_SIZE - 4096ULL) return;
    --g_scheduler_kstack_log_budget;
    printf("[sched][WARN] %s pid=%d task=%s kstack-used=0x%x/0x%x sp=0x%x top=0x%x\n",
           where ? where : "kstack",
           t->pid,
           t->name,
           (uint32_t)used,
           (uint32_t)EDGE_TASK_KSTACK_SIZE,
           (uint32_t)sp,
           (uint32_t)t->kernel_stack_top);
}

static inline void fxsave_task(task_t *t) {
    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("fxsave", t);
        return;
    }
    __asm__ __volatile__("fxsave (%0)" :: "r"(t->fxsave_region) : "memory");
}

static inline void fxrstor_task(task_t *t) {
    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("fxrstor", t);
        return;
    }
    __asm__ __volatile__("fxrstor (%0)" :: "r"(t->fxsave_region) : "memory");
}

#ifndef EDGE_SCHED_DEBUG
#define EDGE_SCHED_DEBUG 0
#endif

static const char *sched_state_name(task_state_t st) {
    switch (st) {
        case TASK_UNUSED: return "UNUSED";
        case TASK_RUNNABLE: return "RUNNABLE";
        case TASK_RUNNING: return "RUNNING";
        case TASK_BLOCKED: return "BLOCKED";
        case TASK_STOPPED: return "STOPPED";
        case TASK_ZOMBIE: return "ZOMBIE";
        default: return "???";
    }
}

static int sched_pid(task_t *t) {
    if (t && !scheduler_task_ptr_valid(t)) return -9999;
    return t ? t->pid : -1;
}

static void sched_log_cpu(const char *op, scheduler_cpu_t *cpu, task_t *t) {
#if EDGE_SCHED_DEBUG
    if (!cpu) return;
    printf("[sched] %s cpu=%u pid=%d st=%s acpu=%d onrq=%d head=%d tail=%d cur=%d\n",
           op,
           cpu->logical_id,
           sched_pid(t),
           t ? sched_state_name(t->state) : "nil",
           t ? t->assigned_cpu : -1,
           t ? (int)t->on_runqueue : -1,
           sched_pid(cpu->rq_head),
           sched_pid(cpu->rq_tail),
           sched_pid(cpu->current));
#else
    (void)op; (void)cpu; (void)t;
#endif
}

static void sched_invariant_check(const char *where, scheduler_cpu_t *cpu) {
#if EDGE_SCHED_DEBUG
    if (!cpu) return;
    if (!cpu->current) {
        printf("[sched][ERR] %s cpu=%u current=NULL\n", where, cpu->logical_id);
    }
    if (cpu->rq_head == 0 && cpu->rq_tail != 0) {
        printf("[sched][ERR] %s cpu=%u head=NULL tail=%d\n", where, cpu->logical_id, sched_pid(cpu->rq_tail));
    }
    if (cpu->rq_head != 0 && cpu->rq_tail == 0) {
        printf("[sched][ERR] %s cpu=%u head=%d tail=NULL\n", where, cpu->logical_id, sched_pid(cpu->rq_head));
    }
    if (cpu->rq_head == 0 && cpu->current && !cpu->current->is_idle) {
        printf("[sched][ERR] %s cpu=%u rq-empty current-not-idle pid=%d st=%s\n",
               where, cpu->logical_id, cpu->current->pid, sched_state_name(cpu->current->state));
    }
    if (cpu->current && !cpu->current->is_idle && cpu->current->state != TASK_RUNNING) {
        printf("[sched][ERR] %s cpu=%u current pid=%d state=%s (expected RUNNING)\n",
               where, cpu->logical_id, cpu->current->pid, sched_state_name(cpu->current->state));
    }

    for (int i = 0; i < PROC_MAX_TASKS; ++i) {
        task_t *t = (task_t *)process_task_by_index(i);
        int rq_count = 0;
        int rq_owner = -1;
        int is_current_any = 0;
        if (!t || t->state == TASK_UNUSED) continue;

        for (uint32_t c = 0; c < SCHED_MAX_CPUS; ++c) {
            scheduler_cpu_t *sc = &g_sched_cpus[c];
            if (sc->current == t) is_current_any = 1;
            for (task_t *q = sc->rq_head; q; q = q->rq_next) {
                if (q == t) {
                    rq_count++;
                    rq_owner = (int)c;
                }
            }
        }

        if (t->on_runqueue && t->state != TASK_RUNNABLE) {
            printf("[sched][ERR] %s pid=%d onrq=1 state=%s\n",
                   where, t->pid, sched_state_name(t->state));
        }
        if ((t->state == TASK_RUNNABLE || t->state == TASK_RUNNING) &&
            !t->on_runqueue && !is_current_any && !t->switch_pending) {
            printf("[sched][ERR] %s pid=%d state=%s onrq=0 and not current\n",
                   where, t->pid, sched_state_name(t->state));
        }
        if (rq_count > 1) {
            printf("[sched][ERR] %s pid=%d present on %d runqueues\n", where, t->pid, rq_count);
        }
        if (t->on_runqueue && rq_count == 0) {
            printf("[sched][ERR] %s pid=%d onrq=1 but not present in any runqueue\n", where, t->pid);
        }
        if (!t->on_runqueue && rq_count > 0) {
            printf("[sched][ERR] %s pid=%d onrq=0 but present in a runqueue\n", where, t->pid);
        }
        if (rq_count == 1 && t->assigned_cpu != rq_owner) {
            printf("[sched][ERR] %s pid=%d assigned_cpu=%d rq_owner=%d mismatch\n",
                   where, t->pid, t->assigned_cpu, rq_owner);
        }
    }
#else
    (void)where; (void)cpu;
#endif
}

static inline uint64_t cr3_read(void) {
    uint64_t v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v;
}

static inline void cr3_write(uint64_t v) {
    __asm__ __volatile__("mov %0, %%cr3" :: "r"(v) : "memory");
}

static uint32_t scheduler_cpu_load(uint32_t cpu_id) {
    scheduler_cpu_t *cpu = cpu_by_id(cpu_id);
    task_t *current = __atomic_load_n(&cpu->current, __ATOMIC_ACQUIRE);
    uint32_t load = __atomic_load_n(&cpu->nr_running, __ATOMIC_ACQUIRE);

    if (current && current != cpu->idle) ++load;
    return load;
}

static void scheduler_idle_loop(void) {
    for (;;) {
        uint32_t cpu_id = scheduler_cpu_id();
        uint32_t ready_work;

        /*
         * Interrupt handlers can make blocked tasks runnable while the CPU is
         * halted in the idle task.  After HLT returns, immediately consult the
         * run queue before halting again; otherwise timer/UART wakeups can put
         * work on the queue but leave the CPU parked in idle forever.  This is
         * especially visible for serial ttys now that foreground reads really
         * sleep instead of spin-yielding.
         */
        /*
         * Network hard IRQ handlers only acknowledge hardware.  Running the
         * NO_SYS lwIP core here provides a serialized process-context bottom
         * half, which can safely fill socket queues and wake exact fd waiters.
         * This must precede scheduler_yield() so a packet that woke HLT can
         * immediately make its sleeping consumer runnable.
        */
        if (cpu_id != 0u) {
            scheduler_cpu_t *cpu = scheduler_cpu_local();

            /*
             * Secondary CPUs have no global timer duties.  Stop their local
             * periodic APIC tick while the runqueue is empty and use the
             * reschedule IPI as the wake source.  Interrupts stay disabled
             * from the final queue check through timer masking, so an enqueue
             * racing this path leaves a pending IPI consumed by STI;HLT.
             */
            __asm__ __volatile__("cli" ::: "memory");
            if (cpu &&
                __atomic_load_n(&cpu->nr_running,
                                __ATOMIC_ACQUIRE) == 0u) {
                apic_timer_pause_periodic();
                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                if (__atomic_load_n(&cpu->nr_running,
                                    __ATOMIC_ACQUIRE) == 0u)
                    __asm__ __volatile__("sti; hlt" ::: "memory");
                else
                    __asm__ __volatile__("sti" ::: "memory");
                apic_timer_resume_periodic();
            } else {
                __asm__ __volatile__("sti" ::: "memory");
            }
            scheduler_yield();
            continue;
        }
        ready_work = kernel_deferred_work_take_ready();
        if (ready_work & KERNEL_DEFERRED_WORK_DISPLAY) {
            edge_drm_pump_deferred();
            fb_user_mmap_pump_deferred();
        }
        if ((ready_work & KERNEL_DEFERRED_WORK_DISPLAY) &&
            !(ready_work & KERNEL_DEFERRED_WORK_GENERAL)) {
            scheduler_yield();
            continue;
        }
        syscall_network_poll();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
        bsd_kthread_pump();
#endif
#ifdef CONFIG_USB
        usb_poll();
#endif
        kernel_boot_log_poll();
        fb_user_mmap_pump_deferred();
        fb_console_pump_deferred();
        scheduler_yield();
        fb_user_mmap_pump_deferred();
        fb_console_pump_deferred();
#ifdef CONFIG_BSD_DRIVER_BRIDGE
        __asm__ __volatile__("cli" ::: "memory");
        if (!bsd_cpu_idle((INT64_C(1) << 32) / 1000))
            __asm__ __volatile__("sti; hlt" ::: "memory");
#else
        __asm__ __volatile__("sti; hlt");
#endif
    }
}

static inline scheduler_cpu_t *cpu_by_id(uint32_t id) {
    if (id >= SCHED_MAX_CPUS) id = 0;
    return &g_sched_cpus[id];
}

static scheduler_cpu_t *scheduler_lock_task_owner(
        task_t *task, uint32_t fallback_cpu, uint32_t *cpu_id_out,
        uint64_t *flags_out) {
    for (;;) {
        int assigned = __atomic_load_n(&task->assigned_cpu, __ATOMIC_ACQUIRE);
        uint32_t cpu_id = assigned >= 0 ? (uint32_t)assigned : fallback_cpu;
        scheduler_cpu_t *cpu;
        uint64_t flags;

        if (cpu_id >= SCHED_MAX_CPUS) cpu_id = 0u;
        cpu = cpu_by_id(cpu_id);
        flags = spin_lock_irqsave(&cpu->rq_lock);
        if (__atomic_load_n(&task->assigned_cpu, __ATOMIC_ACQUIRE) == assigned) {
            if (cpu_id_out) *cpu_id_out = cpu_id;
            if (flags_out) *flags_out = flags;
            return cpu;
        }
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
    }
}

static void rq_push_tail_locked(scheduler_cpu_t *cpu, task_t *t) {
    if (!cpu || !t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("rq_push", t);
        return;
    }
    if (t->state != TASK_RUNNABLE) {
        printf("[sched][ERR] rq_push non-runnable pid=%d state=%s\n",
               t->pid, sched_state_name(t->state));
        return;
    }
    if (!t->context_ready || t->on_cpu) {
        scheduler_log_bad_context("rq_push", t);
        return;
    }
    if (t->on_runqueue) {
        printf("[sched][ERR] rq_push existing cpu=%u current=%d pid=%d state=%s acpu=%d oncpu=%u pending=%u ready=%u caller=%p\n",
               cpu->logical_id, cpu->current ? cpu->current->pid : -1,
               t->pid, sched_state_name(t->state), t->assigned_cpu,
               (unsigned)t->on_cpu, (unsigned)t->switch_pending,
               (unsigned)t->context_ready, __builtin_return_address(0));
        return;
    }
    if (cpu->rq_tail && !scheduler_task_ptr_valid(cpu->rq_tail)) {
        scheduler_log_bad_task_ptr("rq_push_tail", cpu->rq_tail);
        cpu->rq_head = 0;
        cpu->rq_tail = 0;
        __atomic_store_n(&cpu->nr_running, 0u, __ATOMIC_RELEASE);
    }
    t->rq_prev = cpu->rq_tail;
    t->rq_next = 0;
    if (cpu->rq_tail) cpu->rq_tail->rq_next = t;
    else cpu->rq_head = t;
    cpu->rq_tail = t;
    t->on_runqueue = 1;
    if (!t->scheduler_wait_start_us)
        t->scheduler_wait_start_us = boottime_monotonic_us();
    __atomic_add_fetch(&cpu->nr_running, 1u, __ATOMIC_RELEASE);
    scheduler_context_event(SCHED_CONTEXT_QUEUE, cpu->current, t,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));
    sched_log_cpu("rq_push", cpu, t);
}

static void rq_remove_locked(scheduler_cpu_t *cpu, task_t *t) {
    if (!cpu || !t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("rq_remove", t);
        return;
    }
    if (!t->on_runqueue) return;
    if (t->rq_prev && !scheduler_task_ptr_valid(t->rq_prev)) {
        scheduler_log_bad_task_ptr("rq_remove_prev", t->rq_prev);
        t->rq_prev = 0;
    }
    if (t->rq_next && !scheduler_task_ptr_valid(t->rq_next)) {
        scheduler_log_bad_task_ptr("rq_remove_next", t->rq_next);
        t->rq_next = 0;
    }
    if (t->rq_prev) t->rq_prev->rq_next = t->rq_next;
    else cpu->rq_head = t->rq_next;

    if (t->rq_next) t->rq_next->rq_prev = t->rq_prev;
    else cpu->rq_tail = t->rq_prev;

    t->rq_prev = 0;
    t->rq_next = 0;
    t->on_runqueue = 0;
    if (__atomic_load_n(&cpu->nr_running, __ATOMIC_RELAXED) != 0u)
        __atomic_sub_fetch(&cpu->nr_running, 1u, __ATOMIC_RELEASE);
    scheduler_context_event(SCHED_CONTEXT_DEQUEUE, cpu->current, t,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));
    sched_log_cpu("rq_remove", cpu, t);
}

static int rq_contains_locked(const scheduler_cpu_t *cpu,
                              const task_t *target) {
    const task_t *task;
    uint32_t visited = 0u;

    if (!cpu || !target) return 0;
    for (task = cpu->rq_head; task && visited < PROC_MAX_TASKS;
         task = task->rq_next, ++visited) {
        if (!scheduler_task_ptr_valid(task)) return 0;
        if (task == target) return 1;
    }
    return 0;
}

static void rq_recover_stranded_locked(scheduler_cpu_t *cpu, task_t *task) {
    static int recovery_log_budget = 16;

    if (!cpu || !task || !task->on_runqueue ||
        rq_contains_locked(cpu, task))
        return;
    if (recovery_log_budget > 0) {
        --recovery_log_budget;
        printf("[sched][WARN] recover stranded runnable pid=%d cpu=%u\n",
               task->pid, cpu->logical_id);
    }
    task->rq_prev = 0;
    task->rq_next = 0;
    task->on_runqueue = 0;
    if (__atomic_load_n(&cpu->nr_running, __ATOMIC_RELAXED) != 0u)
        __atomic_sub_fetch(&cpu->nr_running, 1u, __ATOMIC_RELEASE);
}

static task_t *pick_next_runnable_locked(scheduler_cpu_t *cpu,
                                         task_t *switching_out) {
    task_t *best = 0;
    task_t *task = cpu->rq_head;
    uint64_t now = boottime_monotonic_us();
    uint64_t average_vruntime = 0;
    uint64_t fair_weight = 0;
    uint32_t fair_tasks = 0;

    for (task = cpu->rq_head; task; task = task->rq_next) {
        edge_linux_scheduler_state_t effective;

        if (!scheduler_task_ptr_valid(task)) break;
        scheduler_effective_state(task, &effective);
        if (task->switch_pending || task->state != TASK_RUNNABLE ||
            (task != switching_out &&
             !scheduler_task_context_valid(task)) ||
            cgroupfs_task_frozen(task->cgroup_id) ||
            !cgroupfs_cpu_task_runnable(task->cgroup_id, now) ||
            !edge_linux_scheduler_entity_runnable(
                &task->scheduler_entity, &effective, now) ||
            !task->scheduler_vruntime_valid ||
            !edge_linux_scheduler_policy_is_fair(effective.policy))
            continue;
        average_vruntime =
            edge_linux_scheduler_vruntime_weighted_average_add(
                average_vruntime, fair_weight, &effective,
                task->scheduler_vruntime_us, &fair_weight);
        ++fair_tasks;
    }
    if (!fair_tasks) fair_tasks = 1u;
    task = cpu->rq_head;
    while (task) {
        task_t *next;
        if (!scheduler_task_ptr_valid(task)) {
            scheduler_log_bad_task_ptr("pick_next", task);
            cpu->rq_head = 0;
            cpu->rq_tail = 0;
            __atomic_store_n(&cpu->nr_running, 0u, __ATOMIC_RELEASE);
            break;
        }
        next = task->rq_next;
        if (task->switch_pending) {
            task = next;
            continue;
        }
        if (task->state != TASK_RUNNABLE ||
            (task != switching_out &&
             !scheduler_task_context_valid(task))) {
            if (task->state == TASK_RUNNABLE)
                scheduler_log_bad_context("pick_next", task);
            rq_remove_locked(cpu, task);
            if (task->state == TASK_RUNNABLE)
                task->state = TASK_ZOMBIE;
        } else if (cgroupfs_task_frozen(task->cgroup_id)) {
            task = next;
            continue;
        } else if (!cgroupfs_cpu_task_runnable(task->cgroup_id, now)) {
            task = next;
            continue;
        } else {
            edge_linux_scheduler_state_t effective;
            edge_linux_scheduler_state_t best_effective;

            scheduler_effective_state(task, &effective);
            if (!edge_linux_scheduler_entity_runnable(
                    &task->scheduler_entity, &effective, now)) {
                task = next;
                continue;
            }
            if (!best) {
                best = task;
            } else {
                int group_order = 0;

                scheduler_effective_state(best, &best_effective);
                if (edge_linux_scheduler_state_compare(
                        &effective, &best_effective) == 0 &&
                    edge_linux_scheduler_policy_is_fair(effective.policy))
                    group_order = cgroupfs_cpu_group_order(
                        task->cgroup_id, best->cgroup_id);
                if (group_order > 0 ||
                    (group_order == 0 &&
                     edge_linux_scheduler_entity_precedes(
                        &effective, &task->scheduler_entity,
                        task->scheduler_vruntime_us,
                        &best_effective, &best->scheduler_entity,
                        best->scheduler_vruntime_us,
                        average_vruntime, fair_tasks, now)))
                    best = task;
            }
        }
        task = next;
    }
    if (best) {
        rq_remove_locked(cpu, best);
        if (best->scheduler_wait_start_us) {
            uint64_t wait = now > best->scheduler_wait_start_us ?
                now - best->scheduler_wait_start_us : 0u;

            best->scheduler_wait_us =
                best->scheduler_wait_us > UINT64_MAX - wait ? UINT64_MAX :
                best->scheduler_wait_us + wait;
            scheduler_counter_add(&cpu->runqueue_wait_us, wait);
            best->scheduler_wait_start_us = 0u;
        }
        return best;
    }
    return cpu->idle;
}

static uint64_t scheduler_min_vruntime_locked(const scheduler_cpu_t *cpu) {
    const task_t *task;
    uint64_t minimum = UINT64_MAX;
    int found = 0;

    if (!cpu) return 0;
    task = cpu->current;
    if (task && !task->is_idle && task->scheduler_vruntime_valid) {
        minimum = task->scheduler_vruntime_us;
        found = 1;
    }
    for (task = cpu->rq_head; task; task = task->rq_next) {
        if (!scheduler_task_ptr_valid(task)) break;
        if (!task->scheduler_vruntime_valid) continue;
        if (!found || task->scheduler_vruntime_us < minimum) {
            minimum = task->scheduler_vruntime_us;
            found = 1;
        }
    }
    return found ? minimum : 0;
}

static void scheduler_place_wakeup_locked(scheduler_cpu_t *cpu, task_t *task,
                                          int woke_from_blocked) {
    uint64_t minimum;
    uint64_t floor;

    if (!cpu || !task) return;
    minimum = scheduler_min_vruntime_locked(cpu);
    if (!task->scheduler_vruntime_valid) {
        task->scheduler_vruntime_us = minimum;
        task->scheduler_vruntime_valid = 1;
        return;
    }
    if (!woke_from_blocked) return;
    floor = minimum > EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US ?
            minimum - EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US : 0;
    if (task->scheduler_vruntime_us < floor)
        task->scheduler_vruntime_us = floor;
}

static uint32_t scheduler_select_allowed_cpu(const task_t *task,
                                             uint32_t requested) {
    uint64_t online = g_online_cpu_mask ? g_online_cpu_mask : 1u;
    uint64_t cpuset = task ?
        cgroupfs_cpuset_cpu_mask64(task->cgroup_id) & online : online;
    uint64_t allowed;
    uint64_t capable = 0u;
    uint32_t selected = SCHED_MAX_CPUS;
    edge_linux_scheduler_state_t effective;

    if (!cpuset) cpuset = online;
    allowed = task ? task->scheduler.affinity_mask & cpuset : cpuset;
    if (!allowed) allowed = cpuset;
    if (task) {
        scheduler_effective_state(task, &effective);
        for (uint32_t cpu = 0; cpu < SCHED_MAX_CPUS; ++cpu) {
            edge_cpu_topology_t topology;

            if (!(allowed & (1ull << cpu)) ||
                edge_smp_get_cpu(cpu, &topology) != 0)
                continue;
            if (topology.capacity >= effective.util_min)
                capable |= 1ull << cpu;
        }
        if (capable) allowed = capable;
    }
    /*
     * Selection may choose another CPU for a running task, but the caller does
     * not expose its live kernel continuation to that CPU.  The scheduling
     * handoff marks switch_pending, switches away on the source CPU, and only
     * then releases the saved context on the destination.  Keeping a task on
     * a now-disallowed CPU until it blocks breaks sched_setaffinity for busy
     * workloads and also defeats per-CPU cgroup fairness.
     */
    if (requested < SCHED_MAX_CPUS &&
        (allowed & (1ull << requested)))
        selected = requested;
    for (uint32_t cpu = 0; cpu < SCHED_MAX_CPUS; ++cpu)
        if (selected >= SCHED_MAX_CPUS && (allowed & (1ull << cpu)))
            selected = cpu;

    if (task && !task->on_cpu && !task->on_runqueue &&
        (task->state == TASK_BLOCKED || task->state == TASK_STOPPED)) {
        uint32_t selected_load = scheduler_cpu_load(selected);
        uint32_t selected_distance = UINT32_MAX;
        edge_cpu_topology_t selected_topology;

        if (edge_smp_get_cpu(selected, &selected_topology) == 0)
            selected_distance = selected_topology.capacity >
                                effective.util_max ?
                selected_topology.capacity - effective.util_max :
                effective.util_max - selected_topology.capacity;

        for (uint32_t cpu = 0; cpu < SCHED_MAX_CPUS; ++cpu) {
            uint32_t load;
            uint32_t distance = UINT32_MAX;
            edge_cpu_topology_t topology;

            if (!(allowed & (1ull << cpu))) continue;
            load = scheduler_cpu_load(cpu);
            if (edge_smp_get_cpu(cpu, &topology) == 0)
                distance = topology.capacity > effective.util_max ?
                    topology.capacity - effective.util_max :
                    effective.util_max - topology.capacity;
            if (load > selected_load ||
                (load == selected_load && distance >= selected_distance))
                continue;
            selected = cpu;
            selected_load = load;
            selected_distance = distance;
        }
    } else if (task && task->on_cpu &&
               (task->state == TASK_RUNNING ||
                task->state == TASK_RUNNABLE) &&
               edge_linux_scheduler_policy_is_fair(effective.policy)) {
        uint32_t loads[SCHED_MAX_CPUS];

        for (uint32_t cpu = 0; cpu < SCHED_MAX_CPUS; ++cpu)
            loads[cpu] = scheduler_cpu_load(cpu);
        selected = edge_linux_scheduler_active_balance_cpu(
            allowed, selected, loads, SCHED_MAX_CPUS);
    }
    return selected < SCHED_MAX_CPUS ? selected : 0u;
}

/*
 * switch_to_cr3 saves the schedule_common continuation from this function's
 * frame pointer. Keep this wrapper out of line so the architecture switch has
 * a stable SysV frame even under production optimization.
 */
static __attribute__((noinline)) void switch_task_context(task_t *prev,
                                                          task_t *next) {
    uint64_t old_cr3;
    uint64_t next_cr3;
    uint64_t next_fs_base;
    uint64_t next_gs_base;
    uint64_t next_kernel_stack_top;
    uint64_t next_rsp;
    uint64_t next_rip;
    cpu_context_t *prev_ctx = 0;
    cpu_context_t *next_ctx;
    if (!next) return;
    if (!scheduler_task_runnable_ptr(next)) {
        scheduler_log_bad_task_ptr("switch_next", next);
        return;
    }
    if (!scheduler_task_context_image_valid(next)) {
        scheduler_log_bad_context("switch_next", next);
        return;
    }
    if (prev && !scheduler_task_ptr_valid(prev)) {
        scheduler_log_bad_task_ptr("switch_prev", prev);
        prev = 0;
    }
    sched_warn_kstack_depth(prev, "switch-prev");

    /*
     * Pull every field needed by the low-level switch while the scheduler is
     * still on a known-good kernel mapping.  EdgeOS currently backs user
     * address spaces with fixed windows that overlap the kernel image's .bss;
     * after loading a task CR3, dereferencing task_t again can fault or fetch a
     * user-window alias.  Linux avoids this by keeping scheduler metadata in
     * always-mapped kernel memory; until EdgeOS has the same split, keep the
     * switch path explicit and do not touch task_t after cr3_write(next_cr3).
     */
    next_cr3 = next->cr3 ? next->cr3 : g_scheduler_kernel_cr3;
    next_fs_base = next->fs_base;
    next_gs_base = next->gs_base;
    next_kernel_stack_top = next->kernel_stack_top;
    next_rsp = next->context.rsp;
    next_rip = next->context.rip;
    next_ctx = &next->context;
    if (prev) prev_ctx = &prev->context;
    if (prev_ctx) {
        uint64_t *switch_frame;
        uint64_t *schedule_frame;
        uint64_t cookie;

        __asm__ __volatile__("mov %%rbp, %0" : "=r"(switch_frame));
        schedule_frame = switch_frame ?
            (uint64_t *)(uintptr_t)switch_frame[0] : 0;
        ++prev->context_generation;
        if (!prev->context_generation) ++prev->context_generation;
        if (schedule_frame &&
            scheduler_task_stack_word_valid(
                prev, (uint64_t)(uintptr_t)&schedule_frame[2]) &&
            scheduler_task_stack_word_valid(
                prev, (uint64_t)(uintptr_t)&schedule_frame[3])) {
            cookie = edgeos_x86_64_resume_cookie(
                prev->context_generation, (uintptr_t)prev,
                schedule_frame[2]);
            schedule_frame[2] = cookie;
            prev_ctx->resume_cookie_addr =
                (uint64_t)(uintptr_t)&schedule_frame[2];
            prev_ctx->resume_cookie_value = cookie;
            prev_ctx->outer_resume_cookie_addr =
                (uint64_t)(uintptr_t)&schedule_frame[3];
            prev_ctx->outer_resume_cookie_value = schedule_frame[3];
        } else {
            /*
             * A missing scheduler frame is not a fresh task context.  Leave a
             * deliberately incomplete cookie image so this task cannot be
             * selected if the current switch still manages to complete.
             */
            prev_ctx->resume_cookie_addr = 0;
            prev_ctx->resume_cookie_value = 1;
            prev_ctx->outer_resume_cookie_addr = 0;
            prev_ctx->outer_resume_cookie_value = 0;
        }
        scheduler_context_event(SCHED_CONTEXT_SAVE, prev, prev,
                                (uint64_t)(uintptr_t)schedule_frame);
        scheduler_arm_context_watch(prev);
    }
    (void)vfs_mount_namespace_activate(next->namespaces.owned ?
                                       next->namespaces.mount : 0u);
    sched_log_switch_target(prev, next, next_cr3, next_rip, next_rsp);
    if (g_scheduler_xfce_switch_log_budget > 0 &&
        ((prev && prev->pid <= 2) || (next && next->pid <= 2))) {
        sched_trace_puts("[sched-switch] prev=");
        sched_trace_dec(prev ? prev->pid : -1);
        sched_trace_puts(" next=");
        sched_trace_dec(next ? next->pid : -1);
        sched_trace_puts(" next_rip=");
        sched_trace_hex(next_rip);
        sched_trace_puts(" next_rsp=");
        sched_trace_hex(next_rsp);
        sched_trace_puts(" next_cr3=");
        sched_trace_hex(next_cr3);
        sched_trace_puts(" fs=");
        sched_trace_hex(next_fs_base);
        sched_trace_puts("\n");
        g_scheduler_xfce_switch_log_budget--;
    }

    old_cr3 = cr3_read();
    /*
     * Threads in one Linux mm use the same page tables.  Keep that address
     * space active across a same-mm switch: loading the kernel CR3 and then
     * immediately loading the identical user CR3 performs two full TLB flushes
     * per pthread/futex handoff.  The scheduler metadata already proved
     * accessible under the current CR3 while collecting the switch state
     * above.  Different-mm switches still pass through the kernel mapping so
     * neither task's fixed user window can alias scheduler-owned memory.
     */
    if (old_cr3 != next_cr3 && g_scheduler_kernel_cr3 &&
        old_cr3 != g_scheduler_kernel_cr3) {
        cr3_write(g_scheduler_kernel_cr3);
    }
    if (prev && prev->state != TASK_UNUSED) fxsave_task(prev);
    /*
     * The FPU state buffers live in task_t, which is kernel-owned memory.
     * Restore the next task's FPU image while still running on the current
     * known-good kernel mapping.  A recycled or shared-VM task with stale CR3
     * state must not make scheduler-owned memory disappear underneath fxrstor.
     */
    fxrstor_task(next);
    gdt_set_tss_rsp0(next_kernel_stack_top);
    process_x86_ldt_activate(next);
    edgeos_x86_64_set_user_gs_base(next_gs_base);

    if (!prev) {
        edgeos_x86_64_set_fs_base(next_fs_base);
        /*
         * The abandon path cannot execute compiler-generated stack reloads
         * after switching CR3.  Load the new address space, stack, and entry in
         * one asm block with all operands already in registers.
         */
        __asm__ __volatile__(
            "mov %0, %%cr3\n"
            "mov %1, %%rsp\n"
            "jmp *%2\n"
            :
            : "r"(next_cr3), "r"(next_rsp), "r"(next_rip)
            : "memory");
        __builtin_unreachable();
    }

    edgeos_x86_64_set_fs_base(next_fs_base);

    /*
     * switch_to_cr3 stores current RIP/RSP into prev->context, loads the next
     * context while kernel scheduler memory is still mapped, then writes CR3
     * and jumps.  Do not use switch_to() here after cr3_write(next_cr3): task_t
     * lives in low kernel .bss addresses that can alias fixed user windows.
     */
    switch_to_cr3(prev_ctx, next_ctx, next_cr3, next_rip, next_rsp);
    /*
     * The task that resumed this frame was restored as `next` by the
     * scheduler instance that switched into it.  Do not touch stack locals
     * here: under fork/exec/exit pressure the old frame may belong to a
     * recycled task slot, and a second fxrstor can dereference stale data.
     */
}

int scheduler_fault_in_switch_window(uint64_t rip) {
    uint64_t start = (uint64_t)(uintptr_t)switch_task_context;
    uint64_t end = (uint64_t)(uintptr_t)scheduler_init;
    return rip >= start && rip < end;
}

void scheduler_init(void) {
    if (g_scheduler_ready) return;
    g_scheduler_kernel_cr3 = cr3_read();

    g_online_cpu_mask = 1u;
    for (uint32_t i = 0; i < SCHED_MAX_CPUS; ++i) {
        scheduler_cpu_t *cpu = &g_sched_cpus[i];
        task_t *idle = &g_idle_tasks[i];
        cpu->current = 0;
        cpu->rq_head = 0;
        cpu->rq_tail = 0;
        __atomic_store_n(&cpu->nr_running, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&cpu->user_time_us, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&cpu->system_time_us, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&cpu->runqueue_wait_us, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&cpu->context_switches, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&cpu->migrations, 0u, __ATOMIC_RELEASE);
        cpu->logical_id = i;
        spinlock_init(&cpu->rq_lock);

        idle->pid = 0;
        idle->ppid = 0;
        idle->exit_code = 0;
        idle->state = TASK_RUNNING;
        idle->on_runqueue = 0;
        idle->is_idle = 1;
        idle->on_cpu = 0;
        idle->context_ready = 1;
        idle->assigned_cpu = (int)i;
        edge_linux_scheduler_state_init(&idle->scheduler, 1ull << i);
        edge_linux_scheduler_entity_init(
            &idle->scheduler_entity, &idle->scheduler,
            boottime_monotonic_us());
        idle->rq_prev = 0;
        idle->rq_next = 0;
        idle->parent = 0;
        idle->first_child = 0;
        idle->sibling_prev = 0;
        idle->sibling_next = 0;
        idle->kernel_stack_top = (uint64_t)(uintptr_t)&g_idle_stacks[i][sizeof(g_idle_stacks[i]) - 16];
        idle->cr3 = g_scheduler_kernel_cr3;
        idle->fs_base = 0;
        idle->context.rsp = idle->kernel_stack_top;
        idle->context.rbp = idle->kernel_stack_top;
        idle->context.rip = (uint64_t)(uintptr_t)scheduler_idle_loop;
        cpu->idle = idle;
        cpu->current = idle;
    }

    g_online_cpu_mask = edge_smp_online_mask64();
    g_scheduler_ready = 1;
}

void scheduler_set_cpu_id(uint32_t logical_id) {
    if (logical_id >= SCHED_MAX_CPUS) logical_id = 0;
    if (edge_smp_cpu_state(logical_id) == EDGE_CPU_STARTING)
        (void)edge_smp_set_state(logical_id, EDGE_CPU_ONLINE);
    __atomic_fetch_or(&g_online_cpu_mask, 1ull << logical_id,
                      __ATOMIC_RELEASE);
}

uint32_t scheduler_cpu_id(void) {
    uint32_t id = x86_smp_current_cpu_id();
    if (id >= SCHED_MAX_CPUS) id = 0;
    return id;
}

uint64_t scheduler_online_cpu_mask(void) {
    uint64_t mask = __atomic_load_n(&g_online_cpu_mask, __ATOMIC_ACQUIRE);
    return mask ? mask : 1u;
}

uint32_t scheduler_pick_target_cpu(uint64_t affinity_mask) {
    uint64_t online = scheduler_online_cpu_mask();
    uint64_t allowed = online & affinity_mask;
    uint32_t current = scheduler_cpu_id();
    uint32_t best = current;
    uint32_t best_load = UINT32_MAX;

    if (!allowed) allowed = online;
    if (!(allowed & (UINT64_C(1) << current))) {
        for (best = 0; best < SCHED_MAX_CPUS && best < 64u; ++best)
            if (allowed & (UINT64_C(1) << best)) break;
    }
    for (uint32_t cpu = 0; cpu < SCHED_MAX_CPUS && cpu < 64u; ++cpu) {
        uint32_t load;

        if (!(allowed & (UINT64_C(1) << cpu))) continue;
        load = scheduler_cpu_load(cpu);
        if (load < best_load || (load == best_load && cpu == current)) {
            best = cpu;
            best_load = load;
        }
    }
    return best < SCHED_MAX_CPUS ? best : 0u;
}

uint64_t scheduler_kernel_cr3(void) {
    return g_scheduler_kernel_cr3;
}

uint64_t scheduler_idle_stack_top(uint32_t logical_id) {
    if (logical_id >= SCHED_MAX_CPUS) return 0;
    return g_idle_tasks[logical_id].kernel_stack_top;
}

void scheduler_secondary_enter(uint32_t logical_id) {
    scheduler_cpu_t *cpu;

    if (logical_id >= SCHED_MAX_CPUS) logical_id = 0;
    scheduler_set_cpu_id(logical_id);
    cpu = cpu_by_id(logical_id);
    cpu->current = cpu->idle;
    cpu->idle->assigned_cpu = (int)logical_id;
    cpu->idle->on_cpu = 1;
    gdt_set_tss_rsp0(cpu->idle->kernel_stack_top);
    __asm__ __volatile__("sti" ::: "memory");
    scheduler_idle_loop();
    __builtin_unreachable();
}

scheduler_cpu_t *scheduler_cpu_local(void) {
    if (!g_scheduler_ready) return 0;
    return cpu_by_id(scheduler_cpu_id());
}

task_t *scheduler_current_task(void) {
    scheduler_cpu_t *cpu = scheduler_cpu_local();
    task_t *cur;
    if (!cpu) return &g_idle_tasks[0];
    cur = cpu->current ? cpu->current : (cpu->idle ? cpu->idle : &g_idle_tasks[0]);
    if (!scheduler_task_ptr_valid(cur)) {
        scheduler_log_bad_task_ptr("current", cur);
        cpu->current = cpu->idle ? cpu->idle : &g_idle_tasks[0];
        cur = cpu->current;
    }
#if EDGE_SCHED_DEBUG
    printf("[sched] current cpu=%u pid=%d st=%s acpu=%d onrq=%d head=%d tail=%d cur=%d\n",
           cpu->logical_id, sched_pid(cur), sched_state_name(cur->state), cur->assigned_cpu,
           (int)cur->on_runqueue, sched_pid(cpu->rq_head), sched_pid(cpu->rq_tail), sched_pid(cpu->current));
#endif
    return cur;
}

void scheduler_set_boot_current(task_t *t) {
    scheduler_cpu_t *cpu = scheduler_cpu_local();
    edge_linux_scheduler_state_t effective;
    if (!cpu || !t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("set_boot_current", t);
        return;
    }

    uint64_t flags = spin_lock_irqsave(&cpu->rq_lock);
    if (t->on_runqueue) rq_remove_locked(cpu, t);
    t->assigned_cpu = (int)scheduler_cpu_id();
    t->state = TASK_RUNNING;
    t->context_ready = 0;
    t->on_cpu = 1;
    scheduler_effective_state(t, &effective);
    edge_linux_scheduler_entity_begin_slice(
        &t->scheduler_entity, &effective);
    scheduler_account_run_start(t, boottime_monotonic_us());
    cpu->current = t;
    process_user_mm_cpu_enter(t, scheduler_cpu_id());
    spin_unlock_irqrestore(&cpu->rq_lock, flags);
}

void scheduler_task_context_ready(task_t *t) {
    if (!t || !scheduler_task_ptr_valid(t) || t->is_idle) return;
    if (!scheduler_task_context_image_valid(t)) {
        scheduler_log_bad_context("context_ready", t);
        return;
    }
    t->on_cpu = 0;
    t->context_ready = 1;
    ++t->context_generation;
    if (!t->context_generation) ++t->context_generation;
    scheduler_context_event(SCHED_CONTEXT_READY, scheduler_current_task(), t,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));
}

void scheduler_task_make_runnable(task_t *t, uint32_t cpu_id) {
    scheduler_cpu_t *cpu;
    scheduler_cpu_t *old_cpu;
    uint64_t flags;
    uint32_t old_cpu_id;
    uint64_t source_min_vruntime = 0u;
    int woke_from_blocked;
    int notify_remote = 0;

    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("make_runnable", t);
        return;
    }
    if (t->is_idle) return;
    /*
     * Object wake queues may observe an event concurrently with task teardown.
     * An exited task is terminal: a stale fd, child, or futex wake must never
     * turn TASK_ZOMBIE or TASK_UNUSED back into a schedulable task.
     */
    if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) return;

    for (;;) {
        int assigned = __atomic_load_n(&t->assigned_cpu, __ATOMIC_ACQUIRE);

        old_cpu_id = assigned >= 0 ? (uint32_t)assigned : cpu_id;
        if (old_cpu_id >= SCHED_MAX_CPUS) old_cpu_id = 0u;
        old_cpu = cpu_by_id(old_cpu_id);
        flags = spin_lock_irqsave(&old_cpu->rq_lock);

        /*
         * assigned_cpu is the runqueue ownership token.  It may change while
         * a remote waker is selecting a destination, so validate it after
         * locking the observed owner.  A mover publishes the new owner before
         * releasing the old queue.  Every concurrent wake therefore either
         * serializes on this lock or retries against the newly published
         * owner; no path can unlink a task through the wrong queue pointers.
         */
        if (__atomic_load_n(&t->assigned_cpu, __ATOMIC_ACQUIRE) != assigned) {
            spin_unlock_irqrestore(&old_cpu->rq_lock, flags);
            continue;
        }

        if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) {
            spin_unlock_irqrestore(&old_cpu->rq_lock, flags);
            return;
        }

        /*
         * A task in a stack handoff already has a destination owner.  Keep a
         * concurrent wake on that owner; the source CPU or migration tail will
         * publish the reusable continuation and queue it after the handoff.
         */
        if (t->switch_pending) {
            if (t->state == TASK_BLOCKED || t->state == TASK_STOPPED)
                t->state = TASK_RUNNABLE;
            if (t->state == TASK_RUNNABLE && t->context_ready &&
                !t->on_cpu && !t->on_runqueue) {
                scheduler_place_wakeup_locked(old_cpu, t, 1);
                rq_push_tail_locked(old_cpu, t);
            }
            spin_unlock_irqrestore(&old_cpu->rq_lock, flags);
            if (old_cpu_id != scheduler_cpu_id())
                (void)edge_smp_reschedule(old_cpu_id);
            return;
        }

        /*
         * A wake can race the block-before-yield window.  The task still owns
         * its live kernel stack, so restore it as the running task on the
         * recorded owner instead of exposing that continuation to a queue.
         */
        if (t->on_cpu) {
            if (t->on_runqueue) rq_remove_locked(old_cpu, t);
            t->assigned_cpu = (int)old_cpu_id;
            if (t->state != TASK_RUNNING) {
                t->state = TASK_RUNNING;
                scheduler_account_run_start(t, boottime_monotonic_us());
            }
            spin_unlock_irqrestore(&old_cpu->rq_lock, flags);
            return;
        }

        /* Repeated wakeups are idempotent.  In particular, do not migrate an
         * already runnable task merely because another CPU observed the same
         * event and supplied its own CPU as the placement hint. */
        if (t->state == TASK_RUNNABLE && t->on_runqueue)
            rq_recover_stranded_locked(old_cpu, t);
        if (t->state == TASK_RUNNING ||
            (t->state == TASK_RUNNABLE && t->on_runqueue)) {
            spin_unlock_irqrestore(&old_cpu->rq_lock, flags);
            return;
        }

        source_min_vruntime = scheduler_min_vruntime_locked(old_cpu);
        cpu_id = scheduler_select_allowed_cpu(t, cpu_id);
        if (cpu_id >= SCHED_MAX_CPUS) cpu_id = 0u;
        if (t->on_runqueue && old_cpu_id != cpu_id)
            rq_remove_locked(old_cpu, t);

        if (old_cpu_id == cpu_id) {
            cpu = old_cpu;
            break;
        }

        __atomic_store_n(&t->assigned_cpu, (int)cpu_id, __ATOMIC_RELEASE);
        spin_unlock_irqrestore(&old_cpu->rq_lock, flags);

        cpu = cpu_by_id(cpu_id);
        flags = spin_lock_irqsave(&cpu->rq_lock);
        if (__atomic_load_n(&t->assigned_cpu, __ATOMIC_ACQUIRE) !=
            (int)cpu_id) {
            spin_unlock_irqrestore(&cpu->rq_lock, flags);
            continue;
        }
        break;
    }

    if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }
    scheduler_context_event(SCHED_CONTEXT_WAKE, cpu->current, t,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));

    /*
     * A wakeup is idempotent.  In particular, never enqueue the task whose
     * kernel stack is executing on this CPU: its saved context describes the
     * previous switch-in and becomes stale as soon as that stack is reused.
     *
     * A waiter marks itself blocked before its final condition check and
     * schedule call.  If the event arrives in that interval, turn it back into
     * the running task without queueing it.  Its following voluntary schedule
     * will then requeue it normally, preserving the wakeup without exposing a
     * stale context to the run queue.
     */
    if (t->on_cpu) {
        if (t->on_runqueue) rq_remove_locked(cpu, t);
        if (t->state != TASK_RUNNING) {
            t->state = TASK_RUNNING;
            scheduler_account_run_start(t, boottime_monotonic_us());
        }
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }

    /* A task already running on another CPU or already queued is awake. */
    if (t->state == TASK_RUNNABLE && t->on_runqueue)
        rq_recover_stranded_locked(cpu, t);
    if (t->state == TASK_RUNNING ||
        (t->state == TASK_RUNNABLE && t->on_runqueue)) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }

    woke_from_blocked = ((t->state == TASK_BLOCKED ||
                          t->state == TASK_STOPPED) && !t->on_runqueue);
    if (t->assigned_cpu >= 0 && old_cpu_id != cpu_id &&
        t->scheduler_migrations != UINT64_MAX) {
        t->scheduler_migrations++;
        scheduler_counter_add(&cpu_by_id(old_cpu_id)->migrations, 1u);
    }
    t->assigned_cpu = (int)cpu_id;
    if (t->on_runqueue) rq_remove_locked(cpu, t);
    t->state = TASK_RUNNABLE;
    if (old_cpu_id != cpu_id && t->scheduler_vruntime_valid) {
        t->scheduler_vruntime_us = edge_linux_scheduler_rebase_vruntime(
            t->scheduler_vruntime_us, source_min_vruntime,
            scheduler_min_vruntime_locked(cpu));
    }
    /*
     * Place a sleeper close to the least-served normal task, with only a
     * bounded wakeup advantage.  A permanent head insertion lets a large set
     * of browser workers repeatedly leapfrog an interactive task and can
     * suspend a tiny syscall for seconds.  Virtual runtime preserves prompt
     * input and IPC wakeups without allowing sleepers to starve existing work.
     */
    scheduler_place_wakeup_locked(cpu, t, woke_from_blocked);
    rq_push_tail_locked(cpu, t);
    notify_remote = cpu_id != scheduler_cpu_id();
    if (cpu->current && !cpu->current->is_idle) {
        uint64_t now = boottime_monotonic_us();
        uint64_t live_runtime = cpu->current->rusage_run_start_us &&
                                now > cpu->current->rusage_run_start_us ?
                                now - cpu->current->rusage_run_start_us : 0;
        uint64_t runtime;
        int preempts;
        edge_linux_scheduler_state_t candidate_effective;
        edge_linux_scheduler_state_t current_effective;
        int group_order = 0;

        scheduler_effective_state(t, &candidate_effective);
        scheduler_effective_state(cpu->current, &current_effective);
        runtime = edge_linux_scheduler_entity_slice_runtime_us(
            &cpu->current->scheduler_entity, &current_effective,
            live_runtime);
        if (edge_linux_scheduler_state_compare(
                &candidate_effective, &current_effective) == 0 &&
            edge_linux_scheduler_policy_is_fair(
                candidate_effective.policy))
            group_order = cgroupfs_cpu_group_order(
                t->cgroup_id, cpu->current->cgroup_id);

        if (group_order != 0 &&
            runtime >= EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US) {
            preempts = group_order > 0;
        } else if (edge_linux_scheduler_policy_is_fair(
                candidate_effective.policy) &&
            edge_linux_scheduler_policy_is_fair(
                current_effective.policy)) {
            preempts = edge_linux_scheduler_fair_wakeup_preempts(
                &candidate_effective, t->scheduler_vruntime_us,
                &current_effective,
                cpu->current->scheduler_vruntime_us,
                runtime, EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US);
        } else {
            preempts = edge_linux_scheduler_entity_precedes(
                &candidate_effective, &t->scheduler_entity,
                t->scheduler_vruntime_us,
                &current_effective,
                &cpu->current->scheduler_entity,
                cpu->current->scheduler_vruntime_us,
                cpu->current->scheduler_vruntime_us, 1u, now);
        }
        if (preempts)
            cpu->current->need_resched = 1;
    }
    sched_log_cpu("make_runnable", cpu, t);
    sched_invariant_check("make_runnable", cpu);

    spin_unlock_irqrestore(&cpu->rq_lock, flags);
    if (notify_remote) (void)edge_smp_reschedule(cpu_id);
}

void scheduler_task_set_blocked(task_t *t) {
    scheduler_cpu_t *cpu;
    uint32_t cpu_id;
    uint64_t flags;

    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("set_blocked", t);
        return;
    }
    if (t->is_idle) return;
    cpu = scheduler_lock_task_owner(t, scheduler_cpu_id(), &cpu_id, &flags);
    if (process_task_group_exit_requested(t, 0)) {
        if (t->state != TASK_ZOMBIE && t->state != TASK_UNUSED)
            t->state = TASK_RUNNING;
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }
    if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }
    scheduler_context_event(SCHED_CONTEXT_BLOCK, cpu->current, t,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));

    if (t->on_runqueue) rq_remove_locked(cpu, t);
    scheduler_account_run_stop(t, boottime_monotonic_us());
    t->assigned_cpu = (int)cpu_id;
    t->state = TASK_BLOCKED;
    sched_log_cpu("set_blocked", cpu, t);
    sched_invariant_check("set_blocked", cpu);

    spin_unlock_irqrestore(&cpu->rq_lock, flags);
}

void scheduler_task_set_stopped(task_t *t) {
    scheduler_cpu_t *cpu;
    uint32_t cpu_id;
    uint64_t flags;

    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("set_stopped", t);
        return;
    }
    if (t->is_idle) return;
    cpu = scheduler_lock_task_owner(t, scheduler_cpu_id(), &cpu_id, &flags);
    if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }

    if (t->on_runqueue) rq_remove_locked(cpu, t);
    scheduler_account_run_stop(t, boottime_monotonic_us());
    t->assigned_cpu = (int)cpu_id;
    t->state = TASK_STOPPED;
    sched_log_cpu("set_stopped", cpu, t);
    sched_invariant_check("set_stopped", cpu);

    spin_unlock_irqrestore(&cpu->rq_lock, flags);
}

void scheduler_task_set_zombie(task_t *t) {
    scheduler_cpu_t *cpu;
    uint32_t cpu_id;
    uint64_t flags;
    int notify_remote = 0;

    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("set_zombie", t);
        return;
    }
    if (t->is_idle) return;
    cpu = scheduler_lock_task_owner(t, scheduler_cpu_id(), &cpu_id, &flags);
    if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }

    if (t->on_runqueue) rq_remove_locked(cpu, t);
    scheduler_account_run_stop(t, boottime_monotonic_us());
    t->assigned_cpu = (int)cpu_id;
    t->state = TASK_ZOMBIE;
    if (t->on_cpu) {
        /*
         * Thread-group teardown can retire a sibling that is executing on a
         * different CPU.  A zombie is no longer eligible for the ordinary
         * tick preemption test, so explicitly request a scheduling boundary;
         * otherwise it can keep executing against resources already released
         * by the group leader.
         */
        t->need_resched = 1;
        notify_remote = cpu_id != scheduler_cpu_id();
    }
    sched_log_cpu("set_zombie", cpu, t);
    sched_invariant_check("set_zombie", cpu);

    spin_unlock_irqrestore(&cpu->rq_lock, flags);
    if (notify_remote) (void)edge_smp_reschedule(cpu_id);
}

void scheduler_task_set_unused(task_t *t) {
    scheduler_cpu_t *cpu;
    uint32_t cpu_id;
    uint64_t flags;

    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("set_unused", t);
        return;
    }
    if (t->is_idle) return;
    cpu = scheduler_lock_task_owner(t, scheduler_cpu_id(), &cpu_id, &flags);

    if (t->on_runqueue) rq_remove_locked(cpu, t);
    t->assigned_cpu = -1;
    t->state = TASK_UNUSED;
    t->on_cpu = 0;
    t->context_ready = 0;

    spin_unlock_irqrestore(&cpu->rq_lock, flags);
}

int scheduler_task_reap_ready(task_t *t) {
    scheduler_cpu_t *cpu;
    uint32_t cpu_id;
    uint64_t flags;
    int ready;

    if (!t || !scheduler_task_ptr_valid(t) || t->is_idle) return 0;
    cpu = scheduler_lock_task_owner(t, 0u, &cpu_id, &flags);
    ready = t->state == TASK_ZOMBIE && !t->on_cpu &&
            !t->switch_pending && !t->on_runqueue;
    spin_unlock_irqrestore(&cpu->rq_lock, flags);
    return ready;
}

void scheduler_task_set_running(task_t *t) {
    scheduler_cpu_t *cpu;
    uint32_t cpu_id;
    uint64_t flags;

    if (!t) return;
    if (!scheduler_task_ptr_valid(t)) {
        scheduler_log_bad_task_ptr("set_running", t);
        return;
    }
    if (t->is_idle) return;
    cpu = scheduler_lock_task_owner(t, scheduler_cpu_id(), &cpu_id, &flags);
    if (t->state == TASK_ZOMBIE || t->state == TASK_UNUSED) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }

    if (t->on_runqueue) rq_remove_locked(cpu, t);
    scheduler_account_run_stop(t, boottime_monotonic_us());
    t->assigned_cpu = (int)cpu_id;
    t->state = TASK_RUNNING;
    /*
     * The futex wake-before-block repair path can return directly to the
     * interrupted task without passing through the normal scheduler pick.
     * Start a fresh accounting interval here so that both rusage and fair
     * virtual runtime continue to advance after that transition.
     */
    scheduler_account_run_start(t, boottime_monotonic_us());
    sched_log_cpu("set_running", cpu, t);
    sched_invariant_check("set_running", cpu);

    spin_unlock_irqrestore(&cpu->rq_lock, flags);
}

void scheduler_schedule_common(int tick_mode) {
    scheduler_cpu_t *cpu = scheduler_cpu_local();
    task_t *prev;
    task_t *next;
    task_t *migration_task = 0;
    uint32_t migration_cpu = 0;
    uint64_t migration_source_min_vruntime = 0u;
    uint64_t flags;
    uint64_t now;
    uint64_t stack_pointer;
    task_t *stack_owner;
    uint32_t account_result;

    if (!g_scheduler_ready || !cpu) return;
    /*
     * Linux fbdev mmap stores become visible to scanout without a userspace
     * syscall.  EdgeOS' virtio-gpu bridge needs an explicit transfer, but that
     * transfer must happen from process context, not the PIT IRQ.  Ordinary
     * yield points are a natural process-context heartbeat for Xorg/ShadowFB
     * and any other fbdev mmap owner that is sleeping in poll/epoll.  Timer IRQ
     * preemption calls schedule_common(tick_mode=1), so do not flush there.
     */
    if (!tick_mode) fb_user_mmap_pump_deferred();

    flags = spin_lock_irqsave(&cpu->rq_lock);
    prev = cpu->current ? cpu->current : cpu->idle;
    if (cpu->retired && cpu->retired != prev) {
        /*
         * Reaching a later scheduler entry on the destination stack proves
         * the preceding architecture switch no longer executes on the old
         * task's kernel stack.  Only now may teardown recycle that task slot.
         */
        uint32_t retired_cpu = cpu->retired->assigned_cpu >= 0 ?
            (uint32_t)cpu->retired->assigned_cpu : scheduler_cpu_id();

        cpu->retired->switch_pending = 0;
        cpu->retired = 0;
        if (retired_cpu != scheduler_cpu_id())
            (void)edge_smp_reschedule(retired_cpu);
    }
    scheduler_context_event(SCHED_CONTEXT_SCHEDULE, prev, prev,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(stack_pointer));
    stack_owner = scheduler_task_for_kernel_sp(stack_pointer);
    if (stack_owner && stack_owner != prev) {
        printf("[sched][FATAL] current/stack mismatch current=%d:%s owner=%d:%s rsp=0x%x current_top=0x%x owner_top=0x%x\n",
               prev ? prev->pid : -1, prev ? prev->name : "nil",
               stack_owner->pid, stack_owner->name,
               (uint32_t)stack_pointer,
               prev ? (uint32_t)prev->kernel_stack_top : 0u,
               (uint32_t)stack_owner->kernel_stack_top);
        spin_unlock_irqrestore(&cpu->rq_lock, flags & ~(1ull << 9));
        for (;;) __asm__ __volatile__("hlt");
    }
    if (!scheduler_task_ptr_valid(prev)) {
        scheduler_log_bad_task_ptr("schedule_prev", prev);
        prev = cpu->idle;
        cpu->current = prev;
    }
    sched_log_cpu(tick_mode ? "yield_tick" : "yield", cpu, prev);

    if (!prev) {
        spin_unlock_irqrestore(&cpu->rq_lock, flags);
        return;
    }

    now = boottime_monotonic_us();
    account_result = scheduler_account_run_stop(prev, now);
    if ((account_result & EDGE_SCHEDULER_ACCOUNT_OVERRUN) &&
        prev && !prev->is_idle)
        (void)process_send_signal_thread(prev->pid, EDGE_LINUX_SIGXCPU);

    if (!prev->is_idle) {
        if (tick_mode) {
            if (prev->state == TASK_RUNNING || prev->state == TASK_RUNNABLE) {
                uint32_t target = scheduler_select_allowed_cpu(
                    prev, scheduler_cpu_id());
                prev->rusage_involuntary_ctxt_switches++;
                prev->on_cpu = 0;
                prev->context_ready = 1;
                prev->state = TASK_RUNNABLE;
                if (target == scheduler_cpu_id()) {
                    rq_push_tail_locked(cpu, prev);
                } else {
                    /*
                     * Publish the stack handoff before changing the task's
                     * runqueue owner.  A remote wake can observe assigned_cpu
                     * immediately and enqueue the task on the destination.
                     * switch_pending keeps that CPU from restoring the saved
                     * context until this CPU has switched away from the live
                     * kernel stack and cleared the handoff on its next
                     * scheduler entry.
                     */
                    prev->switch_pending = 1;
                    cpu->retired = prev;
                    __atomic_thread_fence(__ATOMIC_RELEASE);
                    if (prev->scheduler_migrations != UINT64_MAX)
                        prev->scheduler_migrations++;
                    scheduler_counter_add(&cpu->migrations, 1u);
                    prev->assigned_cpu = (int)target;
                    migration_task = prev;
                    migration_cpu = target;
                    migration_source_min_vruntime =
                        scheduler_min_vruntime_locked(cpu);
                }
            } else {
                /*
                 * A timer can interrupt the block-before-yield window used by
                 * futex and other wait paths.  The task is still the CPU's
                 * current stack, but it is not runnable.  Publish the saved
                 * continuation before selecting another task so a later wake
                 * can enqueue it instead of mistaking stale on_cpu state for
                 * an executing waiter.
                 */
                prev->on_cpu = 0;
                prev->context_ready = 1;
            }
        } else if (prev->state == TASK_RUNNING) {
            uint32_t target = scheduler_select_allowed_cpu(
                prev, scheduler_cpu_id());
            prev->rusage_voluntary_ctxt_switches++;
            prev->on_cpu = 0;
            prev->context_ready = 1;
            prev->state = TASK_RUNNABLE;
            if (target == scheduler_cpu_id()) {
                rq_push_tail_locked(cpu, prev);
            } else {
                /* See the timer-preemption migration handoff above. */
                prev->switch_pending = 1;
                cpu->retired = prev;
                __atomic_thread_fence(__ATOMIC_RELEASE);
                if (prev->scheduler_migrations != UINT64_MAX)
                    prev->scheduler_migrations++;
                scheduler_counter_add(&cpu->migrations, 1u);
                prev->assigned_cpu = (int)target;
                migration_task = prev;
                migration_cpu = target;
                migration_source_min_vruntime =
                    scheduler_min_vruntime_locked(cpu);
            }
        } else {
            prev->on_cpu = 0;
            prev->context_ready = 1;
        }
    } else {
        prev->on_cpu = 0;
        prev->context_ready = 1;
    }

    /*
     * Device interrupts only acknowledge hardware and request process-context
     * work.  Give the idle kernel thread one bounded turn even when userspace
     * remains continuously runnable, otherwise desktop workloads can starve
     * network receive, protocol timers, USB, and other deferred work forever.
     * The idle thread polls once and immediately yields back to the fair run
     * queue, so this is a bottom-half handoff rather than idle-time polling.
     */
    if (tick_mode && cpu->idle &&
        kernel_deferred_work_service_pending(scheduler_cpu_id()))
        next = cpu->idle;
    else
        next = pick_next_runnable_locked(cpu, prev);
    scheduler_context_event(SCHED_CONTEXT_PICK, prev, next,
                            (uint64_t)(uintptr_t)__builtin_return_address(0));
    if (!scheduler_task_runnable_ptr(next)) {
        scheduler_log_bad_task_ptr("schedule_next", next);
        next = cpu->idle;
    }
    if (next && !next->is_idle) {
        edge_linux_scheduler_state_t effective;

        next->assigned_cpu = (int)scheduler_cpu_id();
        next->state = TASK_RUNNING;
        next->need_resched = 0;
        scheduler_effective_state(next, &effective);
        edge_linux_scheduler_entity_begin_slice(
            &next->scheduler_entity, &effective);
        scheduler_account_run_start(next, now);
    }
    if (next) {
        next->consumed_context_generation = next->context_generation;
        next->context_ready = 0;
        next->on_cpu = 1;
        process_user_mm_cpu_enter(next, scheduler_cpu_id());
    }
    if (prev && !prev->is_idle && next != prev) {
        prev->switch_pending = 1;
        cpu->retired = prev;
    }
    cpu->current = next ? next : cpu->idle;
    if (cpu->current != prev)
        scheduler_counter_add(&cpu->context_switches, 1u);
    if (!cpu->current) {
        printf("[sched][ERR] schedule_common cpu=%u selected NULL current\n", cpu->logical_id);
        cpu->current = cpu->idle;
    }
    sched_log_cpu("yield_pick", cpu, cpu->current);
    sched_invariant_check("yield_pick", cpu);

    /*
     * Publishing cpu->current and switching its stack/CR3 is one atomic
     * scheduler transition.  Restoring IF before switch_task_context() leaves
     * a window where a timer IRQ observes the next task as current while the
     * CPU is still executing on the previous task's stack.  The IRQ scheduler
     * then saves that old continuation into the next task and destroys its
     * first-entry context.  Release the runqueue lock with interrupts still
     * masked, perform the architecture switch, and restore the caller's IF
     * state only when an existing context eventually resumes here.  A newly
     * spawned task enters userspace through iretq, which supplies its own IF.
     */
    spin_unlock_irqrestore(&cpu->rq_lock, flags & ~(1ull << 9));

    if (migration_task) {
        scheduler_cpu_t *destination = cpu_by_id(migration_cpu);
        uint64_t destination_flags =
            spin_lock_irqsave(&destination->rq_lock);

        if (migration_task->state == TASK_RUNNABLE &&
            migration_task->context_ready && !migration_task->on_cpu &&
            !migration_task->on_runqueue) {
            if (migration_task->scheduler_vruntime_valid) {
                migration_task->scheduler_vruntime_us =
                    edge_linux_scheduler_rebase_vruntime(
                        migration_task->scheduler_vruntime_us,
                        migration_source_min_vruntime,
                        scheduler_min_vruntime_locked(destination));
            }
            scheduler_place_wakeup_locked(destination, migration_task, 0);
            rq_push_tail_locked(destination, migration_task);
        }
        spin_unlock_irqrestore(&destination->rq_lock,
                               destination_flags & ~(1ull << 9));
    }

    if (cpu->current != prev) {
        switch_task_context(prev, cpu->current);
    }
    /*
     * The architecture wrapper restores IF with an adjacent STI; RET pair.
     * Enabling interrupts inside this C frame lets a pending timer interrupt
     * observe its partially executed epilogue and save a context whose return
     * address lies in the user trap frame.  Keep the stack non-preemptible
     * until it has been completely unwound.
     */
}

void scheduler_request_deferred_work(void) {
    kernel_deferred_work_request();
}

int scheduler_take_deferred_work(void) {
    return kernel_deferred_work_take();
}

void scheduler_tick(void) {
    scheduler_cpu_t *cpu = scheduler_cpu_local();
    task_t *cur;
    int deferred_due = 0;
    int policy_preempts = 0;
    uint64_t now;
    uint64_t runtime;
    if (!g_scheduler_ready || !cpu) return;
    cur = cpu->current ? cpu->current : cpu->idle;
    if (!scheduler_task_ptr_valid(cur)) {
        scheduler_log_bad_task_ptr("tick_current", cur);
        cpu->current = cpu->idle;
        cur = cpu->current;
    }
    if (!cur) return;
    now = boottime_monotonic_us();
    runtime = cur->rusage_run_start_us && now > cur->rusage_run_start_us ?
              now - cur->rusage_run_start_us : 0;
    g_sched_total_ticks++;
    if (cur->is_idle) g_sched_idle_ticks++;
    /*
     * Interrupt-capable devices request an immediate bottom-half turn.  This
     * periodic fallback also services devices operating without a usable IRQ
     * route and advances protocol timers while all user tasks remain runnable.
     */
    if (edge_kernel_timer_runs_global_work(cpu->logical_id) &&
        kernel_deferred_work_tick(EDGE_KERNEL_TIMER_50MS_TICKS)) {
        deferred_due = 1;
    }
    if (!cur->is_idle && cur->state == TASK_RUNNING) {
        edge_linux_scheduler_state_t effective;

        scheduler_effective_state(cur, &effective);
        if (edge_linux_scheduler_policy_is_fair(effective.policy)) {
            uint32_t runnable =
                __atomic_load_n(&cpu->nr_running, __ATOMIC_ACQUIRE);

            runtime = edge_linux_scheduler_entity_slice_runtime_us(
                &cur->scheduler_entity, &effective, runtime);
            if (runnable != UINT32_MAX) ++runnable;
            policy_preempts = runtime >=
                edge_linux_scheduler_request_slice_us(runnable);
        } else {
            policy_preempts = edge_linux_scheduler_entity_tick_preempts(
                &effective, &cur->scheduler_entity,
                &effective, &cur->scheduler_entity, runtime, now);
        }
    }
    if (!cur->is_idle && cur->state == TASK_RUNNING &&
        (policy_preempts || deferred_due ||
         kernel_deferred_work_service_pending(scheduler_cpu_id()))) {
        cur->need_resched = 1;
    }
}

void scheduler_kill_current_and_yield(int code) {
    /*
     * This path is used by Linux exit(2) and by short-lived pthread helpers.
     * Linux exit(2) terminates only the calling task; exit_group(2), fatal
     * signals, and hardware exceptions are the process-fatal paths.  Do not
     * collapse normal thread exit into thread-group teardown or desktop
     * helpers such as GLib worker pools will kill xfce4-session/Xorg when a
     * worker returns normally.
     */
    process_exit_current(code);
    scheduler_yield();
    for (;;) {
        __asm__ __volatile__("sti; hlt");
    }
}

void scheduler_kill_current_group_and_yield(int code) {
    /*
     * Fatal Linux signals terminate the complete thread group, but they still
     * arrive through a valid syscall or interrupt continuation.  Retire the
     * group and let the regular scheduler save and switch that continuation.
     * scheduler_abandon_current_and_yield() is reserved for a kernel frame
     * that is already known to be corrupt and cannot safely be saved.
     */
    process_exit_current_group(code);
    scheduler_yield();
    for (;;) {
        __asm__ __volatile__("sti; hlt");
    }
}

void scheduler_abandon_current_and_yield(int code) {
    scheduler_cpu_t *cpu;
    task_t *prev;
    task_t *next;
    uint64_t flags;

    process_exit_current_group(code);

    cpu = scheduler_cpu_local();
    if (!g_scheduler_ready || !cpu) {
        for (;;) __asm__ __volatile__("sti; hlt");
    }

    flags = spin_lock_irqsave(&cpu->rq_lock);
    prev = cpu->current ? cpu->current : cpu->idle;
    if (prev && scheduler_task_ptr_valid(prev) && !prev->is_idle) {
        if (prev->on_runqueue) rq_remove_locked(cpu, prev);
        scheduler_account_run_stop(prev, boottime_monotonic_us());
        prev->state = TASK_ZOMBIE;
        prev->on_runqueue = 0;
        prev->rq_next = 0;
        prev->rq_prev = 0;
        prev->on_cpu = 0;
        prev->context_ready = 0;
    }

    next = pick_next_runnable_locked(cpu, 0);
    if (!scheduler_task_runnable_ptr(next)) next = cpu->idle;
    if (next && !next->is_idle) {
        edge_linux_scheduler_state_t effective;

        next->assigned_cpu = (int)scheduler_cpu_id();
        next->state = TASK_RUNNING;
        next->need_resched = 0;
        scheduler_effective_state(next, &effective);
        edge_linux_scheduler_entity_begin_slice(
            &next->scheduler_entity, &effective);
        scheduler_account_run_start(next, boottime_monotonic_us());
    }
    if (next) {
        next->consumed_context_generation = next->context_generation;
        next->context_ready = 0;
        next->on_cpu = 1;
        process_user_mm_cpu_enter(next, scheduler_cpu_id());
    }
    if (prev && !prev->is_idle && next != prev) {
        prev->switch_pending = 1;
        cpu->retired = prev;
    }
    cpu->current = next ? next : cpu->idle;
    if (cpu->current != prev)
        scheduler_counter_add(&cpu->context_switches, 1u);

    /*
     * Keep interrupts masked until the dead task's stack has been abandoned.
     * Publishing the replacement as cpu->current while an interrupt can still
     * arrive on the old stack lets the IRQ scheduler save that old continuation
     * into the replacement task.  This is the fatal-exit counterpart of the
     * atomic handoff in scheduler_schedule_common().  The resumed context (or
     * its userspace return frame) restores the destination task's IF state.
     */
    spin_unlock_irqrestore(&cpu->rq_lock, flags & ~(1ull << 9));

    /*
     * Used after detecting a corrupted kernel continuation.  Do not call the
     * normal yield path: switch_to would save the bad faulting scheduler frame
     * into the dying task and it may be resumed later if the slot is recycled.
     */
    switch_task_context(0, cpu->current);
    for (;;) __asm__ __volatile__("sti; hlt");
}

uint64_t scheduler_total_ticks(void) {
    return g_sched_total_ticks;
}

uint64_t scheduler_idle_ticks(void) {
    return g_sched_idle_ticks;
}

int kernel_arch_scheduler_cpu_stats(
        uint32_t cpu_id, kernel_scheduler_cpu_stats_t *stats) {
    scheduler_cpu_t *cpu;
    task_t *current;
    uint64_t now;
    uint64_t accounted;
    uint64_t live = 0u;

    if (!stats || cpu_id >= SCHED_MAX_CPUS ||
        !(scheduler_online_cpu_mask() & (1ull << cpu_id)))
        return -1;
    memset(stats, 0, sizeof(*stats));
    cpu = cpu_by_id(cpu_id);
    stats->user_time_us =
        __atomic_load_n(&cpu->user_time_us, __ATOMIC_ACQUIRE);
    stats->system_time_us =
        __atomic_load_n(&cpu->system_time_us, __ATOMIC_ACQUIRE);
    stats->runqueue_wait_us =
        __atomic_load_n(&cpu->runqueue_wait_us, __ATOMIC_ACQUIRE);
    stats->context_switches =
        __atomic_load_n(&cpu->context_switches, __ATOMIC_ACQUIRE);
    stats->migrations =
        __atomic_load_n(&cpu->migrations, __ATOMIC_ACQUIRE);
    stats->nr_running =
        __atomic_load_n(&cpu->nr_running, __ATOMIC_ACQUIRE);

    now = boottime_monotonic_us();
    current = __atomic_load_n(&cpu->current, __ATOMIC_ACQUIRE);
    if (current && !current->is_idle && current->state == TASK_RUNNING) {
        if (stats->nr_running != UINT32_MAX) ++stats->nr_running;
        if (current->rusage_run_start_us &&
            now > current->rusage_run_start_us)
            live = now - current->rusage_run_start_us;
        if (current->in_syscall)
            stats->system_time_us =
                stats->system_time_us > UINT64_MAX - live ? UINT64_MAX :
                stats->system_time_us + live;
        else
            stats->user_time_us =
                stats->user_time_us > UINT64_MAX - live ? UINT64_MAX :
                stats->user_time_us + live;
    }
    accounted = stats->user_time_us > UINT64_MAX - stats->system_time_us ?
                UINT64_MAX : stats->user_time_us + stats->system_time_us;
    stats->idle_time_us = now > accounted ? now - accounted : 0u;
    return 0;
}
