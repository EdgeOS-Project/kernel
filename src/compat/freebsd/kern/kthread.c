/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Stackful, architecture-neutral kernel workers for imported BSD drivers.
 *
 * The worker scheduler is intentionally separate from Linux userspace tasks.
 * A worker retains its kernel call stack across msleep(), while EdgeOS keeps
 * its Linux task scheduling model unchanged. The only architecture-specific
 * operation is the existing callee-saved context switch.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/mutex.h"
#include "sys/boottime.h"

#define BSD_KTHREAD_MAX 64u
#define BSD_KTHREAD_NAME_MAX 32u
#define BSD_KTHREAD_DEFAULT_STACK_PAGES 16u
#define BSD_KTHREAD_MAX_STACK_PAGES 64u
#define BSD_KTHREAD_CHANNEL_MAX 256u
#define BSD_KTHREAD_PAGE_SIZE 4096u
#define BSD_KTHREAD_MAGIC UINT64_C(0x4253444b54485244)
#define BSD_KTHREAD_RFSTOPPED (1u << 17)
#define BSD_KTHREAD_RFHIGHPID (1u << 18)
#define BSD_KTHREAD_PDROP 0x200
#define BSD_KTHREAD_EINVAL 22
#define BSD_KTHREAD_EAGAIN 35
#define BSD_KTHREAD_EWOULDBLOCK BSD_KTHREAD_EAGAIN

extern int hz;

void (*hwt_hook)(struct thread *thread, int function, void *argument);

typedef enum {
    BSD_KTHREAD_FREE = 0,
    BSD_KTHREAD_RUNNABLE,
    BSD_KTHREAD_RUNNING,
    BSD_KTHREAD_WAITING,
    BSD_KTHREAD_BLOCKED,
    BSD_KTHREAD_SUSPENDED,
    BSD_KTHREAD_EXITED,
} bsd_kthread_state_t;

static void
kthread_bind_process(struct proc *process, struct thread *thread,
    const struct ucred *source_credential)
{
    if (source_credential)
        process->p_ucred_storage = *source_credential;
    else
        bsd_memset(&process->p_ucred_storage, 0,
            sizeof(process->p_ucred_storage));
    if (process->p_ucred_storage.cr_ngroups <= 0) {
        process->p_ucred_storage.cr_ngroups = 1;
        process->p_ucred_storage.cr_groups[0] =
            process->p_ucred_storage.cr_gid;
    }
    process->p_ucred_storage.cr_ref = 1;
    process->p_ucred = &process->p_ucred_storage;
    process->p_edgeos_thread = thread;
    thread->td_proc = process;
    thread->td_ucred = process->p_ucred;
    thread->td_proc_next = 0;
    thread->td_pcb = (struct pcb *)(void *)thread->td_pcb_storage;
}

typedef struct {
    const void *channel;
    uint64_t generation;
} bsd_kthread_channel_t;

#ifdef BSD_BRIDGE_HOST_TEST

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    struct thread public_thread;
    struct proc process;
    pthread_t host_thread;
    void (*entry)(void *);
    void *argument;
    const void *wait_channel;
    uint64_t deadline_us;
    bsd_kthread_state_t state;
    uint8_t suspend_requested;
    uint8_t timed_out;
    char name[BSD_KTHREAD_NAME_MAX];
} bsd_kthread_record_t;

static pthread_mutex_t g_kthread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_kthread_condition = PTHREAD_COND_INITIALIZER;
static bsd_kthread_record_t g_kthreads[BSD_KTHREAD_MAX];
static bsd_kthread_channel_t g_channels[BSD_KTHREAD_CHANNEL_MAX];
static _Thread_local bsd_kthread_record_t *g_current_kthread;
static _Thread_local struct thread *g_public_thread_override;
static uint8_t g_kthread_initialized;

static uint64_t
kthread_now_us(void)
{
    struct timespec now;

    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * UINT64_C(1000000) +
        (uint64_t)now.tv_nsec / 1000u;
}

static struct timespec
kthread_realtime_deadline(uint64_t remaining_us)
{
    struct timespec deadline;
    uint64_t nanoseconds;

    (void)clock_gettime(CLOCK_REALTIME, &deadline);
    nanoseconds = (uint64_t)deadline.tv_nsec +
        (remaining_us % UINT64_C(1000000)) * 1000u;
    deadline.tv_sec += (time_t)(remaining_us / UINT64_C(1000000) +
        nanoseconds / UINT64_C(1000000000));
    deadline.tv_nsec = (long)(nanoseconds % UINT64_C(1000000000));
    return deadline;
}

static bsd_kthread_record_t *
kthread_record(struct thread *thread)
{
    bsd_kthread_record_t *record = (bsd_kthread_record_t *)thread;

    if (!record ||
        record < &g_kthreads[0] ||
        record >= &g_kthreads[BSD_KTHREAD_MAX] ||
        record->public_thread.td_edgeos_cookie !=
        (BSD_KTHREAD_MAGIC ^ (uintptr_t)record))
        return 0;
    return record;
}

static bsd_kthread_channel_t *
kthread_channel_locked(const void *channel, int create)
{
    bsd_kthread_channel_t *available = 0;

    for (uint32_t index = 0; index < BSD_KTHREAD_CHANNEL_MAX; ++index) {
        bsd_kthread_channel_t *entry = &g_channels[index];

        if (entry->channel == channel)
            return entry;
        if (!entry->channel && !available)
            available = entry;
    }
    if (create && available) {
        available->channel = channel;
        available->generation = 1;
        return available;
    }
    return 0;
}

static void *
kthread_host_entry(void *argument)
{
    bsd_kthread_record_t *record = argument;

    g_current_kthread = record;
    pthread_mutex_lock(&g_kthread_lock);
    while (record->state == BSD_KTHREAD_SUSPENDED)
        pthread_cond_wait(&g_kthread_condition, &g_kthread_lock);
    record->state = BSD_KTHREAD_RUNNING;
    pthread_mutex_unlock(&g_kthread_lock);
    record->entry(record->argument);
    kthread_exit();
}

int
bsd_kthread_runtime_initialize(void)
{
    pthread_mutex_lock(&g_kthread_lock);
    if (!g_kthread_initialized) {
        memset(g_kthreads, 0, sizeof(g_kthreads));
        memset(g_channels, 0, sizeof(g_channels));
        g_public_thread_override = 0;
        g_kthread_initialized = 1;
    }
    pthread_mutex_unlock(&g_kthread_lock);
    return 0;
}

int
bsd_kthread_runtime_is_initialized(void)
{
    return __atomic_load_n(&g_kthread_initialized, __ATOMIC_ACQUIRE) != 0;
}

void
bsd_kthread_pump(void)
{
}

void *
bsd_kthread_current_token(void)
{
    return g_current_kthread ? &g_current_kthread->public_thread : 0;
}

struct thread *
bsd_kthread_current_public(void)
{
    struct thread *worker = bsd_kthread_current_token();
    struct thread *current = worker ? worker : g_public_thread_override;

    if (current)
        current->td_oncpu = (int)bsd_kthread_current_cpu_id();
    return current;
}

uint32_t
bsd_kthread_current_cpu_id(void)
{
    return 0;
}

struct thread *
bsd_kthread_public_context_enter(struct thread *thread)
{
    struct thread *previous = g_public_thread_override;

    g_public_thread_override = thread;
    return previous;
}

void
bsd_kthread_public_context_leave(struct thread *previous)
{
    g_public_thread_override = previous;
}

void
bsd_kthread_critical_enter(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread)
        ++thread->td_critnest;
}

void
bsd_kthread_critical_exit(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread && thread->td_critnest > 0)
        --thread->td_critnest;
}

void
bsd_kthread_sleeping_forbid(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread)
        ++thread->td_no_sleeping;
}

void
bsd_kthread_sleeping_allow(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread && thread->td_no_sleeping > 0)
        --thread->td_no_sleeping;
}

int
bsd_kthread_token_valid(void *token)
{
    return kthread_record(token) != 0;
}

int
bsd_kthread_token_can_block(void *token)
{
    return kthread_record(token) == g_current_kthread;
}

void
bsd_kthread_token_prepare_block(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);

    if (record != g_current_kthread)
        abort();
    pthread_mutex_lock(&g_kthread_lock);
    record->state = BSD_KTHREAD_BLOCKED;
    pthread_mutex_unlock(&g_kthread_lock);
}

void
bsd_kthread_token_block_current(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);

    if (record != g_current_kthread)
        abort();
    pthread_mutex_lock(&g_kthread_lock);
    while (record->state == BSD_KTHREAD_BLOCKED)
        pthread_cond_wait(&g_kthread_condition, &g_kthread_lock);
    record->state = BSD_KTHREAD_RUNNING;
    pthread_mutex_unlock(&g_kthread_lock);
}

void
bsd_kthread_token_make_runnable(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);

    if (!record)
        return;
    pthread_mutex_lock(&g_kthread_lock);
    if (record->state == BSD_KTHREAD_BLOCKED)
        record->state = BSD_KTHREAD_RUNNABLE;
    pthread_cond_broadcast(&g_kthread_condition);
    pthread_mutex_unlock(&g_kthread_lock);
}

int
bsd_kthread_sleep(const void *channel, struct mtx *mutex, int priority,
    int timeout_ticks)
{
    bsd_kthread_record_t *record = g_current_kthread;
    bsd_kthread_channel_t *entry;
    uint64_t initial_generation;
    uint64_t deadline = 0;
    int result = 0;

    if (!channel || timeout_ticks < 0)
        return BSD_KTHREAD_EINVAL;
    if (timeout_ticks != 0) {
        uint64_t duration = ((uint64_t)timeout_ticks * UINT64_C(1000000) +
            (uint64_t)hz - 1u) / (uint64_t)hz;

        deadline = kthread_now_us() + duration;
    }
    pthread_mutex_lock(&g_kthread_lock);
    entry = kthread_channel_locked(channel, 1);
    if (!entry) {
        pthread_mutex_unlock(&g_kthread_lock);
        return BSD_KTHREAD_EAGAIN;
    }
    initial_generation = entry->generation;
    if (record) {
        record->wait_channel = channel;
        record->deadline_us = deadline;
        record->timed_out = 0;
        record->state = BSD_KTHREAD_WAITING;
    }
    if (mutex)
        mtx_unlock(mutex);
    while (entry->generation == initial_generation) {
        int wait_error;

        if (record && record->suspend_requested)
            break;
        if (!deadline) {
            wait_error = pthread_cond_wait(
                &g_kthread_condition, &g_kthread_lock);
        } else {
            uint64_t now = kthread_now_us();
            struct timespec absolute;

            if (now >= deadline) {
                result = BSD_KTHREAD_EWOULDBLOCK;
                break;
            }
            absolute = kthread_realtime_deadline(deadline - now);
            wait_error = pthread_cond_timedwait(
                &g_kthread_condition, &g_kthread_lock, &absolute);
            if (wait_error == ETIMEDOUT) {
                result = BSD_KTHREAD_EWOULDBLOCK;
                break;
            }
        }
        if (wait_error != 0 && wait_error != EINTR) {
            result = BSD_KTHREAD_EAGAIN;
            break;
        }
    }
    if (record) {
        record->wait_channel = 0;
        record->deadline_us = 0;
        record->state = BSD_KTHREAD_RUNNING;
    }
    pthread_mutex_unlock(&g_kthread_lock);
    if (mutex && (priority & BSD_KTHREAD_PDROP) == 0)
        mtx_lock(mutex);
    return result;
}

uint64_t
bsd_kthread_wakeup_generation(const void *channel)
{
    bsd_kthread_channel_t *entry;
    uint64_t generation = 0;

    if (!channel)
        return 0;
    pthread_mutex_lock(&g_kthread_lock);
    entry = kthread_channel_locked(channel, 1);
    if (entry)
        generation = entry->generation;
    pthread_mutex_unlock(&g_kthread_lock);
    return generation;
}

int
bsd_kthread_sleep_generation(const void *channel,
    uint64_t generation, int timeout_ticks)
{
    bsd_kthread_record_t *record = g_current_kthread;
    bsd_kthread_channel_t *entry;
    uint64_t deadline = 0;
    int result = 0;

    if (!channel || !generation || timeout_ticks < 0)
        return BSD_KTHREAD_EINVAL;
    if (timeout_ticks != 0) {
        uint64_t duration = ((uint64_t)timeout_ticks * UINT64_C(1000000) +
            (uint64_t)hz - 1u) / (uint64_t)hz;

        deadline = kthread_now_us() + duration;
    }
    pthread_mutex_lock(&g_kthread_lock);
    entry = kthread_channel_locked(channel, 1);
    if (!entry) {
        pthread_mutex_unlock(&g_kthread_lock);
        return BSD_KTHREAD_EAGAIN;
    }
    if (entry->generation != generation) {
        pthread_mutex_unlock(&g_kthread_lock);
        return 0;
    }
    if (record) {
        record->wait_channel = channel;
        record->deadline_us = deadline;
        record->timed_out = 0;
        record->state = BSD_KTHREAD_WAITING;
    }
    while (entry->generation == generation) {
        int wait_error;

        if (record && record->suspend_requested)
            break;
        if (!deadline) {
            wait_error = pthread_cond_wait(
                &g_kthread_condition, &g_kthread_lock);
        } else {
            uint64_t now = kthread_now_us();
            struct timespec absolute;

            if (now >= deadline) {
                result = BSD_KTHREAD_EWOULDBLOCK;
                break;
            }
            absolute = kthread_realtime_deadline(deadline - now);
            wait_error = pthread_cond_timedwait(
                &g_kthread_condition, &g_kthread_lock, &absolute);
            if (wait_error == ETIMEDOUT) {
                result = BSD_KTHREAD_EWOULDBLOCK;
                break;
            }
        }
        if (wait_error != 0 && wait_error != EINTR) {
            result = BSD_KTHREAD_EAGAIN;
            break;
        }
    }
    if (record) {
        record->wait_channel = 0;
        record->deadline_us = 0;
        record->state = BSD_KTHREAD_RUNNING;
    }
    pthread_mutex_unlock(&g_kthread_lock);
    return result;
}

void
bsd_kthread_wakeup(const void *channel, int one)
{
    bsd_kthread_channel_t *entry;

    if (!channel)
        return;
    pthread_mutex_lock(&g_kthread_lock);
    entry = kthread_channel_locked(channel, 1);
    if (entry) {
        ++entry->generation;
        if (!entry->generation)
            ++entry->generation;
    }
    for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
        bsd_kthread_record_t *record = &g_kthreads[index];

        if (record->state != BSD_KTHREAD_WAITING ||
            record->wait_channel != channel)
            continue;
        record->state = BSD_KTHREAD_RUNNABLE;
        record->wait_channel = 0;
        if (one)
            break;
    }
    pthread_cond_broadcast(&g_kthread_condition);
    pthread_mutex_unlock(&g_kthread_lock);
}

static int
kthread_create_common(void (*function)(void *), void *argument,
    struct proc *process, struct thread **thread_out, int flags,
    const char *name)
{
    bsd_kthread_record_t *record = 0;

    if (!function || !thread_out || !name ||
        (flags & ~(int)(BSD_KTHREAD_RFSTOPPED |
        BSD_KTHREAD_RFHIGHPID)) != 0)
        return BSD_KTHREAD_EINVAL;
    if (!bsd_kthread_runtime_is_initialized() &&
        bsd_kthread_runtime_initialize() != 0)
        return BSD_KTHREAD_EAGAIN;
    pthread_mutex_lock(&g_kthread_lock);
    for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
        if (g_kthreads[index].state == BSD_KTHREAD_FREE) {
            record = &g_kthreads[index];
            break;
        }
    }
    if (!record) {
        pthread_mutex_unlock(&g_kthread_lock);
        return BSD_KTHREAD_EAGAIN;
    }
    memset(record, 0, sizeof(*record));
    if (process)
        record->process = *process;
    record->public_thread.td_edgeos_cookie =
        BSD_KTHREAD_MAGIC ^ (uintptr_t)record;
    kthread_bind_process(&record->process, &record->public_thread,
        process ? process->p_ucred : 0);
    record->public_thread.td_bound_cpu = -1;
    record->public_thread.td_saved_cpu = -1;
    record->public_thread.td_pin_saved_bound_cpu = -1;
    record->public_thread.td_affinity_mask = UINT64_MAX;
    record->process.p_edgeos_cookie =
        BSD_KTHREAD_MAGIC ^ (uintptr_t)&record->process;
    record->process.p_pid = (int)(record - g_kthreads) + 1;
    record->process.p_pgid = record->process.p_pid;
    record->public_thread.td_tid = record->process.p_pid;
    record->entry = function;
    record->argument = argument;
    record->state = (flags & BSD_KTHREAD_RFSTOPPED) != 0 ?
        BSD_KTHREAD_SUSPENDED : BSD_KTHREAD_RUNNABLE;
    (void)bsd_strlcpy(record->name, name, sizeof(record->name));
    (void)bsd_strlcpy(record->process.p_comm, name,
        sizeof(record->process.p_comm));
    *thread_out = &record->public_thread;
    if (pthread_create(&record->host_thread, 0, kthread_host_entry,
        record) != 0) {
        memset(record, 0, sizeof(*record));
        pthread_mutex_unlock(&g_kthread_lock);
        *thread_out = 0;
        return BSD_KTHREAD_EAGAIN;
    }
    pthread_mutex_unlock(&g_kthread_lock);
    return 0;
}

#else

#include "arch/task.h"
#include "kernel/arch_cpu.h"
#include "mm/arch_vm.h"

#if defined(__x86_64__)
#include "sys/scheduler.h"
extern void switch_to(cpu_context_t *, cpu_context_t *);
#endif

#define BSD_KTHREAD_CPU_MAX 8u

typedef struct {
    struct thread public_thread;
    struct proc process;
    cpu_context_t context;
    void (*entry)(void *);
    void *argument;
    void *stack;
    uint64_t stack_pages;
    const void *wait_channel;
    uint64_t deadline_us;
    uint64_t interrupt_state;
    uint64_t exited_epoch;
    uint32_t running_cpu;
    bsd_kthread_state_t state;
    uint8_t suspend_requested;
    uint8_t timed_out;
    char name[BSD_KTHREAD_NAME_MAX];
} bsd_kthread_record_t;

static bsd_kthread_record_t g_kthreads[BSD_KTHREAD_MAX];
static bsd_kthread_channel_t g_channels[BSD_KTHREAD_CHANNEL_MAX];
static cpu_context_t g_host_contexts[BSD_KTHREAD_CPU_MAX];
static bsd_kthread_record_t *g_current_kthreads[BSD_KTHREAD_CPU_MAX];
static struct thread *g_public_thread_overrides[BSD_KTHREAD_CPU_MAX];
static volatile uint32_t g_kthread_guard;
static volatile uint32_t g_pump_guard;
static volatile uintptr_t
    g_deferred_wakeup_channels[BSD_KTHREAD_CHANNEL_MAX];
static volatile uint8_t g_deferred_wakeup_overflow;
static uint64_t g_pump_epoch;
static uint8_t g_kthread_initialized;

static uint32_t
kthread_cpu(void)
{
#if defined(__x86_64__)
    uint32_t cpu = scheduler_cpu_id();

    return cpu < BSD_KTHREAD_CPU_MAX ? cpu : 0;
#else
    return 0;
#endif
}

static uint64_t
kthread_now_us(void)
{
    return boottime_monotonic_us();
}

static uint64_t
kthread_interrupt_save_disable(void)
{
#if defined(__x86_64__)
    uint64_t state;

    __asm__ __volatile__("pushfq; popq %0; cli"
        : "=r"(state) :: "memory");
    return state;
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint64_t state;

    __asm__ __volatile__("mrs %0, daif; msr daifset, #0xf"
        : "=r"(state) :: "memory");
    return state;
#else
#error "Unsupported BSD Driver Bridge kernel-worker architecture"
#endif
}

static void
kthread_interrupt_restore(uint64_t state)
{
#if defined(__x86_64__)
    if ((state & (UINT64_C(1) << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("msr daif, %0" :: "r"(state) : "memory");
#endif
}

static uint64_t
kthread_worker_interrupt_state(uint64_t host_state)
{
#if defined(__x86_64__)
    return host_state | (UINT64_C(1) << 9);
#elif defined(__aarch64__) || defined(_M_ARM64)
    return host_state & ~(UINT64_C(1) << 7);
#endif
}

static void
kthread_relax(void)
{
    arch_cpu_relax();
}

static uint64_t
kthread_lock(void)
{
    uint64_t state = kthread_interrupt_save_disable();

    while (__atomic_test_and_set(&g_kthread_guard, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_kthread_guard, __ATOMIC_RELAXED))
            kthread_relax();
    }
    return state;
}

static int
kthread_try_lock(uint64_t *state)
{
    uint64_t interrupt_state;

    if (!state)
        return 0;
    interrupt_state = kthread_interrupt_save_disable();
    if (__atomic_test_and_set(&g_kthread_guard, __ATOMIC_ACQUIRE)) {
        kthread_interrupt_restore(interrupt_state);
        return 0;
    }
    *state = interrupt_state;
    return 1;
}

static void
kthread_unlock(uint64_t state)
{
    __atomic_clear(&g_kthread_guard, __ATOMIC_RELEASE);
    kthread_interrupt_restore(state);
}

static void
kthread_context_switch(cpu_context_t *previous,
    const cpu_context_t *next)
{
#if defined(__x86_64__)
    switch_to(previous, (cpu_context_t *)next);
#elif defined(__aarch64__) || defined(_M_ARM64)
    edgeos_arm64_context_switch(previous, next);
#endif
}

static bsd_kthread_record_t *
kthread_record(struct thread *thread)
{
    bsd_kthread_record_t *record = (bsd_kthread_record_t *)thread;

    if (!record ||
        record < &g_kthreads[0] ||
        record >= &g_kthreads[BSD_KTHREAD_MAX] ||
        record->public_thread.td_edgeos_cookie !=
        (BSD_KTHREAD_MAGIC ^ (uintptr_t)record))
        return 0;
    return record;
}

static bsd_kthread_channel_t *
kthread_channel_locked(const void *channel, int create)
{
    bsd_kthread_channel_t *available = 0;

    for (uint32_t index = 0; index < BSD_KTHREAD_CHANNEL_MAX; ++index) {
        bsd_kthread_channel_t *entry = &g_channels[index];

        if (entry->channel == channel)
            return entry;
        if (!entry->channel && !available)
            available = entry;
    }
    if (create && available) {
        available->channel = channel;
        available->generation = 1;
        return available;
    }
    return 0;
}

static void
kthread_wakeup_locked(const void *channel, int one)
{
    bsd_kthread_channel_t *entry = kthread_channel_locked(channel, 1);

    if (entry) {
        ++entry->generation;
        if (!entry->generation)
            ++entry->generation;
    }
    for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
        bsd_kthread_record_t *record = &g_kthreads[index];

        if (record->state != BSD_KTHREAD_WAITING ||
            record->wait_channel != channel)
            continue;
        record->wait_channel = 0;
        record->deadline_us = 0;
        record->state = BSD_KTHREAD_RUNNABLE;
        if (one)
            break;
    }
}

static void
kthread_defer_wakeup(const void *channel)
{
    for (uint32_t index = 0; index < BSD_KTHREAD_CHANNEL_MAX; ++index) {
        uintptr_t observed = __atomic_load_n(
            &g_deferred_wakeup_channels[index], __ATOMIC_ACQUIRE);
        uintptr_t expected = 0;

        if (observed == (uintptr_t)channel)
            return;
        if (observed == 0 && __atomic_compare_exchange_n(
                &g_deferred_wakeup_channels[index], &expected,
                (uintptr_t)channel, 0, __ATOMIC_RELEASE,
                __ATOMIC_RELAXED))
            return;
    }
    __atomic_store_n(&g_deferred_wakeup_overflow, 1u, __ATOMIC_RELEASE);
}

static void
kthread_drain_deferred_wakeups_locked(void)
{
    for (uint32_t index = 0; index < BSD_KTHREAD_CHANNEL_MAX; ++index) {
        const void *channel = (const void *)(uintptr_t)__atomic_exchange_n(
            &g_deferred_wakeup_channels[index], 0, __ATOMIC_ACQ_REL);

        if (channel)
            kthread_wakeup_locked(channel, 0);
    }
    if (__atomic_exchange_n(&g_deferred_wakeup_overflow, 0,
            __ATOMIC_ACQ_REL) != 0) {
        for (uint32_t index = 0; index < BSD_KTHREAD_CHANNEL_MAX; ++index) {
            if (g_channels[index].channel)
                kthread_wakeup_locked(g_channels[index].channel, 0);
        }
    }
}

static __attribute__((noreturn)) void
kthread_switch_to_host(bsd_kthread_record_t *record)
{
    uint32_t cpu = record->running_cpu;

    record->interrupt_state = kthread_interrupt_save_disable();
    kthread_context_switch(&record->context, &g_host_contexts[cpu]);
    kthread_interrupt_restore(record->interrupt_state);
    __builtin_unreachable();
}

static void
kthread_yield_to_host(bsd_kthread_record_t *record)
{
    uint32_t cpu = record->running_cpu;

    record->interrupt_state = kthread_interrupt_save_disable();
    kthread_context_switch(&record->context, &g_host_contexts[cpu]);
    kthread_interrupt_restore(record->interrupt_state);
}

static __attribute__((noreturn)) void
kthread_entry_trampoline(void)
{
    uint32_t cpu = kthread_cpu();
    bsd_kthread_record_t *record = g_current_kthreads[cpu];

    if (!record)
        bsd_bridge_panic_stop();
    kthread_interrupt_restore(record->interrupt_state);
    record->entry(record->argument);
    kthread_exit();
}

static int
kthread_context_initialize(bsd_kthread_record_t *record, int extra_pages)
{
    uint64_t pages = BSD_KTHREAD_DEFAULT_STACK_PAGES;
    uintptr_t stack_top;

    if (extra_pages > 0)
        pages += (uint64_t)extra_pages;
    if (pages > BSD_KTHREAD_MAX_STACK_PAGES)
        return BSD_KTHREAD_EINVAL;
    if (!record->stack || record->stack_pages < pages) {
        void *stack = arch_vm_reserve_pages(pages);

        if (!stack)
            return BSD_KTHREAD_EAGAIN;
        record->stack = stack;
        record->stack_pages = pages;
    }
    bsd_memset(record->stack, 0,
        (size_t)record->stack_pages * BSD_KTHREAD_PAGE_SIZE);
    bsd_memset(&record->context, 0, sizeof(record->context));
    stack_top = (uintptr_t)record->stack +
        (uintptr_t)record->stack_pages * BSD_KTHREAD_PAGE_SIZE;
    stack_top &= ~(uintptr_t)15u;
#if defined(__x86_64__)
    record->context.rsp = stack_top - sizeof(uint64_t);
    record->context.rip = (uintptr_t)kthread_entry_trampoline;
#elif defined(__aarch64__) || defined(_M_ARM64)
    record->context.sp = stack_top;
    record->context.pc = (uintptr_t)kthread_entry_trampoline;
#endif
    return 0;
}

int
bsd_kthread_runtime_initialize(void)
{
    uint64_t state;

    if (__atomic_load_n(&g_kthread_initialized, __ATOMIC_ACQUIRE))
        return 0;
    state = kthread_lock();
    if (!g_kthread_initialized) {
        bsd_memset(g_kthreads, 0, sizeof(g_kthreads));
        bsd_memset(g_channels, 0, sizeof(g_channels));
        bsd_memset(g_host_contexts, 0, sizeof(g_host_contexts));
        bsd_memset(g_current_kthreads, 0, sizeof(g_current_kthreads));
        bsd_memset(g_public_thread_overrides, 0,
            sizeof(g_public_thread_overrides));
        bsd_memset((void *)g_deferred_wakeup_channels, 0,
            sizeof(g_deferred_wakeup_channels));
        g_deferred_wakeup_overflow = 0;
        g_pump_epoch = 1;
        __atomic_store_n(&g_kthread_initialized, 1, __ATOMIC_RELEASE);
    }
    kthread_unlock(state);
    return 0;
}

int
bsd_kthread_runtime_is_initialized(void)
{
    return __atomic_load_n(&g_kthread_initialized, __ATOMIC_ACQUIRE) != 0;
}

void *
bsd_kthread_current_token(void)
{
    bsd_kthread_record_t *record = g_current_kthreads[kthread_cpu()];

    return record ? &record->public_thread : 0;
}

struct thread *
bsd_kthread_current_public(void)
{
    struct thread *worker = bsd_kthread_current_token();
    struct thread *current = worker ? worker :
        g_public_thread_overrides[kthread_cpu()];

    if (current)
        current->td_oncpu = (int)kthread_cpu();
    return current;
}

uint32_t
bsd_kthread_current_cpu_id(void)
{
    return kthread_cpu();
}

struct thread *
bsd_kthread_public_context_enter(struct thread *thread)
{
    uint32_t cpu = kthread_cpu();
    struct thread *previous = g_public_thread_overrides[cpu];

    g_public_thread_overrides[cpu] = thread;
    return previous;
}

void
bsd_kthread_public_context_leave(struct thread *previous)
{
    g_public_thread_overrides[kthread_cpu()] = previous;
}

void
bsd_kthread_critical_enter(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread)
        ++thread->td_critnest;
}

void
bsd_kthread_critical_exit(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread && thread->td_critnest > 0)
        --thread->td_critnest;
}

void
bsd_kthread_sleeping_forbid(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread)
        ++thread->td_no_sleeping;
}

void
bsd_kthread_sleeping_allow(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread && thread->td_no_sleeping > 0)
        --thread->td_no_sleeping;
}

int
bsd_kthread_token_valid(void *token)
{
    return kthread_record(token) != 0;
}

int
bsd_kthread_token_can_block(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);

    return record && record == g_current_kthreads[kthread_cpu()] &&
        record->state == BSD_KTHREAD_RUNNING;
}

void
bsd_kthread_token_prepare_block(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);
    uint64_t state;

    if (!record || record != g_current_kthreads[kthread_cpu()])
        bsd_bridge_panic_stop();
    state = kthread_lock();
    if (record->state != BSD_KTHREAD_RUNNING) {
        kthread_unlock(state);
        bsd_bridge_panic_stop();
    }
    record->state = BSD_KTHREAD_BLOCKED;
    kthread_unlock(state);
}

void
bsd_kthread_token_block_current(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);

    if (!record || record != g_current_kthreads[kthread_cpu()] ||
        record->state != BSD_KTHREAD_BLOCKED)
        bsd_bridge_panic_stop();
    kthread_yield_to_host(record);
}

void
bsd_kthread_token_make_runnable(void *token)
{
    bsd_kthread_record_t *record = kthread_record(token);
    uint64_t state;

    if (!record)
        return;
    state = kthread_lock();
    if (record->state == BSD_KTHREAD_BLOCKED)
        record->state = BSD_KTHREAD_RUNNABLE;
    kthread_unlock(state);
}

static void
kthread_promote_timeouts_locked(uint64_t now)
{
    for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
        bsd_kthread_record_t *record = &g_kthreads[index];

        if (record->state != BSD_KTHREAD_WAITING ||
            !record->deadline_us || now < record->deadline_us)
            continue;
        record->timed_out = 1;
        record->wait_channel = 0;
        record->deadline_us = 0;
        record->state = BSD_KTHREAD_RUNNABLE;
    }
}

void
bsd_kthread_pump(void)
{
    uint32_t cpu;
    uint32_t budget = BSD_KTHREAD_MAX * 2u;

    if (!bsd_kthread_runtime_is_initialized() ||
        __atomic_test_and_set(&g_pump_guard, __ATOMIC_ACQUIRE))
        return;
    cpu = kthread_cpu();
    while (budget-- != 0) {
        bsd_kthread_record_t *record = 0;
        uint64_t state = kthread_lock();

        kthread_drain_deferred_wakeups_locked();
        ++g_pump_epoch;
        if (!g_pump_epoch)
            ++g_pump_epoch;
        kthread_promote_timeouts_locked(boottime_monotonic_us());
        for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
            if (g_kthreads[index].state == BSD_KTHREAD_RUNNABLE &&
                (g_kthreads[index].public_thread.td_affinity_mask &
                (UINT64_C(1) << cpu)) != 0) {
                record = &g_kthreads[index];
                record->state = BSD_KTHREAD_RUNNING;
                record->running_cpu = cpu;
                break;
            }
        }
        kthread_unlock(state);
        if (!record)
            break;
        {
            uint64_t host_interrupt_state =
                kthread_interrupt_save_disable();

            record->interrupt_state =
                kthread_worker_interrupt_state(host_interrupt_state);
            g_current_kthreads[cpu] = record;
            kthread_context_switch(
                &g_host_contexts[cpu], &record->context);
            g_current_kthreads[cpu] = 0;
            kthread_interrupt_restore(host_interrupt_state);
        }
    }
    __atomic_clear(&g_pump_guard, __ATOMIC_RELEASE);
}

int
bsd_kthread_sleep(const void *channel, struct mtx *mutex, int priority,
    int timeout_ticks)
{
    bsd_kthread_record_t *record =
        g_current_kthreads[kthread_cpu()];
    bsd_kthread_channel_t *entry;
    uint64_t deadline = 0;
    uint64_t initial_generation;
    uint64_t state;
    int result;

    if (!channel || timeout_ticks < 0)
        return BSD_KTHREAD_EINVAL;
    if (timeout_ticks != 0) {
        uint64_t duration = ((uint64_t)timeout_ticks * UINT64_C(1000000) +
            (uint64_t)hz - 1u) / (uint64_t)hz;
        uint64_t now = kthread_now_us();

        deadline = UINT64_MAX - now < duration ?
            UINT64_MAX : now + duration;
    }
    state = kthread_lock();
    entry = kthread_channel_locked(channel, 1);
    if (!entry) {
        kthread_unlock(state);
        return BSD_KTHREAD_EAGAIN;
    }
    initial_generation = entry->generation;
    if (record) {
        record->wait_channel = channel;
        record->deadline_us = deadline;
        record->timed_out = 0;
        record->state = BSD_KTHREAD_WAITING;
    }
    if (mutex)
        mtx_unlock(mutex);
    kthread_unlock(state);

    if (record) {
        kthread_yield_to_host(record);
        result = record->timed_out ?
            BSD_KTHREAD_EWOULDBLOCK : 0;
        record->timed_out = 0;
    } else {
        result = 0;
        for (;;) {
            uint64_t now;

            state = kthread_lock();
            entry = kthread_channel_locked(channel, 0);
            if (!entry || entry->generation != initial_generation) {
                kthread_unlock(state);
                break;
            }
            now = kthread_now_us();
            if (deadline && now >= deadline) {
                kthread_unlock(state);
                result = BSD_KTHREAD_EWOULDBLOCK;
                break;
            }
            kthread_unlock(state);
            bsd_kthread_pump();
            kthread_relax();
        }
    }
    if (mutex && (priority & BSD_KTHREAD_PDROP) == 0)
        mtx_lock(mutex);
    return result;
}

uint64_t
bsd_kthread_wakeup_generation(const void *channel)
{
    bsd_kthread_channel_t *entry;
    uint64_t generation = 0;
    uint64_t state;

    if (!channel)
        return 0;
    state = kthread_lock();
    entry = kthread_channel_locked(channel, 1);
    if (entry)
        generation = entry->generation;
    kthread_unlock(state);
    return generation;
}

int
bsd_kthread_sleep_generation(const void *channel,
    uint64_t generation, int timeout_ticks)
{
    bsd_kthread_record_t *record =
        g_current_kthreads[kthread_cpu()];
    bsd_kthread_channel_t *entry;
    uint64_t deadline = 0;
    uint64_t state;
    int result;

    if (!channel || !generation || timeout_ticks < 0)
        return BSD_KTHREAD_EINVAL;
    if (timeout_ticks != 0) {
        uint64_t duration = ((uint64_t)timeout_ticks * UINT64_C(1000000) +
            (uint64_t)hz - 1u) / (uint64_t)hz;
        uint64_t now = kthread_now_us();

        deadline = UINT64_MAX - now < duration ?
            UINT64_MAX : now + duration;
    }
    state = kthread_lock();
    entry = kthread_channel_locked(channel, 1);
    if (!entry) {
        kthread_unlock(state);
        return BSD_KTHREAD_EAGAIN;
    }
    if (entry->generation != generation) {
        kthread_unlock(state);
        return 0;
    }
    if (record) {
        record->wait_channel = channel;
        record->deadline_us = deadline;
        record->timed_out = 0;
        record->state = BSD_KTHREAD_WAITING;
    }
    kthread_unlock(state);

    if (record) {
        kthread_yield_to_host(record);
        result = record->timed_out ?
            BSD_KTHREAD_EWOULDBLOCK : 0;
        record->timed_out = 0;
    } else {
        result = 0;
        for (;;) {
            uint64_t now;

            state = kthread_lock();
            entry = kthread_channel_locked(channel, 0);
            if (!entry || entry->generation != generation) {
                kthread_unlock(state);
                break;
            }
            now = kthread_now_us();
            if (deadline && now >= deadline) {
                kthread_unlock(state);
                result = BSD_KTHREAD_EWOULDBLOCK;
                break;
            }
            kthread_unlock(state);
            bsd_kthread_pump();
            kthread_relax();
        }
    }
    return result;
}

void
bsd_kthread_wakeup(const void *channel, int one)
{
    uint64_t state;

    if (!channel)
        return;
    if (!kthread_try_lock(&state)) {
        /* Hard-interrupt wakeups must never spin on an interrupted owner. */
        kthread_defer_wakeup(channel);
        return;
    }
    kthread_drain_deferred_wakeups_locked();
    kthread_wakeup_locked(channel, one);
    kthread_unlock(state);
}

static int
kthread_create_common(void (*function)(void *), void *argument,
    struct proc *process, struct thread **thread_out, int flags,
    int extra_pages, const char *name)
{
    bsd_kthread_record_t *record = 0;
    uint64_t state;
    int error;

    if (!function || !thread_out || !name || extra_pages < 0 ||
        (flags & ~(int)(BSD_KTHREAD_RFSTOPPED |
        BSD_KTHREAD_RFHIGHPID)) != 0)
        return BSD_KTHREAD_EINVAL;
    if (!bsd_kthread_runtime_is_initialized() &&
        bsd_kthread_runtime_initialize() != 0)
        return BSD_KTHREAD_EAGAIN;
    state = kthread_lock();
    for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
        bsd_kthread_record_t *candidate = &g_kthreads[index];

        if (candidate->state == BSD_KTHREAD_FREE ||
            (candidate->state == BSD_KTHREAD_EXITED &&
            g_pump_epoch - candidate->exited_epoch > 2u)) {
            record = candidate;
            break;
        }
    }
    if (!record) {
        kthread_unlock(state);
        return BSD_KTHREAD_EAGAIN;
    }
    {
        void *saved_stack = record->stack;
        uint64_t saved_pages = record->stack_pages;

        bsd_memset(record, 0, sizeof(*record));
        record->stack = saved_stack;
        record->stack_pages = saved_pages;
    }
    if (process)
        record->process = *process;
    record->public_thread.td_edgeos_cookie =
        BSD_KTHREAD_MAGIC ^ (uintptr_t)record;
    kthread_bind_process(&record->process, &record->public_thread,
        process ? process->p_ucred : 0);
    record->public_thread.td_bound_cpu = -1;
    record->public_thread.td_saved_cpu = -1;
    record->public_thread.td_pin_saved_bound_cpu = -1;
    record->public_thread.td_affinity_mask = UINT64_MAX;
    record->process.p_edgeos_cookie =
        BSD_KTHREAD_MAGIC ^ (uintptr_t)&record->process;
    record->process.p_pid = (int)(record - g_kthreads) + 1;
    record->process.p_pgid = record->process.p_pid;
    record->public_thread.td_tid = record->process.p_pid;
    record->entry = function;
    record->argument = argument;
    (void)bsd_strlcpy(record->name, name, sizeof(record->name));
    (void)bsd_strlcpy(record->process.p_comm, name,
        sizeof(record->process.p_comm));
    error = kthread_context_initialize(record, extra_pages);
    if (error) {
        record->state = BSD_KTHREAD_FREE;
        kthread_unlock(state);
        return error;
    }
    record->state = (flags & BSD_KTHREAD_RFSTOPPED) != 0 ?
        BSD_KTHREAD_SUSPENDED : BSD_KTHREAD_RUNNABLE;
    *thread_out = &record->public_thread;
    kthread_unlock(state);
    bsd_kthread_pump();
    return 0;
}

#endif

int
bsd_kthread_join(struct thread *thread)
{
    bsd_kthread_record_t *record = kthread_record(thread);

    if (!record || record ==
        (bsd_kthread_record_t *)bsd_kthread_current_token())
        return BSD_KTHREAD_EINVAL;
#ifdef BSD_BRIDGE_HOST_TEST
    {
        pthread_t host_thread;

        pthread_mutex_lock(&g_kthread_lock);
        while (record->state != BSD_KTHREAD_EXITED)
            pthread_cond_wait(&g_kthread_condition, &g_kthread_lock);
        host_thread = record->host_thread;
        pthread_mutex_unlock(&g_kthread_lock);
        if (pthread_join(host_thread, 0) != 0)
            return BSD_KTHREAD_EAGAIN;
        pthread_mutex_lock(&g_kthread_lock);
        if (record->state == BSD_KTHREAD_EXITED)
            memset(record, 0, sizeof(*record));
        pthread_mutex_unlock(&g_kthread_lock);
    }
#else
    for (;;) {
        uint64_t state = kthread_lock();
        int exited = record->state == BSD_KTHREAD_EXITED;

        kthread_unlock(state);
        if (exited)
            break;
        bsd_kthread_pump();
        kthread_relax();
    }
#endif
    return 0;
}

int
kthread_add(void (*function)(void *), void *argument, struct proc *process,
    struct thread **thread_out, int flags, int pages, const char *format, ...)
{
    char name[BSD_KTHREAD_NAME_MAX];
    va_list arguments;

    if (!format)
        return BSD_KTHREAD_EINVAL;
    va_start(arguments, format);
    (void)bsd_vsnprintf(name, sizeof(name), format, arguments);
    va_end(arguments);
#ifdef BSD_BRIDGE_HOST_TEST
    (void)pages;
    return kthread_create_common(function, argument, process, thread_out,
        flags, name);
#else
    return kthread_create_common(function, argument, process, thread_out,
        flags, pages, name);
#endif
}

void
kthread_exit(void)
{
    bsd_kthread_record_t *record =
        (bsd_kthread_record_t *)bsd_kthread_current_token();

    if (!record)
        bsd_bridge_panic_stop();
#ifdef BSD_BRIDGE_HOST_TEST
    pthread_mutex_lock(&g_kthread_lock);
    record->state = BSD_KTHREAD_EXITED;
    pthread_cond_broadcast(&g_kthread_condition);
    pthread_mutex_unlock(&g_kthread_lock);
    bsd_kthread_wakeup(&record->public_thread, 0);
    g_current_kthread = 0;
    pthread_exit(0);
#else
    {
        uint64_t state = kthread_lock();

        record->state = BSD_KTHREAD_EXITED;
        record->exited_epoch = g_pump_epoch;
        kthread_unlock(state);
    }
    bsd_kthread_wakeup(&record->public_thread, 0);
    kthread_switch_to_host(record);
#endif
    __builtin_unreachable();
}

int
kthread_suspend(struct thread *thread, int timeout_ticks)
{
    bsd_kthread_record_t *record = kthread_record(thread);
    uint64_t deadline = 0;

    if (!record || timeout_ticks < 0)
        return BSD_KTHREAD_EINVAL;
    if (timeout_ticks) {
        uint64_t duration = ((uint64_t)timeout_ticks * UINT64_C(1000000) +
            (uint64_t)hz - 1u) / (uint64_t)hz;
        deadline = kthread_now_us() + duration;
    }
#ifdef BSD_BRIDGE_HOST_TEST
    pthread_mutex_lock(&g_kthread_lock);
    record->suspend_requested = 1;
    pthread_cond_broadcast(&g_kthread_condition);
    while (record->state != BSD_KTHREAD_SUSPENDED &&
        record->state != BSD_KTHREAD_EXITED) {
        int wait_error;

        if (deadline) {
            uint64_t now = kthread_now_us();
            struct timespec absolute;

            if (now >= deadline) {
                pthread_mutex_unlock(&g_kthread_lock);
                return BSD_KTHREAD_EWOULDBLOCK;
            }
            absolute = kthread_realtime_deadline(deadline - now);
            wait_error = pthread_cond_timedwait(
                &g_kthread_condition, &g_kthread_lock, &absolute);
            if (wait_error == ETIMEDOUT) {
                pthread_mutex_unlock(&g_kthread_lock);
                return BSD_KTHREAD_EWOULDBLOCK;
            }
        } else {
            wait_error = pthread_cond_wait(
                &g_kthread_condition, &g_kthread_lock);
        }
        if (wait_error != 0 && wait_error != EINTR) {
            pthread_mutex_unlock(&g_kthread_lock);
            return BSD_KTHREAD_EAGAIN;
        }
    }
    pthread_mutex_unlock(&g_kthread_lock);
#else
    {
        uint64_t state = kthread_lock();
        record->suspend_requested = 1;
        if (record->state == BSD_KTHREAD_WAITING ||
            record->state == BSD_KTHREAD_BLOCKED)
            record->state = BSD_KTHREAD_RUNNABLE;
        kthread_unlock(state);
    }
    while (record->state != BSD_KTHREAD_SUSPENDED &&
        record->state != BSD_KTHREAD_EXITED) {
        if (deadline && kthread_now_us() >= deadline)
            return BSD_KTHREAD_EWOULDBLOCK;
        bsd_kthread_pump();
        kthread_relax();
    }
#endif
    return 0;
}

int
kthread_resume(struct thread *thread)
{
    bsd_kthread_record_t *record = kthread_record(thread);

    if (!record)
        return BSD_KTHREAD_EINVAL;
#ifdef BSD_BRIDGE_HOST_TEST
    pthread_mutex_lock(&g_kthread_lock);
    record->suspend_requested = 0;
    if (record->state == BSD_KTHREAD_SUSPENDED)
        record->state = BSD_KTHREAD_RUNNABLE;
    pthread_cond_broadcast(&g_kthread_condition);
    pthread_mutex_unlock(&g_kthread_lock);
#else
    {
        uint64_t state = kthread_lock();

        record->suspend_requested = 0;
        if (record->state == BSD_KTHREAD_SUSPENDED)
            record->state = BSD_KTHREAD_RUNNABLE;
        kthread_unlock(state);
    }
    bsd_kthread_pump();
#endif
    return 0;
}

void
kthread_suspend_check(void)
{
    bsd_kthread_record_t *record =
        (bsd_kthread_record_t *)bsd_kthread_current_token();

    if (!record || !record->suspend_requested)
        return;
#ifdef BSD_BRIDGE_HOST_TEST
    pthread_mutex_lock(&g_kthread_lock);
    record->state = BSD_KTHREAD_SUSPENDED;
    pthread_cond_broadcast(&g_kthread_condition);
    while (record->suspend_requested)
        pthread_cond_wait(&g_kthread_condition, &g_kthread_lock);
    record->state = BSD_KTHREAD_RUNNING;
    pthread_mutex_unlock(&g_kthread_lock);
#else
    {
        uint64_t state = kthread_lock();

        record->state = BSD_KTHREAD_SUSPENDED;
        kthread_unlock(state);
    }
    bsd_kthread_wakeup(&record->public_thread, 0);
    kthread_yield_to_host(record);
#endif
}

static void
kthread_descriptor_entry(void *argument)
{
    const struct kthread_desc *descriptor = argument;

    descriptor->func();
}

void
kthread_start(const void *argument)
{
    const struct kthread_desc *descriptor = argument;

    if (!descriptor || !descriptor->func || !descriptor->global_threadpp ||
        kthread_add(kthread_descriptor_entry, (void *)descriptor, 0,
        descriptor->global_threadpp, 0, 0, "%s",
        descriptor->arg0 ? descriptor->arg0 : "kthread") != 0)
        bsd_bridge_panic_stop();
}

void
kthread_shutdown(void *argument, int howto)
{
    (void)howto;
    (void)kthread_suspend((struct thread *)argument, 60 * hz);
}

int
kproc_create(void (*function)(void *), void *argument,
    struct proc **process_out, int flags, int pages, const char *format, ...)
{
    struct thread *thread = 0;
    bsd_kthread_record_t *record;
    char name[BSD_KTHREAD_NAME_MAX];
    va_list arguments;
    int error;

    if (!process_out || !format)
        return BSD_KTHREAD_EINVAL;
    va_start(arguments, format);
    (void)bsd_vsnprintf(name, sizeof(name), format, arguments);
    va_end(arguments);
#ifdef BSD_BRIDGE_HOST_TEST
    (void)pages;
    error = kthread_create_common(function, argument, 0, &thread,
        flags, name);
#else
    error = kthread_create_common(function, argument, 0, &thread,
        flags, pages, name);
#endif
    if (error)
        return error;
    record = kthread_record(thread);
    *process_out = record ? &record->process : 0;
    return record ? 0 : BSD_KTHREAD_EAGAIN;
}

void
kproc_exit(int status)
{
    (void)status;
    kthread_exit();
}

int
kproc_suspend(struct proc *process, int timeout_ticks)
{
    return process && process->p_edgeos_thread ?
        kthread_suspend(process->p_edgeos_thread, timeout_ticks) :
        BSD_KTHREAD_EINVAL;
}

int
kproc_resume(struct proc *process)
{
    return process && process->p_edgeos_thread ?
        kthread_resume(process->p_edgeos_thread) :
        BSD_KTHREAD_EINVAL;
}

void
kproc_suspend_check(struct proc *process)
{
    bsd_kthread_record_t *record =
        (bsd_kthread_record_t *)bsd_kthread_current_token();

    if (record && process &&
        record->process.p_edgeos_cookie == process->p_edgeos_cookie)
        kthread_suspend_check();
}

static void
kproc_descriptor_entry(void *argument)
{
    const struct kproc_desc *descriptor = argument;

    descriptor->func();
}

void
kproc_start(const void *argument)
{
    const struct kproc_desc *descriptor = argument;

    if (!descriptor || !descriptor->func || !descriptor->global_procpp ||
        kproc_create(kproc_descriptor_entry, (void *)descriptor,
        descriptor->global_procpp, 0, 0, "%s",
        descriptor->arg0 ? descriptor->arg0 : "kproc") != 0)
        bsd_bridge_panic_stop();
}

void
kproc_shutdown(void *argument, int howto)
{
    (void)howto;
    (void)kproc_suspend((struct proc *)argument, 60 * hz);
}

int
kproc_kthread_add(void (*function)(void *), void *argument,
    struct proc **process_inout, struct thread **thread_out, int flags,
    int pages, const char *process_name, const char *thread_format, ...)
{
    char thread_name[BSD_KTHREAD_NAME_MAX];
    va_list arguments;
    int error;

    if (!process_inout || !thread_out || !thread_format)
        return BSD_KTHREAD_EINVAL;
    va_start(arguments, thread_format);
    (void)bsd_vsnprintf(
        thread_name, sizeof(thread_name), thread_format, arguments);
    va_end(arguments);
    if (!*process_inout) {
        error = kproc_create(function, argument, process_inout,
            flags, pages, "%s", process_name ? process_name : thread_name);
        if (error)
            return error;
        *thread_out = (*process_inout)->p_edgeos_thread;
        return 0;
    }
#ifdef BSD_BRIDGE_HOST_TEST
    (void)pages;
    return kthread_create_common(function, argument, *process_inout,
        thread_out, flags, thread_name);
#else
    return kthread_create_common(function, argument, *process_inout,
        thread_out, flags, pages, thread_name);
#endif
}

void
bsd_proc_lock(struct proc *process)
{
    if (!process)
        return;
    while (__atomic_test_and_set(&process->p_lock, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

void
bsd_proc_unlock(struct proc *process)
{
    if (process)
        __atomic_clear(&process->p_lock, __ATOMIC_RELEASE);
}

int
bsd_proc_lock_owned(const struct proc *process)
{
    return process &&
        __atomic_load_n(&process->p_lock, __ATOMIC_ACQUIRE) != 0;
}

struct proc *
pfind(int pid)
{
    struct thread *current = bsd_kthread_current_public();

    if (current && current->td_proc && current->td_proc->p_pid == pid) {
        bsd_proc_lock(current->td_proc);
        return current->td_proc;
    }
    for (uint32_t index = 0; index < BSD_KTHREAD_MAX; ++index) {
        bsd_kthread_record_t *record = &g_kthreads[index];

        if (record->state == BSD_KTHREAD_FREE ||
            record->state == BSD_KTHREAD_EXITED ||
            record->process.p_pid != pid)
            continue;
        bsd_proc_lock(&record->process);
        if (record->state != BSD_KTHREAD_FREE &&
            record->state != BSD_KTHREAD_EXITED &&
            record->process.p_pid == pid)
            return &record->process;
        bsd_proc_unlock(&record->process);
    }
    return 0;
}

void
crhold(struct ucred *credential)
{
    if (credential)
        (void)__atomic_add_fetch(&credential->cr_ref, 1,
            __ATOMIC_RELAXED);
}

void
crfree(struct ucred *credential)
{
    uint32_t references;

    if (!credential)
        return;
    references = __atomic_load_n(&credential->cr_ref, __ATOMIC_RELAXED);
    while (references > 1 &&
        !__atomic_compare_exchange_n(&credential->cr_ref, &references,
        references - 1, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
    }
}

int
groupmember(uint32_t group, const struct ucred *credential)
{
    int count;

    if (!credential)
        return 0;
    if (credential->cr_gid == group || credential->cr_rgid == group ||
        credential->cr_svgid == group)
        return 1;
    count = credential->cr_ngroups;
    if (count < 0)
        count = 0;
    if (count > (int)(sizeof(credential->cr_groups) /
        sizeof(credential->cr_groups[0])))
        count = sizeof(credential->cr_groups) /
            sizeof(credential->cr_groups[0]);
    for (int index = 0; index < count; ++index) {
        if (credential->cr_groups[index] == group)
            return 1;
    }
    return 0;
}
