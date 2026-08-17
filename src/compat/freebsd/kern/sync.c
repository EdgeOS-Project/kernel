/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS synchronization backend for BSD driver compatibility.
 *
 * Waiters are reserved per blocked task so condition waits never allocate
 * while holding a driver mutex. Wakeups are made race-free by marking the
 * current task blocked before releasing the object's internal guard.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/sys/jail.h"
#include "compat/freebsd/sys/kernel.h"
#include "compat/freebsd/sys/mutex.h"
#include "kernel/runtime_limits.h"

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdlib.h>
#else
#include <stdio.h>
#if defined(__x86_64__)
#include "sys/process.h"
#include "sys/scheduler.h"
#elif defined(__aarch64__)
#include "kernel/arch_cpu.h"
#endif
#endif

struct mtx Giant;
struct prison prison0 = {
    .pr_hostname = "EdgeOS",
};
#ifndef BSD_BRIDGE_HOST_TEST
MTX_SYSINIT(edgeos_giant, &Giant, "Giant", MTX_DEF | MTX_RECURSE);
MTX_SYSINIT(edgeos_prison0, &prison0.pr_mtx, "host identity", MTX_DEF);
#endif

typedef struct bsd_sync_waiter bsd_sync_waiter_t;

struct bsd_sync_waiter {
    bsd_sync_waiter_t *next;
    void *thread;
    uint8_t active;
};

static bsd_sync_ops_t g_sync_ops;
static bsd_sync_waiter_t g_sync_waiters[EDGE_RUNTIME_MAX_TASKS];
static volatile uint32_t g_waiter_guard;
static uint8_t g_sync_initialized;

#if !defined(BSD_BRIDGE_HOST_TEST)
static uintptr_t g_boot_thread_tokens[64];
static uint64_t g_spinlock_interrupt_state[64];
static uint32_t g_spinlock_depth[64];
#endif

static void sync_fatal(const char *message);

static uint64_t interrupt_save_disable(void) {
#ifdef BSD_BRIDGE_HOST_TEST
    return 0;
#elif defined(__x86_64__)
    uint64_t state;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(state) :: "memory");
    return state;
#elif defined(__aarch64__)
    uint64_t state;
    __asm__ __volatile__("mrs %0, daif; msr daifset, #0xf"
                         : "=r"(state) :: "memory");
    return state;
#else
#error "BSD Driver Bridge synchronization needs an interrupt backend"
#endif
}

static void interrupt_restore(uint64_t state) {
#ifdef BSD_BRIDGE_HOST_TEST
    (void)state;
#elif defined(__x86_64__)
    if (state & (1ull << 9)) __asm__ __volatile__("sti" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("msr daif, %0" :: "r"(state) : "memory");
#endif
}

void
spinlock_enter(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return;
#else
    uint32_t cpu = bsd_kthread_current_cpu_id() % 64u;
    uint64_t state = interrupt_save_disable();

    if (g_spinlock_depth[cpu]++ == 0)
        g_spinlock_interrupt_state[cpu] = state;
#endif
}

void
spinlock_exit(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return;
#else
    uint32_t cpu = bsd_kthread_current_cpu_id() % 64u;

    if (g_spinlock_depth[cpu] == 0)
        sync_fatal("spinlock exit without matching enter");
    if (--g_spinlock_depth[cpu] == 0)
        interrupt_restore(g_spinlock_interrupt_state[cpu]);
#endif
}

static void processor_relax(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void raw_guard_lock(volatile uint32_t *guard) {
    while (__atomic_test_and_set(guard, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(guard, __ATOMIC_RELAXED))
            processor_relax();
    }
}

static void raw_guard_unlock(volatile uint32_t *guard) {
    __atomic_clear(guard, __ATOMIC_RELEASE);
}

static uint64_t guard_lock(volatile uint32_t *guard) {
    uint64_t state = interrupt_save_disable();
    raw_guard_lock(guard);
    return state;
}

static void guard_unlock(volatile uint32_t *guard, uint64_t state) {
    raw_guard_unlock(guard);
    interrupt_restore(state);
}

static void sync_fatal(const char *message) {
    if (g_sync_ops.fatal)
        g_sync_ops.fatal(message, g_sync_ops.context);
#ifdef BSD_BRIDGE_HOST_TEST
    abort();
#else
    printf("[bsd-bridge] fatal synchronization error: %s\n", message);
    __builtin_trap();
#endif
}

static void *current_thread(void) {
    void *thread;
    if (!g_sync_initialized || !g_sync_ops.current_thread)
        sync_fatal("synchronization backend is not initialized");
    thread = g_sync_ops.current_thread(g_sync_ops.context);
    if (!thread) sync_fatal("synchronization backend returned no current task");
    return thread;
}

static bsd_sync_waiter_t *waiter_allocate(void *thread) {
    bsd_sync_waiter_t *available = 0;
    uint64_t state = guard_lock(&g_waiter_guard);
    for (uint32_t index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index) {
        bsd_sync_waiter_t *waiter = &g_sync_waiters[index];
        if (waiter->active && waiter->thread == thread) {
            guard_unlock(&g_waiter_guard, state);
            sync_fatal("task attempted to wait on multiple bridge objects");
        }
        if (!waiter->active && !available) available = waiter;
    }
    if (available) {
        memset(available, 0, sizeof(*available));
        available->thread = thread;
        available->active = 1;
    }
    guard_unlock(&g_waiter_guard, state);
    return available;
}

static void waiter_release(bsd_sync_waiter_t *waiter) {
    uint64_t state;
    if (!waiter) return;
    state = guard_lock(&g_waiter_guard);
    memset(waiter, 0, sizeof(*waiter));
    guard_unlock(&g_waiter_guard, state);
}

static void wait_queue_push(void **head, void **tail,
                            bsd_sync_waiter_t *waiter) {
    waiter->next = 0;
    if (*tail)
        ((bsd_sync_waiter_t *)*tail)->next = waiter;
    else
        *head = waiter;
    *tail = waiter;
}

static bsd_sync_waiter_t *wait_queue_pop(void **head, void **tail) {
    bsd_sync_waiter_t *waiter = (bsd_sync_waiter_t *)*head;
    if (!waiter) return 0;
    *head = waiter->next;
    if (!*head) *tail = 0;
    waiter->next = 0;
    return waiter;
}

static void wake_waiter(bsd_sync_waiter_t *waiter) {
    void *thread;
    if (!waiter) return;
    thread = waiter->thread;
    waiter_release(waiter);
    g_sync_ops.wake_thread(thread, g_sync_ops.context);
}

#if !defined(BSD_BRIDGE_HOST_TEST) && defined(__x86_64__)
static void *default_current_thread(void *context) {
    void *worker = bsd_kthread_current_token();
    task_t *task = scheduler_current_task();
    uint32_t cpu;
    (void)context;
    if (worker) return worker;
    if (task) return task;
    cpu = scheduler_cpu_id() % 64u;
    return &g_boot_thread_tokens[cpu];
}

static int default_can_block(void *thread, void *context) {
    task_t *task = scheduler_current_task();
    (void)context;
    if (bsd_kthread_token_valid(thread))
        return bsd_kthread_token_can_block(thread);
    return task && thread == task && !task->is_idle;
}

static void default_prepare_block(void *thread, void *context) {
    (void)context;
    if (bsd_kthread_token_valid(thread)) {
        bsd_kthread_token_prepare_block(thread);
        return;
    }
    scheduler_task_set_blocked((task_t *)thread);
}

static void default_block_current(void *thread, void *context) {
    (void)context;
    if (bsd_kthread_token_valid(thread)) {
        bsd_kthread_token_block_current(thread);
        return;
    }
    scheduler_yield();
}

static void default_wake_thread(void *thread, void *context) {
    task_t *task = (task_t *)thread;
    uint32_t cpu;
    (void)context;
    if (bsd_kthread_token_valid(thread)) {
        bsd_kthread_token_make_runnable(thread);
        return;
    }
    cpu = task->assigned_cpu >= 0 ? (uint32_t)task->assigned_cpu
                                  : scheduler_cpu_id();
    scheduler_task_make_runnable(task, cpu);
}

static void default_yield(void *context) {
    (void)context;
    scheduler_yield();
}
#elif !defined(BSD_BRIDGE_HOST_TEST) && defined(__aarch64__)
static void *default_current_thread(void *context) {
    void *worker = bsd_kthread_current_token();
    uintptr_t task = (uintptr_t)arch_cpu_current_task();

    (void)context;
    if (worker) return worker;
    return task ? (void *)task : &g_boot_thread_tokens[0];
}

static int default_can_block(void *thread, void *context) {
    /*
     * ARM64 currently resumes blocked userspace operations from saved EL0
     * frames instead of retaining arbitrary kernel call stacks. Imported
     * drivers therefore use non-sleeping mutex acquisition until the common
     * kernel-thread scheduler is active.
     */
    (void)context;
    if (bsd_kthread_token_valid(thread))
        return bsd_kthread_token_can_block(thread);
    return 0;
}

static void default_prepare_block(void *thread, void *context) {
    (void)context;
    if (bsd_kthread_token_valid(thread)) {
        bsd_kthread_token_prepare_block(thread);
        return;
    }
    sync_fatal("ARM64 bridge task unexpectedly prepared to block");
}

static void default_block_current(void *thread, void *context) {
    (void)context;
    if (bsd_kthread_token_valid(thread)) {
        bsd_kthread_token_block_current(thread);
        return;
    }
    sync_fatal("ARM64 bridge task unexpectedly attempted to block");
}

static void default_wake_thread(void *thread, void *context) {
    (void)context;
    if (bsd_kthread_token_valid(thread)) {
        bsd_kthread_token_make_runnable(thread);
        return;
    }
    sync_fatal("ARM64 bridge task unexpectedly entered a wait queue");
}

static void default_yield(void *context) {
    (void)context;
    processor_relax();
}
#endif

int bsd_sync_initialize(const bsd_sync_ops_t *ops) {
    bsd_sync_ops_t selected;
    uint64_t state;

    memset(&selected, 0, sizeof(selected));
    if (ops) {
        selected = *ops;
    } else {
#ifdef BSD_BRIDGE_HOST_TEST
        return -1;
#elif defined(__x86_64__) || defined(__aarch64__)
        selected.current_thread = default_current_thread;
        selected.can_block = default_can_block;
        selected.prepare_block = default_prepare_block;
        selected.block_current = default_block_current;
        selected.wake_thread = default_wake_thread;
        selected.yield_thread = default_yield;
#else
        return -1;
#endif
    }
    if (!selected.current_thread || !selected.can_block ||
        !selected.prepare_block || !selected.block_current ||
        !selected.wake_thread || !selected.yield_thread)
        return -1;

    state = guard_lock(&g_waiter_guard);
    if (g_sync_initialized) {
        guard_unlock(&g_waiter_guard, state);
        return -1;
    }
    memset(g_sync_waiters, 0, sizeof(g_sync_waiters));
    g_sync_ops = selected;
    g_sync_initialized = 1;
    guard_unlock(&g_waiter_guard, state);
#ifdef BSD_BRIDGE_HOST_TEST
    mtx_init(&Giant, "Giant", 0, MTX_DEF | MTX_RECURSE);
    mtx_init(&prison0.pr_mtx, "host identity", 0, MTX_DEF);
#endif
    return 0;
}

int bsd_sync_is_initialized(void) {
    return __atomic_load_n(&g_sync_initialized, __ATOMIC_ACQUIRE) != 0;
}

void bsd_sync_yield_current(void) {
    if (bsd_sync_is_initialized())
        g_sync_ops.yield_thread(g_sync_ops.context);
    else
        processor_relax();
}

int bsd_mutex_init(bsd_mutex_t *mutex, const char *name, uint32_t flags) {
    if (!mutex || !bsd_sync_is_initialized()) return -1;
    if (flags & ~(BSD_MUTEX_SPIN | BSD_MUTEX_RECURSE)) return -1;
    memset(mutex, 0, sizeof(*mutex));
    mutex->name = name;
    mutex->flags = flags;
    mutex->initialized = 1;
    return 0;
}

int bsd_mutex_destroy(bsd_mutex_t *mutex) {
    uint64_t state;
    if (!mutex || !mutex->initialized) return -1;
    state = guard_lock(&mutex->guard);
    if (mutex->owner || mutex->wait_head) {
        guard_unlock(&mutex->guard, state);
        return -1;
    }
    mutex->initialized = 0;
    guard_unlock(&mutex->guard, state);
    return 0;
}

static int mutex_acquire_locked(bsd_mutex_t *mutex, void *thread,
                                uint64_t spin_state) {
    uintptr_t owner = (uintptr_t)thread;
    if (!mutex->owner) {
        mutex->owner = owner;
        mutex->recursion = 0;
        if (mutex->flags & BSD_MUTEX_SPIN)
            mutex->spin_interrupt_state = spin_state;
        return 1;
    }
    if (mutex->owner == owner) {
        if ((mutex->flags & BSD_MUTEX_RECURSE) == 0) {
#ifndef BSD_BRIDGE_HOST_TEST
            printf("[bsd-bridge] mutex=%s object=%p owner=%p\n",
                mutex->name ? mutex->name : "<unnamed>", (void *)mutex,
                thread);
#endif
            sync_fatal("non-recursive mutex acquired twice");
        }
        mutex->recursion++;
        return 1;
    }
    return 0;
}

static void mutex_lock_spin(bsd_mutex_t *mutex, void *thread) {
    uint64_t interrupt_state = interrupt_save_disable();
    for (;;) {
        raw_guard_lock(&mutex->guard);
        if (mutex_acquire_locked(mutex, thread, interrupt_state)) {
            raw_guard_unlock(&mutex->guard);
            return;
        }
        raw_guard_unlock(&mutex->guard);
        processor_relax();
    }
}

void bsd_mutex_lock(bsd_mutex_t *mutex) {
    void *thread;
    if (!mutex || !mutex->initialized)
        sync_fatal("attempted to lock an uninitialized mutex");
    thread = current_thread();
    if (mutex->flags & BSD_MUTEX_SPIN) {
        mutex_lock_spin(mutex, thread);
        return;
    }

    for (;;) {
        bsd_sync_waiter_t *waiter;
        uint64_t state = guard_lock(&mutex->guard);
        if (mutex_acquire_locked(mutex, thread, 0)) {
            guard_unlock(&mutex->guard, state);
            return;
        }
        if (!g_sync_ops.can_block(thread, g_sync_ops.context)) {
            guard_unlock(&mutex->guard, state);
            g_sync_ops.yield_thread(g_sync_ops.context);
            continue;
        }
        waiter = waiter_allocate(thread);
        if (!waiter) {
            guard_unlock(&mutex->guard, state);
            sync_fatal("BSD bridge waiter capacity exhausted");
        }
        wait_queue_push(&mutex->wait_head, &mutex->wait_tail, waiter);
        g_sync_ops.prepare_block(thread, g_sync_ops.context);
        guard_unlock(&mutex->guard, state);
        g_sync_ops.block_current(thread, g_sync_ops.context);
    }
}

int bsd_mutex_trylock(bsd_mutex_t *mutex) {
    void *thread;
    int acquired;
    uint64_t state;
    if (!mutex || !mutex->initialized) return 0;
    thread = current_thread();
    state = interrupt_save_disable();
    raw_guard_lock(&mutex->guard);
    if (mutex->owner == (uintptr_t)thread &&
        (mutex->flags & BSD_MUTEX_RECURSE) == 0)
        acquired = 0;
    else
        acquired = mutex_acquire_locked(mutex, thread, state);
    raw_guard_unlock(&mutex->guard);
    if (!acquired || (mutex->flags & BSD_MUTEX_SPIN) == 0)
        interrupt_restore(state);
    return acquired;
}

void bsd_mutex_unlock(bsd_mutex_t *mutex) {
    bsd_sync_waiter_t *waiter;
    void *thread;
    uint64_t state;
    uint64_t spin_state = 0;

    if (!mutex || !mutex->initialized)
        sync_fatal("attempted to unlock an uninitialized mutex");
    thread = current_thread();
    state = guard_lock(&mutex->guard);
    if (mutex->owner != (uintptr_t)thread) {
        guard_unlock(&mutex->guard, state);
        sync_fatal("mutex unlocked by a non-owner");
    }
    if (mutex->recursion) {
        mutex->recursion--;
        guard_unlock(&mutex->guard, state);
        return;
    }
    if (mutex->flags & BSD_MUTEX_SPIN)
        spin_state = mutex->spin_interrupt_state;
    mutex->owner = 0;
    mutex->spin_interrupt_state = 0;
    waiter = wait_queue_pop(&mutex->wait_head, &mutex->wait_tail);
    guard_unlock(&mutex->guard, state);
    if (waiter) wake_waiter(waiter);
    if (mutex->flags & BSD_MUTEX_SPIN)
        interrupt_restore(spin_state);
}

int bsd_mutex_owned(const bsd_mutex_t *mutex) {
    if (!mutex || !mutex->initialized || !bsd_sync_is_initialized()) return 0;
    return __atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) ==
           (uintptr_t)current_thread();
}

int bsd_mutex_recursed(const bsd_mutex_t *mutex) {
    return bsd_mutex_owned(mutex) && mutex->recursion != 0;
}

int bsd_mutex_assert(const bsd_mutex_t *mutex, int assertion) {
    int owned = bsd_mutex_owned(mutex);
    int recursed = owned && mutex->recursion != 0;
    int valid = 0;
    switch (assertion) {
        case BSD_MUTEX_ASSERT_OWNED:
            valid = owned;
            break;
        case BSD_MUTEX_ASSERT_NOTOWNED:
            valid = !owned;
            break;
        case BSD_MUTEX_ASSERT_RECURSED:
            valid = recursed;
            break;
        case BSD_MUTEX_ASSERT_NOTRECURSED:
            valid = owned && !recursed;
            break;
        default:
            break;
    }
    if (!valid) {
#ifndef BSD_BRIDGE_HOST_TEST
        printf("[bsd-bridge] mutex assertion failed: name=%s "
            "assertion=%d initialized=%u owner=%p current=%p "
            "recursion=%u flags=0x%x\n",
            mutex && mutex->name ? mutex->name : "(unnamed)",
            assertion, mutex ? (unsigned int)mutex->initialized : 0u,
            mutex ? (void *)mutex->owner : 0, current_thread(),
            mutex ? mutex->recursion : 0u,
            mutex ? mutex->flags : 0u);
#endif
        sync_fatal("mutex ownership assertion failed");
    }
    return valid ? 0 : -1;
}

int bsd_condition_init(bsd_condition_t *condition, const char *description) {
    if (!condition || !bsd_sync_is_initialized()) return -1;
    memset(condition, 0, sizeof(*condition));
    condition->description = description;
    condition->initialized = 1;
    return 0;
}

int bsd_condition_destroy(bsd_condition_t *condition) {
    uint64_t state;
    if (!condition || !condition->initialized) return -1;
    state = guard_lock(&condition->guard);
    if (condition->wait_head) {
        guard_unlock(&condition->guard, state);
        return -1;
    }
    condition->initialized = 0;
    guard_unlock(&condition->guard, state);
    return 0;
}

void bsd_condition_wait(bsd_condition_t *condition, bsd_mutex_t *mutex) {
    bsd_sync_waiter_t *waiter;
    void *thread;
    uint64_t state;
    if (!condition || !condition->initialized || !mutex ||
        !mutex->initialized)
        sync_fatal("invalid condition wait");
    if (mutex->flags & BSD_MUTEX_SPIN)
        sync_fatal("condition wait attempted with a spin mutex");
    if (!bsd_mutex_owned(mutex))
        sync_fatal("condition wait requires an owned mutex");

    thread = current_thread();
    if (!g_sync_ops.can_block(thread, g_sync_ops.context))
        sync_fatal("current task cannot block on a condition");
    state = guard_lock(&condition->guard);
    waiter = waiter_allocate(thread);
    if (!waiter) {
        guard_unlock(&condition->guard, state);
        sync_fatal("BSD bridge waiter capacity exhausted");
    }
    wait_queue_push(&condition->wait_head, &condition->wait_tail, waiter);
    g_sync_ops.prepare_block(thread, g_sync_ops.context);
    bsd_mutex_unlock(mutex);
    guard_unlock(&condition->guard, state);
    g_sync_ops.block_current(thread, g_sync_ops.context);
    bsd_mutex_lock(mutex);
}

void bsd_condition_signal(bsd_condition_t *condition) {
    bsd_sync_waiter_t *waiter;
    uint64_t state;
    if (!condition || !condition->initialized)
        sync_fatal("invalid condition signal");
    state = guard_lock(&condition->guard);
    waiter = wait_queue_pop(&condition->wait_head, &condition->wait_tail);
    guard_unlock(&condition->guard, state);
    if (waiter) wake_waiter(waiter);
}

void bsd_condition_broadcast(bsd_condition_t *condition) {
    if (!condition || !condition->initialized)
        sync_fatal("invalid condition broadcast");
    for (;;) {
        bsd_sync_waiter_t *waiter;
        uint64_t state = guard_lock(&condition->guard);
        waiter = wait_queue_pop(&condition->wait_head, &condition->wait_tail);
        guard_unlock(&condition->guard, state);
        if (!waiter) return;
        wake_waiter(waiter);
    }
}

int bsd_rwlock_init(bsd_rwlock_t *lock, const char *name, uint32_t flags) {
    if (!lock || !bsd_sync_is_initialized()) return -1;
    if (flags & ~BSD_RWLOCK_RECURSE) return -1;
    memset(lock, 0, sizeof(*lock));
    lock->name = name;
    lock->flags = flags;
    lock->initialized = 1;
    return 0;
}

int bsd_rwlock_destroy(bsd_rwlock_t *lock) {
    uint64_t state;

    if (!lock || !lock->initialized) return -1;
    state = guard_lock(&lock->guard);
    if (lock->writer || lock->readers || lock->reader_wait_head ||
        lock->writer_wait_head) {
        guard_unlock(&lock->guard, state);
        return -1;
    }
    lock->initialized = 0;
    guard_unlock(&lock->guard, state);
    return 0;
}

static bsd_sync_waiter_t *rwlock_grant_writer_locked(bsd_rwlock_t *lock) {
    bsd_sync_waiter_t *waiter;

    waiter = wait_queue_pop(
        &lock->writer_wait_head, &lock->writer_wait_tail);
    if (!waiter) return 0;
    if (!lock->waiting_writers)
        sync_fatal("reader/writer lock writer queue is inconsistent");
    lock->waiting_writers--;
    lock->writer = (uintptr_t)waiter->thread;
    lock->writer_grant = (uintptr_t)waiter->thread;
    return waiter;
}

static bsd_sync_waiter_t *rwlock_detach_readers_locked(
    bsd_rwlock_t *lock) {
    bsd_sync_waiter_t *head = lock->reader_wait_head;

    lock->reader_wait_head = 0;
    lock->reader_wait_tail = 0;
    return head;
}

static void rwlock_wake_list(bsd_sync_waiter_t *head) {
    while (head) {
        bsd_sync_waiter_t *next = head->next;

        head->next = 0;
        wake_waiter(head);
        head = next;
    }
}

void bsd_rwlock_read_lock(bsd_rwlock_t *lock) {
    void *thread;

    if (!lock || !lock->initialized)
        sync_fatal("attempted to read-lock an uninitialized lock");
    thread = current_thread();
    for (;;) {
        bsd_sync_waiter_t *waiter;
        uint64_t state = guard_lock(&lock->guard);

        if (!lock->writer && !lock->waiting_writers) {
            lock->readers++;
            guard_unlock(&lock->guard, state);
            return;
        }
        if (!g_sync_ops.can_block(thread, g_sync_ops.context)) {
            guard_unlock(&lock->guard, state);
            g_sync_ops.yield_thread(g_sync_ops.context);
            continue;
        }
        waiter = waiter_allocate(thread);
        if (!waiter) {
            guard_unlock(&lock->guard, state);
            sync_fatal("BSD bridge waiter capacity exhausted");
        }
        wait_queue_push(
            &lock->reader_wait_head, &lock->reader_wait_tail, waiter);
        g_sync_ops.prepare_block(thread, g_sync_ops.context);
        guard_unlock(&lock->guard, state);
        g_sync_ops.block_current(thread, g_sync_ops.context);
    }
}

int bsd_rwlock_try_read_lock(bsd_rwlock_t *lock) {
    int acquired = 0;
    uint64_t state;

    if (!lock || !lock->initialized) return 0;
    state = guard_lock(&lock->guard);
    if (!lock->writer && !lock->waiting_writers) {
        lock->readers++;
        acquired = 1;
    }
    guard_unlock(&lock->guard, state);
    return acquired;
}

void bsd_rwlock_read_unlock(bsd_rwlock_t *lock) {
    bsd_sync_waiter_t *writer = 0;
    bsd_sync_waiter_t *readers = 0;
    uint64_t state;

    if (!lock || !lock->initialized)
        sync_fatal("attempted to read-unlock an uninitialized lock");
    state = guard_lock(&lock->guard);
    if (!lock->readers) {
        guard_unlock(&lock->guard, state);
        sync_fatal("reader/writer lock has no active reader");
    }
    lock->readers--;
    if (!lock->readers) {
        writer = rwlock_grant_writer_locked(lock);
        if (!writer)
            readers = rwlock_detach_readers_locked(lock);
    }
    guard_unlock(&lock->guard, state);
    if (writer) wake_waiter(writer);
    rwlock_wake_list(readers);
}

void bsd_rwlock_write_lock(bsd_rwlock_t *lock) {
    void *thread;
    uintptr_t owner;

    if (!lock || !lock->initialized)
        sync_fatal("attempted to write-lock an uninitialized lock");
    thread = current_thread();
    owner = (uintptr_t)thread;
    for (;;) {
        bsd_sync_waiter_t *waiter;
        uint64_t state = guard_lock(&lock->guard);

        if (lock->writer_grant == owner) {
            lock->writer_grant = 0;
            guard_unlock(&lock->guard, state);
            return;
        }
        if (lock->writer == owner) {
            if ((lock->flags & BSD_RWLOCK_RECURSE) == 0) {
                guard_unlock(&lock->guard, state);
                sync_fatal("non-recursive writer lock acquired twice");
            }
            lock->writer_recursion++;
            guard_unlock(&lock->guard, state);
            return;
        }
        if (!lock->writer && !lock->readers) {
            lock->writer = owner;
            guard_unlock(&lock->guard, state);
            return;
        }
        if (!g_sync_ops.can_block(thread, g_sync_ops.context)) {
            guard_unlock(&lock->guard, state);
            g_sync_ops.yield_thread(g_sync_ops.context);
            continue;
        }
        waiter = waiter_allocate(thread);
        if (!waiter) {
            guard_unlock(&lock->guard, state);
            sync_fatal("BSD bridge waiter capacity exhausted");
        }
        wait_queue_push(
            &lock->writer_wait_head, &lock->writer_wait_tail, waiter);
        lock->waiting_writers++;
        g_sync_ops.prepare_block(thread, g_sync_ops.context);
        guard_unlock(&lock->guard, state);
        g_sync_ops.block_current(thread, g_sync_ops.context);
    }
}

int bsd_rwlock_try_write_lock(bsd_rwlock_t *lock) {
    void *thread;
    uintptr_t owner;
    int acquired = 0;
    uint64_t state;

    if (!lock || !lock->initialized) return 0;
    thread = current_thread();
    owner = (uintptr_t)thread;
    state = guard_lock(&lock->guard);
    if (lock->writer == owner) {
        if (lock->flags & BSD_RWLOCK_RECURSE) {
            lock->writer_recursion++;
            acquired = 1;
        }
    } else if (!lock->writer && !lock->readers) {
        lock->writer = owner;
        acquired = 1;
    }
    guard_unlock(&lock->guard, state);
    return acquired;
}

void bsd_rwlock_write_unlock(bsd_rwlock_t *lock) {
    bsd_sync_waiter_t *writer = 0;
    bsd_sync_waiter_t *readers = 0;
    uintptr_t owner;
    uint64_t state;

    if (!lock || !lock->initialized)
        sync_fatal("attempted to write-unlock an uninitialized lock");
    owner = (uintptr_t)current_thread();
    state = guard_lock(&lock->guard);
    if (lock->writer != owner || lock->writer_grant) {
        guard_unlock(&lock->guard, state);
        sync_fatal("writer lock released by a non-owner");
    }
    if (lock->writer_recursion) {
        lock->writer_recursion--;
        guard_unlock(&lock->guard, state);
        return;
    }
    lock->writer = 0;
    writer = rwlock_grant_writer_locked(lock);
    if (!writer)
        readers = rwlock_detach_readers_locked(lock);
    guard_unlock(&lock->guard, state);
    if (writer) wake_waiter(writer);
    rwlock_wake_list(readers);
}

int bsd_rwlock_write_owned(const bsd_rwlock_t *lock) {
    if (!lock || !lock->initialized || !bsd_sync_is_initialized()) return 0;
    return __atomic_load_n(&lock->writer, __ATOMIC_ACQUIRE) ==
           (uintptr_t)current_thread();
}

int bsd_rwlock_read_locked(const bsd_rwlock_t *lock) {
    if (!lock || !lock->initialized) return 0;
    return __atomic_load_n(&lock->readers, __ATOMIC_ACQUIRE) != 0;
}

int bsd_rwlock_try_upgrade(bsd_rwlock_t *lock) {
    uintptr_t owner;
    int upgraded = 0;
    uint64_t state;

    if (!lock || !lock->initialized) return 0;
    owner = (uintptr_t)current_thread();
    state = guard_lock(&lock->guard);
    if (!lock->writer && lock->readers == 1) {
        lock->readers = 0;
        lock->writer = owner;
        upgraded = 1;
    }
    guard_unlock(&lock->guard, state);
    return upgraded;
}

void bsd_rwlock_downgrade(bsd_rwlock_t *lock) {
    bsd_sync_waiter_t *readers;
    uintptr_t owner;
    uint64_t state;

    if (!lock || !lock->initialized)
        sync_fatal("attempted to downgrade an uninitialized lock");
    owner = (uintptr_t)current_thread();
    state = guard_lock(&lock->guard);
    if (lock->writer != owner || lock->writer_grant ||
        lock->writer_recursion) {
        guard_unlock(&lock->guard, state);
        sync_fatal("invalid writer lock downgrade");
    }
    lock->writer = 0;
    lock->readers = 1;
    readers = rwlock_detach_readers_locked(lock);
    guard_unlock(&lock->guard, state);
    rwlock_wake_list(readers);
}
