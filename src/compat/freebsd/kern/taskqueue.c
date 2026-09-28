/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD-compatible taskqueues on the shared BSD bridge worker runtime. */

#include <stdarg.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/callout.h"
#include "compat/freebsd/sys/cpuset.h"
#include "compat/freebsd/sys/smp.h"
#include "compat/freebsd/sys/taskqueue.h"

#define BSD_TASKQUEUE_NAME_MAX 32u
#define BSD_TASKQUEUE_EINVAL 22
#define BSD_TASKQUEUE_EBUSY 16
#define BSD_TASKQUEUE_ENOMEM 12
#define BSD_TASKQUEUE_STOPPED 0x01u
#define BSD_TASKQUEUE_BLOCKED 0x02u
#define BSD_TASKQUEUE_STARTED 0x04u
#define BSD_TIMEOUT_CALLOUT_ARMED 0x01

typedef struct {
    taskqueue_callback_fn function;
    void *context;
} bsd_taskqueue_callback_t;

struct taskqueue {
    volatile uint32_t guard;
    uint64_t guard_interrupt_state;
    struct taskqueue *self;
    struct task *head;
    struct task *running;
    struct thread *worker;
    taskqueue_enqueue_fn enqueue;
    void *enqueue_context;
    bsd_taskqueue_callback_t callbacks[TASKQUEUE_NUM_CALLBACKS];
    uint32_t flags;
    char name[BSD_TASKQUEUE_NAME_MAX];
};

struct taskqueue *taskqueue_thread;
struct taskqueue *taskqueue_swi;
struct taskqueue *taskqueue_swi_giant;
struct taskqueue *taskqueue_fast;
struct taskqueue *taskqueue_bus;

static volatile uint32_t g_taskqueue_runtime_state;

static void
taskqueue_relax(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    __asm__ __volatile__("" ::: "memory");
#elif defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("yield");
#endif
}

static uint64_t
taskqueue_interrupt_save_disable(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    return 0;
#elif defined(__x86_64__)
    uint64_t state;

    __asm__ __volatile__(
        "pushfq; popq %0; cli" : "=r"(state) :: "memory");
    return state;
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint64_t state;

    __asm__ __volatile__(
        "mrs %0, daif; msr daifset, #0xf"
        : "=r"(state) :: "memory");
    return state;
#else
#error "BSD Driver Bridge taskqueues need an interrupt backend"
#endif
}

static void
taskqueue_interrupt_restore(uint64_t state)
{
#ifdef BSD_BRIDGE_HOST_TEST
    (void)state;
#elif defined(__x86_64__)
    if ((state & (1ull << 9)) != 0)
        __asm__ __volatile__("sti" ::: "memory");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("msr daif, %0" :: "r"(state) : "memory");
#endif
}

static void
taskqueue_lock(struct taskqueue *queue)
{
    uint64_t interrupt_state = taskqueue_interrupt_save_disable();

    while (__atomic_test_and_set(&queue->guard, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&queue->guard, __ATOMIC_RELAXED))
            taskqueue_relax();
    }
    queue->guard_interrupt_state = interrupt_state;
}

static void
taskqueue_unlock(struct taskqueue *queue)
{
    uint64_t interrupt_state = queue->guard_interrupt_state;

    __atomic_clear(&queue->guard, __ATOMIC_RELEASE);
    taskqueue_interrupt_restore(interrupt_state);
}

static int
taskqueue_contains_locked(struct taskqueue *queue, struct task *task)
{
    for (struct task *entry = queue->head; entry;
        entry = entry->ta_link.stqe_next) {
        if (entry == task)
            return 1;
    }
    return 0;
}

static void
taskqueue_insert_locked(struct taskqueue *queue, struct task *task)
{
    struct task **position = &queue->head;

    while (*position &&
        (*position)->ta_priority >= task->ta_priority)
        position = &(*position)->ta_link.stqe_next;
    task->ta_link.stqe_next = *position;
    *position = task;
}

struct taskqueue *
taskqueue_create(const char *name, int flags,
    taskqueue_enqueue_fn enqueue, void *context)
{
    uint32_t allocator_flags;
    struct taskqueue *queue;

    if (!name)
        return 0;
    allocator_flags = (flags & M_WAITOK) != 0 ?
        BSD_M_WAITOK : BSD_M_NOWAIT;
    queue = bsd_kmalloc(
        sizeof(*queue), allocator_flags | BSD_M_ZERO);
    if (!queue)
        return 0;
    queue->self = queue;
    queue->enqueue = enqueue;
    queue->enqueue_context = context;
    (void)bsd_strlcpy(queue->name, name, sizeof(queue->name));
    return queue;
}

struct taskqueue *
taskqueue_create_fast(const char *name, int flags,
    taskqueue_enqueue_fn enqueue, void *context)
{
    return taskqueue_create(name, flags, enqueue, context);
}

static int
taskqueue_start_common(struct taskqueue **queue_pointer, int count,
    int priority, const cpuset_t *mask, const char *name)
{
    struct taskqueue *queue;
    uint64_t affinity_mask = UINT64_MAX;

    if (!queue_pointer || !*queue_pointer || count != 1)
        return BSD_TASKQUEUE_EINVAL;
    if (mask) {
        affinity_mask = bsd_cpuset_low64(mask) &
            bsd_cpuset_low64(&all_cpus);
        if (affinity_mask == 0)
            return BSD_TASKQUEUE_EINVAL;
    }
    queue = *queue_pointer;
    taskqueue_lock(queue);
    if ((queue->flags &
        (BSD_TASKQUEUE_STARTED | BSD_TASKQUEUE_STOPPED)) != 0) {
        taskqueue_unlock(queue);
        return BSD_TASKQUEUE_EBUSY;
    }
    queue->flags |= BSD_TASKQUEUE_STARTED;
    taskqueue_unlock(queue);
    if (kthread_add(taskqueue_thread_loop, queue_pointer, 0,
        &queue->worker, RFSTOPPED, 0, "%s", name) != 0) {
        taskqueue_lock(queue);
        queue->flags &= ~BSD_TASKQUEUE_STARTED;
        taskqueue_unlock(queue);
        return BSD_TASKQUEUE_ENOMEM;
    }
    queue->worker->td_priority = priority;
    queue->worker->td_affinity_mask = affinity_mask;
    if ((affinity_mask & (affinity_mask - 1u)) == 0)
        queue->worker->td_bound_cpu =
            (int)__builtin_ctzll(affinity_mask);
    if (kthread_resume(queue->worker) != 0) {
        taskqueue_lock(queue);
        queue->flags &= ~BSD_TASKQUEUE_STARTED;
        taskqueue_unlock(queue);
        return BSD_TASKQUEUE_EBUSY;
    }
    return 0;
}

int
taskqueue_start_threads(struct taskqueue **queue, int count, int priority,
    const char *format, ...)
{
    char name[BSD_TASKQUEUE_NAME_MAX];
    va_list arguments;

    if (!format)
        return BSD_TASKQUEUE_EINVAL;
    va_start(arguments, format);
    (void)bsd_vsnprintf(name, sizeof(name), format, arguments);
    va_end(arguments);
    return taskqueue_start_common(queue, count, priority, 0, name);
}

int
taskqueue_start_threads_in_proc(struct taskqueue **queue, int count,
    int priority, struct proc *process, const char *format, ...)
{
    char name[BSD_TASKQUEUE_NAME_MAX];
    va_list arguments;

    (void)process;
    if (!format)
        return BSD_TASKQUEUE_EINVAL;
    va_start(arguments, format);
    (void)bsd_vsnprintf(name, sizeof(name), format, arguments);
    va_end(arguments);
    return taskqueue_start_common(queue, count, priority, 0, name);
}

int
taskqueue_start_threads_cpuset(struct taskqueue **queue, int count,
    int priority, cpuset_t *mask, const char *format, ...)
{
    char name[BSD_TASKQUEUE_NAME_MAX];
    va_list arguments;

    if (!mask || !format)
        return BSD_TASKQUEUE_EINVAL;
    va_start(arguments, format);
    (void)bsd_vsnprintf(name, sizeof(name), format, arguments);
    va_end(arguments);
    return taskqueue_start_common(queue, count, priority, mask, name);
}

int
taskqueue_enqueue_flags(struct taskqueue *queue, struct task *task, int flags)
{
    taskqueue_enqueue_fn enqueue;
    void *context;
    int notify = 0;

    if (!queue || !task || !task->ta_func ||
        (flags & ~(TASKQUEUE_FAIL_IF_PENDING |
        TASKQUEUE_FAIL_IF_CANCELING)) != 0)
        return BSD_TASKQUEUE_EINVAL;
    taskqueue_lock(queue);
    if ((queue->flags & BSD_TASKQUEUE_STOPPED) != 0 ||
        (task->ta_flags & TASK_NOENQUEUE) != 0) {
        taskqueue_unlock(queue);
        return BSD_TASKQUEUE_EBUSY;
    }
    if (task->ta_pending != 0) {
        if ((flags & TASKQUEUE_FAIL_IF_PENDING) != 0) {
            taskqueue_unlock(queue);
            return BSD_TASKQUEUE_EBUSY;
        }
        if (task->ta_pending != UINT16_MAX)
            ++task->ta_pending;
    } else {
        task->ta_pending = 1;
        task->ta_flags |= TASK_ENQUEUED;
        taskqueue_insert_locked(queue, task);
        notify = (queue->flags & BSD_TASKQUEUE_BLOCKED) == 0;
    }
    enqueue = queue->enqueue;
    context = queue->enqueue_context;
    taskqueue_unlock(queue);
    if (notify) {
        if (enqueue)
            enqueue(context);
        else
            bsd_wakeup_one(queue);
    }
    return 0;
}

int
taskqueue_enqueue(struct taskqueue *queue, struct task *task)
{
    return taskqueue_enqueue_flags(queue, task, 0);
}

static void
taskqueue_timeout_fire(void *argument)
{
    struct timeout_task *timeout_task = argument;
    struct taskqueue *queue;

    if (!timeout_task || !timeout_task->q)
        return;
    queue = timeout_task->q;
    taskqueue_lock(queue);
    timeout_task->f &= ~BSD_TIMEOUT_CALLOUT_ARMED;
    taskqueue_unlock(queue);
    (void)taskqueue_enqueue(queue, &timeout_task->t);
}

void
_timeout_task_init(struct taskqueue *queue,
    struct timeout_task *timeout_task, int priority, task_fn_t *function,
    void *context)
{
    if (!timeout_task)
        return;
    timeout_task->q = queue;
    TASK_INIT(&timeout_task->t, priority, function, context);
    callout_init(&timeout_task->c, 1);
    timeout_task->f = 0;
}

int
taskqueue_enqueue_timeout_sbt(struct taskqueue *queue,
    struct timeout_task *timeout_task, sbintime_t sbt,
    sbintime_t precision, int flags)
{
    int callout_result;
    int pending;
    int reset_callout = 1;

    if (!queue || !timeout_task)
        return BSD_TASKQUEUE_EINVAL;
    taskqueue_lock(queue);
    if (timeout_task->q && timeout_task->q != queue) {
        taskqueue_unlock(queue);
        return BSD_TASKQUEUE_EINVAL;
    }
    timeout_task->q = queue;
    pending = timeout_task->t.ta_pending;
    if (sbt == 0) {
        taskqueue_unlock(queue);
        return taskqueue_enqueue(queue, &timeout_task->t) == 0 ?
            pending : BSD_TASKQUEUE_EBUSY;
    }
    if ((timeout_task->f & BSD_TIMEOUT_CALLOUT_ARMED) != 0) {
        ++pending;
        if (sbt < 0)
            reset_callout = 0;
    } else {
        timeout_task->f |= BSD_TIMEOUT_CALLOUT_ARMED;
        if (sbt < 0)
            sbt = sbt == INT64_MIN ? SBT_MAX : -sbt;
    }
    taskqueue_unlock(queue);

    if (!reset_callout)
        return pending;
    callout_result = callout_reset_sbt(&timeout_task->c, sbt, precision,
        taskqueue_timeout_fire, timeout_task, flags);
    if (callout_result > 1) {
        taskqueue_lock(queue);
        timeout_task->f &= ~BSD_TIMEOUT_CALLOUT_ARMED;
        taskqueue_unlock(queue);
        return BSD_TASKQUEUE_EINVAL;
    }
    return pending;
}

int
taskqueue_enqueue_timeout(struct taskqueue *queue,
    struct timeout_task *timeout_task, int timeout_ticks)
{
    sbintime_t sbt;

    if (timeout_ticks > 0 && tick_sbt > SBT_MAX / timeout_ticks)
        sbt = SBT_MAX;
    else if (timeout_ticks < 0 &&
        tick_sbt > SBT_MAX / -(int64_t)timeout_ticks)
        sbt = -SBT_MAX;
    else
        sbt = tick_sbt * (sbintime_t)timeout_ticks;
    return taskqueue_enqueue_timeout_sbt(queue, timeout_task,
        sbt, 0, C_HARDCLOCK);
}

void
taskqueue_run(struct taskqueue *queue)
{
    if (!queue)
        return;
    for (;;) {
        struct task *task;
        uint16_t pending;

        taskqueue_lock(queue);
        if ((queue->flags & BSD_TASKQUEUE_BLOCKED) != 0 ||
            !queue->head) {
            taskqueue_unlock(queue);
            return;
        }
        task = queue->head;
        queue->head = task->ta_link.stqe_next;
        task->ta_link.stqe_next = 0;
        pending = task->ta_pending;
        task->ta_pending = 0;
        task->ta_flags &= (uint8_t)~TASK_ENQUEUED;
        queue->running = task;
        taskqueue_unlock(queue);

        task->ta_func(task->ta_context, (int)pending);

        taskqueue_lock(queue);
        if (queue->running == task)
            queue->running = 0;
        taskqueue_unlock(queue);
        bsd_wakeup(task);
        bsd_wakeup(queue);
    }
}

void
taskqueue_thread_loop(void *argument)
{
    struct taskqueue **queue_pointer = argument;
    struct taskqueue *queue =
        queue_pointer ? *queue_pointer : 0;
    bsd_taskqueue_callback_t initial;

    if (!queue)
        kthread_exit();
    taskqueue_lock(queue);
    initial = queue->callbacks[TASKQUEUE_CALLBACK_TYPE_INIT];
    taskqueue_unlock(queue);
    if (initial.function)
        initial.function(initial.context);
    for (;;) {
        uint64_t generation;
        uint32_t flags;
        int pending;

        taskqueue_run(queue);
        generation = bsd_kthread_wakeup_generation(queue);
        taskqueue_lock(queue);
        flags = queue->flags;
        pending = queue->head != 0;
        taskqueue_unlock(queue);
        if ((flags & BSD_TASKQUEUE_STOPPED) != 0)
            break;
        if (pending)
            continue;
        /*
         * Sleep on the same queue object used by enqueue notifications.
         * Comparing the observed generation closes the gap between the empty
         * check and entering the wait state. Keep one bounded scheduler tick
         * as a recovery path for platforms where an interrupt can make the
         * worker runnable before the host reaches its next worker pump.
         */
        (void)bsd_kthread_sleep_generation(queue, generation, 1);
    }
    taskqueue_lock(queue);
    initial = queue->callbacks[TASKQUEUE_CALLBACK_TYPE_SHUTDOWN];
    taskqueue_unlock(queue);
    if (initial.function)
        initial.function(initial.context);
    kthread_exit();
}

void
taskqueue_thread_enqueue(void *context)
{
    struct taskqueue **queue_pointer = context;
    struct taskqueue *queue =
        queue_pointer ? *queue_pointer : 0;

    if (queue)
        bsd_wakeup_one(queue);
}

int
taskqueue_poll_is_busy(struct taskqueue *queue, struct task *task)
{
    int busy;

    if (!queue || !task)
        return 0;
    taskqueue_lock(queue);
    busy = queue->running == task ||
        taskqueue_contains_locked(queue, task);
    taskqueue_unlock(queue);
    return busy;
}

int
taskqueue_cancel(struct taskqueue *queue, struct task *task,
    unsigned int *pending)
{
    struct task **position;
    unsigned int count = 0;
    int result = 0;

    if (!queue || !task)
        return BSD_TASKQUEUE_EINVAL;
    taskqueue_lock(queue);
    position = &queue->head;
    while (*position && *position != task)
        position = &(*position)->ta_link.stqe_next;
    if (*position == task) {
        *position = task->ta_link.stqe_next;
        task->ta_link.stqe_next = 0;
        count = task->ta_pending;
        task->ta_pending = 0;
        task->ta_flags &= (uint8_t)~TASK_ENQUEUED;
    } else if (queue->running == task) {
        result = BSD_TASKQUEUE_EBUSY;
    }
    taskqueue_unlock(queue);
    if (pending)
        *pending = count;
    return result;
}

int
taskqueue_cancel_timeout(struct taskqueue *queue,
    struct timeout_task *timeout_task, unsigned int *pending)
{
    unsigned int task_pending = 0;
    unsigned int callout_pending;
    int result;

    if (!queue || !timeout_task)
        return BSD_TASKQUEUE_EINVAL;
    callout_pending = callout_stop(&timeout_task->c) > 0 ? 1u : 0u;
    taskqueue_lock(queue);
    timeout_task->f &= ~BSD_TIMEOUT_CALLOUT_ARMED;
    taskqueue_unlock(queue);
    result = taskqueue_cancel(queue, &timeout_task->t, &task_pending);
    if (pending)
        *pending = task_pending + callout_pending;
    return result;
}

void
taskqueue_drain(struct taskqueue *queue, struct task *task)
{
    if (!queue || !task)
        return;
    while (taskqueue_poll_is_busy(queue, task))
        (void)bsd_pause("taskdrain", 1);
}

void
taskqueue_drain_timeout(struct taskqueue *queue,
    struct timeout_task *timeout_task)
{
    if (!queue || !timeout_task)
        return;
    (void)callout_drain(&timeout_task->c);
    taskqueue_lock(queue);
    timeout_task->f &= ~BSD_TIMEOUT_CALLOUT_ARMED;
    taskqueue_unlock(queue);
    taskqueue_drain(queue, &timeout_task->t);
}

void
taskqueue_drain_all(struct taskqueue *queue)
{
    if (!queue)
        return;
    for (;;) {
        int busy;

        taskqueue_lock(queue);
        busy = queue->head != 0 || queue->running != 0;
        taskqueue_unlock(queue);
        if (!busy)
            return;
        (void)bsd_pause("taskdrainall", 1);
    }
}

void
taskqueue_quiesce(struct taskqueue *queue)
{
    taskqueue_drain_all(queue);
}

void
taskqueue_free(struct taskqueue *queue)
{
    struct thread *worker;

    if (!queue)
        return;
    taskqueue_lock(queue);
    queue->flags |= BSD_TASKQUEUE_STOPPED;
    queue->flags &= ~BSD_TASKQUEUE_BLOCKED;
    worker = queue->worker;
    taskqueue_unlock(queue);
    bsd_wakeup(queue);
    if (worker)
        (void)bsd_kthread_join(worker);
    else
        taskqueue_run(queue);
    taskqueue_drain_all(queue);
    bsd_kfree(queue);
}

void
taskqueue_block(struct taskqueue *queue)
{
    if (!queue)
        return;
    taskqueue_lock(queue);
    queue->flags |= BSD_TASKQUEUE_BLOCKED;
    taskqueue_unlock(queue);
}

void
taskqueue_unblock(struct taskqueue *queue)
{
    int notify;

    if (!queue)
        return;
    taskqueue_lock(queue);
    queue->flags &= ~BSD_TASKQUEUE_BLOCKED;
    notify = queue->head != 0;
    taskqueue_unlock(queue);
    if (notify)
        bsd_wakeup_one(queue);
}

int
taskqueue_member(struct taskqueue *queue, struct thread *thread)
{
    return queue && thread && queue->worker == thread;
}

void
taskqueue_set_callback(struct taskqueue *queue,
    enum taskqueue_callback_type type, taskqueue_callback_fn callback,
    void *context)
{
    if (!queue || type < TASKQUEUE_CALLBACK_TYPE_INIT ||
        type >= TASKQUEUE_NUM_CALLBACKS)
        return;
    taskqueue_lock(queue);
    queue->callbacks[type].function = callback;
    queue->callbacks[type].context = context;
    taskqueue_unlock(queue);
}

int
bsd_taskqueue_runtime_initialize(void)
{
    uint32_t expected = 0;

    if (__atomic_load_n(
        &g_taskqueue_runtime_state, __ATOMIC_ACQUIRE) == 2)
        return 0;
    if (!__atomic_compare_exchange_n(&g_taskqueue_runtime_state,
        &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(
            &g_taskqueue_runtime_state, __ATOMIC_ACQUIRE) == 1)
            taskqueue_relax();
        return __atomic_load_n(
            &g_taskqueue_runtime_state, __ATOMIC_ACQUIRE) == 2 ?
            0 : BSD_TASKQUEUE_ENOMEM;
    }
    taskqueue_thread = taskqueue_create(
        "thread", M_WAITOK, taskqueue_thread_enqueue,
        &taskqueue_thread);
    if (!taskqueue_thread ||
        taskqueue_start_threads(&taskqueue_thread, 1, 0,
        "taskqueue_thread") != 0) {
        if (taskqueue_thread)
            taskqueue_free(taskqueue_thread);
        taskqueue_thread = 0;
        taskqueue_swi = 0;
        taskqueue_swi_giant = 0;
        taskqueue_fast = 0;
        taskqueue_bus = 0;
        __atomic_store_n(&g_taskqueue_runtime_state, 0,
            __ATOMIC_RELEASE);
        return BSD_TASKQUEUE_ENOMEM;
    }
    taskqueue_bus = taskqueue_create(
        "bus", M_WAITOK, taskqueue_thread_enqueue, &taskqueue_bus);
    if (!taskqueue_bus ||
        taskqueue_start_threads(&taskqueue_bus, 1, 0,
        "taskqueue_bus") != 0) {
        if (taskqueue_bus)
            taskqueue_free(taskqueue_bus);
        taskqueue_bus = 0;
        taskqueue_free(taskqueue_thread);
        taskqueue_thread = 0;
        taskqueue_swi = 0;
        taskqueue_swi_giant = 0;
        taskqueue_fast = 0;
        __atomic_store_n(&g_taskqueue_runtime_state, 0,
            __ATOMIC_RELEASE);
        return BSD_TASKQUEUE_ENOMEM;
    }
    taskqueue_swi = taskqueue_thread;
    taskqueue_swi_giant = taskqueue_thread;
    taskqueue_fast = taskqueue_thread;
    __atomic_store_n(&g_taskqueue_runtime_state, 2,
        __ATOMIC_RELEASE);
    return 0;
}

int
bsd_taskqueue_runtime_is_initialized(void)
{
    return __atomic_load_n(
        &g_taskqueue_runtime_state, __ATOMIC_ACQUIRE) == 2;
}

struct taskqueue *
bsd_taskqueue_worker_create(const char *name)
{
    struct taskqueue *queue;

    if (!name || !bsd_kthread_runtime_is_initialized())
        return 0;
    queue = taskqueue_create(name, M_WAITOK, taskqueue_thread_enqueue, 0);
    if (!queue)
        return 0;
    queue->enqueue_context = &queue->self;
    if (taskqueue_start_common(&queue->self, 1, 0, 0, name) != 0) {
        taskqueue_free(queue);
        return 0;
    }
    return queue;
}

int
bsd_taskqueue_worker_schedule(struct taskqueue *queue, struct task *task)
{
    return taskqueue_enqueue(queue, task);
}

void
bsd_taskqueue_worker_drain(struct taskqueue *queue, struct task *task)
{
    taskqueue_drain(queue, task);
}

void
bsd_taskqueue_worker_destroy(struct taskqueue *queue)
{
    taskqueue_free(queue);
}

void
bsd_taskqueue_task_init(struct task *task, uint8_t priority,
    bsd_taskqueue_task_fn_t *function, void *context)
{
    if (!task)
        return;
    TASK_INIT(task, priority, function, context);
}

int
bsd_taskqueue_task_schedule(struct task *task)
{
    if (!taskqueue_thread || !task)
        return BSD_TASKQUEUE_EINVAL;
    return taskqueue_enqueue(taskqueue_thread, task);
}

void
bsd_taskqueue_task_drain(struct task *task)
{
    if (taskqueue_thread && task)
        taskqueue_drain(taskqueue_thread, task);
}
