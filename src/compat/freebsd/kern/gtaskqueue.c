/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD group taskqueues on the shared EdgeOS kernel-worker runtime. */

#include "compat/freebsd/sys/gtaskqueue.h"

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/smp.h"

#define BSD_GTASKQUEUE_EAGAIN 11
#define BSD_GTASKQUEUE_ENOMEM 12
#define BSD_GTASKQUEUE_EBUSY 16
#define BSD_GTASKQUEUE_EINVAL 22
#define BSD_GTASKQUEUE_STOPPED 0x01u
#define BSD_GTASKQUEUE_BLOCKED 0x02u
#define BSD_TASKQGROUP_DESTROYING 0x01u
#define BSD_GTASKQUEUE_NAME_MAX 32u
#define BSD_GTASKQUEUE_MAX_QUEUES 64

struct gtaskqueue {
    volatile uint32_t guard;
    uint64_t guard_interrupt_state;
    struct gtask *head;
    struct gtask *tail;
    struct gtask *running;
    struct thread *worker;
    uint32_t flags;
    char name[BSD_GTASKQUEUE_NAME_MAX];
};

struct taskqgroup_cpu {
    struct grouptask *tasks;
    struct gtaskqueue *queue;
    int task_count;
    int cpu;
};

struct taskqgroup {
    volatile uint32_t guard;
    uint64_t guard_interrupt_state;
    int count;
    int stride;
    uint32_t flags;
    char name[BSD_GTASKQUEUE_NAME_MAX];
    struct taskqgroup_cpu queues[];
};

struct taskqgroup *qgroup_softirq;

#ifndef BSD_BRIDGE_HOST_TEST
int bus_bind_intr(device_t device, struct resource *resource, int cpu);
#endif

static uint64_t
gtaskqueue_interrupt_save_disable(void)
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
#error "BSD Driver Bridge group taskqueues need an interrupt backend"
#endif
}

static void
gtaskqueue_interrupt_restore(uint64_t state)
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
gtaskqueue_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(_M_ARM64)
    __asm__ __volatile__("yield");
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

static void
gtaskqueue_guard_lock(volatile uint32_t *guard, uint64_t *interrupt_state)
{
    uint64_t state = gtaskqueue_interrupt_save_disable();

    while (__atomic_test_and_set(guard, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(guard, __ATOMIC_RELAXED))
            gtaskqueue_relax();
    }
    *interrupt_state = state;
}

static void
gtaskqueue_guard_unlock(volatile uint32_t *guard, uint64_t interrupt_state)
{
    __atomic_clear(guard, __ATOMIC_RELEASE);
    gtaskqueue_interrupt_restore(interrupt_state);
}

static void
gtaskqueue_lock(struct gtaskqueue *queue)
{
    gtaskqueue_guard_lock(
        &queue->guard, &queue->guard_interrupt_state);
}

static void
gtaskqueue_unlock(struct gtaskqueue *queue)
{
    uint64_t state = queue->guard_interrupt_state;

    gtaskqueue_guard_unlock(&queue->guard, state);
}

static void
taskqgroup_lock(struct taskqgroup *group)
{
    gtaskqueue_guard_lock(
        &group->guard, &group->guard_interrupt_state);
}

static void
taskqgroup_unlock(struct taskqgroup *group)
{
    uint64_t state = group->guard_interrupt_state;

    gtaskqueue_guard_unlock(&group->guard, state);
}

static void
gtaskqueue_append_locked(struct gtaskqueue *queue, struct gtask *task)
{
    task->ta_link.stqe_next = 0;
    if (queue->tail)
        queue->tail->ta_link.stqe_next = task;
    else
        queue->head = task;
    queue->tail = task;
}

static int
gtaskqueue_remove_locked(struct gtaskqueue *queue, struct gtask *task)
{
    struct gtask *previous = 0;
    struct gtask *entry = queue->head;

    while (entry && entry != task) {
        previous = entry;
        entry = entry->ta_link.stqe_next;
    }
    if (!entry)
        return 0;
    if (previous)
        previous->ta_link.stqe_next = entry->ta_link.stqe_next;
    else
        queue->head = entry->ta_link.stqe_next;
    if (queue->tail == entry)
        queue->tail = previous;
    entry->ta_link.stqe_next = 0;
    return 1;
}

static void
gtaskqueue_run(struct gtaskqueue *queue)
{
    for (;;) {
        struct gtask *task;

        gtaskqueue_lock(queue);
        if ((queue->flags & BSD_GTASKQUEUE_BLOCKED) != 0 ||
            !queue->head) {
            gtaskqueue_unlock(queue);
            return;
        }
        task = queue->head;
        queue->head = task->ta_link.stqe_next;
        if (!queue->head)
            queue->tail = 0;
        task->ta_link.stqe_next = 0;
        task->ta_flags &= (uint16_t)~TASK_ENQUEUED;
        queue->running = task;
        gtaskqueue_unlock(queue);

        task->ta_func(task->ta_context);

        gtaskqueue_lock(queue);
        if (queue->running == task)
            queue->running = 0;
        gtaskqueue_unlock(queue);
        bsd_wakeup(task);
        bsd_wakeup(queue);
    }
}

static void
gtaskqueue_worker(void *argument)
{
    struct gtaskqueue *queue = argument;

    for (;;) {
        uint64_t generation;
        uint32_t flags;
        int pending;

        gtaskqueue_run(queue);
        generation = bsd_kthread_wakeup_generation(queue);
        gtaskqueue_lock(queue);
        flags = queue->flags;
        pending = queue->head != 0 &&
            (flags & BSD_GTASKQUEUE_BLOCKED) == 0;
        gtaskqueue_unlock(queue);
        if ((flags & BSD_GTASKQUEUE_STOPPED) != 0)
            break;
        if (pending)
            continue;
        (void)bsd_kthread_sleep_generation(queue, generation, 1);
    }
    kthread_exit();
}

static struct gtaskqueue *
gtaskqueue_create(const char *name)
{
    struct gtaskqueue *queue =
        bsd_kmalloc(sizeof(*queue), BSD_M_WAITOK | BSD_M_ZERO);

    if (!queue)
        return 0;
    (void)bsd_strlcpy(queue->name,
        name ? name : "gtaskqueue", sizeof(queue->name));
    if (kthread_add(gtaskqueue_worker, queue, 0, &queue->worker,
        0, 0, "%s", queue->name) != 0) {
        bsd_kfree(queue);
        return 0;
    }
    return queue;
}

static void
gtaskqueue_destroy(struct gtaskqueue *queue)
{
    struct thread *worker;

    if (!queue)
        return;
    gtaskqueue_lock(queue);
    queue->flags &= ~BSD_GTASKQUEUE_BLOCKED;
    queue->flags |= BSD_GTASKQUEUE_STOPPED;
    worker = queue->worker;
    gtaskqueue_unlock(queue);
    bsd_wakeup(queue);
    if (worker)
        (void)bsd_kthread_join(worker);
    bsd_kfree(queue);
}

void
gtaskqueue_block(struct gtaskqueue *queue)
{
    if (!queue)
        return;
    gtaskqueue_lock(queue);
    queue->flags |= BSD_GTASKQUEUE_BLOCKED;
    gtaskqueue_unlock(queue);
}

void
gtaskqueue_unblock(struct gtaskqueue *queue)
{
    int notify;

    if (!queue)
        return;
    gtaskqueue_lock(queue);
    queue->flags &= ~BSD_GTASKQUEUE_BLOCKED;
    notify = queue->head != 0;
    gtaskqueue_unlock(queue);
    if (notify)
        bsd_wakeup_one(queue);
}

int
gtaskqueue_cancel(struct gtaskqueue *queue, struct gtask *task)
{
    int result = 0;

    if (!queue || !task)
        return BSD_GTASKQUEUE_EINVAL;
    gtaskqueue_lock(queue);
    if ((task->ta_flags & TASK_ENQUEUED) != 0) {
        (void)gtaskqueue_remove_locked(queue, task);
        task->ta_flags &= (uint16_t)~TASK_ENQUEUED;
    } else if (queue->running == task) {
        result = BSD_GTASKQUEUE_EBUSY;
    }
    gtaskqueue_unlock(queue);
    return result;
}

void
gtaskqueue_drain(struct gtaskqueue *queue, struct gtask *task)
{
    if (!queue || !task)
        return;
    for (;;) {
        int busy;

        gtaskqueue_lock(queue);
        busy = queue->running == task ||
            (task->ta_flags & TASK_ENQUEUED) != 0;
        gtaskqueue_unlock(queue);
        if (!busy)
            return;
        (void)bsd_pause("gtaskdrain", 1);
    }
}

void
gtaskqueue_drain_all(struct gtaskqueue *queue)
{
    if (!queue)
        return;
    for (;;) {
        int busy;

        gtaskqueue_lock(queue);
        busy = queue->head != 0 || queue->running != 0;
        gtaskqueue_unlock(queue);
        if (!busy)
            return;
        (void)bsd_pause("gtaskdrainall", 1);
    }
}

void
grouptask_block(struct grouptask *task)
{
    struct gtaskqueue *queue;

    if (!task || !(queue = task->gt_taskqueue))
        return;
    gtaskqueue_lock(queue);
    task->gt_task.ta_flags |= TASK_NOENQUEUE;
    gtaskqueue_unlock(queue);
    gtaskqueue_drain(queue, &task->gt_task);
}

void
grouptask_unblock(struct grouptask *task)
{
    struct gtaskqueue *queue;

    if (!task || !(queue = task->gt_taskqueue))
        return;
    gtaskqueue_lock(queue);
    task->gt_task.ta_flags &= (uint16_t)~TASK_NOENQUEUE;
    gtaskqueue_unlock(queue);
}

int
grouptaskqueue_enqueue(struct gtaskqueue *queue, struct gtask *task)
{
    if (!queue || !task || !task->ta_func)
        return BSD_GTASKQUEUE_EINVAL;
    gtaskqueue_lock(queue);
    if ((queue->flags & BSD_GTASKQUEUE_STOPPED) != 0) {
        gtaskqueue_unlock(queue);
        return BSD_GTASKQUEUE_EBUSY;
    }
    if ((task->ta_flags & TASK_ENQUEUED) != 0) {
        gtaskqueue_unlock(queue);
        return 0;
    }
    if ((task->ta_flags & TASK_NOENQUEUE) != 0) {
        gtaskqueue_unlock(queue);
        return BSD_GTASKQUEUE_EAGAIN;
    }
    gtaskqueue_append_locked(queue, task);
    task->ta_flags |= TASK_ENQUEUED;
    if ((queue->flags & BSD_GTASKQUEUE_BLOCKED) == 0) {
        gtaskqueue_unlock(queue);
        bsd_wakeup_one(queue);
    } else {
        gtaskqueue_unlock(queue);
    }
    return 0;
}

static int
taskqgroup_find_locked(struct taskqgroup *group, void *unique)
{
    int selected = -1;
    int selected_count = 0;

    for (int strict = 1; selected < 0; strict = 0) {
        for (int index = 0; index < group->count; ++index) {
            struct taskqgroup_cpu *candidate = &group->queues[index];
            int duplicate = 0;

            if (selected >= 0 &&
                candidate->task_count > selected_count)
                continue;
            if (strict) {
                for (struct grouptask *task = candidate->tasks;
                    task; task = task->gt_list.le_next) {
                    if (task->gt_uniq == unique) {
                        duplicate = 1;
                        break;
                    }
                }
            }
            if (duplicate)
                continue;
            selected = index;
            selected_count = candidate->task_count;
        }
    }
    return selected;
}

static void
taskqgroup_link_locked(struct taskqgroup_cpu *queue,
    struct grouptask *task)
{
    task->gt_list.le_next = queue->tasks;
    task->gt_list.le_prev = &queue->tasks;
    if (queue->tasks)
        queue->tasks->gt_list.le_prev = &task->gt_list.le_next;
    queue->tasks = task;
    ++queue->task_count;
    task->gt_taskqueue = queue->queue;
}

static void
taskqgroup_unlink_locked(struct taskqgroup_cpu *queue,
    struct grouptask *task)
{
    if (task->gt_list.le_next)
        task->gt_list.le_next->gt_list.le_prev =
            task->gt_list.le_prev;
    if (task->gt_list.le_prev)
        *task->gt_list.le_prev = task->gt_list.le_next;
    task->gt_list.le_next = 0;
    task->gt_list.le_prev = 0;
    if (queue->task_count > 0)
        --queue->task_count;
}

static void
taskqgroup_set_metadata(struct grouptask *task, void *unique,
    device_t device, struct resource *irq, int cpu, const char *name)
{
    task->gt_uniq = unique;
    task->gt_dev = device;
    task->gt_irq = irq;
    task->gt_cpu = cpu;
    (void)bsd_strlcpy(task->gt_name,
        name ? name : "grouptask", sizeof(task->gt_name));
}

static void
taskqgroup_bind_interrupt(struct grouptask *task)
{
#ifndef BSD_BRIDGE_HOST_TEST
    if (task->gt_dev && task->gt_irq)
        (void)bus_bind_intr(task->gt_dev, task->gt_irq, task->gt_cpu);
#else
    (void)task;
#endif
}

void
taskqgroup_attach(struct taskqgroup *group, struct grouptask *task,
    void *unique, device_t device, struct resource *irq, const char *name)
{
    int queue_index;
    int cpu;

    if (!group || !task || group->count <= 0)
        return;
    taskqgroup_lock(group);
    if ((group->flags & BSD_TASKQGROUP_DESTROYING) != 0 ||
        task->gt_taskqueue) {
        taskqgroup_unlock(group);
        return;
    }
    queue_index = taskqgroup_find_locked(group, unique);
    cpu = device && irq ? group->queues[queue_index].cpu : -1;
    taskqgroup_set_metadata(task, unique, device, irq,
        cpu, name);
    taskqgroup_link_locked(&group->queues[queue_index], task);
    taskqgroup_unlock(group);
    taskqgroup_bind_interrupt(task);
}

int
taskqgroup_attach_cpu(struct taskqgroup *group, struct grouptask *task,
    void *unique, int cpu, device_t device, struct resource *irq,
    const char *name)
{
    int queue_index = -1;

    if (!group || !task || cpu < 0)
        return BSD_GTASKQUEUE_EINVAL;
    taskqgroup_lock(group);
    if ((group->flags & BSD_TASKQGROUP_DESTROYING) != 0 ||
        task->gt_taskqueue) {
        taskqgroup_unlock(group);
        return BSD_GTASKQUEUE_EBUSY;
    }
    for (int index = 0; index < group->count; ++index) {
        if (group->queues[index].cpu == cpu) {
            queue_index = index;
            break;
        }
    }
    if (queue_index < 0) {
        taskqgroup_unlock(group);
        return BSD_GTASKQUEUE_EINVAL;
    }
    taskqgroup_set_metadata(task, unique, device, irq, cpu, name);
    taskqgroup_link_locked(&group->queues[queue_index], task);
    taskqgroup_unlock(group);
    taskqgroup_bind_interrupt(task);
    return 0;
}

void
taskqgroup_detach(struct taskqgroup *group, struct grouptask *task)
{
    int queue_index = -1;

    if (!group || !task || !task->gt_taskqueue)
        return;
    grouptask_block(task);
    taskqgroup_lock(group);
    for (int index = 0; index < group->count; ++index) {
        if (group->queues[index].queue == task->gt_taskqueue) {
            queue_index = index;
            break;
        }
    }
    if (queue_index < 0) {
        taskqgroup_unlock(group);
        grouptask_unblock(task);
        return;
    }
    taskqgroup_unlink_locked(&group->queues[queue_index], task);
    task->gt_taskqueue = 0;
    task->gt_task.ta_flags &= (uint16_t)~TASK_NOENQUEUE;
    taskqgroup_unlock(group);
}

struct taskqgroup *
taskqgroup_create(const char *name, int count, int stride)
{
    struct taskqgroup *group;
    size_t allocation_size;
    int available_cpus = mp_ncpus > 0 ? mp_ncpus : 1;

    if (count <= 0 || count > BSD_GTASKQUEUE_MAX_QUEUES ||
        stride <= 0)
        return 0;
    if (count > available_cpus)
        count = available_cpus;
    allocation_size = sizeof(*group) +
        (size_t)count * sizeof(group->queues[0]);
    group = bsd_kmalloc(
        allocation_size, BSD_M_WAITOK | BSD_M_ZERO);
    if (!group)
        return 0;
    group->count = count;
    group->stride = stride;
    (void)bsd_strlcpy(group->name,
        name ? name : "taskqgroup", sizeof(group->name));
    for (int index = 0; index < count; ++index) {
        char queue_name[BSD_GTASKQUEUE_NAME_MAX];
        int cpu = (index * stride) % available_cpus;

        group->queues[index].cpu = cpu;
        (void)bsd_snprintf(queue_name, sizeof(queue_name),
            "%s_%d", group->name, index);
        group->queues[index].queue =
            gtaskqueue_create(queue_name);
        if (!group->queues[index].queue) {
            for (int created = 0; created < index; ++created)
                gtaskqueue_destroy(group->queues[created].queue);
            bsd_kfree(group);
            return 0;
        }
    }
    return group;
}

void
taskqgroup_destroy(struct taskqgroup *group)
{
    if (!group)
        return;
    taskqgroup_lock(group);
    group->flags |= BSD_TASKQGROUP_DESTROYING;
    for (int index = 0; index < group->count; ++index) {
        struct gtaskqueue *queue = group->queues[index].queue;

        gtaskqueue_lock(queue);
        for (struct grouptask *task = group->queues[index].tasks;
            task; task = task->gt_list.le_next)
            task->gt_task.ta_flags |= TASK_NOENQUEUE;
        gtaskqueue_unlock(queue);
    }
    taskqgroup_unlock(group);
    for (int index = 0; index < group->count; ++index)
        gtaskqueue_destroy(group->queues[index].queue);
    taskqgroup_lock(group);
    for (int index = 0; index < group->count; ++index) {
        struct grouptask *task = group->queues[index].tasks;

        while (task) {
            struct grouptask *next = task->gt_list.le_next;

            task->gt_taskqueue = 0;
            task->gt_task.ta_flags &=
                (uint16_t)~(TASK_ENQUEUED | TASK_NOENQUEUE);
            task->gt_list.le_next = 0;
            task->gt_list.le_prev = 0;
            task = next;
        }
        group->queues[index].tasks = 0;
        group->queues[index].task_count = 0;
    }
    taskqgroup_unlock(group);
    bsd_kfree(group);
}

void
taskqgroup_bind(struct taskqgroup *group)
{
    (void)group;
}

void
taskqgroup_drain_all(struct taskqgroup *group)
{
    if (!group)
        return;
    for (int index = 0; index < group->count; ++index)
        gtaskqueue_drain_all(group->queues[index].queue);
}

static void
taskqgroup_softirq_initialize(void *argument)
{
    (void)argument;
    qgroup_softirq = taskqgroup_create("softirq",
        mp_ncpus > 0 ? mp_ncpus : 1, 1);
}

SYSINIT(taskqgroup_softirq, SI_SUB_TASKQ, SI_ORDER_FIRST,
    taskqgroup_softirq_initialize, 0);
