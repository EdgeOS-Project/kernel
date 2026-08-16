/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD group taskqueues backed by EdgeOS kernel workers. */

#ifndef _SYS_GTASKQUEUE_H_
#define _SYS_GTASKQUEUE_H_

#ifndef _KERNEL
#error "group taskqueues are a kernel interface"
#endif

#include <sys/types.h>
#include "_task.h"
#include "queue_compat.h"
#include "taskqueue.h"

struct gtaskqueue;
struct _device;
struct resource;
struct taskqgroup;
typedef struct _device *device_t;

struct grouptask {
    struct gtask gt_task;
    void *gt_taskqueue;
    LIST_ENTRY(grouptask) gt_list;
    void *gt_uniq;
#define GROUPTASK_NAMELEN 32
    char gt_name[GROUPTASK_NAMELEN];
    device_t gt_dev;
    struct resource *gt_irq;
    int gt_cpu;
};

void gtaskqueue_block(struct gtaskqueue *queue);
void gtaskqueue_unblock(struct gtaskqueue *queue);
int gtaskqueue_cancel(struct gtaskqueue *queue, struct gtask *task);
void gtaskqueue_drain(struct gtaskqueue *queue, struct gtask *task);
void gtaskqueue_drain_all(struct gtaskqueue *queue);

void grouptask_block(struct grouptask *task);
void grouptask_unblock(struct grouptask *task);
int grouptaskqueue_enqueue(struct gtaskqueue *queue, struct gtask *task);

void taskqgroup_attach(struct taskqgroup *group, struct grouptask *task,
    void *unique, device_t device, struct resource *irq, const char *name);
int taskqgroup_attach_cpu(struct taskqgroup *group, struct grouptask *task,
    void *unique, int cpu, device_t device, struct resource *irq,
    const char *name);
void taskqgroup_detach(struct taskqgroup *group, struct grouptask *task);
struct taskqgroup *taskqgroup_create(const char *name, int count,
    int stride);
void taskqgroup_destroy(struct taskqgroup *group);
void taskqgroup_bind(struct taskqgroup *group);
void taskqgroup_drain_all(struct taskqgroup *group);

#define GTASK_INIT(task, flags, priority, function, context) do {       \
    (task)->ta_link.stqe_next = 0;                                      \
    (task)->ta_flags = (flags);                                         \
    (task)->ta_priority = (priority);                                   \
    (task)->ta_func = (function);                                       \
    (task)->ta_context = (context);                                     \
} while (0)

#define GROUPTASK_INIT(task, priority, function, context)               \
    GTASK_INIT(&(task)->gt_task, 0, (priority), (function), (context))
#define NET_GROUPTASK_INIT(task, priority, function, context)           \
    GTASK_INIT(&(task)->gt_task, TASK_NETWORK, (priority),              \
        (function), (context))
#define GROUPTASK_ENQUEUE(task)                                         \
    grouptaskqueue_enqueue((task)->gt_taskqueue, &(task)->gt_task)

#define TASKQGROUP_DECLARE(name) extern struct taskqgroup *qgroup_##name

#define TASKQGROUP_DEFINE(name, count, stride)                          \
    struct taskqgroup *qgroup_##name;                                   \
    static void taskqgroup_define_##name(void *argument)                \
    {                                                                   \
        (void)argument;                                                  \
        qgroup_##name = taskqgroup_create(                              \
            #name, (count), (stride));                                  \
    }                                                                   \
    SYSINIT(taskqgroup_##name, SI_SUB_TASKQ, SI_ORDER_FIRST,            \
        taskqgroup_define_##name, 0);                                   \
    static void taskqgroup_bind_##name(void *argument)                  \
    {                                                                   \
        (void)argument;                                                  \
        taskqgroup_bind(qgroup_##name);                                 \
    }                                                                   \
    SYSINIT(taskqgroup_bind_##name, SI_SUB_SMP, SI_ORDER_ANY,           \
        taskqgroup_bind_##name, 0)

TASKQGROUP_DECLARE(softirq);

#endif
