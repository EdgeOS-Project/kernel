/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD taskqueue interface backed by the EdgeOS shared worker runtime. */

#ifndef _SYS_TASKQUEUE_H_
#define _SYS_TASKQUEUE_H_

#include <stdint.h>
#include <sys/cdefs.h>
#include "cpuset.h"

#include "_task.h"
#include "../edgeos/taskqueue.h"

struct proc;
struct thread;
struct taskqueue;

typedef void (*taskqueue_enqueue_fn)(void *context);
typedef void (*taskqueue_callback_fn)(void *context);

#define TASKQUEUE_FAIL_IF_PENDING 0x01
#define TASKQUEUE_FAIL_IF_CANCELING 0x02
#define TASKQUEUE_NAMELEN 32

enum taskqueue_callback_type {
    TASKQUEUE_CALLBACK_TYPE_INIT = 0,
    TASKQUEUE_CALLBACK_TYPE_SHUTDOWN = 1,
    TASKQUEUE_NUM_CALLBACKS = 2,
};

#define TASK_INITIALIZER(priority, function, context) \
    { .ta_priority = (priority), .ta_func = (function), \
      .ta_context = (context) }

#define TASK_INIT_FLAGS(task, priority, function, context, flags) do { \
    (task)->ta_link.stqe_next = 0; \
    (task)->ta_pending = 0; \
    (task)->ta_priority = (priority); \
    (task)->ta_flags = (flags); \
    (task)->ta_func = (function); \
    (task)->ta_context = (context); \
} while (0)

#define TASK_INIT(task, priority, function, context) \
    TASK_INIT_FLAGS(task, priority, function, context, 0)
#define NET_TASK_INIT(task, priority, function, context) \
    TASK_INIT_FLAGS(task, priority, function, context, TASK_NETWORK)

void _timeout_task_init(struct taskqueue *queue,
    struct timeout_task *timeout_task, int priority, task_fn_t *function,
    void *context);
#define TIMEOUT_TASK_INIT(queue, timeout_task, priority, function, context) \
    _timeout_task_init((queue), (timeout_task), (priority), (function), \
        (context))

struct taskqueue *taskqueue_create(const char *name, int flags,
    taskqueue_enqueue_fn enqueue, void *context);
struct taskqueue *taskqueue_create_fast(const char *name, int flags,
    taskqueue_enqueue_fn enqueue, void *context);
int taskqueue_start_threads(struct taskqueue **queue, int count, int priority,
    const char *format, ...) __printflike(4, 5);
int taskqueue_start_threads_in_proc(struct taskqueue **queue, int count,
    int priority, struct proc *process, const char *format, ...)
    __printflike(5, 6);
int taskqueue_start_threads_cpuset(struct taskqueue **queue, int count,
    int priority, cpuset_t *mask, const char *format, ...)
    __printflike(5, 6);
int taskqueue_enqueue(struct taskqueue *queue, struct task *task);
int taskqueue_enqueue_flags(struct taskqueue *queue, struct task *task,
    int flags);
int taskqueue_enqueue_timeout(struct taskqueue *queue,
    struct timeout_task *timeout_task, int timeout_ticks);
int taskqueue_enqueue_timeout_sbt(struct taskqueue *queue,
    struct timeout_task *timeout_task, sbintime_t sbt,
    sbintime_t precision, int flags);
int taskqueue_poll_is_busy(struct taskqueue *queue, struct task *task);
int taskqueue_cancel(struct taskqueue *queue, struct task *task,
    unsigned int *pending);
int taskqueue_cancel_timeout(struct taskqueue *queue,
    struct timeout_task *timeout_task, unsigned int *pending);
void taskqueue_drain(struct taskqueue *queue, struct task *task);
void taskqueue_drain_timeout(struct taskqueue *queue,
    struct timeout_task *timeout_task);
void taskqueue_drain_all(struct taskqueue *queue);
void taskqueue_quiesce(struct taskqueue *queue);
void taskqueue_free(struct taskqueue *queue);
void taskqueue_run(struct taskqueue *queue);
void taskqueue_block(struct taskqueue *queue);
void taskqueue_unblock(struct taskqueue *queue);
int taskqueue_member(struct taskqueue *queue, struct thread *thread);
void taskqueue_set_callback(struct taskqueue *queue,
    enum taskqueue_callback_type type, taskqueue_callback_fn callback,
    void *context);
void taskqueue_thread_loop(void *argument);
void taskqueue_thread_enqueue(void *context);

extern struct taskqueue *taskqueue_thread;
extern struct taskqueue *taskqueue_swi;
extern struct taskqueue *taskqueue_swi_giant;
extern struct taskqueue *taskqueue_fast;
extern struct taskqueue *taskqueue_bus;

#define TASKQUEUE_DECLARE(name) extern struct taskqueue *taskqueue_##name

#endif
