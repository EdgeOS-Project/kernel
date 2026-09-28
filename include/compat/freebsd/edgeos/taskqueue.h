/* SPDX-License-Identifier: MPL-2.0 */
/* Shared taskqueue runtime for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_TASKQUEUE_H
#define EDGEOS_COMPAT_FREEBSD_TASKQUEUE_H

#include <stdint.h>
#include "../sys/_task.h"

struct taskqueue;

typedef task_fn_t bsd_taskqueue_task_fn_t;

int bsd_taskqueue_runtime_initialize(void);
int bsd_taskqueue_runtime_is_initialized(void);
struct taskqueue *bsd_taskqueue_worker_create(const char *name);
int bsd_taskqueue_worker_schedule(struct taskqueue *queue,
    struct task *task);
void bsd_taskqueue_worker_drain(struct taskqueue *queue,
    struct task *task);
void bsd_taskqueue_worker_destroy(struct taskqueue *queue);
void bsd_taskqueue_task_init(struct task *task, uint8_t priority,
    bsd_taskqueue_task_fn_t *function, void *context);
int bsd_taskqueue_task_schedule(struct task *task);
void bsd_taskqueue_task_drain(struct task *task);

#endif
