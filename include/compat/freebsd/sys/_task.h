/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD task records shared by the EdgeOS BSD Driver Bridge. */

#ifndef _SYS__TASK_H_
#define _SYS__TASK_H_

#include <stdint.h>
#include "queue_compat.h"
#include "_callout.h"

typedef void task_fn_t(void *context, int pending);

struct task {
    STAILQ_ENTRY(task) ta_link;
    uint16_t ta_pending;
    uint8_t ta_priority;
    uint8_t ta_flags;
    task_fn_t *ta_func;
    void *ta_context;
};

#define TASK_ENQUEUED 0x01
#define TASK_NOENQUEUE 0x02
#define TASK_NETWORK 0x04
#define TASK_IS_NET(task) (((task)->ta_flags & TASK_NETWORK) != 0)

struct taskqueue;

struct timeout_task {
    struct taskqueue *q;
    struct task t;
    struct callout c;
    int f;
};

#ifdef _KERNEL

typedef void gtask_fn_t(void *context);

struct gtask {
    STAILQ_ENTRY(gtask) ta_link;
    uint16_t ta_flags;
    unsigned short ta_priority;
    gtask_fn_t *ta_func;
    void *ta_context;
};

#endif

#endif
