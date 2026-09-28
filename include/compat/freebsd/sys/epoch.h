/* SPDX-License-Identifier: MPL-2.0 */

#ifndef _SYS_EPOCH_H_
#define _SYS_EPOCH_H_

#include <sys/cdefs.h>

struct epoch_context {
    void *data[2];
} __attribute__((aligned(sizeof(void *))));

typedef struct epoch_context *epoch_context_t;
typedef void epoch_callback_t(epoch_context_t);

struct epoch;
typedef struct epoch *epoch_t;

struct epoch_tracker {
    unsigned int active;
};

typedef struct epoch_tracker *epoch_tracker_t;

#define EPOCH_PREEMPT 0x1
#define EPOCH_LOCKED 0x2

extern epoch_t global_epoch;
extern epoch_t global_epoch_preempt;
extern epoch_t net_epoch_preempt;

epoch_t epoch_alloc(const char *name, int flags);
void epoch_free(epoch_t epoch);
void epoch_wait(epoch_t epoch);
void epoch_wait_preempt(epoch_t epoch);
void epoch_drain_callbacks(epoch_t epoch);
void epoch_call(epoch_t epoch, epoch_callback_t callback,
    epoch_context_t context);
int in_epoch(epoch_t epoch);
int in_epoch_verbose(epoch_t epoch, int dump_on_failure);
void _epoch_enter_preempt(epoch_t epoch, epoch_tracker_t tracker);
void _epoch_exit_preempt(epoch_t epoch, epoch_tracker_t tracker);
void epoch_enter(epoch_t epoch);
void epoch_exit(epoch_t epoch);

#define epoch_enter_preempt(epoch, tracker) \
    _epoch_enter_preempt((epoch), (tracker))
#define epoch_exit_preempt(epoch, tracker) \
    _epoch_exit_preempt((epoch), (tracker))

#define NET_EPOCH_ENTER(tracker) \
    epoch_enter_preempt(net_epoch_preempt, &(tracker))
#define NET_EPOCH_EXIT(tracker) \
    epoch_exit_preempt(net_epoch_preempt, &(tracker))
#define NET_EPOCH_WAIT() epoch_wait_preempt(net_epoch_preempt)
#define NET_EPOCH_CALL(callback, context) \
    epoch_call(net_epoch_preempt, (callback), (context))
#define NET_EPOCH_DRAIN_CALLBACKS() \
    epoch_drain_callbacks(net_epoch_preempt)
#define NET_EPOCH_ASSERT() do { } while (0)

#endif
