/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS POSIX timer runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_POSIX_TIMER_RUNTIME_H
#define EDGEOS_KERNEL_POSIX_TIMER_RUNTIME_H

#include <stdint.h>

enum kernel_posix_timer_notification {
    KERNEL_POSIX_TIMER_SIGEV_SIGNAL = 0,
    KERNEL_POSIX_TIMER_SIGEV_NONE = 1,
    KERNEL_POSIX_TIMER_SIGEV_THREAD = 2,
    KERNEL_POSIX_TIMER_SIGEV_THREAD_ID = 4,
};

typedef struct kernel_posix_timer_create_request {
    int32_t clock_id;
    int32_t notify;
    int32_t signal_number;
    int32_t target_tid;
    uint64_t signal_value;
    uint8_t default_event;
} kernel_posix_timer_create_request_t;

typedef struct kernel_posix_timer_state {
    uint64_t remaining_microseconds;
    uint64_t interval_microseconds;
    int32_t last_overrun;
} kernel_posix_timer_state_t;

typedef struct kernel_posix_timer_backend_ops {
    int (*current_identity)(void *context, int32_t *tid, int32_t *tgid);
    int (*thread_group_for_tid)(void *context, int32_t tid, int32_t *tgid);
    int (*enqueue_signal)(void *context, int32_t target,
                          uint32_t signal, int directed,
                          const void *information);
} kernel_posix_timer_backend_ops_t;

int kernel_posix_timer_backend_register(
    const kernel_posix_timer_backend_ops_t *ops, void *context);
int kernel_posix_timer_create(
    const kernel_posix_timer_create_request_t *request,
    int32_t *timer_id);
int kernel_posix_timer_get(int32_t timer_id,
                           kernel_posix_timer_state_t *state);
int kernel_posix_timer_set(int32_t timer_id,
                           uint64_t initial_microseconds,
                           uint64_t interval_microseconds,
                           int absolute,
                           kernel_posix_timer_state_t *previous);
int kernel_posix_timer_get_overrun(int32_t timer_id);
int kernel_posix_timer_delete(int32_t timer_id);
void kernel_posix_timer_delete_process(int32_t process_id);
void kernel_posix_timer_signal_consumed(int32_t timer_id, int32_t overrun);
void kernel_posix_timer_poll(void);

#endif
