/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_SIGNAL_QUEUE_H
#define EDGEOS_KERNEL_SIGNAL_QUEUE_H

#include <stdint.h>

#define KERNEL_SIGNAL_INFO_SIZE 128u

typedef struct kernel_signal_queue_ticket {
    uint64_t sequence;
} kernel_signal_queue_ticket_t;

void kernel_signal_info_build_sender(void *signal_info, uint32_t signal,
                                     int32_t code, int32_t sender_pid,
                                     uint32_t sender_uid, uint64_t value);
void kernel_signal_info_build_child(void *signal_info, uint32_t signal,
                                    int32_t code, int32_t child_pid,
                                    uint32_t child_uid, int32_t status,
                                    uint64_t user_ticks,
                                    uint64_t system_ticks);
void kernel_signal_info_build_timer(void *signal_info, uint32_t signal,
                                    int32_t timer_id, int32_t overrun,
                                    uint64_t value);
void kernel_signal_info_build_seccomp(void *signal_info, uint32_t signal,
                                      int32_t error, uint64_t call_address,
                                      int32_t syscall_number,
                                      uint32_t audit_architecture);

int kernel_signal_queue_enqueue(int32_t target, uint32_t signal,
                                int thread_directed,
                                const void *signal_info);
int kernel_signal_queue_enqueue_ticket(
    int32_t target, uint32_t signal, int thread_directed,
    const void *signal_info, kernel_signal_queue_ticket_t *ticket);
void kernel_signal_queue_cancel(
    const kernel_signal_queue_ticket_t *ticket);
int kernel_signal_queue_peek(int32_t target, uint32_t signal,
                             int thread_directed, void *signal_info);
int kernel_signal_queue_consume(int32_t target, uint32_t signal,
                                int thread_directed, void *signal_info,
                                int *same_signal_remains);
void kernel_signal_queue_purge(int32_t target, int thread_directed);
void kernel_signal_queue_purge_signal(int32_t target, uint32_t signal,
                                      int thread_directed);
void kernel_signal_queue_reset(void);
int kernel_signal_queue_update_timer_overrun(int32_t timer_id,
                                             int32_t overrun);

#endif
