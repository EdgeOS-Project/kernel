/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-independent queued siginfo storage.  Standard signals
 * coalesce, while realtime signals preserve every queued record in order.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "kernel/signal_queue.h"
#include "string.h"
#include "sys/spinlock.h"

typedef struct kernel_signal_queue_record {
    uint8_t used;
    uint8_t thread_directed;
    uint16_t signal;
    int32_t target;
    uint64_t sequence;
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE];
} kernel_signal_queue_record_t;

static kernel_signal_queue_record_t
    g_signal_queue[EDGE_RUNTIME_SIGNAL_QUEUE_SIZE];
static uint64_t g_signal_queue_sequence;
static spinlock_t g_signal_queue_lock;

static int32_t kernel_signal_info_read_i32(const uint8_t *information,
                                           uint32_t offset) {
    int32_t value;
    memcpy(&value, information + offset, sizeof(value));
    return value;
}

static void kernel_signal_info_write_i32(uint8_t *information,
                                         uint32_t offset, int32_t value) {
    memcpy(information + offset, &value, sizeof(value));
}

static void kernel_signal_info_write_u32(uint8_t *information,
                                         uint32_t offset, uint32_t value) {
    memcpy(information + offset, &value, sizeof(value));
}

static void kernel_signal_info_write_u64(uint8_t *information,
                                         uint32_t offset, uint64_t value) {
    memcpy(information + offset, &value, sizeof(value));
}

void kernel_signal_info_build_sender(void *signal_info, uint32_t signal,
                                     int32_t code, int32_t sender_pid,
                                     uint32_t sender_uid, uint64_t value) {
    uint8_t *information = (uint8_t *)signal_info;
    if (!information) return;
    memset(information, 0, KERNEL_SIGNAL_INFO_SIZE);
    kernel_signal_info_write_u32(information, 0u, signal);
    kernel_signal_info_write_i32(information, 8u, code);
    kernel_signal_info_write_i32(information, 16u, sender_pid);
    kernel_signal_info_write_u32(information, 20u, sender_uid);
    kernel_signal_info_write_u64(information, 24u, value);
}

void kernel_signal_info_build_child(void *signal_info, uint32_t signal,
                                    int32_t code, int32_t child_pid,
                                    uint32_t child_uid, int32_t status,
                                    uint64_t user_ticks,
                                    uint64_t system_ticks) {
    uint8_t *information = (uint8_t *)signal_info;
    if (!information) return;
    memset(information, 0, KERNEL_SIGNAL_INFO_SIZE);
    kernel_signal_info_write_u32(information, 0u, signal);
    kernel_signal_info_write_i32(information, 8u, code);
    kernel_signal_info_write_i32(information, 16u, child_pid);
    kernel_signal_info_write_u32(information, 20u, child_uid);
    kernel_signal_info_write_i32(information, 24u, status);
    kernel_signal_info_write_u64(information, 32u, user_ticks);
    kernel_signal_info_write_u64(information, 40u, system_ticks);
}

void kernel_signal_info_build_timer(void *signal_info, uint32_t signal,
                                    int32_t timer_id, int32_t overrun,
                                    uint64_t value) {
    uint8_t *information = (uint8_t *)signal_info;
    if (!information) return;
    memset(information, 0, KERNEL_SIGNAL_INFO_SIZE);
    kernel_signal_info_write_u32(information, 0u, signal);
    kernel_signal_info_write_i32(information, 8u, -2); /* SI_TIMER */
    kernel_signal_info_write_i32(information, 16u, timer_id);
    kernel_signal_info_write_i32(information, 20u, overrun);
    kernel_signal_info_write_u64(information, 24u, value);
}

void kernel_signal_info_build_seccomp(void *signal_info, uint32_t signal,
                                      int32_t error, uint64_t call_address,
                                      int32_t syscall_number,
                                      uint32_t audit_architecture) {
    uint8_t *information = (uint8_t *)signal_info;
    if (!information) return;
    memset(information, 0, KERNEL_SIGNAL_INFO_SIZE);
    kernel_signal_info_write_u32(information, 0u, signal);
    kernel_signal_info_write_i32(information, 4u, error);
    kernel_signal_info_write_i32(information, 8u, 1); /* SYS_SECCOMP */
    kernel_signal_info_write_u64(information, 16u, call_address);
    kernel_signal_info_write_i32(information, 24u, syscall_number);
    kernel_signal_info_write_u32(information, 28u, audit_architecture);
}

static int kernel_signal_queue_record_matches(
    const kernel_signal_queue_record_t *record, int32_t target,
    uint32_t signal, int thread_directed) {
    return record && record->used && record->target == target &&
           record->signal == signal &&
           record->thread_directed == (uint8_t)(thread_directed != 0);
}

static kernel_signal_queue_record_t *kernel_signal_queue_oldest_locked(
    int32_t target, uint32_t signal, int thread_directed) {
    kernel_signal_queue_record_t *selected = 0;
    for (uint32_t index = 0; index < EDGE_RUNTIME_SIGNAL_QUEUE_SIZE;
         ++index) {
        kernel_signal_queue_record_t *record = &g_signal_queue[index];
        if (!kernel_signal_queue_record_matches(
                record, target, signal, thread_directed))
            continue;
        if (!selected || record->sequence < selected->sequence)
            selected = record;
    }
    return selected;
}

int kernel_signal_queue_enqueue_ticket(
    int32_t target, uint32_t signal, int thread_directed,
    const void *signal_info, kernel_signal_queue_ticket_t *ticket) {
    kernel_signal_queue_record_t *free_record = 0;
    uint64_t irq_flags;
    int result = 0;
    if (ticket) ticket->sequence = 0;
    if (target <= 0 || !signal || signal > 64u || !signal_info)
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    for (uint32_t index = 0; index < EDGE_RUNTIME_SIGNAL_QUEUE_SIZE;
         ++index) {
        kernel_signal_queue_record_t *record = &g_signal_queue[index];
        if (signal < 32u && kernel_signal_queue_record_matches(
                record, target, signal, thread_directed))
            goto out;
        if (!record->used && !free_record) free_record = record;
    }
    if (!free_record) {
        result = -EDGE_LINUX_EAGAIN;
        goto out;
    }
    memset(free_record, 0, sizeof(*free_record));
    free_record->used = 1u;
    free_record->thread_directed = (uint8_t)(thread_directed != 0);
    free_record->signal = (uint16_t)signal;
    free_record->target = target;
    ++g_signal_queue_sequence;
    if (!g_signal_queue_sequence) ++g_signal_queue_sequence;
    free_record->sequence = g_signal_queue_sequence;
    if (ticket) ticket->sequence = free_record->sequence;
    memcpy(free_record->information, signal_info,
           sizeof(free_record->information));
out:
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
    return result;
}

int kernel_signal_queue_enqueue(int32_t target, uint32_t signal,
                                int thread_directed,
                                const void *signal_info) {
    return kernel_signal_queue_enqueue_ticket(
        target, signal, thread_directed, signal_info, 0);
}

void kernel_signal_queue_cancel(
    const kernel_signal_queue_ticket_t *ticket) {
    uint64_t irq_flags;
    if (!ticket || !ticket->sequence) return;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    for (uint32_t index = 0; index < EDGE_RUNTIME_SIGNAL_QUEUE_SIZE;
         ++index) {
        kernel_signal_queue_record_t *record = &g_signal_queue[index];
        if (record->used && record->sequence == ticket->sequence) {
            memset(record, 0, sizeof(*record));
            break;
        }
    }
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
}

int kernel_signal_queue_peek(int32_t target, uint32_t signal,
                             int thread_directed, void *signal_info) {
    kernel_signal_queue_record_t *selected;
    uint64_t irq_flags;
    int result = 0;
    if (!signal_info || target <= 0 || !signal || signal > 64u) return 0;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    selected = kernel_signal_queue_oldest_locked(
        target, signal, thread_directed);
    if (selected) {
        memcpy(signal_info, selected->information,
               sizeof(selected->information));
        result = 1;
    }
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
    return result;
}

int kernel_signal_queue_consume(int32_t target, uint32_t signal,
                                int thread_directed, void *signal_info,
                                int *same_signal_remains) {
    kernel_signal_queue_record_t *selected;
    uint64_t irq_flags;
    int remains = 0;
    int result = 0;
    if (same_signal_remains) *same_signal_remains = 0;
    if (target <= 0 || !signal || signal > 64u) return 0;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    selected = kernel_signal_queue_oldest_locked(
        target, signal, thread_directed);
    if (selected) {
        if (signal_info)
            memcpy(signal_info, selected->information,
                   sizeof(selected->information));
        memset(selected, 0, sizeof(*selected));
        remains = kernel_signal_queue_oldest_locked(
                      target, signal, thread_directed) != 0;
        result = 1;
    }
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
    if (same_signal_remains) *same_signal_remains = remains;
    return result;
}

void kernel_signal_queue_purge(int32_t target, int thread_directed) {
    uint64_t irq_flags;
    if (target <= 0) return;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    for (uint32_t index = 0; index < EDGE_RUNTIME_SIGNAL_QUEUE_SIZE;
         ++index) {
        kernel_signal_queue_record_t *record = &g_signal_queue[index];
        if (record->used && record->target == target &&
            record->thread_directed == (uint8_t)(thread_directed != 0))
            memset(record, 0, sizeof(*record));
    }
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
}

void kernel_signal_queue_purge_signal(int32_t target, uint32_t signal,
                                      int thread_directed) {
    uint64_t irq_flags;
    if (target <= 0 || !signal || signal > 64u) return;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    for (uint32_t index = 0; index < EDGE_RUNTIME_SIGNAL_QUEUE_SIZE;
         ++index) {
        kernel_signal_queue_record_t *record = &g_signal_queue[index];
        if (kernel_signal_queue_record_matches(
                record, target, signal, thread_directed))
            memset(record, 0, sizeof(*record));
    }
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
}

void kernel_signal_queue_reset(void) {
    uint64_t irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    memset(g_signal_queue, 0, sizeof(g_signal_queue));
    g_signal_queue_sequence = 0;
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
}

int kernel_signal_queue_update_timer_overrun(int32_t timer_id,
                                             int32_t overrun) {
    uint64_t irq_flags;
    int result = -EDGE_LINUX_ENOENT;
    irq_flags = spin_lock_irqsave(&g_signal_queue_lock);
    for (uint32_t index = 0; index < EDGE_RUNTIME_SIGNAL_QUEUE_SIZE;
         ++index) {
        kernel_signal_queue_record_t *record = &g_signal_queue[index];
        if (!record->used ||
            kernel_signal_info_read_i32(record->information, 8u) != -2 ||
            kernel_signal_info_read_i32(record->information, 16u) != timer_id)
            continue;
        kernel_signal_info_write_i32(record->information, 20u, overrun);
        result = 0;
        break;
    }
    spin_unlock_irqrestore(&g_signal_queue_lock, irq_flags);
    return result;
}
