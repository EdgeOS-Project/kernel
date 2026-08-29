/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent scheduler entry policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/process_runtime.h"
#include "sys/boottime.h"

#define SCHEDULER_LOAD_FSHIFT 11u
#define SCHEDULER_LOAD_FIXED_ONE (1u << SCHEDULER_LOAD_FSHIFT)
#define SCHEDULER_LOAD_INTERVAL_US 5000000u
#define SCHEDULER_LOAD_EXP_1 1884u
#define SCHEDULER_LOAD_EXP_5 2014u
#define SCHEDULER_LOAD_EXP_15 2037u

static volatile uint8_t g_scheduler_load_lock;
static uint64_t g_scheduler_load_last_update_us;
static uint64_t g_scheduler_load_averages[3];

static void scheduler_load_lock(void) {
    while (__atomic_test_and_set(&g_scheduler_load_lock, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("" ::: "memory");
}

static void scheduler_load_unlock(void) {
    __atomic_clear(&g_scheduler_load_lock, __ATOMIC_RELEASE);
}

static uint64_t scheduler_load_fixed_multiply(uint64_t left,
                                              uint64_t right) {
    if (!left || !right) return 0u;
    if (left > (UINT64_MAX - (SCHEDULER_LOAD_FIXED_ONE / 2u)) / right)
        return UINT64_MAX;
    return (left * right + SCHEDULER_LOAD_FIXED_ONE / 2u) >>
           SCHEDULER_LOAD_FSHIFT;
}

static uint64_t scheduler_load_fixed_power(uint64_t base,
                                           uint64_t exponent) {
    uint64_t result = SCHEDULER_LOAD_FIXED_ONE;

    while (exponent) {
        if (exponent & 1u)
            result = scheduler_load_fixed_multiply(result, base);
        exponent >>= 1u;
        if (exponent)
            base = scheduler_load_fixed_multiply(base, base);
    }
    return result;
}

static uint64_t scheduler_load_advance(uint64_t load, uint32_t active,
                                       uint32_t decay,
                                       uint64_t periods) {
    uint64_t factor;
    uint64_t active_fixed;
    uint64_t retained;
    uint64_t added;

    if (!periods) return load;
    factor = scheduler_load_fixed_power(decay, periods);
    active_fixed = (uint64_t)active * SCHEDULER_LOAD_FIXED_ONE;
    retained = scheduler_load_fixed_multiply(load, factor);
    added = scheduler_load_fixed_multiply(
        active_fixed, SCHEDULER_LOAD_FIXED_ONE - factor);
    return retained > UINT64_MAX - added ? UINT64_MAX : retained + added;
}

static uint32_t scheduler_load_active_tasks(void) {
    uint64_t online = kernel_arch_scheduler_online_cpu_mask();
    uint64_t active = 0u;

    /* Keep periodic accounting proportional to the number of CPUs. */
    if (!online) online = 1u;
    for (uint32_t cpu = 0; cpu < 64u; ++cpu) {
        kernel_scheduler_cpu_stats_t stats;

        if (!(online & (1ull << cpu)) ||
            kernel_arch_scheduler_cpu_stats(cpu, &stats) < 0)
            continue;
        active = active > UINT32_MAX - stats.nr_running ? UINT32_MAX :
                 active + stats.nr_running;
    }
    return (uint32_t)active;
}

void kernel_scheduler_load_tick(void) {
    uint64_t now_us = boottime_monotonic_us();
    uint64_t previous;
    uint64_t periods;
    uint32_t active;

    previous = __atomic_load_n(&g_scheduler_load_last_update_us,
                               __ATOMIC_ACQUIRE);
    if (previous && now_us >= previous &&
        now_us - previous < SCHEDULER_LOAD_INTERVAL_US)
        return;
    active = scheduler_load_active_tasks();
    scheduler_load_lock();
    if (!g_scheduler_load_last_update_us) {
        g_scheduler_load_last_update_us = now_us ? now_us : 1u;
        scheduler_load_unlock();
        return;
    }
    if (now_us <= g_scheduler_load_last_update_us) {
        scheduler_load_unlock();
        return;
    }
    periods = (now_us - g_scheduler_load_last_update_us) /
              SCHEDULER_LOAD_INTERVAL_US;
    if (!periods) {
        scheduler_load_unlock();
        return;
    }
    g_scheduler_load_averages[0] = scheduler_load_advance(
        g_scheduler_load_averages[0], active, SCHEDULER_LOAD_EXP_1,
        periods);
    g_scheduler_load_averages[1] = scheduler_load_advance(
        g_scheduler_load_averages[1], active, SCHEDULER_LOAD_EXP_5,
        periods);
    g_scheduler_load_averages[2] = scheduler_load_advance(
        g_scheduler_load_averages[2], active, SCHEDULER_LOAD_EXP_15,
        periods);
    g_scheduler_load_last_update_us +=
        periods * SCHEDULER_LOAD_INTERVAL_US;
    scheduler_load_unlock();
}

static uint32_t scheduler_load_hundredths(uint64_t fixed) {
    uint64_t value;

    if (fixed > (UINT64_MAX - SCHEDULER_LOAD_FIXED_ONE / 2u) / 100u)
        return UINT32_MAX;
    value = (fixed * 100u + SCHEDULER_LOAD_FIXED_ONE / 2u) >>
            SCHEDULER_LOAD_FSHIFT;
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

void kernel_scheduler_load_snapshot(uint32_t *one_hundredths,
                                    uint32_t *five_hundredths,
                                    uint32_t *fifteen_hundredths) {
    uint64_t averages[3];

    kernel_scheduler_load_tick();
    scheduler_load_lock();
    for (uint32_t index = 0; index < 3u; ++index)
        averages[index] = g_scheduler_load_averages[index];
    scheduler_load_unlock();
    if (one_hundredths)
        *one_hundredths = scheduler_load_hundredths(averages[0]);
    if (five_hundredths)
        *five_hundredths = scheduler_load_hundredths(averages[1]);
    if (fifteen_hundredths)
        *fifteen_hundredths = scheduler_load_hundredths(averages[2]);
}

static int scheduler_proc_append(char *buffer, uint32_t capacity,
                                 uint32_t *length, const char *text) {
    if (!buffer || !length || !text) return -1;
    while (*text) {
        if (*length + 1u >= capacity) return -1;
        buffer[(*length)++] = *text++;
    }
    buffer[*length] = 0;
    return 0;
}

static int scheduler_proc_append_u64(char *buffer, uint32_t capacity,
                                     uint32_t *length, uint64_t value) {
    char digits[24];
    uint32_t count = 0u;

    if (!value) digits[count++] = '0';
    while (value) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char digit[2] = { digits[--count], 0 };

        if (scheduler_proc_append(
                buffer, capacity, length, digit) < 0)
            return -1;
    }
    return 0;
}

static int scheduler_proc_append_s64(char *buffer, uint32_t capacity,
                                     uint32_t *length, int64_t value) {
    uint64_t magnitude;

    if (value >= 0)
        return scheduler_proc_append_u64(
            buffer, capacity, length, (uint64_t)value);
    if (scheduler_proc_append(buffer, capacity, length, "-") < 0)
        return -1;
    magnitude = (uint64_t)(-(value + 1)) + 1u;
    return scheduler_proc_append_u64(
        buffer, capacity, length, magnitude);
}

static int scheduler_proc_append_milliseconds(
        char *buffer, uint32_t capacity, uint32_t *length,
        uint64_t microseconds) {
    uint64_t fraction = (microseconds % 1000u) * 1000u;
    uint64_t divisor = 100000u;

    if (scheduler_proc_append_u64(
            buffer, capacity, length, microseconds / 1000u) < 0 ||
        scheduler_proc_append(buffer, capacity, length, ".") < 0)
        return -1;
    while (divisor) {
        char digit[2] = {
            (char)('0' + (fraction / divisor) % 10u), 0
        };

        if (scheduler_proc_append(
                buffer, capacity, length, digit) < 0)
            return -1;
        divisor /= 10u;
    }
    return 0;
}

static uint64_t scheduler_proc_microseconds_to_nanoseconds(uint64_t value) {
    return value > UINT64_MAX / 1000u ? UINT64_MAX : value * 1000u;
}

int kernel_scheduler_proc_task_render(int32_t tid, char *buffer,
                                      uint32_t capacity) {
    kernel_proc_task_view_t view;
    uint64_t execution_us;
    uint64_t switches;
    uint32_t threads = 0u;
    uint32_t length = 0u;
    int32_t thread_tid;
    int64_t priority;

    if (!buffer || !capacity ||
        kernel_proc_task_view_get(tid, &view) < 0)
        return -1;
    while (kernel_proc_thread_at(view.tgid, threads, &thread_tid) == 0)
        ++threads;
    if (!threads) threads = 1u;
    execution_us = view.usage.user_time_us >
                   UINT64_MAX - view.usage.sys_time_us ? UINT64_MAX :
                   view.usage.user_time_us + view.usage.sys_time_us;
    switches = view.usage.voluntary_ctxt_switches >
               UINT64_MAX - view.usage.involuntary_ctxt_switches ?
               UINT64_MAX : view.usage.voluntary_ctxt_switches +
                            view.usage.involuntary_ctxt_switches;
    priority = edge_linux_scheduler_policy_is_realtime(
                   view.scheduler.policy) ?
               99 - (int64_t)view.scheduler.priority :
               120 + (int64_t)view.scheduler.nice;

    if (scheduler_proc_append(buffer, capacity, &length, view.comm) < 0 ||
        scheduler_proc_append(buffer, capacity, &length, " (") < 0 ||
        scheduler_proc_append_s64(buffer, capacity, &length, view.tid) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
                              ", #threads: ") < 0 ||
        scheduler_proc_append_u64(buffer, capacity, &length, threads) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            ")\n---------------------------------------------------------\n"
            "se.vruntime                             : ") < 0 ||
        scheduler_proc_append_milliseconds(
            buffer, capacity, &length,
            view.scheduler_vruntime_us) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nse.sum_exec_runtime                     : ") < 0 ||
        scheduler_proc_append_milliseconds(
            buffer, capacity, &length, execution_us) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nse.nr_migrations                        : ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length,
            view.scheduler_migrations) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nnr_switches                             : ") < 0 ||
        scheduler_proc_append_u64(buffer, capacity, &length, switches) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nnr_voluntary_switches                   : ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length,
            view.usage.voluntary_ctxt_switches) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nnr_involuntary_switches                 : ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length,
            view.usage.involuntary_ctxt_switches) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nse.load.weight                          : ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length,
            (uint64_t)edge_linux_scheduler_nice_weight(
                view.scheduler.nice) * 1024u) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\npolicy                                  : ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length, view.scheduler.policy) < 0 ||
        scheduler_proc_append(buffer, capacity, &length,
            "\nprio                                    : ") < 0 ||
        scheduler_proc_append_s64(buffer, capacity, &length, priority) < 0 ||
        scheduler_proc_append(buffer, capacity, &length, "\n") < 0)
        return -1;
    return (int)length;
}

int kernel_scheduler_proc_task_schedstat(int32_t tid, char *buffer,
                                         uint32_t capacity) {
    kernel_proc_task_view_t view;
    uint64_t execution_us;
    uint64_t switches;
    uint32_t length = 0u;

    if (!buffer || !capacity ||
        kernel_proc_task_view_get(tid, &view) < 0)
        return -1;
    execution_us = view.usage.user_time_us >
                   UINT64_MAX - view.usage.sys_time_us ? UINT64_MAX :
                   view.usage.user_time_us + view.usage.sys_time_us;
    switches = view.usage.voluntary_ctxt_switches >
               UINT64_MAX - view.usage.involuntary_ctxt_switches ?
               UINT64_MAX : view.usage.voluntary_ctxt_switches +
                            view.usage.involuntary_ctxt_switches;
    if (scheduler_proc_append_u64(
            buffer, capacity, &length,
            scheduler_proc_microseconds_to_nanoseconds(execution_us)) < 0 ||
        scheduler_proc_append(buffer, capacity, &length, " ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length,
            scheduler_proc_microseconds_to_nanoseconds(
                view.scheduler_wait_us)) < 0 ||
        scheduler_proc_append(buffer, capacity, &length, " ") < 0 ||
        scheduler_proc_append_u64(buffer, capacity, &length, switches) < 0 ||
        scheduler_proc_append(buffer, capacity, &length, "\n") < 0)
        return -1;
    return (int)length;
}

int kernel_scheduler_proc_system_schedstat(char *buffer,
                                           uint32_t capacity) {
    uint64_t online;
    uint32_t length = 0u;
    uint32_t emitted = 0u;

    if (!buffer || !capacity) return -1;
    online = kernel_arch_scheduler_online_cpu_mask();
    if (!online) online = 1u;
    if (scheduler_proc_append(buffer, capacity, &length,
                              "version 15\ntimestamp ") < 0 ||
        scheduler_proc_append_u64(
            buffer, capacity, &length,
            boottime_monotonic_us() / 10000u) < 0 ||
        scheduler_proc_append(buffer, capacity, &length, "\n") < 0)
        return -1;
    for (uint32_t cpu = 0; cpu < 64u; ++cpu) {
        kernel_scheduler_cpu_stats_t stats;
        uint64_t execution_us;

        if (!(online & (1ull << cpu)) ||
            kernel_arch_scheduler_cpu_stats(cpu, &stats) < 0)
            continue;
        execution_us = stats.user_time_us >
                       UINT64_MAX - stats.system_time_us ? UINT64_MAX :
                       stats.user_time_us + stats.system_time_us;
        if (scheduler_proc_append(buffer, capacity, &length, "cpu") < 0 ||
            scheduler_proc_append_u64(buffer, capacity, &length, cpu) < 0 ||
            scheduler_proc_append(buffer, capacity, &length,
                                  " 0 0 0 0 0 0 ") < 0 ||
            scheduler_proc_append_u64(
                buffer, capacity, &length,
                scheduler_proc_microseconds_to_nanoseconds(execution_us)) < 0 ||
            scheduler_proc_append(buffer, capacity, &length, " ") < 0 ||
            scheduler_proc_append_u64(
                buffer, capacity, &length,
                scheduler_proc_microseconds_to_nanoseconds(
                    stats.runqueue_wait_us)) < 0 ||
            scheduler_proc_append(buffer, capacity, &length, " ") < 0 ||
            scheduler_proc_append_u64(
                buffer, capacity, &length, stats.context_switches) < 0 ||
            scheduler_proc_append(buffer, capacity, &length, "\n") < 0)
            return -1;
        ++emitted;
    }
    return emitted ? (int)length : -1;
}

int kernel_runtime_yield(void) {
    return arch_runtime_yield();
}

int kernel_runtime_wait_sequence(volatile uint64_t *sequence,
                                 uint64_t observed,
                                 uint64_t deadline_microseconds) {
    if (!sequence ||
        __atomic_load_n(sequence, __ATOMIC_ACQUIRE) != observed)
        return 1;
    return arch_runtime_wait_sequence(
        sequence, observed, deadline_microseconds);
}

void kernel_runtime_notify_sequence(volatile uint64_t *sequence) {
    if (sequence) arch_runtime_notify_sequence(sequence);
}

int kernel_runtime_contention_begin(void) {
    return arch_runtime_contention_begin();
}

void kernel_runtime_contention_end(int released) {
    arch_runtime_contention_end(released);
}

void kernel_runtime_fuse_notify(uint64_t description_identity) {
    arch_runtime_fuse_notify(description_identity);
}

void kernel_runtime_fuse_reply_wait(uint64_t description_identity) {
    arch_runtime_fuse_reply_wait(description_identity);
}

void kernel_runtime_fuse_reply_notify(uint64_t description_identity,
                                      uintptr_t context_token) {
    arch_runtime_fuse_reply_notify(description_identity, context_token);
}

int64_t kernel_scheduler_yield(void *user_registers) {
    return arch_scheduler_yield(user_registers);
}

int64_t kernel_current_sleep_until(uint64_t deadline_microseconds,
                                   uint64_t remaining_user,
                                   int write_remaining,
                                   int remaining_time32,
                                   void *user_registers) {
    if (boottime_monotonic_us() >= deadline_microseconds) return 0;
    return arch_current_sleep_until(
        deadline_microseconds, remaining_user,
        write_remaining, remaining_time32, user_registers);
}
