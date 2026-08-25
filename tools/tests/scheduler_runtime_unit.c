/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent scheduler runtime unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/process_runtime.h"

static int g_failures;
static uint64_t g_now;
static uint64_t g_deadline;
static uint64_t g_remaining_user;
static int g_write_remaining;
static void *g_user_registers;
static int g_runtime_yield_calls;
static int g_scheduler_yield_calls;
static int g_sleep_calls;
static uint64_t g_fuse_notify_identity;
static uint64_t g_fuse_wait_identity;
static uint64_t g_fuse_reply_identity;
static uintptr_t g_fuse_reply_token;

int kernel_proc_task_view_get(int32_t tid, kernel_proc_task_view_t *view) {
    if (tid != 7 || !view) return -1;
    memset(view, 0, sizeof(*view));
    view->tid = 7;
    view->tgid = 7;
    strcpy(view->comm, "worker");
    view->scheduler.policy = EDGE_LINUX_SCHED_OTHER;
    view->scheduler.nice = 0;
    view->scheduler_vruntime_us = 2500u;
    view->scheduler_wait_us = 4000u;
    view->scheduler_migrations = 3u;
    view->usage.user_time_us = 1000u;
    view->usage.sys_time_us = 2000u;
    view->usage.voluntary_ctxt_switches = 5u;
    view->usage.involuntary_ctxt_switches = 6u;
    return 0;
}

int kernel_proc_thread_at(int32_t tgid, uint32_t ordinal, int32_t *tid_out) {
    if (tgid != 7 || ordinal >= 2u || !tid_out) return -1;
    *tid_out = ordinal ? 8 : 7;
    return 0;
}

int kernel_proc_task_load_snapshot(uint32_t *running_out,
                                   uint32_t *total_out) {
    if (!running_out || !total_out) return -1;
    *running_out = 2u;
    *total_out = 3u;
    return 0;
}

uint64_t kernel_arch_scheduler_online_cpu_mask(void) {
    return 1u;
}

int kernel_arch_scheduler_cpu_stats(
        uint32_t cpu, kernel_scheduler_cpu_stats_t *stats) {
    if (cpu != 0u || !stats) return -1;
    memset(stats, 0, sizeof(*stats));
    stats->user_time_us = 1000u;
    stats->system_time_us = 2000u;
    stats->idle_time_us = 7000u;
    stats->runqueue_wait_us = 4000u;
    stats->context_switches = 11u;
    stats->nr_running = 2u;
    return 0;
}

int kernel_arch_scheduler_state_commit(
        const kernel_scheduler_state_commit_t *commit) {
    (void)commit;
    return -1;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

uint64_t boottime_monotonic_us(void) {
    return g_now;
}

int arch_runtime_yield(void) {
    ++g_runtime_yield_calls;
    return 17;
}

int arch_runtime_contention_begin(void) {
    return 0;
}

void arch_runtime_contention_end(int released) {
    (void)released;
}

void arch_runtime_fuse_notify(uint64_t description_identity) {
    g_fuse_notify_identity = description_identity;
}

void arch_runtime_fuse_reply_wait(uint64_t description_identity) {
    g_fuse_wait_identity = description_identity;
}

void arch_runtime_fuse_reply_notify(uint64_t description_identity,
                                    uintptr_t context_token) {
    g_fuse_reply_identity = description_identity;
    g_fuse_reply_token = context_token;
}

int64_t arch_scheduler_yield(void *user_registers) {
    ++g_scheduler_yield_calls;
    g_user_registers = user_registers;
    return 18;
}

int64_t arch_current_sleep_until(uint64_t deadline_microseconds,
                                 uint64_t remaining_user,
                                 int write_remaining,
                                 int remaining_time32,
                                 void *user_registers) {
    ++g_sleep_calls;
    g_deadline = deadline_microseconds;
    g_remaining_user = remaining_user;
    g_write_remaining = write_remaining;
    (void)remaining_time32;
    g_user_registers = user_registers;
    return 19;
}

int main(void) {
    void *registers = (void *)(uintptr_t)0x1234u;
    char proc_buffer[4096];
    uint32_t load_one;
    uint32_t load_five;
    uint32_t load_fifteen;

    expect_true("runtime yield dispatch",
                kernel_runtime_yield() == 17 &&
                g_runtime_yield_calls == 1);
    expect_true("scheduler yield dispatch",
                kernel_scheduler_yield(registers) == 18 &&
                g_scheduler_yield_calls == 1 &&
                g_user_registers == registers);
    kernel_runtime_fuse_notify(41u);
    kernel_runtime_fuse_reply_wait(42u);
    kernel_runtime_fuse_reply_notify(43u, (uintptr_t)0x5678u);
    expect_true("FUSE runtime dispatch",
                g_fuse_notify_identity == 41u &&
                g_fuse_wait_identity == 42u &&
                g_fuse_reply_identity == 43u &&
                g_fuse_reply_token == (uintptr_t)0x5678u);

    g_now = 100;
    g_sleep_calls = 0;
    expect_true("expired sleep fast path",
                kernel_current_sleep_until(100, 11, 1, 0, registers) == 0 &&
                g_sleep_calls == 0);

    g_now = 99;
    expect_true("pending sleep dispatch",
                kernel_current_sleep_until(100, 11, 1, 0, registers) == 19 &&
                g_sleep_calls == 1 && g_deadline == 100 &&
                g_remaining_user == 11 && g_write_remaining == 1 &&
                g_user_registers == registers);

    expect_true("proc sched rendering",
                kernel_scheduler_proc_task_render(
                    7, proc_buffer, sizeof(proc_buffer)) > 0 &&
                strstr(proc_buffer, "worker (7, #threads: 2)") != 0 &&
                strstr(proc_buffer,
                       "se.vruntime                             : 2.500000") != 0 &&
                strstr(proc_buffer,
                       "se.nr_migrations                        : 3") != 0 &&
                strstr(proc_buffer,
                       "nr_switches                             : 11") != 0 &&
                strstr(proc_buffer,
                       "se.load.weight                          : 1048576") != 0 &&
                strstr(proc_buffer, "se.avg.") == 0);
    expect_true("proc schedstat rendering",
                kernel_scheduler_proc_task_schedstat(
                    7, proc_buffer, sizeof(proc_buffer)) > 0 &&
                strcmp(proc_buffer, "3000000 4000000 11\n") == 0);
    expect_true("system proc schedstat rendering",
                kernel_scheduler_proc_system_schedstat(
                    proc_buffer, sizeof(proc_buffer)) > 0 &&
                strstr(proc_buffer, "version 15\ntimestamp 0\n") ==
                    proc_buffer &&
                strstr(proc_buffer,
                       "cpu0 0 0 0 0 0 0 3000000 4000000 11\n") != 0);
    expect_true("proc scheduler rejects missing task",
                kernel_scheduler_proc_task_render(
                    99, proc_buffer, sizeof(proc_buffer)) < 0);

    g_now = 1u;
    kernel_scheduler_load_tick();
    g_now = 5000001u;
    kernel_scheduler_load_snapshot(
        &load_one, &load_five, &load_fifteen);
    expect_true("Linux load averages use independent decay windows",
                load_one == 16u && load_five == 3u &&
                load_fifteen == 1u);
    g_now = 10000001u;
    kernel_scheduler_load_snapshot(
        &load_one, &load_five, &load_fifteen);
    expect_true("Linux load averages accumulate runnable history",
                load_one == 31u && load_five == 7u &&
                load_fifteen == 2u);

    if (g_failures) return 1;
    puts("scheduler_runtime_unit: PASS");
    return 0;
}
