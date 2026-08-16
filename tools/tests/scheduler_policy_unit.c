/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent scheduler policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/process_runtime.h"
#include "kernel/scheduler_policy.h"
#include "kernel/timer_policy.h"

static int g_failures;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

uint64_t kernel_arch_scheduler_online_cpu_mask(void) {
    return 1u;
}

int kernel_proc_task_view_get(int32_t tid, kernel_proc_task_view_t *view) {
    (void)tid;
    (void)view;
    return -1;
}

int kernel_arch_scheduler_state_commit(
    const kernel_scheduler_state_commit_t *commit) {
    (void)commit;
    return -1;
}

static void test_idle_policy_is_low_weight_fair(void) {
    edge_linux_scheduler_state_t normal;
    edge_linux_scheduler_state_t idle;
    uint64_t normal_delta;
    uint64_t idle_delta;

    edge_linux_scheduler_state_init(&normal, 1u);
    idle = normal;
    idle.policy = EDGE_LINUX_SCHED_IDLE;

    expect_true("normal policy is fair",
                edge_linux_scheduler_policy_is_fair(normal.policy));
    expect_true("idle policy is fair",
                edge_linux_scheduler_policy_is_fair(idle.policy));
    expect_true("idle is the lowest fair class",
                edge_linux_scheduler_state_compare(&idle, &normal) < 0 &&
                edge_linux_scheduler_state_compare(&normal, &idle) > 0);
    expect_true("idle does not precede a normal task",
                !edge_linux_scheduler_fair_precedes(
                    &idle, 10u, &normal, 11u));
    expect_true("normal wakeup preempts an idle task",
                edge_linux_scheduler_fair_wakeup_preempts(
                    &normal, 100u, &idle, 0u,
                    EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US,
                    EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US));
    expect_true("idle wakeup does not preempt a normal task",
                !edge_linux_scheduler_fair_wakeup_preempts(
                    &idle, 0u, &normal, 100u,
                    EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US,
                    EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US));

    normal_delta = edge_linux_scheduler_vruntime_delta(&normal, 1000u);
    idle_delta = edge_linux_scheduler_vruntime_delta(&idle, 1000u);
    expect_true("idle receives a low fair weight",
                normal_delta == 1000u &&
                idle_delta == 341334u);
}

static void test_exact_nice_weights(void) {
    edge_linux_scheduler_state_t state;

    edge_linux_scheduler_state_init(&state, 1u);
    expect_true("nice minus twenty weight",
                edge_linux_scheduler_nice_weight(-20) == 88761u);
    expect_true("nice zero weight",
                edge_linux_scheduler_nice_weight(0) == 1024u);
    expect_true("nice nineteen weight",
                edge_linux_scheduler_nice_weight(19) == 15u);
    state.nice = -20;
    expect_true("nice minus twenty runtime scale",
                edge_linux_scheduler_vruntime_delta(&state, 1000u) == 12u);
    state.nice = 19;
    expect_true("nice nineteen runtime scale",
                edge_linux_scheduler_vruntime_delta(&state, 1000u) ==
                    68267u);
}

static void test_eevdf_selection(void) {
    edge_linux_scheduler_state_t normal;
    edge_linux_scheduler_state_t favored;
    edge_linux_scheduler_state_t realtime;
    edge_linux_scheduler_state_t idle;
    uint64_t total_weight = 0;
    uint64_t average;

    edge_linux_scheduler_state_init(&normal, 1u);
    favored = normal;
    favored.nice = -10;
    expect_true("eevdf request slice scales with load",
                edge_linux_scheduler_request_slice_us(1u) == 6000u &&
                edge_linux_scheduler_request_slice_us(4u) == 1500u &&
                edge_linux_scheduler_request_slice_us(32u) == 750u);
    expect_true("eligible task precedes ineligible task",
                edge_linux_scheduler_eevdf_precedes(
                    &normal, 100u, &normal, 200u, 150u, 2u));
    expect_true("earlier virtual deadline wins among eligible tasks",
                edge_linux_scheduler_eevdf_precedes(
                    &favored, 100u, &normal, 100u, 100u, 2u));
    realtime = normal;
    realtime.policy = EDGE_LINUX_SCHED_FIFO;
    realtime.priority = 1u;
    expect_true("higher class overrides fair deadline",
                edge_linux_scheduler_eevdf_precedes(
                    &realtime, 1000u, &normal, 0u, 0u, 2u));
    expect_true("running average avoids sum overflow",
                edge_linux_scheduler_vruntime_average_add(
                    UINT64_MAX - 10u, 1u, UINT64_MAX) ==
                    UINT64_MAX - 5u);
    idle = normal;
    idle.policy = EDGE_LINUX_SCHED_IDLE;
    average = edge_linux_scheduler_vruntime_weighted_average_add(
        0u, 0u, &normal, 1000u, &total_weight);
    average = edge_linux_scheduler_vruntime_weighted_average_add(
        average, total_weight, &idle, 0u, &total_weight);
    expect_true("weighted average preserves normal task eligibility",
                average == 998u && total_weight == 1027u);
    expect_true("migration preserves positive fair lag",
                edge_linux_scheduler_rebase_vruntime(
                    1400u, 1000u, 9000u) == 9400u);
    expect_true("migration preserves negative fair lag",
                edge_linux_scheduler_rebase_vruntime(
                    700u, 1000u, 9000u) == 8700u);
    expect_true("migration saturates positive fair lag",
                edge_linux_scheduler_rebase_vruntime(
                    UINT64_MAX, 0u, 1u) == UINT64_MAX);
    expect_true("migration clamps negative fair lag",
                edge_linux_scheduler_rebase_vruntime(
                    0u, UINT64_MAX, 10u) == 0u);
}

static void test_realtime_still_preempts_fair(void) {
    edge_linux_scheduler_state_t normal;
    edge_linux_scheduler_state_t realtime;

    edge_linux_scheduler_state_init(&normal, 1u);
    realtime = normal;
    realtime.policy = EDGE_LINUX_SCHED_FIFO;
    realtime.priority = 1u;
    expect_true("realtime remains a higher class",
                edge_linux_scheduler_state_compare(
                    &realtime, &normal) > 0 &&
                edge_linux_scheduler_state_compare(
                    &normal, &realtime) < 0);
}

static void test_shared_timer_policy(void) {
    expect_true("shared scheduler timer uses 100 Hz",
                EDGE_KERNEL_TIMER_HZ == 100u);
    expect_true("shared scheduler timer tick is ten milliseconds",
                EDGE_KERNEL_TIMER_TICK_US == 10000u);
    expect_true("display polling preserves twenty milliseconds",
                EDGE_KERNEL_TIMER_20MS_TICKS == 2u);
    expect_true("deferred polling preserves fifty milliseconds",
                EDGE_KERNEL_TIMER_50MS_TICKS == 5u);
    expect_true("network polling preserves one hundred milliseconds",
                EDGE_KERNEL_TIMER_100MS_TICKS == 10u);
    expect_true("console cursor preserves five hundred milliseconds",
                EDGE_KERNEL_TIMER_500MS_TICKS == 50u);
    expect_true("CPU zero owns global timer work",
                edge_kernel_timer_runs_global_work(0u));
    expect_true("secondary CPUs only account local scheduler time",
                !edge_kernel_timer_runs_global_work(1u) &&
                !edge_kernel_timer_runs_global_work(255u));
}

static void test_smp_cache_affinity_and_targeted_wakeup(void) {
    const uint32_t balanced_loads[4] = {1u, 1u, 1u, 1u};
    const uint32_t busy_current_loads[4] = {3u, 0u, 1u, 1u};
    const uint32_t one_task_difference[4] = {2u, 1u, 2u, 2u};

    expect_true("local task precedes equal remote task",
                edge_linux_scheduler_cache_affinity_order(
                    3u, 2u, 2u) > 0);
    expect_true("remote task follows equal local task",
                edge_linux_scheduler_cache_affinity_order(
                    2u, 3u, 2u) < 0);
    expect_true("unknown placement remains neutral",
                edge_linux_scheduler_cache_affinity_order(
                    0u, 0u, 2u) == 0);
    expect_true("wakeup returns to the previous allowed CPU",
                edge_linux_scheduler_wake_cpu(
                    0x0fu, 3u, 0u) == 2u);
    expect_true("new wakeup remains on the current allowed CPU",
                edge_linux_scheduler_wake_cpu(
                    0x0fu, 0u, 1u) == 1u);
    expect_true("wakeup selects one allowed fallback CPU",
                edge_linux_scheduler_wake_cpu(
                    0x0au, 1u, 0u) == 1u);
    expect_true("empty wakeup mask has no target",
                edge_linux_scheduler_wake_cpu(
                    0u, 1u, 0u) == UINT32_MAX);
    expect_true("local wakeup avoids a remote notification",
                edge_linux_scheduler_local_wake_cpu(
                    0x0fu, 3u, 1u) == 1u);
    expect_true("local wakeup preserves affinity on fallback",
                edge_linux_scheduler_local_wake_cpu(
                    0x0du, 3u, 1u) == 2u);
    expect_true("empty local wakeup mask has no target",
                edge_linux_scheduler_local_wake_cpu(
                    0u, 1u, 0u) == UINT32_MAX);
    expect_true("balanced wakeup preserves cache affinity",
                edge_linux_scheduler_least_loaded_wake_cpu(
                    0x0fu, 3u, 0u, balanced_loads, 4u) == 2u);
    expect_true("busy wakeup selects an allowed idle CPU",
                edge_linux_scheduler_least_loaded_wake_cpu(
                    0x0fu, 1u, 0u, busy_current_loads, 4u) == 1u);
    expect_true("load-aware wakeup respects affinity",
                edge_linux_scheduler_least_loaded_wake_cpu(
                    0x0du, 1u, 0u, busy_current_loads, 4u) == 2u);
    expect_true("active balance moves sustained work to an idle CPU",
                edge_linux_scheduler_active_balance_cpu(
                    0x0fu, 0u, busy_current_loads, 4u) == 1u);
    expect_true("active balance respects affinity",
                edge_linux_scheduler_active_balance_cpu(
                    0x0du, 0u, busy_current_loads, 4u) == 2u);
    expect_true("active balance preserves a one-task cache-local gap",
                edge_linux_scheduler_active_balance_cpu(
                    0x0fu, 0u, one_task_difference, 4u) == 0u);
    expect_true("active balance preserves an already balanced CPU",
                edge_linux_scheduler_active_balance_cpu(
                    0x0fu, 2u, balanced_loads, 4u) == 2u);
    expect_true("local fair task can run immediately",
                edge_linux_scheduler_fair_migration_ready(
                    3u, 2u, 1000u, 1001u));
    expect_true("new fair wakeup stays cache local",
                !edge_linux_scheduler_fair_migration_ready(
                    3u, 1u, 1000u,
                    1000u + EDGE_LINUX_SCHED_MIGRATION_COST_US - 1u));
    expect_true("fair task becomes stealable after migration cost",
                edge_linux_scheduler_fair_migration_ready(
                    3u, 1u, 1000u,
                    1000u + EDGE_LINUX_SCHED_MIGRATION_COST_US));
    expect_true("unplaced fair task can run on any CPU",
                edge_linux_scheduler_fair_migration_ready(
                    0u, 1u, 1000u, 1001u));
}

static void test_realtime_and_deadline_entities(void) {
    edge_linux_scheduler_state_t rr;
    edge_linux_scheduler_state_t deadline;
    edge_linux_scheduler_state_t later_deadline;
    edge_linux_scheduler_entity_t rr_entity;
    edge_linux_scheduler_entity_t deadline_entity;
    edge_linux_scheduler_entity_t later_entity;
    uint32_t result;

    edge_linux_scheduler_state_init(&rr, 1u);
    rr.policy = EDGE_LINUX_SCHED_RR;
    rr.priority = 10u;
    edge_linux_scheduler_entity_init(&rr_entity, &rr, 100u);
    expect_true("RR starts with the shared quantum",
                rr_entity.rr_remaining_us ==
                    EDGE_LINUX_SCHED_RR_QUANTUM_US);
    result = edge_linux_scheduler_entity_account(
        &rr_entity, &rr, 4000u, 4100u);
    expect_true("RR accounts partial runtime",
                result == 0 && rr_entity.rr_remaining_us == 6000u);
    result = edge_linux_scheduler_entity_account(
        &rr_entity, &rr, 6000u, 10100u);
    expect_true("RR expires at the shared quantum",
                result == EDGE_SCHEDULER_ACCOUNT_PREEMPT &&
                rr_entity.rr_remaining_us == 0u);
    expect_true("RR replenishes before its next dispatch",
                edge_linux_scheduler_entity_runnable(
                    &rr_entity, &rr, 10100u) &&
                rr_entity.rr_remaining_us ==
                    EDGE_LINUX_SCHED_RR_QUANTUM_US);

    edge_linux_scheduler_state_init(&deadline, 1u);
    deadline.policy = EDGE_LINUX_SCHED_DEADLINE;
    deadline.runtime = 2000000u;
    deadline.deadline = 5000000u;
    deadline.period = 10000000u;
    deadline.flags = EDGE_LINUX_SCHED_FLAG_DL_OVERRUN;
    edge_linux_scheduler_entity_init(&deadline_entity, &deadline, 100u);
    expect_true("deadline entity converts parameters to runtime units",
                deadline_entity.deadline_remaining_us == 2000u &&
                deadline_entity.deadline_absolute_us == 5100u &&
                deadline_entity.deadline_replenish_us == 10100u);
    result = edge_linux_scheduler_entity_account(
        &deadline_entity, &deadline, 2000u, 2100u);
    expect_true("deadline runtime exhaustion throttles and records overrun",
                result == (EDGE_SCHEDULER_ACCOUNT_PREEMPT |
                           EDGE_SCHEDULER_ACCOUNT_THROTTLED |
                           EDGE_SCHEDULER_ACCOUNT_OVERRUN) &&
                deadline_entity.deadline_throttled &&
                deadline_entity.deadline_overrun_pending);
    expect_true("deadline remains throttled before replenishment",
                !edge_linux_scheduler_entity_runnable(
                    &deadline_entity, &deadline, 10099u));
    expect_true("deadline replenishes at its period boundary",
                edge_linux_scheduler_entity_runnable(
                    &deadline_entity, &deadline, 10100u) &&
                deadline_entity.deadline_remaining_us == 2000u &&
                deadline_entity.deadline_absolute_us == 15100u);

    later_deadline = deadline;
    edge_linux_scheduler_entity_init(&later_entity, &later_deadline, 11000u);
    expect_true("EDF selects the earliest absolute deadline",
                edge_linux_scheduler_entity_precedes(
                    &deadline, &deadline_entity, 0u,
                    &later_deadline, &later_entity, 0u,
                    0u, 1u, 10100u));
}

static void test_fair_slice_survives_mode_accounting(void) {
    edge_linux_scheduler_state_t normal;
    edge_linux_scheduler_entity_t entity;

    edge_linux_scheduler_state_init(&normal, 1u);
    edge_linux_scheduler_entity_init(&entity, &normal, 0u);
    (void)edge_linux_scheduler_entity_account(
        &entity, &normal, 400u, 400u);
    (void)edge_linux_scheduler_entity_account(
        &entity, &normal, 350u, 750u);
    expect_true("fair slice accumulates across mode boundaries",
                edge_linux_scheduler_entity_slice_runtime_us(
                    &entity, &normal, 250u) == 1000u);
    edge_linux_scheduler_entity_begin_slice(&entity, &normal);
    expect_true("fair slice resets only on dispatch",
                edge_linux_scheduler_entity_slice_runtime_us(
                    &entity, &normal, 250u) == 250u);
}

int main(void) {
    test_idle_policy_is_low_weight_fair();
    test_exact_nice_weights();
    test_eevdf_selection();
    test_realtime_still_preempts_fair();
    test_shared_timer_policy();
    test_smp_cache_affinity_and_targeted_wakeup();
    test_realtime_and_deadline_entities();
    test_fair_slice_survives_mode_accounting();
    if (g_failures) return 1;
    puts("scheduler_policy_unit: PASS");
    return 0;
}
