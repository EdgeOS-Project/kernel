/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux scheduling policy state.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SCHEDULER_POLICY_H
#define EDGEOS_KERNEL_SCHEDULER_POLICY_H

#include <stdint.h>

/*
 * Bound the time an equal-priority task awakened by input, IPC, or a futex
 * waits behind the current task.  Linux desktop workloads with many browser
 * workers need a sub-millisecond wakeup granularity to keep the display server
 * and compositor responsive.  A nonzero interval still lets a producer finish
 * short related event batches.
 */
#define EDGE_LINUX_SCHED_WAKEUP_GRANULARITY_US 500u
#define EDGE_LINUX_SCHED_MIGRATION_COST_US 500u
#define EDGE_LINUX_SCHED_MIN_GRANULARITY_US 750u
#define EDGE_LINUX_SCHED_TARGET_LATENCY_US 6000u
#define EDGE_LINUX_SCHED_RR_QUANTUM_US 10000u

#define EDGE_LINUX_SCHED_OTHER 0u
#define EDGE_LINUX_SCHED_FIFO 1u
#define EDGE_LINUX_SCHED_RR 2u
#define EDGE_LINUX_SCHED_BATCH 3u
#define EDGE_LINUX_SCHED_IDLE 5u
#define EDGE_LINUX_SCHED_DEADLINE 6u
#define EDGE_LINUX_SCHED_EXT 7u

#define EDGE_LINUX_SCHED_RESET_ON_FORK 0x40000000u

#define EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK (1ull << 0)
#define EDGE_LINUX_SCHED_FLAG_RECLAIM (1ull << 1)
#define EDGE_LINUX_SCHED_FLAG_DL_OVERRUN (1ull << 2)
#define EDGE_LINUX_SCHED_FLAG_KEEP_POLICY (1ull << 3)
#define EDGE_LINUX_SCHED_FLAG_KEEP_PARAMS (1ull << 4)
#define EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MIN (1ull << 5)
#define EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MAX (1ull << 6)
#define EDGE_LINUX_SCHED_FLAG_ALL ((1ull << 7) - 1u)

#define EDGE_LINUX_SCHED_ATTR_SIZE_VER0 48u
#define EDGE_LINUX_SCHED_ATTR_SIZE_VER1 56u
#define EDGE_LINUX_SCHED_UTIL_SCALE 1024u

typedef struct edge_linux_scheduler_state {
    uint64_t affinity_mask;
    uint64_t runtime;
    uint64_t deadline;
    uint64_t period;
    uint64_t flags;
    int32_t nice;
    uint32_t policy;
    uint32_t priority;
    uint32_t util_min;
    uint32_t util_max;
} edge_linux_scheduler_state_t;

typedef struct edge_linux_scheduler_entity {
    uint64_t fair_slice_runtime_us;
    uint64_t rr_remaining_us;
    uint64_t deadline_remaining_us;
    uint64_t deadline_absolute_us;
    uint64_t deadline_replenish_us;
    uint8_t deadline_throttled;
    uint8_t deadline_overrun_pending;
} edge_linux_scheduler_entity_t;

enum {
    EDGE_SCHEDULER_ACCOUNT_PREEMPT = 1u << 0,
    EDGE_SCHEDULER_ACCOUNT_THROTTLED = 1u << 1,
    EDGE_SCHEDULER_ACCOUNT_OVERRUN = 1u << 2,
};

enum {
    EDGE_SCHEDULER_UPDATE_AFFINITY = 1u << 0,
    EDGE_SCHEDULER_UPDATE_POLICY = 1u << 1,
    EDGE_SCHEDULER_UPDATE_NICE = 1u << 2,
    EDGE_SCHEDULER_UPDATE_UTILIZATION = 1u << 3,
};

#define EDGE_SCHEDULER_UPDATE_ALL \
    (EDGE_SCHEDULER_UPDATE_AFFINITY | EDGE_SCHEDULER_UPDATE_POLICY | \
     EDGE_SCHEDULER_UPDATE_NICE | EDGE_SCHEDULER_UPDATE_UTILIZATION)

typedef struct kernel_scheduler_target {
    int32_t tid;
    int32_t tgid;
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    edge_linux_scheduler_state_t state;
} kernel_scheduler_target_t;

typedef struct kernel_scheduler_state_commit {
    kernel_scheduler_target_t target;
    edge_linux_scheduler_state_t requested;
    uint32_t update_mask;
} kernel_scheduler_state_commit_t;

void edge_linux_scheduler_state_init(edge_linux_scheduler_state_t *state,
                                     uint64_t online_mask);
void edge_linux_scheduler_state_inherit(
    edge_linux_scheduler_state_t *child,
    const edge_linux_scheduler_state_t *parent);
void edge_linux_scheduler_state_apply_updates(
    edge_linux_scheduler_state_t *destination,
    const edge_linux_scheduler_state_t *requested, uint32_t update_mask);
int edge_linux_scheduler_state_equal(
    const edge_linux_scheduler_state_t *left,
    const edge_linux_scheduler_state_t *right);
int edge_linux_scheduler_policy_is_realtime(uint32_t policy);
int edge_linux_scheduler_policy_is_normal(uint32_t policy);
int edge_linux_scheduler_policy_is_fair(uint32_t policy);
void edge_linux_scheduler_entity_init(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t now_us);
void edge_linux_scheduler_entity_inherit(
    edge_linux_scheduler_entity_t *child,
    const edge_linux_scheduler_state_t *child_state, uint64_t now_us);
void edge_linux_scheduler_entity_begin_slice(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state);
uint64_t edge_linux_scheduler_entity_slice_runtime_us(
    const edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t live_runtime_us);
uint32_t edge_linux_scheduler_entity_account(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state,
    uint64_t runtime_us, uint64_t now_us);
int edge_linux_scheduler_entity_runnable(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t now_us);
int edge_linux_scheduler_entity_precedes(
    const edge_linux_scheduler_state_t *candidate,
    edge_linux_scheduler_entity_t *candidate_entity,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    edge_linux_scheduler_entity_t *current_entity,
    uint64_t current_vruntime_us,
    uint64_t average_vruntime_us, uint32_t runnable_tasks,
    uint64_t now_us);
int edge_linux_scheduler_entity_tick_preempts(
    const edge_linux_scheduler_state_t *candidate,
    edge_linux_scheduler_entity_t *candidate_entity,
    const edge_linux_scheduler_state_t *current,
    edge_linux_scheduler_entity_t *current_entity,
    uint64_t current_runtime_us, uint64_t now_us);
int edge_linux_scheduler_state_compare(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current);
int edge_linux_scheduler_cache_affinity_order(
    uint16_t candidate_last_cpu_plus_one,
    uint16_t current_last_cpu_plus_one, uint32_t cpu);
uint32_t edge_linux_scheduler_wake_cpu(
    uint64_t allowed_mask, uint16_t last_cpu_plus_one,
    uint32_t current_cpu);
uint32_t edge_linux_scheduler_local_wake_cpu(
    uint64_t allowed_mask, uint16_t last_cpu_plus_one,
    uint32_t current_cpu);
uint32_t edge_linux_scheduler_least_loaded_wake_cpu(
    uint64_t allowed_mask, uint16_t last_cpu_plus_one,
    uint32_t current_cpu, const uint32_t *cpu_loads,
    uint32_t cpu_count);
uint32_t edge_linux_scheduler_active_balance_cpu(
    uint64_t allowed_mask, uint32_t current_cpu,
    const uint32_t *cpu_loads, uint32_t cpu_count);
int edge_linux_scheduler_fair_migration_ready(
    uint16_t last_cpu_plus_one, uint32_t current_cpu,
    uint64_t runnable_since_us, uint64_t now_us);
int edge_linux_scheduler_wakeup_preempts(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current);
int edge_linux_scheduler_wakeup_preempts_after(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_runtime_us, uint64_t minimum_granularity_us);
int edge_linux_scheduler_tick_preempts(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current);
uint64_t edge_linux_scheduler_vruntime_delta(
    const edge_linux_scheduler_state_t *state, uint64_t runtime_us);
uint64_t edge_linux_scheduler_rebase_vruntime(
    uint64_t vruntime_us, uint64_t source_min_vruntime_us,
    uint64_t destination_min_vruntime_us);
uint32_t edge_linux_scheduler_nice_weight(int32_t nice);
uint64_t edge_linux_scheduler_request_slice_us(uint32_t runnable_tasks);
uint64_t edge_linux_scheduler_virtual_deadline_us(
    const edge_linux_scheduler_state_t *state, uint64_t vruntime_us,
    uint32_t runnable_tasks);
uint64_t edge_linux_scheduler_vruntime_average_add(
    uint64_t average_vruntime_us, uint32_t previous_tasks,
    uint64_t vruntime_us);
uint64_t edge_linux_scheduler_vruntime_weighted_average_add(
    uint64_t average_vruntime_us, uint64_t previous_weight,
    const edge_linux_scheduler_state_t *state, uint64_t vruntime_us,
    uint64_t *total_weight);
int edge_linux_scheduler_eevdf_precedes(
    const edge_linux_scheduler_state_t *candidate,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_vruntime_us,
    uint64_t average_vruntime_us, uint32_t runnable_tasks);
int edge_linux_scheduler_fair_precedes(
    const edge_linux_scheduler_state_t *candidate,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_vruntime_us);
int edge_linux_scheduler_fair_wakeup_preempts(
    const edge_linux_scheduler_state_t *candidate,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_vruntime_us,
    uint64_t current_runtime_us,
    uint64_t minimum_granularity_us);

#endif
