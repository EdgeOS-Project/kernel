/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux scheduling policy helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/scheduler_policy.h"
#include "kernel/process_runtime.h"

void edge_linux_scheduler_state_init(edge_linux_scheduler_state_t *state,
                                     uint64_t online_mask) {
    if (!state) return;
    state->affinity_mask = online_mask ? online_mask : 1u;
    state->runtime = 0;
    state->deadline = 0;
    state->period = 0;
    state->flags = 0;
    state->nice = 0;
    state->policy = EDGE_LINUX_SCHED_OTHER;
    state->priority = 0;
    state->util_min = 0;
    state->util_max = EDGE_LINUX_SCHED_UTIL_SCALE;
}

void edge_linux_scheduler_state_inherit(
    edge_linux_scheduler_state_t *child,
    const edge_linux_scheduler_state_t *parent) {
    if (!child || !parent) return;
    *child = *parent;
    if (!(parent->flags & EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK)) return;

    if (edge_linux_scheduler_policy_is_realtime(parent->policy) ||
        parent->policy == EDGE_LINUX_SCHED_DEADLINE) {
        child->policy = EDGE_LINUX_SCHED_OTHER;
        child->priority = 0;
        child->runtime = 0;
        child->deadline = 0;
        child->period = 0;
    }
    if (child->nice < 0) child->nice = 0;
    child->flags &= ~EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK;
}

void edge_linux_scheduler_state_apply_updates(
    edge_linux_scheduler_state_t *destination,
    const edge_linux_scheduler_state_t *requested, uint32_t update_mask) {
    if (!destination || !requested) return;
    if (update_mask & EDGE_SCHEDULER_UPDATE_AFFINITY)
        destination->affinity_mask = requested->affinity_mask;
    if (update_mask & EDGE_SCHEDULER_UPDATE_POLICY) {
        destination->policy = requested->policy;
        destination->priority = requested->priority;
        destination->runtime = requested->runtime;
        destination->deadline = requested->deadline;
        destination->period = requested->period;
        destination->flags = requested->flags;
    }
    if (update_mask & EDGE_SCHEDULER_UPDATE_NICE)
        destination->nice = requested->nice;
    if (update_mask & EDGE_SCHEDULER_UPDATE_UTILIZATION) {
        destination->util_min = requested->util_min;
        destination->util_max = requested->util_max;
    }
}

int edge_linux_scheduler_state_equal(
    const edge_linux_scheduler_state_t *left,
    const edge_linux_scheduler_state_t *right) {
    if (!left || !right) return 0;
    return left->affinity_mask == right->affinity_mask &&
           left->runtime == right->runtime &&
           left->deadline == right->deadline &&
           left->period == right->period &&
           left->flags == right->flags &&
           left->nice == right->nice &&
           left->policy == right->policy &&
           left->priority == right->priority &&
           left->util_min == right->util_min &&
           left->util_max == right->util_max;
}

uint64_t kernel_scheduler_online_cpu_mask(void) {
    uint64_t online = kernel_arch_scheduler_online_cpu_mask();
    return online ? online : 1u;
}

int kernel_scheduler_state_get(int32_t tid,
                               edge_linux_scheduler_state_t *state) {
    kernel_proc_task_view_t view;
    if (!state || tid <= 0) return -1;
    if (kernel_proc_task_view_get(tid, &view) < 0 ||
        view.state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    *state = view.scheduler;
    return 0;
}

int kernel_scheduler_state_set(const kernel_scheduler_target_t *target,
                               const edge_linux_scheduler_state_t *requested,
                               uint32_t update_mask) {
    kernel_scheduler_state_commit_t commit;
    if (!target || !requested || target->tid <= 0 || target->tgid <= 0 ||
        !update_mask || (update_mask & ~EDGE_SCHEDULER_UPDATE_ALL))
        return -1;
    commit.target = *target;
    commit.requested = *requested;
    commit.update_mask = update_mask;
    return kernel_arch_scheduler_state_commit(&commit);
}

int kernel_process_nice_set(const kernel_process_control_t *process,
                            int8_t nice_value) {
    kernel_scheduler_target_t target;
    edge_linux_scheduler_state_t requested;
    if (!process) return -1;
    target.tid = process->tid;
    target.tgid = process->tgid;
    target.uid = process->uid;
    target.euid = process->euid;
    target.suid = process->suid;
    target.state = process->scheduler;
    requested = target.state;
    requested.nice = nice_value;
    return kernel_scheduler_state_set(
        &target, &requested, EDGE_SCHEDULER_UPDATE_NICE);
}

int edge_linux_scheduler_policy_is_realtime(uint32_t policy) {
    return policy == EDGE_LINUX_SCHED_FIFO ||
           policy == EDGE_LINUX_SCHED_RR;
}

int edge_linux_scheduler_policy_is_normal(uint32_t policy) {
    return policy == EDGE_LINUX_SCHED_OTHER ||
           policy == EDGE_LINUX_SCHED_BATCH;
}

int edge_linux_scheduler_policy_is_fair(uint32_t policy) {
    return edge_linux_scheduler_policy_is_normal(policy) ||
           policy == EDGE_LINUX_SCHED_IDLE;
}

static int scheduler_class(const edge_linux_scheduler_state_t *state) {
    if (!state) return 0;
    if (state->policy == EDGE_LINUX_SCHED_DEADLINE) return 3;
    if (edge_linux_scheduler_policy_is_realtime(state->policy)) return 2;
    return edge_linux_scheduler_policy_is_fair(state->policy) ? 1 : 0;
}

int edge_linux_scheduler_state_compare(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current) {
    int candidate_class = scheduler_class(candidate);
    int current_class = scheduler_class(current);
    if (candidate_class != current_class)
        return candidate_class > current_class ? 1 : -1;
    if (candidate_class == 2 && candidate->priority != current->priority)
        return candidate->priority > current->priority ? 1 : -1;
    if (candidate_class == 3 && candidate->deadline != current->deadline)
        return candidate->deadline < current->deadline ? 1 : -1;
    if (candidate_class == 1 &&
        (candidate->policy == EDGE_LINUX_SCHED_IDLE) !=
        (current->policy == EDGE_LINUX_SCHED_IDLE))
        return candidate->policy == EDGE_LINUX_SCHED_IDLE ? -1 : 1;
    return 0;
}

int edge_linux_scheduler_cache_affinity_order(
    uint16_t candidate_last_cpu_plus_one,
    uint16_t current_last_cpu_plus_one, uint32_t cpu) {
    int candidate_local;
    int current_local;

    if (cpu >= 64u) return 0;
    candidate_local = candidate_last_cpu_plus_one == (uint16_t)(cpu + 1u);
    current_local = current_last_cpu_plus_one == (uint16_t)(cpu + 1u);
    if (candidate_local == current_local) return 0;
    return candidate_local ? 1 : -1;
}

uint32_t edge_linux_scheduler_wake_cpu(
    uint64_t allowed_mask, uint16_t last_cpu_plus_one,
    uint32_t current_cpu) {
    uint32_t last_cpu;

    if (!allowed_mask) return UINT32_MAX;
    if (last_cpu_plus_one) {
        last_cpu = (uint32_t)last_cpu_plus_one - 1u;
        if (last_cpu < 64u &&
            (allowed_mask & (1ULL << last_cpu)))
            return last_cpu;
    }
    if (current_cpu < 64u &&
        (allowed_mask & (1ULL << current_cpu)))
        return current_cpu;
    for (uint32_t cpu = 0; cpu < 64u; ++cpu)
        if (allowed_mask & (1ULL << cpu)) return cpu;
    return UINT32_MAX;
}

uint32_t edge_linux_scheduler_local_wake_cpu(
    uint64_t allowed_mask, uint16_t last_cpu_plus_one,
    uint32_t current_cpu) {
    uint32_t last_cpu;

    if (!allowed_mask) return UINT32_MAX;
    /*
     * A task made runnable by the current CPU can begin running without an
     * inter-processor notification. Prefer that path for high-frequency IPC
     * and futex wakeups. If affinity excludes the current CPU, preserve cache
     * locality by returning to the previous allowed CPU before falling back.
     */
    if (current_cpu < 64u &&
        (allowed_mask & (UINT64_C(1) << current_cpu)))
        return current_cpu;
    if (last_cpu_plus_one) {
        last_cpu = (uint32_t)last_cpu_plus_one - 1u;
        if (last_cpu < 64u &&
            (allowed_mask & (UINT64_C(1) << last_cpu)))
            return last_cpu;
    }
    for (uint32_t cpu = 0; cpu < 64u; ++cpu)
        if (allowed_mask & (UINT64_C(1) << cpu)) return cpu;
    return UINT32_MAX;
}

uint32_t edge_linux_scheduler_least_loaded_wake_cpu(
    uint64_t allowed_mask, uint16_t last_cpu_plus_one,
    uint32_t current_cpu, const uint32_t *cpu_loads,
    uint32_t cpu_count) {
    uint32_t preferred;
    uint32_t least_loaded = UINT32_MAX;
    uint32_t least_load = UINT32_MAX;

    preferred = edge_linux_scheduler_wake_cpu(
        allowed_mask, last_cpu_plus_one, current_cpu);
    if (!cpu_loads || !cpu_count) return preferred;
    if (cpu_count > 64u) cpu_count = 64u;
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu) {
        if (!(allowed_mask & (1ULL << cpu))) continue;
        if (cpu_loads[cpu] < least_load) {
            least_load = cpu_loads[cpu];
            least_loaded = cpu;
        }
    }
    if (least_loaded == UINT32_MAX) return UINT32_MAX;
    /* Keep cache affinity only while it is also work-conserving. */
    if (preferred < cpu_count &&
        (allowed_mask & (1ULL << preferred)) &&
        cpu_loads[preferred] == least_load)
        return preferred;
    return least_loaded;
}

uint32_t edge_linux_scheduler_active_balance_cpu(
    uint64_t allowed_mask, uint32_t current_cpu,
    const uint32_t *cpu_loads, uint32_t cpu_count) {
    uint32_t current_load;
    uint32_t least_loaded;
    uint32_t least_load;

    if (!allowed_mask || !cpu_loads || !cpu_count ||
        current_cpu >= cpu_count || current_cpu >= 64u ||
        !(allowed_mask & (UINT64_C(1) << current_cpu)))
        return current_cpu;
    if (cpu_count > 64u) cpu_count = 64u;
    current_load = cpu_loads[current_cpu];
    least_loaded = current_cpu;
    least_load = current_load;
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu) {
        if (!(allowed_mask & (UINT64_C(1) << cpu)) ||
            cpu_loads[cpu] >= least_load)
            continue;
        least_loaded = cpu;
        least_load = cpu_loads[cpu];
    }

    /*
     * Moving one runnable task changes both queues.  A one-task difference is
     * already balanced and moving it would only exchange the busy CPU while
     * discarding cache locality.  Migrate sustained fair work only when the
     * source has at least two more runnable tasks than the destination.
     */
    if (least_loaded != current_cpu &&
        current_load > least_load + 1u)
        return least_loaded;
    return current_cpu;
}

int edge_linux_scheduler_fair_migration_ready(
    uint16_t last_cpu_plus_one, uint32_t current_cpu,
    uint64_t runnable_since_us, uint64_t now_us) {
    uint32_t last_cpu;

    if (!last_cpu_plus_one || current_cpu >= 64u)
        return 1;
    last_cpu = (uint32_t)last_cpu_plus_one - 1u;
    if (last_cpu == current_cpu || last_cpu >= 64u ||
        !runnable_since_us || now_us < runnable_since_us)
        return 1;
    return now_us - runnable_since_us >=
        EDGE_LINUX_SCHED_MIGRATION_COST_US;
}

static uint64_t scheduler_nanoseconds_to_microseconds(uint64_t nanoseconds) {
    if (!nanoseconds) return 0;
    return nanoseconds / 1000u + (nanoseconds % 1000u != 0u);
}

static uint64_t scheduler_saturating_add(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static uint64_t scheduler_saturating_multiply(uint64_t value,
                                              uint64_t factor) {
    if (!value || !factor) return 0;
    return value > UINT64_MAX / factor ? UINT64_MAX : value * factor;
}

static void scheduler_deadline_parameters(
    const edge_linux_scheduler_state_t *state,
    uint64_t *runtime_us, uint64_t *deadline_us, uint64_t *period_us) {
    uint64_t runtime = scheduler_nanoseconds_to_microseconds(
        state ? state->runtime : 0);
    uint64_t deadline = scheduler_nanoseconds_to_microseconds(
        state ? state->deadline : 0);
    uint64_t period = scheduler_nanoseconds_to_microseconds(
        state && state->period ? state->period :
        (state ? state->deadline : 0));

    if (runtime_us) *runtime_us = runtime;
    if (deadline_us) *deadline_us = deadline;
    if (period_us) *period_us = period;
}

void edge_linux_scheduler_entity_init(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t now_us) {
    uint64_t runtime_us;
    uint64_t deadline_us;
    uint64_t period_us;

    if (!entity) return;
    entity->fair_slice_runtime_us = 0;
    entity->rr_remaining_us = EDGE_LINUX_SCHED_RR_QUANTUM_US;
    entity->deadline_remaining_us = 0;
    entity->deadline_absolute_us = 0;
    entity->deadline_replenish_us = 0;
    entity->deadline_throttled = 0;
    entity->deadline_overrun_pending = 0;
    if (!state || state->policy != EDGE_LINUX_SCHED_DEADLINE) return;
    scheduler_deadline_parameters(state, &runtime_us, &deadline_us,
                                  &period_us);
    if (!runtime_us || !deadline_us || !period_us ||
        runtime_us > deadline_us || deadline_us > period_us) {
        entity->deadline_throttled = 1;
        return;
    }
    entity->deadline_remaining_us = runtime_us;
    entity->deadline_absolute_us = scheduler_saturating_add(
        now_us, deadline_us);
    entity->deadline_replenish_us = scheduler_saturating_add(
        now_us, period_us);
}

void edge_linux_scheduler_entity_inherit(
    edge_linux_scheduler_entity_t *child,
    const edge_linux_scheduler_state_t *child_state, uint64_t now_us) {
    edge_linux_scheduler_entity_init(child, child_state, now_us);
}

void edge_linux_scheduler_entity_begin_slice(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state) {
    if (!entity || !state) return;
    if (edge_linux_scheduler_policy_is_fair(state->policy))
        entity->fair_slice_runtime_us = 0;
}

uint64_t edge_linux_scheduler_entity_slice_runtime_us(
    const edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t live_runtime_us) {
    if (!entity || !state ||
        !edge_linux_scheduler_policy_is_fair(state->policy))
        return live_runtime_us;
    return entity->fair_slice_runtime_us > UINT64_MAX - live_runtime_us ?
        UINT64_MAX : entity->fair_slice_runtime_us + live_runtime_us;
}

static void scheduler_deadline_replenish(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t now_us) {
    uint64_t runtime_us;
    uint64_t deadline_us;
    uint64_t period_us;
    uint64_t periods;
    uint64_t advance;

    if (!entity || !state || state->policy != EDGE_LINUX_SCHED_DEADLINE)
        return;
    scheduler_deadline_parameters(state, &runtime_us, &deadline_us,
                                  &period_us);
    if (!runtime_us || !deadline_us || !period_us ||
        runtime_us > deadline_us || deadline_us > period_us) {
        entity->deadline_throttled = 1;
        return;
    }
    if (!entity->deadline_absolute_us ||
        !entity->deadline_replenish_us) {
        edge_linux_scheduler_entity_init(entity, state, now_us);
        return;
    }
    if (now_us < entity->deadline_replenish_us) return;
    periods = (now_us - entity->deadline_replenish_us) / period_us + 1u;
    advance = scheduler_saturating_multiply(period_us, periods);
    entity->deadline_replenish_us = scheduler_saturating_add(
        entity->deadline_replenish_us, advance);
    entity->deadline_absolute_us = scheduler_saturating_add(
        entity->deadline_absolute_us, advance);
    entity->deadline_remaining_us = runtime_us;
    entity->deadline_throttled = 0;
}

uint32_t edge_linux_scheduler_entity_account(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state,
    uint64_t runtime_us, uint64_t now_us) {
    uint32_t result = 0;

    if (!entity || !state || !runtime_us) return 0;
    if (edge_linux_scheduler_policy_is_fair(state->policy)) {
        entity->fair_slice_runtime_us =
            entity->fair_slice_runtime_us > UINT64_MAX - runtime_us ?
            UINT64_MAX : entity->fair_slice_runtime_us + runtime_us;
        return 0;
    }
    if (state->policy == EDGE_LINUX_SCHED_RR) {
        if (!entity->rr_remaining_us)
            entity->rr_remaining_us = EDGE_LINUX_SCHED_RR_QUANTUM_US;
        if (runtime_us >= entity->rr_remaining_us) {
            entity->rr_remaining_us = 0;
            return EDGE_SCHEDULER_ACCOUNT_PREEMPT;
        }
        entity->rr_remaining_us -= runtime_us;
        return 0;
    }
    if (state->policy != EDGE_LINUX_SCHED_DEADLINE) return 0;
    scheduler_deadline_replenish(entity, state, now_us);
    if (entity->deadline_throttled)
        return EDGE_SCHEDULER_ACCOUNT_PREEMPT |
               EDGE_SCHEDULER_ACCOUNT_THROTTLED;
    if (runtime_us < entity->deadline_remaining_us) {
        entity->deadline_remaining_us -= runtime_us;
        return 0;
    }
    entity->deadline_remaining_us = 0;
    entity->deadline_throttled = 1;
    result = EDGE_SCHEDULER_ACCOUNT_PREEMPT |
             EDGE_SCHEDULER_ACCOUNT_THROTTLED;
    if (state->flags & EDGE_LINUX_SCHED_FLAG_DL_OVERRUN) {
        entity->deadline_overrun_pending = 1;
        result |= EDGE_SCHEDULER_ACCOUNT_OVERRUN;
    }
    return result;
}

int edge_linux_scheduler_entity_runnable(
    edge_linux_scheduler_entity_t *entity,
    const edge_linux_scheduler_state_t *state, uint64_t now_us) {
    if (!entity || !state) return 0;
    if (state->policy == EDGE_LINUX_SCHED_RR &&
        !entity->rr_remaining_us)
        entity->rr_remaining_us = EDGE_LINUX_SCHED_RR_QUANTUM_US;
    if (state->policy != EDGE_LINUX_SCHED_DEADLINE) return 1;
    scheduler_deadline_replenish(entity, state, now_us);
    return !entity->deadline_throttled &&
           entity->deadline_remaining_us != 0u;
}

int edge_linux_scheduler_entity_precedes(
    const edge_linux_scheduler_state_t *candidate,
    edge_linux_scheduler_entity_t *candidate_entity,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    edge_linux_scheduler_entity_t *current_entity,
    uint64_t current_vruntime_us,
    uint64_t average_vruntime_us, uint32_t runnable_tasks,
    uint64_t now_us) {
    int candidate_class;
    int current_class;

    if (!candidate || !current) return 0;
    candidate_class = scheduler_class(candidate);
    current_class = scheduler_class(current);
    if (candidate_class != current_class)
        return candidate_class > current_class;
    if (candidate_class == 3) {
        scheduler_deadline_replenish(candidate_entity, candidate, now_us);
        scheduler_deadline_replenish(current_entity, current, now_us);
        if (!candidate_entity || !current_entity) return 0;
        return candidate_entity->deadline_absolute_us <
               current_entity->deadline_absolute_us;
    }
    if (candidate_class == 2) {
        if (candidate->priority != current->priority)
            return candidate->priority > current->priority;
        return 0;
    }
    return edge_linux_scheduler_eevdf_precedes(
        candidate, candidate_vruntime_us, current, current_vruntime_us,
        average_vruntime_us, runnable_tasks);
}

int edge_linux_scheduler_entity_tick_preempts(
    const edge_linux_scheduler_state_t *candidate,
    edge_linux_scheduler_entity_t *candidate_entity,
    const edge_linux_scheduler_state_t *current,
    edge_linux_scheduler_entity_t *current_entity,
    uint64_t current_runtime_us, uint64_t now_us) {
    int candidate_class;
    int current_class;

    if (!candidate || !current) return 0;
    candidate_class = scheduler_class(candidate);
    current_class = scheduler_class(current);
    if (candidate_class != current_class)
        return candidate_class > current_class;
    if (candidate_class == 3) {
        scheduler_deadline_replenish(candidate_entity, candidate, now_us);
        scheduler_deadline_replenish(current_entity, current, now_us);
        if (!candidate_entity || !current_entity) return 0;
        if (current_runtime_us >= current_entity->deadline_remaining_us)
            return 1;
        return candidate_entity->deadline_absolute_us <
               current_entity->deadline_absolute_us;
    }
    if (candidate_class == 2) {
        if (candidate->priority != current->priority)
            return candidate->priority > current->priority;
        return current->policy == EDGE_LINUX_SCHED_RR &&
               current_entity &&
               current_runtime_us >= current_entity->rr_remaining_us;
    }
    return candidate_class == 1;
}

int edge_linux_scheduler_wakeup_preempts(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current) {
    int order = edge_linux_scheduler_state_compare(candidate, current);
    if (order != 0) return order > 0;
    if (!candidate || !current) return 0;
    /*
     * Preserve a minimum execution granularity between equal-priority normal
     * tasks.  Immediately switching to a peer after every pipe, futex, or Unix
     * socket wakeup creates ping-pong scheduling and can suspend a producer
     * between related messages.  X11 makes the failure especially visible: a
     * synthetic key press can reach Xorg, preempt its producer, and autorepeat
     * before the matching release is sent.  A higher scheduling class still
     * preempts above; equal peers rotate at the next scheduler tick or when the
     * current task blocks, matching Linux's wakeup-granularity contract.
     */
    return 0;
}

int edge_linux_scheduler_wakeup_preempts_after(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_runtime_us, uint64_t minimum_granularity_us) {
    int order = edge_linux_scheduler_state_compare(candidate, current);

    if (order != 0) return order > 0;
    if (!candidate || !current || !minimum_granularity_us ||
        current_runtime_us < minimum_granularity_us)
        return 0;
    /*
     * Equal-priority normal tasks use wakeup preemption only after the
     * current task has consumed a minimum runtime.  This approximates the
     * Linux wakeup-granularity contract without requiring architecture code
     * to duplicate scheduling policy or preempt a FIFO/RR task incorrectly.
     */
    return edge_linux_scheduler_policy_is_normal(candidate->policy) &&
           edge_linux_scheduler_policy_is_normal(current->policy);
}

int edge_linux_scheduler_tick_preempts(
    const edge_linux_scheduler_state_t *candidate,
    const edge_linux_scheduler_state_t *current) {
    int order = edge_linux_scheduler_state_compare(candidate, current);
    if (order != 0) return order > 0;
    if (!candidate || !current) return 0;
    return current->policy != EDGE_LINUX_SCHED_FIFO;
}

uint32_t edge_linux_scheduler_nice_weight(int32_t nice) {
    static const uint32_t weights[40] = {
        88761u, 71755u, 56483u, 46273u, 36291u,
        29154u, 23254u, 18705u, 14949u, 11916u,
         9548u,  7620u,  6100u,  4904u,  3906u,
         3121u,  2501u,  1991u,  1586u,  1277u,
         1024u,   820u,   655u,   526u,   423u,
          335u,   272u,   215u,   172u,   137u,
          110u,    87u,    70u,    56u,    45u,
           36u,    29u,    23u,    18u,    15u
    };

    if (nice < -20) nice = -20;
    if (nice > 19) nice = 19;
    return weights[nice + 20];
}

static uint64_t scheduler_scale_runtime(uint64_t runtime_us,
                                        uint32_t weight) {
    uint64_t quotient;
    uint64_t remainder;
    uint64_t scaled;
    uint64_t fraction;

    if (!runtime_us || !weight) return 0;
    quotient = runtime_us / weight;
    remainder = runtime_us % weight;
    if (quotient > UINT64_MAX / 1024u) return UINT64_MAX;
    scaled = quotient * 1024u;
    fraction = (remainder * 1024u + weight - 1u) / weight;
    return scaled > UINT64_MAX - fraction ? UINT64_MAX : scaled + fraction;
}

uint64_t edge_linux_scheduler_vruntime_delta(
    const edge_linux_scheduler_state_t *state, uint64_t runtime_us) {
    uint32_t weight;

    if (!runtime_us) return 0;
    weight = state && state->policy == EDGE_LINUX_SCHED_IDLE ? 3u :
             edge_linux_scheduler_nice_weight(state ? state->nice : 0);
    runtime_us = scheduler_scale_runtime(runtime_us, weight);
    return runtime_us ? runtime_us : 1u;
}

uint64_t edge_linux_scheduler_rebase_vruntime(
    uint64_t vruntime_us, uint64_t source_min_vruntime_us,
    uint64_t destination_min_vruntime_us) {
    uint64_t distance;

    /*
     * Per-CPU fair clocks do not share an absolute origin. Preserve the
     * entity's lag relative to its source queue when it moves to another CPU.
     * Copying the absolute value can make an ordinary sleeper appear seconds
     * ahead of every entity on the destination queue after load balancing.
     */
    if (vruntime_us >= source_min_vruntime_us) {
        distance = vruntime_us - source_min_vruntime_us;
        return destination_min_vruntime_us > UINT64_MAX - distance ?
            UINT64_MAX : destination_min_vruntime_us + distance;
    }
    distance = source_min_vruntime_us - vruntime_us;
    return distance >= destination_min_vruntime_us ?
        0u : destination_min_vruntime_us - distance;
}

uint64_t edge_linux_scheduler_request_slice_us(uint32_t runnable_tasks) {
    uint64_t slice;

    if (!runnable_tasks) runnable_tasks = 1u;
    slice = EDGE_LINUX_SCHED_TARGET_LATENCY_US / runnable_tasks;
    if (slice < EDGE_LINUX_SCHED_MIN_GRANULARITY_US)
        slice = EDGE_LINUX_SCHED_MIN_GRANULARITY_US;
    if (slice > EDGE_LINUX_SCHED_TARGET_LATENCY_US)
        slice = EDGE_LINUX_SCHED_TARGET_LATENCY_US;
    return slice;
}

uint64_t edge_linux_scheduler_virtual_deadline_us(
    const edge_linux_scheduler_state_t *state, uint64_t vruntime_us,
    uint32_t runnable_tasks) {
    uint64_t request = edge_linux_scheduler_request_slice_us(runnable_tasks);
    uint64_t virtual_request =
        edge_linux_scheduler_vruntime_delta(state, request);

    return vruntime_us > UINT64_MAX - virtual_request ? UINT64_MAX :
           vruntime_us + virtual_request;
}

uint64_t edge_linux_scheduler_vruntime_average_add(
    uint64_t average_vruntime_us, uint32_t previous_tasks,
    uint64_t vruntime_us) {
    uint64_t distance;
    uint64_t adjustment;
    uint64_t divisor = (uint64_t)previous_tasks + 1u;

    if (!previous_tasks) return vruntime_us;
    if (vruntime_us >= average_vruntime_us) {
        distance = vruntime_us - average_vruntime_us;
        adjustment = distance / divisor;
        return average_vruntime_us + adjustment;
    }
    distance = average_vruntime_us - vruntime_us;
    adjustment = distance / divisor;
    return average_vruntime_us - adjustment;
}

uint64_t edge_linux_scheduler_vruntime_weighted_average_add(
    uint64_t average_vruntime_us, uint64_t previous_weight,
    const edge_linux_scheduler_state_t *state, uint64_t vruntime_us,
    uint64_t *total_weight) {
    uint64_t weight = state && state->policy == EDGE_LINUX_SCHED_IDLE ? 3u :
                      edge_linux_scheduler_nice_weight(
                          state ? state->nice : 0);
    uint64_t combined;
    uint64_t distance;
    uint64_t quotient;
    uint64_t remainder;
    uint64_t adjustment;

    if (!previous_weight) {
        if (total_weight) *total_weight = weight;
        return vruntime_us;
    }
    if (previous_weight > UINT64_MAX - weight) {
        if (total_weight) *total_weight = UINT64_MAX;
        return average_vruntime_us;
    }
    combined = previous_weight + weight;
    distance = vruntime_us >= average_vruntime_us ?
               vruntime_us - average_vruntime_us :
               average_vruntime_us - vruntime_us;
    quotient = distance / combined;
    remainder = distance % combined;
    adjustment = quotient * weight + (remainder * weight) / combined;
    if (total_weight) *total_weight = combined;
    return vruntime_us >= average_vruntime_us ?
           average_vruntime_us + adjustment :
           average_vruntime_us - adjustment;
}

int edge_linux_scheduler_eevdf_precedes(
    const edge_linux_scheduler_state_t *candidate,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_vruntime_us,
    uint64_t average_vruntime_us, uint32_t runnable_tasks) {
    uint64_t candidate_deadline;
    uint64_t current_deadline;
    int candidate_eligible;
    int current_eligible;
    int order = edge_linux_scheduler_state_compare(candidate, current);

    if (order != 0) return order > 0;
    if (!candidate || !current) return 0;
    if (!edge_linux_scheduler_policy_is_fair(candidate->policy) ||
        !edge_linux_scheduler_policy_is_fair(current->policy))
        return 0;

    candidate_eligible = candidate_vruntime_us <= average_vruntime_us;
    current_eligible = current_vruntime_us <= average_vruntime_us;
    if (candidate_eligible != current_eligible) return candidate_eligible;
    if (!candidate_eligible)
        return candidate_vruntime_us < current_vruntime_us;

    candidate_deadline = edge_linux_scheduler_virtual_deadline_us(
        candidate, candidate_vruntime_us, runnable_tasks);
    current_deadline = edge_linux_scheduler_virtual_deadline_us(
        current, current_vruntime_us, runnable_tasks);
    if (candidate_deadline != current_deadline)
        return candidate_deadline < current_deadline;
    return candidate_vruntime_us < current_vruntime_us;
}

int edge_linux_scheduler_fair_precedes(
    const edge_linux_scheduler_state_t *candidate,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_vruntime_us) {
    int order = edge_linux_scheduler_state_compare(candidate, current);

    if (order != 0) return order > 0;
    if (!candidate || !current) return 0;
    if (edge_linux_scheduler_policy_is_fair(candidate->policy) &&
        edge_linux_scheduler_policy_is_fair(current->policy))
        return candidate_vruntime_us < current_vruntime_us;
    return 0;
}

int edge_linux_scheduler_fair_wakeup_preempts(
    const edge_linux_scheduler_state_t *candidate,
    uint64_t candidate_vruntime_us,
    const edge_linux_scheduler_state_t *current,
    uint64_t current_vruntime_us,
    uint64_t current_runtime_us,
    uint64_t minimum_granularity_us) {
    uint64_t projected;
    uint64_t delta;
    int order = edge_linux_scheduler_state_compare(candidate, current);

    if (order != 0) return order > 0;
    if (!candidate || !current ||
        current_runtime_us < minimum_granularity_us)
        return 0;
    if (candidate->policy == EDGE_LINUX_SCHED_IDLE ||
        current->policy == EDGE_LINUX_SCHED_IDLE)
        return candidate->policy != EDGE_LINUX_SCHED_IDLE &&
               current->policy == EDGE_LINUX_SCHED_IDLE;
    if (!edge_linux_scheduler_policy_is_normal(candidate->policy) ||
        !edge_linux_scheduler_policy_is_normal(current->policy))
        return 0;

    delta = edge_linux_scheduler_vruntime_delta(current, current_runtime_us);
    projected = current_vruntime_us > UINT64_MAX - delta ?
                UINT64_MAX : current_vruntime_us + delta;
    if (candidate_vruntime_us >= projected) return 0;
    return projected - candidate_vruntime_us > minimum_granularity_us;
}
