/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux perf event service.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/perf_event.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"
#include "string.h"
#include "sys/boottime.h"

typedef struct kernel_perf_event {
    uint8_t used;
    uint8_t enabled;
    uint8_t enable_on_exec;
    uint8_t remove_on_exec;
    uint8_t inherited;
    uint8_t padding8[3];
    uint32_t references;
    int32_t target_tid;
    int32_t cpu;
    int32_t group_leader;
    int32_t inherit_root;
    uint64_t id;
    kernel_perf_event_attr_t attr;
    uint64_t baseline;
    uint64_t accumulated;
    uint64_t enabled_started_us;
    uint64_t enabled_accumulated_us;
} kernel_perf_event_t;

static kernel_perf_event_t g_perf_events[EDGE_RUNTIME_MAX_PERF_EVENTS];
static volatile uint32_t g_perf_event_lock;
static uint64_t g_perf_event_next_id = 1u;

_Static_assert(sizeof(kernel_perf_event_attr_t) ==
               KERNEL_PERF_ATTR_SIZE_CURRENT,
               "perf_event_attr layout must match Linux UAPI");

static void perf_event_lock(void) {
    while (__sync_lock_test_and_set(&g_perf_event_lock, 1u)) { }
}

static void perf_event_unlock(void) {
    __sync_lock_release(&g_perf_event_lock);
}

static uint64_t perf_saturating_add(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static uint64_t perf_microseconds_to_nanoseconds(uint64_t value) {
    return value > UINT64_MAX / 1000u ? UINT64_MAX : value * 1000u;
}

static kernel_perf_event_t *perf_event_get_locked(int event_id) {
    if (event_id < 0 || event_id >= EDGE_RUNTIME_MAX_PERF_EVENTS ||
        !g_perf_events[event_id].used)
        return 0;
    return &g_perf_events[event_id];
}

static int perf_event_task_sample(const kernel_perf_event_t *event,
                                  uint64_t *value) {
    kernel_proc_task_view_t task;
    uint64_t user;
    uint64_t system;

    if (!event || !value || event->target_tid <= 0 ||
        kernel_proc_task_view_get(event->target_tid, &task) < 0)
        return -EDGE_LINUX_ESRCH;
    user = task.usage.user_time_us;
    system = task.usage.sys_time_us;
    switch (event->attr.config) {
    case KERNEL_PERF_COUNT_SW_CPU_CLOCK:
    case KERNEL_PERF_COUNT_SW_TASK_CLOCK:
        if (event->attr.flags & KERNEL_PERF_ATTR_EXCLUDE_USER) user = 0;
        if (event->attr.flags & KERNEL_PERF_ATTR_EXCLUDE_KERNEL) system = 0;
        *value = perf_microseconds_to_nanoseconds(
            perf_saturating_add(user, system));
        return 0;
    case KERNEL_PERF_COUNT_SW_PAGE_FAULTS:
        *value = perf_saturating_add(
            task.usage.minor_faults, task.usage.major_faults);
        return 0;
    case KERNEL_PERF_COUNT_SW_CONTEXT_SWITCHES:
        *value = perf_saturating_add(
            task.usage.voluntary_ctxt_switches,
            task.usage.involuntary_ctxt_switches);
        return 0;
    case KERNEL_PERF_COUNT_SW_CPU_MIGRATIONS:
        *value = task.scheduler_migrations;
        return 0;
    case KERNEL_PERF_COUNT_SW_PAGE_FAULTS_MIN:
        *value = task.usage.minor_faults;
        return 0;
    case KERNEL_PERF_COUNT_SW_PAGE_FAULTS_MAJ:
        *value = task.usage.major_faults;
        return 0;
    case KERNEL_PERF_COUNT_SW_ALIGNMENT_FAULTS:
    case KERNEL_PERF_COUNT_SW_EMULATION_FAULTS:
    case KERNEL_PERF_COUNT_SW_DUMMY:
    case KERNEL_PERF_COUNT_SW_CGROUP_SWITCHES:
        *value = 0;
        return 0;
    default:
        return -EDGE_LINUX_EOPNOTSUPP;
    }
}

static int perf_event_cpu_sample(const kernel_perf_event_t *event,
                                 uint64_t *value) {
    kernel_scheduler_cpu_stats_t stats;

    if (!event || !value || event->cpu < 0 ||
        kernel_arch_scheduler_cpu_stats((uint32_t)event->cpu, &stats) < 0)
        return -EDGE_LINUX_ENODEV;
    switch (event->attr.config) {
    case KERNEL_PERF_COUNT_SW_CPU_CLOCK:
        *value = perf_microseconds_to_nanoseconds(boottime_monotonic_us());
        return 0;
    case KERNEL_PERF_COUNT_SW_TASK_CLOCK:
        *value = perf_microseconds_to_nanoseconds(
            perf_saturating_add(stats.user_time_us, stats.system_time_us));
        return 0;
    case KERNEL_PERF_COUNT_SW_CONTEXT_SWITCHES:
        *value = stats.context_switches;
        return 0;
    case KERNEL_PERF_COUNT_SW_CPU_MIGRATIONS:
        *value = stats.migrations;
        return 0;
    case KERNEL_PERF_COUNT_SW_ALIGNMENT_FAULTS:
    case KERNEL_PERF_COUNT_SW_EMULATION_FAULTS:
    case KERNEL_PERF_COUNT_SW_DUMMY:
    case KERNEL_PERF_COUNT_SW_CGROUP_SWITCHES:
        *value = 0;
        return 0;
    default:
        return -EDGE_LINUX_EOPNOTSUPP;
    }
}

static int perf_event_sample(const kernel_perf_event_t *event,
                             uint64_t *value) {
    return event && event->target_tid > 0 ?
        perf_event_task_sample(event, value) :
        perf_event_cpu_sample(event, value);
}

static uint64_t perf_event_local_count_locked(
    const kernel_perf_event_t *event) {
    uint64_t sampled;

    if (!event) return 0;
    if (!event->enabled || perf_event_sample(event, &sampled) < 0)
        return event->accumulated;
    return perf_saturating_add(
        event->accumulated,
        sampled >= event->baseline ? sampled - event->baseline : 0);
}

static uint64_t perf_event_current_count_locked(
    const kernel_perf_event_t *event) {
    uint64_t count;
    int root_id;

    if (!event) return 0;
    count = perf_event_local_count_locked(event);
    if (event->inherited) return count;
    root_id = (int)(event - g_perf_events);
    for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
        const kernel_perf_event_t *child = &g_perf_events[index];
        if (!child->used || !child->inherited ||
            child->inherit_root != root_id)
            continue;
        count = perf_saturating_add(
            count, perf_event_local_count_locked(child));
    }
    return count;
}

static uint64_t perf_event_enabled_time_locked(
    const kernel_perf_event_t *event) {
    uint64_t elapsed;
    uint64_t now;

    if (!event || !event->enabled) return event ?
        perf_microseconds_to_nanoseconds(event->enabled_accumulated_us) : 0;
    now = boottime_monotonic_us();
    elapsed = now >= event->enabled_started_us ?
        now - event->enabled_started_us : 0;
    return perf_microseconds_to_nanoseconds(perf_saturating_add(
        event->enabled_accumulated_us, elapsed));
}

static void perf_event_enable_locked(kernel_perf_event_t *event) {
    uint64_t sampled = 0;

    if (!event || event->enabled) return;
    (void)perf_event_sample(event, &sampled);
    event->baseline = sampled;
    event->enabled_started_us = boottime_monotonic_us();
    event->enabled = 1;
}

static void perf_event_disable_locked(kernel_perf_event_t *event) {
    uint64_t now;

    if (!event || !event->enabled) return;
    event->accumulated = perf_event_local_count_locked(event);
    now = boottime_monotonic_us();
    if (now >= event->enabled_started_us)
        event->enabled_accumulated_us = perf_saturating_add(
            event->enabled_accumulated_us,
            now - event->enabled_started_us);
    event->enabled = 0;
}

static void perf_event_reset_locked(kernel_perf_event_t *event) {
    uint64_t sampled = 0;

    if (!event) return;
    event->accumulated = 0;
    if (!event->enabled) return;
    (void)perf_event_sample(event, &sampled);
    event->baseline = sampled;
    event->enabled_started_us = boottime_monotonic_us();
}

static int perf_event_request_valid(
    const kernel_perf_event_open_request_t *request) {
    const kernel_perf_event_attr_t *attr;
    uint64_t unsupported_flags;

    if (!request) return -EDGE_LINUX_EINVAL;
    attr = &request->attr;
    if (request->flags & ~KERNEL_PERF_FLAG_MASK)
        return -EDGE_LINUX_EINVAL;
    if (request->flags & (KERNEL_PERF_FLAG_FD_OUTPUT |
                          KERNEL_PERF_FLAG_PID_CGROUP))
        return -EDGE_LINUX_EOPNOTSUPP;
    if (attr->type != KERNEL_PERF_TYPE_SOFTWARE)
        return -EDGE_LINUX_ENOENT;
    if (attr->config >= KERNEL_PERF_COUNT_SW_MAX)
        return -EDGE_LINUX_EINVAL;
    if (attr->config == KERNEL_PERF_COUNT_SW_BPF_OUTPUT)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (attr->reserved2 || (attr->auxiliary_action & ~7u))
        return -EDGE_LINUX_EINVAL;
    if (attr->sample_period || attr->sample_type || attr->wakeup_events ||
        attr->branch_sample_type || attr->sample_registers_user ||
        attr->sample_stack_user || attr->sample_registers_interrupt ||
        attr->auxiliary_watermark || attr->auxiliary_sample_size ||
        attr->auxiliary_action)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (attr->read_format & ~KERNEL_PERF_FORMAT_MASK)
        return -EDGE_LINUX_EINVAL;
    unsupported_flags = attr->flags &
        ~(KERNEL_PERF_ATTR_DISABLED | KERNEL_PERF_ATTR_INHERIT |
          KERNEL_PERF_ATTR_PINNED | KERNEL_PERF_ATTR_EXCLUSIVE |
          KERNEL_PERF_ATTR_EXCLUDE_USER |
          KERNEL_PERF_ATTR_EXCLUDE_KERNEL |
          KERNEL_PERF_ATTR_EXCLUDE_HV |
          KERNEL_PERF_ATTR_EXCLUDE_IDLE |
          KERNEL_PERF_ATTR_ENABLE_ON_EXEC |
          KERNEL_PERF_ATTR_REMOVE_ON_EXEC);
    if (unsupported_flags || (attr->flags & KERNEL_PERF_ATTR_RESERVED_MASK))
        return -EDGE_LINUX_EINVAL;
    if ((attr->flags & KERNEL_PERF_ATTR_ENABLE_ON_EXEC) &&
        (attr->flags & KERNEL_PERF_ATTR_REMOVE_ON_EXEC))
        return -EDGE_LINUX_EINVAL;
    if (request->target_tid <= 0 && request->cpu < 0)
        return -EDGE_LINUX_EINVAL;
    if (request->cpu < -1)
        return -EDGE_LINUX_EINVAL;
    if (request->cpu >= 64)
        return -EDGE_LINUX_ENODEV;
    if (request->cpu >= 0 &&
        !(kernel_scheduler_online_cpu_mask() & (1ULL << request->cpu)))
        return -EDGE_LINUX_ENODEV;
    return 0;
}

int kernel_perf_event_open(const kernel_perf_event_open_request_t *request) {
    kernel_perf_event_t *leader = 0;
    kernel_perf_event_t *event = 0;
    uint64_t sampled = 0;
    int result;

    result = perf_event_request_valid(request);
    if (result < 0) return result;
    if (request->target_tid > 0) {
        kernel_proc_task_view_t task;
        if (kernel_proc_task_view_get(request->target_tid, &task) < 0)
            return -EDGE_LINUX_ESRCH;
    }
    perf_event_lock();
    if (request->group_id >= 0 &&
        !(request->flags & KERNEL_PERF_FLAG_FD_NO_GROUP)) {
        leader = perf_event_get_locked(request->group_id);
        if (!leader || leader->group_leader != request->group_id) {
            perf_event_unlock();
            return leader ? -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBADF;
        }
        if (leader->target_tid != request->target_tid ||
            leader->cpu != request->cpu ||
            ((leader->attr.flags ^ request->attr.flags) &
             KERNEL_PERF_ATTR_INHERIT) ||
            (request->attr.flags & (KERNEL_PERF_ATTR_PINNED |
                                    KERNEL_PERF_ATTR_EXCLUSIVE))) {
            perf_event_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        if (leader->references == UINT32_MAX) {
            perf_event_unlock();
            return -EDGE_LINUX_EMFILE;
        }
    }
    for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
        if (!g_perf_events[index].used) {
            event = &g_perf_events[index];
            result = index;
            break;
        }
    }
    if (!event) {
        perf_event_unlock();
        return -EDGE_LINUX_EMFILE;
    }
    memset(event, 0, sizeof(*event));
    event->used = 1;
    event->references = 1;
    event->target_tid = request->target_tid;
    event->cpu = request->cpu;
    event->group_leader = leader ? request->group_id : result;
    event->inherit_root = -1;
    if (leader) ++leader->references;
    event->attr = request->attr;
    event->enable_on_exec =
        (request->attr.flags & KERNEL_PERF_ATTR_ENABLE_ON_EXEC) != 0;
    event->remove_on_exec =
        (request->attr.flags & KERNEL_PERF_ATTR_REMOVE_ON_EXEC) != 0;
    event->id = g_perf_event_next_id++;
    if (!event->id) event->id = g_perf_event_next_id++;
    if (!(request->attr.flags & KERNEL_PERF_ATTR_DISABLED) &&
        !event->enable_on_exec) {
        (void)perf_event_sample(event, &sampled);
        event->baseline = sampled;
        event->enabled_started_us = boottime_monotonic_us();
        event->enabled = 1;
    }
    perf_event_unlock();
    return result;
}

int kernel_perf_event_retain(int event_id) {
    kernel_perf_event_t *event;
    int result = -EDGE_LINUX_EBADF;

    perf_event_lock();
    event = perf_event_get_locked(event_id);
    if (event && event->references != UINT32_MAX) {
        ++event->references;
        result = 0;
    }
    perf_event_unlock();
    return result;
}

static void perf_event_drop_reference_locked(int event_id) {
    kernel_perf_event_t *event;
    int leader_id = -1;

    event = perf_event_get_locked(event_id);
    if (event && event->references && !--event->references) {
        if (event->group_leader != event_id)
            leader_id = event->group_leader;
        memset(event, 0, sizeof(*event));
        event = perf_event_get_locked(leader_id);
        if (event && event->references && !--event->references)
            memset(event, 0, sizeof(*event));
    }
}

void kernel_perf_event_release(int event_id) {
    perf_event_lock();
    perf_event_drop_reference_locked(event_id);
    perf_event_unlock();
}

int kernel_perf_event_query(int event_id, kernel_perf_event_state_t *state) {
    kernel_perf_event_t *event;

    if (!state) return -EDGE_LINUX_EINVAL;
    perf_event_lock();
    event = perf_event_get_locked(event_id);
    if (!event) {
        perf_event_unlock();
        return -EDGE_LINUX_EBADF;
    }
    memset(state, 0, sizeof(*state));
    state->id = event->id;
    state->target_tid = event->target_tid;
    state->cpu = event->cpu;
    state->group_leader = event->group_leader;
    state->enabled = event->enabled;
    state->enable_on_exec = event->enable_on_exec;
    state->remove_on_exec = event->remove_on_exec;
    perf_event_unlock();
    return 0;
}

static uint32_t perf_event_read_one_locked(
    const kernel_perf_event_t *event, uint64_t *values,
    uint32_t offset, uint32_t capacity, int in_group,
    uint64_t format) {

    if (offset >= capacity) return UINT32_MAX;
    values[offset++] = perf_event_current_count_locked(event);
    if (!in_group && (format & KERNEL_PERF_FORMAT_TOTAL_TIME_ENABLED)) {
        if (offset >= capacity) return UINT32_MAX;
        values[offset++] = perf_event_enabled_time_locked(event);
    }
    if (!in_group && (format & KERNEL_PERF_FORMAT_TOTAL_TIME_RUNNING)) {
        if (offset >= capacity) return UINT32_MAX;
        values[offset++] = perf_event_enabled_time_locked(event);
    }
    if (format & KERNEL_PERF_FORMAT_ID) {
        if (offset >= capacity) return UINT32_MAX;
        values[offset++] = event->id;
    }
    if (format & KERNEL_PERF_FORMAT_LOST) {
        if (offset >= capacity) return UINT32_MAX;
        values[offset++] = 0;
    }
    return offset;
}

int64_t kernel_perf_event_read(int event_id, uint64_t *values,
                               uint32_t value_capacity) {
    kernel_perf_event_t *event;
    uint32_t offset = 0;

    if (!values) return -EDGE_LINUX_EFAULT;
    perf_event_lock();
    event = perf_event_get_locked(event_id);
    if (!event) {
        perf_event_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (event->attr.read_format & KERNEL_PERF_FORMAT_GROUP) {
        int leader_id = event->group_leader;
        kernel_perf_event_t *leader = perf_event_get_locked(leader_id);
        uint32_t count = 0;

        if (!leader || event_id != leader_id || value_capacity < 1u) {
            perf_event_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        values[offset++] = 0;
        if (leader->attr.read_format &
            KERNEL_PERF_FORMAT_TOTAL_TIME_ENABLED) {
            if (offset >= value_capacity) goto too_small;
            values[offset++] = perf_event_enabled_time_locked(leader);
        }
        if (leader->attr.read_format &
            KERNEL_PERF_FORMAT_TOTAL_TIME_RUNNING) {
            if (offset >= value_capacity) goto too_small;
            values[offset++] = perf_event_enabled_time_locked(leader);
        }
        for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
            kernel_perf_event_t *member = &g_perf_events[index];
            uint32_t next;
            if (!member->used || member->group_leader != leader_id)
                continue;
            next = perf_event_read_one_locked(
                member, values, offset, value_capacity, 1,
                leader->attr.read_format);
            if (next == UINT32_MAX) goto too_small;
            offset = next;
            ++count;
        }
        values[0] = count;
    } else {
        offset = perf_event_read_one_locked(
            event, values, 0, value_capacity, 0,
            event->attr.read_format);
        if (offset == UINT32_MAX) goto too_small;
    }
    perf_event_unlock();
    return (int64_t)offset * (int64_t)sizeof(uint64_t);

too_small:
    perf_event_unlock();
    return -EDGE_LINUX_EINVAL;
}

int kernel_perf_event_control(int event_id, uint32_t command,
                              uint32_t flags, uint64_t *id_out) {
    kernel_perf_event_t *event;
    int leader_id;

    if (flags & ~KERNEL_PERF_IOC_FLAG_GROUP) return -EDGE_LINUX_EINVAL;
    perf_event_lock();
    event = perf_event_get_locked(event_id);
    if (!event) {
        perf_event_unlock();
        return -EDGE_LINUX_EBADF;
    }
    if (command == KERNEL_PERF_IOC_ID) {
        if (!id_out) {
            perf_event_unlock();
            return -EDGE_LINUX_EFAULT;
        }
        *id_out = event->id;
        perf_event_unlock();
        return 0;
    }
    if (command != KERNEL_PERF_IOC_ENABLE &&
        command != KERNEL_PERF_IOC_DISABLE &&
        command != KERNEL_PERF_IOC_RESET) {
        perf_event_unlock();
        return command == KERNEL_PERF_IOC_REFRESH ?
            -EDGE_LINUX_EINVAL : -EDGE_LINUX_ENOTTY;
    }
    leader_id = event->group_leader;
    for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
        kernel_perf_event_t *member = &g_perf_events[index];
        kernel_perf_event_t *root = member;
        int root_id = index;

        if (!member->used) continue;
        if (member->inherited) {
            root_id = member->inherit_root;
            root = perf_event_get_locked(root_id);
            if (!root || root->inherited) continue;
        }
        if ((flags & KERNEL_PERF_IOC_FLAG_GROUP) ?
                root->group_leader != leader_id : root_id != event_id)
            continue;
        if (command == KERNEL_PERF_IOC_ENABLE)
            perf_event_enable_locked(member);
        else if (command == KERNEL_PERF_IOC_DISABLE)
            perf_event_disable_locked(member);
        else
            perf_event_reset_locked(member);
    }
    perf_event_unlock();
    return 0;
}

void kernel_perf_event_task_fork(int32_t parent_tid, int32_t child_tid) {
    int source_slots[EDGE_RUNTIME_MAX_PERF_EVENTS];
    int child_slots[EDGE_RUNTIME_MAX_PERF_EVENTS];
    uint32_t count = 0;

    if (parent_tid <= 0 || child_tid <= 0 || parent_tid == child_tid)
        return;
    perf_event_lock();
    for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
        kernel_perf_event_t *source = &g_perf_events[index];
        int free_slot = -1;
        int root_id;
        kernel_perf_event_t *root;

        if (!source->used || source->target_tid != parent_tid ||
            !(source->attr.flags & KERNEL_PERF_ATTR_INHERIT))
            continue;
        root_id = source->inherited ? source->inherit_root : index;
        root = perf_event_get_locked(root_id);
        if (!root || root->inherited || root->references == UINT32_MAX)
            continue;
        for (int candidate = 0;
             candidate < EDGE_RUNTIME_MAX_PERF_EVENTS; ++candidate) {
            int reserved = 0;
            if (g_perf_events[candidate].used) continue;
            for (uint32_t prior = 0; prior < count; ++prior)
                if (child_slots[prior] == candidate) reserved = 1;
            if (!reserved) {
                free_slot = candidate;
                break;
            }
        }
        if (free_slot < 0) break;
        source_slots[count] = index;
        child_slots[count] = free_slot;
        ++count;
    }
    for (uint32_t position = 0; position < count; ++position) {
        kernel_perf_event_t *source =
            &g_perf_events[source_slots[position]];
        kernel_perf_event_t *child =
            &g_perf_events[child_slots[position]];
        kernel_perf_event_t *root;
        uint64_t sampled = 0;
        int root_id = source->inherited ?
            source->inherit_root : source_slots[position];

        root = perf_event_get_locked(root_id);
        if (!root || root->references == UINT32_MAX) continue;
        memset(child, 0, sizeof(*child));
        child->used = 1;
        child->inherited = 1;
        child->references = 1;
        child->target_tid = child_tid;
        child->cpu = source->cpu;
        child->inherit_root = root_id;
        child->attr = source->attr;
        child->enable_on_exec = source->enable_on_exec;
        child->remove_on_exec = source->remove_on_exec;
        child->id = g_perf_event_next_id++;
        if (!child->id) child->id = g_perf_event_next_id++;
        child->enabled = source->enabled;
        if (child->enabled) {
            (void)perf_event_sample(child, &sampled);
            child->baseline = sampled;
            child->enabled_started_us = boottime_monotonic_us();
        }
        ++root->references;
    }
    for (uint32_t position = 0; position < count; ++position) {
        kernel_perf_event_t *source =
            &g_perf_events[source_slots[position]];
        kernel_perf_event_t *child =
            perf_event_get_locked(child_slots[position]);
        int child_leader = -1;

        if (!child || !child->inherited) continue;
        if (source->group_leader == source_slots[position]) {
            child->group_leader = child_slots[position];
            continue;
        }
        for (uint32_t leader = 0; leader < count; ++leader)
            if (source_slots[leader] == source->group_leader) {
                child_leader = child_slots[leader];
                break;
            }
        if (child_leader >= 0) {
            child->group_leader = child_leader;
            continue;
        }
        {
            int root_id = child->inherit_root;
            memset(child, 0, sizeof(*child));
            perf_event_drop_reference_locked(root_id);
        }
    }
    perf_event_unlock();
}

void kernel_perf_event_task_exec(int32_t tid) {
    perf_event_lock();
    for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
        kernel_perf_event_t *event = &g_perf_events[index];
        if (!event->used || event->target_tid != tid) continue;
        if (event->remove_on_exec) {
            perf_event_disable_locked(event);
            event->target_tid = -2;
        } else if (event->enable_on_exec) {
            event->enable_on_exec = 0;
            perf_event_enable_locked(event);
        }
    }
    perf_event_unlock();
}

void kernel_perf_event_task_exit(int32_t tid) {
    perf_event_lock();
    for (int index = 0; index < EDGE_RUNTIME_MAX_PERF_EVENTS; ++index) {
        kernel_perf_event_t *event = &g_perf_events[index];
        if (!event->used || event->target_tid != tid) continue;
        perf_event_disable_locked(event);
        if (!event->inherited) {
            event->target_tid = -2;
            continue;
        }
        {
            int root_id = event->inherit_root;
            kernel_perf_event_t *root = perf_event_get_locked(root_id);
            if (root && !root->inherited)
                root->accumulated = perf_saturating_add(
                    root->accumulated, event->accumulated);
            memset(event, 0, sizeof(*event));
            perf_event_drop_reference_locked(root_id);
        }
    }
    perf_event_unlock();
}
