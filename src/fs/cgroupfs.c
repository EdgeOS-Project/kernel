/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS cgroup v2 core filesystem.
 * Copyright (c) EdgeOS Contributors.
 *
 * This implements the controller-independent cgroup v2 hierarchy used for
 * process organization and lifecycle tracking.  Resource controllers are
 * advertised only after their control files and scheduler enforcement are
 * available.  The hierarchy itself is real: directories persist, process
 * membership follows fork/clone, cgroup.procs moves a complete thread group,
 * and removal refuses populated or non-empty groups.
 */

#include <stdint.h>
#include "block/block.h"
#include "fs/cgroupfs.h"
#include "kernel/inotify.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/proc_memory.h"
#include "kernel/process_runtime.h"
#include "kernel/scheduler_policy.h"
#include "kernel/smp.h"
#include "kernel/signal_queue.h"
#include "kernel/signal_runtime.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"
#include "vfs/vfs.h"

#define CGROUPFS_MAX_NODES 256u
#define CGROUPFS_SNAPSHOT_CAPACITY 32768u
#define CGROUPFS_LIMIT_MAX UINT32_MAX
#define CGROUPFS_CPU_WEIGHT_DEFAULT 100u
#define CGROUPFS_CPU_WEIGHT_MIN 1u
#define CGROUPFS_CPU_WEIGHT_MAX 10000u
#define CGROUPFS_CPU_PERIOD_DEFAULT_US 100000u
#define CGROUPFS_CPU_PERIOD_MIN_US 1000u
#define CGROUPFS_CPU_PERIOD_MAX_US 1000000u
#define CGROUPFS_CPU_BURST_MAX_US 1000000u
#define CGROUPFS_CPU_QUOTA_MAX UINT64_MAX
#define CGROUPFS_IO_WEIGHT_DEFAULT 100u
#define CGROUPFS_IO_WEIGHT_MIN 1u
#define CGROUPFS_IO_WEIGHT_MAX 10000u
#define CGROUPFS_IO_DEVICE_SLOTS 8u
#define CGROUPFS_IO_WEIGHT_QUANTUM_BYTES 4096u
#define CGROUPFS_CONTROLLER_CPU 0x1u
#define CGROUPFS_CONTROLLER_PIDS 0x2u
#define CGROUPFS_CONTROLLER_MEMORY 0x4u
#define CGROUPFS_CONTROLLER_CPUSET 0x8u
#define CGROUPFS_CONTROLLER_IO 0x10u
#define CGROUPFS_CONTROLLER_ALL                                           \
    (CGROUPFS_CONTROLLER_CPU | CGROUPFS_CONTROLLER_PIDS |                \
     CGROUPFS_CONTROLLER_MEMORY | CGROUPFS_CONTROLLER_CPUSET |           \
     CGROUPFS_CONTROLLER_IO)

enum cgroupfs_inode_kind {
    CGROUPFS_INODE_DIRECTORY = 1,
    CGROUPFS_INODE_CONTROLLERS,
    CGROUPFS_INODE_SUBTREE_CONTROL,
    CGROUPFS_INODE_PROCS,
    CGROUPFS_INODE_EVENTS,
    CGROUPFS_INODE_KILL,
    CGROUPFS_INODE_FREEZE,
    CGROUPFS_INODE_THREADS,
    CGROUPFS_INODE_TYPE,
    CGROUPFS_INODE_STAT,
    CGROUPFS_INODE_MAX_DEPTH,
    CGROUPFS_INODE_MAX_DESCENDANTS,
    CGROUPFS_INODE_CPUSET_CPUS,
    CGROUPFS_INODE_CPUSET_CPUS_EFFECTIVE,
    CGROUPFS_INODE_CPUSET_MEMS,
    CGROUPFS_INODE_CPUSET_MEMS_EFFECTIVE,
    CGROUPFS_INODE_CPU_WEIGHT,
    CGROUPFS_INODE_CPU_WEIGHT_NICE,
    CGROUPFS_INODE_CPU_MAX,
    CGROUPFS_INODE_CPU_MAX_BURST,
    CGROUPFS_INODE_CPU_IDLE,
    CGROUPFS_INODE_CPU_UCLAMP_MIN,
    CGROUPFS_INODE_CPU_UCLAMP_MAX,
    CGROUPFS_INODE_CPU_STAT,
    CGROUPFS_INODE_PIDS_CURRENT,
    CGROUPFS_INODE_PIDS_MAX,
    CGROUPFS_INODE_PIDS_EVENTS,
    CGROUPFS_INODE_PIDS_EVENTS_LOCAL,
    CGROUPFS_INODE_PIDS_PEAK,
    CGROUPFS_INODE_MEMORY_CURRENT,
    CGROUPFS_INODE_MEMORY_MIN,
    CGROUPFS_INODE_MEMORY_LOW,
    CGROUPFS_INODE_MEMORY_HIGH,
    CGROUPFS_INODE_MEMORY_MAX,
    CGROUPFS_INODE_MEMORY_PEAK,
    CGROUPFS_INODE_MEMORY_EVENTS,
    CGROUPFS_INODE_MEMORY_EVENTS_LOCAL,
    CGROUPFS_INODE_MEMORY_STAT,
    CGROUPFS_INODE_MEMORY_PRESSURE,
    CGROUPFS_INODE_MEMORY_OOM_GROUP,
    CGROUPFS_INODE_MEMORY_SWAP_CURRENT,
    CGROUPFS_INODE_MEMORY_SWAP_PEAK,
    CGROUPFS_INODE_MEMORY_SWAP_HIGH,
    CGROUPFS_INODE_MEMORY_SWAP_MAX,
    CGROUPFS_INODE_MEMORY_SWAP_EVENTS,
    CGROUPFS_INODE_MEMORY_RECLAIM,
    CGROUPFS_INODE_IO_STAT,
    CGROUPFS_INODE_IO_WEIGHT,
    CGROUPFS_INODE_IO_MAX,
    CGROUPFS_INODE_LAST = CGROUPFS_INODE_IO_MAX
};

typedef struct {
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t ctime;
} cgroupfs_inode_metadata_t;

typedef struct {
    uint8_t used;
    uint8_t limits_configured;
    uint32_t major;
    uint32_t minor;
    uint32_t weight;
    uint64_t read_bytes;
    uint64_t write_bytes;
    uint64_t read_operations;
    uint64_t write_operations;
    uint64_t read_bytes_per_second;
    uint64_t write_bytes_per_second;
    uint64_t read_operations_per_second;
    uint64_t write_operations_per_second;
    uint64_t read_byte_deadline_us;
    uint64_t write_byte_deadline_us;
    uint64_t read_operation_deadline_us;
    uint64_t write_operation_deadline_us;
    uint64_t weighted_deadline_us;
} cgroupfs_io_device_t;

typedef struct {
    uint8_t used;
    uint8_t populated;
    uint8_t populated_known;
    uint8_t frozen;
    uint8_t subtree_controllers;
    uint8_t cpu_throttled;
    uint8_t cpuset_cpus_configured;
    uint8_t cpuset_mems_configured;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t generation;
    uint32_t parent;
    uint32_t max_depth;
    uint32_t max_descendants;
    uint32_t ctime;
    uint32_t task_count;
    uint32_t subtree_task_count;
    uint32_t cpu_weight;
    uint32_t cpu_uclamp_min;
    uint32_t cpu_uclamp_max;
    uint8_t cpu_idle;
    edge_cpumask_t cpuset_cpus;
    edge_cpumask_t cpuset_mems;
    uint64_t cpu_quota_us;
    uint64_t cpu_period_us;
    uint64_t cpu_burst_us;
    uint64_t cpu_burst_credit_us;
    uint64_t cpu_period_start_us;
    uint64_t cpu_period_usage_us;
    uint64_t cpu_usage_us;
    uint64_t cpu_user_us;
    uint64_t cpu_system_us;
    uint64_t cpu_nr_periods;
    uint64_t cpu_nr_throttled;
    uint64_t cpu_throttled_us;
    uint64_t cpu_throttle_start_us;
    uint64_t cpu_scheduler_vruntime_us;
    uint8_t cpu_scheduler_vruntime_valid;
    uint32_t pids_max;
    uint32_t pids_peak;
    uint64_t pids_max_events;
    uint64_t pids_max_events_local;
    uint64_t memory_direct;
    uint64_t memory_current;
    uint64_t memory_min;
    uint64_t memory_low;
    uint64_t memory_high;
    uint64_t memory_max;
    uint64_t memory_peak;
    uint64_t memory_max_events;
    uint64_t memory_max_events_local;
    uint64_t memory_low_events;
    uint64_t memory_low_events_local;
    uint64_t memory_high_events;
    uint64_t memory_high_events_local;
    uint64_t memory_minor_faults;
    uint64_t memory_major_faults;
    uint64_t memory_scanned_pages;
    uint64_t memory_reclaimed_pages;
    edge_mm_pressure_state_t memory_pressure;
    uint64_t memory_oom_events;
    uint64_t memory_oom_events_local;
    uint64_t memory_oom_kill_events;
    uint64_t memory_oom_kill_events_local;
    uint64_t memory_oom_group_kill_events;
    uint64_t memory_oom_group_kill_events_local;
    uint8_t memory_oom_group;
    uint32_t io_weight;
    uint64_t memory_swap_current;
    uint64_t memory_swap_peak;
    uint64_t memory_swap_high;
    uint64_t memory_swap_max;
    uint64_t memory_swap_high_events;
    uint64_t memory_swap_max_events;
    uint64_t memory_swap_fail_events;
    cgroupfs_io_device_t io_devices[CGROUPFS_IO_DEVICE_SLOTS];
    cgroupfs_inode_metadata_t
        interface_metadata[CGROUPFS_INODE_LAST + 1u];
    char name[VFS_NAME_MAX];
} cgroupfs_node_t;

typedef struct {
    uint8_t initialized;
    uint32_t next_generation;
    cgroupfs_node_t nodes[CGROUPFS_MAX_NODES];
} cgroupfs_state_t;

typedef struct {
    const char *name;
    uint32_t kind;
    uint16_t mode;
} cgroupfs_interface_t;

static const cgroupfs_interface_t g_cgroup_interfaces[] = {
    { "cgroup.controllers", CGROUPFS_INODE_CONTROLLERS, 0444 },
    { "cgroup.subtree_control", CGROUPFS_INODE_SUBTREE_CONTROL, 0644 },
    { "cgroup.procs", CGROUPFS_INODE_PROCS, 0644 },
    { "cgroup.events", CGROUPFS_INODE_EVENTS, 0444 },
    { "cgroup.kill", CGROUPFS_INODE_KILL, 0200 },
    { "cgroup.freeze", CGROUPFS_INODE_FREEZE, 0644 },
    { "cgroup.threads", CGROUPFS_INODE_THREADS, 0444 },
    { "cgroup.type", CGROUPFS_INODE_TYPE, 0444 },
    { "cgroup.stat", CGROUPFS_INODE_STAT, 0444 },
    { "cgroup.max.depth", CGROUPFS_INODE_MAX_DEPTH, 0644 },
    { "cgroup.max.descendants", CGROUPFS_INODE_MAX_DESCENDANTS, 0644 },
    { "cpuset.cpus", CGROUPFS_INODE_CPUSET_CPUS, 0644 },
    { "cpuset.cpus.effective", CGROUPFS_INODE_CPUSET_CPUS_EFFECTIVE, 0444 },
    { "cpuset.mems", CGROUPFS_INODE_CPUSET_MEMS, 0644 },
    { "cpuset.mems.effective", CGROUPFS_INODE_CPUSET_MEMS_EFFECTIVE, 0444 },
    { "cpu.weight", CGROUPFS_INODE_CPU_WEIGHT, 0644 },
    { "cpu.weight.nice", CGROUPFS_INODE_CPU_WEIGHT_NICE, 0644 },
    { "cpu.max", CGROUPFS_INODE_CPU_MAX, 0644 },
    { "cpu.max.burst", CGROUPFS_INODE_CPU_MAX_BURST, 0644 },
    { "cpu.idle", CGROUPFS_INODE_CPU_IDLE, 0644 },
    { "cpu.uclamp.min", CGROUPFS_INODE_CPU_UCLAMP_MIN, 0644 },
    { "cpu.uclamp.max", CGROUPFS_INODE_CPU_UCLAMP_MAX, 0644 },
    { "cpu.stat", CGROUPFS_INODE_CPU_STAT, 0444 },
    { "pids.current", CGROUPFS_INODE_PIDS_CURRENT, 0444 },
    { "pids.max", CGROUPFS_INODE_PIDS_MAX, 0644 },
    { "pids.events", CGROUPFS_INODE_PIDS_EVENTS, 0444 },
    { "pids.events.local", CGROUPFS_INODE_PIDS_EVENTS_LOCAL, 0444 },
    { "pids.peak", CGROUPFS_INODE_PIDS_PEAK, 0444 },
    { "memory.current", CGROUPFS_INODE_MEMORY_CURRENT, 0444 },
    { "memory.min", CGROUPFS_INODE_MEMORY_MIN, 0644 },
    { "memory.low", CGROUPFS_INODE_MEMORY_LOW, 0644 },
    { "memory.high", CGROUPFS_INODE_MEMORY_HIGH, 0644 },
    { "memory.max", CGROUPFS_INODE_MEMORY_MAX, 0644 },
    { "memory.peak", CGROUPFS_INODE_MEMORY_PEAK, 0644 },
    { "memory.events", CGROUPFS_INODE_MEMORY_EVENTS, 0444 },
    { "memory.events.local", CGROUPFS_INODE_MEMORY_EVENTS_LOCAL, 0444 },
    { "memory.stat", CGROUPFS_INODE_MEMORY_STAT, 0444 },
    { "memory.pressure", CGROUPFS_INODE_MEMORY_PRESSURE, 0444 },
    { "memory.oom.group", CGROUPFS_INODE_MEMORY_OOM_GROUP, 0644 },
    { "memory.swap.current", CGROUPFS_INODE_MEMORY_SWAP_CURRENT, 0444 },
    { "memory.swap.peak", CGROUPFS_INODE_MEMORY_SWAP_PEAK, 0644 },
    { "memory.swap.high", CGROUPFS_INODE_MEMORY_SWAP_HIGH, 0644 },
    { "memory.swap.max", CGROUPFS_INODE_MEMORY_SWAP_MAX, 0644 },
    { "memory.swap.events", CGROUPFS_INODE_MEMORY_SWAP_EVENTS, 0444 },
    { "memory.reclaim", CGROUPFS_INODE_MEMORY_RECLAIM, 0200 },
    { "io.stat", CGROUPFS_INODE_IO_STAT, 0444 },
    { "io.weight", CGROUPFS_INODE_IO_WEIGHT, 0644 },
    { "io.max", CGROUPFS_INODE_IO_MAX, 0644 }
};

static cgroupfs_state_t g_cgroupfs;
static vfs_superblock_t g_cgroupfs_sb;
static volatile uint32_t g_cgroupfs_lock;
static spinlock_t g_cgroupfs_memory_lock;
static volatile uint32_t g_cgroupfs_snapshot_lock;
static char g_cgroupfs_snapshot[CGROUPFS_SNAPSHOT_CAPACITY];
static char g_cgroupfs_event_path[VFS_PATH_MAX];

static void cgroupfs_rebuild_task_counts_locked(void);

static void cgroupfs_lock(volatile uint32_t *lock) {
    while (__sync_lock_test_and_set(lock, 1u)) {
        while (*lock) __asm__ __volatile__("" ::: "memory");
    }
}

static int cgroupfs_try_lock(volatile uint32_t *lock) {
    return __sync_lock_test_and_set(lock, 1u) == 0u;
}

static void cgroupfs_unlock(volatile uint32_t *lock) {
    __sync_lock_release(lock);
}

static uint32_t cgroupfs_now(void) {
    return (uint32_t)(boottime_realtime_us() / 1000000u);
}

static uint64_t cgroupfs_u64_add_saturating(uint64_t left,
                                            uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static uint32_t cgroupfs_cpu_weight_from_nice(int32_t nice) {
    uint64_t scheduler_weight = edge_linux_scheduler_nice_weight(nice);
    uint64_t weight =
        (scheduler_weight * CGROUPFS_CPU_WEIGHT_DEFAULT + 512u) / 1024u;

    if (weight < CGROUPFS_CPU_WEIGHT_MIN) return CGROUPFS_CPU_WEIGHT_MIN;
    if (weight > CGROUPFS_CPU_WEIGHT_MAX) return CGROUPFS_CPU_WEIGHT_MAX;
    return (uint32_t)weight;
}

static int32_t cgroupfs_cpu_nice_from_weight(uint32_t weight) {
    int32_t closest = -20;
    uint32_t closest_delta = UINT32_MAX;

    for (int32_t nice = -20; nice <= 19; ++nice) {
        uint32_t candidate = cgroupfs_cpu_weight_from_nice(nice);
        uint32_t delta = candidate > weight ? candidate - weight :
                                             weight - candidate;
        if (delta >= closest_delta) continue;
        closest = nice;
        closest_delta = delta;
    }
    return closest;
}

static void cgroupfs_initialize_cpu(cgroupfs_node_t *node) {
    if (!node) return;
    node->cpu_weight = CGROUPFS_CPU_WEIGHT_DEFAULT;
    node->cpu_uclamp_min = 0u;
    node->cpu_uclamp_max = EDGE_LINUX_SCHED_UTIL_SCALE;
    node->cpu_idle = 0u;
    node->cpu_quota_us = CGROUPFS_CPU_QUOTA_MAX;
    node->cpu_period_us = CGROUPFS_CPU_PERIOD_DEFAULT_US;
    edge_cpumask_init(&node->cpuset_cpus, edge_smp_nr_cpu_ids());
    edge_cpumask_init(&node->cpuset_mems, 1u);
}

static void cgroupfs_initialize_pids(cgroupfs_node_t *node) {
    if (!node) return;
    node->pids_max = CGROUPFS_LIMIT_MAX;
}

static void cgroupfs_initialize_memory(cgroupfs_node_t *node) {
    if (!node) return;
    node->memory_max = UINT64_MAX;
    node->memory_high = UINT64_MAX;
    node->memory_swap_high = UINT64_MAX;
    node->memory_swap_max = UINT64_MAX;
}

static void cgroupfs_initialize_io(cgroupfs_node_t *node) {
    if (!node) return;
    node->io_weight = CGROUPFS_IO_WEIGHT_DEFAULT;
}

static void cgroupfs_initialize_interface_metadata(cgroupfs_node_t *node) {
    uint32_t now;
    if (!node) return;
    now = cgroupfs_now();
    for (uint32_t index = 0;
         index < sizeof(g_cgroup_interfaces) / sizeof(g_cgroup_interfaces[0]);
         ++index) {
        const cgroupfs_interface_t *interface = &g_cgroup_interfaces[index];
        cgroupfs_inode_metadata_t *metadata =
            &node->interface_metadata[interface->kind];
        metadata->mode = interface->mode;
        metadata->uid = node->uid;
        metadata->gid = node->gid;
        metadata->ctime = now;
    }
}

static void cgroupfs_initialize(void) {
    if (__atomic_load_n(&g_cgroupfs.initialized, __ATOMIC_ACQUIRE)) return;
    cgroupfs_lock(&g_cgroupfs_lock);
    if (!g_cgroupfs.initialized) {
        cgroupfs_node_t *root;
        memset(&g_cgroupfs, 0, sizeof(g_cgroupfs));
        g_cgroupfs.next_generation = 1;
        root = &g_cgroupfs.nodes[0];
        root->used = 1;
        root->mode = 0755;
        root->generation = 1;
        root->parent = 0;
        root->max_depth = CGROUPFS_LIMIT_MAX;
        root->max_descendants = CGROUPFS_LIMIT_MAX;
        root->ctime = cgroupfs_now();
        cgroupfs_initialize_cpu(root);
        cgroupfs_initialize_pids(root);
        cgroupfs_initialize_memory(root);
        cgroupfs_initialize_io(root);
        root->subtree_controllers = CGROUPFS_CONTROLLER_ALL;
        cgroupfs_initialize_interface_metadata(root);
        block_set_io_policy(cgroupfs_io_begin, cgroupfs_io_complete);
        cgroupfs_rebuild_task_counts_locked();
        __atomic_store_n(&g_cgroupfs.initialized, 1u,
                         __ATOMIC_RELEASE);
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
}

static int cgroupfs_append(char *buffer, uint32_t capacity, uint32_t *offset,
                           const char *text) {
    if (!buffer || !offset || !text) return -1;
    while (*text) {
        if (*offset + 1u >= capacity) return -1;
        buffer[(*offset)++] = *text++;
    }
    buffer[*offset] = 0;
    return 0;
}

static int cgroupfs_append_u32(char *buffer, uint32_t capacity,
                               uint32_t *offset, uint32_t value) {
    char digits[12];
    uint32_t count = 0;
    if (!value) digits[count++] = '0';
    while (value) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = { digits[--count], 0 };
        if (cgroupfs_append(buffer, capacity, offset, byte) < 0) return -1;
    }
    return 0;
}

static int cgroupfs_append_u64(char *buffer, uint32_t capacity,
                               uint32_t *offset, uint64_t value) {
    char digits[24];
    uint32_t count = 0;
    if (!value) digits[count++] = '0';
    while (value) {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = { digits[--count], 0 };
        if (cgroupfs_append(buffer, capacity, offset, byte) < 0) return -1;
    }
    return 0;
}

static int cgroupfs_append_uclamp(char *buffer, uint32_t capacity,
                                  uint32_t *offset, uint32_t value,
                                  int render_max) {
    uint32_t hundredths;

    if (render_max && value >= EDGE_LINUX_SCHED_UTIL_SCALE)
        return cgroupfs_append(buffer, capacity, offset, "max");
    if (value > EDGE_LINUX_SCHED_UTIL_SCALE)
        value = EDGE_LINUX_SCHED_UTIL_SCALE;
    hundredths = (value * 10000u +
                  EDGE_LINUX_SCHED_UTIL_SCALE / 2u) /
                 EDGE_LINUX_SCHED_UTIL_SCALE;
    if (cgroupfs_append_u32(buffer, capacity, offset,
                            hundredths / 100u) < 0 ||
        cgroupfs_append(buffer, capacity, offset, ".") < 0)
        return -1;
    if (hundredths % 100u < 10u &&
        cgroupfs_append(buffer, capacity, offset, "0") < 0)
        return -1;
    return cgroupfs_append_u32(buffer, capacity, offset,
                               hundredths % 100u);
}

static int cgroupfs_node_valid(uint32_t index, uint32_t generation) {
    return index < CGROUPFS_MAX_NODES && g_cgroupfs.nodes[index].used &&
           (!generation || g_cgroupfs.nodes[index].generation == generation);
}

static void cgroupfs_cpuset_effective_locked(uint32_t node, int memory,
                                              edge_cpumask_t *effective) {
    edge_cpumask_t configured;

    if (!effective) return;
    if (memory) {
        edge_cpumask_init(effective, 1u);
        (void)edge_cpumask_set_cpu(effective, 0u);
    } else {
        edge_smp_online_mask(effective);
    }
    if (!cgroupfs_node_valid(node, 0)) node = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        int is_configured = memory ? group->cpuset_mems_configured :
                                    group->cpuset_cpus_configured;

        if (is_configured) {
            configured = memory ? group->cpuset_mems : group->cpuset_cpus;
            edge_cpumask_and(effective, effective, &configured);
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
}

static int cgroupfs_render_resource_set(const edge_cpumask_t *mask,
                                        char *buffer, uint32_t capacity,
                                        uint32_t *offset) {
    uint32_t cpu = UINT32_MAX;
    int first_range = 1;

    if (!mask || !buffer || !offset) return -1;
    while ((cpu = edge_cpumask_next(mask, cpu)) < mask->nbits) {
        uint32_t start = cpu;
        uint32_t end = cpu;

        while (end + 1u < mask->nbits &&
               edge_cpumask_test_cpu(mask, end + 1u))
            ++end;
        if (!first_range &&
            cgroupfs_append(buffer, capacity, offset, ",") < 0)
            return -1;
        if (cgroupfs_append_u32(buffer, capacity, offset, start) < 0)
            return -1;
        if (end != start &&
            (cgroupfs_append(buffer, capacity, offset, "-") < 0 ||
             cgroupfs_append_u32(buffer, capacity, offset, end) < 0))
            return -1;
        first_range = 0;
        cpu = end;
    }
    return 0;
}

static int cgroupfs_inode_node(const vfs_inode_t *inode, uint32_t *index_out) {
    uint32_t index;
    if (!inode || !index_out) return -1;
    index = inode->fs_private[1];
    if (!cgroupfs_node_valid(index, inode->fs_private[2])) return -1;
    *index_out = index;
    return 0;
}

static void cgroupfs_fill_inode(uint32_t node, uint32_t kind, uint16_t mode,
                                vfs_inode_t *out) {
    cgroupfs_node_t *group;
    cgroupfs_inode_metadata_t *metadata = 0;
    if (!out || !cgroupfs_node_valid(node, 0)) return;
    group = &g_cgroupfs.nodes[node];
    if (kind != CGROUPFS_INODE_DIRECTORY &&
        kind <= CGROUPFS_INODE_LAST)
        metadata = &group->interface_metadata[kind];
    memset(out, 0, sizeof(*out));
    out->ino = 0xc7000000u | ((node & 0xffffu) << 8) | (kind & 0xffu);
    if (metadata) mode = metadata->mode;
    out->mode = (uint16_t)((kind == CGROUPFS_INODE_DIRECTORY ?
                            VFS_INODE_DIR : VFS_INODE_FILE) | mode);
    out->uid = metadata ? metadata->uid : group->uid;
    out->gid = metadata ? metadata->gid : group->gid;
    out->ctime = metadata ? metadata->ctime : group->ctime;
    out->mtime = out->ctime;
    out->fs_private[0] = kind;
    out->fs_private[1] = node;
    out->fs_private[2] = group->generation;
}

static int cgroupfs_cpu_interface(uint32_t kind) {
    return kind == CGROUPFS_INODE_CPU_WEIGHT ||
           kind == CGROUPFS_INODE_CPU_WEIGHT_NICE ||
           kind == CGROUPFS_INODE_CPU_MAX ||
           kind == CGROUPFS_INODE_CPU_MAX_BURST ||
           kind == CGROUPFS_INODE_CPU_IDLE ||
           kind == CGROUPFS_INODE_CPU_UCLAMP_MIN ||
           kind == CGROUPFS_INODE_CPU_UCLAMP_MAX ||
           kind == CGROUPFS_INODE_CPU_STAT;
}

static int cgroupfs_cpuset_interface(uint32_t kind) {
    return kind == CGROUPFS_INODE_CPUSET_CPUS ||
           kind == CGROUPFS_INODE_CPUSET_CPUS_EFFECTIVE ||
           kind == CGROUPFS_INODE_CPUSET_MEMS ||
           kind == CGROUPFS_INODE_CPUSET_MEMS_EFFECTIVE;
}

static int cgroupfs_cpuset_available_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0)) return 0;
    if (!node) return 1;
    node = g_cgroupfs.nodes[node].parent;
    return cgroupfs_node_valid(node, 0) &&
           (g_cgroupfs.nodes[node].subtree_controllers &
            CGROUPFS_CONTROLLER_CPUSET) != 0;
}

static int cgroupfs_cpu_available_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0)) return 0;
    if (!node) return 1;
    node = g_cgroupfs.nodes[node].parent;
    return cgroupfs_node_valid(node, 0) &&
           (g_cgroupfs.nodes[node].subtree_controllers &
            CGROUPFS_CONTROLLER_CPU) != 0;
}

static uint32_t cgroupfs_cpu_domain_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0)) node = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];

        if (cgroupfs_cpu_available_locked(node)) return node;
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    return 0;
}

static uint32_t cgroupfs_cpu_parent_domain_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0) || !node) return 0;
    node = g_cgroupfs.nodes[node].parent;
    return cgroupfs_cpu_domain_locked(node);
}

static int cgroupfs_pids_interface(uint32_t kind) {
    return kind == CGROUPFS_INODE_PIDS_CURRENT ||
           kind == CGROUPFS_INODE_PIDS_MAX ||
           kind == CGROUPFS_INODE_PIDS_EVENTS ||
           kind == CGROUPFS_INODE_PIDS_EVENTS_LOCAL ||
           kind == CGROUPFS_INODE_PIDS_PEAK;
}

static int cgroupfs_pids_available_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0)) return 0;
    if (!node) return 1;
    node = g_cgroupfs.nodes[node].parent;
    return cgroupfs_node_valid(node, 0) &&
           (g_cgroupfs.nodes[node].subtree_controllers &
            CGROUPFS_CONTROLLER_PIDS) != 0;
}

static int cgroupfs_memory_interface(uint32_t kind) {
    return kind == CGROUPFS_INODE_MEMORY_CURRENT ||
           kind == CGROUPFS_INODE_MEMORY_MIN ||
           kind == CGROUPFS_INODE_MEMORY_LOW ||
           kind == CGROUPFS_INODE_MEMORY_HIGH ||
           kind == CGROUPFS_INODE_MEMORY_MAX ||
           kind == CGROUPFS_INODE_MEMORY_PEAK ||
           kind == CGROUPFS_INODE_MEMORY_EVENTS ||
           kind == CGROUPFS_INODE_MEMORY_EVENTS_LOCAL ||
           kind == CGROUPFS_INODE_MEMORY_STAT ||
           kind == CGROUPFS_INODE_MEMORY_PRESSURE ||
           kind == CGROUPFS_INODE_MEMORY_OOM_GROUP ||
           kind == CGROUPFS_INODE_MEMORY_SWAP_CURRENT ||
           kind == CGROUPFS_INODE_MEMORY_SWAP_PEAK ||
           kind == CGROUPFS_INODE_MEMORY_SWAP_HIGH ||
           kind == CGROUPFS_INODE_MEMORY_SWAP_MAX ||
           kind == CGROUPFS_INODE_MEMORY_SWAP_EVENTS ||
           kind == CGROUPFS_INODE_MEMORY_RECLAIM;
}

static int cgroupfs_io_interface(uint32_t kind) {
    return kind == CGROUPFS_INODE_IO_STAT ||
           kind == CGROUPFS_INODE_IO_WEIGHT ||
           kind == CGROUPFS_INODE_IO_MAX;
}

static int cgroupfs_io_available_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0)) return 0;
    if (!node) return 1;
    node = g_cgroupfs.nodes[node].parent;
    return cgroupfs_node_valid(node, 0) &&
           (g_cgroupfs.nodes[node].subtree_controllers &
            CGROUPFS_CONTROLLER_IO) != 0;
}

static int cgroupfs_memory_available_locked(uint32_t node) {
    if (!cgroupfs_node_valid(node, 0)) return 0;
    if (!node) return 1;
    node = g_cgroupfs.nodes[node].parent;
    return cgroupfs_node_valid(node, 0) &&
           (g_cgroupfs.nodes[node].subtree_controllers &
            CGROUPFS_CONTROLLER_MEMORY) != 0;
}

static int cgroupfs_interface_visible_locked(uint32_t node, uint32_t kind) {
    if ((kind == CGROUPFS_INODE_KILL ||
         kind == CGROUPFS_INODE_FREEZE) && node == 0)
        return 0;
    if (cgroupfs_cpuset_interface(kind))
        return cgroupfs_cpuset_available_locked(node);
    if (cgroupfs_cpu_interface(kind))
        return cgroupfs_cpu_available_locked(node);
    if (cgroupfs_pids_interface(kind))
        return cgroupfs_pids_available_locked(node);
    if (cgroupfs_memory_interface(kind))
        return cgroupfs_memory_available_locked(node);
    if (cgroupfs_io_interface(kind))
        return cgroupfs_io_available_locked(node);
    return 1;
}

static int cgroupfs_find_child(uint32_t parent, const char *name) {
    if (!name) return -1;
    for (uint32_t index = 1; index < CGROUPFS_MAX_NODES; ++index) {
        cgroupfs_node_t *node = &g_cgroupfs.nodes[index];
        if (node->used && node->parent == parent &&
            strcmp(node->name, name) == 0)
            return (int)index;
    }
    return -1;
}

static int cgroupfs_interface(const char *name,
                              const cgroupfs_interface_t **interface_out) {
    for (uint32_t index = 0;
         index < sizeof(g_cgroup_interfaces) / sizeof(g_cgroup_interfaces[0]);
         ++index) {
        if (strcmp(name, g_cgroup_interfaces[index].name) != 0) continue;
        if (interface_out) *interface_out = &g_cgroup_interfaces[index];
        return 0;
    }
    return -1;
}

static uint32_t cgroupfs_node_depth(uint32_t node) {
    uint32_t depth = 0;
    while (node && depth < CGROUPFS_MAX_NODES) {
        if (!cgroupfs_node_valid(node, 0)) return CGROUPFS_LIMIT_MAX;
        node = g_cgroupfs.nodes[node].parent;
        ++depth;
    }
    return depth;
}

static int cgroupfs_is_descendant(uint32_t node, uint32_t ancestor) {
    for (uint32_t depth = 0; depth < CGROUPFS_MAX_NODES; ++depth) {
        if (!cgroupfs_node_valid(node, 0)) return 0;
        if (node == ancestor) return 1;
        if (!node) return 0;
        node = g_cgroupfs.nodes[node].parent;
    }
    return 0;
}

static int cgroupfs_kill_subtree_locked(
        uint32_t node, const kernel_linux_identity_t *identity) {
    struct edge_linux_siginfo information;

    if (!identity || !cgroupfs_node_valid(node, 0)) return -1;
    kernel_signal_info_build_sender(
        &information, 9u, EDGE_LINUX_SI_USER,
        identity->global_tgid, identity->uid, 0u);
    for (uint32_t ordinal = 0;; ++ordinal) {
        kernel_proc_task_snapshot_t task;
        int32_t pid;
        int result;

        if (kernel_proc_task_at(ordinal, &pid) < 0) break;
        if (kernel_proc_task_snapshot(pid, &task) < 0 || task.state == 'Z' ||
            !cgroupfs_is_descendant(task.cgroup_id, node))
            continue;
        result = kernel_linux_signal_send(pid, 9u, 0, &information);
        if (result < 0 && result != -EDGE_LINUX_ESRCH) return -1;
    }
    return 0;
}

static uint32_t cgroupfs_descendant_count(uint32_t node) {
    uint32_t count = 0;
    for (uint32_t index = 1; index < CGROUPFS_MAX_NODES; ++index)
        if (index != node && g_cgroupfs.nodes[index].used &&
            cgroupfs_is_descendant(index, node))
            ++count;
    return count;
}

static uint32_t cgroupfs_subtree_height(uint32_t node) {
    uint32_t base_depth = cgroupfs_node_depth(node);
    uint32_t height = 0;
    for (uint32_t index = 1; index < CGROUPFS_MAX_NODES; ++index) {
        uint32_t depth;
        if (!g_cgroupfs.nodes[index].used ||
            !cgroupfs_is_descendant(index, node))
            continue;
        depth = cgroupfs_node_depth(index);
        if (depth != CGROUPFS_LIMIT_MAX && depth >= base_depth &&
            depth - base_depth > height)
            height = depth - base_depth;
    }
    return height;
}

static int cgroupfs_render_tasks(uint32_t node, int threads, char *buffer,
                                 uint32_t capacity, uint32_t *offset) {
    for (uint32_t process_ordinal = 0;; ++process_ordinal) {
        kernel_proc_task_snapshot_t leader;
        int32_t pid;
        if (kernel_proc_task_at(process_ordinal, &pid) < 0) break;
        if (kernel_proc_task_snapshot(pid, &leader) < 0 || leader.state == 'Z')
            continue;
        if (!threads) {
            if (leader.cgroup_id != node) continue;
            if (cgroupfs_append_u32(buffer, capacity, offset,
                                    (uint32_t)leader.tgid) < 0 ||
                cgroupfs_append(buffer, capacity, offset, "\n") < 0)
                return -1;
            continue;
        }
        for (uint32_t thread_ordinal = 0;; ++thread_ordinal) {
            kernel_proc_task_snapshot_t thread;
            int32_t tid;
            if (kernel_proc_thread_at(leader.tgid, thread_ordinal, &tid) < 0)
                break;
            if (kernel_proc_task_snapshot(tid, &thread) < 0 ||
                thread.state == 'Z' || thread.cgroup_id != node)
                continue;
            if (cgroupfs_append_u32(buffer, capacity, offset,
                                    (uint32_t)thread.pid) < 0 ||
                cgroupfs_append(buffer, capacity, offset, "\n") < 0)
                return -1;
        }
    }
    return 0;
}

static int cgroupfs_populated(uint32_t node) {
    return cgroupfs_node_valid(node, 0) &&
           g_cgroupfs.nodes[node].subtree_task_count != 0;
}

static int cgroupfs_event_path_locked(uint32_t node, char *path,
                                      uint32_t capacity) {
    uint32_t chain[CGROUPFS_MAX_NODES];
    uint32_t count = 0;
    uint32_t offset = 0;
    if (!path || !capacity || !g_cgroupfs_sb.mountpoint[0] ||
        !cgroupfs_node_valid(node, 0))
        return -1;
    path[0] = 0;
    if (cgroupfs_append(path, capacity, &offset,
                        g_cgroupfs_sb.mountpoint) < 0)
        return -1;
    while (offset > 1u && path[offset - 1u] == '/') path[--offset] = 0;
    while (node && count < CGROUPFS_MAX_NODES) {
        chain[count++] = node;
        node = g_cgroupfs.nodes[node].parent;
    }
    if (node) return -1;
    while (count) {
        if (cgroupfs_append(path, capacity, &offset, "/") < 0 ||
            cgroupfs_append(path, capacity, &offset,
                            g_cgroupfs.nodes[chain[--count]].name) < 0)
            return -1;
    }
    if (cgroupfs_append(path, capacity, &offset,
                        "/cgroup.events") < 0)
        return -1;
    return 0;
}

static void cgroupfs_note_population_locked(uint32_t node,
                                           uint8_t previous) {
    cgroupfs_node_t *group;
    uint8_t populated;
    if (!cgroupfs_node_valid(node, 0)) return;
    group = &g_cgroupfs.nodes[node];
    populated = group->subtree_task_count != 0;
    group->populated = populated;
    group->populated_known = 1u;
    if (previous == populated ||
        cgroupfs_event_path_locked(node, g_cgroupfs_event_path,
                                   sizeof(g_cgroupfs_event_path)) < 0)
        return;
    kernel_inotify_notify_path(g_cgroupfs_event_path,
                               KERNEL_INOTIFY_MODIFY, 0);
}

static void cgroupfs_adjust_task_count_locked(uint32_t node, int delta) {
    uint32_t current;
    if (!cgroupfs_node_valid(node, 0)) node = 0;
    if (delta > 0) {
        if (g_cgroupfs.nodes[node].task_count != UINT32_MAX)
            ++g_cgroupfs.nodes[node].task_count;
    } else if (g_cgroupfs.nodes[node].task_count) {
        --g_cgroupfs.nodes[node].task_count;
    } else {
        return;
    }
    current = node;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[current];
        uint8_t previous = group->subtree_task_count != 0;
        if (delta > 0) {
            if (group->subtree_task_count != UINT32_MAX)
                ++group->subtree_task_count;
        } else if (group->subtree_task_count) {
            --group->subtree_task_count;
        }
        if (!group->subtree_task_count && current)
            group->cpu_scheduler_vruntime_valid = 0u;
        if (group->subtree_task_count > group->pids_peak)
            group->pids_peak = group->subtree_task_count;
        cgroupfs_note_population_locked(current, previous);
        if (!current) break;
        current = group->parent;
        if (!cgroupfs_node_valid(current, 0)) current = 0;
    }
}

static void cgroupfs_rebuild_task_counts_locked(void) {
    uint8_t previous[CGROUPFS_MAX_NODES];
    for (uint32_t node = 0; node < CGROUPFS_MAX_NODES; ++node) {
        previous[node] = g_cgroupfs.nodes[node].populated;
        g_cgroupfs.nodes[node].task_count = 0;
        g_cgroupfs.nodes[node].subtree_task_count = 0;
    }
    for (uint32_t process_ordinal = 0;; ++process_ordinal) {
        kernel_proc_task_snapshot_t leader;
        int32_t pid;
        if (kernel_proc_task_at(process_ordinal, &pid) < 0) break;
        if (kernel_proc_task_snapshot(pid, &leader) < 0 || leader.state == 'Z')
            continue;
        for (uint32_t thread_ordinal = 0;; ++thread_ordinal) {
            kernel_proc_task_snapshot_t thread;
            uint32_t node;
            int32_t tid;
            if (kernel_proc_thread_at(leader.tgid, thread_ordinal, &tid) < 0)
                break;
            if (kernel_proc_task_snapshot(tid, &thread) < 0 ||
                thread.state == 'Z')
                continue;
            node = cgroupfs_node_valid(thread.cgroup_id, 0) ?
                   thread.cgroup_id : 0;
            if (g_cgroupfs.nodes[node].task_count != UINT32_MAX)
                ++g_cgroupfs.nodes[node].task_count;
            for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
                cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
                if (group->subtree_task_count != UINT32_MAX)
                    ++group->subtree_task_count;
                if (!node) break;
                node = cgroupfs_node_valid(group->parent, 0) ?
                       group->parent : 0;
            }
        }
    }
    for (uint32_t node = 0; node < CGROUPFS_MAX_NODES; ++node)
        if (cgroupfs_node_valid(node, 0)) {
            if (g_cgroupfs.nodes[node].subtree_task_count >
                g_cgroupfs.nodes[node].pids_peak)
                g_cgroupfs.nodes[node].pids_peak =
                    g_cgroupfs.nodes[node].subtree_task_count;
            cgroupfs_note_population_locked(node, previous[node]);
        }
}

void cgroupfs_task_state_changed(uint32_t cgroup_id) {
    (void)cgroup_id;
    if (!g_cgroupfs.initialized) return;
    cgroupfs_lock(&g_cgroupfs_lock);
    cgroupfs_rebuild_task_counts_locked();
    cgroupfs_unlock(&g_cgroupfs_lock);
}

void cgroupfs_task_join(uint32_t cgroup_id) {
    if (!g_cgroupfs.initialized) return;
    cgroupfs_lock(&g_cgroupfs_lock);
    cgroupfs_adjust_task_count_locked(cgroup_id, 1);
    cgroupfs_unlock(&g_cgroupfs_lock);
}

void cgroupfs_task_leave(uint32_t cgroup_id) {
    if (!g_cgroupfs.initialized) return;
    cgroupfs_lock(&g_cgroupfs_lock);
    cgroupfs_adjust_task_count_locked(cgroup_id, -1);
    cgroupfs_unlock(&g_cgroupfs_lock);
}

int cgroupfs_task_frozen(uint32_t cgroup_id) {
    int frozen = 0;

    if (!g_cgroupfs.initialized) return 0;
    /* Scheduler queries can run from a timer interrupt. */
    if (!cgroupfs_try_lock(&g_cgroupfs_lock)) return 0;
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[cgroup_id];
        if (group->frozen) {
            frozen = 1;
            break;
        }
        if (!cgroup_id) break;
        cgroup_id = cgroupfs_node_valid(group->parent, 0) ?
                    group->parent : 0;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    return frozen;
}

int cgroupfs_pids_validate_task(int32_t pid, int already_counted) {
    kernel_proc_task_snapshot_t task;
    uint32_t failed_node = 0;
    uint32_t node;
    int allowed = 1;

    if (pid <= 0 || !g_cgroupfs.initialized) return 0;
    if (kernel_proc_task_snapshot(pid, &task) < 0) return -1;
    cgroupfs_lock(&g_cgroupfs_lock);
    node = cgroupfs_node_valid(task.cgroup_id, 0) ? task.cgroup_id : 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        uint32_t prospective = group->subtree_task_count;
        if (!already_counted && prospective != UINT32_MAX) ++prospective;
        if (cgroupfs_pids_available_locked(node) &&
            group->pids_max != CGROUPFS_LIMIT_MAX &&
            prospective > group->pids_max) {
            allowed = 0;
            failed_node = node;
            break;
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    if (!allowed) {
        g_cgroupfs.nodes[failed_node].pids_max_events_local =
            cgroupfs_u64_add_saturating(
                g_cgroupfs.nodes[failed_node].pids_max_events_local, 1u);
        node = failed_node;
        for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
            cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
            group->pids_max_events = cgroupfs_u64_add_saturating(
                group->pids_max_events, 1u);
            if (!node) break;
            node = cgroupfs_node_valid(group->parent, 0) ?
                   group->parent : 0;
        }
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    return allowed ? 0 : -1;
}

int cgroupfs_memory_charge(uint32_t cgroup_id, uint64_t bytes,
                           uint32_t *oom_cgroup_id) {
    uint32_t failed_node = 0;
    uint32_t node;
    uint64_t memory_flags;
    int allowed = 1;

    if (oom_cgroup_id) *oom_cgroup_id = 0;
    if (!bytes) return 0;
    if (!g_cgroupfs.initialized) cgroupfs_initialize();
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        uint64_t prospective = cgroupfs_u64_add_saturating(
            group->memory_current, bytes);
        if (node != 0 && cgroupfs_memory_available_locked(node) &&
            group->memory_high != UINT64_MAX &&
            (prospective == UINT64_MAX ||
             prospective > group->memory_high)) {
            group->memory_high_events = cgroupfs_u64_add_saturating(
                group->memory_high_events, 1u);
            if (node == cgroup_id)
                group->memory_high_events_local =
                    cgroupfs_u64_add_saturating(
                        group->memory_high_events_local, 1u);
        }
        if (node != 0 && cgroupfs_memory_available_locked(node) &&
            group->memory_max != UINT64_MAX &&
            (prospective == UINT64_MAX || prospective > group->memory_max)) {
            failed_node = node;
            allowed = 0;
            break;
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    if (!allowed) {
        cgroupfs_node_t *failed = &g_cgroupfs.nodes[failed_node];
        failed->memory_oom_events_local = cgroupfs_u64_add_saturating(
            failed->memory_oom_events_local, 1u);
        node = failed_node;
        for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
            cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
            group->memory_oom_events = cgroupfs_u64_add_saturating(
                group->memory_oom_events, 1u);
            if (!node) break;
            node = cgroupfs_node_valid(group->parent, 0) ?
                   group->parent : 0;
        }
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        if (oom_cgroup_id) *oom_cgroup_id = failed_node;
        return -1;
    }
    g_cgroupfs.nodes[cgroup_id].memory_direct =
        cgroupfs_u64_add_saturating(
            g_cgroupfs.nodes[cgroup_id].memory_direct, bytes);
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        group->memory_current = cgroupfs_u64_add_saturating(
            group->memory_current, bytes);
        if (group->memory_current > group->memory_peak)
            group->memory_peak = group->memory_current;
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
    return 0;
}

int cgroupfs_memory_prepare_charge(uint32_t cgroup_id, uint64_t bytes,
                                   uint64_t *excess_bytes) {
    uint32_t failed_node = 0;
    uint32_t node;
    uint64_t excess = 0;
    uint64_t memory_flags;

    if (excess_bytes) *excess_bytes = 0;
    if (!bytes) return 0;
    if (!g_cgroupfs.initialized) cgroupfs_initialize();
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        uint64_t prospective = cgroupfs_u64_add_saturating(
            group->memory_current, bytes);

        if (node != 0 && cgroupfs_memory_available_locked(node) &&
            group->memory_max != UINT64_MAX &&
            (prospective == UINT64_MAX || prospective > group->memory_max)) {
            failed_node = node;
            excess = prospective == UINT64_MAX ? bytes :
                     prospective - group->memory_max;
            break;
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    if (failed_node) {
        cgroupfs_node_t *failed = &g_cgroupfs.nodes[failed_node];

        failed->memory_max_events_local = cgroupfs_u64_add_saturating(
            failed->memory_max_events_local, 1u);
        node = failed_node;
        for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
            cgroupfs_node_t *group = &g_cgroupfs.nodes[node];

            group->memory_max_events = cgroupfs_u64_add_saturating(
                group->memory_max_events, 1u);
            if (!node) break;
            node = cgroupfs_node_valid(group->parent, 0) ?
                   group->parent : 0;
        }
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
    if (excess_bytes) *excess_bytes = excess;
    return failed_node ? 1 : 0;
}

void cgroupfs_memory_uncharge(uint32_t cgroup_id, uint64_t bytes) {
    uint32_t node;
    uint64_t memory_flags;

    if (!bytes || !g_cgroupfs.initialized) return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    if (g_cgroupfs.nodes[cgroup_id].memory_direct > bytes)
        g_cgroupfs.nodes[cgroup_id].memory_direct -= bytes;
    else
        g_cgroupfs.nodes[cgroup_id].memory_direct = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (group->memory_current > bytes)
            group->memory_current -= bytes;
        else
            group->memory_current = 0;
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

void cgroupfs_memory_note_fault(uint32_t cgroup_id, int major) {
    uint64_t memory_flags;
    uint32_t node;

    if (!g_cgroupfs.initialized) return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        uint64_t *counter = major ? &group->memory_major_faults :
                                    &group->memory_minor_faults;

        *counter = cgroupfs_u64_add_saturating(*counter, 1u);
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

void cgroupfs_memory_note_reclaim(uint32_t cgroup_id,
                                  uint64_t scanned_pages,
                                  uint64_t reclaimed_pages) {
    uint64_t memory_flags;
    uint32_t node;

    if ((!scanned_pages && !reclaimed_pages) || !g_cgroupfs.initialized)
        return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];

        group->memory_scanned_pages = cgroupfs_u64_add_saturating(
            group->memory_scanned_pages, scanned_pages);
        group->memory_reclaimed_pages = cgroupfs_u64_add_saturating(
            group->memory_reclaimed_pages, reclaimed_pages);
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

void cgroupfs_memory_note_pressure(uint32_t cgroup_id, uint64_t now_us,
                                   uint64_t some_stall_us,
                                   uint64_t full_stall_us) {
    uint64_t memory_flags;
    uint32_t node;

    if ((!some_stall_us && !full_stall_us) || !g_cgroupfs.initialized)
        return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];

        edge_mm_pressure_record(&group->memory_pressure, now_us,
                                some_stall_us, full_stall_us);
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

int cgroupfs_memory_pressure(uint32_t cgroup_id, uint64_t *excess_bytes) {
    uint64_t memory_flags;
    uint64_t excess = 0;
    uint32_t node;

    if (excess_bytes) *excess_bytes = 0;
    if (!g_cgroupfs.initialized) return 0;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (node != 0 && cgroupfs_memory_available_locked(node) &&
            group->memory_high != UINT64_MAX &&
            group->memory_current > group->memory_high) {
            uint64_t current_excess =
                group->memory_current - group->memory_high;
            if (current_excess > excess) excess = current_excess;
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
    if (excess_bytes) *excess_bytes = excess;
    return excess != 0;
}

void cgroupfs_memory_note_low_reclaim(uint32_t cgroup_id) {
    uint64_t memory_flags;
    uint32_t node;

    if (!g_cgroupfs.initialized) return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        group->memory_low_events = cgroupfs_u64_add_saturating(
            group->memory_low_events, 1u);
        if (node == cgroup_id)
            group->memory_low_events_local =
                cgroupfs_u64_add_saturating(
                    group->memory_low_events_local, 1u);
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

void cgroupfs_memory_note_oom_kill(uint32_t cgroup_id) {
    uint32_t node;
    uint64_t memory_flags;

    if (!g_cgroupfs.initialized) return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    g_cgroupfs.nodes[cgroup_id].memory_oom_kill_events_local =
        cgroupfs_u64_add_saturating(
            g_cgroupfs.nodes[cgroup_id].memory_oom_kill_events_local, 1u);
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        group->memory_oom_kill_events = cgroupfs_u64_add_saturating(
            group->memory_oom_kill_events, 1u);
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

int cgroupfs_memory_oom_group_kill(uint32_t oom_cgroup_id,
                                   int32_t fault_tgid) {
    kernel_linux_identity_t identity;
    struct edge_linux_siginfo information;
    uint64_t memory_flags;
    int enabled;

    if (!g_cgroupfs.initialized || fault_tgid <= 0) return 0;
    if (kernel_current_linux_identity(&identity) < 0) return 0;
    cgroupfs_lock(&g_cgroupfs_lock);
    enabled = cgroupfs_node_valid(oom_cgroup_id, 0) &&
              g_cgroupfs.nodes[oom_cgroup_id].memory_oom_group;
    if (!enabled) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }

    kernel_signal_info_build_sender(
        &information, 9u, EDGE_LINUX_SI_USER,
        identity.global_tgid, identity.uid, 0u);
    for (uint32_t ordinal = 0;; ++ordinal) {
        kernel_proc_task_view_t task;
        int32_t pid;
        int result;

        if (kernel_proc_task_at(ordinal, &pid) < 0) break;
        if (pid <= 1 || pid == fault_tgid ||
            kernel_proc_task_view_get(pid, &task) < 0 ||
            task.state == KERNEL_PROC_TASK_ZOMBIE ||
            task.oom_score_adj <= -1000 ||
            !cgroupfs_is_descendant(task.cgroup_id, oom_cgroup_id))
            continue;
        result = kernel_linux_signal_send(pid, 9u, 0, &information);
        if (result < 0 && result != -EDGE_LINUX_ESRCH) continue;
        if (result == 0) cgroupfs_memory_note_oom_kill(task.cgroup_id);
    }

    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (cgroupfs_node_valid(oom_cgroup_id, 0)) {
        uint32_t node = oom_cgroup_id;

        g_cgroupfs.nodes[oom_cgroup_id].memory_oom_group_kill_events_local =
            cgroupfs_u64_add_saturating(
                g_cgroupfs.nodes[oom_cgroup_id]
                    .memory_oom_group_kill_events_local,
                1u);
        for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
            cgroupfs_node_t *group = &g_cgroupfs.nodes[node];

            group->memory_oom_group_kill_events =
                cgroupfs_u64_add_saturating(
                    group->memory_oom_group_kill_events, 1u);
            if (!node) break;
            node = cgroupfs_node_valid(group->parent, 0) ?
                   group->parent : 0;
        }
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
    cgroupfs_unlock(&g_cgroupfs_lock);
    return 1;
}

int cgroupfs_memory_swap_charge(uint32_t cgroup_id, uint64_t bytes) {
    uint64_t memory_flags;
    uint32_t node;

    if (!bytes) return 0;
    if (!g_cgroupfs.initialized) cgroupfs_initialize();
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        uint64_t prospective = cgroupfs_u64_add_saturating(
            group->memory_swap_current, bytes);
        if (node != 0 && cgroupfs_memory_available_locked(node) &&
            group->memory_swap_high != UINT64_MAX &&
            (prospective == UINT64_MAX ||
             prospective > group->memory_swap_high))
            group->memory_swap_high_events =
                cgroupfs_u64_add_saturating(
                    group->memory_swap_high_events, 1u);
        if (node != 0 && cgroupfs_memory_available_locked(node) &&
            group->memory_swap_max != UINT64_MAX &&
            (prospective == UINT64_MAX ||
             prospective > group->memory_swap_max)) {
            group->memory_swap_max_events =
                cgroupfs_u64_add_saturating(
                    group->memory_swap_max_events, 1u);
            group->memory_swap_fail_events =
                cgroupfs_u64_add_saturating(
                    group->memory_swap_fail_events, 1u);
            spin_unlock_irqrestore(
                &g_cgroupfs_memory_lock, memory_flags);
            return -1;
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        group->memory_swap_current = cgroupfs_u64_add_saturating(
            group->memory_swap_current, bytes);
        if (group->memory_swap_current > group->memory_swap_peak)
            group->memory_swap_peak = group->memory_swap_current;
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
    return 0;
}

void cgroupfs_memory_swap_uncharge(uint32_t cgroup_id, uint64_t bytes) {
    uint64_t memory_flags;
    uint32_t node;

    if (!bytes || !g_cgroupfs.initialized) return;
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    node = cgroup_id;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (group->memory_swap_current > bytes)
            group->memory_swap_current -= bytes;
        else
            group->memory_swap_current = 0;
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ?
               group->parent : 0;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
}

static uint32_t cgroupfs_current_node(void) {
    kernel_task_identity_view_t identity;
    kernel_proc_task_view_t task;

    if (kernel_arch_current_identity_sample(&identity) < 0 ||
        kernel_arch_proc_task_lookup(identity.tid, &task) < 0)
        return 0;
    return task.cgroup_id;
}

static cgroupfs_io_device_t *cgroupfs_io_device_locked(
    cgroupfs_node_t *group, uint32_t major, uint32_t minor, int allocate) {
    cgroupfs_io_device_t *free_slot = 0;

    if (!group) return 0;
    for (uint32_t index = 0; index < CGROUPFS_IO_DEVICE_SLOTS; ++index) {
        cgroupfs_io_device_t *device = &group->io_devices[index];
        if (device->used && device->major == major &&
            device->minor == minor)
            return device;
        if (!device->used && !free_slot) free_slot = device;
    }
    if (!allocate || !free_slot) return 0;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1u;
    free_slot->major = major;
    free_slot->minor = minor;
    return free_slot;
}

static uint64_t cgroupfs_io_rate_interval(uint64_t amount,
                                         uint64_t per_second) {
    uint64_t whole;
    uint64_t remainder;
    uint64_t interval;

    if (!amount || !per_second) return 0;
    whole = amount / per_second;
    remainder = amount % per_second;
    if (whole > UINT64_MAX / 1000000u) return UINT64_MAX;
    interval = whole * 1000000u;
    if (remainder) {
        uint64_t fractional = remainder > UINT64_MAX / 1000000u ?
            UINT64_MAX : remainder * 1000000u;
        fractional = fractional == UINT64_MAX ? UINT64_MAX :
                     (fractional + per_second - 1u) / per_second;
        interval = cgroupfs_u64_add_saturating(interval, fractional);
    }
    return interval;
}

static uint64_t cgroupfs_io_reserve_deadline(uint64_t *cursor,
                                             uint64_t now_us,
                                             uint64_t interval_us) {
    uint64_t start;

    if (!cursor || !interval_us) return now_us;
    start = *cursor > now_us ? *cursor : now_us;
    *cursor = cgroupfs_u64_add_saturating(start, interval_us);
    return start;
}

void cgroupfs_io_begin(uint32_t major, uint32_t minor, int write,
                       uint64_t bytes) {
    uint32_t node;
    uint64_t now_us;
    uint64_t deadline_us;

    if (!bytes || !g_cgroupfs.initialized) return;
    node = cgroupfs_current_node();
    now_us = boottime_monotonic_us();
    deadline_us = now_us;
    cgroupfs_lock(&g_cgroupfs_lock);
    if (!cgroupfs_node_valid(node, 0)) node = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        cgroupfs_io_device_t *device = cgroupfs_io_device_locked(
            group, major, minor, 1);
        if (device) {
            uint32_t weight = device->weight ? device->weight :
                              group->io_weight;
            uint64_t quanta =
                (bytes + CGROUPFS_IO_WEIGHT_QUANTUM_BYTES - 1u) /
                CGROUPFS_IO_WEIGHT_QUANTUM_BYTES;
            uint64_t weighted_interval =
                (quanta * CGROUPFS_IO_WEIGHT_DEFAULT + weight - 1u) /
                weight;
            uint64_t candidate = cgroupfs_io_reserve_deadline(
                &device->weighted_deadline_us, now_us,
                weighted_interval);
            uint64_t byte_rate = write ? device->write_bytes_per_second :
                                         device->read_bytes_per_second;
            uint64_t operation_rate = write ?
                device->write_operations_per_second :
                device->read_operations_per_second;
            uint64_t *byte_cursor = write ?
                &device->write_byte_deadline_us :
                &device->read_byte_deadline_us;
            uint64_t *operation_cursor = write ?
                &device->write_operation_deadline_us :
                &device->read_operation_deadline_us;
            if (candidate > deadline_us) deadline_us = candidate;
            candidate = cgroupfs_io_reserve_deadline(
                byte_cursor, now_us,
                cgroupfs_io_rate_interval(bytes, byte_rate));
            if (candidate > deadline_us) deadline_us = candidate;
            candidate = cgroupfs_io_reserve_deadline(
                operation_cursor, now_us,
                cgroupfs_io_rate_interval(1u, operation_rate));
            if (candidate > deadline_us) deadline_us = candidate;
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    if (deadline_us > now_us)
        (void)kernel_current_sleep_until(deadline_us, 0, 0, 0);
}

void cgroupfs_io_complete(uint32_t major, uint32_t minor, int write,
                          uint64_t bytes) {
    uint32_t node;

    if (!bytes || !g_cgroupfs.initialized) return;
    node = cgroupfs_current_node();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (!cgroupfs_node_valid(node, 0)) node = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        cgroupfs_io_device_t *device = cgroupfs_io_device_locked(
            group, major, minor, 1);
        if (device) {
            if (write) {
                device->write_bytes = cgroupfs_u64_add_saturating(
                    device->write_bytes, bytes);
                device->write_operations = cgroupfs_u64_add_saturating(
                    device->write_operations, 1u);
            } else {
                device->read_bytes = cgroupfs_u64_add_saturating(
                    device->read_bytes, bytes);
                device->read_operations = cgroupfs_u64_add_saturating(
                    device->read_operations, 1u);
            }
        }
        if (!node) break;
        node = cgroupfs_node_valid(group->parent, 0) ? group->parent : 0;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
}

static void cgroupfs_cpu_refresh_locked(cgroupfs_node_t *group,
                                        uint64_t now_us) {
    uint64_t elapsed_periods;
    uint64_t next_period_start;

    if (!group || !group->cpu_period_us) return;
    if (!group->cpu_period_start_us) {
        group->cpu_period_start_us =
            now_us - (now_us % group->cpu_period_us);
        return;
    }
    if (now_us - group->cpu_period_start_us < group->cpu_period_us)
        return;
    elapsed_periods =
        (now_us - group->cpu_period_start_us) / group->cpu_period_us;
    next_period_start = group->cpu_period_start_us +
                        elapsed_periods * group->cpu_period_us;
    group->cpu_nr_periods = cgroupfs_u64_add_saturating(
        group->cpu_nr_periods, elapsed_periods);
    if (group->cpu_quota_us != CGROUPFS_CPU_QUOTA_MAX &&
        group->cpu_burst_us) {
        uint64_t credit = group->cpu_burst_credit_us;

        if (group->cpu_period_usage_us < group->cpu_quota_us) {
            credit = cgroupfs_u64_add_saturating(
                credit,
                group->cpu_quota_us - group->cpu_period_usage_us);
        } else if (group->cpu_period_usage_us > group->cpu_quota_us) {
            uint64_t consumed =
                group->cpu_period_usage_us - group->cpu_quota_us;
            credit = consumed < credit ? credit - consumed : 0u;
        }
        if (elapsed_periods > 1u) {
            uint64_t empty_periods = elapsed_periods - 1u;
            uint64_t earned =
                empty_periods > UINT64_MAX / group->cpu_quota_us ?
                UINT64_MAX : empty_periods * group->cpu_quota_us;
            credit = cgroupfs_u64_add_saturating(credit, earned);
        }
        group->cpu_burst_credit_us =
            credit < group->cpu_burst_us ? credit : group->cpu_burst_us;
    } else {
        group->cpu_burst_credit_us = 0u;
    }
    if (group->cpu_throttled && group->cpu_throttle_start_us) {
        uint64_t throttle_end = next_period_start < now_us ?
                                next_period_start : now_us;
        if (throttle_end > group->cpu_throttle_start_us)
            group->cpu_throttled_us = cgroupfs_u64_add_saturating(
                group->cpu_throttled_us,
                throttle_end - group->cpu_throttle_start_us);
    }
    group->cpu_period_start_us = next_period_start;
    group->cpu_period_usage_us = 0;
    group->cpu_throttled = 0;
    group->cpu_throttle_start_us = 0;
}

static int cgroupfs_cpu_group_runnable_locked(cgroupfs_node_t *group,
                                              uint64_t now_us) {
    uint64_t runtime_limit;

    if (!group) return 1;
    cgroupfs_cpu_refresh_locked(group, now_us);
    if (group->cpu_quota_us == CGROUPFS_CPU_QUOTA_MAX)
        return 1;
    runtime_limit = cgroupfs_u64_add_saturating(
        group->cpu_quota_us, group->cpu_burst_credit_us);
    if (group->cpu_period_usage_us < runtime_limit) return 1;
    if (!group->cpu_throttled) {
        group->cpu_throttled = 1;
        group->cpu_throttle_start_us = now_us;
        group->cpu_nr_throttled = cgroupfs_u64_add_saturating(
            group->cpu_nr_throttled, 1u);
    }
    return 0;
}

static uint64_t cgroupfs_cpu_weighted_vruntime_delta(uint64_t runtime_us,
                                                     uint32_t weight) {
    uint64_t quotient;
    uint64_t remainder;
    uint64_t scaled;
    uint64_t fraction;

    if (!runtime_us) return 0;
    if (!weight) weight = CGROUPFS_CPU_WEIGHT_DEFAULT;
    quotient = runtime_us / weight;
    remainder = runtime_us % weight;
    if (quotient > UINT64_MAX / CGROUPFS_CPU_WEIGHT_DEFAULT)
        return UINT64_MAX;
    scaled = quotient * CGROUPFS_CPU_WEIGHT_DEFAULT;
    fraction = (remainder * CGROUPFS_CPU_WEIGHT_DEFAULT + weight - 1u) /
               weight;
    return scaled > UINT64_MAX - fraction ? UINT64_MAX : scaled + fraction;
}

static uint64_t cgroupfs_cpu_initial_vruntime_locked(uint32_t node) {
    uint32_t parent = cgroupfs_cpu_parent_domain_locked(node);
    uint64_t minimum = UINT64_MAX;

    for (uint32_t sibling = 1; sibling < CGROUPFS_MAX_NODES; ++sibling) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[sibling];

        if (!group->used || sibling == node || !group->subtree_task_count ||
            !group->cpu_scheduler_vruntime_valid ||
            !cgroupfs_cpu_available_locked(sibling) ||
            cgroupfs_cpu_parent_domain_locked(sibling) != parent)
            continue;
        if (group->cpu_scheduler_vruntime_us < minimum)
            minimum = group->cpu_scheduler_vruntime_us;
    }
    return minimum == UINT64_MAX ? 0u : minimum;
}

static void cgroupfs_cpu_account_group_locked(uint32_t node,
                                              uint64_t runtime_us) {
    cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
    uint64_t delta;

    if (!group->cpu_scheduler_vruntime_valid) {
        group->cpu_scheduler_vruntime_us =
            cgroupfs_cpu_initial_vruntime_locked(node);
        group->cpu_scheduler_vruntime_valid = 1u;
    }
    delta = cgroupfs_cpu_weighted_vruntime_delta(runtime_us,
                                                 group->cpu_weight);
    group->cpu_scheduler_vruntime_us = cgroupfs_u64_add_saturating(
        group->cpu_scheduler_vruntime_us, delta);
}

static uint32_t cgroupfs_cpu_domain_depth_locked(uint32_t node) {
    uint32_t depth = 0u;

    node = cgroupfs_cpu_domain_locked(node);
    while (node && depth < CGROUPFS_MAX_NODES) {
        ++depth;
        node = cgroupfs_cpu_parent_domain_locked(node);
    }
    return depth;
}

int cgroupfs_cpu_group_order(uint32_t candidate_cgroup_id,
                            uint32_t current_cgroup_id) {
    uint32_t candidate;
    uint32_t current;
    uint32_t candidate_child;
    uint32_t current_child;
    uint32_t candidate_depth;
    uint32_t current_depth;
    int order = 0;

    if (!g_cgroupfs.initialized) return 0;
    if (!cgroupfs_try_lock(&g_cgroupfs_lock)) return 0;
    candidate = cgroupfs_cpu_domain_locked(candidate_cgroup_id);
    current = cgroupfs_cpu_domain_locked(current_cgroup_id);
    if (candidate == current) goto out;
    candidate_child = candidate;
    current_child = current;
    candidate_depth = cgroupfs_cpu_domain_depth_locked(candidate);
    current_depth = cgroupfs_cpu_domain_depth_locked(current);
    while (candidate_depth > current_depth) {
        candidate_child = candidate;
        candidate = cgroupfs_cpu_parent_domain_locked(candidate);
        --candidate_depth;
    }
    while (current_depth > candidate_depth) {
        current_child = current;
        current = cgroupfs_cpu_parent_domain_locked(current);
        --current_depth;
    }
    while (candidate != current) {
        candidate_child = candidate;
        current_child = current;
        candidate = cgroupfs_cpu_parent_domain_locked(candidate);
        current = cgroupfs_cpu_parent_domain_locked(current);
    }
    if (candidate_child == candidate || current_child == current)
        goto out;
    if (!g_cgroupfs.nodes[candidate_child].cpu_scheduler_vruntime_valid &&
        !g_cgroupfs.nodes[current_child].cpu_scheduler_vruntime_valid)
        goto out;
    if (!g_cgroupfs.nodes[candidate_child].cpu_scheduler_vruntime_valid) {
        order = 1;
        goto out;
    }
    if (!g_cgroupfs.nodes[current_child].cpu_scheduler_vruntime_valid) {
        order = -1;
        goto out;
    }
    if (g_cgroupfs.nodes[candidate_child].cpu_scheduler_vruntime_us <
        g_cgroupfs.nodes[current_child].cpu_scheduler_vruntime_us)
        order = 1;
    else if (g_cgroupfs.nodes[candidate_child].cpu_scheduler_vruntime_us >
             g_cgroupfs.nodes[current_child].cpu_scheduler_vruntime_us)
        order = -1;
out:
    cgroupfs_unlock(&g_cgroupfs_lock);
    return order;
}

void cgroupfs_cpu_account_runtime_mode(uint32_t cgroup_id,
                                       uint64_t runtime_us,
                                       uint64_t now_us, int system_time) {
    if (!runtime_us || !g_cgroupfs.initialized) return;
    /* Never wait on a lock which the interrupted task may already own. */
    if (!cgroupfs_try_lock(&g_cgroupfs_lock)) return;
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    cgroup_id = cgroupfs_cpu_domain_locked(cgroup_id);
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[cgroup_id];

        cgroupfs_cpu_account_group_locked(cgroup_id, runtime_us);
        cgroupfs_cpu_refresh_locked(group, now_us);
        group->cpu_usage_us = cgroupfs_u64_add_saturating(
            group->cpu_usage_us, runtime_us);
        if (system_time) {
            group->cpu_system_us = cgroupfs_u64_add_saturating(
                group->cpu_system_us, runtime_us);
        } else {
            group->cpu_user_us = cgroupfs_u64_add_saturating(
                group->cpu_user_us, runtime_us);
        }
        group->cpu_period_usage_us = cgroupfs_u64_add_saturating(
            group->cpu_period_usage_us, runtime_us);
        if (!cgroup_id) break;
        cgroup_id = cgroupfs_cpu_parent_domain_locked(cgroup_id);
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
}

void cgroupfs_cpu_account_runtime(uint32_t cgroup_id, uint64_t runtime_us,
                                  uint64_t now_us) {
    cgroupfs_cpu_account_runtime_mode(cgroup_id, runtime_us, now_us, 0);
}

int cgroupfs_cpu_task_runnable(uint32_t cgroup_id, uint64_t now_us) {
    int runnable = 1;

    if (!g_cgroupfs.initialized) return 1;
    if (!cgroupfs_try_lock(&g_cgroupfs_lock)) return 1;
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[cgroup_id];
        if (!cgroupfs_cpu_group_runnable_locked(group, now_us)) {
            runnable = 0;
            break;
        }
        if (!cgroup_id) break;
        cgroup_id = cgroupfs_node_valid(group->parent, 0) ?
                    group->parent : 0;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    return runnable;
}

void cgroupfs_cpu_effective_scheduler_state(
    uint32_t cgroup_id, const edge_linux_scheduler_state_t *task_state,
    edge_linux_scheduler_state_t *effective_state) {
    uint32_t group_min = 0u;
    uint32_t group_max = EDGE_LINUX_SCHED_UTIL_SCALE;
    int idle = 0;

    if (!task_state || !effective_state) return;
    *effective_state = *task_state;
    if (!g_cgroupfs.initialized) return;

    if (!cgroupfs_try_lock(&g_cgroupfs_lock)) return;
    if (!cgroupfs_node_valid(cgroup_id, 0)) cgroup_id = 0;
    for (uint32_t guard = 0; guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[cgroup_id];

        if (group->cpu_uclamp_min > group_min)
            group_min = group->cpu_uclamp_min;
        if (group->cpu_uclamp_max < group_max)
            group_max = group->cpu_uclamp_max;
        if (group->cpu_idle) idle = 1;
        if (!cgroup_id) break;
        cgroup_id = cgroupfs_node_valid(group->parent, 0) ?
                    group->parent : 0;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);

    if (effective_state->util_min < group_min)
        effective_state->util_min = group_min;
    if (effective_state->util_max > group_max)
        effective_state->util_max = group_max;
    if (effective_state->util_min > effective_state->util_max)
        effective_state->util_min = effective_state->util_max;
    if (idle && edge_linux_scheduler_policy_is_fair(
                    effective_state->policy))
        effective_state->policy = EDGE_LINUX_SCHED_IDLE;
}

uint64_t cgroupfs_cpuset_cpu_mask64(uint32_t cgroup_id) {
    edge_cpumask_t effective;
    uint64_t mask;

    if (!__atomic_load_n(&g_cgroupfs.initialized, __ATOMIC_ACQUIRE))
        return edge_smp_online_mask64();
    if (!cgroupfs_try_lock(&g_cgroupfs_lock))
        return edge_smp_online_mask64();
    cgroupfs_cpuset_effective_locked(cgroup_id, 0, &effective);
    mask = effective.nwords ? effective.bits[0] : 0u;
    cgroupfs_unlock(&g_cgroupfs_lock);
    return mask;
}

static int cgroupfs_lookup(vfs_superblock_t *sb, vfs_inode_t *dir,
                           const char *name, vfs_inode_t *out) {
    const cgroupfs_interface_t *interface;
    uint32_t node;
    int child;
    (void)sb;
    if (!dir || !name || !out ||
        dir->fs_private[0] != CGROUPFS_INODE_DIRECTORY)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(dir, &node) < 0) goto fail;
    if (strcmp(name, ".") == 0) {
        cgroupfs_fill_inode(node, CGROUPFS_INODE_DIRECTORY,
                            g_cgroupfs.nodes[node].mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    if (strcmp(name, "..") == 0) {
        node = g_cgroupfs.nodes[node].parent;
        cgroupfs_fill_inode(node, CGROUPFS_INODE_DIRECTORY,
                            g_cgroupfs.nodes[node].mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    if (cgroupfs_interface(name, &interface) == 0) {
        if (!cgroupfs_interface_visible_locked(node, interface->kind))
            goto fail;
        cgroupfs_fill_inode(node, interface->kind, interface->mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    child = cgroupfs_find_child(node, name);
    if (child >= 0) {
        cgroupfs_fill_inode((uint32_t)child, CGROUPFS_INODE_DIRECTORY,
                            g_cgroupfs.nodes[child].mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
fail:
    cgroupfs_unlock(&g_cgroupfs_lock);
    return -1;
}

static int cgroupfs_render(vfs_inode_t *inode, char *buffer,
                           uint32_t capacity, uint32_t *size_out) {
    uint32_t node;
    uint32_t kind;
    uint32_t offset = 0;
    if (!inode || !buffer || !capacity || !size_out) return -1;
    kind = inode->fs_private[0];
    if (cgroupfs_inode_node(inode, &node) < 0 ||
        kind == CGROUPFS_INODE_DIRECTORY)
        return -1;
    buffer[0] = 0;
    if (kind == CGROUPFS_INODE_CONTROLLERS) {
        if (cgroupfs_cpuset_available_locked(node) &&
            cgroupfs_append(buffer, capacity, &offset, "cpuset") < 0)
            return -1;
        if (cgroupfs_cpu_available_locked(node) &&
            ((offset && cgroupfs_append(
                            buffer, capacity, &offset, " ") < 0) ||
             cgroupfs_append(buffer, capacity, &offset, "cpu") < 0))
            return -1;
        if (cgroupfs_pids_available_locked(node)) {
            if (offset && buffer[offset - 1u] != '\n' &&
                cgroupfs_append(buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "pids") < 0)
                return -1;
        }
        if (cgroupfs_memory_available_locked(node)) {
            if (offset && buffer[offset - 1u] != '\n' &&
                cgroupfs_append(buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "memory") < 0)
                return -1;
        }
        if (cgroupfs_io_available_locked(node)) {
            if (offset && buffer[offset - 1u] != '\n' &&
                cgroupfs_append(buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "io") < 0)
                return -1;
        }
        if (cgroupfs_append(buffer, capacity, &offset, "\n") < 0) return -1;
    } else if (kind == CGROUPFS_INODE_SUBTREE_CONTROL) {
        if ((g_cgroupfs.nodes[node].subtree_controllers &
             CGROUPFS_CONTROLLER_CPUSET) != 0 &&
            cgroupfs_append(buffer, capacity, &offset, "cpuset") < 0)
            return -1;
        if ((g_cgroupfs.nodes[node].subtree_controllers &
             CGROUPFS_CONTROLLER_CPU) != 0) {
            if (offset && cgroupfs_append(
                              buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "cpu") < 0)
                return -1;
        }
        if ((g_cgroupfs.nodes[node].subtree_controllers &
             CGROUPFS_CONTROLLER_PIDS) != 0) {
            if (offset && cgroupfs_append(buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "pids") < 0)
                return -1;
        }
        if ((g_cgroupfs.nodes[node].subtree_controllers &
             CGROUPFS_CONTROLLER_MEMORY) != 0) {
            if (offset && cgroupfs_append(buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "memory") < 0)
                return -1;
        }
        if ((g_cgroupfs.nodes[node].subtree_controllers &
             CGROUPFS_CONTROLLER_IO) != 0) {
            if (offset && cgroupfs_append(buffer, capacity, &offset, " ") < 0)
                return -1;
            if (cgroupfs_append(buffer, capacity, &offset, "io") < 0)
                return -1;
        }
        if (cgroupfs_append(buffer, capacity, &offset, "\n") < 0) return -1;
    } else if (kind == CGROUPFS_INODE_PROCS ||
               kind == CGROUPFS_INODE_THREADS) {
        if (cgroupfs_render_tasks(node, kind == CGROUPFS_INODE_THREADS,
                                  buffer, capacity, &offset) < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_EVENTS) {
        uint32_t populated = (uint32_t)cgroupfs_populated(node);
        g_cgroupfs.nodes[node].populated = (uint8_t)populated;
        g_cgroupfs.nodes[node].populated_known = 1u;
        if (cgroupfs_append(buffer, capacity, &offset, "populated ") < 0 ||
            cgroupfs_append_u32(buffer, capacity, &offset, populated) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nfrozen ") < 0 ||
            cgroupfs_append_u32(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].frozen) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_FREEZE) {
        if (cgroupfs_append_u32(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].frozen) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_TYPE) {
        if (cgroupfs_append(buffer, capacity, &offset, "domain\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_STAT) {
        if (cgroupfs_append(buffer, capacity, &offset,
                            "nr_descendants ") < 0 ||
            cgroupfs_append_u32(buffer, capacity, &offset,
                                cgroupfs_descendant_count(node)) < 0 ||
            cgroupfs_append(buffer, capacity, &offset,
                            "\nnr_dying_descendants 0\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MAX_DEPTH ||
               kind == CGROUPFS_INODE_MAX_DESCENDANTS) {
        uint32_t value = kind == CGROUPFS_INODE_MAX_DEPTH ?
                         g_cgroupfs.nodes[node].max_depth :
                         g_cgroupfs.nodes[node].max_descendants;
        if (value == CGROUPFS_LIMIT_MAX) {
            if (cgroupfs_append(buffer, capacity, &offset, "max\n") < 0)
                return -1;
        } else if (cgroupfs_append_u32(buffer, capacity, &offset, value) < 0 ||
                   cgroupfs_append(buffer, capacity, &offset, "\n") < 0) {
            return -1;
        }
    } else if (kind == CGROUPFS_INODE_CPUSET_CPUS ||
               kind == CGROUPFS_INODE_CPUSET_MEMS) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        int memory = kind == CGROUPFS_INODE_CPUSET_MEMS;
        int configured = memory ? group->cpuset_mems_configured :
                                  group->cpuset_cpus_configured;
        edge_cpumask_t *mask = memory ? &group->cpuset_mems :
                                        &group->cpuset_cpus;
        if (configured && cgroupfs_render_resource_set(
                mask, buffer, capacity, &offset) < 0)
            return -1;
        if (cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPUSET_CPUS_EFFECTIVE ||
               kind == CGROUPFS_INODE_CPUSET_MEMS_EFFECTIVE) {
        edge_cpumask_t effective;
        cgroupfs_cpuset_effective_locked(
            node, kind == CGROUPFS_INODE_CPUSET_MEMS_EFFECTIVE, &effective);
        if (cgroupfs_render_resource_set(
                &effective, buffer, capacity, &offset) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_WEIGHT) {
        uint32_t weight = g_cgroupfs.nodes[node].cpu_idle ? 0u :
                          g_cgroupfs.nodes[node].cpu_weight;
        if (cgroupfs_append_u32(buffer, capacity, &offset, weight) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_WEIGHT_NICE) {
        int32_t nice = cgroupfs_cpu_nice_from_weight(
            g_cgroupfs.nodes[node].cpu_weight);
        if (nice < 0 &&
            cgroupfs_append(buffer, capacity, &offset, "-") < 0)
            return -1;
        if (cgroupfs_append_u32(buffer, capacity, &offset,
                                (uint32_t)(nice < 0 ? -nice : nice)) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_MAX) {
        if (g_cgroupfs.nodes[node].cpu_quota_us == CGROUPFS_CPU_QUOTA_MAX) {
            if (cgroupfs_append(buffer, capacity, &offset, "max") < 0)
                return -1;
        } else if (cgroupfs_append_u64(
                       buffer, capacity, &offset,
                       g_cgroupfs.nodes[node].cpu_quota_us) < 0) {
            return -1;
        }
        if (cgroupfs_append(buffer, capacity, &offset, " ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].cpu_period_us) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_MAX_BURST) {
        if (cgroupfs_append_u64(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].cpu_burst_us) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_IDLE) {
        if (cgroupfs_append_u32(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].cpu_idle) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_UCLAMP_MIN ||
               kind == CGROUPFS_INODE_CPU_UCLAMP_MAX) {
        uint32_t value = kind == CGROUPFS_INODE_CPU_UCLAMP_MIN ?
                         g_cgroupfs.nodes[node].cpu_uclamp_min :
                         g_cgroupfs.nodes[node].cpu_uclamp_max;
        if (cgroupfs_append_uclamp(
                buffer, capacity, &offset, value,
                kind == CGROUPFS_INODE_CPU_UCLAMP_MAX) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_CPU_STAT) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        cgroupfs_cpu_refresh_locked(group, boottime_monotonic_us());
        if (cgroupfs_append(buffer, capacity, &offset, "usage_usec ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->cpu_usage_us) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nuser_usec ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->cpu_user_us) < 0 ||
            cgroupfs_append(buffer, capacity, &offset,
                            "\nsystem_usec ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->cpu_system_us) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nnr_periods ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->cpu_nr_periods) < 0 ||
            cgroupfs_append(buffer, capacity, &offset,
                            "\nnr_throttled ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->cpu_nr_throttled) < 0 ||
            cgroupfs_append(buffer, capacity, &offset,
                            "\nthrottled_usec ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->cpu_throttled_us) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_PIDS_CURRENT) {
        cgroupfs_rebuild_task_counts_locked();
        if (cgroupfs_append_u32(
                buffer, capacity, &offset,
                g_cgroupfs.nodes[node].subtree_task_count) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_PIDS_MAX) {
        if (g_cgroupfs.nodes[node].pids_max == CGROUPFS_LIMIT_MAX) {
            if (cgroupfs_append(buffer, capacity, &offset, "max\n") < 0)
                return -1;
        } else if (cgroupfs_append_u32(
                       buffer, capacity, &offset,
                       g_cgroupfs.nodes[node].pids_max) < 0 ||
                   cgroupfs_append(buffer, capacity, &offset, "\n") < 0) {
            return -1;
        }
    } else if (kind == CGROUPFS_INODE_PIDS_EVENTS ||
               kind == CGROUPFS_INODE_PIDS_EVENTS_LOCAL) {
        uint64_t events = kind == CGROUPFS_INODE_PIDS_EVENTS ?
                          g_cgroupfs.nodes[node].pids_max_events :
                          g_cgroupfs.nodes[node].pids_max_events_local;
        if (cgroupfs_append(buffer, capacity, &offset, "max ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset, events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_PIDS_PEAK) {
        if (cgroupfs_append_u32(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].pids_peak) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_CURRENT) {
        if (cgroupfs_append_u64(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].memory_current) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_MIN ||
               kind == CGROUPFS_INODE_MEMORY_LOW) {
        uint64_t value = kind == CGROUPFS_INODE_MEMORY_MIN ?
                         g_cgroupfs.nodes[node].memory_min :
                         g_cgroupfs.nodes[node].memory_low;
        if (cgroupfs_append_u64(buffer, capacity, &offset, value) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_HIGH) {
        if (g_cgroupfs.nodes[node].memory_high == UINT64_MAX) {
            if (cgroupfs_append(buffer, capacity, &offset, "max\n") < 0)
                return -1;
        } else if (cgroupfs_append_u64(
                       buffer, capacity, &offset,
                       g_cgroupfs.nodes[node].memory_high) < 0 ||
                   cgroupfs_append(buffer, capacity, &offset, "\n") < 0) {
            return -1;
        }
    } else if (kind == CGROUPFS_INODE_MEMORY_MAX) {
        if (g_cgroupfs.nodes[node].memory_max == UINT64_MAX) {
            if (cgroupfs_append(buffer, capacity, &offset, "max\n") < 0)
                return -1;
        } else if (cgroupfs_append_u64(
                       buffer, capacity, &offset,
                       g_cgroupfs.nodes[node].memory_max) < 0 ||
                   cgroupfs_append(buffer, capacity, &offset, "\n") < 0) {
            return -1;
        }
    } else if (kind == CGROUPFS_INODE_MEMORY_PEAK) {
        if (cgroupfs_append_u64(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].memory_peak) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_EVENTS ||
               kind == CGROUPFS_INODE_MEMORY_EVENTS_LOCAL) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        int local = kind == CGROUPFS_INODE_MEMORY_EVENTS_LOCAL;
        uint64_t max_events = local ? group->memory_max_events_local :
                                      group->memory_max_events;
        uint64_t low_events = local ? group->memory_low_events_local :
                                      group->memory_low_events;
        uint64_t high_events = local ? group->memory_high_events_local :
                                       group->memory_high_events;
        uint64_t oom_events = local ? group->memory_oom_events_local :
                                      group->memory_oom_events;
        uint64_t kill_events = local ? group->memory_oom_kill_events_local :
                                       group->memory_oom_kill_events;
        uint64_t group_kill_events = local ?
            group->memory_oom_group_kill_events_local :
            group->memory_oom_group_kill_events;
        if (cgroupfs_append(buffer, capacity, &offset, "low ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset, low_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nhigh ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset, high_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nmax ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset, max_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\noom ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset, oom_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\noom_kill ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset, kill_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset,
                            "\noom_group_kill ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group_kill_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_STAT) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (cgroupfs_append(buffer, capacity, &offset, "anon ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_current) < 0 ||
            cgroupfs_append(buffer, capacity, &offset,
                            "\nfile 0\nkernel 0\nkernel_stack 0\n"
                            "pagetables 0\npercpu 0\nsock 0\nshmem 0\n"
                            "file_mapped 0\nfile_dirty 0\nfile_writeback 0\n"
                            "swapcached 0\npgfault ") < 0 ||
            cgroupfs_append_u64(
                buffer, capacity, &offset,
                cgroupfs_u64_add_saturating(group->memory_minor_faults,
                                             group->memory_major_faults)) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\npgmajfault ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_major_faults) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\npgscan ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_scanned_pages) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\npgsteal ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_reclaimed_pages) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_PRESSURE) {
        edge_mm_pressure_snapshot_t pressure;
        int rendered;
        uint64_t memory_flags = spin_lock_irqsave(
            &g_cgroupfs_memory_lock);

        edge_mm_pressure_snapshot_at(
            &g_cgroupfs.nodes[node].memory_pressure,
            boottime_monotonic_us(), &pressure);
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        rendered = kernel_proc_memory_pressure_render(
            buffer, capacity, &pressure);
        if (rendered < 0) return -1;
        offset = (uint32_t)rendered;
    } else if (kind == CGROUPFS_INODE_MEMORY_OOM_GROUP) {
        if (cgroupfs_append_u32(buffer, capacity, &offset,
                                g_cgroupfs.nodes[node].memory_oom_group) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_SWAP_CURRENT) {
        if (cgroupfs_append_u64(
                buffer, capacity, &offset,
                g_cgroupfs.nodes[node].memory_swap_current) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_SWAP_PEAK) {
        if (cgroupfs_append_u64(
                buffer, capacity, &offset,
                g_cgroupfs.nodes[node].memory_swap_peak) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_SWAP_HIGH ||
               kind == CGROUPFS_INODE_MEMORY_SWAP_MAX) {
        uint64_t limit = kind == CGROUPFS_INODE_MEMORY_SWAP_HIGH ?
                         g_cgroupfs.nodes[node].memory_swap_high :
                         g_cgroupfs.nodes[node].memory_swap_max;
        if (limit == UINT64_MAX) {
            if (cgroupfs_append(buffer, capacity, &offset, "max\n") < 0)
                return -1;
        } else if (cgroupfs_append_u64(buffer, capacity, &offset,
                                       limit) < 0 ||
                   cgroupfs_append(buffer, capacity, &offset, "\n") < 0) {
            return -1;
        }
    } else if (kind == CGROUPFS_INODE_MEMORY_SWAP_EVENTS) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (cgroupfs_append(buffer, capacity, &offset, "high ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_swap_high_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nmax ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_swap_max_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\nfail ") < 0 ||
            cgroupfs_append_u64(buffer, capacity, &offset,
                                group->memory_swap_fail_events) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
    } else if (kind == CGROUPFS_INODE_MEMORY_RECLAIM) {
        return -1;
    } else if (kind == CGROUPFS_INODE_IO_STAT) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        for (uint32_t index = 0; index < CGROUPFS_IO_DEVICE_SLOTS; ++index) {
            cgroupfs_io_device_t *device = &group->io_devices[index];
            if (!device->used ||
                (!device->read_bytes && !device->write_bytes &&
                 !device->read_operations && !device->write_operations))
                continue;
            if (cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->major) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, ":") < 0 ||
                cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->minor) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, " rbytes=") < 0 ||
                cgroupfs_append_u64(buffer, capacity, &offset,
                                    device->read_bytes) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, " wbytes=") < 0 ||
                cgroupfs_append_u64(buffer, capacity, &offset,
                                    device->write_bytes) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, " rios=") < 0 ||
                cgroupfs_append_u64(buffer, capacity, &offset,
                                    device->read_operations) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, " wios=") < 0 ||
                cgroupfs_append_u64(buffer, capacity, &offset,
                                    device->write_operations) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
                return -1;
        }
    } else if (kind == CGROUPFS_INODE_IO_WEIGHT) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (cgroupfs_append(buffer, capacity, &offset, "default ") < 0 ||
            cgroupfs_append_u32(buffer, capacity, &offset,
                                group->io_weight) < 0 ||
            cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
            return -1;
        for (uint32_t index = 0; index < CGROUPFS_IO_DEVICE_SLOTS; ++index) {
            cgroupfs_io_device_t *device = &group->io_devices[index];
            if (!device->used || !device->weight) continue;
            if (cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->major) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, ":") < 0 ||
                cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->minor) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, " ") < 0 ||
                cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->weight) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
                return -1;
        }
    } else if (kind == CGROUPFS_INODE_IO_MAX) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        for (uint32_t index = 0; index < CGROUPFS_IO_DEVICE_SLOTS; ++index) {
            cgroupfs_io_device_t *device = &group->io_devices[index];
            if (!device->used || !device->limits_configured) continue;
            if (cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->major) < 0 ||
                cgroupfs_append(buffer, capacity, &offset, ":") < 0 ||
                cgroupfs_append_u32(buffer, capacity, &offset,
                                    device->minor) < 0)
                return -1;
#define CGROUPFS_RENDER_IO_LIMIT(label, field)                              \
            do {                                                           \
                if (cgroupfs_append(buffer, capacity, &offset, label) < 0)  \
                    return -1;                                             \
                if (device->field) {                                       \
                    if (cgroupfs_append_u64(                               \
                            buffer, capacity, &offset, device->field) < 0)  \
                        return -1;                                         \
                } else if (cgroupfs_append(                                \
                               buffer, capacity, &offset, "max") < 0)      \
                    return -1;                                             \
            } while (0)
            CGROUPFS_RENDER_IO_LIMIT(" rbps=", read_bytes_per_second);
            CGROUPFS_RENDER_IO_LIMIT(" wbps=", write_bytes_per_second);
            CGROUPFS_RENDER_IO_LIMIT(" riops=", read_operations_per_second);
            CGROUPFS_RENDER_IO_LIMIT(" wiops=", write_operations_per_second);
#undef CGROUPFS_RENDER_IO_LIMIT
            if (cgroupfs_append(buffer, capacity, &offset, "\n") < 0)
                return -1;
        }
    } else {
        return -1;
    }
    *size_out = offset;
    return 0;
}

static int cgroupfs_read(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint32_t off, void *buffer, uint32_t len) {
    uint32_t size;
    uint32_t count;
    (void)sb;
    if (!inode || !buffer) return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_snapshot_lock);
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_render(inode, g_cgroupfs_snapshot,
                        sizeof(g_cgroupfs_snapshot), &size) < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        cgroupfs_unlock(&g_cgroupfs_snapshot_lock);
        return -1;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    if (off >= size) {
        cgroupfs_unlock(&g_cgroupfs_snapshot_lock);
        return 0;
    }
    count = size - off;
    if (count > len) count = len;
    memcpy(buffer, g_cgroupfs_snapshot + off, count);
    cgroupfs_unlock(&g_cgroupfs_snapshot_lock);
    return (int)count;
}

static int cgroupfs_parse_pid(const void *buffer, uint32_t len,
                              int32_t *pid_out) {
    const char *text = (const char *)buffer;
    uint64_t value = 0;
    uint32_t index = 0;
    int digits = 0;
    if (!buffer || !len || !pid_out) return -1;
    while (index < len && (text[index] == ' ' || text[index] == '\t' ||
                           text[index] == '\n' || text[index] == '\r'))
        ++index;
    while (index < len && text[index] >= '0' && text[index] <= '9') {
        digits = 1;
        value = value * 10u + (uint32_t)(text[index++] - '0');
        if (value > 0x7fffffffu) return -1;
    }
    while (index < len && (text[index] == ' ' || text[index] == '\t' ||
                           text[index] == '\n' || text[index] == '\r'))
        ++index;
    if (!digits || index != len) return -1;
    *pid_out = (int32_t)value;
    return 0;
}

static int cgroupfs_parse_limit(const void *buffer, uint32_t len,
                                uint32_t *value_out) {
    const char *text = (const char *)buffer;
    uint64_t value = 0;
    uint32_t index = 0;
    int digits = 0;
    if (!buffer || !len || !value_out) return -1;
    while (index < len && (text[index] == ' ' || text[index] == '\t')) ++index;
    if (index + 3u <= len && text[index] == 'm' && text[index + 1u] == 'a' &&
        text[index + 2u] == 'x') {
        index += 3u;
        *value_out = CGROUPFS_LIMIT_MAX;
    } else {
        while (index < len && text[index] >= '0' && text[index] <= '9') {
            digits = 1;
            value = value * 10u + (uint32_t)(text[index++] - '0');
            if (value >= CGROUPFS_LIMIT_MAX) return -1;
        }
        if (!digits) return -1;
        *value_out = (uint32_t)value;
    }
    while (index < len && (text[index] == ' ' || text[index] == '\t' ||
                           text[index] == '\n' || text[index] == '\r'))
        ++index;
    return index == len ? 0 : -1;
}

static int cgroupfs_parse_freeze(const void *buffer, uint32_t len,
                                 uint8_t *frozen_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;

    if (!buffer || !len || !frozen_out) return -1;
    while (index < len && (text[index] == ' ' || text[index] == '\t'))
        ++index;
    if (index >= len || (text[index] != '0' && text[index] != '1'))
        return -1;
    *frozen_out = (uint8_t)(text[index++] - '0');
    while (index < len && (text[index] == ' ' || text[index] == '\t' ||
                           text[index] == '\n' || text[index] == '\r'))
        ++index;
    return index == len ? 0 : -1;
}

static void cgroupfs_skip_space(const char *text, uint32_t len,
                                uint32_t *index) {
    while (*index < len &&
           (text[*index] == ' ' || text[*index] == '\t' ||
            text[*index] == '\n' || text[*index] == '\r'))
        ++*index;
}

static int cgroupfs_parse_u64_token(const char *text, uint32_t len,
                                    uint32_t *index, uint64_t *value_out) {
    uint64_t value = 0;
    int digits = 0;

    while (*index < len && text[*index] >= '0' && text[*index] <= '9') {
        uint32_t digit = (uint32_t)(text[(*index)++] - '0');
        digits = 1;
        if (value > (UINT64_MAX - digit) / 10u) return -1;
        value = value * 10u + digit;
    }
    if (!digits) return -1;
    *value_out = value;
    return 0;
}

static int cgroupfs_parse_resource_set(
    const void *buffer, uint32_t len, uint32_t resources,
    edge_cpumask_t *mask_out, uint8_t *configured_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;

    if (!buffer || !len || !resources || !mask_out || !configured_out)
        return -1;
    edge_cpumask_init(mask_out, resources);
    cgroupfs_skip_space(text, len, &index);
    if (index == len) {
        *configured_out = 0;
        return 0;
    }
    for (;;) {
        uint64_t first;
        uint64_t last;

        if (cgroupfs_parse_u64_token(text, len, &index, &first) < 0)
            return -1;
        last = first;
        if (index < len && text[index] == '-') {
            ++index;
            if (cgroupfs_parse_u64_token(text, len, &index, &last) < 0 ||
                last < first)
                return -1;
        }
        if (last >= resources) return -1;
        for (uint64_t resource = first; resource <= last; ++resource)
            (void)edge_cpumask_set_cpu(mask_out, (uint32_t)resource);
        if (index >= len || text[index] != ',') break;
        ++index;
    }
    cgroupfs_skip_space(text, len, &index);
    if (index != len || !edge_cpumask_weight(mask_out)) return -1;
    *configured_out = 1;
    return 0;
}

static int cgroupfs_parse_u64_limit(const void *buffer, uint32_t len,
                                    uint64_t *value_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;
    uint64_t value;

    if (!buffer || !len || !value_out) return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index + 3u <= len && text[index] == 'm' &&
        text[index + 1u] == 'a' && text[index + 2u] == 'x' &&
        (index + 3u == len || text[index + 3u] == ' ' ||
         text[index + 3u] == '\t' || text[index + 3u] == '\n' ||
         text[index + 3u] == '\r')) {
        value = UINT64_MAX;
        index += 3u;
    } else if (cgroupfs_parse_u64_token(text, len, &index, &value) < 0) {
        return -1;
    }
    cgroupfs_skip_space(text, len, &index);
    if (index != len) return -1;
    *value_out = value;
    return 0;
}

static int cgroupfs_parse_cpu_weight(const void *buffer, uint32_t len,
                                     uint32_t *weight_out) {
    const char *text = (const char *)buffer;
    uint64_t value;
    uint32_t index = 0;

    if (!buffer || !len || !weight_out) return -1;
    cgroupfs_skip_space(text, len, &index);
    if (cgroupfs_parse_u64_token(text, len, &index, &value) < 0)
        return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index != len || value < CGROUPFS_CPU_WEIGHT_MIN ||
        value > CGROUPFS_CPU_WEIGHT_MAX)
        return -1;
    *weight_out = (uint32_t)value;
    return 0;
}

static int cgroupfs_parse_cpu_nice(const void *buffer, uint32_t len,
                                   int32_t *nice_out) {
    const char *text = (const char *)buffer;
    uint64_t magnitude;
    uint32_t index = 0;
    int negative = 0;
    int32_t nice;

    if (!buffer || !len || !nice_out) return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index < len && (text[index] == '-' || text[index] == '+')) {
        negative = text[index] == '-';
        ++index;
    }
    if (cgroupfs_parse_u64_token(text, len, &index, &magnitude) < 0 ||
        magnitude > 20u)
        return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index != len) return -1;
    nice = negative ? -(int32_t)magnitude : (int32_t)magnitude;
    if (nice < -20 || nice > 19) return -1;
    *nice_out = nice;
    return 0;
}

static int cgroupfs_parse_cpu_max(const void *buffer, uint32_t len,
                                  uint64_t old_period_us,
                                  uint64_t *quota_out,
                                  uint64_t *period_out) {
    const char *text = (const char *)buffer;
    uint64_t quota;
    uint64_t period = old_period_us;
    uint32_t index = 0;

    if (!buffer || !len || !quota_out || !period_out) return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index + 3u <= len && text[index] == 'm' &&
        text[index + 1u] == 'a' && text[index + 2u] == 'x' &&
        (index + 3u == len || text[index + 3u] == ' ' ||
         text[index + 3u] == '\t' || text[index + 3u] == '\n' ||
         text[index + 3u] == '\r')) {
        quota = CGROUPFS_CPU_QUOTA_MAX;
        index += 3u;
    } else if (cgroupfs_parse_u64_token(text, len, &index, &quota) < 0 ||
               quota < CGROUPFS_CPU_PERIOD_MIN_US) {
        return -1;
    }
    cgroupfs_skip_space(text, len, &index);
    if (index < len) {
        if (cgroupfs_parse_u64_token(text, len, &index, &period) < 0)
            return -1;
        cgroupfs_skip_space(text, len, &index);
    }
    if (index != len || period < CGROUPFS_CPU_PERIOD_MIN_US ||
        period > CGROUPFS_CPU_PERIOD_MAX_US)
        return -1;
    *quota_out = quota;
    *period_out = period;
    return 0;
}

static int cgroupfs_parse_cpu_burst(const void *buffer, uint32_t len,
                                    uint64_t *burst_out) {
    const char *text = (const char *)buffer;
    uint64_t burst;
    uint32_t index = 0;

    if (!buffer || !len || !burst_out) return -1;
    cgroupfs_skip_space(text, len, &index);
    if (cgroupfs_parse_u64_token(text, len, &index, &burst) < 0)
        return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index != len || burst > CGROUPFS_CPU_BURST_MAX_US)
        return -1;
    *burst_out = burst;
    return 0;
}

static int cgroupfs_parse_cpu_idle(const void *buffer, uint32_t len,
                                   uint8_t *idle_out) {
    uint64_t value;

    if (!idle_out || cgroupfs_parse_u64_limit(buffer, len, &value) < 0 ||
        value > 1u)
        return -1;
    *idle_out = (uint8_t)value;
    return 0;
}

static int cgroupfs_parse_cpu_uclamp(const void *buffer, uint32_t len,
                                     int accept_max, uint32_t *value_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;
    uint64_t whole;
    uint32_t fraction = 0;
    uint32_t digits = 0;
    uint64_t hundredths;

    if (!buffer || !len || !value_out) return -1;
    cgroupfs_skip_space(text, len, &index);
    if (accept_max && index + 3u <= len &&
        memcmp(text + index, "max", 3u) == 0) {
        index += 3u;
        cgroupfs_skip_space(text, len, &index);
        if (index != len) return -1;
        *value_out = EDGE_LINUX_SCHED_UTIL_SCALE;
        return 0;
    }
    if (cgroupfs_parse_u64_token(text, len, &index, &whole) < 0)
        return -1;
    if (index < len && text[index] == '.') {
        ++index;
        while (index < len && text[index] >= '0' && text[index] <= '9') {
            if (digits >= 2u) return -1;
            fraction = fraction * 10u + (uint32_t)(text[index++] - '0');
            ++digits;
        }
        if (!digits) return -1;
        if (digits == 1u) fraction *= 10u;
    }
    cgroupfs_skip_space(text, len, &index);
    if (index != len || whole > 100u ||
        (whole == 100u && fraction != 0u))
        return -1;
    hundredths = whole * 100u + fraction;
    *value_out = (uint32_t)((hundredths *
                            EDGE_LINUX_SCHED_UTIL_SCALE + 5000u) /
                           10000u);
    return 0;
}

static int cgroupfs_parse_io_device(const char *text, uint32_t len,
                                    uint32_t *index, uint32_t *major_out,
                                    uint32_t *minor_out) {
    uint64_t major;
    uint64_t minor;

    if (cgroupfs_parse_u64_token(text, len, index, &major) < 0 ||
        *index >= len || text[(*index)++] != ':' ||
        cgroupfs_parse_u64_token(text, len, index, &minor) < 0 ||
        major > UINT32_MAX || minor > UINT32_MAX)
        return -1;
    *major_out = (uint32_t)major;
    *minor_out = (uint32_t)minor;
    return 0;
}

static int cgroupfs_parse_io_weight(const void *buffer, uint32_t len,
                                    int *device_specific,
                                    uint32_t *major_out,
                                    uint32_t *minor_out,
                                    uint32_t *weight_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;
    uint64_t weight;

    if (!buffer || !len || !device_specific || !major_out || !minor_out ||
        !weight_out)
        return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index + 7u <= len && memcmp(text + index, "default", 7u) == 0 &&
        (index + 7u == len || text[index + 7u] == ' ' ||
         text[index + 7u] == '\t')) {
        index += 7u;
        *device_specific = 0;
    } else {
        uint32_t saved = index;
        if (cgroupfs_parse_io_device(
                text, len, &index, major_out, minor_out) == 0) {
            *device_specific = 1;
        } else {
            index = saved;
            *device_specific = 0;
        }
    }
    cgroupfs_skip_space(text, len, &index);
    if (cgroupfs_parse_u64_token(text, len, &index, &weight) < 0)
        return -1;
    cgroupfs_skip_space(text, len, &index);
    if (index != len || weight < CGROUPFS_IO_WEIGHT_MIN ||
        weight > CGROUPFS_IO_WEIGHT_MAX)
        return -1;
    *weight_out = (uint32_t)weight;
    return 0;
}

static int cgroupfs_parse_io_rate(const char *text, uint32_t len,
                                  uint32_t *index, uint64_t *value_out) {
    if (*index + 3u <= len && memcmp(text + *index, "max", 3u) == 0 &&
        (*index + 3u == len || text[*index + 3u] == ' ' ||
         text[*index + 3u] == '\t' || text[*index + 3u] == '\n' ||
         text[*index + 3u] == '\r')) {
        *value_out = 0;
        *index += 3u;
        return 0;
    }
    return cgroupfs_parse_u64_token(text, len, index, value_out);
}

#define CGROUPFS_IO_MAX_RBPS  0x01u
#define CGROUPFS_IO_MAX_WBPS  0x02u
#define CGROUPFS_IO_MAX_RIOPS 0x04u
#define CGROUPFS_IO_MAX_WIOPS 0x08u

static int cgroupfs_parse_io_max(const void *buffer, uint32_t len,
                                 uint32_t *major_out, uint32_t *minor_out,
                                 uint32_t *fields_out, uint64_t values[4]) {
    static const char *names[] = { "rbps", "wbps", "riops", "wiops" };
    static const uint32_t lengths[] = { 4u, 4u, 5u, 5u };
    const char *text = (const char *)buffer;
    uint32_t index = 0;
    uint32_t fields = 0;

    if (!buffer || !len || !major_out || !minor_out || !fields_out ||
        !values)
        return -1;
    cgroupfs_skip_space(text, len, &index);
    if (cgroupfs_parse_io_device(
            text, len, &index, major_out, minor_out) < 0)
        return -1;
    while (1) {
        int matched = -1;
        cgroupfs_skip_space(text, len, &index);
        if (index == len) break;
        for (uint32_t field = 0; field < 4u; ++field) {
            if (index + lengths[field] + 1u <= len &&
                memcmp(text + index, names[field], lengths[field]) == 0 &&
                text[index + lengths[field]] == '=') {
                matched = (int)field;
                index += lengths[field] + 1u;
                break;
            }
        }
        if (matched < 0 ||
            cgroupfs_parse_io_rate(
                text, len, &index, &values[matched]) < 0)
            return -1;
        fields |= 1u << (uint32_t)matched;
    }
    if (!fields) return -1;
    *fields_out = fields;
    return 0;
}

static int cgroupfs_parse_subtree_control(const void *buffer, uint32_t len,
                                          uint8_t current,
                                          int cpuset_available,
                                          int cpu_available,
                                          int pids_available,
                                          int memory_available,
                                          int io_available,
                                          uint8_t *controllers_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;
    uint8_t controllers = current;

    if (!buffer || !len || !controllers_out) return -1;
    while (1) {
        char operation;
        uint32_t start;
        uint32_t name_len;
        cgroupfs_skip_space(text, len, &index);
        if (index == len) break;
        operation = text[index++];
        if (operation != '+' && operation != '-') return -1;
        start = index;
        while (index < len && text[index] != ' ' && text[index] != '\t' &&
               text[index] != '\n' && text[index] != '\r')
            ++index;
        name_len = index - start;
        if (name_len == 6u && text[start] == 'c' &&
            text[start + 1u] == 'p' && text[start + 2u] == 'u' &&
            text[start + 3u] == 's' && text[start + 4u] == 'e' &&
            text[start + 5u] == 't') {
            if (operation == '+') {
                if (!cpuset_available) return -1;
                controllers |= CGROUPFS_CONTROLLER_CPUSET;
            } else {
                controllers &= (uint8_t)~CGROUPFS_CONTROLLER_CPUSET;
            }
        } else if (name_len == 3u && text[start] == 'c' &&
            text[start + 1u] == 'p' && text[start + 2u] == 'u') {
            if (operation == '+') {
                if (!cpu_available) return -1;
                controllers |= CGROUPFS_CONTROLLER_CPU;
            } else {
                controllers &= (uint8_t)~CGROUPFS_CONTROLLER_CPU;
            }
        } else if (name_len == 4u && text[start] == 'p' &&
                   text[start + 1u] == 'i' &&
                   text[start + 2u] == 'd' &&
                   text[start + 3u] == 's') {
            if (operation == '+') {
                if (!pids_available) return -1;
                controllers |= CGROUPFS_CONTROLLER_PIDS;
            } else {
                controllers &= (uint8_t)~CGROUPFS_CONTROLLER_PIDS;
            }
        } else if (name_len == 6u && text[start] == 'm' &&
                   text[start + 1u] == 'e' &&
                   text[start + 2u] == 'm' &&
                   text[start + 3u] == 'o' &&
                   text[start + 4u] == 'r' &&
                   text[start + 5u] == 'y') {
            if (operation == '+') {
                if (!memory_available) return -1;
                controllers |= CGROUPFS_CONTROLLER_MEMORY;
            } else {
                controllers &= (uint8_t)~CGROUPFS_CONTROLLER_MEMORY;
            }
        } else if (name_len == 2u && text[start] == 'i' &&
                   text[start + 1u] == 'o') {
            if (operation == '+') {
                if (!io_available) return -1;
                controllers |= CGROUPFS_CONTROLLER_IO;
            } else {
                controllers &= (uint8_t)~CGROUPFS_CONTROLLER_IO;
            }
        } else {
            return -1;
        }
    }
    *controllers_out = controllers;
    return 0;
}

static int cgroupfs_write(vfs_superblock_t *sb, vfs_inode_t *inode,
                          uint32_t off, const void *buffer, uint32_t len) {
    kernel_linux_identity_t identity;
    uint32_t node;
    uint32_t kind;
    uint32_t old_cgroup = 0;
    uint64_t reclaim_bytes = 0;
    int membership_changed = 0;
    int reclaim_requested = 0;
    (void)sb;
    if (!inode || (!buffer && len) || off != 0 || !len) return -1;
    if (kernel_current_linux_identity(&identity) < 0) return -1;
    cgroupfs_initialize();
    kind = inode->fs_private[0];
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(inode, &node) < 0) goto fail;
    if (kind == CGROUPFS_INODE_PROCS) {
        kernel_proc_task_snapshot_t target;
        int32_t pid;
        if (cgroupfs_parse_pid(buffer, len, &pid) < 0) goto fail;
        if (!pid) pid = kernel_current_pid();
        /*
         * Delegation grants control over a subtree, not over arbitrary
         * processes.  Linux permits an unprivileged writer to migrate its
         * own processes within a delegated hierarchy while retaining a
         * credential check on the target task.  The VFS has already checked
         * write access to cgroup.procs; keep this second check so ownership of
         * a delegated cgroup cannot be used to move another user's process.
         */
        if (kernel_proc_task_snapshot(pid, &target) < 0 ||
            (identity.euid != 0 &&
             (target.uid != identity.euid ||
             target.euid != identity.euid ||
             target.suid != identity.euid)))
            goto fail;
        old_cgroup = target.cgroup_id;
        if (kernel_proc_cgroup_attach(pid, node, 1) < 0) goto fail;
        membership_changed = 1;
    } else if (kind == CGROUPFS_INODE_SUBTREE_CONTROL) {
        uint8_t controllers;
        if (cgroupfs_parse_subtree_control(
                buffer, len, g_cgroupfs.nodes[node].subtree_controllers,
                cgroupfs_cpuset_available_locked(node),
                cgroupfs_cpu_available_locked(node),
                cgroupfs_pids_available_locked(node),
                cgroupfs_memory_available_locked(node),
                cgroupfs_io_available_locked(node), &controllers) < 0)
            goto fail;
        g_cgroupfs.nodes[node].subtree_controllers = controllers;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_KILL) {
        uint8_t kill;
        if (cgroupfs_parse_freeze(buffer, len, &kill) < 0 || !kill ||
            cgroupfs_kill_subtree_locked(node, &identity) < 0)
            goto fail;
    } else if (kind == CGROUPFS_INODE_FREEZE) {
        uint8_t frozen;
        if (cgroupfs_parse_freeze(buffer, len, &frozen) < 0) goto fail;
        if (g_cgroupfs.nodes[node].frozen != frozen) {
            g_cgroupfs.nodes[node].frozen = frozen;
            g_cgroupfs.nodes[node].ctime = cgroupfs_now();
            if (cgroupfs_event_path_locked(
                    node, g_cgroupfs_event_path,
                    sizeof(g_cgroupfs_event_path)) == 0)
                kernel_inotify_notify_path(
                    g_cgroupfs_event_path, KERNEL_INOTIFY_MODIFY, 0);
        }
    } else if (kind == CGROUPFS_INODE_MAX_DEPTH ||
               kind == CGROUPFS_INODE_MAX_DESCENDANTS) {
        uint32_t value;
        if (cgroupfs_parse_limit(buffer, len, &value) < 0) goto fail;
        if (kind == CGROUPFS_INODE_MAX_DEPTH) {
            if (value != CGROUPFS_LIMIT_MAX &&
                cgroupfs_subtree_height(node) > value)
                goto fail;
            g_cgroupfs.nodes[node].max_depth = value;
        } else {
            if (value != CGROUPFS_LIMIT_MAX &&
                cgroupfs_descendant_count(node) > value)
                goto fail;
            g_cgroupfs.nodes[node].max_descendants = value;
        }
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPUSET_CPUS ||
               kind == CGROUPFS_INODE_CPUSET_MEMS) {
        edge_cpumask_t mask;
        edge_cpumask_t effective;
        edge_cpumask_t previous;
        uint8_t configured;
        uint8_t previous_configured;
        uint32_t resources = kind == CGROUPFS_INODE_CPUSET_CPUS ?
                             edge_smp_nr_cpu_ids() : 1u;
        if (!cgroupfs_cpuset_available_locked(node) ||
            cgroupfs_parse_resource_set(
                buffer, len, resources, &mask, &configured) < 0)
            goto fail;
        if (kind == CGROUPFS_INODE_CPUSET_CPUS) {
            previous = g_cgroupfs.nodes[node].cpuset_cpus;
            previous_configured =
                g_cgroupfs.nodes[node].cpuset_cpus_configured;
            g_cgroupfs.nodes[node].cpuset_cpus_configured = configured;
            g_cgroupfs.nodes[node].cpuset_cpus = mask;
            cgroupfs_cpuset_effective_locked(node, 0, &effective);
            if (!edge_cpumask_weight(&effective)) {
                g_cgroupfs.nodes[node].cpuset_cpus = previous;
                g_cgroupfs.nodes[node].cpuset_cpus_configured =
                    previous_configured;
                goto fail;
            }
        } else {
            previous = g_cgroupfs.nodes[node].cpuset_mems;
            previous_configured =
                g_cgroupfs.nodes[node].cpuset_mems_configured;
            g_cgroupfs.nodes[node].cpuset_mems_configured = configured;
            g_cgroupfs.nodes[node].cpuset_mems = mask;
            cgroupfs_cpuset_effective_locked(node, 1, &effective);
            if (!edge_cpumask_weight(&effective)) {
                g_cgroupfs.nodes[node].cpuset_mems = previous;
                g_cgroupfs.nodes[node].cpuset_mems_configured =
                    previous_configured;
                goto fail;
            }
        }
        for (uint32_t child = 0; child < CGROUPFS_MAX_NODES; ++child) {
            if (!g_cgroupfs.nodes[child].used ||
                !cgroupfs_is_descendant(child, node))
                continue;
            cgroupfs_cpuset_effective_locked(
                child, kind == CGROUPFS_INODE_CPUSET_MEMS, &effective);
            if (edge_cpumask_weight(&effective)) continue;
            if (kind == CGROUPFS_INODE_CPUSET_CPUS) {
                g_cgroupfs.nodes[node].cpuset_cpus = previous;
                g_cgroupfs.nodes[node].cpuset_cpus_configured =
                    previous_configured;
            } else {
                g_cgroupfs.nodes[node].cpuset_mems = previous;
                g_cgroupfs.nodes[node].cpuset_mems_configured =
                    previous_configured;
            }
            goto fail;
        }
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPU_WEIGHT) {
        uint32_t weight;
        if (!cgroupfs_cpu_available_locked(node) ||
            cgroupfs_parse_cpu_weight(buffer, len, &weight) < 0)
            goto fail;
        g_cgroupfs.nodes[node].cpu_weight = weight;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPU_WEIGHT_NICE) {
        int32_t nice;
        if (!cgroupfs_cpu_available_locked(node) ||
            cgroupfs_parse_cpu_nice(buffer, len, &nice) < 0)
            goto fail;
        g_cgroupfs.nodes[node].cpu_weight =
            cgroupfs_cpu_weight_from_nice(nice);
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPU_MAX) {
        uint64_t quota;
        uint64_t period;
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (!cgroupfs_cpu_available_locked(node) ||
            cgroupfs_parse_cpu_max(buffer, len, group->cpu_period_us,
                                   &quota, &period) < 0)
            goto fail;
        group->cpu_quota_us = quota;
        group->cpu_period_us = period;
        group->cpu_burst_credit_us = 0;
        group->cpu_period_start_us = 0;
        group->cpu_period_usage_us = 0;
        group->cpu_throttled = 0;
        group->cpu_throttle_start_us = 0;
        group->ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPU_MAX_BURST) {
        uint64_t burst;
        cgroupfs_node_t *group = &g_cgroupfs.nodes[node];
        if (!cgroupfs_cpu_available_locked(node) ||
            cgroupfs_parse_cpu_burst(buffer, len, &burst) < 0)
            goto fail;
        group->cpu_burst_us = burst;
        group->cpu_burst_credit_us = 0;
        group->ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPU_IDLE) {
        uint8_t idle;
        if (!cgroupfs_cpu_available_locked(node) ||
            cgroupfs_parse_cpu_idle(buffer, len, &idle) < 0)
            goto fail;
        g_cgroupfs.nodes[node].cpu_idle = idle;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_CPU_UCLAMP_MIN ||
               kind == CGROUPFS_INODE_CPU_UCLAMP_MAX) {
        uint32_t value;
        if (!cgroupfs_cpu_available_locked(node) ||
            cgroupfs_parse_cpu_uclamp(
                buffer, len, kind == CGROUPFS_INODE_CPU_UCLAMP_MAX,
                &value) < 0)
            goto fail;
        if (kind == CGROUPFS_INODE_CPU_UCLAMP_MIN)
            g_cgroupfs.nodes[node].cpu_uclamp_min = value;
        else
            g_cgroupfs.nodes[node].cpu_uclamp_max = value;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_PIDS_MAX) {
        uint32_t value;
        if (!cgroupfs_pids_available_locked(node) ||
            cgroupfs_parse_limit(buffer, len, &value) < 0)
            goto fail;
        g_cgroupfs.nodes[node].pids_max = value;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_MEMORY_MIN ||
               kind == CGROUPFS_INODE_MEMORY_LOW ||
               kind == CGROUPFS_INODE_MEMORY_HIGH ||
               kind == CGROUPFS_INODE_MEMORY_MAX) {
        uint64_t value;
        uint64_t memory_flags;
        if (!cgroupfs_memory_available_locked(node) || node == 0 ||
            cgroupfs_parse_u64_limit(buffer, len, &value) < 0)
            goto fail;
        if ((kind == CGROUPFS_INODE_MEMORY_MIN ||
             kind == CGROUPFS_INODE_MEMORY_LOW) &&
            value == UINT64_MAX)
            goto fail;
        memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
        if (kind == CGROUPFS_INODE_MEMORY_MIN)
            g_cgroupfs.nodes[node].memory_min = value;
        else if (kind == CGROUPFS_INODE_MEMORY_LOW)
            g_cgroupfs.nodes[node].memory_low = value;
        else if (kind == CGROUPFS_INODE_MEMORY_HIGH)
            g_cgroupfs.nodes[node].memory_high = value;
        else
            g_cgroupfs.nodes[node].memory_max = value;
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_MEMORY_PEAK) {
        uint64_t value;
        uint64_t memory_flags;
        if (!cgroupfs_memory_available_locked(node) || node == 0 ||
            cgroupfs_parse_u64_limit(buffer, len, &value) < 0 || value != 0)
            goto fail;
        memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
        g_cgroupfs.nodes[node].memory_peak =
            g_cgroupfs.nodes[node].memory_current;
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_MEMORY_OOM_GROUP) {
        uint8_t enabled;
        uint64_t memory_flags;
        if (!cgroupfs_memory_available_locked(node) || node == 0 ||
            cgroupfs_parse_freeze(buffer, len, &enabled) < 0)
            goto fail;
        memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
        g_cgroupfs.nodes[node].memory_oom_group = enabled;
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_MEMORY_SWAP_PEAK) {
        uint64_t value;
        uint64_t memory_flags;
        if (!cgroupfs_memory_available_locked(node) || node == 0 ||
            cgroupfs_parse_u64_limit(buffer, len, &value) < 0 || value != 0)
            goto fail;
        memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
        g_cgroupfs.nodes[node].memory_swap_peak =
            g_cgroupfs.nodes[node].memory_swap_current;
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_MEMORY_SWAP_HIGH ||
               kind == CGROUPFS_INODE_MEMORY_SWAP_MAX) {
        uint64_t value;
        uint64_t memory_flags;
        if (!cgroupfs_memory_available_locked(node) ||
            cgroupfs_parse_u64_limit(buffer, len, &value) < 0)
            goto fail;
        memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
        if (kind == CGROUPFS_INODE_MEMORY_SWAP_HIGH)
            g_cgroupfs.nodes[node].memory_swap_high = value;
        else
            g_cgroupfs.nodes[node].memory_swap_max = value;
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_MEMORY_RECLAIM) {
        if (!cgroupfs_memory_available_locked(node) || node == 0 ||
            cgroupfs_parse_u64_limit(buffer, len, &reclaim_bytes) < 0 ||
            reclaim_bytes == UINT64_MAX)
            goto fail;
        reclaim_requested = 1;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_IO_WEIGHT) {
        int device_specific;
        uint32_t major = 0;
        uint32_t minor = 0;
        uint32_t weight;
        cgroupfs_io_device_t *device;
        if (!cgroupfs_io_available_locked(node) ||
            cgroupfs_parse_io_weight(
                buffer, len, &device_specific, &major, &minor,
                &weight) < 0)
            goto fail;
        if (device_specific) {
            device = cgroupfs_io_device_locked(
                &g_cgroupfs.nodes[node], major, minor, 1);
            if (!device) goto fail;
            device->weight = weight;
        } else {
            g_cgroupfs.nodes[node].io_weight = weight;
        }
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else if (kind == CGROUPFS_INODE_IO_MAX) {
        uint32_t major;
        uint32_t minor;
        uint32_t fields;
        uint64_t values[4] = {0, 0, 0, 0};
        cgroupfs_io_device_t *device;
        if (!cgroupfs_io_available_locked(node) ||
            cgroupfs_parse_io_max(
                buffer, len, &major, &minor, &fields, values) < 0)
            goto fail;
        device = cgroupfs_io_device_locked(
            &g_cgroupfs.nodes[node], major, minor, 1);
        if (!device) goto fail;
        if (fields & CGROUPFS_IO_MAX_RBPS)
            device->read_bytes_per_second = values[0];
        if (fields & CGROUPFS_IO_MAX_WBPS)
            device->write_bytes_per_second = values[1];
        if (fields & CGROUPFS_IO_MAX_RIOPS)
            device->read_operations_per_second = values[2];
        if (fields & CGROUPFS_IO_MAX_WIOPS)
            device->write_operations_per_second = values[3];
        device->limits_configured = 1u;
        device->read_byte_deadline_us = 0;
        device->write_byte_deadline_us = 0;
        device->read_operation_deadline_us = 0;
        device->write_operation_deadline_us = 0;
        g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    } else {
        goto fail;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    if (reclaim_requested) {
        uint64_t remaining_pages =
            reclaim_bytes / KERNEL_MM_USER_PAGE_SIZE +
            (reclaim_bytes % KERNEL_MM_USER_PAGE_SIZE != 0u);

        while (remaining_pages) {
            uint32_t batch = remaining_pages > 64u ?
                             64u : (uint32_t)remaining_pages;
            uint32_t reclaimed = kernel_mm_reclaim_pages(node, batch);

            if (!reclaimed) break;
            remaining_pages -= reclaimed > remaining_pages ?
                               remaining_pages : reclaimed;
            if (reclaimed < batch) break;
        }
    }
    if (membership_changed) {
        cgroupfs_task_state_changed(old_cgroup);
        if (node != old_cgroup) cgroupfs_task_state_changed(node);
    }
    return (int)len;
fail:
    cgroupfs_unlock(&g_cgroupfs_lock);
    return -1;
}

static int cgroupfs_valid_name(const char *name) {
    uint32_t length = 0;
    if (!name || !name[0] || strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0)
        return 0;
    while (name[length]) {
        if (name[length] == '/' || ++length >= VFS_NAME_MAX) return 0;
    }
    if (length >= 7u && name[0] == 'c' && name[1] == 'g' && name[2] == 'r' &&
        name[3] == 'o' && name[4] == 'u' && name[5] == 'p' && name[6] == '.')
        return 0;
    return 1;
}

static int cgroupfs_alloc_node(uint32_t uid, uint32_t gid) {
    for (uint32_t index = 1; index < CGROUPFS_MAX_NODES; ++index) {
        if (g_cgroupfs.nodes[index].used) continue;
        memset(&g_cgroupfs.nodes[index], 0,
               sizeof(g_cgroupfs.nodes[index]));
        g_cgroupfs.nodes[index].used = 1;
        g_cgroupfs.nodes[index].populated_known = 1u;
        if (!++g_cgroupfs.next_generation) ++g_cgroupfs.next_generation;
        g_cgroupfs.nodes[index].generation = g_cgroupfs.next_generation;
        g_cgroupfs.nodes[index].max_depth = CGROUPFS_LIMIT_MAX;
        g_cgroupfs.nodes[index].max_descendants = CGROUPFS_LIMIT_MAX;
        cgroupfs_initialize_cpu(&g_cgroupfs.nodes[index]);
        cgroupfs_initialize_pids(&g_cgroupfs.nodes[index]);
        cgroupfs_initialize_memory(&g_cgroupfs.nodes[index]);
        cgroupfs_initialize_io(&g_cgroupfs.nodes[index]);
        g_cgroupfs.nodes[index].uid = uid;
        g_cgroupfs.nodes[index].gid = gid;
        cgroupfs_initialize_interface_metadata(&g_cgroupfs.nodes[index]);
        return (int)index;
    }
    return -1;
}

static int cgroupfs_mkdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                          const char *name, uint16_t mode, vfs_inode_t *out) {
    kernel_linux_identity_t identity;
    uint32_t parent;
    uint32_t new_depth;
    int allocated;
    (void)sb;
    if (!dir || !out || !cgroupfs_valid_name(name) ||
        dir->fs_private[0] != CGROUPFS_INODE_DIRECTORY)
        return -1;
    /* vfs_mkdir_mode() has already enforced write/search permission. */
    if (kernel_current_linux_identity(&identity) < 0) return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(dir, &parent) < 0 ||
        cgroupfs_find_child(parent, name) >= 0)
        goto fail;
    new_depth = cgroupfs_node_depth(parent) + 1u;
    for (uint32_t ancestor = parent, guard = 0;
         guard < CGROUPFS_MAX_NODES; ++guard) {
        uint32_t ancestor_depth = cgroupfs_node_depth(ancestor);
        cgroupfs_node_t *limit = &g_cgroupfs.nodes[ancestor];
        if (limit->max_depth != CGROUPFS_LIMIT_MAX &&
            new_depth - ancestor_depth > limit->max_depth)
            goto fail;
        if (limit->max_descendants != CGROUPFS_LIMIT_MAX &&
            cgroupfs_descendant_count(ancestor) + 1u >
                limit->max_descendants)
            goto fail;
        if (!ancestor) break;
        ancestor = limit->parent;
    }
    allocated = cgroupfs_alloc_node(identity.fsuid, identity.fsgid);
    if (allocated < 0) goto fail;
    g_cgroupfs.nodes[allocated].parent = parent;
    g_cgroupfs.nodes[allocated].subtree_controllers =
        g_cgroupfs.nodes[parent].subtree_controllers;
    g_cgroupfs.nodes[allocated].mode = (uint16_t)(mode & 0777u);
    g_cgroupfs.nodes[allocated].ctime = cgroupfs_now();
    strncpy(g_cgroupfs.nodes[allocated].name, name,
            sizeof(g_cgroupfs.nodes[allocated].name) - 1u);
    cgroupfs_fill_inode((uint32_t)allocated, CGROUPFS_INODE_DIRECTORY,
                        g_cgroupfs.nodes[allocated].mode, out);
    cgroupfs_unlock(&g_cgroupfs_lock);
    return 0;
fail:
    cgroupfs_unlock(&g_cgroupfs_lock);
    return -1;
}

static int cgroupfs_node_has_tasks(uint32_t node) {
    for (uint32_t ordinal = 0;; ++ordinal) {
        kernel_proc_task_snapshot_t leader;
        int32_t pid;
        if (kernel_proc_task_at(ordinal, &pid) < 0) break;
        if (kernel_proc_task_snapshot(pid, &leader) < 0) continue;
        if (leader.state != 'Z' && leader.cgroup_id == node)
            return 1;
        if (leader.tgid <= 0) continue;
        for (uint32_t thread_ordinal = 0;; ++thread_ordinal) {
            kernel_proc_task_snapshot_t thread;
            int32_t tid;
            if (kernel_proc_thread_at(leader.tgid, thread_ordinal, &tid) < 0)
                break;
            if (kernel_proc_task_snapshot(tid, &thread) == 0 &&
                thread.state != 'Z' && thread.cgroup_id == node)
                return 1;
        }
    }
    return 0;
}

static int cgroupfs_rmdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                          const char *name) {
    uint32_t parent;
    uint64_t memory_flags;
    int child;
    (void)sb;
    if (!dir || !cgroupfs_valid_name(name) ||
        dir->fs_private[0] != CGROUPFS_INODE_DIRECTORY)
        return VFS_PATH_ERR_INVALID;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(dir, &parent) < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_INVALID;
    }
    child = cgroupfs_find_child(parent, name);
    if (child < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_NOT_FOUND;
    }
    if (cgroupfs_descendant_count((uint32_t)child) != 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_NOT_EMPTY;
    }
    memory_flags = spin_lock_irqsave(&g_cgroupfs_memory_lock);
    if (g_cgroupfs.nodes[child].memory_current != 0) {
        spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_BUSY;
    }
    spin_unlock_irqrestore(&g_cgroupfs_memory_lock, memory_flags);
    if (cgroupfs_node_has_tasks((uint32_t)child)) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_BUSY;
    }
    memset(&g_cgroupfs.nodes[child], 0, sizeof(g_cgroupfs.nodes[child]));
    cgroupfs_unlock(&g_cgroupfs_lock);
    return 0;
}

static int cgroupfs_rename(vfs_superblock_t *sb, vfs_inode_t *old_dir,
                           const char *old_name, vfs_inode_t *new_dir,
                           const char *new_name) {
    uint32_t old_parent;
    uint32_t new_parent;
    uint32_t subtree_size;
    uint32_t subtree_height;
    uint32_t new_depth;
    int node;
    (void)sb;
    if (!old_dir || !new_dir || !cgroupfs_valid_name(old_name) ||
        !cgroupfs_valid_name(new_name) ||
        old_dir->fs_private[0] != CGROUPFS_INODE_DIRECTORY ||
        new_dir->fs_private[0] != CGROUPFS_INODE_DIRECTORY)
        return VFS_PATH_ERR_INVALID;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(old_dir, &old_parent) < 0 ||
        cgroupfs_inode_node(new_dir, &new_parent) < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_INVALID;
    }
    node = cgroupfs_find_child(old_parent, old_name);
    if (node < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_NOT_FOUND;
    }
    if (old_parent == new_parent && strcmp(old_name, new_name) == 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    if (cgroupfs_find_child(new_parent, new_name) >= 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return VFS_PATH_ERR_EXISTS;
    }
    if (cgroupfs_is_descendant(new_parent, (uint32_t)node))
        goto fail;
    subtree_size = cgroupfs_descendant_count((uint32_t)node) + 1u;
    subtree_height = cgroupfs_subtree_height((uint32_t)node);
    new_depth = cgroupfs_node_depth(new_parent) + 1u;
    for (uint32_t ancestor = new_parent, guard = 0;
         guard < CGROUPFS_MAX_NODES; ++guard) {
        cgroupfs_node_t *limit = &g_cgroupfs.nodes[ancestor];
        uint32_t ancestor_depth = cgroupfs_node_depth(ancestor);
        uint32_t count = cgroupfs_descendant_count(ancestor);
        if (!cgroupfs_is_descendant((uint32_t)node, ancestor))
            count += subtree_size;
        if (limit->max_descendants != CGROUPFS_LIMIT_MAX &&
            count > limit->max_descendants)
            goto fail;
        if (limit->max_depth != CGROUPFS_LIMIT_MAX &&
            new_depth + subtree_height - ancestor_depth > limit->max_depth)
            goto fail;
        if (!ancestor) break;
        ancestor = limit->parent;
    }
    g_cgroupfs.nodes[node].parent = new_parent;
    g_cgroupfs.nodes[node].cpu_scheduler_vruntime_valid = 0u;
    memset(g_cgroupfs.nodes[node].name, 0,
           sizeof(g_cgroupfs.nodes[node].name));
    strncpy(g_cgroupfs.nodes[node].name, new_name,
            sizeof(g_cgroupfs.nodes[node].name) - 1u);
    g_cgroupfs.nodes[node].ctime = cgroupfs_now();
    cgroupfs_unlock(&g_cgroupfs_lock);
    return 0;
fail:
    cgroupfs_unlock(&g_cgroupfs_lock);
    return VFS_PATH_ERR_INVALID;
}

static int cgroupfs_readdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                            uint32_t index, char *name, vfs_inode_t *out) {
    uint32_t node;
    uint32_t child_ordinal;
    uint32_t visible_interfaces = 0;
    (void)sb;
    if (!dir || !name || !out ||
        dir->fs_private[0] != CGROUPFS_INODE_DIRECTORY)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(dir, &node) < 0) goto fail;
    if (index == 0) {
        strcpy(name, ".");
        cgroupfs_fill_inode(node, CGROUPFS_INODE_DIRECTORY,
                            g_cgroupfs.nodes[node].mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    if (index == 1) {
        uint32_t parent = g_cgroupfs.nodes[node].parent;
        strcpy(name, "..");
        cgroupfs_fill_inode(parent, CGROUPFS_INODE_DIRECTORY,
                            g_cgroupfs.nodes[parent].mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    index -= 2u;
    for (uint32_t interface_index = 0;
         interface_index < sizeof(g_cgroup_interfaces) /
                               sizeof(g_cgroup_interfaces[0]);
         ++interface_index) {
        const cgroupfs_interface_t *interface =
            &g_cgroup_interfaces[interface_index];
        if (!cgroupfs_interface_visible_locked(node, interface->kind))
            continue;
        if (index != visible_interfaces++) continue;
        strcpy(name, interface->name);
        cgroupfs_fill_inode(node, interface->kind, interface->mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
    child_ordinal = index - visible_interfaces;
    for (uint32_t child = 1; child < CGROUPFS_MAX_NODES; ++child) {
        if (!g_cgroupfs.nodes[child].used ||
            g_cgroupfs.nodes[child].parent != node)
            continue;
        if (child_ordinal) {
            --child_ordinal;
            continue;
        }
        strcpy(name, g_cgroupfs.nodes[child].name);
        cgroupfs_fill_inode(child, CGROUPFS_INODE_DIRECTORY,
                            g_cgroupfs.nodes[child].mode, out);
        cgroupfs_unlock(&g_cgroupfs_lock);
        return 0;
    }
fail:
    cgroupfs_unlock(&g_cgroupfs_lock);
    return -1;
}

static int cgroupfs_statfs(vfs_superblock_t *sb, uint32_t *total,
                           uint32_t *used) {
    (void)sb;
    if (!total || !used) return -1;
    *total = 0;
    *used = 0;
    return 0;
}

static int cgroupfs_truncate(vfs_superblock_t *sb, vfs_inode_t *inode,
                             uint32_t length) {
    uint32_t node;
    int valid;
    (void)sb;
    /* Linux permits O_TRUNC when opening writable cgroup control files. */
    if (!inode || length != 0 ||
        inode->fs_private[0] == CGROUPFS_INODE_DIRECTORY)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    valid = cgroupfs_inode_node(inode, &node) == 0;
    cgroupfs_unlock(&g_cgroupfs_lock);
    return valid ? 0 : -1;
}

static int cgroupfs_getattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                            vfs_inode_t *out) {
    uint32_t node;
    uint32_t kind;
    int result = -1;
    (void)sb;
    if (!inode || !out) return -1;
    kind = inode->fs_private[0];
    if (kind < CGROUPFS_INODE_DIRECTORY ||
        kind > CGROUPFS_INODE_LAST)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(inode, &node) == 0 &&
        cgroupfs_interface_visible_locked(node, kind)) {
        cgroupfs_fill_inode(node, kind, g_cgroupfs.nodes[node].mode, out);
        result = 0;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    return result;
}

static int cgroupfs_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                            uint16_t mode, uint32_t uid, uint32_t gid,
                            uint32_t valid) {
    cgroupfs_node_t *group;
    cgroupfs_inode_metadata_t *metadata = 0;
    uint32_t node;
    uint32_t kind;
    uint32_t now;
    (void)sb;
    if (!inode || !valid ||
        (valid & ~(VFS_SETATTR_MODE | VFS_SETATTR_UID | VFS_SETATTR_GID |
                   VFS_SETATTR_CTIME)))
        return -1;
    kind = inode->fs_private[0];
    if (kind < CGROUPFS_INODE_DIRECTORY ||
        kind > CGROUPFS_INODE_LAST)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (cgroupfs_inode_node(inode, &node) < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return -1;
    }
    group = &g_cgroupfs.nodes[node];
    if (!cgroupfs_interface_visible_locked(node, kind)) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return -1;
    }
    if (kind != CGROUPFS_INODE_DIRECTORY)
        metadata = &group->interface_metadata[kind];
    now = cgroupfs_now();
    if (metadata) {
        if (valid & VFS_SETATTR_MODE) metadata->mode = (uint16_t)(mode & 07777u);
        if (valid & VFS_SETATTR_UID) metadata->uid = uid;
        if (valid & VFS_SETATTR_GID) metadata->gid = gid;
        metadata->ctime = now;
    } else {
        if (valid & VFS_SETATTR_MODE) group->mode = (uint16_t)(mode & 07777u);
        if (valid & VFS_SETATTR_UID) group->uid = uid;
        if (valid & VFS_SETATTR_GID) group->gid = gid;
        group->ctime = now;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    return 0;
}

static filesystem_ops_t g_cgroupfs_ops = {
    .lookup = cgroupfs_lookup,
    .read = cgroupfs_read,
    .write = cgroupfs_write,
    .mkdir = cgroupfs_mkdir,
    .rename = cgroupfs_rename,
    .readdir = cgroupfs_readdir,
    .statfs = cgroupfs_statfs,
    .rmdir = cgroupfs_rmdir,
    .truncate = cgroupfs_truncate,
    .getattr = cgroupfs_getattr,
    .setattr = cgroupfs_setattr
};

int cgroupfs_mount(const char *dev, const char *target) {
    const char *source = dev && dev[0] ? dev : "cgroup2";
    if (!target) return -1;
    if (vfs_mount_exists(target, "cgroup2", source)) return 0;
    cgroupfs_initialize();
    memset(&g_cgroupfs_sb, 0, sizeof(g_cgroupfs_sb));
    strcpy(g_cgroupfs_sb.fs_name, "cgroup2");
    strncpy(g_cgroupfs_sb.dev_name, source,
            sizeof(g_cgroupfs_sb.dev_name) - 1u);
    strncpy(g_cgroupfs_sb.mountpoint, target,
            sizeof(g_cgroupfs_sb.mountpoint) - 1u);
    cgroupfs_lock(&g_cgroupfs_lock);
    cgroupfs_fill_inode(0, CGROUPFS_INODE_DIRECTORY,
                        g_cgroupfs.nodes[0].mode, &g_cgroupfs_sb.root);
    cgroupfs_unlock(&g_cgroupfs_lock);
    g_cgroupfs_sb.ops = &g_cgroupfs_ops;
    g_cgroupfs_sb.fs_private = &g_cgroupfs;
    return vfs_add_superblock(&g_cgroupfs_sb);
}

int cgroupfs_directory_valid(vfs_superblock_t *sb,
                             const vfs_inode_t *inode) {
    uint32_t node;
    int valid;
    /*
     * vfs_add_superblock() installs a value copy in the active mount table,
     * and mount namespaces retain further copies of that table.  File
     * descriptors therefore point at the mounted instance rather than the
     * registration object.  Identify cgroup2 by its real operations and
     * backing state; pointer equality with g_cgroupfs_sb incorrectly rejects
     * valid O_PATH directory descriptors used by clone3(CLONE_INTO_CGROUP).
     */
    if (!sb || sb->ops != &g_cgroupfs_ops ||
        sb->fs_private != &g_cgroupfs || !inode)
        return 0;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    valid = inode->fs_private[0] == CGROUPFS_INODE_DIRECTORY &&
            cgroupfs_inode_node(inode, &node) == 0;
    cgroupfs_unlock(&g_cgroupfs_lock);
    return valid;
}

int cgroupfs_attach_process(vfs_superblock_t *sb,
                            const vfs_inode_t *inode, int32_t pid) {
    kernel_proc_task_snapshot_t target;
    uint32_t old_cgroup;
    uint32_t node;
    int result;
    if (!sb || sb->ops != &g_cgroupfs_ops ||
        sb->fs_private != &g_cgroupfs || !inode || pid <= 0)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    if (inode->fs_private[0] != CGROUPFS_INODE_DIRECTORY ||
        cgroupfs_inode_node(inode, &node) < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return -1;
    }
    if (kernel_proc_task_snapshot(pid, &target) < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return -1;
    }
    old_cgroup = target.cgroup_id;
    result = kernel_proc_cgroup_attach(pid, node, 1);
    cgroupfs_unlock(&g_cgroupfs_lock);
    if (result == 0) {
        cgroupfs_task_state_changed(old_cgroup);
        if (node != old_cgroup) cgroupfs_task_state_changed(node);
    }
    return result;
}

int cgroupfs_proc_cgroups_snapshot(char *buffer, uint32_t capacity) {
    uint32_t offset = 0;
    uint32_t count = 0;
    if (!buffer || !capacity) return -1;
    if (cgroupfs_append(buffer, capacity, &offset,
                        "#subsys_name\thierarchy\tnum_cgroups\tenabled\n") < 0)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    for (uint32_t node = 0; node < CGROUPFS_MAX_NODES; ++node)
        if (g_cgroupfs.nodes[node].used) ++count;
    cgroupfs_unlock(&g_cgroupfs_lock);
    if (cgroupfs_append(buffer, capacity, &offset, "cpu\t0\t") < 0 ||
        cgroupfs_append_u32(buffer, capacity, &offset, count) < 0 ||
        cgroupfs_append(buffer, capacity, &offset, "\t1\n") < 0)
        return -1;
    if (cgroupfs_append(buffer, capacity, &offset, "pids\t0\t") < 0 ||
        cgroupfs_append_u32(buffer, capacity, &offset, count) < 0 ||
        cgroupfs_append(buffer, capacity, &offset, "\t1\n") < 0)
        return -1;
    if (cgroupfs_append(buffer, capacity, &offset, "memory\t0\t") < 0 ||
        cgroupfs_append_u32(buffer, capacity, &offset, count) < 0 ||
        cgroupfs_append(buffer, capacity, &offset, "\t1\n") < 0)
        return -1;
    if (cgroupfs_append(buffer, capacity, &offset, "io\t0\t") < 0 ||
        cgroupfs_append_u32(buffer, capacity, &offset, count) < 0 ||
        cgroupfs_append(buffer, capacity, &offset, "\t1\n") < 0)
        return -1;
    return (int)offset;
}

int cgroupfs_proc_pid_snapshot(int32_t pid, char *buffer,
                               uint32_t capacity) {
    kernel_proc_task_snapshot_t task;
    uint32_t chain[CGROUPFS_MAX_NODES];
    uint32_t count = 0;
    uint32_t offset = 0;
    uint32_t node;
    if (!buffer || !capacity || pid <= 0 ||
        kernel_proc_task_snapshot(pid, &task) < 0)
        return -1;
    cgroupfs_initialize();
    cgroupfs_lock(&g_cgroupfs_lock);
    node = cgroupfs_node_valid(task.cgroup_id, 0) ? task.cgroup_id : 0;
    while (node && count < CGROUPFS_MAX_NODES) {
        chain[count++] = node;
        node = g_cgroupfs.nodes[node].parent;
    }
    if (node || cgroupfs_append(buffer, capacity, &offset, "0::/") < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return -1;
    }
    while (count) {
        cgroupfs_node_t *group = &g_cgroupfs.nodes[chain[--count]];
        if (cgroupfs_append(buffer, capacity, &offset, group->name) < 0 ||
            (count && cgroupfs_append(buffer, capacity, &offset, "/") < 0)) {
            cgroupfs_unlock(&g_cgroupfs_lock);
            return -1;
        }
    }
    if (cgroupfs_append(buffer, capacity, &offset, "\n") < 0) {
        cgroupfs_unlock(&g_cgroupfs_lock);
        return -1;
    }
    cgroupfs_unlock(&g_cgroupfs_lock);
    return (int)offset;
}
