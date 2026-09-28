/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-independent BSD process accounting runtime. */

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/process_accounting.h"
#include "kernel/proc_maps.h"
#include "kernel/runtime_limits.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/boottime.h"

#define PROCESS_ACCOUNTING_MAX_NAMESPACES 64u
#define PROCESS_ACCOUNTING_AHZ 100u
#define PROCESS_ACCOUNTING_MANTISSA_BITS 13u
#define PROCESS_ACCOUNTING_EXPONENT_SHIFT 3u
#define PROCESS_ACCOUNTING_MAX_MANTISSA \
    ((1u << PROCESS_ACCOUNTING_MANTISSA_BITS) - 1u)

#define PROCESS_ACCOUNTING_FLAG_FORK_NO_EXEC 0x01u
#define PROCESS_ACCOUNTING_FLAG_SIGNAL       0x10u

typedef struct process_accounting_target {
    uint8_t used;
    uint8_t retiring;
    uint32_t writers;
    uint32_t pid_namespace_id;
    vfs_superblock_t *superblock;
    vfs_inode_t inode;
    char path[VFS_PATH_MAX];
} process_accounting_target_t;

typedef struct process_accounting_group {
    uint8_t used;
    uint8_t leader_status_valid;
    uint8_t leader_fork_no_exec;
    uint8_t signaled;
    uint32_t pid_namespace_id;
    int32_t tgid;
    int32_t leader_exit_code;
    uint32_t leader_signal;
    uint64_t user_time_us;
    uint64_t system_time_us;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t earliest_start_ticks;
    uint64_t virtual_memory_kb;
} process_accounting_group_t;

static process_accounting_target_t
    g_process_accounting_targets[PROCESS_ACCOUNTING_MAX_NAMESPACES];
static process_accounting_group_t
    g_process_accounting_groups[EDGE_RUNTIME_MAX_TASKS];
static volatile uint32_t g_process_accounting_lock;

static void process_accounting_lock(void) {
    while (__sync_lock_test_and_set(&g_process_accounting_lock, 1u)) { }
}

static void process_accounting_unlock(void) {
    __sync_lock_release(&g_process_accounting_lock);
}

static uint64_t process_accounting_add_saturating(uint64_t left,
                                                  uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

kernel_process_accounting_comp_t kernel_process_accounting_encode_comp(
    uint64_t value) {
    uint32_t exponent = 0u;
    uint32_t round = 0u;

    while (value > PROCESS_ACCOUNTING_MAX_MANTISSA) {
        round = (uint32_t)(
            value & (1u << (PROCESS_ACCOUNTING_EXPONENT_SHIFT - 1u)));
        value >>= PROCESS_ACCOUNTING_EXPONENT_SHIFT;
        ++exponent;
    }
    if (round && ++value > PROCESS_ACCOUNTING_MAX_MANTISSA) {
        value >>= PROCESS_ACCOUNTING_EXPONENT_SHIFT;
        ++exponent;
    }
    if (exponent > 7u) return UINT16_MAX;
    return (kernel_process_accounting_comp_t)(
        (exponent << PROCESS_ACCOUNTING_MANTISSA_BITS) | (uint32_t)value);
}

uint32_t kernel_process_accounting_encode_float(uint64_t value) {
    uint32_t exponent = 190u;
    uint32_t mantissa;

    if (!value) return 0u;
    while ((int64_t)value > 0) {
        value <<= 1u;
        --exponent;
    }
    mantissa = (uint32_t)(value >> 40u) & 0x7fffffu;
    return mantissa | (exponent << 23u);
}

static int process_accounting_path_copy(char *destination,
                                        const char *source) {
    uint32_t length = 0u;
    if (!source || source[0] != '/')
        return -EDGE_LINUX_EINVAL;
    while (source[length]) {
        if (length + 1u >= VFS_PATH_MAX)
            return -EDGE_LINUX_ENAMETOOLONG;
        if (destination) destination[length] = source[length];
        ++length;
    }
    if (destination) destination[length] = 0;
    return 0;
}

static int process_accounting_target_find_locked(uint32_t namespace_id) {
    uint32_t index;
    for (index = 0; index < PROCESS_ACCOUNTING_MAX_NAMESPACES; ++index)
        if (g_process_accounting_targets[index].used &&
            g_process_accounting_targets[index].pid_namespace_id ==
                namespace_id)
            return (int)index;
    return -1;
}

static int process_accounting_target_free_slot_locked(void) {
    uint32_t index;
    for (index = 0; index < PROCESS_ACCOUNTING_MAX_NAMESPACES; ++index)
        if (!g_process_accounting_targets[index].used &&
            !g_process_accounting_targets[index].retiring &&
            !g_process_accounting_targets[index].writers)
            return (int)index;
    return -1;
}

static int process_accounting_group_find_locked(uint32_t namespace_id,
                                                int32_t tgid) {
    uint32_t index;
    for (index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index)
        if (g_process_accounting_groups[index].used &&
            g_process_accounting_groups[index].pid_namespace_id ==
                namespace_id &&
            g_process_accounting_groups[index].tgid == tgid)
            return (int)index;
    return -1;
}

static process_accounting_group_t *process_accounting_group_get_locked(
    uint32_t namespace_id, int32_t tgid, int create) {
    int existing = process_accounting_group_find_locked(namespace_id, tgid);
    uint32_t index;
    process_accounting_group_t *group;

    if (existing >= 0) return &g_process_accounting_groups[existing];
    if (!create) return 0;
    for (index = 0; index < EDGE_RUNTIME_MAX_TASKS; ++index)
        if (!g_process_accounting_groups[index].used) break;
    if (index == EDGE_RUNTIME_MAX_TASKS) return 0;
    group = &g_process_accounting_groups[index];
    memset(group, 0, sizeof(*group));
    group->used = 1u;
    group->pid_namespace_id = namespace_id;
    group->tgid = tgid;
    return group;
}

static void process_accounting_group_collect(
    process_accounting_group_t *group,
    const kernel_proc_task_view_t *task, int32_t exit_code,
    uint32_t terminating_signal) {
    if (!group || !task) return;
    group->user_time_us = process_accounting_add_saturating(
        group->user_time_us, task->usage.user_time_us);
    group->system_time_us = process_accounting_add_saturating(
        group->system_time_us, task->usage.sys_time_us);
    group->minor_faults = process_accounting_add_saturating(
        group->minor_faults, task->usage.minor_faults);
    group->major_faults = process_accounting_add_saturating(
        group->major_faults, task->usage.major_faults);
    if (!group->earliest_start_ticks ||
        (task->start_time_ticks &&
         task->start_time_ticks < group->earliest_start_ticks))
        group->earliest_start_ticks = task->start_time_ticks;
    if (task->tid == (task->tgid > 0 ? task->tgid : task->tid)) {
        group->leader_exit_code = exit_code;
        group->leader_signal = terminating_signal;
        group->leader_status_valid = 1u;
        group->leader_fork_no_exec = !task->execed_since_fork;
    }
    if (terminating_signal) group->signaled = 1u;
}

static void process_accounting_build_record(
    kernel_process_accounting_record_v3_t *record,
    const kernel_proc_task_view_t *task,
    const process_accounting_group_t *group, int32_t exit_code,
    uint32_t terminating_signal) {
    uint64_t now_monotonic_us = boottime_monotonic_us();
    uint64_t now_realtime_us = boottime_realtime_us();
    uint64_t start_us = group->earliest_start_ticks * 10000u;
    uint64_t elapsed_us = now_monotonic_us > start_us ?
        now_monotonic_us - start_us : 0u;
    uint64_t elapsed_ticks = elapsed_us / 10000u;
    uint64_t begin_seconds = now_realtime_us > elapsed_us ?
        (now_realtime_us - elapsed_us) / 1000000u : 0u;
    uint32_t signal = terminating_signal;
    int32_t status = exit_code;
    uint32_t index;

    if (group->leader_status_valid) {
        status = group->leader_exit_code;
        signal = group->leader_signal;
    }
    memset(record, 0, sizeof(*record));
    record->version = KERNEL_PROCESS_ACCOUNTING_VERSION;
    if (group->leader_fork_no_exec)
        record->flag |= PROCESS_ACCOUNTING_FLAG_FORK_NO_EXEC;
    if (group->signaled) record->flag |= PROCESS_ACCOUNTING_FLAG_SIGNAL;
    record->exit_code = ((uint32_t)status & 0xffu) << 8u;
    record->exit_code |= signal & 0x7fu;
    record->uid = task->uid;
    record->gid = task->gid;
    record->pid = (uint32_t)(task->tgid > 0 ? task->tgid : task->tid);
    record->ppid = task->ppid > 0 ? (uint32_t)task->ppid : 0u;
    record->begin_time = begin_seconds > UINT32_MAX ?
        UINT32_MAX : (uint32_t)begin_seconds;
    record->elapsed_time =
        kernel_process_accounting_encode_float(elapsed_ticks);
    record->user_time = kernel_process_accounting_encode_comp(
        group->user_time_us / 10000u);
    record->system_time = kernel_process_accounting_encode_comp(
        group->system_time_us / 10000u);
    record->memory = kernel_process_accounting_encode_comp(
        group->virtual_memory_kb);
    record->minor_faults = kernel_process_accounting_encode_comp(
        group->minor_faults);
    record->major_faults = kernel_process_accounting_encode_comp(
        group->major_faults);
    for (index = 0; index < sizeof(record->command) - 1u &&
                    task->comm[index]; ++index)
        record->command[index] = task->comm[index];
}

int kernel_process_accounting_enable(
    uint32_t pid_namespace_id, const char *path,
    vfs_superblock_t *superblock, const vfs_inode_t *inode) {
    process_accounting_target_t *target;
    vfs_superblock_t *previous_superblock = 0;
    vfs_inode_t previous_inode;
    vfs_superblock_t *stable;
    int previous_used = 0;
    int existing;
    int slot;
    int status;

    if (!path || !superblock || !inode ||
        (inode->mode & 0xf000u) != VFS_INODE_FILE)
        return -EDGE_LINUX_EACCES;
    if (!superblock->ops || !superblock->ops->write)
        return -EDGE_LINUX_EIO;
    if (superblock->mount_flags & VFS_MOUNT_READONLY)
        return -EDGE_LINUX_EROFS;
    status = process_accounting_path_copy(0, path);
    if (status < 0) return status;
    if (vfs_inode_open(superblock, inode) < 0)
        return -EDGE_LINUX_EIO;
    stable = vfs_superblock_stable(superblock);
    if (!stable) {
        vfs_inode_close(superblock, inode);
        return -EDGE_LINUX_EIO;
    }

    process_accounting_lock();
    existing = process_accounting_target_find_locked(pid_namespace_id);
    if (existing >= 0 &&
        !g_process_accounting_targets[existing].writers)
        slot = existing;
    else
        slot = process_accounting_target_free_slot_locked();
    if (slot >= 0) {
        target = &g_process_accounting_targets[slot];
        previous_used = target->used;
        if (previous_used) {
            previous_superblock = target->superblock;
            previous_inode = target->inode;
        }
        memset(target, 0, sizeof(*target));
        target->used = 1u;
        target->pid_namespace_id = pid_namespace_id;
        target->superblock = stable;
        target->inode = *inode;
        (void)process_accounting_path_copy(target->path, path);
        if (existing >= 0 && existing != slot) {
            g_process_accounting_targets[existing].used = 0u;
            g_process_accounting_targets[existing].retiring = 1u;
        }
    }
    process_accounting_unlock();
    if (slot < 0) {
        vfs_inode_close(stable, inode);
        return -EDGE_LINUX_ENOSPC;
    }
    if (previous_used)
        vfs_inode_close(previous_superblock, &previous_inode);
    return 0;
}

int kernel_process_accounting_disable(uint32_t pid_namespace_id) {
    vfs_superblock_t *previous_superblock = 0;
    vfs_inode_t previous_inode;
    int previous_used = 0;
    int slot;

    process_accounting_lock();
    slot = process_accounting_target_find_locked(pid_namespace_id);
    if (slot >= 0) {
        g_process_accounting_targets[slot].used = 0u;
        g_process_accounting_targets[slot].retiring = 1u;
        if (!g_process_accounting_targets[slot].writers) {
            previous_used = 1;
            previous_superblock =
                g_process_accounting_targets[slot].superblock;
            previous_inode = g_process_accounting_targets[slot].inode;
            memset(&g_process_accounting_targets[slot], 0,
                   sizeof(g_process_accounting_targets[slot]));
        }
    }
    process_accounting_unlock();
    if (previous_used)
        vfs_inode_close(previous_superblock, &previous_inode);
    return 0;
}

void kernel_process_accounting_task_exit(
    const kernel_proc_task_view_t *task, int32_t exit_code,
    uint32_t terminating_signal, int final_thread) {
    process_accounting_group_t *group;
    process_accounting_target_t *target;
    vfs_superblock_t *retired_superblock = 0;
    vfs_inode_t retired_inode;
    kernel_process_accounting_record_v3_t record;
    int target_pinned = 0;
    int retired = 0;
    int target_slot;
    int32_t tgid;
    uint32_t offset;
    kernel_proc_vma_accounting_t memory;

    if (!task || task->tid <= 0) return;
    tgid = task->tgid > 0 ? task->tgid : task->tid;
    memset(&memory, 0, sizeof(memory));
    if (final_thread &&
        kernel_proc_vma_account(task->tid, &memory) < 0)
        memset(&memory, 0, sizeof(memory));
    process_accounting_lock();
    group = process_accounting_group_get_locked(
        task->pid_namespace_id, tgid, 1);
    if (!group) {
        process_accounting_unlock();
        return;
    }
    process_accounting_group_collect(
        group, task, exit_code, terminating_signal);
    if (final_thread)
        group->virtual_memory_kb = memory.virtual_size_bytes / 1024u;
    if (!final_thread) {
        process_accounting_unlock();
        return;
    }
    target_slot = process_accounting_target_find_locked(
        task->pid_namespace_id);
    if (target_slot >= 0) {
        target = &g_process_accounting_targets[target_slot];
        process_accounting_build_record(
            &record, task, group, exit_code, terminating_signal);
        ++target->writers;
        target_pinned = 1;
    }
    memset(group, 0, sizeof(*group));
    process_accounting_unlock();
    if (target_pinned) {
        if (!(target->superblock->mount_flags & VFS_MOUNT_READONLY) &&
            vfs_append_write(
                target->path, target->superblock, &target->inode,
                &record, sizeof(record), &offset) == (int)sizeof(record)) {
            (void)vfs_sync_mutation_if_required(target->superblock, 0);
            vfs_path_cache_invalidate(target->path);
        }
        process_accounting_lock();
        if (target->writers) --target->writers;
        if (target->retiring && !target->writers) {
            retired = 1;
            retired_superblock = target->superblock;
            retired_inode = target->inode;
            memset(target, 0, sizeof(*target));
        }
        process_accounting_unlock();
        if (retired)
            vfs_inode_close(retired_superblock, &retired_inode);
    }
}

static void process_usage_accumulate(kernel_process_usage_t *total,
                                     const kernel_process_usage_t *part) {
    total->user_time_us = process_accounting_add_saturating(
        total->user_time_us, part->user_time_us);
    total->sys_time_us = process_accounting_add_saturating(
        total->sys_time_us, part->sys_time_us);
    if (part->maxrss_kb > total->maxrss_kb)
        total->maxrss_kb = part->maxrss_kb;
    total->minor_faults = process_accounting_add_saturating(
        total->minor_faults, part->minor_faults);
    total->major_faults = process_accounting_add_saturating(
        total->major_faults, part->major_faults);
    total->input_blocks = process_accounting_add_saturating(
        total->input_blocks, part->input_blocks);
    total->output_blocks = process_accounting_add_saturating(
        total->output_blocks, part->output_blocks);
    total->voluntary_ctxt_switches = process_accounting_add_saturating(
        total->voluntary_ctxt_switches, part->voluntary_ctxt_switches);
    total->involuntary_ctxt_switches = process_accounting_add_saturating(
        total->involuntary_ctxt_switches,
        part->involuntary_ctxt_switches);
}

int kernel_process_usage(int who, kernel_process_usage_t *usage) {
    kernel_task_identity_view_t current;
    kernel_proc_task_view_t view;
    int32_t tgid;
    int found = 0;

    if (!usage ||
        (who != EDGE_LINUX_RUSAGE_SELF &&
         who != EDGE_LINUX_RUSAGE_CHILDREN &&
         who != EDGE_LINUX_RUSAGE_THREAD))
        return -1;

    memset(usage, 0, sizeof(*usage));
    if (kernel_arch_current_identity_sample(&current) < 0) return -1;
    tgid = current.tgid > 0 ? current.tgid : current.tid;

    for (uint32_t slot = 0;; ++slot) {
        kernel_process_usage_t sampled;
        const kernel_process_usage_t *part;
        int status = kernel_arch_proc_task_sample(slot, &view);
        if (status < 0) break;
        if (status > 0) continue;

        if (who == EDGE_LINUX_RUSAGE_THREAD) {
            if (view.tid != current.tid) continue;
            part = &view.usage;
        } else if (who == EDGE_LINUX_RUSAGE_CHILDREN) {
            if (view.tid != tgid) continue;
            part = &view.children_usage;
        } else {
            int32_t view_tgid = view.tgid > 0 ? view.tgid : view.tid;
            if (view_tgid != tgid) continue;
            part = &view.usage;
        }

        sampled = *part;
        if (who != EDGE_LINUX_RUSAGE_CHILDREN &&
            view.memory_context_id) {
            uint64_t pages = arch_vm_address_space_resident_pages(
                view.memory_context_id);
            uint64_t bytes = pages > UINT64_MAX / KERNEL_MM_USER_PAGE_SIZE ?
                UINT64_MAX : pages * KERNEL_MM_USER_PAGE_SIZE;
            uint64_t peak = kernel_mm_resident_peak_observe(
                view.memory_context_id, bytes);
            uint64_t peak_kb = peak / 1024u;

            if (peak_kb > sampled.maxrss_kb)
                sampled.maxrss_kb = peak_kb;
        }
        part = &sampled;

        process_usage_accumulate(usage, part);
        found = 1;
        if (who != EDGE_LINUX_RUSAGE_SELF) break;
    }
    return found ? 0 : -1;
}

int kernel_process_times(kernel_process_times_t *times) {
    kernel_process_usage_t self;
    kernel_process_usage_t children;

    if (!times ||
        kernel_process_usage(EDGE_LINUX_RUSAGE_SELF, &self) < 0 ||
        kernel_process_usage(EDGE_LINUX_RUSAGE_CHILDREN, &children) < 0)
        return -1;
    times->user_ticks = self.user_time_us / 10000u;
    times->system_ticks = self.sys_time_us / 10000u;
    times->children_user_ticks = children.user_time_us / 10000u;
    times->children_system_ticks = children.sys_time_us / 10000u;
    times->elapsed_ticks = boottime_monotonic_us() / 10000u;
    return 0;
}
