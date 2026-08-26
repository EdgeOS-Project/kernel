/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS cgroup v2 filesystem interface.
 * Copyright (c) EdgeOS Contributors.
 */
#ifndef EDGEOS_FS_CGROUPFS_H
#define EDGEOS_FS_CGROUPFS_H

#include <stdint.h>
#include "kernel/bpf_runtime.h"
#include "kernel/scheduler_policy.h"
#include "vfs/vfs.h"

int cgroupfs_mount(const char *dev, const char *target);
int cgroupfs_proc_cgroups_snapshot(char *buffer, uint32_t capacity);
int cgroupfs_proc_pid_snapshot(int32_t pid, char *buffer,
                               uint32_t capacity);
int cgroupfs_directory_valid(vfs_superblock_t *sb,
                             const vfs_inode_t *inode);
int cgroupfs_reference_get(vfs_superblock_t *sb,
                           const vfs_inode_t *inode,
                           uint64_t *reference);
int cgroupfs_reference_retain(uint64_t reference);
void cgroupfs_reference_put(uint64_t reference);
int cgroupfs_bpf_program_attach(vfs_superblock_t *sb,
                                const vfs_inode_t *inode,
                                int object_id, uint32_t flags,
                                int replace_object_id,
                                int relative_object_id,
                                uint64_t expected_revision);
int cgroupfs_bpf_program_detach(vfs_superblock_t *sb,
                                const vfs_inode_t *inode,
                                int object_id,
                                uint64_t expected_revision);
int cgroupfs_bpf_program_query(vfs_superblock_t *sb,
                               const vfs_inode_t *inode,
                               int effective, int *object_ids,
                               uint32_t *attach_flags,
                               uint32_t capacity, uint32_t *count,
                               uint64_t *revision);
int cgroupfs_bpf_link_create(vfs_superblock_t *sb,
                             const vfs_inode_t *inode,
                             int object_id, uint32_t attach_type,
                             uint32_t flags, int relative_object_id,
                             uint64_t expected_revision);
int cgroupfs_bpf_program_query_links(vfs_superblock_t *sb,
                                     const vfs_inode_t *inode,
                                     int effective, int *object_ids,
                                     uint32_t *attach_flags,
                                     int *link_object_ids,
                                     uint32_t capacity, uint32_t *count,
                                     uint64_t *revision);
int cgroupfs_bpf_device_allowed(
    uint32_t cgroup_id,
    const kernel_bpf_cgroup_device_context_t *context);
int cgroupfs_attach_process(vfs_superblock_t *sb,
                            const vfs_inode_t *inode, int32_t pid);
void cgroupfs_task_state_changed(uint32_t cgroup_id);
void cgroupfs_task_join(uint32_t cgroup_id);
void cgroupfs_task_leave(uint32_t cgroup_id);
int cgroupfs_task_frozen(uint32_t cgroup_id);
int cgroupfs_pids_validate_task(int32_t pid, int already_counted);
int cgroupfs_memory_charge(uint32_t cgroup_id, uint64_t bytes,
                           uint32_t *oom_cgroup_id);
int cgroupfs_memory_prepare_charge(uint32_t cgroup_id, uint64_t bytes,
                                   uint64_t *excess_bytes);
void cgroupfs_memory_uncharge(uint32_t cgroup_id, uint64_t bytes);
void cgroupfs_memory_note_fault(uint32_t cgroup_id, int major);
void cgroupfs_memory_note_reclaim(uint32_t cgroup_id,
                                  uint64_t scanned_pages,
                                  uint64_t reclaimed_pages);
void cgroupfs_memory_note_pressure(uint32_t cgroup_id, uint64_t now_us,
                                   uint64_t some_stall_us,
                                   uint64_t full_stall_us);
void cgroupfs_memory_note_oom_kill(uint32_t cgroup_id);
int cgroupfs_memory_oom_group_kill(uint32_t oom_cgroup_id,
                                   int32_t fault_tgid);
int cgroupfs_memory_pressure(uint32_t cgroup_id, uint64_t *excess_bytes);
void cgroupfs_memory_note_low_reclaim(uint32_t cgroup_id);
int cgroupfs_memory_swap_charge(uint32_t cgroup_id, uint64_t bytes);
void cgroupfs_memory_swap_uncharge(uint32_t cgroup_id, uint64_t bytes);
void cgroupfs_cpu_account_runtime(uint32_t cgroup_id, uint64_t runtime_us,
                                  uint64_t now_us);
void cgroupfs_cpu_account_runtime_mode(uint32_t cgroup_id,
                                       uint64_t runtime_us,
                                       uint64_t now_us, int system_time);
void cgroupfs_cpu_note_pressure(uint32_t cgroup_id, uint64_t now_us,
                                uint64_t some_stall_us,
                                uint64_t full_stall_us);
int cgroupfs_cpu_task_runnable(uint32_t cgroup_id, uint64_t now_us);
void cgroupfs_cpu_effective_scheduler_state(
    uint32_t cgroup_id, const edge_linux_scheduler_state_t *task_state,
    edge_linux_scheduler_state_t *effective_state);
int cgroupfs_cpu_group_order(uint32_t candidate_cgroup_id,
                            uint32_t current_cgroup_id);
uint64_t cgroupfs_cpuset_cpu_mask64(uint32_t cgroup_id);
void cgroupfs_io_begin(uint32_t major, uint32_t minor, int write,
                       uint64_t bytes);
void cgroupfs_io_complete(uint32_t major, uint32_t minor, int write,
                          uint64_t bytes);

#endif
