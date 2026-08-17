/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux process accounting policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "kernel/mm_runtime.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/boottime.h"

static uint64_t process_usage_saturating_add(uint64_t left, uint64_t right) {
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static void process_usage_accumulate(kernel_process_usage_t *total,
                                     const kernel_process_usage_t *part) {
    total->user_time_us = process_usage_saturating_add(
        total->user_time_us, part->user_time_us);
    total->sys_time_us = process_usage_saturating_add(
        total->sys_time_us, part->sys_time_us);
    if (part->maxrss_kb > total->maxrss_kb)
        total->maxrss_kb = part->maxrss_kb;
    total->minor_faults = process_usage_saturating_add(
        total->minor_faults, part->minor_faults);
    total->major_faults = process_usage_saturating_add(
        total->major_faults, part->major_faults);
    total->input_blocks = process_usage_saturating_add(
        total->input_blocks, part->input_blocks);
    total->output_blocks = process_usage_saturating_add(
        total->output_blocks, part->output_blocks);
    total->voluntary_ctxt_switches = process_usage_saturating_add(
        total->voluntary_ctxt_switches, part->voluntary_ctxt_switches);
    total->involuntary_ctxt_switches = process_usage_saturating_add(
        total->involuntary_ctxt_switches, part->involuntary_ctxt_switches);
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
