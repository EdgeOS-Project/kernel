/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-independent BSD process accounting runtime. */

#ifndef EDGEOS_KERNEL_PROCESS_ACCOUNTING_H
#define EDGEOS_KERNEL_PROCESS_ACCOUNTING_H

#include <stdint.h>

#include "kernel/process_runtime.h"
#include "vfs/vfs.h"

#define KERNEL_PROCESS_ACCOUNTING_VERSION 3u

typedef uint16_t kernel_process_accounting_comp_t;

typedef struct kernel_process_accounting_record_v3 {
    uint8_t flag;
    uint8_t version;
    uint16_t tty;
    uint32_t exit_code;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t ppid;
    uint32_t begin_time;
    uint32_t elapsed_time;
    kernel_process_accounting_comp_t user_time;
    kernel_process_accounting_comp_t system_time;
    kernel_process_accounting_comp_t memory;
    kernel_process_accounting_comp_t input_output;
    kernel_process_accounting_comp_t read_write;
    kernel_process_accounting_comp_t minor_faults;
    kernel_process_accounting_comp_t major_faults;
    kernel_process_accounting_comp_t swaps;
    char command[16];
} kernel_process_accounting_record_v3_t;

_Static_assert(sizeof(kernel_process_accounting_record_v3_t) == 64u,
               "Linux acct_v3 layout mismatch");

int kernel_process_accounting_enable(
    uint32_t pid_namespace_id, const char *path,
    vfs_superblock_t *superblock, const vfs_inode_t *inode);
int kernel_process_accounting_disable(uint32_t pid_namespace_id);
void kernel_process_accounting_task_exit(
    const kernel_proc_task_view_t *task, int32_t exit_code,
    uint32_t terminating_signal, int final_thread);

kernel_process_accounting_comp_t kernel_process_accounting_encode_comp(
    uint64_t value);
uint32_t kernel_process_accounting_encode_float(uint64_t value);

#endif
