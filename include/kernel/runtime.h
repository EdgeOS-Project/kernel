/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_RUNTIME_H
#define EDGEOS_KERNEL_RUNTIME_H

#include <stdint.h>
#include "kernel/arch_user.h"

int kernel_process_runtime_init(const char *init_path, uint64_t address_space,
                                uint64_t entry, uint64_t stack);
__attribute__((noreturn)) void kernel_process_runtime_enter(void);
__attribute__((noreturn)) void kernel_fault_current(uint32_t signal);
int kernel_current_file_mapping_info(uint64_t address, uint64_t *start_out,
                                     uint64_t *end_out,
                                     uint64_t *file_offset_out,
                                     uint32_t *inode_out);
typedef enum kernel_memory_mapping_kind {
    KERNEL_MEMORY_MAPPING_NONE = 0,
    KERNEL_MEMORY_MAPPING_ANONYMOUS = 1,
    KERNEL_MEMORY_MAPPING_TMPFS = 2,
    KERNEL_MEMORY_MAPPING_FILE = 3,
} kernel_memory_mapping_kind_t;

typedef struct kernel_memory_mapping_info {
    uint64_t start;
    uint64_t end;
    uint32_t protection;
    uint8_t kind;
    uint8_t shared;
    uint8_t reserved[2];
} kernel_memory_mapping_info_t;

int kernel_current_memory_mapping_info(
    uint64_t address, kernel_memory_mapping_info_t *info);
uint32_t kernel_current_last_syscall(uint64_t arguments[6]);
int kernel_handle_page_fault(arch_user_frame_t *frame);
void kernel_save_current_fp(void);
void kernel_restore_current_fp(void);
const char *kernel_current_mapping_name(uint64_t address, uint64_t *offset_out);
void kernel_timer_tick(int poll_network, int user_mode);
int kernel_scheduler_cpu_is_idle(void);
int kernel_scheduler_reschedule_pending(void);
void kernel_debug_dump_tasks(void);
void kernel_preempt(arch_user_frame_t *frame);
void kernel_reschedule(arch_user_frame_t *frame);
void kernel_deliver_signal(arch_user_frame_t *frame);
void kernel_finish_deferred_group_exit(void);

#endif
