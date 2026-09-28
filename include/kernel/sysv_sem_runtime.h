/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent SysV semaphore interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SYSV_SEM_RUNTIME_H
#define EDGEOS_KERNEL_SYSV_SEM_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_SYSV_SEM_UNDO 0x1000u

#define KERNEL_SYSV_SEM_GETPID 11u
#define KERNEL_SYSV_SEM_GETVAL 12u
#define KERNEL_SYSV_SEM_GETALL 13u
#define KERNEL_SYSV_SEM_GETNCNT 14u
#define KERNEL_SYSV_SEM_GETZCNT 15u
#define KERNEL_SYSV_SEM_SETVAL 16u
#define KERNEL_SYSV_SEM_SETALL 17u
#define KERNEL_SYSV_SEM_STAT 18u
#define KERNEL_SYSV_SEM_INFO 19u
#define KERNEL_SYSV_SEM_STAT_ANY 20u
#define KERNEL_SYSV_SEM_MAX_SETS 128u
#define KERNEL_SYSV_SEM_MAX_PER_SET 64u
#define KERNEL_SYSV_SEM_MAX_OPS 500u
#define KERNEL_SYSV_SEM_VALUE_MAX 32767u

typedef struct kernel_sysv_sem_status {
    struct edge_linux_ipc_perm64 permission;
    int64_t operation_time;
    int64_t change_time;
    uint64_t semaphore_count;
} kernel_sysv_sem_status_t;

typedef struct kernel_sysv_sem_wait {
    uint16_t semaphore_number;
    uint8_t wait_for_zero;
    uint8_t valid;
} kernel_sysv_sem_wait_t;

int64_t kernel_sysv_sem_get(uint32_t ipc_namespace_id, int32_t key,
                            uint32_t semaphore_count, uint32_t flags);
int64_t kernel_sysv_sem_operate(uint32_t ipc_namespace_id, int32_t identifier,
                                const struct edge_linux_sembuf *operations,
                                uint32_t operation_count,
                                kernel_sysv_sem_wait_t *wait);
int64_t kernel_sysv_sem_control(uint32_t ipc_namespace_id, int32_t identifier,
                                uint32_t semaphore_number, uint32_t command,
                                int32_t value, uint16_t *values,
                                uint32_t value_count,
                                kernel_sysv_sem_status_t *status,
                                struct edge_linux_seminfo *information);
int kernel_sysv_sem_count(uint32_t ipc_namespace_id, int32_t identifier,
                          uint32_t requested_access, uint32_t *count);
void kernel_sysv_sem_waiter_change(uint32_t ipc_namespace_id,
                                   int32_t identifier,
                                   const kernel_sysv_sem_wait_t *wait,
                                   int delta);
void kernel_sysv_sem_task_exit(int32_t task_id);

#endif
