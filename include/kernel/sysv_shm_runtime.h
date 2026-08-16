/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent SysV shared-memory interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SYSV_SHM_RUNTIME_H
#define EDGEOS_KERNEL_SYSV_SHM_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#include "kernel/linux_abi.h"

#define KERNEL_SYSV_IPC_PRIVATE 0
#define KERNEL_SYSV_IPC_CREAT 01000u
#define KERNEL_SYSV_IPC_EXCL 02000u
#define KERNEL_SYSV_IPC_RMID 0u
#define KERNEL_SYSV_IPC_SET 1u
#define KERNEL_SYSV_IPC_STAT 2u
#define KERNEL_SYSV_IPC_64 0x100u

#define KERNEL_SYSV_SHM_DEST 01000u
#define KERNEL_SYSV_SHM_RDONLY 010000u
#define KERNEL_SYSV_SHM_RND 020000u
#define KERNEL_SYSV_SHM_REMAP 040000u
#define KERNEL_SYSV_SHM_EXEC 0100000u
#define KERNEL_SYSV_SHM_NORESERVE 010000u
#define KERNEL_SYSV_SHMLBA 4096u

typedef uint64_t kernel_sysv_shm_page_t;

int64_t kernel_sysv_shm_get(int32_t key, uint64_t size, uint32_t flags);
int64_t kernel_sysv_shm_attach(int32_t identifier, uint64_t address,
                               uint32_t flags);
int kernel_sysv_shm_detach(uint64_t address);
int kernel_sysv_shm_control(int32_t identifier, uint32_t command,
                            struct edge_linux_shmid_ds64 *information);

int kernel_sysv_shm_address_space_clone(uintptr_t parent_address_space,
                                        uintptr_t child_address_space,
                                        int32_t child_pid);
void kernel_sysv_shm_address_space_release(uintptr_t address_space,
                                           int32_t last_pid);
uint64_t kernel_runtime_sysv_shmem_bytes(void);

/* Architecture VM hooks. They implement mechanism, never Linux IPC policy. */
uintptr_t kernel_sysv_shm_arch_current_address_space(void);
int kernel_sysv_shm_arch_page_allocate(kernel_sysv_shm_page_t *page);
void kernel_sysv_shm_arch_page_release(kernel_sysv_shm_page_t page);
int kernel_sysv_shm_arch_map(uintptr_t address_space,
                             uint64_t requested_address,
                             uint64_t length,
                             const kernel_sysv_shm_page_t *pages,
                             uint32_t page_count,
                             uint32_t flags,
                             uint64_t *mapped_address);
int kernel_sysv_shm_arch_unmap(uintptr_t address_space,
                               uint64_t address, uint64_t length);

#endif
