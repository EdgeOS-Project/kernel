/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent SysV message queue interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SYSV_MSG_RUNTIME_H
#define EDGEOS_KERNEL_SYSV_MSG_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "kernel/sysv_shm_runtime.h"

#define KERNEL_SYSV_MSG_NOERROR 010000u
#define KERNEL_SYSV_MSG_EXCEPT 020000u
#define KERNEL_SYSV_MSG_COPY 040000u

#define KERNEL_SYSV_MSG_STAT 11u
#define KERNEL_SYSV_MSG_INFO 12u
#define KERNEL_SYSV_MSG_STAT_ANY 13u

#define KERNEL_SYSV_MSG_MAX_QUEUES 128u
#define KERNEL_SYSV_MSG_MAX_MESSAGES 256u
#define KERNEL_SYSV_MSG_MAX_BYTES 8192u
#define KERNEL_SYSV_MSG_DEFAULT_QUEUE_BYTES 16384u

int64_t kernel_sysv_msg_get(uint32_t ipc_namespace_id, int32_t key,
                            uint32_t flags);
int64_t kernel_sysv_msg_send(uint32_t ipc_namespace_id, int32_t identifier,
                             int64_t type, const void *data, uint32_t length,
                             uint32_t flags);
int64_t kernel_sysv_msg_receive(uint32_t ipc_namespace_id,
                                int32_t identifier, int64_t requested_type,
                                void *data, uint32_t capacity,
                                uint32_t flags, int64_t *type);
int64_t kernel_sysv_msg_control(uint32_t ipc_namespace_id,
                                int32_t identifier, uint32_t command,
                                struct edge_linux_msqid_ds64 *status,
                                struct edge_linux_msginfo *information);

#endif
