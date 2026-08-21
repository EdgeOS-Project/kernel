/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux syscall interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_SYSCALL_H
#define EDGEOS_KERNEL_LINUX_SYSCALL_H

#include <stdint.h>

#include "generated/linux_syscall_ids.h"
#include "kernel/event_runtime.h"
#include "kernel/file_metadata.h"
#include "kernel/linux_abi.h"

typedef enum edge_linux_syscall_architecture {
    EDGE_LINUX_ARCH_X86_64 = 1,
    EDGE_LINUX_ARCH_AARCH64 = 2,
} edge_linux_syscall_architecture_t;

typedef enum edge_linux_syscall_route_status {
    EDGE_LINUX_SYSCALL_IMPLEMENTED = 1,
    EDGE_LINUX_SYSCALL_ENOSYS = 2,
} edge_linux_syscall_route_status_t;

typedef struct edge_linux_syscall_number {
    uint32_t number;
    edge_linux_syscall_id_t id;
    edge_linux_syscall_route_status_t status;
} edge_linux_syscall_number_t;

typedef struct edge_linux_syscall_arch_ops {
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
    uint64_t user_address_minimum;
    uint64_t user_address_limit;
    /* Optional rejection for architecture mappings aliased into user range. */
    int (*validate_user_range_arch)(void *context, uint64_t address,
                                    uint64_t size, int write);
    int (*copy_stat_to_user)(
        void *context, edge_linux_copy_to_user_fn copy_to_user,
        uint64_t user_destination,
        const kernel_file_metadata_t *metadata);
    int (*copy_epoll_event_from_user)(void *context,
                                      uint64_t user_source,
                                      kernel_epoll_event_t *event);
    uint32_t fcntl_setfl_mask;
    uint32_t open_direct_flag;
    const char *machine;
    const char *release;
    const char *version;
} edge_linux_syscall_arch_ops_t;

typedef struct edge_linux_syscall_context {
    edge_linux_syscall_id_t id;
    edge_linux_syscall_architecture_t architecture;
    edge_linux_syscall_route_status_t route_status;
    uint64_t raw_number;
    uint64_t arguments[6];
    void *current_task;
    void *user_registers;
    const edge_linux_syscall_arch_ops_t *arch_ops;
    int64_t result;
} edge_linux_syscall_context_t;

struct kernel_linux_identity;

enum {
    EDGE_LINUX_SYSCALL_NOT_HANDLED = 0,
    EDGE_LINUX_SYSCALL_HANDLED = 1,
};

int edge_linux_syscall_map(edge_linux_syscall_architecture_t architecture,
                           uint64_t raw_number,
                           edge_linux_syscall_id_t *id,
                           edge_linux_syscall_route_status_t *status);

int edge_linux_current_magic_fd_metadata(
    const char *path, const struct kernel_linux_identity *identity,
    kernel_file_metadata_t *metadata, int *handled);

int edge_linux_syscall_dispatch(edge_linux_syscall_context_t *context);

#endif
