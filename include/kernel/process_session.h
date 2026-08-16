/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux process-group and session policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_PROCESS_SESSION_H
#define EDGEOS_KERNEL_PROCESS_SESSION_H

#include <stdint.h>

typedef enum edge_linux_process_session_operation {
    EDGE_LINUX_PROCESS_SET_PGID = 1,
    EDGE_LINUX_PROCESS_CREATE_SESSION = 2,
} edge_linux_process_session_operation_t;

typedef struct edge_linux_process_session_request {
    edge_linux_process_session_operation_t operation;
    int32_t pid;
    int32_t pgid;
} edge_linux_process_session_request_t;

typedef struct edge_linux_process_session_member {
    int32_t pid;
    int32_t ppid;
    int32_t pgid;
    int32_t sid;
    uint8_t execed_since_fork;
} edge_linux_process_session_member_t;

typedef struct edge_linux_process_session_commit {
    int32_t caller_tid;
    edge_linux_process_session_member_t current;
    edge_linux_process_session_member_t target;
    int32_t new_pgid;
    int32_t new_sid;
    int32_t required_existing_pgid;
    uint8_t require_absent_process_group;
    uint8_t detach_controlling_terminal;
} edge_linux_process_session_commit_t;

int kernel_arch_process_session_commit(
    const edge_linux_process_session_commit_t *commit);
int kernel_process_group_id(int32_t pid, int32_t *pgid_out);
int kernel_process_session_id(int32_t pid, int32_t *sid_out);
int64_t kernel_process_session_change(
    const edge_linux_process_session_request_t *request);

#endif
