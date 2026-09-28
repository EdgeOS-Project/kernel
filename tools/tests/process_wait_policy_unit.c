/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Host-side tests for the architecture-independent process wait policy.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"

extern int printf(const char *format, ...);

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            printf("process_wait_policy_unit: %s:%d: %s\n",                \
                   __func__, __LINE__, #condition);                          \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static int test_current_process_group_zero(void) {
    kernel_process_wait_request_t request = {
        .selector = 0,
        .flags = KERNEL_PROCESS_WAIT_EXITED,
        .pid_namespace_id = 7,
    };
    kernel_process_wait_query_t query;

    CHECK(kernel_process_wait_query_build(&request, 0, &query) == 0);
    CHECK(query.id_type == KERNEL_PROCESS_WAIT_ID_PGID);
    CHECK(query.id == 0);
    CHECK(query.flags == KERNEL_PROCESS_WAIT_EXITED);
    CHECK(query.pid_namespace_id == 7);
    CHECK(kernel_process_wait_query_matches(&query, 41, 0) == 1);
    CHECK(kernel_process_wait_query_matches(&query, 42, 1) == 0);
    return 0;
}

static int test_invalid_current_process_group(void) {
    kernel_process_wait_request_t request = {
        .selector = 0,
        .flags = KERNEL_PROCESS_WAIT_EXITED,
        .pid_namespace_id = 1,
    };
    kernel_process_wait_query_t query;

    CHECK(kernel_process_wait_query_build(&request, -1, &query) ==
          -EDGE_LINUX_ECHILD);
    return 0;
}

int kernel_process_group_id(int32_t pid, int32_t *pgid_out) {
    (void)pid;
    if (!pgid_out) return -1;
    *pgid_out = 0;
    return 0;
}

int64_t arch_process_wait(const kernel_process_wait_query_t *query,
                          kernel_process_wait_result_t *result,
                          void *user_registers) {
    (void)query;
    (void)result;
    (void)user_registers;
    return 0;
}

int64_t arch_process_wait_for_tid(
        const kernel_process_wait_query_t *query,
        kernel_process_wait_result_t *result, int32_t waiter_tid) {
    (void)query;
    (void)result;
    (void)waiter_tid;
    return 0;
}

int main(void) {
    int failures = 0;

    failures += test_current_process_group_zero();
    failures += test_invalid_current_process_group();
    if (failures) {
        printf("process_wait_policy_unit: FAIL (%d)\n", failures);
        return 1;
    }
    printf("process_wait_policy_unit: PASS\n");
    return 0;
}
