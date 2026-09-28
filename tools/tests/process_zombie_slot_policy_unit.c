/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <stdint.h>

#include "kernel/process_slot_policy.h"

extern int printf(const char *format, ...);

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            printf("process_zombie_slot_policy_unit: %s:%d: %s\n",         \
                   __func__, __LINE__, #condition);                          \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static int test_reuse_requires_retired_unclaimed_task(void) {
    CHECK(kernel_process_zombie_slot_reusable(0u, 1) == 1);
    CHECK(kernel_process_zombie_slot_reusable(1u, 1) == 0);
    CHECK(kernel_process_zombie_slot_reusable(0u, 0) == 0);
    CHECK(kernel_process_zombie_slot_reusable(1u, 0) == 0);
    return 0;
}

static int test_reap_retry_is_rate_limited(void) {
    uint64_t deadline = kernel_process_zombie_reap_retry_deadline(5000u);

    CHECK(deadline == 6000u);
    CHECK(kernel_process_zombie_reap_retry_due(5000u, 0u) == 1);
    CHECK(kernel_process_zombie_reap_retry_due(5999u, deadline) == 0);
    CHECK(kernel_process_zombie_reap_retry_due(6000u, deadline) == 1);
    CHECK(kernel_process_zombie_reap_retry_deadline(UINT64_MAX - 5u) ==
          UINT64_MAX);
    return 0;
}

int main(void) {
    int failures = test_reuse_requires_retired_unclaimed_task();

    failures += test_reap_retry_is_rate_limited();

    if (failures) {
        printf("process_zombie_slot_policy_unit: FAIL (%d)\n", failures);
        return 1;
    }
    printf("process_zombie_slot_policy_unit: PASS\n");
    return 0;
}
