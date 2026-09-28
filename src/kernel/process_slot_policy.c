/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include "kernel/process_slot_policy.h"

int kernel_process_zombie_slot_reusable(uint32_t reap_claimed,
                                        int scheduler_reap_ready) {
    return reap_claimed == 0u && scheduler_reap_ready != 0;
}

uint64_t kernel_process_zombie_reap_retry_deadline(uint64_t now_us) {
    const uint64_t retry_us = 1000u;

    return now_us > UINT64_MAX - retry_us ? UINT64_MAX : now_us + retry_us;
}

int kernel_process_zombie_reap_retry_due(uint64_t now_us,
                                         uint64_t retry_after_us) {
    return retry_after_us == 0u || now_us >= retry_after_us;
}
