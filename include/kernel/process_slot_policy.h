/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_PROCESS_SLOT_POLICY_H
#define EDGEOS_KERNEL_PROCESS_SLOT_POLICY_H

#include <stdint.h>

int kernel_process_zombie_slot_reusable(uint32_t reap_claimed,
                                        int scheduler_reap_ready);
uint64_t kernel_process_zombie_reap_retry_deadline(uint64_t now_us);
int kernel_process_zombie_reap_retry_due(uint64_t now_us,
                                         uint64_t retry_after_us);

#endif
