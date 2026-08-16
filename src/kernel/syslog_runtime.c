/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent kernel-log wait policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/syslog_runtime.h"
#include "sys/bootlog.h"

int kernel_syslog_wait_for_data(uint64_t observed_next,
                                void *user_registers) {
    if (bootlog_next_offset() != observed_next) return 1;
    return arch_syslog_wait_for_data(observed_next, user_registers);
}

void kernel_syslog_notify_data(void) {
    arch_syslog_notify_data();
}
