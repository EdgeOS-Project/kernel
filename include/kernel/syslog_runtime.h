/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS kernel-log wait runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SYSLOG_RUNTIME_H
#define EDGEOS_KERNEL_SYSLOG_RUNTIME_H

#include <stdint.h>

/* Returns one when the caller should retry, or a negative Linux errno. */
int kernel_syslog_wait_for_data(uint64_t observed_next,
                                void *user_registers);
void kernel_syslog_notify_data(void);

int arch_syslog_wait_for_data(uint64_t observed_next,
                              void *user_registers);
void arch_syslog_notify_data(void);

#endif
