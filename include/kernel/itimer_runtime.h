/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS process interval-timer runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_ITIMER_RUNTIME_H
#define EDGEOS_KERNEL_ITIMER_RUNTIME_H

#include <stdint.h>
#include "kernel/linux_time.h"

typedef struct kernel_itimer_backend_ops {
    int (*current_thread_group)(void *context, int32_t *tgid);
    int (*send_signal)(void *context, int32_t tgid, uint32_t signal);
} kernel_itimer_backend_ops_t;

int kernel_itimer_backend_register(
    const kernel_itimer_backend_ops_t *ops, void *context);
int kernel_itimer_real_get(linux_itimerval64_t *value);
int kernel_itimer_real_exchange(const linux_itimerval64_t *replacement,
                                linux_itimerval64_t *previous);
void kernel_itimer_real_poll(void);
void kernel_itimer_real_delete_process(int32_t process_id);

#endif
