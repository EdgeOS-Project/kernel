/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux signal policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SIGNAL_POLICY_H
#define EDGEOS_KERNEL_SIGNAL_POLICY_H

#include <stdint.h>

#include "kernel/linux_abi.h"

typedef struct edge_linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
} edge_linux_signal_action_t;

typedef enum edge_linux_signal_default_disposition {
    EDGE_LINUX_SIGNAL_DEFAULT_TERMINATE = 0,
    EDGE_LINUX_SIGNAL_DEFAULT_IGNORE = 1,
    EDGE_LINUX_SIGNAL_DEFAULT_CORE = 2,
    EDGE_LINUX_SIGNAL_DEFAULT_STOP = 3,
    EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE = 4,
} edge_linux_signal_default_disposition_t;

typedef enum edge_linux_signal_altstack_status {
    EDGE_LINUX_SIGNAL_ALTSTACK_VALID = 0,
    EDGE_LINUX_SIGNAL_ALTSTACK_INVALID = 1,
    EDGE_LINUX_SIGNAL_ALTSTACK_TOO_SMALL = 2,
} edge_linux_signal_altstack_status_t;

int edge_linux_signal_valid(uint32_t signal);
int edge_linux_signal_catchable(uint32_t signal);
uint64_t edge_linux_signal_mask_bit(uint32_t signal);
uint64_t edge_linux_signal_sanitize_mask(uint64_t mask);
uint32_t edge_linux_signal_altstack_report_flags(uint32_t stored_flags,
                                                 int on_stack);
edge_linux_signal_altstack_status_t edge_linux_signal_altstack_normalize(
    const struct edge_linux_stack64 *requested, uint64_t minimum_size,
    struct edge_linux_stack64 *normalized);
int edge_linux_signal_frame_restore(
    void *user_registers, uint64_t signal_mask,
    const struct edge_linux_stack64 *signal_stack);
edge_linux_signal_default_disposition_t
edge_linux_signal_default_disposition(uint32_t signal);

_Static_assert(sizeof(edge_linux_signal_action_t) == 32,
               "Linux rt_sigaction ABI layout");
_Static_assert(__builtin_offsetof(edge_linux_signal_action_t, flags) == 8,
               "Linux rt_sigaction flags offset");
_Static_assert(__builtin_offsetof(edge_linux_signal_action_t, restorer) == 16,
               "Linux rt_sigaction restorer offset");
_Static_assert(__builtin_offsetof(edge_linux_signal_action_t, mask) == 24,
               "Linux rt_sigaction mask offset");

#endif
