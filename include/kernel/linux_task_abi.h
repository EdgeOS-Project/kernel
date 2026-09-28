/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_LINUX_TASK_ABI_H
#define EDGEOS_KERNEL_LINUX_TASK_ABI_H

#include <stdint.h>

typedef enum edge_linux_task_abi {
    EDGE_LINUX_TASK_ABI_NATIVE64 = 0,
    EDGE_LINUX_TASK_ABI_X32 = 1,
    EDGE_LINUX_TASK_ABI_IA32 = 2,
} edge_linux_task_abi_t;

static inline uint8_t edge_linux_task_abi_word_size(
    edge_linux_task_abi_t abi) {
    return abi == EDGE_LINUX_TASK_ABI_NATIVE64 ? 8u : 4u;
}

#endif
