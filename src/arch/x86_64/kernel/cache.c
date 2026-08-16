/* SPDX-License-Identifier: MPL-2.0 */
/* x86 cache-coherent device visibility hooks. */

#include <stdint.h>
#include "kernel/arch_cpu.h"

void arch_cpu_clean_data_range(const void *address, uint64_t length) {
    (void)address;
    (void)length;
    __asm__ __volatile__("mfence" ::: "memory");
}

void arch_cpu_invalidate_data_range(const void *address, uint64_t length) {
    (void)address;
    (void)length;
    __asm__ __volatile__("mfence" ::: "memory");
}
