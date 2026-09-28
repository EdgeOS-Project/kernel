/* SPDX-License-Identifier: MPL-2.0 */
/* Verify immutable per-address-space auxv, partial reads, and fork lifetime. */
#include <assert.h>
#include "stdio.h"
#include "../../src/kernel/mm_runtime.c"

static uint8_t user_memory[1024];
static uint8_t registry_memory[16384];

int arch_copy_from_user(uint64_t address_space, void *destination,
                        uint64_t source, uint64_t length) {
    if (!address_space || source < 0x1000u || length > sizeof(user_memory) ||
        source - 0x1000u > sizeof(user_memory) - length) return -1;
    memcpy(destination, user_memory + source - 0x1000u, (uint32_t)length);
    return 0;
}

void arch_vm_free_page(void *page) {
    assert(!page);
}

int main(void) {
    const uint64_t stack64[] = {1, 0x2000, 0, 0x3000, 0, 6, 4096, 17, 100, 0, 0};
    const uint32_t stack32[] = {1, 0x2000, 0, 0x3000, 0, 6, 4096, 17, 100, 0, 0};
    uint64_t result[6] = {0};
    uint32_t small[6] = {0};
    assert(kernel_mm_lock_space_pool_initialize(registry_memory, sizeof(registry_memory), 4u) == 0);
    memcpy(user_memory, stack64, sizeof(stack64));
    assert(kernel_mm_auxv_capture(1, 0x1000, 8) == 0);
    memset(user_memory, 0, sizeof(user_memory));
    assert(kernel_mm_auxv_read(1, result, sizeof(result)) == 48);
    assert(result[0] == 6 && result[1] == 4096 && result[2] == 17 && result[3] == 100);
    assert(result[4] == 0 && result[5] == 0);
    assert(kernel_mm_auxv_read(1, 0, 0) == 48);
    assert(kernel_mm_auxv_read(1, small, 3) == 48);
    assert(((uint8_t *)small)[0] == 6 && ((uint8_t *)small)[3] == 0);
    assert(kernel_mm_auxv_clone(1, 2) == 0);
    kernel_mm_lock_space_release(1);
    assert(kernel_mm_auxv_read(1, result, sizeof(result)) == 0);
    assert(kernel_mm_auxv_read(2, result, sizeof(result)) == 48);
    memcpy(user_memory, stack32, sizeof(stack32));
    assert(kernel_mm_auxv_capture(3, 0x1000, 4) == 0);
    assert(kernel_mm_auxv_read(3, small, sizeof(small)) == 24);
    assert(small[0] == 6 && small[1] == 4096 && small[4] == 0 && small[5] == 0);
    assert(kernel_mm_auxv_capture(3, 0x1000, 2) == -EDGE_LINUX_EINVAL);
    assert(kernel_mm_auxv_capture(3, 0xffff, 8) == -EDGE_LINUX_EFAULT);
    printf("auxv_runtime_unit: PASS\n");
    return 0;
}
