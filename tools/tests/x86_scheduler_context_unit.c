/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS x86_64 scheduler continuation-cookie unit test.
 * Copyright (c) EdgeOS Contributors.
 */
#include "arch/x86_64/task.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    const uintptr_t first_task = UINT64_C(0x0000000012345000);
    const uintptr_t second_task = UINT64_C(0x0000000012346000);
    const uint64_t flags = UINT64_C(0x246);
    uint64_t first;
    uint64_t next_generation;
    uint64_t next_task;

    first = edgeos_x86_64_resume_cookie(7, first_task, flags);
    next_generation =
        edgeos_x86_64_resume_cookie(8, first_task, flags);
    next_task =
        edgeos_x86_64_resume_cookie(7, second_task, flags);

    assert((first & EDGEOS_X86_64_RESUME_FLAGS_MASK) == flags);
    assert(first != flags);
    assert(first != next_generation);
    assert(first != next_task);
    assert(next_generation != next_task);

    puts("x86_scheduler_context_unit: PASS");
    return 0;
}
