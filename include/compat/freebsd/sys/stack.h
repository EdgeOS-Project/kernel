/* SPDX-License-Identifier: BSD-2-Clause */
/* Compact kernel stack interface used by FreeBSD LinuxKPI diagnostics. */

#ifndef _SYS_STACK_H_
#define _SYS_STACK_H_

#include <vm/vm.h>

#define STACK_MAX 18

struct stack {
    int depth;
    vm_offset_t pcs[STACK_MAX];
};

void stack_save(struct stack *stack);
void stack_print(const struct stack *stack);

#endif
