/* SPDX-License-Identifier: MPL-2.0 */
/* Non-local execution context used by imported x86 firmware emulation. */

#ifndef _MACHINE_SETJMP_H_
#define _MACHINE_SETJMP_H_

/*
 * GCC reserves five pointer slots for its freestanding non-local context.
 * The builtins emit the required register and return-state handling directly,
 * so the bridge does not depend on a userspace C library.
 */
typedef void *jmp_buf[5];

#define setjmp(environment) \
    __builtin_setjmp((void **)(environment))
#define longjmp(environment, value) do { \
    (void)(value); \
    __builtin_longjmp((void **)(environment), 1); \
} while (0)

#endif
