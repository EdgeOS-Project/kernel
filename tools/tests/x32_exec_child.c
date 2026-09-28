/* SPDX-License-Identifier: MPL-2.0 */
/* Native child image for the Linux x32 exec compatibility probe. */

#include <stdint.h>

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_exit 60

static const char marker[] = "X32_EXEC_CHILD_PASS\n";

static long call(long number, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a0),
                     "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

START_ATTRIBUTES void _start(void) {
    call(SYS_write, 1, (long)marker, sizeof(marker) - 1u, 0, 0, 0);
    call(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
