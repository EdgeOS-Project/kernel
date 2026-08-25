/* SPDX-License-Identifier: MPL-2.0 */
/* Final exec target for the freestanding Linux i386 runtime UAPI probe. */

    .equ SYS_exit, 1
    .equ SYS_write, 4

    .section .rodata
.Lpass:
    .ascii "IA32_RUNTIME_UAPI_PROBE_PASS\n"
.Lpass_end:

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl $1, %ebx
    movl $.Lpass, %ecx
    movl $.Lpass_end - .Lpass, %edx
    movl $SYS_write, %eax
    int $0x80
    xorl %ebx, %ebx
    movl $SYS_exit, %eax
    int $0x80

    .section .note.GNU-stack,"",@progbits
