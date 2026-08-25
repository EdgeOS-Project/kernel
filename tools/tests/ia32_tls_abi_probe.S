/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 GDT TLS syscall and segment-access probe. */

    .equ IA32_SYS_exit, 1
    .equ IA32_SYS_write, 4
    .equ IA32_SYS_set_thread_area, 243
    .equ IA32_SYS_get_thread_area, 244
    .equ TLS_FLAGS, 0x51
    .equ EMPTY_FLAGS, 0x28
    .equ TLS_SENTINEL, 0x51a32eed
    .equ TLS_WRITTEN, 0x2437cafe

    .section .rodata
.Lpass:
    .ascii "IA32_TLS_ABI_PROBE_PASS\n"
.Lpass_end:
.Lfail_set:
    .ascii "IA32_TLS_ABI_PROBE_FAIL set_thread_area\n"
.Lfail_set_end:
.Lfail_entry:
    .ascii "IA32_TLS_ABI_PROBE_FAIL allocated_entry\n"
.Lfail_entry_end:
.Lfail_access:
    .ascii "IA32_TLS_ABI_PROBE_FAIL segment_access\n"
.Lfail_access_end:
.Lfail_get:
    .ascii "IA32_TLS_ABI_PROBE_FAIL get_thread_area\n"
.Lfail_get_end:
.Lfail_layout:
    .ascii "IA32_TLS_ABI_PROBE_FAIL descriptor_layout\n"
.Lfail_layout_end:
.Lfail_delete:
    .ascii "IA32_TLS_ABI_PROBE_FAIL descriptor_delete\n"
.Lfail_delete_end:

    .section .data
    .balign 4
.Ltls_data:
    .long TLS_SENTINEL
    .long 0
.Ldescription:
    .long -1
    .long .Ltls_data
    .long 0x000fffff
    .long TLS_FLAGS
.Lquery:
    .long 0
    .long 0
    .long 0
    .long 0
.Lempty:
    .long 0
    .long 0
    .long 0
    .long EMPTY_FLAGS

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl $IA32_SYS_set_thread_area, %eax
    movl $.Ldescription, %ebx
    int $0x80
    testl %eax, %eax
    jne .Lset_failed

    movl .Ldescription, %ecx
    cmpl $12, %ecx
    jb .Lentry_failed
    cmpl $14, %ecx
    ja .Lentry_failed
    movl %ecx, .Lquery
    movl %ecx, .Lempty
    shll $3, %ecx
    orl $3, %ecx
    movw %cx, %gs

    movl %gs:0, %eax
    cmpl $TLS_SENTINEL, %eax
    jne .Laccess_failed
    movl $TLS_WRITTEN, %gs:4
    cmpl $TLS_WRITTEN, .Ltls_data + 4
    jne .Laccess_failed

    movl $IA32_SYS_get_thread_area, %eax
    movl $.Lquery, %ebx
    int $0x80
    testl %eax, %eax
    jne .Lget_failed
    movl .Lquery + 4, %eax
    cmpl $.Ltls_data, %eax
    jne .Llayout_failed
    cmpl $0x000fffff, .Lquery + 8
    jne .Llayout_failed
    movl .Lquery + 12, %eax
    andl $0x7f, %eax
    cmpl $TLS_FLAGS, %eax
    jne .Llayout_failed

    xorl %eax, %eax
    movw %ax, %gs
    movl $IA32_SYS_set_thread_area, %eax
    movl $.Lempty, %ebx
    int $0x80
    testl %eax, %eax
    jne .Ldelete_failed
    movl $IA32_SYS_get_thread_area, %eax
    movl $.Lquery, %ebx
    movl .Lempty, %ecx
    movl %ecx, .Lquery
    int $0x80
    testl %eax, %eax
    jne .Ldelete_failed
    cmpl $0, .Lquery + 4
    jne .Ldelete_failed
    cmpl $0, .Lquery + 8
    jne .Ldelete_failed
    cmpl $0x28, .Lquery + 12
    jne .Ldelete_failed

    movl $1, %ebx
    movl $.Lpass, %ecx
    movl $.Lpass_end - .Lpass, %edx
    movl $IA32_SYS_write, %eax
    int $0x80
    xorl %ebx, %ebx
    movl $IA32_SYS_exit, %eax
    int $0x80

.Lset_failed:
    movl $.Lfail_set, %ecx
    movl $.Lfail_set_end - .Lfail_set, %edx
    jmp .Lfail
.Lentry_failed:
    movl $.Lfail_entry, %ecx
    movl $.Lfail_entry_end - .Lfail_entry, %edx
    jmp .Lfail
.Laccess_failed:
    movl $.Lfail_access, %ecx
    movl $.Lfail_access_end - .Lfail_access, %edx
    jmp .Lfail
.Lget_failed:
    movl $.Lfail_get, %ecx
    movl $.Lfail_get_end - .Lfail_get, %edx
    jmp .Lfail
.Llayout_failed:
    movl $.Lfail_layout, %ecx
    movl $.Lfail_layout_end - .Lfail_layout, %edx
    jmp .Lfail
.Ldelete_failed:
    movl $.Lfail_delete, %ecx
    movl $.Lfail_delete_end - .Lfail_delete, %edx
.Lfail:
    movl $2, %ebx
    movl $IA32_SYS_write, %eax
    int $0x80
    movl $1, %ebx
    movl $IA32_SYS_exit, %eax
    int $0x80

    .section .note.GNU-stack,"",@progbits
