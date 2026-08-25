/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 clone, CLONE_SETTLS and clear-tid probe. */

    .equ SYS_exit, 1
    .equ SYS_write, 4
    .equ SYS_clone, 120
    .equ SYS_sched_yield, 158
    .equ SYS_set_thread_area, 243
    .equ CLONE_VM, 0x00000100
    .equ CLONE_FS, 0x00000200
    .equ CLONE_FILES, 0x00000400
    .equ CLONE_SIGHAND, 0x00000800
    .equ CLONE_THREAD, 0x00010000
    .equ CLONE_SYSVSEM, 0x00040000
    .equ CLONE_SETTLS, 0x00080000
    .equ CLONE_PARENT_SETTID, 0x00100000
    .equ CLONE_CHILD_CLEARTID, 0x00200000
    .equ CLONE_CHILD_SETTID, 0x01000000
    .equ CLONE_FLAGS, (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID)
    .equ TLS_FLAGS, 0x51
    .equ PARENT_VALUE, 0x13579bdf
    .equ CHILD_VALUE, 0x2468ace0

    .section .rodata
.Lpass:
    .ascii "IA32_CLONE_TLS_ABI_PROBE_PASS\n"
.Lpass_end:
.Lfail:
    .ascii "IA32_CLONE_TLS_ABI_PROBE_FAIL\n"
.Lfail_end:

    .section .data
    .balign 4
.Lparent_tls:
    .long PARENT_VALUE
.Lchild_tls:
    .long CHILD_VALUE
.Lparent_description:
    .long 12
    .long .Lparent_tls
    .long 0x000fffff
    .long TLS_FLAGS
.Lchild_description:
    .long 12
    .long .Lchild_tls
    .long 0x000fffff
    .long TLS_FLAGS
.Lparent_tid:
    .long -1
.Lchild_tid:
    .long -1
.Lchild_result:
    .long 0

    .section .bss
    .balign 16
.Lchild_stack:
    .skip 16384
.Lchild_stack_end:

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl $SYS_set_thread_area, %eax
    movl $.Lparent_description, %ebx
    int $0x80
    testl %eax, %eax
    jne .Lfailed
    movw $0x63, %ax
    movw %ax, %gs
    cmpl $PARENT_VALUE, %gs:0
    jne .Lfailed

    movl $SYS_clone, %eax
    movl $CLONE_FLAGS, %ebx
    movl $.Lchild_stack_end, %ecx
    movl $.Lparent_tid, %edx
    movl $.Lchild_description, %esi
    movl $.Lchild_tid, %edi
    int $0x80
    testl %eax, %eax
    js .Lfailed
    jz .Lchild

    cmpl %eax, .Lparent_tid
    jne .Lfailed
    movl $1000000, %ecx
.Lwait_child:
    cmpl $1, .Lchild_result
    jne .Lyield
    cmpl $0, .Lchild_tid
    je .Lchild_complete
.Lyield:
    pushl %ecx
    movl $SYS_sched_yield, %eax
    int $0x80
    popl %ecx
    loop .Lwait_child
    jmp .Lfailed
.Lchild_complete:
    cmpl $PARENT_VALUE, %gs:0
    jne .Lfailed
    movl $1, %ebx
    movl $.Lpass, %ecx
    movl $.Lpass_end - .Lpass, %edx
    movl $SYS_write, %eax
    int $0x80
    xorl %ebx, %ebx
    movl $SYS_exit, %eax
    int $0x80

.Lchild:
    cmpl $CHILD_VALUE, %gs:0
    jne .Lchild_failed
    movl $1, .Lchild_result
    xorl %ebx, %ebx
    movl $SYS_exit, %eax
    int $0x80
.Lchild_failed:
    movl $-1, .Lchild_result
    movl $1, %ebx
    movl $SYS_exit, %eax
    int $0x80

.Lfailed:
    movl $2, %ebx
    movl $.Lfail, %ecx
    movl $.Lfail_end - .Lfail, %edx
    movl $SYS_write, %eax
    int $0x80
    movl $1, %ebx
    movl $SYS_exit, %eax
    int $0x80

    .section .note.GNU-stack,"",@progbits
