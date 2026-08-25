/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux x32 signal-frame and rt_sigreturn ABI probe. */

.equ X32_SYSCALL_BIT, 0x40000000
.equ X32_SYS_write, X32_SYSCALL_BIT + 1
.equ X32_SYS_rt_sigaction, X32_SYSCALL_BIT + 512
.equ X32_SYS_rt_sigreturn, X32_SYSCALL_BIT + 513
.equ X32_SYS_getpid, X32_SYSCALL_BIT + 39
.equ X32_SYS_kill, X32_SYSCALL_BIT + 62
.equ X32_SYS_exit, X32_SYSCALL_BIT + 60
.equ SIGUSR1, 10
.equ SA_SIGINFO, 4
.equ SA_RESTORER, 0x04000000
.equ RESTORED_R12, 0x5a17c032

.section .rodata
pass_message:
    .ascii "X32_SIGNAL_FRAME_ABI_PROBE_PASS\n"
.set pass_message_size, . - pass_message
fail_registration:
    .ascii "X32_SIGNAL_FRAME_ABI_PROBE_FAIL registration\n"
.set fail_registration_size, . - fail_registration
fail_kill:
    .ascii "X32_SIGNAL_FRAME_ABI_PROBE_FAIL kill\n"
.set fail_kill_size, . - fail_kill
fail_handler:
    .ascii "X32_SIGNAL_FRAME_ABI_PROBE_FAIL handler\n"
.set fail_handler_size, . - fail_handler
fail_layout:
    .ascii "X32_SIGNAL_FRAME_ABI_PROBE_FAIL layout\n"
.set fail_layout_size, . - fail_layout
fail_restore:
    .ascii "X32_SIGNAL_FRAME_ABI_PROBE_FAIL restore\n"
.set fail_restore_size, . - fail_restore

.section .data
.balign 8
signal_action:
    .long signal_handler
    .long SA_SIGINFO | SA_RESTORER
    .long signal_restorer
    .long 0
    .long 0
handler_seen:
    .long 0
handler_layout_ok:
    .long 0

.section .text
.global _start
.type _start, @function
_start:
    movl $X32_SYS_rt_sigaction, %eax
    movl $SIGUSR1, %edi
    leal signal_action(%rip), %esi
    xorl %edx, %edx
    movl $8, %r10d
    syscall
    testq %rax, %rax
    jne .Lfail_registration

    movl $X32_SYS_getpid, %eax
    syscall
    testq %rax, %rax
    jle .Lfail_kill
    movl %eax, %edi
    movl $SIGUSR1, %esi
    movl $0x1729c032, %r12d
    movl $X32_SYS_kill, %eax
    syscall
    testq %rax, %rax
    jne .Lfail_kill

    cmpl $1, handler_seen(%rip)
    jne .Lfail_handler
    cmpl $1, handler_layout_ok(%rip)
    jne .Lfail_layout
    cmpq $RESTORED_R12, %r12
    jne .Lfail_restore

    movl $1, %edi
    leal pass_message(%rip), %esi
    movl $pass_message_size, %edx
    movl $X32_SYS_write, %eax
    syscall
    cmpq $pass_message_size, %rax
    jne .Lfail_restore
    xorl %edi, %edi
    movl $X32_SYS_exit, %eax
    syscall

.type signal_handler, @function
signal_handler:
    movl $1, handler_seen(%rip)
    cmpl $SIGUSR1, %edi
    jne .Lhandler_return
    cmpl $SIGUSR1, 0(%rsi)
    jne .Lhandler_return
    movq %rsi, %rax
    subq %rdx, %rax
    cmpq $288, %rax
    jne .Lhandler_return
    movl 0(%rdx), %eax
    andl $~7, %eax
    jne .Lhandler_return
    movq 208(%rdx), %rax
    testq %rax, %rax
    jz .Lhandler_return
    movq %rax, %rcx
    shrq $32, %rcx
    jne .Lhandler_return
    testq $63, %rax
    jne .Lhandler_return
    movq $RESTORED_R12, 56(%rdx)
    movl $1, handler_layout_ok(%rip)
.Lhandler_return:
    ret
.size signal_handler, . - signal_handler

.type signal_restorer, @function
signal_restorer:
    movl $X32_SYS_rt_sigreturn, %eax
    syscall
    ud2
.size signal_restorer, . - signal_restorer

.Lfail_registration:
    leal fail_registration(%rip), %esi
    movl $fail_registration_size, %edx
    jmp .Lemit_failure
.Lfail_kill:
    leal fail_kill(%rip), %esi
    movl $fail_kill_size, %edx
    jmp .Lemit_failure
.Lfail_handler:
    leal fail_handler(%rip), %esi
    movl $fail_handler_size, %edx
    jmp .Lemit_failure
.Lfail_layout:
    leal fail_layout(%rip), %esi
    movl $fail_layout_size, %edx
    jmp .Lemit_failure
.Lfail_restore:
    leal fail_restore(%rip), %esi
    movl $fail_restore_size, %edx
.Lemit_failure:
    movl $2, %edi
    movl $X32_SYS_write, %eax
    syscall
    movl $1, %edi
    movl $X32_SYS_exit, %eax
    syscall
.size _start, . - _start

.section .note.GNU-stack,"",@progbits
