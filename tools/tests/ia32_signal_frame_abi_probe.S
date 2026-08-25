/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 signal-frame and rt_sigreturn ABI probe. */

    .equ IA32_SYS_exit, 1
    .equ IA32_SYS_write, 4
    .equ IA32_SYS_getpid, 20
    .equ IA32_SYS_kill, 37
    .equ IA32_SYS_rt_sigreturn, 173
    .equ IA32_SYS_rt_sigaction, 174
    .equ SIGUSR1, 10
    .equ SA_SIGINFO, 4
    .equ SA_RESTORER, 0x04000000
    .equ RESTORED_EDI, 0x5a17c032

    .section .rodata
.Lpass_message:
    .ascii "IA32_SIGNAL_FRAME_ABI_PROBE_PASS\n"
.Lpass_message_end:
.Lfail_registration:
    .ascii "IA32_SIGNAL_FRAME_ABI_PROBE_FAIL registration\n"
.Lfail_registration_end:
.Lfail_kill:
    .ascii "IA32_SIGNAL_FRAME_ABI_PROBE_FAIL kill\n"
.Lfail_kill_end:
.Lfail_handler:
    .ascii "IA32_SIGNAL_FRAME_ABI_PROBE_FAIL handler\n"
.Lfail_handler_end:
.Lfail_layout:
    .ascii "IA32_SIGNAL_FRAME_ABI_PROBE_FAIL layout\n"
.Lfail_layout_end:
.Lfail_restore:
    .ascii "IA32_SIGNAL_FRAME_ABI_PROBE_FAIL restore\n"
.Lfail_restore_end:

    .section .data
    .balign 4
.Lsignal_action:
    .long .Lsignal_handler
    .long SA_SIGINFO | SA_RESTORER
    .long .Lsignal_restorer
    .long 0
    .long 0
.Lhandler_seen:
    .long 0
.Lhandler_layout_ok:
    .long 0
.Lhandler_failure_code:
    .long 1

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl $IA32_SYS_rt_sigaction, %eax
    movl $SIGUSR1, %ebx
    movl $.Lsignal_action, %ecx
    xorl %edx, %edx
    movl $8, %esi
    int $0x80
    testl %eax, %eax
    jne .Lregistration_failed

    movl $IA32_SYS_getpid, %eax
    int $0x80
    testl %eax, %eax
    jle .Lkill_failed
    movl %eax, %ebx
    movl $SIGUSR1, %ecx
    movl $0x1729c032, %edi
    movl $IA32_SYS_kill, %eax
    int $0x80
    testl %eax, %eax
    jne .Lkill_failed

    cmpl $1, .Lhandler_seen
    jne .Lhandler_failed
    cmpl $1, .Lhandler_layout_ok
    jne .Llayout_failed
    cmpl $RESTORED_EDI, %edi
    jne .Lrestore_failed

    movl $1, %ebx
    movl $.Lpass_message, %ecx
    movl $.Lpass_message_end - .Lpass_message, %edx
    movl $IA32_SYS_write, %eax
    int $0x80
    cmpl $.Lpass_message_end - .Lpass_message, %eax
    jne .Lrestore_failed
    xorl %ebx, %ebx
    movl $IA32_SYS_exit, %eax
    int $0x80

    .type .Lsignal_handler, @function
.Lsignal_handler:
    movl $1, .Lhandler_seen
    movl $1, .Lhandler_failure_code
    cmpl $SIGUSR1, %eax
    jne .Lhandler_return
    movl $2, .Lhandler_failure_code
    cmpl $SIGUSR1, 4(%esp)
    jne .Lhandler_return
    movl $3, .Lhandler_failure_code
    leal 16(%esp), %eax
    cmpl %eax, %edx
    jne .Lhandler_return
    movl $4, .Lhandler_failure_code
    leal 144(%esp), %eax
    cmpl %eax, %ecx
    jne .Lhandler_return
    movl $5, .Lhandler_failure_code
    cmpl $SIGUSR1, 0(%edx)
    jne .Lhandler_return
    movl $6, .Lhandler_failure_code
    movl 96(%ecx), %eax
    testl %eax, %eax
    jz .Lhandler_return
    movl $7, .Lhandler_failure_code
    addl $112, %eax
    testl $63, %eax
    jne .Lhandler_return
    movl $8, .Lhandler_failure_code
    movl $RESTORED_EDI, 36(%ecx)
    movl $1, .Lhandler_layout_ok
    movl $0, .Lhandler_failure_code
.Lhandler_return:
    ret

    .type .Lsignal_restorer, @function
.Lsignal_restorer:
    movl $IA32_SYS_rt_sigreturn, %eax
    int $0x80
    ud2

.Lregistration_failed:
    movl $.Lfail_registration, %ecx
    movl $.Lfail_registration_end - .Lfail_registration, %edx
    jmp .Lemit_failure
.Lkill_failed:
    movl $.Lfail_kill, %ecx
    movl $.Lfail_kill_end - .Lfail_kill, %edx
    jmp .Lemit_failure
.Lhandler_failed:
    movl $.Lfail_handler, %ecx
    movl $.Lfail_handler_end - .Lfail_handler, %edx
    jmp .Lemit_failure
.Llayout_failed:
    movl $.Lfail_layout, %ecx
    movl $.Lfail_layout_end - .Lfail_layout, %edx
    movl .Lhandler_failure_code, %esi
    jmp .Lemit_layout_failure
.Lrestore_failed:
    movl $.Lfail_restore, %ecx
    movl $.Lfail_restore_end - .Lfail_restore, %edx
.Lemit_failure:
    movl $2, %ebx
    movl $IA32_SYS_write, %eax
    int $0x80
    movl $1, %ebx
    movl $IA32_SYS_exit, %eax
    int $0x80
.Lemit_layout_failure:
    movl $2, %ebx
    movl $IA32_SYS_write, %eax
    int $0x80
    movl %esi, %ebx
    movl $IA32_SYS_exit, %eax
    int $0x80

    .section .note.GNU-stack,"",@progbits
