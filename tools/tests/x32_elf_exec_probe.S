/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding x32 process-entry and initial-stack probe. */

.equ X32_SYSCALL_BIT, 0x40000000
.equ X32_SYS_write, X32_SYSCALL_BIT + 1
.equ X32_SYS_exit, X32_SYSCALL_BIT + 60

.section .rodata
pass_message:
    .ascii "X32_ELF_EXEC_PROBE_PASS\n"
.set pass_message_size, . - pass_message
fail_argc:
    .ascii "X32_ELF_EXEC_PROBE_FAIL argc\n"
.set fail_argc_size, . - fail_argc
fail_argv:
    .ascii "X32_ELF_EXEC_PROBE_FAIL argv\n"
.set fail_argv_size, . - fail_argv
fail_phent:
    .ascii "X32_ELF_EXEC_PROBE_FAIL phent\n"
.set fail_phent_size, . - fail_phent
fail_pagesz:
    .ascii "X32_ELF_EXEC_PROBE_FAIL pagesz\n"
.set fail_pagesz_size, . - fail_pagesz
fail_entry:
    .ascii "X32_ELF_EXEC_PROBE_FAIL entry\n"
.set fail_entry_size, . - fail_entry
fail_write:
    .ascii "X32_ELF_EXEC_PROBE_FAIL write\n"
.set fail_write_size, . - fail_write

.section .text
.global _start
.type _start, @function
_start:
    cmpl $1, 0(%rsp)
    jne .Lfail_argc
    movl 4(%rsp), %eax
    testl %eax, %eax
    jz .Lfail_argv
    cmpb $0, 0(%rax)
    je .Lfail_argv

    movl 0(%rsp), %ecx
    leaq 8(%rsp,%rcx,4), %r8
.Lskip_environment:
    movl 0(%r8), %eax
    addq $4, %r8
    testl %eax, %eax
    jne .Lskip_environment

    xorl %r9d, %r9d
    xorl %r10d, %r10d
    xorl %r11d, %r11d
.Lscan_auxv:
    movl 0(%r8), %eax
    movl 4(%r8), %edx
    addq $8, %r8
    testl %eax, %eax
    je .Lcheck_auxv
    cmpl $4, %eax
    je .Lsave_phent
    cmpl $6, %eax
    je .Lsave_pagesz
    cmpl $9, %eax
    je .Lsave_entry
    jmp .Lscan_auxv
.Lsave_phent:
    movl %edx, %r9d
    jmp .Lscan_auxv
.Lsave_pagesz:
    movl %edx, %r10d
    jmp .Lscan_auxv
.Lsave_entry:
    movl %edx, %r11d
    jmp .Lscan_auxv

.Lcheck_auxv:
    cmpl $32, %r9d
    jne .Lfail_phent
    cmpl $4096, %r10d
    jne .Lfail_pagesz
    testl %r11d, %r11d
    jz .Lfail_entry

    movl $1, %edi
    leal pass_message(%rip), %esi
    movl $pass_message_size, %edx
    movl $X32_SYS_write, %eax
    syscall
    cmpq $pass_message_size, %rax
    jne .Lfail_write
    xorl %edi, %edi
    movl $X32_SYS_exit, %eax
    syscall

.Lfail_argc:
    leal fail_argc(%rip), %esi
    movl $fail_argc_size, %edx
    jmp .Lemit_fail
.Lfail_argv:
    leal fail_argv(%rip), %esi
    movl $fail_argv_size, %edx
    jmp .Lemit_fail
.Lfail_phent:
    leal fail_phent(%rip), %esi
    movl $fail_phent_size, %edx
    jmp .Lemit_fail
.Lfail_pagesz:
    leal fail_pagesz(%rip), %esi
    movl $fail_pagesz_size, %edx
    jmp .Lemit_fail
.Lfail_entry:
    leal fail_entry(%rip), %esi
    movl $fail_entry_size, %edx
    jmp .Lemit_fail
.Lfail_write:
    leal fail_write(%rip), %esi
    movl $fail_write_size, %edx
.Lemit_fail:
    movl $2, %edi
    movl $X32_SYS_write, %eax
    syscall
    movl $1, %edi
    movl $X32_SYS_exit, %eax
    syscall
.size _start, . - _start

.section .note.GNU-stack,"",@progbits
