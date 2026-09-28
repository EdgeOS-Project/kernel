/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 process-entry and int 0x80 ABI probe. */

    .section .text
    .code32
    .global _start
    .type _start, @function
_start:
    movl %esp, %ebp
    testl $15, %esp
    jne .Lfail

    movl 0(%ebp), %eax
    cmpl $1, %eax
    jb .Lfail
    movl 4(%ebp), %ecx
    testl %ecx, %ecx
    jz .Lfail

    leal 8(%ebp,%eax,4), %esi
    cmpl $0, -4(%esi)
    jne .Lfail
.Lskip_env:
    movl (%esi), %eax
    addl $4, %esi
    testl %eax, %eax
    jne .Lskip_env

    xorl %edi, %edi
    xorl %ebx, %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
.Lscan_auxv:
    movl (%esi), %eax
    testl %eax, %eax
    jz .Lcheck_auxv
    cmpl $4, %eax
    jne .Lnot_phent
    cmpl $32, 4(%esi)
    jne .Lfail
    movl $1, %edi
.Lnot_phent:
    cmpl $6, %eax
    jne .Lnot_pagesz
    cmpl $4096, 4(%esi)
    jne .Lfail
    movl $1, %ebx
.Lnot_pagesz:
    cmpl $9, %eax
    jne .Lnot_entry
    cmpl $0, 4(%esi)
    je .Lfail
    movl $1, %ecx
.Lnot_entry:
    cmpl $15, %eax
    jne .Lnext_auxv
    movl 4(%esi), %eax
    testl %eax, %eax
    jz .Lfail
    cmpl $0x36383669, (%eax)
    jne .Lfail
    cmpb $0, 4(%eax)
    jne .Lfail
    movl $1, %edx
.Lnext_auxv:
    addl $8, %esi
    jmp .Lscan_auxv

.Lcheck_auxv:
    testl %edi, %edi
    jz .Lfail
    testl %ebx, %ebx
    jz .Lfail
    testl %ecx, %ecx
    jz .Lfail
    testl %edx, %edx
    jz .Lfail

    movl $4, %eax
    movl $1, %ebx
    movl $.Lpass_message, %ecx
    movl $.Lpass_message_end - .Lpass_message, %edx
    int $0x80
    cmpl $.Lpass_message_end - .Lpass_message, %eax
    jne .Lfail
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80

.Lfail:
    movl $4, %eax
    movl $1, %ebx
    movl $.Lfail_message, %ecx
    movl $.Lfail_message_end - .Lfail_message, %edx
    int $0x80
    movl $1, %eax
    movl $1, %ebx
    int $0x80

    .section .rodata
.Lpass_message:
    .ascii "IA32_EXEC_ABI_PROBE_PASS\n"
.Lpass_message_end:
.Lfail_message:
    .ascii "IA32_EXEC_ABI_PROBE_FAIL\n"
.Lfail_message_end:

    .section .note.GNU-stack,"",@progbits
