/* SPDX-License-Identifier: MPL-2.0 */
/* x86-64 assembly entry helpers for unmodified FreeBSD drivers. */

#ifndef _MACHINE_ASMACROS_H_
#define _MACHINE_ASMACROS_H_

#define SUPERALIGN_TEXT .p2align 4,0x90

#ifdef LOCORE

/*
 * The imported Hyper-V vector enters through an EdgeOS interrupt gate while
 * retaining the FreeBSD trap-frame layout expected by the driver.  The PTI
 * entry is an alias because EdgeOS currently uses one kernel page table.
 */
    .macro INTR_HANDLER vec_name
    .text
    SUPERALIGN_TEXT
    .globl X\vec_name\()_pti
    .type X\vec_name\()_pti,@function
X\vec_name\()_pti:
    jmp X\vec_name

    SUPERALIGN_TEXT
    .globl X\vec_name
    .type X\vec_name,@function
X\vec_name:
    testb $3, 8(%rsp)
    jz .Ledgeos_bsd_gs_ready
    swapgs
.Ledgeos_bsd_gs_ready:
    lfence
    cld
    subq $TF_RIP, %rsp
    movq %rdi, TF_RDI(%rsp)
    movq %rsi, TF_RSI(%rsp)
    movq %rdx, TF_RDX(%rsp)
    movq %rcx, TF_RCX(%rsp)
    movq %r8, TF_R8(%rsp)
    movq %r9, TF_R9(%rsp)
    movq %rax, TF_RAX(%rsp)
    movq %rbx, TF_RBX(%rsp)
    movq %rbp, TF_RBP(%rsp)
    movq %r10, TF_R10(%rsp)
    movq %r11, TF_R11(%rsp)
    movq %r12, TF_R12(%rsp)
    movq %r13, TF_R13(%rsp)
    movq %r14, TF_R14(%rsp)
    movq %r15, TF_R15(%rsp)
    movq $0, TF_TRAPNO(%rsp)
    movq $0, TF_ADDR(%rsp)
    movq $0, TF_FLAGS(%rsp)
    movq $0, TF_ERR(%rsp)
    jmp .Ledgeos_bsd_interrupt_body

.Ledgeos_bsd_doreti:
    cli
    movq TF_RDI(%rsp), %rdi
    movq TF_RSI(%rsp), %rsi
    movq TF_RDX(%rsp), %rdx
    movq TF_RCX(%rsp), %rcx
    movq TF_R8(%rsp), %r8
    movq TF_R9(%rsp), %r9
    movq TF_RAX(%rsp), %rax
    movq TF_RBX(%rsp), %rbx
    movq TF_RBP(%rsp), %rbp
    movq TF_R10(%rsp), %r10
    movq TF_R11(%rsp), %r11
    movq TF_R12(%rsp), %r12
    movq TF_R13(%rsp), %r13
    movq TF_R14(%rsp), %r14
    movq TF_R15(%rsp), %r15
    addq $TF_RIP, %rsp
    testb $3, 8(%rsp)
    jz .Ledgeos_bsd_iret
    swapgs
.Ledgeos_bsd_iret:
    iretq

.Ledgeos_bsd_interrupt_body:
    .endm

#define doreti .Ledgeos_bsd_doreti

#endif

#endif
