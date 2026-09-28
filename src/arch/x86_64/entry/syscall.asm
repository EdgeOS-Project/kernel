; SPDX-License-Identifier: MPL-2.0
;
; Native Linux x86-64 SYSCALL entry.  SYSCALL does not switch RSP, so SWAPGS
; exposes the per-CPU kernel stack before any user-controlled stack is used.

section .text
bits 64

%define USER_CS             0x1b
%define USER_DS             0x23
%define SYSCALL_VECTOR      256
%define ENTRY_KERNEL_RSP    0
%define ENTRY_USER_RSP      8

extern edgeos_x86_64_syscall_dispatch
extern isr_return_from_frame

global edgeos_x86_64_syscall_entry
edgeos_x86_64_syscall_entry:
    swapgs
    mov [gs:ENTRY_USER_RSP], rsp
    mov rsp, [gs:ENTRY_KERNEL_RSP]

    ; Build edgeos_x86_64_trap_frame_t in the same order as exception.asm.
    push qword USER_DS
    push qword [gs:ENTRY_USER_RSP]
    push r11
    push qword USER_CS
    push rcx
    push qword 0
    push qword SYSCALL_VECTOR

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rsi
    push rdi
    push rbp
    push rdx
    push rcx
    push rbx
    push rax

    cld
    ; Linux enables maskable interrupts after the complete user register frame
    ; is on the per-task kernel stack.  Keeping IF clear for the whole syscall
    ; prevents remote TLB invalidations and device completions from running
    ; until a long mmap/read/ioctl returns, which serializes desktop threads.
    ; IRQ-side scheduling remains restricted to frames interrupted in ring 3,
    ; so an interrupt nested here cannot switch away from this syscall stack.
    sti
    mov rdi, rsp
    call edgeos_x86_64_syscall_dispatch
    cli
    jmp isr_return_from_frame

section .note.GNU-stack noalloc noexec nowrite progbits
