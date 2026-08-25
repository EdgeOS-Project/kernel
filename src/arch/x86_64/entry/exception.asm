section .text
bits 64

%define KERNEL_DS 0x10
%define USER_DS 0x23
%define USER32_CS 0x4b
%define USER32_DS 0x53
%define FRAME_CS_OFFSET 144

extern isr_exception_handler
global isr_return_from_frame

%macro PUSH_GPRS 0
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
%endmacro

%macro POP_GPRS 0
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rbp
    pop rdi
    pop rsi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
%endmacro

exception_common:
    ; SWAPGS exactly once for entries from ring 3.  Kernel-origin exceptions
    ; already run with the per-CPU entry area in GS.
    test byte [rsp + 24], 3
    jz .kernel_gs_ready
    swapgs
.kernel_gs_ready:
    ; User mode is allowed to set DF with std.  Linux enters the kernel with
    ; DF cleared before running C code; EdgeOS string primitives and compiler
    ; generated copies rely on the same invariant.  The user's RFLAGS were
    ; already saved by the CPU on the interrupt frame, so this does not change
    ; the flags restored by iretq.
    cld
    PUSH_GPRS
    mov ax, KERNEL_DS
    mov ds, ax
    mov es, ax
    mov rdi, rsp
    call isr_exception_handler
isr_return_from_frame:
    ; No maskable interrupt may observe user GS while CPL is still zero.
    cli
    test byte [rsp + FRAME_CS_OFFSET], 3
    jz .kernel_segments_ready
    cmp word [rsp + FRAME_CS_OFFSET], USER32_CS
    jne .native_user_segments
    mov ax, USER32_DS
    mov ds, ax
    mov es, ax
    jmp .segments_ready
.native_user_segments:
    mov ax, USER_DS
    mov ds, ax
    mov es, ax
    jmp .segments_ready
.kernel_segments_ready:
    mov ax, KERNEL_DS
    mov ds, ax
    mov es, ax
.segments_ready:
    POP_GPRS
    add rsp, 16
    test byte [rsp + 8], 3
    jz .iret
    swapgs
.iret:
    iretq

%macro EXC_NOERR 1
    global exception_%1
exception_%1:
    push qword 0
    push qword %1
    jmp exception_common
%endmacro

%macro EXC_ERR 1
    global exception_%1
exception_%1:
    push qword %1
    jmp exception_common
%endmacro

EXC_NOERR 0
EXC_NOERR 1
EXC_NOERR 2
EXC_NOERR 3
EXC_NOERR 4
EXC_NOERR 5
EXC_NOERR 6
EXC_NOERR 7
EXC_ERR   8
EXC_NOERR 9
EXC_ERR   10
EXC_ERR   11
EXC_ERR   12
EXC_ERR   13
EXC_ERR   14
EXC_NOERR 15
EXC_NOERR 16
EXC_ERR   17
EXC_NOERR 18
EXC_NOERR 19
EXC_NOERR 20
EXC_NOERR 21
EXC_NOERR 22
EXC_NOERR 23
EXC_NOERR 24
EXC_NOERR 25
EXC_NOERR 26
EXC_NOERR 27
EXC_NOERR 28
EXC_NOERR 29
EXC_ERR   30
EXC_NOERR 31

global exception_128
exception_128:
    push qword 0
    push qword 128
    jmp exception_common

section .note.GNU-stack noalloc noexec nowrite progbits
