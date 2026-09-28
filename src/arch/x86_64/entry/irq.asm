section .text
bits 64

%define USER32_CS 0x4b
%define FRAME_CS_OFFSET 144

extern isr_irq_handler
extern process_x86_compat_capture_user_segments
extern process_x86_compat_user_segments

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

irq_common:
    test byte [rsp + 24], 3
    jz .kernel_gs_ready
    swapgs
.kernel_gs_ready:
    ; Keep the kernel's x86 ABI invariant even if an IRQ interrupted user code
    ; after std.  RFLAGS for the interrupted context are already on the CPU
    ; interrupt frame and will be restored by iretq.
    cld
    PUSH_GPRS
    cmp word [rsp + FRAME_CS_OFFSET], USER32_CS
    jne .segments_captured
    call process_x86_compat_capture_user_segments
.segments_captured:
    mov rdi, rsp
    call isr_irq_handler
    cli
    cmp word [rsp + FRAME_CS_OFFSET], USER32_CS
    jne .compat_segments_ready
    call process_x86_compat_user_segments
    mov [rsp + 120], rax
.compat_segments_ready:
    POP_GPRS
    test byte [rsp + 24], 3
    jz .kernel_return
    cmp word [rsp + 24], USER32_CS
    jne .native_user_return
    swapgs
    push rax
    mov eax, [rsp + 8]
    mov fs, ax
    shr eax, 16
    mov gs, ax
    pop rax
    add rsp, 16
    jmp .iret
.native_user_return:
    add rsp, 16
    swapgs
    jmp .iret
.kernel_return:
    add rsp, 16
.iret:
    iretq

%macro IRQ 2
    global irq_%1
irq_%1:
    push qword 0
    push qword %2
    jmp irq_common
%endmacro

IRQ 0, 32
IRQ 1, 33
IRQ 2, 34
IRQ 3, 35
IRQ 4, 36
IRQ 5, 37
IRQ 6, 38
IRQ 7, 39
IRQ 8, 40
IRQ 9, 41
IRQ 10, 42
IRQ 11, 43
IRQ 12, 44
IRQ 13, 45
IRQ 14, 46
IRQ 15, 47
IRQ 16, 48
IRQ 17, 49
IRQ 18, 50
IRQ 19, 51
IRQ 20, 52
IRQ 21, 53
IRQ 22, 54
IRQ 23, 55
IRQ 24, 56
IRQ 25, 57
IRQ 26, 58
IRQ 27, 59
IRQ 28, 60
IRQ 29, 61
IRQ 30, 62
IRQ 31, 63

global irq_apic_reschedule
irq_apic_reschedule:
    push qword 0
    push qword 0xF0
    jmp irq_common

global irq_apic_timer
irq_apic_timer:
    push qword 0
    push qword 0xF1
    jmp irq_common

global irq_apic_tlb
irq_apic_tlb:
    push qword 0
    push qword 0xF2
    jmp irq_common

section .note.GNU-stack noalloc noexec nowrite progbits
