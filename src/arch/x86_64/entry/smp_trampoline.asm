; SPDX-License-Identifier: MPL-2.0
; EdgeOS x86 secondary CPU real-mode startup trampoline.

%define AP_MAILBOX_BASE       0x7000
%define AP_MAILBOX_CR3        (AP_MAILBOX_BASE + 0)
%define AP_MAILBOX_STACK      (AP_MAILBOX_BASE + 8)
%define AP_MAILBOX_ENTRY      (AP_MAILBOX_BASE + 16)
%define AP_MAILBOX_LOGICAL_ID (AP_MAILBOX_BASE + 24)
%define AP_TRAMPOLINE_BASE    0x8000

%define CR4_PAE        (1 << 5)
%define CR4_OSFXSR     (1 << 9)
%define CR4_OSXMMEXCPT (1 << 10)
%define CR0_PG         (1 << 31)
%define CR0_MP         (1 << 1)
%define CR0_EM         (1 << 2)
%define CR0_TS         (1 << 3)
%define CR0_NE         (1 << 5)
%define CR0_WP         (1 << 16)
%define IA32_EFER_MSR  0xC0000080
%define IA32_EFER_LME  (1 << 8)

section .rodata
align 16
global x86_ap_trampoline_start
global x86_ap_trampoline_end

bits 16
x86_ap_trampoline_start:
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    lgdt [AP_TRAMPOLINE_BASE + ap_gdt_ptr - x86_ap_trampoline_start]
    mov eax, cr0
    and eax, 0x9fffffff
    or eax, 1
    mov cr0, eax
    wbinvd
    jmp dword 0x08:(AP_TRAMPOLINE_BASE + ap_protected - x86_ap_trampoline_start)

bits 32
ap_protected:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov eax, [AP_MAILBOX_CR3]
    mov cr3, eax
    mov eax, cr4
    or eax, CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT
    mov cr4, eax
    mov ecx, IA32_EFER_MSR
    rdmsr
    or eax, IA32_EFER_LME
    wrmsr
    mov eax, cr0
    and eax, ~(CR0_EM | CR0_TS)
    or eax, CR0_PG | CR0_MP | CR0_NE | CR0_WP
    mov cr0, eax
    jmp 0x18:(AP_TRAMPOLINE_BASE + ap_long_mode - x86_ap_trampoline_start)

bits 64
ap_long_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov rbx, AP_MAILBOX_BASE
    mov rsp, [rbx + 8]
    and rsp, -16
    mov edi, [rbx + 24]
    mov rax, [rbx + 16]
    call rax
.halt:
    cli
    hlt
    jmp .halt

align 8
ap_gdt:
    dq 0
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00AF9A000000FFFF
ap_gdt_end:
ap_gdt_ptr:
    dw ap_gdt_end - ap_gdt - 1
    dd AP_TRAMPOLINE_BASE + ap_gdt - x86_ap_trampoline_start

x86_ap_trampoline_end:

section .note.GNU-stack noalloc noexec nowrite progbits
