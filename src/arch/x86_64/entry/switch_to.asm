[BITS 64]

section .text
global switch_to
global switch_to_cr3
global process_spawn_entry
global fork_ret
global ret_from_fork
extern isr_return_from_frame
extern process_enter_user_current
extern scheduler_schedule_common

; Preserve the caller's IF state while ensuring that an enabled interrupt can
; only arrive after this wrapper has returned to a fully unwound caller stack.
; STI inhibits maskable interrupts through the following RET instruction.
global scheduler_yield
scheduler_yield:
    pushfq
    xor edi, edi
    call scheduler_schedule_common
    test qword [rsp], 0x200
    jz .yield_if_disabled
    add rsp, 8
    sti
    ret
.yield_if_disabled:
    add rsp, 8
    ret

global scheduler_yield_from_irq
scheduler_yield_from_irq:
    pushfq
    mov edi, 1
    call scheduler_schedule_common
    test qword [rsp], 0x200
    jz .irq_if_disabled
    add rsp, 8
    sti
    ret
.irq_if_disabled:
    add rsp, 8
    ret

switch_to:
    mov [rdi + 0x00], r15
    mov [rdi + 0x08], r14
    mov [rdi + 0x10], r13
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], rbx
    mov [rdi + 0x28], rbp

    pop rax
    mov [rdi + 0x30], rax
    mov [rdi + 0x38], rsp

    mov rsp, [rsi + 0x38]
    mov rax, [rsi + 0x30]
    push rax

    mov r15, [rsi + 0x00]
    mov r14, [rsi + 0x08]
    mov r13, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov rbx, [rsi + 0x20]
    mov rbp, [rsi + 0x28]

    ret

; rdi = prev cpu_context_t*, rsi = next cpu_context_t*, rdx = next cr3,
; rcx = next rip, r8 = next rsp
; Save and load scheduler-owned context memory before switching CR3.
;
; Save the caller's continuation, not this function's return address.  The C
; caller is switch_task_context(), which itself was called by schedule_common().
; Resuming through switch_task_context's local frame means executing its
; epilogue and popping another return address from a stack that may have held
; nested syscall/X11/DBus work for a long time.  XFCE exposed that as resumes to
; .bss words such as g_vts.  Store schedule_common's "after switch_task_context"
; RIP/RSP/RBP instead, mirroring a longjmp-style context switch.
;
; The next task context is still copied before CR3 changes because task_t lives
; in kernel-owned memory that can alias fixed user windows after switching.
switch_to_cr3:
    mov rax, rcx
    mov rcx, r8
    mov [rdi + 0x00], r15
    mov [rdi + 0x08], r14
    mov [rdi + 0x10], r13
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], rbx
    mov r8,  [rbp + 0x00]
    mov r9,  [rbp + 0x08]
    lea r10, [rbp + 0x10]
    mov [rdi + 0x28], r8
    mov [rdi + 0x30], r9
    mov [rdi + 0x38], r10

    mov r15, [rsi + 0x00]
    mov r14, [rsi + 0x08]
    mov r13, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov rbx, [rsi + 0x20]
    mov rbp, [rsi + 0x28]

    ; A CLONE_VM context switch already runs in the destination address space.
    ; Avoid flushing the complete TLB for pthread/futex handoffs.  Different-mm
    ; switches arrive here on the kernel CR3 and still load rdx normally.
    mov r11, cr3
    cmp r11, rdx
    je .cr3_ready
    mov cr3, rdx
.cr3_ready:
    mov rsp, rcx
    jmp rax

; First entry for a freshly spawned process.
;
; The scheduler reaches task contexts with a direct jump, not a call.  Entering a
; C function directly on an empty kernel stack violates the SysV x86_64 entry
; alignment rule: a normal function starts with RSP%16 == 8 because CALL pushed a
; return address.  Desktop process storms made that latent bug visible as saved
; scheduler continuations resuming at BSS words.  Reserve one dummy qword so the
; C prologue and its calls run with the same alignment they would have after CALL.
process_spawn_entry:
    sub rsp, 8
    xor rbp, rbp
    jmp process_enter_user_current

global fork_ret
fork_ret:
    xor rax, rax
    ret

; r12 = pointer to edge_trap_frame_t
; Return to user mode through normal iretq path with copied syscall frame.
ret_from_fork:
    mov rsp, r12
    jmp isr_return_from_frame
section .note.GNU-stack noalloc noexec nowrite progbits
