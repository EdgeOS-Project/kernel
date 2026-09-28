/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 EL0 return path.
 *
 * The caller has populated a private TTBR0 with the Linux process image,
 * assigned its ASID, and installed VBAR_EL1.  EL0 uses SPSR.M=EL0t; all
 * exception return state is architectural, rather than an x86 IRET frame.
 */

        .text
        .align  4
        .global edgeos_arm64_enter_user
edgeos_arm64_enter_user:
        msr     daifset, #0xf
        mov     sp, x3
        /* The C entry adapter has already activated x0 with ASID semantics. */
        msr     sp_el0, x2
        msr     elr_el1, x1
        msr     tpidr_el0, xzr
        mov     x3, xzr
        msr     spsr_el1, x3
        mov     x0, xzr
        mov     x1, xzr
        mov     x2, xzr
        mov     x3, xzr
        mov     x4, xzr
        mov     x5, xzr
        mov     x6, xzr
        mov     x7, xzr
        mov     x8, xzr
        mov     x9, xzr
        mov     x10, xzr
        mov     x11, xzr
        mov     x12, xzr
        mov     x13, xzr
        mov     x14, xzr
        mov     x15, xzr
        mov     x16, xzr
        mov     x17, xzr
        mov     x18, xzr
        mov     x19, xzr
        mov     x20, xzr
        mov     x21, xzr
        mov     x22, xzr
        mov     x23, xzr
        mov     x24, xzr
        mov     x25, xzr
        mov     x26, xzr
        mov     x27, xzr
        mov     x28, xzr
        mov     x29, xzr
        mov     x30, xzr
        isb
        eret

        .align  4
        .global edgeos_arm64_resume_user
edgeos_arm64_resume_user:
        msr     daifset, #0xf
        mov     sp, x2
        /* Avoid a second serialized TTBR0 write on every context switch. */
        mov     x17, x1
        ldr     x16, [x17, #264]
        msr     elr_el1, x16
        ldr     x16, [x17, #272]
        msr     spsr_el1, x16
        ldr     x16, [x17, #280]
        msr     sp_el0, x16
        ldp     x0, x1, [x17, #0]
        ldp     x2, x3, [x17, #16]
        ldp     x4, x5, [x17, #32]
        ldp     x6, x7, [x17, #48]
        ldp     x8, x9, [x17, #64]
        ldp     x10, x11, [x17, #80]
        ldp     x12, x13, [x17, #96]
        ldp     x14, x15, [x17, #112]
        ldr     x16, [x17, #128]
        ldp     x19, x20, [x17, #152]
        ldp     x21, x22, [x17, #168]
        ldp     x23, x24, [x17, #184]
        ldp     x25, x26, [x17, #200]
        ldp     x27, x28, [x17, #216]
        ldp     x29, x30, [x17, #232]
        ldr     x18, [x17, #144]
        ldr     x17, [x17, #136]
        isb
        eret
