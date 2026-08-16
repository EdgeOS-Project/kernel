/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 EL1 exception vectors. */

        .text
        .align  11
        .global edgeos_arm64_vectors
edgeos_arm64_vectors:
        b edgeos_arm64_sync_entry
        .space 124
        b edgeos_arm64_irq_entry
        .space 124
        b edgeos_arm64_fiq_entry
        .space 124
        b edgeos_arm64_serror_entry
        .space 124
        b edgeos_arm64_sync_entry
        .space 124
        b edgeos_arm64_irq_entry
        .space 124
        b edgeos_arm64_fiq_entry
        .space 124
        b edgeos_arm64_serror_entry
        .space 124
        b edgeos_arm64_sync_entry
        .space 124
        b edgeos_arm64_irq_entry
        .space 124
        b edgeos_arm64_fiq_entry
        .space 124
        b edgeos_arm64_serror_entry
        .space 124
        b edgeos_arm64_sync_entry
        .space 124
        b edgeos_arm64_irq_entry
        .space 124
        b edgeos_arm64_fiq_entry
        .space 124
        b edgeos_arm64_serror_entry
        .space 124

        .macro edgeos_save_frame
        sub     sp, sp, #288
        stp     x0, x1, [sp, #0]
        stp     x2, x3, [sp, #16]
        stp     x4, x5, [sp, #32]
        stp     x6, x7, [sp, #48]
        stp     x8, x9, [sp, #64]
        stp     x10, x11, [sp, #80]
        stp     x12, x13, [sp, #96]
        stp     x14, x15, [sp, #112]
        stp     x16, x17, [sp, #128]
        stp     x18, x19, [sp, #144]
        stp     x20, x21, [sp, #160]
        stp     x22, x23, [sp, #176]
        stp     x24, x25, [sp, #192]
        stp     x26, x27, [sp, #208]
        stp     x28, x29, [sp, #224]
        str     x30, [sp, #240]
        mrs     x0, esr_el1
        str     x0, [sp, #248]
        mrs     x0, far_el1
        str     x0, [sp, #256]
        mrs     x0, elr_el1
        str     x0, [sp, #264]
        mrs     x0, spsr_el1
        str     x0, [sp, #272]
        mrs     x0, sp_el0
        str     x0, [sp, #280]
        mov     x0, sp
        .endm

        .macro edgeos_restore_frame
        ldr     x0, [sp, #264]
        msr     elr_el1, x0
        ldr     x0, [sp, #272]
        msr     spsr_el1, x0
        ldr     x0, [sp, #280]
        msr     sp_el0, x0
        isb
        ldp     x0, x1, [sp, #0]
        ldp     x2, x3, [sp, #16]
        ldp     x4, x5, [sp, #32]
        ldp     x6, x7, [sp, #48]
        ldp     x8, x9, [sp, #64]
        ldp     x10, x11, [sp, #80]
        ldp     x12, x13, [sp, #96]
        ldp     x14, x15, [sp, #112]
        ldp     x16, x17, [sp, #128]
        ldp     x18, x19, [sp, #144]
        ldp     x20, x21, [sp, #160]
        ldp     x22, x23, [sp, #176]
        ldp     x24, x25, [sp, #192]
        ldp     x26, x27, [sp, #208]
        ldp     x28, x29, [sp, #224]
        ldr     x30, [sp, #240]
        add     sp, sp, #288
        eret
        .endm

edgeos_arm64_sync_entry:
        edgeos_save_frame
        bl      edgeos_arm64_sync_handler
        edgeos_restore_frame
edgeos_arm64_irq_entry:
        edgeos_save_frame
        bl      edgeos_arm64_irq_handler
        edgeos_restore_frame
edgeos_arm64_fiq_entry:
        edgeos_save_frame
        bl      edgeos_arm64_fiq_handler
        edgeos_restore_frame
edgeos_arm64_serror_entry:
        edgeos_save_frame
        bl      edgeos_arm64_serror_handler
        edgeos_restore_frame
