/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 exception-level transition.
 * Copyright (c) EdgeOS Contributors.
 *
 * Generic UEFI firmware may invoke an EFI application at EL2 or EL1.  EdgeOS
 * owns its kernel execution at EL1h.  Keep interrupts masked until the EL1
 * vector table and GIC driver have been installed by the ARM64 kernel.
 */

        .text
        .align  4
        .global edgeos_arm64_kernel_entry
edgeos_arm64_kernel_entry:
        mov     x19, x0
        mrs     x1, CurrentEL
        cmp     x1, #0x8
        b.eq    1f
        cmp     x1, #0x4
        b.eq    2f
        b       3f

1:      mov     x2, #(1 << 31)
        msr     hcr_el2, x2
        mov     x2, #3
        msr     cnthctl_el2, x2
        msr     cntvoff_el2, xzr
        adrp    x3, edgeos_arm64_booted_from_el2
        add     x3, x3, :lo12:edgeos_arm64_booted_from_el2
        mov     w4, #1
        str     w4, [x3]
        adrp    x3, hyp_stub_vectors
        add     x3, x3, :lo12:hyp_stub_vectors
        msr     vbar_el2, x3
        /*
         * FreeBSD's non-VHE bhyve entry stubs execute through physical
         * identity addresses.  UEFI may leave EL2 translation enabled, so
         * retire that firmware-owned translation regime before entering the
         * EdgeOS EL1 kernel.  The EFI image and handoff tables are identity
         * addressed at this point and EL1 already owns its translation
         * tables.
         */
        dsb     sy
        mrs     x5, sctlr_el2
        bic     x5, x5, #1
        msr     sctlr_el2, x5
        isb
        mov     x2, #0x3c5
        msr     spsr_el2, x2
        adr     x2, 2f
        msr     elr_el2, x2
        isb
        eret

2:      msr     daifset, #0xf
        adrp    x1, edgeos_arm64_el1_stack_top
        add     x1, x1, :lo12:edgeos_arm64_el1_stack_top
        mov     sp, x1
        mov     x0, x19
        bl      edgeos_arm64_el1_main

3:      wfe
        b       3b

        .bss
        .align  12
        .global edgeos_arm64_el1_stack
edgeos_arm64_el1_stack:
        .skip   65536
        .global edgeos_arm64_el1_stack_top
edgeos_arm64_el1_stack_top:

        .text
        .align  4
        .global edgeos_arm64_spin_table_entry
edgeos_arm64_spin_table_entry:
        /* RPi spin-table CPUs identify their logical slot with MPIDR.Aff0. */
        mrs     x0, mpidr_el1
        and     x0, x0, #0xff
        b       edgeos_arm64_secondary_entry

        .align  4
        .global edgeos_arm64_secondary_entry
edgeos_arm64_secondary_entry:
        msr     daifset, #0xf
        mrs     x1, CurrentEL
        cmp     x1, #0x8
        b.ne    4f
        mov     x1, #(1 << 31)
        msr     hcr_el2, x1
        mov     x1, #3
        msr     cnthctl_el2, x1
        msr     cntvoff_el2, xzr
        adrp    x2, hyp_stub_vectors
        add     x2, x2, :lo12:hyp_stub_vectors
        msr     vbar_el2, x2
        dsb     sy
        mrs     x2, sctlr_el2
        bic     x2, x2, #1
        msr     sctlr_el2, x2
        isb
        mov     x1, #0x3c5
        msr     spsr_el2, x1
        adr     x1, 4f
        msr     elr_el2, x1
        isb
        eret

4:      adrp    x1, edgeos_arm64_secondary_mair
        add     x1, x1, :lo12:edgeos_arm64_secondary_mair
        ldr     x2, [x1]
        msr     mair_el1, x2
        adrp    x1, edgeos_arm64_secondary_tcr
        add     x1, x1, :lo12:edgeos_arm64_secondary_tcr
        ldr     x2, [x1]
        msr     tcr_el1, x2
        adrp    x1, edgeos_arm64_secondary_ttbr0
        add     x1, x1, :lo12:edgeos_arm64_secondary_ttbr0
        ldr     x2, [x1]
        msr     ttbr0_el1, x2
        dsb     sy
        isb
        tlbi    vmalle1
        dsb     sy
        isb
        adrp    x1, edgeos_arm64_secondary_sctlr
        add     x1, x1, :lo12:edgeos_arm64_secondary_sctlr
        ldr     x2, [x1]
        msr     sctlr_el1, x2
        isb
        adrp    x1, edgeos_arm64_secondary_cpacr
        add     x1, x1, :lo12:edgeos_arm64_secondary_cpacr
        ldr     x2, [x1]
        msr     cpacr_el1, x2
        isb
        adrp    x1, edgeos_arm64_secondary_stack_top
        add     x1, x1, :lo12:edgeos_arm64_secondary_stack_top
        ldr     x2, [x1, x0, lsl #3]
        mov     sp, x2
        bl      edgeos_arm64_secondary_main
5:      wfe
        b       5b
