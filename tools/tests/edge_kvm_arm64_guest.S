/* AArch64 guest for the EdgeOS QEMU/KVM timer and interrupt acceptance gate. */

.section .text.boot, "ax"
.global _start
.type _start, %function

.equ PL011_BASE, 0x09000000
.equ PL011_FR, 0x18
.equ PL011_FR_TXFF, 5
.equ GICD_BASE, 0x08000000
.equ GICD_CTLR, 0x0000
.equ GICR_BASE, 0x080a0000
.equ GICR_WAKER, 0x0014
.equ GICR_SGI_BASE, 0x00010000
.equ GICR_IGROUPR0, 0x0080
.equ GICR_ISENABLER0, 0x0100
.equ GICR_IPRIORITYR0, 0x0400
.equ GICR_PPI_VTIMER, 27
.equ PSCI_SYSTEM_OFF, 0x84000008

_start:
    mrs x0, CurrentEL
    cmp x0, #0x4
    b.ne invalid_el

    adr x0, exception_vectors
    msr VBAR_EL1, x0
    isb

    adr x1, startup_message
    bl uart_write

    /* Wake the redistributor before enabling the virtual timer PPI. */
    ldr x0, =GICR_BASE
    ldr w1, [x0, #GICR_WAKER]
    bic w1, w1, #0x2
    str w1, [x0, #GICR_WAKER]
1:
    ldr w1, [x0, #GICR_WAKER]
    tbnz w1, #2, 1b

    add x0, x0, #GICR_SGI_BASE
    ldr w1, [x0, #GICR_IGROUPR0]
    mov w2, #(1 << GICR_PPI_VTIMER)
    orr w1, w1, w2
    str w1, [x0, #GICR_IGROUPR0]
    mov w1, #0x80
    strb w1, [x0, #(GICR_IPRIORITYR0 + GICR_PPI_VTIMER)]
    str w2, [x0, #GICR_ISENABLER0]
    ldr w3, [x0, #GICR_ISENABLER0]
    tbz w3, #GICR_PPI_VTIMER, gic_enable_failure

    ldr x0, =GICD_BASE
    mov w1, #0x12
    str w1, [x0, #GICD_CTLR]
2:
    ldr w1, [x0, #GICD_CTLR]
    tbnz w1, #31, 2b

    mov x0, #0x7
    msr ICC_SRE_EL1, x0
    isb
    mov x0, #0xff
    msr ICC_PMR_EL1, x0
    msr ICC_BPR1_EL1, xzr
    mov x0, #1
    msr ICC_IGRPEN1_EL1, x0
    isb

    adr x1, armed_message
    bl uart_write

    msr daifset, #2
    mrs x20, CNTFRQ_EL0
    mov x1, #1000
    udiv x20, x20, x1
    mrs x21, CNTVCT_EL0
    msr CNTV_TVAL_EL0, x20
    mov x0, #1
    msr CNTV_CTL_EL0, x0
    isb
    mov x22, xzr
3:
    mrs x0, CNTV_CTL_EL0
    tbnz x0, #2, 4f
    cbnz x22, 3b
    mrs x0, CNTVCT_EL0
    sub x0, x0, x21
    cmp x0, x20
    b.lo 3b
    mov x22, #1
    adr x1, counter_message
    bl uart_write
    b 3b
4:
    adr x1, status_message
    bl uart_write
    msr daifclr, #2
5:
    yield
    b 5b

invalid_el:
    adr x1, invalid_el_message
    bl uart_write
    b power_off

gic_enable_failure:
    adr x1, gic_enable_failure_message
    bl uart_write
    b power_off

unexpected_exception:
    msr daifset, #2
    adr x1, exception_failure_message
    bl uart_write
    b power_off

irq_handler:
    mrs x9, ICC_IAR1_EL1
    ubfx x10, x9, #0, #24
    cmp x10, #GICR_PPI_VTIMER
    b.ne unexpected_irq
    msr CNTV_CTL_EL0, xzr
    msr ICC_EOIR1_EL1, x9
    isb
    adr x1, timer_pass_message
    bl uart_write
    adr x1, io_pass_message
    bl uart_write
    b power_off

unexpected_irq:
    msr ICC_EOIR1_EL1, x9
    adr x1, irq_failure_message
    bl uart_write

power_off:
    movz w0, #0x0008
    movk w0, #0x8400, lsl #16
    hvc #0
6:
    wfe
    b 6b

uart_write:
    ldr x0, =PL011_BASE
7:
    ldrb w2, [x1], #1
    cbz w2, 9f
8:
    ldr w3, [x0, #PL011_FR]
    tbnz w3, #PL011_FR_TXFF, 8b
    str w2, [x0]
    b 7b
9:
    ret

.size _start, . - _start

.macro vector target
    b \target
    .balign 128
.endm

.align 11
exception_vectors:
    vector unexpected_exception
    vector irq_handler
    vector unexpected_exception
    vector unexpected_exception
    vector unexpected_exception
    vector irq_handler
    vector unexpected_exception
    vector unexpected_exception
    vector unexpected_exception
    vector irq_handler
    vector unexpected_exception
    vector unexpected_exception
    vector unexpected_exception
    vector irq_handler
    vector unexpected_exception
    vector unexpected_exception

.section .rodata, "a"
startup_message:
    .asciz "EDGE_ARM64_QEMU_KVM_TIMER_START\n"
armed_message:
    .asciz "EDGE_ARM64_QEMU_KVM_TIMER_ARMED\n"
counter_message:
    .asciz "EDGE_ARM64_QEMU_KVM_COUNTER_PASS\n"
status_message:
    .asciz "EDGE_ARM64_QEMU_KVM_TIMER_STATUS_PASS\n"
timer_pass_message:
    .asciz "EDGE_ARM64_QEMU_KVM_TIMER_IRQ_PASS\n"
io_pass_message:
    .asciz "EDGE_ARM64_QEMU_KVM_GUEST_IO_PASS\n"
invalid_el_message:
    .asciz "EDGE_ARM64_QEMU_KVM_INVALID_EL\n"
gic_enable_failure_message:
    .asciz "EDGE_ARM64_QEMU_KVM_GIC_ENABLE_FAIL\n"
exception_failure_message:
    .asciz "EDGE_ARM64_QEMU_KVM_EXCEPTION_FAIL\n"
irq_failure_message:
    .asciz "EDGE_ARM64_QEMU_KVM_UNEXPECTED_IRQ\n"
