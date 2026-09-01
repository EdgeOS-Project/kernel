/* AArch64 heartbeat guest for KVM dirty-log migration acceptance. */

.section .text.boot, "ax"
.global _start
.type _start, %function

.equ PL011_BASE, 0x09000000
.equ PL011_FR, 0x18
.equ PL011_FR_TXFF, 5

_start:
    adr x1, startup_message
    bl uart_write
    adr x20, heartbeat_counter

heartbeat:
    ldr x0, [x20]
    add x0, x0, #1
    str x0, [x20]
    adr x1, heartbeat_message
    bl uart_write
    mov x4, #0x100
delay_outer:
    movz x2, #0x20, lsl #16
delay:
    subs x2, x2, #1
    b.ne delay
    subs x4, x4, #1
    b.ne delay_outer
    b heartbeat

uart_write:
    ldr x0, =PL011_BASE
1:
    ldrb w2, [x1], #1
    cbz w2, 3f
2:
    ldr w3, [x0, #PL011_FR]
    tbnz w3, #PL011_FR_TXFF, 2b
    str w2, [x0]
    b 1b
3:
    ret

.size _start, . - _start

.section .rodata, "a"
startup_message:
    .asciz "EDGE_ARM64_MIGRATION_SOURCE_RUNNING\n"
heartbeat_message:
    .asciz "EDGE_ARM64_MIGRATION_RESUME_HEARTBEAT\n"

.section .data, "aw"
.balign 8
heartbeat_counter:
    .quad 0
