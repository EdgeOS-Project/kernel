.code16
.global _start

.set DEBUG_PORT, 0xe9

_start:
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x7c00, %sp
    mov $pre_message, %si
    call write_string

heartbeat:
    mov $heartbeat_message, %si
    call write_string
    mov $0x1000, %bx
1:
    mov $0xffff, %cx
2:
    loop 2b
    dec %bx
    jnz 1b
    jmp heartbeat

write_string:
    mov $DEBUG_PORT, %dx
3:
    lodsb
    test %al, %al
    jz 4f
    out %al, %dx
    jmp 3b
4:
    ret

pre_message:
    .asciz "EDGE_X86_MIGRATION_SOURCE_RUNNING\n"
heartbeat_message:
    .asciz "EDGE_X86_MIGRATION_RESUME_HEARTBEAT\n"

.org 510
.word 0xaa55
