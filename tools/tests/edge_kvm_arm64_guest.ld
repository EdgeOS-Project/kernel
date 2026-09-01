ENTRY(_start)

SECTIONS
{
    . = 0x40000000;
    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        *(.text*)
    }
    .rodata : ALIGN(16) {
        *(.rodata*)
    }
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}

