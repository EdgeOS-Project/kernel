ENTRY(_start)

PHDRS
{
    headers PT_PHDR PHDRS;
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x400000 + SIZEOF_HEADERS;
    .text : { *(.text*) } :text
    .rodata : { *(.rodata*) *(.eh_frame*) } :text

    . = ALIGN(0x1000);
    .data : { *(.data*) } :data
    .bss : { *(.bss*) *(COMMON) } :data
}
