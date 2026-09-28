/* SPDX-License-Identifier: MPL-2.0 */
/* Link layout for freestanding AArch64 Linux ABI probes. */

ENTRY(_start)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x400000 + SIZEOF_HEADERS;
    .text : {
        *(.text .text.*)
        *(.rodata .rodata.*)
    } :text

    . = ALIGN(4096);
    .data : {
        *(.data .data.*)
    } :data
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
