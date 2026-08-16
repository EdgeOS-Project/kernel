/* SPDX-License-Identifier: MPL-2.0 */
PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    dynamic PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = SIZEOF_HEADERS;
    .hash           : { *(.hash) } :text
    .gnu.hash       : { *(.gnu.hash) } :text
    .dynsym         : { *(.dynsym) } :text
    .dynstr         : { *(.dynstr) } :text
    .gnu.version    : { *(.gnu.version) } :text
    .gnu.version_d  : { *(.gnu.version_d) } :text
    .dynamic        : { *(.dynamic) } :text :dynamic
    .rodata         : { *(.rodata*) } :text
    .text           : { *(.text*) } :text
    .eh_frame_hdr   : { *(.eh_frame_hdr) } :text
    .eh_frame       : { *(.eh_frame) } :text
    . = ALIGN(4096);
    .vdso_data      : { *(.vdso_data) } :text
    /DISCARD/       : { *(.comment) *(.note.GNU-stack) }
}
