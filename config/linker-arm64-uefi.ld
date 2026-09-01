OUTPUT_FORMAT(elf64-littleaarch64)
ENTRY(efi_main)

SECTIONS
{
    ImageBase = DEFINED(EDGEOS_IMAGE_BASE) ? EDGEOS_IMAGE_BASE : 0;
    . = ImageBase + 0x1000;
    _kernel_start = .;

    .text : ALIGN(4096)
    {
        *(.text*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata*)
        *(.srodata*)
    }

    .bsd_sysinit : ALIGN(8)
    {
        __start_bsd_sysinit = .;
        KEEP(*(bsd_sysinit))
        __stop_bsd_sysinit = .;
    }

    .bsd_sysuninit : ALIGN(8)
    {
        __start_bsd_sysuninit = .;
        KEEP(*(bsd_sysuninit))
        __stop_bsd_sysuninit = .;
    }

    .bsd_module_metadata : ALIGN(8)
    {
        __start_bsd_module_metadata = .;
        KEEP(*(bsd_module_metadata))
        __stop_bsd_module_metadata = .;
    }

    .bsd_linker_sets : ALIGN(8)
    {
        KEEP(*(set_*))
    }

    .data : ALIGN(4096)
    {
        *(.data*)
        *(.sdata*)
    }

    .dynamic : ALIGN(8)
    {
        *(.dynamic)
    }

    .rela : ALIGN(8)
    {
        *(.rela*)
    }

    .bss : ALIGN(4096)
    {
        *(COMMON)
        *(.bss*)
        *(.sbss*)
    }

    _kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
