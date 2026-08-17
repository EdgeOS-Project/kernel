OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x08000000;
    _kernel_start = .;

    .multiboot2 : ALIGN(8)
    {
        KEEP(*(.multiboot2))
    }

    _kernel_text_start = .;

    .bootstrap.text : ALIGN(4096)
    {
        *(.bootstrap.text)
    }

    .text : ALIGN(4096)
    {
        *(.text*)
    }

    _kernel_text_end = .;

    .rodata : ALIGN(4096)
    {
        *(.rodata*)
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
        /*
         * FreeBSD linker sets use $a/$m/$z subsection suffixes for start,
         * member, and stop ordering.  Keep the sort here: the output section
         * intentionally combines every set, so input order cannot provide
         * correct per-set boundaries.
         */
        KEEP(*(SORT_BY_NAME(set_*)))
    }

    .data : ALIGN(4096)
    {
        *(.data*)
    }

    .bss : ALIGN(4096)
    {
        *(COMMON)
        *(.bss*)
    }

    .bootstrap.bss (NOLOAD) : ALIGN(4096)
    {
        *(.bootstrap.bss)
    }

    _kernel_end = .;

    ASSERT(_kernel_end <= 0x40000000,
           "x86_64 kernel image overlaps fixed userspace windows")
}
