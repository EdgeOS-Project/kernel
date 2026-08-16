/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared relocatable-object loader for external BSD driver modules.
 *
 * The x86_64 kernel consumes ELF64 ET_REL objects using the SysV ABI.  The
 * ARM64 UEFI kernel consumes AArch64 COFF objects so imported drivers retain
 * the same calling convention as the kernel image.  Both formats converge on
 * one allocated image and one lifecycle-record contract.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/linker.h"
#include "compat/freebsd/edgeos/systm.h"
#include "mm/arch_vm.h"

#define BSD_LINKER_PAGE_SIZE 4096u
#define BSD_LINKER_IMAGE_MAGIC 0x454d4f44u
#define BSD_LINKER_MAX_SECTIONS 4096u
#define BSD_LINKER_MAX_SYMBOLS 262144u
#define BSD_LINKER_MAX_IMAGE_BYTES (128u * 1024u * 1024u)

#define ELF_CLASS_64 2u
#define ELF_DATA_LITTLE_ENDIAN 1u
#define ELF_TYPE_RELOCATABLE 1u
#define ELF_MACHINE_X86_64 62u
#define ELF_SECTION_PROGBITS 1u
#define ELF_SECTION_SYMTAB 2u
#define ELF_SECTION_STRTAB 3u
#define ELF_SECTION_RELA 4u
#define ELF_SECTION_NOBITS 8u
#define ELF_FLAG_ALLOC 0x2u
#define ELF_FLAG_EXEC 0x4u
#define ELF_SECTION_UNDEFINED 0u
#define ELF_SECTION_ABSOLUTE 0xfff1u
#define ELF_SECTION_COMMON 0xfff2u
#define ELF_BIND_WEAK 2u
#define ELF_RELOC_X86_64_64 1u
#define ELF_RELOC_X86_64_PC32 2u
#define ELF_RELOC_X86_64_PLT32 4u
#define ELF_RELOC_X86_64_32 10u
#define ELF_RELOC_X86_64_32S 11u

#define COFF_MACHINE_ARM64 0xaa64u
#define COFF_SECTION_UNDEFINED 0
#define COFF_SECTION_ABSOLUTE (-1)
#define COFF_STORAGE_EXTERNAL 2u
#define COFF_STORAGE_WEAK_EXTERNAL 105u
#define COFF_SECTION_CODE 0x00000020u
#define COFF_SECTION_INITIALIZED_DATA 0x00000040u
#define COFF_SECTION_UNINITIALIZED_DATA 0x00000080u
#define COFF_SECTION_DISCARDABLE 0x02000000u
#define COFF_RELOC_ARM64_ADDR32 0x0001u
#define COFF_RELOC_ARM64_ADDR32NB 0x0002u
#define COFF_RELOC_ARM64_BRANCH26 0x0003u
#define COFF_RELOC_ARM64_PAGEBASE_REL21 0x0004u
#define COFF_RELOC_ARM64_REL21 0x0005u
#define COFF_RELOC_ARM64_PAGEOFFSET_12A 0x0006u
#define COFF_RELOC_ARM64_PAGEOFFSET_12L 0x0007u
#define COFF_RELOC_ARM64_SECREL 0x0008u
#define COFF_RELOC_ARM64_ADDR64 0x000eu
#define COFF_RELOC_ARM64_BRANCH19 0x000fu
#define COFF_RELOC_ARM64_BRANCH14 0x0010u
#define COFF_RELOC_ARM64_REL32 0x0011u

#define INVALID_OFFSET UINT64_MAX

typedef struct __attribute__((packed)) {
    unsigned char identification[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t program_header_offset;
    uint64_t section_header_offset;
    uint32_t flags;
    uint16_t header_size;
    uint16_t program_header_size;
    uint16_t program_header_count;
    uint16_t section_header_size;
    uint16_t section_header_count;
    uint16_t section_name_index;
} elf64_header_t;

typedef struct __attribute__((packed)) {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t address;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t information;
    uint64_t alignment;
    uint64_t entry_size;
} elf64_section_t;

typedef struct __attribute__((packed)) {
    uint32_t name;
    unsigned char information;
    unsigned char other;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
} elf64_symbol_t;

typedef struct __attribute__((packed)) {
    uint64_t offset;
    uint64_t information;
    int64_t addend;
} elf64_relocation_t;

typedef struct __attribute__((packed)) {
    uint16_t machine;
    uint16_t section_count;
    uint32_t timestamp;
    uint32_t symbol_table_offset;
    uint32_t symbol_count;
    uint16_t optional_header_size;
    uint16_t characteristics;
} coff_header_t;

typedef struct __attribute__((packed)) {
    unsigned char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t relocation_offset;
    uint32_t line_number_offset;
    uint16_t relocation_count;
    uint16_t line_number_count;
    uint32_t characteristics;
} coff_section_t;

typedef struct __attribute__((packed)) {
    unsigned char name[8];
    uint32_t value;
    int16_t section_number;
    uint16_t type;
    unsigned char storage_class;
    unsigned char auxiliary_count;
} coff_symbol_t;

typedef struct __attribute__((packed)) {
    uint32_t virtual_address;
    uint32_t symbol_index;
    uint16_t type;
} coff_relocation_t;

struct bsd_linker_image {
    uint32_t magic;
    uint32_t page_count;
    bsd_linker_architecture_t architecture;
    uint32_t reserved;
    unsigned char *allocation;
    unsigned char *base;
    uint64_t size;
    uint64_t veneer_offset;
    uint64_t veneer_limit;
    bsd_linker_record_set_t records;
};

typedef struct {
    void *memory;
    uint32_t page_count;
} linker_workspace_t;

static uint16_t
read_u16(const void *pointer)
{
    const unsigned char *bytes = pointer;

    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t
read_u32(const void *pointer)
{
    const unsigned char *bytes = pointer;

    return (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static int32_t
read_i32(const void *pointer)
{
    return (int32_t)read_u32(pointer);
}

static uint64_t
read_u64(const void *pointer)
{
    return (uint64_t)read_u32(pointer) |
        ((uint64_t)read_u32((const unsigned char *)pointer + 4) << 32);
}

static void
write_u32(void *pointer, uint32_t value)
{
    unsigned char *bytes = pointer;

    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
}

static void
write_u64(void *pointer, uint64_t value)
{
    write_u32(pointer, (uint32_t)value);
    write_u32((unsigned char *)pointer + 4, (uint32_t)(value >> 32));
}

static int
range_valid(size_t total, uint64_t offset, uint64_t length)
{
    return offset <= total && length <= (uint64_t)total - offset;
}

static int
add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left > UINT64_MAX - right)
        return -1;
    *result = left + right;
    return 0;
}

static int
multiply_u64(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left != 0 && right > UINT64_MAX / left)
        return -1;
    *result = left * right;
    return 0;
}

static int
align_u64(uint64_t value, uint64_t alignment, uint64_t *result)
{
    uint64_t mask;

    if (!alignment)
        alignment = 1;
    if ((alignment & (alignment - 1u)) != 0)
        return -1;
    mask = alignment - 1u;
    if (value > UINT64_MAX - mask)
        return -1;
    *result = (value + mask) & ~mask;
    return 0;
}

static int64_t
sign_extend(uint64_t value, unsigned int bits)
{
    uint64_t sign = 1ULL << (bits - 1u);

    return (int64_t)((value ^ sign) - sign);
}

static int
string_in_table(const unsigned char *table, uint64_t size, uint64_t offset,
    const char **name)
{
    uint64_t cursor;

    if (!table || !name || offset >= size)
        return -1;
    for (cursor = offset; cursor < size; ++cursor) {
        if (table[cursor] == '\0') {
            *name = (const char *)table + offset;
            return 0;
        }
    }
    return -1;
}

static int
name_equal(const char *left, const char *right)
{
    return left && right && bsd_strcmp(left, right) == 0;
}

static void
free_pages(void *memory, uint32_t page_count)
{
    unsigned char *bytes = memory;

    if (!memory)
        return;
    for (uint32_t page = 0; page < page_count; ++page)
        arch_vm_free_page(bytes + (uint64_t)page * BSD_LINKER_PAGE_SIZE);
}

static int
workspace_allocate(uint64_t bytes, linker_workspace_t *workspace)
{
    uint64_t pages;

    if (!workspace || !bytes ||
        align_u64(bytes, BSD_LINKER_PAGE_SIZE, &bytes) < 0)
        return BSD_LINKER_ERR_MEMORY;
    pages = bytes / BSD_LINKER_PAGE_SIZE;
    if (!pages || pages > UINT32_MAX)
        return BSD_LINKER_ERR_MEMORY;
    workspace->memory = arch_vm_alloc_pages(pages);
    if (!workspace->memory)
        return BSD_LINKER_ERR_MEMORY;
    workspace->page_count = (uint32_t)pages;
    bsd_memset(workspace->memory, 0, (size_t)bytes);
    return 0;
}

static void
workspace_release(linker_workspace_t *workspace)
{
    if (!workspace)
        return;
    free_pages(workspace->memory, workspace->page_count);
    workspace->memory = 0;
    workspace->page_count = 0;
}

static int
image_allocate(uint64_t image_size, bsd_linker_architecture_t architecture,
    bsd_linker_image_t **image_out)
{
    bsd_linker_image_t *image;
    unsigned char *allocation;
    uint64_t aligned_size;
    uint64_t pages;

    if (!image_out || !image_size ||
        image_size > BSD_LINKER_MAX_IMAGE_BYTES ||
        align_u64(image_size, BSD_LINKER_PAGE_SIZE, &aligned_size) < 0)
        return BSD_LINKER_ERR_MEMORY;
    pages = aligned_size / BSD_LINKER_PAGE_SIZE + 1u;
    if (pages > UINT32_MAX)
        return BSD_LINKER_ERR_MEMORY;
    allocation = arch_vm_alloc_pages(pages);
    if (!allocation)
        return BSD_LINKER_ERR_MEMORY;
    bsd_memset(allocation, 0, (size_t)(pages * BSD_LINKER_PAGE_SIZE));
    image = (bsd_linker_image_t *)allocation;
    image->magic = BSD_LINKER_IMAGE_MAGIC;
    image->page_count = (uint32_t)pages;
    image->architecture = architecture;
    image->allocation = allocation;
    image->base = allocation + BSD_LINKER_PAGE_SIZE;
    image->size = image_size;
    *image_out = image;
    return 0;
}

static void
image_sync_code(bsd_linker_image_t *image)
{
    uint32_t pages;

    if (!image || !image->base)
        return;
    pages = (uint32_t)((image->size + BSD_LINKER_PAGE_SIZE - 1u) /
        BSD_LINKER_PAGE_SIZE);
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_sync_loaded_page(
            image->base + (uint64_t)page * BSD_LINKER_PAGE_SIZE, 1);
}

static bsd_linker_architecture_t
native_architecture(void)
{
#if defined(__x86_64__)
    return BSD_LINKER_ARCH_X86_64;
#elif defined(__aarch64__)
    return BSD_LINKER_ARCH_ARM64;
#else
    return BSD_LINKER_ARCH_NATIVE;
#endif
}

static int
architecture_matches(bsd_linker_architecture_t actual,
    bsd_linker_architecture_t expected)
{
    if (expected == BSD_LINKER_ARCH_NATIVE)
        expected = native_architecture();
    return expected == actual;
}

static int
record_section_assign(bsd_linker_image_t *image, const char *name,
    uint64_t offset, uint64_t size, int coff)
{
    const void *const *begin;
    const void *const *end;
    int kind = 0;

    if ((!coff && name_equal(name, "bsd_sysinit")) ||
        (coff && name_equal(name, ".bsdsi$m")))
        kind = 1;
    else if ((!coff && name_equal(name, "bsd_sysuninit")) ||
        (coff && name_equal(name, ".bsdsu$m")))
        kind = 2;
    else if ((!coff && name_equal(name, "bsd_module_metadata")) ||
        (coff && name_equal(name, ".bsdmm$m")))
        kind = 3;
    if (!kind)
        return 0;
    if ((size & (sizeof(void *) - 1u)) != 0)
        return BSD_LINKER_ERR_FORMAT;
    begin = (const void *const *)(image->base + offset);
    end = begin + size / sizeof(void *);
    if (kind == 1) {
        image->records.sysinit_begin = begin;
        image->records.sysinit_end = end;
    } else if (kind == 2) {
        image->records.sysuninit_begin = begin;
        image->records.sysuninit_end = end;
    } else {
        image->records.metadata_begin = begin;
        image->records.metadata_end = end;
    }
    return 0;
}

static int
resolve_external_symbol(const char *name, unsigned char binding,
    bsd_linker_symbol_resolver_t resolver, void *context, uint64_t *address)
{
    if (!name || !address)
        return BSD_LINKER_ERR_SYMBOL;
    if (resolver && resolver(name, address, context) == 0)
        return 0;
    if (binding == ELF_BIND_WEAK || binding == COFF_STORAGE_WEAK_EXTERNAL) {
        *address = 0;
        return 0;
    }
    return BSD_LINKER_ERR_SYMBOL;
}

static int
elf_section_name(const void *object, size_t object_size,
    const elf64_header_t *header, uint32_t index, const char **name)
{
    elf64_section_t names;
    elf64_section_t section;
    uint64_t section_offset;

    if (!header || index >= header->section_header_count ||
        header->section_name_index >= header->section_header_count)
        return -1;
    section_offset = header->section_header_offset +
        (uint64_t)index * header->section_header_size;
    if (!range_valid(object_size, section_offset, sizeof(section)))
        return -1;
    bsd_memcpy(&section, (const unsigned char *)object + section_offset,
        sizeof(section));
    section_offset = header->section_header_offset +
        (uint64_t)header->section_name_index * header->section_header_size;
    if (!range_valid(object_size, section_offset, sizeof(names)))
        return -1;
    bsd_memcpy(&names, (const unsigned char *)object + section_offset,
        sizeof(names));
    if (names.type != ELF_SECTION_STRTAB ||
        !range_valid(object_size, names.offset, names.size))
        return -1;
    return string_in_table(
        (const unsigned char *)object + names.offset, names.size,
        section.name, name);
}

static int
elf_get_section(const void *object, size_t object_size,
    const elf64_header_t *header, uint32_t index, elf64_section_t *section)
{
    uint64_t offset;

    if (!header || !section || index >= header->section_header_count)
        return -1;
    offset = header->section_header_offset +
        (uint64_t)index * header->section_header_size;
    if (!range_valid(object_size, offset, sizeof(*section)))
        return -1;
    bsd_memcpy(section, (const unsigned char *)object + offset,
        sizeof(*section));
    return 0;
}

static int
elf_get_symbol(const void *object, size_t object_size,
    const elf64_section_t *symbol_section, uint32_t index,
    elf64_symbol_t *symbol)
{
    uint64_t offset;

    if (!symbol_section || !symbol || !symbol_section->entry_size ||
        index >= symbol_section->size / symbol_section->entry_size)
        return -1;
    offset = symbol_section->offset +
        (uint64_t)index * symbol_section->entry_size;
    if (!range_valid(object_size, offset, sizeof(*symbol)))
        return -1;
    bsd_memcpy(symbol, (const unsigned char *)object + offset,
        sizeof(*symbol));
    return 0;
}

static int
elf_symbol_address(const void *object, size_t object_size,
    const elf64_header_t *header, const elf64_section_t *symbol_section,
    const elf64_section_t *string_section, const uint64_t *section_offsets,
    const uint64_t *common_offsets, const bsd_linker_image_t *image,
    uint32_t symbol_index, bsd_linker_symbol_resolver_t resolver,
    void *resolver_context, uint64_t *address)
{
    elf64_symbol_t symbol;
    const char *name;

    if (elf_get_symbol(object, object_size, symbol_section, symbol_index,
            &symbol) < 0)
        return BSD_LINKER_ERR_FORMAT;
    if (symbol.section_index == ELF_SECTION_UNDEFINED) {
        if (string_section->type != ELF_SECTION_STRTAB ||
            !range_valid(object_size, string_section->offset,
                string_section->size) ||
            string_in_table(
                (const unsigned char *)object + string_section->offset,
                string_section->size, symbol.name, &name) < 0)
            return BSD_LINKER_ERR_FORMAT;
        return resolve_external_symbol(
            name, symbol.information >> 4, resolver, resolver_context,
            address);
    }
    if (symbol.section_index == ELF_SECTION_ABSOLUTE) {
        *address = symbol.value;
        return 0;
    }
    if (symbol.section_index == ELF_SECTION_COMMON) {
        if (!common_offsets ||
            common_offsets[symbol_index] == INVALID_OFFSET)
            return BSD_LINKER_ERR_FORMAT;
        *address = (uint64_t)(uintptr_t)image->base +
            common_offsets[symbol_index];
        return 0;
    }
    if (symbol.section_index >= header->section_header_count ||
        section_offsets[symbol.section_index] == INVALID_OFFSET)
        return BSD_LINKER_ERR_FORMAT;
    *address = (uint64_t)(uintptr_t)image->base +
        section_offsets[symbol.section_index] + symbol.value;
    return 0;
}

static int
elf_apply_relocation(unsigned char *target, uint32_t type,
    uint64_t symbol, int64_t addend, uint64_t place)
{
    uint64_t unsigned_value;
    int64_t signed_value;

    if (type == ELF_RELOC_X86_64_64) {
        unsigned_value = symbol + (uint64_t)addend;
        write_u64(target, unsigned_value);
        return 0;
    }
    signed_value = (int64_t)symbol + addend;
    if (type == ELF_RELOC_X86_64_PC32 ||
        type == ELF_RELOC_X86_64_PLT32) {
        signed_value -= (int64_t)place;
        if (signed_value < INT32_MIN || signed_value > INT32_MAX)
            return BSD_LINKER_ERR_RANGE;
        write_u32(target, (uint32_t)(int32_t)signed_value);
        return 0;
    }
    if (type == ELF_RELOC_X86_64_32) {
        if (signed_value < 0 || (uint64_t)signed_value > UINT32_MAX)
            return BSD_LINKER_ERR_RANGE;
        write_u32(target, (uint32_t)signed_value);
        return 0;
    }
    if (type == ELF_RELOC_X86_64_32S) {
        if (signed_value < INT32_MIN || signed_value > INT32_MAX)
            return BSD_LINKER_ERR_RANGE;
        write_u32(target, (uint32_t)(int32_t)signed_value);
        return 0;
    }
    return BSD_LINKER_ERR_RELOCATION;
}

static int
load_elf_x86_64(const void *object, size_t object_size,
    bsd_linker_architecture_t expected_architecture,
    bsd_linker_symbol_resolver_t resolver, void *resolver_context,
    bsd_linker_image_t **image_out)
{
    elf64_header_t header;
    elf64_section_t symbol_section = {0};
    elf64_section_t string_section = {0};
    linker_workspace_t workspace = {0};
    uint64_t *section_offsets;
    uint64_t *common_offsets;
    uint64_t workspace_bytes;
    uint64_t image_size = 0;
    uint32_t symbol_count = 0;
    uint32_t symbol_section_index = UINT32_MAX;
    bsd_linker_image_t *image = 0;
    int result = BSD_LINKER_ERR_FORMAT;

    if (!range_valid(object_size, 0, sizeof(header)))
        return BSD_LINKER_ERR_FORMAT;
    bsd_memcpy(&header, object, sizeof(header));
    if (header.identification[0] != 0x7f ||
        header.identification[1] != 'E' ||
        header.identification[2] != 'L' ||
        header.identification[3] != 'F' ||
        header.identification[4] != ELF_CLASS_64 ||
        header.identification[5] != ELF_DATA_LITTLE_ENDIAN ||
        header.type != ELF_TYPE_RELOCATABLE ||
        header.machine != ELF_MACHINE_X86_64 ||
        header.section_header_size < sizeof(elf64_section_t) ||
        !header.section_header_count ||
        header.section_header_count > BSD_LINKER_MAX_SECTIONS ||
        !range_valid(object_size, header.section_header_offset,
            (uint64_t)header.section_header_count *
                header.section_header_size))
        return BSD_LINKER_ERR_FORMAT;
    if (!architecture_matches(
            BSD_LINKER_ARCH_X86_64, expected_architecture))
        return BSD_LINKER_ERR_ARCHITECTURE;

    workspace_bytes =
        (uint64_t)header.section_header_count * sizeof(uint64_t);
    for (uint32_t index = 0; index < header.section_header_count; ++index) {
        elf64_section_t section;

        if (elf_get_section(object, object_size, &header, index, &section) < 0)
            return BSD_LINKER_ERR_FORMAT;
        if (section.type == ELF_SECTION_SYMTAB) {
            if (symbol_section.type != 0 || !section.entry_size ||
                section.size % section.entry_size != 0 ||
                section.size / section.entry_size > BSD_LINKER_MAX_SYMBOLS ||
                section.link >= header.section_header_count)
                return BSD_LINKER_ERR_FORMAT;
            symbol_section = section;
            symbol_section_index = index;
            symbol_count = (uint32_t)(section.size / section.entry_size);
            if (elf_get_section(object, object_size, &header, section.link,
                    &string_section) < 0 ||
                string_section.type != ELF_SECTION_STRTAB)
                return BSD_LINKER_ERR_FORMAT;
        }
    }
    if (!symbol_count ||
        add_u64(workspace_bytes,
            (uint64_t)symbol_count * sizeof(uint64_t),
            &workspace_bytes) < 0 ||
        workspace_allocate(workspace_bytes, &workspace) < 0)
        return BSD_LINKER_ERR_MEMORY;
    section_offsets = workspace.memory;
    common_offsets = section_offsets + header.section_header_count;
    for (uint32_t index = 0; index < header.section_header_count; ++index)
        section_offsets[index] = INVALID_OFFSET;
    for (uint32_t index = 0; index < symbol_count; ++index)
        common_offsets[index] = INVALID_OFFSET;

    for (uint32_t index = 0; index < header.section_header_count; ++index) {
        elf64_section_t section;
        const char *name;

        if (elf_get_section(object, object_size, &header, index, &section) < 0 ||
            elf_section_name(object, object_size, &header, index, &name) < 0)
            goto finish;
        if (!(section.flags & ELF_FLAG_ALLOC) ||
            name_equal(name, ".eh_frame"))
            continue;
        if (section.type != ELF_SECTION_PROGBITS &&
            section.type != ELF_SECTION_NOBITS)
            goto finish;
        if (align_u64(image_size, section.alignment, &image_size) < 0 ||
            image_size > BSD_LINKER_MAX_IMAGE_BYTES - section.size)
            goto finish;
        section_offsets[index] = image_size;
        image_size += section.size;
    }
    for (uint32_t index = 0; index < symbol_count; ++index) {
        elf64_symbol_t symbol;

        if (elf_get_symbol(object, object_size, &symbol_section, index,
                &symbol) < 0)
            goto finish;
        if (symbol.section_index != ELF_SECTION_COMMON)
            continue;
        if (align_u64(image_size, symbol.value, &image_size) < 0 ||
            image_size > BSD_LINKER_MAX_IMAGE_BYTES - symbol.size)
            goto finish;
        common_offsets[index] = image_size;
        image_size += symbol.size;
    }
    if (!image_size ||
        image_allocate(image_size, BSD_LINKER_ARCH_X86_64, &image) < 0) {
        result = BSD_LINKER_ERR_MEMORY;
        goto finish;
    }

    for (uint32_t index = 0; index < header.section_header_count; ++index) {
        elf64_section_t section;
        const char *name;

        if (section_offsets[index] == INVALID_OFFSET)
            continue;
        if (elf_get_section(object, object_size, &header, index, &section) < 0 ||
            elf_section_name(object, object_size, &header, index, &name) < 0)
            goto finish;
        if (section.type == ELF_SECTION_PROGBITS) {
            if (!range_valid(object_size, section.offset, section.size))
                goto finish;
            bsd_memcpy(image->base + section_offsets[index],
                (const unsigned char *)object + section.offset,
                (size_t)section.size);
        }
        result = record_section_assign(image, name, section_offsets[index],
            section.size, 0);
        if (result < 0)
            goto finish;
    }

    for (uint32_t index = 0; index < header.section_header_count; ++index) {
        elf64_section_t relocation_section;
        elf64_section_t target_section;
        uint64_t relocation_count;

        if (elf_get_section(object, object_size, &header, index,
                &relocation_section) < 0)
            goto finish;
        if (relocation_section.type != ELF_SECTION_RELA)
            continue;
        if (relocation_section.information >= header.section_header_count ||
            relocation_section.link >= header.section_header_count ||
            relocation_section.link != symbol_section_index)
            goto finish;
        if (section_offsets[relocation_section.information] == INVALID_OFFSET)
            continue;
        if (!relocation_section.entry_size ||
            relocation_section.size % relocation_section.entry_size != 0 ||
            !range_valid(object_size, relocation_section.offset,
                relocation_section.size) ||
            elf_get_section(object, object_size, &header,
                relocation_section.information, &target_section) < 0)
            goto finish;
        relocation_count =
            relocation_section.size / relocation_section.entry_size;
        for (uint64_t relocation_index = 0;
            relocation_index < relocation_count; ++relocation_index) {
            elf64_relocation_t relocation;
            uint64_t relocation_offset = relocation_section.offset +
                relocation_index * relocation_section.entry_size;
            uint32_t symbol_index;
            uint32_t type;
            uint64_t symbol;
            uint64_t width;
            unsigned char *target;
            uint64_t place;

            if (!range_valid(object_size, relocation_offset,
                    sizeof(relocation)))
                goto finish;
            bsd_memcpy(&relocation,
                (const unsigned char *)object + relocation_offset,
                sizeof(relocation));
            symbol_index = (uint32_t)(relocation.information >> 32);
            type = (uint32_t)relocation.information;
            width = type == ELF_RELOC_X86_64_64 ? 8u : 4u;
            if (relocation.offset > target_section.size ||
                width > target_section.size - relocation.offset)
                goto finish;
            result = elf_symbol_address(
                object, object_size, &header, &symbol_section,
                &string_section, section_offsets, common_offsets, image,
                symbol_index, resolver, resolver_context, &symbol);
            if (result < 0)
                goto finish;
            target = image->base +
                section_offsets[relocation_section.information] +
                relocation.offset;
            place = (uint64_t)(uintptr_t)target;
            result = elf_apply_relocation(
                target, type, symbol, relocation.addend, place);
            if (result < 0)
                goto finish;
        }
    }

    image_sync_code(image);
    *image_out = image;
    image = 0;
    result = 0;

finish:
    if (image)
        bsd_linker_release_image(image);
    workspace_release(&workspace);
    return result;
}

static int
coff_get_section(const void *object, size_t object_size,
    const coff_header_t *header, uint32_t index, coff_section_t *section)
{
    uint64_t offset;

    if (!header || !section || index >= header->section_count)
        return -1;
    offset = sizeof(coff_header_t) + header->optional_header_size +
        (uint64_t)index * sizeof(coff_section_t);
    if (!range_valid(object_size, offset, sizeof(*section)))
        return -1;
    bsd_memcpy(section, (const unsigned char *)object + offset,
        sizeof(*section));
    return 0;
}

static int
coff_string_table(const void *object, size_t object_size,
    const coff_header_t *header, const unsigned char **table,
    uint32_t *table_size)
{
    uint64_t offset;
    uint32_t size;

    if (multiply_u64(header->symbol_count, sizeof(coff_symbol_t), &offset) < 0 ||
        add_u64(header->symbol_table_offset, offset, &offset) < 0 ||
        !range_valid(object_size, offset, 4u))
        return -1;
    size = read_u32((const unsigned char *)object + offset);
    if (size < 4u || !range_valid(object_size, offset, size))
        return -1;
    *table = (const unsigned char *)object + offset;
    *table_size = size;
    return 0;
}

static int
coff_name(const unsigned char raw_name[8], const unsigned char *string_table,
    uint32_t string_table_size, char short_name[9], const char **name)
{
    uint32_t offset;

    if (!raw_name || !name)
        return -1;
    if (raw_name[0] == '/' && raw_name[1] >= '0' && raw_name[1] <= '9') {
        offset = 0;
        for (uint32_t index = 1; index < 8 && raw_name[index]; ++index) {
            if (raw_name[index] < '0' || raw_name[index] > '9')
                return -1;
            if (offset > (UINT32_MAX -
                    (uint32_t)(raw_name[index] - '0')) / 10u)
                return -1;
            offset = offset * 10u + (uint32_t)(raw_name[index] - '0');
        }
        return string_in_table(
            string_table, string_table_size, offset, name);
    }
    if (read_u32(raw_name) == 0) {
        offset = read_u32(raw_name + 4);
        return string_in_table(
            string_table, string_table_size, offset, name);
    }
    for (uint32_t index = 0; index < 8; ++index)
        short_name[index] = (char)raw_name[index];
    short_name[8] = '\0';
    *name = short_name;
    return 0;
}

static int
coff_get_symbol(const void *object, size_t object_size,
    const coff_header_t *header, uint32_t index, coff_symbol_t *symbol)
{
    uint64_t offset;

    if (!header || !symbol || index >= header->symbol_count)
        return -1;
    offset = header->symbol_table_offset +
        (uint64_t)index * sizeof(coff_symbol_t);
    if (!range_valid(object_size, offset, sizeof(*symbol)))
        return -1;
    bsd_memcpy(symbol, (const unsigned char *)object + offset,
        sizeof(*symbol));
    return 0;
}

static uint64_t
coff_section_alignment(uint32_t characteristics)
{
    uint32_t encoded = (characteristics >> 20) & 0xfu;

    if (!encoded)
        return 16u;
    return 1ULL << (encoded - 1u);
}

static int
coff_symbol_address(const void *object, size_t object_size,
    const coff_header_t *header, const unsigned char *string_table,
    uint32_t string_table_size, const uint64_t *section_offsets,
    const uint64_t *common_offsets, const bsd_linker_image_t *image,
    uint32_t symbol_index, bsd_linker_symbol_resolver_t resolver,
    void *resolver_context, uint64_t *address, int *external)
{
    coff_symbol_t symbol;
    char short_name[9];
    const char *name;

    if (coff_get_symbol(object, object_size, header, symbol_index,
            &symbol) < 0)
        return BSD_LINKER_ERR_FORMAT;
    if (symbol.section_number == COFF_SECTION_UNDEFINED) {
        if (symbol.value != 0) {
            if (!common_offsets ||
                common_offsets[symbol_index] == INVALID_OFFSET)
                return BSD_LINKER_ERR_FORMAT;
            *address = (uint64_t)(uintptr_t)image->base +
                common_offsets[symbol_index];
            if (external)
                *external = 0;
            return 0;
        }
        if (coff_name(symbol.name, string_table, string_table_size,
                short_name, &name) < 0)
            return BSD_LINKER_ERR_FORMAT;
        if (external)
            *external = 1;
        return resolve_external_symbol(
            name, symbol.storage_class, resolver, resolver_context,
            address);
    }
    if (symbol.section_number == COFF_SECTION_ABSOLUTE) {
        *address = symbol.value;
        if (external)
            *external = 0;
        return 0;
    }
    if (symbol.section_number <= 0 ||
        (uint32_t)symbol.section_number > header->section_count ||
        section_offsets[symbol.section_number - 1u] == INVALID_OFFSET)
        return BSD_LINKER_ERR_FORMAT;
    *address = (uint64_t)(uintptr_t)image->base +
        section_offsets[symbol.section_number - 1u] + symbol.value;
    if (external)
        *external = 0;
    return 0;
}

static int
arm64_write_branch(unsigned char *target, uint64_t destination,
    unsigned int immediate_bits, uint32_t immediate_mask,
    unsigned int immediate_shift)
{
    uint64_t place = (uint64_t)(uintptr_t)target;
    int64_t delta = (int64_t)destination - (int64_t)place;
    int64_t minimum = -(1LL << (immediate_bits - 1u)) * 4;
    int64_t maximum = ((1LL << (immediate_bits - 1u)) - 1) * 4;
    uint32_t instruction;
    uint32_t immediate;

    if ((delta & 3) != 0 || delta < minimum || delta > maximum)
        return BSD_LINKER_ERR_RANGE;
    instruction = read_u32(target);
    immediate = (uint32_t)((uint64_t)(delta >> 2) &
        ((1ULL << immediate_bits) - 1u));
    instruction &= ~immediate_mask;
    instruction |= immediate << immediate_shift;
    write_u32(target, instruction);
    return 0;
}

static int
arm64_allocate_veneer(bsd_linker_image_t *image, uint64_t destination,
    uint64_t *veneer_address)
{
    unsigned char *veneer;

    if (!image || !veneer_address ||
        image->veneer_offset > image->veneer_limit ||
        16u > image->veneer_limit - image->veneer_offset)
        return BSD_LINKER_ERR_RANGE;
    veneer = image->base + image->veneer_offset;
    write_u32(veneer, 0x58000050u);
    write_u32(veneer + 4, 0xd61f0200u);
    write_u64(veneer + 8, destination);
    *veneer_address = (uint64_t)(uintptr_t)veneer;
    image->veneer_offset += 16u;
    return 0;
}

static int
arm64_apply_relocation(bsd_linker_image_t *image, unsigned char *target,
    uint16_t type, uint64_t symbol, int external)
{
    uint64_t place = (uint64_t)(uintptr_t)target;
    uint64_t value;
    uint32_t instruction;
    int64_t delta;
    int result;

    if (type == COFF_RELOC_ARM64_ADDR64) {
        write_u64(target, read_u64(target) + symbol);
        return 0;
    }
    if (type == COFF_RELOC_ARM64_ADDR32 ||
        type == COFF_RELOC_ARM64_ADDR32NB) {
        value = read_u32(target) + symbol;
        if (type == COFF_RELOC_ARM64_ADDR32NB)
            value -= (uint64_t)(uintptr_t)image->base;
        if (value > UINT32_MAX)
            return BSD_LINKER_ERR_RANGE;
        write_u32(target, (uint32_t)value);
        return 0;
    }
    if (type == COFF_RELOC_ARM64_REL32) {
        delta = (int64_t)symbol + read_i32(target) - (int64_t)place - 4;
        if (delta < INT32_MIN || delta > INT32_MAX)
            return BSD_LINKER_ERR_RANGE;
        write_u32(target, (uint32_t)(int32_t)delta);
        return 0;
    }
    if (type == COFF_RELOC_ARM64_BRANCH26) {
        uint64_t destination = symbol +
            (uint64_t)(sign_extend(read_u32(target) & 0x03ffffffu, 26) << 2);

        result = arm64_write_branch(
            target, destination, 26u, 0x03ffffffu, 0u);
        if (result == BSD_LINKER_ERR_RANGE && external) {
            uint64_t veneer;

            result = arm64_allocate_veneer(image, destination, &veneer);
            if (result == 0)
                result = arm64_write_branch(
                    target, veneer, 26u, 0x03ffffffu, 0u);
        }
        return result;
    }
    if (type == COFF_RELOC_ARM64_BRANCH19)
        return arm64_write_branch(
            target, symbol, 19u, 0x00ffffe0u, 5u);
    if (type == COFF_RELOC_ARM64_BRANCH14)
        return arm64_write_branch(
            target, symbol, 14u, 0x0007ffe0u, 5u);
    instruction = read_u32(target);
    if (type == COFF_RELOC_ARM64_PAGEBASE_REL21 ||
        type == COFF_RELOC_ARM64_REL21) {
        uint64_t encoded = ((uint64_t)((instruction >> 5) & 0x7ffffu) << 2) |
            ((instruction >> 29) & 0x3u);
        int64_t addend = sign_extend(encoded, 21);
        int64_t immediate;

        if (type == COFF_RELOC_ARM64_PAGEBASE_REL21) {
            immediate = ((int64_t)(symbol & ~0xfffULL) -
                (int64_t)(place & ~0xfffULL)) >> 12;
            immediate += addend;
        } else {
            immediate = (int64_t)symbol - (int64_t)place + addend;
        }
        if (immediate < -(1LL << 20) ||
            immediate > (1LL << 20) - 1)
            return BSD_LINKER_ERR_RANGE;
        encoded = (uint64_t)immediate & 0x1fffffu;
        instruction &= ~((0x7ffffu << 5) | (0x3u << 29));
        instruction |= (uint32_t)((encoded >> 2) << 5);
        instruction |= (uint32_t)((encoded & 0x3u) << 29);
        write_u32(target, instruction);
        return 0;
    }
    if (type == COFF_RELOC_ARM64_PAGEOFFSET_12A) {
        uint64_t scale = (instruction & (1u << 22)) ? 4096u : 1u;
        uint64_t addend = ((instruction >> 10) & 0xfffu) * scale;
        uint64_t offset = (symbol + addend) & 0xfffu;

        if (offset % scale != 0 || offset / scale > 0xfffu)
            return BSD_LINKER_ERR_RANGE;
        instruction &= ~(0xfffu << 10);
        instruction |= (uint32_t)(offset / scale) << 10;
        write_u32(target, instruction);
        return 0;
    }
    if (type == COFF_RELOC_ARM64_PAGEOFFSET_12L) {
        uint64_t scale = 1ULL << ((instruction >> 30) & 0x3u);
        uint64_t addend = ((instruction >> 10) & 0xfffu) * scale;
        uint64_t offset = (symbol + addend) & 0xfffu;

        if (offset % scale != 0 || offset / scale > 0xfffu)
            return BSD_LINKER_ERR_RANGE;
        instruction &= ~(0xfffu << 10);
        instruction |= (uint32_t)(offset / scale) << 10;
        write_u32(target, instruction);
        return 0;
    }
    if (type == COFF_RELOC_ARM64_SECREL) {
        value = symbol - (uint64_t)(uintptr_t)image->base + read_u32(target);
        if (value > UINT32_MAX)
            return BSD_LINKER_ERR_RANGE;
        write_u32(target, (uint32_t)value);
        return 0;
    }
    return BSD_LINKER_ERR_RELOCATION;
}

static int
load_coff_arm64(const void *object, size_t object_size,
    bsd_linker_architecture_t expected_architecture,
    bsd_linker_symbol_resolver_t resolver, void *resolver_context,
    bsd_linker_image_t **image_out)
{
    coff_header_t header;
    const unsigned char *string_table;
    uint32_t string_table_size;
    linker_workspace_t workspace = {0};
    uint64_t *section_offsets;
    uint64_t *common_offsets;
    uint64_t workspace_bytes;
    uint64_t image_size = 0;
    uint64_t veneer_bytes = 0;
    bsd_linker_image_t *image = 0;
    int result = BSD_LINKER_ERR_FORMAT;

    if (!range_valid(object_size, 0, sizeof(header)))
        return BSD_LINKER_ERR_FORMAT;
    bsd_memcpy(&header, object, sizeof(header));
    if (header.machine != COFF_MACHINE_ARM64 ||
        !header.section_count ||
        header.section_count > BSD_LINKER_MAX_SECTIONS ||
        header.symbol_count > BSD_LINKER_MAX_SYMBOLS ||
        !range_valid(object_size,
            sizeof(header) + header.optional_header_size,
            (uint64_t)header.section_count * sizeof(coff_section_t)) ||
        !range_valid(object_size, header.symbol_table_offset,
            (uint64_t)header.symbol_count * sizeof(coff_symbol_t)) ||
        coff_string_table(object, object_size, &header, &string_table,
            &string_table_size) < 0)
        return BSD_LINKER_ERR_FORMAT;
    if (!architecture_matches(BSD_LINKER_ARCH_ARM64, expected_architecture))
        return BSD_LINKER_ERR_ARCHITECTURE;

    workspace_bytes =
        (uint64_t)header.section_count * sizeof(uint64_t);
    if (add_u64(workspace_bytes,
            (uint64_t)header.symbol_count * sizeof(uint64_t),
            &workspace_bytes) < 0 ||
        workspace_allocate(workspace_bytes, &workspace) < 0)
        return BSD_LINKER_ERR_MEMORY;
    section_offsets = workspace.memory;
    common_offsets = section_offsets + header.section_count;
    for (uint32_t index = 0; index < header.section_count; ++index)
        section_offsets[index] = INVALID_OFFSET;
    for (uint32_t index = 0; index < header.symbol_count; ++index)
        common_offsets[index] = INVALID_OFFSET;

    for (uint32_t index = 0; index < header.section_count; ++index) {
        coff_section_t section;
        uint32_t content_flags;

        if (coff_get_section(object, object_size, &header, index,
                &section) < 0)
            goto finish;
        content_flags = section.characteristics &
            (COFF_SECTION_CODE | COFF_SECTION_INITIALIZED_DATA |
             COFF_SECTION_UNINITIALIZED_DATA);
        if (!content_flags ||
            (section.characteristics & COFF_SECTION_DISCARDABLE))
            continue;
        if (align_u64(image_size,
                coff_section_alignment(section.characteristics),
                &image_size) < 0 ||
            image_size > BSD_LINKER_MAX_IMAGE_BYTES - section.raw_size)
            goto finish;
        section_offsets[index] = image_size;
        image_size += section.raw_size;
        if (section.relocation_count != 0) {
            uint64_t bytes;

            if (multiply_u64(section.relocation_count,
                    sizeof(coff_relocation_t), &bytes) < 0 ||
                !range_valid(object_size, section.relocation_offset, bytes))
                goto finish;
            for (uint32_t relocation_index = 0;
                relocation_index < section.relocation_count;
                ++relocation_index) {
                coff_relocation_t relocation;
                uint64_t offset = section.relocation_offset +
                    (uint64_t)relocation_index * sizeof(relocation);

                bsd_memcpy(&relocation,
                    (const unsigned char *)object + offset,
                    sizeof(relocation));
                if (relocation.type == COFF_RELOC_ARM64_BRANCH26)
                    veneer_bytes += 16u;
            }
        }
    }
    for (uint32_t index = 0; index < header.symbol_count;) {
        coff_symbol_t symbol;
        uint32_t next;

        if (coff_get_symbol(object, object_size, &header, index, &symbol) < 0)
            goto finish;
        next = index + 1u + symbol.auxiliary_count;
        if (next <= index || next > header.symbol_count)
            goto finish;
        if (symbol.section_number == COFF_SECTION_UNDEFINED &&
            symbol.value != 0) {
            uint64_t alignment = symbol.value;

            if ((alignment & (alignment - 1u)) != 0)
                alignment = 16u;
            if (align_u64(image_size, alignment, &image_size) < 0 ||
                image_size > BSD_LINKER_MAX_IMAGE_BYTES - symbol.value)
                goto finish;
            common_offsets[index] = image_size;
            image_size += symbol.value;
        }
        index = next;
    }
    if (align_u64(image_size, 16u, &image_size) < 0 ||
        image_size > BSD_LINKER_MAX_IMAGE_BYTES - veneer_bytes)
        goto finish;
    {
        uint64_t veneer_offset = image_size;

        image_size += veneer_bytes;
        if (!image_size ||
            image_allocate(image_size, BSD_LINKER_ARCH_ARM64, &image) < 0) {
            result = BSD_LINKER_ERR_MEMORY;
            goto finish;
        }
        image->veneer_offset = veneer_offset;
        image->veneer_limit = image_size;
    }

    for (uint32_t index = 0; index < header.section_count; ++index) {
        coff_section_t section;
        char short_name[9];
        const char *name;

        if (section_offsets[index] == INVALID_OFFSET)
            continue;
        if (coff_get_section(object, object_size, &header, index,
                &section) < 0 ||
            coff_name(section.name, string_table, string_table_size,
                short_name, &name) < 0)
            goto finish;
        if ((section.characteristics & COFF_SECTION_UNINITIALIZED_DATA) == 0 &&
            section.raw_size != 0) {
            if (!range_valid(object_size, section.raw_offset,
                    section.raw_size))
                goto finish;
            bsd_memcpy(image->base + section_offsets[index],
                (const unsigned char *)object + section.raw_offset,
                section.raw_size);
        }
        result = record_section_assign(image, name, section_offsets[index],
            section.raw_size, 1);
        if (result < 0)
            goto finish;
    }

    for (uint32_t index = 0; index < header.section_count; ++index) {
        coff_section_t section;

        if (section_offsets[index] == INVALID_OFFSET)
            continue;
        if (coff_get_section(object, object_size, &header, index,
                &section) < 0)
            goto finish;
        for (uint32_t relocation_index = 0;
            relocation_index < section.relocation_count;
            ++relocation_index) {
            coff_relocation_t relocation;
            uint64_t relocation_offset = section.relocation_offset +
                (uint64_t)relocation_index * sizeof(relocation);
            uint64_t symbol;
            int external = 0;
            uint64_t width =
                relocation.type == COFF_RELOC_ARM64_ADDR64 ? 8u : 4u;
            unsigned char *target;

            if (!range_valid(object_size, relocation_offset,
                    sizeof(relocation)))
                goto finish;
            bsd_memcpy(&relocation,
                (const unsigned char *)object + relocation_offset,
                sizeof(relocation));
            if (relocation.virtual_address > section.raw_size ||
                width > section.raw_size - relocation.virtual_address)
                goto finish;
            result = coff_symbol_address(
                object, object_size, &header, string_table,
                string_table_size, section_offsets, common_offsets, image,
                relocation.symbol_index, resolver, resolver_context,
                &symbol, &external);
            if (result < 0)
                goto finish;
            target = image->base + section_offsets[index] +
                relocation.virtual_address;
            result = arm64_apply_relocation(
                image, target, relocation.type, symbol, external);
            if (result < 0)
                goto finish;
        }
    }

    image_sync_code(image);
    *image_out = image;
    image = 0;
    result = 0;

finish:
    if (image)
        bsd_linker_release_image(image);
    workspace_release(&workspace);
    return result;
}

int
bsd_linker_load_object(const void *object, size_t object_size,
    bsd_linker_architecture_t expected_architecture,
    bsd_linker_symbol_resolver_t resolver, void *resolver_context,
    bsd_linker_image_t **image_out)
{
    const unsigned char *bytes = object;

    if (!object || object_size < sizeof(coff_header_t) || !image_out)
        return BSD_LINKER_ERR_INVALID;
    *image_out = 0;
    if (object_size >= 4u &&
        bytes[0] == 0x7f && bytes[1] == 'E' &&
        bytes[2] == 'L' && bytes[3] == 'F')
        return load_elf_x86_64(
            object, object_size, expected_architecture,
            resolver, resolver_context, image_out);
    if (read_u16(object) == COFF_MACHINE_ARM64)
        return load_coff_arm64(
            object, object_size, expected_architecture,
            resolver, resolver_context, image_out);
    return BSD_LINKER_ERR_FORMAT;
}

void
bsd_linker_release_image(bsd_linker_image_t *image)
{
    unsigned char *allocation;
    uint32_t pages;

    if (!image || image->magic != BSD_LINKER_IMAGE_MAGIC)
        return;
    allocation = image->allocation;
    pages = image->page_count;
    image->magic = 0;
    free_pages(allocation, pages);
}

bsd_linker_architecture_t
bsd_linker_image_architecture(const bsd_linker_image_t *image)
{
    return image && image->magic == BSD_LINKER_IMAGE_MAGIC ?
        image->architecture : BSD_LINKER_ARCH_NATIVE;
}

const void *
bsd_linker_image_base(const bsd_linker_image_t *image)
{
    return image && image->magic == BSD_LINKER_IMAGE_MAGIC ?
        image->base : 0;
}

size_t
bsd_linker_image_size(const bsd_linker_image_t *image)
{
    return image && image->magic == BSD_LINKER_IMAGE_MAGIC ?
        (size_t)image->size : 0;
}

int
bsd_linker_image_records(const bsd_linker_image_t *image,
    bsd_linker_record_set_t *records)
{
    if (!image || image->magic != BSD_LINKER_IMAGE_MAGIC || !records)
        return BSD_LINKER_ERR_INVALID;
    *records = image->records;
    return 0;
}
