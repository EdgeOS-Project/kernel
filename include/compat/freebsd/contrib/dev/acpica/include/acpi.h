/* SPDX-License-Identifier: MPL-2.0 */
/* ACPICA-compatible type surface backed by EdgeOS firmware metadata. */

#ifndef EDGEOS_COMPAT_FREEBSD_ACPI_H
#define EDGEOS_COMPAT_FREEBSD_ACPI_H

#ifdef EDGEOS_BSD_FULL_ACPICA
#include_next <contrib/dev/acpica/include/acpi.h>
#else

#include <stddef.h>
#include <stdint.h>

typedef void *ACPI_HANDLE;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t ACPI_STATUS;
typedef uint32_t ACPI_OBJECT_TYPE;

typedef void (*ACPI_NOTIFY_HANDLER)(ACPI_HANDLE device, UINT32 value,
    void *context);

typedef union acpi_object {
    uint32_t Type;
    struct {
        uint32_t Type;
        uint64_t Value;
    } Integer;
    struct {
        uint32_t Type;
        uint32_t Length;
        char *Pointer;
    } String;
    struct {
        uint32_t Type;
        uint32_t Length;
        uint8_t *Pointer;
    } Buffer;
    struct {
        uint32_t Type;
        uint32_t Count;
        union acpi_object *Elements;
    } Package;
} ACPI_OBJECT;

typedef struct acpi_object_list {
    uint32_t Count;
    ACPI_OBJECT *Pointer;
} ACPI_OBJECT_LIST;

typedef struct acpi_buffer {
    size_t Length;
    void *Pointer;
} ACPI_BUFFER;

typedef struct acpi_table_header {
    char Signature[4];
    UINT32 Length;
    UINT8 Revision;
    UINT8 Checksum;
    char OemId[6];
    char OemTableId[8];
    UINT32 OemRevision;
    char AslCompilerId[4];
    UINT32 AslCompilerRevision;
} __attribute__((packed)) ACPI_TABLE_HEADER;

typedef struct acpi_subtable_header {
    UINT8 Type;
    UINT8 Length;
} __attribute__((packed)) ACPI_SUBTABLE_HEADER;

#define AE_OK 0
#define AE_ERROR 1
#define AE_NOT_FOUND 5
#define ACPI_TYPE_INTEGER 0x01
#define ACPI_TYPE_STRING 0x02
#define ACPI_TYPE_BUFFER 0x03
#define ACPI_TYPE_PACKAGE 0x04
#define ACPI_ALLOCATE_BUFFER ((size_t)-1)
#define ACPI_SUCCESS(status) ((status) == AE_OK)
#define ACPI_FAILURE(status) ((status) != AE_OK)
#define ACPI_NAMESEG_SIZE 4

void AcpiOsFree(void *memory);
ACPI_STATUS AcpiEvaluateObject(ACPI_HANDLE object, const char *path,
    ACPI_OBJECT_LIST *arguments, ACPI_BUFFER *return_buffer);

#ifndef ACPI_UNUSED_VAR
#define ACPI_UNUSED_VAR __attribute__((unused))
#endif
#ifndef ACPI_MODULE_NAME
#define ACPI_MODULE_NAME(name) \
    static const char ACPI_UNUSED_VAR _AcpiModuleName[] = (name);
#endif

#endif

#endif
