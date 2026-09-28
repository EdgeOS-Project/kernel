/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression test for ELF64 and AArch64 COFF module relocation. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/linker.h"

#define TEST_PAGE_SIZE 4096u
#define TEST_ALLOCATION_LIMIT 16u

typedef struct {
    uint8_t *base;
    uint64_t pages;
    uint64_t released;
} test_allocation_t;

typedef struct fixture_module_record {
    const uint64_t *external_value;
    const uint64_t *local_value;
    const char *label;
    uint64_t (*callback)(uint64_t value);
} fixture_module_record_t;

static test_allocation_t g_allocations[TEST_ALLOCATION_LIMIT];
static uint64_t g_external_value;
static uint64_t g_external_function;

void *
arch_vm_alloc_pages(uint64_t pages)
{
    if (!pages || pages > SIZE_MAX / TEST_PAGE_SIZE)
        return 0;
    for (uint32_t index = 0; index < TEST_ALLOCATION_LIMIT; ++index) {
        if (!g_allocations[index].base) {
            uint8_t *base = calloc((size_t)pages, TEST_PAGE_SIZE);

            if (!base)
                return 0;
            g_allocations[index].base = base;
            g_allocations[index].pages = pages;
            return base;
        }
    }
    return 0;
}

void
arch_vm_free_page(void *page)
{
    uint8_t *pointer = page;

    for (uint32_t index = 0; index < TEST_ALLOCATION_LIMIT; ++index) {
        test_allocation_t *allocation = &g_allocations[index];
        uint8_t *end;

        if (!allocation->base)
            continue;
        end = allocation->base + allocation->pages * TEST_PAGE_SIZE;
        if (pointer < allocation->base || pointer >= end ||
            (uint64_t)(pointer - allocation->base) % TEST_PAGE_SIZE != 0)
            continue;
        allocation->released++;
        assert(allocation->released <= allocation->pages);
        if (allocation->released == allocation->pages) {
            free(allocation->base);
            memset(allocation, 0, sizeof(*allocation));
        }
        return;
    }
    assert(!"attempted to release an unknown page");
}

void
arch_vm_sync_loaded_page(void *page, int executable)
{
    assert(page != 0);
    assert(executable == 1);
}

static void
assert_no_allocations(void)
{
    for (uint32_t index = 0; index < TEST_ALLOCATION_LIMIT; ++index)
        assert(g_allocations[index].base == 0);
}

static int
fixture_resolve(const char *name, uint64_t *address, void *context)
{
    (void)context;
    if (strcmp(name, "fixture_external_value") == 0) {
        *address = (uint64_t)(uintptr_t)&g_external_value;
        return 0;
    }
    if (strcmp(name, "fixture_external_add") == 0) {
        *address = (uint64_t)(uintptr_t)&g_external_function;
        return 0;
    }
    return -1;
}

static uint8_t *
read_object(const char *path, size_t *size)
{
    FILE *stream;
    long length;
    uint8_t *data;

    stream = fopen(path, "rb");
    assert(stream != 0);
    assert(fseek(stream, 0, SEEK_END) == 0);
    length = ftell(stream);
    assert(length > 0);
    assert(fseek(stream, 0, SEEK_SET) == 0);
    data = malloc((size_t)length);
    assert(data != 0);
    assert(fread(data, 1, (size_t)length, stream) == (size_t)length);
    assert(fclose(stream) == 0);
    *size = (size_t)length;
    return data;
}

static void
test_object(const char *path, bsd_linker_architecture_t architecture)
{
    bsd_linker_image_t *image = 0;
    bsd_linker_record_set_t records;
    const fixture_module_record_t *record;
    const uint8_t *base;
    size_t image_size;
    size_t object_size;
    uint8_t *object = read_object(path, &object_size);
    int result;

    result = bsd_linker_load_object(
        object, object_size, architecture, fixture_resolve, 0, &image);
    if (result != 0)
        fprintf(stderr, "%s: load failed: %d\n", path, result);
    assert(result == 0);
    assert(image != 0);
    assert(bsd_linker_image_architecture(image) == architecture);
    base = bsd_linker_image_base(image);
    image_size = bsd_linker_image_size(image);
    assert(base != 0);
    assert(image_size != 0);
    assert(bsd_linker_image_records(image, &records) == 0);
    assert(records.metadata_begin != 0);
    assert(records.metadata_end == records.metadata_begin + 1);
    record = records.metadata_begin[0];
    assert((const uint8_t *)record >= base);
    assert((const uint8_t *)record + sizeof(*record) <= base + image_size);
    assert(record->external_value == &g_external_value);
    assert((const uint8_t *)record->local_value >= base);
    assert((const uint8_t *)record->local_value + sizeof(uint64_t) <=
        base + image_size);
    assert(*record->local_value == 0x6c6f63616c76616cULL);
    assert((const uint8_t *)record->label >= base);
    assert((const uint8_t *)record->label < base + image_size);
    assert(strcmp(record->label, "edgeos-module-fixture") == 0);
    assert((const uint8_t *)(uintptr_t)record->callback >= base);
    assert((const uint8_t *)(uintptr_t)record->callback < base + image_size);
    bsd_linker_release_image(image);
    free(object);
    assert_no_allocations();
}

int
main(int argc, char **argv)
{
    bsd_linker_image_t *image = 0;
    uint8_t invalid[64] = {0};

    assert(argc == 3);
    test_object(argv[1], BSD_LINKER_ARCH_X86_64);
    test_object(argv[2], BSD_LINKER_ARCH_ARM64);
    assert(bsd_linker_load_object(
               invalid, sizeof(invalid), BSD_LINKER_ARCH_NATIVE,
               fixture_resolve, 0, &image) == BSD_LINKER_ERR_FORMAT);
    assert(image == 0);
    assert_no_allocations();
    puts("bsd_linker_unit: PASS");
    return 0;
}
