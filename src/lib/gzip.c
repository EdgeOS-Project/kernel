/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-neutral gzip adapter for the permissively licensed zlib
 * sources carried by the imported FreeBSD source tree.
 */

#include <stdint.h>

#include "lib/gzip.h"
#include "mm/arch_vm.h"
#include "string.h"

#define Z_SOLO 1
#define Z_PREFIX 1
#include "zlib/upstream/zlib.h"

#define EDGE_GZIP_PAGE_SIZE 4096u
#define EDGE_GZIP_ALLOCATION_MAGIC 0x475a4950u

typedef struct {
    uint32_t magic;
    uint32_t pages;
    uint64_t requested_size;
} edge_gzip_allocation_t;

static void *edge_gzip_allocate_pages(uint64_t requested_size) {
    edge_gzip_allocation_t *allocation;
    uint64_t total_size;
    uint64_t pages;

    if (!requested_size ||
        requested_size > UINT64_MAX - sizeof(*allocation))
        return 0;
    total_size = requested_size + sizeof(*allocation);
    pages = (total_size + EDGE_GZIP_PAGE_SIZE - 1u) /
            EDGE_GZIP_PAGE_SIZE;
    if (!pages || pages > UINT32_MAX) return 0;
    allocation = (edge_gzip_allocation_t *)arch_vm_alloc_pages(pages);
    if (!allocation) return 0;
    allocation->magic = EDGE_GZIP_ALLOCATION_MAGIC;
    allocation->pages = (uint32_t)pages;
    allocation->requested_size = requested_size;
    return allocation + 1;
}

static void edge_gzip_free_pages(void *pointer) {
    edge_gzip_allocation_t *allocation;
    uint8_t *base;
    uint32_t pages;

    if (!pointer) return;
    allocation = (edge_gzip_allocation_t *)pointer - 1;
    if (allocation->magic != EDGE_GZIP_ALLOCATION_MAGIC) return;
    pages = allocation->pages;
    base = (uint8_t *)allocation;
    allocation->magic = 0;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(base + (uint64_t)page * EDGE_GZIP_PAGE_SIZE);
}

static voidpf edge_gzip_zalloc(voidpf opaque, uInt items, uInt size) {
    uint64_t bytes;

    (void)opaque;
    if (items != 0 && size > UINT64_MAX / items) return Z_NULL;
    bytes = (uint64_t)items * size;
    return edge_gzip_allocate_pages(bytes);
}

static void edge_gzip_zfree(voidpf opaque, voidpf pointer) {
    (void)opaque;
    edge_gzip_free_pages(pointer);
}

int edge_gzip_is_archive(const void *input, uint64_t input_size) {
    const uint8_t *bytes = (const uint8_t *)input;

    return bytes && input_size >= 18u &&
           bytes[0] == 0x1fu && bytes[1] == 0x8bu &&
           bytes[2] == 8u;
}

int edge_gzip_uncompressed_size(const void *input, uint64_t input_size,
                                uint64_t *output_size) {
    const uint8_t *bytes = (const uint8_t *)input;
    uint32_t size;

    if (!output_size || !edge_gzip_is_archive(input, input_size))
        return -1;
    size = (uint32_t)bytes[input_size - 4u] |
           ((uint32_t)bytes[input_size - 3u] << 8) |
           ((uint32_t)bytes[input_size - 2u] << 16) |
           ((uint32_t)bytes[input_size - 1u] << 24);
    if (!size) return -1;
    *output_size = size;
    return 0;
}

int edge_gzip_decompress(const void *input, uint64_t input_size,
                         uint64_t maximum_output_size, void **output,
                         uint64_t *output_size) {
    z_stream stream;
    uint64_t expected_size;
    uint8_t *decoded;
    int result;

    if (!output || !output_size || !maximum_output_size ||
        input_size > UINT32_MAX ||
        edge_gzip_uncompressed_size(
            input, input_size, &expected_size) < 0 ||
        expected_size > maximum_output_size ||
        expected_size > UINT32_MAX)
        return -1;
    *output = 0;
    *output_size = 0;
    decoded = (uint8_t *)edge_gzip_allocate_pages(expected_size);
    if (!decoded) return -1;

    memset(&stream, 0, sizeof(stream));
    stream.zalloc = edge_gzip_zalloc;
    stream.zfree = edge_gzip_zfree;
    stream.next_in = (Bytef *)(uintptr_t)input;
    stream.avail_in = (uInt)input_size;
    stream.next_out = decoded;
    stream.avail_out = (uInt)expected_size;
    result = inflateInit2(&stream, MAX_WBITS + 16);
    if (result != Z_OK) {
        edge_gzip_free_pages(decoded);
        return -1;
    }
    result = inflate(&stream, Z_FINISH);
    if (result != Z_STREAM_END ||
        stream.total_out != expected_size ||
        stream.avail_in != 0) {
        (void)inflateEnd(&stream);
        edge_gzip_free_pages(decoded);
        return -1;
    }
    if (inflateEnd(&stream) != Z_OK) {
        edge_gzip_free_pages(decoded);
        return -1;
    }
    *output = decoded;
    *output_size = expected_size;
    return 0;
}

void edge_gzip_release(void *output) {
    edge_gzip_free_pages(output);
}
