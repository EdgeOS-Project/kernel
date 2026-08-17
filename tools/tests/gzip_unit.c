/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression test for the shared in-memory gzip adapter. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/gzip.h"

#define TEST_PAGE_SIZE 4096u
#define TEST_ALLOCATION_LIMIT 16u

typedef struct {
    uint8_t *base;
    uint64_t pages;
    uint64_t released;
} test_allocation_t;

static test_allocation_t g_allocations[TEST_ALLOCATION_LIMIT];

void *arch_vm_alloc_pages(uint64_t pages) {
    if (!pages || pages > SIZE_MAX / TEST_PAGE_SIZE) return 0;
    for (uint32_t index = 0; index < TEST_ALLOCATION_LIMIT; ++index) {
        if (!g_allocations[index].base) {
            uint8_t *base = calloc((size_t)pages, TEST_PAGE_SIZE);

            if (!base) return 0;
            g_allocations[index].base = base;
            g_allocations[index].pages = pages;
            g_allocations[index].released = 0;
            return base;
        }
    }
    return 0;
}

void arch_vm_free_page(void *page) {
    uint8_t *pointer = (uint8_t *)page;

    for (uint32_t index = 0; index < TEST_ALLOCATION_LIMIT; ++index) {
        test_allocation_t *allocation = &g_allocations[index];
        uint8_t *end;

        if (!allocation->base) continue;
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

static void assert_no_allocations(void) {
    for (uint32_t index = 0; index < TEST_ALLOCATION_LIMIT; ++index)
        assert(g_allocations[index].base == 0);
}

int main(void) {
    static const uint8_t compressed[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff,
        0x33, 0x30, 0x37, 0x30, 0x37, 0x30, 0x4c, 0xce, 0xcf, 0x2d,
        0x28, 0x4a, 0x2d, 0x2e, 0x4e, 0x4d, 0xd1, 0xcd, 0xcc, 0xcb,
        0x2c, 0x29, 0x4a, 0xcc, 0x4d, 0x2b, 0xd6, 0x2d, 0x48, 0xac,
        0xcc, 0xc9, 0x4f, 0x4c, 0x01, 0x00, 0x8f, 0x8e, 0xe3, 0x50,
        0x22, 0x00, 0x00, 0x00,
    };
    static const char expected[] = "070701compressed-initramfs-payload";
    uint64_t decoded_size = 0;
    void *decoded = 0;

    assert(edge_gzip_is_archive(compressed, sizeof(compressed)));
    assert(edge_gzip_uncompressed_size(
               compressed, sizeof(compressed), &decoded_size) == 0);
    assert(decoded_size == sizeof(expected) - 1u);
    assert(edge_gzip_decompress(
               compressed, sizeof(compressed), decoded_size - 1u,
               &decoded, &decoded_size) < 0);
    assert_no_allocations();
    assert(edge_gzip_decompress(
               compressed, sizeof(compressed), 4096u,
               &decoded, &decoded_size) == 0);
    assert(decoded_size == sizeof(expected) - 1u);
    assert(memcmp(decoded, expected, decoded_size) == 0);
    edge_gzip_release(decoded);
    assert_no_allocations();
    assert(edge_gzip_decompress(
               compressed, sizeof(compressed) - 1u, 4096u,
               &decoded, &decoded_size) < 0);
    assert_no_allocations();
    puts("gzip_unit: PASS");
    return 0;
}
